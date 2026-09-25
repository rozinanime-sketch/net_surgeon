//! Выполнение Action. Раньше это был кусок гигантского match внутри run_app()
//! в cli/mod.rs, вперемешку с отрисовкой терминала и event loop'ом. Теперь
//! mod.rs занимается только терминалом и вызовом screen::handle_key(); всё,
//! что порождает фоновую tokio-задачу, живёт здесь.
//!
//! Action::None/Quit/ToggleBackground обрабатываются в cli/mod.rs напрямую —
//! им нужен доступ к терминалу (ToggleBackground) или к самому event loop'у
//! (Quit), которого здесь нет.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::dns::ip_cache::IpDomainCache;
use crate::observability::metrics::Metrics;
use crate::engine::strategy::{self, HelloClass, StrategyStore};

use super::action::Action;
use super::app::App;
use crate::observability::logging::{self as log, LogLevel, LogSender};
use super::screen::{config_editor, domains_editor};

/// Сводка по всем измеренным техникам с их полезностью — чтобы выбор
/// был виден, а не только его результат.
fn reward_table(
    result: &crate::engine::diagnostics::DiagnosticResult,
    weights: crate::engine::strategy::RewardWeights,
) -> String {
    use crate::engine::strategy::{reward, Strategy};

    [
        (Strategy::TlsRecord, &result.tls_record),
        (Strategy::SniSplit, &result.sni_split),
        (Strategy::Oob, &result.oob),
        (Strategy::Disorder, &result.disorder),
        (Strategy::Fake, &result.fake),
    ]
    .into_iter()
    .filter(|(_, s)| s.attempts > 0)
    .map(|(strategy, s)| {
        format!(
            "{}={:.2}({}/{}, {})",
            strategy.as_str(),
            reward(s, weights),
            s.successes,
            s.attempts,
            s.median_ms.map(|ms| format!("{:.0}мс", ms)).unwrap_or_else(|| "—".into())
        )
    })
    .collect::<Vec<_>>()
    .join(" ")
}

/// Форматирует медианную задержку успешных проб: «120 мс» или «—».
fn fmt_ms(value: Option<f64>) -> String {
    value.map(|ms| format!("{:.0}", ms)).unwrap_or_else(|| "—".to_string())
}

/// Предупреждает, что техника fake в этом прогоне не будет измерена.
///
/// Сейчас она выключена всегда (см. `socket::fake_supported`), а раньше
/// пропускалась без `CAP_NET_ADMIN`. В обоих случаях в отчёте остаётся
/// строка «0/0», по которой не понять, что техника не провалилась, а просто
/// не запускалась. Вызывается один раз на прогон, а не на домен — иначе при
/// массовой диагностике предупреждение повторилось бы для каждого домена.
fn warn_if_fake_unavailable(log_tx: &LogSender) {
    if !crate::bypass::socket::fake_supported() {
        log::log_t(log_tx, LogLevel::Info, "log.fake_disabled", vec![]);
    } else if !crate::bypass::socket::tcp_repair_available() {
        log::log_t(log_tx, LogLevel::Warning, "log.fake_unavailable", vec![]);
    }
}

/// Сохраняет хранилище стратегий в блокирующем пуле.
///
/// Диагностика идёт задачей на рабочем потоке tokio, и синхронная запись
/// файла занимала бы его вместе со всеми соединениями, которые он
/// обслуживает. Так же сохраняет `proxy::adaptive`.
async fn save_store(strategies: &Arc<StrategyStore>) -> std::io::Result<()> {
    let store = Arc::clone(strategies);
    tokio::task::spawn_blocking(move || store.save())
        .await
        .unwrap_or_else(|e| Err(std::io::Error::other(e)))
}

/// Единый отчёт по результатам диагностики одного домена.
///
/// Раньше одиночная и массовая диагностика логировали по-разному: одиночная
/// показывала четыре сводные строки, массовая — подробности, и только при
/// неудаче. Хуже того, сводная строка называлась «HTTPS split», хотя её
/// значение — успех ЛЮБОЙ из трёх техник (две TLS-записи / сплит по SNI /
/// свип позиций). Из-за этого нельзя было понять, что именно сработало.
fn report_diagnostics(log_tx: &LogSender, domain: &str, result: &crate::engine::diagnostics::DiagnosticResult) {
    // Прямая проба: отличает блокировку по IP от разбора SNI.
    log::log_nested_t(log_tx, LogLevel::Info, "log.diag_direct", "verdict", result.direct.description_key(), vec![
        ("domain", domain.to_string()),
    ]);

    // Каждая техника — отдельной строкой, с числами, а не сводным вердиктом.
    log::log_t(log_tx, LogLevel::Info, "log.tls_record_score", vec![
        ("domain", domain.to_string()),
        ("successes", result.tls_record.successes.to_string()),
        ("attempts", result.tls_record.attempts.to_string()),
        ("confidence", format!("{:.2}", result.tls_record.confidence)),
        ("median", fmt_ms(result.tls_record.median_ms)),
    ]);

    log::log_t(log_tx, LogLevel::Info, "log.oob_score", vec![
        ("domain", domain.to_string()),
        ("successes", result.oob.successes.to_string()),
        ("attempts", result.oob.attempts.to_string()),
        ("confidence", format!("{:.2}", result.oob.confidence)),
        ("median", fmt_ms(result.oob.median_ms)),
    ]);

    log::log_t(log_tx, LogLevel::Info, "log.disorder_score", vec![
        ("domain", domain.to_string()),
        ("successes", result.disorder.successes.to_string()),
        ("attempts", result.disorder.attempts.to_string()),
        ("confidence", format!("{:.2}", result.disorder.confidence)),
        ("median", fmt_ms(result.disorder.median_ms)),
    ]);

    log::log_t(log_tx, LogLevel::Info, "log.sni_score", vec![
        ("domain", domain.to_string()),
        ("successes", result.sni_split.successes.to_string()),
        ("attempts", result.sni_split.attempts.to_string()),
        ("confidence", format!("{:.2}", result.sni_split.confidence)),
        ("median", fmt_ms(result.sni_split.median_ms)),
    ]);

    log::log_t(log_tx, LogLevel::Info, "log.fake_score", vec![
        ("domain", domain.to_string()),
        ("successes", result.fake.successes.to_string()),
        ("attempts", result.fake.attempts.to_string()),
        ("confidence", format!("{:.2}", result.fake.confidence)),
        ("median", fmt_ms(result.fake.median_ms)),
    ]);

    log::log_nested_t(log_tx, LogLevel::Info, "log.diag_quic", "verdict", result.quic.description_key(), vec![
        ("domain", domain.to_string()),
    ]);
}

#[allow(clippy::too_many_arguments)]
pub fn run(
    action: Action,
    app: &mut App,
    // `&mut`: перезапуск прокси перечитывает конфиг и список доменов, и
    // новые значения должны увидеть и последующие действия (диагностика).
    config: &mut Arc<Config>,
    domains: &mut Arc<HashSet<String>>,
    metrics: &Arc<Metrics>,
    ip_cache: &Arc<IpDomainCache>,
    strategies: &Arc<StrategyStore>,
    log_tx: &LogSender,
    rt: &tokio::runtime::Handle,
) {
    match action {
        Action::None | Action::Quit | Action::ToggleBackground => {
            // Обрабатываются вызывающим кодом (cli/mod.rs).
        }

        Action::RunDiagnostics(_) | Action::RunDiagnosticsAll if app.diagnostics_running => {
            // Два прогона сразу удваивают число проб к одним и тем же
            // серверам и портят оба результата. Раньше экран диагностики
            // позволял нажать `a` или `n` поверх идущего прогона.
            log::log_t(log_tx, LogLevel::Warning, "log.diagnostics_busy", vec![]);
        }

        Action::RunDiagnostics(domain) => {
            app.diagnostics_running = true;
            let log_tx = log_tx.clone();
            let config = Arc::clone(config);
            let strategies = Arc::clone(strategies);
            rt.spawn(async move {
                log::log_t(&log_tx, LogLevel::Info, "diagnostics.started", vec![("domain", domain.clone())]);
                warn_if_fake_unavailable(&log_tx);

                let timing = crate::engine::diagnostics::ProbeTiming {
                    gap_min_ms: config.probe_gap_min_ms,
                    gap_max_ms: config.probe_gap_max_ms,
                    hello_size: crate::engine::diagnostics::browser_hello_size(),
                };
                let result = crate::engine::diagnostics::diagnose(&domain, &config.bypass, timing).await;

                report_diagnostics(&log_tx, &domain, &result);

                use crate::engine::diagnostics::ProbeOutcome::*;

                // Итог называет КОНКРЕТНУЮ технику. Раньше здесь было общее
                // «обход помогает», основанное на сводном флаге, который
                // на самом деле означал «сработало хоть что-то».
                match strategy::choose_from_diagnostics(&result) {
                    Some(chosen) => {
                        // Результат сохраняется так же, как в массовом прогоне.
                        // Раньше одиночная диагностика только печатала вердикт:
                        // чтобы стратегия попала в strategies.txt, приходилось
                        // гонять весь список целиком.
                        strategies.set(&domain, HelloClass::Large, chosen, strategy::confidence_of(&result, chosen));
                        if let Err(e) = save_store(&strategies).await {
                            log::log_t(&log_tx, LogLevel::Error, "error.strategy_write", vec![("error", e.to_string())]);
                        }

                        log::log_nested_t(&log_tx, LogLevel::Success, "log.strategy_chosen", "strategy", chosen.label_key(), vec![
                            ("domain", domain.clone()),
                        ]);
                    }
                    None => {
                        // Ни одна TCP-техника не прошла — запоминаем отказ
                        // (если сервер был досягаем) и уточняем, почему.
                        strategies.record_nothing_worked(&domain, HelloClass::Large, &result);
                        if let Err(e) = save_store(&strategies).await {
                            log::log_t(&log_tx, LogLevel::Error, "error.strategy_write", vec![("error", e.to_string())]);
                        }

                        // Прямая проба не открыла TCP — значит домен не резолвится
                        // либо заблокирован по IP, и техники обхода тут ни при чём.
                        if result.direct == ConnectFailed {
                            log::log_t(&log_tx, LogLevel::Warning, "log.diag_ip_block", vec![("domain", domain.clone())]);
                        } else {
                            log::log_t(&log_tx, LogLevel::Warning, "log.diag_bypass_failed", vec![("domain", domain.clone())]);
                        }
                    }
                }

                // QUIC отмечается отдельно: он не участвует в лестнице стратегий
                // (прокси гоняет TCP), но знать, что UDP/443 проходит, полезно.
                //
                // Сравнение именно с UdpReachable, а не с Success: проба доказывает
                // достижимость, а не работоспособность QUIC в приложении.
                if result.quic == UdpReachable && result.direct != Success {
                    log::log_t(&log_tx, LogLevel::Info, "log.diag_quic_works", vec![("domain", domain.clone())]);
                }

                log::log(&log_tx, LogLevel::Info, "__DIAGNOSTICS_DONE__");
            });
        }

        Action::RunDiagnosticsAll => {
            app.diagnostics_running = true;
            let log_tx = log_tx.clone();
            let config = Arc::clone(config);
            let domains = Arc::clone(domains);
            let strategies = Arc::clone(strategies);

            rt.spawn(async move {
                // Домены независимы, поэтому проверяются группами параллельно.
                // Раньше прогон шёл строго по очереди, и общее время было суммой
                // таймаутов: на заблокированном домене каждая проба ждёт молчания.
                //
                // Ограничение снижено с шести до четырёх: вместе с паузами между
                // пробами это уменьшает суммарную интенсивность зондирования.
                // Наблюдения показали, что плотная серия подключений сама
                // ухудшает вердикт — успехи приходились на быстрый проход
                // с малым числом проб, а не на плотный тщательный.
                const CONCURRENCY: usize = 4;

                log::log_t(&log_tx, LogLevel::Info, "log.diag_all_started", vec![("count", domains.len().to_string())]);

                // Параметры прогона в лог: результат зависит не только от домена
                // и техники, но и от плотности зондирования, числа проб и
                // параллельности. Без записи условий прогоны разных дней
                // сравнивать нельзя — а именно сравнением и подбирается пауза.
                log::log_t(&log_tx, LogLevel::Info, "log.diag_params", vec![
                    ("gap_min", config.probe_gap_min_ms.to_string()),
                    ("gap_max", config.probe_gap_max_ms.to_string()),
                    ("trials", crate::engine::diagnostics::TRIALS_PER_POSITION.to_string()),
                    ("concurrency", CONCURRENCY.to_string()),
                ]);

                // Накопленная обратная связь с прошлых прогонов: сколько раз
                // выбранные стратегии применялись и сколько раз подвели.
                // Домены, где бой расходится с диагностикой сильнее всего.
                // Пять применений — минимум, при котором доля неудач хоть
                // что-то значит.
                for (domain, strategy, predicted, live_fail_rate) in
                    strategies.live_disagreements(5).into_iter().take(5)
                {
                    if live_fail_rate > 0.2 {
                        log::log_nested_t(&log_tx, LogLevel::Warning, "log.live_disagreement", "strategy", strategy.label_key(), vec![
                            ("domain", domain),
                            ("predicted", format!("{:.2}", predicted)),
                            ("live", format!("{:.0}", live_fail_rate * 100.0)),
                        ]);
                    }
                }

                let stats = strategies.verification_stats();
                if stats.total > 0 {
                    log::log_t(&log_tx, LogLevel::Info, "log.verification_stats", vec![
                        ("total", stats.total.to_string()),
                        ("failures", stats.failures.to_string()),
                        ("rate", format!("{:.1}", stats.failure_rate().unwrap_or(0.0) * 100.0)),
                        ("invalidations", stats.invalidations.to_string()),
                    ]);
                }

                // Домены сортируем, чтобы прогон был воспроизводимым и лог
                // читался одинаково от запуска к запуску.
                let mut list: Vec<String> = domains.iter().cloned().collect();
                list.sort();

                warn_if_fake_unavailable(&log_tx);



                let mut found = 0usize;
                // Домены без результата откладываем на второй проход:
                // часть техник срабатывает вероятностно, и при трёх пробах
                // с досрочным прекращением домен может быть объявлен мёртвым
                // просто по невезению.
                let mut retry: Vec<String> = Vec::new();

                for chunk in list.chunks(CONCURRENCY) {
                    let mut running = Vec::with_capacity(chunk.len());

                    for domain in chunk {
                        let domain = domain.clone();
                        let config = Arc::clone(&config);
                        running.push(tokio::spawn(async move {
                            let timing = crate::engine::diagnostics::ProbeTiming {
                    gap_min_ms: config.probe_gap_min_ms,
                    gap_max_ms: config.probe_gap_max_ms,
                    hello_size: crate::engine::diagnostics::browser_hello_size(),
                };
                let result = crate::engine::diagnostics::diagnose(&domain, &config.bypass, timing).await;
                            (domain, result)
                        }));
                    }

                    for task in running {
                        let Ok((domain, result)) = task.await else {
                            continue;
                        };

                        match strategy::choose_from_diagnostics(&result) {
                            Some(chosen) => {
                                // Сохраняем вместе с уверенностью, на которой было
                                // принято решение — иначе через сутки известно лишь,
                                // что стратегия «когда-то была выбрана».
                                strategies.set(&domain, HelloClass::Large, chosen, strategy::confidence_of(&result, chosen));
                                found += 1;
                                log::log_nested_t(&log_tx, LogLevel::Success, "log.strategy_chosen", "strategy", chosen.label_key(), vec![
                                    ("domain", domain.clone()),
                                ]);
                            }
                            None => {
                                retry.push(domain);
                            }
                        }
                    }
                }

                // Второй проход: больше проб, без досрочного прекращения.
                // Цена времени оправдана — доменов здесь немного.
                if !retry.is_empty() {
                    log::log_t(&log_tx, LogLevel::Info, "log.diag_retry_started", vec![
                        ("count", retry.len().to_string()),
                    ]);

                    for chunk in retry.chunks(CONCURRENCY) {
                        let mut running = Vec::with_capacity(chunk.len());

                        for domain in chunk {
                            let domain = domain.clone();
                            let config = Arc::clone(&config);
                            running.push(tokio::spawn(async move {
                                let timing = crate::engine::diagnostics::ProbeTiming {
                                    gap_min_ms: config.probe_gap_min_ms,
                                    gap_max_ms: config.probe_gap_max_ms,
                                    hello_size: crate::engine::diagnostics::browser_hello_size(),
                                };
                                let result = crate::engine::diagnostics::diagnose_thorough(&domain, &config.bypass, timing).await;
                                (domain, result)
                            }));
                        }

                        for task in running {
                            let Ok((domain, result)) = task.await else { continue };

                            // Тщательный проход измерил все техники, поэтому
                            // выбор идёт по функции полезности, а не по порядку
                            // в лестнице: при равной надёжности предпочитается
                            // более быстрая.
                            let weights = strategy::RewardWeights {
                                reliability: config.reward_reliability,
                                latency: config.reward_latency,
                            };
                            match strategy::choose_best(&result, weights) {
                                Some((chosen, score)) => {
                                    strategies.set(&domain, HelloClass::Large, chosen, strategy::confidence_of(&result, chosen));
                                    found += 1;
                                    log::log_nested_t(&log_tx, LogLevel::Success, "log.strategy_chosen_retry", "strategy", chosen.label_key(), vec![
                                        ("domain", domain.clone()),
                                    ]);
                                    // Сравнение техник в лог: видно, был ли выбор
                                    // очевидным или между близкими вариантами.
                                    log::log_t(&log_tx, LogLevel::Info, "log.reward_table", vec![
                                        ("domain", domain.clone()),
                                        ("score", format!("{:.2}", score)),
                                        ("table", reward_table(&result, weights)),
                                    ]);
                                }
                                None => {
                                    // Старая запись заменяется отказом (или убирается, если
                                    // сервер был недосягаем): иначе одна случайная удача
                                    // прошлого прогона живёт до конца TTL и применяется
                                    // в бою, хотя воспроизводимо не работает.
                                    strategies.record_nothing_worked(&domain, HelloClass::Large, &result);
                                    log::log_t(&log_tx, LogLevel::Warning, "log.strategy_not_found", vec![("domain", domain.clone())]);
                                    report_diagnostics(&log_tx, &domain, &result);
                                }
                            }
                        }
                    }
                }

                match save_store(&strategies).await {
                    Ok(()) => {
                        log::log_t(&log_tx, LogLevel::Success, "log.diag_all_done", vec![
                            ("found", found.to_string()),
                            ("total", strategies.len().to_string()),
                        ]);
                    }
                    Err(e) => {
                        log::log_t(&log_tx, LogLevel::Error, "error.strategy_write", vec![("error", e.to_string())]);
                    }
                }

                log::log(&log_tx, LogLevel::Info, "__DIAGNOSTICS_DONE__");
            });
        }

        Action::SaveConfigField(path, new_value) => {
            let log_tx = log_tx.clone();
            let proxy_started = app.proxy_started;
            rt.spawn(async move {
                let result = tokio::task::spawn_blocking(move || {
                    config_editor::save_field(path, &new_value)
                }).await;

                match result {
                    Ok(Ok(())) => {
                        if proxy_started {
                            log::log_t(&log_tx, LogLevel::Warning, "config.field_restart", vec![("field", path.to_string())]);
                        } else {
                            log::log_t(&log_tx, LogLevel::Success, "config.field_saved", vec![("field", path.to_string())]);
                        }
                    }
                    Ok(Err(e)) => log::log_err(&log_tx, LogLevel::Error, e),
                    Err(e) => log::log_t(&log_tx, LogLevel::Error, "log.save_task_error", vec![("error", e.to_string())]),
                }
            });
        }

        Action::SaveDomains(list, domains_snapshot) => {
            let log_tx = log_tx.clone();
            let proxy_started = app.proxy_started;
            rt.spawn(async move {
                let result = tokio::task::spawn_blocking(move || {
                    domains_editor::save_domains(list, &domains_snapshot)
                }).await;

                match result {
                    Ok(Ok(())) => {
                        let level = if proxy_started { LogLevel::Warning } else { LogLevel::Success };
                        log::log_t(&log_tx, level, list.saved_key(proxy_started), vec![]);
                    }
                    Ok(Err(e)) => log::log_err(&log_tx, LogLevel::Error, e),
                    Err(e) => log::log_t(&log_tx, LogLevel::Error, "log.save_task_error", vec![("error", e.to_string())]),
                }
            });
        }

        Action::StartProxy if app.diagnostics_only => {
            // Режим «только диагностика»: смотреть на сеть можно,
            // менять трафик — нет.
            log::log_t(log_tx, LogLevel::Warning, "log.diagnostics_only_mode", vec![]);
        }

        Action::StartProxy => {
            // Отмену старых слушателей ждём в фоновой задаче, а не здесь:
            // `run` вызывается прямо из event loop терминала, и блокирующий
            // sleep замораживал интерфейс на полсекунды при каждом перезапуске.
            let old_token = app.proxy_token.take();

            // Перечитываем конфиг и список доменов. Раньше перезапуск брал
            // значения, прочитанные при старте программы, и сообщения
            // «изменится после перезапуска прокси» были неправдой: правки из
            // редакторов применялись только после перезапуска всей программы.
            reload(app, config, domains);

            let new_token = CancellationToken::new();
            app.proxy_token = Some(new_token.clone());
            app.proxy_started = true;
            // Статусы ON/OFF больше здесь не выставляются: их ставят сами
            // слушатели после успешного bind (см. metrics.set_*_listening).
            // Иначе интерфейс показывал ON даже когда все порты заняты.

            let config = Arc::clone(config);
            let domains = Arc::clone(domains);
            let log_tx = log_tx.clone();
            let metrics = Arc::clone(metrics);
            let ip_cache = Arc::clone(ip_cache);

            let strategies = Arc::clone(strategies);

            rt.spawn(async move {
                // Порты освобождаются не мгновенно: слушатель снимается по
                // token.cancelled() в select!, и bind нового до этого момента
                // упал бы с «address already in use».
                if let Some(old_token) = old_token {
                    old_token.cancel();
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                crate::proxy::run_all(config, domains, log_tx, metrics, new_token, ip_cache, strategies).await;
            });

            app.push_log_t(LogLevel::Success, "startup.proxy_started", vec![]);
        }
    }
}

/// Перечитывает config.toml и bypass_domains.txt перед перезапуском прокси.
///
/// Первый запуск прокси тоже проходит здесь — это дешевле, чем помнить,
/// менялось ли что-нибудь: файлы маленькие.
fn reload(app: &mut App, config: &mut Arc<Config>, domains: &mut Arc<HashSet<String>>) {
    match crate::config::load_config() {
        Ok(fresh) => {
            // Резолвер — синглтон, инициализированный при старте (OnceLock),
            // переинициализировать его на лету нельзя. Честно предупреждаем.
            if fresh.resolve_via_doh != config.resolve_via_doh
                || fresh.doh_provider != config.doh_provider
                || fresh.smart_dns_provider != config.smart_dns_provider
            {
                app.push_log_t(LogLevel::Warning, "startup.resolver_restart_needed", vec![]);
            }
            *config = Arc::new(fresh);
        }
        Err(e) => {
            // Битый конфиг не должен ронять уже работающую программу.
            app.push_log_t(LogLevel::Error, "startup.config_reload_failed", vec![("error".to_string(), e)]);
            return;
        }
    }

    let (fresh_domains, domains_error) = crate::config::load_bypass_domains();
    if let Some(reason) = domains_error {
        app.push_log_t(LogLevel::Error, "startup.domains_missing", vec![("error".to_string(), reason)]);
    } else if fresh_domains.is_empty() {
        app.push_log_t(LogLevel::Warning, "startup.domains_empty", vec![]);
    }
    *domains = Arc::new(fresh_domains);

    app.status.domains_count = domains.len();
    app.status.tcp_port = config.port;
    app.status.udp_port = config.udp_port;
    app.status.socks5_port = config.socks5_port;
    app.status.transparent_port = config.transparent_port;

    if app.proxy_started {
        app.push_log_t(LogLevel::Info, "startup.config_reloaded", vec![]);
    }
}
