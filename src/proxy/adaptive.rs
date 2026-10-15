//! Выбор стратегии под конкретное соединение — с учётом размера ClientHello.
//!
//! # Зачем
//!
//! Диагностика мерила техники пробой одного размера (~1500 байт, как у
//! браузера), и стратегия записывалась на домен целиком. Но размер сам по
//! себе меняет вердикт: для updates.discord.com две TLS-записи проходили
//! с ClientHello curl (1584 байта) и не проходили с ClientHello rustls
//! у программы обновления Discord (273 байта). Программа висела на
//! «Проверке обновлений», а диагностика считала домен решённым.
//!
//! # Как
//!
//! Стратегии хранятся отдельно для маленьких и больших ClientHello
//! ([`HelloClass`]). Если для размера, который пришёл в бою, измерения нет,
//! диагностика запускается сама, в фоне, пробой ТОГО ЖЕ размера. Пока она
//! идёт, соединение получает запасной вариант, и ручная настройка не нужна:
//! следующая попытка программы уже пойдёт с измеренной стратегией.
//!
//! Все три пути (HTTPS-туннель, прозрачный режим, SOCKS5) выбирают стратегию
//! здесь, чтобы логика не разъезжалась.

use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tokio::sync::Semaphore;

use crate::config::BypassParams;
use crate::engine::diagnostics::{self, ProbeTiming};
use crate::engine::strategy::{self, HelloClass, MatchKind, Strategy, StrategyStore};
use crate::observability::logging::{log_nested_t, log_t, LogLevel, LogSender};

/// Как долго не повторять автоматическую диагностику той же пары
/// «домен + размер» — и пока она идёт, и если она ничего не нашла.
const AUTO_DIAGNOSIS_COOLDOWN: Duration = Duration::from_secs(10 * 60);

/// Сколько автоматических диагностик идёт одновременно. Каждая — серия
/// подключений к серверу; десяток сразу выглядел бы для DPI как сканирование.
const AUTO_DIAGNOSIS_CONCURRENCY: usize = 2;

fn auto_diagnosis_slots() -> &'static Semaphore {
    static SLOTS: OnceLock<Semaphore> = OnceLock::new();
    SLOTS.get_or_init(|| Semaphore::new(AUTO_DIAGNOSIS_CONCURRENCY))
}

/// Выбранная стратегия и запись, из которой она взята.
#[derive(Debug, Clone, Copy)]
pub struct Selected {
    pub strategy: Strategy,
    /// Класс записи, которой принадлежит стратегия. `None` — запасной
    /// вариант без своей записи: исход такого соединения никому не
    /// засчитывается. Иначе провалы программы обновления, временно
    /// взявшей стратегию браузера, сбросили бы рабочую запись браузера.
    pub source: Option<HelloClass>,
    /// Сеть на момент выбора (`net_state::net_generation`). Сменилась, пока
    /// соединение жило, — исход относится к прежней сети, и записи новой его
    /// не засчитывают.
    pub net: u64,
    /// Размер ClientHello соединения: если запись сбросят по его исходу,
    /// передиагностика мерит пакетом того же размера. 0 — неизвестен.
    pub hello_len: usize,
}

impl Selected {
    pub const DIRECT: Selected = Selected { strategy: Strategy::None, source: None, net: 0, hello_len: 0 };

    pub fn new(strategy: Strategy, source: Option<HelloClass>) -> Selected {
        Selected { strategy, source, net: crate::engine::net_state::net_generation(), hello_len: 0 }
    }
}

/// Что нужно для выбора — одно и то же во всех трёх путях.
pub struct Context<'a> {
    pub strategies: &'a Arc<StrategyStore>,
    pub bypass_params: &'a BypassParams,
    pub ttl_hours: u64,
    pub log_tx: &'a LogSender,
}

/// Стратегия для соединения, которому нужен обход.
///
/// `hello` — первый пакет клиента (ClientHello): по его размеру выбирается
/// класс стратегии, а сам он становится образцом для проб диагностики.
pub fn select(ctx: &Context<'_>, domain: &str, hello: &[u8]) -> Selected {
    select_with(ctx, domain, hello, false)
}

/// То же для перехвата пакетов (Windows): он умеет не всё.
///
/// Запись с техникой, недоступной на пакетах (две TLS-записи, OOB, —
/// скорее всего, измерена прокси до включения перехвата), считается
/// отсутствующей: домен перемеряется пакетными техниками. Применить вместо
/// неё что-то «похожее» значило бы получать провалы, сбрасывать запись и
/// снова мерить то же самое по кругу.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn select_packet(ctx: &Context<'_>, domain: &str, hello: &[u8]) -> Selected {
    select_with(ctx, domain, hello, true)
}

fn select_with(ctx: &Context<'_>, domain: &str, hello: &[u8], packet: bool) -> Selected {
    let hello_len = crate::bypass::tls::client_hello_len(hello);
    // Ручная и массовая диагностика мерят пакетом того же размера и вида,
    // что шлёт клиент: все боевые пути проходят здесь.
    diagnostics::note_battle_hello(hello);
    Selected { hello_len, ..choose(ctx, domain, hello_len, packet) }
}

fn choose(ctx: &Context<'_>, domain: &str, hello_len: usize, packet: bool) -> Selected {
    // Seqovl — только под перехватом пакетов (сокету номер последовательности
    // не задать); прочие пакетные техники — как раньше: под перехватом лишь
    // те, что он умеет применить.
    let usable = |s: Strategy| match s {
        Strategy::Seqovl | Strategy::FakedSplit => packet,
        _ => !packet || crate::bypass::packet_mode::supports(s),
    };
    let class = HelloClass::of(hello_len);

    // Закреплённая техника (pin_strategies.txt) — раньше всего: жёстко, в
    // обход диагностики и кэша, не зависит от сети. Для хотспота с меняющимся
    // IP шлюза это единственное, что переживает смену ключа сети.
    if let Some(forced) = crate::engine::pin::pinned(domain).filter(|s| usable(*s)) {
        log_nested_t(ctx.log_tx, LogLevel::Info, "log.strategy_pinned", "strategy", forced.label_key(), vec![
            ("domain", domain.to_string()),
        ]);
        return Selected::new(forced, None);
    }

    if let Some((cached, kind)) = ctx.strategies.lookup_detailed(domain, class, ctx.ttl_hours)
        && usable(cached)
    {
        let key = match kind {
            MatchKind::Exact => "log.strategy_from_cache",
            MatchKind::Inherited => "log.strategy_inherited",
        };
        log_nested_t(ctx.log_tx, LogLevel::Info, key, "strategy", cached.label_key(), vec![
            ("domain", domain.to_string()),
        ]);
        return Selected::new(cached, Some(class));
    }

    // Для этого размера измерения нет — ставим его в очередь.
    spawn_diagnosis(ctx, domain, class, hello_len);

    // Пока диагностика идёт: для маленького пакета лучше всего то, что
    // сработало с большим, — это хотя бы измерено на этом домене.
    //
    // Кроме двух TLS-записей: с маленьким ClientHello они как раз и не
    // проходят (ради этого случая размеры и разделены), так что брать их
    // у большого пакета значит заведомо повесить соединение.
    //
    // И кроме отказа: «ничего не помогло» снято с большим пакетом и о
    // маленьком ничего не говорит, а одолжить его значит отправить маленький
    // ClientHello вовсе без обхода, хотя его ещё никто не мерил.
    if class == HelloClass::Small
        && let Some((other, _)) = ctx.strategies.lookup_detailed(domain, HelloClass::Large, ctx.ttl_hours)
        && other != Strategy::TlsRecord
        && usable(other)
        && !ctx.strategies.is_resigned(domain, HelloClass::Large, ctx.ttl_hours)
    {
        log_nested_t(ctx.log_tx, LogLevel::Info, "log.strategy_other_size", "strategy", other.label_key(), vec![
            ("domain", domain.to_string()),
            ("bytes", hello_len.to_string()),
        ]);
        return Selected::new(other, None);
    }

    // Под перехватом пакетов до конца диагностики берём hostfakesplit: он
    // прячет само имя разрешённым (seqovl убран — живой тест его не пробивал).
    let fallback = if packet { Strategy::HostFakeSplit } else { unmeasured_default(class) };
    Selected::new(fallback, None)
}

/// Техника для домена, по которому нет подходящего измерения.
///
/// Раньше это всегда были две TLS-записи. Для большого ClientHello это
/// по-прежнему самое сильное, а для маленького — наоборот: наблюдалось,
/// что они не проходят (updates.discord.com, 273 байта), и соединения,
/// пришедшие до конца автодиагностики, висели впустую. Диагностика таких
/// доменов выбирала oob или disorder; oob дешевле — без ретрансмита.
/// Без поддержки OOB на платформе остаётся прежний вариант.
fn unmeasured_default(class: HelloClass) -> Strategy {
    match class {
        HelloClass::Small if crate::bypass::socket::supports_ttl_tricks() => Strategy::Oob,
        _ => Strategy::TlsRecord,
    }
}

/// Отмечает исход соединения и, если запись сброшена, сохраняет это на диск.
/// Удалось ли соединение со стратегией: сервер ответил TLS, И рукопожатие
/// завершилось — клиент после ClientHello отправил ещё что-то (Finished и
/// запрос). Раньше хватало первых байт ответа: DPI, который режет посреди
/// рукопожатия (ServerHello приходит, дальше тишина), выглядел успехом, и
/// нерабочая стратегия не сбрасывалась никогда — так висел Discord.
/// `client_sent` — всё, что клиент отправил серверу за соединение.
pub fn handshake_completed(selected: &Selected, responded: bool, client_sent: u64) -> bool {
    responded && (selected.hello_len == 0 || client_sent > selected.hello_len as u64)
}

pub fn record_outcome(ctx: &Context<'_>, domain: &str, selected: Selected, responded: bool) {
    // Стратегия `None` из собственной записи домена тоже проверяется: это
    // вердикт «прямое соединение работает», и он может оказаться ошибочным.
    // Отказ («ничего не помогло») хранилище само не засчитывает.
    let Some(class) = selected.source else { return };
    if selected.net != crate::engine::net_state::net_generation() {
        return;
    }
    if !ctx.strategies.record_outcome(domain, class, selected.strategy, responded, ctx.ttl_hours) {
        return;
    }

    log_nested_t(ctx.log_tx, LogLevel::Warning, "log.strategy_invalidated", "strategy", selected.strategy.label_key(), vec![
        ("domain", domain.to_string()),
    ]);
    // Сразу перемерить, не дожидаясь следующего соединения без записи и не
    // глядя на паузу автодиагностики. Иначе поддомен после сброса брал
    // стратегию родителя — обычно ту же нерабочую, — и диагностика не
    // запускалась вовсе: так Discord и висел, когда провайдер перестал
    // пропускать OOB и две TLS-записи.
    if selected.hello_len > 0 {
        ctx.strategies.forget_auto_diagnosis(domain, class);
        spawn_diagnosis(ctx, domain, class, selected.hello_len);
    }
    // Сброс закрепляется на диске, иначе после перезапуска вернётся та же
    // нерабочая запись. Запись файла — в блокирующий пул: здесь обработчик
    // соединения, и синхронный вызов задержал бы рабочий поток tokio.
    let store = Arc::clone(ctx.strategies);
    let log_tx = ctx.log_tx.clone();
    tokio::task::spawn_blocking(move || {
        if let Err(e) = store.save() {
            log_t(&log_tx, LogLevel::Error, "error.strategy_write", vec![("error", e.to_string())]);
        }
    });
}

fn spawn_diagnosis(ctx: &Context<'_>, domain: &str, class: HelloClass, hello_len: usize) {
    // Без имени мерить нечего: проба строит ClientHello с этим SNI.
    if domain.parse::<IpAddr>().is_ok() {
        return;
    }
    if !ctx.strategies.claim_auto_diagnosis(domain, class, AUTO_DIAGNOSIS_COOLDOWN) {
        return;
    }

    let domain = domain.to_string();
    let store = Arc::clone(ctx.strategies);
    let params = ctx.bypass_params.clone();
    let log_tx = ctx.log_tx.clone();

    tokio::spawn(async move {
        let Ok(slot) = auto_diagnosis_slots().acquire().await else { return };

        log_t(&log_tx, LogLevel::Info, "log.auto_diag_started", vec![
            ("domain", domain.clone()),
            ("bytes", hello_len.to_string()),
        ]);

        // Проба того же размера, что пришёл в бою: ради этого всё и делается.
        let timing = ProbeTiming { hello_size: hello_len, ..ProbeTiming::default() };
        let result = diagnostics::diagnose(&domain, &params, timing).await;
        if let Some(name) = &result.decoy_sni {
            log_t(&log_tx, LogLevel::Success, "log.decoy_sni_found", vec![
                ("domain", domain.clone()),
                ("name", name.clone()),
            ]);
        }

        // Слот освобождаем до freeze-проб: они идут через прокси и не должны
        // держать лимит одновременных диагностик (проба может ждать до ~30с).
        drop(slot);

        // Эскалация на decoy при заморозке: дешёвая техника может пройти
        // рукопожатие, но замёрзнуть после 16 КБ. freeze-проба это ловит и
        // переключает на fake (сокетный путь; в пакетном seqovl уже подобран).
        let chosen = strategy::choose_from_diagnostics(&result);
        let escalation = crate::engine::freeze::escalate_on_freeze(&domain, chosen, &log_tx).await;

        match escalation.strategy {
            Some(chosen) => {
                // Приманку, выбранную freeze-пробой, диагностика могла не
                // мерить: тогда уверенность — по одной прошедшей пробе.
                let mut confidence = strategy::confidence_of(&result, chosen);
                if escalation.escalated {
                    confidence = confidence.max(crate::observability::stats::wilson_lower_bound(1, 1));
                }
                store.set(&domain, class, chosen, confidence);
                log_nested_t(&log_tx, LogLevel::Success, "log.auto_diag_chosen", "strategy", chosen.label_key(), vec![
                    ("domain", domain.clone()),
                    ("bytes", hello_len.to_string()),
                ]);
                let save_log = log_tx.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    if let Err(e) = store.save() {
                        log_t(&save_log, LogLevel::Error, "error.strategy_write", vec![("error", e.to_string())]);
                    }
                })
                .await;
            }
            None => {
                // Запоминаем именно как решение, а не просто пишем в лог.
                // Иначе следующее же соединение снова возьмёт стратегию по
                // умолчанию и применит технику, которая только что провалила
                // все пробы, — а обратной связи по такому выбору нет.
                let key = if store.record_nothing_worked(&domain, class, &result) {
                    "log.auto_diag_nothing"
                } else {
                    "log.auto_diag_unreachable"
                };
                log_t(&log_tx, LogLevel::Warning, key, vec![
                    ("domain", domain.clone()),
                    ("bytes", hello_len.to_string()),
                ]);
                let save_log = log_tx.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    if let Err(e) = store.save() {
                        log_t(&save_log, LogLevel::Error, "error.strategy_write", vec![("error", e.to_string())]);
                    }
                })
                .await;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ClientHello ровно в `len` байт: по длине выбирается класс стратегии.
    fn hello(len: usize) -> Vec<u8> {
        crate::bypass::tls::build_decoy_hello("probe.example", len).expect("ClientHello такой длины")
    }

    fn ctx_parts() -> (Arc<StrategyStore>, BypassParams, LogSender) {
        let (tx, _rx) = crate::observability::logging::channel();
        let params: BypassParams = toml::from_str(
            "split_pos_min = 4\nsplit_pos_max = 12\nsplit_delay_ms = 3\nwindow_clamp = 0\n",
        ).expect("параметры обхода");
        (Arc::new(StrategyStore::new()), params, tx)
    }

    /// Сервер ответил, но клиент после ClientHello не отправил ничего —
    /// рукопожатие оборвано посреди, это провал, а не успех.
    #[test]
    fn cut_handshake_is_not_success() {
        let selected = Selected { hello_len: 1500, ..Selected::new(Strategy::Disorder, Some(HelloClass::Large)) };
        assert!(!handshake_completed(&selected, true, 1500), "только ClientHello");
        assert!(handshake_completed(&selected, true, 1580), "ClientHello и Finished");
        assert!(!handshake_completed(&selected, false, 5000), "сервер не ответил TLS");
    }

    /// Сброс записи запускает передиагностику сразу, даже в паузу
    /// автодиагностики: иначе поддомен брал нерабочую стратегию родителя.
    #[tokio::test]
    async fn invalidated_strategy_is_rediagnosed_at_once() {
        let (store, params, tx) = ctx_parts();
        store.set("discord.gg", HelloClass::Large, Strategy::Oob, 0.44);
        store.set("gateway.discord.gg", HelloClass::Large, Strategy::Oob, 0.44);
        // Пауза автодиагностики идёт — раньше она и мешала перемерить.
        store.claim_auto_diagnosis("gateway.discord.gg", HelloClass::Large, AUTO_DIAGNOSIS_COOLDOWN);
        let ctx = Context { strategies: &store, bypass_params: &params, ttl_hours: 24, log_tx: &tx };

        let selected = select(&ctx, "gateway.discord.gg", &hello(1800));
        assert_eq!(selected.hello_len, 1800);
        for _ in 0..3 {
            record_outcome(&ctx, "gateway.discord.gg", selected, false);
        }
        // Пауза снята и тут же занята новой диагностикой.
        assert!(!store.claim_auto_diagnosis("gateway.discord.gg", HelloClass::Large, AUTO_DIAGNOSIS_COOLDOWN));
    }

    #[tokio::test]
    async fn small_hello_without_its_own_entry_borrows_large_but_does_not_own_it() {
        let (store, params, tx) = ctx_parts();
        store.set("updates.discord.com", HelloClass::Large, Strategy::SniSplit, 0.44);
        // Диагностика уже «идёт» — тест не должен лезть в сеть
        store.claim_auto_diagnosis("updates.discord.com", HelloClass::Small, AUTO_DIAGNOSIS_COOLDOWN);

        let ctx = Context { strategies: &store, bypass_params: &params, ttl_hours: 24, log_tx: &tx };
        let selected = select(&ctx, "updates.discord.com", &hello(273));
        assert_eq!(selected.strategy, Strategy::SniSplit);
        assert_eq!(selected.source, None);

        // Сколько бы программа обновления ни проваливалась, запись браузера цела
        for _ in 0..10 {
            record_outcome(&ctx, "updates.discord.com", selected, false);
        }
        assert!(store.lookup_detailed("updates.discord.com", HelloClass::Large, 24).is_some());
    }

    #[tokio::test]
    async fn small_hello_never_gets_tls_record_before_measurement() {
        let (store, params, tx) = ctx_parts();
        store.claim_auto_diagnosis("stable.dl2.discordapp.net", HelloClass::Small, AUTO_DIAGNOSIS_COOLDOWN);
        store.claim_auto_diagnosis("stable.dl2.discordapp.net", HelloClass::Large, AUTO_DIAGNOSIS_COOLDOWN);
        store.claim_auto_diagnosis("updates.discord.com", HelloClass::Small, AUTO_DIAGNOSIS_COOLDOWN);
        let ctx = Context { strategies: &store, bypass_params: &params, ttl_hours: 24, log_tx: &tx };

        // Домен не измерялся вовсе
        let small = select(&ctx, "stable.dl2.discordapp.net", &hello(274));
        assert_eq!((small.strategy, small.source), (Strategy::Oob, None));
        // Большому пакету по-прежнему достаются две TLS-записи
        let large = select(&ctx, "stable.dl2.discordapp.net", &hello(1800));
        assert_eq!(large.strategy, Strategy::TlsRecord);

        // Две TLS-записи большого пакета маленькому не одалживаются
        store.set("updates.discord.com", HelloClass::Large, Strategy::TlsRecord, 0.44);
        let borrowed = select(&ctx, "updates.discord.com", &hello(273));
        assert_eq!((borrowed.strategy, borrowed.source), (Strategy::Oob, None));
    }

    /// Отказ, снятый с большим пакетом, маленькому не одалживается: иначе
    /// неизмеренный маленький ClientHello ушёл бы вовсе без обхода.
    #[tokio::test]
    async fn small_hello_does_not_borrow_large_resignation() {
        let (store, params, tx) = ctx_parts();
        store.set_resigned("stable.dl2.discordapp.net", HelloClass::Large);
        store.claim_auto_diagnosis("stable.dl2.discordapp.net", HelloClass::Small, AUTO_DIAGNOSIS_COOLDOWN);

        let ctx = Context { strategies: &store, bypass_params: &params, ttl_hours: 24, log_tx: &tx };
        let small = select(&ctx, "stable.dl2.discordapp.net", &hello(274));
        assert_eq!((small.strategy, small.source), (unmeasured_default(HelloClass::Small), None));

        // Сам большой пакет отказ соблюдает
        let large = select(&ctx, "stable.dl2.discordapp.net", &hello(1800));
        assert_eq!((large.strategy, large.source), (Strategy::None, Some(HelloClass::Large)));
    }

    /// «Прямое соединение работает» проверяется в бою: соединения без
    /// ответа сбрасывают запись, и домен уходит на переизмерение.
    #[tokio::test]
    async fn direct_verdict_is_verified_in_battle() {
        let (store, params, tx) = ctx_parts();
        store.set("flaky.example.com", HelloClass::Large, Strategy::None, 1.0);
        let ctx = Context { strategies: &store, bypass_params: &params, ttl_hours: 24, log_tx: &tx };

        let selected = select(&ctx, "flaky.example.com", &hello(1800));
        assert_eq!((selected.strategy, selected.source), (Strategy::None, Some(HelloClass::Large)));
        for _ in 0..3 {
            record_outcome(&ctx, "flaky.example.com", selected, false);
        }
        assert_eq!(store.lookup_detailed("flaky.example.com", HelloClass::Large, 24), None);
    }

    #[tokio::test]
    async fn measured_small_entry_is_used_for_small_hello() {
        let (store, params, tx) = ctx_parts();
        store.set("updates.discord.com", HelloClass::Large, Strategy::TlsRecord, 0.44);
        store.set("updates.discord.com", HelloClass::Small, Strategy::Oob, 0.44);

        let ctx = Context { strategies: &store, bypass_params: &params, ttl_hours: 24, log_tx: &tx };
        let small = select(&ctx, "updates.discord.com", &hello(273));
        assert_eq!((small.strategy, small.source), (Strategy::Oob, Some(HelloClass::Small)));
        let large = select(&ctx, "updates.discord.com", &hello(1800));
        assert_eq!((large.strategy, large.source), (Strategy::TlsRecord, Some(HelloClass::Large)));
    }
}
