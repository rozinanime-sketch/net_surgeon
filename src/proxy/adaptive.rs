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
}

impl Selected {
    pub const DIRECT: Selected = Selected { strategy: Strategy::None, source: None };
}

/// Что нужно для выбора — одно и то же во всех трёх путях.
pub struct Context<'a> {
    pub strategies: &'a Arc<StrategyStore>,
    pub bypass_params: &'a BypassParams,
    pub ttl_hours: u64,
    pub log_tx: &'a LogSender,
}

/// Стратегия для соединения, которому нужен обход.
pub fn select(ctx: &Context<'_>, domain: &str, hello_len: usize) -> Selected {
    let class = HelloClass::of(hello_len);

    if let Some((cached, kind)) = ctx.strategies.lookup_detailed(domain, class, ctx.ttl_hours) {
        let key = match kind {
            MatchKind::Exact => "log.strategy_from_cache",
            MatchKind::Inherited => "log.strategy_inherited",
        };
        log_nested_t(ctx.log_tx, LogLevel::Info, key, "strategy", cached.label_key(), vec![
            ("domain", domain.to_string()),
        ]);
        return Selected { strategy: cached, source: Some(class) };
    }

    // Для этого размера измерения нет — ставим его в очередь.
    spawn_diagnosis(ctx, domain, class, hello_len);

    // Пока диагностика идёт: для маленького пакета лучше всего то, что
    // сработало с большим, — это хотя бы измерено на этом домене.
    //
    // Кроме двух TLS-записей: с маленьким ClientHello они как раз и не
    // проходят (ради этого случая размеры и разделены), так что брать их
    // у большого пакета значит заведомо повесить соединение.
    if class == HelloClass::Small
        && let Some((other, _)) = ctx.strategies.lookup_detailed(domain, HelloClass::Large, ctx.ttl_hours)
        && other != Strategy::TlsRecord
    {
        log_nested_t(ctx.log_tx, LogLevel::Info, "log.strategy_other_size", "strategy", other.label_key(), vec![
            ("domain", domain.to_string()),
            ("bytes", hello_len.to_string()),
        ]);
        return Selected { strategy: other, source: None };
    }

    Selected { strategy: unmeasured_default(class), source: None }
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
pub fn record_outcome(ctx: &Context<'_>, domain: &str, selected: Selected, responded: bool) {
    let Some(class) = selected.source else { return };
    if selected.strategy == Strategy::None {
        return;
    }
    if !ctx.strategies.record_outcome(domain, class, responded) {
        return;
    }

    log_nested_t(ctx.log_tx, LogLevel::Warning, "log.strategy_invalidated", "strategy", selected.strategy.label_key(), vec![
        ("domain", domain.to_string()),
    ]);
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
        let Ok(_slot) = auto_diagnosis_slots().acquire().await else { return };

        log_t(&log_tx, LogLevel::Info, "log.auto_diag_started", vec![
            ("domain", domain.clone()),
            ("bytes", hello_len.to_string()),
        ]);

        // Проба того же размера, что пришёл в бою: ради этого всё и делается.
        let timing = ProbeTiming { hello_size: hello_len, ..ProbeTiming::default() };
        let result = diagnostics::diagnose(&domain, &params, timing).await;

        match strategy::choose_from_diagnostics(&result) {
            Some(chosen) => {
                store.set(&domain, class, chosen, strategy::confidence_of(&result, chosen));
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
                log_t(&log_tx, LogLevel::Warning, "log.auto_diag_nothing", vec![
                    ("domain", domain.clone()),
                    ("bytes", hello_len.to_string()),
                ]);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_parts() -> (Arc<StrategyStore>, BypassParams, LogSender) {
        let (tx, _rx) = crate::observability::logging::channel();
        let params: BypassParams = toml::from_str(
            "split_pos_min = 4\nsplit_pos_max = 12\nsplit_delay_ms = 3\nwindow_clamp = 0\n",
        ).expect("параметры обхода");
        (Arc::new(StrategyStore::new()), params, tx)
    }

    #[tokio::test]
    async fn small_hello_without_its_own_entry_borrows_large_but_does_not_own_it() {
        let (store, params, tx) = ctx_parts();
        store.set("updates.discord.com", HelloClass::Large, Strategy::SniSplit, 0.44);
        // Диагностика уже «идёт» — тест не должен лезть в сеть
        store.claim_auto_diagnosis("updates.discord.com", HelloClass::Small, AUTO_DIAGNOSIS_COOLDOWN);

        let ctx = Context { strategies: &store, bypass_params: &params, ttl_hours: 24, log_tx: &tx };
        let selected = select(&ctx, "updates.discord.com", 273);
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
        let small = select(&ctx, "stable.dl2.discordapp.net", 274);
        assert_eq!((small.strategy, small.source), (Strategy::Oob, None));
        // Большому пакету по-прежнему достаются две TLS-записи
        let large = select(&ctx, "stable.dl2.discordapp.net", 1800);
        assert_eq!(large.strategy, Strategy::TlsRecord);

        // Две TLS-записи большого пакета маленькому не одалживаются
        store.set("updates.discord.com", HelloClass::Large, Strategy::TlsRecord, 0.44);
        let borrowed = select(&ctx, "updates.discord.com", 273);
        assert_eq!((borrowed.strategy, borrowed.source), (Strategy::Oob, None));
    }

    #[tokio::test]
    async fn measured_small_entry_is_used_for_small_hello() {
        let (store, params, tx) = ctx_parts();
        store.set("updates.discord.com", HelloClass::Large, Strategy::TlsRecord, 0.44);
        store.set("updates.discord.com", HelloClass::Small, Strategy::Oob, 0.44);

        let ctx = Context { strategies: &store, bypass_params: &params, ttl_hours: 24, log_tx: &tx };
        let small = select(&ctx, "updates.discord.com", 273);
        assert_eq!((small.strategy, small.source), (Strategy::Oob, Some(HelloClass::Small)));
        let large = select(&ctx, "updates.discord.com", 1800);
        assert_eq!((large.strategy, large.source), (Strategy::TlsRecord, Some(HelloClass::Large)));
    }
}
