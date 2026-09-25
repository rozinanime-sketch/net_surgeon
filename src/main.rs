//! Точка входа: разобрать флаги, поднять общее состояние, отдать управление.
//!
//! Вся логика живёт в библиотеке (`src/lib.rs`) — здесь только выбор режима.
//! Так ядро можно собрать отдельно: под Android, например, нужен один лишь
//! SOCKS5-сервер, подключённый к `VpnService`, и ни терминал, ни разбор
//! аргументов там не при чём.

use net_surgeon::{bootstrap, headless};

/// Перевод сообщения запуска на язык по умолчанию.
fn tr(key: &str, args: &[(&str, String)]) -> String {
    let args: Vec<(String, String)> = args.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
    net_surgeon::observability::i18n::translate(net_surgeon::default_language(), key, &args)
}

/// Как запускаться.
enum Mode {
    /// Терминальный интерфейс.
    Tui,
    /// Без интерфейса: слушатели плюс логи в stdout.
    Headless,
    /// Только диагностика, трафик не меняется.
    DiagnoseOnly,
}

fn parse_mode() -> Mode {
    // Полноценный разбор аргументов не заводим: опций три, и каждая
    // отвечает на вопрос «что делать», а не «как именно».
    let args: Vec<String> = std::env::args().collect();
    let has = |flag: &str| args.iter().any(|a| a == flag);

    if has("--diagnose-only") {
        return Mode::DiagnoseOnly;
    }

    // Без feature `tui` интерфейса в сборке просто нет, и выбирать нечего.
    if has("--headless") || !cfg!(feature = "tui") {
        return Mode::Headless;
    }

    Mode::Tui
}

#[tokio::main]
async fn main() {
    net_surgeon::set_locale(net_surgeon::default_language());

    let startup = match bootstrap() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[✗] {}", e);
            std::process::exit(1);
        }
    };

    // `--firewall` передаёт run.sh: перехват ставит сама программа, и ядро
    // снимет его при любом её завершении (см. src/firewall.rs).
    #[cfg(target_os = "linux")]
    if std::env::args().any(|a| a == "--firewall") {
        let cfg = &startup.config;
        match net_surgeon::firewall::install(cfg.transparent_port, cfg.udp_port) {
            Ok(msg) => eprintln!("[✓] {}", msg),
            Err(e) => {
                eprintln!("[✗] {}", tr("startup.transparent_failed", &[("error", e)]));
                std::process::exit(1);
            }
        }
    }

    match parse_mode() {
        Mode::Headless => headless::run(false, startup).await,
        Mode::DiagnoseOnly => run_diagnose_only(startup).await,
        Mode::Tui => run_tui(startup),
    }

    #[cfg(target_os = "linux")]
    net_surgeon::firewall::release();
}

/// `--diagnose-only` в сборке с интерфейсом остаётся интерактивным: смотреть
/// на сеть удобнее в TUI. Без интерфейса — сообщение и выход.
async fn run_diagnose_only(startup: net_surgeon::Startup) {
    #[cfg(feature = "tui")]
    {
        run_tui_with(startup, true);
    }
    #[cfg(not(feature = "tui"))]
    {
        headless::run(true, startup).await;
    }
}

#[cfg(feature = "tui")]
fn run_tui(startup: net_surgeon::Startup) {
    run_tui_with(startup, false);
}

#[cfg(not(feature = "tui"))]
fn run_tui(_startup: net_surgeon::Startup) {
    unreachable!("без feature `tui` parse_mode никогда не вернёт Mode::Tui");
}

#[cfg(feature = "tui")]
fn run_tui_with(startup: net_surgeon::Startup, diagnostics_only: bool) {
    let net_surgeon::Startup { config, domains, domains_error, metrics, ip_cache, strategies } = startup;

    if let Err(e) = net_surgeon::cli::run(
        diagnostics_only,
        config,
        domains,
        domains_error,
        metrics,
        ip_cache,
        strategies,
    ) {
        eprintln!("[✗] {}", tr("startup.tui_error", &[("error", e.to_string())]));
        eprintln!("[i] {}", tr("startup.tui_hint", &[]));
        std::process::exit(1);
    }
}
