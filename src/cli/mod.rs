mod app;
mod ui;
mod events;
mod config_editor;
mod domains_editor;
mod traffic_history;
mod i18n;
pub mod logger;

use tokio_util::sync::CancellationToken;
use crate::dns::ip_cache::IpDomainCache;

pub use app::{App, LogLevel};
pub use logger::{LogSender, log, log_t, log_nested_t};

use ratatui::{backend::CrosstermBackend, Terminal};
use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::io::{self, Stdout};
use std::time::Duration;
use std::sync::Arc;
use std::collections::HashSet;

use crate::config::Config;
use crate::metrics::Metrics;

fn install_panic_hook() {
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        original_hook(panic_info);
    }));
}

fn enter_background_mode(terminal: &mut Terminal<CrosstermBackend<Stdout>>, app: &App) -> io::Result<()> {
    use std::io::Write;

    restore_terminal(terminal)?;

    let msg = if app.language.code() == "ru" {
        "\n  Прокси работает в фоне. Нажмите Enter чтобы вернуться в интерфейс.\n"
    } else {
        "\n  Proxy running in background. Press Enter to return to the interface.\n"
    };
    println!("{}", msg);
    io::stdout().flush()?;

    let mut buf = String::new();
    let _ = std::io::stdin().read_line(&mut buf);

    *terminal = setup_terminal()?;
    terminal.clear()?;

    Ok(())
}

pub fn run(config: Arc<Config>, domains: Arc<HashSet<String>>, metrics: Arc<Metrics>, ip_cache: Arc<IpDomainCache>) -> io::Result<()> {
    install_panic_hook();

    let mut terminal = setup_terminal()?;
    let mut app = App::new();
    app.status.domains_count = domains.len();
    app.status.tcp_port = config.port;
    app.status.udp_port = config.udp_port;
    app.status.socks5_port = config.socks5_port;

    app.push_log(LogLevel::Info, "net surgeon запущен");

    let result = run_app(&mut terminal, &mut app, config, domains, metrics, ip_cache);

    restore_terminal(&mut terminal)?;

    result
}

fn run_app(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut App,
    config: Arc<Config>,
    domains: Arc<HashSet<String>>,
    metrics: Arc<Metrics>,
    ip_cache: Arc<IpDomainCache>,
) -> io::Result<()> {
    let (log_tx, mut log_rx) = logger::channel();
    let rt = tokio::runtime::Handle::current();

    let mut had_popup = false;
    let mut was_diagnostics_running = false;

    loop {
        let mut needs_clear = false;

        while let Ok(msg) = log_rx.try_recv() {
            match &msg.payload {
                logger::LogPayload::Plain(text) if text == "__DIAGNOSTICS_DONE__" => {
                    if let Some(screen) = app.diagnostics.as_mut() {
                        screen.running = false;
                    }
                    continue;
                }
                _ => {}
            }
            match msg.payload {
                logger::LogPayload::Plain(text) => {
                    app.push_log(msg.level, text);
                }
                logger::LogPayload::Translated { key, args } => {
                    app.push_log_t(msg.level, key, args);
                }
                logger::LogPayload::NestedTranslated { key, nested_arg, nested_key, args } => {
                    app.push_log_nested_t(msg.level, key, nested_arg, nested_key, args);
                }
            }
        }

        app.metrics = metrics.snapshot();
        app.traffic_history.record(app.metrics.bytes_rx, app.metrics.bytes_tx);

        let has_popup = app.overlay.is_some()
        || app.config_editor.is_some()
        || app.domains_editor.is_some()
        || app.diagnostics.is_some();

        if has_popup != had_popup {
            needs_clear = true;
        }
        had_popup = has_popup;

        let is_diagnostics_running = app.diagnostics.as_ref().map(|d| d.running).unwrap_or(false);
        if was_diagnostics_running && !is_diagnostics_running {
            needs_clear = true;
        }
        was_diagnostics_running = is_diagnostics_running;

        if needs_clear {
            terminal.clear()?;
        }

        terminal.draw(|frame| ui::draw(frame, app))?;

        if let Some(event) = events::poll_event(Duration::from_millis(10))? {
            match events::handle_event(app, event) {
                events::Action::Quit => {
                    app.should_quit = true;
                    break;
                }
                events::Action::ToggleBackground => {
                    enter_background_mode(terminal, app)?;
                }
                events::Action::RunDiagnostics(domain) => {
                    let log_tx = log_tx.clone();
                    let config = Arc::clone(&config);
                    rt.spawn(async move {
                        let result = crate::diagnostics::diagnose(&domain, &config.bypass).await;

                        log_nested_t(&log_tx, LogLevel::Info, "log.diag_direct", "verdict", result.direct.description_key(), vec![
                            ("domain", domain.clone()),
                        ]);
                        log_nested_t(&log_tx, LogLevel::Info, "log.diag_https_split", "verdict", result.https_split.description_key(), vec![
                            ("domain", domain.clone()),
                        ]);
                        log_nested_t(&log_tx, LogLevel::Info, "log.diag_socks5_style", "verdict", result.socks5_style.description_key(), vec![
                            ("domain", domain.clone()),
                        ]);
                        log_nested_t(&log_tx, LogLevel::Info, "log.diag_quic", "verdict", result.quic.description_key(), vec![
                            ("domain", domain.clone()),
                        ]);

                        use crate::diagnostics::ProbeOutcome::*;

                        if result.direct == Success {
                            log_t(&log_tx, LogLevel::Info, "log.diag_no_block", vec![("domain", domain.clone())]);
                        } else {
                            if result.https_split == Success {
                                log_t(&log_tx, LogLevel::Success, "log.diag_bypass_works", vec![("domain", domain.clone())]);
                            }
                            if result.socks5_style == Success {
                                log_t(&log_tx, LogLevel::Success, "log.diag_socks5_works", vec![("domain", domain.clone())]);
                            }
                            if result.quic == Success {
                                log_t(&log_tx, LogLevel::Success, "log.diag_quic_works", vec![("domain", domain.clone())]);
                            }
                            if result.direct == ConnectFailed && result.https_split == ConnectFailed && result.socks5_style == ConnectFailed {
                                log_t(&log_tx, LogLevel::Warning, "log.diag_ip_block", vec![("domain", domain.clone())]);
                            } else if result.https_split != Success && result.socks5_style != Success && result.quic != Success {
                                log_t(&log_tx, LogLevel::Warning, "log.diag_bypass_failed", vec![("domain", domain.clone())]);
                            }
                        }

                        log(&log_tx, LogLevel::Info, "__DIAGNOSTICS_DONE__");
                    });
                }
                events::Action::SaveConfigField(path, new_value) => {
                    let log_tx = log_tx.clone();
                    let proxy_started = app.proxy_started;
                    rt.spawn(async move {
                        let result = tokio::task::spawn_blocking(move || {
                            config_editor::save_field(path, &new_value)
                        }).await;

                        match result {
                            Ok(Ok(())) => {
                                if proxy_started {
                                    log_t(&log_tx, LogLevel::Warning, "config.field_restart", vec![("field", path.to_string())]);
                                } else {
                                    log_t(&log_tx, LogLevel::Success, "config.field_saved", vec![("field", path.to_string())]);
                                }
                            }
                            Ok(Err(e)) => {
                                log(&log_tx, LogLevel::Error, e);
                            }
                            Err(e) => {
                                log(&log_tx, LogLevel::Error, format!("Ошибка фоновой задачи сохранения: {}", e));
                            }
                        }
                    });
                }
                events::Action::SaveDomains(domains_snapshot) => {
                    let log_tx = log_tx.clone();
                    let proxy_started = app.proxy_started;
                    rt.spawn(async move {
                        let result = tokio::task::spawn_blocking(move || {
                            domains_editor::save_domains(&domains_snapshot)
                        }).await;

                        match result {
                            Ok(Ok(())) => {
                                if proxy_started {
                                    log_t(&log_tx, LogLevel::Warning, "domains.saved_restart", vec![]);
                                } else {
                                    log_t(&log_tx, LogLevel::Success, "domains.saved", vec![]);
                                }
                            }
                            Ok(Err(e)) => {
                                log(&log_tx, LogLevel::Error, e);
                            }
                            Err(e) => {
                                log(&log_tx, LogLevel::Error, format!("Ошибка фоновой задачи сохранения: {}", e));
                            }
                        }
                    });
                }
                events::Action::StartProxy => {
                    if let Some(old_token) = app.proxy_token.take() {
                        old_token.cancel();
                        std::thread::sleep(Duration::from_millis(500));
                    }

                    let new_token = CancellationToken::new();
                    app.proxy_token = Some(new_token.clone());
                    app.proxy_started = true;
                    app.status.tcp_running = true;
                    app.status.udp_running = true;
                    app.status.socks5_running = true;

                    let config = Arc::clone(&config);
                    let domains = Arc::clone(&domains);
                    let log_tx = log_tx.clone();
                    let metrics = Arc::clone(&metrics);
                    let ip_cache = Arc::clone(&ip_cache);

                    rt.spawn(async move {
                        crate::proxy::run_all(config, domains, log_tx, metrics, new_token, ip_cache).await;
                    });

                    app.push_log_t(LogLevel::Success, "startup.proxy_started", vec![]);
                }
                events::Action::None => {}
            }
        }
    }

    Ok(())
}

fn setup_terminal() -> io::Result<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    Terminal::new(backend)
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> io::Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}
