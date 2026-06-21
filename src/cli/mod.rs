mod app;
mod ui;
mod events;
mod config_editor;
mod domains_editor;
mod traffic_history;
pub mod logger;

pub use app::{App, LogLevel};
pub use logger::{LogSender, log};

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

pub fn run(config: Arc<Config>, domains: Arc<HashSet<String>>, metrics: Arc<Metrics>) -> io::Result<()> {
    install_panic_hook();

    let mut terminal = setup_terminal()?;
    let mut app = App::new();
    app.status.domains_count = domains.len();
    app.status.tcp_port = config.port;
    app.status.udp_port = config.udp_port;
    app.status.socks5_port = config.socks5_port;

    app.push_log(LogLevel::Info, "net_surgeon запущен");

    let result = run_app(&mut terminal, &mut app, config, domains, metrics);

    restore_terminal(&mut terminal)?;

    result
}

fn install_panic_hook() {
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        original_hook(panic_info);
    }));
}

fn run_app(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut App,
    config: Arc<Config>,
    domains: Arc<HashSet<String>>,
    metrics: Arc<Metrics>,
) -> io::Result<()> {
    let (log_tx, mut log_rx) = logger::channel();
    let rt = tokio::runtime::Handle::current();

    let mut had_popup = false;
    let mut was_diagnostics_running = false;

    loop {
        let mut needs_clear = false;

        while let Ok(msg) = log_rx.try_recv() {
            if msg.text == "__DIAGNOSTICS_DONE__" {
                if let Some(screen) = app.diagnostics.as_mut() {
                    screen.running = false;
                }
                continue;
            }
            app.push_log(msg.level, msg.text);
        }

        app.metrics = metrics.snapshot();
        app.traffic_history.record(app.metrics.bytes_rx, app.metrics.bytes_tx);

        let has_popup = app.overlay.is_some()
        || app.config_editor.is_some()
        || app.domains_editor.is_some()
        || app.diagnostics.is_some();

        // Попап открылся или закрылся — чистим, чтобы не было наложений
        if has_popup != had_popup {
            needs_clear = true;
        }
        had_popup = has_popup;

        // Диагностика только что завершилась — отдельная точка, где чаще всего видны артефакты
        let is_diagnostics_running = app.diagnostics.as_ref().map(|d| d.running).unwrap_or(false);
        if was_diagnostics_running && !is_diagnostics_running {
            needs_clear = true;
        }
        was_diagnostics_running = is_diagnostics_running;

        if needs_clear {
            terminal.clear()?;
        }

        terminal.draw(|frame| ui::draw(frame, app))?;

        if let Some(event) = events::poll_event(Duration::from_millis(100))? {
            match events::handle_event(app, event) {
                events::Action::Quit => {
                    app.should_quit = true;
                    break;
                }
                events::Action::RunDiagnostics(domain) => {
                    let log_tx = log_tx.clone();
                    let config = Arc::clone(&config);
                    rt.spawn(async move {
                        let result = crate::diagnostics::diagnose(&domain, &config.bypass).await;

                        log(&log_tx, LogLevel::Info, format!(
                            "Диагностика {}: напрямую — {}", domain, result.direct.description()
                        ));
                        log(&log_tx, LogLevel::Info, format!(
                            "Диагностика {}: с обходом — {}", domain, result.bypass.description()
                        ));

                        use crate::diagnostics::ProbeOutcome::*;
                        match (result.direct, result.bypass) {
                            (Success, _) => {
                                log(&log_tx, LogLevel::Info, format!("{}: блокировки не обнаружено", domain));
                            }
                            (_, Success) => {
                                log(&log_tx, LogLevel::Success, format!("{}: обход реально помогает!", domain));
                            }
                            (ConnectFailed, ConnectFailed) => {
                                log(&log_tx, LogLevel::Warning, format!("{}: блокировка на уровне IP, фрагментация TLS не поможет", domain));
                            }
                            _ => {
                                log(&log_tx, LogLevel::Warning, format!("{}: обход не сработал, нужны другие параметры", domain));
                            }
                        }

                        log(&log_tx, LogLevel::Info, "__DIAGNOSTICS_DONE__");
                    });
                }
                events::Action::StartProxy => {
                    if !app.proxy_started {
                        app.proxy_started = true;
                        app.status.tcp_running = true;
                        app.status.udp_running = true;
                        app.status.socks5_running = true;

                        let config = Arc::clone(&config);
                        let domains = Arc::clone(&domains);
                        let log_tx = log_tx.clone();
                        let metrics = Arc::clone(&metrics);
                        rt.spawn(async move {
                            crate::proxy::run_all(config, domains, log_tx, metrics).await;
                        });

                        app.push_log(LogLevel::Success, "Прокси-задачи запущены в фоне");
                    } else {
                        app.push_log(LogLevel::Warning, "Прокси уже запущен");
                    }
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
