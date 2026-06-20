mod app;
mod ui;
mod events;
mod config_editor;
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

pub fn run(config: Arc<Config>, domains: Arc<HashSet<String>>) -> io::Result<()> {
    install_panic_hook();

    let mut terminal = setup_terminal()?;
    let mut app = App::new();
    app.status.domains_count = domains.len();
    app.status.tcp_port = config.port;
    app.status.udp_port = config.udp_port;
    app.status.socks5_port = config.socks5_port;

    app.push_log(LogLevel::Info, "net_surgeon запущен");

    let result = run_app(&mut terminal, &mut app, config, domains);

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
) -> io::Result<()> {
    let (log_tx, mut log_rx) = logger::channel();

    // tokio runtime для фоновых задач прокси — TUI-цикл сам синхронный
    let rt = tokio::runtime::Handle::current();

    loop {
        // Сливаем все накопленные логи из фоновых задач в app.logs
        while let Ok(msg) = log_rx.try_recv() {
            app.push_log(msg.level, msg.text);
        }

        terminal.draw(|frame| ui::draw(frame, app))?;

        if let Some(event) = events::poll_event(Duration::from_millis(100))? {
            match events::handle_event(app, event) {
                events::Action::Quit => {
                    app.should_quit = true;
                    break;
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
                        rt.spawn(async move {
                            crate::proxy::run_all(config, domains, log_tx).await;
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
