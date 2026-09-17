//! Терминал и event loop. Теперь ЭТОТ файл занимается только своей задачей —
//! setup/restore терминала, паник-хук, фоновый режим, чтение канала логов,
//! и вызов screen::handle_key()/dispatch::run(). Вся бизнес-логика (что
//! происходит при каждом Action) переехала в dispatch.rs.

mod action;
mod app;
mod dispatch;

mod screen;
mod traffic_history;

pub use app::App;


use ratatui::{backend::CrosstermBackend, Terminal};
use crossterm::{
    event::{self, Event, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::collections::HashSet;
use std::io::{self, Stdout};
use std::sync::Arc;
use std::time::Duration;

use crate::config::Config;
use crate::dns::ip_cache::IpDomainCache;
use crate::observability::logging::{self as log, LogLevel};
use crate::observability::metrics::Metrics;
use crate::engine::strategy::StrategyStore;

use action::Action;

fn install_panic_hook() {
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        original_hook(panic_info);
    }));
}

/// Уходит в фон: возвращает терминал в обычный режим и ждёт Enter.
///
/// Enter ждёт отдельный поток, а не сам цикл событий. Раньше здесь стоял
/// блокирующий `read_line`, и пока интерфейс был свёрнут, цикл стоял целиком:
/// логи копились в неограниченном канале, накопленные исходы стратегий не
/// сбрасывались на диск, автодиагностика не запускалась. Фоновый режим при
/// этом и задуман для долгой работы.
///
/// Возвращает канал, в который поток сообщит о нажатии Enter.
fn enter_background_mode(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &App,
) -> io::Result<std::sync::mpsc::Receiver<()>> {
    use std::io::Write;

    restore_terminal(terminal)?;

    let msg = if app.language.code() == "ru" {
        "\n  Прокси работает в фоне. Нажмите Enter чтобы вернуться в интерфейс.\n"
    } else {
        "\n  Proxy running in background. Press Enter to return to the interface.\n"
    };
    println!("{}", msg);
    io::stdout().flush()?;

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = std::io::stdin().read_line(&mut buf);
        let _ = tx.send(());
    });

    Ok(rx)
}

#[allow(clippy::too_many_arguments)]
pub fn run(
    diagnostics_only: bool,
    config: Arc<Config>,
    domains: Arc<HashSet<String>>,
    domains_error: Option<String>,
    metrics: Arc<Metrics>,
    ip_cache: Arc<IpDomainCache>,
    strategies: Arc<StrategyStore>,
) -> io::Result<()> {
    install_panic_hook();

    let mut terminal = setup_terminal()?;
    let mut app = App::new();
    // Флаг командной строки имеет приоритет над значением из конфига.
    app.diagnostics_only = diagnostics_only || config.diagnostics_only;
    app.status.domains_count = domains.len();
    app.status.tcp_port = config.port;
    app.status.udp_port = config.udp_port;
    app.status.socks5_port = config.socks5_port;
    app.status.transparent_port = config.transparent_port;

    app.push_log_t(LogLevel::Info, "startup.app_started", vec![]);

    // Пустой список обхода — самый тихий способ сломать программу: она
    // работает, слушает порты и ничего не обходит. Говорим об этом вслух.
    if let Some(reason) = domains_error {
        app.push_log_t(LogLevel::Error, "startup.domains_missing", vec![("error".to_string(), reason)]);
    } else if domains.is_empty() {
        app.push_log_t(LogLevel::Warning, "startup.domains_empty", vec![]);
    }

    if app.diagnostics_only {
        app.push_log_t(LogLevel::Warning, "log.diagnostics_only_mode", vec![]);
    }

    let result = run_app(&mut terminal, &mut app, config, domains, metrics, ip_cache, strategies);

    restore_terminal(&mut terminal)?;

    result
}

fn run_app(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut App,
    mut config: Arc<Config>,
    mut domains: Arc<HashSet<String>>,
    metrics: Arc<Metrics>,
    ip_cache: Arc<IpDomainCache>,
    strategies: Arc<StrategyStore>,
) -> io::Result<()> {
    let (log_tx, mut log_rx) = log::channel();

    // Резолвер поднят раньше интерфейса, поэтому канал логов подключается
    // отдельно: без этого откат DoH на системный DNS был бы не виден.
    crate::dns::resolver::attach_logger(log_tx.clone());
    let rt = tokio::runtime::Handle::current();

    let mut was_popup = false;
    let mut was_diagnostics_running = false;

    // Автозапуск: провайдер меняет правила без предупреждения, а TTL лишь
    // помечает запись протухшей — переизмерить её иначе некому, пока
    // пользователь сам не нажмёт клавишу.
    let mut last_auto = std::time::Instant::now();

    /// Через сколько снимать флаг «прогон идёт» принудительно.
    ///
    /// Флаг сбрасывается по маркеру завершения, но если задача упадёт, не
    /// дойдя до него, автозапуск замолчит навсегда. Полчаса заведомо больше
    /// самого долгого прогона.
    const DIAGNOSTICS_STUCK_AFTER: Duration = Duration::from_secs(30 * 60);
    let mut diagnostics_started_at: Option<std::time::Instant> = None;

    /// Как часто сбрасывать накопленные исходы применения стратегий на диск.
    ///
    /// Писать на каждое соединение нельзя — это файл в горячем пути. Но и не
    /// писать вовсе нельзя: `live_ok`/`live_fail` тогда не переживают
    /// перезапуск, и статистика, ради которой верификация и сделана, никогда
    /// не накапливается. Полминуты — компромисс: потерять можно только
    /// последние полминуты наблюдений, и то лишь при аварийном завершении.
    const STORE_FLUSH_INTERVAL: Duration = Duration::from_secs(30);
    let mut last_store_flush = std::time::Instant::now();

    // Some — интерфейс свёрнут, и канал сообщит о нажатии Enter.
    let mut background: Option<std::sync::mpsc::Receiver<()>> = None;

    loop {
        let mut needs_clear = false;

        // Единая точка приёма логов из фоновых задач — раньше здесь был
        // match по LogPayload::Plain/Translated/NestedTranslated с тремя
        // разными вызовами push_log*(); теперь один payload передаётся
        // как есть (app.push_payload), см. cli/log.rs и cli/app.rs.
        while let Ok(msg) = log_rx.try_recv() {
            if let log::LogPayload::Plain(text) = &msg.payload
                && text == "__DIAGNOSTICS_DONE__"
            {
                app.diagnostics_running = false;
                if let screen::Screen::Diagnostics(state) = &mut app.screen {
                    state.running = false;
                }
                continue;
            }
            app.push_payload(msg.level, msg.payload);
        }

        app.metrics = metrics.snapshot();
        // Статус портов — из реальных флагов слушателей, а не из намерения запустить.
        app.status.tcp_running = app.metrics.tcp_listening;
        app.status.udp_running = app.metrics.udp_listening;
        app.status.socks5_running = app.metrics.socks5_listening;
        app.status.transparent_running = app.metrics.transparent_listening;
        app.status.transparent_udp_running = app.metrics.transparent_udp_listening;
        app.traffic_history.record(app.metrics.bytes_rx, app.metrics.bytes_tx);

        // Было: has_popup = overlay.is_some() || config_editor.is_some() || ...
        // Теперь: одна функция над одним enum.
        let is_popup = screen::is_popup(&app.screen);
        if is_popup != was_popup {
            needs_clear = true;
        }
        was_popup = is_popup;

        let is_diag_running = screen::is_diagnostics_running(&app.screen);
        if was_diagnostics_running && !is_diag_running {
            needs_clear = true;
        }
        was_diagnostics_running = is_diag_running;

        // В фоне терминал принадлежит обычному выводу — рисовать нельзя.
        if background.is_none() {
            if needs_clear {
                terminal.clear()?;
            }
            terminal.draw(|frame| screen::draw(frame, app))?;
        }

        // Запуск по расписанию — только когда прогон не идёт: наложение
        // двух прогонов удвоило бы нагрузку на сеть и исказило результат.
        // Страховка от залипания: если задача упала, не отправив маркер
        // завершения, флаг остался бы взведён и автозапуск замолчал бы.
        if let Some(started) = diagnostics_started_at
            && app.diagnostics_running
            && started.elapsed() > DIAGNOSTICS_STUCK_AFTER
        {
            app.diagnostics_running = false;
            diagnostics_started_at = None;
        }
        if !app.diagnostics_running {
            diagnostics_started_at = None;
        } else if diagnostics_started_at.is_none() {
            diagnostics_started_at = Some(std::time::Instant::now());
        }

        if last_store_flush.elapsed() >= STORE_FLUSH_INTERVAL && strategies.is_dirty() {
            last_store_flush = std::time::Instant::now();
            let store = Arc::clone(&strategies);
            let log_for_save = log_tx.clone();
            rt.spawn_blocking(move || {
                if let Err(e) = store.save() {
                    log::log_t(&log_for_save, LogLevel::Error, "error.strategy_write", vec![("error", e.to_string())]);
                }
            });
        }

        // Интервал берётся из текущего конфига: перезапуск прокси его перечитывает.
        let auto_interval = (config.auto_diagnostics_hours > 0)
            .then(|| Duration::from_secs(config.auto_diagnostics_hours.saturating_mul(3600)));
        if let Some(interval) = auto_interval
            && !app.diagnostics_running
            && last_auto.elapsed() >= interval
        {
            last_auto = std::time::Instant::now();
            dispatch::run(Action::RunDiagnosticsAll, app, &mut config, &mut domains, &metrics, &ip_cache, &strategies, &log_tx, &rt);
        }

        if let Some(enter) = &background {
            match enter.recv_timeout(Duration::from_millis(200)) {
                Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    background = None;
                    *terminal = setup_terminal()?;
                    terminal.clear()?;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            }
            continue;
        }

        // 50 мс, а не 10: каждый цикл перерисовывает весь экран, и при 10 мс
        // это сотня полных кадров в секунду без всякой пользы. 20 кадров
        // хватает и для логов, и для отклика на клавиши.
        if event::poll(Duration::from_millis(50))?
            && let Event::Key(key) = event::read()?
        {
            if key.kind != KeyEventKind::Press {
                continue;
            }

            let action = screen::handle_key(app, key.code);

            match action {
                Action::Quit => {
                    app.should_quit = true;
                    break;
                }
                Action::ToggleBackground => {
                    background = Some(enter_background_mode(terminal, app)?);
                }
                other => dispatch::run(other, app, &mut config, &mut domains, &metrics, &ip_cache, &strategies, &log_tx, &rt),
            }
        }
    }

    // Выход — последняя возможность сохранить накопленное. Синхронно и до
    // восстановления терминала: фоновая задача здесь уже не успела бы,
    // рантайм останавливается сразу за возвратом из run().
    if strategies.is_dirty()
        && let Err(e) = strategies.save()
    {
        eprintln!("[✗] Не удалось сохранить strategies.txt: {}", e);
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
