//! Главный экран — меню + панель логов. Навигация (Tab/стрелки/PageUp-Down/
//! Home/End/язык) перенесена как есть из старого events.rs — багов тут не было.

use crossterm::event::KeyCode;
use rust_i18n::t;
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Sparkline},
    Frame,
};

use crate::cli::action::Action;
use crate::cli::app::{App, Focus, MenuItem};
use crate::observability::logging::{LogLevel, LogPayload};

use super::domains_editor::DomainList;
use super::{config_editor, diagnostics, domains_editor, Screen, StepResult};

pub fn handle_key(app: &mut App, key: KeyCode) -> StepResult {
    match key {
        KeyCode::Tab => { app.toggle_focus(); StepResult::Stay(Action::None) }
        KeyCode::Char('H') => StepResult::Stay(Action::ToggleBackground),
        KeyCode::Char('L') => { app.toggle_language(); StepResult::Stay(Action::None) }
        KeyCode::Up | KeyCode::Char('k') => {
            match app.focus {
                Focus::Menu => app.previous(),
                Focus::Logs => app.scroll_logs_up(1),
            }
            StepResult::Stay(Action::None)
        }
        KeyCode::Down | KeyCode::Char('j') => {
            match app.focus {
                Focus::Menu => app.next(),
                Focus::Logs => app.scroll_logs_down(1),
            }
            StepResult::Stay(Action::None)
        }
        KeyCode::PageUp => { app.scroll_logs_up(5); StepResult::Stay(Action::None) }
        KeyCode::PageDown => { app.scroll_logs_down(5); StepResult::Stay(Action::None) }
        KeyCode::Home => {
            if app.focus == Focus::Logs {
                app.log_autoscroll = false;
                app.log_scroll = app.logs.len();
            }
            StepResult::Stay(Action::None)
        }
        KeyCode::End => {
            app.log_autoscroll = true;
            app.log_scroll = 0;
            StepResult::Stay(Action::None)
        }
        KeyCode::Enter if app.focus == Focus::Menu => handle_select(app),
        // Только `q`, как и написано в подсказке внизу. Esc на всех остальных
        // экранах значит «назад», и лишнее нажатие на главном закрывало
        // программу вместе с прозрачным перехватом.
        KeyCode::Char('q') => StepResult::Stay(Action::Quit),
        _ => StepResult::Stay(Action::None),
    }
}

fn handle_select(app: &mut App) -> StepResult {
    match app.current() {
        MenuItem::Domains => open_domains(app, DomainList::Bypass),
        MenuItem::Blocklist => open_domains(app, DomainList::Block),
        MenuItem::Diagnostics => {
            // Прогон мог начаться раньше, и экран закрывали: без этого он
            // открывался бы в режиме «можно запускать», хотя прогон идёт.
            let mut state = diagnostics::DiagnosticsState::new();
            state.running = app.diagnostics_running;
            StepResult::Switch(Screen::Diagnostics(state), Action::None)
        }
        MenuItem::Config => match config_editor::load_fields() {
            Ok(fields) => StepResult::Switch(
                Screen::ConfigEditor(config_editor::ConfigEditorState::new(fields)),
                Action::None,
            ),
            Err(e) => { app.push_err(e); StepResult::Stay(Action::None) }
        },
        MenuItem::Start => StepResult::Stay(Action::StartProxy),
        MenuItem::Quit => StepResult::Stay(Action::Quit),
    }
}

fn open_domains(app: &mut App, list: DomainList) -> StepResult {
    match domains_editor::load_domains(list) {
        Ok(domains) => StepResult::Switch(
            Screen::DomainsEditor(domains_editor::DomainsEditorState::new(list, domains)),
            Action::None,
        ),
        Err(e) => { app.push_err(e); StepResult::Stay(Action::None) }
    }
}

// --- Отрисовка. Перенесено из старого ui.rs, с заменой app.overlay/config_editor/
// domains_editor/diagnostics (4 отдельных Option) на один match по app.screen для
// футера (единственное место здесь, где нужно знать про все варианты Screen сразу —
// остальная раскладка/виджеты этого экрана от Screen не зависят).

pub fn draw(frame: &mut Frame, app: &App) {
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0), Constraint::Length(3)])
        .split(frame.area());

    draw_header(frame, root[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(22), Constraint::Min(0)])
        .split(root[1]);

    draw_menu(frame, body[0], app);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(6), Constraint::Length(3), Constraint::Length(5), Constraint::Min(0)])
        .split(body[1]);

    draw_status(frame, right[0], app);
    draw_metrics(frame, right[1], app);
    draw_traffic_graph(frame, right[2], app);
    draw_logs(frame, right[3], app);

    draw_footer(frame, root[2], app);
}

fn draw_header(frame: &mut Frame, area: Rect) {
    let title = Paragraph::new(t!("app.title").to_string())
        .style(Style::default().fg(Color::LightBlue).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(title, area);
}

fn menu_label(item: MenuItem) -> String {
    match item {
        MenuItem::Domains => t!("menu.domains").to_string(),
        MenuItem::Blocklist => t!("menu.blocklist").to_string(),
        MenuItem::Diagnostics => t!("menu.diagnostics").to_string(),
        MenuItem::Config => t!("menu.config").to_string(),
        MenuItem::Start => t!("menu.start").to_string(),
        MenuItem::Quit => t!("menu.quit").to_string(),
    }
}

fn draw_menu(frame: &mut Frame, area: Rect, app: &App) {
    let items: Vec<ListItem> = MenuItem::ALL
        .iter()
        .enumerate()
        .map(|(i, item)| {
            let selected = i == app.selected;
            let prefix = if selected { "▶ " } else { "  " };
            let style = if selected {
                Style::default().fg(Color::White).bg(Color::Rgb(42, 42, 90))
            } else if *item == MenuItem::Quit {
                Style::default().fg(Color::LightRed)
            } else if *item == MenuItem::Start {
                Style::default().fg(Color::LightGreen)
            } else {
                Style::default().fg(Color::Gray)
            };
            ListItem::new(format!("{}{}", prefix, menu_label(*item))).style(style)
        })
        .collect();

    let border_style = if app.focus == Focus::Menu { Style::default().fg(Color::LightBlue) } else { Style::default() };

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(format!(" {} ", t!("menu.panel_title"))).border_style(border_style));
    frame.render_widget(list, area);
}

fn draw_status(frame: &mut Frame, area: Rect, app: &App) {
    let s = &app.status;

    // Пятая панель — прозрачный режим — появляется только когда порт задан
    // (0 = выключено). Иначе она бы всегда пустовала и просто отъедала место
    // у остальных четырёх, которые нужны всегда.
    let show_transparent = s.transparent_port > 0;

    let cols = if show_transparent {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(20),
                Constraint::Percentage(20),
                Constraint::Percentage(20),
                Constraint::Percentage(20),
                Constraint::Percentage(20),
            ])
            .split(area)
    } else {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(25), Constraint::Percentage(25), Constraint::Percentage(25), Constraint::Percentage(25)])
            .split(area)
    };

    let block = |label: String, on: bool, port: Option<u16>| {
        let (status_text, color) = if on {
            (t!("status.on").to_string(), Color::LightGreen)
        } else {
            (t!("status.off").to_string(), Color::DarkGray)
        };
        let port_line = port.map(|p| format!(":{}", p)).unwrap_or_default();
        Paragraph::new(vec![
            Line::from(Span::styled(status_text, Style::default().fg(color).add_modifier(Modifier::BOLD))),
            Line::from(Span::styled(port_line, Style::default().fg(Color::DarkGray))),
        ])
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL).title(format!(" {} ", label)))
    };

    frame.render_widget(block(t!("status.tcp").to_string(), s.tcp_running, Some(s.tcp_port)), cols[0]);
    frame.render_widget(block(t!("status.udp").to_string(), s.udp_running, Some(s.udp_port)), cols[1]);
    frame.render_widget(block(t!("status.socks5").to_string(), s.socks5_running, Some(s.socks5_port)), cols[2]);

    let domains = Paragraph::new(vec![
        Line::from(Span::styled(s.domains_count.to_string(), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
        Line::from(Span::styled(t!("status.bypass_label").to_string(), Style::default().fg(Color::DarkGray))),
    ])
    .alignment(Alignment::Center)
    .block(Block::default().borders(Borders::ALL).title(format!(" {} ", t!("status.domains_panel"))));
    frame.render_widget(domains, cols[3]);

    if show_transparent {
        // У прозрачного режима две половины, и они поднимаются независимо:
        // TCP хватает правила iptables, а UDP (QUIC) требует CAP_NET_ADMIN
        // и может не стартовать. Показываем обе, иначе «ON» означало бы,
        // что QUIC тоже идёт через обход, — а это как раз неизвестно.
        let quic_mark = if s.transparent_udp_running {
            format!(":{} +{}", s.transparent_port, t!("status.transparent_udp"))
        } else {
            format!(":{}", s.transparent_port)
        };
        let (status_text, color) = if s.transparent_running {
            (t!("status.on").to_string(), Color::LightGreen)
        } else {
            (t!("status.off").to_string(), Color::DarkGray)
        };
        let panel = Paragraph::new(vec![
            Line::from(Span::styled(status_text, Style::default().fg(color).add_modifier(Modifier::BOLD))),
            Line::from(Span::styled(
                quic_mark,
                Style::default().fg(if s.transparent_udp_running { Color::LightGreen } else { Color::DarkGray }),
            )),
        ])
        .alignment(Alignment::Center)
        .block(Block::default().borders(Borders::ALL).title(format!(" {} ", t!("status.transparent"))));
        frame.render_widget(panel, cols[4]);
    }
}

fn draw_metrics(frame: &mut Frame, area: Rect, app: &App) {
    let m = &app.metrics;

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(18),
            Constraint::Percentage(18),
            Constraint::Percentage(18),
            Constraint::Percentage(22),
            Constraint::Percentage(24),
        ])
        .split(area);

    let conn_color = if m.active_connections > 0 { Color::LightGreen } else { Color::DarkGray };
    // Рядом с числом подключений — медиана времени установки TCP-соединения:
    // если connect быстрый, а TTFB огромный, значит режет не сеть, а DPI.
    let mut conn_spans = vec![
        Span::styled(t!("metrics.connections").to_string(), Style::default().fg(Color::DarkGray)),
        Span::styled(m.active_connections.to_string(), Style::default().fg(conn_color).add_modifier(Modifier::BOLD)),
    ];
    if let Some(connect_p50) = m.connect_p50 {
        conn_spans.push(Span::styled(
            format!("  ⇄{:.0}", connect_p50),
            Style::default().fg(Color::DarkGray),
        ));
    }
    let connections = Paragraph::new(Line::from(conn_spans))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(connections, cols[0]);

    let rx_text = crate::observability::metrics::format_bytes(m.bytes_rx);
    let rx = Paragraph::new(Line::from(vec![
        Span::styled(t!("metrics.rx").to_string(), Style::default().fg(Color::DarkGray)),
        Span::styled(rx_text, Style::default().fg(Color::LightBlue).add_modifier(Modifier::BOLD)),
    ]))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(rx, cols[1]);

    let tx_text = crate::observability::metrics::format_bytes(m.bytes_tx);
    let tx = Paragraph::new(Line::from(vec![
        Span::styled(t!("metrics.tx").to_string(), Style::default().fg(Color::DarkGray)),
        Span::styled(tx_text, Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD)),
    ]))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(tx, cols[2]);

    let dns_status = if m.dns_ok { t!("metrics.ok").to_string() } else { t!("metrics.fail").to_string() };
    let dns_color = if m.dns_ok { Color::LightGreen } else { Color::LightRed };
    // QUIC-обход идёт через SOCKS5 UDP: показываем число активных сессий
    // и сколько фейковых Initial отправлено. Прежний индикатор OK/FAIL
    // относился к удалённому форвардеру и ни о чём не говорил.
    let quic_info = if m.quic_initial_sent > 0 {
        format!("{} ({})", m.quic_sessions, m.quic_initial_sent)
    } else {
        m.quic_sessions.to_string()
    };

    let health = Paragraph::new(Line::from(vec![
        Span::styled(t!("metrics.dns").to_string(), Style::default().fg(Color::DarkGray)),
        Span::styled(dns_status, Style::default().fg(dns_color).add_modifier(Modifier::BOLD)),
        Span::raw("  "),
        Span::styled(t!("metrics.quic").to_string(), Style::default().fg(Color::DarkGray)),
        Span::styled(quic_info, Style::default().fg(Color::Gray)),
    ]))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(health, cols[3]);

    // Задержки: медиана и хвост. Среднее здесь было бы бесполезно — оно
    // прячет редкие двухсекундные ответы, из-за которых и кажется, что
    // «интернет тормозит», хотя типичный запрос быстрый.
    let latency_line = match (m.ttfb_p50, m.ttfb_p95, m.ttfb_p99) {
        (Some(p50), Some(p95), Some(p99)) => Line::from(vec![
            Span::styled(t!("metrics.latency").to_string(), Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{:.0}", p50), Style::default().fg(latency_color(p50)).add_modifier(Modifier::BOLD)),
            Span::styled("/", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{:.0}", p95), Style::default().fg(latency_color(p95))),
            Span::styled("/", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{:.0}", p99), Style::default().fg(latency_color(p99))),
            Span::styled(format!(" ({})", m.latency_samples), Style::default().fg(Color::DarkGray)),
        ]),
        _ => Line::from(Span::styled(
            t!("metrics.latency_waiting").to_string(),
            Style::default().fg(Color::DarkGray),
        )),
    };

    let latency = Paragraph::new(latency_line)
        .block(Block::default().borders(Borders::ALL).title(format!(" {} ", t!("metrics.latency_panel"))));
    frame.render_widget(latency, cols[4]);
}

/// Цвет по задержке: до 100 мс отзывчиво, до 500 терпимо, дальше плохо.
fn latency_color(ms: f64) -> Color {
    if ms < 100.0 {
        Color::LightGreen
    } else if ms < 500.0 {
        Color::Yellow
    } else {
        Color::LightRed
    }
}

fn draw_traffic_graph(frame: &mut Frame, area: Rect, app: &App) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let rx_data: Vec<u64> = app.traffic_history.rx_speed.iter().copied().collect();
    let rx_max = rx_data.iter().copied().max().unwrap_or(0);
    // К пику добавляем коэффициент вариации по Уэлфорду: насколько ровный канал.
    let rx_label = if rx_max > 0 {
        let base = t!("graph.rx_peak", peak = crate::observability::metrics::format_bytes(rx_max)).to_string();
        match app.traffic_history.rx_variation() {
            Some(cv) => format!("{}{}", base, t!("graph.variation", cv = format!("{:.2}", cv))),
            None => base,
        }
    } else {
        t!("graph.rx").to_string()
    };
    let rx_sparkline = Sparkline::default()
        .block(Block::default().borders(Borders::ALL).title(rx_label))
        .data(&rx_data)
        .style(Style::default().fg(Color::LightBlue));
    frame.render_widget(rx_sparkline, cols[0]);

    let tx_data: Vec<u64> = app.traffic_history.tx_speed.iter().copied().collect();
    let tx_max = tx_data.iter().copied().max().unwrap_or(0);
    let tx_label = if tx_max > 0 {
        t!("graph.tx_peak", peak = crate::observability::metrics::format_bytes(tx_max)).to_string()
    } else {
        t!("graph.tx").to_string()
    };
    let tx_sparkline = Sparkline::default()
        .block(Block::default().borders(Borders::ALL).title(tx_label))
        .data(&tx_data)
        .style(Style::default().fg(Color::LightGreen));
    frame.render_widget(tx_sparkline, cols[1]);
}

fn draw_logs(frame: &mut Frame, area: Rect, app: &App) {
    let visible_height = area.height.saturating_sub(2) as usize;
    let total = app.logs.len();

    // Дальше последнего экрана прокручивать некуда. Раньше здесь стояло
    // `log_scroll.min(total.saturating_sub(h).max(log_scroll))`, что тождественно
    // равно log_scroll: `a.min(b.max(a)) == a`. Клампа не было, и Home
    // (он ставит log_scroll = logs.len()) просто гасил панель.
    let max_scroll = total.saturating_sub(visible_height.max(1));
    let skip_from_end = app.log_scroll.min(max_scroll);

    let items: Vec<ListItem> = app.logs
        .iter()
        .rev()
        .skip(skip_from_end)
        .take(visible_height)
        .map(|entry| {
            let (icon, color) = match entry.level {
                LogLevel::Info => ("[i]", Color::LightBlue),
                LogLevel::Success => ("[✓]", Color::LightGreen),
                // Не эмодзи: ⚡ ratatui считает шириной в 2 клетки, а терминалы
                // часто рисуют в одну. Строка съезжала, и при частичной
                // перерисовке на экране оставались обрывки старого текста.
                LogLevel::Warning => ("[!]", Color::Yellow),
                LogLevel::Error => ("[✗]", Color::LightRed),
            };
            ListItem::new(Line::from(vec![
                Span::styled(icon, Style::default().fg(color)),
                Span::raw(" "),
                Span::styled(&entry.time, Style::default().fg(Color::DarkGray)),
                Span::raw(" "),
                Span::styled(render_log_payload(app, &entry.payload), Style::default().fg(color)),
            ]))
        })
        .collect();

    let title = if app.log_autoscroll { format!(" {} ", t!("logs.panel_title")) } else { format!(" {} (scroll) ", t!("logs.panel_title")) };
    let title_style = if app.log_autoscroll { Style::default() } else { Style::default().fg(Color::Yellow) };
    let border_style = if app.focus == Focus::Logs { Style::default().fg(Color::LightBlue) } else { Style::default() };

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title).title_style(title_style).border_style(border_style));
    frame.render_widget(list, area);
}

fn render_log_payload(app: &App, payload: &LogPayload) -> String {
    match payload {
        LogPayload::Plain(s) => s.clone(),
        LogPayload::Translated { key, args } => crate::observability::i18n::translate(app.language.code(), key, args),
        LogPayload::NestedTranslated { key, nested_arg, nested_key, args } => {
            crate::observability::i18n::translate_nested(app.language.code(), key, nested_arg, nested_key, args)
        }
    }
}

fn draw_footer(frame: &mut Frame, area: Rect, app: &App) {
    // Было: 4 отдельных if app.overlay.is_some() / app.config_editor.is_some() / ... —
    // теперь один match по app.screen, компилятор не даст забыть вариант.
    let line = match &app.screen {
        Screen::Diagnostics(state) => {
            if state.input_buffer.is_some() {
                Line::from(vec![
                    Span::styled("Enter", Style::default().fg(Color::LightBlue)),
                    Span::raw(format!(" {}   ", t!("footer.run"))),
                    Span::styled("Esc", Style::default().fg(Color::LightBlue)),
                    Span::raw(format!(" {}", t!("footer.cancel"))),
                ])
            } else {
                Line::from(vec![
                    Span::styled("n", Style::default().fg(Color::LightBlue)),
                    Span::raw(format!(" {}   ", t!("footer.new_test"))),
                    Span::styled("a", Style::default().fg(Color::LightBlue)),
                    Span::raw(format!(" {}   ", t!("footer.run_all"))),
                    Span::styled("Esc/q", Style::default().fg(Color::LightBlue)),
                    Span::raw(format!(" {}", t!("footer.back"))),
                ])
            }
        }
        Screen::DomainsEditor(state) => {
            if state.editing_buffer.is_some() {
                Line::from(vec![
                    Span::styled("Enter", Style::default().fg(Color::LightBlue)),
                    Span::raw(format!(" {}   ", t!("footer.save"))),
                    Span::styled("Esc", Style::default().fg(Color::LightBlue)),
                    Span::raw(format!(" {}", t!("footer.cancel"))),
                ])
            } else {
                Line::from(vec![
                    Span::styled("↑↓", Style::default().fg(Color::LightBlue)),
                    Span::raw(format!(" {}   ", t!("footer.navigation"))),
                    Span::styled("a", Style::default().fg(Color::LightBlue)),
                    Span::raw(format!(" {}   ", t!("footer.add"))),
                    Span::styled("e", Style::default().fg(Color::LightBlue)),
                    Span::raw(format!(" {}   ", t!("footer.change"))),
                    Span::styled("d", Style::default().fg(Color::LightBlue)),
                    Span::raw(format!(" {}   ", t!("footer.delete"))),
                    Span::styled("Esc/q", Style::default().fg(Color::LightBlue)),
                    Span::raw(format!(" {}", t!("footer.back"))),
                ])
            }
        }
        Screen::ConfigEditor(state) => {
            if state.editing_buffer.is_some() {
                Line::from(vec![
                    Span::styled("Enter", Style::default().fg(Color::LightBlue)),
                    Span::raw(format!(" {}   ", t!("footer.save"))),
                    Span::styled("Esc", Style::default().fg(Color::LightBlue)),
                    Span::raw(format!(" {}", t!("footer.cancel"))),
                ])
            } else {
                Line::from(vec![
                    Span::styled("↑↓", Style::default().fg(Color::LightBlue)),
                    Span::raw(format!(" {}   ", t!("footer.navigation"))),
                    Span::styled("Enter", Style::default().fg(Color::LightBlue)),
                    Span::raw(format!(" {}   ", t!("footer.edit"))),
                    Span::styled("Esc/q", Style::default().fg(Color::LightBlue)),
                    Span::raw(format!(" {}", t!("footer.back"))),
                ])
            }
        }
        Screen::Main => Line::from(vec![
            Span::styled("Tab", Style::default().fg(Color::LightBlue)),
            Span::raw(format!(" {}   ", t!("footer.focus"))),
            Span::styled("↑↓", Style::default().fg(Color::LightBlue)),
            Span::raw(format!(" {}   ", t!("footer.nav_logs"))),
            Span::styled("Enter", Style::default().fg(Color::LightBlue)),
            Span::raw(format!(" {}   ", t!("footer.select"))),
            Span::styled("L", Style::default().fg(Color::LightBlue)),
            Span::raw(format!(" {}   ", t!("footer.lang"))),
            Span::styled("H", Style::default().fg(Color::LightBlue)),
            Span::raw(format!(" {}   ", t!("footer.background"))),
            Span::styled("q", Style::default().fg(Color::LightBlue)),
            Span::raw(format!(" {}", t!("footer.quit"))),
        ]),
    };

    let footer = Paragraph::new(line).alignment(Alignment::Center).block(Block::default().borders(Borders::ALL));
    frame.render_widget(footer, area);
}
