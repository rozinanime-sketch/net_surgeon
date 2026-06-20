use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
    Frame,
};

use super::app::{App, LogLevel, MenuItem};

pub fn draw(frame: &mut Frame, app: &App) {
    let root = Layout::default()
    .direction(Direction::Vertical)
    .constraints([
        Constraint::Length(3),
                 Constraint::Min(0),
                 Constraint::Length(3),
    ])
    .split(frame.area());

    draw_header(frame, root[0]);

    let body = Layout::default()
    .direction(Direction::Horizontal)
    .constraints([Constraint::Length(22), Constraint::Min(0)])
    .split(root[1]);

    draw_menu(frame, body[0], app);

    let right = Layout::default()
    .direction(Direction::Vertical)
    .constraints([
        Constraint::Length(6),
                 Constraint::Length(3),
                 Constraint::Min(0),
    ])
    .split(body[1]);

    draw_status(frame, right[0], app);
    draw_metrics(frame, right[1], app);
    draw_logs(frame, right[2], app);

    draw_footer(frame, root[2], app);

    if let Some(text) = &app.overlay {
        draw_overlay(frame, frame.area(), text);
    }

    if let Some(editor) = &app.config_editor {
        draw_config_editor(frame, frame.area(), editor, app.proxy_started);
    }

    if let Some(editor) = &app.domains_editor {
        draw_domains_editor(frame, frame.area(), editor, app.proxy_started);
    }
}

fn draw_domains_editor(frame: &mut Frame, area: Rect, editor: &super::app::DomainsEditor, proxy_started: bool) {
    let popup = centered_rect(60, 80, area);
    frame.render_widget(Clear, popup);

    let title = if proxy_started {
        format!(" Домены ({}) — прокси запущен, нужен перезапуск ", editor.domains.len())
    } else {
        format!(" Домены ({}) ", editor.domains.len())
    };

    let outer = Block::default()
    .borders(Borders::ALL)
    .title(title)
    .title_style(if proxy_started {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    })
    .style(Style::default().bg(Color::Rgb(20, 20, 35)));
    let inner = outer.inner(popup);
    frame.render_widget(outer, popup);

    let is_editing = editor.editing_buffer.is_some();

    let chunks = Layout::default()
    .direction(Direction::Vertical)
    .constraints(if is_editing {
        vec![Constraint::Min(0), Constraint::Length(1)]
    } else {
        vec![Constraint::Min(0)]
    })
    .split(inner);

    if editor.domains.is_empty() {
        let empty = Paragraph::new("Список пуст. Нажмите 'a' чтобы добавить домен.")
        .style(Style::default().fg(Color::DarkGray));
        frame.render_widget(empty, chunks[0]);
    } else {
        let items: Vec<ListItem> = editor.domains
        .iter()
        .enumerate()
        .map(|(i, domain)| {
            let selected = i == editor.selected && !is_editing;
            let prefix = if selected { "▶ " } else { "  " };
            let style = if selected {
                Style::default().fg(Color::White).bg(Color::Rgb(42, 42, 90))
            } else {
                Style::default().fg(Color::Gray)
            };
            ListItem::new(format!("{}{}", prefix, domain)).style(style)
        })
        .collect();

        let list = List::new(items);
        frame.render_widget(list, chunks[0]);
    }

    if is_editing {
        let buf = editor.editing_buffer.as_ref().unwrap();
        let label = if editor.is_editing_existing { "Изменить домен: " } else { "Новый домен: " };
        let input_line = Line::from(vec![
            Span::styled(label, Style::default().fg(Color::DarkGray)),
                                    Span::styled(format!("{}█", buf), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        ]);
        frame.render_widget(Paragraph::new(input_line), chunks[1]);
    }
}

fn draw_overlay(frame: &mut Frame, area: Rect, text: &str) {
    let popup = centered_rect(70, 60, area);
    frame.render_widget(Clear, popup);

    let block = Block::default()
    .borders(Borders::ALL)
    .title(" config.toml ")
    .style(Style::default().bg(Color::Rgb(20, 20, 35)));

    let paragraph = Paragraph::new(text)
    .style(Style::default().fg(Color::Gray))
    .wrap(Wrap { trim: false })
    .block(block);

    frame.render_widget(paragraph, popup);
}

fn draw_config_editor(frame: &mut Frame, area: Rect, editor: &super::app::ConfigEditor, proxy_started: bool) {
    let popup = centered_rect(70, 80, area);
    frame.render_widget(Clear, popup);

    let title = if proxy_started {
        " Редактирование config.toml (прокси уже запущен — нужен перезапуск) "
    } else {
        " Редактирование config.toml "
    };

    let outer = Block::default()
    .borders(Borders::ALL)
    .title(title)
    .title_style(if proxy_started {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default()
    })
    .style(Style::default().bg(Color::Rgb(20, 20, 35)));
    let inner = outer.inner(popup);
    frame.render_widget(outer, popup);

    let rows = Layout::default()
    .direction(Direction::Vertical)
    .constraints(
        editor.fields.iter().map(|_| Constraint::Length(1)).collect::<Vec<_>>()
    )
    .split(inner);

    for (i, field) in editor.fields.iter().enumerate() {
        if i >= rows.len() {
            break;
        }

        let is_selected = i == editor.selected;
        let is_editing = is_selected && editor.editing_buffer.is_some();

        let label_style = if is_selected {
            Style::default().fg(Color::White).bg(Color::Rgb(42, 42, 90))
        } else {
            Style::default().fg(Color::Gray)
        };

        let value_text = if is_editing {
            format!("{}█", editor.editing_buffer.as_ref().unwrap())
        } else {
            field.value.clone()
        };

        let value_style = if is_editing {
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
        } else if is_selected {
            Style::default().fg(Color::LightGreen)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        let prefix = if is_selected { "▶ " } else { "  " };

        let line = Line::from(vec![
            Span::styled(format!("{}{:<24}", prefix, field.label), label_style),
                              Span::raw(" "),
                              Span::styled(value_text, value_style),
        ]);

        frame.render_widget(Paragraph::new(line), rows[i]);
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
    .direction(Direction::Vertical)
    .constraints([
        Constraint::Percentage((100 - percent_y) / 2),
                 Constraint::Percentage(percent_y),
                 Constraint::Percentage((100 - percent_y) / 2),
    ])
    .split(area);

    Layout::default()
    .direction(Direction::Horizontal)
    .constraints([
        Constraint::Percentage((100 - percent_x) / 2),
                 Constraint::Percentage(percent_x),
                 Constraint::Percentage((100 - percent_x) / 2),
    ])
    .split(vertical[1])[1]
}

fn draw_header(frame: &mut Frame, area: Rect) {
    let title = Paragraph::new("NET SURGEON v0.2.0")
    .style(Style::default().fg(Color::LightBlue).add_modifier(Modifier::BOLD))
    .alignment(ratatui::layout::Alignment::Center)
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(title, area);
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
        ListItem::new(format!("{}{}", prefix, item.label())).style(style)
    })
    .collect();

    let list = List::new(items)
    .block(Block::default().borders(Borders::ALL).title(" Меню "));
    frame.render_widget(list, area);
}

fn draw_status(frame: &mut Frame, area: Rect, app: &App) {
    let s = &app.status;

    let cols = Layout::default()
    .direction(Direction::Horizontal)
    .constraints([
        Constraint::Percentage(25),
                 Constraint::Percentage(25),
                 Constraint::Percentage(25),
                 Constraint::Percentage(25),
    ])
    .split(area);

    let block = |label: &str, on: bool, port: Option<u16>| {
        let (status_text, color) = if on { ("ON", Color::LightGreen) } else { ("OFF", Color::DarkGray) };
        let port_line = port.map(|p| format!(":{}", p)).unwrap_or_default();
        Paragraph::new(vec![
            Line::from(Span::styled(status_text, Style::default().fg(color).add_modifier(Modifier::BOLD))),
                       Line::from(Span::styled(port_line, Style::default().fg(Color::DarkGray))),
        ])
        .alignment(ratatui::layout::Alignment::Center)
        .block(Block::default().borders(Borders::ALL).title(format!(" {} ", label)))
    };

    frame.render_widget(block("TCP", s.tcp_running, Some(s.tcp_port)), cols[0]);
    frame.render_widget(block("UDP", s.udp_running, Some(s.udp_port)), cols[1]);
    frame.render_widget(block("SOCKS5", s.socks5_running, Some(s.socks5_port)), cols[2]);

    let domains = Paragraph::new(vec![
        Line::from(Span::styled(
            s.domains_count.to_string(),
                                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled("bypass", Style::default().fg(Color::DarkGray))),
    ])
    .alignment(ratatui::layout::Alignment::Center)
    .block(Block::default().borders(Borders::ALL).title(" Домены "));
    frame.render_widget(domains, cols[3]);
}

fn draw_metrics(frame: &mut Frame, area: Rect, app: &App) {
    let m = &app.metrics;

    let cols = Layout::default()
    .direction(Direction::Horizontal)
    .constraints([
        Constraint::Percentage(25),
                 Constraint::Percentage(25),
                 Constraint::Percentage(25),
                 Constraint::Percentage(25),
    ])
    .split(area);

    let conn_color = if m.active_connections > 0 { Color::LightGreen } else { Color::DarkGray };
    let connections = Paragraph::new(Line::from(vec![
        Span::styled("Подключений: ", Style::default().fg(Color::DarkGray)),
                                                Span::styled(m.active_connections.to_string(), Style::default().fg(conn_color).add_modifier(Modifier::BOLD)),
    ]))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(connections, cols[0]);

    let rx_text = crate::metrics::format_bytes(m.bytes_rx);
    let rx = Paragraph::new(Line::from(vec![
        Span::styled("↓ RX: ", Style::default().fg(Color::DarkGray)),
                                       Span::styled(rx_text, Style::default().fg(Color::LightBlue).add_modifier(Modifier::BOLD)),
    ]))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(rx, cols[1]);

    let tx_text = crate::metrics::format_bytes(m.bytes_tx);
    let tx = Paragraph::new(Line::from(vec![
        Span::styled("↑ TX: ", Style::default().fg(Color::DarkGray)),
                                       Span::styled(tx_text, Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD)),
    ]))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(tx, cols[2]);

    let dns_status = if m.dns_ok { "OK" } else { "FAIL" };
    let dns_color = if m.dns_ok { Color::LightGreen } else { Color::LightRed };
    let quic_status = if m.quic_target_ok { "OK" } else { "FAIL" };
    let quic_color = if m.quic_target_ok { Color::LightGreen } else { Color::LightRed };

    let health = Paragraph::new(Line::from(vec![
        Span::styled("DNS: ", Style::default().fg(Color::DarkGray)),
                                           Span::styled(dns_status, Style::default().fg(dns_color).add_modifier(Modifier::BOLD)),
                                           Span::raw("  "),
                                           Span::styled("QUIC: ", Style::default().fg(Color::DarkGray)),
                                           Span::styled(quic_status, Style::default().fg(quic_color).add_modifier(Modifier::BOLD)),
                                           Span::raw(format!(" ({})", m.quic_sessions)),
    ]))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(health, cols[3]);
}

fn draw_logs(frame: &mut Frame, area: Rect, app: &App) {
    let items: Vec<ListItem> = app
    .logs
    .iter()
    .rev()
    .take(area.height.saturating_sub(2) as usize)
    .map(|entry| {
        let (icon, color) = match entry.level {
            LogLevel::Info => ("[i]", Color::LightBlue),
         LogLevel::Success => ("[✓]", Color::LightGreen),
         LogLevel::Warning => ("[⚡]", Color::Yellow),
         LogLevel::Error => ("[✗]", Color::LightRed),
        };
        ListItem::new(Line::from(vec![
            Span::styled(icon, Style::default().fg(color)),
                                 Span::raw(" "),
                                 Span::styled(&entry.time, Style::default().fg(Color::DarkGray)),
                                 Span::raw(" "),
                                 Span::raw(&entry.message),
        ]))
    })
    .collect();

    let list = List::new(items)
    .block(Block::default().borders(Borders::ALL).title(" Логи "));
    frame.render_widget(list, area);
}

fn draw_footer(frame: &mut Frame, area: Rect, app: &App) {
    let line = if app.domains_editor.is_some() {
        let is_editing = app.domains_editor.as_ref()
        .map(|e| e.editing_buffer.is_some())
        .unwrap_or(false);
        if is_editing {
            Line::from(vec![
                Span::styled("Enter", Style::default().fg(Color::LightBlue)),
                       Span::raw(" сохранить   "),
                       Span::styled("Esc", Style::default().fg(Color::LightBlue)),
                       Span::raw(" отмена"),
            ])
        } else {
            Line::from(vec![
                Span::styled("↑↓", Style::default().fg(Color::LightBlue)),
                       Span::raw(" навигация   "),
                       Span::styled("a", Style::default().fg(Color::LightBlue)),
                       Span::raw(" добавить   "),
                       Span::styled("e", Style::default().fg(Color::LightBlue)),
                       Span::raw(" изменить   "),
                       Span::styled("d", Style::default().fg(Color::LightBlue)),
                       Span::raw(" удалить   "),
                       Span::styled("Esc/q", Style::default().fg(Color::LightBlue)),
                       Span::raw(" назад"),
            ])
        }
    } else if app.config_editor.is_some() {
        let is_editing = app.config_editor.as_ref()
        .map(|e| e.editing_buffer.is_some())
        .unwrap_or(false);
        if is_editing {
            Line::from(vec![
                Span::styled("Enter", Style::default().fg(Color::LightBlue)),
                       Span::raw(" сохранить   "),
                       Span::styled("Esc", Style::default().fg(Color::LightBlue)),
                       Span::raw(" отмена"),
            ])
        } else {
            Line::from(vec![
                Span::styled("↑↓", Style::default().fg(Color::LightBlue)),
                       Span::raw(" навигация   "),
                       Span::styled("Enter", Style::default().fg(Color::LightBlue)),
                       Span::raw(" редактировать   "),
                       Span::styled("Esc/q", Style::default().fg(Color::LightBlue)),
                       Span::raw(" назад"),
            ])
        }
    } else if app.overlay.is_some() {
        Line::from(vec![
            Span::styled("Esc/Enter", Style::default().fg(Color::LightBlue)),
                   Span::raw(" закрыть"),
        ])
    } else {
        Line::from(vec![
            Span::styled("↑↓", Style::default().fg(Color::LightBlue)),
                   Span::raw(" навигация   "),
                   Span::styled("Enter", Style::default().fg(Color::LightBlue)),
                   Span::raw(" выбрать   "),
                   Span::styled("q", Style::default().fg(Color::LightBlue)),
                   Span::raw(" выход"),
        ])
    };
    let footer = Paragraph::new(line)
    .alignment(ratatui::layout::Alignment::Center)
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(footer, area);
}
