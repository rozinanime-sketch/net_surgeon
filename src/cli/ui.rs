use rust_i18n::t;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Sparkline, Wrap},
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
                 Constraint::Length(5),
                 Constraint::Min(0),
    ])
    .split(body[1]);

    draw_status(frame, right[0], app);
    draw_metrics(frame, right[1], app);
    draw_traffic_graph(frame, right[2], app);
    draw_logs(frame, right[3], app);

    draw_footer(frame, root[2], app);

    if let Some(text) = &app.overlay {
        draw_overlay(frame, frame.area(), text);
    }

    if let Some(editor) = &app.config_editor {
        draw_config_editor(frame, frame.area(), app, editor, app.proxy_started);
    }

    if let Some(screen) = &app.diagnostics {
        draw_diagnostics(frame, frame.area(), screen);
    }

    if let Some(editor) = &app.domains_editor {
        draw_domains_editor(frame, frame.area(), editor, app.proxy_started);
    }
}

fn draw_diagnostics(frame: &mut Frame, area: Rect, screen: &super::app::DiagnosticsScreen) {
    let popup = centered_rect(60, 40, area);
    frame.render_widget(Clear, popup);

    let outer = Block::default()
    .borders(Borders::ALL)
    .title(format!(" {} ", t!("diagnostics.panel_title")))
    .style(Style::default().bg(Color::Rgb(20, 20, 35)));
    let inner = outer.inner(popup);
    frame.render_widget(outer, popup);

    if let Some(buf) = &screen.input_buffer {
        let line = Line::from(vec![
            Span::styled(t!("diagnostics.domain_label").to_string(), Style::default().fg(Color::DarkGray)),
                              Span::styled(format!("{}█", buf), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        ]);
        let hint = Line::from(Span::styled(
            t!("diagnostics.enter_hint").to_string(),
                                           Style::default().fg(Color::DarkGray),
        ));
        let p = Paragraph::new(vec![line, Line::from(""), hint]);
        frame.render_widget(p, inner);
    } else if screen.running {
        let p = Paragraph::new(t!("diagnostics.running").to_string())
        .style(Style::default().fg(Color::Yellow));
        frame.render_widget(p, inner);
    } else {
        let p = Paragraph::new(vec![
            Line::from(t!("diagnostics.result_hint").to_string()),
                               Line::from(""),
                               Line::from(Span::styled(t!("diagnostics.back_hint").to_string(), Style::default().fg(Color::DarkGray))),
        ]);
        frame.render_widget(p, inner);
    }
}

fn draw_domains_editor(frame: &mut Frame, area: Rect, editor: &super::app::DomainsEditor, proxy_started: bool) {
    let popup = centered_rect(60, 80, area);
    frame.render_widget(Clear, popup);

    let title = if proxy_started {
        format!(" {}{} ", t!("domains.panel_title"), t!("domains.restart_needed"))
    } else {
        format!(" {} ({}) ", t!("domains.panel_title"), editor.domains.len())
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
        let empty = Paragraph::new(t!("domains.empty_hint").to_string())
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
        let label = if editor.is_editing_existing {
            t!("domains.edit_domain").to_string()
        } else {
            t!("domains.new_domain").to_string()
        };
        let input_line = Line::from(vec![
            Span::styled(label, Style::default().fg(Color::DarkGray)),
                                    Span::styled(format!("{}█", buf), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        ]);
        frame.render_widget(Paragraph::new(input_line), chunks[1]);
    }
}

fn draw_traffic_graph(frame: &mut Frame, area: Rect, app: &App) {
    let cols = Layout::default()
    .direction(Direction::Horizontal)
    .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
    .split(area);

    let rx_data: Vec<u64> = app.traffic_history.rx_speed.iter().copied().collect();
    let rx_max = rx_data.iter().copied().max().unwrap_or(0);
    let rx_label = if rx_max > 0 {
        format!(" ↓ RX/сек (пик {}) ", crate::metrics::format_bytes(rx_max))
    } else {
        " ↓ RX/сек ".to_string()
    };

    let rx_sparkline = Sparkline::default()
    .block(Block::default().borders(Borders::ALL).title(rx_label))
    .data(&rx_data)
    .style(Style::default().fg(Color::LightBlue));
    frame.render_widget(rx_sparkline, cols[0]);

    let tx_data: Vec<u64> = app.traffic_history.tx_speed.iter().copied().collect();
    let tx_max = tx_data.iter().copied().max().unwrap_or(0);
    let tx_label = if tx_max > 0 {
        format!(" ↑ TX/сек (пик {}) ", crate::metrics::format_bytes(tx_max))
    } else {
        " ↑ TX/сек ".to_string()
    };

    let tx_sparkline = Sparkline::default()
    .block(Block::default().borders(Borders::ALL).title(tx_label))
    .data(&tx_data)
    .style(Style::default().fg(Color::LightGreen));
    frame.render_widget(tx_sparkline, cols[1]);
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

fn draw_config_editor(frame: &mut Frame, area: Rect, app: &App, editor: &super::app::ConfigEditor, proxy_started: bool) {
    let popup = centered_rect(70, 80, area);
    frame.render_widget(Clear, popup);

    let title = if proxy_started {
        format!("{}{}", t!("config.panel_title"), t!("config.restart_needed"))
    } else {
        t!("config.panel_title").to_string()
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
        let label = super::i18n::translate(app.language.code(), field.label_key, &[]);

        let line = Line::from(vec![
            Span::styled(format!("{}{:<24}", prefix, label), label_style),
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
    let title = Paragraph::new(t!("app.title").to_string())
    .style(Style::default().fg(Color::LightBlue).add_modifier(Modifier::BOLD))
    .alignment(ratatui::layout::Alignment::Center)
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(title, area);
}

fn menu_label(item: MenuItem) -> String {
    match item {
        MenuItem::Status => t!("menu.status").to_string(),
        MenuItem::Bypass => t!("menu.bypass").to_string(),
        MenuItem::Domains => t!("menu.domains").to_string(),
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

    let border_style = if app.focus == super::app::Focus::Menu {
        Style::default().fg(Color::LightBlue)
    } else {
        Style::default()
    };

    let list = List::new(items)
    .block(Block::default().borders(Borders::ALL).title(format!(" {} ", t!("menu.panel_title"))).border_style(border_style));
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
        .alignment(ratatui::layout::Alignment::Center)
        .block(Block::default().borders(Borders::ALL).title(format!(" {} ", label)))
    };

    frame.render_widget(block(t!("status.tcp").to_string(), s.tcp_running, Some(s.tcp_port)), cols[0]);
    frame.render_widget(block(t!("status.udp").to_string(), s.udp_running, Some(s.udp_port)), cols[1]);
    frame.render_widget(block(t!("status.socks5").to_string(), s.socks5_running, Some(s.socks5_port)), cols[2]);

    let domains = Paragraph::new(vec![
        Line::from(Span::styled(
            s.domains_count.to_string(),
                                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(t!("status.bypass_label").to_string(), Style::default().fg(Color::DarkGray))),
    ])
    .alignment(ratatui::layout::Alignment::Center)
    .block(Block::default().borders(Borders::ALL).title(format!(" {} ", t!("status.domains_panel"))));
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
        Span::styled(t!("metrics.connections").to_string(), Style::default().fg(Color::DarkGray)),
                                                Span::styled(m.active_connections.to_string(), Style::default().fg(conn_color).add_modifier(Modifier::BOLD)),
    ]))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(connections, cols[0]);

    let rx_text = crate::metrics::format_bytes(m.bytes_rx);
    let rx = Paragraph::new(Line::from(vec![
        Span::styled(t!("metrics.rx").to_string(), Style::default().fg(Color::DarkGray)),
                                       Span::styled(rx_text, Style::default().fg(Color::LightBlue).add_modifier(Modifier::BOLD)),
    ]))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(rx, cols[1]);

    let tx_text = crate::metrics::format_bytes(m.bytes_tx);
    let tx = Paragraph::new(Line::from(vec![
        Span::styled(t!("metrics.tx").to_string(), Style::default().fg(Color::DarkGray)),
                                       Span::styled(tx_text, Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD)),
    ]))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(tx, cols[2]);

    let dns_status = if m.dns_ok { t!("metrics.ok").to_string() } else { t!("metrics.fail").to_string() };
    let dns_color = if m.dns_ok { Color::LightGreen } else { Color::LightRed };
    let quic_status = if m.quic_target_ok { t!("metrics.ok").to_string() } else { t!("metrics.fail").to_string() };
    let quic_color = if m.quic_target_ok { Color::LightGreen } else { Color::LightRed };

    let quic_rate = if m.quic_initial_sent > 0 {
        format!(" {}/{}", m.quic_handshake_success, m.quic_initial_sent)
    } else {
        String::new()
    };

    let health = Paragraph::new(Line::from(vec![
        Span::styled(t!("metrics.dns").to_string(), Style::default().fg(Color::DarkGray)),
                                           Span::styled(dns_status, Style::default().fg(dns_color).add_modifier(Modifier::BOLD)),
                                           Span::raw("  "),
                                           Span::styled(t!("metrics.quic").to_string(), Style::default().fg(Color::DarkGray)),
                                           Span::styled(quic_status, Style::default().fg(quic_color).add_modifier(Modifier::BOLD)),
                                           Span::raw(format!(" ({})", m.quic_sessions)),
                                           Span::styled(quic_rate, Style::default().fg(Color::DarkGray)),
    ]))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(health, cols[3]);
}

fn draw_logs(frame: &mut Frame, area: Rect, app: &App) {
    let visible_height = area.height.saturating_sub(2) as usize;
    let total = app.logs.len();

    let skip_from_end = app.log_scroll.min(total.saturating_sub(visible_height.max(1)).max(app.log_scroll));

    let items: Vec<ListItem> = app
    .logs
    .iter()
    .rev()
    .skip(skip_from_end)
    .take(visible_height)
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
                                 Span::styled(render_log_message(app, &entry.message), Style::default().fg(color)),
        ]))
    })
    .collect();

    let title = if app.log_autoscroll {
        format!(" {} ", t!("logs.panel_title"))
    } else {
        format!(" {} (scroll) ", t!("logs.panel_title"))
    };

    let title_style = if app.log_autoscroll {
        Style::default()
    } else {
        Style::default().fg(Color::Yellow)
    };

    let border_style = if app.focus == super::app::Focus::Logs {
        Style::default().fg(Color::LightBlue)
    } else {
        Style::default()
    };

    let list = List::new(items)
    .block(Block::default().borders(Borders::ALL).title(title).title_style(title_style).border_style(border_style));
    frame.render_widget(list, area);
}

fn render_log_message(app: &App, msg: &super::app::LogMessage) -> String {
    match msg {
        super::app::LogMessage::Plain(s) => s.clone(),
        super::app::LogMessage::Translated { key, args } => {
            super::i18n::translate(app.language.code(), key, args)
        }
        super::app::LogMessage::NestedTranslated { key, nested_arg, nested_key, args } => {
            super::i18n::translate_nested(app.language.code(), key, nested_arg, nested_key, args)
        }
    }
}

fn draw_footer(frame: &mut Frame, area: Rect, app: &App) {
    let line = if app.diagnostics.is_some() {
        let is_input_active = app.diagnostics.as_ref()
        .map(|d| d.input_buffer.is_some())
        .unwrap_or(false);
        if is_input_active {
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
                       Span::styled("Esc/q", Style::default().fg(Color::LightBlue)),
                       Span::raw(format!(" {}", t!("footer.back"))),
            ])
        }
    } else if app.domains_editor.is_some() {
        let is_editing = app.domains_editor.as_ref()
        .map(|e| e.editing_buffer.is_some())
        .unwrap_or(false);
        if is_editing {
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
    } else if app.config_editor.is_some() {
        let is_editing = app.config_editor.as_ref()
        .map(|e| e.editing_buffer.is_some())
        .unwrap_or(false);
        if is_editing {
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
    } else if app.overlay.is_some() {
        Line::from(vec![
            Span::styled("Esc/Enter", Style::default().fg(Color::LightBlue)),
                   Span::raw(format!(" {}", t!("footer.close"))),
        ])
    } else {
        Line::from(vec![
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
        ])
    };
    let footer = Paragraph::new(line)
    .alignment(ratatui::layout::Alignment::Center)
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(footer, area);
}
