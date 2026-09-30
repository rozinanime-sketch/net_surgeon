//! Экран «Трафик» — разбивка по доменам: кто сколько отдал и получил.
//!
//! Отвечает на «кто льёт»: почему трафик такой, какой он есть. Данные —
//! снимок `Metrics::top_domains` (тяжёлые сверху), приходит через
//! `Action::RefreshTraffic` при открытии и по клавише `r`. Копится раз на
//! закрытие соединения, так что цифры отражают завершённые соединения; ещё
//! идущая крупная загрузка появится, когда закроется.

use crossterm::event::KeyCode;
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem},
    Frame,
};
use rust_i18n::t;

use crate::cli::action::Action;
use crate::observability::metrics::{format_bytes, DomainTraffic};

#[derive(Default)]
pub struct TrafficState {
    pub rows: Vec<DomainTraffic>,
    /// Суммарный трафик по всем доменам (не только показанным в топе).
    pub total: u64,
    pub scroll: usize,
}

impl TrafficState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_rows(&mut self, rows: Vec<DomainTraffic>, total: u64) {
        self.rows = rows;
        self.total = total;
        let max = self.rows.len().saturating_sub(1);
        if self.scroll > max {
            self.scroll = max;
        }
    }
}

pub fn handle_key(state: &mut TrafficState, key: KeyCode) -> super::StepResult {
    use super::StepResult;
    let last = state.rows.len().saturating_sub(1);
    match key {
        KeyCode::Esc | KeyCode::Char('q') => StepResult::Close(Action::None),
        KeyCode::Char('r') => StepResult::Stay(Action::RefreshTraffic),
        KeyCode::Up | KeyCode::Char('k') => {
            state.scroll = state.scroll.saturating_sub(1);
            StepResult::Stay(Action::None)
        }
        KeyCode::Down | KeyCode::Char('j') => {
            state.scroll = (state.scroll + 1).min(last);
            StepResult::Stay(Action::None)
        }
        KeyCode::PageUp => {
            state.scroll = state.scroll.saturating_sub(10);
            StepResult::Stay(Action::None)
        }
        KeyCode::PageDown => {
            state.scroll = (state.scroll + 10).min(last);
            StepResult::Stay(Action::None)
        }
        KeyCode::Home => {
            state.scroll = 0;
            StepResult::Stay(Action::None)
        }
        KeyCode::End => {
            state.scroll = last;
            StepResult::Stay(Action::None)
        }
        _ => StepResult::Stay(Action::None),
    }
}

pub fn draw(frame: &mut Frame, area: Rect, state: &TrafficState) {
    frame.render_widget(Clear, area);

    let title = if state.total > 0 {
        format!(" {} — {} ", t!("traffic.panel_title"), format_bytes(state.total))
    } else {
        format!(" {} ", t!("traffic.panel_title"))
    };
    let outer = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .style(Style::default().bg(Color::Rgb(18, 18, 30)));
    let inner = outer.inner(area);
    frame.render_widget(outer, area);

    if state.rows.is_empty() {
        let empty = List::new(vec![ListItem::new(Line::from(Span::styled(
            t!("traffic.empty").to_string(),
            Style::default().fg(Color::DarkGray),
        )))]);
        frame.render_widget(empty, inner);
        return;
    }

    let header = Line::from(Span::styled(
        format!(
            "{:<34} {:>11} {:>11} {:>11}",
            t!("traffic.col_domain"),
            t!("traffic.col_up"),
            t!("traffic.col_down"),
            t!("traffic.col_total"),
        ),
        Style::default().fg(Color::Gray).add_modifier(Modifier::BOLD),
    ));

    let visible = inner.height.saturating_sub(1) as usize; // минус строка шапки
    let mut items: Vec<ListItem> = vec![ListItem::new(header)];
    items.extend(state.rows.iter().skip(state.scroll).take(visible).map(row_item));
    frame.render_widget(List::new(items), inner);
}

fn row_item(r: &DomainTraffic) -> ListItem<'static> {
    ListItem::new(Line::from(vec![
        Span::styled(format!("{:<34} ", truncate(&r.domain, 34)), Style::default().add_modifier(Modifier::BOLD)),
        Span::styled(format!("{:>11} ", format_bytes(r.rx)), Style::default().fg(Color::LightBlue)),
        Span::styled(format!("{:>11} ", format_bytes(r.tx)), Style::default().fg(Color::LightGreen)),
        Span::styled(format!("{:>11}", format_bytes(r.rx + r.tx)), Style::default().fg(Color::Gray)),
    ]))
}

/// Обрезает по числу символов (не байтов), чтобы кириллица не билась.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{cut}…")
    }
}
