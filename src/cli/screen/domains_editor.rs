//! Экран редактирования списков доменов (bypass_domains.txt и
//! block_domains.txt) — состояние + I/O + обработка клавиш. Формат у файлов
//! один, различаются только путь и подписи, поэтому экран общий.

use std::collections::HashSet;

use crossterm::event::KeyCode;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph},
    Frame,
};
use rust_i18n::t;

use crate::cli::action::Action;
use crate::observability::error::AppError;

use super::StepResult;

/// Какой из списков открыт в редакторе.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainList {
    Bypass,
    Block,
}

impl DomainList {
    fn path(self) -> &'static str {
        match self {
            DomainList::Bypass => "bypass_domains.txt",
            DomainList::Block => "block_domains.txt",
        }
    }

    fn title_key(self) -> &'static str {
        match self {
            DomainList::Bypass => "domains.panel_title",
            DomainList::Block => "blocklist.panel_title",
        }
    }

    pub fn saved_key(self, proxy_started: bool) -> &'static str {
        match (self, proxy_started) {
            (DomainList::Bypass, false) => "domains.saved",
            (DomainList::Bypass, true) => "domains.saved_restart",
            (DomainList::Block, false) => "blocklist.saved",
            (DomainList::Block, true) => "blocklist.saved_restart",
        }
    }
}

pub struct DomainsEditorState {
    pub list: DomainList,
    pub domains: Vec<String>,
    pub selected: usize,
    /// Some(buffer) когда вводим новый домен ИЛИ редактируем существующий.
    pub editing_buffer: Option<String>,
    /// true если редактируем существующий домен (а не добавляем новый).
    pub is_editing_existing: bool,
}

impl DomainsEditorState {
    pub fn new(list: DomainList, domains: Vec<String>) -> Self {
        Self { list, domains, selected: 0, editing_buffer: None, is_editing_existing: false }
    }

    pub fn next(&mut self) {
        if !self.domains.is_empty() {
            self.selected = (self.selected + 1) % self.domains.len();
        }
    }

    pub fn previous(&mut self) {
        if !self.domains.is_empty() {
            self.selected = if self.selected == 0 { self.domains.len() - 1 } else { self.selected - 1 };
        }
    }
}

pub fn handle_key(state: &mut DomainsEditorState, key: KeyCode) -> StepResult {
    if state.editing_buffer.is_some() {
        match key {
            KeyCode::Enter => {
                let new_domain = state.editing_buffer.clone().unwrap_or_default().trim().to_lowercase();

                if new_domain.is_empty() {
                    state.editing_buffer = None;
                    state.is_editing_existing = false;
                    return StepResult::Stay(Action::None);
                }

                if state.is_editing_existing {
                    state.domains[state.selected] = new_domain.clone();
                } else if !state.domains.contains(&new_domain) {
                    state.domains.push(new_domain.clone());
                }
                state.domains.sort();
                // Переименование в уже существующий домен оставляло две
                // одинаковые строки. Список отсортирован — дубли рядом.
                state.domains.dedup();
                state.selected = state.domains.iter().position(|d| d == &new_domain).unwrap_or(0);
                state.editing_buffer = None;
                state.is_editing_existing = false;

                // NB: app.status.domains_count обновляется в screen::handle_key()
                // на основе длины Vec внутри этого Action — состояние не знает про App.
                StepResult::Stay(Action::SaveDomains(state.list, state.domains.clone()))
            }
            KeyCode::Esc => {
                state.editing_buffer = None;
                state.is_editing_existing = false;
                StepResult::Stay(Action::None)
            }
            KeyCode::Backspace => {
                if let Some(buf) = state.editing_buffer.as_mut() { buf.pop(); }
                StepResult::Stay(Action::None)
            }
            KeyCode::Char(c) => {
                if let Some(buf) = state.editing_buffer.as_mut() { buf.push(c); }
                StepResult::Stay(Action::None)
            }
            _ => StepResult::Stay(Action::None),
        }
    } else {
        match key {
            KeyCode::Up | KeyCode::Char('k') => { state.previous(); StepResult::Stay(Action::None) }
            KeyCode::Down | KeyCode::Char('j') => { state.next(); StepResult::Stay(Action::None) }
            KeyCode::Char('a') => {
                state.editing_buffer = Some(String::new());
                state.is_editing_existing = false;
                StepResult::Stay(Action::None)
            }
            KeyCode::Char('e') => {
                if !state.domains.is_empty() {
                    state.editing_buffer = Some(state.domains[state.selected].clone());
                    state.is_editing_existing = true;
                }
                StepResult::Stay(Action::None)
            }
            KeyCode::Char('d') | KeyCode::Delete => {
                if state.domains.is_empty() {
                    return StepResult::Stay(Action::None);
                }
                state.domains.remove(state.selected);
                if state.selected >= state.domains.len() && state.selected > 0 {
                    state.selected -= 1;
                }
                StepResult::Stay(Action::SaveDomains(state.list, state.domains.clone()))
            }
            KeyCode::Esc | KeyCode::Char('q') => StepResult::Close(Action::None),
            _ => StepResult::Stay(Action::None),
        }
    }
}

// --- I/O ---

/// Строки-комментарии пропускаются так же, как в `config::load_bypass_domains`.
/// Раньше редактор показывал их как домены и учитывал в счётчике.
pub fn load_domains(list: DomainList) -> Result<Vec<String>, AppError> {
    let text = crate::config::paths::read_to_string(list.path()).unwrap_or_default();
    Ok(text
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect())
}

pub fn save_domains(list: DomainList, domains: &[String]) -> Result<(), AppError> {
    let existing = crate::config::paths::read_to_string(list.path()).unwrap_or_default();
    let content = render_domains_file(&existing, domains);
    crate::config::paths::write_atomic(list.path(), &content)
        .map_err(|e| AppError::new("error.domains_write").with("error", e))
}

/// Файл переписывается по месту: комментарии и пустые строки остаются где
/// были, удалённые домены выпадают, новые дописываются в конец. Раньше все
/// комментарии поднимались наверх, а домены шли следом по алфавиту — в
/// block_domains.txt это отрывало заголовки групп («# Google Analytics»)
/// от их доменов.
fn render_domains_file(existing: &str, domains: &[String]) -> String {
    let wanted: HashSet<&str> = domains.iter().map(String::as_str).collect();
    let mut written: HashSet<&str> = HashSet::new();
    let mut out = String::new();
    for line in existing.lines() {
        let trimmed = line.trim();
        let keep = trimmed.is_empty()
            || trimmed.starts_with('#')
            || (wanted.contains(trimmed) && written.insert(trimmed));
        if keep {
            out.push_str(line);
            out.push('\n');
        }
    }
    for domain in domains {
        if written.insert(domain) {
            out.push_str(domain);
            out.push('\n');
        }
    }
    out
}

// --- Отрисовка ---

pub fn draw(frame: &mut Frame, area: Rect, editor: &DomainsEditorState, proxy_started: bool) {
    let popup = super::centered_rect(60, 80, area);
    frame.render_widget(Clear, popup);

    let title = if proxy_started {
        format!(" {}{} ", t!(editor.list.title_key()), t!("domains.restart_needed"))
    } else {
        format!(" {} ({}) ", t!(editor.list.title_key()), editor.domains.len())
    };

    let outer = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .title_style(if proxy_started { Style::default().fg(Color::Yellow) } else { Style::default() })
        .style(Style::default().bg(Color::Rgb(20, 20, 35)));
    let inner = outer.inner(popup);
    frame.render_widget(outer, popup);

    let is_editing = editor.editing_buffer.is_some();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(if is_editing { vec![Constraint::Min(0), Constraint::Length(1)] } else { vec![Constraint::Min(0)] })
        .split(inner);

    if editor.domains.is_empty() {
        let empty = Paragraph::new(t!("domains.empty_hint").to_string()).style(Style::default().fg(Color::DarkGray));
        frame.render_widget(empty, chunks[0]);
    } else {
        let items: Vec<ListItem> = editor.domains
            .iter()
            .enumerate()
            .map(|(i, domain)| {
                let selected = i == editor.selected && !is_editing;
                let prefix = if selected { crate::observability::glyph::SELECTED } else { "  " };
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
        let label = if editor.is_editing_existing { t!("domains.edit_domain").to_string() } else { t!("domains.new_domain").to_string() };
        let input_line = Line::from(vec![
            Span::styled(label, Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{}█", buf), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        ]);
        frame.render_widget(Paragraph::new(input_line), chunks[1]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saving_keeps_comments_in_place_and_does_not_duplicate_them_as_domains() {
        let existing = "# мой список\nyoutube.com\n\n# ещё\nx.com\n";
        let out = render_domains_file(existing, &["x.com".to_string(), "youtube.com".to_string()]);
        assert_eq!(out, existing);
    }

    #[test]
    fn saving_drops_removed_and_appends_new_domains() {
        let existing = "# Метрика\nmc.yandex.ru\nmc.yandex.by\n\n# GA\ngoogle-analytics.com\n";
        let domains = ["google-analytics.com", "mc.yandex.ru", "new.tracker.io"].map(String::from);
        let out = render_domains_file(existing, &domains);
        assert_eq!(out, "# Метрика\nmc.yandex.ru\n\n# GA\ngoogle-analytics.com\nnew.tracker.io\n");
    }

    #[test]
    fn saving_collapses_duplicate_lines() {
        let out = render_domains_file("x.com\nx.com\n", &["x.com".to_string()]);
        assert_eq!(out, "x.com\n");
    }
}
