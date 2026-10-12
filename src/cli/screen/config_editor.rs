//! Экран редактирования config.toml — состояние + I/O + обработка клавиш
//! в одном файле (в старом проекте I/O жило в отдельном top-level
//! config_editor.rs, а состояние и обработка клавиш — в app.rs/events.rs).

use crossterm::event::KeyCode;
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};
use rust_i18n::t;
use crate::cli::action::Action;
pub use crate::config::editor::{load_fields, save_field, ConfigField};
use crate::cli::app::App;

use super::StepResult;

pub struct ConfigEditorState {
    pub fields: Vec<ConfigField>,
    pub selected: usize,
    pub editing_buffer: Option<String>,
}

impl ConfigEditorState {
    pub fn new(fields: Vec<ConfigField>) -> Self {
        Self { fields, selected: 0, editing_buffer: None }
    }

    pub fn next(&mut self) {
        if !self.fields.is_empty() {
            self.selected = (self.selected + 1) % self.fields.len();
        }
    }

    pub fn previous(&mut self) {
        if !self.fields.is_empty() {
            self.selected = if self.selected == 0 { self.fields.len() - 1 } else { self.selected - 1 };
        }
    }
}

pub fn handle_key(state: &mut ConfigEditorState, key: KeyCode) -> StepResult {
    if state.editing_buffer.is_some() {
        match key {
            KeyCode::Enter => {
                let path = state.fields[state.selected].toml_path;
                let new_value = state.editing_buffer.take().unwrap_or_default();
                // Оптимистично обновляем UI сразу — запись на диск уходит в фон через Action.
                state.fields[state.selected].value = new_value.clone();
                StepResult::Stay(Action::SaveConfigField(path, new_value))
            }
            KeyCode::Esc => {
                state.editing_buffer = None;
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
            KeyCode::Enter => {
                state.editing_buffer = Some(state.fields[state.selected].value.clone());
                StepResult::Stay(Action::None)
            }
            KeyCode::Esc | KeyCode::Char('q') => StepResult::Close(Action::None),
            _ => StepResult::Stay(Action::None),
        }
    }
}

// --- Отрисовка ---

pub fn draw(frame: &mut Frame, area: Rect, app: &App, editor: &ConfigEditorState, proxy_started: bool) {
    let popup = super::centered_rect(70, 80, area);
    frame.render_widget(Clear, popup);

    let title = if proxy_started {
        format!("{}{}", t!("config.panel_title"), t!("config.restart_needed"))
    } else {
        t!("config.panel_title").to_string()
    };

    let outer = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .title_style(if proxy_started { Style::default().fg(Color::Yellow) } else { Style::default() })
        .style(Style::default().bg(Color::Rgb(20, 20, 35)));
    let inner = outer.inner(popup);
    frame.render_widget(outer, popup);

    let lang = app.language.code();
    let mut lines: Vec<Line> = Vec::new();
    let mut selected_line = 0;

    for (i, field) in editor.fields.iter().enumerate() {
        if i == 0 || editor.fields[i - 1].group_key != field.group_key {
            if i > 0 {
                lines.push(Line::raw(""));
            }
            let heading = crate::observability::i18n::translate(lang, field.group_key, &[]);
            lines.push(Line::styled(
                heading,
                Style::default().fg(Color::LightBlue).add_modifier(Modifier::BOLD),
            ));
        }

        let is_selected = i == editor.selected;
        let is_editing = is_selected && editor.editing_buffer.is_some();
        if is_selected {
            selected_line = lines.len();
        }

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

        let prefix = if is_selected { crate::observability::glyph::SELECTED } else { "  " };
        let label = crate::observability::i18n::translate(lang, field.label_key, &[]);

        lines.push(Line::from(vec![
            Span::styled(format!("{}{:<34}", prefix, label), label_style),
            Span::raw(" "),
            Span::styled(value_text, value_style),
        ]));
    }

    // С заголовками групп строк больше, чем влезает в невысокий терминал.
    // Раньше лишние поля просто не рисовались; теперь список прокручивается
    // так, чтобы выбранное поле всегда было видно.
    let height = inner.height as usize;
    let scroll = scroll_offset(selected_line, height, lines.len());
    frame.render_widget(Paragraph::new(lines).scroll((scroll as u16, 0)), inner);
}

/// Выбранная строка держится у нижнего края, пока список не упрётся в конец.
fn scroll_offset(selected_line: usize, height: usize, total: usize) -> usize {
    if height == 0 || total <= height {
        return 0;
    }
    (selected_line + 1).saturating_sub(height).min(total - height)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scroll_keeps_selection_visible() {
        assert_eq!(scroll_offset(5, 10, 30), 0);
        assert_eq!(scroll_offset(9, 10, 30), 0);
        assert_eq!(scroll_offset(10, 10, 30), 1);
        assert_eq!(scroll_offset(29, 10, 30), 20);
        assert_eq!(scroll_offset(29, 40, 30), 0);
    }
}
