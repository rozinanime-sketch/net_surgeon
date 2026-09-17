//! Экран запуска DPI-диагностики — состояние + обработка клавиш.
//!
//! Поле last_result (со структурой DiagnosticsDisplay) из старого проекта
//! сюда сознательно НЕ перенесено — оно никогда не читалось (диагностика
//! всегда шла через логи, log_nested_t), это был мёртвый код (Шаг 1 плана).

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

use super::StepResult;

pub struct DiagnosticsState {
    /// Буфер ввода домена; None пока не активен ввод.
    pub input_buffer: Option<String>,
    /// true пока тест выполняется в фоне.
    pub running: bool,
}

impl DiagnosticsState {
    /// Экран открывается в режиме выбора, а не ввода.
    ///
    /// Раньше ввод был активен сразу, а клавиша `a` в нём перехватывалась под
    /// массовый прогон — из-за чего домен на букву «a» (`api.…`, `amazon.com`)
    /// набрать было невозможно: первая же буква запускала прогон по всему
    /// списку. Теперь `n` открывает ввод, `a` запускает массовый прогон,
    /// и внутри ввода буквы остаются буквами.
    pub fn new() -> Self {
        Self { input_buffer: None, running: false }
    }
}

pub fn handle_key(state: &mut DiagnosticsState, key: KeyCode) -> StepResult {
    let is_input_active = state.input_buffer.is_some();

    if is_input_active {
        match key {
            KeyCode::Enter => {
                let domain = state.input_buffer.clone().unwrap_or_default().trim().to_lowercase();
                if domain.is_empty() {
                    return StepResult::Stay(Action::None);
                }
                state.input_buffer = None;
                state.running = true;
                StepResult::Stay(Action::RunDiagnostics(domain))
            }
            KeyCode::Esc => StepResult::Close(Action::None),
            KeyCode::Backspace => {
                if let Some(buf) = state.input_buffer.as_mut() { buf.pop(); }
                StepResult::Stay(Action::None)
            }
            KeyCode::Char(c) => {
                if let Some(buf) = state.input_buffer.as_mut() { buf.push(c); }
                StepResult::Stay(Action::None)
            }
            _ => StepResult::Stay(Action::None),
        }
    } else {
        match key {
            KeyCode::Char('n') => {
                state.input_buffer = Some(String::new());
                StepResult::Stay(Action::None)
            }
            KeyCode::Char('a') => {
                state.running = true;
                StepResult::Stay(Action::RunDiagnosticsAll)
            }
            KeyCode::Esc | KeyCode::Char('q') => StepResult::Close(Action::None),
            _ => StepResult::Stay(Action::None),
        }
    }
}

// --- Отрисовка: перенесено из старого ui.rs::draw_diagnostics. Поле last_result
// (DiagnosticsDisplay) там не использовалось вообще — соответственно, здесь
// в отрисовке его тоже нет, как и в состоянии выше (Шаг 1 плана). ---

pub fn draw(frame: &mut Frame, area: Rect, screen: &DiagnosticsState) {
    let popup = super::centered_rect(60, 40, area);
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
        let hint = Line::from(Span::styled(t!("diagnostics.enter_hint").to_string(), Style::default().fg(Color::DarkGray)));
        let p = Paragraph::new(vec![line, Line::from(""), hint]);
        frame.render_widget(p, inner);
    } else if screen.running {
        let p = Paragraph::new(t!("diagnostics.running").to_string()).style(Style::default().fg(Color::Yellow));
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
