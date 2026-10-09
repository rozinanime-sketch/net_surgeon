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
use crate::engine::diagnostics::{ProbeOutcome, SplitScore};
use crate::engine::domain_check::DomainCheck;
use crate::engine::strategy::Strategy;

use super::StepResult;

#[derive(Default)]
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
                // Стираем прошлый вердикт: он относился к другому домену и не
                // должен выглядеть ответом на новый вопрос.
                crate::engine::domain_check::clear();
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
    // Готовый разбор показываем крупнее: строк много (направления + пробы техник).
    let has_result = screen.input_buffer.is_none()
        && !screen.running
        && crate::engine::domain_check::with(|c| c.is_some());
    let (w, h) = if has_result { (68, 70) } else { (60, 40) };

    let popup = super::centered_rect(w, h, area);
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
    } else if has_result {
        let lines = crate::engine::domain_check::with(|c| c.map(result_lines)).unwrap_or_default();
        frame.render_widget(Paragraph::new(lines), inner);
    } else {
        let p = Paragraph::new(vec![
            Line::from(t!("diagnostics.result_hint").to_string()),
            Line::from(""),
            Line::from(Span::styled(t!("diagnostics.back_hint").to_string(), Style::default().fg(Color::DarkGray))),
        ]);
        frame.render_widget(p, inner);
    }
}

/// Короткая подпись исхода пробы: три смысловых ведра, чтобы не тонуть в
/// десяти вариантах — «проходит», «подмена/порча», «не проходит».
fn outcome_label(o: ProbeOutcome) -> (String, Color) {
    use ProbeOutcome::*;
    match o {
        Success | UdpReachable => (t!("check.o_pass").to_string(), Color::LightGreen),
        Injected | Mangled => (t!("check.o_inject").to_string(), Color::Yellow),
        NotApplicable => (t!("check.o_na").to_string(), Color::DarkGray),
        _ => (t!("check.o_fail").to_string(), Color::LightRed),
    }
}

/// Строка «метка: значение» с цветным значением.
fn kv(label: String, value: (String, Color)) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label}: "), Style::default().fg(Color::DarkGray)),
        Span::styled(value.0, Style::default().fg(value.1).add_modifier(Modifier::BOLD)),
    ])
}

/// Разбор проверки домена в строки для панели.
fn result_lines(c: &DomainCheck) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(Span::styled(
        c.domain.clone(),
        Style::default().fg(Color::LightBlue).add_modifier(Modifier::BOLD),
    ))];

    if c.blocked {
        lines.push(Line::from(Span::styled(
            t!("check.blocked").to_string(),
            Style::default().fg(Color::LightRed),
        )));
    }

    lines.push(Line::from(""));
    lines.push(kv(t!("check.direct").to_string(), outcome_label(c.result.direct)));
    lines.push(kv(t!("check.quic").to_string(), outcome_label(c.result.quic)));

    lines.push(Line::from(""));
    let (tech_text, tech_color) = match c.chosen {
        Some(s) => {
            let color = if matches!(s, Strategy::Fake | Strategy::Seqovl) { Color::LightMagenta } else { Color::LightGreen };
            (t!(s.label_key()).to_string(), color)
        }
        None => (t!("check.nothing").to_string(), Color::LightRed),
    };
    lines.push(kv(t!("check.technique").to_string(), (tech_text, tech_color)));

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        t!("check.techniques").to_string(),
        Style::default().fg(Color::DarkGray),
    )));
    let probes: [(&str, &SplitScore); 7] = [
        ("tls_record", &c.result.tls_record),
        ("sni_split", &c.result.sni_split),
        ("disorder", &c.result.disorder),
        ("oob", &c.result.oob),
        ("fake", &c.result.fake),
        ("fake_multidisorder", &c.result.fake_multidisorder),
        ("seqovl", &c.result.seqovl),
    ];
    for (name, s) in probes {
        // Не пробовали (напр. seqovl без активного перехвата) — не строка.
        if s.attempts == 0 {
            continue;
        }
        let color = if s.is_convincing() {
            Color::LightGreen
        } else if s.successes > 0 {
            Color::Yellow
        } else {
            Color::DarkGray
        };
        let median = s.median_ms.map(|m| format!("  {m:.0}мс")).unwrap_or_default();
        lines.push(Line::from(Span::styled(
            format!("  {name:<11} {}/{}{median}", s.successes, s.attempts),
            Style::default().fg(color),
        )));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        t!("diagnostics.back_hint").to_string(),
        Style::default().fg(Color::DarkGray),
    )));
    lines
}
