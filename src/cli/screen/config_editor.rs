//! Экран редактирования config.toml — состояние + I/O + обработка клавиш
//! в одном файле (в старом проекте I/O жило в отдельном top-level
//! config_editor.rs, а состояние и обработка клавиш — в app.rs/events.rs).

use crossterm::event::KeyCode;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};
use rust_i18n::t;
use toml_edit::DocumentMut;

use crate::cli::action::Action;
use crate::cli::app::App;
use crate::observability::error::AppError;

use super::StepResult;

const FULL_FIELD_DEFS: &[(&str, &str)] = &[
    ("field.tcp_port", "port"),
    ("field.udp_port", "udp_port"),
    ("field.socks5_port", "socks5_port"),
    ("field.socks5_udp_port", "socks5_udp_port"),
    ("field.transparent_port", "transparent_port"),
    ("field.enabled", "enabled"),
    ("field.split_pos_min", "bypass.split_pos_min"),
    ("field.split_pos_max", "bypass.split_pos_max"),
    ("field.split_delay", "bypass.split_delay_ms"),
    ("field.window_clamp", "bypass.window_clamp"),
    ("field.disorder_ttl", "bypass.disorder_ttl"),
    ("field.junk_count", "socks5_junk.count"),
    ("field.junk_size_min", "socks5_junk.size_min"),
    ("field.junk_size_max", "socks5_junk.size_max"),
    ("field.junk_delay_min", "socks5_junk.delay_min_ms"),
    ("field.junk_delay_max", "socks5_junk.delay_max_ms"),
    ("field.strategy_ttl", "strategy_ttl_hours"),
    ("field.auto_diagnostics", "auto_diagnostics_hours"),
    ("field.probe_gap_min", "probe_gap_min_ms"),
    ("field.probe_gap_max", "probe_gap_max_ms"),
    ("field.resolve_via_doh", "resolve_via_doh"),
    ("field.doh_provider", "doh_provider"),
];

const BYPASS_FIELD_DEFS: &[(&str, &str)] = &[
    ("field.enabled", "enabled"),
    ("field.split_pos_min", "bypass.split_pos_min"),
    ("field.split_pos_max", "bypass.split_pos_max"),
    ("field.split_delay", "bypass.split_delay_ms"),
    ("field.window_clamp", "bypass.window_clamp"),
    ("field.disorder_ttl", "bypass.disorder_ttl"),
    ("field.junk_count", "socks5_junk.count"),
    ("field.junk_size_min", "socks5_junk.size_min"),
    ("field.junk_size_max", "socks5_junk.size_max"),
    ("field.junk_delay_min", "socks5_junk.delay_min_ms"),
    ("field.junk_delay_max", "socks5_junk.delay_max_ms"),
];

#[derive(Debug, Clone)]
pub struct ConfigField {
    pub label_key: &'static str,
    pub toml_path: &'static str,
    pub value: String,
}

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

// --- I/O: без изменений по сравнению со старым config_editor.rs ---

pub fn load_fields() -> Result<Vec<ConfigField>, AppError> {
    load_fields_from(FULL_FIELD_DEFS)
}

pub fn load_bypass_fields() -> Result<Vec<ConfigField>, AppError> {
    load_fields_from(BYPASS_FIELD_DEFS)
}

fn load_fields_from(defs: &[(&'static str, &'static str)]) -> Result<Vec<ConfigField>, AppError> {
    let text = crate::config::paths::read_to_string("config.toml")
        .map_err(|e| AppError::new("error.config_read").with("error", e))?;
    let doc: DocumentMut = text.parse()
        .map_err(|e| AppError::new("error.config_parse").with("error", e))?;

    let mut fields = Vec::new();
    for (label_key, path) in defs {
        let value = get_value_at_path(&doc, path).unwrap_or_default();
        fields.push(ConfigField { label_key, toml_path: path, value });
    }
    Ok(fields)
}

fn get_value_at_path(doc: &DocumentMut, path: &str) -> Option<String> {
    let parts: Vec<&str> = path.split('.').collect();
    let mut item = doc.as_item();
    for part in &parts {
        item = item.get(part)?;
    }
    item.as_value().map(|v| match v {
        toml_edit::Value::String(s) => s.value().clone(),
        other => other.to_string().trim().to_string(),
    })
}

/// Собирает новое значение поля, СОХРАНЯЯ тип того, что там лежало.
///
/// Раньше тип угадывался по введённой строке: `i64`, иначе `bool`, иначе
/// строка. Из-за этого редактор мог записать заведомо нерабочий конфиг —
/// `port = "abc"` или `doh_provider = 123`, — и следующий запуск падал на
/// `load_config`, то есть приложение окирпичивалось из собственного UI.
///
/// Тип берётся из текущего значения в файле: config.toml и есть источник
/// правды о том, что здесь ожидается. Отдельную таблицу типов заводить не
/// нужно, и она не разъедется с реальностью.
fn typed_value(existing: Option<&toml_edit::Item>, new_value: &str) -> Result<toml_edit::Item, AppError> {
    use toml_edit::Value;

    let bad = |kind: &str| {
        AppError::new("error.config_bad_value")
            .with("value", new_value)
            .with("expected", kind)
    };

    match existing.and_then(|i| i.as_value()) {
        Some(Value::Integer(_)) => new_value
            .trim()
            .parse::<i64>()
            .map(toml_edit::value)
            .map_err(|_| bad("integer")),
        Some(Value::Boolean(_)) => new_value
            .trim()
            .parse::<bool>()
            .map(toml_edit::value)
            .map_err(|_| bad("true/false")),
        Some(Value::Float(_)) => new_value
            .trim()
            .parse::<f64>()
            .map(toml_edit::value)
            .map_err(|_| bad("number")),
        Some(Value::String(_)) => Ok(toml_edit::value(new_value)),
        // Поля в файле ещё нет (добавлено в Config с #[serde(default)]) —
        // тип угадываем по введённому, как и раньше.
        _ => Ok(if let Ok(n) = new_value.trim().parse::<i64>() {
            toml_edit::value(n)
        } else if let Ok(b) = new_value.trim().parse::<bool>() {
            toml_edit::value(b)
        } else {
            toml_edit::value(new_value)
        }),
    }
}

pub fn save_field(toml_path: &str, new_value: &str) -> Result<(), AppError> {
    let text = crate::config::paths::read_to_string("config.toml")
        .map_err(|e| AppError::new("error.config_read").with("error", e))?;
    let mut doc: DocumentMut = text.parse()
        .map_err(|e| AppError::new("error.config_parse").with("error", e))?;

    let parts: Vec<&str> = toml_path.split('.').collect();
    if parts.is_empty() || parts.len() > 2 {
        return Err(AppError::new("error.config_bad_path").with("path", toml_path));
    }

    let new_item = typed_value(get_item_at_path(&doc, &parts), new_value)?;

    if parts.len() == 1 {
        doc[parts[0]] = new_item;
    } else {
        doc[parts[0]][parts[1]] = new_item;
    }

    // Проверяем, что получившийся документ ещё читается как Config: иначе
    // ошибку заметит только следующий запуск, и заметит отказом стартовать.
    let rendered = doc.to_string();
    if let Err(e) = toml::from_str::<crate::config::Config>(&rendered) {
        return Err(AppError::new("error.config_would_break").with("error", e));
    }

    crate::config::paths::write_atomic("config.toml", &rendered)
        .map_err(|e| AppError::new("error.config_write").with("error", e))?;

    Ok(())
}

fn get_item_at_path<'a>(doc: &'a DocumentMut, parts: &[&str]) -> Option<&'a toml_edit::Item> {
    let mut item = doc.as_item();
    for part in parts {
        item = item.get(part)?;
    }
    Some(item)
}

// --- Отрисовка: перенесено из старого ui.rs::draw_config_editor 1-в-1. ---

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

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints(editor.fields.iter().map(|_| Constraint::Length(1)).collect::<Vec<_>>())
        .split(inner);

    for (i, field) in editor.fields.iter().enumerate() {
        if i >= rows.len() { break; }

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
        let label = crate::observability::i18n::translate(app.language.code(), field.label_key, &[]);

        let line = Line::from(vec![
            Span::styled(format!("{}{:<24}", prefix, label), label_style),
            Span::raw(" "),
            Span::styled(value_text, value_style),
        ]);

        frame.render_widget(Paragraph::new(line), rows[i]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(text: &str) -> DocumentMut {
        text.parse().unwrap()
    }

    #[test]
    fn keeps_the_type_that_the_field_already_had() {
        let d = doc("port = 1080\nenabled = true\ndoh_provider = \"https://x\"\nreward_latency = 0.3\n");

        // Число остаётся числом
        let item = typed_value(get_item_at_path(&d, &["port"]), "8080").unwrap();
        assert_eq!(item.as_integer(), Some(8080));

        // Строка остаётся строкой, даже если выглядит как число
        let item = typed_value(get_item_at_path(&d, &["doh_provider"]), "123").unwrap();
        assert_eq!(item.as_str(), Some("123"));

        let item = typed_value(get_item_at_path(&d, &["reward_latency"]), "0.75").unwrap();
        assert_eq!(item.as_float(), Some(0.75));
    }

    #[test]
    fn refuses_a_value_of_the_wrong_type() {
        let d = doc("port = 1080\nenabled = true\n");

        // Раньше это записывало port = "abc", и следующий запуск падал
        // на разборе конфига — приложение окирпичивалось из своего же UI.
        assert!(typed_value(get_item_at_path(&d, &["port"]), "abc").is_err());
        assert!(typed_value(get_item_at_path(&d, &["enabled"]), "ага").is_err());
    }

    #[test]
    fn unknown_field_falls_back_to_guessing() {
        let d = doc("port = 1080\n");
        let item = typed_value(get_item_at_path(&d, &["not_there"]), "42").unwrap();
        assert_eq!(item.as_integer(), Some(42));
    }
}
