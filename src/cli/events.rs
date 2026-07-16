use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use std::time::Duration;

use super::app::{App, MenuItem, LogLevel, ConfigEditor, DomainsEditor};
use super::{config_editor, domains_editor};

pub enum Action {
    None,
    Quit,
    StartProxy,
    RunDiagnostics(String),
    SaveConfigField(&'static str, String),
    SaveDomains(Vec<String>),
    ToggleBackground,
}

pub fn poll_event(timeout: Duration) -> std::io::Result<Option<Event>> {
    if event::poll(timeout)? {
        Ok(Some(event::read()?))
    } else {
        Ok(None)
    }
}

pub fn handle_event(app: &mut App, event: Event) -> Action {
    if let Event::Key(key) = event {
        if key.kind != KeyEventKind::Press {
            return Action::None;
        }

        if app.config_editor.is_some() {
            return handle_config_editor_event(app, key.code);
        }

        if app.domains_editor.is_some() {
            return handle_domains_editor_event(app, key.code);
        }

        if app.diagnostics.is_some() {
            return handle_diagnostics_event(app, key.code);
        }

        if app.overlay.is_some() {
            match key.code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                    app.overlay = None;
                }
                _ => {}
            }
            return Action::None;
        }

        match key.code {
            KeyCode::Tab => app.toggle_focus(),
            KeyCode::Char('H') => return Action::ToggleBackground,
            KeyCode::Char('L') => app.toggle_language(),
            KeyCode::Up | KeyCode::Char('k') => {
                match app.focus {
                    super::app::Focus::Menu => app.previous(),
                    super::app::Focus::Logs => app.scroll_logs_up(1),
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                match app.focus {
                    super::app::Focus::Menu => app.next(),
                    super::app::Focus::Logs => app.scroll_logs_down(1),
                }
            }
            KeyCode::PageUp => app.scroll_logs_up(5),
            KeyCode::PageDown => app.scroll_logs_down(5),
            KeyCode::Home => {
                if app.focus == super::app::Focus::Logs {
                    app.log_autoscroll = false;
                    app.log_scroll = app.logs.len();
                }
            }
            KeyCode::End => {
                app.log_autoscroll = true;
                app.log_scroll = 0;
            }
            KeyCode::Enter => {
                if app.focus == super::app::Focus::Menu {
                    return handle_select(app);
                }
            }
            KeyCode::Char('q') | KeyCode::Esc => return Action::Quit,
            _ => {}
        }
    }
    Action::None
}

fn handle_select(app: &mut App) -> Action {
    match app.current() {
        MenuItem::Status => {
            app.push_log(LogLevel::Info, "Обновление статуса…");
            Action::None
        }
        MenuItem::Bypass => {
            match config_editor::load_bypass_fields() {
                Ok(fields) => {
                    app.config_editor = Some(ConfigEditor {
                        fields,
                        selected: 0,
                        editing_buffer: None,
                    });
                }
                Err(e) => {
                    app.push_log(LogLevel::Error, e);
                }
            }
            Action::None
        }
        MenuItem::Domains => {
            match domains_editor::load_domains() {
                Ok(domains) => {
                    app.domains_editor = Some(DomainsEditor {
                        domains,
                        selected: 0,
                        editing_buffer: None,
                        is_editing_existing: false,
                    });
                }
                Err(e) => {
                    app.push_log(LogLevel::Error, e);
                }
            }
            Action::None
        }
        MenuItem::Diagnostics => {
            app.diagnostics = Some(super::app::DiagnosticsScreen {
                input_buffer: Some(String::new()),
                                   running: false,
                                   last_result: None,
            });
            Action::None
        }
        MenuItem::Config => {
            match config_editor::load_fields() {
                Ok(fields) => {
                    app.config_editor = Some(ConfigEditor {
                        fields,
                        selected: 0,
                        editing_buffer: None,
                    });
                }
                Err(e) => {
                    app.push_log(LogLevel::Error, e);
                }
            }
            Action::None
        }
        MenuItem::Start => Action::StartProxy,
        MenuItem::Quit => Action::Quit,
    }
}

/// Обрабатывает ввод внутри экрана диагностики
fn handle_diagnostics_event(app: &mut App, key: KeyCode) -> Action {
    let is_input_active = app.diagnostics.as_ref()
    .map(|d| d.input_buffer.is_some())
    .unwrap_or(false);

    if is_input_active {
        match key {
            KeyCode::Enter => {
                let domain = {
                    let screen = app.diagnostics.as_ref().unwrap();
                    screen.input_buffer.clone().unwrap_or_default().trim().to_lowercase()
                };

                if domain.is_empty() {
                    return Action::None;
                }

                if let Some(screen) = app.diagnostics.as_mut() {
                    screen.input_buffer = None;
                    screen.running = true;
                }

                return Action::RunDiagnostics(domain);
            }
            KeyCode::Esc => {
                app.diagnostics = None;
            }
            KeyCode::Backspace => {
                if let Some(screen) = app.diagnostics.as_mut() {
                    if let Some(buf) = screen.input_buffer.as_mut() {
                        buf.pop();
                    }
                }
            }
            KeyCode::Char(c) => {
                if let Some(screen) = app.diagnostics.as_mut() {
                    if let Some(buf) = screen.input_buffer.as_mut() {
                        buf.push(c);
                    }
                }
            }
            _ => {}
        }
    } else {
        match key {
            KeyCode::Char('n') => {
                // Новый тест
                if let Some(screen) = app.diagnostics.as_mut() {
                    screen.input_buffer = Some(String::new());
                    screen.last_result = None;
                }
            }
            KeyCode::Esc | KeyCode::Char('q') => {
                app.diagnostics = None;
            }
            _ => {}
        }
    }
    Action::None
}

/// Обрабатывает ввод внутри экрана редактирования доменов
fn handle_domains_editor_event(app: &mut App, key: KeyCode) -> Action {
    let is_editing = app.domains_editor.as_ref()
    .map(|e| e.editing_buffer.is_some())
    .unwrap_or(false);

    if is_editing {
        match key {
            KeyCode::Enter => {
                let new_domain = {
                    let editor = app.domains_editor.as_ref().unwrap();
                    editor.editing_buffer.clone().unwrap_or_default().trim().to_lowercase()
                };

                if new_domain.is_empty() {
                    if let Some(editor) = app.domains_editor.as_mut() {
                        editor.editing_buffer = None;
                        editor.is_editing_existing = false;
                    }
                    return Action::None;
                }

                if let Some(editor) = app.domains_editor.as_mut() {
                    if editor.is_editing_existing {
                        editor.domains[editor.selected] = new_domain.clone();
                    } else if !editor.domains.contains(&new_domain) {
                        editor.domains.push(new_domain.clone());
                    }
                    editor.domains.sort();
                    editor.selected = editor.domains.iter().position(|d| d == &new_domain).unwrap_or(0);
                    editor.editing_buffer = None;
                    editor.is_editing_existing = false;
                }

                let domains_snapshot = app.domains_editor.as_ref().unwrap().domains.clone();
                app.status.domains_count = domains_snapshot.len();
                return Action::SaveDomains(domains_snapshot);
            }
            KeyCode::Esc => {
                if let Some(editor) = app.domains_editor.as_mut() {
                    editor.editing_buffer = None;
                    editor.is_editing_existing = false;
                }
            }
            KeyCode::Backspace => {
                if let Some(editor) = app.domains_editor.as_mut() {
                    if let Some(buf) = editor.editing_buffer.as_mut() {
                        buf.pop();
                    }
                }
            }
            KeyCode::Char(c) => {
                if let Some(editor) = app.domains_editor.as_mut() {
                    if let Some(buf) = editor.editing_buffer.as_mut() {
                        buf.push(c);
                    }
                }
            }
            _ => {}
        }
    } else {
        match key {
            KeyCode::Up | KeyCode::Char('k') => {
                if let Some(editor) = app.domains_editor.as_mut() {
                    editor.previous();
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if let Some(editor) = app.domains_editor.as_mut() {
                    editor.next();
                }
            }
            KeyCode::Char('a') => {
                if let Some(editor) = app.domains_editor.as_mut() {
                    editor.editing_buffer = Some(String::new());
                    editor.is_editing_existing = false;
                }
            }
            KeyCode::Char('e') => {
                if let Some(editor) = app.domains_editor.as_mut() {
                    if !editor.domains.is_empty() {
                        editor.editing_buffer = Some(editor.domains[editor.selected].clone());
                        editor.is_editing_existing = true;
                    }
                }
            }
            KeyCode::Char('d') | KeyCode::Delete => {
                let removed = {
                    let editor = app.domains_editor.as_mut().unwrap();
                    if editor.domains.is_empty() {
                        None
                    } else {
                        let removed = editor.domains.remove(editor.selected);
                        if editor.selected >= editor.domains.len() && editor.selected > 0 {
                            editor.selected -= 1;
                        }
                        Some(removed)
                    }
                };

                if removed.is_some() {
                    let domains_snapshot = app.domains_editor.as_ref().unwrap().domains.clone();
                    app.status.domains_count = domains_snapshot.len();
                    return Action::SaveDomains(domains_snapshot);
                }
            }
            KeyCode::Esc | KeyCode::Char('q') => {
                app.domains_editor = None;
            }
            _ => {}
        }
    }
    Action::None
}

/// Обрабатывает ввод внутри формы редактирования конфига
fn handle_config_editor_event(app: &mut App, key: KeyCode) -> Action {
    let is_editing = app.config_editor.as_ref()
    .map(|e| e.editing_buffer.is_some())
    .unwrap_or(false);

    if is_editing {
        match key {
            KeyCode::Enter => {
                let (path, new_value) = {
                    let editor = app.config_editor.as_ref().unwrap();
                    let field = &editor.fields[editor.selected];
                    (field.toml_path, editor.editing_buffer.clone().unwrap_or_default())
                };

                // Оптимистично обновляем UI сразу — запись на диск уйдёт в фон
                if let Some(editor) = app.config_editor.as_mut() {
                    editor.fields[editor.selected].value = new_value.clone();
                    editor.editing_buffer = None;
                }

                return Action::SaveConfigField(path, new_value);
            }
            KeyCode::Esc => {
                if let Some(editor) = app.config_editor.as_mut() {
                    editor.editing_buffer = None;
                }
            }
            KeyCode::Backspace => {
                if let Some(editor) = app.config_editor.as_mut() {
                    if let Some(buf) = editor.editing_buffer.as_mut() {
                        buf.pop();
                    }
                }
            }
            KeyCode::Char(c) => {
                if let Some(editor) = app.config_editor.as_mut() {
                    if let Some(buf) = editor.editing_buffer.as_mut() {
                        buf.push(c);
                    }
                }
            }
            _ => {}
        }
    } else {
        match key {
            KeyCode::Up | KeyCode::Char('k') => {
                if let Some(editor) = app.config_editor.as_mut() {
                    editor.previous();
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if let Some(editor) = app.config_editor.as_mut() {
                    editor.next();
                }
            }
            KeyCode::Enter => {
                if let Some(editor) = app.config_editor.as_mut() {
                    let current_value = editor.fields[editor.selected].value.clone();
                    editor.editing_buffer = Some(current_value);
                }
            }
            KeyCode::Esc | KeyCode::Char('q') => {
                app.config_editor = None;
            }
            _ => {}
        }
    }
    Action::None
}
