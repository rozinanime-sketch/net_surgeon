use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use std::time::Duration;

use super::app::{App, MenuItem, LogLevel, ConfigEditor, DomainsEditor};
use super::{config_editor, domains_editor};

pub enum Action {
    None,
    Quit,
    StartProxy,
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

        // Режим редактирования конфига имеет приоритет над всем остальным
        if app.config_editor.is_some() {
            handle_config_editor_event(app, key.code);
            return Action::None;
        }

        if app.domains_editor.is_some() {
            handle_domains_editor_event(app, key.code);
            return Action::None;
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
            KeyCode::Up | KeyCode::Char('k') => app.previous(),
            KeyCode::Down | KeyCode::Char('j') => app.next(),
            KeyCode::Enter => return handle_select(app),
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

/// Обрабатывает ввод внутри экрана редактирования доменов
fn handle_domains_editor_event(app: &mut App, key: KeyCode) {
    let is_editing = app.domains_editor.as_ref()
    .map(|e| e.editing_buffer.is_some())
    .unwrap_or(false);

    if is_editing {
        match key {
            KeyCode::Enter => {
                let (new_domain, is_existing, old_domain) = {
                    let editor = app.domains_editor.as_ref().unwrap();
                    let new_value = editor.editing_buffer.clone().unwrap_or_default().trim().to_lowercase();
                    let old = if editor.is_editing_existing && !editor.domains.is_empty() {
                        Some(editor.domains[editor.selected].clone())
                    } else {
                        None
                    };
                    (new_value, editor.is_editing_existing, old)
                };

                if new_domain.is_empty() {
                    if let Some(editor) = app.domains_editor.as_mut() {
                        editor.editing_buffer = None;
                        editor.is_editing_existing = false;
                    }
                    return;
                }

                if let Some(editor) = app.domains_editor.as_mut() {
                    if is_existing {
                        // Заменяем существующий домен на новое значение
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
                match domains_editor::save_domains(&domains_snapshot) {
                    Ok(()) => {
                        app.status.domains_count = domains_snapshot.len();
                        let msg = match old_domain {
                            Some(old) => format!("Домен {} изменён на {}", old, new_domain),
                            None => format!("Домен {} добавлен", new_domain),
                        };
                        if app.proxy_started {
                            app.push_log(LogLevel::Warning, format!("{} — изменится после перезапуска прокси", msg));
                        } else {
                            app.push_log(LogLevel::Success, msg);
                        }
                    }
                    Err(e) => app.push_log(LogLevel::Error, e),
                }
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
                // Добавление нового домена — пустой буфер
                if let Some(editor) = app.domains_editor.as_mut() {
                    editor.editing_buffer = Some(String::new());
                    editor.is_editing_existing = false;
                }
            }
            KeyCode::Char('e') => {
                // Редактирование выбранного домена — буфер с текущим значением
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

                if let Some(removed) = removed {
                    let domains_snapshot = app.domains_editor.as_ref().unwrap().domains.clone();
                    match domains_editor::save_domains(&domains_snapshot) {
                        Ok(()) => {
                            app.status.domains_count = domains_snapshot.len();
                            if app.proxy_started {
                                app.push_log(LogLevel::Warning, format!("Домен {} удалён — изменится после перезапуска прокси", removed));
                            } else {
                                app.push_log(LogLevel::Success, format!("Домен {} удалён", removed));
                            }
                        }
                        Err(e) => app.push_log(LogLevel::Error, e),
                    }
                }
            }
            KeyCode::Esc | KeyCode::Char('q') => {
                app.domains_editor = None;
            }
            _ => {}
        }
    }
}

/// Обрабатывает ввод внутри формы редактирования конфига
fn handle_config_editor_event(app: &mut App, key: KeyCode) {
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

                match config_editor::save_field(path, &new_value) {
                    Ok(()) => {
                        if let Some(editor) = app.config_editor.as_mut() {
                            editor.fields[editor.selected].value = new_value;
                            editor.editing_buffer = None;
                        }
                        if app.proxy_started {
                            app.push_log(
                                LogLevel::Warning,
                                format!("Поле {} сохранено — изменится после перезапуска прокси", path),
                            );
                        } else {
                            app.push_log(LogLevel::Success, format!("Поле {} сохранено", path));
                        }
                    }
                    Err(e) => {
                        app.push_log(LogLevel::Error, e);
                        if let Some(editor) = app.config_editor.as_mut() {
                            editor.editing_buffer = None;
                        }
                    }
                }
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
}
