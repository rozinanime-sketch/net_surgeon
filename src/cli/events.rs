use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use std::time::Duration;

use super::app::{App, MenuItem, LogLevel, ConfigEditor};
use super::config_editor;

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
        MenuItem::Fragmentation => {
            app.push_log(LogLevel::Info, "Настройки фрагментации (TODO: форма ввода)");
            Action::None
        }
        MenuItem::UdpSettings => {
            app.push_log(LogLevel::Info, "UDP настройки (TODO: форма ввода)");
            Action::None
        }
        MenuItem::Domains => {
            app.push_log(LogLevel::Info, "Список доменов (TODO: просмотр)");
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
                // Отмена редактирования без сохранения
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
                // Входим в режим редактирования выбранного поля
                if let Some(editor) = app.config_editor.as_mut() {
                    let current_value = editor.fields[editor.selected].value.clone();
                    editor.editing_buffer = Some(current_value);
                }
            }
            KeyCode::Esc | KeyCode::Char('q') => {
                // Выход из формы редактирования конфига обратно в меню
                app.config_editor = None;
            }
            _ => {}
        }
    }
}
