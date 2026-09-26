//! Единый диспетчер экранов. Заменяет то, что в старом проекте было
//! разбросано по трём файлам: needs_clear-проверка в mod.rs, маршрутизация
//! клавиш в events.rs, и решение "что рисовать" в ui.rs — везде отдельно
//! проверялось overlay.is_some() || config_editor.is_some() || ... .
//!
//! Теперь это один enum. Добавишь новый вариант Screen — компилятор укажет
//! все места (handle_key здесь, draw здесь), где не хватает ветки match,
//! потому что в Rust match обязан быть исчерпывающим. Раньше забытое место
//! означало баг, который вылезал только в рантайме (клавиша не работает,
//! экран не рисуется, терминал не чистится) — теперь это ошибка компиляции.

pub(crate) mod config_editor;
pub(crate) mod diagnostics;
pub(crate) mod domains_editor;
mod main_screen;

pub use config_editor::ConfigEditorState;
pub use diagnostics::DiagnosticsState;
pub use domains_editor::DomainsEditorState;

use crossterm::event::KeyCode;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    Frame,
};

use super::action::Action;
use super::app::App;

pub enum Screen {
    Main,
    ConfigEditor(ConfigEditorState),
    DomainsEditor(DomainsEditorState),
    Diagnostics(DiagnosticsState),
}

/// Результат обработки клавиши одним экраном:
/// - Stay — остаёмся на этом же экране (возможно, с изменённым состоянием)
/// - Close — возвращаемся на Main (Esc/q в попапе)
/// - Switch — открываем другой экран (например, Main открывает ConfigEditor)
pub enum StepResult {
    Stay(Action),
    Close(Action),
    Switch(Screen, Action),
}

/// true, если сейчас открыт любой попап поверх главного экрана.
/// Раньше это была строка с четырьмя .is_some(), продублированная в трёх файлах.
pub fn is_popup(screen: &Screen) -> bool {
    !matches!(screen, Screen::Main)
}

/// true, если сейчас идёт выполнение диагностики (нужно для решения о
/// принудительной очистке терминала при завершении — см. cli/mod.rs).
pub fn is_diagnostics_running(screen: &Screen) -> bool {
    matches!(screen, Screen::Diagnostics(state) if state.running)
}

pub fn handle_key(app: &mut App, key: KeyCode) -> Action {
    // Временно забираем Screen из App, чтобы можно было одновременно
    // передавать &mut App в main_screen::handle_key() и матчиться по
    // вынутому значению — иначе получился бы двойной mutable borrow app.screen.
    let mut screen = std::mem::replace(&mut app.screen, Screen::Main);

    let step = match &mut screen {
        Screen::Main => main_screen::handle_key(app, key),
        Screen::ConfigEditor(state) => config_editor::handle_key(state, key),
        Screen::DomainsEditor(state) => domains_editor::handle_key(state, key),
        Screen::Diagnostics(state) => diagnostics::handle_key(state, key),
    };

    let action = match step {
        StepResult::Stay(action) => { app.screen = screen; action }
        StepResult::Close(action) => { app.screen = Screen::Main; action }
        StepResult::Switch(new_screen, action) => { app.screen = new_screen; action }
    };

    // domains_editor не имеет доступа к App (сознательно — состояние экрана
    // не должно знать о статусе прокси), поэтому счётчик доменов в статусе
    // обновляется здесь, на основе данных внутри самого Action.
    // Счётчик в статусе — про список обхода; список блокировки его не трогает.
    if let Action::SaveDomains(domains_editor::DomainList::Bypass, domains) = &action {
        app.status.domains_count = domains.len();
    }

    action
}

/// Постоянная часть интерфейса (шапка/меню/статус/логи/футер) рисуется всегда;
/// поверх неё — попап текущего экрана, если он не Main. Было: draw() в старом
/// ui.rs проверял 4 отдельных Option одно за другим; теперь один match.
pub fn draw(frame: &mut Frame, app: &App) {
    main_screen::draw(frame, app);

    match &app.screen {
        Screen::Main => {}
        Screen::ConfigEditor(state) => config_editor::draw(frame, frame.area(), app, state, app.proxy_started),
        Screen::DomainsEditor(state) => domains_editor::draw(frame, frame.area(), state, app.proxy_started),
        Screen::Diagnostics(state) => diagnostics::draw(frame, frame.area(), state),
    }

    // Фон, который никто не задал, иначе берётся у терминала. У PowerShell
    // он синий, и синие строки лога на нём не читаются. Заливаются только
    // клетки без своего фона, так что выделение в меню остаётся как было.
    #[cfg(windows)]
    for cell in frame.buffer_mut().content.iter_mut() {
        if cell.bg == ratatui::style::Color::Reset {
            cell.bg = ratatui::style::Color::Black;
        }
    }
}

/// Общий хелпер для всех попапов — вычисляет прямоугольник по центру экрана.
pub(super) fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
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

