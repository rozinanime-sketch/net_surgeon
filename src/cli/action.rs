//! Данные "что нужно сделать" — без логики выполнения (та живёт в dispatch.rs).
//! Возвращается из screen::handle_key() и обрабатывается в cli/mod.rs (Quit,
//! ToggleBackground — нужен доступ к терминалу) или в dispatch::run() (остальное).

pub enum Action {
    None,
    Quit,
    StartProxy,
    RunDiagnostics(String),
    /// Прогнать диагностику по всем доменам из bypass_domains.txt
    /// и записать выбранные стратегии в strategies.txt.
    RunDiagnosticsAll,
    SaveConfigField(&'static str, String),
    SaveDomains(Vec<String>),
    ToggleBackground,
}
