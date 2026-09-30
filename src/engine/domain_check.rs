//! Результат последней проверки одного домена — для показа на экране
//! «Диагностика».
//!
//! Диагностика идёт в фоновой задаче (tokio), а экран живёт в основном потоке.
//! Готовый результат кладётся сюда (как `net_state`/`probe_force` — модульный
//! синглтон), и экран читает его при отрисовке. Одна ячейка: интересен только
//! последний ручной прогон по домену, массовый прогон её не трогает.

use std::sync::{Mutex, OnceLock};

use crate::engine::diagnostics::DiagnosticResult;
use crate::engine::strategy::Strategy;

/// Разобранный итог проверки домена. Сырые данные пробы + выбранная техника;
/// человекочитаемый вид собирает экран (у него есть локаль).
pub struct DomainCheck {
    pub domain: String,
    pub result: DiagnosticResult,
    /// Заблокирован как трекер (сброс до сервера) — обход тут ни при чём.
    pub blocked: bool,
    /// Выбранная техника, если хоть одна прошла.
    pub chosen: Option<Strategy>,
}

fn slot() -> &'static Mutex<Option<DomainCheck>> {
    static S: OnceLock<Mutex<Option<DomainCheck>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(None))
}

/// Кладёт итог последней проверки.
pub fn set(check: DomainCheck) {
    *slot().lock().unwrap_or_else(|e| e.into_inner()) = Some(check);
}

/// Стирает итог — при начале нового ввода домена, чтобы старый вердикт
/// не выглядел ответом на новый вопрос.
pub fn clear() {
    *slot().lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// Даёт прочитать итог, не вынимая и не клонируя его (блокировка на время `f`).
pub fn with<R>(f: impl FnOnce(Option<&DomainCheck>) -> R) -> R {
    let guard = slot().lock().unwrap_or_else(|e| e.into_inner());
    f(guard.as_ref())
}
