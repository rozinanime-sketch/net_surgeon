//! Значки статуса в выводе и в интерфейсе.
//!
//! Стандартный шрифт консоли Windows (Consolas) не знает ✓, ✗ и ▶, и
//! вместо них там рисуются знаки вопроса в рамке. Windows Terminal с его
//! шрифтом их показывает, но двойной щелчок по программе открывает старую
//! консоль. Поэтому в Windows значки ASCII.

#[cfg(not(windows))]
pub const OK: &str = "✓";
#[cfg(windows)]
pub const OK: &str = "+";

#[cfg(not(windows))]
pub const ERROR: &str = "✗";
#[cfg(windows)]
pub const ERROR: &str = "x";

/// Отметка выбранной строки в меню и списках.
#[cfg(not(windows))]
pub const SELECTED: &str = "▶ ";
#[cfg(windows)]
pub const SELECTED: &str = "> ";
