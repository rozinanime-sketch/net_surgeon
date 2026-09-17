//! Единая система логов.
//!
//! Живёт на верхнем уровне, а не внутри `cli`, потому что логируют все:
//! proxy, socks5, udp, dns. Пока модуль лежал в `cli`, девять сетевых файлов
//! импортировали `crate::cli::{LogSender, log_t, LogLevel}` — то есть сетевой
//! слой зависел от слоя интерфейса ради записи строки. Это давало циклы
//! cli <-> proxy и cli <-> dns и переворачивало иерархию: логирование —
//! инфраструктура, а не представление.
//!
//! Теперь зависимость односторонняя: все пишут в logging, а `cli` только
//! читает из канала и решает, как показать.
//!
//! Раньше это были ДВЕ независимые копии одного и того же enum:
//! app.rs::LogMessage (для хранения в App.logs) и logger.rs::LogPayload
//! (для передачи по каналу из фоновых задач). mod.rs вручную конвертировал
//! одно в другое при каждом сообщении. Теперь один LogPayload используется
//! и как элемент канала (LogMessage{level, payload}), и как хранимая запись
//! (LogEntry{level, time, payload}) — единственное отличие последней это
//! добавленная метка времени.

use tokio::sync::mpsc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Success,
    Warning,
    Error,
}

#[derive(Debug, Clone)]
pub enum LogPayload {
    Plain(String),
    Translated { key: String, args: Vec<(String, String)> },
    NestedTranslated {
        key: String,
        nested_arg: String,
        nested_key: String,
        args: Vec<(String, String)>,
    },
}

/// Хранится в App.logs для отображения в панели логов.
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub level: LogLevel,
    pub time: String,
    pub payload: LogPayload,
}

/// Передаётся по каналу из фоновых tokio-задач в главный event loop.
#[derive(Debug, Clone)]
pub struct LogMessage {
    pub level: LogLevel,
    pub payload: LogPayload,
}

pub type LogSender = mpsc::UnboundedSender<LogMessage>;
pub type LogReceiver = mpsc::UnboundedReceiver<LogMessage>;

pub fn channel() -> (LogSender, LogReceiver) {
    mpsc::unbounded_channel()
}

/// Простое сообщение без перевода (маркеры, готовый текст).
pub fn log(tx: &LogSender, level: LogLevel, text: impl Into<String>) {
    let _ = tx.send(LogMessage { level, payload: LogPayload::Plain(text.into()) });
}

/// Переводимое сообщение: ключ + список пар (имя_параметра, значение).
pub fn log_t(tx: &LogSender, level: LogLevel, key: &str, args: Vec<(&str, String)>) {
    let args = args.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
    let _ = tx.send(LogMessage { level, payload: LogPayload::Translated { key: key.to_string(), args } });
}

/// Отправляет переводимую ошибку (AppError) — ключ и аргументы уходят как есть,
/// текст собирается уже при отрисовке, на текущем языке интерфейса.
pub fn log_err(tx: &LogSender, level: LogLevel, err: crate::observability::error::AppError) {
    let _ = tx.send(LogMessage {
        level,
        payload: LogPayload::Translated { key: err.key.to_string(), args: err.args },
    });
}

pub fn log_nested_t(
    tx: &LogSender,
    level: LogLevel,
    key: &str,
    nested_arg: &str,
    nested_key: &str,
    args: Vec<(&str, String)>,
) {
    let args = args.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
    let _ = tx.send(LogMessage {
        level,
        payload: LogPayload::NestedTranslated {
            key: key.to_string(),
            nested_arg: nested_arg.to_string(),
            nested_key: nested_key.to_string(),
            args,
        },
    });
}
