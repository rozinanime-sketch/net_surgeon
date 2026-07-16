use tokio::sync::mpsc;
use super::app::LogLevel;

#[derive(Debug, Clone)]
pub enum LogPayload {
    Plain(String),
    Translated { key: String, args: Vec<(String, String)> },
    NestedTranslated { key: String, nested_arg: String, nested_key: String, args: Vec<(String, String)> },
}

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

/// Простое сообщение без перевода (маркеры, готовый текст)
pub fn log(tx: &LogSender, level: LogLevel, text: impl Into<String>) {
    let _ = tx.send(LogMessage { level, payload: LogPayload::Plain(text.into()) });
}

/// Переводимое сообщение: ключ + список пар (имя_параметра, значение_как_строка)
pub fn log_t(tx: &LogSender, level: LogLevel, key: &str, args: Vec<(&str, String)>) {
    let args = args.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
    let _ = tx.send(LogMessage { level, payload: LogPayload::Translated { key: key.to_string(), args } });
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
