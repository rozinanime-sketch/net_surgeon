use tokio::sync::mpsc;
use super::app::LogLevel;

#[derive(Debug, Clone)]
pub struct LogMessage {
    pub level: LogLevel,
    pub text: String,
}

pub type LogSender = mpsc::UnboundedSender<LogMessage>;
pub type LogReceiver = mpsc::UnboundedReceiver<LogMessage>;

pub fn channel() -> (LogSender, LogReceiver) {
    mpsc::unbounded_channel()
}

/// Маленький хелпер чтобы вызовы выглядели похоже на println!
pub fn log(tx: &LogSender, level: LogLevel, text: impl Into<String>) {
    let _ = tx.send(LogMessage { level, text: text.into() });
}
