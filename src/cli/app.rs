use crate::metrics::MetricsSnapshot;
use super::traffic_history::TrafficHistory;
use std::collections::VecDeque;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuItem {
    Status,
    Bypass,
    Domains,
    Diagnostics,
    Config,
    Start,
    Quit,
}

impl MenuItem {
    pub const ALL: [MenuItem; 7] = [
        MenuItem::Status,
        MenuItem::Bypass,
        MenuItem::Domains,
        MenuItem::Diagnostics,
        MenuItem::Config,
        MenuItem::Start,
        MenuItem::Quit,
    ];
}

#[derive(Debug, Clone)]
pub enum LogMessage {
    Plain(String),
    Translated { key: String, args: Vec<(String, String)> },
    NestedTranslated { key: String, nested_arg: String, nested_key: String, args: Vec<(String, String)> },
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub level: LogLevel,
    pub time: String,
    pub message: LogMessage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Success,
    Warning,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Menu,
    Logs,
}

#[derive(Debug, Default)]
pub struct DiagnosticsScreen {
    /// Буфер ввода домена; None пока не активен ввод
    pub input_buffer: Option<String>,
    /// true пока тест выполняется в фоне
    pub running: bool,
    /// Последний результат для отображения
    pub last_result: Option<DiagnosticsDisplay>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    Ru,
    En,
}

impl Language {
    pub fn code(&self) -> &'static str {
        match self {
            Language::Ru => "ru",
            Language::En => "en",
        }
    }

    pub fn toggle(&self) -> Language {
        match self {
            Language::Ru => Language::En,
            Language::En => Language::Ru,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DiagnosticsDisplay {
    pub domain: String,
    pub direct_connect_ok: bool,
    pub direct_tls_ok: bool,
    pub bypass_connect_ok: bool,
    pub bypass_tls_ok: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ProxyStatus {
    pub tcp_running: bool,
    pub tcp_port: u16,
    pub udp_running: bool,
    pub udp_port: u16,
    pub socks5_running: bool,
    pub socks5_port: u16,
    pub domains_count: usize,
}

#[derive(Debug, Clone)]
pub struct ConfigField {
    pub label_key: &'static str,
    pub toml_path: &'static str,
    pub value: String,
}

#[derive(Debug, Default)]
pub struct ConfigEditor {
    pub fields: Vec<ConfigField>,
    pub selected: usize,
    /// Если Some — поле редактируется прямо сейчас, здесь буфер ввода
    pub editing_buffer: Option<String>,
}

impl ConfigEditor {
    pub fn next(&mut self) {
        if !self.fields.is_empty() {
            self.selected = (self.selected + 1) % self.fields.len();
        }
    }

    pub fn previous(&mut self) {
        if !self.fields.is_empty() {
            self.selected = if self.selected == 0 {
                self.fields.len() - 1
            } else {
                self.selected - 1
            };
        }
    }
}

#[derive(Debug, Default)]
pub struct DomainsEditor {
    pub domains: Vec<String>,
    pub selected: usize,
    /// Some(buffer) когда вводим новый домен ИЛИ редактируем существующий
    pub editing_buffer: Option<String>,
    /// true если редактируем существующий домен (а не добавляем новый)
    pub is_editing_existing: bool,
}

impl DomainsEditor {
    pub fn next(&mut self) {
        if !self.domains.is_empty() {
            self.selected = (self.selected + 1) % self.domains.len();
        }
    }

    pub fn previous(&mut self) {
        if !self.domains.is_empty() {
            self.selected = if self.selected == 0 {
                self.domains.len() - 1
            } else {
                self.selected - 1
            };
        }
    }
}

pub struct App {
    pub selected: usize,
    pub logs: VecDeque<LogEntry>,
    pub status: ProxyStatus,
    pub should_quit: bool,
    pub proxy_started: bool,
    pub overlay: Option<String>,
    pub config_editor: Option<ConfigEditor>,
    pub domains_editor: Option<DomainsEditor>,
    pub metrics: MetricsSnapshot,
    pub traffic_history: TrafficHistory,
    pub log_scroll: usize,
    pub log_autoscroll: bool,
    pub focus: Focus,
    pub diagnostics: Option<DiagnosticsScreen>,
    pub language: Language,
    pub proxy_token: Option<CancellationToken>,
}

impl App {
    pub fn new() -> Self {
        Self {
            selected: 0,
            logs: VecDeque::with_capacity(200),
            status: ProxyStatus::default(),
            should_quit: false,
            proxy_started: false,
            overlay: None,
            config_editor: None,
            domains_editor: None,
            metrics: MetricsSnapshot::default(),
            traffic_history: TrafficHistory::new(),
            log_scroll: 0,
            log_autoscroll: true,
            focus: Focus::Menu,
            diagnostics: None,
            language: Language::Ru,
            proxy_token: None,
        }
    }

    pub fn toggle_language(&mut self) {
        self.language = self.language.toggle();
        rust_i18n::set_locale(self.language.code());
    }

    pub fn toggle_focus(&mut self) {
        self.focus = match self.focus {
            Focus::Menu => Focus::Logs,
            Focus::Logs => Focus::Menu,
        };
    }

    pub fn push_log(&mut self, level: LogLevel, message: impl Into<String>) {
        let time = chrono::Local::now().format("%H:%M:%S").to_string();
        if self.logs.len() >= 200 {
            self.logs.pop_front();
        }
        self.logs.push_back(LogEntry { level, time, message: LogMessage::Plain(message.into()) });
    }

    pub fn push_log_t(&mut self, level: LogLevel, key: impl Into<String>, args: Vec<(String, String)>) {
        let time = chrono::Local::now().format("%H:%M:%S").to_string();
        if self.logs.len() >= 200 {
            self.logs.pop_front();
        }
        self.logs.push_back(LogEntry { level, time, message: LogMessage::Translated { key: key.into(), args } });
    }

    pub fn scroll_logs_up(&mut self, amount: usize) {
        self.log_autoscroll = false;
        self.log_scroll = self.log_scroll.saturating_add(amount).min(self.logs.len().saturating_sub(1));
    }

    pub fn scroll_logs_down(&mut self, amount: usize) {
        if self.log_scroll <= amount {
            self.log_scroll = 0;
            self.log_autoscroll = true;
        } else {
            self.log_scroll -= amount;
        }
    }

    pub fn next(&mut self) {
        self.selected = (self.selected + 1) % MenuItem::ALL.len();
    }

    pub fn previous(&mut self) {
        if self.selected == 0 {
            self.selected = MenuItem::ALL.len() - 1;
        } else {
            self.selected -= 1;
        }
    }

    pub fn current(&self) -> MenuItem {
        MenuItem::ALL[self.selected]
    }

    pub fn push_log_nested_t(
        &mut self,
        level: LogLevel,
        key: impl Into<String>,
        nested_arg: impl Into<String>,
        nested_key: impl Into<String>,
        args: Vec<(String, String)>,
    ) {
        let time = chrono::Local::now().format("%H:%M:%S").to_string();
        if self.logs.len() >= 200 {
            self.logs.pop_front();
        }
        self.logs.push_back(LogEntry {
            level,
            time,
            message: LogMessage::NestedTranslated {
                key: key.into(),
                            nested_arg: nested_arg.into(),
                            nested_key: nested_key.into(),
                            args,
            },
        });
    }
}
