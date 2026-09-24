use std::collections::VecDeque;
use tokio_util::sync::CancellationToken;

use crate::observability::metrics::MetricsSnapshot;

use crate::observability::logging::{LogEntry, LogLevel, LogPayload};
use super::screen::Screen;
use super::traffic_history::TrafficHistory;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuItem {
    Domains,
    Blocklist,
    Diagnostics,
    Config,
    Start,
    Quit,
}

impl MenuItem {
    pub const ALL: [MenuItem; 6] = [
        MenuItem::Domains,
        MenuItem::Blocklist,
        MenuItem::Diagnostics,
        MenuItem::Config,
        MenuItem::Start,
        MenuItem::Quit,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Menu,
    Logs,
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

#[derive(Debug, Clone, Default)]
pub struct ProxyStatus {
    pub tcp_running: bool,
    pub tcp_port: u16,
    pub udp_running: bool,
    pub udp_port: u16,
    pub socks5_running: bool,
    pub socks5_port: u16,
    pub transparent_running: bool,
    pub transparent_udp_running: bool,
    pub transparent_port: u16,
    pub domains_count: usize,
}

pub struct App {
    /// Единственное поле состояния экрана — заменяет старые 4 отдельных
    /// Option<T> (overlay/config_editor/domains_editor/diagnostics), проверка
    /// которых была продублирована в трёх местах старого проекта.
    pub screen: Screen,
    pub selected: usize,
    pub logs: VecDeque<LogEntry>,
    pub status: ProxyStatus,
    pub should_quit: bool,
    pub proxy_started: bool,
    pub metrics: MetricsSnapshot,
    pub traffic_history: TrafficHistory,
    pub log_scroll: usize,
    pub log_autoscroll: bool,
    pub focus: Focus,
    pub language: Language,
    pub proxy_token: Option<CancellationToken>,
    /// Идёт ли массовый прогон. Нужен, чтобы автозапуск по расписанию
    /// не стартовал поверх уже идущего — иначе прогоны наложились бы,
    /// удвоив нагрузку на сеть и исказив результат.
    pub diagnostics_running: bool,
    /// Режим только диагностики: слушатели не поднимаются.
    pub diagnostics_only: bool,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
        Self {
            screen: Screen::Main,
            selected: 0,
            logs: VecDeque::with_capacity(200),
            status: ProxyStatus::default(),
            should_quit: false,
            proxy_started: false,
            metrics: MetricsSnapshot::default(),
            traffic_history: TrafficHistory::new(),
            log_scroll: 0,
            log_autoscroll: true,
            focus: Focus::Menu,
            language: Language::Ru,
            proxy_token: None,
            diagnostics_running: false,
            diagnostics_only: false,
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

    pub fn push_log_t(&mut self, level: LogLevel, key: impl Into<String>, args: Vec<(String, String)>) {
        self.push_payload(level, LogPayload::Translated { key: key.into(), args });
    }

    /// Показывает переводимую ошибку в панели логов.
    pub fn push_err(&mut self, err: crate::observability::error::AppError) {
        self.push_payload(LogLevel::Error, LogPayload::Translated { key: err.key.to_string(), args: err.args });
    }

    /// Единая точка приёма лога — используется и внутренними push_log*(),
    /// и напрямую из event loop при разборе сообщений из фонового канала
    /// (там уже готовый LogPayload, конвертировать между enum'ами не нужно).
    pub(crate) fn push_payload(&mut self, level: LogLevel, payload: LogPayload) {
        let time = chrono::Local::now().format("%H:%M:%S").to_string();
        if self.logs.len() >= 200 {
            self.logs.pop_front();
        }
        self.logs.push_back(LogEntry { level, time, payload });
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
}
