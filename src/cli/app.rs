use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuItem {
    Status,
    Fragmentation,
    UdpSettings,
    Domains,
    Config,
    Start,
    Quit,
}

impl MenuItem {
    pub const ALL: [MenuItem; 7] = [
        MenuItem::Status,
        MenuItem::Fragmentation,
        MenuItem::UdpSettings,
        MenuItem::Domains,
        MenuItem::Config,
        MenuItem::Start,
        MenuItem::Quit,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            MenuItem::Status => "Статус",
            MenuItem::Fragmentation => "Фрагментация",
            MenuItem::UdpSettings => "UDP настройки",
            MenuItem::Domains => "Домены",
            MenuItem::Config => "Конфиг",
            MenuItem::Start => "Запустить прокси",
            MenuItem::Quit => "Выход",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Success,
    Warning,
    Error,
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub level: LogLevel,
    pub time: String,
    pub message: String,
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

/// Одно редактируемое поле конфига: путь в TOML (для записи обратно) + текущее значение как строка
#[derive(Debug, Clone)]
pub struct ConfigField {
    pub label: &'static str,
    pub toml_path: &'static str, // напр. "port" или "ranges.frag_min"
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

pub struct App {
    pub selected: usize,
    pub logs: VecDeque<LogEntry>,
    pub status: ProxyStatus,
    pub should_quit: bool,
    pub proxy_started: bool,
    pub overlay: Option<String>,
    pub config_editor: Option<ConfigEditor>,
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
        }
    }

    pub fn push_log(&mut self, level: LogLevel, message: impl Into<String>) {
        let time = chrono::Local::now().format("%H:%M:%S").to_string();
        if self.logs.len() >= 200 {
            self.logs.pop_front();
        }
        self.logs.push_back(LogEntry { level, time, message: message.into() });
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
