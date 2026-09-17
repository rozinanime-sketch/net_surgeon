use std::sync::atomic::{AtomicU64, AtomicUsize, AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::observability::stats::Percentiles;

pub struct Metrics {
    pub active_connections: AtomicUsize,
    pub bytes_rx: AtomicU64,
    pub bytes_tx: AtomicU64,
    /// Активные QUIC-сессии, проходящие через SOCKS5 UDP. Метрики
    /// quic_target_ok и quic_handshake_* убраны вместе с форвардером
    /// udp/quic.rs: писать их стало некому, а показывать числа от
    /// подсистемы, через которую не идёт трафик, — вводить в заблуждение.
    pub quic_sessions: AtomicUsize,
    pub quic_initial_sent: AtomicU64,
    pub dns_ok: AtomicBool,

    /// Реально ли слушается порт. Ставится самим слушателем ПОСЛЕ успешного
    /// bind и снимается при выходе. Раньше статус выставлялся оптимистично
    /// при запуске задач, и интерфейс показывал ON даже когда все порты
    /// оказывались заняты чужим процессом.
    tcp_listening: AtomicBool,
    udp_listening: AtomicBool,
    socks5_listening: AtomicBool,
    transparent_listening: AtomicBool,
    /// TPROXY-слушатель UDP. Отдельно от TCP: он требует CAP_NET_ADMIN и
    /// может не подняться там, где TCP-часть работает нормально.
    transparent_udp_listening: AtomicBool,

    /// Задержки в миллисекундах. Не атомик, потому что перцентили требуют
    /// выборки, а не одного числа; окно небольшое, блокировка короткая
    /// и берётся раз на соединение, а не на каждый байт.
    connect_latency: Mutex<Percentiles>,
    ttfb_latency: Mutex<Percentiles>,
}

impl Metrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            active_connections: AtomicUsize::new(0),
            bytes_rx: AtomicU64::new(0),
            bytes_tx: AtomicU64::new(0),
            quic_sessions: AtomicUsize::new(0),
            quic_initial_sent: AtomicU64::new(0),
            dns_ok: AtomicBool::new(true),
            tcp_listening: AtomicBool::new(false),
            udp_listening: AtomicBool::new(false),
            socks5_listening: AtomicBool::new(false),
            transparent_listening: AtomicBool::new(false),
            transparent_udp_listening: AtomicBool::new(false),
            connect_latency: Mutex::new(Percentiles::new(512)),
            ttfb_latency: Mutex::new(Percentiles::new(512)),
        })
    }

    pub fn conn_opened(&self) { self.active_connections.fetch_add(1, Ordering::Relaxed); }
    pub fn conn_closed(&self) { self.active_connections.fetch_sub(1, Ordering::Relaxed); }
    pub fn add_rx(&self, n: u64) { self.bytes_rx.fetch_add(n, Ordering::Relaxed); }
    pub fn add_tx(&self, n: u64) { self.bytes_tx.fetch_add(n, Ordering::Relaxed); }
    pub fn quic_session_opened(&self) { self.quic_sessions.fetch_add(1, Ordering::Relaxed); }
    pub fn quic_session_closed(&self) { self.quic_sessions.fetch_sub(1, Ordering::Relaxed); }
    pub fn quic_initial_sent(&self) { self.quic_initial_sent.fetch_add(1, Ordering::Relaxed); }
    pub fn set_dns_ok(&self, ok: bool) { self.dns_ok.store(ok, Ordering::Relaxed); }

    pub fn set_tcp_listening(&self, v: bool) { self.tcp_listening.store(v, Ordering::Relaxed); }
    pub fn set_udp_listening(&self, v: bool) { self.udp_listening.store(v, Ordering::Relaxed); }
    pub fn set_socks5_listening(&self, v: bool) { self.socks5_listening.store(v, Ordering::Relaxed); }
    pub fn set_transparent_listening(&self, v: bool) { self.transparent_listening.store(v, Ordering::Relaxed); }
    pub fn set_transparent_udp_listening(&self, v: bool) { self.transparent_udp_listening.store(v, Ordering::Relaxed); }

    /// Время установки TCP-соединения с целевым сервером.
    pub fn record_connect_ms(&self, ms: f64) {
        if let Ok(mut p) = self.connect_latency.lock() {
            p.push(ms);
        }
    }

    /// Time To First Byte: от начала подключения до первого байта ответа сервера.
    /// Именно эта величина отражает, мешает ли DPI: соединение может открыться
    /// мгновенно, а ответ не прийти никогда.
    pub fn record_ttfb_ms(&self, ms: f64) {
        if let Ok(mut p) = self.ttfb_latency.lock() {
            p.push(ms);
        }
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        // Один захват на все четыре величины: раньше ttfb_latency блокировался
        // четырежды подряд, и p50/p95/p99 могли прийти из разных состояний окна.
        let ttfb = self.ttfb_latency.lock().ok();
        let (ttfb_p50, ttfb_p95, ttfb_p99, latency_samples) = match ttfb.as_deref() {
            Some(p) => (p.p50(), p.p95(), p.p99(), p.len()),
            None => (None, None, None, 0),
        };

        MetricsSnapshot {
            active_connections: self.active_connections.load(Ordering::Relaxed),
            bytes_rx: self.bytes_rx.load(Ordering::Relaxed),
            bytes_tx: self.bytes_tx.load(Ordering::Relaxed),
            quic_sessions: self.quic_sessions.load(Ordering::Relaxed),
            quic_initial_sent: self.quic_initial_sent.load(Ordering::Relaxed),
            dns_ok: self.dns_ok.load(Ordering::Relaxed),
            tcp_listening: self.tcp_listening.load(Ordering::Relaxed),
            udp_listening: self.udp_listening.load(Ordering::Relaxed),
            socks5_listening: self.socks5_listening.load(Ordering::Relaxed),
            transparent_listening: self.transparent_listening.load(Ordering::Relaxed),
            transparent_udp_listening: self.transparent_udp_listening.load(Ordering::Relaxed),
            connect_p50: self.connect_latency.lock().ok().and_then(|p| p.p50()),
            ttfb_p50,
            ttfb_p95,
            ttfb_p99,
            latency_samples,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct MetricsSnapshot {
    pub active_connections: usize,
    pub bytes_rx: u64,
    pub bytes_tx: u64,
    pub quic_sessions: usize,
    pub quic_initial_sent: u64,
    pub dns_ok: bool,
    pub tcp_listening: bool,
    pub udp_listening: bool,
    pub socks5_listening: bool,
    pub transparent_listening: bool,
    pub transparent_udp_listening: bool,
    pub connect_p50: Option<f64>,
    pub ttfb_p50: Option<f64>,
    pub ttfb_p95: Option<f64>,
    pub ttfb_p99: Option<f64>,
    pub latency_samples: usize,
}

pub fn format_bytes(n: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB"];
    let mut value = n as f64;
    let mut unit_idx = 0;
    while value >= 1024.0 && unit_idx < UNITS.len() - 1 {
        value /= 1024.0;
        unit_idx += 1;
    }
    if unit_idx == 0 { format!("{} {}", n, UNITS[0]) } else { format!("{:.1} {}", value, UNITS[unit_idx]) }
}
