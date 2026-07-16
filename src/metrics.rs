use std::sync::atomic::{AtomicU64, AtomicUsize, AtomicBool, Ordering};
use std::sync::Arc;

pub struct Metrics {
    pub active_connections: AtomicUsize,
    pub bytes_rx: AtomicU64,
    pub bytes_tx: AtomicU64,

    pub quic_sessions: AtomicUsize,
    pub quic_target_ok: AtomicBool,

    // Новые счётчики для отслеживания успешности QUIC-хендшейков
    pub quic_initial_sent: AtomicU64,
    pub quic_handshake_success: AtomicU64,
    pub quic_handshake_failed: AtomicU64,

    pub dns_ok: AtomicBool,
}

impl Metrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            active_connections: AtomicUsize::new(0),
                 bytes_rx: AtomicU64::new(0),
                 bytes_tx: AtomicU64::new(0),
                 quic_sessions: AtomicUsize::new(0),
                 quic_target_ok: AtomicBool::new(true),
                 quic_initial_sent: AtomicU64::new(0),
                 quic_handshake_success: AtomicU64::new(0),
                 quic_handshake_failed: AtomicU64::new(0),
                 dns_ok: AtomicBool::new(true),
        })
    }

    pub fn conn_opened(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn conn_closed(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn add_rx(&self, n: u64) {
        self.bytes_rx.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_tx(&self, n: u64) {
        self.bytes_tx.fetch_add(n, Ordering::Relaxed);
    }

    pub fn quic_session_opened(&self) {
        self.quic_sessions.fetch_add(1, Ordering::Relaxed);
    }

    pub fn quic_session_closed(&self) {
        self.quic_sessions.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn set_quic_target_ok(&self, ok: bool) {
        self.quic_target_ok.store(ok, Ordering::Relaxed);
    }

    pub fn quic_initial_sent(&self) {
        self.quic_initial_sent.fetch_add(1, Ordering::Relaxed);
    }

    pub fn quic_handshake_success(&self) {
        self.quic_handshake_success.fetch_add(1, Ordering::Relaxed);
    }

    pub fn quic_handshake_failed(&self) {
        self.quic_handshake_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_dns_ok(&self, ok: bool) {
        self.dns_ok.store(ok, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            active_connections: self.active_connections.load(Ordering::Relaxed),
            bytes_rx: self.bytes_rx.load(Ordering::Relaxed),
            bytes_tx: self.bytes_tx.load(Ordering::Relaxed),
            quic_sessions: self.quic_sessions.load(Ordering::Relaxed),
            quic_target_ok: self.quic_target_ok.load(Ordering::Relaxed),
            quic_initial_sent: self.quic_initial_sent.load(Ordering::Relaxed),
            quic_handshake_success: self.quic_handshake_success.load(Ordering::Relaxed),
            quic_handshake_failed: self.quic_handshake_failed.load(Ordering::Relaxed),
            dns_ok: self.dns_ok.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct MetricsSnapshot {
    pub active_connections: usize,
    pub bytes_rx: u64,
    pub bytes_tx: u64,
    pub quic_sessions: usize,
    pub quic_target_ok: bool,
    pub quic_initial_sent: u64,
    pub quic_handshake_success: u64,
    pub quic_handshake_failed: u64,
    pub dns_ok: bool,
}

pub fn format_bytes(n: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB"];
    let mut value = n as f64;
    let mut unit_idx = 0;
    while value >= 1024.0 && unit_idx < UNITS.len() - 1 {
        value /= 1024.0;
        unit_idx += 1;
    }
    if unit_idx == 0 {
        format!("{} {}", n, UNITS[0])
    } else {
        format!("{:.1} {}", value, UNITS[unit_idx])
    }
}
