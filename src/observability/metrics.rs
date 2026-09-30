use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::observability::stats::Percentiles;

/// Сколько доменов помнить в разбивке трафика. При переполнении вытесняется
/// самый лёгкий — интересны как раз тяжёлые. Обновляется раз на соединение
/// (не на байт), так что линейный проход при вытеснении дёшев.
const DOMAIN_TRAFFIC_CAP: usize = 512;
/// Сколько строк отдавать в снимок для интерфейса.
const DOMAIN_TRAFFIC_TOP: usize = 20;

pub struct Metrics {
    pub active_connections: AtomicUsize,
    /// Со стороны прокси: `rx` — принятое от клиента (исходящий трафик
    /// пользователя), `tx` — отданное клиенту (входящий). Ретранслятор
    /// Telegram считал наоборот, а подписи в интерфейсе стояли как для
    /// входящего rx, и при просмотре видео крупные числа были у «↑».
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

    /// Трафик по доменам: имя → (rx, tx). Копится раз на закрытие соединения
    /// суммой за это соединение, а не на каждый байт: домен известен при
    /// установке, а блокировка карты в горячем пути была бы дорогой.
    domain_traffic: Mutex<HashMap<String, (u64, u64)>>,
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
            domain_traffic: Mutex::new(HashMap::new()),
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

    /// Прибавляет трафик соединения его домену. Зовётся один раз, при закрытии
    /// соединения, с суммами за это соединение. Пустой домен и нулевой трафик
    /// пропускаются: они только засоряли бы таблицу.
    pub fn record_domain_traffic(&self, domain: &str, rx: u64, tx: u64) {
        if domain.is_empty() || (rx == 0 && tx == 0) {
            return;
        }
        let Ok(mut map) = self.domain_traffic.lock() else { return };
        let entry = map.entry(domain.to_string()).or_insert((0, 0));
        entry.0 = entry.0.saturating_add(rx);
        entry.1 = entry.1.saturating_add(tx);
        // Переполнение: выбрасываем самый лёгкий домен — интересны тяжёлые.
        if map.len() > DOMAIN_TRAFFIC_CAP
            && let Some(lightest) = map.iter().min_by_key(|(_, (r, t))| r.saturating_add(*t)).map(|(k, _)| k.clone())
        {
            map.remove(&lightest);
        }
    }

    /// Топ доменов по суммарному трафику (rx+tx), тяжёлые сверху, и суммарный
    /// трафик ПО ВСЕМ доменам (не только показанным) — чтобы итог в заголовке
    /// не занижался, когда доменов больше, чем строк в топе.
    pub fn top_domains(&self) -> (Vec<DomainTraffic>, u64) {
        let Ok(map) = self.domain_traffic.lock() else { return (Vec::new(), 0) };
        let total: u64 = map.values().map(|(rx, tx)| rx.saturating_add(*tx)).sum();
        let mut rows: Vec<DomainTraffic> = map
            .iter()
            .map(|(domain, (rx, tx))| DomainTraffic { domain: domain.clone(), rx: *rx, tx: *tx })
            .collect();
        rows.sort_by(|a, b| (b.rx + b.tx).cmp(&(a.rx + a.tx)).then_with(|| a.domain.cmp(&b.domain)));
        rows.truncate(DOMAIN_TRAFFIC_TOP);
        (rows, total)
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

/// Трафик одного домена для показа в интерфейсе (экран «Трафик»).
#[derive(Debug, Clone)]
pub struct DomainTraffic {
    pub domain: String,
    /// Отдано пользователем наружу (запросы, аплоады).
    pub rx: u64,
    /// Получено пользователю (страницы, видео, скачивания).
    pub tx: u64,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_traffic_skips_empty_and_zero_and_accumulates() {
        let m = Metrics::new();
        m.record_domain_traffic("", 100, 100); // пустой домен — не пишем
        m.record_domain_traffic("a.com", 0, 0); // нулевой трафик — не пишем
        m.record_domain_traffic("a.com", 10, 5);
        m.record_domain_traffic("a.com", 1, 2); // накапливается к тому же домену
        let (rows, total) = m.top_domains();
        assert_eq!(rows.len(), 1, "пустой и нулевой не попали");
        assert_eq!((rows[0].rx, rows[0].tx), (11, 7));
        assert_eq!(total, 18);
    }

    #[test]
    fn top_domains_sorted_by_total_desc() {
        let m = Metrics::new();
        m.record_domain_traffic("small.com", 1, 1);
        m.record_domain_traffic("big.com", 100, 100);
        m.record_domain_traffic("mid.com", 50, 0);
        let (rows, total) = m.top_domains();
        let names: Vec<&str> = rows.iter().map(|r| r.domain.as_str()).collect();
        assert_eq!(names, ["big.com", "mid.com", "small.com"], "тяжёлые сверху");
        assert_eq!(total, 252); // 200 + 50 + 2
    }

    #[test]
    fn top_domains_truncates_to_top_but_total_counts_all() {
        let m = Metrics::new();
        // Больше строк, чем показывает топ: итог должен учитывать все.
        for i in 0..(DOMAIN_TRAFFIC_TOP + 5) {
            m.record_domain_traffic(&format!("d{i:03}"), 10, 0);
        }
        let (rows, total) = m.top_domains();
        assert_eq!(rows.len(), DOMAIN_TRAFFIC_TOP, "показываем только топ");
        assert_eq!(total, (DOMAIN_TRAFFIC_TOP as u64 + 5) * 10, "итог — по всем доменам");
    }

    #[test]
    fn cap_evicts_the_lightest_domain() {
        let m = Metrics::new();
        // Самый лёгкий — "d0000" (вес 1); дальше веса растут.
        for i in 0..=DOMAIN_TRAFFIC_CAP {
            m.record_domain_traffic(&format!("d{i:05}"), (i as u64) + 1, 0);
        }
        let (rows, _) = m.top_domains();
        // При переполнении карта усечена до CAP, вытеснен самый лёгкий (d00000).
        assert!(rows.iter().all(|r| r.domain != "d00000"), "самый лёгкий вытеснен");
    }
}
