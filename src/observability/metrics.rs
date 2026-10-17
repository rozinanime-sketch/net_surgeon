use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::observability::stats::Percentiles;

/// Сколько доменов помнить в разбивке трафика. При переполнении вытесняются
/// самые лёгкие из давно не активных — интересны тяжёлые, — пачкой
/// [`DOMAIN_TRAFFIC_EVICT`] за раз, чтобы не сканировать карту на каждое
/// новое имя.
const DOMAIN_TRAFFIC_CAP: usize = 512;
const DOMAIN_TRAFFIC_EVICT: usize = 64;
/// Домен с трафиком за это время не вытесняется, даже если пока лёгкий.
/// Раньше вытеснялся самый лёгкий вообще — а им почти всегда был только что
/// добавленный, и сайт, качающий гигабайты мелкими соединениями, в таблицу
/// не попадал никогда.
const DOMAIN_TRAFFIC_FRESH: Duration = Duration::from_secs(300);
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
    /// Последний DoH-запрос релея удался. До первого запроса и без релея
    /// — неизвестно, а не «OK»: раньше индикатор горел зелёным, ничего не
    /// проверив.
    dns_checked: AtomicBool,
    dns_ok: AtomicBool,

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
    domain_traffic: Mutex<DomainTable>,
}

#[derive(Default)]
struct DomainTable {
    domains: HashMap<String, DomainEntry>,
    /// Трафик вытесненных доменов: итог в заголовке экрана считается по
    /// всем доменам, и без этого он занижался.
    evicted: u64,
}

struct DomainEntry {
    rx: u64,
    tx: u64,
    last: Instant,
}

impl DomainEntry {
    fn total(&self) -> u64 {
        self.rx.saturating_add(self.tx)
    }
}

/// Счётчик открытых соединений: держится, пока жив, и снимается сам —
/// и при панике обработчика, которая раньше оставляла его завышенным.
pub struct ConnectionGuard(Arc<Metrics>);

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.active_connections.fetch_sub(1, Ordering::Relaxed);
    }
}

/// То же для QUIC-сессии: лежит в самой сессии и снимается вместе с ней —
/// при закрытии по таймауту, при перезапуске прокси (таблица сессий
/// выбрасывается целиком) и при панике. Раньше после каждого перезапуска
/// на экране оставались «фантомные» сессии.
pub struct QuicSessionGuard(Arc<Metrics>);

impl Drop for QuicSessionGuard {
    fn drop(&mut self) {
        self.0.quic_sessions.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Metrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            active_connections: AtomicUsize::new(0),
            bytes_rx: AtomicU64::new(0),
            bytes_tx: AtomicU64::new(0),
            quic_sessions: AtomicUsize::new(0),
            dns_checked: AtomicBool::new(false),
            dns_ok: AtomicBool::new(false),
            tcp_listening: AtomicBool::new(false),
            udp_listening: AtomicBool::new(false),
            socks5_listening: AtomicBool::new(false),
            transparent_listening: AtomicBool::new(false),
            transparent_udp_listening: AtomicBool::new(false),
            connect_latency: Mutex::new(Percentiles::new(512)),
            ttfb_latency: Mutex::new(Percentiles::new(512)),
            domain_traffic: Mutex::new(DomainTable::default()),
        })
    }

    /// Открытое соединение; счётчик снимется, когда вернувшийся охранник
    /// будет удалён.
    pub fn connection(self: &Arc<Self>) -> ConnectionGuard {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        ConnectionGuard(Arc::clone(self))
    }
    pub fn add_rx(&self, n: u64) { self.bytes_rx.fetch_add(n, Ordering::Relaxed); }
    pub fn add_tx(&self, n: u64) { self.bytes_tx.fetch_add(n, Ordering::Relaxed); }
    /// QUIC-сессия; охранник храните в самой сессии.
    pub fn quic_session(self: &Arc<Self>) -> QuicSessionGuard {
        self.quic_sessions.fetch_add(1, Ordering::Relaxed);
        QuicSessionGuard(Arc::clone(self))
    }
    /// Для перехвата Windows, который сам ведёт учёт открытых и закрытых
    /// потоков (packet::udp::Tracker) и живёт до конца процесса.
    pub fn quic_session_opened(&self) { self.quic_sessions.fetch_add(1, Ordering::Relaxed); }
    pub fn quic_session_closed(&self) { self.quic_sessions.fetch_sub(1, Ordering::Relaxed); }
    pub fn set_dns_ok(&self, ok: bool) {
        self.dns_ok.store(ok, Ordering::Relaxed);
        self.dns_checked.store(true, Ordering::Relaxed);
    }

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
        let Ok(mut table) = self.domain_traffic.lock() else { return };
        let now = Instant::now();
        // Строка — только для нового имени, а не на каждое соединение.
        if let Some(entry) = table.domains.get_mut(domain) {
            entry.rx = entry.rx.saturating_add(rx);
            entry.tx = entry.tx.saturating_add(tx);
            entry.last = now;
            return;
        }
        table.domains.insert(domain.to_string(), DomainEntry { rx, tx, last: now });
        if table.domains.len() > DOMAIN_TRAFFIC_CAP {
            table.evict(now, domain);
        }
    }

    /// Топ доменов по суммарному трафику (rx+tx), тяжёлые сверху, и суммарный
    /// трафик ПО ВСЕМ доменам (не только показанным) — чтобы итог в заголовке
    /// не занижался, когда доменов больше, чем строк в топе.
    pub fn top_domains(&self) -> (Vec<DomainTraffic>, u64) {
        let Ok(table) = self.domain_traffic.lock() else { return (Vec::new(), 0) };
        let total = table.domains.values().fold(table.evicted, |sum, e| sum.saturating_add(e.total()));
        let mut rows: Vec<DomainTraffic> = table
            .domains
            .iter()
            .map(|(domain, e)| DomainTraffic { domain: domain.clone(), rx: e.rx, tx: e.tx })
            .collect();
        drop(table);
        rows.sort_by(|a, b| {
            b.rx.saturating_add(b.tx).cmp(&a.rx.saturating_add(a.tx)).then_with(|| a.domain.cmp(&b.domain))
        });
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
        // Окно копируется под замком, а сортируется уже без него и один раз
        // на все три перцентиля: снимок берёт интерфейс 20 раз в секунду, а
        // на этом же замке ждут соединения (record_ttfb_ms). Раньше окно
        // сортировалось трижды, и всё — под замком.
        let ttfb = self.ttfb_latency.lock().map(|p| p.clone()).ok();
        let latency_samples = ttfb.as_ref().map_or(0, |p| p.len());
        let [ttfb_p50, ttfb_p95, ttfb_p99] = match ttfb {
            Some(p) => p.percentiles([0.50, 0.95, 0.99]),
            None => [None; 3],
        };
        let connect_p50 = self.connect_latency.lock().map(|p| p.clone()).ok().and_then(|p| p.percentiles([0.50])[0]);

        MetricsSnapshot {
            active_connections: self.active_connections.load(Ordering::Relaxed),
            bytes_rx: self.bytes_rx.load(Ordering::Relaxed),
            bytes_tx: self.bytes_tx.load(Ordering::Relaxed),
            quic_sessions: self.quic_sessions.load(Ordering::Relaxed),
            dns_ok: self.dns_checked.load(Ordering::Relaxed).then(|| self.dns_ok.load(Ordering::Relaxed)),
            tcp_listening: self.tcp_listening.load(Ordering::Relaxed),
            udp_listening: self.udp_listening.load(Ordering::Relaxed),
            socks5_listening: self.socks5_listening.load(Ordering::Relaxed),
            transparent_listening: self.transparent_listening.load(Ordering::Relaxed),
            transparent_udp_listening: self.transparent_udp_listening.load(Ordering::Relaxed),
            connect_p50,
            ttfb_p50,
            ttfb_p95,
            ttfb_p99,
            latency_samples,
        }
    }
}

impl DomainTable {
    /// Выбрасывает пачку самых лёгких из давно не активных доменов; если
    /// таких не хватает — самых лёгких вообще, но не `keep` (только что
    /// добавленный). Их трафик остаётся в итоге.
    fn evict(&mut self, now: Instant, keep: &str) {
        let mut candidates: Vec<(bool, u64, String)> = self
            .domains
            .iter()
            .filter(|(name, _)| name.as_str() != keep)
            .map(|(name, e)| (now.duration_since(e.last) < DOMAIN_TRAFFIC_FRESH, e.total(), name.clone()))
            .collect();
        // Сначала давно не активные (false < true), среди них — лёгкие.
        candidates.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        let excess = self.domains.len() - DOMAIN_TRAFFIC_CAP + DOMAIN_TRAFFIC_EVICT;
        for (_, total, name) in candidates.into_iter().take(excess) {
            self.domains.remove(&name);
            self.evicted = self.evicted.saturating_add(total);
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
    /// `None` — DoH-релей ещё ничего не проверял (или не запущен).
    pub dns_ok: Option<bool>,
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
    fn new_domain_is_not_evicted_and_total_keeps_evicted_bytes() {
        let m = Metrics::new();
        let long_ago = Instant::now() - DOMAIN_TRAFFIC_FRESH - Duration::from_secs(1);
        {
            let mut t = m.domain_traffic.lock().unwrap();
            for i in 0..DOMAIN_TRAFFIC_CAP {
                t.domains.insert(format!("old{i}"), DomainEntry { rx: 1_000_000, tx: 0, last: long_ago });
            }
        }
        // Новый сайт мелкими соединениями: 50 КБ за раз.
        for _ in 0..3 {
            m.record_domain_traffic("new.example", 50_000, 0);
        }
        let (rows, total) = m.top_domains();
        let table = m.domain_traffic.lock().unwrap();
        let new = table.domains.get("new.example").expect("новый домен остаётся в таблице");
        assert_eq!(new.rx, 150_000, "и копит трафик");
        assert!(table.domains.len() <= DOMAIN_TRAFFIC_CAP);
        assert_eq!(total, DOMAIN_TRAFFIC_CAP as u64 * 1_000_000 + 150_000, "итог учитывает вытесненных");
        assert_eq!(rows.len(), DOMAIN_TRAFFIC_TOP);
    }

    #[test]
    fn guards_undo_their_counters_when_dropped() {
        let m = Metrics::new();
        let conn = m.connection();
        let quic = m.quic_session();
        assert_eq!((m.snapshot().active_connections, m.snapshot().quic_sessions), (1, 1));
        drop((conn, quic));
        assert_eq!((m.snapshot().active_connections, m.snapshot().quic_sessions), (0, 0));
    }

    #[test]
    fn dns_is_unknown_until_checked() {
        let m = Metrics::new();
        assert_eq!(m.snapshot().dns_ok, None);
        m.set_dns_ok(false);
        assert_eq!(m.snapshot().dns_ok, Some(false));
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
