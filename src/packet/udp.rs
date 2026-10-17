//! UDP в прозрачном режиме Windows: QUIC и DNS.
//!
//! # Чем отличается от Linux
//!
//! В Linux датаграммы заворачиваются правилом TPROXY в прокси, и он
//! пересылает их от своего имени. Здесь перехват видит сами пакеты, поэтому
//! прокси не нужен вовсе: датаграмма уходит от приложения как есть.
//!
//! Что перехватывается и что с этим делать:
//!
//! * первые датаграммы QUIC (UDP/443, Initial) — см. [`filter`];
//! * адрес трекера — датаграммы выбрасываются, браузер уходит на TCP, где
//!   имя видно и соединение сбрасывается уже по SNI;
//! * всё остальное идёт без изменений.
//!
//! Имя сайта в QUIC зашифровано, поэтому решение принимается по адресу
//! через кэш «адрес → домен». Его наполняют DNS (запросы тоже
//! перехватываются, см. [`reply`]) и прозрачный TCP-режим по SNI.
//!
//! Раньше здесь же перехватывались звонки (STUN, голос Discord, сети
//! Telegram) и перед первым пакетом сайтов из списка и звонков вставлялся
//! мусор — с очередью и отдельным потоком отправки. Мусор удалён (см.
//! `config::CallParams`), а смены порта для звонков в Windows пока нет,
//! так что и перехватывать их стало незачем.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use super::nat::HTTPS_PORT;

const IPPROTO_UDP: u8 = 17;

/// Сколько помнить поток без датаграмм. Как у сессий в Linux.
const IDLE_TTL: Duration = Duration::from_secs(120);
const PURGE_EVERY: Duration = Duration::from_secs(30);
/// Сколько потоков помнить. Сверх — новый поток проходит как есть, без
/// учёта: лавина новых UDP-потоков (торрент, сканер) иначе раздула бы
/// таблицу.
const MAX_FLOWS: usize = 4096;

/// Разобранные заголовки IP и UDP.
#[derive(Debug, Clone, Copy)]
pub struct Udp {
    pub ip_len: usize,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub sport: u16,
    pub dport: u16,
}

pub fn parse(pkt: &[u8]) -> Option<Udp> {
    let (ip_len, src, dst) = match pkt.first()? >> 4 {
        4 => {
            let ihl = usize::from(pkt[0] & 0x0f) * 4;
            if ihl < 20 || pkt.len() < ihl || pkt[9] != IPPROTO_UDP {
                return None;
            }
            if u16::from_be_bytes([pkt[6], pkt[7]]) & 0x3fff != 0 {
                return None;
            }
            let src = Ipv4Addr::from(<[u8; 4]>::try_from(&pkt[12..16]).ok()?);
            let dst = Ipv4Addr::from(<[u8; 4]>::try_from(&pkt[16..20]).ok()?);
            (ihl, IpAddr::V4(src), IpAddr::V4(dst))
        }
        6 => {
            if pkt.len() < 40 || pkt[6] != IPPROTO_UDP {
                return None;
            }
            let src = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[8..24]).ok()?);
            let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[24..40]).ok()?);
            (40, IpAddr::V6(src), IpAddr::V6(dst))
        }
        _ => return None,
    };
    let udp = pkt.get(ip_len..ip_len + 8)?;
    Some(Udp {
        ip_len,
        src,
        dst,
        sport: u16::from_be_bytes([udp[0], udp[1]]),
        dport: u16::from_be_bytes([udp[2], udp[3]]),
    })
}

/// Датаграмма с заголовками `template`, но другим содержимым. Длины в
/// заголовках исправлены, контрольные суммы пересчитывает вызывающий.
pub fn with_payload(template: &[u8], u: &Udp, payload: &[u8]) -> Vec<u8> {
    let head = u.ip_len + 8;
    let mut pkt = Vec::with_capacity(head + payload.len());
    pkt.extend_from_slice(&template[..head]);
    pkt.extend_from_slice(payload);

    let udp_len = (8 + payload.len()) as u16;
    pkt[u.ip_len + 4..u.ip_len + 6].copy_from_slice(&udp_len.to_be_bytes());
    if u.ip_len == 40 {
        pkt[4..6].copy_from_slice(&udp_len.to_be_bytes());
    } else {
        let total = pkt.len() as u16;
        pkt[2..4].copy_from_slice(&total.to_be_bytes());
    }
    pkt
}

/// Ответ на датаграмму `query`: адреса и порты переставлены, содержимое
/// другое. Так перехват отвечает на DNS-запрос от имени сервера, к которому
/// он шёл. Контрольные суммы пересчитывает вызывающий.
pub fn reply(query: &[u8], u: &Udp, payload: &[u8]) -> Vec<u8> {
    let mut pkt = with_payload(query, u, payload);
    let (a, b, n) = if u.ip_len == 40 { (8, 24, 16) } else { (12, 16, 4) };
    for i in 0..n {
        pkt.swap(a + i, b + i);
    }
    pkt[u.ip_len..u.ip_len + 2].copy_from_slice(&u.dport.to_be_bytes());
    pkt[u.ip_len + 2..u.ip_len + 4].copy_from_slice(&u.sport.to_be_bytes());
    pkt
}

/// Первый и последний адрес сети.
pub(super) fn range(base: Ipv4Addr, bits: u8) -> (Ipv4Addr, Ipv4Addr) {
    let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
    let start = u32::from(base) & mask;
    (Ipv4Addr::from(start), Ipv4Addr::from(start | !mask))
}

/// Часть фильтра WinDivert для UDP: что отдавать в [`Tracker`] и на DNS.
///
/// Не все датаграммы QUIC, а только те, по которым решается судьба потока:
/// пакеты с длинным заголовком Initial (и 0-RTT: у них тот же диапазон
/// первого байта, 0xC0–0xDF). Трекер выбрасывается тоже по Initial: без
/// него рукопожатие не начнётся. Раньше через программу шёл каждый пакет
/// QUIC (видео YouTube), и под нагрузкой они ждали в очереди драйвера.
///
/// Счётчик QUIC-сессий в интерфейсе из-за этого приблизительный: сессия
/// считается закрытой через две минуты после последнего Initial.
pub fn filter(dns: bool) -> String {
    let mut parts = vec![format!(
        "(udp.DstPort == {HTTPS_PORT} and udp.PayloadLength > 0 \
         and udp.Payload[0] >= 192 and udp.Payload[0] <= 223)"
    )];
    if dns {
        parts.push("udp.DstPort == 53".into());
    }
    format!("(outbound and udp and ({}))", parts.join(" or "))
}

/// Что делать с новым потоком.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    Pass,
    Block,
}

/// Что сделать с датаграммой.
#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    Pass,
    /// Выбросить. `first` — первая датаграмма потока, о ней стоит написать
    /// в лог; об остальных нет, повторы браузера засыпали бы его.
    Drop { first: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Key {
    src: IpAddr,
    sport: u16,
    dst: IpAddr,
}

struct Flow {
    last_seen: Instant,
    blocked: bool,
    /// Начался ли поток с QUIC Initial: только такие считаются QUIC-сессиями
    /// в интерфейсе, как и в остальных режимах.
    is_quic: bool,
}

pub struct Tracker {
    flows: HashMap<Key, Flow>,
    last_purge: Instant,
}

impl Default for Tracker {
    fn default() -> Self {
        Tracker { flows: HashMap::new(), last_purge: Instant::now() }
    }
}

impl Tracker {
    /// Решает судьбу исходящей датаграммы.
    ///
    /// `policy` спрашивается один раз на поток, с заголовками и содержимым
    /// первой датаграммы. Второе значение — изменение числа QUIC-сессий.
    pub fn process(
        &mut self,
        pkt: &[u8],
        now: Instant,
        policy: impl FnOnce(&Udp, &[u8]) -> Policy,
    ) -> (Step, QuicCount) {
        let closed = self.purge(now);
        let Some(u) = parse(pkt) else { return (Step::Pass, closed) };
        let payload = &pkt[u.ip_len + 8..];
        let key = Key { src: u.src, sport: u.sport, dst: u.dst };

        if let Some(flow) = self.flows.get_mut(&key) {
            flow.last_seen = now;
            if flow.blocked {
                return (Step::Drop { first: false }, closed);
            }
            return (Step::Pass, closed);
        }

        if self.flows.len() >= MAX_FLOWS {
            return (Step::Pass, closed);
        }
        let is_quic = crate::proxy::udp::session::is_quic_initial(payload);
        let mut flow = Flow { last_seen: now, blocked: false, is_quic };
        let step = match policy(&u, payload) {
            Policy::Block => {
                flow.blocked = true;
                Step::Drop { first: true }
            }
            Policy::Pass => Step::Pass,
        };
        let opened = QuicCount { opened: usize::from(is_quic), ..closed };
        self.flows.insert(key, flow);
        (step, opened)
    }

    fn purge(&mut self, now: Instant) -> QuicCount {
        let mut count = QuicCount::default();
        if now.duration_since(self.last_purge) < PURGE_EVERY {
            return count;
        }
        self.last_purge = now;
        self.flows.retain(|_, f| {
            let alive = now.duration_since(f.last_seen) < IDLE_TTL;
            if !alive && f.is_quic {
                count.closed += 1;
            }
            alive
        });
        count
    }
}

/// Изменение числа QUIC-сессий для счётчика в интерфейсе.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QuicCount {
    pub opened: usize,
    pub closed: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP: [u8; 4] = [192, 168, 1, 10];
    const SERVER: [u8; 4] = [203, 0, 113, 5];

    fn v4(dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 28];
        p[0] = 0x45;
        p[8] = 64;
        p[9] = IPPROTO_UDP;
        p[12..16].copy_from_slice(&APP);
        p[16..20].copy_from_slice(&SERVER);
        p[20..22].copy_from_slice(&50000u16.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        let u = parse(&p).unwrap();
        with_payload(&p, &u, payload)
    }

    fn initial() -> Vec<u8> {
        crate::bypass::fragment::build_fake_quic_initial()
    }

    #[test]
    fn replacing_payload_fixes_lengths() {
        let pkt = v4(443, b"hello");
        assert_eq!(u16::from_be_bytes([pkt[2], pkt[3]]), 28 + 5);
        assert_eq!(u16::from_be_bytes([pkt[24], pkt[25]]), 8 + 5);

        let u = parse(&pkt).unwrap();
        let bigger = with_payload(&pkt, &u, &[7u8; 1200]);
        assert_eq!(bigger.len(), 28 + 1200);
        assert_eq!(u16::from_be_bytes([bigger[2], bigger[3]]), 28 + 1200);
        assert_eq!(u16::from_be_bytes([bigger[24], bigger[25]]), 8 + 1200);
        assert_eq!(&bigger[12..24], &pkt[12..24], "адреса и порты те же");
    }

    /// Сверх MAX_FLOWS новый поток проходит как есть, даже трекер.
    #[test]
    fn flows_beyond_the_limit_pass_untouched() {
        let mut t = Tracker::default();
        let now = Instant::now();
        let from = |sport: u16| {
            let mut p = v4(443, &initial());
            p[20..22].copy_from_slice(&sport.to_be_bytes());
            p
        };
        for sport in 0..MAX_FLOWS as u16 {
            t.process(&from(sport), now, |_, _| Policy::Pass);
        }
        let (step, _) = t.process(&from(MAX_FLOWS as u16), now, |_, _| Policy::Block);
        assert_eq!(step, Step::Pass);
        assert_eq!(t.flows.len(), MAX_FLOWS);
    }

    /// Судьба потока решается по первой датаграмме, дальше политика не
    /// спрашивается.
    #[test]
    fn policy_is_asked_once_per_flow() {
        let mut t = Tracker::default();
        let now = Instant::now();
        let (step, count) = t.process(&v4(443, &initial()), now, |_, _| Policy::Pass);
        assert_eq!(step, Step::Pass);
        assert_eq!(count.opened, 1);
        let (step, _) = t.process(&v4(443, b"next"), now, |_, _| panic!());
        assert_eq!(step, Step::Pass);
    }

    #[test]
    fn tracker_flows_are_dropped_silently_after_the_first() {
        let mut t = Tracker::default();
        let now = Instant::now();
        let (step, _) = t.process(&v4(443, &initial()), now, |_, _| Policy::Block);
        assert_eq!(step, Step::Drop { first: true });
        let (step, _) = t.process(&v4(443, &initial()), now, |_, _| panic!());
        assert_eq!(step, Step::Drop { first: false });
    }

    #[test]
    fn dns_reply_comes_from_the_server_asked() {
        let query = v4(53, b"query");
        let u = parse(&query).unwrap();
        let answer = reply(&query, &u, b"a longer answer");
        let r = parse(&answer).unwrap();
        assert_eq!((r.src, r.sport, r.dst, r.dport), (u.dst, 53, u.src, u.sport));
        assert_eq!(&answer[28..], b"a longer answer");
        assert_eq!(u16::from_be_bytes([answer[2], answer[3]]) as usize, answer.len());
    }

    #[test]
    fn filter_takes_quic_initials_and_dns() {
        let quic = filter(false);
        assert!(quic.contains("udp.DstPort == 443"));
        assert!(quic.contains("udp.Payload[0] >= 192"), "только длинные заголовки QUIC");
        assert!(!quic.contains("udp.DstPort == 53"));
        assert!(filter(true).contains("udp.DstPort == 53"));

        let initial = initial();
        assert!(crate::proxy::udp::session::is_quic_initial(&initial));
        assert!((192..=223).contains(&initial[0]), "Initial попадает в диапазон фильтра");
    }

    #[test]
    fn idle_quic_sessions_are_counted_as_closed() {
        let mut t = Tracker::default();
        let start = Instant::now();
        t.process(&v4(443, &initial()), start, |_, _| Policy::Pass);

        let later = start + IDLE_TTL + PURGE_EVERY;
        let (_, count) = t.process(&v4(50000, b"x"), later, |_, _| Policy::Pass);
        assert_eq!(count.closed, 1);
    }
}
