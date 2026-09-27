//! UDP в прозрачном режиме Windows: QUIC, звонки и DNS.
//!
//! # Чем отличается от Linux
//!
//! В Linux датаграммы заворачиваются правилом TPROXY в прокси, и он
//! пересылает их от своего имени, а мусор перед первым пакетом шлёт со
//! своего сокета. Здесь перехват видит сами пакеты, поэтому прокси не
//! нужен вовсе: датаграмма уходит от приложения как есть, а мусорные пакеты
//! вставляются перед ней в тот же поток, с теми же адресами и портами.
//!
//! Что перехватывается и что с этим делать — то же, что в Linux:
//!
//! * UDP/443 (QUIC) и UDP на порты звонков (`session::CALL_PORTS`, сети
//!   Telegram) — см. [`filter`]; из QUIC и звонков в программу попадают
//!   только первые датаграммы, узнаваемые по байтам, остальное идёт мимо;
//! * адрес трекера — датаграммы выбрасываются, браузер уходит на TCP, где
//!   имя видно и соединение сбрасывается уже по SNI;
//! * сайт из списка обхода или звонок (`session::is_call_flow`) — перед
//!   первым пакетом мусор, как в Linux;
//! * всё остальное идёт без изменений.
//!
//! Имя сайта в QUIC зашифровано, поэтому решение принимается по адресу
//! через кэш «адрес → домен». Его наполняют DNS (запросы тоже
//! перехватываются, см. [`reply`]) и прозрачный TCP-режим по SNI.
//!
//! Мусор уходит с паузами, а цикл перехвата ждать не может: он держит весь
//! трафик машины. Поэтому мусор и хвост потока, пришедший за это время,
//! отправляет отдельный поток ([`Step::Junk`]), строго по порядку: иначе
//! следующие датаграммы обогнали бы первый пакет.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use super::nat::HTTPS_PORT;
use crate::proxy::udp::session::{CALL_PORTS, LOCAL_NETS_V4};

const IPPROTO_UDP: u8 = 17;

/// Сколько помнить поток без датаграмм. Как у сессий в Linux.
const IDLE_TTL: Duration = Duration::from_secs(120);
const PURGE_EVERY: Duration = Duration::from_secs(30);
/// Сколько после начала потока его датаграммы идут через очередь
/// отправителя мусора. С запасом больше, чем уходит на сам мусор
/// (по умолчанию 6 пакетов с паузами до 40 мс).
const QUEUE_WINDOW: Duration = Duration::from_secs(2);

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
/// Те же потоки, что у правил nftables в Linux (`firewall::ruleset`):
/// QUIC, DNS, порты звонков вне локальных сетей и сети Telegram. Звонки,
/// как и в Linux, только по IPv4.
///
/// Но не все их датаграммы, а только те, перед которыми может понадобиться
/// мусор или которые надо выбросить: мусор уходит перед первой датаграммой
/// потока, а она узнаётся по байтам. Раньше через программу шёл каждый
/// пакет QUIC (видео YouTube) и каждый пакет на портах 50000–65535 (голос
/// и игры), и под нагрузкой они ждали в очереди драйвера. Теперь:
///
/// * QUIC — только пакеты с длинным заголовком Initial (и 0-RTT: у них
///   тот же диапазон первого байта, 0xC0–0xDF). Трекер выбрасывается тоже
///   по Initial: без него рукопожатие не начнётся.
/// * Порты звонков — только STUN (им начинают звонок WebRTC и Telegram
///   между собеседниками) и запрос IP discovery голоса Discord. Сам голос
///   и игры на тех же портах идут мимо программы.
/// * Сети Telegram — по-прежнему всё: у голоса через его серверы нет
///   узнаваемого первого пакета. Эти потоки есть только во время звонка
///   в Telegram.
///
/// Счётчик QUIC-сессий в интерфейсе из-за этого приблизительный: сессия
/// считается закрытой через две минуты после последнего Initial.
pub fn filter(dns: bool, calls: bool) -> String {
    let mut parts = vec![format!(
        "(udp.DstPort == {HTTPS_PORT} and udp.PayloadLength > 0 \
         and udp.Payload[0] >= 192 and udp.Payload[0] <= 223)"
    )];
    if dns {
        parts.push("udp.DstPort == 53".into());
    }
    if calls {
        let local = LOCAL_NETS_V4
            .iter()
            .map(|(ip, bits)| {
                let (a, b) = range(Ipv4Addr::from(*ip), *bits);
                format!("!(ip.DstAddr >= {a} and ip.DstAddr <= {b})")
            })
            .collect::<Vec<_>>()
            .join(" and ");
        let ports = CALL_PORTS
            .iter()
            .map(|(a, b)| format!("(udp.DstPort >= {a} and udp.DstPort <= {b})"))
            .collect::<Vec<_>>()
            .join(" or ");
        // STUN: магическое число 0x2112A442 в байтах 4..8. Discord: 74 байта,
        // тип 0x0001, длина 70 (см. session::is_stun, is_discord_ip_discovery).
        let first = "((udp.PayloadLength >= 20 and udp.Payload[4] == 33 and udp.Payload[5] == 18 \
                     and udp.Payload[6] == 164 and udp.Payload[7] == 66) \
                     or (udp.PayloadLength == 74 and udp.Payload[0] == 0 and udp.Payload[1] == 1 \
                     and udp.Payload[2] == 0 and udp.Payload[3] == 70))";
        parts.push(format!("(ip and {local} and ({ports}) and {first})"));

        let telegram = crate::proxy::telegram::networks_v4()
            .map(|(ip, bits)| {
                let (a, b) = range(ip, bits);
                format!("(ip.DstAddr >= {a} and ip.DstAddr <= {b})")
            })
            .collect::<Vec<_>>()
            .join(" or ");
        parts.push(format!("(ip and udp.DstPort != 53 and ({telegram}))"));
    }
    format!("(outbound and udp and ({}))", parts.join(" or "))
}

/// Что делать с новым потоком.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    Pass,
    Block,
    /// Мусор перед первым пакетом. `quic` — поддельные Initial вместо
    /// случайных байт.
    Junk { quic: bool },
}

/// Что сделать с датаграммой.
pub enum Step<M> {
    Pass,
    /// Выбросить. `first` — первая датаграмма потока, о ней стоит написать
    /// в лог; об остальных нет, повторы браузера засыпали бы его.
    Drop { first: bool },
    /// Новый поток с обходом. Датаграмма уже лежит в очереди: отправитель
    /// шлёт мусор, потом всё из очереди по порядку.
    Junk { rx: mpsc::Receiver<M>, quic: bool },
    /// Датаграмма встала в очередь отправителя мусора.
    Queued,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Key {
    src: IpAddr,
    sport: u16,
    dst: IpAddr,
}

struct Flow<M> {
    last_seen: Instant,
    blocked: bool,
    /// Начался ли поток с QUIC Initial: только такие считаются QUIC-сессиями
    /// в интерфейсе, как и в остальных режимах.
    is_quic: bool,
    queue: Option<(mpsc::Sender<M>, Instant)>,
}

pub struct Tracker<M> {
    flows: HashMap<Key, Flow<M>>,
    last_purge: Instant,
}

impl<M> Default for Tracker<M> {
    fn default() -> Self {
        Tracker { flows: HashMap::new(), last_purge: Instant::now() }
    }
}

impl<M> Tracker<M> {
    /// Решает судьбу исходящей датаграммы.
    ///
    /// `policy` спрашивается один раз на поток, с заголовками и содержимым
    /// первой датаграммы. `item` — то, что кладётся в очередь отправителя
    /// мусора (пакет с метаданными перехвата). Второе значение — изменение
    /// числа QUIC-сессий.
    pub fn process(
        &mut self,
        pkt: &[u8],
        now: Instant,
        policy: impl FnOnce(&Udp, &[u8]) -> Policy,
        item: impl FnOnce() -> M,
    ) -> (Step<M>, QuicCount) {
        let closed = self.purge(now);
        let Some(u) = parse(pkt) else { return (Step::Pass, closed) };
        let payload = &pkt[u.ip_len + 8..];
        let key = Key { src: u.src, sport: u.sport, dst: u.dst };

        if let Some(flow) = self.flows.get_mut(&key) {
            flow.last_seen = now;
            if flow.blocked {
                return (Step::Drop { first: false }, closed);
            }
            if let Some((tx, until)) = &flow.queue {
                // Окно очереди прошло — отправитель давно разобрал её, и
                // дальше датаграммы идут напрямую. Закрытие очереди
                // заодно завершает его поток.
                if now < *until && tx.send(item()).is_ok() {
                    return (Step::Queued, closed);
                }
                flow.queue = None;
            }
            return (Step::Pass, closed);
        }

        let is_quic = crate::proxy::udp::session::is_quic_initial(payload);
        let mut flow = Flow { last_seen: now, blocked: false, is_quic, queue: None };
        let step = match policy(&u, payload) {
            Policy::Block => {
                flow.blocked = true;
                Step::Drop { first: true }
            }
            Policy::Junk { quic } => {
                let (tx, rx) = mpsc::channel();
                let _ = tx.send(item());
                flow.queue = Some((tx, now + QUEUE_WINDOW));
                Step::Junk { rx, quic }
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

    /// Как решал бы перехват: мусор перед QUIC.
    fn bypass(_: &Udp, payload: &[u8]) -> Policy {
        Policy::Junk { quic: crate::proxy::udp::session::is_quic_initial(payload) }
    }

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

    /// Initial к сайту из списка открывает очередь, и следующие датаграммы
    /// встают за ним, пока не пройдёт окно.
    #[test]
    fn bypass_flow_queues_behind_junk_then_goes_direct() {
        let mut t: Tracker<u32> = Tracker::default();
        let now = Instant::now();

        let (step, count) = t.process(&v4(443, &initial()), now, bypass, || 1);
        let Step::Junk { rx, quic: true } = step else { panic!("ожидали мусор") };
        assert_eq!(count.opened, 1);

        let (step, _) = t.process(&v4(443, b"next"), now, |_, _| panic!(), || 2);
        assert!(matches!(step, Step::Queued));
        assert_eq!(rx.try_iter().collect::<Vec<_>>(), vec![1, 2]);

        let later = now + QUEUE_WINDOW;
        let (step, _) = t.process(&v4(443, b"late"), later, |_, _| panic!(), || 3);
        assert!(matches!(step, Step::Pass));
        // Очередь закрыта: отправитель мусора завершится.
        assert!(rx.recv().is_err());
    }

    #[test]
    fn tracker_flows_are_dropped_silently_after_the_first() {
        let mut t: Tracker<()> = Tracker::default();
        let now = Instant::now();
        let (step, _) = t.process(&v4(443, &initial()), now, |_, _| Policy::Block, || ());
        assert!(matches!(step, Step::Drop { first: true }));
        let (step, _) = t.process(&v4(443, &initial()), now, |_, _| panic!(), || ());
        assert!(matches!(step, Step::Drop { first: false }));
    }

    /// Мусор получает только новый поток: середина потока, который уже
    /// шёл, идёт как есть.
    #[test]
    fn junk_only_for_the_first_datagram() {
        let mut t: Tracker<()> = Tracker::default();
        let now = Instant::now();
        let (step, count) = t.process(&v4(50007, b"stun"), now, |_, _| Policy::Junk { quic: false }, || ());
        assert!(matches!(step, Step::Junk { quic: false, .. }));
        assert_eq!(count.opened, 0, "не QUIC — не QUIC-сессия");

        let (step, _) = t.process(&v4(50007, b"voice"), now + QUEUE_WINDOW, |_, _| panic!(), || ());
        assert!(matches!(step, Step::Pass));
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
    fn filter_matches_linux_rules() {
        let quic = filter(false, false);
        assert!(quic.contains("udp.DstPort == 443"));
        assert!(quic.contains("udp.Payload[0] >= 192"), "только длинные заголовки QUIC");
        assert!(!quic.contains("udp.DstPort == 53"));
        let f = filter(true, true);
        assert!(f.contains("udp.DstPort == 53"));
        assert!(f.contains("(udp.DstPort >= 50000 and udp.DstPort <= 65535)"));
        assert!(f.contains("!(ip.DstAddr >= 192.168.0.0 and ip.DstAddr <= 192.168.255.255)"));
        assert!(f.contains("(ip.DstAddr >= 149.154.160.0 and ip.DstAddr <= 149.154.175.255)"));
        assert!(f.contains("!(ip.DstAddr >= 255.255.255.255 and ip.DstAddr <= 255.255.255.255)"));
        assert!(f.contains("udp.Payload[4] == 33"), "на портах звонков — только STUN");
        assert!(f.contains("udp.PayloadLength == 74"), "и IP discovery Discord");
    }

    /// Фильтр пропускает ровно то, что узнают session::is_stun и
    /// is_discord_ip_discovery: байты в фильтре записаны вручную, и
    /// разойтись с проверкой в коде они не должны.
    #[test]
    fn filter_signatures_match_the_call_detectors() {
        let mut stun = vec![0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42];
        stun.extend_from_slice(&[0u8; 12]);
        assert!(crate::proxy::udp::session::is_stun(&stun));
        assert_eq!((stun[4], stun[5], stun[6], stun[7]), (33, 18, 164, 66));

        let mut discovery = vec![0x00, 0x01, 0x00, 70];
        discovery.resize(74, 0);
        assert!(crate::proxy::udp::session::is_discord_ip_discovery(&discovery));

        let quic = initial();
        assert!(crate::proxy::udp::session::is_quic_initial(&quic));
        assert!((192..=223).contains(&quic[0]), "Initial попадает в диапазон фильтра");
    }

    #[test]
    fn idle_quic_sessions_are_counted_as_closed() {
        let mut t: Tracker<()> = Tracker::default();
        let start = Instant::now();
        t.process(&v4(443, &initial()), start, |_, _| Policy::Pass, || ());

        let later = start + IDLE_TTL + PURGE_EVERY;
        let (_, count) = t.process(&v4(50000, b"x"), later, |_, _| Policy::Pass, || ());
        assert_eq!(count.closed, 1);
    }
}
