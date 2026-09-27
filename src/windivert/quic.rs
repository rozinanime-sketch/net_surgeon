//! QUIC в прозрачном режиме Windows.
//!
//! # Чем отличается от Linux
//!
//! В Linux датаграммы UDP/443 заворачиваются правилом TPROXY в прокси, и он
//! пересылает их от своего имени, а мусор перед первым пакетом шлёт со
//! своего сокета. Здесь перехват видит сами пакеты, поэтому прокси не
//! нужен вовсе: датаграмма уходит от приложения как есть, а мусорные пакеты
//! вставляются перед ней в тот же поток, с теми же адресами и портами.
//!
//! Решение то же, что в Linux, и принимается по адресу через кэш «адрес →
//! домен»: имя в QUIC зашифровано. Кэш наполняет прозрачный TCP-режим по
//! SNI, а браузер обычно сначала открывает сайт по TCP.
//!
//! * адрес трекера — датаграммы выбрасываются, браузер уходит на TCP, где
//!   имя видно и соединение сбрасывается уже по SNI;
//! * сайт из списка обхода и первый пакет — QUIC Initial — сначала мусор
//!   (поддельные Initial), потом настоящий пакет;
//! * всё остальное идёт без изменений.
//!
//! Мусор уходит с паузами, а цикл перехвата ждать не может: он держит весь
//! трафик машины. Поэтому мусор и хвост потока, пришедший за это время,
//! отправляет отдельный поток ([`Step::Junk`]), строго по порядку: иначе
//! следующие датаграммы обогнали бы Initial.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use super::nat::HTTPS_PORT;

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

/// Что делать с датаграммами к этому адресу.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    Pass,
    Block,
    Bypass,
}

/// Что сделать с датаграммой.
pub enum Step<M> {
    Pass,
    /// Выбросить. `first` — первая датаграмма потока, о ней стоит написать
    /// в лог; об остальных нет, повторы браузера засыпали бы его.
    Drop { first: bool },
    /// Новый поток с обходом. Датаграмма уже лежит в очереди: отправитель
    /// шлёт мусор, потом всё из очереди по порядку.
    Junk(mpsc::Receiver<M>),
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
    /// `policy` спрашивается один раз на поток. `item` — то, что кладётся
    /// в очередь отправителя мусора (пакет с метаданными перехвата).
    /// Второе значение — изменение числа QUIC-сессий.
    pub fn process(
        &mut self,
        pkt: &[u8],
        now: Instant,
        policy: impl FnOnce(IpAddr) -> Policy,
        item: impl FnOnce() -> M,
    ) -> (Step<M>, QuicCount) {
        let closed = self.purge(now);
        let Some(u) = parse(pkt) else { return (Step::Pass, closed) };
        if u.dport != HTTPS_PORT {
            return (Step::Pass, closed);
        }
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
        let step = match policy(u.dst) {
            Policy::Block => {
                flow.blocked = true;
                Step::Drop { first: true }
            }
            // Мусор только перед Initial: посреди потока, начатого до
            // перехвата, он ничего не обходит.
            Policy::Bypass if is_quic => {
                let (tx, rx) = mpsc::channel();
                let _ = tx.send(item());
                flow.queue = Some((tx, now + QUEUE_WINDOW));
                Step::Junk(rx)
            }
            _ => Step::Pass,
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

    /// Initial к сайту из списка открывает очередь, и следующие датаграммы
    /// встают за ним, пока не пройдёт окно.
    #[test]
    fn bypass_flow_queues_behind_junk_then_goes_direct() {
        let mut t: Tracker<u32> = Tracker::default();
        let now = Instant::now();

        let (step, count) = t.process(&v4(443, &initial()), now, |_| Policy::Bypass, || 1);
        let Step::Junk(rx) = step else { panic!("ожидали мусор") };
        assert_eq!(count.opened, 1);

        let (step, _) = t.process(&v4(443, b"next"), now, |_| panic!(), || 2);
        assert!(matches!(step, Step::Queued));
        assert_eq!(rx.try_iter().collect::<Vec<_>>(), vec![1, 2]);

        let later = now + QUEUE_WINDOW;
        let (step, _) = t.process(&v4(443, b"late"), later, |_| panic!(), || 3);
        assert!(matches!(step, Step::Pass));
        // Очередь закрыта: отправитель мусора завершится.
        assert!(rx.recv().is_err());
    }

    #[test]
    fn tracker_flows_are_dropped_silently_after_the_first() {
        let mut t: Tracker<()> = Tracker::default();
        let now = Instant::now();
        let (step, _) = t.process(&v4(443, &initial()), now, |_| Policy::Block, || ());
        assert!(matches!(step, Step::Drop { first: true }));
        let (step, _) = t.process(&v4(443, &initial()), now, |_| panic!(), || ());
        assert!(matches!(step, Step::Drop { first: false }));
    }

    /// Без Initial мусор бесполезен, а не-QUIC и другие порты не трогаются.
    #[test]
    fn only_initial_to_443_gets_junk() {
        let mut t: Tracker<()> = Tracker::default();
        let now = Instant::now();
        let (step, count) = t.process(&v4(443, b"short header"), now, |_| Policy::Bypass, || ());
        assert!(matches!(step, Step::Pass));
        assert_eq!(count.opened, 0);

        let (step, _) = t.process(&v4(53, &initial()), now, |_| panic!(), || ());
        assert!(matches!(step, Step::Pass));
    }

    #[test]
    fn idle_quic_sessions_are_counted_as_closed() {
        let mut t: Tracker<()> = Tracker::default();
        let start = Instant::now();
        t.process(&v4(443, &initial()), start, |_| Policy::Pass, || ());

        let later = start + IDLE_TTL + PURGE_EVERY;
        let (_, count) = t.process(&v4(53, b"x"), later, |_| panic!(), || ());
        assert_eq!(count.closed, 1);
    }
}
