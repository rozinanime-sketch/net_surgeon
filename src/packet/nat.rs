//! Разворот перехваченных соединений на локальный слушатель.
//!
//! Чистая логика над байтами пакета, без WinDivert: так её можно проверить
//! тестами на любой системе, а драйвер остаётся тонкой обёрткой вокруг неё.
//!
//! # Схема
//!
//! Приложение открывает соединение `A:p → B:443` (A — адрес этой машины).
//! Исходящий пакет переписывается в `B:p → A:порт` и возвращается в систему
//! как входящий: ядро видит, будто B подключился к нашему слушателю.
//! Ответы слушателя `A:порт → B:p` переписываются обратно в `B:443 → A:p`
//! и тоже доставляются как входящие — приложению кажется, что отвечает B.
//!
//! Исходный адрес назначения при этом не теряется: `peer_addr()` принятого
//! соединения — это `B:p`, а порт назначения всегда 443. Таблица соединений
//! нужна только для того, чтобы отличать перехваченные потоки от прочих.
//!
//! # Что не трогается
//!
//! * Соединения, открытые до запуска: перехватывается только поток,
//!   начатый с SYN при работающем перехвате. Переписать середину чужого
//!   потока значит оборвать его.
//! * Соединения самого прокси: иначе он бы подключался сам к себе. Кто
//!   открыл соединение, решает вызывающий (по таблице сокетов системы).
//!
//! Этот приём — тот же, что в примере streamdump из поставки WinDivert.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

/// Порт, соединения на который перехватываются. Тот же, что у правила
/// nftables в Linux.
pub const HTTPS_PORT: u16 = 443;

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;
const IPPROTO_TCP: u8 = 6;

/// Сколько помнить поток без пакетов. Столько же по умолчанию ждёт TCP
/// keepalive: забытый живой поток дальше шёл бы мимо слушателя, и сервер
/// ответил бы на него сбросом.
const IDLE_TTL: Duration = Duration::from_secs(2 * 60 * 60);
/// Закрытый с обеих сторон поток помнится недолго: только чтобы дошли
/// последние подтверждения.
const CLOSED_TTL: Duration = Duration::from_secs(30);
const PURGE_EVERY: Duration = Duration::from_secs(30);

/// Что сделать с пакетом.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Отправить дальше без изменений.
    Pass,
    /// Пакет переписан: доставить как входящий.
    Reflect,
    /// Выбросить.
    Drop,
    /// Слушатель не ответил на перехваченный SYN, и повтор SYN отпущен к
    /// серверу напрямую. Так бывает, если входящие на порт слушателя режет
    /// брандмауэр: без этого отката перехват оставил бы машину без HTTPS.
    GaveUp,
}

/// Поток со стороны приложения: `A:p → B`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    local: IpAddr,
    local_port: u16,
    remote: IpAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Redirected { answered: bool, fin_out: bool, fin_in: bool },
    /// Перехват не удался, поток идёт к серверу напрямую.
    Direct,
}

struct Flow {
    state: State,
    last_seen: Instant,
}

pub struct Nat {
    port: u16,
    flows: HashMap<FlowKey, Flow>,
    last_purge: Instant,
}

/// Разобранные заголовки IP и TCP.
struct Tcp {
    ip_len: usize,
    src: IpAddr,
    dst: IpAddr,
    sport: u16,
    dport: u16,
    flags: u8,
}

fn parse(pkt: &[u8]) -> Option<Tcp> {
    let version = pkt.first()? >> 4;
    let (ip_len, src, dst) = match version {
        4 => {
            let ihl = usize::from(pkt[0] & 0x0f) * 4;
            if ihl < 20 || pkt.len() < ihl || pkt[9] != IPPROTO_TCP {
                return None;
            }
            // Фрагмент: заголовка TCP в нём может не быть вовсе.
            let frag = u16::from_be_bytes([pkt[6], pkt[7]]);
            if frag & 0x3fff != 0 {
                return None;
            }
            let src = Ipv4Addr::from(<[u8; 4]>::try_from(&pkt[12..16]).ok()?);
            let dst = Ipv4Addr::from(<[u8; 4]>::try_from(&pkt[16..20]).ok()?);
            (ihl, IpAddr::V4(src), IpAddr::V4(dst))
        }
        // Только без заголовков расширения: у TCP их практически не бывает,
        // а редкий такой пакет просто уйдёт как есть.
        6 => {
            if pkt.len() < 40 || pkt[6] != IPPROTO_TCP {
                return None;
            }
            let src = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[8..24]).ok()?);
            let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[24..40]).ok()?);
            (40, IpAddr::V6(src), IpAddr::V6(dst))
        }
        _ => return None,
    };
    let tcp = pkt.get(ip_len..ip_len + 20)?;
    Some(Tcp {
        ip_len,
        src,
        dst,
        sport: u16::from_be_bytes([tcp[0], tcp[1]]),
        dport: u16::from_be_bytes([tcp[2], tcp[3]]),
        flags: tcp[13],
    })
}

/// Меняет местами адреса и ставит новые порты. Контрольные суммы после
/// этого пересчитывает вызывающий: у исходящих пакетов их часто считает
/// сетевая карта, и в перехваченном пакете они недействительны.
fn rewrite(pkt: &mut [u8], t: &Tcp, sport: u16, dport: u16) {
    let (a, b, n) = if t.ip_len == 40 { (8, 24, 16) } else { (12, 16, 4) };
    for i in 0..n {
        pkt.swap(a + i, b + i);
    }
    pkt[t.ip_len..t.ip_len + 2].copy_from_slice(&sport.to_be_bytes());
    pkt[t.ip_len + 2..t.ip_len + 4].copy_from_slice(&dport.to_be_bytes());
}

impl Nat {
    pub fn new(port: u16) -> Self {
        Nat { port, flows: HashMap::new(), last_purge: Instant::now() }
    }

    /// Решает судьбу пакета и при необходимости переписывает его.
    ///
    /// `redirect` спрашивается на SYN нового потока: перехватывать ли
    /// соединение с этого локального адреса и порта. Ответ «нет» должен
    /// быть и тогда, когда владельца узнать не удалось: ошибка в сторону
    /// перехвата замкнула бы прокси на самого себя.
    pub fn process(
        &mut self,
        pkt: &mut [u8],
        outbound: bool,
        now: Instant,
        redirect: impl FnOnce(IpAddr, u16) -> bool,
    ) -> Verdict {
        self.purge(now);
        let Some(t) = parse(pkt) else { return Verdict::Pass };

        if !outbound {
            // Входящее на порт слушателя снаружи. Слушатель открыт на всех
            // адресах, потому что развёрнутые пакеты приходят на адрес
            // сетевой карты, но из сети к нему подключаться не должны.
            // Свои развёрнутые пакеты сюда не попадают: WinDivert не отдаёт
            // обратно то, что сам же отправил.
            return if t.dport == self.port { Verdict::Drop } else { Verdict::Pass };
        }

        if t.sport == self.port {
            // Ответ слушателя `A:порт → B:p`. Разворачивается всегда, даже
            // без записи о потоке: подключиться к слушателю можно было только
            // через перехват, раз входящие снаружи выбрасываются.
            let key = FlowKey { local: t.src, local_port: t.dport, remote: t.dst };
            if let Some(flow) = self.flows.get_mut(&key) {
                flow.last_seen = now;
                if let State::Redirected { answered, fin_in, .. } = &mut flow.state {
                    *answered = true;
                    *fin_in |= t.flags & TCP_FIN != 0;
                }
                if t.flags & TCP_RST != 0 {
                    self.flows.remove(&key);
                }
            }
            rewrite(pkt, &t, HTTPS_PORT, t.dport);
            return Verdict::Reflect;
        }

        if t.dport != HTTPS_PORT {
            return Verdict::Pass;
        }

        let key = FlowKey { local: t.src, local_port: t.sport, remote: t.dst };
        let is_syn = t.flags & TCP_SYN != 0 && t.flags & TCP_ACK == 0;

        if is_syn {
            let known = self.flows.get(&key).map(|f| f.state);
            if let Some(State::Redirected { answered: false, .. }) = known {
                // Повтор SYN: слушатель на первый не ответил.
                self.flows.insert(key, Flow { state: State::Direct, last_seen: now });
                return Verdict::GaveUp;
            }
            if let Some(State::Direct) = known {
                return Verdict::Pass;
            }
            if !redirect(t.src, t.sport) {
                self.flows.remove(&key);
                return Verdict::Pass;
            }
            let state = State::Redirected { answered: false, fin_out: false, fin_in: false };
            self.flows.insert(key, Flow { state, last_seen: now });
        } else {
            let Some(flow) = self.flows.get_mut(&key) else { return Verdict::Pass };
            flow.last_seen = now;
            let State::Redirected { fin_out, .. } = &mut flow.state else { return Verdict::Pass };
            *fin_out |= t.flags & TCP_FIN != 0;
            if t.flags & TCP_RST != 0 {
                self.flows.remove(&key);
            }
        }

        rewrite(pkt, &t, t.sport, self.port);
        Verdict::Reflect
    }

    fn purge(&mut self, now: Instant) {
        if now.duration_since(self.last_purge) < PURGE_EVERY {
            return;
        }
        self.last_purge = now;
        self.flows.retain(|_, f| {
            let idle = now.duration_since(f.last_seen);
            let closed = matches!(f.state, State::Redirected { fin_out: true, fin_in: true, .. });
            idle < if closed { CLOSED_TTL } else { IDLE_TTL }
        });
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.flows.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PORT: u16 = 1083;
    const APP: [u8; 4] = [192, 168, 1, 10];
    const SERVER: [u8; 4] = [203, 0, 113, 5];

    fn v4(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, flags: u8) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&40u16.to_be_bytes());
        p[8] = 64;
        p[9] = IPPROTO_TCP;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p[32] = 5 << 4;
        p[33] = flags;
        p
    }

    fn v6(src: Ipv6Addr, dst: Ipv6Addr, sport: u16, dport: u16, flags: u8) -> Vec<u8> {
        let mut p = vec![0u8; 60];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&20u16.to_be_bytes());
        p[6] = IPPROTO_TCP;
        p[7] = 64;
        p[8..24].copy_from_slice(&src.octets());
        p[24..40].copy_from_slice(&dst.octets());
        p[40..42].copy_from_slice(&sport.to_be_bytes());
        p[42..44].copy_from_slice(&dport.to_be_bytes());
        p[52] = 5 << 4;
        p[53] = flags;
        p
    }

    fn addrs(p: &[u8]) -> (IpAddr, u16, IpAddr, u16) {
        let t = parse(p).unwrap();
        (t.src, t.sport, t.dst, t.dport)
    }

    fn ip(a: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(a))
    }

    /// Полный круг: SYN приложения уходит на слушатель, ответ слушателя
    /// приходит приложению от имени сервера.
    #[test]
    fn syn_goes_to_listener_and_reply_looks_like_server() {
        let mut nat = Nat::new(PORT);
        let now = Instant::now();

        let mut syn = v4(APP, SERVER, 50000, 443, TCP_SYN);
        assert_eq!(nat.process(&mut syn, true, now, |_, _| true), Verdict::Reflect);
        // Сервер виден слушателю как клиент, с портом приложения.
        assert_eq!(addrs(&syn), (ip(SERVER), 50000, ip(APP), PORT));

        let mut syn_ack = v4(APP, SERVER, PORT, 50000, TCP_SYN | TCP_ACK);
        assert_eq!(nat.process(&mut syn_ack, true, now, |_, _| panic!()), Verdict::Reflect);
        assert_eq!(addrs(&syn_ack), (ip(SERVER), 443, ip(APP), 50000));

        let mut data = v4(APP, SERVER, 50000, 443, TCP_ACK);
        assert_eq!(nat.process(&mut data, true, now, |_, _| panic!()), Verdict::Reflect);
        assert_eq!(addrs(&data), (ip(SERVER), 50000, ip(APP), PORT));
    }

    #[test]
    fn ipv6_is_rewritten_too() {
        let app: Ipv6Addr = "2001:db8::10".parse().unwrap();
        let server: Ipv6Addr = "2001:db8:ffff::5".parse().unwrap();
        let mut nat = Nat::new(PORT);
        let mut syn = v6(app, server, 50001, 443, TCP_SYN);
        assert_eq!(nat.process(&mut syn, true, Instant::now(), |_, _| true), Verdict::Reflect);
        assert_eq!(addrs(&syn), (IpAddr::V6(server), 50001, IpAddr::V6(app), PORT));
    }

    /// Соединения самого прокси и потоки, начатые до перехвата, идут как есть.
    #[test]
    fn own_and_preexisting_flows_pass() {
        let mut nat = Nat::new(PORT);
        let now = Instant::now();

        let mut own_syn = v4(APP, SERVER, 50002, 443, TCP_SYN);
        assert_eq!(nat.process(&mut own_syn, true, now, |_, _| false), Verdict::Pass);
        let mut own_data = v4(APP, SERVER, 50002, 443, TCP_ACK);
        assert_eq!(nat.process(&mut own_data, true, now, |_, _| panic!()), Verdict::Pass);
        assert_eq!(own_data, v4(APP, SERVER, 50002, 443, TCP_ACK), "пакет не должен меняться");

        let mut old = v4(APP, SERVER, 50003, 443, TCP_ACK);
        assert_eq!(nat.process(&mut old, true, now, |_, _| panic!()), Verdict::Pass);
        assert_eq!(nat.len(), 0);
    }

    #[test]
    fn inbound_to_listener_port_is_dropped() {
        let mut nat = Nat::new(PORT);
        let mut probe = v4(SERVER, APP, 40000, PORT, TCP_SYN);
        assert_eq!(nat.process(&mut probe, false, Instant::now(), |_, _| panic!()), Verdict::Drop);
    }

    /// Слушатель не ответил (брандмауэр): повтор SYN уходит к серверу,
    /// и дальше поток не перехватывается.
    #[test]
    fn unanswered_syn_falls_back_to_direct() {
        let mut nat = Nat::new(PORT);
        let now = Instant::now();
        let mut syn = v4(APP, SERVER, 50004, 443, TCP_SYN);
        assert_eq!(nat.process(&mut syn, true, now, |_, _| true), Verdict::Reflect);

        let mut retry = v4(APP, SERVER, 50004, 443, TCP_SYN);
        assert_eq!(nat.process(&mut retry, true, now, |_, _| panic!()), Verdict::GaveUp);
        assert_eq!(retry, v4(APP, SERVER, 50004, 443, TCP_SYN));

        let mut data = v4(APP, SERVER, 50004, 443, TCP_ACK);
        assert_eq!(nat.process(&mut data, true, now, |_, _| panic!()), Verdict::Pass);
    }

    #[test]
    fn closed_and_reset_flows_are_forgotten() {
        let mut nat = Nat::new(PORT);
        let start = Instant::now();

        let mut syn = v4(APP, SERVER, 50005, 443, TCP_SYN);
        nat.process(&mut syn, true, start, |_, _| true);
        let mut rst = v4(APP, SERVER, 50005, 443, TCP_RST | TCP_ACK);
        assert_eq!(nat.process(&mut rst, true, start, |_, _| panic!()), Verdict::Reflect);
        assert_eq!(nat.len(), 0);

        let mut syn = v4(APP, SERVER, 50006, 443, TCP_SYN);
        nat.process(&mut syn, true, start, |_, _| true);
        nat.process(&mut v4(APP, SERVER, PORT, 50006, TCP_SYN | TCP_ACK), true, start, |_, _| panic!());
        nat.process(&mut v4(APP, SERVER, 50006, 443, TCP_FIN | TCP_ACK), true, start, |_, _| panic!());
        nat.process(&mut v4(APP, SERVER, PORT, 50006, TCP_FIN | TCP_ACK), true, start, |_, _| panic!());
        assert_eq!(nat.len(), 1);

        // Любой пакет после паузы запускает уборку.
        let later = start + CLOSED_TTL + PURGE_EVERY;
        nat.process(&mut v4(APP, SERVER, 1, 80, TCP_ACK), true, later, |_, _| panic!());
        assert_eq!(nat.len(), 0);
    }

    #[test]
    fn fragments_and_other_ports_pass() {
        let mut nat = Nat::new(PORT);
        let now = Instant::now();
        let mut frag = v4(APP, SERVER, 50007, 443, TCP_SYN);
        frag[6] = 0x20; // More Fragments
        assert_eq!(nat.process(&mut frag, true, now, |_, _| panic!()), Verdict::Pass);

        let mut http = v4(APP, SERVER, 50008, 80, TCP_SYN);
        assert_eq!(nat.process(&mut http, true, now, |_, _| panic!()), Verdict::Pass);
    }
}
