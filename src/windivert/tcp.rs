//! Решения перехвата TCP в Windows: что делать с ClientHello и как
//! засчитывать ответ сервера.
//!
//! Через программу идут только пакеты, которые пропускает [`filter`]:
//! начало ClientHello, первый ответ сервера (ServerHello, alert) и сброс.
//! Всё остальное соединение остаётся в ядре — в этом и смысл: раньше
//! каждый пакет каждого HTTPS-соединения шёл через программу, и под
//! нагрузкой пинг вырастал в разы.
//!
//! Логика отделена от драйвера через [`Env`], чтобы проверять её тестами
//! на любой системе.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use super::desync::{self, Technique, Tcp, TCP_RST};
use crate::bypass::packet_mode::Mark;
use crate::engine::strategy::Strategy;
use crate::proxy::adaptive::Selected;

pub const HTTPS_PORT: u16 = 443;

/// Сколько ждать ответа сервера на ClientHello, прежде чем засчитать
/// стратегии провал. Больше таймаута пробы: в бою бывают медленные сети.
const REPLY_TIMEOUT: Duration = Duration::from_secs(10);
/// Сколько помнить поток: повторная отправка ClientHello (сервер не
/// подтвердил) должна получить ту же технику, а не новое решение.
const FLOW_TTL: Duration = Duration::from_secs(120);
const PURGE_EVERY: Duration = Duration::from_secs(5);

/// Фильтр WinDivert для TCP.
///
/// * Исходящее на 443 с началом ClientHello: запись handshake (22),
///   версия 3.x, сообщение ClientHello (1).
/// * Входящее с 443: сброс или начало записи handshake/alert — первый
///   ответ сервера, по нему проверяется стратегия. Данные приложения
///   идут записями типа 23 и сюда не попадают.
/// * Входящее снаружи на порт слушателя — выбрасывается: слушатель открыт
///   на всех адресах.
/// * Если задан ретранслятор Telegram — соединения к сетям Telegram
///   целиком и ответы слушателя: их по-прежнему разворачивает [`super::nat`].
pub fn filter(port: u16, telegram: Option<&[(Ipv4Addr, u8)]>) -> String {
    let mut parts = vec![
        format!(
            "(outbound and tcp.DstPort == {HTTPS_PORT} and tcp.PayloadLength > 5 \
             and tcp.Payload[0] == 22 and tcp.Payload[1] == 3 and tcp.Payload[5] == 1)"
        ),
        format!(
            "(inbound and tcp.SrcPort == {HTTPS_PORT} and (tcp.Rst or (tcp.PayloadLength > 1 \
             and (tcp.Payload[0] == 22 or tcp.Payload[0] == 21) and tcp.Payload[1] == 3)))"
        ),
        format!("(inbound and tcp.DstPort == {port})"),
    ];
    if let Some(nets) = telegram {
        let nets = nets
            .iter()
            .map(|(ip, bits)| {
                let (a, b) = super::udp::range(*ip, *bits);
                format!("(ip.DstAddr >= {a} and ip.DstAddr <= {b})")
            })
            .collect::<Vec<_>>()
            .join(" or ");
        parts.push(format!("(outbound and tcp.SrcPort == {port})"));
        parts.push(format!("(outbound and tcp.DstPort == {HTTPS_PORT} and ip and ({nets}))"));
    }
    format!("!loopback and tcp and ({})", parts.join(" or "))
}

/// Всё, что перехвату нужно от остальной программы.
pub trait Env {
    fn take_mark(&self, local_port: u16) -> Option<Mark>;
    fn is_blocked(&self, domain: &str) -> bool;
    fn needs_bypass(&self, domain: &str) -> bool;
    fn select(&self, domain: &str, hello_len: usize) -> Selected;
    fn record(&self, domain: &str, selected: Selected, responded: bool);
    fn remember(&self, ip: IpAddr, domain: &str);
    fn lookup(&self, ip: IpAddr) -> Option<String>;
    fn decoy(&self, len: usize) -> Vec<u8>;
    fn log_intercepted(&self, domain: &str, dst: IpAddr, bypass: bool);
    fn log_applied(&self, domain: &str, detail: &str);
    fn log_blocked(&self, domain: &str);
}

/// Что отправить вместо перехваченного исходящего пакета.
#[derive(Debug, PartialEq, Eq)]
pub enum Outbound {
    /// Эти пакеты в этом порядке, исходящими.
    Send(Vec<Vec<u8>>),
    /// Выбросить пакет и сбросить соединение: этот пакет уходит
    /// приложению входящим.
    Reset(Vec<u8>),
}

/// Поток со стороны приложения: `A:p → B:443`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Key {
    local: IpAddr,
    local_port: u16,
    remote: IpAddr,
}

#[derive(Debug)]
enum Kind {
    /// Соединение самой программы: не трогать.
    Own,
    /// Проба диагностики или поток без обхода — только техника.
    Plain,
    /// Поток с обходом: ждём ответа сервера, чтобы засчитать стратегию.
    Awaiting { domain: String, selected: Selected, sent: Instant },
    /// Ответ получен или засчитывать нечего.
    Done,
}

struct Flow {
    kind: Kind,
    technique: Technique,
    seen: Instant,
}

#[derive(Default)]
pub struct Engine {
    flows: HashMap<Key, Flow>,
    last_purge: Option<Instant>,
}

impl Engine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Исходящий пакет, прошедший фильтр: начало ClientHello.
    pub fn outbound(&mut self, pkt: &[u8], now: Instant, env: &impl Env) -> Outbound {
        self.purge(now, env);
        let Some(t) = desync::parse(pkt) else { return Outbound::Send(vec![pkt.to_vec()]) };
        let key = Key { local: t.src, local_port: t.sport, remote: t.dst };

        // Повтор ClientHello: сервер не подтвердил первый. Та же техника,
        // без нового решения и строки в логе.
        if let Some(flow) = self.flows.get_mut(&key) {
            flow.seen = now;
            return Outbound::Send(desync::apply(pkt, &t, &flow.technique));
        }

        let payload = t.payload(pkt);
        let (kind, technique) = match env.take_mark(t.sport) {
            Some(Mark::Own) => (Kind::Own, Technique::Pass),
            Some(Mark::Probe(strategy)) => (Kind::Plain, technique_for(strategy, payload, env)),
            None => match self.decide(pkt, &t, now, env) {
                Ok(decided) => decided,
                Err(reset) => return reset,
            },
        };
        let packets = desync::apply(pkt, &t, &technique);
        self.flows.insert(key, Flow { kind, technique, seen: now });
        Outbound::Send(packets)
    }

    /// Решение для ClientHello чужой программы. `Err` — трекер: сбросить.
    fn decide(&self, pkt: &[u8], t: &Tcp, now: Instant, env: &impl Env) -> Result<(Kind, Technique), Outbound> {
        let payload = t.payload(pkt);
        let sni = crate::bypass::tls::sni_host_prefix(payload);
        if let Some(host) = &sni {
            // Для QUIC к тому же адресу: там имя зашифровано.
            env.remember(t.dst, host);
            // Сброс, а не молчание: приложение сразу видит отказ и не ждёт
            // таймаута. До сервера ClientHello не доходит.
            if env.is_blocked(host) {
                env.log_blocked(host);
                return Err(Outbound::Reset(desync::reset_for(pkt, t)));
            }
        }
        let domain = sni
            .or_else(|| env.lookup(t.dst))
            .unwrap_or_else(|| t.dst.to_string());

        let bypass = env.needs_bypass(&domain);
        env.log_intercepted(&domain, t.dst, bypass);
        if !bypass {
            return Ok((Kind::Done, Technique::Pass));
        }

        // Размер — всей записи из заголовка, а не сегмента: по нему
        // выбирается класс стратегии, как у прокси.
        let hello_len = crate::bypass::tls::record_len(payload).unwrap_or(payload.len());
        let selected = env.select(&domain, hello_len);
        let technique = technique_for(selected.strategy, payload, env);
        if let Some(detail) = describe(&technique, payload.len()) {
            env.log_applied(&domain, &detail);
        }
        let kind = if selected.source.is_some() {
            Kind::Awaiting { domain, selected, sent: now }
        } else {
            Kind::Done
        };
        Ok((kind, technique))
    }

    /// Входящий пакет с 443, прошедший фильтр. Сам пакет вызывающий
    /// отправляет дальше без изменений.
    pub fn inbound(&mut self, pkt: &[u8], now: Instant, env: &impl Env) {
        self.purge(now, env);
        let Some(t) = desync::parse(pkt) else { return };
        let key = Key { local: t.dst, local_port: t.dport, remote: t.src };
        let rst = t.flags & TCP_RST != 0;
        let Some(flow) = self.flows.get_mut(&key) else { return };
        if let Kind::Awaiting { domain, selected, .. } = &flow.kind {
            // Сброс в ответ на ClientHello и alert о повреждённых данных —
            // провал техники, любой другой ответ — успех.
            let responded = !rst && crate::bypass::tls::server_accepted(t.payload(pkt));
            env.record(domain, *selected, responded);
            flow.kind = Kind::Done;
        }
        if rst {
            self.flows.remove(&key);
        }
    }

    fn purge(&mut self, now: Instant, env: &impl Env) {
        if self.last_purge.is_some_and(|at| now.duration_since(at) < PURGE_EVERY) {
            return;
        }
        self.last_purge = Some(now);
        for flow in self.flows.values_mut() {
            if let Kind::Awaiting { domain, selected, sent } = &flow.kind
                && now.duration_since(*sent) >= REPLY_TIMEOUT
            {
                env.record(domain, *selected, false);
                flow.kind = Kind::Done;
            }
        }
        self.flows.retain(|_, f| now.duration_since(f.seen) < FLOW_TTL);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.flows.len()
    }
}

/// Техника на пакетах для выбранной стратегии.
///
/// Две TLS-записи и OOB сюда попадают только из пробы, которая меряет их
/// по ошибке: перехват их не умеет (см. `packet_mode::supports`), и вместо
/// них уходит обычный сплит.
fn technique_for(strategy: Strategy, payload: &[u8], env: &impl Env) -> Technique {
    let pos = desync::split_pos(payload);
    match strategy {
        Strategy::None => Technique::Pass,
        Strategy::SniSplit | Strategy::TlsRecord | Strategy::Oob => Technique::Split { pos },
        Strategy::Disorder => Technique::Disorder { pos },
        Strategy::Fake => Technique::Fake { pos, decoy: env.decoy(payload.len()) },
    }
}

/// Строка для лога: что сделано с ClientHello.
fn describe(technique: &Technique, len: usize) -> Option<String> {
    match technique {
        Technique::Pass => None,
        Technique::Split { pos } => Some(format!("split {}+{}", pos, len - pos)),
        Technique::Disorder { pos } => Some(format!("disorder {}+{}", pos, len - pos)),
        Technique::Fake { pos, decoy } => Some(format!("fake {}+{}+{}", decoy.len(), pos, len - pos)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::strategy::HelloClass;
    use std::cell::RefCell;

    #[derive(Default)]
    struct FakeEnv {
        marks: RefCell<HashMap<u16, Mark>>,
        strategy: Option<Strategy>,
        blocked: bool,
        records: RefCell<Vec<bool>>,
        remembered: RefCell<Vec<String>>,
    }

    impl Env for FakeEnv {
        fn take_mark(&self, port: u16) -> Option<Mark> {
            self.marks.borrow_mut().remove(&port)
        }
        fn is_blocked(&self, _: &str) -> bool {
            self.blocked
        }
        fn needs_bypass(&self, _: &str) -> bool {
            self.strategy.is_some()
        }
        fn select(&self, _: &str, _: usize) -> Selected {
            Selected { strategy: self.strategy.unwrap(), source: Some(HelloClass::Small) }
        }
        fn record(&self, _: &str, _: Selected, responded: bool) {
            self.records.borrow_mut().push(responded);
        }
        fn remember(&self, _: IpAddr, domain: &str) {
            self.remembered.borrow_mut().push(domain.to_string());
        }
        fn lookup(&self, _: IpAddr) -> Option<String> {
            None
        }
        fn decoy(&self, len: usize) -> Vec<u8> {
            crate::bypass::tls::build_client_hello_sized("www.google.com", len)
        }
        fn log_intercepted(&self, _: &str, _: IpAddr, _: bool) {}
        fn log_applied(&self, _: &str, _: &str) {}
        fn log_blocked(&self, _: &str) {}
    }

    const APP: [u8; 4] = [192, 168, 1, 10];
    const SERVER: [u8; 4] = [203, 0, 113, 5];

    fn packet(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x45;
        p[8] = 64;
        p[9] = 6;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p[24..28].copy_from_slice(&5000u32.to_be_bytes());
        p[32] = 5 << 4;
        p[33] = flags;
        p.extend_from_slice(payload);
        let len = p.len() as u16;
        p[2..4].copy_from_slice(&len.to_be_bytes());
        p
    }

    fn hello(port: u16) -> Vec<u8> {
        let hello = crate::bypass::tls::build_client_hello_sized("discord.com", 517);
        packet(APP, SERVER, port, 443, 0x18, &hello)
    }

    fn reply(port: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
        packet(SERVER, APP, 443, port, flags, payload)
    }

    fn sent(out: Outbound) -> Vec<Vec<u8>> {
        match out {
            Outbound::Send(p) => p,
            Outbound::Reset(_) => panic!("ожидалась отправка"),
        }
    }

    #[test]
    fn bypassed_hello_is_split_and_server_hello_counts_as_success() {
        let env = FakeEnv { strategy: Some(Strategy::Disorder), ..Default::default() };
        let mut engine = Engine::new();
        let now = Instant::now();
        let pkt = hello(50000);
        let parts = sent(engine.outbound(&pkt, now, &env));
        assert_eq!(parts.len(), 2, "disorder: две части");
        assert_eq!(env.remembered.borrow().as_slice(), ["discord.com"]);

        engine.inbound(&reply(50000, 0x18, &[0x16, 0x03, 0x03, 0x00, 0x7a, 0x02]), now, &env);
        assert_eq!(env.records.borrow().as_slice(), [true]);
        // Второй ответ того же потока уже ничего не засчитывает.
        engine.inbound(&reply(50000, 0x18, &[0x16, 0x03, 0x03, 0x00, 0x7a, 0x0b]), now, &env);
        assert_eq!(env.records.borrow().len(), 1);
    }

    #[test]
    fn corruption_alert_reset_and_silence_count_as_failure() {
        let env = FakeEnv { strategy: Some(Strategy::SniSplit), ..Default::default() };
        let mut engine = Engine::new();
        let now = Instant::now();

        engine.outbound(&hello(50001), now, &env);
        engine.inbound(&reply(50001, 0x18, &[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 50]), now, &env);

        engine.outbound(&hello(50002), now, &env);
        engine.inbound(&reply(50002, TCP_RST | 0x10, &[]), now, &env);

        engine.outbound(&hello(50003), now, &env);
        engine.inbound(&[0u8; 3], now + REPLY_TIMEOUT, &env);
        assert_eq!(env.records.borrow().as_slice(), [false, false, false]);
    }

    #[test]
    fn retransmitted_hello_gets_the_same_technique_without_a_new_decision() {
        let env = FakeEnv { strategy: Some(Strategy::SniSplit), ..Default::default() };
        let mut engine = Engine::new();
        let now = Instant::now();
        let pkt = hello(50004);
        let first = sent(engine.outbound(&pkt, now, &env));
        let again = sent(engine.outbound(&pkt, now, &env));
        assert_eq!(first, again);
        assert_eq!(env.remembered.borrow().len(), 1, "решение принято один раз");
    }

    #[test]
    fn own_connections_pass_untouched_and_probes_get_their_technique() {
        let env = FakeEnv { strategy: Some(Strategy::Disorder), ..Default::default() };
        env.marks.borrow_mut().insert(50005, Mark::Own);
        env.marks.borrow_mut().insert(50006, Mark::Probe(Strategy::Fake));
        let mut engine = Engine::new();
        let now = Instant::now();

        let own = hello(50005);
        assert_eq!(sent(engine.outbound(&own, now, &env)), vec![own.clone()]);
        // И повтор тоже: метка уже забрана, но поток запомнен.
        assert_eq!(sent(engine.outbound(&own, now, &env)), vec![own]);

        assert_eq!(sent(engine.outbound(&hello(50006), now, &env)).len(), 3, "fake: подделка и две части");
        engine.inbound(&reply(50006, 0x18, &[0x16, 0x03, 0x03, 0x00, 0x7a, 0x02]), now, &env);
        assert!(env.records.borrow().is_empty(), "пробы в бой не засчитываются");
    }

    #[test]
    fn tracker_is_reset_before_reaching_the_server() {
        let env = FakeEnv { strategy: Some(Strategy::SniSplit), blocked: true, ..Default::default() };
        let mut engine = Engine::new();
        match engine.outbound(&hello(50007), Instant::now(), &env) {
            Outbound::Reset(rst) => {
                let r = desync::parse(&rst).unwrap();
                assert_eq!((r.sport, r.dport), (443, 50007));
            }
            other => panic!("ожидался сброс, а не {other:?}"),
        }
    }

    #[test]
    fn unlisted_domain_passes_as_is() {
        let env = FakeEnv::default();
        let mut engine = Engine::new();
        let pkt = hello(50008);
        assert_eq!(sent(engine.outbound(&pkt, Instant::now(), &env)), vec![pkt]);
    }

    #[test]
    fn old_flows_are_forgotten() {
        let env = FakeEnv::default();
        let mut engine = Engine::new();
        let start = Instant::now();
        engine.outbound(&hello(50009), start, &env);
        assert_eq!(engine.len(), 1);
        engine.inbound(&[0u8; 3], start + FLOW_TTL, &env);
        assert_eq!(engine.len(), 0);
    }

    #[test]
    fn filter_mentions_telegram_only_with_a_relay() {
        let without = filter(1083, None);
        assert!(without.contains("tcp.Payload[5] == 1"));
        assert!(!without.contains("SrcPort == 1083"));
        let nets = [(Ipv4Addr::new(149, 154, 160, 0), 20)];
        let with = filter(1083, Some(&nets));
        assert!(with.contains("tcp.SrcPort == 1083"));
        assert!(with.contains("149.154.160.0"));
    }
}
