//! Пакетный обход на Linux через NFQUEUE — как nfqws в zapret.
//!
//! На Windows пакеты отдаёт драйвер WinDivert (`crate::packet`), на Linux —
//! netfilter через очередь NFQUEUE. Движок общий: разбор и перезапись пакетов
//! живут в [`crate::packet::desync`], а этот модуль лишь подаёт им пакеты и
//! отправляет результат.
//!
//! # Чем Linux отличается от Windows
//!
//! Вердикт очереди умеет только пропустить или отбросить один пакет — добавить
//! новые через него нельзя. Поэтому получившиеся сегменты мы шлём сами через
//! raw-сокет, а оригинал в очереди дропаем. Raw-сокет уходит прямо на провод,
//! так что контрольные суммы IP и TCP приходится считать здесь: `desync` их
//! намеренно не трогает (на Windows это делает сетевая карта).
//!
//! Свои переотправленные пакеты помечаются [`MARK`] через `SO_MARK`, а правило
//! nftables/iptables эту метку исключает — иначе перехват зациклился бы на
//! собственных пакетах.
//!
//! # Область
//!
//! Пока IPv4: raw-сокет с `IP_HDRINCL` отдаёт заголовок сам только для v4.
//! Этого хватает, чтобы проверить seqovl на живом трафике; продуктовый путь
//! (полный [`crate::packet::tcp::Interceptor`] и `Env`) строится поверх.

use crate::bypass::needs_bypass;
use crate::bypass::packet_mode::Mark;
use crate::bypass::tls;
use crate::config::BypassParams;
use crate::dns::ip_cache::IpDomainCache;
use crate::engine::strategy::StrategyStore;
use crate::observability::logging::{log_t, LogLevel, LogSender};
use crate::proxy::adaptive::{self, Selected};
use crate::packet::desync::{self, Technique};
use crate::packet::nat::HTTPS_PORT;
use crate::packet::tcp::{Engine, Env, Outbound};
use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Метка на переотправленных пакетах. Правило очереди пропускает их мимо —
/// иначе мы бесконечно перехватывали бы собственные сегменты. Единый источник
/// значения — `crate::bypass::packet_mode`.
pub const MARK: u32 = crate::bypass::packet_mode::REINJECT_FWMARK;

/// Имя из белого списка ТСПУ, которым притворяется приманка seqovl.
pub const DECOY_SNI: &str = "www.google.com";

/// Номер очереди NFQUEUE. Тот же указывает правило nftables (`firewall.rs`).
pub const QUEUE_NUM: u16 = 0;

/// Один рантайм на процесс: очередь нельзя занять дважды. Перезапуск прокси
/// из интерфейса не поднимает второй цикл, а переиспользует работающий.
static RUNNING: AtomicBool = AtomicBool::new(false);

/// Стенд seqovl: перехватывает исходящие ClientHello в очереди `queue_num`,
/// кладёт перед ними полный поддельный ClientHello Google на номерах до начала
/// данных и переотправляет. Сервер отбрасывает приманку как уже принятое и
/// получает настоящий поток; ТСПУ видит в начале разрешённое имя.
///
/// Блокирующий цикл: NFQUEUE читается синхронно. Возвращается только при ошибке.
pub fn run_seqovl_stand(queue_num: u16) -> io::Result<()> {
    use nfq::{Queue, Verdict};

    // Приманка — полноценный ClientHello с разрешённым именем. Её длина и есть
    // overlap: весь поддельный ClientHello ложится перед настоящим.
    let decoy = tls::build_client_hello_sized(DECOY_SNI, 517);
    let overlap = decoy.len();

    let raw = open_raw_v4()?;
    let mut queue = Queue::open()?;
    queue.bind(queue_num)?;
    eprintln!("nfqueue: очередь {queue_num}, приманка {DECOY_SNI} ({overlap} Б), IPv4. Ctrl-C — выход.");

    loop {
        let mut msg = queue.recv()?;
        let verdict = match handle_seqovl(msg.get_payload(), &decoy, overlap, raw) {
            Ok(true) => Verdict::Drop,    // сегменты отправлены сами
            Ok(false) => Verdict::Accept, // не наш пакет — пропускаем
            Err(e) => {
                eprintln!("nfqueue: ошибка отправки, пропускаю пакет как есть: {e}");
                Verdict::Accept
            }
        };
        msg.set_verdict(verdict);
        queue.verdict(msg)?;
    }
}

/// `Ok(true)` — это исходящий ClientHello, seqovl применён и сегменты
/// отправлены (оригинал надо дропнуть). `Ok(false)` — пакет не наш.
fn handle_seqovl(pkt: &[u8], decoy: &[u8], overlap: usize, raw: RawFd) -> io::Result<bool> {
    let Some(t) = desync::parse(pkt) else { return Ok(false) };
    // Только IPv4: raw-сокет ниже отдаёт IP-заголовок сам лишь для v4.
    let std::net::IpAddr::V4(dst) = t.dst else { return Ok(false) };
    if t.dport != 443 {
        return Ok(false);
    }
    let payload = t.payload(pkt);
    // Настоящий ClientHello с открытым именем? Иначе не трогаем.
    let Some(sni) = tls::find_sni(payload) else { return Ok(false) };
    let name = String::from_utf8_lossy(&payload[sni.offset..sni.offset + sni.len]).into_owned();

    let pos = desync::split_pos(payload);
    let parts = desync::apply(pkt, &t, &Technique::Seqovl { pos, overlap, decoy: decoy.to_vec() });
    eprintln!("→ {name}: seqovl overlap={overlap} pos={pos}, сегментов {}", parts.len());

    for mut seg in parts {
        fixup_v4(&mut seg);
        send_v4(raw, &seg, dst)?;
    }
    Ok(true)
}

/// Raw-сокет IPv4 с собственным IP-заголовком (`IPPROTO_RAW` включает
/// `IP_HDRINCL`). Метка `SO_MARK` уводит наши пакеты мимо очереди.
pub fn open_raw_v4() -> io::Result<RawFd> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mark = MARK;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            std::ptr::addr_of!(mark).cast(),
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        let e = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(e);
    }
    Ok(fd)
}

/// Ставит соединению-пробе fwmark, по которой правило заворачивает её в
/// очередь несмотря на исключение группы прокси. Иначе проба ушла бы мимо
/// перехвата и мерила бы прямое соединение вместо техники.
pub fn set_probe_mark(fd: RawFd) -> io::Result<()> {
    let mark = crate::bypass::packet_mode::PROBE_FWMARK;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            std::ptr::addr_of!(mark).cast(),
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Отправляет готовый IPv4-пакет. Порт в адресе для raw-сокета игнорируется,
/// маршрут ядро выбирает по адресу назначения.
pub fn send_v4(raw: RawFd, pkt: &[u8], dst: Ipv4Addr) -> io::Result<()> {
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sa.sin_family = libc::AF_INET as libc::sa_family_t;
    // octets() уже в сетевом порядке — ровно то, что ждёт s_addr.
    sa.sin_addr.s_addr = u32::from_ne_bytes(dst.octets());
    let ret = unsafe {
        libc::sendto(
            raw,
            pkt.as_ptr().cast(),
            pkt.len(),
            0,
            std::ptr::addr_of!(sa).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Начало записи TLS с ClientHello: тип записи handshake (22), версия 3.x,
/// сообщение ClientHello (1). Те же байты проверяет фильтр WinDivert.
fn is_client_hello(payload: &[u8]) -> bool {
    payload.len() > 5 && payload[0] == 22 && payload[1] == 3 && payload[5] == 1
}

const IPPROTO_TCP: u16 = 6;

/// Пересчитывает контрольные суммы IP и TCP на месте. `desync` их не считает
/// (на Windows это делает сетевая карта), а raw-сокет шлёт пакет на провод как
/// есть, поэтому здесь они обязательны. Не-IPv4 пакет остаётся нетронутым.
pub fn fixup_v4(pkt: &mut [u8]) {
    if pkt.first().map(|b| b >> 4) != Some(4) {
        return;
    }
    let ihl = usize::from(pkt[0] & 0x0f) * 4;
    if pkt.len() < ihl + 20 {
        return;
    }
    // IP: сумма по заголовку.
    pkt[10] = 0;
    pkt[11] = 0;
    let ip_csum = checksum(&pkt[..ihl]);
    pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // TCP: псевдозаголовок (адреса, протокол, длина) плюс сам сегмент.
    pkt[ihl + 16] = 0;
    pkt[ihl + 17] = 0;
    let tcp_len = pkt.len() - ihl;
    let mut sum = ones_sum(&pkt[12..20]); // src + dst
    sum += u32::from(IPPROTO_TCP);
    sum += tcp_len as u32;
    sum += ones_sum(&pkt[ihl..]);
    let tcp_csum = fold(sum);
    pkt[ihl + 16..ihl + 18].copy_from_slice(&tcp_csum.to_be_bytes());
}

/// Сумма 16-битных слов без свёртки. Нечётный хвост дополняется нулём.
fn ones_sum(data: &[u8]) -> u32 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    if let [last] = chunks.remainder() {
        sum += u32::from(*last) << 8;
    }
    sum
}

/// Свёртка переносов и дополнение — итог интернет-контрольной суммы.
fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn checksum(data: &[u8]) -> u16 {
    fold(ones_sum(data))
}

// --- Продуктовый путь: общий движок поверх NFQUEUE -------------------------

/// Остальная программа для перехвата — Linux-двойник виндового `WinEnv`.
///
/// Поля те же (`WinEnv` живёт под `#[cfg(windows)]`, переиспользовать его здесь
/// нельзя), и стратегию выбирает тот же `adaptive`, так что автоподбор и файл
/// стратегий общие для обеих систем.
pub struct LinuxEnv {
    pub strategies: Arc<StrategyStore>,
    pub bypass_params: BypassParams,
    pub ttl_hours: u64,
    pub is_enabled: bool,
    pub bypass_domains: Arc<HashSet<String>>,
    pub ip_cache: Arc<IpDomainCache>,
    pub log_tx: LogSender,
}

impl LinuxEnv {
    fn adaptive(&self) -> adaptive::Context<'_> {
        adaptive::Context {
            strategies: &self.strategies,
            bypass_params: &self.bypass_params,
            ttl_hours: self.ttl_hours,
            log_tx: &self.log_tx,
        }
    }
}

impl Env for LinuxEnv {
    fn take_mark(&self, local_port: u16) -> Option<Mark> {
        crate::bypass::packet_mode::take(local_port)
    }
    fn is_blocked(&self, domain: &str) -> bool {
        crate::block::is_blocked(domain)
    }
    fn needs_bypass(&self, domain: &str) -> bool {
        needs_bypass(self.is_enabled, domain, &self.bypass_domains)
    }
    fn select(&self, domain: &str, hello_len: usize) -> Selected {
        // Стратегии измеряют сокетные пробы (общий StrategyStore), а пакетный
        // режим их только применяет. Поэтому `source` зануляется: движок
        // считает поток сразу решённым (Kind::Done) и не ждёт входящего ответа
        // для подтверждения — входящие мы намеренно не заворачиваем, чтобы не
        // гнать скачивание через userspace. Без этого поток завис бы в
        // Awaiting и по таймауту записал бы ложный провал.
        let mut selected = adaptive::select_packet(&self.adaptive(), domain, hello_len);
        selected.source = None;
        selected
    }
    fn record(&self, domain: &str, selected: Selected, responded: bool) {
        adaptive::record_outcome(&self.adaptive(), domain, selected, responded);
    }
    fn remember(&self, ip: IpAddr, domain: &str) {
        self.ip_cache.insert(ip, domain.to_string());
    }
    fn lookup(&self, ip: IpAddr) -> Option<String> {
        self.ip_cache.lookup(&ip)
    }
    fn decoy(&self, len: usize) -> Vec<u8> {
        tls::build_client_hello_sized(&self.bypass_params.fake_sni, len)
    }
    fn log_intercepted(&self, domain: &str, dst: IpAddr, bypass: bool) {
        log_t(&self.log_tx, LogLevel::Success, "log.transparent_tunnel", vec![
            ("domain", domain.to_string()),
            ("addr", SocketAddr::new(dst, HTTPS_PORT).to_string()),
            ("bypass", bypass.to_string()),
        ]);
    }
    fn log_applied(&self, domain: &str, detail: &str) {
        log_t(&self.log_tx, LogLevel::Warning, "log.transparent_applied", vec![
            ("domain", domain.to_string()),
            ("detail", detail.to_string()),
        ]);
    }
    fn log_blocked(&self, domain: &str) {
        log_t(&self.log_tx, LogLevel::Info, "log.blocked", vec![
            ("domain", domain.to_string()),
            ("via", "SNI".to_string()),
        ]);
    }
}

/// Что сделать с оригиналом в очереди после обработки.
#[derive(Debug, PartialEq, Eq)]
pub enum Disposition {
    /// Пропустить как есть (ответ сервера или не наш пакет).
    Accept,
    /// Отбросить: вместо него мы уже отправили переписанные пакеты.
    Drop,
}

/// Отправитель переписанных пакетов. В бою — raw-сокет, в тестах — буфер.
pub trait Injector {
    fn send(&self, pkt: &[u8]) -> io::Result<()>;
}

/// Отправка через raw-сокет IPv4. Адрес назначения берётся из самого пакета.
pub struct RawInjector {
    fd: RawFd,
}

impl RawInjector {
    pub fn new() -> io::Result<Self> {
        Ok(Self { fd: open_raw_v4()? })
    }
}

impl Injector for RawInjector {
    fn send(&self, pkt: &[u8]) -> io::Result<()> {
        if pkt.len() < 20 {
            return Ok(());
        }
        let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
        send_v4(self.fd, pkt, dst)
    }
}

impl Drop for RawInjector {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

/// Прогоняет один пакет из очереди через общий движок — Linux-двойник тела
/// виндового `run_tcp`. Переписанные пакеты уходят через `inj`, а вердикт для
/// оригинала возвращается вызывающему.
///
/// Направление берётся из порта: к 443 — исходящий ClientHello (движок решает
/// технику и отдаёт сегменты), от 443 — ответ сервера (движку для учёта
/// стратегии, сам пакет не меняется).
pub fn process<E: Env, I: Injector>(
    pkt: &[u8],
    engine: &mut Engine,
    env: &E,
    inj: &I,
    now: Instant,
) -> io::Result<Disposition> {
    let Some(t) = desync::parse(pkt) else { return Ok(Disposition::Accept) };
    if t.dport == HTTPS_PORT {
        // Только ClientHello, как фильтр WinDivert (tcp.Payload[0]==22, [1]==3,
        // [5]==1). Правило nft ловит все PSH+ACK на 443, поэтому сузим здесь:
        // иначе движок переписывал бы и каждый последующий пакет данных
        // (аплоады) — впустую гоняя их через userspace и (для seqovl) добавляя
        // приманку к каждому. Поток уже известен, и `outbound` повторил бы
        // технику. Повтор самого ClientHello (ретрансмит) проверку проходит.
        if !is_client_hello(t.payload(pkt)) {
            return Ok(Disposition::Accept);
        }
        match engine.outbound(pkt, now, env) {
            Outbound::Send(parts) => {
                for mut p in parts {
                    fixup_v4(&mut p);
                    inj.send(&p)?;
                }
                Ok(Disposition::Drop)
            }
            Outbound::Reset(mut rst) => {
                // Сброс приложению: адреса в пакете уже развёрнуты на локальный,
                // raw-сокет доставит его в местный стек.
                fixup_v4(&mut rst);
                inj.send(&rst)?;
                Ok(Disposition::Drop)
            }
        }
    } else if t.sport == HTTPS_PORT {
        engine.inbound(pkt, now, env);
        Ok(Disposition::Accept)
    } else {
        Ok(Disposition::Accept)
    }
}

/// Продуктовый цикл: гоняет полный `Engine` с автоподбором на очереди
/// `queue_num`. Блокирующий; возвращается только при ошибке очереди.
///
/// Правило заворачивает только исходящие 443 (кроме пакетов с меткой [`MARK`]):
/// этого хватает, чтобы применить технику. Входящие движок обрабатывать умеет
/// (`process` → `Engine::inbound`), но `LinuxEnv::select` зануляет `source`,
/// так что поток сразу помечается решённым и ответа сервера не ждёт — учёт
/// стратегий идёт по сокетным пробам, а не отсюда. Выбор стратегии запускает
/// диагностику на tokio, поэтому цикл должен работать внутри рантайма
/// (`Handle::enter` у вызывающего).
pub fn run(queue_num: u16, env: LinuxEnv) -> io::Result<()> {
    use nfq::{Queue, Verdict};

    // Инициализация ДО захвата флага: если raw-сокет или очередь не поднялись,
    // флаг не должен остаться взведённым — иначе повторный старт (перезапуск
    // прокси) молча ничего не сделает, и пакетный режим уже не включить.
    let inj = RawInjector::new()?;
    let mut queue = Queue::open()?;
    queue.bind(queue_num)?;
    if RUNNING.swap(true, Ordering::SeqCst) {
        return Ok(()); // уже работает — повторный старт не нужен
    }
    let mut engine = Engine::new();
    // Соединения прокси и пробы диагностики должны помечаться с первого же
    // ClientHello — как и на Windows перед стартом потоков перехвата.
    crate::bypass::packet_mode::set_active(true);

    let result = (|| -> io::Result<()> {
        loop {
            let mut msg = queue.recv()?;
            let now = Instant::now();
            let verdict = match process(msg.get_payload(), &mut engine, &env, &inj, now) {
                Ok(Disposition::Drop) => Verdict::Drop,
                Ok(Disposition::Accept) => Verdict::Accept,
                Err(e) => {
                    eprintln!("nfqueue: ошибка обработки, пропускаю пакет: {e}");
                    Verdict::Accept
                }
            };
            msg.set_verdict(verdict);
            queue.verdict(msg)?;
        }
    })();

    // Сюда попадаем только при ошибке очереди. Снимаем флаги, чтобы перезапуск
    // прокси мог поднять пакетный режим заново, а сокетный путь снова считал
    // себя главным (is_active → false включает его freeze-эскалацию).
    RUNNING.store(false, Ordering::SeqCst);
    crate::bypass::packet_mode::set_active(false);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Контрольная сумма правильного пакета, посчитанная заново, сходится к
    /// нулю: признак того, что fixup кладёт верные значения.
    fn verifies(pkt: &[u8]) -> bool {
        let ihl = usize::from(pkt[0] & 0x0f) * 4;
        if checksum(&pkt[..ihl]) != 0 {
            return false;
        }
        let tcp_len = pkt.len() - ihl;
        let mut sum = ones_sum(&pkt[12..20]);
        sum += u32::from(IPPROTO_TCP);
        sum += tcp_len as u32;
        sum += ones_sum(&pkt[ihl..]);
        fold(sum) == 0
    }

    fn v4_tcp(payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 20 + 20];
        p[0] = 0x45;
        p[9] = IPPROTO_TCP as u8;
        p[12..16].copy_from_slice(&[192, 168, 1, 10]);
        p[16..20].copy_from_slice(&[162, 159, 0, 1]);
        p[20..22].copy_from_slice(&50000u16.to_be_bytes());
        p[22..24].copy_from_slice(&443u16.to_be_bytes());
        p[24..28].copy_from_slice(&1000u32.to_be_bytes());
        p[32] = 5 << 4;
        p[33] = 0x18; // PSH+ACK
        p.extend_from_slice(payload);
        let len = p.len() as u16;
        p[2..4].copy_from_slice(&len.to_be_bytes());
        p
    }

    #[test]
    fn fixup_produces_checksums_that_verify() {
        let mut p = v4_tcp(b"hello");
        // Стереть суммы, как будто пакет пришёл от desync.
        p[10] = 0xff;
        p[11] = 0xff;
        fixup_v4(&mut p);
        assert!(verifies(&p));
    }

    #[test]
    fn seqovl_segments_all_verify_after_fixup() {
        let hello = tls::build_client_hello_sized("discord.com", 517);
        let p = v4_tcp(&hello);
        let t = desync::parse(&p).unwrap();
        let decoy = tls::build_client_hello_sized(DECOY_SNI, 517);
        let pos = desync::split_pos(t.payload(&p));
        let parts = desync::apply(&p, &t, &Technique::Seqovl { pos, overlap: decoy.len(), decoy });
        for mut seg in parts {
            fixup_v4(&mut seg);
            assert!(verifies(&seg), "сегмент с верными суммами");
        }
    }

    #[test]
    fn non_ipv4_is_left_untouched() {
        let mut p = vec![0x60u8; 40]; // IPv6-версия в старшем полубайте
        let before = p.clone();
        fixup_v4(&mut p);
        assert_eq!(p, before);
    }

    // --- Продуктовый путь -------------------------------------------------

    /// Env без обхода: движок пропускает ClientHello как есть (техника Pass).
    /// Хватает, чтобы проверить направление и вердикты `process`.
    struct FakeEnv;
    impl Env for FakeEnv {
        fn take_mark(&self, _: u16) -> Option<Mark> {
            None
        }
        fn is_blocked(&self, _: &str) -> bool {
            false
        }
        fn needs_bypass(&self, _: &str) -> bool {
            false
        }
        fn select(&self, _: &str, _: usize) -> Selected {
            Selected::DIRECT
        }
        fn record(&self, _: &str, _: Selected, _: bool) {}
        fn remember(&self, _: IpAddr, _: &str) {}
        fn lookup(&self, _: IpAddr) -> Option<String> {
            None
        }
        fn decoy(&self, len: usize) -> Vec<u8> {
            vec![0; len]
        }
        fn log_intercepted(&self, _: &str, _: IpAddr, _: bool) {}
        fn log_applied(&self, _: &str, _: &str) {}
        fn log_blocked(&self, _: &str) {}
    }

    struct VecInjector(std::cell::RefCell<Vec<Vec<u8>>>);
    impl Injector for VecInjector {
        fn send(&self, pkt: &[u8]) -> io::Result<()> {
            self.0.borrow_mut().push(pkt.to_vec());
            Ok(())
        }
    }

    #[test]
    fn outbound_client_hello_is_dropped_and_reinjected_with_valid_sums() {
        let hello = tls::build_client_hello_sized("discord.com", 517);
        let pkt = v4_tcp(&hello); // dport 443 — исходящий
        let mut engine = Engine::new();
        let inj = VecInjector(std::cell::RefCell::new(Vec::new()));
        let disp = process(&pkt, &mut engine, &FakeEnv, &inj, Instant::now()).unwrap();
        assert_eq!(disp, Disposition::Drop);
        let sent = inj.0.borrow();
        assert_eq!(sent.len(), 1, "без обхода — один пакет");
        assert!(verifies(&sent[0]), "переотправленный пакет с верными суммами");
    }

    #[test]
    fn outbound_non_client_hello_data_is_passed_through_not_rewritten() {
        // Пакет данных к 443, но не ClientHello (аплоад в середине потока):
        // правило nft его ловит, а движок не должен его трогать.
        let pkt = v4_tcp(b"POST /upload payload bytes, not a TLS ClientHello");
        let mut engine = Engine::new();
        let inj = VecInjector(std::cell::RefCell::new(Vec::new()));
        let disp = process(&pkt, &mut engine, &FakeEnv, &inj, Instant::now()).unwrap();
        assert_eq!(disp, Disposition::Accept, "не ClientHello — пропускаем как есть");
        assert!(inj.0.borrow().is_empty(), "ничего не переотправляем");
    }

    #[test]
    fn inbound_from_server_is_accepted_and_not_injected() {
        let mut p = v4_tcp(b"server-data");
        p[20..22].copy_from_slice(&443u16.to_be_bytes()); // sport = 443 — входящий
        p[22..24].copy_from_slice(&50000u16.to_be_bytes());
        let mut engine = Engine::new();
        let inj = VecInjector(std::cell::RefCell::new(Vec::new()));
        let disp = process(&p, &mut engine, &FakeEnv, &inj, Instant::now()).unwrap();
        assert_eq!(disp, Disposition::Accept);
        assert!(inj.0.borrow().is_empty(), "ответ сервера не переотправляется");
    }
}
