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
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use crate::observability::metrics::Metrics;

/// Метка на переотправленных пакетах. Правило очереди пропускает их мимо —
/// иначе мы бесконечно перехватывали бы собственные сегменты. Единый источник
/// значения — `crate::bypass::packet_mode`.
pub const MARK: u32 = crate::bypass::packet_mode::REINJECT_FWMARK;

/// Имя из белого списка ТСПУ, которым притворяется приманка seqovl.
pub const DECOY_SNI: &str = "www.google.com";

/// Номер очереди NFQUEUE. Тот же указывает правило nftables (`firewall.rs`).
pub const QUEUE_NUM: u16 = 0;

/// Состояние цикла очереди — всё под одним замком.
///
/// Цикл один на процесс (очередь нельзя занять дважды) и живёт до его конца:
/// у NFQUEUE нет чистой отмены. Перезапуск прокси подменяет циклу настройки,
/// остановка снимает их, и без них пакеты идут как есть.
///
/// Флаг «пакетный режим активен» (`packet_mode::is_active`) и индикатор
/// «слушает» выводятся отсюда же, в [`Loop::sync`], а не выставляются из
/// разных мест. Раньше их меняли четыре места без общей синхронизации, и флаг
/// мог остаться `true` без работающего цикла: сокетный путь выключал защиту
/// от заморозки, а пробы диагностики получали метки впустую — ложный
/// «ничего не помогло».
struct Loop {
    /// Поток цикла запущен (возможно, ещё занимает очередь).
    running: bool,
    /// Очередь занята, пакеты идут через цикл.
    bound: bool,
    /// Настройки и номер их установки.
    env: Option<(u64, Arc<LinuxEnv>)>,
    generation: u64,
    /// Установка, о которой уже сказано «слушает».
    announced: Option<u64>,
}

static LOOP: Mutex<Loop> = Mutex::new(Loop { running: false, bound: false, env: None, generation: 0, announced: None });

fn state() -> MutexGuard<'static, Loop> {
    LOOP.lock().unwrap_or_else(|e| e.into_inner())
}

impl Loop {
    /// Сводит флаг активности и индикатор «слушает» с состоянием.
    fn sync(&mut self) {
        crate::bypass::packet_mode::set_active(self.bound && self.env.is_some());
        match &self.env {
            Some((generation, env)) if self.bound => {
                if self.announced != Some(*generation) {
                    self.announced = Some(*generation);
                    env.metrics.set_transparent_listening(true);
                    log_t(&env.log_tx, LogLevel::Success, "log.transparent_listening", vec![
                        ("addr", format!("nfqueue:{QUEUE_NUM}")),
                    ]);
                }
            }
            Some((_, env)) => {
                env.metrics.set_transparent_listening(false);
                self.announced = None;
            }
            None => self.announced = None,
        }
    }
}

/// Ставит настройки цикла; номер — для [`uninstall`].
pub fn install(env: LinuxEnv) -> u64 {
    let mut s = state();
    s.generation += 1;
    let generation = s.generation;
    s.env = Some((generation, Arc::new(env)));
    s.sync();
    generation
}

/// Снимает настройки, если их не успел подменить следующий старт.
pub fn uninstall(generation: u64) {
    let mut s = state();
    if s.env.as_ref().is_some_and(|(g, _)| *g == generation) {
        if let Some((_, env)) = s.env.take() {
            env.metrics.set_transparent_listening(false);
        }
        s.sync();
    }
}

fn current_env() -> Option<(u64, Arc<LinuxEnv>)> {
    state().env.as_ref().map(|(g, env)| (*g, Arc::clone(env)))
}

/// Ошибка цикла — в лог программы, а не только в stderr: в интерфейсе
/// stderr не видно, и причина, по которой обход перестал работать, терялась.
fn log_error(error: &io::Error) {
    match current_env() {
        Some((_, env)) => log_t(&env.log_tx, LogLevel::Warning, "log.nfqueue_error", vec![("error", error.to_string())]),
        None => eprintln!("nfqueue: {error}"),
    }
}

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
    if let Err(e) = set_mark(fd, MARK) {
        unsafe { libc::close(fd) };
        return Err(e);
    }
    Ok(fd)
}

fn set_mark(fd: RawFd, mark: u32) -> io::Result<()> {
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

/// Ставит соединению-пробе fwmark, по которой правило заворачивает её в
/// очередь несмотря на исключение группы прокси. Иначе проба ушла бы мимо
/// перехвата и мерила бы прямое соединение вместо техники.
pub fn set_probe_mark(fd: RawFd) -> io::Result<()> {
    set_mark(fd, crate::bypass::packet_mode::PROBE_FWMARK)
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
    let (words, rest) = data.as_chunks::<2>();
    for w in words {
        sum += u32::from(u16::from_be_bytes(*w));
    }
    if let [last] = rest {
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
    /// Индикатор «слушает» (см. `Loop::sync`).
    pub metrics: Arc<Metrics>,
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
    fn take_mark(&self, local_port: u16, remote: std::net::IpAddr) -> Option<Mark> {
        crate::bypass::packet_mode::take(local_port, remote)
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
    fn decoy(&self, payload: &[u8]) -> Vec<u8> {
        let p = &self.bypass_params;
        tls::decoy_for(payload, payload.len(), &p.fake_sni, p.fake_clone)
            .unwrap_or_else(|| tls::build_client_hello_sized(&p.fake_sni, payload.len()))
    }
    fn fake_host(&self, len: usize) -> Vec<u8> {
        tls::fake_host(&self.bypass_params.fake_sni, len)
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
        // Не молчаливый «успех»: иначе оригинал отбросили бы без замены.
        if pkt.len() < 20 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "packet shorter than an IPv4 header"));
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

/// Отправить замену до конца не удалось: что делать с оригиналом и почему.
#[derive(Debug)]
pub struct Failed {
    pub disposition: Disposition,
    pub error: io::Error,
}

/// Прогоняет один пакет из очереди через общий движок — Linux-двойник тела
/// виндового `run_tcp`. Переписанные пакеты уходят через `inj`, а вердикт для
/// оригинала возвращается вызывающему — и при неудаче тоже (см. [`Failed`]).
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
) -> Result<Disposition, Failed> {
    // Только IPv4: raw-сокет переотправки отдаёт заголовок сам лишь для v4.
    // От IPv6 в очереди бережёт правило nft, но если он туда всё же попадёт,
    // переотправка исказила бы пакет, а оригинал был бы отброшен.
    if pkt.first().map(|b| b >> 4) != Some(4) {
        return Ok(Disposition::Accept);
    }
    let Some(t) = desync::parse(pkt) else { return Ok(Disposition::Accept) };
    if t.dport == HTTPS_PORT {
        // Только ClientHello, как фильтр WinDivert (tcp.Payload[0]==22, [1]==3,
        // [5]==1). Правило nft отбирает так же, но на старом nft (без `@ih`)
        // ловит все PSH+ACK на 443, поэтому сузим и здесь:
        // иначе движок переписывал бы и каждый последующий пакет данных
        // (аплоады) — впустую гоняя их через userspace и (для seqovl) добавляя
        // приманку к каждому. Поток уже известен, и `outbound` повторил бы
        // технику. Повтор самого ClientHello (ретрансмит) проверку проходит.
        if !is_client_hello(t.payload(pkt)) {
            return Ok(Disposition::Accept);
        }
        match engine.outbound(pkt, now, env) {
            Outbound::Send(parts) => {
                for (i, mut p) in parts.into_iter().enumerate() {
                    fixup_v4(&mut p);
                    if let Err(error) = inj.send(&p) {
                        // Ничего не ушло — пусть идёт оригинал. Часть уже
                        // ушла (приманка) — оригинал поверх неё дал бы
                        // полутехнику с дублем данных; ядро само повторит
                        // его, и повтор снова пройдёт через очередь.
                        let disposition = if i == 0 { Disposition::Accept } else { Disposition::Drop };
                        return Err(Failed { disposition, error });
                    }
                }
                Ok(Disposition::Drop)
            }
            Outbound::Reset(mut rst) => {
                // Сброс приложению: адреса в пакете уже развёрнуты на локальный,
                // raw-сокет доставит его в местный стек. Не ушёл — оригинал
                // всё равно не пропускаем: это ClientHello заблокированного
                // домена.
                fixup_v4(&mut rst);
                inj.send(&rst).map_err(|error| Failed { disposition: Disposition::Drop, error })?;
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

/// Ошибок очереди подряд, после которых цикл сдаётся. Разовые (EINTR,
/// ENOBUFS при всплеске) не должны выключать обход до ручного перезапуска.
const MAX_QUEUE_ERRORS_IN_ROW: u32 = 50;

/// Ошибка очереди: в лог и короткая пауза. `Some` — подряд их слишком много,
/// цикл сдаётся.
fn queue_error(e: io::Error, errors_in_row: &mut u32) -> Option<io::Error> {
    *errors_in_row += 1;
    log_error(&e);
    if *errors_in_row >= MAX_QUEUE_ERRORS_IN_ROW {
        return Some(e);
    }
    std::thread::sleep(Duration::from_millis(10));
    None
}

/// Продуктовый цикл: гоняет полный `Engine` с автоподбором на очереди
/// `queue_num` по настройкам из [`install`]. Блокирующий; возвращается при
/// стойкой ошибке очереди или сразу, если цикл уже работает.
///
/// Правило заворачивает только исходящие 443 (кроме пакетов с меткой [`MARK`]):
/// этого хватает, чтобы применить технику. Входящие движок обрабатывать умеет
/// (`process` → `Engine::inbound`), но `LinuxEnv::select` зануляет `source`,
/// так что поток сразу помечается решённым и ответа сервера не ждёт — учёт
/// стратегий идёт по сокетным пробам, а не отсюда. Выбор стратегии запускает
/// диагностику на tokio, поэтому цикл должен работать внутри рантайма
/// (`Handle::enter` у вызывающего).
pub fn run(queue_num: u16) -> io::Result<()> {
    use nfq::{Queue, Verdict};

    // Работающий цикл уже держит очередь: второй bind упал бы, а новые
    // настройки он подхватит сам.
    {
        let mut s = state();
        if s.running {
            return Ok(());
        }
        s.running = true;
    }
    // Не поднялись raw-сокет или очередь — флаг снимается, иначе повторный
    // старт (перезапуск прокси) молча ничего не сделал бы.
    let opened = (|| -> io::Result<_> {
        let inj = RawInjector::new()?;
        let mut queue = Queue::open()?;
        queue.bind(queue_num)?;
        // Переполнилась очередь (цикл ненадолго задумался, а браузер открыл
        // пачку соединений) — ядро пропускает пакеты как есть, а не
        // выбрасывает. Флаг `bypass` в правиле покрывает лишь «читателя нет».
        // Старое ядро этого не умеет — работаем и без.
        let _ = queue.set_fail_open(queue_num, true);
        Ok((inj, queue))
    })();
    let (inj, mut queue) = match opened {
        Ok(opened) => opened,
        Err(e) => {
            let mut s = state();
            s.running = false;
            s.sync();
            return Err(e);
        }
    };
    // Соединения прокси и пробы диагностики должны помечаться с первого же
    // ClientHello — как и на Windows перед стартом потоков перехвата.
    {
        let mut s = state();
        s.bound = true;
        s.sync();
    }

    // Движок — заново на каждую установку настроек: потоки, решённые по
    // прежним (домен убрали из списка, обход выключили), иначе повторяли бы
    // старую технику на повторах ClientHello.
    let mut engine = Engine::new();
    let mut engine_for = None;
    let mut errors_in_row = 0u32;
    let result = loop {
        let mut msg = match queue.recv() {
            Ok(msg) => msg,
            Err(e) => match queue_error(e, &mut errors_in_row) {
                Some(e) => break Err(e),
                None => continue,
            },
        };
        let now = Instant::now();
        // Прокси остановлен — пакеты идут как есть.
        let processed = match current_env() {
            Some((generation, env)) => {
                if engine_for != Some(generation) {
                    engine = Engine::new();
                    engine_for = Some(generation);
                }
                process(msg.get_payload(), &mut engine, &*env, &inj, now)
            }
            None => Ok(Disposition::Accept),
        };
        let disposition = processed.unwrap_or_else(|failed| {
            log_error(&failed.error);
            failed.disposition
        });
        msg.set_verdict(match disposition {
            Disposition::Drop => Verdict::Drop,
            Disposition::Accept => Verdict::Accept,
        });
        match queue.verdict(msg) {
            Ok(()) => errors_in_row = 0,
            Err(e) => {
                if let Some(e) = queue_error(e, &mut errors_in_row) {
                    break Err(e);
                }
            }
        }
    };

    // Цикл сдался. Флаги снимаются, чтобы перезапуск прокси мог поднять
    // пакетный режим заново, а сокетный путь снова считал себя главным
    // (is_active → false включает его freeze-эскалацию).
    let mut s = state();
    s.running = false;
    s.bound = false;
    s.sync();
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
        fn take_mark(&self, _: u16, _: std::net::IpAddr) -> Option<Mark> {
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
        fn decoy(&self, payload: &[u8]) -> Vec<u8> {
            vec![0; payload.len()]
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

    /// Отказывает начиная с отправки номер `fail_from` (с нуля).
    struct FailingInjector {
        fail_from: usize,
        sent: std::cell::Cell<usize>,
    }
    impl Injector for FailingInjector {
        fn send(&self, _: &[u8]) -> io::Result<()> {
            let n = self.sent.get();
            self.sent.set(n + 1);
            if n >= self.fail_from { Err(io::Error::from(io::ErrorKind::PermissionDenied)) } else { Ok(()) }
        }
    }

    /// Обход для любого домена техникой disorder — два сегмента.
    struct DisorderEnv;
    impl Env for DisorderEnv {
        fn take_mark(&self, _: u16, _: std::net::IpAddr) -> Option<Mark> {
            None
        }
        fn is_blocked(&self, _: &str) -> bool {
            false
        }
        fn needs_bypass(&self, _: &str) -> bool {
            true
        }
        fn select(&self, _: &str, _: usize) -> Selected {
            Selected::new(crate::engine::strategy::Strategy::Disorder, None)
        }
        fn record(&self, _: &str, _: Selected, _: bool) {}
        fn remember(&self, _: IpAddr, _: &str) {}
        fn lookup(&self, _: IpAddr) -> Option<String> {
            None
        }
        fn decoy(&self, payload: &[u8]) -> Vec<u8> {
            vec![0; payload.len()]
        }
        fn log_intercepted(&self, _: &str, _: IpAddr, _: bool) {}
        fn log_applied(&self, _: &str, _: &str) {}
        fn log_blocked(&self, _: &str) {}
    }

    /// Замена не ушла вовсе — оригинал пропускается; ушла частично —
    /// оригинал не идёт поверх неё.
    #[test]
    fn failed_reinjection_decides_by_what_already_left() {
        let pkt = v4_tcp(&tls::build_client_hello_sized("discord.com", 517));

        let none_sent = FailingInjector { fail_from: 0, sent: std::cell::Cell::new(0) };
        let failed = process(&pkt, &mut Engine::new(), &DisorderEnv, &none_sent, Instant::now()).unwrap_err();
        assert_eq!(failed.disposition, Disposition::Accept);

        let first_sent = FailingInjector { fail_from: 1, sent: std::cell::Cell::new(0) };
        let failed = process(&pkt, &mut Engine::new(), &DisorderEnv, &first_sent, Instant::now()).unwrap_err();
        assert_eq!(failed.disposition, Disposition::Drop);
    }

    #[test]
    fn ipv6_is_passed_through_untouched() {
        let mut pkt = v4_tcp(&tls::build_client_hello_sized("discord.com", 517));
        pkt[0] = 0x60;
        let inj = VecInjector(std::cell::RefCell::new(Vec::new()));
        let disp = process(&pkt, &mut Engine::new(), &DisorderEnv, &inj, Instant::now()).unwrap();
        assert_eq!(disp, Disposition::Accept);
        assert!(inj.0.borrow().is_empty());
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
