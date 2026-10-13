//! Telegram через ретранслятор на Cloudflare.
//!
//! # Почему не как остальные сайты
//!
//! Все техники обхода прячут имя сайта в ClientHello. Приложение Telegram
//! имени не шлёт: оно ходит на IP-адреса своих серверов собственным
//! протоколом MTProto. А у части операторов эти адреса заблокированы целиком,
//! на уровне IP: до `149.154.*` и `91.108.*` не доходит даже SYN, с любым
//! содержимым. Маскировать тут нечего — пакеты просто не доезжают. Веб-вход
//! `kws*.web.telegram.org`, через который работает tg-ws-proxy, стоит на тех
//! же адресах и заблокирован так же.
//!
//! # Как обходится
//!
//! Соединение к адресу Telegram заворачивается в WebSocket до воркера на
//! Cloudflare (`cloudflare/worker.js`), а тот из сети Cloudflare открывает
//! обычный TCP к серверу Telegram:
//!
//! ```text
//! Telegram → net_surgeon → wss://<воркер>/apiws?dst=IP&port=443 → IP:443
//! ```
//!
//! Адреса Cloudflare не блокируют: на них половина интернета. Воркер свой,
//! на аккаунте пользователя, и видит только зашифрованный поток MTProto.
//!
//! Воркер перекладывает байты как есть, поэтому здесь не нужно ни разбирать
//! заголовок MTProto, ни резать поток на сообщения, как делает tg-ws-proxy:
//! байты клиента уходят кадрами WebSocket в том виде, в каком пришли.
//!
//! # Настройка
//!
//! Адрес воркера — первая строка `telegram_relay.txt` в каталоге данных.
//! Файла нет — ретранслятор выключен, и Telegram идёт напрямую, как раньше.
//! Файл не в git: адрес воркера — это доступ к квоте чужого аккаунта.

use std::net::IpAddr;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::config::paths;
use crate::observability::logging::{log_t, LogLevel, LogSender};
use crate::observability::metrics::Metrics;

const CONFIG_FILE: &str = "telegram_relay.txt";

/// Сколько ждать подключения к воркеру на 443 вместе с TLS, и отдельно —
/// рукопожатия WebSocket.
///
/// Время на приманку и пробу 8443 сюда не входит: у них свои пределы
/// (`FAKE_BUDGET`, `FAKE_ATTEMPT_TIMEOUT`). Раньше одно общее окно
/// покрывало всё, и две неудачные попытки приманки по 4 с оставляли
/// откату 2 с — соединение отваливалось по таймауту.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Предел одного кадра от воркера. Воркер шлёт то, что прочитал из TCP, —
/// десятки килобайт; кадр в гигабайт означал бы сломанный поток, а не данные.
const MAX_FRAME: u64 = 16 * 1024 * 1024;

/// Сети Telegram — те же, что в `cloudflare/worker.js`. Воркер пустит только
/// к ним, так что заворачивать что-то ещё бесполезно.
const TELEGRAM_V4: &[([u8; 4], u8)] = &[
    ([149, 154, 160, 0], 20),
    ([91, 108, 4, 0], 22),
    ([91, 108, 8, 0], 22),
    ([91, 108, 12, 0], 22),
    ([91, 108, 16, 0], 22),
    ([91, 108, 20, 0], 22),
    ([91, 108, 56, 0], 22),
    ([91, 105, 192, 0], 23),
    ([95, 161, 64, 0], 20),
    ([185, 76, 151, 0], 24),
];

/// Порты, которые пропускает воркер.
const PORTS: &[u16] = &[443, 80, 5222];

static RELAY: RwLock<Option<Arc<str>>> = RwLock::new(None);

/// Секрет воркера (`token: …` в telegram_relay.txt), если задан. Уходит
/// заголовком `X-Relay-Token`: без него воркер с секретом не отвечает (см.
/// cloudflare/worker.js). В лог не пишется.
static RELAY_TOKEN: RwLock<Option<Arc<str>>> = RwLock::new(None);

/// Имя в приманке для TLS до воркера (`[bypass] fake_sni`). Остальное
/// у приманки ретранслятора своё (см. `ws::fake_handshake`), из конфига
/// берётся только имя.
///
/// Соединение к адресам Cloudflare ТСПУ пропускает, но глушит после
/// пары килобайт от клиента: сервер перестаёт подтверждать пакеты, и
/// MTProto встаёт сразу после рукопожатия WebSocket. Приманка перед
/// ClientHello (как у `fake`) сбивает классификацию потока, и заморозки
/// нет — проверено на воркере: без неё третий запрос по соединению
/// не доходит, с ней проходят все.
static FAKE_SNI: RwLock<Option<Arc<str>>> = RwLock::new(None);

/// Неудачи подряд, после которых что-то признаётся не работающим: общий
/// счётчик для приманки, порта 8443 и md5sig.
struct Streak {
    failures: u32,
    last_failure: Option<std::time::Instant>,
    tripped_at: Option<std::time::Instant>,
}
impl Streak {
    const FRESH: Streak = Streak { failures: 0, last_failure: None, tripped_at: None };

    /// Неудача; `true` — набралось `limit` подряд. Неудачи ближе `round`
    /// друг к другу считаются за одну.
    fn fail(&mut self, limit: u32, round: Duration) -> bool {
        let now = std::time::Instant::now();
        if self.last_failure.is_some_and(|at| now.duration_since(at) < round) {
            return false;
        }
        self.last_failure = Some(now);
        self.failures += 1;
        if self.failures < limit {
            return false;
        }
        self.failures = 0;
        self.tripped_at = Some(now);
        true
    }

    fn ok(&mut self) {
        self.failures = 0;
        self.last_failure = None;
    }

    fn tripped_within(&self, d: Duration) -> bool {
        self.tripped_at.is_some_and(|at| at.elapsed() < d)
    }
}

/// Неудачи приманки подряд, после которых сеть считается не требующей её.
/// Минуту после этого её не пробуем: каждая неудача — это таймаут.
///
/// Откат без приманки в сети с заморозкой бесполезен: соединение
/// встаёт после пары килобайт. Раньше одна неудача отправляла туда все
/// соединения на минуту, и Telegram заметно тормозил. Теперь без приманки —
/// только когда закрыт сам порт 8443 или она не помогла несколько раз
/// подряд (сеть без заморозки).
static FAKE: std::sync::Mutex<Streak> = std::sync::Mutex::new(Streak::FRESH);
const FAKE_FAILURES_LIMIT: u32 = 3;
/// Неудачи приманки ближе этого друг к другу — один раунд: Telegram
/// открывает соединения пачкой, и короткий сбой сети давал бы «три
/// неудачи подряд» разом. Покрывает попытку с приманкой целиком.
const FAKE_FAILURE_ROUND: Duration = FAKE_ATTEMPT_TIMEOUT;
const FAKE_RETRY_AFTER: Duration = Duration::from_secs(60);
/// TTL приманки до воркера (см. `ws::fake_handshake`).
const RELAY_FAKE_TTL: u32 = 12;
/// Порт воркера для подключения с приманкой. Cloudflare отдаёт HTTPS и на
/// 2053/2083/2087/2096/8443, а DPI на них мягче: на 443 любая приманка
/// убивает соединение сразу (0 байт ответа), без неё оно замерзает; на 8443
/// приманка проходит 3/3 (замер на воркере, 10 запросов по 1 КБ).
const RELAY_FAKE_PORT: u16 = 8443;
/// Сколько ждать рукопожатия с приманкой. Настоящий ClientHello уходит
/// повтором после приманки, и на мобильном интернете с его RTO 3 с не
/// хватало: удачные попытки обрывались.
const FAKE_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(4);
/// Сколько ждать TCP до 8443 по всем адресам воркера вместе. Меньше
/// FAKE_ATTEMPT_TIMEOUT: остаток — на TLS.
const FAKE_CONNECT_TIMEOUT: Duration = Duration::from_millis(2500);
/// Предел на все попытки приманки одного соединения, включая очередь на
/// подбор TTL (`SWEEP`): Telegram открывает соединения пачками, и без него
/// последние в очереди ждали десятки секунд.
const FAKE_BUDGET: Duration = Duration::from_secs(9);
/// Фора 8443 перед 443 при подключении без приманки (см. `ws::plain`):
/// с запасом на TCP и TLS, то есть на два-три RTT мобильной сети.
const PLAIN_HEAD_START: Duration = Duration::from_secs(1);

/// Неудачные TCP-подключения к 8443 подряд — по раундам, а не по попыткам
/// (см. `PORT_FAILURE_ROUND`). Когда порт признан закрытым, минуту 8443 не
/// пробуем вовсе: каждая проба — это таймаут. Только после нескольких
/// подряд — в сети, где 443 до воркера закрыт, одна случайная неудача
/// отправляла бы все соединения туда.
static PORT: std::sync::Mutex<Streak> = std::sync::Mutex::new(Streak::FRESH);
const PORT_FAILURES_LIMIT: u32 = 3;
/// Неудачи ближе этого друг к другу — один раунд и считаются за одну:
/// подбор TTL открывает девять подключений разом, Telegram — пачку своих,
/// и один сбой сети давал бы «три неудачи подряд» за миллисекунду.
const PORT_FAILURE_ROUND: Duration = FAKE_CONNECT_TIMEOUT;

/// Ядро без `CONFIG_TCP_MD5SIG` (так на части Android): приманка уходит
/// без подписи, и TTL уже нельзя брать с запасом — дошедшая до сервера
/// приманка ломает рукопожатие. Свойство ядра, поэтому не сбрасывается.
static NO_MD5SIG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// Отказы приманки с md5sig подряд. Отказ бывает и разовым (не собралась
/// приманка, не встал TTL на этом сокете), поэтому «ядро без md5sig»
/// решается только после нескольких подряд — иначе одна случайность
/// навсегда переводила ноутбук на слабый режим.
static MD5SIG_REFUSALS: std::sync::Mutex<Streak> = std::sync::Mutex::new(Streak::FRESH);
const MD5SIG_REFUSALS_LIMIT: u32 = 3;
/// TTL приманки без md5sig, найденный подбором; сбрасывается, когда
/// перестаёт работать (сменилась сеть).
static RELAY_TTL: std::sync::Mutex<Option<u32>> = std::sync::Mutex::new(None);
/// Подбор идёт один на всех: Telegram открывает соединения пачками, и без
/// этого каждое запускало свои девять подключений с приманкой разом.
static SWEEP: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
/// Кандидаты подбора без md5sig, как autottl в zapret: нужен наибольший
/// TTL, при котором рукопожатие живо, — приманка умирает перед самым
/// сервером, то есть заведомо дальше DPI. По убыванию.
const RELAY_TTL_SWEEP: &[u32] = &[14, 12, 10, 9, 8, 7, 6, 5, 4];
/// Сколько после первого удачного TTL ждать бóльших: слишком большой TTL
/// обычно отказывает быстро, но ждать его до таймаута незачем.
const SWEEP_GRACE: Duration = Duration::from_millis(500);

/// Адрес Telegram, к которому воркер нас пустит.
pub fn is_telegram(ip: IpAddr, port: u16) -> bool {
    PORTS.contains(&port) && is_telegram_network(ip)
}

/// Адрес в сетях Telegram, на любом порту. Серверы голоса в звонках
/// слушают не 443, поэтому для UDP порт не проверяется.
pub fn is_telegram_network(ip: IpAddr) -> bool {
    let IpAddr::V4(v4) = ip else { return false };
    let n = u32::from(v4);
    TELEGRAM_V4.iter().any(|(base, bits)| {
        let mask = u32::MAX << (32 - bits);
        n & mask == u32::from_be_bytes(*base)
    })
}

/// Сети Telegram (IPv4) как «адрес, длина префикса» — для правил перехвата
/// звонков в nftables и WinDivert.
pub fn networks_v4() -> impl Iterator<Item = (std::net::Ipv4Addr, u8)> {
    TELEGRAM_V4.iter().map(|(base, bits)| (std::net::Ipv4Addr::from(*base), *bits))
}

/// Адрес воркера, если ретранслятор включён.
pub fn relay() -> Option<Arc<str>> {
    RELAY.read().ok()?.clone()
}

/// Перечитывает `telegram_relay.txt`. Зовётся из `run_all`, как и список
/// блокировки: правка файла применяется перезапуском прокси.
pub fn reload(log_tx: &LogSender, bypass: &crate::config::BypassParams) {
    if let Ok(mut guard) = FAKE_SNI.write() {
        *guard = Some(Arc::from(bypass.fake_sni.as_str()));
    }
    for streak in [&FAKE, &PORT] {
        if let Ok(mut streak) = streak.lock() {
            *streak = Streak::FRESH;
        }
    }
    if let Ok(mut ttl) = RELAY_TTL.lock() {
        *ttl = None;
    }
    let text = paths::read_to_string(CONFIG_FILE).ok();
    let host = text.as_deref().and_then(parse);
    if let Some(h) = &host {
        log_t(log_tx, LogLevel::Info, "log.telegram_relay_active", vec![("host", masked(h))]);
    }
    if let Ok(mut guard) = RELAY.write() {
        *guard = host.map(Arc::from);
    }
    if let Ok(mut guard) = RELAY_TOKEN.write() {
        *guard = text.as_deref().and_then(parse_token).map(Arc::from);
    }
}

/// Адрес воркера для лога: без середины имени.
///
/// Адрес — это доступ к квоте аккаунта Cloudflare (поэтому файл не в git и
/// не в релизном APK), а лог на телефоне отправляют кнопкой «Поделиться».
/// Раньше в него попадал полный адрес. По маске видно, какой воркер
/// настроен, но подключиться к нему нельзя:
/// `net-surgeon-tg.your-subdomain.workers.dev` → `net-surgeon-tg.***.workers.dev`.
fn masked(host: &str) -> String {
    let labels: Vec<&str> = host.split('.').collect();
    match labels.as_slice() {
        [first, .., a, b] if labels.len() > 3 => format!("{first}.***.{a}.{b}"),
        [first, _, last] => format!("{first}.***.{last}"),
        [_, last] => format!("***.{last}"),
        _ => "***".to_string(),
    }
}

/// Имя хоста для лога: адрес воркера — под маской, остальное как есть.
/// Для модулей, которые не знают, чей это адрес (резолвер).
pub(crate) fn masked_if_relay(host: &str) -> String {
    match relay() {
        Some(relay) if relay.eq_ignore_ascii_case(host) => masked(host),
        _ => host.to_string(),
    }
}

/// Первая строка, не пустая и не комментарий. Схема, порт и путь, если их
/// вписали по привычке, отрезаются: нужен только хост — порты ретранслятор
/// выбирает сам (443 и 8443).
fn parse(text: &str) -> Option<String> {
    let line = config_lines(text).find(|l| token_value(l).is_none())?;
    let without_scheme = line.split_once("://").map_or(line, |(_, rest)| rest);
    let authority = without_scheme.split('/').next()?;
    let host = match authority.rsplit_once(':') {
        Some((host, port)) if port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => authority,
    }
    .trim();
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Строки файла без пустых и комментариев.
fn config_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#'))
}

/// Значение строки `token: …` (или `token = …`).
fn token_value(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("token")?.trim_start();
    let value = rest.strip_prefix(':').or_else(|| rest.strip_prefix('='))?.trim();
    (!value.is_empty()).then_some(value)
}

/// Секрет воркера, если он записан в файле.
fn parse_token(text: &str) -> Option<String> {
    config_lines(text).find_map(token_value).map(str::to_string)
}

/// Ведёт соединение клиента к `ip:port` через воркер.
///
/// `early` — байты, которые клиент уже прислал (хвост запроса SOCKS5,
/// первый пакет прозрачного режима). Возвращает ошибку, только если до
/// воркера достучаться не удалось: тогда клиент ещё ничего не потерял, и
/// вызывающий может попробовать напрямую.
pub async fn relay_connection<C>(
    client: C,
    relay_host: &str,
    ip: IpAddr,
    port: u16,
    early: &[u8],
    log_tx: &LogSender,
    metrics: &Arc<Metrics>,
) -> std::io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin + Send,
{
    let path = format!("/apiws?dst={ip}&port={port}");
    let ws = ws::connect(relay_host, &path)
        .await
        // Ошибка идёт в лог, а в тексте бывает полный адрес воркера
        // («host:443: подключение не установилось…»).
        .map_err(|e| std::io::Error::new(e.kind(), e.to_string().replace(relay_host, &masked(relay_host))))?;

    log_t(log_tx, LogLevel::Info, "log.telegram_relayed", vec![("addr", format!("{ip}:{port}"))]);

    let (mut ws_read, ws_write) = tokio::io::split(ws);
    let ws_write = Arc::new(Mutex::new(ws_write));
    let (mut client_read, mut client_write) = tokio::io::split(client);

    if !early.is_empty() {
        ws::send(&ws_write, ws::OP_BINARY, early).await?;
        metrics.add_rx(early.len() as u64);
    }

    let up = {
        let ws_write = Arc::clone(&ws_write);
        let metrics = Arc::clone(metrics);
        async move {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = match client_read.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                if ws::send(&ws_write, ws::OP_BINARY, &buf[..n]).await.is_err() {
                    break;
                }
                metrics.add_rx(n as u64);
            }
            let _ = ws::send(&ws_write, ws::OP_CLOSE, &1000u16.to_be_bytes()).await;
        }
    };

    let down = {
        let ws_write = Arc::clone(&ws_write);
        let metrics = Arc::clone(metrics);
        async move {
            loop {
                let (op, payload) = match ws::recv(&mut ws_read, MAX_FRAME).await {
                    Ok(frame) => frame,
                    Err(_) => break,
                };
                match op {
                    ws::OP_BINARY | ws::OP_TEXT | ws::OP_CONTINUATION => {
                        if client_write.write_all(&payload).await.is_err() {
                            break;
                        }
                        metrics.add_tx(payload.len() as u64);
                    }
                    ws::OP_PING => {
                        if ws::send(&ws_write, ws::OP_PONG, &payload).await.is_err() {
                            break;
                        }
                    }
                    ws::OP_CLOSE => break,
                    _ => {}
                }
            }
            let _ = client_write.shutdown().await;
        }
    };

    // Любая сторона закрылась — закрываем обе: полуоткрытое соединение
    // Telegram не нужно, а висящая задача держала бы сокеты.
    tokio::select! {
        _ = up => {}
        _ = down => {}
    }
    Ok(())
}

/// Минимальный клиент WebSocket (RFC 6455) поверх TLS: ровно то, что нужно
/// для одного воркера. Своя реализация вместо библиотеки — это сотня строк
/// против отдельного стека зависимостей, а расширения, сжатие и прочее
/// воркеру не нужны.
mod ws {
    use super::*;
    use base64::Engine;
    use tokio::io::WriteHalf;
    use tokio::net::TcpStream;
    use tokio_rustls::client::TlsStream;

    pub const OP_CONTINUATION: u8 = 0x0;
    pub const OP_TEXT: u8 = 0x1;
    pub const OP_BINARY: u8 = 0x2;
    pub const OP_CLOSE: u8 = 0x8;
    pub const OP_PING: u8 = 0x9;
    pub const OP_PONG: u8 = 0xA;

    pub type Stream = TlsStream<TcpStream>;

    /// Корни — встроенный список Mozilla, а не системное хранилище: на
    /// Android до системного из Rust без Java не добраться.
    fn tls() -> tokio_rustls::TlsConnector {
        static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
        let config = CONFIG.get_or_init(|| {
            let roots = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            let mut config = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("TLS 1.2/1.3")
                .with_root_certificates(roots)
                .with_no_client_auth();
            // Без ALPN Cloudflare может выбрать HTTP/2, а Upgrade в нём нет.
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            Arc::new(config)
        });
        tokio_rustls::TlsConnector::from(Arc::clone(config))
    }

    /// Имя для приманки, если её сейчас стоит пробовать.
    fn fake_sni() -> Option<Arc<str>> {
        if !crate::bypass::socket::fake_supported() {
            return None;
        }
        let recently_failed = FAKE.lock().is_ok_and(|fake| fake.tripped_within(FAKE_RETRY_AFTER));
        if recently_failed || port_known_closed() {
            return None;
        }
        FAKE_SNI.read().ok()?.clone()
    }

    /// 8443 недавно признан закрытым (см. `PORT`).
    fn port_known_closed() -> bool {
        PORT.lock().is_ok_and(|port| port.tripped_within(FAKE_RETRY_AFTER))
    }

    /// Неудачное подключение к 8443. «Сеть недоступна» — не про порт: так
    /// бывает при смене сети, и закрытым порт от этого не считается.
    fn note_port_failed(e: &std::io::Error) {
        if e.kind() == std::io::ErrorKind::NetworkUnreachable {
            return;
        }
        if let Ok(mut port) = PORT.lock() {
            port.fail(PORT_FAILURES_LIMIT, PORT_FAILURE_ROUND);
        }
    }

    fn note_port_open() {
        if let Ok(mut port) = PORT.lock() {
            port.ok();
        }
    }

    /// TCP до 8443. Ошибка — всегда `HostUnreachable`: по ней `port_closed`
    /// отличает закрытый порт от неудачной приманки.
    async fn connect_fake_port(host: &str) -> std::io::Result<TcpStream> {
        let unreachable = |e: Box<dyn std::error::Error + Send + Sync>| std::io::Error::new(std::io::ErrorKind::HostUnreachable, e);
        // Резолв — до предела на подключение и не в счёт закрытого порта:
        // медленный DNS на холодном кэше — не повод считать порт закрытым.
        let addrs = crate::dns::resolver::resolve_all(&format!("{host}:{RELAY_FAKE_PORT}")).await;
        if addrs.is_empty() {
            return Err(unreachable(rust_i18n::t!("err.no_addresses").into_owned().into()));
        }
        match crate::dns::resolver::connect_without_dead_cache(&addrs, FAKE_CONNECT_TIMEOUT).await {
            Ok(tcp) => {
                note_port_open();
                Ok(tcp)
            }
            Err(e) => {
                note_port_failed(&e);
                Err(unreachable(e.into()))
            }
        }
    }

    /// Параметры для `split_with_fake`: он берёт из них только имя, TTL и
    /// md5sig, остальные поля — про сплит и сюда не относятся.
    fn decoy(sni: &str, ttl: u32, md5sig: bool) -> crate::config::BypassParams {
        crate::config::BypassParams {
            split_pos_min: 0,
            split_pos_max: 0,
            split_delay_ms: 0,
            window_clamp: 0,
            disorder_ttl: 0,
            fake_ttl: ttl,
            fake_md5sig: md5sig,
            fake_sni: sni.to_string(),
            fake_clone: true,
            hostfakesplit_midhost: false,
            hostfakesplit_disorder_after: false,
            fake_sni_candidates: Vec::new(),
        }
    }

    /// Неудача приманки. Минута без неё — только после нескольких подряд.
    fn note_fake_failed() {
        if let Ok(mut fake) = FAKE.lock() {
            fake.fail(FAKE_FAILURES_LIMIT, FAKE_FAILURE_ROUND);
        }
    }

    fn note_fake_worked() {
        if let Ok(mut fake) = FAKE.lock() {
            fake.ok();
        }
    }

    /// Порт 8443 недоступен (провайдер закрыл): приманке тут делать нечего.
    fn port_closed(e: &std::io::Error) -> bool {
        e.kind() == std::io::ErrorKind::HostUnreachable
    }

    fn remembered_ttl() -> Option<u32> {
        RELAY_TTL.lock().ok().and_then(|ttl| *ttl)
    }

    fn remember_ttl(ttl: u32) {
        if let Ok(mut slot) = RELAY_TTL.lock() {
            *slot = Some(ttl);
        }
    }

    /// Забыть TTL, если это всё ещё он: соседний подбор мог уже найти новый.
    fn forget_ttl(ttl: u32) {
        if let Ok(mut slot) = RELAY_TTL.lock()
            && *slot == Some(ttl)
        {
            *slot = None;
        }
    }

    async fn attempt(host: &str, params: &crate::config::BypassParams) -> std::io::Result<Stream> {
        within(FAKE_ATTEMPT_TIMEOUT, handshake(host, Some(params))).await
    }

    /// Рукопожатие с приманкой; `None` — идти без неё.
    ///
    /// Свои TTL и md5sig, а не подобранные диагностикой: тот TTL — бегущий
    /// минимум по сайтам сети, и для Cloudflare он оказывался мал — приманка
    /// 3–6 рвала соединение целиком. С md5sig сервер выбрасывает приманку,
    /// даже если она до него дошла, поэтому TTL можно брать с запасом (как
    /// autottl + md5sig в zapret). Замер на воркере: 12 и 16 с md5sig — 3/3,
    /// без md5sig 16 уже ломает рукопожатие.
    async fn fake_handshake(host: &str) -> Option<Stream> {
        use std::sync::atomic::Ordering;
        let sni = fake_sni()?;
        if !NO_MD5SIG.load(Ordering::Relaxed) {
            // Вторая попытка — потому что неудача бывает и разовой (потерялся
            // пакет), а откат без приманки в сети с заморозкой хуже ожидания.
            let mut unsigned_needed = false;
            for _ in 0..2 {
                match attempt(host, &decoy(&sni, RELAY_FAKE_TTL, true)).await {
                    Ok(stream) => {
                        if let Ok(mut refusals) = MD5SIG_REFUSALS.lock() {
                            refusals.ok();
                        }
                        note_fake_worked();
                        return Some(stream);
                    }
                    // Приманка с подписью не ушла: дальше без подписи, а
                    // «ядро без md5sig» — только после нескольких отказов подряд.
                    Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {
                        if MD5SIG_REFUSALS.lock().is_ok_and(|mut r| r.fail(MD5SIG_REFUSALS_LIMIT, FAKE_FAILURE_ROUND)) {
                            NO_MD5SIG.store(true, Ordering::Relaxed);
                        }
                        unsigned_needed = true;
                        break;
                    }
                    Err(e) if port_closed(&e) => return None,
                    Err(_) => {}
                }
            }
            if !unsigned_needed {
                note_fake_failed();
                return None;
            }
        }

        sweep(host, &sni).await
    }

    /// Рукопожатие без md5sig: с найденным TTL, а нет его — подбор. Подбор —
    /// все кандидаты разом, берётся наибольший с живым рукопожатием.
    ///
    /// Подбор один на всех (`SWEEP`). Кто ждал, пробует то, что нашёл подбор
    /// перед ним, — уже без замка: под замком ждущие шли бы по одному, на
    /// рукопожатие каждый, и последние в пачке упирались бы в `FAKE_BUDGET`.
    async fn sweep(host: &str, sni: &Arc<str>) -> Option<Stream> {
        let mut tried = None;
        let _guard = loop {
            if let Some(ttl) = remembered_ttl().filter(|&ttl| tried != Some(ttl)) {
                if let Ok(stream) = attempt(host, &decoy(sni, ttl, false)).await {
                    note_fake_worked();
                    return Some(stream);
                }
                // Сеть сменилась: подбираем заново прямо сейчас, а не отдаём
                // это соединение без приманки, где оно замёрзнет.
                forget_ttl(ttl);
                tried = Some(ttl);
                continue;
            }
            let guard = SWEEP.lock().await;
            // Пока ждали, подборы перед нами могли признать приманку
            // бесполезной или найти новый TTL.
            fake_sni()?;
            if remembered_ttl().is_none_or(|ttl| tried == Some(ttl)) {
                break guard;
            }
        };

        let mut set = tokio::task::JoinSet::new();
        for &ttl in RELAY_TTL_SWEEP {
            let params = decoy(sni, ttl, false);
            let host = host.to_string();
            set.spawn(async move { (ttl, attempt(&host, &params).await) });
        }
        let mut best: Option<(u32, Stream)> = None;
        let mut deadline: Option<tokio::time::Instant> = None;
        loop {
            let next = match deadline {
                Some(at) => match tokio::time::timeout_at(at, set.join_next()).await {
                    Ok(next) => next,
                    Err(_) => break,
                },
                None => set.join_next().await,
            };
            let Some(joined) = next else { break };
            if let Ok((ttl, Ok(stream))) = joined
                && best.as_ref().is_none_or(|(b, _)| ttl > *b)
            {
                // Сразу, а не в конце: если `FAKE_BUDGET` оборвёт подбор
                // во время SWEEP_GRACE, найденное не пропадёт.
                remember_ttl(ttl);
                best = Some((ttl, stream));
                if ttl == RELAY_TTL_SWEEP[0] {
                    break;
                }
                deadline.get_or_insert_with(|| tokio::time::Instant::now() + SWEEP_GRACE);
            }
        }
        // Оставшиеся попытки не нужны: JoinSet снимает их при выходе.
        let Some((_, stream)) = best else {
            note_fake_failed();
            return None;
        };
        note_fake_worked();
        Some(stream)
    }

    /// TLS до воркера. С `fake` ClientHello забирается у rustls до начала
    /// рукопожатия и уходит через [`crate::bypass::fragment::split_with_fake`]
    /// по второму дескриптору того же сокета; дальше рукопожатие ведёт
    /// tokio-rustls как обычно.
    async fn handshake(host: &str, fake: Option<&crate::config::BypassParams>) -> std::io::Result<Stream> {
        let tcp = connect_fake_port(host).await?;
        let _ = tcp.set_nodelay(true);
        let name = server_name(host)?;
        let Some(params) = fake else {
            return tls().connect(name, tcp).await;
        };

        let std_tcp = tcp.into_std()?;
        let mut side = TcpStream::from_std(std_tcp.try_clone()?)?;
        let tcp = TcpStream::from_std(std_tcp)?;
        let mut hello = Vec::new();
        let mut taken = Ok(0);
        let pending = tls().connect_with(name, tcp, |conn| taken = conn.write_tls(&mut hello));
        taken?;
        let fd = crate::bypass::socket::raw_sock(&side);
        // Приманка не ушла (нет md5sig в ядре) — ClientHello не отправлен,
        // решает вызывающий: молча послать его как есть значило бы получить
        // замерзающее соединение вместо отката.
        if crate::bypass::fragment::split_with_fake(&mut side, fd, &hello, params).await?.is_none() {
            return Err(std::io::ErrorKind::Unsupported.into());
        }
        drop(side);
        pending.await
    }

    fn server_name(host: &str) -> std::io::Result<rustls::pki_types::ServerName<'static>> {
        rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
    }

    /// TLS до воркера без приманки — на 8443 и 443 внахлёст.
    ///
    /// Бывают сети, где до воркера на 443 не подключиться вовсе, а 8443
    /// открыт, и сети, где 8443 принимает TCP, а TLS на нём виснет (там, где
    /// DPI нет, 443 работает). Поэтому 8443 стартует первым, 443 — через
    /// `PLAIN_HEAD_START` или сразу, как 8443 отказал, и берётся первое
    /// готовое рукопожатие. По очереди каждое соединение во второй сети ждало
    /// бы таймаут 8443 целиком, и запомнить это негде: порт-то открыт.
    async fn plain(host: &str) -> std::io::Result<Stream> {
        let via_443 = within(CONNECT_TIMEOUT, async {
            let tcp = crate::dns::resolver::connect(&format!("{host}:443")).await?;
            let _ = tcp.set_nodelay(true);
            tls().connect(server_name(host)?, tcp).await
        });
        if port_known_closed() {
            return via_443.await;
        }
        let via_8443 = within(FAKE_ATTEMPT_TIMEOUT, handshake(host, None));
        tokio::pin!(via_443, via_8443);
        tokio::select! {
            result = &mut via_8443 => return match result {
                Ok(stream) => Ok(stream),
                Err(_) => via_443.await,
            },
            _ = tokio::time::sleep(PLAIN_HEAD_START) => {}
        }
        tokio::select! {
            result = &mut via_8443 => match result {
                Ok(stream) => Ok(stream),
                Err(_) => via_443.await,
            },
            result = &mut via_443 => match result {
                Ok(stream) => Ok(stream),
                Err(e) => via_8443.await.map_err(|_| e),
            },
        }
    }

    /// `f` с пределом по времени; по истечении — `TimedOut`.
    async fn within<T>(limit: Duration, f: impl std::future::Future<Output = std::io::Result<T>>) -> std::io::Result<T> {
        tokio::time::timeout(limit, f).await.unwrap_or_else(|_| {
            Err(std::io::Error::new(std::io::ErrorKind::TimedOut, rust_i18n::t!("err.relay_timeout").into_owned()))
        })
    }

    pub async fn connect(host: &str, path: &str) -> std::io::Result<Stream> {
        // Приманка не дала рукопожатия (TTL не тот, порт закрыт): без неё
        // соединение хотя бы установится там, где DPI нет.
        let stream = match tokio::time::timeout(FAKE_BUDGET, fake_handshake(host)).await.ok().flatten() {
            Some(stream) => stream,
            None => plain(host).await?,
        };
        within(CONNECT_TIMEOUT, upgrade(stream, host, path)).await
    }

    /// Рукопожатие WebSocket поверх готового TLS.
    async fn upgrade(mut stream: Stream, host: &str, path: &str) -> std::io::Result<Stream> {
        let key = base64::engine::general_purpose::STANDARD.encode(crate::bypass::random::bytes(16));
        let token = RELAY_TOKEN
            .read()
            .ok()
            .and_then(|t| t.clone())
            .map(|t| format!("X-Relay-Token: {t}\r\n"))
            .unwrap_or_default();
        let request = format!(
            "GET {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {key}\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Protocol: binary\r\n\
             {token}\r\n"
        );
        stream.write_all(request.as_bytes()).await?;

        // Заголовки ответа читаются по байту: за ними сразу могут идти кадры,
        // и лишнее прочитанное пришлось бы где-то хранить. Ответ короткий.
        let mut head = Vec::with_capacity(256);
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if head.len() > 8192 {
                return Err(std::io::Error::other(rust_i18n::t!("err.relay_long_reply").into_owned()));
            }
            stream.read_exact(&mut byte).await?;
            head.push(byte[0]);
        }
        let status = String::from_utf8_lossy(&head);
        let first = status.lines().next().unwrap_or_default();
        if first.split_whitespace().nth(1) != Some("101") {
            return Err(std::io::Error::other(rust_i18n::t!("err.relay_replied", status = first).into_owned()));
        }
        Ok(stream)
    }

    /// Кадр от клиента: FIN, опкод, маска (обязательна по RFC 6455).
    pub fn frame(op: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(payload.len() + 14);
        out.push(0x80 | op);
        let len = payload.len();
        if len < 126 {
            out.push(0x80 | len as u8);
        } else if len <= u16::MAX as usize {
            out.push(0x80 | 126);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            out.push(0x80 | 127);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }
        let mask: [u8; 4] = crate::bypass::random::bytes(4).try_into().unwrap_or([0x5a; 4]);
        out.extend_from_slice(&mask);
        out.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        out
    }

    pub async fn send(writer: &Mutex<WriteHalf<Stream>>, op: u8, payload: &[u8]) -> std::io::Result<()> {
        let bytes = frame(op, payload);
        let mut w = writer.lock().await;
        w.write_all(&bytes).await?;
        w.flush().await
    }

    /// Кадр от воркера. Сервер кадры не маскирует, но если маска есть —
    /// снимаем её, а не спотыкаемся.
    pub async fn recv<R: AsyncRead + Unpin>(reader: &mut R, max: u64) -> std::io::Result<(u8, Vec<u8>)> {
        let mut head = [0u8; 2];
        reader.read_exact(&mut head).await?;
        let op = head[0] & 0x0f;
        let masked = head[1] & 0x80 != 0;
        let len = match head[1] & 0x7f {
            126 => {
                let mut b = [0u8; 2];
                reader.read_exact(&mut b).await?;
                u16::from_be_bytes(b) as u64
            }
            127 => {
                let mut b = [0u8; 8];
                reader.read_exact(&mut b).await?;
                u64::from_be_bytes(b)
            }
            n => n as u64,
        };
        if len > max {
            return Err(std::io::Error::other(rust_i18n::t!("err.relay_frame_too_big").into_owned()));
        }
        let mut mask = [0u8; 4];
        if masked {
            reader.read_exact(&mut mask).await?;
        }
        let mut payload = vec![0u8; len as usize];
        reader.read_exact(&mut payload).await?;
        if masked {
            payload.iter_mut().enumerate().for_each(|(i, b)| *b ^= mask[i % 4]);
        }
        Ok((op, payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_telegram_addresses_and_ports() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(is_telegram(ip("149.154.167.51"), 443));
        assert!(is_telegram(ip("149.154.175.50"), 80));
        assert!(is_telegram(ip("91.108.56.100"), 5222));
        assert!(is_telegram(ip("91.105.192.100"), 443));
        // Соседи по сети и чужие порты — нет: воркер их не пустит.
        assert!(!is_telegram(ip("149.154.176.1"), 443));
        assert!(!is_telegram(ip("91.108.24.1"), 443));
        assert!(!is_telegram(ip("149.154.167.51"), 22));
        assert!(!is_telegram(ip("1.1.1.1"), 443));
        assert!(!is_telegram(ip("2001:b28:f23d::a"), 443));
    }

    #[test]
    fn relay_address_is_masked_for_the_log() {
        assert_eq!(masked("net-surgeon-tg.your-subdomain.workers.dev"), "net-surgeon-tg.***.workers.dev");
        assert_eq!(masked("relay.mysite.ru"), "relay.***.ru");
        assert_eq!(masked("mysite.ru"), "***.ru");
        assert_eq!(masked("localhost"), "***");
    }

    #[test]
    fn parses_optional_token_line() {
        let text = "# воркер\ntoken: s3cret-value\nabc.x.workers.dev\n";
        assert_eq!(parse(text).as_deref(), Some("abc.x.workers.dev"), "строка секрета — не хост");
        assert_eq!(parse_token(text).as_deref(), Some("s3cret-value"));
        assert_eq!(parse_token("abc.x.workers.dev\ntoken = other\n").as_deref(), Some("other"));
        assert_eq!(parse_token("abc.x.workers.dev\n"), None);
        assert_eq!(parse_token("token:\n"), None, "пустой секрет — нет секрета");
    }

    /// Список сетей и портов в воркере — копия здешнего. Разойдутся — и
    /// клиент поведёт соединение к воркеру, а тот ответит 403.
    #[test]
    fn worker_allows_the_same_networks_and_ports() {
        let worker = include_str!("../../cloudflare/worker.js");
        let nets: Vec<String> = worker
            .lines()
            .filter_map(|l| {
                let l = l.trim().strip_prefix("[\"")?;
                let (ip, rest) = l.split_once("\", ")?;
                let bits = rest.strip_suffix("],")?;
                Some(format!("{ip}/{bits}"))
            })
            .collect();
        let ours: Vec<String> = networks_v4().map(|(ip, bits)| format!("{ip}/{bits}")).collect();
        assert_eq!(nets, ours);

        let ports_line = worker.lines().find(|l| l.starts_with("const PORTS")).expect("PORTS в воркере");
        let mut theirs: Vec<u16> = ports_line.split('"').filter_map(|p| p.parse().ok()).collect();
        let mut ours = PORTS.to_vec();
        theirs.sort_unstable();
        ours.sort_unstable();
        assert_eq!(theirs, ours);
    }

    #[test]
    fn parses_relay_host() {
        assert_eq!(parse("# мой воркер\n\nabc.x.workers.dev\n").as_deref(), Some("abc.x.workers.dev"));
        assert_eq!(parse("https://ABC.x.workers.dev/apiws\n").as_deref(), Some("abc.x.workers.dev"));
        assert_eq!(parse("HTTPS://abc.x.workers.dev").as_deref(), Some("abc.x.workers.dev"));
        assert_eq!(parse("http://abc.x.workers.dev:8443/").as_deref(), Some("abc.x.workers.dev"));
        assert_eq!(parse("abc.x.workers.dev:443").as_deref(), Some("abc.x.workers.dev"));
        assert_eq!(parse("# пусто\n"), None);
        assert_eq!(parse(""), None);
    }

    #[tokio::test]
    async fn frames_round_trip_through_the_reader() {
        for len in [0usize, 5, 125, 126, 70_000] {
            let payload: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let bytes = ws::frame(ws::OP_BINARY, &payload);
            let (op, got) = ws::recv(&mut &bytes[..], MAX_FRAME).await.unwrap();
            assert_eq!(op, ws::OP_BINARY);
            assert_eq!(got, payload, "длина {len}");
        }
    }

    #[tokio::test]
    async fn refuses_oversized_frames() {
        let bytes = [0x82u8, 127, 0, 0, 0, 1, 0, 0, 0, 0];
        assert!(ws::recv(&mut &bytes[..], MAX_FRAME).await.is_err());
    }
}
