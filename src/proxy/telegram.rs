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

/// Сколько ждать подключения к воркеру вместе с TLS и рукопожатием WebSocket.
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

/// Адрес Telegram, к которому воркер нас пустит.
pub fn is_telegram(ip: IpAddr, port: u16) -> bool {
    let IpAddr::V4(v4) = ip else { return false };
    if !PORTS.contains(&port) {
        return false;
    }
    let n = u32::from(v4);
    TELEGRAM_V4.iter().any(|(base, bits)| {
        let mask = u32::MAX << (32 - bits);
        n & mask == u32::from_be_bytes(*base)
    })
}

/// Адрес воркера, если ретранслятор включён.
pub fn relay() -> Option<Arc<str>> {
    RELAY.read().ok()?.clone()
}

/// Перечитывает `telegram_relay.txt`. Зовётся из `run_all`, как и список
/// блокировки: правка файла применяется перезапуском прокси.
pub fn reload(log_tx: &LogSender) {
    let host = paths::read_to_string(CONFIG_FILE).ok().and_then(|text| parse(&text));
    if let Some(h) = &host {
        log_t(log_tx, LogLevel::Info, "log.telegram_relay_active", vec![("host", masked(h))]);
    }
    if let Ok(mut guard) = RELAY.write() {
        *guard = host.map(Arc::from);
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

/// Первая строка, не пустая и не комментарий. Схема и путь, если их
/// вписали по привычке, отрезаются: нужен только хост.
fn parse(text: &str) -> Option<String> {
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))?;
    let host = line
        .trim_start_matches("https://")
        .trim_start_matches("wss://")
        .split('/')
        .next()?
        .trim();
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
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
    let ws = tokio::time::timeout(CONNECT_TIMEOUT, ws::connect(relay_host, &path))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, rust_i18n::t!("err.relay_timeout").into_owned()))?
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

    pub async fn connect(host: &str, path: &str) -> std::io::Result<Stream> {
        let tcp = crate::dns::resolver::connect(&format!("{host}:443")).await?;
        let _ = tcp.set_nodelay(true);
        let name = rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        let mut stream = tls().connect(name, tcp).await?;

        let key = base64::engine::general_purpose::STANDARD.encode(crate::bypass::random::bytes(16));
        let request = format!(
            "GET {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {key}\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Protocol: binary\r\n\r\n"
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
    fn parses_relay_host() {
        assert_eq!(parse("# мой воркер\n\nabc.x.workers.dev\n").as_deref(), Some("abc.x.workers.dev"));
        assert_eq!(parse("https://ABC.x.workers.dev/apiws\n").as_deref(), Some("abc.x.workers.dev"));
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
