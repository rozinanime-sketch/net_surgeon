//! Прозрачный режим для UDP — то есть для QUIC.
//!
//! # Зачем
//!
//! Прозрачный режим TCP ловит правило `-p tcp --dport 443 -j REDIRECT`.
//! Но Chrome и весь Google по умолчанию ходят по QUIC, а это UDP/443 — мимо
//! этого правила. Получалось, что режим, который обещает «приложения
//! настраивать не нужно», молча пропускал самый массовый трафик: YouTube
//! шёл в обход обхода.
//!
//! # Почему TPROXY, а не REDIRECT
//!
//! REDIRECT работает и для UDP, но он переписывает адрес назначения, и
//! восстановить исходный нечем. У TCP выручает conntrack через
//! `SO_ORIGINAL_DST`, а у UDP соединения нет, и эта опция возвращает адрес
//! самого сокета, а не то, куда шёл клиент. Без адреса назначения пересылать
//! датаграмму некуда — в QUIC имя хоста лежит внутри зашифрованного Initial,
//! спросить его не у кого.
//!
//! TPROXY устроен иначе: он не переписывает заголовки, а доставляет пакет
//! локальному сокету «как есть». Исходное назначение приходит рядом с
//! данными, управляющим сообщением `IP_ORIGDSTADDR`, — для этого сокет
//! помечается `IP_RECVORIGDSTADDR`, а читать приходится через `recvmsg`,
//! потому что `recv_from` вспомогательные данные не отдаёт.
//!
//! # Ответ должен идти от чужого адреса
//!
//! Клиент отправил датаграмму на `142.250.x.x:443` и ждёт ответ ОТТУДА же.
//! Ответ с адреса прокси он отбросит. Поэтому на обратном пути сокет
//! привязывается к исходному назначению — чужому для этой машины адресу.
//! Обычное ядро такого не разрешает; разрешает `IP_TRANSPARENT`.
//!
//! # Цена: CAP_NET_ADMIN
//!
//! `IP_TRANSPARENT` требует `CAP_NET_ADMIN` — и на приёмном сокете, и на
//! обратном. Это отличается от TCP-режима, которому хватает правила iptables
//! и непривилегированного процесса.
//!
//! Обратному сокету нужен ещё `CAP_NET_BIND_SERVICE`: он привязан к порту
//! сервера, 443, а порты ниже 1024 без этого полномочия закрыты
//! (`EACCES`, «Permission denied»).
//!
//! Полномочия выдаются один раз на файл и не требует запуска от root:
//!
//! ```text
//! sudo setcap cap_net_admin,cap_net_bind_service+ep ./target/release/net_surgeon
//! ```
//!
//! `cargo build` пересоздаёт файл и полномочие снимает, поэтому `run.sh`
//! проставляет его после каждой сборки. Без него UDP-слушатель не поднимется
//! и честно скажет об этом в лог — TCP-часть прозрачного режима продолжит
//! работать как работала.
//!
//! # Ограничение
//!
//! Только IPv4: правила в скриптах ставятся для IPv4, и разбор
//! вспомогательного сообщения здесь тоже под `sockaddr_in`. Для IPv6
//! понадобились бы `IPV6_RECVORIGDSTADDR` и вторая ветка разбора.

use std::collections::HashMap;
use std::collections::HashSet;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::unix::AsyncFd;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::bypass::needs_bypass;
use crate::config::Socks5JunkParams;
use crate::dns::ip_cache::IpDomainCache;
use crate::observability::logging::{log_t, LogLevel, LogSender};
use crate::observability::metrics::Metrics;

use super::udp::session::{self, WriterLog};

/// Максимальный размер датаграммы. Меньший буфер молча срезал бы хвост:
/// `recvmsg` об усечении данных не сообщает.
const MAX_DATAGRAM: usize = 65535;

const SESSION_TIMEOUT: Duration = Duration::from_secs(120);
const GC_INTERVAL: Duration = Duration::from_secs(30);

struct Session {
    /// Очередь отправки. Сама отправка — в отдельной задаче
    /// (`udp::session`): мусор с паузами больше не держит цикл приёма,
    /// а датаграммы уходят строго по порядку.
    sender: tokio::sync::mpsc::Sender<Vec<u8>>,
    /// Когда по сессии последний раз шёл трафик в любую сторону. QUIC-сессия
    /// может минутами только принимать (видео), и отметка лишь по исходящим
    /// убивала бы её посреди просмотра.
    last_seen: Arc<std::sync::Mutex<Instant>>,
    cancel: CancellationToken,
    /// Начался ли разговор с QUIC Initial. Счётчик QUIC-сессий в интерфейсе
    /// должен означать одно и то же везде: в SOCKS5-режиме он считает только
    /// такие сессии, а здесь раньше считал любую UDP-сессию, и одно и то же
    /// поле показывало разные величины в зависимости от режима.
    is_quic: bool,
}

/// Ключ — пара «клиент, назначение»: один клиентский порт разговаривает
/// с несколькими серверами, и общий сокет перепутал бы их ответы.
type SessionKey = (SocketAddr, SocketAddr);

// --- низкоуровневая часть --------------------------------------------------

fn set_opt(fd: RawFd, level: libc::c_int, name: libc::c_int, value: libc::c_int) -> io::Result<()> {
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &value as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}

fn to_sockaddr_in(addr: SocketAddrV4) -> libc::sockaddr_in {
    let mut raw: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    raw.sin_family = libc::AF_INET as libc::sa_family_t;
    raw.sin_port = addr.port().to_be();
    raw.sin_addr.s_addr = u32::from(*addr.ip()).to_be();
    raw
}

fn from_sockaddr_in(raw: &libc::sockaddr_in) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::from(u32::from_be(raw.sin_addr.s_addr)),
        u16::from_be(raw.sin_port),
    ))
}

/// Создаёт UDP-сокет с `IP_TRANSPARENT`, привязанный к `bind_to`.
///
/// `recv_orig_dst` включает доставку исходного назначения рядом с данными —
/// нужно только приёмному сокету. Обратный к нему ничего не читает.
fn transparent_socket(bind_to: SocketAddrV4, recv_orig_dst: bool) -> io::Result<std::net::UdpSocket> {
    let fd = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // Владение забираем сразу: дальше любой ранний выход закроет дескриптор
    // сам, без ручного `libc::close` на каждой ветке.
    let sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };

    // Обратных сокетов на один и тот же сервер может быть много — по одному
    // на клиента, — и все они привязываются к одному адресу назначения.
    set_opt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
    set_opt(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT, 1)?;

    // Право привязаться к чужому адресу и получать чужие пакеты.
    set_opt(fd, libc::SOL_IP, libc::IP_TRANSPARENT, 1)?;

    if recv_orig_dst {
        set_opt(fd, libc::SOL_IP, libc::IP_RECVORIGDSTADDR, 1)?;
    }

    let raw = to_sockaddr_in(bind_to);
    let rc = unsafe {
        libc::bind(
            fd,
            &raw as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(sock)
}

/// Читает датаграмму вместе с исходным адресом назначения.
///
/// `recv_from` здесь не годится: он отдаёт только отправителя, а назначение
/// приходит вспомогательным сообщением, и добраться до него можно лишь
/// через `recvmsg`.
fn recv_with_orig_dst(
    sock: &std::net::UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    let mut src: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    // Места с запасом на одно сообщение IP_ORIGDSTADDR плюс выравнивание.
    // Буфер служебных данных обязан быть выровнен как `cmsghdr`: ниже на
    // заголовок берётся ссылка (`&*cmsg`), а ссылка на невыровненные данные
    // в Rust — неопределённое поведение, даже там, где x86 это прощает.
    // Массив u64 даёт нужное выравнивание при том же размере в 128 байт.
    let mut control = [0u64; 16];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut src as *mut libc::sockaddr_in as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = std::mem::size_of_val(&control) as _;

    let n = unsafe { libc::recvmsg(sock.as_raw_fd(), &mut msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut orig_dst = None;
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    while !cmsg.is_null() {
        let header = unsafe { &*cmsg };
        if header.cmsg_level == libc::SOL_IP && header.cmsg_type == libc::IP_ORIGDSTADDR {
            let mut raw: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    libc::CMSG_DATA(cmsg),
                    &mut raw as *mut libc::sockaddr_in as *mut u8,
                    std::mem::size_of::<libc::sockaddr_in>(),
                );
            }
            orig_dst = Some(from_sockaddr_in(&raw));
            break;
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
    }

    // Без назначения датаграмму девать некуда: значит, правило TPROXY
    // не стоит либо сокет создан без IP_RECVORIGDSTADDR.
    let Some(orig_dst) = orig_dst else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            rust_i18n::t!("err.no_origdst").into_owned(),
        ));
    };

    Ok((n as usize, from_sockaddr_in(&src), orig_dst))
}

// --- слушатель -------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub async fn run_transparent_udp(
    listen_host: &str,
    port: u16,
    is_enabled: bool,
    bypass_domains: Arc<HashSet<String>>,
    junk: Socks5JunkParams,
    log_tx: LogSender,
    metrics: Arc<Metrics>,
    token: CancellationToken,
    ip_cache: Arc<IpDomainCache>,
) {
    let Ok(host) = listen_host.parse::<Ipv4Addr>() else {
        log_t(&log_tx, LogLevel::Error, "log.tproxy_ipv4_only", vec![
            ("addr", listen_host.to_string()),
        ]);
        return;
    };
    let bind_to = SocketAddrV4::new(host, port);

    let socket = match transparent_socket(bind_to, true) {
        Ok(s) => s,
        Err(e) => {
            // Самая частая причина — отсутствие CAP_NET_ADMIN, и общее
            // «отказано в доступе» тут ничего не объясняет. Подсказываем
            // ровно ту команду, которой это лечится.
            if e.kind() == io::ErrorKind::PermissionDenied {
                log_t(&log_tx, LogLevel::Error, "log.tproxy_needs_cap", vec![
                    ("error", e.to_string()),
                ]);
            } else {
                log_t(&log_tx, LogLevel::Error, "log.bind_error", vec![
                    ("addr", bind_to.to_string()),
                    ("error", e.to_string()),
                ]);
            }
            return;
        }
    };

    let async_fd = match AsyncFd::new(socket) {
        Ok(fd) => Arc::new(fd),
        Err(e) => {
            log_t(&log_tx, LogLevel::Error, "log.bind_error", vec![
                ("addr", bind_to.to_string()),
                ("error", e.to_string()),
            ]);
            return;
        }
    };

    metrics.set_transparent_udp_listening(true);
    log_t(&log_tx, LogLevel::Success, "log.tproxy_listening", vec![
        ("addr", bind_to.to_string()),
    ]);

    let sessions: Arc<Mutex<HashMap<SessionKey, Session>>> = Arc::new(Mutex::new(HashMap::new()));
    spawn_gc(Arc::clone(&sessions), Arc::clone(&metrics), token.clone());

    let mut buf = [0u8; MAX_DATAGRAM];

    loop {
        let readable = tokio::select! {
            _ = token.cancelled() => break,
            r = async_fd.readable() => r,
        };

        let mut guard = match readable {
            Ok(g) => g,
            Err(e) => {
                log_t(&log_tx, LogLevel::Error, "log.udp_error", vec![("error", e.to_string())]);
                break;
            }
        };

        // try_io снимает готовность, если ядро вернуло EWOULDBLOCK, —
        // иначе цикл крутился бы вхолостую на ложном пробуждении.
        let received = match guard.try_io(|inner| recv_with_orig_dst(inner.get_ref(), &mut buf)) {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => {
                log_t(&log_tx, LogLevel::Warning, "log.udp_error", vec![("error", e.to_string())]);
                continue;
            }
            Err(_would_block) => continue,
        };

        let (len, client_addr, orig_dst) = received;
        let payload = buf[..len].to_vec();

        metrics.add_rx(len as u64);

        handle_datagram(
            payload,
            client_addr,
            orig_dst,
            is_enabled,
            &bypass_domains,
            &junk,
            &sessions,
            &log_tx,
            &metrics,
            &token,
            &ip_cache,
        )
        .await;
    }

    metrics.set_transparent_udp_listening(false);
}

#[allow(clippy::too_many_arguments)]
async fn handle_datagram(
    payload: Vec<u8>,
    client_addr: SocketAddr,
    orig_dst: SocketAddr,
    is_enabled: bool,
    bypass_domains: &Arc<HashSet<String>>,
    junk: &Socks5JunkParams,
    sessions: &Arc<Mutex<HashMap<SessionKey, Session>>>,
    log_tx: &LogSender,
    metrics: &Arc<Metrics>,
    token: &CancellationToken,
    ip_cache: &Arc<IpDomainCache>,
) {
    let key: SessionKey = (client_addr, orig_dst);
    let mut table = sessions.lock().await;

    if let Some(session) = table.get(&key) {
        if !session.cancel.is_cancelled() {
            if let Ok(mut seen) = session.last_seen.lock() {
                *seen = Instant::now();
            }
            session::enqueue(&session.sender, payload);
            return;
        }
        // Обратный путь умер — сессию открываем заново.
        if let Some(dead) = table.remove(&key)
            && dead.is_quic
        {
            metrics.quic_session_closed();
        }
    }

    // Имя домена в QUIC зашифровано, поэтому решение об обходе
    // принимается по адресу — через кэш «адрес → домен». Его наполняют
    // DoH-релей и прозрачный TCP-режим (по SNI): браузер обычно сначала
    // открывает сайт по TCP и лишь потом переходит на QUIC.
    let domain = ip_cache.lookup(&orig_dst.ip());

    // Здесь блокировка по кэшу допустима, в отличие от TCP: если адрес
    // общий и кэш ошибся, браузер просто откатится на TCP, где имя видно
    // в SNI. Сессия не открывается — следующие датаграммы придут сюда же
    // и отбросятся так же дёшево. В лог — только первая, по Initial:
    // повторы браузера и хвосты старых соединений его бы засыпали.
    if let Some(d) = &domain
        && crate::block::is_blocked(d)
    {
        if session::is_quic_initial(&payload) {
            log_t(log_tx, LogLevel::Info, "log.blocked", vec![
                ("domain", d.clone()),
                ("via", "QUIC".to_string()),
            ]);
        }
        return;
    }

    let bypass = match &domain {
        Some(d) => needs_bypass(is_enabled, d, bypass_domains),
        None => false,
    };
    let is_quic = session::is_quic_initial(&payload);
    let junk_plan = bypass.then(|| (junk.clone(), is_quic));

    let Some(session) = open_session(client_addr, orig_dst, is_quic, junk_plan, log_tx, metrics, token).await else {
        return;
    };

    if is_quic {
        metrics.quic_session_opened();
    }
    log_t(log_tx, LogLevel::Info, "log.tproxy_session", vec![
        ("addr", orig_dst.to_string()),
        ("domain", domain.unwrap_or_else(|| orig_dst.ip().to_string())),
        ("bypass", bypass.to_string()),
    ]);

    // Первая датаграмма встаёт в очередь за мусором: задача отправки
    // сначала отработает мусор, потом её — цикл приёма не ждёт ни того,
    // ни другого.
    session::enqueue(&session.sender, payload);
    table.insert(key, session);
}

/// Поднимает пару сокетов под новую сессию и запускает оба направления.
async fn open_session(
    client_addr: SocketAddr,
    orig_dst: SocketAddr,
    is_quic: bool,
    junk: Option<(Socks5JunkParams, bool)>,
    log_tx: &LogSender,
    metrics: &Arc<Metrics>,
    token: &CancellationToken,
) -> Option<Session> {
    let (SocketAddr::V4(client_v4), SocketAddr::V4(dst_v4)) = (client_addr, orig_dst) else {
        return None;
    };

    // Исходящий — обычный сокет: наружу мы идём от своего адреса, и
    // никаких особых прав для этого не нужно.
    let upstream = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            log_t(log_tx, LogLevel::Error, "log.bind_error", vec![
                ("addr", "0.0.0.0:0".to_string()),
                ("error", e.to_string()),
            ]);
            return None;
        }
    };
    if let Err(e) = upstream.connect(orig_dst).await {
        log_t(log_tx, LogLevel::Warning, "log.tproxy_forward_error", vec![
            ("addr", orig_dst.to_string()),
            ("error", e.to_string()),
        ]);
        return None;
    }

    // Обратный — привязан к АДРЕСУ СЕРВЕРА: клиент ждёт ответ оттуда,
    // с любого другого адреса он его отбросит.
    let reply = match transparent_socket(dst_v4, false) {
        Ok(s) => s,
        Err(e) => {
            log_t(log_tx, LogLevel::Warning, "log.tproxy_reply_bind_error", vec![
                ("addr", dst_v4.to_string()),
                ("error", e.to_string()),
            ]);
            return None;
        }
    };
    let reply = match UdpSocket::from_std(reply) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            log_t(log_tx, LogLevel::Warning, "log.tproxy_reply_bind_error", vec![
                ("addr", dst_v4.to_string()),
                ("error", e.to_string()),
            ]);
            return None;
        }
    };

    let last_seen = Arc::new(std::sync::Mutex::new(Instant::now()));
    let cancel = token.child_token();

    tokio::spawn(return_path(
        Arc::clone(&upstream),
        reply,
        SocketAddr::V4(client_v4),
        Arc::clone(&last_seen),
        Arc::clone(metrics),
        cancel.clone(),
    ));

    let sender = session::spawn_writer(
        upstream,
        junk,
        Arc::clone(metrics),
        cancel.clone(),
        WriterLog {
            log_tx: log_tx.clone(),
            addr: orig_dst,
            forward_error_key: "log.tproxy_forward_error",
            junk_sent_key: None,
        },
    );

    Some(Session { sender, last_seen, cancel, is_quic })
}

async fn return_path(
    upstream: Arc<UdpSocket>,
    reply: Arc<UdpSocket>,
    client_addr: SocketAddr,
    last_seen: Arc<std::sync::Mutex<Instant>>,
    metrics: Arc<Metrics>,
    cancel: CancellationToken,
) {
    let mut buf = vec![0u8; MAX_DATAGRAM];

    loop {
        let n = tokio::select! {
            _ = cancel.cancelled() => break,
            r = upstream.recv(&mut buf) => match r {
                Ok(n) => n,
                // Разовый ICMP-отказ не повод хоронить сессию.
                Err(e) if super::socks5::udp::is_transient_udp_error(&e) => continue,
                Err(_) => break,
            },
        };

        if reply.send_to(&buf[..n], client_addr).await.is_err() {
            break;
        }

        metrics.add_tx(n as u64);
        if let Ok(mut seen) = last_seen.lock() {
            *seen = Instant::now();
        }
    }

    // Сессия без обратного пути мертва: отмена останавливает отправку и
    // подсказывает `handle_datagram` открыть её заново.
    cancel.cancel();
}

fn spawn_gc(
    sessions: Arc<Mutex<HashMap<SessionKey, Session>>>,
    metrics: Arc<Metrics>,
    token: CancellationToken,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = token.cancelled() => break,
                _ = tokio::time::sleep(GC_INTERVAL) => {
                    let now = Instant::now();
                    let mut closed = 0usize;

                    let mut table = sessions.lock().await;
                    table.retain(|_, session| {
                        let last = session.last_seen.lock().map(|s| *s).unwrap_or(now);
                        let alive = now.duration_since(last) < SESSION_TIMEOUT;
                        if !alive {
                            session.cancel.cancel();
                            if session.is_quic {
                                closed += 1;
                            }
                        }
                        alive
                    });
                    drop(table);

                    for _ in 0..closed {
                        metrics.quic_session_closed();
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sockaddr_conversion_round_trips() {
        let addr = SocketAddrV4::new(Ipv4Addr::new(142, 250, 74, 46), 443);
        let raw = to_sockaddr_in(addr);

        // Поля должны лежать в сетевом порядке байт
        assert_eq!(raw.sin_port, 443u16.to_be());
        assert_eq!(raw.sin_family, libc::AF_INET as libc::sa_family_t);
        assert_eq!(from_sockaddr_in(&raw), SocketAddr::V4(addr));
    }

    #[test]
    fn transparent_socket_reports_missing_capability() {
        // Под обычным пользователем IP_TRANSPARENT недоступен, и это должно
        // быть честной ошибкой, а не паникой: вызывающий код показывает
        // подсказку про setcap и оставляет TCP-часть работать.
        let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0);
        match transparent_socket(addr, true) {
            Err(e) => assert_eq!(
                e.kind(),
                io::ErrorKind::PermissionDenied,
                "ожидали отказ по правам, получили: {e}"
            ),
            // Тест гоняют и от root (в контейнерах CI) — тогда сокет создастся.
            Ok(sock) => assert!(sock.local_addr().is_ok()),
        }
    }
}
