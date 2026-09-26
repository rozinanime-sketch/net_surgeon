//! Низкоуровневые операции над сокетом, нужные техникам десинхронизации.
//!
//! Всё это userspace: `setsockopt` и `send` с флагом, никаких raw-сокетов,
//! NFQUEUE и прав root.
//!
//! # Платформа
//!
//! Реализация Linux-специфична: `SO_DOMAIN` есть только в Linux и Android,
//! `TCP_WINDOW_CLAMP` — тоже. Раньше это было неявным: код просто не собрался
//! бы на других системах, хотя ничто об этом не предупреждало.
//!
//! Теперь платформенная часть отделена явно, а на остальных системах функции
//! возвращают «не поддерживается». Вызывающий код это уже умеет обрабатывать:
//! техника откатывается на обычный сплит, а не падает. Так порт на другую ОС
//! становится задачей «дописать реализацию», а не «понять, почему не собирается».
//!
//! На Windows TTL и OOB дописаны через `socket2`: `IP_TTL`,
//! `IPV6_UNICAST_HOPS` и `MSG_OOB` в Winsock есть. `SO_DOMAIN` там нет,
//! поэтому семейство берётся из локального адреса сокета. `SO_ORIGINAL_DST`
//! и `TCP_REPAIR` остаются заглушками: прозрачного режима на Windows пока нет.

/// Сокет в том виде, в каком его знает система: номер файла в Unix,
/// `SOCKET` в Windows. Техники получают его до разделения потока на половины,
/// потому что половины tokio сокет наружу не отдают.
#[cfg(unix)]
pub type RawSock = std::os::fd::RawFd;
#[cfg(windows)]
pub type RawSock = std::os::windows::io::RawSocket;

/// Сокет потока для техник ниже. Одна функция вместо `as_raw_fd` в каждом
/// месте вызова: иначе каждое из них пришлось бы размечать под две системы.
#[cfg(unix)]
pub fn raw_sock(stream: &impl std::os::fd::AsRawFd) -> RawSock {
    stream.as_raw_fd()
}

#[cfg(windows)]
pub fn raw_sock(stream: &impl std::os::windows::io::AsRawSocket) -> RawSock {
    stream.as_raw_socket()
}

/// Доступны ли на этой платформе техники, требующие управления TTL и OOB.
/// Диагностика может пропускать соответствующие пробы, а не тратить время
/// на заведомо неуспешные попытки.
pub const fn supports_ttl_tricks() -> bool {
    cfg!(any(target_os = "linux", target_os = "android", windows))
}

/// Номер опции `SO_ORIGINAL_DST`. Крейт `libc` её не экспортирует,
/// поэтому значение берётся из заголовков ядра (`linux/netfilter_ipv4.h`).
#[cfg(any(target_os = "linux", target_os = "android"))]
const SO_ORIGINAL_DST: libc::c_int = 80;

/// Один запрос `SO_ORIGINAL_DST` на заданном уровне протокола.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn original_dst_at(fd: RawSock, level: libc::c_int) -> Option<libc::sockaddr_storage> {
    // sockaddr_storage, а не sockaddr_in: он достаточно велик и для IPv6,
    // а ядро само скажет семейство через ss_family.
    let mut addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

    let rc = unsafe {
        libc::getsockopt(
            fd,
            level,
            SO_ORIGINAL_DST,
            &mut addr as *mut libc::sockaddr_storage as *mut libc::c_void,
            &mut len,
        )
    };

    (rc == 0).then_some(addr)
}

/// Исходный адрес назначения для соединения, перенаправленного iptables.
///
/// В обычном прокси адрес приходит от клиента (`CONNECT host:443`), но в
/// прозрачном режиме клиент не знает, что говорит с прокси, — он думает,
/// что подключается к серверу. Ядро сохраняет настоящий адрес назначения
/// в conntrack, и `SO_ORIGINAL_DST` его возвращает.
///
/// Имя домена берётся отдельно — из SNI в ClientHello, парсером из
/// `bypass::tls`. Поэтому прозрачный режим не требует ни CONNECT,
/// ни настройки прокси в приложениях.
///
/// Linux-специфично, как и остальное в этом модуле.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn original_dst(fd: RawSock) -> Option<std::net::SocketAddr> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    // Спрашиваем оба уровня: у IPv6-соединения conntrack отвечает только на
    // SOL_IPV6, и прежняя версия, знавшая лишь SOL_IP с sockaddr_in, на нём
    // молча возвращала None — прозрачный режим для IPv6 не работал вообще.
    let addr = original_dst_at(fd, libc::SOL_IP)
        .or_else(|| original_dst_at(fd, libc::IPPROTO_IPV6))?;

    // Поля conntrack приходят в сетевом порядке байт.
    match addr.ss_family as libc::c_int {
        libc::AF_INET => {
            let v4 = unsafe { *(&addr as *const libc::sockaddr_storage as *const libc::sockaddr_in) };
            Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(u32::from_be(v4.sin_addr.s_addr))),
                u16::from_be(v4.sin_port),
            ))
        }
        libc::AF_INET6 => {
            let v6 = unsafe { *(&addr as *const libc::sockaddr_storage as *const libc::sockaddr_in6) };
            Some(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(v6.sin6_addr.s6_addr)),
                u16::from_be(v6.sin6_port),
            ))
        }
        _ => None,
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn original_dst(_fd: RawSock) -> Option<std::net::SocketAddr> {
    None
}

/// Определяет семейство адресов сокета, чтобы выбрать правильную опцию TTL:
/// у IPv4 это `IP_TTL`, у IPv6 — `IPV6_UNICAST_HOPS`.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn socket_domain(fd: RawSock) -> Option<libc::c_int> {
    let mut domain: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;

    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_DOMAIN,
            &mut domain as *mut libc::c_int as *mut libc::c_void,
            &mut len,
        )
    };

    (rc == 0).then_some(domain)
}

/// Текущий TTL (или hop limit) сокета.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn get_ttl(fd: RawSock) -> Option<u32> {
    let (level, name) = match socket_domain(fd)? {
        libc::AF_INET6 => (libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS),
        _ => (libc::IPPROTO_IP, libc::IP_TTL),
    };

    let mut ttl: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;

    let rc = unsafe {
        libc::getsockopt(fd, level, name, &mut ttl as *mut libc::c_int as *mut libc::c_void, &mut len)
    };

    (rc == 0).then_some(ttl as u32)
}

/// Устанавливает TTL. Возвращает false, если ядро отказало.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn set_ttl(fd: RawSock, ttl: u32) -> bool {
    let Some(domain) = socket_domain(fd) else {
        return false;
    };
    let (level, name) = match domain {
        libc::AF_INET6 => (libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS),
        _ => (libc::IPPROTO_IP, libc::IP_TTL),
    };

    let value = ttl as libc::c_int;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &value as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    rc == 0
}

/// Отправляет один байт как out-of-band (флаг URG).
///
/// Получатель без `SO_OOBINLINE` этот байт отбрасывает — до сервера он
/// не доходит как данные. А DPI, читающий поток последовательно, обычно
/// учитывает его наравне с остальными байтами, и разбор смещается.
///
/// Пишем напрямую через `libc::send`, минуя tokio: флага `MSG_OOB` в его
/// API нет. Сокет неблокирующий, поэтому `EAGAIN` возможен — на свежем
/// соединении буфер почти наверняка свободен, но случай обрабатывается.
///
/// Функция async ради единственной вещи: уступить управление рантайму между
/// попытками. Раньше здесь стоял `std::thread::yield_now()`, который на
/// воркере tokio не отдаёт задачу планировщику, а просто крутит поток —
/// то есть на заполненном буфере тормозил все соединения этого воркера.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub async fn send_oob(fd: RawSock, byte: u8) -> std::io::Result<()> {
    let buf = [byte];

    for _ in 0..3 {
        let sent = unsafe {
            libc::send(fd, buf.as_ptr() as *const libc::c_void, 1, libc::MSG_OOB)
        };

        if sent == 1 {
            return Ok(());
        }

        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::WouldBlock {
            return Err(err);
        }

        tokio::task::yield_now().await;
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::WouldBlock,
        rust_i18n::t!("err.oob_busy").into_owned(),
    ))
}

// --- Windows: те же TTL и OOB через socket2 ---

/// Одалживает сокет у вызывающего на время `f`.
///
/// Закрывать его здесь нельзя, он принадлежит потоку tokio. Поэтому
/// `BorrowedSocket`, а не `Socket::from_raw_socket`: у второго `Drop`
/// закрыл бы чужой сокет.
#[cfg(windows)]
fn with_sock<T>(sock: RawSock, f: impl FnOnce(socket2::SockRef<'_>) -> T) -> T {
    // SAFETY: вызывающий держит поток живым, пока идёт вызов, а сокет
    // из него взят через `raw_sock` того же потока.
    let borrowed = unsafe { std::os::windows::io::BorrowedSocket::borrow_raw(sock) };
    f(socket2::SockRef::from(&borrowed))
}

#[cfg(windows)]
fn is_ipv6(sock: &socket2::SockRef<'_>) -> Option<bool> {
    sock.local_addr().ok().map(|a| a.is_ipv6())
}

#[cfg(windows)]
pub fn get_ttl(sock: RawSock) -> Option<u32> {
    with_sock(sock, |s| {
        let ttl = if is_ipv6(&s)? { s.unicast_hops_v6() } else { s.ttl_v4() };
        ttl.ok()
    })
}

#[cfg(windows)]
pub fn set_ttl(sock: RawSock, ttl: u32) -> bool {
    with_sock(sock, |s| match is_ipv6(&s) {
        Some(true) => s.set_unicast_hops_v6(ttl).is_ok(),
        Some(false) => s.set_ttl_v4(ttl).is_ok(),
        None => false,
    })
}

/// То же, что версия для Linux: сокет неблокирующий, и на занятом буфере
/// Winsock отвечает `WSAEWOULDBLOCK`, которое std переводит в `WouldBlock`.
#[cfg(windows)]
pub async fn send_oob(sock: RawSock, byte: u8) -> std::io::Result<()> {
    for _ in 0..3 {
        match with_sock(sock, |s| s.send_out_of_band(&[byte])) {
            Ok(1) => return Ok(()),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }
        tokio::task::yield_now().await;
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::WouldBlock,
        rust_i18n::t!("err.oob_busy").into_owned(),
    ))
}

// --- Заглушки для платформ без нужных опций сокета ---
//
// Возвращают «не поддерживается», а не паникуют: техники disorder и oob
// в этом случае просто откатываются на обычный сплит.

#[cfg(not(any(target_os = "linux", target_os = "android", windows)))]
pub fn get_ttl(_fd: RawSock) -> Option<u32> {
    None
}

#[cfg(not(any(target_os = "linux", target_os = "android", windows)))]
pub fn set_ttl(_fd: RawSock, _ttl: u32) -> bool {
    false
}

#[cfg(not(any(target_os = "linux", target_os = "android", windows)))]
pub async fn send_oob(_fd: RawSock, _byte: u8) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        rust_i18n::t!("err.oob_unsupported").into_owned(),
    ))
}

// --- TCP_REPAIR: отмотка номера последовательности ---
//
// Нужна для техники fake: фальшивый ClientHello отправляется с низким TTL
// и до сервера не доходит, но байты уже заняли место в sequence space.
// Без отмотки сервер увидел бы дыру в нумерации и ждал бы недостающие
// данные вечно.
//
// Именно поэтому раньше я считал fake невозможным в userspace. Возможен —
// но ценой CAP_NET_ADMIN: TCP_REPAIR позволяет переписывать состояние
// TCP-соединения, и ядро справедливо не даёт этого без привилегий.

/// Опции из `linux/tcp.h`; крейт `libc` их не экспортирует.
///
/// Используются техникой fake (bypass::fragment::split_with_fake).
#[cfg(any(target_os = "linux", target_os = "android"))]
mod repair {
    pub const TCP_REPAIR: libc::c_int = 19;
    pub const TCP_REPAIR_QUEUE: libc::c_int = 20;
    pub const TCP_QUEUE_SEQ: libc::c_int = 21;
    pub const TCP_SEND_QUEUE: libc::c_int = 2;
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn set_int_opt(fd: RawSock, name: libc::c_int, value: libc::c_int) -> bool {
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            name,
            &value as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    rc == 0
}

/// Текущий номер последовательности очереди отправки.
///
/// `None` означает, что режим ремонта недоступен — почти всегда это
/// отсутствие `CAP_NET_ADMIN`. Вызывающий код тогда откатывается
/// на технику, не требующую привилегий.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn tcp_send_seq(fd: RawSock) -> Option<u32> {
    use repair::*;

    if !set_int_opt(fd, TCP_REPAIR, 1) {
        return None;
    }
    if !set_int_opt(fd, TCP_REPAIR_QUEUE, TCP_SEND_QUEUE) {
        set_int_opt(fd, TCP_REPAIR, 0);
        return None;
    }

    let mut seq: libc::c_uint = 0;
    let mut len = std::mem::size_of::<libc::c_uint>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            TCP_QUEUE_SEQ,
            &mut seq as *mut libc::c_uint as *mut libc::c_void,
            &mut len,
        )
    };

    // Режим ремонта снимаем сразу: пока он включён, запись в сокет
    // не уходит на провод, а складывается в очередь.
    set_int_opt(fd, TCP_REPAIR, 0);

    (rc == 0).then_some(seq as u32)
}

/// Возвращает номер последовательности к сохранённому значению.
///
/// После этого следующая запись переиспользует те же номера, то есть
/// перезаписывает фальшивые данные настоящими.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn set_tcp_send_seq(fd: RawSock, seq: u32) -> bool {
    use repair::*;

    if !set_int_opt(fd, TCP_REPAIR, 1) {
        return false;
    }
    let ok = set_int_opt(fd, TCP_REPAIR_QUEUE, TCP_SEND_QUEUE)
        && set_int_opt(fd, TCP_QUEUE_SEQ, seq as libc::c_int);
    set_int_opt(fd, TCP_REPAIR, 0);
    ok
}

/// Доступен ли режим ремонта вообще — без живого соединения.
///
/// Нужен диагностике: она решает, гонять ли пробы техники fake, ЕЩЁ ДО того,
/// как откроет сокет. Проверять на боевом соединении поздно — если прав нет,
/// проба отправит приманку, не сможет отмотать номер и испортит соединение
/// вместо того, чтобы честно сказать «техника недоступна».
///
/// Проверка делается на одноразовом сокете: `TCP_REPAIR` включается и на
/// неподключённом (на этом держится восстановление соединений в CRIU), а
/// отказ по правам приходит одинаково в любом состоянии.
///
/// Результат кэшируется: полномочия процесса за время работы не меняются,
/// а проба стоит двух системных вызовов на каждый домен.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn tcp_repair_available() -> bool {
    use std::sync::OnceLock;
    static AVAILABLE: OnceLock<bool> = OnceLock::new();

    *AVAILABLE.get_or_init(|| {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return false;
        }

        let ok = set_int_opt(fd, repair::TCP_REPAIR, 1);
        if ok {
            set_int_opt(fd, repair::TCP_REPAIR, 0);
        }
        unsafe { libc::close(fd) };
        ok
    })
}

/// Может ли техника fake вообще сработать.
///
/// Нет, и дело не в правах. Ей нужно после приманки вернуть номер
/// последовательности назад через `TCP_QUEUE_SEQ`, а ядро разрешает это
/// только сокету в состоянии CLOSE — то есть при восстановлении соединения
/// (CRIU), но не на живом. На установленном соединении вызов возвращает
/// EPERM даже с CAP_NET_ADMIN (проверено на 7.2). В итоге каждая проба
/// отправляла приманку, падала и теряла соединение.
///
/// Пока нет способа писать сырые пакеты с неверным номером (NFQUEUE,
/// raw-сокет), техника выключена целиком — и в диагностике, и в бою.
pub const fn fake_supported() -> bool {
    false
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn tcp_repair_available() -> bool {
    false
}


#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn tcp_send_seq(_fd: RawSock) -> Option<u32> {
    None
}


#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn set_tcp_send_seq(_fd: RawSock, _seq: u32) -> bool {
    false
}

