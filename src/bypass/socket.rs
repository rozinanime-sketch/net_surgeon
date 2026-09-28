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
//! и приманка fake остаются заглушками: в Windows исходный адрес прозрачного
//! режима даёт сам перехват (`windivert::original_dst`), он же вставляет
//! приманку (`windivert::desync`).

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

// --- Приманка fake: подмена данных под ретрансмит ---
//
// Приманка должна занять в потоке ровно те номера, что и настоящий
// ClientHello: DPI, который собирает поток, запоминает первое, что увидел
// на этих номерах, а повтор считает ретрансмитом и не разбирает. Раньше
// номер пытались отмотать назад через TCP_REPAIR, но на живом соединении
// ядро этого не даёт даже с CAP_NET_ADMIN (EPERM, проверено на 7.2).
//
// Приём из ByeDPI (`desync.c`, `send_fake`) обходится без отмотки и без
// привилегий. Данные отдаются сокету через `vmsplice` + `splice`, то есть
// без копирования: очередь отправки ссылается прямо на нашу страницу
// памяти. Сначала там лежит приманка, и она уходит с низким TTL. Сервер
// её не получает и не подтверждает. Когда она ушла, страница
// перезаписывается настоящим ClientHello, и ядро, повторяя
// неподтверждённое, отправляет уже его — с теми же номерами и обычным TTL.

/// Сколько ждать, пока приманка покинет очередь отправки. Обычно это
/// доли миллисекунды: буфер сокета в начале соединения пуст.
#[cfg(any(target_os = "linux", target_os = "android"))]
const FAKE_SEND_WAIT: std::time::Duration = std::time::Duration::from_millis(500);

/// `SIOCOUTQNSD` из `linux/sockios.h`: байты очереди, ещё не отправленные
/// ни разу. Крейт `libc` её не экспортирует.
#[cfg(any(target_os = "linux", target_os = "android"))]
const SIOCOUTQNSD: libc::c_ulong = 0x894B;

#[cfg(any(target_os = "linux", target_os = "android"))]
fn unsent_bytes(fd: RawSock) -> Option<libc::c_int> {
    let mut n: libc::c_int = 0;
    let rc = unsafe { libc::ioctl(fd, SIOCOUTQNSD as _, &mut n) };
    (rc == 0).then_some(n)
}

/// Включает (`key_len` > 0) или снимает (0) TCP-подпись MD5 для пакетов к
/// собеседнику сокета. Ключ из нулей: его всё равно никто не проверяет, а
/// сервер без ключа пакет с такой опцией выбрасывает (как в ByeDPI,
/// `set_md5sig`).
#[cfg(any(target_os = "linux", target_os = "android"))]
fn set_md5sig(fd: RawSock, key_len: u16) -> bool {
    /// `struct tcp_md5sig` из `linux/tcp.h`; крейт `libc` её не экспортирует.
    #[repr(C)]
    struct TcpMd5Sig {
        addr: libc::sockaddr_storage,
        flags: u8,
        prefixlen: u8,
        keylen: u16,
        ifindex: libc::c_int,
        key: [u8; 80],
    }

    let mut md5: TcpMd5Sig = unsafe { std::mem::zeroed() };
    md5.keylen = key_len;
    let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let rc = unsafe { libc::getpeername(fd, (&mut md5.addr as *mut libc::sockaddr_storage).cast(), &mut len) };
    if rc != 0 {
        return false;
    }
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_MD5SIG,
            (&md5 as *const TcpMd5Sig).cast(),
            std::mem::size_of::<TcpMd5Sig>() as libc::socklen_t,
        )
    };
    rc == 0
}

/// Отправляет `decoy` с TTL `ttl` так, что ядро потом повторит на тех же
/// номерах `real`. Длины должны совпадать. `md5sig` — вдобавок пометить
/// приманку MD5-подписью (см. [`set_md5sig`]); повтор уходит уже без неё.
///
/// `Ok(false)` — техника здесь не сработала до отправки чего-либо (не та
/// длина, не вышло выделить память или сменить TTL): вызывающий может
/// откатиться на другую. Ошибка — приманка могла уйти частично, и
/// соединение лучше не продолжать.
///
/// Настоящие данные уходят только ретрансмитом, поэтому соединение
/// начинается позже на время RTO: у Linux не меньше 200 мс.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub async fn send_fake(fd: RawSock, decoy: &[u8], real: &[u8], ttl: u32, md5sig: bool) -> std::io::Result<bool> {
    if decoy.len() != real.len() || decoy.is_empty() {
        return Ok(false);
    }
    let Some(page) = FakePage::new(decoy) else {
        return Ok(false);
    };

    let original_ttl = get_ttl(fd).unwrap_or(64);
    if !set_ttl(fd, ttl) {
        return Ok(false);
    }
    if md5sig && !set_md5sig(fd, 5) {
        // Ядро без CONFIG_TCP_MD5SIG или запрет на живом соединении: без
        // подписи приманка дошла бы до сервера — лучше не отправлять вовсе.
        set_ttl(fd, original_ttl);
        return Ok(false);
    }

    let sent = splice_page(fd, &page).await;
    if sent.is_ok() {
        // TTL берётся в момент передачи, а не записи в очередь: вернуть его
        // раньше — и приманка уйдёт с обычным и дойдёт до сервера.
        let deadline = std::time::Instant::now() + FAKE_SEND_WAIT;
        while unsent_bytes(fd).is_some_and(|n| n > 0) && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    }
    // Если приманка так и не ушла, подмена безвредна: уйдут сразу настоящие
    // данные, просто без обмана DPI.
    page.overwrite(real);
    // Подпись снимается вместе с TTL: повтор с настоящими данными сервер
    // должен принять.
    let unsigned = !md5sig || set_md5sig(fd, 0);
    let restored = set_ttl(fd, original_ttl) && unsigned;

    sent?;
    if !restored {
        return Err(std::io::Error::other(rust_i18n::t!(
            "err.ttl_restore",
            ttl = original_ttl,
            error = std::io::Error::last_os_error()
        ).into_owned()));
    }
    Ok(true)
}

/// Страница с данными приманки. Освобождается при любом исходе; очередь
/// отправки держит на неё свою ссылку, так что munmap не отнимет данные у
/// ретрансмита.
#[cfg(any(target_os = "linux", target_os = "android"))]
struct FakePage {
    ptr: *mut libc::c_void,
    len: usize,
}

// SAFETY: страница принадлежит только этой структуре, а пишется через
// `&mut`-свободный `overwrite` строго после того, как ушла приманка.
#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe impl Send for FakePage {}
#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe impl Sync for FakePage {}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl FakePage {
    fn new(data: &[u8]) -> Option<FakePage> {
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                data.len(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return None;
        }
        let page = FakePage { ptr, len: data.len() };
        page.overwrite(data);
        Some(page)
    }

    /// Длина задана при создании, лишнее отбрасывается.
    fn overwrite(&self, data: &[u8]) {
        let n = data.len().min(self.len);
        unsafe { std::ptr::copy_nonoverlapping(data.as_ptr(), self.ptr.cast::<u8>(), n) };
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl Drop for FakePage {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.ptr, self.len) };
    }
}

/// Передаёт страницу сокету без копирования: `vmsplice` кладёт в канал
/// ссылку на неё, `splice` переносит ссылку в очередь сокета.
#[cfg(any(target_os = "linux", target_os = "android"))]
async fn splice_page(fd: RawSock, page: &FakePage) -> std::io::Result<()> {
    let mut pipe = [0 as libc::c_int; 2];
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    struct Close([libc::c_int; 2]);
    impl Drop for Close {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.0[0]);
                libc::close(self.0[1]);
            }
        }
    }
    let _close = Close(pipe);

    let len = page.len;
    // iovec держит сырой указатель: он не должен дожить до await ниже.
    let queued = {
        let iov = libc::iovec { iov_base: page.ptr, iov_len: len };
        unsafe { libc::vmsplice(pipe[1], &iov, 1, libc::SPLICE_F_GIFT) }
    };
    if queued < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Канал вмещает 64 КиБ, ClientHello — пару килобайт: vmsplice берёт
    // всё сразу. Иначе часть приманки ушла бы обычной записью, мимо подмены.
    if queued as usize != len {
        return Err(std::io::Error::other(rust_i18n::t!("err.fake_splice").into_owned()));
    }

    let mut left = len;
    for _ in 0..100 {
        let n = unsafe { libc::splice(pipe[0], std::ptr::null_mut(), fd, std::ptr::null_mut(), left, 0) };
        if n > 0 {
            left -= n as usize;
            if left == 0 {
                return Ok(());
            }
            continue;
        }
        let err = std::io::Error::last_os_error();
        // Сокет неблокирующий: буфер занят — уступаем рантайму и пробуем снова.
        if n < 0 && err.kind() == std::io::ErrorKind::WouldBlock {
            tokio::task::yield_now().await;
            continue;
        }
        return Err(err);
    }
    Err(std::io::Error::other(rust_i18n::t!("err.fake_splice").into_owned()))
}

/// Может ли техника fake сработать на сокете прокси.
///
/// В Linux и Android — да, см. [`send_fake`]. В Windows сокетом так не
/// сделать, там приманку вставляет перехват пакетов (`windivert::desync`).
pub const fn fake_supported() -> bool {
    cfg!(any(target_os = "linux", target_os = "android"))
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub async fn send_fake(_fd: RawSock, _decoy: &[u8], _real: &[u8], _ttl: u32, _md5sig: bool) -> std::io::Result<bool> {
    Ok(false)
}
