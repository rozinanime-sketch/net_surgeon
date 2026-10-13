//! Пределы на одновременные TCP-соединения, UDP-сессии и DNS-запросы.
//!
//! Без них число задач и сокетов ничем не ограничено. Программа, открывшая
//! тысячи соединений (торрент, сканер, зациклившийся клиент), выбирала
//! лимит дескрипторов процесса — 1024 по умолчанию в Linux. Дальше `accept`
//! отвечал EMFILE сразу, цикл приёма крутился вхолостую и засыпал лог, а
//! новые соединения не открывались ни у кого, включая браузер.
//!
//! Пределы общие на все слушатели: дескрипторы у процесса одни. Сверх
//! предела новое отклоняется сразу — уже идущие соединения не страдают.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::observability::logging::{log_t, LogLevel, LogSender};

/// Сколько дескрипторов оставить на всё прочее: файлы данных, DoH-клиент,
/// пробы диагностики, слушатели.
const FD_RESERVE: u64 = 256;

/// Верхние пределы — даже если дескрипторов хватает на больше: за ними уже
/// память на буферы пересылки (по 32 КБ на соединение).
const TCP_CEILING: usize = 8192;
const UDP_CEILING: usize = 4096;
/// Нижние — чтобы при скупом лимите прокси всё же работал.
const TCP_FLOOR: usize = 128;
const UDP_FLOOR: usize = 64;

/// DNS-запросы в работе. Каждый — задача и поход к DoH; браузер отправляет
/// десятки разом, а тысячи — это уже не браузер.
const DNS_IN_FLIGHT: usize = 512;

/// Пауза после ошибки `accept`. EMFILE возвращается мгновенно, и без паузы
/// цикл приёма занимал ядро процессора целиком.
pub(crate) const ACCEPT_ERROR_PAUSE: Duration = Duration::from_millis(100);

/// Место под соединение или сессию; освобождается, когда его отпускают.
pub(crate) type Slot = OwnedSemaphorePermit;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Tcp,
    Udp,
    Dns,
}

struct Limits {
    tcp: Arc<Semaphore>,
    udp: Arc<Semaphore>,
    dns: Arc<Semaphore>,
    /// Сами пределы — для предупреждения.
    tcp_max: usize,
    udp_max: usize,
}

fn limits() -> &'static Limits {
    static LIMITS: OnceLock<Limits> = OnceLock::new();
    LIMITS.get_or_init(|| {
        let (tcp, udp) = split_budget(fd_limit());
        Limits {
            tcp: Arc::new(Semaphore::new(tcp)),
            udp: Arc::new(Semaphore::new(udp)),
            dns: Arc::new(Semaphore::new(DNS_IN_FLIGHT)),
            tcp_max: tcp,
            udp_max: udp,
        }
    })
}

/// Делит дескрипторы между TCP и UDP. TCP-соединение занимает два (клиент и
/// сервер), UDP-сессия — один-два; половина бюджета TCP, четверть UDP,
/// остальное — запас.
fn split_budget(fds: Option<u64>) -> (usize, usize) {
    let Some(fds) = fds else {
        return (TCP_CEILING, UDP_CEILING);
    };
    let budget = fds.saturating_sub(FD_RESERVE) as usize;
    ((budget / 4).clamp(TCP_FLOOR, TCP_CEILING), (budget / 8).clamp(UDP_FLOOR, UDP_CEILING))
}

/// Лимит дескрипторов процесса; `None` — у системы его нет (Windows).
#[cfg(unix)]
#[allow(clippy::unnecessary_cast)] // rlim_t — u64 не на всех системах
fn fd_limit() -> Option<u64> {
    let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: getrlimit только пишет в переданную структуру.
    (unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } == 0).then_some(lim.rlim_cur as u64)
}

#[cfg(not(unix))]
fn fd_limit() -> Option<u64> {
    None
}

/// Поднимает мягкий лимит дескрипторов до жёсткого. Мягкий в Linux — 1024,
/// жёсткий обычно в сотни раз больше, и поднять его до жёсткого может любой
/// процесс без прав. Так делают Go, nginx и прочие серверы. Вызывать до
/// первого соединения: пределы считаются от лимита один раз.
#[cfg(unix)]
pub fn raise_fd_limit() {
    let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: обе функции работают только с переданной структурой.
    unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) == 0 && lim.rlim_cur < lim.rlim_max {
            lim.rlim_cur = lim.rlim_max;
            libc::setrlimit(libc::RLIMIT_NOFILE, &lim);
        }
    }
}

#[cfg(not(unix))]
pub fn raise_fd_limit() {}

fn take(kind: Kind, log_tx: &LogSender) -> Option<Slot> {
    let l = limits();
    let sem = match kind {
        Kind::Tcp => &l.tcp,
        Kind::Udp => &l.udp,
        Kind::Dns => &l.dns,
    };
    let slot = Arc::clone(sem).try_acquire_owned().ok();
    if slot.is_none() {
        warn_full(kind, log_tx);
    }
    slot
}

/// Место под TCP-соединение; `None` — предел достигнут, соединение закрыть.
pub(crate) fn tcp_slot(log_tx: &LogSender) -> Option<Slot> {
    take(Kind::Tcp, log_tx)
}

/// Место под новую UDP-сессию; `None` — датаграмму отбросить.
pub(crate) fn udp_slot(log_tx: &LogSender) -> Option<Slot> {
    take(Kind::Udp, log_tx)
}

/// Место под DNS-запрос; `None` — запрос отбросить, клиент повторит.
pub(crate) fn dns_slot(log_tx: &LogSender) -> Option<Slot> {
    take(Kind::Dns, log_tx)
}

/// Предупреждение о пределе — не чаще раза в 10 секунд на вид: упираются в
/// него лавиной, и строка на каждое отклонённое соединение утопила бы лог.
fn warn_full(kind: Kind, log_tx: &LogSender) {
    const EVERY_SECS: u64 = 10;
    static LAST: [AtomicU64; 3] = [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];
    let (idx, key, limit) = match kind {
        Kind::Tcp => (0, "log.limit_tcp", limits().tcp_max),
        Kind::Udp => (1, "log.limit_udp", limits().udp_max),
        Kind::Dns => (2, "log.limit_dns", DNS_IN_FLIGHT),
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let last = LAST[idx].load(Ordering::Relaxed);
    if now.saturating_sub(last) >= EVERY_SECS
        && LAST[idx].compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed).is_ok()
    {
        log_t(log_tx, LogLevel::Warning, key, vec![("limit", limit.to_string())]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_follows_the_descriptor_limit() {
        // Мягкий лимит Linux по умолчанию: пределы меньше него с запасом
        let (tcp, udp) = split_budget(Some(1024));
        assert_eq!((tcp, udp), (192, 96));
        assert!(2 * tcp + 2 * udp + FD_RESERVE as usize <= 1024);
        // Лимит поднят до жёсткого — упираемся в потолки
        assert_eq!(split_budget(Some(1_048_576)), (TCP_CEILING, UDP_CEILING));
        // Скупой лимит — всё равно хоть что-то
        assert_eq!(split_budget(Some(100)), (TCP_FLOOR, UDP_FLOOR));
        // Лимита нет
        assert_eq!(split_budget(None), (TCP_CEILING, UDP_CEILING));
    }
}
