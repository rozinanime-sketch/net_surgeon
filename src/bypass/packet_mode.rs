//! Обход на уровне пакетов (перехват WinDivert в Windows) и собственные
//! соединения программы.
//!
//! Перехват пакетов видит ClientHello всех программ машины, включая эту.
//! Соединения прокси уже обойдены на сокете, и трогать их второй раз
//! нельзя; пробы диагностики, наоборот, должны получить ровно ту технику,
//! которую меряют. Отличить их по пакету невозможно, поэтому программа
//! сама помечает свои соединения по локальному порту до отправки первого
//! байта, а перехват забирает метку, когда видит ClientHello с этого порта.
//!
//! Раньше свои соединения узнавались по таблице сокетов Windows, которую
//! приходилось перебирать на каждое новое соединение машины.
//!
//! Модуль общий для всех систем: вызовы в прокси и диагностике не
//! обрастают условиями компиляции, а без перехвата ничего не делают.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::engine::strategy::Strategy;

/// Чья метка.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    /// Соединение прокси: обход уже сделан на сокете, пакет не трогать.
    Own,
    /// Проба диагностики: применить эту технику и ничего не записывать.
    Probe(Strategy),
}

/// fwmark пакетного режима Linux (skb mark, а не метка по порту выше).
/// Значения согласованы с правилом nftables (`firewall.rs`) и рантаймом
/// (`crate::nfqueue`); держим их здесь единым источником.
///
/// `REINJECT` стоит на пакетах, которые рантайм переотправил сам, — правило
/// пропускает их мимо очереди, иначе перехват зациклился бы на своих же
/// сегментах. `PROBE` стоит на соединениях-пробах: правило ловит их несмотря
/// на исключение группы прокси, иначе проба ушла бы мимо перехвата и мерила
/// бы прямое соединение вместо техники.
pub const REINJECT_FWMARK: u32 = 0x73;
pub const PROBE_FWMARK: u32 = 0x74;

/// Сколько хранить метку, которую перехват так и не забрал (соединение
/// закрылось без единого байта или ушло не на 443).
const MARK_TTL: Duration = Duration::from_secs(60);

static ACTIVE: AtomicBool = AtomicBool::new(false);

/// Ключ метки: локальный порт и адрес сервера. Одного порта мало — ядро
/// отдаёт тот же эфемерный порт соединениям к разным адресам, и чужое
/// соединение с совпавшим портом забрало бы метку прокси. Адрес приводится
/// к каноническому виду: у сокета он может быть IPv4-mapped, а в пакете —
/// чистый IPv4.
type Key = (u16, IpAddr);

fn marks() -> &'static Mutex<HashMap<Key, (Mark, Instant)>> {
    static MARKS: OnceLock<Mutex<HashMap<Key, (Mark, Instant)>>> = OnceLock::new();
    MARKS.get_or_init(Default::default)
}

/// Работает ли перехват пакетов. Пока нет, метки не нужны и не ставятся.
pub fn is_active() -> bool {
    ACTIVE.load(Ordering::Relaxed)
}

pub fn set_active(active: bool) {
    ACTIVE.store(active, Ordering::Relaxed);
    if !active {
        marks().lock().unwrap_or_else(|e| e.into_inner()).clear();
    }
}

/// Помечает соединение по локальному порту и адресу сервера. Звать до
/// первой записи.
pub fn mark(stream: &tokio::net::TcpStream, mark: Mark) {
    if !is_active() {
        return;
    }
    let (Ok(local), Ok(peer)) = (stream.local_addr(), stream.peer_addr()) else { return };
    mark_port(local.port(), peer.ip(), mark);
}

fn mark_port(port: u16, remote: IpAddr, mark: Mark) {
    let now = Instant::now();
    let mut marks = marks().lock().unwrap_or_else(|e| e.into_inner());
    marks.retain(|_, (_, at)| now.duration_since(*at) < MARK_TTL);
    marks.insert((port, remote.to_canonical()), (mark, now));
}

/// Забирает метку соединения: для перехвата, увидевшего ClientHello.
///
/// Просроченная метка не отдаётся. Чистка в `mark_port` идёт только при
/// новой метке, и без этой проверки метка соединения, закрытого без
/// ClientHello, досталась бы чужому соединению, занявшему порт хоть через
/// час.
pub fn take(port: u16, remote: IpAddr) -> Option<Mark> {
    let (mark, at) = marks()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&(port, remote.to_canonical()))?;
    (at.elapsed() < MARK_TTL).then_some(mark)
}

/// Доступна ли техника на уровне пакетов. Две TLS-записи и OOB меняют
/// число байт в потоке, а у перехваченного соединения нумерацию ведёт
/// ядро приложения (см. `packet::desync`).
pub fn supports(strategy: Strategy) -> bool {
    !matches!(strategy, Strategy::TlsRecord | Strategy::Oob)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marks_are_taken_once() {
        let server: IpAddr = [192, 0, 2, 1].into();
        mark_port(40001, server, Mark::Probe(Strategy::Fake));
        assert_eq!(take(40001, server), Some(Mark::Probe(Strategy::Fake)));
        assert_eq!(take(40001, server), None);
    }

    #[test]
    fn mark_belongs_to_its_server_only() {
        let ours: IpAddr = [192, 0, 2, 2].into();
        let other: IpAddr = [198, 51, 100, 2].into();
        mark_port(40002, ours, Mark::Own);
        assert_eq!(take(40002, other), None, "чужое соединение с тем же портом");
        assert_eq!(take(40002, ours), Some(Mark::Own));
    }

    #[test]
    fn mapped_and_plain_ipv4_are_one_server() {
        let mapped: IpAddr = "::ffff:192.0.2.3".parse().unwrap();
        let plain: IpAddr = [192, 0, 2, 3].into();
        mark_port(40003, mapped, Mark::Own);
        assert_eq!(take(40003, plain), Some(Mark::Own));
    }

    #[test]
    fn expired_mark_is_not_handed_out() {
        let server: IpAddr = [192, 0, 2, 4].into();
        let stale = Instant::now().checked_sub(MARK_TTL + Duration::from_secs(1));
        let Some(stale) = stale else { return };
        marks()
            .lock()
            .unwrap()
            .insert((40004, server), (Mark::Own, stale));
        assert_eq!(take(40004, server), None);
    }

    #[test]
    fn stream_changing_techniques_are_not_available() {
        assert!(supports(Strategy::SniSplit));
        assert!(supports(Strategy::Fake));
        assert!(!supports(Strategy::TlsRecord));
        assert!(!supports(Strategy::Oob));
    }
}
