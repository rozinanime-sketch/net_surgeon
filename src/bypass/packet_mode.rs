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

/// Сколько хранить метку, которую перехват так и не забрал (соединение
/// закрылось без единого байта или ушло не на 443).
const MARK_TTL: Duration = Duration::from_secs(60);

static ACTIVE: AtomicBool = AtomicBool::new(false);

fn marks() -> &'static Mutex<HashMap<u16, (Mark, Instant)>> {
    static MARKS: OnceLock<Mutex<HashMap<u16, (Mark, Instant)>>> = OnceLock::new();
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

/// Помечает соединение по его локальному порту. Звать до первой записи.
pub fn mark(stream: &tokio::net::TcpStream, mark: Mark) {
    if !is_active() {
        return;
    }
    let Ok(local) = stream.local_addr() else { return };
    mark_port(local.port(), mark);
}

fn mark_port(port: u16, mark: Mark) {
    let now = Instant::now();
    let mut marks = marks().lock().unwrap_or_else(|e| e.into_inner());
    marks.retain(|_, (_, at)| now.duration_since(*at) < MARK_TTL);
    marks.insert(port, (mark, now));
}

/// Забирает метку локального порта: для перехвата, увидевшего ClientHello.
pub fn take(port: u16) -> Option<Mark> {
    marks().lock().unwrap_or_else(|e| e.into_inner()).remove(&port).map(|(m, _)| m)
}

/// Доступна ли техника на уровне пакетов. Две TLS-записи и OOB меняют
/// число байт в потоке, а у перехваченного соединения нумерацию ведёт
/// ядро приложения (см. `windivert::desync`).
pub fn supports(strategy: Strategy) -> bool {
    !matches!(strategy, Strategy::TlsRecord | Strategy::Oob)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marks_are_taken_once() {
        mark_port(40001, Mark::Probe(Strategy::Fake));
        assert_eq!(take(40001), Some(Mark::Probe(Strategy::Fake)));
        assert_eq!(take(40001), None);
    }

    #[test]
    fn stream_changing_techniques_are_not_available() {
        assert!(supports(Strategy::SniSplit));
        assert!(supports(Strategy::Fake));
        assert!(!supports(Strategy::TlsRecord));
        assert!(!supports(Strategy::Oob));
    }
}
