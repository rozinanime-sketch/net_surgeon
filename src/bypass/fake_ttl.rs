//! Автоподбор TTL для приманки `fake`.
//!
//! Приманка (поддельный ClientHello с разрешённым именем) должна умереть в
//! пути **дальше DPI, но ближе сервера**: DPI её увидит и «забелит» соединение
//! (иначе — заморозка после ~16 КБ), а сервер не получит и не оборвёт
//! рукопожатие. Нужный TTL — это число хопов, попадающее в это окно, и оно
//! зависит от сети, а не от домена: фиксированное значение из конфига на
//! мобильной сети часто мимо.
//!
//! Диагностика подбирает рабочий TTL перебором (наибольший, при котором
//! рукопожатие ещё живо, — он гарантированно дальше DPI) и кладёт его сюда.
//! Боевой путь (`strategy::apply::first_packet`) берёт подобранное значение
//! вместо конфигового; сами пробы — нет, они меряют конкретный TTL.
//!
//! # Почему бегущий минимум
//!
//! Разные домены — разное число хопов до сервера. Минимум по доменам меньше
//! числа хопов до любого из серверов (значит приманка ни до одного не дойдёт),
//! но по-прежнему больше, чем до DPI (он ближе любого зарубежного сервера).
//! Так одно значение безопасно для всех обходимых доменов.

use std::sync::atomic::{AtomicU32, Ordering};

/// Подобранный TTL; 0 — ещё не подобран, берётся значение из конфига.
static AUTO: AtomicU32 = AtomicU32::new(0);

/// TTL для боевого применения: подобранный, если есть, иначе конфиговый.
pub fn effective(config_ttl: u32) -> u32 {
    match AUTO.load(Ordering::Relaxed) {
        0 => config_ttl,
        auto => auto,
    }
}

/// Запоминает рабочий TTL как бегущий минимум по доменам.
pub fn note_working(ttl: u32) {
    if ttl == 0 {
        return;
    }
    let mut cur = AUTO.load(Ordering::Relaxed);
    loop {
        let new = if cur == 0 { ttl } else { cur.min(ttl) };
        if new == cur {
            return;
        }
        match AUTO.compare_exchange_weak(cur, new, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(actual) => cur = actual,
        }
    }
}

/// Текущее подобранное значение, если оно есть (для лога/диагностики).
pub fn current() -> Option<u32> {
    match AUTO.load(Ordering::Relaxed) {
        0 => None,
        auto => Some(auto),
    }
}

/// Сбрасывает подобранный TTL — при смене сети прежнее значение неверно
/// (другое число хопов до DPI и до серверов), и бегущий минимум сам бы не
/// поднялся. См. `crate::reset_network_tuning`.
pub fn reset() {
    AUTO.store(0, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_falls_back_to_config_then_keeps_running_min() {
        reset();
        assert_eq!(effective(8), 8, "не подобран — конфиг");
        note_working(10);
        assert_eq!(effective(8), 10, "подобран — вместо конфига");
        note_working(6);
        assert_eq!(current(), Some(6), "минимум по доменам");
        note_working(9);
        assert_eq!(current(), Some(6), "большее значение не поднимает минимум");
        note_working(0);
        assert_eq!(current(), Some(6), "ноль игнорируется");
        reset();
    }
}
