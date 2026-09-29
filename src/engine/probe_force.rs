//! Принудительная стратегия для одного соединения — для freeze-проб.
//!
//! Freeze-проба гоняет конкретную технику через настоящий прокси и настоящий
//! TLS: так проверяется не только рукопожатие, но и переживает ли соединение
//! ~16 КБ (заморозка ТСПУ). Проба помечает свой локальный порт нужной
//! стратегией, а `socks5::handle_connect` берёт её вместо автоподбора.
//!
//! Метка одноразовая и с TTL: если проба не дошла до отправки ClientHello
//! (закрылась раньше), запись сама протухнет и не повлияет на чужой порт,
//! который система позже переиспользует.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::engine::strategy::Strategy;

const TTL: Duration = Duration::from_secs(30);

fn map() -> &'static Mutex<HashMap<u16, (Strategy, Instant)>> {
    static M: OnceLock<Mutex<HashMap<u16, (Strategy, Instant)>>> = OnceLock::new();
    M.get_or_init(Default::default)
}

/// Помечает локальный порт соединения стратегией. Звать до отправки ClientHello.
pub fn set(port: u16, strategy: Strategy) {
    let now = Instant::now();
    let mut m = map().lock().unwrap_or_else(|e| e.into_inner());
    m.retain(|_, (_, at)| now.duration_since(*at) < TTL);
    m.insert(port, (strategy, now));
}

/// Забирает метку порта (одноразово): для `handle_connect`, увидевшего CONNECT.
pub fn take(port: u16) -> Option<Strategy> {
    map().lock().unwrap_or_else(|e| e.into_inner()).remove(&port).map(|(s, _)| s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mark_is_taken_once() {
        set(51000, Strategy::Fake);
        assert_eq!(take(51000), Some(Strategy::Fake));
        assert_eq!(take(51000), None, "метка одноразовая");
    }
}
