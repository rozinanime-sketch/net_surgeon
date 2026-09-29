//! Идентичность сети для стратегий.
//!
//! Стратегия, снятая на одной сети, неверна на другой: у другого провайдера
//! другой DPI, другое число хопов, другой набор блокировок. Раньше `strategies.txt`
//! ключевался только по домену, и записи с домашнего Wi-Fi применялись на
//! мобильной сети (и наоборот) до истечения TTL. Теперь ключ включает id сети:
//! записи разных сетей сосуществуют, а при возврате в знакомую сеть
//! переиспользуются — без передиагностики.
//!
//! # Откуда берётся id
//!
//! * **Linux-десктоп** — шлюз по умолчанию из `/proc/net/route` ([`detect`]).
//! * **Android** — из `ConnectivityManager` (имя интерфейса + DNS), передаётся
//!   из Kotlin по колбэку смены сети (см. `NativeBridge.onNetworkChanged`).
//! * **Прочее / не определено** — пустая строка: все сети считаются одной
//!   (для стационарной машины, которая не роумит, это верно).

use std::sync::RwLock;

fn slot() -> &'static RwLock<String> {
    static ID: std::sync::OnceLock<RwLock<String>> = std::sync::OnceLock::new();
    ID.get_or_init(|| RwLock::new(String::new()))
}

/// Текущий id сети. Пустая строка — сеть не определена (единый профиль).
pub fn current() -> String {
    slot().read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Устанавливает id сети. Звать при старте и при смене сети.
pub fn set(id: String) {
    *slot().write().unwrap_or_else(|e| e.into_inner()) = id;
}

/// Шлюз по умолчанию как id сети (Linux-десктоп). Пусто — не определился.
///
/// На Android не используется: там маршрут по умолчанию ведёт в TUN, а не в
/// физический шлюз, поэтому id приходит из Kotlin.
#[cfg(target_os = "linux")]
pub fn detect() -> String {
    std::fs::read_to_string("/proc/net/route").map(|t| parse_default_gw(&t)).unwrap_or_default()
}

/// Шлюз по умолчанию из текста `/proc/net/route`. Строка с Destination
/// 00000000 — маршрут по умолчанию, третье поле — шлюз (hex). Отдельно от
/// чтения файла, чтобы разбор проверялся тестом без диска и без глобала.
#[cfg(target_os = "linux")]
fn parse_default_gw(route_text: &str) -> String {
    for line in route_text.lines().skip(1) {
        let mut f = line.split_whitespace();
        let (_iface, dest, gw) = (f.next(), f.next(), f.next());
        if dest == Some("00000000")
            && let Some(gw) = gw
            && gw != "00000000"
        {
            return format!("gw:{gw}");
        }
    }
    String::new()
}

// Тест только на чистый разбор: `set/current` трогают глобальное состояние,
// а параллельные тесты стора зависят от того, что оно остаётся пустым.
#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::parse_default_gw;

    #[test]
    fn parses_default_gateway_and_ignores_other_routes() {
        let route = "Iface\tDestination\tGateway\tFlags\n\
                     wlan0\t00000000\t0102A8C0\t0003\n\
                     wlan0\t0002A8C0\t00000000\t0001\n";
        assert_eq!(parse_default_gw(route), "gw:0102A8C0");
        // Нет маршрута по умолчанию — пусто (единый профиль).
        assert_eq!(parse_default_gw("Iface\tDestination\tGateway\nwlan0\t0002A8C0\t00000000\t0001\n"), "");
    }
}
