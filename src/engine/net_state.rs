//! Единый дом для состояния, зависящего от текущей сети.
//!
//! Раньше эти глобалы были раскиданы: id сети в `net_id`, «сеть морозит» и порт
//! проб в `freeze`, подобранный TTL приманки в `bypass::fake_ttl`. Поведение
//! (эскалация, freeze-проба, выбор TTL) осталось в тех модулях, а всё
//! *состояние* собрано здесь — в одном месте, с одним сбросом при смене сети.
//! Так видно сразу всё, что зависит от сети, и нечему рассинхронизироваться.
//!
//! Модули `net_id`, `freeze`, `fake_ttl` теперь тонко делегируют сюда, поэтому
//! их внешний API не изменился.

use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};
use std::sync::{OnceLock, RwLock};

// --- id сети (ключует стратегии) ------------------------------------------

fn net_id_slot() -> &'static RwLock<String> {
    static ID: OnceLock<RwLock<String>> = OnceLock::new();
    ID.get_or_init(|| RwLock::new(String::new()))
}

/// Текущий id сети. Пустая строка — сеть не определена (единый профиль).
pub fn net_id() -> String {
    net_id_slot().read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Задаёт id сети (старт и смена сети).
pub fn set_net_id(id: String) {
    *net_id_slot().write().unwrap_or_else(|e| e.into_inner()) = id;
}

/// Читаемый вид id сети для интерфейса. Десктопный id вида `gw:0102A8C0` —
/// это шлюз hex'ом (little-endian, как в `/proc/net/route`); раскрываем его в
/// точечный IP. Сам КЛЮЧ стратегий остаётся hex-строкой — менять его формат
/// значило бы обесценить все записи в strategies.txt и вызвать передиагностику.
/// Android-id (`iface|dns`) и так читаемый — возвращаем как есть.
pub fn display_net_id(id: &str) -> String {
    if let Some(hex) = id.strip_prefix("gw:")
        && hex.len() == 8
        && let Ok(raw) = u32::from_str_radix(hex, 16)
    {
        let [a, b, c, d] = raw.to_le_bytes();
        return format!("gw:{a}.{b}.{c}.{d}");
    }
    id.to_string()
}

/// Шлюз по умолчанию как id сети (Linux-десктоп). Пусто — не определился.
#[cfg(target_os = "linux")]
pub fn detect_net_id() -> String {
    std::fs::read_to_string("/proc/net/route").map(|t| parse_default_gw(&t)).unwrap_or_default()
}

/// Шлюз по умолчанию из текста `/proc/net/route` — отдельно от чтения файла,
/// чтобы разбор проверялся без диска и без глобала.
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

// --- «сеть морозит незабелённый TLS» → предпочитать decoy ------------------

static PREFER_DECOY: AtomicBool = AtomicBool::new(false);

pub fn prefer_decoy() -> bool {
    PREFER_DECOY.load(Ordering::Relaxed)
}

pub fn set_prefer_decoy(on: bool) {
    PREFER_DECOY.store(on, Ordering::Relaxed);
}

// --- порт SOCKS5, через который идут freeze-пробы --------------------------

static SOCKS_PORT: AtomicU16 = AtomicU16::new(0);

pub fn set_socks_port(port: u16) {
    SOCKS_PORT.store(port, Ordering::Relaxed);
}

pub fn socks_port() -> Option<u16> {
    match SOCKS_PORT.load(Ordering::Relaxed) {
        0 => None,
        p => Some(p),
    }
}

// --- подобранный TTL приманки fake (бегущий минимум по доменам) ------------

static AUTO_FAKE_TTL: AtomicU32 = AtomicU32::new(0);

/// TTL для боя: подобранный, если есть, иначе конфиговый.
pub fn effective_fake_ttl(config_ttl: u32) -> u32 {
    match AUTO_FAKE_TTL.load(Ordering::Relaxed) {
        0 => config_ttl,
        auto => auto,
    }
}

/// Запоминает рабочий TTL как бегущий минимум по доменам (меньше числа хопов
/// до любого сервера, но больше, чем до DPI, — безопасно для всех доменов сети).
pub fn note_fake_ttl(ttl: u32) {
    if ttl == 0 {
        return;
    }
    let mut cur = AUTO_FAKE_TTL.load(Ordering::Relaxed);
    loop {
        let new = if cur == 0 { ttl } else { cur.min(ttl) };
        if new == cur {
            return;
        }
        match AUTO_FAKE_TTL.compare_exchange_weak(cur, new, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(actual) => cur = actual,
        }
    }
}

/// Текущий подобранный TTL, если есть (для лога/диагностики).
pub fn auto_fake_ttl() -> Option<u32> {
    match AUTO_FAKE_TTL.load(Ordering::Relaxed) {
        0 => None,
        auto => Some(auto),
    }
}

// --- сброс при смене сети --------------------------------------------------

/// Сбрасывает подобранное под конкретную сеть: «сеть морозит» и TTL приманки.
/// Число хопов до DPI и серверов на другой сети иное, и старые значения ломали
/// бы обход. Порт SOCKS5 (из конфига) и сам id сети здесь не трогаем — их
/// выставляет вызывающий.
pub fn reset_for_network() {
    set_prefer_decoy(false);
    AUTO_FAKE_TTL.store(0, Ordering::Relaxed);
}

/// Общий замок для тестов, трогающих сетевые глобалы (`PREFER_DECOY`,
/// `AUTO_FAKE_TTL`). Они живут в одном тестовом бинаре и без сериализации
/// затирали бы состояние друг друга при параллельном прогоне (в т.ч. тест
/// `freeze`, который тоже правит `PREFER_DECOY`).
#[cfg(test)]
pub(crate) fn test_guard() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_ttl_running_min_and_reset() {
        let _g = test_guard();
        AUTO_FAKE_TTL.store(0, Ordering::Relaxed);
        assert_eq!(effective_fake_ttl(8), 8, "не подобран — конфиг");
        note_fake_ttl(10);
        assert_eq!(effective_fake_ttl(8), 10);
        note_fake_ttl(6);
        assert_eq!(auto_fake_ttl(), Some(6), "минимум по доменам");
        note_fake_ttl(9);
        assert_eq!(auto_fake_ttl(), Some(6), "большее не поднимает минимум");
        reset_for_network();
        assert_eq!(auto_fake_ttl(), None, "сброс при смене сети");
    }

    #[test]
    fn prefer_decoy_reset() {
        let _g = test_guard();
        set_prefer_decoy(true);
        reset_for_network();
        assert!(!prefer_decoy());
    }

    #[test]
    fn display_decodes_gateway_hex_to_dotted_ip() {
        assert_eq!(display_net_id("gw:0102A8C0"), "gw:192.168.2.1");
        assert_eq!(display_net_id("gw:6AA0460A"), "gw:10.70.160.106");
        // Не gw и не 8 hex-символов — возвращается как есть.
        assert_eq!(display_net_id("wlan0|10.0.0.1"), "wlan0|10.0.0.1");
        assert_eq!(display_net_id(""), "");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_default_gateway() {
        let route = "Iface\tDestination\tGateway\tFlags\n\
                     wlan0\t00000000\t0102A8C0\t0003\n\
                     wlan0\t0002A8C0\t00000000\t0001\n";
        assert_eq!(parse_default_gw(route), "gw:0102A8C0");
        assert_eq!(parse_default_gw("h\nwlan0\t0002A8C0\t00000000\t0001\n"), "");
    }
}
