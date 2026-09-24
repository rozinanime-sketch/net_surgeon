use std::collections::HashSet;
use serde::Deserialize;

pub mod paths;

// Секция [ranges] удалена вместе с тем, что её использовало.
//
// `frag_*` и `delay_*` настраивали фрагментацию обычного HTTP на порту 80,
// `udp_jitter_*` — случайную задержку ответа в простом UDP-релее. Ни то ни
// другое к обходу DPI отношения не имело: практически весь трафик идёт по
// HTTPS, где работают техники из [`BypassParams`] и лестница стратегий,
// а джиттер на ответе резолвера не обходит вообще ничего.
//
// Держать в конфиге раздел, к которому пришлось приписывать предупреждение
// «эти параметры НЕ влияют на HTTPS», — значит тратить внимание читателя
// на то, что ему не нужно.

#[derive(Debug, Deserialize, Clone)]
pub struct BypassParams {
    /// Позиция сплита ClientHello выбирается случайно в [split_pos_min, split_pos_max]
    /// на каждое соединение. Раньше это было одно фиксированное число — DPI видел
    /// один и тот же паттерн разбиения каждый раз.
    pub split_pos_min: usize,
    pub split_pos_max: usize,
    pub split_delay_ms: u64,
    pub window_clamp: u32,
    /// TTL для первой половины при disorder. Должен быть достаточным, чтобы
    /// пакет прошёл DPI провайдера, но недостаточным, чтобы дойти до сервера.
    /// Подбирается под сеть: 1-2 для DPI на первом хопе, 3-6 для дальнего.
    #[serde(default = "default_disorder_ttl")]
    pub disorder_ttl: u32,
    /// TTL приманки в технике fake. Смысл тот же, что у disorder: пакет
    /// должен дойти до DPI, но не до сервера.
    #[serde(default = "default_fake_ttl")]
    pub fake_ttl: u32,
    /// Имя, которое подставляется в поддельный ClientHello.
    ///
    /// Должно выглядеть безобидно и быть заведомо разблокированным — по
    /// нему DPI и классифицирует соединение. zapret в своих конфигурациях
    /// под Telegram использует www.google.com.
    #[serde(default = "default_fake_sni")]
    pub fake_sni: String,
}

/// Параметры junk-обфускации в SOCKS5 UDP (раньше были захардкожены
/// прямо в run_socks5_udp_processor).
#[derive(Debug, Deserialize, Clone)]
pub struct Socks5JunkParams {
    pub count: usize,
    pub size_min: usize,
    pub size_max: usize,
    pub delay_min_ms: u64,
    pub delay_max_ms: u64,
}

impl Default for Socks5JunkParams {
    fn default() -> Self {
        Self { count: 6, size_min: 100, size_max: 800, delay_min_ms: 15, delay_max_ms: 40 }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    /// На каком адресе слушать все прокси-порты.
    ///
    /// По умолчанию `127.0.0.1`, а не `0.0.0.0`, и это не перестраховка.
    /// Здесь пять слушателей без какой-либо аутентификации: HTTP-прокси,
    /// SOCKS5, SOCKS5-UDP, DNS-релей и прозрачный режим. На `0.0.0.0` любой
    /// сосед по локальной сети получает открытый прокси, а UDP-слушатели
    /// вдобавок работают отражателем для усиления трафика.
    ///
    /// Прозрачному режиму localhost не мешает: правило iptables стоит в
    /// цепочке OUTPUT, а REDIRECT там заворачивает на 127.0.0.1.
    ///
    /// Ставьте `0.0.0.0`, только если прокси нужен другим машинам, и тогда
    /// ограничивайте доступ файрволом.
    #[serde(default = "default_listen_host")]
    pub listen_host: String,
    pub port: u16,
    /// Порт DoH-релея. 0 — выключен.
    ///
    /// Раньше на этом порту жил один из двух режимов на выбор (`dns_mode`):
    /// DoH-релей либо простой форвардер DNS на фиксированный адрес. Второй
    /// удалён — он только добавлял к ответу случайную задержку, что не
    /// обходит ничего, зато держал открытый UDP-порт, годный под усиление
    /// трафика. Выбирать стало не из чего, поэтому вместо режима — 0/не 0.
    ///
    /// Релей полезен не столько как DNS, сколько тем, что наполняет кэш
    /// «адрес → домен»: по нему HTTPS-туннель и прозрачный режим включают
    /// обход, когда клиент пришёл по IP или без SNI.
    pub udp_port: u16,
    pub socks5_port: u16,
    pub socks5_udp_port: u16,
    /// Порт прозрачного режима. 0 — выключен.
    ///
    /// Перехват настраивается правилом iptables и не требует настройки
    /// приложений: адрес назначения берётся из conntrack, имя домена —
    /// из SNI в ClientHello.
    #[serde(default)]
    pub transparent_port: u16,
    pub enabled: bool,
    pub bypass: BypassParams,
    #[serde(default)]
    pub socks5_junk: Socks5JunkParams,
    /// Через сколько часов запись в strategies.txt считается протухшей
    /// и домен проверяется диагностикой заново.
    #[serde(default = "default_strategy_ttl_hours")]
    pub strategy_ttl_hours: u64,
    /// Вес надёжности в функции полезности. Чем больше, тем сильнее
    /// предпочтение технике, которая проходит стабильнее.
    #[serde(default = "default_reward_reliability")]
    pub reward_reliability: f64,
    /// Вес задержки. Чем больше, тем сильнее штраф за медленную технику.
    ///
    /// По умолчанию втрое меньше надёжности: работающий медленно обход
    /// полезнее быстрого, который не работает. Но при равной надёжности
    /// разница в задержке решает — например, disorder платит ретрансмитом
    /// в сотни миллисекунд.
    #[serde(default = "default_reward_latency")]
    pub reward_latency: f64,
    /// Через сколько часов автоматически перезапускать массовую диагностику.
    /// 0 — только вручную по клавише `a`.
    ///
    /// Смысл в том, что провайдер меняет правила без предупреждения, а TTL
    /// записи лишь помечает её протухшей — переизмерить её всё равно некому,
    /// пока пользователь сам не нажмёт клавишу.
    #[serde(default)]
    pub auto_diagnostics_hours: u64,
    /// Только диагностика: прокси-слушатели не запускаются.
    ///
    /// Позволяет посмотреть, что происходит с сетью, не включая изменение
    /// трафика. Флаг командной строки `--diagnose-only` имеет приоритет.
    #[serde(default)]
    pub diagnostics_only: bool,
    /// Пауза между пробами одной техники при диагностике, мс.
    ///
    /// Вынесено в конфиг, чтобы гипотезу о влиянии плотности зондирования
    /// можно было проверить экспериментом: наблюдалось, что серия из пяти
    /// проб подряд даёт 0/5 там, где две-три пробы иногда проходят. Меняя
    /// эти значения и сравнивая результаты прогонов, можно выяснить,
    /// реагирует ли DPI на частоту подключений или дело в чём-то другом.
    #[serde(default = "default_probe_gap_min")]
    pub probe_gap_min_ms: u64,
    #[serde(default = "default_probe_gap_max")]
    pub probe_gap_max_ms: u64,
    /// Разрешать ли адреса для исходящих подключений через DoH.
    ///
    /// По умолчанию выключено, и это вывод из измерений, а не осторожность.
    /// Cloudflare DoH принципиально не поддерживает EDNS Client Subnet и
    /// отвечает со своей точки зрения, а не с точки зрения клиента. Для
    /// CDN-доменов это даёт другой anycast-узел: на проверке x.com и
    /// meduza.io перестали открываться, хотя с адресами от системного
    /// резолвера работали через две TLS-записи.
    ///
    /// Включать имеет смысл, если провайдер подменяет DNS-ответы — тогда
    /// системному резолверу доверять нельзя, и чужой узел лучше подмены.
    #[serde(default)]
    pub resolve_via_doh: bool,
    #[serde(default = "default_doh_provider")]
    pub doh_provider: String,

    /// IP-адрес самого DoH-провайдера, если его имя нельзя резолвить обычным
    /// путём.
    ///
    /// Нужен ровно в одном случае: когда системный DNS завёрнут на наш же
    /// релей (`run.sh` умеет перехватывать UDP/53). Тогда, чтобы ответить на
    /// первый же запрос, релею пришлось бы сначала узнать адрес провайдера —
    /// у самого себя. Здесь этот круг разрывается: адрес берётся из конфига,
    /// и резолв имени провайдера не выполняется вообще.
    ///
    /// Пустое поле — обычное поведение, имя провайдера резолвится системой.
    #[serde(default)]
    pub doh_bootstrap_ip: Option<std::net::IpAddr>,

    /// Блокировать домены из block_domains.txt — счётчики вроде
    /// Яндекс.Метрики. По умолчанию выключено: прокси, который молча режет
    /// часть трафика, неожиданен, и включать это должен сам пользователь.
    #[serde(default)]
    pub block_trackers: bool,
}

fn default_listen_host() -> String { "127.0.0.1".to_string() }
fn default_disorder_ttl() -> u32 { 2 }
fn default_fake_ttl() -> u32 { 2 }
fn default_fake_sni() -> String { "www.google.com".to_string() }
fn default_strategy_ttl_hours() -> u64 { 24 }
fn default_reward_reliability() -> f64 { 1.0 }
fn default_reward_latency() -> f64 { 0.3 }
fn default_probe_gap_min() -> u64 { 250 }
fn default_probe_gap_max() -> u64 { 700 }
fn default_doh_provider() -> String { "https://cloudflare-dns.com/dns-query".to_string() }

pub fn load_config() -> Result<Config, String> {
    // В сообщении — полный путь, по которому искали. Иначе «файл не найден»
    // ничего не подсказывает: каталог данных вычисляется, а не берётся из CWD.
    let path = paths::resolve("config.toml");
    let contents = std::fs::read_to_string(&path)
        .map_err(|e| format!("Не удалось прочитать {}: {}", path.display(), e))?;
    toml::from_str(&contents)
        .map_err(|e| format!("Не удалось распарсить config.toml: {}", e))
}

/// Список доменов для обхода.
///
/// Пустое множество — валидный результат (обход просто никому не нужен), но
/// оно же получается при отсутствии файла. Отличить одно от другого важно:
/// пустой список молча выключает обход целиком. Поэтому отсутствие файла
/// возвращается отдельно, а показывает его `cli` — стартового вывода в
/// терминал не видно, TUI затирает его альтернативным экраном.
pub fn load_bypass_domains() -> (HashSet<String>, Option<String>) {
    let text = match paths::read_to_string("bypass_domains.txt") {
        Ok(t) => t,
        Err(e) => return (HashSet::new(), Some(e.to_string())),
    };

    let set = text
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .map(|l| l.trim().to_lowercase())
        .collect();
    (set, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// config.toml из репозитория. Читается по пути крейта, а не через
    /// каталог данных: в тестах тот указывает во временный каталог, чтобы
    /// тесты не перезаписывали рабочие файлы.
    fn shipped_config() -> String {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("config.toml");
        std::fs::read_to_string(path).expect("config.toml должен читаться")
    }

    /// Конфиг, который лежит в репозитории, обязан разбираться этой же
    /// структурой. Опечатка в нём или забытое поле обнаруживались только
    /// при запуске — программа падала на старте с сообщением от serde,
    /// а тесты при этом оставались зелёными.
    #[test]
    fn shipped_config_parses() {
        let text = shipped_config();
        let config: Config = toml::from_str(&text).expect("config.toml должен разбираться");

        // Заодно проверяем, что значения доезжают, а не подставляются
        // умолчаниями из-за неверной секции.
        assert!(config.port > 0);
        assert!(!config.doh_provider.is_empty());
    }

    /// Закреплённый адрес провайдера имеет смысл, только если из адреса
    /// провайдера вообще извлекается имя хоста: `doh_client` молча
    /// игнорирует `doh_bootstrap_ip`, когда URL разобрать не удалось.
    /// Тогда перехват DNS замкнулся бы сам на себя, и понять почему —
    /// по логам невозможно.
    #[test]
    fn pinned_provider_address_is_actually_usable() {
        let text = shipped_config();
        let config: Config = toml::from_str(&text).expect("config.toml должен разбираться");

        if config.doh_bootstrap_ip.is_some() {
            assert!(
                crate::dns::provider_endpoint(&config.doh_provider).is_some(),
                "задан doh_bootstrap_ip, но из doh_provider ({}) не извлекается хост — \
                 закреплённый адрес не будет использован",
                config.doh_provider,
            );
        }
    }
}
