use std::collections::HashSet;
use serde::Deserialize;

pub mod list_updates;
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
    /// Пометить приманку TCP-опцией MD5-подписи. Сервер без ключа такой
    /// пакет выбрасывает, даже если низкий TTL его не остановил, а DPI
    /// обычно принимает. Работает с серверами на Linux (в том числе
    /// Cloudflare) и только там, где fake идёт через сокет (Linux, Android).
    #[serde(default)]
    pub fake_md5sig: bool,
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
    /// Мусор и перед потоками звонков: STUN и UDP к сетям Telegram. См.
    /// `session::is_call_flow`. Экспериментально, поэтому с выключателем.
    #[serde(default = "default_true")]
    pub calls: bool,
}

fn default_true() -> bool { true }

impl Default for Socks5JunkParams {
    fn default() -> Self {
        Self { count: 6, size_min: 100, size_max: 800, delay_min_ms: 15, delay_max_ms: 40, calls: true }
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
    /// Пакетный режим прозрачного перехвата на Linux (NFQUEUE, как nfqws).
    ///
    /// Вместо разворота TCP/443 на сокетный слушатель ClientHello уходит в
    /// очередь NFQUEUE, где его переписывает общий с Windows движок
    /// (`crate::nfqueue`, `crate::packet::desync`). Это единственный режим,
    /// где доступен seqovl: обычному сокету номер последовательности не задать.
    /// По умолчанию выключен — работает прежний сокетный путь. На других
    /// системах не действует.
    #[serde(default)]
    pub packet_mode: bool,
    /// Прописывать ли программу системным прокси Windows на время работы.
    ///
    /// Прозрачного режима там нет, и без этого прокси пришлось бы включать
    /// в настройках руками. Прежние настройки возвращаются при выходе (см.
    /// src/system_proxy.rs). На других системах не действует.
    #[serde(default = "default_true")]
    pub system_proxy: bool,
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
    /// По умолчанию выключено: DNS провайдера отдаёт адреса CDN рядом с
    /// клиентом, а DoH — со своей точки зрения. Так было измерено на
    /// Cloudflare DoH, который не передаёт EDNS Client Subnet: x.com и
    /// meduza.io получали чужой anycast-узел и переставали открываться.
    /// Провайдер по умолчанию теперь Quad9 dns11, он ECS передаёт, но
    /// перемерять это пока не перемеряли.
    ///
    /// Включать имеет смысл, если провайдер подменяет DNS-ответы — тогда
    /// системному резолверу доверять нельзя. Выключенный DoH всё равно
    /// остаётся запасным: им переспрашиваются имена, которые система не нашла.
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
    /// Ключа нет вовсе — адрес провайдера по умолчанию, как в config.toml
    /// (см. `drop_foreign_bootstrap`).
    #[serde(default = "default_doh_bootstrap_ip", deserialize_with = "empty_as_none")]
    pub doh_bootstrap_ip: Option<std::net::IpAddr>,

    /// «Умный» DoH (GeoHide) для доменов из smart_dns_domains.txt —
    /// сервисов, закрытых для России по IP. Остальные имена идут через
    /// `doh_provider`. Пусто — выключено; ключа нет — GeoHide, как в
    /// config.toml.
    #[serde(default = "default_smart_dns_provider")]
    pub smart_dns_provider: String,

    /// То же, что `doh_bootstrap_ip`, но для `smart_dns_provider`.
    #[serde(default = "default_smart_dns_bootstrap_ip", deserialize_with = "empty_as_none")]
    pub smart_dns_bootstrap_ip: Option<std::net::IpAddr>,

    /// Дописывать в списки доменов те, что появились в новой версии.
    /// Только добавляет и каждый домен один раз (см. list_updates.rs).
    #[serde(default = "default_true")]
    pub add_new_domains: bool,

    /// Блокировать домены из block_domains.txt — счётчики вроде
    /// Яндекс.Метрики. По умолчанию включено: сбор данных о себе мало кому
    /// нужен. Если сайт без счётчика не работает, блокировку выключают
    /// здесь (или убирают домен из списка), а в логе видно, что и через что
    /// заблокировано («log.blocked»).
    #[serde(default = "default_true")]
    pub block_trackers: bool,

    /// В config.toml был неработающий умный DNS (Xbox DNS или Comss), и при
    /// загрузке он подменён на GeoHide (см. `replace_dead_smart_dns`). Пишется в лог при запуске:
    /// пользователь должен знать, кому теперь уходят запросы.
    #[serde(skip)]
    pub smart_dns_replaced: bool,
}

/// Адрес, где пустая строка значит «не задан». Без этого `doh_bootstrap_ip = ""`,
/// обещанный в config.toml как обычное поведение, не разбирался, а редактор
/// в TUI отказывался сохранять стёртое поле.
fn empty_as_none<'de, D>(deserializer: D) -> Result<Option<std::net::IpAddr>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    let text = String::deserialize(deserializer)?;
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    text.parse().map(Some).map_err(serde::de::Error::custom)
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
fn default_doh_provider() -> String { DEFAULT_DOH_PROVIDER.to_string() }
fn default_doh_bootstrap_ip() -> Option<std::net::IpAddr> { Some(std::net::IpAddr::from(DEFAULT_DOH_IP)) }
fn default_smart_dns_provider() -> String { GEOHIDE_DNS.to_string() }
fn default_smart_dns_bootstrap_ip() -> Option<std::net::IpAddr> { Some(std::net::IpAddr::from(GEOHIDE_DNS_IP)) }

/// Провайдер DoH по умолчанию и его адрес — те же, что в config.toml.
const DEFAULT_DOH_PROVIDER: &str = "https://dns11.quad9.net/dns-query";
const DEFAULT_DOH_IP: [u8; 4] = [9, 9, 9, 11];

pub fn load_config() -> Result<Config, String> {
    // В сообщении — полный путь, по которому искали. Иначе «файл не найден»
    // ничего не подсказывает: каталог данных вычисляется, а не берётся из CWD.
    let path = paths::resolve("config.toml");
    let contents = std::fs::read_to_string(&path)
        .map_err(|e| rust_i18n::t!("startup.config_read", path = path.display(), error = e).into_owned())?;
    let mut config: Config = toml::from_str(&contents)
        .map_err(|e| rust_i18n::t!("startup.config_parse", error = e).into_owned())?;
    config.replace_dead_smart_dns();
    config.drop_foreign_bootstrap();
    Ok(config)
}

/// Умный DNS, сменивший закрытый Xbox DNS и переставший работать Comss.
const GEOHIDE_DNS: &str = "https://geohide.ru/dns-query";
const GEOHIDE_DNS_IP: [u8; 4] = [193, 233, 112, 67];
/// Прежние адреса GeoHide: config.toml с ними поставлялся раньше и при
/// обновлении не перезаписывается.
const OLD_GEOHIDE_DNS_IPS: &[[u8; 4]] = &[[159, 194, 200, 33]];

/// Умные DNS, которые больше не открывают нейросети.
const DEAD_SMART_DNS: &[&str] = &["xbox-dns.ru", "dns.comss.one"];

impl Config {
    /// Xbox DNS (xbox-dns.ru) закрылся осенью 2026 под блокировками, а
    /// сменивший его Comss DNS перестал открывать нейросети. config.toml
    /// у уже установленных копий — и на телефонах, где его не
    /// поправить руками, — не перезаписывается при обновлении. Без подмены
    /// нейросети из smart_dns_domains.txt молча перестали открываться.
    fn replace_dead_smart_dns(&mut self) {
        let dead = crate::dns::provider_endpoint(&self.smart_dns_provider).is_some_and(|(host, _)| {
            let host = host.trim_end_matches('.');
            DEAD_SMART_DNS.iter().any(|d| host.eq_ignore_ascii_case(d))
        });
        let geohide_old_ip = provider_host_is(&self.smart_dns_provider, GEOHIDE_DNS)
            && self
                .smart_dns_bootstrap_ip
                .is_some_and(|ip| OLD_GEOHIDE_DNS_IPS.iter().any(|old| ip == std::net::IpAddr::from(*old)));
        if dead || geohide_old_ip {
            self.smart_dns_provider = GEOHIDE_DNS.to_string();
            self.smart_dns_bootstrap_ip = Some(std::net::IpAddr::from(GEOHIDE_DNS_IP));
            self.smart_dns_replaced = true;
        }
    }

    /// Адрес по умолчанию подставляется, когда ключа нет. Но он — адрес
    /// провайдера по умолчанию: если провайдер в конфиге другой, такой адрес
    /// увёл бы его запросы не на тот сервер. Тогда имя резолвится как обычно.
    fn drop_foreign_bootstrap(&mut self) {
        if self.doh_bootstrap_ip == default_doh_bootstrap_ip() && !provider_host_is(&self.doh_provider, DEFAULT_DOH_PROVIDER) {
            self.doh_bootstrap_ip = None;
        }
        if self.smart_dns_bootstrap_ip == default_smart_dns_bootstrap_ip() && !provider_host_is(&self.smart_dns_provider, GEOHIDE_DNS) {
            self.smart_dns_bootstrap_ip = None;
        }
    }
}

/// Тот же ли хост у двух адресов DoH (регистр и точка в конце не важны).
fn provider_host_is(url: &str, other: &str) -> bool {
    let host = |u: &str| crate::dns::provider_endpoint(u).map(|(h, _)| h.trim_end_matches('.').to_string());
    host(url).is_some_and(|h| Some(h) == host(other))
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

    // Тот же разбор, что у остальных списков: со своим точка в конце
    // («youtube.com.») не отрезалась, и домен оставался без обхода.
    (crate::block::parse(&text), None)
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

    #[test]
    fn old_geohide_address_is_updated() {
        let mut config: Config = toml::from_str(&shipped_config()).expect("config.toml должен разбираться");
        config.smart_dns_bootstrap_ip = Some(std::net::IpAddr::from([159, 194, 200, 33]));
        config.replace_dead_smart_dns();
        assert_eq!(config.smart_dns_bootstrap_ip, Some(std::net::IpAddr::from(GEOHIDE_DNS_IP)));
        assert!(config.smart_dns_replaced);
    }

    /// Ключей DNS нет вовсе — значения как в config.toml; адрес по умолчанию
    /// не прикрепляется к чужому провайдеру.
    #[test]
    fn missing_dns_keys_default_like_the_shipped_config() {
        let minimal: String = shipped_config()
            .lines()
            .filter(|l| !["doh_provider", "doh_bootstrap_ip", "smart_dns_provider", "smart_dns_bootstrap_ip"]
                .contains(&l.split('=').next().unwrap_or("").trim()))
            .collect::<Vec<_>>()
            .join("\n");
        let mut config: Config = toml::from_str(&minimal).expect("config.toml без ключей DNS");
        config.drop_foreign_bootstrap();
        let shipped: Config = toml::from_str(&shipped_config()).unwrap();
        assert_eq!(config.doh_provider, shipped.doh_provider);
        assert_eq!(config.doh_bootstrap_ip, shipped.doh_bootstrap_ip);
        assert_eq!(config.smart_dns_provider, shipped.smart_dns_provider);
        assert_eq!(config.smart_dns_bootstrap_ip, shipped.smart_dns_bootstrap_ip);

        // В начало: в конце файла ключ попал бы в последнюю таблицу TOML.
        let own = format!("doh_provider = \"https://dns.example.org/dns-query\"\n{minimal}");
        let mut config: Config = toml::from_str(&own).unwrap();
        config.drop_foreign_bootstrap();
        assert_eq!(config.doh_bootstrap_ip, None, "адрес Quad9 к чужому провайдеру не прикрепляется");
    }

    #[test]
    fn dead_xbox_dns_is_replaced() {
        let text = shipped_config()
            .lines()
            .map(|l| match l.split('=').next().map(str::trim) {
                Some("smart_dns_provider") => "smart_dns_provider = \"https://XBOX-DNS.ru./dns-query\"",
                Some("smart_dns_bootstrap_ip") => "smart_dns_bootstrap_ip = \"111.88.96.56\"",
                _ => l,
            })
            .collect::<Vec<_>>()
            .join("\n");
        let mut config: Config = toml::from_str(&text).expect("config.toml должен разбираться");
        config.replace_dead_smart_dns();
        assert_eq!(config.smart_dns_provider, GEOHIDE_DNS);
        assert_eq!(config.smart_dns_bootstrap_ip, Some(std::net::IpAddr::from(GEOHIDE_DNS_IP)));
        assert!(config.smart_dns_replaced);

        // Comss тоже больше не работает и заменяется так же.
        let mut comss: Config = toml::from_str(&shipped_config()).expect("config.toml должен разбираться");
        comss.smart_dns_provider = "https://dns.comss.one/dns-query".to_string();
        comss.replace_dead_smart_dns();
        assert_eq!(comss.smart_dns_provider, GEOHIDE_DNS);
        assert!(comss.smart_dns_replaced);

        // Свой провайдер не трогаем.
        let mut own: Config = toml::from_str(&shipped_config()).expect("config.toml должен разбираться");
        own.smart_dns_provider = "https://example.org/dns-query".to_string();
        own.replace_dead_smart_dns();
        assert_eq!(own.smart_dns_provider, "https://example.org/dns-query");
        assert!(!own.smart_dns_replaced);
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

    #[test]
    fn empty_bootstrap_address_means_unset() {
        // По ключу, а не по значению: адрес меняется вместе с провайдером.
        let text = shipped_config()
            .lines()
            .map(|l| if l.split('=').next().map(str::trim) == Some("doh_bootstrap_ip") { "doh_bootstrap_ip = \"\"" } else { l })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("doh_bootstrap_ip = \"\""));
        let config: Config = toml::from_str(&text).expect("пустой адрес должен разбираться");
        assert_eq!(config.doh_bootstrap_ip, None);

        let text = text.replace("doh_bootstrap_ip = \"\"", "doh_bootstrap_ip = \"не-адрес\"");
        assert!(toml::from_str::<Config>(&text).is_err());
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
        if config.smart_dns_bootstrap_ip.is_some() {
            assert!(
                crate::dns::provider_endpoint(&config.smart_dns_provider).is_some(),
                "задан smart_dns_bootstrap_ip, но из smart_dns_provider ({}) не извлекается хост",
                config.smart_dns_provider,
            );
        }
    }
}
