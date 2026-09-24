//! Разрешение адресов через DoH.
//!
//! # Зачем
//!
//! Раньше и прокси, и диагностика вызывали `TcpStream::connect("host:443")` —
//! то есть шли через системный резолвер, а значит через DNS провайдера. Того
//! самого, который и блокирует. Инструмент обхода блокировок, зависящий от
//! DNS блокирующей стороны, — слабое место по построению: при подмене ответов
//! соединение уходит не туда, и никакая манипуляция TLS уже не поможет.
//!
//! Второй довод практичнее: системный резолвер выдаёт адреса по кругу, поэтому
//! диагностика могла измерить один IP, а прокси пойти на другой — вердикт не
//! воспроизводился. Общий кэш это устраняет.
//!
//! # Как
//!
//! # Почему выключено по умолчанию
//!
//! Идея правдоподобная, но первое измерение её не подтвердило — и причина
//! оказалась не в DoH, а в конкретном провайдере. Cloudflare по своей
//! документации не отправляет EDNS Client Subnet: это осознанная позиция
//! ради приватности. Из-за этого CDN отвечает узлом, оптимальным для
//! Cloudflare, а не для клиента — на проверке x.com и meduza.io перестали
//! открываться, хотя с адресами системного резолвера работали.
//!
//! Google Public DNS, напротив, опирается на ECS для геолокации. То есть
//! резолв через DoH сам по себе рабочая идея, просто требует резолвера
//! с поддержкой ECS.
//!
//! Поэтому `resolve_via_doh` по умолчанию `false`, а в config.toml рядом
//! с `doh_provider` записано, какой резолвер брать при включении.
//!
//! Резолвер — модульный синглтон, инициализируемый один раз при старте.
//! Так вызывающему коду не нужно протаскивать ещё один `Arc` через шесть
//! слоёв: замена сводится к одной строке на каждой точке подключения.
//!
//! При любой неудаче (DoH недоступен, режим `udp`, домен не разрешился)
//! происходит откат на системный резолвер — прокси не должен переставать
//! работать из-за проблем с DoH.
//!
//! # Наблюдаемость
//!
//! Откат НЕ молчаливый. Иначе возможна ситуация, разрушающая доверие к
//! диагностике: DoH ломается, резолв уходит в системный DNS, тот отдаёт
//! другой адрес, вердикты меняются — и понять причину невозможно. Для
//! проекта про воспроизводимость это неприемлемо.
//!
//! Логируется смена состояния, а не каждое соединение: переход домена на
//! запасной резолвер и возврат обратно. Плюс сам факт запроса к DoH при
//! промахе кэша — то есть примерно раз в TTL на домен.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant};

use tokio::net::TcpStream;

use crate::observability::logging::{log_t, LogLevel, LogSender};

use super::ip_cache::{extract_ips_from_dns_response, IpDomainCache};

/// Сколько держать разрешённые адреса. TTL из DNS-ответа сознательно
/// игнорируется: у CDN он бывает в единицы секунд, а нам важнее, чтобы
/// диагностика и прокси в пределах сессии работали с одним адресом.
const CACHE_TTL: Duration = Duration::from_secs(300);

/// Порог, после которого протухшие записи выбрасываются.
///
/// Без него кэш рос бы неограниченно: записи истекают по времени, но из
/// памяти сами не исчезают, а браузер за сутки обходит тысячи доменов.
/// Тот же приём, что в ip_cache.
const CACHE_MAX_ENTRIES: usize = 10_000;

/// Сколько считать провайдера недоступным после неудачного запроса.
///
/// Неудача не запоминалась, а запросы к одному домену стоят в очереди на
/// замке (`in_flight`). Когда DoH заблокирован, каждый следующий в очереди
/// заново ждал полный таймаут клиента: десять параллельных соединений
/// браузера — и последнее ждало около 50 секунд, прежде чем уйти на
/// системный резолвер. Отказ транспорта — это отказ провайдера, а не
/// домена, поэтому пауза общая для всех имён.
///
/// Коротко, чтобы разовый сбой не уводил резолв в системный DNS надолго.
const PROVIDER_BACKOFF: Duration = Duration::from_secs(15);

struct Entry {
    ips: Vec<IpAddr>,
    expires: Instant,
}

struct Resolver {
    client: reqwest::Client,
    provider: String,
    /// Прямое отображение домен → адреса. Обратное (адрес → домен) живёт
    /// в `IpDomainCache` и используется для обхода при CONNECT по IP.
    forward: RwLock<HashMap<String, Entry>>,
    /// Замок на домен, пока по нему идёт запрос к DoH.
    ///
    /// Браузер открывает к одному хосту десятки соединений разом, и на
    /// холодном кэше каждое отправляло СВОЙ HTTPS-запрос к провайдеру:
    /// полсотни одинаковых запросов вместо одного, и все ждут полный RTT.
    /// Теперь первый идёт за ответом, остальные ждут на замке и забирают
    /// уже готовую запись из кэша.
    in_flight: tokio::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// До какого момента провайдер считается недоступным (см. `PROVIDER_BACKOFF`).
    down_until: std::sync::Mutex<Option<Instant>>,
    ip_cache: Arc<IpDomainCache>,
}

static RESOLVER: OnceLock<Option<Resolver>> = OnceLock::new();

/// Канал логов подключается отдельно от init: он создаётся уже внутри
/// event loop интерфейса, когда резолвер давно поднят.
static LOG: OnceLock<LogSender> = OnceLock::new();

/// Домены, которые сейчас разрешаются через системный резолвер вместо DoH.
/// Нужны, чтобы сообщать о переходе, а не повторять предупреждение на каждое
/// соединение — браузер их открывает десятками.
static ON_FALLBACK: OnceLock<RwLock<std::collections::HashSet<String>>> = OnceLock::new();

fn fallback_set() -> &'static RwLock<std::collections::HashSet<String>> {
    ON_FALLBACK.get_or_init(|| RwLock::new(std::collections::HashSet::new()))
}

/// Подключает канал логов. Вызывается из event loop интерфейса.
pub fn attach_logger(tx: LogSender) {
    let _ = LOG.set(tx);
}

/// Сообщает о переходе домена на системный резолвер — один раз, до возврата.
fn note_fallback(host: &str) {
    let already = fallback_set().read().unwrap().contains(host);
    if already {
        return;
    }
    fallback_set().write().unwrap().insert(host.to_string());

    if let Some(tx) = LOG.get() {
        log_t(tx, LogLevel::Warning, "log.doh_fallback", vec![("domain", host.to_string())]);
    }
}

/// Сообщает, что домен снова разрешается через DoH.
fn note_recovered(host: &str) {
    let was = fallback_set().write().unwrap().remove(host);
    if was && let Some(tx) = LOG.get() {
        log_t(tx, LogLevel::Success, "log.doh_recovered", vec![("domain", host.to_string())]);
    }
}

/// Инициализация при старте. `None` — резолв через DoH выключен, всё идёт
/// через системный резолвер.
pub fn init(
    enabled: bool,
    provider: String,
    bootstrap: Option<std::net::IpAddr>,
    ip_cache: Arc<IpDomainCache>,
) {
    let resolver = if enabled {
        super::doh_client(&provider, bootstrap, Duration::from_secs(5))
            .ok()
            .map(|client| Resolver {
                client,
                provider,
                forward: RwLock::new(HashMap::new()),
                in_flight: tokio::sync::Mutex::new(HashMap::new()),
                down_until: std::sync::Mutex::new(None),
                ip_cache,
            })
    } else {
        None
    };

    let _ = RESOLVER.set(resolver);
}

/// Разрешает `host:port` в один адрес, готовый для подключения.
///
/// Вынесено отдельно от `connect`, потому что резолв и подключение нельзя
/// мерить и ограничивать одним таймаутом: запрос к DoH — это HTTPS-обмен,
/// который на холодном кэше занимает сотни миллисекунд, а при параллельном
/// прогоне и секунды. Диагностика оборачивала `connect` таймаутом в 3 с,
/// внутрь которого попадал и резолв, — и живые домены получали вердикт
/// «TCP не открылся», хотя до них попросту не успевали дойти.
///
/// `None` означает «разрешай сам»: DoH выключен, хост уже адрес,
/// либо резолв не удался и нужен откат на системный резолвер.
pub async fn resolve_first(target: &str) -> Option<SocketAddr> {
    match resolve_target(target).await {
        Resolution::Resolved(addrs) => addrs.into_iter().next(),
        Resolution::Failed(host) => {
            note_fallback(&host);
            None
        }
        Resolution::NotApplicable => None,
    }
}

/// Сколько ждать одного адреса, прежде чем перейти к следующему.
const PER_ADDRESS_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(4);

/// Сколько ждать запасного подключения через системный резолвер, когда ни
/// один адрес от DoH не ответил. Больше, чем на один адрес: системный
/// резолвер может вернуть несколько, и они перебираются по очереди.
const FALLBACK_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Подключается к `host:port`, разрешив имя через DoH.
///
/// Для вызывающего кода это обычный `TcpStream::connect`. Откат на системный
/// резолвер прозрачен по поведению, но не по наблюдаемости: смена источника
/// разрешения попадает в лог, иначе изменившиеся вердикты диагностики
/// невозможно было бы объяснить.
pub async fn connect(target: &str) -> std::io::Result<TcpStream> {
    match resolve_target(target).await {
        Resolution::Resolved(addrs) => {
            // Таймаут на КАЖДЫЙ адрес. Без него один мёртвый адрес в списке
            // (у updates.discord.com 162.159.136.232 не отвечал на SYN)
            // держал подключение около двух минут — столько ядро повторяет
            // SYN, — и до живых адресов дело не доходило.
            if let Ok(stream) = connect_each(&addrs).await {
                return Ok(stream);
            }
            // Адреса получены, но ни один не подключился — это уже не проблема
            // резолва, поэтому откат не отмечаем как отказ DoH. Таймаут и
            // здесь: без него мёртвый адрес от системного резолвера держал бы
            // подключение около двух минут, ровно как было до таймаутов выше.
            match tokio::time::timeout(FALLBACK_CONNECT_TIMEOUT, connect_system(target)).await {
                Ok(result) => result,
                Err(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("{target}: подключение не установилось за {} с", FALLBACK_CONNECT_TIMEOUT.as_secs()),
                )),
            }
        }
        Resolution::Failed(host) => {
            note_fallback(&host);
            connect_system(target).await
        }
        // DoH выключен (так по умолчанию) или хост уже адрес — резолвить
        // нечего, это не отказ. Таймаут на адрес нужен и здесь: раньше эта
        // ветка звала голый `TcpStream::connect`, и при настройках по
        // умолчанию мёртвый адрес по-прежнему держал соединение две минуты.
        Resolution::NotApplicable => connect_system(target).await,
    }
}

/// Подключается к одному адресу, но не дольше [`PER_ADDRESS_CONNECT_TIMEOUT`].
///
/// Для прозрачного режима, где адрес уже известен из conntrack.
pub async fn connect_addr(addr: SocketAddr) -> std::io::Result<TcpStream> {
    match tokio::time::timeout(PER_ADDRESS_CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("{addr}: подключение не установилось за {} с", PER_ADDRESS_CONNECT_TIMEOUT.as_secs()),
        )),
    }
}

/// Перебирает адреса по очереди, каждому — свой таймаут. Возвращает первую
/// удачу либо последнюю ошибку.
async fn connect_each(addrs: &[SocketAddr]) -> std::io::Result<TcpStream> {
    let mut last_error = std::io::Error::new(std::io::ErrorKind::NotFound, "нет адресов для подключения");
    for addr in addrs {
        match connect_addr(*addr).await {
            Ok(stream) => return Ok(stream),
            Err(e) => last_error = e,
        }
    }
    Err(last_error)
}

/// Резолв системным резолвером и перебор адресов с таймаутом на каждый.
///
/// `TcpStream::connect("host:port")` делает то же, но без таймаутов: каждый
/// недоступный адрес стоит полного цикла повторов SYN.
async fn connect_system(target: &str) -> std::io::Result<TcpStream> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(target).await?.collect();
    connect_each(&addrs).await
}

/// Откуда взялся адрес. Различать важно: «DoH выключен» и «DoH сломался» —
/// разные вещи, и во втором случае нужно предупредить.
enum Resolution {
    Resolved(Vec<SocketAddr>),
    NotApplicable,
    Failed(String),
}

/// Разрешает "host:port" в список адресов через DoH.
async fn resolve_target(target: &str) -> Resolution {
    let Some(Some(resolver)) = RESOLVER.get().map(|r| r.as_ref()) else {
        return Resolution::NotApplicable;
    };

    let Some((host, port)) = split_host_port(target) else {
        return Resolution::NotApplicable;
    };

    // Хост уже адрес — резолвить нечего.
    if host.parse::<IpAddr>().is_ok() {
        return Resolution::NotApplicable;
    }

    match resolver.lookup(&host).await {
        Ok(ips) if !ips.is_empty() => {
            note_recovered(&host);
            Resolution::Resolved(ips.into_iter().map(|ip| SocketAddr::new(ip, port)).collect())
        }
        // DoH ответил, но A-записей нет: у домена их и правда может не быть.
        // Предупреждать не о чем — просто подключаемся системным резолвером.
        Ok(_) => {
            note_recovered(&host);
            Resolution::NotApplicable
        }
        Err(()) => Resolution::Failed(host),
    }
}

/// Делит "host:port", корректно обрабатывая IPv6 в скобках.
fn split_host_port(target: &str) -> Option<(String, u16)> {
    if let Some(rest) = target.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = tail.strip_prefix(':')?.parse().ok()?;
        return Some((host.to_string(), port));
    }
    let (host, port) = target.rsplit_once(':')?;
    Some((host.to_lowercase(), port.parse().ok()?))
}

impl Resolver {
    /// `Ok(ips)` — адреса получены. `Ok(empty)` — DoH ответил, но A-записей
    /// нет (так бывает у apex-доменов вроде ytimg.com, где сервис живёт
    /// только на поддоменах). `Err(())` — запрос не удался.
    async fn lookup(&self, host: &str) -> Result<Vec<IpAddr>, ()> {
        if let Some(cached) = self.cached(host) {
            return Ok(cached);
        }

        let Some(query) = build_dns_query(host) else {
            return Err(());
        };

        if self.provider_down() {
            return Err(());
        }

        // Единственный запрос на домен: остальные ждут здесь.
        let gate = {
            let mut map = self.in_flight.lock().await;
            Arc::clone(map.entry(host.to_string()).or_default())
        };
        let _guard = gate.lock().await;

        // Пока ждали замка, первый мог уже всё положить в кэш.
        if let Some(cached) = self.cached(host) {
            self.release_gate(host).await;
            return Ok(cached);
        }
        // А мог и выяснить, что провайдер не отвечает: тогда повторять
        // его таймаут незачем.
        if self.provider_down() {
            self.release_gate(host).await;
            return Err(());
        }

        let outcome = self.query_provider(query, host).await;
        self.set_provider_down(outcome.is_err());
        self.release_gate(host).await;
        outcome
    }

    fn provider_down(&self) -> bool {
        let guard = self.down_until.lock().unwrap();
        guard.is_some_and(|until| Instant::now() < until)
    }

    fn set_provider_down(&self, down: bool) {
        *self.down_until.lock().unwrap() = down.then(|| Instant::now() + PROVIDER_BACKOFF);
    }

    /// Снимает запись о «запрос в полёте», чтобы карта не росла по домену
    /// на каждый когда-либо резолвившийся хост.
    async fn release_gate(&self, host: &str) {
        let mut map = self.in_flight.lock().await;
        if let Some(gate) = map.get(host)
            // Ссылок минимум две: в карте и у нас самих (`gate` в `lookup`
            // жив до конца функции). Раньше здесь сравнивалось с единицей —
            // условие не выполнялось никогда, и карта росла на каждый домен.
            // Больше двух — значит, кто-то ещё ждёт, и запись нужна ему.
            && Arc::strong_count(gate) == 2
        {
            map.remove(host);
        }
    }

    async fn query_provider(&self, query: Vec<u8>, host: &str) -> Result<Vec<IpAddr>, ()> {
        let response = self
            .client
            .post(&self.provider)
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(query)
            .send()
            .await
            .map_err(|_| ())?;

        if !response.status().is_success() {
            return Err(());
        }

        let body = response.bytes().await.map_err(|_| ())?;
        let ips = extract_ips_from_dns_response(&body);
        if ips.is_empty() {
            // Ответ получен, просто A-записей нет — это не отказ DoH.
            return Ok(Vec::new());
        }

        // Промах кэша, то есть примерно раз в TTL на домен: видно, каким
        // резолвером получен адрес, которым потом пользуются прокси
        // и диагностика.
        if let Some(tx) = LOG.get() {
            let listed = ips.iter().map(|ip| ip.to_string()).collect::<Vec<_>>().join(", ");
            log_t(tx, LogLevel::Info, "log.doh_resolved", vec![
                ("domain", host.to_string()),
                ("ips", listed),
            ]);
        }

        // Заполняем и обратный кэш: он нужен, когда клиент шлёт CONNECT
        // сразу на IP, минуя имя из списка обхода.
        for ip in &ips {
            self.ip_cache.insert(*ip, host.to_string());
        }

        {
            let mut guard = self.forward.write().unwrap();
            if guard.len() > CACHE_MAX_ENTRIES {
                let now = Instant::now();
                guard.retain(|_, e| e.expires > now);
            }
            guard.insert(
                host.to_string(),
                Entry { ips: ips.clone(), expires: Instant::now() + CACHE_TTL },
            );
        }

        Ok(ips)
    }

    fn cached(&self, host: &str) -> Option<Vec<IpAddr>> {
        let guard = self.forward.read().unwrap();
        let entry = guard.get(host)?;
        (entry.expires > Instant::now()).then(|| entry.ips.clone())
    }
}

/// Собирает DNS-запрос типа A в формате wire (RFC 1035) — тот же формат,
/// что принимает DoH по RFC 8484.
fn build_dns_query(host: &str) -> Option<Vec<u8>> {
    if host.is_empty() || host.len() > 253 {
        return None;
    }

    let mut out = Vec::with_capacity(host.len() + 18);

    // Идентификатор 0: для DoH он не нужен, ответ приходит по HTTP.
    out.extend_from_slice(&[0x00, 0x00]);
    // Флаги: стандартный запрос с рекурсией
    out.extend_from_slice(&[0x01, 0x00]);
    // QDCOUNT=1, остальные секции пусты
    out.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0x00);

    // QTYPE=A, QCLASS=IN
    out.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_host_and_port() {
        assert_eq!(split_host_port("example.com:443"), Some(("example.com".into(), 443)));
        assert_eq!(split_host_port("Example.COM:80"), Some(("example.com".into(), 80)));
        assert_eq!(split_host_port("[::1]:8080"), Some(("::1".into(), 8080)));
        assert_eq!(split_host_port("no-port"), None);
    }

    #[test]
    fn builds_a_valid_dns_query() {
        let q = build_dns_query("youtube.com").expect("запрос должен собраться");

        // Заголовок: 12 байт, QDCOUNT = 1
        assert_eq!(&q[4..6], &[0x00, 0x01]);
        // Имя кодируется метками с длиной: 7"youtube" 3"com" 0
        assert_eq!(q[12], 7);
        assert_eq!(&q[13..20], b"youtube");
        assert_eq!(q[20], 3);
        assert_eq!(&q[21..24], b"com");
        assert_eq!(q[24], 0);
        // QTYPE=A, QCLASS=IN
        assert_eq!(&q[25..29], &[0x00, 0x01, 0x00, 0x01]);
    }

    /// Провайдер принимает соединение и молчит — так выглядит DoH,
    /// заблокированный по-тихому. Параллельные запросы одного имени не должны
    /// ждать его таймаут по очереди: первый упирается в таймаут, остальные
    /// сразу уходят на системный резолвер.
    #[tokio::test]
    async fn silent_provider_is_waited_for_once_not_per_request() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&accepted);
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                held.push(stream);
            }
        });

        let timeout = Duration::from_millis(400);
        let resolver = Arc::new(Resolver {
            client: crate::dns::doh_client(&format!("http://{addr}/dns-query"), None, timeout).unwrap(),
            provider: format!("http://{addr}/dns-query"),
            forward: RwLock::new(HashMap::new()),
            in_flight: tokio::sync::Mutex::new(HashMap::new()),
            down_until: std::sync::Mutex::new(None),
            ip_cache: Arc::new(IpDomainCache::new()),
        });

        let started = Instant::now();
        let lookups: Vec<_> = (0..5)
            .map(|_| {
                let r = Arc::clone(&resolver);
                tokio::spawn(async move { r.lookup("blocked.example").await })
            })
            .collect();
        for l in lookups {
            assert!(l.await.unwrap().is_err());
        }

        // Без паузы на провайдера это было бы 5 × 400 мс.
        assert!(started.elapsed() < timeout * 2, "ждали {:?}", started.elapsed());
        assert_eq!(accepted.load(Ordering::SeqCst), 1, "к молчащему провайдеру должен уйти один запрос");

        // Другое имя тоже не ждёт: отказ транспорта — это отказ провайдера.
        let other = Instant::now();
        assert!(resolver.lookup("other.example").await.is_err());
        assert!(other.elapsed() < timeout / 2);
    }

    #[test]
    fn rejects_malformed_hostnames() {
        assert_eq!(build_dns_query(""), None);
        assert_eq!(build_dns_query("a..b"), None);
        assert_eq!(build_dns_query(&"x".repeat(64)), None);
    }
}
