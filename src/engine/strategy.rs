//! Выбор стратегии обхода по домену — «лестница с запоминанием».
//!
//! Вместо многорукого бандита (UCB/Thompson) здесь детерминированная схема:
//! диагностика перебирает стратегии от дешёвой к дорогой, первая сработавшая
//! записывается в файл и используется для этого домена дальше. Через TTL
//! запись протухает и домен проверяется заново — этого достаточно вместо CUSUM,
//! потому что провайдер меняет правила не каждую минуту.
//!
//! Почему не бандит: стратегий 4, доменов десятки — это таблица, а не задача
//! исследования пространства. Таблицу можно просто заполнить и прочитать
//! глазами. Так же устроены zapret и GoodbyeDPI: заданные стратегии на домен,
//! никакой статистики.
//!
//! Формат файла (`strategies.txt`) намеренно простой и greppable:
//! ```text
//! domain            strategy      decided_at   confidence  version
//! youtube.com       tls_record    1757100000   0.44        1
//! google.com        none          1757100050   1.00        1
//! ```
//! Строки старого формата (три поля) читаются как version = 0 и потому
//! считаются протухшими — домен просто переизмеряется.
//!
//! Вместо стратегии может стоять `resigned` — вывод «ни одна техника не
//! сработала». Пакет тогда уходит как есть, как и при `none`, но запись
//! живёт час, а не TTL (см. `RESIGNED_TTL_HOURS`).

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::engine::diagnostics::{DiagnosticResult, ProbeOutcome};

const STORE_PATH: &str = "strategies.txt";

/// Версия формата файла — отдельно от версии методики диагностики.
/// Методика отвечает на «сопоставимы ли измерения», формат — на «как
/// разобрать строку». Раньше версионировалось только первое, и добавление
/// нового поля пришлось бы угадывать по числу колонок.
const STORE_FORMAT: u32 = 5;

/// Формат, где вывод «ничего не помогло» писался как `none` с нулевой
/// уверенностью, а не отдельным словом `resigned`. Колонки те же, что
/// в текущем; при чтении такие строки переводятся в явный признак.
const STORE_FORMAT_IMPLICIT_RESIGNED: u32 = 4;

/// Как в файле записывается вывод «ни одна техника не сработала».
const RESIGNED_STORE_STRING: &str = "resigned";

/// Формат без колонки `hello`: все его записи сняты пробой браузерного
/// размера и читаются как [`HelloClass::Large`].
const STORE_FORMAT_WITHOUT_HELLO: u32 = 3;

/// ClientHello короче этого считается маленьким.
///
/// Граница взята по наблюдению, а не из спецификации: две TLS-записи
/// проходили с ClientHello curl (1584 байта) и браузера (~1800) и не
/// проходили с ClientHello rustls у программы обновления Discord (273).
/// Браузеры без постквантового key share дополняют пакет примерно до
/// 520 байт, так что 1000 разводит программы и браузеры по разные стороны.
pub const SMALL_HELLO_MAX: usize = 1000;

/// Класс размера ClientHello. Стратегия хранится для каждого отдельно:
/// одна и та же техника на одном домене работает с большим пакетом
/// и не работает с маленьким.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HelloClass {
    Large,
    Small,
}

impl HelloClass {
    pub fn of(len: usize) -> Self {
        if len < SMALL_HELLO_MAX { HelloClass::Small } else { HelloClass::Large }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            HelloClass::Large => "large",
            HelloClass::Small => "small",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "large" => Some(HelloClass::Large),
            "small" => Some(HelloClass::Small),
            _ => None,
        }
    }
}

type Key = (String, HelloClass);

/// Стратегия обхода для TCP/TLS-пути (HTTPS-туннель).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Strategy {
    /// Обход не нужен — домен открывается напрямую.
    None,
    /// Разрыв точно посередине имени домена в SNI. Позиция вычисляется на лету,
    /// поэтому стратегия переносима между доменами и клиентами.
    SniSplit,
    /// Перестроение ClientHello в две TLS-записи.
    TlsRecord,
    /// Первая половина с TTL=1 не доходит; порядок восстанавливается
    /// ретрансмитом, а DPI видит куски перепутанными.
    Disorder,
    /// Между половинами вставлен OOB-байт: сервер его отбрасывает,
    /// DPI учитывает и сбивается.
    Oob,
    /// Перед настоящим ClientHello уходит поддельный, с чужим именем.
    ///
    /// Единственная ступень, которой не нужен SNI в настоящем пакете:
    /// она его не прячет, а подделывает. Отсюда и единственный класс
    /// протоколов, доступный только ей — без открытого имени вообще
    /// (подключение по IP, ECH, MTProto).
    ///
    /// Сейчас выключена целиком (см. `socket::fake_supported`): отмотать
    /// номер последовательности после приманки через TCP_REPAIR на живом
    /// соединении ядро не даёт даже с CAP_NET_ADMIN.
    Fake,
}

impl Strategy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Strategy::None => "none",
            Strategy::SniSplit => "sni_split",
            Strategy::TlsRecord => "tls_record",
            Strategy::Disorder => "disorder",
            Strategy::Oob => "oob",
            Strategy::Fake => "fake",
        }
    }

    /// Разбирает строку из файла.
    ///
    /// Ни одна ступень больше не несёт параметров: позиция была только
    /// у удалённой HttpsSplit. Старые записи вида `https_split:76`
    /// не совпадут ни с одним вариантом и дадут None — домен
    /// продиагностируется заново.
    pub fn parse(s: &str) -> Option<Strategy> {
        match s {
            "none" => Some(Strategy::None),
            // Ступень удалена вместе со свипом по позициям: она была
            // достижима только через него. Старые записи не распознаются,
            // и домен просто продиагностируется заново.
            "https_split" => None,
            "sni_split" => Some(Strategy::SniSplit),
            "tls_record" => Some(Strategy::TlsRecord),
            "disorder" => Some(Strategy::Disorder),
            "oob" => Some(Strategy::Oob),
            "fake" => Some(Strategy::Fake),
            // Техника убрана как нерабочая; записи из старых strategies.txt
            // не распознаются, и домен просто продиагностируется заново.
            "tiny_chunks" | "socks5_style" => None,
            _ => None,
        }
    }

    /// Как стратегия записывается в файл.
    pub fn to_store_string(&self) -> String {
        self.as_str().to_string()
    }

    /// Ключ локали для показа в логах.
    pub fn label_key(&self) -> &'static str {
        match self {
            Strategy::None => "strategy.none",
            Strategy::SniSplit => "strategy.sni_split",
            Strategy::TlsRecord => "strategy.tls_record",
            Strategy::Disorder => "strategy.disorder",
            Strategy::Oob => "strategy.oob",
            Strategy::Fake => "strategy.fake",
        }
    }
}

/// Верхняя граница шкалы задержки, мс. Всё, что медленнее, штрафуется
/// одинаково: разница между двумя и десятью секундами для пользователя
/// уже несущественна — и то и другое неприемлемо.
const LATENCY_SCALE_MS: f64 = 2000.0;

/// Веса функции полезности.
#[derive(Debug, Clone, Copy)]
pub struct RewardWeights {
    pub reliability: f64,
    pub latency: f64,
}

impl Default for RewardWeights {
    fn default() -> Self {
        Self { reliability: 1.0, latency: 0.3 }
    }
}

/// Функция полезности: `R = w_r·надёжность − w_l·задержка`.
///
/// Из исходной формулы `R = w_s·S − w_l·L + w_t·T − w_p·P` остались два
/// слагаемых — те, что действительно измеряются. Пропускной способности
/// и потерь пакетов на технику у нас нет, и подставлять туда выдуманные
/// величины значило бы придать формуле точность, которой за ней не стоит.
///
/// Надёжность берётся как нижняя граница Уилсона, а не доля успехов:
/// 3/3 по везению не должно обгонять устойчивые 8/10.
///
/// Обе величины нормализованы к 0..1, иначе веса означали бы разное:
/// уверенность измеряется в долях, задержка — в миллисекундах.
pub fn reward(score: &crate::engine::diagnostics::SplitScore, weights: RewardWeights) -> f64 {
    let reliability = score.confidence;
    let latency = score
        .median_ms
        .map(|ms| crate::observability::stats::normalize(ms, 0.0, LATENCY_SCALE_MS))
        // Задержки нет — значит и успехов не было; штрафуем по максимуму.
        .unwrap_or(1.0);

    weights.reliability * reliability - weights.latency * latency
}

/// Выбор по функции полезности среди техник, которые прошли порог.
///
/// В отличие от лестницы, требует, чтобы ВСЕ техники были измерены —
/// иначе сравнивать не с чем. Применяется в тщательном проходе, где это
/// условие выполняется.
///
/// Зачем вообще: наблюдалось, что один и тот же домен в разных прогонах
/// получал то `tls_record`, то `oob`. Значит работают обе, а лестница
/// просто берёт ту, что проверена раньше — без оглядки на то, какая
/// надёжнее и быстрее.
pub fn choose_best(
    result: &DiagnosticResult,
    weights: RewardWeights,
) -> Option<(Strategy, f64)> {
    if result.direct == ProbeOutcome::Success {
        // Обход не нужен — это лучший исход по определению: полная надёжность
        // без штрафа за задержку. Раньше здесь возвращалась бесконечность,
        // и в логе печаталось «inf».
        return Some((Strategy::None, weights.reliability));
    }

    let candidates = [
        (Strategy::TlsRecord, &result.tls_record),
        (Strategy::SniSplit, &result.sni_split),
        (Strategy::Oob, &result.oob),
        (Strategy::Disorder, &result.disorder),
        (Strategy::Fake, &result.fake),
    ];

    candidates
        .into_iter()
        .filter(|(_, score)| score.is_convincing())
        .map(|(strategy, score)| (strategy, reward(score, weights)))
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
}

/// Лестница: от дешёвой стратегии к дорогой. Первая, давшая Success, побеждает.
/// `None` означает, что не сработало вообще ничего.
pub fn choose_from_diagnostics(result: &DiagnosticResult) -> Option<Strategy> {
    if result.direct == ProbeOutcome::Success {
        return Some(Strategy::None);
    }
    // TLS-record split — первым после direct: он единственный не боится
    // пересборки TCP, поэтому если работает, остальное можно не пробовать.
    if result.tls_record.is_convincing() {
        return Some(Strategy::TlsRecord);
    }
    // SNI-сплит идёт раньше свипа: он не зависит от длины ClientHello,
    // а значит переживёт смену браузера и не привязан к одному домену.
    if result.sni_split.is_convincing() {
        return Some(Strategy::SniSplit);
    }
    // OOB дешевле disorder: не платит задержку ретрансмита.
    if result.oob.is_convincing() {
        return Some(Strategy::Oob);
    }
    // Disorder последним: он работает через ретрансмит, а это сотни
    // миллисекунд на каждое соединение.
    if result.disorder.is_convincing() {
        return Some(Strategy::Disorder);
    }
    // Fake последним: он единственный требует CAP_NET_ADMIN, и если
    // работает что-то непривилегированное, брать его незачем. Зато он
    // единственный, кому не нужен SNI в настоящем пакете, — поэтому
    // там, где не прошло ничего, шанс остаётся только у него.
    if result.fake.is_convincing() {
        return Some(Strategy::Fake);
    }
    None
}

/// Разбор содержимого strategies.txt. Отдельно от чтения файла, чтобы
/// разбор проверялся тестами без диска.
fn parse_entries(text: &str) -> HashMap<Key, Entry> {
    // Версия формата проверяется, а не только пишется. Раньше STORE_FORMAT
    // попадал в заголовок и там же и оставался: файл, записанный другой
    // раскладкой колонок, разбирался как придётся.
    let format = parse_store_format(text);
    if let Some(found) = format
        && found != STORE_FORMAT
        && found != STORE_FORMAT_IMPLICIT_RESIGNED
        && found != STORE_FORMAT_WITHOUT_HELLO
    {
        return HashMap::new();
    }
    let has_hello_column = matches!(format, Some(STORE_FORMAT | STORE_FORMAT_IMPLICIT_RESIGNED));
    // В файлах до пятого формата признак отказа выражался нулевой уверенностью
    // у `none`. Прямой успех всегда писался с 1.0, так что перевод однозначен.
    let implicit_resigned = format != Some(STORE_FORMAT);

    let mut map = HashMap::new();
    for line in text.lines() {
        if line.trim_start().starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let mut parts = line.split('\t');
        let (Some(domain), Some(strategy), Some(ts)) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        let strategy = strategy.trim();
        let explicit_resigned = strategy == RESIGNED_STORE_STRING;
        let strategy = if explicit_resigned { Some(Strategy::None) } else { Strategy::parse(strategy) };
        let (Some(strategy), Ok(decided_at)) = (strategy, ts.trim().parse::<u64>()) else {
            continue;
        };
        // Поля появились позже: их отсутствие означает старый формат.
        let confidence = parts.next().and_then(|c| c.trim().parse::<f64>().ok()).unwrap_or(0.0);
        let resigned = explicit_resigned
            || (implicit_resigned && strategy == Strategy::None && confidence <= f64::EPSILON);
        let version = parts.next().and_then(|v| v.trim().parse::<u32>().ok()).unwrap_or(0);

        // Вердикт, снятый другой версией методики, не просто игнорируется при
        // чтении — он и не загружается. Иначе такие строки жили бы в файле
        // вечно: `usable` их не признаёт, а `save` честно пишет обратно всё,
        // что лежит в памяти, и strategies.txt только растёт. Домен всё равно
        // переизмеряется и записывается заново.
        if version != crate::engine::diagnostics::DIAGNOSTIC_VERSION {
            continue;
        }
        let live_ok = parts.next().and_then(|v| v.trim().parse::<u32>().ok()).unwrap_or(0);
        let live_fail = parts.next().and_then(|v| v.trim().parse::<u32>().ok()).unwrap_or(0);
        let class = if has_hello_column {
            match parts.next().and_then(|c| HelloClass::parse(c.trim())) {
                Some(c) => c,
                None => continue,
            }
        } else {
            HelloClass::Large
        };

        map.insert((normalize_domain(domain), class), Entry {
            strategy, decided_at, confidence, version,
            resigned,
            failures: 0,
            live_ok, live_fail,
        });
    }

    map
}

/// Достаёт `format=N` из строки-заголовка. `None` — заголовка нет
/// (файл, записанный до появления версии).
fn parse_store_format(text: &str) -> Option<u32> {
    text.lines()
        .take_while(|l| l.trim_start().starts_with('#'))
        .find_map(|l| {
            l.split_whitespace()
                .find_map(|tok| tok.strip_prefix("format="))
                .and_then(|v| v.parse().ok())
        })
}

/// Единая нормализация ключа. Раньше `set`, `remove` и `load` приводили домен
/// к нижнему регистру, а `lookup` брал строку как есть — расхождение не било
/// только потому, что вызывающие уже нормализуют домен сами.
fn normalize_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_lowercase()
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// Сколько подряд неудач в бою до сброса записи.
///
/// Три, а не одна: соединение может оборваться по причинам, не связанным
/// со стратегией — сервер закрыл, сеть моргнула, пользователь ушёл со
/// страницы. Одиночный провал ничего не доказывает, три подряд — уже
/// закономерность.
const MAX_CONSECUTIVE_FAILURES: u32 = 3;

/// Сколько часов помнить вывод «ничего не помогло».
///
/// Меньше обычного TTL, и намеренно: это не измеренное решение, а признание
/// поражения. Провайдер мог перенастроить DPI, домен мог переехать — такое
/// стоит перепроверять скоро. Но не при каждом соединении: диагностика это
/// десяток проб с паузами, и гонять её на каждый запрос дороже, чем час
/// походить без обхода.
const RESIGNED_TTL_HOURS: u64 = 1;

#[derive(Debug, Clone, Copy)]
struct Entry {
    strategy: Strategy,
    decided_at: u64,
    /// Нижняя граница Уилсона на момент решения — видно, насколько твёрдым
    /// был выбор, а не только что он когда-то был сделан.
    confidence: f64,
    /// Версия методики. Записи, снятые другой версией, несопоставимы
    /// с текущей логикой и считаются протухшими.
    version: u32,
    /// Вывод «ни одна техника не сработала»: пакет уходит как есть, но не
    /// потому, что прямое соединение работает.
    ///
    /// Стратегия у обоих выводов одна — `None`, — а обращаться с ними надо
    /// по-разному: у отказа короткий TTL, его не проверяют в бою и не
    /// одалживают маленькому ClientHello. Раньше отказ опознавался по нулевой
    /// уверенности; такой признак ломается от любой правки формулы
    /// уверенности и не читается глазами в strategies.txt.
    resigned: bool,
    /// Неудач подряд при реальном использовании. Обнуляется при успехе.
    failures: u32,
    /// Накопленные исходы применения в бою за всё время жизни записи.
    ///
    /// Хранятся на диске вместе со стратегией: без этого свидетельства
    /// обнулялись при каждом перезапуске, и статистика, ради которой
    /// верификация и делалась, никогда бы не накопилась.
    ///
    /// Отличаются от `confidence` тем, что та — снимок на момент решения
    /// по нескольким пробам, а это — то, что происходит на самом деле.
    live_ok: u32,
    live_fail: u32,
}

/// Откуда взята стратегия при поиске.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchKind {
    /// Домен измерялся сам.
    Exact,
    /// Решение унаследовано от родительского домена.
    Inherited,
}

#[derive(Default)]
pub struct StrategyStore {
    inner: RwLock<HashMap<Key, Entry>>,
    /// Когда для пары «домен + размер» последний раз запускалась
    /// автоматическая диагностика. Не даёт запускать её на каждое
    /// соединение, пока она идёт или если ничего не нашла.
    auto_diagnosis: std::sync::Mutex<HashMap<Key, std::time::Instant>>,
    /// Сколько раз стратегия применялась в бою и чем это кончилось.
    ///
    /// Без этих чисел покрытие («23 из 29») ничего не говорит о качестве
    /// выбора: неизвестно, сколько решений оказались ошибочными и сколько
    /// доменов записаны в безнадёжные напрасно. Порог уверенности остаётся
    /// эвристикой ровно до тех пор, пока доля неудач не измерена.
    verifications: std::sync::atomic::AtomicU64,
    verification_failures: std::sync::atomic::AtomicU64,
    invalidations: std::sync::atomic::AtomicU64,
    /// Есть ли изменения, не попавшие на диск.
    ///
    /// Без него `live_ok`/`live_fail` не переживали перезапуск, хотя вся
    /// верификация задумана ради накопления именно этих чисел: `save()`
    /// вызывался только при инвалидации (а она запись удаляет) и после
    /// массового прогона (а он их только что обнулил). Писать на каждое
    /// соединение нельзя — это файл на диске в горячем пути, — поэтому
    /// изменения помечаются, а сбрасывает их по таймеру event loop.
    dirty: std::sync::atomic::AtomicBool,
    /// Упорядочивает сохранения на диск (см. `save`).
    save_lock: std::sync::Mutex<()>,
}

/// Накопленная обратная связь по применению стратегий.
#[derive(Debug, Clone, Copy)]
pub struct VerificationStats {
    /// Соединений, где применялась стратегия из кэша.
    pub total: u64,
    /// Из них без единого байта в ответ.
    pub failures: u64,
    /// Записей сброшено после трёх неудач подряд.
    pub invalidations: u64,
}

impl VerificationStats {
    /// Доля неудачных применений. `None`, если данных ещё нет.
    pub fn failure_rate(&self) -> Option<f64> {
        (self.total > 0).then(|| self.failures as f64 / self.total as f64)
    }
}

impl StrategyStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Читает файл при старте. Битые строки пропускаются молча — файл
    /// правится руками, и одна кривая строка не должна ронять весь кэш.
    pub fn load() -> Self {
        let store = Self::new();
        let Ok(text) = crate::config::paths::read_to_string(STORE_PATH) else {
            return store;
        };

        *store.inner.write().unwrap() = parse_entries(&text);
        store
    }

    /// Стратегия для домена, если запись есть и не протухла.
    ///
    /// Если точной записи нет, проверяются родительские домены: диагностика
    /// гоняется по списку из bypass_domains.txt, где записан `googlevideo.com`,
    /// а соединения идут на `rr3---sn-pivhx-n8vs.googlevideo.com`. Без этого
    /// поддомены получали обход (needs_bypass суффиксный), но стратегию
    /// не находили и откатывались на дефолт.
    /// То же, но сообщает, откуда взято решение: точная запись или родительский
    /// домен. Разные поддомены одного сайта могут вести себя неодинаково
    /// (`api.` и `cdn.` живут на разных адресах), поэтому наследование —
    /// разумный запасной вариант, а не равноценная замена точному измерению.
    pub fn lookup_detailed(&self, domain: &str, class: HelloClass, ttl_hours: u64) -> Option<(Strategy, MatchKind)> {
        let key = normalize_domain(domain);
        let guard = self.inner.read().unwrap();
        let ttl_secs = ttl_hours.saturating_mul(3600);
        let resigned_ttl_secs = RESIGNED_TTL_HOURS.saturating_mul(3600).min(ttl_secs);
        let now = now_secs();

        // Запись годится, если не протухла по времени И снята текущей
        // версией методики: после смены профиля ClientHello или набора
        // техник прошлые вердикты несопоставимы с новыми.
        let usable = |entry: &Entry| {
            let ttl = if entry.resigned { resigned_ttl_secs } else { ttl_secs };
            now.saturating_sub(entry.decided_at) < ttl
                && entry.version == crate::engine::diagnostics::DIAGNOSTIC_VERSION
        };

        // Точная запись решает всё: если она протухла, наследовать стратегию
        // у родителя НЕЛЬЗЯ. Наследование заодно отменяет переизмерение
        // (см. `adaptive::select`), и поддомен с протухшей записью навсегда
        // застрял бы на родительской стратегии, ни разу не перепроверившись.
        // Лучше дефолт на несколько секунд и честная диагностика.
        if let Some(entry) = guard.get(&(key.clone(), class)) {
            return usable(entry).then_some((entry.strategy, MatchKind::Exact));
        }

        // «Без обхода» по наследству не передаётся. Поддомен, который сам
        // записан в bypass_domains.txt, живёт на своих адресах и режется
        // отдельно: gateway.discord.gg получал `none` от discord.gg и шёл
        // напрямую, и ошибка жила, пока её не ловила проверка в бою самого
        // discord.gg. Лучше дефолтный обход, чем уверенно выключенный.
        //
        // Протухший предок не обрывает подъём: раньше здесь стоял `return`, и
        // стоило `googlevideo.com` протухнуть, как поддомен получал None, хотя
        // выше по дереву могла лежать свежая запись. Теперь перебор идёт
        // дальше, до первого предка, который годится.
        for parent in crate::bypass::parent_domains(&key) {
            if let Some(entry) = guard.get(&(parent.to_string(), class))
                && entry.strategy != Strategy::None
                && usable(entry)
            {
                return Some((entry.strategy, MatchKind::Inherited));
            }
        }

        None
    }

    /// Убирает запись — вызывается, когда диагностика больше не находит
    /// рабочую стратегию. Без этого одна случайная удача жила бы до конца TTL.
    pub fn remove(&self, domain: &str, class: HelloClass) {
        self.inner.write().unwrap().remove(&(normalize_domain(domain), class));
        self.mark_dirty();
    }

    /// Запоминает вывод «ни одна техника не сработала».
    ///
    /// Без этой записи `lookup_detailed` возвращал None, вызывающий код брал
    /// стратегию по умолчанию — и применял технику, про которую диагностика
    /// только что выяснила, что она не работает. Хуже того, у такого выбора
    /// нет `source`, поэтому проверка в бою (три провала — запись долой) к
    /// нему не применялась: сломанная техника применялась к домену вечно и
    /// без обратной связи. Именно так ломалась закачка обновлений Discord —
    /// напрямую файл качался, через обход рвался с битой TLS-записью.
    pub fn set_resigned(&self, domain: &str, class: HelloClass) {
        self.insert(domain, class, Strategy::None, 0.0, true);
    }

    pub fn set(&self, domain: &str, class: HelloClass, strategy: Strategy, confidence: f64) {
        self.insert(domain, class, strategy, confidence, false);
    }

    /// Итог диагностики, в которой не прошла ни одна техника.
    ///
    /// Отказ записывается, только если сервер вообще был досягаем. Если
    /// прямая проба не открыла даже TCP (`ConnectFailed`), провалились все
    /// пробы разом — а это сбой сети, DNS или блокировка по IP, и о техниках
    /// такой прогон ничего не говорит. Записать его как отказ значило бы
    /// после минутного обрыва связи на час оставить домен без обхода.
    /// Тогда старая запись просто убирается, как было до появления отказа.
    ///
    /// Возвращает true, если записан отказ.
    pub fn record_nothing_worked(&self, domain: &str, class: HelloClass, result: &DiagnosticResult) -> bool {
        if result.direct == ProbeOutcome::ConnectFailed {
            self.remove(domain, class);
            false
        } else {
            self.set_resigned(domain, class);
            true
        }
    }

    /// Есть ли для пары «домен + размер» действующий вывод «ничего не
    /// помогло». Нужен `adaptive::select`: такой вывод не одалживается
    /// ClientHello другого размера.
    pub fn is_resigned(&self, domain: &str, class: HelloClass, ttl_hours: u64) -> bool {
        let key = (normalize_domain(domain), class);
        let resigned = self.inner.read().unwrap().get(&key).is_some_and(|e| e.resigned);
        resigned && self.lookup_detailed(domain, class, ttl_hours).is_some()
    }

    fn insert(&self, domain: &str, class: HelloClass, strategy: Strategy, confidence: f64, resigned: bool) {
        let key = (normalize_domain(domain), class);
        let mut guard = self.inner.write().unwrap();

        // Накопленные исходы переживают переизмерение, если техника та же:
        // они описывают поведение КОНКРЕТНОЙ стратегии на этом домене, и
        // повторное подтверждение того же выбора их не обесценивает. При
        // смене техники счётчики обнуляются — они относились бы к другой.
        let (live_ok, live_fail) = match guard.get(&key) {
            Some(existing) if existing.strategy == strategy && existing.resigned == resigned => {
                (existing.live_ok, existing.live_fail)
            }
            _ => (0, 0),
        };

        guard.insert(key, Entry {
            strategy,
            decided_at: now_secs(),
            confidence,
            version: crate::engine::diagnostics::DIAGNOSTIC_VERSION,
            resigned,
            failures: 0,
            live_ok,
            live_fail,
        });
        drop(guard);
        self.mark_dirty();
    }

    /// Отмечает исход реального использования стратегии.
    ///
    /// Закрывает главный пробел: решение принималось по нескольким пробам
    /// и дальше жило сутки без единой проверки. Порог уверенности оставался
    /// инженерной эвристикой, потому что доля ошибочных решений нигде не
    /// измерялась, а протухшую запись мог сбросить только TTL.
    ///
    /// Возвращает true, если запись была сброшена — вызывающий код тогда
    /// сообщает об этом в лог.
    pub fn record_outcome(&self, domain: &str, class: HelloClass, succeeded: bool) -> bool {
        use std::sync::atomic::Ordering;

        let exact = (normalize_domain(domain), class);
        let mut guard = self.inner.write().unwrap();

        // Ключ ищется той же лестницей, что и в `lookup_detailed`: точная
        // запись, иначе ближайший родитель.
        //
        // Раньше здесь брался только точный ключ, и это обесценивало всю
        // верификацию ровно там, где она нужнее всего. Наследование
        // существует именно ради доменов без собственной записи —
        // `rr3---sn-....googlevideo.com` берёт стратегию у `googlevideo.com`.
        // Такой поддомен получал стратегию, применял её, а исход уходил
        // в никуда: записи под своим именем у него нет, `get_mut` возвращал
        // None. В итоге нерабочая унаследованная стратегия не набирала
        // ни одной неудачи и не сбрасывалась никогда, а счётчики
        // применений не учитывали самый массовый класс соединений.
        let key = if guard.contains_key(&exact) {
            exact
        } else {
            // Записи «без обхода» пропускаются ровно как в `lookup_detailed`:
            // стратегию поддомену дала не она, и засчитывать ей чужие провалы
            // значило бы сбросить рабочий `none`, оставив нерабочую технику.
            let owner = crate::bypass::parent_domains(&exact.0).find(|p| {
                guard
                    .get(&(p.to_string(), class))
                    .is_some_and(|e| e.strategy != Strategy::None)
            });
            match owner {
                Some(parent) => (parent.to_string(), class),
                None => return false,
            }
        };

        let Some(entry) = guard.get_mut(&key) else {
            return false;
        };

        // Отказ не проверяется: что прямое соединение не проходит, он и так
        // утверждает, и счёт его провалов сбрасывал бы запись через три
        // соединения вместо часа — с новой диагностикой каждый раз.
        //
        // Запись «прямое соединение работает» проверяется наравне с
        // техниками. Раньше её пропускали, и вердикт, снятый одной удачной
        // пробой, жил сутки без обратной связи: если DPI пропускал пакеты
        // через раз, домен до конца TTL ходил без обхода и не открывался.
        if entry.resigned {
            return false;
        }

        self.verifications.fetch_add(1, Ordering::Relaxed);
        if !succeeded {
            self.verification_failures.fetch_add(1, Ordering::Relaxed);
        }

        if succeeded {
            entry.failures = 0;
            entry.live_ok = entry.live_ok.saturating_add(1);
            drop(guard);
            self.mark_dirty();
            return false;
        }

        entry.failures += 1;
        entry.live_fail = entry.live_fail.saturating_add(1);
        let invalidated = entry.failures >= MAX_CONSECUTIVE_FAILURES;
        if invalidated {
            guard.remove(&key);
            self.invalidations.fetch_add(1, Ordering::Relaxed);
        }
        drop(guard);
        self.mark_dirty();
        invalidated
    }

    /// Расхождение между тем, что обещала диагностика, и тем, что вышло в бою.
    ///
    /// Возвращает домены, где накопилось хотя бы `min_samples` применений,
    /// отсортированные по доле неудач. Это и есть измерение, которого не
    /// хватало: пока его нет, порог уверенности остаётся эвристикой,
    /// а покрытие «23 из 29» ничего не говорит о качестве выбора.
    pub fn live_disagreements(&self, min_samples: u32) -> Vec<(String, Strategy, f64, f64)> {
        let guard = self.inner.read().unwrap();
        let mut rows: Vec<(String, Strategy, f64, f64)> = guard
            .iter()
            .filter_map(|((domain, class), e)| {
                let total = e.live_ok + e.live_fail;
                (total >= min_samples).then(|| {
                    let live_rate = e.live_fail as f64 / total as f64;
                    let name = match class {
                        HelloClass::Large => domain.clone(),
                        HelloClass::Small => format!("{domain} (small)"),
                    };
                    (name, e.strategy, e.confidence, live_rate)
                })
            })
            .collect();
        rows.sort_by(|a, b| b.3.partial_cmp(&a.3).unwrap_or(std::cmp::Ordering::Equal));
        rows
    }

    /// Снимок накопленной обратной связи.
    pub fn verification_stats(&self) -> VerificationStats {
        use std::sync::atomic::Ordering;
        VerificationStats {
            total: self.verifications.load(Ordering::Relaxed),
            failures: self.verification_failures.load(Ordering::Relaxed),
            invalidations: self.invalidations.load(Ordering::Relaxed),
        }
    }

    /// Сохраняет весь кэш на диск. Возвращает ошибку строкой — вызывающий код
    /// решает, как её показать.
    pub fn save(&self) -> Result<(), std::io::Error> {
        use std::sync::atomic::Ordering;

        // Сохранения идут строго по одному. Иначе два параллельных `save()`
        // (автодиагностика, сброс по таймеру, инвалидация) могли закончиться
        // так, что последним переименовывался более старый снимок, и на диске
        // оставалось состояние без свежих изменений.
        let _serial = self.save_lock.lock().unwrap_or_else(|e| e.into_inner());

        // Флаг снимается ДО снимка: изменение, сделанное во время записи,
        // снова поднимет его и попадёт в следующее сохранение. Раньше флаг
        // сбрасывался после записи и стирал такую пометку.
        self.dirty.store(false, Ordering::Relaxed);

        let guard = self.inner.read().unwrap();
        let mut lines: Vec<String> = guard
            .iter()
            .map(|((domain, class), e)| format!(
                "{}\t{}\t{}\t{:.2}\t{}\t{}\t{}\t{}",
                domain,
                if e.resigned { RESIGNED_STORE_STRING.to_string() } else { e.strategy.to_store_string() },
                e.decided_at,
                e.confidence, e.version, e.live_ok, e.live_fail, class.as_str()
            ))
            .collect();
        // Блокировка не держится на время записи на диск: иначе `set` и
        // `record_outcome` из обработчиков соединений ждали бы файловую
        // систему на синхронном замке, занимая рабочие потоки tokio.
        drop(guard);
        lines.sort();

        let header = format!(
            "# format={} columns=domain,strategy,decided_at,confidence,version,live_ok,live_fail,hello\n",
            STORE_FORMAT
        );
        let written = crate::config::paths::write_atomic(STORE_PATH, &(header + &lines.join("\n") + "\n"));
        // Запись не удалась — изменения по-прежнему не на диске.
        if written.is_err() {
            self.mark_dirty();
        }
        written
    }

    /// Есть ли несохранённые изменения. Читает `cli`, чтобы сбрасывать
    /// хранилище на диск по таймеру и при выходе.
    pub fn is_dirty(&self) -> bool {
        self.dirty.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn mark_dirty(&self) {
        self.dirty.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn len(&self) -> usize {
        self.inner.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.read().unwrap().is_empty()
    }

    /// Можно ли сейчас запустить автоматическую диагностику для пары
    /// «домен + размер». Если да — момент запуска запоминается, и следующий
    /// вызов в пределах `cooldown` вернёт false.
    ///
    /// Пауза покрывает и идущую диагностику (десятки соединений подряд
    /// не должны запускать десятки прогонов), и неудачную: если не сработало
    /// ничего, повторять прогон на каждое соединение бессмысленно.
    pub fn claim_auto_diagnosis(&self, domain: &str, class: HelloClass, cooldown: std::time::Duration) -> bool {
        let key = (normalize_domain(domain), class);
        let now = std::time::Instant::now();
        let mut guard = self.auto_diagnosis.lock().unwrap();
        match guard.get(&key) {
            Some(started) if now.duration_since(*started) < cooldown => false,
            _ => {
                guard.insert(key, now);
                true
            }
        }
    }
}

/// Уверенность, с которой диагностика выбрала стратегию.
pub fn confidence_of(result: &DiagnosticResult, chosen: Strategy) -> f64 {
    match chosen {
        Strategy::TlsRecord => result.tls_record.confidence,
        Strategy::SniSplit => result.sni_split.confidence,
        Strategy::Disorder => result.disorder.confidence,
        Strategy::Oob => result.oob.confidence,
        Strategy::Fake => result.fake.confidence,
        Strategy::None => 1.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::engine::diagnostics::SplitScore;

    fn result(direct: ProbeOutcome, split_ok: bool) -> DiagnosticResult {
        let sni = if split_ok {
            SplitScore { successes: 3, attempts: 3, confidence: 0.44, median_ms: Some(120.0) }
        } else {
            SplitScore { successes: 0, attempts: 3, confidence: 0.0, median_ms: None }
        };
        DiagnosticResult {
            direct,
            quic: ProbeOutcome::NotApplicable,
            tls_record: SplitScore { successes: 0, attempts: 3, confidence: 0.0, median_ms: None },
            sni_split: sni,
            disorder: SplitScore { successes: 0, attempts: 3, confidence: 0.0, median_ms: None },
            oob: SplitScore { successes: 0, attempts: 3, confidence: 0.0, median_ms: None },
            fake: SplitScore { successes: 0, attempts: 3, confidence: 0.0, median_ms: None },
        }
    }

    #[test]
    fn prefers_direct_when_nothing_is_blocked() {
        let r = result(ProbeOutcome::Success, true);
        assert_eq!(choose_from_diagnostics(&r), Some(Strategy::None));
    }

    #[test]
    fn falls_back_to_split_then_socks5() {
        let r = result(ProbeOutcome::SilentDrop, true);
        assert_eq!(choose_from_diagnostics(&r), Some(Strategy::SniSplit));

        let r = result(ProbeOutcome::SilentDrop, false);
        assert_eq!(choose_from_diagnostics(&r), None);
    }

    #[test]
    fn returns_none_when_everything_fails() {
        let r = result(ProbeOutcome::SilentDrop, false);
        assert_eq!(choose_from_diagnostics(&r), None);
    }

    #[test]
    fn tls_record_wins_over_everything_but_direct() {
        let mut r = result(ProbeOutcome::SilentDrop, true);
        r.sni_split = SplitScore { successes: 3, attempts: 3, confidence: 0.44, median_ms: Some(120.0) };
        r.tls_record = SplitScore { successes: 3, attempts: 3, confidence: 0.44, median_ms: Some(120.0) };
        assert_eq!(choose_from_diagnostics(&r), Some(Strategy::TlsRecord));

        // но если домен открывается напрямую — обход не нужен вовсе
        let mut r = result(ProbeOutcome::Success, true);
        r.tls_record = SplitScore { successes: 3, attempts: 3, confidence: 0.44, median_ms: Some(120.0) };
        assert_eq!(choose_from_diagnostics(&r), Some(Strategy::None));
    }

    #[test]
    fn sni_split_is_chosen_when_it_works() {
        let mut r = result(ProbeOutcome::SilentDrop, true);
        r.sni_split = SplitScore { successes: 3, attempts: 3, confidence: 0.44, median_ms: Some(120.0) };
        assert_eq!(choose_from_diagnostics(&r), Some(Strategy::SniSplit));
    }

    #[test]
    fn strategy_survives_string_round_trip() {
        let s = Strategy::TlsRecord;
        assert_eq!(Strategy::parse(&s.to_store_string()), Some(s));
        // Удалённые ступени не распознаются — домен переизмеряется
        assert_eq!(Strategy::parse("https_split"), None);
        assert_eq!(Strategy::parse("none"), Some(Strategy::None));
        assert_eq!(Strategy::parse("sni_split"), Some(Strategy::SniSplit));
        assert_eq!(Strategy::parse("tls_record"), Some(Strategy::TlsRecord));
        // Убранная техника не распознаётся — домен продиагностируется заново
        assert_eq!(Strategy::parse("tiny_chunks"), None);
        assert_eq!(Strategy::parse("socks5_style"), None);
    }

    #[test]
    fn fake_is_chosen_when_nothing_else_works() {
        // Fake — единственная техника, не показывающая настоящий SNI в первом
        // пакете, поэтому там, где остальные провалились, выбор за ним.
        let mut r = result(ProbeOutcome::SilentDrop, false);
        r.fake = SplitScore { successes: 3, attempts: 3, confidence: 0.44, median_ms: Some(150.0) };
        assert_eq!(choose_from_diagnostics(&r), Some(Strategy::Fake));
    }

    #[test]
    fn unprivileged_technique_wins_over_fake() {
        // Fake требует CAP_NET_ADMIN — если работает что-то без привилегий,
        // лестница берёт его, даже когда fake тоже прошёл.
        let mut r = result(ProbeOutcome::SilentDrop, false);
        r.fake = SplitScore { successes: 3, attempts: 3, confidence: 0.44, median_ms: Some(150.0) };
        r.disorder = SplitScore { successes: 3, attempts: 3, confidence: 0.44, median_ms: Some(400.0) };
        assert_eq!(choose_from_diagnostics(&r), Some(Strategy::Disorder));

        // А прямой доступ отменяет обход вовсе
        let mut r = result(ProbeOutcome::Success, false);
        r.fake = SplitScore { successes: 3, attempts: 3, confidence: 0.44, median_ms: Some(150.0) };
        assert_eq!(choose_from_diagnostics(&r), Some(Strategy::None));
    }

    #[test]
    fn unmeasured_fake_is_never_chosen() {
        // Без прав диагностика не гоняет fake и оставляет 0/0. Такой счёт не
        // должен выглядеть ни успехом, ни поводом выбрать технику.
        let mut r = result(ProbeOutcome::SilentDrop, false);
        r.fake = SplitScore { successes: 0, attempts: 0, confidence: 0.0, median_ms: None };
        assert_eq!(choose_from_diagnostics(&r), None);
        assert_eq!(choose_best(&r, RewardWeights::default()), None);
    }

    #[test]
    fn fake_competes_in_reward_choice() {
        let mut r = result(ProbeOutcome::SilentDrop, false);
        r.fake = SplitScore { successes: 3, attempts: 3, confidence: 0.44, median_ms: Some(150.0) };
        assert_eq!(choose_best(&r, RewardWeights::default()).map(|(s, _)| s), Some(Strategy::Fake));

        // При равной надёжности выигрывает более быстрая техника
        r.oob = SplitScore { successes: 3, attempts: 3, confidence: 0.44, median_ms: Some(80.0) };
        assert_eq!(choose_best(&r, RewardWeights::default()).map(|(s, _)| s), Some(Strategy::Oob));
    }

    #[test]
    fn fake_survives_string_round_trip() {
        assert_eq!(Strategy::parse("fake"), Some(Strategy::Fake));
        assert_eq!(Strategy::parse(&Strategy::Fake.to_store_string()), Some(Strategy::Fake));
        assert_eq!(Strategy::Fake.label_key(), "strategy.fake");
    }

    #[test]
    fn single_lucky_probe_is_not_enough() {
        // 1/3 — наивно «работает», но доказательств мало
        let mut r = result(ProbeOutcome::SilentDrop, false);
        r.tls_record = SplitScore { successes: 1, attempts: 3, confidence: 0.06, median_ms: Some(120.0) };
        assert_eq!(choose_from_diagnostics(&r), None);

        // 2/3 — уже воспроизводимо
        r.tls_record = SplitScore { successes: 2, attempts: 3, confidence: 0.21, median_ms: Some(120.0) };
        assert_eq!(choose_from_diagnostics(&r), Some(Strategy::TlsRecord));
    }

    #[test]
    fn lookup_normalizes_the_key() {
        let store = StrategyStore::new();
        store.set("Example.COM", HelloClass::Large, Strategy::TlsRecord, 0.44);
        assert_eq!(store.lookup_detailed("example.com", HelloClass::Large, 24).map(|(s, _)| s), Some(Strategy::TlsRecord));
        assert_eq!(store.lookup_detailed("EXAMPLE.com", HelloClass::Large, 24).map(|(s, _)| s), Some(Strategy::TlsRecord));
        // Завершающая точка в FQDN тоже не должна создавать вторую запись
        assert_eq!(store.lookup_detailed("example.com.", HelloClass::Large, 24).map(|(s, _)| s), Some(Strategy::TlsRecord));
    }

    #[test]
    fn lookup_reports_where_the_decision_came_from() {
        let store = StrategyStore::new();
        store.set("googlevideo.com", HelloClass::Large, Strategy::TlsRecord, 0.44);
        assert_eq!(
            store.lookup_detailed("googlevideo.com", HelloClass::Large, 24).map(|(_, k)| k),
            Some(MatchKind::Exact)
        );
        assert_eq!(
            store.lookup_detailed("rr3.googlevideo.com", HelloClass::Large, 24).map(|(_, k)| k),
            Some(MatchKind::Inherited)
        );
    }

    #[test]
    fn subdomain_inherits_parent_strategy() {
        let store = StrategyStore::new();
        store.set("googlevideo.com", HelloClass::Large, Strategy::TlsRecord, 0.44);
        // Видеосерверы YouTube имеют уникальные имена, записи под них нет
        assert_eq!(
            store.lookup_detailed("rr3---sn-pivhx-n8vs.googlevideo.com", HelloClass::Large, 24).map(|(s, _)| s),
            Some(Strategy::TlsRecord)
        );
    }

    #[test]
    fn subdomain_does_not_inherit_no_bypass() {
        let store = StrategyStore::new();
        store.set("discord.gg", HelloClass::Large, Strategy::None, 1.0);
        // Своей записи нет, а «без обхода» от родителя не берётся —
        // вызывающий код применит дефолтную технику
        assert_eq!(store.lookup_detailed("gateway.discord.gg", HelloClass::Large, 24), None);
        // Сам родитель своё решение сохраняет
        assert_eq!(
            store.lookup_detailed("discord.gg", HelloClass::Large, 24),
            Some((Strategy::None, MatchKind::Exact))
        );
        // Выше по цепочке может найтись настоящая техника
        store.set("example.com", HelloClass::Large, Strategy::TlsRecord, 0.44);
        store.set("a.example.com", HelloClass::Large, Strategy::None, 1.0);
        assert_eq!(
            store.lookup_detailed("b.a.example.com", HelloClass::Large, 24),
            Some((Strategy::TlsRecord, MatchKind::Inherited))
        );
    }

    #[test]
    fn exact_entry_wins_over_parent() {
        let store = StrategyStore::new();
        store.set("googlevideo.com", HelloClass::Large, Strategy::TlsRecord, 0.44);
        store.set("rr3.googlevideo.com", HelloClass::Large, Strategy::SniSplit, 0.44);
        assert_eq!(store.lookup_detailed("rr3.googlevideo.com", HelloClass::Large, 24).map(|(s, _)| s), Some(Strategy::SniSplit));
    }

    #[test]
    fn live_outcome_of_a_subdomain_reaches_the_parent_entry() {
        // Поддомен пользуется стратегией родителя, значит и отвечать за неё
        // должен родитель: иначе техника, выбранная для googlevideo.com,
        // применяется к каждому видеосерверу и не получает ни одной оценки.
        let store = StrategyStore::new();
        store.set("googlevideo.com", HelloClass::Large, Strategy::TlsRecord, 0.44);

        for _ in 0..MAX_CONSECUTIVE_FAILURES - 1 {
            assert!(!store.record_outcome("rr3---sn-pivhx.googlevideo.com", HelloClass::Large, false));
        }
        // Третья неудача подряд сбрасывает запись родителя
        assert!(store.record_outcome("rr5---sn-other.googlevideo.com", HelloClass::Large, false));
        assert_eq!(store.lookup_detailed("googlevideo.com", HelloClass::Large, 24), None);

        assert_eq!(store.verification_stats().total, MAX_CONSECUTIVE_FAILURES as u64);
        assert_eq!(store.verification_stats().invalidations, 1);
    }

    #[test]
    fn live_outcome_skips_a_no_bypass_parent_like_lookup_does() {
        // b.a.example.com получает tls_record от example.com: `none` у
        // a.example.com по наследству не передаётся. Значит и провалы должны
        // лечь на example.com, а не сбросить чужую запись `none`.
        let store = StrategyStore::new();
        store.set("example.com", HelloClass::Large, Strategy::TlsRecord, 0.44);
        store.set("a.example.com", HelloClass::Large, Strategy::None, 1.0);

        for _ in 0..MAX_CONSECUTIVE_FAILURES {
            store.record_outcome("b.a.example.com", HelloClass::Large, false);
        }
        assert_eq!(
            store.lookup_detailed("a.example.com", HelloClass::Large, 24),
            Some((Strategy::None, MatchKind::Exact)),
            "запись none не должна страдать от чужих провалов"
        );
        assert_eq!(store.lookup_detailed("example.com", HelloClass::Large, 24), None, "сброшена должна быть нерабочая техника");
    }

    #[test]
    fn success_on_a_subdomain_clears_the_parent_failure_streak() {
        let store = StrategyStore::new();
        store.set("googlevideo.com", HelloClass::Large, Strategy::TlsRecord, 0.44);

        assert!(!store.record_outcome("a.googlevideo.com", HelloClass::Large, false));
        assert!(!store.record_outcome("b.googlevideo.com", HelloClass::Large, true));
        // Серия прервана, поэтому следующие две неудачи ещё не сбрасывают запись
        assert!(!store.record_outcome("c.googlevideo.com", HelloClass::Large, false));
        assert!(!store.record_outcome("d.googlevideo.com", HelloClass::Large, false));
        assert!(store.lookup_detailed("googlevideo.com", HelloClass::Large, 24).is_some());
    }

    #[test]
    fn outcome_for_an_unknown_domain_is_ignored() {
        let store = StrategyStore::new();
        assert!(!store.record_outcome("example.com", HelloClass::Large, false));
        assert_eq!(store.verification_stats().total, 0);
    }

    #[test]
    fn live_counters_survive_a_repeat_measurement() {
        // Массовый прогон переизмеряет домен и вызывает set(). Раньше это
        // обнуляло live_ok/live_fail — то есть ровно в тот момент, когда
        // накопленное единственный раз и попадало на диск.
        let store = StrategyStore::new();
        store.set("example.com", HelloClass::Large, Strategy::TlsRecord, 0.44);
        for _ in 0..4 {
            store.record_outcome("example.com", HelloClass::Large, true);
        }
        store.record_outcome("example.com", HelloClass::Large, false);

        // Та же техника — статистика продолжает накапливаться
        store.set("example.com", HelloClass::Large, Strategy::TlsRecord, 0.60);
        let rows = store.live_disagreements(5);
        assert_eq!(rows.len(), 1, "накопленные исходы не должны теряться: {rows:?}");
        assert!((rows[0].3 - 0.2).abs() < 1e-9, "доля неудач 1 из 5: {}", rows[0].3);

        // Другая техника — прежние наблюдения к ней не относятся
        store.set("example.com", HelloClass::Large, Strategy::Oob, 0.44);
        assert!(store.live_disagreements(1).is_empty());
    }

    #[test]
    fn store_format_is_checked_not_only_written() {
        assert_eq!(parse_store_format("# format=3 columns=a,b\nx\ty\t1\n"), Some(3));
        assert_eq!(parse_store_format("x\ty\t1\n"), None);
        // Заголовок ищется только среди ведущих комментариев
        assert_eq!(parse_store_format("x\ty\t1\n# format=9\n"), None);
    }

    #[test]
    fn hello_class_boundary() {
        assert_eq!(HelloClass::of(273), HelloClass::Small);
        assert_eq!(HelloClass::of(SMALL_HELLO_MAX - 1), HelloClass::Small);
        assert_eq!(HelloClass::of(SMALL_HELLO_MAX), HelloClass::Large);
        assert_eq!(HelloClass::of(1584), HelloClass::Large);
    }

    #[test]
    fn small_and_large_hello_keep_separate_strategies() {
        let store = StrategyStore::new();
        store.set("updates.discord.com", HelloClass::Large, Strategy::TlsRecord, 0.44);
        store.set("updates.discord.com", HelloClass::Small, Strategy::Oob, 0.44);

        assert_eq!(store.lookup_detailed("updates.discord.com", HelloClass::Large, 24).map(|(s, _)| s), Some(Strategy::TlsRecord));
        assert_eq!(store.lookup_detailed("updates.discord.com", HelloClass::Small, 24).map(|(s, _)| s), Some(Strategy::Oob));

        // Провалы маленького пакета сбрасывают только его запись
        for _ in 0..MAX_CONSECUTIVE_FAILURES {
            store.record_outcome("updates.discord.com", HelloClass::Small, false);
        }
        assert_eq!(store.lookup_detailed("updates.discord.com", HelloClass::Small, 24), None);
        assert_eq!(store.lookup_detailed("updates.discord.com", HelloClass::Large, 24).map(|(s, _)| s), Some(Strategy::TlsRecord));
    }

    #[test]
    fn old_format_is_read_as_large_hello() {
        let v = crate::engine::diagnostics::DIAGNOSTIC_VERSION;
        let old = format!("# format=3 columns=domain,strategy,decided_at,confidence,version,live_ok,live_fail\nexample.com\ttls_record\t1\t0.44\t{v}\t0\t0\n");
        let map = parse_entries(&old);
        assert!(map.contains_key(&("example.com".to_string(), HelloClass::Large)));

        let new = format!("# format=4 columns=domain,strategy,decided_at,confidence,version,live_ok,live_fail,hello\nexample.com\toob\t1\t0.44\t{v}\t0\t0\tsmall\n");
        let map = parse_entries(&new);
        assert_eq!(map.get(&("example.com".to_string(), HelloClass::Small)).map(|e| e.strategy), Some(Strategy::Oob));
        assert!(!map.contains_key(&("example.com".to_string(), HelloClass::Large)));
    }

    #[test]
    fn auto_diagnosis_is_not_repeated_within_cooldown() {
        let store = StrategyStore::new();
        let cooldown = std::time::Duration::from_secs(600);
        assert!(store.claim_auto_diagnosis("example.com", HelloClass::Small, cooldown));
        assert!(!store.claim_auto_diagnosis("example.com", HelloClass::Small, cooldown));
        // Другой размер — отдельная очередь
        assert!(store.claim_auto_diagnosis("example.com", HelloClass::Large, cooldown));
        // Пауза истекла
        assert!(store.claim_auto_diagnosis("example.com", HelloClass::Small, std::time::Duration::ZERO));
    }

    /// Строка store с заданными доменом, стратегией и возрастом.
    fn store_line(domain: &str, strategy: Strategy, age_secs: u64, version: u32) -> String {
        format!(
            "{}\t{}\t{}\t0.44\t{}\t0\t0\tlarge\n",
            domain,
            strategy.as_str(),
            now_secs() - age_secs,
            version,
        )
    }

    fn store_from(lines: &str) -> StrategyStore {
        let text = format!(
            "# format=5 columns=domain,strategy,decided_at,confidence,version,live_ok,live_fail,hello\n{lines}"
        );
        let store = StrategyStore::new();
        *store.inner.write().unwrap() = parse_entries(&text);
        store
    }

    /// Протухший предок не должен обрывать подъём по дереву: выше может
    /// лежать свежая запись, и раньше она не находилась.
    #[test]
    fn a_stale_parent_does_not_hide_a_fresh_grandparent() {
        let v = crate::engine::diagnostics::DIAGNOSTIC_VERSION;
        let store = store_from(&format!(
            "{}{}",
            store_line("b.example.com", Strategy::SniSplit, 10 * 3600, v),
            store_line("example.com", Strategy::TlsRecord, 0, v),
        ));

        assert_eq!(
            store.lookup_detailed("a.b.example.com", HelloClass::Large, 1),
            Some((Strategy::TlsRecord, MatchKind::Inherited)),
        );
    }

    /// Записи чужой версии методики не доживают до памяти, иначе они навсегда
    /// оставались бы в файле: пользоваться ими нельзя, а `save` их сохраняет.
    #[test]
    fn entries_from_another_methodology_version_are_dropped_on_load() {
        let v = crate::engine::diagnostics::DIAGNOSTIC_VERSION;
        let store = store_from(&format!(
            "{}{}",
            store_line("old.example.com", Strategy::SniSplit, 0, v.wrapping_add(1)),
            store_line("fresh.example.com", Strategy::TlsRecord, 0, v),
        ));

        assert_eq!(store.len(), 1);
        assert_eq!(
            store.lookup_detailed("fresh.example.com", HelloClass::Large, 24).map(|(s, _)| s),
            Some(Strategy::TlsRecord),
        );
        assert_eq!(store.lookup_detailed("old.example.com", HelloClass::Large, 24), None);
    }

    /// Вывод «ничего не помогло» должен возвращаться из хранилища как
    /// решение. Иначе вызывающий код берёт стратегию по умолчанию и
    /// применяет технику, которая только что провалила все пробы.
    #[test]
    fn resignation_is_remembered_as_a_decision() {
        let store = StrategyStore::new();
        store.set_resigned("stable.dl2.discordapp.net", HelloClass::Large);

        assert_eq!(
            store.lookup_detailed("stable.dl2.discordapp.net", HelloClass::Large, 24),
            Some((Strategy::None, MatchKind::Exact)),
        );
    }

    /// Признание поражения живёт меньше измеренного вердикта: DPI могли
    /// перенастроить, и проверить это стоит скоро.
    #[test]
    fn resignation_expires_sooner_than_a_measured_verdict() {
        let v = crate::engine::diagnostics::DIAGNOSTIC_VERSION;
        let two_hours_ago = now_secs() - 2 * 3600;
        let store = store_from(&format!(
            "resigned.example.com\tresigned\t{two_hours_ago}\t0.00\t{v}\t0\t0\tlarge\n\
             measured.example.com\ttls_record\t{two_hours_ago}\t0.44\t{v}\t0\t0\tlarge\n",
        ));

        // Настроенный TTL — сутки: измеренная запись двухчасовой давности жива.
        assert_eq!(
            store.lookup_detailed("measured.example.com", HelloClass::Large, 24).map(|(s, _)| s),
            Some(Strategy::TlsRecord),
        );
        // А признание поражения уже протухло: ему отведён час.
        assert_eq!(store.lookup_detailed("resigned.example.com", HelloClass::Large, 24), None);
    }

    /// «Прямое соединение работает» и «ничего не помогло» — разные выводы с
    /// одной стратегией. Различает их уверенность, и путать их нельзя:
    /// у первого полный TTL, у второго час.
    #[test]
    fn direct_success_is_not_mistaken_for_resignation() {
        let v = crate::engine::diagnostics::DIAGNOSTIC_VERSION;
        let two_hours_ago = now_secs() - 2 * 3600;
        let store = store_from(&format!(
            "direct.example.com\tnone\t{two_hours_ago}\t1.00\t{v}\t0\t0\tlarge\n",
        ));

        assert_eq!(
            store.lookup_detailed("direct.example.com", HelloClass::Large, 24).map(|(s, _)| s),
            Some(Strategy::None),
            "запись «прямое соединение работает» не должна протухать за час",
        );
    }

    /// В файлах четвёртого формата отказ писался как `none` с нулевой
    /// уверенностью. При чтении он должен стать отказом (час жизни), а не
    /// «прямое соединение работает» (сутки без обхода).
    #[test]
    fn format_4_zero_confidence_none_is_read_as_resignation() {
        let v = crate::engine::diagnostics::DIAGNOSTIC_VERSION;
        let two_hours_ago = now_secs() - 2 * 3600;
        let text = format!(
            "# format=4 columns=domain,strategy,decided_at,confidence,version,live_ok,live_fail,hello\n\
             resigned.example.com\tnone\t{two_hours_ago}\t0.00\t{v}\t0\t0\tlarge\n\
             direct.example.com\tnone\t{two_hours_ago}\t1.00\t{v}\t0\t0\tlarge\n",
        );
        let store = StrategyStore::new();
        *store.inner.write().unwrap() = parse_entries(&text);

        assert_eq!(store.lookup_detailed("resigned.example.com", HelloClass::Large, 24), None, "отказ живёт час");
        assert_eq!(
            store.lookup_detailed("direct.example.com", HelloClass::Large, 24).map(|(s, _)| s),
            Some(Strategy::None),
        );
    }

    /// В пятом формате отказ опознаётся только по слову `resigned`: нулевая
    /// уверенность у `none` больше ничего не означает.
    #[test]
    fn resignation_is_explicit_in_the_current_format() {
        let v = crate::engine::diagnostics::DIAGNOSTIC_VERSION;
        let now = now_secs();
        let store = store_from(&format!(
            "a.example.com\tresigned\t{now}\t0.00\t{v}\t0\t0\tlarge\n\
             b.example.com\tnone\t{now}\t0.00\t{v}\t0\t0\tlarge\n",
        ));
        assert!(store.is_resigned("a.example.com", HelloClass::Large, 24));
        assert!(!store.is_resigned("b.example.com", HelloClass::Large, 24));
    }

    /// Сервер не открыл даже TCP — это сеть или блокировка по IP, а не вывод
    /// о техниках. Отказ не записывается, старая запись убирается.
    #[test]
    fn unreachable_server_is_not_recorded_as_resignation() {
        let store = StrategyStore::new();
        store.set("down.example.com", HelloClass::Large, Strategy::Oob, 0.44);

        let unreachable = result(ProbeOutcome::ConnectFailed, false);
        assert!(!store.record_nothing_worked("down.example.com", HelloClass::Large, &unreachable));
        assert_eq!(store.lookup_detailed("down.example.com", HelloClass::Large, 24), None);
        assert!(!store.is_resigned("down.example.com", HelloClass::Large, 24));

        let blocked = result(ProbeOutcome::SilentDrop, false);
        assert!(store.record_nothing_worked("down.example.com", HelloClass::Large, &blocked));
        assert!(store.is_resigned("down.example.com", HelloClass::Large, 24));
    }

    /// Вердикт «прямое соединение работает» проверяется в бою, как и
    /// техники: три соединения подряд без ответа — и запись сброшена.
    #[test]
    fn direct_verdict_is_invalidated_by_live_failures() {
        let store = StrategyStore::new();
        store.set("flaky.example.com", HelloClass::Large, Strategy::None, 1.0);

        assert!(!store.record_outcome("flaky.example.com", HelloClass::Large, false));
        assert!(!store.record_outcome("flaky.example.com", HelloClass::Large, false));
        assert!(store.record_outcome("flaky.example.com", HelloClass::Large, false));
        assert_eq!(store.lookup_detailed("flaky.example.com", HelloClass::Large, 24), None);
        assert_eq!(store.verification_stats().invalidations, 1);
    }

    /// Отказ в бою не проверяется: что напрямую не проходит, он и так
    /// утверждает. Иначе он сбрасывался бы через три соединения, а не через час.
    #[test]
    fn resignation_is_not_invalidated_by_live_failures() {
        let store = StrategyStore::new();
        store.set_resigned("hopeless.example.com", HelloClass::Large);

        for _ in 0..10 {
            assert!(!store.record_outcome("hopeless.example.com", HelloClass::Large, false));
        }
        assert!(store.is_resigned("hopeless.example.com", HelloClass::Large, 24));
        assert_eq!(store.verification_stats().total, 0);
    }

    #[test]
    fn expired_entry_is_not_returned() {
        let store = StrategyStore::new();
        store.set("example.com", HelloClass::Large, Strategy::TlsRecord, 0.44);
        assert_eq!(store.lookup_detailed("example.com", HelloClass::Large, 24).map(|(s, _)| s), Some(Strategy::TlsRecord));
        // ttl = 0 часов: любая запись считается протухшей
        assert_eq!(store.lookup_detailed("example.com", HelloClass::Large, 0).map(|(s, _)| s), None);
    }
}

/// Применение выбранной стратегии к первому пакету (ClientHello).
///
/// Вынесено сюда, чтобы HTTPS-туннель и SOCKS5 CONNECT применяли одну и ту же
/// логику. Раньше SOCKS5 жёстко слал 2-байтовые чанки мимо всего хранилища:
/// для x.com это давало 788 фрагментов, почти секунду задержки — и провал,
/// хотя через HTTP-прокси тот же домен открывался с tls_record.
pub mod apply {
    use crate::bypass::fragment;
    use crate::config::BypassParams;

    use super::Strategy;

    /// Что именно было применено — для лога вызывающей стороны.
    pub enum Applied {
        None,
        TlsRecord { bytes: usize },
        SniSplit { first: usize, second: usize },
        Disorder { first: usize, second: usize },
        Oob { first: usize, second: usize },
        Fake { decoy: usize, real: usize },
        Split { first: usize, second: usize },
    }

    /// Отправляет первый пакет по выбранной стратегии.
    /// `Ok(None)` — запись не удалась, соединение надо закрывать.
    pub async fn first_packet<W>(
        writer: &mut W,
        fd: std::os::fd::RawFd,
        data: &[u8],
        strategy: Strategy,
        bypass: &BypassParams,
    ) -> std::io::Result<Applied>
    where
        W: tokio::io::AsyncWriteExt + Unpin,
    {
        match strategy {
            Strategy::None => {
                writer.write_all(data).await?;
                writer.flush().await?;
                Ok(Applied::None)
            }
            Strategy::TlsRecord => {
                match fragment::tls_record_split(writer, data, bypass.split_delay_ms).await? {
                    Some(bytes) => Ok(Applied::TlsRecord { bytes }),
                    // SNI нет (подключение по IP, ECH) — откат на обычный сплит
                    None => {
                        let info = fragment::split_client_hello(writer, data, bypass).await?;
                        Ok(Applied::Split { first: info.first, second: info.second })
                    }
                }
            }
            Strategy::Disorder => {
                match fragment::split_with_disorder(writer, fd, data, bypass.disorder_ttl).await? {
                    Some(info) => Ok(Applied::Disorder { first: info.first, second: info.second }),
                    None => {
                        let info = fragment::split_client_hello(writer, data, bypass).await?;
                        Ok(Applied::Split { first: info.first, second: info.second })
                    }
                }
            }
            Strategy::Oob => {
                match fragment::split_with_oob(writer, fd, data).await? {
                    Some(info) => Ok(Applied::Oob { first: info.first, second: info.second }),
                    None => {
                        let info = fragment::split_client_hello(writer, data, bypass).await?;
                        Ok(Applied::Split { first: info.first, second: info.second })
                    }
                }
            }
            Strategy::SniSplit => {
                match fragment::split_at_sni(writer, data, bypass.split_delay_ms).await? {
                    Some(info) => Ok(Applied::SniSplit { first: info.first, second: info.second }),
                    None => {
                        let info = fragment::split_client_hello(writer, data, bypass).await?;
                        Ok(Applied::Split { first: info.first, second: info.second })
                    }
                }
            }
            Strategy::Fake => {
                match fragment::split_with_fake(writer, fd, data, bypass.fake_ttl, &bypass.fake_sni).await? {
                    Some(info) => Ok(Applied::Fake { decoy: info.decoy, real: info.real }),
                    // Нет CAP_NET_ADMIN — откат на обычный сплит, как у прочих.
                    None => {
                        let info = fragment::split_client_hello(writer, data, bypass).await?;
                        Ok(Applied::Split { first: info.first, second: info.second })
                    }
                }
            }
        }
    }
}
