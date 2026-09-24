use std::time::{Duration, Instant};
use tokio::net::{TcpStream, UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::BypassParams;
use crate::bypass::fragment;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// TCP-соединение не установилось. Причина не установлена: блокировка
    /// по IP, маршрут, firewall, отсутствие сервиса на порту, временный сбой —
    /// проба их не различает.
    ConnectFailed,
    ResetOnWrite,
    SilentDrop,
    ResetAfterHello,
    /// Соединение закрыто штатно (FIN) после ClientHello, без единого байта
    /// ответа: разговор оборвал сервер или DPI от его имени.
    ///
    /// Раньше FIN записывался в «молча дропаются», если пришёл позже 500 мс,
    /// и в «сброшено», если раньше. Ни то ни другое не правда: пакеты не
    /// пропадали, и RST не было, — а по отчёту читалась другая блокировка.
    ClosedAfterHello,
    Success,
    /// В ответ пришли байты, но не TLS: заглушка, редирект или мусор,
    /// подставленный по пути. Сервер пробу не получил.
    ///
    /// Раньше успехом считался любой байт ответа, и DPI, отвечающий вместо
    /// сервера, выглядел как «прямое соединение работает» — обход домену
    /// выключался на сутки.
    Injected,
    /// Ответ на QUIC Version Negotiation получен: UDP/443 доходит до сервера.
    ///
    /// Отдельно от `Success`, потому что это принципиально более слабое
    /// утверждение. Раньше QUIC-проба возвращала Success и подписывалась
    /// «TLS-рукопожатие прошло успешно» — неправда: никакого рукопожатия
    /// не происходит, VN-ответ приходит незашифрованным и доказывает лишь
    /// достижимость. Работает ли через QUIC само приложение — вопрос,
    /// на который эта проба не отвечает.
    UdpReachable,
    NotApplicable,
}

impl ProbeOutcome {
    pub fn description_key(&self) -> &'static str {
        match self {
            ProbeOutcome::ConnectFailed => "verdict.connect_failed",
            ProbeOutcome::UdpReachable => "verdict.udp_reachable",
            ProbeOutcome::ResetOnWrite => "verdict.reset_on_write",
            ProbeOutcome::SilentDrop => "verdict.silent_drop",
            ProbeOutcome::ResetAfterHello => "verdict.reset_after_hello",
            ProbeOutcome::ClosedAfterHello => "verdict.closed_after_hello",
            ProbeOutcome::Success => "verdict.success",
            ProbeOutcome::Injected => "verdict.injected",
            ProbeOutcome::NotApplicable => "verdict.not_applicable",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum FragStrategy {
    None,
    /// Сплит на КОНКРЕТНОЙ позиции. Раньше стратегия брала позицию из конфига,
    /// где она выбирается случайно — из-за этого две подряд диагностики одного
    /// домена давали противоположные вердикты: тестировалась не стратегия,
    /// а везение с позицией.
    /// Разрыв точно посередине имени домена в SNI. Позиция вычисляется из
    /// самого ClientHello, поэтому работает независимо от его длины —
    /// в отличие от свипа по абсолютным числам, который может ни разу
    /// не попасть внутрь имени.
    SniSplit,
    /// Первая половина с низким TTL; порядок восстанавливается ретрансмитом.
    Disorder,
    /// OOB-байт между половинами.
    Oob,
    /// Поддельный ClientHello с чужим именем перед настоящим.
    Fake,
    /// Перестроение ClientHello в две TLS-записи. Единственная техника здесь,
    /// которая работает против DPI, пересобирающего TCP-поток.
    TlsRecord,
}

/// Сколько раз проверять каждую позицию. Сеть шумит (потери, таймауты,
/// неодинаковая реакция DPI), одна проба ничего не доказывает.
pub const TRIALS_PER_POSITION: u32 = 3;

/// Пауза между пробами одной техники.
///
/// Наблюдение из прогонов: успехи случаются в быстром проходе (2-3 пробы),
/// а тщательный (5 проб подряд) не спас ни одного домена ни разу — те же
/// домены давали ровно 0/5. Пробы шли вплотную, по шесть доменов
/// параллельно.
///
/// Правдоподобное объяснение: DPI ужесточает реакцию на серию однотипных
/// подключений, и чем настойчивее зондирование, тем хуже вердикт. Тогда
/// измеряется не блокировка, а реакция на само зондирование.
///
/// Поэтому пробы разрежены. Значение случайное, чтобы серия не выглядела
/// машинной — ровный интервал сам по себе примета.
/// Разрежение серии проб.
///
/// Значения приходят из конфига (`probe_gap_*`), чтобы гипотезу о влиянии
/// плотности зондирования можно было проверить экспериментом: менять паузу
/// между прогонами и сравнивать результат, а не спорить о ней.
#[derive(Debug, Clone, Copy)]
pub struct ProbeTiming {
    pub gap_min_ms: u64,
    pub gap_max_ms: u64,
    /// Размер пробного ClientHello, байт. См. `build_client_hello_sized`.
    pub hello_size: usize,
}

impl Default for ProbeTiming {
    fn default() -> Self {
        Self { gap_min_ms: 250, gap_max_ms: 700, hello_size: browser_hello_size() }
    }
}

/// Размер последнего большого ClientHello, прошедшего через прокси в бою.
/// 0 — такого ещё не было.
static OBSERVED_BROWSER_HELLO: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Больше одной TLS-записи ClientHello не бывает: RFC 8446 ограничивает
/// запись 16384 байтами нагрузки. Длина приходит от клиента, и проба
/// такого размера была бы отвергнута сервером как record_overflow.
const MAX_PROBE_HELLO: usize = 5 + 16384;

/// Запоминает размер ClientHello, увиденного в бою.
///
/// Ручная и массовая диагностика мерят пакетом того размера, что реально
/// шлёт браузер: размер сам по себе меняет вердикт, а с появлением
/// постквантового key share браузерный ClientHello вырос с ~1500 до ~1900
/// байт, и любая зашитая константа рано или поздно устареет так же.
/// Маленькие пакеты (программы, rustls) не учитываются: их мерит
/// автодиагностика своим размером, по классам.
pub fn note_battle_hello(len: usize) {
    if is_browser_sized(len) {
        OBSERVED_BROWSER_HELLO.store(len, std::sync::atomic::Ordering::Relaxed);
    }
}

fn is_browser_sized(len: usize) -> bool {
    use crate::engine::strategy::HelloClass;
    HelloClass::of(len) == HelloClass::Large && len <= MAX_PROBE_HELLO
}

/// Размер ClientHello для ручной и массовой диагностики: последний
/// увиденный в бою, а пока его нет — `BROWSER_HELLO_SIZE`.
pub fn browser_hello_size() -> usize {
    match OBSERVED_BROWSER_HELLO.load(std::sync::atomic::Ordering::Relaxed) {
        0 => crate::bypass::tls::BROWSER_HELLO_SIZE,
        seen => seen,
    }
}

/// Сколько проб делать во втором, тщательном проходе.
///
/// Часть техник работает вероятностно: наблюдалось `OOB-байт — успехов 1/3`,
/// то есть примерно каждое третье соединение проходит. При обычном правиле
/// «две неудачи подряд — бросаем» такая техника даёт `0/2` заметно чаще,
/// чем ей следовало бы, и домен объявляется мёртвым по невезению — отсюда
/// расхождения между прогонами для x.com и twitter.com.
///
/// Пять проб при вероятности успеха 0.5 дают два и более успеха примерно
/// в 80% случаев против 50% при трёх пробах. Но само по себе увеличение
/// числа проб результата не дало — оно работает только вместе с паузами
/// между ними (см. PROBE_GAP_*).
pub const TRIALS_THOROUGH: u32 = 5;

/// Во сколько раз ждать ответа дольше, чем длилось установление соединения.
///
/// Время connect — это измеренный RTT до сервера, и оно доступно даже на
/// заблокированном домене: DPI обычно режет не на SYN, а позже, на ClientHello.
/// Ответ сервера — это ещё один оборот плюс небольшая обработка, так что
/// десятикратный запас перекрывает и джиттер, и медленный сервер.
///
/// Тот же принцип, по которому TCP выводит RTO из наблюдаемого RTT,
/// а не берёт константу.
const RESPONSE_TIMEOUT_FACTOR: u32 = 10;

/// Нижняя граница ожидания: на быстрой сети RTT бывает 2-3 мс, и без пола
/// таймаут вышел бы меньше времени обработки на сервере.
const RESPONSE_TIMEOUT_MIN: Duration = Duration::from_millis(800);

/// Верхняя граница — прежнее фиксированное значение.
const RESPONSE_TIMEOUT_MAX: Duration = Duration::from_secs(3);

/// Версия методики диагностики.
///
/// Увеличивается при изменениях, после которых прошлые измерения нельзя
/// сравнивать с новыми: другой ClientHello, другой набор техник, другие
/// пороги. Записи в strategies.txt с другой версией считаются протухшими
/// и домен переизмеряется. За время работы профиль ClientHello менялся
/// дважды, и оба раза старые вердикты становились недействительными —
/// без версии это приходилось замечать вручную.
///
/// 3: успехом пробы считается только ответ, похожий на TLS (см.
/// `classify_reply`), а не любой байт. Прежние вердикты «прямое соединение
/// работает» могли быть сняты по заглушке провайдера.
///
/// 4: исправлена длина списка в key_share пробного ClientHello. Строгие
/// серверы отвечали на пробу decode_error, а на разрезанную молчали, и
/// рабочие техники проваливались — отсюда ложные `resigned`.
///
/// 5: каждая проба шлёт свежий ClientHello. DPI помнит пакет, увиденный
/// прямой пробой, и резал его повторы в любой нарезке — вердикты версии 4
/// тоже ложные `resigned`.
pub const DIAGNOSTIC_VERSION: u32 = 5;

/// Минимальная нижняя граница Уилсона, при которой техника считается рабочей.
///
/// 0.15 отсекает единичные удачи, но принимает воспроизводимый результат:
///
/// | наблюдения | Уилсон | вердикт      |
/// |------------|--------|--------------|
/// | 3/3        | 0.44   | принимается  |
/// | 2/2        | 0.34   | принимается  |
/// | 2/3        | 0.21   | принимается  |
/// | 1/2        | 0.09   | отвергается  |
/// | 1/3        | 0.06   | отвергается  |
///
/// Раньше решение принималось по `successes > 0`: одна удачная проба из трёх
/// закрепляла стратегию на сутки, хотя сам же интервал Уилсона говорил, что
/// доказательств мало. Статистика считалась и игнорировалась.
pub const MIN_CONFIDENCE: f64 = 0.15;

/// Итог по одной позиции сплита: сколько проб прошло и насколько мы уверены.
#[derive(Debug, Clone, Copy)]
pub struct SplitScore {
    pub successes: u32,
    pub attempts: u32,
    /// Нижняя граница интервала Уилсона: «в какой доле успехов мы уверены».
    /// Ранжируем по ней, а не по successes/attempts, иначе 3/3 по счастливой
    /// случайности обгонит устойчивые 8/10.
    pub confidence: f64,
    /// Медианное время успешной пробы, мс. `None`, если успехов не было.
    ///
    /// Пока не участвует в выборе: перебор останавливается на первой
    /// подходящей технике, так что сравнивать не с чем. Но «сработало» и
    /// «сработало быстро» — разные вещи, и disorder тому пример: он проходит
    /// через ретрансмит и стоит сотни миллисекунд. Число показывается в
    /// отчёте, чтобы эта разница была видна до того, как на неё опираться.
    pub median_ms: Option<f64>,
}

impl SplitScore {
    /// Достаточно ли доказательств, чтобы полагаться на технику.
    /// Единая точка: используется и при раннем выходе из перебора,
    /// и при выборе стратегии — иначе перебор мог остановиться на слабом
    /// результате, так и не попробовав следующую ступень.
    pub fn is_convincing(&self) -> bool {
        self.confidence >= MIN_CONFIDENCE
    }
}

/// Сводного поля вроде «сработал ли обход» здесь тоже нет: раньше было
/// `https_split`, означавшее «прошла хоть одна из трёх техник». Читать его
/// было бесполезно — по нему нельзя понять, какая именно сработала, — а в
/// логе подпись «HTTPS split» прямо вводила в заблуждение. Решение теперь
/// принимается по конкретным полям: tls_record, sni_split, oob, disorder.
///
/// Домена здесь нет намеренно: вызывающий код всегда знает, какой домен он
/// диагностировал, и хранить его копию в результате было бы дублированием.
#[derive(Debug, Clone)]
pub struct DiagnosticResult {
    pub direct: ProbeOutcome,
    pub quic: ProbeOutcome,
    /// Перестроение в две TLS-записи — единственная техника, работающая
    /// против DPI, который пересобирает TCP.
    pub tls_record: SplitScore,
    /// Сплит точно по SNI — считается отдельно от свипа, потому что это
    /// не «ещё одна позиция», а другой способ её выбирать.
    pub sni_split: SplitScore,
    /// Перестановка половин через низкий TTL и ретрансмит.
    pub disorder: SplitScore,
    /// Вставка OOB-байта между половинами.
    pub oob: SplitScore,
    /// Поддельный ClientHello-приманка перед настоящим.
    ///
    /// Меряется последней и только при наличии CAP_NET_ADMIN: без него
    /// TCP_REPAIR недоступен, техника молча выродилась бы в обычный сплит
    /// и дала бы бессмысленный результат.
    pub fake: SplitScore,
}

fn classify_write_error(_e: &std::io::Error) -> ProbeOutcome { ProbeOutcome::ResetOnWrite }

/// Чем был ответ на пробу: сервер ответил по TLS или ответил кто-то другой.
///
/// Засчитывается и alert, не только ServerHello: на синтетический ClientHello
/// сервер вправе ответить отказом (не тот набор шифров, неизвестное имя), и
/// это всё равно доказывает, что проба до него дошла — а только это
/// диагностика и выясняет.
fn classify_reply(reply: &[u8]) -> ProbeOutcome {
    if crate::bypass::tls::looks_like_tls_reply(reply) {
        ProbeOutcome::Success
    } else {
        ProbeOutcome::Injected
    }
}

fn classify_read_error(e: &std::io::Error) -> ProbeOutcome {
    use std::io::ErrorKind::*;
    match e.kind() {
        ConnectionReset | ConnectionAborted => ProbeOutcome::ResetAfterHello,
        _ => ProbeOutcome::SilentDrop,
    }
}

/// Проба с замером длительности: «сработало» и «сработало быстро» —
/// разные вещи, и disorder тому пример (он проходит через ретрансмит).
async fn probe_tcp(
    target: &str,
    hello: &[u8],
    strategy: FragStrategy,
    bypass_params: &BypassParams,
) -> (ProbeOutcome, f64) {
    let started = Instant::now();
    let outcome = probe_tcp_inner(target, hello, strategy, bypass_params).await;
    (outcome, started.elapsed().as_secs_f64() * 1000.0)
}

async fn probe_tcp_inner(target: &str, hello: &[u8], strategy: FragStrategy, bypass_params: &BypassParams) -> ProbeOutcome {
    // Резолв ДО замера: через тот же резолвер, что и прокси, чтобы вердикт
    // относился к тому же адресу. Но время DoH-запроса не должно попадать
    // ни в connect_rtt, ни в таймаут подключения — иначе живой домен
    // получает «TCP не открылся» просто потому, что резолв был медленным.
    let resolved = crate::dns::resolver::resolve_first(target).await;

    let connect_started = Instant::now();
    let connect_result = match resolved {
        Some(addr) => tokio::time::timeout(RESPONSE_TIMEOUT_MAX, TcpStream::connect(addr)).await,
        None => tokio::time::timeout(RESPONSE_TIMEOUT_MAX, TcpStream::connect(target)).await,
    };
    let stream = match connect_result {
        Ok(Ok(s)) => s,
        _ => return ProbeOutcome::ConnectFailed,
    };
    let connect_rtt = connect_started.elapsed();

    // Как в бою: боевые пути выключают Nagle на соединении с сервером, и
    // проба обязана делать то же. Иначе вторая часть разрезанного ClientHello
    // ждала ACK на первую: disorder вырождался в обычный сплит (первая
    // половина с низким TTL не доходит, ACK нет, вторая стоит до ретрансмита),
    // а остальные техники уходили с паузой в RTT между частями. Причём только
    // при пробе короче ~1500 байт — вторая часть длиннее MSS уходит и так.
    // Проба мерила не то, что прокси потом применяет.
    let _ = stream.set_nodelay(true);

    // Ждём ответа пропорционально измеренному RTT, а не фиксированные 3 с.
    // На заблокированных доменах именно это ожидание и съедало всё время:
    // проба «молчание» всегда стоила полный таймаут.
    let response_timeout = (connect_rtt * RESPONSE_TIMEOUT_FACTOR)
        .clamp(RESPONSE_TIMEOUT_MIN, RESPONSE_TIMEOUT_MAX);

    // Clamp применяется ко ВСЕМ пробам одинаково или ни к одной. Раньше он
    // стоял только на сплит-пробах, и это делало сравнение нечестным: провал
    // сплита нельзя было отличить от влияния маленького окна.
    //
    // Само окно приёма, кстати, влияет не на исходящий ClientHello (где лежит
    // SNI), а на то, как сервер шлёт ОТВЕТ — техника против DPI, читающего
    // сертификат. 0 = выключено.
    if bypass_params.window_clamp > 0 {
        let _ = fragment::apply_window_clamp(&stream, bypass_params.window_clamp);
    }

    // Дескриптор берём до разделения: техники disorder и oob работают
    // с сокетом напрямую (setsockopt/MSG_OOB), а половины его не отдают.
    let fd = {
        use std::os::fd::AsRawFd;
        stream.as_raw_fd()
    };

    let (mut reader, mut writer) = stream.into_split();

    // Каждая стратегия возвращает своё (SplitInfo / число чанков / ()) — здесь важен
    // только факт успеха записи, поэтому приводим всё к io::Result<()>.
    let write_result: std::io::Result<()> = match strategy {
        FragStrategy::None => writer.write_all(hello).await,
        FragStrategy::SniSplit => fragment::split_at_sni(&mut writer, hello, bypass_params.split_delay_ms).await.map(|_| ()),
        FragStrategy::TlsRecord => fragment::tls_record_split(&mut writer, hello, bypass_params.split_delay_ms).await.map(|_| ()),
        FragStrategy::Disorder => fragment::split_with_disorder(&mut writer, fd, hello, bypass_params.disorder_ttl).await.map(|_| ()),
        FragStrategy::Oob => fragment::split_with_oob(&mut writer, fd, hello).await.map(|_| ()),
        FragStrategy::Fake => fragment::split_with_fake(&mut writer, fd, hello, bypass_params.fake_ttl, &bypass_params.fake_sni).await.map(|_| ()),
    };

    if let Err(e) = write_result {
        return classify_write_error(&e);
    }

    let mut buf = [0u8; 64];
    match tokio::time::timeout(response_timeout, reader.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => classify_reply(&buf[..n]),
        Ok(Ok(_)) => ProbeOutcome::ClosedAfterHello,
        Ok(Err(e)) => classify_read_error(&e),
        Err(_) => ProbeOutcome::SilentDrop,
    }
}

/// QUIC-зонд через Version Negotiation.
///
/// Раньше сюда слался фейковый Initial со случайным мусором вместо CRYPTO-фрейма.
/// Проблема: нормальный сервер не может его расшифровать и молча дропает — то есть
/// `SilentDrop` был ОЖИДАЕМЫМ ответом здорового сервера, и колонка QUIC показывала
/// одно и то же для заблокированных и незаблокированных доменов. Бесполезно.
///
/// Здесь используется приём из RFC 9000 §6: если прислать long-header пакет с
/// неизвестной сервером версией, сервер обязан ответить Version Negotiation —
/// а этот ответ НЕ зашифрован, его не нужно расшифровывать. Версии вида
/// 0x?a?a?a?a зарезервированы стандартом (§15) именно для принудительного
/// вызова VN, так что ни один сервер их не поддерживает.
///
/// Ограничение: отсутствие ответа означает либо блокировку по UDP/443, либо что
/// сервер вообще не говорит по QUIC. Различить эти два случая без полноценного
/// QUIC-стека нельзя.
async fn probe_quic(domain: &str) -> ProbeOutcome {
    let target = format!("{}:443", domain);

    let sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        // Локальная проблема (не смогли открыть свой сокет) — это не вердикт
        // о домене, а невозможность провести тест вообще.
        Err(_) => return ProbeOutcome::NotApplicable,
    };

    if sock.connect(&target).await.is_err() {
        return ProbeOutcome::ConnectFailed;
    }

    if sock.send(&build_version_negotiation_trigger()).await.is_err() {
        return ProbeOutcome::ResetOnWrite;
    }

    let mut buf = [0u8; 1500];
    match tokio::time::timeout(RESPONSE_TIMEOUT_MAX, sock.recv(&mut buf)).await {
        Ok(Ok(n)) if n >= 5 => {
            // Version Negotiation: старший бит первого байта = 1 (long header),
            // поле версии полностью нулевое.
            let is_long_header = buf[0] & 0x80 != 0;
            let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
            // И VN-ответ, и любой другой означают одно: датаграмма дошла
            // и сервер ответил. Утверждать что-то о работоспособности QUIC
            // на уровне приложения проба не может.
            let _ = (is_long_header, version);
            ProbeOutcome::UdpReachable
        }
        Ok(Ok(_)) => ProbeOutcome::SilentDrop,
        Ok(Err(_)) => ProbeOutcome::ResetAfterHello,
        Err(_) => ProbeOutcome::SilentDrop,
    }
}

/// Long-header пакет с зарезервированной версией 0x1a2a3a4a, дополненный до
/// 1200 байт: сервер по RFC 9000 вправе игнорировать датаграммы меньше 1200
/// (защита от усиления), поэтому паддинг обязателен.
fn build_version_negotiation_trigger() -> Vec<u8> {
    let dcid = crate::bypass::random::bytes(8);
    let scid = crate::bypass::random::bytes(8);

    let mut out = Vec::with_capacity(1200);
    out.push(0xC0);
    // Версия вида 0x?a?a?a?a — гарантированно неподдерживаемая (RFC 9000 §15)
    out.extend_from_slice(&[0x1a, 0x2a, 0x3a, 0x4a]);
    out.push(dcid.len() as u8);
    out.extend_from_slice(&dcid);
    out.push(scid.len() as u8);
    out.extend_from_slice(&scid);
    out.resize(1200, 0);
    out
}

/// Прогон техник по лестнице с ранним выходом.
///
/// Раньше прогонялись ВСЕ техники всегда: direct + 3 пробы SNI + 7 позиций × 3
/// пробы + чанки + QUIC. При таймауте 3 с на пробу это давало до полуминуты
/// на домен и ~7 минут на список из 17. Теперь перебор останавливается на
/// первой сработавшей технике — ровно так же, как потом действует прокси,
/// поэтому лишние измерения ничего не решают.
///
/// Техника «чанки по 2 байта» убрана: она не выиграла ни на одном домене,
/// а на незаблокированных ломала соединение (google.com: direct проходил,
/// чанки давали reset). 1580 байт по 2 байта — это ~790 сегментов.
/// Обычный прогон: мало проб, досрочное прекращение — нужен для скорости
/// на списке из десятков доменов.
pub async fn diagnose(domain: &str, bypass_params: &BypassParams, timing: ProbeTiming) -> DiagnosticResult {
    diagnose_with(domain, bypass_params, TRIALS_PER_POSITION, true, timing).await
}

/// Тщательный прогон: больше проб, без досрочного прекращения серии
/// И БЕЗ раннего выхода из лестницы — измеряются все техники.
///
/// Второе важнее первого: пока перебор останавливался на первой подходящей
/// технике, сравнивать было нечего, и функция полезности не имела смысла.
/// Наблюдалось, что один домен в разных прогонах получал то `tls_record`,
/// то `oob` — значит работают обе, просто вместе их никто не мерил. Применяется
/// вторым проходом к доменам, где обычный не нашёл ничего — там цена времени
/// уже оправдана, а вероятностные техники получают шанс проявиться.
pub async fn diagnose_thorough(domain: &str, bypass_params: &BypassParams, timing: ProbeTiming) -> DiagnosticResult {
    diagnose_with(domain, bypass_params, TRIALS_THOROUGH, false, timing).await
}

async fn diagnose_with(
    domain: &str,
    bypass_params: &BypassParams,
    trials_count: u32,
    early_abandon: bool,
    timing: ProbeTiming,
) -> DiagnosticResult {
    let target = format!("{}:443", domain);

    // ClientHello собирается заново для КАЖДОЙ пробы, со своими random,
    // session_id и ключом. DPI запоминает ClientHello, который видел целиком
    // с запрещённым именем, и потом режет те же байты даже разрезанными.
    // Раньше один пакет уходил сначала прямой пробой, а затем им же
    // проверялись все техники — и все проваливались: ложный `resigned` там,
    // где браузер (он шлёт свежий ClientHello на каждое соединение) проходил.
    let fresh_hello = || crate::bypass::tls::build_client_hello_sized(domain, timing.hello_size);

    let empty = SplitScore {
            successes: 0, attempts: 0, confidence: 0.0, median_ms: None };

    // Серия проб одной техники с досрочным прекращением на двух неудачах подряд.
    async fn trials(
        target: &str,
        domain: &str,
        strategy: FragStrategy,
        bypass_params: &BypassParams,
        trials_count: u32,
        early_abandon: bool,
        timing: ProbeTiming,
    ) -> SplitScore {
        let mut successes = 0u32;
        let mut attempts = 0u32;
        let mut durations: Vec<f64> = Vec::new();

        for trial in 0..trials_count {
            // Разрежение серии: пауза перед всеми пробами, кроме первой.
            // В тщательном проходе она длиннее — там и цель другая, не скорость.
            if trial > 0 {
                let gap = if early_abandon {
                    crate::bypass::random::in_range(timing.gap_min_ms, timing.gap_max_ms)
                } else {
                    crate::bypass::random::in_range(timing.gap_min_ms * 3, timing.gap_max_ms * 3)
                };
                tokio::time::sleep(Duration::from_millis(gap)).await;
            }

            let hello = crate::bypass::tls::build_client_hello_sized(domain, timing.hello_size);
            let (outcome, ms) = probe_tcp(target, &hello, strategy, bypass_params).await;
            attempts += 1;
            if outcome == ProbeOutcome::Success {
                successes += 1;
                durations.push(ms);
            }
            if early_abandon && trial + 1 == 2 && successes == 0 {
                break;
            }
        }

        // Медиана, а не среднее: одна аномально долгая проба не должна
        // определять оценку техники.
        let median_ms = if durations.is_empty() {
            None
        } else {
            durations.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            Some(durations[durations.len() / 2])
        };

        SplitScore {
            successes,
            attempts,
            confidence: crate::observability::stats::wilson_lower_bound(successes, attempts),
            median_ms,
        }
    }

    let (direct, _direct_ms) = probe_tcp(&target, &fresh_hello(), FragStrategy::None, bypass_params).await;

    // Домен открывается напрямую — обход не нужен, остальное измерять незачем.
    if direct == ProbeOutcome::Success {
        return DiagnosticResult {
            direct,
            quic: ProbeOutcome::NotApplicable,
            tls_record: empty,
            sni_split: empty,
            disorder: empty,
            oob: empty,
            fake: empty,
        };
    }

    // Ступень 1: две TLS-записи — единственная техника, которой не мешает
    // пересборка TCP-потока, поэтому пробуется первой.
    let tls_record = trials(&target, domain, FragStrategy::TlsRecord, bypass_params, trials_count, early_abandon, timing).await;
    if early_abandon && tls_record.is_convincing() {
        return DiagnosticResult {
            direct,
            quic: ProbeOutcome::NotApplicable,
            tls_record,
            sni_split: empty,
            disorder: empty,
            oob: empty,
            fake: empty,
        };
    }

    // Ступень 2: разрыв точно по SNI.
    let sni_split = trials(&target, domain, FragStrategy::SniSplit, bypass_params, trials_count, early_abandon, timing).await;
    if early_abandon && sni_split.is_convincing() {
        return DiagnosticResult {
            direct,
            quic: ProbeOutcome::NotApplicable,
            tls_record,
            sni_split,
            disorder: empty,
            oob: empty,
            fake: empty,
        };
    }

    // Ступень 3: OOB-байт. Дешёвый — не платит задержку ретрансмита.
    // На платформах без MSG_OOB и управления TTL пробу не гоняем: она бы
    // просто откатилась на обычный сплит и дала бессмысленный результат.
    let oob = if crate::bypass::socket::supports_ttl_tricks() {
        trials(&target, domain, FragStrategy::Oob, bypass_params, trials_count, early_abandon, timing).await
    } else {
        empty
    };
    if early_abandon && oob.is_convincing() {
        return DiagnosticResult {
            direct,
            quic: ProbeOutcome::NotApplicable,
            tls_record,
            sni_split,
            disorder: empty,
            oob,
            fake: empty,
        };
    }

    // Свип по абсолютным позициям удалён.
    //
    // Он делал то же, что сплит по SNI, только вслепую: перебирал семь чисел
    // в надежде попасть внутрь имени домена, тогда как sni_split вычисляет
    // смещение точно. Если точное попадание не сработало, угадывание тем
    // более не сработает.
    //
    // При этом свип стоил семь проб против одной у остальных техник — дороже
    // всех прочих вместе — и за все наблюдения не выиграл ни разу.
    //
    // Сплит по SNI при этом ОСТАВЛЕН, хотя тоже пока не побеждал: он
    // покрывает другой класс DPI. Две TLS-записи уходят одним TCP-сегментом
    // и ломают разбор на уровне записей; sni_split режет TCP-поток и ломает
    // тех, кто его не пересобирает. Слабости ортогональные, и то, что здесь
    // обе бесполезны, — факт про эту сеть, а не про технику.
    // Ступень 5: disorder — последним, потому что работает через ретрансмит
    // и добавляет сотни миллисекунд к каждому соединению.
    let disorder = if crate::bypass::socket::supports_ttl_tricks() {
        trials(&target, domain, FragStrategy::Disorder, bypass_params, trials_count, early_abandon, timing).await
    } else {
        empty
    };

    // Ступень 6: fake. Последняя и единственная привилегированная — пробуем
    // только когда режим ремонта TCP реально доступен, иначе техника молча
    // откатилась бы на обычный сплит и мы бы измерили не её.
    let fake = if crate::bypass::socket::fake_supported() && crate::bypass::socket::tcp_repair_available() {
        trials(&target, domain, FragStrategy::Fake, bypass_params, trials_count, early_abandon, timing).await
    } else {
        empty
    };

    // QUIC проверяем только когда по TCP не вышло ничего: знать, что UDP/443
    // проходит, полезно, но на выбор стратегии это не влияет.
    let quic = if direct == ProbeOutcome::ConnectFailed {
        // TCP вообще не открылся — домен не резолвится либо блок по IP.
        ProbeOutcome::NotApplicable
    } else {
        probe_quic(domain).await
    };

    DiagnosticResult { direct, quic, tls_record, sni_split, disorder, oob, fake }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn params() -> BypassParams {
        toml::from_str("split_pos_min = 4\nsplit_pos_max = 12\nsplit_delay_ms = 1\nwindow_clamp = 0\n")
            .expect("параметры обхода")
    }

    /// Локальный «сервер»: дочитывает ClientHello и отвечает `reply`
    /// (пустой ответ — закрыть соединение без единого байта).
    async fn server(reply: &'static [u8]) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut hello = vec![0u8; 5];
            stream.read_exact(&mut hello).await.unwrap();
            let len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
            let mut body = vec![0u8; len];
            stream.read_exact(&mut body).await.unwrap();
            if !reply.is_empty() {
                stream.write_all(reply).await.unwrap();
            }
            stream.shutdown().await.unwrap();
        });
        addr
    }

    async fn probe(reply: &'static [u8], strategy: FragStrategy) -> ProbeOutcome {
        let addr = server(reply).await;
        let hello = crate::bypass::tls::build_client_hello_sized("probe.example", 1850);
        probe_tcp_inner(&addr, &hello, strategy, &params()).await
    }

    #[tokio::test]
    async fn tls_reply_counts_as_success() {
        assert_eq!(probe(&[0x16, 0x03, 0x03, 0x00, 0x02, 0x02, 0x00], FragStrategy::None).await, ProbeOutcome::Success);
        assert_eq!(probe(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28], FragStrategy::TlsRecord).await, ProbeOutcome::Success);
    }

    #[tokio::test]
    async fn block_page_is_not_success() {
        assert_eq!(
            probe(b"HTTP/1.1 302 Found\r\nLocation: http://blocked.example\r\n\r\n", FragStrategy::None).await,
            ProbeOutcome::Injected,
        );
    }

    /// FIN без ответа — не «молча дропаются» и не «сброшено»: пакеты
    /// дошли, RST не было, соединение закрыли.
    #[tokio::test]
    async fn fin_without_reply_is_its_own_outcome() {
        assert_eq!(probe(b"", FragStrategy::SniSplit).await, ProbeOutcome::ClosedAfterHello);
    }

    #[test]
    fn only_browser_sized_hellos_calibrate_the_probe() {
        assert!(is_browser_sized(1889));
        assert!(!is_browser_sized(273), "маленький пакет мерит автодиагностика по своему классу");
        assert!(!is_browser_sized(MAX_PROBE_HELLO + 1), "больше одной TLS-записи ClientHello не бывает");
    }
}
