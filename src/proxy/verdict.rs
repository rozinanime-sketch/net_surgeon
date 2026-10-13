//! Итог соединения с обходом: на какой стадии оно кончилось и похоже ли это
//! на блокировку.
//!
//! Только диагностика. На выбор стратегий вердикт не влияет — исход для них
//! по-прежнему считает `adaptive::handshake_completed`. Пока вердикты не
//! сверены с дампами трафика, менять по ним обход рано: ошибка классификатора
//! сломала бы то, что сейчас работает.
//!
//! Классификатор осторожен. По счётчикам прокси нельзя отличить DPI,
//! заглушивший поток, от приложения, которому сервер просто не ответил, —
//! поэтому «остановка данных» только подозревается, а там, где доводов нет,
//! вердикт `UNKNOWN`.

use std::time::{Duration, Instant};

use crate::engine::strategy::Strategy;
use crate::observability::logging::{log_nested_t, LogLevel, LogSender};

/// Сколько сервер должен молчать в ответ на данные клиента, чтобы
/// заподозрить остановку. Приложения ждут ответа на запрос секунды, а не
/// десятки; меньше — и медленный сервер сошёл бы за блокировку.
const STALL_SILENCE: Duration = Duration::from_secs(10);

/// Сколько получить, чтобы ответ был больше самого рукопожатия. Ответ
/// сервера на ClientHello (сертификаты, билеты сессии) — обычно 2–4 КБ, и
/// столько же приходит, когда DPI глушит поток сразу после рукопожатия.
/// Тот же порог у zapret2 (`standard_success_detector`, inseq=4096).
const PAST_HANDSHAKE: u64 = 4 * 1024;

/// Сколько получить, чтобы успех был несомненным. Заморозка DPI бьёт в
/// первых ~16 КБ ответа (см. engine::freeze); поток, прошедший дальше с
/// запасом, через неё уже прошёл.
const PAST_FREEZE: u64 = 32 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Side {
    Client,
    Server,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum How {
    Fin,
    Reset,
    Error,
}

/// Чем и когда кончилось одно направление пересылки.
#[derive(Debug)]
pub(crate) struct End {
    pub side: Side,
    pub how: How,
    pub error: Option<String>,
    pub at: Instant,
}

impl End {
    pub fn fin(side: Side) -> Self {
        End { side, how: How::Fin, error: None, at: Instant::now() }
    }

    pub fn new(side: Side, e: &std::io::Error) -> Self {
        // Сброс отдельно от прочих ошибок: RST посреди потока — почерк DPI,
        // а сервер так закрывается редко.
        let how = match e.kind() {
            std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted => How::Reset,
            _ => How::Error,
        };
        End { side, how, error: Some(e.to_string()), at: Instant::now() }
    }

    fn key(&self) -> &'static str {
        match (self.side, self.how) {
            (Side::Server, How::Fin) => "close.server_fin",
            (Side::Server, How::Reset) => "close.server_rst",
            (Side::Server, How::Error) => "close.server_error",
            (Side::Client, How::Fin) => "close.client_fin",
            (Side::Client, How::Reset) => "close.client_rst",
            (Side::Client, How::Error) => "close.client_error",
        }
    }
}

/// Сколько начала потока помнить: заголовки HTTP-ответа (редирект на
/// заглушку) помещаются с запасом.
const HEAD_MAX: usize = 1024;

/// Одно направление пересылки: сколько байт прошло, когда последний кусок
/// и чем кончилось.
#[derive(Debug, Default)]
pub(crate) struct Flow {
    pub bytes: u64,
    pub last: Option<Instant>,
    /// `None` — направление кончилось без отдельного события (например,
    /// до пересылки дело не дошло).
    pub end: Option<End>,
    /// Начало потока, до HEAD_MAX байт.
    pub head: Vec<u8>,
    /// Повторы отправки по сокету сервера к концу пересылки — заполняется у
    /// направления «сервер → клиент», пока сокет ещё открыт.
    pub retrans: Option<crate::bypass::socket::Retransmits>,
}

impl Flow {
    pub fn add(&mut self, chunk: &[u8]) {
        if self.head.len() < HEAD_MAX {
            let take = chunk.len().min(HEAD_MAX - self.head.len());
            self.head.extend_from_slice(&chunk[..take]);
        }
        self.bytes += chunk.len() as u64;
        self.last = Some(Instant::now());
    }
}

/// Сколько повторов отправки при неподтверждённых данных — уже не потери
/// на Wi-Fi, а глухая стена. Тот же порог у zapret2 (retrans=3).
const RETRANS_STUCK: u32 = 3;

/// Ответ — HTTP-редирект на чужой сайт: так DPI отдаёт заглушку «доступ
/// ограничен». Чужой — другой домен второго уровня, как у zapret2
/// (`is_dpi_redirect`): переход с `example.com` на `www.example.com` — не он.
pub(crate) fn is_dpi_redirect(domain: &str, reply: &[u8]) -> bool {
    let text = String::from_utf8_lossy(&reply[..reply.len().min(HEAD_MAX)]);
    let mut lines = text.split("\r\n");
    let status = lines.next().unwrap_or_default();
    let code = status.strip_prefix("HTTP/1.").and_then(|r| r.get(2..5));
    if !matches!(code, Some("302" | "307")) {
        return false;
    }
    let Some(location) = lines.take_while(|l| !l.is_empty()).find_map(|l| {
        let (name, value) = l.split_once(':')?;
        name.trim().eq_ignore_ascii_case("location").then(|| value.trim())
    }) else {
        return false;
    };
    let host = location.split("://").nth(1).unwrap_or("").split(['/', ':', '?', '#']).next().unwrap_or("");
    let sld = |h: &str| {
        let h = h.trim_end_matches('.').to_ascii_lowercase();
        let parts: Vec<&str> = h.rsplitn(3, '.').take(2).collect();
        parts.into_iter().rev().collect::<Vec<_>>().join(".")
    };
    !host.is_empty() && sld(host) != sld(domain)
}

/// Длина ClientHello, если первый пакет — TLS; 0 — не TLS.
pub(crate) fn tls_hello_len(first: &[u8]) -> u64 {
    let tls = first.len() >= 5 && first[0] == 0x16 && first[1] == 0x03;
    if tls { crate::bypass::tls::client_hello_len(first) as u64 } else { 0 }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    ConnectFail,
    TlsFail,
    DataStallSuspected,
    Reset,
    DpiRedirect,
    Ok,
    Unknown,
}

impl Verdict {
    fn as_str(self) -> &'static str {
        match self {
            Verdict::ConnectFail => "CONNECT_FAIL",
            Verdict::TlsFail => "TLS_FAIL",
            Verdict::DataStallSuspected => "DATA_STALL_SUSPECTED",
            Verdict::Reset => "RESET",
            Verdict::DpiRedirect => "DPI_REDIRECT",
            Verdict::Ok => "OK",
            Verdict::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    fn as_str(self) -> &'static str {
        match self {
            Confidence::Low => "LOW",
            Confidence::Medium => "MEDIUM",
            Confidence::High => "HIGH",
        }
    }
}

/// Вердикт, уверенность и ключ перевода с объяснением.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Finding {
    pub verdict: Verdict,
    pub confidence: Confidence,
    pub reason: &'static str,
}

/// Что известно о соединении к моменту, когда первая сторона его закрыла.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Facts {
    /// Длина ClientHello; 0 — соединение не TLS.
    pub hello_len: u64,
    pub sent: u64,
    pub received: u64,
    /// Первый кусок ответа — TLS alert (`tls::server_accepted` == false).
    pub alert: bool,
    /// Кто и как закрыл первым.
    pub side: Side,
    pub how: How,
    /// Клиент писал после последнего байта сервера — сколько с тех пор
    /// прошло до конца. `None` — последним говорил сервер.
    pub unanswered: Option<Duration>,
    /// Ядро не раз повторяло отправку, а сервер так и не подтвердил данные:
    /// пакеты пропадают в сети, а не сервер молчит.
    pub stuck: bool,
    /// Ответ — редирект на заглушку (см. [`is_dpi_redirect`]).
    pub redirect: bool,
}

pub(crate) fn classify(f: &Facts) -> Finding {
    let finding = |verdict, confidence, reason| Finding { verdict, confidence, reason };

    // Alert первым ответом — сервер отверг ClientHello (или получил его
    // испорченным): рукопожатие провалено, и сказал это сам сервер.
    if f.received > 0 && f.alert {
        return finding(Verdict::TlsFail, Confidence::High, "verdict.alert");
    }
    if f.redirect {
        return finding(Verdict::DpiRedirect, Confidence::High, "verdict.dpi_redirect");
    }
    // Сброс со стороны сервера. Кто его прислал — сервер или DPI от его
    // имени, — по сокету не видно. Но в первых килобайтах это почерк DPI
    // (zapret2 считает так RST до 4 КБ), а позже — скорее сам сервер.
    if f.side == Side::Server && f.how == How::Reset {
        return if f.received <= PAST_HANDSHAKE {
            finding(Verdict::Reset, Confidence::High, "verdict.server_reset_early")
        } else {
            finding(Verdict::Reset, Confidence::Medium, "verdict.server_reset")
        };
    }
    if f.hello_len == 0 {
        return finding(Verdict::Unknown, Confidence::Low, "verdict.not_tls");
    }
    // На ClientHello не пришло ни байта: дальше рукопожатия дело не дошло.
    if f.received == 0 {
        // Сервер не подтвердил даже ClientHello: соединение заглушили.
        return if f.stuck {
            finding(Verdict::TlsFail, Confidence::High, "verdict.blackhole")
        } else {
            finding(Verdict::TlsFail, Confidence::Medium, "verdict.no_reply")
        };
    }
    // Ответ был, но клиент ничего не дослал после ClientHello: свою часть
    // рукопожатия (Finished) он не отправил — ответ сервера до него не дошёл
    // целиком или оказался не тем. Первый ответ сервера сам по себе — ещё не
    // завершённое рукопожатие.
    if f.sent <= f.hello_len {
        return finding(Verdict::TlsFail, Confidence::Medium, "verdict.handshake_unfinished");
    }
    // Рукопожатие завершено. Дальше вопрос — отвечал ли сервер на данные.
    match f.unanswered {
        Some(silence) if silence >= STALL_SILENCE => {
            // Ядро сдалось, повторяя отправку, — пакеты пропадали в сети, это
            // уже не похоже на молчащее приложение.
            // Повторы с неподтверждёнными данными — данные не доходят.
            if f.stuck {
                return finding(Verdict::DataStallSuspected, Confidence::High, "verdict.unanswered_retrans");
            }
            let confidence = if f.side == Side::Server && f.how == How::Error { Confidence::Medium } else { Confidence::Low };
            finding(Verdict::DataStallSuspected, confidence, "verdict.unanswered")
        }
        // Клиент написал и закрыл, не дождавшись: ни успеха, ни провала.
        Some(_) => finding(Verdict::Unknown, Confidence::Low, "verdict.closed_early"),
        None if f.received >= PAST_FREEZE => finding(Verdict::Ok, Confidence::High, "verdict.ok_past_freeze"),
        None if f.received > PAST_HANDSHAKE => finding(Verdict::Ok, Confidence::Medium, "verdict.ok"),
        // Последними могли быть билеты сессии, а не ответ приложения.
        None => finding(Verdict::Unknown, Confidence::Low, "verdict.handshake_sized"),
    }
}

/// Неудачное подключение к серверу. Стратегии ещё нет: она выбирается по
/// ClientHello, а до него дело не дошло.
pub(crate) fn report_connect_fail(log_tx: &LogSender, domain: &str) {
    log_finding(log_tx, domain, "—", Finding {
        verdict: Verdict::ConnectFail,
        confidence: Confidence::High,
        reason: "verdict.connect_fail",
    });
}

/// Что пересылка узнала о соединении.
pub(crate) struct Exchange {
    /// Начало соединения — от него считается его жизнь.
    pub opened: Instant,
    /// Длина ClientHello; 0 — не TLS.
    pub hello_len: u64,
    /// «Клиент → сервер».
    pub up: Flow,
    /// «Сервер → клиент».
    pub down: Flow,
    /// Первый кусок ответа не был TLS alert (`tls::server_accepted`).
    pub accepted: bool,
}

/// Итог пересылки: как кончилось соединение и вердикт.
pub(crate) fn report(log_tx: &LogSender, domain: &str, strategy: Strategy, conn: Exchange) {
    let Exchange { opened, hello_len, up, down, accepted } = conn;
    let Some(first) = up.end.into_iter().chain(down.end).min_by_key(|e| e.at) else {
        return;
    };
    let life = first.at.duration_since(opened);
    let idle = first.at.duration_since(down.last.unwrap_or(opened));
    log_nested_t(log_tx, LogLevel::Info, "log.conn_closed", "end", first.key(), vec![
        ("domain", domain.to_string()),
        ("life", format!("{:.1}", life.as_secs_f64())),
        ("sent", up.bytes.to_string()),
        ("received", down.bytes.to_string()),
        ("idle", format!("{:.1}", idle.as_secs_f64())),
        ("detail", first.error.as_ref().map(|e| format!(" ({e})")).unwrap_or_default()),
    ]);

    let unanswered = match (up.last, down.last) {
        (Some(tx), Some(rx)) if tx <= rx => None,
        (Some(tx), _) => Some(first.at.saturating_duration_since(tx)),
        (None, _) => None,
    };
    let finding = classify(&Facts {
        hello_len,
        sent: up.bytes,
        received: down.bytes,
        alert: !accepted,
        side: first.side,
        how: first.how,
        unanswered,
        stuck: down.retrans.is_some_and(|r| r.total >= RETRANS_STUCK && r.unacked_segments > 0),
        redirect: hello_len == 0 && is_dpi_redirect(domain, &down.head),
    });
    log_finding(log_tx, domain, strategy.as_str(), finding);
}

fn log_finding(log_tx: &LogSender, domain: &str, strategy: &str, f: Finding) {
    let level = match f.verdict {
        Verdict::Ok | Verdict::Unknown => LogLevel::Info,
        _ => LogLevel::Warning,
    };
    log_nested_t(log_tx, level, "log.conn_verdict", "reason", f.reason, vec![
        ("domain", domain.to_string()),
        ("verdict", f.verdict.as_str().to_string()),
        ("confidence", f.confidence.as_str().to_string()),
        ("strategy", strategy.to_string()),
    ]);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Рукопожатие завершено, ответ получен, закрыло приложение.
    fn done() -> Facts {
        Facts {
            hello_len: 517,
            sent: 900,
            received: 6000,
            alert: false,
            side: Side::Client,
            how: How::Fin,
            unanswered: None,
            stuck: false,
            redirect: false,
        }
    }

    fn verdict(f: Facts) -> (Verdict, Confidence) {
        let found = classify(&f);
        (found.verdict, found.confidence)
    }

    #[test]
    fn alert_as_first_reply_is_a_tls_failure() {
        assert_eq!(verdict(Facts { sent: 517, received: 7, alert: true, side: Side::Server, how: How::Fin, ..done() }),
            (Verdict::TlsFail, Confidence::High));
    }

    #[test]
    fn server_reset_is_reported_before_and_after_the_handshake() {
        let rst = Facts { side: Side::Server, how: How::Reset, ..done() };
        assert_eq!(verdict(rst).0, Verdict::Reset);
        assert_eq!(verdict(Facts { sent: 517, received: 0, ..rst }).0, Verdict::Reset);
        // Сброс от приложения — не сетевой: решают остальные признаки
        assert_eq!(verdict(Facts { side: Side::Client, how: How::Reset, ..done() }).0, Verdict::Ok);
    }

    #[test]
    fn no_reply_to_client_hello_is_a_tls_failure() {
        assert_eq!(verdict(Facts { sent: 517, received: 0, ..done() }), (Verdict::TlsFail, Confidence::Medium));
    }

    #[test]
    fn first_server_bytes_alone_are_not_a_finished_handshake() {
        // Сервер ответил, но клиент так и не отправил Finished
        let f = Facts { sent: 517, received: 2773, side: Side::Client, how: How::Fin, ..done() };
        assert_eq!(classify(&f).reason, "verdict.handshake_unfinished");
        assert_eq!(verdict(f).0, Verdict::TlsFail);
    }

    #[test]
    fn long_silence_after_client_data_is_only_a_suspected_stall() {
        // Как Discord на телефоне: рукопожатие прошло, запрос ушёл, ответа нет
        let f = Facts { sent: 723, received: 2773, unanswered: Some(Duration::from_secs(120)), ..done() };
        assert_eq!(verdict(f), (Verdict::DataStallSuspected, Confidence::Low));
        // Ядро бросило повторную отправку — признак сильнее
        let timed_out = Facts { side: Side::Server, how: How::Error, ..f };
        assert_eq!(verdict(timed_out), (Verdict::DataStallSuspected, Confidence::Medium));
    }

    #[test]
    fn small_traffic_alone_is_neither_a_stall_nor_a_success() {
        // Последним говорил сервер, но пришло не больше рукопожатия: это
        // могли быть билеты сессии, а не ответ
        assert_eq!(verdict(Facts { sent: 723, received: 2773, ..done() }).0, Verdict::Unknown);
        assert_eq!(verdict(Facts { sent: 723, received: 6000, ..done() }), (Verdict::Ok, Confidence::Medium));
        // Клиент написал и сразу закрыл — судить не о чем
        let early = Facts { unanswered: Some(Duration::from_secs(2)), ..done() };
        assert_eq!(verdict(early).0, Verdict::Unknown);
    }

    #[test]
    fn traffic_past_the_freeze_window_is_a_sure_success() {
        assert_eq!(verdict(Facts { received: 200_000, ..done() }), (Verdict::Ok, Confidence::High));
    }

    #[test]
    fn non_tls_is_unknown_unless_reset() {
        let plain = Facts { hello_len: 0, ..done() };
        assert_eq!(verdict(plain).0, Verdict::Unknown);
        assert_eq!(verdict(Facts { side: Side::Server, how: How::Reset, ..plain }).0, Verdict::Reset);
    }

    /// Сегодняшний Discord: ClientHello ушёл, ядро повторяет его, а сервер
    /// не подтвердил ни байта — соединение заглушено, а не сервер молчит.
    #[test]
    fn unacknowledged_hello_is_a_blackhole() {
        let silent = Facts { sent: 1586, received: 0, ..done() };
        assert_eq!(classify(&silent).reason, "verdict.no_reply");
        let stuck = Facts { stuck: true, ..silent };
        assert_eq!(verdict(stuck), (Verdict::TlsFail, Confidence::High));
        assert_eq!(classify(&stuck).reason, "verdict.blackhole");
    }

    #[test]
    fn retransmits_turn_a_suspected_stall_into_a_sure_one() {
        let f = Facts { sent: 723, received: 2773, unanswered: Some(Duration::from_secs(60)), stuck: true, ..done() };
        assert_eq!(verdict(f), (Verdict::DataStallSuspected, Confidence::High));
    }

    #[test]
    fn early_reset_is_dpi_like_late_one_is_not_sure() {
        let early = Facts { received: 1200, side: Side::Server, how: How::Reset, ..done() };
        assert_eq!(classify(&early).reason, "verdict.server_reset_early");
        assert_eq!(verdict(early).1, Confidence::High);
        let late = Facts { received: 500_000, ..early };
        assert_eq!(verdict(late), (Verdict::Reset, Confidence::Medium));
    }

    #[test]
    fn redirect_to_another_site_is_a_block_page() {
        let reply = |code: &str, location: &str| format!("HTTP/1.1 {code} Found\r\nServer: x\r\nLocation: {location}\r\n\r\n").into_bytes();
        assert!(is_dpi_redirect("rutracker.org", &reply("302", "http://warning.rt.ru/?id=1")));
        assert!(is_dpi_redirect("rutracker.org", &reply("307", "https://blocked.example.net:8080/")));
        // Свой сайт, относительный путь, постоянный редирект — не заглушка
        assert!(!is_dpi_redirect("example.com", &reply("302", "https://www.example.com/login")));
        assert!(!is_dpi_redirect("example.com", &reply("302", "/login")));
        assert!(!is_dpi_redirect("example.com", &reply("301", "https://other.org/")));
        assert!(!is_dpi_redirect("example.com", b"HTTP/1.1 200 OK\r\n\r\n"));

        let f = Facts { hello_len: 0, redirect: true, ..done() };
        assert_eq!(verdict(f), (Verdict::DpiRedirect, Confidence::High));
    }

    #[test]
    fn flow_keeps_only_the_head_of_the_stream() {
        let mut flow = Flow::default();
        flow.add(&[1u8; 700]);
        flow.add(&[2u8; 700]);
        assert_eq!((flow.bytes, flow.head.len()), (1400, HEAD_MAX));
        assert_eq!(flow.head[HEAD_MAX - 1], 2);
    }

    /// Ядро отвечает на TCP_INFO по живому соединению: повторов нет.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[tokio::test]
    async fn retransmits_are_read_from_a_live_socket() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let _server = listener.accept().await.unwrap();
        let r = crate::bypass::socket::retransmits(crate::bypass::socket::raw_sock(&client)).unwrap();
        assert_eq!(r, crate::bypass::socket::Retransmits::default());
    }

    #[test]
    fn reset_is_told_apart_from_other_failures() {
        use std::io::{Error, ErrorKind};
        let rst = End::new(Side::Server, &Error::from(ErrorKind::ConnectionReset));
        assert_eq!(rst.key(), "close.server_rst");
        let other = End::new(Side::Server, &Error::from(ErrorKind::TimedOut));
        assert_eq!(other.key(), "close.server_error");
        assert_eq!(End::fin(Side::Client).key(), "close.client_fin");
    }

    #[test]
    fn hello_len_is_zero_for_non_tls() {
        assert_eq!(tls_hello_len(b"GET / HTTP/1.1\r\n"), 0);
        let hello = crate::bypass::tls::build_client_hello("example.com");
        assert_eq!(tls_hello_len(&hello), hello.len() as u64);
    }
}
