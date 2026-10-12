//! Обнаружение «заморозки после ~16 КБ» и эскалация на decoy-технику.
//!
//! На сетях с ТСПУ TLS-соединение к зарубежному хостингу замирает после ~16 КБ,
//! если DPI не отнёс его к разрешённому имени. Спрятать имя (tls_record,
//! sni_split) от этого не спасает — спасает только подстановка разрешённого
//! имени (fake/seqovl). Но диагностика меряет лишь рукопожатие: у tls_record
//! оно проходит, техника выбирается, а после 16 КБ — заморозка.
//!
//! [`probe`] доводит НАСТОЯЩЕЕ TLS-соединение через собственный SOCKS5 прокси с
//! принудительной техникой (см. [`crate::engine::probe_force`]) и качает больше
//! 16 КБ: так видно, замирает ли поток. [`spawn_diagnosis`] прогоняет им
//! выбранную технику и, если та морозит, переключается на decoy.
//!
//! # Проверка в бою
//!
//! Саму заморозку нельзя воспроизвести без цензурирующей сети, поэтому «Frozen»
//! проверяется у пользователя. Логика порогов и путь «Survived/Inconclusive»
//! покрыты тестами и локальным сервером.

use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::engine::strategy::Strategy;

// Состояние «сеть морозит» и порт проб живут в net_state (единый дом сетевого
// состояния); здесь — привычные имена, делегирующие туда.
use crate::engine::net_state;

pub fn prefer_decoy() -> bool {
    net_state::prefer_decoy()
}

pub fn set_prefer_decoy(on: bool) {
    net_state::set_prefer_decoy(on);
}

pub fn set_socks_port(port: u16) {
    net_state::set_socks_port(port);
}

pub fn socks_port() -> Option<u16> {
    net_state::socks_port()
}

/// Техника, подставляющая разрешённое имя в начало потока. Только она
/// переживает заморозку после 16 КБ.
pub fn is_decoy(strategy: Strategy) -> bool {
    matches!(strategy, Strategy::Fake | Strategy::Seqovl | Strategy::FakeMultiDisorder)
}

/// Что показала freeze-проба.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Поток прошёл 16 КБ — техника переживает заморозку.
    Survived,
    /// Поток встал после начала данных, но раньше порога — заморозка.
    Frozen,
    /// Проверить не удалось (ресурс мал, ошибка сети/TLS) — не улика.
    Inconclusive,
}

/// Сколько байт прикладных данных считаем доказательством, что 16 КБ пройдены.
const SURVIVE_BYTES: usize = 24 * 1024;
/// Данных прошло больше этого — значит рукопожатие позади и пошёл поток.
/// Порог низкий (заголовки ответа и первый кусок тела): часть сетей морозит
/// соединение уже на 2–3 КБ, а не на 16 КБ, и при пороге 4 КБ заморозка до
/// него просто не доходила — вердикт `Frozen` не выставлялся, и эскалации на
/// decoy не было. От ложного `Frozen` защищает не этот порог, а STALL_CONFIRM.
const STARTED_BYTES: usize = 1024;
/// Как часто проверять, идут ли данные.
const READ_POLL: Duration = Duration::from_secs(2);
/// Непрерывная тишина дольше этого — поток действительно встал (заморозка), а
/// не просто пауза мобильной сети. Порог высокий намеренно: ложный `Frozen`
/// выключил бы дешёвые техники на неморозящей сети.
const STALL_CONFIRM: Duration = Duration::from_secs(12);
/// Общий предел на пробу, чтобы она не висела вечно.
const PROBE_DEADLINE: Duration = Duration::from_secs(30);

/// Доводит TLS к `host` через собственный SOCKS5 (`127.0.0.1:socks_port`) с
/// принудительной техникой `strategy` и качает ответ, определяя заморозку.
pub async fn probe(socks_port: u16, host: &str, strategy: Strategy) -> Verdict {
    match tokio::time::timeout(PROBE_DEADLINE, probe_inner(socks_port, host, strategy)).await {
        Ok(v) => v,
        Err(_) => Verdict::Inconclusive,
    }
}

async fn probe_inner(socks_port: u16, host: &str, strategy: Strategy) -> Verdict {
    let Ok(tcp) = TcpStream::connect(("127.0.0.1", socks_port)).await else {
        return Verdict::Inconclusive;
    };
    let _ = tcp.set_nodelay(true);
    // Принудительная техника — по нашему локальному порту, до отправки ClientHello.
    let Ok(local) = tcp.local_addr() else { return Verdict::Inconclusive };
    crate::engine::probe_force::set(local.port(), strategy);

    let mut tcp = tcp;
    if socks5_connect(&mut tcp, host, 443).await.is_err() {
        crate::engine::probe_force::take(local.port()); // проба сорвалась — снять метку
        return Verdict::Inconclusive;
    }

    let name = match rustls::pki_types::ServerName::try_from(host.to_string()) {
        Ok(n) => n,
        Err(_) => {
            crate::engine::probe_force::take(local.port()); // ClientHello не уйдёт — снять метку
            return Verdict::Inconclusive;
        }
    };
    let mut tls = match connector().connect(name, tcp).await {
        Ok(s) => s,
        // Рукопожатие не прошло — не улика о заморозке. Метку снимаем на случай,
        // если соединение оборвалось до отправки ClientHello (тогда прокси её
        // не забрал); если ClientHello ушёл, take уже вернул None — вреда нет.
        Err(_) => {
            crate::engine::probe_force::take(local.port());
            return Verdict::Inconclusive;
        }
    };

    // identity, а не gzip: сжатие занизило бы объём и могло увести ниже 16 КБ,
    // так и не дойдя до порога заморозки.
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
    );
    if tls.write_all(request.as_bytes()).await.is_err() {
        return Verdict::Inconclusive;
    }

    let mut total = 0usize;
    let mut response = ResponseEnd::default();
    let mut buf = [0u8; 8192];
    // Момент начала непрерывной тишины; сбрасывается на каждом пришедшем байте.
    let mut silent_since: Option<Instant> = None;
    loop {
        match tokio::time::timeout(READ_POLL, tls.read(&mut buf)).await {
            // Чистый конец потока: сервер отдал всё.
            Ok(Ok(0)) => {
                return if total >= 16 * 1024 { Verdict::Survived } else { Verdict::Inconclusive };
            }
            Ok(Ok(n)) => {
                total += n;
                silent_since = None;
                if total >= SURVIVE_BYTES {
                    return Verdict::Survived;
                }
                response.feed(&buf[..n]);
                // Ответ пришёл целиком, а сервер держит соединение вопреки
                // `Connection: close`: дальше будет тишина, но не заморозка.
                // Ресурс мал для проверки.
                if response.complete() {
                    return Verdict::Inconclusive;
                }
            }
            // Ошибка чтения — не улика.
            Ok(Err(_)) => return Verdict::Inconclusive,
            // Тишина в этом опросе. Заморозка — только если поток шёл (данные
            // начались) и молчит уже дольше STALL_CONFIRM подряд: короткие
            // паузы мобильной сети под это не подпадают.
            Err(_) => {
                let since = *silent_since.get_or_insert_with(Instant::now);
                if total >= STARTED_BYTES && since.elapsed() >= STALL_CONFIRM {
                    return Verdict::Frozen;
                }
            }
        }
    }
}

/// Итог эскалации.
pub struct Escalation {
    pub strategy: Option<Strategy>,
    /// Приманку выбрала freeze-проба, а не диагностика: та её могла и не
    /// мерить (лестница останавливается на первой дешёвой технике).
    pub escalated: bool,
}

/// Проверяет выбранную технику на заморозку и при необходимости переключает на
/// decoy.
///
/// Только сокетный путь: в пакетном режиме seqovl подбирается обычными пробами
/// (см. diagnostics), там эскалация не нужна. Запускается лишь когда поднят
/// собственный SOCKS5 (через него идёт проба) и выбрана НЕ decoy-техника.
/// «Напрямую» тоже проверяется: заморозка бьёт по незабелённому TLS, а не по
/// заблокированным именам, и прямое рукопожатие она пропускает.
pub async fn escalate_on_freeze(
    domain: &str,
    chosen: Option<Strategy>,
    log_tx: &crate::observability::logging::LogSender,
) -> Escalation {
    use crate::observability::logging::{log_t, LogLevel};

    let unchanged = Escalation { strategy: chosen, escalated: false };
    if crate::bypass::packet_mode::is_active() {
        return unchanged;
    }
    let Some(port) = socks_port() else { return unchanged };

    // Решение отделено от сетевого I/O (тестируется), пробы подставляются здесь.
    let (final_strategy, froze) = resolve(chosen, |s| probe(port, domain, s)).await;

    if froze {
        // Сеть морозит незабелённый TLS: дальше по умолчанию предпочитаем decoy.
        set_prefer_decoy(true);
        log_t(log_tx, LogLevel::Warning, "log.freeze_detected", vec![("domain", domain.to_string())]);
        if final_strategy != chosen {
            log_t(log_tx, LogLevel::Success, "log.freeze_escalated", vec![("domain", domain.to_string())]);
        }
    }
    Escalation { strategy: final_strategy, escalated: final_strategy != chosen }
}

/// Приманки сокетного пути по возрастанию цены (seqovl без перехвата пакетов
/// недоступен).
const SOCKET_DECOYS: [Strategy; 2] = [Strategy::Fake, Strategy::FakeMultiDisorder];

/// Чистое решение эскалации: по вердиктам проб (через `probe_fn`) выбирает
/// итоговую технику и говорит, обнаружена ли заморозка. Без сети и глобалов —
/// поэтому тестируется. `probe_fn(strategy) -> Verdict`.
///
/// Приманки проверяются самой freeze-пробой, а не по итогам диагностики: та
/// останавливается на первой прошедшей дешёвой технике и fake обычно не мерит,
/// и раньше эскалации из-за этого почти не случалось.
async fn resolve<F, Fut>(chosen: Option<Strategy>, mut probe_fn: F) -> (Option<Strategy>, bool)
where
    F: FnMut(Strategy) -> Fut,
    Fut: std::future::Future<Output = Verdict>,
{
    let Some(current) = chosen else { return (chosen, false) };
    if is_decoy(current) {
        return (chosen, false); // уже подставляет имя — проверять нечего
    }
    if probe_fn(current).await != Verdict::Frozen {
        return (chosen, false); // дешёвая техника переживает 16 КБ
    }
    for decoy in SOCKET_DECOYS {
        if probe_fn(decoy).await == Verdict::Survived {
            return (Some(decoy), true);
        }
    }
    (chosen, true) // decoy не помог или недоступен — оставляем измеренную технику
}

/// Где кончается HTTP-ответ. Проба просит `Connection: close`, но сервер
/// вправе держать соединение, отдав ответ целиком (keep-alive за частью CDN),
/// и тишина после полного ответа на 1–16 КБ выглядела заморозкой.
#[derive(Default)]
struct ResponseEnd {
    /// Начало потока, пока не найден конец заголовков.
    head: Vec<u8>,
    /// Смещение тела от начала потока.
    body_start: Option<usize>,
    length: Option<usize>,
    chunked: bool,
    /// Последние байты потока: конец chunked-тела — `0\r\n\r\n`.
    tail: Vec<u8>,
    total: usize,
}

impl ResponseEnd {
    /// Заголовки длиннее — не наш случай, искать конец незачем.
    const HEAD_MAX: usize = 16 * 1024;
    const CHUNKED_END: &'static [u8] = b"0\r\n\r\n";

    fn feed(&mut self, data: &[u8]) {
        self.total += data.len();
        self.tail.extend_from_slice(data);
        let excess = self.tail.len().saturating_sub(Self::CHUNKED_END.len());
        self.tail.drain(..excess);

        if self.body_start.is_some() || self.head.len() >= Self::HEAD_MAX {
            return;
        }
        self.head.extend_from_slice(data);
        let Some(end) = self.head.windows(4).position(|w| w == b"\r\n\r\n") else { return };
        self.body_start = Some(end + 4);
        for line in String::from_utf8_lossy(&self.head[..end]).lines().skip(1) {
            let Some((name, value)) = line.split_once(':') else { continue };
            let value = value.trim();
            if name.trim().eq_ignore_ascii_case("content-length") {
                self.length = value.parse().ok();
            } else if name.trim().eq_ignore_ascii_case("transfer-encoding") {
                self.chunked = value.to_ascii_lowercase().contains("chunked");
            }
        }
        self.head = Vec::new();
    }

    /// Ответ пришёл целиком.
    fn complete(&self) -> bool {
        let Some(start) = self.body_start else { return false };
        if self.chunked {
            return self.tail == Self::CHUNKED_END;
        }
        self.length.is_some_and(|len| self.total >= start + len)
    }
}

/// Минимальный клиент SOCKS5: без аутентификации, CONNECT к `host:port` по имени.
async fn socks5_connect(tcp: &mut TcpStream, host: &str, port: u16) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};
    tcp.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greeting = [0u8; 2];
    tcp.read_exact(&mut greeting).await?;
    if greeting != [0x05, 0x00] {
        return Err(Error::other("socks5 greeting"));
    }
    let host_bytes = host.as_bytes();
    if host_bytes.len() > 255 {
        return Err(Error::new(ErrorKind::InvalidInput, "host too long"));
    }
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8];
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&port.to_be_bytes());
    tcp.write_all(&req).await?;
    // Ответ: VER REP RSV ATYP BND.ADDR BND.PORT. Для нашего прокси ATYP=1 (IPv4).
    let mut head = [0u8; 4];
    tcp.read_exact(&mut head).await?;
    if head[1] != 0x00 {
        return Err(Error::other("socks5 connect refused"));
    }
    let addr_len = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            tcp.read_exact(&mut l).await?;
            l[0] as usize
        }
        _ => return Err(Error::other("socks5 atyp")),
    };
    let mut rest = vec![0u8; addr_len + 2];
    tcp.read_exact(&mut rest).await?;
    Ok(())
}

fn connector() -> tokio_rustls::TlsConnector {
    use std::sync::{Arc, OnceLock};
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    let config = CONFIG.get_or_init(|| {
        let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("TLS 1.2/1.3")
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(config)
    });
    tokio_rustls::TlsConnector::from(Arc::clone(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefer_decoy_flag_roundtrips() {
        let _g = crate::engine::net_state::test_guard();
        set_prefer_decoy(false);
        assert!(!prefer_decoy());
        set_prefer_decoy(true);
        assert!(prefer_decoy());
        set_prefer_decoy(false);
    }

    #[tokio::test]
    async fn resolve_escalates_only_on_freeze_and_when_a_decoy_survives() {
        use Strategy::{Fake, FakeMultiDisorder, TlsRecord};
        use Verdict::{Frozen, Inconclusive, Survived};
        // Прогоняет resolve с заранее заданными вердиктами проб по порядку.
        async fn go(chosen: Option<Strategy>, verdicts: &[Verdict]) -> (Option<Strategy>, bool) {
            let idx = std::cell::Cell::new(0);
            let result = resolve(chosen, |_s| {
                let i = idx.get();
                idx.set(i + 1);
                let v = verdicts[i];
                async move { v }
            })
            .await;
            assert_eq!(idx.get(), verdicts.len(), "лишние или недостающие пробы");
            result
        }
        // Нечего эскалировать: нет техники / уже decoy — пробы не запускаются.
        assert_eq!(go(None, &[]).await, (None, false));
        assert_eq!(go(Some(Fake), &[]).await, (Some(Fake), false));
        // Дешёвая техника переживает 16 КБ — оставляем, заморозки нет.
        assert_eq!(go(Some(TlsRecord), &[Survived]).await, (Some(TlsRecord), false));
        // Заморозка + fake проходит → fake, флаг ставится.
        assert_eq!(go(Some(TlsRecord), &[Frozen, Survived]).await, (Some(Fake), true));
        // fake не проверился, fake+multidisorder прошёл → он.
        assert_eq!(go(Some(TlsRecord), &[Frozen, Inconclusive, Survived]).await, (Some(FakeMultiDisorder), true));
        // Обе приманки морозят → остаёмся, но заморозку зафиксировали.
        assert_eq!(go(Some(TlsRecord), &[Frozen, Frozen, Frozen]).await, (Some(TlsRecord), true));
    }

    #[test]
    fn response_end_by_length_and_chunked() {
        let mut fixed = ResponseEnd::default();
        fixed.feed(b"HTTP/1.1 301 Moved\r\nContent-Length: 5\r\n\r\nab");
        assert!(!fixed.complete());
        fixed.feed(b"cde");
        assert!(fixed.complete());

        let mut chunked = ResponseEnd::default();
        chunked.feed(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r");
        assert!(!chunked.complete());
        chunked.feed(b"\n\r\n");
        assert!(chunked.complete());

        // Без длины конец не известен — тишина остаётся уликой.
        let mut open = ResponseEnd::default();
        open.feed(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>");
        assert!(!open.complete());
    }

    #[test]
    fn only_name_substituting_techniques_are_decoy() {
        assert!(is_decoy(Strategy::Fake));
        assert!(is_decoy(Strategy::Seqovl));
        assert!(!is_decoy(Strategy::TlsRecord));
        assert!(!is_decoy(Strategy::SniSplit));
        assert!(!is_decoy(Strategy::Disorder));
        assert!(!is_decoy(Strategy::None));
    }
}
