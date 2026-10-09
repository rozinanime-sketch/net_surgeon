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

/// Проверяет выбранную технику на заморозку и при необходимости переключает на
/// decoy. Возвращает итоговую стратегию для сохранения.
///
/// Только сокетный путь: в пакетном режиме seqovl подбирается обычными пробами
/// (см. diagnostics), там эскалация не нужна. Запускается лишь когда поднят
/// собственный SOCKS5 (через него идёт проба) и выбрана НЕ decoy-техника.
pub async fn escalate_on_freeze(
    domain: &str,
    chosen: Option<Strategy>,
    result: &crate::engine::diagnostics::DiagnosticResult,
    log_tx: &crate::observability::logging::LogSender,
) -> Option<Strategy> {
    use crate::observability::logging::{log_t, LogLevel};

    if crate::bypass::packet_mode::is_active() {
        return chosen;
    }
    let Some(port) = socks_port() else { return chosen };
    let fake_convincing = result.fake.is_convincing();

    // Решение отделено от сетевого I/O (тестируется), пробы подставляются здесь.
    let (final_strategy, froze) =
        resolve(chosen, fake_convincing, |s| probe(port, domain, s)).await;

    if froze {
        // Сеть морозит незабелённый TLS: дальше по умолчанию предпочитаем decoy.
        set_prefer_decoy(true);
        log_t(log_tx, LogLevel::Warning, "log.freeze_detected", vec![("domain", domain.to_string())]);
        if final_strategy != chosen {
            log_t(log_tx, LogLevel::Success, "log.freeze_escalated", vec![("domain", domain.to_string())]);
        }
    }
    final_strategy
}

/// Чистое решение эскалации: по вердиктам проб (через `probe_fn`) выбирает
/// итоговую технику и говорит, обнаружена ли заморозка. Без сети и глобалов —
/// поэтому тестируется. `probe_fn(strategy) -> Verdict`.
async fn resolve<F, Fut>(
    chosen: Option<Strategy>,
    fake_convincing: bool,
    mut probe_fn: F,
) -> (Option<Strategy>, bool)
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
    // Заморозка. На сокете decoy — это fake (seqovl без перехвата недоступен).
    if fake_convincing && probe_fn(Strategy::Fake).await == Verdict::Survived {
        return (Some(Strategy::Fake), true);
    }
    (chosen, true) // decoy не помог или недоступен — оставляем измеренную технику
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
    async fn resolve_escalates_only_on_freeze_and_when_fake_survives() {
        use Strategy::{Fake, TlsRecord};
        // Прогоняет resolve с заранее заданными вердиктами проб по порядку.
        async fn go(chosen: Option<Strategy>, fake_conv: bool, verdicts: &[Verdict]) -> (Option<Strategy>, bool) {
            let idx = std::cell::Cell::new(0);
            resolve(chosen, fake_conv, |_s| {
                let i = idx.get();
                idx.set(i + 1);
                let v = verdicts[i];
                async move { v }
            })
            .await
        }
        // Нечего эскалировать: нет техники / уже decoy — пробы не запускаются.
        assert_eq!(go(None, true, &[]).await, (None, false));
        assert_eq!(go(Some(Fake), true, &[]).await, (Some(Fake), false));
        // Дешёвая техника переживает 16 КБ — оставляем, заморозки нет.
        assert_eq!(go(Some(TlsRecord), true, &[Verdict::Survived]).await, (Some(TlsRecord), false));
        // Заморозка + fake проходит → переключаемся на fake, флаг ставится.
        assert_eq!(go(Some(TlsRecord), true, &[Verdict::Frozen, Verdict::Survived]).await, (Some(Fake), true));
        // Заморозка, но fake не измерен → остаёмся, но заморозку зафиксировали.
        assert_eq!(go(Some(TlsRecord), false, &[Verdict::Frozen]).await, (Some(TlsRecord), true));
        // Заморозка, fake измерен, но тоже морозит → остаёмся, флаг стоит.
        assert_eq!(go(Some(TlsRecord), true, &[Verdict::Frozen, Verdict::Frozen]).await, (Some(TlsRecord), true));
    }

    #[test]
    fn only_fake_and_seqovl_are_decoy() {
        assert!(is_decoy(Strategy::Fake));
        assert!(is_decoy(Strategy::Seqovl));
        assert!(!is_decoy(Strategy::TlsRecord));
        assert!(!is_decoy(Strategy::SniSplit));
        assert!(!is_decoy(Strategy::Disorder));
        assert!(!is_decoy(Strategy::None));
    }
}
