//! Прозрачный режим: перехват без настройки приложений.
//!
//! # Зачем
//!
//! Обычные режимы требуют, чтобы приложение знало о прокси: браузеру нужно
//! прописать адрес, curl — передать `--proxy`. Настраивать каждое приложение
//! отдельно неудобно, а часть их прокси вообще не поддерживает.
//!
//! Здесь соединения перехватываются правилом iptables на уровне ядра.
//! Приложение думает, что подключается к серверу напрямую, и ничего
//! настраивать не нужно.
//!
//! # Откуда берётся адрес и имя
//!
//! При перехвате теряется и то и другое: `CONNECT host:443` не приходит,
//! а `peer_addr()` показывает наш собственный порт. Восстанавливаются они
//! из разных мест:
//!
//! * **адрес** — из conntrack через `SO_ORIGINAL_DST`: ядро помнит, куда
//!   пакет шёл до подмены;
//! * **имя домена** — из SNI в ClientHello, тем же парсером, что используют
//!   техники обхода.
//!
//! Второе и делает режим полноценным: без имени нельзя было бы ни выбрать
//! стратегию по домену, ни понять, нужен ли обход вообще.
//!
//! # Настройка
//!
//! Правило добавляется отдельно и требует root; сам прокси работает
//! без привилегий:
//!
//! ```text
//! sudo ./setup-transparent.sh on
//! sg nsproxy -c 'cargo run --release'
//! ```
//!
//! Исключение обязательно: без него исходящие соединения самого прокси
//! попадали бы обратно в него же, и получилась бы петля. Но исключать
//! по ПОЛЬЗОВАТЕЛЮ нельзя — прокси и браузер работают под одним и тем же,
//! и такое правило выкинуло бы из перехвата вообще весь трафик. Поэтому
//! прокси запускается в отдельной группе, и исключение делается по ней.

use std::collections::HashSet;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use crate::bypass::{matches_list, needs_bypass, socket};
use crate::config::BypassParams;
use crate::dns::ip_cache::IpDomainCache;
use crate::observability::logging::{log_t, LogLevel, LogSender};
use crate::observability::metrics::Metrics;
use crate::engine::strategy::{apply::Applied, Strategy, StrategyStore};

/// Адрес для IPv6-соединений, парный к `listen_host`.
///
/// REDIRECT в ip6tables заворачивает на `::1`, а не на `127.0.0.1`, и
/// слушатель только на IPv4 такие соединения не принимал: всё, что шло по
/// IPv6, либо проходило мимо обхода (правила не было), либо упиралось
/// в закрытый порт. `None` — у заданного адреса пары нет.
fn ipv6_companion(listen_host: &str) -> Option<&'static str> {
    match listen_host {
        "127.0.0.1" | "localhost" => Some("::1"),
        "0.0.0.0" => Some("::"),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn run_transparent_proxy(
    listen_host: &str,
    port: u16,
    is_enabled: bool,
    bypass_domains: Arc<HashSet<String>>,
    bypass_params: BypassParams,
    strategy_ttl_hours: u64,
    log_tx: LogSender,
    metrics: Arc<Metrics>,
    token: CancellationToken,
    ip_cache: Arc<IpDomainCache>,
    strategies: Arc<StrategyStore>,
) {
    let addr = format!("{}:{}", listen_host, port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            log_t(&log_tx, LogLevel::Error, "log.bind_error", vec![
                ("addr", addr.clone()),
                ("error", e.to_string()),
            ]);
            return;
        }
    };

    metrics.set_transparent_listening(true);
    log_t(&log_tx, LogLevel::Success, "log.transparent_listening", vec![("addr", addr.clone())]);

    // IPv6-слушатель необязателен: на машине без IPv6 он не поднимется,
    // и это не повод выключать IPv4-часть. Правило ip6tables в run.sh
    // тоже ставится только если получилось.
    let listener_v6 = match ipv6_companion(listen_host) {
        Some(host) => {
            let addr_v6 = format!("[{}]:{}", host, port);
            match TcpListener::bind(&addr_v6).await {
                Ok(l) => {
                    log_t(&log_tx, LogLevel::Success, "log.transparent_listening", vec![("addr", addr_v6)]);
                    Some(l)
                }
                Err(e) => {
                    log_t(&log_tx, LogLevel::Info, "log.transparent_ipv6_unavailable", vec![
                        ("addr", addr_v6),
                        ("error", e.to_string()),
                    ]);
                    None
                }
            }
        }
        None => None,
    };

    let serve = |listener: TcpListener| {
        let bypass_domains = Arc::clone(&bypass_domains);
        let bypass_params = bypass_params.clone();
        let log_tx = log_tx.clone();
        let metrics = Arc::clone(&metrics);
        let token = token.clone();
        let ip_cache = Arc::clone(&ip_cache);
        let strategies = Arc::clone(&strategies);
        async move {
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    accept_result = listener.accept() => {
                        match accept_result {
                            Ok((client, _peer)) => {
                                let bypass_domains = Arc::clone(&bypass_domains);
                                let bypass_params = bypass_params.clone();
                                let log_tx = log_tx.clone();
                                let metrics = Arc::clone(&metrics);
                                let ip_cache = Arc::clone(&ip_cache);
                                let strategies = Arc::clone(&strategies);
                                tokio::spawn(async move {
                                    metrics.conn_opened();
                                    handle(client, is_enabled, &bypass_domains, &bypass_params,
                                           strategy_ttl_hours, &log_tx, &metrics, &ip_cache, &strategies).await;
                                    metrics.conn_closed();
                                });
                            }
                            Err(e) => log_t(&log_tx, LogLevel::Error, "log.tcp_error", vec![("error", e.to_string())]),
                        }
                    }
                }
            }
        }
    };

    match listener_v6 {
        Some(v6) => { tokio::join!(serve(listener), serve(v6)); }
        None => serve(listener).await,
    }

    metrics.set_transparent_listening(false);
}

#[allow(clippy::too_many_arguments)]
async fn handle(
    mut client: TcpStream,
    is_enabled: bool,
    bypass_domains: &HashSet<String>,
    bypass_params: &BypassParams,
    strategy_ttl_hours: u64,
    log_tx: &LogSender,
    metrics: &Arc<Metrics>,
    ip_cache: &Arc<IpDomainCache>,
    strategies: &Arc<StrategyStore>,
) {
    // Куда клиент шёл на самом деле. Без этого перехваченное соединение
    // некуда переслать: peer_addr() показывает наш же порт.
    let Some(target_addr) = socket::original_dst(client.as_raw_fd()) else {
        log_t(log_tx, LogLevel::Warning, "log.transparent_no_dst", vec![]);
        return;
    };

    // Адрес Telegram — через ретранслятор, если он настроен. Раньше первого
    // чтения: по содержимому тут решать нечего, а клиент MTProto заговорит
    // сам, как только соединение пойдёт дальше.
    if super::telegram::is_telegram(target_addr.ip(), target_addr.port())
        && let Some(relay) = super::telegram::relay()
    {
        if let Err(e) = super::telegram::relay_connection(&mut client, &relay, target_addr.ip(), target_addr.port(), &[], log_tx, metrics).await {
            log_t(log_tx, LogLevel::Warning, "log.telegram_relay_error", vec![
                ("addr", target_addr.to_string()),
                ("error", e.to_string()),
            ]);
        }
        return;
    }

    // Первый пакет: для TLS это ClientHello, из которого достаём имя домена.
    // Собираем его целиком — SNI может лежать за границей первого сегмента.
    let mut payload: Vec<u8> = Vec::with_capacity(4096);
    {
        // Молчание клиента не повод держать соединение без пересылки вечно,
        // но и не повод его рвать: на 443 бывает и протокол, где первым
        // говорит сервер. По истечении срока соединение просто пересылается
        // как есть, без стратегии — обходить нечего, ClientHello нет.
        let mut buf = [0u8; 4096];
        match tokio::time::timeout(super::HANDSHAKE_TIMEOUT, client.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => return,
            Ok(Ok(n)) => payload.extend_from_slice(&buf[..n]),
            Err(_) => {}
        }
    }
    if super::handshake::complete_client_hello(&mut client, &mut payload).await
        == super::handshake::FirstPacket::Incomplete
    {
        log_t(log_tx, LogLevel::Warning, "log.clienthello_incomplete", vec![
            ("bytes", payload.len().to_string()),
        ]);
    }

    // Имя домена — из SNI. Если его нет (не TLS, подключение по IP,
    // зашифрованный ECH), спрашиваем кэш «адрес → домен», который наполняет
    // DoH-релей. Раньше этот запасной путь был только описан в комментарии:
    // ip_cache сюда вообще не передавался, и без SNI обход молча отключался,
    // хотя в HTTPS-туннеле такой же случай обрабатывался.
    let sni = crate::bypass::tls::sni_host(&payload);

    // SNI увиден — запоминаем «адрес → домен». Кроме DoH-релея, в который
    // системный DNS обычно не ходит, кэш больше никто не наполнял, и обход
    // QUIC (решение там принимается только по адресу) не включался никогда.
    // Браузер открывает сайт по TCP, а на QUIC переходит позже — к этому
    // моменту адрес уже опознан.
    if let Some(host) = &sni {
        ip_cache.insert(target_addr.ip(), host.clone());

        // Кэш выше заполнен и для трекера: по нему QUIC на тот же адрес
        // тоже будет отброшен. Блокируется только по SNI, не по кэшу — за
        // адресом трекера живут и другие сайты (см. модуль block).
        //
        // Сброс, а не закрытие: браузер сразу видит отказ и не повторяет
        // попытку по таймауту. До сервера соединение не доходит вовсе.
        if crate::block::is_blocked(host) {
            log_t(log_tx, LogLevel::Info, "log.blocked", vec![
                ("domain", host.clone()),
                ("via", "SNI".to_string()),
            ]);
            let _ = client.set_zero_linger();
            return;
        }
    }

    let from_cache = sni.is_none().then(|| ip_cache.lookup(&target_addr.ip())).flatten();
    if let Some(cached) = &from_cache
        && matches_list(cached, bypass_domains)
    {
        log_t(log_tx, LogLevel::Info, "log.transparent_bypass_via_ip", vec![
            ("ip", target_addr.ip().to_string()),
            ("domain", cached.clone()),
        ]);
    }

    // Последний запасной вариант — сам адрес. Берём именно ip(), а не разбор
    // строки "host:port": для IPv6 она выглядит как "[::1]:443", и деление
    // по первому двоеточию давало "[".
    let domain = sni
        .or(from_cache)
        .unwrap_or_else(|| target_addr.ip().to_string());

    let adaptive_ctx = crate::proxy::adaptive::Context {
        strategies, bypass_params, ttl_hours: strategy_ttl_hours, log_tx,
    };
    let selected = if !payload.is_empty() && needs_bypass(is_enabled, &domain, bypass_domains) {
        crate::proxy::adaptive::select(&adaptive_ctx, &domain, payload.len())
    } else {
        crate::proxy::adaptive::Selected::DIRECT
    };
    let strategy = selected.strategy;

    let started = std::time::Instant::now();
    // Имя сайта известно только из SNI или кэша; без него запасных адресов
    // не найти.
    let name = (domain.parse::<std::net::IpAddr>().is_err()).then_some(domain.as_str());
    let (server, target_addr) = match connect_with_fallback(target_addr, name, log_tx).await {
        Ok(pair) => {
            metrics.record_connect_ms(started.elapsed().as_secs_f64() * 1000.0);
            pair
        }
        Err(e) => {
            log_t(log_tx, LogLevel::Error, "log.https_connect_error", vec![
                ("target", target_addr.to_string()),
                ("error", e.to_string()),
            ]);
            return;
        }
    };

    let _ = client.set_nodelay(true);
    let _ = server.set_nodelay(true);

    log_t(log_tx, LogLevel::Success, "log.transparent_tunnel", vec![
        ("domain", domain.clone()),
        ("addr", target_addr.to_string()),
        ("bypass", (strategy != Strategy::None).to_string()),
    ]);

    let server_fd = server.as_raw_fd();
    let (mut client_reader, mut client_writer) = client.into_split();
    let (mut server_reader, mut server_writer) = server.into_split();

    // Первый пакет уходит по выбранной стратегии — здесь и происходит обход.
    match crate::engine::strategy::apply::first_packet(&mut server_writer, server_fd, &payload, strategy, bypass_params).await {
        Ok(applied) => {
            let detail = match applied {
                Applied::TlsRecord { bytes } => Some(format!("tls_record {}", bytes)),
                Applied::SniSplit { first, second } => Some(format!("sni_split {}+{}", first, second)),
                Applied::Split { first, second } => Some(format!("split {}+{}", first, second)),
                Applied::Disorder { first, second } => Some(format!("disorder {}+{}", first, second)),
                Applied::Oob { first, second } => Some(format!("oob {}+{}", first, second)),
                Applied::Fake { decoy, real } => Some(format!("fake {}+{}", decoy, real)),
                // Без обхода писать нечего: «bypass: false» уже есть в строке
                // перехвата выше. Иначе каждое постороннее соединение давало
                // лишнее предупреждение и топило в логе настоящие. Так же
                // сделано в HTTPS-туннеле.
                Applied::None => None,
            };
            if let Some(detail) = detail {
                log_t(log_tx, LogLevel::Warning, "log.transparent_applied", vec![
                    ("domain", domain.clone()),
                    ("detail", detail),
                ]);
            }
        }
        Err(_) => return,
    }

    metrics.add_rx(payload.len() as u64);

    let responded = Arc::new(AtomicBool::new(false));
    let responded_flag = Arc::clone(&responded);
    let metrics_s2c = Arc::clone(metrics);

    let to_client = async move {
        let mut buf = [0u8; 4096];
        let mut first = true;
        loop {
            match server_reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(len) => {
                    if first {
                        first = false;
                        responded_flag.store(true, Ordering::Relaxed);
                        metrics_s2c.record_ttfb_ms(started.elapsed().as_secs_f64() * 1000.0);
                    }
                    metrics_s2c.add_tx(len as u64);
                    if client_writer.write_all(&buf[..len]).await.is_err() {
                        break;
                    }
                }
            }
        }
        // Полузакрытие, а не обрыв: в HTTPS-туннеле это делалось, здесь — нет,
        // и вторая сторона висела до собственного таймаута.
        let _ = client_writer.shutdown().await;
    };

    let metrics_c2s = Arc::clone(metrics);
    let to_server = async move {
        let mut buf = [0u8; 4096];
        loop {
            match client_reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(len) => {
                    metrics_c2s.add_rx(len as u64);
                    if server_writer.write_all(&buf[..len]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = server_writer.shutdown().await;
    };

    let _ = tokio::join!(to_server, to_client);

    // Обратная связь по стратегии — та же, что в остальных режимах.
    crate::proxy::adaptive::record_outcome(&adaptive_ctx, &domain, selected, responded.load(Ordering::Relaxed));
}

/// Сколько помнить адрес, который не ответил на подключение.
const DEAD_ADDR_TTL: std::time::Duration = std::time::Duration::from_secs(600);

/// Адреса, которые недавно не ответили: `адрес → когда забыть`.
static DEAD_ADDRS: std::sync::Mutex<Option<std::collections::HashMap<std::net::IpAddr, std::time::Instant>>> =
    std::sync::Mutex::new(None);

fn is_dead(ip: std::net::IpAddr) -> bool {
    let Ok(mut guard) = DEAD_ADDRS.lock() else { return false };
    let map = guard.get_or_insert_with(Default::default);
    let now = std::time::Instant::now();
    map.retain(|_, until| *until > now);
    map.contains_key(&ip)
}

fn mark_dead(ip: std::net::IpAddr) {
    if let Ok(mut guard) = DEAD_ADDRS.lock() {
        guard.get_or_insert_with(Default::default).insert(ip, std::time::Instant::now() + DEAD_ADDR_TTL);
    }
}

/// Подключается к адресу, который выбрал браузер, а если тот не отвечает —
/// к другому адресу того же сайта.
///
/// В прозрачном режиме адрес выбирает не прокси, а браузер: берёт один из
/// DNS-ответа. У Discord часть адресов Cloudflare заблокирована по IP
/// (162.159.136.232 не отвечает на SYN), а DNS отдаёт адреса по кругу —
/// сайт то открывался, то нет. Обход DPI тут бессилен: пакеты до сервера
/// не доходят вовсе. Зато у сайта есть другие адреса, и они живы.
///
/// Мёртвый адрес запоминается на [`DEAD_ADDR_TTL`], чтобы следующие
/// соединения не ждали на нём таймаут каждое.
async fn connect_with_fallback(
    target: std::net::SocketAddr,
    name: Option<&str>,
    log_tx: &LogSender,
) -> std::io::Result<(TcpStream, std::net::SocketAddr)> {
    let first_error = if name.is_some() && is_dead(target.ip()) {
        std::io::Error::new(std::io::ErrorKind::TimedOut, format!("{target}: недавно не отвечал"))
    } else {
        // С таймаутом: без него недоступный сервер держал соединение около
        // двух минут, пока ядро повторяет SYN.
        match crate::dns::resolver::connect_addr(target).await {
            Ok(s) => return Ok((s, target)),
            Err(e) => {
                mark_dead(target.ip());
                e
            }
        }
    };
    let Some(name) = name else { return Err(first_error) };

    let Ok(addrs) = tokio::net::lookup_host((name, target.port())).await else {
        return Err(first_error);
    };
    // Только того же семейства: к IPv6 из IPv4-соединения (и наоборот)
    // может не быть маршрута.
    for addr in addrs.filter(|a| a.is_ipv4() == target.is_ipv4() && a.ip() != target.ip()) {
        if is_dead(addr.ip()) {
            continue;
        }
        match crate::dns::resolver::connect_addr(addr).await {
            Ok(s) => {
                log_t(log_tx, LogLevel::Info, "log.transparent_fallback_addr", vec![
                    ("domain", name.to_string()),
                    ("dead", target.ip().to_string()),
                    ("addr", addr.ip().to_string()),
                ]);
                return Ok((s, addr));
            }
            Err(_) => mark_dead(addr.ip()),
        }
    }
    Err(first_error)
}

#[cfg(test)]
mod dead_addr_tests {
    use super::*;

    #[test]
    fn remembers_dead_address_only() {
        let dead: std::net::IpAddr = "192.0.2.77".parse().unwrap();
        let alive: std::net::IpAddr = "192.0.2.78".parse().unwrap();
        mark_dead(dead);
        assert!(is_dead(dead));
        assert!(!is_dead(alive));
    }
}
