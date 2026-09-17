use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::BypassParams;
use crate::bypass::{extract_domain, matches_list, needs_bypass, fragment};
use crate::observability::logging::{LogSender, log_t, LogLevel};
use crate::observability::metrics::Metrics;
use crate::dns::ip_cache::IpDomainCache;
use crate::engine::strategy::{apply::Applied, Strategy, StrategyStore};
use super::tcp::parse_connect_target;
use super::adaptive::Selected;

#[allow(clippy::too_many_arguments)]
pub async fn handle_connect(
    client_stream: TcpStream,
    request: &str,
    initial_payload: Vec<u8>,
    is_enabled: bool,
    bypass_domains: Arc<HashSet<String>>,
    bypass_params: BypassParams,
    strategy_ttl_hours: u64,
    log_tx: LogSender,
    metrics: Arc<Metrics>,
    ip_cache: Arc<IpDomainCache>,
    strategies: Arc<StrategyStore>,
) {
    let target = match parse_connect_target(request) {
        Some(t) => t,
        None => {
            log_t(&log_tx, LogLevel::Warning, "log.connect_parse_error", vec![]);
            return;
        }
    };

    let mut domain = extract_domain(&target);
    let mut needs = needs_bypass(is_enabled, &domain, &bypass_domains);

    // Отсчёт с момента начала подключения: TTFB считается от него, потому что
    // пользователя интересует полное время до первых данных, а не только
    // время после установки соединения.
    let started = Instant::now();

    let server_stream = match crate::dns::resolver::connect(&target).await {
        Ok(s) => {
            metrics.record_connect_ms(started.elapsed().as_secs_f64() * 1000.0);
            s
        }
        Err(e) => {
            log_t(&log_tx, LogLevel::Error, "log.https_connect_error", vec![("target", target.clone()), ("error", e.to_string())]);
            let mut cs = client_stream;
            let _ = cs.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
            return;
        }
    };

    if is_enabled
        && !needs
        && let Ok(peer) = server_stream.peer_addr()
        && let Some(cached_domain) = ip_cache.lookup(&peer.ip())
        // Тоже по суффиксу: DoH мог зарезолвить поддомен вроде
        // rr3---sn-....googlevideo.com, которого нет в списке дословно.
        && matches_list(&cached_domain, &bypass_domains)
    {
        needs = true;
        log_t(&log_tx, LogLevel::Info, "log.bypass_via_ip_cache", vec![
            ("ip", peer.ip().to_string()),
            ("domain", cached_domain.clone()),
        ]);
        // Дальше стратегия выбирается и оценивается по домену из кэша. Раньше
        // здесь оставалась строка с IP: записей под IP в strategies.txt нет,
        // и измеренная для домена стратегия не применялась никогда.
        domain = cached_domain;
    }

    log_t(&log_tx, LogLevel::Success, "log.https_tunnel", vec![("target", target.clone()), ("bypass", needs.to_string())]);

    // Clamp — независимая от стратегии настройка (действует на ОТВЕТ сервера),
    // поэтому применяется по значению в конфиге, а не по типу обхода. 0 = выкл.
    if needs && bypass_params.window_clamp > 0 {
        let ok = fragment::apply_window_clamp(&server_stream, bypass_params.window_clamp);
        if ok {
            log_t(&log_tx, LogLevel::Info, "log.window_clamp", vec![("window", bypass_params.window_clamp.to_string())]);
        } else {
            log_t(&log_tx, LogLevel::Warning, "log.window_clamp_failed", vec![("window", bypass_params.window_clamp.to_string())]);
        }
    }

    let _ = client_stream.set_nodelay(true);
    let _ = server_stream.set_nodelay(true);

    let mut client_stream = client_stream;
    if client_stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.is_err() {
        return;
    }

    // Дескриптор до разделения: disorder и oob работают с сокетом напрямую.
    let server_fd = {
        use std::os::fd::AsRawFd;
        server_stream.as_raw_fd()
    };

    let (mut client_reader, mut client_writer) = client_stream.into_split();
    let (mut server_reader, mut server_writer) = server_stream.into_split();

    let log_tx_c2s = log_tx.clone();
    let domain_c2s = domain.clone();
    let metrics_c2s = Arc::clone(&metrics);
    let strategies_c2s = Arc::clone(&strategies);
    let bypass_params_c2s = bypass_params.clone();
    let client_to_server = async move {
        // Первый пакет собирается ЦЕЛИКОМ и только потом уходит по стратегии.
        // Часть его могла прийти в одном сегменте с CONNECT (initial_payload),
        // остальное дочитывается по длине из заголовка TLS-записи.
        let mut first = initial_payload;
        if first.is_empty() {
            let mut buffer = [0u8; 4096];
            match client_reader.read(&mut buffer).await {
                Ok(0) | Err(_) => { let _ = server_writer.shutdown().await; return Selected::DIRECT; }
                Ok(n) => first.extend_from_slice(&buffer[..n]),
            }
        }

        if needs
            && super::handshake::complete_client_hello(&mut client_reader, &mut first).await
                == super::handshake::FirstPacket::Incomplete
        {
            log_t(&log_tx_c2s, LogLevel::Warning, "log.clienthello_incomplete", vec![
                ("bytes", first.len().to_string()),
            ]);
        }

        // Стратегия выбирается здесь, а не до ответа клиенту: она зависит
        // от размера ClientHello, а его до этого момента не видно.
        let selected = if needs {
            let ctx = super::adaptive::Context {
                strategies: &strategies_c2s,
                bypass_params: &bypass_params_c2s,
                ttl_hours: strategy_ttl_hours,
                log_tx: &log_tx_c2s,
            };
            super::adaptive::select(&ctx, &domain_c2s, first.len())
        } else {
            Selected::DIRECT
        };
        let strategy = selected.strategy;

        metrics_c2s.add_rx(first.len() as u64);

        if strategy != Strategy::None {
            // Первый пакет — ClientHello, единственное место, где стратегия
            // что-то меняет. Логика применения общая с SOCKS5-путём
            // (strategy::apply), чтобы два пути не разъезжались.
            match crate::engine::strategy::apply::first_packet(&mut server_writer, server_fd, &first, strategy, &bypass_params_c2s).await {
                Ok(applied) => {
                    match applied {
                        Applied::TlsRecord { bytes } => log_t(&log_tx_c2s, LogLevel::Warning, "log.tls_record_applied", vec![
                            ("bytes", bytes.to_string()),
                            ("domain", domain_c2s.clone()),
                        ]),
                        Applied::SniSplit { first, second } => log_t(&log_tx_c2s, LogLevel::Warning, "log.sni_split_applied", vec![
                            ("first", first.to_string()),
                            ("second", second.to_string()),
                            ("domain", domain_c2s.clone()),
                        ]),
                        Applied::Split { first, second } => log_t(&log_tx_c2s, LogLevel::Warning, "log.split_applied", vec![
                            ("first", first.to_string()),
                            ("second", second.to_string()),
                            ("domain", domain_c2s.clone()),
                        ]),
                        Applied::Disorder { first, second } => log_t(&log_tx_c2s, LogLevel::Warning, "log.disorder_applied", vec![
                            ("first", first.to_string()),
                            ("second", second.to_string()),
                            ("domain", domain_c2s.clone()),
                        ]),
                        Applied::Oob { first, second } => log_t(&log_tx_c2s, LogLevel::Warning, "log.oob_applied", vec![
                            ("first", first.to_string()),
                            ("second", second.to_string()),
                            ("domain", domain_c2s.clone()),
                        ]),
                        Applied::Fake { decoy, real } => log_t(&log_tx_c2s, LogLevel::Warning, "log.fake_applied", vec![
                            ("decoy", decoy.to_string()),
                            ("real", real.to_string()),
                            ("domain", domain_c2s.clone()),
                        ]),
                        Applied::None => {}
                    }
                }
                Err(_) => return selected,
            }
        } else if server_writer.write_all(&first).await.is_err() {
            return selected;
        }

        // Дальше стратегия уже ни при чём — обычное перекладывание байт.
        let mut buffer = [0u8; 4096];
        loop {
            match client_reader.read(&mut buffer).await {
                Ok(0) => { let _ = server_writer.shutdown().await; break; }
                Ok(n) => {
                    metrics_c2s.add_rx(n as u64);
                    if server_writer.write_all(&buffer[..n]).await.is_err() { break; }
                }
                Err(_) => break,
            }
        }
        selected
    };

    // Ответил ли сервер хоть чем-то. Это и есть проверка стратегии в бою:
    // если DPI режет по SNI, до первого байта дело не доходит.
    let responded = Arc::new(AtomicBool::new(false));

    let metrics_s2c = Arc::clone(&metrics);
    let responded_s2c = Arc::clone(&responded);
    let server_to_client = async move {
        let mut buffer = [0u8; 4096];
        let mut first_byte_seen = false;
        loop {
            match server_reader.read(&mut buffer).await {
                Ok(0) => { let _ = client_writer.shutdown().await; break; }
                Ok(bytes_read) => {
                    if !first_byte_seen {
                        first_byte_seen = true;
                        responded_s2c.store(true, Ordering::Relaxed);
                        // TTFB: сервер реально ответил. Если DPI режет по SNI,
                        // сюда мы просто никогда не попадём — и замер не появится,
                        // что само по себе сигнал.
                        metrics_s2c.record_ttfb_ms(started.elapsed().as_secs_f64() * 1000.0);
                    }
                    let data = &buffer[..bytes_read];
                    metrics_s2c.add_tx(bytes_read as u64);
                    if client_writer.write_all(data).await.is_err() { break; }
                }
                Err(_) => break,
            }
        }
    };

    let (selected, _) = tokio::join!(client_to_server, server_to_client);

    // Обратная связь по применённой стратегии. Раньше решение принималось
    // по нескольким пробам и дальше жило сутки без единой проверки.
    let ctx = super::adaptive::Context {
        strategies: &strategies,
        bypass_params: &bypass_params,
        ttl_hours: strategy_ttl_hours,
        log_tx: &log_tx,
    };
    super::adaptive::record_outcome(&ctx, &domain, selected, responded.load(Ordering::Relaxed));
}
