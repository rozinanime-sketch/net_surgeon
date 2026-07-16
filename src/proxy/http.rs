use std::collections::HashSet;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::Ranges;
use crate::bypass::{extract_domain, needs_bypass, fragment};
use crate::cli::{LogSender, log_t, LogLevel};
use crate::metrics::Metrics;
use super::tcp::parse_http_target;

pub async fn handle_http(
    client_stream: TcpStream,
    request_str: &str,
    raw_request: &[u8],
    ranges: Ranges,
    is_enabled: bool,
    bypass_domains: Arc<HashSet<String>>,
    log_tx: LogSender,
    metrics: Arc<Metrics>,
) {
    let target = match parse_http_target(request_str) {
        Some(t) => t,
        None => {
            log_t(&log_tx, LogLevel::Warning, "log.http_host_error", vec![]);
            return;
        }
    };

    let domain = extract_domain(&target);
    let bypass = needs_bypass(is_enabled, &domain, &bypass_domains);

    let mut server_stream = match TcpStream::connect(&target).await {
        Ok(s) => s,
        Err(e) => {
            log_t(&log_tx, LogLevel::Error, "log.http_connect_error", vec![("target", target.clone()), ("error", e.to_string())]);
            return;
        }
    };

    log_t(&log_tx, LogLevel::Success, "log.http_request", vec![("target", target.clone()), ("bypass", bypass.to_string())]);

    if bypass {
        let request_bytes = request_str.as_bytes();
        metrics.add_rx(request_bytes.len() as u64);

        if fragment::fragment_http_request(&mut server_stream, request_bytes, &ranges).await.is_err() {
            return;
        }

        // Буфер в tcp.rs мог прочитать не только заголовки, но и начало тела запроса
        // (например POST-формы) — если это тело потерять, сервер зависнет по таймауту
        // ожидая данные, которые уже пришли, но были отброшены.
        if raw_request.len() > request_bytes.len() {
            let leftover = &raw_request[request_bytes.len()..];
            metrics.add_rx(leftover.len() as u64);
            if server_stream.write_all(leftover).await.is_err() {
                return;
            }
        }
    } else {
        metrics.add_rx(raw_request.len() as u64);
        if server_stream.write_all(raw_request).await.is_err() { return; }
        let _ = server_stream.flush().await;
    }

    let (mut client_reader, mut client_writer) = client_stream.into_split();
    let (mut server_reader, mut server_writer) = server_stream.into_split();

    let metrics_c2s = Arc::clone(&metrics);
    let client_to_server = async move {
        let mut buffer = [0u8; 4096];
        loop {
            match client_reader.read(&mut buffer).await {
                Ok(0) => {
                    // Клиент закончил передачу — сигналим серверу через half-close,
                    // но не рвём соединение целиком, сервер может ещё отвечать
                    let _ = server_writer.shutdown().await;
                    break;
                }
                Ok(bytes_read) => {
                    metrics_c2s.add_rx(bytes_read as u64);
                    if server_writer.write_all(&buffer[..bytes_read]).await.is_err() { break; }
                }
                Err(_) => break,
            }
        }
    };

    let metrics_s2c = Arc::clone(&metrics);
    let server_to_client = async move {
        let mut buffer = [0u8; 4096];
        loop {
            match server_reader.read(&mut buffer).await {
                Ok(0) => {
                    let _ = client_writer.shutdown().await;
                    break;
                }
                Ok(bytes_read) => {
                    let data = &buffer[..bytes_read];
                    metrics_s2c.add_tx(bytes_read as u64);
                    if client_writer.write_all(data).await.is_err() { break; }
                }
                Err(_) => break,
            }
        }
    };

    // join вместо select — обе стороны докручиваются до конца, а не рвутся
    // как только одна из них первой отдала Ok(0)
    let _ = tokio::join!(client_to_server, server_to_client);
}
