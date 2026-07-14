use std::collections::HashSet;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::{Ranges, BypassParams};
use crate::bypass::{extract_domain, needs_bypass, fragment};
use crate::cli::{LogSender, log_t, LogLevel};
use crate::metrics::Metrics;
use crate::dns::ip_cache::IpDomainCache;
use super::tcp::parse_connect_target;

pub async fn handle_connect(
    client_stream: TcpStream,
    request: &str,
    initial_payload: Vec<u8>,
    _ranges: Ranges,
    is_enabled: bool,
    bypass_domains: Arc<HashSet<String>>,
    bypass_params: BypassParams,
    log_tx: LogSender,
    metrics: Arc<Metrics>,
    ip_cache: Arc<IpDomainCache>,
) {
    let target = match parse_connect_target(request) {
        Some(t) => t,
        None => {
            log_t(&log_tx, LogLevel::Warning, "log.connect_parse_error", vec![]);
            return;
        }
    };

    let domain = extract_domain(&target);
    let mut needs = needs_bypass(is_enabled, &domain, &bypass_domains);

    let server_stream = match TcpStream::connect(&target).await {
        Ok(s) => s,
        Err(e) => {
            log_t(&log_tx, LogLevel::Error, "log.https_connect_error", vec![("target", target.clone()), ("error", e.to_string())]);
            let mut cs = client_stream;
            let _ = cs.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
            return;
        }
    };

    if is_enabled && !needs {
        if let Ok(peer) = server_stream.peer_addr() {
            if let Some(cached_domain) = ip_cache.lookup(&peer.ip()) {
                if bypass_domains.contains(&cached_domain) {
                    needs = true;
                    log_t(&log_tx, LogLevel::Info, "log.bypass_via_ip_cache", vec![
                        ("ip", peer.ip().to_string()),
                          ("domain", cached_domain),
                    ]);
                }
            }
        }
    }

    log_t(&log_tx, LogLevel::Success, "log.https_tunnel", vec![("target", target.clone()), ("bypass", needs.to_string())]);

    if needs {
        fragment::apply_window_clamp(&server_stream, bypass_params.window_clamp);
    }

    let _ = client_stream.set_nodelay(true);
    let _ = server_stream.set_nodelay(true);

    let mut client_stream = client_stream;
    if client_stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.is_err() {
        return;
    }

    let (mut client_reader, mut client_writer) = client_stream.into_split();
    let (mut server_reader, mut server_writer) = server_stream.into_split();

    let log_tx_c2s = log_tx.clone();
    let domain_c2s = domain.clone();
    let metrics_c2s = Arc::clone(&metrics);
    let client_to_server = async move {
        let mut buffer = [0u8; 4096];
        let mut is_first_packet = true;
        let mut leftover = initial_payload;

        loop {
            let data: &[u8];
            let bytes_read: usize;

            if !leftover.is_empty() {
                bytes_read = leftover.len();
                buffer[..bytes_read].copy_from_slice(&leftover);
                data = &buffer[..bytes_read];
                leftover.clear();
            } else {
                match client_reader.read(&mut buffer).await {
                    Ok(0) => {
                        let _ = server_writer.shutdown().await;
                        break;
                    }
                    Ok(n) => {
                        bytes_read = n;
                        data = &buffer[..bytes_read];
                    }
                    Err(_) => break,
                }
            }

            metrics_c2s.add_rx(bytes_read as u64);

            if needs && is_first_packet {
                if fragment::split_client_hello(&mut server_writer, data, &bypass_params).await.is_err() {
                    break;
                }
                log_t(&log_tx_c2s, LogLevel::Warning, "log.split_applied", vec![
                    ("first", bypass_params.split_pos.to_string()),
                      ("second", bytes_read.saturating_sub(bypass_params.split_pos).to_string()),
                      ("domain", domain_c2s.clone()),
                ]);
                is_first_packet = false;
            } else {
                if server_writer.write_all(data).await.is_err() { break; }
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

    let _ = tokio::join!(client_to_server, server_to_client);
}
