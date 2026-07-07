use std::collections::HashSet;
use std::str;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::AsyncReadExt;

use crate::config::{Ranges, BypassParams};
use crate::cli::{LogSender, log_t, LogLevel};
use crate::metrics::Metrics;
use super::{http, https};

pub async fn run_tcp_proxy(
    listen_address: String,
    ranges: Ranges,
    is_enabled: bool,
    bypass_domains: Arc<HashSet<String>>,
    bypass_params: BypassParams,
    log_tx: LogSender,
    metrics: Arc<Metrics>,
) {
    let listener = TcpListener::bind(&listen_address).await
    .expect("Ошибка: не удалось занять TCP порт");

    log_t(&log_tx, LogLevel::Success, "log.tcp_listening", vec![("addr", listen_address.clone())]);

    loop {
        match listener.accept().await {
            Ok((client_stream, addr)) => {
                let _ = addr;
                let ranges_clone = ranges.clone();
                let bypass_clone = Arc::clone(&bypass_domains);
                let bypass_params_clone = bypass_params.clone();
                let log_tx = log_tx.clone();
                let metrics = Arc::clone(&metrics);
                tokio::spawn(async move {
                    metrics.conn_opened();
                    handle_connection(client_stream, ranges_clone, is_enabled, bypass_clone, bypass_params_clone, log_tx, Arc::clone(&metrics)).await;
                    metrics.conn_closed();
                });
            }
            Err(e) => log_t(&log_tx, LogLevel::Error, "log.tcp_error", vec![("error", e.to_string())]),
        }
    }
}

#[allow(unused_assignments)]
async fn handle_connection(
    mut client_stream: TcpStream,
    ranges: Ranges,
    is_enabled: bool,
    bypass_domains: Arc<HashSet<String>>,
    bypass_params: BypassParams,
    log_tx: LogSender,
    metrics: Arc<Metrics>,
) {
    let mut buffer = [0u8; 8192];
    let mut total_read = 0;
    let mut header_end_idx: Option<usize> = None;

    loop {
        match client_stream.read(&mut buffer[total_read..]).await {
            Ok(0) => return,
            Ok(n) => {
                total_read += n;
                let current_slice = &buffer[..total_read];
                if let Some(pos) = current_slice.windows(4).position(|w| w == b"\r\n\r\n") {
                    header_end_idx = Some(pos + 4);
                    break;
                }
                if total_read >= buffer.len() {
                    return;
                }
            }
            Err(_) => return,
        }
    }

    let end_idx = match header_end_idx {
        Some(idx) => idx,
        None => return,
    };

    let request = match str::from_utf8(&buffer[..end_idx]) {
        Ok(r) => r.to_string(),
        Err(_) => return,
    };

    if request.starts_with("CONNECT") {
        let initial_payload = buffer[end_idx..total_read].to_vec();
        https::handle_connect(client_stream, &request, initial_payload, ranges, is_enabled, bypass_domains, bypass_params, log_tx, metrics).await;
    } else {
        http::handle_http(client_stream, &request, &buffer[..total_read], ranges, is_enabled, bypass_domains, log_tx, metrics).await;
    }
}

pub fn parse_connect_target(request: &str) -> Option<String> {
    let line = request.lines().next()?;
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() >= 2 {
        Some(parts[1].to_string())
    } else {
        None
    }
}

pub fn parse_http_target(request: &str) -> Option<String> {
    for line in request.lines() {
        if line.to_lowercase().starts_with("host:") {
            let host = line[5..].trim().to_string();
            if host.contains(':') {
                return Some(host);
            } else {
                return Some(format!("{}:80", host));
            }
        }
    }
    None
}
