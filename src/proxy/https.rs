use std::collections::HashSet;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::{Ranges, BypassParams};
use crate::bypass::{extract_domain, needs_bypass, fragment};
use crate::cli::{LogSender, log, LogLevel};
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
) {
    let target = match parse_connect_target(request) {
        Some(t) => t,
        None => {
            log(&log_tx, LogLevel::Warning, "Не удалось распарсить CONNECT");
            return;
        }
    };

    let domain = extract_domain(&target);
    let needs = needs_bypass(is_enabled, &domain, &bypass_domains);

    let server_stream = match TcpStream::connect(&target).await {
        Ok(s) => s,
        Err(e) => {
            log(&log_tx, LogLevel::Error, format!("Ошибка подключения к {}: {}", target, e));
            let mut cs = client_stream;
            let _ = cs.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
            return;
        }
    };

    log(&log_tx, LogLevel::Success, format!("HTTPS туннель: {} (bypass: {})", target, needs));

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
                    Ok(0) => break,
                    Ok(n) => {
                        bytes_read = n;
                        data = &buffer[..bytes_read];
                    }
                    Err(_) => break,
                }
            }

            if needs && is_first_packet {
                if fragment::split_client_hello(&mut server_writer, data, &bypass_params).await.is_err() {
                    break;
                }
                log(&log_tx_c2s, LogLevel::Warning, format!("SPLIT {}+{} байт -> {}", bypass_params.split_pos, bytes_read.saturating_sub(bypass_params.split_pos), domain_c2s));
                is_first_packet = false;
            } else {
                if server_writer.write_all(data).await.is_err() { break; }
            }
        }
    };

    let server_to_client = async move {
        let mut buffer = [0u8; 4096];
        loop {
            match server_reader.read(&mut buffer).await {
                Ok(0) => break,
                Ok(bytes_read) => {
                    let data = &buffer[..bytes_read];
                    if client_writer.write_all(data).await.is_err() { break; }
                }
                Err(_) => break,
            }
        }
    };

    tokio::select! {
        _ = client_to_server => {},
        _ = server_to_client => {},
    }
    log(&log_tx, LogLevel::Info, format!("HTTPS туннель закрыт: {}", target));
}
