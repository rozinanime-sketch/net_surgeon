use std::collections::HashSet;
use std::str;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;

use crate::config::BypassParams;
use crate::observability::logging::{LogSender, log_t, LogLevel};
use crate::observability::metrics::Metrics;
use crate::dns::ip_cache::IpDomainCache;
use crate::engine::strategy::StrategyStore;
use super::{http, https};

// Парсеры адресов живут в `protocol` — чистые функции над байтами, общие
// для прокси и тестов. Здесь только реэкспорт, чтобы http.rs/https.rs
// не тянули путь через весь крейт.
pub use crate::protocol::http::{parse_connect_target, parse_http_target};

#[allow(clippy::too_many_arguments)]
pub async fn run_tcp_proxy(
    listen_address: String,
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
    let listener = match TcpListener::bind(&listen_address).await {
        Ok(l) => l,
        Err(e) => {
            log_t(&log_tx, LogLevel::Error, "log.bind_error", vec![("addr", listen_address.clone()), ("error", e.to_string())]);
            return;
        }
    };

    metrics.set_tcp_listening(true);
    log_t(&log_tx, LogLevel::Success, "log.tcp_listening", vec![("addr", listen_address.clone())]);

    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((client_stream, _addr)) => {

                        let bypass_clone = Arc::clone(&bypass_domains);
                        let bypass_params_clone = bypass_params.clone();
                        let log_tx = log_tx.clone();
                        let metrics = Arc::clone(&metrics);
                        let ip_cache = Arc::clone(&ip_cache);
                        let strategies = Arc::clone(&strategies);
                        tokio::spawn(async move {
                            metrics.conn_opened();
                            handle_connection(client_stream, is_enabled, bypass_clone, bypass_params_clone, strategy_ttl_hours, log_tx, Arc::clone(&metrics), ip_cache, strategies).await;
                            metrics.conn_closed();
                        });
                    }
                    Err(e) => log_t(&log_tx, LogLevel::Error, "log.tcp_error", vec![("error", e.to_string())]),
                }
            }
        }
    }

    metrics.set_tcp_listening(false);
}

#[allow(clippy::too_many_arguments)]
#[allow(unused_assignments)]
async fn handle_connection(
    mut client_stream: TcpStream,
    is_enabled: bool,
    bypass_domains: Arc<HashSet<String>>,
    bypass_params: BypassParams,
    strategy_ttl_hours: u64,
    log_tx: LogSender,
    metrics: Arc<Metrics>,
    ip_cache: Arc<IpDomainCache>,
    strategies: Arc<StrategyStore>,
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
                if total_read >= buffer.len() { return; }
            }
            Err(_) => return,
        }
    }

    let end_idx = match header_end_idx { Some(idx) => idx, None => return };

    let request = match str::from_utf8(&buffer[..end_idx]) {
        Ok(r) => r.to_string(),
        Err(_) => return,
    };

    if request.starts_with("CONNECT") {
        let initial_payload = buffer[end_idx..total_read].to_vec();
        https::handle_connect(client_stream, &request, initial_payload, is_enabled, bypass_domains, bypass_params, strategy_ttl_hours, log_tx, metrics, ip_cache, strategies).await;
    } else {
        http::handle_http(client_stream, &request, &buffer[end_idx..total_read], is_enabled, bypass_domains, log_tx, metrics).await;
    }
}
