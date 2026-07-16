use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

use crate::cli::{LogSender, log_t, LogLevel};
use crate::metrics::Metrics;
use super::ip_cache::{IpDomainCache, extract_qname, extract_ips_from_dns_response};

pub async fn run_doh_relay(
    listen_address: String,
    doh_provider: String,
    log_tx: LogSender,
    metrics: Arc<Metrics>,
    token: CancellationToken,
    ip_cache: Arc<IpDomainCache>,
) {
    use tokio::net::UdpSocket;

    let socket = match UdpSocket::bind(&listen_address).await {
        Ok(s) => s,
        Err(e) => {
            log_t(&log_tx, LogLevel::Error, "log.bind_error", vec![("addr", listen_address.clone()), ("error", e.to_string())]);
            return;
        }
    };
    let socket = Arc::new(socket);

    log_t(&log_tx, LogLevel::Success, "log.doh_listening", vec![
        ("addr", listen_address.clone()),
          ("provider", doh_provider.clone()),
    ]);

    let client = reqwest::Client::builder()
    .timeout(Duration::from_secs(5))
    .build()
    .expect("Не удалось создать HTTP-клиент для DoH");

    let mut buffer = [0u8; 4096];
    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            recv_result = socket.recv_from(&mut buffer) => {
                match recv_result {
                    Ok((len, client_addr)) => {
                        let query = buffer[..len].to_vec();
                        let socket = Arc::clone(&socket);
                        let client = client.clone();
                        let doh_provider = doh_provider.clone();
                        let log_tx = log_tx.clone();
                        let metrics = Arc::clone(&metrics);
                        let ip_cache = Arc::clone(&ip_cache);

                        tokio::spawn(async move {
                            metrics.add_rx(query.len() as u64);

                            match resolve_via_doh(&client, &doh_provider, &query).await {
                                Ok(response) => {
                                    metrics.add_tx(response.len() as u64);

                                    if let Some(qname) = extract_qname(&query) {
                                        for ip in extract_ips_from_dns_response(&response) {
                                            ip_cache.insert(ip, qname.clone());
                                        }
                                    }

                                    let _ = socket.send_to(&response, client_addr).await;
                                }
                                Err(e) => {
                                    log_t(&log_tx, LogLevel::Warning, "log.doh_error", vec![("error", e)]);
                                }
                            }
                        });
                    }
                    Err(e) => {
                        log_t(&log_tx, LogLevel::Error, "log.udp_error", vec![("error", e.to_string())]);
                    }
                }
            }
        }
    }
}

async fn resolve_via_doh(client: &reqwest::Client, provider: &str, dns_query: &[u8]) -> Result<Vec<u8>, String> {
    let response = client
    .post(provider)
    .header("content-type", "application/dns-message")
    .header("accept", "application/dns-message")
    .body(dns_query.to_vec())
    .send()
    .await
    .map_err(|e| e.to_string())?;

    if !response.status().is_success() {
        return Err(format!("DoH HTTP status: {}", response.status()));
    }

    response.bytes().await
    .map(|b| b.to_vec())
    .map_err(|e| e.to_string())
}
