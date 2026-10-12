use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

use crate::observability::logging::{LogSender, log_t, LogLevel};
use crate::observability::metrics::Metrics;
use super::ip_cache::{IpDomainCache, extract_qname, extract_ips_from_dns_response, nxdomain_response, servfail_response};

#[allow(clippy::too_many_arguments)]
pub async fn run_doh_relay(
    listen_address: String,
    doh_provider: String,
    bootstrap: Option<std::net::IpAddr>,
    smart_provider: String,
    smart_bootstrap: Option<std::net::IpAddr>,
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

    // Раньше здесь был .expect(): падение сборки HTTP-клиента паниковало внутри
    // спавнутой задачи, то есть DoH-релей молча умирал, а TUI продолжал показывать
    // его как работающий. «Слушает» — только после клиента, по той же причине.
    let client = match super::doh_client(&doh_provider, bootstrap, Duration::from_secs(5)) {
        Ok(c) => c,
        Err(e) => {
            log_t(&log_tx, LogLevel::Error, "log.doh_client_error", vec![("error", e.to_string())]);
            return;
        }
    };

    metrics.set_udp_listening(true);
    log_t(&log_tx, LogLevel::Success, "log.doh_listening", vec![
        ("addr", listen_address.clone()),
        ("provider", doh_provider.clone()),
    ]);

    // Умный DNS — только для имён из smart_dns_domains.txt (см. dns::smart).
    // Не собрался клиент — работаем без него: все имена идут основным путём.
    let smart = if smart_provider.is_empty() {
        None
    } else {
        match super::doh_client(&smart_provider, smart_bootstrap, Duration::from_secs(5)) {
            Ok(c) => Some((c, Arc::new(smart_provider))),
            Err(e) => {
                log_t(&log_tx, LogLevel::Error, "log.doh_client_error", vec![("error", e.to_string())]);
                None
            }
        }
    };

    // Второй сокет — на IPv6 той же петли: перехват (src/firewall.rs)
    // заворачивает сюда и DNS к IPv6-резолверам. Не поднялся — не беда,
    // IPv4 работает и без него.
    let socket_v6 = match ipv6_companion(&listen_address) {
        Some(addr) => match bind_v6_only(addr) {
            Ok(s) => Some(Arc::new(s)),
            Err(e) => {
                log_t(&log_tx, LogLevel::Info, "log.transparent_ipv6_unavailable", vec![
                    ("addr", addr.to_string()),
                    ("error", e.to_string()),
                ]);
                None
            }
        },
        None => None,
    };

    // 65535, а не 4096: recv_from не сообщает об усечении — лишние байты
    // просто пропадают, и запрос уходит провайдеру обрезанным.
    let mut buffer = [0u8; 65535];
    let mut buffer_v6 = [0u8; 65535];
    loop {
        let recv_v6 = async {
            match &socket_v6 {
                Some(s) => s.recv_from(&mut buffer_v6).await.map(|(len, from)| (buffer_v6[..len].to_vec(), from, Arc::clone(s))),
                None => std::future::pending().await,
            }
        };
        let recv_v4 = async {
            socket.recv_from(&mut buffer).await.map(|(len, from)| (buffer[..len].to_vec(), from, Arc::clone(&socket)))
        };
        tokio::select! {
            _ = token.cancelled() => break,
            recv_result = async { tokio::select! { r = recv_v4 => r, r = recv_v6 => r } } => {
                match recv_result {
                    Ok((query, client_addr, socket)) => {
                        let client = client.clone();
                        let doh_provider = doh_provider.clone();
                        let log_tx = log_tx.clone();
                        let metrics = Arc::clone(&metrics);
                        let ip_cache = Arc::clone(&ip_cache);
                        let smart = smart.clone();

                        tokio::spawn(async move {
                            metrics.add_rx(query.len() as u64);
                            // Трекер получает «такого домена нет» сразу, без
                            // похода к провайдеру: соединения не будет вовсе.
                            if let Some(qname) = extract_qname(&query)
                                && crate::block::is_blocked(&qname)
                                && let Some(response) = nxdomain_response(&query)
                            {
                                log_t(&log_tx, LogLevel::Info, "log.blocked", vec![
                                    ("domain", qname),
                                    ("via", "DNS".to_string()),
                                ]);
                                metrics.add_tx(response.len() as u64);
                                let _ = socket.send_to(&response, client_addr).await;
                                return;
                            }
                            // Индикатор DNS в интерфейсе теперь отражает СВОЙ
                            // резолв, а не чужой. Раньше его выставляла проба
                            // простого UDP-релея; тот удалён, и без этой строки
                            // панель вечно показывала бы OK, ничего не измеряя.
                            let qname = extract_qname(&query);
                            let via_smart = smart.as_ref().filter(|_| {
                                qname.as_deref().is_some_and(super::smart::matches)
                            });
                            // Ответ умного DNS — общий адрес его прокси для
                            // всех имён списка: в кэш «адрес → домен» он не
                            // идёт, там осталось бы последнее имя, и соединение
                            // по адресу получило бы чужой домен и стратегию.
                            let mut from_smart = false;
                            let result = match via_smart {
                                Some((smart_client, smart_provider)) => {
                                    match resolve_via_doh(smart_client, smart_provider, &query).await {
                                        Ok(r) => {
                                            from_smart = true;
                                            Ok(r)
                                        }
                                        // Умный DNS не ответил — лучше настоящий
                                        // адрес от основного провайдера, чем никакого:
                                        // сервис хотя бы скажет, что закрыт по стране.
                                        Err(e) => {
                                            log_t(&log_tx, LogLevel::Warning, "log.smart_dns_error", vec![
                                                ("domain", qname.clone().unwrap_or_default()),
                                                ("error", e),
                                            ]);
                                            resolve_via_doh(&client, &doh_provider, &query).await
                                        }
                                    }
                                }
                                None => resolve_via_doh(&client, &doh_provider, &query).await,
                            };
                            match result {
                                Ok(response) => {
                                    metrics.set_dns_ok(true);
                                    metrics.add_tx(response.len() as u64);
                                    if let Some(qname) = qname.filter(|_| !from_smart) {
                                        for ip in extract_ips_from_dns_response(&response) {
                                            ip_cache.insert(ip, qname.clone());
                                        }
                                    }
                                    let _ = socket.send_to(&response, client_addr).await;
                                }
                                // SERVFAIL, а не молчание: иначе клиент ждал
                                // свой таймаут (~5 с) на каждый запрос, прежде
                                // чем идти к следующему серверу.
                                Err(e) => {
                                    metrics.set_dns_ok(false);
                                    log_t(&log_tx, LogLevel::Warning, "log.doh_error", vec![("error", e)]);
                                    if let Some(response) = servfail_response(&query) {
                                        metrics.add_tx(response.len() as u64);
                                        let _ = socket.send_to(&response, client_addr).await;
                                    }
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

    metrics.set_udp_listening(false);
}

/// Адрес IPv6-сокета рядом с `listen_address`: петля к петле, «все адреса»
/// к «всем адресам». Иначе — нет.
fn ipv6_companion(listen_address: &str) -> Option<std::net::SocketAddr> {
    let (host, port) = listen_address.rsplit_once(':')?;
    let port = port.parse().ok()?;
    let ip: std::net::IpAddr = match host {
        "127.0.0.1" | "localhost" => std::net::Ipv6Addr::LOCALHOST.into(),
        "0.0.0.0" => std::net::Ipv6Addr::UNSPECIFIED.into(),
        _ => return None,
    };
    Some(std::net::SocketAddr::new(ip, port))
}

/// UDP только на IPv6: обычный bind `[::]` в Linux претендует и на IPv4 и
/// не встал бы рядом с `0.0.0.0` на том же порту.
fn bind_v6_only(addr: std::net::SocketAddr) -> std::io::Result<tokio::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    tokio::net::UdpSocket::from_std(socket.into())
}

async fn resolve_via_doh(client: &reqwest::Client, provider: &str, dns_query: &[u8]) -> Result<Vec<u8>, String> {
    let response = super::post_dns(client, provider, dns_query)
        .await
        .map_err(|e| super::error_chain(&e))?;

    if !response.status().is_success() {
        return Err(format!("DoH HTTP status: {}", response.status()));
    }

    response.bytes().await.map(|b| b.to_vec()).map_err(|e| super::error_chain(&e))
}
