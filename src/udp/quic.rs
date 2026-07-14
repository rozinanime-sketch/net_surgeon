use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::cli::{LogSender, log_t, LogLevel};
use crate::metrics::Metrics;

struct UdpSession {
    socket: Arc<UdpSocket>,
    last_seen: Instant,
}

type SessionMap = Arc<Mutex<HashMap<SocketAddr, UdpSession>>>;

pub async fn run_udp_quic_proxy(
    listen_port: u16,
    target: String,
    log_tx: LogSender,
    metrics: Arc<Metrics>,
    token: CancellationToken,
) {
    let listen_addr = format!("0.0.0.0:{}", listen_port);
    let inbound = Arc::new(
        UdpSocket::bind(&listen_addr).await
        .expect("Не удалось занять UDP порт для QUIC"),
    );
    log_t(&log_tx, LogLevel::Success, "log.quic_listening", vec![("addr", listen_addr.clone()), ("target", target.clone())]);

    let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));

    {
        let sessions_gc = Arc::clone(&sessions);
        let log_tx = log_tx.clone();
        let metrics = Arc::clone(&metrics);
        let token = token.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                     _ = tokio::time::sleep(Duration::from_secs(30)) => {
                         let mut map = sessions_gc.lock().await;
                         let before = map.len();
                         map.retain(|_, s| s.last_seen.elapsed() < Duration::from_secs(60));
                         let removed = before - map.len();
                         if removed > 0 {
                             for _ in 0..removed {
                                 metrics.quic_session_closed();
                             }
                             log_t(&log_tx, LogLevel::Info, "log.quic_gc", vec![("count", removed.to_string())]);
                         }
                     }
                }
            }
        });
    }

    let mut buf = vec![0u8; 65535];
    loop {
        let (len, client_addr) = tokio::select! {
            _ = token.cancelled() => break,
            recv_result = inbound.recv_from(&mut buf) => {
                match recv_result {
                    Ok(v) => v,
                    Err(e) => { log_t(&log_tx, LogLevel::Error, "log.quic_recv_error", vec![("error", e.to_string())]); continue; }
                }
            }
        };

        let data = buf[..len].to_vec();
        let inbound_ref = Arc::clone(&inbound);
        let sessions_ref = Arc::clone(&sessions);
        let target = target.clone();
        let log_tx = log_tx.clone();
        let metrics = Arc::clone(&metrics);

        tokio::spawn(async move {
            let upstream = {
                let mut map = sessions_ref.lock().await;

                if let Some(session) = map.get_mut(&client_addr) {
                    session.last_seen = Instant::now();
                    Arc::clone(&session.socket)
                } else {
                    let sock = match UdpSocket::bind("0.0.0.0:0").await {
                        Ok(s) => Arc::new(s),
                     Err(e) => {
                         log_t(&log_tx, LogLevel::Error, "log.quic_socket_error", vec![("error", e.to_string())]);
                         return;
                     }
                    };

                    if let Err(e) = sock.connect(&target).await {
                        log_t(&log_tx, LogLevel::Error, "log.quic_connect_error", vec![("target", target.clone()), ("error", e.to_string())]);
                        return;
                    }

                    log_t(&log_tx, LogLevel::Info, "log.quic_session", vec![("addr", client_addr.to_string())]);
                    metrics.quic_session_opened();
                    metrics.set_quic_target_ok(true);

                    {
                        let fake_packet = crate::bypass::fragment::build_fake_quic_initial();

                        let delay: u64 = {
                            let mut rng = rand::rng();
                            use rand::prelude::*;
                            rng.random_range(15u64..=30u64)
                        };

                        log_t(&log_tx, LogLevel::Warning, "log.quic_fake_packet", vec![
                            ("bytes", fake_packet.len().to_string()),
                              ("target", target.clone()),
                        ]);
                        let _ = sock.send(&fake_packet).await;
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                    }

                    map.insert(client_addr, UdpSession {
                        socket: Arc::clone(&sock),
                               last_seen: Instant::now(),
                    });

                    {
                        let sock_back = Arc::clone(&sock);
                        let inbound_back = Arc::clone(&inbound_ref);
                        let log_tx = log_tx.clone();
                        let metrics = Arc::clone(&metrics);
                        tokio::spawn(async move {
                            let mut resp_buf = vec![0u8; 65535];
                            loop {
                                match tokio::time::timeout(
                                    Duration::from_secs(60),
                                                           sock_back.recv(&mut resp_buf),
                                ).await {
                                    Ok(Ok(n)) => {
                                        metrics.add_tx(n as u64);
                                        if let Err(e) = inbound_back
                                            .send_to(&resp_buf[..n], client_addr)
                                            .await
                                            {
                                                log_t(&log_tx, LogLevel::Error, "log.quic_send_error", vec![("addr", client_addr.to_string()), ("error", e.to_string())]);
                                                break;
                                            }
                                    }
                                    Ok(Err(e)) => {
                                        log_t(&log_tx, LogLevel::Error, "log.quic_upstream_recv_error", vec![("error", e.to_string())]);
                                        metrics.set_quic_target_ok(false);
                                        break;
                                    }
                                    Err(_) => break,
                                }
                            }
                        });
                    }

                    sock
                }
            };

            metrics.add_rx(data.len() as u64);
            if let Err(e) = upstream.send(&data).await {
                log_t(&log_tx, LogLevel::Error, "log.quic_upstream_send_error", vec![("addr", client_addr.to_string()), ("error", e.to_string())]);
                metrics.set_quic_target_ok(false);
            }
        });
    }
}
