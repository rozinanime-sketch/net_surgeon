#![allow(dead_code)]
use quinn::{Connection, Endpoint, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use rand::prelude::*;

use crate::cli::{LogSender, log, LogLevel};
use crate::metrics::Metrics;

fn generate_self_signed_cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap();
    (cert_der, key_der)
}

fn make_server_config() -> ServerConfig {
    let (cert, key) = generate_self_signed_cert();
    let mut tls_config = rustls::ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)
    .unwrap();
    tls_config.alpn_protocols = vec![b"hq-29".to_vec(), b"h3".to_vec()];
    ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config).unwrap(),
    ))
}

struct UdpSession {
    socket: Arc<UdpSocket>,
    last_seen: Instant,
}

type SessionMap = Arc<Mutex<HashMap<SocketAddr, UdpSession>>>;

pub async fn run_udp_quic_proxy(listen_port: u16, target: String, log_tx: LogSender, metrics: Arc<Metrics>) {
    let listen_addr = format!("0.0.0.0:{}", listen_port);
    let inbound = Arc::new(
        UdpSocket::bind(&listen_addr).await
        .expect("Не удалось занять UDP порт для QUIC"),
    );
    log(&log_tx, LogLevel::Success, format!("UDP/QUIC прокси слушает: {} -> {}", listen_addr, target));

    let sessions: SessionMap = Arc::new(Mutex::new(HashMap::new()));

    {
        let sessions_gc = Arc::clone(&sessions);
        let log_tx = log_tx.clone();
        let metrics = Arc::clone(&metrics);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(30)).await;
                let mut map = sessions_gc.lock().await;
                let before = map.len();
                map.retain(|_, s| s.last_seen.elapsed() < Duration::from_secs(60));
                let removed = before - map.len();
                if removed > 0 {
                    for _ in 0..removed {
                        metrics.quic_session_closed();
                    }
                    log(&log_tx, LogLevel::Info, format!("QUIC GC: удалено {} протухших сессий", removed));
                }
            }
        });
    }

    let mut buf = vec![0u8; 65535];
    loop {
        let (len, client_addr) = match inbound.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => { log(&log_tx, LogLevel::Error, format!("UDP recv ошибка: {}", e)); continue; }
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
                         log(&log_tx, LogLevel::Error, format!("Не удалось создать upstream сокет: {}", e));
                         metrics.set_quic_target_ok(false);
                         return;
                     }
                    };

                    if let Err(e) = sock.connect(&target).await {
                        log(&log_tx, LogLevel::Error, format!("UDP connect к {} провалился: {}", target, e));
                        metrics.set_quic_target_ok(false);
                        return;
                    }

                    log(&log_tx, LogLevel::Info, format!("QUIC сессия: {}", client_addr));
                    metrics.quic_session_opened();
                    metrics.set_quic_target_ok(true);

                    {
                        let fake_packet: Vec<u8> = {
                            let mut rng = rand::rng();
                            let fake_size: usize = rng.random_range(500..=1200);
                            (0..fake_size).map(|_| rng.random_range(0u8..=255u8)).collect()
                        };

                        let delay: u64 = {
                            let mut rng = rand::rng();
                            rng.random_range(15u64..=30u64)
                        };

                        log(&log_tx, LogLevel::Warning, format!(
                            "FAKE пакет {} байт впрыснут -> {}",
                            fake_packet.len(), target
                        ));
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
                                                log(&log_tx, LogLevel::Error, format!("Ошибка отправки клиенту {}: {}", client_addr, e));
                                                break;
                                            }
                                    }
                                    Ok(Err(e)) => {
                                        log(&log_tx, LogLevel::Error, format!("Upstream recv ошибка: {}", e));
                                        metrics.set_quic_target_ok(false);
                                        break;
                                    }
                                    Err(_) => {
                                        break;
                                    }
                                }
                            }
                        });
                    }

                    sock
                }
            };

            metrics.add_rx(data.len() as u64);
            if let Err(e) = upstream.send(&data).await {
                log(&log_tx, LogLevel::Error, format!("Ошибка upstream send для {}: {}", client_addr, e));
                metrics.set_quic_target_ok(false);
            }
        });
    }
}

pub async fn run_quic_proxy(listen_port: u16, target: String) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let listen_addr = format!("0.0.0.0:{}", listen_port).parse().unwrap();
    let server_config = make_server_config();
    let endpoint = Endpoint::server(server_config, listen_addr)
    .expect("Ошибка: не удалось создать QUIC endpoint");

    println!("[QUIC TLS] Прокси слушает: {}", listen_addr);

    while let Some(incoming) = endpoint.accept().await {
        let target = target.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    handle_quic_connection(conn, target).await;
                }
                Err(e) => println!("[-] QUIC ошибка соединения: {}", e),
            }
        });
    }
}

async fn handle_quic_connection(conn: Connection, target: String) {
    loop {
        match conn.accept_bi().await {
            Ok((mut send, mut recv)) => {
                let target = target.clone();
                tokio::spawn(async move {
                    handle_quic_stream(&mut send, &mut recv, &target).await;
                });
            }
            Err(e) => { println!("[QUIC] Соединение закрыто: {}", e); break; }
        }
    }
}

async fn handle_quic_stream(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    target: &str,
) {
    let server = match tokio::net::TcpStream::connect(target).await {
        Ok(s) => s,
        Err(e) => { println!("[-] QUIC->TCP ошибка к {}: {}", target, e); return; }
    };
    let (mut tcp_reader, mut tcp_writer) = server.into_split();
    tokio::select! {
        res = tokio::io::copy(recv, &mut tcp_writer) => {
            if let Err(e) = res { println!("[-] QUIC->TCP: {}", e); }
        }
        res = tokio::io::copy(&mut tcp_reader, send) => {
            if let Err(e) = res { println!("[-] TCP->QUIC: {}", e); }
        }
    }
}
