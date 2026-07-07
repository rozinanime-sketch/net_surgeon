use tokio::net::UdpSocket;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::net::SocketAddr;
use rand::prelude::*;
use std::time::Duration;

use crate::cli::{LogSender, log_t, LogLevel};

type SessionTable = Arc<Mutex<HashMap<SocketAddr, SocketAddr>>>;

pub async fn run_socks5_udp_processor(socks5_udp_port: &str, log_tx: LogSender) {
    let server_socket = Arc::new(
        UdpSocket::bind(socks5_udp_port)
        .await
        .expect("Не удалось занять UDP порт для SOCKS5")
    );
    log_t(&log_tx, LogLevel::Success, "log.socks5_udp_listening", vec![("addr", socks5_udp_port.to_string())]);

    let mut buffer = [0u8; 4096];
    let active_sessions: SessionTable = Arc::new(Mutex::new(HashMap::new()));

    let jc = 6;
    let jmin = 100;
    let jmax = 800;

    loop {
        match server_socket.recv_from(&mut buffer).await {
            Ok((bytes_read, client_src_addr)) => {
                if bytes_read < 10 { continue; }

                let packet = buffer[..bytes_read].to_vec();
                let socket_clone = server_socket.clone();
                let sessions_clone = active_sessions.clone();
                let log_tx = log_tx.clone();

                tokio::spawn(async move {
                    let atyp = packet[3];

                    let (dst_addr, payload_start) = match atyp {
                        1 => {
                            let ip = std::net::Ipv4Addr::new(packet[4], packet[5], packet[6], packet[7]);
                            let port = u16::from_be_bytes([packet[8], packet[9]]);
                            (SocketAddr::new(std::net::IpAddr::V4(ip), port), 10)
                        },
                        _ => return,
                    };

                    let raw_payload = &packet[payload_start..];
                    let mut table = sessions_clone.lock().await;

                    if !table.contains_key(&client_src_addr) {
                        log_t(&log_tx, LogLevel::Warning, "log.socks5_udp_junk", vec![("addr", dst_addr.to_string())]);
                        table.insert(client_src_addr, dst_addr);
                        drop(table);

                        for _i in 1..=jc {
                            let (junk_packet, sleep_delay) = {
                                let mut rng = rand::rng();
                                let junk_size = rng.random_range(jmin..=jmax);
                                let mut packet = vec![0u8; junk_size];
                                rng.fill(&mut packet[..]);

                                let delay = rng.random_range(15..40);
                                (packet, delay)
                            };

                            let _ = socket_clone.send_to(&junk_packet, dst_addr).await;

                            tokio::time::sleep(Duration::from_millis(sleep_delay)).await;
                        }
                        log_t(&log_tx, LogLevel::Success, "log.socks5_udp_junk_sent", vec![("count", jc.to_string()), ("addr", dst_addr.to_string())]);
                    } else {
                        drop(table);
                    }

                    let _ = socket_clone.send_to(raw_payload, dst_addr).await;
                });
            }
            Err(e) => {
                log_t(&log_tx, LogLevel::Error, "log.socks5_udp_error", vec![("error", e.to_string())]);
            }
        }
    }
}
