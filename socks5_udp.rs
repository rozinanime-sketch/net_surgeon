use tokio::net::UdpSocket;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::net::SocketAddr;
use rand::prelude::*;
use std::time::Duration;

type SessionTable = Arc<Mutex<HashMap<SocketAddr, SocketAddr>>>;

pub async fn run_socks5_udp_processor(socks5_udp_port: &str) {
    let server_socket = Arc::new(
        UdpSocket::bind(socks5_udp_port)
        .await
        .expect("Не удалось занять UDP порт для SOCKS5")
    );
    println!("[SOCKS5 UDP] Сервер запущен и слушает на порту {}", socks5_udp_port);

    let mut buffer = [0u8; 4096];
    let active_sessions: SessionTable = Arc::new(Mutex::new(HashMap::new()));

    // Параметры обфускации
    let jc = 6;
    let jmin = 100;
    let jmax = 800;

    loop {
        match server_socket.recv_from(&mut buffer).await {
            Ok((bytes_read, client_src_addr)) => {
                if bytes_read < 10 { continue; } // Слишком маленький пакет

                let packet = buffer[..bytes_read].to_vec();
                let socket_clone = server_socket.clone();
                let sessions_clone = active_sessions.clone();

                tokio::spawn(async move {
                    let atyp = packet[3];

                    let (dst_addr, payload_start) = match atyp {
                        1 => { // IPv4
                            let ip = std::net::Ipv4Addr::new(packet[4], packet[5], packet[6], packet[7]);
                            let port = u16::from_be_bytes([packet[8], packet[9]]);
                            (SocketAddr::new(std::net::IpAddr::V4(ip), port), 10)
                        },
                        _ => return,
                    };

                    let raw_payload = &packet[payload_start..];
                    let mut table = sessions_clone.lock().await;

                    if !table.contains_key(&client_src_addr) {
                        println!("[💥 SOCKS5 QUIC JUNK] Обнаружен новый QUIC поток к {}. Запуск обфускации...", dst_addr);
                        table.insert(client_src_addr, dst_addr);
                        drop(table); // Освобождаем лок перед паузами

                        // Изолированный блок генерации джанка (Send-safe)
                        for i in 1..=jc {
                            let (junk_packet, sleep_delay) = {
                                let mut rng = rand::rng();
                                let junk_size = rng.random_range(jmin..=jmax);
                                let mut packet = vec![0u8; junk_size];
                                rng.fill(&mut packet[..]);

                                let delay = rng.random_range(15..40);
                                (packet, delay)
                            };

                            if socket_clone.send_to(&junk_packet, dst_addr).await.is_ok() {
                                println!("[Junk => {}] Пакет №{} отправлен (размер: {})", dst_addr, i, junk_packet.len());
                            }

                            tokio::time::sleep(Duration::from_millis(sleep_delay)).await;
                        }
                    } else {
                        drop(table);
                    }

                    // Отправляем реальные зашифрованные данные QUIC
                    let _ = socket_clone.send_to(raw_payload, dst_addr).await;
                });
            }
            Err(e) => {
                println!("[-] Ошибка SOCKS5 UDP: {}", e);
            }
        }
    }
}
