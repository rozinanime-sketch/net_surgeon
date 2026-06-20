use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

use crate::config::Ranges;
use crate::bypass::fragment;
use crate::cli::{LogSender, log, LogLevel};

pub async fn run_udp_proxy(listen_address: String, udp_target: String, ranges: Ranges, log_tx: LogSender) {
    let socket = UdpSocket::bind(&listen_address).await
    .expect("Ошибка: не удалось занять UDP порт");
    let socket = Arc::new(socket);

    log(&log_tx, LogLevel::Success, format!("UDP прокси слушает: {}", listen_address));

    let mut buffer = [0u8; 65535];
    loop {
        match socket.recv_from(&mut buffer).await {
            Ok((len, client_addr)) => {
                log(&log_tx, LogLevel::Info, format!("UDP пакет {} байт от {}", len, client_addr));
                let data = buffer[..len].to_vec();
                let main_socket = Arc::clone(&socket);
                let target = udp_target.clone();
                let ranges_clone = ranges.clone();
                let log_tx = log_tx.clone();

                tokio::spawn(async move {
                    let upstream_socket = match UdpSocket::bind("0.0.0.0:0").await {
                        Ok(s) => s,
                             Err(_) => return,
                    };

                    if upstream_socket.send_to(&data, &target).await.is_ok() {
                        let mut resp_buf = [0u8; 65535];
                        if let Ok(Ok((resp_len, _))) = tokio::time::timeout(
                            Duration::from_secs(4),
                                                                            upstream_socket.recv_from(&mut resp_buf),
                        ).await {
                            fragment::apply_udp_jitter(&ranges_clone).await;
                            let _ = main_socket.send_to(&resp_buf[..resp_len], client_addr).await;
                            log(&log_tx, LogLevel::Info, format!("UDP ответ {} байт -> {}", resp_len, client_addr));
                        }
                    }
                });
            }
            Err(e) => log(&log_tx, LogLevel::Error, format!("Ошибка UDP: {}", e)),
        }
    }
}
