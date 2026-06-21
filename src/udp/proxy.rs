use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

use crate::config::Ranges;
use crate::bypass::fragment;
use crate::cli::{LogSender, log, LogLevel};
use crate::metrics::Metrics;

pub async fn run_udp_proxy(listen_address: String, udp_target: String, ranges: Ranges, log_tx: LogSender, metrics: Arc<Metrics>) {
    let socket = UdpSocket::bind(&listen_address).await
    .expect("Ошибка: не удалось занять UDP порт");
    let socket = Arc::new(socket);

    log(&log_tx, LogLevel::Success, format!("UDP прокси слушает: {}", listen_address));

    // Фоновая проверка здоровья DNS-апстрима каждые 15 секунд
    {
        let target = udp_target.clone();
        let metrics = Arc::clone(&metrics);
        let log_tx = log_tx.clone();
        tokio::spawn(async move {
            loop {
                let ok = dns_health_check(&target).await;
                metrics.set_dns_ok(ok);
                if !ok {
                    log(&log_tx, LogLevel::Warning, format!("DNS health-check провален: {}", target));
                }
                tokio::time::sleep(Duration::from_secs(15)).await;
            }
        });
    }

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
                let metrics = Arc::clone(&metrics);

                tokio::spawn(async move {
                    let upstream_socket = match UdpSocket::bind("0.0.0.0:0").await {
                        Ok(s) => s,
                             Err(_) => return,
                    };

                    metrics.add_rx(data.len() as u64);

                    if upstream_socket.send_to(&data, &target).await.is_ok() {
                        let mut resp_buf = [0u8; 65535];
                        if let Ok(Ok((resp_len, _))) = tokio::time::timeout(
                            Duration::from_secs(4),
                                                                            upstream_socket.recv_from(&mut resp_buf),
                        ).await {
                            fragment::apply_udp_jitter(&ranges_clone).await;
                            let _ = main_socket.send_to(&resp_buf[..resp_len], client_addr).await;
                            metrics.add_tx(resp_len as u64);
                            log(&log_tx, LogLevel::Info, format!("UDP ответ {} байт -> {}", resp_len, client_addr));
                        }
                    }
                });
            }
            Err(e) => log(&log_tx, LogLevel::Error, format!("Ошибка UDP: {}", e)),
        }
    }
}

/// Лёгкая проверка: отправляем минимальный DNS-запрос (A-запись для "google.com")
/// и ждём любой ответ с таймаутом 2 секунды.
async fn dns_health_check(target: &str) -> bool {
    let probe: [u8; 28] = [
        0x12, 0x34, // ID
        0x01, 0x00, // флаги: рекурсивный запрос
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // остальные счётчики = 0
        0x06, b'g', b'o', b'o', b'g', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00, // конец имени
        0x00, 0x01, // QTYPE = A
        0x00, 0x01, // QCLASS = IN
    ];

    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return false,
    };

    if socket.send_to(&probe, target).await.is_err() {
        return false;
    }

    let mut buf = [0u8; 512];
    matches!(
        tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await,
             Ok(Ok(_))
    )
}
