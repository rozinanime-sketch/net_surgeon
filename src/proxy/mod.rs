mod tcp;
mod http;
mod https;

use std::sync::Arc;
use std::collections::HashSet;
use std::str;
use crate::config::Config;
use crate::udp;
use crate::socks5;
use crate::cli::{LogSender, log, LogLevel};

pub async fn run_all(config: Arc<Config>, domains: Arc<HashSet<String>>, log_tx: LogSender) {
    let listen_address = format!("0.0.0.0:{}", config.port);
    let udp_address = format!("0.0.0.0:{}", config.udp_port);
    let socks5_udp_address = format!("0.0.0.0:{}", config.socks5_udp_port);

    log(&log_tx, LogLevel::Info, format!("TCP порт: {}", listen_address));
    log(&log_tx, LogLevel::Info, format!("UDP порт: {} -> {}", udp_address, config.udp_target));
    log(&log_tx, LogLevel::Info, format!("QUIC порт: {} -> {}", config.quic.listen_port, config.quic.target));
    log(&log_tx, LogLevel::Info, format!("SOCKS5 порт: {}  SOCKS5 UDP: {}", config.socks5_port, config.socks5_udp_port));

    let tcp_task = {
        let config = Arc::clone(&config);
        let domains = Arc::clone(&domains);
        let log_tx = log_tx.clone();
        tokio::spawn(async move {
            tcp::run_tcp_proxy(
                listen_address,
                config.ranges.clone(),
                               config.enabled,
                               domains,
                               config.bypass.clone(),
                               log_tx,
            ).await;
        })
    };

    let udp_task = {
        let config = Arc::clone(&config);
        let log_tx = log_tx.clone();
        tokio::spawn(async move {
            udp::proxy::run_udp_proxy(udp_address, config.udp_target.clone(), config.ranges.clone(), log_tx).await;
        })
    };

    let quic_task = {
        let config = Arc::clone(&config);
        let log_tx = log_tx.clone();
        tokio::spawn(async move {
            udp::quic::run_udp_quic_proxy(config.quic.listen_port, config.quic.target.clone(), log_tx).await;
        })
    };

    let socks5_task = {
        let config = Arc::clone(&config);
        let log_tx = log_tx.clone();
        tokio::spawn(async move {
            socks5::tcp::run_socks5_server(config.socks5_port, config.socks5_udp_port, log_tx).await;
        })
    };

    let socks5_udp_task = {
        let log_tx = log_tx.clone();
        tokio::spawn(async move {
            socks5::udp::run_socks5_udp_processor(&socks5_udp_address, log_tx).await;
        })
    };

    let _ = tokio::join!(tcp_task, udp_task, quic_task, socks5_task, socks5_udp_task);
}

pub fn print_payload(direction: &str, data: &[u8]) {
    println!("{}", direction);
    if let Ok(text) = str::from_utf8(data) {
        for line in text.lines().take(4) {
            if !line.trim().is_empty() {
                println!("    | {}", line);
            }
        }
    } else {
        print!("     | [HEX]: ");
        for byte in data.iter().take(16) {
            print!("{:02X} ", byte);
        }
        if data.len() > 16 {
            print!("... (+{} байт)", data.len() - 16);
        }
        println!();
    }
}
