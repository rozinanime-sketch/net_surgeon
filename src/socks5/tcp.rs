use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::cli::{LogSender, log, LogLevel};

const SOCKS5_VERSION: u8 = 0x05;
const NO_AUTH: u8 = 0x00;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const REP_SUCCESS: u8 = 0x00;

pub async fn run_socks5_server(port: u16, udp_port: u16, log_tx: LogSender) {
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await
    .expect("Ошибка: не удалось занять SOCKS5 порт");

    log(&log_tx, LogLevel::Success, format!("SOCKS5 сервер слушает: {}", addr));

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                log(&log_tx, LogLevel::Info, format!("SOCKS5 подключение от: {}", addr));
                let log_tx = log_tx.clone();
                tokio::spawn(async move {
                    handle_socks5(stream, udp_port, log_tx).await;
                });
            }
            Err(e) => log(&log_tx, LogLevel::Error, format!("SOCKS5 ошибка: {}", e)),
        }
    }
}

async fn handle_socks5(mut stream: TcpStream, udp_port: u16, log_tx: LogSender) {
    let mut buf = [0u8; 256];

    let n = match stream.read(&mut buf).await {
        Ok(n) => n,
        Err(_) => return,
    };

    if n < 2 || buf[0] != SOCKS5_VERSION {
        log(&log_tx, LogLevel::Warning, "SOCKS5: неверная версия");
        return;
    }

    if stream.write_all(&[SOCKS5_VERSION, NO_AUTH]).await.is_err() {
        return;
    }

    let n = match stream.read(&mut buf).await {
        Ok(n) => n,
        Err(_) => return,
    };

    if n < 7 || buf[0] != SOCKS5_VERSION {
        return;
    }

    let cmd = buf[1];

    match cmd {
        CMD_UDP_ASSOCIATE => {
            log(&log_tx, LogLevel::Info, "SOCKS5 UDP ASSOCIATE запрос");
            handle_udp_associate(&mut stream, udp_port, &log_tx).await;
        }
        0x01 => {
            log(&log_tx, LogLevel::Info, "SOCKS5 CONNECT запрос");
            handle_connect(&mut stream, &buf[..n], &log_tx).await;
        }
        _ => {
            log(&log_tx, LogLevel::Warning, format!("SOCKS5: неизвестная команда {}", cmd));
        }
    }
}

async fn handle_udp_associate(stream: &mut TcpStream, udp_port: u16, log_tx: &LogSender) {
    let port_bytes = udp_port.to_be_bytes();
    let response = [
        SOCKS5_VERSION,
        REP_SUCCESS,
        0x00,
        ATYP_IPV4,
        127, 0, 0, 1,
        port_bytes[0],
        port_bytes[1],
    ];

    if stream.write_all(&response).await.is_err() {
        return;
    }

    log(log_tx, LogLevel::Info, format!("SOCKS5 UDP ASSOCIATE: сказали слать на порт {}", udp_port));

    let mut buf = [0u8; 1];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => break,
            Err(_) => break,
            _ => {}
        }
    }
}

async fn handle_connect(stream: &mut TcpStream, request: &[u8], log_tx: &LogSender) {
    let target = match parse_target(request) {
        Some(t) => t,
        None => {
            let _ = stream.write_all(&[
                SOCKS5_VERSION, 0x01, 0x00,
                ATYP_IPV4, 0, 0, 0, 0, 0, 0
            ]).await;
            return;
        }
    };

    log(log_tx, LogLevel::Info, format!("SOCKS5 CONNECT к: {}", target));

    let mut server = match tokio::net::TcpStream::connect(&target).await {
        Ok(s) => s,
        Err(e) => {
            log(log_tx, LogLevel::Error, format!("SOCKS5 CONNECT ошибка {}: {}", target, e));
            let _ = stream.write_all(&[
                SOCKS5_VERSION, 0x04, 0x00,
                ATYP_IPV4, 0, 0, 0, 0, 0, 0
            ]).await;
            return;
        }
    };

    let _ = stream.write_all(&[
        SOCKS5_VERSION, REP_SUCCESS, 0x00,
        ATYP_IPV4, 127, 0, 0, 1, 0, 0
    ]).await;

    let mut hello_buf = vec![0u8; 4096];

    let _ = stream.read_exact(&mut hello_buf[..5]).await;

    let data_len = u16::from_be_bytes([hello_buf[3], hello_buf[4]]) as usize;

    let _ = stream.read_exact(&mut hello_buf[5..5 + data_len]).await;

    let total = 5 + data_len;
    let hello = &hello_buf[..total];

    log(log_tx, LogLevel::Info, format!("SOCKS5 Client Hello перехвачен: {} байт", total));

    let frag_size = 2;
    for chunk in hello.chunks(frag_size) {
        if server.write_all(chunk).await.is_err() {
            return;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
    }

    log(log_tx, LogLevel::Success, format!("SOCKS5 Client Hello отправлен фрагментами -> {}", target));

    let (mut cr, mut cw) = stream.split();
    let (mut sr, mut sw) = server.split();

    let t1 = tokio::io::copy(&mut cr, &mut sw);
    let t2 = tokio::io::copy(&mut sr, &mut cw);

    tokio::select! {
        _ = t1 => {}
        _ = t2 => {}
    }
}

fn parse_target(request: &[u8]) -> Option<String> {
    if request.len() < 7 {
        return None;
    }

    let atyp = request[3];
    match atyp {
        0x01 => {
            if request.len() < 10 {
                return None;
            }
            let ip = format!(
                "{}.{}.{}.{}",
                request[4], request[5],
                request[6], request[7]
            );
            let port = u16::from_be_bytes([request[8], request[9]]);
            Some(format!("{}:{}", ip, port))
        }
        0x03 => {
            let len = request[4] as usize;
            if request.len() < 5 + len + 2 {
                return None;
            }
            let domain = std::str::from_utf8(
                &request[5..5 + len]
            ).ok()?.to_string();
            let port = u16::from_be_bytes([
                request[5 + len],
                request[5 + len + 1]
            ]);
            Some(format!("{}:{}", domain, port))
        }
        _ => None,
    }
}
