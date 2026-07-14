use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::cli::{LogSender, log_t, LogLevel};

const SOCKS5_VERSION: u8 = 0x05;
const NO_AUTH: u8 = 0x00;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const REP_SUCCESS: u8 = 0x00;

use tokio_util::sync::CancellationToken;

pub async fn run_socks5_server(port: u16, udp_port: u16, log_tx: LogSender, token: CancellationToken) {
    let addr = format!("0.0.0.0:{}", port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            log_t(&log_tx, LogLevel::Error, "log.socks5_bind_error", vec![("addr", addr.clone()), ("error", e.to_string())]);
            return;
        }
    };

    log_t(&log_tx, LogLevel::Success, "log.socks5_listening", vec![("addr", addr.clone())]);

    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, addr)) => {
                        let _ = addr;
                        let log_tx = log_tx.clone();
                        tokio::spawn(async move {
                            handle_socks5(stream, udp_port, log_tx).await;
                        });
                    }
                    Err(e) => log_t(&log_tx, LogLevel::Error, "log.socks5_error", vec![("error", e.to_string())]),
                }
            }
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
        log_t(&log_tx, LogLevel::Warning, "log.socks5_bad_version", vec![]);
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
            log_t(&log_tx, LogLevel::Info, "log.socks5_udp_associate", vec![]);
            handle_udp_associate(&mut stream, udp_port, &log_tx).await;
        }
        0x01 => {
            log_t(&log_tx, LogLevel::Info, "log.socks5_connect_request", vec![]);
            handle_connect(&mut stream, &buf[..n], &log_tx).await;
        }
        _ => {
            log_t(&log_tx, LogLevel::Warning, "log.socks5_unknown_cmd", vec![("cmd", cmd.to_string())]);
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

    log_t(log_tx, LogLevel::Info, "log.socks5_udp_told", vec![("port", udp_port.to_string())]);

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

    log_t(log_tx, LogLevel::Info, "log.socks5_connect_to", vec![("target", target.clone())]);

    let mut server = match tokio::net::TcpStream::connect(&target).await {
        Ok(s) => s,
        Err(e) => {
            log_t(log_tx, LogLevel::Error, "log.socks5_connect_error", vec![("target", target.clone()), ("error", e.to_string())]);
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

    // --- НАЧАЛО НОВОГО КОДА (Безопасный перехватчик) ---
    let mut initial_buf = [0u8; 8192];
    let n = match stream.read(&mut initial_buf).await {
        Ok(0) | Err(_) => return, // Клиент закрыл соединение или произошла ошибка
        Ok(n) => n,
    };

    // Проверяем, является ли первый пакет TLS ClientHello (0x16 = Handshake, 0x03 = SSL/TLS)
    let is_tls = n >= 5 && initial_buf[0] == 0x16 && initial_buf[1] == 0x03;

    if is_tls {
        log_t(log_tx, LogLevel::Info, "log.socks5_hello_intercepted", vec![("bytes", n.to_string())]);

        // Применяем фрагментацию DPI только для TLS-трафика
        if crate::bypass::fragment::fragment_socks5_style(&mut server, &initial_buf[..n]).await.is_err() {
            return;
        }
        log_t(log_tx, LogLevel::Success, "log.socks5_hello_sent", vec![("target", target.clone())]);
    } else {
        // Это не TLS (или пакет слишком короткий), просто пересылаем всё как есть
        if server.write_all(&initial_buf[..n]).await.is_err() {
            return;
        }
    }
    // --- КОНЕЦ НОВОГО КОДА ---

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
        0x04 => { // Поддержка IPv6
            if request.len() < 22 {
                return None;
            }
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&request[4..20]);
            let ip = std::net::Ipv6Addr::from(ip_bytes);
            let port = u16::from_be_bytes([request[20], request[21]]);
            Some(format!("[{}]:{}", ip, port))
        }
        _ => None, // <--- "Всё остальное" строго в самом конце
    }
}
