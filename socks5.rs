use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// Константы протокола SOCKS5
const SOCKS5_VERSION: u8 = 0x05;
const NO_AUTH: u8 = 0x00;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const REP_SUCCESS: u8 = 0x00;

pub async fn run_socks5_server(port: u16, udp_port: u16) {
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await
    .expect("Ошибка: не удалось занять SOCKS5 порт");

    println!("[SOCKS5] Сервер слушает: {}", addr);

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                println!("[SOCKS5] Подключение от: {}", addr);
                tokio::spawn(async move {
                    handle_socks5(stream, udp_port).await;
                });
            }
            Err(e) => println!("[-] SOCKS5 ошибка: {}", e),
        }
    }
}

async fn handle_socks5(mut stream: TcpStream, udp_port: u16) {
    // Шаг 1: Читаем приветствие клиента
    // [VER, NMETHODS, METHODS...]
    let mut buf = [0u8; 256];

    let n = match stream.read(&mut buf).await {
        Ok(n) => n,
        Err(_) => return,
    };

    if n < 2 || buf[0] != SOCKS5_VERSION {
        println!("[-] SOCKS5: неверная версия");
        return;
    }

    // Шаг 2: Отвечаем — выбираем NO_AUTH
    // [VER, METHOD]
    if stream.write_all(&[SOCKS5_VERSION, NO_AUTH]).await.is_err() {
        return;
    }

    // Шаг 3: Читаем запрос клиента
    // [VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT]
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
            println!("[SOCKS5] UDP ASSOCIATE запрос");
            handle_udp_associate(&mut stream, udp_port).await;
        }
        0x01 => {
            // CONNECT — обычный TCP
            println!("[SOCKS5] CONNECT запрос");
            handle_connect(&mut stream, &buf[..n]).await;
        }
        _ => {
            println!("[-] SOCKS5: неизвестная команда {}", cmd);
        }
    }
}

async fn handle_udp_associate(
    stream: &mut TcpStream,
    udp_port: u16,
) {
    // Отвечаем браузеру: UDP порт открыт
    // [VER, REP, RSV, ATYP, BND.ADDR, BND.PORT]
    let port_bytes = udp_port.to_be_bytes();
    let response = [
        SOCKS5_VERSION,
        REP_SUCCESS,
        0x00,          // RSV
        ATYP_IPV4,     // IPv4
        127, 0, 0, 1,  // 127.0.0.1
        port_bytes[0],
        port_bytes[1],
    ];

    if stream.write_all(&response).await.is_err() {
        return;
    }

    println!(
        "[SOCKS5] UDP ASSOCIATE: сказали браузеру слать на порт {}",
        udp_port
    );

    // Держим TCP соединение открытым как управляющий канал
    // Браузер закроет его когда закончит UDP сессию
    let mut buf = [0u8; 1];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => {
                println!("[SOCKS5] Управляющее соединение закрыто");
                break;
            }
            Err(_) => break,
            _ => {}
        }
    }
}

async fn handle_connect(stream: &mut TcpStream, request: &[u8]) {
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

    println!("[SOCKS5] CONNECT к: {}", target);

    let mut server = match tokio::net::TcpStream::connect(&target).await {
        Ok(s) => s,
        Err(e) => {
            println!("[-] SOCKS5 CONNECT ошибка {}: {}", target, e);
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

    // Читаем первый пакет от клиента (Client Hello)
    // Читаем полный TLS Client Hello
    let mut hello_buf = vec![0u8; 4096];

    // Сначала читаем 5 байт заголовка TLS record
    let _ = stream.read_exact(&mut hello_buf[..5]).await;

    // Байты 3-4 это длина данных
    let data_len = u16::from_be_bytes([hello_buf[3], hello_buf[4]]) as usize;

    // Читаем оставшиеся данные
    let _ = stream.read_exact(&mut hello_buf[5..5 + data_len]).await;

    let total = 5 + data_len;
    let hello = &hello_buf[..total];

    println!("[SOCKS5] Client Hello перехвачен: {} байт", total);

    // Фрагментируем
    let frag_size = 2;
    for chunk in hello.chunks(frag_size) {
        if server.write_all(chunk).await.is_err() {
            return;
        }
        tokio::time::sleep(
            tokio::time::Duration::from_millis(1)
        ).await;
    }

    println!("[SOCKS5] Client Hello отправлен фрагментами");

    // Дальше проксируем обычно
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
            // IPv4
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
            // Domain name
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
