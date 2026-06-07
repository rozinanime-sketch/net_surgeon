use std::fs;
use serde::Deserialize;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::str;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
struct Config {
    fragment_size: u32,
    port: u16,
    udp_port: u16,
    host_ip: [u8; 4],
    enabled: bool,
}
fn print_payload(direction: &str, data: &[u8]){
    println!("{}", direction);
    if let Ok(text) = str::from_utf8(data){
        for line in text.lines().take(4) {
            if !line.trim().is_empty(){
                println!("    | {}",line);
            }
        }
    } else{
        print!("     | [HEX]: ");
        for byte in data.iter().take(16){
            print!("{:02X} ", byte);
        }
        if data.len() > 16 {
            print!("... (+{} байт)", data.len() - 16);
        }
        println!()
    }
}

#[tokio::main]
async fn main() {
    let config_contents = fs::read_to_string("config.toml")
        .expect("Ошибка: не удалось прочитать конфиг");
    let settings: Config = toml::from_str(&config_contents)
        .expect("Ошибка: не удалось распарсить TOML");

    let listen_address = format!("0.0.0.0:{}",settings.port);
    let udp_address = format!("0.0.0.0:{}", settings.udp_port);
    let frag_size = settings.fragment_size as usize;
    let is_enabled = settings.enabled;

    println!("---Net Surgeon запущен---");
    println!("TCP порт: {}", listen_address);
    println!("UDP порт: {}", udp_address);

    let tcp_task = tokio::spawn(async move {
        run_tcp_proxy(listen_address, frag_size, is_enabled).await;
    });

    let udp_task = tokio::spawn(async move {
        run_udp_proxy(udp_address).await;
    });

    let _ = tokio::join!(tcp_task, udp_task);
}
async fn run_tcp_proxy(
    listen_address: String,
    frag_size: usize,
    is_enabled: bool,
) {
    let listener = TcpListener::bind(&listen_address).await
        .expect("Ошибка: не удалось занять TCP порт");

    loop {
        match listener.accept().await {
            Ok((client_stream, addr)) => {
                println!("[TCP] [+] Подключение от: {}", addr);
                tokio::spawn(async move{
                    handle_connection(
                        client_stream,
                        frag_size,
                        is_enabled,
                    ).await;
                });
            } Err(e) => println!("[-] Ошибка TCP: {}", e),
        }
    }
}

async fn run_udp_proxy(listen_address: String) {
    let socket = UdpSocket::bind(&listen_address.as_str()).await
        .expect("Ошибка: не удалось занять UDP порт");
    let socket = Arc::new(socket);

    println!("[UDP] Прокси слушает: {}", listen_address);

    let mut buffer = [0u8; 65535];
    
    loop {
        match socket.recv_from(&mut buffer).await{
            Ok((len, client_addr)) => {
                let data = buffer[..len].to_vec();
                let socket = Arc::clone(&socket);

                println!("[UDP] Пакет {} байт от {}", len, client_addr);

                tokio::spawn(async move {
                    let temp = match UdpSocket::bind("0.0.0.0:0").await {
                        Ok(s) => s,
                        Err(_) => return,
                    };

                    print!("    | [HEX]: ");
                    for byte in data.iter().take(16) {
                        print!("{:02X} ", byte);
                    }
                    println!();

                    let _ = socket
                        .send_to(&data, client_addr)
                        .await;
                    });
            }Err(e) => println!("[-] Ошибка UDP: {}" ,e),
        }
    }
}

async fn handle_connection(
    mut client_stream: TcpStream,
    frag_size: usize,
    is_enabled: bool,
) {
    let mut buffer = [0u8; 4096];
    let bytes_read =match client_stream.read(&mut buffer).await {
        Ok(n) => n,
        Err(_) => return,
    }; 

    let request = match str::from_utf8(&buffer[..bytes_read]) {
        Ok(r) => r.to_string(),
        Err(_) => return,
    };
    if request.starts_with("CONNECT") {
        handle_connect(client_stream, &request, frag_size, is_enabled).await;
    } else {
        handle_http(client_stream, &request, frag_size, is_enabled).await;
    }
}
async fn handle_connect(
    mut client_stream: TcpStream,
    request: &str,
    frag_size: usize,
    is_enabled: bool,
) {
    let target = match parse_connect_target(request) {
        Some(t) => t,
        None => {
            println!("[-] Не удалось распарсить CONNECT");
            return;
        }
    };
    println!("[HTTPS] Туннель к: {}", target);

    let mut server_stream = match TcpStream::connect(&target).await {
        Ok(s) => s,
        Err(e) => {
            println!("[-] Ошибка подключения к {}: {}", target, e);
            let _ = client_stream
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                .await;
            return;
        }
    };
    
    let _ = client_stream
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
        .await;
    println!("[HTTPS] Туннель установлен проксируем...");

    let (mut client_reader, mut client_writer) = client_stream.into_split();
    let (mut server_reader, mut server_writer) = server_stream.into_split();

    let t1 = tokio::spawn(async move {
        let mut buffer = [0; 4096];
        loop {
            match client_reader.read(&mut buffer).await {
                Ok(0) => break,
                Ok(bytes_read) => {
                    let data = &buffer[..bytes_read];
                    let msg = format!(
                        "[HTTPS => Server] {} байт", 
                        bytes_read
                    );
                    print_payload(&msg, data);

                    if is_enabled{
                        for chunk in data.chunks(frag_size) {
                            if server_writer.write_all(chunk).await.is_err() {break;}
                        }
                    }else{if server_writer.write_all(data).await.is_err() {break;}
                    }
                } Err(_) => break,
            }
        }
    });
let t2 = tokio::spawn(async move{
    let mut buffer = [0u8; 4096];
    loop {
        match server_reader.read(&mut buffer).await {
            Ok(0) => break,
            Ok(bytes_read) => {
                let data = &buffer[..bytes_read];
                let msg = format!("[HTTPS <= Client] Получен ответ: {} байт", bytes_read);
                print_payload(&msg, data);

                if client_writer.write_all(data).await.is_err() {break;}
            }
            Err(_) => break,
        }
    }
});

let _ =tokio::join!(t1,t2);
println!("[HTTPS] Туннель закрыт: {}", target);
}

async fn handle_http(
    mut client_stream: TcpStream,
    request: &str,
    frag_size: usize,
    is_enabled: bool,
) {
    let target = match parse_http_target(request) {
        Some(t) => t,
        None => {
            println!("[-] Не удалось найти Host");
            return;
            }
    };
    println!("[HTTP] Запрос к: {}", target);

    let mut server_stream = match TcpStream::connect(&target).await {
        Ok(s) => s,
        Err(e) => {
            println!("[-] Ошибка: {}", e);
            return;
        }
    };
    let data = request.as_bytes();
    let msg = format!("[HTTP => Server] {} байт", data.len());
    print_payload(&msg, data);

    if is_enabled {
        for chunk in data.chunks(frag_size) {
            if server_stream.write_all(chunk).await.is_err() {
                return;
            }
        }
    } else {
        let _ = server_stream.write_all(data).await;
    }

    let (mut client_reader, mut client_writer) = client_stream.into_split();
    let (mut server_reader, mut server_writer) = server_stream.into_split();

    let t1 = tokio::spawn(async move {
        let mut buffer = [0u8; 4096];
        loop {
            match client_reader.read(&mut buffer).await {
                Ok(0) => break,
                Ok(bytes_read) => {
                    if server_writer.write_all(&buffer[..bytes_read]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let t2 = tokio::spawn(async move {
        let mut buffer = [0u8; 4096];
        loop {
            match server_reader.read(&mut buffer).await {
                Ok(0) => break,
                Ok(bytes_read) => {
                    let data = &buffer[..bytes_read];
                    let msg = format!("[HTTP <= Server] {} байт", bytes_read);
                    print_payload(&msg, data);
                    if client_writer.write_all(data).await.is_err() {
                        break;
                    }
                } Err(_) => break,
            }
        }
    });

    let _ = tokio::join!(t1, t2);
}

fn parse_connect_target(request: &str) -> Option<String> {
    let line = request.lines().next()?;
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() >= 2 {
        Some(parts[1].to_string())
    } else {
        None
    }
}

fn parse_http_target(request: &str) -> Option<String> {
    for line in request.lines() {
        if line.to_lowercase().starts_with("host:") {
            let host = line[5..].trim().to_string();
            if host.contains(':'){
                return Some(host);
            } else {
                return Some(format!("{}:80", host));
            }
        }
    }None
}
