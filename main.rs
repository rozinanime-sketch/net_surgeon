use std::fs;
use std::time::Duration;
use serde::Deserialize;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::str;
use std::sync::Arc;
use rand::RngExt; // Трейт для генерации диапазонов в rand 0.10

mod quic;

#[derive(Debug, Deserialize, Clone)]
struct Ranges {
    frag_min: usize,
    frag_max: usize,
    delay_min_ms: u64,
    delay_max_ms: u64,
    udp_jitter_min_ms: u64,
    udp_jitter_max_ms: u64,
}

#[derive(Debug, Deserialize, Clone)]
struct Config {
    port: u16,
    udp_port: u16,
    udp_target: String,
    enabled: bool,
    ranges: Ranges,
}

// Твоя функция красивого логирования пакетов
fn print_payload(direction: &str, data: &[u8]) {
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

#[tokio::main]
async fn main() {
    let config_contents = fs::read_to_string("config.toml")
    .expect("Ошибка: не удалось прочитать config.toml");
    let settings: Config = toml::from_str(&config_contents)
    .expect("Ошибка: не удалось распарсить TOML");

    let listen_address = format!("0.0.0.0:{}", settings.port);
    let udp_address = format!("0.0.0.0:{}", settings.udp_port);
    let is_enabled = settings.enabled;
    let udp_target = settings.udp_target.clone();
    let ranges = settings.ranges.clone();

    println!("--- Net Surgeon (Модифицированный дебаг-режим) запущен ---");
    println!("TCP порт (HTTP/HTTPS): {}", listen_address);
    println!("UDP порт: {}", udp_address);
    println!("UDP Upstream: {}", udp_target);

    let tcp_task = tokio::spawn(async move {
        run_tcp_proxy(listen_address, ranges, is_enabled).await;
    });

    let udp_task = tokio::spawn(async move {
        run_udp_proxy(udp_address, udp_target, settings.ranges.clone()).await;
    });

    let quic_task = tokio::spawn(async move {
        quic::run_quic_proxy(8443, "youtube.com:443".to_string()).await;
    });

    let _ = tokio::join!(tcp_task, udp_task, quic_task);
}

async fn run_tcp_proxy(listen_address: String, ranges: Ranges, is_enabled: bool) {
    let listener = TcpListener::bind(&listen_address).await
    .expect("Ошибка: не удалось занять TCP порт");

    loop {
        match listener.accept().await {
            Ok((client_stream, addr)) => {
                println!("[TCP] [+] Подключение от: {}", addr);
                let ranges_clone = ranges.clone();
                tokio::spawn(async move {
                    handle_connection(client_stream, ranges_clone, is_enabled).await;
                });
            }
            Err(e) => println!("[-] Ошибка TCP: {}", e),
        }
    }
}

async fn run_udp_proxy(listen_address: String, udp_target: String, ranges: Ranges) {
    let socket = UdpSocket::bind(&listen_address).await
    .expect("Ошибка: не удалось занять UDP порт");
    let socket = Arc::new(socket);

    println!("[UDP] Прокси слушает: {}", listen_address);

    let mut buffer = [0u8; 65535];
    loop {
        match socket.recv_from(&mut buffer).await {
            Ok((len, client_addr)) => {
                println!("[UDP] Пакет {} байт от {}", len, client_addr);
                let data = buffer[..len].to_vec();
                let main_socket = Arc::clone(&socket);
                let target = udp_target.clone();
                let ranges_clone = ranges.clone();

                tokio::spawn(async move {
                    let upstream_socket = match UdpSocket::bind("0.0.0.0:0").await {
                        Ok(s) => s,
                             Err(_) => return,
                    };

                    if upstream_socket.send_to(&data, &target).await.is_ok() {
                        let mut resp_buf = [0u8; 65535];
                        if let Ok(Ok((resp_len, _))) = tokio::time::timeout(
                            Duration::from_secs(4),
                                                                            upstream_socket.recv_from(&mut resp_buf)
                        ).await {
                            // Изолируем rng внутри блока
                            let udp_jitter = {
                                let mut rng = rand::rng();
                                rng.random_range(ranges_clone.udp_jitter_min_ms..=ranges_clone.udp_jitter_max_ms)
                            };
                            println!("[UDP <= Server] Задержка джиттера: {} мс", udp_jitter);
                            tokio::time::sleep(Duration::from_millis(udp_jitter)).await;

                            let _ = main_socket.send_to(&resp_buf[..resp_len], client_addr).await;
                        }
                    }
                });
            }
            Err(e) => println!("[-] Ошибка UDP: {}", e),
        }
    }
}

async fn handle_connection(mut client_stream: TcpStream, ranges: Ranges, is_enabled: bool) {
    let mut buffer = [0u8; 4096];
    let bytes_read = match client_stream.read(&mut buffer).await {
        Ok(n) if n > 0 => n,
        _ => return,
    };

    let request = match str::from_utf8(&buffer[..bytes_read]) {
        Ok(r) => r.to_string(),
        Err(_) => return,
    };

    if request.starts_with("CONNECT") {
        handle_connect(client_stream, &request, ranges, is_enabled).await;
    } else {
        handle_http(client_stream, &request, &buffer[..bytes_read], ranges, is_enabled).await;
    }
}

fn find_sni_index(data: &[u8], target_domain: &str) -> Option<usize> {
    let target_bytes = target_domain.as_bytes();
    data.windows(target_bytes.len())
    .position(|window| window == target_bytes)
}

async fn handle_connect(client_stream: TcpStream, request: &str, ranges: Ranges, is_enabled: bool) {
    let target = match parse_connect_target(request) {
        Some(t) => t,
        None => {
            println!("[-] Не удалось распарсить CONNECT");
            return;
        }
    };
    println!("[HTTPS] Туннель к: {}", target);

    let server_stream = match TcpStream::connect(&target).await {
        Ok(s) => s,
        Err(e) => {
            println!("[-] Ошибка подключения к {}: {}", target, e);
            let mut cs = client_stream;
            let _ = cs.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
            return;
        }
    };

    let _ = client_stream.set_nodelay(true);
    let _ = server_stream.set_nodelay(true);

    let mut client_stream = client_stream;
    if client_stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.is_err() {
        return;
    }
    println!("[HTTPS] Туннель установлен, проксируем...");

    let (mut client_reader, mut client_writer) = client_stream.into_split();
    let (mut server_reader, mut server_writer) = server_stream.into_split();

    let target_clone = target.clone();

    let client_to_server = async move {
        let mut buffer = [0u8; 4096];
        let mut is_first_packet = true;
        loop {
            match client_reader.read(&mut buffer).await {
                Ok(0) => break,
                Ok(bytes_read) => {
                    let data = &buffer[..bytes_read];

                    if is_enabled && is_first_packet {
                        // Извлекаем чистый домен без порта для поиска (например, "www.youtube.com")
                        let pattern = "youtube";

                        if let Some(sni_pos) = find_sni_index(data, pattern) {
                            // Режем прямо внутри слова "youtube"!
                            // sni_pos — это буква 'y'. + 2 означает, что 'y' и 'o' улетят в Чанке 1,
                            // а 'utube.com' улетит в Чанке 2.
                            let cut_offset = 2;
                            let dynamic_frag = sni_pos + cut_offset;

                            if dynamic_frag < data.len() {
                                let (first_chunk, second_chunk) = data.split_at(dynamic_frag);

                                println!("[✂️ REAL SNI SPLIT] Паттерн '{}' найден на позиции {}. Режем на индексе {}", pattern, sni_pos, dynamic_frag);

                                let msg1 = format!("[HTTPS => Server] Чанк 1: {} байт", first_chunk.len());
                                print_payload(&msg1, first_chunk);
                                if server_writer.write_all(first_chunk).await.is_err() { break; }
                                let _ = server_writer.flush().await;

                                let random_delay = {
                                    let mut rng = rand::rng();
                                    rng.random_range(ranges.delay_min_ms..=ranges.delay_max_ms)
                                };
                                println!("[HTTPS => Server] Пауза: {} мс", random_delay);
                                tokio::time::sleep(Duration::from_millis(random_delay)).await;

                                let msg2 = format!("[HTTPS => Server] Чанк 2: {} байт", second_chunk.len());
                                print_payload(&msg2, second_chunk);
                                if server_writer.write_all(second_chunk).await.is_err() { break; }
                                let _ = server_writer.flush().await;
                            } else {
                                if server_writer.write_all(data).await.is_err() { break; }
                            }
                        } else {
                            // Если домен в байтах не нашли (например, это не TLS, а другой протокол),
                            // режем по старой логике из конфига
                            let min_bound = ranges.frag_min.min(data.len());
                            let max_bound = std::cmp::min(ranges.frag_max, data.len()).max(min_bound);
                            let dynamic_frag = {
                                let mut rng = rand::rng();
                                if min_bound < max_bound { rng.random_range(min_bound..=max_bound) } else { min_bound }
                            };

                            if data.len() > dynamic_frag && dynamic_frag > 0 {
                                let (first_chunk, second_chunk) = data.split_at(dynamic_frag);
                                if server_writer.write_all(first_chunk).await.is_err() { break; }
                                let _ = server_writer.flush().await;
                                let random_delay = {
                                    let mut rng = rand::rng();
                                    rng.random_range(ranges.delay_min_ms..=ranges.delay_max_ms)
                                };
                                tokio::time::sleep(Duration::from_millis(random_delay)).await;
                                if server_writer.write_all(second_chunk).await.is_err() { break; }
                            } else {
                                if server_writer.write_all(data).await.is_err() { break; }
                            }
                        }
                        is_first_packet = false;
                    } else {
                        if server_writer.write_all(data).await.is_err() { break; }
                    }
                }
                Err(_) => break,
            }
        }
    };

    let server_to_client = async move {
        let mut buffer = [0u8; 4096];
        loop {
            match server_reader.read(&mut buffer).await {
                Ok(0) => break,
                Ok(bytes_read) => {
                    let data = &buffer[..bytes_read];
                    let msg = format!("[HTTPS <= Server] Получен ответ: {} байт", bytes_read);
                    print_payload(&msg, data);

                    if client_writer.write_all(data).await.is_err() { break; }
                }
                Err(_) => break,
            }
        }
    };

    tokio::select! {
        _ = client_to_server => {},
        _ = server_to_client => {},
    }
    println!("[HTTPS] Туннель закрыт: {}", target);
}

async fn handle_http(
    client_stream: TcpStream,
    request_str: &str,
    raw_request: &[u8],
    ranges: Ranges,
    is_enabled: bool
) {
    let target = match parse_http_target(request_str) {
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
            println!("[-] Ошибка подключения к HTTP: {}", e);
            return;
        }
    };

    if is_enabled {
        let min_bound = ranges.frag_min.min(raw_request.len());
        let max_bound = std::cmp::min(ranges.frag_max, raw_request.len()).max(min_bound);

        let frag_size = {
            let mut rng = rand::rng();
            if min_bound < max_bound {
                rng.random_range(min_bound..=max_bound)
            } else {
                min_bound
            }
        };

        if raw_request.len() > frag_size && frag_size > 0 {
            let (first_chunk, second_chunk) = raw_request.split_at(frag_size);

            let msg1 = format!("[HTTP => Server] Чанк 1: {} байт", first_chunk.len());
            print_payload(&msg1, first_chunk);
            if server_stream.write_all(first_chunk).await.is_err() { return; }
            let _ = server_stream.flush().await;

            let random_delay = {
                let mut rng = rand::rng();
                rng.random_range(ranges.delay_min_ms..=ranges.delay_max_ms)
            };
            println!("[HTTP => Server] Искусственная пауза: {} мс", random_delay);
            tokio::time::sleep(Duration::from_millis(random_delay)).await;

            let msg2 = format!("[HTTP => Server] Чанк 2: {} байт", second_chunk.len());
            print_payload(&msg2, second_chunk);
            if server_stream.write_all(second_chunk).await.is_err() { return; }
            let _ = server_stream.flush().await;
        } else {
            let msg = format!("[HTTP => Server] {} байт", raw_request.len());
            print_payload(&msg, raw_request);
            if server_stream.write_all(raw_request).await.is_err() { return; }
            let _ = server_stream.flush().await;
        }
    } else {
        let msg = format!("[HTTP => Server] {} байт (без модификаций)", raw_request.len());
        print_payload(&msg, raw_request);
        if server_stream.write_all(raw_request).await.is_err() { return; }
        let _ = server_stream.flush().await;
    }

    let (mut client_reader, mut client_writer) = client_stream.into_split();
    let (mut server_reader, mut server_writer) = server_stream.into_split();

    let client_to_server = async move {
        let mut buffer = [0u8; 4096];
        loop {
            match client_reader.read(&mut buffer).await {
                Ok(0) => break,
                Ok(bytes_read) => {
                    if server_writer.write_all(&buffer[..bytes_read]).await.is_err() { break; }
                }
                Err(_) => break,
            }
        }
    };

    let server_to_client = async move {
        let mut buffer = [0u8; 4096];
        loop {
            match server_reader.read(&mut buffer).await {
                Ok(0) => break,
                Ok(bytes_read) => {
                    let data = &buffer[..bytes_read];
                    let msg = format!("[HTTP <= Server] Получен ответ: {} байт", bytes_read);
                    print_payload(&msg, data);
                    if client_writer.write_all(data).await.is_err() { break; }
                }
                Err(_) => break,
            }
        }
    };

    tokio::select! {
        _ = client_to_server => {},
        _ = server_to_client => {},
    }
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
            if host.contains(':') {
                return Some(host);
            } else {
                return Some(format!("{}:80", host));
            }
        }
    }
    None
}
