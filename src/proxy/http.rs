use std::collections::HashSet;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::bypass::{extract_domain, needs_bypass};
use crate::observability::logging::{LogSender, log_t, LogLevel};
use crate::observability::metrics::Metrics;
use super::tcp::parse_http_target;
use crate::protocol::http::rewrite_for_origin;

/// Обычный HTTP (порт 80) — простая пересылка, без обхода.
///
/// Фрагментация запроса отсюда удалена. Она резала plaintext-запрос на два
/// куска, но имя хоста в открытом HTTP видно провайдеру и так, на уровне
/// заголовка `Host:`, — а разрыв TCP-потока не мешает его прочитать никакому
/// DPI, который собирает поток. Обход живёт в HTTPS-пути, где есть TLS
/// ClientHello и есть что прятать.
///
/// Путь оставлен рабочим, чтобы `http://`-сайты через прокси открывались,
/// но развивать его незачем.
pub async fn handle_http(
    client_stream: TcpStream,
    request_str: &str,
    // Байты, пришедшие следом за заголовками (начало тела запроса).
    body_prefix: &[u8],
    is_enabled: bool,
    bypass_domains: Arc<HashSet<String>>,
    log_tx: LogSender,
    metrics: Arc<Metrics>,
) {
    let target = match parse_http_target(request_str) {
        Some(t) => t,
        None => { log_t(&log_tx, LogLevel::Warning, "log.http_host_error", vec![]); return; }
    };

    let domain = extract_domain(&target);
    let bypass = needs_bypass(is_enabled, &domain, &bypass_domains);

    let mut server_stream = match crate::dns::resolver::connect(&target).await {
        Ok(s) => s,
        Err(e) => {
            log_t(&log_tx, LogLevel::Error, "log.http_connect_error", vec![("target", target.clone()), ("error", e.to_string())]);
            return;
        }
    };

    log_t(&log_tx, LogLevel::Success, "log.http_request", vec![("target", target.clone()), ("bypass", bypass.to_string())]);

    // Серверу уходит один запрос с `Connection: close`: иначе следующие
    // запросы keep-alive соединения, адресованные другим хостам, ушли бы
    // на этот же сервер (см. rewrite_for_origin).
    let head = rewrite_for_origin(request_str);
    metrics.add_rx((request_str.len() + body_prefix.len()) as u64);
    if server_stream.write_all(head.as_bytes()).await.is_err() { return; }
    if !body_prefix.is_empty() && server_stream.write_all(body_prefix).await.is_err() { return; }
    let _ = server_stream.flush().await;

    let (mut client_reader, mut client_writer) = client_stream.into_split();
    let (mut server_reader, mut server_writer) = server_stream.into_split();

    let metrics_c2s = Arc::clone(&metrics);
    let client_to_server = async move {
        let mut buffer = [0u8; 4096];
        loop {
            match client_reader.read(&mut buffer).await {
                Ok(0) => { let _ = server_writer.shutdown().await; break; }
                Ok(bytes_read) => {
                    metrics_c2s.add_rx(bytes_read as u64);
                    if server_writer.write_all(&buffer[..bytes_read]).await.is_err() { break; }
                }
                Err(_) => break,
            }
        }
    };

    let metrics_s2c = Arc::clone(&metrics);
    let server_to_client = async move {
        let mut buffer = [0u8; 4096];
        loop {
            match server_reader.read(&mut buffer).await {
                Ok(0) => { let _ = client_writer.shutdown().await; break; }
                Ok(bytes_read) => {
                    let data = &buffer[..bytes_read];
                    metrics_s2c.add_tx(bytes_read as u64);
                    if client_writer.write_all(data).await.is_err() { break; }
                }
                Err(_) => break,
            }
        }
    };

    // Сервер закрыл соединение (а после `Connection: close` он это сделает) —
    // пересылка от клиента дальше не нужна: всё, что клиент пришлёт по этому
    // соединению, адресовано уже не этому серверу. Если же первым закончил
    // клиент, ответ сервера дочитывается до конца.
    tokio::pin!(client_to_server, server_to_client);
    tokio::select! {
        _ = &mut server_to_client => {}
        _ = &mut client_to_server => { server_to_client.await; }
    }
}
