use quinn::{Endpoint, ServerConfig, Connection};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use rustls::crypto::ring;

// Генерируем самоподписанный сертификат при старте
fn generate_self_signed_cert() -> (
    CertificateDer<'static>,
    PrivateKeyDer<'static>,
) {
    let cert = rcgen::generate_simple_self_signed(
        vec!["localhost".to_string()]
    ).unwrap();

    let cert_der = CertificateDer::from(
        cert.cert.der().to_vec()
    );
    let key_der = PrivateKeyDer::try_from(
        cert.signing_key.serialize_der()
    ).unwrap();

    (cert_der, key_der)
}

fn make_server_config() -> ServerConfig {
    let (cert, key) = generate_self_signed_cert();

    let mut tls_config = rustls::ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)
    .unwrap();

    tls_config.alpn_protocols = vec![
        b"hq-29".to_vec(),  // HTTP/3
    ];

    ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(
            tls_config
        ).unwrap()
    ))
}

pub async fn run_quic_proxy(
    listen_port: u16,
    target: String,
) {
    let _ = rustls::crypto::ring::default_provider()
        .install_default();

    let listen_addr = format!("0.0.0.0:{}", listen_port)
    .parse()
    .unwrap();

    let server_config = make_server_config();

    let endpoint = Endpoint::server(server_config, listen_addr)
    .expect("Ошибка: не удалось создать QUIC endpoint");

    println!(
        "[QUIC] Прокси слушает: {}",
        listen_addr
    );

    while let Some(incoming) = endpoint.accept().await {
        let target = target.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    println!(
                        "[QUIC] Новое соединение от: {}",
                        conn.remote_address()
                    );
                    handle_quic_connection(conn, target).await;
                }
                Err(e) => {
                    println!("[-] QUIC ошибка соединения: {}", e);
                }
            }
        });
    }
}

async fn handle_quic_connection(
    conn: Connection,
    target: String,
) {
    loop {
        // Принимаем новый двунаправленный стрим
        match conn.accept_bi().await {
            Ok((mut send, mut recv)) => {
                let target = target.clone();
                tokio::spawn(async move {
                    handle_quic_stream(
                        &mut send,
                        &mut recv,
                        &target,
                    ).await;
                });
            }
            Err(e) => {
                println!(
                    "[QUIC] Соединение закрыто: {}",
                    e
                );
                break;
            }
        }
    }
}

async fn handle_quic_stream(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    target: &str,
) {
    // Читаем данные от клиента
    let mut buf = vec![0u8; 65535];
    let n = match recv.read(&mut buf).await {
        Ok(Some(n)) => n,
        _ => return,
    };

    let data = &buf[..n];
    println!(
        "[QUIC] Стрим: {} байт -> {}",
        n, target
    );

    // Подключаемся к целевому серверу через TCP
    // (QUIC -> TCP мост)
    let mut server = match tokio::net::TcpStream::connect(target).await {
        Ok(s) => s,
        Err(e) => {
            println!("[-] QUIC->TCP ошибка: {}", e);
            return;
        }
    };

    // Отправляем данные на сервер
    if server.write_all(data).await.is_err() {
        return;
    }

    // Читаем ответ и отправляем клиенту
    let mut resp_buf = vec![0u8; 65535];
    match server.read(&mut resp_buf).await {
        Ok(n) if n > 0 => {
            let _ = send.write_all(&resp_buf[..n]).await;
        }
        _ => {}
    }
}
