use quinn::{Endpoint, ServerConfig, Connection};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;

fn generate_self_signed_cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap();
    (cert_der, key_der)
}

fn make_server_config() -> ServerConfig {
    let (cert, key) = generate_self_signed_cert();
    let mut tls_config = rustls::ServerConfig::builder()
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)
    .unwrap();

    tls_config.alpn_protocols = vec![b"hq-29".to_vec(), b"h3".to_vec()]; // Добавлен h3 для совместимости

    ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config).unwrap()
    ))
}

pub async fn run_quic_proxy(listen_port: u16, target: String) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let listen_addr = format!("0.0.0.0:{}", listen_port).parse().unwrap();
    let server_config = make_server_config();
    let endpoint = Endpoint::server(server_config, listen_addr)
    .expect("Ошибка: не удалось создать QUIC endpoint");

    println!("[QUIC] Прокси слушает: {}", listen_addr);

    while let Some(incoming) = endpoint.accept().await {
        let target = target.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    println!("[QUIC] Новое соединение от: {}", conn.remote_address());
                    handle_quic_connection(conn, target).await;
                }
                Err(e) => println!("[-] QUIC ошибка соединения: {}", e),
            }
        });
    }
}

async fn handle_quic_connection(conn: Connection, target: String) {
    loop {
        match conn.accept_bi().await {
            Ok((mut send, mut recv)) => {
                let target = target.clone();
                tokio::spawn(async move {
                    handle_quic_stream(&mut send, &mut recv, &target).await;
                });
            }
            Err(e) => {
                println!("[QUIC] Соединение закрыто: {}", e);
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
    // Подключаемся к целевому серверу по TCP
    let server = match tokio::net::TcpStream::connect(target).await {
        Ok(s) => s,
        Err(e) => {
            println!("[-] QUIC->TCP ошибка подключения к {}: {}", target, e);
            return;
        }
    };

    // Разделяем TCP сокет на чтение и запись
    let (mut tcp_reader, mut tcp_writer) = server.into_split();

    // Исправлено: Запускаем полноценное двустороннее копирование
    let client_to_server = tokio::io::copy(recv, &mut tcp_writer);
    let server_to_client = tokio::io::copy(&mut tcp_reader, send);

    // Ждем завершения передачи в любую из сторон
    tokio::select! {
        res = client_to_server => {
            if let Err(e) = res {
                println!("[-] Ошибка QUIC -> TCP: {}", e);
            }
        }
        res = server_to_client => {
            if let Err(e) = res {
                println!("[-] Ошибка TCP -> QUIC: {}", e);
            }
        }
    }
}
