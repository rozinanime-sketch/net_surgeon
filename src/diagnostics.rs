use std::time::Duration;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::BypassParams;
use crate::bypass::fragment;

#[derive(Debug, Clone)]
pub struct DiagnosticResult {
    pub domain: String,
    pub direct_connect_ok: bool,
    pub direct_tls_ok: bool,
    pub bypass_connect_ok: bool,
    pub bypass_tls_ok: bool,
}

/// Собирает минимальный, но валидный TLS 1.2/1.3 ClientHello с заданным SNI.
/// Это диагностический зонд — не несёт реальной криптографии, только
/// чтобы DPI увидел "настоящий" ClientHello и среагировал так же, как на реальный трафик.
fn build_client_hello(sni: &str) -> Vec<u8> {
    let mut hello_body = Vec::new();

    // Client Version: TLS 1.2 (0x0303) в самом ClientHello, реальная версия
    // согласовывается через extension supported_versions
    hello_body.extend_from_slice(&[0x03, 0x03]);

    // Random: 32 байта
    let random: [u8; 32] = rand::random();
    hello_body.extend_from_slice(&random);

    // Session ID: пусто
    hello_body.push(0x00);

    // Cipher Suites
    let cipher_suites: &[u8] = &[
        0x13, 0x01, // TLS_AES_128_GCM_SHA256
        0x13, 0x02, // TLS_AES_256_GCM_SHA384
        0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
        0xc0, 0x2f, // ECDHE-RSA-AES128-GCM-SHA256
        0xc0, 0x30, // ECDHE-RSA-AES256-GCM-SHA384
    ];
    hello_body.extend_from_slice(&(cipher_suites.len() as u16).to_be_bytes());
    hello_body.extend_from_slice(cipher_suites);

    // Compression methods: только null
    hello_body.push(0x01);
    hello_body.push(0x00);

    // === Extensions ===
    let mut extensions = Vec::new();

    // SNI extension (0x0000)
    let sni_bytes = sni.as_bytes();
    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&((sni_bytes.len() + 3) as u16).to_be_bytes());
    sni_ext.push(0x00); // name_type: host_name
    sni_ext.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(sni_bytes);

    extensions.extend_from_slice(&[0x00, 0x00]);
    extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni_ext);

    // supported_versions extension (0x002b)
    extensions.extend_from_slice(&[0x00, 0x2b]);
    extensions.extend_from_slice(&[0x00, 0x05]);
    extensions.push(0x04);
    extensions.extend_from_slice(&[0x03, 0x04]); // TLS 1.3
    extensions.extend_from_slice(&[0x03, 0x03]); // TLS 1.2

    hello_body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello_body.extend_from_slice(&extensions);

    // Handshake header: type=ClientHello(1) + 3-byte length
    let mut handshake = Vec::new();
    handshake.push(0x01);
    let len = hello_body.len() as u32;
    handshake.extend_from_slice(&len.to_be_bytes()[1..4]);
    handshake.extend_from_slice(&hello_body);

    // TLS Record header: type=handshake(22), version=TLS1.0(0x0301), length
    let mut record = Vec::new();
    record.push(0x16);
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    record
}

/// Пытается подключиться и отправить ClientHello, ждёт ответ.
/// Возвращает (соединение установлено, получен TLS-ответ).
async fn probe(
    target: &str,
    hello: &[u8],
    use_bypass: bool,
    bypass_params: &BypassParams,
) -> (bool, bool) {
    let stream = match tokio::time::timeout(
        Duration::from_secs(3),
                                            TcpStream::connect(target),
    ).await {
        Ok(Ok(s)) => s,
        _ => return (false, false),
    };

    if use_bypass {
        fragment::apply_window_clamp(&stream, bypass_params.window_clamp);
    }

    // into_split даёт владеющие половинки — то, что требует split_client_hello
    let (mut reader, mut writer) = stream.into_split();

    let write_result = if use_bypass {
        fragment::split_client_hello(&mut writer, hello, bypass_params).await
    } else {
        writer.write_all(hello).await
    };

    if write_result.is_err() {
        return (true, false);
    }

    let mut buf = [0u8; 64];
    let tls_ok = matches!(
        tokio::time::timeout(Duration::from_secs(3), reader.read(&mut buf)).await,
                          Ok(Ok(n)) if n > 0
    );

    (true, tls_ok)
}

pub async fn diagnose(domain: &str, bypass_params: &BypassParams) -> DiagnosticResult {
    let target = format!("{}:443", domain);
    let hello = build_client_hello(domain);

    let (direct_connect_ok, direct_tls_ok) = probe(&target, &hello, false, bypass_params).await;
    let (bypass_connect_ok, bypass_tls_ok) = probe(&target, &hello, true, bypass_params).await;

    DiagnosticResult {
        domain: domain.to_string(),
        direct_connect_ok,
        direct_tls_ok,
        bypass_connect_ok,
        bypass_tls_ok,
    }
}
