use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::BypassParams;
use crate::bypass::fragment;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    ConnectFailed,
    ResetOnWrite,
    SilentDrop,
    ResetAfterHello,
    Success,
}

impl ProbeOutcome {
    pub fn description_key(&self) -> &'static str {
        match self {
            ProbeOutcome::ConnectFailed => "verdict.connect_failed",
            ProbeOutcome::ResetOnWrite => "verdict.reset_on_write",
            ProbeOutcome::SilentDrop => "verdict.silent_drop",
            ProbeOutcome::ResetAfterHello => "verdict.reset_after_hello",
            ProbeOutcome::Success => "verdict.success",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DiagnosticResult {
    pub domain: String,
    pub direct: ProbeOutcome,
    pub bypass: ProbeOutcome,
}

/// Собирает минимальный, но валидный TLS 1.2/1.3 ClientHello с заданным SNI.
fn build_client_hello(sni: &str) -> Vec<u8> {
    let mut hello_body = Vec::new();

    hello_body.extend_from_slice(&[0x03, 0x03]);

    let random: [u8; 32] = rand::random();
    hello_body.extend_from_slice(&random);

    hello_body.push(0x00);

    let cipher_suites: &[u8] = &[
        0x13, 0x01, 0x13, 0x02, 0x13, 0x03,
        0xc0, 0x2f, 0xc0, 0x30,
    ];
    hello_body.extend_from_slice(&(cipher_suites.len() as u16).to_be_bytes());
    hello_body.extend_from_slice(cipher_suites);

    hello_body.push(0x01);
    hello_body.push(0x00);

    let mut extensions = Vec::new();

    let sni_bytes = sni.as_bytes();
    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&((sni_bytes.len() + 3) as u16).to_be_bytes());
    sni_ext.push(0x00);
    sni_ext.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(sni_bytes);

    extensions.extend_from_slice(&[0x00, 0x00]);
    extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni_ext);

    extensions.extend_from_slice(&[0x00, 0x2b]);
    extensions.extend_from_slice(&[0x00, 0x05]);
    extensions.push(0x04);
    extensions.extend_from_slice(&[0x03, 0x04]);
    extensions.extend_from_slice(&[0x03, 0x03]);

    hello_body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello_body.extend_from_slice(&extensions);

    let mut handshake = Vec::new();
    handshake.push(0x01);
    let len = hello_body.len() as u32;
    handshake.extend_from_slice(&len.to_be_bytes()[1..4]);
    handshake.extend_from_slice(&hello_body);

    let mut record = Vec::new();
    record.push(0x16);
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    record
}

/// Классифицирует ошибку io::Error в категорию исхода.
fn classify_write_error(e: &std::io::Error) -> ProbeOutcome {
    use std::io::ErrorKind::*;
    match e.kind() {
        ConnectionReset | ConnectionAborted | BrokenPipe => ProbeOutcome::ResetOnWrite,
        _ => ProbeOutcome::ResetOnWrite, // любая ошибка записи трактуем как немедленный сброс
    }
}

fn classify_read_error(e: &std::io::Error) -> ProbeOutcome {
    use std::io::ErrorKind::*;
    match e.kind() {
        ConnectionReset | ConnectionAborted => ProbeOutcome::ResetAfterHello,
        _ => ProbeOutcome::SilentDrop,
    }
}

async fn probe(
    target: &str,
    hello: &[u8],
    use_bypass: bool,
    bypass_params: &BypassParams,
) -> ProbeOutcome {
    let stream = match tokio::time::timeout(
        Duration::from_secs(3),
                                            TcpStream::connect(target),
    ).await {
        Ok(Ok(s)) => s,
        _ => return ProbeOutcome::ConnectFailed,
    };

    if use_bypass {
        fragment::apply_window_clamp(&stream, bypass_params.window_clamp);
    }

    let (mut reader, mut writer) = stream.into_split();

    let write_started = Instant::now();
    let write_result = if use_bypass {
        fragment::split_client_hello(&mut writer, hello, bypass_params).await
    } else {
        writer.write_all(hello).await
    };

    if let Err(e) = write_result {
        return classify_write_error(&e);
    }

    let mut buf = [0u8; 64];
    match tokio::time::timeout(Duration::from_secs(3), reader.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => ProbeOutcome::Success,
        Ok(Ok(_)) => {
            // n == 0: соединение закрыто без данных (FIN). Если это случилось быстро
            // после отправки — похоже на реакцию DPI, иначе просто пустой ответ сервера.
            if write_started.elapsed() < Duration::from_millis(500) {
                ProbeOutcome::ResetAfterHello
            } else {
                ProbeOutcome::SilentDrop
            }
        }
        Ok(Err(e)) => classify_read_error(&e),
        Err(_) => ProbeOutcome::SilentDrop, // таймаут чтения — тишина
    }
}

pub async fn diagnose(domain: &str, bypass_params: &BypassParams) -> DiagnosticResult {
    let target = format!("{}:443", domain);
    let hello = build_client_hello(domain);

    let direct = probe(&target, &hello, false, bypass_params).await;
    let bypass = probe(&target, &hello, true, bypass_params).await;

    DiagnosticResult {
        domain: domain.to_string(),
        direct,
        bypass,
    }
}
