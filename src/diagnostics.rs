use std::time::{Duration, Instant};
use tokio::net::{TcpStream, UdpSocket};
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
    /// Отдельный исход для путей, которые в принципе не были протестированы
    /// (например QUIC, если целевой хост не поддерживает его)
    NotApplicable,
}

impl ProbeOutcome {
    pub fn description_key(&self) -> &'static str {
        match self {
            ProbeOutcome::ConnectFailed => "verdict.connect_failed",
            ProbeOutcome::ResetOnWrite => "verdict.reset_on_write",
            ProbeOutcome::SilentDrop => "verdict.silent_drop",
            ProbeOutcome::ResetAfterHello => "verdict.reset_after_hello",
            ProbeOutcome::Success => "verdict.success",
            ProbeOutcome::NotApplicable => "verdict.not_applicable",
        }
    }
}

/// Стратегия фрагментации, применяемая при зондировании TCP/TLS
#[derive(Debug, Clone, Copy)]
pub enum FragStrategy {
    /// Без обхода — контрольный прогон
    None,
    /// Split в начале ClientHello + window clamp, как в proxy/https.rs
    HttpsSplit,
    /// Фиксированные чанки по 2 байта, как в socks5/tcp.rs
    Socks5Style,
}

#[derive(Debug, Clone)]
pub struct DiagnosticResult {
    pub domain: String,
    pub direct: ProbeOutcome,
    pub https_split: ProbeOutcome,
    pub socks5_style: ProbeOutcome,
    pub quic: ProbeOutcome,
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

fn classify_write_error(_e: &std::io::Error) -> ProbeOutcome {
    ProbeOutcome::ResetOnWrite
}

fn classify_read_error(e: &std::io::Error) -> ProbeOutcome {
    use std::io::ErrorKind::*;
    match e.kind() {
        ConnectionReset | ConnectionAborted => ProbeOutcome::ResetAfterHello,
        _ => ProbeOutcome::SilentDrop,
    }
}

/// Единый TCP/TLS зонд, параметризованный стратегией фрагментации.
async fn probe_tcp(
    target: &str,
    hello: &[u8],
    strategy: FragStrategy,
    bypass_params: &BypassParams,
) -> ProbeOutcome {
    let stream = match tokio::time::timeout(
        Duration::from_secs(3),
                                            TcpStream::connect(target),
    ).await {
        Ok(Ok(s)) => s,
        _ => return ProbeOutcome::ConnectFailed,
    };

    if matches!(strategy, FragStrategy::HttpsSplit) {
        fragment::apply_window_clamp(&stream, bypass_params.window_clamp);
    }

    let (mut reader, mut writer) = stream.into_split();

    let write_started = Instant::now();
    let write_result = match strategy {
        FragStrategy::None => writer.write_all(hello).await,
        FragStrategy::HttpsSplit => fragment::split_client_hello(&mut writer, hello, bypass_params).await,
        FragStrategy::Socks5Style => fragment::fragment_socks5_style(&mut writer, hello).await,
    };

    if let Err(e) = write_result {
        return classify_write_error(&e);
    }

    let mut buf = [0u8; 64];
    match tokio::time::timeout(Duration::from_secs(3), reader.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => ProbeOutcome::Success,
        Ok(Ok(_)) => {
            if write_started.elapsed() < Duration::from_millis(500) {
                ProbeOutcome::ResetAfterHello
            } else {
                ProbeOutcome::SilentDrop
            }
        }
        Ok(Err(e)) => classify_read_error(&e),
        Err(_) => ProbeOutcome::SilentDrop,
    }
}

/// QUIC-зонд: имитирует стратегию из udp/quic.rs — отправляет структурно валидный
/// QUIC v1 Initial-пакет (long header, версия, DCID/SCID, varint length) со случайным
/// "телом" вместо настоящего CRYPTO-фрейма перед основным зондом. Такой пакет проходит
/// поверхностный структурный парсинг DPI, но не поддаётся расшифровке без ключа.
///
/// Техника генерации структурного QUIC Initial адаптирована из проекта SonicDPI
/// (fakes.rs::build_fake_quic_initial) — оригинальный подход там использовал
/// собственный xorshift-генератор без зависимости от rand; здесь используется rand
/// как уже имеющаяся зависимость проекта.
async fn probe_quic(domain: &str) -> ProbeOutcome {
    let target = format!("{}:443", domain);

    let sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return ProbeOutcome::ConnectFailed,
    };

    if sock.connect(&target).await.is_err() {
        return ProbeOutcome::ConnectFailed;
    }

    // Разогревающий пакет — сбивает DPI перед основным зондом
    let fake_packet = crate::bypass::fragment::build_fake_quic_initial();
    let _ = sock.send(&fake_packet).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Основной зонд
    let probe_packet = crate::bypass::fragment::build_fake_quic_initial();

    if sock.send(&probe_packet).await.is_err() {
        return ProbeOutcome::ResetOnWrite;
    }

    let mut buf = [0u8; 128];
    match tokio::time::timeout(Duration::from_secs(3), sock.recv(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => ProbeOutcome::Success,
        Ok(Ok(_)) => ProbeOutcome::SilentDrop,
        Ok(Err(_)) => ProbeOutcome::ResetAfterHello,
        Err(_) => ProbeOutcome::SilentDrop,
    }
}

pub async fn diagnose(domain: &str, bypass_params: &BypassParams) -> DiagnosticResult {
    let target = format!("{}:443", domain);
    let hello = build_client_hello(domain);

    let direct = probe_tcp(&target, &hello, FragStrategy::None, bypass_params).await;
    let https_split = probe_tcp(&target, &hello, FragStrategy::HttpsSplit, bypass_params).await;
    let socks5_style = probe_tcp(&target, &hello, FragStrategy::Socks5Style, bypass_params).await;
    let quic = probe_quic(domain).await;

    DiagnosticResult {
        domain: domain.to_string(),
        direct,
        https_split,
        socks5_style,
        quic,
    }
}
