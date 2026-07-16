use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use rand::prelude::*;

use crate::config::{Ranges, BypassParams};

/// TLS ClientHello split: первые split_pos байт + пауза + остаток.
pub async fn split_client_hello(
    server_writer: &mut tokio::net::tcp::OwnedWriteHalf,
    data: &[u8],
    bypass: &BypassParams,
) -> std::io::Result<()> {
    let data_len = data.len();
    let split_pos = bypass.split_pos.min(data_len);

    println!("[⚡ SPLIT] {} байт -> split {}+{}", data_len, split_pos, data_len - split_pos);

    server_writer.write_all(&data[..split_pos]).await?;
    server_writer.flush().await?;

    tokio::time::sleep(Duration::from_millis(bypass.split_delay_ms)).await;

    server_writer.write_all(&data[split_pos..]).await?;
    server_writer.flush().await?;

    Ok(())
}

/// Window clamp на TCP-сокете сервера.
pub fn apply_window_clamp(stream: &TcpStream, window: u32) {
    unsafe {
        use std::os::unix::io::AsRawFd;
        let fd = stream.as_raw_fd();
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_WINDOW_CLAMP,
            &window as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        );
    }
    println!("[🪟 WCLAMP] Window clamp={} применён", window);
}

/// HTTP-фрагментация запроса.
pub async fn fragment_http_request(
    server_stream: &mut TcpStream,
    request_bytes: &[u8],
    ranges: &Ranges,
) -> std::io::Result<()> {
    let min_bound = ranges.frag_min.min(request_bytes.len());
    let max_bound = std::cmp::min(ranges.frag_max, request_bytes.len()).max(min_bound);

    let frag_size = {
        let mut rng = rand::rng();
        if min_bound < max_bound {
            rng.random_range(min_bound..=max_bound)
        } else {
            min_bound
        }
    };

    if request_bytes.len() > frag_size && frag_size > 0 {
        let (first_chunk, second_chunk) = request_bytes.split_at(frag_size);

        println!("[HTTP => Server] Чанк 1: {} байт (bypass)", first_chunk.len());
        server_stream.write_all(first_chunk).await?;
        server_stream.flush().await?;

        let random_delay = {
            let mut rng = rand::rng();
            rng.random_range(ranges.delay_min_ms..=ranges.delay_max_ms)
        };
        println!("[HTTP => Server] Пауза: {} мс", random_delay);
        tokio::time::sleep(Duration::from_millis(random_delay)).await;

        println!("[HTTP => Server] Чанк 2: {} байт", second_chunk.len());
        server_stream.write_all(second_chunk).await?;
        server_stream.flush().await?;
    } else {
        server_stream.write_all(request_bytes).await?;
        server_stream.flush().await?;
    }

    Ok(())
}

/// UDP jitter — случайная задержка перед отправкой ответа клиенту
pub async fn apply_udp_jitter(ranges: &Ranges) {
    let jitter = {
        let mut rng = rand::rng();
        rng.random_range(ranges.udp_jitter_min_ms..=ranges.udp_jitter_max_ms)
    };
    println!("[UDP <= Server] Задержка джиттера: {} мс", jitter);
    tokio::time::sleep(Duration::from_millis(jitter)).await;
}

pub async fn fragment_socks5_style<W>(writer: &mut W, data: &[u8]) -> std::io::Result<()>
where
W: tokio::io::AsyncWriteExt + Unpin,
{
    let frag_size = 2;
    for chunk in data.chunks(frag_size) {
        writer.write_all(chunk).await?;
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    Ok(())
}

/// Собирает синтетический QUIC v1 Initial-пакет с валидным структурным заголовком
/// (long header, version, DCID/SCID, varint length, packet number) и случайным
/// "телом" вместо настоящего зашифрованного CRYPTO-фрейма.
///
/// В отличие от чисто случайных байт, такой пакет проходит поверхностный
/// структурный парсинг DPI (выглядит как настоящий QUIC Initial по формату RFC 9000),
/// но расшифровать его невозможно — внутри бессмысленный шум.
///
/// Подход адаптирован из проекта SonicDPI (fakes.rs::build_fake_quic_initial).
pub fn build_fake_quic_initial() -> Vec<u8> {
    use rand::prelude::*;
    let mut rng = rand::rng();

    let dcid_len: usize = 8;
    let scid_len: usize = 0;

    // Целимся в ~1200 байт — типичный MTU-заполненный Initial настоящего браузера
    let header_len = 1 + 4 + 1 + dcid_len + 1 + scid_len + 1 + 2 + 1;
    let payload_len = 1200usize.saturating_sub(header_len);

    let mut out = Vec::with_capacity(1200);

    // 0xC0 = long-header(1) + fixed-bit(1) + type Initial(00) + младшие биты
    out.push(0xC0);
    // version = 1 (QUIC v1, RFC 9000)
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);

    out.push(dcid_len as u8);
    let mut dcid = vec![0u8; dcid_len];
    rng.fill(&mut dcid[..]);
    out.extend_from_slice(&dcid);

    out.push(scid_len as u8);
    // token length (varint, 0 — токен отсутствует)
    out.push(0x00);

    // Length как 2-байтовый varint (диапазон 64..=16383): старшие два бита 0b01
    let varint = 0x4000u16 | (payload_len as u16 + 1);
    out.extend_from_slice(&varint.to_be_bytes());

    // Однобайтовый packet number
    out.push(0x00);

    // Случайное "тело" — имитация зашифрованного CRYPTO-фрейма + AEAD tag
    let mut body = vec![0u8; payload_len];
    rng.fill(&mut body[..]);
    out.extend_from_slice(&body);

    out
}
