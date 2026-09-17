//! Единый парсер SOCKS5-адреса (ATYP IPv4/domain/IPv6) — реализация взята
//! из старого socks5/tcp.rs::parse_target (самая полная версия в проекте)
//! и переиспользуется теперь и в socks5/tcp.rs (CONNECT), и в socks5/udp.rs
//! (UDP ASSOCIATE), вместо двух независимых копий (вторая — в socks5/udp.rs
//! старого проекта — понимала только ATYP 0x01/IPv4, остальное молча дропала).
//!
//! HTTP CONNECT / Host-заголовок (proxy/tcp.rs) — отдельный протокол,
//! формат целевого адреса там текстовый (не бинарный SOCKS5 ATYP), поэтому
//! туда этот парсер не переносится; унификация HTTP-парсеров — отдельная
//! задача на будущее, не блокирующая эту.

/// Разбирает адрес назначения из SOCKS5-запроса (CONNECT или UDP ASSOCIATE) —
/// в обоих форматах байт [3] это ATYP, дальше DST.ADDR + DST.PORT одинаково.
/// Возвращает (адрес как "host:port" или "[ipv6]:port", число прочитанных байт).
pub fn parse_socks5_target(request: &[u8]) -> Option<(String, usize)> {
    if request.len() < 4 {
        return None;
    }

    let atyp = request[3];
    match atyp {
        0x01 => {
            if request.len() < 10 {
                return None;
            }
            let ip = format!("{}.{}.{}.{}", request[4], request[5], request[6], request[7]);
            let port = u16::from_be_bytes([request[8], request[9]]);
            Some((format!("{}:{}", ip, port), 10))
        }
        0x03 => {
            if request.len() < 5 {
                return None;
            }
            let len = request[4] as usize;
            if request.len() < 5 + len + 2 {
                return None;
            }
            let domain = std::str::from_utf8(&request[5..5 + len]).ok()?.to_string();
            let port = u16::from_be_bytes([request[5 + len], request[5 + len + 1]]);
            Some((format!("{}:{}", domain, port), 5 + len + 2))
        }
        0x04 => {
            if request.len() < 22 {
                return None;
            }
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&request[4..20]);
            let ip = std::net::Ipv6Addr::from(ip_bytes);
            let port = u16::from_be_bytes([request[20], request[21]]);
            Some((format!("[{}]:{}", ip, port), 22))
        }
        _ => None,
    }
}
