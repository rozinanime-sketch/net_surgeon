//! Простой кэш соответствия IP -> домен, наполняемый ответами,
//! которые наш собственный DoH-relay (dns/doh.rs) и так возвращает клиенту.
//!
//! В отличие от пассивного DNS-снифера (как в проекте SonicDPI, dns.rs),
//! который перехватывает чужой DNS-трафик на уровне пакетов, здесь мы
//! просто запоминаем ответы из наших же DoH-запросов — у нас explicit-proxy
//! архитектура, и клиент и так обращается к нам напрямую за резолвом,
//! подсматривать не нужно.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::{Duration, Instant};

const CACHE_TTL: Duration = Duration::from_secs(600);

struct Entry {
    domain: String,
    expires: Instant,
}

#[derive(Default)]
pub struct IpDomainCache {
    inner: RwLock<HashMap<IpAddr, Entry>>,
}

impl IpDomainCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn lookup(&self, ip: &IpAddr) -> Option<String> {
        let now = Instant::now();
        let guard = self.inner.read().unwrap();
        guard.get(ip).filter(|e| e.expires > now).map(|e| e.domain.clone())
    }

    pub fn insert(&self, ip: IpAddr, domain: String) {
        let mut guard = self.inner.write().unwrap();

        // Простая защита от неограниченного роста — чистим протухшие записи
        if guard.len() > 20_000 {
            let now = Instant::now();
            guard.retain(|_, e| e.expires > now);
        }

        guard.insert(ip, Entry { domain, expires: Instant::now() + CACHE_TTL });
    }
}

/// Минимальный парсер A/AAAA записей из сырого DNS-ответа (RFC 1035),
/// достаточный чтобы вытащить IP-адреса без сторонних DNS-библиотек.
pub fn extract_ips_from_dns_response(buf: &[u8]) -> Vec<IpAddr> {
    let mut ips = Vec::new();

    if buf.len() < 12 {
        return ips;
    }

    let qd = u16::from_be_bytes([buf[4], buf[5]]);
    let an = u16::from_be_bytes([buf[6], buf[7]]);
    if qd == 0 {
        return ips;
    }

    let mut p = 12usize;

    // Пропускаем вопрос (qname + qtype + qclass)
    if skip_name(buf, &mut p).is_none() {
        return ips;
    }
    if p + 4 > buf.len() {
        return ips;
    }
    p += 4;

    for _ in 0..an {
        if skip_name(buf, &mut p).is_none() {
            return ips;
        }
        if p + 10 > buf.len() {
            return ips;
        }
        let rtype = u16::from_be_bytes([buf[p], buf[p + 1]]);
        p += 8; // class(2) + ttl(4) + оставили rtype прочитанным выше
        if p + 2 > buf.len() {
            return ips;
        }
        let rdlen = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
        p += 2;
        if p + rdlen > buf.len() {
            return ips;
        }

        match rtype {
            1 if rdlen == 4 => {
                let octets = [buf[p], buf[p + 1], buf[p + 2], buf[p + 3]];
                ips.push(IpAddr::V4(std::net::Ipv4Addr::from(octets)));
            }
            28 if rdlen == 16 => {
                let mut o = [0u8; 16];
                o.copy_from_slice(&buf[p..p + 16]);
                ips.push(IpAddr::V6(std::net::Ipv6Addr::from(o)));
            }
            _ => {}
        }
        p += rdlen;
    }

    ips
}

/// Извлекает qname (имя запрошенного домена) из сырого DNS-запроса/ответа
pub fn extract_qname(buf: &[u8]) -> Option<String> {
    if buf.len() < 12 {
        return None;
    }
    let mut p = 12usize;
    read_name(buf, &mut p)
}

fn skip_name(buf: &[u8], cursor: &mut usize) -> Option<()> {
    read_name(buf, cursor).map(|_| ())
}

fn read_name(buf: &[u8], cursor: &mut usize) -> Option<String> {
    let mut out = String::new();
    let mut p = *cursor;
    let mut hops = 0usize;
    let mut jumped = false;
    let mut original_cursor = *cursor;

    loop {
        if p >= buf.len() {
            return None;
        }
        let len = buf[p];
        if len == 0 {
            p += 1;
            break;
        }
        if (len & 0xC0) == 0xC0 {
            if p + 1 >= buf.len() {
                return None;
            }
            let off = (((len & 0x3F) as usize) << 8) | (buf[p + 1] as usize);
            if !jumped {
                original_cursor = p + 2;
                jumped = true;
            }
            p = off;
            hops += 1;
            if hops > 16 {
                return None;
            }
            continue;
        }
        let label_end = p + 1 + len as usize;
        if label_end > buf.len() {
            return None;
        }
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(std::str::from_utf8(&buf[p + 1..label_end]).ok()?);
        if out.len() > 255 {
            return None;
        }
        p = label_end;
    }

    *cursor = if jumped { original_cursor } else { p };
    Some(out)
}
