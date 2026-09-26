use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;
use std::time::{Duration, Instant};

const CACHE_TTL: Duration = Duration::from_secs(600);

struct Entry { domain: String, expires: Instant }

#[derive(Default)]
pub struct IpDomainCache { inner: RwLock<HashMap<IpAddr, Entry>> }

impl IpDomainCache {
    pub fn new() -> Self { Self::default() }

    pub fn lookup(&self, ip: &IpAddr) -> Option<String> {
        let now = Instant::now();
        let guard = self.inner.read().unwrap_or_else(|e| e.into_inner());
        guard.get(ip).filter(|e| e.expires > now).map(|e| e.domain.clone())
    }

    pub fn insert(&self, ip: IpAddr, domain: String) {
        // Имя приводится к виду списков обхода: они в нижнем регистре и без
        // точки в конце, а сравнение с ними точное. DoH-релей клал имя из
        // запроса как есть, и `YouTube.com` по IP обхода не получал.
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        let mut guard = self.inner.write().unwrap_or_else(|e| e.into_inner());
        if guard.len() > 20_000 {
            let now = Instant::now();
            guard.retain(|_, e| e.expires > now);
        }
        guard.insert(ip, Entry { domain, expires: Instant::now() + CACHE_TTL });
    }
}

pub fn extract_ips_from_dns_response(buf: &[u8]) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    if buf.len() < 12 { return ips; }

    let qd = u16::from_be_bytes([buf[4], buf[5]]);
    let an = u16::from_be_bytes([buf[6], buf[7]]);
    if qd == 0 { return ips; }

    // Пропускаем ВСЕ секции вопроса, а не одну. Раньше пропускалась ровно
    // одна, и при QDCOUNT больше единицы второй вопрос разбирался как
    // ответная запись: у вопроса нет TTL и RDLENGTH, курсор уезжал на восемь
    // байт вперёд и читал длину из мусора. В кэш «адрес → домен» мог попасть
    // выдуманный адрес, а по нему решается, обходить ли соединение.
    let mut p = 12usize;
    for _ in 0..qd {
        if skip_name(buf, &mut p).is_none() { return ips; }
        // QTYPE(2) + QCLASS(2)
        if p + 4 > buf.len() { return ips; }
        p += 4;
    }

    for _ in 0..an {
        if skip_name(buf, &mut p).is_none() { return ips; }
        if p + 10 > buf.len() { return ips; }
        let rtype = u16::from_be_bytes([buf[p], buf[p + 1]]);
        p += 8;
        if p + 2 > buf.len() { return ips; }
        let rdlen = u16::from_be_bytes([buf[p], buf[p + 1]]) as usize;
        p += 2;
        if p + rdlen > buf.len() { return ips; }

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

/// Ответ NXDOMAIN на запрос: тот же ID и вопрос, без записей.
///
/// NXDOMAIN, а не адрес 0.0.0.0: он годится для любого типа запроса
/// (A, AAAA, HTTPS), и клиенту не с чем пытаться соединиться. Секция
/// дополнительных записей (EDNS) отбрасывается вместе со своим счётчиком.
pub fn nxdomain_response(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 { return None; }
    // Только стандартный запрос: ответ на что-то другое — не наше дело.
    if query[2] & 0x80 != 0 || (query[2] >> 3) & 0x0F != 0 { return None; }

    let qd = u16::from_be_bytes([query[4], query[5]]);
    let mut p = 12usize;
    for _ in 0..qd {
        skip_name(query, &mut p)?;
        if p + 4 > query.len() { return None; }
        p += 4;
    }

    let mut out = query[..p].to_vec();
    // QR = 1, RD копируется из запроса; RA = 1, RCODE = 3 (NXDOMAIN).
    out[2] = 0x80 | (query[2] & 0x01);
    out[3] = 0x80 | 0x03;
    // ANCOUNT, NSCOUNT, ARCOUNT
    out[6..12].fill(0);
    Some(out)
}

pub fn extract_qname(buf: &[u8]) -> Option<String> {
    if buf.len() < 12 { return None; }
    let mut p = 12usize;
    read_name(buf, &mut p)
}

fn skip_name(buf: &[u8], cursor: &mut usize) -> Option<()> { read_name(buf, cursor).map(|_| ()) }

fn read_name(buf: &[u8], cursor: &mut usize) -> Option<String> {
    let mut out = String::new();
    let mut p = *cursor;
    let mut hops = 0usize;
    let mut jumped = false;
    let mut original_cursor = *cursor;

    loop {
        if p >= buf.len() { return None; }
        let len = buf[p];
        if len == 0 { p += 1; break; }
        if (len & 0xC0) == 0xC0 {
            if p + 1 >= buf.len() { return None; }
            let off = (((len & 0x3F) as usize) << 8) | (buf[p + 1] as usize);
            if !jumped { original_cursor = p + 2; jumped = true; }
            p = off;
            hops += 1;
            if hops > 16 { return None; }
            continue;
        }
        let label_end = p + 1 + len as usize;
        if label_end > buf.len() { return None; }
        if !out.is_empty() { out.push('.'); }
        out.push_str(std::str::from_utf8(&buf[p + 1..label_end]).ok()?);
        if out.len() > 255 { return None; }
        p = label_end;
    }

    *cursor = if jumped { original_cursor } else { p };
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Собирает DNS-ответ: `questions` секций вопроса и один A-ответ.
    fn response(questions: usize, name: &[u8], ip: [u8; 4]) -> Vec<u8> {
        let mut out = vec![0x00, 0x00, 0x81, 0x80];
        out.extend_from_slice(&(questions as u16).to_be_bytes()); // QDCOUNT
        out.extend_from_slice(&[0x00, 0x01]); // ANCOUNT
        out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // NS + AR

        let question = |out: &mut Vec<u8>| {
            for label in name.split(|b| *b == b'.') {
                out.push(label.len() as u8);
                out.extend_from_slice(label);
            }
            out.push(0x00);
            out.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A QCLASS=IN
        };
        for _ in 0..questions {
            question(&mut out);
        }

        out.extend_from_slice(&[0xc0, 0x0c]); // указатель на имя из вопроса
        out.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // TYPE=A CLASS=IN
        out.extend_from_slice(&[0x00, 0x00, 0x01, 0x2c]); // TTL
        out.extend_from_slice(&[0x00, 0x04]); // RDLENGTH
        out.extend_from_slice(&ip);
        out
    }

    #[test]
    fn reads_the_address_from_an_ordinary_response() {
        let buf = response(1, b"example.com", [93, 184, 216, 34]);
        assert_eq!(
            extract_ips_from_dns_response(&buf),
            vec![IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 216, 34))]
        );
    }

    /// При QDCOUNT больше единицы пропускались не все вопросы, и второй
    /// разбирался как ответная запись: в кэш попадал выдуманный адрес.
    #[test]
    fn skips_every_question_section() {
        let buf = response(2, b"example.com", [93, 184, 216, 34]);
        assert_eq!(
            extract_ips_from_dns_response(&buf),
            vec![IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 216, 34))]
        );
    }

    #[test]
    fn truncated_response_yields_nothing() {
        let buf = response(1, b"example.com", [93, 184, 216, 34]);
        assert!(extract_ips_from_dns_response(&buf[..buf.len() - 3]).is_empty());
        assert!(extract_ips_from_dns_response(&buf[..8]).is_empty());
    }

    /// Запрос mc.yandex.ru типа A с EDNS-записью в конце, как шлёт резолвер.
    fn query(name: &[u8]) -> Vec<u8> {
        let mut out = vec![0xab, 0xcd, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        for label in name.split(|b| *b == b'.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label);
        }
        out.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
        // OPT: имя корня, TYPE=41, размер UDP, флаги, RDLENGTH=0
        out.extend_from_slice(&[0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        out
    }

    #[test]
    fn nxdomain_keeps_id_and_question_and_drops_the_rest() {
        let q = query(b"mc.yandex.ru");
        let r = nxdomain_response(&q).expect("стандартный запрос");

        assert_eq!(&r[..2], &[0xab, 0xcd], "ID запроса");
        assert_eq!(r[2], 0x81, "QR и RD из запроса");
        assert_eq!(r[3] & 0x0f, 3, "RCODE = NXDOMAIN");
        assert_eq!(&r[4..12], &[0, 1, 0, 0, 0, 0, 0, 0], "один вопрос, записей нет");
        assert_eq!(extract_qname(&r).as_deref(), Some("mc.yandex.ru"));
        // Вопрос целиком, EDNS отброшен.
        assert_eq!(r.len(), 12 + 14 + 4);
        assert!(extract_ips_from_dns_response(&r).is_empty());
    }

    #[test]
    fn nxdomain_refuses_what_is_not_a_query() {
        let mut q = query(b"mc.yandex.ru");
        assert!(nxdomain_response(&q[..10]).is_none());
        assert!(nxdomain_response(&q[..20]).is_none(), "обрезанный вопрос");
        q[2] |= 0x80;
        assert!(nxdomain_response(&q).is_none(), "это уже ответ");
    }
}
