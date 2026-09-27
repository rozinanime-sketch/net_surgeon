//! Техники обхода на уровне пакетов, как в zapret (winws).
//!
//! Чистая логика над байтами, без WinDivert: так её можно проверить тестами
//! на любой системе.
//!
//! # Зачем
//!
//! Раньше перехват в Windows разворачивал каждое HTTPS-соединение на
//! локальный прокси целиком, и через программу шёл каждый пакет в обе
//! стороны. Под нагрузкой пакеты стояли в очереди драйвера, и пинг
//! вырастал в разы. Здесь через программу идёт только первый сегмент
//! ClientHello: он режется и отправляется заново, а всё остальное
//! соединение остаётся в ядре.
//!
//! # Что возможно, а что нет
//!
//! Сегмент можно разрезать, переставить части местами или предварить
//! подделкой, но нельзя изменить число байт в потоке: ядро приложения
//! ведёт свою нумерацию, и сервер подтвердил бы байты, которых оно не
//! отправляло. Поэтому две TLS-записи (+5 байт на каждую) и OOB (+1 байт)
//! на уровне пакетов недоступны — они остаются у прокси.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const IPPROTO_TCP: u8 = 6;
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

/// Наибольшая часть данных в одном отправляемом пакете.
///
/// С аппаратной нарезкой (LSO) Windows отдаёт перехвату исходящий пакет
/// больше MTU: делить его на сегменты должна была бы сетевая карта. Части
/// отправляются заново, и полагаться на это нельзя, поэтому они режутся
/// сами — с запасом под минимальный MTU IPv6 (1280) и заголовки.
pub const MAX_SEGMENT: usize = 1200;

/// На сколько сдвинуть номер последовательности подделки, чтобы сервер
/// её отбросил как чужую (zapret, `--dpi-desync-fooling=badseq`).
const BADSEQ_SHIFT: u32 = 10_000;

/// Разобранный TCP-пакет.
#[derive(Debug, Clone)]
pub struct Tcp {
    pub ip_len: usize,
    pub tcp_len: usize,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
}

impl Tcp {
    pub fn payload<'a>(&self, pkt: &'a [u8]) -> &'a [u8] {
        &pkt[self.ip_len + self.tcp_len..]
    }
}

/// Разбирает IPv4 или IPv6 (без заголовков расширения) с TCP внутри.
/// Фрагменты не разбираются: заголовка TCP в них может не быть.
pub fn parse(pkt: &[u8]) -> Option<Tcp> {
    let (ip_len, src, dst, total) = match pkt.first()? >> 4 {
        4 => {
            let ihl = usize::from(pkt[0] & 0x0f) * 4;
            if ihl < 20 || pkt.len() < ihl || pkt[9] != IPPROTO_TCP {
                return None;
            }
            if u16::from_be_bytes([pkt[6], pkt[7]]) & 0x3fff != 0 {
                return None;
            }
            let src = Ipv4Addr::from(<[u8; 4]>::try_from(&pkt[12..16]).ok()?);
            let dst = Ipv4Addr::from(<[u8; 4]>::try_from(&pkt[16..20]).ok()?);
            let total = usize::from(u16::from_be_bytes([pkt[2], pkt[3]]));
            (ihl, IpAddr::V4(src), IpAddr::V4(dst), total)
        }
        6 => {
            if pkt.len() < 40 || pkt[6] != IPPROTO_TCP {
                return None;
            }
            let src = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[8..24]).ok()?);
            let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[24..40]).ok()?);
            let total = 40 + usize::from(u16::from_be_bytes([pkt[4], pkt[5]]));
            (40, IpAddr::V6(src), IpAddr::V6(dst), total)
        }
        _ => return None,
    };
    // Длина из заголовка должна совпасть с тем, что пришло: иначе границы
    // данных неизвестны, и резать такой пакет нельзя.
    if total != pkt.len() {
        return None;
    }
    let tcp = pkt.get(ip_len..ip_len + 20)?;
    let tcp_len = usize::from(tcp[12] >> 4) * 4;
    if tcp_len < 20 || pkt.len() < ip_len + tcp_len {
        return None;
    }
    Some(Tcp {
        ip_len,
        tcp_len,
        src,
        dst,
        sport: u16::from_be_bytes([tcp[0], tcp[1]]),
        dport: u16::from_be_bytes([tcp[2], tcp[3]]),
        seq: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
        ack: u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]),
        flags: tcp[13],
    })
}

/// Копия пакета с другими данными и номером последовательности.
///
/// Заголовки, включая опции TCP (метки времени), берутся из исходного.
/// Длины в заголовке IP правятся здесь, контрольные суммы пересчитывает
/// вызывающий: у исходящих пакетов их часто считает сетевая карта, и в
/// перехваченном они и так недействительны.
pub fn with_payload(pkt: &[u8], t: &Tcp, payload: &[u8], seq: u32, flags: u8) -> Vec<u8> {
    let head = t.ip_len + t.tcp_len;
    let mut out = Vec::with_capacity(head + payload.len());
    out.extend_from_slice(&pkt[..head]);
    out.extend_from_slice(payload);
    set_ip_len(&mut out, t.ip_len);
    out[t.ip_len + 4..t.ip_len + 8].copy_from_slice(&seq.to_be_bytes());
    out[t.ip_len + 13] = flags;
    out
}

fn set_ip_len(pkt: &mut [u8], ip_len: usize) {
    let len = pkt.len();
    if ip_len == 40 {
        pkt[4..6].copy_from_slice(&((len - 40) as u16).to_be_bytes());
    } else {
        pkt[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    }
}

/// Сброс приложению от имени сервера — ответ на исходящий пакет `pkt`.
///
/// Номер берётся из подтверждения в самом пакете: ровно его приложение
/// ждёт от сервера, так что сброс оно примет. Опции TCP отбрасываются.
pub fn reset_for(pkt: &[u8], t: &Tcp) -> Vec<u8> {
    let mut out = Vec::with_capacity(t.ip_len + 20);
    out.extend_from_slice(&pkt[..t.ip_len]);
    let (a, b, n) = if t.ip_len == 40 { (8, 24, 16) } else { (12, 16, 4) };
    for i in 0..n {
        out.swap(a + i, b + i);
    }
    let mut tcp = [0u8; 20];
    tcp[0..2].copy_from_slice(&t.dport.to_be_bytes());
    tcp[2..4].copy_from_slice(&t.sport.to_be_bytes());
    tcp[4..8].copy_from_slice(&t.ack.to_be_bytes());
    let data_len = (pkt.len() - t.ip_len - t.tcp_len) as u32;
    tcp[8..12].copy_from_slice(&t.seq.wrapping_add(data_len).to_be_bytes());
    tcp[12] = 5 << 4;
    tcp[13] = TCP_RST | TCP_ACK;
    out.extend_from_slice(&tcp);
    // У IPv4 ещё и опции заголовка: их длина уже учтена в ip_len.
    set_ip_len(&mut out, t.ip_len);
    out
}

/// Что сделать с первым сегментом ClientHello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Technique {
    /// Отправить как есть.
    Pass,
    /// Два сегмента по границе `pos` данных.
    Split { pos: usize },
    /// Те же два сегмента, но второй уходит первым. В отличие от disorder
    /// на сокете, первой половине не нужен низкий TTL и ожидание
    /// ретрансмита: переставить пакеты можно прямо здесь.
    Disorder { pos: usize },
    /// Подделка с чужим именем и сдвинутым номером последовательности,
    /// следом настоящие данные двумя сегментами. DPI разбирает подделку,
    /// сервер её отбрасывает: номер вне его окна.
    Fake { pos: usize, decoy: Vec<u8> },
}

/// Где резать данные: посередине имени, если оно целиком в сегменте,
/// иначе после первого байта (как `--dpi-desync-split-pos=1` в zapret).
pub fn split_pos(payload: &[u8]) -> usize {
    match crate::bypass::tls::find_sni_prefix(payload) {
        Some(loc) => loc.split_point(),
        None => 1,
    }
    .clamp(1, payload.len().saturating_sub(1).max(1))
}

/// Пакеты, которые уйдут вместо исходного, в порядке отправки.
pub fn apply(pkt: &[u8], t: &Tcp, technique: &Technique) -> Vec<Vec<u8>> {
    let payload = t.payload(pkt);
    // Сегменты данных `[from, to)`, каждый не длиннее MAX_SEGMENT.
    let segments = |from: usize, to: usize| -> Vec<Vec<u8>> {
        (from..to)
            .step_by(MAX_SEGMENT)
            .map(|start| {
                let end = (start + MAX_SEGMENT).min(to);
                // PSH только у сегмента с последним байтом: так делает и ядро.
                let flags = if end == payload.len() { t.flags } else { t.flags & !TCP_PSH };
                with_payload(pkt, t, &payload[start..end], t.seq.wrapping_add(start as u32), flags)
            })
            .collect()
    };
    let halves = |pos: usize| {
        let pos = pos.min(payload.len());
        (segments(0, pos), segments(pos, payload.len()))
    };
    match technique {
        Technique::Pass => vec![pkt.to_vec()],
        _ if payload.len() < 2 => vec![pkt.to_vec()],
        Technique::Split { pos } => {
            let (a, b) = halves(*pos);
            [a, b].concat()
        }
        Technique::Disorder { pos } => {
            let (a, b) = halves(*pos);
            [b, a].concat()
        }
        Technique::Fake { pos, decoy } => {
            let decoy = &decoy[..decoy.len().min(MAX_SEGMENT)];
            let fake = with_payload(pkt, t, decoy, t.seq.wrapping_sub(BADSEQ_SHIFT), t.flags);
            let (a, b) = halves(*pos);
            [vec![fake], a, b].concat()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(payload: &[u8], flags: u8) -> Vec<u8> {
        let mut p = vec![0u8; 20 + 32];
        p[0] = 0x45;
        p[8] = 64;
        p[9] = IPPROTO_TCP;
        p[12..16].copy_from_slice(&[192, 168, 1, 10]);
        p[16..20].copy_from_slice(&[203, 0, 113, 5]);
        p[20..22].copy_from_slice(&50000u16.to_be_bytes());
        p[22..24].copy_from_slice(&443u16.to_be_bytes());
        p[24..28].copy_from_slice(&1000u32.to_be_bytes());
        p[28..32].copy_from_slice(&7777u32.to_be_bytes());
        // 32 байта TCP: 12 байт опций, как с метками времени.
        p[32] = 8 << 4;
        p[33] = flags;
        p[40..52].copy_from_slice(&[1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2]);
        p.extend_from_slice(payload);
        let len = p.len() as u16;
        p[2..4].copy_from_slice(&len.to_be_bytes());
        p
    }

    fn v6(payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 60];
        p[0] = 0x60;
        p[6] = IPPROTO_TCP;
        p[7] = 64;
        p[8..24].copy_from_slice(&"2001:db8::10".parse::<Ipv6Addr>().unwrap().octets());
        p[24..40].copy_from_slice(&"2001:db8::5".parse::<Ipv6Addr>().unwrap().octets());
        p[40..42].copy_from_slice(&50000u16.to_be_bytes());
        p[42..44].copy_from_slice(&443u16.to_be_bytes());
        p[44..48].copy_from_slice(&u32::MAX.to_be_bytes());
        p[52] = 5 << 4;
        p[53] = TCP_ACK | TCP_PSH;
        p.extend_from_slice(payload);
        let len = (p.len() - 40) as u16;
        p[4..6].copy_from_slice(&len.to_be_bytes());
        p
    }

    /// Все части вместе дают ровно исходные данные на своих местах.
    fn reassemble(parts: &[Vec<u8>], base_seq: u32) -> Vec<u8> {
        let mut out = Vec::new();
        let mut pieces: Vec<(u32, Vec<u8>)> = parts
            .iter()
            .map(|p| {
                let t = parse(p).expect("часть разбирается");
                (t.seq.wrapping_sub(base_seq), t.payload(p).to_vec())
            })
            .filter(|(off, _)| *off < 1 << 20) // подделка с badseq — не в окне
            .collect();
        pieces.sort_by_key(|(off, _)| *off);
        for (off, data) in pieces {
            assert_eq!(off as usize, out.len(), "без дыр и наложений");
            out.extend_from_slice(&data);
        }
        out
    }

    #[test]
    fn parse_reads_ports_seq_and_payload() {
        let pkt = v4(b"hello", TCP_ACK | TCP_PSH);
        let t = parse(&pkt).unwrap();
        assert_eq!((t.sport, t.dport, t.seq, t.ack), (50000, 443, 1000, 7777));
        assert_eq!(t.tcp_len, 32);
        assert_eq!(t.payload(&pkt), b"hello");
    }

    #[test]
    fn length_mismatch_and_fragments_are_not_parsed() {
        let mut pkt = v4(b"hello", TCP_ACK);
        pkt.push(0);
        assert!(parse(&pkt).is_none(), "лишний байт после данных");
        let mut frag = v4(b"hello", TCP_ACK);
        frag[6] = 0x20;
        assert!(parse(&frag).is_none());
    }

    #[test]
    fn split_keeps_the_stream_and_fixes_lengths() {
        let hello = crate::bypass::tls::build_client_hello_sized("discord.com", 517);
        let pkt = v4(&hello, TCP_ACK | TCP_PSH);
        let t = parse(&pkt).unwrap();
        let pos = split_pos(t.payload(&pkt));
        let loc = crate::bypass::tls::find_sni(&hello).unwrap();
        assert!(pos > loc.offset && pos < loc.offset + loc.len, "разрез внутри имени");

        let parts = apply(&pkt, &t, &Technique::Split { pos });
        assert_eq!(parts.len(), 2);
        for p in &parts {
            let pt = parse(p).expect("длина в заголовке IP совпадает с пакетом");
            assert_eq!(pt.tcp_len, 32, "опции TCP сохранены");
        }
        assert_eq!(parse(&parts[0]).unwrap().flags & TCP_PSH, 0);
        assert_ne!(parse(&parts[1]).unwrap().flags & TCP_PSH, 0);
        assert_eq!(reassemble(&parts, 1000), hello);
    }

    #[test]
    fn disorder_sends_the_second_half_first() {
        let pkt = v4(b"0123456789", TCP_ACK | TCP_PSH);
        let t = parse(&pkt).unwrap();
        let parts = apply(&pkt, &t, &Technique::Disorder { pos: 4 });
        assert_eq!(parse(&parts[0]).unwrap().seq, 1004);
        assert_eq!(parse(&parts[1]).unwrap().seq, 1000);
        assert_eq!(reassemble(&parts, 1000), b"0123456789");
    }

    #[test]
    fn fake_goes_first_outside_the_server_window() {
        let pkt = v4(b"0123456789", TCP_ACK | TCP_PSH);
        let t = parse(&pkt).unwrap();
        let decoy = crate::bypass::tls::build_client_hello_sized("www.google.com", 517);
        let parts = apply(&pkt, &t, &Technique::Fake { pos: 4, decoy: decoy.clone() });
        assert_eq!(parts.len(), 3);
        let fake = parse(&parts[0]).unwrap();
        assert_eq!(fake.seq, 1000u32.wrapping_sub(BADSEQ_SHIFT));
        assert_eq!(fake.payload(&parts[0]), &decoy[..]);
        assert_eq!(reassemble(&parts, 1000), b"0123456789");
    }

    #[test]
    fn ipv6_split_wraps_sequence_numbers() {
        let pkt = v6(b"abcdef");
        let t = parse(&pkt).unwrap();
        let parts = apply(&pkt, &t, &Technique::Split { pos: 2 });
        assert_eq!(parse(&parts[1]).unwrap().seq, 1, "переход через u32::MAX");
        assert_eq!(reassemble(&parts, u32::MAX), b"abcdef");
    }

    /// Пакет больше MTU (аппаратная нарезка): части не длиннее MAX_SEGMENT,
    /// поток цел, PSH только у последней.
    #[test]
    fn oversized_packet_is_cut_into_mtu_sized_parts() {
        let hello = crate::bypass::tls::build_client_hello_sized("discord.com", 1800);
        let pkt = v4(&hello, TCP_ACK | TCP_PSH);
        let t = parse(&pkt).unwrap();
        let decoy = crate::bypass::tls::build_client_hello_sized("www.google.com", 1800);
        for technique in [
            Technique::Split { pos: 130 },
            Technique::Disorder { pos: 130 },
            Technique::Fake { pos: 130, decoy },
        ] {
            let parts = apply(&pkt, &t, &technique);
            assert!(parts.iter().all(|p| parse(p).unwrap().payload(p).len() <= MAX_SEGMENT), "{technique:?}");
            let psh = parts.iter().filter(|p| parse(p).unwrap().flags & TCP_PSH != 0).count();
            let expected_psh = if matches!(technique, Technique::Fake { .. }) { 2 } else { 1 };
            assert_eq!(psh, expected_psh, "PSH у последней части (и у подделки)");
            assert_eq!(reassemble(&parts, 1000), hello, "{technique:?}");
        }
    }

    #[test]
    fn one_byte_payload_is_not_split() {
        let pkt = v4(b"x", TCP_ACK);
        let t = parse(&pkt).unwrap();
        assert_eq!(apply(&pkt, &t, &Technique::Disorder { pos: 1 }), vec![pkt.clone()]);
    }

    /// SNI во втором сегменте (ClientHello больше MSS): режем после первого
    /// байта, как zapret по умолчанию.
    #[test]
    fn name_beyond_the_segment_splits_after_the_first_byte() {
        let hello = crate::bypass::tls::build_client_hello_sized("discord.com", 1800);
        let loc = crate::bypass::tls::find_sni(&hello).unwrap();
        assert!(crate::bypass::tls::find_sni_prefix(&hello[..loc.offset + 2]).is_none());
        assert_eq!(split_pos(&hello[..loc.offset + 2]), 1);
        assert_eq!(split_pos(&hello[..loc.offset + loc.len]), loc.split_point());
    }

    #[test]
    fn reset_answers_as_the_server() {
        let pkt = v4(b"0123456789", TCP_ACK | TCP_PSH);
        let t = parse(&pkt).unwrap();
        let rst = reset_for(&pkt, &t);
        let r = parse(&rst).unwrap();
        assert_eq!((r.src, r.dst, r.sport, r.dport), (t.dst, t.src, 443, 50000));
        assert_eq!((r.seq, r.ack), (7777, 1010));
        assert_eq!(r.flags, TCP_RST | TCP_ACK);
        assert!(r.payload(&rst).is_empty());
    }
}
