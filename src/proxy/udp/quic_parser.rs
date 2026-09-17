//! Zero-copy парсер QUIC-заголовков. Перенесено 1-в-1, включая тесты —
//! лучший по качеству файл в проекте, менять не требовалось.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuicPacketType { Initial, ZeroRtt, Handshake, Retry, Short }

/// Полный заголовок по RFC 9000. Сейчас логика прокси (миграция сессий по DCID
/// в udp/quic.rs) читает только `dcid`, но парсер намеренно разбирает и остальное:
/// эти поля проверяются юнит-тестами ниже и нужны для будущих проверок
/// (например, отличить Initial от Handshake или поймать Version Negotiation).
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct QuicHeader<'a> {
    pub version: Option<u32>,
    pub dcid: &'a [u8],
    pub scid: Option<&'a [u8]>,
    pub packet_type: QuicPacketType,
}

pub fn parse_quic_header<'a>(packet: &'a [u8], short_dcid_len: usize) -> Option<QuicHeader<'a>> {
    if packet.is_empty() { return None; }
    let first_byte = packet[0];

    if first_byte & 0x80 == 0 {
        if first_byte & 0x40 == 0 { return None; }
        if packet.len() < 1 + short_dcid_len { return None; }
        return Some(QuicHeader {
            version: None,
            dcid: &packet[1..1 + short_dcid_len],
            scid: None,
            packet_type: QuicPacketType::Short,
        });
    }

    if packet.len() < 5 { return None; }
    let version = u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]);
    if version == 0 { return None; }

    let packet_type = match (first_byte & 0x30) >> 4 {
        0x00 => QuicPacketType::Initial,
        0x01 => QuicPacketType::ZeroRtt,
        0x02 => QuicPacketType::Handshake,
        0x03 => QuicPacketType::Retry,
        _ => return None,
    };

    let mut pos = 5usize;
    if pos >= packet.len() { return None; }
    let dcid_len = packet[pos] as usize;
    if dcid_len > 20 { return None; }
    pos += 1;
    if pos + dcid_len > packet.len() { return None; }
    let dcid = &packet[pos..pos + dcid_len];
    pos += dcid_len;

    if pos >= packet.len() { return None; }
    let scid_len = packet[pos] as usize;
    if scid_len > 20 { return None; }
    pos += 1;
    if pos + scid_len > packet.len() { return None; }
    let scid = &packet[pos..pos + scid_len];

    Some(QuicHeader { version: Some(version), dcid, scid: Some(scid), packet_type })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_test_header(packet_type_bits: u8, dcid: &[u8], scid: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(0x80 | 0x40 | (packet_type_bits << 4));
        out.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        out.push(dcid.len() as u8);
        out.extend_from_slice(dcid);
        out.push(scid.len() as u8);
        out.extend_from_slice(scid);
        out
    }

    #[test]
    fn parses_initial_packet() {
        let packet = build_test_header(0x00, &[1, 2, 3, 4, 5, 6, 7, 8], &[]);
        let header = parse_quic_header(&packet, 8).unwrap();
        assert_eq!(header.version, Some(1));
        assert_eq!(header.packet_type, QuicPacketType::Initial);
        assert_eq!(header.dcid, &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn parses_short_header() {
        let packet = vec![0x40, 1, 2, 3, 4, 5, 6, 7, 8, 255, 255];
        let header = parse_quic_header(&packet, 8).unwrap();
        assert_eq!(header.packet_type, QuicPacketType::Short);
        assert_eq!(header.dcid, &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(header.version, None);
        assert_eq!(header.scid, None);
    }

    #[test]
    fn rejects_invalid_cid_length() {
        let mut packet = vec![0xC0, 0x00, 0x00, 0x00, 0x01, 21];
        packet.extend(vec![0; 21]);
        assert!(parse_quic_header(&packet, 8).is_none());
    }
}
