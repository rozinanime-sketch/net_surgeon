//! Высокопроизводительный Zero-copy парсер QUIC-заголовков.
//! Поддерживает как Long Headers (Initial, Handshake, ZeroRtt),
//! так и Short Headers для полноценного Connection Migration.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuicPacketType {
    Initial,
    ZeroRtt,
    Handshake,
    Retry,
    Short, // <-- Добавлен тип для поддержки миграции
}

/// Zero-copy структура заголовка (привязана к времени жизни пакета &'a [u8])
#[derive(Debug, Clone)]
pub struct QuicHeader<'a> {
    pub version: Option<u32>, // У Short Header нет версии
    pub dcid: &'a [u8],       // Без аллокаций (ссылка на слайс)
    pub scid: Option<&'a [u8]>, // У Short Header нет SCID
    pub packet_type: QuicPacketType,
}

/// Парсит QUIC Header.
/// Параметр `short_dcid_len` необходим, так как Short Headers по RFC 9000
/// не содержат информации о длине DCID (обычно это 8 байт).
pub fn parse_quic_header<'a>(packet: &'a [u8], short_dcid_len: usize) -> Option<QuicHeader<'a>> {
    if packet.is_empty() {
        return None;
    }

    let first_byte = packet[0];

    // --- Обработка Short Header (после Handshake) ---
    // Если первый бит равен 0 — это Short Header.
    if first_byte & 0x80 == 0 {
        // По RFC 9000, бит 0x40 (Fixed Bit) должен быть 1.
        if first_byte & 0x40 == 0 {
            return None; // Мусорный пакет
        }

        // Проверяем, хватает ли длины для извлечения DCID
        if packet.len() < 1 + short_dcid_len {
            return None;
        }

        return Some(QuicHeader {
            version: None,
            dcid: &packet[1..1 + short_dcid_len],
            scid: None,
            packet_type: QuicPacketType::Short,
        });
    }

    // --- Обработка Long Header (до завершения Handshake) ---
    if packet.len() < 5 {
        return None;
    }

    let version = u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]);

    // Version == 0 означает Version Negotiation
    if version == 0 {
        return None;
    }

    let packet_type = match (first_byte & 0x30) >> 4 {
        0x00 => QuicPacketType::Initial,
        0x01 => QuicPacketType::ZeroRtt,
        0x02 => QuicPacketType::Handshake,
        0x03 => QuicPacketType::Retry,
        _ => return None,
    };

    let mut pos = 5usize;

    // Чтение DCID
    if pos >= packet.len() {
        return None;
    }
    let dcid_len = packet[pos] as usize;
    // RFC 9000: Длина CID в Long Header не может превышать 20 байт
    if dcid_len > 20 {
        return None;
    }
    pos += 1;
    if pos + dcid_len > packet.len() {
        return None;
    }
    let dcid = &packet[pos..pos + dcid_len];
    pos += dcid_len;

    // Чтение SCID
    if pos >= packet.len() {
        return None;
    }
    let scid_len = packet[pos] as usize;
    if scid_len > 20 {
        return None;
    }
    pos += 1;
    if pos + scid_len > packet.len() {
        return None;
    }
    let scid = &packet[pos..pos + scid_len];

    Some(QuicHeader {
        version: Some(version),
         dcid,
         scid: Some(scid),
         packet_type,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_test_header(packet_type_bits: u8, dcid: &[u8], scid: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(0x80 | 0x40 | (packet_type_bits << 4)); // 0x40 - Fixed bit
        out.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // version 1
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
        // Первый байт: 0x40 (Short Header, Fixed Bit = 1), далее 8 байт DCID
        let packet = vec![0x40, 1, 2, 3, 4, 5, 6, 7, 8, 255, 255];
        let header = parse_quic_header(&packet, 8).unwrap();

        assert_eq!(header.packet_type, QuicPacketType::Short);
        assert_eq!(header.dcid, &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(header.version, None);
        assert_eq!(header.scid, None);
    }

    #[test]
    fn rejects_invalid_cid_length() {
        // Пытаемся передать длину 21 байт, что запрещено RFC 9000
        let mut packet = vec![0xC0, 0x00, 0x00, 0x00, 0x01, 21];
        packet.extend(vec![0; 21]);

        assert!(parse_quic_header(&packet, 8).is_none());
    }
}
