//! Разбор заголовка QUIC — по нему UDP-сессия признаётся началом QUIC.
#![no_main]

use libfuzzer_sys::fuzz_target;
use net_surgeon::proxy::udp::quic_parser;

fuzz_target!(|data: &[u8]| {
    for dcid_len in [0usize, 8, 20, 255] {
        if let Some(header) = quic_parser::parse_quic_header(data, dcid_len) {
            // RFC 9000 ограничивает идентификаторы 20 байтами; всё, что
            // длиннее, обязано быть отвергнуто, а не срезано молча.
            assert!(header.dcid.len() <= dcid_len.max(20));
            if let Some(scid) = header.scid {
                assert!(scid.len() <= 20);
            }
        }
    }
});
