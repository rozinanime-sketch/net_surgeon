//! Разбор адреса назначения в запросе SOCKS5.
//!
//! Возвращённое «сколько байт занял адрес» используется как смещение хвоста
//! (клиент мог дослать ClientHello следом), поэтому оно обязано укладываться
//! в полученные данные.
#![no_main]

use libfuzzer_sys::fuzz_target;
use net_surgeon::protocol::socks5::parse_socks5_target;

fuzz_target!(|data: &[u8]| {
    if let Some((target, consumed)) = parse_socks5_target(data) {
        assert!(consumed <= data.len());
        assert!(!target.is_empty());
    }
});
