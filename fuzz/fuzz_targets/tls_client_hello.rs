//! Разбор TLS ClientHello: поиск SNI и перестройка в две записи.
//!
//! Самая ценная цель из всех: сюда приходит первый пакет КАЖДОГО соединения,
//! и приходит он до того, как хоть что-то проверено.
#![no_main]

use libfuzzer_sys::fuzz_target;
use net_surgeon::bypass::tls;

fuzz_target!(|data: &[u8]| {
    if let Some(loc) = tls::find_sni(data) {
        // Найденное имя обязано лежать внутри буфера: по этому смещению
        // потом режется пакет, и выход за границу — это паника в бою.
        assert!(loc.len > 0);
        assert!(loc.offset + loc.len <= data.len());
        assert!(loc.split_point() >= loc.offset);
        assert!(loc.split_point() < loc.offset + loc.len);
    }

    let _ = tls::record_len(data);
    let _ = tls::looks_like_handshake(data);

    if let Some(out) = tls::split_into_two_records(data) {
        // Перестройка добавляет ровно один заголовок записи — пять байт.
        // Ни одного байта нагрузки при этом потеряться не должно.
        assert_eq!(out.len(), data.len() + 5);
        assert_eq!(out[0], 0x16);
    }
});
