//! Разбор TLS ClientHello: поиск SNI и перестройка в несколько записей.
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

    // Имя из SNI уходит в кэш и в выбор стратегии: оно обязано быть уже
    // приведено к виду списков, иначе сравнение с ними молча промахнётся.
    if let Some(host) = tls::sni_host(data) {
        assert!(!host.is_empty());
        assert_eq!(host, host.to_ascii_lowercase());
        assert!(!host.ends_with('.'));
    }

    let _ = tls::record_len(data);
    let _ = tls::looks_like_handshake(data);

    if let Some(out) = tls::split_into_records(data) {
        // Перестройка добавляет только заголовки записей — по пять байт на
        // каждую новую. Ни одного байта нагрузки при этом потеряться не должно.
        assert!(out.len() > data.len());
        assert!((out.len() - data.len()).is_multiple_of(5));
        assert_eq!(out[0], 0x16);
    }
});
