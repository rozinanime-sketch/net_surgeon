//! Разбор и переписывание заголовков HTTP.
//!
//! Строка сюда приходит из сети и не обязана быть ни валидным HTTP, ни даже
//! ASCII: индексация байтовых смещений по строке с кириллицей в заголовке
//! уже однажды могла уронить прокси.
#![no_main]

use libfuzzer_sys::fuzz_target;
use net_surgeon::protocol::http;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };

    let _ = http::parse_connect_target(text);
    let _ = http::parse_http_target(text);

    // Переписанные заголовки уходят на сервер: адресованных прокси полей
    // в них остаться не должно. Первую строку пропускаем — это строка
    // запроса, и «proxy-connection:» внутри её пути заголовком не является.
    let out = http::rewrite_for_origin(text);
    assert!(out.ends_with("Connection: close\r\n\r\n"));
    for line in out.split("\r\n").skip(1) {
        let name = line.split(':').next().unwrap_or("").trim().to_ascii_lowercase();
        assert!(
            !matches!(name.as_str(), "proxy-connection" | "proxy-authorization" | "keep-alive"),
            "заголовок для прокси уехал на сервер: {line}",
        );
    }
});
