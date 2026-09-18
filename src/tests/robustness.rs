//! Устойчивость разборщиков к испорченному входу.
//!
//! Все эти функции разбирают байты, пришедшие из сети, то есть вход им задаёт
//! кто угодно: враждебный DPI, кривой клиент, просто потерянный посреди пакета
//! сегмент. Обычные тесты проверяют правильные входы и несколько придуманных
//! неправильных — но придумать удаётся только то, о чём уже подумал.
//!
//! Здесь наоборот: берутся ЗАВЕДОМО правильные пакеты и портятся случайным
//! образом — переставленные биты, обрезка, дописанный мусор. После каждой
//! порчи разборщик обязан вернуть ответ, а не паниковать, и ответ обязан быть
//! непротиворечивым: смещение SNI должно лежать внутри буфера, «съеденная»
//! длина запроса SOCKS5 — не превышать полученного.
//!
//! Это дешёвая замена настоящему фаззеру (папка `fuzz/`, требует nightly):
//! тот умнее, потому что смотрит, какие ветки кода отработали, и подбирает
//! вход целенаправленно. Зато этот прогон идёт вместе с обычным `cargo test`
//! на стабильном компиляторе и ловит грубые промахи сразу.
//!
//! Зерно ГСЧ зафиксировано: упавший прогон воспроизводится повторным запуском,
//! а не «иногда бывает».

use crate::bypass::tls;
use crate::dns::ip_cache;
use crate::protocol::{http, socks5};
use crate::proxy::udp::quic_parser;

/// xorshift64* — четыре строки, без зависимостей и без скрытого состояния.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next() % n as u64) as usize }
    }
}

/// Портит копию пакета одним из способов, которыми его портит жизнь.
fn mutate(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut data = seed.to_vec();

    match rng.below(6) {
        // Один байт не такой: сбитая длина, чужой тип расширения, битый флаг.
        0 => {
            if !data.is_empty() {
                let at = rng.below(data.len());
                data[at] = rng.next() as u8;
            }
        }
        // Пакет пришёл не целиком — самый частый случай в сети.
        1 => {
            let keep = rng.below(data.len() + 1);
            data.truncate(keep);
        }
        // За пакетом идёт что-то ещё: следующая запись, мусор, чужие данные.
        2 => {
            let extra = rng.below(64);
            data.extend((0..extra).map(|_| rng.next() as u8));
        }
        // Обнулённый кусок: так выглядит недописанный буфер.
        3 => {
            if !data.is_empty() {
                let at = rng.below(data.len());
                let len = rng.below(data.len() - at);
                data[at..at + len].fill(0);
            }
        }
        // Поле длины, задранное до предела, — классика переполнений.
        4 => {
            if data.len() >= 2 {
                let at = rng.below(data.len() - 1);
                data[at] = 0xff;
                data[at + 1] = 0xff;
            }
        }
        // Несколько мелких правок сразу.
        _ => {
            for _ in 0..rng.below(8) {
                if data.is_empty() { break; }
                let at = rng.below(data.len());
                data[at] ^= 1 << rng.below(8);
            }
        }
    }

    data
}

/// Прогоняет вход через ВСЕ разборщики сразу: байты TLS попадают и в разбор
/// DNS, и в разбор QUIC. Так проверяется главное свойство — разборщик обязан
/// пережить любой вход, а не только «свой».
fn feed_every_parser(data: &[u8]) {
    if let Some(loc) = tls::find_sni(data) {
        assert!(loc.len > 0, "пустое имя выдано за найденное: {data:02x?}");
        assert!(
            loc.offset + loc.len <= data.len(),
            "SNI указывает за пределы буфера: offset={} len={} буфер={}",
            loc.offset, loc.len, data.len(),
        );
        assert!(
            loc.split_point() >= loc.offset && loc.split_point() < loc.offset + loc.len,
            "точка разрыва вне имени домена",
        );
    }

    let _ = tls::record_len(data);
    let _ = tls::looks_like_handshake(data);

    if let Some(out) = tls::split_into_two_records(data) {
        // Перестройка добавляет ровно один заголовок записи — пять байт.
        assert_eq!(
            out.len(), data.len() + 5,
            "перестроенный ClientHello потерял или выдумал байты",
        );
        assert_eq!(out[0], 0x16, "первая запись перестала быть handshake");
    }

    let _ = ip_cache::extract_ips_from_dns_response(data);
    let _ = ip_cache::extract_qname(data);

    for dcid_len in [0usize, 8, 20] {
        if let Some(header) = quic_parser::parse_quic_header(data, dcid_len) {
            assert!(header.dcid.len() <= 20, "DCID длиннее разрешённого RFC 9000");
            if let Some(scid) = header.scid {
                assert!(scid.len() <= 20, "SCID длиннее разрешённого RFC 9000");
            }
        }
    }

    if let Some((_target, consumed)) = socks5::parse_socks5_target(data) {
        assert!(
            consumed <= data.len(),
            "разбор SOCKS5 «съел» больше, чем получил: {consumed} > {}",
            data.len(),
        );
    }

    // Текстовые разборщики: вход из сети не обязан быть валидным UTF-8,
    // поэтому проверяем оба пути — и корректную строку, и заменённые байты.
    let text = String::from_utf8_lossy(data);
    let _ = http::parse_connect_target(&text);
    let _ = http::parse_http_target(&text);
    let _ = http::rewrite_for_origin(&text);
}

/// Заведомо правильные пакеты — точки, от которых пляшет порча.
fn seeds() -> Vec<Vec<u8>> {
    let mut dns = vec![0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
    for label in [b"example".as_slice(), b"com".as_slice()] {
        dns.push(label.len() as u8);
        dns.extend_from_slice(label);
    }
    dns.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
    dns.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01]);
    dns.extend_from_slice(&[0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 93, 184, 216, 34]);

    let mut socks = vec![0x05, 0x01, 0x00, 0x03, 11];
    socks.extend_from_slice(b"example.com");
    socks.extend_from_slice(&443u16.to_be_bytes());

    vec![
        tls::build_client_hello("www.example.com"),
        tls::build_client_hello_sized("a.b.c.example.com", 300),
        crate::bypass::fragment::build_fake_quic_initial(),
        dns,
        socks,
        b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n".to_vec(),
        b"GET http://example.com/a?b=1 HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\n\r\n".to_vec(),
    ]
}

#[test]
fn parsers_survive_mutated_input() {
    let seeds = seeds();
    let mut rng = Rng(0x5EED_1234_ABCD_0001);

    for seed in &seeds {
        feed_every_parser(seed);
        for _ in 0..2_000 {
            let data = mutate(&mut rng, seed);
            feed_every_parser(&data);
        }
    }
}

#[test]
fn parsers_survive_pure_noise() {
    let mut rng = Rng(0x00C0_FFEE_D15E_A5E5);

    for _ in 0..4_000 {
        let len = rng.below(2048);
        let data: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        feed_every_parser(&data);
    }
}

#[test]
fn parsers_survive_every_prefix_of_a_valid_packet() {
    // Обрезка по всем длинам подряд — то, что даёт TCP, отдавая пакет
    // частями. Случайная порча до такого систематического перебора
    // добирается редко.
    for seed in seeds() {
        for len in 0..seed.len().min(600) {
            feed_every_parser(&seed[..len]);
        }
    }
}
