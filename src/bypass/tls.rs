//! Разбор TLS ClientHello — поиск точного смещения имени домена (SNI).
//!
//! Зачем: свип по абсолютным позициям (2, 8, 20, 40, …) бьёт вслепую. Длина
//! ClientHello зависит от браузера — набор cipher suites, ALPN, расширения,
//! session ticket. Из-за этого SNI у разных клиентов и доменов оказывается на
//! разном смещении, и фиксированная позиция может ни разу в него не попасть.
//!
//! zapret решает это опцией `--split-tls=sni`: разрыв ставится по вычисленному
//! смещению, а не по числу. Здесь то же самое — и для этого не нужно ни одной
//! новой зависимости, байты ClientHello уже на руках.
//!
//! Структура (RFC 8446 §4.1.2 и RFC 6066 §3):
//! ```text
//! запись TLS:   тип(1) версия(2) длина(2)
//! handshake:    тип(1) длина(3)
//! ClientHello:  версия(2) random(32) session_id_len(1) session_id
//!               cipher_suites_len(2) suites
//!               compression_len(1) methods
//!               extensions_len(2) extensions
//! расширение:   тип(2) длина(2) данные
//! SNI (тип 0):  list_len(2) entry_type(1) name_len(2) name
//! ```

/// Где в буфере лежит имя домена из SNI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SniLocation {
    /// Смещение первого байта имени от начала переданного буфера.
    pub offset: usize,
    pub len: usize,
}

impl SniLocation {
    /// Позиция для разрыва — середина имени домена.
    ///
    /// Разрыв именно внутри имени, а не перед ним: DPI, который ищет строку
    /// «youtube.com», не найдёт её ни в одной половине. Разрыв перед именем
    /// оставляет его целым во втором сегменте.
    pub fn split_point(&self) -> usize {
        self.offset + self.len / 2
    }
}

fn u16_at(data: &[u8], pos: usize) -> Option<usize> {
    // checked_add, а не pos + 2: смещение приходит из разбираемых данных,
    // и переполнение в debug-сборке дало бы панику вместо честного None.
    let bytes = data.get(pos..pos.checked_add(2)?)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]) as usize)
}

/// Сколько всего байт занимает первая TLS-запись в буфере, вместе с
/// пятибайтовым заголовком. `None` — это не handshake-запись либо заголовок
/// ещё не дочитан.
pub fn record_len(data: &[u8]) -> Option<usize> {
    if data.len() < 5 || data[0] != 0x16 || data[1] != 0x03 {
        return None;
    }
    Some(5 + u16::from_be_bytes([data[3], data[4]]) as usize)
}

/// Похож ли ответ сервера на TLS: запись рукопожатия (ServerHello) или
/// alert, с версией 3.x во втором байте.
///
/// Нужна, чтобы отличать ответ сервера от ответа, подставленного по пути:
/// HTTP-заглушка провайдера начинается с `H`, и засчитывать её как успех
/// нельзя. Одного байта хватает для решения по типу записи — второй может
/// прийти следующим сегментом, и тогда он просто не проверяется.
pub fn looks_like_tls_reply(data: &[u8]) -> bool {
    const HANDSHAKE: u8 = 0x16;
    const ALERT: u8 = 0x15;
    matches!(data, [HANDSHAKE | ALERT] | [HANDSHAKE | ALERT, 0x03, ..])
}

/// Похоже ли начало буфера на TLS handshake. Отличается от [`record_len`]
/// тем, что отвечает и на неполном заголовке: первого байта достаточно.
pub fn looks_like_handshake(data: &[u8]) -> bool {
    match data {
        [] => false,
        [0x16] => true,
        [0x16, 0x03, ..] => true,
        _ => false,
    }
}

/// Ищет SNI в TLS ClientHello. Возвращает None, если это не ClientHello,
/// буфер обрезан или расширения SNI нет (например, подключение по IP).
pub fn find_sni(data: &[u8]) -> Option<SniLocation> {
    // Заголовок записи: тип 0x16 (handshake), версия 0x03xx
    if data.len() < 5 || data[0] != 0x16 || data[1] != 0x03 {
        return None;
    }

    // Заголовок handshake: тип 0x01 (ClientHello) + длина (3 байта)
    if data.get(5)? != &0x01 {
        return None;
    }

    let mut pos = 9; // 5 (запись) + 1 (тип) + 3 (длина)

    pos += 2;  // client version
    pos += 32; // random

    let session_id_len = *data.get(pos)? as usize;
    pos += 1 + session_id_len;

    let cipher_suites_len = u16_at(data, pos)?;
    pos += 2 + cipher_suites_len;

    let compression_len = *data.get(pos)? as usize;
    pos += 1 + compression_len;

    let extensions_len = u16_at(data, pos)?;
    pos += 2;
    let extensions_end = pos.checked_add(extensions_len)?;
    if extensions_end > data.len() {
        return None;
    }

    while pos + 4 <= extensions_end {
        let ext_type = u16_at(data, pos)?;
        let ext_len = u16_at(data, pos + 2)?;
        let ext_data = pos + 4;

        if ext_data + ext_len > extensions_end {
            return None;
        }

        // 0x0000 — server_name
        if ext_type == 0x0000 {
            // list_len(2) entry_type(1) name_len(2) name
            let entry_type = *data.get(ext_data + 2)?;
            if entry_type != 0x00 {
                return None; // не host_name
            }
            let name_len = u16_at(data, ext_data + 3)?;
            let name_offset = ext_data + 5;
            if name_offset + name_len > data.len() || name_len == 0 {
                return None;
            }
            return Some(SniLocation { offset: name_offset, len: name_len });
        }

        pos = ext_data + ext_len;
    }

    None
}


/// Собирает ClientHello, похожий на браузерный.
///
/// Живёт здесь, а не в диагностике, потому что нужен двоим: диагностике —
/// как проба, технике `fake` — как подделка-приманка. Раньше сборщик был
/// написан в проекте трижды (диагностика и два теста), и они успели
/// разъехаться: у минимальных вариантов нет ни ALPN, ни key_share, а именно
/// от размера и набора расширений зависит, как на пакет реагирует DPI.
///
/// Раньше здесь был минимальный вариант: 4 cipher suite, пустой session_id,
/// две крошечные extensions — итого ~130 байт. Реальный ClientHello от curl
/// или браузера весит ~1500-1900 байт и содержит ALPN, key_share, длинный
/// список шифров и групп.
///
/// Разница оказалась решающей: диагностика сообщала «две TLS-записи — 0/2»
/// для доменов, которые в бою этой же техникой открывались нормально.
/// Синтетический пакет и по размеру, и по структуре не похож на настоящий,
/// и DPI реагирует на него иначе. Проба должна выглядеть как реальный трафик,
/// иначе она измеряет не то.
pub fn build_client_hello(sni: &str) -> Vec<u8> {
    build_client_hello_sized(sni, BROWSER_HELLO_SIZE)
}

/// Размер ClientHello браузера, пока реальный не наблюдался в бою
/// (см. `diagnostics::browser_hello_size`).
///
/// Было 1500, но браузеры с постквантовым key share (X25519MLKEM768, это
/// больше килобайта ключа) шлют 1800–1900 байт: в логах прокси 1817–1898.
/// Проба в 1500 байт мерила не тот пакет: автодиагностика реальным размером
/// находила для youtube.com две TLS-записи, а ручная и массовая с 1500 —
/// ничего.
pub const BROWSER_HELLO_SIZE: usize = 1850;

/// То же, но с заданным итоговым размером.
///
/// Размер сам по себе меняет вердикт: две TLS-записи проходили с
/// ClientHello браузера (~1800 байт) и не проходили с ClientHello rustls
/// у программы обновления Discord (273 байта). Проба фиксированного размера
/// такую разницу не видит. Если `target` меньше пакета без дополнения,
/// дополнение не добавляется — получается самый короткий вариант (~300 байт).
pub fn build_client_hello_sized(sni: &str, target: usize) -> Vec<u8> {
    let mut body = Vec::new();

    // legacy_version = TLS 1.2 (реальная версия объявляется в supported_versions)
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&super::random::bytes(32));

    // legacy_session_id — браузеры шлют 32 байта ради совместимости
    body.push(32);
    body.extend_from_slice(&super::random::bytes(32));

    // Набор шифров как у современного браузера
    let cipher_suites: &[u8] = &[
        0x13, 0x01, 0x13, 0x02, 0x13, 0x03,             // TLS 1.3
        0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30, // ECDHE-ECDSA/RSA AES-GCM
        0xcc, 0xa9, 0xcc, 0xa8,                          // ChaCha20-Poly1305
        0xc0, 0x13, 0xc0, 0x14,                          // ECDHE AES-CBC
        0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35,  // RSA
    ];
    body.extend_from_slice(&(cipher_suites.len() as u16).to_be_bytes());
    body.extend_from_slice(cipher_suites);

    body.push(0x01); // compression_methods
    body.push(0x00);

    let mut ext = Vec::new();

    // server_name — то, ради чего всё и затевается
    let sni_bytes = sni.as_bytes();
    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&((sni_bytes.len() + 3) as u16).to_be_bytes());
    sni_ext.push(0x00);
    sni_ext.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(sni_bytes);
    push_ext(&mut ext, 0x0000, &sni_ext);

    // ec_point_formats: uncompressed
    push_ext(&mut ext, 0x000b, &[0x01, 0x00]);

    // supported_groups: x25519, secp256r1, secp384r1
    push_ext(&mut ext, 0x000a, &[0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18]);

    // session_ticket (пустой)
    push_ext(&mut ext, 0x0023, &[]);

    // ALPN: h2, http/1.1 — без него пакет сразу не похож на браузерный
    let alpn: &[u8] = &[0x00, 0x0c, 0x02, b'h', b'2', 0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1'];
    push_ext(&mut ext, 0x0010, alpn);

    // status_request (OCSP)
    push_ext(&mut ext, 0x0005, &[0x01, 0x00, 0x00, 0x00, 0x00]);

    // signature_algorithms
    let sigalgs: &[u8] = &[
        0x00, 0x12,
        0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03,
        0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01,
    ];
    push_ext(&mut ext, 0x000d, sigalgs);

    // supported_versions: TLS 1.3, 1.2
    push_ext(&mut ext, 0x002b, &[0x04, 0x03, 0x04, 0x03, 0x03]);

    // psk_key_exchange_modes
    push_ext(&mut ext, 0x002d, &[0x01, 0x01]);

    // key_share: x25519 с 32 случайными байтами.
    // Длина списка — 36 (группа 2 + длина 2 + ключ 32), без своих 2 байт.
    // Здесь стояло 38 (0x26), и строгие серверы отвечали decode_error,
    // а через разрезанную пробу молчали — диагностика видела блокировку там,
    // где обход работал.
    let mut ks = Vec::new();
    ks.extend_from_slice(&[0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]);
    ks.extend_from_slice(&super::random::bytes(32));
    push_ext(&mut ext, 0x0033, &ks);

    // padding — добиваем до заданного размера.
    // Размер важен сам по себе: короткий пакет DPI видит иначе, и проба
    // перестаёт отражать боевой трафик.
    let so_far = 5 + 4 + body.len() + 2 + ext.len() + 4;
    if so_far < target {
        let pad = target - so_far;
        push_ext(&mut ext, 0x0015, &vec![0u8; pad]);
    }

    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);

    let mut handshake = vec![0x01];
    handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..4]);
    handshake.extend_from_slice(&body);

    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// Добавляет расширение TLS: тип(2) длина(2) данные.
pub(crate) fn push_ext(out: &mut Vec<u8>, ext_type: u16, data: &[u8]) {
    out.extend_from_slice(&ext_type.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}
/// Перестраивает ClientHello в ДВЕ TLS-записи с границей внутри имени домена.
///
/// Ключевое отличие от TCP-сплита: тот режет поток байт, и DPI, который
/// пересобирает TCP, склеивает всё обратно и спокойно читает SNI. Здесь же
/// меняется сама структура TLS: получается две полноценные записи, каждая
/// со своим 5-байтовым заголовком. По RFC 8446 handshake-сообщение может
/// занимать несколько записей, сервер соберёт нормально — а DPI, который ищет
/// SNI внутри одной записи, не найдёт его даже при идеальной сборке TCP.
///
/// Возвращает готовый буфер для отправки одним куском: техника работает на
/// уровне TLS, дополнительная фрагментация TCP ей не нужна.
pub fn split_into_two_records(data: &[u8]) -> Option<Vec<u8>> {
    let loc = find_sni(data)?;

    // Заголовок записи — первые 5 байт; дальше идёт полезная нагрузка.
    const HEADER: usize = 5;
    if data.len() <= HEADER {
        return None;
    }

    // Перестраивается ТОЛЬКО первая запись. Раньше бралось всё до конца
    // буфера, и то, что клиент прислал следом (ChangeCipherSpec, early data,
    // данные вместе с запросом SOCKS5), попадало внутрь второй записи
    // рукопожатия — сервер рвал соединение. Неполная запись не трогается:
    // её длина из заголовка не совпала бы с тем, что уйдёт.
    let record_end = record_len(data)?;
    if record_end > data.len() {
        return None;
    }
    let trailing = &data[record_end..];

    let version = [data[1], data[2]];
    let payload = &data[HEADER..record_end];

    // Точку разрыва переводим из координат буфера в координаты нагрузки.
    let split_at = loc.split_point().checked_sub(HEADER)?;
    if split_at == 0 || split_at >= payload.len() {
        return None;
    }

    let (first, second) = payload.split_at(split_at);

    let mut out = Vec::with_capacity(data.len() + HEADER);
    out.push(0x16);
    out.extend_from_slice(&version);
    out.extend_from_slice(&(first.len() as u16).to_be_bytes());
    out.extend_from_slice(first);

    out.push(0x16);
    out.extend_from_slice(&version);
    out.extend_from_slice(&(second.len() as u16).to_be_bytes());
    out.extend_from_slice(second);

    out.extend_from_slice(trailing);

    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_reply_is_told_apart_from_an_injected_one() {
        // ServerHello и alert — ответ сервера
        assert!(looks_like_tls_reply(&[0x16, 0x03, 0x03, 0x00, 0x7a]));
        assert!(looks_like_tls_reply(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]));
        // Первый байт пришёл отдельным сегментом — решаем по типу записи
        assert!(looks_like_tls_reply(&[0x16]));
        // Заглушка провайдера, мусор, запись с чужой версией — нет
        assert!(!looks_like_tls_reply(b"HTTP/1.1 302 Found\r\nLocation: http://warning.rt.ru\r\n"));
        assert!(!looks_like_tls_reply(&[0x17, 0x03, 0x03]));
        assert!(!looks_like_tls_reply(&[0x16, 0x48]));
        assert!(!looks_like_tls_reply(&[]));
    }

    /// Собирает минимальный ClientHello с заданным SNI — та же схема, что
    /// в diagnostics.rs, но локально, чтобы тест не зависел от чужого кода.
    fn build_client_hello(sni: &str) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0x00); // session_id_len

        let suites: &[u8] = &[0x13, 0x01, 0x13, 0x02];
        body.extend_from_slice(&(suites.len() as u16).to_be_bytes());
        body.extend_from_slice(suites);

        body.push(0x01); // compression_len
        body.push(0x00);

        let mut extensions = Vec::new();

        // Сначала постороннее расширение — проверяем, что цикл его перешагнёт
        extensions.extend_from_slice(&[0x00, 0x2b]); // supported_versions
        extensions.extend_from_slice(&[0x00, 0x03]);
        extensions.extend_from_slice(&[0x02, 0x03, 0x04]);

        let name = sni.as_bytes();
        let mut sni_ext = Vec::new();
        sni_ext.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        sni_ext.push(0x00);
        sni_ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(name);

        extensions.extend_from_slice(&[0x00, 0x00]);
        extensions.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_ext);

        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = vec![0x01];
        handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..4]);
        handshake.extend_from_slice(&body);

        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn finds_sni_and_points_at_the_hostname() {
        let hello = build_client_hello("youtube.com");
        let loc = find_sni(&hello).expect("SNI должен найтись");

        assert_eq!(loc.len, "youtube.com".len());
        assert_eq!(&hello[loc.offset..loc.offset + loc.len], b"youtube.com");
    }

    #[test]
    fn split_point_lands_inside_the_hostname() {
        let hello = build_client_hello("youtube.com");
        let loc = find_sni(&hello).unwrap();
        let split = loc.split_point();

        // Разрыв строго внутри имени: обе половины неполные
        assert!(split > loc.offset);
        assert!(split < loc.offset + loc.len);

        let (first, second) = hello.split_at(split);
        assert!(!first.ends_with(b"youtube.com"));
        assert!(!second.starts_with(b"youtube.com"));
    }

    #[test]
    fn works_for_different_hostname_lengths() {
        for host in ["x.com", "www.instagram.com", "gateway.discord.gg"] {
            let hello = build_client_hello(host);
            let loc = find_sni(&hello).unwrap_or_else(|| panic!("не нашли SNI для {host}"));
            assert_eq!(&hello[loc.offset..loc.offset + loc.len], host.as_bytes());
        }
    }

    #[test]
    fn two_records_hide_the_hostname_from_single_record_parsing() {
        let hello = build_client_hello("youtube.com");
        let reframed = split_into_two_records(&hello).expect("должно перестроиться");

        // Обе записи — валидные TLS-записи с корректной длиной
        let len1 = u16::from_be_bytes([reframed[3], reframed[4]]) as usize;
        assert_eq!(reframed[0], 0x16);
        let second_start = 5 + len1;
        assert_eq!(reframed[second_start], 0x16);
        let len2 = u16::from_be_bytes([reframed[second_start + 3], reframed[second_start + 4]]) as usize;

        // Суммарная нагрузка совпадает с исходной — ничего не потеряно
        assert_eq!(len1 + len2, hello.len() - 5);
        assert_eq!(reframed.len(), hello.len() + 5);

        // Имя домена не лежит целиком ни в одной из записей
        let first_record = &reframed[5..5 + len1];
        let second_record = &reframed[second_start + 5..second_start + 5 + len2];
        assert!(!first_record.windows(11).any(|w| w == b"youtube.com"));
        assert!(!second_record.windows(11).any(|w| w == b"youtube.com"));
    }

    #[test]
    fn bytes_after_the_hello_are_not_pulled_into_the_second_record() {
        let hello = build_client_hello("youtube.com");
        // Следом за ClientHello — ChangeCipherSpec, как шлёт TLS 1.3 в режиме совместимости
        let ccs = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
        let mut data = hello.clone();
        data.extend_from_slice(&ccs);

        let reframed = split_into_two_records(&data).expect("должно перестроиться");
        let len1 = u16::from_be_bytes([reframed[3], reframed[4]]) as usize;
        let second_start = 5 + len1;
        let len2 = u16::from_be_bytes([reframed[second_start + 3], reframed[second_start + 4]]) as usize;

        assert_eq!(len1 + len2, hello.len() - 5, "записи рукопожатия покрывают только ClientHello");
        assert_eq!(&reframed[second_start + 5 + len2..], &ccs, "хвост уходит как был");
    }

    #[test]
    fn incomplete_record_is_not_reframed() {
        let hello = build_client_hello("youtube.com");
        let mut data = hello.clone();
        // Заголовок обещает больше, чем пришло
        let claimed = (hello.len() - 5 + 100) as u16;
        data[3..5].copy_from_slice(&claimed.to_be_bytes());
        assert_eq!(split_into_two_records(&data), None);
    }

    #[test]
    fn reframing_needs_sni() {
        assert_eq!(split_into_two_records(b"GET / HTTP/1.1\r\n"), None);
        assert_eq!(split_into_two_records(&[]), None);
    }

    #[test]
    fn probe_hello_size_is_configurable() {
        let big = super::build_client_hello_sized("updates.discord.com", 1500);
        assert_eq!(big.len(), 1500);
        // Меньше минимума — без дополнения, но SNI на месте и разбирается
        let small = super::build_client_hello_sized("updates.discord.com", 0);
        assert!(small.len() < 400, "короткий вариант: {} байт", small.len());
        assert!(find_sni(&small).is_some());
        assert!(split_into_two_records(&small).is_some());
    }

    /// Каждое поле длины в пробе сходится с тем, что за ним лежит.
    /// Ошибка в одном из них не видна ни DPI, ни `find_sni`, но строгий
    /// сервер отвечает на такой пакет decode_error.
    #[test]
    fn probe_hello_lengths_are_consistent() {
        let be16 = |b: &[u8], at: usize| u16::from_be_bytes([b[at], b[at + 1]]) as usize;
        for target in [0, 1500, 1850] {
            let h = build_client_hello_sized("www.wattpad.com", target);
            assert_eq!(be16(&h, 3), h.len() - 5, "длина записи");
            let hs_len = u32::from_be_bytes([0, h[6], h[7], h[8]]) as usize;
            assert_eq!(hs_len, h.len() - 9, "длина handshake");

            let mut p = 9 + 2 + 32;
            p += 1 + h[p] as usize; // session_id
            p += 2 + be16(&h, p); // cipher_suites
            p += 1 + h[p] as usize; // compression_methods
            assert_eq!(be16(&h, p), h.len() - p - 2, "длина расширений");
            p += 2;

            while p < h.len() {
                let (ty, len) = (be16(&h, p), be16(&h, p + 2));
                let data = &h[p + 4..p + 4 + len];
                // У этих расширений внутри ещё один список со своей длиной
                if matches!(ty, 0x0000 | 0x000a | 0x000d | 0x0010 | 0x0033) {
                    assert_eq!(be16(data, 0), len - 2, "внутренняя длина расширения {ty:#06x}");
                }
                p += 4 + len;
            }
            assert_eq!(p, h.len());
        }
    }

    #[test]
    fn record_len_covers_the_whole_record() {
        let hello = build_client_hello("youtube.com");
        assert_eq!(record_len(&hello), Some(hello.len()));
        // Заголовка достаточно, даже если тело ещё не пришло
        assert_eq!(record_len(&hello[..5]), Some(hello.len()));
        // Меньше заголовка — длина неизвестна
        assert_eq!(record_len(&hello[..4]), None);
        assert_eq!(record_len(b"GET / HTTP/1.1"), None);
    }

    #[test]
    fn handshake_is_recognised_from_the_first_byte() {
        assert!(looks_like_handshake(&[0x16]));
        assert!(looks_like_handshake(&[0x16, 0x03, 0x01]));
        assert!(!looks_like_handshake(&[]));
        assert!(!looks_like_handshake(b"GET "));
        // Application data — не рукопожатие
        assert!(!looks_like_handshake(&[0x17, 0x03, 0x03]));
    }

    #[test]
    fn rejects_non_clienthello() {
        assert_eq!(find_sni(&[]), None);
        assert_eq!(find_sni(&[0x17, 0x03, 0x03, 0x00, 0x10]), None); // application data
        assert_eq!(find_sni(b"GET / HTTP/1.1\r\n"), None);
    }

    #[test]
    fn rejects_truncated_buffer() {
        let hello = build_client_hello("youtube.com");
        // Обрезаем на половине — парсер не должен паниковать
        assert_eq!(find_sni(&hello[..hello.len() / 2]), None);
    }
}
