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

/// Размер ClientHello по заголовку его TLS-записи, а не по первому
/// прочитанному куску: большой ClientHello приходит несколькими кусками, и
/// остаток сошёл бы за данные после рукопожатия. Не TLS — длина куска.
pub fn client_hello_len(first: &[u8]) -> usize {
    record_len(first).unwrap_or(first.len())
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

/// Жалуется ли сервер на испорченные байты: TLS-alert с кодом, который
/// означает «пришло не то, что было отправлено», а не «не договорились».
///
/// Отдельно от [`looks_like_tls_reply`], потому что любой alert доказывает
/// лишь, что сервер что-то получил. Техника, которая по пути портит поток,
/// тоже получает alert: OOB-байт, у которого оборудование оператора срезало
/// флаг URG, приходит серверу внутрь ClientHello, и Cloudflare отвечает
/// decode_error. Считать такое успехом нельзя — браузер получает обрыв.
///
/// Отказ по существу (handshake_failure, protocol_version, unrecognized_name)
/// сюда не входит: на синтетический ClientHello сервер вправе так ответить.
pub fn is_corruption_alert(data: &[u8]) -> bool {
    const ALERT: u8 = 0x15;
    const UNEXPECTED_MESSAGE: u8 = 10;
    const BAD_RECORD_MAC: u8 = 20;
    const RECORD_OVERFLOW: u8 = 22;
    const ILLEGAL_PARAMETER: u8 = 47;
    const DECODE_ERROR: u8 = 50;
    matches!(
        data,
        [ALERT, 0x03, _, _, _, _, UNEXPECTED_MESSAGE | BAD_RECORD_MAC | RECORD_OVERFLOW | ILLEGAL_PARAMETER | DECODE_ERROR, ..]
    )
}

/// Фатальный TLS-alert: сервер оборвал рукопожатие. Уровень лежит в шестом
/// байте; если он ещё не пришёл, решения нет — `false`.
pub fn is_fatal_alert(data: &[u8]) -> bool {
    const ALERT: u8 = 0x15;
    const FATAL: u8 = 2;
    matches!(data, [ALERT, 0x03, _, _, _, FATAL, ..])
}

/// Принял ли сервер отправленное. Для обратной связи по стратегии в бою.
///
/// Здесь ClientHello настоящий, от браузера или приложения, и любой
/// фатальный alert на него означает, что соединение у пользователя
/// сорвалось. Так выглядит и приманка fake, дошедшая до сервера:
/// Cloudflare отвечает на неё handshake_failure, а настоящий ClientHello
/// выбрасывает как повтор. Раньше такой отказ считался ответом, и
/// нерабочая стратегия не сбрасывалась никогда.
pub fn server_accepted(first_reply: &[u8]) -> bool {
    !is_corruption_alert(first_reply) && !is_fatal_alert(first_reply)
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
    find_sni_in(data, false)
}

/// То же, что [`find_sni`], но для начала ClientHello: буфер может
/// обрываться, лишь бы имя целиком было внутри.
///
/// Для перехвата пакетов в Windows: ClientHello браузера (около 1800 байт
/// с постквантовым ключом) в один TCP-сегмент не помещается, а перехват
/// видит только первый.
pub fn find_sni_prefix(data: &[u8]) -> Option<SniLocation> {
    find_sni_in(data, true)
}

/// Имя домена из SNI в начале ClientHello — см. [`find_sni_prefix`].
pub fn sni_host_prefix(data: &[u8]) -> Option<String> {
    host_at(data, find_sni_prefix(data)?)
}

fn find_sni_in(data: &[u8], truncated_ok: bool) -> Option<SniLocation> {
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
    let mut extensions_end = pos.checked_add(extensions_len)?;
    if extensions_end > data.len() {
        if !truncated_ok {
            return None;
        }
        extensions_end = data.len();
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

/// Имя домена из SNI — в том виде, в каком его ждут списки: нижний
/// регистр, без точки в конце. `None`, если SNI нет или имя не UTF-8.
///
/// Нужна там, где имя больше взять неоткуда: в прозрачном режиме и в
/// SOCKS5, когда клиент прислал голый IP.
pub fn sni_host(data: &[u8]) -> Option<String> {
    host_at(data, find_sni(data)?)
}

fn host_at(data: &[u8], loc: SniLocation) -> Option<String> {
    let host = std::str::from_utf8(&data[loc.offset..loc.offset + loc.len]).ok()?;
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
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
    push_ext(&mut ext, 0x0000, &server_name_ext(sni));

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

    wrap_client_hello(&body)
}

/// Приманка — копия настоящего ClientHello с другим именем (как
/// `tls_client_hello_clone` и `dupsid` в zapret2).
///
/// Собранный с нуля ClientHello отличается от браузерного всем, кроме
/// имени: набором шифров, порядком расширений, отпечатком JA3/JA4. DPI,
/// который это сверяет, видит, что приманка — не тот же клиент, и не
/// верит ей. Копия совпадает с настоящим во всём, кроме SNI и поля random:
/// тот же session id, те же расширения в том же порядке, тот же размер.
///
/// Длина обязана совпасть с настоящим байт в байт (ретрансмит займёт те же
/// номера). Разницу в длине имени забирает расширение padding: оно есть у
/// браузеров, а если его нет — добавляется. Если подогнать так нельзя,
/// берётся имя той же длины, что настоящее (см. [`fake_host`]).
///
/// `None` — это не один целый ClientHello в одной записи или в нём нет SNI:
/// вызывающий берёт собранную с нуля приманку.
pub fn clone_client_hello(real: &[u8], sni: &str) -> Option<Vec<u8>> {
    let parsed = ParsedHello::parse(real)?;
    let sni = sni.trim_end_matches('.');
    parsed.rebuild(sni.as_bytes(), real.len()).or_else(|| {
        // Не подогнать padding'ом — имя той же длины, что настоящее.
        let same = fake_host(sni, parsed.sni_len);
        parsed.rebuild(&same, real.len())
    })
}

/// ClientHello, разобранный до расширений: то, что нужно для его копии.
struct ParsedHello<'a> {
    /// Тело ClientHello от версии до длины расширений (не включая её).
    head: &'a [u8],
    /// Расширения: тип и данные, в исходном порядке.
    extensions: Vec<(u16, &'a [u8])>,
    /// Длина имени в настоящем SNI.
    sni_len: usize,
    /// Версия в заголовке TLS-записи.
    record_version: [u8; 2],
}

impl<'a> ParsedHello<'a> {
    fn parse(data: &'a [u8]) -> Option<Self> {
        // Ровно одна запись с одним целым ClientHello: иначе копия заняла бы
        // не те байты, что настоящий пакет.
        if record_len(data)? != data.len() || data.get(5)? != &0x01 {
            return None;
        }
        let hs_len = u32::from_be_bytes([0, data[6], data[7], data[8]]) as usize;
        if 9 + hs_len != data.len() {
            return None;
        }
        let mut pos = 9 + 2 + 32;
        pos += 1 + *data.get(pos)? as usize; // session id
        pos += 2 + u16_at(data, pos)?; // шифры
        pos += 1 + *data.get(pos)? as usize; // сжатие
        let head = data.get(9..pos)?;
        let ext_end = pos + 2 + u16_at(data, pos)?;
        if ext_end != data.len() {
            return None;
        }
        pos += 2;
        let mut extensions = Vec::new();
        let mut sni_len = None;
        while pos < ext_end {
            let ext_type = u16_at(data, pos)? as u16;
            let len = u16_at(data, pos + 2)?;
            let body = data.get(pos + 4..pos + 4 + len)?;
            if ext_type == 0x0000 {
                // list_len(2) type(1) name_len(2) name — одно имя host_name
                if body.get(2)? != &0x00 || 5 + u16_at(body, 3)? != body.len() {
                    return None;
                }
                sni_len = Some(u16_at(body, 3)?);
            }
            extensions.push((ext_type, body));
            pos += 4 + len;
        }
        Some(ParsedHello { head, extensions, sni_len: sni_len?, record_version: [data[1], data[2]] })
    }

    /// Копия с именем `name` ровно в `target` байт; `None` — не подогнать.
    fn rebuild(&self, name: &[u8], target: usize) -> Option<Vec<u8>> {
        const PADDING: u16 = 0x0015;
        const PRE_SHARED_KEY: u16 = 0x0029;
        let name = std::str::from_utf8(name).ok()?;

        // Всё, кроме padding: его размер подбирается под остаток.
        let mut ext = Vec::new();
        let mut padding_at = None;
        for &(ext_type, body) in &self.extensions {
            match ext_type {
                0x0000 => push_ext(&mut ext, 0x0000, &server_name_ext(name)),
                PADDING => padding_at = Some(ext.len()),
                // pre_shared_key обязан быть последним: новый padding — до него
                PRE_SHARED_KEY if padding_at.is_none() => {
                    padding_at = Some(ext.len());
                    push_ext(&mut ext, ext_type, body);
                }
                _ => push_ext(&mut ext, ext_type, body),
            }
        }
        let padding_at = padding_at.unwrap_or(ext.len());

        // запись(5) + handshake(4) + head + длина расширений(2) + расширения
        let without_padding = 5 + 4 + self.head.len() + 2 + ext.len();
        let pad = target.checked_sub(without_padding)?;
        if pad != 0 {
            // Заголовок padding — 4 байта: остаток в 1–3 байта не уложить.
            let data_len = pad.checked_sub(4)?;
            let mut padding = Vec::with_capacity(pad);
            push_ext(&mut padding, PADDING, &vec![0u8; data_len]);
            ext.splice(padding_at..padding_at, padding);
        }

        let mut body = self.head.to_vec();
        // Поле random — своё: одинаковое у приманки и настоящего пакета
        // выдало бы, что это одно и то же. Session id остаётся — как у
        // zapret2 (dupsid): по нему DPI связывает приманку с соединением.
        body[2..34].copy_from_slice(&super::random::bytes(32));
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut out = wrap_client_hello(&body);
        out[1..3].copy_from_slice(&self.record_version);
        (out.len() == target).then_some(out)
    }
}

/// Приманка для настоящего ClientHello `real` длиной `len`: его копия с
/// именем `sni`, если `clone` и копия собирается ровно в `len`, иначе
/// собранная с нуля. `None` — приманку такой длины не собрать.
pub fn decoy_for(real: &[u8], len: usize, sni: &str, clone: bool) -> Option<Vec<u8>> {
    if clone
        && let Some(copy) = clone_client_hello(real, sni)
        && copy.len() == len
    {
        return Some(copy);
    }
    build_decoy_hello(sni, len)
}

/// Данные расширения server_name: list_len(2) entry_type(1) name_len(2) name.
fn server_name_ext(sni: &str) -> Vec<u8> {
    let name = sni.as_bytes();
    let mut out = Vec::with_capacity(5 + name.len());
    out.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
    out.push(0x00);
    out.extend_from_slice(&(name.len() as u16).to_be_bytes());
    out.extend_from_slice(name);
    out
}

/// Оборачивает тело ClientHello в заголовок handshake и TLS-запись.
fn wrap_client_hello(body: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(9 + body.len());
    record.extend_from_slice(&[0x16, 0x03, 0x01]);
    record.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
    record.push(0x01);
    record.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..4]);
    record.extend_from_slice(body);
    record
}

/// Приманка для техники fake: ClientHello с именем `sni` ровно в `target`
/// байт. `None` — такой короткий не собрать (меньше ~80 байт).
///
/// Поддельное имя ровно в `len` байт на основе разрешённого `allowed`
/// (`www.google.com`) — для hostfakesplit: подделка занимает в потоке те же
/// номера, что настоящее имя, поэтому длина обязана совпасть.
///
/// Берётся самое длинное окончание разрешённого имени, которое помещается:
/// само имя той же длины, иначе со случайной меткой спереди
/// (`k3x9.www.google.com`), иначе его часть (`ab12x.google.com`), в худшем
/// случае — случайная метка с зоной (`abcdefg.com`). Имя выглядит
/// правдоподобно и для DPI разбирается как обычный домен.
///
/// Раньше окончания не перебирались, а имя ровно той же длины не бралось:
/// для `discord.com` (11 байт) при `fake_sni = "www.google.com"` подделкой
/// было случайное `xxxxxxx.com` — Google в нём не было вовсе. Что вышло
/// на деле, видно в логе (см. [`keeps_allowed`]).
pub fn fake_host(allowed: &str, len: usize) -> Vec<u8> {
    let label = |n: usize| -> Vec<u8> {
        super::random::bytes(n).iter().map(|b| b"abcdefghijklmnopqrstuvwxyz0123456789"[*b as usize % 36]).collect()
    };
    let allowed = allowed.trim_end_matches('.');
    let suffixes = std::iter::once(allowed).chain(allowed.match_indices('.').map(|(i, _)| &allowed[i + 1..]));
    for suffix in suffixes.filter(|s| !s.is_empty()) {
        if len == suffix.len() {
            return suffix.as_bytes().to_vec();
        }
        if len >= suffix.len() + 2 {
            let mut out = label(len - suffix.len() - 1);
            out.push(b'.');
            out.extend_from_slice(suffix.as_bytes());
            return out;
        }
    }
    label(len)
}

/// Середина домена второго уровня в имени — `midsld` у zapret: в
/// `gateway.discord.gg` это середина `discord`. Именно эту часть DPI
/// сверяет со списком, и разрез по ней прячет её надёжнее, чем по краю
/// имени. `None` — резать нечего (имя короче двух байт).
pub fn mid_sld(host: &[u8]) -> Option<usize> {
    let host = host.strip_suffix(b".").unwrap_or(host);
    let dots: Vec<usize> = host.iter().enumerate().filter(|(_, b)| **b == b'.').map(|(i, _)| i).collect();
    let (start, end) = match dots.as_slice() {
        [] => (0, host.len()),
        [only] => (0, *only),
        [.., before, last] => (before + 1, *last),
    };
    let mid = start + (end - start) / 2;
    (mid > 0 && mid < host.len()).then_some(mid)
}

/// Сохранила ли подделка разрешённое имя целиком. Нет — имя длиннее
/// настоящего, и DPI видит лишь его окончание или случайное имя: смена
/// `fake_sni` тогда проверяет не то, что задумано.
pub fn keeps_allowed(fake: &[u8], allowed: &str) -> bool {
    let allowed = allowed.trim_end_matches('.').as_bytes();
    fake == allowed || (fake.ends_with(allowed) && fake.len() > allowed.len() && fake[fake.len() - allowed.len() - 1] == b'.')
}

/// Приманка должна занять в потоке ровно те номера, что и настоящий
/// пакет. Обычный [`build_client_hello_sized`] короче ~300 байт не бывает,
/// а у программы обновления Discord (rustls) ClientHello — 268: для него
/// fake не применялся вовсе, и обновление висело там, где помогает только
/// приманка. Поэтому для коротких собирается минимальный пакет: DPI
/// нужно лишь разобрать в нём имя.
pub fn build_decoy_hello(sni: &str, target: usize) -> Option<Vec<u8>> {
    let full = build_client_hello_sized(sni, target);
    if full.len() == target {
        return Some(full);
    }

    let mut ext = Vec::new();
    push_ext(&mut ext, 0x0000, &server_name_ext(sni));
    push_ext(&mut ext, 0x002b, &[0x04, 0x03, 0x04, 0x03, 0x03]);

    let suites: &[u8] = &[0x13, 0x01, 0x13, 0x02, 0xc0, 0x2b, 0xc0, 0x2f];
    // version + random + длина session_id + шифры + сжатие + длина расширений
    let fixed = 2 + 32 + 1 + 2 + suites.len() + 2 + 2;
    let base = 5 + 4 + fixed + ext.len();
    let rem = target.checked_sub(base)?;
    // Добиваем расширением padding, а остаток короче его заголовка (4 байта)
    // — длиной session_id: иначе ровно в `target` не попасть.
    let (session_id, pad) = if rem == 0 || rem >= 4 { (0, rem.checked_sub(4)) } else { (rem, None) };
    if let Some(pad) = pad {
        push_ext(&mut ext, 0x0015, &vec![0u8; pad]);
    }

    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&super::random::bytes(32));
    body.push(session_id as u8);
    body.extend_from_slice(&super::random::bytes(session_id));
    body.extend_from_slice(&(suites.len() as u16).to_be_bytes());
    body.extend_from_slice(suites);
    body.extend_from_slice(&[0x01, 0x00]);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);

    let record = wrap_client_hello(&body);
    (record.len() == target).then_some(record)
}

/// Добавляет расширение TLS: тип(2) длина(2) данные.
pub(crate) fn push_ext(out: &mut Vec<u8>, ext_type: u16, data: &[u8]) {
    out.extend_from_slice(&ext_type.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}
/// Сколько символов имени домена лежит в одной TLS-записи.
///
/// DPI ищет запрещённое слово в каждой записи. Раньше записей было две с
/// границей посередине имени, и работало это, только если середина
/// попадала внутрь слова: «www.you|tube.com» проходил, а
/// «youtubei.go|ogleapis.com» нет — «youtube» целиком оставалось в первой
/// записи, и соединение молча висело. Граница у начала имени ломала уже
/// www.youtube.com: «youtube.com» целиком лежало во второй. Где слово,
/// заранее не известно, поэтому имя режется на куски короче любого
/// разумного ключевого слова: оно не поместится ни в одну запись.
const NAME_CHUNK: usize = 3;

/// Перестраивает ClientHello в несколько TLS-записей, разрезая имя домена
/// на куски по [`NAME_CHUNK`] символов.
///
/// Ключевое отличие от TCP-сплита: тот режет поток байт, и DPI, который
/// пересобирает TCP, склеивает всё обратно и спокойно читает SNI. Здесь же
/// меняется сама структура TLS: каждая запись — полноценная, со своим
/// 5-байтовым заголовком. По RFC 8446 handshake-сообщение может занимать
/// несколько записей, сервер соберёт нормально — а DPI, который ищет
/// имя внутри одной записи, не найдёт его даже при идеальной сборке TCP.
///
/// Первая запись — всё до конца первого куска имени; последняя — последний
/// кусок и остаток ClientHello. Возвращает готовый буфер: вызывающий код
/// отправляет первую запись отдельным сегментом, остальное — следом.
pub fn split_into_records(data: &[u8]) -> Option<Vec<u8>> {
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

    // Границы записей в координатах буфера: внутри имени через каждые
    // NAME_CHUNK символов. Имя целиком внутри первой записи.
    let name_end = loc.offset.checked_add(loc.len)?;
    if loc.offset <= HEADER || name_end > record_end {
        return None;
    }
    let mut bounds = vec![HEADER];
    bounds.extend((loc.offset + NAME_CHUNK..name_end).step_by(NAME_CHUNK));
    bounds.push(record_end);
    if bounds.len() < 3 {
        return None;
    }

    let mut out = Vec::with_capacity(data.len() + HEADER * (bounds.len() - 2));
    for pair in bounds.windows(2) {
        let part = &data[pair[0]..pair[1]];
        out.push(0x16);
        out.extend_from_slice(&version);
        out.extend_from_slice(&(part.len() as u16).to_be_bytes());
        out.extend_from_slice(part);
    }
    out.extend_from_slice(trailing);

    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Типы расширений по порядку — «отпечаток», который копия обязана
    /// сохранить (кроме padding, чей размер подгоняется).
    fn ext_types(hello: &[u8]) -> Vec<u16> {
        ParsedHello::parse(hello).unwrap().extensions.iter().map(|(t, _)| *t).collect()
    }

    fn session_id(hello: &[u8]) -> &[u8] {
        let len = hello[9 + 34] as usize;
        &hello[9 + 35..9 + 35 + len]
    }

    #[test]
    fn clone_keeps_everything_but_the_name_and_random() {
        let real = build_client_hello_sized("discord.com", 1850);
        let copy = clone_client_hello(&real, "www.google.com").unwrap();
        assert_eq!(copy.len(), real.len());
        assert_eq!(sni_host(&copy).as_deref(), Some("www.google.com"));
        assert_eq!(session_id(&copy), session_id(&real));
        assert_ne!(copy[11..43], real[11..43], "random — своё");
        assert_eq!(ext_types(&copy), ext_types(&real));
        // Настоящий пакет не тронут
        assert_eq!(sni_host(&real).as_deref(), Some("discord.com"));
    }

    /// Без padding в настоящем пакете он добавляется, если имя короче, а
    /// длиннее — берётся имя той же длины: размер совпадает всегда.
    #[test]
    fn clone_without_padding_still_matches_the_length() {
        let real = build_client_hello_sized("updates.discord.com", 0);
        assert!(!ext_types(&real).contains(&0x0015));

        let shorter = clone_client_hello(&real, "www.google.com").unwrap();
        assert_eq!(shorter.len(), real.len());
        assert_eq!(sni_host(&shorter).as_deref(), Some("www.google.com"));
        assert!(ext_types(&shorter).contains(&0x0015));

        let longer = clone_client_hello(&real, "a-much-longer-allowed-name.example.com").unwrap();
        assert_eq!(longer.len(), real.len());
        assert_eq!(sni_host(&longer).unwrap().len(), "updates.discord.com".len());
    }

    /// pre_shared_key должен остаться последним: добавленный padding — до него.
    #[test]
    fn clone_keeps_pre_shared_key_last() {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[7u8; 32]);
        body.extend_from_slice(&[32]);
        body.extend_from_slice(&[9u8; 32]);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01, 0x01, 0x00]);
        let mut ext = Vec::new();
        push_ext(&mut ext, 0x0000, &server_name_ext("updates.discord.com"));
        push_ext(&mut ext, 0x0029, &[1, 2, 3, 4]);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let real = wrap_client_hello(&body);

        let copy = clone_client_hello(&real, "google.com").unwrap();
        assert_eq!(copy.len(), real.len());
        assert_eq!(ext_types(&copy), vec![0x0000, 0x0015, 0x0029]);
    }

    #[test]
    fn clone_refuses_what_is_not_one_whole_client_hello() {
        let real = build_client_hello_sized("discord.com", 600);
        // Обрывок, лишние байты после записи, вовсе не TLS
        assert!(clone_client_hello(&real[..300], "www.google.com").is_none());
        assert!(clone_client_hello(&[real.as_slice(), b"x"].concat(), "www.google.com").is_none());
        assert!(clone_client_hello(b"GET / HTTP/1.1\r\n", "www.google.com").is_none());
    }

    /// Настоящий ClientHello от rustls (так ходит программа обновления
    /// Discord), а не наш синтетический: другой набор и порядок расширений.
    #[test]
    fn clone_of_a_real_rustls_hello() {
        use std::sync::Arc;
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let name = rustls::pki_types::ServerName::try_from("updates.discord.com").unwrap();
        let mut conn = rustls::ClientConnection::new(Arc::new(config), name).unwrap();
        let mut real = Vec::new();
        conn.write_tls(&mut real).unwrap();

        let copy = clone_client_hello(&real, "www.google.com").unwrap();
        assert_eq!(copy.len(), real.len());
        assert_eq!(sni_host(&copy).as_deref(), Some("www.google.com"));
        assert_eq!(session_id(&copy), session_id(&real));
        let without_padding = |h: &[u8]| ext_types(h).into_iter().filter(|t| *t != 0x0015).collect::<Vec<_>>();
        assert_eq!(without_padding(&copy), without_padding(&real));
    }

    /// decoy_for: копия, если просили и она подходит по длине; иначе — с нуля.
    #[test]
    fn decoy_for_falls_back_to_a_built_decoy() {
        let real = build_client_hello_sized("discord.com", 1850);
        let copy = decoy_for(&real, real.len(), "www.google.com", true).unwrap();
        assert_eq!(session_id(&copy), session_id(&real));
        let built = decoy_for(&real, real.len(), "www.google.com", false).unwrap();
        assert_ne!(session_id(&built), session_id(&real));
        // Первая половина для fake + disorder: копия длиннее — собранная с нуля
        let half = decoy_for(&real, 700, "www.google.com", true).unwrap();
        assert_eq!(half.len(), 700);
        assert_eq!(sni_host(&half).as_deref(), Some("www.google.com"));
    }

    /// Поддельное имя ровно нужной длины и похоже на домен.
    #[test]
    fn fake_host_has_the_requested_length() {
        for len in [3, 5, 9, 14, 16, 30, 60] {
            let h = fake_host("www.google.com", len);
            assert_eq!(h.len(), len, "длина {len}");
            assert!(h.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'.'));
        }
        assert!(fake_host("www.google.com", 30).ends_with(b".www.google.com"));
        assert!(fake_host("www.google.com", 9).ends_with(b".com"));
        // Та же длина — само имя; на один короче — окончание
        assert_eq!(fake_host("www.google.com", 14), b"www.google.com");
        assert_eq!(fake_host("www.google.com", 10), b"google.com");
        assert!(fake_host("www.google.com", 13).ends_with(b".google.com"));
        // discord.com (11): от google.com не поместится ничего, кроме зоны
        assert!(fake_host("www.google.com", 11).ends_with(b".com"));
        assert!(fake_host("cloudflare.com", 19).ends_with(b".cloudflare.com"));
    }

    #[test]
    fn mid_sld_cuts_the_second_level_name_in_half() {
        assert_eq!(mid_sld(b"gateway.discord.gg"), Some(8 + 3)); // disc|ord
        assert_eq!(mid_sld(b"discord.com"), Some(3)); // dis|cord
        assert_eq!(mid_sld(b"localhost"), Some(4));
        assert_eq!(mid_sld(b"x"), None);
    }

    #[test]
    fn keeps_allowed_tells_whether_the_whole_name_survived() {
        assert!(keeps_allowed(b"www.google.com", "www.google.com"));
        assert!(keeps_allowed(b"k3x9.www.google.com", "www.google.com."));
        assert!(!keeps_allowed(b"ab12x.google.com", "www.google.com"));
        assert!(!keeps_allowed(b"abcdefg.com", "cloudflare.com"));
        // Окончание совпало, но не по границе метки
        assert!(!keeps_allowed(b"xcloudflare.com", "cloudflare.com"));
    }

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

    /// Нагрузки записей рукопожатия подряд и то, что лежит после них.
    fn handshake_records(mut buf: &[u8]) -> (Vec<&[u8]>, &[u8]) {
        let mut records = Vec::new();
        while buf.first() == Some(&0x16) {
            let len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
            records.push(&buf[5..5 + len]);
            buf = &buf[5 + len..];
        }
        (records, buf)
    }

    #[test]
    fn records_hide_the_hostname_from_single_record_parsing() {
        let hello = build_client_hello("youtube.com");
        let reframed = split_into_records(&hello).expect("должно перестроиться");
        let (records, rest) = handshake_records(&reframed);

        // Нагрузка записей подряд — исходный ClientHello, ничего не потеряно
        assert!(rest.is_empty());
        assert_eq!(records.concat(), &hello[5..]);
        assert_eq!(reframed.len(), hello.len() + 5 * (records.len() - 1));

        // Имя домена не лежит целиком ни в одной из записей
        for record in &records {
            assert!(!record.windows(11).any(|w| w == b"youtube.com"));
        }
    }

    #[test]
    fn no_record_holds_a_blocked_word_wherever_it_sits_in_the_name() {
        // Две половины резали слово, только если середина в него попадала:
        // www.you|tube.com проходил, youtubei.go|ogleapis.com — нет.
        for host in ["www.youtube.com", "youtubei.googleapis.com", "youtube.googleapis.com"] {
            let hello = build_client_hello(host);
            let reframed = split_into_records(&hello).expect("должно перестроиться");
            let (records, _) = handshake_records(&reframed);
            for record in &records {
                assert!(!record.windows(4).any(|w| w == b"yout" || w == b"tube"), "{host}");
            }
        }
    }

    #[test]
    fn bytes_after_the_hello_are_not_pulled_into_the_records() {
        let hello = build_client_hello("youtube.com");
        // Следом за ClientHello — ChangeCipherSpec, как шлёт TLS 1.3 в режиме совместимости
        let ccs = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
        let mut data = hello.clone();
        data.extend_from_slice(&ccs);

        let reframed = split_into_records(&data).expect("должно перестроиться");
        let (records, rest) = handshake_records(&reframed);

        assert_eq!(records.concat(), &hello[5..], "записи рукопожатия покрывают только ClientHello");
        assert_eq!(rest, &ccs, "хвост уходит как был");
    }

    #[test]
    fn incomplete_record_is_not_reframed() {
        let hello = build_client_hello("youtube.com");
        let mut data = hello.clone();
        // Заголовок обещает больше, чем пришло
        let claimed = (hello.len() - 5 + 100) as u16;
        data[3..5].copy_from_slice(&claimed.to_be_bytes());
        assert_eq!(split_into_records(&data), None);
    }

    #[test]
    fn reframing_needs_sni() {
        assert_eq!(split_into_records(b"GET / HTTP/1.1\r\n"), None);
        assert_eq!(split_into_records(&[]), None);
    }

    #[test]
    fn probe_hello_size_is_configurable() {
        let big = super::build_client_hello_sized("updates.discord.com", 1500);
        assert_eq!(big.len(), 1500);
        // Меньше минимума — без дополнения, но SNI на месте и разбирается
        let small = super::build_client_hello_sized("updates.discord.com", 0);
        assert!(small.len() < 400, "короткий вариант: {} байт", small.len());
        assert!(find_sni(&small).is_some());
        assert!(split_into_records(&small).is_some());
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

    #[test]
    fn decoy_fits_any_hello_size() {
        // От минимального до браузерного: ровно в размер и с разбираемым именем.
        for target in (60..2000).step_by(1) {
            let Some(decoy) = build_decoy_hello("www.google.com", target) else {
                assert!(target < 90, "{target} байт: приманка должна собираться");
                continue;
            };
            assert_eq!(decoy.len(), target);
            assert_eq!(sni_host(&decoy).as_deref(), Some("www.google.com"), "{target} байт");
        }
        assert!(build_decoy_hello("www.google.com", 268).is_some(), "ClientHello программы обновления Discord");
    }

}
