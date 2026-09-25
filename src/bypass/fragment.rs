//! Стратегии фрагментации трафика.
//!
//! Эти функции НЕ логируют сами и не знают про LogSender — они возвращают
//! факт о том, что сделали, а логирует вызывающий код. Так они остаются
//! чистыми и переиспользуемыми: diagnostics.rs дёргает те же функции
//! без всякого логгера и просто игнорирует возвращённое значение.
//!
//! Раньше здесь был println!(), который в TUI-режиме (EnterAlternateScreen)
//! либо не виден вообще, либо портит рендер ratatui поверх интерфейса —
//! то есть информация о фрагментации не доходила до панели логов никогда.

use std::time::Duration;
use tokio::net::TcpStream;

use std::os::fd::RawFd;

use crate::config::BypassParams;
use super::{random, socket};

/// Как именно был разбит ClientHello — для лога вызывающей стороны.
pub struct SplitInfo {
    pub first: usize,
    pub second: usize,
}


/// TLS ClientHello split на ЗАДАННОЙ позиции.
///
/// Отделено от `split_client_hello`, потому что у диагностики и у боевого пути
/// разные требования: диагностике нужна воспроизводимость (иначе она измеряет
/// везение, а не стратегию), бою — непредсказуемость для DPI.
pub async fn split_client_hello_at<W>(
    server_writer: &mut W,
    data: &[u8],
    split_pos: usize,
    delay_ms: u64,
) -> std::io::Result<SplitInfo>
where
    W: tokio::io::AsyncWriteExt + Unpin,
{
    let data_len = data.len();
    let split_pos = split_pos.min(data_len);

    server_writer.write_all(&data[..split_pos]).await?;
    server_writer.flush().await?;

    tokio::time::sleep(Duration::from_millis(delay_ms)).await;

    server_writer.write_all(&data[split_pos..]).await?;
    server_writer.flush().await?;

    Ok(SplitInfo { first: split_pos, second: data_len - split_pos })
}

/// TLS ClientHello split со случайной позицией из [split_pos_min, split_pos_max].
///
/// Фиксированная позиция даёт DPI стабильный паттерн разбиения, по которому
/// обход детектируется статистически, поэтому в бою позиция дрожит.
pub async fn split_client_hello<W>(
    server_writer: &mut W,
    data: &[u8],
    bypass: &BypassParams,
) -> std::io::Result<SplitInfo>
where
    W: tokio::io::AsyncWriteExt + Unpin,
{
    let split_pos = random::in_range_usize(bypass.split_pos_min, bypass.split_pos_max);
    split_client_hello_at(server_writer, data, split_pos, bypass.split_delay_ms).await
}

/// Disorder: получатель видит вторую половину раньше первой.
///
/// Первая половина уходит с TTL=1 и умирает на первом же маршрутизаторе —
/// до сервера не доходит. Вторая уходит с обычным TTL и приходит первой.
/// Дальше ядро само ретранслирует первую половину (уже с восстановленным
/// TTL), потому что не дождалось подтверждения. Сервер собирает поток
/// правильно по sequence numbers, а DPI, читающий последовательно, видит
/// куски не в том порядке.
///
/// Цена техники — задержка ретрансмита (RTO, обычно сотни миллисекунд),
/// поэтому она уместна только там, где дешёвые техники не сработали.
///
/// Возвращает `Ok(None)`, если SNI не найден или ядро отказало в смене TTL.
pub async fn split_with_disorder<W>(
    server_writer: &mut W,
    fd: RawFd,
    data: &[u8],
    ttl: u32,
) -> std::io::Result<Option<SplitInfo>>
where
    W: tokio::io::AsyncWriteExt + Unpin,
{
    let Some(loc) = super::tls::find_sni(data) else {
        return Ok(None);
    };
    let split_pos = loc.split_point().min(data.len());

    let original_ttl = socket::get_ttl(fd).unwrap_or(64);
    if !socket::set_ttl(fd, ttl) {
        return Ok(None);
    }

    let first_result = async {
        server_writer.write_all(&data[..split_pos]).await?;
        server_writer.flush().await
    }
    .await;

    // Пауза ПЕРЕД восстановлением TTL — не для DPI, а из-за гонки с ядром.
    // `flush()` у TCP-сокета ничего не гарантирует: write_all лишь скопировал
    // данные в буфер ядра, а момент передачи выбирает оно само. Если вернуть
    // обычный TTL раньше, чем сегмент ушёл, он уйдёт с нормальным TTL, дойдёт
    // до сервера, и disorder молча выродится в обычный сплит.
    //
    // Несколько миллисекунд достаточно для передачи и несопоставимо меньше
    // RTO (сотни миллисекунд), поэтому ретрансмит всё равно получит
    // восстановленный TTL.
    tokio::time::sleep(Duration::from_millis(3)).await;

    // TTL возвращаем в любом случае: ретрансмит первой половины должен уйти
    // с нормальным TTL, иначе он тоже не дойдёт и соединение зависнет.
    let restored = restore_ttl(fd, original_ttl);
    first_result?;
    restored?;

    // Небольшая пауза, чтобы первый сегмент действительно ушёл до второго.
    tokio::time::sleep(Duration::from_millis(5)).await;

    server_writer.write_all(&data[split_pos..]).await?;
    server_writer.flush().await?;

    Ok(Some(SplitInfo { first: split_pos, second: data.len() - split_pos }))
}

/// Возвращает сокету обычный TTL после низкого.
///
/// Результат проверяется, а не выбрасывается: если вернуть не удалось, всё
/// дальнейшее, включая ретрансмит первой половины, уходит с TTL в пару
/// хопов и до сервера не доходит. Соединение при этом не рвётся, а тихо
/// виснет — и в бою это выглядит как провал стратегии, а не как сбой.
/// Честная ошибка закрывает соединение сразу, и клиент переподключается.
fn restore_ttl(fd: RawFd, ttl: u32) -> std::io::Result<()> {
    if socket::set_ttl(fd, ttl) {
        Ok(())
    } else {
        Err(std::io::Error::other(rust_i18n::t!(
            "err.ttl_restore",
            ttl = ttl,
            error = std::io::Error::last_os_error()
        ).into_owned()))
    }
}

/// Как прошла техника fake — для лога вызывающей стороны.
pub struct FakeInfo {
    /// Размер отправленной приманки.
    pub decoy: usize,
    /// Размер настоящего ClientHello.
    pub real: usize,
}

/// Fake: перед настоящим ClientHello уходит поддельный, с чужим именем.
///
/// # Зачем это отдельно от остальных техник
///
/// Все прочие ступени ищут SNI в НАСТОЯЩЕМ пакете и как-то его прячут. Если
/// SNI нет — подключение по IP, ECH, MTProto у Telegram, — прятать нечего,
/// и техники вырождаются в слепой сплит. Здесь наоборот: имя не прячут, его
/// ПОДДЕЛЫВАЮТ. Первым уходит синтетический ClientHello с безобидным SNI,
/// DPI классифицирует соединение по нему и дальше не смотрит.
///
/// Поэтому fake покрывает класс протоколов, недоступный остальным.
///
/// # Как приманка не доходит до сервера
///
/// TTL занижается ровно как в disorder: пакет умирает на промежуточном
/// маршрутизаторе, DPI провайдера его увидеть успевает, сервер — нет.
///
/// zapret для этого чаще использует `--dpi-desync-fooling=badseq`: приманка
/// уходит с заведомо неверным номером последовательности, сервер отбрасывает
/// её как вне окна. Так надёжнее — не нужно угадывать TTL, — но из обычного
/// сокета так нельзя: произвольный seq пишется только сырым пакетом через
/// NFQUEUE. Отсюда TTL как единственный доступный вариант.
///
/// # Зачем отматывать номер последовательности
///
/// Приманка до сервера не дошла, но место в нумерации уже заняла. Без отката
/// настоящие данные ушли бы со сдвигом, сервер увидел бы дыру и ждал бы
/// недостающий кусок вечно. `TCP_REPAIR` позволяет вернуть номер назад, и
/// настоящий ClientHello переиспользует ту же нумерацию.
///
/// Именно из-за этого техника требует `CAP_NET_ADMIN`: ядро справедливо не
/// отдаёт переписывание состояния TCP кому попало. Без полномочия
/// возвращается `Ok(None)`, и вызывающий откатывается на другую стратегию.
pub async fn split_with_fake<W>(
    server_writer: &mut W,
    fd: RawFd,
    data: &[u8],
    ttl: u32,
    decoy_sni: &str,
) -> std::io::Result<Option<FakeInfo>>
where
    W: tokio::io::AsyncWriteExt + Unpin,
{
    // Отмотать номер на живом соединении ядро не даст (см. fake_supported),
    // и выяснится это только ПОСЛЕ отправки приманки. Отказываемся заранее,
    // чтобы вызывающий откатился на обычный сплит, а соединение уцелело.
    if !socket::fake_supported() {
        return Ok(None);
    }

    // Номер запоминаем ДО отправки приманки. Заодно это проверка прав:
    // без CAP_NET_ADMIN режим ремонта не включится и вернётся None.
    let Some(saved_seq) = socket::tcp_send_seq(fd) else {
        return Ok(None);
    };

    let decoy = super::tls::build_client_hello(decoy_sni);

    let original_ttl = socket::get_ttl(fd).unwrap_or(64);
    if !socket::set_ttl(fd, ttl) {
        return Ok(None);
    }

    let sent = async {
        server_writer.write_all(&decoy).await?;
        server_writer.flush().await
    }
    .await;

    // Пауза перед восстановлением TTL — та же гонка с ядром, что в disorder:
    // flush() лишь скопировал данные в буфер, момент передачи выбирает ядро.
    // Вернуть TTL раньше — и приманка уйдёт с обычным, дойдёт до сервера
    // и всё сломает вместо того, чтобы обмануть DPI.
    tokio::time::sleep(Duration::from_millis(3)).await;
    let restored = restore_ttl(fd, original_ttl);
    sent?;
    restored?;

    if !socket::set_tcp_send_seq(fd, saved_seq) {
        // Приманка уже в сети, а откатить нумерацию не вышло. Продолжать
        // нельзя: сервер получит данные со сдвигом и будет ждать дыру.
        // Честная ошибка лучше повисшего соединения.
        return Err(std::io::Error::other(rust_i18n::t!("err.fake_seq").into_owned()));
    }

    server_writer.write_all(data).await?;
    server_writer.flush().await?;

    Ok(Some(FakeInfo { decoy: decoy.len(), real: data.len() }))
}

/// OOB: между половинами ClientHello вставляется мусорный байт с флагом URG.
///
/// Получатель без `SO_OOBINLINE` его отбрасывает, то есть сервер видит
/// исходные данные без изменений. DPI же обычно учитывает байт как часть
/// потока — и разбор SNI смещается на один символ.
pub async fn split_with_oob<W>(
    server_writer: &mut W,
    fd: RawFd,
    data: &[u8],
) -> std::io::Result<Option<SplitInfo>>
where
    W: tokio::io::AsyncWriteExt + Unpin,
{
    let Some(loc) = super::tls::find_sni(data) else {
        return Ok(None);
    };
    let split_pos = loc.split_point().min(data.len());

    server_writer.write_all(&data[..split_pos]).await?;
    server_writer.flush().await?;

    // Байт выбирается случайно: постоянное значение само стало бы приметой.
    socket::send_oob(fd, random::bytes(1)[0]).await?;

    server_writer.write_all(&data[split_pos..]).await?;
    server_writer.flush().await?;

    Ok(Some(SplitInfo { first: split_pos, second: data.len() - split_pos }))
}

/// Перестраивает ClientHello в несколько TLS-записей (см.
/// [`super::tls::split_into_records`]) и отправляет первую отдельным
/// TCP-сегментом, остальные — следом.
///
/// Раньше все записи уходили одним куском в расчёте на то, что DPI ищет SNI
/// только внутри одной записи. Для ClientHello браузера (~1800 байт) это
/// работало случайно: он не влезает в один сегмент, и записи и так
/// разъезжались по пакетам. Маленький ClientHello (rustls у программы
/// обновления Discord — 273 байта, curl — около 500) целиком ложился в один
/// пакет, DPI разбирал обе записи подряд и находил имя: соединение молча
/// висело. Диагностика этого не видела — её проба добита до 1500 байт.
///
/// `Ok(None)` — SNI не найден, вызывающий код откатывается на другую стратегию.
pub async fn tls_record_split<W>(
    server_writer: &mut W,
    data: &[u8],
    delay_ms: u64,
) -> std::io::Result<Option<usize>>
where
    W: tokio::io::AsyncWriteExt + Unpin,
{
    let Some(reframed) = super::tls::split_into_records(data) else {
        return Ok(None);
    };
    // Граница — конец первой записи: заголовок (5 байт) плюс её длина.
    let first_len = 5 + u16::from_be_bytes([reframed[3], reframed[4]]) as usize;
    split_client_hello_at(server_writer, &reframed, first_len, delay_ms).await?;
    Ok(Some(reframed.len()))
}

/// Split точно посередине имени домена в SNI.
///
/// В отличие от сплита по абсолютной позиции, работает одинаково для любого
/// клиента и домена: смещение вычисляется из самого ClientHello. Возвращает
/// `Ok(None)`, если SNI не найден (не ClientHello, подключение по IP,
/// зашифрованный ECH) — вызывающий код тогда откатывается на другую стратегию.
pub async fn split_at_sni<W>(
    server_writer: &mut W,
    data: &[u8],
    delay_ms: u64,
) -> std::io::Result<Option<SplitInfo>>
where
    W: tokio::io::AsyncWriteExt + Unpin,
{
    let Some(loc) = super::tls::find_sni(data) else {
        return Ok(None);
    };
    let info = split_client_hello_at(server_writer, data, loc.split_point(), delay_ms).await?;
    Ok(Some(info))
}

/// Window clamp на TCP-сокете сервера. Возвращает true, если setsockopt
/// прошёл успешно — раньше результат молча игнорировался, и о неудаче
/// нельзя было узнать никак.
///
/// `TCP_WINDOW_CLAMP` — опция Linux; на других платформах возвращается false.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn apply_window_clamp(stream: &TcpStream, window: u32) -> bool {
    let rc = unsafe {
        use std::os::unix::io::AsRawFd;
        let fd = stream.as_raw_fd();
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_WINDOW_CLAMP,
            &window as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    rc == 0
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn apply_window_clamp(_stream: &TcpStream, _window: u32) -> bool {
    false
}

// `fragment_http_request` и `apply_udp_jitter` удалены.
//
// Первая резала на два куска запрос обычного HTTP на порту 80. Практически
// весь трафик идёт по HTTPS, где SNI лежит в ClientHello и работают техники
// выше; фрагментация plaintext-запроса ничего не решала, а тянула за собой
// половину конфига.
//
// Вторая добавляла случайную задержку перед ответом простого UDP-релея. Это
// не техника обхода: DPI не смотрит на то, когда резолвер ответил клиенту.
//
// Обе жили ради секции [ranges], которая удалена вместе с ними.

/// Собирает синтетический QUIC v1 Initial-пакет с валидным структурным заголовком
/// (long header, version, DCID/SCID, varint length, packet number) и случайным
/// "телом" вместо настоящего зашифрованного CRYPTO-фрейма.
///
/// В отличие от чисто случайных байт, такой пакет проходит поверхностный
/// структурный парсинг DPI (выглядит как настоящий QUIC Initial по формату RFC 9000),
/// но расшифровать его невозможно — внутри бессмысленный шум.
///
/// Подход адаптирован из проекта SonicDPI (fakes.rs::build_fake_quic_initial).
pub fn build_fake_quic_initial() -> Vec<u8> {
    let dcid_len: usize = 8;
    let scid_len: usize = 0;

    // Целимся в ~1200 байт — типичный MTU-заполненный Initial настоящего браузера
    let header_len = 1 + 4 + 1 + dcid_len + 1 + scid_len + 1 + 2 + 1;
    let payload_len = 1200usize.saturating_sub(header_len);

    let mut out = Vec::with_capacity(1200);

    // 0xC0 = long-header(1) + fixed-bit(1) + type Initial(00) + младшие биты
    out.push(0xC0);
    // version = 1 (QUIC v1, RFC 9000)
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);

    out.push(dcid_len as u8);
    out.extend_from_slice(&random::bytes(dcid_len));

    out.push(scid_len as u8);
    // token length (varint, 0 — токен отсутствует)
    out.push(0x00);

    // Length как 2-байтовый varint (диапазон 64..=16383): старшие два бита 0b01
    let varint = 0x4000u16 | (payload_len as u16 + 1);
    out.extend_from_slice(&varint.to_be_bytes());

    // Однобайтовый packet number
    out.push(0x00);

    // Случайное "тело" — имитация зашифрованного CRYPTO-фрейма + AEAD tag
    out.extend_from_slice(&random::bytes(payload_len));

    out
}
