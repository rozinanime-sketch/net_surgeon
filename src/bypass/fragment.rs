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

use crate::config::BypassParams;
use super::{random, socket};
use super::socket::RawSock;

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
    fd: RawSock,
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

    // Ждём ухода сегмента ПЕРЕД восстановлением TTL — не для DPI, а из-за
    // гонки с ядром. `flush()` у TCP-сокета ничего не гарантирует: write_all
    // лишь скопировал данные в буфер ядра, а момент передачи выбирает оно
    // само (пейсинг, занятый воркер). Если вернуть обычный TTL раньше, чем
    // сегмент ушёл, он уйдёт с нормальным TTL, дойдёт до сервера, и disorder
    // молча выродится в обычный сплит. Поэтому не пауза наугад, а очередь
    // сокета; если ядро о ней не отвечает — прежние несколько миллисекунд.
    if !socket::wait_sent(fd, DISORDER_SEND_WAIT).await {
        tokio::time::sleep(socket::UNKNOWN_QUEUE_PAUSE).await;
    }

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

/// Сколько disorder ждёт ухода первой половины с низким TTL. Обычно это
/// доли миллисекунды: буфер сокета в начале соединения пуст.
const DISORDER_SEND_WAIT: Duration = Duration::from_millis(500);

/// Возвращает сокету обычный TTL после низкого.
///
/// Результат проверяется, а не выбрасывается: если вернуть не удалось, всё
/// дальнейшее, включая ретрансмит первой половины, уходит с TTL в пару
/// хопов и до сервера не доходит. Соединение при этом не рвётся, а тихо
/// виснет — и в бою это выглядит как провал стратегии, а не как сбой.
/// Честная ошибка закрывает соединение сразу, и клиент переподключается.
fn restore_ttl(fd: RawSock, ttl: u32) -> std::io::Result<()> {
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

/// Fake: на месте настоящего ClientHello сначала уходит поддельный, с
/// чужим именем.
///
/// # Зачем это отдельно от остальных техник
///
/// Все прочие ступени ищут SNI в НАСТОЯЩЕМ пакете и как-то его прячут:
/// режут, переставляют, разбивают на записи. DPI, который собирает поток
/// целиком (так ведут себя фильтры в сетях вузов и организаций), склеивает
/// куски обратно и видит имя. Здесь имя не прячут, а ПОДДЕЛЫВАЮТ: DPI
/// первым видит синтетический ClientHello с безобидным SNI, классифицирует
/// соединение по нему, а настоящий на тех же номерах принимает за повтор.
///
/// По той же причине fake покрывает и протоколы без открытого имени
/// (подключение по IP, ECH, MTProto), где остальным прятать нечего.
///
/// # Как приманка не доходит до сервера
///
/// TTL занижается ровно как в disorder: пакет умирает на промежуточном
/// маршрутизаторе, DPI его увидеть успевает, сервер — нет. Если TTL не
/// помогает, приманку можно пометить MD5-подписью (`fake_md5sig`): сервер
/// её выбросит, даже получив. Настоящие данные
/// ядро потом отправляет повтором на тех же номерах (см.
/// [`socket::send_fake`]), поэтому соединение начинается позже на RTO.
///
/// `Ok(None)` — техника здесь неприменима (не та система, ClientHello
/// короче ~80 байт), вызывающий откатывается на сплит.
pub async fn split_with_fake<W>(
    server_writer: &mut W,
    fd: RawSock,
    data: &[u8],
    params: &crate::config::BypassParams,
) -> std::io::Result<Option<FakeInfo>>
where
    W: tokio::io::AsyncWriteExt + Unpin,
{
    let Some(decoy) = send_decoy(server_writer, fd, data, params).await? else {
        return Ok(None);
    };
    Ok(Some(FakeInfo { decoy, real: data.len() }))
}

/// Общая часть fake и fake + disorder: приманка на номерах `real`, которые
/// потом займёт ретрансмит настоящих данных. Возвращает размер приманки;
/// `Ok(None)` — техника здесь неприменима, ничего не отправлено.
async fn send_decoy<W>(
    server_writer: &mut W,
    fd: RawSock,
    real: &[u8],
    params: &crate::config::BypassParams,
) -> std::io::Result<Option<usize>>
where
    W: tokio::io::AsyncWriteExt + Unpin,
{
    if !socket::fake_supported() {
        return Ok(None);
    }
    // Приманка обязана занять ровно столько номеров, сколько настоящие
    // данные: ретрансмит повторяет их байт в байт.
    let Some(decoy) = super::tls::build_decoy_hello(&params.fake_sni, real.len()) else {
        return Ok(None);
    };

    // Всё записанное раньше должно уйти до приманки, мимо подмены.
    server_writer.flush().await?;
    if !send_fake_signed_or_not(fd, &decoy, real, params).await? {
        return Ok(None);
    }
    Ok(Some(decoy.len()))
}

/// Приманка с подписью, если её просили и ядро умеет; ядро отказало — та же
/// приманка без подписи, на одном TTL.
async fn send_fake_signed_or_not(fd: RawSock, decoy: &[u8], real: &[u8], params: &crate::config::BypassParams) -> std::io::Result<bool> {
    let md5sig = socket::md5sig_available(params.fake_md5sig);
    if socket::send_fake(fd, decoy, real, params.fake_ttl, md5sig).await? {
        return Ok(true);
    }
    // Отказ именно в подписи — повтор без неё; иной отказ повторять незачем.
    if md5sig && !socket::md5sig_available(true) {
        return socket::send_fake(fd, decoy, real, params.fake_ttl, false).await;
    }
    Ok(false)
}

/// Как прошла техника fake + disorder — для лога вызывающей стороны.
pub struct FakeDisorderInfo {
    /// Размер отправленной приманки (= размер первой половины).
    pub decoy: usize,
    /// Первая половина настоящих данных (её доставляет ретрансмит).
    pub first: usize,
    /// Вторая половина (уходит сразу, с бОльшим номером).
    pub second: usize,
}

/// Fake + disorder: приманка на первой половине, затем настоящие данные
/// переставленными.
///
/// Это сокетная версия zapret-комбо `fake,multidisorder`. Чистого
/// multidisorder на сокете не сделать — ядро ретранслирует неподтверждённые
/// данные целиком, а не выбранными сегментами, — поэтому здесь перестановка
/// на две части, но вместе с приманкой:
///
/// 1. Приманка (чужое имя, длиной в первую половину) уходит с низким TTL и
///    умирает за DPI — тот классифицирует соединение по разрешённому имени.
///    Механизм тот же, что у [`split_with_fake`]: ядро займёт её номерами
///    `[S, S+pos)` и потом повторит на них настоящую первую половину.
/// 2. Сразу следом уходит ВТОРАЯ половина — с восстановленным TTL и номером
///    `S+pos`. Она доходит до сервера раньше, чем ретрансмит первой: DPI,
///    читающий поток подряд, видит куски не в том порядке (disorder).
/// 3. Ретрансмит доставляет настоящую первую половину на `[S, pos)`, и сервер
///    собирает целый ClientHello.
///
/// `Ok(None)` — техника здесь неприменима (не та система, нет SNI, слишком
/// короткий ClientHello для приманки): вызывающий откатывается на сплит.
pub async fn split_with_fake_disorder<W>(
    server_writer: &mut W,
    fd: RawSock,
    data: &[u8],
    params: &crate::config::BypassParams,
) -> std::io::Result<Option<FakeDisorderInfo>>
where
    W: tokio::io::AsyncWriteExt + Unpin,
{
    if !socket::fake_supported() {
        return Ok(None);
    }
    let Some(loc) = super::tls::find_sni(data) else {
        return Ok(None);
    };
    let pos = loc.split_point().min(data.len());
    // Нужны обе непустые половины: иначе это не disorder, а обычный fake.
    if pos < 1 || pos >= data.len() {
        return Ok(None);
    }
    let (first, second) = data.split_at(pos);

    // Приманка ровно в размер первой половины: ретрансмит повторит её номера
    // байт в байт настоящей первой половиной. Возвращает управление, как
    // только приманка ушла: TTL уже восстановлен, а настоящая первая половина
    // ждёт ретрансмита на `[S, pos)`.
    let Some(decoy) = send_decoy(server_writer, fd, first, params).await? else {
        return Ok(None);
    };
    // Вторая половина — с обычным TTL и номером S+pos: доходит раньше ретрансмита.
    server_writer.write_all(second).await?;
    server_writer.flush().await?;

    Ok(Some(FakeDisorderInfo { decoy, first: first.len(), second: second.len() }))
}

/// Как прошёл hostfakesplit — для лога вызывающей стороны.
pub struct HostFakeInfo {
    /// До имени, само имя, после имени.
    pub before: usize,
    pub host: usize,
    pub after: usize,
}

/// hostfakesplit (как у zapret): ClientHello режется по границам имени в
/// SNI, и на месте имени сначала уходит поддельное той же длины — с низким
/// TTL, как приманка fake.
///
/// 1. До имени — как есть.
/// 2. Поддельное имя (`fake_host`) — с низким TTL: доходит до DPI и умирает
///    за ним, а номера занимает те же, что настоящее имя.
/// 3. После имени — как есть, сразу.
/// 4. Настоящее имя — повтором ядра на своих номерах.
///
/// В отличие от fake, DPI видит не чужой ClientHello целиком, а ТОТ ЖЕ, где
/// отличается только имя: размер, расширения, ключи — всё настоящее. DPI,
/// собирающий поток и сверяющий его, обмануть так труднее. Платит, как fake,
/// временем ретрансмита.
pub async fn split_with_host_fake<W>(
    server_writer: &mut W,
    fd: RawSock,
    data: &[u8],
    params: &crate::config::BypassParams,
) -> std::io::Result<Option<HostFakeInfo>>
where
    W: tokio::io::AsyncWriteExt + Unpin,
{
    if !socket::fake_supported() {
        return Ok(None);
    }
    let Some(loc) = super::tls::find_sni(data) else {
        return Ok(None);
    };
    let (start, end) = (loc.offset, (loc.offset + loc.len).min(data.len()));
    if start == 0 || start >= end {
        return Ok(None);
    }
    let (before, rest) = data.split_at(start);
    let (host, after) = rest.split_at(end - start);
    let fake = super::tls::fake_host(&params.fake_sni, host.len());

    server_writer.write_all(before).await?;
    // Всё до имени — до подмены, с обычным TTL.
    server_writer.flush().await?;
    if !send_fake_signed_or_not(fd, &fake, host, params).await? {
        // Начало уже ушло — отказываться поздно: остальное как есть.
        server_writer.write_all(rest).await?;
        server_writer.flush().await?;
        return Ok(Some(HostFakeInfo { before: before.len(), host: 0, after: rest.len() }));
    }
    server_writer.write_all(after).await?;
    server_writer.flush().await?;
    Ok(Some(HostFakeInfo { before: before.len(), host: host.len(), after: after.len() }))
}

/// OOB: между половинами ClientHello вставляется мусорный байт с флагом URG.
///
/// Получатель без `SO_OOBINLINE` его отбрасывает, то есть сервер видит
/// исходные данные без изменений. DPI же обычно учитывает байт как часть
/// потока — и разбор SNI смещается на один символ.
pub async fn split_with_oob<W>(
    server_writer: &mut W,
    fd: RawSock,
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

// --- Окно приёма (как wssize у zapret, но для ответа сервера) -------------
//
// Маленькое окно приёма заставляет сервер слать ответ — ServerHello и
// сертификат — мелкими порциями, и DPI, который читает их целиком, не может
// этого сделать. На исходящий ClientHello (SNI) окно не влияет.
//
// Окно ставится ДО подключения: оно и коэффициент масштабирования
// объявляются в SYN, а уже объявленное окно Linux не уменьшает. Раньше
// `TCP_WINDOW_CLAMP` ставился после рукопожатия, и первая порция ответа —
// как раз ServerHello с сертификатом — приходила целиком.
//
// Цена: с маленьким окном в SYN ядро не включает масштабирование окна, и
// после отпускания ([`WindowRelease`]) окно не больше 64 КБ — на далёком
// сервере это потолок скорости (64 КБ за RTT: ~10 Мбит/с при 50 мс).

/// Сколько байт ответа сервер шлёт при маленьком окне. Больше рукопожатия
/// TLS с сертификатом; дальше окно отпускается.
pub const WINDOW_CLAMP_CUTOFF: usize = 16 * 1024;
/// Окно после отпускания: наибольшее без масштабирования.
const WINDOW_RELEASED: u32 = u16::MAX as u32;

/// Подключается к `addr` с окном приёма `clamp`, выставленным до SYN.
/// 0 — обычное подключение. Где окно не выставить (не Linux), — тоже
/// обычное.
pub async fn connect_clamped(addr: std::net::SocketAddr, clamp: u32) -> std::io::Result<TcpStream> {
    if clamp == 0 {
        return TcpStream::connect(addr).await;
    }
    let socket = if addr.is_ipv4() { tokio::net::TcpSocket::new_v4()? } else { tokio::net::TcpSocket::new_v6()? };
    set_window_clamp(super::socket::raw_sock(&socket), clamp);
    socket.connect(addr).await
}

/// `TCP_WINDOW_CLAMP` на сокете; false — не вышло или не Linux.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn set_window_clamp(fd: super::socket::RawSock, window: u32) -> bool {
    let rc = unsafe {
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
fn set_window_clamp(_fd: super::socket::RawSock, _window: u32) -> bool {
    false
}

/// Отпускает окно после первых [`WINDOW_CLAMP_CUTOFF`] байт ответа, как
/// `wssize-cutoff` у zapret: иначе маленькое окно тормозило бы всё
/// соединение. Без окна (`clamped = false`) ничего не делает.
pub struct WindowRelease {
    fd: super::socket::RawSock,
    left: Option<usize>,
}

impl WindowRelease {
    pub fn new(fd: super::socket::RawSock, clamped: bool) -> Self {
        Self { fd, left: clamped.then_some(WINDOW_CLAMP_CUTOFF) }
    }

    /// Пришло `n` байт от сервера.
    pub fn on_received(&mut self, n: usize) {
        let Some(left) = self.left else { return };
        if n >= left {
            set_window_clamp(self.fd, WINDOW_RELEASED);
            self.left = None;
        } else {
            self.left = Some(left - n);
        }
    }
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

/// Поддельный STUN Binding Request (RFC 5389): приманка для потоков звонков,
/// которые DPI узнаёт по STUN (WebRTC, P2P Telegram/WhatsApp).
///
/// В отличие от случайного мусора, это структурно валидный STUN: DPI видит
/// «начало звонка» и классифицирует поток по приманке, а настоящий первый
/// пакет принимает за продолжение. Так же zapret шлёт `--dpi-desync-fake-stun`.
///
/// Тип — Binding Request (0x0001), magic cookie по RFC, случайный 12-байтовый
/// transaction ID (чтобы серия не выглядела машинной), без атрибутов (длина 0).
/// Сервер на чужой transaction ID не ответит ничем, что сломало бы звонок:
/// настоящий ICE-агент сверяет ID и отбрасывает несовпавшее.
pub fn build_fake_stun() -> Vec<u8> {
    let mut out = Vec::with_capacity(20);
    out.extend_from_slice(&[0x00, 0x01]); // Binding Request
    out.extend_from_slice(&[0x00, 0x00]); // длина атрибутов = 0
    out.extend_from_slice(&[0x21, 0x12, 0xA4, 0x42]); // magic cookie
    out.extend_from_slice(&random::bytes(12)); // transaction ID
    out
}

/// Поддельный первый пакет голоса Discord (запрос IP discovery): приманка
/// для голосовых потоков Discord, которые узнаются именно по нему, а не по
/// STUN (см. [`crate::proxy::udp::session::is_discord_ip_discovery`]).
///
/// Форма точная (74 байта, тип 0x0001, длина 70), тело — случайное: SSRC и
/// адрес настоящему серверу ни о чём не говорят, а DPI видит узнаваемый
/// пакет голоса и пропускает поток. Аналог `--dpi-desync-fake-discord`
/// с заготовленным `ACTIVE_DISCORD_UDP.bin` у zapret.
pub fn build_fake_discord_voice() -> Vec<u8> {
    let mut out = Vec::with_capacity(74);
    out.extend_from_slice(&[0x00, 0x01, 0x00, 70]); // тип запроса + длина тела
    out.extend_from_slice(&random::bytes(70)); // SSRC + адрес + порт — шум
    out
}

#[cfg(test)]
mod window_tests {
    use super::*;

    /// Окно уходит в SYN: с ним ядро не включает масштабирование окна, без
    /// него — включает. Раньше окно ставилось после рукопожатия и в SYN не
    /// попадало вовсе.
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    #[tokio::test]
    async fn window_clamp_is_announced_in_syn() {
        fn rcv_wscale(stream: &TcpStream) -> u8 {
            let mut info: libc::tcp_info = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
            let fd = super::super::socket::raw_sock(stream);
            let rc = unsafe { libc::getsockopt(fd, libc::IPPROTO_TCP, libc::TCP_INFO, (&raw mut info).cast(), &mut len) };
            assert_eq!(rc, 0);
            info.tcpi_snd_rcv_wscale >> 4
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let a = listener.accept().await.unwrap().0;
            let b = listener.accept().await.unwrap().0;
            (a, b)
        });
        let clamped = connect_clamped(addr, 1024).await.unwrap();
        let plain = connect_clamped(addr, 0).await.unwrap();
        let _servers = accept.await.unwrap();
        assert_eq!(rcv_wscale(&clamped), 0, "с окном в SYN масштабирования нет");
        assert!(rcv_wscale(&plain) > 0, "без окна масштабирование есть");
    }

    #[test]
    fn window_is_released_after_the_cutoff() {
        let mut w = WindowRelease::new(Default::default(), true);
        w.on_received(WINDOW_CLAMP_CUTOFF - 1);
        assert!(w.left.is_some());
        w.on_received(1);
        assert!(w.left.is_none());
        let mut off = WindowRelease::new(Default::default(), false);
        off.on_received(1);
        assert!(off.left.is_none());
    }
}
