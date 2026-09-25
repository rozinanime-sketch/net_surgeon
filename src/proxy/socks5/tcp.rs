use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::bypass::{extract_domain, matches_list, needs_bypass};
use crate::dns::ip_cache::IpDomainCache;
use crate::observability::logging::{LogSender, log_t, LogLevel};
use crate::config::BypassParams;
use crate::observability::metrics::Metrics;
use crate::engine::strategy::{apply::Applied, StrategyStore};
use crate::protocol::socks5::parse_socks5_target;

const SOCKS5_VERSION: u8 = 0x05;
const NO_AUTH: u8 = 0x00;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_IPV6: u8 = 0x04;
const REP_SUCCESS: u8 = 0x00;

#[allow(clippy::too_many_arguments)]
pub async fn run_socks5_server(
    listen_host: &str,
    port: u16,
    udp_port: u16,
    is_enabled: bool,
    bypass_domains: Arc<HashSet<String>>,
    bypass_params: BypassParams,
    strategy_ttl_hours: u64,
    log_tx: LogSender,
    metrics: Arc<Metrics>,
    token: CancellationToken,
    strategies: Arc<StrategyStore>,
    ip_cache: Arc<IpDomainCache>,
) {
    let addr = format!("{}:{}", listen_host, port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            log_t(&log_tx, LogLevel::Error, "log.socks5_bind_error", vec![("addr", addr.clone()), ("error", e.to_string())]);
            return;
        }
    };

    metrics.set_socks5_listening(true);
    log_t(&log_tx, LogLevel::Success, "log.socks5_listening", vec![("addr", addr.clone())]);

    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, peer)) => {
                        let _ = peer;
                        let log_tx = log_tx.clone();
                        let bypass_domains = Arc::clone(&bypass_domains);
                        let bypass_params = bypass_params.clone();
                        let strategies = Arc::clone(&strategies);
                        let metrics = Arc::clone(&metrics);
                        let ip_cache = Arc::clone(&ip_cache);
                        tokio::spawn(async move {
                            metrics.conn_opened();
                            handle_socks5(stream, udp_port, is_enabled, bypass_domains, bypass_params, strategy_ttl_hours, log_tx, Arc::clone(&metrics), strategies, ip_cache).await;
                            metrics.conn_closed();
                        });
                    }
                    Err(e) => log_t(&log_tx, LogLevel::Error, "log.socks5_error", vec![("error", e.to_string())]),
                }
            }
        }
    }

    metrics.set_socks5_listening(false);
}

#[allow(clippy::too_many_arguments)]
async fn handle_socks5(
    mut stream: TcpStream,
    udp_port: u16,
    is_enabled: bool,
    bypass_domains: Arc<HashSet<String>>,
    bypass_params: BypassParams,
    strategy_ttl_hours: u64,
    log_tx: LogSender,
    metrics: Arc<Metrics>,
    strategies: Arc<StrategyStore>,
    ip_cache: Arc<IpDomainCache>,
) {
    // 512, а не 256: запрос с ATYP=0x03 это 4 байта заголовка + 1 байт длины
    // + до 255 байт имени + 2 байта порта = 262. В прежний буфер такой запрос
    // не помещался, обрезался посередине имени и не разбирался вовсе —
    // соединение к длинному домену просто молча не открывалось.
    let mut buf = [0u8; 512];

    // Приветствие и запрос ДОЧИТЫВАЮТСЯ до конца, а не берутся одним `read`.
    // TCP не обязан отдавать сообщение целиком: запрос с длинным доменным
    // именем (до 262 байт) спокойно приходит двумя сегментами, и одиночный
    // read давал обрезанный буфер — разбор падал, и соединение молча умирало.
    //
    // Оба шага укладываются в общий срок (см. `HANDSHAKE_TIMEOUT`): иначе
    // клиент, открывший соединение и замолчавший, держал его вечно.
    let deadline = tokio::time::Instant::now() + crate::proxy::HANDSHAKE_TIMEOUT;
    let Ok(Some((n, carried))) = tokio::time::timeout_at(deadline, read_greeting(&mut stream, &mut buf)).await else { return };
    if n < 2 || buf[0] != SOCKS5_VERSION {
        log_t(&log_tx, LogLevel::Warning, "log.socks5_bad_version", vec![]);
        return;
    }

    // Хвост, пришедший в одном сегменте с приветствием, — это уже запрос.
    // По RFC 1928 клиент обязан дождаться выбора метода, но некоторые шлют
    // оба сообщения одним пакетом. Раньше этот хвост затирался следующим
    // чтением, и соединение висело: запроса прокси так и не дожидался,
    // а клиент — ответа на него. Переносим хвост в начало буфера, дальше
    // `read_request` дочитывает поверх него.
    buf.copy_within(n..n + carried, 0);

    if stream.write_all(&[SOCKS5_VERSION, NO_AUTH]).await.is_err() { return; }

    let Ok(Some(n)) = tokio::time::timeout_at(deadline, read_request(&mut stream, &mut buf, carried)).await else { return };
    if n < 7 || buf[0] != SOCKS5_VERSION { return; }

    let cmd = buf[1];
    match cmd {
        CMD_UDP_ASSOCIATE => {
            log_t(&log_tx, LogLevel::Info, "log.socks5_udp_associate", vec![]);
            handle_udp_associate(&mut stream, udp_port, &log_tx).await;
        }
        0x01 => {
            handle_connect(&mut stream, &buf[..n], is_enabled, &bypass_domains, &bypass_params, strategy_ttl_hours, &log_tx, &metrics, &strategies, &ip_cache).await;
        }
        _ => {
            log_t(&log_tx, LogLevel::Warning, "log.socks5_unknown_cmd", vec![("cmd", cmd.to_string())]);
        }
    }
}

/// Приветствие RFC 1928: VER(1) NMETHODS(1) METHODS(NMETHODS).
///
/// Возвращает длину самого приветствия и сколько байт СЛЕДУЮЩЕГО сообщения
/// уже лежит в буфере сразу за ним: клиент мог прислать приветствие и запрос
/// одним сегментом, и эти байты из сети больше не придут.
async fn read_greeting(stream: &mut TcpStream, buf: &mut [u8]) -> Option<(usize, usize)> {
    let mut have = 0usize;
    loop {
        match stream.read(&mut buf[have..]).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => have += n,
        }
        if have >= 2 {
            let greeting_len = 2 + buf[1] as usize;
            if have >= greeting_len {
                return Some((greeting_len, have - greeting_len));
            }
        }
        // Недостижимо для корректного приветствия: NMETHODS не больше 255,
        // то есть приветствие не длиннее 257 байт и в буфер всегда влезает.
        if have >= buf.len() {
            return Some((have, 0));
        }
    }
}

/// Запрос RFC 1928: VER CMD RSV ATYP DST.ADDR DST.PORT.
///
/// Признак «дочитали» — успешный разбор адреса: он знает длины всех вариантов
/// ATYP. Хвост за адресом (клиент мог сразу дослать ClientHello) остаётся
/// в буфере и подхватывается по `consumed`.
///
/// `carried` — сколько байт запроса уже лежит в начале буфера: они пришли
/// вместе с приветствием. Проверка стоит до чтения, иначе запрос, целиком
/// уместившийся в тот же сегмент, ждал бы из сети данных, которых не будет.
async fn read_request(stream: &mut TcpStream, buf: &mut [u8], carried: usize) -> Option<usize> {
    let mut have = carried;
    loop {
        if parse_socks5_target(&buf[..have]).is_some() || have >= buf.len() {
            return Some(have);
        }
        match stream.read(&mut buf[have..]).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => have += n,
        }
    }
}

async fn handle_udp_associate(stream: &mut TcpStream, udp_port: u16, log_tx: &LogSender) {
    // Адрес UDP-релея — тот, на который клиент подключился к нам по TCP.
    // Раньше здесь всегда стоял 127.0.0.1: при `listen_host = 0.0.0.0`
    // клиент с другой машины слал датаграммы себе же на localhost.
    let relay_ip = stream
        .local_addr()
        .map(|a| a.ip())
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    let response = udp_associate_reply(relay_ip, udp_port);

    if stream.write_all(&response).await.is_err() { return; }

    log_t(log_tx, LogLevel::Info, "log.socks5_udp_told", vec![("port", udp_port.to_string())]);

    let mut buf = [0u8; 1];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => break,
            Err(_) => break,
            _ => {}
        }
    }
}

/// Ответ на UDP ASSOCIATE: VER REP RSV ATYP BND.ADDR BND.PORT (RFC 1928).
fn udp_associate_reply(ip: std::net::IpAddr, port: u16) -> Vec<u8> {
    let mut out = vec![SOCKS5_VERSION, REP_SUCCESS, 0x00];
    match ip {
        std::net::IpAddr::V4(v4) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&v4.octets());
        }
        std::net::IpAddr::V6(v6) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&port.to_be_bytes());
    out
}

#[allow(clippy::too_many_arguments)]
async fn handle_connect(
    stream: &mut TcpStream,
    request: &[u8],
    is_enabled: bool,
    bypass_domains: &HashSet<String>,
    bypass_params: &BypassParams,
    strategy_ttl_hours: u64,
    log_tx: &LogSender,
    metrics: &Arc<Metrics>,
    strategies: &Arc<StrategyStore>,
    ip_cache: &IpDomainCache,
) {
    let (target, consumed) = match parse_socks5_target(request) {
        Some(v) => v,
        None => {
            let _ = stream.write_all(&[SOCKS5_VERSION, 0x01, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]).await;
            return;
        }
    };

    // Байты, пришедшие в одном TCP-сегменте следом за запросом.
    //
    // Число прочитанных байт парсер возвращал и раньше, но оно отбрасывалось
    // (`Some((t, _consumed))`), а хвост оставался в буфере и терялся вместе
    // с ним. Клиент, который шлёт CONNECT и ClientHello не дожидаясь ответа,
    // из-за этого терял всё рукопожатие: обычный `read` ниже получал уже
    // следующую порцию данных, а первая просто пропадала.
    let pipelined = request.get(consumed..).unwrap_or(&[]).to_vec();

    // REP 0x02 — «запрещено правилами»: ровно этот случай, и клиент не
    // путает его с недоступным сервером.
    let requested = extract_domain(&target);
    if crate::block::is_blocked(&requested) {
        log_t(log_tx, LogLevel::Info, "log.blocked", vec![
            ("domain", requested),
            ("via", "SOCKS5".to_string()),
        ]);
        let _ = stream.write_all(&[SOCKS5_VERSION, 0x02, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]).await;
        return;
    }

    // Адрес Telegram — через ретранслятор, если он настроен (см. модуль
    // telegram). Успех отвечается сразу: клиент MTProto заговорит только
    // после него, а до воркера ещё идти TLS и рукопожатию WebSocket.
    if let Ok(addr) = target.parse::<std::net::SocketAddr>()
        && crate::proxy::telegram::is_telegram(addr.ip(), addr.port())
        && let Some(relay) = crate::proxy::telegram::relay()
    {
        if stream.write_all(&[SOCKS5_VERSION, REP_SUCCESS, 0x00, ATYP_IPV4, 127, 0, 0, 1, 0, 0]).await.is_err() {
            return;
        }
        if let Err(e) = crate::proxy::telegram::relay_connection(&mut *stream, &relay, addr.ip(), addr.port(), &pipelined, log_tx, metrics).await {
            log_t(log_tx, LogLevel::Warning, "log.telegram_relay_error", vec![
                ("addr", addr.to_string()),
                ("error", e.to_string()),
            ]);
        }
        return;
    }

    log_t(log_tx, LogLevel::Info, "log.socks5_connect_to", vec![("target", target.clone())]);

    let mut server = match crate::dns::resolver::connect(&target).await {
        Ok(s) => s,
        Err(e) => {
            log_t(log_tx, LogLevel::Error, "log.socks5_connect_error", vec![("target", target.clone()), ("error", e.to_string())]);
            let _ = stream.write_all(&[SOCKS5_VERSION, 0x04, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0]).await;
            return;
        }
    };

    let _ = stream.write_all(&[SOCKS5_VERSION, REP_SUCCESS, 0x00, ATYP_IPV4, 127, 0, 0, 1, 0, 0]).await;

    // Nagle выключается, как в HTTPS-туннеле и прозрачном режиме. Без этого
    // вторая часть разрезанного ClientHello ждала ACK на первую: disorder
    // вырождался в обычный сплит с задержкой ретрансмита (первая половина
    // с низким TTL не доходит, ACK нет), остальные техники получали паузу
    // в RTT. Через этот путь идёт весь трафик Android, а диагностика мерила
    // техники с выключенным Nagle — в бою применялось не то, что измерено.
    let _ = stream.set_nodelay(true);
    let _ = server.set_nodelay(true);

    // Дескриптор до разделения: disorder и oob работают с сокетом напрямую.
    let server_fd = {
        use std::os::fd::AsRawFd;
        server.as_raw_fd()
    };

    let requested_domain = extract_domain(&target);

    let adaptive_ctx = crate::proxy::adaptive::Context {
        strategies, bypass_params, ttl_hours: strategy_ttl_hours, log_tx,
    };

    let (mut cr, mut cw) = stream.split();
    let (mut sr, mut sw) = server.split();

    // Байты считаются в обе стороны. Раньше их здесь не считал никто:
    // направление «клиент → сервер» шло через tokio::io::copy, а обратное
    // просто не звало add_tx. В итоге весь трафик через SOCKS5 не попадал
    // ни в счётчики, ни в график — интерфейс показывал ноль при работающем
    // туннеле.
    let metrics_c2s = Arc::clone(metrics);
    let metrics_s2c = Arc::clone(metrics);

    // Ответил ли сервер хоть чем-то. `tokio::io::copy` такого не сообщает,
    // поэтому направление «сервер → клиент» копируется вручную: без этого
    // сигнала SOCKS5-путь оставался единственным, по которому применённая
    // стратегия никак не проверялась.
    let responded = Arc::new(AtomicBool::new(false));
    let responded_flag = Arc::clone(&responded);

    // Первый пакет клиента ждётся ВНУТРИ направления «клиент → сервер», а не
    // до запуска обоих направлений. Раньше прокси сначала дочитывал первый
    // пакет и только потом начинал пересылать ответы сервера. Для протоколов,
    // где первым говорит сервер (SSH, SMTP, IMAP, FTP), это взаимная блокировка:
    // клиент ждёт приветствие сервера, прокси — данные клиента, и оба висят.
    // Так же устроен HTTPS-туннель.
    let to_server = async {
        let mut initial: Vec<u8> = pipelined;
        if initial.is_empty() {
            let mut initial_buf = [0u8; 4096];
            match cr.read(&mut initial_buf).await {
                Ok(0) | Err(_) => {
                    let _ = sw.shutdown().await;
                    return (crate::proxy::adaptive::Selected::DIRECT, requested_domain);
                }
                Ok(n) => initial.extend_from_slice(&initial_buf[..n]),
            }
        }

        // ClientHello добирается до конца записи: иначе find_sni на обрезанном
        // буфере вернул бы None и стратегия молча выродилась бы в слепой сплит.
        if crate::proxy::handshake::complete_client_hello(&mut cr, &mut initial).await
            == crate::proxy::handshake::FirstPacket::Incomplete
        {
            log_t(log_tx, LogLevel::Warning, "log.clienthello_incomplete", vec![
                ("bytes", initial.len().to_string()),
            ]);
        }

        metrics_c2s.add_rx(initial.len() as u64);

        // Имя решается здесь, а не до пересылки: для голого IP его лучше
        // всего знает сам ClientHello.
        let domain = match connection_name(&requested_domain, &initial, ip_cache, bypass_domains, is_enabled, log_tx) {
            Some(domain) => domain,
            None => {
                // Трекер по SNI. Серверу не ушло ни байта: закрываем его
                // сторону, он закроет свою, и клиент получит конец потока.
                let _ = sw.shutdown().await;
                return (crate::proxy::adaptive::Selected::DIRECT, requested_domain);
            }
        };
        let wants_bypass = needs_bypass(is_enabled, &domain, bypass_domains);

        let is_tls = initial.len() >= 5 && initial[0] == 0x16 && initial[1] == 0x03;
        let mut selected = crate::proxy::adaptive::Selected::DIRECT;

        if is_tls {
            // Раньше здесь жёстко применялись 2-байтовые чанки мимо хранилища
            // стратегий: для x.com это 788 фрагментов, ~секунда задержки и провал,
            // хотя через HTTP-прокси тот же домен открывался с tls_record.
            // Теперь все пути выбирают стратегию в одном месте.
            if wants_bypass {
                selected = crate::proxy::adaptive::select(&adaptive_ctx, &domain, initial.len());
            }

            match crate::engine::strategy::apply::first_packet(&mut sw, server_fd, &initial, selected.strategy, bypass_params).await {
                Ok(applied) => {
                    let detail = match applied {
                        Applied::TlsRecord { bytes } => format!("tls_record {}", bytes),
                        Applied::SniSplit { first, second } => format!("sni_split {}+{}", first, second),
                        Applied::Split { first, second } => format!("split {}+{}", first, second),
                        Applied::Disorder { first, second } => format!("disorder {}+{}", first, second),
                        Applied::Oob { first, second } => format!("oob {}+{}", first, second),
                        Applied::Fake { decoy, real } => format!("fake {}+{}", decoy, real),
                        Applied::None => "direct".to_string(),
                    };
                    log_t(log_tx, LogLevel::Success, "log.socks5_hello_sent", vec![
                        ("target", target.clone()),
                        ("detail", detail),
                    ]);
                }
                Err(_) => {
                    let _ = sw.shutdown().await;
                    return (selected, domain);
                }
            }
        } else if sw.write_all(&initial).await.is_err() {
            return (selected, domain);
        }

        let mut buf = [0u8; 8192];
        loop {
            match cr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    metrics_c2s.add_rx(n as u64);
                    if sw.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        // Полузакрытие, а не обрыв: клиент договорил, но сервер ещё может
        // досылать ответ.
        let _ = sw.shutdown().await;
        (selected, domain)
    };
    let to_client = async {
        let mut buf = [0u8; 8192];
        loop {
            match sr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    responded_flag.store(true, Ordering::Relaxed);
                    metrics_s2c.add_tx(n as u64);
                    if cw.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = cw.shutdown().await;
    };

    // join, а не select: select бросает вторую половину, как только закончилась
    // первая. Клиент, закрывший свою сторону сразу после запроса (обычное дело
    // для HTTP-подобных протоколов), тем самым обрывал ещё идущий ответ сервера
    // на середине. HTTPS-туннель здесь всегда использовал join — SOCKS5-путь
    // расходился с ним без всякой причины.
    let ((selected, domain), _) = tokio::join!(to_server, to_client);

    // Обратная связь по применённой стратегии — та же, что в HTTPS-туннеле.
    crate::proxy::adaptive::record_outcome(&adaptive_ctx, &domain, selected, responded.load(Ordering::Relaxed));
}

/// Имя, по которому соединение получает решение об обходе и стратегию.
/// `None` — по SNI это трекер, соединение надо закрыть.
///
/// Имя из запроса SOCKS5 — истина, его ничто не подменяет. Голый IP
/// (ATYP 0x01/0x04) присылают приложения, которые резолвят имена сами, —
/// на Android так бывает при включённом «Частном DNS»: в обход virtual DNS
/// приложения получают настоящие адреса. Для него порядок тот же, что в
/// прозрачном режиме: SNI из ClientHello, иначе кэш ответов DNS, иначе
/// сам адрес. Раньше SNI не смотрелся, а своего DNS-релея на телефоне нет —
/// кэш пуст, и обход молча выключался для всех сайтов.
fn connection_name(
    requested: &str,
    first_packet: &[u8],
    ip_cache: &IpDomainCache,
    bypass_domains: &HashSet<String>,
    is_enabled: bool,
    log_tx: &LogSender,
) -> Option<String> {
    let Ok(ip) = requested.parse::<std::net::IpAddr>() else {
        return Some(requested.to_string());
    };

    if let Some(host) = crate::bypass::tls::sni_host(first_packet) {
        // Запоминаем «адрес → домен» и для соединений без SNI (ECH, не TLS)
        // к тому же адресу — так же делает прозрачный режим.
        ip_cache.insert(ip, host.clone());

        // По SNI блокируется, по кэшу — нет: за адресом трекера живут
        // и другие сайты (см. модуль block).
        if crate::block::is_blocked(&host) {
            log_t(log_tx, LogLevel::Info, "log.blocked", vec![
                ("domain", host),
                ("via", "SNI".to_string()),
            ]);
            return None;
        }
        if is_enabled && matches_list(&host, bypass_domains) {
            log_t(log_tx, LogLevel::Info, "log.socks5_name_from_sni", vec![
                ("ip", ip.to_string()),
                ("domain", host.clone()),
            ]);
        }
        return Some(host);
    }

    // Кэш — только если он включает обход: на общих адресах CDN за одним
    // IP много сайтов, и чужое имя без нужды лучше не брать.
    if is_enabled
        && let Some(cached) = ip_cache.lookup(&ip)
        && matches_list(&cached, bypass_domains)
    {
        log_t(log_tx, LogLevel::Info, "log.bypass_via_ip_cache", vec![
            ("ip", ip.to_string()),
            ("domain", cached.clone()),
        ]);
        return Some(cached);
    }

    Some(requested.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_associate_reply_carries_the_address_the_client_reached() {
        assert_eq!(
            udp_associate_reply("192.168.1.5".parse().unwrap(), 1082),
            vec![0x05, 0x00, 0x00, 0x01, 192, 168, 1, 5, 0x04, 0x3a]
        );
        let v6 = udp_associate_reply("::1".parse().unwrap(), 1082);
        assert_eq!(v6[3], 0x04);
        assert_eq!(v6.len(), 4 + 16 + 2);
    }

    fn name_for(requested: &str, first_packet: &[u8], cache: &IpDomainCache) -> Option<String> {
        let list: HashSet<String> = ["example.com".to_string()].into();
        let (log_tx, _rx) = crate::observability::logging::channel();
        connection_name(requested, first_packet, cache, &list, true, &log_tx)
    }

    #[test]
    fn requested_name_is_never_replaced() {
        let cache = IpDomainCache::new();
        let hello = crate::bypass::tls::build_client_hello("other.example.com");
        assert_eq!(name_for("site.org", &hello, &cache).as_deref(), Some("site.org"));
    }

    #[test]
    fn bare_ip_takes_the_name_from_sni_and_remembers_it() {
        let cache = IpDomainCache::new();
        let hello = crate::bypass::tls::build_client_hello("WWW.Example.com");
        assert_eq!(name_for("203.0.113.7", &hello, &cache).as_deref(), Some("www.example.com"));
        // Соединение без SNI к тому же адресу опознаётся по запомненному
        assert_eq!(name_for("203.0.113.7", b"\x00", &cache).as_deref(), Some("www.example.com"));
    }

    #[test]
    fn sni_wins_over_the_cache() {
        let cache = IpDomainCache::new();
        cache.insert("203.0.113.8".parse().unwrap(), "cdn.example.com".into());
        let hello = crate::bypass::tls::build_client_hello("unrelated.org");
        assert_eq!(name_for("203.0.113.8", &hello, &cache).as_deref(), Some("unrelated.org"));
    }

    #[test]
    fn bare_ip_without_sni_keeps_the_address_unless_the_cache_enables_bypass() {
        let cache = IpDomainCache::new();
        cache.insert("203.0.113.9".parse().unwrap(), "unrelated.org".into());
        assert_eq!(name_for("203.0.113.9", b"SSH-2.0", &cache).as_deref(), Some("203.0.113.9"));
        assert_eq!(name_for("2001:db8::1", b"", &cache).as_deref(), Some("2001:db8::1"));
    }
}
