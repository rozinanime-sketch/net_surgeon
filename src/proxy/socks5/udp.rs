use tokio::net::UdpSocket;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

use crate::bypass::{extract_domain, needs_bypass};
use crate::dns::ip_cache::IpDomainCache;
use crate::observability::logging::{LogSender, log_t, LogLevel};
use crate::config::Socks5JunkParams;
use crate::observability::metrics::Metrics;
use crate::protocol::socks5::parse_socks5_target;
use crate::proxy::udp::session::{self, WriterLog};

struct SocksSession {
    /// Когда по сессии последний раз шёл трафик — В ЛЮБУЮ сторону.
    ///
    /// Общая с задачей обратного пути, поэтому за Arc/Mutex: раньше отметка
    /// обновлялась только на пути «клиент → сервер», и сессия, которая лишь
    /// принимает (скачивание, видеопоток), умирала по таймауту GC посреди
    /// живой передачи.
    last_seen: Arc<std::sync::Mutex<Instant>>,
    /// Была ли сессия QUIC. Нужно, чтобы GC декрементировал счётчик
    /// ровно для тех сессий, для которых он инкрементировался: иначе
    /// quic_sessions в интерфейсе растёт и никогда не падает.
    is_quic: bool,
    /// Очередь отправки через отдельный исходящий сокет (слушающий для этого
    /// не годится: ответ сервера был бы неотличим от нового пакета клиента).
    /// Отправку ведёт одна задача на сессию — так мусор уходит первым,
    /// а датаграммы не обгоняют друг друга.
    sender: tokio::sync::mpsc::Sender<Vec<u8>>,
    /// Останавливает задачу обратного пути, когда GC закрывает сессию.
    cancel: CancellationToken,
}

/// Ключ сессии — пара «клиент, назначение», а не один адрес клиента.
///
/// По одному адресу клиента сессия склеивала разные назначения: браузер с
/// одного UDP-порта говорит и с сервером видео, и с API, а исходящий сокет
/// у них получался общий. Ответы при этом приходили вперемешку, junk уходил
/// только для первого адреса, а отдельный сокет на пару вдобавок позволяет
/// сделать `connect()` — и тогда ядро само отбрасывает датаграммы от всех,
/// кроме этого сервера.
type SessionKey = (SocketAddr, SocketAddr);

type SessionTable = Arc<Mutex<HashMap<SessionKey, SocksSession>>>;

const SESSION_TIMEOUT: Duration = Duration::from_secs(300);
const GC_INTERVAL: Duration = Duration::from_secs(60);
/// Максимальный размер UDP-датаграммы. Меньший буфер молча срезал бы хвост
/// пакета: recv_from не сообщает об усечении и лишние байты просто пропадают.
const MAX_DATAGRAM: usize = 65535;

/// Заголовок RFC 1928 для датаграммы в сторону клиента: RSV(2) + FRAG(1) +
/// ATYP + ADDR + PORT. Клиент ждёт ответ в той же обёртке, в какой отправлял
/// запрос, и голый payload отбрасывает как повреждённый.
fn encode_reply_header(from: SocketAddr) -> Vec<u8> {
    let mut header = vec![0x00, 0x00, 0x00];
    match from {
        SocketAddr::V4(addr) => {
            header.push(0x01);
            header.extend_from_slice(&addr.ip().octets());
        }
        SocketAddr::V6(addr) => {
            header.push(0x04);
            header.extend_from_slice(&addr.ip().octets());
        }
    }
    header.extend_from_slice(&from.port().to_be_bytes());
    header
}

#[allow(clippy::too_many_arguments)]
async fn run_return_path(
    upstream: Arc<UdpSocket>,
    server_socket: Arc<UdpSocket>,
    client_addr: SocketAddr,
    last_seen: Arc<std::sync::Mutex<Instant>>,
    metrics: Arc<Metrics>,
    log_tx: LogSender,
    cancel: CancellationToken,
) {
    let mut buffer = [0u8; MAX_DATAGRAM];

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            recv_result = upstream.recv_from(&mut buffer) => {
                let (bytes_read, from) = match recv_result {
                    Ok(v) => v,
                    // ICMP «порт недоступен» на connected-сокете приходит
                    // разовой ошибкой ECONNREFUSED. Раньше она завершала
                    // обратный путь навсегда, а сессия оставалась в таблице:
                    // клиент слал дальше, ответы больше не доходили.
                    Err(e) if is_transient_udp_error(&e) => continue,
                    Err(e) => {
                        log_t(&log_tx, LogLevel::Warning, "log.socks5_udp_reply_error", vec![
                            ("addr", client_addr.to_string()),
                            ("error", e.to_string()),
                        ]);
                        break;
                    }
                };

                let mut datagram = encode_reply_header(from);
                datagram.extend_from_slice(&buffer[..bytes_read]);

                if let Err(e) = server_socket.send_to(&datagram, client_addr).await {
                    log_t(&log_tx, LogLevel::Warning, "log.socks5_udp_reply_error", vec![
                        ("addr", client_addr.to_string()),
                        ("error", e.to_string()),
                    ]);
                    break;
                }

                metrics.add_tx(bytes_read as u64);

                // Сессия жива, пока по ней идёт трафик в любую сторону.
                if let Ok(mut seen) = last_seen.lock() {
                    *seen = Instant::now();
                }
            }
        }
    }

    // Обратного пути больше нет — сессия мертва. Отмена останавливает
    // задачу отправки и служит признаком для `route`: следующая датаграмма
    // откроет сессию заново, а не уйдёт в пустоту.
    cancel.cancel();
}

/// Ошибки UDP-сокета, после которых чтение можно продолжать.
pub(crate) fn is_transient_udp_error(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset
    )
}

/// Кому из UDP-потоков нужен мусор перед первой датаграммой.
///
/// Раньше мусор получал КАЖДЫЙ поток, без оглядки на список обхода и даже
/// при выключенном обходе. На Android через SOCKS5 идёт весь UDP телефона:
/// звонки, игры, QUIC ко всем сайтам — и у каждого нового потока первая
/// датаграмма ждала шесть мусорных пакетов, 75–200 мс. Решение теперь то же,
/// что в прозрачном режиме: по имени назначения или по кэшу «адрес → домен».
#[derive(Clone)]
pub struct UdpPolicy {
    pub is_enabled: bool,
    pub bypass_domains: Arc<HashSet<String>>,
    pub ip_cache: Arc<IpDomainCache>,
}

pub async fn run_socks5_udp_processor(
    socks5_udp_port: &str,
    junk: Socks5JunkParams,
    policy: UdpPolicy,
    log_tx: LogSender,
    metrics: Arc<Metrics>,
    token: CancellationToken,
) {
    let server_socket = match UdpSocket::bind(socks5_udp_port).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            log_t(&log_tx, LogLevel::Error, "log.bind_error", vec![("addr", socks5_udp_port.to_string()), ("error", e.to_string())]);
            return;
        }
    };
    log_t(&log_tx, LogLevel::Success, "log.socks5_udp_listening", vec![("addr", socks5_udp_port.to_string())]);

    let active_sessions: SessionTable = Arc::new(Mutex::new(HashMap::new()));

    // Клиентские UDP-порты меняются часто, так что без GC таблица росла бы
    // неограниченно вместе с сокетами обратного пути.
    {
        let sessions_gc = Arc::clone(&active_sessions);
        let metrics_gc = Arc::clone(&metrics);
        let token = token.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    _ = tokio::time::sleep(GC_INTERVAL) => {
                        let now = Instant::now();
                        let mut table = sessions_gc.lock().await;

                        // Считаем закрываемые QUIC-сессии, чтобы счётчик
                        // уменьшался ровно там, где он увеличивался.
                        let mut closed_quic = 0usize;
                        table.retain(|_, session| {
                            let last = session.last_seen.lock().map(|s| *s).unwrap_or(now);
                            let alive = now.duration_since(last) < SESSION_TIMEOUT;
                            if !alive {
                                if session.is_quic {
                                    closed_quic += 1;
                                }
                                session.cancel.cancel();
                            }
                            alive
                        });
                        drop(table);

                        for _ in 0..closed_quic {
                            metrics_gc.quic_session_closed();
                        }
                    }
                }
            }
        });
    }

    let mut buffer = [0u8; MAX_DATAGRAM];

    loop {
        tokio::select! {
            _ = token.cancelled() => break,
            recv_result = server_socket.recv_from(&mut buffer) => {
                let (bytes_read, client_src_addr) = match recv_result {
                    Ok(v) => v,
                    Err(e) => {
                        log_t(&log_tx, LogLevel::Error, "log.socks5_udp_error", vec![("error", e.to_string())]);
                        continue;
                    }
                };
                if bytes_read < 10 { continue; }
                let packet = &buffer[..bytes_read];

                // FRAG != 0 — фрагмент датаграммы (RFC 1928 §7). Сборку мы не
                // поддерживаем, а молча переслать фрагмент как целую датаграмму
                // значит отдать серверу битые данные.
                if packet[2] != 0x00 {
                    log_t(&log_tx, LogLevel::Warning, "log.socks5_udp_frag_unsupported", vec![
                        ("frag", packet[2].to_string()),
                    ]);
                    continue;
                }

                let Some((dst_addr_str, payload_start)) = parse_socks5_target(packet) else { continue };
                let payload = packet[payload_start..].to_vec();
                metrics.add_rx(payload.len() as u64);

                let ctx = RouteCtx {
                    server_socket: Arc::clone(&server_socket),
                    sessions: Arc::clone(&active_sessions),
                    junk: junk.clone(),
                    policy: policy.clone(),
                    log_tx: log_tx.clone(),
                    metrics: Arc::clone(&metrics),
                    token: token.clone(),
                };

                match dst_addr_str.parse::<SocketAddr>() {
                    // Адрес уже числовой — обрабатываем прямо здесь. Раньше
                    // каждая датаграмма уходила в свою задачу, и задачи
                    // обгоняли друг друга: вторая датаграмма сессии уходила
                    // на сервер раньше первой. Здесь нет ни одного долгого
                    // ожидания — отправка идёт через очередь сессии.
                    Ok(dst_addr) => route(ctx, client_src_addr, dst_addr, None, payload).await,
                    // ATYP 0x03 отдаёт имя, а резолв может занять сотни
                    // миллисекунд — его нельзя ждать в цикле приёма, иначе
                    // встанут все клиенты. Порядок датаграмм к одному имени
                    // на время резолва не гарантируется; клиенты, которым
                    // он важен (QUIC), шлют адрес, а не имя.
                    Err(_) => {
                        // Сервисы умного DNS (нейросети) — только по TCP.
                        // Системный резолвер здесь дал бы настоящий адрес, и
                        // QUIC пришёл бы к сервису с российского IP: отказ по
                        // региону, хотя TCP идёт через умный DNS. Без ответа
                        // браузер сразу уходит на TCP.
                        let host = dst_addr_str.rsplit_once(':').map_or(dst_addr_str.as_str(), |(h, _)| h);
                        if crate::dns::smart::matches(host) {
                            continue;
                        }
                        tokio::spawn(async move {
                            let dst_addr = match crate::dns::resolver::lookup_system(&dst_addr_str).await {
                                Ok(addrs) => match addrs.into_iter().next() {
                                    Some(a) => a,
                                    None => return,
                                },
                                Err(e) => {
                                    log_t(&ctx.log_tx, LogLevel::Warning, "log.socks5_udp_resolve_error", vec![
                                        ("target", dst_addr_str.clone()),
                                        ("error", e.to_string()),
                                    ]);
                                    return;
                                }
                            };
                            route(ctx, client_src_addr, dst_addr, Some(extract_domain(&dst_addr_str)), payload).await;
                        });
                    }
                }
            }
        }
    }
}

/// Всё, что нужно для пересылки одной датаграммы.
struct RouteCtx {
    server_socket: Arc<UdpSocket>,
    sessions: SessionTable,
    junk: Socks5JunkParams,
    policy: UdpPolicy,
    log_tx: LogSender,
    metrics: Arc<Metrics>,
    token: CancellationToken,
}

/// Находит или открывает сессию и ставит датаграмму в её очередь.
///
/// `name` — имя назначения, если клиент прислал его (ATYP 0x03), а не адрес.
async fn route(ctx: RouteCtx, client_src_addr: SocketAddr, dst_addr: SocketAddr, name: Option<String>, payload: Vec<u8>) {
    // Блокировка держится и на время bind: иначе два первых пакета одного
    // клиента подняли бы по сокету каждый, и ответы пошли бы мимо живой сессии.
    let key: SessionKey = (client_src_addr, dst_addr);
    let mut table = ctx.sessions.lock().await;

    if let Some(session) = table.get(&key) {
        if !session.cancel.is_cancelled() {
            if let Ok(mut seen) = session.last_seen.lock() {
                *seen = Instant::now();
            }
            session::enqueue(&session.sender, payload);
            return;
        }
        // Обратный путь сессии умер — убираем её и открываем новую ниже.
        if let Some(dead) = table.remove(&key)
            && dead.is_quic
        {
            ctx.metrics.quic_session_closed();
        }
    }

    // Имя назначения: присланное клиентом, иначе из кэша «адрес → домен» —
    // его наполняют DoH-релей и SOCKS5 CONNECT по SNI. Браузер обычно сначала
    // открывает сайт по TCP и лишь потом переходит на QUIC, так что к этому
    // моменту адрес уже опознан.
    let domain = name.or_else(|| ctx.policy.ip_cache.lookup(&dst_addr.ip()));
    let is_quic = session::is_quic_initial(&payload);

    // Трекер отбрасывается, как в прозрачном режиме: сессия не открывается,
    // следующие датаграммы придут сюда же. Если адрес общий и кэш ошибся,
    // браузер откатится на TCP, где имя видно в SNI. В лог — только по
    // Initial, иначе повторы его засыпали бы.
    if let Some(d) = &domain
        && crate::block::is_blocked(d)
    {
        if is_quic {
            log_t(&ctx.log_tx, LogLevel::Info, "log.blocked", vec![
                ("domain", d.clone()),
                ("via", "QUIC".to_string()),
            ]);
        }
        return;
    }

    let bypass = domain
        .as_deref()
        .is_some_and(|d| needs_bypass(ctx.policy.is_enabled, d, &ctx.policy.bypass_domains));
    // Звонок (STUN или UDP к сетям Telegram) — мусор и без списка обхода:
    // DPI режет звонки по STUN, а у ретрансляторов голоса нет имени.
    let call = !bypass
        && ctx.policy.is_enabled
        && ctx.junk.calls
        && session::is_call_flow(&payload, dst_addr.ip());

    // Семейство исходящего сокета должно совпадать с адресом назначения,
    // иначе send упадёт.
    let bind_addr = if dst_addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let upstream = match UdpSocket::bind(bind_addr).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            log_t(&ctx.log_tx, LogLevel::Error, "log.bind_error", vec![
                ("addr", bind_addr.to_string()),
                ("error", e.to_string()),
            ]);
            return;
        }
    };

    // connect на UDP не открывает соединения, а фиксирует пир: ядро начинает
    // отбрасывать датаграммы от всех остальных. Без этого любой, кто угадает
    // эфемерный порт, мог подсунуть клиенту свой ответ.
    if let Err(e) = upstream.connect(dst_addr).await {
        log_t(&ctx.log_tx, LogLevel::Warning, "log.socks5_udp_forward_error", vec![
            ("addr", dst_addr.to_string()),
            ("error", e.to_string()),
        ]);
        return;
    }

    let last_seen = Arc::new(std::sync::Mutex::new(Instant::now()));
    let cancel = ctx.token.child_token();

    tokio::spawn(run_return_path(
        Arc::clone(&upstream),
        Arc::clone(&ctx.server_socket),
        client_src_addr,
        Arc::clone(&last_seen),
        Arc::clone(&ctx.metrics),
        ctx.log_tx.clone(),
        cancel.clone(),
    ));

    if call {
        log_t(&ctx.log_tx, LogLevel::Info, "log.call_junk", vec![("addr", dst_addr.to_string())]);
    }
    if bypass {
        // С именем: по одному адресу не понять, почему поток получил мусор.
        let target = match &domain {
            Some(d) => format!("{d} ({dst_addr})"),
            None => dst_addr.to_string(),
        };
        log_t(&ctx.log_tx, LogLevel::Warning, "log.socks5_udp_junk", vec![("addr", target)]);
    }
    if is_quic {
        ctx.metrics.quic_session_opened();
    }

    // Мусор отправит задача сессии, первая датаграмма встанет в очередь
    // следом за ним.
    let sender = session::spawn_writer(
        upstream,
        (bypass || call).then(|| (ctx.junk.clone(), is_quic)),
        Arc::clone(&ctx.metrics),
        cancel.clone(),
        WriterLog {
            log_tx: ctx.log_tx.clone(),
            addr: dst_addr,
            forward_error_key: "log.socks5_udp_forward_error",
            junk_sent_key: Some("log.socks5_udp_junk_sent"),
        },
    );
    session::enqueue(&sender, payload);

    table.insert(key, SocksSession { last_seen, is_quic, sender, cancel });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reply_header_wraps_ipv4_source() {
        let header = encode_reply_header("93.184.216.34:443".parse().unwrap());
        assert_eq!(header, vec![0x00, 0x00, 0x00, 0x01, 93, 184, 216, 34, 0x01, 0xBB]);
    }

    #[test]
    fn reply_header_round_trips_through_the_request_parser() {
        // Клиент разбирает ответ тем же кодом, что и мы — запрос клиента,
        // поэтому обёртка обязана читаться обратно без потерь.
        let source: SocketAddr = "[2606:4700:4700::1111]:53".parse().unwrap();
        let mut datagram = encode_reply_header(source);
        let payload_start = datagram.len();
        datagram.extend_from_slice(b"payload");

        let (parsed, offset) = parse_socks5_target(&datagram).unwrap();
        assert_eq!(parsed, source.to_string());
        assert_eq!(offset, payload_start);
        assert_eq!(&datagram[offset..], b"payload");
    }
}
