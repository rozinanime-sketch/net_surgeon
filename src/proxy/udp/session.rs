//! Исходящая половина UDP-сессии: мусорные пакеты и пересылка по порядку.
//!
//! # Зачем отдельная задача на сессию
//!
//! Раньше датаграммы отправлялись прямо там, где их принимали, и это ломалось
//! по-разному в двух местах:
//!
//! * прозрачный режим отправлял мусор с паузами прямо в цикле приёма, и на
//!   75–200 мс замирал приём UDP/443 для ВСЕХ приложений на каждую новую
//!   сессию;
//! * SOCKS5 UDP обрабатывал каждую датаграмму своей задачей: пока первая
//!   слала мусор, вторая находила готовую сессию и уходила раньше неё —
//!   QUIC Initial приходил на сервер переставленным.
//!
//! Здесь у сессии одна очередь и одна задача, которая её разгребает: сначала
//! мусор, потом датаграммы строго в порядке приёма. Приёмник только кладёт
//! в очередь и сразу возвращается к чтению.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::bypass::{fragment, random};
use crate::config::Socks5JunkParams;
use crate::observability::logging::{log_t, LogLevel, LogSender};
use crate::observability::metrics::Metrics;

use super::quic_parser::{parse_quic_header, QuicPacketType};

/// Сколько датаграмм может ждать отправки. Очередь ограничена: если сервер
/// не успевает, лишнее отбрасывается — для UDP это обычная потеря пакета,
/// а неограниченная очередь съела бы память.
const QUEUE_CAPACITY: usize = 512;

/// Какие ключи логов использовать — у SOCKS5 и прозрачного режима свои.
#[derive(Clone)]
pub struct WriterLog {
    pub log_tx: LogSender,
    pub addr: SocketAddr,
    pub forward_error_key: &'static str,
    /// Сообщение после отправки мусора. `None` — не писать.
    pub junk_sent_key: Option<&'static str>,
}

/// Первая ли это датаграмма QUIC-рукопожатия: мусор для неё должен
/// выглядеть как QUIC, иначе поток случайных байт сам становится приметой.
pub fn is_quic_initial(payload: &[u8]) -> bool {
    matches!(
        parse_quic_header(payload, 8),
        Some(h) if h.packet_type == QuicPacketType::Initial
    )
}

/// Пакет STUN (RFC 5389): служебный протокол, которым стороны звонка
/// договариваются о соединении через NAT.
///
/// По нему DPI оператора и узнаёт звонки: голос дальше зашифрован без
/// узнаваемой сигнатуры, а STUN стандартный. Признак надёжный: два старших
/// бита типа нулевые, в байтах 4..8 «магическое число» 0x2112A442, длина
/// в заголовке совпадает с остатком пакета и кратна четырём.
pub fn is_stun(payload: &[u8]) -> bool {
    const MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];
    if payload.len() < 20 || payload[0] & 0xC0 != 0 || payload[4..8] != MAGIC_COOKIE {
        return false;
    }
    let length = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    length == payload.len() - 20 && length.is_multiple_of(4)
}

/// Похоже ли на поток звонка: STUN или UDP к сетям Telegram.
///
/// Звонки Telegram ходят и на его собственные серверы (ретрансляторы
/// голоса), и напрямую между собеседниками. Первые узнаются по адресу,
/// вторые — по STUN в первом пакете. Мусор перед ними — тот же приём,
/// что `--dpi-desync=fake` с фильтром STUN у zapret.
pub fn is_call_flow(payload: &[u8], dst: std::net::IpAddr) -> bool {
    is_stun(payload) || crate::proxy::telegram::is_telegram_network(dst)
}

/// Запускает задачу отправки и возвращает очередь для датаграмм.
///
/// `junk` — параметры мусора и признак QUIC; `None` — сессия без обхода.
/// Задача завершается, когда все отправители очереди удалены (сессию убрал
/// GC) или отменён `cancel`.
pub fn spawn_writer(
    upstream: Arc<UdpSocket>,
    junk: Option<(Socks5JunkParams, bool)>,
    metrics: Arc<Metrics>,
    cancel: CancellationToken,
    log: WriterLog,
) -> mpsc::Sender<Vec<u8>> {
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(QUEUE_CAPACITY);

    tokio::spawn(async move {
        if let Some((params, quic)) = junk {
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = send_junk(&upstream, &params, quic, &metrics) => {}
            }
            if let Some(key) = log.junk_sent_key {
                log_t(&log.log_tx, LogLevel::Success, key, vec![
                    ("count", params.count.to_string()),
                    ("addr", log.addr.to_string()),
                ]);
            }
        }

        loop {
            let payload = tokio::select! {
                _ = cancel.cancelled() => break,
                p = rx.recv() => match p {
                    Some(p) => p,
                    None => break,
                },
            };
            if let Err(e) = upstream.send(&payload).await {
                log_t(&log.log_tx, LogLevel::Warning, log.forward_error_key, vec![
                    ("addr", log.addr.to_string()),
                    ("error", e.to_string()),
                ]);
            }
        }
    });

    tx
}

/// Кладёт датаграмму в очередь, не дожидаясь отправки. Переполненная или
/// закрытая очередь означает потерю пакета — для UDP это допустимо.
pub fn enqueue(sender: &mpsc::Sender<Vec<u8>>, payload: Vec<u8>) {
    let _ = sender.try_send(payload);
}

async fn send_junk(upstream: &UdpSocket, junk: &Socks5JunkParams, quic: bool, metrics: &Metrics) {
    for i in 0..junk.count {
        let packet = if quic {
            metrics.quic_initial_sent();
            fragment::build_fake_quic_initial()
        } else {
            random::bytes(random::in_range_usize(junk.size_min, junk.size_max))
        };

        let _ = upstream.send(&packet).await;

        // Пауза только между мусорными пакетами: хвостовая задерживала бы
        // настоящую датаграмму ни за чем.
        if i + 1 < junk.count {
            let delay = random::in_range(junk.delay_min_ms, junk.delay_max_ms);
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// STUN Binding Request: тип 0x0001, длина 0, cookie, 12 байт ID.
    fn binding_request() -> Vec<u8> {
        let mut p = vec![0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42];
        p.extend_from_slice(&[7u8; 12]);
        p
    }

    #[test]
    fn stun_is_recognised_and_lookalikes_are_not() {
        let mut req = binding_request();
        assert!(is_stun(&req));

        // С атрибутом: длина в заголовке растёт вместе с пакетом
        req[3] = 8;
        req.extend_from_slice(&[0x80, 0x22, 0x00, 0x04, b't', b'e', b's', b't']);
        assert!(is_stun(&req));

        let mut wrong_cookie = binding_request();
        wrong_cookie[4] = 0x00;
        assert!(!is_stun(&wrong_cookie));

        let mut wrong_length = binding_request();
        wrong_length[3] = 4;
        assert!(!is_stun(&wrong_length));

        // QUIC long header: старший бит взведён
        let mut quic = binding_request();
        quic[0] = 0xC0;
        assert!(!is_stun(&quic));
        assert!(!is_stun(&[0u8; 19]));
    }

    #[test]
    fn call_flows_are_stun_or_telegram_networks() {
        let elsewhere: std::net::IpAddr = "203.0.113.5".parse().unwrap();
        let telegram: std::net::IpAddr = "91.108.56.130".parse().unwrap();
        assert!(is_call_flow(&binding_request(), elsewhere));
        assert!(is_call_flow(b"any payload", telegram));
        assert!(!is_call_flow(b"any payload", elsewhere));
    }

    #[tokio::test]
    async fn junk_goes_first_and_payloads_keep_their_order() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        upstream.connect(server.local_addr().unwrap()).await.unwrap();

        let (log_tx, _rx) = crate::observability::logging::channel();
        let junk = Socks5JunkParams { count: 3, size_min: 1000, size_max: 1000, delay_min_ms: 20, delay_max_ms: 20, calls: true };
        let tx = spawn_writer(
            Arc::new(upstream),
            Some((junk, false)),
            Metrics::new(),
            CancellationToken::new(),
            WriterLog {
                log_tx,
                addr: server.local_addr().unwrap(),
                forward_error_key: "log.tproxy_forward_error",
                junk_sent_key: None,
            },
        );

        // Обе датаграммы попадают в очередь сразу, пока мусор ещё уходит
        enqueue(&tx, b"first".to_vec());
        enqueue(&tx, b"second".to_vec());

        let mut buf = [0u8; 2048];
        let mut got = Vec::new();
        for _ in 0..5 {
            let n = tokio::time::timeout(Duration::from_secs(2), server.recv(&mut buf))
                .await
                .expect("датаграмма не пришла")
                .unwrap();
            got.push(buf[..n].to_vec());
        }

        assert!(got[..3].iter().all(|p| p.len() == 1000), "сначала мусор");
        assert_eq!(got[3], b"first");
        assert_eq!(got[4], b"second");
    }
}
