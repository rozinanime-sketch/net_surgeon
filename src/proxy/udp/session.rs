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

    #[tokio::test]
    async fn junk_goes_first_and_payloads_keep_their_order() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        upstream.connect(server.local_addr().unwrap()).await.unwrap();

        let (log_tx, _rx) = crate::observability::logging::channel();
        let junk = Socks5JunkParams { count: 3, size_min: 1000, size_max: 1000, delay_min_ms: 20, delay_max_ms: 20 };
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
