use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use parking_lot::Mutex;
use bytes::Bytes;

use super::quic_parser::{parse_quic_header, QuicPacketType};
use crate::cli::{LogSender, log_t, LogLevel};
use crate::metrics::Metrics;

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// Структура отдельной сессии QUIC
struct UdpSession {
    tx: mpsc::Sender<Bytes>,
    cancel_token: CancellationToken,
    last_seen_secs: u64, // Обычный u64: намного быстрее и проще, т.к. доступ уже под Mutex
    dcid: Option<Vec<u8>>,
}

/// Единый менеджер для хранения сессий и индексов DCID.
struct SessionManager {
    sessions: HashMap<SocketAddr, UdpSession>,
    dcid_index: HashMap<Vec<u8>, SocketAddr>,
}

impl SessionManager {
    fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            dcid_index: HashMap::new(),
        }
    }

    /// Очищает устаревшие сессии и возвращает количество удаленных элементов
    fn gc(&mut self, timeout: Duration) -> usize {
        let current_time = now_secs();
        let timeout_secs = timeout.as_secs();

        let expired: Vec<_> = self
        .sessions
        .iter()
        .filter(|(_, session)| {
            // Прямой доступ без атомиков
            current_time.saturating_sub(session.last_seen_secs) >= timeout_secs
        })
        .map(|(addr, session)| (*addr, session.dcid.clone()))
        .collect();

        let removed = expired.len();

        for (addr, dcid) in expired {
            if let Some(session) = self.sessions.remove(&addr) {
                session.cancel_token.cancel();
            }
            if let Some(dcid) = dcid {
                self.dcid_index.remove(&dcid);
            }
        }

        removed
    }
}

pub async fn run_udp_quic_proxy(
    listen_port: u16,
    target: String,
    log_tx: LogSender,
    metrics: Arc<Metrics>,
    token: CancellationToken,
) {
    let listen_addr = format!("0.0.0.0:{}", listen_port);
    let inbound = Arc::new(
        UdpSocket::bind(&listen_addr)
        .await
        .expect("Не удалось занять UDP порт для QUIC"),
    );

    log_t(
        &log_tx,
        LogLevel::Success,
        "log.quic_listening",
        vec![("addr", listen_addr.clone()), ("target", target.clone())],
    );

    let session_manager = Arc::new(Mutex::new(SessionManager::new()));

    // --- Фоновая задача для сборки мусора (GC) ---
    {
        let manager_gc = Arc::clone(&session_manager);
        let log_tx = log_tx.clone();
        let metrics = Arc::clone(&metrics);
        let token = token.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                     _ = tokio::time::sleep(Duration::from_secs(60)) => {
                         let removed = {
                             let mut manager = manager_gc.lock();
                             // Таймаут 5 минут для мертвых сессий
                             manager.gc(Duration::from_secs(300))
                         };

                         if removed > 0 {
                             for _ in 0..removed {
                                 metrics.quic_session_closed();
                             }
                             log_t(
                                 &log_tx,
                                 LogLevel::Info,
                                 "log.quic_gc",
                                 vec![("count", removed.to_string())],
                             );
                         }
                     }
                }
            }
        });
    }

    let mut buf = vec![0u8; 65535]; // Оставляем большой буфер для защиты от усечения UDP

    // --- Основной цикл обработки входящих пакетов ---
    loop {
        let (len, client_addr) = tokio::select! {
            _ = token.cancelled() => break,
            recv_result = inbound.recv_from(&mut buf) => {
                match recv_result {
                    Ok(v) => v,
                    Err(e) => {
                        log_t(&log_tx, LogLevel::Error, "log.quic_recv_error", vec![("error", e.to_string())]);
                        continue;
                    }
                }
            }
        };

        // Zero-copy: копируем ОДИН раз в immutable Bytes
        let data = Bytes::copy_from_slice(&buf[..len]);
        metrics.add_rx(data.len() as u64);

        let parsed_dcid = parse_quic_header(&data, 8).map(|h| h.dcid);

        let mut manager = session_manager.lock();

        // 1. Быстрая проверка существующей сессии
        if let Some(session) = manager.sessions.get_mut(&client_addr) {
            session.last_seen_secs = now_secs(); // Простое присваивание

            if let Err(e) = session.tx.try_send(data) {
                if let mpsc::error::TrySendError::Full(_) = e {
                    metrics.quic_packet_dropped();
                    log_t(&log_tx, LogLevel::Warn, "log.quic_packet_dropped", vec![("addr", client_addr.to_string())]);
                }
            }
            continue;
        }

        // 2. Логика Connection Migration по DCID
        if let Some(ref dcid) = parsed_dcid {
            if let Some(old_addr) = manager.dcid_index.get(dcid).copied() {
                if let Some(mut session) = manager.sessions.remove(&old_addr) {
                    session.last_seen_secs = now_secs();

                    if let Err(e) = session.tx.try_send(data) {
                        if let mpsc::error::TrySendError::Full(_) = e {
                            metrics.quic_packet_dropped();
                            log_t(&log_tx, LogLevel::Warn, "log.quic_packet_dropped_migration", vec![("addr", client_addr.to_string())]);
                        }
                    }

                    manager.dcid_index.insert(dcid.to_vec(), client_addr);
                    manager.sessions.insert(client_addr, session);

                    log_t(&log_tx, LogLevel::Info, "log.quic_migrated", vec![
                        ("old_addr", old_addr.to_string()),
                          ("new_addr", client_addr.to_string()),
                    ]);
                    continue;
                }
            }
        }

        // 3. Регистрация новой сессии
        let (tx, rx) = mpsc::channel(1024);
        let session_token = token.child_token();

        if let Err(e) = tx.try_send(data) {
            if let mpsc::error::TrySendError::Full(_) = e {
                metrics.quic_packet_dropped();
                log_t(&log_tx, LogLevel::Warn, "log.quic_packet_dropped_new", vec![("addr", client_addr.to_string())]);
            }
        }

        manager.sessions.insert(
            client_addr,
            UdpSession {
                tx: tx.clone(),
                                cancel_token: session_token.clone(),
                                last_seen_secs: now_secs(), // Инициализация обычного u64
                                dcid: parsed_dcid.clone(),
            },
        );

        if let Some(ref dcid) = parsed_dcid {
            manager.dcid_index.insert(dcid.to_vec(), client_addr);
        }

        // Явный сброс блокировки
        drop(manager);

        tokio::spawn(handle_session_lifecycle(
            client_addr,
            rx,
            session_token,
            Arc::clone(&inbound),
                                              target.clone(),
                                              log_tx.clone(),
                                              Arc::clone(&metrics),
                                              Arc::clone(&session_manager),
        ));
    }
}

async fn connect_new_socket(
    target: &str,
    log_tx: &LogSender,
    metrics: &Arc<Metrics>,
) -> Option<Arc<UdpSocket>> {
    let sock = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            log_t(
                log_tx,
                LogLevel::Error,
                "log.quic_socket_error",
                vec![("error", e.to_string())],
            );
            return None;
        }
    };

    if let Err(e) = sock.connect(target).await {
        log_t(
            log_tx,
            LogLevel::Error,
            "log.quic_connect_error",
            vec![("target", target.to_string()), ("error", e.to_string())],
        );
        return None;
    }

    metrics.quic_session_opened();
    metrics.set_quic_target_ok(true);

    let delay = {
        use rand::prelude::*;
        let mut rng = rand::rng();
        rng.random_range(15..=30)
    };

    let fake_packet = crate::bypass::fragment::build_fake_quic_initial();
    let bytes = fake_packet.len();
    let _ = sock.send(&fake_packet).await;
    metrics.quic_initial_sent();

    log_t(
        log_tx,
        LogLevel::Info,
        "log.quic_fake_packet",
        vec![("target", target.to_string()), ("bytes", bytes.to_string())],
    );

    tokio::time::sleep(Duration::from_millis(delay)).await;

    Some(sock)
}

/// Единая задача, управляющая жизненным циклом сессии
async fn handle_session_lifecycle(
    client_addr: SocketAddr,
    mut client_rx: mpsc::Receiver<Bytes>,
    token: CancellationToken,
    inbound: Arc<UdpSocket>,
    target: String,
    log_tx: LogSender,
    metrics: Arc<Metrics>,
    session_manager: Arc<Mutex<SessionManager>>,
) {
    let Some(upstream_sock) = connect_new_socket(&target, &log_tx, &metrics).await else {
        let mut manager = session_manager.lock();
        if let Some(session) = manager.sessions.remove(&client_addr) {
            if let Some(dcid) = session.dcid {
                manager.dcid_index.remove(&dcid);
            }
            metrics.quic_session_closed();
        }
        return;
    };

    // Возвращаем буфер 65535, чтобы избежать UDP Truncation для Jumbo Frames
    let mut buf = vec![0u8; 65535];
    let mut first_response_seen = false;

    loop {
        tokio::select! {
            _ = token.cancelled() => break,

            packet_opt = client_rx.recv() => {
                if let Some(data) = packet_opt {
                    if let Err(e) = upstream_sock.send(&data).await {
                        log_t(
                            &log_tx,
                            LogLevel::Error,
                            "log.quic_upstream_send_error",
                            vec![("addr", client_addr.to_string()), ("error", e.to_string())],
                        );
                        metrics.set_quic_target_ok(false);
                    }
                } else {
                    break;
                }
            }

            // Таймаут увеличен до 120 секунд, так как QUIC может долго молчать
            recv_res = tokio::time::timeout(Duration::from_secs(120), upstream_sock.recv(&mut buf)) => {
                match recv_res {
                    Ok(Ok(n)) => {
                        metrics.add_tx(n as u64);
                        if let Err(e) = inbound.send_to(&buf[..n], client_addr).await {
                            log_t(
                                &log_tx,
                                LogLevel::Error,
                                "log.quic_send_error",
                                vec![("addr", client_addr.to_string()), ("error", e.to_string())],
                            );
                            break;
                        }
                        if !first_response_seen {
                            metrics.quic_first_response();
                            first_response_seen = true;
                        }
                    }
                    Ok(Err(e)) => {
                        metrics.set_quic_target_ok(false);
                        log_t(
                            &log_tx,
                            LogLevel::Error,
                            "log.quic_upstream_recv_error",
                            vec![("error", e.to_string())],
                        );
                        break;
                    }
                    Err(_) => break, // Таймаут
                }
            }
        }
    }

    let mut manager = session_manager.lock();
    if let Some(session) = manager.sessions.remove(&client_addr) {
        if let Some(dcid) = session.dcid {
            manager.dcid_index.remove(&dcid);
        }
        metrics.quic_session_closed();
    }
}
