//! Интеграционные проверки: настоящие сокеты, реальный путь применения стратегии.
//!
//! Юнит-тесты покрывают парсеры и статистику, но не отвечают на главный вопрос:
//! доходит ли до сервера ровно то, что задумано. Здесь поднимается фиктивный
//! upstream, через `strategy::apply::first_packet` — тот же код, что работает
//! в бою для HTTPS и SOCKS5 — отправляется ClientHello, и проверяется структура
//! принятых байт.
//!
//! TLS-сервер не нужен: upstream просто копит байты. Проверяется обрамление,
//! а не рукопожатие.
//!
//! Тесты живут внутри крейта, потому что net_surgeon — бинарный крейт, и папка
//! tests/ видела бы только публичный API библиотеки, которой здесь нет.

use std::time::Duration;

use tokio::io::AsyncReadExt;
use std::os::fd::AsRawFd;

use tokio::net::{TcpListener, TcpStream};

use crate::config::BypassParams;
use crate::engine::strategy::{apply::first_packet, Strategy};

/// Минимальный ClientHello с заданным SNI, собранный независимо от
/// проверяемого кода — иначе тест подтверждал бы сам себя.
fn client_hello(sni: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0u8; 32]);
    body.push(0x00);

    let suites: &[u8] = &[0x13, 0x01, 0x13, 0x02];
    body.extend_from_slice(&(suites.len() as u16).to_be_bytes());
    body.extend_from_slice(suites);

    body.push(0x01);
    body.push(0x00);

    let name = sni.as_bytes();
    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
    sni_ext.push(0x00);
    sni_ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(name);

    let mut ext = Vec::new();
    ext.extend_from_slice(&[0x00, 0x00]);
    ext.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
    ext.extend_from_slice(&sni_ext);

    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);

    let mut hs = vec![0x01];
    hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..4]);
    hs.extend_from_slice(&body);

    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

fn test_bypass_params() -> BypassParams {
    BypassParams {
        split_pos_min: 4,
        split_pos_max: 12,
        split_delay_ms: 1,
        window_clamp: 0,
        disorder_ttl: 2,
        fake_ttl: 2,
        fake_sni: "www.google.com".to_string(),
    }
}

/// Слушатель, копящий всё принятое. Возвращает порт и задачу с результатом.
async fn spawn_collector() -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().unwrap().port();

    let handle = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("accept");
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];

        loop {
            match tokio::time::timeout(Duration::from_millis(400), sock.read(&mut chunk)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
                Ok(Err(_)) => break,
                Err(_) => break, // фиктивный сервер не отвечает — ждать нечего
            }
        }
        buf
    });

    (port, handle)
}

/// Разбирает поток на TLS-записи: тип(1) версия(2) длина(2) данные.
fn parse_records(data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos + 5 <= data.len() {
        let len = u16::from_be_bytes([data[pos + 3], data[pos + 4]]) as usize;
        let end = pos + 5 + len;
        if end > data.len() {
            break;
        }
        out.push(&data[pos + 5..end]);
        pos = end;
    }
    out
}

#[tokio::test]
async fn tls_record_strategy_produces_two_records_hiding_the_hostname() {
    let hello = client_hello("blocked.example");
    let (port, collector) = spawn_collector().await;

    let mut upstream = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
    let fd = upstream.as_raw_fd();
    first_packet(&mut upstream, fd, &hello, Strategy::TlsRecord, &test_bypass_params())
        .await
        .expect("стратегия должна примениться");
    drop(upstream);

    let received = collector.await.expect("collector");

    // Ровно один дополнительный 5-байтовый заголовок записи
    assert_eq!(received.len(), hello.len() + 5);

    let records = parse_records(&received);
    assert_eq!(records.len(), 2, "ClientHello должен уйти двумя TLS-записями");

    // Ради этого техника и существует: имени домена нет целиком ни в одной записи
    let needle = b"blocked.example";
    for rec in &records {
        assert!(
            !rec.windows(needle.len()).any(|w| w == needle),
            "имя домена не должно попадать целиком в одну запись"
        );
    }

    // Содержимое handshake сохранено побайтово — сервер соберёт исходное сообщение
    assert_eq!(records.concat(), hello[5..]);
}

/// Запоминает каждую запись отдельно: TCP-сборщик склеивает поток,
/// а проверить нужно именно границы отправки.
#[derive(Default)]
struct WriteLog(Vec<Vec<u8>>);

impl tokio::io::AsyncWrite for WriteLog {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.0.push(buf.to_vec());
        std::task::Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn tls_records_are_sent_as_separate_writes() {
    // Маленький ClientHello, как у rustls: одним куском он целиком лёг бы
    // в один TCP-сегмент, и DPI прочитал бы обе записи подряд.
    let hello = client_hello("updates.discord.com");
    let mut log = WriteLog::default();

    crate::bypass::fragment::tls_record_split(&mut log, &hello, 0)
        .await
        .expect("запись")
        .expect("SNI найден");

    assert_eq!(log.0.len(), 2, "каждая TLS-запись — отдельной отправкой");
    for chunk in &log.0 {
        assert_eq!(parse_records(chunk).len(), 1, "граница отправки совпадает с границей записи");
    }
}

#[tokio::test]
async fn direct_strategy_leaves_the_packet_untouched() {
    let hello = client_hello("open.example");
    let (port, collector) = spawn_collector().await;

    let mut upstream = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
    let fd = upstream.as_raw_fd();
    first_packet(&mut upstream, fd, &hello, Strategy::None, &test_bypass_params())
        .await
        .expect("прямая отправка");
    drop(upstream);

    let received = collector.await.expect("collector");
    assert_eq!(received, hello, "без обхода пакет уходит байт в байт");
}

#[tokio::test]
async fn sni_split_changes_segmentation_but_not_bytes() {
    let hello = client_hello("split.example");
    let (port, collector) = spawn_collector().await;

    let mut upstream = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
    let fd = upstream.as_raw_fd();
    first_packet(&mut upstream, fd, &hello, Strategy::SniSplit, &test_bypass_params())
        .await
        .expect("сплит по SNI");
    drop(upstream);

    let received = collector.await.expect("collector");
    // TCP-сплит трогает только сегментацию: на приёме поток совпадает с исходным
    assert_eq!(received, hello);
}

#[tokio::test]
async fn parallel_connections_do_not_interfere() {
    // Браузер открывает десятки соединений на одну страницу. 100 — уже
    // не проверка корректности, а проверка того, что применение стратегии
    // не имеет общего состояния и не упирается в дескрипторы.
    let mut tasks = Vec::new();

    for i in 0..100 {
        tasks.push(tokio::spawn(async move {
            let host = format!("host{}.example", i);
            let hello = client_hello(&host);
            let (port, collector) = spawn_collector().await;

            let mut upstream = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
            let fd = upstream.as_raw_fd();
    first_packet(&mut upstream, fd, &hello, Strategy::TlsRecord, &test_bypass_params())
                .await
                .expect("стратегия");
            drop(upstream);

            let received = collector.await.expect("collector");
            (hello.len(), received)
        }));
    }

    for task in tasks {
        let (sent_len, received) = task.await.expect("задача");
        assert_eq!(received.len(), sent_len + 5);
        assert_eq!(parse_records(&received).len(), 2);
    }
}

#[tokio::test]
async fn oob_byte_is_dropped_by_the_receiver() {
    // Суть техники: DPI считает OOB-байт частью потока, а получатель без
    // SO_OOBINLINE его отбрасывает. Проверяем вторую половину утверждения —
    // до приложения на том конце доходят ровно исходные байты.
    let hello = client_hello("oob.example");
    let (port, collector) = spawn_collector().await;

    let mut upstream = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
    let fd = upstream.as_raw_fd();
    first_packet(&mut upstream, fd, &hello, Strategy::Oob, &test_bypass_params())
        .await
        .expect("oob");
    drop(upstream);

    let received = collector.await.expect("collector");
    assert_eq!(
        received, hello,
        "OOB-байт не должен попадать в поток данных получателя"
    );
}

/// SOCKS5 UDP ASSOCIATE — путь туда и обратно.
///
/// Раньше релей был односторонним: пакет уходил на сервер через слушающий
/// сокет, ответ прилетал на него же и разбирался как новый запрос клиента —
/// то есть отбрасывался. Здесь поднимается эхо-сервер и проверяется, что
/// ответ доходит до клиента в обёртке RFC 1928.
#[tokio::test]
async fn socks5_udp_returns_the_reply_to_the_client() {
    use std::net::SocketAddr;
    use tokio::net::UdpSocket;
    use tokio_util::sync::CancellationToken;

    use crate::config::Socks5JunkParams;
    use crate::observability::logging;
    use crate::observability::metrics::Metrics;
    use crate::proxy::socks5::udp::run_socks5_udp_processor;
    use crate::protocol::socks5::parse_socks5_target;

    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((n, from)) = echo.recv_from(&mut buf).await {
            if &buf[..n] == b"ping" {
                let _ = echo.send_to(b"pong", from).await;
            }
        }
    });

    // Порт релея берём у ядра и сразу освобождаем: run_socks5_udp_processor
    // биндится сам и адрес наружу не отдаёт.
    let relay_addr = {
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        probe.local_addr().unwrap()
    };

    let token = CancellationToken::new();
    let (log_tx, _log_rx) = logging::channel();
    let junk = Socks5JunkParams { count: 0, ..Socks5JunkParams::default() };
    {
        let token = token.clone();
        let relay = relay_addr.to_string();
        tokio::spawn(async move {
            run_socks5_udp_processor(&relay, junk, log_tx, Metrics::new(), token).await;
        });
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut request = vec![0x00, 0x00, 0x00, 0x01];
    match echo_addr {
        SocketAddr::V4(a) => request.extend_from_slice(&a.ip().octets()),
        SocketAddr::V6(_) => unreachable!("эхо-сервер поднят на 127.0.0.1"),
    }
    request.extend_from_slice(&echo_addr.port().to_be_bytes());
    request.extend_from_slice(b"ping");
    client.send_to(&request, relay_addr).await.unwrap();

    let mut buf = [0u8; 2048];
    let (n, _) = tokio::time::timeout(Duration::from_secs(3), client.recv_from(&mut buf))
        .await
        .expect("ответ не вернулся к клиенту: обратный путь снова односторонний")
        .unwrap();

    let (source, payload_start) =
        parse_socks5_target(&buf[..n]).expect("ответ пришёл без заголовка RFC 1928");
    assert_eq!(source, echo_addr.to_string(), "в заголовке должен стоять адрес источника");
    assert_eq!(&buf[payload_start..n], b"pong");

    token.cancel();
}

/// Протоколы, где первым говорит сервер (SSH, SMTP, IMAP), через SOCKS5
/// висели намертво: прокси ждал первый пакет клиента и до тех пор не
/// пересылал ответы сервера, а клиент ждал приветствие сервера.
#[tokio::test]
async fn socks5_connect_relays_server_greeting_before_client_speaks() {
    use std::collections::HashSet;
    use std::sync::Arc;
    use tokio::io::AsyncWriteExt;
    use tokio_util::sync::CancellationToken;

    use crate::engine::strategy::StrategyStore;
    use crate::observability::logging;
    use crate::observability::metrics::Metrics;
    use crate::proxy::socks5::tcp::run_socks5_server;

    // Сервер-«SSH»: сразу после подключения шлёт баннер, ничего не дожидаясь.
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = upstream.accept().await {
            let _ = sock.write_all(b"SSH-2.0-test\r\n").await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });

    let socks_port = {
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        probe.local_addr().unwrap().port()
    };

    let token = CancellationToken::new();
    let (log_tx, _log_rx) = logging::channel();
    {
        let token = token.clone();
        tokio::spawn(async move {
            run_socks5_server(
                "127.0.0.1", socks_port, 0, true, Arc::new(HashSet::new()),
                test_bypass_params(), 24, log_tx, Metrics::new(), token,
                Arc::new(StrategyStore::new()),
                Arc::new(crate::dns::ip_cache::IpDomainCache::new()),
            ).await;
        });
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut client = TcpStream::connect(("127.0.0.1", socks_port)).await.unwrap();
    client.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greeting = [0u8; 2];
    client.read_exact(&mut greeting).await.unwrap();

    let mut request = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    request.extend_from_slice(&upstream_port.to_be_bytes());
    client.write_all(&request).await.unwrap();
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00, "CONNECT должен пройти");

    // Клиент молчит — баннер сервера всё равно обязан дойти.
    let mut banner = [0u8; 14];
    tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut banner))
        .await
        .expect("баннер сервера не дошёл: прокси ждёт первый пакет клиента")
        .unwrap();
    assert_eq!(&banner, b"SSH-2.0-test\r\n");

    token.cancel();
}

/// Приветствие и запрос, пришедшие одним сегментом, не теряются.
///
/// RFC 1928 велит клиенту дождаться выбора метода, но некоторые клиенты шлют
/// оба сообщения сразу. Приветствие дочитывалось «сколько дали», а следующее
/// чтение начинало писать в тот же буфер с нуля — запрос затирался. Прокси
/// ждал запрос, которого уже не будет, клиент ждал ответ, и соединение
/// висело до таймаута.
#[tokio::test]
async fn socks5_accepts_greeting_and_request_in_one_segment() {
    use std::collections::HashSet;
    use std::sync::Arc;
    use tokio::io::AsyncWriteExt;
    use tokio_util::sync::CancellationToken;

    use crate::engine::strategy::StrategyStore;
    use crate::observability::logging;
    use crate::observability::metrics::Metrics;
    use crate::proxy::socks5::tcp::run_socks5_server;

    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = upstream.accept().await {
            let _ = sock.write_all(b"SSH-2.0-test\r\n").await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });

    let socks_port = {
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        probe.local_addr().unwrap().port()
    };

    let token = CancellationToken::new();
    let (log_tx, _log_rx) = logging::channel();
    {
        let token = token.clone();
        tokio::spawn(async move {
            run_socks5_server(
                "127.0.0.1", socks_port, 0, true, Arc::new(HashSet::new()),
                test_bypass_params(), 24, log_tx, Metrics::new(), token,
                Arc::new(StrategyStore::new()),
                Arc::new(crate::dns::ip_cache::IpDomainCache::new()),
            ).await;
        });
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut client = TcpStream::connect(("127.0.0.1", socks_port)).await.unwrap();

    // Приветствие и CONNECT одним write_all — ядро отдаст их прокси вместе.
    let mut both = vec![0x05, 0x01, 0x00];
    both.extend_from_slice(&[0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1]);
    both.extend_from_slice(&upstream_port.to_be_bytes());
    client.write_all(&both).await.unwrap();

    let mut greeting = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut greeting))
        .await
        .expect("прокси не ответил на приветствие")
        .unwrap();
    assert_eq!(greeting, [0x05, 0x00]);

    let mut reply = [0u8; 10];
    tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut reply))
        .await
        .expect("ответа на CONNECT нет: запрос из того же сегмента потерян")
        .unwrap();
    assert_eq!(reply[1], 0x00, "CONNECT должен пройти");

    token.cancel();
}
