//! Исходящая половина UDP-сессии: пересылка по порядку и смена порта.
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
//! Здесь у сессии одна очередь и одна задача, которая её разгребает:
//! датаграммы уходят строго в порядке приёма. Приёмник только кладёт в
//! очередь и сразу возвращается к чтению. Мусора с тех пор нет совсем (см.
//! `config::CallParams`), но порядок по-прежнему держит эта задача, и смена
//! порта ([`Hop`]) тоже живёт здесь.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::observability::logging::{log_t, LogLevel, LogSender};

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
}

/// Смена исходного порта каждые `every` датаграмм.
///
/// Провайдер режет UDP к сетям Cloudflare и AWS (а на них голос Discord,
/// серверы `c-…`) по счётчику на поток: первые пять пакетов проходят, дальше
/// поток глохнет навсегда, на любом порту и с любым содержимым. Замер
/// 2026-10-17, NTP к time.cloudflare.com: `✓✓✓✓✓..........`; пауза в 30 с
/// блок не снимает, пакет раз в 2 с — тоже (считаются пакеты, а не время).
/// Мусор против этого бессилен — он сам идёт в счёт пяти. А вот
/// новый исходный порт каждые 4 пакета прошёл весь: `✓✓✓✓|✓✓✓✓|✓✓✓✓|…`.
/// Счётчик у провайдера привязан к потоку, и поток просто не доживает
/// до отсечки.
///
/// Ответы сервер может слать на любой из недавних портов, поэтому старые
/// сокеты не закрываются сразу: их читатели живут, пока сокет не замолчит
/// на [`HOP_IDLE`] (см. `transparent_udp::return_path` и
/// `socks5::udp::run_return_path`).
pub struct Hop {
    pub every: u32,
    pub dst: SocketAddr,
    /// Номер текущего сокета. Читатель старого сокета по нему понимает, что
    /// сокет уже не текущий и при тишине его можно бросить.
    pub generation: Arc<AtomicU64>,
    /// Запускает читателя ответов для нового сокета (сокет, его номер).
    pub on_new: Box<dyn Fn(Arc<UdpSocket>, u64) + Send + Sync>,
}

/// Сколько тишины терпит читатель старого сокета при смене порта. Ответ на
/// последний отправленный с него пакет приходит за время RTT; держать
/// дольше — копить сокеты: голос шлёт ~50 пакетов в секунду, при смене
/// каждые 4 это дюжина новых портов в секунду.
pub const HOP_IDLE: std::time::Duration = std::time::Duration::from_secs(5);

/// Старый ли это сокет: `hop` — (номер сокета, номер текущего). Читатель
/// старого сокета при тишине уходит, текущего — ждёт дальше.
pub fn is_stale(hop: &Option<(u64, Arc<AtomicU64>)>) -> bool {
    matches!(hop, Some((mine, current)) if *mine != current.load(Ordering::Relaxed))
}

/// Новый исходящий сокет к тому же назначению — то есть новый исходный порт.
async fn fresh_upstream(dst: SocketAddr) -> std::io::Result<UdpSocket> {
    let any = if dst.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let sock = UdpSocket::bind(any).await?;
    sock.connect(dst).await?;
    Ok(sock)
}

impl Hop {
    /// Открывает следующий сокет и запускает его читателя. При ошибке
    /// остаётся старый: лучше поток, который скоро обрежут, чем никакого.
    async fn next(&self, log: &WriterLog) -> Option<Arc<UdpSocket>> {
        match fresh_upstream(self.dst).await {
            Ok(sock) => {
                let sock = Arc::new(sock);
                let generation = self.generation.fetch_add(1, Ordering::Relaxed) + 1;
                (self.on_new)(Arc::clone(&sock), generation);
                Some(sock)
            }
            Err(e) => {
                log_t(&log.log_tx, LogLevel::Warning, log.forward_error_key, vec![
                    ("addr", log.addr.to_string()),
                    ("error", e.to_string()),
                ]);
                None
            }
        }
    }
}

/// Первая ли это датаграмма QUIC-рукопожатия: по ней считаются QUIC-сессии
/// в интерфейсе и пишется лог о блокировке.
pub fn is_quic_initial(payload: &[u8]) -> bool {
    matches!(
        parse_quic_header(payload, 8),
        Some(h) if h.packet_type == QuicPacketType::Initial
    )
}

/// Пакет STUN (RFC 5389): служебный протокол, которым стороны звонка
/// договариваются о соединении через NAT. Им начинается звонок WebRTC и
/// P2P Telegram/WhatsApp. Признак надёжный: два старших
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

/// Первый пакет голоса Discord: запрос IP discovery.
///
/// Discord не пользуется STUN. Свой внешний адрес клиент узнаёт у
/// голосового сервера сам: 74 байта, тип 0x0001, длина 70, дальше SSRC,
/// адрес и порт. По этому пакету голос Discord и отличается от прочего UDP
/// на тех же портах.
pub fn is_discord_ip_discovery(payload: &[u8]) -> bool {
    payload.len() == 74 && payload[..4] == [0x00, 0x01, 0x00, 70]
}

/// Похоже ли на поток звонка: STUN, голос Discord или UDP к сетям Telegram.
///
/// Звонки Telegram ходят и на его собственные серверы (ретрансляторы
/// голоса), и напрямую между собеседниками. Первые узнаются по адресу,
/// вторые — по STUN в первом пакете. Таким потокам меняется исходный порт
/// (см. [`Hop`]).
pub fn is_call_flow(payload: &[u8], dst: std::net::IpAddr) -> bool {
    is_stun(payload) || is_discord_ip_discovery(payload) || crate::proxy::telegram::is_telegram_network(dst)
}

/// Порты назначения, на которых бывают звонки: STUN (стандартный) и
/// голосовые серверы Discord.
///
/// Диапазон `19294-19344` перекрывает и Google STUN (`19302-19309`, через
/// него идёт WebRTC), и голосовые серверы Discord: часть из них отвечает в
/// `19294-19344`, и на прежнем узком `19302-19309` такие звонки проходили
/// мимо перехвата. Так же этот диапазон держат zapret/Flowseal.
///
/// По ним прозрачный режим Linux решает, какой UDP вообще перехватывать
/// (правила nftables). Весь UDP перехватывать незачем: игры и VPN шли бы через прокси без
/// всякой пользы. Сети Telegram перехватываются по адресу, на любом порту.
pub const CALL_PORTS: &[(u16, u16)] = &[(3478, 3481), (19294, 19344), (50000, 65535)];

/// Адреса, UDP к которым по портам звонков не перехватывается: петля,
/// домашняя сеть, мультикаст. На тех же портах там бывают локальные игры
/// и службы, а DPI провайдера их всё равно не видит.
pub const LOCAL_NETS_V4: &[([u8; 4], u8)] = &[
    ([127, 0, 0, 0], 8),
    ([10, 0, 0, 0], 8),
    ([100, 64, 0, 0], 10),
    ([169, 254, 0, 0], 16),
    ([172, 16, 0, 0], 12),
    ([192, 168, 0, 0], 16),
    ([224, 0, 0, 0], 4),
    ([255, 255, 255, 255], 32),
];

/// Запускает задачу отправки и возвращает очередь для датаграмм.
///
/// `hop` — смена исходного порта (см. [`Hop`]); `None` — один сокет на всю
/// сессию. Задача завершается, когда все отправители очереди удалены
/// (сессию убрал GC) или отменён `cancel`.
pub fn spawn_writer(
    upstream: Arc<UdpSocket>,
    hop: Option<Hop>,
    cancel: CancellationToken,
    log: WriterLog,
) -> mpsc::Sender<Vec<u8>> {
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(QUEUE_CAPACITY);

    tokio::spawn(async move {
        let mut upstream = upstream;
        let mut sent: u32 = 0;
        loop {
            let payload = tokio::select! {
                _ = cancel.cancelled() => break,
                p = rx.recv() => match p {
                    Some(p) => p,
                    None => break,
                },
            };
            if let Some(h) = &hop
                && sent >= h.every
            {
                if let Some(next) = h.next(&log).await {
                    upstream = next;
                }
                sent = 0;
            }
            sent += 1;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

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
    fn discord_voice_is_recognised_by_ip_discovery() {
        let mut discovery = vec![0x00, 0x01, 0x00, 70];
        discovery.extend_from_slice(&[0u8; 70]);
        let elsewhere: std::net::IpAddr = "203.0.113.5".parse().unwrap();
        assert!(is_call_flow(&discovery, elsewhere));

        // Ответ сервера (тип 0x0002) и пакет другой длины — не то.
        let mut reply = discovery.clone();
        reply[1] = 0x02;
        assert!(!is_discord_ip_discovery(&reply));
        assert!(!is_discord_ip_discovery(&discovery[..73]));
    }

    #[test]
    fn call_flows_are_stun_or_telegram_networks() {
        let elsewhere: std::net::IpAddr = "203.0.113.5".parse().unwrap();
        let telegram: std::net::IpAddr = "91.108.56.130".parse().unwrap();
        assert!(is_call_flow(&binding_request(), elsewhere));
        assert!(is_call_flow(b"any payload", telegram));
        assert!(!is_call_flow(b"any payload", elsewhere));
    }

    #[test]
    fn quic_initial_is_recognised() {
        assert!(is_quic_initial(&crate::bypass::fragment::build_fake_quic_initial()));
        assert!(!is_quic_initial(&binding_request()));
    }

    #[tokio::test]
    async fn payloads_keep_their_order() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        upstream.connect(server.local_addr().unwrap()).await.unwrap();

        let (log_tx, _rx) = crate::observability::logging::channel();
        let tx = spawn_writer(
            Arc::new(upstream),
            None,
            CancellationToken::new(),
            WriterLog { log_tx, addr: server.local_addr().unwrap(), forward_error_key: "log.tproxy_forward_error" },
        );

        enqueue(&tx, b"first".to_vec());
        enqueue(&tx, b"second".to_vec());

        let mut buf = [0u8; 2048];
        for want in [&b"first"[..], b"second"] {
            let n = tokio::time::timeout(Duration::from_secs(2), server.recv(&mut buf))
                .await
                .expect("датаграмма не пришла")
                .unwrap();
            assert_eq!(&buf[..n], want);
        }
    }

    #[tokio::test]
    async fn hop_changes_source_port_every_n_datagrams() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dst = server.local_addr().unwrap();
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        upstream.connect(dst).await.unwrap();

        let readers = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = Arc::clone(&readers);
        let generation = Arc::new(AtomicU64::new(0));
        let hop = Hop {
            every: 2,
            dst,
            generation: Arc::clone(&generation),
            on_new: Box::new(move |_sock, g| seen.lock().unwrap().push(g)),
        };

        let (log_tx, _rx) = crate::observability::logging::channel();
        let tx = spawn_writer(
            Arc::new(upstream),
            Some(hop),
            CancellationToken::new(),
            WriterLog { log_tx, addr: dst, forward_error_key: "log.tproxy_forward_error" },
        );
        for i in 0..5u8 {
            enqueue(&tx, vec![i]);
        }

        let mut buf = [0u8; 16];
        let mut from = Vec::new();
        for i in 0..5u8 {
            let (n, src) = tokio::time::timeout(Duration::from_secs(2), server.recv_from(&mut buf))
                .await
                .expect("датаграмма не пришла")
                .unwrap();
            assert_eq!(&buf[..n], &[i], "порядок сохраняется и при смене порта");
            from.push(src.port());
        }

        // По два пакета с порта: [a, a, b, b, c].
        assert_eq!(from[0], from[1]);
        assert_ne!(from[1], from[2]);
        assert_eq!(from[2], from[3]);
        assert_ne!(from[3], from[4]);
        assert_eq!(*readers.lock().unwrap(), vec![1, 2], "у каждого нового сокета свой читатель");
        assert_eq!(generation.load(Ordering::Relaxed), 2);
    }
}
