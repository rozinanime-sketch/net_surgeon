//! UDP-диагностика голоса: отвечает на вопрос «звонки у меня проходят,
//! режутся через несколько пакетов или не проходят вовсе?».
//!
//! # Как
//!
//! Напрямую проверить голосовой сервер Discord нельзя: его адрес клиент
//! узнаёт у шлюза уже в сессии звонка, заранее его нет. Поэтому проба идёт
//! к публичным STUN-серверам — в том числе на Cloudflare и AWS, где живут
//! голосовые серверы Discord (`c-…`).
//!
//! # Почему серия, а не один запрос
//!
//! Раньше проба слала один запрос (и второй заход — с приманкой). На сети,
//! где UDP к Cloudflare/AWS режут по счётчику — первые пять пакетов потока
//! проходят, дальше тишина навсегда (замер 2026-10-17), — один запрос
//! укладывался в эти пять и проба честно писала «проходит», а голос Discord
//! висел с пингом 5000 мс. Звонок — это тысячи пакетов в одном потоке,
//! значит и проба должна быть серией в одном потоке: тогда отсечка видна
//! как «ответы были, потом пропали» ([`VoiceVerdict::Cut`]).
//!
//! # Чего проба НЕ знает
//!
//! Если сам публичный STUN-сервер недоступен по IP (а Google STUN в части
//! сетей режут), «нет ответа» неотличимо от дропа по пути. Поэтому серверов
//! несколько, и вердикт — по самому показательному из них.

use std::time::Duration;

use tokio::net::UdpSocket;

use crate::proxy::udp::session::is_stun;

/// Публичные STUN-серверы для пробы: Google, Cloudflare и Twilio (AWS).
/// Несколько — чтобы блок одного по IP не выдавался за общий вывод.
const STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun.cloudflare.com:3478",
    "global.stun.twilio.com:3478",
];

/// Сколько запросов в серии. С запасом больше отсечки в пять пакетов.
const SERIES: usize = 10;

/// Сколько ждать ответ на один запрос серии. Сигнальный трафик быстрый;
/// дольше ждать — растягивать диагностику на глухих серверах.
const REPLY_TIMEOUT: Duration = Duration::from_millis(700);

/// Сколько молчаний подряд хватает, чтобы закончить серию досрочно: после
/// ответов — это отсечка, без ответов — сервер глух.
const SILENT_STREAK: usize = 3;

/// Исход серии к одному серверу.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Series {
    /// Ответы шли до конца серии.
    Open,
    /// Сначала ответы были, потом пропали — отсечка по счётчику пакетов.
    Cut,
    /// Ни одного ответа: дроп по пути либо сервер недоступен.
    Silent,
    /// Пробу не удалось даже отправить (свой сокет не открылся, имя не
    /// резолвится) — это не вердикт о сети, а невозможность теста.
    Unreachable,
}

/// Вердикт по голосу.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoiceVerdict {
    /// Серия прошла целиком — UDP звонков эта сеть не режет. Если голос
    /// всё равно не работает, дело не в сети (NAT, сам сервер, клиент).
    Open,
    /// Первые пакеты проходят, потом поток обрезают. Помогает смена
    /// исходного порта: `[calls] hop = 4` (прозрачный режим Linux и Android).
    Cut,
    /// Не ответил ни один сервер — похоже на блок по IP.
    Hard,
    /// Пробу не удалось провести вовсе (нет сети, STUN не резолвится).
    Unavailable,
}

impl VoiceVerdict {
    /// Ключ локали для показа.
    pub fn description_key(&self) -> &'static str {
        match self {
            VoiceVerdict::Open => "voice.open",
            VoiceVerdict::Cut => "voice.cut",
            VoiceVerdict::Hard => "voice.hard",
            VoiceVerdict::Unavailable => "voice.unavailable",
        }
    }
}

/// Чистое решение по ответам серии (по порядку запросов) — без сети,
/// поэтому проверяется тестами.
///
/// Отсечка — это ответы, за которыми идёт хвост из молчаний. Одиночная
/// потеря посреди ответов отсечкой не считается: UDP имеет право терять.
fn classify_series(answers: &[bool]) -> Series {
    let Some(last_answer) = answers.iter().rposition(|&a| a) else {
        return Series::Silent;
    };
    if answers.len() - 1 - last_answer >= SILENT_STREAK {
        Series::Cut
    } else {
        Series::Open
    }
}

/// Вердикт по всем серверам. Отсечка показательнее всего: голос Discord
/// живёт на Cloudflare, и если хоть один сервер обрезало, обрежет и его.
/// Потом — «проходит», потом — молчание.
fn classify(results: &[Series]) -> VoiceVerdict {
    if results.contains(&Series::Cut) {
        VoiceVerdict::Cut
    } else if results.contains(&Series::Open) {
        VoiceVerdict::Open
    } else if results.contains(&Series::Silent) {
        VoiceVerdict::Hard
    } else {
        VoiceVerdict::Unavailable
    }
}

/// STUN Binding Request (RFC 5389) со случайным transaction ID.
fn binding_request() -> Vec<u8> {
    let mut out = Vec::with_capacity(20);
    out.extend_from_slice(&[0x00, 0x01]); // Binding Request
    out.extend_from_slice(&[0x00, 0x00]); // длина атрибутов = 0
    out.extend_from_slice(&[0x21, 0x12, 0xA4, 0x42]); // magic cookie
    out.extend_from_slice(&crate::bypass::random::bytes(12)); // transaction ID
    out
}

/// Серия запросов к одному серверу — все из одного сокета, то есть одним
/// потоком, как идёт звонок.
async fn probe_series(server: &str) -> Series {
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await else {
        return Series::Unreachable;
    };
    // connect на UDP резолвит имя и фиксирует пир; соединения не открывает.
    if sock.connect(server).await.is_err() {
        return Series::Unreachable;
    }

    let mut answers = Vec::with_capacity(SERIES);
    for _ in 0..SERIES {
        let request = binding_request();
        if sock.send(&request).await.is_err() {
            return Series::Unreachable;
        }
        // Засчитывается ответ именно на этот запрос: запоздавший ответ на
        // прошлый сдвинул бы серию и спрятал бы отсечку.
        let wait = async {
            let mut buf = [0u8; 512];
            loop {
                match sock.recv(&mut buf).await {
                    Ok(n) if is_stun(&buf[..n]) && buf[8..20] == request[8..20] => return true,
                    Ok(_) => continue,
                    Err(_) => return false,
                }
            }
        };
        answers.push(matches!(tokio::time::timeout(REPLY_TIMEOUT, wait).await, Ok(true)));

        let tail = answers.iter().rev().take_while(|&&a| !a).count();
        if tail >= SILENT_STREAK {
            break;
        }
    }
    classify_series(&answers)
}

/// Вердикт по голосу: серия STUN-запросов к каждому серверу.
pub async fn diagnose_voice() -> VoiceVerdict {
    let mut results = Vec::with_capacity(STUN_SERVERS.len());
    for server in STUN_SERVERS {
        results.push(probe_series(server).await);
    }
    classify(&results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn series_tells_cut_from_loss_and_silence() {
        let t = true;
        let f = false;
        assert_eq!(classify_series(&[t; SERIES]), Series::Open);
        // Одиночные потери посреди ответов — не отсечка.
        assert_eq!(classify_series(&[t, t, f, t, t, f, t, t, t, t]), Series::Open);
        // Как на сети с отсечкой: пять ответов, потом тишина.
        assert_eq!(classify_series(&[t, t, t, t, t, f, f, f]), Series::Cut);
        assert_eq!(classify_series(&[f, f, f]), Series::Silent);
        assert_eq!(classify_series(&[]), Series::Silent);
    }

    #[test]
    fn cut_on_any_server_wins() {
        use Series::*;
        assert_eq!(classify(&[Open, Cut, Silent]), VoiceVerdict::Cut);
        assert_eq!(classify(&[Silent, Open, Unreachable]), VoiceVerdict::Open);
        assert_eq!(classify(&[Silent, Unreachable]), VoiceVerdict::Hard);
        assert_eq!(classify(&[Unreachable, Unreachable]), VoiceVerdict::Unavailable);
    }

    #[test]
    fn binding_request_is_valid_stun() {
        assert!(is_stun(&binding_request()));
    }

    /// Локальный «STUN-сервер»: отвечает Binding Success на первые `limit`
    /// запросов и дальше молчит — как сеть с отсечкой по счётчику.
    async fn stun_server(limit: usize) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let mut answered = 0;
            while let Ok((n, from)) = sock.recv_from(&mut buf).await {
                if n >= 20 && answered < limit {
                    answered += 1;
                    // Эхо transaction ID в Binding Success (тип 0x0101).
                    let mut resp = vec![0x01, 0x01, 0x00, 0x00];
                    resp.extend_from_slice(&buf[4..20]);
                    let _ = sock.send_to(&resp, from).await;
                }
            }
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn series_sees_open_cut_and_silent_servers() {
        let (open, a) = stun_server(usize::MAX).await;
        assert_eq!(probe_series(&open.to_string()).await, Series::Open);

        let (cut, b) = stun_server(5).await;
        assert_eq!(probe_series(&cut.to_string()).await, Series::Cut);

        let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
        assert_eq!(probe_series(&dead.to_string()).await, Series::Silent);
        a.abort();
        b.abort();
    }
}
