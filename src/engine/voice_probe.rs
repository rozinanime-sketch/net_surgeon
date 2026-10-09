//! UDP-диагностика голоса: отвечает на вопрос «звонки у меня режут по DPI
//! (приманка поможет) или по IP (не поможет)?».
//!
//! # Как
//!
//! Напрямую проверить голосовой сервер Discord нельзя: его адрес клиент
//! узнаёт у шлюза уже в сессии звонка, заранее его нет. Но DPI, который
//! режет звонки, узнаёт их по STUN — служебному протоколу установки
//! соединения (WebRTC, P2P Telegram/WhatsApp). Поэтому STUN к публичному
//! серверу — честный индикатор: пройдёт STUN — пройдёт и сигнализация
//! звонка; порежут STUN — порежут и звонок.
//!
//! Проба идёт в два захода: сначала «как есть», потом с приманкой перед
//! запросом (как в бою, см. [`crate::proxy::udp::session`]). Разница и даёт
//! вердикт.
//!
//! # Чего проба НЕ знает
//!
//! Если сам публичный STUN-сервер недоступен по IP (а Google STUN в части
//! сетей режут), «нет ответа» неотличимо от DPI-дропа — выйдет осторожный
//! [`VoiceVerdict::Hard`], а не ложный «всё плохо по DPI». Поэтому серверов
//! несколько: достаточно одного прошедшего, чтобы вынести уверенный вердикт.

use std::time::Duration;

use tokio::net::UdpSocket;

use crate::bypass::fragment;
use crate::config::Socks5JunkParams;
use crate::proxy::udp::session::is_stun;

/// Публичные STUN-серверы для пробы. Несколько — чтобы блок одного по IP не
/// выдавался за DPI-блок звонков вообще (см. оговорку в заголовке модуля).
const STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun.cloudflare.com:3478",
];

/// Сколько ждать ответ STUN. Звонковый сигнальный трафик быстрый; дольше
/// ждать смысла нет — это диагностика, а не само соединение.
const STUN_TIMEOUT: Duration = Duration::from_secs(2);

/// Исход одной STUN-пробы к одному серверу.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StunReply {
    /// Пришёл валидный STUN-ответ — датаграмма дошла и вернулась.
    Answered,
    /// Ответа нет (таймаут): дроп по пути либо сервер недоступен.
    NoReply,
    /// Пробу не удалось даже отправить (свой сокет не открылся/не
    /// подключился) — это не вердикт о сети, а невозможность теста.
    Unreachable,
}

/// Вердикт по голосу.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoiceVerdict {
    /// STUN прошёл напрямую — эта сеть звонки по DPI не режет. Если голос всё
    /// равно не работает, дело не в DPI (NAT, сам сервер, клиент).
    Open,
    /// Напрямую не прошёл, а с приманкой — прошёл. Звонки режут по DPI, и
    /// приманка (`fake`) его обходит: голосу обход net_surgeon должен помочь.
    DpiBypassable,
    /// Не прошёл даже с приманкой. Либо блок по IP (обход бесполезен), либо
    /// DPI, который эта приманка не берёт. Осторожный вывод: см. оговорку.
    Hard,
    /// Пробу не удалось провести вовсе (нет сети, STUN не резолвится).
    Unavailable,
}

impl VoiceVerdict {
    /// Ключ локали для показа.
    pub fn description_key(&self) -> &'static str {
        match self {
            VoiceVerdict::Open => "voice.open",
            VoiceVerdict::DpiBypassable => "voice.dpi_bypassable",
            VoiceVerdict::Hard => "voice.hard",
            VoiceVerdict::Unavailable => "voice.unavailable",
        }
    }
}

/// Чистое решение по двум заходам — без сети, поэтому проверяется тестами.
///
/// Прямой ответ важнее всего: раз STUN проходит как есть, звонки не режут.
/// Иначе решает заход с приманкой. «Недоступно» — только когда ни один
/// сервер не удалось даже опросить.
fn classify(direct: StunReply, with_fake: StunReply) -> VoiceVerdict {
    match (direct, with_fake) {
        (StunReply::Answered, _) => VoiceVerdict::Open,
        (_, StunReply::Answered) => VoiceVerdict::DpiBypassable,
        (StunReply::Unreachable, StunReply::Unreachable) => VoiceVerdict::Unavailable,
        _ => VoiceVerdict::Hard,
    }
}

/// Одна проба к одному серверу: при `fake` сначала уходит `count` приманок,
/// как в бою, затем настоящий Binding Request.
async fn probe_one(server: &str, fake: bool, junk: &Socks5JunkParams) -> StunReply {
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await else {
        return StunReply::Unreachable;
    };
    // connect на UDP резолвит имя и фиксирует пир; соединения не открывает.
    if sock.connect(server).await.is_err() {
        return StunReply::Unreachable;
    }

    if fake {
        // Приманки-STUN перед настоящим запросом — та же схема, что шлёт
        // боевой путь (session::send_junk с DecoyKind::Stun).
        for _ in 0..junk.count {
            let _ = sock.send(&fragment::build_fake_stun()).await;
        }
    }

    // Настоящий Binding Request — валидный STUN, сервер обязан ответить
    // Binding Success, если датаграмма дошла.
    let request = fragment::build_fake_stun();
    if sock.send(&request).await.is_err() {
        return StunReply::Unreachable;
    }

    // Приманки — тоже валидные запросы, и сервер отвечает и на них. Засчитать
    // такой ответ — значит выдать «дошли лишние повторы» за «помогла
    // приманка», поэтому ждём ответа именно с transaction ID запроса.
    let wait = async {
        let mut buf = [0u8; 512];
        loop {
            match sock.recv(&mut buf).await {
                // Ответ STUN (в т.ч. Binding Success — те же два нулевых
                // старших бита типа и magic cookie, что проверяет is_stun).
                Ok(n) if is_stun(&buf[..n]) && buf[8..20] == request[8..20] => return true,
                Ok(_) => continue,
                Err(_) => return false,
            }
        }
    };
    match tokio::time::timeout(STUN_TIMEOUT, wait).await {
        Ok(true) => StunReply::Answered,
        _ => StunReply::NoReply,
    }
}

/// Лучший исход серии проб по всем серверам: ответ важнее молчания, молчание
/// важнее «не смогли отправить».
async fn best_over_servers(fake: bool, junk: &Socks5JunkParams) -> StunReply {
    let mut best = StunReply::Unreachable;
    for server in STUN_SERVERS {
        match probe_one(server, fake, junk).await {
            StunReply::Answered => return StunReply::Answered,
            StunReply::NoReply => best = StunReply::NoReply,
            StunReply::Unreachable => {}
        }
    }
    best
}

/// Вердикт по голосу: проходит ли STUN напрямую, а если нет — помогает ли
/// приманка. Заход с приманкой запускается только когда прямой не прошёл:
/// раз уж STUN идёт как есть, звонки не режут и проверять приманку незачем.
pub async fn diagnose_voice(junk: &Socks5JunkParams) -> VoiceVerdict {
    let direct = best_over_servers(false, junk).await;
    if direct == StunReply::Answered {
        return VoiceVerdict::Open;
    }
    let with_fake = best_over_servers(true, junk).await;
    classify(direct, with_fake)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn verdict_prefers_direct_then_fake() {
        use StunReply::*;
        // Прямой ответ — звонки не режут, что бы ни показал заход с приманкой.
        assert_eq!(classify(Answered, NoReply), VoiceVerdict::Open);
        assert_eq!(classify(Answered, Answered), VoiceVerdict::Open);
        // Прямого нет, с приманкой есть — DPI, приманка обходит.
        assert_eq!(classify(NoReply, Answered), VoiceVerdict::DpiBypassable);
        assert_eq!(classify(Unreachable, Answered), VoiceVerdict::DpiBypassable);
        // Молчание в обоих — осторожный Hard.
        assert_eq!(classify(NoReply, NoReply), VoiceVerdict::Hard);
        assert_eq!(classify(NoReply, Unreachable), VoiceVerdict::Hard);
        // Ни один сервер не удалось опросить — тест не проведён.
        assert_eq!(classify(Unreachable, Unreachable), VoiceVerdict::Unavailable);
    }

    /// Локальный «STUN-сервер», отвечающий Binding Success на любой запрос.
    async fn fake_stun_server() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = sock.recv_from(&mut buf).await {
                // Эхо transaction ID в Binding Success (тип 0x0101), без
                // атрибутов: is_stun это примет (длина 0, cookie на месте).
                if n >= 20 {
                    let mut resp = vec![0x01, 0x01, 0x00, 0x00];
                    resp.extend_from_slice(&buf[4..20]); // cookie + transaction ID
                    let _ = sock.send_to(&resp, from).await;
                }
            }
        });
        (addr, handle)
    }

    #[tokio::test]
    async fn direct_reachable_server_reads_as_open() {
        let (addr, server) = fake_stun_server().await;
        let junk = Socks5JunkParams::default();
        assert_eq!(probe_one(&addr.to_string(), false, &junk).await, StunReply::Answered);
        // А на заведомо глухой адрес (наш же сокет, который никто не слушает)
        // ответа нет.
        let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
        assert_eq!(probe_one(&dead.to_string(), false, &junk).await, StunReply::NoReply);
        server.abort();
    }

    #[tokio::test]
    async fn fake_prefix_still_reaches_the_server() {
        let (addr, server) = fake_stun_server().await;
        let junk = Arc::new(Socks5JunkParams::default());
        // С приманкой перед запросом настоящий STUN всё равно доходит.
        assert_eq!(probe_one(&addr.to_string(), true, &junk).await, StunReply::Answered);
        server.abort();
    }
}
