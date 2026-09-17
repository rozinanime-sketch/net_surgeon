//! Сборка первого пакета клиента целиком.
//!
//! # Зачем
//!
//! Все три пути обхода (HTTPS-туннель, прозрачный режим, SOCKS5 CONNECT)
//! применяли стратегию к тому, что вернул ПЕРВЫЙ `read`. Это неверное
//! допущение: TCP не обязан отдавать сообщение одним куском. ClientHello
//! современного браузера — это 1.5–2 КБ, а с постквантовыми key share и
//! больше, и он спокойно приходит двумя сегментами.
//!
//! Последствие было тихим: `find_sni` на обрезанном буфере возвращает `None`,
//! и `strategy::apply` откатывался на слепой `split_client_hello` по случайной
//! позиции из конфига. То есть выбранная диагностикой техника молча
//! подменялась другой, заметно более слабой, — и именно на тех соединениях,
//! где ClientHello длиннее, то есть на настоящих браузерных.
//!
//! # Как
//!
//! Из заголовка TLS-записи известна её полная длина, поэтому дочитываем ровно
//! до неё. Ожидание ограничено по времени и по объёму: если клиент говорит
//! не по TLS или замолчал, обход всё равно должен пойти дальше, а не повиснуть.

use std::time::Duration;

use tokio::io::AsyncReadExt;

use crate::bypass::tls;

/// Сколько ждать недостающий хвост ClientHello.
///
/// Это не сетевой таймаут, а защита от зависания: недостающие байты уже в пути
/// (клиент отправил их вместе с первым сегментом), поэтому реально ожидание
/// измеряется миллисекундами. Секунда — с запасом на медленную сеть.
const COMPLETION_TIMEOUT: Duration = Duration::from_secs(1);

/// Верхняя граница на размер первого пакета. RFC 8446 ограничивает запись
/// 16384 байтами нагрузки; больше этого читать нечего, а необходимость
/// предела очевидна — длина приходит от клиента.
const MAX_FIRST_PACKET: usize = 5 + 16384;

/// Что получилось собрать.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirstPacket {
    /// TLS-запись дочитана целиком — стратегию можно применять как задумано.
    Complete,
    /// Это не TLS: обычный HTTP, свой протокол поверх SOCKS5 и так далее.
    /// Стратегиям тут делать нечего, данные идут как есть.
    NotTls,
    /// Похоже на TLS, но запись не дособралась (клиент замолчал, запись
    /// длиннее допустимого). Вызывающий код применяет стратегию к тому,
    /// что есть, и сообщает об этом в лог.
    Incomplete,
}

/// Дочитывает `data` до конца первой TLS-записи.
///
/// `data` уже содержит то, что успело прийти (возможно, пусто). Функция
/// дополняет буфер на месте и ничего не отбрасывает: вызывающий код в любом
/// исходе отправляет ровно то, что собралось.
pub async fn complete_client_hello<R>(reader: &mut R, data: &mut Vec<u8>) -> FirstPacket
where
    R: AsyncReadExt + Unpin,
{
    if !tls::looks_like_handshake(data) {
        return FirstPacket::NotTls;
    }

    let deadline = tokio::time::Instant::now() + COMPLETION_TIMEOUT;
    let mut chunk = [0u8; 4096];

    loop {
        // Пока заголовок не дочитан, нужная длина неизвестна — читаем дальше.
        if let Some(needed) = tls::record_len(data) {
            if needed > MAX_FIRST_PACKET {
                return FirstPacket::Incomplete;
            }
            if data.len() >= needed {
                return FirstPacket::Complete;
            }
        }

        match tokio::time::timeout_at(deadline, reader.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return FirstPacket::Incomplete,
            Ok(Ok(n)) => data.extend_from_slice(&chunk[..n]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ClientHello в 600 байт: заведомо больше одного куска в тестовом ридере.
    fn client_hello(sni: &str) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0x00);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
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
        // padding, чтобы запись гарантированно не влезла в один сегмент
        ext.extend_from_slice(&[0x00, 0x15]);
        ext.extend_from_slice(&(500u16).to_be_bytes());
        ext.extend_from_slice(&vec![0u8; 500]);

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

    #[tokio::test]
    async fn assembles_a_hello_split_across_segments() {
        let hello = client_hello("blocked.example");
        // Первый сегмент — только начало записи, остальное «придёт позже»
        let (head, tail) = hello.split_at(40);

        let mut data = head.to_vec();
        let mut reader = tail;

        assert_eq!(complete_client_hello(&mut reader, &mut data).await, FirstPacket::Complete);
        assert_eq!(data, hello, "буфер должен совпасть с исходным ClientHello");

        // И главное: SNI теперь находится, а на обрезанном буфере — нет
        assert!(crate::bypass::tls::find_sni(head).is_none());
        assert!(crate::bypass::tls::find_sni(&data).is_some());
    }

    #[tokio::test]
    async fn complete_hello_is_left_untouched() {
        let hello = client_hello("x.example");
        let mut data = hello.clone();
        let mut reader: &[u8] = &[];

        assert_eq!(complete_client_hello(&mut reader, &mut data).await, FirstPacket::Complete);
        assert_eq!(data, hello);
    }

    #[tokio::test]
    async fn non_tls_is_reported_and_not_read_further() {
        let mut data = b"GET / HTTP/1.1\r\n".to_vec();
        let before = data.clone();
        let mut reader: &[u8] = b"should not be consumed";

        assert_eq!(complete_client_hello(&mut reader, &mut data).await, FirstPacket::NotTls);
        assert_eq!(data, before);
    }

    #[tokio::test]
    async fn truncated_hello_is_reported_not_hung() {
        let hello = client_hello("cut.example");
        let mut data = hello[..40].to_vec();
        // Клиент замолчал: ридер сразу отдаёт EOF
        let mut reader: &[u8] = &[];

        assert_eq!(complete_client_hello(&mut reader, &mut data).await, FirstPacket::Incomplete);
    }
}
