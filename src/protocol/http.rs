//! Модуль безопасного текстового парсинга целевых адресов из HTTP/HTTPS запросов.

/// Разбирает целевой адрес из первой строки HTTP CONNECT запроса.
///
/// Пример входных данных: "CONNECT example.com:443 HTTP/1.1"
/// Возвращает: Some("example.com:443")
pub fn parse_connect_target(request: &str) -> Option<String> {
    let first_line = request.lines().next()?;
    let mut parts = first_line.split_whitespace();

    // Проверяем метод CONNECT
    let method = parts.next()?;
    if !method.eq_ignore_ascii_case("CONNECT") {
        return None;
    }

    // Вторая часть — целевой хост и порт
    let target = parts.next()?;
    if target.is_empty() {
        None
    } else {
        Some(target.to_string())
    }
}

/// Разбирает заголовок `Host:` из обычного HTTP-запроса.
///
/// Если порт не указан, подставляет `:80` по умолчанию.
/// Пример: "Host: example.com" -> "example.com:80"
pub fn parse_http_target(request: &str) -> Option<String> {
    for line in request.lines() {
        let trimmed = line.trim();
        // Ищем заголовок Host без учета регистра
        // Сравниваем по БАЙТАМ, а не срезом строки: `&trimmed[..5]` паникует,
        // если пятый байт попадает в середину многобайтового символа. Заголовок
        // приходит от клиента, то есть любая строка вида "Хост: …" роняла
        // задачу соединения — а вместе с ней и TUI, потому что паник-хук
        // выходит из альтернативного экрана из любого потока.
        let bytes = trimmed.as_bytes();
        if bytes.len() >= 5 && bytes[..5].eq_ignore_ascii_case(b"host:") {
            let host_value = trimmed[5..].trim();
            if host_value.is_empty() {
                return None;
            }

            // Голый IPv6-литерал без порта ("[::1]") содержит ':', но порта в нём нет —
            // отличаем по завершающей ']'.
            if host_value.ends_with(']') {
                return Some(format!("{}:80", host_value));
            }

            // Если порт уже указан (например example.com:8080 или [::1]:8080)
            if host_value.contains(':') {
                return Some(host_value.to_string());
            } else {
                // Подставляем стандартный порт HTTP
                return Some(format!("{}:80", host_value));
            }
        }
    }
    None
}

/// Готовит заголовки запроса к отправке серверу: одно соединение — один запрос.
///
/// Прокси выбирает сервер по заголовку `Host` ПЕРВОГО запроса, а дальше
/// просто перекладывает байты. Браузер же по одному keep-alive соединению
/// с прокси шлёт запросы и к другим хостам — и они уходили на первый сервер.
/// Поэтому соединение с сервером закрывается после ответа (`Connection: close`),
/// и следующий запрос клиент отправит уже по новому соединению с прокси.
///
/// Заодно убираются заголовки, адресованные прокси (`Proxy-Connection`,
/// `Proxy-Authorization`), и абсолютный URI (`GET http://host/path`) приводится
/// к виду `/path`, который ожидает обычный сервер.
///
/// `head` — заголовки целиком, включая завершающий `\r\n\r\n`.
pub fn rewrite_for_origin(head: &str) -> String {
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");

    let mut out = String::with_capacity(head.len() + 20);
    out.push_str(&origin_form_request_line(request_line));
    out.push_str("\r\n");

    for line in lines {
        if line.is_empty() {
            continue;
        }
        let name = line.split(':').next().unwrap_or("").trim();
        let hop_by_hop = ["connection", "proxy-connection", "keep-alive", "proxy-authorization"]
            .iter()
            .any(|h| name.eq_ignore_ascii_case(h));
        if hop_by_hop {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }

    out.push_str("Connection: close\r\n\r\n");
    out
}

/// `GET http://example.com:8080/a?b HTTP/1.1` → `GET /a?b HTTP/1.1`.
fn origin_form_request_line(line: &str) -> String {
    let mut parts = line.splitn(3, ' ');
    let (Some(method), Some(uri), Some(version)) = (parts.next(), parts.next(), parts.next()) else {
        return line.to_string();
    };

    let lower = uri.to_ascii_lowercase();
    let Some(rest_start) = ["http://", "https://"].iter().find(|s| lower.starts_with(*s)).map(|s| s.len()) else {
        return line.to_string();
    };
    let rest = &uri[rest_start..];
    let path = match rest.find('/') {
        Some(i) => &rest[i..],
        None => "/",
    };
    format!("{method} {path} {version}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_rewrite_closes_the_connection_and_strips_proxy_headers() {
        let head = "GET http://example.com/a?b=1 HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n";
        let out = rewrite_for_origin(head);
        assert_eq!(out, "GET /a?b=1 HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\nConnection: close\r\n\r\n");
    }

    #[test]
    fn origin_rewrite_keeps_origin_form_and_handles_bare_host() {
        assert_eq!(
            rewrite_for_origin("GET /x HTTP/1.1\r\nHost: a\r\n\r\n"),
            "GET /x HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n"
        );
        assert!(rewrite_for_origin("GET http://a.com:8080 HTTP/1.1\r\nHost: a.com\r\n\r\n").starts_with("GET / HTTP/1.1\r\n"));
    }

    #[test]
    fn test_parse_connect() {
        let req = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        assert_eq!(parse_connect_target(req), Some("example.com:443".to_string()));
    }

    #[test]
    fn test_parse_http_host_without_port() {
        let req = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(parse_http_target(req), Some("example.com:80".to_string()));
    }

    #[test]
    fn test_parse_http_bare_ipv6_gets_default_port() {
        let req = "GET / HTTP/1.1\r\nHost: [::1]\r\n\r\n";
        assert_eq!(parse_http_target(req), Some("[::1]:80".to_string()));
    }

    #[test]
    fn test_parse_http_ipv6_with_port() {
        let req = "GET / HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n";
        assert_eq!(parse_http_target(req), Some("[::1]:8080".to_string()));
    }

    #[test]
    fn non_ascii_header_does_not_panic() {
        // Срез `&trimmed[..5]` падал, если пятый байт попадал в середину
        // многобайтового символа. Заголовок приходит от клиента, то есть
        // это была удалённо вызываемая паника в задаче соединения.
        let req = "GET / HTTP/1.1\r\nХост: пример\r\nHost: example.com\r\n\r\n";
        assert_eq!(parse_http_target(req), Some("example.com:80".to_string()));

        // Заголовок ровно из пяти байт мультибайтовых символов
        assert_eq!(parse_http_target("GET / HTTP/1.1\r\nЯЯ: x\r\n\r\n"), None);
    }

    #[test]
    fn test_parse_http_host_with_port() {
        let req = "GET / HTTP/1.1\r\nHOST: example.com:8080\r\n\r\n";
        assert_eq!(parse_http_target(req), Some("example.com:8080".to_string()));
    }
}
