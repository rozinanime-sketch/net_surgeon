pub mod doh;
pub mod ip_cache;
pub mod resolver;

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// Хост и порт из адреса DoH-провайдера: `https://xbox-dns.ru/dns-query` →
/// `("xbox-dns.ru", 443)`.
///
/// Порт по умолчанию 443, а не 80 даже для `http://`: DoH без TLS не бывает,
/// и такой адрес в конфиге — это опечатка, а не намерение.
pub fn provider_endpoint(url: &str) -> Option<(&str, u16)> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.is_empty() {
        return None;
    }

    // IPv6 в адресе пишется в скобках: [2606:4700::1111]:8443
    if let Some(after) = authority.strip_prefix('[') {
        let (host, tail) = after.split_once(']')?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None => 443,
        };
        return Some((host, port));
    }

    match authority.split_once(':') {
        Some((host, port)) => Some((host, port.parse().ok()?)),
        None => Some((authority, 443)),
    }
}

/// HTTP-клиент для запросов к DoH-провайдеру.
///
/// # Зачем здесь `bootstrap`
///
/// Чтобы отправить запрос провайдеру, клиенту нужен его IP-адрес — то есть
/// сначала надо выполнить обычный резолв имени `xbox-dns.ru`. Пока DNS в
/// системе идёт мимо нас, это не проблема. Но стоит завернуть системный DNS
/// на наш же релей (прозрачный перехват UDP/53 в `run.sh`), и получается
/// замкнутый круг: релей не может ответить на запрос, пока не сходит к
/// провайдеру, а сходить не может, пока кто-то не ответит на запрос об имени
/// провайдера — то есть пока не ответит он сам.
///
/// Исключения по группе `nsproxy` здесь не хватает: между нами и сетью стоит
/// systemd-resolved, и наружу ходит уже он, а его правило перехвата ловит.
///
/// Поэтому адрес провайдера можно прибить гвоздями: `doh_bootstrap_ip` в
/// конфиге подставляется прямо в клиент, и резолв имени провайдера не
/// выполняется вообще. Так же поступают dnscrypt-proxy и stubby — там это
/// называется bootstrap resolver.
pub fn doh_client(
    provider: &str,
    bootstrap: Option<IpAddr>,
    timeout: Duration,
) -> reqwest::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder().timeout(timeout);

    if let Some(ip) = bootstrap
        && let Some((host, port)) = provider_endpoint(provider)
    {
        builder = builder.resolve(host, SocketAddr::new(ip, port));
    }

    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_provider_url_into_host_and_port() {
        assert_eq!(provider_endpoint("https://xbox-dns.ru/dns-query"), Some(("xbox-dns.ru", 443)));
        assert_eq!(provider_endpoint("https://dns.google/dns-query"), Some(("dns.google", 443)));
        assert_eq!(provider_endpoint("https://example.com:8443/dns-query"), Some(("example.com", 8443)));
        assert_eq!(provider_endpoint("https://[2606:4700:4700::1111]/dns-query"), Some(("2606:4700:4700::1111", 443)));
        assert_eq!(provider_endpoint("https://[2606:4700::1111]:8443/x"), Some(("2606:4700::1111", 8443)));
    }

    #[test]
    fn rejects_what_is_not_a_provider_url() {
        assert_eq!(provider_endpoint("xbox-dns.ru/dns-query"), None);
        assert_eq!(provider_endpoint("https://"), None);
        assert_eq!(provider_endpoint("https://host:порт/dns-query"), None);
    }

    #[test]
    fn bootstrap_is_optional_and_never_fails_the_client() {
        let timeout = Duration::from_secs(5);
        assert!(doh_client("https://xbox-dns.ru/dns-query", None, timeout).is_ok());
        assert!(doh_client("https://xbox-dns.ru/dns-query", Some("111.88.96.56".parse().unwrap()), timeout).is_ok());
        // Адрес есть, а разобрать его не из чего — клиент всё равно собирается,
        // просто без закреплённого адреса.
        assert!(doh_client("не-адрес", Some("111.88.96.56".parse().unwrap()), timeout).is_ok());
    }
}
