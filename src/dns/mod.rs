pub mod doh;
pub mod ip_cache;
pub mod resolver;
pub mod smart;

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

    // По умолчанию reqwest проверяет сертификаты системным верификатором,
    // а на Android ему нужна инициализация через JNI. Без неё проверка
    // паникует внутри задачи соединения, и оно молча зависает. Поэтому там
    // корни — встроенный список Mozilla, как в telegram.rs.
    #[cfg(target_os = "android")]
    {
        builder = builder.tls_backend_preconfigured(android_tls());
    }

    builder.build()
}

#[cfg(target_os = "android")]
fn android_tls() -> rustls::ClientConfig {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("TLS 1.2/1.3")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config
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
