//! Имя в приманке: подобранное диагностикой («белый SNI») или из конфига.
//!
//! Тонкий фасад над [`crate::engine::net_state`], как `fake_ttl`.
//!
//! Зачем подбирать: DPI классифицирует соединение по имени в приманке, и
//! не всякое разрешённое имя ему подходит. bol-van (zapret2) пишет, что
//! блокировки на хостингах вроде Cloudflare — это белые списки, и
//! пробиваются они именем из такого списка. Какие имена в нём — от сети
//! к сети разное и меняется, поэтому диагностика перебирает кандидатов из
//! `fake_sni_candidates`, когда с `fake_sni` не прошла ни одна приманка, и
//! запоминает рабочее для домена. При смене сети подобранное сбрасывается.

use crate::engine::net_state;

/// Имя приманки для соединения с `host`: подобранное для него (или для
/// родительского домена), иначе `config` (`fake_sni`).
pub fn for_host(host: &str, config: &str) -> String {
    net_state::decoy_name(&host.to_ascii_lowercase()).unwrap_or_else(|| config.to_string())
}

/// То же по имени из SNI настоящего ClientHello; без SNI — `config`.
pub fn for_hello(hello: &[u8], config: &str) -> String {
    match super::tls::sni_host(hello) {
        Some(host) => for_host(&host, config),
        None => config.to_string(),
    }
}

/// Запоминает имя приманки, с которым у домена прошёл обход.
pub fn note_working(domain: &str, name: &str) {
    net_state::note_decoy_name(domain, name);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noted_name_replaces_the_config_one_for_that_domain_only() {
        let _g = net_state::test_guard();
        net_state::reset_for_network();
        let hello = crate::bypass::tls::build_client_hello("gateway.discord.gg");
        assert_eq!(for_hello(&hello, "www.google.com"), "www.google.com");

        note_working("discord.gg", "vk.com");
        assert_eq!(for_hello(&hello, "www.google.com"), "vk.com");
        assert_eq!(for_host("youtube.com", "www.google.com"), "www.google.com");
        // Не TLS — имя из конфига
        assert_eq!(for_hello(b"GET / HTTP/1.1\r\n", "www.google.com"), "www.google.com");
        net_state::reset_for_network();
    }
}
