pub mod fragment;
pub mod random;
pub mod socket;
pub mod tls;

use std::collections::HashSet;

/// Нужен ли обход для домена.
///
/// Совпадение по суффиксу, а не по точной строке: запись `googlevideo.com`
/// покрывает и `rr3---sn-pivhx-n8vs.googlevideo.com`, откуда реально идёт
/// видео YouTube. При строгом сравнении такие поддомены шли мимо обхода —
/// страница открывалась, а видео оставалось серым, потому что каждый
/// видеосервер имеет собственное уникальное имя.
pub fn needs_bypass(enabled: bool, domain: &str, bypass_domains: &HashSet<String>) -> bool {
    enabled && matches_list(domain, bypass_domains)
}

/// true, если домен есть в списке точно либо является его поддоменом.
///
/// Проверка идёт по границе метки (точке), поэтому `notgooglevideo.com`
/// не совпадёт с `googlevideo.com` — иначе список ловил бы чужие домены,
/// просто оканчивающиеся на нужные буквы.
pub fn matches_list(domain: &str, list: &HashSet<String>) -> bool {
    if list.contains(domain) {
        return true;
    }
    parent_domains(domain).any(|parent| list.contains(parent))
}

/// Перебирает родительские домены, отбрасывая метки слева:
/// `a.b.example.com` → `b.example.com`, `example.com`, `com`.
pub fn parent_domains(domain: &str) -> impl Iterator<Item = &str> {
    domain
        .match_indices('.')
        .map(move |(i, _)| &domain[i + 1..])
}

/// Хост из `host:port` в нижнем регистре.
///
/// IPv6 записывается в скобках: `[2a00::1]:443`. Деление по первому
/// двоеточию давало для него `"[2a00"`, и такой «домен» уходил дальше —
/// вплоть до автодиагностики, которая мерила несуществующее имя.
pub fn extract_domain(target: &str) -> String {
    let host = if let Some(rest) = target.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else if target.matches(':').count() > 1 {
        // Голый IPv6 без скобок и порта
        target
    } else {
        target.split(':').next().unwrap_or("")
    };
    host.trim_end_matches('.').to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(items: &[&str]) -> HashSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn exact_match_still_works() {
        let l = list(&["youtube.com"]);
        assert!(matches_list("youtube.com", &l));
    }

    #[test]
    fn subdomains_match_the_parent_entry() {
        let l = list(&["googlevideo.com", "youtube.com"]);
        // Именно этот случай ломал воспроизведение видео
        assert!(matches_list("rr3---sn-pivhx-n8vs.googlevideo.com", &l));
        assert!(matches_list("www.youtube.com", &l));
        assert!(matches_list("a.b.c.youtube.com", &l));
    }

    #[test]
    fn does_not_match_across_label_boundary() {
        let l = list(&["googlevideo.com"]);
        // Совпадение суффикса строк, но не домена — не должно срабатывать
        assert!(!matches_list("notgooglevideo.com", &l));
        assert!(!matches_list("evilgooglevideo.com", &l));
    }

    #[test]
    fn unrelated_domains_do_not_match() {
        let l = list(&["youtube.com"]);
        assert!(!matches_list("example.com", &l));
        assert!(!matches_list("com", &l));
    }

    #[test]
    fn extract_domain_handles_ipv6_and_ports() {
        assert_eq!(extract_domain("Example.COM:443"), "example.com");
        assert_eq!(extract_domain("example.com"), "example.com");
        assert_eq!(extract_domain("example.com.:443"), "example.com");
        assert_eq!(extract_domain("1.2.3.4:443"), "1.2.3.4");
        assert_eq!(extract_domain("[2A00::1]:443"), "2a00::1");
        assert_eq!(extract_domain("2a00::1"), "2a00::1");
    }

    #[test]
    fn parent_chain_is_complete() {
        let parents: Vec<&str> = parent_domains("a.b.example.com").collect();
        assert_eq!(parents, vec!["b.example.com", "example.com", "com"]);
    }
}
