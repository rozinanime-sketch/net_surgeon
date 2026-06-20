pub mod fragment;

use std::collections::HashSet;

pub fn needs_bypass(enabled: bool, domain: &str, bypass_domains: &HashSet<String>) -> bool {
    enabled && bypass_domains.contains(domain)
}

pub fn extract_domain(target: &str) -> String {
    target.split(':').next().unwrap_or("").to_lowercase()
}
