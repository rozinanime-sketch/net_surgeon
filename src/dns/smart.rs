//! Домены, которые разрешаются через отдельный «умный» DNS.
//!
//! # Зачем
//!
//! ChatGPT, Claude, Gemini и другие нейросети закрыты для России самими
//! сервисами: они смотрят на IP клиента, и никакая манипуляция TLS тут не
//! поможет. Умный DNS вроде xbox-dns.ru отвечает на такие имена адресами
//! своих серверов за границей, и сервис видит уже их адрес.
//!
//! Отдавать такому DNS все запросы незачем: он узнаёт каждый сайт, который
//! вы открываете, а остальным сайтам его ответы не нужны. Поэтому через
//! него идут только имена из `smart_dns_domains.txt`, остальное — через
//! обычный `doh_provider`.
//!
//! # Где применяется
//!
//! * DoH-релей (прозрачный режим на компьютере) — по имени из запроса.
//! * Резолвер исходящих подключений (SOCKS5, HTTP-прокси, телефон) — по
//!   имени хоста, даже если `resolve_via_doh` выключен.
//!
//! Список модульный, как у блокировки трекеров, и перечитывается при каждом
//! запуске прокси (`run_all`).

use std::collections::HashSet;
use std::sync::{Arc, RwLock};

use crate::bypass::matches_list;
use crate::config::paths;
use crate::observability::logging::{log_t, LogLevel, LogSender};

const LIST_PATH: &str = "smart_dns_domains.txt";

static LIST: RwLock<Option<Arc<HashSet<String>>>> = RwLock::new(None);

/// Идёт ли домен через умный DNS: сам или как поддомен записи из списка.
pub fn matches(domain: &str) -> bool {
    let Some(list) = LIST.read().ok().and_then(|g| g.clone()) else { return false };
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    matches_list(&domain, &list)
}

fn install(list: HashSet<String>) {
    let value = (!list.is_empty()).then(|| Arc::new(list));
    if let Ok(mut guard) = LIST.write() {
        *guard = value;
    }
}

/// Перечитывает список. Без провайдера (`smart_dns_provider` пуст) список
/// не нужен: сбрасываем, чтобы выключение в конфиге действовало сразу.
pub fn reload(provider: &str, log_tx: &LogSender) {
    if provider.is_empty() {
        install(HashSet::new());
        return;
    }
    match paths::read_to_string(LIST_PATH) {
        Ok(text) => {
            let list = crate::block::parse(&text);
            log_t(log_tx, LogLevel::Info, "log.smart_dns_active", vec![
                ("count", list.len().to_string()),
                ("provider", provider.to_string()),
            ]);
            install(list);
        }
        Err(e) => {
            log_t(log_tx, LogLevel::Warning, "log.smart_dns_missing", vec![
                ("path", paths::resolve(LIST_PATH).display().to_string()),
                ("error", e.to_string()),
            ]);
            install(HashSet::new());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Одним тестом: список глобальный, а тесты идут параллельно.
    #[test]
    fn matches_listed_domains_and_subdomains_only() {
        install(crate::block::parse("# нейросети\nchatgpt.com\ngemini.google.com\n"));

        assert!(matches("chatgpt.com"));
        assert!(matches("ab.ChatGPT.com."));
        assert!(matches("gemini.google.com"));
        // Остальной Google — мимо: ему умный DNS не нужен.
        assert!(!matches("google.com"));
        assert!(!matches("www.google.com"));
        assert!(!matches("notchatgpt.com"));
    }
}
