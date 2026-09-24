//! Блокировка трекеров по имени домена.
//!
//! Прозрачный режим и так видит каждое соединение и знает его домен, так
//! что отказать счётчику вроде Яндекс.Метрики — дело одной проверки. Это
//! дешевле, чем пропускать его: заблокированное соединение не открывает
//! второго сокета к серверу и ничего не пересылает.
//!
//! # Где проверяется
//!
//! * DoH-релей отвечает NXDOMAIN — соединения не будет вообще. Самый
//!   дешёвый путь, но его обходит браузер со своим защищённым DNS.
//! * Прозрачный TCP — по SNI, сбросом (RST), чтобы браузер понял отказ
//!   сразу, а не ждал таймаута.
//! * QUIC — датаграммы отбрасываются, браузер откатывается на TCP.
//! * HTTP-прокси и SOCKS5 — отказом по протоколу (403 и REP 0x02).
//!
//! # Почему только по имени, а не по кэшу «адрес → домен»
//!
//! За одним адресом живёт много сайтов: у Яндекса метрика и остальные
//! сервисы делят адреса. Кэш помнит последнее имя, увиденное на адресе, и
//! блокировка по нему рвала бы чужие соединения. Исключение — QUIC: имя там
//! зашифровано, других данных нет, а ложное срабатывание безвредно —
//! браузер просто уходит на TCP, где имя видно в SNI.
//!
//! # Почему синглтон
//!
//! Список нужен пяти слушателям, и тащить его через все сигнатуры рядом с
//! `bypass_domains` значит удлинить их ещё на аргумент. Как и резолвер, он
//! модульный, но перечитывается при каждом запуске прокси (`run_all`), так
//! что правки файла применяются перезапуском прокси, а не программы.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};

use crate::bypass::matches_list;
use crate::config::paths;
use crate::observability::logging::{log_t, LogLevel, LogSender};

const LIST_PATH: &str = "block_domains.txt";

/// Пустой список и `None` означают одно — блокировка выключена. `None`
/// нужен только затем, чтобы статик собирался без ленивой инициализации.
static LIST: RwLock<Option<Arc<HashSet<String>>>> = RwLock::new(None);

/// Заблокирован ли домен: сам или как поддомен записи из списка.
pub fn is_blocked(domain: &str) -> bool {
    let Some(list) = current() else { return false };
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    matches_list(&domain, &list)
}

fn current() -> Option<Arc<HashSet<String>>> {
    LIST.read().ok()?.clone()
}

fn install(list: HashSet<String>) {
    let value = (!list.is_empty()).then(|| Arc::new(list));
    if let Ok(mut guard) = LIST.write() {
        *guard = value;
    }
}

/// Перечитывает список с диска и сообщает в лог, что вышло.
///
/// При выключенном флаге список сбрасывается: иначе выключение в конфиге
/// не действовало бы до перезапуска программы.
pub fn reload(enabled: bool, log_tx: &LogSender) {
    if !enabled {
        install(HashSet::new());
        return;
    }
    match paths::read_to_string(LIST_PATH) {
        Ok(text) => {
            let list = parse(&text);
            log_t(log_tx, LogLevel::Info, "log.blocklist_active", vec![
                ("count", list.len().to_string()),
            ]);
            install(list);
        }
        Err(e) => {
            // Флаг включён, а файла нет — это не норма, а забытый файл:
            // молча работать без блокировки значит обмануть пользователя.
            log_t(log_tx, LogLevel::Warning, "log.blocklist_missing", vec![
                ("path", paths::resolve(LIST_PATH).display().to_string()),
                ("error", e.to_string()),
            ]);
            install(HashSet::new());
        }
    }
}

/// Тот же формат, что у bypass_domains.txt: домен на строку, `#` — комментарий.
fn parse(text: &str) -> HashSet<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.trim_end_matches('.').to_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_like_bypass_list() {
        let list = parse("# счётчики\nmc.yandex.ru\n\n  Top-FWZ1.mail.ru.  \n");
        assert_eq!(list.len(), 2);
        assert!(list.contains("mc.yandex.ru"));
        assert!(list.contains("top-fwz1.mail.ru"));
    }

    /// Все проверки в одном тесте: список глобальный, а тесты идут
    /// параллельно, и отдельный тест с пустым списком мешал бы этому.
    #[test]
    fn blocks_listed_domains_and_subdomains_only() {
        install(parse("mc.yandex.ru\n"));

        assert!(is_blocked("mc.yandex.ru"));
        assert!(is_blocked("MC.Yandex.RU."));
        assert!(is_blocked("a.mc.yandex.ru"));
        // Родитель и соседи — нет: блокируется счётчик, а не весь Яндекс.
        assert!(!is_blocked("yandex.ru"));
        assert!(!is_blocked("ya.ru"));
        assert!(!is_blocked("notmc.yandex.ru"));
        assert!(!is_blocked("87.250.251.119"));
    }
}
