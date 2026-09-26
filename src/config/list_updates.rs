//! Новые домены для списков, которые у пользователя уже есть.
//!
//! # Зачем
//!
//! Списки доменов лежат рядом с программой и правятся руками, поэтому при
//! обновлении их никто не перезаписывает. Но тогда домен, добавленный в
//! новой версии, до старого пользователя не доходит: так в 0.6.2 приложение
//! Gemini заработало только у тех, кто заменил smart_dns_domains.txt сам.
//!
//! # Как, чтобы не мешать
//!
//! * Только дописываем в конец. Ничего не удаляется и не переставляется,
//!   комментарии и правки пользователя остаются как были.
//! * Каждый домен предлагается один раз. Предложенные запоминаются в
//!   файле-метке рядом со списком, и если пользователь домен удалит, при
//!   следующем запуске он не вернётся.
//! * Домен, который уже покрыт списком (он сам или его родитель), не
//!   дописывается.
//! * Нет файла списка — ничего не создаём: его отсутствие и так видно
//!   (см. `startup.domains_missing`), а создавать его за пользователя
//!   незачем.
//! * Сеть не нужна: новые домены вшиты в программу.
//! * Выключается `add_new_domains = false` в config.toml.
//!
//! Имена файлов-меток те же, что были у Android-приложения, когда оно
//! делало это само: уже предложенное там не предлагается заново.

use std::collections::HashSet;

use super::paths;
use crate::observability::logging::{LogLevel, LogPayload};

/// Домены, появившиеся в списке после первых версий.
struct Offer {
    file: &'static str,
    mark: &'static str,
    domains: &'static [&'static str],
}

/// Сюда дописываются домены, которые новая версия добавляет в список.
/// Удалять отсюда ничего не нужно: у кого домен уже есть, тому он не
/// дописывается.
const OFFERS: &[Offer] = &[
    Offer {
        file: "bypass_domains.txt",
        mark: ".added_bypass",
        domains: &["youtubei.googleapis.com"],
    },
    Offer {
        file: "smart_dns_domains.txt",
        mark: ".added_smart_dns",
        // API, в которые ходят приложения Gemini и NotebookLM (0.6.2).
        domains: &[
            "robinfrontend-pa.googleapis.com",
            "proactivebackend-pa.googleapis.com",
            "aisandbox-pa.googleapis.com",
            "notebooklm-pa.googleapis.com",
        ],
    },
];

/// Что произошло с одним списком. Списки, где ничего не менялось, в
/// результат не попадают.
#[derive(Debug, PartialEq)]
pub struct ListUpdate {
    pub file: &'static str,
    pub result: Result<Vec<String>, String>,
}

impl ListUpdate {
    /// Строка для лога: какие домены дописаны или почему не удалось.
    pub fn log_message(&self) -> (LogLevel, LogPayload) {
        let (level, key, args) = match &self.result {
            Ok(added) => (LogLevel::Info, "startup.list_domains_added", ("domains", added.join(", "))),
            Err(e) => (LogLevel::Warning, "startup.list_update_failed", ("error", e.clone())),
        };
        let args = vec![("file".to_string(), self.file.to_string()), (args.0.to_string(), args.1)];
        (level, LogPayload::Translated { key: key.to_string(), args })
    }
}

/// Дописывает новые домены во все списки. Вызывается при запуске до того,
/// как списки прочитаны.
pub fn apply() -> Vec<ListUpdate> {
    OFFERS.iter().filter_map(apply_offer).collect()
}

fn apply_offer(offer: &Offer) -> Option<ListUpdate> {
    let offered: HashSet<String> = paths::read_to_string(offer.mark)
        .map(|t| t.lines().map(|l| l.trim().to_string()).collect())
        .unwrap_or_default();
    let fresh: Vec<&str> = offer.domains.iter().copied().filter(|d| !offered.contains(*d)).collect();
    if fresh.is_empty() {
        return None;
    }
    let current = paths::read_to_string(offer.file).ok()?;

    let (text, added) = append_missing(&current, &fresh);
    let fail = |e: std::io::Error| Some(ListUpdate { file: offer.file, result: Err(e.to_string()) });
    if let Some(text) = &text
        && let Err(e) = paths::write_atomic(offer.file, text)
    {
        // Метку не пишем: в следующий раз попробуем снова.
        return fail(e);
    }

    let mut mark: Vec<&str> = offered.iter().map(String::as_str).filter(|l| !l.is_empty()).collect();
    mark.extend(&fresh);
    mark.sort_unstable();
    if let Err(e) = paths::write_atomic(offer.mark, &(mark.join("\n") + "\n")) {
        return fail(e);
    }

    (!added.is_empty()).then_some(ListUpdate { file: offer.file, result: Ok(added) })
}

/// Новый текст списка, если в него есть что дописать, и дописанные домены.
fn append_missing(current: &str, fresh: &[&str]) -> (Option<String>, Vec<String>) {
    let present = crate::block::parse(current);
    let added: Vec<String> = fresh
        .iter()
        .filter(|d| !crate::bypass::matches_list(d, &present))
        .map(|d| d.to_string())
        .collect();
    if added.is_empty() {
        return (None, added);
    }
    let sep = if current.is_empty() || current.ends_with('\n') { "" } else { "\n" };
    (Some(format!("{current}{sep}{}\n", added.join("\n"))), added)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appends_only_missing_domains_and_keeps_the_rest() {
        let current = "# мой список\nchatgpt.com\n";
        let (text, added) = append_missing(current, &["chatgpt.com", "gemini.google.com"]);
        assert_eq!(added, ["gemini.google.com"]);
        assert_eq!(text.as_deref(), Some("# мой список\nchatgpt.com\ngemini.google.com\n"));
    }

    #[test]
    fn domain_covered_by_parent_is_not_appended() {
        let (text, added) = append_missing("googleapis.com\n", &["robinfrontend-pa.googleapis.com"]);
        assert!(added.is_empty());
        assert_eq!(text, None);
    }

    #[test]
    fn missing_newline_at_end_is_added() {
        let (text, _) = append_missing("a.com", &["b.com"]);
        assert_eq!(text.as_deref(), Some("a.com\nb.com\n"));
    }

    // Файлы — в каталоге данных тестов (временном), у каждого теста свои.
    fn write(name: &str, text: &str) {
        paths::write_atomic(name, text).unwrap();
    }
    fn read(name: &str) -> String {
        paths::read_to_string(name).unwrap()
    }

    #[test]
    fn each_domain_is_offered_once_even_if_user_removes_it() {
        let offer = Offer { file: "lu_once.txt", mark: ".lu_once", domains: &["new.example"] };
        write("lu_once.txt", "old.example\n");

        let update = apply_offer(&offer).unwrap();
        assert_eq!(update.result, Ok(vec!["new.example".to_string()]));
        assert_eq!(read("lu_once.txt"), "old.example\nnew.example\n");

        // Пользователь удалил домен — назад он не возвращается.
        write("lu_once.txt", "old.example\n");
        assert_eq!(apply_offer(&offer), None);
        assert_eq!(read("lu_once.txt"), "old.example\n");
    }

    #[test]
    fn domain_already_in_list_is_remembered_without_changes() {
        let offer = Offer { file: "lu_have.txt", mark: ".lu_have", domains: &["x.example"] };
        write("lu_have.txt", "x.example\n");

        assert_eq!(apply_offer(&offer), None);
        assert_eq!(read("lu_have.txt"), "x.example\n");
        assert_eq!(read(".lu_have"), "x.example\n");
    }

    #[test]
    fn missing_list_is_not_created() {
        let offer = Offer { file: "lu_absent.txt", mark: ".lu_absent", domains: &["y.example"] };
        assert_eq!(apply_offer(&offer), None);
        assert!(paths::read_to_string("lu_absent.txt").is_err());
        // И домен не считается предложенным: появится список — допишется.
        assert!(paths::read_to_string(".lu_absent").is_err());
    }

    #[test]
    fn shipped_lists_already_contain_every_offered_domain() {
        // Иначе новый пользователь получил бы «добавлено» при первом же
        // запуске: домен забыли внести в сам список в репозитории.
        for offer in OFFERS {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(offer.file);
            let list = crate::block::parse(&std::fs::read_to_string(path).unwrap());
            for d in offer.domains {
                assert!(crate::bypass::matches_list(d, &list), "{d} нет в {}", offer.file);
            }
        }
    }
}
