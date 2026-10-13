//! Поля config.toml для редакторов настроек: терминального интерфейса и
//! экрана «Настройки» на телефоне. Один список полей и одна запись с
//! проверкой — чтобы ни один редактор не мог записать конфиг, с которым
//! программа потом не стартует.

use toml_edit::DocumentMut;

use crate::observability::error::AppError;

/// Поля config.toml по группам: (ключ заголовка группы, [(ключ подписи, путь в TOML)]).
/// Порядок здесь — порядок на экране. Раньше было два плоских списка:
/// полный для «Конфига» и его подмножество для «Параметров обхода».
const FIELD_GROUPS: &[(&str, &[(&str, &str)])] = &[
    ("config.group_ports", &[
        ("field.tcp_port", "port"),
        ("field.udp_port", "udp_port"),
        ("field.socks5_port", "socks5_port"),
        ("field.socks5_udp_port", "socks5_udp_port"),
        ("field.transparent_port", "transparent_port"),
        ("field.packet_mode", "packet_mode"),
    ]),
    ("config.group_bypass", &[
        ("field.enabled", "enabled"),
        ("field.split_pos_min", "bypass.split_pos_min"),
        ("field.split_pos_max", "bypass.split_pos_max"),
        ("field.split_delay", "bypass.split_delay_ms"),
        ("field.window_clamp", "bypass.window_clamp"),
        ("field.disorder_ttl", "bypass.disorder_ttl"),
        ("field.fake_ttl", "bypass.fake_ttl"),
        ("field.fake_md5sig", "bypass.fake_md5sig"),
        ("field.fake_sni", "bypass.fake_sni"),
        ("field.fake_clone", "bypass.fake_clone"),
        ("field.hostfakesplit_midhost", "bypass.hostfakesplit_midhost"),
        ("field.hostfakesplit_disorder_after", "bypass.hostfakesplit_disorder_after"),
    ]),
    ("config.group_junk", &[
        ("field.junk_count", "socks5_junk.count"),
        ("field.junk_size_min", "socks5_junk.size_min"),
        ("field.junk_size_max", "socks5_junk.size_max"),
        ("field.junk_delay_min", "socks5_junk.delay_min_ms"),
        ("field.junk_delay_max", "socks5_junk.delay_max_ms"),
    ]),
    ("config.group_diagnostics", &[
        ("field.strategy_ttl", "strategy_ttl_hours"),
        ("field.auto_diagnostics", "auto_diagnostics_hours"),
        ("field.probe_gap_min", "probe_gap_min_ms"),
        ("field.probe_gap_max", "probe_gap_max_ms"),
    ]),
    ("config.group_dns", &[
        ("field.resolve_via_doh", "resolve_via_doh"),
        ("field.doh_provider", "doh_provider"),
        ("field.doh_bootstrap_ip", "doh_bootstrap_ip"),
        ("field.smart_dns_provider", "smart_dns_provider"),
        ("field.smart_dns_bootstrap_ip", "smart_dns_bootstrap_ip"),
        ("field.block_trackers", "block_trackers"),
    ]),
];

#[derive(Debug, Clone)]
pub struct ConfigField {
    pub group_key: &'static str,
    pub label_key: &'static str,
    pub toml_path: &'static str,
    pub value: String,
}


pub fn load_fields() -> Result<Vec<ConfigField>, AppError> {
    let text = crate::config::paths::read_to_string("config.toml")
        .map_err(|e| AppError::new("error.config_read").with("error", e))?;
    let doc: DocumentMut = text.parse()
        .map_err(|e| AppError::new("error.config_parse").with("error", e))?;

    let mut fields = Vec::new();
    for (group_key, defs) in FIELD_GROUPS {
        for (label_key, path) in *defs {
            let value = get_value_at_path(&doc, path).unwrap_or_default();
            fields.push(ConfigField { group_key, label_key, toml_path: path, value });
        }
    }
    Ok(fields)
}

fn get_value_at_path(doc: &DocumentMut, path: &str) -> Option<String> {
    let parts: Vec<&str> = path.split('.').collect();
    let mut item = doc.as_item();
    for part in &parts {
        item = item.get(part)?;
    }
    item.as_value().map(|v| match v {
        toml_edit::Value::String(s) => s.value().clone(),
        other => other.to_string().trim().to_string(),
    })
}

/// Собирает новое значение поля, СОХРАНЯЯ тип того, что там лежало.
///
/// Раньше тип угадывался по введённой строке: `i64`, иначе `bool`, иначе
/// строка. Из-за этого редактор мог записать заведомо нерабочий конфиг —
/// `port = "abc"` или `doh_provider = 123`, — и следующий запуск падал на
/// `load_config`, то есть приложение окирпичивалось из собственного UI.
///
/// Тип берётся из текущего значения в файле: config.toml и есть источник
/// правды о том, что здесь ожидается. Отдельную таблицу типов заводить не
/// нужно, и она не разъедется с реальностью.
fn typed_value(existing: Option<&toml_edit::Item>, new_value: &str) -> Result<toml_edit::Item, AppError> {
    use toml_edit::Value;

    let bad = |kind: &str| {
        AppError::new("error.config_bad_value")
            .with("value", new_value)
            .with("expected", kind)
    };

    match existing.and_then(|i| i.as_value()) {
        Some(Value::Integer(_)) => new_value
            .trim()
            .parse::<i64>()
            .map(toml_edit::value)
            .map_err(|_| bad(&rust_i18n::t!("config.kind_integer"))),
        Some(Value::Boolean(_)) => new_value
            .trim()
            .parse::<bool>()
            .map(toml_edit::value)
            .map_err(|_| bad("true/false")),
        Some(Value::Float(_)) => new_value
            .trim()
            .parse::<f64>()
            .map(toml_edit::value)
            .map_err(|_| bad(&rust_i18n::t!("config.kind_number"))),
        Some(Value::String(_)) => Ok(toml_edit::value(new_value)),
        // Поля в файле ещё нет (добавлено в Config с #[serde(default)]) —
        // тип угадываем по введённому, как и раньше.
        _ => Ok(if let Ok(n) = new_value.trim().parse::<i64>() {
            toml_edit::value(n)
        } else if let Ok(b) = new_value.trim().parse::<bool>() {
            toml_edit::value(b)
        } else {
            toml_edit::value(new_value)
        }),
    }
}

pub fn save_field(toml_path: &str, new_value: &str) -> Result<(), AppError> {
    let text = crate::config::paths::read_to_string("config.toml")
        .map_err(|e| AppError::new("error.config_read").with("error", e))?;
    let mut doc: DocumentMut = text.parse()
        .map_err(|e| AppError::new("error.config_parse").with("error", e))?;

    let parts: Vec<&str> = toml_path.split('.').collect();
    if parts.is_empty() || parts.len() > 2 {
        return Err(AppError::new("error.config_bad_path").with("path", toml_path));
    }

    let new_item = typed_value(get_item_at_path(&doc, &parts), new_value)?;

    if parts.len() == 1 {
        doc[parts[0]] = new_item;
    } else {
        doc[parts[0]][parts[1]] = new_item;
    }

    // Проверяем, что получившийся документ ещё читается как Config: иначе
    // ошибку заметит только следующий запуск, и заметит отказом стартовать.
    let rendered = doc.to_string();
    if let Err(e) = toml::from_str::<crate::config::Config>(&rendered) {
        return Err(AppError::new("error.config_would_break").with("error", e));
    }

    crate::config::paths::write_atomic("config.toml", &rendered)
        .map_err(|e| AppError::new("error.config_write").with("error", e))?;

    Ok(())
}

fn get_item_at_path<'a>(doc: &'a DocumentMut, parts: &[&str]) -> Option<&'a toml_edit::Item> {
    let mut item = doc.as_item();
    for part in parts {
        item = item.get(part)?;
    }
    Some(item)
}


impl ConfigField {
    /// Переключатель «да/нет», а не текстовое поле.
    pub fn is_bool(&self) -> bool {
        matches!(self.value.as_str(), "true" | "false")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(text: &str) -> DocumentMut {
        text.parse().unwrap()
    }

    #[test]
    fn every_field_appears_once() {
        let mut paths: Vec<&str> = FIELD_GROUPS.iter().flat_map(|(_, defs)| defs.iter().map(|(_, p)| *p)).collect();
        let total = paths.len();
        paths.sort();
        paths.dedup();
        assert_eq!(paths.len(), total);
    }

    /// Каждое поле есть в config.toml из репозитория: иначе редактор показал
    /// бы пустое значение, а тип пришлось бы угадывать.
    #[test]
    fn every_field_exists_in_the_shipped_config() {
        let text = std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("config.toml")).unwrap();
        let d = doc(&text);
        for (_, defs) in FIELD_GROUPS {
            for (_, path) in *defs {
                assert!(get_value_at_path(&d, path).is_some(), "{path} нет в config.toml");
            }
        }
    }
    #[test]
    fn keeps_the_type_that_the_field_already_had() {
        let d = doc("port = 1080\nenabled = true\ndoh_provider = \"https://x\"\nreward_latency = 0.3\n");

        // Число остаётся числом
        let item = typed_value(get_item_at_path(&d, &["port"]), "8080").unwrap();
        assert_eq!(item.as_integer(), Some(8080));

        // Строка остаётся строкой, даже если выглядит как число
        let item = typed_value(get_item_at_path(&d, &["doh_provider"]), "123").unwrap();
        assert_eq!(item.as_str(), Some("123"));

        let item = typed_value(get_item_at_path(&d, &["reward_latency"]), "0.75").unwrap();
        assert_eq!(item.as_float(), Some(0.75));
    }

    #[test]
    fn refuses_a_value_of_the_wrong_type() {
        let d = doc("port = 1080\nenabled = true\n");

        // Раньше это записывало port = "abc", и следующий запуск падал
        // на разборе конфига — приложение окирпичивалось из своего же UI.
        assert!(typed_value(get_item_at_path(&d, &["port"]), "abc").is_err());
        assert!(typed_value(get_item_at_path(&d, &["enabled"]), "ага").is_err());
    }

    #[test]
    fn unknown_field_falls_back_to_guessing() {
        let d = doc("port = 1080\n");
        let item = typed_value(get_item_at_path(&d, &["not_there"]), "42").unwrap();
        assert_eq!(item.as_integer(), Some(42));
    }
}
