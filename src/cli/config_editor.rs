use toml_edit::DocumentMut;
use super::app::ConfigField;

/// Полный список — используется экраном "Конфиг"
const FULL_FIELD_DEFS: &[(&str, &str)] = &[
    ("TCP порт", "port"),
    ("UDP порт", "udp_port"),
    ("UDP цель", "udp_target"),
    ("SOCKS5 порт", "socks5_port"),
    ("SOCKS5 UDP порт", "socks5_udp_port"),
    ("Обход включён", "enabled"),
    ("Frag мин (байт)", "ranges.frag_min"),
    ("Frag макс (байт)", "ranges.frag_max"),
    ("Задержка мин (мс)", "ranges.delay_min_ms"),
    ("Задержка макс (мс)", "ranges.delay_max_ms"),
    ("UDP jitter мин (мс)", "ranges.udp_jitter_min_ms"),
    ("UDP jitter макс (мс)", "ranges.udp_jitter_max_ms"),
    ("Split позиция (байт)", "bypass.split_pos"),
    ("Split задержка (мс)", "bypass.split_delay_ms"),
    ("Window clamp", "bypass.window_clamp"),
    ("QUIC порт", "quic.listen_port"),
    ("QUIC цель", "quic.target"),
];

/// Боевые DPI-параметры — используется экраном "Параметры обхода"
const BYPASS_FIELD_DEFS: &[(&str, &str)] = &[
    ("Обход включён", "enabled"),
    ("Frag мин (байт)", "ranges.frag_min"),
    ("Frag макс (байт)", "ranges.frag_max"),
    ("Задержка мин (мс)", "ranges.delay_min_ms"),
    ("Задержка макс (мс)", "ranges.delay_max_ms"),
    ("UDP jitter мин (мс)", "ranges.udp_jitter_min_ms"),
    ("UDP jitter макс (мс)", "ranges.udp_jitter_max_ms"),
    ("Split позиция (байт)", "bypass.split_pos"),
    ("Split задержка (мс)", "bypass.split_delay_ms"),
    ("Window clamp", "bypass.window_clamp"),
];

pub fn load_fields() -> Result<Vec<ConfigField>, String> {
    load_fields_from(FULL_FIELD_DEFS)
}

pub fn load_bypass_fields() -> Result<Vec<ConfigField>, String> {
    load_fields_from(BYPASS_FIELD_DEFS)
}

fn load_fields_from(defs: &[(&'static str, &'static str)]) -> Result<Vec<ConfigField>, String> {
    let text = std::fs::read_to_string("config.toml")
    .map_err(|e| format!("Не удалось прочитать config.toml: {}", e))?;
    let doc: DocumentMut = text.parse()
    .map_err(|e| format!("Не удалось распарсить config.toml: {}", e))?;

    let mut fields = Vec::new();
    for (label, path) in defs {
        let value = get_value_at_path(&doc, path).unwrap_or_default();
        fields.push(ConfigField {
            label,
            toml_path: path,
            value,
        });
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

pub fn save_field(toml_path: &str, new_value: &str) -> Result<(), String> {
    let text = std::fs::read_to_string("config.toml")
    .map_err(|e| format!("Не удалось прочитать config.toml: {}", e))?;
    let mut doc: DocumentMut = text.parse()
    .map_err(|e| format!("Не удалось распарсить config.toml: {}", e))?;

    let parts: Vec<&str> = toml_path.split('.').collect();

    let new_item: toml_edit::Item = if let Ok(n) = new_value.parse::<i64>() {
        toml_edit::value(n)
    } else if let Ok(b) = new_value.parse::<bool>() {
        toml_edit::value(b)
    } else {
        toml_edit::value(new_value)
    };

    if parts.len() == 1 {
        doc[parts[0]] = new_item;
    } else if parts.len() == 2 {
        doc[parts[0]][parts[1]] = new_item;
    } else {
        return Err(format!("Неподдерживаемый путь: {}", toml_path));
    }

    std::fs::write("config.toml", doc.to_string())
    .map_err(|e| format!("Не удалось сохранить config.toml: {}", e))?;

    Ok(())
}
