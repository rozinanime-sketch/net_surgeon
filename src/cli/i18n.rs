use std::collections::HashMap;
use std::sync::OnceLock;

struct Translations {
    ru: HashMap<String, String>,
    en: HashMap<String, String>,
}

static TRANSLATIONS: OnceLock<Translations> = OnceLock::new();

fn load_yaml_flat(path: &str) -> HashMap<String, String> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let mut map = HashMap::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("_version") {
            continue;
        }
        // Формат: key: "value" (плоские ключи, _version: 1 стиль)
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim().to_string();
            let value = value.trim();
            let value = value.trim_matches('"').to_string();
            map.insert(key, value);
        }
    }

    map
}

fn ensure_loaded() -> &'static Translations {
    TRANSLATIONS.get_or_init(|| Translations {
        ru: load_yaml_flat("locales/ru.yml"),
                             en: load_yaml_flat("locales/en.yml"),
    })
}

/// Переводит ключ для текущего языка приложения (передаётся явно, раз rust_i18n::locale()
/// и наш собственный загрузчик — два независимых источника истины).
pub fn translate(lang_code: &str, key: &str, args: &[(String, String)]) -> String {
    let translations = ensure_loaded();
    let map = if lang_code == "ru" { &translations.ru } else { &translations.en };

    let mut text = map.get(key).cloned().unwrap_or_else(|| key.to_string());

    for (name, value) in args {
        text = text.replace(&format!("%{{{}}}", name), value);
    }

    text
}

pub fn translate_nested(lang_code: &str, key: &str, nested_arg_name: &str, nested_key: &str, other_args: &[(String, String)]) -> String {
    let nested_text = translate(lang_code, nested_key, &[]);
    let mut args: Vec<(String, String)> = other_args.to_vec();
    args.push((nested_arg_name.to_string(), nested_text));
    translate(lang_code, key, &args)
}
