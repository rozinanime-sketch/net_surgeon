//! Перевод для динамических данных (логи с рантайм-ключами, метки полей
//! конфига) — ключ здесь приходит из логики (log_t/log_nested_t), а не
//! строковым литералом, как в макросе rust_i18n::t!().
//!
//! Было: отдельное чтение locales/*.yml через serde_yaml во время работы.
//! Это дублировало rust_i18n, который те же файлы уже вшивает в бинарь при
//! сборке, тянуло за собой объявленный устаревшим serde_yaml и молча
//! превращало все сообщения в голые ключи, если каталог locales/ не
//! находился рядом с программой. Теперь перевод берётся из того же
//! встроенного словаря, что и у t!(), — с тем же откатом на английский.

pub fn translate(lang_code: &str, key: &str, args: &[(String, String)]) -> String {
    let mut text = crate::_rust_i18n_try_translate(lang_code, key)
        .map(|t| t.into_owned())
        .unwrap_or_else(|| key.to_string());
    for (name, value) in args {
        text = text.replace(&format!("%{{{}}}", name), value);
    }
    text
}

pub fn translate_nested(
    lang_code: &str,
    key: &str,
    nested_arg_name: &str,
    nested_key: &str,
    other_args: &[(String, String)],
) -> String {
    let nested_text = translate(lang_code, nested_key, &[]);
    let mut args: Vec<(String, String)> = other_args.to_vec();
    args.push((nested_arg_name.to_string(), nested_text));
    translate(lang_code, key, &args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translates_from_the_embedded_dictionary_with_arguments() {
        let args = vec![("field".to_string(), "port".to_string())];
        assert_eq!(translate("ru", "config.field_saved", &args), "Поле port сохранено");
        assert_eq!(translate("en", "config.field_saved", &args), "Field port saved");
    }

    #[test]
    fn unknown_key_is_shown_as_is() {
        assert_eq!(translate("ru", "no.such.key", &[]), "no.such.key");
    }
}
