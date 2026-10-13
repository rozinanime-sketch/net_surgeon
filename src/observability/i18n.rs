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
    let template = crate::_rust_i18n_try_translate(lang_code, key)
        .map(|t| t.into_owned())
        .unwrap_or_else(|| key.to_string());
    substitute(&template, args)
}

/// Подставляет `%{имя}` за один проход по шаблону. Раньше аргументы
/// подставлялись по очереди в растущую строку, и значение, в котором самом
/// встречалось `%{error}` (заголовок Host от клиента, текст ошибки),
/// подменялось следующим аргументом.
fn substitute(template: &str, args: &[(String, String)]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("%{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        match after.find('}') {
            Some(end) => {
                let name = &after[..end];
                match args.iter().find(|(n, _)| n == name) {
                    Some((_, value)) => out.push_str(value),
                    None => out.push_str(&rest[start..start + 2 + end + 1]),
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push_str(&rest[start..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
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
    fn values_are_not_substituted_again() {
        let args = vec![
            ("addr".to_string(), "evil%{error}".to_string()),
            ("error".to_string(), "timeout".to_string()),
        ];
        assert_eq!(substitute("%{addr}: %{error} %{unknown}", &args), "evil%{error}: timeout %{unknown}");
        assert_eq!(substitute("open %{", &args), "open %{");
    }

    #[test]
    fn unknown_key_is_shown_as_is() {
        assert_eq!(translate("ru", "no.such.key", &[]), "no.such.key");
    }
}
