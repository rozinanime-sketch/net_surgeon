//! Закреплённые техники: `домен → техника`, жёстко и в обход диагностики.
//!
//! # Зачем
//!
//! Диагностика выбирает технику по пробам, а на мерцающих сетях (ковровый
//! блок Cloudflare) пробы — монетка: то `fake`, то `hostfakesplit`. Если вы
//! знаете, что для домена работает конкретная техника, закрепите её в
//! `pin_strategies.txt` — она применяется всегда, не зависит ни от сети, ни
//! от диагностики и не сбрасывается.
//!
//! Особенно полезно на телефонном хотспоте, где IP шлюза (а с ним и ключ
//! сети стратегий) меняется, и обычные записи `strategies.txt` каждый раз
//! обнуляются.
//!
//! Формат — как у списков доменов: по строке `домен TAB техника`, суффиксное
//! совпадение (поддомены — тоже). Техники: как в strategies.txt
//! (`hostfakesplit`, `fake`, `tls_record`, `disorder`, `oob`, `sni_split`,
//! `fake_multidisorder`, `none`, …).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::engine::strategy::Strategy;

const FILE: &str = "pin_strategies.txt";

static PINS: RwLock<Option<Arc<HashMap<String, Strategy>>>> = RwLock::new(None);

/// Закреплённая техника для домена или его родителя; `None` — не закреплено.
pub fn pinned(domain: &str) -> Option<Strategy> {
    let map = PINS.read().ok().and_then(|g| g.clone())?;
    let mut cur = domain.trim_end_matches('.').to_ascii_lowercase();
    loop {
        if let Some(s) = map.get(&cur) {
            return Some(*s);
        }
        cur = cur.split_once('.')?.1.to_string();
    }
}

/// Перечитывает файл (при старте прокси, как `block`/`smart`/`whitelist`).
pub fn reload() {
    let map = crate::config::paths::read_to_string(FILE).map(|t| parse(&t)).unwrap_or_default();
    if let Ok(mut g) = PINS.write() {
        *g = (!map.is_empty()).then(|| Arc::new(map));
    }
}

/// Разбор: строки `домен TAB техника`, комментарии (`#`) и пустые — мимо.
/// Неизвестная техника пропускается, чтобы опечатка не роняла весь файл.
fn parse(text: &str) -> HashMap<String, Strategy> {
    let mut map = HashMap::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut cols = line.split_whitespace();
        if let (Some(domain), Some(tech)) = (cols.next(), cols.next())
            && let Some(s) = Strategy::parse(tech)
        {
            map.insert(domain.trim_end_matches('.').to_ascii_lowercase(), s);
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_matches_subdomains() {
        let map = parse("# коммент\ndiscord.com\thostfakesplit\ngateway.discord.gg\tfake\nbad.example\tнеттакой\n");
        assert_eq!(map.get("discord.com"), Some(&Strategy::HostFakeSplit));
        assert_eq!(map.get("gateway.discord.gg"), Some(&Strategy::Fake));
        assert!(!map.contains_key("bad.example"), "неизвестная техника пропущена");

        let install: HashMap<String, Strategy> = map;
        *PINS.write().unwrap() = Some(Arc::new(install));
        assert_eq!(pinned("discord.com"), Some(Strategy::HostFakeSplit));
        assert_eq!(pinned("CDN.discord.com."), Some(Strategy::HostFakeSplit), "поддомен и регистр/точка");
        assert_eq!(pinned("gateway.discord.gg"), Some(Strategy::Fake));
        assert_eq!(pinned("youtube.com"), None);
        *PINS.write().unwrap() = None;
    }
}
