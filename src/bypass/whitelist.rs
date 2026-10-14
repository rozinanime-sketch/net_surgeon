//! Коллекция «белых» имён SNI, которые DPI сети пропускает к Cloudflare.
//!
//! # Зачем
//!
//! На части сетей ТСПУ держит «ковровую» блокировку Cloudflare: соединения
//! к адресам Cloudflare режутся, если имя в ClientHello не из белого списка
//! оператора. Обход — приманка (`fake`, `hostfakesplit`) с именем ИЗ этого
//! списка: DPI видит разрешённое имя и пропускает, а сервер Cloudflare всё
//! равно смотрит на настоящее имя внутри.
//!
//! Какие имена в белом списке — своё у каждого оператора и меняется со
//! временем. Поэтому список не зашит, а собирается на лету и хранится в
//! `whitelist_sni.txt`, по сетям (ключ — тот же `net_id`, что у стратегий).
//!
//! # Откуда берутся имена
//!
//! 1. Сами: сайт на адресе Cloudflare открылся БЕЗ обхода и отдал данные —
//!    значит, его имя в белом списке (`observe`, из путей пересылки).
//! 2. Из диагностики: имя, с которым прошла приманка (`note`).
//! 3. Вручную: файл можно править.
//!
//! Имена из файла диагностика пробует приманками в первую очередь, до
//! `fake_sni_candidates` из конфига.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::{OnceLock, RwLock};

use crate::config::paths;

const FILE: &str = "whitelist_sni.txt";

/// Слишком длинное имя приманке бесполезно (для hostfakesplit оно не влезет
/// на место короткого), а в файле только мусорит.
const MAX_NAME_LEN: usize = 40;

/// Сколько имён помнить на сеть: больше диагностика всё равно не переберёт,
/// а файл рос бы без предела на сетях с широким белым списком.
const MAX_PER_NET: usize = 64;

type Store = BTreeMap<String, Vec<String>>;

fn store() -> &'static RwLock<Store> {
    static STORE: OnceLock<RwLock<Store>> = OnceLock::new();
    STORE.get_or_init(|| RwLock::new(load_file()))
}

fn load_file() -> Store {
    paths::read_to_string(FILE).map(|t| parse(&t)).unwrap_or_default()
}

/// Разбирает файл: строки `сеть \t имя \t дата` (дата необязательна).
/// Комментарии (`#`) и пустые строки пропускаются.
fn parse(text: &str) -> Store {
    let mut store = Store::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut cols = line.split('\t').map(str::trim).filter(|c| !c.is_empty());
        let (Some(net), Some(name)) = (cols.next(), cols.next()) else { continue };
        let names = store.entry(net.to_string()).or_default();
        let name = name.to_ascii_lowercase();
        if !names.contains(&name) && names.len() < MAX_PER_NET {
            names.push(name);
        }
    }
    store
}

/// Собирает файл обратно из памяти, в стабильном порядке (сети и имена
/// отсортированы) — чтобы правки diff'ались, а не переставлялись каждый раз.
fn render(store: &Store) -> String {
    let today = chrono::Local::now().format("%Y-%m-%d");
    let mut out = String::from(
        "# Белые имена SNI, которые DPI сети пропускает к Cloudflare.\n\
         # Собирается автоматически и правится вручную. Строка: сеть, имя, дата.\n\
         # Имя из этого файла приманка (fake/hostfakesplit) подставляет вместо\n\
         # настоящего, и DPI пропускает соединение (см. bypass::whitelist).\n\n",
    );
    for (net, names) in store {
        let mut names = names.clone();
        names.sort();
        for name in names {
            out.push_str(&format!("{net}\t{name}\t{today}\n"));
        }
    }
    out
}

/// Имена для сети по возрастанию длины: короткие годятся и для hostfakesplit
/// (подделка обязана совпасть по длине с настоящим именем), и для fake.
pub fn names(net_id: &str) -> Vec<String> {
    let mut names = store()
        .read()
        .ok()
        .and_then(|s| s.get(net_id).cloned())
        .unwrap_or_default();
    names.sort_by_key(|n| (n.len(), n.clone()));
    names
}

/// Запоминает имя как белое для сети. `true` — имя новое: файл переписан.
/// Пустая сеть (не определилась) не сохраняется: смешала бы разные сети.
pub fn note(net_id: &str, name: &str) -> bool {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    if net_id.is_empty() || name.is_empty() || name.len() > MAX_NAME_LEN || !name.contains('.') {
        return false;
    }
    let rendered = {
        let Ok(mut store) = store().write() else { return false };
        let names = store.entry(net_id.to_string()).or_default();
        if names.contains(&name) || names.len() >= MAX_PER_NET {
            return false;
        }
        names.push(name);
        render(&store)
    };
    // Запись вне блокировки: save() зовут и из других мест, а файл атомарный.
    let _ = paths::write_atomic(FILE, &rendered);
    true
}

/// Сайт на адресе Cloudflare открылся без обхода и отдал данные — его имя в
/// белом списке. Условия узкие нарочно: не-Cloudflare сайты открываются и
/// так (имя оператору ни о чём не говорит), а без данных это могло быть
/// оборванное на рукопожатии соединение.
pub fn observe(net_id: &str, ip: IpAddr, host: &str, received: u64, bypassed: bool) {
    const MIN_DATA: u64 = 2 * 1024;
    if !bypassed && received >= MIN_DATA && is_cloudflare(ip) && host.parse::<IpAddr>().is_err() {
        note(net_id, host);
    }
}

/// Перечитывает файл (при старте прокси, как у `block`/`smart`).
pub fn reload() {
    if let Ok(mut store) = store().write() {
        *store = load_file();
    }
}

/// Диапазоны Cloudflare (IPv4), на которых живут Discord, Telegram-web и
/// половина сайтов. Официальный список cloudflare.com/ips; меняется редко.
const CLOUDFLARE_V4: &[([u8; 4], u8)] = &[
    ([173, 245, 48, 0], 20),
    ([103, 21, 244, 0], 22),
    ([103, 22, 200, 0], 22),
    ([103, 31, 4, 0], 22),
    ([141, 101, 64, 0], 18),
    ([108, 162, 192, 0], 18),
    ([190, 93, 240, 0], 20),
    ([188, 114, 96, 0], 20),
    ([197, 234, 240, 0], 22),
    ([198, 41, 128, 0], 17),
    ([162, 158, 0, 0], 15),
    ([104, 16, 0, 0], 13),
    ([104, 24, 0, 0], 14),
    ([172, 64, 0, 0], 13),
    ([131, 0, 72, 0], 22),
];

/// Адрес принадлежит Cloudflare.
pub fn is_cloudflare(ip: IpAddr) -> bool {
    let IpAddr::V4(v4) = ip else { return false };
    let n = u32::from(v4);
    CLOUDFLARE_V4.iter().any(|(base, bits)| {
        let mask = u32::MAX << (32 - bits);
        n & mask == u32::from_be_bytes(*base)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_render_round_trip_dedupes_and_sorts() {
        let store = parse("# коммент\ngw:A\t4pda.to\t2026-10-14\ngw:A\tdi.fm\ngw:A\t4pda.to\ngw:B\tzoom.us\n\n");
        assert_eq!(store["gw:A"].len(), 2, "дубль 4pda.to не повторяется");
        let text = render(&store);
        // Имена сети отсортированы, сети тоже; повторный разбор совпадает.
        assert_eq!(parse(&text), store);
        assert!(text.contains("gw:A\t4pda.to\t"));
        assert!(text.contains("gw:B\tzoom.us\t"));
    }

    #[test]
    fn names_are_returned_shortest_first() {
        let store = parse("gw:A\tstackoverflow.com\ngw:A\t4pda.to\ngw:A\tdi.fm\n");
        let names: Vec<String> = {
            let mut n = store["gw:A"].clone();
            n.sort_by_key(|x| (x.len(), x.clone()));
            n
        };
        assert_eq!(names, ["di.fm", "4pda.to", "stackoverflow.com"]);
    }

    #[test]
    fn cloudflare_ranges_recognise_discord_and_reject_others() {
        assert!(is_cloudflare("162.159.137.232".parse().unwrap()), "адрес Discord");
        assert!(is_cloudflare("104.16.123.96".parse().unwrap()), "cloudflare.com");
        assert!(!is_cloudflare("142.251.153.4".parse().unwrap()), "Google");
        assert!(!is_cloudflare("8.8.8.8".parse().unwrap()));
        assert!(!is_cloudflare("2606:4700::1111".parse().unwrap()), "IPv6 не проверяем");
    }

    #[test]
    fn parse_skips_malformed_and_lowercases() {
        let store = parse("gw:A\n\tname.only\njunk-without-tab\ngw:A\tFANDOM.com\t2026-01-01\n");
        assert_eq!(store.get("gw:A").map(Vec::as_slice), Some(["fandom.com".to_string()].as_slice()));
    }
}
