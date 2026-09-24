//! Ядро net_surgeon — и карта проекта.
//!
//! # Почему библиотека, а не один бинарь
//!
//! Раньше всё висело на `main.rs`: модули объявлялись там же, где точка входа.
//! Для одной программы это нормально ровно до того момента, когда ядро
//! понадобилось где-то ещё. Самый близкий случай — Android: там нет ни
//! терминала, ни iptables, а нужен только SOCKS5-сервер, который подключают
//! к `VpnService` через JNI. Из бинарного крейта его не достать.
//!
//! Теперь логика живёт в библиотеке, а `main.rs` — тонкая обёртка: разобрать
//! флаг, поднять общее состояние, отдать управление интерфейсу. Заодно это
//! разделение сделало возможным `--headless`: те же слушатели без TUI.
//!
//! # Как разложен код
//!
//! Каждый модуль — каталог, и имя каталога отвечает на вопрос «зачем этот
//! код», а не «какого он размера»:
//!
//! * `config` — единственный источник настроек (config.toml) и разрешение
//!   путей к файлам данных.
//! * `observability` — как программа рассказывает о себе: логи, метрики,
//!   статистика, перевод, переводимые ошибки.
//! * `protocol` — разбор проволочных форматов: адрес назначения из SOCKS5
//!   и из HTTP. Чистые функции над байтами, без сети и без состояния.
//! * `bypass` — сами техники обхода: разбор TLS ClientHello, фрагментация,
//!   операции над сокетом.
//! * `engine` — что применять и почему: диагностика измеряет техники,
//!   хранилище стратегий помнит решение по каждому домену.
//! * `proxy` — слушатели, через которые идёт трафик: HTTP/HTTPS, прозрачный
//!   режим (TCP и QUIC), SOCKS5.
//! * `dns` — резолв: DoH-клиент, релей и кэш «адрес → домен».
//! * `block` — какие домены не пропускать вовсе: трекеры и счётчики.
//! * `cli` — терминальный интерфейс. Единственный модуль за feature-флагом.
//! * `headless` — тот же запуск без интерфейса.
//!
//! # Направление зависимостей
//!
//! Сверху вниз и без обратных рёбер: `cli` знает про `proxy` и `engine`,
//! `proxy` — про `bypass`, `protocol` и `dns`, а `observability`, `protocol`
//! и `config` не знают ни про кого.
//!
//! Перевод переехал из `cli` в `observability` именно поэтому: сообщения
//! нужны и headless-режиму, а он про терминал ничего не знает. Пока модуль
//! лежал в `cli`, вытащить его оттуда без TUI было нельзя.

rust_i18n::i18n!("locales", fallback = "en");

pub mod block;
pub mod bypass;
pub mod config;
pub mod dns;
pub mod engine;
pub mod headless;
pub mod observability;
pub mod protocol;
pub mod proxy;

/// Терминальный интерфейс. Отключается сборкой без feature `tui` — вместе
/// с ним уходят ratatui и crossterm, которые на сервере и на Android
/// не нужны и только удлиняют сборку.
#[cfg(feature = "tui")]
pub mod cli;

#[cfg(test)]
mod tests;

use std::collections::HashSet;
use std::sync::Arc;

use crate::config::Config;
use crate::dns::ip_cache::IpDomainCache;
use crate::engine::strategy::StrategyStore;
use crate::observability::metrics::Metrics;

/// Общее состояние, которое нужно и интерфейсу, и headless-режиму.
///
/// Собирается один раз при старте: конфиг, список доменов, метрики, кэши.
/// Раньше эта последовательность жила прямо в `main`, и второй способ
/// запуска пришлось бы копировать целиком.
pub struct Startup {
    pub config: Arc<Config>,
    pub domains: Arc<HashSet<String>>,
    /// Почему не удалось прочитать список обхода, если не удалось.
    ///
    /// Пустой список — валидный результат, но он же получается при
    /// отсутствии файла, а это молча выключает обход для всех доменов.
    /// Причину показывает тот, у кого есть куда её показать.
    pub domains_error: Option<String>,
    pub metrics: Arc<Metrics>,
    pub ip_cache: Arc<IpDomainCache>,
    pub strategies: Arc<StrategyStore>,
}

/// Читает конфиг и поднимает общее состояние.
///
/// Резолвер инициализируется здесь же: он модульный синглтон, и обоим
/// режимам запуска нужен одинаково настроенный.
pub fn bootstrap() -> Result<Startup, String> {
    let config = Arc::new(config::load_config()?);

    let (domains, domains_error) = config::load_bypass_domains();
    let domains = Arc::new(domains);

    let metrics = Metrics::new();
    let ip_cache = Arc::new(IpDomainCache::new());
    // Кэш выбранных стратегий переживает перезапуск — читаем с диска.
    let strategies = Arc::new(StrategyStore::load());

    // Резолвер поднимается один раз: дальше прокси и диагностика ходят
    // через него, а не через системный DNS провайдера.
    dns::resolver::init(
        config.resolve_via_doh,
        config.doh_provider.clone(),
        config.doh_bootstrap_ip,
        Arc::clone(&ip_cache),
    );

    Ok(Startup { config, domains, domains_error, metrics, ip_cache, strategies })
}

/// Язык сообщений. Обёртка нужна, чтобы бинарь не зависел от rust_i18n
/// напрямую: макрос `i18n!` раскрывается в этом крейте, и локаль логичнее
/// переключать тоже отсюда.
pub fn set_locale(code: &str) {
    rust_i18n::set_locale(code);
}
