mod adaptive;
mod tcp;
mod handshake;
mod http;
mod https;
mod transparent;
mod transparent_udp;
// pub, потому что подмодули ходят друг к другу (socks5/udp.rs читает
// udp::quic_parser) и на них смотрят интеграционные тесты.
pub mod socks5;
pub mod udp;

use std::sync::Arc;
use std::collections::HashSet;
use crate::config::Config;
use crate::observability::logging::{LogSender, log_t, LogLevel};
use crate::observability::metrics::Metrics;
use crate::dns::ip_cache::IpDomainCache;
use crate::engine::strategy::StrategyStore;
use tokio_util::sync::CancellationToken;

/// Сколько ждать от клиента начала разговора: заголовков HTTP-запроса,
/// приветствия и запроса SOCKS5, первого пакета в прозрачном режиме.
///
/// Без предела соединение, которое открыли и замолчали, жило вечно: задача,
/// сокет и буфер на каждое. Сканер портов, зависшее приложение или просто
/// много полуоткрытых соединений понемногу выедали дескрипторы, пока прокси
/// не упирался в `ulimit -n` и не переставал принимать всех остальных.
///
/// Только до начала пересылки: дальше молчание нормально (keep-alive,
/// long polling), и обрывать его нельзя.
pub(crate) const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

pub async fn run_all(
    config: Arc<Config>,
    domains: Arc<HashSet<String>>,
    log_tx: LogSender,
    metrics: Arc<Metrics>,
    token: CancellationToken,
    ip_cache: Arc<IpDomainCache>,
    strategies: Arc<StrategyStore>,
) {
    let host = config.listen_host.clone();
    let listen_address = format!("{}:{}", host, config.port);
    let udp_address = format!("{}:{}", host, config.udp_port);
    let socks5_udp_address = format!("{}:{}", host, config.socks5_udp_port);

    log_t(&log_tx, LogLevel::Info, "log.proxy_port_tcp", vec![("addr", listen_address.clone())]);
    if config.udp_port > 0 {
        log_t(&log_tx, LogLevel::Info, "log.proxy_port_doh", vec![
            ("addr", udp_address.clone()),
            ("provider", config.doh_provider.clone()),
        ]);
    }
    log_t(&log_tx, LogLevel::Info, "log.proxy_port_socks5", vec![("port", config.socks5_port.to_string()), ("udp_port", config.socks5_udp_port.to_string())]);

    // Здесь, а не при старте программы: run_all зовётся и при перезапуске
    // прокси из интерфейса, и правки списка применяются тогда же, когда
    // правки config.toml и bypass_domains.txt.
    crate::block::reload(config.block_trackers, &log_tx);

    let tcp_task = {
        let config = Arc::clone(&config);
        let domains = Arc::clone(&domains);
        let log_tx = log_tx.clone();
        let metrics = Arc::clone(&metrics);
        let token = token.clone();
        let ip_cache = Arc::clone(&ip_cache);
        let strategies = Arc::clone(&strategies);
        tokio::spawn(async move {
            tcp::run_tcp_proxy(listen_address, config.enabled, domains, config.bypass.clone(), config.strategy_ttl_hours, log_tx, metrics, token, ip_cache, strategies).await;
        })
    };

    // DoH-релей. Выбора режима больше нет: простой форвардер DNS удалён,
    // так что порт либо занят релеем, либо выключен нулём.
    let udp_task = {
        let config = Arc::clone(&config);
        let log_tx = log_tx.clone();
        let metrics = Arc::clone(&metrics);
        let token = token.clone();
        let ip_cache = Arc::clone(&ip_cache);
        tokio::spawn(async move {
            if config.udp_port > 0 {
                crate::dns::doh::run_doh_relay(
                    udp_address,
                    config.doh_provider.clone(),
                    config.doh_bootstrap_ip,
                    log_tx,
                    metrics,
                    token,
                    ip_cache,
                ).await;
            }
        })
    };

    let socks5_task = {
        let config = Arc::clone(&config);
        let domains = Arc::clone(&domains);
        let log_tx = log_tx.clone();
        let metrics = Arc::clone(&metrics);
        let token = token.clone();
        let strategies = Arc::clone(&strategies);
        let ip_cache = Arc::clone(&ip_cache);
        tokio::spawn(async move {
            socks5::tcp::run_socks5_server(
                &config.listen_host,
                config.socks5_port,
                config.socks5_udp_port,
                config.enabled,
                domains,
                config.bypass.clone(),
                config.strategy_ttl_hours,
                log_tx,
                metrics,
                token,
                strategies,
                ip_cache,
            ).await;
        })
    };

    // Прозрачный режим — только если порт задан: он требует правила iptables,
    // без которого слушатель просто никого не дождётся.
    let transparent_task = {
        let config = Arc::clone(&config);
        let domains = Arc::clone(&domains);
        let log_tx = log_tx.clone();
        let metrics = Arc::clone(&metrics);
        let token = token.clone();
        let ip_cache = Arc::clone(&ip_cache);
        let strategies = Arc::clone(&strategies);
        tokio::spawn(async move {
            if config.transparent_port > 0 {
                transparent::run_transparent_proxy(
                    &config.listen_host,
                    config.transparent_port,
                    config.enabled,
                    domains,
                    config.bypass.clone(),
                    config.strategy_ttl_hours,
                    log_tx,
                    metrics,
                    token,
                    ip_cache,
                    strategies,
                ).await;
            }
        })
    };

    // Тот же порт, что у TCP-части прозрачного режима: протоколы разные,
    // за порт они не спорят, а конфиг остаётся с одним понятным числом.
    //
    // Слушатель поднимается отдельной задачей, потому что требует
    // CAP_NET_ADMIN и может не стартовать там, где TCP-часть работает.
    // Его отказ не должен утаскивать за собой остальное.
    let transparent_udp_task = {
        let config = Arc::clone(&config);
        let domains = Arc::clone(&domains);
        let log_tx = log_tx.clone();
        let metrics = Arc::clone(&metrics);
        let token = token.clone();
        let ip_cache = Arc::clone(&ip_cache);
        tokio::spawn(async move {
            if config.transparent_port > 0 {
                transparent_udp::run_transparent_udp(
                    &config.listen_host,
                    config.transparent_port,
                    config.enabled,
                    domains,
                    config.socks5_junk.clone(),
                    log_tx,
                    metrics,
                    token,
                    ip_cache,
                ).await;
            }
        })
    };

    let socks5_udp_task = {
        let config = Arc::clone(&config);
        let log_tx = log_tx.clone();
        let metrics = Arc::clone(&metrics);
        let token = token.clone();
        tokio::spawn(async move {
            socks5::udp::run_socks5_udp_processor(&socks5_udp_address, config.socks5_junk.clone(), log_tx, metrics, token).await;
        })
    };

    let _ = tokio::join!(
        tcp_task,
        udp_task,
        socks5_task,
        socks5_udp_task,
        transparent_task,
        transparent_udp_task
    );
}
