mod config;
mod cli;
mod proxy;
mod bypass;
mod udp;
mod socks5;
mod metrics;
mod diagnostics;

use std::sync::Arc;

#[tokio::main]
async fn main() {
    let config = match config::load_config() {
        Ok(c) => Arc::new(c),
        Err(e) => {
            eprintln!("[✗] {}", e);
            std::process::exit(1);
        }
    };

    let domains = Arc::new(config::load_bypass_domains());
    let metrics = metrics::Metrics::new();

    if let Err(e) = cli::run(config, domains, metrics) {
        eprintln!("[✗] Ошибка TUI: {}", e);
        std::process::exit(1);
    }
}
