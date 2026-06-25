use std::fs;
use std::collections::HashSet;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Ranges {
    pub frag_min: usize,
    pub frag_max: usize,
    pub delay_min_ms: u64,
    pub delay_max_ms: u64,
    pub udp_jitter_min_ms: u64,
    pub udp_jitter_max_ms: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct BypassParams {
    pub split_pos: usize,
    pub split_delay_ms: u64,
    pub window_clamp: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct QuicConfig {
    pub listen_port: u16,
    pub target: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub port: u16,
    pub udp_port: u16,
    pub udp_target: String,
    pub socks5_port: u16,
    pub socks5_udp_port: u16,
    pub enabled: bool,
    pub ranges: Ranges,
    pub bypass: BypassParams,
    pub quic: QuicConfig,
}

pub fn load_config() -> Result<Config, String> {
    let contents = fs::read_to_string("config.toml")
    .map_err(|e| format!("Не удалось прочитать config.toml: {}", e))?;
    toml::from_str(&contents)
    .map_err(|e| format!("Не удалось распарсить config.toml: {}", e))
}

pub fn load_bypass_domains() -> HashSet<String> {
    fs::read_to_string("bypass_domains.txt")
    .unwrap_or_default()
    .lines()
    .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
    .map(|l| l.trim().to_lowercase())
    .collect()
}
