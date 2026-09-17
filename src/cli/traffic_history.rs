//! История трафика: мгновенная скорость, сглаженная EMA, и статистика
//! стабильности по Уэлфорду.

use std::collections::VecDeque;
use std::time::Instant;

use crate::observability::stats::{Ema, Welford};

const SPARKLINE_HISTORY: usize = 60;

/// Вес нового отсчёта в EMA. 0.25 заметно гасит одиночные всплески,
/// но реагирует на реальное изменение скорости за 3–4 секунды.
const EMA_ALPHA: f64 = 0.25;

#[derive(Debug)]
pub struct TrafficHistory {
    /// Сглаженная EMA скорость — именно она рисуется на графике, потому что
    /// сырые посекундные значения скачут на порядок и график нечитаем.
    pub rx_speed: VecDeque<u64>,
    pub tx_speed: VecDeque<u64>,
    /// Последние сырые значения — для показа текущей скорости числом.
    pub rx_raw: u64,
    pub tx_raw: u64,
    rx_ema: Ema,
    tx_ema: Ema,
    /// Статистика по RX за всю сессию: среднее и разброс. Коэффициент
    /// вариации из неё показывает стабильность канала.
    rx_stats: Welford,
    last_bytes_rx: u64,
    last_bytes_tx: u64,
    last_tick: Option<Instant>,
}

impl Default for TrafficHistory {
    fn default() -> Self {
        Self::new()
    }
}

impl TrafficHistory {
    pub fn new() -> Self {
        Self {
            rx_speed: VecDeque::with_capacity(SPARKLINE_HISTORY),
            tx_speed: VecDeque::with_capacity(SPARKLINE_HISTORY),
            rx_raw: 0,
            tx_raw: 0,
            rx_ema: Ema::new(EMA_ALPHA),
            tx_ema: Ema::new(EMA_ALPHA),
            rx_stats: Welford::new(),
            last_bytes_rx: 0,
            last_bytes_tx: 0,
            last_tick: None,
        }
    }

    /// Коэффициент вариации RX: 0 — идеально ровный канал, >1 — сильно рваный.
    /// Считается по Уэлфорду инкрементально, история отсчётов не хранится.
    pub fn rx_variation(&self) -> Option<f64> {
        self.rx_stats.coefficient_of_variation()
    }

    pub fn record(&mut self, total_rx: u64, total_tx: u64) {
        let now = Instant::now();

        let elapsed = match self.last_tick {
            Some(prev) => now.duration_since(prev).as_secs_f64(),
            None => {
                self.last_tick = Some(now);
                self.last_bytes_rx = total_rx;
                self.last_bytes_tx = total_tx;
                return;
            }
        };

        if elapsed < 1.0 {
            return;
        }

        let rx_delta = total_rx.saturating_sub(self.last_bytes_rx);
        let tx_delta = total_tx.saturating_sub(self.last_bytes_tx);

        let rx_speed = rx_delta as f64 / elapsed;
        let tx_speed = tx_delta as f64 / elapsed;

        self.rx_raw = rx_speed as u64;
        self.tx_raw = tx_speed as u64;

        // Статистику копим по сырым значениям — сглаженные занизили бы разброс.
        self.rx_stats.push(rx_speed);

        let rx_smooth = self.rx_ema.push(rx_speed) as u64;
        let tx_smooth = self.tx_ema.push(tx_speed) as u64;

        if self.rx_speed.len() >= SPARKLINE_HISTORY { self.rx_speed.pop_front(); }
        if self.tx_speed.len() >= SPARKLINE_HISTORY { self.tx_speed.pop_front(); }
        self.rx_speed.push_back(rx_smooth);
        self.tx_speed.push_back(tx_smooth);

        self.last_bytes_rx = total_rx;
        self.last_bytes_tx = total_tx;
        self.last_tick = Some(now);
    }
}
