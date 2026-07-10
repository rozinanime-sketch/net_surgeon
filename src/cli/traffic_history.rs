use std::collections::VecDeque;
use std::time::Instant;

const SPARKLINE_HISTORY: usize = 60; // 60 точек истории (примерно 60 секунд при обновлении раз в сек)

#[derive(Debug)]
pub struct TrafficHistory {
    pub rx_speed: VecDeque<u64>,
    pub tx_speed: VecDeque<u64>,
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
            last_bytes_rx: 0,
            last_bytes_tx: 0,
            last_tick: None,
        }
    }

    /// Вызывается каждый раз, когда обновляется metrics snapshot.
    /// Считает байт/сек с момента последнего вызова и кладёт в историю.
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

        // Обновляем не чаще раза в секунду, чтобы график не дёргался каждый кадр (100мс)
        if elapsed < 1.0 {
            return;
        }

        let rx_delta = total_rx.saturating_sub(self.last_bytes_rx);
        let tx_delta = total_tx.saturating_sub(self.last_bytes_tx);

        let rx_speed = (rx_delta as f64 / elapsed) as u64;
        let tx_speed = (tx_delta as f64 / elapsed) as u64;

        if self.rx_speed.len() >= SPARKLINE_HISTORY {
            self.rx_speed.pop_front();
        }
        if self.tx_speed.len() >= SPARKLINE_HISTORY {
            self.tx_speed.pop_front();
        }
        self.rx_speed.push_back(rx_speed);
        self.tx_speed.push_back(tx_speed);

        self.last_bytes_rx = total_rx;
        self.last_bytes_tx = total_tx;
        self.last_tick = Some(now);
    }
}
