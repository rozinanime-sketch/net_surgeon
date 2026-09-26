//! Статистика.
//!
//! Три инструмента, каждый под свою задачу:
//!
//! * `wilson_lower_bound` — оценка вероятности успеха стратегии по серии проб.
//!   Нужен потому, что измерение обхода шумное: сеть теряет пакеты, DPI реагирует
//!   не всегда одинаково. Наивное `успехи/попытки` на 3 пробах даёт 1.0 при 3/3 —
//!   и мы уверенно закрепляем стратегию, которой просто повезло.
//!
//! * `Ema` — сглаживание графиков скорости, чтобы они не дёргались посекундно.
//!
//! * `Welford` — среднее и дисперсия «на лету», без хранения истории.

/// Скользящее окно наблюдений для перцентилей.
///
/// Среднее скрывает хвосты: стратегия может давать 35 мс в типичном случае и
/// 2 секунды в одном запросе из двадцати — по среднему это будет выглядеть
/// приемлемо, а пользоваться невозможно. P95/P99 показывают именно это.
///
/// Хранится последние `capacity` значений: точный расчёт по окну дешевле и
/// понятнее приближённых потоковых алгоритмов, а окна в несколько сотен
/// наблюдений достаточно, чтобы старые замеры не тянули статистику назад.
#[derive(Debug, Clone)]
pub struct Percentiles {
    window: std::collections::VecDeque<f64>,
    capacity: usize,
}

impl Percentiles {
    pub fn new(capacity: usize) -> Self {
        Self { window: std::collections::VecDeque::with_capacity(capacity), capacity: capacity.max(1) }
    }

    pub fn push(&mut self, x: f64) {
        if self.window.len() >= self.capacity {
            self.window.pop_front();
        }
        self.window.push_back(x);
    }

    pub fn len(&self) -> usize {
        self.window.len()
    }

    pub fn is_empty(&self) -> bool {
        self.window.is_empty()
    }

    /// Перцентиль `p` в диапазоне 0.0..=1.0 методом ближайшего ранга.
    pub fn percentile(&self, p: f64) -> Option<f64> {
        if self.window.is_empty() {
            return None;
        }
        let mut sorted: Vec<f64> = self.window.iter().copied().collect();
        sorted.sort_by(f64::total_cmp);

        let p = p.clamp(0.0, 1.0);
        let rank = (p * (sorted.len() - 1) as f64).round() as usize;
        sorted.get(rank).copied()
    }

    pub fn p50(&self) -> Option<f64> {
        self.percentile(0.50)
    }

    pub fn p95(&self) -> Option<f64> {
        self.percentile(0.95)
    }

    pub fn p99(&self) -> Option<f64> {
        self.percentile(0.99)
    }
}

impl Default for Percentiles {
    fn default() -> Self {
        Self::new(512)
    }
}

/// Приводит величину к диапазону 0..1 относительно заданных границ.
///
/// Нужна, чтобы складывать несопоставимое: уверенность измеряется в долях,
/// задержка — в миллисекундах, и без общего масштаба веса в функции
/// полезности означали бы разное для разных слагаемых.
///
/// Значения за границами прижимаются к краям: задержка в 10 секунд и в час
/// одинаково плохи, различать их незачем.
pub fn normalize(value: f64, min: f64, max: f64) -> f64 {
    if max <= min {
        return 0.0;
    }
    ((value - min) / (max - min)).clamp(0.0, 1.0)
}

/// z для 95% доверительного интервала (двусторонний).
const Z_95: f64 = 1.96;

/// Нижняя граница доверительного интервала Уилсона для доли успехов.
///
/// В отличие от наивного `successes / attempts`, автоматически штрафует малую
/// выборку — то есть отвечает не на вопрос «какая доля успехов получилась»,
/// а «в какой доле успехов мы уверены»:
///
/// | наблюдения | наивная оценка | Уилсон (нижняя) |
/// |------------|----------------|-----------------|
/// | 1/1        | 1.00           | ~0.21           |
/// | 3/3        | 1.00           | ~0.44           |
/// | 30/30      | 1.00           | ~0.89           |
/// | 9/10       | 0.90           | ~0.60           |
///
/// Благодаря этому стратегия с 3/3 не выигрывает у стратегии с 28/30,
/// хотя наивные оценки у них равны.
pub fn wilson_lower_bound(successes: u32, attempts: u32) -> f64 {
    if attempts == 0 {
        return 0.0;
    }

    let n = attempts as f64;
    let p = successes as f64 / n;
    let z = Z_95;
    let z2 = z * z;

    let denominator = 1.0 + z2 / n;
    let center = p + z2 / (2.0 * n);
    let margin = z * ((p * (1.0 - p) / n) + (z2 / (4.0 * n * n))).sqrt();

    ((center - margin) / denominator).max(0.0)
}

/// Экспоненциальное скользящее среднее: `E_t = α·x_t + (1-α)·E_{t-1}`.
///
/// `alpha` — вес нового значения: чем меньше, тем плавнее и инертнее график.
/// 0.1–0.3 — разумный диапазон для секундных отсчётов.
#[derive(Debug, Clone)]
pub struct Ema {
    alpha: f64,
    value: Option<f64>,
}

impl Ema {
    pub fn new(alpha: f64) -> Self {
        Self { alpha: alpha.clamp(0.0, 1.0), value: None }
    }

    /// Добавляет отсчёт и возвращает сглаженное значение.
    /// Первый отсчёт становится начальным значением как есть — иначе график
    /// пришлось бы «разгонять» от нуля несколько секунд.
    pub fn push(&mut self, x: f64) -> f64 {
        let next = match self.value {
            Some(prev) => self.alpha * x + (1.0 - self.alpha) * prev,
            None => x,
        };
        self.value = Some(next);
        next
    }

}

/// Алгоритм Уэлфорда: среднее и дисперсия одним проходом, без хранения выборки.
///
/// Наивный способ (сумма квадратов минус квадрат суммы) на больших числах
/// теряет точность из-за вычитания близких величин; Уэлфорд от этого свободен.
#[derive(Debug, Clone, Default)]
pub struct Welford {
    count: u64,
    mean: f64,
    m2: f64,
}

impl Welford {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, x: f64) {
        self.count += 1;
        let delta = x - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = x - self.mean;
        self.m2 += delta * delta2;
    }

    /// Выборочная дисперсия (несмещённая). Нужно минимум два наблюдения.
    pub fn variance(&self) -> Option<f64> {
        if self.count < 2 {
            None
        } else {
            Some(self.m2 / (self.count - 1) as f64)
        }
    }

    pub fn stddev(&self) -> Option<f64> {
        self.variance().map(|v| v.sqrt())
    }

    /// Коэффициент вариации σ/μ — безразмерная мера нестабильности,
    /// позволяющая сравнивать разброс у величин разного масштаба.
    pub fn coefficient_of_variation(&self) -> Option<f64> {
        let sd = self.stddev()?;
        if self.mean.abs() < f64::EPSILON {
            None
        } else {
            Some(sd / self.mean)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx(a: f64, b: f64) -> bool {
        (a - b).abs() < 0.01
    }

    #[test]
    fn percentiles_show_the_tail_that_mean_hides() {
        let mut p = Percentiles::new(100);
        // 19 быстрых ответов и один очень медленный
        for _ in 0..19 { p.push(35.0); }
        p.push(2000.0);

        assert_eq!(p.p50(), Some(35.0));
        // Хвост виден в P99, хотя среднее (~133) выглядит терпимо
        assert_eq!(p.p99(), Some(2000.0));
    }

    #[test]
    fn percentiles_window_drops_old_samples() {
        let mut p = Percentiles::new(3);
        for x in [100.0, 200.0, 300.0, 400.0] { p.push(x); }
        assert_eq!(p.len(), 3);
        // 100 вытеснено, минимум теперь 200
        assert_eq!(p.percentile(0.0), Some(200.0));
    }

    #[test]
    fn percentiles_empty_is_none() {
        assert_eq!(Percentiles::new(10).p50(), None);
    }

    #[test]
    fn normalize_maps_range_and_clamps_outliers() {
        assert_eq!(normalize(0.0, 0.0, 100.0), 0.0);
        assert_eq!(normalize(50.0, 0.0, 100.0), 0.5);
        assert_eq!(normalize(100.0, 0.0, 100.0), 1.0);
        // За границами — прижимается, а не уходит в минус или за единицу
        assert_eq!(normalize(-10.0, 0.0, 100.0), 0.0);
        assert_eq!(normalize(1000.0, 0.0, 100.0), 1.0);
        // Вырожденный диапазон не должен делить на ноль
        assert_eq!(normalize(5.0, 3.0, 3.0), 0.0);
    }

    #[test]
    fn wilson_punishes_small_samples() {
        // Наивно обе оценки = 1.0, но уверенность разная
        let few = wilson_lower_bound(3, 3);
        let many = wilson_lower_bound(30, 30);
        assert!(few < many, "3/3 ({few}) должно быть ниже 30/30 ({many})");
        assert!(few < 0.5, "3/3 не должно выглядеть как надёжный результат: {few}");
        assert!(many > 0.85, "30/30 должно быть уверенным: {many}");
    }

    #[test]
    fn wilson_prefers_more_evidence_over_perfect_streak() {
        // Классическая ловушка: 2/2 против 28/30
        assert!(wilson_lower_bound(28, 30) > wilson_lower_bound(2, 2));
    }

    #[test]
    fn wilson_zero_cases() {
        assert_eq!(wilson_lower_bound(0, 0), 0.0);
        assert_eq!(wilson_lower_bound(0, 10), 0.0);
    }

    #[test]
    fn ema_starts_at_first_sample_and_smooths() {
        let mut ema = Ema::new(0.5);
        assert_eq!(ema.push(10.0), 10.0);
        // 0.5*20 + 0.5*10 = 15
        assert!(approx(ema.push(20.0), 15.0));
    }

    #[test]
    fn ema_damps_a_spike() {
        let mut ema = Ema::new(0.2);
        for _ in 0..10 {
            ema.push(100.0);
        }
        let after_spike = ema.push(1000.0);
        assert!(after_spike < 300.0, "всплеск не должен утаскивать среднее: {after_spike}");
    }

    #[test]
    fn welford_matches_known_values() {
        let mut w = Welford::new();
        for x in [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0] {
            w.push(x);
        }
        // выборочная дисперсия этого набора = 4.571…
        assert!(approx(w.variance().unwrap(), 4.5714));
        // CV = σ/μ = 2.138/5 — проверяет и среднее, и разброс разом
        assert!(approx(w.coefficient_of_variation().unwrap(), 0.4276));
    }

    #[test]
    fn welford_needs_two_samples_for_variance() {
        let mut w = Welford::new();
        assert!(w.variance().is_none());
        w.push(1.0);
        assert!(w.variance().is_none());
        w.push(2.0);
        assert!(w.variance().is_some());
    }
}
