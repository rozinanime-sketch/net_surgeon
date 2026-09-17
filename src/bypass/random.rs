//! Общие хелперы случайности.
//!
//! Раньше связка `let mut rng = rand::rng(); rng.random_range(min..=max)`
//! дублировалась в fragment.rs (дважды), udp/quic.rs и socks5/udp.rs —
//! каждый раз с ручной защитой (или без неё) от случая min > max.

use rand::prelude::*;

/// Случайное значение в диапазоне [min, max]. Если min >= max, возвращает min —
/// `random_range` паникует на пустом диапазоне, а конфиг правится руками
/// и вполне может содержать frag_min > frag_max.
pub fn in_range(min: u64, max: u64) -> u64 {
    if min >= max {
        return min;
    }
    rand::rng().random_range(min..=max)
}

/// То же для usize (размеры фрагментов, позиции сплита).
pub fn in_range_usize(min: usize, max: usize) -> usize {
    if min >= max {
        return min;
    }
    rand::rng().random_range(min..=max)
}

/// Буфер случайных байт заданной длины (junk-пакеты, DCID, тело fake QUIC Initial).
pub fn bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rand::rng().fill(&mut buf[..]);
    buf
}
