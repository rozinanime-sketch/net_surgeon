//! Что применять и почему.
//!
//! `diagnostics` измеряет техники на живой сети и выносит вердикт по домену,
//! `strategy` помнит это решение между запусками и отдаёт его прокси.
//! Зависимость односторонняя: strategy читает типы диагностики, обратной
//! ссылки нет.

pub mod diagnostics;
pub mod freeze;
pub mod net_id;
pub mod probe_force;
pub mod strategy;
