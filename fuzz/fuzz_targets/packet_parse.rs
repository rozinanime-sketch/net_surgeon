//! Разбор и перезапись сырых пакетов (`packet::desync`) + пересчёт сумм
//! (`nfqueue::fixup_v4`).
//!
//! Сюда приходит недоверенный ввод из NFQUEUE/WinDivert. Парсер обязан либо
//! вернуть `None`, либо дать корректные границы: паника в бою — это падение
//! перехвата на первом же кривом пакете.

#![no_main]

use libfuzzer_sys::fuzz_target;
use net_surgeon::packet::desync::{self, Technique};

fuzz_target!(|data: &[u8]| {
    let Some(t) = desync::parse(data) else { return };

    // payload по границам из заголовка не должен выходить за буфер.
    let payload = t.payload(data);
    assert!(payload.len() <= data.len());

    let pos = desync::split_pos(payload);
    let decoy = vec![0x16u8, 0x03, 0x01, 0x00, 0x10, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    for tech in [
        Technique::Pass,
        Technique::Split { pos },
        Technique::Disorder { pos },
        Technique::Fake { pos, decoy: decoy.clone() },
        Technique::Seqovl { pos, overlap: decoy.len(), decoy: decoy.clone() },
    ] {
        // Ни разбор, ни перезапись, ни пересчёт сумм не должны паниковать.
        let mut parts = desync::apply(data, &t, &tech);
        for p in &mut parts {
            net_surgeon::nfqueue::fixup_v4(p);
        }
    }
});
