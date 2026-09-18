#!/usr/bin/env bash
#
# Те же проверки, что и в CI, но локально и до отправки.
#
#   ./check.sh          — clippy, тесты, тесты без интерфейса
#   ./check.sh 120      — то же плюс фаззинг, по 120 секунд на цель
#
# CI полезен тем, что не забывает; этот скрипт полезен тем, что не надо
# ждать CI, чтобы узнать про опечатку.

set -euo pipefail
cd "$(dirname "$0")"

FUZZ_SECONDS="${1:-0}"

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m==>\033[0m %s\n' "$*"; }

say "clippy (любое предупреждение — ошибка)"
cargo clippy --all-targets --all-features -- -D warnings

say "тесты"
cargo test --all-features

say "сборка и тесты без интерфейса (сервер, Android)"
cargo test --no-default-features

if [[ $FUZZ_SECONDS -eq 0 ]]; then
    say "Готово. Для фаззинга: ./check.sh 60"
    exit 0
fi

# Фаззеру нужен nightly: libFuzzer есть только там. Сам проект при этом
# остаётся на stable — цели лежат отдельным крейтом в fuzz/.
if ! rustup toolchain list 2>/dev/null | grep -q '^nightly'; then
    warn "Нет nightly — фаззинг пропущен.  rustup toolchain install nightly"
    exit 0
fi
if ! cargo +nightly fuzz --version >/dev/null 2>&1; then
    warn "Нет cargo-fuzz — фаззинг пропущен.  cargo install cargo-fuzz --locked"
    exit 0
fi

for target in $(cargo +nightly fuzz list); do
    say "фаззинг: $target (${FUZZ_SECONDS} с)"
    cargo +nightly fuzz run "$target" -- \
        -max_total_time="$FUZZ_SECONDS" \
        -max_len=4096 \
        -print_final_stats=1
done

say "Готово. Накопленный корпус лежит в fuzz/corpus — со следующего раза"
say "фаззер стартует не с нуля, а с него."
