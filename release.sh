#!/usr/bin/env bash
#
# Сборка всех файлов релиза одной командой.
#
#   ./release.sh
#
# Собирает Linux (статически, musl), Windows и Android, упаковывает так же,
# как раньше руками, и считает контрольные суммы. Всё кладётся в dist/.
# Публикует не сам: в конце печатает команду для `gh release create`.
#
# Версия берётся из Cargo.toml. Её надо заранее поднять везде, где она
# записана, — скрипт это проверяет и без совпадения не собирает.
#
# Почему не в GitHub Actions: APK подписывается ключом проекта, и в CI его
# пришлось бы отдать в секреты GitHub. Утечка ключа — это чужие «обновления»
# у всех пользователей, а сборка на своей машине занимает пару минут.

set -euo pipefail
cd "$(dirname "$0")"

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m==> %s\033[0m\n' "$*" >&2; exit 1; }

V=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)
[[ -n $V ]] || die "не нашёл version в Cargo.toml"
say "Версия $V"

# Номер версии записан в нескольких местах, и забытое место — самая
# частая ошибка релиза: приложение показывает старую версию или README
# ведёт на прошлый архив.
check_has() {
    grep -qF -- "$2" "$1" || die "в $1 нет «$2» — версия поднята не везде"
}
check_has android/native/Cargo.toml "version = \"$V\""
check_has android/app/build.gradle.kts "versionName = \"$V\""
check_has locales/ru.yml "v$V\""
check_has locales/en.yml "v$V\""
check_has README.md "net_surgeon-$V-x86_64-linux.tar.gz"
check_has README.en.md "net_surgeon-$V-x86_64-linux.tar.gz"

[[ -z $(git status --porcelain --untracked-files=no) ]] \
    || die "есть незакоммиченные изменения: релиз должен собираться из коммита"

# Как в android/build.sh: без этого в бинарь попадают пути /home/<имя>/...
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$HOME=~"

say "Linux (musl)"
cargo build --release --target x86_64-unknown-linux-musl
say "Windows"
cargo build --release --target x86_64-pc-windows-gnu
say "Android"
./android/build.sh release

LINUX_BIN=target/x86_64-unknown-linux-musl/release/net_surgeon
WIN_BIN=target/x86_64-pc-windows-gnu/release/net_surgeon.exe
APK=android/app/build/outputs/apk/release/app-release.apk

# Релиз публичный. Домашний путь выдаёт имя пользователя, адрес своего
# воркера Telegram тратил бы лимит чужого аккаунта Cloudflare.
say "Проверка на личные данные"
RELAY=""
if [[ -f telegram_relay.txt ]]; then
    RELAY=$(grep -v '^[[:space:]]*#' telegram_relay.txt | sed 's#^[a-z]*://##; s#/.*##' | grep -m1 . || true)
fi
for f in "$LINUX_BIN" "$WIN_BIN" "$APK"; do
    if grep -aq "$HOME" "$f"; then die "в $f есть путь $HOME"; fi
    if [[ -n $RELAY ]] && { grep -aqF "$RELAY" "$f" || unzip -p "$f" 2>/dev/null | grep -aqF "$RELAY"; }; then
        die "в $f адрес своего воркера Telegram"
    fi
done
APKSIGNER=$(ls -d "${ANDROID_HOME:-$HOME/Android/Sdk}"/build-tools/* | sort -V | tail -n1)/apksigner
"$APKSIGNER" verify --print-certs "$APK" | grep -q "Android Debug" \
    && die "APK подписан отладочным ключом: обновление у пользователей не встанет"

say "Упаковка"
DIST=dist
rm -rf "$DIST"
mkdir -p "$DIST/linux/net_surgeon-$V/target/release" "$DIST/windows/net_surgeon-$V"

COMMON=(LICENSE README.md config.toml bypass_domains.txt block_domains.txt smart_dns_domains.txt)
cp "${COMMON[@]}" run.sh setup-transparent.sh "$DIST/linux/net_surgeon-$V/"
cp "$LINUX_BIN" "$DIST/linux/net_surgeon-$V/target/release/"
cp "${COMMON[@]}" "$WIN_BIN" "$DIST/windows/net_surgeon-$V/"

tar -C "$DIST/linux" --owner=root --group=root -czf "$DIST/net_surgeon-$V-x86_64-linux.tar.gz" "net_surgeon-$V"
# zip есть не везде, а python3 — почти везде.
(cd "$DIST/windows" && python3 - "net_surgeon-$V" "../net_surgeon-$V-x86_64-windows.zip" <<'EOF'
import os, sys, zipfile
src, out = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for root, _, files in os.walk(src):
        for f in sorted(files):
            z.write(os.path.join(root, f))
EOF
)
cp "$APK" "$DIST/net_surgeon-$V-arm64.apk"
rm -rf "$DIST/linux" "$DIST/windows"

(cd "$DIST" && for f in net_surgeon-*; do sha256sum "$f" > "$f.sha256"; done)

say "Готово:"
ls -lh "$DIST"
cat <<EOF

Дальше:
  git tag v$V && git push origin main v$V
  gh release create v$V --title "net_surgeon $V — …" --notes-file <описание.md> $DIST/net_surgeon-$V-*
EOF
