#!/usr/bin/env bash
#
# Сборка Android-приложения одной командой.
#
#   ./android/build.sh           — отладочный APK
#   ./android/build.sh install   — собрать и поставить на телефон по USB
#   ./android/build.sh release   — APK для публикации (без отладки)
#
# Что нужно (ставится без sudo, см. android/README.md):
#   ~/Android/Sdk   — SDK с NDK 29, platform-tools, platforms;android-36
#   ~/Android/jdk21 — JDK 21 для Gradle
#   cargo-ndk и rustup target aarch64-linux-android

set -euo pipefail
cd "$(dirname "$0")"

export ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-$(ls -d "$ANDROID_HOME"/ndk/* | sort -V | tail -n1)}"
export JAVA_HOME="${JAVA_HOME_ANDROID:-$HOME/Android/jdk21}"
GRADLE="${GRADLE:-$HOME/Android/gradle-8.14.3/bin/gradle}"

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }

say "Rust-ядро под arm64"
(cd native && cargo ndk -t arm64-v8a -P 26 -o ../app/src/main/jniLibs build --release)

# Файлы данных — те же, что на компьютере, с двумя отличиями. Прозрачного
# режима на телефоне нет (его роль играет VpnService), а DNS отвечает
# virtual DNS внутри tun2proxy, так что свой UDP-релей не нужен.
say "Файлы данных"
ASSETS=app/src/main/assets
mkdir -p "$ASSETS"
cp ../bypass_domains.txt ../block_domains.txt "$ASSETS"/
# Адрес своего воркера для Telegram (см. cloudflare/README.md). Файла нет —
# в сборку он не попадёт, и Telegram пойдёт напрямую. В релиз адрес не кладём
# никогда: APK публичный, и чужой воркер тратил бы лимит вашего аккаунта.
# Пользователь релиза вписывает свой адрес в приложении, кнопка «Telegram».
rm -f "$ASSETS/telegram_relay.txt"
if [[ ${1:-} != release && -f ../telegram_relay.txt ]]; then
    cp ../telegram_relay.txt "$ASSETS"/
fi
sed -E \
    -e 's/^([[:space:]]*transparent_port[[:space:]]*=).*/\1 0/' \
    -e 's/^([[:space:]]*udp_port[[:space:]]*=).*/\1 0/' \
    ../config.toml > "$ASSETS/config.toml"

say "APK"
# Отладочная сборка разрешает `adb shell run-as` — через него читаются файлы
# приложения. В релизе этого нет, поэтому для публикации сборка своя.
if [[ ${1:-} == release ]]; then
    "$GRADLE" -q --console=plain assembleRelease
    APK=app/build/outputs/apk/release/app-release.apk
else
    "$GRADLE" -q --console=plain assembleDebug
    APK=app/build/outputs/apk/debug/app-debug.apk
fi
say "Готово: android/$APK ($(du -h "$APK" | cut -f1))"

if [[ ${1:-} == install ]]; then
    say "Ставлю на телефон"
    "$ANDROID_HOME/platform-tools/adb" install -r "$APK"
    "$ANDROID_HOME/platform-tools/adb" shell am start -n io.github.netsurgeon/.MainActivity
fi
