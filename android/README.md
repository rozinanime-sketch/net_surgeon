# net_surgeon для Android

То же ядро, что на компьютере, но трафик перехватывает `VpnService`:

```
приложения телефона → VpnService (TUN) → tun2proxy → SOCKS5 ядра → интернет
```

Это не настоящий VPN: сервера нет, трафик не уходит с телефона, сайты видят
ваш обычный IP. `VpnService` — единственный способ, которым Android разрешает
обычному приложению перехватывать трафик. Поэтому в строке состояния
появляется значок ключа, и одновременно с другим VPN приложение работать
не может.

DNS обрабатывает virtual DNS внутри tun2proxy: приложения получают выдуманные
адреса из 198.18.0.0/15, а в ядро уходит имя сайта. Ядро резолвит его через
свой DoH, так что оператор не видит DNS-запросов.

## Сборка

Все инструменты ставятся в `~/Android`, без sudo:

```sh
# SDK: https://developer.android.com/studio#command-tools → ~/Android/Sdk/cmdline-tools/latest
~/Android/Sdk/cmdline-tools/latest/bin/sdkmanager \
    "platform-tools" "platforms;android-36" "build-tools;36.1.0" "ndk;29.0.14206865"

# JDK 21 для Gradle → ~/Android/jdk21, Gradle 8.14.3 → ~/Android/gradle-8.14.3

rustup target add aarch64-linux-android
cargo install cargo-ndk
```

Потом из корня проекта:

```sh
./android/build.sh           # собрать APK
./android/build.sh install   # собрать и поставить на телефон по USB
```

Для `install` на телефоне нужно включить «Отладку по USB» в настройках
разработчика.

## Файлы на телефоне

При первом запуске в папку приложения копируются `config.toml`,
`bypass_domains.txt` и `block_domains.txt` из корня проекта, с двумя
отличиями в конфиге: `transparent_port = 0` и `udp_port = 0`. Прозрачный
режим заменяет VpnService, а DNS-релей заменяет virtual DNS.

Списки доменов правятся в приложении. Подобранные техники лежат в
`strategies.txt`, посмотреть их можно так:

```sh
adb shell run-as io.github.netsurgeon cat files/strategies.txt
```

## Проверено

Honor 90, Android 15, мобильный интернет: YouTube (`tls_record`) и Discord
(`oob`) открываются.
