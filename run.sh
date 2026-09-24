#!/usr/bin/env bash
#
# Запуск net_surgeon одной командой.
#
#   ./run.sh              — прозрачный режим: перехват настраивается сам
#   ./run.sh plain        — обычный режим: только прокси-порты, без iptables
#   ./run.sh --diagnose   — только диагностика, трафик не меняется
#   ./run.sh off          — аварийно снять перехват и вернуть сеть
#   ./run.sh status       — показать, есть ли сейчас правила перехвата
#
# Перехватывается TCP/443 (через nat/REDIRECT), UDP/443 — то есть QUIC —
# через TPROXY, и UDP/53, то есть DNS: запросы уходят встроенному DoH-релею,
# и шифрованный DNS получают все приложения сразу, без настройки в каждом. Второе требует у бинаря CAP_NET_ADMIN; run.sh выдаёт его сам
# после сборки. Если не вышло, QUIC просто пойдёт мимо обхода, а TCP-часть
# продолжит работать.
#
#
# ПОЧЕМУ ЭТО ОДИН СКРИПТ, А НЕ НАБОР КОМАНД
#
# Прозрачный режим требует правила iptables, а правило живёт дольше
# процесса. Если прокси завершился, а правило осталось — весь HTTPS
# машины заворачивается на порт, где никто не слушает, и интернет
# отваливается целиком. Причём выглядит это как поломка сети, а не
# как забытая настройка.
#
#
# КАК ЭТО УСТРОЕНО ТЕПЕРЬ
#
# Если в системе есть nft, правила ставит сама программа — в таблицу
# nftables с флагом owner, которую ядро удаляет вместе с процессом (см.
# src/firewall.rs). Всё описанное ниже про снятие правил относится к
# старому пути через iptables: он остался для систем без nftables и
# включается принудительно через NET_SURGEON_LEGACY=1.
#
#
# ПОЧЕМУ СНЯТИЕ ПРАВИЛА УСТРОЕНО ТАК СЛОЖНО (старый путь)
#
# Одного `trap cleanup EXIT` недостаточно — на практике правило оставалось
# висеть, и сеть падала. Причин было четыре, и закрыты они по отдельности:
#
#   1. Не ловился SIGHUP. Закрытие окна терминала убивает bash сигналом,
#      который не был в списке trap, — а для необработанного сигнала bash
#      выполняет действие по умолчанию (завершиться) и EXIT-обработчик уже
#      НЕ запускает. Теперь HUP и QUIT в списке.
#
#   2. `iptables -D` удаляет ровно ОДНУ копию правила. Если такое же правило
#      уже добавлял `setup-transparent.sh on`, копий было две, и одна
#      оставалась. Теперь удаление идёт в цикле, до последней копии, плюс
#      отдельной «зачисткой» сносится всё, что заворачивает на наш порт,
#      даже если условия правила отличаются (другая группа, другой gid).
#
#   3. Провал удаления молча проглатывался (`2>/dev/null || true`). Если к
#      моменту выхода истёк кэш sudo, правило не снималось, а скрипт всё
#      равно печатал «Готово». Теперь результат ПРОВЕРЯЕТСЯ, и при неудаче
#      выводится громкое предупреждение с командой для ручного снятия.
#
#   4. Ничто не спасало от `kill -9`, падения или обрыва питания: скрипт
#      в этих случаях кода не выполняет вообще. Поэтому поднимается
#      сторож — отдельный процесс от root в своей сессии, который следит
#      за PID скрипта и снимает правило, как только тот исчез.

set -euo pipefail

cd "$(dirname "$0")"

PORT=1083
GROUP=nsproxy
BIN=./target/release/net_surgeon

# --- перехват QUIC (UDP/443) -----------------------------------------------
#
# TCP заворачивается через nat/REDIRECT, а с UDP так нельзя: REDIRECT переписывает
# адрес назначения, и прокси уже не узнает, куда шёл клиент. У TCP это спасает
# conntrack (SO_ORIGINAL_DST), у UDP соединения нет. Поэтому TPROXY — он ничего
# не переписывает, а отдаёт исходный адрес рядом с данными.
#
# Но TPROXY — цель таблицы mangle в цепочке PREROUTING, а наш трафик рождается
# на этой же машине и в PREROUTING не попадает. Обходной путь стандартный:
# в OUTPUT пакет помечается меткой, отдельная таблица маршрутизации объявляет
# всё помеченное локальным и заворачивает на lo, откуда пакет уже проходит
# PREROUTING — и там его подхватывает TPROXY.
#
# Отсюда три сущности вместо одной, и снимать при выходе надо все три:
# правило mangle/PREROUTING, правило mangle/OUTPUT и пару ip rule + ip route.
MARK=0x1
RT_TABLE=100

# --- как узнать СВОИ правила ------------------------------------------------
#
# Раньше правила искались grep по подстроке: `--to-ports 1083` совпадало и
# с 10830, `--set-xmark 0x1` — с 0x10 и 0x1f, `lookup 100` — с `lookup 1000`.
# Снятие перехвата могло удалить правила VPN или другой программы. Шаблоны
# ниже привязаны к концу поля и к форме, в которой `iptables -S` и
# `ip rule` печатают именно наши правила.
NAT_PAT="-j REDIRECT --to-ports ${PORT}( |\$)"
TPROXY_PAT="-j TPROXY --on-port ${PORT}( |\$)"
MARK_PAT="--dport 443 .*-j MARK --set-xmark ${MARK}/0xffffffff( |\$)"
RULE_PAT="fwmark ${MARK} lookup ${RT_TABLE}( |\$)"

# Порт DoH-релея берём из конфига, а не хардкодим: релей может быть выключен
# (udp_port = 0), и тогда заворачивать DNS некуда.
DNS_PORT="$(sed -nE 's/^[[:space:]]*udp_port[[:space:]]*=[[:space:]]*([0-9]+).*/\1/p' config.toml | head -n1)"
DNS_PORT="${DNS_PORT:-0}"
DNS_PAT="--dport 53 .*-j REDIRECT --to-ports ${DNS_PORT}( |\$)"
DOH_PROVIDER="$(sed -nE 's/^[[:space:]]*doh_provider[[:space:]]*=[[:space:]]*"([^"]*)".*/\1/p' config.toml | head -n1)"
DOH_BOOTSTRAP="$(sed -nE 's/^[[:space:]]*doh_bootstrap_ip[[:space:]]*=[[:space:]]*"([^"]*)".*/\1/p' config.toml | head -n1)"

MODE="${1:-transparent}"
RULE_ADDED=0
UDP_ADDED=0
DNS_ADDED=0
CLEANED=0
WATCHDOG_STARTED=0
SUDO_KEEPALIVE=""

# --- вспомогательное -------------------------------------------------------

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m==>\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m==>\033[0m %s\n' "$*" >&2; exit 1; }

# --- операции над правилом перехвата ---------------------------------------

# Заполняет MATCH — точное условие правила. Требует существующей группы.
build_match() {
    GID="$(getent group "$GROUP" | cut -d: -f3)"
    MATCH=(
        -p tcp --dport 443
        -m owner ! --gid-owner "$GID"
        -j REDIRECT --to-ports "$PORT"
    )
}

# Есть ли в nat/OUTPUT хоть одно правило, заворачивающее трафик на наш порт.
# Проверка по порту, а не по полному условию: правило, добавленное с другой
# группой или другим gid, ломает сеть ровно так же, а точному совпадению
# не соответствует.
rule_present() {
    sudo iptables -t nat -S OUTPUT 2>/dev/null | grep -qE -- "$NAT_PAT" && return 0
    have_ip6 && sudo ip6tables -t nat -S OUTPUT 2>/dev/null | grep -qE -- "$NAT_PAT" && return 0
    return 1
}

# Есть ли ip6tables вообще. Без него IPv6 просто не перехватывается.
have_ip6() {
    command -v ip6tables >/dev/null
}

# Снимает ВСЕ правила, заворачивающие на наш порт.
#
# Идём по выводу `-S`, а не по номерам строк: номера сдвигаются после
# каждого удаления, и цикл по ним снёс бы чужие правила. Каждая строка
# `-S` — это готовая спецификация, её достаточно передать в `-D`.
# Разбиение на слова здесь намеренное: спецификация должна стать
# отдельными аргументами iptables.
sweep_rules() {
    local spec tool
    for tool in iptables ip6tables; do
        [[ $tool == ip6tables ]] && ! have_ip6 && continue
        while IFS= read -r spec; do
            [[ -n $spec ]] || continue
            # shellcheck disable=SC2086
            sudo "$tool" -t nat -D OUTPUT ${spec#-A OUTPUT } 2>/dev/null || true
        done < <(sudo "$tool" -t nat -S OUTPUT 2>/dev/null | grep -E -- "$NAT_PAT" || true)
    done

    sweep_udp_rules
    sweep_dns_rules
}

# Заворачивает системный DNS на встроенный DoH-релей.
#
# Зачем: без этого шифрованный DNS надо включать в каждом приложении по
# отдельности (в браузере — своя галочка, у остальных её просто нет).
# Здесь запросы перехватываются у всех сразу и уходят провайдеру по HTTPS.
#
# Только UDP: TCP/53 клиенты используют для ответов, не влезающих в датаграмму,
# а релей слушает UDP. Завернуть TCP было бы хуже, чем не заворачивать, —
# отвечать на той стороне некому, и запрос завис бы до таймаута.
#
# ! -d 127.0.0.0/8 — не трогаем локальные резолверы: systemd-resolved слушает
# 127.0.0.53, и если завернуть обращения к нему, он окажется не у дел вместе
# со своим кэшем, /etc/hosts и настройками отдельных интерфейсов. Наружу он
# ходит уже на настоящий адрес, и вот там правило его и ловит.
enable_dns() {
    sudo iptables -t nat -A OUTPUT -p udp --dport 53 ! -d 127.0.0.0/8 \
        -m owner ! --gid-owner "$GID" -j REDIRECT --to-ports "$DNS_PORT" || return 1
    return 0
}

dns_rule_present() {
    [[ $DNS_PORT -gt 0 ]] || return 1
    sudo iptables -t nat -S OUTPUT 2>/dev/null | grep -qE -- "$DNS_PAT"
}

sweep_dns_rules() {
    [[ $DNS_PORT -gt 0 ]] || return 0
    local spec
    while IFS= read -r spec; do
        [[ -n $spec ]] || continue
        # shellcheck disable=SC2086
        sudo iptables -t nat -D OUTPUT ${spec#-A OUTPUT } 2>/dev/null || true
    done < <(sudo iptables -t nat -S OUTPUT 2>/dev/null | grep -E -- "$DNS_PAT" || true)
    return 0
}

# Есть ли хоть что-то от перехвата QUIC: правило TPROXY, метка в OUTPUT
# или маршрутная пара.
udp_rule_present() {
    sudo iptables -t mangle -S PREROUTING 2>/dev/null | grep -qE -- "$TPROXY_PAT" && return 0
    sudo iptables -t mangle -S OUTPUT 2>/dev/null | grep -qE -- "$MARK_PAT" && return 0
    ip rule list 2>/dev/null | grep -qE "$RULE_PAT" && return 0
    return 1
}

# Снимает ВСЁ, что ставит enable_udp: оба правила mangle и маршрутную пару.
#
# Порядок важен: сначала правила, потом маршрутизация. Если снять сначала
# ip rule, помеченные пакеты на мгновение уйдут в обычную таблицу и уедут
# наружу с чужой меткой — не смертельно, но и незачем.
sweep_udp_rules() {
    local spec
    while IFS= read -r spec; do
        [[ -n $spec ]] || continue
        # shellcheck disable=SC2086
        sudo iptables -t mangle -D PREROUTING ${spec#-A PREROUTING } 2>/dev/null || true
    done < <(sudo iptables -t mangle -S PREROUTING 2>/dev/null | grep -E -- "$TPROXY_PAT" || true)

    while IFS= read -r spec; do
        [[ -n $spec ]] || continue
        # shellcheck disable=SC2086
        sudo iptables -t mangle -D OUTPUT ${spec#-A OUTPUT } 2>/dev/null || true
    done < <(sudo iptables -t mangle -S OUTPUT 2>/dev/null | grep -E -- "$MARK_PAT" || true)

    # ip rule может накопиться в нескольких копиях — удаляем, пока удаляется.
    local guard=0
    while ip rule list 2>/dev/null | grep -qE "$RULE_PAT"; do
        sudo ip rule del fwmark "$MARK" lookup "$RT_TABLE" 2>/dev/null || break
        guard=$((guard + 1))
        [[ $guard -gt 16 ]] && break
    done

    # Только свой маршрут, а не `flush` всей таблицы: номер таблицы мог занять
    # VPN или другая программа, и flush снёс бы её маршруты.
    guard=0
    while sudo ip route del local default dev lo table "$RT_TABLE" 2>/dev/null; do
        guard=$((guard + 1))
        [[ $guard -gt 16 ]] && break
    done
    return 0
}

# Ставит перехват QUIC. Возвращает ненулевой код, если что-то не вышло —
# тогда вызывающий откатывает уже сделанное и работает без QUIC.
enable_udp() {
    sudo ip rule add fwmark "$MARK" lookup "$RT_TABLE" || return 1
    sudo ip route add local default dev lo table "$RT_TABLE" || return 1

    # -i lo: ловим только то, что вернулось через маршрутную петлю, то есть
    # свой же трафик. Без этого правило цепляло бы и транзитный UDP/443,
    # если машина когда-нибудь станет маршрутизатором.
    sudo iptables -t mangle -A PREROUTING -i lo -p udp --dport 443 \
        -j TPROXY --on-port "$PORT" --tproxy-mark "$MARK" || return 1

    sudo iptables -t mangle -A OUTPUT -p udp --dport 443 \
        -m owner ! --gid-owner "$GID" -j MARK --set-mark "$MARK" || return 1

    return 0
}

# --- проверка VPN ------------------------------------------------------------
#
# Когда включён VPN, провайдерский DPI трафик не видит: обход ничего не даёт,
# а диагностика мерит путь через VPN и записывает в strategies.txt стратегии,
# которые без VPN не работают. Хуже того, техники на низком TTL и OOB
# упираются в tun2socks и дальше не идут. tools/discord-check.sh об этом
# предупреждал, а run.sh — нет.
#
# NET_SURGEON_IGNORE_VPN=1 отключает проверку (например, VPN с раздельным
# туннелированием, где эти адреса идут мимо него).
vpn_route_dev() {
    local ip dev
    # Адрес Discord и адрес Cloudflare: заблокированный и заведомо открытый.
    for ip in 162.159.135.232 1.1.1.1; do
        dev="$(ip route get "$ip" 2>/dev/null | grep -oP 'dev \K\S+' | head -n1)"
        case "$dev" in
            tun*|tap*|wg*|amn*|ppp*|nekoray*|sing*|throne*|utun*)
                printf '%s\n' "$dev"
                return 0
                ;;
        esac
    done
    return 1
}

check_vpn() {
    [[ ${NET_SURGEON_IGNORE_VPN:-0} == 1 ]] && return 0

    local dev answer
    dev="$(vpn_route_dev)" || return 0

    warn "Трафик идёт через интерфейс $dev — похоже, включён VPN."
    warn "Провайдер этот трафик не видит: обход бесполезен, а диагностика"
    warn "запишет в strategies.txt стратегии, измеренные через VPN."

    if [[ -t 0 ]]; then
        read -r -p "Всё равно продолжить? [y/N] " answer
        [[ $answer == [yYдД]* ]] || die "Остановлено. Выключите VPN и запустите снова."
    else
        warn "Терминала нет, спросить некого — продолжаю. Отключить проверку: NET_SURGEON_IGNORE_VPN=1"
    fi
}

# --- снятие правила при ЛЮБОМ выходе ---------------------------------------

# Сторож здесь не убивается намеренно. `setsid --fork` отвязывает его от нас,
# и его PID мы не знаем: нам вернулся номер уже завершившегося посредника,
# а `kill` по такому номеру рискует попасть в чужой процесс, успевший его
# занять. Сторож и так уходит сам, увидев, что наш PID исчез, — и его
# повторная зачистка после штатного выхода просто ничего не находит.
stop_helpers() {
    [[ -n $SUDO_KEEPALIVE ]] && kill "$SUDO_KEEPALIVE" 2>/dev/null || true
    return 0
}

cleanup() {
    # По сигналу срабатывают оба обработчика — например INT и EXIT.
    # Флаг снимается первым же вызовом, чтобы второй ничего не делал.
    [[ $CLEANED -eq 1 ]] && return 0
    CLEANED=1

    if [[ $RULE_ADDED -eq 1 || $UDP_ADDED -eq 1 || $DNS_ADDED -eq 1 ]]; then
        echo
        say "Снимаю перехват…"

        # Без прав root ни снять правила, ни даже прочитать их нельзя: grep
        # по пустому выводу `sudo iptables -S` ничего не находил, и скрипт
        # объявлял «Готово», хотя перехват оставался. Так бывает, когда кэш
        # sudo истёк или терминал уже закрыт и пароль спросить негде.
        if ! sudo -n true 2>/dev/null && ! { [[ -t 0 ]] && sudo -v; }; then
            warn "Нет прав sudo — снять перехват отсюда не получилось."
            if [[ $WATCHDOG_STARTED -eq 1 ]]; then
                warn "Его снимет сторож в течение пары секунд после выхода."
            fi
            warn "Проверить:  ./run.sh status     Снять вручную:  ./run.sh off"
            warn "Если sudo недоступен совсем — перезагрузитесь: правила не переживают перезагрузку."
            stop_helpers
            return 0
        fi

        sweep_rules

        # Проверяем результат, а не надеемся на него: без проверки скрипт
        # печатал «Готово» даже тогда, когда правило осталось на месте,
        # и причину падения сети приходилось искать вручную.
        if rule_present || udp_rule_present || dns_rule_present; then
            warn "НЕ УДАЛОСЬ снять перехват — интернет останется сломанным."
            warn "Снимите вручную:  ./run.sh off"
            warn "в крайнем случае найдите правила с портом $PORT и удалите их по одному (-D):"
            warn "                  sudo iptables -t nat -S OUTPUT; sudo iptables -t mangle -S"
            warn "                  sudo ip rule del fwmark $MARK lookup $RT_TABLE"
        else
            say "Готово, сеть в обычном режиме."
        fi
    fi

    stop_helpers
}
trap cleanup EXIT INT TERM HUP QUIT

# --- сборка ----------------------------------------------------------------

build() {
    # Время изменения каталога src меняется только при добавлении и удалении
    # файлов, но не при правке — поэтому сравниваем с самими исходниками.
    local stale=0
    if [[ ! -x $BIN ]]; then
        stale=1
    elif find src Cargo.toml -newer "$BIN" -print -quit 2>/dev/null | grep -q .; then
        stale=1
    fi

    if [[ $stale -eq 1 ]]; then
        say "Собираю…"
        cargo build --release
    fi
}

# --- аварийное снятие и статус ---------------------------------------------
#
# Отдельные команды нужны как раз для случая, когда правило уже осталось
# висеть: лезть за ним в iptables руками в момент, когда сеть не работает,
# — худший момент для изучения синтаксиса.

if [[ $MODE == off || $MODE == --off ]]; then
    # Перехват нового образца (nftables, owner) живёт ровно столько, сколько
    # процесс: остановить его — и ядро снимет таблицу само, без root.
    if pgrep -x net_surgeon >/dev/null; then
        say "Останавливаю net_surgeon — перехват снимется вместе с ним."
        pkill -x net_surgeon || true
        sleep 1
        pgrep -x net_surgeon >/dev/null && pkill -9 -x net_surgeon
    fi
    say "Нужны права root, чтобы снять перехват."
    sudo -v || die "Без sudo правило не снять."
    sweep_rules
    if command -v nft >/dev/null && sudo nft list table inet net_surgeon >/dev/null 2>&1; then
        die "Таблица nftables net_surgeon осталась — значит, её держит живой процесс. Найдите его: ps -ef | grep net_surgeon"
    fi
    if rule_present || udp_rule_present || dns_rule_present; then
        die "Снять не удалось. Найдите правила с портом $PORT (sudo iptables -t nat -S OUTPUT; sudo iptables -t mangle -S) и удалите их по одному через -D. Не используйте -F: это снесёт и правила Docker/VPN."
    fi
    say "Перехват снят (TCP, QUIC и DNS), сеть в обычном режиме."
    exit 0
fi

if [[ $MODE == status || $MODE == --status ]]; then
    sudo -v || die "Нужны права root, чтобы прочитать таблицу nat."
    if command -v nft >/dev/null && sudo nft list table inet net_surgeon >/dev/null 2>&1; then
        warn "Перехват ВКЛЮЧЁН (nftables, снимется вместе с процессом net_surgeon):"
        sudo nft list table inet net_surgeon | grep -E "redirect|tproxy" | sed 's/^[[:space:]]*/  /'
        exit 0
    fi
    if rule_present || udp_rule_present || dns_rule_present; then
        warn "Перехват на порт $PORT ВКЛЮЧЁН. Действующие правила:"
        sudo iptables -t nat -S OUTPUT 2>/dev/null | grep -E -- "$NAT_PAT" || true
        have_ip6 && { sudo ip6tables -t nat -S OUTPUT 2>/dev/null | grep -E -- "$NAT_PAT" | sed 's/^/[IPv6] /' || true; }
        sudo iptables -t mangle -S PREROUTING 2>/dev/null | grep -E -- "$TPROXY_PAT" || true
        sudo iptables -t mangle -S OUTPUT 2>/dev/null | grep -E -- "$MARK_PAT" || true
        ip rule list 2>/dev/null | grep -E "$RULE_PAT" || true
        sudo iptables -t nat -S OUTPUT 2>/dev/null | grep -E -- "$DNS_PAT" || true
    else
        say "Перехвата нет, сеть в обычном режиме."
    fi
    exit 0
fi

# --- обычный режим ---------------------------------------------------------

if [[ $MODE == plain ]]; then
    check_vpn
    build
    say "Обычный режим: прокси на портах из config.toml, перехвата нет."
    exec "$BIN"
fi

if [[ $MODE == --diagnose || $MODE == diagnose ]]; then
    check_vpn
    build
    say "Только диагностика: трафик не изменяется."
    exec "$BIN" --diagnose-only
fi

# --- прозрачный режим ------------------------------------------------------

check_vpn
build

# --- новый путь: правила ставит сама программа -----------------------------
#
# Таблица nftables с флагом owner принадлежит процессу и исчезает вместе с
# ним, как бы он ни завершился (src/firewall.rs). Снимать при выходе нечего,
# поэтому sudo нужен только один раз после сборки — выдать бинарю права:
#
#   группа nsproxy + setgid  — прокси сразу стартует в своей группе, и его
#                              трафик не попадает обратно в перехват;
#   cap_net_admin            — ставить правила и маршруты;
#   cap_net_bind_service     — обратный сокет QUIC привязывается к порту 443.
#
# Пересборка заменяет файл, и всё это с него слетает — тогда спросим снова.
# Без nft (или с NET_SURGEON_LEGACY=1) — старый путь через iptables ниже.
ensure_config_port() {
    # Порт в конфиге — правим сами, чтобы не заставлять лезть в редактор.
    # Но config.toml принадлежит пользователю, поэтому: трогаем его только
    # когда значение действительно другое, и вслух говорим, что поменяли.
    if grep -qE '^[[:space:]]*transparent_port[[:space:]]*=' config.toml; then
        CURRENT_PORT="$(sed -nE 's/^[[:space:]]*transparent_port[[:space:]]*=[[:space:]]*([^#[:space:]]*).*/\1/p' config.toml | head -n1)"
        if [[ $CURRENT_PORT != "$PORT" ]]; then
            sed -i -E "s/^([[:space:]]*transparent_port[[:space:]]*=).*/\1 $PORT/" config.toml
            warn "В config.toml изменён transparent_port: ${CURRENT_PORT:-пусто} -> $PORT"
        fi
    else
        printf '\ntransparent_port = %s\n' "$PORT" >> config.toml
        warn "В config.toml добавлена строка transparent_port = $PORT"
    fi
}

bin_privileged() {
    [[ $(stat -c %G "$BIN" 2>/dev/null) == "$GROUP" ]] || return 1
    [[ -g $BIN ]] || return 1
    getcap "$BIN" 2>/dev/null | grep -q cap_net_admin || return 1
}

if command -v nft >/dev/null && command -v getcap >/dev/null && [[ -z ${NET_SURGEON_LEGACY:-} ]]; then
    ensure_config_port

    if ! bin_privileged; then
        say "Выдаю программе права на перехват (один раз после сборки, нужен sudo)."
        sudo -v || die "Без sudo прозрачный режим не настроить. Попробуйте: ./run.sh plain"
        getent group "$GROUP" >/dev/null || sudo groupadd --system "$GROUP"
        # Порядок важен: chgrp сбрасывает и бит setgid, и полномочия файла.
        sudo chgrp "$GROUP" "$BIN"
        sudo chmod 2755 "$BIN"
        sudo setcap cap_net_admin,cap_net_bind_service+ep "$BIN"
        bin_privileged || die "Права выдать не удалось. Каталог на разделе с nosuid? Тогда: NET_SURGEON_LEGACY=1 ./run.sh"
    fi

    say "Запуск. Перехват снимется сам при любом выходе, даже при закрытии окна."
    "$BIN" --firewall || true
    exit 0
fi

# --- старый путь: iptables через sudo --------------------------------------

# Права понадобятся дважды: поставить правило и снять. Спрашиваем один раз
# и держим sudo «тёплым», чтобы при выходе не появился запрос пароля
# в самый неподходящий момент.
say "Нужны права root, чтобы настроить перехват."
sudo -v || die "Без sudo прозрачный режим не настроить. Попробуйте: ./run.sh plain"

while true; do sudo -n true; sleep 50; kill -0 "$$" 2>/dev/null || exit; done 2>/dev/null &
SUDO_KEEPALIVE=$!

# Отдельная группа нужна, чтобы исходящие соединения самого прокси не
# попадали обратно в перехват. По пользователю разделить нельзя: прокси
# и браузер работают под одним и тем же, и такое исключение выкинуло бы
# из перехвата вообще весь трафик.
if ! getent group "$GROUP" >/dev/null; then
    say "Создаю группу $GROUP…"
    sudo groupadd --system "$GROUP"
fi
build_match

ensure_config_port

# Правила с прошлого запуска (или от `setup-transparent.sh on`) могли
# остаться. Сносим ВСЕ, а не одно: иначе добавленное сейчас станет вторым
# по счёту, а при выходе снимется только одно — и одна копия переживёт
# завершение прокси, чего достаточно, чтобы сеть легла.
sweep_rules

say "Включаю перехват: TCP/443 -> 127.0.0.1:$PORT"
sudo iptables -t nat -A OUTPUT "${MATCH[@]}"
RULE_ADDED=1

# IPv6: без этого правила всё, что открывается по IPv6, шло мимо обхода.
# REDIRECT здесь заворачивает на [::1], где прокси поднимает второй
# слушатель. Необязательно: без ip6tables или без IPv6 nat в ядре
# работаем как раньше, только по IPv4.
if have_ip6 && sudo ip6tables -t nat -A OUTPUT "${MATCH[@]}" 2>/dev/null; then
    say "Включаю перехват: TCP/443 по IPv6 -> [::1]:$PORT"
else
    warn "IPv6 не перехватывается (нет ip6tables или nat для IPv6) — только IPv4."
fi

# Перехват QUIC. Ставится ПОСЛЕ TCP и не обязателен: если ядро собрано без
# модуля TPROXY или без поддержки нужной цели, откатываем добавленное
# и работаем как раньше — по TCP. Ронять весь режим из-за этого незачем.
say "Включаю перехват QUIC: UDP/443 -> 127.0.0.1:$PORT"
if enable_udp; then
    UDP_ADDED=1

    # IP_TRANSPARENT требует CAP_NET_ADMIN у самого процесса. Полномочие
    # висит на файле и слетает при каждой пересборке, поэтому проставляем
    # его здесь, а не разово руками.
    #
    # cap_net_bind_service нужен обратному сокету: он привязывается к адресу
    # СЕРВЕРА, то есть к порту 443, а порты ниже 1024 без этого полномочия
    # закрыты. Без него каждый QUIC-поток падал с Permission denied, и
    # приложения на QUIC (Discord, браузер) висели до отката на TCP.
    if sudo setcap cap_net_admin,cap_net_bind_service+ep "$BIN" 2>/dev/null; then
        say "Выдал бинарю cap_net_admin и cap_net_bind_service (нужны для TPROXY)."
    else
        warn "Не удалось выдать полномочия — QUIC пойдёт мимо обхода."
        warn "Вручную: sudo setcap cap_net_admin,cap_net_bind_service+ep $BIN"
    fi
else
    warn "TPROXY недоступен (нет модуля ядра xt_TPROXY?) — QUIC пойдёт мимо обхода."
    sweep_udp_rules
fi

# Перехват DNS. Включается сам, если релей не выключен в конфиге: тогда
# шифрованный DNS получают все приложения разом, без настройки в каждом.
#
# Неудача здесь не повод ронять режим: без правила DNS просто идёт как шёл,
# провайдеру видно, какие домены вы спрашиваете, но TCP- и QUIC-обход
# работают по-прежнему.
if [[ $DNS_PORT -gt 0 ]]; then
    say "Включаю перехват DNS: UDP/53 -> 127.0.0.1:$DNS_PORT (провайдер: $DOH_PROVIDER)"
    if enable_dns; then
        DNS_ADDED=1
        if [[ -z $DOH_BOOTSTRAP ]]; then
            warn "В config.toml не задан doh_bootstrap_ip — релей не сможет узнать"
            warn "адрес самого провайдера, потому что спросит об этом сам себя."
            warn "Добавьте строку вида:  doh_bootstrap_ip = \"1.2.3.4\""
        fi
    else
        warn "Не вышло завернуть DNS — запросы пойдут напрямую, как раньше."
    fi
else
    say "Перехват DNS выключен: в config.toml udp_port = 0."
fi

# Сторож на случай, когда скрипт не выполнит уже ничего: kill -9, OOM,
# падение ядра. Он живёт от root в СВОЕЙ сессии (setsid), поэтому его не
# заденет ни закрытие терминала, ни убийство группы процессов, и снимает
# правила, как только PID скрипта исчезает.
#
# Снимает ОБА перехвата: с появлением QUIC осталось бы висеть правило
# mangle с маршрутной петлёй, а это ломает сеть не хуже забытого REDIRECT.
sudo setsid --fork bash -c '
    parent=$1
    port=$2
    mark=$3
    table=$4
    dns_port=$5
    while kill -0 "$parent" 2>/dev/null; do sleep 2; done

    # Шаблоны те же, что NAT_PAT и остальные выше: только свои правила.
    for tool in iptables ip6tables; do
        command -v "$tool" >/dev/null || continue
        "$tool" -t nat -S OUTPUT 2>/dev/null | grep -E -- "-j REDIRECT --to-ports $port( |\$)" | while read -r spec; do
            "$tool" -t nat -D OUTPUT ${spec#-A OUTPUT } 2>/dev/null || true
        done
    done
    iptables -t mangle -S PREROUTING 2>/dev/null | grep -E -- "-j TPROXY --on-port $port( |\$)" | while read -r spec; do
        iptables -t mangle -D PREROUTING ${spec#-A PREROUTING } 2>/dev/null || true
    done
    iptables -t mangle -S OUTPUT 2>/dev/null | grep -E -- "--dport 443 .*-j MARK --set-xmark $mark/0xffffffff( |\$)" | while read -r spec; do
        iptables -t mangle -D OUTPUT ${spec#-A OUTPUT } 2>/dev/null || true
    done
    guard=0
    while ip rule list 2>/dev/null | grep -qE "fwmark $mark lookup $table( |\$)"; do
        ip rule del fwmark "$mark" lookup "$table" 2>/dev/null || break
        guard=$((guard + 1))
        [ "$guard" -gt 16 ] && break
    done
    guard=0
    while ip route del local default dev lo table "$table" 2>/dev/null; do
        guard=$((guard + 1))
        [ "$guard" -gt 16 ] && break
    done

    [ "$dns_port" -gt 0 ] 2>/dev/null && iptables -t nat -S OUTPUT 2>/dev/null |
        grep -E -- "--dport 53 .*-j REDIRECT --to-ports $dns_port( |\$)" |
        while read -r spec; do
            iptables -t nat -D OUTPUT ${spec#-A OUTPUT } 2>/dev/null || true
        done
' _ "$$" "$PORT" "$MARK" "$RT_TABLE" "$DNS_PORT" >/dev/null 2>&1 && WATCHDOG_STARTED=1

# Раньше провал здесь проглатывался молча, и о том, что страховки от
# kill -9 и закрытия окна нет, никто не узнавал.
if [[ $WATCHDOG_STARTED -ne 1 ]]; then
    warn "Не удалось запустить сторожа (нет setsid?). Перехват снимется при"
    warn "обычном выходе, но не при kill -9 или падении — тогда ./run.sh off."
fi

say "Готово. Приложения настраивать не нужно."
warn "При выходе перехват снимется автоматически — в том числе если окно закрыть."
warn "Если сеть всё-таки осталась сломанной:  ./run.sh off"
echo

# Запуск с эффективной группой $GROUP.
#
# Привилегии тут не нужны — нужна только смена группы, по которой iptables
# отличает трафик прокси от всего остального. Но способы её сменить
# по-разному доступны:
#
#   setpriv  — из util-linux, есть почти везде. sudo запускает его от root
#              (это разрешено обычным правилом sudoers), а он сбрасывает
#              права до нужных uid и gid;
#   sg       — из пакета shadow, ставится не всегда;
#   sudo -g  — требует в sudoers правила вида (ALL:ALL), а по умолчанию
#              обычно стоит (ALL), которое смену группы не разрешает.
#
# Поэтому пробуем по очереди, а не полагаемся на что-то одно.
#
# `|| true` нужен, чтобы падение прокси не обрывало скрипт по `set -e`
# ДО снятия правила: выйти с ошибкой, оставив сеть сломанной, — худший
# из возможных исходов.
MY_UID="$(id -u)"

if command -v setpriv >/dev/null; then
    say "Запуск через setpriv (uid=$MY_UID, gid=$GID)"
    sudo setpriv --reuid="$MY_UID" --regid="$GID" --clear-groups "$BIN" || true
elif command -v sg >/dev/null && id -nG | tr ' ' '\n' | grep -qx "$GROUP"; then
    # sg без пароля группы работает только для её участников — иначе он
    # спросит пароль и не запустит прокси.
    say "Запуск через sg"
    sg "$GROUP" -c "$BIN" || true
else
    say "Запуск через sudo -g"
    sudo -u "$(id -un)" -g "$GROUP" "$BIN" || true
fi
