#!/usr/bin/env bash
#
# Настройка прозрачного режима net_surgeon.
#
#   ./setup-transparent.sh on   [порт] [группа]  — включить
#   ./setup-transparent.sh off  [порт] [группа]  — выключить
#   ./setup-transparent.sh status                — состояние
#
# По умолчанию: порт 1083, группа nsproxy.
#
#
# ЗАЧЕМ ОТДЕЛЬНАЯ ГРУППА
#
# Перехват заворачивает исходящие соединения на 443 в локальный прокси.
# Но сам прокси тоже открывает соединения на 443 — и без исключения они
# попадали бы обратно в него же. Бесконечная петля.
#
# Исключать по пользователю нельзя: прокси и браузер работают от одного
# и того же пользователя, и такое исключение выкинуло бы из перехвата
# вообще весь трафик — правило было бы, а толку ноль.
#
# Поэтому прокси запускается в отдельной ГРУППЕ, и исключение делается
# по ней. Всё остальное, что запущено под тем же пользователем, но в его
# обычной группе, перехватывается нормально.

set -euo pipefail

ACTION="${1:-status}"
PORT="${2:-1083}"
GROUP="${3:-nsproxy}"
TABLE="nat"
CHAIN="OUTPUT"

# Шаблоны своих правил. Подстрока (`--to-ports 1083`) совпадала и с чужими:
# 10830, метка 0x10, таблица 1000 — и `off` мог снести правила VPN.
# Подробнее — в run.sh, шаблоны там те же.
MARK=0x1
RT_TABLE=100
NAT_PAT="-j REDIRECT --to-ports ${PORT}( |\$)"
TPROXY_PAT="-j TPROXY --on-port ${PORT}( |\$)"
MARK_PAT="--dport 443 .*-j MARK --set-xmark ${MARK}/0xffffffff( |\$)"
RULE_PAT="fwmark ${MARK} lookup ${RT_TABLE}( |\$)"

have_ip6() {
    command -v ip6tables >/dev/null
}

need_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "Нужны права root:  sudo $0 $*" >&2
        exit 1
    fi
}

ensure_group() {
    if ! getent group "$GROUP" >/dev/null; then
        echo "Группы '$GROUP' нет. Создаю…"
        groupadd --system "$GROUP"
        echo "Создана."
    fi
    GID="$(getent group "$GROUP" | cut -d: -f3)"
}

build_match() {
    MATCH=(
        -p tcp --dport 443
        -m owner ! --gid-owner "$GID"
        -j REDIRECT --to-ports "$PORT"
    )
}

rule_exists() {
    iptables -t "$TABLE" -C "$CHAIN" "${MATCH[@]}" 2>/dev/null
}

# Есть ли ВООБЩЕ правило, заворачивающее трафик на наш порт.
#
# Отдельно от rule_exists, который проверяет точное совпадение условия.
# Правило, добавленное с другим gid (группу пересоздали, номер сменился),
# ломает сеть ровно так же, но точному условию уже не соответствует —
# и потому раньше не находилось ни `off`, ни `status`.
port_rule_present() {
    iptables -t "$TABLE" -S "$CHAIN" 2>/dev/null | grep -qE -- "$NAT_PAT" && return 0
    have_ip6 && ip6tables -t "$TABLE" -S "$CHAIN" 2>/dev/null | grep -qE -- "$NAT_PAT" && return 0
    return 1
}

# Снимает ВСЕ правила, заворачивающие на наш порт.
#
# `iptables -D` удаляет ровно одну копию. Копий бывает несколько: правило
# добавляет и этот скрипт, и run.sh, и повторный `on` после смены gid.
# Оставшейся копии достаточно, чтобы интернет лежал, поэтому здесь
# удаляются все — по спецификациям из `-S`, а не по номерам строк
# (номера сдвигаются после каждого удаления).
sweep_port_rules() {
    local spec tool
    for tool in iptables ip6tables; do
        [[ $tool == ip6tables ]] && ! have_ip6 && continue
        while IFS= read -r spec; do
            [[ -n $spec ]] || continue
            # shellcheck disable=SC2086
            "$tool" -t "$TABLE" -D "$CHAIN" ${spec#-A $CHAIN } 2>/dev/null || true
        done < <("$tool" -t "$TABLE" -S "$CHAIN" 2>/dev/null | grep -E -- "$NAT_PAT" || true)
    done
}

# --- перехват QUIC ---------------------------------------------------------
#
# Ставит его ./run.sh (TPROXY в mangle плюс маршрутная петля через метку),
# но снимать должен уметь и этот скрипт: он — аварийная кнопка, и оставить
# после него висеть маршрутную петлю значит не вернуть сеть. Механика
# описана в комментарии run.sh. MARK и RT_TABLE заданы в начале файла.

udp_rule_present() {
    iptables -t mangle -S PREROUTING 2>/dev/null | grep -qE -- "$TPROXY_PAT" && return 0
    iptables -t mangle -S OUTPUT 2>/dev/null | grep -qE -- "$MARK_PAT" && return 0
    ip rule list 2>/dev/null | grep -qE "$RULE_PAT" && return 0
    return 1
}

sweep_udp_rules() {
    local spec
    while IFS= read -r spec; do
        [[ -n $spec ]] || continue
        # shellcheck disable=SC2086
        iptables -t mangle -D PREROUTING ${spec#-A PREROUTING } 2>/dev/null || true
    done < <(iptables -t mangle -S PREROUTING 2>/dev/null | grep -E -- "$TPROXY_PAT" || true)

    while IFS= read -r spec; do
        [[ -n $spec ]] || continue
        # shellcheck disable=SC2086
        iptables -t mangle -D OUTPUT ${spec#-A OUTPUT } 2>/dev/null || true
    done < <(iptables -t mangle -S OUTPUT 2>/dev/null | grep -E -- "$MARK_PAT" || true)

    local guard=0
    while ip rule list 2>/dev/null | grep -qE "$RULE_PAT"; do
        ip rule del fwmark "$MARK" lookup "$RT_TABLE" 2>/dev/null || break
        guard=$((guard + 1))
        [[ $guard -gt 16 ]] && break
    done

    # Только свой маршрут, а не `flush` всей таблицы: номер таблицы мог занять
    # VPN или другая программа.
    guard=0
    while ip route del local default dev lo table "$RT_TABLE" 2>/dev/null; do
        guard=$((guard + 1))
        [[ $guard -gt 16 ]] && break
    done
    return 0
}

case "$ACTION" in
    on)
        need_root "$@"
        ensure_group
        build_match

        if rule_exists; then
            echo "Правило уже есть."
        else
            iptables -t "$TABLE" -A "$CHAIN" "${MATCH[@]}"
            echo "Перехват включён: TCP/443 -> 127.0.0.1:$PORT"
        fi

        # IPv6 — необязательно, как и в run.sh: прокси слушает [::1]:$PORT.
        if have_ip6; then
            if ip6tables -t "$TABLE" -C "$CHAIN" "${MATCH[@]}" 2>/dev/null; then
                echo "Правило IPv6 уже есть."
            elif ip6tables -t "$TABLE" -A "$CHAIN" "${MATCH[@]}" 2>/dev/null; then
                echo "Перехват включён: TCP/443 по IPv6 -> [::1]:$PORT"
            else
                echo "IPv6 не перехватывается: ip6tables не поддерживает nat на этой системе."
            fi
        fi

        REAL_USER="${SUDO_USER:-$(id -un)}"
        echo
        echo "Теперь запускать прокси НУЖНО в группе '$GROUP' (gid=$GID):"
        echo
        echo "    sg $GROUP -c 'cargo run --release'"
        echo
        echo "Проверить, что процесс действительно в группе:"
        echo "    ps -o pid,user,group,cmd -C net_surgeon"
        echo
        echo "И не забудьте  transparent_port = $PORT  в config.toml."
        echo
        echo "Пользователю $REAL_USER нужно состоять в группе:"
        echo "    sudo usermod -aG $GROUP $REAL_USER   # затем перелогиниться"
        echo
        echo "ВАЖНО: правило переживает выход прокси. Пока оно стоит, а прокси"
        echo "не слушает порт $PORT, весь HTTPS машины уходит в никуда и сеть"
        echo "выглядит сломанной. Снять:  sudo $0 off"
        echo "Скрипт ./run.sh делает это сам при любом завершении — им проще."
        ;;

    off)
        need_root "$@"

        # Наличие группы больше не проверяется: группу могли удалить, а
        # правило осталось — и тогда прежний код отвечал «правила не было»
        # при лежащей сети. Ищем по порту, он в правиле есть всегда.
        if ! port_rule_present && ! udp_rule_present; then
            echo "Правил не было."
            exit 0
        fi

        sweep_port_rules
        sweep_udp_rules

        if port_rule_present || udp_rule_present; then
            echo "Снять правила не удалось. Найдите правила с портом $PORT и удалите по одному (-D):" >&2
            echo "  iptables -t nat -S OUTPUT; iptables -t mangle -S" >&2
            echo "  (не используйте -F: это снесёт и правила Docker/VPN)" >&2
            echo "  ip rule del fwmark $MARK lookup $RT_TABLE" >&2
            exit 1
        fi
        echo "Перехват выключен (TCP и QUIC)."
        ;;

    status)
        if [[ $EUID -ne 0 ]]; then
            echo "Нужен sudo:  sudo $0 status" >&2
            exit 1
        fi
        echo "Цепочка $CHAIN таблицы $TABLE:"
        iptables -t "$TABLE" -L "$CHAIN" -n --line-numbers
        echo
        if port_rule_present; then
            echo "Перехват TCP на $PORT: ВКЛЮЧЁН"
            iptables -t "$TABLE" -S "$CHAIN" | grep -E -- "$NAT_PAT" || true
            have_ip6 && { ip6tables -t "$TABLE" -S "$CHAIN" 2>/dev/null | grep -E -- "$NAT_PAT" | sed 's/^/[IPv6] /' || true; }
        else
            echo "Перехват TCP на $PORT: выключен"
        fi
        if udp_rule_present; then
            echo "Перехват QUIC на $PORT: ВКЛЮЧЁН"
            iptables -t mangle -S PREROUTING 2>/dev/null | grep -E -- "$TPROXY_PAT" || true
            iptables -t mangle -S OUTPUT 2>/dev/null | grep -E -- "$MARK_PAT" || true
            ip rule list 2>/dev/null | grep -E "$RULE_PAT" || true
        else
            echo "Перехват QUIC на $PORT: выключен"
        fi
        ;;

    *)
        echo "Использование: $0 {on|off|status} [порт] [группа]" >&2
        exit 1
        ;;
esac
