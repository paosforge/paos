#!/bin/busybox sh
# Only udhcpc's exact selected physical interface. No eval or public output.
set -eu
set -f
B=/bin/busybox
wifi_ipv4() {
    case "$1" in ''|.*|*.|*..*|*[!0-9.]*) return 1 ;; esac
    old_ifs=$IFS;IFS=.;set -- $1;IFS=$old_ifs
    [ "$#" -eq 4 ] || return 1
    WIFI_IPV4=0
    for octet in "$@"; do
        case "$octet" in ''|0[0-9]*|????*) return 1 ;; esac
        [ "$octet" -le 255 ] || return 1
        WIFI_IPV4=$((WIFI_IPV4*256+octet))
    done
}
wifi_mask() {
    wifi_ipv4 "$1" || return 1
    WIFI_MASK=$WIFI_IPV4
    old_ifs=$IFS;IFS=.;set -- $1;IFS=$old_ifs
    WIFI_PREFIX=0;tail=0
    for octet in "$@"; do
        [ "$tail" -eq 0 ] || [ "$octet" -eq 0 ] || return 1
        case "$octet" in
            255) bits=8 ;; 254) bits=7 ;; 252) bits=6 ;; 248) bits=5 ;;
            240) bits=4 ;; 224) bits=3 ;; 192) bits=2 ;; 128) bits=1 ;; 0) bits=0 ;;
            *) return 1 ;;
        esac
        WIFI_PREFIX=$((WIFI_PREFIX+bits))
        [ "$bits" -eq 8 ] || tail=1
    done
    [ "$WIFI_PREFIX" -gt 0 ]
}
wifi_dhcp_main() {
    expected=$($B cat /run/paos-wpa/interface) || return 1
    case "$expected" in ''|*[!a-zA-Z0-9_.-]*) return 1 ;; esac
    [ "${interface:-}" = "$expected" ] || return 1
    case "${1:-}" in
        deconfig) $B ip addr flush dev "$interface";return ;;
        bound|renew) ;;
        *) return 1 ;;
    esac
    wifi_ipv4 "${ip:-}" || return 1
    address=$WIFI_IPV4
    wifi_mask "${subnet:-}" || return 1
    # The isolated relay must not overlap the selected uplink's subnet.
    [ "$((address&WIFI_MASK))" -ne "$((182910977&WIFI_MASK))" ] || return 1
    gateway= count=0
    for value in ${router:-}; do
        wifi_ipv4 "$value" || return 1
        count=$((count+1));[ "$count" -le 8 ] || return 1
        [ -n "$gateway" ] || gateway=$value
    done
    [ -n "$gateway" ] || return 1
    count=0
    for value in ${dns:-}; do
        wifi_ipv4 "$value" || return 1
        count=$((count+1));[ "$count" -le 8 ] || return 1
    done
    [ "$count" -gt 0 ] || return 1
    $B ip addr replace "$ip/$WIFI_PREFIX" dev "$interface" || return 1
    $B ip route replace default via "$gateway" dev "$interface" || return 1
    : > /etc/resolv.conf || return 1
    for value in $dns; do printf 'nameserver %s\n' "$value" >> /etc/resolv.conf || return 1;done
    printf 'bound\n' > /run/paos-wpa/lease || return 1
}
if [ "${PAOS_WIFI_DHCP_LIBRARY:-0}" != 1 ]; then wifi_dhcp_main "$@";fi
