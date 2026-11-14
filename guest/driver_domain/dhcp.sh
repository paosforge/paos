#!/bin/busybox sh
# Shared udhcpc callback: guest bridge by default; explicit bound native NIC.
# PaOS's frames, identity and lease never pass through here. No eval or output.
set -eu
set -f
B=/bin/busybox
nd_ipv4() {
    case "$1" in ''|.*|*.|*..*|*[!0-9.]*) return 1 ;; esac
    old_ifs=$IFS;IFS=.;set -- $1;IFS=$old_ifs
    [ "$#" -eq 4 ] || return 1
    for octet in "$@"; do
        case "$octet" in ''|0[0-9]*|????*) return 1 ;; esac
        [ "$octet" -le 255 ] || return 1
    done
}
nd_mask() {
    nd_ipv4 "$1" || return 1
    old_ifs=$IFS;IFS=.;set -- $1;IFS=$old_ifs
    ND_PREFIX=0;tail=0
    for octet in "$@"; do
        [ "$tail" -eq 0 ] || [ "$octet" -eq 0 ] || return 1
        case "$octet" in
            255) bits=8 ;; 254) bits=7 ;; 252) bits=6 ;; 248) bits=5 ;;
            240) bits=4 ;; 224) bits=3 ;; 192) bits=2 ;; 128) bits=1 ;; 0) bits=0 ;;
            *) return 1 ;;
        esac
        ND_PREFIX=$((ND_PREFIX+bits))
        [ "$bits" -eq 8 ] || tail=1
    done
    [ "$ND_PREFIX" -gt 0 ]
}
nd_dhcp_interface() {
    ND_INTERFACE=paosbr0
    case "$ND_NATIVE" in
        0) [ "${interface:-}" = paosbr0 ] || return 1; return ;;
        1) ;;
        *) return 1 ;;
    esac
    # Only the native entry writes this separate binding. Never source it or
    # accept an arbitrary udhcpc interface just because native mode was set.
    ND_INTERFACE= ND_BDF= ND_SEEN=
    [ -f /run/paos-native-binding ] || return 1
    while IFS='=' read -r key value; do
        case " $ND_SEEN " in *" $key "*) return 1 ;; esac
        ND_SEEN="$ND_SEEN $key"
        case "$key" in
            bdf) ND_BDF=$value ;;
            physical_interface) ND_INTERFACE=$value ;;
            *) return 1 ;;
        esac
    done < /run/paos-native-binding
    printf '%s\n' "$ND_BDF" | $B grep -Eq '^0000:[0-9a-f]{2}:[01][0-9a-f]\.[0-7]$' || return 1
    case "$ND_INTERFACE" in ''|.|..|paosbr0|*[!a-zA-Z0-9_.-]*) return 1 ;; esac
    [ "${#ND_INTERFACE}" -le 15 ] && [ "${interface:-}" = "$ND_INTERFACE" ] || return 1
    [ "/sys/class/net/$ND_INTERFACE/device" -ef "/sys/bus/pci/devices/$ND_BDF" ] || return 1
    ND_CLASS=$($B cat "/sys/bus/pci/devices/$ND_BDF/class") || return 1
    case "$ND_CLASS" in 0x0200??) ;; *) return 1 ;; esac
}
nd_dhcp_main() {
    nd_dhcp_interface || return 1
    case "${1:-}" in
        deconfig) $B ip addr flush dev "$ND_INTERFACE";return ;;
        bound|renew) ;;
        *) return 1 ;;
    esac
    nd_ipv4 "${ip:-}" || return 1
    nd_mask "${subnet:-}" || return 1
    gateway= count=0
    for value in ${router:-}; do
        nd_ipv4 "$value" || return 1
        count=$((count+1));[ "$count" -le 8 ] || return 1
        [ -n "$gateway" ] || gateway=$value
    done
    [ -n "$gateway" ] || return 1
    count=0
    for value in ${dns:-}; do
        nd_ipv4 "$value" || return 1
        count=$((count+1));[ "$count" -le 8 ] || return 1
    done
    [ "$count" -gt 0 ] || return 1
    $B ip addr replace "$ip/$ND_PREFIX" dev "$ND_INTERFACE" || return 1
    $B ip route replace default via "$gateway" dev "$ND_INTERFACE" || return 1
    : > /etc/resolv.conf.paos || return 1
    for value in $dns; do printf 'nameserver %s\n' "$value" >> /etc/resolv.conf.paos || return 1;done
    $B mv -f /etc/resolv.conf.paos /etc/resolv.conf
}
ND_NATIVE=0
if [ "${1:-}" = --native ]; then ND_NATIVE=1; shift; fi
if [ "${PAOS_ND_DHCP_LIBRARY:-0}" != 1 ]; then nd_dhcp_main "$@";fi
