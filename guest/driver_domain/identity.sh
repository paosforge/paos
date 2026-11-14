#!/bin/busybox sh
# Read-only admission and sysfs binding, also usable on an offline guest tree.
nd_admission() {
    case $- in *f*) nd_was_noglob=1 ;; *) nd_was_noglob=0 ;; esac
    set -f
    if nd_parse_admission "$1"; then nd_rc=0; else nd_rc=$?; fi
    [ "$nd_was_noglob" -eq 1 ] || set +f
    return "$nd_rc"
}

nd_parse_admission() {
    BDF= PHYSICAL_BDF= START= NONCE=
    nd_seen=

    for token in $1; do
        case "$token" in paos.ndbdf=*|paos.ndphysical=*|paos.ndstart=*|paos.ndnonce=*)
            nd_key=${token%%=*}
            case " $nd_seen " in *" $nd_key "*) return 1 ;; esac
            nd_seen="$nd_seen $nd_key" ;;
        esac
        case "$token" in
            paos.ndbdf=*) [ -z "$BDF" ] || return 1; BDF=${token#*=} ;;
            paos.ndphysical=*) PHYSICAL_BDF=${token#*=} ;;
            paos.ndstart=*) [ -z "$START" ] || return 1; START=${token#*=} ;;
            paos.ndnonce=*) [ -z "$NONCE" ] || return 1; NONCE=${token#*=} ;;
        esac
    done
    printf '%s\n' "$BDF" | /bin/busybox grep -Eq '^0000:[0-9a-f]{2}:[01][0-9a-f]\.[0-7]$' || return 1
    printf '%s\n' "$PHYSICAL_BDF" | /bin/busybox grep -Eq '^0000:[0-9a-f]{2}:[01][0-9a-f]\.[0-7]$' || return 1
    printf '%s\n' "$START" | /bin/busybox grep -Eq '^[1-9][0-9]{0,9}$' || return 1
    printf '%s\n' "$NONCE" | /bin/busybox grep -Eq '^[0-9a-f]{16}$' || return 1
    [ "$NONCE" != 0000000000000000 ] && [ "$START" -le 4294967295 ]
}

nd_interfaces() {
    # Return 0=exact pair, 1=not yet ready, 2=ambiguous/malformed. No IO writes.
    ND_ROOT=$1
    ND_BDF=$2
    PHY= RELAY= PCOUNT=0 RCOUNT=0
    expected=$(/bin/busybox readlink -f "$ND_ROOT/sys/bus/pci/devices/$ND_BDF") || return 1
    [ -n "$expected" ] || return 1
    # Linux virtio_mmio.c vm_cmdline_get publishes actual address -> platform ID.
    # Its sysfs parent is numbered; interface names and probe order are not IDs.
    ND_MMIO_ID= ND_MMIO_COUNT=0
    [ -f "$ND_ROOT/sys/module/virtio_mmio/parameters/device" ] || return 1
    while IFS= read -r entry; do
        case "$entry" in 0x1000@0xd0001000:*|0x1000@0xD0001000:*)
            printf '%s\n' "$entry" | /bin/busybox grep -Eq '^0x1000@0x[dD]0001000:[0-9]+:[0-9]+$' || return 2
            ND_MMIO_ID=${entry##*:}; ND_MMIO_COUNT=$((ND_MMIO_COUNT+1)) ;;
        esac
    done < "$ND_ROOT/sys/module/virtio_mmio/parameters/device"
    [ "$ND_MMIO_COUNT" -le 1 ] || return 2
    [ "$ND_MMIO_COUNT" -eq 1 ] || return 1
    ND_MMIO_PARENT="$ND_ROOT/sys/devices/virtio-mmio-cmdline/virtio-mmio.$ND_MMIO_ID"
    for path in "$ND_ROOT"/sys/class/net/*; do
        [ -e "$path/device" ] || continue
        name=${path##*/}
        case "$name" in ''|*[!a-zA-Z0-9_.-]*) return 2 ;; esac
        device=$(/bin/busybox readlink -f "$path/device") || return 2
        if [ "$device" = "$expected" ]; then
            PHY=$name; PCOUNT=$((PCOUNT+1))
        fi
        if [ "${device%/*}" = "$ND_MMIO_PARENT" ]; then
            leaf=${device##*/}; index=${leaf#virtio}
            [ "$leaf" = "virtio$index" ] || continue
            case "$index" in ''|*[!0-9]*) continue ;; esac
            [ "$(/bin/busybox cat "$path/device/device")" = 0x00000001 ] || continue
            RELAY=$name; RCOUNT=$((RCOUNT+1))
        fi
    done
    [ "$PCOUNT" -le 1 ] && [ "$RCOUNT" -le 1 ] || return 2
    [ "$PCOUNT" -eq 1 ] && [ "$RCOUNT" -eq 1 ] && [ "$PHY" != "$RELAY" ]
}

# Optional signed profile marker: duplicate/malformed values always refuse.
nd_wifi_mode() {
    WIFI=0
    nd_wifi_seen=0
    case $- in *f*) nd_wifi_noglob=1 ;; *) nd_wifi_noglob=0 ;; esac
    set -f
    nd_wifi_bad=0
    for token in $1; do
        case "$token" in paos.wifi=*)
            nd_wifi_seen=$((nd_wifi_seen+1))
            [ "$token" = paos.wifi=1 ] || nd_wifi_bad=1
            WIFI=1 ;;
        esac
    done
    [ "$nd_wifi_noglob" -eq 1 ] || set +f
    [ "$nd_wifi_bad" -eq 0 ] && [ "$nd_wifi_seen" -le 1 ]
}
