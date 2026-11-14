#!/bin/busybox sh
# Finite actual guest observations. Optional ROOT is offline-fixture-only;
# the sole admitted Terminal command supplies a challenge and no ROOT.
set -eu
B=/bin/busybox
N=${1:-}; R=${2:-}
[ "$#" -ge 1 ] && [ "$#" -le 2 ] || exit 1
printf '%s\n' "$N" | $B grep -Eq '^[0-9a-f]{16}$' || exit 1
[ "$N" != 0000000000000000 ] || exit 1
case "$R" in ''|/*) ;; *) exit 1 ;; esac
small() {
    v=$($B head -c 241 "$1") || return 1
    [ "${#v}" -le 240 ] || return 1
    printf '%s' "$v"
}
token() { case "$1" in ''|*[!a-zA-Z0-9_:./+-]*) return 1 ;; esac; [ "${#1}" -le 80 ]; }
START= NONCE= BDF= PHYSICAL= PHY= RELAY= SEEN=
binding=$(small "$R/run/paos-driver-binding")
while IFS='=' read -r key value; do
    token "$value" || exit 1
    case " $SEEN " in *" $key "*) exit 1 ;; esac
    SEEN="$SEEN $key"
    case "$key" in start) START=$value ;; nonce) NONCE=$value ;; bdf) BDF=$value ;;
      physical_bdf) PHYSICAL=$value ;; physical_interface) PHY=$value ;; relay) RELAY=$value ;; *) exit 1 ;; esac
done <<EOF
$binding
EOF
[ -n "$START" ] && [ -n "$NONCE" ] && [ -n "$BDF" ] && [ -n "$PHYSICAL" ] && [ -n "$PHY" ] && [ -n "$RELAY" ] || exit 1
case "$PHY" in ''|.|..|*[!a-zA-Z0-9_.-]*) exit 1 ;; esac
[ "${#PHY}" -le 15 ] || exit 1
boot=$(small "$R/proc/sys/kernel/random/boot_id"); token "$boot" || exit 1
printf 'GI1 %s %s %s %s %s %s\n' "$N" "$START" "$NONCE" "$BDF" "$PHYSICAL" "$boot"
field() { printf 'GIF1 %s %s %s\n' "$N" "$1" "$2"; }
missing() { printf 'GIM1 %s %s\n' "$N" "$1"; }
text() {
    if [ -r "$2" ] && v=$(small "$2") && token "$v"; then field "$1" "$v"; else missing "$1"; fi
}
hash() {
    # Fixed software/firmware files only; finite extent, no recursive host/tree hash.
    if [ -f "$2" ] && [ -r "$2" ] && [ "$($B stat -L -c %s "$2")" -le 8388608 ]; then
        sha=$($B sha256sum "$2"); field "$1" "${sha%% *}"
    else missing "$1"; fi
}
text release "$R/proc/sys/kernel/osrelease"
hash config "$R/etc/paos/driver-kernel.config"
hash busybox "$R/bin/busybox"
p="$R/sys/bus/pci/devices/$BDF"
assigned_pci="$p"
if vendor=$(small "$p/vendor") && device=$(small "$p/device") && class=$(small "$p/class") && token "$vendor:$device:$class"; then
    field pci "$vendor:$device:$class"
else missing pci; fi
# The fixed assigned PCI function supplies driver authority; a loaded module
# or the virtio relay is never a substitute. Keep unavailable facts explicit.
driver_target=
if [ -L "$p/driver" ] && driver_target=$($B readlink -f "$p/driver"); then
    case "$driver_target" in "$R/sys/bus/pci/drivers/"*)
        driver=${driver_target##*/}
        case "$driver" in ''|*[!a-zA-Z0-9_.+-]*) missing driver ;;
          *) if [ "${#driver}" -le 80 ] && [ "$driver_target" = "$R/sys/bus/pci/drivers/$driver" ] && [ -d "$driver_target" ]; then field driver "$driver"; else missing driver; fi ;;
        esac ;;
      *) missing driver ;;
    esac
else missing driver; fi
net="$R/sys/class/net/$PHY"
net_mapped=0
if [ -L "$net/device" ] && [ "$net/device" -ef "$p" ]; then
    net_mapped=1
    field netif "$PHY"
    if state=$(small "$net/operstate"); then
        case "$state" in unknown|notpresent|down|lowerlayerdown|testing|dormant|up) field operstate "$state" ;; *) missing operstate ;; esac
    else missing operstate; fi
    if carrier=$(small "$net/carrier"); then
        case "$carrier" in 0|1) field carrier "$carrier" ;; *) missing carrier ;; esac
    else missing carrier; fi
else missing netif; missing operstate; missing carrier; fi
if [ -d "$R/sys/bus/pci" ] && [ -d "$R/sys/bus/virtio" ]; then field buses pci,virtio; else missing buses; fi
count=0
for p in "$R/sys/bus/virtio/devices"/virtio*; do
    [ -d "$p" ] || continue
    count=$((count+1)); [ "$count" -le 4 ] || exit 1
    name=${p##*/}; token "$name" || exit 1
    device=$(small "$p/device"); vendor=$(small "$p/vendor")
    token "$device" && token "$vendor" || exit 1
    printf 'GIV1 %s %s %s %s\n' "$N" "$name" "$device" "$vendor"
done
[ "$count" -gt 0 ] || missing virtio
# Linux publishes each actual command-line MMIO platform ID here, the same
# interface used by identity.sh to locate the relay. Do not infer parent IDs
# from enumeration order or a repeated virtio console device ID.
platform() {
    params="$R/sys/module/virtio_mmio/parameters/device"
    if [ ! -r "$params" ]; then printf 'GIPM1 %s mmio\n' "$N"; return; fi
    if ! entries=$($B head -c 241 "$params"); then printf 'GIPM1 %s mmio\n' "$N"; return; fi
    if [ "${#entries}" -gt 240 ]; then printf 'GIPERR1 %s bound\n' "$N"; return; fi
    mappings=0; incomplete=0; identities=
    while IFS= read -r entry; do
        [ -n "$entry" ] || continue
        mappings=$((mappings+1))
        if [ "$mappings" -gt 4 ]; then printf 'GIPERR1 %s bound\n' "$N"; return; fi
        entry=$(printf '%s' "$entry" | $B tr A-F a-f)
        if ! printf '%s\n' "$entry" | $B grep -Eq '^0x1000@0x[0-9a-f]{8}:[0-9]{1,3}:[0-9]{1,3}$'; then
            printf 'GIPERR1 %s parameter\n' "$N"; return
        fi
        id=${entry##*:}
        case " $identities " in *" $id "*) printf 'GIPERR1 %s parent\n' "$N"; return ;; esac
        identities="$identities $id"
        parent="$R/sys/devices/virtio-mmio-cmdline/virtio-mmio.$id"
        children=0
        for child in "$parent"/virtio*; do
            [ -d "$child" ] || continue
            children=$((children+1)); name=${child##*/}
            if [ "$children" -gt 1 ] || ! printf '%s\n' "$name" | $B grep -Eq '^virtio[0-9]{1,3}$'; then
                printf 'GIPERR1 %s parent\n' "$N"; return
            fi
            bus="$R/sys/bus/virtio/devices/$name"
            if [ ! -e "$bus" ]; then
                printf 'GIP1 %s %s -\n' "$N" "$entry"; incomplete=1; continue
            fi
            if [ ! -L "$bus" ] || [ ! "$bus" -ef "$child" ] ||
               [ "$($B readlink -f "$bus")" != "$parent/$name" ]; then
                printf 'GIPERR1 %s parent\n' "$N"; return
            fi
            printf 'GIP1 %s %s %s\n' "$N" "$entry" "$name"
        done
        if [ "$children" -eq 0 ]; then
            printf 'GIP1 %s %s -\n' "$N" "$entry"; incomplete=1
        fi
    done <<EOF
$entries
EOF
    if [ "$mappings" -eq 0 ] || [ "$incomplete" -eq 1 ]; then printf 'GIPM1 %s mmio\n' "$N"; fi
    [ "$(small "$params")" = "$entries" ] || exit 1
}
platform
firmware() {
    state=unavailable
    if [ -r "$2" ] && [ -x "$2" ]; then
        if [ -d "$2/$3" ] && [ -r "$2/$3" ] && [ -x "$2/$3" ]; then state=present
        elif [ ! -e "$2/$3" ] && [ ! -L "$2/$3" ]; then state=absent; fi
    fi
    printf 'GIFW1 %s %s %s\n' "$N" "$1" "$state"
}
firmware efi "$R/sys/firmware" efi
firmware acpi "$R/sys/firmware" acpi
firmware dmi "$R/sys/class/dmi" id
hash bios "$R/sys/class/dmi/id/bios_version"
text efi "$R/sys/firmware/efi/fw_platform_size"
# Reject a restart/rebind during the observation instead of relabelling it.
[ "$(small "$R/run/paos-driver-binding")" = "$binding" ] || exit 1
[ "$(small "$R/proc/sys/kernel/random/boot_id")" = "$boot" ] || exit 1
if [ -n "$driver_target" ]; then
    [ "$( $B readlink -f "$assigned_pci/driver" )" = "$driver_target" ] || exit 1
fi
if [ "$net_mapped" -eq 1 ]; then [ -L "$net/device" ] && [ "$net/device" -ef "$assigned_pci" ] || exit 1; fi
printf 'GID1 %s\n' "$N"
