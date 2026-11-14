#!/bin/busybox sh
# Read-only Linux facts. Optional root is for an offline mounted guest snapshot.
set -eu
B=/bin/busybox
R=${1:-}
case "$R" in ''|/*) ;; *) exit 1 ;; esac
# Every variable emitted as a token is restricted; files are never sourced.
token() { case "$1" in ''|*[!a-zA-Z0-9_:./,+@=-]*) return 1 ;; esac; [ "${#1}" -le 240 ]; }
field() { value=$($B cat "$1"); token "$value" || exit 1; printf '%s' "$value"; }
[ -f "$R/run/paos-driver-binding" ] || exit 1
BDF= PHYSICAL_BDF= START= NONCE= PHY= RELAY=
SEEN=
while IFS='=' read -r key value; do
    token "$value" || exit 1
    case " $SEEN " in *" $key "*) exit 1 ;; esac
    SEEN="$SEEN $key"
    case "$key" in bdf) BDF=$value ;; start) START=$value ;; nonce) NONCE=$value ;;
        physical_bdf) PHYSICAL_BDF=$value ;; physical_interface) PHY=$value ;; relay) RELAY=$value ;; *) exit 1 ;; esac
done < "$R/run/paos-driver-binding"
[ -n "$PHYSICAL_BDF" ] && [ -n "$BDF" ] && [ -n "$START" ] && [ -n "$NONCE" ] && [ -n "$PHY" ] && [ -n "$RELAY" ] || exit 1
RELEASE=$(field "$R/proc/sys/kernel/osrelease")
printf 'PAOS_DRIVER_CENSUS_BEGIN v=1 start=%s nonce=%s bdf=%s physical_bdf=%s release=%s physical_interface=%s relay=%s\n' "$START" "$NONCE" "$BDF" "$PHYSICAL_BDF" "$RELEASE" "$PHY" "$RELAY"
for item in MemTotal MemFree MemAvailable; do
    $B awk -v key="$item:" '$1==key && $2~/^[0-9]+$/ {print "MEMORY "key" "$2" "$3; found=1} END {if(!found) exit 1}' "$R/proc/meminfo"
done
# The full available catalog is observed every boot, independent of loaded set.
printf 'CONFIG sha256='; digest=$($B sha256sum "$R/etc/paos/driver-kernel.config"); printf '%s\n' "${digest%% *}"
COUNT=0
for list in "$R/lib/modules/$RELEASE/modules.dep" "$R/lib/modules/$RELEASE/modules.builtin"; do
    [ -f "$list" ] || exit 1
    printf 'CATALOG file=%s sha256=' "${list##*/}"; digest=$($B sha256sum "$list"); printf '%s\n' "${digest%% *}"
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        path=${line%%:*}; token "$path" || exit 1
        COUNT=$((COUNT+1)); [ "$COUNT" -le 32768 ] || exit 1
        printf 'AVAILABLE file=%s kind=%s\n' "$path" "${list##*/}"
    done < "$list"
done
COUNT=0
while read -r name size refs depends state address rest; do
    [ -n "$name" ] || continue
    token "$name" && token "$size" && token "$refs" && token "$state" || exit 1
    COUNT=$((COUNT+1)); [ "$COUNT" -le 4096 ] || exit 1
    printf 'LOADED name=%s bytes=%s refs=%s state=%s\n' "$name" "$size" "$refs" "$state"
done < "$R/proc/modules"
COUNT=0
for dev in "$R"/sys/bus/pci/devices/*; do
    [ -d "$dev" ] || continue
    bdf=${dev##*/}; token "$bdf" || exit 1
    COUNT=$((COUNT+1)); [ "$COUNT" -le 256 ] || exit 1
    driver=unbound
    if [ -L "$dev/driver" ]; then driver=$($B readlink "$dev/driver"); driver=${driver##*/}; fi
    token "$driver" || exit 1
    vendor=$(field "$dev/vendor"); device=$(field "$dev/device"); class=$(field "$dev/class")
    printf 'PCI bdf=%s vendor=%s device=%s class=%s driver=%s\n' "$bdf" "$vendor" "$device" "$class" "$driver"
    if [ -f "$dev/resource" ]; then
        bar=0
        while read -r start end flags rest; do
            token "$start" && token "$end" && token "$flags" || exit 1
            [ "$bar" -le 16 ] || exit 1
            printf 'RESOURCE bdf=%s index=%s start=%s end=%s flags=%s\n' "$bdf" "$bar" "$start" "$end" "$flags"
            bar=$((bar+1))
        done < "$dev/resource"
    fi
done
for dev in "$R"/sys/class/net/*; do
    [ -d "$dev" ] || continue
    iface=${dev##*/}; token "$iface" || exit 1
    mtu=$(field "$dev/mtu"); mac=$(field "$dev/address"); state=$(field "$dev/operstate")
    printf 'NET name=%s mtu=%s mac=%s state=%s\n' "$iface" "$mtu" "$mac" "$state"
done
printf 'PAOS_DRIVER_CENSUS_END v=1 start=%s nonce=%s bdf=%s physical_bdf=%s\n' "$START" "$NONCE" "$BDF" "$PHYSICAL_BDF"
