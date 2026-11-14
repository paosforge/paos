#!/bin/busybox sh
# Read-only Linux facts. Optional root is for an offline mounted guest snapshot.
set -eu
B=/bin/busybox
R=${1:-}
case "$R" in ''|/*) ;; *) exit 1 ;; esac
# Every variable emitted as a token is restricted; files are never sourced.
token() { case "$1" in ''|*[!a-zA-Z0-9_:./,+@=-]*) return 1 ;; esac; [ "${#1}" -le 240 ]; }
field() { value=$($B cat "$1"); token "$value" || exit 1; printf '%s' "$value"; }
[ "$#" -le 2 ] || exit 1
ARM=${2:-guest}
case "$ARM" in
    guest)
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
        ;;
    native)
        BDF= PHY= SEEN=
        [ -f "$R/run/paos-native-binding" ] || exit 1
        while IFS='=' read -r key value; do
            token "$value" || exit 1
            case " $SEEN " in *" $key "*) exit 1 ;; esac
            SEEN="$SEEN $key"
            case "$key" in bdf) BDF=$value ;; physical_interface) PHY=$value ;; *) exit 1 ;; esac
        done < "$R/run/paos-native-binding"
        printf '%s\n' "$BDF" | $B grep -Eq '^0000:[0-9a-f]{2}:[01][0-9a-f]\.[0-7]$' || exit 1
        case "$PHY" in ''|.|..|*[!a-zA-Z0-9_.-]*) exit 1 ;; esac
        [ "${#PHY}" -le 15 ] && [ "$R/sys/class/net/$PHY/device" -ef "$R/sys/bus/pci/devices/$BDF" ] || exit 1
        ;;
    *) exit 1 ;;
esac
RELEASE=$(field "$R/proc/sys/kernel/osrelease")
if [ "$ARM" = native ]; then
    printf 'PAOS_NATIVE_CENSUS_BEGIN v=1 bdf=%s release=%s physical_interface=%s\n' "$BDF" "$RELEASE" "$PHY"
else
    printf 'PAOS_DRIVER_CENSUS_BEGIN v=1 start=%s nonce=%s bdf=%s physical_bdf=%s release=%s physical_interface=%s relay=%s\n' "$START" "$NONCE" "$BDF" "$PHYSICAL_BDF" "$RELEASE" "$PHY" "$RELAY"
fi
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
# Preserve bounded exact kernel-interface bytes in this same closed census.
# One private temporary snapshot per interface avoids re-reading changing proc
# counters for the digest and data. No host path or command is guest-controlled.
T=$($B mktemp -d "$R/run/paos-legacy.XXXXXX")
trap '$B rm -f "$T/raw" "$T/prefix"; $B rmdir "$T"' EXIT HUP INT TERM
legacy() {
    name=$1; path=$2; limit=$3
    if [ ! -r "$path" ] || [ ! -f "$path" ] || ! $B head -c "$((limit+1))" "$path" > "$T/raw"; then
        printf 'LEGACY_SOURCE name=%s state=unavailable bytes=0 sha256=-\n' "$name"
        return
    fi
    size=$($B stat -c %s "$T/raw"); state=observed
    if [ "$size" -gt "$limit" ]; then
        state=overflow
        $B head -c "$limit" "$T/raw" > "$T/prefix"
        $B mv "$T/prefix" "$T/raw"; size=$limit
    fi
    digest=$($B sha256sum "$T/raw")
    printf 'LEGACY_SOURCE name=%s state=%s bytes=%s sha256=%s\n' "$name" "$state" "$size" "${digest%% *}"
    $B od -An -v -tx1 -w64 "$T/raw" | $B awk -v name="$name" '
        { gsub(/[ \t]/, ""); print "LEGACY_BYTES name="name" offset="(at+0)" hex="$0; at+=length($0)/2 }'
}
legacy ioports "$R/proc/ioports" 4096
legacy serial "$R/proc/tty/driver/serial" 4096
legacy interrupts "$R/proc/interrupts" 4096
legacy clocksource "$R/sys/devices/system/clocksource/clocksource0/current_clocksource" 128
if [ "$ARM" = native ]; then
    printf 'PAOS_NATIVE_CENSUS_END v=1 bdf=%s\n' "$BDF"
else
    printf 'PAOS_DRIVER_CENSUS_END v=1 start=%s nonce=%s bdf=%s physical_bdf=%s\n' "$START" "$NONCE" "$BDF" "$PHYSICAL_BDF"
fi
