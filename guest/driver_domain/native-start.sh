#!/bin/busybox sh
# T6-1 native EFIstub entry in the SAME DDINIT. /init remains the PaOS entry.
# No guest START/nonce, relay, MAC rewrite or private paos.power transport.
set -eu
B=/bin/busybox
fail() { echo "PAOS_NATIVE_REFUSED reason=$1"; exit 1; }
$B mkdir -p /proc /sys /dev /run /tmp /root
$B mount -t proc proc /proc
$B mount -t sysfs sysfs /sys
$B mount -t devtmpfs devtmpfs /dev
if [ -f /etc/paos/local-clis.json ]; then
    $B mkdir -p /dev/pts
    $B mount -t devpts -o nosuid,noexec,mode=0620,ptmxmode=0666 devpts /dev/pts
fi
CMDLINE=$($B cat /proc/cmdline)
BDF= CONSOLE=/dev/tty1 SEEN=
# No glob expansion of command-line text. Full domain/bus/device/function,
# matching PaOS's selected physical BDF; never pick the first Ethernet card.
set -f
for token in $CMDLINE; do
    case "$token" in
        paos.ndbdf=*|paos.ndphysical=*|paos.ndstart=*|paos.ndnonce=*|paos.guest=*) fail admission ;;
        paos.nativebdf=*|paos.nativeconsole=*)
            key=${token%%=*}
            case " $SEEN " in *" $key "*) fail admission ;; esac
            SEEN="$SEEN $key" ;;
    esac
    case "$token" in
        paos.nativebdf=*) BDF=${token#*=} ;;
        paos.nativeconsole=tty1) CONSOLE=/dev/tty1 ;;
        paos.nativeconsole=ttyS0) CONSOLE=/dev/ttyS0 ;;
        paos.nativeconsole=*) fail admission ;;
    esac
done
set +f
printf '%s\n' "$BDF" | $B grep -Eq '^0000:[0-9a-f]{2}:[01][0-9a-f]\.[0-7]$' || fail admission
[ -d "/sys/bus/pci/devices/$BDF" ] || fail selected_nic_absent
CLASS=$($B cat "/sys/bus/pci/devices/$BDF/class")
case "$CLASS" in 0x0200??) ;; *) fail selected_not_ethernet ;; esac
[ -c "$CONSOLE" ] || fail console
# Same full catalog and current modalias loop as the driver-domain entry.
MODPROBE=/sbin/modprobe
[ -x "$MODPROBE" ] || fail modprobe_missing
LOAD_FAILURES=0
for alias in /sys/bus/pci/devices/*/modalias /sys/bus/virtio/devices/*/modalias; do
    [ -f "$alias" ] || continue
    value=$($B cat "$alias")
    case "$value" in ''|*[!a-zA-Z0-9_:]*) fail modalias ;; esac
    $B timeout 2 "$MODPROBE" -- "$value" || LOAD_FAILURES=$((LOAD_FAILURES+1))
done
expected=$($B readlink -f "/sys/bus/pci/devices/$BDF") || fail selected_nic_absent
[ -n "$expected" ] || fail selected_nic_absent
tries=0 PHY=
while [ "$tries" -lt 20 ]; do
    PHY= PCOUNT=0
    for path in /sys/class/net/*; do
        [ -e "$path/device" ] || continue
        name=${path##*/}
        case "$name" in ''|.|..|*[!a-zA-Z0-9_.-]*) fail interface_name ;; esac
        [ "${#name}" -le 15 ] || fail interface_name
        device=$($B readlink -f "$path/device") || fail interface_binding
        if [ "$device" = "$expected" ]; then
            PHY=$name; PCOUNT=$((PCOUNT+1))
        fi
    done
    [ "$PCOUNT" -le 1 ] || fail ambiguous_interface
    [ "$PCOUNT" -eq 1 ] && break
    tries=$((tries+1)); $B sleep 0.1
done
[ -n "$PHY" ] || fail selected_interface_absent
# Separate binding: never manufacture guest START/nonce/relay identity.
printf '%s\n' "bdf=$BDF" "physical_interface=$PHY" > /run/paos-native-binding
$B ip link set dev "$PHY" up
# Same lease client, callback, hostname and nonblocking readiness. The tiny
# wrapper passes --native explicitly; the default callback admits only paosbr0.
$B udhcpc -f -i "$PHY" -s /sbin/paos-native-dhcp -x hostname:paos-linux < /dev/null > /dev/null 2>&1 &
$B timeout 15 /bin/busybox sh /sbin/paos-driver-census '' native > /run/paos-driver-census.txt || fail census
CENSUS_BYTES=$($B wc -c < /run/paos-driver-census.txt)
CENSUS_SHA=$($B sha256sum /run/paos-driver-census.txt); CENSUS_SHA=${CENSUS_SHA%% *}
printf 'PAOS_NATIVE_READY v=1 bdf=%s physical_interface=%s module_load_failures=%s census_bytes=%s census_sha256=%s\n' \
    "$BDF" "$PHY" "$LOAD_FAILURES" "$CENSUS_BYTES" "$CENSUS_SHA" > "$CONSOLE"
export HOME=/root TERM=vt100 PS1='paos-linux# '
exec /bin/busybox setsid /bin/busybox cttyhack /bin/busybox sh -i < "$CONSOLE" > "$CONSOLE" 2>&1
