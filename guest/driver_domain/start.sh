#!/bin/busybox sh
# Dedicated init only: no native launch authority or cached/learned module list.
set -eu
B=/bin/busybox
fail() { echo "PAOS_DDOM_REFUSED reason=$1"; exit 1; }
. /sbin/paos-driver-identity
CMDLINE=$($B cat /proc/cmdline)
nd_admission "$CMDLINE" || fail boot_admission
nd_wifi_mode "$CMDLINE" || fail wifi_admission
[ -d "/sys/bus/pci/devices/$BDF" ] || fail assigned_nic_absent
CLASS=$($B cat "/sys/bus/pci/devices/$BDF/class")
if [ "$WIFI" -eq 1 ]; then
    case "$CLASS" in 0x0280??) ;; *) fail assigned_not_wireless ;; esac
else
    case "$CLASS" in 0x0200??) ;; *) fail assigned_not_ethernet ;; esac
fi
# Load the *current* guest-visible modaliases against the full shipped catalog.
# Built-in drivers may already be bound. No learned/cached allowlist is read.
MODPROBE=/sbin/modprobe
[ -x "$MODPROBE" ] || fail modprobe_missing
LOAD_FAILURES=0
for alias in /sys/bus/pci/devices/*/modalias /sys/bus/virtio/devices/*/modalias; do
    [ -f "$alias" ] || continue
    value=$($B cat "$alias")
    case "$value" in ''|*[!a-zA-Z0-9_:]*) fail modalias ;; esac
    $B timeout 2 "$MODPROBE" -- "$value" || LOAD_FAILURES=$((LOAD_FAILURES+1))
done
# Same BDF stays fixed. No 'first non-virtio interface' fallback.
tries=0
while [ "$tries" -lt 20 ]; do
    if nd_interfaces '' "$BDF"; then break; else rc=$?; fi
    [ "$rc" -ne 2 ] || fail ambiguous_interface
    tries=$((tries+1)); $B sleep 0.1
done
[ -n "$PHY" ] && [ -n "$RELAY" ] && [ "$PHY" != "$RELAY" ] || fail relay_binding
# The Ethernet bridge carries PaOS's own frames/MAC and DHCP. The explicit
# Wi-Fi profile instead waits for its private one-shot grant in its own service;
# local password entry must not block complete census or this exact Terminal.
if [ "$WIFI" -eq 1 ]; then
    . /sbin/paos-wifi-start
    wifi_service < /dev/null > /dev/null 2>&1 &
else
# Guest L3 (ROOT109426 (3)): the guest's own IPv4 lives on the bridge under its
# own address, never PaOS's 02:50:41:4f:53 relay identity, the relay's virtio
# MAC or the card's burned-in MAC (a native PaOS boot may own that lease).
# Locally administered 06 plus the card's last five bytes, or 0a when the card's
# own first byte is already 06, so the two never match; set before any port.
PHY_MAC=$($B cat "/sys/class/net/$PHY/address")
case "$PHY_MAC" in
    [0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]) ;;
    *) fail guest_mac ;;
esac
case "$PHY_MAC" in
    06:*) GUEST_MAC=0a:${PHY_MAC#??:} ;;
    *) GUEST_MAC=06:${PHY_MAC#??:} ;;
esac
$B brctl addbr paosbr0
$B ip link set dev paosbr0 address "$GUEST_MAC"
$B brctl stp paosbr0 off
$B brctl setfd paosbr0 0
$B brctl addif paosbr0 "$PHY"
$B brctl addif paosbr0 "$RELAY"
# Explicit promiscuous ports: bridge auto-promisc left r8169 at AcceptMyPhys on
# Lenovo metal (fork vtd.asm str_vtd_domain_bridge_post, desktop-root 109466
# (2)), dropping unicast to PaOS's and the guest's own addresses.
$B ip link set dev "$PHY" up promisc on
$B ip link set dev "$RELAY" up promisc on
$B ip link set dev paosbr0 up
# One background lease client on the bridge only; it never gates census,
# readiness or PaOS's own frames, and PaOS never depends on its result.
$B udhcpc -f -i paosbr0 -s /sbin/paos-driver-dhcp -x hostname:paos-linux < /dev/null > /dev/null 2>&1 &
fi
printf '%s\n' "bdf=$BDF" "start=$START" "nonce=$NONCE" "physical_bdf=$PHYSICAL_BDF" "physical_interface=$PHY" "relay=$RELAY" > /run/paos-driver-binding
# Record facts in the guest, then advertise bounded byte/hash identity on hvc0.
# Native owns collection, authenticity, signed data persistence and UI display.
$B timeout 15 /bin/busybox sh /sbin/paos-driver-census > /run/paos-driver-census.txt || fail census
CENSUS_BYTES=$($B wc -c < /run/paos-driver-census.txt)
CENSUS_SHA=$($B sha256sum /run/paos-driver-census.txt); CENSUS_SHA=${CENSUS_SHA%% *}
[ -c /dev/hvc0 ] || fail console
printf 'PAOS_DDOM_READY v=1 start=%s nonce=%s bdf=%s physical_bdf=%s physical_interface=%s relay=%s module_load_failures=%s census_bytes=%s census_sha256=%s\n' \
    "$START" "$NONCE" "$BDF" "$PHYSICAL_BDF" "$PHY" "$RELAY" "$LOAD_FAILURES" "$CENSUS_BYTES" "$CENSUS_SHA" > /dev/hvc0
# Stream the closed file before readiness; helper preserves the tty mode.
/bin/busybox sh /sbin/paos-driver-stream /run/paos-driver-census.txt "$NONCE" "$START" > /dev/hvc0 || fail census_stream
# Native consumes this exact observation marker; public Internet/Terminal
# oracles still decide success under the original whole-check deadline.
printf 'PAOS_ND_READY %s %s\n' "$NONCE" "$START" > /dev/hvc0
# Private Shut down listener (paos.power port): background, stdio /dev/null, never hvc0.
/bin/busybox sh /sbin/paos-driver-power "$START" "$NONCE" < /dev/null > /dev/null 2>&1 &
# The public Terminal uses this exact hvc0 session. No serial/login listener.
export HOME=/root TERM=vt100 PS1='paos-linux# '
exec /bin/busybox setsid /bin/busybox cttyhack /bin/busybox sh -i < /dev/hvc0 > /dev/hvc0 2>&1
