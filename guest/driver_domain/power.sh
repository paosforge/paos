#!/bin/busybox sh
# Private Shut down listener (T5-1.C10b-1b, spec 8.1.1). Host-to-guest only: native
# writes one line on the paos.power virtio port and never reads a reply. This guest has
# no udev, so the port is found by its sysfs name. stdio is /dev/null; the public
# Terminal console is never opened here. One exact line, then sync and poweroff -f
# (no ACPI: Linux halts with IF=0, which native counts as the clean exit). Any other
# line, a second port with the name, or a node that is not root-only: exit, no action.
set -eu
B=/bin/busybox
SYS=/sys
DEV=/dev
[ "$#" -eq 2 ] || exit 1
START=$1
NONCE=$2
printf '%s\n' "$START" | $B grep -Eq '^[1-9][0-9]{0,9}$' || exit 1
printf '%s\n' "$NONCE" | $B grep -Eq '^[0-9a-f]{16}$' || exit 1
node=
tries=0
while :; do
    for f in "$SYS"/class/virtio-ports/vport*p*/name; do
        [ -f "$f" ] || continue
        [ "$($B cat "$f")" = paos.power ] || continue
        [ -z "$node" ] || exit 1
        d=${f%/name}
        node="$DEV/${d##*/}"
    done
    [ -z "$node" ] || break
    tries=$((tries + 1))
    [ "$tries" -lt 600 ] || exit 1
    $B sleep 0.1
done
[ -c "$node" ] || exit 1
[ "$($B stat -c '%u:%g:%a' "$node")" = 0:0:600 ] || exit 1
line=
IFS= read -r -n 65 line < "$node" || exit 1      # a line must end in a newline
[ "$line" = "PAOS_POWER_V1 shutdown $START $NONCE" ] || exit 1
$B sync
exec $B poweroff -f
