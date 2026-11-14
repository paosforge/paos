#!/bin/busybox sh
# Bounded guest observation stream; native owns hash verification and signing.
set -eu
set -o pipefail
B=/bin/busybox
[ "$#" -eq 3 ] || exit 1
FILE=$1 NONCE=$2 START=$3
[ -f "$FILE" ] && [ ! -L "$FILE" ] || exit 1
case "$NONCE" in ''|*[!0-9a-f]*) exit 1 ;; esac
[ "${#NONCE}" -eq 16 ] && [ "$NONCE" != 0000000000000000 ] || exit 1
case "$START" in ''|0*|*[!0-9]*) exit 1 ;; esac
[ "${#START}" -le 10 ] && [ "$START" -le 4294967295 ] || exit 1
BYTES=$($B stat -c %s "$FILE")
case "$BYTES" in ''|*[!0-9]*) exit 1 ;; esac
[ "$BYTES" -gt 0 ] && [ "$BYTES" -le 8388608 ] || exit 1
SHA=$($B sha256sum "$FILE"); SHA=${SHA%% *}
printf '%s\n' "$SHA" | $B grep -Eq '^[0-9a-f]{64}$' || exit 1
# A real hvc tty may translate LF to CRLF. Save and restore its actual mode;
# pipes/files used by source checks are unaffected.
if [ -t 1 ]; then
    exec 3>&1
    TTY_MODE=$($B stty -g <&3)
    $B stty -opost <&3
    trap 'RESULT=$?; trap - EXIT; $B stty "$TTY_MODE" <&3 || RESULT=1; exit "$RESULT"' EXIT
fi
printf 'PAOS_DDOM_BEGIN %s %s %s %s\n' "$NONCE" "$START" "$BYTES" "$SHA"
# One sequential read, one encoder process. Plain hex retains every row and
# actual trailing zero byte, with no padded data in a short final row.
# Read one byte beyond the declared extent so growth refuses rather than clips.
$B xxd -p -c 256 -l "$((BYTES+1))" "$FILE" | (
    OFFSET=0
    while IFS= read -r HEX; do
        # The fixed xxd format itself supplies lowercase hexadecimal.
        [ -n "$HEX" ] || exit 1
        LENGTH=${#HEX}
        [ "$LENGTH" -le 512 ] && [ "$((LENGTH%2))" -eq 0 ] || exit 1
        NEXT=$((OFFSET+LENGTH/2))
        [ "$NEXT" -le "$BYTES" ] || exit 1
        printf 'PAOS_DDOM_DATA %s %s %s %s\n' "$NONCE" "$START" "$OFFSET" "$HEX"
        OFFSET=$NEXT
    done
    [ "$OFFSET" -eq "$BYTES" ] || exit 1
    printf 'PAOS_DDOM_END %s %s\n' "$NONCE" "$START"
)
