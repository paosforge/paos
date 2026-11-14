#!/bin/busybox sh
# Read-only two-sample guest measurements. ROOT is solely an offline fixture root;
# the admitted public Terminal command never supplies it. No load or device write.
set -eu
B=/bin/busybox
N=${1:-}; R=${2:-}
[ "$#" -ge 1 ] && [ "$#" -le 2 ] || exit 1
printf '%s\n' "$N" | $B grep -Eq '^[0-9a-f]{16}$' || exit 1
[ "$N" != 0000000000000000 ] || exit 1
case "$R" in ''|/*) ;; *) exit 1 ;; esac
read_small() {
    value=$($B head -c 241 "$1") || exit 1
    [ "${#value}" -le 240 ] || exit 1
    printf '%s' "$value"
}
token() { case "$1" in ''|*[!a-zA-Z0-9_:./-]*) return 1 ;; esac; [ "${#1}" -le 80 ]; }
number() { printf '%s\n' "$1" | $B grep -Eq '^(0|[1-9][0-9]{0,19})$'; }
sample() {
    I=$1; START= NONCE= BDF= PHYSICAL_BDF= PHY= RELAY=; SEEN=
    # Re-read admission at each sample, not an identity cached across restart.
    binding=$(read_small "$R/run/paos-driver-binding")
    while IFS='=' read -r key value; do
        token "$value" || exit 1
        case " $SEEN " in *" $key "*) exit 1 ;; esac
        SEEN="$SEEN $key"
        case "$key" in start) START=$value ;; nonce) NONCE=$value ;; bdf) BDF=$value ;;
          physical_bdf) PHYSICAL_BDF=$value ;; physical_interface) PHY=$value ;; relay) RELAY=$value ;; *) exit 1 ;; esac
    done <<EOF
$binding
EOF
    [ -n "$START" ] && [ -n "$NONCE" ] && [ -n "$BDF" ] && [ -n "$PHYSICAL_BDF" ] && [ -n "$PHY" ] && [ -n "$RELAY" ] || exit 1
    [ "$PHY" != "$RELAY" ] || exit 1
    boot=$(read_small "$R/proc/sys/kernel/random/boot_id"); token "$boot" || exit 1
    printf 'GM1 %s %s %s %s %s %s %s %s %s\n' "$N" "$I" "$START" "$NONCE" "$BDF" "$PHYSICAL_BDF" "$boot" "$PHY" "$RELAY"
    uptime=$(read_small "$R/proc/uptime"); uptime=${uptime%% *}
    printf 'GT1 %s %s %s\n' "$N" "$I" "$uptime"
    $B awk -v n="$N" -v i="$I" 'NR==1 {if($1!="cpu" || NF!=11) exit 1; printf "GC1 %s %s cpu",n,i; for(j=2;j<=11;j++) {if($j!~/^[0-9]+$/ || length($j)>20) exit 1; printf " %s",$j} print ""; exit}' "$R/proc/stat"
    $B awk -v n="$N" -v i="$I" '$1=="MemTotal:" || $1=="MemAvailable:" {if(NF!=3 || $2!~/^[0-9]+$/ || length($2)>20 || $3!="kB") exit 1; k=$1; sub(/:$/,"",k); print "GMEM1",n,i,k,$2,$3; count++} END {if(count!=2) exit 1}' "$R/proc/meminfo"
    for iface in "$PHY" "$RELAY"; do
        case "$iface" in ''|*[!a-zA-Z0-9_-]*) exit 1 ;; esac
        printf 'GIO1 %s %s %s' "$N" "$I" "$iface"
        for field in rx_bytes tx_bytes rx_packets tx_packets rx_dropped tx_dropped; do
            value=$(read_small "$R/sys/class/net/$iface/statistics/$field"); number "$value" || exit 1
            printf ' %s' "$value"
        done
        printf '\n'
        count=0; observed=0
        for queue in "$R/sys/class/net/$iface"/queues/tx-*; do
            [ -d "$queue" ] || continue
            count=$((count+1)); [ "$count" -le 8 ] || exit 1
            name=${queue##*/}; token "$name" || exit 1
            if [ -f "$queue/byte_queue_limits/inflight" ] && [ -f "$queue/byte_queue_limits/limit" ]; then
                inflight=$(read_small "$queue/byte_queue_limits/inflight")
                limit=$(read_small "$queue/byte_queue_limits/limit")
                number "$inflight" && number "$limit" || exit 1
                printf 'GQ1 %s %s %s %s %s %s\n' "$N" "$I" "$iface" "$name" "$inflight" "$limit"
                observed=$((observed+1))
            else
                printf 'GQM1 %s %s %s %s\n' "$N" "$I" "$iface" "$name"
            fi
        done
        [ "$count" -gt 0 ] || printf 'GQM1 %s %s %s\n' "$N" "$I" "$iface"
    done
    uptime=$(read_small "$R/proc/uptime"); uptime=${uptime%% *}
    printf 'GE1 %s %s %s\n' "$N" "$I" "$uptime"
}
sample 0
$B sleep 1
sample 1
printf 'GD1 %s\n' "$N"
