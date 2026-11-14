#!/bin/busybox sh
# Project the existing closed boot census; do not run another census. ROOT is fixture-only;
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
boot=$(small "$R/proc/sys/kernel/random/boot_id"); token "$boot" || exit 1
printf 'GM1 %s %s %s %s %s %s\n' "$N" "$START" "$NONCE" "$BDF" "$PHYSICAL" "$boot"
F="$R/run/paos-driver-census.txt"
missing() { printf 'GMX1 %s %s\n' "$N" "$1"; }
if [ ! -f "$F" ] || [ -L "$F" ] || [ ! -r "$F" ]; then missing census_unavailable; exit 0; fi
size=$($B stat -c %s "$F")
if [ "$size" -eq 0 ] || [ "$size" -gt 8388608 ]; then missing census_extent; exit 0; fi
sha=$($B sha256sum "$F"); sha=${sha%% *}
printf 'GMC1 %s %s %s\n' "$N" "$size" "$sha"
# Emit each available catalog/loaded observation before checking later peers.
# A failed or truncated census must not erase an earlier observed conflict.
if projection=$($B awk -v n="$N" -v s="$START" -v nonce="$NONCE" -v bdf="$BDF" -v phys="$PHYSICAL" '
function short(k) { return k=="modules.dep" ? "d" : "b" }
function bad() { invalid=1; exit 1 }
function digest(x) { return length(x)==64 && x !~ /[^0-9a-f]/ }
function number(x) { return x ~ /^(0|[1-9][0-9]*)$/ && length(x)<=10 }
{
 if (length($0)>2048 || ended) bad()
 if ($1=="PAOS_DRIVER_CENSUS_BEGIN") {
  if (NR!=1 || NF!=9 || $2!="v=1" || $3!="start="s || $4!="nonce="nonce || $5!="bdf="bdf || $6!="physical_bdf="phys || $7 !~ /^release=[a-zA-Z0-9_.+-]+$/) bad()
  release=substr($7,9); if(length(release)>80) bad()
  print "GMR1 "n" "release; began=1
 } else if (!began) bad()
 else if ($1=="CONFIG") {
  v=substr($2,8); if (NF!=2 || $2 !~ /^sha256=/ || !digest(v) || conf++) bad()
  print "GMF1 "n" config "v
 } else if ($1=="CATALOG") {
  k=substr($2,6); v=substr($3,8)
  if (NF!=3 || $2 !~ /^file=/ || (k!="modules.dep" && k!="modules.builtin") || $3 !~ /^sha256=/ || !digest(v) || catalog[k]++ || (k=="modules.builtin" && !catalog["modules.dep"])) bad()
  kind=k; print "GMF1 "n" "short(k)" "v
 } else if ($1=="AVAILABLE") {
  p=substr($2,6); k=substr($3,6)
  if (NF!=3 || $2 !~ /^file=/ || $3!="kind="kind || length(p)>240 || p !~ /^[a-zA-Z0-9_:.\/,+@=-]+$/ || ++count[k]>32768 || ++available>32768) bad()
 } else if ($1=="LOADED") {
  name=substr($2,6); size=substr($3,7); refs=substr($4,6); state=substr($5,7)
  if (NF!=5 || $2 !~ /^name=/ || name !~ /^[a-zA-Z0-9_-]+$/ || length(name)>56 || $3 !~ /^bytes=/ || !number(size) || $4 !~ /^refs=/ || !number(refs) || $5 !~ /^state=/ || state !~ /^[a-zA-Z]+$/ || length(state)>12 || names[name]++ || ++loaded>4096) bad()
  if (loaded<=8) print "GML1 "n" "name" "size" "refs" "state
 } else if ($1=="PAOS_DRIVER_CENSUS_END") {
  if(NF!=6 || $2!="v=1" || $3!="start="s || $4!="nonce="nonce || $5!="bdf="bdf || $6!="physical_bdf="phys || !catalog["modules.dep"] || !catalog["modules.builtin"] || !conf) bad()
  ended=1
 } else if ($1!="MEMORY" && $1!="PCI" && $1!="RESOURCE" && $1!="NET" && $1!="LEGACY_SOURCE" && $1!="LEGACY_BYTES") bad()
}
END {
 if(invalid || !ended) exit 1
 print "GMS1 "n" "(loaded+0)
 if(loaded>8) print "GMX1 "n" loaded_overflow"
 for(i=1;i<=2;i++) { k=(i==1 ? "modules.dep" : "modules.builtin"); print "GMN1 "n" "short(k)" "(count[k]+0) }
}' "$F"); then
    printf '%s\n' "$projection"
else
    [ -z "$projection" ] || printf '%s\n' "$projection"
    missing census_incomplete; exit 0
fi
# Hash ALL original AVAILABLE lines, never a Terminal prefix. The independent
# reader derives the same projection from actual selected archive catalog bytes.
for k in modules.dep modules.builtin; do
    set -o pipefail
    value=$($B awk -v k="$k" '$1=="AVAILABLE" && $3=="kind="k { print }' "$F" | $B sha256sum)
    case "$k" in modules.dep) tag=d ;; modules.builtin) tag=b ;; esac
    printf 'GMA1 %s %s %s\n' "$N" "$tag" "${value%% *}"
done
[ "$(small "$R/run/paos-driver-binding")" = "$binding" ] || exit 1
[ "$(small "$R/proc/sys/kernel/random/boot_id")" = "$boot" ] || exit 1
after=$($B sha256sum "$F"); [ "${after%% *}" = "$sha" ] || exit 1
[ "$($B stat -c %s "$F")" = "$size" ] || exit 1
printf 'GMD1 %s\n' "$N"
