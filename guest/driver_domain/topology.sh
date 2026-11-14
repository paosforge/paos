#!/bin/busybox sh
# Project the existing closed boot census; do not run another census. ROOT is fixture-only;
# the sole admitted Terminal command supplies a challenge and no ROOT.
set -eu
B=/bin/busybox
N=${1:-}; P=${2:-}; R=${3:-}
[ "$#" -ge 2 ] && [ "$#" -le 3 ] || exit 1
printf '%s\n' "$N" | $B grep -Eq '^[0-9a-f]{16}$' || exit 1
[ "$N" != 0000000000000000 ] || exit 1
case "$P" in [0-9]|[12][0-9]|3[01]) ;; *) exit 1 ;; esac
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
printf 'GT1 %s %s %s %s %s %s %s\n' "$N" "$P" "$START" "$NONCE" "$BDF" "$PHYSICAL" "$boot"
F="$R/run/paos-driver-census.txt"
missing() { printf 'GTX1 %s %s\n' "$N" "$1"; }
if [ ! -f "$F" ] || [ -L "$F" ] || [ ! -r "$F" ]; then missing census_unavailable; exit 0; fi
size=$($B stat -c %s "$F")
if [ "$size" -eq 0 ] || [ "$size" -gt 8388608 ]; then missing census_extent; exit 0; fi
sha=$($B sha256sum "$F"); sha=${sha%% *}
printf 'GTC1 %s %s %s\n' "$N" "$size" "$sha"
# Only existing original bytes are read. Deterministic whole-record pages have
# <=1200 ASCII bytes, independent of requested page. Scan all rows for counts.
rc=0
projection=$($B awk -v n="$N" -v want="$P" -v s="$START" -v nonce="$NONCE" -v bdf="$BDF" -v phys="$PHYSICAL" -v phy="$PHY" -v relay="$RELAY" '
function bad() { invalid=1; exit 2 }
function token(x) { return length(x)>0 && length(x)<=240 && x !~ /[^a-zA-Z0-9_:.,+@=\/-]/ }
function number(x) { return x ~ /^(0|[1-9][0-9]*)$/ && length(x)<=10 }
function digest(x) { return length(x)==64 && x !~ /[^0-9a-f]/ }
function pci(x) { return x ~ /^[0-9a-f][0-9a-f][0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[01][0-9a-f]\.[0-7]$/ }
function hex(x,len) { return length(x)==len+2 && x ~ /^0x[0-9a-f]+$/ }
function emit(line) {
 if(used+length(line)+1>1200) { page++; used=0 }
 used+=length(line)+1
 if(page+0==want+0) print line
}
{
 if(length($0)>2048 || ended) bad()
 if($1=="PAOS_DRIVER_CENSUS_BEGIN") {
  if(NR!=1 || NF!=9 || $2!="v=1" || $3!="start="s || $4!="nonce="nonce || $5!="bdf="bdf || $6!="physical_bdf="phys || $7 !~ /^release=[a-zA-Z0-9_.+-]+$/ || $8!="physical_interface="phy || $9!="relay="relay) bad()
  release=substr($7,9); if(length(release)>80) bad(); began=1
 } else if(!began) bad()
 else if($1=="CONFIG") {
  config=substr($2,8); if(NF!=2 || $2 !~ /^sha256=/ || !digest(config) || conf++) bad()
 } else if($1=="CATALOG") {
  k=substr($2,6); v=substr($3,8)
  if(NF!=3 || $2 !~ /^file=/ || (k!="modules.dep" && k!="modules.builtin") || $3 !~ /^sha256=/ || !digest(v) || catalog[k]++) bad()
  kind=k
 } else if($1=="AVAILABLE") {
  if(NF!=3 || $2 !~ /^file=/ || !token(substr($2,6)) || $3!="kind="kind || !kind || ++available>32768) bad()
 } else if($1=="LOADED") {
  if(NF!=5 || $2 !~ /^name=/ || !token(substr($2,6)) || $3 !~ /^bytes=/ || !number(substr($3,7)) || $4 !~ /^refs=/ || !number(substr($4,6)) || $5 !~ /^state=/ || !token(substr($5,7)) || ++loaded>4096) bad()
 } else if($1=="PCI") {
  b=substr($2,5); v=substr($3,8); d=substr($4,8); c=substr($5,7); driver=substr($6,8)
  if(NF!=6 || $2 !~ /^bdf=/ || !pci(b) || $3 !~ /^vendor=/ || !hex(v,4) || $4 !~ /^device=/ || !hex(d,4) || $5 !~ /^class=/ || !hex(c,6) || $6 !~ /^driver=/ || !token(driver) || seen[b]++ || ++devices>256) bad()
  emit("P "b" "v" "d" "c" "driver)
 } else if($1=="RESOURCE") {
  b=substr($2,5); i=substr($3,7); a=substr($4,7); z=substr($5,5); flags=substr($6,7)
  if(NF!=6 || $2 !~ /^bdf=/ || !pci(b) || !seen[b] || $3 !~ /^index=/ || !number(i) || i+0>16 || i+0!=bars[b]+0 || $4 !~ /^start=/ || !hex(a,16) || $5 !~ /^end=/ || !hex(z,16) || $6 !~ /^flags=/ || !hex(flags,16) || ++resources>4352) bad()
  bars[b]++; emit("R "b" "i" "a" "z" "flags)
 } else if($1=="LEGACY_SOURCE") {
  name=substr($2,6); state=substr($3,7); bytes=substr($4,7); hash=substr($5,8)
  limit=(name=="clocksource" ? 128 : 4096)
  if(NF!=5 || $2 !~ /^name=/ || name !~ /^(ioports|serial|interrupts|clocksource)$/ || legacy[name]++ || $3 !~ /^state=/ || state !~ /^(observed|unavailable|overflow)$/ || $4 !~ /^bytes=/ || !number(bytes) || bytes+0>limit || $5 !~ /^sha256=/ || (state=="unavailable" ? (bytes!="0" || hash!="-") : (!digest(hash) || (state=="overflow" && bytes+0!=limit)))) bad()
  emit("LH "name" "state" "bytes" "hash)
 } else if($1=="LEGACY_BYTES") {
  name=substr($2,6); at=substr($3,8); value=substr($4,5)
  limit=(name=="clocksource" ? 128 : 4096)
  if(NF!=4 || $2 !~ /^name=/ || name !~ /^(ioports|serial|interrupts|clocksource)$/ || $3 !~ /^offset=/ || !number(at) || at%64!=0 || $4 !~ /^hex=/ || !length(value) || length(value)>128 || length(value)%2 || value ~ /[^0-9a-f]/ || at+length(value)/2>limit || fragments[name,at]++) bad()
  emit("LB "name" "at" "value)
 } else if($1=="NET") {
  if(NF!=5 || $2 !~ /^name=/ || !token(substr($2,6)) || $3 !~ /^mtu=/ || !number(substr($3,5)) || $4 !~ /^mac=/ || !token(substr($4,5)) || $5 !~ /^state=/ || !token(substr($5,7))) bad()
 } else if($1=="MEMORY") {
  if(NF!=4 || $2 !~ /^(MemTotal:|MemFree:|MemAvailable:)$/ || !number($3) || $4!="kB") bad()
 } else if($1=="PAOS_DRIVER_CENSUS_END") {
  if(NF!=6 || $2!="v=1" || $3!="start="s || $4!="nonce="nonce || $5!="bdf="bdf || $6!="physical_bdf="phys || !conf || !catalog["modules.dep"] || !catalog["modules.builtin"]) bad()
  ended=1
 } else bad()
}
END {
 if(invalid) exit 2
 if(!ended) exit 1
 print "GTM1 "n" "(page+1)" "(devices+0)" "(resources+0)" "release" "config
 if(page>=32) print "GTX1 "n" page_overflow"
}' "$F") || rc=$?
[ -z "$projection" ] || printf '%s\n' "$projection"
case "$rc" in 0) ;; 1) missing census_incomplete; exit 0 ;; *) missing census_conflict; exit 0 ;; esac
[ -z "$( $B tail -c 1 "$F" )" ] || { missing census_incomplete; exit 0; }
[ "$(small "$R/run/paos-driver-binding")" = "$binding" ] || { missing binding_changed; exit 0; }
[ "$(small "$R/proc/sys/kernel/random/boot_id")" = "$boot" ] || { missing boot_changed; exit 0; }
after=$($B sha256sum "$F")
[ "${after%% *}" = "$sha" ] && [ "$($B stat -c %s "$F")" = "$size" ] || { missing census_changed; exit 0; }
printf 'GTD1 %s %s\n' "$N" "$P"
