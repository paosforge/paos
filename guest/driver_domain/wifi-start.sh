#!/bin/busybox sh
# Sourced by the admitted full guest. No passphrase/config/log/argv secret.
# Native owns the one WFA1 grant, actual START, radio assignment and STOP.
wifi_service() {
    wifi_start || return 1
    # Keep one owner for these exact children after setup. A daemon exit ends
    # this service and reaps its siblings; it never retries association/leases.
    trap wifi_failed EXIT HUP INT TERM
    while kill -0 "$WPA_PID" 2>/dev/null &&
          kill -0 "$DHCP_PID" 2>/dev/null &&
          kill -0 "$DNS_PID" 2>/dev/null; do
        $B sleep 1 || return 1
    done
    return 1
}

wifi_start() {
    umask 077
    [ -d "/sys/class/net/$PHY/wireless" ] || return 1
    [ -c /dev/hvc1 ] || return 1
    [ ! -e /run/paos-wpa ] || return 1
    $B mkdir -m 700 /run/paos-wpa || return 1
    printf '%s\n' "$PHY" > /run/paos-wpa/interface || return 1
    WPA_PID= DNS_PID= DHCP_PID=
    wifi_failed() {
        for pid in "$DNS_PID" "$DHCP_PID" "$WPA_PID"; do
            [ -n "$pid" ] || continue
            kill "$pid" 2>/dev/null || :
            wait "$pid" 2>/dev/null || :
        done
        DNS_PID= DHCP_PID= WPA_PID=
    }
    trap wifi_failed EXIT HUP INT TERM
    $B ip link set dev "$PHY" up || return 1
    /sbin/wpa_supplicant -Dnl80211 -i "$PHY" -C /run/paos-wpa > /dev/null 2>&1 &
    WPA_PID=$!
    tries=0
    while [ "$tries" -lt 20 ]; do
        [ -S "/run/paos-wpa/$PHY" ] && break
        kill -0 "$WPA_PID" 2>/dev/null || return 1
        tries=$((tries+1));$B sleep 0.1
    done
    [ -S "/run/paos-wpa/$PHY" ] || return 1
    # READY and the single frame travel only over the private hvc1 device.
    /sbin/paos-wifi-receiver "$PHY" "$START" "$NONCE" || return 1
    # One selected-interface lease attempt; no public/native-NIC fallback.
    # Keep this exact client alive for renewals. Bound the initial wait to
    # ten seconds; never restart a failed lease attempt on a different NIC.
    $B udhcpc -f -n -t 3 -T 2 -i "$PHY" -s /sbin/paos-wifi-dhcp > /dev/null 2>&1 &
    DHCP_PID=$!
    tries=0
    while [ "$tries" -lt 100 ]; do
        kill -0 "$DHCP_PID" 2>/dev/null || return 1
        [ -f /run/paos-wpa/lease ] && break
        tries=$((tries+1));$B sleep 0.1
    done
    [ -f /run/paos-wpa/lease ] || return 1
    $B ip addr add 10.231.0.1/24 dev "$RELAY" || return 1
    $B ip link set dev "$RELAY" up || return 1
    # This namespace starts without a ruleset. Refuse existing same-name state;
    # no flush of unrelated tables and no NAT/association inferred from stdout.
    /sbin/nft -f - <<RULES || return 1
add table inet paos_wifi
add chain inet paos_wifi input { type filter hook input priority 0; policy drop; }
add rule inet paos_wifi input iifname "lo" accept
add rule inet paos_wifi input iifname "$PHY" ct state established,related accept
add rule inet paos_wifi input iifname "$PHY" udp sport 67 udp dport 68 accept
add rule inet paos_wifi input iifname "$RELAY" ip saddr 10.231.0.2 udp dport { 53, 67 } accept
add rule inet paos_wifi input iifname "$RELAY" ip saddr 0.0.0.0 udp sport 68 udp dport 67 accept
add rule inet paos_wifi input iifname "$RELAY" ip saddr 10.231.0.2 tcp dport 53 accept
add chain inet paos_wifi forward { type filter hook forward priority 0; policy drop; }
add rule inet paos_wifi forward ct state invalid drop
add rule inet paos_wifi forward iifname "$RELAY" oifname "$PHY" ip saddr 10.231.0.2 accept
add rule inet paos_wifi forward iifname "$PHY" oifname "$RELAY" ip daddr 10.231.0.2 ct state established,related accept
add table ip paos_wifi_nat
add chain ip paos_wifi_nat postrouting { type nat hook postrouting priority 100; policy accept; }
add rule ip paos_wifi_nat postrouting oifname "$PHY" ip saddr 10.231.0.2 masquerade
RULES
    printf '1\n' > /proc/sys/net/ipv4/ip_forward || return 1
    /sbin/dnsmasq --keep-in-foreground --conf-file=/dev/null --interface="$RELAY" \
        --bind-interfaces --listen-address=10.231.0.1 --dhcp-range=10.231.0.2,10.231.0.2,255.255.255.0,1h \
        --dhcp-option=3,10.231.0.1 --dhcp-option=6,10.231.0.1 --dhcp-leasefile=/run/paos-wpa/relay.leases \
        --pid-file=/run/paos-wpa/dnsmasq.pid > /dev/null 2>&1 &
    DNS_PID=$!
    $B sleep 0.1
    kill -0 "$DNS_PID" 2>/dev/null || return 1
    trap - EXIT HUP INT TERM
}
