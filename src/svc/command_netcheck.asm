;; MODULE svc/command_netcheck
%include "core/abi/build_profile.inc"
;; LAYER 5
;; EXPORTS command_netcheck_init, netcheck_out_ready, netcheck_out_buf, netcheck_collect, netcheck_classify, nc_check
;; IMPORTS boot/header, core/lib/fmt, dev/net/e1000e, dev/net/rtl8168, dev/net/virtio_domain, net/arp_cache, net/dhcp, net/dns, net/http, net/netdev, svc/command, svc/command_udp, svc/command_web
;; CAPS
;; OWNER saga:net
; RCQ-40 J3: NETCHECK, the bounded native Network Check (G1). One read-only
; registry verb that composes the facts STATUS, NETMON_STAT, RESOLVE and
; HTTPSTAT already hold into one line, for the SELECTED adapter (G5), with the
; first layer that is not positively observed:
;   " NETCHECK v=1 check=<layer> adapter= driver= link= addr_nic= net= dhcp= ip=
;     gw= gw_arp= gw_age_s= dns= resolver= resolver_age_s= web= web_status= web_age_s="
; It has no effect: no frame, lookup or fetch; no ARP recency touch (arp_table is
; scanned here, not through arp_cache_lookup); no selection, health or egress
; change; no driver call. Absent gateway evidence is "incomplete:gateway", never a
; gateway fault (G7). A fetch or lookup older than NETCHECK_FRESH_MS (the ARP TTL)
; is not evidence (G4). Registered cap=0/destr=0 with no exact-name public grant,
; so remote callers need the owner (command_auth_required_cap); a locked session
; refuses it (not in lock_ingress_names).

NETCHECK_FRESH_MS equ 300000             ; ARP_TTL x ARP_AGE_MS: one window for all evidence
NETCHECK_OUT_CAP  equ 384
NETCHECK_NAME_MAX equ 15
NETCHECK_AGE_MAX  equ 999999             ; seconds; larger ages print as this

NC_LINK_DOWN      equ 0
NC_LINK_UP        equ 1
NC_LINK_UNPROBED  equ 2

NC_ADDR_SELECTED  equ 0
NC_ADDR_OTHER     equ 1
NC_ADDR_NONE      equ 2

; check codes, in S0's layer order (index into netcheck_check_words)
NC_NO_ADAPTER     equ 0
NC_STARTING       equ 1
NC_INC_ADAPTER    equ 2
NC_NO_LINK        equ 3
NC_NO_LEASE       equ 4
NC_INC_GATEWAY    equ 5
NC_DNS_FAIL       equ 6
NC_INC_RESOLVER   equ 7
NC_WEB_FAIL       equ 8
NC_INC_WEB        equ 9
NC_HEALTHY        equ 10

; web words (index into netcheck_web_words)
NC_WEB_UNPINNED   equ 0
NC_WEB_IDLE       equ 1
NC_WEB_PENDING    equ 2
NC_WEB_DONE       equ 3
NC_WEB_HTTP_ERROR equ 4
NC_WEB_TLS_ERROR  equ 5
NC_WEB_LOST       equ 6
NC_WEB_TIMEOUT    equ 7

; command_netcheck_init — register NETCHECK: cap=0, ARGT_NONE, destr=0.
;   clobbers: caller-saved.
command_netcheck_init:
    lea  rdi, [rel str_verb_netcheck]
    lea  rsi, [rel cmd_verb_netcheck]
    xor  edx, edx
    mov  ecx, ARGT_NONE
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    ret

; cmd_verb_netcheck(RDI=req, RSI=resp) — stage one NETCHECK line.
cmd_verb_netcheck:
    call cmd_handler_prologue
    push rbx
    mov  rbx, rsi
    call netcheck_collect
    call netcheck_classify
    call netcheck_format
    mov  byte [rel netcheck_out_ready], 1
    mov  qword [rbx + RSP_CODE], CMDE_OK
    pop  rbx
    ret

; netcheck_link_sample(RDI=command NIC handle) -> EAX NC_LINK_*. The cached bit
;   udp_nic_link_value reports for the command NIC, minus its "no sample = 0" fold:
;   a NIC with no sample (a domain NIC, a fleet rebind) is NC_LINK_UNPROBED, never
;   down. No driver call.
netcheck_link_sample:
    lea  rax, [rel e1000e_dev]
    cmp  rdi, rax
    je   .shared
    lea  rax, [rel rtl8168_dev]
    cmp  rdi, rax
    je   .shared
    cmp  dword [rdi + dev.health], HEALTH_DEAD
    je   .down                                  ; positive detach evidence
    cmp  byte [rel udp_public_dhcp], 1
    je   .public
    cmp  rdi, [rel udp_static_owner_handle]
    jne  .none
    movzx eax, byte [rel udp_fleet_link_up]
    ret
.public:
    call virtio_domain_is_handle                ; registry check only
    test eax, eax
    jnz  .none
    movzx eax, byte [rel udp_public_link_up]
    ret
.shared:
    movzx eax, byte [rel e1000e_link_up]
    ret
.down:
    xor  eax, eax
    ret
.none:
    mov  eax, NC_LINK_UNPROBED
    ret

; netcheck_collect — snapshot every fact into nc_*. clobbers: caller-saved.
netcheck_collect:
    push rbx
    call boot_ms_now
    mov  [rel nc_now], rax
    ; adapter (G5): the member the next TX would leave on, and whether the
    ; command NIC (which the DHCP/IP facts describe) is that member
    call netdev_select_peek
    mov  [rel nc_sel], rax
    mov  rbx, rax
    mov  rdx, [rel udp_nic_handle]
    mov  ecx, NC_ADDR_NONE
    test rdx, rdx
    jz   .addr
    mov  ecx, NC_ADDR_OTHER
    cmp  rdx, rbx
    jne  .addr
    mov  ecx, NC_ADDR_SELECTED
.addr:
    mov  [rel nc_addr], cl
    mov  byte [rel nc_link], NC_LINK_UNPROBED
    cmp  cl, NC_ADDR_SELECTED
    jne  .dhcp
    mov  rdi, rbx
    call netcheck_link_sample
    mov  [rel nc_link], al
.dhcp:
    ; address facts, as STATUS reports them (G6: the lease is the DHCP word)
    movzx eax, byte [rel dhcp_wire_state]
    lea  r11, [rel netcheck_dhcp_words]
    cmp  eax, DHCP_WS_REBINDING
    ja   .idle_word
    call netcheck_word
    test rax, rax
    jnz  .word
.idle_word:
    call command_udp_dhcp_idle_word
.word:
    mov  [rel nc_dhcp_word], rax
    mov  eax, [rel udp_our_ip3]
    test eax, eax
    jnz  .ip
    mov  eax, [rel udp_our_ip2]
.ip:
    mov  [rel nc_ip], eax
    ; Live configuration authority covers DHCP, fleet static and manual tuples.
    ; ACK scratch can belong to an earlier lease. Never mix a different source
    ; with this command NIC's IP, or resurrect stale settings after release.
    mov  dword [rel nc_gw], 0
    mov  dword [rel nc_dns], 0
    call dns_wire_config_peek                   ; EAX source, EDX gateway, ECX DNS
    test eax, eax
    jz   .configured
    cmp  eax, [rel nc_ip]
    jne  .configured
    mov  [rel nc_gw], edx
    mov  [rel nc_dns], ecx
.configured:
    ; gateway evidence (G7): a valid ARP entry for GW, read without a touch
    mov  byte [rel nc_gw_arp], 0
    mov  byte [rel nc_gw_age], 0
    mov  eax, [rel nc_gw]
    test eax, eax
    jz   .resolver
    lea  rdx, [rel arp_table]
    mov  ecx, ARP_N
.arp_scan:
    cmp  byte [rdx + E_VALID], 0
    je   .arp_next
    cmp  eax, [rdx + E_IP]
    jne  .arp_next
    mov  byte [rel nc_gw_arp], 1
    mov  r8b, [rdx + E_AGE]
    mov  [rel nc_gw_age], r8b
    jmp  .resolver
.arp_next:
    add  rdx, E_SIZE
    dec  ecx
    jnz  .arp_scan
.resolver:
    call dns_wire_state_peek                    ; EAX state, RDX started ms (one locked read)
    mov  [rel nc_dns_state], al
    mov  [rel nc_dns_started], rdx
    ; web (G4): the latched outcome of the last HTTPGET fetch
    mov  byte [rel nc_web], NC_WEB_UNPINNED
%if !PAOS_PUBLIC_BUILD
    lea  rdx, [rel http_server_pin]
    xor  ecx, ecx
.pin:
    cmp  byte [rdx + rcx], 0
    jne  .pinned
    inc  ecx
    cmp  ecx, 32
    jb   .pin
    jmp  .out
.pinned:
    mov  byte [rel nc_web], NC_WEB_PENDING
    cmp  byte [rel http_fetch_active], 1
    je   .out
    movzx eax, byte [rel http_fetch_outcome]   ; HTTP_FO_NONE: no fetch since boot
    mov  ecx, NC_WEB_IDLE
    test eax, eax
    jz   .web
    lea  ecx, [rax + NC_WEB_DONE - HTTP_FO_DONE]
    cmp  ecx, NC_WEB_TIMEOUT
    jbe  .web
    mov  ecx, NC_WEB_IDLE
.web:
    mov  [rel nc_web], cl
%endif
.out:
    pop  rbx
    ret

; netcheck_fresh(RDI=start ms) -> EAX 1 iff 0 < start and now - start <= NETCHECK_FRESH_MS.
netcheck_fresh:
    xor  eax, eax
    test rdi, rdi
    jz   .out
    mov  rcx, [rel nc_now]
    cmp  rcx, rdi
    jb   .out
    sub  rcx, rdi
    cmp  rcx, NETCHECK_FRESH_MS
    ja   .out
    mov  eax, 1
.out:
    ret

; netcheck_classify -> nc_check: the first layer, in S0's order, that is not
;   positively observed. Healthy is a positive finding on every layer.
netcheck_classify:
    mov  ecx, NC_NO_ADAPTER
    cmp  qword [rel nc_sel], 0
    je   .set
    lea  rax, [rel str_udp_dhcp_nodriver]
    cmp  [rel nc_dhcp_word], rax
    je   .set
    mov  ecx, NC_STARTING
    cmp  byte [rel boot_nic_state], NIC_ST_WARMING
    je   .set
    mov  ecx, NC_INC_ADAPTER                    ; G5: never mix two adapters' facts
    cmp  byte [rel nc_addr], NC_ADDR_SELECTED
    jne  .set
    cmp  byte [rel nc_link], NC_LINK_UNPROBED
    je   .set
    mov  ecx, NC_NO_LINK
    cmp  byte [rel nc_link], NC_LINK_UP
    jne  .set
    mov  ecx, NC_NO_LEASE
    cmp  dword [rel nc_ip], 0
    je   .set
    lea  r11, [rel netcheck_no_lease_words]
    xor  edx, edx
.no_lease:
    mov  eax, edx
    call netcheck_word
    test rax, rax
    jz   .gateway
    cmp  rax, [rel nc_dhcp_word]
    je   .set
    inc  edx
    jmp  .no_lease
.gateway:
    mov  ecx, NC_INC_GATEWAY                    ; G7: absent evidence, not a fault
    cmp  byte [rel nc_gw_arp], 1
    jne  .set
    mov  rdi, [rel nc_dns_started]
    call netcheck_fresh
    mov  ecx, NC_INC_RESOLVER
    test eax, eax
    jz   .set
    movzx eax, byte [rel nc_dns_state]
    cmp  eax, DNS_WS_DONE
    je   .web
    cmp  eax, DNS_WS_NX
    je   .dns_fail
    cmp  eax, DNS_WS_NODATA
    je   .dns_fail
    cmp  eax, DNS_WS_TIMEOUT
    jne  .set                                   ; idle or pending
.dns_fail:
    mov  ecx, NC_DNS_FAIL
    jmp  .set
 .web:
%if !PAOS_PUBLIC_BUILD
    movzx eax, byte [rel nc_web]
    cmp  eax, NC_WEB_UNPINNED
    je   .healthy                               ; no web check available: not a fault
    mov  ecx, NC_INC_WEB
    cmp  eax, NC_WEB_DONE
    jb   .set                                   ; idle or pending
    cmp  eax, NC_WEB_LOST
    je   .set
    push rax
    mov  rdi, [rel http_fetch_started_ms]
    call netcheck_fresh
    mov  edx, eax
    pop  rax
    mov  ecx, NC_INC_WEB
    test edx, edx
    jz   .set                                   ; G4: a stale fetch is not evidence now
    mov  ecx, NC_WEB_FAIL
    cmp  eax, NC_WEB_DONE
    jne  .set                                   ; http_error / tls_error
    mov  eax, [rel http_status]
    cmp  eax, 200
    jb   .set
    cmp  eax, 399
    ja   .set
%endif
.healthy:
    mov  ecx, NC_HEALTHY
.set:
    mov  [rel nc_check], cl
    ret

; netcheck_evidence_age_ms -> RAX: the age of the oldest fact a healthy result rests on.
;   Only meaningful after a classify that said healthy, which proved each one fresh.
netcheck_evidence_age_ms:
    movzx eax, byte [rel nc_gw_age]
    imul rax, rax, ARP_AGE_MS
    mov  rcx, [rel nc_now]
    mov  rdx, rcx
    sub  rdx, [rel nc_dns_started]
    cmp  rax, rdx
    cmovb rax, rdx
%if !PAOS_PUBLIC_BUILD
    cmp  byte [rel nc_web], NC_WEB_UNPINNED
    je   .out
    mov  rdx, rcx
    sub  rdx, [rel http_fetch_started_ms]
    cmp  rax, rdx
    cmovb rax, rdx
.out:
%endif
    ret

; --- bounded writer -------------------------------------------------------
netcheck_out_reset:
    lea  rax, [rel netcheck_out_buf]
    mov  [rel netcheck_out_cur], rax
    mov  byte [rax], 0
    ret

; netcheck_out_text(RDI=NUL-terminated) — append, never past the cap.
netcheck_out_text:
    mov  rsi, [rel netcheck_out_cur]
    lea  rdx, [rel netcheck_out_buf + NETCHECK_OUT_CAP - 1]
.copy:
    cmp  rsi, rdx
    jae  .done
    mov  al, [rdi]
    test al, al
    jz   .done
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .copy
.done:
    mov  byte [rsi], 0
    mov  [rel netcheck_out_cur], rsi
    ret

; netcheck_out_num(RDI=value) — decimal, through a scratch buffer.
netcheck_out_num:
    lea  rsi, [rel netcheck_num_buf]
    call fmt_dec                                ; NUL-terminated
    lea  rdi, [rel netcheck_num_buf]
    jmp  netcheck_out_text

; netcheck_out_age(RDI=start ms) — seconds since start, or "-" when never.
netcheck_out_age:
    test rdi, rdi
    jz   .none
    mov  rax, [rel nc_now]
    cmp  rax, rdi
    jb   .none
    sub  rax, rdi
    xor  edx, edx
    mov  ecx, 1000
    div  rcx
    mov  rdi, rax
    cmp  rdi, NETCHECK_AGE_MAX
    jbe  netcheck_out_num
    mov  edi, NETCHECK_AGE_MAX
    jmp  netcheck_out_num
.none:
    lea  rdi, [rel str_nc_dash]
    jmp  netcheck_out_text

; netcheck_out_ipv4(EDI=address, memory byte order) — dotted, or "unset" for 0.
netcheck_out_ipv4:
    push rbx
    push r12
    mov  ebx, edi
    test ebx, ebx
    jnz  .octets
    lea  rdi, [rel str_nc_unset]
    call netcheck_out_text
    jmp  .out
.octets:
    mov  r12d, 4
.octet:
    movzx edi, bl
    call netcheck_out_num
    shr  ebx, 8
    dec  r12d
    jz   .out
    lea  rdi, [rel str_nc_dot]
    call netcheck_out_text
    jmp  .octet
.out:
    pop  r12
    pop  rbx
    ret

; netcheck_out_name(RDI=name or 0) — at most NETCHECK_NAME_MAX chars of
;   [A-Za-z0-9._-] ('_' for any other byte, '~' when longer, '?' when absent), so a
;   device name can never forge a field.
netcheck_out_name:
    lea  rsi, [rel netcheck_num_buf]
    test rdi, rdi
    jz   .absent
    xor  ecx, ecx
.char:
    mov  al, [rdi + rcx]
    test al, al
    jz   .end
    cmp  ecx, NETCHECK_NAME_MAX
    jae  .long
    mov  dl, al
    or   dl, 0x20
    cmp  dl, 'a'
    jb   .not_alpha
    cmp  dl, 'z'
    jbe  .keep
.not_alpha:
    cmp  al, '0'
    jb   .punct
    cmp  al, '9'
    jbe  .keep
.punct:
    cmp  al, '.'
    je   .keep
    cmp  al, '-'
    je   .keep
    mov  al, '_'
.keep:
    mov  [rsi + rcx], al
    inc  ecx
    jmp  .char
.long:
    mov  byte [rsi + rcx], '~'
    inc  ecx
.end:
    test ecx, ecx
    jz   .absent
    mov  byte [rsi + rcx], 0
    mov  rdi, rsi
    jmp  netcheck_out_text
.absent:
    lea  rdi, [rel str_nc_absent]
    jmp  netcheck_out_text

; netcheck_word(R11=word table, EAX=index) -> RAX = the word's address, 0 for a 0 entry.
netcheck_word:
    movsxd rax, dword [r11 + rax*4]
    test rax, rax
    jz   .none
    add  rax, r11
.none:
    ret

; netcheck_put(RDI=" key=") then the word at RSI.
netcheck_put:
    push rsi
    call netcheck_out_text
    pop  rdi
    jmp  netcheck_out_text

; netcheck_format — the fixed-order line into netcheck_out_buf.
netcheck_format:
    push rbx
    call netcheck_out_reset
    movzx eax, byte [rel nc_check]
    lea  r11, [rel netcheck_check_words]
    lea  rdi, [rel str_nc_head]
    call netcheck_word
    mov  rsi, rax
    call netcheck_put
    ; adapter / driver (registry fields of the selected member)
    lea  rdi, [rel str_nc_adapter]
    call netcheck_out_text
    mov  rbx, [rel nc_sel]
    xor  edi, edi
    test rbx, rbx
    jz   .adapter_none
    mov  rdi, [rbx + dev.name]
    call netcheck_out_name
    lea  rdi, [rel str_nc_driver]
    call netcheck_out_text
    xor  edi, edi
    mov  rax, [rbx + dev.info]
    test rax, rax
    jz   .driver
    mov  rdi, [rax + netdev_info.name]
.driver:
    call netcheck_out_name
    jmp  .link
.adapter_none:
    lea  rdi, [rel str_nc_none]
    call netcheck_out_text
    lea  rdi, [rel str_nc_driver]
    lea  rsi, [rel str_nc_none]
    call netcheck_put
.link:
    movzx eax, byte [rel nc_link]
    lea  r11, [rel netcheck_link_words]
    lea  rdi, [rel str_nc_link]
    call netcheck_word
    mov  rsi, rax
    call netcheck_put
    movzx eax, byte [rel nc_addr]
    lea  r11, [rel netcheck_addr_words]
    lea  rdi, [rel str_nc_addr]
    call netcheck_word
    mov  rsi, rax
    call netcheck_put
    lea  rsi, [rel str_udp_r_net_warming]
    movzx eax, byte [rel boot_nic_state]
    cmp  eax, NIC_ST_READY
    jne  .net_parked
    lea  rsi, [rel str_udp_r_net_ready]
.net_parked:
    cmp  eax, NIC_ST_PARKED
    jne  .net
    lea  rsi, [rel str_udp_r_net_parked]
.net:
    lea  rdi, [rel str_nc_net]
    call netcheck_put
    lea  rdi, [rel str_nc_dhcp]
    mov  rsi, [rel nc_dhcp_word]
    call netcheck_put
    lea  rdi, [rel str_nc_ip]
    call netcheck_out_text
    mov  edi, [rel nc_ip]
    call netcheck_out_ipv4
    lea  rdi, [rel str_nc_gw]
    call netcheck_out_text
    mov  edi, [rel nc_gw]
    call netcheck_out_ipv4
    ; gw_arp / gw_age_s
    lea  rsi, [rel str_nc_unset]
    cmp  dword [rel nc_gw], 0
    je   .gw_arp
    lea  rsi, [rel str_nc_absent_word]
    cmp  byte [rel nc_gw_arp], 1
    jne  .gw_arp
    lea  rsi, [rel str_nc_seen]
.gw_arp:
    lea  rdi, [rel str_nc_gw_arp]
    call netcheck_put
    lea  rdi, [rel str_nc_gw_age]
    call netcheck_out_text
    cmp  byte [rel nc_gw_arp], 1
    jne  .gw_age_none
    movzx eax, byte [rel nc_gw_age]
    imul eax, eax, 75                           ; E_AGE ticks of 37.5 s
    shr  eax, 1
    mov  edi, eax
    call netcheck_out_num
    jmp  .dns
.gw_age_none:
    lea  rdi, [rel str_nc_dash]
    call netcheck_out_text
.dns:
    lea  rdi, [rel str_nc_dns]
    call netcheck_out_text
    mov  edi, [rel nc_dns]
    call netcheck_out_ipv4
    movzx eax, byte [rel nc_dns_state]
    cmp  eax, DNS_WS_NODATA
    je   .resolver
    cmp  eax, DNS_WS_TIMEOUT
    jbe  .resolver
    xor  eax, eax
.resolver:
    lea  r11, [rel netcheck_resolver_words]
    lea  rdi, [rel str_nc_resolver]
    call netcheck_word
    mov  rsi, rax
    call netcheck_put
    lea  rdi, [rel str_nc_resolver_age]
    call netcheck_out_text
    mov  rdi, [rel nc_dns_started]
    call netcheck_out_age
    ; web / web_status / web_age_s
    movzx eax, byte [rel nc_web]
    lea  r11, [rel netcheck_web_words]
    lea  rdi, [rel str_nc_web]
    call netcheck_word
    mov  rsi, rax
    call netcheck_put
%if !PAOS_PUBLIC_BUILD
    cmp  byte [rel nc_web], NC_WEB_TLS_ERROR
    jne  .web_status
    movzx edi, byte [rel http_fetch_tls_err]
    call netcheck_out_num
.web_status:
    lea  rdi, [rel str_nc_web_status]
    call netcheck_out_text
    cmp  byte [rel nc_web], NC_WEB_DONE
    jne  .web_status_none
    mov  edi, [rel http_status]
    cmp  edi, 999
    jbe  .web_status_num
    lea  rdi, [rel str_nc_other]                ; rc-sec J3 Q2 (ii): a bounded decimal, else "other"
    call netcheck_out_text
    jmp  .web_age
.web_status_num:
    call netcheck_out_num
    jmp  .web_age
.web_status_none:
    lea  rdi, [rel str_nc_dash]
    call netcheck_out_text
.web_age:
    lea  rdi, [rel str_nc_web_age]
    call netcheck_out_text
    xor  edi, edi
    cmp  byte [rel nc_web], NC_WEB_IDLE
    jbe  .web_age_put                           ; unpinned or no fetch: "-"
    mov  rdi, [rel http_fetch_started_ms]
.web_age_put:
    call netcheck_out_age
%endif
    pop  rbx
    ret

; --- data -------------------------------------------------------------------
; HTTP_FO_DONE..TIMEOUT and NC_WEB_DONE..TIMEOUT keep one order (netcheck_collect maps by offset).
%if !PAOS_PUBLIC_BUILD
    times -((HTTP_FO_HTTP_ERROR - HTTP_FO_DONE != NC_WEB_HTTP_ERROR - NC_WEB_DONE) | (HTTP_FO_TLS_ERROR - HTTP_FO_DONE != NC_WEB_TLS_ERROR - NC_WEB_DONE) | (HTTP_FO_LOST - HTTP_FO_DONE != NC_WEB_LOST - NC_WEB_DONE)) db 0
    times -(HTTP_FO_TIMEOUT - HTTP_FO_DONE != NC_WEB_TIMEOUT - NC_WEB_DONE) db 0
%endif
%include "core/abi/wdata.inc" ; WDATA_BSS_DEFER; standalone assemblies expand blocks in place
; Zero-initialised state: the zero-fill tail (no image bytes).
%macro WDATA_svc_command_netcheck_0 0
alignb 8
nc_now:          resq 1
nc_sel:          resq 1
nc_dhcp_word:    resq 1
nc_dns_started:  resq 1
netcheck_out_cur: resq 1
nc_ip:           resd 1
nc_gw:           resd 1
nc_dns:          resd 1
nc_addr:         resb 1
nc_link:         resb 1
nc_gw_arp:       resb 1
nc_gw_age:       resb 1
nc_dns_state:    resb 1
nc_web:          resb 1
nc_check:        resb 1
; netcheck_out_ready — 1 while a staged NETCHECK line waits for the reply builder.
netcheck_out_ready: resb 1
netcheck_num_buf: resb 24
; netcheck_out_buf — the staged line (NETCHECK_OUT_CAP bytes, NUL-terminated).
netcheck_out_buf: resb NETCHECK_OUT_CAP
%endmacro
WDATA_BSS_DEFER WDATA_svc_command_netcheck_0



align 4
; Word tables: rel32 offsets from each table's own label (org 0 image: no absolute
; pointers; tools/abs_ptr_check.py), read through netcheck_word. 0 = no word.
netcheck_check_words:
    dd str_nc_c_no_adapter - netcheck_check_words, str_nc_c_starting - netcheck_check_words
    dd str_nc_c_inc_adapter - netcheck_check_words, str_nc_c_no_link - netcheck_check_words
    dd str_nc_c_no_lease - netcheck_check_words, str_nc_c_inc_gateway - netcheck_check_words
    dd str_nc_c_dns_fail - netcheck_check_words, str_nc_c_inc_resolver - netcheck_check_words
    dd str_nc_c_web_fail - netcheck_check_words, str_nc_c_inc_web - netcheck_check_words
    dd str_nc_c_healthy - netcheck_check_words
netcheck_link_words:
    dd str_nc_down - netcheck_link_words, str_nc_up - netcheck_link_words, str_nc_unprobed - netcheck_link_words
netcheck_addr_words:
    dd str_nc_selected - netcheck_addr_words, str_nc_other - netcheck_addr_words, str_nc_none - netcheck_addr_words
netcheck_resolver_words:
    dd str_nc_idle - netcheck_resolver_words, str_nc_pending - netcheck_resolver_words, str_nc_pending - netcheck_resolver_words
    dd str_nc_answered - netcheck_resolver_words, str_nc_nxdomain - netcheck_resolver_words, str_nc_timeout - netcheck_resolver_words
    dd str_nc_pending - netcheck_resolver_words, str_nc_nodata - netcheck_resolver_words
netcheck_web_words:
    dd str_nc_unpinned - netcheck_web_words, str_nc_idle - netcheck_web_words
    dd str_nc_pending - netcheck_web_words, str_nc_done - netcheck_web_words
    dd str_nc_http_error - netcheck_web_words, str_nc_tls_error - netcheck_web_words
    dd str_nc_lost - netcheck_web_words, str_nc_timeout - netcheck_web_words
; DHCP_WS_* -> the STATUS DHCP= word (0 = the idle word decides)
netcheck_dhcp_words:
    dd 0, str_udp_dhcp_selecting - netcheck_dhcp_words
    dd str_udp_dhcp_requesting - netcheck_dhcp_words, str_udp_dhcp_bound - netcheck_dhcp_words
    dd str_udp_dhcp_fallback - netcheck_dhcp_words, str_udp_dhcp_renewing - netcheck_dhcp_words
    dd str_udp_dhcp_rebinding - netcheck_dhcp_words
; S0's NO_LEASE set, 0-terminated
netcheck_no_lease_words:
    dd str_udp_dhcp_selecting - netcheck_no_lease_words, str_udp_dhcp_requesting - netcheck_no_lease_words
    dd str_udp_dhcp_fallback - netcheck_no_lease_words, str_udp_dhcp_none - netcheck_no_lease_words
    dd 0

str_verb_netcheck:   db "NETCHECK", 0
str_nc_head:         db " NETCHECK v=1 check=", 0
str_nc_adapter:      db " adapter=", 0
str_nc_driver:       db " driver=", 0
str_nc_link:         db " link=", 0
str_nc_addr:         db " addr_nic=", 0
str_nc_net:          db " net=", 0
str_nc_dhcp:         db " dhcp=", 0
str_nc_ip:           db " ip=", 0
str_nc_gw:           db " gw=", 0
str_nc_gw_arp:       db " gw_arp=", 0
str_nc_gw_age:       db " gw_age_s=", 0
str_nc_dns:          db " dns=", 0
str_nc_resolver:     db " resolver=", 0
str_nc_resolver_age: db " resolver_age_s=", 0
str_nc_web:          db " web=", 0
str_nc_web_status:   db " web_status=", 0
str_nc_web_age:      db " web_age_s=", 0
str_nc_c_no_adapter:   db "no_adapter", 0
str_nc_c_starting:     db "starting", 0
str_nc_c_inc_adapter:  db "incomplete:adapter", 0
str_nc_c_no_link:      db "no_link", 0
str_nc_c_no_lease:     db "no_lease", 0
str_nc_c_inc_gateway:  db "incomplete:gateway", 0
str_nc_c_dns_fail:     db "dns_fail", 0
str_nc_c_inc_resolver: db "incomplete:resolver", 0
str_nc_c_web_fail:     db "web_fail", 0
str_nc_c_inc_web:      db "incomplete:web", 0
str_nc_c_healthy:      db "healthy", 0
str_nc_up:           db "up", 0
str_nc_down:         db "down", 0
str_nc_unprobed:     db "unprobed", 0
str_nc_selected:     db "selected", 0
str_nc_other:        db "other", 0
str_nc_none:         db "none", 0
str_nc_unset:        db "unset", 0
str_nc_seen:         db "seen", 0
str_nc_absent_word:  db "absent", 0
str_nc_absent:       db "?", 0
str_nc_dash:         db "-", 0
str_nc_dot:          db ".", 0
str_nc_idle:         db "idle", 0
str_nc_pending:      db "pending", 0
str_nc_answered:     db "answered", 0
str_nc_nxdomain:     db "nxdomain", 0
str_nc_nodata:       db "nodata", 0
str_nc_timeout:      db "timeout", 0
str_nc_unpinned:     db "unpinned", 0
str_nc_done:         db "done", 0
str_nc_http_error:   db "http_error", 0
str_nc_tls_error:    db "tls_error:", 0
str_nc_lost:         db "lost", 0
