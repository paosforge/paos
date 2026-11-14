;; MODULE net/ntp
;; LAYER 4
;; EXPORTS ntp_reply_view, ntp_reply_start_ms, ntp_reply_done_ms, ntp_route_revoke, ntp_sample_t1_1, ntp_sample_t1_2, ntp_sample_t1_3, ntp_sample_t1_4, ntp_sample_t4_1, ntp_sample_t4_2, ntp_sample_t4_3, ntp_sample_t4_4, ntp_init, ntp_mark_ready, ntp_sync_start, ntp_sync_wall_offset, ntp_tick, ntp_wire_ingest, ntp_applied, ntp_offset_ms, ntp_delay_ms, ntp_stratum, ntp_state, ntp_reason, ntp_server_port, ntp_timeout_phase, ntp_arp_tx, ntp_query_tx, ntp_rx_udp, ntp_rx_match, ntp_sample_count, ntp_selected_sample, ntp_wall_offset_before, ntp_wall_offset_after, ntp_sync_mono_start, ntp_sync_mono_commit, ntp_rtc_reads_before, ntp_rtc_reads_after, ntp_rtc_writes_before, ntp_rtc_writes_after, ntp_guard_start_ms, ntp_guard_deadline_ms, ntp_guard_fire_ms, ntp_guard_fired, ntp_receipt_valid, ntp_receipt_persisted, ntp_receipt_objid, ntp_receipt_version, ntp_receipt_owner, ntp_receipt_schema, ntp_receipt_checksum, ntp_receipt_utc_us, ntp_receipt_offset_fp, ntp_receipt_delay_fp, ntp_receipt_server_ip, ntp_receipt_samples, ntp_receipt_selected, ntp_receipt_stratum, ntp_m_ready, ntp_m_query, ntp_m_apply
;; IMPORTS lib/safe_buffer, boot/serial, core/lib/mem, core/lib/fixed, core/time, net/arp_cache, net/dns, net/udp
;; CAPS
;; OWNER saga:net
; RFC 5905 client decision layered over Task1060's RFC 4330 wire transaction.
; One non-blocking transaction rides the shared
; DHCP-derived route and shared UDP frame seam.  A rejected sample never writes
; wall_offset; a bounded lowest-delay selection replaces only that record while
; invariant TSC remains the interval clock.

NTP_PORT              equ 123
NTP_SRC_PORT          equ 49154
NTP_PACKET_LEN        equ 48
NTP_REPLY_MAX         equ 2048 ; no live payload exceeds the original whole RX frame
NTP_UNIX_DELTA_Q      equ 0x83AA7E8000000000
NTP_MAX_OFFSET_Q      equ 0x0001518000000000 ; 86400 seconds
NTP_MAX_DELAY_Q       equ 0x0000000500000000 ; 5 seconds
NTP_ARP_RETRY_MS      equ 250
NTP_ARP_BUDGET_MS     equ 3000
; The 3s bound includes setup, polling and terminal recording. End the ARP
; wait one existing retry interval early to leave those operations time;
; a stalled poll must still record its real (possibly late) terminal sample.
NTP_ARP_WAIT_US       equ (NTP_ARP_BUDGET_MS - NTP_ARP_RETRY_MS) * 1000
NTP_REPLY_TIMEOUT_MS  equ 2000
NTP_SAMPLE_TARGET     equ 4
NTP_SAMPLE_GAP_MS     equ 250
NTP_GUARD_INTERVAL_MS equ 10000
NTP_MAX_ROOT_16       equ 0x00050000   ; 5.0 s signed root delay
NTP_MAX_DISP_16       equ 0x00050000   ; 5.0 s unsigned root dispersion
NTP_RECEIPT_OWNER     equ 1
NTP_RECEIPT_OBJID     equ 0x4e54505245434549 ; stable "NTPRECEI" object id
NTP_RECEIPT_SCHEMA    equ 0x4e545053594e4301 ; "NTPSYNC" schema v1

NTP_ST_IDLE       equ 0
NTP_ST_WAIT_ARP   equ 1
NTP_ST_WAIT_REPLY equ 2
NTP_ST_DONE       equ 3
NTP_ST_REJECTED   equ 4

NTP_R_NONE       equ 0
NTP_R_ACCEPTED   equ 1
NTP_R_KOD        equ 2
NTP_R_MALFORMED  equ 3
NTP_R_ORIGIN     equ 4
NTP_R_OFFSET     equ 5
NTP_R_DELAY      equ 6
NTP_R_TIMEOUT    equ 7
NTP_R_NO_ROUTE   equ 8
NTP_R_BAD_SERVER equ 9
NTP_R_DISPERSION equ 10

ntp_init:
    mov  byte [rel ntp_state], NTP_ST_IDLE
    mov  byte [rel ntp_applied], 0
    mov  byte [rel ntp_m_ready], 0
    mov  byte [rel ntp_m_query], 0
    mov  byte [rel ntp_m_apply], 0
    mov  word [rel ntp_server_port], NTP_PORT
    mov  byte [rel ntp_timeout_phase], 0
    mov  qword [rel ntp_arp_tx], 0
    mov  qword [rel ntp_query_tx], 0
    mov  qword [rel ntp_rx_udp], 0
    mov  qword [rel ntp_rx_match], 0
    mov  byte [rel ntp_guard_armed], 0
    mov  byte [rel ntp_guard_fired], 0
    mov  qword [rel ntp_guard_start_ms], 0
    mov  qword [rel ntp_guard_deadline_ms], 0
    mov  qword [rel ntp_guard_fire_ms], 0
    mov  byte [rel ntp_receipt_persisted], 0
    call ntp_grade_reset
    call ntp_selftest
    ret

; Called only after both registry verbs were installed successfully.
ntp_mark_ready:
    mov  byte [rel ntp_m_ready], 1
    lea  rdi, [rel str_ntp_ready]
    call serial_string
    ret

; Reset only the bounded decision state.  The previous wall offset and receipt
; stay intact until a complete sane sample set earns a replacement.
ntp_grade_reset:
    mov  qword [rel ntp_reply_start_ms], 0
    mov  qword [rel ntp_reply_done_ms], 0
    mov  qword [rel ntp_sample_t1_1], 0
    mov  qword [rel ntp_sample_t1_2], 0
    mov  qword [rel ntp_sample_t1_3], 0
    mov  qword [rel ntp_sample_t1_4], 0
    mov  qword [rel ntp_sample_t4_1], 0
    mov  qword [rel ntp_sample_t4_2], 0
    mov  qword [rel ntp_sample_t4_3], 0
    mov  qword [rel ntp_sample_t4_4], 0
    mov  byte [rel ntp_sample_count], 0
    mov  byte [rel ntp_selected_sample], 0
    mov  byte [rel ntp_best_valid], 0
    mov  qword [rel ntp_best_delay_fp], -1
    mov  qword [rel ntp_best_offset_fp], 0
    mov  qword [rel ntp_best_wall_us], 0
    mov  qword [rel ntp_best_mono_us], 0
    mov  byte [rel ntp_best_stratum], 0
    ret

; ntp_grade_select_sample(RDI=corrected UTC us, RSI=signed offset Q32.32,
; RDX=round-trip delay Q32.32, ECX=stratum).  Task1060 remains the sole parser;
; this decision layer merely retains the lowest-delay sane output.  Samples are
; separated by boot_ms_now; ARP expiry uses the microsecond duration clock.
ntp_grade_select_sample:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rdx
    mov  r14d, ecx
    call time_monotonic_now_us
    mov  r15, rax
    movzx eax, byte [rel ntp_sample_count]
    inc  eax
    mov  [rel ntp_sample_count], al
    cmp  byte [rel ntp_best_valid], 1
    jne  .select
    cmp  r13, [rel ntp_best_delay_fp]
    jae  .selected
.select:
    mov  byte [rel ntp_best_valid], 1
    mov  [rel ntp_best_delay_fp], r13
    mov  [rel ntp_best_offset_fp], r12
    mov  [rel ntp_best_wall_us], rbx
    mov  [rel ntp_best_mono_us], r15
    mov  [rel ntp_best_stratum], r14b
    mov  al, [rel ntp_sample_count]
    mov  [rel ntp_selected_sample], al
.selected:
    cmp  byte [rel ntp_sample_count], NTP_SAMPLE_TARGET
    jae  .commit
    mov  [rel ntp_arp_start_us], r15
    call boot_ms_now
    lea  rdx, [rax + NTP_ARP_BUDGET_MS]
    mov  [rel ntp_deadline_ms], rdx
    lea  rdx, [rax + NTP_SAMPLE_GAP_MS]
    mov  [rel ntp_retry_ms], rdx
    mov  byte [rel ntp_state], NTP_ST_WAIT_ARP
    mov  byte [rel ntp_reason], NTP_R_NONE
    mov  byte [rel ntp_applied], 0
    xor  eax, eax
    jmp  .out
.commit:
    call ntp_grade_commit_best
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Age the selected sample only with elapsed monotonic time, then publish the
; resulting UTC by replacing wall_offset.  The receipt uses DATABASE's forever
; header shape plus TIME.md's canonical u64 UTC-microsecond timestamp.  The
; record is marked prepared here; the L5 command projection persists it through
; Task1057's one journal-ready store API without introducing an L4->L5 import.
ntp_grade_commit_best:
    cmp  byte [rel ntp_best_valid], 1
    jne  .commit_fail
    call time_monotonic_now_us
    mov  [rel ntp_sync_mono_commit], rax
    cmp  rax, [rel ntp_best_mono_us]
    jb   .commit_fail
    sub  rax, [rel ntp_best_mono_us]
    add  rax, [rel ntp_best_wall_us]
    jo   .commit_fail
    mov  rdi, rax
    mov  esi, TIME_SRC_NTP
    call time_wall_set_us               ; sole clock mutation: wall_offset only
    mov  rax, [rel wall_offset]
    mov  [rel ntp_wall_offset_after], rax
    mov  rax, [rel time_rtc_read_count]
    mov  [rel ntp_rtc_reads_after], rax
    mov  rax, [rel time_rtc_write_count]
    mov  [rel ntp_rtc_writes_after], rax

    mov  rax, [rel ntp_best_offset_fp]
    mov  [rel ntp_offset_fp], rax
    mov  rdi, rax
    call q32_to_ms_signed
    mov  [rel ntp_offset_ms], rax
    mov  rax, [rel ntp_best_delay_fp]
    mov  [rel ntp_delay_fp], rax
    mov  rdi, rax
    call q32_to_ms_signed
    mov  [rel ntp_delay_ms], rax
    mov  al, [rel ntp_best_stratum]
    mov  [rel ntp_stratum], al

    inc  qword [rel ntp_receipt_generation]
    mov  rax, NTP_RECEIPT_OBJID
    mov  [rel ntp_receipt_objid], rax
    mov  rax, [rel ntp_receipt_generation]
    mov  [rel ntp_receipt_version], rax
    mov  qword [rel ntp_receipt_owner], NTP_RECEIPT_OWNER
    mov  rax, NTP_RECEIPT_SCHEMA
    mov  [rel ntp_receipt_schema], rax
    call time_wall_now_us
    mov  [rel ntp_receipt_utc_us], rax
    mov  eax, [rel ntp_server_ip]
    mov  [rel ntp_receipt_server_ip], eax
    mov  al, [rel ntp_sample_count]
    mov  [rel ntp_receipt_samples], al
    mov  al, [rel ntp_selected_sample]
    mov  [rel ntp_receipt_selected], al
    mov  al, [rel ntp_stratum]
    mov  [rel ntp_receipt_stratum], al
    mov  byte [rel ntp_receipt_valid], 1
    mov  byte [rel ntp_receipt_persisted], 0
    mov  rax, [rel ntp_offset_fp]
    mov  [rel ntp_receipt_offset_fp], rax
    mov  rax, [rel ntp_delay_fp]
    mov  [rel ntp_receipt_delay_fp], rax
    mov  rax, [rel ntp_receipt_objid]
    xor  rax, [rel ntp_receipt_version]
    xor  rax, [rel ntp_receipt_owner]
    xor  rax, [rel ntp_receipt_schema]
    xor  rax, [rel ntp_receipt_utc_us]
    xor  rax, [rel ntp_receipt_offset_fp]
    xor  rax, [rel ntp_receipt_delay_fp]
    xor  rax, [rel ntp_receipt_server_ip] ; server + samples/selected/stratum/valid
    mov  [rel ntp_receipt_checksum], rax
    mov  byte [rel ntp_applied], 1
    mov  byte [rel ntp_state], NTP_ST_DONE
    mov  byte [rel ntp_reason], NTP_R_ACCEPTED
    xor  eax, eax
    ret
.commit_fail:
    mov  edi, NTP_R_OFFSET
    call ntp_set_reject
    mov  rax, -1
    ret

; Contract-facing name for the Task1060-backed wall-offset synchronization.
; It is an alias, not a second packet/client path.
ntp_sync_wall_offset:
    jmp  ntp_sync_start

; ntp_sync_start(RDI=dotted IPv4[:port] text) -> 0 pending / -1 bad / -2 no route.
; Port 123 remains the ordinary/default service.  The optional port is a real
; endpoint seam for local known-clock and hostile peers; it does not weaken any
; reply checks because the selected source port is matched on receive.
ntp_sync_start:
    ; Even a refused fresh request must not project the previous reply timer.
    mov  qword [rel ntp_reply_start_ms], 0
    mov  qword [rel ntp_reply_done_ms], 0
    ; 1230e1 seam: accepted samples may update wall time, never monotonic time.
    push rbx
    push r12
    push r13
    mov  r12, rdi
    call ntp_parse_ipv4
    cmp  eax, -1
    je   .bad_server
    mov  ebx, eax
    mov  r13d, edx
    lea  rdi, [rel ntp_route]
    call dns_wire_route_snapshot
    test rax, rax
    jnz  .no_route
    cmp  dword [rel ntp_route + dns_route_snapshot.source_ip], 0
    je   .no_route
    cmp  dword [rel ntp_route + dns_route_snapshot.mask_ip], 0
    je   .no_route
    cmp  dword [rel ntp_route + dns_route_snapshot.source_mac], 0
    je   .no_route
    call time_wall_now_us
    test rax, rax
    jz   .no_route

    mov  [rel ntp_server_ip], ebx
    mov  [rel ntp_server_port], r13w
    mov  eax, ebx
    and  eax, [rel ntp_route + dns_route_snapshot.mask_ip]
    mov  edx, [rel ntp_route + dns_route_snapshot.source_ip]
    and  edx, [rel ntp_route + dns_route_snapshot.mask_ip]
    cmp  eax, edx
    jne  .gateway
    mov  [rel ntp_next_hop_ip], ebx
    jmp  .route_ready
.gateway:
    mov  eax, [rel ntp_route + dns_route_snapshot.gateway_ip]
    test eax, eax
    jz   .no_route
    mov  [rel ntp_next_hop_ip], eax
.route_ready:
    mov  byte [rel ntp_applied], 0
    mov  byte [rel ntp_stratum], 0
    mov  qword [rel ntp_offset_ms], 0
    mov  qword [rel ntp_delay_ms], 0
    mov  byte [rel ntp_reason], NTP_R_NONE
    mov  byte [rel ntp_timeout_phase], 0
    mov  qword [rel ntp_arp_tx], 0
    mov  qword [rel ntp_query_tx], 0
    mov  qword [rel ntp_rx_udp], 0
    mov  qword [rel ntp_rx_match], 0
    call ntp_grade_reset
    mov  rax, [rel wall_offset]
    mov  [rel ntp_wall_offset_before], rax
    mov  [rel ntp_wall_offset_after], rax
    call time_monotonic_now_us
    mov  [rel ntp_sync_mono_start], rax
    mov  [rel ntp_sync_mono_commit], rax
    mov  [rel ntp_arp_start_us], rax
    mov  rax, [rel time_rtc_read_count]
    mov  [rel ntp_rtc_reads_before], rax
    mov  [rel ntp_rtc_reads_after], rax
    mov  rax, [rel time_rtc_write_count]
    mov  [rel ntp_rtc_writes_before], rax
    mov  [rel ntp_rtc_writes_after], rax
    call boot_ms_now
    mov  [rel ntp_guard_start_ms], rax
    mov  [rel ntp_guard_deadline_ms], rax
    add  qword [rel ntp_guard_deadline_ms], NTP_GUARD_INTERVAL_MS
    mov  qword [rel ntp_guard_fire_ms], 0
    mov  byte [rel ntp_guard_fired], 0
    mov  byte [rel ntp_guard_armed], 1
    call ntp_build_request
    cmp  eax, NTP_PACKET_LEN
    jne  .no_route
    call boot_ms_now
    lea  rdx, [rax + NTP_ARP_BUDGET_MS]
    mov  [rel ntp_deadline_ms], rdx
    mov  qword [rel ntp_retry_ms], 0
    mov  byte [rel ntp_state], NTP_ST_WAIT_ARP
    xor  eax, eax
    jmp  .start_out
.bad_server:
    mov  edi, NTP_R_BAD_SERVER
    call ntp_set_reject
    mov  rax, -1
    jmp  .start_out
.no_route:
    mov  edi, NTP_R_NO_ROUTE
    call ntp_set_reject
    lea  rdi, [rel str_ntp_no_route]
    call serial_string
    mov  rax, -2
.start_out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Parse A.B.C.D or A.B.C.D:port.  IPv4 output is wire-order in EAX and the
; numeric UDP port is in EDX.  Every component is bounded before publication.
ntp_parse_ipv4:
    push rbx
    push r12
    mov  r12, rdi
    test r12, r12
    jz   .parse_bad
    xor  ebx, ebx                     ; packed wire bytes
    xor  r8d, r8d                     ; component index
.component:
    xor  eax, eax
    xor  r9d, r9d                     ; digit count
.digit:
    movzx ecx, byte [r12]
    cmp  cl, '0'
    jb   .component_done
    cmp  cl, '9'
    ja   .component_done
    cmp  r9d, 3
    jae  .parse_bad
    imul eax, eax, 10
    sub  ecx, '0'
    add  eax, ecx
    cmp  eax, 255
    ja   .parse_bad
    inc  r12
    inc  r9d
    jmp  .digit
.component_done:
    test r9d, r9d
    jz   .parse_bad
    mov  ecx, r8d
    shl  ecx, 3
    shl  eax, cl
    or   ebx, eax
    cmp  r8d, 3
    je   .last
    cmp  byte [r12], '.'
    jne  .parse_bad
    inc  r12
    inc  r8d
    jmp  .component
.last:
    cmp  byte [r12], 0
    je   .default_port
    cmp  byte [r12], ':'
    jne  .parse_bad
    inc  r12
    xor  edx, edx
    xor  r9d, r9d
.port_digit:
    movzx ecx, byte [r12]
    cmp  cl, '0'
    jb   .port_done
    cmp  cl, '9'
    ja   .port_done
    cmp  r9d, 5
    jae  .parse_bad
    imul edx, edx, 10
    sub  ecx, '0'
    add  edx, ecx
    cmp  edx, 65535
    ja   .parse_bad
    inc  r12
    inc  r9d
    jmp  .port_digit
.port_done:
    test r9d, r9d
    jz   .parse_bad
    cmp  byte [r12], 0
    jne  .parse_bad
    test edx, edx
    jz   .parse_bad
    jmp  .endpoint_ok
.default_port:
    mov  edx, NTP_PORT
.endpoint_ok:
    test ebx, ebx
    jz   .parse_bad
    mov  eax, ebx
    jmp  .parse_out
.parse_bad:
    mov  eax, -1
.parse_out:
    pop  r12
    pop  rbx
    ret

; Build the 48-byte client request and bind its transmit timestamp as T1.
ntp_build_request:
    call time_wall_now_us
    test rax, rax
    jz   .build_fail
    mov  rdi, rax
    call q32_from_us
    mov  rcx, NTP_UNIX_DELTA_Q
    add  rax, rcx
    mov  [rel ntp_t1_fp], rax
    lea  rdi, [rel ntp_request]
    xor  esi, esi
    mov  edx, NTP_PACKET_LEN
    call memset
    mov  byte [rel ntp_request], 0x23  ; LI=0, VN=4, mode=3 client
    lea  rdi, [rel ntp_request + 40]
    mov  rsi, [rel ntp_t1_fp]
    call be64_store
    mov  eax, NTP_PACKET_LEN
    ret
.build_fail:
    mov  eax, -1
    ret

; An in-flight transaction belongs to its captured route. Re-read the coherent
; DNS/DHCP tuple before further TX or accepting a matching reply. A changed or
; absent route cancels this sync; only an explicit start may capture a new one.
ntp_route_check:
    lea  rdi, [rel ntp_route_current]
    call dns_wire_route_snapshot
    test rax, rax
    jnz  .route_out
    lea  rdi, [rel ntp_route]
    lea  rsi, [rel ntp_route_current]
    mov  edx, dns_route_snapshot_size
    jmp  memcmp
.route_out:
    ret

; Explicit route retirement must cancel even when an identical tuple is
; installed before the next poll. Tuple comparison alone cannot observe that
; intervening withdrawal. Preserve completed wall/receipt/guard state; only a
; fresh explicit sync may capture the replacement route.
ntp_route_revoke:
    cmp  byte [rel ntp_state], NTP_ST_WAIT_ARP
    je   .active
    cmp  byte [rel ntp_state], NTP_ST_WAIT_REPLY
    jne  .out
.active:
    mov  edi, NTP_R_NO_ROUTE
    jmp  ntp_set_reject
.out:
    ret

; Non-blocking ARP/reply FSM, called from the ordinary UDP poll cadence.
ntp_tick:
    call ntp_timeout_guard_tick
    movzx eax, byte [rel ntp_state]
    cmp  eax, NTP_ST_WAIT_ARP
    je   .active
    cmp  eax, NTP_ST_WAIT_REPLY
    jne  .tick_out
.active:
    push rbx
    push r12
    call ntp_route_check
    test rax, rax
    jnz  .no_route
    cmp  byte [rel ntp_state], NTP_ST_WAIT_ARP
    jne  .reply_clock
    ; Match the original measured start, without converting between the
    ; independent boot-ms and monotonic-us origins or granting setup extra time.
    call time_monotonic_now_us
    sub  rax, [rel ntp_arp_start_us]
    cmp  rax, NTP_ARP_WAIT_US
    jae  .timeout
.reply_clock:
    call boot_ms_now
    mov  r12, rax
    cmp  byte [rel ntp_state], NTP_ST_WAIT_ARP
    je   .arp_retry
    cmp  rax, [rel ntp_deadline_ms]
    jae  .timeout
    jmp  .tick_pop
.arp_retry:
    cmp  rax, [rel ntp_retry_ms]
    jb   .tick_pop
    mov  edi, [rel ntp_next_hop_ip]
    call arp_cache_lookup
    test rax, rax
    jz   .send_arp
    lea  rbx, [rax + E_MAC]
    call ntp_build_request               ; T1 belongs at transmit, after ARP wait
    cmp  eax, NTP_PACKET_LEN
    jne  .timeout

    lea  rdx, [rel ntp_frame]
    mov  [rel ntp_tx_desc + udp4_tx.frame], rdx
    mov  dword [rel ntp_tx_desc + udp4_tx.capacity], 128
    mov  edx, [rel ntp_route + dns_route_snapshot.source_ip]
    mov  [rel ntp_tx_desc + udp4_tx.src_ip], edx
    mov  edx, [rel ntp_server_ip]
    mov  [rel ntp_tx_desc + udp4_tx.dst_ip], edx
    mov  word [rel ntp_tx_desc + udp4_tx.src_port], NTP_SRC_PORT
    mov  dx, [rel ntp_server_port]
    mov  word [rel ntp_tx_desc + udp4_tx.dst_port], dx
    lea  rdx, [rel ntp_route + dns_route_snapshot.source_mac]
    mov  [rel ntp_tx_desc + udp4_tx.src_mac], rdx
    mov  [rel ntp_tx_desc + udp4_tx.dst_mac], rbx
    lea  rdx, [rel ntp_request]
    mov  [rel ntp_tx_desc + udp4_tx.payload], rdx
    mov  dword [rel ntp_tx_desc + udp4_tx.payload_len], NTP_PACKET_LEN
    lea  rdi, [rel ntp_tx_desc]
    call udp4_send
    test rax, rax
    jnz  .send_arp
    inc  qword [rel ntp_query_tx]
    mov  byte [rel ntp_state], NTP_ST_WAIT_REPLY
    ; Retain the exact deadline base sampled BEFORE udp4_send. A failed send
    ; above publishes no reply phase; send latency must not shorten its trace.
    mov  [rel ntp_reply_start_ms], r12
    mov  qword [rel ntp_reply_done_ms], 0
    lea  rax, [r12 + NTP_REPLY_TIMEOUT_MS]
    mov  [rel ntp_deadline_ms], rax
    jmp  .tick_pop
.send_arp:
    lea  rdi, [rel ntp_route + dns_route_snapshot.source_mac]
    mov  esi, [rel ntp_route + dns_route_snapshot.source_ip]
    mov  edx, [rel ntp_next_hop_ip]
    lea  rcx, [rel ntp_frame]
    mov  r8d, 128
    call udp4_arp_request
    inc  qword [rel ntp_arp_tx]
    lea  rax, [r12 + NTP_ARP_RETRY_MS]
    mov  [rel ntp_retry_ms], rax
    jmp  .tick_pop
.no_route:
    mov  edi, NTP_R_NO_ROUTE
    call ntp_set_reject
    jmp  .tick_pop
.timeout:
    mov  al, [rel ntp_state]
    mov  [rel ntp_timeout_phase], al
    mov  edi, NTP_R_TIMEOUT
    call ntp_set_reject
.tick_pop:
    pop  r12
    pop  rbx
.tick_out:
    ret

; A real monotonic deadline armed before synchronization.  It remains live
; after wall_offset changes and can fire only from boot_ms_now, never wall time.
ntp_timeout_guard_tick:
    cmp  byte [rel ntp_guard_armed], 1
    jne  .guard_out
    call boot_ms_now
    cmp  rax, [rel ntp_guard_deadline_ms]
    jb   .guard_out
    mov  [rel ntp_guard_fire_ms], rax
    mov  byte [rel ntp_guard_fired], 1
    mov  byte [rel ntp_guard_armed], 0
.guard_out:
    ret

; ntp_wire_ingest(RDI=Ethernet frame, RSI=len) -> EAX=1 consumed / 0 unrelated.
ntp_wire_ingest:
    cmp  byte [rel ntp_state], NTP_ST_WAIT_REPLY
    jne  .unrelated
    lea  rdx, [rel ntp_rx_view]
    call udp4_payload_view
    test rax, rax
    jnz  .unrelated
    inc  qword [rel ntp_rx_udp]
    mov  eax, [rel ntp_rx_view + udp4_view.src_ip]
    cmp  eax, [rel ntp_server_ip]
    jne  .unrelated
    mov  eax, [rel ntp_rx_view + udp4_view.dst_ip]
    cmp  eax, [rel ntp_route + dns_route_snapshot.source_ip]
    jne  .unrelated
    mov  ax, [rel ntp_server_port]
    cmp  word [rel ntp_rx_view + udp4_view.src_port], ax
    jne  .unrelated
    cmp  word [rel ntp_rx_view + udp4_view.dst_port], NTP_SRC_PORT
    jne  .unrelated
    inc  qword [rel ntp_rx_match]
    ; Receive may run before the next timer poll. A matching datagram cannot
    ; extend the absolute reply budget or complete an expired sample set.
    ; Check after UDP validation/tuple matching, before wall time or parsing.
    call boot_ms_now
    cmp  rax, [rel ntp_deadline_ms]
    jae  .timeout
    call ntp_route_check
    test rax, rax
    jnz  .no_route
    cmp  dword [rel ntp_rx_view + udp4_view.payload_len], NTP_PACKET_LEN
    jb   .malformed
    call time_wall_now_us
    test rax, rax
    jz   .malformed
    mov  rdi, rax
    call q32_from_us
    mov  rcx, NTP_UNIX_DELTA_Q
    add  rax, rcx
    mov  rdx, rax                       ; T4
    mov  rdi, [rel ntp_rx_view + udp4_view.payload]
    mov  esi, [rel ntp_rx_view + udp4_view.payload_len]
    call ntp_accept_reply
    mov  eax, 1
    ret
.timeout:
    mov  byte [rel ntp_timeout_phase], NTP_ST_WAIT_REPLY
    mov  edi, NTP_R_TIMEOUT
    jmp  .reject
.no_route:
    mov  edi, NTP_R_NO_ROUTE
    call ntp_set_reject
    mov  eax, 1
    ret
.malformed:
    mov  edi, NTP_R_MALFORMED
.reject:
    call ntp_set_reject
    mov  eax, 1
    ret
.unrelated:
    xor  eax, eax
    ret

; Validate one reply and apply ((T2-T1)+(T3-T4))/2.  Every parsed value stays
; in registers until all guards pass; a reject cannot partially update clock.
ntp_accept_reply:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r13, rdx                       ; original T4 for accepted trace
    mov  rcx, [rel ntp_t1_fp]
    call ntp_reply_view
    cmp  rax, -1
    je   .reject
    mov  rbx, rsi
    mov  r12, rdx
    mov  r15d, ecx
    ; Retain only parser-accepted T1/T4, in sample order. T2/T3 remain on
    ; the wire; these raw Q32.32 values let an independent capture compute
    ; every guest delay. Rejected replies cannot overwrite a retained slot.
    movzx ecx, byte [rel ntp_sample_count]
    cmp  ecx, NTP_SAMPLE_TARGET
    jae  .trace_full
    lea  rdx, [rel ntp_sample_t1_1]
    mov  rsi, [rel ntp_t1_fp]
    mov  [rdx + rcx*8], rsi
    lea  rdx, [rel ntp_sample_t4_1]
    mov  [rdx + rcx*8], r13
.trace_full:
    mov  rdi, rax
    mov  rsi, rbx
    mov  rdx, r12
    mov  ecx, r15d
    call ntp_grade_select_sample         ; no mutation until bounded selection
    jmp  .accept_out
.reject:
    call ntp_set_reject
    mov  rax, -1
.accept_out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Pure original wire reply decoder, shared by ntp_accept_reply and census.
; RDI=payload, RSI=declared span, RDX=T4, RCX=expected T1.
; RAX=UTC us, RSI=signed offset Q32.32, RDX=delay Q32.32, ECX=stratum;
; refusal RAX=-1, EDI=existing NTP reason, remaining outputs zero.
; No clock, route, transaction, sample, receipt or network state is touched.
ntp_reply_view:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  r12, rcx                       ; expected originate timestamp
    mov  r13, rdx                       ; T4
    cmp  rsi, NTP_PACKET_LEN
    jb   .reject_malformed
    cmp  rsi, NTP_REPLY_MAX
    ja   .reject_malformed
    mov  rcx, rsi                       ; validate full declared end before load
    xor  edx, edx
    call safe_span_validate
    test eax, eax
    jnz  .reject_malformed
    mov  al, [rbx]
    mov  ah, al
    and  ah, 0xc0
    cmp  ah, 0xc0                       ; LI=3, unsynchronised
    je   .reject_malformed
    mov  ah, al
    shr  ah, 3
    and  ah, 7
    cmp  ah, 3
    jb   .reject_malformed
    cmp  ah, 4
    ja   .reject_malformed
    and  al, 7
    cmp  al, 4                          ; server mode
    jne  .reject_malformed
    movzx r15d, byte [rbx + 1]
    test r15d, r15d
    jz   .reject_kod                    ; stratum 0 kiss-o-death
    cmp  r15d, 15
    ja   .reject_malformed

    ; Root delay is signed 16.16; root dispersion is unsigned 16.16.
    ; A peer with an excessive declared error budget is not a sane selector
    ; candidate even when its local four-timestamp round trip looks small.
    mov  eax, [rbx + 4]
    bswap eax
    test eax, eax
    js   .reject_delay
    cmp  eax, NTP_MAX_ROOT_16
    ja   .reject_delay
    mov  eax, [rbx + 8]
    bswap eax
    cmp  eax, NTP_MAX_DISP_16
    ja   .reject_dispersion

    lea  rdi, [rbx + 24]
    call be64_load
    cmp  rax, r12
    jne  .reject_origin
    lea  rdi, [rbx + 32]
    call be64_load
    mov  r8, rax                        ; T2
    lea  rdi, [rbx + 40]
    call be64_load
    test rax, rax
    jz   .reject_malformed
    mov  r9, rax                        ; T3

    mov  r10, r8
    sub  r10, r12           ; T2-T1
    jo   .reject_offset
    mov  r11, r9
    sub  r11, r13                       ; T3-T4
    jo   .reject_offset
    add  r10, r11
    jo   .reject_offset
    sar  r10, 1                         ; signed offset Q32.32

    mov  r11, r13
    sub  r11, r12           ; T4-T1
    jo   .reject_delay
    test r11, r11
    js   .reject_delay
    mov  rcx, NTP_MAX_DELAY_Q
    cmp  r11, rcx
    ja   .reject_delay
    mov  rax, r9
    sub  rax, r8                        ; T3-T2
    jo   .reject_delay
    test rax, rax
    js   .reject_delay
    cmp  rax, rcx
    ja   .reject_delay
    sub  r11, rax                       ; round-trip delay
    jo   .reject_delay
    test r11, r11
    js   .reject_delay
    mov  rax, NTP_MAX_DELAY_Q
    cmp  r11, rax
    ja   .reject_delay
    mov  rax, r10
    test rax, rax
    jns  .offset_abs
    neg  rax
    jo   .reject_offset
.offset_abs:
    mov  rcx, NTP_MAX_OFFSET_Q
    cmp  rax, rcx
    ja   .reject_offset
    mov  r14, r13
    add  r14, r10                       ; corrected NTP Q32.32
    mov  rcx, NTP_UNIX_DELTA_Q
    cmp  r14, rcx
    jb   .reject_offset
    sub  r14, rcx
    mov  rbx, r10                       ; preserve accepted values across calls
    mov  r12, r11
    mov  rdi, r14
    call q32_to_us
    test rax, rax
    jz   .reject_offset
    mov  rsi, rbx
    mov  rdx, r12
    mov  ecx, r15d
    jmp  .view_out
.reject_kod:
    mov  edi, NTP_R_KOD
    jmp  .reject
.reject_malformed:
    mov  edi, NTP_R_MALFORMED
    jmp  .reject
.reject_origin:
    mov  edi, NTP_R_ORIGIN
    jmp  .reject
.reject_offset:
    mov  edi, NTP_R_OFFSET
    jmp  .reject
.reject_delay:
    mov  edi, NTP_R_DELAY
    jmp  .reject
.reject_dispersion:
    mov  edi, NTP_R_DISPERSION
.reject:
    mov  rax, -1
    xor  esi, esi
    xor  edx, edx
    xor  ecx, ecx
.view_out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

ntp_set_reject:
    mov  byte [rel ntp_applied], 0
    mov  byte [rel ntp_state], NTP_ST_REJECTED
    mov  [rel ntp_reason], dil
    mov  qword [rel ntp_offset_ms], 0
    mov  qword [rel ntp_delay_ms], 0
    mov  rax, [rel wall_offset]
    mov  [rel ntp_wall_offset_after], rax
    call time_monotonic_now_us
    mov  [rel ntp_sync_mono_commit], rax
    mov  rax, [rel time_rtc_read_count]
    mov  [rel ntp_rtc_reads_after], rax
    mov  rax, [rel time_rtc_write_count]
    mov  [rel ntp_rtc_writes_after], rax
    cmp  byte [rel ntp_reason], NTP_R_TIMEOUT
    jne  .reject_out
    cmp  byte [rel ntp_timeout_phase], NTP_ST_WAIT_REPLY
    jne  .reject_out
    ; Actual terminal completion, not the deadline or a later status-read time.
    ; boot_ms_now has a different origin from time_monotonic_now_us: retain
    ; both endpoints in the very clock domain that enforces this reply timer.
    call boot_ms_now
    mov  [rel ntp_reply_done_ms], rax
.reject_out:
    ret

; Deterministic request/read-back + bounded lowest-delay selection and hostile
; KAT.  Every rejection is checked against the byte-exact prior wall_offset;
; the live wall is restored after the temporary apply.
ntp_selftest:
    push rbx
    push r12
    push r13
    push r14
    push r15
    call time_wall_now_us
    mov  r15, rax                       ; restore point
    movzx eax, byte [rel time_wall_source]
    mov  [rel ntp_kat_saved_source], al ; RCQ-17: restored with the wall
    lea  rdi, [rel ntp_kat_endpoint_default]
    call ntp_parse_ipv4
    cmp  eax, 0x0a0200c0                ; wire bytes 192.0.2.10
    jne  .kat_fail
    cmp  edx, NTP_PORT
    jne  .kat_fail
    lea  rdi, [rel ntp_kat_endpoint_port]
    call ntp_parse_ipv4
    cmp  eax, 0x0a0200c0
    jne  .kat_fail
    cmp  edx, 40123
    jne  .kat_fail
    lea  rdi, [rel ntp_kat_endpoint_bad]
    call ntp_parse_ipv4
    cmp  eax, -1
    jne  .kat_fail
    call ntp_build_request
    cmp  eax, NTP_PACKET_LEN
    jne  .kat_fail
    cmp  byte [rel ntp_request], 0x23
    jne  .kat_fail
    cmp  qword [rel ntp_t1_fp], 0
    je   .kat_fail
    lea  rdi, [rel ntp_kat_sink]
    lea  rsi, [rel ntp_request]
    mov  edx, NTP_PACKET_LEN
    call memcpy
    lea  rdi, [rel ntp_kat_sink]
    lea  rsi, [rel ntp_request]
    mov  edx, NTP_PACKET_LEN
    call memcmp
    test rax, rax
    jnz  .kat_fail

    lea  rdi, [rel ntp_kat_reply]
    xor  esi, esi
    mov  edx, NTP_PACKET_LEN
    call memset
    mov  byte [rel ntp_kat_reply], 0x24
    mov  byte [rel ntp_kat_reply + 1], 2
    mov  r12, NTP_UNIX_DELTA_Q + (1700000000 << 32)
    mov  [rel ntp_t1_fp], r12
    lea  rdi, [rel ntp_kat_reply + 24]
    mov  rsi, r12
    call be64_store
    lea  rdi, [rel ntp_kat_reply + 32]
    mov  rsi, r12
    mov  rax, 0x100000000
    add  rsi, rax                       ; T2=T1+1.0s
    call be64_store
    lea  rdi, [rel ntp_kat_reply + 40]
    mov  rsi, r12
    mov  rax, 0x11999999a
    add  rsi, rax                       ; T3=T1+1.1s
    call be64_store

    call ntp_grade_reset
    mov  rax, [rel wall_offset]
    mov  [rel ntp_wall_offset_before], rax
    mov  rax, [rel time_rtc_read_count]
    mov  [rel ntp_rtc_reads_before], rax
    mov  rax, [rel time_rtc_write_count]
    mov  [rel ntp_rtc_writes_before], rax
    call time_monotonic_now_us
    mov  [rel ntp_sync_mono_start], rax

    ; Four distinct injected samples: delays 300, 200, 100, 250 ms. Offsets also
    ; differ, so selecting sample 3 proves the delay comparison—not a canned
    ; value or last-sample policy—drove the outcome.
    lea  rdx, [r12 + 0x66666666]        ; T4=T1+0.40s: delay=.30, offset=.85
    lea  rdi, [rel ntp_kat_reply]
    mov  esi, NTP_PACKET_LEN
    call ntp_accept_reply
    test rax, rax
    jnz  .kat_fail
    cmp  byte [rel ntp_applied], 0
    jne  .kat_fail
    lea  rdx, [r12 + 0x4ccccccd]        ; T4=T1+0.30s: delay=.20, offset=.90
    lea  rdi, [rel ntp_kat_reply]
    mov  esi, NTP_PACKET_LEN
    call ntp_accept_reply
    test rax, rax
    jnz  .kat_fail
    lea  rdx, [r12 + 0x33333333]        ; T4=T1+0.20s: delay=.10, offset=.95
    lea  rdi, [rel ntp_kat_reply]
    mov  esi, NTP_PACKET_LEN
    call ntp_accept_reply
    test rax, rax
    jnz  .kat_fail
    lea  rdx, [r12 + 0x5999999a]        ; T4=T1+0.35s: delay=.25, offset=.875
    lea  rdi, [rel ntp_kat_reply]
    mov  esi, NTP_PACKET_LEN
    call ntp_accept_reply
    test rax, rax
    jnz  .kat_fail
    cmp  byte [rel ntp_applied], 1
    jne  .kat_fail
    cmp  byte [rel ntp_sample_count], NTP_SAMPLE_TARGET
    jne  .kat_fail
    cmp  byte [rel ntp_selected_sample], 3
    jne  .kat_fail
    mov  rax, [rel ntp_wall_offset_after]
    cmp  rax, [rel ntp_wall_offset_before]
    je   .kat_fail
    mov  rax, [rel ntp_offset_ms]
    cmp  rax, 949
    jb   .kat_fail
    cmp  rax, 951
    ja   .kat_fail
    mov  rax, [rel ntp_delay_ms]
    cmp  rax, 99
    jb   .kat_fail
    cmp  rax, 101
    ja   .kat_fail
    call time_wall_now_s
    cmp  rax, 1700000001
    jb   .kat_fail
    cmp  rax, 1700000002
    ja   .kat_fail
    cmp  byte [rel ntp_receipt_valid], 1
    jne  .kat_fail
    mov  rax, NTP_RECEIPT_OBJID
    cmp  [rel ntp_receipt_objid], rax
    jne  .kat_fail
    cmp  qword [rel ntp_receipt_version], 1
    jne  .kat_fail
    cmp  qword [rel ntp_receipt_owner], NTP_RECEIPT_OWNER
    jne  .kat_fail
    mov  rax, NTP_RECEIPT_SCHEMA
    cmp  [rel ntp_receipt_schema], rax
    jne  .kat_fail
    cmp  qword [rel ntp_receipt_utc_us], 0
    je   .kat_fail
    call time_wall_now_us
    cmp  rax, [rel ntp_receipt_utc_us]
    jb   .kat_fail
    sub  rax, [rel ntp_receipt_utc_us]
    cmp  rax, 100000
    ja   .kat_fail
    mov  rax, [rel ntp_receipt_objid]
    xor  rax, [rel ntp_receipt_version]
    xor  rax, [rel ntp_receipt_owner]
    xor  rax, [rel ntp_receipt_schema]
    xor  rax, [rel ntp_receipt_utc_us]
    xor  rax, [rel ntp_receipt_offset_fp]
    xor  rax, [rel ntp_receipt_delay_fp]
    xor  rax, [rel ntp_receipt_server_ip]
    cmp  rax, [rel ntp_receipt_checksum]
    jne  .kat_fail
    mov  rax, [rel ntp_sync_mono_commit]
    cmp  rax, [rel ntp_sync_mono_start]
    jb   .kat_fail
    mov  rax, [rel ntp_rtc_reads_before]
    cmp  rax, [rel ntp_rtc_reads_after]
    jne  .kat_fail
    mov  rax, [rel ntp_rtc_writes_before]
    cmp  rax, [rel ntp_rtc_writes_after]
    jne  .kat_fail

    ; KoD, wrong originate, invalid mode/version/leap/stratum, excessive
    ; dispersion, huge offset, and truncation all preserve the prior offset.
    mov  rax, [rel wall_offset]
    mov  [rel ntp_kat_guard_offset], rax
    mov  byte [rel ntp_kat_reply + 1], 0
    lea  rdi, [rel ntp_kat_reply]
    mov  esi, NTP_PACKET_LEN
    lea  rdx, [r12 + 0x33333333]
    call ntp_accept_reply
    cmp  byte [rel ntp_applied], 0
    jne  .kat_fail
    cmp  byte [rel ntp_reason], NTP_R_KOD
    jne  .kat_fail
    mov  rax, [rel wall_offset]
    cmp  rax, [rel ntp_kat_guard_offset]
    jne  .kat_fail

    mov  byte [rel ntp_kat_reply + 1], 2
    lea  rdi, [rel ntp_kat_reply + 24]
    lea  rsi, [r12 + 1]
    call be64_store
    lea  rdi, [rel ntp_kat_reply]
    mov  esi, NTP_PACKET_LEN
    lea  rdx, [r12 + 0x33333333]
    call ntp_accept_reply
    cmp  byte [rel ntp_reason], NTP_R_ORIGIN
    jne  .kat_fail
    mov  rax, [rel wall_offset]
    cmp  rax, [rel ntp_kat_guard_offset]
    jne  .kat_fail
    lea  rdi, [rel ntp_kat_reply + 24]
    mov  rsi, r12
    call be64_store

    mov  byte [rel ntp_kat_reply], 0x23 ; client mode, not server mode
    lea  rdi, [rel ntp_kat_reply]
    mov  esi, NTP_PACKET_LEN
    lea  rdx, [r12 + 0x33333333]
    call ntp_accept_reply
    cmp  byte [rel ntp_reason], NTP_R_MALFORMED
    jne  .kat_fail
    mov  byte [rel ntp_kat_reply], 0x14 ; version 2
    lea  rdi, [rel ntp_kat_reply]
    mov  esi, NTP_PACKET_LEN
    lea  rdx, [r12 + 0x33333333]
    call ntp_accept_reply
    cmp  byte [rel ntp_reason], NTP_R_MALFORMED
    jne  .kat_fail
    mov  byte [rel ntp_kat_reply], 0xe4 ; LI=3 unsynchronised
    lea  rdi, [rel ntp_kat_reply]
    mov  esi, NTP_PACKET_LEN
    lea  rdx, [r12 + 0x33333333]
    call ntp_accept_reply
    cmp  byte [rel ntp_reason], NTP_R_MALFORMED
    jne  .kat_fail
    mov  byte [rel ntp_kat_reply], 0x24
    mov  byte [rel ntp_kat_reply + 1], 16
    lea  rdi, [rel ntp_kat_reply]
    mov  esi, NTP_PACKET_LEN
    lea  rdx, [r12 + 0x33333333]
    call ntp_accept_reply
    cmp  byte [rel ntp_reason], NTP_R_MALFORMED
    jne  .kat_fail
    mov  rax, [rel wall_offset]
    cmp  rax, [rel ntp_kat_guard_offset]
    jne  .kat_fail

    mov  byte [rel ntp_kat_reply + 1], 2
    mov  dword [rel ntp_kat_reply + 8], 0x00000600 ; BE 6.0s dispersion
    lea  rdi, [rel ntp_kat_reply]
    mov  esi, NTP_PACKET_LEN
    lea  rdx, [r12 + 0x33333333]
    call ntp_accept_reply
    cmp  byte [rel ntp_reason], NTP_R_DISPERSION
    jne  .kat_fail
    mov  dword [rel ntp_kat_reply + 8], 0
    mov  rax, [rel wall_offset]
    cmp  rax, [rel ntp_kat_guard_offset]
    jne  .kat_fail

    mov  dword [rel ntp_kat_reply + 4], 0x00000600 ; BE 6.0s root delay
    lea  rdi, [rel ntp_kat_reply]
    mov  esi, NTP_PACKET_LEN
    lea  rdx, [r12 + 0x33333333]
    call ntp_accept_reply
    cmp  byte [rel ntp_reason], NTP_R_DELAY
    jne  .kat_fail
    mov  dword [rel ntp_kat_reply + 4], 0
    mov  rdx, r12
    mov  rax, 6
    shl  rax, 32
    add  rdx, rax                       ; local round trip > 5 seconds
    lea  rdi, [rel ntp_kat_reply]
    mov  esi, NTP_PACKET_LEN
    call ntp_accept_reply
    cmp  byte [rel ntp_reason], NTP_R_DELAY
    jne  .kat_fail
    mov  rax, [rel wall_offset]
    cmp  rax, [rel ntp_kat_guard_offset]
    jne  .kat_fail

    lea  rdi, [rel ntp_kat_reply + 32]
    mov  rsi, r12
    mov  rax, 90000
    shl  rax, 32
    add  rsi, rax
    call be64_store
    lea  rdi, [rel ntp_kat_reply + 40]
    mov  rsi, r12
    mov  rax, 90000
    shl  rax, 32
    add  rsi, rax
    add  rsi, 0x1999999a
    call be64_store
    lea  rdi, [rel ntp_kat_reply]
    mov  esi, NTP_PACKET_LEN
    lea  rdx, [r12 + 0x33333333]
    call ntp_accept_reply
    cmp  byte [rel ntp_applied], 0
    jne  .kat_fail
    cmp  byte [rel ntp_reason], NTP_R_OFFSET
    jne  .kat_fail
    mov  rax, [rel wall_offset]
    cmp  rax, [rel ntp_kat_guard_offset]
    jne  .kat_fail
    lea  rdi, [rel ntp_kat_reply]
    mov  esi, NTP_PACKET_LEN - 1
    lea  rdx, [r12 + 0x33333333]
    call ntp_accept_reply
    cmp  byte [rel ntp_reason], NTP_R_MALFORMED
    jne  .kat_fail
    mov  rax, [rel wall_offset]
    cmp  rax, [rel ntp_kat_guard_offset]
    jne  .kat_fail

    mov  byte [rel ntp_m_query], 1
    lea  rdi, [rel str_ntp_query_kat]
    call serial_string
    mov  byte [rel ntp_m_apply], 1
    lea  rdi, [rel str_ntp_apply_kat]
    call serial_string
    jmp  .kat_restore
.kat_fail:
    lea  rdi, [rel str_ntp_kat_fail]
    call serial_string
.kat_restore:
    test r15, r15
    jz   .kat_unseeded
    mov  rdi, r15
    movzx esi, byte [rel ntp_kat_saved_source]
    call time_wall_set_us
    jmp  .kat_reset
.kat_unseeded:
    call time_wall_clear                ; RCQ-17: no fixture time left as a valid ntp wall
.kat_reset:
    call ntp_grade_reset
    mov  byte [rel ntp_state], NTP_ST_IDLE
    mov  byte [rel ntp_applied], 0
    mov  byte [rel ntp_reason], NTP_R_NONE
    mov  qword [rel ntp_offset_ms], 0
    mov  qword [rel ntp_delay_ms], 0
    mov  byte [rel ntp_receipt_valid], 0
    mov  byte [rel ntp_receipt_persisted], 0
    mov  qword [rel ntp_receipt_generation], 0
    mov  qword [rel ntp_receipt_objid], 0
    mov  qword [rel ntp_receipt_version], 0
    mov  qword [rel ntp_receipt_checksum], 0
    mov  qword [rel ntp_receipt_utc_us], 0
    mov  qword [rel ntp_receipt_offset_fp], 0
    mov  qword [rel ntp_receipt_delay_fp], 0
    mov  qword [rel ntp_receipt_server_ip], 0
    mov  rax, [rel wall_offset]
    mov  [rel ntp_wall_offset_before], rax
    mov  [rel ntp_wall_offset_after], rax
    call time_monotonic_now_us
    mov  [rel ntp_sync_mono_start], rax
    mov  [rel ntp_sync_mono_commit], rax
    mov  rax, [rel time_rtc_read_count]
    mov  [rel ntp_rtc_reads_before], rax
    mov  [rel ntp_rtc_reads_after], rax
    mov  rax, [rel time_rtc_write_count]
    mov  [rel ntp_rtc_writes_before], rax
    mov  [rel ntp_rtc_writes_after], rax
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_net_ntp_0 0
align 8
ntp_deadline_ms: dq 0 ; reply expiry / legacy ARP ceiling; ARP uses start_us
ntp_retry_ms:    dq 0
ntp_arp_start_us: dq 0
; Accepted decision trace, reset together with sample_count. Each group is
; four contiguous Q32.32 words, with named scalar fields for NTPSTAT.
ntp_sample_t1_1: dq 0
ntp_sample_t1_2: dq 0
ntp_sample_t1_3: dq 0
ntp_sample_t1_4: dq 0
ntp_sample_t4_1: dq 0
ntp_sample_t4_2: dq 0
ntp_sample_t4_3: dq 0
ntp_sample_t4_4: dq 0
ntp_t1_fp:       dq 0
ntp_offset_fp:   dq 0
ntp_delay_fp:    dq 0
ntp_offset_ms:   dq 0
ntp_delay_ms:    dq 0
ntp_best_delay_fp:  dq -1
ntp_best_offset_fp: dq 0
ntp_best_wall_us:   dq 0
ntp_best_mono_us:   dq 0
ntp_wall_offset_before: dq 0
ntp_wall_offset_after:  dq 0
ntp_sync_mono_start:    dq 0
ntp_sync_mono_commit:   dq 0
ntp_reply_start_ms:     dq 0
ntp_reply_done_ms:      dq 0
ntp_rtc_reads_before:   dq 0
ntp_rtc_reads_after:    dq 0
ntp_rtc_writes_before:  dq 0
ntp_rtc_writes_after:   dq 0
ntp_guard_start_ms:      dq 0
ntp_guard_deadline_ms:   dq 0
ntp_guard_fire_ms:       dq 0
ntp_kat_guard_offset:    dq 0
ntp_server_ip:   dd 0
ntp_next_hop_ip: dd 0
ntp_server_port: dw NTP_PORT
ntp_state:       db NTP_ST_IDLE
ntp_reason:      db NTP_R_NONE
ntp_applied:     db 0
ntp_stratum:     db 0
ntp_sample_count:   db 0
ntp_selected_sample: db 0
ntp_best_valid:     db 0
ntp_best_stratum:   db 0
ntp_guard_armed:    db 0
ntp_guard_fired:    db 0
ntp_timeout_phase: db 0
ntp_m_ready:     db 0
ntp_m_query:     db 0
ntp_m_apply:     db 0
ntp_kat_saved_source: db 0             ; RCQ-17: pre-self-test wall source
align 8
ntp_arp_tx:      dq 0
ntp_query_tx:    dq 0
ntp_rx_udp:      dq 0
ntp_rx_match:    dq 0

; Prepared UTC synchronization receipt. utc_us uses TIME.md's canonical u64
; microsecond representation. L5 retains this metadata in the dedicated NTR1
; NVRAM record, or replaces it with Task1057's committed forever-header fields
; on the legacy scratch backend. receipt_persisted requires exact readback.
ntp_receipt_objid:      dq 0
ntp_receipt_version:    dq 0
ntp_receipt_owner:      dq NTP_RECEIPT_OWNER
ntp_receipt_schema:     dq NTP_RECEIPT_SCHEMA
ntp_receipt_checksum:   dq 0
ntp_receipt_utc_us:     dq 0
ntp_receipt_offset_fp:  dq 0
ntp_receipt_delay_fp:   dq 0
ntp_receipt_generation: dq 0
ntp_receipt_server_ip:  dd 0
ntp_receipt_samples:    db 0
ntp_receipt_selected:   db 0
ntp_receipt_stratum:    db 0
ntp_receipt_valid:      db 0
ntp_receipt_persisted:  db 0

align 8
ntp_route:       times dns_route_snapshot_size db 0
ntp_route_current: times dns_route_snapshot_size db 0
align 8
ntp_tx_desc:     times udp4_tx_size db 0
align 8
ntp_rx_view:     times udp4_view_size db 0
ntp_request:     times NTP_PACKET_LEN db 0
ntp_frame:       times 128 db 0
ntp_kat_reply:   times NTP_PACKET_LEN db 0
ntp_kat_sink:    times NTP_PACKET_LEN db 0

str_ntp_ready:     db "[PAOS64] P8 ntp: SNTP client ready [ntp.client.ready]",13,10,0
str_ntp_query_kat: db "[PAOS64] P8 ntp: client request built+sent selftest PASS [ntp.query.tx]",13,10,0
str_ntp_apply_kat: db "[PAOS64] P8 ntp: offset compute+sanity+apply selftest PASS [ntp.offset.apply]",13,10,0
str_ntp_kat_fail:  db "[PAOS64] P8 ntp: selftest FAIL",13,10,0
str_ntp_no_route:  db "[PAOS64-DEGRADED] P8 ntp: skipped (no NIC/route)",13,10,0
ntp_kat_endpoint_default: db "192.0.2.10",0
ntp_kat_endpoint_port:    db "192.0.2.10:40123",0
ntp_kat_endpoint_bad:     db "192.0.2.10:70000",0
%endmacro
WDATA_DEFER WDATA_net_ntp_0
