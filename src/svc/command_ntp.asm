;; MODULE svc/command_ntp
;; LAYER 5
;; EXPORTS command_ntp_init, ntp_persist_receipt, ntp_cmd_out_ready, ntp_cmd_out_buf, ntp_auto_tick, ntp_auto_state, ntp_auto_reason, ntp_auto_server, ntp_auto_start_rc, ntp_auto_deadline_ms
;; IMPORTS core/lib/fmt, core/time, net/ntp, net/dns, net/dhcp, svc/command, svc/ntp_receipt_store, data/kvstore, fs/data_crypto_store, fs/storage_access
;; CAPS
;; OWNER saga:net
; Thin registry projection: NTPSYNC starts the asynchronous client and NTPSTAT
; stages a content-bearing snapshot for the existing UDP reply formatter.

command_ntp_init:
    call ntp_init
    lea  rdi, [rel str_verb_ntpsync]
    lea  rsi, [rel cmd_verb_ntpsync]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    cmp  eax, -1
    je   .init_out
    lea  rdi, [rel str_verb_ntpstat]
    lea  rsi, [rel cmd_verb_ntpstat]
    xor  edx, edx
    mov  ecx, ARGT_NONE
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    cmp  eax, -1
    je   .init_out
    call ntp_mark_ready
.init_out:
    ret

; Persist exactly one accepted synchronization receipt in its own PaOS NVRAM
; record, or Task1057's legacy scratch path when runtime is absent.
; The L4 NTP decision layer publishes immutable receipt
; fields; this L5 projection is the first layer allowed to call the L5 store.
; A failed durable commit stays pending and is retried by the next NTPSTAT.
; Storage canon: called ONLY from the NTPSTAT verb (never the resident poll loop) and always with IMPLICIT
; intent — a status read is not an explicit write request, even owner-signed.
ntp_persist_receipt:
    push rbx
    call storage_access_request_intent
    mov  ebx, eax
    mov  edi, SA_INTENT_IMPLICIT          ; a status read is never write authority (storage canon rule 4)
    call storage_access_set_request_intent
    call ntp_persist_receipt_now
    mov  edi, ebx
    call storage_access_set_request_intent
    pop  rbx
    ret

ntp_persist_receipt_now:
    cmp  byte [rel ntp_receipt_valid], 1
    jne  .out
    cmp  byte [rel ntp_receipt_persisted], 1
    je   .out
    cmp  byte [rel ntp_state], 3          ; NTP_ST_DONE
    jne  .out
    call time_monotonic_now_us
    cmp  rax, [rel ntp_receipt_retry_us]
    jb   .out
    lea  rdx, [rax + 1000000]             ; failed media: retry at most once/sec
    mov  [rel ntp_receipt_retry_us], rdx
    call ntp_receipt_nvram_store
    test eax, eax
    jz   .nvram_committed
    cmp  eax, 1
    jne  .out                           ; present runtime: no alternate-store fallback
    ; storage-access canon: implicit intent -> only PaOS-owned/test-scratch storage. On a real disk the
    ;   receipt stays in RAM for this boot (no further retries) and NTPSTAT reports receipt_persisted=0.
    call data_crypto_write_permitted
    test rax, rax
    jz   .permitted
    mov  qword [rel ntp_receipt_retry_us], -1
    jmp  .out
.permitted:
    push rbx
    mov  rax, [rel ntp_receipt_utc_us]
    mov  [rel ntp_receipt_value], rax
    mov  rax, [rel ntp_receipt_offset_fp]
    mov  [rel ntp_receipt_value + 8], rax
    mov  rax, [rel ntp_receipt_delay_fp]
    mov  [rel ntp_receipt_value + 16], rax
    mov  eax, [rel ntp_receipt_server_ip]
    mov  [rel ntp_receipt_value + 24], eax
    mov  al, [rel ntp_receipt_samples]
    mov  [rel ntp_receipt_value + 28], al
    mov  al, [rel ntp_receipt_selected]
    mov  [rel ntp_receipt_value + 29], al
    mov  al, [rel ntp_receipt_stratum]
    mov  [rel ntp_receipt_value + 30], al

    call kv_store_lock_acquire
    lea  rdi, [rel ntp_receipt_key]
    mov  esi, ntp_receipt_key.len
    lea  rdx, [rel ntp_receipt_value]
    mov  ecx, 31                        ; fits Task1057's 35-byte value capacity
    xor  r8d, r8d                       ; verified TMP + PRIMARY durable commit
    call kv_store_put
    mov  ebx, eax
    test eax, eax
    jnz  .unlock

    ; Copy the exact header metadata Task1057 just committed while its lock is
    ; still held.  These are observations of the canonical record, not a
    ; second receipt-header implementation.
    mov  rax, [rel kv_next_objid]
    mov  [rel ntp_receipt_objid], rax
    mov  eax, [rel kv_next_version]
    mov  [rel ntp_receipt_version], rax
    mov  qword [rel ntp_receipt_owner], 1
    mov  qword [rel ntp_receipt_schema], 1 ; KV_SCHEMA_BLOB
    mov  eax, [rel kv_plain_buf + 16]      ; KV_CHECKSUM
    mov  [rel ntp_receipt_checksum], rax
    mov  qword [rel ntp_receipt_retry_us], 0
    mov  byte [rel ntp_receipt_persisted], 1
.unlock:
    call kv_store_lock_release
    mov  eax, ebx
    pop  rbx
.out:
    ret
.nvram_committed:
    mov  qword [rel ntp_receipt_retry_us], 0
    mov  byte [rel ntp_receipt_persisted], 1
    ret

ntp_out_reset:
    lea  rax, [rel ntp_cmd_out_buf]
    mov  [rel ntp_cmd_out_cur], rax
    mov  byte [rax], 0
    ret

ntp_out_text:
    mov  rsi, [rel ntp_cmd_out_cur]
.text_loop:
    mov  al, [rdi]
    test al, al
    jz   .text_done
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .text_loop
.text_done:
    mov  byte [rsi], 0
    mov  [rel ntp_cmd_out_cur], rsi
    ret

ntp_out_u64:
    mov  rsi, [rel ntp_cmd_out_cur]
    push rsi
    call fmt_dec
    pop  rsi
    add  rsi, rax
    mov  [rel ntp_cmd_out_cur], rsi
    ret

ntp_out_s64:
    test rdi, rdi
    jns  ntp_out_u64
    mov  rsi, [rel ntp_cmd_out_cur]
    mov  byte [rsi], '-'
    inc  rsi
    mov  byte [rsi], 0
    mov  [rel ntp_cmd_out_cur], rsi
    neg  rdi
    jmp  ntp_out_u64

ntp_stage_status:
    call ntp_out_reset
    lea  rdi, [rel str_ntp_applied]
    call ntp_out_text
    movzx edi, byte [rel ntp_applied]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_offset]
    call ntp_out_text
    mov  rdi, [rel ntp_offset_ms]
    call ntp_out_s64
    lea  rdi, [rel str_ntp_delay]
    call ntp_out_text
    mov  rdi, [rel ntp_delay_ms]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_unixtime]
    call ntp_out_text
    call time_wall_now_s
    mov  rdi, rax
    call ntp_out_u64
    lea  rdi, [rel str_ntp_stratum]
    call ntp_out_text
    movzx edi, byte [rel ntp_stratum]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_state]
    call ntp_out_text
    movzx edi, byte [rel ntp_state]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_reason]
    call ntp_out_text
    movzx edi, byte [rel ntp_reason]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_port]
    call ntp_out_text
    movzx edi, word [rel ntp_server_port]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_phase]
    call ntp_out_text
    movzx edi, byte [rel ntp_timeout_phase]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_arptx]
    call ntp_out_text
    mov  rdi, [rel ntp_arp_tx]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_querytx]
    call ntp_out_text
    mov  rdi, [rel ntp_query_tx]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_rxudp]
    call ntp_out_text
    mov  rdi, [rel ntp_rx_udp]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_rxmatch]
    call ntp_out_text
    mov  rdi, [rel ntp_rx_match]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_samples]
    call ntp_out_text
    movzx edi, byte [rel ntp_sample_count]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_selected]
    call ntp_out_text
    movzx edi, byte [rel ntp_selected_sample]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_wall_before]
    call ntp_out_text
    mov  rdi, [rel ntp_wall_offset_before]
    call ntp_out_s64
    lea  rdi, [rel str_ntp_wall_after]
    call ntp_out_text
    mov  rdi, [rel ntp_wall_offset_after]
    call ntp_out_s64
    lea  rdi, [rel str_ntp_mono_start]
    call ntp_out_text
    mov  rdi, [rel ntp_sync_mono_start]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_mono_commit]
    call ntp_out_text
    mov  rdi, [rel ntp_sync_mono_commit]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_rtcr_before]
    call ntp_out_text
    mov  rdi, [rel ntp_rtc_reads_before]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_rtcr_after]
    call ntp_out_text
    mov  rdi, [rel ntp_rtc_reads_after]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_rtcw_before]
    call ntp_out_text
    mov  rdi, [rel ntp_rtc_writes_before]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_rtcw_after]
    call ntp_out_text
    mov  rdi, [rel ntp_rtc_writes_after]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_reply_start]
    call ntp_out_text
    mov  rdi, [rel ntp_reply_start_ms]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_reply_done]
    call ntp_out_text
    mov  rdi, [rel ntp_reply_done_ms]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_guard_start]
    call ntp_out_text
    mov  rdi, [rel ntp_guard_start_ms]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_guard_deadline]
    call ntp_out_text
    mov  rdi, [rel ntp_guard_deadline_ms]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_guard_fire]
    call ntp_out_text
    mov  rdi, [rel ntp_guard_fire_ms]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_guard_fired]
    call ntp_out_text
    movzx edi, byte [rel ntp_guard_fired]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_receipt_valid]
    call ntp_out_text
    movzx edi, byte [rel ntp_receipt_valid]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_receipt_persisted]
    call ntp_out_text
    movzx edi, byte [rel ntp_receipt_persisted]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_receipt_objid]
    call ntp_out_text
    mov  rdi, [rel ntp_receipt_objid]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_receipt_ver]
    call ntp_out_text
    mov  rdi, [rel ntp_receipt_version]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_receipt_owner]
    call ntp_out_text
    mov  rdi, [rel ntp_receipt_owner]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_receipt_schema]
    call ntp_out_text
    mov  rdi, [rel ntp_receipt_schema]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_receipt_ck]
    call ntp_out_text
    mov  rdi, [rel ntp_receipt_checksum]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_receipt_utc]
    call ntp_out_text
    mov  rdi, [rel ntp_receipt_utc_us]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_receipt_offset]
    call ntp_out_text
    mov  rdi, [rel ntp_receipt_offset_fp]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_receipt_delay]
    call ntp_out_text
    mov  rdi, [rel ntp_receipt_delay_fp]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_receipt_server]
    call ntp_out_text
    mov  edi, [rel ntp_receipt_server_ip]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_receipt_samples]
    call ntp_out_text
    movzx edi, byte [rel ntp_receipt_samples]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_receipt_selected]
    call ntp_out_text
    movzx edi, byte [rel ntp_receipt_selected]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_receipt_stratum]
    call ntp_out_text
    movzx edi, byte [rel ntp_receipt_stratum]
    call ntp_out_u64
    ; Eight bounded scalars keep the complete status below its 1400-byte buffer.
    lea  rdi, [rel str_ntp_sample_t1_1]
    call ntp_out_text
    mov  rdi, [rel ntp_sample_t1_1]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_sample_t1_2]
    call ntp_out_text
    mov  rdi, [rel ntp_sample_t1_2]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_sample_t1_3]
    call ntp_out_text
    mov  rdi, [rel ntp_sample_t1_3]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_sample_t1_4]
    call ntp_out_text
    mov  rdi, [rel ntp_sample_t1_4]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_sample_t4_1]
    call ntp_out_text
    mov  rdi, [rel ntp_sample_t4_1]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_sample_t4_2]
    call ntp_out_text
    mov  rdi, [rel ntp_sample_t4_2]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_sample_t4_3]
    call ntp_out_text
    mov  rdi, [rel ntp_sample_t4_3]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_sample_t4_4]
    call ntp_out_text
    mov  rdi, [rel ntp_sample_t4_4]
    call ntp_out_u64
    ; SEC 122036 T1 provenance, appended last (0 none, 1 owner NTPSYNC, 2 auto
    ; option 42, 3 auto default name). Full-width worst case is 1438 of 1440 (with NUL).
    lea  rdi, [rel str_ntp_origin]
    call ntp_out_text
    movzx edi, byte [rel ntp_origin]
    call ntp_out_u64
    lea  rdi, [rel str_ntp_receipt_origin]
    call ntp_out_text
    movzx edi, byte [rel ntp_receipt_origin]
    call ntp_out_u64
    mov  byte [rel ntp_cmd_out_ready], 1
    ret

; ---------------------------------------------------------------------------
; Clock unit (ROOT 122029; BOOT 121852 design; ROOT 121857(2)): once per boot,
; when the network is ready and the wall is not already NTP-set, start the one
; existing graded SNTP path. Server: the held DHCP lease's option 42, else the
; build constant PAOS_SNTP_DEFAULT resolved through the existing DNS client.
; The latch is set before any packet and never re-arms (lease renewal, route
; change, failure or a later boot of the same session all leave it). An owner
; NTPSYNC is never blocked or overridden: a busy FSM only defers this. With no
; accepted sample the wall source stays RTC and the face keeps its '~'.
; Accept rules and the one-day envelope are ntp.asm's, unchanged.
%ifndef PAOS_SNTP_DEFAULT
%define PAOS_SNTP_DEFAULT 'pool.ntp.org'
%endif
NTP_AUTO_WAIT      equ 0              ; not yet network-ready
NTP_AUTO_RESOLVING equ 1              ; default name query admitted
NTP_AUTO_STARTED   equ 2              ; ntp_sync_start_ip called (rc kept)
NTP_AUTO_STOPPED   equ 3              ; latched without a start
NTP_AUTO_R_NONE    equ 0
NTP_AUTO_R_NTP     equ 1              ; wall already NTP-set: nothing to do
NTP_AUTO_R_OPT42   equ 2              ; started at the lease's option-42 server (= NTP_ORIGIN_OPT42)
NTP_AUTO_R_DEFAULT equ 3              ; started at the resolved default name (= NTP_ORIGIN_DEFAULT)
NTP_AUTO_R_OFF     equ 4              ; built without a default name, no option 42
NTP_AUTO_R_DNS     equ 5              ; default name: refused / NX / no A
NTP_AUTO_R_DNS_TIME equ 6             ; default name: no answer within the bound
NTP_AUTO_R_OWNER   equ 7              ; an owner NTPSYNC came first this boot
NTP_AUTO_DNS_MS    equ 8000           ; backstop over DNS's own 6 s request bound

ntp_auto_tick:
    movzx eax, byte [rel ntp_auto_state]
    cmp  eax, NTP_AUTO_WAIT
    je   .wait
    cmp  eax, NTP_AUTO_RESOLVING
    je   .resolving
    ret
.wait:
    cmp  byte [rel time_wall_source], TIME_SRC_NTP
    je   .already_ntp
    cmp  byte [rel ntp_state], 1          ; NTP_ST_WAIT_ARP: an owner sync is live
    je   .out
    cmp  byte [rel ntp_state], 2          ; NTP_ST_WAIT_REPLY
    je   .out
    lea  rdi, [rel ntp_auto_route]
    call dns_wire_route_snapshot          ; 0 only with source IP, mask and MAC set
    test rax, rax
    jnz  .out                             ; no coherent route yet
    mov  edi, [rel ntp_auto_route + dns_route_snapshot.source_ip]
    call dhcp_wire_ntp_server
    test eax, eax
    jz   .default
    mov  byte [rel ntp_auto_reason], NTP_AUTO_R_OPT42
    jmp  .start
.default:
    lea  rdi, [rel ntp_auto_name]
    cmp  byte [rdi], 0
    je   .off
    call dns_resolve_start
    cmp  eax, DNS_LOOKUP_A
    je   .admitted
    cmp  eax, DNS_LOOKUP_PENDING
    jne  .dns_failed
.admitted:
    call boot_ms_now
    add  rax, NTP_AUTO_DNS_MS
    mov  [rel ntp_auto_deadline_ms], rax
    mov  byte [rel ntp_auto_state], NTP_AUTO_RESOLVING
    ret
.resolving:
    lea  rdi, [rel ntp_auto_name]
    call dns_cache_get
    cmp  eax, DNS_LOOKUP_A
    je   .resolved
    cmp  eax, DNS_LOOKUP_PENDING
    jne  .dns_failed
    call boot_ms_now
    cmp  rax, [rel ntp_auto_deadline_ms]
    jb   .out
    mov  byte [rel ntp_auto_reason], NTP_AUTO_R_DNS_TIME
    jmp  .stop
.resolved:
    mov  eax, edx
    mov  byte [rel ntp_auto_reason], NTP_AUTO_R_DEFAULT
.start:
    mov  [rel ntp_auto_server], eax
    mov  byte [rel ntp_auto_state], NTP_AUTO_STARTED ; latched before any packet
    mov  edi, eax
    movzx esi, byte [rel ntp_auto_reason] ; origin: NTP_ORIGIN_OPT42 / _DEFAULT
    call ntp_sync_start_ip                ; refuses a non-unicast server (SEC T3)
    mov  [rel ntp_auto_start_rc], rax
    ret
.already_ntp:
    mov  byte [rel ntp_auto_reason], NTP_AUTO_R_NTP
    jmp  .stop
.off:
    mov  byte [rel ntp_auto_reason], NTP_AUTO_R_OFF
    jmp  .stop
.dns_failed:
    mov  byte [rel ntp_auto_reason], NTP_AUTO_R_DNS
.stop:
    mov  byte [rel ntp_auto_state], NTP_AUTO_STOPPED
.out:
    ret

cmd_verb_ntpsync:
    call cmd_handler_prologue
    ; SEC 122045 T2 / ROOT 122048: ANY owner NTPSYNC this boot, applied,
    ; refused or in flight, spends the automatic attempt if it has not fired.
    ; Once started, the auto exchange is replaced by the FSM restart below.
    cmp  byte [rel ntp_auto_state], NTP_AUTO_STARTED
    jae  .auto_spent
    mov  byte [rel ntp_auto_reason], NTP_AUTO_R_OWNER
    mov  byte [rel ntp_auto_state], NTP_AUTO_STOPPED
.auto_spent:
    push rbx
    push r12
    mov  r12, rdi
    mov  rbx, rsi
    mov  rdi, [r12 + REQ_ARG]
    test rdi, rdi
    jz   .sync_bad
    cmp  byte [rdi], 0
    je   .sync_bad
    call ntp_sync_wall_offset
    test rax, rax
    jnz  .sync_failed
    mov  qword [rbx + RSP_ACCEPTED], 1
    mov  qword [rbx + RSP_CODE], CMDE_OK
    jmp  .sync_stage
.sync_bad:
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    jmp  .sync_stage
.sync_failed:
    mov  qword [rbx + RSP_CODE], CMDE_OK
.sync_stage:
    call ntp_stage_status
    pop  r12
    pop  rbx
    ret

cmd_verb_ntpstat:
    call cmd_handler_prologue
    push rbx
    mov  rbx, rsi
    call ntp_persist_receipt
    call ntp_stage_status
    mov  qword [rbx + RSP_CODE], CMDE_OK
    pop  rbx
    ret

ntp_cmd_out_ready: db 0
align 8
ntp_cmd_out_cur:   dq 0
ntp_cmd_out_buf:   times 1440 db 0       ; full-width status below UDP's 1464-byte content clamp
ntp_receipt_value: times 31 db 0
align 8
ntp_receipt_retry_us: dq 0

str_verb_ntpsync: db "NTPSYNC",0
str_verb_ntpstat: db "NTPSTAT",0
ntp_receipt_key: db "ntp-receipt-v1"
.len: equ $ - ntp_receipt_key
str_ntp_applied:  db " applied=",0
str_ntp_offset:   db " offset_ms=",0
str_ntp_delay:    db " delay_ms=",0
str_ntp_unixtime: db " unixtime=",0
str_ntp_stratum:  db " stratum=",0
str_ntp_state:    db " state=",0
str_ntp_reason:   db " reason=",0
str_ntp_port:     db " port=",0
str_ntp_phase:    db " timeout_phase=",0
str_ntp_arptx:    db " arp_tx=",0
str_ntp_querytx:  db " query_tx=",0
str_ntp_rxudp:    db " rx_udp=",0
str_ntp_rxmatch:  db " rx_match=",0
str_ntp_samples:  db " samples=",0
str_ntp_selected: db " selected=",0
str_ntp_wall_before: db " wall_before=",0
str_ntp_wall_after:  db " wall_after=",0
str_ntp_mono_start:  db " mono_start=",0
str_ntp_mono_commit: db " mono_commit=",0
str_ntp_reply_start: db " reply_start_ms=",0
str_ntp_reply_done:  db " reply_done_ms=",0
str_ntp_rtcr_before: db " rtc_reads_before=",0
str_ntp_rtcr_after:  db " rtc_reads_after=",0
str_ntp_rtcw_before: db " rtc_writes_before=",0
str_ntp_rtcw_after:  db " rtc_writes_after=",0
str_ntp_guard_start:    db " guard_start=",0
str_ntp_guard_deadline: db " guard_deadline=",0
str_ntp_guard_fire:     db " guard_fire=",0
str_ntp_guard_fired:    db " guard_fired=",0
str_ntp_receipt_valid:  db " receipt_valid=",0
str_ntp_receipt_persisted: db " receipt_persisted=",0
str_ntp_receipt_objid:  db " receipt_objid=",0
str_ntp_receipt_ver:    db " receipt_version=",0
str_ntp_receipt_owner:  db " receipt_owner=",0
str_ntp_receipt_schema: db " receipt_schema=",0
str_ntp_receipt_ck:     db " receipt_checksum=",0
str_ntp_receipt_utc:    db " receipt_utc_us=",0
str_ntp_receipt_offset: db " receipt_offset_fp=",0
str_ntp_receipt_delay:  db " receipt_delay_fp=",0
str_ntp_receipt_server: db " receipt_server_ip=",0
str_ntp_receipt_samples: db " receipt_samples=",0
str_ntp_receipt_selected: db " receipt_selected=",0
str_ntp_receipt_stratum: db " receipt_stratum=",0

; T1 request and T4 receive timestamps for samples= current decision, not
; historical receipt fields. Zeroed slots have not yet earned a sane sample.
str_ntp_sample_t1_1: db " t1_1=",0
str_ntp_sample_t1_2: db " t1_2=",0
str_ntp_sample_t1_3: db " t1_3=",0
str_ntp_sample_t1_4: db " t1_4=",0
str_ntp_sample_t4_1: db " t4_1=",0
str_ntp_sample_t4_2: db " t4_2=",0
str_ntp_sample_t4_3: db " t4_3=",0
str_ntp_sample_t4_4: db " t4_4=",0
str_ntp_origin:      db " origin=",0
str_ntp_receipt_origin: db " receipt_origin=",0

; An empty definition (make NASM_EXTRA="-DPAOS_SNTP_DEFAULT=''", whose quotes the
; recipe shell strips) builds no default contact: option 42 alone (ROOT 122038).
ntp_auto_name:
%ifempty PAOS_SNTP_DEFAULT
    db 0
%else
    db PAOS_SNTP_DEFAULT, 0
%endif

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
%macro WDATA_svc_command_ntp_auto 0
align 8
ntp_auto_deadline_ms: dq 0
ntp_auto_start_rc:    dq 0
ntp_auto_route:       times 24 db 0       ; dns_route_snapshot (18 bytes) + pad
ntp_auto_server:      dd 0
ntp_auto_state:       db 0
ntp_auto_reason:      db 0
%endmacro
WDATA_DEFER WDATA_svc_command_ntp_auto
