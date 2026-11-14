;; MODULE svc/boot_gates
;; LAYER 5
;; EXPORTS boot_gates_mark_ready, boot_gates_mark_dhcp, boot_gates_mark_dhcp_wire, boot_gates_tick, boot_gates_format, boot_gates_format_cell, boot_gates_d1_class, boot_gates_ms, boot_gates_buf
;; IMPORTS boot/header, boot/serial, boot/boot_v2_handoff, boot/boot_v2_health, config/keep_config, core/log, core/lib/fmt, core/time, net/dhcp, svc/command_udp
;; CAPS
;; OWNER saga:rcq32_boot_gates
; ============================================================================
; svc/boot_gates.asm — RCQ-32 slice 1 (RC spec 7.6.1-7.6.3; root 2026-10-08 14:49
; and 14:54): the payload's internal boot-gate stamps, measurement only.
;
; The writers own the moment and store one raw TSC each into boot/header's
; WDATA_boot_header_bg slots (0 = not reached):
;   bg4  boot/paging   ExitBootServices returned success
;   bg5  this module   the readiness gate passed (= the RCQ-28 G9 arm edge)
;   bg5b this module   PaOSBootReady published (idle-tick watcher on the latch;
;                      the trust-path publisher itself is untouched)
;   bg6  gui/lock_screen the first presented sign-in frame; CLI presentation
;                      uses the P7 headless login paint (boot/header)
;   bg7  core/log      the first-arrival kbd/ptr-live timeline latches
;   bg8  svc/command_udp the first successful UDP reply
; Here they are only read: every value is (tsc - boot_tsc_start) / tsc_khz,
; the same base as BOOT_MS and NOW_MS, and 0 while unset or uncalibrated.
; BG5b is a durability row, never a boot-time delta; a run without it is a
; failed run in its cell (root 14:54). Nothing here gates, skips or reorders
; a check. Formatting is compare-chosen (no pointer tables).
; ============================================================================

BOOT_GATES_BUF_SIZE equ 256

BG_D1_DIRECT    equ 0                   ; no accepted Manager handoff
BG_D1_TRIAL     equ 1
BG_D1_CONFIRMED equ 2                   ; steady or first-confirmed (the recorder splits by history)
BG_D1_ROLLBACK  equ 3
BG_D1_ANOMALY   equ 4                   ; Safe or an escalated reason (BIP, invalid state/payload, CMOS)
BG_D1_OWNER     equ 5                   ; owner-requested entry
BG_D1_RESCUE    equ 6
BG_D1_UNKNOWN   equ 7

; boot_gates_ms(RDI = raw TSC) -> RAX ms since boot_tsc_start; 0 if unset,
; earlier than the start, or the TSC is uncalibrated. clobbers RAX,RCX,RDX.
boot_gates_ms:
    xor  eax, eax
    test rdi, rdi
    jz   .out
    mov  rcx, [rel tsc_khz]
    test rcx, rcx
    jz   .out
    mov  rax, rdi
    sub  rax, [rel boot_tsc_start]
    jb   .zero
    xor  edx, edx
    div  rcx
.out:
    ret
.zero:
    xor  eax, eax
    ret

; boot_gates_d1_class(EDI = manager_launch, ESI = profile, EDX = reason) -> EAX BG_D1_*.
; Pure: the payload's view of the Boot-v2 class from the validated PBH1 handoff.
boot_gates_d1_class:
    mov  eax, BG_D1_DIRECT
    cmp  edi, 1
    jne  .out
    mov  eax, BG_D1_RESCUE
    cmp  esi, PBM_PROFILE_RESCUE
    je   .out
    cmp  edx, PBM_REASON_RESCUE
    je   .out
    mov  eax, BG_D1_OWNER
    cmp  edx, PBM_REASON_OWNER_REQUEST
    je   .out
    mov  eax, BG_D1_ANOMALY
    cmp  esi, PBM_PROFILE_SAFE
    je   .out
    mov  eax, BG_D1_UNKNOWN
    cmp  esi, PBM_PROFILE_NORMAL
    jne  .out
    mov  eax, BG_D1_CONFIRMED
    cmp  edx, PBM_REASON_HEALTHY
    je   .out
    mov  eax, BG_D1_TRIAL
    cmp  edx, PBM_REASON_TRIAL
    je   .out
    mov  eax, BG_D1_ROLLBACK
    cmp  edx, PBM_REASON_ROLLBACK
    je   .out
    mov  eax, BG_D1_ANOMALY
    cmp  edx, PBM_REASON_PREVIOUS_BIP
    je   .out
    cmp  edx, PBM_REASON_SAFE_RETRY
    je   .out
    cmp  edx, PBM_REASON_INVALID_STATE
    je   .out
    cmp  edx, PBM_REASON_INVALID_PAYLOAD
    je   .out
    cmp  edx, PBM_REASON_CMOS_UNTRUSTED
    je   .out
    mov  eax, BG_D1_UNKNOWN
.out:
    ret

; boot_gates_mark_ready: the readiness gate passed (svc/command_software_stop,
; before the G9 arm or the unmanaged publish). First call only.
boot_gates_mark_ready:
    cmp  qword [rel boot_bg5_ready_tsc], 0
    jne  .out
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [rel boot_bg5_ready_tsc], rax
    lea  rdi, [rel str_bg_marker_ready]
    jmp  boot_gates_serial
.out:
    ret

; boot_gates_tick: every BSP idle tick. Stamps BG5b once, when the strong
; health latch is first seen set.
boot_gates_tick:
    cmp  qword [rel boot_bg5b_ack_tsc], 0
    jne  .out
    cmp  byte [rel pbm_strong_health_published], 1
    jne  .out
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [rel boot_bg5b_ack_tsc], rax
    lea  rdi, [rel str_bg_marker_ack]
    jmp  boot_gates_serial
.out:
    ret

; boot_gates_serial(RDI = marker tail): one serial line with the reply keys.
boot_gates_serial:
    push rdi
    lea  rdi, [rel boot_gates_buf]
    mov  esi, BOOT_GATES_BUF_SIZE
    call boot_gates_format
    lea  rdi, [rel str_bg_serial_pre]
    call serial_string
    lea  rdi, [rel boot_gates_buf]
    call serial_string
    pop  rdi
    jmp  serial_string

; boot_gates_format(RDI = buf, ESI = cap >= 1) -> RAX length. Every reply:
;   " NOW_MS= bg4_ebs_ms= bg5_ready_ms= bg5b_ack_ms= bg6_first_pixel_ms= bg7_input_ms= bg8_first_udp_ms="
boot_gates_format:
    call bg_open
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  rsi, rax
    lea  rdi, [rel str_bg_now]
    call bg_put_key_ms
    lea  rdi, [rel str_bg4]
    mov  rsi, [rel boot_bg4_ebs_tsc]
    call bg_put_key_ms
    lea  rdi, [rel str_bg5]
    mov  rsi, [rel boot_bg5_ready_tsc]
    call bg_put_key_ms
    lea  rdi, [rel str_bg5b]
    mov  rsi, [rel boot_bg5b_ack_tsc]
    call bg_put_key_ms
    call bg_bg6_tsc
    mov  rsi, rax
    lea  rdi, [rel str_bg6]
    call bg_put_key_ms
    call bg_bg7_tsc
    mov  rsi, rax
    lea  rdi, [rel str_bg7]
    call bg_put_key_ms
    lea  rdi, [rel str_bg8]
    mov  rsi, [rel udp_first_reply_tsc]
    call bg_put_key_ms
    jmp  bg_close

; boot_gates_format_cell(RDI = buf, ESI = cap >= 1) -> RAX length. STATUS only:
;   " FIRST_UDP_MS=<raw> d1=<class>:<reason> bv2=<L><E><P><R>/<flags hex>
;     d2=log:<mode>/<trigger>,menu:<0|1>,selftests:<full|gated>
;     d3=handoff:<accepted|none>,selftests:<n>/<pass>/<fail>/<skip> bg6_src=<signin|cli-login>"
; FIRST_UDP_MS keeps its existing raw post-reset TSC meaning (FULL BOOTLOG).
boot_gates_format_cell:
    call bg_open
    lea  rdi, [rel str_bg_first_udp]
    call bg_put_str
    xor  eax, eax
    mov  rcx, [rel tsc_khz]
    test rcx, rcx
    jz   .first_udp
    mov  rax, [rel udp_first_reply_tsc]
    xor  edx, edx
    div  rcx
.first_udp:
    mov  rdi, rax
    call bg_put_dec

    lea  rdi, [rel str_bg_d1]
    call bg_put_str
    movzx edi, byte [rel pbm_manager_launch]
    movzx esi, byte [rel pbm_profile]
    movzx edx, byte [rel pbm_reason]
    call boot_gates_d1_class
    lea  rdi, [rel str_d1_direct]
    cmp  eax, BG_D1_DIRECT
    je   .d1_emit
    lea  rdi, [rel str_d1_trial]
    cmp  eax, BG_D1_TRIAL
    je   .d1_emit
    lea  rdi, [rel str_d1_confirmed]
    cmp  eax, BG_D1_CONFIRMED
    je   .d1_emit
    lea  rdi, [rel str_d1_rollback]
    cmp  eax, BG_D1_ROLLBACK
    je   .d1_emit
    lea  rdi, [rel str_d1_anomaly]
    cmp  eax, BG_D1_ANOMALY
    je   .d1_emit
    lea  rdi, [rel str_d1_owner]
    cmp  eax, BG_D1_OWNER
    je   .d1_emit
    lea  rdi, [rel str_d1_rescue]
    cmp  eax, BG_D1_RESCUE
    je   .d1_emit
    lea  rdi, [rel str_d1_unknown]
.d1_emit:
    call bg_put_str
    lea  rdi, [rel str_bg_colon]
    call bg_put_str
    call bg_reason_str
    call bg_put_str

    lea  rdi, [rel str_bg_bv2]
    call bg_put_str
    movzx edi, byte [rel pbm_manager_launch]
    call bg_put_dec
    movzx edi, byte [rel pbm_entry]
    call bg_put_dec
    movzx edi, byte [rel pbm_profile]
    call bg_put_dec
    movzx edi, byte [rel pbm_reason]
    call bg_put_dec
    lea  rdi, [rel str_bg_slash]
    call bg_put_str
    movzx edi, byte [rel pbm_flags]
    call bg_put_hex8

    lea  rdi, [rel str_bg_d2_log]
    call bg_put_str
    lea  rdi, [rel str_d2_verbose]
    cmp  byte [rel boot_log_mode], LOG_MODE_LEAN
    jne  .d2_mode
    lea  rdi, [rel str_d2_lean]
.d2_mode:
    call bg_put_str
    lea  rdi, [rel str_bg_slash]
    call bg_put_str
    movzx eax, byte [rel boot_log_trigger]
    lea  rdi, [rel str_d2_clean]
    cmp  eax, LOG_TRIGGER_CLEAN
    je   .d2_trigger
    lea  rdi, [rel str_d2_trial]
    cmp  eax, LOG_TRIGGER_TRIAL
    je   .d2_trigger
    lea  rdi, [rel str_d2_faults]
    cmp  eax, LOG_TRIGGER_FAULTS
    je   .d2_trigger
    lea  rdi, [rel str_d2_first]
    cmp  eax, LOG_TRIGGER_FIRST
    je   .d2_trigger
    lea  rdi, [rel str_d2_override]
    cmp  eax, LOG_TRIGGER_OVERRIDE
    je   .d2_trigger
    lea  rdi, [rel str_d1_unknown]
.d2_trigger:
    call bg_put_str
    lea  rdi, [rel str_bg_d2_menu]
    call bg_put_str
    movzx edi, byte [rel pbm_flags]
    shr  edi, 1                         ; PBM_HF_MENU_WAS_VISIBLE = 0x02
    and  edi, 1
    call bg_put_dec
    lea  rdi, [rel str_bg_d2_selftests]
    call bg_put_str
    lea  rdi, [rel str_d2_full]
    cmp  byte [rel boot_budget_force_full], 0
    jne  .d2_selftests
    cmp  byte [rel boot_budget_class], BOOT_CLASS_TRIAL
    je   .d2_selftests
    lea  rdi, [rel str_d2_gated]
.d2_selftests:
    call bg_put_str

    lea  rdi, [rel str_bg_d3_handoff]
    call bg_put_str
    lea  rdi, [rel str_d3_none]
    cmp  byte [rel pbm_manager_launch], 1
    jne  .d3_handoff
    lea  rdi, [rel str_d3_accepted]
.d3_handoff:
    call bg_put_str
    lea  rdi, [rel str_bg_d3_selftests]
    call bg_put_str
    mov  edi, [rel selftest_verdict_count]
    call bg_put_dec
    lea  rdi, [rel str_bg_slash]
    call bg_put_str
    mov  edi, [rel selftest_verdict_passes]
    call bg_put_dec
    lea  rdi, [rel str_bg_slash]
    call bg_put_str
    mov  edi, [rel selftest_verdict_fails]
    call bg_put_dec
    lea  rdi, [rel str_bg_slash]
    call bg_put_str
    mov  edi, [rel selftest_verdict_skips]
    call bg_put_dec

    lea  rdi, [rel str_bg6_src]
    call bg_put_str
    lea  rdi, [rel str_bg6_signin]
    cmp  byte [rel keep_presentation_target], PRESENTATION_CLI
    jne  .bg6_src
    lea  rdi, [rel str_bg6_cli]
.bg6_src:
    call bg_put_str
    jmp  bg_close

; -> RDI = the PBM reason name for pbm_reason.
bg_reason_str:
    movzx eax, byte [rel pbm_reason]
    lea  rdi, [rel str_r_healthy]
    cmp  eax, PBM_REASON_HEALTHY
    je   .out
    lea  rdi, [rel str_r_owner]
    cmp  eax, PBM_REASON_OWNER_REQUEST
    je   .out
    lea  rdi, [rel str_r_trial]
    cmp  eax, PBM_REASON_TRIAL
    je   .out
    lea  rdi, [rel str_r_previous_bip]
    cmp  eax, PBM_REASON_PREVIOUS_BIP
    je   .out
    lea  rdi, [rel str_r_safe_retry]
    cmp  eax, PBM_REASON_SAFE_RETRY
    je   .out
    lea  rdi, [rel str_r_rollback]
    cmp  eax, PBM_REASON_ROLLBACK
    je   .out
    lea  rdi, [rel str_r_invalid_state]
    cmp  eax, PBM_REASON_INVALID_STATE
    je   .out
    lea  rdi, [rel str_r_invalid_payload]
    cmp  eax, PBM_REASON_INVALID_PAYLOAD
    je   .out
    lea  rdi, [rel str_r_rescue]
    cmp  eax, PBM_REASON_RESCUE
    je   .out
    lea  rdi, [rel str_r_cmos_untrusted]
    cmp  eax, PBM_REASON_CMOS_UNTRUSTED
    je   .out
    lea  rdi, [rel str_d1_unknown]
.out:
    ret

; BG6: CLI presentation paints its login at P7; GUI presents the sign-in surface.
bg_bg6_tsc:
    mov  rax, [rel boot_bg6_pixel_tsc]
    cmp  byte [rel keep_presentation_target], PRESENTATION_CLI
    jne  .out
    mov  rax, [rel boot_p7_tsc]
.out:
    ret

; BG7: the earlier of the kbd-live and ptr-live first-arrival records (0 if neither).
bg_bg7_tsc:
    mov  edi, BOOT_TIMELINE_ID_INPUT_KBD_LIVE
    call bg_timeline_tsc
    mov  r8, rax
    mov  edi, BOOT_TIMELINE_ID_INPUT_PTR_LIVE
    call bg_timeline_tsc
    test r8, r8
    jz   .out
    test rax, rax
    jz   .kbd
    cmp  rax, r8
    jbe  .out
.kbd:
    mov  rax, r8
.out:
    ret

; bg_timeline_tsc(EDI = timeline id) -> RAX its first-arrival TSC, 0 if absent.
bg_timeline_tsc:
    lea  rsi, [rel boot_timeline_records]
    mov  ecx, [rel boot_timeline_count]
    cmp  ecx, BOOT_TIMELINE_MAX
    jbe  .scan
    mov  ecx, BOOT_TIMELINE_MAX
.scan:
    test ecx, ecx
    jz   .none
    cmp  word [rsi], di
    je   .hit
    add  rsi, BOOT_TIMELINE_REC_SIZE
    dec  ecx
    jmp  .scan
.hit:
    mov  rax, [rsi + 2]
    ret
.none:
    xor  eax, eax
    ret

; Measurement only (BOOTCLOCK v6 `dhcp`): first usable lease, latched once by
; command_udp_dhcp_accept after dhcp_wire_mark_bound. First arrival wins (a later
; renew keeps the stamp). Preserves every GPR; no wait, policy or gate.
boot_gates_mark_dhcp:
    push rdi
    mov  edi, BOOT_TIMELINE_ID_DHCP_BOUND
    call boot_timeline_latch
    pop  rdi
    ret

; Measurement only, after each DHCP start/tick/ingest: the first DISCOVER the
; wire accepted and the first OFFER the client accepted (it sends REQUEST in
; the same ingest).  dhcp.asm's own m_discover/m_offer flags are the source;
; first arrival is kept by boot_timeline_latch.  Preserves every register and
; RFLAGS, so a caller may insert it between a call and its result test.
boot_gates_mark_dhcp_wire:
    pushfq
    push rdi
    cmp  byte [rel dhcp_wire_m_discover], 0
    je   .offer
    mov  edi, BOOT_TIMELINE_ID_DHCP_DISCOVER
    call boot_timeline_latch
.offer:
    cmp  byte [rel dhcp_wire_m_offer], 0
    je   .done
    mov  edi, BOOT_TIMELINE_ID_DHCP_OFFER
    call boot_timeline_latch
.done:
    pop  rdi
    popfq
    ret

; Bounded appender over [bg_cur, bg_lim); always NUL-terminated.
bg_open:
    mov  [rel bg_start], rdi
    mov  [rel bg_cur], rdi
    lea  rax, [rdi + rsi - 1]
    mov  [rel bg_lim], rax
    mov  byte [rdi], 0
    ret

bg_close:
    mov  rax, [rel bg_cur]
    sub  rax, [rel bg_start]
    ret

bg_put_str:
    mov  rax, [rel bg_cur]
.loop:
    mov  cl, [rdi]
    test cl, cl
    jz   .done
    cmp  rax, [rel bg_lim]
    jae  .done
    mov  [rax], cl
    inc  rax
    inc  rdi
    jmp  .loop
.done:
    mov  byte [rax], 0
    mov  [rel bg_cur], rax
    ret

bg_put_dec:
    lea  rsi, [rel bg_num]
    call fmt_dec
    lea  rdi, [rel bg_num]
    jmp  bg_put_str

; EDI = byte -> two lowercase hex digits.
bg_put_hex8:
    mov  eax, edi
    shr  eax, 4
    and  eax, 0x0f
    mov  ecx, edi
    and  ecx, 0x0f
    lea  rdx, [rel str_bg_hexdigits]
    mov  al, [rdx + rax]
    mov  cl, [rdx + rcx]
    mov  [rel bg_num], al
    mov  [rel bg_num + 1], cl
    mov  byte [rel bg_num + 2], 0
    lea  rdi, [rel bg_num]
    jmp  bg_put_str

; RDI = key, RSI = raw TSC -> key + ms.
bg_put_key_ms:
    push rsi
    call bg_put_str
    pop  rdi
    call boot_gates_ms
    mov  rdi, rax
    jmp  bg_put_dec

%include "core/abi/wdata.inc"
%macro WDATA_svc_boot_gates 0
bg_start:       resq 1
bg_cur:         resq 1
bg_lim:         resq 1
bg_num:         resb 24
boot_gates_buf: resb BOOT_GATES_BUF_SIZE
%endmacro
WDATA_BSS_DEFER WDATA_svc_boot_gates

str_bg_serial_pre:  db "[PAOS64] boot-gates:", 0
str_bg_marker_ready: db " [boot.gates.ready]", 13, 10, 0
str_bg_marker_ack:  db " [boot.gates.ack]", 13, 10, 0
str_bg_now:         db " NOW_MS=", 0
str_bg4:            db " bg4_ebs_ms=", 0
str_bg5:            db " bg5_ready_ms=", 0
str_bg5b:           db " bg5b_ack_ms=", 0
str_bg6:            db " bg6_first_pixel_ms=", 0
str_bg7:            db " bg7_input_ms=", 0
str_bg8:            db " bg8_first_udp_ms=", 0
str_bg_first_udp:   db " FIRST_UDP_MS=", 0
str_bg_d1:          db " d1=", 0
str_bg_bv2:         db " bv2=", 0
str_bg_d2_log:      db " d2=log:", 0
str_bg_d2_menu:     db ",menu:", 0
str_bg_d2_selftests: db ",selftests:", 0
str_bg_d3_handoff:  db " d3=handoff:", 0
str_bg_d3_selftests: db ",selftests:", 0
str_bg6_src:        db " bg6_src=", 0
str_bg_colon:       db ":", 0
str_bg_slash:       db "/", 0
str_bg_hexdigits:   db "0123456789abcdef"
str_d1_direct:      db "direct", 0
str_d1_trial:       db "trial", 0
str_d1_confirmed:   db "confirmed", 0
str_d1_rollback:    db "rollback", 0
str_d1_anomaly:     db "anomaly", 0
str_d1_owner:       db "owner", 0
str_d1_rescue:      db "rescue", 0
str_d1_unknown:     db "unknown", 0
str_r_healthy:      db "healthy", 0
str_r_owner:        db "owner-request", 0
str_r_trial:        db "trial", 0
str_r_previous_bip: db "previous-bip", 0
str_r_safe_retry:   db "safe-retry", 0
str_r_rollback:     db "rollback", 0
str_r_invalid_state: db "invalid-state", 0
str_r_invalid_payload: db "invalid-payload", 0
str_r_rescue:       db "rescue", 0
str_r_cmos_untrusted: db "cmos-untrusted", 0
str_d2_lean:        db "lean", 0
str_d2_verbose:     db "verbose", 0
str_d2_clean:       db "clean", 0
str_d2_trial:       db "trial", 0
str_d2_faults:      db "faults", 0
str_d2_first:       db "first", 0
str_d2_override:    db "override", 0
str_d2_full:        db "full", 0
str_d2_gated:       db "gated", 0
str_d3_accepted:    db "accepted", 0
str_d3_none:        db "none", 0
str_bg6_signin:     db "signin", 0
str_bg6_cli:        db "cli-login", 0
