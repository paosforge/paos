;; MODULE svc/command_software_stop
;; LAYER 5
;; EXPORTS software_stop_checkpoint, software_stop_declare, software_stop_qemu_selftest, software_stop_publish_strong_health, software_stop_stability_tick, software_stop_stability_exit_hook, software_stop_stability_state, boot_phase_tsc, c3wd_out_buf, c3wd_out_cur, c3wd_out_ready, c3wd_checkpoint_rc
;; IMPORTS boot/header, boot/serial, boot/boot_v2_handoff, boot/boot_v2_health, core/diag, svc/command, net/netdev, fs/blockdev, svc/boot_gates, svc/command_udp
;; CAPS
;; OWNER saga:boot_v2_ge_c3_software_stop_watchdog_ladder
; ============================================================================
; GE C3 software-stop watchdog ladder observation.
;
; The Manager journal records the armed attempt; PaOSInitCheckpoint records the
; stopped stage used by the recovery policy.  At PaOS's existing strong-health
; boundary this module requires the exact-read-back P0-P8 graph to be complete.
; Recovery remains Manager-owned: one Safe attempt per verified slot, then
; another verified/known-good slot, then independent Rescue.  This module does
; not reset, edit the ESP, or claim the refuted PCH-TCO countdown.  C3WATCH
; projects the exact final checkpoint plus the Manager-bound state that was
; read before EBS, so a healthy boot cannot counterfeit recovery evidence.
; ============================================================================

C3WD_ROUTE_VISIBLE_STOP equ 0
C3WD_ROUTE_SAFE         equ 1
C3WD_ROUTE_KNOWN_GOOD   equ 2
C3WD_ROUTE_RESCUE       equ 3
C3WD_OUT_CAP            equ 640  ; 512 cannot hold the P3 timing fields; C7HV precedent
C3WD_NET_PUBLISH        equ 0
C3WD_NET_DEFER          equ 1
C3WD_NET_WITHHOLD       equ 2
; P3 in-memory timing validity labels (C3WATCH p3_start_status/p3_total_status).
C3WD_P3_NONE            equ 0   ; no P3 edge measured this boot
C3WD_P3_VALID           equ 1
C3WD_P3_CLOCK           equ 2   ; uncalibrated/missing/backwards boot_ms_now
C3WD_P3_RECORD          equ 3   ; record stale, nonmatching or not durable
C3WD_P3_RC              equ 4   ; STARTING transition returned nonzero
C3WD_P3_ARMED           equ 5   ; internal: before-sample taken, call in flight

%if PBM_MENU_TIMEOUT_MIN != 3 || PBM_MENU_TIMEOUT_MAX != 30
    %error "GE C3 requires the retained Task1179 3..30 second Manager timeout bound"
%endif

; Pure projection of the Manager's frozen ordering, used only by the QEMU KAT.
; EDI=current slot bit, ESI=Verified mask, EDX=Safe-attempted mask,
; ECX=other slot bit, R8D=Rescue present, R9D=quarantine mask.
software_stop_select_route:
    mov  eax, esi
    and  eax, edi
    jz   .known_good
    mov  r10d, r9d
    and  r10d, edi
    jnz  .known_good
    mov  r10d, edx
    and  r10d, edi
    jnz  .known_good
    mov  eax, C3WD_ROUTE_SAFE
    ret
.known_good:
    mov  eax, esi
    and  eax, ecx
    jz   .rescue
    mov  r10d, r9d
    and  r10d, ecx
    jnz  .rescue
    mov  eax, C3WD_ROUTE_KNOWN_GOOD
    ret
.rescue:
    test r8d, r8d
    jz   .visible_stop
    mov  eax, C3WD_ROUTE_RESCUE
    ret
.visible_stop:
    mov  eax, C3WD_ROUTE_VISIBLE_STOP
    ret

; Persist one real boot edge through the proven checkpoint API.
; EDI=stage P0..P8, ESI=STARTING|COMPLETED, EDX=0 (primary subsystem).
; Direct/Safe/Rescue launches are exact no-ops.  Optional-budget degradation is
; a valid completed graph edge; every other nonzero return is latched so later
; edges cannot overwrite the first failure and strong health remains blocked.
software_stop_checkpoint:
    push r12
    mov  [rel c3wd_requested_stage], dil
    mov  [rel c3wd_requested_transition], sil
    call software_stop_phase_stamp
    movzx edi, byte [rel c3wd_requested_stage]
    movzx esi, byte [rel c3wd_requested_transition]
    xor  edx, edx
    movzx r12d, byte [rel c3wd_checkpoint_rc]
    test r12d, r12d
    jnz  .latched
    cmp  byte [rel pbm_manager_launch], 1
    jne  .not_managed_attempt
    test byte [rel pbm_flags], PBM_HF_MUTABLE_ATTEMPT
    jz   .not_managed_attempt
    cmp  byte [rel pbm_profile], PBM_PROFILE_NORMAL
    jne  .not_managed_attempt
    movzx eax, byte [rel pbm_entry]
    cmp  eax, PBM_ENTRY_PAOS_A
    je   .identity_ok
    cmp  eax, PBM_ENTRY_PAOS_B
    jne  .not_managed_attempt
.identity_ok:
    cmp  qword [rel pbm_manager_sequence], 0
    je   .identity_failed
    cmp  qword [rel pbm_attempt_nonce], 0
    je   .identity_failed

    call software_stop_p3_start_begin
    movzx edi, byte [rel c3wd_requested_stage]
    movzx esi, byte [rel c3wd_requested_transition]
    xor  edx, edx
    call boot_v2_init_checkpoint_transition
    mov  r12d, eax
    mov  edi, eax
    call software_stop_p3_observe
    cmp  byte [rel c3wd_requested_stage], PBM_INIT_STAGE_P6
    jne  .checkpoint_result
    cmp  byte [rel c3wd_requested_transition], PBM_INIT_TRANSITION_COMPLETED
    jne  .checkpoint_result
    mov  eax, [rel pbm_init_checkpoint_record + PBM_INIT_ELAPSED_MS_OFF]
    mov  [rel c3wd_p6_elapsed_ms], eax
    mov  eax, [rel pbm_init_checkpoint_record + PBM_INIT_BUDGET_MS_OFF]
    mov  [rel c3wd_p6_budget_ms], eax
.checkpoint_result:
    mov  eax, r12d
    cmp  eax, PBM_INIT_RC_DEGRADED
    je   .ok
    test eax, eax
    jnz  .failed
.ok:
.not_managed_attempt:
    xor  eax, eax
    pop  r12
    ret
.latched:
    mov  eax, r12d
    pop  r12
    ret
.identity_failed:
    mov  eax, PBM_INIT_RC_ARGUMENT
    jmp  .failed
.failed:
    mov  [rel c3wd_checkpoint_rc], al
    mov  r12d, eax
    call software_stop_emit_failure
    lea  rdi, [rel str_c3wd_checkpoint_failed]
    call serial_string
    mov  eax, r12d
    pop  r12
    ret

; P3 timing observation (in-memory only; never persists or changes the rc).
; The record's started_ms is stamped before the synchronous STARTING persist,
; so P3 elapsed mixes firmware latency with stage body time.  These helpers
; bracket only the first managed P3 STARTING transition of this boot and keep
; P3's own elapsed/budget after later stages overwrite the shared record.
software_stop_p3_start_begin:
    cmp  byte [rel c3wd_requested_stage], PBM_INIT_STAGE_P3
    jne  .out
    cmp  byte [rel c3wd_requested_transition], PBM_INIT_TRANSITION_STARTING
    jne  .out
    cmp  byte [rel c3wd_p3_start_status], C3WD_P3_NONE
    jne  .out                            ; repeated request keeps the first timing
    call boot_ms_now
    mov  [rel c3wd_p3_before_ms], eax
    mov  byte [rel c3wd_p3_start_status], C3WD_P3_ARMED
.out:
    ret

; EDI=transition rc (preserved by the caller in R12D).
software_stop_p3_observe:
    cmp  byte [rel c3wd_requested_stage], PBM_INIT_STAGE_P3
    jne  .out
    cmp  byte [rel c3wd_requested_transition], PBM_INIT_TRANSITION_COMPLETED
    je   .total
    cmp  byte [rel c3wd_p3_start_status], C3WD_P3_ARMED
    jne  .out
    mov  r9d, edi
    call boot_ms_now
    mov  r8d, eax
    mov  ecx, [rel c3wd_p3_before_ms]
    mov  dl, C3WD_P3_CLOCK
    test ecx, ecx
    jz   .start_store                    ; boot_ms_now is 0 when uncalibrated
    cmp  r8d, ecx
    jb   .start_store
    mov  eax, r8d
    sub  eax, ecx
    mov  [rel c3wd_p3_start_ms], eax
    mov  dl, C3WD_P3_RC
    test r9d, r9d
    jnz  .start_store
    mov  dl, C3WD_P3_RECORD
    call software_stop_p3_record_current
    jne  .start_store
    cmp  byte [rel pbm_init_checkpoint_record + PBM_INIT_TRANSITION_OFF], PBM_INIT_TRANSITION_STARTING
    jne  .start_store
    mov  eax, [rel pbm_init_checkpoint_record + PBM_INIT_STARTED_MS_OFF]
    cmp  eax, ecx                        ; a fresh write stamps inside the bracket
    jb   .start_store
    cmp  eax, r8d
    ja   .start_store
    mov  [rel c3wd_p3_started_ms], eax
    mov  dl, C3WD_P3_VALID
.start_store:
    mov  [rel c3wd_p3_start_status], dl
    ret
.total:
    cmp  byte [rel c3wd_p3_total_status], C3WD_P3_NONE
    jne  .out
    mov  dl, C3WD_P3_RECORD
    call software_stop_p3_record_current
    jne  .total_store
    mov  eax, [rel pbm_init_checkpoint_record + PBM_INIT_ELAPSED_MS_OFF]
    mov  [rel c3wd_p3_elapsed_ms], eax
    mov  eax, [rel pbm_init_checkpoint_record + PBM_INIT_BUDGET_MS_OFF]
    mov  [rel c3wd_p3_budget_ms], eax
    mov  dl, C3WD_P3_CLOCK
    cmp  dword [rel c3wd_p3_elapsed_ms], 0
    je   .total_store                    ; finish clock was uncalibrated/backwards
    mov  dl, C3WD_P3_RECORD
    cmp  byte [rel c3wd_p3_start_status], C3WD_P3_VALID
    jne  .total_store
    mov  eax, [rel pbm_init_checkpoint_record + PBM_INIT_STARTED_MS_OFF]
    cmp  eax, [rel c3wd_p3_started_ms]
    jne  .total_store
    mov  dl, C3WD_P3_VALID
.total_store:
    mov  [rel c3wd_p3_total_status], dl
.out:
    ret

; ZF=1 when the loaded durable record is P3 of the current Manager attempt.
software_stop_p3_record_current:
    cmp  byte [rel pbm_init_checkpoint_loaded], 1
    jne  .out
    cmp  byte [rel pbm_init_checkpoint_durable], 1
    jne  .out
    cmp  byte [rel pbm_init_checkpoint_record + PBM_INIT_STAGE_OFF], PBM_INIT_STAGE_P3
    jne  .out
    mov  rax, [rel pbm_attempt_nonce]
    cmp  rax, [rel pbm_init_checkpoint_record + PBM_INIT_ATTEMPT_NONCE_OFF]
    jne  .out
    mov  rax, [rel pbm_manager_sequence]
    cmp  rax, [rel pbm_init_checkpoint_record + PBM_INIT_MANAGER_SEQ_OFF]
.out:
    ret

; Capture every existing C3WD_EDGE in one fixed start/complete table. P0 and
; P1-start precede diag_init, so P1-complete replays those original timestamps
; into the newly-live ring. P2-start and every later edge append immediately.
; Observation is independent of Manager mutability/profile; the persistence
; policy in software_stop_checkpoint remains Manager-owned.
software_stop_phase_stamp:
    push rbx
    push r12
    push r13
    mov  r12d, edi
    mov  r13d, esi
    cmp  r12d, PBM_INIT_STAGE_P8
    ja   .out
    cmp  r13d, PBM_INIT_TRANSITION_STARTING
    je   .slot
    cmp  r13d, PBM_INIT_TRANSITION_COMPLETED
    jne  .out
.slot:
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    lea  rbx, [rel boot_phase_tsc]
    mov  ecx, r12d
    shl  ecx, 4
    add  rbx, rcx
    cmp  r13d, PBM_INIT_TRANSITION_COMPLETED
    jne  .store
    add  rbx, 8
.store:
    mov  [rbx], rax

    cmp  r12d, PBM_INIT_STAGE_P1
    jb   .out
    jne  .append_live
    cmp  r13d, PBM_INIT_TRANSITION_COMPLETED
    jne  .out
    ; diag_init has just completed: replay P0 start through P1 complete once.
    lea  rbx, [rel boot_phase_tsc]
    xor  r13d, r13d
.replay:
    mov  rdx, [rbx + r13*8]
    test rdx, rdx
    jz   .replay_next
    mov  edi, r13d
    shr  edi, 1
    mov  esi, PBM_INIT_TRANSITION_STARTING
    test r13d, 1
    jz   .replay_append
    mov  esi, PBM_INIT_TRANSITION_COMPLETED
.replay_append:
    call diag_boot_phase_record
.replay_next:
    inc  r13d
    cmp  r13d, 4
    jb   .replay
    jmp  .out

.append_live:
    mov  edi, r12d
    mov  esi, r13d
    mov  rdx, rax
    call diag_boot_phase_record
    cmp  r12d, PBM_INIT_STAGE_P8
    jne  .out
    cmp  r13d, PBM_INIT_TRANSITION_COMPLETED
    jne  .out
    call software_stop_phase_ordering_kat
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Earn the public marker only when all 18 edges exist in the fixed C3 order.
software_stop_phase_ordering_kat:
    lea  rdx, [rel boot_phase_tsc]
    xor  ecx, ecx
    xor  r8d, r8d
.scan:
    mov  rax, [rdx + rcx*8]
    test rax, rax
    jz   .fail
    test ecx, ecx
    jz   .next
    cmp  rax, r8
    jb   .fail
.next:
    mov  r8, rax
    inc  ecx
    cmp  ecx, 18
    jb   .scan
    lea  rdi, [rel str_boot_phases_recorded]
    call serial_string
    ret
.fail:
    lea  rdi, [rel str_boot_phases_failed]
    call serial_string
    ret

; The health edge is deliberately wrapped rather than followed by a
; proceed-anyway branch in header.asm.  A checkpoint persistence failure or an
; incomplete P0-P8 graph leaves the Manager's BIP journal set and therefore
; routes the next attempt through its bounded Safe/known-good/Rescue policy.
software_stop_publish_strong_health:
    pushfq
    push rax
    mov  eax, 34
    call command_udp_progress_enter
    pop  rax
    popfq
    push rbx
    movzx edi, byte [rel net_required]
    movzx esi, byte [rel boot_nic_state]
    call software_stop_net_gate_decide
    HP_FIRST                         ; actual returned EAX, before original branch
    cmp  eax, C3WD_NET_PUBLISH
    je   .network_satisfied
    cmp  eax, C3WD_NET_WITHHOLD
    jne  .out                            ; WARMING/unknown: watcher retries on resolution
    cmp  byte [rel c3wd_net_withheld], 1
    je   .out
    mov  byte [rel c3wd_net_withheld], 1
    HP_NET_REFUSAL                       ; opt-in returned first-DEFER refusal only
    lea  rdi, [rel str_c3wd_net_withheld]
    call serial_string                   ; PARKED/absent refusal is never silent
    jmp  .out
.network_satisfied:
    cmp  byte [rel pbm_manager_launch], 1
    jne  .publish                        ; original publisher performs its no-op gate
    test byte [rel pbm_flags], PBM_HF_MUTABLE_ATTEMPT
    jz   .publish
    cmp  byte [rel pbm_profile], PBM_PROFILE_NORMAL
    jne  .publish
    movzx eax, byte [rel pbm_entry]
    cmp  eax, PBM_ENTRY_PAOS_A
    je   .managed
    cmp  eax, PBM_ENTRY_PAOS_B
    jne  .publish
.managed:
    movzx eax, byte [rel c3wd_checkpoint_rc]
    test eax, eax
%if PAOS_HEALTH_PROGRESS
    jz   .checkpoint_ok
    HP_TERMINAL 2                    ; actual sticky checkpoint refusal
    jmp  .out
.checkpoint_ok:
%else
    jnz  .out
%endif
    cmp  byte [rel pbm_init_checkpoint_loaded], 1
    jne  .incomplete
    cmp  byte [rel pbm_init_checkpoint_durable], 1
    jne  .incomplete
    cmp  byte [rel pbm_init_checkpoint_record + PBM_INIT_STAGE_OFF], PBM_INIT_STAGE_P8
    jne  .incomplete
    cmp  byte [rel pbm_init_checkpoint_record + PBM_INIT_TRANSITION_OFF], PBM_INIT_TRANSITION_COMPLETED
    jne  .incomplete
    cmp  byte [rel pbm_init_checkpoint_record + PBM_INIT_RESULT_OFF], PBM_INIT_RESULT_HEALTHY
    jne  .incomplete
    cmp  word [rel pbm_init_checkpoint_record + PBM_INIT_COMPLETED_MASK_OFF], PBM_INIT_STAGE_ALL_MASK
    jne  .incomplete
    ; G9: readiness ARMS the post-readiness stability window; the stability tick
    ; publishes the unchanged PaOSBootReady only after it (or never).
    call boot_gates_mark_ready           ; RCQ-32 BG5: the readiness edge (stamp only)
    call software_stop_stability_arm
    jmp  .out
.publish:
    call boot_gates_mark_ready           ; RCQ-32 BG5: the readiness edge (stamp only)
    pushfq
    push rax
    mov  eax, 35
    call command_udp_progress_enter
    pop  rax
    popfq
    call boot_v2_publish_strong_health
    HP_TERMINAL 3                    ; guarded publisher returned, not Ready proof
    pushfq
    push rax
    mov  eax, 35
    call command_udp_progress_complete
    pop  rax
    popfq
    jmp  .out
.incomplete:
    mov  byte [rel c3wd_checkpoint_rc], PBM_INIT_RC_TRANSITION
    mov  eax, PBM_INIT_RC_TRANSITION
    call software_stop_emit_failure
    lea  rdi, [rel str_c3wd_checkpoint_failed]
    call serial_string
    mov  eax, PBM_INIT_RC_TRANSITION
    HP_TERMINAL 2
.out:
    pop  rbx
    pushfq
    push rax
    mov  eax, 34
    call command_udp_progress_complete
    pop  rax
    popfq
    ret

; Pure predicate shared by the publisher and its QEMU KAT.
; EDI=net_required, ESI=NIC_ST_*; EAX=C3WD_NET_{PUBLISH,DEFER,WITHHOLD}.
; Unknown states fail closed as DEFER rather than minting authority.
software_stop_net_gate_decide:
    test edi, edi
    jz   .publish
    cmp  esi, NIC_ST_READY
    je   .publish
    cmp  esi, NIC_ST_PARKED
    je   .withhold
    mov  eax, C3WD_NET_DEFER
    ret
.withhold:
    mov  eax, C3WD_NET_WITHHOLD
    ret
.publish:
    mov  eax, C3WD_NET_PUBLISH
    ret

; Preserve enough bounded serial state to distinguish a rejected requested
; edge from a persisted-record/clock failure even when Manager rolls the Trial
; back before C3WATCH can be queried.  EAX=PBM_INIT_RC_* and is preserved.
software_stop_emit_failure:
    push rbx
    mov  ebx, eax
    lea  rdi, [rel str_c3wd_diag_rc]
    call serial_string
    mov  edi, ebx
    call serial_hex64
    lea  rdi, [rel str_c3wd_diag_request_stage]
    call serial_string
    movzx edi, byte [rel c3wd_requested_stage]
    call serial_hex64
    lea  rdi, [rel str_c3wd_diag_request_transition]
    call serial_string
    movzx edi, byte [rel c3wd_requested_transition]
    call serial_hex64
    lea  rdi, [rel str_c3wd_diag_record_stage]
    call serial_string
    movzx edi, byte [rel pbm_init_checkpoint_record + PBM_INIT_STAGE_OFF]
    call serial_hex64
    lea  rdi, [rel str_c3wd_diag_record_transition]
    call serial_string
    movzx edi, byte [rel pbm_init_checkpoint_record + PBM_INIT_TRANSITION_OFF]
    call serial_hex64
    lea  rdi, [rel str_c3wd_diag_result]
    call serial_string
    movzx edi, byte [rel pbm_init_checkpoint_record + PBM_INIT_RESULT_OFF]
    call serial_hex64
    lea  rdi, [rel str_c3wd_diag_durable]
    call serial_string
    movzx edi, byte [rel pbm_init_checkpoint_durable]
    call serial_hex64
    lea  rdi, [rel str_c3wd_diag_mask]
    call serial_string
    movzx edi, word [rel pbm_init_checkpoint_record + PBM_INIT_COMPLETED_MASK_OFF]
    call serial_hex64
    lea  rdi, [rel str_c3wd_diag_elapsed]
    call serial_string
    mov  edi, [rel pbm_init_checkpoint_record + PBM_INIT_ELAPSED_MS_OFF]
    call serial_hex64
    lea  rdi, [rel str_c3wd_diag_budget]
    call serial_string
    mov  edi, [rel pbm_init_checkpoint_record + PBM_INIT_BUDGET_MS_OFF]
    call serial_hex64
    lea  rdi, [rel str_c3wd_diag_end]
    call serial_string
    mov  eax, ebx
    pop  rbx
    ret

software_stop_declare:
    mov  byte [rel c3wd_out_ready], 0
    lea  rdi, [rel str_c3wd_verb]
    lea  rsi, [rel cmd_verb_c3watch]
    xor  edx, edx
    mov  ecx, ARGT_NONE
    xor  r8, r8
    xor  r9, r9                         ; strictly read-only observation
    call command_register_verb
    ret

cmd_verb_c3watch:
    call cmd_handler_prologue
    push r12
    mov  r12, rsi
    call c3wd_out_reset
    lea  rdi, [rel str_c3wd_pre]
    call c3wd_out_str

    cmp  byte [rel pbm_init_checkpoint_loaded], 1
    jne  .checkpoint_unavailable
    cmp  byte [rel pbm_init_checkpoint_durable], 1
    jne  .checkpoint_unavailable
    lea  rdi, [rel str_c3wd_durable]
    call c3wd_out_str
    jmp  .checkpoint_fields
.checkpoint_unavailable:
    lea  rdi, [rel str_c3wd_unavailable]
    call c3wd_out_str
.checkpoint_fields:
    lea  rdi, [rel str_c3wd_stage]
    call c3wd_out_str
    movzx edi, byte [rel pbm_init_checkpoint_record + PBM_INIT_STAGE_OFF]
    call c3wd_out_hex8
    lea  rdi, [rel str_c3wd_transition]
    call c3wd_out_str
    movzx edi, byte [rel pbm_init_checkpoint_record + PBM_INIT_TRANSITION_OFF]
    call c3wd_out_hex8
    lea  rdi, [rel str_c3wd_result]
    call c3wd_out_str
    movzx edi, byte [rel pbm_init_checkpoint_record + PBM_INIT_RESULT_OFF]
    call c3wd_out_hex8
    lea  rdi, [rel str_c3wd_durable_field]
    call c3wd_out_str
    movzx edi, byte [rel pbm_init_checkpoint_durable]
    call c3wd_out_hex8
    lea  rdi, [rel str_c3wd_checkpoint_rc]
    call c3wd_out_str
    movzx edi, byte [rel c3wd_checkpoint_rc]
    call c3wd_out_hex8
    lea  rdi, [rel str_c3wd_p6_elapsed]
    call c3wd_out_str
    mov  edi, [rel c3wd_p6_elapsed_ms]
    call c3wd_out_hex32
    lea  rdi, [rel str_c3wd_p6_budget]
    call c3wd_out_str
    mov  edi, [rel c3wd_p6_budget_ms]
    call c3wd_out_hex32
    lea  rdi, [rel str_c3wd_p3_start]
    call c3wd_out_str
    mov  edi, [rel c3wd_p3_start_ms]
    call c3wd_out_hex32
    lea  rdi, [rel str_c3wd_p3_start_status]
    call c3wd_out_str
    movzx edi, byte [rel c3wd_p3_start_status]
    call c3wd_out_hex8
    lea  rdi, [rel str_c3wd_p3_elapsed]
    call c3wd_out_str
    mov  edi, [rel c3wd_p3_elapsed_ms]
    call c3wd_out_hex32
    lea  rdi, [rel str_c3wd_p3_budget]
    call c3wd_out_str
    mov  edi, [rel c3wd_p3_budget_ms]
    call c3wd_out_hex32
    lea  rdi, [rel str_c3wd_p3_total_status]
    call c3wd_out_str
    movzx edi, byte [rel c3wd_p3_total_status]
    call c3wd_out_hex8

    lea  rdi, [rel str_c3wd_manager]
    call c3wd_out_str
    movzx edi, byte [rel pbm_manager_launch]
    call c3wd_out_hex8
    lea  rdi, [rel str_c3wd_entry]
    call c3wd_out_str
    movzx edi, byte [rel pbm_entry]
    call c3wd_out_hex8
    lea  rdi, [rel str_c3wd_profile]
    call c3wd_out_str
    movzx edi, byte [rel pbm_profile]
    call c3wd_out_hex8
    lea  rdi, [rel str_c3wd_reason]
    call c3wd_out_str
    movzx edi, byte [rel pbm_reason]
    call c3wd_out_hex8
    lea  rdi, [rel str_c3wd_health]
    call c3wd_out_str
    movzx edi, byte [rel pbm_strong_health_published]
    call c3wd_out_hex8

    lea  rdi, [rel str_c3wd_policy]
    call c3wd_out_str
    mov  byte [rel c3wd_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_OK
    movzx eax, byte [rel pbm_init_checkpoint_durable]
    mov  [r12 + RSP_VAL], rax
    pop  r12
    ret

; The marker is earned by all four route outcomes.  The full stop matrix and
; reset-surviving state replay are content-graded by the Phase-6 host driver.
software_stop_qemu_selftest:
    push rbx
    push r12
    sub  rsp, 8
    ; Exercise the production predicate under a hypervisor even when the
    ; emulated NIC reaches READY. The wrapper call proves PARKED returns before
    ; the PaOSBootReady writer; restore live boot state before continuing.
    mov  eax, 1
    cpuid
    bt   ecx, 31                         ; CPUID.1:ECX.HYPERVISOR
    jnc  .route_matrix
    mov  edi, 1
    mov  esi, NIC_ST_WARMING
    call software_stop_net_gate_decide
    cmp  eax, C3WD_NET_DEFER
    jne  .out
    mov  edi, 1
    mov  esi, NIC_ST_READY
    call software_stop_net_gate_decide
    cmp  eax, C3WD_NET_PUBLISH
    jne  .out
    mov  edi, 1
    mov  esi, NIC_ST_PARKED
    call software_stop_net_gate_decide
    cmp  eax, C3WD_NET_WITHHOLD
    jne  .out
    xor  edi, edi
    mov  esi, NIC_ST_PARKED
    call software_stop_net_gate_decide
    cmp  eax, C3WD_NET_PUBLISH
    jne  .out
    lea  rdi, [rel str_c3wd_no_nic_publish]
    call serial_string                   ; degenerate descriptor decision is observable
    movzx ebx, byte [rel boot_nic_state]
    movzx r12d, byte [rel net_required]
    mov  byte [rel c3wd_net_withheld], 0
    mov  byte [rel net_required], 1
    mov  byte [rel boot_nic_state], NIC_ST_PARKED
    call software_stop_publish_strong_health
    cmp  byte [rel c3wd_net_withheld], 1
    jne  .restore_failed
    mov  byte [rel c3wd_net_withheld], 0 ; the selftest's refusal must not silence a real one
    mov  [rel boot_nic_state], bl
    mov  [rel net_required], r12b
    jmp  .route_matrix
.restore_failed:
    mov  [rel boot_nic_state], bl
    mov  [rel net_required], r12b
    jmp  .out
.route_matrix:
%ifdef PAOS_GE_C3_QEMU_SCENARIO
    mov  edi, 0x02
    mov  esi, 0x06
    xor  edx, edx
    mov  ecx, 0x04
    mov  r8d, 1
    xor  r9d, r9d
    call software_stop_select_route
    cmp  eax, C3WD_ROUTE_SAFE
    jne  .out

    mov  edi, 0x02
    mov  esi, 0x06
    mov  edx, 0x02
    mov  ecx, 0x04
    mov  r8d, 1
    xor  r9d, r9d
    call software_stop_select_route
    cmp  eax, C3WD_ROUTE_KNOWN_GOOD
    jne  .out

    mov  edi, 0x02
    mov  esi, 0x06
    mov  edx, 0x02
    mov  ecx, 0x04
    mov  r8d, 1
    mov  r9d, 0x04
    call software_stop_select_route
    cmp  eax, C3WD_ROUTE_RESCUE
    jne  .out

    mov  edi, 0x02
    xor  esi, esi
    xor  edx, edx
    mov  ecx, 0x04
    xor  r8d, r8d
    xor  r9d, r9d
    call software_stop_select_route
    cmp  eax, C3WD_ROUTE_VISIBLE_STOP
    jne  .out

    lea  rdi, [rel str_c3wd_qemu_pass]
    call serial_string
%endif
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

c3wd_out_reset:
    lea  rax, [rel c3wd_out_buf]
    mov  [rel c3wd_out_cur], rax
    mov  byte [rax], 0
    ret

c3wd_out_str:
    mov  rsi, [rel c3wd_out_cur]
.copy:
    mov  al, [rdi]
    test al, al
    jz   .done
    mov  [rsi], al
    inc  rdi
    inc  rsi
    jmp  .copy
.done:
    mov  byte [rsi], 0
    mov  [rel c3wd_out_cur], rsi
    ret

c3wd_out_hex8:
    mov  rsi, [rel c3wd_out_cur]
    lea  r8, [rel c3wd_hex]
    mov  byte [rsi], '0'
    mov  byte [rsi + 1], 'x'
    mov  eax, edi
    mov  edx, eax
    shr  eax, 4
    and  eax, 0x0F
    mov  al, [r8 + rax]
    mov  [rsi + 2], al
    and  edx, 0x0F
    mov  dl, [r8 + rdx]
    mov  [rsi + 3], dl
    mov  byte [rsi + 4], 0
    add  rsi, 4
    mov  [rel c3wd_out_cur], rsi
    ret

c3wd_out_hex32:
    mov  rsi, [rel c3wd_out_cur]
    lea  r8, [rel c3wd_hex]
    mov  byte [rsi], '0'
    mov  byte [rsi + 1], 'x'
    mov  eax, edi
    mov  ecx, 8
    lea  r9, [rsi + 2]
.digit:
    rol  eax, 4
    mov  edx, eax
    and  edx, 0x0F
    mov  dl, [r8 + rdx]
    mov  [r9], dl
    inc  r9
    dec  ecx
    jnz  .digit
    mov  byte [rsi + 10], 0
    add  rsi, 10
    mov  [rel c3wd_out_cur], rsi
    ret

; --- G9 stability BEGIN ---------------------------------------------------------
; RCQ-28 G9 (root 2026-10-08 14:03; srcreview conditions 14:22): the strong health
; ack is not written the instant readiness passes. The managed readiness edge ARMS
; a deadline; the BSP idle loop's tick re-measures at the deadline against the
; arm-time snapshot and publishes the unchanged PaOSBootReady exactly once, or
; latches WITHHELD for the rest of this boot. A dead loop never publishes. One
; build constant, no knob: nothing shortens the window, forces a publish or clears
; WITHHELD. A clean exit inside the window (power_execute, UDP/serial reset) runs
; the same checks once and publishes only after STAB_EXIT_MIN_MS.
%define STAB_WINDOW_MS_VALUE 90000
STAB_WINDOW_MS      equ STAB_WINDOW_MS_VALUE
STAB_EXIT_MIN_MS    equ 30000
STAB_MAX_BLK        equ 64              ; = BLK_REGISTRY_LIMIT: blk_iter_after never returns more,
                                        ; so a snapshot is never truncated (srcreview R1)
STAB_IDLE           equ 0
STAB_ARMED          equ 1
STAB_PUBLISHED      equ 2
STAB_WITHHELD       equ 3
STAB_UNMEASURED     equ 4               ; published at readiness, clock uncalibrated: NOT a G9 pass
STAB_R_NONE         equ 0
STAB_R_NET          equ 1               ; command NIC READY at arm, not READY/linked now
STAB_R_STORAGE      equ 2               ; a fixed block device healthy at arm is not healthy now
STAB_R_DESKTOP      equ 3               ; GUI presentation: the idle loop's compositor call did not run
STAB_R_WATCHDOG     equ 4               ; c3wd recorded a software stop after readiness
STAB_R_PUBLISH      equ 5               ; the SetVariable publish itself failed
STAB_R_EARLY_EXIT   equ 6               ; clean exit before STAB_EXIT_MIN_MS
STAB_R_CLOCK        equ 7               ; overflow, unavailable or regressed armed clock
; struct stab_sample (one at arm, one at the decision)
SS_NET_READY        equ 0               ; qword 1/0
SS_NET_HANDLE       equ 8
SS_GUI              equ 16              ; qword 1 = GUI presentation
SS_COMP_TICKS       equ 24
SS_WATCHDOG_OK      equ 32
SS_BLK_COUNT        equ 40
SS_BLK              equ 48              ; healthy fixed (non-removable) block handles
SS_SIZE             equ SS_BLK + STAB_MAX_BLK * 8

; software_stop_stability_decide(RDI=arm sample, RSI=now sample) -> EAX reason.
; Pure: no regression from the arm-time snapshot is the whole rule.
software_stop_stability_decide:
    mov  eax, STAB_R_WATCHDOG
    cmp  qword [rsi + SS_WATCHDOG_OK], 1
    jne  .out
    mov  eax, STAB_R_NET
    cmp  qword [rdi + SS_NET_READY], 1
    jne  .net_ok                        ; no command NIC ready at arm: not a gate
    cmp  qword [rsi + SS_NET_READY], 1
    jne  .out
    mov  rcx, [rdi + SS_NET_HANDLE]
    cmp  rcx, [rsi + SS_NET_HANDLE]
    jne  .out
.net_ok:
    mov  eax, STAB_R_STORAGE
    xor  ecx, ecx
.blk_next:
    cmp  rcx, [rdi + SS_BLK_COUNT]
    jae  .blk_ok
    mov  r8, [rdi + SS_BLK + rcx*8]
    xor  edx, edx
.blk_find:
    cmp  rdx, [rsi + SS_BLK_COUNT]
    jae  .out                           ; healthy at arm, not healthy now
    cmp  r8, [rsi + SS_BLK + rdx*8]
    je   .blk_found
    inc  rdx
    jmp  .blk_find
.blk_found:
    inc  rcx
    jmp  .blk_next
.blk_ok:
    ; Desktop: the idle loop's wmx_draw_flush_deferred call ran since arm. The
    ; counter is bumped in the same loop that runs this tick, so this proves the
    ; idle loop (compositor call included) is alive, not compositor health; a
    ; hung compositor hangs that loop and the tick never publishes anyway.
    mov  eax, STAB_R_DESKTOP
    cmp  qword [rdi + SS_GUI], 1
    jne  .desktop_ok
    mov  rcx, [rsi + SS_COMP_TICKS]
    cmp  rcx, [rdi + SS_COMP_TICKS]
    jbe  .out
.desktop_ok:
    xor  eax, eax
.out:
    ret

; software_stop_stability_arm: once per boot; a second call never moves the deadline.
software_stop_stability_arm:
    cmp  byte [rel stab_state], STAB_IDLE
    jne  .out
    sub  rsp, 8
    lea  rdi, [rel stab_arm_sample]
    call software_stop_stability_sample
    call boot_ms_now
    test rax, rax
    jz   .unmeasured                    ; uncalibrated TSC: the window cannot elapse
    mov  [rel stab_armed_ms], rax
    mov  [rel stab_last_ms], rax
    add  rax, STAB_WINDOW_MS
    jc   .clock_failed                  ; a wrapped deadline is never a measured window
    mov  [rel stab_deadline_ms], rax
    mov  byte [rel stab_state], STAB_ARMED
    lea  rdi, [rel str_stab_armed]
    call serial_string
    add  rsp, 8
.out:
    ret
.clock_failed:
    add  rsp, 8
    jmp  software_stop_stability_clock_failed
.unmeasured:
    ; Fail open to the pre-G9 behaviour (publish at readiness), loudly: a box
    ; whose clock never calibrated must not lose promotion on every trial.
    ; srcreview R2: visible as health_ack=unmeasured, never as a G9 pass.
    lea  rdi, [rel str_stab_unmeasured]
    call serial_string
    call boot_v2_publish_strong_health
    mov  byte [rel stab_state], STAB_UNMEASURED
    cmp  byte [rel pbm_strong_health_published], 1
    je   .unmeasured_done
    mov  byte [rel stab_reason], STAB_R_PUBLISH
    mov  byte [rel stab_state], STAB_WITHHELD
.unmeasured_done:
    add  rsp, 8
    HP_TERMINAL 4
    ret

; software_stop_stability_tick: every BSP idle tick; a no-op unless armed and due.
software_stop_stability_tick:
    cmp  byte [rel stab_state], STAB_ARMED
    jne  .out
    sub  rsp, 8
    call software_stop_stability_elapsed
    lea  rsp, [rsp + 8]                 ; preserve the interval-valid carry flag
    jc   software_stop_stability_clock_failed
    cmp  rax, STAB_WINDOW_MS
    jb   .out
    jmp  software_stop_stability_conclude
.out:
    ret

; software_stop_stability_exit_hook: a clean power/reset path is about to end this
; boot. Inside the window: the same checks once, after STAB_EXIT_MIN_MS only.
software_stop_stability_exit_hook:
    cmp  byte [rel stab_state], STAB_ARMED
    jne  .out
    sub  rsp, 8
    call software_stop_stability_elapsed
    lea  rsp, [rsp + 8]
    jc   software_stop_stability_clock_failed
    cmp  rax, STAB_EXIT_MIN_MS
    jae  software_stop_stability_conclude
    mov  byte [rel stab_reason], STAB_R_EARLY_EXIT
    jmp  software_stop_stability_withhold
.out:
    ret

; Armed clock observations (tick, clean exit and STATUS) share one monotonic
; high-water mark. RAX=elapsed, CF=0 only for a nonzero, nonregressed sample.
; Initial arm's explicit unmeasured policy never applies after a valid arm.
software_stop_stability_elapsed:
    sub  rsp, 8
    call boot_ms_now
    add  rsp, 8
    test rax, rax
    jz   .invalid
    cmp  rax, [rel stab_last_ms]
    jb   .invalid
    mov  rcx, rax
    sub  rax, [rel stab_armed_ms]
    jb   .invalid
    mov  [rel stab_last_ms], rcx
    clc
    ret
.invalid:
    stc
    ret

software_stop_stability_clock_failed:
    mov  byte [rel stab_reason], STAB_R_CLOCK
    jmp  software_stop_stability_withhold

software_stop_stability_conclude:
    sub  rsp, 8
    lea  rdi, [rel stab_now_sample]
    call software_stop_stability_sample
    lea  rdi, [rel stab_arm_sample]
    lea  rsi, [rel stab_now_sample]
    call software_stop_stability_decide
    add  rsp, 8
    mov  [rel stab_reason], al
    test eax, eax
    jnz  software_stop_stability_withhold
    sub  rsp, 8
    pushfq
    push rax
    mov  eax, 35
    call command_udp_progress_enter
    pop  rax
    popfq
    call boot_v2_publish_strong_health
    pushfq
    push rax
    mov  eax, 35
    call command_udp_progress_complete
    pop  rax
    popfq
    add  rsp, 8
    cmp  byte [rel pbm_strong_health_published], 1
    jne  .publish_failed
    mov  byte [rel stab_state], STAB_PUBLISHED
    HP_TERMINAL 4
    ret
.publish_failed:
    mov  byte [rel stab_reason], STAB_R_PUBLISH
    jmp  software_stop_stability_withhold

software_stop_stability_withhold:
    mov  byte [rel stab_state], STAB_WITHHELD
    movzx eax, byte [rel stab_reason]
    lea  rdi, [rel str_stab_withheld_storage]
    cmp  eax, STAB_R_STORAGE
    je   .emit
    lea  rdi, [rel str_stab_withheld_desktop]
    cmp  eax, STAB_R_DESKTOP
    je   .emit
    lea  rdi, [rel str_stab_withheld_watchdog]
    cmp  eax, STAB_R_WATCHDOG
    je   .emit
    lea  rdi, [rel str_stab_withheld_publish]
    cmp  eax, STAB_R_PUBLISH
    je   .emit
    lea  rdi, [rel str_stab_withheld_early_exit]
    cmp  eax, STAB_R_EARLY_EXIT
    je   .emit
    lea  rdi, [rel str_stab_withheld_clock]
    cmp  eax, STAB_R_CLOCK
    je   .emit
    lea  rdi, [rel str_stab_withheld_net]
.emit:
    sub  rsp, 8
    call serial_string
    add  rsp, 8
    HP_TERMINAL 4
    ret

; software_stop_stability_state(RDI=ms_left out) -> EAX state (STAB_IDLE..STAB_UNMEASURED),
; EDX reason (STATUS). Observes the same armed interval as tick/exit, latching
; clock failure rather than claiming an active measurement forever. ms_left is
; clamped to 0 between the valid window's end and the next tick; never publishes.
software_stop_stability_state:
    mov  qword [rdi], 0
    cmp  byte [rel stab_state], STAB_ARMED
    jne  .out
    push rdi
    call software_stop_stability_elapsed
    jc   .clock_failed
    mov  ecx, STAB_WINDOW_MS
    sub  rcx, rax
    jae  .left
    xor  ecx, ecx
.left:
    pop  rdi
    mov  [rdi], rcx
.out:
    movzx eax, byte [rel stab_state]
    movzx edx, byte [rel stab_reason]
    ret
.clock_failed:
    call software_stop_stability_clock_failed
    pop  rdi
    jmp  .out

%include "core/abi/wdata.inc"
%macro WDATA_svc_software_stop_g9 0
stab_armed_ms:     resq 1
stab_deadline_ms:  resq 1
stab_last_ms:      resq 1
stab_arm_sample:   resb SS_SIZE
stab_now_sample:   resb SS_SIZE
stab_state:        resb 1
stab_reason:       resb 1
%endmacro
WDATA_BSS_DEFER WDATA_svc_software_stop_g9
%if STAB_IDLE != 0 || STAB_R_NONE != 0
    %error "stab_state/stab_reason are zero-filled: STAB_IDLE and STAB_R_NONE must stay 0"
%endif
%defstr STAB_WINDOW_MS_STR STAB_WINDOW_MS_VALUE
str_stab_armed:              db "[PAOS64] boot-v2: strong health armed; stability window_ms=", STAB_WINDOW_MS_STR, " [boot.v2.health.stability-armed]",13,10,0
str_stab_unmeasured:         db "[PAOS64] boot-v2: strong health published at readiness; stability window unmeasured (clock uncalibrated) [boot.v2.health.stability-unmeasured]",13,10,0
str_stab_withheld_net:       db "[PAOS64] boot-v2: strong health withheld reason=net [boot.v2.health.stability-failed]",13,10,0
str_stab_withheld_storage:   db "[PAOS64] boot-v2: strong health withheld reason=storage [boot.v2.health.stability-failed]",13,10,0
str_stab_withheld_desktop:   db "[PAOS64] boot-v2: strong health withheld reason=desktop [boot.v2.health.stability-failed]",13,10,0
str_stab_withheld_watchdog:  db "[PAOS64] boot-v2: strong health withheld reason=watchdog [boot.v2.health.stability-failed]",13,10,0
str_stab_withheld_publish:   db "[PAOS64] boot-v2: strong health withheld reason=publish [boot.v2.health.stability-failed]",13,10,0
str_stab_withheld_early_exit: db "[PAOS64] boot-v2: strong health withheld reason=early-exit [boot.v2.health.stability-failed]",13,10,0
str_stab_withheld_clock:      db "[PAOS64] boot-v2: strong health withheld reason=clock [boot.v2.health.stability-failed]",13,10,0
; software_stop_stability_sample(RDI=struct stab_sample): the live measurements.
software_stop_stability_sample:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  rdi, rbx
    mov  ecx, SS_SIZE
    xor  eax, eax
    rep  stosb
    ; network: the selected command NIC is READY, healthy and linked (fresh poll)
    cmp  byte [rel boot_nic_state], NIC_ST_READY
    jne  .net_done
    mov  rdi, [rel udp_nic_handle]       ; expected registered owner, not REP STOSB end
    call netdev_selected_owner
    test rax, rax
    jz   .net_done
    cmp  dword [rax + dev.health], HEALTH_OK
    jne  .net_done
    mov  r12, rax
    mov  rdi, rax
    call netdev_selected_link_ready
    cmp  rax, r12
    jne  .net_done
    mov  qword [rbx + SS_NET_READY], 1
    mov  [rbx + SS_NET_HANDLE], r12
.net_done:
    ; storage (srcreview R1): every FIXED block device the registry still returns
    ; healthy. The ESP the booted slot came from is on one of them; PaOS has no
    ; finer runtime identity for it. Removable media (USB sticks, the installer
    ; medium, card readers), mounted or not, are excluded: unplugging one is an
    ; owner action, not a regression of this build.
    xor  r12d, r12d                     ; previous handle
    xor  r13d, r13d                     ; count
.blk:
    cmp  r13d, STAB_MAX_BLK
    jae  .blk_done
    mov  rdi, r12
    xor  esi, esi
    mov  edx, BLKF_REMOVABLE
    call blk_iter_after
    test rax, rax
    jz   .blk_done
    mov  [rbx + SS_BLK + r13*8], rax
    mov  r12, rax
    inc  r13d
    jmp  .blk
.blk_done:
    mov  [rbx + SS_BLK_COUNT], r13
    ; desktop: in GUI presentation the idle loop's compositor call must keep running
    cmp  byte [rel keep_presentation_target], PRESENTATION_CLI
    je   .cli
    mov  qword [rbx + SS_GUI], 1
.cli:
    mov  rax, [rel boot_idle_compositor_ticks]
    mov  [rbx + SS_COMP_TICKS], rax
    ; watchdog: no software stop recorded since readiness
    cmp  byte [rel c3wd_checkpoint_rc], PBM_INIT_RC_OK
    jne  .out
    mov  qword [rbx + SS_WATCHDOG_OK], 1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret
; --- G9 stability END -----------------------------------------------------------

align 8
boot_phase_tsc: times 18 dq 0
c3wd_out_cur:   dq 0
c3wd_out_ready: db 0
c3wd_checkpoint_rc: db PBM_INIT_RC_OK
c3wd_net_withheld: db 0
c3wd_requested_stage: db PBM_INIT_STAGE_NONE
c3wd_requested_transition: db PBM_INIT_TRANSITION_NONE
c3wd_p3_start_status: db C3WD_P3_NONE
c3wd_p3_total_status: db C3WD_P3_NONE
align 4
c3wd_p6_elapsed_ms: dd 0
c3wd_p6_budget_ms:  dd 0
c3wd_p3_before_ms:  dd 0
c3wd_p3_start_ms:   dd 0
c3wd_p3_started_ms: dd 0
c3wd_p3_elapsed_ms: dd 0
c3wd_p3_budget_ms:  dd 0
align 8
c3wd_out_buf:   times C3WD_OUT_CAP db 0

c3wd_hex: db "0123456789abcdef"
str_c3wd_verb:          db "C3WATCH",0
str_c3wd_pre:           db " c3_watch checkpoint=",0
str_c3wd_durable:       db "durable",0
str_c3wd_unavailable:   db "unavailable",0
str_c3wd_stage:         db " stage=",0
str_c3wd_transition:    db " transition=",0
str_c3wd_result:        db " result=",0
str_c3wd_durable_field: db " durable=",0
str_c3wd_checkpoint_rc: db " checkpoint_rc=",0
str_c3wd_p6_elapsed:   db " p6_elapsed_ms=",0
str_c3wd_p6_budget:    db " p6_budget_ms=",0
str_c3wd_p3_start:     db " p3_start_checkpoint_ms=",0
str_c3wd_p3_start_status: db " p3_start_status=",0
str_c3wd_p3_elapsed:   db " p3_elapsed_ms=",0
str_c3wd_p3_budget:    db " p3_budget_ms=",0
str_c3wd_p3_total_status: db " p3_total_status=",0
str_c3wd_manager:       db " manager_launch=",0
str_c3wd_entry:         db " entry=",0
str_c3wd_profile:       db " profile=",0
str_c3wd_reason:        db " reason=",0
str_c3wd_health:        db " strong_health=",0
str_c3wd_policy:
    db " recovery_owner=manager retry_budget=one-safe-per-verified-slot"
    db " routes=safe>known-good>rescue timeout_min_s=3 timeout_max_s=30"
    db " false_health=refuse-until-p8-complete power_cycle=0 tco_selfreset=0"
    db " direct_bootmgfw_write=0",0
str_c3wd_reply_static_end:
%if ((str_c3wd_reply_static_end - str_c3wd_pre) + (12 * 4) + (5 * 10)) >= C3WD_OUT_CAP
    %error "GE C3 fixed reply exceeds c3wd_out_buf"
%endif
str_c3wd_diag_rc:                 db "[PAOS64] GE C3 checkpoint diagnostic rc=",0
str_c3wd_diag_request_stage:      db " request_stage=",0
str_c3wd_diag_request_transition: db " request_transition=",0
str_c3wd_diag_record_stage:       db " record_stage=",0
str_c3wd_diag_record_transition:  db " record_transition=",0
str_c3wd_diag_result:             db " result=",0
str_c3wd_diag_durable:            db " durable=",0
str_c3wd_diag_mask:               db " completed_mask=",0
str_c3wd_diag_elapsed:            db " elapsed_ms=",0
str_c3wd_diag_budget:             db " budget_ms=",0
str_c3wd_diag_end:                db 13,10,0
str_c3wd_checkpoint_failed:
    db "[PAOS64] GE C3 checkpoint edge failed; strong health refused and Manager BIP retained [boot.v2.ge.c3.checkpoint-failed]",13,10,0
str_boot_phases_recorded:
    db "[PAOS64] P8 svc: per-phase TSC ledger recorded (P0-P8) [boot.phases.recorded]",13,10,0
str_boot_phases_failed:
    db "[PAOS64] P8 svc: per-phase TSC ledger FAILED (missing/non-monotone edge)",13,10,0
str_c3wd_net_withheld:
    db "[PAOS64] P8 health: strong-health WITHHELD while NIC parked/absent (net_required) [net.health.publish.gated]",13,10,0
str_c3wd_no_nic_publish:
    db "[PAOS64] P8 health KAT: net_required=0 parked_decision=publish",13,10,0
str_c3wd_qemu_pass:
    db "[boot.v2.ge.c3.scenario] GE C3 QEMU scenario PASS [boot.v2.ge.c3.scenario]",13,10,0
