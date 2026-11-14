;; MODULE svc/hook_edge_smpstat
;; LAYER 5
;; EXPORTS hook_smpstat_plan, hook_smpstat_post
;; IMPORTS svc/command, svc/command_hook, svc/command_smp
;; CAPS
;; OWNER saga:command
; SMPSTAT and owned SMPWORK STATUS/DETAIL/PROGRESS/RESULTS projection of the shipped V2 interposer, not its legacy V1
; registration text. POLICY/VALIDATE project native read-only policy diagnostics.
; CANCEL WORK delegates existing owned native cancellation; no new work,
; policy apply, sampling loop or frequency read is added.
; HEALTH/LOAD CHIP use the native capture; LOAD logical sample=N reads that exact
; native snapshot and preserves stale/unavailable refusals. CPU is live topology.
; The normal nested dispatcher owns source/principal/cap/idempotency and refusal.
; BSP command serialization owns all plan/stage/parse lifetime; consume staging
; on every post path. Fixed SMPSTAT transport nonce is checked then omitted;
; the optional WORK selector preserves its original owned nonce/generation.
; Native complete ordered grammar is stricter than a field-search projection:
; no unknown/duplicate/private fields, wrong view/CPU/sample, overflow or partial
; record. This is passive diagnostic data, no new physical acceptance claim.

hook_smpstat_plan:
    mov  byte [rel hsw_pending], 0
    mov  dword [rel hsw_nonce], 0
    mov  qword [rel hsw_generation], 0
    mov  dword [rel hpo_profile], 0
    cmp  edi, HOP_GET
    je   .supported
    cmp  edi, HOP_CANCEL
    jne  .na
.supported:
    cmp  byte [rsi], 0
    jne  .bad
    push rbx
    mov  rbx, rdx
    mov  dword [rel hsm_view], 0
    cmp  edi, HOP_CANCEL
    mov  rdi, rdx
    je   .cancel
    cmp  byte [rdi], 0
    je   .summary
    lea  rsi, [rel hsm_selectors]
    call hsm_enum
    test eax, eax
    jz   .bad_pop
    mov  [rel hsm_view], eax             ; SUMMARY1 CPU2 HEALTH3 LOAD4 SCHEMA5
    cmp  eax, 11
    je   .results
    cmp  eax, 9
    je   .policy
    cmp  eax, 10
    je   .validate
    cmp  eax, 6
    je   .work
    cmp  eax, 7
    je   .detail
    cmp  eax, 8
    je   .progress
    cmp  eax, 2
    je   .cpu
    cmp  eax, 4
    je   .load
    cmp  byte [rdi], 0
    jne  .bad_pop
    jmp  .plan
.policy:
    cmp  byte [rdi], 0
    jne  .bad_pop
    mov  dword [rel hsm_view], 10
    call hsw_retire
    lea  rdi, [rel hpo_nonce]
    call command_hook_arg_str
    lea  rax, [rel hpo_stat_verb]
    jmp  .policy_ready
.validate:
    cmp  byte [rdi], ' '
    jne  .bad_pop
    inc  rdi
    lea  rsi, [rel hpo_profiles]
    call hsm_enum
    test eax, eax
    jz   .bad_pop
    cmp  byte [rdi], 0
    jne  .bad_pop
    mov  [rel hpo_profile], eax
    mov  dword [rel hsm_view], 11
    call hsw_retire
    lea  rdi, [rel hpo_validate_balanced]
    cmp  dword [rel hpo_profile], 1
    je   .validate_arg
    lea  rdi, [rel hpo_validate_physical]
.validate_arg:
    call command_hook_arg_str
    lea  rax, [rel hpo_validate_verb]
.policy_ready:
    mov  byte [rel hsw_pending], 1
    pop  rbx
    ret
.cancel:
    lea  rsi, [rel hsw_cancel_selector]
    call hsm_enum
    cmp  eax, 1
    jne  .work_bad
    mov  dword [rel hsm_view], 13        ; effectful owned cancel, not GET
    jmp  .owned
.work:
    mov  dword [rel hsm_view], 7         ; distinct from LOAD CPU6
    jmp  .owned
.detail:
    mov  dword [rel hsm_view], 8         ; admission snapshot, not lean STATUS
    jmp  .owned
.progress:
    mov  dword [rel hsm_view], 9         ; retained publications, not live APs
    jmp  .owned
.results:
    mov  dword [rel hsm_view], 12        ; frozen rows, non-consuming
.owned:
    push rdi
    call hsw_retire
    pop  rdi
    cmp  byte [rdi], ' '
    jne  .work_bad
    inc  rdi
    mov  rbx, rdi                      ; exact original owned handle argument
    mov  esi, 8
    call hsw_arg_hex
    test eax, eax
    jz   .work_bad
    mov  [rel hsw_nonce], r8d
    cmp  byte [rdi], ' '
    jne  .work_bad
    inc  rdi
    mov  esi, 16
    call hsw_arg_hex
    test eax, eax
    jz   .work_bad
    mov  [rel hsw_generation], r8
    cmp  byte [rdi], 0
    jne  .work_bad
    lea  rdi, [rel hsw_status_arg]
    cmp  dword [rel hsm_view], 12
    je   .results_arg
    cmp  dword [rel hsm_view], 13
    je   .cancel_arg
    cmp  dword [rel hsm_view], 9
    je   .progress_arg
    cmp  dword [rel hsm_view], 8
    jne  .owned_arg
    lea  rdi, [rel hsd_arg]
    jmp  .owned_arg
.progress_arg:
    lea  rdi, [rel hsp_arg]
    jmp  .owned_arg
.cancel_arg:
    lea  rdi, [rel hsw_cancel_arg]
    jmp  .owned_arg
.results_arg:
    lea  rdi, [rel hsr_arg]
.owned_arg:
    call command_hook_arg_str
    mov  rdi, rbx
    call command_hook_arg_str
    mov  byte [rel hsw_pending], 1
    lea  rax, [rel hsw_verb]
    pop  rbx
    ret
.work_bad:
    call hsw_retire
    pop  rbx
    jmp  .bad
.summary:
    mov  dword [rel hsm_view], 1
    lea  rbx, [rel hsm_summary_arg]
    jmp  .plan
.cpu:
    cmp  byte [rdi], ' '
    jne  .bad_pop
    inc  rdi
    call hsm_u64
    test eax, eax
    jz   .bad_pop
    ; Product capacity is 32 in this ABI; native range/row gate still decides.
    cmp  r8, 31
    ja   .bad_pop
    mov  [rel hsm_logical], r8d
    cmp  byte [rdi], 0
    jne  .bad_pop
    jmp  .plan
.load:
    cmp  byte [rdi], ' '
    jne  .bad_pop
    inc  rdi
    push rdi
    lea  rsi, [rel hsm_chip_arg]
    call hsm_literal
    test eax, eax
    pop  rax
    jz   .load_cpu
    cmp  byte [rdi], 0
    jne  .bad_pop
    jmp  .plan
.load_cpu:
    mov  rdi, rax
    call hsm_u64
    test eax, eax
    jz   .bad_pop
    cmp  r8, 31
    ja   .bad_pop
    mov  [rel hsm_logical], r8d
    lea  rsi, [rel hsm_sample_arg]
    call hsm_literal
    test eax, eax
    jz   .bad_pop
    call hsm_u64
    test eax, eax
    jz   .bad_pop
    mov  eax, 0xffffffff
    cmp  r8, rax
    ja   .bad_pop
    mov  [rel hsm_sample], r8d
    cmp  byte [rdi], 0
    jne  .bad_pop
    mov  dword [rel hsm_view], 6         ; LOAD CPU, distinct from LOAD CHIP4
.plan:
    lea  rdi, [rel hsm_nonce_arg]
    call command_hook_arg_str
    mov  rdi, rbx
    call command_hook_arg_str
    mov  byte [rel smpobs_out_ready], 0
    mov  byte [rel smpobs_out_buf], 0
    lea  rax, [rel hsm_verb]
    pop  rbx
    ret
.bad_pop:
    pop  rbx
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
    ret
.na:
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    ret

; post(EDI planned op, RSI instance, RDX rest, RCX native rsp)
hook_smpstat_post:
    cmp  dword [rel hsm_view], 12
    je   hsd_post
    cmp  dword [rel hsm_view], 13
    je   hsw_post
    cmp  dword [rel hsm_view], 10
    jae  hpo_post
    cmp  dword [rel hsm_view], 9
    je   hsd_post
    cmp  dword [rel hsm_view], 8
    je   hsd_post
    cmp  dword [rel hsm_view], 7
    je   hsw_post
    cmp  qword [rcx + RSP_CODE], CMDE_OK
    jne  .refused
    push rbx
    push r12
    mov  rbx, rcx
    cmp  byte [rel smpobs_out_ready], 1
    jne  .bad
    cmp  qword [rbx + RSP_VAL], 0       ; fixed transport nonce, no scalar substitute
    jne  .bad
    xor  r12d, r12d
.scan:
    cmp  r12d, 2048                     ; actual SMPOBS_OUT_CAP, NUL must fit
    jae  .bad
    lea  rax, [rel smpobs_out_buf]
    cmp  byte [rax + r12], 0
    je   .bounded
    inc  r12d
    jmp  .scan
.bounded:
    add  rax, r12
    cmp  rax, [rel smpobs_out_cur]       ; complete native end, never a prefix
    jne  .bad
    lea  rdi, [rel smpobs_out_buf]
    call hsm_record
    test eax, eax
    jz   .bad
    call command_hook_out_reset
    lea  rdi, [rel hsm_typed_head]
    call command_hook_out_str
    lea  rdi, [rel smpobs_out_buf + 33]  ; skip exact V2 header + fixed nonce
    mov  esi, r12d
    sub  esi, 33
    call command_hook_out_strn
    jmp  .retire
.bad:
    call command_hook_out_reset
    lea  rdi, [rel hsm_bad]
    call command_hook_out_str
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_ACCEPTED], 0
    lea  rax, [rel hsm_bad]
    mov  [rbx + RSP_HINT], rax
.retire:
    mov  byte [rel smpobs_out_ready], 0
    mov  byte [rel smpobs_out_buf], 0
    pop  r12
    pop  rbx
    mov  eax, 1
    ret
.refused:
    mov  byte [rel smpobs_out_ready], 0
    mov  byte [rel smpobs_out_buf], 0
    xor  eax, eax
    ret

; RDI is a NUL-bounded native record. Each path requires the full exact grammar.
hsm_record:
    push rbx
    mov  dword [rel hsm_optional_bits], 0
    lea  rsi, [rel hsm_native_head]
    call hsm_literal
    test eax, eax
    jz   .out
    mov  eax, [rel hsm_view]
    lea  rsi, [rel hsm_summary_fields]
    cmp  eax, 1
    je   .fields
    lea  rsi, [rel hsm_cpu_start]
    cmp  eax, 2
    je   .cpu
    lea  rsi, [rel hsm_health_fields]
    cmp  eax, 3
    je   .fields
    lea  rsi, [rel hsm_chip_fields]
    cmp  eax, 4
    je   .chip
    lea  rsi, [rel hsm_schema_fields]
    cmp  eax, 5
    je   .fields
    cmp  eax, 6
    jne  .no
    lea  rsi, [rel hsm_load_cpu_fields]
    call hsm_fields
    test eax, eax
    jz   .out
    ; Six nullable fields in order: APERF,MPERF,base,frequency,effective,ratio.
    ; State/source availability is native, never reinterpret missing as zero.
    mov  eax, [rel hsm_optional_bits]
    cmp  dword [rel hsm_frequency_state], 3 ; unsupported
    je   .unsupported
    cmp  dword [rel hsm_frequency_state], 2 ; idle
    je   .idle
    cmp  eax, 51                        ; measured, base unavailable
    je   .end
    cmp  eax, 63                        ; measured, base and MHz supplied
    je   .end
    jmp  .no
.unsupported:
    test eax, eax
    jz   .end
    jmp  .no
.idle:
    cmp  eax, 50                        ; idle base unavailable
    je   .end
    cmp  eax, 58                        ; idle base available
    je   .end
    jmp  .no
.cpu:
    call hsm_fields
    test eax, eax
    jz   .out
    call hsm_cpu_observations
    test eax, eax
    jz   .out
    lea  rsi, [rel hsm_cpu_state_fields]
    call hsm_fields
    test eax, eax
    jz   .out
    ; smpstat_cpu_microcode picks the scope from cpu_state: they must agree.
    mov  eax, [rel hsm_uc_bsp]
    cmp  eax, -1
    je   .scope_ok
    xor  edx, edx
    cmp  dword [rel hsm_cpu_state], 1
    sete dl
    cmp  eax, edx
    jne  .no
.scope_ok:
    cmp  dword [rel hsm_cpu_state], 1    ; BSP alone has LAPIC fields
    jne  .cpu_tail
    lea  rsi, [rel hsm_lapic_fields]
    call hsm_fields
    test eax, eax
    jz   .out
.cpu_tail:
    lea  rsi, [rel hsm_cpu_tail]
    jmp  .fields
.chip:
    call hsm_fields
    test eax, eax
    jz   .out
    xor  edx, edx
    cmp  dword [rel hsm_active], 0
    je   .ratio
    mov  edx, 14                       ; frequency,min,max numeric together
.ratio:
    cmp  dword [rel hsm_measured], 0
    je   .chip_check
    or   edx, 1
.chip_check:
    cmp  edx, [rel hsm_optional_bits]
    jne  .no
    jmp  .end
.fields:
    call hsm_fields
    test eax, eax
    jz   .out
.end:
    cmp  byte [rdi], 0
    jne  .no
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  rbx
    ret

; Optional versioned CPU observation sections precede state. An older row may
; omit both, or contain only cpu_init. A section is all-or-none according to its
; own ready flag: unavailable carries no stale fields. No unknown/duplicate keys,
; scope coercion, private fault bytes, or generic extension skipping is allowed.
; Validate syntax and widths, then copy exact bytes. This is not a second apply
; oracle: independent owner, refused result and before/post validity stay as
; observed; the offline evidence decoder owns any APPLIED interpretation.
hsm_cpu_observations:
    push rbx
    mov  rbx, rdi
    lea  rsi, [rel hsm_sec_header]
    call hsm_literal
    test eax, eax
    jz   .absent
    call hsm_u64
    test eax, eax
    jz   .out
    cmp  r8, 1
    ja   .bad
    test r8, r8
    jz   .microcode
    lea  rsi, [rel hsm_sec_fields]
    call hsm_fields
    test eax, eax
    jz   .out
.microcode:
    mov  rbx, rdi
    mov  dword [rel hsm_uc_bsp], 1
    lea  rsi, [rel hsm_uc_bsp_header]
    call hsm_literal
    test eax, eax
    jnz  .scope
    mov  dword [rel hsm_uc_bsp], 0
    mov  rdi, rbx
    lea  rsi, [rel hsm_uc_header]
    call hsm_literal
    test eax, eax
    jz   .absent
.scope:
    call hsm_u64
    test eax, eax
    jz   .out
    cmp  r8, 1
    ja   .bad
    test r8, r8
    jz   .yes
    lea  rsi, [rel hsm_uc_fields]
    call hsm_fields
    jmp  .out
.absent:
    mov  dword [rel hsm_uc_bsp], -1      ; no section: nothing for the state to contradict
    mov  rdi, rbx
.yes:
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  rbx
    ret

; Ordered field table: (literal,kind,limit/enum), terminated by a zero literal.
; Literal and enum pointers are signed offsets from their own live cells.
; kind0 literal;1 bounded decimal;2 enum;3 logical;4 sample;5 nullable decimal;
; 6 frequency state;7 CPU state;8 active count;9 measured count. Exact delimiters
; belong to the next literal, so neither numeric nor enum prefix matches pass.
hsm_fields:
    push rbx
    mov  rbx, rsi
.next:
    mov  rsi, [rbx]
    test rsi, rsi
    jz   .yes
    add  rsi, rbx                     ; self-relative literal at this live row
    call hsm_literal
    test eax, eax
    jz   .out
    mov  eax, [rbx + 8]
    test eax, eax
    jz   .advance
    cmp  eax, 2
    je   .enum
    cmp  eax, 6
    je   .enum
    cmp  eax, 7
    je   .enum
    cmp  eax, 5
    jne  .number
    shl  dword [rel hsm_optional_bits], 1
    push rdi
    lea  rsi, [rel hsm_unavailable]
    call hsm_literal
    test eax, eax
    pop  rax
    jz   .optional_number
    jmp  .advance
.optional_number:
    mov  rdi, rax
    or   dword [rel hsm_optional_bits], 1
.number:
    call hsm_u64
    test eax, eax
    jz   .out
    cmp  r8, [rbx + 16]
    ja   .no
    mov  eax, [rbx + 8]
    cmp  eax, 3
    jne  .sample
    cmp  r8d, [rel hsm_logical]
    jne  .no
.sample:
    cmp  eax, 4
    jne  .active
    cmp  r8d, [rel hsm_sample]
    jne  .no
.active:
    cmp  eax, 8
    jne  .measured
    mov  [rel hsm_active], r8d
.measured:
    cmp  eax, 9
    jne  .advance
    mov  [rel hsm_measured], r8d
    jmp  .advance
.enum:
    mov  rsi, [rbx + 16]
    lea  rsi, [rbx + rsi + 16]         ; enum offset is relative to its own cell
    call hsm_enum
    test eax, eax
    jz   .out
    cmp  dword [rbx + 8], 6
    jne  .cpu_state
    mov  [rel hsm_frequency_state], eax
.cpu_state:
    cmp  dword [rbx + 8], 7
    jne  .advance
    mov  [rel hsm_cpu_state], eax
.advance:
    add  rbx, 24
    jmp  .next
.yes:
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  rbx
    ret

hsm_literal:
    mov  al, [rsi]
    test al, al
    jz   .yes
    cmp  al, [rdi]
    jne  .no
    inc  rsi
    inc  rdi
    jmp  hsm_literal
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; RDI input, RSI double-NUL enum literals -> EAX ordinal+1/0, RDI advanced on
; match. The caller must require its exact following delimiter.

hsm_enum:
    push rbx
    push r12
    mov  rbx, rdi
    mov  r12d, 1
.next:
    push rsi
    call hsm_literal
    pop  rsi
    test eax, eax
    jz   .restore
    cmp  byte [rdi], 0
    je   .yes
    cmp  byte [rdi], ' '
    je   .yes
.restore:
    mov  rdi, rbx
.skip:
    cmp  byte [rsi], 0
    lea  rsi, [rsi + 1]
    jne  .skip
    inc  r12d
    cmp  byte [rsi], 0
    jne  .next
    xor  eax, eax
    jmp  .out
.yes:
    mov  eax, r12d
.out:
    pop  r12
    pop  rbx
    ret

; RDI decimal -> EAX 1/0, R8 full64 value and RDI after digits on success.
; Check BEFORE arithmetic: at most20 digits and no multiply/add wrap. Native
; formatting is canonical, so reject leading zeros as well as signed numbers.

hsm_u64:
    mov  rcx, rdi
    xor  r8d, r8d
    xor  r9d, r9d
    mov  r11, 1844674407370955161
.digit:
    movzx r10d, byte [rcx]
    sub  r10d, '0'
    jb   .end
    cmp  r10d, 9
    ja   .end
    cmp  r9d, 20
    jae  .no
    cmp  r8, r11
    ja   .no
    jb   .accumulate
    cmp  r10d, 5
    ja   .no
.accumulate:
    imul r8, r8, 10
    add  r8, r10
    inc  r9d
    inc  rcx
    jmp  .digit
.end:
    test r9d, r9d
    jz   .no
    cmp  r9d, 1
    jbe  .yes
    cmp  byte [rdi], '0'
    je   .no
.yes:
    mov  rdi, rcx
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

align 8
hsm_view: dd 0
hsm_logical: dd 0
hsm_sample: dd 0
hsm_optional_bits: dd 0
hsm_frequency_state: dd 0
hsm_cpu_state: dd 0
hsm_uc_bsp: dd 0                         ; this row's uc_scope: 1 early_bsp, 0 early_ap, -1 none
hsm_active: dd 0
hsm_measured: dd 0
hsm_verb: db "SMPSTAT",0
hsm_nonce_arg: db "0000000000000000 ",0
hsm_summary_arg: db "SUMMARY",0
hsm_chip_arg: db "CHIP",0
hsm_sample_arg: db " sample=",0
hsm_selectors: db "SUMMARY",0,"CPU",0,"HEALTH",0,"LOAD",0,"SCHEMA",0,"WORK",0,"DETAIL",0,"PROGRESS",0,"POLICY",0,"VALIDATE",0,"RESULTS",0,0
hsm_typed_head: db " smpstat v=2",0
hsm_native_head: db "SMPSTAT_V2 nonce=0000000000000000",0
hsm_bad: db " hook err=smpstat_reply_incomplete",0
hsm_unavailable: db "unavailable",0
hsm_cpu_states: db "bsp",0,"online",0,"discovered",0,"pending",0,"failed",0,0
hsm_freq_states: db "measured",0,"idle",0,"unsupported",0,0
hsm_freq_sources: db "aperfmperf_cpuid16",0,"aperfmperf_platform_info",0,"aperfmperf_base_unavailable",0,"unsupported",0,0
hsm_health_states: db "ok",0,"stalled",0,0
hsm_current_states: db "idle",0,"unified",0,0
hsm_vendors: db "GenuineIntel",0,"AuthenticAMD",0,"unknown",0,0
hsm_leaves: db "0x0000001f",0,"0x0000000b",0,"0x8000001e",0,"unknown",0,0
hsm_lapics: db "xapic",0,"x2apic",0,0
align 8
hsm_summary_fields:
    dq hsm_lit_0 - $, 0, 0
    dq hsm_lit_1 - $, 1, 4294967295
    dq hsm_lit_2 - $, 1, 4294967295
    dq hsm_lit_3 - $, 1, 4294967295
    dq hsm_lit_4 - $, 1, 4294967295
    dq hsm_lit_5 - $, 1, 4294967295
    dq hsm_lit_6 - $, 1, 4294967295
    dq hsm_lit_7 - $, 2, hsm_vendors - ($ + 16)
    dq hsm_lit_8 - $, 1, 4294967295
    dq hsm_lit_9 - $, 1, 4294967295
    dq hsm_lit_10 - $, 1, 4294967295
    dq hsm_lit_11 - $, 1, 4294967295
    dq hsm_lit_12 - $, 1, 4294967295
    dq hsm_lit_13 - $, 1, 1
    dq hsm_lit_14 - $, 2, hsm_leaves - ($ + 16)
    dq hsm_lit_15 - $, 1, 4294967295
    dq hsm_lit_16 - $, 2, hsm_lapics - ($ + 16)
    dq hsm_lit_17 - $, 0, 0
    dq hsm_lit_18 - $, 1, 4294967295
    dq hsm_lit_19 - $, 1, 4294967295
    dq hsm_lit_20 - $, 1, 255
    dq 0
align 8
hsm_cpu_start:
    dq hsm_lit_21 - $, 0, 0
    dq hsm_lit_22 - $, 3, 31
    dq hsm_lit_23 - $, 1, 4294967295
    dq hsm_lit_24 - $, 1, 4294967295
    dq hsm_lit_25 - $, 1, 4294967295
    dq hsm_lit_26 - $, 1, 4294967295
    dq hsm_lit_27 - $, 1, 4294967295
    dq 0
align 8
hsm_cpu_state_fields:
    dq hsm_lit_28 - $, 7, hsm_cpu_states - ($ + 16)
    dq hsm_lit_6 - $, 1, 1
    dq hsm_lit_29 - $, 1, 1
    dq hsm_lit_30 - $, 1, 1
    dq hsm_lit_31 - $, 1, 1
    dq hsm_lit_32 - $, 1, 1
    dq hsm_lit_33 - $, 1, 1
    dq hsm_lit_34 - $, 0, 0
    dq hsm_lit_35 - $, 1, 18446744073709551615
    dq hsm_lit_36 - $, 1, 4294967295
    dq hsm_lit_37 - $, 1, 4294967295
    dq hsm_lit_38 - $, 1, 18446744073709551615
    dq 0
align 8
hsm_lapic_fields:
    dq hsm_lit_39 - $, 1, 4294967295
    dq hsm_lit_40 - $, 1, 4294967295
    dq hsm_lit_41 - $, 1, 4294967295
    dq hsm_lit_42 - $, 1, 4294967295
    dq hsm_lit_43 - $, 1, 4294967295
    dq 0
align 8
hsm_cpu_tail:
    dq hsm_lit_44 - $, 1, 4294967295
    dq hsm_lit_45 - $, 1, 18446744073709551615
    dq hsm_lit_46 - $, 1, 18446744073709551615
    dq hsm_lit_47 - $, 1, 18446744073709551615
    dq hsm_lit_core_type - $, 1, 255
    dq 0
align 8
hsm_health_fields:
    dq hsm_lit_48 - $, 0, 0
    dq hsm_lit_49 - $, 1, 4294967295
    dq hsm_lit_50 - $, 1, 4294967295
    dq hsm_lit_51 - $, 1, 4294967295
    dq hsm_lit_4 - $, 1, 4294967295
    dq hsm_lit_52 - $, 1, 4294967295
    dq hsm_lit_53 - $, 1, 4294967295
    dq hsm_lit_54 - $, 1, 18446744073709551615
    dq hsm_lit_55 - $, 0, 0
    dq 0
align 8
hsm_schema_fields:
    dq hsm_lit_56 - $, 0, 0
    dq 0
align 8
hsm_chip_fields:
    dq hsm_lit_57 - $, 0, 0
    dq hsm_lit_22 - $, 1, 4294967295
    dq hsm_lit_4 - $, 1, 4294967295
    dq hsm_lit_49 - $, 1, 4294967295
    dq hsm_lit_50 - $, 1, 4294967295
    dq hsm_lit_51 - $, 1, 4294967295
    dq hsm_lit_58 - $, 1, 1000
    dq hsm_lit_59 - $, 1, 1000
    dq hsm_lit_60 - $, 1, 4294967295
    dq hsm_lit_61 - $, 1, 4294967295
    dq hsm_lit_62 - $, 1, 4294967295
    dq hsm_lit_63 - $, 1, 1000
    dq hsm_lit_64 - $, 1, 4294967295
    dq hsm_lit_65 - $, 1, 4294967295
    dq hsm_lit_66 - $, 9, 4294967295
    dq hsm_lit_67 - $, 1, 4294967295
    dq hsm_lit_68 - $, 8, 4294967295
    dq hsm_lit_69 - $, 1, 18446744073709551615
    dq hsm_lit_70 - $, 1, 18446744073709551615
    dq hsm_lit_71 - $, 5, 18446744073709551615
    dq hsm_lit_72 - $, 1, 18446744073709551615
    dq hsm_lit_73 - $, 1, 18446744073709551615
    dq hsm_lit_74 - $, 5, 18446744073709551615
    dq hsm_lit_75 - $, 5, 18446744073709551615
    dq hsm_lit_76 - $, 5, 18446744073709551615
    dq hsm_lit_77 - $, 0, 0
    dq 0
align 8
hsm_load_cpu_fields:
    dq hsm_lit_78 - $, 0, 0
    dq hsm_lit_22 - $, 3, 31
    dq hsm_lit_25 - $, 1, 4294967295
    dq hsm_lit_26 - $, 1, 4294967295
    dq hsm_lit_27 - $, 1, 4294967295
    dq hsm_lit_49 - $, 4, 4294967295
    dq hsm_lit_50 - $, 1, 4294967295
    dq hsm_lit_51 - $, 1, 4294967295
    dq hsm_lit_58 - $, 1, 1000
    dq hsm_lit_59 - $, 1, 1000
    dq hsm_lit_33 - $, 1, 4294967295
    dq hsm_lit_79 - $, 2, hsm_current_states - ($ + 16)
    dq hsm_lit_80 - $, 1, 18446744073709551615
    dq hsm_lit_81 - $, 1, 18446744073709551615
    dq hsm_lit_82 - $, 1, 18446744073709551615
    dq hsm_lit_83 - $, 1, 18446744073709551615
    dq hsm_lit_84 - $, 1, 4294967295
    dq hsm_lit_85 - $, 1, 4294967295
    dq hsm_lit_86 - $, 1, 18446744073709551615
    dq hsm_lit_44 - $, 1, 4294967295
    dq hsm_lit_87 - $, 2, hsm_health_states - ($ + 16)
    dq hsm_lit_88 - $, 5, 18446744073709551615
    dq hsm_lit_89 - $, 5, 18446744073709551615
    dq hsm_lit_90 - $, 5, 4294967295
    dq hsm_lit_71 - $, 5, 18446744073709551615
    dq hsm_lit_91 - $, 5, 18446744073709551615
    dq hsm_lit_76 - $, 5, 18446744073709551615
    dq hsm_lit_92 - $, 6, hsm_freq_states - ($ + 16)
    dq hsm_lit_93 - $, 2, hsm_freq_sources - ($ + 16)
    dq hsm_lit_94 - $, 0, 0
    dq 0
hsm_lit_0: db " view=summary",0
hsm_lit_1: db " configured=",0
hsm_lit_2: db " enabled=",0
hsm_lit_3: db " discovered=",0
hsm_lit_4: db " online=",0
hsm_lit_5: db " failed=",0
hsm_lit_6: db " late=",0
hsm_lit_7: db " vendor=",0
hsm_lit_8: db " capacity=",0
hsm_lit_9: db " packages=",0
hsm_lit_10: db " physical_cores=",0
hsm_lit_11: db " threads_per_core=",0
hsm_lit_12: db " logical_cpus=",0
hsm_lit_13: db " overflow=",0
hsm_lit_14: db " topology_leaf=",0
hsm_lit_15: db " bsp=",0
hsm_lit_16: db " lapic=",0
hsm_lit_17: db " scheduler=unified",0
hsm_lit_18: db " resched_ipi=",0
hsm_lit_19: db " tlb_epoch=",0
hsm_lit_20: db " crashes=",0
hsm_lit_21: db " view=cpu",0
hsm_lit_22: db " logical=",0
hsm_lit_23: db " apic=",0
hsm_lit_24: db " uid=",0
hsm_lit_25: db " package=",0
hsm_lit_26: db " core=",0
hsm_lit_27: db " thread=",0
hsm_lit_28: db " state=",0
hsm_lit_29: db " stack=",0
hsm_lit_30: db " tss=",0
hsm_lit_31: db " ist=",0
hsm_lit_32: db " timer=",0
hsm_lit_33: db " runq=",0
hsm_lit_34: db " current=unified",0
hsm_lit_35: db " preempt=",0
hsm_lit_36: db " steal_in=",0
hsm_lit_37: db " steal_out=",0
hsm_lit_38: db " irq=",0
hsm_lit_39: db " lapic_lvt=",0
hsm_lit_40: db " lapic_dcr=",0
hsm_lit_41: db " lapic_icr=",0
hsm_lit_42: db " lapic_rearm_required=",0
hsm_lit_43: db " lapic_rearm_acked=",0
hsm_lit_44: db " faults=",0
hsm_lit_45: db " halts=",0
hsm_lit_46: db " chunks=",0
hsm_lit_47: db " busy_tsc=",0
hsm_lit_core_type: db " core_type=",0
hsm_lit_48: db " view=health",0
hsm_lit_49: db " sample_seq=",0
hsm_lit_50: db " sample_ms=",0
hsm_lit_51: db " sample_us=",0
hsm_lit_52: db " healthy=",0
hsm_lit_53: db " stalled=",0
hsm_lit_54: db " last_progress_ms=",0
hsm_lit_55: db " critical_tasks=protected",0
hsm_lit_56: db " view=schema selectors=SUMMARY,CPU,HEALTH,LOAD,SCHEMA ai_projection=registry sample_model=stable_snapshot frequency_model=passive_aperfmperf effect=read",0
hsm_lit_57: db " view=load target=chip",0
hsm_lit_58: db " load_permille=",0
hsm_lit_59: db " idle_permille=",0
hsm_lit_60: db " load_sum_permille=",0
hsm_lit_61: db " runq_total=",0
hsm_lit_62: db " runq_max=",0
hsm_lit_63: db " imbalance_permille=",0
hsm_lit_64: db " busiest_logical=",0
hsm_lit_65: db " freq_capable=",0
hsm_lit_66: db " freq_measured=",0
hsm_lit_67: db " freq_idle=",0
hsm_lit_68: db " freq_active_mhz=",0
hsm_lit_69: db " aperf_delta_total=",0
hsm_lit_70: db " mperf_delta_total=",0
hsm_lit_71: db " frequency=",0
hsm_lit_72: db " effective_mhz_total=",0
hsm_lit_73: db " effective_mhz_mean=",0
hsm_lit_74: db " freq_min_mhz=",0
hsm_lit_75: db " freq_max_mhz=",0
hsm_lit_76: db " freq_ratio_permille=",0
hsm_lit_77: db " freq_source=mixed temperature=unavailable",0
hsm_lit_78: db " view=load target=cpu",0
hsm_lit_79: db " current=",0
hsm_lit_80: db " irq_delta=",0
hsm_lit_81: db " preempt_delta=",0
hsm_lit_82: db " ctx_switch_delta=",0
hsm_lit_83: db " migration_delta=",0
hsm_lit_84: db " steal_in_delta=",0
hsm_lit_85: db " steal_out_delta=",0
hsm_lit_86: db " progress_age_ms=",0
hsm_lit_87: db " health=",0
hsm_lit_88: db " aperf_delta=",0
hsm_lit_89: db " mperf_delta=",0
hsm_lit_90: db " base_mhz=",0
hsm_lit_91: db " effective_mhz=",0
hsm_lit_92: db " freq_state=",0
hsm_lit_93: db " freq_source=",0
hsm_lit_94: db " temperature=unavailable",0

hsm_sec_header: db " sec_scope=cpu_init sec_policy=incomplete sec_ready=",0
hsm_uc_header: db " uc_scope=early_ap uc_ready=",0
hsm_uc_bsp_header: db " uc_scope=early_bsp uc_ready=",0
hsm_sec_vendor: db " sec_vendor=",0
hsm_sec_hv: db " sec_hv=",0
hsm_sec_sig: db " sec_sig=",0
hsm_sec_rev_valid: db " sec_rev_valid=",0
hsm_sec_rev: db " sec_rev=",0
hsm_sec_caps: db " sec_caps=",0
hsm_sec_ctrl_mask: db " sec_ctrl_mask=",0
hsm_sec_ctrl_valid: db " sec_ctrl_valid=",0
hsm_sec_ctrl: db " sec_ctrl=",0
hsm_sec_arch_valid: db " sec_arch_valid=",0
hsm_sec_arch: db " sec_arch=",0
hsm_uc_result32: db " uc_result32=",0
hsm_uc_owner: db " uc_owner=",0
hsm_uc_owner_valid: db " uc_owner_valid=",0
hsm_uc_load_match: db " uc_load_match=",0
hsm_uc_post_valid: db " uc_post_valid=",0
hsm_uc_pid: db " uc_pid=",0
hsm_uc_selected: db " uc_selected=",0
hsm_uc_readback: db " uc_readback=",0
hsm_uc_io_count: db " uc_io_count=",0
hsm_uc_io_failure: db " uc_io_failure=",0
hsm_uc_pre_vendor: db " uc_pre_vendor=",0
hsm_uc_pre_hv: db " uc_pre_hv=",0
hsm_uc_pre_sig: db " uc_pre_sig=",0
hsm_uc_pre_rev_valid: db " uc_pre_rev_valid=",0
hsm_uc_pre_rev: db " uc_pre_rev=",0
hsm_uc_pre_caps: db " uc_pre_caps=",0
hsm_uc_pre_ctrl_mask: db " uc_pre_ctrl_mask=",0
hsm_uc_pre_ctrl_valid: db " uc_pre_ctrl_valid=",0
hsm_uc_pre_ctrl: db " uc_pre_ctrl=",0
hsm_uc_pre_arch_valid: db " uc_pre_arch_valid=",0
hsm_uc_pre_arch: db " uc_pre_arch=",0
hsm_uc_post_vendor: db " uc_post_vendor=",0
hsm_uc_post_hv: db " uc_post_hv=",0
hsm_uc_post_sig: db " uc_post_sig=",0
hsm_uc_post_rev_valid: db " uc_post_rev_valid=",0
hsm_uc_post_rev: db " uc_post_rev=",0
hsm_uc_post_caps: db " uc_post_caps=",0
hsm_uc_post_ctrl_mask: db " uc_post_ctrl_mask=",0
hsm_uc_post_ctrl_valid: db " uc_post_ctrl_valid=",0
hsm_uc_post_ctrl: db " uc_post_ctrl=",0
hsm_uc_post_arch_valid: db " uc_post_arch_valid=",0
hsm_uc_post_arch: db " uc_post_arch=",0
align 8
hsm_sec_fields:
    dq hsm_sec_vendor - $, 1, 2
    dq hsm_sec_hv - $, 1, 1
    dq hsm_sec_sig - $, 1, 4294967295
    dq hsm_sec_rev_valid - $, 1, 1
    dq hsm_sec_rev - $, 1, 4294967295
    dq hsm_sec_caps - $, 1, 18446744073709551615
    dq hsm_sec_ctrl_mask - $, 1, 18446744073709551615
    dq hsm_sec_ctrl_valid - $, 1, 1
    dq hsm_sec_ctrl - $, 1, 18446744073709551615
    dq hsm_sec_arch_valid - $, 1, 1
    dq hsm_sec_arch - $, 1, 18446744073709551615
    dq 0
align 8
hsm_uc_fields:
    dq hsm_uc_result32 - $, 1, 4294967295
    dq hsm_uc_owner - $, 1, 4294967295
    dq hsm_uc_owner_valid - $, 1, 1
    dq hsm_uc_load_match - $, 1, 1
    dq hsm_uc_post_valid - $, 1, 1
    dq hsm_uc_pid - $, 1, 4294967295
    dq hsm_uc_selected - $, 1, 4294967295
    dq hsm_uc_readback - $, 1, 4294967295
    dq hsm_uc_io_count - $, 1, 16
    dq hsm_uc_io_failure - $, 1, 6
    dq hsm_uc_pre_vendor - $, 1, 2
    dq hsm_uc_pre_hv - $, 1, 1
    dq hsm_uc_pre_sig - $, 1, 4294967295
    dq hsm_uc_pre_rev_valid - $, 1, 1
    dq hsm_uc_pre_rev - $, 1, 4294967295
    dq hsm_uc_pre_caps - $, 1, 18446744073709551615
    dq hsm_uc_pre_ctrl_mask - $, 1, 18446744073709551615
    dq hsm_uc_pre_ctrl_valid - $, 1, 1
    dq hsm_uc_pre_ctrl - $, 1, 18446744073709551615
    dq hsm_uc_pre_arch_valid - $, 1, 1
    dq hsm_uc_pre_arch - $, 1, 18446744073709551615
    dq hsm_uc_post_vendor - $, 1, 2
    dq hsm_uc_post_hv - $, 1, 1
    dq hsm_uc_post_sig - $, 1, 4294967295
    dq hsm_uc_post_rev_valid - $, 1, 1
    dq hsm_uc_post_rev - $, 1, 4294967295
    dq hsm_uc_post_caps - $, 1, 18446744073709551615
    dq hsm_uc_post_ctrl_mask - $, 1, 18446744073709551615
    dq hsm_uc_post_ctrl_valid - $, 1, 1
    dq hsm_uc_post_ctrl - $, 1, 18446744073709551615
    dq hsm_uc_post_arch_valid - $, 1, 1
    dq hsm_uc_post_arch - $, 1, 18446744073709551615
    dq 0

; Owned selectors use the original work identity, not a fresh transport nonce.
; GET STATUS is passive; CANCEL delegates native maintenance and cancellation.
; The synchronous native cancellation leaves ACCEPTED=0 (no new async job).
; Native STATUS/CANCEL have no scalar: require zero, exact end cursor and complete
; canonical reply before copying it. BSP dispatch serializes plan/post/staging.
hsw_post:
    push rbx
    push r12
    mov  rbx, rcx
    cmp  qword [rbx + RSP_CODE], CMDE_OK
    jne  .refused
    cmp  dword [rel hsm_view], 13
    jne  .custody
    cmp  qword [rbx + RSP_ACCEPTED], 0   ; synchronous native cancellation envelope
    jne  .bad
.custody:
    cmp  byte [rel hsw_pending], 1
    jne  .bad
    cmp  byte [rel smpobs_out_ready], 1
    jne  .bad
    cmp  qword [rbx + RSP_VAL], 0
    jne  .bad
    xor  r12d, r12d
.scan:
    cmp  r12d, 1024                     ; actual native SMPOBS_OUT_CAP
    jae  .bad
    lea  rax, [rel smpobs_out_buf]
    cmp  byte [rax + r12], 0
    je   .bounded
    inc  r12d
    jmp  .scan
.bounded:
    add  rax, r12
    cmp  rax, [rel smpobs_out_cur]
    jne  .bad
    lea  rdi, [rel smpobs_out_buf]
    call hsw_record
    test eax, eax
    jz   .bad
    call command_hook_out_reset
    lea  rdi, [rel hsw_typed_head]
    cmp  dword [rel hsm_view], 13
    jne  .typed_head
    lea  rdi, [rel hsw_cancel_head]
.typed_head:
    call command_hook_out_str
    lea  rdi, [rel smpobs_out_buf + 13]  ; full state + both owned handle fields
    mov  esi, r12d
    sub  esi, 13
    call command_hook_out_strn
    jmp  .staged
.bad:
    call command_hook_out_reset
    lea  rdi, [rel hsm_bad]
    call command_hook_out_str
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_ACCEPTED], 0
    lea  rax, [rel hsm_bad]
    mov  [rbx + RSP_HINT], rax
.staged:
    mov  qword [rbx + RSP_VAL], 0
    call hsw_retire
    mov  eax, 1
    jmp  .out
.refused:
    mov  qword [rbx + RSP_VAL], 0
    call hsw_retire
    xor  eax, eax                       ; preserve the actual native refusal
.out:
    pop  r12
    pop  rbx
    ret

hsw_record:
    lea  rsi, [rel hsw_native_head]
    call hsm_literal
    test eax, eax
    jz   .out
    lea  rsi, [rel hsw_states]
    call hsm_enum
    test eax, eax
    jz   .out
    cmp  dword [rel hsm_view], 13
    jne  .state_ok
    cmp  eax, 4                        ; CANCELLED only for cancellation
    jne  .bad
.state_ok:
    lea  rsi, [rel hsw_nonce_key]
    call hsm_literal
    test eax, eax
    jz   .out
    mov  esi, 16
    call hsw_reply_hex
    test eax, eax
    jz   .out
    mov  eax, [rel hsw_nonce]            ; upper32 must remain zero
    cmp  r8, rax
    jne  .bad
    lea  rsi, [rel hsw_generation_key]
    call hsm_literal
    test eax, eax
    jz   .out
    mov  esi, 16
    call hsw_reply_hex
    test eax, eax
    jz   .out
    cmp  r8, [rel hsw_generation]
    jne  .bad
    cmp  byte [rdi], 0
    jne  .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
.out:
    ret

; Input accepts the native case-insensitive digits with lowercase 0x; emitted
; replies must use canonical lowercase digits. Exact fixed width, no overflow.
hsw_arg_hex:
    mov  r9d, 1
    jmp  hsw_hex
hsw_reply_hex:
    xor  r9d, r9d
hsw_hex:
    cmp  word [rdi], '0x'
    jne  .bad
    add  rdi, 2
    xor  r8d, r8d
.next:
    movzx edx, byte [rdi]
    cmp  edx, '0'
    jb   .bad
    cmp  edx, '9'
    jbe  .decimal
    cmp  edx, 'a'
    jb   .upper
    cmp  edx, 'f'
    ja   .bad
    sub  edx, 'a' - 10
    jmp  .accumulate
.upper:
    test r9d, r9d
    jz   .bad
    cmp  edx, 'A'
    jb   .bad
    cmp  edx, 'F'
    ja   .bad
    sub  edx, 'A' - 10
    jmp  .accumulate
.decimal:
    sub  edx, '0'
.accumulate:
    shl  r8, 4
    or   r8, rdx
    inc  rdi
    dec  esi
    jnz  .next
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

hsw_retire:
    mov  qword [rel hsp_mask], 0
    mov  qword [rel hsp_expected], 0
    mov  qword [rel hsp_pubmask], 0
    mov  dword [rel hsd_state], 0
    mov  qword [rel hsd_phase], 0
    mov  qword [rel hsd_result], 0
    mov  byte [rel hsw_pending], 0
    mov  dword [rel hsw_nonce], 0
    mov  qword [rel hsw_generation], 0
    mov  byte [rel smpobs_out_ready], 0
    mov  qword [rel smpobs_out_cur], 0
    lea  rdi, [rel smpobs_out_buf]
    xor  eax, eax
    mov  ecx, 1024 / 8
    rep stosq
    ret

align 8
hsw_generation: dq 0
hsw_nonce: dd 0
hsw_pending: db 0
hsw_verb: db "SMPWORK",0
hsw_status_arg: db "ASYNC STATUS ",0
hsw_cancel_arg: db "ASYNC CANCEL ",0
hsw_cancel_selector: db "WORK",0,0
hsw_cancel_head: db " smpstat v=2 view=cancel",0
hsw_native_head: db "SMPWORK_ASYNC state=",0
hsw_typed_head: db " smpstat v=2 view=work",0
hsw_nonce_key: db " nonce=",0
hsw_generation_key: db " generation=",0
hsw_states: db "PENDING",0,"READY",0,"PARTIAL",0,"CANCELLED",0,0

; Admission-only DETAIL uses the same native staging and original owned handle.
; Unlike STATUS, known retained failure and BUSY/STALE records have BADARG.
; Validate/copy those complete facts while retaining the actual refusal code;
; common OBSERVE never gives a success witness for a native refused result.
hsd_post:
    push rbx
    push r12
    mov  rbx, rcx
    cmp  byte [rel hsw_pending], 1
    jne  .bad
    cmp  byte [rel smpobs_out_ready], 1
    je   .staged
    cmp  qword [rbx + RSP_CODE], CMDE_OK
    jne  .refused
    jmp  .bad
.staged:
    cmp  dword [rel hsm_view], 12
    jne  .value
    cmp  qword [rbx + RSP_ACCEPTED], 0   ; synchronous native RESULTS envelope
    jne  .bad
.value:
    cmp  qword [rbx + RSP_VAL], 0
    jne  .bad
    xor  r12d, r12d
.scan:
    cmp  r12d, 1024                    ; RESULTS fits whole staging, no elision
    jae  .bad
    cmp  dword [rel hsm_view], 12
    je   .scan_byte
    cmp  r12d, 320                     ; native PROGRESS complete wire <320
    jae  .bad
    cmp  dword [rel hsm_view], 9
    je   .scan_byte
    cmp  r12d, 256                     ; preserve native DETAIL bound
    jae  .bad
.scan_byte:
    lea  rax, [rel smpobs_out_buf]
    cmp  byte [rax + r12], 0
    je   .bounded
    inc  r12d
    jmp  .scan
.bounded:
    add  rax, r12
    cmp  rax, [rel smpobs_out_cur]
    jne  .bad
    lea  rdi, [rel smpobs_out_buf]
    cmp  dword [rel hsm_view], 12
    je   .results_record
    cmp  dword [rel hsm_view], 9
    je   .progress_record
    call hsd_record
    jmp  .record_done
.progress_record:
    call hsp_record
    jmp  .record_done
.results_record:
    call hsr_record
.record_done:
    test eax, eax
    jz   .bad
    xor  eax, eax
    cmp  dword [rel hsd_state], 4
    jbe  .code
    mov  eax, CMDE_BADARG
.code:
    cmp  [rbx + RSP_CODE], rax
    jne  .bad
    call command_hook_out_reset
    cmp  dword [rel hsm_view], 12
    je   .results_copy
    cmp  dword [rel hsm_view], 9
    je   .progress_copy
    lea  rdi, [rel hsd_typed_head]
    call command_hook_out_str
    lea  rdi, [rel smpobs_out_buf + 17]  ; exact SMPWORK_DETAIL_V1 prefix
    mov  esi, r12d
    sub  esi, 17
    jmp  .copy
.progress_copy:
    lea  rdi, [rel hsp_typed_head]
    call command_hook_out_str
    lea  rdi, [rel smpobs_out_buf + 19]  ; exact SMPWORK_PROGRESS_V1 prefix
    mov  esi, r12d
    sub  esi, 19
    jmp  .copy
.results_copy:
    lea  rdi, [rel hsr_typed_head]
    call command_hook_out_str
    lea  rdi, [rel smpobs_out_buf + 18]  ; exact SMPWORK_RESULTS_V1 prefix
    mov  esi, r12d
    sub  esi, 18
.copy:
    call command_hook_out_strn
    jmp  .clear
.bad:
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_ACCEPTED], 0
    lea  rax, [rel hsm_bad]
    mov  [rbx + RSP_HINT], rax
    call command_hook_out_reset
    lea  rdi, [rel hsm_bad]
    call command_hook_out_str
.clear:
    mov  qword [rbx + RSP_VAL], 0
    call hsw_retire
    mov  eax, 1
    jmp  .out
.refused:
    mov  qword [rbx + RSP_VAL], 0
    call hsw_retire
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

hsd_record:
    lea  rsi, [rel hsd_native_head]
    jmp  hsd_parse

; Share the original admission decoder without changing DETAIL semantics.
; PROGRESS additionally checks its counted admission/publication sets.
hsp_record:
    lea  rsi, [rel hsp_native_head]
hsd_parse:
    call hsm_literal
    test eax, eax
    jz   .out
    lea  rsi, [rel hsd_states]
    call hsm_enum
    test eax, eax
    jz   .out
    mov  [rel hsd_state], eax
    lea  rsi, [rel hsw_nonce_key]
    call hsm_literal
    test eax, eax
    jz   .out
    mov  esi, 16
    call hsw_reply_hex
    test eax, eax
    jz   .out
    mov  eax, [rel hsw_nonce]
    cmp  r8, rax
    jne  .bad
    lea  rsi, [rel hsw_generation_key]
    call hsm_literal
    test eax, eax
    jz   .out
    mov  esi, 16
    call hsw_reply_hex
    test eax, eax
    jz   .out
    cmp  r8, [rel hsw_generation]
    jne  .bad
    cmp  dword [rel hsd_state], 8
    jae  .unknown
    cmp  dword [rel hsm_view], 9
    jne  .known
    test r8, r8                       ; known PROGRESS admission has a handle
    jz   .bad
.known:
    lea  rsi, [rel hsd_known]
    call hsm_literal
    test eax, eax
    jz   .out
    call hsm_u64
    test eax, eax
    jz   .out
    mov  [rel hsd_phase], r8
    lea  rsi, [rel hsd_result_key]
    call hsm_literal
    test eax, eax
    jz   .out
    call hsm_u64
    test eax, eax
    jz   .out
    mov  [rel hsd_result], r8
    lea  rsi, [rel hsd_epoch_key]
    call hsm_literal
    test eax, eax
    jz   .out
    call hsm_u64
    test eax, eax
    jz   .out
    test r8, r8
    jz   .bad
    mov  eax, 0xffffffff
    cmp  r8, rax
    ja   .bad
    lea  rsi, [rel hsd_mask_key]
    call hsm_literal
    test eax, eax
    jz   .out
    mov  esi, 16
    call hsw_reply_hex
    test eax, eax
    jz   .out
    mov  eax, 0xffffffff
    cmp  r8, rax
    ja   .bad
    mov  [rel hsp_mask], r8
    lea  rsi, [rel hsd_expected_key]
    call hsm_literal
    test eax, eax
    jz   .out
    call hsm_u64
    test eax, eax
    jz   .out
    cmp  r8, 32
    ja   .bad
    mov  [rel hsp_expected], r8
    mov  eax, [rel hsd_state]
    dec  eax
    lea  rsi, [rel hsd_phases]
    movzx ecx, byte [rsi + rax]
    cmp  [rel hsd_phase], rcx
    jne  .bad
    lea  rsi, [rel hsd_results]
    movzx ecx, byte [rsi + rax]
    cmp  [rel hsd_result], rcx
    jne  .bad
    cmp  dword [rel hsm_view], 9
    jne  .end
    mov  r8, [rel hsp_mask]
    call hsp_popcount32
    cmp  r8, [rel hsp_expected]
    jne  .bad
    cmp  dword [rel hsd_state], 3
    ja   .pub_unknown
    lea  rsi, [rel hsp_known]
    call hsm_literal
    test eax, eax
    jz   .out
    mov  esi, 16
    call hsw_reply_hex
    test eax, eax
    jz   .out
    mov  eax, 0xffffffff
    cmp  r8, rax
    ja   .bad
    mov  [rel hsp_pubmask], r8
    mov  rax, [rel hsp_mask]
    not  rax
    test r8, rax                      ; only originally admitted members
    jnz  .bad
    lea  rsi, [rel hsp_count_key]
    call hsm_literal
    test eax, eax
    jz   .out
    call hsm_u64
    test eax, eax
    jz   .out
    cmp  r8, [rel hsp_expected]
    ja   .bad
    mov  r9, r8
    mov  r8, [rel hsp_pubmask]
    call hsp_popcount32
    cmp  r8, r9                       ; exact population, including known zero
    jne  .bad
    jmp  .end
.unknown:
    lea  rsi, [rel hsd_unknown]
    call hsm_literal
    test eax, eax
    jz   .out
    cmp  dword [rel hsm_view], 9
    jne  .end
.pub_unknown:
    lea  rsi, [rel hsp_unknown]
    call hsm_literal
    test eax, eax
    jz   .out
.end:
    cmp  byte [rdi], 0
    jne  .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
.out:
    ret

hsd_arg: db "ASYNC DETAIL ",0
hsd_native_head: db "SMPWORK_DETAIL_V1 state=",0
hsd_typed_head: db " smpstat v=2 view=detail",0
hsd_states: db "PENDING",0,"READY",0,"PARTIAL",0,"CANCELLED",0,"CLOCK",0,"COUNTER",0,"TOPOLOGY",0,"BUSY",0,"STALE",0,0
hsd_known: db " known=1 phase=",0
hsd_result_key: db " result=",0
hsd_epoch_key: db " epoch=",0
hsd_mask_key: db " mask=",0
hsd_expected_key: db " expected=",0
hsd_unknown: db " known=0 phase=unknown result=unknown epoch=unknown mask=unknown expected=unknown",0
hsd_phases: db 1,11,11,0,11,11,11
hsd_results: db 0,2,3,6,7,8,9
align 8
hsd_phase: dq 0
hsd_result: dq 0
hsd_state: dd 0

; Bounded software census avoids any new CPU feature requirement. R8 -> count,
; clobbers RAX/RCX only; preserves parser cursor and R9 comparison value.
hsp_popcount32:
    mov  eax, r8d
    xor  r8d, r8d
    mov  ecx, 32
.next:
    shr  eax, 1
    adc  r8d, 0
    dec  ecx
    jnz  .next
    ret

hsp_arg: db "ASYNC PROGRESS ",0
hsp_native_head: db "SMPWORK_PROGRESS_V1 state=",0
hsp_typed_head: db " smpstat v=2 view=progress",0
hsp_known: db " pub_known=1 published_mask=",0
hsp_count_key: db " published=",0
hsp_unknown: db " pub_known=0 published_mask=unknown published=unknown",0
align 8
hsp_mask: dq 0
hsp_expected: dq 0
hsp_pubmask: dq 0

; Frozen RESULTS keeps every native byte after its versioned prefix. The
; original full handle binds the reply; admission/row populations, state and
; packed widths must agree. Tokens are diagnostics, not authenticated proofs.
; Reuse retired parse cells: hsd_phase=workers; hsp_pubmask=rowmask.
hsr_record:
    lea  rsi, [rel hsr_native_head]
    call hsm_literal
    test eax, eax
    jz   .out
    lea  rsi, [rel hsd_states]
    call hsm_enum
    test eax, eax
    jz   .out
    mov  [rel hsd_state], eax
    lea  rsi, [rel hsw_nonce_key]
    call hsm_literal
    test eax, eax
    jz   .out
    mov  esi, 16
    call hsw_reply_hex
    test eax, eax
    jz   .out
    mov  eax, [rel hsw_nonce]
    cmp  r8, rax
    jne  .bad
    lea  rsi, [rel hsw_generation_key]
    call hsm_literal
    test eax, eax
    jz   .out
    mov  esi, 16
    call hsw_reply_hex
    test eax, eax
    jz   .out
    cmp  r8, [rel hsw_generation]
    jne  .bad
    cmp  dword [rel hsd_state], 2
    je   .known
    cmp  dword [rel hsd_state], 3
    jne  .unknown
.known:
    test r8, r8                       ; known snapshot has a real generation
    jz   .bad
    lea  rsi, [rel hsr_known]
    call hsm_literal
    test eax, eax
    jz   .out
    call hsm_u64
    test eax, eax
    jz   .out
    test r8, r8
    jz   .bad
    mov  eax, 0xffffffff
    cmp  r8, rax
    ja   .bad
    lea  rsi, [rel hsd_mask_key]
    call hsm_literal
    test eax, eax
    jz   .out
    mov  esi, 16
    call hsw_reply_hex
    test eax, eax
    jz   .out
    mov  eax, 0xffffffff
    cmp  r8, rax
    ja   .bad
    mov  [rel hsp_mask], r8
    lea  rsi, [rel hsd_expected_key]
    call hsm_literal
    test eax, eax
    jz   .out
    call hsm_u64
    test eax, eax
    jz   .out
    test r8, r8
    jz   .bad
    cmp  r8, 32
    ja   .bad
    mov  [rel hsp_expected], r8
    mov  r8, [rel hsp_mask]
    call hsp_popcount32
    cmp  r8, [rel hsp_expected]
    jne  .bad
    lea  rsi, [rel hsr_workers_key]
    call hsm_literal
    test eax, eax
    jz   .out
    call hsm_u64
    test eax, eax
    jz   .out
    cmp  r8, [rel hsp_expected]
    ja   .bad
    mov  [rel hsd_phase], r8
    cmp  dword [rel hsd_state], 2
    jne  .partial
    cmp  r8, [rel hsp_expected]
    jne  .bad
    jmp  .rowmask
.partial:
    cmp  r8, [rel hsp_expected]
    jae  .bad
.rowmask:
    lea  rsi, [rel hsr_rowmask_key]
    call hsm_literal
    test eax, eax
    jz   .out
    mov  esi, 16
    call hsw_reply_hex
    test eax, eax
    jz   .out
    mov  rax, [rel hsp_mask]
    not  rax
    test r8, rax                      ; row membership is admitted u32 subset
    jnz  .bad
    mov  [rel hsp_pubmask], r8
    call hsp_popcount32
    cmp  r8, [rel hsd_phase]
    jne  .bad
    lea  rsi, [rel hsr_audit_key]
    call hsm_literal
    test eax, eax
    jz   .out
    mov  ecx, 3
.audit:
    movzx eax, byte [rdi]
    sub  eax, '0'
    cmp  eax, 1
    ja   .bad
    inc  rdi
    dec  ecx
    jnz  .audit
    lea  rsi, [rel hsr_rows_key]
    call hsm_literal
    test eax, eax
    jz   .out
    mov  rcx, [rel hsd_phase]
    test rcx, rcx
    jz   .empty
    imul ecx, ecx, 24                 ; token8 + runs16, ascending rowmask
.packed:
    movzx eax, byte [rdi]
    cmp  eax, '0'
    jb   .bad
    cmp  eax, '9'
    jbe  .nibble
    cmp  eax, 'a'
    jb   .bad
    cmp  eax, 'f'
    ja   .bad
.nibble:
    inc  rdi
    dec  ecx
    jnz  .packed
    jmp  .end
.empty:
    cmp  byte [rdi], '-'
    jne  .bad
    inc  rdi
    jmp  .end
.unknown:
    lea  rsi, [rel hsr_unknown]
    call hsm_literal
    test eax, eax
    jz   .out
.end:
    cmp  byte [rdi], 0
    jne  .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
.out:
    ret

hsr_arg: db "ASYNC RESULTS ",0
hsr_native_head: db "SMPWORK_RESULTS_V1 state=",0
hsr_typed_head: db " smpstat v=2 view=results",0
hsr_known: db " known=1 epoch=",0
hsr_workers_key: db " workers=",0
hsr_rowmask_key: db " rowmask=",0
hsr_audit_key: db " audit=",0
hsr_rows_key: db " rows=",0
hsr_unknown: db " known=0 epoch=unknown mask=unknown expected=unknown workers=unknown rowmask=unknown audit=unknown rows=unknown",0

; Policy diagnostics reuse the native staging and registry. Neither native verb
; applies policy; both are existing exact public observations. Full ordered
; grammar, ready/cursor/zero-value binding and retirement prevent stale or
; private fields from becoming typed data. Fixed nonce is never a witness input.
hpo_post:
    push rbx
    push r12
    mov  rbx, rcx
    cmp  qword [rbx + RSP_CODE], CMDE_OK
    jne  .refused
    cmp  byte [rel hsw_pending], 1
    jne  .bad
    cmp  qword [rbx + RSP_VAL], 0
    jne  .bad
    cmp  byte [rel smpobs_out_ready], 1
    jne  .bad
    xor  r12d, r12d
.scan:
    cmp  r12d, 512
    jae  .bad
    lea  rax, [rel smpobs_out_buf]
    cmp  byte [rax + r12], 0
    je   .bounded
    inc  r12d
    jmp  .scan
.bounded:
    add  rax, r12
    cmp  rax, [rel smpobs_out_cur]
    jne  .bad
    lea  rdi, [rel smpobs_out_buf]
    call hpo_record
    test eax, eax
    jz   .bad
    call command_hook_out_reset
    lea  rdi, [rel hpo_typed_policy]
    cmp  dword [rel hsm_view], 10
    je   .head
    lea  rdi, [rel hpo_typed_validate]
.head:
    call command_hook_out_str
    lea  rdi, [rel smpobs_out_buf + hpo_policy_skip]
    mov  esi, r12d
    sub  esi, hpo_policy_skip
    cmp  dword [rel hsm_view], 10
    je   .copy
    lea  rdi, [rel smpobs_out_buf + hpo_validate_skip]
    mov  esi, r12d
    sub  esi, hpo_validate_skip
.copy:
    call command_hook_out_strn
    jmp  .clear
.bad:
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_ACCEPTED], 0
    lea  rax, [rel hsm_bad]
    mov  [rbx + RSP_HINT], rax
    call command_hook_out_reset
    lea  rdi, [rel hsm_bad]
    call command_hook_out_str
.clear:
    mov  qword [rbx + RSP_VAL], 0
    call hsw_retire
    mov  dword [rel hpo_profile], 0
    mov  eax, 1
    jmp  .out
.refused:
    mov  qword [rbx + RSP_VAL], 0
    call hsw_retire
    mov  dword [rel hpo_profile], 0
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

hpo_record:
    lea  rsi, [rel hpo_native_policy]
    cmp  dword [rel hsm_view], 10
    je   .head
    lea  rsi, [rel hpo_native_validate]
.head:
    call hsm_literal
    test eax, eax
    jz   .out
    cmp  dword [rel hsm_view], 10
    jne  .validate
    lea  rsi, [rel hpo_policy_fields]
    call hsm_fields
    test eax, eax
    jz   .out
    jmp  .invariants
.validate:
    lea  rsi, [rel hpo_profile_key]
    call hsm_literal
    test eax, eax
    jz   .out
    lea  rsi, [rel hpo_profiles]
    call hsm_enum
    cmp  eax, [rel hpo_profile]
    jne  .bad
    lea  rsi, [rel hpo_valid]
    call hsm_literal
    test eax, eax
    jz   .out
.invariants:
    lea  rsi, [rel hpo_invariants]
    call hsm_literal
    test eax, eax
    jz   .out
    cmp  byte [rdi], 0
    jne  .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
.out:
    ret

align 8
hpo_profile: dd 0
hpo_stat_verb: db "SMPPOLSTAT",0
hpo_validate_verb: db "SMPPOLVALIDATE",0
hpo_nonce: db "0000000000000000",0
hpo_validate_balanced: db "0000000000000000 profile=balanced",0
hpo_validate_physical: db "0000000000000000 profile=physical_first",0
hpo_profiles: db "balanced",0,"physical_first",0,0
hpo_native_policy: db "SMPPOLSTAT nonce=0000000000000000",0
hpo_policy_skip equ $ - hpo_native_policy - 1
hpo_native_validate: db "SMPPOLVALIDATE nonce=0000000000000000",0
hpo_validate_skip equ $ - hpo_native_validate - 1
hpo_typed_policy: db " smpstat v=2 view=policy",0
hpo_typed_validate: db " smpstat v=2 view=validate",0
hpo_profile_key: db " profile=",0
hpo_generation_key: db " generation=",0
hpo_previous_profile_key: db " previous_profile=",0
hpo_previous_generation_key: db " previous_generation=",0
hpo_audit_key: db " audit=",0
hpo_auto_key: db " auto_rollback=",0
hpo_valid: db " valid=1 mutated=0",0
hpo_invariants: db " critical_tasks=protected online_change=0 smt_change=0 topology_change=0 effect=scheduling_preference",0
align 8
hpo_policy_fields:
    dq hpo_profile_key - $, 2, hpo_profiles - ($ + 16)
    dq hpo_generation_key - $, 1, 4294967295
    dq hpo_previous_profile_key - $, 2, hpo_profiles - ($ + 16)
    dq hpo_previous_generation_key - $, 1, 4294967295
    dq hpo_audit_key - $, 1, 4294967295
    dq hpo_auto_key - $, 1, 1
    dq 0
