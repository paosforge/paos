;; MODULE svc/power_mode
;; LAYER 5
;; EXPORTS power_mode_declare, cmd_verb_powermode, power_mode_word, power_mode_set, gov_power_mode
;; IMPORTS core/smp, core/lib/str, svc/command, svc/command_auth, svc/governor, svc/thermal
;; CAPS
;; OWNER saga:power
; ============================================================================
; svc/power_mode.asm — RC power service P1: the owner's Power mode (root 52080 (3),
; plan 52188, GO 54382; P1_DESIGN.md).
;
; Three modes over the governor's own per-CPU request MSR (Intel IA32_HWP_REQUEST
; 774H, AMD CPPC_REQ C001_02B3), every field from the fused capability window the
; governor admitted at boot:
;   Efficiency  max = HWP guaranteed / CPPC nominal (lowers the limit), EPP 0xC0
;   Balanced    the boot relax word (gov_relax), EPP 0x80   <- every boot
;   Performance max = highest, EPP 0x40 (only the hint moves)
; min stays lowest (Intel) / lowest_nonlinear (AMD): no mode raises min or exceeds
; the fused highest. RAM only: no EFI variable, no NVRAM, no persistence; a reboot
; is Balanced. Firmware keeps fans and emergency throttling.
;
; A set writes no MSR unless the governor relaxed every CPU at boot on bare metal
; (no hypervisor, no PaOSPowerPolicy=FWCT, HWP or CPPC present, boot relax with an
; empty failed mask). Performance is refused while 19CH reports thermal, PROCHOT
; or critical (read on the HWP path only; root 54382). The APs are written through
; smp_msr_apply_aps, then the BSP, each read back. Any failure re-applies Balanced
; the same way: Balanced is reported only when every rollback readback passes; a
; failed rollback is mode=unknown state=mixed and every later set is refused until
; reboot (root 54382). Both masks are kept and reported.
;
; Owner only: registered with CMD_AUTH_CAP_MUTATE and the handler checks the
; owner envelope itself (SYSTEM holds generic MUTATE), as POWERSTAT does.
;
; Reply "POWERMODE mode=<eff|bal|perf|unknown> word=<hex> ok=<hex> failed=<hex>
;   rollback_ok=<hex> rollback_failed=<hex> reverted=<0|1> reason=<name>"
; ============================================================================

PMODE_EFF           equ 0
PMODE_BAL           equ 1
PMODE_PERF          equ 2
PMODE_UNKNOWN       equ 3
PMODE_EPP_EFF       equ 0xC0
PMODE_EPP_PERF      equ 0x40
PMODE_THERM_HOT     equ (1 << 0) | (1 << 2) | (1 << 4) ; 19CH thermal, PROCHOT#/FORCEPR#, critical

PMR_OK              equ 0
PMR_BOOTING         equ 1            ; the boot relax has not run
PMR_RELAX_FAILED    equ 2            ; the boot relax left a failed mask
PMR_NOHWP           equ 3            ; neither HWP nor CPPC admitted (HP Zen+, invalid caps)
PMR_FWCT            equ 4            ; PaOSPowerPolicy = FWCT
PMR_HYPERVISOR      equ 5
PMR_THERMAL         equ 6            ; Performance refused while hot
PMR_MIXED           equ 7            ; a rollback did not read back: refused until reboot
PMR_REVERTED        equ 8            ; the set failed; Balanced restored and read back
PMR_COUNT           equ 9

power_mode_declare:
    lea  rdi, [rel str_verb_powermode]
    lea  rsi, [rel cmd_verb_powermode]
    mov  rdx, CMD_AUTH_CAP_MUTATE           ; explicit owner cap: never public
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1                              ; changes the CPUs' runtime request (RAM only)
    jmp  command_register_verb

; ---------------------------------------------------------------------------
; power_mode_word(EDI = PMODE_EFF|BAL|PERF) -> EAX = the request word for this
;   boot's admitted vendor path, 0 when neither HWP nor CPPC was admitted. Pure
;   over the governor's caps. Clobbers RAX, RCX, RDX, R8, R9.
; ---------------------------------------------------------------------------
power_mode_word:
    mov  r9d, GOV_EPP_BALANCE
    cmp  edi, PMODE_EFF
    jne  .not_eff
    mov  r9d, PMODE_EPP_EFF
.not_eff:
    cmp  edi, PMODE_PERF
    jne  .epp
    mov  r9d, PMODE_EPP_PERF
.epp:
    cmp  byte [rel gov_hwp_present], 1
    je   .intel
    cmp  byte [rel gov_cppc_present], 1
    jne  .none
    ; AMD: [7:0] max [15:8] min [23:16] desired 0 [31:24] EPP, from CPPC_CAP1
    mov  edx, [rel gov_cppc_cap1]
    mov  eax, edx
    shr  eax, 24                            ; highest
    cmp  edi, PMODE_EFF
    jne  .amd_max
    mov  eax, edx
    shr  eax, 16
    and  eax, 0xFF                          ; nominal (gov_cppc_detect: <= highest)
.amd_max:
    and  edx, 0xFF00                        ; lowest_nonlinear in [15:8]
    or   eax, edx
    shl  r9d, 24
    or   eax, r9d
    ret
.intel:
    ; Intel: [7:0] min [15:8] max [23:16] desired 0 [31:24] EPP, from HWP_CAP
    movzx eax, byte [rel gov_perf_lowest]
    movzx r8d, byte [rel gov_perf_highest]
    cmp  edi, PMODE_EFF
    jne  .intel_max
    movzx ecx, byte [rel gov_perf_guaranteed] ; gov_init publishes it only inside [lowest, highest]
    test ecx, ecx
    jz   .intel_max                         ; no guaranteed level: max stays highest
    mov  r8d, ecx
.intel_max:
    shl  r8d, 8
    or   eax, r8d
    shl  r9d, 24
    or   eax, r9d
    ret
.none:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; power_mode_apply(EDI = word) -> EAX = ok mask, EDX = failed mask (dense CPUs,
;   BSP = bit 0). The APs through smp_msr_apply_aps, then the BSP, each read back.
;   Clobbers caller-saved.
; ---------------------------------------------------------------------------
power_mode_apply:
    push rbx
    push r12
    push r13
    push r14
    mov  ebx, edi
    mov  r14d, GOV_MSR_HWP_REQ
    cmp  byte [rel gov_hwp_present], 1
    je   .aps
    mov  r14d, GOV_MSR_CPPC_REQ
.aps:
    mov  edi, r14d
    mov  esi, ebx
    xor  edx, edx                           ; CPPC_ENABLE was set on every CPU at boot
    call smp_msr_apply_aps                  ; -> EAX ok, EDX failed/missing (APs)
    mov  r12d, eax
    mov  r13d, edx
    mov  ecx, r14d
    mov  eax, ebx
    xor  edx, edx
    wrmsr
    rdmsr
    cmp  eax, ebx
    jne  .bsp_fail
    or   r12d, 1
    jmp  .out
.bsp_fail:
    or   r13d, 1
.out:
    mov  eax, r12d
    mov  edx, r13d
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; power_mode_set(EDI = PMODE_EFF|BAL|PERF) -> EAX = PMR_*. Updates gov_power_mode,
;   the word and the masks. Clobbers caller-saved.
; ---------------------------------------------------------------------------
power_mode_set:
    push rbx
    push r12
    mov  r12d, edi
    ; A mixed machine keeps the failed apply/rollback evidence until reboot.
    mov  ebx, PMR_MIXED
    cmp  byte [rel pm_mixed], 1
    je   .out
    mov  dword [rel pm_ok_mask], 0
    mov  dword [rel pm_fail_mask], 0
    mov  dword [rel pm_rb_ok_mask], 0
    mov  dword [rel pm_rb_fail_mask], 0
    mov  byte [rel pm_reverted], 0
    mov  eax, 1
    cpuid                                   ; clobbers EBX: the reason is set after
    mov  ebx, PMR_HYPERVISOR
    bt   ecx, 31
    jc   .out
    mov  ebx, PMR_FWCT
    cmp  byte [rel gov_policy_fw_seen], 1
    je   .out
    mov  ebx, PMR_NOHWP
    cmp  byte [rel gov_hwp_present], 1
    je   .hw
    cmp  byte [rel gov_cppc_present], 1
    jne  .out
.hw:
    mov  ebx, PMR_BOOTING
    cmp  byte [rel gov_relax_done], 1
    jne  .out
    mov  ebx, PMR_RELAX_FAILED
    cmp  dword [rel gov_relax_fail_mask], 0
    jne  .out
    cmp  r12d, PMODE_PERF
    jne  .apply
    cmp  byte [rel gov_hwp_present], 1
    jne  .apply                             ; 19CH is Intel's: read on the HWP path only
    mov  ecx, GOV_MSR_THERM_STAT
    rdmsr
    mov  ebx, PMR_THERMAL
    test eax, PMODE_THERM_HOT
    jnz  .out
.apply:
    mov  edi, r12d
    call power_mode_word
    mov  edi, eax
    call power_mode_apply
    mov  [rel pm_ok_mask], eax
    mov  [rel pm_fail_mask], edx
    test edx, edx
    jnz  .rollback
    mov  [rel gov_power_mode], r12b
    mov  ebx, PMR_OK
    jmp  .out
.rollback:
    mov  edi, PMODE_BAL
    call power_mode_word
    mov  edi, eax
    call power_mode_apply
    mov  [rel pm_rb_ok_mask], eax
    mov  [rel pm_rb_fail_mask], edx
    mov  byte [rel pm_reverted], 1
    test edx, edx
    jnz  .mixed
    mov  byte [rel gov_power_mode], PMODE_BAL
    mov  ebx, PMR_REVERTED
    jmp  .out
.mixed:
    mov  byte [rel gov_power_mode], PMODE_UNKNOWN
    mov  byte [rel pm_mixed], 1
    mov  ebx, PMR_MIXED
.out:
    mov  [rel pm_reason], ebx
    mov  eax, ebx
    pop  r12
    pop  rbx
    ret

; --- VERB: POWERMODE [eff|bal|perf] — no argument reads the mode ----------------
cmd_verb_powermode:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov  r12, rsi
    mov  r13, rdi
    cmp  qword [rdi + REQ_SOURCE], CMD_SOURCE_CONSOLE
    je   .owner                             ; the dispatcher already requires the console owner
    call command_auth_owner_request         ; 1 = own AUTH1 owner ticket, 2 = owner SSH key
    test eax, eax
    jz   .not_owner
.owner:
    mov  rbx, [r13 + REQ_ARG]
    test rbx, rbx
    jz   .get
    cmp  byte [rbx], 0
    je   .get
    mov  rdi, rbx
    lea  rsi, [rel str_pm_eff]
    call strcmp
    mov  edi, PMODE_EFF
    test eax, eax
    jz   .set
    mov  rdi, rbx
    lea  rsi, [rel str_pm_bal]
    call strcmp
    mov  edi, PMODE_BAL
    test eax, eax
    jz   .set
    mov  rdi, rbx
    lea  rsi, [rel str_pm_perf]
    call strcmp
    mov  edi, PMODE_PERF
    test eax, eax
    jz   .set
    call therm_out_reset
    lea  rdi, [rel str_pm_badarg]
    call therm_out_str
    mov  byte [rel therm_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_BADARG
    mov  qword [r12 + RSP_VAL], 0
    jmp  .out
.set:
    call power_mode_set
    jmp  .reply
.get:                                       ; the last set's reason and masks stay reported
.reply:
    call power_mode_format
    mov  byte [rel therm_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_OK
    mov  eax, [rel pm_reason]
    mov  [r12 + RSP_VAL], rax
    jmp  .out
.not_owner:
    call therm_out_reset
    lea  rdi, [rel str_pm_owner_only]
    call therm_out_str
    mov  byte [rel therm_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_AUTHDENY
    mov  qword [r12 + RSP_VAL], 0
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; power_mode_format — the POWERMODE reply in therm_out_buf (< 200 bytes).
power_mode_format:
    push rbx
    call therm_out_reset
    lea  rdi, [rel str_pm_verb]
    call therm_out_str
    movzx ebx, byte [rel gov_power_mode]
    cmp  ebx, PMODE_UNKNOWN
    jbe  .name
    mov  ebx, PMODE_UNKNOWN
.name:
    mov  eax, ebx
    shl  eax, 3                             ; 8-byte slots
    lea  rdi, [rel pm_mode_names]
    add  rdi, rax
    call therm_out_str
    lea  rdi, [rel str_pm_word]
    call therm_out_str
    xor  eax, eax
    cmp  ebx, PMODE_UNKNOWN
    je   .word
    mov  edi, ebx
    call power_mode_word                    ; 0 when no vendor path was admitted
.word:
    mov  edi, eax
    call therm_out_hex
    lea  rdi, [rel str_pm_ok]
    call therm_out_str
    mov  edi, [rel pm_ok_mask]
    call therm_out_hex
    lea  rdi, [rel str_pm_failed]
    call therm_out_str
    mov  edi, [rel pm_fail_mask]
    call therm_out_hex
    lea  rdi, [rel str_pm_rb_ok]
    call therm_out_str
    mov  edi, [rel pm_rb_ok_mask]
    call therm_out_hex
    lea  rdi, [rel str_pm_rb_failed]
    call therm_out_str
    mov  edi, [rel pm_rb_fail_mask]
    call therm_out_hex
    lea  rdi, [rel str_pm_reverted]
    call therm_out_str
    movzx edi, byte [rel pm_reverted]
    call therm_out_dec
    lea  rdi, [rel str_pm_reason]
    call therm_out_str
    mov  eax, [rel pm_reason]
    cmp  eax, PMR_COUNT
    jb   .reason
    mov  eax, PMR_MIXED
.reason:
    shl  eax, 4                             ; 16-byte slots
    lea  rdi, [rel pm_reason_names]
    add  rdi, rax
    call therm_out_str
    pop  rbx
    ret

align 4
pm_reason:          dd PMR_OK
pm_ok_mask:         dd 0
pm_fail_mask:       dd 0
pm_rb_ok_mask:      dd 0
pm_rb_fail_mask:    dd 0
gov_power_mode:     db PMODE_BAL           ; RAM only: every boot is Balanced
pm_mixed:           db 0                   ; a rollback failed: sets refused until reboot
pm_reverted:        db 0

pm_mode_names:
    db "eff", 0, 0, 0, 0, 0
    db "bal", 0, 0, 0, 0, 0
    db "perf", 0, 0, 0, 0
    db "unknown", 0
pm_reason_names:
    db "ok", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    db "booting", 0, 0, 0, 0, 0, 0, 0, 0, 0
    db "relax_failed", 0, 0, 0, 0
    db "nohwp", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    db "fwct", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    db "hypervisor", 0, 0, 0, 0, 0, 0
    db "thermal", 0, 0, 0, 0, 0, 0, 0, 0, 0
    db "mixed", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    db "reverted", 0, 0, 0, 0, 0, 0, 0, 0

str_verb_powermode: db "POWERMODE", 0
str_pm_eff:         db "eff", 0
str_pm_bal:         db "bal", 0
str_pm_perf:        db "perf", 0
str_pm_verb:        db "POWERMODE mode=", 0
str_pm_word:        db " word=", 0
str_pm_ok:          db " ok=", 0
str_pm_failed:      db " failed=", 0
str_pm_rb_ok:       db " rollback_ok=", 0
str_pm_rb_failed:   db " rollback_failed=", 0
str_pm_reverted:    db " reverted=", 0
str_pm_reason:      db " reason=", 0
str_pm_badarg:      db "POWERMODE err=badarg want=eff|bal|perf", 0
str_pm_owner_only:  db "POWERMODE err=owner_only", 0
