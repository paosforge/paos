;; MODULE svc/idle_probe
;; LAYER 5
;; EXPORTS idle_observation_snapshot, idle_probe_declare, cmd_verb_idleprobe, idle_probe_gate, idle_probe_port_check, idle_probe_run, cmd_verb_idledepth, idle_depth_row, idle_depth_select, idle_probe_cpu_ident
;; IMPORTS boot/serial, boot/smbios, core/lib/fmt, core/smp, bus/acpi, dev/power/ec_power, svc/command, svc/command_auth, svc/governor, svc/thermal
;; CAPS
;; OWNER saga:power
; ============================================================================
; svc/idle_probe.asm — RCQ-27 B2: read-only idle-depth discovery (IDLEPROBE).
;
; It reads facts and never acts on them: no MSR or port write, no MONITOR/MWAIT,
; no C-state port read. Every CPU keeps idling in plain hlt (`state=hlt`).
; Register sources: Intel SDM Vol 2A CPUID, Vol 4 model-specific registers;
; AMD PPR 17h/18h p.138 and 19h/11h p.64 (MSRC001_0073);
; ACPI 6.5 section 5.2.9 FADT and section 8.1.3 _CST.
;   - CPUID.01H (vendor, family, model, stepping, MONITOR, hypervisor), 05H
;     (MONITOR/MWAIT leaf, EAX..EDX), 06H.EAX[2] (ARAT); per AP: 05H:EDX and the
;     1AH core type (hybrid parts).
;   - MSRs only on a cited part and never under a hypervisor (idle_probe_gate):
;     Intel family 6 models 8Eh/9Eh/9Ah/C6h read MSR_PKG_CST_CONFIG_CONTROL (E2h);
;     AMD families 17h/19h read the C-state base address MSRC001_0073. Both also
;     read the microcode/patch level as latched in MSR 8Bh (never written here).
;     Each MSR is read on every online CPU (smp_msr_read_aps) and must be equal.
;   - AMD: conservative PaOS port policy: base != 0, base <=
;     FFF8h, the 8-port window disjoint from FADT SMI_CMD, PM1a/b EVT/CNT, PM2_CNT,
;     PM_TMR, GPE0/1, a System I/O RESET_REG (legacy and X_ forms), from PIT,
;     PS/2, EC 62h/66h, CMOS, POST 80h, COM1-4 and PCI CF8-CFF, and from the EC
;     data/command ports ec_power drives. No alignment is claimed.
; Owner read (srcreview P1): declared CMD_AUTH_CAP_MUTATE, destr 0, so the
; classifier requires the owner and the verb can never join a public/T0 set.
; One `[idle.depth.probe]` serial line on the first IDLEPROBE of a boot.
; Per-CPU idle HLT counts are in SMPSTAT CPU <n> halts=; IDLEPROBE halts= is their sum.
;
; RCQ-27 B2 L2 (Beelink, then Lenovo; root 13:31, srcreview 13:13 c1-c6, root 16:20):
; the per-target rows below are the opt-in, and every row ships DEFAULT OFF:
; each boot starts on plain hlt and says so once ([idle.depth]). The owner verb
; IDLEDEPTH [HLT|C1E|C6|C8|C10|C2|C3] picks this boot's state (RAM only: every
; boot starts on the target default, and only a reviewed per-target row ever
; makes a depth persistent, never this verb; root 19:52), and
; only on a matched row (SMBIOS Type-1 vendor + product exact, the row's CPUID
; vendor/family/model, no hypervisor) with no NVRAM opt-out (PaOSPowerPolicy =
; FWCT, read once by gov_init) and the hint's sub-state enumerated on this CPU.
; core/smp's smp_idle_enter re-checks every CPU for itself before any MWAIT.
; L1 (AMD rows, root 14:46 step iii): the row names the C-state IO base its
; offline _CST decompile implies and the offset per state (IDLEDEPTH C2/C3).
; Selecting one also needs this boot's IDLEPROBE to have read that base on
; every CPU with port=ok; smp_idle_enter re-reads the MSR on each CPU.
; ============================================================================

IDLE_V_OTHER        equ 0
IDLE_V_INTEL        equ 1
IDLE_V_AMD          equ 2
IDLE_MSR_INTEL_CST  equ 0xE2          ; MSR_PKG_CST_CONFIG_CONTROL (read only)
IDLE_MSR_AMD_CSTB   equ 0xC0010073    ; C-state base address (read only)
IDLE_MSR_UCODE      equ 0x8B          ; IA32_BIOS_SIGN_ID / AMD PATCH_LEVEL (read only)

IDLE_PORT_NA        equ 0             ; also the zero-init: unset is never OK
IDLE_PORT_ZERO      equ 1
IDLE_PORT_HIGH      equ 2
IDLE_PORT_NO_FADT   equ 3
IDLE_PORT_FADT      equ 4
IDLE_PORT_LEGACY    equ 5
IDLE_PORT_UNEQUAL   equ 6
IDLE_PORT_OK        equ 7

IDLE_FADT_LENS      equ 94            ; the PM block length bytes end at offset 93

; Passive snapshot ABI, 80 bytes owned by the caller. Only the serialized BSP
; command path calls this: policy/topology cannot change during this copy. APs
; publish their cached check once and increment aligned per-CPU qwords; each
; counter load is atomic, but two counters are sequential samples, NOT one
; simultaneous hardware measurement. No probe, clock, MSR, port or policy call.
; Producer arrays live for the entire boot; CPU hotplug would require revisiting
; this lifetime contract. Raw entry counts wrap modulo 2^64 and imply no duration.
IDO_STATE equ 0
IDO_HINT equ 4
IDO_REASON equ 8
IDO_ROW equ 12
IDO_PROBE equ 16                         ; 0 unprobed, 1 unsupported, 2 cached, -1 unknown
IDO_MSR equ 20
IDO_TOPO equ 24                          ; 0 unknown, 1 bounded boot topology
IDO_NCPU equ 28
IDO_CPU equ 32                           ; -1 summary, otherwise dense CPU
IDO_LIVE equ 36
IDO_MASK equ 40                          ; online BSP/AP bits (capacity is 32)
IDO_HALTS equ 48
IDO_DEEP equ 56
IDO_CHECK equ 64
IDO_SZ equ 80

; RDI points to IDO_SZ writable bytes, ESI dense CPU or -1 for summary.
; Clobbers caller-saved only. Unknown topology/CPU never dereferences a slot.
idle_observation_snapshot:
    mov  r8, rdi
    xor  eax, eax
    mov  ecx, IDO_SZ / 8
    rep  stosq
    mov  rdi, r8
    mov  [rdi + IDO_CPU], esi
    mov  eax, [rel idle_depth_state]
    mov  [rdi + IDO_STATE], eax
    mov  eax, [rel smp_idle_hint]
    mov  [rdi + IDO_HINT], eax
    mov  eax, [rel idle_depth_reason]
    mov  [rdi + IDO_REASON], eax
    cmp  qword [rel idle_depth_row_ptr], 0
    setne byte [rdi + IDO_ROW]
    movzx eax, byte [rel idle_logged]     ; first completed native probe, boot-local
    test eax, eax
    jz   .topology
    cmp  eax, 1
    jne  .probe_unknown
    mov  dword [rdi + IDO_PROBE], 1
    mov  eax, [rel idle_msr]
    mov  [rdi + IDO_MSR], eax
    test eax, eax
    jz   .topology
    mov  dword [rdi + IDO_PROBE], 2
    jmp  .topology
.probe_unknown:
    mov  dword [rdi + IDO_PROBE], -1
.topology:
    add  rdi, IDO_TOPO
    jmp  smp_idle_observation_snapshot       ; core owns array bounds and CPU custody

; ---------------------------------------------------------------------------
; idle_probe_declare — register IDLEPROBE (owner read, no argument).
; ---------------------------------------------------------------------------
idle_probe_declare:
    lea  rdi, [rel str_verb_idleprobe]
    lea  rsi, [rel cmd_verb_idleprobe]
    mov  rdx, CMD_AUTH_CAP_MUTATE           ; explicit owner cap: never public
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9                             ; read-only
    call command_register_verb
    lea  rdi, [rel str_verb_idledepth]      ; L2: owner only, boot-scoped, never persisted
    lea  rsi, [rel cmd_verb_idledepth]
    mov  rdx, CMD_AUTH_CAP_MUTATE
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    call power_stat_declare                 ; RC power T1: POWERSTAT (owner read)
    call idle_depth_row                     ; the boot state: hlt on every target (default off)
    mov  [rel idle_depth_reason], eax
    lea  rdi, [rel str_idle_depth_log]
    jmp  idle_depth_log

; ---------------------------------------------------------------------------
; idle_depth_row -> EAX = IDLE_R_* why this target may not leave hlt, or
;   IDLE_R_DEFAULT_OFF when a row matched (the boot state is still hlt), with
;   idle_depth_row_ptr = that row or 0. CPUID 0/1 and the SMBIOS snapshot only.
;   clobbers: caller-saved.
; ---------------------------------------------------------------------------
idle_depth_row:
    push rbx
    mov  qword [rel idle_depth_row_ptr], 0
    xor  eax, eax
    cpuid
    mov  r8d, IDLE_V_OTHER
    cmp  ebx, 0x756e6547                    ; "Genu" "ineI" "ntel"
    jne  .amd
    cmp  edx, 0x49656e69
    jne  .fms
    cmp  ecx, 0x6c65746e
    jne  .fms
    mov  r8d, IDLE_V_INTEL
    jmp  .fms
.amd:
    cmp  ebx, 0x68747541                    ; "Auth" "enti" "cAMD"
    jne  .fms
    cmp  edx, 0x69746e65
    jne  .fms
    cmp  ecx, 0x444d4163
    jne  .fms
    mov  r8d, IDLE_V_AMD
.fms:
    mov  eax, 1
    xor  ecx, ecx
    cpuid
    mov  r10d, IDLE_R_HV
    bt   ecx, 31
    jc   .out
    mov  r9d, eax
    shr  r9d, 8
    and  r9d, 0xF                           ; base family
    cmp  r9d, 0xF
    jne  .model
    mov  r10d, eax
    shr  r10d, 20
    and  r10d, 0xFF
    add  r9d, r10d                          ; + extended family (AMD 19h = 0Fh + 0Ah)
.model:
    mov  r11d, eax
    shr  r11d, 4
    and  r11d, 0xF
    shr  eax, 12
    and  eax, 0xF0
    or   r11d, eax                          ; model with its extended nibble
    mov  r10d, IDLE_R_NO_ROW
    cmp  dword [rel smbios_identity_state], SMB_ST_OK
    jne  .out
    lea  rbx, [rel idle_rows]
.row:
    lea  rax, [rel idle_rows_end]
    cmp  rbx, rax
    jae  .out
    cmp  r8d, [rbx + IDLE_ROW_VENDOR]
    jne  .next
    cmp  r9d, [rbx + IDLE_ROW_FAMILY]
    jne  .next
    cmp  r11d, [rbx + IDLE_ROW_MODEL]
    jne  .next
    lea  rdi, [rel smbios_sys_vendor]
    lea  rsi, [rbx + IDLE_ROW_SYS_VENDOR]
    mov  ecx, IDLE_ROW_PRODUCT - IDLE_ROW_SYS_VENDOR
    call idle_streq
    jne  .next
    lea  rdi, [rel smbios_sys_product]
    lea  rsi, [rbx + IDLE_ROW_PRODUCT]
    mov  ecx, IDLE_ROW_FAMILY - IDLE_ROW_PRODUCT
    call idle_streq
    jne  .next
    mov  [rel idle_depth_row_ptr], rbx
    mov  r10d, IDLE_R_FWCT
    cmp  byte [rel gov_policy_fw_seen], 1   ; NVRAM opt-out: it can only keep hlt
    je   .out
    mov  r10d, IDLE_R_DEFAULT_OFF
    jmp  .out
.next:
    add  rbx, IDLE_ROW_SIZE
    jmp  .row
.out:
    mov  eax, r10d
    pop  rbx
    ret

; idle_streq(RDI = NUL-terminated text, RSI = NUL-padded field, ECX = field size)
;   -> ZF=1 when the text equals the field exactly (no prefix match).
idle_streq:
    movzx eax, byte [rsi]
    cmp  al, [rdi]
    jne  .out                               ; ZF=0
    test eax, eax
    jz   .out                               ; both ended: ZF=1
    inc  rdi
    inc  rsi
    dec  ecx
    jnz  idle_streq
    cmp  byte [rdi], 0                      ; field full: the text must end here too
.out:
    ret

; ---------------------------------------------------------------------------
; idle_depth_select(EDI = IDLE_S_*) -> EAX = IDLE_R_OWNER when this boot's state
;   is now that one, else the IDLE_R_* refusal (the state is unchanged). HLT is
;   always allowed. A deep state needs the matched row (idle_depth_row), its
;   hint, and this CPU's own check (smp_idle_check_local) with the hint's
;   sub-state enumerated. clobbers: caller-saved.
; ---------------------------------------------------------------------------
idle_depth_select:
    push rbx
    push r12
    mov  r12d, edi
    test r12d, r12d
    jz   .set_hlt
    call idle_depth_row
    cmp  eax, IDLE_R_DEFAULT_OFF
    jne  .out
    mov  rbx, [rel idle_depth_row_ptr]
    mov  eax, IDLE_R_NOT_OFFERED
    mov  edx, [rbx + IDLE_ROW_HINTS + r12*4]
    cmp  edx, -1
    je   .out
    mov  ecx, [rbx + IDLE_ROW_IO_BASE]
    test ecx, ecx
    jz   .hint                              ; an MWAIT row
    mov  eax, IDLE_R_PROBE                  ; step (iii): this boot's IDLEPROBE proved the base
    cmp  dword [rel idle_msr], IDLE_MSR_AMD_CSTB
    jne  .out
    cmp  dword [rel idle_port], IDLE_PORT_OK  ; all CPUs equal, none missing, window clear
    jne  .out
    movzx r8d, word [rel idle_val]
    cmp  r8d, ecx
    jne  .out
    mov  [rel smp_idle_io_base], ecx        ; before the hint: smp_idle_enter reads the hint first
.hint:
    mov  ebx, edx                           ; the hint
    call smp_current_logical                ; -> EAX this CPU's dense id
    cmp  eax, MAXCORE
    jae  .cpu_refused
    mov  edi, eax
    lea  rcx, [rel smp_idle_cpu_state]
    cmp  byte [rcx + rdi], 0
    jne  .checked
    push rdi
    call smp_idle_check_local
    pop  rdi
.checked:
    lea  rcx, [rel smp_idle_cpu_state]
    cmp  dword [rel smp_idle_io_base], 0
    jne  .io_checked                        ; L1: its own check, no MWAIT sub-state
    cmp  byte [rcx + rdi], SMP_IDLE_CPU_OK
    jne  .cpu_refused
    lea  rcx, [rel smp_idle_cpu_edx5]
    mov  edx, [rcx + rdi*4]
    mov  ecx, ebx
    shr  ecx, 4
    and  ecx, 0x0F
    inc  ecx
    shl  ecx, 2
    shr  edx, cl                            ; ECX < 32: hints are 0x01..0x60
    and  edx, 0x0F
    mov  ecx, ebx
    and  ecx, 0x0F
    mov  eax, IDLE_R_SUBSTATE
    cmp  ecx, edx
    jae  .out
    jmp  .set
.io_checked:
    cmp  byte [rcx + rdi], SMP_IDLE_CPU_IO_OK  ; the IO-window check, never the MWAIT OK
    jne  .cpu_refused
.set:
    mov  [rel idle_depth_state], r12d
    mov  [rel smp_idle_hint], ebx
    mov  eax, IDLE_R_OWNER
    jmp  .out
.cpu_refused:
    mov  eax, IDLE_R_CPU
    jmp  .out
.set_hlt:
    mov  dword [rel smp_idle_hint], -1
    mov  dword [rel idle_depth_state], IDLE_S_HLT
    mov  eax, IDLE_R_OWNER
.out:
    pop  r12
    pop  rbx
    ret

; idle_depth_log(RDI = line prefix) — "[PAOS64] <prefix> state=<s> hint=<h>
;   reason=<r>" + its marker, from idle_depth_state / smp_idle_hint /
;   idle_depth_reason. clobbers: caller-saved.
idle_depth_log:
    push rdi
    lea  rdi, [rel str_idle_log_pre]
    call serial_string
    pop  rdi
    call serial_string
    mov  eax, [rel idle_depth_state]
    lea  rdi, [rel idle_state_names]
    lea  rdi, [rdi + rax*8]
    call serial_string
    lea  rdi, [rel str_idle_depth_hint]
    call serial_string
    mov  edi, [rel smp_idle_hint]
    call serial_hex64
    lea  rdi, [rel str_idle_depth_reason]
    call serial_string
    mov  eax, [rel idle_depth_reason]
    shl  eax, 4                             ; 16-byte slots
    lea  rdi, [rel idle_reason_names]
    add  rdi, rax
    call serial_string
    lea  rdi, [rel str_idle_depth_tail]
    jmp  serial_string

; ---------------------------------------------------------------------------
; idle_probe_gate(EDI=vendor IDLE_V_*, ESI=family, EDX=model, ECX=hypervisor)
;   -> EAX = the idle MSR this part may read, or 0 (read no MSR at all).
;   Only the parts the addendum cites; unknown means no MSR, as unknown means hlt.
; ---------------------------------------------------------------------------
idle_probe_gate:
    xor  eax, eax
    test ecx, ecx
    jnz  .out                               ; hypervisor: no MSR
    cmp  edi, IDLE_V_INTEL
    jne  .amd
    cmp  esi, 6
    jne  .out
    cmp  edx, 0x8E                          ; Kaby Lake R (Dell i7-8650U)
    je   .intel
    cmp  edx, 0x9E                          ; Coffee Lake-S (Lenovo i5-8500)
    je   .intel
    cmp  edx, 0x9A                          ; Alder Lake-U/P (Beelink i5-1235U)
    je   .intel
    cmp  edx, 0xC6                          ; Arrow Lake-S (MSI 265K)
    jne  .out
.intel:
    mov  eax, IDLE_MSR_INTEL_CST
    ret
.amd:
    cmp  edi, IDLE_V_AMD
    jne  .out
    cmp  esi, 0x17                          ; Zen+ (HP 3400G), PPR 17h/18h
    je   .amd_ok
    cmp  esi, 0x19                          ; Zen 4 (Reatan 8745HS), PPR 19h
    jne  .out
.amd_ok:
    mov  eax, IDLE_MSR_AMD_CSTB
.out:
    ret

; ---------------------------------------------------------------------------
; idle_probe_port_check(EDI=base port, RSI=FADT or 0, EDX=FADT length,
;   RCX=extra ranges or 0) -> EAX = IDLE_PORT_*. Pure: table data in, verdict out.
;   The 8-port window [base, base+8) must not touch any excluded range. Range
;   tables are (dw start, dw count) rows ending at count 0; a start of 0 is an
;   absent port and skipped. A FADT that is absent or too short to name its PM
;   blocks fails closed (NO_FADT): the check cannot be made.
; ---------------------------------------------------------------------------
idle_probe_port_check:
    push rbx
    push r12
    push r13
    push r14
    mov  r14, rcx
    mov  eax, IDLE_PORT_ZERO
    test edi, edi
    jz   .out
    mov  eax, IDLE_PORT_HIGH
    cmp  edi, 0xFFF8
    ja   .out
    mov  r12d, edi                          ; window start
    lea  r13d, [rdi + 8]                    ; window end (exclusive)
    lea  rbx, [rel idle_legacy_ports]
    call .ranges
    jc   .legacy_hit
    mov  rbx, r14
    test rbx, rbx
    jz   .fadt
    call .ranges
    jnc  .fadt
.legacy_hit:
    mov  eax, IDLE_PORT_LEGACY
    jmp  .out
.fadt:
    mov  eax, IDLE_PORT_NO_FADT
    test rsi, rsi
    jz   .out
    cmp  edx, IDLE_FADT_LENS
    jb   .out
    lea  rbx, [rel idle_fadt_ports]
.entry:
    movzx r8d, word [rbx]                   ; offset of the port field
    test r8d, r8d
    jz   .clean
    movzx r9d, byte [rbx + 3]               ; 0 = legacy dword, 1 = GAS
    lea  r10d, [r8d + 4]
    test r9d, r9d
    jz   .need
    lea  r10d, [r8d + 12]
.need:
    cmp  edx, r10d
    jb   .next                              ; an older FADT without this field
    test r9d, r9d
    jnz  .gas
    mov  eax, [rsi + r8]
    jmp  .len
.gas:
    cmp  byte [rsi + r8], 1                 ; System I/O only
    jne  .next
    mov  rax, [rsi + r8 + 4]
    cmp  rax, 0xFFFF
    ja   .next                              ; not a 16-bit port
.len:
    test eax, eax
    jz   .next
    movzx ecx, byte [rbx + 2]               ; offset of the length byte, 0 = one port
    test ecx, ecx
    jz   .one
    movzx ecx, byte [rsi + rcx]
    test ecx, ecx
    jnz  .have_len
.one:
    mov  ecx, 1                             ; a named port with no length: one port
.have_len:
    call .overlap
    jc   .fadt_hit
.next:
    add  rbx, 4
    jmp  .entry
.fadt_hit:
    mov  eax, IDLE_PORT_FADT
    jmp  .out
.clean:
    mov  eax, IDLE_PORT_OK
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
; RBX = range table -> CF=1 when a row touches the window. Clobbers EAX, ECX, RBX.
.ranges:
    movzx ecx, word [rbx + 2]
    test ecx, ecx
    jz   .ranges_clear
    movzx eax, word [rbx]
    add  rbx, 4
    test eax, eax
    jz   .ranges
    call .overlap
    jnc  .ranges
    ret
.ranges_clear:
    clc
    ret
; [EAX, EAX+ECX) against the window [R12D, R13D) -> CF=1 on overlap. EAX,ECX kept.
.overlap:
    cmp  eax, r13d
    jae  .apart
    lea  r11d, [rax + rcx]
    cmp  r12d, r11d
    jae  .apart
    stc
    ret
.apart:
    clc
    ret

; ---------------------------------------------------------------------------
; idle_probe_cpu_ident(RDI = 5 dwords: max_leaf, vendor IDLE_V_*, family, model,
;   stepping) -> ECX = CPUID.01H:ECX.  The one CPUID.00H/01H decoder (display
;   family/model with the extended fields); idle_probe_run and the RCQ-29 hardware
;   report (svc/hw_report) both use it.  clobbers RAX, RCX, RDX, R8-R10.
; ---------------------------------------------------------------------------
idle_probe_cpu_ident:
    push rbx
    xor  eax, eax
    xor  ecx, ecx
    cpuid
    mov  [rdi], eax
    mov  dword [rdi + 4], IDLE_V_OTHER
    cmp  ebx, 0x756e6547                    ; "Genu" "ineI" "ntel"
    jne  .not_intel
    cmp  ecx, 0x6c65746e
    jne  .vendor_done
    mov  dword [rdi + 4], IDLE_V_INTEL
    jmp  .vendor_done
.not_intel:
    cmp  ebx, 0x68747541                    ; "Auth" "enti" "cAMD"
    jne  .vendor_done
    cmp  ecx, 0x444d4163
    jne  .vendor_done
    mov  dword [rdi + 4], IDLE_V_AMD
.vendor_done:
    mov  eax, 1
    xor  ecx, ecx
    cpuid
    mov  r8d, eax
    and  r8d, 0xF
    mov  [rdi + 16], r8d
    mov  r8d, eax
    shr  r8d, 8
    and  r8d, 0xF                           ; base family
    mov  r9d, eax
    shr  r9d, 4
    and  r9d, 0xF                           ; base model
    cmp  r8d, 0xF
    jne  .ext_model
    mov  r10d, eax
    shr  r10d, 20
    and  r10d, 0xFF
    add  r8d, r10d                          ; + extended family
.ext_model:
    cmp  r8d, 6
    je   .add_model
    cmp  r8d, 0xF
    jb   .fms_done
.add_model:
    mov  r10d, eax
    shr  r10d, 16
    and  r10d, 0xF
    shl  r10d, 4
    or   r9d, r10d                          ; + extended model
.fms_done:
    mov  [rdi + 8], r8d
    mov  [rdi + 12], r9d
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; idle_probe_run — collect the facts on every CPU and stage the reply in
;   therm_out_buf; the first run of a boot also logs it. clobbers: caller-saved.
; ---------------------------------------------------------------------------
idle_probe_run:
    push rbx
    push r12
    push r13
    push r14
    push r15
    lea  rdi, [rel idle_facts]
    xor  eax, eax
    mov  ecx, idle_facts_end - idle_facts
    rep  stosb
    lea  rdi, [rel idle_max_leaf]           ; max_leaf, vendor, family, model, stepping
    call idle_probe_cpu_ident               ; ECX = CPUID.01H:ECX
    bt   ecx, 31
    setc byte [rel idle_hv]
    bt   ecx, 3
    setc byte [rel idle_mwait]
    cmp  dword [rel idle_max_leaf], 5
    jb   .leaf6
    mov  eax, 5
    xor  ecx, ecx
    cpuid
    mov  [rel idle_c5], eax
    mov  [rel idle_c5 + 4], ebx
    mov  [rel idle_c5 + 8], ecx
    mov  [rel idle_c5 + 12], edx
.leaf6:
    cmp  dword [rel idle_max_leaf], 6
    jb   .leaf1a
    mov  eax, 6
    xor  ecx, ecx
    cpuid
    bt   eax, 2
    setc byte [rel idle_arat]
.leaf1a:
    cmp  dword [rel idle_max_leaf], 0x1A
    jb   .gate
    mov  eax, 0x1A
    xor  ecx, ecx
    cpuid
    shr  eax, 24
    mov  [rel idle_bsp_type], al
.gate:
    mov  edi, [rel idle_vendor]
    mov  esi, [rel idle_family]
    mov  edx, [rel idle_model]
    movzx ecx, byte [rel idle_hv]
    call idle_probe_gate
    mov  [rel idle_msr], eax
    test eax, eax
    jz   .aps
    cmp  dword [rel idle_vendor], IDLE_V_INTEL
    jne  .ucode_amd
    mov  eax, 1
    xor  ecx, ecx
    cpuid                                   ; latch the signature (no 8Bh write)
    mov  ecx, IDLE_MSR_UCODE
    rdmsr
    mov  [rel idle_ucode], edx
    jmp  .bsp_msr
.ucode_amd:
    mov  ecx, IDLE_MSR_UCODE
    rdmsr
    mov  [rel idle_ucode], eax
.bsp_msr:
    mov  ecx, [rel idle_msr]
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  [rel idle_val], rax
.aps:
    mov  edi, [rel idle_msr]
    call smp_msr_read_aps                   ; -> EAX answered, EDX missing (APs)
    mov  [rel idle_missing], edx
    mov  r12d, eax                          ; answered APs
    mov  dword [rel idle_cpus], 1           ; the BSP
    mov  dword [rel idle_equal], 1
    mov  dword [rel idle_c5eq], 1
    movzx eax, byte [rel idle_bsp_type]
    call .count_type
    mov  ebx, 1
.ap:
    cmp  ebx, 32
    jae  .summary
    bt   r12d, ebx
    jnc  .ap_next
    inc  dword [rel idle_cpus]
    lea  rax, [rel smp_msr_req_rd_val]
    mov  rax, [rax + rbx*8]
    cmp  rax, [rel idle_val]
    jne  .ap_c5
    inc  dword [rel idle_equal]
.ap_c5:
    lea  rax, [rel smp_msr_req_rd_c5]
    mov  eax, [rax + rbx*4]
    cmp  eax, [rel idle_c5 + 12]
    jne  .ap_type
    inc  dword [rel idle_c5eq]
.ap_type:
    lea  rax, [rel smp_msr_req_rd_type]
    movzx eax, byte [rax + rbx]
    call .count_type
.ap_next:
    inc  ebx
    jmp  .ap
.summary:
    mov  dword [rel idle_port], IDLE_PORT_NA
    cmp  dword [rel idle_msr], IDLE_MSR_AMD_CSTB
    jne  .stage
    mov  dword [rel idle_port], IDLE_PORT_UNEQUAL
    mov  eax, [rel idle_equal]
    cmp  eax, [rel idle_cpus]
    jne  .stage
    cmp  dword [rel idle_missing], 0
    jne  .stage                             ; an AP that never answered is not proven equal
    movzx eax, word [rel ecp_data_port]     ; the EC ports ec_power drives (0 = none)
    mov  [rel idle_ec_ports], ax
    movzx eax, word [rel ecp_cmd_port]
    mov  [rel idle_ec_ports + 4], ax
    mov  edi, 'FACP'
    call acpi_find_table                    ; -> RAX FADT or 0
    mov  rsi, rax
    xor  edx, edx
    test rax, rax
    jz   .check
    mov  edx, [rax + 4]                     ; SDT length
.check:
    movzx edi, word [rel idle_val]          ; base = bits 15:0
    lea  rcx, [rel idle_ec_ports]
    call idle_probe_port_check
    mov  [rel idle_port], eax
.stage:
    call idle_probe_format
    cmp  byte [rel idle_logged], 1
    je   .done
    mov  byte [rel idle_logged], 1
    lea  rdi, [rel str_idle_log_pre]
    call serial_string
    lea  rdi, [rel therm_out_buf]
    call serial_string
    lea  rdi, [rel str_idle_log_tail]
    call serial_string
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
; EAX = CPUID.1AH core type: 40h Core (P), 20h Atom (E), else neither.
.count_type:
    cmp  eax, 0x40
    jne  .not_p
    inc  dword [rel idle_ptype]
    ret
.not_p:
    cmp  eax, 0x20
    jne  .not_e
    inc  dword [rel idle_etype]
.not_e:
    ret

; idle_probe_format — the facts as one fixed-shape line in therm_out_buf (< 256).
; It ends with halts= (RCQ-12): smp_idle_hlt_count summed over every CPU, a live
; count, so the line is no longer the same on every read. Worst case 251 bytes.
idle_probe_format:
    push rbx
    call therm_out_reset
    lea  rdi, [rel str_idle_v]
    call therm_out_str
    mov  eax, [rel idle_vendor]
    lea  rdi, [rel str_idle_other]
    cmp  eax, IDLE_V_INTEL
    jne  .v_amd
    lea  rdi, [rel str_idle_intel]
.v_amd:
    cmp  eax, IDLE_V_AMD
    jne  .v_out
    lea  rdi, [rel str_idle_amd]
.v_out:
    call therm_out_str
    lea  rdi, [rel str_idle_f]
    mov  esi, [rel idle_family]
    call .hex
    lea  rdi, [rel str_idle_m]
    mov  esi, [rel idle_model]
    call .hex
    lea  rdi, [rel str_idle_s]
    mov  esi, [rel idle_stepping]
    call .dec
    lea  rdi, [rel str_idle_ucode]
    mov  esi, [rel idle_ucode]
    call .hex
    lea  rdi, [rel str_idle_hv]
    movzx esi, byte [rel idle_hv]
    call .dec
    lea  rdi, [rel str_idle_mwait]
    movzx esi, byte [rel idle_mwait]
    call .dec
    lea  rdi, [rel str_idle_c5]
    mov  esi, [rel idle_c5]
    call .hex
    lea  rdi, [rel str_idle_dot]
    mov  esi, [rel idle_c5 + 4]
    call .hex
    lea  rdi, [rel str_idle_dot]
    mov  esi, [rel idle_c5 + 8]
    call .hex
    lea  rdi, [rel str_idle_dot]
    mov  esi, [rel idle_c5 + 12]
    call .hex
    lea  rdi, [rel str_idle_arat]
    movzx esi, byte [rel idle_arat]
    call .dec
    lea  rdi, [rel str_idle_msr]
    mov  esi, [rel idle_msr]
    call .hex
    lea  rdi, [rel str_idle_val]
    mov  rsi, [rel idle_val]
    call .hex
    lea  rdi, [rel str_idle_cpus]
    mov  esi, [rel idle_cpus]
    call .dec
    lea  rdi, [rel str_idle_eq]
    mov  esi, [rel idle_equal]
    call .dec
    lea  rdi, [rel str_idle_miss]
    mov  esi, [rel idle_missing]
    call .hex
    lea  rdi, [rel str_idle_port]
    call therm_out_str
    mov  eax, [rel idle_port]
    lea  rdi, [rel idle_port_names]
    lea  rdi, [rdi + rax*8]
    call therm_out_str
    lea  rdi, [rel str_idle_p]
    mov  esi, [rel idle_ptype]
    call .dec
    lea  rdi, [rel str_idle_e]
    mov  esi, [rel idle_etype]
    call .dec
    lea  rdi, [rel str_idle_c5eq]
    mov  esi, [rel idle_c5eq]
    call .dec
    lea  rdi, [rel str_idle_state]
    call therm_out_str
    mov  eax, [rel idle_depth_state]        ; L2: this boot's real state (hlt by default)
    lea  rdi, [rel idle_state_names]
    lea  rdi, [rdi + rax*8]
    call therm_out_str
    lea  rcx, [rel smp_idle_hlt_count]      ; RCQ-12: idle HLT entries, summed over every CPU
    xor  esi, esi
    xor  ebx, ebx
.halts:
    add  rsi, [rcx + rbx*8]
    inc  ebx
    cmp  ebx, MAXCORE
    jb   .halts
    lea  rdi, [rel str_idle_halts]
    call .dec
    pop  rbx
    ret
; RDI = label, RSI = value
.hex:
    push rsi
    call therm_out_str
    pop  rdi
    jmp  therm_out_hex
.dec:
    push rsi
    call therm_out_str
    pop  rdi
    jmp  therm_out_dec

; --- VERB: IDLEPROBE — read-only idle-depth facts (see the header). ---
cmd_verb_idleprobe:
    call cmd_handler_prologue
    push rdi
    push rsi
    call idle_probe_run
    mov  byte [rel therm_out_ready], 1
    pop  rsi                                ; restore resp/req AFTER the clobbering staging
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; --- VERB: IDLEDEPTH [HLT|C1E|C6|C8|C10|C2|C3] — this boot's idle state (L1/L2, owner). ---
;   No argument: report, open to any caller the dispatcher admits (the AI
;   operator may read the depth). A name: OWNER-only (root 19:52: an idle depth
;   is a hardware-behaviour change that can hang a box): every other principal,
;   PRIN_SYSTEM included, gets AUTHDENY and the report plus " applied=0
;   err=owner_only", and nothing is parsed or changed. The owner's name selects
;   it (idle_depth_select); a refusal keeps the state and says why.
;   Reply "IDLEDEPTH state=<s> hint=<h> reason=<r> row=<0|1> ok=<n> no=<n>
;   deep=<n> irqref=<n> io=<base>" (ok/no: CPUs whose own check passed/failed
;   so far; deep: MWAIT or IO entries on all CPUs; io: the L1 C-state IO base in
;   use, 0 = none).
cmd_verb_idledepth:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov  r12, rsi
    mov  r13, [rdi + REQ_ARG]
    test r13, r13
    jz   .report
    cmp  byte [r13], 0
    je   .report
    cmp  qword [rdi + REQ_SOURCE], CMD_SOURCE_CONSOLE
    je   .owner                             ; the dispatcher already requires the console owner
    call command_auth_owner_request         ; 1 = own AUTH1 owner ticket, 2 = owner SSH key
    test eax, eax
    jz   .not_owner
.owner:
    xor  ebx, ebx                           ; IDLE_S_* candidate
.name:
    cmp  ebx, IDLE_S_COUNT
    jae  .badarg
    lea  rsi, [rel idle_state_args]
    lea  rsi, [rsi + rbx*8]
    mov  rdi, r13
    mov  ecx, 8
    call idle_streq
    je   .select
    inc  ebx
    jmp  .name
.select:
    mov  edi, ebx
    call idle_depth_select
    mov  [rel idle_depth_reason], eax
    cmp  eax, IDLE_R_OWNER
    jne  .report
    lea  rdi, [rel str_idle_depth_set]
    call idle_depth_log
    jmp  .report
.badarg:
    mov  qword [r12 + RSP_CODE], CMDE_BADARG
    jmp  .out
.not_owner:
    call idle_depth_format
    lea  rdi, [rel str_idle_depth_owner_only]
    call therm_out_str
    mov  byte [rel therm_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_AUTHDENY
    mov  eax, [rel idle_depth_state]
    mov  [r12 + RSP_VAL], rax
    jmp  .out
.report:
    call idle_depth_format
    mov  byte [rel therm_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_OK
    mov  eax, [rel idle_depth_state]
    mov  [r12 + RSP_VAL], rax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; idle_depth_format — the IDLEDEPTH reply in therm_out_buf (< 160 bytes).
idle_depth_format:
    push rbx
    push r12
    push r13
    push r14
    call therm_out_reset
    lea  rdi, [rel str_idle_depth_verb]
    call therm_out_str
    mov  eax, [rel idle_depth_state]
    lea  rdi, [rel idle_state_names]
    lea  rdi, [rdi + rax*8]
    call therm_out_str
    lea  rdi, [rel str_idle_depth_hint]
    call therm_out_str
    mov  edi, [rel smp_idle_hint]
    call therm_out_hex
    lea  rdi, [rel str_idle_depth_reason]
    call therm_out_str
    mov  eax, [rel idle_depth_reason]
    shl  eax, 4                             ; 16-byte slots
    lea  rdi, [rel idle_reason_names]
    add  rdi, rax
    call therm_out_str
    lea  rdi, [rel str_idle_depth_row]
    call therm_out_str
    xor  edi, edi
    cmp  qword [rel idle_depth_row_ptr], 0
    setne dil
    call therm_out_dec
    xor  r12d, r12d                         ; ok
    xor  r13d, r13d                         ; no
    xor  r14d, r14d                         ; deep (sum)
    xor  ebx, ebx
.cpu:
    cmp  ebx, MAXCORE
    jae  .counted
    lea  rax, [rel smp_idle_cpu_state]
    movzx eax, byte [rax + rbx]
    cmp  eax, SMP_IDLE_CPU_OK
    je   .cpu_ok
    cmp  eax, SMP_IDLE_CPU_IO_OK
    jne  .not_ok
.cpu_ok:
    inc  r12d
.not_ok:
    cmp  eax, SMP_IDLE_CPU_NO
    jne  .deep
    inc  r13d
.deep:
    lea  rax, [rel smp_idle_mwait_count]
    add  r14, [rax + rbx*8]
    inc  ebx
    jmp  .cpu
.counted:
    lea  rdi, [rel str_idle_depth_ok]
    call therm_out_str
    mov  edi, r12d
    call therm_out_dec
    lea  rdi, [rel str_idle_depth_no]
    call therm_out_str
    mov  edi, r13d
    call therm_out_dec
    lea  rdi, [rel str_idle_depth_deep]
    call therm_out_str
    mov  rdi, r14
    call therm_out_dec
    lea  rdi, [rel str_idle_depth_irq]
    call therm_out_str
    mov  rdi, [rel smp_idle_irq_refusals]
    call therm_out_dec
    lea  rdi, [rel str_idle_depth_io]
    call therm_out_str
    mov  edi, [rel smp_idle_io_base]
    call therm_out_hex
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; --- data ---------------------------------------------------------------------
IDLE_S_HLT          equ 0               ; idle_depth_state / IDLEDEPTH argument index
IDLE_S_COUNT        equ 7               ; HLT C1E C6 C8 C10 (MWAIT), C2 C3 (AMD IO)
IDLE_R_DEFAULT_OFF  equ 0               ; a row matched; the boot state stays hlt
IDLE_R_NO_ROW       equ 1
IDLE_R_FWCT         equ 2
IDLE_R_HV           equ 3
IDLE_R_NOT_OFFERED  equ 4
IDLE_R_CPU          equ 5
IDLE_R_SUBSTATE     equ 6
IDLE_R_OWNER        equ 7
IDLE_R_PROBE        equ 8               ; L1: no IDLEPROBE this boot proving the row's base
; Per-target rows: firmware LPIT/_CST and CPUID encodings are cited at each row.
; The Intel specification-update errata KBL152/CFL144 apply as described below.
IDLE_ROW_VENDOR     equ 0               ; dd IDLE_V_*
IDLE_ROW_FAMILY     equ 4 + 16 + 24     ; dd (after the two SMBIOS fields)
IDLE_ROW_SYS_VENDOR equ 4               ; 16 bytes, NUL-padded, exact
IDLE_ROW_PRODUCT    equ 4 + 16          ; 24 bytes, NUL-padded, exact
IDLE_ROW_MODEL      equ IDLE_ROW_FAMILY + 4
IDLE_ROW_HINTS      equ IDLE_ROW_MODEL + 4 ; IDLE_S_COUNT dd: MWAIT hints / IO offsets, -1 = not offered
IDLE_ROW_IO_BASE    equ IDLE_ROW_HINTS + IDLE_S_COUNT * 4 ; dd AMD C-state IO base, 0 = MWAIT row
IDLE_ROW_SIZE       equ IDLE_ROW_IO_BASE + 4
align 4
idle_rows:
    ; Beelink EQi12, i5-1235U (06_9AH, 12th Gen Core; rc-target4 17:33 SMBIOS read,
    ; RAW_SSH_OUTPUT.txt 3601e3bf). Hints are MWAIT encodings (SDM Vol 2B MWAIT:
    ; EAX[7:4] C-state - 1, [3:0] sub-state), each gated per CPU on CPUID 05H:EDX;
    ; 0x60, the deepest, is this firmware's own LPIT FFH entry trigger (rc-target4
    ; 20261008-0120 capture, LPIT.aml 2704c471). The names are PaOS labels.
    dd IDLE_V_INTEL
    db "AZW"
    times 16 - 3 db 0
    db "EQ"
    times 24 - 2 db 0
    dd 6, 0x9A
    dd -1, 0x01, 0x20, 0x40, 0x60           ; HLT, C1E, C6, C8, C10
    dd -1, -1, 0                            ; C2, C3: no IO states; IO base none
    ; Lenovo M720s (serial redacted), i5-8500 (06_9EH, 8th Gen Core; PaOS's own boot line
    ; "P0 smbios: ... system=LENOVO / 10SUS1UL00", Lenovo metal serial). The same
    ; MWAIT encodings, gated per CPU on CPUID 05H:EDX (no Lenovo ACPI capture; the
    ; Dell KBL-R LPIT also triggers FFH 0x60, LPIT.aml 65d70d03). CFL144
    ; (KBL152): no interrupt handler ever runs with IF set, so no fixed
    ; interrupt can be dispatched under one in service.
    dd IDLE_V_INTEL
    db "LENOVO"
    times 16 - 6 db 0
    db "10SUS1UL00"
    times 24 - 10 db 0
    dd 6, 0x9E
    dd -1, 0x01, 0x20, 0x40, 0x60           ; HLT, C1E, C6, C8, C10
    dd -1, -1, 0                            ; C2, C3: no IO states; IO base none
    ; Reatan A8, Ryzen 7 8745HS (Hawk Point 19h/75h). L1 (root 14:46/16:20): the
    ; offline _CST decompile (SSD2 21da5df9, rc-amd 16:13) names C2 = SystemIO
    ; 0x414 = base 0x413 + 1. MWAIT reaches C1 only (05H:EDX 0x11), so no MWAIT
    ; state. C3 (0x415) is not offered. SMBIOS from rc-target2's raw Type-1 read
    ; (19:06, SMBiosData.bin 50043c16): "reatan" / "A8", no padding.
    dd IDLE_V_AMD
    db "reatan"
    times 16 - 6 db 0
    db "A8"
    times 24 - 2 db 0
    dd 0x19, 0x75
    dd -1, -1, -1, -1, -1                   ; HLT, C1E, C6, C8, C10: none by MWAIT
    dd 1, -1                                ; C2 = IO base + 1, C3 not offered
    dd 0x413                                ; the IO base every CPU must read
idle_rows_end:
idle_depth_state:   dd IDLE_S_HLT
idle_depth_reason:  dd IDLE_R_NO_ROW
align 8
idle_depth_row_ptr: dq 0
; IDLEDEPTH arguments and state names, 8-byte slots indexed by IDLE_S_*
idle_state_args:
    db "HLT", 0, 0, 0, 0, 0
    db "C1E", 0, 0, 0, 0, 0
    db "C6", 0, 0, 0, 0, 0, 0
    db "C8", 0, 0, 0, 0, 0, 0
    db "C10", 0, 0, 0, 0, 0
    db "C2", 0, 0, 0, 0, 0, 0
    db "C3", 0, 0, 0, 0, 0, 0
idle_state_names:
    db "hlt", 0, 0, 0, 0, 0
    db "c1e", 0, 0, 0, 0, 0
    db "c6", 0, 0, 0, 0, 0, 0
    db "c8", 0, 0, 0, 0, 0, 0
    db "c10", 0, 0, 0, 0, 0
    db "c2", 0, 0, 0, 0, 0, 0
    db "c3", 0, 0, 0, 0, 0, 0
; refusal/reason names, 16-byte slots indexed by IDLE_R_*
idle_reason_names:
    db "default_off", 0, 0, 0, 0, 0
    db "no_row", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    db "fwct", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    db "hv", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    db "not_offered", 0, 0, 0, 0, 0
    db "cpu", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    db "substate", 0, 0, 0, 0, 0, 0, 0, 0
    db "owner", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    db "probe", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
str_verb_idledepth: db "IDLEDEPTH", 0
str_idle_depth_verb: db "IDLEDEPTH state=", 0
str_idle_depth_log: db "idle depth: boot state=", 0
str_idle_depth_set: db "idle depth: owner set state=", 0
str_idle_depth_owner_only: db " applied=0 err=owner_only", 0
str_idle_depth_hint: db " hint=", 0
str_idle_depth_reason: db " reason=", 0
str_idle_depth_io:  db " io=", 0
str_idle_depth_row: db " row=", 0
str_idle_depth_ok:  db " ok=", 0
str_idle_depth_no:  db " no=", 0
str_idle_depth_deep: db " deep=", 0
str_idle_depth_irq: db " irqref=", 0
str_idle_depth_tail: db " [idle.depth]", 13, 10, 0
align 8
idle_facts:
idle_val:           dq 0            ; BSP value of the idle MSR (0 when none read)
idle_max_leaf:      dd 0
idle_vendor:        dd 0            ; IDLE_V_*
idle_family:        dd 0
idle_model:         dd 0
idle_stepping:      dd 0
idle_ucode:         dd 0            ; MSR 8Bh as latched (Intel EDX, AMD EAX)
idle_c5:            times 4 dd 0    ; CPUID.05H EAX, EBX, ECX, EDX (BSP)
idle_msr:           dd 0            ; the gated MSR, 0 = none
idle_cpus:          dd 0            ; BSP + answered APs
idle_equal:         dd 0            ; CPUs whose MSR value equals the BSP's
idle_c5eq:          dd 0            ; CPUs whose CPUID.05H:EDX equals the BSP's
idle_missing:       dd 0            ; APs that never answered (dense mask)
idle_port:          dd IDLE_PORT_NA ; IDLE_PORT_* (cleared per run to NA)
idle_ptype:         dd 0            ; CPUID.1AH core type 40h (P) count
idle_etype:         dd 0            ; CPUID.1AH core type 20h (E) count
idle_hv:            db 0            ; CPUID.01H:ECX[31]
idle_mwait:         db 0            ; CPUID.01H:ECX[3] MONITOR/MWAIT
idle_arat:          db 0            ; CPUID.06H:EAX[2]
idle_bsp_type:      db 0
idle_facts_end:
idle_logged:        db 0            ; the serial line is logged once per boot
align 4
; Conservative PaOS denylist: start, count. These ranges are excluded even
; when a device is absent; this is policy, not a discovered port-ownership map.
; PaOS consumers: boot/serial COM1, bus/pci CF8/CFC, dev/input/ps2 60h/64h,
; dev/power/ec_power descriptor EC ports. Other historical ranges stay denied.
idle_legacy_ports:
    dw 0x40, 4                      ; PIT
    dw 0x60, 5                      ; PS/2 (60h-64h)
    dw 0x62, 1                      ; EC data (ACPI EC default)
    dw 0x66, 1                      ; EC command/status
    dw 0x70, 4                      ; CMOS / RTC, both banks
    dw 0x80, 1                      ; POST
    dw 0x3F8, 8                     ; COM1
    dw 0x2F8, 8                     ; COM2
    dw 0x3E8, 8                     ; COM3
    dw 0x2E8, 8                     ; COM4
    dw 0xCF8, 8                     ; PCI CF8-CFF (incl. reset CF9)
    dw 0, 0
; ACPI 6.5 section 5.2.9 Table 5.9: FADT port fields and block lengths.
; Field offset, length-byte offset (0 = one port), 0, kind (0 dword, 1 GAS)
idle_fadt_ports:
    dw 48
    db 0, 0                         ; SMI_CMD
    dw 56
    db 88, 0                        ; PM1a_EVT_BLK
    dw 60
    db 88, 0                        ; PM1b_EVT_BLK
    dw 64
    db 89, 0                        ; PM1a_CNT_BLK
    dw 68
    db 89, 0                        ; PM1b_CNT_BLK
    dw 72
    db 90, 0                        ; PM2_CNT_BLK
    dw 76
    db 91, 0                        ; PM_TMR_BLK
    dw 80
    db 92, 0                        ; GPE0_BLK
    dw 84
    db 93, 0                        ; GPE1_BLK
    dw 116
    db 0, 1                         ; RESET_REG (GAS)
    dw 148
    db 88, 1                        ; X_PM1a_EVT_BLK
    dw 160
    db 88, 1                        ; X_PM1b_EVT_BLK
    dw 172
    db 89, 1                        ; X_PM1a_CNT_BLK
    dw 184
    db 89, 1                        ; X_PM1b_CNT_BLK
    dw 196
    db 90, 1                        ; X_PM2_CNT_BLK
    dw 208
    db 91, 1                        ; X_PM_TMR_BLK
    dw 220
    db 92, 1                        ; X_GPE0_BLK
    dw 232
    db 93, 1                        ; X_GPE1_BLK
    dw 0
    db 0, 0
idle_ec_ports:                      ; filled per run from ec_power (start 0 = absent)
    dw 0, 1
    dw 0, 1
    dw 0, 0
; port verdict names, 8-byte slots indexed by IDLE_PORT_* (no absolute pointers)
idle_port_names:
    db "na", 0, 0, 0, 0, 0, 0
    db "zero", 0, 0, 0, 0
    db "high", 0, 0, 0, 0
    db "no_fadt", 0
    db "fadt", 0, 0, 0, 0
    db "legacy", 0, 0
    db "unequal", 0
    db "ok", 0, 0, 0, 0, 0, 0
str_verb_idleprobe: db "IDLEPROBE", 0
str_idle_v:         db "idle v=", 0
str_idle_intel:     db "intel", 0
str_idle_amd:       db "amd", 0
str_idle_other:     db "other", 0
str_idle_f:         db " f=", 0
str_idle_m:         db " m=", 0
str_idle_s:         db " s=", 0
str_idle_ucode:     db " ucode=", 0
str_idle_hv:        db " hv=", 0
str_idle_mwait:     db " mwait=", 0
str_idle_c5:        db " c5=", 0
str_idle_dot:       db ".", 0
str_idle_arat:      db " arat=", 0
str_idle_msr:       db " msr=", 0
str_idle_val:       db " val=", 0
str_idle_cpus:      db " cpus=", 0
str_idle_eq:        db " eq=", 0
str_idle_miss:      db " miss=", 0
str_idle_port:      db " port=", 0
str_idle_p:         db " p=", 0
str_idle_e:         db " e=", 0
str_idle_c5eq:      db " c5eq=", 0
str_idle_state:     db " state=", 0
str_idle_halts:     db " halts=", 0
str_idle_log_pre:   db "[PAOS64] ", 0
str_idle_log_tail:  db " [idle.depth.probe]", 13, 10, 0
