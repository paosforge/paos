;; MODULE svc/thermal
;; LAYER 5
;; EXPORTS thermal_init, thermal_selftest, thermal_declare, thermal_read_live, thermal_pkg_read, cmd_verb_therm, cmd_verb_therminduce, cmd_verb_throttlelog, cmd_verb_pstate, therm_out_reset, therm_out_str, therm_out_dec, therm_out_hex, therm_out_buf, therm_out_ready
;; IMPORTS boot/serial, core/lib/fmt, core/diag, svc/command, svc/governor, bus/pci
;; CAPS
;; OWNER saga:power
; ============================================================================
; svc/thermal.asm — valid live temperature, software notice custody and P-state.
; A software threshold notice is not proof of hardware throttling. Live notices
; require a supported, available reading >= the temporary notice threshold.
; Their raw source, temperature, status and TSC are captured together, independently
; of subsequent THERM reads. Intel hardware logbit is never synthesized; AMD Tctl
; supplies temperature/raw SMN only, not an Intel status/log bit. Counts saturate.
; Native dispatch and typed observation use existing BSP command serialization;
; event snapshots change only when another valid notice is admitted. No MSR write
; or hardware thermal-protection change is involved. The boot marker KAT is
; explicitly synthetic and never publishes a live event or diag record.
; ============================================================================

THERM_MSR_STATUS      equ 0x19C     ; IA32_THERM_STATUS [0]=thermal [1]=thermal-log [2]=PROCHOT [3]=PROCHOT-log [22:16]=readout [31]=reading-valid
THERM_MSR_TJTARGET    equ 0x1A2     ; IA32_TEMPERATURE_TARGET [23:16]=Tj_max (deg C)
THERM_NOTICE_DEFAULT  equ 90        ; default software throttle-notice threshold (deg C)
THERM_NOTICE_INDUCED  equ 1         ; induced threshold: any live temp >= 1 C fires a notice
THERM_KAT_TEMP        equ 55        ; synthetic temp for the QEMU read-logic KAT (no DTS)
THERM_KAT_RATIO       equ 100       ; synthetic P-state ratio for the QEMU KAT (no APERF)
; PSTATE is a measured dword percentage, never a wrapped/synthetic live value.
POWER_UNSUPPORTED    equ 0
POWER_VALID          equ 1
POWER_INVALID        equ 2
THERM_PS_ITERS        equ 2000000   ; bounded load window for the live APERF/MPERF sample
THERM_DIAG_KIND       equ 4         ; diag-ring record kind for a throttle event (1/2/3 = enter/exit/fault)
; RCQ-27 POWER-03: the temperature source (THERM reports it as source=)
THERM_SRC_NONE        equ 0
THERM_SRC_DTS         equ 1         ; Intel digital thermal sensor (0x19C / 0x1A2)
THERM_SRC_AMD_TCTL    equ 2         ; AMD Tctl, SMN 0x00059800 through the root complex
THERM_AMD_SMN_INDEX   equ 0x60      ; D0F0 SMN index (AMD root complex only)
THERM_AMD_SMN_DATA    equ 0x64
THERM_AMD_TCTL_SMN    equ 0x00059800
THERM_AMD_ROOT_17H_M10 equ 0x15D01022 ; fam 17h M10h-2Fh root complex (Raven/Picasso: the HP's Ryzen 5 PRO 3400G)
THERM_AMD_ROOT_19H_M70 equ 0x14E81022 ; fam 19h M70h-7Fh root complex (Phoenix/Hawk Point: the Reatan's Ryzen 7 8745HS)
THERM_AMD_MAX_C       equ 125

; ---------------------------------------------------------------------------
; thermal_init — detect the DTS, cache Tj_max, arm the monitor. Emits
;   thermal.monitor.armed (present-or-degraded, ALWAYS). clobbers: caller-saved.
; ---------------------------------------------------------------------------
thermal_init:
    push rbx
    ; Every initialization owns its calibration, including unsupported/repeat init.
    mov  dword [rel therm_notice_threshold], THERM_NOTICE_DEFAULT
    mov  dword [rel therm_tjmax], 0          ; unknown; never a software reference
    mov  byte [rel therm_calibrated], 0
    mov  dword [rel therm_last_temp], -1
    mov  dword [rel therm_last_status], 0
    mov  byte [rel therm_dts_present], 0
    mov  byte [rel therm_source], THERM_SRC_NONE
    mov  byte [rel therm_degraded], 1
    xor  eax, eax
    cpuid
    cmp  eax, 6
    jb   .no_dts
    cmp  ebx, 0x756e6547                   ; GenuineIntel; leaf6 alone is not a vendor
    jne  .no_dts
    cmp  edx, 0x49656e69
    jne  .no_dts
    cmp  ecx, 0x6c65746e
    jne  .no_dts
    mov  eax, 6
    xor  ecx, ecx
    cpuid
    test eax, 1
    jz   .no_dts
    mov  byte [rel therm_dts_present], 1
    mov  byte [rel therm_source], THERM_SRC_DTS
    ; DTS admits the architectural raw status, not model-specific 0x1A2.
    ; Intel SDM rev093 vol4 section2.1 requires DisplayFamily/DisplayModel.
    ; The exact models below are documented by sections2.4,2.8-2.17 (Atom
    ; Silvermont+, Nehalem through the listed Core/Xeon successors). Unlisted
    ; models retain raw status, but cannot supply an absolute Celsius value.
    mov  eax, 1
    cpuid
    mov  edx, eax
    shr  edx, 8
    and  edx, 0xF
    cmp  edx, 6
    jne  .uncalibrated
    mov  edx, eax
    shr  edx, 12
    and  edx, 0xF0
    shr  eax, 4
    and  eax, 0xF
    or   eax, edx                         ; family6 DisplayModel
    cmp  eax, 0x1A
    je   .target_supported
    cmp  eax, 0x1E
    je   .target_supported
    cmp  eax, 0x1F
    je   .target_supported
    cmp  eax, 0x25
    je   .target_supported
    cmp  eax, 0x2C
    je   .target_supported
    cmp  eax, 0x2F
    je   .target_supported
    cmp  eax, 0x2A
    je   .target_supported
    cmp  eax, 0x2D
    je   .target_supported
    cmp  eax, 0x3A
    je   .target_supported
    cmp  eax, 0x3E
    je   .target_supported
    cmp  eax, 0x3C
    je   .target_supported
    cmp  eax, 0x45
    je   .target_supported
    cmp  eax, 0x46
    je   .target_supported
    cmp  eax, 0x3F
    je   .target_supported
    cmp  eax, 0x3D
    je   .target_supported
    cmp  eax, 0x47
    je   .target_supported
    cmp  eax, 0x4F
    je   .target_supported
    cmp  eax, 0x56
    je   .target_supported
    cmp  eax, 0x4E
    je   .target_supported
    cmp  eax, 0x5E
    je   .target_supported
    cmp  eax, 0x55
    je   .target_supported
    cmp  eax, 0x8E
    je   .target_supported
    cmp  eax, 0x9E
    je   .target_supported
    cmp  eax, 0x66
    je   .target_supported
    cmp  eax, 0xA5
    je   .target_supported
    cmp  eax, 0xA6
    je   .target_supported
    cmp  eax, 0x7E
    je   .target_supported
    cmp  eax, 0x8C
    je   .target_supported
    cmp  eax, 0x8D
    je   .target_supported
    cmp  eax, 0x6A
    je   .target_supported
    cmp  eax, 0x6C
    je   .target_supported
    cmp  eax, 0x97
    je   .target_supported
    cmp  eax, 0x9A
    je   .target_supported
    cmp  eax, 0xBA
    je   .target_supported
    cmp  eax, 0xB7
    je   .target_supported
    cmp  eax, 0xBF
    je   .target_supported
    cmp  eax, 0x8F
    je   .target_supported
    cmp  eax, 0xCF
    je   .target_supported
    cmp  eax, 0xAA
    je   .target_supported
    cmp  eax, 0xAD
    je   .target_supported
    cmp  eax, 0xAE
    je   .target_supported
    cmp  eax, 0xAF
    je   .target_supported
    cmp  eax, 0xBD
    je   .target_supported
    cmp  eax, 0x37
    je   .target_supported
    cmp  eax, 0x4A
    je   .target_supported
    cmp  eax, 0x4D
    je   .target_supported
    cmp  eax, 0x5A
    je   .target_supported
    cmp  eax, 0x5D
    je   .target_supported
    cmp  eax, 0x4C
    je   .target_supported
    cmp  eax, 0x5C
    je   .target_supported
    cmp  eax, 0x5F
    je   .target_supported
    cmp  eax, 0x7A
    je   .target_supported
    cmp  eax, 0x86
    je   .target_supported
    cmp  eax, 0x8A
    je   .target_supported
    cmp  eax, 0x96
    je   .target_supported
    cmp  eax, 0x9C
    je   .target_supported
    cmp  eax, 0xBE
    je   .target_supported
    jmp  .uncalibrated
.target_supported:
    mov  ecx, THERM_MSR_TJTARGET
    rdmsr
    shr  eax, 16
    and  eax, 0xFF
    test eax, eax
    jz   .uncalibrated                     ; no usable hardware calibration
    mov  [rel therm_tjmax], eax
    mov  byte [rel therm_calibrated], 1
    mov  byte [rel therm_degraded], 0
    lea  rdi, [rel str_therm_armed_ok]
    call serial_string
    mov  byte [rel therm_m_armed], 1
    pop  rbx
    ret
.uncalibrated:
    lea  rdi, [rel str_therm_armed_uncal]
    call serial_string
    mov  byte [rel therm_m_armed], 1
    pop  rbx
    ret
.no_dts:
    mov  byte [rel therm_dts_present], 0
    call therm_amd_detect                   ; AMD Tctl (fleet root complexes only)
    test eax, eax
    jz   .no_sensor
    mov  byte [rel therm_degraded], 0
    mov  byte [rel therm_source], THERM_SRC_AMD_TCTL
    lea  rdi, [rel str_therm_armed_amd]
    call serial_string
    mov  byte [rel therm_m_armed], 1
    pop  rbx
    ret
.no_sensor:
    mov  byte [rel therm_source], THERM_SRC_NONE
    mov  byte [rel therm_degraded], 1
    lea  rdi, [rel str_therm_armed_deg]
    call serial_string
    mov  byte [rel therm_m_armed], 1
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; thermal_read_live -> EAX = live core temp in C, or -1 if unavailable.
;   Updates therm_last_temp + therm_last_status (the raw 0x19C word). Gated on the
;   DTS flag so rdmsr 0x19C is never issued on a no-DTS box (#GP-safe). clobbers:
;   RAX,RCX,RDX,R8.
; ---------------------------------------------------------------------------
thermal_read_live:
    cmp  byte [rel therm_source], THERM_SRC_AMD_TCTL
    je   .amd
    cmp  byte [rel therm_dts_present], 1
    jne  .degraded
    mov  ecx, THERM_MSR_STATUS
    rdmsr
    mov  [rel therm_last_status], eax      ; full status word (real MSR read)
    test eax, 1 << 31                       ; readout is usable only when reading-valid is set
    jz   .unavailable                      ; keep raw throttle/trip diagnostics, retry next read
    cmp  byte [rel therm_calibrated], 1
    jne  .unavailable                      ; raw status survives missing calibration
    mov  r8d, eax
    shr  r8d, 16
    and  r8d, 0x7F                          ; bits[22:16] = digital readout (offset below Tj_max)
    mov  eax, [rel therm_tjmax]
    sub  eax, r8d                           ; tempC = Tj_max - readout (NOT the raw readout)
    mov  [rel therm_last_temp], eax
    ret
.amd:
    mov  dword [rel therm_last_status], 0   ; no throttle/trip status word on this source
    call therm_amd_read                     ; EAX = C, or -1 when implausible
    mov  [rel therm_last_temp], eax
    ret
.degraded:
    mov  dword [rel therm_last_status], 0
.unavailable:
    mov  dword [rel therm_last_temp], -1
    mov  eax, -1
    ret

; ---------------------------------------------------------------------------
; thermal_pkg_read -> EAX = package temperature (C), or -1 (RC power T1 POWERSTAT).
;   Intel DTS source only, with a calibrated Tj_max and CPUID.06H:EAX[6] (PTM):
;   IA32_PACKAGE_THERM_STATUS 1B1H, Pkg Digital Readout [22:16] below Tj_max (SDM
;   Vol.4 Table 2-2). Read-only. clobbers: RAX, RCX, RDX.
; ---------------------------------------------------------------------------
thermal_pkg_read:
    cmp  byte [rel therm_source], THERM_SRC_DTS
    jne  .none
    cmp  byte [rel therm_calibrated], 1
    jne  .none
    push rbx
    mov  eax, 6
    xor  ecx, ecx
    cpuid
    pop  rbx
    test eax, 1 << 6
    jz   .none
    mov  ecx, 0x1B1
    rdmsr
    shr  eax, 16
    and  eax, 0x7F
    mov  ecx, [rel therm_tjmax]
    sub  ecx, eax
    mov  eax, ecx
    ret
.none:
    mov  eax, -1
    ret

; ---------------------------------------------------------------------------
; therm_amd_detect -> EAX 1 when the AMD Tctl source is usable, else 0 (RCQ-27
;   POWER-03). Read-only on the sensor; the one write is the SMN index of the AMD
;   root complex, and it is issued only after every gate passed: AuthenticAMD,
;   not under a hypervisor (on QEMU's q35 host bridge 0x60 is PCIEXBAR), family
;   17h or 19h, 00:00.0 exactly one of the two fleet root complexes, and a
;   plausible first reading. Anything else stays temp=unavailable.
;   clobbers: caller-saved.
; ---------------------------------------------------------------------------
therm_amd_detect:
    push rbx
    xor  eax, eax
    cpuid
    cmp  ebx, 'Auth'
    jne  .no
    cmp  edx, 'enti'
    jne  .no
    cmp  ecx, 'cAMD'
    jne  .no
    mov  eax, 1
    cpuid
    bt   ecx, 31                            ; hypervisor
    jc   .no
    mov  edx, eax
    shr  edx, 8
    and  edx, 0xF                           ; base family
    shr  eax, 20
    and  eax, 0xFF                          ; extended family
    add  eax, edx
    cmp  eax, 0x17
    je   .family_ok
    cmp  eax, 0x19
    jne  .no
.family_ok:
    xor  edi, edi
    xor  esi, esi
    xor  edx, edx
    xor  ecx, ecx
    call pci_cfg_read32                     ; 00:00.0 vendor:device
    cmp  eax, THERM_AMD_ROOT_17H_M10
    je   .root_ok
    cmp  eax, THERM_AMD_ROOT_19H_M70
    jne  .no
.root_ok:
    call therm_amd_read
    cmp  eax, -1
    je   .no
    mov  eax, 1
    pop  rbx
    ret
.no:
    xor  eax, eax
    pop  rbx
    ret

; therm_amd_read -> EAX = Tctl in whole degrees C, or -1 when out of 0..125.
;   SMN 0x00059800 (THM_TCON_CUR_TMP): [31:21] temperature in 0.125 C steps; the
;   range-select bit 19, or TJ_SEL [17:16] = 3, means the -49 C range (k10temp).
;   clobbers: caller-saved.
therm_amd_read:
    xor  edi, edi
    xor  esi, esi
    xor  edx, edx
    mov  ecx, THERM_AMD_SMN_INDEX
    mov  r8d, THERM_AMD_TCTL_SMN
    call pci_cfg_write32
    xor  edi, edi
    xor  esi, esi
    xor  edx, edx
    mov  ecx, THERM_AMD_SMN_DATA
    call pci_cfg_read32
    mov  [rel therm_amd_raw], eax           ; raw SMN custody, not IA32_THERM_STATUS
    mov  ecx, eax
    shr  eax, 21
    and  eax, 0x7FF
    imul eax, eax, 125                      ; millidegrees
    test ecx, 1 << 19
    jnz  .range
    mov  edx, ecx
    shr  edx, 16
    and  edx, 3
    cmp  edx, 3
    jne  .whole
.range:
    sub  eax, 49000
.whole:
    ; Validate signed raw precision before truncation: -0.125 is unavailable,
    ; and 125.125 must not become a valid 125 C. Keep the existing 0..125 policy.
    cmp  eax, 0
    jl   .bad
    cmp  eax, THERM_AMD_MAX_C * 1000
    jg   .bad
    cdq
    mov  ecx, 1000
    idiv ecx                                ; valid nonnegative whole-C display
    ret
.bad:
    mov  eax, -1
    ret

; ---------------------------------------------------------------------------
; Pure software-notice predicate: EDI=tempC, ESI=source, EDX=degraded,
; ECX=threshold -> EAX=0/1. Reader already checks DTS validity/calibration and
; AMD raw precision. The boot KAT uses only local synthetic inputs to this seam.
thermal_notice_admit:
    xor  eax, eax
    test edx, edx
    jnz  .done
    cmp  esi, THERM_SRC_DTS
    je   .sample
    cmp  esi, THERM_SRC_AMD_TCTL
    jne  .done
.sample:
    cmp  edi, -1
    je   .done
    cmp  edi, ecx
    setge al
.done:
    ret

; Capture one admitted software notice. The caller has just read the live sensor.
; BSP dispatch serializes the complete snapshot with passive THROTTLE_LOG/THERM.
; Returns EAX=1 recorded, 0 rejected; rejection leaves ALL event history alone.
thermal_record_event:
    mov  edi, [rel therm_last_temp]
    movzx esi, byte [rel therm_source]
    movzx edx, byte [rel therm_degraded]
    mov  ecx, [rel therm_notice_threshold]
    call thermal_notice_admit
    test eax, eax
    jz   .done
    mov  eax, [rel therm_last_temp]
    mov  [rel therm_event_temp], eax
    mov  al, [rel therm_source]
    mov  [rel therm_event_source], al
    mov  edx, [rel therm_last_status]
    mov  [rel therm_event_status], edx
    mov  [rel therm_event_raw], edx
    xor  eax, eax
    cmp  byte [rel therm_event_source], THERM_SRC_DTS
    jne  .amd
    mov  eax, edx
    shr  eax, 1
    and  eax, 1                             ; hardware thermal-log bit ONLY
    jmp  .logbit
.amd:
    mov  edx, [rel therm_amd_raw]
    mov  [rel therm_event_raw], edx
.logbit:
    mov  [rel therm_logbit], al
    mov  byte [rel therm_event_notice], 1
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [rel therm_last_tsc], rax
    cmp  qword [rel therm_events], -1
    je   .counted
    inc  qword [rel therm_events]            ; saturating u64, never an empty wrap
.counted:
    mov  edi, THERM_DIAG_KIND
    mov  rsi, [rel therm_events]
    mov  eax, 0xffffffff
    cmp  rsi, rax
    cmova rsi, rax                          ; diag arg is a saturating u32 count
    mov  edx, [rel therm_event_raw]          ; a = source-specific raw sensor word
    mov  rcx, [rel therm_last_tsc]           ; b = event raw TSC (no age conversion)
    mov  r8d, [rel therm_event_temp]          ; c = measured event whole Celsius
    lea  r9, [rel therm_tag_dts]             ; tag carries software provenance/source
    cmp  byte [rel therm_event_source], THERM_SRC_DTS
    je   .append
    lea  r9, [rel therm_tag_amd]
.append:
    call diag_ring_append
    mov  eax, 1
.done:
    ret

; Bounded notice probe, never hardware throttling. All admission paths converge
; on unconditional default-threshold restoration; EAX reports this attempt only.
thermal_induce_and_log:
    mov  dword [rel therm_notice_threshold], THERM_NOTICE_INDUCED
    call thermal_read_live
    call thermal_record_event
    mov  dword [rel therm_notice_threshold], THERM_NOTICE_DEFAULT
    ret

; ---------------------------------------------------------------------------
; power_read_pstate -> EAX = dAPERF*100/dMPERF, or 0 when unavailable.
;   power_state distinguishes a valid idle/rounded zero from unavailable data.
;   Modular deltas below 2^63 permit real rollover and reject detectable resets /
;   backward or ambiguous windows. Two reads cannot detect a reset that exactly
;   imitates forward progress. The sampling window must be shorter than 2^63 ticks.
;   Reuses governor read/load helpers; no policy or MSR writes. Caller-saved only.
; ---------------------------------------------------------------------------
power_read_pstate:
    mov  byte [rel power_state], POWER_UNSUPPORTED
    cmp  byte [rel gov_apmf_present], 1
    jne  .none
    mov  byte [rel power_state], POWER_INVALID
    call gov_rd_mperf
    mov  r10, rax                           ; mperf0
    call gov_rd_aperf
    mov  r11, rax                           ; aperf0
    mov  rcx, THERM_PS_ITERS
    call gov_busy_load                      ; touches only RCX,R8 -> R10/R11 preserved
    call gov_rd_mperf
    sub  rax, r10
    mov  r10, rax                           ; dMPERF, modular forward distance
    call gov_rd_aperf
    sub  rax, r11                           ; dAPERF, modular forward distance
    test r10, r10
    jle  .none                              ; zero denominator or distance >= 2^63
    test rax, rax
    js   .none                              ; ambiguous/backward APERF; idle zero is valid
    mov  rcx, 100
    mul  rcx                                ; retain full RDX:RAX product
    cmp  rdx, r10
    jae  .none                              ; DIV would fault if quotient exceeds u64
    div  r10                                ; percent of base, rounded down
    mov  edx, 0xffffffff
    cmp  rax, rdx
    ja   .none                              ; public/cache dword must never wrap
    mov  byte [rel power_state], POWER_VALID
    mov  [rel power_ratio], eax
    ret
.none:
    xor  eax, eax
    mov  [rel power_ratio], eax              ; no stale or synthetic live cache
    ret

; ---------------------------------------------------------------------------
; thermal_selftest — live read/P-state checks plus an isolated synthetic notice
; predicate KAT. Markers prove boot logic only, never physical throttling.
; ---------------------------------------------------------------------------
thermal_selftest:
    push rbx
    ; --- (2) READ ---
    call thermal_read_live
    lea  rdi, [rel str_therm_read_pre]
    call serial_string
    cmp  byte [rel therm_source], THERM_SRC_NONE
    je   .read_synthetic                   ; no sensor: logic KAT only
    cmp  dword [rel therm_last_temp], -1
    je   .read_unavailable
    mov  edi, [rel therm_last_temp]
    call therm_emit_dec
    jmp  .read_mark
.read_unavailable:
    lea  rdi, [rel str_to_unavail]
    call serial_string
    jmp  .read_mark
.read_synthetic:
    mov  edi, THERM_KAT_TEMP                ; serial-only, never cached as live
    call therm_emit_dec
    lea  rdi, [rel str_therm_read_syn]
    call serial_string
.read_mark:
    lea  rdi, [rel str_therm_read_post]
    call serial_string
    mov  byte [rel therm_m_read], 1
    ; --- (3) Synthetic predicate KAT: never induce, append or touch history. ---
    mov  edi, THERM_KAT_TEMP
    mov  esi, THERM_SRC_DTS
    xor  edx, edx
    mov  ecx, THERM_NOTICE_INDUCED
    call thermal_notice_admit
    cmp  eax, 1
    jne  .kat_bad
    mov  edi, -1
    mov  esi, THERM_SRC_DTS
    xor  edx, edx
    mov  ecx, THERM_NOTICE_INDUCED
    call thermal_notice_admit
    test eax, eax
    jnz  .kat_bad
    lea  rdi, [rel str_therm_thr_pre]
    call serial_string
    lea  rdi, [rel str_therm_thr_post]
    call serial_string
    mov  byte [rel therm_m_throttle], 1
    jmp  .kat_done
.kat_bad:
    mov  byte [rel therm_m_throttle], 0
    lea  rdi, [rel str_therm_thr_fail]
    call serial_string
.kat_done:
    ; --- (4) PSTATE ---
    call power_read_pstate
    lea  rdi, [rel str_power_ps_pre]
    call serial_string
    cmp  byte [rel power_state], POWER_VALID
    je   .ps_live
    cmp  byte [rel power_state], POWER_UNSUPPORTED
    je   .ps_synthetic
    lea  rdi, [rel str_to_unavail]
    call serial_string
    lea  rdi, [rel str_ps_invalid]
    call serial_string
    jmp  .ps_mark
.ps_synthetic:
    mov  edi, THERM_KAT_RATIO                ; LOGIC KAT only, never stored as live
    call therm_emit_dec
    lea  rdi, [rel str_power_ps_syn]
    call serial_string
    jmp  .ps_mark
.ps_live:
    mov  edi, [rel power_ratio]              ; includes a valid idle ratio of zero
    call therm_emit_dec
.ps_mark:
    lea  rdi, [rel str_power_ps_post]
    call serial_string
    mov  byte [rel power_m_pstate], 1
    pop  rbx
    ret

; therm_emit_dec(RDI=value) — unsigned decimal to serial via canonical fmt_dec (G1).
therm_emit_dec:
    lea  rsi, [rel therm_numbuf]
    call fmt_dec
    lea  rdi, [rel therm_numbuf]
    call serial_string
    ret

; therm_emit_hex(RDI=value) — lowercase hex to serial via canonical fmt_hex (G1).
therm_emit_hex:
    lea  rsi, [rel therm_numbuf]
    xor  edx, edx
    call fmt_hex
    lea  rdi, [rel therm_numbuf]
    call serial_string
    ret

; ===========================================================================
; UDP/registry PROJECTION — the four live verbs. Each is a THIN handler: it reads
; the REAL MSRs (or degrades honestly) and STAGES its reply line into therm_out_buf
; (framed verbatim by command_udp.asm's udp_send_reply, the same staging pattern the
; governor/reinit surfaces use). The raw arg token (nonce) round-trips via ARG=.
; ===========================================================================

; thermal_declare — register THERM / THERM_INDUCE / THROTTLE_LOG / PSTATE? through
;   the SAME command_register_verb (additive, no registry-core edit — the §9.4
;   degenerate-Nth seam). All ARGT_TEXT so a text nonce echoes back verbatim.
;   clobbers: caller-saved.
thermal_declare:
    lea  rdi, [rel str_verb_therm]
    lea  rsi, [rel cmd_verb_therm]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9                             ; read-only
    call command_register_verb
    lea  rdi, [rel str_verb_therminduce]
    lea  rsi, [rel cmd_verb_therminduce]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1                              ; mutates the software notice threshold (auto-reverts)
    call command_register_verb
    lea  rdi, [rel str_verb_throttlelog]
    lea  rsi, [rel cmd_verb_throttlelog]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_verb_pstate]
    lea  rsi, [rel cmd_verb_pstate]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    ret

; --- VERB: THERM <nonce> — live temperature; tjmax=0 means no observed target.
;   Preserve numeric target/wire shape for the typed THERM parser. Missing Intel
;   calibration reports tempC=unavailable degraded=1 source=dts, not a default.
cmd_verb_therm:
    call cmd_handler_prologue
    push rdi
    push rsi
    call thermal_read_live
    call therm_out_reset
    lea  rdi, [rel str_to_tempc]
    call therm_out_str
    cmp  byte [rel therm_degraded], 1
    je   .deg
    cmp  dword [rel therm_last_temp], -1
    je   .deg                               ; a source with no plausible reading right now
    mov  edi, [rel therm_last_temp]
    call therm_out_dec
    jmp  .tj
.deg:
    lea  rdi, [rel str_to_unavail]
    call therm_out_str
.tj:
    lea  rdi, [rel str_to_tjmax]
    call therm_out_str
    mov  edi, [rel therm_tjmax]
    call therm_out_dec
    lea  rdi, [rel str_to_degraded]
    call therm_out_str
    movzx edi, byte [rel therm_degraded]
    call therm_out_dec
    lea  rdi, [rel str_to_source]
    call therm_out_str
    lea  rdi, [rel str_to_src_none]
    cmp  byte [rel therm_source], THERM_SRC_DTS
    jne  .src_amd
    lea  rdi, [rel str_to_src_dts]
.src_amd:
    cmp  byte [rel therm_source], THERM_SRC_AMD_TCTL
    jne  .src_out
    lea  rdi, [rel str_to_src_amd]
.src_out:
    call therm_out_str
    mov  byte [rel therm_out_ready], 1
    pop  rsi                                ; restore resp/req AFTER the clobbering staging
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; --- VERB: THERM_INDUCE — lower the notice threshold, log a throttle, auto-revert.
cmd_verb_therminduce:
    call cmd_handler_prologue
    push rdi
    push rsi
    call thermal_induce_and_log
    push rax                               ; per-attempt result survives formatting
    call therm_out_reset
    lea  rdi, [rel str_to_induced]
    call therm_out_str
    pop  rdi
    call therm_out_dec
    mov  byte [rel therm_out_ready], 1
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; --- VERB: THROTTLE_LOG — passive last admitted software-notice snapshot.
; Original four keys retained; explicit notice/source/temp/raw extend provenance.
cmd_verb_throttlelog:
    call cmd_handler_prologue
    push rdi
    push rsi
    call therm_out_reset
    lea  rdi, [rel str_tl_status]
    call therm_out_str
    mov  edi, [rel therm_event_status]
    call therm_out_hex
    lea  rdi, [rel str_tl_logbit]
    call therm_out_str
    movzx edi, byte [rel therm_logbit]
    call therm_out_dec
    lea  rdi, [rel str_tl_events]
    call therm_out_str
    mov  rdi, [rel therm_events]
    call therm_out_dec
    lea  rdi, [rel str_tl_ts]
    call therm_out_str
    mov  rdi, [rel therm_last_tsc]
    call therm_out_dec
    lea  rdi, [rel str_tl_notice]
    call therm_out_str
    movzx edi, byte [rel therm_event_notice]
    call therm_out_dec
    lea  rdi, [rel str_tl_source]
    call therm_out_str
    lea  rdi, [rel str_tl_none]
    cmp  byte [rel therm_event_source], THERM_SRC_DTS
    jne  .amd
    lea  rdi, [rel str_tl_dts]
.amd:
    cmp  byte [rel therm_event_source], THERM_SRC_AMD_TCTL
    jne  .source
    lea  rdi, [rel str_tl_amd]
.source:
    call therm_out_str
    lea  rdi, [rel str_tl_temp]
    call therm_out_str
    cmp  byte [rel therm_event_notice], 1
    jne  .empty
    mov  edi, [rel therm_event_temp]
    call therm_out_dec
    jmp  .raw
.empty:
    lea  rdi, [rel str_tl_unavailable]
    call therm_out_str
.raw:
    lea  rdi, [rel str_tl_raw]
    call therm_out_str
    mov  edi, [rel therm_event_raw]
    call therm_out_hex
    mov  byte [rel therm_out_ready], 1
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; --- VERB: PSTATE? — measured "ratio=NN", or unavailable with a reason.
cmd_verb_pstate:
    call cmd_handler_prologue
    push rdi
    push rsi
    call power_read_pstate
    call therm_out_reset
    lea  rdi, [rel str_ps_ratio]
    call therm_out_str
    cmp  byte [rel power_state], POWER_VALID
    jne  .unavailable
    mov  edi, [rel power_ratio]
    call therm_out_dec
    jmp  .ready
.unavailable:
    lea  rdi, [rel str_to_unavail]
    call therm_out_str
    lea  rdi, [rel str_ps_unsupported]
    cmp  byte [rel power_state], POWER_UNSUPPORTED
    je   .reason
    lea  rdi, [rel str_ps_invalid]
.reason:
    call therm_out_str
.ready:
    mov  byte [rel therm_out_ready], 1
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; --- staged-reply buffer helpers (mirror the reinit/gov staging pattern) ---
therm_out_reset:
    lea  rax, [rel therm_out_buf]
    mov  [rel therm_out_cur], rax
    ret
; therm_out_str(RDI=cstr) — append NUL-terminated string at the cursor.
therm_out_str:
    mov  rsi, [rel therm_out_cur]
.cp:
    mov  al, [rdi]
    test al, al
    jz   .done
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .cp
.done:
    mov  byte [rsi], 0
    mov  [rel therm_out_cur], rsi
    ret
; therm_out_dec(RDI=value) — append unsigned decimal via canonical fmt_dec (G1).
therm_out_dec:
    mov  rsi, [rel therm_out_cur]
    push rsi
    call fmt_dec
    pop  rsi
    add  rsi, rax
    mov  [rel therm_out_cur], rsi
    ret
; therm_out_hex(RDI=value) — append lowercase hex via canonical fmt_hex (G1).
therm_out_hex:
    mov  rsi, [rel therm_out_cur]
    push rsi
    xor  edx, edx
    call fmt_hex
    pop  rsi
    add  rsi, rax
    mov  [rel therm_out_cur], rsi
    ret

; --- core/thermal data (RW under our page tables, in-image) ------------------
align 8
therm_events:          dq 0            ; saturating admitted software-notice count
therm_last_tsc:        dq 0            ; RDTSC timestamp of the last logged event
therm_event_status:   dd 0            ; Intel event status; zero on AMD/no history
therm_event_raw:      dd 0            ; raw Intel status OR raw AMD Tctl SMN
therm_event_temp:     dd 0            ; meaningful only with notice=1
therm_amd_raw:        dd 0            ; most recent raw AMD read, separate live cache
therm_event_source:   db THERM_SRC_NONE
therm_event_notice:   db 0            ; explicit software notice, never hardware logbit
align 8
therm_out_cur:         dq 0            ; live staged-reply cursor
therm_tjmax:           dd 0            ; observed target C; 0 == no calibration (all sources)
therm_calibrated:      db 0            ; Intel target admitted this init, independent of read-valid
align 4
therm_last_temp:       dd 0            ; last live temperature (C), -1 if unavailable
therm_last_status:     dd 0            ; last raw IA32_THERM_STATUS word (real MSR read)
therm_notice_threshold: dd 0           ; software throttle-notice threshold (deg C)
power_ratio:           dd 0            ; measured ratio, zero when unavailable (see state)
power_state:           db POWER_UNSUPPORTED ; POWER_*; valid idle is distinct from unavailable
therm_dts_present:     db 0            ; CPUID.06H:EAX bit0 (Digital Thermal Sensor)
therm_source:          db 0            ; THERM_SRC_* (RCQ-27 POWER-03)
therm_degraded:        db 0            ; no sensor or no Intel calibration -> unavailable
therm_logbit:          db 0            ; last event's thermal-log indication
therm_m_armed:         db 0            ; thermal.monitor.armed earned
therm_m_read:          db 0            ; thermal.read.ok earned
therm_m_throttle:      db 0            ; thermal.throttle.logged earned
power_m_pstate:        db 0            ; power.pstate.ok earned
therm_out_ready:       db 0            ; a per-command reply line is staged in therm_out_buf
therm_numbuf:          times 24 db 0   ; u64 dec/hex scratch
therm_tag_dts:         db "software-notice:dts", 0
therm_tag_amd:         db "software-notice:amd_tctl", 0
align 8
therm_out_buf:         times 256 db 0

; --- boot markers (serial + BOOTLOG content-grade) ---
str_therm_armed_uncal: db "[PAOS64] P3 therm: DTS raw status armed, calibration unavailable; temp=unavailable [thermal.monitor.armed]", 13, 10, 0
str_therm_armed_ok:  db "[PAOS64] P3 therm: DTS monitor armed (MSR 0x19C/0x1A2, Tj_max cached) [thermal.monitor.armed]", 13, 10, 0
str_therm_armed_amd: db "[PAOS64] P3 therm: AMD Tctl (SMN 0x00059800 via the root complex) armed, no trip/throttle status on this source [thermal.monitor.armed]", 13, 10, 0
str_therm_armed_deg: db "[PAOS64] P3 therm: no supported sensor — armed DEGRADED, temp=unavailable [thermal.monitor.armed]", 13, 10, 0
str_therm_read_pre:  db "[PAOS64] P3 therm: live temperature read tempC=", 0
str_therm_read_syn:  db " (synthetic; no supported sensor — degrade)", 0
str_therm_read_post: db " [thermal.read.ok]", 13, 10, 0
str_therm_thr_pre:   db "[PAOS64] P3 therm: synthetic notice logic KAT (no live event or diag append)", 0
str_therm_thr_fail:  db "[PAOS64] P3 therm: synthetic notice logic KAT FAILED", 13, 10, 0
str_therm_thr_st:    db " therm_status=0x", 0
str_therm_thr_lb:    db " logbit=", 0
str_therm_thr_post:  db " [thermal.throttle.logged]", 13, 10, 0
str_power_ps_pre:    db "[PAOS64] P3 power: live P-state ratio=", 0
str_power_ps_syn:    db " (synthetic; status=unsupported)", 0
str_power_ps_post:   db " [power.pstate.ok]", 13, 10, 0

; --- verb names (matched verbatim by command_lookup; keep the '?' / '_') ---
str_verb_therm:       db "THERM", 0
str_verb_therminduce: db "THERM_INDUCE", 0
str_verb_throttlelog: db "THROTTLE_LOG", 0
str_verb_pstate:      db "PSTATE?", 0

; --- staged UDP reply fragments ---
str_to_tempc:     db "tempC=", 0
str_to_unavail:   db "unavailable", 0
str_to_tjmax:     db " tjmax=", 0
str_to_degraded:  db " degraded=", 0
str_to_source:    db " source=", 0
str_to_src_none:  db "none", 0
str_to_src_dts:   db "dts", 0
str_to_src_amd:   db "amd_tctl", 0
str_to_induced:   db "induced=1 notice_threshold=1 reverted=1 recorded=", 0
str_tl_status:    db "therm_status=0x", 0
str_tl_logbit:    db " logbit=", 0
str_tl_events:    db " events=", 0
str_tl_ts:        db " ts=", 0
str_tl_notice:    db " notice=", 0
str_tl_source:    db " source=", 0
str_tl_none:      db "none", 0
str_tl_dts:       db "dts", 0
str_tl_amd:       db "amd_tctl", 0
str_tl_temp:      db " tempC=", 0
str_tl_unavailable: db "unavailable", 0
str_tl_raw:       db " raw=0x", 0
str_ps_ratio:     db "ratio=", 0

str_ps_unsupported: db " status=unsupported", 0
str_ps_invalid:     db " status=invalid", 0
