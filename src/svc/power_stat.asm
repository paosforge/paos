;; MODULE svc/power_stat
;; LAYER 5
;; EXPORTS power_stat_declare, cmd_verb_powerstat, power_stat_gate, power_stat_mw
;; IMPORTS core/smp, core/time, svc/command, svc/command_auth, svc/idle_probe, svc/thermal, dev/power/ec_power
;; CAPS
;; OWNER saga:power
; ============================================================================
; svc/power_stat.asm — RC power service T1: owner-only POWERSTAT (root 52080 (2),
; plan 52188). Read-only: no MSR, EC, port or NVRAM write, no AML.
;
; POWERSTAT measures package energy over one halting 100 ms window on the
; serving CPU: two reads of the package energy counter, TSC-timed, around
; smp_halt_wait_us. Register sources (T1_DESIGN.md, Citations):
;   Intel  MSR_RAPL_POWER_UNIT 606H ESU[12:8], MSR_PKG_ENERGY_STATUS 611H[31:0]
;          (SDM Vol.3B 17.10.1/17.10.3, Vol.4 Table 2-20 and 2.17).
;   AMD    CPUID Fn8000_0007 EDX[14] RAPL, then MSRC001_0299 ESU[12:8] and
;          MSRC001_029B[31:0] (PPR 55570-B1 pp.74, 147-148).
; MSRs are read only on the parts idle_probe_gate admits (the fleet's cited
; family/model rows, never under a hypervisor), and on AMD only with the RAPL bit.
; Anything else is energy=unknown with a reason, never 0 mW. Deltas use the low 32
; bits modulo 2^32 on both vendors (a 63:0 counter, PPR 19h M11h, stays correct);
; a 100 ms window cannot wrap twice (the SDM's wrap is ~60 s at high power).
;
; Owner only (root: "owner-only energy/temperature telemetry"). Package energy is a
; known side channel, so the verb is registered with the owner cap AND checks the
; owner envelope itself: SYSTEM holds generic MUTATE, so the cap alone would admit
; the AI ticket. Any other principal gets AUTHDENY and no measurement at all.
;
; Reply "POWERSTAT energy=<rapl|unknown> why=<reason> pkg_mw=<n|-> window_ms=<n>
;   esu=<n> temp_c=<n|-> pkg_temp_c=<n|-> cpus=<n> halts=<n> deep=<n>"
;   " batt_s=<low|->:<high|-> health_pct=<n|->"
;   (temp_c: thermal_read_live; pkg_temp_c: Intel package sensor when CPUID.06H:EAX[6];
;   halts/deep: idle HLT and MWAIT/IO entries summed over all CPUs).
;   Battery seconds are the backend engineering range, not an accuracy claim.
;   Unknown/expired/AC-on runtime stays "-"; health may remain known on AC.
;   The BSP snapshot revalidates published data and performs no EC IO. Per-CPU
;   frequency stays in SMPSTAT LOAD and per-CPU halts in SMPSTAT CPU <n>.
; ============================================================================

PST_MSR_INTEL_UNIT  equ 0x606
PST_MSR_INTEL_PKG   equ 0x611
PST_MSR_AMD_UNIT    equ 0xC0010299
PST_MSR_AMD_PKG     equ 0xC001029B
PST_WINDOW_US       equ 100000

PST_R_OK            equ 0             ; energy=rapl
PST_R_HYPERVISOR    equ 1             ; no MSR read under a hypervisor
PST_R_PART          equ 2             ; not a cited part
PST_R_NORAPL        equ 3             ; AMD part without CPUID Fn8000_0007 EDX[14]
PST_R_UNIT          equ 4             ; ESU read as 0
PST_R_STATIC        equ 5             ; the counter did not advance over the window
PST_R_CLOCK         equ 6             ; no calibrated TSC or an empty window
PST_R_RANGE         equ 7             ; the mW arithmetic would overflow
PST_R_COUNT         equ 8

; ---------------------------------------------------------------------------
; power_stat_declare — register POWERSTAT (owner read, no argument).
; ---------------------------------------------------------------------------
power_stat_declare:
    lea  rdi, [rel str_verb_powerstat]
    lea  rsi, [rel cmd_verb_powerstat]
    mov  rdx, CMD_AUTH_CAP_MUTATE           ; explicit owner cap: never public
    mov  ecx, ARGT_NONE
    xor  r8, r8
    xor  r9, r9                             ; read-only
    jmp  command_register_verb

; ---------------------------------------------------------------------------
; power_stat_gate(EDI=vendor IDLE_V_*, ESI=family, EDX=model, ECX=hypervisor,
;   R8D=AMD CPUID Fn8000_0007 EDX[14]) -> EAX = PST_R_OK or the reason no energy
;   MSR may be read. Pure.
; ---------------------------------------------------------------------------
power_stat_gate:
    push rbx
    push r12
    mov  ebx, ecx
    mov  r12d, edi
    call idle_probe_gate                    ; the cited parts; 0 under a hypervisor
    test eax, eax
    jnz  .part_ok
    mov  eax, PST_R_PART
    test ebx, ebx
    jz   .out
    mov  eax, PST_R_HYPERVISOR
    jmp  .out
.part_ok:
    xor  eax, eax
    cmp  r12d, IDLE_V_AMD
    jne  .out
    test r8d, r8d
    jnz  .out
    mov  eax, PST_R_NORAPL
.out:
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; power_stat_mw(EDI=energy delta in units, ESI=ESU, RDX=TSC delta, RCX=tsc_khz)
;   -> RAX = mW = delta * 10^6 * tsc_khz / (2^ESU * TSC delta), or -1 when the
;   clock is missing or the result does not fit. Pure; 128-bit intermediate.
; ---------------------------------------------------------------------------
power_stat_mw:
    test rdx, rdx
    jz   .bad
    test rcx, rcx
    jz   .bad
    mov  r8, rdx                            ; TSC delta
    mov  r9, rcx                            ; tsc_khz
    mov  eax, edi                           ; zero-extended u32
    imul rax, rax, 1000000                  ; <= 4.3e15, fits
    mul  r9                                 ; RDX:RAX = delta * 10^6 * khz
    mov  ecx, esi
    and  ecx, 31
    shrd rax, rdx, cl
    shr  rdx, cl
    cmp  rdx, r8
    jae  .bad                               ; the quotient would not fit (#DE)
    div  r8
    ret
.bad:
    mov  rax, -1
    ret

; --- VERB: POWERSTAT — package energy over 100 ms, temperatures, idle counters (owner). ---
cmd_verb_powerstat:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 32                            ; idle_probe_cpu_ident's 5 dwords
    mov  r12, rsi
    cmp  qword [rdi + REQ_SOURCE], CMD_SOURCE_CONSOLE
    je   .owner                             ; the dispatcher already requires the console owner
    call command_auth_owner_request         ; 1 = own AUTH1 owner ticket, 2 = owner SSH key
    test eax, eax
    jz   .not_owner
.owner:
    mov  qword [rel pst_mw], -1
    mov  dword [rel pst_window_ms], 0
    mov  dword [rel pst_esu], 0
    mov  rdi, rsp
    call idle_probe_cpu_ident               ; ECX = CPUID.01H:ECX
    shr  ecx, 31                            ; hypervisor present
    mov  r13d, ecx
    xor  r8d, r8d
    cmp  dword [rsp + 4], IDLE_V_AMD
    jne  .gate
    mov  eax, 0x80000000
    xor  ecx, ecx
    cpuid
    cmp  eax, 0x80000007
    jb   .gate
    mov  eax, 0x80000007
    xor  ecx, ecx
    cpuid
    mov  r8d, edx
    shr  r8d, 14
    and  r8d, 1
.gate:
    mov  edi, [rsp + 4]
    mov  esi, [rsp + 8]
    mov  edx, [rsp + 12]
    mov  ecx, r13d
    call power_stat_gate
    mov  [rel pst_reason], eax
    test eax, eax
    jnz  .temps
    mov  r14d, PST_MSR_INTEL_UNIT
    mov  r15d, PST_MSR_INTEL_PKG
    cmp  dword [rsp + 4], IDLE_V_AMD
    jne  .units
    mov  r14d, PST_MSR_AMD_UNIT
    mov  r15d, PST_MSR_AMD_PKG
.units:
    mov  dword [rel pst_reason], PST_R_CLOCK
    cmp  qword [rel tsc_khz], 0
    je   .temps
    mov  ecx, r14d
    rdmsr
    shr  eax, 8
    and  eax, 0x1F                          ; ESU[12:8]
    mov  [rel pst_esu], eax
    mov  dword [rel pst_reason], PST_R_UNIT
    test eax, eax
    jz   .temps
    mov  ecx, r15d
    rdmsr
    mov  ebx, eax                           ; E0 (low 32 bits)
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  r13, rax                           ; T0
    mov  edi, PST_WINDOW_US
    call smp_halt_wait_us                   ; the serving CPU halts through the window
    mov  ecx, r15d
    rdmsr
    mov  r14d, eax                          ; E1
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    sub  rax, r13                           ; TSC delta
    mov  r13, rax
    xor  edx, edx
    div  qword [rel tsc_khz]
    mov  [rel pst_window_ms], eax
    sub  r14d, ebx                          ; modulo 2^32
    mov  dword [rel pst_reason], PST_R_STATIC
    jz   .temps
    mov  edi, r14d
    mov  esi, [rel pst_esu]
    mov  rdx, r13
    mov  rcx, [rel tsc_khz]
    call power_stat_mw
    mov  dword [rel pst_reason], PST_R_RANGE
    cmp  rax, -1
    je   .temps
    mov  [rel pst_mw], rax
    mov  dword [rel pst_reason], PST_R_OK
.temps:
    call thermal_read_live                  ; EAX = C or -1
    mov  [rel pst_temp], eax
    call thermal_pkg_read                   ; EAX = C or -1
    mov  [rel pst_pkg_temp], eax
    ; Only the admitted owner reaches this trusted, BSP-serialized snapshot.
    ; Reset unknowns before querying: a short/failed ABI reply cannot expose old data.
    mov  qword [rel pst_forecast], 0
    mov  qword [rel pst_forecast + 16], -1
    mov  qword [rel pst_forecast + 24], -1
    mov  qword [rel pst_forecast + 32], -1
    lea  rdi, [rel pst_forecast]
    mov  esi, 64
    call ecp_forecast_snapshot
    cmp  eax, 64
    je   .forecast_ready
    mov  qword [rel pst_forecast], 0
    mov  qword [rel pst_forecast + 32], -1
.forecast_ready:
    call power_stat_format
    mov  byte [rel therm_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_OK
    mov  eax, [rel pst_reason]
    mov  [r12 + RSP_VAL], rax
    jmp  .out
.not_owner:
    call therm_out_reset
    lea  rdi, [rel str_pst_owner_only]
    call therm_out_str
    mov  byte [rel therm_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_AUTHDENY
    mov  qword [r12 + RSP_VAL], 0
.out:
    add  rsp, 32
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; power_stat_format — POWERSTAT plus published battery forecast in therm_out_buf.
; Forecast seconds <=235922400, health <=6553400 (backend capacity/rate bounds).
; At MAXCORE=64 even u64 counters/mW, u32 window and sign-extended i32
; temperatures fit 251 bytes plus NUL. Keep range compact in the 256-byte buffer.
power_stat_format:
    push rbx
    push r12
    push r13
    call therm_out_reset
    lea  rdi, [rel str_pst_verb]
    call therm_out_str
    lea  rdi, [rel str_pst_rapl]
    cmp  dword [rel pst_reason], PST_R_OK
    je   .energy
    lea  rdi, [rel str_pst_unknown]
.energy:
    call therm_out_str
    lea  rdi, [rel str_pst_why]
    call therm_out_str
    mov  eax, [rel pst_reason]
    cmp  eax, PST_R_COUNT
    jb   .why
    mov  eax, PST_R_RANGE
.why:
    shl  eax, 4                             ; 16-byte slots
    lea  rdi, [rel pst_reason_names]
    add  rdi, rax
    call therm_out_str
    lea  rdi, [rel str_pst_mw]
    call therm_out_str
    mov  rdi, [rel pst_mw]
    call pst_out_known
    lea  rdi, [rel str_pst_window]
    call therm_out_str
    mov  edi, [rel pst_window_ms]
    call therm_out_dec
    lea  rdi, [rel str_pst_esu]
    call therm_out_str
    mov  edi, [rel pst_esu]
    call therm_out_dec
    lea  rdi, [rel str_pst_temp]
    call therm_out_str
    movsxd rdi, dword [rel pst_temp]
    call pst_out_known
    lea  rdi, [rel str_pst_pkg_temp]
    call therm_out_str
    movsxd rdi, dword [rel pst_pkg_temp]
    call pst_out_known
    lea  rdi, [rel str_pst_cpus]
    call therm_out_str
    mov  edi, [rel smp_topology_online]
    call therm_out_dec
    xor  r12d, r12d                         ; halts (sum)
    xor  r13d, r13d                         ; deep (sum)
    xor  ebx, ebx
.cpu:
    cmp  ebx, MAXCORE
    jae  .counted
    lea  rax, [rel smp_idle_hlt_count]
    add  r12, [rax + rbx*8]
    lea  rax, [rel smp_idle_mwait_count]
    add  r13, [rax + rbx*8]
    inc  ebx
    jmp  .cpu
.counted:
    lea  rdi, [rel str_pst_halts]
    call therm_out_str
    mov  rdi, r12
    call therm_out_dec
    lea  rdi, [rel str_pst_deep]
    call therm_out_str
    mov  rdi, r13
    call therm_out_dec
    lea  rdi, [rel str_pst_batt_low]
    call therm_out_str
    mov  rdi, -1
    cmp  qword [rel pst_forecast], 1
    jne  .low
    mov  rdi, [rel pst_forecast + 16]
.low:
    call pst_out_known
    lea  rdi, [rel str_pst_batt_high]
    call therm_out_str
    mov  rdi, -1
    cmp  qword [rel pst_forecast], 1
    jne  .high
    mov  rdi, [rel pst_forecast + 24]
.high:
    call pst_out_known
    lea  rdi, [rel str_pst_batt_health]
    call therm_out_str
    mov  rdi, [rel pst_forecast + 32]
    call pst_out_known
    pop  r13
    pop  r12
    pop  rbx
    ret

; pst_out_known(RDI = value, -1 = unknown) — decimal, or "-".
pst_out_known:
    cmp  rdi, -1
    jne  therm_out_dec
    lea  rdi, [rel str_pst_dash]
    jmp  therm_out_str

align 8
pst_forecast:       times 8 dq 0          ; accepted 64-byte kernel snapshot ABI
pst_mw:             dq -1
pst_reason:         dd PST_R_PART
pst_window_ms:      dd 0
pst_esu:            dd 0
pst_temp:           dd -1
pst_pkg_temp:       dd -1

; PST_R_* names, 16-byte slots
pst_reason_names:
    db "ok", 0
    times 16 - 3 db 0
    db "hypervisor", 0
    times 16 - 11 db 0
    db "part", 0
    times 16 - 5 db 0
    db "norapl", 0
    times 16 - 7 db 0
    db "unit", 0
    times 16 - 5 db 0
    db "static", 0
    times 16 - 7 db 0
    db "clock", 0
    times 16 - 6 db 0
    db "range", 0
    times 16 - 6 db 0

str_verb_powerstat: db "POWERSTAT", 0
str_pst_verb:       db "POWERSTAT energy=", 0
str_pst_rapl:       db "rapl", 0
str_pst_unknown:    db "unknown", 0
str_pst_why:        db " why=", 0
str_pst_mw:         db " pkg_mw=", 0
str_pst_window:     db " window_ms=", 0
str_pst_esu:        db " esu=", 0
str_pst_temp:       db " temp_c=", 0
str_pst_pkg_temp:   db " pkg_temp_c=", 0
str_pst_cpus:       db " cpus=", 0
str_pst_halts:      db " halts=", 0
str_pst_deep:       db " deep=", 0
str_pst_dash:       db "-", 0
str_pst_owner_only: db "POWERSTAT err=owner_only", 0

str_pst_batt_low:    db " batt_s=", 0
str_pst_batt_high:   db ":", 0
str_pst_batt_health: db " health_pct=", 0
