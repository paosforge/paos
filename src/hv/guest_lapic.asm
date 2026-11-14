;; MODULE hv/guest_lapic
;; LAYER 5
;; EXPORTS glapic_reset, glapic_start, glapic_rdmsr, glapic_wrmsr, glapic_accept, glapic_pending, glapic_ack, glapic_tick, glapic_extint_ok, glapic_pic_blocked, glapic_msr, glapic_cpuid, glapic_inject_pick, glapic_on, glapic_msr_value, glapic_set_vcpus, glapic_instance, glapic_vcpus, glv_msr, glv_cpuid, glv_inject_pick, glv_take_startup, glv_take_kick, glv_startup_state, glapic_mptable
;; IMPORTS hv/vcpu_observe
;; CAPS
;; OWNER saga:hv
; RCQ-50 S3: the guest's virtual local APIC, x2APIC mode only.
;
; Guests boot `nolapic` today, so no MSI can be delivered. A GPU guest's driver
; needs MSI/MSI-X, which targets a local APIC. This module holds the APIC's
; architectural state and rules. S4 adds the exit-facing decisions that the
; VMX/SVM exit handler calls only while a profile selects VP_DEV_LAPIC
; (glapic_on): glapic_msr (APIC_BASE and the x2APIC MSRs), glapic_cpuid and
; glapic_inject_pick. With glapic_on clear every one of them is a no-op, so a
; guest without the device keeps today's exits exactly.
;
; Why x2APIC only (Linux 6.6 arch/x86/kernel/apic/apic.c): APIC_BASE reads as
; already enabled in x2APIC mode (firmware-enabled, EXTD set), so
; check_x2apic() switches to the MSR interface at once. Under `noapic`,
; enable_IR_x2apic() returns before try_to_enable_x2apic(), so a kernel
; without interrupt remapping or a recognised hypervisor keeps x2APIC and
; never needs the xAPIC page at 0xFEE00000. The guest kernel must be built
; with CONFIG_X86_X2APIC=y; a kernel without it disables its APIC instead
; (and the 8259 path below still works).
;
;   registers  ID 0, version 0x14 with max LVT 5 (no CMCI), TPR, PPR, EOI, LDR,
;              SVR, ISR/TMR/IRR (8 x 32 bits), ESR, the six LVTs, ICR, timer
;              initial/current count, divide configuration, SELF IPI.
;              Reading a write-only register, writing a read-only one, setting
;              a reserved bit, or an unknown offset is #GP (SDM 11.12.1.2).
;   delivery   glapic_accept latches a fixed vector in IRR. Vectors 0-15 are
;              illegal: ESR bit 6 "received illegal vector" is set and nothing
;              is latched. glapic_pending returns the highest IRR vector whose
;              priority class is above PPR's while the APIC is software-enabled;
;              glapic_ack moves it to ISR at injection; an EOI write clears the
;              highest ISR bit.
;   timer      TSC-deadline mode fires once at the deadline. One-shot and
;              periodic modes count down at TSC >> (divide shift), the virtual
;              APIC bus clock. glapic_tick(TSC) raises the LVT timer vector
;              unless the LVT is masked.
;   ExtINT     glapic_extint_ok: the 8259 may still inject while the APIC is
;              software-disabled, or while LINT0 is unmasked ExtINT (virtual
;              wire mode).
;
; Every check runs before a write is applied, so a #GP changes nothing.
;
; T1-5 S7 (root 76858): one APIC per vCPU, GLAPIC_VCPU_MAX records side by
; side in glapic_state; record i has APIC ID i (LDR cluster 0, bit i) and
; only record 0 reads the BSP bit in APIC_BASE. The glv_* bodies take the
; record in R8 and preserve it; every glapic_* entry is the vCPU 0 record,
; so the one-vCPU callers are unchanged. glapic_set_vcpus selects how many
; records answer (1 after every reset).
;   IPIs      an ICR names a target set by shorthand, physical ID (0xFFFFFFFF
;             broadcast) or logical cluster 0 bits. Fixed delivery latches
;             a vector 16-255 in each target. INIT (assert) and START-UP act
;             only when vCPU 0 sends them, on targets other than vCPU 0.
;             Lowest priority, SMI, NMI and ExtINT are recorded and dropped.
;   cross     (SEC 76937 D3) a vCPU other than 0 writes another record only
;             by fixed delivery: one IRR bit (lock bts) and GL_KICK (lock or).
;             vCPU 0 also writes GL_RUN atomically (INIT/START-UP). The
;             target's own CPU applies INIT (glv_take_startup) and clears the
;             kick (glv_take_kick). A vCPU other than 0 resets into wait-for-SIPI.

GLAPIC_VERSION   equ 0x00050014        ; version 0x14, max LVT entry 5
GLAPIC_SVR_EN    equ 0x100
GLAPIC_LVT_MASK  equ 0x10000
GLAPIC_ESR_RX_ILLEGAL equ 0x40
GLAPIC_ESR_TX_ILLEGAL equ 0x20
GLAPIC_TM_ONESHOT  equ 0
GLAPIC_TM_PERIODIC equ 1
GLAPIC_TM_DEADLINE equ 2
GLAPIC_MSR_TSC_DEADLINE equ 0x6E0
GLAPIC_ICR_RSVD  equ 0x00000000FFF33000 ; x2APIC ICR bits 12, 13, 16, 17, 20-31
GLAPIC_APIC_BASE equ 0xFEE00D00        ; 0xFEE00000 | EN (bit 11) | EXTD (bit 10) | BSP (bit 8)
GLAPIC_MSR_NONE  equ 0                 ; not an APIC MSR, or no guest APIC: the caller's rules apply
GLAPIC_MSR_DONE  equ 1                 ; handled (a read's value is in glapic_msr_value)
GLAPIC_MSR_GP    equ 2                 ; the instruction takes #GP(0)
GLAPIC_APIC_BASE_AP equ 0xFEE00C00     ; the same without BSP (bit 8): every vCPU but 0
GLAPIC_VCPU_MAX  equ 2
GLAPIC_RUN_RUNNING equ 0               ; GL_RUN low byte; bits 8-15 hold a START-UP vector
GLAPIC_RUN_WAIT  equ 1                 ; wait-for-SIPI
GLAPIC_RUN_SIPI  equ 2                 ; START-UP received: run at vector << 12
GLAPIC_RUN_INIT  equ 3                 ; INIT received, not yet applied by the vCPU's CPU
GLAPIC_RUN_INIT_SIPI equ 4             ; INIT, then START-UP, neither applied yet
GLAPIC_STARTUP_NONE equ 0              ; glv_take_startup results
GLAPIC_STARTUP_WAIT equ 1
GLAPIC_STARTUP_GO equ 2
GLAPIC_MP_GPA    equ 0x9FC00           ; the top 1 KiB of base RAM that Linux scans; the guest e820 ends here
GLAPIC_MP_LAPIC  equ 0xFEE00000        ; must be non-zero; an x2APIC guest never maps it
GLAPIC_MP_HDR    equ 16                ; the floating pointer; the configuration table follows it
GLAPIC_MP_TABLE  equ 44                ; configuration table header
GLAPIC_MP_CPU    equ 20                ; one processor entry
GLAPIC_MP_BUS    equ 8                 ; one bus entry
GLAPIC_MP_BYTES  equ GLAPIC_MP_HDR + GLAPIC_MP_TABLE + GLAPIC_MP_CPU * GLAPIC_VCPU_MAX + GLAPIC_MP_BUS

; State record (glapic_state), all little-endian.
GL_TPR      equ 0      ; u32
GL_SVR      equ 4      ; u32
GL_ESR      equ 8      ; u32 latched errors (what ESR reads)
GL_ESR_PEND equ 12     ; u32 errors since the last ESR write
GL_LVT      equ 16     ; 6 x u32: timer, thermal, perf, LINT0, LINT1, error
GL_DCR      equ 40     ; u32 divide configuration
GL_INIT     equ 44     ; u32 timer initial count
GL_ICR      equ 48     ; u64
GL_ISR      equ 56     ; 8 x u32
GL_IRR      equ 88     ; 8 x u32
GL_DEADLINE equ 120    ; u64 IA32_TSC_DEADLINE (0 = disarmed)
GL_T0       equ 128    ; u64 TSC at the start of the current count
GL_ARMED    equ 136    ; u32 a one-shot/periodic count is running
GL_ID       equ 144    ; u32 APIC ID (the record's index); a reset keeps it
GL_RUN      equ 148    ; u32 GLAPIC_RUN_* | vector << 8, written atomically; a reset keeps it
GL_KICK     equ 152    ; u32 another vCPU latched work here; a reset keeps it
GL_RSVD     equ 156    ; u32 = 0
GL_BYTES    equ 160

; glv_reset_one(R8 = record): power-on state (SDM 11.4.7.1): LVTs masked,
; SVR 0xFF, the rest 0. GL_ID, GL_RUN and GL_KICK are kept. RAX/RCX/RDI only.
glv_reset_one:
    mov  rdi, r8
    xor  eax, eax
    mov  ecx, GL_ID / 8
    rep  stosq
    mov  dword [r8 + GL_SVR], 0xFF
    mov  eax, GLAPIC_LVT_MASK
    mov  [r8 + GL_LVT + 0], eax
    mov  [r8 + GL_LVT + 4], eax
    mov  [r8 + GL_LVT + 8], eax
    mov  [r8 + GL_LVT + 12], eax
    mov  [r8 + GL_LVT + 16], eax
    mov  [r8 + GL_LVT + 20], eax
    ret

; glapic_reset: every record to power-on state; vCPU 0 running, the others in
; wait-for-SIPI; one vCPU answers. RAX/RCX/RDI only.
glapic_reset:
    ; S7: backend/profile/topology stays frozen through full retirement.
    cmp  qword [rel vca_ready], 0
    jne  vcb_fail_stop
    push r8
    lea  r8, [rel glapic_state]
    xor  ecx, ecx
.one:
    push rcx
    call glv_reset_one
    pop  rcx
    mov  [r8 + GL_ID], ecx
    xor  eax, eax
    test ecx, ecx
    setnz al                                ; GLAPIC_RUN_WAIT for every vCPU but 0
    mov  [r8 + GL_RUN], eax
    mov  qword [r8 + GL_KICK], 0            ; GL_KICK and GL_RSVD
    add  r8, GL_BYTES
    inc  ecx
    cmp  ecx, GLAPIC_VCPU_MAX
    jb   .one
    mov  dword [rel glapic_vcpus], 1
    pop  r8
    ret

; glapic_set_vcpus(EDI = vCPU count) -> EAX = 0, or 1 (outside 1..GLAPIC_VCPU_MAX: unchanged).
glapic_set_vcpus:
    ; S7: backend/profile/topology stays frozen through full retirement.
    cmp  qword [rel vca_ready], 0
    jne  vcb_fail_stop
    mov  eax, 1
    lea  ecx, [rdi - 1]
    cmp  ecx, GLAPIC_VCPU_MAX - 1
    ja   .out
    mov  [rel glapic_vcpus], edi
    xor  eax, eax
.out:
    ret

; glapic_instance(EDI = vCPU index) -> RAX = its record, or 0 when that vCPU does not answer.
glapic_instance:
    xor  eax, eax
    cmp  edi, [rel glapic_vcpus]
    jae  .out
    imul eax, edi, GL_BYTES
    lea  rcx, [rel glapic_state]
    add  rax, rcx
.out:
    ret

; glapic_mptable(RDI = host address of guest GPA GLAPIC_MP_GPA, ESI = vCPU count) -> EAX = bytes written
; (at most GLAPIC_MP_BYTES), or 0 for a count outside 1..GLAPIC_VCPU_MAX, with nothing written.
; T1-5 S7: the guest learns its vCPUs from an MPS 1.4 table (no ACPI). A floating pointer (spec 4, one
; paragraph, configuration table right after it) and a table with processor i = APIC ID i (the glapic
; record index), version GLAPIC_VERSION, enabled, processor 0 the boot CPU, then one ISA bus. No I/O APIC
; or interrupt entries: guests keep `noapic`, so LINT0 stays ExtINT on vCPU 0 only (Linux 6.6 apic.c:1636).
; Both checksums make their bytes sum to 0.
glapic_mptable:
    xor  eax, eax
    lea  ecx, [rsi - 1]
    cmp  ecx, GLAPIC_VCPU_MAX - 1
    ja   .refuse
    mov  r8, rdi
    imul ecx, esi, GLAPIC_MP_CPU
    add  ecx, GLAPIC_MP_HDR + GLAPIC_MP_TABLE + GLAPIC_MP_BUS
    rep  stosb                              ; every reserved and feature byte is 0, and nothing past the table
    mov  dword [r8], '_MP_'
    mov  dword [r8 + 4], GLAPIC_MP_GPA + GLAPIC_MP_HDR
    mov  byte [r8 + 8], 1                   ; length in paragraphs
    mov  byte [r8 + 9], 4                   ; MPS 1.4; feature1 0 = the table is present
    lea  rdi, [r8 + GLAPIC_MP_HDR]
    mov  dword [rdi], 'PCMP'
    imul eax, esi, GLAPIC_MP_CPU
    add  eax, GLAPIC_MP_TABLE + GLAPIC_MP_BUS
    mov  [rdi + 4], ax                      ; base table length
    mov  byte [rdi + 6], 4
    mov  rdx, 'PAOS    '
    mov  [rdi + 8], rdx                     ; OEM ID
    mov  rdx, 'PAOS VCP'
    mov  [rdi + 16], rdx                    ; product ID
    mov  dword [rdi + 24], 'U   '
    lea  edx, [rsi + 1]
    mov  [rdi + 34], dx                     ; entry count: the processors and the bus
    mov  dword [rdi + 36], GLAPIC_MP_LAPIC
    lea  rcx, [rdi + GLAPIC_MP_TABLE]
    xor  edx, edx
.cpu:
    mov  [rcx + 1], dl                      ; APIC ID (type 0, processor, from the clear)
    mov  byte [rcx + 2], GLAPIC_VERSION & 0xFF
    xor  eax, eax
    test edx, edx
    setz al
    lea  eax, [rax*2 + 1]                   ; enabled; the boot CPU for vCPU 0
    mov  [rcx + 3], al
    add  rcx, GLAPIC_MP_CPU
    inc  edx
    cmp  edx, esi
    jb   .cpu
    mov  byte [rcx], 1                      ; bus 0
    mov  dword [rcx + 2], 'ISA '
    mov  word [rcx + 6], '  '
    movzx ecx, word [rdi + 4]
    xor  eax, eax
.sum_table:
    sub  al, [rdi + rcx - 1]
    dec  ecx
    jnz  .sum_table
    mov  [rdi + 7], al
    mov  ecx, GLAPIC_MP_HDR
    xor  eax, eax
.sum_hdr:
    sub  al, [r8 + rcx - 1]
    dec  ecx
    jnz  .sum_hdr
    mov  [r8 + 10], al
    movzx eax, word [rdi + 4]
    add  eax, GLAPIC_MP_HDR
.refuse:
    ret

; glapic_highest(RSI = 8 x u32 vector bitmap) -> EAX = highest set vector, or 0.
; Vector 0 is never latched (accept refuses 0-15), so 0 means "none".
glapic_highest:
    mov  ecx, 7
.word:
    mov  eax, [rsi + rcx*4]
    test eax, eax
    jnz  .found
    dec  ecx
    jns  .word
    xor  eax, eax
    ret
.found:
    bsr  eax, eax
    shl  ecx, 5
    add  eax, ecx
    ret

; glapic_ppr(R8) -> EAX = processor priority (SDM 11.8.3.1) from TPR and the highest ISR.
glapic_ppr:
    lea  rsi, [r8 + GL_ISR]
    call glapic_highest
    mov  ecx, eax
    and  ecx, 0xF0                          ; ISRV class (0 when ISR is empty)
    mov  eax, [r8 + GL_TPR]
    mov  edx, eax
    and  edx, 0xF0
    cmp  edx, ecx
    jae  .tpr
    mov  eax, ecx
.tpr:
    ret

; glv_accept(R8 = record, EDI = vector): latch a fixed-mode interrupt in IRR.
; -> EAX = 1 latched, 0 refused (an illegal vector; ESR records it).
glv_accept:
    and  edi, 0xFF
    cmp  edi, 16
    jae  .legal
    lock or dword [r8 + GL_ESR_PEND], GLAPIC_ESR_RX_ILLEGAL
    xor  eax, eax
    ret
.legal:
    lea  rsi, [r8 + GL_IRR]
    lock bts [rsi], edi
    mov  eax, 1
    ret

; glv_pending(R8) -> EAX = the vector to inject now, or -1.
glv_pending:
    test dword [r8 + GL_SVR], GLAPIC_SVR_EN
    jz   .none
    lea  rsi, [r8 + GL_IRR]
    call glapic_highest
    test eax, eax
    jz   .none
    push rax
    call glapic_ppr
    mov  edx, eax
    pop  rax
    mov  ecx, eax
    and  ecx, 0xF0
    and  edx, 0xF0
    cmp  ecx, edx
    jbe  .none                              ; its class does not exceed PPR's
    ret
.none:
    mov  eax, -1
    ret

; glv_ack(R8, EDI = vector): the vector was injected: IRR -> ISR.
glv_ack:
    and  edi, 0xFF
    lea  rsi, [r8 + GL_IRR]
    lock btr [rsi], edi
    lea  rsi, [r8 + GL_ISR]
    bts  [rsi], edi
    ret

; glv_extint_ok(R8) -> EAX = 1 when the 8259 may inject (APIC software-disabled,
; or LINT0 unmasked with delivery mode ExtINT), else 0.
glv_extint_ok:
    mov  eax, 1
    test dword [r8 + GL_SVR], GLAPIC_SVR_EN
    jz   .out
    mov  edx, [r8 + GL_LVT + 12]
    xor  eax, eax
    test edx, GLAPIC_LVT_MASK
    jnz  .out
    and  edx, 0x700
    cmp  edx, 0x700
    sete al
.out:
    ret

; glapic_pic_blocked -> EAX = 1 when a selected LAPIC keeps the 8259 output
; from the CPU (not glapic_extint_ok); 0 without one, the old direct wire.
; EAX/EDX only.
glapic_pic_blocked:
    xor  eax, eax
    cmp  byte [rel glapic_on], 1
    jne  .out
    call glapic_extint_ok
    xor  eax, 1
.out:
    ret

; glapic_shift(R8) -> ECX = divide shift from DCR bits 0, 1 and 3 (SDM 11.5.4):
; 000b divides by 2 ... 110b by 128, 111b by 1.
glapic_shift:
    mov  eax, [r8 + GL_DCR]
    mov  ecx, eax
    and  ecx, 3
    shr  eax, 1
    and  eax, 4
    or   ecx, eax
    inc  ecx
    and  ecx, 7
    ret

; glapic_mode(R8) -> EAX = timer mode (LVT timer bits 17-18).
glapic_mode:
    mov  eax, [r8 + GL_LVT]
    shr  eax, 17
    and  eax, 3
    ret

; glapic_elapsed(R8, RDI = TSC) -> RAX = bus ticks since T0 (0 if TSC is before T0).
glapic_elapsed:
    call glapic_shift
    mov  rax, rdi
    sub  rax, [r8 + GL_T0]
    jae  .shift
    xor  eax, eax
.shift:
    shr  rax, cl
    ret

; glapic_current(R8, RDI = TSC) -> EAX = timer current count.
glapic_current:
    cmp  dword [r8 + GL_ARMED], 0
    je   .zero
    call glapic_elapsed
    mov  ecx, [r8 + GL_INIT]
    cmp  rax, rcx
    jb   .left
    call glapic_mode
    cmp  eax, GLAPIC_TM_PERIODIC
    jne  .zero
    call glapic_elapsed                     ; periodic: what remains of this period
    mov  ecx, [r8 + GL_INIT]
    xor  edx, edx
    div  rcx
    mov  rax, rdx
.left:
    sub  ecx, eax
    mov  eax, ecx
    ret
.zero:
    xor  eax, eax
    ret

; glv_tick(R8, RDI = TSC) -> EAX = 1 when the timer fired now (its vector latched,
; or dropped by the LVT mask), else 0. Called before each injection decision.
glv_tick:
    push rbx
    mov  rbx, rdi
    call glapic_mode
    cmp  eax, GLAPIC_TM_DEADLINE
    jne  .count
    mov  rax, [r8 + GL_DEADLINE]
    test rax, rax
    jz   .idle
    cmp  rbx, rax
    jb   .idle
    mov  qword [r8 + GL_DEADLINE], 0
    jmp  .fire
.count:
    cmp  dword [r8 + GL_ARMED], 0
    je   .idle
    mov  rdi, rbx
    call glapic_elapsed
    mov  ecx, [r8 + GL_INIT]
    cmp  rax, rcx
    jb   .idle
    call glapic_mode
    cmp  eax, GLAPIC_TM_PERIODIC
    je   .reload
    mov  dword [r8 + GL_ARMED], 0
    jmp  .fire
.reload:
    ; Skip every whole period already past: T0 += floor(elapsed / init) * init << shift.
    mov  rdi, rbx
    call glapic_elapsed
    mov  ecx, [r8 + GL_INIT]
    xor  edx, edx
    div  rcx
    imul rax, rcx
    push rax
    call glapic_shift
    pop  rax
    shl  rax, cl
    add  [r8 + GL_T0], rax
.fire:
    mov  edi, [r8 + GL_LVT]
    test edi, GLAPIC_LVT_MASK
    jnz  .fired
    call glv_accept
.fired:
    mov  eax, 1
    pop  rbx
    ret
.idle:
    xor  eax, eax
    pop  rbx
    ret

; glv_rdmsr(R8, EDI = MSR, RSI = TSC) -> RAX = value and EDX = 0, or EDX = 1 (#GP).
glv_rdmsr:
    cmp  edi, GLAPIC_MSR_TSC_DEADLINE
    jne  .x2
    call glapic_mode
    cmp  eax, GLAPIC_TM_DEADLINE
    jne  .zero                              ; reads 0 outside TSC-deadline mode
    mov  rax, [r8 + GL_DEADLINE]
    jmp  .ok
.x2:
    mov  eax, edi
    sub  eax, 0x800
    cmp  eax, 0xFF
    ja   .gp
    mov  rcx, r8
    cmp  eax, 0x02
    je   .id
    cmp  eax, 0x03
    je   .version
    cmp  eax, 0x08
    je   .tpr
    cmp  eax, 0x0A
    je   .ppr
    cmp  eax, 0x0D
    je   .ldr
    cmp  eax, 0x0F
    je   .svr
    cmp  eax, 0x10
    jb   .gp
    cmp  eax, 0x17
    jbe  .isr
    cmp  eax, 0x1F
    jbe  .zero                              ; TMR: edge delivery only
    cmp  eax, 0x27
    jbe  .irr
    cmp  eax, 0x28
    je   .esr
    cmp  eax, 0x30
    je   .icr
    cmp  eax, 0x32
    jb   .gp
    cmp  eax, 0x37
    jbe  .lvt
    cmp  eax, 0x38
    je   .init
    cmp  eax, 0x39
    je   .cur
    cmp  eax, 0x3E
    je   .dcr
    jmp  .gp                                ; EOI 0x80B and SELF IPI 0x83F are write-only
.version:
    mov  eax, GLAPIC_VERSION
    jmp  .ok
.tpr:
    mov  eax, [rcx + GL_TPR]
    jmp  .ok
.ppr:
    call glapic_ppr
    jmp  .ok
.id:
    mov  eax, [rcx + GL_ID]
    jmp  .ok
.ldr:
    mov  ecx, [rcx + GL_ID]                 ; cluster ID >> 4 (0 here), bit (ID & 15)
    mov  eax, 1
    shl  eax, cl
    jmp  .ok
.svr:
    mov  eax, [rcx + GL_SVR]
    jmp  .ok
.isr:
    mov  eax, [rcx + GL_ISR + rax*4 - 0x10*4]
    jmp  .ok
.irr:
    mov  eax, [rcx + GL_IRR + rax*4 - 0x20*4]
    jmp  .ok
.esr:
    mov  eax, [rcx + GL_ESR]
    jmp  .ok
.icr:
    mov  rax, [rcx + GL_ICR]
    jmp  .ok
.lvt:
    mov  eax, [rcx + GL_LVT + rax*4 - 0x32*4]
    jmp  .ok
.init:
    mov  eax, [rcx + GL_INIT]
    jmp  .ok
.cur:
    mov  rdi, rsi
    call glapic_current
    jmp  .ok
.dcr:
    mov  eax, [rcx + GL_DCR]
    jmp  .ok
.zero:
    xor  eax, eax
.ok:
    xor  edx, edx
    ret
.gp:
    xor  eax, eax
    mov  edx, 1
    ret

; glv_wrmsr(R8, EDI = MSR, RSI = value, RDX = TSC) -> EAX = 0, or 1 (#GP: nothing changed).
glv_wrmsr:
    push rbx
    push r12
    push r9
    push r10
    push r11
    mov  rbx, rsi
    mov  r12, rdx
    mov  rcx, r8
    cmp  edi, GLAPIC_MSR_TSC_DEADLINE
    jne  .x2
    call glapic_mode
    cmp  eax, GLAPIC_TM_DEADLINE
    jne  .ok                                ; ignored outside TSC-deadline mode
    mov  [r8 + GL_DEADLINE], rbx
    jmp  .ok
.x2:
    mov  eax, edi
    sub  eax, 0x800
    cmp  eax, 0xFF
    ja   .gp
    cmp  eax, 0x30
    je   .icr                               ; the only 64-bit register
    mov  rdx, rbx
    shr  rdx, 32
    jnz  .gp                                ; every other register is 32 bits wide
    cmp  eax, 0x08
    je   .tpr
    cmp  eax, 0x0B
    je   .eoi
    cmp  eax, 0x0F
    je   .svr
    cmp  eax, 0x28
    je   .esr
    cmp  eax, 0x32
    je   .lvt_timer
    cmp  eax, 0x33
    jb   .gp
    cmp  eax, 0x37
    jbe  .lvt
    cmp  eax, 0x38
    je   .init
    cmp  eax, 0x3E
    je   .dcr
    cmp  eax, 0x3F
    je   .self
    jmp  .gp                                ; ID, version, PPR, LDR, ISR/TMR/IRR, current count: read-only
.tpr:
    test ebx, ~0xFF
    jnz  .gp
    mov  [rcx + GL_TPR], ebx
    jmp  .ok
.eoi:
    test ebx, ebx
    jnz  .gp                                ; x2APIC: a non-zero EOI write is #GP
    lea  rsi, [rcx + GL_ISR]
    call glapic_highest
    test eax, eax
    jz   .ok
    lea  rsi, [r8 + GL_ISR]
    btr  [rsi], eax
    jmp  .ok
.svr:
    test ebx, ~0x3FF                        ; vector, enable, focus (no effect); no EOI-broadcast suppression
    jnz  .gp
    mov  [rcx + GL_SVR], ebx
    test ebx, GLAPIC_SVR_EN
    jnz  .ok
    ; a software disable masks every LVT (SDM 11.4.7.2)
    or   dword [rcx + GL_LVT + 0], GLAPIC_LVT_MASK
    or   dword [rcx + GL_LVT + 4], GLAPIC_LVT_MASK
    or   dword [rcx + GL_LVT + 8], GLAPIC_LVT_MASK
    or   dword [rcx + GL_LVT + 12], GLAPIC_LVT_MASK
    or   dword [rcx + GL_LVT + 16], GLAPIC_LVT_MASK
    or   dword [rcx + GL_LVT + 20], GLAPIC_LVT_MASK
    jmp  .ok
.esr:
    test ebx, ebx
    jnz  .gp                                ; x2APIC: ESR is written with 0 only
    mov  eax, [rcx + GL_ESR_PEND]
    mov  [rcx + GL_ESR], eax
    mov  dword [rcx + GL_ESR_PEND], 0
    jmp  .ok
.lvt_timer:
    test ebx, ~0x700FF                      ; vector, mask, mode (bits 17-18)
    jnz  .gp
    mov  eax, ebx
    shr  eax, 17
    and  eax, 3
    cmp  eax, 3
    je   .gp                                ; reserved timer mode
    test dword [rcx + GL_SVR], GLAPIC_SVR_EN
    jnz  .lvt_timer_set
    or   ebx, GLAPIC_LVT_MASK               ; cannot unmask while software-disabled
.lvt_timer_set:
    mov  edx, [rcx + GL_LVT]
    mov  [rcx + GL_LVT], ebx
    xor  edx, ebx
    test edx, 0x60000
    jz   .ok
    mov  dword [rcx + GL_ARMED], 0          ; a mode change disarms both timers
    mov  qword [rcx + GL_DEADLINE], 0
    jmp  .ok
.lvt:
    ; thermal 0x833, perf 0x834, LINT0 0x835, LINT1 0x836, error 0x837
    mov  edx, ~0x107FF                      ; vector, delivery mode, mask
    cmp  eax, 0x35
    jb   .lvt_check
    cmp  eax, 0x36
    ja   .lvt_err
    mov  edx, ~0x1A7FF                      ; LINTn also: polarity, trigger mode
    jmp  .lvt_check
.lvt_err:
    mov  edx, ~0x100FF                      ; error: vector and mask only
.lvt_check:
    test ebx, edx
    jnz  .gp
    test dword [rcx + GL_SVR], GLAPIC_SVR_EN
    jnz  .lvt_set
    or   ebx, GLAPIC_LVT_MASK
.lvt_set:
    mov  [rcx + GL_LVT + rax*4 - 0x32*4], ebx
    jmp  .ok
.init:
    call glapic_mode
    mov  rcx, r8
    cmp  eax, GLAPIC_TM_DEADLINE
    je   .ok                                ; ignored in TSC-deadline mode
    mov  [rcx + GL_INIT], ebx
    mov  [rcx + GL_T0], r12
    xor  eax, eax
    test ebx, ebx
    setnz al                                ; 0 stops the timer
    mov  [rcx + GL_ARMED], eax
    jmp  .ok
.dcr:
    test ebx, ~0xB
    jnz  .gp
    mov  [rcx + GL_DCR], ebx
    jmp  .ok
.self:
    test ebx, ~0xFF
    jnz  .gp
    mov  edi, ebx
    call glv_accept
    jmp  .ok
.icr:
    mov  rdx, GLAPIC_ICR_RSVD
    test rbx, rdx
    jnz  .gp
    mov  [rcx + GL_ICR], rbx
    call glv_icr_targets
    mov  r9d, eax                           ; target records, bit i = vCPU i
    mov  edx, ebx
    shr  edx, 8
    and  edx, 7
    jz   .icr_fixed
    cmp  edx, 5
    je   .icr_init
    cmp  edx, 6
    je   .icr_sipi
    jmp  .ok                                ; lowest priority, SMI, NMI, reserved, ExtINT: recorded and dropped
.icr_fixed:
    movzx r12d, bl                          ; vector
    xor  r10d, r10d
.icr_fixed_next:
    bt   r9d, r10d
    jnc  .icr_fixed_skip
    imul r11d, r10d, GL_BYTES
    lea  rax, [rel glapic_state]
    add  r11, rax
    cmp  r12d, 16
    jae  .icr_fixed_send
    lock or dword [r8 + GL_ESR_PEND], GLAPIC_ESR_TX_ILLEGAL
    cmp  r11, r8
    jne  .icr_fixed_skip                    ; an illegal vector is not sent to another APIC
.icr_fixed_send:
    push r8
    mov  r8, r11
    mov  edi, r12d
    call glv_accept
    pop  r8
    mov  edi, [r8 + GL_ID]
    mov  esi, r10d
    call vob_ipi
    cmp  r11, r8
    je   .icr_fixed_skip
    lock or dword [r11 + GL_KICK], 1
.icr_fixed_skip:
    inc  r10d
    cmp  r10d, GLAPIC_VCPU_MAX
    jb   .icr_fixed_next
    jmp  .ok
.icr_init:
    cmp  dword [r8 + GL_ID], 0
    jne  .ok                                ; only vCPU 0 sends INIT or START-UP
    test ebx, 0x4000
    jz   .ok                                ; INIT level de-assert: no effect
    mov  r12d, GLAPIC_RUN_INIT
    jmp  .icr_ap
.icr_sipi:
    cmp  dword [r8 + GL_ID], 0
    jne  .ok                                ; only vCPU 0 sends INIT or START-UP
    movzx r12d, bl
    shl  r12d, 8
    or   r12d, GLAPIC_RUN_SIPI
.icr_ap:
    xor  r10d, r10d
.icr_ap_next:
    bt   r9d, r10d
    jnc  .icr_ap_skip
    test r10d, r10d
    jz   .icr_ap_skip                       ; vCPU 0 (the sender) is never re-initialised
    imul r11d, r10d, GL_BYTES
    lea  rax, [rel glapic_state]
    add  r11, rax
    cmp  r12d, GLAPIC_RUN_INIT
    jne  .icr_ap_sipi
    mov  eax, r12d
    xchg [r11 + GL_RUN], eax                ; INIT cancels any START-UP not yet applied
    jmp  .icr_ap_kick
.icr_ap_sipi:
    ; START-UP only in wait-for-SIPI (SDM 10.4.7.3), or after an INIT still pending.
    ; The pending INIT first: the target's CPU may move INIT to WAIT at any time, but
    ; nothing leaves WAIT except a START-UP, so the second compare cannot miss.
    mov  eax, GLAPIC_RUN_INIT
    mov  edx, r12d
    add  edx, GLAPIC_RUN_INIT_SIPI - GLAPIC_RUN_SIPI
    lock cmpxchg [r11 + GL_RUN], edx
    je   .icr_ap_kick
    mov  eax, GLAPIC_RUN_WAIT
    mov  edx, r12d
    lock cmpxchg [r11 + GL_RUN], edx
    jne  .icr_ap_skip
.icr_ap_kick:
    mov  edi, [r8 + GL_ID]
    mov  esi, r10d
    call vob_ipi
    lock or dword [r11 + GL_KICK], 1
.icr_ap_skip:
    inc  r10d
    cmp  r10d, GLAPIC_VCPU_MAX
    jb   .icr_ap_next
.ok:
    xor  eax, eax
    jmp  .out
.gp:
    mov  eax, 1
.out:
    pop  r11
    pop  r10
    pop  r9
    pop  r12
    pop  rbx
    ret

; glapic_start(EDI = non-zero when the profile selects the guest LAPIC): every
; START resets the state; the exits see the APIC only when it is selected.
glapic_start:
    push rdi
    call glapic_reset
    pop  rdi
    test edi, edi
    setnz byte [rel glapic_on]
    ret

; glv_msr(R8, EDI = MSR, RSI = WRMSR value, EDX = 1 for WRMSR / 0 for RDMSR,
; RCX = guest TSC) -> EAX = GLAPIC_MSR_*, RDX = a read's value (0 after a
; refused read; undefined after a write).
glv_msr:
    xor  eax, eax
    cmp  byte [rel glapic_on], 1
    jne  .out
    cmp  edi, 0x1B
    je   .base
    cmp  edi, GLAPIC_MSR_TSC_DEADLINE
    je   .mine
    mov  eax, edi
    sub  eax, 0x800
    cmp  eax, 0xFF
    mov  eax, GLAPIC_MSR_NONE
    ja   .out
.mine:
    test edx, edx
    jnz  .write
    mov  rsi, rcx
    call glv_rdmsr
    xchg rax, rdx                           ; RDX = the value, EAX = #GP
    jmp  .status
.write:
    mov  rdx, rcx
    call glv_wrmsr
.status:
    test eax, eax
    mov  eax, GLAPIC_MSR_DONE
    jz   .out
    mov  eax, GLAPIC_MSR_GP
.out:
    ret
.base:
    ; IA32_APIC_BASE: fixed at 0xFEE00000, enabled, x2APIC, BSP on vCPU 0 only.
    ; Moving it, disabling it or leaving x2APIC mode is #GP; rewriting the
    ; value is a no-op.
    mov  eax, GLAPIC_APIC_BASE              ; zero-extended: never an imm32 compare (bit 31 set)
    cmp  dword [r8 + GL_ID], 0
    je   .base_id
    mov  eax, GLAPIC_APIC_BASE_AP
.base_id:
    test edx, edx
    jnz  .base_write
    mov  rdx, rax
    mov  eax, GLAPIC_MSR_DONE
    ret
.base_write:
    cmp  rsi, rax
    mov  eax, GLAPIC_MSR_DONE
    je   .base_out
    mov  eax, GLAPIC_MSR_GP
.base_out:
    ret

; glapic_msr: glv_msr on vCPU 0; a read (DONE or #GP) leaves its value in glapic_msr_value.
glapic_msr:
    push r8
    push rdx
    lea  r8, [rel glapic_state]
    call glv_msr
    pop  r8                                 ; the WRMSR flag
    test r8d, r8d
    jnz  .out
    cmp  eax, GLAPIC_MSR_NONE
    je   .out
    mov  [rel glapic_msr_value], rdx
.out:
    pop  r8
    ret

; glv_cpuid(R8, EDI = leaf, ESI = subleaf, EAX/EBX/ECX/EDX = the values so far)
; -> the values the guest sees. Only EAX-EDX change.
glv_cpuid:
    cmp  byte [rel glapic_on], 1
    jne  .out
    cmp  edi, 1
    jne  .topo
    or   ecx, (1 << 21) | (1 << 24)         ; x2APIC, TSC-deadline timer
    or   edx, 1 << 9                        ; on-chip APIC
    and  ebx, 0x00FFFFFF
    push rax
    mov  eax, [r8 + GL_ID]
    shl  eax, 24
    or   ebx, eax                           ; initial APIC ID
    pop  rax
    ret
.topo:
    cmp  edi, 0xB
    je   .id
    cmp  edi, 0x1F
    je   .id
    cmp  edi, 0x8000001E
    jne  .out
    mov  eax, [r8 + GL_ID]                  ; AMD extended APIC ID
    ret
.id:
    mov  edx, [r8 + GL_ID]                  ; x2APIC ID
.out:
    ret

; glv_inject_pick(R8, RDI = guest TSC, ESI = HV_INJ_BLOCK_* flags of this entry)
; -> EAX = the vector to inject now (moved IRR -> ISR), or -1. The timer is
; advanced first; a blocked entry (IF = 0, a shadow, a queued event) leaves
; the vector in IRR for a later entry.
glv_inject_pick:
    mov  eax, -1
    cmp  byte [rel glapic_on], 1
    jne  .out
    push rbx
    mov  ebx, esi
    call glv_tick
    call glv_pending
    cmp  eax, -1
    je   .done
    test ebx, ebx
    jnz  .blocked
    push rax
    mov  edi, eax
    call glv_ack
    pop  rax
    jmp  .done
.blocked:
    mov  eax, -1
.done:
    pop  rbx
.out:
    ret

; glv_icr_targets(R8 = sender, RBX = ICR) -> EAX = target records (bit i =
; vCPU i), among the vCPUs that answer. EAX/ECX/EDX only.
glv_icr_targets:
    mov  ecx, [rel glapic_vcpus]
    mov  eax, 1
    shl  eax, cl
    dec  eax                                ; every answering vCPU
    mov  edx, ebx
    shr  edx, 18
    and  edx, 3
    jz   .dest
    cmp  edx, 2
    je   .out                               ; all including self
    mov  ecx, [r8 + GL_ID]
    cmp  edx, 1
    je   .self
    btr  eax, ecx                           ; all excluding self
    ret
.self:
    mov  eax, 1
    shl  eax, cl
    ret
.dest:
    mov  rdx, rbx
    shr  rdx, 32
    cmp  edx, -1
    je   .out                               ; broadcast, physical or logical
    test ebx, 0x800
    jnz  .logical
    cmp  edx, [rel glapic_vcpus]
    jae  .none
    mov  ecx, edx
    mov  eax, 1
    shl  eax, cl
    ret
.logical:
    test edx, 0xFFFF0000
    jnz  .none                              ; every vCPU is in cluster 0
    and  eax, edx
    ret
.none:
    xor  eax, eax
.out:
    ret

; glv_take_startup(R8) -> EAX = GLAPIC_STARTUP_NONE (running), _WAIT (in
; wait-for-SIPI) or _GO with EDX = the START-UP vector (now running). A pending
; INIT resets the record first. Only the vCPU's own CPU calls this.
glv_take_startup:
.again:
    mov  eax, [r8 + GL_RUN]
    movzx edx, al
    cmp  edx, GLAPIC_RUN_WAIT
    je   .wait
    cmp  edx, GLAPIC_RUN_SIPI
    je   .go
    cmp  edx, GLAPIC_RUN_INIT
    je   .init
    cmp  edx, GLAPIC_RUN_INIT_SIPI
    je   .init
    mov  eax, GLAPIC_STARTUP_NONE
    ret
.init:
    push rax
    push rcx
    push rdi
    call glv_reset_one
    pop  rdi
    pop  rcx
    pop  rax
    movzx edx, al
    cmp  edx, GLAPIC_RUN_INIT
    jne  .go
    mov  edx, GLAPIC_RUN_WAIT
    lock cmpxchg [r8 + GL_RUN], edx
    jne  .again                             ; a START-UP arrived meanwhile
.wait:
    mov  eax, GLAPIC_STARTUP_WAIT
    ret
.go:
    xor  edx, edx                           ; GLAPIC_RUN_RUNNING
    push rax
    lock cmpxchg [r8 + GL_RUN], edx
    pop  rdx
    jne  .again
    shr  edx, 8
    movzx edx, dl
    mov  eax, GLAPIC_STARTUP_GO
    ret

; Snapshot only on the single selected-vCPU executor's both-root path. It
; distinguishes INIT (which resets private CPU state) from an existing WAIT.
; Startup consumption still uses the existing atomic transition routine.
glv_startup_state:
    movzx eax, byte [r8 + GL_RUN]
    ret

; glv_take_kick(R8) -> EAX = 1 when another vCPU latched work here since the
; last call, else 0.
glv_take_kick:
    xor  eax, eax
    xchg [r8 + GL_KICK], eax
    ret

; vCPU 0 entries: the record is glapic_state; R8 is preserved.
%macro GLAPIC_VCPU0 1
glapic_%1:
    push r8
    lea  r8, [rel glapic_state]
    call glv_%1
    pop  r8
    ret
%endmacro
GLAPIC_VCPU0 accept
GLAPIC_VCPU0 pending
GLAPIC_VCPU0 ack
GLAPIC_VCPU0 extint_ok
GLAPIC_VCPU0 tick
GLAPIC_VCPU0 rdmsr
GLAPIC_VCPU0 wrmsr
GLAPIC_VCPU0 cpuid
GLAPIC_VCPU0 inject_pick

%macro WDATA_hv_guest_lapic 0
align 8
glapic_state: resb GL_BYTES * GLAPIC_VCPU_MAX
glapic_msr_value: resq 1
glapic_vcpus: resd 1
glapic_on: resb 1
%endmacro
WDATA_BSS_DEFER WDATA_hv_guest_lapic
