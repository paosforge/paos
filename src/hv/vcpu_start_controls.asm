;; MODULE hv/vcpu_start_controls
;; LAYER 5
;; EXPORTS vst_controls_build, vst_caps_capture
;; IMPORTS hv/vcpu_ap_run
;; CAPS
;; OWNER saga:hv
; Creator: Codex / rc-vm-claude. Pure START control construction, no MSR/VMCS
; access. RDI output10q (BSP5 then AP5), RSI BSP5q capabilities, RDX AP5q.
; Each input contains pin/primary/secondary/exit/entry MSRs, low32 must-one,
; high32 allowed-one, sampled on that core using its own selected true bank.
; Output must be disjoint from both inputs; inputs may alias each other.
; Both cores accept each common candidate, including the two mode variants.
; Unsupported semantics never enter via mandatory-bit folding. Legacy fixed
; reserved bits follow Intel SDM Vol3C 25.6/25.7/25.8 (326019-078US).
; Return1 complete/0 refuse. No partial output, READY or policy publication.

; Selected core, live guarded custody: capture THIS core's capability
; MSRs using its own true-control bank. No output before all reads complete.
; CPUID gates VMX MSRs; primary allowed-secondary gates the secondary MSR.
; MISC[5] is required for saved LMA and hardware ENTRY bit9 updates (SEC E3).
; RDI mapped output72: five control MSRs, then CR0_FIXED0/FIXED1 and
; CR4_FIXED0/FIXED1. Return1/0. Never capture one core on another's behalf.
vst_caps_capture:
    cmp  qword [rel vca_ready], 0
    jne  vst_frozen_refuse
    push rbx
    push r12
    push r13
    sub  rsp, 80
    mov  r12, rdi
    test r12, r12
    jz   .bad
    xor  eax, eax
    cpuid
    cmp  ebx, 0x756E6547
    jne  .bad
    cmp  edx, 0x49656E69
    jne  .bad
    cmp  ecx, 0x6C65746E
    jne  .bad
    mov  eax, 1
    cpuid
    bt   ecx, 5
    jnc  .bad
    mov  ecx, 0x480
    rdmsr
    xor  r13d, r13d
    bt   edx, 23
    jnc  .legacy
    mov  r13d, 4
.legacy:
    mov  ecx, 0x485
    rdmsr
    bt   eax, 5
    jnc  .bad
    xor  ebx, ebx
.field:
    lea  rax, [rel vst_caps_msrs]
    add  rax, r13
    mov  ecx, [rax + rbx*8]
    rdmsr
    cmp  ebx, 1
    jne  .save
    bt   edx, 31
    jnc  .bad
.save:
    shl  rdx, 32
    or   rax, rdx
    mov  [rsp + rbx*8], rax
    inc  ebx
    cmp  ebx, 9
    jb   .field
    mov  rdi, r12
    mov  rsi, rsp
    mov  ecx, 9
    rep  movsq
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    add  rsp, 80
    pop  r13
    pop  r12
    pop  rbx
    ret

vst_controls_build:
    cmp  qword [rel vca_ready], 0
    jne  vst_frozen_refuse
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 88                        ; private10q; preserve ABI alignment
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    test rdi, rdi
    jz   .bad
    test rsi, rsi
    jz   .bad
    test rdx, rdx
    jz   .bad
    mov  rax, rdi
    add  rax, 80
    jc   .bad
    mov  rcx, rsi
    add  rcx, 40
    jc   .bad
    cmp  rdi, rcx
    jae  .other
    cmp  rsi, rax
    jb   .bad
.other:
    mov  rcx, rdx
    add  rcx, 40
    jc   .bad
    cmp  rdi, rcx
    jae  .begin
    cmp  rdx, rax
    jb   .bad
.begin:
    xor  ebx, ebx
.field:
    mov  r8, [r13 + rbx*8]
    mov  r9, [r14 + rbx*8]
    mov  r10, r8
    shr  r10, 32
    mov  r11, r9
    shr  r11, 32
    and  r10d, r11d                    ; allowed on BOTH CPUs
    or   r8d, r9d                      ; mandatory on EITHER CPU
    lea  rdx, [rel vst_ctl_policy]
    lea  rdx, [rdx + rbx*8]
    mov  eax, [rdx]                    ; required BSP seed
    or   eax, r8d
    mov  ecx, [rdx + 4]                ; supported bits, including legacy ones
    not  ecx
    test eax, ecx
    jnz  .bad
    mov  ecx, r10d
    not  ecx
    test eax, ecx                      ; never silently drop a required bit
    jnz  .bad
    mov  [rsp + rbx*8], rax
    mov  edx, eax
    cmp  ebx, 3
    jne  .entry
    test eax, 1 << 15                  ; BSP keeps host IRQ pending
    jnz  .bad
    or   edx, 1 << 15                  ; AP owns acknowledged external IRQ
.entry:
    cmp  ebx, 4
    jne  .ap_check
    and  edx, ~(1 << 9)                ; AP starts in virtual wait-for-SIPI
.ap_check:
    test edx, ecx                      ; AP variant must be supported on both
    jnz  .bad
    mov  r9d, edx
    not  r9d
    test r9d, r8d                      ; AP variant must retain must-one bits
    jnz  .bad
    mov  [rsp + rbx*8 + 40], rdx
    inc  ebx
    cmp  ebx, 5
    jb   .field
    mov  rdi, r12
    mov  rsi, rsp
    mov  ecx, 10
    rep  movsq                         ; publish only a complete validated pair
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    add  rsp, 88
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

vst_frozen_refuse:
    xor  eax, eax
    ret

align 4
vst_ctl_policy:                         ; seed, closed supported-bit mask
    dd 0x49,       0x5F                 ; pin legacy reserved1,2,4
    dd 0x81980080, 0x859861F2           ; legacy reserved only; CR3 traps unsupported
    dd 0x108A,     0x108A               ; EPT, RDTSCP, UG, INVPCID only
    dd 0x7C0204,   0x7F6FFF             ; legacy reserved; BSP ACK prohibited
    dd 0xC204,     0xD3FF               ; legacy reserved0..8,12; IA32e mutable
vst_caps_msrs:
    dd 0x481,0x48D,0x482,0x48E,0x48B,0x48B,0x483,0x48F,0x484,0x490
    dd 0x486,0x486,0x487,0x487,0x488,0x488,0x489,0x489
