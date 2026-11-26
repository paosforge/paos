; Inline entry fences. The complete kernel enables these unconditionally in
; paos.asm. Standalone leaf fixtures without the boot graph retain normal policy;
; policy HOST fixtures explicitly enable the same production macros.
%ifndef PAOS_NATIVE_DRIVER_GATE_INC
%define PAOS_NATIVE_DRIVER_GATE_INC 1
%macro NATIVE_DRIVER_REFUSE 1-2 -1
%ifdef PAOS_NATIVE_DRIVER_POLICY_LINKED
    push rdi
    push rsi
    mov edi, %1
    mov rsi, -1
    call native_driver_gate
    pop rsi
    pop rdi
    jnc %%admit
    mov rax, %2
    ret
%%admit:
%endif
%endmacro

; Candidate-level A1 reservation. Invoke before claim, BAR/MMIO, reset or PCI
; enable. Unlike class6 policy this keeps the control NIC and every other native
; candidate. Preserve all registers while adapting the driver's bus/dev/fn.
%macro A1_NATIVE_NIC_SKIP 4
%ifdef PAOS_A1_SERVICE_LINKED
    push rdi
    push rsi
    push rdx
    ; Inputs may themselves be argument registers: stage all three first.
    push %1
    push %2
    push %3
    pop rdx
    pop rsi
    pop rdi
    call a1_native_nic_gate
    pop rdx
    pop rsi
    pop rdi
    jc %4
%endif
%endmacro

; A's private complete reservation set excludes NEW PCI NIC binds, including
; when common bytes are stale or POISON. This is not the class6 policy gate:
; existing native TX/link/recovery never calls it. A's query touches only RAX.
; Fixtures without the production A capability have no A custody to enforce.
%macro PCIA_NATIVE_COLD_REFUSE 0-1 -1
%ifdef PAOS_PCIA_GRP_AUTHORITY
    push rax
    call pcia_grp_any_held
    test eax, eax
    pop rax
    jz %%admit
    mov rax, %1
    ret
%%admit:
%endif
%endmacro
%endif
