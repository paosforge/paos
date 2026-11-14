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
%endif
