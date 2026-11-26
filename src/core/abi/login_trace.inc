; Lab diagnostic only. Every expansion preserves all registers and flags.
; A stage is an observation, never authentication, admission or a verdict.
%ifndef PAOS_LOGIN_TRACE_INC
%define PAOS_LOGIN_TRACE_INC 1
%include "core/abi/build_profile.inc"
%macro LOGIN_TRACE 1
%if PAOS_PUBLIC_BUILD = 0
%ifdef PAOS_PUBLICITY_LAB_PROFILE
%if PAOS_PUBLICITY_LAB_PROFILE = 1
    push rax
    mov eax, %1
    call command_udp_login_trace
    pop rax
%endif
%endif
%endif
%endmacro
%macro LOGIN_TRACE_BEGIN 2
%if PAOS_PUBLIC_BUILD = 0
%ifdef PAOS_PUBLICITY_LAB_PROFILE
%if PAOS_PUBLICITY_LAB_PROFILE = 1
    push rdi
    push rsi
    mov rdi, %1
    mov rsi, %2
    LOGIN_TRACE 1
    pop rsi
    pop rdi
%endif
%endif
%endif
%endmacro
%endif
