; Default-off finite post-PARKED diagnostic, no policy or firmware authority.
; PWV1/v1 128B projection; fixed32 first-occurrence RAM slots, no retry/log ring.
; Edge0 reason0 = watcher budget expiry (retained); reason1 = initial required
; native presence/rings refusal. First edge0 RAM slot is immutable. Wire byte6
; describes the last unique edge, not a persistent arm reason after later edges.
%ifndef PAOS_PARKED_WATCH_DIAG
%define PAOS_PARKED_WATCH_DIAG 0
%endif
%if PAOS_PARKED_WATCH_DIAG != 0 && PAOS_PARKED_WATCH_DIAG != 1
%error "PAOS_PARKED_WATCH_DIAG must be 0 or 1"
%endif
%if PAOS_PARKED_WATCH_DIAG
%ifndef PAOS_NATIVE_TRACE_NONCE
%error "PAOS_PARKED_WATCH_DIAG requires retained native trace composition nonce"
%elif PAOS_NATIVE_TRACE_NONCE = 0
%error "PAOS_PARKED_WATCH_DIAG requires a nonzero native trace composition nonce"
%endif
%endif
; Preserve flags, all GPRs and x87/SSE state around read-only capture/drawing.
; RAX at the actual site is retained as the raw operand/returned value.
%macro PW_EDGE 1-2 0
%if PAOS_PARKED_WATCH_DIAG
    pushfq
%if %1 != 0
    cmp byte [rel pw_active],1
    jne %%inactive
%endif
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov rsi,rax
    mov rbx,rsp
    sub rsp,528
    and rsp,-16
    fxsave64 [rsp]
    mov edi,%1 | (%2 << 8)
    call parked_watch_observe
    fxrstor64 [rsp]
    mov rsp,rbx
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    popfq
%if %1 != 0
    jmp %%done
%%inactive:
    popfq
%%done:
%endif
%endif
%endmacro
; In enabled images project the actual taken rejection, retaining its operands.
; Default0 expands to the original single conditional branch, byte for byte.
%macro PW_BRANCH 4-5 0
%if PAOS_PARKED_WATCH_DIAG
    %1 %%skip
    PW_EDGE %3,%5
    jmp %4
%%skip:
%else
    %2 %4
%endif
%endmacro
%macro PW_REPAINT 0
%if PAOS_PARKED_WATCH_DIAG
    PW_EDGE 32                     ; repaint only; not a trace slot
%endif
%endmacro
%macro WDATA_parked_watch 0
alignb 16
pw_active: resb 1
pw_last_edge: resb 1
pw_last_reason: resb 1
pw_sequence: resb 1
pw_watch_scope: resb 1
alignb 4
pw_seen: resd 1
pw_candidate: resq 1
pw_slots: resb 32*32             ; tag, ordinal, raw operand, clock/anchor
pw_wire: resb 128
%endmacro
