%ifndef PAOS_HV_GUEST_POWER
%define PAOS_HV_GUEST_POWER 1
; BSP-only adapter gates. Preserve every argument, caller DF and FP state.
; No attachment leaves existing producer semantics intact. IO wrappers account
; synchronous owned work through calls/yields; a parked exit cannot overlap it.
%macro HV_POWER_CHECK 2
    cmp qword [rel hv_guest_power_context], 0
    je %%done
    pushfq
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    mov rax, rsp
    and rsp, -16
    sub rsp, 16
    mov [rsp], rax
    cld
    call %1
    test rax, rax
    mov rsp, [rsp]
    jnz %%refused
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    popfq
    jmp %%done
%%refused:
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    popfq
    jmp %2
%%done:
%endmacro

%macro HV_POWER_WORK 3
    HV_POWER_CHECK %3, %%refused
    ; No yield between admission and custody. Counter never wraps.
    cmp qword [rel hv_guest_power_inflight], 64
    jae %%refused
    inc qword [rel hv_guest_power_inflight]
    lea rsp, [rsp - 8]
    call %1.power_body
    lea rsp, [rsp + 8]
    pushfq
    dec qword [rel hv_guest_power_inflight]
    popfq
    ret
%%refused:
%if %2 < 0
    mov rax, %2
%else
    mov eax, %2
%endif
    ret
.power_body:
%endmacro
%endif
