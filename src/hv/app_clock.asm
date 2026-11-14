;; MODULE hv/app_clock
;; LAYER 5
;; EXPORTS app_clock_pio
;; IMPORTS hv/app_vm, core/smp, core/time
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Public genuine UTC only. No virtual RTC rewrite and no authority/grant API.
; Scalar IN32 low50b0 then high50b4/status50b8 transfers one <=1s old sample, exactly once.
app_clock_pio:
    push rbx
    push r12
    sub rsp,8
    mov ebx,edi
    call app_vm_exit_endpoint
    test rax,rax
    jz .bad
    call smp_current_logical
    test eax,eax
    jnz .bad
    mov eax,ebx
    and eax,0xffbf
    cmp eax,11                    ; only IN32, optionally immediate port bit
    jne .bad
    shr ebx,16
    cmp ebx,0x50b0
    je .port
    cmp ebx,0x50b4
    je .port
    cmp ebx,0x50b8
    jne .bad
.port:
    mov rdi,[rel avm_instance]
    lea rsi,[rel ac_current]
    mov edx,128
    call app_vm_snapshot
    cmp eax,1
    jne .bad
    cmp ebx,0x50b0
    je .low
    mov r12,[rel ac_seconds]
    mov eax,1
    cmp ebx,0x50b8
    jne .phase
    inc eax
.phase:
    cmp [rel ac_pending],rax
    jne .unavailable
    mov qword [rel ac_pending],0 ; consume before calling any producer
    lea rdi,[rel ac_current]
    lea rsi,[rel ac_binding]
    mov ecx,16
    cld
    repe cmpsq
    jne .bad
    call time_monotonic_now_us
    test rax,rax
    jz .unavailable
    cmp rax,[rel app_clock_begin_us]
    jb .unavailable
    cmp rax,[rel ac_deadline]
    jae .unavailable
    call time_wall_utc_now_s       ; current provenance must still be genuine UTC
    test rax,rax
    jz .unavailable
    mov edx,1
    cmp ebx,0x50b8
    je .claimed
    mov qword [rel ac_pending],2
    mov rdx,r12
    shr rdx,32
    jmp .claimed
.low:
    mov qword [rel ac_pending],0
    call time_wall_utc_now_s       ; native applied SNTP only, unknown =>0
    test rax,rax
    jz .unavailable
    mov r12,rax
    call time_monotonic_now_us
    test rax,rax
    jz .unavailable
    mov [rel app_clock_begin_us],rax
    add rax,1000000
    jc .unavailable
    mov [rel ac_deadline],rax
    mov [rel ac_seconds],r12
    lea rdi,[rel ac_binding]
    lea rsi,[rel ac_current]
    mov ecx,16
    cld
    rep movsq
    mov qword [rel ac_pending],1
    mov edx,r12d
.claimed:
    mov eax,1
    jmp .out
.unavailable:
    mov qword [rel ac_pending],0
    xor edx,edx
    jmp .claimed
.bad:
    mov qword [rel ac_pending],0
    xor eax,eax
    xor edx,edx
.out:
    add rsp,8
    pop r12
    pop rbx
    ret

%include "core/abi/wdata.inc"
%macro WDATA_hv_app_clock 0
align 8
ac_pending: dq 0
ac_seconds: dq 0
app_clock_begin_us: dq 0
ac_deadline: dq 0
ac_binding: times 128 db 0
ac_current: times 128 db 0
%endmacro
WDATA_DEFER WDATA_hv_app_clock
