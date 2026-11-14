;; MODULE hv/app_runtime_observer
;; LAYER 5
;; PURPOSE Inactive bounded original-bound runtime diagnostics, never authority.
;; EXPORTS app_runtime_observer_pio, app_runtime_observer_reset, app_runtime_observe
;; IMPORTS hv/app_vm, core/time
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; No common include/define activation. The pinned Linux producer is a future
; trust assumption: closed exit proves this VM, not a Linux PID or syscall.
%ifdef APP_RUNTIME_OBSERVER_ABI_V1
ARO_RECORD equ 512
ARO_ROWS equ 12
ARO_STRIDE equ 528
ARO_BYTES equ 6528

; Native lifecycle reset only. No guest reset command; never touch VM/account
; state, CPU, resource reservations or policy. All diagnostic storage erased.
app_runtime_observer_reset:
    lea rdi,[rel aro_state_begin]
    xor eax,eax
    mov ecx,(aro_state_end-aro_state_begin)/8
    cld
    rep stosq
    ret

; EDI normalized actual exit qualification, ESI original guest EAX.
; 50d0 OUT32 512 begins one fixed record, IN32 status0 empty/1 committed/2fault.
; 50d4 OUT32 appends exactly128 words, no guest pointer/offset/seek/readback.
; Every accepted transfer checks closed original CPU exit and full snapshot128.
app_runtime_observer_pio:
    push rbx
    push r12
    push r13
    mov ebx,edi
    mov r12d,esi
    cmp dword [rel aro_busy],0
    jne .bad
    call app_vm_exit_endpoint
    test rax,rax
    jz .bad
    mov eax,ebx
    and eax,0xffbf
    cmp eax,3
    je .width
    cmp eax,11
    jne .bad
.width:
    mov r13d,ebx
    shr r13d,16
    cmp r13d,0x50d0
    je .admitted
    cmp r13d,0x50d4
    jne .bad
.admitted:
    mov dword [rel aro_busy],1
    cmp dword [rel aro_fault],0
    jne .fault_status
    call aro_current
    cmp eax,1
    jne .fault
    cmp r13d,0x50d4
    je .data
    test ebx,8
    jnz .status
    cmp r12d,ARO_RECORD
    jne .fault
    cmp dword [rel aro_upload],0
    jne .fault
    cmp dword [rel aro_count],ARO_ROWS
    jae .fault
    cmp dword [rel aro_bound],1
    je .begin
    lea rdi,[rel aro_origin]
    lea rsi,[rel aro_check]
    mov ecx,16
    cld
    rep movsq
    mov dword [rel aro_bound],1
.begin:
    mov dword [rel aro_cursor],0
    mov dword [rel aro_upload],1
    jmp .zero
.status:
    xor edx,edx
    cmp dword [rel aro_upload],0
    jne .ok                       ; incomplete, never a completed record
    cmp dword [rel aro_count],0
    setne dl
    jmp .ok
.data:
    test ebx,8
    jnz .fault
    cmp dword [rel aro_upload],1
    jne .fault
    mov eax,[rel aro_cursor]
    cmp eax,ARO_RECORD
    jae .fault
    lea rcx,[rel aro_staging]
    mov [rcx+rax],r12d
    add eax,4
    mov [rel aro_cursor],eax
    cmp eax,ARO_RECORD
    jne .zero
    ; Only framing is native-validated. Remaining bytes are fixed producer
    ; scalar metadata, NOT native proof of their Linux-derived truth.
    cmp qword [rel aro_staging],1
    jne .fault
    mov rax,[rel aro_staging+8]
    dec rax
    cmp rax,7
    ja .fault
    mov rax,[rel aro_staging+16]
    dec rax
    cmp rax,4
    ja .fault
    mov eax,[rel aro_count]
    inc eax
    cmp [rel aro_staging+24],rax
    jne .fault
    call time_monotonic_now_us
    test rax,rax
    jz .fault
    mov [rel aro_last_us],rax
    mov edx,[rel aro_count]
    imul rdx,ARO_STRIDE
    lea rdi,[rel aro_rows]
    add rdi,rdx
    mov [rdi],rax
    mov qword [rdi+8],ARO_RECORD
    add rdi,16
    lea rsi,[rel aro_staging]
    mov ecx,ARO_RECORD/8
    cld
    rep movsq
    inc dword [rel aro_count]      ; publish only the complete original record
    mov dword [rel aro_upload],0
    mov dword [rel aro_cursor],0
    lea rdi,[rel aro_staging]
    xor eax,eax
    mov ecx,ARO_RECORD/8
    rep stosq
    jmp .zero
.fault:
    ; Unknown observation is sticky, never a successful zero/empty assertion.
    ; Native lifecycle alone can reset. Retain original binding for diagnostics
    ; but erase every uploaded byte and committed row. No product state change.
    mov dword [rel aro_fault],1
    mov dword [rel aro_upload],0
    mov dword [rel aro_cursor],0
    mov dword [rel aro_count],0
    mov qword [rel aro_last_us],0
    lea rdi,[rel aro_staging]
    xor eax,eax
    mov ecx,(ARO_RECORD+ARO_ROWS*ARO_STRIDE)/8
    cld
    rep stosq
.fault_status:
    xor edx,edx
    cmp r13d,0x50d0
    jne .ok
    test ebx,8
    jz .ok
    mov edx,2
    jmp .ok
.zero:
    xor edx,edx
.ok:
    mov dword [rel aro_busy],0
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
    xor edx,edx
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Fresh full native request binding + bundle proof + selected runtime generation.
; No grant/yield/guest entry. Used by each transfer AND readonly native capture.
aro_current:
    sub rsp,8
    cmp qword [rel avm_state],4
    jne .bad
    mov rdi,[rel avm_instance]
    lea rsi,[rel aro_check]
    mov edx,128
    call app_vm_snapshot
    cmp eax,1
    jne .bad
    cmp dword [rel aro_bound],0
    je .ok
    lea rdi,[rel aro_origin]
    lea rsi,[rel aro_check]
    mov ecx,16
    cld
    repe cmpsq
    jne .bad
.ok:
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    add rsp,8
    ret

; Trusted native output only, exact6528. Readonly: no consume/reset/authorization.
; Header8qwords; full actual snapshot128;12 rows(native us,512,record512).
; Empty0 means MISSING, never proves any inactive/denied/erased property.
; Partial, sticky fault or stale/unknown original ->status2 and zero record area.
app_runtime_observe:
    push rbx
    cmp esi,ARO_BYTES
    jne .bad
    test rdi,rdi
    jz .bad
    mov rax,rdi
    add rax,ARO_BYTES
    jc .bad
    mov rbx,rdi
    xor eax,eax
    mov ecx,ARO_BYTES/8
    cld
    rep stosq
    mov qword [rbx],1
    mov qword [rbx+8],ARO_BYTES
    mov qword [rbx+32],1
    cmp dword [rel aro_busy],0
    jne .unavailable
    cmp dword [rel aro_fault],0
    jne .unavailable
    cmp dword [rel aro_upload],0
    jne .unavailable
    cmp dword [rel aro_bound],0
    je .ok
    call aro_current
    cmp eax,1
    jne .unavailable
    mov eax,[rel aro_count]
    mov [rbx+16],rax
    inc eax
    mov [rbx+32],rax
    mov qword [rbx+24],1
    mov rax,[rel aro_last_us]
    mov [rbx+48],rax
    lea rdi,[rbx+64]
    lea rsi,[rel aro_origin]
    mov ecx,16
    cld
    rep movsq
    lea rdi,[rbx+192]
    lea rsi,[rel aro_rows]
    mov ecx,ARO_ROWS*ARO_STRIDE/8
    rep movsq
    jmp .ok
.unavailable:
    mov qword [rbx+24],2
.ok:
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

%include "core/abi/wdata.inc"
%macro WDATA_hv_app_runtime_observer 0
align 8
aro_state_begin:
aro_bound: dd 0
aro_busy: dd 0
aro_fault: dd 0
aro_upload: dd 0
aro_cursor: dd 0
aro_count: dd 0
aro_last_us: dq 0
aro_origin: times 128 db 0
aro_check: times 128 db 0
aro_staging: times ARO_RECORD db 0
aro_rows: times ARO_ROWS*ARO_STRIDE db 0
aro_state_end:
%endmacro
WDATA_DEFER WDATA_hv_app_runtime_observer
%endif
