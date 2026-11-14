;; MODULE hv/driver_domain_return
;; LAYER 5
;; EXPORTS nd_return_prepare, nd_return_record
;; IMPORTS hv/driver_domain, hv/vmx, core/sched, boot/header
;; CAPS extension
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Authorized return owner calls once after request frames unwind and before CLI.
; This is quiescence, not a reset or a persistence implementation. No network
; reply can certify it: stopping this domain can remove the sole endpoint.
; EAX: 0 exact clean before120s,1 no domain,2 clean late,3 unsafe,4 local budget.
; The fixed128 native observation is consumed by the original return owner.
nd_return_prepare:
    push rbx
    push r12
    push r13
    push r14
    push r15
    lea r15,[rel nd_return_record]
    cmp byte [rel nd_return_once],0
    jne .cached
    mov byte [rel nd_return_once],1
    mov rdi,r15
    xor eax,eax
    mov ecx,16
    cld
    rep stosq
    mov rax,0x0000314e5452444e       ; NDRTN1 followed by two zeros
    mov [r15],rax
    mov dword [r15+8],1
    mov dword [r15+12],128
    mov r12,[rel nd_generation]
    mov [r15+16],r12
    lea rdi,[r15+24]
    lea rsi,[rel nd_nonce]
    mov ecx,16
    rep movsb
    lea rdi,[rel nd_return_nonce]
    lea rsi,[rel nd_nonce]
    mov ecx,17
    rep movsb
    mov eax,[rel nd_bdf]
    mov [r15+40],eax
    call boot_ms_now
    mov r13,rax
    mov [r15+48],rax
    mov [r15+56],rax
    test rax,rax
    jz .unsafe
    mov r14d,4096                  ; finite even if a damaged clock stalls
    mov eax,[rel nd_state]
    test eax,eax
    jz .idle
    cmp eax,5
    je .idle
    cmp eax,6
    jae .unsafe
    test r12,r12
    jz .unsafe
    cmp eax,4
    je .poll
    mov edi,[rel hv_linux_start_gen]
    cmp rdi,r12
    jne .unsafe
    mov rdi,r12
    lea rsi,[rel nd_return_nonce]
    call nd_stop                   ; exactly one original request, no retry
    test eax,eax
    jnz .unsafe
.poll:
    mov rax,[rel nd_generation]
    cmp rax,r12
    jne .unsafe
    mov eax,[rel hv_linux_start_gen]
    cmp rax,r12
    jne .unsafe
    lea rdi,[rel nd_nonce]
    lea rsi,[r15+24]
    mov ecx,16
    cld
    repe cmpsb
    jne .unsafe
    call boot_ms_now
    cmp rax,[r15+56]
    jb .unsafe
    mov [r15+56],rax
    sub rax,r13
    cmp rax,ND_CALL_MS
    jae .budget
    cmp dword [rel nd_state],6
    je .unsafe
    cmp dword [rel nd_state],4
    jne .yield
    cmp dword [rel nd_terminal],1
    jne .unsafe
    cmp dword [rel nd_released],1
    jne .unsafe
    call nd_return_empty
    test eax,eax
    jz .yield
    xor ebx,ebx
    cmp qword [r15+56],ND_BOOT_MS
    jb .record
    mov ebx,2                      ; actual safe retirement, missed boot oracle
    jmp .record
.yield:
    dec r14d
    jz .budget
    call sched_yield               ; original native task owns CPU/DMA/RAM exit
    jmp .poll
.idle:
    call nd_return_empty
    test eax,eax
    jz .unsafe
    mov ebx,1
    jmp .record
.unsafe:
    mov ebx,3
    jmp .record
.budget:
    mov ebx,4
.record:
    mov [r15+44],ebx
    mov eax,[rel nd_state]
    mov [r15+64],eax
    mov eax,[rel nd_terminal]
    mov [r15+68],eax
    mov eax,[rel nd_released]
    mov [r15+72],eax
    mov eax,[rel nd_fault]
    mov [r15+76],eax
    mov eax,[rel hv_linux_start_gen]
    mov [r15+80],eax
    mov eax,[rel hv_linux_start_consumed]
    mov [r15+84],eax
    mov al,[rel hv_linux_running]
    mov [r15+88],al
    mov al,[rel hv_linux_start_active]
    mov [r15+89],al
    mov al,[rel hv_linux_vmx_live]
    mov [r15+90],al
    mov al,[rel hv_linux_run_req]
    mov [r15+91],al
    mov rax,[rel hv_svm_cur_vmcb]
    mov [r15+96],rax
    mov rax,[rel hv_linux_ram]
    mov [r15+104],rax
    mov rax,[rel hv_linux_region]
    mov [r15+120],rax
.cached:
    mov eax,[r15+44]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Zero CPU and actual allocator span, not the earlier STOP ACK or NIC receipt.
; hv_linux_ram_bytes is a size selector with a nonzero static default: it owns
; nothing and is never cleared, so it cannot be part of this test or the record.
nd_return_empty:
    mov al,[rel hv_linux_running]
    or al,[rel hv_linux_start_active]
    or al,[rel hv_linux_vmx_live]
    or al,[rel hv_linux_run_req]
    jnz .bad
    mov rax,[rel hv_svm_cur_vmcb]
    or rax,[rel hv_linux_ram]
    or rax,[rel hv_linux_region_resident]
    or rax,[rel hv_linux_region]
    or rax,[rel hv_linux_region_capacity]
    or rax,[rel hv_linux_mb_token]
    jnz .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

%include "core/abi/wdata.inc"
%macro WDATA_BSS_hv_driver_domain_return 0
alignb 8
nd_return_record: resb 128
nd_return_once: resb 1
nd_return_nonce: resb 17
%endmacro
WDATA_BSS_DEFER WDATA_BSS_hv_driver_domain_return
