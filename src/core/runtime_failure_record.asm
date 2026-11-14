;; MODULE core/runtime_failure_record
;; LAYER 1
;; CONTEXT: bsp_only
;; EXPORTS runtime_failure_save, runtime_failure_snapshot, runtime_failure_wire_ok, runtime_failure_snapshot_bytes
;; IMPORTS core/build_id, boot/boot_v2_handoff, boot/beacon, boot/header, boot/paging, boot/nvram_access
;; CAPS
;; OWNER rc-vm-claude
; Latest bounded scalar failure; actual producer calls after containment in BSP
; task context. Never IRQ/panic, allocation, text, pointer or policy authority.
; <=16 attempted writes/boot. Unknown stores preserved; uncertainty sticky.
%include "core/abi/runtime_failure.inc"

; RDI=256B, EAX=1 canonical/full identity, else 0. No current globals needed.
runtime_failure_wire_ok:
    push rbx
    mov rbx,rdi
    cmp dword [rbx],RFR_MAGIC
    jne .bad
    cmp dword [rbx+4],0x01000001
    jne .bad
    movzx eax,word [rbx+8]
    dec eax
    cmp eax,8
    ja .bad
    lea rdx,[rel runtime_failure_components]
    movzx eax,byte [rdx+rax]
    cmp [rbx+10],ax
    jne .bad
    cmp dword [rbx+12],7
    jne .bad
    cmp qword [rbx+16],1
    jb .bad
    cmp qword [rbx+16],RFR_MAX_WRITES
    ja .bad
    cmp qword [rbx+24],0
    je .bad
    cmp qword [rbx+32],0
    je .bad
    cmp dword [rbx+44],0
    jne .bad
    cmp qword [rbx+48],0
    je .bad
    cmp qword [rbx+56],0
    je .bad
    cmp qword [rbx+64],0
    je .bad
    mov rax,[rbx+72]
    or rax,[rbx+80]
    or rax,[rbx+88]
    or rax,[rbx+96]
    jz .bad
    mov rax,[rbx+104]
    or rax,[rbx+112]
    or rax,[rbx+120]
    or rax,[rbx+128]
    jz .bad
    cmp byte [rbx+160],1
    jb .bad
    cmp byte [rbx+160],2
    ja .bad
    cmp word [rbx+161],0x0100 ; Normal and measured MATCH
    jne .bad
    lea rdi,[rbx+163]
    mov ecx,89
    xor eax,eax
    repe scasb
    jne .bad
    mov rdi,rbx
    mov esi,RFR_CRC
    call pbm_crc32
    cmp eax,[rbx+RFR_CRC]
    jne .bad
    test eax,eax
    jz .bad
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; RDI=kind1..9, RSI=nonzero typed reason, RDX/RCX/R8=scalar context.
; 0 saved+exactreadback,2 unavailable,3 unknown/uncertain,4 badinput,5 budget.
; Context is typed by the trusted producer; never an address or secret.
runtime_failure_save:
    push rbp
    mov rbp,rsp
    and rsp,-16
    push rbx
    push r12
    push r13
    push r14
    mov r13,rdi
    mov r14,rsi
    lea rbx,[rel runtime_failure_record]
    mov [rbx+136],rdx
    mov [rbx+144],rcx
    mov [rbx+152],r8
    cmp r13,1
    jb .invalid
    cmp r13,9
    ja .invalid
    test r14,r14
    jz .invalid
    cmp byte [rel runtime_failure_uncertain],0
    jne .unknown
    cmp qword [rel runtime_failure_attempts],RFR_MAX_WRITES
    jae .budget
    cmp byte [rel pbm_manager_launch],1
    jne .unavailable
    cmp byte [rel pbm_runtime_code_mapped],1
    jne .unavailable
    test byte [rel pbm_flags],PBM_HF_MUTABLE_ATTEMPT
    jz .unavailable
    cmp byte [rel pbm_profile],PBM_PROFILE_NORMAL
    jne .unavailable
    cmp byte [rel paos_build_state],BID_ST_MATCH
    jne .unavailable
    mov r12,[rel runtime_services]
    test r12,r12
    jz .unavailable
    ; Preserve the three scalar inputs while clearing every other byte.
    mov rdi,rbx
    mov ecx,136/8
    xor eax,eax
    rep stosq
    lea rdi,[rbx+160]
    mov ecx,96/8
    rep stosq
    mov dword [rbx],RFR_MAGIC
    mov dword [rbx+4],0x01000001
    mov [rbx+8],r13w
    lea rdx,[rel runtime_failure_components-1]
    movzx eax,byte [rdx+r13]
    mov [rbx+10],ax
    mov dword [rbx+12],7
    mov rax,[rel runtime_failure_attempts]
    inc rax
    mov [rbx+16],rax
    mov [rbx+24],r14
    mov rax,[rel boot_tsc_start]
    mov [rbx+32],rax
    mov eax,[rel boot_nonce]
    mov [rbx+40],rax
    mov rax,[rel pbm_manager_sequence]
    mov [rbx+48],rax
    mov rax,[rel pbm_attempt_nonce]
    mov [rbx+56],rax
    mov rax,[rel pbm_state_generation]
    mov [rbx+64],rax
    lea rdi,[rbx+72]
    lea rsi,[rel paos_build_measured]
    mov ecx,4
    rep movsq
    lea rsi,[rel pbm_payload_sha] ; exact 32-byte digest from the validated PBH1
    mov ecx,4
    rep movsq
    mov al,[rel pbm_entry]
    mov [rbx+160],al
    mov byte [rbx+162],1
    mov rdi,rbx
    mov esi,RFR_CRC
    call pbm_crc32
    mov [rbx+RFR_CRC],eax
    mov rdi,rbx
    call runtime_failure_wire_ok
    test eax,eax
    jz .unavailable
    inc qword [rel runtime_failure_attempts] ; before first fallible EFI call
    call runtime_failure_read
    mov rdx,0x800000000000000E
    cmp rax,rdx
    je .gate
    test rax,rax
    jnz .unknown
    cmp dword [rel runtime_failure_attrs],7
    jne .unknown
    cmp qword [rel runtime_failure_size],RFR_BYTES
    jne .unknown
    lea rdi,[rel runtime_failure_verify]
    call runtime_failure_wire_ok
    test eax,eax
    jz .unknown
.gate:
    lea rdi,[rel runtime_failure_guid]
    lea rsi,[rel runtime_failure_name]
    xor edx,edx
    lea rcx,[rel runtime_failure_tag]
    call storage_access_nvram_require
    test rax,rax
    jnz .unavailable
    mov byte [rel runtime_failure_uncertain],1
    lea rcx,[rel runtime_failure_name]
    lea rdx,[rel runtime_failure_guid]
    mov r8d,7
    mov r9d,RFR_BYTES
    sub rsp,48
    mov [rsp+32],rbx
    call [r12+0x58]
    add rsp,48
    test rax,rax
    jnz .unknown
    call runtime_failure_read
    test rax,rax
    jnz .unknown
    cmp dword [rel runtime_failure_attrs],7
    jne .unknown
    cmp qword [rel runtime_failure_size],RFR_BYTES
    jne .unknown
    lea rdi,[rel runtime_failure_verify]
    mov rsi,rbx
    mov ecx,RFR_BYTES/8
    repe cmpsq
    jne .unknown
    mov byte [rel runtime_failure_uncertain],0
    xor eax,eax
    jmp .out
.unknown:
    mov byte [rel runtime_failure_uncertain],1
    mov eax,3
    jmp .out
.unavailable:
    mov eax,2
    jmp .out
.invalid:
    mov eax,4
    jmp .out
.budget:
    mov eax,5
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    mov rsp,rbp
    pop rbp
    ret

; Read only: EAX0 absent,1 valid,2 unavailable,3 unknown; all nonvalid bytes0.
runtime_failure_snapshot:
    push rbp
    mov rbp,rsp
    and rsp,-16
    push rbx
    push r12
    lea rdi,[rel runtime_failure_snapshot_bytes]
    mov ecx,RFR_BYTES/8
    xor eax,eax
    rep stosq
    mov ebx,2
    cmp byte [rel pbm_manager_launch],1
    jne .out
    cmp byte [rel pbm_runtime_code_mapped],1
    jne .out
    mov r12,[rel runtime_services]
    test r12,r12
    jz .out
    call runtime_failure_read
    mov rdx,0x800000000000000E
    cmp rax,rdx
    jne .present
    xor ebx,ebx
    jmp .out
.present:
    mov ebx,3
    test rax,rax
    jnz .out
    cmp dword [rel runtime_failure_attrs],7
    jne .out
    cmp qword [rel runtime_failure_size],RFR_BYTES
    jne .out
    lea rdi,[rel runtime_failure_verify]
    call runtime_failure_wire_ok
    test eax,eax
    jz .out
    lea rsi,[rel runtime_failure_verify]
    lea rdi,[rel runtime_failure_snapshot_bytes]
    mov ecx,RFR_BYTES/8
    rep movsq
    mov ebx,1
.out:
    mov eax,ebx
    pop r12
    pop rbx
    mov rsp,rbp
    pop rbp
    ret

runtime_failure_read:
    mov qword [rel runtime_failure_size],RFR_BYTES
    mov dword [rel runtime_failure_attrs],0
    lea rcx,[rel runtime_failure_name]
    lea rdx,[rel runtime_failure_guid]
    lea r8,[rel runtime_failure_attrs]
    lea r9,[rel runtime_failure_size]
    sub rsp,40
    lea rax,[rel runtime_failure_verify]
    mov [rsp+32],rax
    call [r12+0x48]
    add rsp,40
    ret

runtime_failure_components: db 1,2,3,2,2,4,4,5,6
runtime_failure_guid: dd 0x7a965d12
    dw 0xc839,0x4a77
    db 0xb1,0xe2,0x90,0x6e,0xf7,0x24,0x43,0x8c
align 2
runtime_failure_name: dw 'P','a','O','S','R','u','n','t','i','m','e','F','a','i','l','u','r','e','R','e','c','o','r','d',0
runtime_failure_tag: db 'runtime-failure',0

%include "core/abi/wdata.inc"
%macro WDATA_core_runtime_failure_record 0
align 8
runtime_failure_attempts: dq 0
runtime_failure_size: dq 0
runtime_failure_attrs: dd 0
runtime_failure_uncertain: db 0
align 8
runtime_failure_record: times RFR_BYTES db 0
runtime_failure_verify: times RFR_BYTES db 0
runtime_failure_snapshot_bytes: times RFR_BYTES db 0
%endmacro
WDATA_DEFER WDATA_core_runtime_failure_record
