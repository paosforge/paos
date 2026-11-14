;; MODULE hv/driver_domain_data
;; LAYER 5
;; EXPORTS nd_learn_bind, nd_learn_bind_provisioned, nd_learn_save, nd_learn_validate, nd_learn_pump
;; IMPORTS hv/driver_domain_learned, fs/fat32_disk, fs/storage_access, sec/node_identity, core/lib/sha256, core/heap
;; CAPS extension
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Original synchronous DATA provider only. No inferred disk, private FAT fd,
; request-authority swap, write retry or guest signing key. The highest fully
; verified slot survives replacement. A read error is never an empty slot.
; Persist state:0 unbound,1 bound,2 durable+verified,3 uncertain,4 refused.
nd_learn_bind:
    xor r8d,r8d
    jmp nd_learn_bind_common

; Sole provider resolves its sealed explicit DAT1 role and live exact media.
nd_learn_bind_provisioned:
    mov r8d,1
nd_learn_bind_common:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12,rdi
    mov r13,rsi
    mov r14d,r8d
    cmp dword [rel nd_learn_persist_state],3
    jne .start
    mov rax,[rel nd_generation]
    cmp rax,[rel nd_learn_persist_gen]
    je .bad
.start:
    mov byte [rel nd_learn_bound],0
    mov dword [rel nd_learn_persist_state],0
    call boot_ms_now
    test rax,rax
    jz .bad
    cmp rax,120000
    jae .bad
    mov r15,rax
    ; A missing active identity cannot classify existing records as invalid.
    ; Otherwise a later key load could save with an unverified slot choice.
    lea rdi,[rel nd_learn_verify_pub]
    mov esi,32
    call node_identity_public
    test eax,eax
    jnz .pending
    mov [rel nd_learn_service],r14b
    test r14d,r14d
    jnz .provisioned
    mov rdi,r12
    mov rsi,r13
    lea rdx,[rel nd_learn_data_token]
    call data_config_bind
    jmp .bound
.provisioned:
    lea rdi,[rel nd_learn_data_token]
    call data_config_bind_provisioned
.bound:
    test eax,eax
    jnz .bad
    cmp qword [rel nd_learn_verify_buffer],0
    jne .allocated
    mov edi,ND_LEARN_MAX+ND_LEARN_HEADER
    call kmalloc
    test rax,rax
    jz .bad
    mov [rel nd_learn_verify_buffer],rax
.allocated:
    lea rsi,[rel nd_learn_data_token+56]
    lea rdi,[rel nd_learn_volume_identity]
    mov ecx,56
    cld
    rep movsb
    mov rax,[rel nd_learn_data_token+48]
    mov [rel nd_learn_volume_identity+56],rax
    xor r12d,r12d                  ; greatest verified sequence
    xor r13d,r13d                  ; current slot
    xor r14d,r14d                  ; replacement slot
.read:
    lea rdi,[rel nd_learn_data_token]
    lea rsi,[rel nd_learn_slot_names]
    imul eax,r13d,11
    add rsi,rax
    mov rdx,[rel nd_learn_verify_buffer]
    mov ecx,ND_LEARN_MAX+ND_LEARN_HEADER
    call data_config_read
    cmp rax,-4                     ; positively absent, not IO failure
    je .next
    test rax,rax
    js .bad
    mov rdi,[rel nd_learn_verify_buffer]
    mov rsi,rax
    call nd_learn_validate
    test eax,eax
    jnz .next                      ; known bytes, invalid record
    mov rbx,[rel nd_learn_verify_buffer]
    mov rax,[rbx+16]
    cmp rax,r12
    je .bad                        ; equal positive sequences are ambiguous
    jb .next
    mov r12,rax
    mov r14d,r13d
    xor r14d,1
.next:
    call nd_learn_data_cost
    test eax,eax
    jnz .bad
    inc r13d
    cmp r13d,2
    jb .read
    lea rdi,[rel nd_learn_data_token]
    call data_config_current
    test eax,eax
    jnz .bad
    call nd_learn_data_cost
    test eax,eax
    jnz .bad
    inc r12
    jz .bad                        ; never wrap the signed sequence
    mov [rel nd_learn_sequence],r12
    mov [rel nd_learn_target],r14d
    mov byte [rel nd_learn_bound],1
    mov dword [rel nd_learn_persist_state],1
    mov rax,[rel nd_generation]
    mov [rel nd_learn_persist_gen],rax
    cmp dword [rel nd_learn_state],3
    jne .ok
    mov dword [rel nd_learn_state],2 ; re-sign any earlier RAM-only header
.ok:
    xor eax,eax
    jmp .out
.pending:
    cmp dword [rel nd_learn_state],2
    je .key_pending
    cmp dword [rel nd_learn_state],3
    jne .bad
.key_pending:
    mov dword [rel nd_learn_state],6
.bad:
    mov eax,-1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; RDI=whole bounded record,RSI=exact EOF. Historic records supply ordering only;
; they never authorize DMA, native code or a new START.
nd_learn_validate:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx,rdi
    cmp rsi,ND_LEARN_HEADER+1
    jb .bad
    cmp rsi,ND_LEARN_HEADER+ND_LEARN_MAX
    ja .bad
    mov rax,'DDLEARN1'
    cmp [rbx],rax
    jne .bad
    cmp dword [rbx+8],1
    jne .bad
    cmp dword [rbx+12],ND_LEARN_HEADER
    jne .bad
    cmp qword [rbx+16],0
    je .bad
    mov rax,[rbx+24]
    test rax,rax
    jz .bad
    shr rax,32
    jnz .bad
    cmp dword [rbx+32],65535
    ja .bad
    mov r12d,[rbx+36]
    test r12d,r12d
    jz .bad
    cmp r12d,ND_LEARN_MAX
    ja .bad
    lea rax,[r12+ND_LEARN_HEADER]
    cmp rax,rsi
    jne .bad
    xor ecx,ecx
    xor edx,edx
.nonce:
    mov al,[rbx+40+rcx]
    cmp al,'0'
    jb .bad
    cmp al,'9'
    jbe .nibble
    cmp al,'a'
    jb .bad
    cmp al,'f'
    ja .bad
.nibble:
    cmp al,'0'
    setne al
    or dl,al
    inc ecx
    cmp ecx,16
    jb .nonce
    test dl,dl
    jz .bad
    cmp dword [rbx+120],0x8007
    jne .bad
    cmp dword [rbx+124],0
    jne .bad
    lea rdi,[rbx+168]
    lea rsi,[rel nd_learn_volume_identity]
    mov ecx,64
    cld
    repe cmpsb
    jne .bad
    lea rdi,[rbx+232]
    mov ecx,216
.reserved:
    cmp byte [rdi],0
    jne .bad
    inc rdi
    loop .reserved
    lea rdi,[rel nd_learn_verify_pub]
    mov esi,32
    call node_identity_public
    test eax,eax
    jnz .bad
    lea rdi,[rbx+56]
    lea rsi,[rel nd_learn_verify_pub]
    mov ecx,32
    repe cmpsb
    jne .bad
    mov rdi,rbx
    mov esi,448
    lea rdx,[rbx+448]
    mov ecx,64
    call node_identity_verify
    test eax,eax
    jnz .bad
    lea rdi,[rel nd_learn_verify_sha]
    lea rsi,[rbx+ND_LEARN_HEADER]
    mov edx,r12d
    call sha256_hash
    test eax,eax
    jnz .bad
    lea rdi,[rbx+88]
    lea rsi,[rel nd_learn_verify_sha]
    mov ecx,32
    repe cmpsb
    jne .bad
    xor eax,eax
    jmp .out
.bad:
    mov eax,-1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

nd_learn_save:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rax,[rel nd_generation]
    cmp rax,[rel nd_learn_persist_gen]
    jne .bad
    cmp dword [rel nd_learn_persist_state],2
    je .already
    cmp dword [rel nd_learn_persist_state],3
    je .bad                         ; sticky, no uncertain resend
    cmp byte [rel nd_learn_bound],1
    jne .bad
    mov rax,[rel nd_generation]
    cmp rax,[rel nd_learn_persist_gen]
    jne .bad
    call boot_ms_now
    test rax,rax
    jz .bad
    cmp rax,120000
    jae .bad
    mov r15,rax
    call nd_learn_write_current
    test eax,eax
    jnz .bad
    call nd_learn_sign
    cmp dword [rel nd_learn_state],3
    jne .bad
    call nd_learn_write_current
    test eax,eax
    jnz .bad
    call nd_learn_data_cost
    test eax,eax
    jnz .bad
    mov ebx,[rel nd_learn_bytes]
    add ebx,ND_LEARN_HEADER
    lea r14,[rel nd_learn_slot_names]
    imul eax,[rel nd_learn_target],11
    add r14,rax
    lea rdi,[rel nd_learn_data_token]
    mov rsi,r14
    mov rdx,[rel nd_learn_buffer]
    mov ecx,ebx
    ; Any attempted effect remains uncertain until provider success AND our
    ; exact reopened signed bytes, current custody and full cost all agree.
    mov dword [rel nd_learn_persist_state],3
    cmp byte [rel nd_learn_service],1
    je .service_write
    call data_config_write
    jmp .written
.service_write:
    call data_config_write_learned
.written:
    test eax,eax
    jnz .bad
    lea rdi,[rel nd_learn_data_token]
    mov rsi,r14
    mov rdx,[rel nd_learn_verify_buffer]
    mov ecx,ND_LEARN_MAX+ND_LEARN_HEADER
    call data_config_read
    cmp rax,rbx
    jne .bad
    mov rdi,[rel nd_learn_verify_buffer]
    mov rsi,rax
    call nd_learn_validate
    test eax,eax
    jnz .bad
    mov rdi,[rel nd_learn_verify_buffer]
    mov rsi,[rel nd_learn_buffer]
    mov ecx,ebx
    cld
    repe cmpsb
    jne .bad
    call nd_learn_write_current
    test eax,eax
    jnz .bad
    call nd_learn_data_cost
    test eax,eax
    jnz .bad
    mov dword [rel nd_learn_state],4
    mov dword [rel nd_learn_persist_state],2
.already:
    call nd_learn_write_current
    test eax,eax
    jnz .bad
.ok:
    xor eax,eax
    jmp .out
.bad:
    mov eax,-1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

nd_learn_write_current:
    push rbx
    call nd_current
    cmp eax,1
    jne .bad
    cmp byte [rel nd_learn_service],1
    je .provider
    call storage_access_request_owner
    cmp eax,1
    jne .bad
    call storage_access_request_intent
    cmp eax,1
    jne .bad
.provider:
    lea rdi,[rel nd_learn_data_token]
    call data_config_current
    pop rbx
    ret
.bad:
    mov eax,-1
    pop rbx
    ret

; R15=original entire operation start, never a fresh subcall allowance.
nd_learn_data_cost:
    push rbx
    call boot_ms_now
    cmp rax,120000
    jae .bad
    sub rax,r15
    jc .bad
    cmp rax,4000
    jae .bad
    xor eax,eax
    pop rbx
    ret
.bad:
    mov eax,-1
    pop rbx
    ret

; Clean native VM exit only. One automatic persistence attempt per START;
; unavailable role/key stays pending and an uncertain physical effect stays
; sticky. No timers, synthetic owner or second backend.
nd_learn_pump:
    push rbx
    cmp dword [rel nd_state],2
    jne .out
    call nd_current
    cmp eax,1
    jne .out
    mov rax,[rel nd_generation]
    cmp rax,[rel nd_learn_pump_gen]
    je .generation
    mov [rel nd_learn_pump_gen],rax
    mov byte [rel nd_learn_pump_attempted],0
.generation:
    cmp byte [rel nd_learn_pump_attempted],0
    jne .out
    cmp dword [rel nd_learn_state],2
    jne .out
    mov byte [rel nd_learn_pump_attempted],1
    call nd_learn_bind_provisioned
    test eax,eax
    jnz .out
    call nd_learn_save
.out:
    pop rbx
    ret

nd_learn_slot_names: db 'DDLEARN0BIN','DDLEARN1BIN'
%include "core/abi/wdata.inc"
%macro WDATA_driver_domain_data 0
align 8
nd_learn_verify_buffer: dq 0
nd_learn_persist_gen: dq 0
nd_learn_data_token: times 112 db 0
nd_learn_target: dd 0
nd_learn_persist_state: dd 0
nd_learn_bound: db 0
nd_learn_service: db 0
nd_learn_pump_attempted: db 0
align 8
nd_learn_pump_gen: dq 0
nd_learn_verify_sha: times 32 db 0
nd_learn_verify_pub: times 32 db 0
%endmacro
WDATA_DEFER WDATA_driver_domain_data
