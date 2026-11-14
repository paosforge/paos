;; MODULE hv/driver_domain_learned
;; LAYER 5
;; EXPORTS nd_learn_reset, nd_learn_feed, nd_learn_line, nd_learn_sign
;; IMPORTS hv/driver_domain, hv/driver_domain_command, core/heap, core/lib/sha256, sec/node_identity
;; CAPS extension
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Complete guest hardware census is untrusted observation, never a driver or
; DMA grant. Exact original START/nonce, ordered offsets and SHA256 precede
; native signing. One bounded native heap allocation is reused across STARTs;
; a partial/error stream cannot publish a signature or replace a DATA slot.
; State 0 absent,1 receiving,2 hash verified,3 signed,4 DATA verified,
; 5 refused,6 active node identity unavailable. Persistence owns state4.
ND_LEARN_MAX equ 8388608
ND_LEARN_HEADER equ 512
nd_learn_reset:
    mov dword [rel nd_learn_state],0
    mov dword [rel nd_learn_received],0
    mov dword [rel nd_learn_bytes],0
    mov dword [rel nd_learn_pos],0
    mov byte [rel nd_learn_line_ready],0
    mov rax,[rel hv_vcon_epoch]
    mov [rel nd_learn_epoch],rax
    ret

; EDI=one original counted hvc0 TX byte. The first partial line is discarded.
nd_learn_feed:
    push rbx
    mov ebx,edi
    mov rax,[rel hv_vcon_epoch]
    cmp rax,[rel nd_learn_epoch]
    je .epoch
    mov [rel nd_learn_epoch],rax
    mov dword [rel nd_learn_pos],0
    mov byte [rel nd_learn_line_ready],0
    cmp dword [rel nd_learn_state],1
    jne .epoch
    mov dword [rel nd_learn_state],5
.epoch:
    cmp bl,10
    je .newline
    cmp byte [rel nd_learn_line_ready],1
    jne .out
    mov eax,[rel nd_learn_pos]
    cmp eax,640
    jae .drop
    lea rdx,[rel nd_learn_line_buf]
    mov [rdx+rax],bl
    inc dword [rel nd_learn_pos]
    jmp .out
.newline:
    cmp byte [rel nd_learn_line_ready],1
    jne .fresh
    mov eax,[rel nd_learn_pos]
    lea rdi,[rel nd_learn_line_buf]
    mov byte [rdi+rax],0
    ; Permit a single CR from the existing console line discipline.
    test eax,eax
    jz .fresh
    cmp byte [rdi+rax-1],13
    jne .parse
    mov byte [rdi+rax-1],0
.parse:
    call nd_learn_line
.fresh:
    mov byte [rel nd_learn_line_ready],1
    mov dword [rel nd_learn_pos],0
    jmp .out
.drop:
    mov byte [rel nd_learn_line_ready],0
    cmp dword [rel nd_learn_state],1
    jne .out
    mov dword [rel nd_learn_state],5
.out:
    pop rbx
    ret

; RDI=private NUL-terminated bounded line. Only this namespace is parsed.
nd_learn_line:
    push rbx
    push r12
    push r13
    mov r12,rdi
    lea rsi,[rel nd_learn_tag]
    mov ecx,10
    cld
    repe cmpsb
    jne .out
    cmp dword [rel nd_state],2
    jne .bad
    call nd_current
    cmp eax,1
    jne .bad
    mov rdi,r12
    lea rsi,[rel nd_learn_t0]
    mov edx,24
    call nd_token
    test rax,rax
    jz .bad
    mov rdi,rax
    lea rsi,[rel nd_learn_t1]
    mov edx,17
    call nd_token
    test rax,rax
    jz .bad
    mov rdi,rax
    lea rsi,[rel nd_learn_t2]
    mov edx,11
    call nd_token
    test rax,rax
    jz .bad
    mov r12,rax
    lea rdi,[rel nd_learn_t1]
    lea rsi,[rel nd_nonce]
    mov ecx,17
    repe cmpsb
    jne .bad
    lea rdi,[rel nd_learn_t2]
    mov esi,10
    mov edx,10
    call nd_number
    jc .bad
    cmp rax,[rel nd_generation]
    jne .bad
    lea rdi,[rel nd_learn_t0]
    lea rsi,[rel nd_learn_end]
    mov ecx,14
    repe cmpsb
    je .end
    mov rdi,r12
    lea rsi,[rel nd_learn_t3]
    mov edx,11
    call nd_token
    test rax,rax
    jz .bad
    mov rdi,rax
    lea rsi,[rel nd_learn_t4]
    mov edx,513
    call nd_token
    test rax,rax
    jz .bad
    cmp byte [rax],0
    jne .bad
    lea rdi,[rel nd_learn_t3]
    mov esi,10
    mov edx,10
    call nd_number
    jc .bad
    mov r13d,eax
    lea rdi,[rel nd_learn_t0]
    lea rsi,[rel nd_learn_begin]
    mov ecx,16
    repe cmpsb
    je .begin
    lea rdi,[rel nd_learn_t0]
    lea rsi,[rel nd_learn_data]
    mov ecx,15
    repe cmpsb
    jne .bad
    cmp dword [rel nd_learn_state],1
    jne .bad
    cmp r13d,[rel nd_learn_received]
    jne .bad
    lea rdi,[rel nd_learn_t4]
    lea rsi,[rel nd_learn_chunk]
    mov edx,256
    call nd_learn_unhex
    test eax,eax
    jz .bad
    mov ebx,eax
    add eax,r13d
    jc .bad
    cmp eax,[rel nd_learn_bytes]
    ja .bad
    mov rdi,[rel nd_learn_buffer]
    add rdi,ND_LEARN_HEADER
    add rdi,r13
    lea rsi,[rel nd_learn_chunk]
    mov ecx,ebx
    rep movsb
    lea rdi,[rel nd_learn_sha]
    lea rsi,[rel nd_learn_chunk]
    mov edx,ebx
    call sha256_stream_update
    test eax,eax
    jnz .bad
    add [rel nd_learn_received],ebx
    jmp .out
.begin:
    cmp dword [rel nd_learn_state],0
    jne .bad
    test r13d,r13d
    jz .bad
    cmp r13d,ND_LEARN_MAX
    ja .bad
    lea rdi,[rel nd_learn_t4]
    lea rsi,[rel nd_learn_expected]
    mov edx,32
    call nd_learn_unhex
    cmp eax,32
    jne .bad
    cmp qword [rel nd_learn_buffer],0
    jne .allocated
    mov edi,ND_LEARN_MAX+ND_LEARN_HEADER
    call kmalloc
    test rax,rax
    jz .bad
    mov [rel nd_learn_buffer],rax
.allocated:
    mov [rel nd_learn_bytes],r13d
    mov dword [rel nd_learn_received],0
    lea rdi,[rel nd_learn_sha]
    call sha256_stream_init
    mov dword [rel nd_learn_state],1
    jmp .out
.end:
    cmp byte [r12],0
    jne .bad
    cmp dword [rel nd_learn_state],1
    jne .bad
    mov eax,[rel nd_learn_received]
    cmp eax,[rel nd_learn_bytes]
    jne .bad
    lea rdi,[rel nd_learn_sha]
    lea rsi,[rel nd_learn_digest]
    call sha256_stream_final
    test eax,eax
    jnz .bad
    lea rdi,[rel nd_learn_digest]
    lea rsi,[rel nd_learn_expected]
    mov ecx,32
    repe cmpsb
    jne .bad
    call nd_current
    cmp eax,1
    jne .bad
    mov dword [rel nd_learn_state],2
    jmp .out
.bad:
    mov dword [rel nd_learn_state],5
.out:
    pop r13
    pop r12
    pop rbx
    ret

; RDI=lowerhex NUL token,RSI=bounded output,EDX=maxbytes -> bytes or0.
nd_learn_unhex:
    push rbx
    push r12
    push r13
    mov r12,rsi
    mov r13d,edx
    xor ebx,ebx
.loop:
    cmp byte [rdi],0
    je .done
    cmp ebx,r13d
    jae .bad
    call nd_learn_nibble
    jc .bad
    shl al,4
    mov dl,al
    inc rdi
    call nd_learn_nibble
    jc .bad
    or al,dl
    mov [r12+rbx],al
    inc ebx
    inc rdi
    jmp .loop
.done:
    mov eax,ebx
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret
nd_learn_nibble:
    movzx eax,byte [rdi]
    sub eax,'0'
    cmp eax,9
    jbe .good
    sub eax,39
    cmp eax,10
    jb .bad
    cmp eax,15
    ja .bad
.good:
    clc
    ret
.bad:
    stc
    ret

; Native context only, outside console/IRQ frames. Never uses a guest key.
; DATA reader supplies the next verified sequence before calling this routine.
nd_learn_sign:
    push rbx
    push r12
    push r13
    mov eax,[rel nd_learn_state]
    cmp eax,2
    je .ready
    cmp eax,6
    jne .out
.ready:
    call nd_current
    cmp eax,1
    jne .bad
    call boot_ms_now
    test rax,rax
    jz .bad
    cmp rax,120000
    jae .bad
    mov r13,rax
    mov rbx,[rel nd_learn_buffer]
    test rbx,rbx
    jz .bad
    mov rdi,rbx
    xor eax,eax
    mov ecx,ND_LEARN_HEADER/8
    cld
    rep stosq
    mov rax,'DDLEARN1'
    mov [rbx],rax
    mov dword [rbx+8],1
    mov dword [rbx+12],ND_LEARN_HEADER
    mov rax,[rel nd_learn_sequence]
    test rax,rax
    jz .bad
    mov [rbx+16],rax
    mov rax,[rel nd_generation]
    mov [rbx+24],rax
    mov eax,[rel nd_bdf]
    mov [rbx+32],eax
    mov eax,[rel nd_learn_bytes]
    mov [rbx+36],eax
    lea rsi,[rel nd_nonce]
    lea rdi,[rbx+40]
    mov ecx,16
    rep movsb
    lea rsi,[rel nd_learn_volume_identity]
    lea rdi,[rbx+168]
    mov ecx,64
    rep movsb
    lea rsi,[rel nd_learn_digest]
    lea rdi,[rbx+88]
    mov ecx,32
    rep movsb
    mov dword [rbx+120],0x8007
    mov rax,[rel boot_tsc_start]
    mov [rbx+128],rax
    lea rdi,[rbx+136]
    mov rsi,[rel nd_profile]
    mov edx,280
    call sha256_hash
    test eax,eax
    jnz .bad
    lea rdi,[rbx+56]
    mov esi,32
    call node_identity_public
    test eax,eax
    jnz .pending
    mov rdi,rbx
    mov esi,448
    lea rdx,[rbx+448]
    mov ecx,64
    call node_identity_sign_active
    test eax,eax
    jnz .pending
    mov rdi,rbx
    mov esi,448
    lea rdx,[rbx+448]
    mov ecx,64
    call node_identity_verify
    test eax,eax
    jnz .bad
    call nd_current
    cmp eax,1
    jne .bad
    call boot_ms_now
    cmp rax,120000
    jae .bad
    sub rax,r13
    jc .bad
    cmp rax,4000
    jae .bad
    mov dword [rel nd_learn_state],3
    jmp .out
.pending:
    mov dword [rel nd_learn_state],6
    jmp .out
.bad:
    mov dword [rel nd_learn_state],5
.out:
    pop r13
    pop r12
    pop rbx
    ret

nd_learn_tag: db 'PAOS_DDOM_'
nd_learn_begin: db 'PAOS_DDOM_BEGIN',0
nd_learn_data: db 'PAOS_DDOM_DATA',0
nd_learn_end: db 'PAOS_DDOM_END',0
%include "core/abi/wdata.inc"
%macro WDATA_driver_domain_learned 0
align 8
nd_learn_buffer: dq 0
nd_learn_sequence: dq 1
nd_learn_volume_identity: times 64 db 0
nd_learn_epoch: dq 0
nd_learn_state: dd 0
nd_learn_received: dd 0
nd_learn_bytes: dd 0
nd_learn_pos: dd 0
nd_learn_line_ready: db 0
nd_learn_line_buf: times 641 db 0
nd_learn_t0: times 24 db 0
nd_learn_t1: times 17 db 0
nd_learn_t2: times 11 db 0
nd_learn_t3: times 11 db 0
nd_learn_t4: times 513 db 0
nd_learn_chunk: times 256 db 0
nd_learn_expected: times 32 db 0
nd_learn_digest: times 32 db 0
nd_learn_sha: times 112 db 0
%endmacro
WDATA_DEFER WDATA_driver_domain_learned
