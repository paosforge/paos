;; MODULE hv/nic_observation
;; LAYER 5
;; EXPORTS nics_register_verbs
;; IMPORTS hv/nic_selection, hv/driver_domain_command, hv/vmx, svc/command
;; CAPS extension
;; OWNER saga:device_assignment_portability
;; CONTEXT: bsp_only
; Read-only diagnostic around the unchanged selected-NIC/group/claim snapshot.
; No ownership or lifecycle state; ordinary shared registry and output only.
nics_register_verbs:
    push rbx
    lea rdi,[rel nics_verb]
    lea rsi,[rel nd_command_nics]
    xor edx,edx
    mov ecx,ARGT_TEXT
    xor r8d,r8d
    xor r9d,r9d
    call command_register_verb
    pop rbx
    ret

; NICS hhhh probe16 sequence page. Sequence0/page0 captures once; pages1/2
; read that frozen observation in order. Independent of START/domain cache.
; Every request is bounded to63 bytes and the ordinary read-only registry/auth.
; No guest, assignment, reset, claim transition or physical config write.
nd_command_nics:
    push rbx
    push r12
    push r13
    push r14
    sub rsp,8
    call cmd_handler_prologue
    mov r12,rsi
    mov rbx,[rdi+REQ_ARG]
    call hv_out_reset
    test rbx,rbx
    jz .syntax
    xor ecx,ecx
.bound:
    cmp byte [rbx+rcx],0
    je .parse
    inc ecx
    cmp ecx,64
    jb .bound
    jmp .syntax
.parse:
    mov rdi,rbx
    lea rsi,[rel nics_arg_bdf]
    mov edx,5
    call nd_token
    test rax,rax
    jz .syntax
    mov rdi,rax
    lea rsi,[rel nics_arg_probe]
    mov edx,17
    call nd_token
    test rax,rax
    jz .syntax
    mov rdi,rax
    lea rsi,[rel nics_arg_seq]
    mov edx,11
    call nd_token
    test rax,rax
    jz .syntax
    mov rdi,rax
    lea rsi,[rel nics_arg_page]
    mov edx,2
    call nd_token
    test rax,rax
    jz .syntax
    cmp byte [rax],0
    jne .syntax
    lea rdi,[rel nics_arg_bdf]
    mov esi,16
    mov edx,4
    call nd_number
    jc .syntax
    cmp ecx,4
    jne .syntax
    mov r13d,eax
    lea rdi,[rel nics_arg_probe]
    call nics_probe_valid
    test eax,eax
    jz .syntax
    lea rdi,[rel nics_arg_seq]
    mov esi,10
    mov edx,10
    call nd_number
    jc .syntax
    mov r14d,eax
    movzx ebx,byte [rel nics_arg_page]
    sub ebx,'0'
    cmp ebx,2
    ja .syntax
    test r14d,r14d
    jnz .cached
    test ebx,ebx
    jnz .syntax
    ; A new capture invalidates prior success even if selection refuses or
    ; the sequence exhausts. Never expose the untouched output on refusal.
    mov dword [rel nics_valid],0
    mov dword [rel nics_refusal_bytes],0
    cmp dword [rel nics_sequence],0xffffffff
    je .cache_error
    inc dword [rel nics_sequence]
    mov [rel nics_bdf],r13d
    lea rdi,[rel nics_probe]
    lea rsi,[rel nics_arg_probe]
    mov ecx,17
    cld
    rep movsb
    mov edi,r13d
    lea rsi,[rel nics_cache]
    mov edx,592
    call nic_select_snapshot
    cmp eax,14
    ja .cache_error
    mov [rel nics_status],eax
    cmp eax,7
    jne .captured
    cmp edx,272
    jne .captured
    test rcx,rcx
    jz .captured
    ; Copy immediately, before another producer can change BSP scratch.
    ; Builder only initializes used records: canonicalize unused tail to zero.
    mov rsi,rcx
    movzx r8d,byte [rsi+3]
    test r8d,r8d
    jz .cache_error
    cmp r8d,32
    ja .cache_error
    lea rdi,[rel nics_cache]
    mov ecx,272/8
    xor eax,eax
    cld
    rep stosq
    lea rdi,[rel nics_cache]
    lea ecx,[r8d+2]
    rep movsq
    mov dword [rel nics_refusal_bytes],272
.captured:
    mov dword [rel nics_next_page],1
    mov dword [rel nics_valid],1
    jmp .emit
.cached:
    test ebx,ebx
    jz .cache_error
    cmp dword [rel nics_valid],1
    jne .cache_error
    cmp r14d,[rel nics_sequence]
    jne .cache_error
    cmp r13d,[rel nics_bdf]
    jne .cache_error
    cmp dword [rel nics_status],0
    je .identity
    cmp dword [rel nics_status],7
    jne .cache_error
    cmp dword [rel nics_refusal_bytes],272
    jne .cache_error
    cmp ebx,1
    jne .cache_error
.identity:
    cmp ebx,[rel nics_next_page]
    jne .cache_error
    lea rdi,[rel nics_arg_probe]
    lea rsi,[rel nics_probe]
    mov ecx,17
    cld
    repe cmpsb
    jne .cache_error
    inc dword [rel nics_next_page]
.emit:
    lea rdi,[rel nics_ok]
    call hv_out_str
    lea rdi,[rel nics_probe]
    call hv_out_str
    mov edi,[rel nics_bdf]
    call nd_info_number
    mov edi,[rel nics_sequence]
    call nd_info_number
    mov edi,[rel nics_status]
    call nd_info_number
    mov edi,ebx
    call nd_info_number
    xor r14d,r14d
    cmp dword [rel nics_status],0
    jne .refusal_length
    mov r14d,256
    cmp ebx,2
    jne .length
    mov r14d,80
    jmp .length
.refusal_length:
    cmp dword [rel nics_status],7
    jne .length
    cmp dword [rel nics_refusal_bytes],272
    jne .length
    mov r14d,256
    test ebx,ebx
    jz .length
    mov r14d,16
.length:
    mov edi,r14d
    call nd_info_number
    lea rdi,[rel nics_space]
    call hv_out_str
    test r14d,r14d
    jz .empty
    shl ebx,8
    lea r13,[rel nics_cache]
    add r13,rbx
    add r14,r13
.hex:
    lea rdx,[rel nics_hex]
    movzx eax,byte [r13]
    shr eax,4
    mov al,[rdx+rax]
    call hv_out_putc
    lea rdx,[rel nics_hex]
    movzx eax,byte [r13]
    and eax,15
    mov al,[rdx+rax]
    call hv_out_putc
    inc r13
    cmp r13,r14
    jb .hex
    jmp .ready
.empty:
    mov al,'-'
    call hv_out_putc
    jmp .ready
.syntax:
    lea rdi,[rel nics_syntax]
    call hv_out_str
    jmp .ready
.cache_error:
    lea rdi,[rel nics_stale]
    call hv_out_str
.ready:
    mov byte [rel hv_out_ready],1
    mov qword [r12+RSP_CODE],CMDE_OK
    add rsp,8
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Private wire-token validation, independent of any START/domain nonce.
nics_probe_valid:
    xor ecx,ecx
    xor edx,edx
.loop:
    mov al,[rdi+rcx]
    cmp al,'0'
    jb .bad
    cmp al,'9'
    jbe .digit
    cmp al,'a'
    jb .bad
    cmp al,'f'
    ja .bad
.digit:
    cmp al,'0'
    je .next
    inc edx
.next:
    inc ecx
    cmp ecx,16
    jb .loop
    cmp byte [rdi+16],0
    jne .bad
    test edx,edx
    setnz al
    movzx eax,al
    ret
.bad:
    xor eax,eax
    ret

nics_verb: db 'NICS',0
nics_ok: db 'NICS1 ',0
nics_syntax: db 'NICSERR1 1',0
nics_stale: db 'NICSERR1 2',0
nics_space: db ' ',0
nics_hex: db '0123456789abcdef'
%include "core/abi/wdata.inc"
%macro WDATA_hv_nic_observation 0
align 8
nics_sequence: dq 0
nics_valid: dd 0
nics_bdf: dd 0
nics_status: dd 0
nics_refusal_bytes: dd 0
nics_next_page: dd 0
nics_probe: times 17 db 0
nics_arg_bdf: times 5 db 0
nics_arg_probe: times 17 db 0
nics_arg_seq: times 11 db 0
nics_arg_page: times 2 db 0
align 16
nics_cache: times 592 db 0
%endmacro
WDATA_DEFER WDATA_hv_nic_observation
