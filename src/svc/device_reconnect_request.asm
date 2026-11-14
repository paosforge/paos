;; MODULE svc/device_reconnect_request
;; LAYER 5
;; EXPORTS device_reconnect_request
;; IMPORTS svc/device_reconnect
;; CAPS
;; OWNER rc-vm-claude
; RDI=original SELFTEST argument. Return0 only after complete strict parsing.
; The class coordinator alone checks actual selected incarnation and consumes
; its effect before power. No controller pointer or arbitrary class operation.
device_reconnect_request:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx,rdi
    test rdi,rdi
    jz .bad
    cmp dword [rbx],'RECO'
    jne .bad
    cmp byte [rbx+4],'N'
    jne .bad
    xor r12d,r12d
    cmp byte [rbx+5],'Q'
    je .index
    inc r12d
    cmp byte [rbx+5],'O'
    je .index
    inc r12d
    cmp byte [rbx+5],'S'
    je .index
%ifidn PAOS_LAB_D8_HID_REJECT,1
    inc r12d
    cmp byte [rbx+5],'F'
    jne .bad
    cmp byte [rbx+6],'4' ; controlled HID only, never media
    je .bad
%else
    jmp .bad
%endif
.index:
    movzx r13d,byte [rbx+6]
    sub r13d,'0'
    cmp r13d,4
    ja .bad
    cmp byte [rbx+7],' '
    jne .bad
    lea rdi,[rbx+8]
    mov ecx,24
    call device_reconnect_hex
    test edx,edx
    jnz .bad
    xor r14d,r14d
    xor r15d,r15d
    xor r8d,r8d
    test r12d,r12d
    jz .end
    cmp byte [rdi],'.'
    jne .bad
    inc rdi
    mov ecx,2
    call device_reconnect_hex
    test edx,edx
    jnz .bad
    cmp eax,3
    ja .bad
    mov r14d,eax
    cmp byte [rdi],'.'
    jne .bad
    inc rdi
    mov ecx,2
    call device_reconnect_hex
    test edx,edx
    jnz .bad
    test eax,eax
    jz .bad
    cmp eax,31
    ja .bad
    mov r15d,eax
    cmp byte [rdi],'.'
    jne .bad
    inc rdi
    mov ecx,16
    call device_reconnect_hex
    test edx,edx
    jnz .bad
    test rax,rax
    jz .bad
    mov r8,rax
.end:
    cmp byte [rdi],0
    jne .bad
    mov edi,r12d
    mov esi,r13d
    mov edx,r14d
    mov ecx,r15d
    call device_reconnect_control
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

; Advance RDI by exactly ECX lower-case hex digits. Nonce24 is validated but
; deliberately truncated locally (unused); the incarnation16 is a full u64.
; EDX=0/-1, RAX=value. No read past the first invalid/terminating byte.
device_reconnect_hex:
    xor eax,eax
.next:
    movzx edx,byte [rdi]
    sub edx,'0'
    cmp edx,9
    jbe .digit
    sub edx,'a'-'0'
    cmp edx,5
    ja .bad
    add edx,10
.digit:
    shl rax,4
    or rax,rdx
    inc rdi
    dec ecx
    jnz .next
    xor edx,edx
    ret
.bad:
    mov edx,-1
    ret
