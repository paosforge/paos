;; MODULE hv/filesystem_wire
;; LAYER 5
;; EXPORTS fsc_wire_request, fsc_wire_reply, fsc_grant_validate
;; IMPORTS
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; FSC1 v2, fixed256 raw hvc1. Pure bounded validation on PRIVATE snapshots.
; No address, grant or storage authority arrives over this channel. Sequence
; is per-control, monotonic in the native owner, not merely per-copy job.

; RDI=80-byte zero-padded basename, ECX=exact nonzero length ->0/-1.
fsc_wire_name:
    test ecx,ecx
    jz .bad
    cmp ecx,80
    ja .bad
    xor edx,edx
.scan:
    mov al,[rdi+rdx]
    cmp al,'0'
    jb .punct
    cmp al,'9'
    jbe .next
    cmp al,'A'
    jb .punct
    cmp al,'Z'
    jbe .next
    cmp al,'a'
    jb .punct
    cmp al,'z'
    jbe .next
.punct:
    test edx,edx
    jz .bad
    cmp al,'_'
    je .next
    cmp al,'-'
    je .next
    cmp al,'.'
    jne .bad
.next:
    inc edx
    cmp edx,ecx
    jb .scan
    cmp byte [rdi+rdx-1],'.'
    je .bad
.padding:
    cmp edx,80
    jae .ok
    cmp byte [rdi+rdx],0
    jne .bad
    inc edx
    jmp .padding
.ok:
    xor eax,eax
    ret
.bad:
    mov eax,-1
    ret

; RDI=private canonical256 request ->0/-1. All token bit patterns are syntax;
; only an independent native authorization can bind their meaning.
fsc_wire_request:
    push rbx
    mov rbx,rdi
    cmp dword [rbx],0x31435346
    jne .bad
    cmp word [rbx+4],2
    jne .bad
    movzx eax,word [rbx+6]
    dec eax
    cmp eax,3
    ja .bad
    cmp qword [rbx+72],0
    je .bad
    cmp qword [rbx+248],0
    je .bad
    cmp dword [rbx+84],0
    jne .bad
    lea rdi,[rbx+88]
    movzx ecx,word [rbx+80]
    call fsc_wire_name
    test eax,eax
    jnz .bad
    lea rdi,[rbx+168]
    movzx ecx,word [rbx+82]
    call fsc_wire_name
    test eax,eax
    jnz .bad
    mov ax,[rbx+80]
    cmp ax,[rbx+82]
    jne .ok
    lea rdi,[rbx+88]
    lea rsi,[rbx+168]
    movzx ecx,ax
    cld
    repe cmpsb
    je .bad
.ok:
    xor eax,eax
    pop rbx
    ret
.bad:
    mov eax,-1
    pop rbx
    ret

; RDI=private256 reply, RSI=exact outstanding256 request ->0/-1.
; Echoes cannot create completion, durability or backend-stopped authority.
fsc_wire_reply:
    push rbx
    mov rbx,rdi
    cmp dword [rbx],0x31435346
    jne .bad
    cmp word [rbx+4],2
    jne .bad
    mov ax,[rsi+6]
    or ax,0x8000
    cmp ax,[rbx+6]
    jne .bad
    mov ecx,4                       ; request + job
    lea rdi,[rbx+8]
    add rsi,8
    cld
    repe cmpsq
    jne .bad
    ; RSI now request+40: principal then attachment/generation.
    mov rax,[rsi]
    cmp rax,[rbx+200]
    jne .bad
    mov rax,[rsi+8]
    cmp rax,[rbx+208]
    jne .bad
    mov rax,[rsi+16]
    cmp rax,[rbx+40]
    jne .bad
    mov rax,[rsi+24]
    cmp rax,[rbx+48]
    jne .bad
    mov rax,[rsi+32]
    cmp rax,[rbx+56]
    jne .bad
    mov rax,[rsi+208]                ; exact per-control sequence@248
    cmp rax,[rbx+104]
    jne .bad
    cmp dword [rbx+64],7
    ja .bad
    cmp dword [rbx+68],15
    ja .bad
    test dword [rbx+88],~63
    jnz .bad
    mov eax,[rbx+92]
    test eax,eax
    jz .tail
    cmp eax,65536
    jne .bad
.tail:
    lea rdi,[rbx+216]
    mov ecx,5
    xor eax,eax
    cld
    repe scasq
    jne .bad
    xor eax,eax
    pop rbx
    ret
.bad:
    mov eax,-1
    pop rbx
    ret

; RDI=private320 native FSG1, RSI=private256 START ->0/-1.
; Package interface is independent of guest request bytes; this routine checks
; their correspondence AFTER the native supervisor constructs the grant.
fsc_grant_validate:
    push rbx
    push r12
    sub rsp,8
    mov rbx,rdi
    mov r12,rsi
    mov rdi,rsi
    call fsc_wire_request
    test eax,eax
    jnz .bad
    cmp word [r12+6],1
    jne .bad
    cmp dword [rbx],0x31475346       ; FSG1
    jne .bad
    cmp word [rbx+4],1
    jne .bad
    cmp word [rbx+6],1              ; first native package NTFS only
    jne .bad
    lea rdi,[rbx+8]
    lea rsi,[r12+8]
    mov ecx,9                       ; all four tokens and generation
    cld
    repe cmpsq
    jne .bad
    mov rax,[rbx+80]
    test rax,rax
    jz .bad
    cmp rax,0x40000000
    ja .bad
    mov eax,[rbx+88]
    test eax,eax
    jz .bad
    cmp eax,300000
    ja .bad
    mov eax,[rbx+92]
    cmp eax,[r12+80]
    jne .bad
    lea rdi,[rbx+104]
    lea rsi,[r12+88]
    mov ecx,20                      ; both exact80 basename fields
    repe cmpsq
    jne .bad
    mov rax,[rbx+264]
    or rax,[rbx+272]
    jz .bad                         ; native boot nonce must exist
    mov rax,[rbx+280]
    test rax,rax
    jz .bad
    test rax,511
    jnz .bad
    lea rdi,[rbx+288]
    mov ecx,4
    xor eax,eax
    repe scasq
    jne .bad
    xor eax,eax
    jmp .out
.bad:
    mov eax,-1
.out:
    add rsp,8
    pop r12
    pop rbx
    ret
