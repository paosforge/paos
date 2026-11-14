;; MODULE hv/wifi_wire
;; LAYER 5
;; EXPORTS wfw_request_validate, wfw_ready_validate, wfw_reply_validate
;; IMPORTS
;; CAPS
;; OWNER rc-vm-claude
;; CONTEXT: bsp_only
; PRIVATE fixed snapshots only. Syntax/echo checks confer no native authority.
; WFA1/1/256: START64@8, one-use nonce16@16, NDnonce16@32, BDF32@48,
; mode32@52, epoch64@56, native deadline_ms64@64, profileid16@72,
; revision64@88, ssidlen32@96, budget_ms32@100, paddedSSID32@104,
; binaryPSK32@136, ownerhash32@168, nodehash32@200, zero24@232.
; The guest budget never extends the original native deadline.
wfw_nonzero16:
    mov rax,[rdi]
    or rax,[rdi+8]
    setnz al
    movzx eax,al
    ret
wfw_ndnonce:
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
    test edx,edx
    jz .bad
    xor eax,eax
    ret
.bad:
    mov eax,-1
    ret
; RDI=private request,RSI=exact size ->0/-1. Zero PSK is valid binary.
wfw_request_validate:
    push rbx
    mov rbx,rdi
    test rdi,rdi
    jz .bad
    cmp rsi,256
    jne .bad
    cmp dword [rbx],'WFA1'
    jne .bad
    cmp word [rbx+4],1
    jne .bad
    cmp word [rbx+6],256
    jne .bad
    cmp qword [rbx+8],0
    je .bad
    cmp dword [rbx+12],0
    jne .bad
    lea rdi,[rbx+16]
    call wfw_nonzero16
    test eax,eax
    jz .bad
    lea rdi,[rbx+32]
    call wfw_ndnonce
    test eax,eax
    jnz .bad
    cmp dword [rbx+48],0xFFFF
    ja .bad
    cmp dword [rbx+52],1
    jne .bad
    cmp qword [rbx+56],0
    je .bad
    cmp qword [rbx+64],0
    je .bad
    lea rdi,[rbx+72]
    call wfw_nonzero16
    test eax,eax
    jz .bad
    cmp qword [rbx+88],0
    je .bad
    mov ecx,[rbx+96]
    cmp ecx,1
    jb .bad
    cmp ecx,32
    ja .bad
    cmp dword [rbx+100],1
    jb .bad
    cmp dword [rbx+100],30000
    ja .bad
.pad:
    cmp ecx,32
    jae .context
    cmp byte [rbx+rcx+104],0
    jne .bad
    inc ecx
    jmp .pad
.context:
    mov rax,[rbx+168]
    or rax,[rbx+176]
    or rax,[rbx+184]
    or rax,[rbx+192]
    jz .bad
    mov rax,[rbx+200]
    or rax,[rbx+208]
    or rax,[rbx+216]
    or rax,[rbx+224]
    jz .bad
    mov rax,[rbx+232]
    or rax,[rbx+240]
    or rax,[rbx+248]
    jnz .bad
    xor eax,eax
    pop rbx
    ret
.bad:
    mov eax,-1
    pop rbx
    ret
; RDI=READY64,RSI=size,RDX=actualSTART,RCX=actualNDnonce16 ->0/-1.
wfw_ready_validate:
    cmp rsi,64
    jne .bad
    test rdi,rdi
    jz .bad
    test rcx,rcx
    jz .bad
    cmp dword [rdi],'WFRD'
    jne .bad
    cmp word [rdi+4],1
    jne .bad
    cmp word [rdi+6],64
    jne .bad
    test rdx,rdx
    jz .bad
    cmp [rdi+8],rdx
    jne .bad
    mov rax,[rcx]
    cmp [rdi+16],rax
    jne .bad
    mov rax,[rcx+8]
    cmp [rdi+24],rax
    jne .bad
    mov rax,[rdi+32]
    or rax,[rdi+40]
    or rax,[rdi+48]
    or rax,[rdi+56]
    jnz .bad
    xor eax,eax
    ret
.bad:
    mov eax,-1
    ret
; RDI=ACK64,RSI=size,RDX=retainedrequest256 ->0/-1.
; Status0 association observation,1 refusal,2 uncertain; none is Internet.
wfw_reply_validate:
    cmp rsi,64
    jne .bad
    test rdi,rdi
    jz .bad
    test rdx,rdx
    jz .bad
    cmp dword [rdi],'WFAA'
    jne .bad
    cmp word [rdi+4],1
    jne .bad
    cmp word [rdi+6],64
    jne .bad
    mov rax,[rdx+8]
    cmp [rdi+8],rax
    jne .bad
    mov rax,[rdx+16]
    cmp [rdi+16],rax
    jne .bad
    mov rax,[rdx+24]
    cmp [rdi+24],rax
    jne .bad
    cmp dword [rdi+32],2
    ja .bad
    cmp dword [rdi+36],0
    jne .bad
    mov rax,[rdx+72]
    cmp [rdi+40],rax
    jne .bad
    mov rax,[rdx+80]
    cmp [rdi+48],rax
    jne .bad
    mov rax,[rdx+88]
    cmp [rdi+56],rax
    jne .bad
    xor eax,eax
    ret
.bad:
    mov eax,-1
    ret
