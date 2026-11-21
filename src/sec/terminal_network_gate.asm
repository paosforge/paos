;; MODULE sec/terminal_network_gate
;; LAYER 6
;; PURPOSE Bounded pure hostname and TLS ClientHello leaves for Terminal egress.
;; EXPORTS terminal_network_host_canon, terminal_network_host_allowed, terminal_network_clienthello
;; IMPORTS
;; OWNER saga:terminal_network
;; CONTEXT: any
;
; Native-only leaves, NOT authorization or a network endpoint. The composing
; broker must prove current actual tools VM/owner/policy, port443, public DNS
; destination and original TCP custody at every effect/copyout. No leaf reads
; a guest pointer, performs I/O, retains pointers or installs an allowlist.
; Buffers below are caller-owned mapped native spans, mutually disjoint.
; All SysV callee-saved registers are preserved. No shared mutable scratch.

; RDI out256, RSI input, EDX length -> EAX canonical length, or -1.
; Validate before writing: refusal leaves all256 output bytes unchanged.
; ASCII DNS labels only, at least two labels, final label starts with a-z.
; The latter excludes numeric, octal and hex IPv4 alternatives as well as
; single-integer addresses. No implicit IDNA conversion or trailing-dot alias.
terminal_network_host_canon:
    test rdi,rdi
    jz .bad
    test rsi,rsi
    jz .bad
    test edx,edx
    jz .bad
    cmp edx,253
    ja .bad
    xor r8d,r8d                 ; current label length
    xor r9d,r9d                 ; final label start
    xor r10d,r10d               ; completed labels
    xor ecx,ecx
.validate:
    movzx eax,byte [rsi+rcx]
    cmp al,'.'
    je .dot
    cmp al,'A'
    jb .lowered
    cmp al,'Z'
    ja .lowered
    add al,32
.lowered:
    cmp al,'a'
    jb .number
    cmp al,'z'
    jbe .char
.number:
    cmp al,'0'
    jb .hyphen
    cmp al,'9'
    jbe .char
.hyphen:
    cmp al,'-'
    jne .bad
    test r8d,r8d
    jz .bad
.char:
    inc r8d
    cmp r8d,63
    ja .bad
    jmp .advance
.dot:
    test r8d,r8d
    jz .bad
    cmp byte [rsi+rcx-1],'-'
    je .bad
    xor r8d,r8d
    lea r9d,[ecx+1]
    inc r10d
.advance:
    inc ecx
    cmp ecx,edx
    jb .validate
    test r8d,r8d
    jz .bad
    test r10d,r10d
    jz .bad
    cmp byte [rsi+rcx-1],'-'
    je .bad
    ; Lowercase only for validation; input remains untouched.
    movzx eax,byte [rsi+r9]
    or al,32
    cmp al,'a'
    jb .bad
    cmp al,'z'
    ja .bad
.copy_start:
    xor ecx,ecx
.copy:
    mov al,[rsi+rcx]
    cmp al,'A'
    jb .store
    cmp al,'Z'
    ja .store
    add al,32
.store:
    mov [rdi+rcx],al
    inc ecx
    cmp ecx,edx
    jb .copy
    mov r8d,edx
    add rdi,rcx
    mov ecx,256
    sub ecx,r8d
    xor eax,eax
    cld
    rep stosb
    mov eax,r8d
    ret
.bad:
    mov eax,-1
    ret

; RDI authenticated canonical slots256, RSI canonical query, EDX query length,
; ECX count0..16 -> EAX1 exact match, else0. Each slot: length:u8 + host253 +
; zero padding2. Store validation is the caller's job. Default count is zero;
; no host is compiled into this module. This comparison grants no authority.
terminal_network_host_allowed:
    test rdi,rdi
    jz .no
    test rsi,rsi
    jz .no
    test edx,edx
    jz .no
    cmp edx,253
    ja .no
    cmp ecx,16
    ja .no
    test ecx,ecx
    jz .no
.slot:
    movzx eax,byte [rdi]
    cmp eax,edx
    jne .next
    xor r9d,r9d
.compare:
    mov al,[rsi+r9]
    cmp al,[rdi+r9+1]
    jne .next
    inc r9d
    cmp r9d,edx
    jb .compare
    mov eax,1
    ret
.next:
    add rdi,256
    dec ecx
    jnz .slot
.no:
    xor eax,eax
    ret

; RDI canonical host, ESI host length1..253; RDX complete buffered wire prefix,
; ECX wire length0..16384; R8 private scratch16384 -> EAX -1 invalid,0 incomplete,
; 1 complete exact-SNI ClientHello. Reassemble from this prefix on every call;
; stale scratch never supplies missing input. Scratch may contain plaintext
; handshake bytes and must be wiped by the broker on retirement. Buffer raw
; wire separately and forward NONE until1 plus fresh broker authorization.
; One message only. Every input byte must belong to that ClientHello. No
; trailing records/CCS/early data, ECH, duplicate SNI or non-null compression.
; A monotonic cumulative deadline belongs to the native connection, not here.
; This does not decrypt/verify TLS or enforce encrypted HTTP authority.
terminal_network_clienthello:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov rbx,rdi
    mov ebp,esi
    mov r12,rdx
    mov r13d,ecx
    mov r14,r8
    test rbx,rbx
    jz .bad
    test ebp,ebp
    jz .bad
    cmp ebp,253
    ja .bad
    test r12,r12
    jz .bad
    test r14,r14
    jz .bad
    cmp r13d,16384
    ja .bad
    xor r15d,r15d               ; raw wire consumed
    xor r9d,r9d                 ; assembled handshake length
    xor r10d,r10d               ; expected complete message length
.record:
    mov rax,r13
    sub rax,r15
    cmp rax,5
    jb .incomplete
    cmp byte [r12+r15],22
    jne .bad
    cmp byte [r12+r15+1],3
    jne .bad
    movzx eax,byte [r12+r15+2]
    dec eax
    cmp eax,2
    ja .bad
    movzx r8d,word [r12+r15+3]
    rol r8w,8
    test r8d,r8d
    jz .bad
    lea r11,[r15+r8+5]
    cmp r11,16384
    ja .bad
    cmp r11,r13
    ja .incomplete
    lea rax,[r9+r8]
    cmp rax,16384
    ja .bad
    lea rsi,[r12+r15+5]
    lea rdi,[r14+r9]
    mov ecx,r8d
    cld
    rep movsb
    add r9,r8
    mov r15,r11
    cmp r9d,4
    jb .message_incomplete
    cmp byte [r14],1
    jne .bad
    mov r10d,[r14]
    bswap r10d
    and r10d,0x00ffffff
    add r10d,4
    cmp r10d,44                 ; fixed fields + minimal vectors
    jb .bad
    cmp r10d,16384
    ja .bad
    cmp r9,r10
    ja .bad
    jb .message_incomplete
    cmp r15,r13
    jne .bad
    jmp .parse
.message_incomplete:
    cmp r15,r13
    jb .record
.incomplete:
    cmp r13d,16384
    jae .bad
    xor eax,eax
    jmp .done
.parse:
    lea r12,[r14+4]
    lea r13,[r14+r9]
    cmp byte [r12],3
    jne .bad
    movzx eax,byte [r12+1]
    dec eax
    cmp eax,2
    ja .bad
    add r12,34                 ; legacy version + random32
    movzx eax,byte [r12]        ; minimum44 checked above
    cmp eax,32
    ja .bad
    lea r12,[r12+rax+1]
    lea rax,[r12+2]
    cmp rax,r13
    ja .bad
    movzx eax,word [r12]
    rol ax,8
    cmp eax,2
    jb .bad
    test al,1
    jnz .bad
    lea r12,[r12+rax+2]
    lea rax,[r12+2]
    cmp rax,r13
    ja .bad
    cmp word [r12],1            ; exactly one null compression method
    jne .bad
    add r12,2
    lea rax,[r12+2]
    cmp rax,r13
    ja .bad
    movzx eax,word [r12]
    rol ax,8
    lea r12,[r12+2]
    add rax,r12
    cmp rax,r13
    jne .bad
    xor r15d,r15d               ; SNI seen, exactly once
.extension:
    cmp r12,r13
    je .extensions_end
    lea rax,[r12+4]
    cmp rax,r13
    ja .bad
    movzx eax,word [r12]
    rol ax,8
    movzx r8d,word [r12+2]
    rol r8w,8
    add r12,4
    lea r11,[r12+r8]
    cmp r11,r13
    ja .bad
    cmp eax,0xfe0d
    je .bad
    cmp eax,0xffce              ; legacy ESNI can hide the inner name too
    je .bad
    cmp eax,0xfe08              ; ECH draft extension code points
    jb .not_ech_draft
    cmp eax,0xfe0c
    jbe .bad
.not_ech_draft:
    cmp eax,42
    je .bad
    test eax,eax
    jnz .extension_next
    test r15d,r15d
    jnz .bad
    mov r15d,1
    lea eax,[rbp+5]
    cmp eax,r8d
    jne .bad
    movzx eax,word [r12]
    rol ax,8
    add eax,2
    cmp eax,r8d
    jne .bad
    cmp byte [r12+2],0
    jne .bad
    movzx eax,word [r12+3]
    rol ax,8
    cmp eax,ebp
    jne .bad
    xor ecx,ecx
.sni:
    mov al,[r12+rcx+5]
    cmp al,'A'
    jb .sni_compare
    cmp al,'Z'
    ja .sni_compare
    add al,32
.sni_compare:
    cmp al,[rbx+rcx]
    jne .bad
    inc ecx
    cmp ecx,ebp
    jb .sni
.extension_next:
    mov r12,r11
    jmp .extension
.extensions_end:
    cmp r15d,1
    jne .bad
    mov eax,1
    jmp .done
.bad:
    mov eax,-1
.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
