;; MODULE core/lib/sha1
;; LAYER 1
;; EXPORTS sha1_stream_init, sha1_stream_update, sha1_stream_final, sha1_hash
;; IMPORTS
;; CAPS
;; OWNER rc-sec-claude
;; CONTEXT: any  (caller-owned context and stack scratch; no static state)
; SHA-1 for RFC 4226/6238 HMAC and WPA2 PBKDF2 interoperability ONLY.
; New signatures, manifests
; and artifact digests must continue to use the existing stronger algorithms.
; Independent implementation of RFC 3174 sections 4-6 (no reference-code copy).
; https://www.rfc-editor.org/rfc/rfc3174
;
; Context: state[5] + status u32 (0 live/1 finalized), total u64, used u64,
; block[64]. Caller owns 104 writable bytes and valid buffers; no overlap with
; the context. Nonempty data and output pointers must be valid. SysV callee-save
; registers preserved, DF cleared. Validation failures leave context/output alone.
; Final destroys context then marks it finalized; init is required for reuse.
S1_STATE equ 0
S1_STATUS equ 20
S1_TOTAL equ 24
S1_USED equ 32
S1_BLOCK equ 40
S1_CTX_SZ equ 104

sha1_stream_init:
    cld
    push rdi
    xor eax,eax
    mov ecx,S1_CTX_SZ / 8
    rep stosq
    pop rdi
    mov dword [rdi],0x67452301
    mov dword [rdi+4],0xefcdab89
    mov dword [rdi+8],0x98badcfe
    mov dword [rdi+12],0x10325476
    mov dword [rdi+16],0xc3d2e1f0
    ret

; (RDI=ctx, RSI=data, RDX=length) -> EAX 0/-1.
; Reject lengths outside SHA-1's 64-bit BIT count before touching data.
sha1_stream_update:
    cld
    cmp dword [rdi+S1_STATUS],0
    jne .invalid
    cmp qword [rdi+S1_USED],63
    ja .invalid
    mov rax,[rdi+S1_TOTAL]
    add rax,rdx
    jc .invalid
    mov r9,0x1fffffffffffffff
    cmp rax,r9
    ja .invalid
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    mov [r12+S1_TOTAL],rax
    mov rbx,[r12+S1_USED]
    test rbx,rbx
    jz .blocks
    mov r15d,64
    sub r15,rbx
    cmp r15,r14
    cmova r15,r14
    lea rdi,[r12+S1_BLOCK+rbx]
    mov rsi,r13
    mov rcx,r15
    rep movsb
    add r13,r15
    sub r14,r15
    add rbx,r15
    mov [r12+S1_USED],rbx
    cmp rbx,64
    jne .ok
    mov rdi,r12
    lea rsi,[r12+S1_BLOCK]
    call sha1_transform
    mov qword [r12+S1_USED],0
.blocks:
    cmp r14,64
    jb .tail
    mov rdi,r12
    mov rsi,r13
    call sha1_transform
    add r13,64
    sub r14,64
    jmp .blocks
.tail:
    lea rdi,[r12+S1_BLOCK]
    mov rsi,r13
    mov rcx,r14
    rep movsb
    mov [r12+S1_USED],r14
.ok:
    xor eax,eax
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.invalid:
    mov eax,-1
    ret

; (RDI=ctx, RSI=out20) -> EAX 0/-1. No truncation, one final only.
sha1_stream_final:
    cld
    cmp dword [rdi+S1_STATUS],0
    jne .invalid
    cmp qword [rdi+S1_USED],63
    ja .invalid
    mov rax,0x1fffffffffffffff
    cmp [rdi+S1_TOTAL],rax
    ja .invalid
    push rbx
    push r12
    push r13
    mov r12,rdi
    mov r13,rsi
    mov rbx,[r12+S1_USED]
    mov byte [r12+S1_BLOCK+rbx],0x80
    inc rbx
    cmp rbx,56
    jbe .one
    lea rdi,[r12+S1_BLOCK+rbx]
    mov ecx,64
    sub rcx,rbx
    xor eax,eax
    rep stosb
    mov rdi,r12
    lea rsi,[r12+S1_BLOCK]
    call sha1_transform
    xor ebx,ebx
.one:
    lea rdi,[r12+S1_BLOCK+rbx]
    mov ecx,56
    sub rcx,rbx
    xor eax,eax
    rep stosb
    mov rax,[r12+S1_TOTAL]
    shl rax,3
    bswap rax
    mov [r12+S1_BLOCK+56],rax
    mov rdi,r12
    lea rsi,[r12+S1_BLOCK]
    call sha1_transform
    xor ecx,ecx
.digest:
    mov eax,[r12+rcx*4]
    bswap eax
    mov [r13+rcx*4],eax
    inc ecx
    cmp ecx,5
    jb .digest
    mov rdi,r12
    xor eax,eax
    mov ecx,S1_CTX_SZ / 8
    rep stosq
    mov dword [r12+S1_STATUS],1
    pop r13
    pop r12
    pop rbx
    ret
.invalid:
    mov eax,-1
    ret

; (RDI=out20, RSI=data, RDX=length) -> EAX 0/-1.
sha1_hash:
    push r12
    push r13
    push r14
    sub rsp,112
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    mov rdi,rsp
    call sha1_stream_init
    mov rdi,rsp
    mov rsi,r13
    mov rdx,r14
    call sha1_stream_update
    test eax,eax
    jnz .wipe
    mov rdi,rsp
    mov rsi,r12
    call sha1_stream_final
.wipe:
    mov r14d,eax
    mov rdi,rsp
    xor eax,eax
    mov ecx,14
    rep stosq
    mov eax,r14d
    add rsp,112
    pop r14
    pop r13
    pop r12
    ret

; Internal compression, 80 rounds, all message schedule in wiped stack storage.
sha1_transform:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    sub rsp,320
    mov r12,rdi
    mov r13,rsp
    xor ecx,ecx
.load:
    mov eax,[rsi+rcx*4]
    bswap eax
    mov [r13+rcx*4],eax
    inc ecx
    cmp ecx,16
    jb .load
.expand:
    mov eax,[r13+rcx*4-12]
    xor eax,[r13+rcx*4-32]
    xor eax,[r13+rcx*4-56]
    xor eax,[r13+rcx*4-64]
    rol eax,1
    mov [r13+rcx*4],eax
    inc ecx
    cmp ecx,80
    jb .expand
    mov r8d,[r12]
    mov r9d,[r12+4]
    mov r10d,[r12+8]
    mov r11d,[r12+12]
    mov ebx,[r12+16]
    xor r14d,r14d
.round:
    cmp r14d,20
    jae .r20
    mov eax,r10d
    xor eax,r11d
    and eax,r9d
    xor eax,r11d
    mov ecx,0x5a827999
    jmp .mix
.r20:
    cmp r14d,40
    jae .r40
    mov ecx,0x6ed9eba1
    jmp .parity
.r40:
    cmp r14d,60
    jae .r60
    mov eax,r9d
    and eax,r10d
    mov edx,r9d
    or edx,r10d
    and edx,r11d
    or eax,edx
    mov ecx,0x8f1bbcdc
    jmp .mix
.r60:
    mov ecx,0xca62c1d6
.parity:
    mov eax,r9d
    xor eax,r10d
    xor eax,r11d
.mix:
    add eax,ecx
    add eax,ebx
    add eax,[r13+r14*4]
    mov edx,r8d
    rol edx,5
    add eax,edx
    mov ebx,r11d
    mov r11d,r10d
    mov r10d,r9d
    ror r10d,2
    mov r9d,r8d
    mov r8d,eax
    inc r14d
    cmp r14d,80
    jb .round
    add [r12],r8d
    add [r12+4],r9d
    add [r12+8],r10d
    add [r12+12],r11d
    add [r12+16],ebx
    mov rdi,rsp
    xor eax,eax
    mov ecx,40
    rep stosq
    xor r8d,r8d
    xor r9d,r9d
    xor r10d,r10d
    xor r11d,r11d
    xor edx,edx
    add rsp,320
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
