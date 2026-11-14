;; MODULE sec/totp
;; LAYER 2
;; EXPORTS vfy_hotp_ascii, vfy_totp_prepare
;; IMPORTS core/lib/hmac_sha1, core/lib/hmac_sha256
;; CAPS
;; OWNER rc-sec-claude
;; CONTEXT: bsp_only  (existing HMAC-SHA256 uses module-static SHA256 scratch)
; RFC 4226 / RFC 6238 numeric foundation. No enrollment, authentication, state,
; clock acquisition, rate limiter or delivery. No boot registration in this slice.
; https://www.rfc-editor.org/rfc/rfc4226
; https://www.rfc-editor.org/rfc/rfc6238
;
; Native trusted caller only: valid stable input buffers, disjoint output, no
; IRQ/AP entry. All key/code temporary stack buffers are wiped before return.
; Dynamic truncation uses the standard digest offset; fixed-length comparison
; never exits on a differing digit. This is not a formal CPU timing guarantee.
;
; vfy_hotp_ascii(RDI=out9, RSI=key, RDX=key_len, RCX=counter,
;                R8D=digits (6/8), R9D=algorithm (1 SHA1/2 SHA256)) -> EAX 0/-1.
; Requires 20..64 key bytes. Invalid arguments leave output untouched. Success
; writes exactly nine bytes: zero-padded decimal digits, NUL, then zero padding.
;
; vfy_totp_prepare(RDI=request, RSI=64, RDX=out16, RCX=capacity>=16)
; -> EAX 0 prepared / -1 invalid / -2 untrusted clock / -3 no eligible match.
; Every writable out16 is zeroed on refusal; insufficient/null output untouched.
; request64 little endian, immutable:
;  +0 version u32=1, +4 flags u32 (1 trusted UTC, 2 has replay floor)
;  +8 key ptr, +16 key len u64 (20..64), +24 UTC seconds u64 (<=INT64_MAX)
;  +32 last accepted counter u64 (zero if flag2 absent), +40 code ptr
;  +48 code length/digits u32 (6/8), +52 algorithm u32 (1/2), +56 reserved u64=0.
; out16: +0 candidate counter u64, +8 reserved u64=0. Counter zero is valid.
; Window current-1..current+1 (at epoch zero: zero and one). If multiple
; candidates collide, choose the HIGHEST eligible counter, conservatively.
; Caller must serialize, authenticate/anti-rollback the stored floor, persist
; the candidate BEFORE authorization, enforce rate limits and account/session/
; request binding. Repeated prepare calls intentionally return the same result:
; this API grants NO authentication and does NOT implement durable single-use.
VFY_TOTP_REQUEST_SIZE equ 64
VFY_OTP_FRAME equ 72

vfy_hotp_ascii:
    cld
    test rdi,rdi
    jz .invalid
    test rsi,rsi
    jz .invalid
    cmp rdx,20
    jb .invalid
    cmp rdx,64
    ja .invalid
    cmp r8d,6
    je .digits_ok
    cmp r8d,8
    jne .invalid
.digits_ok:
    cmp r9d,1
    je .alg_ok
    cmp r9d,2
    jne .invalid
.alg_ok:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,VFY_OTP_FRAME
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    mov ebp,r8d
    mov ebx,r9d
    bswap rcx
    mov [rsp],rcx
    lea rdi,[rsp+8]                 ; digest max32, ASCII scratch at40..48
    mov rsi,r13
    mov rdx,r14
    lea rcx,[rsp]
    mov r8d,8
    cmp ebx,1
    jne .sha256
    call hmac_sha1
    mov ecx,19
    jmp .truncated
.sha256:
    call hmac_sha256
    mov ecx,31
.truncated:
    test eax,eax
    jnz .fail
    movzx ecx,byte [rsp+8+rcx]
    and ecx,15
    mov eax,[rsp+8+rcx]
    bswap eax
    and eax,0x7fffffff
    mov ecx,1000000
    cmp ebp,6
    je .reduce
    mov ecx,100000000
.reduce:
    xor edx,edx
    div ecx
    mov eax,edx
    mov qword [rsp+40],0
    mov byte [rsp+48],0
    mov ecx,ebp
    mov r8d,10
.decimal:
    xor edx,edx
    div r8d
    add dl,'0'
    dec ecx
    mov [rsp+40+rcx],dl
    test ecx,ecx
    jnz .decimal
    mov rax,[rsp+40]
    mov [r12],rax
    mov al,[rsp+48]
    mov [r12+8],al
    xor ebx,ebx
    jmp .wipe
.fail:
    mov ebx,-1
.wipe:
    mov rdi,rsp
    xor eax,eax
    mov ecx,VFY_OTP_FRAME / 8
    rep stosq
    mov eax,ebx
    add rsp,VFY_OTP_FRAME
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.invalid:
    mov eax,-1
    ret

VFY_PREP_FRAME equ 216
vfy_totp_prepare:
    cld
    test rdx,rdx
    jz .invalid_out
    cmp rcx,16
    jb .invalid_out
    mov qword [rdx],0
    mov qword [rdx+8],0
    test rdi,rdi
    jz .invalid_out
    cmp rsi,VFY_TOTP_REQUEST_SIZE
    jne .invalid_out
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,VFY_PREP_FRAME
    mov r12,rdx
    mov r13,rdi
    mov rdi,rsp
    xor eax,eax
    mov ecx,VFY_PREP_FRAME / 8
    rep stosq
    mov rdi,rsp
    mov rsi,r13
    mov ecx,8
    rep movsq
    mov ebx,-1
    cmp dword [rsp],1
    jne .wipe
    mov ebp,[rsp+4]
    test ebp,~3
    jnz .wipe
    cmp qword [rsp+56],0
    jne .wipe
    cmp qword [rsp+8],0
    je .wipe
    cmp qword [rsp+40],0
    je .wipe
    cmp qword [rsp+16],20
    jb .wipe
    cmp qword [rsp+16],64
    ja .wipe
    mov eax,[rsp+48]
    cmp eax,6
    je .digits_ok
    cmp eax,8
    jne .wipe
.digits_ok:
    mov eax,[rsp+52]
    cmp eax,1
    je .alg_ok
    cmp eax,2
    jne .wipe
.alg_ok:
    test ebp,2
    jnz .floor_ok
    cmp qword [rsp+32],0
    jne .wipe
.floor_ok:
    test ebp,1
    jz .clock_bad
    mov rax,[rsp+24]
    test rax,rax
    js .clock_bad
    xor edx,edx
    mov ecx,30
    div rcx
    mov [rsp+160],rax               ; current counter
    ; Snapshot key and exact length code; do not read a terminator.
    lea rdi,[rsp+64]
    mov rsi,[rsp+8]
    mov rcx,[rsp+16]
    rep movsb
    mov rsi,[rsp+40]
    xor ecx,ecx
.copy_code:
    mov al,[rsi+rcx]
    sub al,'0'
    cmp al,9
    ja .wipe
    add al,'0'
    mov [rsp+128+rcx],al
    inc ecx
    cmp ecx,[rsp+48]
    jb .copy_code
    xor r14d,r14d
    mov r15,[rsp+160]
    test r15,r15
    jnz .previous
    inc r14d                       ; skip mathematical -1, never wrap to MAX
    jmp .candidate
.previous:
    dec r15
.candidate:
    lea rdi,[rsp+144]
    lea rsi,[rsp+64]
    mov rdx,[rsp+16]
    mov rcx,r15
    mov r8d,[rsp+48]
    mov r9d,[rsp+52]
    call vfy_hotp_ascii
    test eax,eax
    jnz .wipe
    xor eax,eax
    xor ecx,ecx
.compare:
    mov dl,[rsp+144+rcx]
    xor dl,[rsp+128+rcx]
    or al,dl
    inc ecx
    cmp ecx,[rsp+48]
    jb .compare
    test al,al
    sete dl
    movzx edx,dl
    test ebp,2
    jz .eligible
    cmp r15,[rsp+32]
    seta al
    movzx eax,al
    and edx,eax
.eligible:
    test edx,edx
    mov rax,[rsp+168]
    cmovnz rax,r15
    mov [rsp+168],rax
    or [rsp+176],rdx
    inc r15
    inc r14d
    cmp r14d,3
    jb .candidate
    mov ebx,-3
    cmp qword [rsp+176],0
    je .wipe
    mov rax,[rsp+168]
    mov [r12],rax
    xor ebx,ebx
    jmp .wipe
.clock_bad:
    mov ebx,-2
.wipe:
    mov rdi,rsp
    xor eax,eax
    mov ecx,VFY_PREP_FRAME / 8
    rep stosq
    mov eax,ebx
    add rsp,VFY_PREP_FRAME
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.invalid_out:
    mov eax,-1
    ret
