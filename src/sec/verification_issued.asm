;; MODULE sec/verification_issued
;; LAYER 2
;; EXPORTS vfy_issued_prepare, vfy_issued_check_prepare
;; IMPORTS core/lib/hmac_sha256, core/csprng, core/time
;; CAPS
;; OWNER rc-sec-claude
;; CONTEXT: bsp_only  (serialized; SHA256 has static scratch)
; Native trusted stable valid DISJOINT pointers only. No AP/IRQ/yield entry.
; Unlinked preparation API: grants NO authentication; no storage or rate limit.
; Caller obtains a dedicated 32-byte machine-secret-derived key, captures owner,
; machine, session/challenge, connector generation and purpose itself. It must
; serialize and durably commit anti-rollback sequence/rates/row BEFORE publishing
; the frame, and durably commit a returned BURNED row BEFORE using a candidate.
; Re-preparing the same old LIVE snapshot intentionally can match again. This
; module cannot prove persistence or single use. Persist failures grant nothing.
; Native NTP-source-qualified UTC is NOT cryptographically authenticated time;
; caller supplies a durable minimum UTC floor. Strong clock policy remains open.
;
; vfy_issued_prepare(RDI=ctx96, RSI=key32, RDX=out448, RCX=capacity>=448)
; -> 0 prepared; -1 invalid; -2 clock; -3 entropy/crypto; -8 draw exhaustion.
; out448 = sealed row192 || VFD1 frame256. No delivery occurs here. Caller wipes
; the plaintext frame after publishing/failure/cancel. Record contains no code.
;
; ctx96 LE: +0 'VIC1', +4 ver u16=1, +6 purpose u16=1..4 (unlock second
; step/reset/enroll/remove, CONTEXT ONLY, no reset or enrollment flow implemented),
; +8 sequence u64=1..UINT64_MAX-1; +16 machine16; +32 owner16; +48 session16
; (each ID nonzero); +64 connector u32!=0; +68 generation u32!=0;
; +72 channel u32=1..3; +76 TTL seconds u32=1..300; +80 UTC floor<=INT64_MAX;
; +88 reserved u64=0. Sequence must come from authenticated durable caller state.
;
; row192 LE: +0 'VIR1', +4 ver u16=1, +6 state u16=1LIVE/2BURNED;
; +8 sequence; +16 DRBG request ID16; +32 machine16; +48 owner16; +64 session16;
; +80 purpose u32; +84 connector u32; +88 generation u32; +92 channel u32;
; +96 issued UTC; +104 expires UTC; +112 verifier32 (zero when burned);
; +144 reserved16=0; +160 row MAC32. All three numbers UTC/sequence are u64.
; verifier = HMAC-SHA256(key, 'PaOS/vfy/code/v1'16 || row[8:112]104 || code8).
; row MAC = HMAC-SHA256(key, 'PaOS/vfy/row/v1\0'16 || row[0:160]160).
; Both use fixed-length full comparisons, no first-differing-byte exit. No formal
; CPU constant-time claim. Code is uniformly rejection-sampled from DRBG u32:
; accept <4200000000, remainder100000000, eight zero-padded ASCII digits.
;
; VFD1: +0 magic, +4 version u16=1, +6 channel u8, +7 purpose u8;
; +8 requestID16, +24 expires u64, +32 connector u32, +36 generation u32,
; +40 text length u16=18, +42 reserved u16=0, +44 'PaOS code ' + code8;
; remaining bytes zero. No address/owner label or authority travels in frame.
;
; vfy_issued_check_prepare(RDI=descriptor64, RSI=64, RDX=out192,
;                          RCX=capacity>=192)
; descriptor LE: +0 version u32=1, +4 flags u32=0, +8 row ptr, +16 ctx ptr,
; +24 key ptr, +32 code ptr (nonnull if len8), +40 code length u64,
; +48 reserved16=0. Exact lengths/digits required for match. No code read for
; length !=8. On authenticated bound LIVE row, a first attempt prepares BURNED
; row on match0, clock-2, expired-5, wrong-7. Invalid/binding-4/burned-6/crypto-3
; leave writable output zero. BURNED requires verifier zero and valid MAC.
; Every other full-size writable refusal is zero. Short/null output untouched.
; All temporary stack buffers are wiped, including code and digest, on return.
VI_FRAME equ 680

%macro VI_ROW_MAC 0
    lea rdi,[rsp+448]
    lea rsi,[rel vi_row_domain]
    mov ecx,16
    rep movsb
    lea rsi,[rsp]
    mov ecx,160
    rep movsb
    lea rdi,[rsp+624]
    mov rsi,r13
    mov edx,32
    lea rcx,[rsp+448]
    mov r8d,176
    call hmac_sha256
%endmacro

%macro VI_CODE_MAC 0
    lea rdi,[rsp+448]
    lea rsi,[rel vi_code_domain]
    mov ecx,16
    rep movsb
    lea rsi,[rsp+8]
    mov ecx,104
    rep movsb
    lea rsi,[rsp+656]
    mov ecx,8
    rep movsb
    lea rdi,[rsp+624]
    mov rsi,r13
    mov edx,32
    lea rcx,[rsp+448]
    mov r8d,128
    call hmac_sha256
%endmacro

%macro VI_ENTER 0
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,VI_FRAME
    mov r14,rdx
    xor eax,eax
    mov rdi,rsp
    mov ecx,VI_FRAME/8
    rep stosq
%endmacro

%macro VI_LEAVE 0
    mov r15d,eax
    xor eax,eax
    mov rdi,rsp
    mov ecx,VI_FRAME/8
    rep stosq
    mov eax,r15d
    add rsp,VI_FRAME
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
%endmacro

vfy_issued_prepare:
    cld
    test rdx,rdx
    jz .early
    cmp rcx,448
    jb .early
    mov r10,rdi
    mov r11,rsi
    mov rdi,rdx
    xor eax,eax
    mov ecx,56
    rep stosq
    mov rdi,r10
    mov rsi,r11
    VI_ENTER
    mov r12,r10
    mov r13,r11
    mov rdi,r12
    call vi_context_valid
    test eax,eax
    jnz .bad
    test r13,r13
    jz .bad
    call time_wall_utc_now_s
    test rax,rax
    jle .clock
    cmp rax,[r12+80]
    jb .clock
    mov [rsp+96],rax
    mov ecx,[r12+76]
    add rax,rcx
    jc .clock
    test rax,rax
    js .clock
    mov [rsp+104],rax
    mov dword [rsp],0x31524956     ; VIR1
    mov dword [rsp+4],0x00010001
    mov rax,[r12+8]
    mov [rsp+8],rax
    lea rdi,[rsp+32]
    lea rsi,[r12+16]
    mov ecx,48
    rep movsb
    movzx eax,word [r12+6]
    mov [rsp+80],eax
    mov rax,[r12+64]
    mov [rsp+84],rax
    mov eax,[r12+72]
    mov [rsp+92],eax
    lea rdi,[rsp+16]
    mov esi,16
    call csprng_generate
    test eax,eax
    jnz .crypto
    mov rax,[rsp+16]
    or rax,[rsp+24]
    jz .crypto                      ; zero request ID refused, no weak fallback
    mov ebp,32
.draw:
    lea rdi,[rsp+664]
    mov esi,4
    call csprng_generate
    test eax,eax
    jnz .crypto
    mov eax,[rsp+664]
    cmp eax,4200000000
    jb .sample
    dec ebp
    jnz .draw
    mov eax,-8
    jmp .leave
.sample:
    xor edx,edx
    mov ecx,100000000
    div ecx
    mov eax,edx
    mov ecx,8
    mov ebx,10
.decimal:
    xor edx,edx
    div ebx
    add dl,'0'
    mov [rsp+656+rcx-1],dl
    dec ecx
    jnz .decimal
    VI_CODE_MAC
    test eax,eax
    jnz .crypto
    lea rdi,[rsp+112]
    lea rsi,[rsp+624]
    mov ecx,32
    rep movsb
    VI_ROW_MAC
    test eax,eax
    jnz .crypto
    lea rdi,[rsp+160]
    lea rsi,[rsp+624]
    mov ecx,32
    rep movsb
    mov dword [rsp+192],0x31444656 ; VFD1
    mov word [rsp+196],1
    mov al,[r12+72]
    mov [rsp+198],al
    mov al,[r12+6]
    mov [rsp+199],al
    lea rdi,[rsp+200]
    lea rsi,[rsp+16]
    mov ecx,16
    rep movsb
    mov rax,[rsp+104]
    mov [rsp+216],rax
    mov rax,[r12+64]
    mov [rsp+224],rax
    mov word [rsp+232],18
    lea rdi,[rsp+236]
    lea rsi,[rel vi_text]
    mov ecx,10
    rep movsb
    lea rsi,[rsp+656]
    mov ecx,8
    rep movsb
    mov rdi,r14
    mov rsi,rsp
    mov ecx,448
    rep movsb
    xor eax,eax
    jmp .leave
.bad:
    mov eax,-1
    jmp .leave
.clock:
    mov eax,-2
    jmp .leave
.crypto:
    mov eax,-3
.leave:
    VI_LEAVE
.early:
    mov eax,-1
    ret

vfy_issued_check_prepare:
    cld
    test rdx,rdx
    jz .early
    cmp rcx,192
    jb .early
    mov r10,rdi
    mov r11,rsi
    mov rdi,rdx
    xor eax,eax
    mov ecx,24
    rep stosq
    VI_ENTER
    mov r15,r10
    cmp r11,64
    jne .bad
    test r15,r15
    jz .bad
    cmp dword [r15],1
    jne .bad
    cmp dword [r15+4],0
    jne .bad
    mov rax,[r15+48]
    or rax,[r15+56]
    jnz .bad
    mov r12,[r15+16]
    mov r13,[r15+24]
    test r13,r13
    jz .bad
    mov rdi,r12
    call vi_context_valid
    test eax,eax
    jnz .bad
    mov rsi,[r15+8]
    test rsi,rsi
    jz .bad
    mov rdi,rsp
    mov ecx,192
    rep movsb
    cmp dword [rsp],0x31524956
    jne .binding
    cmp word [rsp+4],1
    jne .binding
    movzx eax,word [rsp+6]
    dec eax
    cmp eax,1
    ja .binding
    mov rax,[rsp+144]
    or rax,[rsp+152]
    jnz .binding
    mov rax,[rsp+16]
    or rax,[rsp+24]
    jz .binding
    VI_ROW_MAC
    test eax,eax
    jnz .crypto
    lea rdi,[rsp+160]
    lea rsi,[rsp+624]
    call vi_equal32
    test eax,eax
    jnz .binding
    mov rax,[r12+8]
    cmp rax,[rsp+8]
    jne .binding
    lea rdi,[r12+16]
    lea rsi,[rsp+32]
    mov ecx,48
    repe cmpsb
    jne .binding
    movzx eax,word [r12+6]
    cmp eax,[rsp+80]
    jne .binding
    mov rax,[r12+64]
    cmp rax,[rsp+84]
    jne .binding
    mov eax,[r12+72]
    cmp eax,[rsp+92]
    jne .binding
    mov rax,[rsp+96]
    test rax,rax
    jle .binding
    mov rcx,[rsp+104]
    test rcx,rcx
    jle .binding
    sub rcx,rax
    jbe .binding
    mov eax,[r12+76]
    cmp rcx,rax
    jne .binding
    cmp word [rsp+6],2
    je .burned
    cmp qword [r15+40],8
    jne .wrong
    mov rsi,[r15+32]
    test rsi,rsi
    jz .bad
    lea rdi,[rsp+656]
    mov ecx,8
    rep movsb
    xor ecx,ecx
.digits:
    movzx eax,byte [rsp+656+rcx]
    sub eax,'0'
    cmp eax,9
    ja .wrong
    inc ecx
    cmp ecx,8
    jb .digits
    VI_CODE_MAC
    test eax,eax
    jnz .crypto
    lea rdi,[rsp+112]
    lea rsi,[rsp+624]
    call vi_equal32
    test eax,eax
    jnz .wrong
    xor ebp,ebp
    jmp .time
.wrong:
    mov ebp,-7
.time:
    call time_wall_utc_now_s
    test rax,rax
    jle .clock
    cmp rax,[r12+80]
    jb .clock
    cmp rax,[rsp+96]
    jb .clock
    cmp rax,[rsp+104]
    jae .expired
    jmp .burn
.clock:
    mov ebp,-2
    jmp .burn
.expired:
    mov ebp,-5
.burn:
    mov word [rsp+6],2
    lea rdi,[rsp+112]
    xor eax,eax
    mov ecx,4
    rep stosq
    VI_ROW_MAC
    test eax,eax
    jnz .crypto
    lea rdi,[rsp+160]
    lea rsi,[rsp+624]
    mov ecx,32
    rep movsb
    mov rdi,r14
    mov rsi,rsp
    mov ecx,192
    rep movsb
    mov eax,ebp
    jmp .leave
.burned:
    mov rax,[rsp+112]
    or rax,[rsp+120]
    or rax,[rsp+128]
    or rax,[rsp+136]
    jnz .binding
    mov eax,-6
    jmp .leave
.binding:
    mov eax,-4
    jmp .leave
.bad:
    mov eax,-1
    jmp .leave
.crypto:
    mov eax,-3
.leave:
    VI_LEAVE
.early:
    mov eax,-1
    ret

; Leaf context validator. Caller retains trusted pointers in callee-save regs.
vi_context_valid:
    test rdi,rdi
    jz .bad
    cmp dword [rdi],0x31434956
    jne .bad
    cmp word [rdi+4],1
    jne .bad
    movzx eax,word [rdi+6]
    dec eax
    cmp eax,3
    ja .bad
    mov rax,[rdi+8]
    test rax,rax
    jz .bad
    cmp rax,-1
    je .bad
    mov ecx,16
.ids:
    mov rax,[rdi+rcx]
    or rax,[rdi+rcx+8]
    jz .bad
    add ecx,16
    cmp ecx,64
    jb .ids
    cmp dword [rdi+64],0
    je .bad
    cmp dword [rdi+68],0
    je .bad
    mov eax,[rdi+72]
    dec eax
    cmp eax,2
    ja .bad
    mov eax,[rdi+76]
    dec eax
    cmp eax,299
    ja .bad
    cmp qword [rdi+80],0
    jl .bad
    cmp qword [rdi+88],0
    jne .bad
    xor eax,eax
    ret
.bad:
    mov eax,-1
    ret

vi_equal32:
    xor eax,eax
    xor ecx,ecx
.loop:
    mov dl,[rdi+rcx]
    xor dl,[rsi+rcx]
    or al,dl
    inc ecx
    cmp ecx,32
    jb .loop
    ret

align 8
vi_code_domain: db 'PaOS/vfy/code/v1'
vi_row_domain: db 'PaOS/vfy/row/v1',0
vi_text: db 'PaOS code '
