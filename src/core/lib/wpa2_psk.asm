;; MODULE core/lib/wpa2_psk
;; LAYER 1
;; EXPORTS wpa2_psk_derive
;; IMPORTS core/lib/hmac_sha1
;; CAPS
;; OWNER rc-sec-claude
;; CONTEXT: any (caller-owned buffers, wiped stack scratch, no static state)
; WPA2 compatibility only: PBKDF2-HMAC-SHA1(P, SSID, 4096, 32).
; RDI=out32, RSI=binary SSID, RDX=SSID length1..32,
; RCX=password bytes, R8=password length8..63 -> EAX0/-1.
; Explicit byte lengths, no terminator/encoding/normalization or raw hex parser.
; Caller supplies accessible ranges; out32 must not overlap either input.
; Refusals (including HMAC errors) leave output untouched. Inputs never change.
; SysV callee-save preserved, DF clear; all168 private stack bytes wiped.
; Caller owns authority/revision/cancel rechecks before AND after this bounded
; synchronous calculation, and wipes its plaintext password/output on disposal.
WP_U equ 0
WP_NEXT equ 24
WP_T equ 48
WP_SALT equ 72
WP_RESULT equ 112
WP_SALTLEN equ 144
WP_ITER equ 152
WP_BLOCK equ 156
WP_FRAME equ 168

wpa2_psk_derive:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,WP_FRAME
    cld
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    mov r15,rcx
    mov rbp,r8
    ; Validate shape and nonwrapping ranges before any input/output access.
    test r12,r12
    jz .fail
    test r13,r13
    jz .fail
    test r15,r15
    jz .fail
    cmp r14,1
    jb .fail
    cmp r14,32
    ja .fail
    cmp rbp,8
    jb .fail
    cmp rbp,63
    ja .fail
    mov r9,r12
    add r9,32
    jc .fail
    mov r10,r13
    add r10,r14
    jc .fail
    mov r11,r15
    add r11,rbp
    jc .fail
    ; Adjacent ranges are valid; overlapping output would destroy caller input.
    cmp r12,r10
    jae .password_overlap
    cmp r13,r9
    jb .fail
.password_overlap:
    cmp r12,r11
    jae .valid
    cmp r15,r9
    jb .fail
.valid:
    lea rdi,[rsp+WP_SALT]
    mov rsi,r13
    mov rcx,r14
    rep movsb
    add r14,4
    mov [rsp+WP_SALTLEN],r14
    mov dword [rsp+WP_BLOCK],1
.block:
    mov eax,[rsp+WP_BLOCK]
    bswap eax
    mov [rsp+WP_SALT+r14-4],eax
    lea rdi,[rsp+WP_U]
    mov rsi,r15
    mov rdx,rbp
    lea rcx,[rsp+WP_SALT]
    mov r8,[rsp+WP_SALTLEN]
    call hmac_sha1
    test eax,eax
    jnz .fail
    lea rdi,[rsp+WP_T]
    lea rsi,[rsp+WP_U]
    mov ecx,20
    rep movsb
    mov dword [rsp+WP_ITER],4095 ; U1 already computed: total4096 per block.
.iterate:
    lea rdi,[rsp+WP_NEXT]
    mov rsi,r15
    mov rdx,rbp
    lea rcx,[rsp+WP_U]
    mov r8d,20
    call hmac_sha1
    test eax,eax
    jnz .fail
    xor ecx,ecx
.xor:
    mov al,[rsp+WP_NEXT+rcx]
    mov [rsp+WP_U+rcx],al
    xor [rsp+WP_T+rcx],al
    inc ecx
    cmp ecx,20
    jb .xor
    dec dword [rsp+WP_ITER]
    jnz .iterate
    lea rsi,[rsp+WP_T]
    lea rdi,[rsp+WP_RESULT]
    cmp dword [rsp+WP_BLOCK],1
    jne .second
    mov ecx,20
    rep movsb
    inc dword [rsp+WP_BLOCK]
    jmp .block
.second:
    add rdi,20
    mov ecx,12
    rep movsb
    ; Atomic output publication only after both complete blocks succeeded.
    mov rdi,r12
    lea rsi,[rsp+WP_RESULT]
    mov ecx,4
    rep movsq
    xor ebx,ebx
    jmp .wipe
.fail:
    mov ebx,-1
.wipe:
    mov rdi,rsp
    xor eax,eax
    mov ecx,WP_FRAME/8
    rep stosq
    xor ecx,ecx
    xor edx,edx
    xor esi,esi
    xor edi,edi
    xor r8d,r8d
    xor r9d,r9d
    xor r10d,r10d
    xor r11d,r11d
    mov eax,ebx
    add rsp,WP_FRAME
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
