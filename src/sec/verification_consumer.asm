;; MODULE sec/verification_consumer
;; LAYER 2
;; EXPORTS vfy_issued_consume
;; IMPORTS sec/verification_issued
;; CAPS
;; OWNER rc-sec-claude
;; CONTEXT: bsp_only  (serialized; nested SHA256 has static scratch)
; Unlinked native lifecycle seam. A zero result is a verification CANDIDATE ONLY.
; No durable storage, rate policy, issuer authorization or authentication grant.
; Caller owns stable valid DISJOINT native pointers and one mutable row, with no
; AP/IRQ/yield/reentry or concurrent access. Never accept guest pointers here.
; A restored old LIVE snapshot can match again: durable burn/anti-rollback and
; a trusted clock/rate policy MUST precede any future use of a candidate.
;
; vfy_issued_consume(RDI=descriptor80, RSI=exact80) -> signed status.
; descriptor LE: +0 version u32=1; +4 operation u32=1CHECK/2REVOKE/3EXPIRE;
; +8 mutable row192 ptr; +16 ctx96 ptr; +24 dedicated key32 ptr;
; +32 code ptr; +40 code length u64; +48 expected request ID16 (nonzero);
; +64 reserved16=0. Native caller captures all bindings, operation and request
; identity. REVOKE is a trusted native operation, NOT an owner authorization API.
; CHECK null code with length8 is invalid. Other lengths never read code.
; REVOKE/EXPIRE ignore code pointer/length entirely.
;
; Authenticate/canonically bind through the accepted core with no code first.
; Check the full expected request ID before mutation. EXPIRE on a still-current
; row returns -10 and leaves it LIVE; clock refusal or expiry consumes it.
; CHECK/REVOKE adopt the sealed BURNED row in caller RAM BEFORE any code read or
; comparison. That RAM write is NOT a durable commit. Revoke/expiry do not read
; the code. Later compare/crypto/time failures keep the row burned.
; Returns 0 candidate, -1 invalid, -2 clock (burned), -3 crypto, -4 binding,
; -5 expired (burned), -6 already burned, -7 wrong (burned), -9 revoked (burned),
; -10 not yet expired (unchanged). Pre-burn crypto/binding/invalid failures leave
; the original row unchanged. Expiry/clock status takes precedence over revoke.
; All consumer stack scratch (snapshot, prepared row, descriptor) is erased.
VC_FRAME equ 520

vfy_issued_consume:
    cld
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,VC_FRAME
    mov r12,rdi
    mov rbx,rsi
    mov rdi,rsp
    xor eax,eax
    mov ecx,VC_FRAME/8
    rep stosq
    cmp rbx,80
    jne .invalid
    test r12,r12
    jz .invalid
    cmp dword [r12],1
    jne .invalid
    mov r14d,[r12+4]
    lea eax,[r14-1]
    cmp eax,2
    ja .invalid
    mov rax,[r12+64]
    or rax,[r12+72]
    jnz .invalid
    mov rax,[r12+48]
    or rax,[r12+56]
    jz .invalid
    mov r13,[r12+8]
    test r13,r13
    jz .invalid
    cmp qword [r12+16],0
    je .invalid
    cmp qword [r12+24],0
    je .invalid
    cmp r14d,1
    jne .snapshot
    cmp qword [r12+40],8
    jne .snapshot
    cmp qword [r12+32],0
    je .invalid
.snapshot:
    mov rdi,rsp
    mov rsi,r13
    mov ecx,192
    rep movsb
    mov dword [rsp+384],1
    mov [rsp+392],rsp
    mov rax,[r12+16]
    mov [rsp+400],rax
    mov rax,[r12+24]
    mov [rsp+408],rax
    ; Dummy length0: authenticates/binds/time-checks and prepares burn without
    ; touching user code or computing its keyed verifier.
    lea rdi,[rsp+384]
    mov esi,64
    lea rdx,[rsp+192]
    mov ecx,192
    call vfy_issued_check_prepare
    mov r15d,eax
    cmp eax,-7
    je .request
    cmp eax,-2
    je .request
    cmp eax,-5
    jne .leave
.request:
    mov rax,[r12+48]
    xor rax,[rsp+16]
    mov rdx,[r12+56]
    xor rdx,[rsp+24]
    or rax,rdx
    jnz .binding
    cmp r14d,3
    jne .adopt
    cmp r15d,-7
    je .pending
.adopt:
    mov rdi,r13
    lea rsi,[rsp+192]
    mov ecx,192
    rep movsb                        ; RAM burn BEFORE supplied code access
    mov eax,r15d
    cmp eax,-7
    jne .leave                       ; clock/expiry already consumed, no code
    cmp r14d,2
    je .revoked
    ; Only a current bound CHECK reaches the supplied code. The immutable
    ; local LIVE snapshot is used once; caller's owned row is already BURNED.
    mov rax,[r12+32]
    mov [rsp+416],rax
    mov rax,[r12+40]
    mov [rsp+424],rax
    lea rdi,[rsp+384]
    mov esi,64
    lea rdx,[rsp+192]
    mov ecx,192
    call vfy_issued_check_prepare
    jmp .leave
.pending:
    mov eax,-10
    jmp .leave
.revoked:
    mov eax,-9
    jmp .leave
.binding:
    mov eax,-4
    jmp .leave
.invalid:
    mov eax,-1
.leave:
    mov r15d,eax
    mov rdi,rsp
    xor eax,eax
    mov ecx,VC_FRAME/8
    rep stosq
    mov eax,r15d
    add rsp,VC_FRAME
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
