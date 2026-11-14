;; MODULE sec/verification_durable
;; LAYER 5
;; EXPORTS vfy_issued_durable
;; IMPORTS sec/verification_consumer, sec/verification_issued, sec/verification_store, sec/verification_delivery
;; CAPS
;; OWNER rc-sec-claude
;; CONTEXT: bsp_only  (serialized trusted native; no IRQ/AP/yield/reentry)
; Next issued-row lifecycle prerequisite; unlinked, CANDIDATE ONLY, no login.
; vfy_issued_durable(RDI=descriptor80, RSI=exact80) -> signed status.
; LE descriptor: +0 version u32=1; +4 op u32=1CHECK/2REVOKE/3EXPIRE;
; +8 trusted ctx96 ptr; +16 dedicated key32 ptr; +24 code ptr; +32 code_len;
; +40 expected requestID16 nonzero; +56 reserved24 zero.
; Caller captures current owner/machine/session/connector/purpose/sequence and
; durable UTC floor, supplies mapped stable DISJOINT native pointers and owns
; the BSP service transaction. Never guest pointers or delivery-worker calls.
; Existing core/consumer statuses retained; -11 storage unavailable/uncertain,
; -12 stored row changed. No caller row or prepared candidate can replace the
; fixed authoritative storage load. Authenticate/bind without reading code;
; prepare a sealed burn, cancel delivery, compare old row and persist/read back
; the burn BEFORE first code read/comparison. There is no candidate on failure.
; EXPIRE on a current row returns -10 unchanged. Clock refusal burns too.
; After commit, check uses the private LIVE snapshot once; every later failure
; leaves storage BURNED. A crash loses the candidate, never revives the row.
; Scratch is wiped, no code/keys/row pointers retained or exposed to delivery.
; Backend needs mapped UEFI runtime, NV durability and exclusive service access.
; Provisioning, issuance/rates, trusted monotonic rollback floor, authenticator
; enrollment, runtime wiring and authentication remain separate prerequisites.
; Hostile whole-firmware rollback is not prevented by a runtime NV variable.
VD_FRAME equ 536

vfy_issued_durable:
    cld
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,VD_FRAME
    mov r12,rdi
    mov rbx,rsi
    xor eax,eax
    mov rdi,rsp
    mov ecx,VD_FRAME/8
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
    cmp qword [r12+8],0
    je .invalid
    cmp qword [r12+16],0
    je .invalid
    mov rax,[r12+40]
    or rax,[r12+48]
    jz .invalid
    mov rax,[r12+56]
    or rax,[r12+64]
    or rax,[r12+72]
    jnz .invalid
    cmp r14d,1
    jne .load
    cmp qword [r12+32],8
    jne .load
    cmp qword [r12+24],0
    je .invalid
.load:
    mov rdi,rsp
    call vfy_store_load
    test eax,eax
    jnz .leave
    lea rdi,[rsp+192]
    mov rsi,rsp
    mov ecx,24
    rep movsq
    mov dword [rsp+384],1
    mov [rsp+388],r14d
    lea rax,[rsp+192]
    mov [rsp+392],rax
    mov rax,[r12+8]
    mov [rsp+400],rax
    mov rax,[r12+16]
    mov [rsp+408],rax
    mov rax,[r12+40]
    mov [rsp+432],rax
    mov rax,[r12+48]
    mov [rsp+440],rax
    ; CHECK uses length0 here: authenticate and prepare burn, never read code.
    lea rdi,[rsp+384]
    mov esi,80
    call vfy_issued_consume
    mov r15d,eax
    cmp eax,-7
    je .commit
    cmp eax,-9
    je .commit
    cmp eax,-5
    je .commit
    cmp eax,-2
    jne .leave
.commit:
    lea rdi,[r12+40]
    call vfy_delivery_cancel         ; conservative even if persistence fails
    mov rdi,rsp                     ; exact expected LIVE snapshot
    lea rsi,[rsp+192]                ; sealed BURNED replacement only
    call vfy_store_commit
    test eax,eax
    jnz .leave
    mov eax,r15d
    cmp eax,-7
    jne .leave                      ; revoke/expiry/clock: no code access
    ; Only a current CHECK survives. Storage is durably burned and read back.
    mov dword [rsp+464],1
    mov [rsp+472],rsp
    mov rax,[r12+8]
    mov [rsp+480],rax
    mov rax,[r12+16]
    mov [rsp+488],rax
    mov rax,[r12+24]
    mov [rsp+496],rax
    mov rax,[r12+32]
    mov [rsp+504],rax
    lea rdi,[rsp+464]
    mov esi,64
    lea rdx,[rsp+192]
    mov ecx,192
    call vfy_issued_check_prepare
    jmp .leave
.invalid:
    mov eax,-1
.leave:
    mov r15d,eax
    xor eax,eax
    mov rdi,rsp
    mov ecx,VD_FRAME/8
    rep stosq
    mov eax,r15d
    add rsp,VD_FRAME
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
