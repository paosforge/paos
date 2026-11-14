;; MODULE core/lib/ssh_crypto_work
;; LAYER 1
;; EXPORTS ssh_crypto_work, ssh_crypto_work_fullfit
;; IMPORTS core/lib/ed25519, core/lib/mem, core/time, boot/pmod_loader
;; CAPS
;; OWNER saga:sec
;; CONTEXT: bsp_only
; Trusted AV caller only. This is compute/custody, never session authority.
; See gauntlet_v2/docs/ssh_crypto_work.md. No shared scratch or owner selector.
SW_BIND       equ 0             ; AV's immutable eight-qword snapshot
SW_CID_GEN    equ 64
SW_MSG_LEN    equ 72
SW_SEED       equ 80
SW_EXPECTED   equ 112
SW_MESSAGE    equ 144
SW_PUBLIC     equ 1168
SW_SIGNATURE  equ 1200
SW_STATUS     equ 1264
SW_SCRATCH    equ 1280
SW_BYTES      equ (SW_SCRATCH + ED25519_CONTEXT_BYTES + 15) & ~15
SW_RESULT_BYTES equ 160         ; binding64, public32, signature64
SW_DONE       equ 0
SW_CANCELLED  equ 1
SW_STALE      equ 2
SW_EXPIRED    equ 3
SW_REFUSED    equ 4
SW_FAULT      equ 5
SW_TIMEOUT    equ 6
SW_UNAVAILABLE equ 7

; Span helpers: trusted mapped pointers only; these checks do not authenticate
; memory. RAX=start, ECX=bytes -> R10=end, CF=malformed. Inputs unchanged.
ssh_work_span:
    test rax, rax
    jz .bad
    mov r10, rax
    add r10, rcx
    jc .bad
    clc
    ret
.bad:
    stc
    ret
; RAX/R10=[start,end), RDI/ECX=other span -> CF on overlap/wrap.
ssh_work_disjoint:
    test rdi, rdi
    jz .bad
    mov r11, rdi
    add r11, rcx
    jc .bad
    cmp rdi, r10
    jae .ok
    cmp r11, rax
    ja .bad
.ok:
    clc
    ret
.bad:
    stc
    ret

; ssh_crypto_work(work,bytes,live_binding,cancel_record,result,earned_lease_ms)
; RDI,RSI,RDX,RCX,R8,R9 respectively. Result is provisional public data only.
; -> RAX=SW_* status. RDX=TARGET's pmod_call_deadline_strict observation for an
; admitted until-call (1 = TSC-deadline delivery held), else 0. RDX=1 is only
; the core's observation, not a numeric cutoff/IRQ/cleanup bound; RDX=0 claims
; no strict wall stop at D.
; Malformed/aliased span refusal is untouched (caller keeps secret custody).
; After span admission every return wipes the ENTIRE exclusive work capsule.
;
; ssh_crypto_work_fullfit(same six, reserve_us): seventh SysV argument on the
; stack ([rsp+8] at entry), the caller's whole post-cutoff reserve. Refused
; (SW_REFUSED) when 0; SW_EXPIRED unless 1000*lease + reserve (checked) <=
; D - now. Enters TARGET105791 until_fullfit with RCX = reserve and R9 =
; unchanged [work+56]. Core -4 (D reached at arm) and -5 (lease + reserve no
; longer fit at the masked arm) never enter the module: SW_EXPIRED, RDX 0.
; The reserve is never written to the work record, the binding or the result.
; ssh_crypto_work keeps the plain until entry.
ssh_crypto_work_fullfit:
    mov r10, [rsp + 8]            ; reserve_us, read once
    mov r11d, 1
    jmp ssh_crypto_work_body
ssh_crypto_work:
    xor r10d, r10d                ; no reserve: plain until entry, as before
    xor r11d, r11d
ssh_crypto_work_body:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 40
    mov qword [rsp + 8], 0        ; strict observation, set only after admission
    mov [rsp + 16], r10           ; reserve_us (0 on the six-argument entry)
    mov [rsp + 24], r11           ; 1 = full-fit entry
    mov rbx, rdi
    mov r12, rdx
    mov r13, rcx
    mov r14, r8
    mov r15, r9
    cmp rsi, SW_BYTES
    jne .bad_span
    test bl, 15
    jnz .bad_span
    mov rax, rbx
    mov ecx, SW_BYTES
    call ssh_work_span
    jc .bad_span
    mov rdi, r12
    mov ecx, 64
    call ssh_work_disjoint
    jc .bad_span
    mov rdi, r13
    mov ecx, 16
    call ssh_work_disjoint
    jc .bad_span
    mov rdi, r14
    mov ecx, SW_RESULT_BYTES
    call ssh_work_disjoint
    jc .bad_span
    lea rdi, [rel ed_sha_state]
    mov ecx, ED25519_CONTEXT_BYTES
    call ssh_work_disjoint
    jc .bad_span
    mov rax, r14
    mov ecx, SW_RESULT_BYTES
    call ssh_work_span
    jc .bad_span
    mov rdi, r12
    mov ecx, 64
    call ssh_work_disjoint
    jc .bad_span
    mov rdi, r13
    mov ecx, 16
    call ssh_work_disjoint
    jc .bad_span
    lea rdi, [rel ed_sha_state]
    mov ecx, ED25519_CONTEXT_BYTES
    call ssh_work_disjoint
    jc .bad_span
    mov rax, r12
    mov ecx, 64
    call ssh_work_span
    jc .bad_span
    mov rdi, r13
    mov ecx, 16
    call ssh_work_disjoint
    jc .bad_span
    mov qword [rsp], SW_REFUSED
    test r15, r15
    jz .clean
    cmp r15, 100                  ; fence ABI range, NOT a chosen quantum
    ja .clean
    cmp qword [rsp + 24], 0
    je .reserve_ok
    cmp qword [rsp + 16], 0       ; full-fit entry: no absent/zero reserve
    je .clean
.reserve_ok:
    cmp qword [rbx + SW_MSG_LEN], ED25519_MAX_MESSAGE
    ja .clean
    cmp qword [rbx + SW_CID_GEN], 0
    je .clean
    cmp qword [rbx], 6           ; actual AV session slots 0..5
    jae .clean
    cmp qword [rbx + 8], 0       ; nonreused allocation generation
    je .clean
    cmp qword [rbx + 24], 0      ; actual tracked TCP incarnation
    je .clean
    cmp qword [rbx + 32], 0      ; nonreused dial generation
    je .clean
    cmp qword [rbx + 40], 0      ; nonreused work generation
    je .clean
    mov rax, [rbx + 48]
    test rax, rax
    jz .clean
    cmp rax, [rbx + 56]          ; unchanged original TCP <= channel deadline
    ja .clean
    call .current
    test eax, eax
    jnz .status_clean
    call time_monotonic_now_us
    test rax, rax
    jz .expired
    mov rbp, rax
    mov rdx, [rbx + 56]
    sub rdx, rax
    jbe .expired
    imul rax, r15, 1000
    add rax, [rsp + 16]          ; whole service: lease + reserve (0 if plain)
    jc .expired
    cmp rax, rdx
    ja .expired                 ; never renew or round the original D up
    mov qword [rbx + SW_STATUS], SW_REFUSED
    lea rdi, [rel ssh_crypto_work_compute]
    mov rsi, rbx
    mov edx, SW_BYTES
    mov r8, r15
    mov r9, [rbx + 56]           ; immutable original channel D caps the arm
    cmp qword [rsp + 24], 0
    jne .call_fullfit
    call pmod_sandbox_call_sensitive_until
    jmp .returned
.call_fullfit:
    mov rcx, [rsp + 16]          ; reserve_us in the 4th SysV slot
    call pmod_sandbox_call_sensitive_until_fullfit
.returned:
    cmp rax, -3
    je .unavailable              ; refused before admission: core flag is stale
    cmp qword [rsp + 24], 0
    je .observe
    cmp rax, -4
    je .expired                  ; D reached at arm: never entered, RDX 0
    cmp rax, -5
    je .expired                  ; whole fit lost at arm: never entered, RDX 0
.observe:
    movzx ecx, byte [rel pmod_call_deadline_strict]
    mov [rsp + 8], rcx
    cmp rax, -4
    je .expired                  ; D reached at arm, module never entered
    cmp rax, -1
    je .fault
    cmp rax, -2
    je .timeout
    test rax, rax
    jnz .unavailable
    cmp qword [rbx + SW_STATUS], SW_DONE
    jne .clean
    call .current
    test eax, eax
    jnz .status_clean
    call time_monotonic_now_us
    test rax, rax
    jz .expired
    cmp rax, rbp
    jb .expired                 ; unknown/backward clock refuses
    cmp rax, [rbx + 56]
    jae .expired
    ; Only provisional result, not auth/send. AV independently checks the
    ; live key, owner/cancel/full binding and original D again before use.
    mov rsi, rbx
    mov rdi, r14
    mov ecx, 8
    cld
    rep movsq
    lea rsi, [rbx + SW_PUBLIC]
    mov ecx, 12
    rep movsq
    mov qword [rsp], SW_DONE
    jmp .clean
.current:
    mov rdi, rbx
    mov rsi, r12
    mov edx, 64
    sub rsp, 8
    call memcmp
    add rsp, 8
    test eax, eax
    jnz .stale
    mov rax, [r13]
    cmp rax, [rbx + 40]
    jne .current_ok             ; another generation's cancel cannot cancel us
    cmp qword [r13 + 8], 0
    jne .cancelled
.current_ok:
    xor eax, eax
    ret
.stale:
    mov eax, SW_STALE
    ret
.cancelled:
    mov eax, SW_CANCELLED
    ret
.expired:
    mov eax, SW_EXPIRED
    jmp .status_clean
.fault:
    mov eax, SW_FAULT
    jmp .status_clean
.timeout:
    mov eax, SW_TIMEOUT
    jmp .status_clean
.unavailable:
    mov eax, SW_UNAVAILABLE
.status_clean:
    mov [rsp], rax
.clean:
    ; Fence has actually returned: only THIS exclusive capsule is retired.
    mov rdi, rbx
    mov ecx, SW_BYTES / 8
    xor eax, eax
    cld
    rep stosq
    mov rax, [rsp]
    jmp .out
.bad_span:
    mov eax, SW_REFUSED
.out:
    mov rdx, [rsp + 8]
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Pure fenced entry: no credentials, transport, principal switches, callbacks,
; interrupts masking, locks or shared Ed context. RDI=exclusive inline capsule.
ssh_crypto_work_compute:
    push rbx
    mov rbx, rdi
    lea rdi, [rbx + SW_SEED]
    mov esi, 32
    lea rdx, [rbx + SW_PUBLIC]
    lea rax, [rbx + SW_SCRATCH]
    mov r10d, ED25519_CONTEXT_BYTES
    call ed25519_public_from_seed_context
    test eax, eax
    jnz .refused
    lea rdi, [rbx + SW_PUBLIC]
    lea rsi, [rbx + SW_EXPECTED]
    mov edx, 32
    call memcmp
    test eax, eax
    jnz .refused                 ; enrolled-public comparison BEFORE signing
    lea rdi, [rbx + SW_SEED]
    mov esi, 32
    lea rdx, [rbx + SW_MESSAGE]
    mov rcx, [rbx + SW_MSG_LEN]
    lea r8, [rbx + SW_SIGNATURE]
    mov r9d, 64
    lea rax, [rbx + SW_SCRATCH]
    mov r10d, ED25519_CONTEXT_BYTES
    call ed25519_sign_context
    test eax, eax
    jnz .refused
    mov qword [rbx + SW_STATUS], SW_DONE
.refused:
    lea rdi, [rbx + SW_SEED]
    mov ecx, 4
    xor eax, eax
    cld
    rep stosq
    ; No secret register is deliberately published as module RAX/RDX result.
    xor edx, edx
    pop rbx
    ret
