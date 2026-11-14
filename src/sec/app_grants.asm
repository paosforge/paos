;; MODULE sec/app_grants
;; LAYER 5
;; PURPOSE Bounded native WAIT policy and frozen one-invocation human approval.
;; EXPORTS app_grants_observe, app_grants_configure, app_grants_configure_scope, app_grants_configure_installed, app_grants_set, app_grants_revoke, app_grants_revoke_bundle, app_grants_check, app_grants_ask, app_grants_pending, app_grants_approve, app_grants_consume, app_grants_cancel, app_grants_resume, ag_generation
;; IMPORTS sec/session, sec/principal, svc/command, core/time, core/smp
;; OWNER saga:app_grants
; Trusted native APIs only: no command/guest policy setter or asserted bundle hash.
; Validator proves the WHOLE descriptor from enforced native launcher/VM/window
; records, not guest labels. It is non-yielding, read-only and preserves SysV
; callee-saved registers. Missing proof/continuation is DENY, even for ASK.
; Runtime keys retire on lock/rebind. Remembered installation consent is an
; optional native resolver which must prove the current instance independently.
AG_DENY equ 0
AG_ALLOW equ 1
AG_ASK equ 2
AG_DESC_SIZE equ 160
AG_KEY_SIZE equ 128
AG_ROWS equ 8
AG_ROW_SIZE equ 144
AG_POLICY_MAX_US equ 300000000
AG_HUMAN_US equ 30000000
AG_D_VERSION equ 0
AG_D_PID equ 8
AG_D_INSTANCE equ 16
AG_D_START equ 24
AG_D_RETIRE equ 32
AG_D_EPOCH equ 40
AG_D_OWNER equ 48
AG_D_WINDOW equ 56
AG_D_RAWGEN equ 64
AG_D_RESET equ 72
AG_D_BUNDLE equ 80
AG_D_HASH equ 88
AG_D_OP equ 120
AG_D_SEQ equ 128
AG_D_CURSOR equ 136
AG_D_TIMEOUT equ 144
AG_D_RESERVED equ 152
AG_P_NONE equ 0
AG_P_WAIT equ 1
AG_P_APPROVED equ 2

; configure(RDI=validator,RSI=VM original-request resume), depth0 native init.
; Retires policies and any pending approval. Both callbacks needed before grants.
app_grants_configure:
    cmp byte [rel cmd_in_dispatch], 0
    jne ag_bad
    cmp byte [rel ag_delivering],0
    jne ag_bad
    mov qword [rel ag_scope],0
    mov [rel ag_validator], rdi
    mov [rel ag_resume_op], rsi
    jmp app_grants_revoke

; configure_scope(RDI=native policy-key normalizer or0)->1/0.
; Only composition can register; never a guest setter. Revokes all runtime rows
; and pending original requests before changing scope. Reconfigure clears it.
app_grants_configure_scope:
    cmp byte [rel cmd_in_dispatch],0
    jne ag_bad
    cmp byte [rel ag_delivering],0
    jne ag_bad
    push rdi
    call app_grants_revoke
    pop rdi
    mov [rel ag_scope],rdi
    mov eax,1
    ret

; Original descriptor has already passed ag_validate. A native scope may map
; only window/rawgen/reset into another fully validated native identity.
; Op, immutable app identity and ALL invocation operands must remain exact.
; RDI original -> RAX readonly key160,0 refusal. Never overwrites the original.
ag_policy_key:
    push rbx
    push r12
    sub rsp,8
    mov rbx,rdi
    mov rax,rdi
    cmp qword [rel ag_scope],0
    je .out
    call [rel ag_scope]
    test rax,rax
    jz .bad
    mov r12,rax
    mov rdi,rax
    mov rsi,rbx
    mov ecx,56/8
    cld
    repe cmpsq
    jne .bad
    lea rdi,[r12+80]
    lea rsi,[rbx+80]
    mov ecx,(AG_DESC_SIZE-80)/8
    repe cmpsq
    jne .bad
    mov rdi,r12
    call [rel ag_validator]
    cmp eax,1
    jne .bad
    mov rax,r12
    jmp .out
.bad:
    xor eax,eax
.out:
    add rsp,8
    pop r12
    pop rbx
    ret

; configure_installed(RDI=native resolver or0), depth0 composition only.
; Resolver(desc160)->policy0..2/current generation. ag_validate always runs first;
; remembered consent never substitutes for current VM/window/session proof.
app_grants_configure_installed:
    cmp byte [rel cmd_in_dispatch],0
    jne ag_bad
    mov [rel ag_installed_resolver],rdi
    call app_grants_revoke
    mov eax,1
    ret

; Unconditional runtime revoke. Remembered owner consent has its own revoke API.
; Saturation permanently closes both runtime rows and installed resolution.
app_grants_revoke:
    push rdi
    push rcx
    lea rdi, [rel ag_rows]
    xor eax, eax
    mov ecx, AG_ROWS*AG_ROW_SIZE/8
    rep stosq
    call app_grants_cancel
    cmp qword [rel ag_generation], -1
    je .out
    inc qword [rel ag_generation]
.out:
    pop rcx
    pop rdi
    xor eax, eax
    ret

; cancel(): wipe frozen args before any future prompt can use this slot.
app_grants_cancel:
    push rdi
    push rcx
    mov qword [rel ag_pending_state], AG_P_NONE
    mov qword [rel ag_pending_id], 0
    lea rdi, [rel ag_snapshot]
    xor eax, eax
    mov ecx, AG_DESC_SIZE/8
    rep stosq
    pop rcx
    pop rdi
    ret

; revoke_bundle(RDI native digest32, RSI owner epoch)->1 retired/absent,0 refused.
; Exact REMOVE helper, after the coordinator's durable REMOVING + VM quiescence.
; Denial only: does not manufacture approval or authorize a storage effect.
; Copy before mutation; caller owns mapped native lifetime. Preserve unrelated
; keys/pending, so global generation is unchanged. Deleted keys cannot resolve;
; the install caller separately removes the exact remembered policy.
app_grants_revoke_bundle:
    push rbx
    push r12
    sub rsp,32
    cld
    mov rbx,rdi
    mov r12,rsi
    call smp_current_logical
    test eax,eax
    jnz .bad
    cmp byte [rel cmd_in_dispatch],0
    jne .bad
    cmp byte [rel ag_delivering],0
    jne .bad
    test rbx,rbx
    jz .bad
    mov rax,rbx
    add rax,32
    jc .bad
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .bad
    test rdx,rdx
    jz .bad
    cmp rdx,-1
    je .bad
    cmp rdx,r12
    jne .bad
    mov rsi,rbx
    mov rdi,rsp
    mov ecx,4
    rep movsq
    lea r8,[rel ag_rows]
    mov r9d,AG_ROWS
.row:
    ; AG_D_OWNER is the app principal, not the human session principal.
    cmp [r8+AG_D_EPOCH],r12
    jne .next
    lea rdi,[r8+AG_D_HASH]
    mov rsi,rsp
    mov ecx,4
    repe cmpsq
    jne .next
    mov rdi,r8
    xor eax,eax
    mov ecx,AG_ROW_SIZE/8
    rep stosq
.next:
    add r8,AG_ROW_SIZE
    dec r9d
    jnz .row
    cmp qword [rel ag_pending_state],AG_P_NONE
    je .ok
    cmp [rel ag_snapshot+AG_D_EPOCH],r12
    jne .ok
    lea rdi,[rel ag_snapshot+AG_D_HASH]
    mov rsi,rsp
    mov ecx,4
    repe cmpsq
    jne .ok
    call app_grants_cancel
.ok:
    mov ebx,1
    jmp .out
.bad:
    xor ebx,ebx
.out:
    mov rdi,rsp
    xor eax,eax
    mov ecx,4
    rep stosq
    mov eax,ebx
    add rsp,32
    pop r12
    pop rbx
    ret

ag_bad:
    xor eax, eax
    xor edx, edx
    ret

; Internal validate(RDI=160B native descriptor)->1; time in RDX.
; Caller owns native RAM lifetime; this is never a user pointer API.
ag_validate:
    push rbx
    mov rbx, rdi
    cmp qword [rel ag_generation], -1
    je .bad
    cmp qword [rel ag_validator], 0
    je .bad
    cmp qword [rel ag_resume_op], 0
    je .bad
    cmp qword [rel tsc_khz], 0
    je .bad
    cmp byte [rel session_locked], SESSION_UNLOCKED
    jne .bad
    cmp qword [rel session_key_handle], 0
    je .bad
    test rbx, rbx
    jz .bad
    cmp qword [rbx + AG_D_VERSION], 1
    jne .bad
    cmp qword [rbx + AG_D_RESERVED], 0
    jne .bad
    mov rax, [rel session_authority_epoch]
    test rax, rax
    jz .bad
    cmp rax, -1
    je .bad
    cmp rax, [rbx + AG_D_EPOCH]
    jne .bad
    ; All opaque native lifetime identities must be nonzero.
    mov ecx, AG_D_PID
.ids:
    cmp qword [rbx + rcx], 0
    je .bad
    add ecx, 8
    cmp ecx, AG_D_HASH
    jb .ids
    mov rax, [rbx + AG_D_PID]
    cmp rax, [rbx + AG_D_OWNER]
    jne .bad
    mov rax, [rbx + AG_D_RAWGEN]
    shr rax, 32
    jnz .bad
    mov rax, [rbx + AG_D_HASH]
    or rax, [rbx + AG_D_HASH + 8]
    or rax, [rbx + AG_D_HASH + 16]
    or rax, [rbx + AG_D_HASH + 24]
    jz .bad
    cmp qword [rbx + AG_D_OP], 1
    jb .bad
    cmp qword [rbx + AG_D_OP], 4
    ja .bad
    cmp qword [rbx + AG_D_SEQ], 0
    je .bad
    cmp qword [rbx + AG_D_TIMEOUT], 5000
    ja .bad
    cmp qword [rbx + AG_D_OP], 2
    je .args_ok
    cmp qword [rbx + AG_D_TIMEOUT], 0
    jne .bad
    cmp qword [rbx + AG_D_OP], 1
    jne .token
    cmp qword [rbx + AG_D_CURSOR], 0
    jne .bad
    jmp .args_ok
.token:
    cmp qword [rbx + AG_D_CURSOR], 0
    je .bad
.args_ok:
    call [rel ag_validator]
    cmp eax, 1
    jne .bad
    call time_monotonic_now_us
    test rax, rax
    jz .bad
    mov rdx, rax
    mov eax, 1
    pop rbx
    ret
.bad:
    xor eax, eax
    xor edx, edx
    pop rbx
    ret

; set(RDI=desc,ESI=DENY/ALLOW/ASK,RDX=ttl_us)->1/0.
; Only live keyed local OWNER outside dispatch/injection can change policy.
; Key is validated native first128 bytes, optionally scoped only across windows.
; Every original descriptor still proves its exact requested window first.
app_grants_set:
    push rbx
    push r12
    push r13
    push r14
    sub rsp,8
    mov rbx, rdi
    mov r12d, esi
    mov r13, rdx
    cmp byte [rel cmd_in_dispatch], 0
    jne .bad
    cmp esi, AG_ASK
    ja .bad
    test r13, r13
    jz .bad
    cmp r13, AG_POLICY_MAX_US
    ja .bad
    call session_shell_local_authority
    cmp rax, PRIN_OWNER
    jne .bad
    mov rdi, rbx
    call ag_validate
    test eax, eax
    jz .bad
    mov [rsp],rdx
    mov rdi,rbx
    call ag_policy_key
    mov rdx,[rsp]
    test rax,rax
    jz .bad
    mov rbx,rax
    add r13, rdx
    jc .bad
    ; Reuse exact key, otherwise a vacant/expired slot. No implicit eviction.
    lea r14, [rel ag_rows]
    xor r8d, r8d
    mov r9d, AG_ROWS
.scan:
    cmp qword [r14 + AG_KEY_SIZE + 8], rdx
    jbe .free
    mov rdi, r14
    mov rsi, rbx
    mov ecx, AG_KEY_SIZE/8
    repe cmpsq
    je .found
    jmp .next
.free:
    test r8, r8
    jnz .next
    mov r8, r14
.next:
    add r14, AG_ROW_SIZE
    dec r9d
    jnz .scan
    mov r14, r8
    test r14, r14
    jz .bad
.found:
    ; Mutation cancels pending even when setting identical policy.
    cmp qword [rel ag_generation], -2
    jae .bad
    inc qword [rel ag_generation]
    call app_grants_cancel
    mov rdi, r14
    mov rsi, rbx
    mov ecx, AG_KEY_SIZE/8
    rep movsq
    mov [r14 + AG_KEY_SIZE], r12
    mov [r14 + AG_KEY_SIZE + 8], r13
    mov eax, 1
    jmp .out
.bad:
    xor eax, eax
.out:
    add rsp,8
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; check(desc)->EAX policy (0 closed), RDX exact current generation or0.
; Passive extra results R8 source0closed/1runtime/2installed, R9 validated
; resolution time_us (0 unavailable), R10 runtime expiry_us (0 otherwise).
; These report this lookup only; they never change policy or imply revocation.
app_grants_check:
    push rbx
    push r12
    push r13
    push r14
    sub rsp,8
    xor r13d,r13d
    mov r14,rdi
    mov rbx, rdi
    call ag_validate
    test eax, eax
    jz .bad
    mov r13,rdx
    mov rdi,rbx
    call ag_policy_key
    test rax,rax
    jz .bad
    mov rbx,rax
    mov rdx,r13
    lea r12, [rel ag_rows]
    mov r8d, AG_ROWS
.scan:
    cmp qword [r12 + AG_KEY_SIZE + 8], rdx
    jbe .next
    mov rdi, r12
    mov rsi, rbx
    mov ecx, AG_KEY_SIZE/8
    repe cmpsq
    je .found
.next:
    add r12, AG_ROW_SIZE
    dec r8d
    jnz .scan
    cmp qword [rel ag_installed_resolver],0
    je .bad
    mov rdi,r14                  ; resolver proves the actual requested window
    call [rel ag_installed_resolver]
    cmp eax,AG_ASK
    ja .bad
    cmp rdx,[rel ag_generation]
    jne .bad
    mov r8d,2
    xor r10d,r10d
    jmp .out
.bad:
    xor eax, eax
    xor edx, edx
    xor r8d,r8d
    xor r10d,r10d
    jmp .out
.found:
    mov eax, [r12 + AG_KEY_SIZE]
    mov rdx, [rel ag_generation]
    mov r8d,1
    mov r10,[r12 + AG_KEY_SIZE + 8]
.out:
    mov r9,r13
    add rsp,8
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ask(desc)->RAX native opaque id,0 refusal. One pending slot. Caller VM must
; have frozen original invocation independently; no borrowed frame or replay.
app_grants_ask:
    push rbx
    push r12
    mov rbx, rdi
    call app_grants_pending
    test rax, rax
    jnz .bad
    mov rdi, rbx
    call app_grants_check
    cmp eax, AG_ASK
    jne .bad
    mov r12, rdx
    cmp qword [rel ag_serial], -1
    je .bad
    call time_monotonic_now_us
    add rax, AG_HUMAN_US
    jc .bad
    mov [rel ag_pending_until], rax
    mov [rel ag_pending_generation], r12
    inc qword [rel ag_serial]
    mov rax, [rel ag_serial]
    mov [rel ag_pending_id], rax
    mov rsi, rbx
    lea rdi, [rel ag_snapshot]
    mov ecx, AG_DESC_SIZE/8
    rep movsq
    mov qword [rel ag_pending_state], AG_P_WAIT
    jmp .out
.bad:
    xor eax, eax
.out:
    pop r12
    pop rbx
    ret

; pending()->RAX id, RDX read-only native snapshot or0; revalidate every tick.
app_grants_pending:
    cmp qword [rel ag_pending_state], AG_P_NONE
    je ag_bad
    push rbx
    mov rbx, [rel ag_pending_generation]
    cmp rbx, [rel ag_generation]
    jne .cancel
    lea rdi, [rel ag_snapshot]
    call app_grants_check
    cmp eax, AG_ASK
    jne .cancel
    cmp rbx, rdx
    jne .cancel
    call time_monotonic_now_us
    cmp rax, [rel ag_pending_until]
    jae .cancel
    mov rax, [rel ag_pending_id]
    lea rdx, [rel ag_snapshot]
    pop rbx
    ret
.cancel:
    call app_grants_cancel
    xor eax, eax
    xor edx, edx
    pop rbx
    ret

; approve(RDI=id,RSI=authority snapshot from HUMAN key)->1/0.
; GUI is the only caller. This API is not a provenance oracle for guest code.
; Every failed approval retires pending; no effect or durable policy mutation.
app_grants_approve:
    push rbx
    push r12
    mov rbx, rdi
    mov r12, rsi
    cmp byte [rel cmd_in_dispatch], 0
    jne .bad
    cmp qword [rel ag_pending_state], AG_P_WAIT
    jne .bad
    call session_shell_local_authority
    cmp rax, PRIN_OWNER
    jne .bad
    cmp rdx, r12
    jne .bad
    call app_grants_pending
    test rax, rax
    jz .bad
    cmp rax, rbx
    jne .bad
    mov qword [rel ag_pending_state], AG_P_APPROVED
    mov eax, 1
    jmp .out
.bad:
    call app_grants_cancel
    xor eax, eax
.out:
    pop r12
    pop rbx
    ret

; consume(RDI=id,RSI=exact original desc)->1/0. Native VM continuation only.
; Revalidate then spend BEFORE any effect, failure, callback or reentry.
app_grants_consume:
    push rbx
    push r12
    mov rbx, rdi
    mov r12, rsi
    cmp qword [rel ag_pending_state], AG_P_APPROVED
    jne .bad
    call app_grants_pending
    test rax, rax
    jz .bad
    cmp rax, rbx
    jne .bad
    lea rdi, [rel ag_snapshot]
    mov rsi, r12
    mov ecx, AG_DESC_SIZE/8
    repe cmpsq
    jne .bad
    call app_grants_cancel
    mov eax, 1
    jmp .out
.bad:
    call app_grants_cancel
    xor eax, eax
.out:
    pop r12
    pop rbx
    ret

; resume(): depth0 UI tick only, after approve. Mark delivering first, call
; original native VM continuation exactly once. It MUST consume before effect.
; Snapshot copy survives consume's wipe only on this native stack, then erased.
app_grants_resume:
    cmp byte [rel cmd_in_dispatch], 0
    jne .bad
    cmp byte [rel ag_delivering], 0
    jne .bad
    cmp qword [rel ag_pending_state], AG_P_APPROVED
    jne .bad
    push rbx
    sub rsp, AG_DESC_SIZE
    call app_grants_pending
    test rax, rax
    jz .done
    mov rbx, rax
    mov rsi, rdx
    mov rdi, rsp
    mov ecx, AG_DESC_SIZE/8
    rep movsq
    mov byte [rel ag_delivering], 1
    mov rdi, rbx
    mov rsi, rsp
    call [rel ag_resume_op]
    mov byte [rel ag_delivering], 0
    ; No result is inferred here; VM owns typed final response and uncertainty.
    call app_grants_cancel
.done:
    mov rdi, rsp
    xor eax, eax
    mov ecx, AG_DESC_SIZE/8
    rep stosq
    add rsp, AG_DESC_SIZE
    pop rbx
.bad:
    ret

%include "core/abi/wdata.inc"
%macro WDATA_app_grants 0
align 8
ag_validator: dq 0
ag_scope: dq 0
ag_installed_resolver: dq 0
ag_resume_op: dq 0
ag_generation: dq 1
ag_serial: dq 0
ag_pending_state: dq 0
ag_pending_id: dq 0
ag_pending_generation: dq 0
ag_pending_until: dq 0
ag_delivering: db 0
%endmacro
WDATA_DEFER WDATA_app_grants
%macro WDATA_app_grants_bss 0
alignb 8
ag_rows: resb AG_ROWS*AG_ROW_SIZE
ag_snapshot: resb AG_DESC_SIZE
%endmacro
WDATA_BSS_DEFER WDATA_app_grants_bss

; Native depth-zero diagnostic: digest32 -> exact runtime row count / pending count.
; Read only; not policy resolution and never an approval or grant setter.
app_grants_observe:
    push rbx
    mov rbx,rdi
    xor r10d,r10d
    xor r11d,r11d
    lea r8,[rel ag_rows]
    mov r9d,AG_ROWS
.row:
    cmp qword [r8+AG_D_INSTANCE],0
    je .next
    lea rdi,[r8+AG_D_HASH]
    mov rsi,rbx
    mov ecx,4
    cld
    repe cmpsq
    jne .next
    inc r10d
.next:
    add r8,AG_ROW_SIZE
    dec r9d
    jnz .row
    cmp qword [rel ag_pending_state],AG_P_NONE
    je .out
    lea rdi,[rel ag_snapshot+AG_D_HASH]
    mov rsi,rbx
    mov ecx,4
    repe cmpsq
    jne .out
    inc r11d
.out:
    mov rax,r10
    mov rdx,r11
    pop rbx
    ret
