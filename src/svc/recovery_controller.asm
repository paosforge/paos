;; MODULE svc/recovery_controller
;; LAYER 5
;; EXPORTS recovery_controller_arm, recovery_controller_arm_grant, recovery_controller_touch, recovery_controller_cancel, recovery_controller_tick, recovery_controller_validate, recovery_controller_state
;; IMPORTS svc/recovery_boot, bootmgr/recovery_grant, svc/command_auth, core/time, boot/boot_v2_handoff, boot/boot_v2_health
;; CAPS
;; OWNER saga:boot
; Explicit owner-authorized recovery policy. BSP only. No default timer, traffic
; heuristic, firmware/storage write, reset, health mutation or action retry.
; The signed route, exact source state and enrolled owner grant MUST have
; passed pre-EBS admission before either arm entry may accept a request.
; Cooperative depth-zero controller: independent of command/status replies, not
; an NMI/hardware deadman for a stopped CPU or blocked driver stack.
;
; Request at RDI: five qwords: exact Manager attempt nonce, generation,
; operation nonce, silence seconds, maximum operation seconds. All are explicit.
; The signed policy fixes 180 seconds silence / 1800 seconds maximum. No automatic renewal
; or first-contact cancellation. One policy per boot, including cancellation or
; terminal refusal. A failed pre-arm validation has no authority/effect.
RC_OFF      equ 0
RC_ARMED    equ 1
RC_CANCELLED equ 2
RC_CLAIMED  equ 3
RC_REFUSED  equ 4
RC_MIN_SECONDS equ 30
RC_MAX_SECONDS equ 1800

; EAX=1 accepted, 0 refused. A consumed exact BOOT ticket is required, never
; an unconsumed owner envelope. The public/unsigned/local-injection floors do
; not gain authority from this API. The command caller preserves session guards.
recovery_controller_arm:
    push rbx
    mov rbx, rdi
    call command_auth_owner_request
    test eax, eax
    jz rc_arm_verified.no
    jmp rc_arm_verified

; NEXT only: actual owner-RSA grant and durable Manager attempt binding were
; verified pre-EBS. This is never callable as an unsigned command shortcut.
recovery_controller_arm_grant:
    push rbx
    mov rbx,rdi
    cmp byte [rel r5_grant+12],R5_NEXT
    jne rc_arm_verified.no
rc_arm_verified:
    cmp byte [rel recovery_boot_ready],1
    jne rc_arm_verified.no
    mov rax,[rbx+16]
    cmp rax,[rel r5_grant+R5_OP]
    jne rc_arm_verified.no
    cmp byte [rel recovery_controller_state], RC_OFF
    jne .no
    call rc_identity_ready
    test eax, eax
    jz .no
    mov rax, [rbx]
    cmp rax, [rel pbm_attempt_nonce]
    jne .no
    mov rax, [rbx + 8]
    cmp rax, [rel pbm_state_generation]
    jne .no
    cmp qword [rbx + 16], 0
    je .no
    mov rax, [rbx + 24]
    cmp rax,R5_SOFT_SECONDS
    jne .no
    mov rdx, [rbx + 32]
    cmp rdx,R5_HARD_SECONDS
    jne .no
    cmp qword [rel tsc_khz], 0
    je .no
    call time_monotonic_now_us
    test rax, rax
    jz .no
    mov r8, [rbx + 32]
    imul r8, 1000000
    add r8, rax
    jc .no
    mov r9, [rbx + 24]
    imul r9, 1000000
    mov [rel rc_gap_us], r9
    add r9, rax
    jc .no
    mov [rel rc_last_us], rax
    mov [rel rc_absolute_us], r8
    mov [rel rc_deadline_us], r9
    mov rax, [rbx]
    mov [rel rc_boot_nonce], rax
    mov rax, [rbx + 8]
    mov [rel rc_generation], rax
    mov rax, [rbx + 16]
    mov [rel rc_operation], rax
    mov rax, [rel pbm_manager_sequence]
    mov [rel rc_manager_sequence], rax
    mov al, [rel pbm_entry]
    mov [rel rc_entry], al
    lea rsi, [rel pbm_payload_sha]
    lea rdi, [rel rc_payload_sha]
    mov ecx, 4
    rep movsq
    mov byte [rel recovery_controller_state], RC_ARMED
    mov eax, 1
    jmp .out
.no:
    xor eax, eax
.out:
    pop rbx
    ret

; Only the matching operation's consumed owner request may renew or cancel.
; A late request never revives/cancels an expired policy. A wrong operation or
; unsigned traffic never changes the deadline, even after initial contact.
recovery_controller_touch:
    push rbx
    mov rbx, rdi
    call rc_owner_operation
    test eax, eax
    jz .out
    mov rdx, [rel rc_gap_us]
    add rdx, [rel rc_last_us]
    jc .bad
    cmp rdx, [rel rc_absolute_us]
    jbe .store
    mov rdx, [rel rc_absolute_us]
.store:
    mov [rel rc_deadline_us], rdx
    mov eax, 1
    jmp .out
.bad:
    mov byte [rel recovery_controller_state], RC_REFUSED
    xor eax, eax
.out:
    pop rbx
    ret

recovery_controller_cancel:
    push rbx
    mov rbx, rdi
    call rc_owner_operation
    test eax, eax
    jz .out
    mov byte [rel recovery_controller_state], RC_CANCELLED
    mov eax, 1
.out:
    pop rbx
    ret

; Internal: RBX=request with the first three bound identity qwords.
rc_owner_operation:
    call command_auth_owner_request
    test eax, eax
    jz .no
    cmp byte [rel recovery_controller_state], RC_ARMED
    jne .no
    mov rax, [rbx]
    cmp rax, [rel rc_boot_nonce]
    jne .no
    mov rax, [rbx + 8]
    cmp rax, [rel rc_generation]
    jne .no
    mov rax, [rbx + 16]
    cmp rax, [rel rc_operation]
    jne .no
    call recovery_controller_validate
    test eax, eax
    jz .no
    mov rax, [rel rc_last_us]
    cmp rax, [rel rc_deadline_us]
    jae .no
    cmp rax, [rel rc_absolute_us]
    jae .no
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

; Depth zero only, after every request/driver frame has unwound. EAX=1 ONCE
; at min(silence deadline, absolute operation cap); otherwise 0. Consumption
; precedes all quiesce/route/reset effects. A failure cannot retry via the loop.
recovery_controller_tick:
    cmp byte [rel recovery_controller_state], RC_ARMED
    jne .no
    call recovery_controller_validate
    test eax, eax
    jz .no
    mov rax, [rel rc_last_us]
    cmp rax, [rel rc_deadline_us]
    jae .claim
    cmp rax, [rel rc_absolute_us]
    jb .no
.claim:
    mov byte [rel recovery_controller_state], RC_CLAIMED
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

; Validate the exact boot/operation binding and monotonic domain again at the
; power boundary. A vanished/regressed/overflowing clock or identity drift is
; terminal: refuse instead of resetting on guessed elapsed time or another boot.
; Only armed/claimed policies validate; no empty policy can authorize a reset.
recovery_controller_validate:
    cmp byte [rel recovery_controller_state], RC_ARMED
    je .check
    cmp byte [rel recovery_controller_state], RC_CLAIMED
    jne .no
.check:
    call rc_identity_ready
    test eax, eax
    jz .bad
    mov rax, [rel pbm_attempt_nonce]
    cmp rax, [rel rc_boot_nonce]
    jne .bad
    mov rax, [rel pbm_state_generation]
    cmp rax, [rel rc_generation]
    jne .bad
    mov rax, [rel pbm_manager_sequence]
    cmp rax, [rel rc_manager_sequence]
    jne .bad
    mov al, [rel pbm_entry]
    cmp al, [rel rc_entry]
    jne .bad
    lea rsi, [rel pbm_payload_sha]
    lea rdi, [rel rc_payload_sha]
    mov ecx, 4
    repe cmpsq
    jne .bad
    cmp qword [rel tsc_khz], 0
    je .bad
    call time_monotonic_now_us
    test rax, rax
    jz .bad
    cmp rax, [rel rc_last_us]
    jb .bad
    mov [rel rc_last_us], rax
    mov eax, 1
    ret
.bad:
    mov byte [rel recovery_controller_state], RC_REFUSED
.no:
    xor eax, eax
    ret

rc_identity_ready:
    cmp byte [rel pbm_manager_launch], 1
    jne .no
    cmp byte [rel pbm_try_media], 0
    jne .no
    cmp byte [rel pbm_profile], PBM_PROFILE_NORMAL
    jne .no
    cmp byte [rel pbm_strong_health_published], 1
    je .health_ready
    ; An owner-signed NEXT grant also permits pre-health Rescue entry. It
    ; never acknowledges health or clears BIP; Manager preserves those fields.
    cmp byte [rel r5_grant+12],R5_NEXT
    jne .no
    cmp byte [rel recovery_boot_ready],1
    jne .no
.health_ready:
    cmp byte [rel pbm_sb_secureboot], 1
    jne .no
    cmp byte [rel pbm_runtime_code_mapped], 1
    jne .no
    cmp qword [rel pbm_attempt_nonce], 0
    je .no
    cmp qword [rel pbm_state_generation], 0
    je .no
    cmp qword [rel pbm_manager_sequence], 0
    je .no
    mov al, [rel pbm_entry]
    cmp al, PBM_ENTRY_PAOS_A
    je .digest
    cmp al, PBM_ENTRY_PAOS_B
    jne .no
.digest:
    lea rdx, [rel pbm_payload_sha]
    mov rax, [rdx]
    or rax, [rdx + 8]
    or rax, [rdx + 16]
    or rax, [rdx + 24]
    jz .no
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

%include "core/abi/wdata.inc"
%macro WDATA_recovery_controller 0
align 8
rc_boot_nonce: dq 0
rc_generation: dq 0
rc_operation: dq 0
rc_manager_sequence: dq 0
rc_gap_us: dq 0
rc_last_us: dq 0
rc_absolute_us: dq 0
rc_deadline_us: dq 0
rc_payload_sha: times 32 db 0
rc_entry: db 0
recovery_controller_state: db 0
%endmacro
WDATA_DEFER WDATA_recovery_controller
