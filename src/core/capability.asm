;; MODULE core/capability
;; LAYER 1
;; EXPORTS cap_scope_admit, cap_check_gate, cap_enter_scope, cap_leave_scope, capability_selftest, cap_current_mask, cap_denied_count, cap_block_write_denied
;; IMPORTS boot/serial
;; CAPS
;; OWNER saga:pmod_bundle_seam
; ============================================================================
; Runtime capability word used while an untrusted PMOD is inside the Tier-1
; sandbox.  This is honest-mistake containment, not an adversarial boundary:
; the hardware page view/guards are the isolation boundary (SECURITY.md 1.1).
; ============================================================================

PMCAP_LOG         equ (1 << 0)
PMCAP_MMIO        equ (1 << 1)
PMCAP_BLOCK_READ  equ (1 << 2)
PMCAP_BLOCK_WRITE equ (1 << 3)
PMCAP_NET         equ (1 << 4)
PMCAP_COMPUTE     equ (1 << 5)       ; portable JOB local/peer compute authority

; cap_check_gate(RDI=required bit mask) -> RAX=0 allowed / -1 denied
;  in: RDI=all bits the requested service requires
; out: RAX=0 or -1; denial counter saturates atomically; sticky reason updated
; clobbers: RAX, RCX
; caps: none
cap_check_gate:
    mov  rax, [rel cap_current_mask]
    mov  rcx, rax
    and  rax, rdi
    cmp  rax, rdi
    je   .allow
    ; One observation per denied gate, including explicit self-test probes.
    ; Saturate atomically: observation/ack reads must never see a wrapped total.
    mov  rax, [rel cap_denied_count]
.count:
    cmp  rax, -1
    je   .counted
    lea  rcx, [rax + 1]
    lock cmpxchg qword [rel cap_denied_count], rcx
    jne  .count
.counted:
    mov  [rel cap_last_denied], rdi
    test rdi, PMCAP_BLOCK_WRITE
    jz   .deny
    mov  byte [rel cap_block_write_denied], 1
.deny:
    mov  rax, -1
    ret
.allow:
    xor  eax, eax
    ret

; cap_enter_scope(RDI=granted mask) -> RAX=previous mask
;  in: RDI=manifest-authorized grant for one sandbox invocation
; out: RAX=mask to restore with cap_leave_scope
; clobbers: RAX
; caps: none
cap_enter_scope:
    mov  rax, [rel cap_current_mask]
    mov  [rel cap_current_mask], rdi
    pushfq
    inc  qword [rel cap_scope_depth]
    popfq
    ret

; cap_leave_scope(RDI=previous mask)
;  in: RDI=value returned by cap_enter_scope
; out: none
; clobbers: none
; caps: none
cap_leave_scope:
    mov  [rel cap_current_mask], rdi
    pushfq
    cmp  qword [rel cap_scope_depth], 0
    je   .out
    dec  qword [rel cap_scope_depth]
.out:
    popfq
    ret

; cap_scope_admit(RDI=requested mask) -> RAX=0/-1.
; The native host has no ambient PMOD grant (mask starts at zero). Inside an
; entered PMOD/JOB scope, a nested JOB must fit that scope, even when empty.
; Depth follows the same serialized scale-1 lifetime as cap_current_mask.
cap_scope_admit:
    cmp  qword [rel cap_scope_depth], 0
    je   .native
    jmp  cap_check_gate
.native:
    xor  eax, eax
    ret

; capability_selftest -> RAX=0 only when absent write is refused and granted
; read is accepted.  The sticky write denial is what CAP_TEST_BLOCKED exposes.
;  in: none
; out: RAX=0 pass / -1 fail
; clobbers: caller-saved
; caps: none
capability_selftest:
    mov  qword [rel cap_current_mask], 0
    mov  byte [rel cap_block_write_denied], 0
    mov  rdi, PMCAP_BLOCK_WRITE
    call cap_check_gate
    cmp  rax, -1
    jne  .fail
    mov  rdi, PMCAP_BLOCK_READ
    call cap_enter_scope
    push rax
    mov  rdi, PMCAP_BLOCK_READ
    call cap_check_gate
    pop  rdi
    call cap_leave_scope
    test rax, rax
    jnz  .fail
    cmp  byte [rel cap_block_write_denied], 1
    jne  .fail
    lea  rdi, [rel str_cap_pmod_ok]
    call serial_string
    xor  eax, eax
    ret
.fail:
    lea  rdi, [rel str_cap_pmod_fail]
    call serial_string
    mov  rax, -1
    ret

align 8
cap_current_mask:       dq 0
cap_scope_depth:        dq 0
cap_denied_count:       dq 0
cap_last_denied:        dq 0
cap_block_write_denied: db 0
str_cap_pmod_ok:   db "[PAOS64] PMOD cap gate: absent CAP_BLOCK_WRITE denied_by_cap [pmod.cap.blocked]",13,10,0
str_cap_pmod_fail: db "[PAOS64] PMOD cap gate: FAIL",13,10,0
