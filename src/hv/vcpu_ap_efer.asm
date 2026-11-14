;; MODULE hv/vcpu_ap_efer
;; LAYER 5
;; EXPORTS vcpu_ap_efer_write_check
;; IMPORTS
;; CAPS
;; OWNER saga:hv
; Creator: Codex / rc-vm-claude. Checked helpers; AP cycle wiring remains separate.
; Private guest EFER candidate validation; the caller owns VMCS publication.
; The caller already validated/bound the current mode tuple with mode_check.
; RDI tuple, RSI WRMSR value, RDX private candidate output, RCX writable
; EFER mask frozen at START (subset SCE|LME|NXE). -> EAX 1 candidate staged,
; or 0 guest #GP(0), or 2 internal-integrity refusal (caller must stop).
; Both refusals leave candidate, old tuple and RIP untouched.
; This only stages a value: eventual caller commits guest EFER in its VMCS,
; keeping host EFER and the frozen host-load controls/restore value separate.
; Intel SDM vol3A 4.1.1: WRMSR ignores the read-only LMA source bit.
vcpu_ap_efer_write_check:
    test rcx, ~0x901
    jnz  .internal
    mov  r8, rcx
    or   r8, 1 << 10
    not  r8
    test rsi, r8
    jnz  .gp                            ; reserved or unadvertised feature
    mov  r9, [rdi + 40]
    test r9, r8
    jnz  .internal                      ; never turn a bad host tuple into guest #GP
    bt   qword [rdi + 24], 31            ; cannot change LME while paging
    jnc  .value
    mov  r8, rsi
    xor  r8, r9
    test r8, 1 << 8
    jnz  .gp
.value:
    and  rsi, ~(1 << 10)
    and  r9, 1 << 10
    or   rsi, r9
    mov  [rdx], rsi                     ; only write, after every check
    mov  eax, 1
    ret
.gp:
    xor  eax, eax
    ret
.internal:
    mov  eax, 2
    ret
