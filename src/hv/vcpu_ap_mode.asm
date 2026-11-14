;; MODULE hv/vcpu_ap_mode
;; LAYER 5
;; EXPORTS vcpu_ap_mode_check
;; IMPORTS
;; CAPS
;; OWNER saga:hv
; Creator: Codex / rc-vm-claude. Checked helpers; AP cycle wiring remains separate.
; Pure mode validation for the accepted E3 amendment; AP entry wiring is separate.
; Frozen GO tuple: vcpu, epoch, go, CR0, CR4, EFER, CS access rights, entry
; controls (8 qwords). Inputs must come from the quiescent VMCS hand-off or
; actual hardware-saved state, never from a prior expected-mode word.
; RDI tuple, RSI exact epoch, RDX exact GO, ECX START entry controls,
; R8 writable EFER feature mask (subset of SCE|LME|NXE frozen at START).
; Returns 1 iff the tuple is bound, mode-consistent, and bit9 matches LMA.
; Other guest-state entry checks, capability checks, memory freezing and
; INIT/SIPI construction belong to the eventual caller. No record is written.
vcpu_ap_mode_check:
    cmp  qword [rdi], 1
    jne  .bad
    test rsi, rsi
    jz   .bad
    cmp  [rdi + 8], rsi
    jne  .bad
    test rdx, rdx
    jz   .bad
    cmp  [rdi + 16], rdx
    jne  .bad
    test r8, ~0x901
    jnz  .bad
    mov  r9, [rdi + 40]                  ; private guest EFER, never host MSR
    mov  rax, r8
    or   rax, 1 << 10                    ; LMA is derived/read-only
    not  rax
    test r9, rax
    jnz  .bad
    xor  r10d, r10d                      ; independently derived active mode
    bt   qword [rdi + 24], 31            ; CR0.PG
    jnc  .derived
    test byte [rdi + 24], 1              ; paging always requires CR0.PE
    jz   .bad
    test r9d, 1 << 8                     ; legacy paging does not need LME/PAE
    jz   .derived
    test byte [rdi + 32], 1 << 5         ; IA-32e paging requires CR4.PAE
    jz   .bad
    mov  r10d, 1 << 10
.derived:
    mov  eax, r9d
    and  eax, 1 << 10
    cmp  eax, r10d
    jne  .bad                            ; consume/check actual exit-saved LMA
    test qword [rdi + 48], 1 << 13       ; CS.L: compatibility CS.L=0 is legal
    jz   .entry
    test r10d, r10d
    jz   .bad
    test qword [rdi + 48], 1 << 14       ; CS.L and CS.D/B cannot both be one
    jnz  .bad
.entry:
    mov  rax, [rdi + 56]
    mov  ecx, ecx
    xor  rcx, rax
    and  rcx, ~(1 << 9)
    jnz  .bad                            ; every other control remains START-exact
    and  eax, 1 << 9
    shr  r10d, 1
    cmp  eax, r10d
    jne  .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret
