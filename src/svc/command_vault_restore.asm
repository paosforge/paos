;; MODULE svc/command_vault_restore
;; LAYER 5
;; EXPORTS vault_restore_select, vault_restore_qemu_selftest
;; IMPORTS boot/serial
;; CAPS
;; OWNER saga:boot_v2_ge_c4_vault_verify_restore
; ============================================================================
; GE C4 immutable-Vault restore policy.
;
; The E02 Manager owns the actual pre-EBS filesystem transaction.  This module
; deliberately has no ESP writer and no command/target mutation surface.  It
; keeps the product-side decision boundary independently testable: only one of
; the four retained recovery targets may be selected, both owner signatures
; must already have verified, and the selected Vault source must exactly match
; its signed identity.  An exact live target is a no-op; only missing/corrupt
; selected targets advance to the Manager's bounded one-file transaction.
; ============================================================================

C4VR_TARGET_SLOT_A  equ 1
C4VR_TARGET_SLOT_B  equ 2
C4VR_TARGET_RESCUE  equ 3
C4VR_TARGET_MANAGER equ 4

C4VR_LIVE_MISSING equ 0
C4VR_LIVE_EXACT   equ 1
C4VR_LIVE_CORRUPT equ 2

C4VR_REFUSE  equ 0
C4VR_NOOP    equ 1
C4VR_RESTORE equ 2

; Pure pre-transaction selector.
; EDI=target class, ESI=normal manifest verified, EDX=Vault receipt signature
; verified, ECX=selected source exact, R8D=live state.  Returns C4VR_* in EAX.
vault_restore_select:
    cmp  edi, C4VR_TARGET_SLOT_A
    jb   .refuse
    cmp  edi, C4VR_TARGET_MANAGER
    ja   .refuse
    cmp  esi, 1
    jne  .refuse
    cmp  edx, 1
    jne  .refuse
    cmp  ecx, 1
    jne  .refuse
    cmp  r8d, C4VR_LIVE_CORRUPT
    ja   .refuse
    cmp  r8d, C4VR_LIVE_EXACT
    je   .noop
    mov  eax, C4VR_RESTORE
    ret
.noop:
    mov  eax, C4VR_NOOP
    ret
.refuse:
    mov  eax, C4VR_REFUSE
    ret

; The Phase-6 host driver content-grades the full signed fixture matrix.  This
; KAT prevents the product decision seam/marker from going stale or becoming a
; proceed-anyway branch while retaining zero write authority in PaOS.
vault_restore_qemu_selftest:
%ifdef PAOS_GE_C4_QEMU_SCENARIO
    mov  edi, C4VR_TARGET_SLOT_A
    mov  esi, 1
    mov  edx, 1
    mov  ecx, 1
    mov  r8d, C4VR_LIVE_MISSING
    call vault_restore_select
    cmp  eax, C4VR_RESTORE
    jne  .out

    mov  edi, C4VR_TARGET_MANAGER
    mov  esi, 1
    mov  edx, 1
    mov  ecx, 1
    mov  r8d, C4VR_LIVE_CORRUPT
    call vault_restore_select
    cmp  eax, C4VR_RESTORE
    jne  .out

    mov  edi, C4VR_TARGET_RESCUE
    mov  esi, 1
    mov  edx, 1
    mov  ecx, 1
    mov  r8d, C4VR_LIVE_EXACT
    call vault_restore_select
    cmp  eax, C4VR_NOOP
    jne  .out

    mov  edi, C4VR_TARGET_SLOT_B
    mov  esi, 1
    xor  edx, edx
    mov  ecx, 1
    mov  r8d, C4VR_LIVE_CORRUPT
    call vault_restore_select
    cmp  eax, C4VR_REFUSE
    jne  .out

    mov  edi, C4VR_TARGET_MANAGER + 1
    mov  esi, 1
    mov  edx, 1
    mov  ecx, 1
    mov  r8d, C4VR_LIVE_MISSING
    call vault_restore_select
    cmp  eax, C4VR_REFUSE
    jne  .out

    mov  edi, C4VR_TARGET_SLOT_A
    mov  esi, 1
    mov  edx, 1
    xor  ecx, ecx
    mov  r8d, C4VR_LIVE_CORRUPT
    call vault_restore_select
    cmp  eax, C4VR_REFUSE
    jne  .out

    lea  rdi, [rel str_c4vr_qemu_pass]
    call serial_string
.out:
%endif
    ret

str_c4vr_qemu_pass:
    db "[boot.v2.ge.c4.scenario] GE C4 QEMU scenario PASS [boot.v2.ge.c4.scenario]",13,10,0
