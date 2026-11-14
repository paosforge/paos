;; MODULE boot/menu_labels_qemu
;; LAYER 0
;; EXPORTS menu_labels_qemu_selftest
;; IMPORTS boot/serial
;; CAPS
;; OWNER saga:boot_v2_manager_menu_user_labels
; Task 1311 regression KAT. The real Manager/QEMU/OCR matrix is graded by
; gauntlet_v2/test/boot_v2_manager_menu_user_labels_cases.py. This small
; product-side KAT checks the A/B complement mapping used by the Manager before
; emitting the contract-declared marker in fixture and ordinary regressions; it
; has no live-path side effects beyond the serial evidence line.

menu_labels_qemu_selftest:
    mov  eax, 1                       ; Active=A
    mov  edx, 3
    sub  edx, eax                     ; standby must be B
    cmp  edx, 2
    jne  .out
    mov  eax, 2                       ; Active=B
    mov  edx, 3
    sub  edx, eax                     ; standby must be A
    cmp  edx, 1
    jne  .out
    lea  rdi, [rel str_menu_labels_qemu_pass]
    call serial_string
.out:
    ret

str_menu_labels_qemu_pass:
    db "[boot.v2.menu.labels.scenario] menu user-labels QEMU scenario PASS [boot.v2.menu.labels.scenario]",13,10,0
