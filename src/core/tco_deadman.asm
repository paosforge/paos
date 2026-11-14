;; MODULE core/tco_deadman
;; LAYER 1
;; EXPORTS tco_deadman_arm, tco_deadman_kick, tco_deadman_state, tco_deadman_base, tco_deadman_cnt0, tco_deadman_ran, tco_deadman_kicks, tco_proof_hang
;; IMPORTS core/time, boot/serial, core/reset_wipe
;; CAPS io
;; OWNER saga:msi_desktop_completion
; ============================================================================
; core/tco_deadman.asm — a HARDWARE deadman: the Intel PCH TCO watchdog, armed
; and kicked, so a wedge nobody can see still ends with a platform reset.
;
; Ported from the MSI spoke (paos_msi src/core/tco_deadman.asm, hub packet 0011).
; Every software return (a CF9 tick, an armed fault CF9, a PMI/NMI deadman) needs
; the CPU to keep executing PaOS code. The TCO counts in the chipset: once armed
; and no longer reloaded it resets the platform by itself, whatever the CPU does.
;
; Opt-in (PAOS_TCO_DEADMAN): boot/header.asm arms it right after boot_ab_early
; (P1, after EBS + paging, before the P3+ device selftests) and the idle loop
; kicks it at most every second, so the platform resets about TCO_BUDGET_S after
; the loop last ran. boot_ab's own TCO measurement (halted afterwards) runs
; first and never touches the TCO again. Arming on every hub build by default is
; a hub decision (see the packet header).
;
; Discovery (read-only CF8/CFC): the SMBus function (class 0C05) at 1F.4 on bus
; 0 or the PCH die's bus 0x80 (Arrow Lake: 80:1F.4 8086:7f23) with TCOCTL (0x54)
; bit 8 TCO_BASE_EN and TCOBASE (0x50); else the ICH-style LPC 1F.0 ACPI base
; (0x40, enable 0x44 bit 7) + 0x60 (QEMU q35 ICH9).
; Registers (16-bit I/O): +0x00 TCO_RLD (read = count, write = reload),
; +0x04 TCO1_STS (bit 3 TIMEOUT, W1C), +0x06 TCO2_STS (bit 1 SECOND_TO,
; bit 2 BOOT_STS, W1C), +0x08 TCO1_CNT (bit 11 TMR_HLT, bit 12 TCO_LOCK, bit 0
; NO_REBOOT on the SMBus-based TCO v6), +0x12 TCO_TMR (bits 9:0, 0.6 s ticks).
; The chipset resets on the SECOND expiry with TIMEOUT still set, so the
; budget is two timer periods.
;
; States (tco_deadman_state): 0 not run, 1 armed (halt cleared and verified),
; 2 no TCO found, 3 UNAVAILABLE: the firmware set TCO_LOCK (read-only from
; then on), 4 NO_REBOOT could not be cleared, 5 not armed by build
; (PAOS_TCO_NOARM negative control).
;
; MEASURED on metal: the MSI MS-7E19 firmware leaves TCO1_CNT = 0x1800
; (TCO_LOCK + TMR_HLT; spoke tcodiag1, 2026-10-01), as does the Lenovo M720s
; (2026-08-07). There the deadman is UNAVAILABLE: the arm path only reads, and
; nothing may count it as return coverage. It arms under QEMU q35 (ICH9).
; Lab only: PAOS_LAB_TCO_FW_LOCK makes tco_lab_firmware_lock write that same
; 0x1800 first, the MSI firmware's state, so QEMU shows the UNAVAILABLE path.
; ============================================================================
TCO_BUDGET_S      equ 150
TCO_TICKS         equ (TCO_BUDGET_S * 10 / 6) / 2   ; one period = half the budget (0.6 s ticks)
TCO_KICK_US       equ 1000000
TCO_PROOF_SAFETY_US equ 420000000                  ; a proof hang ends itself by CF9 after 7 min
TCO_R_RLD         equ 0x00
TCO_R_STS1        equ 0x04
TCO_R_STS2        equ 0x06
TCO_R_CNT1        equ 0x08
TCO_R_TMR         equ 0x12
TCO_CNT_HLT       equ 0x0800
TCO_CNT_LOCK      equ 0x1000
TCO_CNT_NOREBOOT  equ 0x0001

; tco_deadman_arm(): discover and arm. Never faults; records why it could not.
tco_deadman_arm:
    push rbx
    push r12
    push r13
%ifdef PAOS_TCO_NOARM
    mov  byte [rel tco_deadman_state], 5
    lea  rdi, [rel tco_text_noarm]
    call serial_string
    jmp  .out
%endif
    call tco_discover                   ; -> EAX base (0 none), EDX 1 = SMBus TCO (v6)
    test eax, eax
    jnz  .found
    mov  byte [rel tco_deadman_state], 2
    lea  rdi, [rel tco_text_absent]
    call serial_string
    jmp  .out
.found:
    mov  [rel tco_deadman_base], ax
    mov  r13d, edx
    mov  ebx, eax
    lea  edx, [rbx + TCO_R_CNT1]
    in   ax, dx
    mov  [rel tco_deadman_cnt0], ax
    movzx r12d, ax
    test r12d, TCO_CNT_LOCK
    jz   .noreboot
    ; TCO_LOCK set by the firmware (the MSI: TCO1_CNT 0x1800, halted too):
    ; UNAVAILABLE. Not one TCO register is written; a locked timer belongs to
    ; the firmware even when it is not halted.
    mov  byte [rel tco_deadman_state], 3
    lea  rdi, [rel tco_text_locked]
    call serial_string
    jmp  .out
.noreboot:
    test r13d, r13d
    jnz  .noreboot_cnt
    ; ICH-style (QEMU q35 ICH9): NO_REBOOT is GCS bit 5 in the LPC root complex
    ; register block (RCBA = LPC 0xF0, enable bit 0; GCS at +0x3410). Pre-EBS
    ; the firmware's identity map covers it.
    xor  edi, edi
    mov  esi, 0x1f
    xor  edx, edx
    mov  ecx, 0xf0
    call tco_cfg_read32
    test eax, 1
    jz   .timer
    and  eax, 0xffffc000
    jz   .timer
    lea  rcx, [rax + 0x3410]
    mov  eax, [rcx]
    test eax, 0x20
    jz   .timer
    and  eax, ~0x20
    mov  [rcx], eax
    mov  eax, [rcx]
    test eax, 0x20
    jz   .timer
    mov  byte [rel tco_deadman_state], 4
    lea  rdi, [rel tco_text_noreboot]
    call serial_string
    jmp  .out
.noreboot_cnt:
    test r12d, TCO_CNT_NOREBOOT
    jz   .timer
    lea  edx, [rbx + TCO_R_CNT1]
    mov  eax, r12d
    and  eax, ~TCO_CNT_NOREBOOT & 0xffff
    out  dx, ax
    in   ax, dx
    test ax, TCO_CNT_NOREBOOT
    jz   .timer
    mov  byte [rel tco_deadman_state], 4
    lea  rdi, [rel tco_text_noreboot]
    call serial_string
    jmp  .out
.timer:
    lea  edx, [rbx + TCO_R_TMR]
    in   ax, dx
    and  ax, 0xfc00
    or   ax, TCO_TICKS
    out  dx, ax
    lea  edx, [rbx + TCO_R_RLD]
    mov  ax, 1
    out  dx, ax                         ; reload to the new period
    lea  edx, [rbx + TCO_R_STS1]
    mov  ax, 0x0008
    out  dx, ax                         ; clear TIMEOUT
    lea  edx, [rbx + TCO_R_STS2]
    mov  ax, 0x0006
    out  dx, ax                         ; clear SECOND_TO and BOOT_STS
    lea  edx, [rbx + TCO_R_CNT1]
    in   ax, dx
    and  ax, ~TCO_CNT_HLT & 0xffff
    out  dx, ax                         ; start counting
    in   ax, dx
    test ax, TCO_CNT_HLT
    jz   .armed
    mov  byte [rel tco_deadman_state], 3
    lea  rdi, [rel tco_text_locked]
    call serial_string
    jmp  .out
.armed:
    mov  byte [rel tco_deadman_state], 1
    lea  rdi, [rel tco_text_armed]
    call serial_string
    movzx edi, word [rel tco_deadman_base]
    call serial_hex64
    call serial_newline
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; tco_discover -> EAX TCO I/O base (0 none), EDX 1 SMBus-based / 0 ICH-style
tco_discover:
    push rbx
    push r12
    lea  r12, [rel tco_smbus_buses]
    xor  ebx, ebx
.smbus:
    cmp  ebx, 2
    jae  .lpc
    movzx edi, byte [r12 + rbx]
    mov  esi, 0x1f
    mov  edx, 4
    xor  ecx, ecx
    call tco_cfg_read32
    cmp  ax, 0x8086
    jne  .next_bus
    movzx edi, byte [r12 + rbx]
    mov  esi, 0x1f
    mov  edx, 4
    mov  ecx, 0x08
    call tco_cfg_read32
    shr  eax, 16
    cmp  ax, 0x0c05                     ; SMBus
    jne  .next_bus
    movzx edi, byte [r12 + rbx]
    mov  esi, 0x1f
    mov  edx, 4
    mov  ecx, 0x54                      ; TCOCTL
    call tco_cfg_read32
    test eax, 0x100                     ; TCO_BASE_EN
    jz   .next_bus
    movzx edi, byte [r12 + rbx]
    mov  esi, 0x1f
    mov  edx, 4
    mov  ecx, 0x50                      ; TCOBASE
    call tco_cfg_read32
    and  eax, 0xffe0
    jz   .next_bus
    mov  edx, 1
    jmp  .out
.next_bus:
    inc  ebx
    jmp  .smbus
.lpc:
    xor  edi, edi
    mov  esi, 0x1f
    xor  edx, edx
    xor  ecx, ecx
    call tco_cfg_read32
    cmp  ax, 0x8086
    jne  .none
    xor  edi, edi
    mov  esi, 0x1f
    xor  edx, edx
    mov  ecx, 0x08
    call tco_cfg_read32
    shr  eax, 16
    cmp  ax, 0x0601                     ; ISA bridge (LPC)
    jne  .none
    xor  edi, edi
    mov  esi, 0x1f
    xor  edx, edx
    mov  ecx, 0x44                      ; ACPI_CNTL
    call tco_cfg_read32
    test eax, 0x80                      ; ACPI_EN
    jz   .none
    xor  edi, edi
    mov  esi, 0x1f
    xor  edx, edx
    mov  ecx, 0x40                      ; ACPI base (PMBASE)
    call tco_cfg_read32
    and  eax, 0xff80
    jz   .none
    add  eax, 0x60
    xor  edx, edx
    jmp  .out
.none:
    xor  eax, eax
    xor  edx, edx
.out:
    pop  r12
    pop  rbx
    ret

; tco_cfg_read32(EDI bus, ESI device, EDX function, ECX offset) -> EAX: the
; same CF8/CFC read as bus/pci, local so this layer-1 module imports no driver.
tco_cfg_read32:
    mov  eax, edi
    shl  eax, 16
    mov  r8d, esi
    shl  r8d, 11
    or   eax, r8d
    mov  r8d, edx
    shl  r8d, 8
    or   eax, r8d
    mov  r8d, ecx
    and  r8d, 0xfc
    or   eax, r8d
    or   eax, 0x80000000
    mov  dx, 0x0cf8
    out  dx, eax
    mov  dx, 0x0cfc
    in   eax, dx
    ret

; tco_deadman_kick(): reload from the resident loop, at most every TCO_KICK_US.
; The first kick records whether the chipset counter actually ran.
tco_deadman_kick:
    cmp  byte [rel tco_deadman_state], 1
    jne  .out
    push rax
    push rcx
    push rdx
    push rdi
    push r8
    call time_monotonic_now_us
    cmp  rax, [rel tco_next_kick_us]
    jb   .done
    add  rax, TCO_KICK_US
    mov  [rel tco_next_kick_us], rax
    movzx ecx, word [rel tco_deadman_base]
    lea  edx, [rcx + TCO_R_RLD]
    cmp  byte [rel tco_deadman_ran], 0
    jne  .reload
    in   ax, dx
    and  eax, 0x3ff
    cmp  eax, TCO_TICKS
    jae  .reload
    mov  byte [rel tco_deadman_ran], 1   ; it counted down from the reload value
.reload:
    mov  ax, 1
    out  dx, ax
    lea  edx, [rcx + TCO_R_STS1]
    mov  ax, 0x0008
    out  dx, ax                         ; a first expiry must not carry over
    inc  qword [rel tco_deadman_kicks]
.done:
    pop  r8
    pop  rdi
    pop  rdx
    pop  rcx
    pop  rax
.out:
    ret

%ifdef PAOS_LAB_TCO_FW_LOCK
; tco_lab_firmware_lock(): lab only. Leave TCO1_CNT as the MSI firmware does
; (TCO_LOCK + TMR_HLT = 0x1800) before tco_deadman_arm runs.
tco_lab_firmware_lock:
    push rbx
    call tco_discover
    test eax, eax
    jz   .out
    mov  ebx, eax
    lea  edx, [rbx + TCO_R_CNT1]
    in   ax, dx
    or   ax, TCO_CNT_LOCK | TCO_CNT_HLT
    out  dx, ax
    lea  rdi, [rel tco_text_lab_lock]
    call serial_string
    lea  edx, [rbx + TCO_R_CNT1]
    in   ax, dx
    movzx edi, ax
    call serial_hex64
    call serial_newline
.out:
    pop  rbx
    ret
tco_text_lab_lock: db "[PAOS64] lab.tco.fw_lock TCO1_CNT=",0
%endif

; tco_proof_hang(): the deliberate wedge of a TCO proof build (PAOS_TCO_PROOF):
; interrupts off, no kick, nothing else runs. Bare metal only unless the QEMU
; proof build (PAOS_TCO_PROOF_QEMU) asks for it under a hypervisor, so the same
; candidate's QEMU natural-return fixture is unaffected. If the chipset never
; resets, the spin ends itself by CF9 after TCO_PROOF_SAFETY_US: the timing of
; the Windows return tells which one fired (TCO ~TCO_BUDGET_S, safety later).
tco_proof_hang:
%ifdef PAOS_TCO_PROOF
%ifndef PAOS_TCO_PROOF_QEMU
    mov  eax, 1
    cpuid
    bt   ecx, 31                        ; hypervisor present: no proof hang
    jc   .out
%endif
    lea  rdi, [rel tco_text_proof]
    call serial_string
    call serial_drain_poll
    cli
    call time_monotonic_now_us
    add  rax, TCO_PROOF_SAFETY_US
    mov  r12, rax
.spin:
    pause
    call time_monotonic_now_us
    cmp  rax, r12
    jb   .spin
    call reset_wipe_all                 ; SEC-pre-reset-wipe-hook: the proof reset keeps DRAM
    mov  dx, 0x0cf9
    mov  al, 0x06
    out  dx, al
.stuck:
    hlt
    jmp  .stuck
.out:
%endif
    ret

tco_smbus_buses:   db 0x80, 0x00        ; Arrow Lake PCH die first, then a single-die PCH
tco_text_armed:    db "[PAOS64] tco.deadman.armed budget_s=150 base=",0
tco_text_absent:   db "[PAOS64] tco.deadman.absent",13,10,0
tco_text_locked:   db "[PAOS64] tco.deadman.locked (TCO_LOCK keeps the timer halted)",13,10,0
tco_text_noreboot: db "[PAOS64] tco.deadman.noreboot_locked",13,10,0
tco_text_noarm:    db "[PAOS64] tco.deadman.not_armed (negative-control build)",13,10,0
tco_text_proof:    db "[PAOS64] tco.proof.hang (deliberate wedge; the TCO must reset the platform)",13,10,0
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_core_tco_deadman_0 0
tco_deadman_state: resb 1
tco_deadman_ran:   resb 1
alignb 2
tco_deadman_base:  resw 1
tco_deadman_cnt0:  resw 1
alignb 8
tco_deadman_kicks: resq 1
tco_next_kick_us:  resq 1
%endmacro
WDATA_BSS_DEFER WDATA_core_tco_deadman_0
