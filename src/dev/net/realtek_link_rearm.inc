; Shared ordinary producer transition state. Caller already owns the driver
; producer gate; this body never recurses through its public gated operations.
; State qwords: phase, pre-down OWN bitmap, down, up, rearmed, stuck, failures.
; 0 unseen, 1 up, 2 down, 3 own autoneg settling, 4 failed (no private retry).
; Diagnostic record (ROOT120117), written only here and by the settle check,
; never read back by any transition: ticks, live OWN bitmap, raw link-status
; register, settle-check BMCR and BMSR, raw CMD byte. 65535 = not read.
; At an up edge a live CMD without TE|RE armed takes the checked reset, and
; every reset must read TE|RE back armed or the machine fails closed.
%ifndef PAOS_REALTEK_LINK_REARM
%define PAOS_REALTEK_LINK_REARM 1
REALTEK_LR_TICKS equ 56
REALTEK_LR_OWN   equ 64
REALTEK_LR_PHYS  equ 72
REALTEK_LR_BMCR  equ 80
REALTEK_LR_BMSR  equ 88
REALTEK_LR_CMD   equ 96
REALTEK_LR_SIZE  equ 104
REALTEK_LR_UNREAD equ 65535
REALTEK_LR_CMD_MASK  equ 0x1c       ; CMD RESET|RE|TE
REALTEK_LR_CMD_ARMED equ 0x0c       ; RE|TE, not in reset
%macro REALTEK_LINK_REARM_BODY 1
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov r12, rax
    inc qword [r12+REALTEK_LR_TICKS]
    cmp qword [r12], 4
    je %%unavailable
    call %1 %+ _lr_sample            ; RAX 0/1/-1, RDX raw register or UNREAD
    mov [r12+REALTEK_LR_PHYS], rdx
    cmp rax, 1
    ja %%unavailable                 ; unknown is never an edge
    mov r13, rax
    ; Diagnostic snapshot: every tick outside phase 1, else ticks 1, 65, 129...
    ; Memory and MMIO reads only; no effect and no transition reads them.
    cmp qword [r12], 1
    jne %%snapshot
    mov eax, [r12+REALTEK_LR_TICKS]
    and eax, 63
    cmp eax, 1
    jne %%snapshot_done
%%snapshot:
    call %1 %+ _lr_own
    mov [r12+REALTEK_LR_OWN], rax
    call %1 %+ _lr_cmd
    mov [r12+REALTEK_LR_CMD], rax
%%snapshot_done:
    mov rax, r13
    cmp qword [r12], 3
    je %%settling
    test eax, eax
    jnz %%up
    cmp qword [r12], 2
    je %%ok
    cmp qword [r12], 1
    jne %%save_down
    inc qword [r12+16]
%%save_down:
    call %1 %+ _lr_own
    mov [r12+8], rax
    mov qword [r12], 2
    jmp %%ok
%%up:
    cmp qword [r12], 2
    jne %%initial_up
    inc qword [r12+24]
    ; The checked clear-PDOWN/readback/restart sequence comes before DMA
    ; recovery. No descriptor is cleared on a failed PHY transaction.
    call %1 %+ _lr_wake
    test eax, eax
    jnz %%failed
    call %1 %+ _lr_own
    and rax, [r12+8]
    jz %%own_clear
    inc qword [r12+40]
    jmp %%reset
%%own_clear:
    ; A MAC that lost TE|RE across the outage takes the same checked
    ; reset/rearm (ROOT122393, Beelink790: CMD 0x0c -> 0 with OWN clear).
    ; RESET set, 0xff or an unread CMD also fails the armed test.
    call %1 %+ _lr_cmd
    mov [r12+REALTEK_LR_CMD], rax
    and eax, REALTEK_LR_CMD_MASK
    cmp eax, REALTEK_LR_CMD_ARMED
    je %%woken
%%reset:
    call %1 %+ _lr_reset
    test eax, eax
    jnz %%failed
    ; A rearm counts only once the MAC reads back TE|RE armed.
    call %1 %+ _lr_cmd
    mov [r12+REALTEK_LR_CMD], rax
    and eax, REALTEK_LR_CMD_MASK
    cmp eax, REALTEK_LR_CMD_ARMED
    jne %%failed
    inc qword [r12+32]
%%woken:
    mov qword [r12], 3
    call %1 %+ _lr_sample       ; post-effect physical sample, never cached
    mov [r12+REALTEK_LR_PHYS], rdx
    mov r13, rax
    ; ANRESTART is self-clearing. Require actual negotiated-up completion,
    ; not a timer or the pre-restart cached link bit, before arming a new edge.
%%settling:
    cmp r13, 1
    jne %%unavailable
    call %1 %+ _lr_ready
    cmp eax, 1
    jne %%unavailable
%%initial_up:
    mov qword [r12], 1
%%ok:
    xor eax, eax
    jmp %%out
%%failed:
    inc qword [r12+48]
    mov qword [r12], 4
    call %1 %+ _lr_close
%%unavailable:
    mov rax, -1
%%out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret
%endmacro
; Checked standard MII wake, private read/write callbacks operate at OCP
; addresses in EDI, value EDX, return word/-1 or zero/-1. Pinned BMCR facts:
; TI TLK111 table 8-4; driver's own BSD MII/OCP mapping, no imported code.
%macro REALTEK_PHY_WAKE_BODY 1
    push r14
    mov edi, 0xa400
    call %1 %+ _lr_phy_read
    cmp eax, 0xffff
    jae %%bad
    mov r14d, eax
    test r14d, 0x0800
    jz %%restart
    and r14d, ~0x0800
    mov edi, 0xa400
    mov edx, r14d
    call %1 %+ _lr_phy_write
    test eax, eax
    jnz %%bad
    mov edi, 0xa400
    call %1 %+ _lr_phy_read
    cmp eax, 0xffff
    jae %%bad
    test eax, 0x0800
    jnz %%bad
    mov r14d, eax
%%restart:
    call %1 %+ _lr_advertise
    test eax, eax
    jnz %%bad
    and r14d, ~0x0800
    or r14d, 0x1200
    mov edi, 0xa400
    mov edx, r14d
    call %1 %+ _lr_phy_write
    test eax, eax
    jnz %%bad
    mov edi, 0xa400
    call %1 %+ _lr_phy_read
    cmp eax, 0xffff
    jae %%bad
    and eax, 0x1800
    cmp eax, 0x1000
    jne %%bad
    xor eax, eax
    pop r14
    ret
%%bad:
    mov rax, -1
    pop r14
    ret
%endmacro
; Status record copy (memory only, no producer lock, no hardware access).
; R8 transition state, R9 destination of ten qwords: phase, saved OWN, live
; OWN, raw link status, BMCR, BMSR, CMD, (+56/+64 left for the caller's TX
; timeout and rx_poll counts), ticks. BMCR/BMSR 0 = no settle check has run.
%macro REALTEK_LR_RECORD 0
    mov rax, [r8]
    mov [r9], rax
    mov rax, [r8+8]
    mov [r9+8], rax
    mov rax, [r8+REALTEK_LR_OWN]
    mov [r9+16], rax
    mov rax, [r8+REALTEK_LR_PHYS]
    mov [r9+24], rax
    mov rax, [r8+REALTEK_LR_BMCR]
    mov [r9+32], rax
    mov rax, [r8+REALTEK_LR_BMSR]
    mov [r9+40], rax
    mov rax, [r8+REALTEK_LR_CMD]
    mov [r9+48], rax
    mov rax, [r8+REALTEK_LR_TICKS]
    mov [r9+72], rax
%endmacro
; Called only from REALTEK_LINK_REARM_BODY: R12 is that transition state. The
; record keeps what this check read; a register it did not reach stays UNREAD.
%macro REALTEK_PHY_READY_BODY 1
    mov qword [r12+REALTEK_LR_BMSR], REALTEK_LR_UNREAD
    mov edi, 0xa400
    call %1 %+ _lr_phy_read
    call %%record_bmcr
    cmp eax, 0xffff
    jae %%not_ready
    and eax, 0x1a00                ; awake, enabled, restart consumed
    cmp eax, 0x1000
    jne %%not_ready
    mov edi, 0xa402               ; BMSR, completion is current (not cached)
    call %1 %+ _lr_phy_read
    call %%record_bmsr
    cmp eax, 0xffff
    jae %%not_ready
    test eax, 0x20                ; autonegotiation complete
    jz %%not_ready
    mov eax, 1
    ret
%%not_ready:
    xor eax, eax
    ret
%%record_bmcr:
    mov edx, REALTEK_LR_UNREAD
    cmp rax, 0xffff
    cmovb edx, eax
    mov [r12+REALTEK_LR_BMCR], rdx
    ret
%%record_bmsr:
    mov edx, REALTEK_LR_UNREAD
    cmp rax, 0xffff
    cmovb edx, eax
    mov [r12+REALTEK_LR_BMSR], rdx
    ret
%endmacro
%endif
