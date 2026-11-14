; Shared ordinary producer transition state. Caller already owns the driver
; producer gate; this body never recurses through its public gated operations.
; State qwords: phase, pre-down OWN bitmap, down, up, rearmed, stuck, failures.
; 0 unseen, 1 up, 2 down, 3 own autoneg settling, 4 failed (no private retry).
%ifndef PAOS_REALTEK_LINK_REARM
%define PAOS_REALTEK_LINK_REARM 1
REALTEK_LR_SIZE equ 56
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
    cmp qword [r12], 4
    je %%unavailable
    call %1 %+ _lr_sample
    cmp rax, 1
    ja %%unavailable                 ; unknown is never an edge
    mov r13, rax
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
    jz %%woken
    inc qword [r12+40]
    call %1 %+ _lr_reset
    test eax, eax
    jnz %%failed
    inc qword [r12+32]
%%woken:
    mov qword [r12], 3
    call %1 %+ _lr_sample       ; post-effect physical sample, never cached
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
%macro REALTEK_PHY_READY_BODY 1
    mov edi, 0xa400
    call %1 %+ _lr_phy_read
    cmp eax, 0xffff
    jae %%not_ready
    and eax, 0x1a00                ; awake, enabled, restart consumed
    cmp eax, 0x1000
    jne %%not_ready
    mov edi, 0xa402               ; BMSR, completion is current (not cached)
    call %1 %+ _lr_phy_read
    cmp eax, 0xffff
    jae %%not_ready
    test eax, 0x20                ; autonegotiation complete
    jz %%not_ready
    mov eax, 1
    ret
%%not_ready:
    xor eax, eax
    ret
%endmacro
%endif
