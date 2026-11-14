;; MODULE dev/input/i2c_dw
;; LAYER 3
;; EXPORTS i2c_dw_probe, i2c_dw_lpss_wake, i2c_dw_init, i2c_dw_xfer, i2c_dw_disable, i2c_dw_mmio_rd, i2c_dw_mmio_wr
;; IMPORTS
;; CAPS CAP_MMIO
;; OWNER saga:input_system
; ============================================================================
; dev/input/i2c_dw.asm — TP0 `i2c_designware_host_core` (hub/touchpad lane, 2026-10-01).
;
; Generic, polled, bounded master for the Synopsys DesignWare APB I2C core. The
; same core sits behind Intel PCH Serial IO (LPSS wrapper: private clock/reset
; registers at +0x200) and AMD FCH I2C (ACPI AMDI0010: the bare core). Written
; from the publicly documented register map (Intel PCH datasheet volume 2,
; "Serial IO I2C" register tables; AMD FCH register reference); no third-party
; driver code. Register offsets used:
;   0x00 IC_CON  0x04 IC_TAR  0x10 IC_DATA_CMD  0x14/0x18 SS SCL H/L count
;   0x1C/0x20 FS SCL H/L count  0x30 IC_INTR_MASK  0x34 IC_RAW_INTR_STAT
;   0x40 IC_CLR_INTR  0x54 IC_CLR_TX_ABRT  0x60 IC_CLR_STOP_DET  0x6C IC_ENABLE
;   0x70 IC_STATUS  0x78 IC_RXFLR  0x80 IC_TX_ABRT_SOURCE  0x9C IC_ENABLE_STATUS
;   0xFC IC_COMP_TYPE (0x44570140, "DW" + 0x0140)
;
; The core never computes bus timing: SCL high/low counts are inputs (from the
; platform's ACPI SSCN/FMCN methods or the signed per-model table, TP1). A zero
; count is refused (I2C_DW_ERR_NO_TIMING), never guessed.
;
; All register access and time go through the caller's ops context, so the
; exact production code runs against a register model on the host
; (gauntlet_v2/tests/test_i2c_dw_core_host.py). Every wait is bounded by
; DWC_TIMEOUT_MS of the context clock. No interrupts, no DMA. SysV register
; discipline: RBX/RBP/R12-R15 preserved; the stack is realigned before every
; ops call.
; ============================================================================

; ---- ops context (caller-owned, zero-initialised) ----
DWC_RD          equ 0           ; dq fn(rdi=ctx, esi=offset) -> eax
DWC_WR          equ 8           ; dq fn(rdi=ctx, esi=offset, edx=value)
DWC_NOW_MS      equ 16          ; dq fn(rdi=ctx) -> rax monotonic ms
DWC_BASE        equ 24          ; dq MMIO base (used by i2c_dw_mmio_rd/wr only)
DWC_FRONT       equ 32          ; dd 0 = bare core (AMD), 1 = Intel LPSS wrapper
DWC_SPEED       equ 36          ; dd 1 = standard (100 kHz), 2 = fast (400 kHz)
DWC_HCNT        equ 40          ; dd SCL high count for DWC_SPEED (input, nonzero)
DWC_LCNT        equ 44          ; dd SCL low count for DWC_SPEED (input, nonzero)
DWC_TIMEOUT_MS  equ 48          ; dd bound for every wait (0 -> I2C_DW_DEFAULT_MS)
DWC_LAST_ABRT   equ 52          ; dd out: last IC_TX_ABRT_SOURCE
DWC_LAST_ERR    equ 56          ; dd out: last status code
DWC_RX_GOT      equ 60          ; dd out: bytes received by the last transfer
DWC_SIZE        equ 64

; ---- status codes (EAX) ----
I2C_DW_OK               equ 0
I2C_DW_ERR_NOT_DW       equ 1   ; IC_COMP_TYPE is not the DesignWare signature
I2C_DW_ERR_BAD_ARGS     equ 2   ; empty transfer, oversized read, bad speed/address
I2C_DW_ERR_NO_TIMING    equ 3   ; SCL counts not supplied
I2C_DW_ERR_DISABLE_TO   equ 4   ; IC_ENABLE_STATUS never reached the requested state
I2C_DW_ERR_ADDR_NAK     equ 5   ; abort: 7-bit address not acknowledged
I2C_DW_ERR_DATA_NAK     equ 6   ; abort: a written data byte not acknowledged
I2C_DW_ERR_ABORT        equ 7   ; any other abort source
I2C_DW_ERR_TIMEOUT      equ 8   ; TX FIFO never drained / no STOP within the bound
I2C_DW_ERR_RX_SHORT     equ 9   ; STOP seen with fewer bytes than requested

I2C_DW_DEFAULT_MS       equ 25
I2C_DW_RX_MAX           equ 256
I2C_DW_COMP_TYPE        equ 0x44570140

IC_CON              equ 0x00
IC_TAR              equ 0x04
IC_DATA_CMD         equ 0x10
IC_SS_SCL_HCNT      equ 0x14
IC_SS_SCL_LCNT      equ 0x18
IC_FS_SCL_HCNT      equ 0x1C
IC_FS_SCL_LCNT      equ 0x20
IC_INTR_MASK        equ 0x30
IC_RAW_INTR_STAT    equ 0x34
IC_CLR_INTR         equ 0x40
IC_CLR_TX_ABRT      equ 0x54
IC_CLR_STOP_DET     equ 0x60
IC_ENABLE           equ 0x6C
IC_STATUS           equ 0x70
IC_RXFLR            equ 0x78
IC_TX_ABRT_SOURCE   equ 0x80
IC_ENABLE_STATUS    equ 0x9C
IC_COMP_TYPE        equ 0xFC

DWC_LPSS_PRIV_CLOCK     equ 0x200   ; bit0 clock enable (+ M/N divider fields, left as firmware set them)
DWC_LPSS_PRIV_RESETS    equ 0x204   ; bits 1:0 function reset deasserted, bit2 iDMA reset deasserted

CON_MASTER          equ 0x01
CON_SPEED_SHIFT     equ 1
CON_RESTART_EN      equ 0x20
CON_SLAVE_DISABLE   equ 0x40

CMD_READ            equ 0x100
CMD_STOP            equ 0x200
CMD_RESTART         equ 0x400

ST_TFNF             equ 0x02    ; IC_STATUS: transmit FIFO not full
ST_RFNE             equ 0x08    ; IC_STATUS: receive FIFO not empty
RAW_TX_ABRT         equ 0x40
RAW_STOP_DET        equ 0x200

ABRT_7B_ADDR_NOACK  equ 0x01
ABRT_TXDATA_NOACK   equ 0x08

; ---------------------------------------------------------------------------
; Production ops: plain 32-bit MMIO relative to DWC_BASE.
i2c_dw_mmio_rd:
    mov  rax, [rdi + DWC_BASE]
    mov  esi, esi
    mov  eax, [rax + rsi]
    ret

i2c_dw_mmio_wr:
    mov  rax, [rdi + DWC_BASE]
    mov  esi, esi
    mov  [rax + rsi], edx
    ret

; ---------------------------------------------------------------------------
; Seam calls. RBX/RBP/R12-R15 survive; the stack is aligned for the callee.
dw_rd:                          ; rdi=ctx, esi=offset -> eax
    push rbp
    mov  rbp, rsp
    and  rsp, -16
    call [rdi + DWC_RD]
    mov  rsp, rbp
    pop  rbp
    ret

dw_wr:                          ; rdi=ctx, esi=offset, edx=value
    push rbp
    mov  rbp, rsp
    and  rsp, -16
    call [rdi + DWC_WR]
    mov  rsp, rbp
    pop  rbp
    ret

dw_now:                         ; rdi=ctx -> rax
    push rbp
    mov  rbp, rsp
    and  rsp, -16
    call [rdi + DWC_NOW_MS]
    mov  rsp, rbp
    pop  rbp
    ret

; dw_deadline(rdi=ctx) -> rax = now + bound
dw_deadline:
    push rbx
    mov  rbx, rdi
    call dw_now
    mov  ecx, [rbx + DWC_TIMEOUT_MS]
    test ecx, ecx
    jnz  .have
    mov  ecx, I2C_DW_DEFAULT_MS
.have:
    add  rax, rcx
    pop  rbx
    ret

; dw_expired(rdi=ctx, rsi=deadline) -> eax 1 iff now >= deadline
dw_expired:
    push rbx
    mov  rbx, rsi
    call dw_now
    xor  ecx, ecx
    cmp  rax, rbx
    setae cl
    mov  eax, ecx
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; i2c_dw_probe(rdi=ctx) -> eax status. Reads only.
i2c_dw_probe:
    push rbx
    mov  rbx, rdi
    mov  esi, IC_COMP_TYPE
    call dw_rd
    mov  ecx, I2C_DW_ERR_NOT_DW
    cmp  eax, I2C_DW_COMP_TYPE
    mov  eax, I2C_DW_OK
    cmovne eax, ecx
    mov  [rbx + DWC_LAST_ERR], eax
    pop  rbx
    ret

; i2c_dw_lpss_wake(rdi=ctx) -> eax status. Intel front-end only: deassert the
; LPSS function and iDMA resets, then set the clock-enable bit (preserving the
; firmware's divider fields). A bare core (AMD) is a no-op.
i2c_dw_lpss_wake:
    push rbx
    mov  rbx, rdi
    cmp  dword [rbx + DWC_FRONT], 1
    jne  .done
    mov  rdi, rbx
    mov  esi, DWC_LPSS_PRIV_RESETS
    mov  edx, 0x7
    call dw_wr
    mov  rdi, rbx
    mov  esi, DWC_LPSS_PRIV_CLOCK
    call dw_rd
    or   eax, 1
    mov  edx, eax
    mov  rdi, rbx
    mov  esi, DWC_LPSS_PRIV_CLOCK
    call dw_wr
.done:
    xor  eax, eax
    mov  [rbx + DWC_LAST_ERR], eax
    pop  rbx
    ret

; dw_set_enable(rdi=ctx, esi=0|1) -> eax status. Writes IC_ENABLE and waits
; (bounded) until IC_ENABLE_STATUS bit0 matches.
dw_set_enable:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12d, esi
    mov  edx, esi
    mov  esi, IC_ENABLE
    call dw_wr
    mov  rdi, rbx
    call dw_deadline
    mov  r13, rax
.poll:
    mov  rdi, rbx
    mov  esi, IC_ENABLE_STATUS
    call dw_rd
    and  eax, 1
    cmp  eax, r12d
    je   .ok
    mov  rdi, rbx
    mov  rsi, r13
    call dw_expired
    test eax, eax
    jz   .poll
    mov  eax, I2C_DW_ERR_DISABLE_TO
    jmp  .out
.ok:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; i2c_dw_disable(rdi=ctx) -> eax status
i2c_dw_disable:
    push rbx
    mov  rbx, rdi
    xor  esi, esi
    call dw_set_enable
    mov  [rbx + DWC_LAST_ERR], eax
    pop  rbx
    ret

; i2c_dw_init(rdi=ctx, esi=7-bit target address) -> eax status.
; Disable -> master config for DWC_SPEED -> SCL counts -> target -> mask all
; interrupts (polled) -> clear stale state -> enable.
i2c_dw_init:
    push rbx
    push r12
    mov  rbx, rdi
    mov  r12d, esi
    mov  eax, I2C_DW_ERR_BAD_ARGS
    cmp  r12d, 0x08                 ; 0x00-0x07 / 0x78-0x7F are reserved addresses
    jb   .fail
    cmp  r12d, 0x77
    ja   .fail
    mov  ecx, [rbx + DWC_SPEED]
    cmp  ecx, 1
    jb   .fail
    cmp  ecx, 2
    ja   .fail
    mov  eax, I2C_DW_ERR_NO_TIMING
    cmp  dword [rbx + DWC_HCNT], 0
    je   .fail
    cmp  dword [rbx + DWC_LCNT], 0
    je   .fail
    mov  rdi, rbx
    xor  esi, esi
    call dw_set_enable
    test eax, eax
    jnz  .fail
    mov  edx, [rbx + DWC_SPEED]
    shl  edx, CON_SPEED_SHIFT
    or   edx, CON_MASTER | CON_RESTART_EN | CON_SLAVE_DISABLE
    mov  rdi, rbx
    mov  esi, IC_CON
    call dw_wr
    mov  esi, IC_SS_SCL_HCNT
    cmp  dword [rbx + DWC_SPEED], 2
    jne  .counts
    mov  esi, IC_FS_SCL_HCNT
.counts:
    push rsi
    push rsi                        ; keep 16-byte parity for the pushes below
    mov  edx, [rbx + DWC_HCNT]
    mov  rdi, rbx
    call dw_wr
    pop  rsi
    pop  rsi
    add  esi, 4                     ; LCNT follows HCNT in both speed pairs
    mov  edx, [rbx + DWC_LCNT]
    mov  rdi, rbx
    call dw_wr
    mov  rdi, rbx
    mov  esi, IC_TAR
    mov  edx, r12d
    call dw_wr
    mov  rdi, rbx
    mov  esi, IC_INTR_MASK
    xor  edx, edx
    call dw_wr
    mov  rdi, rbx
    mov  esi, IC_CLR_INTR           ; read-to-clear
    call dw_rd
    mov  rdi, rbx
    mov  esi, 1
    call dw_set_enable
.fail:
    mov  [rbx + DWC_LAST_ERR], eax
    pop  r12
    pop  rbx
    ret

; dw_check_abort(rdi=ctx) -> eax 0 = no abort, else the classified status.
; Clears the abort (read IC_CLR_TX_ABRT) when one is latched.
dw_check_abort:
    push rbx
    mov  rbx, rdi
    mov  esi, IC_RAW_INTR_STAT
    call dw_rd
    test eax, RAW_TX_ABRT
    jz   .none
    mov  rdi, rbx
    mov  esi, IC_TX_ABRT_SOURCE
    call dw_rd
    mov  [rbx + DWC_LAST_ABRT], eax
    push rax
    push rax
    mov  rdi, rbx
    mov  esi, IC_CLR_TX_ABRT
    call dw_rd
    pop  rax
    pop  rax
    mov  ecx, I2C_DW_ERR_ADDR_NAK
    test eax, ABRT_7B_ADDR_NOACK
    jnz  .classified
    mov  ecx, I2C_DW_ERR_DATA_NAK
    test eax, ABRT_TXDATA_NOACK
    jnz  .classified
    mov  ecx, I2C_DW_ERR_ABORT
.classified:
    mov  eax, ecx
    pop  rbx
    ret
.none:
    xor  eax, eax
    pop  rbx
    ret

; dw_push_cmd(rdi=ctx, esi=data_cmd word, rdx=deadline) -> eax status.
; Waits (bounded) for TX FIFO space, then writes IC_DATA_CMD.
dw_push_cmd:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12d, esi
    mov  r13, rdx
.wait:
    mov  rdi, rbx
    call dw_check_abort
    test eax, eax
    jnz  .out
    mov  rdi, rbx
    mov  esi, IC_STATUS
    call dw_rd
    test eax, ST_TFNF
    jnz  .room
    mov  rdi, rbx
    mov  rsi, r13
    call dw_expired
    test eax, eax
    jz   .wait
    mov  eax, I2C_DW_ERR_TIMEOUT
    jmp  .out
.room:
    mov  rdi, rbx
    mov  esi, IC_DATA_CMD
    mov  edx, r12d
    call dw_wr
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; i2c_dw_xfer(rdi=ctx, rsi=tx, edx=tx_len, rcx=rx, r8d=rx_len) -> eax status.
; One combined transaction: tx bytes, then (RESTART) rx_len reads; STOP on the
; final command. DWC_RX_GOT = bytes stored to rx.
i2c_dw_xfer:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 24                    ; [rsp]=deadline [rsp+8]=commands issued, [rsp+16]=commands total
    mov  rbx, rdi
    mov  r12, rsi                   ; tx cursor
    mov  r13d, edx                  ; tx remaining
    mov  r14, rcx                   ; rx base
    mov  r15d, r8d                  ; rx requested
    mov  dword [rbx + DWC_RX_GOT], 0
    mov  dword [rbx + DWC_LAST_ABRT], 0
    mov  eax, I2C_DW_ERR_BAD_ARGS
    cmp  r15d, I2C_DW_RX_MAX
    ja   .done
    mov  ecx, r13d
    add  ecx, r15d
    jz   .done
    test r13d, r13d
    jz   .no_tx_ptr
    test r12, r12
    jz   .done
.no_tx_ptr:
    test r15d, r15d
    jz   .args_ok
    test r14, r14
    jz   .done
.args_ok:
    mov  [rsp + 16], rcx
    mov  qword [rsp + 8], 0
    mov  rdi, rbx
    mov  esi, IC_CLR_INTR           ; drop stale STOP/abort state from a previous transfer
    call dw_rd
    mov  rdi, rbx
    call dw_deadline
    mov  [rsp], rax
    ; --- writes ---
.tx:
    test r13d, r13d
    jz   .rx_issue
    movzx esi, byte [r12]
    inc  r12
    dec  r13d
    inc  qword [rsp + 8]
    mov  rax, [rsp + 8]
    cmp  rax, [rsp + 16]
    jne  .tx_push
    or   esi, CMD_STOP              ; write-only transfer: STOP on the last byte
.tx_push:
    mov  rdi, rbx
    mov  rdx, [rsp]
    call dw_push_cmd
    test eax, eax
    jnz  .done
    jmp  .tx
    ; --- reads: issue one READ per byte, draining as the FIFO fills ---
.rx_issue:
    xor  ebp, ebp                   ; reads issued
.rx_loop:
    cmp  ebp, r15d
    jae  .wait_stop
    mov  esi, CMD_READ
    test ebp, ebp
    jnz  .rx_not_first
    mov  rax, [rsp + 8]
    test rax, rax
    jz   .rx_not_first              ; read-only transfer: START, not RESTART
    or   esi, CMD_RESTART
.rx_not_first:
    lea  eax, [ebp + 1]
    cmp  eax, r15d
    jne  .rx_push
    or   esi, CMD_STOP
.rx_push:
    mov  rdi, rbx
    mov  rdx, [rsp]
    call dw_push_cmd
    test eax, eax
    jnz  .done
    inc  ebp
    inc  qword [rsp + 8]
    mov  rdi, rbx
    call .drain
    test eax, eax
    jnz  .done
    jmp  .rx_loop
    ; --- completion: STOP_DET (or abort) within the bound ---
.wait_stop:
    mov  rdi, rbx
    call .drain
    test eax, eax
    jnz  .done
    mov  rdi, rbx
    call dw_check_abort
    test eax, eax
    jnz  .done
    mov  rdi, rbx
    mov  esi, IC_RAW_INTR_STAT
    call dw_rd
    test eax, RAW_STOP_DET
    jnz  .stopped
    mov  rdi, rbx
    mov  rsi, [rsp]
    call dw_expired
    test eax, eax
    jz   .wait_stop
    mov  eax, I2C_DW_ERR_TIMEOUT
    jmp  .done
.stopped:
    mov  rdi, rbx
    call .drain                     ; bytes that landed with the STOP
    test eax, eax
    jnz  .done
    mov  rdi, rbx
    mov  esi, IC_CLR_STOP_DET
    call dw_rd
    mov  eax, I2C_DW_OK
    cmp  [rbx + DWC_RX_GOT], r15d
    je   .done
    mov  eax, I2C_DW_ERR_RX_SHORT
.done:
    mov  [rbx + DWC_LAST_ERR], eax
    add  rsp, 24
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; .drain: local helper (rdi=ctx; uses r14/r15 of the caller frame) -> eax.
; Copies FIFO bytes while RXFLR > 0; a byte beyond the request is refused.
.drain:
    push rbx
    mov  rbx, rdi
.drain_more:
    mov  rdi, rbx
    mov  esi, IC_RXFLR
    call dw_rd
    test eax, eax
    jz   .drain_ok
    mov  ecx, [rbx + DWC_RX_GOT]
    cmp  ecx, r15d
    jae  .drain_over
    mov  rdi, rbx
    mov  esi, IC_DATA_CMD
    call dw_rd
    mov  ecx, [rbx + DWC_RX_GOT]
    mov  [r14 + rcx], al
    inc  dword [rbx + DWC_RX_GOT]
    jmp  .drain_more
.drain_over:
    mov  eax, I2C_DW_ERR_ABORT       ; the controller produced more data than requested
    pop  rbx
    ret
.drain_ok:
    xor  eax, eax
    pop  rbx
    ret
