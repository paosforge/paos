;; MODULE dev/input/i2c_hid
;; LAYER 3
;; EXPORTS i2c_hid_dell_witness
;; IMPORTS bus/acpi, bus/pci, bus/pci_bdf, boot/boot_v2_health, boot/beacon, core/time, boot/serial, boot/nvram_access
;; CAPS CAP_MMIO
;; OWNER saga:dell_input
; ============================================================================
; dev/input/i2c_hid.asm — dell017 (manual sprint 2026-09-19): the Dell 5490's built-in touchpad is
; HID over I2C (ACPI DELL0816, _CID PNP0C50) behind the PCH Serial IO I2C1 controller (PCI 00:15.1,
; 8086:9D61, a Synopsys DesignWare master inside Intel's LPSS wrapper). From the DSDT (TPD1):
;   I2cSerialBusV2 slave 0x2C, 400 kHz, "\_SB.PCI0.I2C1"; HID descriptor register = 0x20 (HID2).
; Windows inventory cross-check: HID\VID_044E&PID_1212 (ALPS). No GPIO interrupt here: the witness
; POLLS the controller (bounded), which is enough to prove the controller + HID-over-I2C protocol:
;   1. PCI 00:15.1 present, BAR0 inside the identity map, PMCSR to D0, memory decode on
;   2. LPSS: clock gate on (priv+0x00 bit0), function/iDMA resets deasserted (priv+0x04 = 0x7)
;   3. DesignWare signature IC_COMP_TYPE == 0x44570140, master/fast-mode/restart config, TAR=0x2C
;   4. HID descriptor read (write 0x0020, read 30 B): wHIDDescLength 0x1E, bcdVersion 0x0100,
;      wVendorID/wProductID/... recorded  -> [input.dell.i2chid.desc]
;   5. SET_POWER(ON) + RESET through the command register, then plain reads of the input register
;      until the reset acknowledgement (2-byte length 0x0000) or a report -> [input.dell.i2chid.report]
; Everything is written to the PaOSI2cBox NVRAM record (64 B, 'PI2C', CRC) read back over the lab network:
;   [0..3] 'PI2C' [4] ver [5] flags: b0 pci b1 bar b2 dw b3 desc b4 report b5 metal b6 d0
;   [6] PMCSR lo before [7] PMCSR lo after [8..11] session [12..15] BAR0 lo [16..19] IC_COMP_TYPE
;   [20..23] last TX_ABRT_SOURCE [24..25] vendor [26..27] product [28..29] version
;   [30..31] wReportDescLength [32..33] wInputRegister [34..35] wMaxInputLength [36..37] wCommandRegister
;   [38..39] report length read [40..47] first 8 report bytes [48..51] last RAW_INTR_STAT
;   [52..53] FS_SCL_HCNT [54..55] FS_SCL_LCNT [56..59] LPSS priv clock reg [60..63] CRC32 over [0..60)
; Bare metal only; every wait is bounded (timer_ticks ms). No DMA, no interrupts, no new HID model:
; a decoded relative report is handed to ps2_pointer_post like the PS/2 aux path.
; ============================================================================

I2CHID_BDF          equ 0xA9              ; 00:15.1 packed bus<<8|dev<<3|fn
I2CHID_PCI_DEV      equ 0x15
I2CHID_PCI_FN       equ 1
I2CHID_VENDEV       equ 0x9D618086
I2CHID_SLAVE        equ 0x2C
I2CHID_HIDDESC_REG  equ 0x0020

LPSS_PRIV           equ 0x200
LPSS_PRIV_CLOCK     equ 0x00
LPSS_PRIV_RESETS    equ 0x04

DW_IC_CON           equ 0x00
DW_IC_TAR           equ 0x04
DW_IC_DATA_CMD      equ 0x10
DW_IC_FS_SCL_HCNT   equ 0x1C
DW_IC_FS_SCL_LCNT   equ 0x20
DW_IC_INTR_MASK     equ 0x30
DW_IC_RAW_INTR_STAT equ 0x34
DW_IC_CLR_INTR      equ 0x40
DW_IC_ENABLE        equ 0x6C
DW_IC_STATUS        equ 0x70
DW_IC_TXFLR         equ 0x74
DW_IC_RXFLR         equ 0x78
DW_IC_TX_ABRT_SRC   equ 0x80
DW_IC_ENABLE_STATUS equ 0x9C
DW_IC_COMP_TYPE     equ 0xFC
DW_COMP_TYPE_VALUE  equ 0x44570140
DW_CON_MASTER_FAST  equ 0x65              ; MASTER | SPEED_FAST(2<<1) | RESTART_EN | SLAVE_DISABLE
DW_CMD_READ         equ 0x100
DW_CMD_STOP         equ 0x200
DW_CMD_RESTART      equ 0x400
DW_STATUS_TFNF      equ 0x02
DW_STATUS_RFNE      equ 0x08
DW_INTR_TX_ABRT     equ 0x40
DW_INTR_STOP_DET    equ 0x200
I2CHID_FS_HCNT      equ 105               ; 120 MHz LPSS clock: round(120*(600+300)/1000)-3
I2CHID_FS_LCNT      equ 191               ;                    round(120*(1300+300)/1000)-1
I2CHID_XFER_MS      equ 100
I2CHID_RX_MAX       equ 64

i2c_hid_dell_witness:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  eax, 1
    cpuid                                     ; QEMU is the wrong ACPI/device negative
    test ecx, (1 << 31)
    jnz  .out
    cmp  qword [rel runtime_services], 0
    je   .out
    cmp  byte [rel pbm_runtime_code_mapped], 1
    jne  .out
    ; A matching PCI function alone is insufficient. Require the Dell 5490's
    ; ACPI device and generic I2C-HID compatible ID in the same validated DSDT
    ; before even reading the controller BAR, and re-check exact PCI identity
    ; below before any LPSS/DesignWare MMIO access.
    lea  rdi, [rel i2chid_acpi_hid]
    lea  rsi, [rel i2chid_acpi_cid]
    mov  edx, 8
    call acpi_dsdt_contains_pair
    test eax, eax
    jz   .out
    lea  rdi, [rel i2chid_rec]
    xor  eax, eax
    mov  ecx, 8
    rep  stosq
    mov  dword [rel i2chid_rec], 0x43324950            ; 'PI2C'
    mov  byte [rel i2chid_rec + 4], 1
    mov  byte [rel i2chid_rec + 5], (1 << 5)           ; bare metal
    mov  eax, [rel boot_nonce]                ; common per-boot evidence binding
    mov  [rel i2chid_rec + 8], eax
    ; --- 1. PCI 00:15.1 ---
    mov  edi, I2CHID_BDF
    xor  esi, esi
    call pci_bdf_read
    cmp  eax, I2CHID_VENDEV
    jne  .record
    or   byte [rel i2chid_rec + 5], 1
    mov  edi, I2CHID_BDF
    mov  esi, 0x10
    call pci_bdf_read
    mov  r12d, eax
    and  r12d, 0xFFFFFFF0
    mov  [rel i2chid_rec + 12], r12d
    and  eax, 6
    cmp  eax, 4
    jne  .bar_low
    mov  edi, I2CHID_BDF
    mov  esi, 0x14
    call pci_bdf_read
    shl  rax, 32
    or   r12, rax
.bar_low:
    test r12, r12
    jz   .record
    cmp  r12, [rel ident_bytes]
    jae  .record
    ; PMCSR -> D0
    mov  edi, I2CHID_BDF
    mov  esi, 0x01                        ; PCI Power Management capability
    call pci_find_cap
    test eax, eax
    jz   .pm_done
    mov  r13d, eax
    mov  edi, I2CHID_BDF
    lea  esi, [r13 + 4]
    call pci_bdf_read
    mov  [rel i2chid_rec + 6], al
    test al, 3
    jz   .pm_d0
    and  eax, 0xFFFF
    and  eax, ~3                          ; D0; keep the RW1C/PME bits untouched by writing the low word only
    mov  edx, eax
    mov  edi, I2CHID_BDF
    lea  esi, [r13 + 4]
    call pci_bdf_write
    mov  edi, 10000
    call tsc_delay_us
    mov  edi, I2CHID_BDF
    lea  esi, [r13 + 4]
    call pci_bdf_read
.pm_d0:
    mov  [rel i2chid_rec + 7], al
    test al, 3
    jnz  .pm_done
    or   byte [rel i2chid_rec + 5], (1 << 6)
.pm_done:
    ; memory decode on
    mov  edi, I2CHID_BDF
    mov  esi, 4
    call pci_bdf_read
    or   eax, 2
    mov  edx, eax
    mov  edi, I2CHID_BDF
    mov  esi, 4
    call pci_bdf_write
    mov  rdi, r12
    call mmio_mark_uc
    or   byte [rel i2chid_rec + 5], 2
    ; --- 2. LPSS wrapper: clock gate on, resets deasserted ---
    mov  eax, [r12 + LPSS_PRIV + LPSS_PRIV_CLOCK]
    test eax, 1
    jnz  .clk_on
    or   eax, 1
    mov  [r12 + LPSS_PRIV + LPSS_PRIV_CLOCK], eax
.clk_on:
    mov  dword [r12 + LPSS_PRIV + LPSS_PRIV_RESETS], 0x7
    mov  edi, 1000
    call tsc_delay_us
    mov  eax, [r12 + LPSS_PRIV + LPSS_PRIV_CLOCK]
    mov  [rel i2chid_rec + 56], eax
    ; --- 3. DesignWare master ---
    mov  eax, [r12 + DW_IC_COMP_TYPE]
    mov  [rel i2chid_rec + 16], eax
    cmp  eax, DW_COMP_TYPE_VALUE
    jne  .record
    or   byte [rel i2chid_rec + 5], 4
    call i2chid_disable
    mov  dword [r12 + DW_IC_INTR_MASK], 0
    mov  dword [r12 + DW_IC_CON], DW_CON_MASTER_FAST
    mov  dword [r12 + DW_IC_TAR], I2CHID_SLAVE
    mov  eax, [r12 + DW_IC_FS_SCL_HCNT]
    test eax, eax
    jz   .set_scl
    cmp  eax, 0xFFFF
    ja   .set_scl
    mov  eax, [r12 + DW_IC_FS_SCL_LCNT]
    test eax, eax
    jz   .set_scl
    cmp  eax, 0xFFFF
    jbe  .scl_ok
.set_scl:
    mov  dword [r12 + DW_IC_FS_SCL_HCNT], I2CHID_FS_HCNT
    mov  dword [r12 + DW_IC_FS_SCL_LCNT], I2CHID_FS_LCNT
.scl_ok:
    mov  eax, [r12 + DW_IC_FS_SCL_HCNT]
    mov  [rel i2chid_rec + 52], ax
    mov  eax, [r12 + DW_IC_FS_SCL_LCNT]
    mov  [rel i2chid_rec + 54], ax
    mov  dword [r12 + DW_IC_ENABLE], 1
    mov  r15, [rel timer_ticks]
.en_wait:
    test dword [r12 + DW_IC_ENABLE_STATUS], 1
    jnz  .enabled
    mov  rax, [rel timer_ticks]
    sub  rax, r15
    cmp  rax, 25
    jae  .record
    pause
    jmp  .en_wait
.enabled:
    ; --- 4. HID descriptor: write register 0x0020, read 30 bytes ---
    mov  word [rel i2chid_tx], I2CHID_HIDDESC_REG
    lea  rsi, [rel i2chid_tx]
    mov  ecx, 2
    lea  rdi, [rel i2chid_rx]
    mov  edx, 30
    call i2chid_xfer
    test eax, eax
    jz   .record
    cmp  word [rel i2chid_rx], 0x1E                ; wHIDDescLength
    jne  .record
    cmp  word [rel i2chid_rx + 2], 0x0100          ; bcdVersion
    jne  .record
    or   byte [rel i2chid_rec + 5], 8
    mov  eax, [rel i2chid_rx + 20]                 ; vendor, product
    mov  [rel i2chid_rec + 24], eax
    mov  ax, [rel i2chid_rx + 24]                  ; version
    mov  [rel i2chid_rec + 28], ax
    mov  ax, [rel i2chid_rx + 4]                   ; wReportDescLength
    mov  [rel i2chid_rec + 30], ax
    mov  ax, [rel i2chid_rx + 8]                   ; wInputRegister
    mov  [rel i2chid_rec + 32], ax
    mov  ax, [rel i2chid_rx + 10]                  ; wMaxInputLength
    mov  [rel i2chid_rec + 34], ax
    mov  ax, [rel i2chid_rx + 16]                  ; wCommandRegister
    mov  [rel i2chid_rec + 36], ax
    lea  rdi, [rel str_i2chid_desc]
    call serial_string
    ; --- 5. SET_POWER(ON), RESET, then plain reads of the input register ---
    mov  ax, [rel i2chid_rec + 36]
    mov  [rel i2chid_tx], ax
    mov  byte [rel i2chid_tx + 2], 0x00            ; report_type<<4 | power state ON
    mov  byte [rel i2chid_tx + 3], 0x08            ; SET_POWER
    lea  rsi, [rel i2chid_tx]
    mov  ecx, 4
    xor  edx, edx
    call i2chid_xfer
    mov  edi, 5000
    call tsc_delay_us
    mov  byte [rel i2chid_tx + 2], 0x00
    mov  byte [rel i2chid_tx + 3], 0x01            ; RESET
    lea  rsi, [rel i2chid_tx]
    mov  ecx, 4
    xor  edx, edx
    call i2chid_xfer
    movzx r14d, word [rel i2chid_rec + 34]         ; wMaxInputLength
    cmp  r14d, I2CHID_RX_MAX
    jbe  .len_ok
    mov  r14d, I2CHID_RX_MAX
.len_ok:
    cmp  r14d, 2
    jae  .poll
    mov  r14d, 2
.poll:
    mov  ebx, 25                                   ; up to 25 x 20 ms for the reset ack / a report
.poll_loop:
    mov  edi, 20000
    call tsc_delay_us
    lea  rsi, [rel i2chid_tx]
    xor  ecx, ecx                                  ; plain read: the input register is the default read
    lea  rdi, [rel i2chid_rx]
    mov  edx, r14d
    call i2chid_xfer
    test eax, eax
    jnz  .report_read
    dec  ebx
    jnz  .poll_loop
    jmp  .record
.report_read:
    or   byte [rel i2chid_rec + 5], (1 << 4)
    movzx eax, word [rel i2chid_rx]
    mov  [rel i2chid_rec + 38], ax
    mov  rax, [rel i2chid_rx]
    mov  [rel i2chid_rec + 40], rax
    lea  rdi, [rel str_i2chid_report]
    call serial_string
    ; a relative report (len>=6: len, id, buttons, dx, dy) goes to the shared pointer path
    movzx eax, word [rel i2chid_rx]
    cmp  eax, 6
    jb   .record
    cmp  eax, r14d
    ja   .record
    movsx edi, byte [rel i2chid_rx + 4]            ; dx
    movsx esi, byte [rel i2chid_rx + 5]            ; dy
    neg  esi
    movzx edx, byte [rel i2chid_rx + 3]
    and  edx, 7
    call ps2_pointer_post
.record:
    mov  eax, [rel i2chid_last_abrt]
    mov  [rel i2chid_rec + 20], eax
    mov  eax, [rel i2chid_last_raw]
    mov  [rel i2chid_rec + 48], eax
    lea  rdi, [rel i2chid_rec]
    mov  esi, 60
    call pbm_crc32
    mov  [rel i2chid_rec + 60], eax
    ; storage gate, NVRAM class (PETER 2026-09-30): PaOS-namespace -> NORMAL.
    lea  rdi, [rel pbm_telemetry_var_guid]
    lea  rsi, [rel i2chid_var_name]
    xor  edx, edx                                  ; SA_INTENT_IMPLICIT (boot-time witness)
    lea  rcx, [rel str_i2chid_nvg_tag]
    call storage_access_nvram_require
    test rax, rax
    lea  rdi, [rel str_i2chid_write_failed]
    jnz  .say
    mov  r13, [rel runtime_services]
    lea  rcx, [rel i2chid_var_name]
    lea  rdx, [rel pbm_telemetry_var_guid]
    mov  r8d, PBM_EFI_HEALTH_ATTRS
    mov  r9d, 64
    sub  rsp, 48
    lea  rax, [rel i2chid_rec]
    mov  [rsp + 32], rax
    call [r13 + 0x58]                              ; SetVariable(PaOSI2cBox)
    add  rsp, 48
    lea  rdi, [rel str_i2chid_written]
    test rax, rax
    jz   .say
    lea  rdi, [rel str_i2chid_write_failed]
.say:
    call serial_string
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; disable the master and wait for ENABLE_STATUS to follow (bounded 25 ms). R12 = BAR0.
i2chid_disable:
    push r15
    mov  dword [r12 + DW_IC_ENABLE], 0
    mov  r15, [rel timer_ticks]
.wait:
    test dword [r12 + DW_IC_ENABLE_STATUS], 1
    jz   .done
    mov  rax, [rel timer_ticks]
    sub  rax, r15
    cmp  rax, 25
    jae  .done
    pause
    jmp  .wait
.done:
    mov  eax, [r12 + DW_IC_CLR_INTR]
    pop  r15
    ret

; i2chid_xfer(RSI=tx bytes, ECX=tx len, RDI=rx buffer, EDX=rx len) -> EAX=1 ok / 0 fail. R12 = BAR0.
;   One I2C transaction: the tx bytes, then (RESTART) rx reads, STOP on the last command. Polled,
;   bounded I2CHID_XFER_MS; a TX_ABRT records TX_ABRT_SOURCE. RX is drained while commands are
;   issued so the FIFO never overflows. Preserves RBX/R13/R14/R15 of the caller.
i2chid_xfer:
    push rbx
    push rbp
    push r13
    push r14
    push r15
    mov  r13, rsi                                  ; tx ptr
    mov  ebx, ecx                                  ; tx remaining
    mov  r14, rdi                                  ; rx ptr
    mov  ebp, edx                                  ; rx remaining to READ
    mov  r15d, edx                                 ; rx commands remaining to ISSUE
    mov  eax, [r12 + DW_IC_CLR_INTR]
    mov  dword [rel i2chid_last_abrt], 0
    mov  rax, [rel timer_ticks]
    mov  [rel i2chid_t0], rax
    mov  byte [rel i2chid_first_rd], 1
    test ebx, ebx
    jnz  .tx_loop
    mov  byte [rel i2chid_first_rd], 0             ; rx-only: the first read starts the transaction
.tx_loop:
    test ebx, ebx
    jz   .rx_issue
    call i2chid_wait_tfnf
    test eax, eax
    jz   .fail
    movzx eax, byte [r13]
    inc  r13
    dec  ebx
    jnz  .tx_put
    test r15d, r15d
    jnz  .tx_put
    or   eax, DW_CMD_STOP                          ; write-only transaction ends here
.tx_put:
    mov  [r12 + DW_IC_DATA_CMD], eax
    jmp  .tx_loop
.rx_issue:
    test r15d, r15d
    jz   .rx_drain_all
    ; keep the command FIFO shallow and drain arrivals meanwhile
    cmp  dword [r12 + DW_IC_TXFLR], 8
    jb   .rx_cmd
    call i2chid_drain_one
    call i2chid_check
    test eax, eax
    jz   .fail
    jmp  .rx_issue
.rx_cmd:
    mov  eax, DW_CMD_READ
    cmp  byte [rel i2chid_first_rd], 1
    jne  .rx_not_first
    or   eax, DW_CMD_RESTART
    mov  byte [rel i2chid_first_rd], 0
.rx_not_first:
    cmp  r15d, 1
    jne  .rx_put
    or   eax, DW_CMD_STOP
.rx_put:
    mov  [r12 + DW_IC_DATA_CMD], eax
    dec  r15d
    call i2chid_drain_one
    jmp  .rx_issue
.rx_drain_all:
    test ebp, ebp
    jz   .stop_wait
    call i2chid_drain_one
    call i2chid_check
    test eax, eax
    jz   .fail
    jmp  .rx_drain_all
.stop_wait:
    mov  eax, [r12 + DW_IC_RAW_INTR_STAT]
    mov  [rel i2chid_last_raw], eax
    test eax, DW_INTR_TX_ABRT
    jnz  .abort
    test eax, DW_INTR_STOP_DET
    jnz  .ok
    call i2chid_check
    test eax, eax
    jz   .fail
    pause
    jmp  .stop_wait
.ok:
    mov  eax, [r12 + DW_IC_CLR_INTR]
    mov  eax, 1
    jmp  .out
.abort:
    mov  eax, [r12 + DW_IC_TX_ABRT_SRC]
    mov  [rel i2chid_last_abrt], eax
.fail:
    mov  eax, [r12 + DW_IC_CLR_INTR]
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbp
    pop  rbx
    ret

; one RX byte if available (RFNE) into [r14], ebp--. clobbers RAX.
i2chid_drain_one:
    test ebp, ebp
    jz   .none
    test dword [r12 + DW_IC_STATUS], DW_STATUS_RFNE
    jz   .none
    mov  eax, [r12 + DW_IC_DATA_CMD]
    mov  [r14], al
    inc  r14
    dec  ebp
.none:
    ret

; EAX=1 while the transaction may continue (no abort, not timed out), 0 otherwise. clobbers RAX.
i2chid_check:
    mov  eax, [r12 + DW_IC_RAW_INTR_STAT]
    mov  [rel i2chid_last_raw], eax
    test eax, DW_INTR_TX_ABRT
    jnz  .bad
    mov  rax, [rel timer_ticks]
    sub  rax, [rel i2chid_t0]
    cmp  rax, I2CHID_XFER_MS
    jae  .bad
    mov  eax, 1
    ret
.bad:
    mov  eax, [r12 + DW_IC_TX_ABRT_SRC]
    mov  [rel i2chid_last_abrt], eax
    xor  eax, eax
    ret

; wait for TX FIFO not full (bounded by the transaction budget). EAX=1 ok / 0 timeout-or-abort.
i2chid_wait_tfnf:
    test dword [r12 + DW_IC_STATUS], DW_STATUS_TFNF
    jnz  .ok
    call i2chid_check
    test eax, eax
    jz   .no
    pause
    jmp  i2chid_wait_tfnf
.ok:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

align 8
i2chid_rec:        times 64 db 0
i2chid_tx:         times 8 db 0
i2chid_rx:         times I2CHID_RX_MAX db 0
i2chid_t0:         dq 0
i2chid_last_abrt:  dd 0
i2chid_last_raw:   dd 0
i2chid_first_rd:   db 0
i2chid_acpi_hid:   db 'DELL0816'
i2chid_acpi_cid:   db 'PNP0C50',0
align 2                                 ; a CHAR16 string handed to firmware must be 2-aligned (UEFI; edk2 ASSERTs)
i2chid_var_name:   dw 'P','a','O','S','I','2','c','B','o','x',0
str_i2chid_nvg_tag: db "i2c_hid_witness",0
str_i2chid_desc:   db "[PAOS64] P8 input: Dell I2C-HID touchpad (DELL0816 @0x2C on PCH I2C1) answered the HID descriptor read [input.dell.i2chid.desc]", 13, 10, 0
str_i2chid_report: db "[PAOS64] P8 input: Dell I2C-HID touchpad input register read after RESET (ack or report) [input.dell.i2chid.report]", 13, 10, 0
str_i2chid_written: db "[PAOS64] P8 input: PaOSI2cBox NVRAM record written", 13, 10, 0
str_i2chid_write_failed: db "[PAOS64] P8 input: PaOSI2cBox NVRAM write FAILED", 13, 10, 0
