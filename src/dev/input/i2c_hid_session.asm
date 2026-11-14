;; MODULE dev/input/i2c_hid_session
;; LAYER 3
;; EXPORTS i2c_hid_session_open, i2c_hid_session_step, i2c_hid_session_ready, i2c_hid_session_detach
;; IMPORTS dev/input/i2c_dw, dev/usb/hid
;; CAPS CAP_MMIO
;; OWNER saga:input_system
; Explicit cooperative, polled HID-over-I2C v1.00 backend. No discovery or
; activation call site. Caller supplies validated ACPI/controller/address/
; descriptor register, exclusive DesignWare ops and actual timing. Caller
; serializes calls, keeps config/ops/storage alive and immutable, and revokes
; *live_generation before detaching/reusing controller storage. See protocol doc.
; One session, strict shared parallel TouchPad profile; other formats refused.
; No report guessing, target tables, AML, new MMIO, output/feature commands.
;
; Caller zeroes 704 bytes, fills offsets0..39. open returns1 for accepted pending
; session, NOT readiness. step performs at most one input/ACK read (plus one
; descriptor read on ACK). ready returns1 only after reset ACK and shared parse.
; detach returns1 after accepted releases; full queue retains retired custody.
IH_DW          equ 0       ; qword existing DWC_SIZE context
IH_TOKEN       equ 8       ; qword nonzero generation
IH_LIVE        equ 16      ; qword pointer to caller's aligned live generation
IH_DESC_REG    equ 24      ; dword verified HID descriptor register
IH_ADDR        equ 28      ; dword7-bit slave
IH_RESET_MS    equ 32      ; dword1..5000, actual platform timeout
IH_POWER_MS    equ 36      ; dword1..1000, actual platform power-on delay
IH_STATE       equ 40      ; 0free 1power-delay 2reset-wait 3ready 4retired
IH_POLLS       equ 44      ; bounded64 attempts per pending phase
IH_STARTED     equ 48      ; qword phase start, wrap/backwards time refused
IH_LAST        equ 56      ; qword last monotonic ms
IH_MAXIN       equ 64      ; word exact prefix+shared wire extent
IH_RDLEN       equ 66      ; word report descriptor extent
IH_CMD         equ 68      ; word command register
IH_RREG        equ 70      ; word report descriptor register
IH_ANCHOR      equ 72      ; 8bytes accepted ID-stable contact anchor
IH_DESC        equ 80      ; 30bytes HID descriptor
IH_TX          equ 112     ; 4bytes command/register address
IH_WIRE        equ 120     ; 34bytes input, including length prefix
IH_RD          equ 160     ; 256bytes report descriptor
IH_MAP         equ 416     ; 272bytes shared immutable proved map
IH_SIZE        equ 704

; Trusted caller pointers, not a userspace API. No I/O or readiness on revocation.
ih_valid:
    test rdi, rdi
    jz   .bad
    cmp  [rel i2c_hid_session_owner], rdi
    jne  .bad
    mov  r10, [rdi + IH_LIVE]
    mov  r11, [rdi + IH_TOKEN]
    cmp  [r10], r11
    jne  .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; Same transfer ABI as DW, except RDI=session and EAX=1 success. Generation
; checked on both sides of every ops callback/transfer before consuming bytes.
ih_xfer:
    push rbx
    mov  rbx, rdi
    call ih_valid
    test eax, eax
    jz   .out
    mov  rdi, [rbx + IH_DW]
    call i2c_dw_xfer
    test eax, eax
    jnz  .bad
    mov  rdi, rbx
    call ih_valid
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  rbx
    ret

; RDI=session -> RAX monotonic ms, CF=1 on backwards time or revocation.
ih_now:
    push rbx
    mov  rbx, rdi
    call ih_valid
    test eax, eax
    jz   .bad
    mov  rdi, [rbx + IH_DW]
    call dw_now
    cmp  rax, [rbx + IH_LAST]
    jb   .bad
    mov  [rbx + IH_LAST], rax
    push rax
    mov  rdi, rbx
    call ih_valid
    mov  ecx, eax
    pop  rax
    test ecx, ecx
    jz   .bad
    clc
    pop  rbx
    ret
.bad:
    stc
    pop  rbx
    ret

i2c_hid_session_open:
    push rbx
    mov  rbx, rdi
    test rdi, rdi
    jz   .bad
    cmp  qword [rel i2c_hid_session_owner], 0
    jne  .bad
    cmp  dword [rbx + IH_STATE], 0
    jne  .bad
    mov  rdx, [rbx + IH_LIVE]
    test rdx, rdx
    jz   .bad
    test dl, 7
    jnz  .bad
    mov  rax, [rbx + IH_TOKEN]
    test rax, rax
    jz   .bad
    cmp  [rdx], rax
    jne  .bad
    cmp  dword [rbx + IH_DESC_REG], 1
    jb   .bad
    cmp  dword [rbx + IH_DESC_REG], 0xFFE2 ;30-byte descriptor cannot wrap
    ja   .bad
    cmp  dword [rbx + IH_ADDR], 8
    jb   .bad
    cmp  dword [rbx + IH_ADDR], 0x77
    ja   .bad
    cmp  dword [rbx + IH_RESET_MS], 1
    jb   .bad
    cmp  dword [rbx + IH_RESET_MS], 5000
    ja   .bad
    cmp  dword [rbx + IH_POWER_MS], 1
    jb   .bad
    cmp  dword [rbx + IH_POWER_MS], 1000
    ja   .bad
    mov  rdi, [rbx + IH_DW]
    test rdi, rdi
    jz   .bad
    cmp  qword [rdi + DWC_RD], 0
    je   .bad
    cmp  qword [rdi + DWC_WR], 0
    je   .bad
    cmp  qword [rdi + DWC_NOW_MS], 0
    je   .bad
    cmp  dword [rdi + DWC_FRONT], 1
    ja   .bad
    cmp  dword [rdi + DWC_SPEED], 1
    jb   .bad
    cmp  dword [rdi + DWC_SPEED], 2
    ja   .bad
    cmp  dword [rdi + DWC_TIMEOUT_MS], 1
    jb   .bad
    cmp  dword [rdi + DWC_TIMEOUT_MS], 1000
    ja   .bad
    cmp  dword [rdi + DWC_HCNT], 1
    jb   .bad
    cmp  dword [rdi + DWC_HCNT], 65535
    ja   .bad
    cmp  dword [rdi + DWC_LCNT], 1
    jb   .bad
    cmp  dword [rdi + DWC_LCNT], 65535
    ja   .bad
    mov  [rel i2c_hid_session_owner], rbx
    ; Initialize all private outputs without altering caller configuration.
    lea  rdi, [rbx + IH_STATE]
    xor  eax, eax
    mov  ecx, IH_SIZE - IH_STATE
    rep  stosb
    mov  rdi, [rbx + IH_DW]
    call i2c_dw_probe
    test eax, eax
    jnz  .fail
    mov  rdi, rbx
    call ih_valid
    test eax, eax
    jz   .fail
    mov  rdi, [rbx + IH_DW]
    mov  esi, [rbx + IH_ADDR]
    call i2c_dw_init          ; wrapper wake/PCI/ACPI remain caller-owned
    test eax, eax
    jnz  .fail
    mov  ax, [rbx + IH_DESC_REG]
    mov  [rbx + IH_TX], ax
    mov  rdi, rbx
    lea  rsi, [rbx + IH_TX]
    mov  edx, 2
    lea  rcx, [rbx + IH_DESC]
    mov  r8d, 30
    call ih_xfer
    test eax, eax
    jz   .fail
    cmp  word [rbx + IH_DESC], 30
    jne  .fail
    cmp  word [rbx + IH_DESC + 2], 0x0100
    jne  .fail
    cmp  dword [rbx + IH_DESC + 26], 0
    jne  .fail
    cmp  word [rbx + IH_DESC + 20], 0 ; spec requires nonzero vendor
    je   .fail
    movzx ecx, word [rbx + IH_DESC + 4]
    cmp  ecx, 1
    jb   .fail
    cmp  ecx, 256
    ja   .fail
    mov  [rbx + IH_RDLEN], cx
    movzx eax, word [rbx + IH_DESC + 6]
    mov  [rbx + IH_RREG], ax
    test eax, eax
    jz   .fail
    add  eax, ecx
    cmp  eax, 0x10000
    ja   .fail
    movzx ecx, word [rbx + IH_DESC + 10]
    cmp  ecx, 3
    jb   .fail
    cmp  ecx, 34
    ja   .fail
    mov  [rbx + IH_MAXIN], cx
    movzx eax, word [rbx + IH_DESC + 8]
    test eax, eax
    jz   .fail
    add  eax, ecx
    cmp  eax, 0x10000
    ja   .fail
    ; Command/data are mandatory nonzero register indexes; a 4-byte command
    ; (address+2-byte payload) must fit the address space. Output optional pair.
    movzx eax, word [rbx + IH_DESC + 16]
    test eax, eax
    jz   .fail
    cmp  eax, 0xFFFE
    ja   .fail
    mov  [rbx + IH_CMD], ax
    cmp  word [rbx + IH_DESC + 18], 0
    je   .fail
    movzx eax, word [rbx + IH_DESC + 12]
    movzx ecx, word [rbx + IH_DESC + 14]
    test eax, eax
    jnz  .output
    test ecx, ecx
    jnz  .fail
    jmp  .power
.output:
    cmp  ecx, 3
    jb   .fail
    add  eax, ecx
    cmp  eax, 0x10000
    ja   .fail
.power:
    mov  ax, [rbx + IH_CMD]
    mov  [rbx + IH_TX], ax
    mov  word [rbx + IH_TX + 2], 0x0800 ; SET_POWER ON
    mov  rdi, rbx
    lea  rsi, [rbx + IH_TX]
    mov  edx, 4
    xor  ecx, ecx
    xor  r8d, r8d
    call ih_xfer
    test eax, eax
    jz   .fail
    mov  rdi, rbx
    call ih_now
    jc   .fail
    mov  [rbx + IH_STARTED], rax
    mov  dword [rbx + IH_STATE], 1
    mov  eax, 1
    pop  rbx
    ret
.fail:
    mov  rdi, rbx
    call i2c_hid_session_detach
.bad:
    xor  eax, eax
    pop  rbx
    ret

i2c_hid_session_ready:
    call ih_valid
    test eax, eax
    jz   .out
    xor  eax, eax
    cmp  dword [rdi + IH_STATE], 3
    sete al
.out:
    ret

i2c_hid_session_step:
    push rbx
    mov  rbx, rdi
    call ih_valid
    test eax, eax
    jz   .fail
    cmp  dword [rbx + IH_STATE], 3
    je   .input
    cmp  dword [rbx + IH_STATE], 1
    je   .pending
    cmp  dword [rbx + IH_STATE], 2
    jne  .fail
.pending:
    inc  dword [rbx + IH_POLLS]
    cmp  dword [rbx + IH_POLLS], 64
    ja   .fail
    mov  rdi, rbx
    call ih_now
    jc   .fail
    sub  rax, [rbx + IH_STARTED]
    cmp  dword [rbx + IH_STATE], 2
    je   .ack
    mov  ecx, [rbx + IH_POWER_MS]
    cmp  rax, rcx
    jb   .none
    mov  ax, [rbx + IH_CMD]
    mov  [rbx + IH_TX], ax
    mov  word [rbx + IH_TX + 2], 0x0100 ; RESET
    mov  rdi, rbx
    lea  rsi, [rbx + IH_TX]
    mov  edx, 4
    xor  ecx, ecx
    xor  r8d, r8d
    call ih_xfer
    test eax, eax
    jz   .fail
    mov  rdi, rbx
    call ih_now
    jc   .fail
    mov  [rbx + IH_STARTED], rax
    mov  dword [rbx + IH_POLLS], 0
    mov  dword [rbx + IH_STATE], 2
    jmp  .none
.ack:
    cmp  rax, 5000
    jae  .fail
    cmp  eax, [rbx + IH_RESET_MS]
    jae  .fail
    call .read
    test eax, eax
    jz   .fail
    cmp  word [rbx + IH_WIRE], 0
    jne  .pre_ack              ; pre-ACK reports never publish or create anchors
    mov  ax, [rbx + IH_RREG]
    mov  [rbx + IH_TX], ax
    mov  rdi, rbx
    lea  rsi, [rbx + IH_TX]
    mov  edx, 2
    lea  rcx, [rbx + IH_RD]
    movzx r8d, word [rbx + IH_RDLEN]
    call ih_xfer
    test eax, eax
    jz   .fail
    lea  rdi, [rbx + IH_RD]
    movzx esi, word [rbx + IH_RDLEN]
    lea  rdx, [rbx + IH_MAP]
    call hid_touchpad_parse
    test eax, eax
    jz   .fail
    movzx eax, byte [rbx + IH_MAP]
    add  eax, 2
    cmp  ax, [rbx + IH_MAXIN]
    jne  .fail
    mov  rdi, rbx
    call ih_now               ; descriptor acquisition must also meet ACK deadline
    jc   .fail
    sub  rax, [rbx + IH_STARTED]
    cmp  rax, 5000
    jae  .fail
    cmp  eax, [rbx + IH_RESET_MS]
    jae  .fail
    mov  dword [rbx + IH_STATE], 3
    jmp  .none
.pre_ack:
    movzx eax, word [rbx + IH_WIRE]
    cmp  ax, [rbx + IH_MAXIN]
    ja   .fail
    cmp  eax, 3
    jb   .fail
    jmp  .none
.input:
    call .read
    test eax, eax
    jz   .fail
    mov  ax, [rbx + IH_MAXIN]
    cmp  [rbx + IH_WIRE], ax   ; zero is a new device reset, never an input report
    jne  .fail
    mov  rdi, rbx
    call ih_valid
    test eax, eax
    jz   .fail
    lea  rdi, [rbx + IH_ANCHOR]
    lea  rsi, [rbx + IH_MAP]
    lea  rdx, [rbx + IH_WIRE + 2]
    movzx ecx, word [rbx + IH_MAXIN]
    sub  ecx, 2
    lea  r8, [rel ih_publish]
    mov  r9, rbx
    call hid_touchpad_consume
    ; Decoder or full queue refusal leaves accepted custody/anchor untouched.
    pop  rbx
    ret
.fail:
    mov  rdi, rbx
    call i2c_hid_session_detach
.none:
    xor  eax, eax
    pop  rbx
    ret
.read:
    mov  rdi, rbx
    xor  esi, esi             ; input register is the default, plain slave read
    xor  edx, edx
    lea  rcx, [rbx + IH_WIRE]
    movzx r8d, word [rbx + IH_MAXIN]
    jmp  ih_xfer

; Same sink as USB. No origin/authority parameter can be supplied by a device.
ih_publish:
    mov  edi, USB_HID_MAX_STATES
    jmp  hid_pointer_publish

i2c_hid_session_detach:
    push rbx
    mov  rbx, rdi
    test rbx, rbx
    jz   .bad
    cmp  [rel i2c_hid_session_owner], rbx
    jne  .bad
    mov  dword [rbx + IH_STATE], 4 ; retire before any native release attempt
    cmp  byte [rel usb_hid_pointer_buttons + USB_HID_MAX_STATES], 0
    je   .clear
    mov  edi, USB_HID_MAX_STATES
    call hid_pointer_retire             ; RCQ-09: buttons up, no click
    test eax, eax
    jz   .bad                 ; held buttons remain owned, no slot/session reuse
.clear:
    lea  rdi, [rbx + IH_STATE]
    xor  eax, eax
    mov  ecx, IH_SIZE - IH_STATE
    rep  stosb
    mov  qword [rel i2c_hid_session_owner], 0
    mov  eax, 1
    pop  rbx
    ret
.bad:
    xor  eax, eax
    pop  rbx
    ret

align 8
i2c_hid_session_owner: dq 0
