;; MODULE dev/net/ax88179b_control
;; LAYER 3
;; EXPORTS ax88179b_init_parked
;; IMPORTS dev/net/ax88179b_attach
;; CAPS
;; OWNER saga:net
; Newer ASIX control initialization, independently implemented from the wire
; protocol in ASIXElectronics/asix-usb-nic-linux-driver commit
; 42feb1252fe0669845a8d6714bcc77bfc19eea1d: ax_main.c chip/MAC reads;
; ax88179a_772d.c:1361..1460,1661..1874 and the associated register headers.
;
; RDI=fresh immutable DEVICE descriptor, RSI=actual completed descriptor bytes,
; RDX=owned enumerated HC port token1..255, RCX=self-less usbhc_ops.control,
; R8=blocking delay_ms callback (RDI milliseconds, result ignored),
; R9=trusted distinct16B output. Caller serializes this device and HC context;
; callbacks preserve SysV nonvolatiles, complete synchronously and cannot keep
; any pointer to our private stack. The control thunk's controller binding is
; already selected by the caller, just like the existing self-less HC seam.
;
; EAX1=initialized PARKED,0=refused/failed. Preserves RBX/RBP/R12-R15.
; Output bytes0..5=MAC,6=chip status,7=pin low2 bits, qword8=schema1.
; Output is published only after all30 exact completions; untouched on failure.
; This is neither link-up nor a netdev. RX_CTL remains zero and MAC_PATH zero.
; Does not configure endpoints, select an interface, register or send frames.
; No production caller yet: only a separately bound newer backend may call it.
;
; Each USB request requires the full 64-bit result to equal wLength, including
; zero for no-data success; negative/short/overlong results fail immediately.
; Partial device writes cannot be rolled back by this function. On failure the
; caller must retire the attempt and reconcile/reset its actual device state;
; there is no retry or implicit cleanup request after an unknown completion.
; No persistent firmware write, flash erase, boot-to-ROM, WOL or PHY-policy
; advertisement command. FW_MODE and RELOAD_FLASH_EFUSE are volatile selection
; and reload commands, not a flash programming sequence.

%macro AXBC_IO 6
    mov rax, (%1 | (%2 << 8) | (%3 << 16) | (%4 << 32) | (%5 << 48))
    mov rdx, %6
    mov [r14 + 8], rdx
    call ax88179b_init_parked.xfer
    jne ax88179b_init_parked.fail
%endmacro
%macro AXBC_MAC 3
    AXBC_IO 0x40, 1, %1, %2, %2, %3
%endmacro

ax88179b_init_parked:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 40                     ; 16-byte aligned before each call
    mov r14, rsp                     ; setup0, data8, staged output16, expected32
    mov rbx, rcx
    mov rbp, rdx
    mov r12, r8
    mov r13, r9
    test rbx, rbx
    jz .fail
    test r12, r12
    jz .fail
    test r13, r13
    jz .fail
    test rbp, rbp
    jz .fail
    cmp rbp, 255
    ja .fail
    call ax88179b_claims_desc        ; descriptor identity before any USB action
    test eax, eax
    jz .fail
    mov qword [r14 + 16], 0
    mov qword [r14 + 24], 1

    AXBC_IO 0xc0, 1, 5, 1, 1, 0    ; fresh native CHIP_STATUS, not cached OS name
    movzx edi, byte [r14 + 8]
    mov [r14 + 22], dil
    call ax88179b_feature_match
    test eax, eax
    jz .fail
    AXBC_IO 0xc0, 1, 0x10, 6, 6, 0 ; NODE_ID, before the first device write
    test byte [r14 + 8], 1          ; multicast (including broadcast) is invalid
    jnz .fail
    mov eax, [r14 + 8]
    movzx edx, word [r14 + 12]
    mov [r14 + 16], eax
    mov [r14 + 20], dx
    or eax, edx
    jz .fail

    AXBC_IO 0x40, 8, 1, 0, 0, 0    ; FW_MODE_179A, no PTP/priority extra endpoints
    AXBC_IO 0x40, 6, 0, 0, 0, 0    ; reload existing flash/eFuse configuration
    AXBC_IO 0xc0, 0x81, 0x3404, 0, 4, 0
    mov edx, [r14 + 8]
    and edx, 0xffff98ff
    or edx, 0x6100                  ; same explicit no-LPM policy as vendor bind
    AXBC_IO 0x40, 0x81, 0x3404, 0, 4, rdx
    AXBC_IO 0xc0, 0x10, 0x18c8, 0, 4, 0
    mov al, [r14 + 8]
    and al, 3
    mov [r14 + 23], al              ; ipalign remains zero for this chip family
    AXBC_IO 0x40, 0x31, 0, 0, 1, 2 ; PHY power on, no legacy PHY reset sequence
    mov edi, 500                    ; vendor PHY250ms + hw_init250ms
    call r12
    AXBC_IO 0x40, 0xc0, 0x500, 0, 0, 0 ; autodetach disabled (low bit0)

    AXBC_MAC 0xb7, 1, 0            ; park both paths before changing dataplane
    AXBC_MAC 0x0b, 2, 0            ; RX_STOP; never set START here
    AXBC_MAC 0x35, 1, 0            ; software TX checksums, no TSO/offload
    AXBC_MAC 0x34, 1, 0            ; software RX checksum policy
    AXBC_MAC 0xb9, 1, 2            ; newer efficient bulk OUT framing
    AXBC_MAC 0x55, 1, 4            ; newer HIGH55=4 (legacy values do not apply)
    AXBC_MAC 0x54, 1, 0x10         ; newer LOW54=16
    AXBC_MAC 0x2b, 1, 0            ; no VLAN strip/filter/insert
    AXBC_MAC 0x41, 1, 0xff         ; BM interrupt mask
    AXBC_MAC 0x43, 1, 0            ; BM RX DMA control
    AXBC_MAC 0x46, 1, 0            ; BM TX DMA control
    AXBC_MAC 0x9e, 1, 0            ; ARC control
    AXBC_MAC 0xb1, 1, 0            ; SWP control
    AXBC_MAC 0xcc, 1, 1            ; newer header checksum (matches new TX codec)
    AXBC_IO 0xc0, 1, 0x24, 1, 1, 0
    movzx edx, byte [r14 + 8]
    and edx, 0xe0                  ; preserve type/polarity, disable wake triggers
    AXBC_MAC 0x24, 1, rdx
    AXBC_IO 0xc0, 1, 0x22, 2, 2, 0
    movzx edx, word [r14 + 8]
    and edx, 0xfffe
    mov r15d, edx
    AXBC_MAC 0x22, 2, rdx           ; vendor medium GIGA clear/set sequence
    mov edx, r15d
    or edx, 1
    AXBC_MAC 0x22, 2, rdx
    AXBC_MAC 0x0e, 1, 0            ; BFM data
    AXBC_MAC 0xb0, 1, 0            ; native protocol, not CDC-ECM mode

    mov rax, [r14 + 16]
    mov rdx, [r14 + 24]
    mov [r13], rax
    mov [r13 + 8], rdx
    mov eax, 1
    jmp .out
.fail:
    xor eax, eax
.out:
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; RAX=packed USB setup, data already at workspace+8. Flags ZF1 iff exact.
; HC self-less ABI: RSI setup*,RDX port,RCX data/null,R8 capacity.
.xfer:
    mov [r14], rax
    movzx r8d, word [r14 + 6]
    mov [r14 + 32], r8
    lea rsi, [r14]
    mov rdx, rbp
    lea rcx, [r14 + 8]
    test r8, r8
    jnz .data
    xor ecx, ecx
.data:
    sub rsp, 8
    call rbx
    add rsp, 8
    cmp rax, [r14 + 32]             ; full width: reject negative/high-bit aliases
    ret

%unmacro AXBC_IO 6
%unmacro AXBC_MAC 3
