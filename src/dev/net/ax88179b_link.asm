;; MODULE dev/net/ax88179b_link
;; LAYER 3
;; EXPORTS ax88179b_link_start
;; IMPORTS dev/net/ax88179b_attach
;; CAPS
;; OWNER saga:net
; Native newer-ASIX link activation. Independent wire implementation from
; ASIXElectronics/asix-usb-nic-linux-driver42feb1252fe0669845a8d6714bcc77bfc19eea1d:
; ax88179a_772d.c AX88179A_BULKIN_SIZE and ax88179a_link_setting;
; ax_main.h PHY11, physical USB link and MAC medium/RX_CTL definitions.
;
; RDI=fresh immutable DEVICE18B,RSI=actual18,RDX=owned HC port1..255,
; RCX=already-bound self-less synchronous usbhc_ops.control,
; R8=xHCI speed1 FS/3 HS/4 SS/5 SSP,R9=trusted distinct32B output.
; Caller has completed the newer parked initializer and endpoint setup, with
; raw untagged RX, software checksums, no PTP, MTU1500, no active/pending RX TD.
; Device/HC context stays serialized. Callbacks preserve SysV nonvolatiles,
; finish synchronously and retain no stack pointers. No production caller yet.
;
; EAX1=controls completed for active link,2=fresh link-down observation without
; writes,0=refused/unknown. Preserves RBX/RBP/R12-R15. Success record:
; MAC0..5,chip6,USB7,PHYword8,mediumword10,queue5B12..16,zero17..23,schema1q24.
; MAC is always read AFTER the caller's firmware mode/reload sequence. The
; parked initializer's earlier MAC is never reused (SOURCE review L1).
; Output publishes only at the final exact completion, or the valid down read.
; No effect rollback/retry: any failure after a write leaves state unknown;
; caller retires/reconciles the attempt rather than reissuing an uncertain TD.
; No frame transfer/netdev, PHY advertisements, firmware/flash/EEPROM programming.

%macro AXBL_IO 6
    mov rax,(%1 | (%2<<8) | (%3<<16) | (%4<<32) | (%5<<48))
    mov rdx,%6
    mov [r14+8],rdx
    call ax88179b_link_start.xfer
    jne ax88179b_link_start.fail
%endmacro
%macro AXBL_MAC 3
    AXBL_IO 0x40,1,%1,%2,%2,%3
%endmacro
ax88179b_link_start:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,72
    mov r14,rsp                     ; setup0,data8,record16,expected48
    mov rbx,rcx
    mov rbp,rdx
    mov r13,r9
    mov r15,r8
    test rbx,rbx
    jz .fail
    test r13,r13
    jz .fail
    test rbp,rbp
    jz .fail
    cmp rbp,255
    ja .fail
    cmp r15,1
    je .args_ok
    cmp r15,3
    jb .fail
    cmp r15,5
    ja .fail
.args_ok:
    call ax88179b_claims_desc
    test eax,eax
    jz .fail
    mov qword [r14+16],0
    mov qword [r14+24],0
    mov qword [r14+32],0
    mov qword [r14+40],1
    AXBL_IO 0xc0,1,5,1,1,0
    movzx edi,byte [r14+8]
    mov [r14+22],dil
    call ax88179b_feature_match
    test eax,eax
    jz .fail
    AXBL_IO 0xc0,1,0x10,6,6,0       ; fresh post-reload NODE_ID
    test byte [r14+8],1
    jnz .fail
    mov eax,[r14+8]
    movzx edx,word [r14+12]
    mov [r14+16],eax
    mov [r14+20],dx
    or eax,edx
    jz .fail
    AXBL_IO 0xc0,2,3,0x11,2,0      ; live negotiated PHY speed/duplex/link
    movzx r12d,word [r14+8]
    mov [r14+24],r12w
    mov eax,r12d
    and eax,0xc000
    cmp eax,0xc000
    je .fail                        ; unknown/reserved speed, including all-ones
    AXBL_IO 0xc0,1,2,1,1,0         ; native physical USB link status
    movzx eax,byte [r14+8]
    mov [r14+23],al
    and eax,7
    mov edx,4
    cmp r15,4
    jae .usb_expected
    mov edx,2
    cmp r15,3
    je .usb_expected
    mov edx,1
.usb_expected:
    cmp eax,edx
    jne .fail                       ; descriptor speed must match live one-hot PLSR
    test r12d,0x400
    jz .down                        ; parked caller remains parked, no writes

    ; Select bcd0200's vendor aggregate row, not the overlapping772D table.
    xor ecx,ecx
    mov eax,r12d
    and eax,0xc000
    test eax,eax
    jz .ten_mbit
    cmp eax,0x8000
    jne .hundred_mbit
    test byte [r14+23],2
    jz .queue_row
    mov ecx,1
    jmp .queue_row
.hundred_mbit:
    test byte [r14+23],4
    jz .not_ss
    mov ecx,2
    jmp .duplex_row
.not_ss:
    test byte [r14+23],2
    jz .duplex_row
    mov ecx,4
.duplex_row:
    test r12d,0x2000
    jnz .queue_row
    inc ecx
    jmp .queue_row
.ten_mbit:
    mov ecx,6
.queue_row:
    imul ecx,5
    lea rdx,[rel axbl_bulk_rows]
    add rdx,rcx
    mov eax,[rdx]
    mov [r14+28],eax
    mov al,[rdx+4]
    mov [r14+32],al
    mov edx,0x130                    ; receive enabled, RX/TX flow control
    test r12d,0x2000
    jz .medium_duplex
    or edx,2
.medium_duplex:
    mov eax,r12d
    and eax,0xc000
    cmp eax,0x8000
    jne .medium_ready
    or edx,1
.medium_ready:
    mov [r14+26],dx

    AXBL_MAC 0x0b,2,0               ; RX_STOP before changing link dataplane
    AXBL_MAC 0xb7,1,0               ; park RX/TX paths
    AXBL_MAC 0xb5,1,0xa5
    AXBL_MAC 0x54,2,0x0410          ; LOW54=16,HIGH55=4
    AXBL_MAC 0xb8,1,0x29
    mov edx,0x007078
    test r12d,0xc000
    jnz .rx_status
    mov edx,0xff70fa
.rx_status:
    AXBL_MAC 0x6d,3,rdx
    mov edx,0x40
    test r12d,0xc000
    jnz .rx_data
    mov edx,0xfa
.rx_data:
    AXBL_MAC 0xc0,1,rdx
    AXBL_MAC 0x0e,1,0
    mov rdx,[r14+28]
    AXBL_MAC 0x2e,5,rdx             ; largest row46KiB < 48KiB DMA capacity
    movzx edx,word [r14+26]
    AXBL_MAC 0x22,2,rdx             ; newer vendor medium, no legacy100M PS bit
    AXBL_MAC 0x0b,2,0x88            ; START|broadcast; no2B IP pad/VLAN strip
    AXBL_MAC 0xb7,1,3               ; RX/TX path ready is the final write
    mov r12d,1
    jmp .publish
.down:
    mov r12d,2
.publish:
    mov rax,[r14+16]
    mov rdx,[r14+24]
    mov rcx,[r14+32]
    mov r8,[r14+40]
    mov [r13],rax
    mov [r13+8],rdx
    mov [r13+16],rcx
    mov [r13+24],r8
    mov eax,r12d
    jmp .out
.fail:
    xor eax,eax
.out:
    add rsp,72
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.xfer:
    mov [r14],rax
    movzx r8d,word [r14+6]
    mov [r14+48],r8
    lea rsi,[r14]
    mov rdx,rbp
    lea rcx,[r14+8]
    sub rsp,8
    call rbx
    add rsp,8
    cmp rax,[r14+48]                 ; full-width actual count, no aliases
    ret
align 8
axbl_bulk_rows:
    db 5,0x7b,0,0x17,0x0f
    db 5,0xc0,2,6,0x0f
    db 7,0xf0,0,0x0c,0x0f
    db 6,0,0,6,0x0f
    db 5,0xc0,4,6,0x0f
    db 7,0xc0,4,6,0x0f
    db 7,0,0,3,0x3f
%unmacro AXBL_IO 6
%unmacro AXBL_MAC 3
