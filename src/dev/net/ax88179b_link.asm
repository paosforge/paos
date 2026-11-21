;; MODULE dev/net/ax88179b_link
;; LAYER 3
;; EXPORTS ax88179b_link_start, ax88179b_phy_word
;; IMPORTS dev/net/ax88179b_attach
;; CAPS
;; OWNER saga:net
; Native newer-ASIX link activation. Independent wire implementation from
; ASIXElectronics/asix-usb-nic-linux-driver42feb1252fe0669845a8d6714bcc77bfc19eea1d:
; ax88179a_772d.c AX88179A_BULKIN_SIZE and ax88179a_link_setting;
; ax_main.h physical USB link and MAC medium/RX_CTL definitions. Link, speed
; and duplex come from the standard IEEE MII registers, as that driver's 179A
; path does (ax_main.c polling BMSR_LSTATUS; get_ether_link via mii). It never
; reads PHYSR reg 0x11 for this chip; the old PHYSR oracle read down on Reatan
; while Windows had link (B1, ROOT 121294).
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
; PHYword keeps the PHYSR bit layout (0x8000 1000,0x4000 100,0x2000 full,
; 0x400 link) but is built by ax88179b_phy_word from standard MII registers.
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
    mov rcx,rbx
    mov rdx,rbp
    call ax88179b_phy_word          ; live link/speed/duplex, standard MII only
    test eax,eax
    jz .fail
    movzx r12d,ax
    mov [r14+24],r12w
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

; RCX=self-less synchronous control (same contract as ax88179b_link_start),
; RDX=owned HC port. Read-only standard MII on PHY3 through AX_ACCESS_PHY:
; BMSR twice (link status latches low), BMCR, then with autonegotiation
; ADVERTISE,LPA,CTRL1000,STAT1000. Resolution follows Linux
; mii_ethtool_get_link_ksettings, which the vendor 179A get_ether_link uses:
; common 1000 > 100 > 10, full duplex from the common mode's FULL bit; forced
; mode from BMCR. Stricter than Linux: link with autonegotiation enabled but
; not complete is down (repolled later), and forced 1000+100 is refused.
; EAX=0x10000|word in PHYSR layout (0x8000 1000,0x4000 100,0x2000 full,
; 0x400 link; down=0), or 0 when any transfer is not exact. No writes, no
; retries. Preserves RBX/RBP/R12-R15.
ax88179b_phy_word:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    sub rsp,32                      ; setup0,data8,BMSR16,BMCR18,ADV20,LPA22,C1000 24,S1000 26
    mov r14,rsp
    mov rbx,rcx
    mov rbp,rdx
    xor r13d,r13d
    mov edi,1
    call .rd                        ; latched BMSR
    jne .fail
    mov edi,1
    call .rd                        ; current BMSR
    jne .fail
    mov [r14+16],ax
    test eax,4                      ; BMSR_LSTATUS
    jz .down
    xor edi,edi
    call .rd                        ; BMCR
    jne .fail
    mov [r14+18],ax
    test eax,0x1000                 ; BMCR_ANENABLE
    jz .forced
    test word [r14+16],0x20         ; BMSR_ANEGCOMPLETE
    jz .down
    mov edi,4
    call .rd                        ; ADVERTISE
    jne .fail
    mov [r14+20],ax
    mov edi,5
    call .rd                        ; LPA
    jne .fail
    mov [r14+22],ax
    mov edi,9
    call .rd                        ; CTRL1000
    jne .fail
    mov [r14+24],ax
    mov edi,10
    call .rd                        ; STAT1000
    jne .fail
    mov [r14+26],ax
    shr eax,2                       ; LPA_1000FULL/HALF onto ADVERTISE_1000FULL/HALF
    movzx edx,word [r14+24]
    and eax,edx
    and eax,0x300
    jz .not_giga
    mov r13d,0x8400
    test eax,0x200
    jz .done
    or r13d,0x2000
    jmp .done
.not_giga:
    movzx eax,word [r14+20]
    movzx edx,word [r14+22]
    and eax,edx
    test eax,0x180                  ; ADVERTISE_100FULL|100HALF
    jz .ten
    mov r13d,0x4400
    test eax,0x100
    jz .done
    or r13d,0x2000
    jmp .done
.ten:
    mov r13d,0x400
    test eax,0x40                   ; ADVERTISE_10FULL
    jz .done
    or r13d,0x2000
    jmp .done
.forced:
    mov edx,eax
    and edx,0x2040
    cmp edx,0x2040
    je .fail                        ; SPEED1000 with SPEED100 is reserved
    mov r13d,0x400
    test eax,0x40
    jz .forced_100
    or r13d,0x8000
.forced_100:
    test eax,0x2000
    jz .forced_duplex
    or r13d,0x4000
.forced_duplex:
    test eax,0x100
    jz .done
    or r13d,0x2000
    jmp .done
.down:
    xor r13d,r13d
.done:
    lea eax,[r13+0x10000]
    jmp .out
.fail:
    xor eax,eax
.out:
    add rsp,32
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.rd:                                ; EDI=MII register; ZF=exact two-byte read, EAX=word
    mov rax,0x00020000000302c0
    shl rdi,32
    or rax,rdi
    mov [r14],rax
    mov word [r14+8],0
    lea rsi,[r14]
    mov rdx,rbp
    lea rcx,[r14+8]
    mov r8d,2
    sub rsp,8
    call rbx
    add rsp,8
    cmp rax,2
    movzx eax,word [r14+8]
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
