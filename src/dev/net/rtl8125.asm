;; MODULE dev/net/rtl8125
;; LAYER 3
;; EXPORTS rtl8125_link_rearm_counts, rtl8125_witness, rtl8125_hw_bringup, rtl8125_ops, rtl8125_inst, rtl8125_bound, rtl8125_matches, rtl8125_released, rtl8125_frame_stats, rtl8125_link_status, rtl8125_carrier_prepare, rtl8125_carrier_set, rtl8125_carrier_observation, rtl8125_carrier_ready, rtl8125_carrier_read, rtl8125_carrier_write, rtl8125_carrier_link, rtl8125_terminal_quiesce
;; IMPORTS boot/native_driver_gate, net/netdev, bus/pci, bus/hal, core/dma, core/time, boot/serial, bus/pci_claim, hv/nic_assignment, hv/pci_assign
;; CAPS mmio dma
;; OWNER saga:net
%include "boot/native_driver_gate.inc"
%include "dev/net/realtek_link_rearm.inc"
; ============================================================================
; PaOS RTL8125 clean-room protocol from pinned BSD facts and PaOS interfaces.
; Firmware-left PHY state remains an experiment requiring separate metal proof.
; No integration until source/similarity review and dirty-side fixture adaptation.
; Protocol reference notices (pinned ISC OpenBSD if_rge.c / if_rgereg.h):
; Copyright (c) 2019, 2020, 2023-2025 Kevin Lo <kevlo@openbsd.org>
; Copyright (c) 2019, 2020, 2025 Kevin Lo <kevlo@openbsd.org>
; Permission to use, copy, modify, and distribute this software for any
; purpose with or without fee is hereby granted, provided that the above
; copyright notice and this permission notice appear in all copies.
; THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
; WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
; MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
; ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
; WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
; ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
; OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
; PCI discovery, per-port state, DMA allocation and registration are kept.
; ============================================================================
%include "core/abi/pci_claim.inc"

R5_VENDEV        equ 0x812510EC        ; PCI identity, vendor low16
R5_MAX_INST      equ 2                ; PaOS instance bound
R5_MAX_SCAN      equ 4                ; PaOS discovery bound
R5_NUM_TX        equ 32               ; PaOS allocation policy
R5_NUM_RX        equ 64
R5_TX_BUF        equ 2048
R5_RX_BUF        equ 2048
R5_FRAME_MIN     equ 14
R5_FRAME_MAX     equ 1518
R5_LINK_WAIT_MS  equ 2500              ; PaOS bounded link wait
; Clean protocol facts: pinned ISC OpenBSD [OH]23-64,113,154-182,
; 212-286,399-401; source URLs/hashes and decisions in spec section 5.
R5_DESC_SIZE     equ 32
C25_TXCFG       equ 0x40
C25_RXCFG       equ 0x44
C25_MAC_LOW     equ 0x00
C25_MAC_HIGH    equ 0x04
C25_ISR         equ 0x3C
C25_MAC_OCP     equ 0xB0
C25_PHY_OCP     equ 0xB8
C25_REV_MASK    equ 0x7CF00000
C25_REV_A       equ 0x60900000
C25_REV_B       equ 0x64100000
C25_RX_A        equ 0x41000700
C25_RX_B        equ 0x41000C00
C25_OWN         equ 0x80000000
C25_LAST        equ 0x40000000
C25_RX_FIRST_END equ 0x03000000
C25_RX_ERROR    equ 0x00100000
C25_RX_LENGTH   equ 0x3FFF
C25_RX_ADDRESS  equ 16
C25_RX_EXTENDED equ 24
C25_RX_STATUS   equ 28
C25_PHY_POLLS   equ 20000             ; [OB]3636-3669, 1us per poll
C25_BMCR_OCP    equ 0xA400            ; [OH]69 + [OB]3606-3632
C25_BMCR_PDOWN  equ 0x0800            ; [OM]49-56: power down
C25_BMCR_ISO    equ 0x0400            ; [OM]49-56: isolate
C25_PHY_UNKNOWN equ 0xFFFF            ; PaOS unavailable-status sentinel
C25_COMMAND     equ 0x37
C25_MASK        equ 0x38
C25_UNLOCK      equ 0x50
C25_PHY_STATUS  equ 0x6C
C25_DOORBELL    equ 0x90
C25_RX_MAX      equ 0xDA
C25_RX_GATE     equ 0xF2
C25_TX_BASE     equ 0x20
C25_RX_BASE     equ 0xE4
C25_CPLUS       equ 0xE0
C25_RSS         equ 0x4500
C25_RX_QUEUE    equ 0x4800
C25_TX_CONFIG   equ 0x03000700
C25_TX_FIRST_END equ 0x30000000


struc r5i
    .dev:        resb dev_size         ; first: the registered handle IS the instance
    .region:     resb 16               ; HAL region: bar_base, bar_size
    .bdf:        resq 1
    .tx_ring:    resq 1
    .rx_ring:    resq 1
    .tx_buffer:  resq 1
    .rx_buffers: resq 1
    .isr_seen: resq 1               ; OR of actual existing ACK observations
    .rx_poll_calls: resq 1
    .rx_status_acks: resq 1          ; observed RX ISR classes before existing W1C
    .tx_status_acks: resq 1          ; observed TX ISR classes, not delivered IRQs
    .tx_frames:  resq 1
    .rx_frames:  resq 1
    .tx_drops:   resq 1
    .rx_drops:   resq 1
    .tx_timeouts: resq 1
    .owner_mismatches: resq 1
    .recover_attempts: resq 1
    .recover_failures: resq 1
    ; Retained carrier observation, copied in this order after valid=1.
    .obs_stage:  resq 1                ; 0 unstarted .. 4 PDOWN verified
    .obs_request: resq 1               ; requested BMCR
    .obs_write:  resq 1                ; raw write return, -2 unreturned
    .obs_readback: resq 1              ; raw BMCR readback, -2 unreturned
    .obs_phys:   resq 1                ; last actual PHYstatus read, -2 none
    .obs_seq:    resq 1                ; accepted set operations, saturating
    .obs_final:  resq 1                ; 0 / -1, -2 unreturned
    .link_rearm: resb REALTEK_LR_SIZE ; ordinary down/up state and counters
    .rxcfg:      resd 1
    .xid:        resd 1
    .tx_head:    resd 1
    .rx_cursor:  resd 1
    .link_speed: resd 1
    .phys_raw:   resd 1                ; observed PHY status at no-link verdict
    .bmcr:       resd 1                ; observed basic mode control; -1 = unavailable
    .mac:        resb 8
    .probed:     resb 1
    .hw_ok:      resb 1
    .rings_ok:   resb 1
    .link_up:    resb 1
    .registered: resb 1
    .recover_busy: resb 1
    .phy_kicked: resb 1
    .ll_timeout: resb 1
    .attach_attempted: resb 1          ; final decision for this bring-up, even on failure
    .tx_busy:    resb 1                ; producer admission, taken by XCHG only
    .attach_pad: resb 2                ; keep the expanded instance stride aligned
endstruc

; --- HAL-gated MMIO on instance RBX (dword only) ---------------------------------
; r5_rd(RBX=inst, RSI=offset) -> EAX. clobbers RAX,RDI.
r5_rd:
    lea  rdi, [rbx + r5i.region]
    jmp  hal_mmio_read32
; r5_wr(RBX=inst, RSI=offset, EDX=value). clobbers RAX,R9,RDI.
r5_wr:
    lea  rdi, [rbx + r5i.region]
    jmp  hal_mmio_write32
r5_or:
    push rsi
    push rdx
    call r5_rd
    pop  rdx
    pop  rsi
    jc   .out
    or   edx, eax
    jmp  r5_wr
.out:
    ret
r5_andn:
    push rsi
    push rdx
    call r5_rd
    pop  rdx
    pop  rsi
    jc   .out
    not  edx
    and  edx, eax
    jmp  r5_wr
.out:
    ret

; Generic exact-width HAL seam approved root 2026-10-09 12:47:49.
r5_rd8:
    lea  rdi, [rbx + r5i.region]
    jmp  hal_mmio_read8
r5_rd16:
    lea  rdi, [rbx + r5i.region]
    jmp  hal_mmio_read16
r5_wr8:
    lea  rdi, [rbx + r5i.region]
    jmp  hal_mmio_write8
r5_wr16:
    lea  rdi, [rbx + r5i.region]
    jmp  hal_mmio_write16
r5_byte_or:
    push rdx
    call r5_rd8
    pop  rdx
    jc   .out
    or   edx, eax
    jmp  r5_wr8
.out:
    ret
r5_byte_andn:
    push rdx
    call r5_rd8
    pop  rdx
    jc   .out
    not  edx
    and  edx, eax
    jmp  r5_wr8
.out:
    ret

; Clear usable state and PCI bus mastering on partial setup/recovery failure.
; PCI command is low16; write0 to the adjacent W1C PCI status word.
r5_contain_dma:
    push r12
    push r13
    push r14
    mov  byte [rbx + r5i.rings_ok], 0
    mov  byte [rbx + r5i.hw_ok], 0
    mov  byte [rbx + r5i.link_up], 0
    mov  dword [rbx + r5i.link_speed], 0
    mov  dword [rbx + r5i.dev + dev.health], HEALTH_DEAD
    mov  r12, [rbx + r5i.bdf]
    mov  r13, r12
    shr  r13, 8
    and  r13d, 0xFF
    mov  r14d, r12d
    and  r14d, 0xFF
    shr  r12, 16
    and  r12d, 0xFF
    mov  edi, r12d
    mov  esi, r13d
    mov  edx, r14d
    mov  ecx, 4
    call pci_cfg_read32
    and  eax, 0x0000FFFB
    mov  r8d, eax
    mov  edi, r12d
    mov  esi, r13d
    mov  edx, r14d
    mov  ecx, 4
    call pci_cfg_write32
    pop  r14
    pop  r13
    pop  r12
    ret

; r5_self(RDI=handle) -> RBX=instance or ZF set when RDI is not one of ours.

; Trusted BSP observation: RDI exact selected handle, RSI 20-qword output.
; EAX=0 complete, -1 unavailable (output may be partial; caller keeps validity
; separate). Existing terminal/policy admission; no waits, PHY/OCP transactions,
; MMIO writes, interrupt clears, DMA ownership writes or readiness decisions.
; Schema: family, software TX cursor, tail(-1 unavailable), active TX slots,
; OWN bitmap, RX cursor, current RX status, live PHY, ISR, IMR, TX/RX frames,
; RX/TX status-ACK class counts (poll mode, NOT delivered IRQs), command,
; service-derived new ISR bits, ACK ISR OR, TX timeouts, owner mismatches, RX polls.
rtl8125_witness:
    push rbx
    call r5_self
    jz .bad
    cmp byte [rel rtl8125_terminal_latched], 0
    jne .bad
    mov al, 1
    xchg al, [rbx + r5i.tx_busy]
    test al, al
    jnz .bad
    call rtl8125_witness_active
    mov byte [rbx + r5i.tx_busy], 0
    pop rbx
    ret
.bad:
    mov rax, -1
    pop rbx
    ret
rtl8125_witness_active:
    cmp byte [rel rtl8125_terminal_latched], 0
    je .open
    mov rax, -1
    ret
.open:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r13, rsi
    call rtl8125_carrier_ready
    cmp eax, 1
    jne .bad
    call r5_self
    mov r12, [rbx + r5i.tx_ring]
    test r12, r12
    jz .bad
    mov r14, [rbx + r5i.rx_ring]
    test r14, r14
    jz .bad
    mov eax, [rbx + r5i.tx_head]
    cmp eax, 32
    jae .bad
    mov [r13 + 8], rax
    mov eax, [rbx + r5i.rx_cursor]
    cmp eax, 64
    jae .bad
    mov [r13 + 40], rax
    shl rax, 5
    add r14, rax
    clflush [r14]
    mfence
    mov eax, [r14 + 28]
    mov [r13 + 48], rax
    xor r15d, r15d
    xor ecx, ecx
.own:
    clflush [r12]
    mfence
    mov eax, [r12]
    test eax, 0x80000000
    jz .next
    bts r15, rcx
.next:
    add r12, 32
    inc ecx
    cmp ecx, 32
    jb .own
    mov [r13 + 32], r15
    mov qword [r13 + 16], -1
    mov qword [r13 + 24], 32
    mov esi, 108
    call r5_rd
    jc .bad
    and eax, 0xffff
    mov [r13 + 56], rax
    mov esi, 60
    call r5_rd
    jc .bad
    mov [r13 + 64], rax
    mov esi, 56
    call r5_rd
    jc .bad
    mov [r13 + 72], rax
    mov esi, 52
    call r5_rd
    jc .bad
    shr eax, 24
    mov [r13 + 112], rax
    mov rax, [rbx + r5i.tx_frames]
    mov [r13 + 80], rax
    mov rax, [rbx + r5i.rx_frames]
    mov [r13 + 88], rax
    mov rax, [rbx + r5i.rx_status_acks]
    mov [r13 + 96], rax
    mov rax, [rbx + r5i.tx_status_acks]
    mov [r13 + 104], rax
    mov qword [r13 + 120], -1          ; service derives 8168 new ISR bits
    mov rax, [rbx + r5i.isr_seen]
    mov [r13 + 128], rax
    mov rax, [rbx + r5i.tx_timeouts]
    mov [r13 + 136], rax
    mov rax, [rbx + r5i.owner_mismatches]
    mov [r13 + 144], rax
    mov rax, [rbx + r5i.rx_poll_calls]
    mov [r13 + 152], rax
    mov qword [r13], 8125
    xor eax, eax
    jmp .out
.bad:
    mov rax, -1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; BEGIN CARRIER_DRILL_LEAVES
; Trusted BSP leaves: coordinator admits exact membership+epoch before every
; call. These also reject foreign handles and unarmed/recovering instances.
rtl8125_carrier_ready:
    NATIVE_DRIVER_REFUSE 6
    push rbx
    call r5_self
    jz .bad
    cmp byte [rbx + r5i.registered], 1
    jne .bad
    cmp byte [rbx + r5i.hw_ok], 1
    jne .bad
    cmp byte [rbx + r5i.rings_ok], 1
    jne .bad
    cmp byte [rbx + r5i.recover_busy], 0
    jne .bad
    mov eax, 1
    pop rbx
    ret
.bad:
    xor eax, eax
    pop rbx
    ret
rtl8125_carrier_read:
    push rbx
    call r5_self
    jz .refuse
    cmp byte [rel rtl8125_terminal_latched], 0
    jne .refuse
    mov al, 1
    xchg al, [rbx+r5i.tx_busy]
    test al, al
    jnz .refuse
    cmp byte [rel rtl8125_terminal_latched], 0
    jne .release_refuse
    call rtl8125_carrier_read_active
    mov byte [rbx+r5i.tx_busy], 0
    pop rbx
    ret
.release_refuse:
    mov byte [rbx+r5i.tx_busy], 0
.refuse:
    mov rax, -1
    pop rbx
    ret
rtl8125_carrier_read_active:
    push rbx
    call rtl8125_carrier_ready
    cmp eax, 1
    jne .bad
    call r5_self
    mov edi, C25_BMCR_OCP
    call r5_phy_read
    jc .bad
    pop rbx
    ret
.bad:
    mov rax, -1
    pop rbx
    ret
rtl8125_carrier_write:
    push rbx
    call r5_self
    jz .refuse
    cmp byte [rel rtl8125_terminal_latched], 0
    jne .refuse
    mov al, 1
    xchg al, [rbx+r5i.tx_busy]
    test al, al
    jnz .refuse
    cmp byte [rel rtl8125_terminal_latched], 0
    jne .release_refuse
    call rtl8125_carrier_write_active
    mov byte [rbx+r5i.tx_busy], 0
    pop rbx
    ret
.release_refuse:
    mov byte [rbx+r5i.tx_busy], 0
.refuse:
    mov rax, -1
    pop rbx
    ret
rtl8125_carrier_write_active:
    push rbx
    call rtl8125_carrier_ready
    cmp eax, 1
    jne .bad
    test esi, 0xffff0000
    jnz .bad
    call r5_self
    mov edx, esi
    mov edi, C25_BMCR_OCP
    call r5_phy_write
    jc .bad
    pop rbx
    ret
.bad:
    mov rax, -1
    pop rbx
    ret
rtl8125_carrier_link:
    push rbx
    call r5_self
    jz .refuse
    cmp byte [rel rtl8125_terminal_latched], 0
    jne .refuse
    mov al, 1
    xchg al, [rbx+r5i.tx_busy]
    test al, al
    jnz .refuse
    cmp byte [rel rtl8125_terminal_latched], 0
    jne .release_refuse
    call rtl8125_carrier_link_active
    mov byte [rbx+r5i.tx_busy], 0
    pop rbx
    ret
.release_refuse:
    mov byte [rbx+r5i.tx_busy], 0
.refuse:
    mov rax, -1
    pop rbx
    ret
rtl8125_carrier_link_active:
    push rbx
    call rtl8125_carrier_ready
    cmp eax, 1
    jne .bad
    call r5_self
    ; Passive physical observation: no cached-link or DNS policy mutation.
    mov esi, C25_PHY_STATUS
    call r5_rd16
    jc .bad
    movzx edx, ax
    cmp edx, 0xffff
    je .bad
    shr eax, 1
    and eax, 1
    pop rbx
    ret
.bad:
    mov rdx, -1
    mov rax, -1
    pop rbx
    ret
; END CARRIER_DRILL_LEAVES

r5_self:
    lea  rbx, [rel rtl8125_inst]
    cmp  rdi, rbx
    je   .ours
    lea  rbx, [rel rtl8125_inst + r5i_size]
    cmp  rdi, rbx
    je   .ours
    xor  ebx, ebx
.ours:
    test rbx, rbx
    ret

rtl8125_noop:
    xor  eax, eax
    ret

; frame stats (netdev_frame_stats seam): RDI=self -> EAX 0, RDX=RX, RCX=TX, or -1.
rtl8125_frame_stats:
    push rbx
    call r5_self
    jz   .unavailable
    cmp  byte [rbx + r5i.registered], 1
    jne  .unavailable
    mov  rdx, [rbx + r5i.rx_frames]
    mov  rcx, [rbx + r5i.tx_frames]
    xor  eax, eax
    pop  rbx
    ret
.unavailable:
    mov  rdx, -1
    mov  rcx, -1
    mov  eax, -1
    pop  rbx
    ret

; CLEANROOM ROUTINE R5: transmit one frame, update only this instance's
; counters after the actual result. RDI=self, RSI=frame, RDX=length -> RAX 0/-1.
; RTL-DELTA-5: one nonblocking atomic admission per instance covers the head
; and OWN checks, bounce copy, publication, doorbell and completion wait. A
; second producer refuses at once; admission is released on every later path,
; while a timed-out descriptor keeps OWN and its bounce bytes.
rtl8125_tx:
    cmp byte [rel rtl8125_terminal_latched], 0
    je .active_entry
    mov rax, -1
    ret
.active_entry:
    push rbx
    push r12
    push r13
    push r14
    push r15
    call r5_self
    jz   .bad_handle
    mov  al, 1
    xchg al, [rbx + r5i.tx_busy]         ; XCHG with memory is implicitly locked
    test al, al
    jnz  .busy
    cmp  byte [rbx + r5i.rings_ok], 1
    jne  .drop
    cmp  qword [rbx + r5i.tx_ring], 0
    je   .drop
    cmp  qword [rbx + r5i.tx_buffer], 0
    je   .drop
    cmp  qword [rbx + r5i.rx_ring], 0
    je   .drop
    cmp  qword [rbx + r5i.rx_buffers], 0
    je   .drop
    test rsi, rsi
    jz   .drop
    mov  r14, rdx
    cmp  r14, R5_FRAME_MIN
    jb   .drop
    cmp  r14, R5_FRAME_MAX
    ja   .drop
    call r5_lr_tick
    test eax, eax
    jnz .drop
    ; Never publish a new OWN descriptor while carrier is down/unknown.
    ; A timed-out slot stays chip-owned and cannot be reused by the caller.
    ; Use a checked fresh PHY status, preserving the caller's frame pointer.
    mov  r12, rsi
    mov  esi, 0x6c
    call r5_rd16
    mov  rsi, r12
    jc   .drop
    cmp  eax, 0xffff
    jae  .drop
    test eax, 2
    jz   .drop
    mov  r13d, [rbx + r5i.tx_head]
    cmp  r13d, R5_NUM_TX
    jae  .owner_bad
    mov  r12, r13
    shl  r12, 5
    add  r12, [rbx + r5i.tx_ring]
    test dword [r12], C25_OWN
    jnz  .owner_bad                     ; never touch shared bounce while owned
    mov  rdi, [rbx + r5i.tx_buffer]
    mov  rcx, r14
    cld
    rep  movsb
    mov  qword [r12], 0                 ; status/ext/reserved zero, no offload
    mov  rax, [rbx + r5i.tx_buffer]
    mov  [r12 + 8], rax
    mov  qword [r12 + 16], 0
    mov  qword [r12 + 24], 0
    mov  eax, r14d
    or   eax, C25_TX_FIRST_END
    cmp  r13d, R5_NUM_TX - 1
    jne  .own
    or   eax, C25_LAST
.own:
    sfence
    or   eax, C25_OWN
    mov  [r12], eax
    sfence
    mov  esi, C25_DOORBELL
    mov  edx, 1
    call r5_wr16
    jc   .doorbell_failed
    mov  r15d, 200                     ; 200*100us =20ms, PaOS5..50ms policy
.wait:
    mov  eax, [r12]                    ; one completion snapshot per poll
    test eax, C25_OWN
    jz   .sent
    mov  edi, 100
    call tsc_delay_us
    dec  r15d
    jnz  .wait
    ; Include completion during the final delayed interval.
    mov  eax, [r12]
    test eax, C25_OWN
    jz   .sent
    lock inc qword [rbx + r5i.tx_timeouts]
    jmp  .drop                         ; leave OWN and cursor intact
.sent:
    inc  r13d
    and  r13d, R5_NUM_TX - 1
    mov  [rbx + r5i.tx_head], r13d
    lock inc qword [rbx + r5i.tx_frames]
    xor  eax, eax
    jmp  .release
.owner_bad:
    lock inc qword [rbx + r5i.owner_mismatches]
    jmp  .drop
.doorbell_failed:
    call r5_contain_dma                 ; don't let a partial post remain usable
.drop:
    lock inc qword [rbx + r5i.tx_drops]
    mov  rax, -1
.release:
    mov  byte [rbx + r5i.tx_busy], 0     ; software admission only, never OWN
    jmp  .out
.busy:
    lock inc qword [rbx + r5i.tx_drops]  ; another producer holds this instance
.bad_handle:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; CLEANROOM ROUTINE R6: receive and repost, bounded by caller capacity.
; RDI=self, RSI=destination, RDX=capacity -> RAX length/0/-1.
rtl8125_rx_poll:
    push rbx
    call r5_self
    jz .refuse
    cmp byte [rel rtl8125_terminal_latched], 0
    jne .refuse
    mov al, 1
    xchg al, [rbx+r5i.tx_busy]
    test al, al
    jnz .refuse
    cmp byte [rel rtl8125_terminal_latched], 0
    jne .release_refuse
    call rtl8125_rx_poll_active
    mov byte [rbx+r5i.tx_busy], 0
    pop rbx
    ret
.release_refuse:
    mov byte [rbx+r5i.tx_busy], 0
.refuse:
    mov rax, -1
    pop rbx
    ret
rtl8125_rx_poll_active:
    push rbx
    push r12
    push r13
    push r14
    push r15
    call r5_self
    jz   .bad_handle
    cmp  byte [rbx + r5i.rings_ok], 1
    jne  .bad_handle
    cmp  qword [rbx + r5i.rx_ring], 0
    je   .bad_handle
    cmp  qword [rbx + r5i.rx_buffers], 0
    je   .bad_handle
    call r5_lr_tick
    test eax, eax
    jnz .bad_handle
    inc qword [rbx + r5i.rx_poll_calls]
    mov  r12, rsi                         ; caller destination
    mov  r13, rdx                         ; caller capacity
    mov  r15d, [rbx + r5i.rx_cursor]
    cmp  r15d, R5_NUM_RX
    jae  .bad_cursor
    mov  r10, r15
    shl  r10, 5
    add  r10, [rbx + r5i.rx_ring]
    mov  eax, [r10 + C25_RX_STATUS]        ; exactly one status snapshot
    test eax, C25_OWN
    jnz  .empty
    mov  ecx, eax
    and  ecx, C25_RX_FIRST_END
    cmp  ecx, C25_RX_FIRST_END
    jne  .drop
    test eax, C25_RX_ERROR
    jnz  .drop
    and  eax, C25_RX_LENGTH
    cmp  eax, 4
    jbe  .drop
    sub  eax, 4                          ; FCS is not delivered to PaOS
    mov  r14d, eax
    cmp  r14d, R5_FRAME_MIN
    jb   .drop
    cmp  r14d, R5_FRAME_MAX
    ja   .drop
    cmp  r14, r13
    ja   .drop
    test r12, r12
    jz   .drop
    mov  rsi, r15
    shl  rsi, 11
    add  rsi, [rbx + r5i.rx_buffers]
    mov  rdi, r12
    mov  rcx, r14
    cld
    rep  movsb
    lock inc qword [rbx + r5i.rx_frames]
    jmp  .consume
.drop:
    lock inc qword [rbx + r5i.rx_drops]
    xor  r14d, r14d
.consume:
    mov  edi, r15d
    call r5_rx_post
    inc  r15d
    and  r15d, R5_NUM_RX - 1
    mov  [rbx + r5i.rx_cursor], r15d
    mov  rax, r14
    jmp  .ack
.bad_cursor:
    lock inc qword [rbx + r5i.owner_mismatches]
    mov  dword [rbx + r5i.rx_cursor], 0
    mov  rax, -1
    jmp  .ack
.empty:
    xor  eax, eax
.ack:
    push rax
    call r5_ack_status
    pop  rax
    jmp  .out
.bad_handle:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; RBX=instance, EDI=validated RX index. [OH]233-286; [OB]1249-1265.
; Address/reserved/ext fields precede OWN; EOR belongs only to the last slot.
r5_rx_post:
    mov  r10d, edi
    shl  r10, 5
    add  r10, [rbx + r5i.rx_ring]
    mov  qword [r10], 0
    mov  qword [r10 + 8], 0
    mov  eax, edi
    shl  rax, 11
    add  rax, [rbx + r5i.rx_buffers]
    mov  [r10 + C25_RX_ADDRESS], rax
    mov  dword [r10 + C25_RX_EXTENDED], 0
    mov  eax, R5_RX_BUF
    cmp  edi, R5_NUM_RX - 1
    jne  .publish
    or   eax, C25_LAST
.publish:
    sfence
    or   eax, C25_OWN
    mov  [r10 + C25_RX_STATUS], eax
    sfence
    ret

; CLEANROOM ROUTINE R7: acknowledge only observed interrupt status, poll mode.
; RBX=instance. No action while rings are not armed.
r5_ack_status:
    cmp  byte [rbx + r5i.rings_ok], 1
    jne  .out
    mov  esi, C25_ISR
    call r5_rd
    jc   .out
    test eax, eax
    jz   .out
    or [rbx + r5i.isr_seen], rax
    test eax, 3                       ; RX OK/error class, one observed W1C
    jz .no_rx_count
    inc qword [rbx + r5i.rx_status_acks]
.no_rx_count:
    test eax, 12                      ; TX OK/error class
    jz .no_tx_count
    inc qword [rbx + r5i.tx_status_acks]
.no_tx_count:
    mov  edx, eax
    call r5_wr                         ; exact observed W1C bits, no IMR write
.out:
    ret

; CLEANROOM ROUTINE R8: one live PHY status read on RBX=instance.
; Update only this instance's link_up, link_speed and phys_raw fields.
; RTL-DELTA-3: EAX 0 readable, -1 unknown (HAL refusal or all-ones status);
; unknown leaves the cleared link/speed cache and is never decoded.
r5_link_refresh:
    mov  byte [rbx + r5i.link_up], 0
    mov  dword [rbx + r5i.link_speed], 0
    mov  esi, C25_PHY_STATUS
    call r5_rd16
    jc   .unavailable
    movzx eax, ax
    mov  [rbx + r5i.phys_raw], eax
    mov  [rbx + r5i.obs_phys], rax      ; actual read only, retained raw
    cmp  eax, C25_PHY_UNKNOWN
    je   .unknown
    test ax, 0x0002
    jz   .out
    mov  byte [rbx + r5i.link_up], 1
    mov  edx, 10
    test ax, 0x0004
    jnz  .speed
    mov  edx, 100
    test ax, 0x0008
    jnz  .speed
    mov  edx, 1000
    test ax, 0x0010
    jnz  .speed
    mov  edx, 2500
    test ax, 0x0400
    jnz  .speed
    xor  edx, edx                      ; link with unknown speed stays unknown
.speed:
    mov  [rbx + r5i.link_speed], edx
.out:
    xor  eax, eax
    ret
.unavailable:
    mov  dword [rbx + r5i.phys_raw], -1
.unknown:
    mov  eax, -1
    ret

; link_status(self) -> RAX bit0 link + Mbps<<8, 0 offline, full -1 unknown.
rtl8125_link_status:
    push rbx
    call r5_self
    jz .refuse
    cmp byte [rel rtl8125_terminal_latched], 0
    jne .refuse
    mov al, 1
    xchg al, [rbx+r5i.tx_busy]
    test al, al
    jnz .refuse
    cmp byte [rel rtl8125_terminal_latched], 0
    jne .release_refuse
    call rtl8125_link_status_active
    mov byte [rbx+r5i.tx_busy], 0
    pop rbx
    ret
.release_refuse:
    mov byte [rbx+r5i.tx_busy], 0
.refuse:
    mov rax, -1
    pop rbx
    ret
rtl8125_link_status_active:
    push rbx
    call r5_self
    jz   .down
    cmp  byte [rbx + r5i.hw_ok], 1
    jne  .down
    call r5_lr_tick
    test eax, eax
    jnz .unknown
    call r5_link_refresh
    test eax, eax
    jnz  .unknown
    xor  eax, eax
    cmp  byte [rbx + r5i.link_up], 1
    jne  .out
    mov  eax, [rbx + r5i.link_speed]
    shl  eax, 8
    or   eax, 1
    jmp  .out
.unknown:
    mov  rax, -1                       ; consumers compare the full register
    mov  byte [rbx + r5i.link_up], 0    ; rearm refusal also invalidates cached status
    mov  dword [rbx + r5i.link_speed], 0
    jmp  .out
.down:
    xor  eax, eax
.out:
    pop  rbx
    ret

; RTL-DELTA-1: carrier_prepare(RDI=exact registered handle) -> EAX original
; 16-bit BMCR, or -1. Observes only: the PHY-OCP read command/selector store is
; the one MMIO write, never PHY configuration or data. A powered-down or
; isolated BMCR, unknown or offline link, or recovery in progress refuses.
rtl8125_carrier_prepare:
    push rbx
    call r5_self
    jz .refuse
    cmp byte [rel rtl8125_terminal_latched], 0
    jne .refuse
    mov al, 1
    xchg al, [rbx+r5i.tx_busy]
    test al, al
    jnz .refuse
    cmp byte [rel rtl8125_terminal_latched], 0
    jne .release_refuse
    call rtl8125_carrier_prepare_active
    mov byte [rbx+r5i.tx_busy], 0
    pop rbx
    ret
.release_refuse:
    mov byte [rbx+r5i.tx_busy], 0
.refuse:
    mov rax, -1
    pop rbx
    ret
rtl8125_carrier_prepare_active:
    push rbx
    call r5_self
    jz   .refuse
    cmp  byte [rbx + r5i.registered], 1
    jne  .refuse
    cmp  byte [rbx + r5i.hw_ok], 1
    jne  .refuse
    cmp  byte [rbx + r5i.rings_ok], 1
    jne  .refuse
    cmp  byte [rbx + r5i.recover_busy], 0
    jne  .refuse
    call r5_link_refresh
    test eax, eax
    jnz  .refuse                       ; unknown status admits nothing
    cmp  byte [rbx + r5i.link_up], 1
    jne  .refuse
    mov  edi, C25_BMCR_OCP
    call r5_phy_read
    jc   .refuse
    test eax, C25_BMCR_PDOWN | C25_BMCR_ISO
    jnz  .refuse                       ; also refuses an all-ones word
    pop  rbx
    ret
.refuse:
    mov  eax, -1
    pop  rbx
    ret

; RTL-DELTA-1/2/4: carrier_set(RDI=original registered handle, ESI=16-bit
; BMCR request) -> EAX 0 only after a valid bounded readback whose PDOWN bit
; equals the request's; -1 otherwise, and a later call may retry. Link need
; not be up (restore runs during the outage). Stages and raw returns are
; retained for carrier_observation; nothing here synthesizes link state.
rtl8125_carrier_set:
    push rbx
    call r5_self
    jz .refuse
    cmp byte [rel rtl8125_terminal_latched], 0
    jne .refuse
    mov al, 1
    xchg al, [rbx+r5i.tx_busy]
    test al, al
    jnz .refuse
    cmp byte [rel rtl8125_terminal_latched], 0
    jne .release_refuse
    call rtl8125_carrier_set_active
    mov byte [rbx+r5i.tx_busy], 0
    pop rbx
    ret
.release_refuse:
    mov byte [rbx+r5i.tx_busy], 0
.refuse:
    mov rax, -1
    pop rbx
    ret
rtl8125_carrier_set_active:
    push rbx
    push r12
    call r5_self
    jz   .refuse
    cmp  byte [rbx + r5i.registered], 1
    jne  .refuse
    cmp  byte [rbx + r5i.hw_ok], 1
    jne  .refuse
    cmp  byte [rbx + r5i.recover_busy], 0
    jne  .refuse
    test esi, 0xFFFF0000
    jnz  .refuse                       ; a BMCR word only, never an address
    mov  r12d, esi
    add  qword [rbx + r5i.obs_seq], 1
    sbb  qword [rbx + r5i.obs_seq], 0  ; saturates at UINT64_MAX
    mov  [rbx + r5i.obs_request], r12
    mov  qword [rbx + r5i.obs_write], -2
    mov  qword [rbx + r5i.obs_readback], -2
    mov  qword [rbx + r5i.obs_final], -2
    mov  qword [rbx + r5i.obs_stage], 1
    mov  edx, r12d
    mov  edi, C25_BMCR_OCP
    call r5_phy_write
    mov  [rbx + r5i.obs_write], rax    ; raw: 0 or 0xffffffff (MOV keeps CF)
    mov  qword [rbx + r5i.obs_stage], 2
    jc   .failed                       ; an acknowledgement is required first
    mov  edi, C25_BMCR_OCP
    call r5_phy_read
    mov  [rbx + r5i.obs_readback], rax ; raw word, or 0xffffffff timeout
    mov  qword [rbx + r5i.obs_stage], 3
    jc   .failed
    cmp  eax, C25_PHY_UNKNOWN
    je   .failed                       ; all-ones readback is not a BMCR
    xor  eax, r12d
    test eax, C25_BMCR_PDOWN
    jnz  .failed                       ; the persistent bit must have taken
    mov  qword [rbx + r5i.obs_stage], 4
    mov  qword [rbx + r5i.obs_final], 0
    xor  eax, eax
    jmp  .out
.failed:
    mov  qword [rbx + r5i.obs_final], -1
.refuse:
    mov  eax, -1
.out:
    pop  r12
    pop  rbx
    ret

; RTL-DELTA-4: carrier_observation(RDI=handle, RSI=eight qwords). Copies
; retained words only: no MMIO, PHY access, wait, lock or refresh. Order:
; valid, stage, request, write, readback, PHYstatus, sequence, final.
; A foreign or unregistered handle yields eight zero words.
rtl8125_carrier_observation:
    push rbx
    call r5_self
    jz   .none
    cmp  byte [rbx + r5i.registered], 1
    jne  .none
    mov  qword [rsi], 1
    xor  ecx, ecx
.copy:
    mov  rax, [rbx + r5i.obs_stage + rcx*8]
    mov  [rsi + 8 + rcx*8], rax
    inc  ecx
    cmp  ecx, 7
    jb   .copy
    pop  rbx
    ret
.none:
    xor  eax, eax
    xor  ecx, ecx
.zero:
    mov  [rsi + rcx*8], rax
    inc  ecx
    cmp  ecx, 8
    jb   .zero
    pop  rbx
    ret

rtl8125_get_mac:
    push rbx
    call r5_self
    jz   .bad
    mov  eax, [rbx + r5i.mac]
    mov  [rsi], eax
    mov  ax, [rbx + r5i.mac + 4]
    mov  [rsi + 4], ax
    xor  eax, eax
    pop  rbx
    ret
.bad:
    mov  rax, -1
    pop  rbx
    ret

; CLEANROOM ROUTINE R1: RBX=instance -> EAX 1 supported / 0 refused.
; Record observed revision in xid, choose rxcfg only for a supported revision.
; The hole refuses before enabling bus mastering, reset, allocation or registry.
r5_identify:
    mov  dword [rbx + r5i.xid], 0
    mov  dword [rbx + r5i.rxcfg], 0
    mov  esi, C25_TXCFG
    call r5_rd
    jc   .refuse
    and  eax, C25_REV_MASK
    mov  edx, eax
    shr  edx, 20
    mov  [rbx + r5i.xid], edx
    cmp  eax, C25_REV_A
    je   .family_a
    cmp  eax, C25_REV_B
    jne  .refuse
    mov  dword [rbx + r5i.rxcfg], C25_RX_B
    jmp  .supported
.family_a:
    mov  dword [rbx + r5i.rxcfg], C25_RX_A
.supported:
    mov  eax, 1
    ret
.refuse:
    xor  eax, eax
    ret

; CLEANROOM ROUTINE R2a: pre-reset hardware preparation, RBX=instance.
r5_hw_init:
    NATIVE_DRIVER_REFUSE 6
    ; Firmware-left PHY state; no tuning/firmware transplant. Reset below is
    ; independently sufficient for every recovery, not just initial probe.
    ret

; CLEANROOM ROUTINE R2b: bounded chip reset, RBX=instance -> EAX 0/-1.
r5_soft_reset:
    push r12
    mov  byte [rbx + r5i.rings_ok], 0
    mov  byte [rbx + r5i.hw_ok], 0
    mov  byte [rbx + r5i.link_up], 0
    mov  dword [rbx + r5i.link_speed], 0
    mov  esi, C25_MASK
    xor  edx, edx
    call r5_wr
    jc   .fail
    mov  esi, C25_ISR
    call r5_rd
    jc   .fail
    test eax, eax
    jz   .gate
    mov  edx, eax
    call r5_wr
    jc   .fail
.gate:
    mov  esi, C25_RXCFG
    mov  edx, 0x3F
    call r5_andn
    jc   .fail
    mov  esi, C25_RX_GATE
    mov  edx, 8
    call r5_byte_or
    jc   .fail
    ; Optional FIFO/STOPREQ drains and OOB exit omitted pending metal evidence.
    mov  esi, C25_COMMAND
    mov  edx, 0x10
    call r5_wr8
    jc   .fail
    mov  r12d, 100
.poll:
    mov  edi, 100
    call tsc_delay_us
    mov  esi, C25_COMMAND
    call r5_rd8
    jc   .fail
    test al, 0x10
    jz   .ready
    dec  r12d
    jnz  .poll
.fail:
    mov  eax, -1
    pop  r12
    ret
.ready:
    xor  eax, eax
    pop  r12
    ret

; CLEANROOM ROUTINE R3: station address, RBX=instance -> EAX 1 valid / 0.
; Store actual six observed bytes only. Never synthesize an identity.
r5_read_mac:
    mov  qword [rbx + r5i.mac], 0
    mov  esi, C25_MAC_LOW
    call r5_rd
    jc   .invalid
    mov  [rbx + r5i.mac], eax
    mov  esi, C25_MAC_HIGH
    call r5_rd
    jc   .invalid
    mov  [rbx + r5i.mac + 4], ax
    test byte [rbx + r5i.mac], 1
    jnz  .invalid
    mov  rax, [rbx + r5i.mac]
    test rax, rax
    jz   .invalid
    mov  eax, 1
    ret
.invalid:
    mov  qword [rbx + r5i.mac], 0
    xor  eax, eax
    ret

; CLEANROOM ROUTINE R4: program this instance's rings, RBX -> EAX 0/-1.
; Refusal must not publish rings_ok or register the instance.
r5_arm_rings:
    push r12
    mov  byte [rbx + r5i.rings_ok], 0
    mov  byte [rbx + r5i.hw_ok], 0
    mov  rdi, [rbx + r5i.tx_ring]
    mov  esi, R5_NUM_TX * R5_DESC_SIZE
    call r5_checked_allocation
    test eax, eax
    jz   .fail
    mov  rdi, [rbx + r5i.rx_ring]
    mov  esi, R5_NUM_RX * R5_DESC_SIZE
    call r5_checked_allocation
    test eax, eax
    jz   .fail
    mov  rdi, [rbx + r5i.tx_buffer]
    mov  esi, R5_TX_BUF
    call r5_checked_allocation
    test eax, eax
    jz   .fail
    mov  rdi, [rbx + r5i.rx_buffers]
    mov  esi, R5_NUM_RX * R5_RX_BUF
    call r5_checked_allocation
    test eax, eax
    jz   .fail
    mov  esi, C25_MASK
    xor  edx, edx
    call r5_wr
    jc   .fail
    mov  esi, C25_ISR
    call r5_rd
    jc   .fail
    test eax, eax
    jz   .descriptors
    mov  edx, eax
    call r5_wr
    jc   .fail
.descriptors:
    mov  rdi, [rbx + r5i.tx_ring]
    xor  eax, eax
    mov  ecx, R5_NUM_TX * R5_DESC_SIZE / 8
    cld
    rep  stosq
    mov  rax, [rbx + r5i.tx_ring]
    mov  dword [rax + (R5_NUM_TX-1)*R5_DESC_SIZE], C25_LAST
    mov  dword [rbx + r5i.tx_head], 0
    xor  r12d, r12d
.rx:
    mov  edi, r12d
    call r5_rx_post
    inc  r12d
    cmp  r12d, R5_NUM_RX
    jb   .rx
    mov  dword [rbx + r5i.rx_cursor], 0
    mov  esi, C25_UNLOCK
    mov  edx, 0xC0
    call r5_byte_or
    jc   .fail
    mov  esi, C25_TX_BASE
    mov  edx, [rbx + r5i.tx_ring]
    call r5_wr
    jc   .fail
    mov  esi, C25_TX_BASE + 4
    xor  edx, edx
    call r5_wr
    jc   .fail
    mov  esi, C25_RX_BASE
    mov  edx, [rbx + r5i.rx_ring]
    call r5_wr
    jc   .fail
    mov  esi, C25_RX_BASE + 4
    xor  edx, edx
    call r5_wr
    jc   .fail
    mov  edi, 0xEB58
    call r5_mac_read
    jc   .fail
    mov  edx, eax
    or   edx, 1
    mov  edi, 0xEB58
    call r5_mac_write
    jc   .fail
    mov  edi, 0xEB58
    call r5_mac_read
    jc   .fail
    test ax, 1
    jz   .fail
    mov  edx, [rbx + r5i.rxcfg]
    cmp  edx, C25_RX_A
    je   .filter
    cmp  edx, C25_RX_B
    jne  .fail
.filter:
    or   edx, 0x0A                       ; individual+broadcast only
    mov  esi, C25_RXCFG
    call r5_wr
    jc   .fail
    mov  esi, C25_TXCFG
    mov  edx, C25_TX_CONFIG
    call r5_wr
    jc   .fail
    mov  esi, C25_RSS                    ; [OB]740: no RSS
    xor  edx, edx
    call r5_wr8
    jc   .fail
    mov  esi, C25_RX_QUEUE
    call r5_rd16
    jc   .fail
    mov  edx, eax
    and  edx, ~0x001C                   ; [OB]742-743: one RX queue
    call r5_wr16
    jc   .fail
    mov  esi, C25_CPLUS
    call r5_rd16
    jc   .fail
    mov  edx, eax
    and  edx, ~0x0020                   ; [OH]194: no checksum offload
    call r5_wr16
    jc   .fail
    mov  esi, C25_RX_MAX
    mov  edx, 1522
    call r5_wr16
    jc   .fail
    mov  esi, C25_RX_GATE
    mov  edx, 8
    call r5_byte_andn
    jc   .fail
    mov  edi, 2000
    call tsc_delay_us
    mov  esi, C25_UNLOCK
    mov  edx, 0xC0
    call r5_byte_andn
    jc   .fail
    mov  edi, 10
    call tsc_delay_us
    mov  esi, C25_COMMAND
    mov  edx, 0x0C                     ; enable TX/RX last
    call r5_wr8
    jc   .fail
    mov  byte [rbx + r5i.hw_ok], 1
    mov  byte [rbx + r5i.rings_ok], 1
    xor  eax, eax
    pop  r12
    ret
.fail:
    mov  esi, C25_UNLOCK
    mov  edx, 0xC0
    call r5_byte_andn                    ; best-effort relock on every failure
    call r5_contain_dma                 ; usable flags off/BME off regardless
    mov  eax, -1
    pop  r12
    ret

r5_checked_allocation:
    test rdi, 0xFFF
    jnz  .bad
    jmp  r5_dma_range_ok
.bad:
    xor  eax, eax
    ret

; CLEANROOM ROUTINE R9: bounded PHY diagnostics/resume, RBX=instance.
; No-link path only; update diagnostics and optionally retry kept link wait.
; [OB]3527-3547: MAC OCP is a full-width command/data register.
; EDI=even MAC register, returns EAX=word, CF on HAL refusal.
r5_mac_read:
    mov  edx, edi
    shr  edx, 1
    shl  edx, 16
    mov  esi, C25_MAC_OCP
    call r5_wr
    jc   .out
    call r5_rd
    jc   .out
    movzx eax, ax
.out:
    ret

; EDI=even MAC register, EDX=word, CF on HAL refusal.
r5_mac_write:
    and  edx, 0xFFFF
    shr  edi, 1
    shl  edi, 16
    or   edx, edi
    or   edx, C25_OWN
    mov  esi, C25_MAC_OCP
    jmp  r5_wr

; [OB]3636-3669: PHY OCP read completes on BUSY set, write on clear.
; EDI=even PHY OCP register, EAX=word/0, CF=1 timeout/HAL refusal.
r5_phy_read:
    push r12
    mov  edx, edi
    shr  edx, 1
    shl  edx, 16
    mov  esi, C25_PHY_OCP
    call r5_wr
    jc   .fail
    mov  r12d, C25_PHY_POLLS
.poll:
    mov  edi, 1
    call tsc_delay_us
    mov  esi, C25_PHY_OCP
    call r5_rd
    jc   .fail
    test eax, C25_OWN
    jnz  .ready
    dec  r12d
    jnz  .poll
.fail:
    mov  eax, -1
    pop  r12
    stc
    ret
.ready:
    movzx eax, ax
    pop  r12
    clc
    ret

; EDI=even PHY register, EDX=word; EAX=0, CF=0 success.
r5_phy_write:
    push r12
    and  edx, 0xFFFF
    shr  edi, 1
    shl  edi, 16
    or   edx, edi
    or   edx, C25_OWN
    mov  esi, C25_PHY_OCP
    call r5_wr
    jc   .fail
    mov  r12d, C25_PHY_POLLS
.poll:
    mov  edi, 1
    call tsc_delay_us
    mov  esi, C25_PHY_OCP
    call r5_rd
    jc   .fail
    test eax, C25_OWN
    jz   .ready
    dec  r12d
    jnz  .poll
.fail:
    mov  eax, -1
    pop  r12
    stc
    ret
.ready:
    xor  eax, eax
    pop  r12
    clc
    ret

r5_no_link:
    mov  dword [rbx + r5i.bmcr], -1
    mov  byte [rbx + r5i.phy_kicked], 0
    mov  edi, C25_BMCR_OCP
    call r5_phy_read
    jc   .observe
    mov  [rbx + r5i.bmcr], eax
    cmp  eax, C25_PHY_UNKNOWN
    je   .observe                       ; RTL-DELTA-6: all-ones is not a BMCR to act on
    test ax, 0x0800                     ; [FM]50-57: powerdown only
    jz   .observe
    mov  edx, eax
    and  edx, ~0x0C00                   ; clear powerdown and isolate only
    or   edx, 0x1200                    ; enable/restart autonegotiation
    mov  edi, C25_BMCR_OCP
    call r5_phy_write
    jc   .write_timeout
    mov  byte [rbx + r5i.phy_kicked], 1
    call r5_link_wait                   ; only acknowledged kick gets retry
    jmp  .observe
.write_timeout:
    mov  byte [rbx + r5i.phy_kicked], 2
.observe:
    call r5_link_refresh
    ret

; recover(self=RDI) -> RAX 0 / -1. Reset, same-MAC identity, re-arm, link read.
rtl8125_recover:
    push rbx
    call r5_self
    jz .refuse
    cmp byte [rel rtl8125_terminal_latched], 0
    jne .refuse
    mov al, 1
    xchg al, [rbx+r5i.tx_busy]
    test al, al
    jnz .refuse
    cmp byte [rel rtl8125_terminal_latched], 0
    jne .release_refuse
    call rtl8125_recover_active
    mov byte [rbx+r5i.tx_busy], 0
    pop rbx
    ret
.release_refuse:
    mov byte [rbx+r5i.tx_busy], 0
.refuse:
    mov rax, -1
    pop rbx
    ret
rtl8125_recover_active:
    NATIVE_DRIVER_REFUSE 6
    push rbx
    call r5_self
    jz   .dead_noinst
    cmp  byte [rbx + r5i.recover_busy], 0
    jne  .dead_noinst
    mov  byte [rbx + r5i.recover_busy], 1
    lock inc qword [rbx + r5i.recover_attempts]
    cmp  byte [rbx + r5i.rings_ok], 1
    jne  .dead
    push qword [rbx + r5i.mac]
    call r5_soft_reset
    test eax, eax
    jnz  .dead_pop
    call r5_read_mac
    test eax, eax                       ; reject invalid result, even if cache matches
    jz   .dead_pop
    pop  rax
    cmp  eax, [rbx + r5i.mac]                    ; the identity must survive reset
    jne  .dead
    shr  rax, 32
    cmp  ax, [rbx + r5i.mac + 4]
    jne  .dead
    call r5_arm_rings
    test eax, eax
    jnz  .dead
    call r5_link_refresh
    mov  byte [rbx + r5i.recover_busy], 0
    xor  eax, eax
    pop  rbx
    ret
.dead_pop:
    pop  rax
.dead:
    call r5_contain_dma
    lock inc qword [rbx + r5i.recover_failures]
    mov  byte [rbx + r5i.recover_busy], 0
.dead_noinst:
    mov  rax, -1
    pop  rbx
    ret

; pci_scan_with_filter callback: record up to R5_MAX_SCAN 10ec:8125 BDFs.
rtl8125_discover_cb:
    cmp  ecx, R5_VENDEV
    jne  .ret
    A1_NATIVE_NIC_SKIP rdi,rsi,rdx,.ret
    mov  eax, [rel rtl8125_matches]
    inc  dword [rel rtl8125_matches]
    cmp  eax, R5_MAX_SCAN
    jae  .ret
    mov  r8d, edi
    shl  r8d, 16
    mov  r9d, esi
    shl  r9d, 8
    or   r8d, r9d
    or   r8d, edx
    lea  r9, [rel rtl8125_scan_bdf]
    mov  [r9 + rax*8], r8
.ret:
    ret

; r5_probe(RBX=inst, R12=bdf) — PCI enable, BAR2, XID gate, reset, MAC, link
;   wait. Sets .probed only for a supported, reset, valid-MAC function. Never
;   allocates DMA and never registers.
r5_probe:
    NATIVE_DRIVER_REFUSE 6
    push r12
    push r13
    push r14
    push r15
    mov  qword [rbx + r5i.obs_phys], -2   ; no PHYstatus read yet
    mov  [rbx + r5i.bdf], r12
    mov  r13, r12
    shr  r13, 16
    and  r13d, 0xFF                               ; bus
    mov  r14, r12
    shr  r14, 8
    and  r14d, 0xFF                               ; dev
    mov  r15, r12
    and  r15d, 0xFF                               ; fn
    mov  edi, r13d
    mov  esi, r14d
    mov  edx, r15d
    mov  ecx, 0x04
    call pci_cfg_read32
    and  eax, 0x0000FFFB                          ; BME off, preserve other Command bits
    or   eax, 0x02                                ; Memory Space only until identified
    mov  r8d, eax
    mov  edi, r13d
    mov  esi, r14d
    mov  edx, r15d
    mov  ecx, 0x04
    call pci_cfg_write32
    mov  edi, r13d
    mov  esi, r14d
    mov  edx, r15d
    mov  ecx, 0x18                                ; BAR2 = MMIO
    call pci_cfg_read32
    lea  rdi, [rel str_r5_why_io_bar]
    test al, 0x01
    jnz  .fail
    mov  r12d, eax
    and  r12d, 0xFFFFFFF0
    test al, 0x04
    jz   .bar_have
    mov  edi, r13d
    mov  esi, r14d
    mov  edx, r15d
    mov  ecx, 0x1C
    call pci_cfg_read32
    lea  rdi, [rel str_r5_why_bar_4g]
    test eax, eax
    jnz  .fail                                    ; base must be < 4 GiB
.bar_have:
    lea  rdi, [rel str_r5_why_bar_zero]
    test r12, r12
    jz   .fail
    mov  [rbx + r5i.region + HAL_R_BAR_BASE], r12
    mov  qword [rbx + r5i.region + HAL_R_BAR_SIZE], 0x10000
    call r5_identify
    test eax, eax
    jnz  .family_ok
    lea  rdi, [rel str_r5_unsupported]
    call serial_string
    mov  edi, [rbx + r5i.xid]
    call serial_hex64
    lea  rdi, [rel str_r5_unsupported_tail]
    call serial_string
    jmp  .out
.family_ok:
    mov  edi, r13d                                ; identified: now Bus Master too
    mov  esi, r14d
    mov  edx, r15d
    mov  ecx, 0x04
    call pci_cfg_read32
    and  eax, 0x0000FFFF                          ; do not echo PCI Status W1C bits
    or   eax, 0x04
    mov  r8d, eax
    mov  edi, r13d
    mov  esi, r14d
    mov  edx, r15d
    mov  ecx, 0x04
    call pci_cfg_write32
    call r5_hw_init
    call r5_soft_reset
    lea  rdi, [rel str_r5_why_reset]
    test eax, eax
    jnz  .fail_bm
    call r5_read_mac
    lea  rdi, [rel str_r5_why_mac]
    test eax, eax
    jz   .fail_bm
    mov  byte [rbx + r5i.hw_ok], 1
    call r5_link_wait
    cmp  byte [rbx + r5i.link_up], 1
    je   .probed
    call r5_no_link
    cmp  byte [rbx + r5i.link_up], 1
    je   .probed
    lea  rdi, [rel str_r5_nolink]
    call serial_string
    mov  rdi, [rbx + r5i.bdf]
    call serial_hex64
    lea  rdi, [rel str_r5_nolink_phys]
    call serial_string
    mov  edi, [rbx + r5i.phys_raw]
    call serial_hex64
    lea  rdi, [rel str_r5_nolink_bmcr]
    call serial_string
    mov  edi, [rbx + r5i.bmcr]
    call serial_hex64
    lea  rdi, [rel str_r5_nolink_kick]
    call serial_string
    movzx edi, byte [rbx + r5i.phy_kicked]
    call serial_hex64
    lea  rdi, [rel str_r5_nolink_ll]
    call serial_string
    movzx edi, byte [rbx + r5i.ll_timeout]
    call serial_hex64
    lea  rdi, [rel str_r5_nolink_tail]
    call serial_string
.probed:
    mov  byte [rbx + r5i.probed], 1
    jmp  .out
.fail_bm:                                         ; identified but unusable: stop DMA
    push rdi
    mov  edi, r13d
    mov  esi, r14d
    mov  edx, r15d
    mov  ecx, 0x04
    call pci_cfg_read32
    and  eax, 0x0000FFFB
    mov  r8d, eax
    mov  edi, r13d
    mov  esi, r14d
    mov  edx, r15d
    mov  ecx, 0x04
    call pci_cfg_write32
    pop  rdi
.fail:                                            ; RDI = reason string
    push rdi
    lea  rdi, [rel str_r5_probefail]
    call serial_string
    mov  rdi, [rbx + r5i.bdf]
    call serial_hex64
    lea  rdi, [rel str_r5_probefail_why]
    call serial_string
    pop  rdi
    call serial_string
    lea  rdi, [rel str_r5_probefail_tail]
    call serial_string
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    ret

; r5_link_wait(RBX) — bounded live PHY status poll, R5_LINK_WAIT_MS x 1 ms.
r5_link_wait:
    push r12
    mov  r12d, R5_LINK_WAIT_MS
.poll:
    call r5_link_refresh
    cmp  byte [rbx + r5i.link_up], 1
    je   .out
    mov  edi, 1000
    call tsc_delay_us
    dec  r12d
    jnz  .poll
.out:
    pop  r12
    ret

; Complete live DMA interval below 4 GiB, PaOS allocation invariant.
; RDI=address, RSI=bytes -> EAX 1/0. No chip access.
r5_dma_range_ok:
    test rdi, rdi
    jz   .bad
    test rsi, rsi
    jz   .bad
    mov  rax, rdi
    add  rax, rsi
    jc   .bad
    shr  rax, 32
    jnz  .bad
    call dma_iommu_lookup
    cmp  rax, rsi
    jb   .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; r5_alloc_one(RDI=bytes) -> RAX range-checked DMA address or 0.
r5_alloc_one:
    push rdi
    call dma_alloc
    pop  rsi
    test rax, rax
    jz   .out
    push rax
    mov  rdi, rax
    call r5_dma_range_ok
    mov  ecx, eax
    pop  rax
    test ecx, ecx
    jnz  .out
    xor  eax, eax
.out:
    ret

; r5_attach(RBX) — rings from the shared DMA pool, arm, register (DEGRADED
;   without link), marker. A pool exhaustion leaves this port unregistered.
r5_attach:
    mov  byte [rbx + r5i.attach_attempted], 1
    mov  edi, R5_NUM_TX * R5_DESC_SIZE
    call r5_alloc_one
    test rax, rax
    jz   .nodma
    mov  [rbx + r5i.tx_ring], rax
    mov  edi, R5_NUM_RX * R5_DESC_SIZE
    call r5_alloc_one
    test rax, rax
    jz   .nodma
    mov  [rbx + r5i.rx_ring], rax
    mov  edi, R5_TX_BUF
    call r5_alloc_one
    test rax, rax
    jz   .nodma
    mov  [rbx + r5i.tx_buffer], rax
    mov  edi, R5_NUM_RX * R5_RX_BUF
    call r5_alloc_one
    test rax, rax
    jz   .nodma
    mov  [rbx + r5i.rx_buffers], rax
    call r5_arm_rings
    test eax, eax
    jnz  .arm_failed
    mov  byte [rbx + r5i.rings_ok], 1
    lea  rax, [rel rtl8125_ops]
    mov  [rbx + r5i.dev + dev.ops], rax
    lea  rax, [rel rtl8125_info]
    mov  [rbx + r5i.dev + dev.info], rax
    mov  qword [rbx + r5i.dev + dev.priv], 0
    mov  dword [rbx + r5i.dev + dev.prio], PRIO_NATIVE
    mov  dword [rbx + r5i.dev + dev.class], CLASS_NET
    mov  dword [rbx + r5i.dev + dev.flags], 0     ; no fleet static address: DHCP
    lea  rax, [rel str_r5_name]
    mov  [rbx + r5i.dev + dev.name], rax
    lea  rdi, [rbx + r5i.dev]
    call netdev_register                          ; forces HEALTH_OK (netdev.asm:107)
    test rax, rax
    js   .register_failed
    ; PaOS owner policy: only a linked port stays healthy; an uncabled
    ; native port never wins egress over a working NIC.
    cmp  byte [rbx + r5i.link_up], 1
    je   .health_set
    mov  dword [rbx + r5i.dev + dev.health], HEALTH_DEGRADED
    or   dword [rbx + r5i.dev + dev.flags], NETDEV_F_LINK_WAIT   ; RCQ-10: link-only; reprobe promotes it
.health_set:
    mov  byte [rbx + r5i.registered], 1
    inc  dword [rel rtl8125_bound]
    lea  rdi, [rel str_r5_bound]
    call serial_string
    mov  edi, [rbx + r5i.xid]
    call serial_hex64
    lea  rdi, [rel str_r5_bound_bdf]
    call serial_string
    mov  rdi, [rbx + r5i.bdf]
    call serial_hex64
    lea  rdi, [rel str_r5_bound_link]
    call serial_string
    movzx edi, byte [rbx + r5i.link_up]
    call serial_hex64
    mov  edi, [rbx + r5i.link_speed]
    call serial_hex64
    lea  rdi, [rel str_r5_bound_tail]
    call serial_string
    jmp  .out
.arm_failed:
    ; r5_arm_rings already contained DMA; keep that decision final.
    lea  rdi, [rel str_r5_armfail]
    call serial_string
    mov  rdi, [rbx + r5i.bdf]
    call serial_hex64
    lea  rdi, [rel str_r5_armfail_tail]
    call serial_string
    jmp  .out
.register_failed:
    call r5_contain_dma
    jmp  .out
.nodma:
    call r5_contain_dma
    lea  rdi, [rel str_r5_nodma]
    call serial_string
.out:
    ret

; r5_ops_init — the vtable and info name are built with lea -> mov, like
;   the other PaOS backends, so the image carries no absolute label pointers.
r5_ops_init:
    NATIVE_DRIVER_REFUSE 6
    lea  rdi, [rel rtl8125_ops]
    lea  rax, [rel rtl8125_noop]
    mov  [rdi + netdev_ops.init], rax
    mov  [rdi + netdev_ops.start], rax
    mov  [rdi + netdev_ops.stop], rax
    lea  rax, [rel rtl8125_tx]
    mov  [rdi + netdev_ops.tx], rax
    lea  rax, [rel rtl8125_rx_poll]
    mov  [rdi + netdev_ops.rx_poll], rax
    lea  rax, [rel rtl8125_link_status]
    mov  [rdi + netdev_ops.link_status], rax
    lea  rax, [rel rtl8125_get_mac]
    mov  [rdi + netdev_ops.get_mac], rax
    lea  rax, [rel rtl8125_recover]
    mov  [rdi + netdev_ops.recover], rax
    lea  rax, [rel str_r5_name]
    mov  [rel rtl8125_info], rax
    ret

; U3b r5_release(RBX=inst): a probed port that no attach pass tried, because another
; port already registered. PaOS policy keeps one native RTL8125 so the other can be
; assigned to a guest. Rings were never armed and no DMA was allocated. Clear Bus Master
; Enable the same way .fail_bm does (other Command bits kept, Status W1C bits not echoed).
; Print one marker, then zero the slot so terminal quiesce and the inactive observation
; see an inactive slot. The caller marks it released, so no pci_claim is recorded.
; Preserves RBX, R12, R13.
r5_release:
    push rbx
    push r12
    push r13
    mov  eax, [rbx + r5i.bdf]
    mov  r13d, eax
    shr  r13d, 16
    and  r13d, 0xFF                      ; bus
    mov  r12d, eax
    shr  r12d, 8
    and  r12d, 0x1F                      ; device
    and  eax, 7
    push rax                             ; function
    sub  rsp, 8
    mov  edi, r13d
    mov  esi, r12d
    mov  edx, [rsp + 8]
    mov  ecx, 0x04
    call pci_cfg_read32
    and  eax, 0x0000FFFB
    mov  r8d, eax
    mov  edi, r13d
    mov  esi, r12d
    mov  edx, [rsp + 8]
    mov  ecx, 0x04
    call pci_cfg_write32
    add  rsp, 16
    lea  rdi, [rel str_r5_released]
    call serial_string
    mov  rdi, [rbx + r5i.bdf]
    call serial_hex64
    lea  rdi, [rel str_r5_released_tail]
    call serial_string
    mov  rdi, rbx
    mov  ecx, r5i_size
    xor  eax, eax
    cld
    rep  stosb
    pop  r13
    pop  r12
    pop  rbx
    ret

; Final PCI reporting for each bounded match, in discovery/probe order.
; Includes unsuccessful probes: their BDF was stored before the first effect.
; Preserves all general-purpose registers; pci_claim_packed16 does likewise.
r5_record_claims:
    push rax
    push rbx
    push rcx
    push rdi
    push r8
    push r12
    push r13
    mov  r13d, [rel rtl8125_matches]
    cmp  r13d, R5_MAX_INST
    jbe  .count_ready
    mov  r13d, R5_MAX_INST
.count_ready:
    xor  r12d, r12d
    lea  rbx, [rel rtl8125_inst]
.claim_loop:
    cmp  r12d, r13d
    jae  .out
    bt   dword [rel rtl8125_released_mask], r12d
    jc   .next                           ; U3b: released for passthrough, never claimed
    mov  edi, [rbx + r5i.bdf]
    mov  ecx, PCI_DRV_RTL8125
    mov  r8d, PCI_CLAIM_FAILED
    cmp  byte [rbx + r5i.registered], 1
    jne  .record
    mov  r8d, PCI_CLAIM_BOUND
.record:
    call pci_claim_packed16
.next:
    add  rbx, r5i_size
    inc  r12d
    jmp  .claim_loop
.out:
    pop  r13
    pop  r12
    pop  r8
    pop  rdi
    pop  rcx
    pop  rbx
    pop  rax
    ret

; ============================================================================
; rtl8125_hw_bringup — every target: absent -> one marker, nothing registered.
; ============================================================================
rtl8125_hw_bringup:
    PCIA_NATIVE_COLD_REFUSE                        ; no unattempted FAILED claim/slot reset
    cmp byte [rel rtl8125_terminal_latched], 0
    je .active_entry
    mov rax, -1
    ret
.active_entry:
    NATIVE_DRIVER_REFUSE 6
    push rbx
    push r12
    push r13
    call r5_ops_init
    mov  dword [rel rtl8125_matches], 0
    mov  dword [rel rtl8125_bound], 0
    mov  dword [rel rtl8125_released], 0
    mov  dword [rel rtl8125_released_mask], 0
    lea  rdi, [rel rtl8125_inst]
    mov  ecx, r5i_size * R5_MAX_INST
    xor  eax, eax
    cld
    rep  stosb
    lea  rdi, [rel rtl8125_discover_cb]
    call pci_scan_with_filter
    mov  r13d, [rel rtl8125_matches]
    test r13d, r13d
    jnz  .present
    lea  rdi, [rel str_r5_absent]
    call serial_string
    jmp  .done
.present:
    cmp  r13d, R5_MAX_INST
    jbe  .probe_all
    lea  rdi, [rel str_r5_extra]
    call serial_string
    mov  edi, r13d
    call serial_hex64
    call serial_newline
    mov  r13d, R5_MAX_INST
.probe_all:
    xor  r12d, r12d
.probe:
    cmp  r12d, r13d
    jae  .attach_linked
    imul ebx, r12d, r5i_size
    lea  rax, [rel rtl8125_inst]
    add  rbx, rax
    lea  rax, [rel rtl8125_scan_bdf]
    push r12
    mov  r12, [rax + r12*8]
    call r5_probe
    pop  r12
    inc  r12d
    jmp  .probe
.attach_linked:                                   ; pass 2a: linked ports first
    xor  r12d, r12d
.linked:
    cmp  r12d, r13d
    jae  .attach_rest
    imul ebx, r12d, r5i_size
    lea  rax, [rel rtl8125_inst]
    add  rbx, rax
    cmp  byte [rbx + r5i.probed], 1
    jne  .linked_next
    cmp  byte [rbx + r5i.link_up], 1
    jne  .linked_next
    cmp  dword [rel rtl8125_bound], 0     ; U3b: one native port; the rest stay free
    jne  .linked_next
    call r5_attach
.linked_next:
    inc  r12d
    jmp  .linked
.attach_rest:                                     ; pass 2b: never-attempted ports only
    ; Containment clears link_up: it must not reopen an attach decision.
    ; This flag resets with the instance at the next explicit bring-up.
    xor  r12d, r12d
.rest:
    cmp  r12d, r13d
    jae  .release_rest
    imul ebx, r12d, r5i_size
    lea  rax, [rel rtl8125_inst]
    add  rbx, rax
    cmp  byte [rbx + r5i.probed], 1
    jne  .rest_next
    cmp  byte [rbx + r5i.attach_attempted], 0
    jne  .rest_next
    cmp  dword [rel rtl8125_bound], 0
    jne  .rest_next
    call r5_attach
.rest_next:
    inc  r12d
    jmp  .rest
.release_rest:                                    ; U3b: release the never-attempted ports
    xor  r12d, r12d
.release:
    cmp  r12d, r13d
    jae  .done
    imul ebx, r12d, r5i_size
    lea  rax, [rel rtl8125_inst]
    add  rbx, rax
    cmp  byte [rbx + r5i.probed], 1
    jne  .release_next
    cmp  byte [rbx + r5i.attach_attempted], 0
    jne  .release_next
    call r5_release
    bts  dword [rel rtl8125_released_mask], r12d
    inc  dword [rel rtl8125_released]
.release_next:
    inc  r12d
    jmp  .release
.done:
    call r5_record_claims
    pop  r13
    pop  r12
    pop  rbx
    ret

; Terminal shutdown only. Trusted caller supplies 160 writable bytes, IF=0.
; Stack snapshots and current registry epochs are never serialized as pointers.
; No buffers, descriptors or mappings are released, even on complete shutdown.
rtl8125_terminal_quiesce:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 1088
    mov rbp, rsp
    mov r12, rdi
    xor eax, eax
    mov ecx, 40
    cld
    rep stosd
    mov dword [r12], 1
    mov dword [r12+32], -1            ; unvisited is never verified inactive
    mov dword [r12+96], -1
    mov dword [rbp+1040], 0           ; temporary held producer gates
    mov dword [rbp+1048], 0           ; verified applicable instances
    cmp byte [rel rtl8125_terminal_latched], 0
    jne .uncertain
    pushfq
    pop rax
    test eax, 0x200
    jnz .refuse
%ifdef PAOS_NIC_ASSIGNMENT
    call nic_assignment_owned
    test eax, eax
    jnz .refuse
%endif
    mov rdi, rbp
    call pci_claim_snapshot
    test edx, edx
    jnz .refuse
    cmp eax, 32
    ja .refuse
    mov [rbp+1044], eax
    mov [r12+20], eax
    cmp dword [rel rtl8125_matches], R5_MAX_INST
    ja .refuse
    cmp dword [rel rtl8125_bound], R5_MAX_INST
    ja .refuse
    xor r13d, r13d
    lea rbx, [rel rtl8125_inst]
    lea r15, [r12+32]
.preflight:
    mov dword [r15], -1
    cmp byte [rbx+r5i.registered], 1
    je .member
    ; An inactive slot must have no retained bind, DMA, hardware or class state.
    ; Passive operands for this original scan; no address or second scan.
    movzx eax, byte [rbx+r5i.registered]
    mov [r15+12], eax
    mov dword [r15+16], r5i_size
    mov eax, [rel rtl8125_matches]
    mov [r15+32], eax
    mov eax, [rel rtl8125_bound]
    mov [r15+36], eax
    mov eax, [rbp+1044]
    mov [r15+40], eax
    mov rdi, rbx
    mov ecx, r5i_size
    xor eax, eax
    repe scasb
    ; MOV/SETZ preserve the original ZF consumed by the following JNE.
    mov [r15+20], ecx
    setz byte [r15+24]
    mov dword [r15+8], (1 << 7) | (1 << 8)
    jne .refuse
    mov dword [r15], 0
    jmp .next
.member:
    cmp byte [rbx+r5i.hw_ok], 1
    jne .refuse
    cmp byte [rbx+r5i.rings_ok], 1
    jne .refuse
    cmp byte [rbx+r5i.recover_busy], 0
    jne .refuse
    mov al, 1
    xchg al, [rbx+r5i.tx_busy]
    test al, al
    jnz .refuse
    bts dword [rbp+1040], r13d
    mov rdi, [rbx+r5i.tx_ring]
    mov esi, R5_NUM_TX*R5_DESC_SIZE
    call r5_dma_range_ok
    cmp eax, 1
    jne .refuse
    mov rdi, [rbx+r5i.rx_ring]
    mov esi, R5_NUM_RX*R5_DESC_SIZE
    call r5_dma_range_ok
    cmp eax, 1
    jne .refuse
    mov rdi, [rbx+r5i.tx_buffer]
    mov esi, R5_TX_BUF
    call r5_dma_range_ok
    cmp eax, 1
    jne .refuse
    mov rdi, [rbx+r5i.rx_buffers]
    mov esi, R5_NUM_RX*R5_RX_BUF
    call r5_dma_range_ok
    cmp eax, 1
    jne .refuse
    mov edi, [rbx+r5i.bdf]
    test edi, 0xff00e0f8
    jnz .refuse
    mov [r15+12], edi
    xor r14d, r14d
    xor ecx, ecx
.claim:
    cmp ecx, [rbp+1044]
    jae .claim_done
    mov eax, ecx
    shl eax, 4
    add rax, rbp
    cmp [rax], edi
    jne .claim_next
    inc r14d
    cmp dword [rax+4], PCI_DRV_RTL8125
    jne .refuse
    cmp dword [rax+8], PCI_CLAIM_BOUND
    jne .refuse
    mov edx, [rax+12]
    test edx, edx
    jz .refuse
    mov [r15+16], edx
.claim_next:
    inc ecx
    jmp .claim
.claim_done:
    cmp r14d, 1
    jne .refuse
    or dword [r15+8], 1
    mov rdi, rbx
    lea rsi, [rel rtl8125_ops]
    call netdev_power_member
    test rax, rax
    jnz .registry
    mov rdi, rbx
    lea rsi, [rel rtl8125_ops]
    call netdev_link_wait_member
    test rax, rax
    jz .refuse
.registry:
    test rdx, rdx
    jz .refuse
    cmp rdx, -1
    je .refuse
    mov [rbp+1024+r13*8], rax
    mov [r15+20], rdx
    or dword [r15+8], 2
    mov ecx, 0
    call r5_terminal_cfg
    mov [r15+28], eax
    cmp eax, R5_VENDEV
    jne .refuse
    mov ecx, 4
    call r5_terminal_cfg
    cmp eax, -1
    je .refuse
    movzx eax, ax
    mov [r15+36], eax
    test eax, 2                        ; memory decoding required for HAL
    jz .refuse
    mov ecx, 0x18
    call r5_terminal_cfg
    test al, 1
    jnz .refuse
    mov edx, eax
    and edx, 0xfffffff0
    cmp rdx, [rbx+r5i.region]
    jne .refuse
    test edx, edx
    jz .refuse
    test al, 4
    jz .bar_ok
    mov ecx, 0x1c
    call r5_terminal_cfg
    test eax, eax
    jnz .refuse
.bar_ok:
    cmp qword [rbx+r5i.region+8], 0x10000
    jne .refuse
    or dword [r15+8], 4
    mov esi, C25_TXCFG
    call r5_rd
    jc .refuse
    mov [r15+32], eax
    and eax, C25_REV_MASK
    cmp eax, C25_REV_A
    je .revision
    cmp eax, C25_REV_B
    jne .refuse
.revision:
    shr eax, 20
    cmp eax, [rbx+r5i.xid]
    jne .refuse
    or dword [r15+8], 8
    ; Poll-mode is the only admitted native interrupt configuration.
    mov esi, C25_MASK
    call r5_rd
    jc .refuse
    test eax, eax
    jnz .refuse
    inc dword [rbp+1048]
.next:
    inc r13d
    add rbx, r5i_size
    add r15, 64
    cmp r13d, R5_MAX_INST
    jb .preflight
    ; Complete snapshot must contain exactly these RTL functions, no extras.
    xor ecx, ecx
    xor edx, edx
.count_claims:
    cmp ecx, [rbp+1044]
    jae .counted
    mov eax, ecx
    shl eax, 4
    cmp dword [rbp+rax+4], PCI_DRV_RTL8125
    jne .count_next
    inc edx
.count_next:
    inc ecx
    jmp .count_claims
.counted:
    cmp edx, [rbp+1048]
    jne .refuse
    cmp edx, [rel rtl8125_bound]
    jne .refuse
    mov eax, [rel rtl8125_matches]
    sub eax, [rel rtl8125_released]        ; U3b: released ports carry no claim
    cmp edx, eax
    jne .refuse
    mov [r12+8], edx
    ; Revalidate full claim census, including sequence, after all producer gates.
    lea rdi, [rbp+512]
    call pci_claim_snapshot
    test edx, edx
    jnz .refuse
    cmp eax, [rbp+1044]
    jne .refuse
    mov ecx, eax
    shl ecx, 1
    mov rsi, rbp
    lea rdi, [rbp+512]
    repe cmpsq
    jne .refuse
    cmp dword [rbp+1048], 0
    je .inactive
    xor r13d, r13d
    lea r15, [r12+32]
.epochs:
    bt dword [rbp+1040], r13d
    jnc .epoch_next
    mov rax, [rbp+1024+r13*8]
    mov rdx, [r15+20]
    cmp [rax], rdx
    jne .refuse
.epoch_next:
    inc r13d
    add r15, 64
    cmp r13d, R5_MAX_INST
    jb .epochs
    ; Irreversible boot-local latch. Every hardware producer takes the same gate.
    mov al, 1
    xchg al, [rel rtl8125_terminal_latched]
    test al, al
    jnz .uncertain
    xor r13d, r13d
    lea rbx, [rel rtl8125_inst]
    lea r15, [r12+32]
.effects:
    bt dword [rbp+1040], r13d
    jnc .effect_next
    mov dword [r15], -2
    mov dword [r15+4], 1
    call r5_terminal_effect
    cmp eax, 1
    jne .uncertain
    mov dword [r15], 1
    inc dword [r12+12]
.effect_next:
    inc r13d
    add rbx, r5i_size
    add r15, 64
    cmp r13d, R5_MAX_INST
    jb .effects
    mov eax, 1
    jmp .out
.inactive:
    xor eax, eax
    jmp .out
.refuse:
    ; No latch or device write has occurred. Release only our temporary gates.
    xor r13d, r13d
    lea rbx, [rel rtl8125_inst]
.release:
    bt dword [rbp+1040], r13d
    jnc .released
    mov byte [rbx+r5i.tx_busy], 0
.released:
    inc r13d
    add rbx, r5i_size
    cmp r13d, R5_MAX_INST
    jb .release
    mov eax, -1
    mov dword [r12+16], 1
    jmp .out
.uncertain:
    mov eax, -2
    mov dword [r12+16], 2
.out:
    mov [r12+4], eax
    add rsp, 1088
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; RBX exact admitted instance, ECX configuration offset. Preserve nonvolatiles.
r5_terminal_cfg:
    mov rdi, [rbx+r5i.bdf]
    mov edx, edi
    and edx, 7
    mov esi, edi
    shr esi, 8
    and esi, 31
    shr edi, 16
    and edi, 255
    jmp pci_cfg_read32

; Trusted effect after all producer gates + latch. Exact-width HAL CF checked.
; OpenBSD pinned rge_reset reset completion: 100 polls, 100us each. Omitted
; optional FIFO drains are not claimed; terminal reset+CR/IMR+own-function BME
; readbacks are required and descriptor memory remains pinned unconditionally.
r5_terminal_effect:
    mov esi, C25_MASK
    xor edx, edx
    call r5_wr
    jc .failed
    mov esi, C25_RXCFG
    mov edx, 0x3f
    call r5_andn
    jc .failed
    mov esi, C25_RX_GATE
    mov edx, 8
    call r5_byte_or
    jc .failed
    mov esi, C25_COMMAND
    mov edx, 0x10
    call r5_wr8
    jc .failed
    mov dword [r15+4], 2
    mov r14d, 100
.poll:
    mov edi, 100
    call tsc_delay_us
    inc dword [r15+52]
    mov esi, C25_COMMAND
    call r5_rd8
    jc .failed
    mov [r15+48], eax
    or dword [r15+8], 16
    test al, 0x10
    jz .reset
    dec r14d
    jnz .poll
    jmp .failed
.reset:
    test al, 0x0c
    jnz .failed
    mov dword [r15+4], 3
    mov esi, C25_MASK
    xor edx, edx
    call r5_wr
    jc .failed
    mov esi, C25_MASK
    call r5_rd
    jc .failed
    mov [r15+44], eax
    or dword [r15+8], 32
    test eax, eax
    jnz .failed
    mov dword [r15+4], 4
    mov ecx, 4
    call r5_terminal_cfg
    cmp eax, -1
    je .failed
    and eax, 0xfffb
    mov r8d, eax
    ; PCI status is W1C: high16 remain zero, only own function Command changes.
    mov rdi, [rbx+r5i.bdf]
    mov edx, edi
    and edx, 7
    mov esi, edi
    shr esi, 8
    and esi, 31
    shr edi, 16
    and edi, 255
    mov ecx, 4
    call pci_cfg_write32
    mov ecx, 4
    call r5_terminal_cfg
    cmp eax, -1
    je .failed
    movzx eax, ax
    mov [r15+40], eax
    or dword [r15+8], 64
    test eax, 4
    jnz .failed
    mov dword [r15+4], 5
    mov eax, 1
    ret
.failed:
    mov dword [r15+56], 2
    mov eax, -2
    ret

; --- rtl8125 data (in-image writable) ---------------------------------------------
align 8
rtl8125_inst:      times r5i_size * R5_MAX_INST db 0
rtl8125_scan_bdf:  times R5_MAX_SCAN dq 0
rtl8125_ops:       times netdev_ops_size db 0     ; filled at runtime (no image-absolute pointers)
rtl8125_terminal_latched: db 0
align 4
rtl8125_matches:   dd 0
rtl8125_bound:     dd 0
rtl8125_released:  dd 0                    ; U3b: probed ports left free for passthrough
rtl8125_released_mask: dd 0               ; bit i = instance slot i released
align 8
rtl8125_info:
    dq 0                               ; name: filled at runtime
    dd 1500
    db 64
    dd 0
    dd 0
str_r5_name:       db "rtl8125", 0
str_r5_absent:     db "[PAOS64] L2 netdev: RTL8125 (10ec:8125) not present -> not registered [netdev.rtl8125.absent]", 13, 10, 0
str_r5_unsupported: db "[PAOS64] L2 netdev: RTL8125 unsupported chip -> not registered xid=", 0
str_r5_unsupported_tail: db " [netdev.rtl8125.unsupported]", 13, 10, 0
str_r5_extra:      db "[PAOS64] L2 netdev: RTL8125 more functions than instances; bound the first 2, total=", 0
str_r5_armfail:    db "[PAOS64] L2 netdev: RTL8125 ring setup refused -> not registered bdf=", 0
str_r5_armfail_tail: db " [netdev.rtl8125.rings_fail]", 13, 10, 0
str_r5_nodma:      db "[PAOS64] L2 netdev: RTL8125 DMA pool exhausted -> port not registered [netdev.rtl8125.nodma]", 13, 10, 0
str_r5_bound:      db "[PAOS64] L2 netdev: RTL8125 bound xid=", 0
str_r5_bound_bdf:  db " bdf=", 0
str_r5_bound_link: db " link,speed=", 0
str_r5_bound_tail: db " [netdev.rtl8125.bound]", 13, 10, 0
str_r5_nolink:     db "[PAOS64] L2 netdev: RTL8125 no link bdf=", 0
str_r5_nolink_phys: db " phystatus=", 0
str_r5_nolink_bmcr: db " bmcr=", 0
str_r5_nolink_kick: db " pdown_cleared=", 0      ; PaOS diagnostic codes: 0 none, 1 acknowledged, 2 timeout
str_r5_nolink_ll:  db " ll_rdy_timeout=", 0
str_r5_nolink_tail: db " [netdev.rtl8125.nolink]", 13, 10, 0
str_r5_released:   db "[PAOS64] L2 netdev: RTL8125 left unclaimed for device assignment bdf=", 0
str_r5_released_tail: db " [netdev.rtl8125.released]", 13, 10, 0
str_r5_probefail:  db "[PAOS64] L2 netdev: RTL8125 probe refused -> not registered bdf=", 0
str_r5_probefail_why: db " reason=", 0
str_r5_probefail_tail: db " [netdev.rtl8125.probe_fail]", 13, 10, 0
str_r5_why_io_bar: db "io_bar", 0
str_r5_why_bar_4g: db "bar_above_4g", 0
str_r5_why_bar_zero: db "bar_zero", 0
str_r5_why_reset:  db "reset_timeout", 0
str_r5_why_mac:    db "bad_mac", 0

; Ordinary link maintenance, called only while this instance's producer gate
; is held. No ring/bounce allocation and no descriptor mutation before reset.
r5_lr_tick:
    NATIVE_DRIVER_REFUSE 6
    lea rax, [rbx+r5i.link_rearm]
    REALTEK_LINK_REARM_BODY r5
r5_lr_sample:
    cmp byte [rbx+r5i.rings_ok], 1
    jne .bad
    cmp qword [rbx+r5i.tx_ring], 0
    je .bad
    mov esi, C25_PHY_STATUS
    call r5_rd16
    jc .bad
    movzx eax, ax
    mov [rbx+r5i.phys_raw], eax
    mov [rbx+r5i.obs_phys], rax    ; retain every actual read, including unavailable 0xffff
    mov edx, eax                   ; raw PHY status for the diagnostic record
    cmp eax, 0xffff
    je .bad
    shr eax, 1
    and eax, 1
    ret
.bad:
    mov edx, REALTEK_LR_UNREAD
    mov rax, -1
    ret
r5_lr_cmd:
    mov esi, 52                    ; command byte is bits 31:24 of dword 0x34
    call r5_rd
    jc .bad
    shr eax, 24
    ret
.bad:
    mov eax, REALTEK_LR_UNREAD
    ret
r5_lr_own:
    mov r8, [rbx+r5i.tx_ring]
    xor eax, eax
    xor ecx, ecx
.loop:
    clflush [r8]
    mfence
    test dword [r8], C25_OWN
    jz .next
    bts eax, ecx
.next:
    add r8, R5_DESC_SIZE
    inc ecx
    cmp ecx, R5_NUM_TX
    jb .loop
    ret
r5_lr_phy_read:
    call r5_phy_read
    jc .bad
    ret
.bad:
    mov rax, -1
    ret
r5_lr_phy_write:
    call r5_phy_write
    jc .bad
    xor eax, eax
    ret
.bad:
    mov rax, -1
    ret
r5_lr_advertise:
    xor eax, eax                 ; retain this port's existing advertisement
    ret
r5_lr_wake:
    REALTEK_PHY_WAKE_BODY r5
r5_lr_ready:
    REALTEK_PHY_READY_BODY r5
r5_lr_reset:
    mov rdi, rbx
    jmp rtl8125_recover_active
r5_lr_close:
    jmp r5_contain_dma

; Read-only aggregate over the two independently admitted ports. Five qwords:
; down/up/rearmed/stuckOWN/failures. Diagnostic counts, not atomic proof.
; Once either port's tick has run, each port then adds its own ten-qword
; record (port 0, then port 1): phase, saved OWN, live OWN, PHY status, BMCR,
; BMSR, CMD, TX timeouts, rx_poll calls, ticks. EAX = qwords (5 or 25).
rtl8125_link_rearm_counts:
    lea r8, [rel rtl8125_inst+r5i.link_rearm+16]
    lea r9, [r8+r5i_size]
    xor ecx, ecx
.copy:
    mov rax, [r8+rcx*8]
    add rax, [r9+rcx*8]
    mov [rdi+rcx*8], rax
    inc ecx
    cmp ecx, 5
    jb .copy
    mov eax, 5
    lea r10, [rel rtl8125_inst]
    mov rcx, [r10+r5i.link_rearm+REALTEK_LR_TICKS]
    or rcx, [r10+r5i_size+r5i.link_rearm+REALTEK_LR_TICKS]
    jz .out                          ; never driven: the legacy five-count tuple
    lea r9, [rdi+40]
    xor ecx, ecx
.port:
    lea r8, [r10+r5i.link_rearm]
    REALTEK_LR_RECORD
    mov rax, [r10+r5i.tx_timeouts]
    mov [r9+56], rax
    mov rax, [r10+r5i.rx_poll_calls]
    mov [r9+64], rax
    add r9, 80
    add r10, r5i_size
    inc ecx
    cmp ecx, R5_MAX_INST
    jb .port
    mov eax, 25
.out:
    ret
