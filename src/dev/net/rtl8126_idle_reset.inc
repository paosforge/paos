; Ordinary link up-edge recovery, one bounded protocol step per BSP idle turn.
; The boot/explicit-recover protocol remains synchronous. This owner retains
; scalar cursors into immutable tables only; no stack, DMA descriptor pointer,
; producer gate or transport call survives a return to the command loop.
;
; Carrier recovery preserves the already negotiated PHY and firmware. Only
; the MAC is reset and the existing rings rebuilt; boot/explicit recovery
; retains its full PHY initialization. Optional observations remain optional; mandatory
; CMD reset, exact identity, terminal ownership and final TE|RE stay fatal.
; No link-up credit comes from a timer: phase 3 uses the ordinary live PHY and
; BMSR completion checks. There is no synchronous negotiation wait here.

r26_job_begin:
    cmp byte [rel e5000b_recover_busy],0
    jne .bad
    mov byte [rel e5000b_recover_busy],1
    lock inc qword [rel e5000b_recover_attempts]
    mov byte [rel e5000b_rings_ok],0
    mov byte [rel e5000b_link_up],0
    mov qword [rel r26_job_pc],0
    mov qword [rel r26_job_cursor],0
    mov qword [rel r26_job_deadline],0
    mov qword [rel r26_job_words],0
    mov byte [rel r26_job_patch_phase],0
    mov byte [rel r26_job_phy_failed],0
    mov byte [rel r26_job_boundary],0
    mov byte [rel r26_job_ups_active],0
    ; Bind the continuation to the exact existing instance and DMA allocation.
    lea rsi,[rel r26_job_identity_fields]
    lea rdi,[rel r26_job_identity]
    lea rdx,[rel r26_job_identity_fields]
    mov ecx,8
.capture:
    movsxd rax,dword [rsi]
    add rax,rdx
    mov rax,[rax]
    mov [rdi],rax
    add rsi,4
    add rdi,8
    loop .capture
    mov eax,[rel e5000b_mac]
    mov [rel r26_job_mac],eax
    mov ax,[rel e5000b_mac+4]
    mov [rel r26_job_mac+4],ax
    mov byte [rel r26_job_active],1
    mov qword [rel rtl8126_link_rearm_state],5
    mov eax,1                       ; pending, never successful rearm
    ret
.bad:
    mov rax,-1
    ret

; The boot idle loop is the sole progress caller. Public TX/RX/link calls
; refuse while pending; they cannot concatenate firmware slices inside UDP.
rtl8126_recovery_poll:
    R26_TERMINAL_PRODUCER r26_job_poll
r26_job_poll:
    pushfq
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    cmp byte [rel r26_job_active],0
    je .out
    cmp byte [rel e5000b_hw_ok],1
    jne .fail
    cmp byte [rel e5000b_mac_ok],1
    jne .fail
    cmp byte [rel e5000b_recover_busy],1
    jne .fail
%ifdef PAOS_NATIVE_DRIVER_POLICY_LINKED
    mov edi,6
    mov rsi,-1
    call native_driver_gate
    jc .fail
%endif
    lea rsi,[rel r26_job_identity_fields]
    lea rdi,[rel r26_job_identity]
    lea rdx,[rel r26_job_identity_fields]
    mov ecx,8
.identity:
    movsxd rax,dword [rsi]
    add rax,rdx
    mov rax,[rax]
    cmp rax,[rdi]
    jne .fail
    add rsi,4
    add rdi,8
    loop .identity
    mov eax,[rel e5000b_mac]
    cmp eax,[rel r26_job_mac]
    jne .fail
    mov ax,[rel e5000b_mac+4]
    cmp ax,[rel r26_job_mac+4]
    jne .fail
    call time_monotonic_now_us
    mov [rel r26_job_now],rax
    mov rax,[rel r26_job_pc]
    cmp rax,(r26_job_program_end-r26_job_program)/16
    jae .fail
    shl rax,4
    lea rbx,[rel r26_job_program]
    ; Both pointers are signed deltas from the runtime program anchor.
    ; Immediate arguments (zero, patch flag and delays) remain numbers.
    movsxd rdx,dword [rbx+rax]
    add rdx,rbx
    movsxd rdi,dword [rbx+rax+4]
    cmp dword [rbx+rax+8],0
    je .dispatch
    add rdi,rbx
.dispatch:
    call rdx
    cmp eax,-1
    je .fail
    test eax,eax
    jnz .out
    inc qword [rel r26_job_pc]
    mov qword [rel r26_job_cursor],0
    mov qword [rel r26_job_deadline],0
    jmp .out
.fail:
    mov byte [rel r26_job_active],0
    mov byte [rel e5000b_recover_busy],0
    mov byte [rel e5000b_rings_ok],0
    mov byte [rel e5000b_link_up],0
    mov qword [rel rtl8126_link_rearm_state],4
    inc qword [rel rtl8126_link_rearm_state+48]
    lock inc qword [rel e5000b_recover_failures]
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    popfq
    ret

; Handler return: 0 step complete, 1 unfinished, -1 mandatory failure.
r26_job_table:
    ; RDI is an immutable protocol table, RSI optional revision-two table.
    add rdi,[rel r26_job_cursor]
    cmp dword [rdi],0
    je r26_job_done
    ; Revision-one tuning contains two more patch handshakes. They share
    ; the same idle continuation as the firmware boundaries; the boot table
    ; interpreter's thousand-read ACK loop must never run from this owner.
    cmp dword [rdi],6
    jne .entry
    mov edi,[rdi+12]
    call r26_job_patch
    cmp eax,1
    je r26_job_pending
    ; Optional handshake failure was recorded by r26_job_patch. As in the
    ; original tuning table, it does not discard the following independent rows.
    jmp .advance
.entry:
    call r26_run_table_entry
.advance:
    add qword [rel r26_job_cursor],16
r26_job_pending:
    mov eax,1
    ret
r26_job_done:
    xor eax,eax
    ret

r26_job_init:
    call r26_trace_init
    mov byte [rel e5000b_drain_expired],0
    mov byte [rel e5000b_bmcr_valid],0
    mov word [rel e5000b_bmcr_before],0
    mov word [rel e5000b_bmcr_after],0
    mov word [rel e5000b_phy_state],0
    mov byte [rel e5000b_reset_phase],1
    xor eax,eax
    ret
r26_job_header:
    mov esi,0x40
    call e5b_rd
    and eax,0x7cf00000
    mov [rel r26_attach_trace+20],eax
    mov byte [rel r26_revision],1
    cmp eax,0x64a00000
    jne .read
    mov byte [rel r26_revision],2
.read:
    mov esi,0xa400
    call e5b_phy_read
    test eax,eax
    js .done
    mov [rel e5000b_bmcr_before],ax
    or byte [rel e5000b_bmcr_valid],1
.done:
    xor eax,eax
    ret

r26_job_dump:
    lea r12,[rel r26_dump_list]
    add r12,[rel r26_job_cursor]
    mov edi,[r12]
    test edi,edi
    jz r26_job_done
    mov esi,[r12+4]
    cmp edi,1
    je .mmio
    cmp edi,2
    je .mac
    call e5b_phy_read
    jmp .record
.mac:
    call e5b_mac_read
    jmp .record
.mmio:
    call e5b_rd
.record:
    mov edi,[r12]
    mov esi,[r12+4]
    xor edx,edx
    cmp edi,3
    jne .save
    test eax,eax
    jns .save
    mov edx,2
.save:
    call r26_record
    add qword [rel r26_job_cursor],8
    jmp r26_job_pending

; Wait descriptor: register, mask, wanted, timeout-us, trace-kind, flags.
; One current read per turn; no delay loop and no poll-count deadline extension.
; flags bit0 PHY, bit1 mandatory, bit2 PHY-reset trace, bit3 state validity,
; bit4 FIFO-expiry, bit5 queue-expiry, bit6 skip when UPS is clear.
r26_job_wait:
    mov r12,rdi
    test dword [r12+20],64
    jz .deadline
    cmp byte [rel r26_job_ups_active],0
    je r26_job_done
.deadline:
    cmp qword [rel r26_job_deadline],0
    jne .read
    mov eax,[r12+12]
    add rax,[rel r26_job_now]
    mov [rel r26_job_deadline],rax
.read:
    mov esi,[r12]
    test dword [r12+20],1
    jz .mmio
    call e5b_phy_read
    jmp .sample
.mmio:
    call e5b_rd
.sample:
    mov r13d,eax
    test dword [r12+20],1
    jz .compare
    test eax,eax
    js .expired
.compare:
    and eax,[r12+4]
    cmp eax,[r12+8]
    je .ok
    mov rax,[rel r26_job_now]
    cmp rax,[rel r26_job_deadline]
    jb r26_job_pending
.expired:
    mov edx,2
    test dword [r12+20],4
    jz .fifo
    inc dword [rel r26_attach_trace+52]
.fifo:
    test dword [r12+20],16
    jz .queue
    or byte [rel e5000b_drain_expired],1
.queue:
    test dword [r12+20],32
    jz .record
    or byte [rel e5000b_drain_expired],2
    jmp .record
.ok:
    xor edx,edx
.record:
    test dword [r12+20],8
    jz .trace
    and byte [rel e5000b_bmcr_valid],0xfb
    mov word [rel e5000b_phy_state],0
    test r13d,r13d
    js .trace
    mov [rel e5000b_phy_state],r13w
    or byte [rel e5000b_bmcr_valid],4
.trace:
    mov eax,r13d
    mov edi,[r12+16]
    mov esi,[r12]
    call r26_record
    test edx,edx
    jz r26_job_done
    test dword [r12+20],2
    jz r26_job_done
    lock inc qword [rel e5000b_recover_timeouts]
    mov dword [rel r26_attach_trace+16],1
    ; Same first-reset failure observation as full_reset: a PHY power-up
    ; attempt is not claimed until the power table has actually begun.
    test byte [rel e5000b_bmcr_valid],0x80
    jnz .fatal_observed
    mov byte [rel e5000b_bmcr_valid],0
    mov word [rel e5000b_bmcr_before],0
    mov word [rel e5000b_bmcr_after],0
    mov word [rel e5000b_phy_state],0
.fatal_observed:
    mov rax,-1
    ret

r26_job_reset_start:
    mov esi,R26_RXCFG
    mov edx,R26_RX_ACCEPT
    call e5b_andn
    mov esi,R26_PPSW_DWORD
    mov edx,R26_RX_GATE
    call e5b_or
    mov esi,R26_IMR
    xor edx,edx
    call e5b_wr
    call e5000b_isr_ack
    mov esi,R26_CMD_DWORD
    call e5b_rd
    and eax,0x00ffffff
    mov edx,eax
    or edx,R26_RESET
    call e5b_wr
    mov byte [rel e5000b_reset_phase],4
    xor eax,eax
    ret
r26_job_ups:
    mov esi,0xd42c
    call e5b_mac_read
    mov edi,2
    mov esi,0xd42c
    xor edx,edx
    call r26_record
    test eax,0x100
    setnz byte [rel r26_job_ups_active]
    xor eax,eax
    ret
r26_job_ups_table:
    cmp byte [rel r26_job_ups_active],0
    je r26_job_done
    jmp r26_job_table
r26_job_power:
    or byte [rel e5000b_bmcr_valid],0x80
    jmp r26_job_table

; At most eight firmware transactions per turn (bounded OCP per transaction).
r26_job_mac_data:
    lea r12,[rel r26_mac_ucode_1]
    lea r13,[rel r26_mac_ucode_1_end]
    cmp byte [rel r26_revision],2
    jne .selected
    lea r12,[rel r26_mac_ucode_2]
    lea r13,[rel r26_mac_ucode_2_end]
.selected:
    mov r14,[rel r26_job_cursor]
    add r12,r14
    mov ebx,4
.word:
    cmp r12,r13
    jae .finish
    cmp r14,256*4
    jne .write
    cmp byte [rel r26_revision],2
    jne .write
    lea rdi,[rel r26_mac_page1]
    call r26_run_table_entry
.write:
    movzx esi,word [r12]
    movzx edx,word [r12+2]
    call e5b_mac_write
    movzx esi,word [r12]
    call e5b_mac_read
    cmp ax,[r12+2]
    je .next
    inc dword [rel r26_attach_trace+48]
    cmp dword [rel r26_attach_trace+60],0
    jne .next
    mov [rel r26_attach_trace+56],eax
    movzx eax,word [r12]
    mov [rel r26_attach_trace+60],eax
.next:
    add r12,4
    add r14,4
    mov [rel r26_job_cursor],r14
    dec ebx
    jnz .word
    jmp r26_job_pending
.finish:
    shr r14,2
    mov [rel r26_attach_trace+24],r14d
    mov eax,r14d
    mov edi,8
    xor esi,esi
    xor edx,edx
    cmp dword [rel r26_attach_trace+48],0
    je .record
    mov edx,1
.record:
    call r26_record
    xor eax,eax
    ret
r26_job_mac_enable:
    lea rdi,[rel r26_mac_enable_1]
    cmp byte [rel r26_revision],2
    jne .selected
    lea rdi,[rel r26_mac_enable_2]
.selected:
    jmp r26_job_table
r26_job_mac_version:
    lea r12,[rel r26_mac_ucode_1_end-16]
    cmp byte [rel r26_revision],2
    jne .selected
    lea r12,[rel r26_mac_ucode_2_end-16]
.selected:
    mov r13,[rel r26_job_cursor]
    cmp r13,16
    jae r26_job_done
    add r12,r13
    shr r13d,1
    lea esi,[r13+0xf9f8]
    movzx edx,word [r12+2]
    call e5b_mac_write
    lea esi,[r13+0xf9f8]
    call e5b_mac_read
    xor edx,edx
    cmp ax,[r12+2]
    je .record
    mov edx,1
.record:
    mov edi,2
    lea esi,[r13+0xf9f8]
    call r26_record
    add qword [rel r26_job_cursor],4
    jmp r26_job_pending

; Patch acknowledgement is polled, never a thousand-read loop. The request
; bit is written once. Each boundary is completely unwound before another turn.
r26_job_patch:
    mov r14d,edi
    cmp byte [rel r26_job_patch_phase],0
    jne .poll
    mov esi,0xb820
    call e5b_phy_read
    test eax,eax
    js .bad
    and eax,0xffef
    test r14d,r14d
    jz .write
    or eax,0x10
.write:
    mov edx,eax
    mov esi,0xb820
    call e5b_phy_write
    test eax,eax
    jnz .bad
    mov rax,[rel r26_job_now]
    add rax,100000
    mov [rel r26_job_patch_deadline],rax
    mov byte [rel r26_job_patch_phase],1
    jmp r26_job_pending
.poll:
    mov esi,0xb800
    call e5b_phy_read
    test eax,eax
    js .bad
    mov edx,eax
    and edx,0x40
    test r14d,r14d
    jz .off
    cmp edx,0x40
    je .ok
    jmp .wait
.off:
    test edx,edx
    jz .ok
.wait:
    mov rdx,[rel r26_job_now]
    cmp rdx,[rel r26_job_patch_deadline]
    jb r26_job_pending
.bad:
    mov edx,2
    jmp .record
.ok:
    xor edx,edx
.record:
    mov byte [rel r26_job_patch_phase],0
    mov edi,6
    mov esi,0xb820
    call r26_record
    test edx,edx
    jz r26_job_done
    mov rax,-1
    ret
r26_job_patch_optional:
    call r26_job_patch
    cmp eax,-1
    jne .out
    cmp byte [rel r26_job_phy_failed],0
    jne .recorded
    inc dword [rel r26_attach_trace+32]
.recorded:
    mov byte [rel r26_job_phy_failed],1
    xor eax,eax
.out:
    ret
r26_job_patch_finish:
    ; The original final patch-off observation does not erase a completed
    ; stream or prevent its version publication on an optional ACK timeout.
    xor edi,edi
    call r26_job_patch
    cmp eax,-1
    jne .out
    xor eax,eax
.out:
    ret
r26_job_phy_data:
    cmp byte [rel r26_job_phy_failed],0
    jne .finish
    lea r12,[rel r26_phy_ucode_1]
    lea r13,[rel r26_phy_ucode_1_end]
    cmp byte [rel r26_revision],2
    jne .selected
    lea r12,[rel r26_phy_ucode_2]
    lea r13,[rel r26_phy_ucode_2_end]
.selected:
    mov r14,[rel r26_job_words]
    lea r12,[r12+r14*4]
    cmp r14,6989
    jne .stream
    cmp byte [rel r26_job_boundary],3
    je .stream
    xor edi,edi
    cmp byte [rel r26_job_boundary],2
    jne .boundary
    inc edi
.boundary:
    call r26_job_patch_optional
    test eax,eax
    jnz .out
    cmp byte [rel r26_job_boundary],2
    je .boundary_done
    mov byte [rel r26_job_boundary],2
    jmp r26_job_pending
.boundary_done:
    mov byte [rel r26_job_boundary],3
    jmp r26_job_pending
.stream:
    mov ebx,8
.word:
    cmp r12,r13
    jae .finish
    movzx esi,word [r12]
    movzx edx,word [r12+2]
    call e5b_phy_write
    test eax,eax
    jnz .bad
    inc qword [rel r26_job_words]
    add r12,4
    cmp qword [rel r26_job_words],6989
    je r26_job_pending
    dec ebx
    jnz .word
    jmp r26_job_pending
.bad:
    inc dword [rel r26_attach_trace+32]
    mov byte [rel r26_job_phy_failed],1
.finish:
    mov eax,[rel r26_job_words]
    mov [rel r26_attach_trace+28],eax
    mov edi,9
    xor esi,esi
    mov edx,4
    cmp byte [rel r26_job_phy_failed],0
    je .record
    mov edx,2
.record:
    call r26_record
    xor eax,eax
.out:
    ret
r26_job_phy_version:
    cmp byte [rel r26_job_phy_failed],0
    jne r26_job_done
    lea rdi,[rel r26_phy_version_1]
    cmp byte [rel r26_revision],2
    jne .selected
    lea rdi,[rel r26_phy_version_2]
.selected:
    jmp r26_job_table
r26_job_phy_tune:
    lea rdi,[rel r26_phy_tuning_1]
    cmp byte [rel r26_revision],2
    jne .selected
    lea rdi,[rel r26_phy_tuning_2]
.selected:
    jmp r26_job_table

r26_job_station:
    ; Do not copy factory bytes over a changed live identity. Both addresses
    ; must still match the captured instance before any descriptor is reused.
    mov esi,0x19e0
    call e5b_rd
    jc .bad
    cmp eax,[rel r26_job_mac]
    jne .bad
    mov esi,0x19e4
    call e5b_rd
    jc .bad
    cmp ax,[rel r26_job_mac+4]
    jne .bad
    mov byte [rel e5000b_reset_phase],24
    mov dword [rel r26_attach_trace+36],24
    mov esi,R26_MAC0
    call e5b_rd
    jc .bad
    cmp eax,[rel r26_job_mac]
    jne .bad
    mov esi,R26_MAC4
    call e5b_rd
    jc .bad
    cmp ax,[rel r26_job_mac+4]
    jne .bad
    xor eax,eax
    ret
.bad:
    mov rax,-1
    ret
r26_job_ring_init:
    mov esi,R26_IMR
    xor edx,edx
    call e5b_wr
    call e5000b_isr_ack
    mov rdi,[rel e5000b_tx_ring]
    mov ecx,E5B_NUM_TX*E5B_DESC_SIZE/8
    xor eax,eax
    cld
    rep stosq
    mov r8,[rel e5000b_tx_ring]
    mov dword [r8+(E5B_NUM_TX-1)*E5B_DESC_SIZE],R26_EOR
    mov dword [rel e5000b_tx_head],0
    xor eax,eax
    ret
r26_job_ring_rx:
    mov ebx,[rel r26_job_cursor]
    cmp ebx,E5B_NUM_RX
    jae .done
    ; One descriptor is reconstructed per turn; no old RX is exposed.
    call e5000b_rx_repost
    inc qword [rel r26_job_cursor]
    jmp r26_job_pending
.done:
    mov dword [rel e5000b_rx_cursor],0
    xor eax,eax
    ret
r26_job_ring_bases:
    mov esi,R26_EECMD
    mov edx,R26_CFG_UNLOCK
    call e5b_or
    mov esi,R26_RX_BASE_LO
    mov edx,[rel e5000b_rx_ring]
    call e5b_wr
    mov esi,R26_RX_BASE_HI
    xor edx,edx
    call e5b_wr
    mov esi,R26_TX_BASE_LO
    mov edx,[rel e5000b_tx_ring]
    call e5b_wr
    mov esi,R26_TX_BASE_HI
    xor edx,edx
    call e5b_wr
    mov esi,R26_RXCFG
    mov edx,R26_RX_CONFIG|R26_RX_FILTER
    call e5b_wr
    mov esi,R26_TXCFG
    mov edx,R26_TX_CONFIG
    call e5b_wr
    xor eax,eax
    ret
r26_job_ring_gate:
    mov esi,R26_RXMAX_DWORD
    call e5b_rd
    and eax,0xffff
    mov edx,eax
    or edx,R26_RX_MAX<<16
    call e5b_wr
    mov esi,R26_PPSW_DWORD
    mov edx,R26_RX_GATE
    call e5b_andn
    xor eax,eax
    ret
r26_job_delay:
    cmp qword [rel r26_job_deadline],0
    jne .wait
    add rdi,[rel r26_job_now]
    mov [rel r26_job_deadline],rdi
    jmp r26_job_pending
.wait:
    mov rax,[rel r26_job_now]
    cmp rax,[rel r26_job_deadline]
    jb r26_job_pending
    xor eax,eax
    ret
r26_job_ring_lock:
    mov esi,R26_EECMD
    mov edx,R26_CFG_UNLOCK
    call e5b_andn
    xor eax,eax
    ret
r26_job_media_readback:
    mov esi,0xa400
    call e5b_phy_read
    test eax,eax
    js .out
    mov [rel e5000b_bmcr_after],ax
    or byte [rel e5000b_bmcr_valid],2
    test ax,0x0800
    jnz .out
    test ax,0x1000
    jz .out
    movzx edx,byte [rel e5000b_bmcr_valid]
    and edx,0x87
    cmp edx,0x87
    jne .out
    movzx edx,word [rel e5000b_phy_state]
    and edx,7
    cmp edx,3
    jne .out
    or byte [rel e5000b_bmcr_valid],0x40
.out:
    xor eax,eax
    ret
r26_job_enable:
    mov esi,R26_CMD_DWORD
    call e5b_rd
    and eax,0x00ffffff
    mov edx,eax
    or edx,R26_ENABLE
    call e5b_wr
    xor eax,eax
    ret
r26_job_commit:
    ; Only the complete protocol can reopen the rings. A live command
    ; readback remains mandatory; negotiation is checked by ordinary phase3.
    call r26_lr_cmd
    mov [rel rtl8126_link_rearm_state+REALTEK_LR_CMD],rax
    and eax,REALTEK_LR_CMD_MASK
    cmp eax,REALTEK_LR_CMD_ARMED
    jne .bad
    inc qword [rel rtl8126_link_rearm_state+32]
    mov qword [rel rtl8126_link_rearm_state],3
    mov byte [rel e5000b_rings_ok],1
    lock inc qword [rel e5000b_recover_successes]
    mov byte [rel e5000b_recover_busy],0
    mov byte [rel r26_job_active],0
    xor eax,eax
    ret
.bad:
    mov rax,-1
    ret

align 8
r26_job_identity_fields:
    ; Signed field offsets from this table's runtime LEA, never image VAs.
    dd e5000b_bdf-r26_job_identity_fields,e5000b_bar-r26_job_identity_fields
    dd e5000b_tx_ring-r26_job_identity_fields,e5000b_rx_ring-r26_job_identity_fields
    dd e5000b_tx_buffer-r26_job_identity_fields,e5000b_rx_buffers-r26_job_identity_fields
    dd e5000b_region-r26_job_identity_fields,e5000b_region+8-r26_job_identity_fields
r26_job_identity: times 8 dq 0
r26_job_mac: times 8 db 0
r26_job_pc: dq 0
r26_job_cursor: dq 0
r26_job_deadline: dq 0
r26_job_now: dq 0
r26_job_words: dq 0
r26_job_patch_deadline: dq 0
r26_job_active: db 0
r26_job_patch_phase: db 0
r26_job_phy_failed: db 0
r26_job_boundary: db 0
r26_job_ups_active: db 0
align 8
r26_job_program:
    ; 16-byte rel32 rows, unchanged dispatch and idle-return ownership.
    ; No PHY power/reset, firmware upload or media/autonegotiation restart.
    dd r26_job_init-r26_job_program,0,0,0
    dd r26_job_dump-r26_job_program,0,0,0
    dd r26_job_header-r26_job_program,0,0,0
    dd r26_job_table-r26_job_program,r26_drain_start-r26_job_program,1,0
    dd r26_job_wait-r26_job_program,r26_job_fifo-r26_job_program,1,0
    dd r26_job_wait-r26_job_program,r26_job_queue-r26_job_program,1,0
    dd r26_job_reset_start-r26_job_program,0,0,0
    dd r26_job_wait-r26_job_program,r26_job_cmd-r26_job_program,1,0
    dd r26_job_station-r26_job_program,0,0,0
    dd r26_job_ring_init-r26_job_program,0,0,0
    dd r26_job_ring_rx-r26_job_program,0,0,0
    dd r26_job_ring_bases-r26_job_program,0,0,0
    dd r26_job_table-r26_job_program,r26_mac_init-r26_job_program,1,0
    dd r26_job_table-r26_job_program,r26_eee_off-r26_job_program,1,0
    dd r26_job_ring_gate-r26_job_program,0,0,0
    dd r26_job_delay-r26_job_program,2000,0,0
    dd r26_job_ring_lock-r26_job_program,0,0,0
    dd r26_job_delay-r26_job_program,10,0,0
    dd r26_job_enable-r26_job_program,0,0,0
    dd r26_job_dump-r26_job_program,0,0,0
    dd r26_job_commit-r26_job_program,0,0,0
r26_job_program_end:
align 4
r26_job_fifo: dd 0xd0,0x30000000,0x30000000,150000,1,16
r26_job_queue: dd 0xe0,0x01030000,0x01030000,150000,1,32
r26_job_cmd: dd 0x34,R26_RESET,0,10000,10,2
r26_job_ups_state: dd 0xa420,7,2,100000,3,1|8|64
r26_job_phy_state: dd 0xa420,7,3,100000,3,1|8
r26_job_bmcr: dd 0xa400,0x8000,0,2500000,11,1|4
