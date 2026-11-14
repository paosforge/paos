; RTL8126/E5000B terminal closure. Pin/license/facts and wire ABI in
; gauntlet_v2/docs/RTL8126_TERMINAL.md. No reset, PHY, D3, free or new admission.
; RDI trusted writable128B; BSP IF0. EAX 0 inactive,1 complete,-1 no effect,
; -2 latched/uncertain/replay. DMA and HAL mappings remain pinned on every path.
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 1064                    ; SysV entry8 + six pushes -> CALL stack0
    mov rbp, rsp
    mov r12, rdi
    xor eax, eax
    mov ecx, 32
    cld
    rep stosd
    mov dword [r12], 1
    mov byte [rbp+1048], 0             ; only our temporary gate
    cmp byte [rel rtl8126_terminal_latched], 0
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
%ifdef PAOS_NATIVE_DRIVER_POLICY_LINKED
    mov edi, 6
    mov rsi, -1
    call native_driver_gate
    jc .refuse
%endif
    mov al, 1
    xchg al, [rel rtl8126_terminal_gate]
    test al, al
    jnz .refuse
    mov byte [rbp+1048], 1
    mov rdi, rbp
    call pci_claim_snapshot
    test edx, edx
    jnz .refuse
    cmp eax, 32
    ja .refuse
    mov [rbp+1024], eax
    mov [r12+20], eax
    ; Exact complete census: only one current RTL8126 function may be owned.
    xor ecx, ecx
    xor r13d, r13d
    xor r14d, r14d
.claim:
    cmp ecx, [rbp+1024]
    jae .claimed
    mov eax, ecx
    shl eax, 4
    cmp dword [rbp+rax+4], PCI_DRV_RTL8126
    jne .next
    inc r13d
    lea r14, [rbp+rax]
.next:
    inc ecx
    jmp .claim
.claimed:
    test r13d, r13d
    jz .inactive_check
    cmp r13d, 1
    jne .refuse
    cmp dword [rel e5000b_matches], 1
    jne .refuse
    cmp byte [rel e5000b_registered], 1
    jne .refuse
    cmp byte [rel e5000b_hw_ok], 1
    jne .refuse
    cmp byte [rel e5000b_mac_ok], 1
    jne .refuse
    cmp byte [rel e5000b_rings_ok], 1
    jne .refuse
    cmp byte [rel e5000b_iso_ok], 1
    jne .refuse
    cmp byte [rel e5000b_recover_busy], 0
    jne .refuse
    cmp byte [rel e5000b_tx_busy], 0
    jne .refuse
    mov rax, [rel e5000b_bdf]
    test rax, rax
    js .refuse
    shr rax, 32
    jnz .refuse
    mov eax, [rel e5000b_bdf]
    test eax, 0xff00e0f8
    jnz .refuse
    mov [r12+32], eax
    mov edx, eax
    and edx, 7
    shr eax, 8
    shl al, 3
    or dl, al
    mov eax, [rel e5000b_bdf]
    shr eax, 16
    shl eax, 8
    or eax, edx
    cmp eax, [r14]
    jne .refuse
    xor ecx, ecx
    xor edx, edx
.unique_bdf:
    cmp ecx, [rbp+1024]
    jae .unique_done
    mov esi, ecx
    shl esi, 4
    cmp eax, [rbp+rsi]
    jne .unique_next
    inc edx
.unique_next:
    inc ecx
    jmp .unique_bdf
.unique_done:
    cmp edx, 1
    jne .refuse
    cmp dword [r14+8], PCI_CLAIM_BOUND
    jne .refuse
    mov eax, [r14+12]
    test eax, eax
    jz .refuse
    mov [r12+36], eax
    or dword [r12+28], 1
    lea rdi, [rel e5000b_dev]
    lea rsi, [rel e5000b_ops]
    call netdev_power_member
    test rax, rax
    jnz .registry
    lea rdi, [rel e5000b_dev]
    lea rsi, [rel e5000b_ops]
    call netdev_link_wait_member
    test rax, rax
    jz .refuse
.registry:
    test rdx, rdx
    jz .refuse
    cmp rdx, -1
    je .refuse
    mov [rbp+1032], rax
    mov [r12+40], rdx
    or dword [r12+28], 2
    mov rdi, [rel e5000b_tx_ring]
    mov esi, E5B_NUM_TX*E5B_DESC_SIZE
    call e5000b_dma_range_ok
    cmp eax, 1
    jne .refuse
    mov rdi, [rel e5000b_rx_ring]
    mov esi, E5B_NUM_RX*E5B_DESC_SIZE
    call e5000b_dma_range_ok
    cmp eax, 1
    jne .refuse
    mov rdi, [rel e5000b_tx_buffer]
    mov esi, E5B_TX_BUF
    call e5000b_dma_range_ok
    cmp eax, 1
    jne .refuse
    mov rdi, [rel e5000b_rx_buffers]
    mov esi, E5B_NUM_RX*E5B_RX_BUF
    call e5000b_dma_range_ok
    cmp eax, 1
    jne .refuse
    xor ecx, ecx
    call r26_terminal_cfg
    mov [r12+48], eax
    cmp eax, E5B_VENDEV
    je .identity
    cmp eax, R26_VENDEV
    jne .refuse
.identity:
    cmp eax, [rel e5000b_devid]
    jne .refuse
    mov ecx, 4
    call r26_terminal_cfg
    cmp eax, -1
    je .refuse
    movzx eax, ax
    mov [r12+56], eax
    test eax, 2
    jz .refuse
    or dword [r12+28], 4
    mov ecx, 0x18
    call r26_terminal_cfg
    test al, 1
    jnz .refuse
    mov r14d, eax
    mov edx, eax
    and edx, 6
    cmp edx, 0
    je .bar32
    cmp edx, 4
    jne .refuse
.bar32:
    and eax, 0xfffffff0
    test eax, eax
    jz .refuse
    cmp rax, [rel e5000b_region]
    jne .refuse
    cmp rax, [rel e5000b_bar]
    jne .refuse
    test r14b, 4
    jz .bar_high_ok
    mov ecx, 0x1c
    call r26_terminal_cfg
    test eax, eax
    jnz .refuse
.bar_high_ok:
    cmp qword [rel e5000b_region+8], 0x10000
    jne .refuse
    or dword [r12+28], 8
    mov esi, R26_TXCFG
    call e5b_rd
    jc .refuse
    mov [r12+52], eax
    and eax, 0x7cf00000
    mov edx, 1
    cmp eax, 0x64900000
    je .revision
    inc edx
    cmp eax, 0x64a00000
    jne .refuse
.revision:
    cmp dl, [rel r26_revision]
    jne .refuse
    mov [r12+108], edx
    or dword [r12+28], 16
    mov esi, 0x20
    call e5b_rd
    jc .refuse
    cmp eax, -1
    je .refuse
    mov [r12+100], eax
    cmp rax, [rel e5000b_tx_ring]
    jne .refuse
    mov esi, 0x24
    call e5b_rd
    jc .refuse
    test eax, eax
    jnz .refuse
    mov esi, 0xe4
    call e5b_rd
    jc .refuse
    cmp eax, -1
    je .refuse
    mov [r12+104], eax
    cmp rax, [rel e5000b_rx_ring]
    jne .refuse
    mov esi, 0xe8
    call e5b_rd
    jc .refuse
    test eax, eax
    jnz .refuse
    or dword [r12+28], 32
    mov esi, R26_IMR
    call e5b_rd
    jc .refuse
    mov [r12+112], eax
    test eax, eax
    jnz .refuse
    or dword [r12+28], 64
    mov esi, R26_CMD_DWORD
    call e5b_rd
    jc .refuse
    mov [r12+72], eax
    cmp eax, -1
    je .refuse
    test eax, 0x10000000
    jnz .refuse
    or dword [r12+28], 0x4000
    mov dword [r12+8], 1
    jmp .recheck
.inactive_check:
    ; No-owned-state witness is not a physical-absence inference. Reject every
    ; partial bind and any exact handle still retained by the registry.
    ; Inactive layout: expose only operands reached by the original predicates.
    mov dword [r12+28], 1 << 15
    mov [r12+100], r13d              ; actual zero RTL8126 claim count
    mov edx, [rel e5000b_matches]
    mov [r12+32], edx
    mov dword [r12+116], 1
    cmp edx, 0
    jne .refuse
    mov edx, [rel e5000b_devid]
    mov [r12+36], edx
    mov dword [r12+116], 3
    cmp edx, 0
    jne .refuse
    mov rax, [rel e5000b_bdf]
    mov [r12+40], rax
    mov dword [r12+116], 7
    cmp rax, -1
    jne .refuse
    lea rdi, [rel e5000b_dev]
    xor eax, eax
    mov ecx, dev_size+netdev_ops_size+16
    mov [r12+48], ecx
    repe scasb
    ; MOV/SETZ leave the original scan flags for the following JNE/JE.
    mov [r12+52], ecx
    setz byte [r12+56]
    mov dword [r12+116], 15
    jne .refuse
    lea rdi, [rel e5000b_bar]
    mov ecx, 5
    mov [r12+60], ecx
    repe scasq
    mov [r12+64], ecx
    setz byte [r12+68]
    mov dword [r12+116], 31
    jne .refuse
    cmp qword [rel e5000b_slot], 0
    setne byte [r12+72]              ; presence, not a retained address
    mov dword [r12+116], 63
    jne .refuse
    mov rdx, [rel e5000b_registered] ; flags through recover_busy + MAC byte
    mov [r12+76], rdx
    mov dword [r12+116], 127
    cmp rdx, 0
    jne .refuse
    movzx edx, byte [rel e5000b_tx_busy]
    mov [r12+84], edx
    mov dword [r12+116], 255
    cmp dl, 0
    jne .refuse
    lea rdi, [rel netdev_table]
    lea rax, [rel e5000b_dev]
    mov ecx, 8
    mov [r12+88], ecx
    repne scasq
    mov [r12+92], ecx
    setz byte [r12+96]
    mov dword [r12+116], 511
    je .refuse
.recheck:
    lea rdi, [rbp+512]
    call pci_claim_snapshot
    test edx, edx
    jnz .refuse
    cmp eax, [rbp+1024]
    jne .refuse
    mov ecx, eax
    shl ecx, 1
    mov rsi, rbp
    lea rdi, [rbp+512]
    repe cmpsq
    jne .refuse
    cmp dword [r12+8], 0
    je .inactive
    mov rax, [rbp+1032]
    mov rdx, [r12+40]
    cmp [rax], rdx
    jne .refuse
    mov al, 1
    xchg al, [rel rtl8126_terminal_latched]
    test al, al
    jnz .uncertain
    mov dword [r12+24], 1
    call r26_terminal_effect
    cmp eax, 1
    jne .uncertain
    mov dword [r12+12], 1
    mov eax, 1
    jmp .out
.inactive:
    mov byte [rel rtl8126_terminal_gate], 0
    xor eax, eax
    jmp .out
.refuse:
    cmp byte [rbp+1048], 0
    je .refused
    mov byte [rel rtl8126_terminal_gate], 0
.refused:
    mov dword [r12+16], 1
    mov eax, -1
    jmp .out
.uncertain:
    mov dword [r12+16], 2
    mov eax, -2
.out:
    mov [r12+4], eax
    add rsp, 1064
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Always this exact retained function, never another device or default BDF.
r26_terminal_cfg:
    mov edi, [rel e5000b_bdf]
    mov esi, edi
    shr esi, 8
    and esi, 0x1f
    mov edx, edi
    and edx, 7
    shr edi, 16
    and edi, 0xff
    jmp pci_cfg_read32
r26_terminal_cfg_write:
    mov edi, [rel e5000b_bdf]
    mov esi, edi
    shr esi, 8
    and esi, 0x1f
    mov edx, edi
    and edx, 7
    shr edi, 16
    and edi, 0xff
    jmp pci_cfg_write32

; Checked 32-bit operations preserve adjacent register bytes. All-ones is
; unavailable even when the wanted drain bits happen to be set.
r26_terminal_effect:
    lea rsp, [rsp-8]                ; nested CALLs enter at RSP%16=8
    mov esi, R26_RXCFG
    call e5b_rd
    jc .bad
    cmp eax, -1
    je .bad
    and eax, ~0x3f
    mov edx, eax
    mov esi, R26_RXCFG
    call e5b_wr
    jc .bad
    mov esi, R26_PPSW_DWORD
    call e5b_rd
    jc .bad
    cmp eax, -1
    je .bad
    or eax, 0x00080000
    mov edx, eax
    mov esi, R26_PPSW_DWORD
    call e5b_wr
    jc .bad
    mov esi, R26_CMD_DWORD
    call e5b_rd
    jc .bad
    cmp eax, -1
    je .bad
    test eax, 0x10000000
    jnz .bad
    or eax, 0x80000000
    mov edx, eax
    mov esi, R26_CMD_DWORD
    call e5b_wr
    jc .bad
    mov dword [r12+24], 2
    mov edi, 200
    call tsc_delay_us
    mov r13d, 3000
.fifo:
    mov edi, 50
    call tsc_delay_us
    inc dword [r12+92]
    mov esi, 0xd0
    call e5b_rd
    jc .bad
    mov [r12+80], eax
    or dword [r12+28], 0x200
    cmp eax, -1
    je .bad
    and eax, 0x30000000
    cmp eax, 0x30000000
    je .fifo_done
    dec r13d
    jnz .fifo
    jmp .bad
.fifo_done:
    mov dword [r12+24], 3
    mov r13d, 3000
.im:
    mov edi, 50
    call tsc_delay_us
    inc dword [r12+96]
    mov esi, 0xe0
    call e5b_rd
    jc .bad
    mov [r12+84], eax
    or dword [r12+28], 0x400
    cmp eax, -1
    je .bad
    and eax, 0x01030000
    cmp eax, 0x01030000
    je .im_done
    dec r13d
    jnz .im
    jmp .bad
.im_done:
    mov dword [r12+24], 4
    mov esi, R26_CMD_DWORD
    call e5b_rd
    jc .bad
    cmp eax, -1
    je .bad
    test eax, 0x10000000
    jnz .bad
    and eax, ~0x0c000000
    mov edx, eax
    mov esi, R26_CMD_DWORD
    call e5b_wr
    jc .bad
    mov esi, R26_CMD_DWORD
    call e5b_rd
    jc .bad
    mov [r12+76], eax
    or dword [r12+28], 0x800
    cmp eax, -1
    je .bad
    test eax, 0x1c000000
    jnz .bad
    mov dword [r12+24], 5
    mov esi, R26_RXCFG
    call e5b_rd
    jc .bad
    mov [r12+64], eax
    or dword [r12+28], 0x80
    cmp eax, -1
    je .bad
    test eax, 0x3f
    jnz .bad
    mov esi, R26_PPSW_DWORD
    call e5b_rd
    jc .bad
    mov [r12+68], eax
    or dword [r12+28], 0x100
    cmp eax, -1
    je .bad
    test eax, 0x00080000
    jz .bad
    mov esi, R26_IMR
    xor edx, edx
    call e5b_wr
    jc .bad
    mov esi, R26_IMR
    call e5b_rd
    jc .bad
    mov [r12+88], eax
    or dword [r12+28], 0x1000
    test eax, eax
    jnz .bad
    mov dword [r12+24], 6
    mov ecx, 4
    call r26_terminal_cfg
    cmp eax, -1
    je .bad
    and eax, 0x0000fffb              ; PCI Status W1C write lanes stay zero
    mov r8d, eax
    mov ecx, 4
    call r26_terminal_cfg_write
    mov ecx, 4
    call r26_terminal_cfg
    mov [r12+60], eax
    or dword [r12+28], 0x2000
    cmp eax, -1
    je .bad
    test eax, 4
    jnz .bad
    mov dword [r12+24], 7
    mov eax, 1
    lea rsp, [rsp+8]
    ret
.bad:
    mov eax, -2
    lea rsp, [rsp+8]
    ret
