; Original 8086:100e terminal observation; Intel317453006EN + kept PaOS.
; Trusted BSP/IF0, RDI=160B. EAX0 exact other backend/never-owned,
; -1 before-effect refusal, -2 latched/attempted/unknown. There is no1 path:
; supported EN/BME readbacks do not supply pending-bus completion evidence.
; Full ABI/provenance: gauntlet_v2/docs/E1000E_82540_TERMINAL.md.
    cld
    test rdi,rdi
    jz .null
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,40
    mov rbx,rdi
    xor eax,eax
    mov ecx,20
    rep stosq
    mov dword [rbx],1
    mov dword [rbx+32],-1
    lea rdi,[rbx+80]
    mov eax,-1
    mov ecx,8
    rep stosd
    mov dword [rbx+140],-1
    movzx eax,byte [rel e1000e_is_qemu]
    movzx edx,byte [rel e1000e_is_82574l]
    shl edx,8
    or eax,edx
    movzx edx,byte [rel e1000e_nic_absent]
    shl edx,16
    or eax,edx
    movzx edx,byte [rel e1000e_bar_bad]
    shl edx,24
    or eax,edx
    mov [rbx+24],eax
    mov eax,[rel e1000e_devid]
    mov [rbx+28],eax
    mov rax,[rel e1000e_region]
    mov [rbx+48],rax
    mov rax,[rel e1000e_region+8]
    mov [rbx+56],rax
    movzx eax,byte [rel e1000e_mac_ok]
    movzx edx,byte [rel e1000e_rings_ok]
    shl edx,8
    or eax,edx
    movzx edx,byte [rel e1000e_tx_enabled]
    shl edx,16
    or eax,edx
    mov [rbx+64],eax
    movzx eax,byte [rel e1000e_tx_busy]
    movzx edx,byte [rel e1000e_rx_busy]
    shl edx,8
    or eax,edx
    movzx edx,byte [rel e1000e_rx_rearm_pending]
    shl edx,16
    or eax,edx
    mov [rbx+68],eax
    xor ecx,ecx
    cmp qword [rel e1000e_region],0
    sete al
    movzx eax,al
    shl eax,0
    or ecx,eax
    cmp qword [rel e1000e_region+8],0
    sete al
    movzx eax,al
    shl eax,1
    or ecx,eax
    cmp qword [rel e1000e_tx_ring],0
    sete al
    movzx eax,al
    shl eax,2
    or ecx,eax
    cmp qword [rel e1000e_rx_ring],0
    sete al
    movzx eax,al
    shl eax,3
    or ecx,eax
    cmp qword [rel e1000e_rx_buffers],0
    sete al
    movzx eax,al
    shl eax,4
    or ecx,eax
    cmp qword [rel e1000e_tx_buffer],0
    sete al
    movzx eax,al
    shl eax,5
    or ecx,eax
    cmp qword [rel e1000e_tx_pending],0
    sete al
    movzx eax,al
    shl eax,6
    or ecx,eax
    cmp qword [rel e1000e_power_gate],0
    sete al
    movzx eax,al
    shl eax,7
    or ecx,eax
    cmp byte [rel e1000e_tx_busy],0
    sete al
    movzx eax,al
    shl eax,8
    or ecx,eax
    cmp byte [rel e1000e_rx_busy],0
    sete al
    movzx eax,al
    shl eax,9
    or ecx,eax
    cmp byte [rel e1000e_tx_enabled],0
    sete al
    movzx eax,al
    shl eax,10
    or ecx,eax
    cmp byte [rel e1000e_mac_ok],0
    sete al
    movzx eax,al
    shl eax,11
    or ecx,eax
    cmp byte [rel e1000e_rings_ok],0
    sete al
    movzx eax,al
    shl eax,12
    or ecx,eax
    mov [rbx+72],ecx
    mov dword [rbx+76],0x1fff ; all13 original RAM comparisons observed

    or dword [rbx+16],1
    mov dword [rbx+12],2
    ; Irreversible custody survives a later caller with IF set.
    cmp dword [rel e1000e_82540_terminal_latched],0
    jne .replay
    pushfq
    pop rax
    test eax,0x200
    jnz .refused_unlocked
    cmp byte [rel e1000e_is_qemu],1
    je .ours
    ; Exact peer selection only; this is not a never-owned decision.
    cmp byte [rel e1000e_is_qemu],0
    jne .refused_unlocked
    cmp byte [rel e1000e_is_82574l],1
    je .peer82574
    cmp byte [rel e1000e_is_82574l],0
    jne .refused_unlocked
    cmp byte [rel e1000e_nic_absent],1
    je .lock_inactive
    cmp byte [rel e1000e_nic_absent],0
    jne .refused_unlocked
    cmp dword [rel e1000e_devid],0x15bc
    je .other
    cmp dword [rel e1000e_devid],0x15d7
    jne .refused_unlocked
    jmp .other
.peer82574:
    cmp dword [rel e1000e_devid],E1000_82574L_DEVID
    jne .refused_unlocked
.other:
    mov dword [rbx+20],1
    mov dword [rbx+12],0
    xor eax,eax
    jmp .out
.ours:
    cmp byte [rel e1000e_is_82574l],0
    jne .refused_unlocked
    cmp dword [rel e1000e_devid],E1000_QEMU_DEVID
    jne .refused_unlocked
.lock_inactive:
    xor eax,eax
    mov edx,1
    lock cmpxchg [rel e1000e_82540_terminal_gate],edx
    jne .refused_unlocked
    cmp dword [rel e1000e_i219_terminal_gate],0
    jne .refused
    cmp qword [rel e1000e_power_gate],0
    jne .refused
    cmp dword [rbx+68],0
    jne .refused
    cmp byte [rel e1000e_nic_absent],1
    je .inactive
    cmp byte [rel e1000e_nic_absent],0
    jne .refused
    mov dword [rbx+20],3
    cmp byte [rel e1000e_bar_bad],0
    jne .refused
    cmp byte [rel e1000e_mac_ok],1
    jne .refused
    cmp byte [rel e1000e_rings_ok],1
    jne .refused
    cmp dword [rel e1000e_pci_dev],31
    ja .refused
    cmp dword [rel e1000e_pci_fn],7
    ja .refused
    mov esi,[rel e1000e_pci_dev]
    mov edx,[rel e1000e_pci_fn]
    call e1000e_bus_identity
    test eax,eax                      ; original qualified bus0 only
    jnz .refused
    mov eax,[rel e1000e_pci_dev]
    shl eax,8
    or eax,[rel e1000e_pci_fn]
    mov [rbx+32],eax
    mov eax,[rel e1000e_pci_dev]
    shl eax,3
    or eax,[rel e1000e_pci_fn]
    mov edi,eax
    mov esi,1
    call e1000e_i219_terminal_claims   ; kept locked census, no device effects
    test eax,eax
    jnz .refused
    mov [rbx+36],edx
    or dword [rbx+16],2
    lea rdi,[rel e1000e_dev]
    lea rsi,[rel e1000e_ops]
    call netdev_power_member
    test rax,rax
    jz .refused
    mov [rsp],rax
    mov [rsp+8],rdx
    mov [rbx+40],rdx
    or dword [rbx+16],4
    xor ecx,ecx
    call e1000e_82540_terminal_pci
    cmp eax,0x100e8086
    jne .refused
    or dword [rbx+16],8
    mov ecx,8
    call e1000e_82540_terminal_pci
    shr eax,16
    cmp eax,0x0200
    jne .refused
    cmp qword [rel e1000e_region+8],0x20000
    jne .refused
    mov rax,[rel e1000e_region]
    test rax,rax
    jz .refused
    test eax,0x1ffff
    jnz .refused
    shr rax,32
    jnz .refused
    mov ecx,0x10
    call e1000e_82540_terminal_pci
    test eax,15
    jnz .refused
    cmp rax,[rel e1000e_region]
    jne .refused
    mov ecx,4
    call e1000e_82540_terminal_pci
    cmp eax,-1
    je .refused
    movzx eax,ax
    mov [rbx+80],eax
    and eax,6
    cmp eax,6
    jne .refused
    or dword [rbx+16],16
    lea rdi,[rel e1000e_tx_ring]
    xor ecx,ecx
.dma:
    mov rax,[rdi+rcx*8]
    test rax,rax
    jz .refused
    test eax,4095
    jnz .refused
    lea rsi,[rel e1000e_i219_terminal_spans]
    mov r8,rax
    add r8,[rsi+rcx*8]
    jc .refused
    xor edx,edx
.overlap:
    cmp edx,ecx
    jae .dma_next
    mov r9,[rdi+rdx*8]
    mov r10,r9
    add r10,[rsi+rdx*8]
    cmp rax,r10
    jae .separate
    cmp r8,r9
    ja .refused
.separate:
    inc edx
    jmp .overlap
.dma_next:
    inc ecx
    cmp ecx,4
    jb .dma

    or dword [rbx+128],1
    call e1000e_82540_terminal_rings
    test eax,eax
    jnz .refused
    or dword [rbx+128],2
    or dword [rbx+16],32
    mov esi,E1000_IMS
    call e1000e_82540_terminal_rd
    jc .refused
    mov [rbx+104],eax
    mov esi,E1000_RCTL
    call e1000e_82540_terminal_rd
    jc .refused
    mov [rbx+88],eax
    mov esi,E1000_TCTL
    call e1000e_82540_terminal_rd
    jc .refused
    mov [rbx+96],eax
    or dword [rbx+16],64
    lea rdi,[rel e1000e_dev]
    lea rsi,[rel e1000e_ops]
    call netdev_power_member
    cmp rax,[rsp]
    jne .refused
    cmp rdx,[rsp+8]
    jne .refused
    or dword [rbx+128],4
    mov eax,[rel e1000e_pci_dev]
    shl eax,3
    or eax,[rel e1000e_pci_fn]
    mov edi,eax
    mov esi,1
    call e1000e_i219_terminal_claims
    test eax,eax
    jnz .refused
    cmp edx,[rbx+36]
    jne .refused
    or dword [rbx+128],8
    cmp byte [rel e1000e_tx_busy],0
    jne .refused
    cmp byte [rel e1000e_rx_busy],0
    jne .refused
    cmp byte [rel e1000e_rx_rearm_pending],0
    jne .refused
    cmp qword [rel e1000e_power_gate],0
    jne .refused
    mov dword [rbx+8],1
    mov dword [rel e1000e_82540_terminal_latched],1
    mov dword [rel e1000e_82540_terminal_gate],2
    mov dword [rbx+132],2
    mov dword [rbx+124],1
    mov dword [rbx+8],2
    mov dword [rbx+12],4
    mov ebp,1000
.tx_wait:
    inc dword [rbx+116]
    mov rdi,[rel e1000e_tx_ring]
    xor ecx,ecx
    xor edx,edx
.tx_desc:
    cmp word [rdi+rcx+8],0
    je .tx_next
    test byte [rdi+rcx+12],E1000_TXD_STA_DD
    jz .pending
    mov eax,ecx
    shr eax,4
    bts edx,eax
.tx_next:
    add ecx,E1000_DESC_SIZE
    cmp ecx,E1000_NUM_TX*E1000_DESC_SIZE
    jb .tx_desc
    mov [rbx+112],edx
    or dword [rbx+16],128
    jmp .mask
.pending:
    mov [rbx+112],edx
    or dword [rbx+16],128
    mov edi,100
    call e1k_delay_us
    dec ebp
    jnz .tx_wait
    jmp .uncertain
.mask:
    mov dword [rbx+8],3
    mov dword [rbx+12],5
    or dword [rbx+124],2
    mov esi,E1000_IMC
    mov edx,-1
    call e1000e_82540_terminal_wr
    jc .uncertain
    mov esi,E1000_IMS
    call e1000e_82540_terminal_rd
    jc .uncertain
    mov [rbx+108],eax
    test eax,eax
    jnz .ignored
    mov dword [rbx+8],4
    or dword [rbx+124],4
    mov esi,E1000_RCTL
    mov edx,[rbx+88]
    and edx,~2
    call e1000e_82540_terminal_wr
    jc .uncertain
    or dword [rbx+124],8
    mov esi,E1000_TCTL
    mov edx,[rbx+96]
    and edx,~2
    call e1000e_82540_terminal_wr
    jc .uncertain
    mov ebp,100
.control_wait:
    inc dword [rbx+120]
    mov esi,E1000_RCTL
    call e1000e_82540_terminal_rd
    jc .uncertain
    mov [rbx+92],eax
    mov r12d,eax
    mov esi,E1000_TCTL
    call e1000e_82540_terminal_rd
    jc .uncertain
    mov [rbx+100],eax
    or eax,r12d
    or dword [rbx+16],256
    test eax,2
    jz .controls_off
    mov edi,100
    call e1k_delay_us
    dec ebp
    jnz .control_wait
    jmp .ignored
.controls_off:
    mov dword [rbx+8],6
    mov dword [rbx+12],7
    mov ecx,4
    call e1000e_82540_terminal_pci
    cmp eax,-1
    je .uncertain
    movzx eax,ax
    cmp eax,[rbx+80]
    jne .changed
    and eax,~4
    mov [rsp+16],eax
    mov r8d,eax                       ; exact low16, Status RW1C receives zero
    xor edi,edi
    mov esi,[rel e1000e_pci_dev]
    mov edx,[rel e1000e_pci_fn]
    mov ecx,4
    or dword [rbx+124],16
    inc dword [rbx+148]
    call pci_cfg_write32
    mov ecx,4
    call e1000e_82540_terminal_pci
    cmp eax,-1
    je .uncertain
    movzx eax,ax
    mov [rbx+84],eax
    or dword [rbx+16],512
    cmp eax,[rsp+16]
    jne .ignored
    mov dword [rbx+8],7
    mov dword [rbx+12],9             ; all supported stop bits observed, bus drain unknown
    jmp .uncertain                   ; never promote EN0/BME0 to all-DMA completion
.inactive:
    cmp dword [rbx+72],0x1fff
    jne .refused
    cmp dword [rel e1000e_dev+dev.class],0
    jne .inactive_registered
    cmp qword [rel e1000e_dev+dev.ops],0
    jne .refused
    jmp .inactive_claims
.inactive_registered:
    cmp dword [rel e1000e_dev+dev.class],CLASS_NET
    jne .refused
    lea rax,[rel e1000e_ops]
    cmp [rel e1000e_dev+dev.ops],rax
    jne .refused
    cmp dword [rel e1000e_dev+dev.health],HEALTH_DEGRADED
    jne .refused
    test dword [rel e1000e_dev+dev.flags],NETDEV_F_ABSENT
    jz .refused
.inactive_claims:
    xor edi,edi
    xor esi,esi
    call e1000e_i219_terminal_claims
    test eax,eax
    jnz .refused
    or dword [rbx+16],2
    mov dword [rbx+20],2
    mov dword [rel e1000e_82540_terminal_gate],0
    mov dword [rbx+12],1
    xor eax,eax
    jmp .out
.ignored:
    mov dword [rbx+12],6
    jmp .uncertain
.changed:
    mov dword [rbx+12],8
    jmp .uncertain
.refused:
    mov dword [rel e1000e_82540_terminal_gate],0
.refused_unlocked:
    mov eax,-1
    jmp .out
.replay:
    mov dword [rbx+12],3
    mov eax,[rel e1000e_82540_terminal_gate]
    mov [rbx+132],eax
.uncertain:
    mov eax,-2
.out:
    mov [rbx+4],eax
    add rsp,40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.null:
    mov eax,-1
    cmp dword [rel e1000e_82540_terminal_latched],0
    je .null_out
    mov eax,-2
.null_out:
    ret

e1000e_82540_terminal_pci:
    inc dword [rbx+144]
    jmp e1000e_i219_terminal_pci

e1000e_82540_terminal_rd:
    inc dword [rbx+152]
    jmp e1000e_i219_terminal_rd

e1000e_82540_terminal_wr:
    inc dword [rbx+156]
    jmp e1000e_i219_terminal_wr

e1000e_82540_terminal_rings:
    push r12
    mov r12,[rel e1000e_tx_ring]
    mov esi,E1000_TDBAL
    call e1000e_82540_terminal_rd
    jc .bad
    cmp eax,r12d
    jne .bad
    mov r12,[rel e1000e_tx_ring]
    shr r12,32
    mov esi,E1000_TDBAH
    call e1000e_82540_terminal_rd
    jc .bad
    cmp eax,r12d
    jne .bad
    mov r12,[rel e1000e_rx_ring]
    mov esi,E1000_RDBAL
    call e1000e_82540_terminal_rd
    jc .bad
    cmp eax,r12d
    jne .bad
    mov r12,[rel e1000e_rx_ring]
    shr r12,32
    mov esi,E1000_RDBAH
    call e1000e_82540_terminal_rd
    jc .bad
    cmp eax,r12d
    jne .bad
    mov esi,E1000_TDLEN
    call e1000e_82540_terminal_rd
    jc .bad
    cmp eax,E1000_NUM_TX*E1000_DESC_SIZE
    jne .bad
    mov esi,E1000_RDLEN
    call e1000e_82540_terminal_rd
    jc .bad
    cmp eax,E1000_NUM_RX*E1000_DESC_SIZE
    jne .bad
    mov esi,E1000_TDT
    call e1000e_82540_terminal_rd
    jc .bad
    cmp eax,E1000_NUM_TX
    jae .bad
    cmp eax,[rel e1000e_tx_tail]
    jne .bad
    mov esi,E1000_RDT
    call e1000e_82540_terminal_rd
    jc .bad
    cmp eax,E1000_NUM_RX
    jae .bad
    cmp dword [rel e1000e_rx_tail_sw],E1000_NUM_RX
    jae .bad
    ; Posted descriptors still name the original shared native bounce buffer.
    mov rdi,[rel e1000e_tx_ring]
    xor ecx,ecx
.tx_owned:
    movzx eax,word [rdi+rcx+8]
    test eax,eax
    jz .tx_owned_next
    cmp eax,E1000_TX_BUF
    ja .bad
    mov rax,[rdi+rcx]
    cmp rax,[rel e1000e_tx_buffer]
    jne .bad
.tx_owned_next:
    add ecx,E1000_DESC_SIZE
    cmp ecx,E1000_NUM_TX*E1000_DESC_SIZE
    jb .tx_owned
    ; Pending pointer must designate the original descriptor, never arbitrary RAM.
    mov rax,[rel e1000e_tx_pending]
    test rax,rax
    jz .good
    sub rax,[rel e1000e_tx_ring]
    jc .bad
    cmp rax,E1000_NUM_TX*E1000_DESC_SIZE
    jae .bad
    test eax,15
    jnz .bad
    mov rdi,[rel e1000e_tx_pending]
    cmp word [rdi+8],0
    je .bad
.good:
    xor eax,eax
    pop r12
    ret
.bad:
    mov eax,-1
    pop r12
    ret
