; Explicit read-only observation of ONE known xHCI controller and root port.
; RDI=registered usb_hc dev*, ESI=1-based root port, RDX=40B caller output.
; EAX=1 iff all three live reads completed, 0 unknown/refused. Clobbers caller-
; saved registers. Output dwords: observed, controller index, PCI BDF, root port,
; generation, USBCMD, USBSTS, PORTSC, dev.health, root-port count.
; No port transfer, register write, poll, instance swap, ownership change or
; boot call. A halted/disconnected controller is an observation, not UNKNOWN.
; Saved-instance regions are the owner's retained HAL BARs, never guessed MMIO.
; Hub-child tokens have no PORTSC; their readiness remains explicitly unknown.
xhci_readiness_snapshot:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12,rdx
    mov r14,rdi
    mov r15d,esi
    mov rdi,rdx
    xor eax,eax
    mov ecx,10
    cld
    rep stosd
    mov rdi,r14
    call xhci_hc_instance
    cmp eax,-1
    je .unknown
    cmp eax,[rel xhci_inst_n]
    jae .unknown
    mov ebx,eax
    ; The attached power participant owns primary-only live state. Respect its
    ; admission before accessing that state; never substitute primary for XHC1+.
    cmp qword [rel reinit_power_xhci_context],0
    je .gate
    test ebx,ebx
    jnz .unknown
    cmp dword [rel xhci_inst_cur],0
    jne .unknown
.gate:
    call reinit_power_xhci_gate
    test rax,rax
    jnz .unknown
    lea r13,[rel xhci_inst_r1]
    cmp ebx,[rel xhci_inst_cur]
    je .state
    imul eax,ebx,XHCI_INST_BYTES
    lea r13,[rel xhci_inst_save]
    add r13,rax
.state:
    test r15d,r15d
    jz .unknown
    cmp r15d,[r13+(xhci_maxports-xhci_inst_r1)]
    ja .unknown
    cmp qword [r13+(xhci_region-xhci_inst_r1)],0
    je .unknown
    mov [r12+4],ebx
    mov eax,[r13+(xhci_bus-xhci_inst_r1)]
    shl eax,8
    mov ecx,[r13+(xhci_dev-xhci_inst_r1)]
    shl ecx,3
    or eax,ecx
    or eax,[r13+(xhci_fn-xhci_inst_r1)]
    mov [r12+8],eax
    mov [r12+12],r15d
    mov eax,[r13+(xhci_generation-xhci_inst_r1)]
    mov [r12+16],eax
    mov eax,[r14+dev.health]
    mov [r12+32],eax
    mov eax,[r13+(xhci_maxports-xhci_inst_r1)]
    mov [r12+36],eax
    lea rdi,[r13+(xhci_region-xhci_inst_r1)]
    mov esi,[r13+(xhci_op-xhci_inst_r1)]
    call hal_mmio_read32
    jc .unknown
    mov [r12+20],eax
    lea rdi,[r13+(xhci_region-xhci_inst_r1)]
    mov esi,[r13+(xhci_op-xhci_inst_r1)]
    add rsi,4
    call hal_mmio_read32
    jc .unknown
    mov [r12+24],eax
    lea rdi,[r13+(xhci_region-xhci_inst_r1)]
    lea esi,[r15d-1]
    shl rsi,4
    add rsi,XHCI_PORTSC_BASE
    mov eax,[r13+(xhci_op-xhci_inst_r1)]
    add rsi,rax
    call hal_mmio_read32
    jc .unknown
    mov [r12+28],eax
    mov eax,[r13+(xhci_generation-xhci_inst_r1)]
    cmp eax,[r12+16]
    jne .unknown
    mov dword [r12],1
    mov eax,1
    jmp .out
.unknown:
    xor eax,eax
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
