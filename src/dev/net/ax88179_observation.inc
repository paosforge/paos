; Explicit native AX snapshot. RDI=88-byte output, EAX=0.
; dwords0..3: present, registered slot, NIC health, frame counters available;
; qwords2..3: RX/TX frames; bytes32..71: xHCI readiness snapshot;
; dwords18..21: retained VID/PID, bcdDevice, actual USB port token, reserved.
; Counters are software completions, not wire delivery. No transfer or retry.
ax88179_observation_snapshot:
    push rbx
    mov rbx,rdi
    xor eax,eax
    mov ecx,11
    cld
    rep stosq
    mov dword [rbx+4],-1
    mov dword [rbx+8],-1
    cmp byte [rel ax_present],1
    jne .out
    mov dword [rbx],1
    mov eax,[rel ax_reg_rc]
    mov [rbx+4],eax
    mov eax,[rel ax_dev+dev.health]
    mov [rbx+8],eax
    mov eax,[rel ax_devbuf+8]
    mov [rbx+72],eax
    movzx eax,word [rel ax_devbuf+12]
    mov [rbx+76],eax
    movzx eax,byte [rel ax_port]
    mov [rbx+80],eax
    lea rdi,[rel ax_dev]
    call netdev_frame_stats
    test eax,eax
    jnz .host
    mov dword [rbx+12],1
    mov [rbx+16],rdx
    mov [rbx+24],rcx
.host:
    mov rdi,[rel ax_hc]
    movzx esi,byte [rel ax_port]
    lea rdx,[rbx+32]
    call xhci_readiness_snapshot
.out:
    xor eax,eax
    pop rbx
    ret
