; Original synchronous post-ACK failed-domain restart only. No command RX path.
; Same 80s owner deadline, bounded one-frame service per scheduler iteration.
; Traffic104: state4, request_ms8, reply_ms8, actual Ethernet/ARP42 each.
virtio_domain_restart_net_start:    ; RDI=fresh START, RSI=nonce17, RDX=fixed native DHCP handler
    push rbx
    push r12
    push r13
    mov [rel domain_restart_dhcp_accept],rdx
    mov r12,rdi
    mov r13,rsi
    lea rdi,[rel domain_restart_traffic]
    xor eax,eax
    mov ecx,104
    cld
    rep stosb
    mov [rel domain_restart_start],r12
    lea rdi,[rel domain_restart_nonce]
    mov rsi,r13
    mov ecx,17
    rep movsb
    mov dword [rel domain_restart_traffic],1
    pop r13
    pop r12
    pop rbx
    ret

; Identity checked before AND after primitive frame delivery/receive. Stable
; not-ready remains missing; an explicit generation/nonce/foreign binding is F.
virtio_domain_restart_net_current:
    cmp dword [rel domain_restart_traffic],1
    jne .no
    mov rax,[rel domain_restart_start]
    cmp rax,[rel nd_generation]
    jne .changed
    lea rdi,[rel domain_restart_nonce]
    lea rsi,[rel nd_nonce]
    mov ecx,17
    cld
    repe cmpsb
    jne .changed
    mov rax,[rel guestnet_domain_ctx]
    test rax,rax
    jz .no
    lea rdx,[rel domain_ctx1]
    cmp rax,rdx
    jne .changed
    cmp byte [rel domain_capstone_active],1
    jne .no
    cmp byte [rel domain_capstone_nd],1
    jne .changed
    call nd_ready_generation
    cmp eax,[rel domain_restart_start]
    jne .no
    mov eax,1
    ret
.changed:
    mov dword [rel domain_restart_traffic],2
.no:
    xor eax,eax
    ret

; Same transport primitive and return semantics. Capture only actual successful
; delivery, never queue acceptance/counters/readiness or an input echo.
virtio_domain_restart_net_deliver:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    call virtio_domain_restart_net_current
    mov r15d,eax
    mov rdi,r12
    mov rsi,r13
    mov rdx,r14
    call guestnet_rx_deliver
    mov ebx,eax
    cmp eax,1
    jne .out
    test r15d,r15d
    jz .out
    call virtio_domain_restart_net_current
    test eax,eax
    jz .out
    lea rax,[rel domain_ctx1]
    cmp r12,rax
    jne .out
    cmp r14,42
    jb .out
    cmp qword [rel domain_restart_traffic+4],0
    jne .out
    ; Canonical gateway probe only, from the current projected lease/MAC.
    cmp dword [r13],0xffffffff
    jne .out
    cmp word [r13+4],0xffff
    jne .out
    cmp word [r13+12],0x0608
    jne .out
    cmp dword [r13+14],0x00080100
    jne .out
    cmp dword [r13+18],0x01000406
    jne .out
    mov eax,[r13+6]
    cmp [r13+22],eax
    jne .out
    mov ax,[r13+10]
    cmp [r13+26],ax
    jne .out
    cmp dword [r13+28],0
    je .out
    cmp dword [r13+38],0
    je .out
    cmp dword [r13+32],0
    jne .out
    cmp word [r13+36],0
    jne .out
    call boot_ms_now
    mov [rel domain_restart_traffic+4],rax
    lea rdi,[rel domain_restart_traffic+20]
    mov rsi,r13
    mov ecx,42
    cld
    rep movsb
.out:
    mov eax,ebx
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

virtio_domain_restart_net_step:     ; ->1 terminal, 0 pending/missing
    push rbx
    call virtio_domain_restart_net_current
    test eax,eax
    jz .status
    cmp qword [rel domain_restart_traffic+12],0
    jne .status
    ; These are the maintained DHCP/ARP helpers; never command_udp_poll.
    call virtio_domain_transport_pump
    call virtio_domain_restart_net_current
    test eax,eax
    jz .status
    call dhcp_wire_tick
    call virtio_domain_gateway_resolution_tick
    lea rdi,[rel domain_ctx1]
    lea rsi,[rel domain_restart_rx]
    mov edx,DOMAIN_FRAME_MAX
    call virtio_domain_rx_poll
    test rax,rax
    jle .status
    mov rbx,rax
    call virtio_domain_restart_net_current
    test eax,eax
    jz .status
    lea rdi,[rel domain_restart_rx]
    mov rsi,rbx
    lea rdx,[rel domain_ctx1]
    cmp qword [rel domain_restart_dhcp_accept],0
    je .status
    call [rel domain_restart_dhcp_accept] ; native owner supplies strict DHCP only
    call virtio_domain_restart_net_current
    test eax,eax
    jz .status
    cmp rbx,42
    jb .status
    cmp qword [rel domain_restart_traffic+4],0
    je .status
    lea rsi,[rel domain_restart_rx]
    cmp word [rsi+12],0x0608
    jne .status
    cmp word [rsi+20],0x0200
    jne .status
    mov eax,[rel domain_restart_traffic+20+38]
    cmp [rsi+28],eax
    jne .status
    mov eax,[rel domain_restart_traffic+20+28]
    cmp [rsi+38],eax
    jne .status
    ; Retain the candidate raw peer before independent shape/MAC validation.
    ; No cache insertion, readiness flag, security policy or ARP admission changes.
    lea rdi,[rel domain_restart_traffic+62]
    mov ecx,42
    cld
    rep movsb
    call boot_ms_now
    mov [rel domain_restart_traffic+12],rax
.status:
    xor eax,eax
    cmp dword [rel domain_restart_traffic],2
    je .terminal
    cmp qword [rel domain_restart_traffic+12],0
    je .out
.terminal:
    mov eax,1
.out:
    pop rbx
    ret

; RDI=original1536B caller record, known-v4 scatter into defined reserved space.
; Stop collecting at this original boundary, before final actual retirement.
virtio_domain_restart_net_pack:
    mov r8,rdi
    lea rsi,[rel domain_restart_traffic]
    lea rdi,[r8+1192]
    mov ecx,24
    cld
    rep movsb
    lea rdi,[r8+1296]
    mov ecx,24
    rep movsb
    lea rdi,[r8+1400]
    mov ecx,24
    rep movsb
    lea rdi,[r8+1496]
    mov ecx,32
    rep movsb
    mov dword [rel domain_restart_traffic],0
    mov qword [rel domain_restart_dhcp_accept],0
    ret

%macro WDATA_dev_net_restart_traffic 0
align 8
domain_restart_dhcp_accept: dq 0
domain_restart_start: dq 0
domain_restart_nonce: times 17 db 0
domain_restart_traffic: times 104 db 0
domain_restart_rx: times DOMAIN_FRAME_MAX db 0
%endmacro
WDATA_DEFER WDATA_dev_net_restart_traffic
