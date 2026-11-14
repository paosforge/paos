; One trusted native SSH service on an already validated public DHCP primary.
; RDI=expected MAC, ESI=expected IPv4, RDX=SSH accept callback -> RAX=0/-1.
; The SSH adapter supplies its fixed native callback, never command input. An
; ungranted listener cannot be adopted, and an existing grant cannot change
; callbacks. No live_init, TCB reset, epoch reset, callbacks, TX or waits here.
; tcp_live_lock protects registration and the retained exact callback grant.
tcp_public_ssh_bind:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12d, esi
    mov  r13, rdx
    test rbx, rbx
    jz   .fail
    test r12d, r12d
    jz   .fail
    test r13, r13
    jz   .fail
    call tcp_live_try_acquire
    test rax, rax
    jnz  .fail
    cmp  byte [rel tcp_client_ready], 1
    jne  .unlock_fail
    cmp  byte [rel tcp_client_public], 1
    jne  .unlock_fail
    cmp  byte [rel tcp_client_alias_ready], 0
    jne  .unlock_fail
    cmp  dword [rel tcp_client_alias_ip], 0
    jne  .unlock_fail
    cmp  r12d, [rel tcp_live_ip]
    jne  .unlock_fail
    mov  eax, [rbx]
    cmp  eax, [rel tcp_live_mac]
    jne  .unlock_fail
    mov  ax, [rbx + 4]
    cmp  ax, [rel tcp_live_mac + 4]
    jne  .unlock_fail
    mov  rax, [rel tcp_public_ssh_callback]
    test rax, rax
    jz   .listeners
    cmp  rax, r13
    jne  .unlock_fail
.listeners:
    call tcp_client_no_listeners_locked
    test eax, eax
    jnz  .unlock_fail
    mov  edi, 22
    mov  rsi, r13
    call tcp_listener_register
    test rax, rax
    jnz  .unlock_fail
    mov  [rel tcp_public_ssh_callback], r13
    call tcp_live_lock_release
    xor  eax, eax
    jmp  .out
.unlock_fail:
    call tcp_live_lock_release
.fail:
    mov  rax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret
