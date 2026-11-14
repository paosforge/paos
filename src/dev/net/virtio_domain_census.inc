; Read-only selected-owner census. RDI=actual selected dev, RSI=64B output
; whose first24B belong to netdev. Never call an ops pointer or launch a guest.
; Tail: state/owner/kind/locator64/unit/mode/lifecycle/readyGeneration/flags.
; flags1 active,2 guest owner,4 assigned BDF present,8 changed snapshot.
virtio_domain_census_read:
    push rbx
    push r12
    push r13
    push r14
    mov rbx,rdi
    mov r12,rsi
    mov qword [r12+24],0
    mov qword [r12+32],0
    mov qword [r12+40],0
    mov qword [r12+48],0
    mov qword [r12+56],0
    mov dword [r12+24],2
    lea rax,[rel domain_ctx1]
    cmp rbx,rax
    jne .out
    mov dword [r12+28],1
    mov dword [r12+32],4
    cmp [rbx+dev.priv],rbx
    jne .bad
%ifdef PAOS_NIC_ASSIGNMENT
    movzx r14d,byte [rel domain_capstone_nd]
    cmp r14d,1
    ja .bad
%endif
    mov rdi,rbx
    call virtio_domain_policy_generation
    mov r13d,eax                     ; bracket the retained identity copy
    mov dword [r12+24],1
    mov eax,[rbx+virtio_domain_ctx.mode]
    mov [r12+48],eax
    cmp eax,1
    ja .bad
    mov eax,[rbx+virtio_domain_ctx.lifecycle]
    mov [r12+52],eax
    cmp eax,3
    ja .bad
    movzx eax,byte [rel domain_capstone_active]
    cmp eax,1
    ja .bad
    mov [r12+60],eax
    mov eax,[rbx+virtio_domain_ctx.owner]
    cmp eax,1
    ja .bad
    shl eax,1
    or [r12+60],eax
%ifdef PAOS_NIC_ASSIGNMENT
    test r14d,r14d
    jz .legacy_assignment
    mov eax,[rel nd_attached]
    jmp .assignment
.legacy_assignment:
%endif
    movzx eax,byte [rel vtd_secondary_found]
.assignment:
    cmp eax,1
    ja .bad
    test eax,eax
    jz .generation
    or dword [r12+60],4
%ifdef PAOS_NIC_ASSIGNMENT
    test r14d,r14d
    jz .legacy_bdf
    mov eax,[rel nd_bdf]
    jmp .bdf
.legacy_bdf:
%endif
    mov eax,[rel vtd_secondary_bdf]
.bdf:
    mov [r12+36],eax
.generation:
    mov [r12+56],r13d
    mov rdi,rbx
    call virtio_domain_policy_generation
    cmp eax,r13d
    jne .changed
%ifdef PAOS_NIC_ASSIGNMENT
    movzx eax,byte [rel domain_capstone_nd]
    cmp eax,r14d
    jne .changed
%endif
    cmp [rbx+dev.priv],rbx
    jne .changed
    mov eax,[rbx+virtio_domain_ctx.mode]
    cmp eax,[r12+48]
    jne .changed
    mov eax,[rbx+virtio_domain_ctx.lifecycle]
    cmp eax,[r12+52]
    jne .changed
    movzx eax,byte [rel domain_capstone_active]
    mov ecx,[rbx+virtio_domain_ctx.owner]
    shl ecx,1
    or eax,ecx
%ifdef PAOS_NIC_ASSIGNMENT
    test r14d,r14d
    jz .legacy_assignment_check
    mov ecx,[rel nd_attached]
    jmp .assignment_check
.legacy_assignment_check:
%endif
    movzx ecx,byte [rel vtd_secondary_found]
.assignment_check:
    shl ecx,2
    or eax,ecx
    cmp eax,[r12+60]
    jne .changed
    test eax,4
    jz .out
%ifdef PAOS_NIC_ASSIGNMENT
    test r14d,r14d
    jz .legacy_bdf_check
    mov eax,[rel nd_bdf]
    jmp .bdf_check
.legacy_bdf_check:
%endif
    mov eax,[rel vtd_secondary_bdf]
.bdf_check:
    cmp eax,[r12+36]
    jne .changed
    jmp .out
.bad:
    mov dword [r12+24],3
    jmp .out
.changed:
    or dword [r12+60],8
    mov dword [r12+24],2
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
