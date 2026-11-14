; Selected instance formatter. R12=internal64B snapshot, R13D=1net/2block.
; Pure cached owner joins: no callback to selected backend, IO or pointer output.
; sel=key,family,owner,state,transport,root,bdf,unit,id,class24,rev,matches.
; state0none,1owner matched,2unknown,3contradictory; transport1PCI2VMD3USB4domain.
hw_registry_instance:
    push rbx
    push r14
    push r15
    sub rsp,96
    mov rdi,rsp
    xor eax,eax
    mov ecx,12
    cld
    rep stosd
    mov [rsp],r13d
    mov eax,[r12+4]
    mov [rsp+4],eax
    mov eax,[r12+28]
    mov [rsp+8],eax
    mov eax,[r12+24]
    mov [rsp+12],eax
    mov eax,[r12+32]
    mov [rsp+16],eax
    mov eax,[r12+44]
    mov [rsp+28],eax
    cmp dword [r12+24],1
    jne .emit
    cmp dword [r12+32],1
    je .pci
    cmp dword [r12+32],2
    je .vmd
    cmp dword [r12+32],3
    je .usb
    cmp dword [r12+32],4
    jne .emit
    test dword [r12+60],4           ; actual assigned device retained
    jnz .pci
    jmp .emit
.pci:
    mov eax,[r12+36]
    mov [rsp+24],eax
    xor ebx,ebx
.pci_next:
    cmp ebx,[rel hw_list_n]
    jae .emit
    cmp ebx,HW_LIST_MAX
    jae .emit
    mov eax,ebx
    shl eax,4
    lea rdx,[rel hw_list]
    add rdx,rax
    mov eax,[r12+36]
    cmp [rdx],eax
    jne .pci_advance
    inc dword [rsp+44]
    mov eax,[rdx+4]
    mov [rsp+32],eax
    mov eax,[rdx+8]
    movzx ecx,al
    mov [rsp+40],ecx
    shr eax,8
    mov [rsp+36],eax
.pci_advance:
    inc ebx
    jmp .pci_next
.vmd:
    mov eax,[rel vmd_root_bus]
    cmp eax,255
    ja .bad
    shl eax,8
    mov ecx,[rel vmd_root_dev]
    cmp ecx,31
    ja .bad
    shl ecx,3
    or eax,ecx
    mov ecx,[rel vmd_root_fn]
    cmp ecx,7
    ja .bad
    or eax,ecx
    mov [rsp+20],eax
    xor ebx,ebx
.vmd_next:
    movzx eax,byte [rel vmd_child_count]
    cmp eax,8
    ja .unknown
    cmp ebx,eax
    jae .emit
    mov edi,ebx
    lea rsi,[rsp+64]
    call vmd_child_identity_snapshot
    test eax,eax
    jz .vmd_advance
    mov rax,[rsp+64]                 ; exact config pointer for NVMe
    cmp dword [r12+4],1
    jne .vmd_compare
    mov rax,[rsp+72]                 ; exact retained AHCI ABAR
.vmd_compare:
    cmp rax,[r12+36]
    jne .vmd_advance
    inc dword [rsp+44]
    mov eax,[rsp+84]
    mov [rsp+24],eax
    mov eax,[rsp+89]
    mov [rsp+32],eax
    mov eax,[rsp+80]
    mov [rsp+36],eax
    movzx eax,byte [rsp+93]
    mov [rsp+40],eax
.vmd_advance:
    inc ebx
    jmp .vmd_next
.usb:
    call usb_dev_count
    cmp eax,16
    ja .unknown
    mov r15d,eax
    xor ebx,ebx
.usb_next:
    cmp ebx,r15d
    jae .emit
    mov edi,ebx
    call usb_dev_is_null
    test eax,eax
    jnz .usb_advance
    mov edi,ebx
    call usb_dev_hc
    cmp rax,[r12+36]
    jne .usb_advance
    mov edi,ebx
    call usb_dev_addr
    cmp eax,[r12+44]
    jne .usb_advance
    mov edi,ebx
    call usb_dev_desc_ptr
    test rax,rax
    jz .usb_advance
    cmp word [rax],0x0112
    jne .usb_advance
    inc dword [rsp+44]
    mov [rsp+24],ebx
    mov edx,[rax+8]
    mov [rsp+32],edx
    movzx edx,word [rax+12]
    mov [rsp+40],edx
    movzx edx,byte [rax+4]
    shl edx,16
    movzx ecx,byte [rax+5]
    shl ecx,8
    or edx,ecx
    movzx ecx,byte [rax+6]
    or edx,ecx
    mov [rsp+36],edx
.usb_advance:
    inc ebx
    jmp .usb_next
.bad:
    mov dword [rsp+12],3
    jmp .emit
.unknown:
    mov dword [rsp+12],2
.emit:
    lea rdi,[rel hwc_registry_sel]
    call hw_puts
    xor ebx,ebx
    mov r14,rsp
.column:
    test ebx,ebx
    jz .value
    lea rdi,[rel str_hw_comma]
    call hw_puts
.value:
    mov edi,[r14+rbx*4]
    call hw_put_dec
    inc ebx
    cmp ebx,12
    jb .column
    cmp r13d,1
    jne .done
    cmp dword [r12+4],9
    jne .done
    call hw_registry_domain
.done:
    add rsp,96
    pop r15
    pop r14
    pop rbx
    ret
hwc_registry_sel: db " sel=",0

; Same immutable selected snapshot; no second owner read or private locator.
hw_registry_domain:
    push rbx
    push r14
    sub rsp,32
    mov eax,[r12+28]
    mov [rsp],eax
    mov eax,[r12+60]
    mov ecx,eax
    and eax,1
    mov [rsp+4],eax
    mov eax,[r12+48]
    mov [rsp+8],eax
    mov eax,[r12+52]
    mov [rsp+12],eax
    mov eax,ecx
    shr eax,1
    and eax,1
    mov [rsp+16],eax
    mov eax,[r12+56]
    mov [rsp+20],eax
    and ecx,~7
    mov [rsp+24],ecx
    lea rdi,[rel hwc_registry_domain]
    call hw_puts
    mov r14,rsp
    xor ebx,ebx
.column:
    test ebx,ebx
    jz .value
    lea rdi,[rel str_hw_comma]
    call hw_puts
.value:
    mov edi,[r14+rbx*4]
    call hw_put_dec
    inc ebx
    cmp ebx,7
    jb .column
    add rsp,32
    pop r14
    pop rbx
    ret
hwc_registry_domain: db " domain=",0
