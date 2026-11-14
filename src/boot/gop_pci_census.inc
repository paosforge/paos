; Common C3 selected-GOP identity, PRE-EBS only. No connect/selection/mode or
; allocation. Entry RSP%16=8 (called inside selected_pci_depth's EFI frame).
; Retained six uint32: state, segment, packed BDF, VIDPID, class24, revision.
; State0 no selected path,1 complete,2 unavailable/unproven,3 contradictory
; firmware identity. Publish fields together only after all reads succeed.
gop_census_pci_capture:
    push rbx
    push r12
    sub rsp,120                  ; MS shadow + fifth arg + private OUT slots
    xor eax,eax
    mov [rel gop_census_pci+4],eax
    mov [rel gop_census_pci+8],eax
    mov [rel gop_census_pci+12],eax
    mov [rel gop_census_pci+16],eax
    mov [rel gop_census_pci+20],eax
    mov dword [rel gop_census_pci],2
    cmp dword [rel gop_census_path_state],1
    jne .done
    mov rax,[rel gop_devpath_ptr]
    test rax,rax
    jz .done
    mov [rsp+40],rax              ; copy; firmware must not replace owner path
    mov qword [rsp+48],0
    mov r12,[rel boot_services]
    test r12,r12
    jz .done
    lea rcx,[rel pci_io_guid]
    lea rdx,[rsp+40]
    lea r8,[rsp+48]
    call [r12+0xb8]               ; LocateDevicePath(PciIo,&pathCopy,&handle)
    test rax,rax
    jnz .done
    cmp qword [rsp+48],0
    je .done
    mov r8,[rsp+40]               ; exact unmatched suffix node
    test r8,r8
    jz .done
    mov rdx,[rel gop_devpath_ptr]
    xor r9d,r9d
    xor r10d,r10d                ; last consumed PCI node, not a guessed bus
.prefix:
    cmp r9d,32
    jae .done
    cmp rdx,r8
    je .suffix_begin
    movzx ecx,word [rdx+2]
    cmp ecx,4
    jb .done
    cmp byte [rdx],0x7f
    je .done                     ; remainder outside original bounded path
    cmp byte [rdx],1
    jne .prefix_next
    cmp byte [rdx+1],1
    jne .prefix_next
    cmp ecx,6
    jb .done
    mov r10,rdx
.prefix_next:
    add rdx,rcx
    inc r9d
    jmp .prefix
.suffix_begin:
    test r10,r10
    jz .done
    mov [rsp+104],r10
.suffix:
    cmp r9d,32
    jae .done
    movzx ecx,word [rdx+2]
    cmp byte [rdx],0x7f
    je .end
    ; A selected display output may append ACPI ADR nodes. Unknown suffixes
    ; stay unproven. In particular, an unmatched PCI node means an ancestor.
    cmp byte [rdx],2
    jne .done
    cmp byte [rdx+1],3
    jne .done
    cmp ecx,8
    jb .done
    test ecx,3
    jnz .done
    add rdx,rcx
    inc r9d
    jmp .suffix
.end:
    cmp byte [rdx+1],0xff
    jne .done
    cmp ecx,4
    jne .done
    mov qword [rsp+56],0
    mov rcx,[rsp+48]
    lea rdx,[rel pci_io_guid]
    lea r8,[rsp+56]
    call [r12+0x98]               ; HandleProtocol(matchedHandle,PciIo)
    test rax,rax
    jnz .done
    mov rbx,[rsp+56]
    test rbx,rbx
    jz .done
    mov qword [rsp+64],0
    mov qword [rsp+72],0
    mov qword [rsp+80],0
    mov qword [rsp+88],0
    mov rcx,rbx
    lea rdx,[rsp+64]
    lea r8,[rsp+72]
    lea r9,[rsp+80]
    lea rax,[rsp+88]
    mov [rsp+32],rax
    call [rbx+112]               ; GetLocation(This,&seg,&bus,&dev,&fn)
    test rax,rax
    jnz .done
    cmp qword [rsp+64],65535
    ja .bad
    cmp qword [rsp+72],255
    ja .bad
    cmp qword [rsp+80],31
    ja .bad
    cmp qword [rsp+88],7
    ja .bad
    mov rdx,[rsp+104]
    mov eax,[rsp+80]
    cmp al,[rdx+5]
    jne .bad
    mov eax,[rsp+88]
    cmp al,[rdx+4]
    jne .bad
    mov dword [rsp+96],0xffffffff
    mov dword [rsp+100],0xffffffff
    mov rcx,rbx
    mov edx,2                    ; EfiPciIoWidthUint32
    xor r8d,r8d                  ; config VIDPID dword
    mov r9d,1
    lea rax,[rsp+96]
    mov [rsp+32],rax
    call [rbx+48]                ; PciIo.Pci.Read, not MMIO
    test rax,rax
    jnz .done
    cmp word [rsp+96],0
    je .bad
    cmp word [rsp+96],0xffff
    je .bad
    mov rcx,rbx
    mov edx,2
    mov r8d,8                    ; actual class/revision dword
    mov r9d,1
    lea rax,[rsp+100]
    mov [rsp+32],rax
    call [rbx+48]
    test rax,rax
    jnz .done
    mov eax,[rsp+64]
    mov [rel gop_census_pci+4],eax
    mov eax,[rsp+72]
    shl eax,8
    mov edx,[rsp+80]
    shl edx,3
    or eax,edx
    or eax,[rsp+88]
    mov [rel gop_census_pci+8],eax
    mov eax,[rsp+96]
    mov [rel gop_census_pci+12],eax
    mov eax,[rsp+100]
    movzx edx,al
    shr eax,8
    mov [rel gop_census_pci+16],eax
    mov [rel gop_census_pci+20],edx
    mov dword [rel gop_census_pci],1
    jmp .done
.bad:
    mov dword [rel gop_census_pci],3
.done:
    add rsp,120
    pop r12
    pop rbx
    ret
