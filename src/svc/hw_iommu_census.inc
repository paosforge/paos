; C3 retained IOMMU selected-unit census. No IO/MMIO, allocation, ownership,
; ACPI discovery or init call. Internal RSI64B output is fully initialized.
; 14u32: backend,outcome,owned,state,type,flags,segment,devid-or-DRHDoffset,
; capoffset-or-scoped,physical-base-low,physical-base-high,matches,native,mapped.
; state0 no unit observed,1 exact unit,2 unavailable/ambiguous,3 contradiction.
; Physical register base is firmware unit identity, never an arena/host pointer.
hw_amdvi_census_snapshot:
    push r12
    mov r12,rsi
    mov rdi,rsi
    xor eax,eax
    mov ecx,8
    cld
    rep stosq
    mov dword [r12],1
    call amdvi_outcome_get
    mov [r12+4],eax
    mov [r12+48],edx
    mov [r12+52],ecx
    movzx eax,byte [rel amdvi_owned]
    mov [r12+8],eax
    mov rdx,[rel amdvi_ivhd]
    test rdx,rdx
    jz .done
    mov dword [r12+12],1
    mov dword [r12+44],1
    movzx eax,byte [rdx]
    mov [r12+16],eax
    cmp eax,0x10
    je .short
    cmp eax,0x11
    je .long
    cmp eax,0x40
    jne .bad
.long:
    cmp word [rdx+2],40
    jb .bad
    jmp .identity
.short:
    cmp word [rdx+2],24
    jb .bad
.identity:
    movzx eax,byte [rdx+1]
    mov [r12+20],eax
    movzx eax,word [rdx+16]
    mov [r12+24],eax
    test eax,eax
    jnz .bad
    movzx eax,word [rdx+4]
    mov [r12+28],eax
    movzx eax,word [rdx+6]
    mov [r12+32],eax
    mov rax,[rdx+8]
    mov [r12+36],rax
    test rax,rax
    jz .bad
    test eax,0x3fff
    jnz .bad
.done:
    pop r12
    ret
.bad:
    mov dword [r12+12],3
    jmp .done

hw_vtd_census_snapshot:
    push r12
    push r13
    push r14
    mov r12,rsi
    mov rdi,rsi
    xor eax,eax
    mov ecx,8
    cld
    rep stosq
    mov dword [r12],2
    call vtd_outcome_get
    mov [r12+4],eax
    movzx eax,byte [rel vtd_ready]
    mov [r12+8],eax
    movzx eax,byte [rel vtd_scoped_unit]
    mov [r12+32],eax
    mov r14,[rel vtd_unitb_base]
    mov [r12+36],r14
    mov r13,[rel vtd_dmar_snap]
    mov ecx,[rel vtd_dmar_snap_len]
    test ecx,ecx
    jz .done
    test r13,r13
    jz .unknown
    cmp ecx,8192                    ; actual VTD_DMAR_SNAP_PAGES=2
    ja .unknown
    cmp ecx,48
    jb .bad
    cmp dword [r13],0x52414d44       ; DMAR protected boot copy
    jne .bad
    cmp [r13+4],ecx
    jne .bad
    xor edx,edx
    xor eax,eax
.checksum:
    add al,[r13+rdx]
    inc edx
    cmp edx,ecx
    jb .checksum
    test al,al
    jnz .bad
    test r14,r14
    jz .done
    test r14d,4095
    jnz .bad
    mov r8d,ecx
    mov r9d,48
.next:
    cmp r9d,r8d
    jae .complete
    mov eax,r9d
    add eax,4
    cmp eax,r8d
    ja .bad
    movzx ecx,word [r13+r9+2]
    cmp ecx,4
    jb .bad
    mov eax,r9d
    add eax,ecx
    cmp eax,r8d
    ja .bad
    cmp word [r13+r9],0
    jne .advance
    cmp ecx,16
    jb .bad
    cmp [r13+r9+8],r14             ; exact full64-bit selected physical unit
    jne .advance
    inc dword [r12+44]
    movzx edx,byte [r13+r9+4]
    mov [r12+20],edx
    movzx edx,word [r13+r9+6]
    mov [r12+24],edx
    mov [r12+28],r9d
.advance:
    add r9d,ecx
    jmp .next
.complete:
    cmp dword [r12+44],1
    jne .unknown
    mov dword [r12+12],1
    cmp dword [r12+24],0
    jne .bad
.done:
    pop r14
    pop r13
    pop r12
    ret
.unknown:
    mov dword [r12+12],2
    jmp .done
.bad:
    mov dword [r12+12],3
    jmp .done

hw_iommu_render:
    push rbx
    push r12
    push r13
    sub rsp,64
    lea rdi,[rel hwc_iommu_scope]
    call hw_puts
    xor r13d,r13d
.next:
    mov rsi,rsp
    test r13d,r13d
    jnz .vtd
    call hw_amdvi_census_snapshot
    jmp .emit
.vtd:
    call hw_vtd_census_snapshot
.emit:
    lea rdi,[rel hwc_iommu_row]
    call hw_puts
    mov r12,rsp
    xor ebx,ebx
.column:
    test ebx,ebx
    jz .value
    lea rdi,[rel str_hw_comma]
    call hw_puts
.value:
    mov edi,[r12+rbx*4]
    call hw_put_dec
    inc ebx
    cmp ebx,14
    jb .column
    inc r13d
    cmp r13d,2
    jb .next
    add rsp,64
    pop r13
    pop r12
    pop rbx
    ret
hwc_iommu_scope: db " iommu_scope=selected-unit-v1",0
hwc_iommu_row: db " iommu=",0
