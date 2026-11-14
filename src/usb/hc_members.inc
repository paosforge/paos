; Read-only cached usbhc_ops membership. RSI -> 128B caller buffer:
; u32 count,flags; up to6 {ordinal,family,health,priority,ops_mask} u32s.
; Registration publishes stable boot-owned objects then increments count.
; No registry lock exists: changed publication count is explicit flag8;
; flag1 means invalid/duplicate/overfull. This is not an atomic health snapshot.
; Only retained RAM and xhci_hc_instance (pure handle lookup), no callbacks/IO.
usb_hc_members_snapshot_impl:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12,rsi
    mov rdi,rsi
    xor eax,eax
    mov ecx,32
    cld
    rep stosd
    mov eax,[rel usb_hc_count]
    mov [r12],eax
    cmp eax,USB_MAX_HC
    ja .bad
    xor r13d,r13d
.walk:
    cmp r13d,[r12]
    jae .stable
    lea rax,[rel usb_hc_arr]
    mov rbx,[rax+r13*8]
    test rbx,rbx
    jz .bad
    xor ecx,ecx
.duplicate:
    cmp ecx,r13d
    jae .valid
    cmp rbx,[rax+rcx*8]
    je .bad
    inc ecx
    jmp .duplicate
.valid:
    cmp dword [rbx+dev.class],CLASS_USBHC
    jne .bad
    mov r15,[rbx+dev.ops]
    test r15,r15
    jz .bad
    mov eax,r13d
    imul eax,eax,20
    lea r14,[r12+rax+8]
    lea eax,[r13+1]
    mov [r14],eax
    mov dword [r14+4],255
    mov eax,[rbx+dev.health]
    mov [r14+8],eax
    mov eax,[rbx+dev.prio]
    mov [r14+12],eax
    mov rdi,rbx
    call xhci_hc_instance
    test eax,eax
    js .null
    mov dword [r14+4],1
    jmp .mask
.null:
    lea rax,[rel usb_nulldev_dev]
    cmp rbx,rax
    jne .mask
    mov dword [r14+4],2
.mask:
    xor ecx,ecx
    xor eax,eax
.op:
    cmp qword [r15+rcx*8],0
    je .absent
    bts eax,ecx
.absent:
    inc ecx
    cmp ecx,15
    jb .op
    mov [r14+16],eax
    inc r13d
    jmp .walk
.bad:
    or dword [r12+4],1
.stable:
    mov eax,[rel usb_hc_count]
    cmp eax,[r12]
    je .done
    or dword [r12+4],8
.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
