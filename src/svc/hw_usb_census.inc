; C3 retained USB selections joined to the actual enumeration HC+port token.
; No port transfer, controller call, physical address, USB serial or MAC.
; usb=backend,state,enum-index,port,VID|PID<<16,device-class24,bcdDevice,
;     actual-interface-class24(FFFFFFFF unknown),number-of-enum-matches.
; IDs1..4 HID state ordinals (NOT enum indexes),5 AX179,6 AX179B,7 ECM,8 NCM,9 BOT.
hw_r_bindusb:
    push rbx
    push r12
    push r13
    sub rsp,32
    lea rdi,[rel hwc_usb_scope]
    call hw_puts
    mov r12d,1
.hid:
    mov edi,r12d
    mov rsi,rsp
    call usb_hid_census_snapshot
    mov rdi,[rsp+16]
    movzx esi,byte [rsp+2]
    mov edx,r12d
    movzx ecx,byte [rsp]
    mov r8d,[rsp+24]
    call hw_usb_census_emit
    inc r12d
    cmp r12d,4
    jbe .hid
    mov rdi,[rel ax_hc]
    movzx esi,byte [rel ax_port]
    mov edx,5
    movzx ecx,byte [rel ax_present]
    mov r8d,-1
    call hw_usb_census_emit
    mov rdi,[rel axb_hc]
    movzx esi,byte [rel axb_port]
    mov edx,6
    movzx ecx,byte [rel axb_state]     ; includes parked/retired ownership
    mov r8d,-1
    call hw_usb_census_emit
    lea rdi,[rel cdc_ecm_cfgbuf]
    mov esi,256                     ; maintained driver configuration caps
    movzx edx,byte [rel cdc_ecm_comm_if]
    call hw_usb_interface_class
    mov r8d,eax
    mov rdi,[rel cdc_ecm_hc]
    movzx esi,byte [rel cdc_ecm_port]
    mov edx,7
    movzx ecx,byte [rel cdc_ecm_present]
    call hw_usb_census_emit
    lea rdi,[rel cdc_ncm_cfgbuf]
    mov esi,512
    movzx edx,byte [rel cdc_ncm_comm_if]
    call hw_usb_interface_class
    mov r8d,eax
    mov rdi,[rel cdc_ncm_hc]
    movzx esi,byte [rel cdc_ncm_port]
    mov edx,8
    movzx ecx,byte [rel cdc_ncm_present]
    call hw_usb_census_emit
    lea rdi,[rel msd_cfgbuf]
    mov esi,256
    movzx edx,byte [rel msd_iface]
    call hw_usb_interface_class
    mov r8d,eax
    mov rdi,[rel msd_hc]
    movzx esi,byte [rel msd_port]
    mov edx,9
    movzx ecx,byte [rel msd_bound]
    call hw_usb_census_emit
    add rsp,32
    pop r13
    pop r12
    pop rbx
    ret
hwc_usb_scope: db " scope=usb-bindings-v1 n=9 audio=unobserved",0

; Cached validated configuration only. Pure, bounded and no guessed class.
; RDI=buffer, ESI=actual capacity, EDX=interface number -> EAX=class24/-1.
hw_usb_interface_class:
    cmp esi,9
    jb .none
    cmp word [rdi],0x0209
    jne .none
    movzx r8d,word [rdi+2]
    cmp r8d,9
    jb .none
    cmp r8d,esi
    ja .none
    xor ecx,ecx
.walk:
    mov eax,r8d
    sub eax,ecx
    cmp eax,2
    jb .none
    movzx eax,byte [rdi+rcx]
    cmp eax,2
    jb .none
    lea r9d,[rcx+rax]
    cmp r9d,r8d
    ja .none
    cmp byte [rdi+rcx+1],4
    jne .next
    cmp eax,9
    jb .none
    cmp byte [rdi+rcx+2],dl
    jne .next
    cmp byte [rdi+rcx+3],0
    jne .next
    movzx eax,byte [rdi+rcx+5]
    shl eax,16
    movzx edx,byte [rdi+rcx+6]
    shl edx,8
    or eax,edx
    movzx edx,byte [rdi+rcx+7]
    or eax,edx
    ret
.next:
    mov ecx,r9d
    jmp .walk
.none:
    mov eax,-1
    ret

hw_usb_census_emit:
    push rbx
    push r13
    push r14
    push r15
    sub rsp,56
    mov [rsp],rdi                  ; private HC pointer, never serialized
    mov [rsp+8],edx
    mov [rsp+12],ecx
    mov dword [rsp+16],255
    mov [rsp+20],esi
    mov qword [rsp+24],0
    mov dword [rsp+32],0
    mov [rsp+36],r8d
    mov dword [rsp+40],0
    test ecx,ecx
    jz .emit
    call usb_dev_count
    mov r15d,eax
    xor r13d,r13d
.lookup:
    cmp r13d,r15d
    jae .emit
    cmp r13d,16
    jae .emit
    mov edi,r13d
    call usb_dev_is_null
    test eax,eax
    jnz .advance
    mov edi,r13d
    call usb_dev_hc
    cmp rax,[rsp]
    jne .advance
    mov edi,r13d
    call usb_dev_addr
    cmp eax,[rsp+20]
    jne .advance
    mov edi,r13d
    call usb_dev_desc_ptr
    test rax,rax
    jz .advance
    cmp word [rax],0x0112
    jne .advance
    inc dword [rsp+40]
    mov [rsp+16],r13d
    mov edx,[rax+8]
    mov [rsp+24],edx
    movzx edx,word [rax+12]
    mov [rsp+32],edx
    movzx edx,byte [rax+4]
    shl edx,16
    movzx ecx,byte [rax+5]
    shl ecx,8
    or edx,ecx
    movzx ecx,byte [rax+6]
    or edx,ecx
    mov [rsp+28],edx
.advance:
    inc r13d
    jmp .lookup
.emit:
    lea rdi,[rel hwc_usb_row]
    call hw_puts
    lea r14,[rsp+8]
    xor r13d,r13d
.column:
    test r13d,r13d
    jz .value
    lea rdi,[rel str_hw_comma]
    call hw_puts
.value:
    mov edi,[r14+r13*4]
    call hw_put_dec
    inc r13d
    cmp r13d,9
    jb .column
    add rsp,56
    pop r15
    pop r14
    pop r13
    pop rbx
    ret
hwc_usb_row: db " usb=",0
