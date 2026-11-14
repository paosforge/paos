; Only an explicitly prepared PaOS capture file on an actual USB device path
; is writable. READ|WRITE, never CREATE, SetInfo, partition or raw Block I/O.
capture_usb_device_path:                ; RSI path, EAX=1 single USB path
    xor ecx,ecx
    xor r10d,r10d
.next:
    cmp ecx,4092
    ja .bad
    movzx eax,word [rsi+2]
    cmp eax,4
    jb .bad
    add ecx,eax
    cmp ecx,4096
    ja .bad
    cmp byte [rsi],0x7f
    je .end
    cmp byte [rsi],3
    jne .advance
    cmp byte [rsi+1],5                 ; USB messaging node
    jne .class
    cmp eax,6
    jb .bad
    jmp .usb
.class:
    cmp byte [rsi+1],15                ; USB class
    jne .wwid
    cmp eax,11
    jb .bad
    jmp .usb
.wwid:
    cmp byte [rsi+1],16                ; USB WWID
    jne .advance
    cmp eax,10
    jb .bad
.usb:
    mov r10d,1
.advance:
    add rsi,rax
    jmp .next
.end:
    cmp byte [rsi+1],0xff              ; no alternate device-path instance
    jne .bad
    cmp eax,4
    jne .bad
    mov eax,r10d
    ret
.bad:
    xor eax,eax
    ret

capture_marker_valid:                  ; RSI fixed64 header
    mov rax,CAPTURE_USB_MAGIC
    cmp [rsi],rax
    je capture_header_identity
    mov rax,CAPTURE_MAGIC
    cmp [rsi],rax
    jne .bad
    ; An earlier interrupted export may be retried from the retained RAM.
    cmp dword [rsi+40],1
    jne .bad
    jmp capture_header_identity
.bad:
    xor eax,eax
    ret

capture_find_usb:                       ; EAX=0 exactly one prepared destination
    push rbx
    push r12
    push r13
    push r14
    push r15
    xor r14d,r14d
    xor r15d,r15d
    mov qword [rel capture_handles],0
    mov qword [rel capture_handle_count],0
    mov ecx,2                          ; ByProtocol
    lea rdx,[rel simple_fs_guid]
    xor r8d,r8d
    lea r9,[rel capture_handle_count]
    mov rax,[rel boot_services]
    PBM_FW_ENTER 40
    lea rbx,[rel capture_handles]
    mov [rsp+32],rbx
    call [rax+0x138]                    ; LocateHandleBuffer
    PBM_FW_LEAVE 40
    test rax,rax
    jnz .fail
    mov r12,[rel capture_handle_count]
    cmp r12,64
    ja .fail
    mov rbx,[rel capture_handles]
    test rbx,rbx
    jz .fail
.next:
    test r12,r12
    jz .finish
    mov r13,[rbx]
    mov rcx,r13
    lea rdx,[rel device_path_guid]
    lea r8,[rel capture_scan_path]
    mov rax,[rel boot_services]
    PBM_FW_ENTER 32
    call [rax+0x98]                     ; HandleProtocol(DevicePath)
    PBM_FW_LEAVE 32
    test rax,rax
    jnz .advance
    mov rsi,[rel capture_scan_path]
    test rsi,rsi
    jz .advance
    call capture_usb_device_path
    test eax,eax
    jz .advance
    mov rcx,r13
    lea rdx,[rel simple_fs_guid]
    lea r8,[rel capture_scan_fs]
    mov rax,[rel boot_services]
    PBM_FW_ENTER 32
    call [rax+0x98]
    PBM_FW_LEAVE 32
    test rax,rax
    jnz .advance
    mov rcx,[rel capture_scan_fs]
    test rcx,rcx
    jz .advance
    lea rdx,[rel capture_candidate_root]
    mov qword [rdx],0
    mov rax,rcx
    PBM_FW_ENTER 32
    call [rax+8]                        ; OpenVolume
    PBM_FW_LEAVE 32
    test rax,rax
    jnz .advance
    mov r14,[rel capture_candidate_root]
    test r14,r14
    jz .advance
    mov rcx,r14
    lea rdx,[rel capture_candidate]
    mov qword [rdx],0
    lea r8,[rel capture_path]
    mov r9d,3                          ; READ|WRITE; no CREATE
    PBM_FW_ENTER 40
    mov qword [rsp+32],0
    call [r14+8]
    PBM_FW_LEAVE 40
    test rax,rax
    jnz .close_current
    mov r15,[rel capture_candidate]
    test r15,r15
    jz .close_current
    mov qword [rel capture_size],64
    mov rcx,r15
    lea rdx,[rel capture_size]
    lea r8,[rel capture_scratch]
    PBM_FW_ENTER 32
    call [r15+32]
    PBM_FW_LEAVE 32
    test rax,rax
    jnz .close_current
    cmp qword [rel capture_size],64
    jne .close_current
    lea rsi,[rel capture_scratch]
    call capture_marker_valid
    test eax,eax
    jz .close_current
    mov qword [rel capture_size],4096
    mov rcx,r15
    lea rdx,[rel capture_file_info_guid]
    lea r8,[rel capture_size]
    lea r9,[rel capture_scratch]
    PBM_FW_ENTER 32
    call [r15+64]                       ; GetInfo EFI_FILE_INFO
    PBM_FW_LEAVE 32
    test rax,rax
    jnz .close_current
    cmp qword [rel capture_size],80
    jb .close_current
    cmp qword [rel capture_size],4096
    ja .close_current
    cmp qword [rel capture_scratch+8],CAPTURE_BYTES
    jne .close_current
    test qword [rel capture_scratch+72],0x10 ; no directory
    jnz .close_current
    cmp qword [rel capture_file],0
    jne .fail                          ; ambiguity: no writes to either candidate
    mov [rel capture_file],r15
    mov [rel capture_root],r14
    xor r15d,r15d
    xor r14d,r14d
    jmp .advance
.close_current:
    call .close_handles
.advance:
    add rbx,8
    dec r12
    jmp .next
.finish:
    cmp qword [rel capture_file],0
    je .fail
    xor r13d,r13d
    jmp .free_array
.fail:
    call .close_handles
    call capture_close_destination
    mov r13d,1
.free_array:
    mov rcx,[rel capture_handles]
    test rcx,rcx
    jz .out
    mov rax,[rel boot_services]
    PBM_FW_ENTER 32
    call [rax+0x48]
    PBM_FW_LEAVE 32
    mov qword [rel capture_handles],0
.out:
    mov eax,r13d
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.close_handles:
    test r15,r15
    jz .root
    mov rcx,r15
    PBM_FW_ENTER 32
    call [r15+16]
    PBM_FW_LEAVE 32
    xor r15d,r15d
.root:
    test r14,r14
    jz .closed
    mov rcx,r14
    PBM_FW_ENTER 32
    call [r14+16]
    PBM_FW_LEAVE 32
    xor r14d,r14d
.closed:
    ret

capture_close_destination:
    mov rcx,[rel capture_file]
    test rcx,rcx
    jz .root
    mov qword [rel capture_file],0
    mov rax,rcx
    PBM_FW_ENTER 32
    call [rax+16]
    PBM_FW_LEAVE 32
.root:
    mov rcx,[rel capture_root]
    test rcx,rcx
    jz .out
    mov qword [rel capture_root],0
    mov rax,rcx
    PBM_FW_ENTER 32
    call [rax+16]
    PBM_FW_LEAVE 32
.out:
    ret
