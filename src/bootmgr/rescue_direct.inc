; Authenticated direct Linux EFI Rescue. Called ONLY after the ordinary whole
; PE owner-manifest verification and pinned shim verification. No new pathname
; or trust override: .pinitrd belongs to that same held, verified source buffer.
; Format: PDRAMF01, u32 version=1/header=64, u64 initrd/cmdline lengths,
; 32-byte informational digest, UTF16 command line, 16-byte pad, initramfs.
; The authoritative authentication is the existing whole-PE descriptor/signature.
;
; Internal helpers preserve RBX/RBP/R12-R15. EFI callback is Microsoft x64 ABI.
direct_rescue_prepare:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,16                       ; LocateDevicePath temporary outputs only
    cmp qword [rel direct_initrd_handle],0
    jne .bad
    mov rbx,[rel verified_source_buffer]
    mov r12d,[rel verified_payload_size]
    test rbx,rbx
    jz .bad
    cmp r12d,64
    jb .bad
    mov eax,[rbx+60]
    mov edx,r12d
    sub edx,24
    cmp eax,edx
    ja .bad
    lea rbp,[rbx+rax]
    cmp dword [rbp],0x00004550
    jne .bad
    movzx r13d,word [rbp+6]
    test r13d,r13d
    jz .bad
    cmp r13d,96
    ja .bad
    movzx edx,word [rbp+20]
    cmp edx,160
    jb .bad
    add rax,24
    add rax,rdx
    imul ecx,r13d,40
    add rcx,rax
    cmp rcx,r12
    ja .bad
    lea rbp,[rbx+rax]
    xor r14d,r14d
.section:
    mov rax,0x647274696e69702e       ; exact eight bytes .pinitrd
    cmp [rbp],rax
    jne .next
    test r14,r14
    jnz .bad                         ; ambiguous duplicate refused
    mov r14,rbp
.next:
    add rbp,40
    dec r13d
    jnz .section
    test r14,r14
    jz .ok                           ; ordinary UKI: preserve existing path
    mov eax,[r14+36]
    and eax,0xe0000040
    cmp eax,0x40000040               ; initialized, read-only, non-executable
    jne .bad
    mov r13d,[r14+8]                ; actual virtual bytes, not raw padding
    cmp r13d,80
    jb .bad
    mov edx,[r14+16]
    cmp edx,r13d
    jb .bad
    mov eax,[r14+20]
    add rdx,rax
    cmp rdx,r12
    ja .bad
    lea rbp,[rbx+rax]
    mov rax,0x3130464d41524450       ; PDRAMF01
    cmp [rbp],rax
    jne .bad
    cmp dword [rbp+8],1
    jne .bad
    cmp dword [rbp+12],64
    jne .bad
    mov r14,[rbp+16]
    test r14,r14
    jz .bad
    cmp r14,r12                      ; bounded UINTN, cannot wrap offset+len
    ja .bad
    mov r15,[rbp+24]
    cmp r15,2
    jb .bad
    cmp r15,166                      ; exact retained line fits; bounded shim buffer
    ja .bad
    test r15b,1
    jnz .bad
    lea rax,[r15+79]                 ; bound all command/data reads first
    and eax,-16
    lea rdx,[r14+rax]
    cmp rdx,r13
    jne .bad
    lea rsi,[rbp+64]
    mov rcx,r15
    shr ecx,1
    dec ecx
    jz .bad                          ; empty command line is not this format
.cmd:
    lodsw
    cmp ax,0x20
    jb .bad
    cmp ax,0x7e
    ja .bad
    loop .cmd
    cmp word [rsi],0
    jne .bad
    lea rax,[r15+79]                 ; align(64 + cmdline bytes,16)
    and eax,-16
    lea rax,[rbp+rax]
    mov [rel direct_initrd_address],rax
    mov [rel direct_initrd_length],r14
    lea rax,[rbp+64]
    mov [rel direct_cmdline],rax
    mov [rel direct_cmdline_bytes],r15d
    ; Prebuild shim's path + space + exact command line before attempt arming.
    lea rdi,[rel direct_shim_options]
    lea rsi,[rel ucs2_rescue]
    mov ecx,ucs2_rescue_end-ucs2_rescue-2
    rep movsb
    mov ax,0x20
    stosw
    mov rsi,[rel direct_cmdline]
    mov ecx,r15d
    rep movsb
    ; Do not steal an existing initrd provider (same upstream Linux media path).
    lea rax,[rel direct_initrd_path]
    mov [rsp],rax
    mov rax,[rel boot_services]
    lea rcx,[rel direct_load_file2_guid]
    mov qword [rsp+8],0
    mov rdx,rsp
    lea r8,[rsp+8]
    PBM_FW_ENTER 32
    call [rax+0xb8]                  ; LocateDevicePath
    PBM_FW_LEAVE 32
    mov rdx,0x800000000000000e       ; EFI_NOT_FOUND only
    cmp rax,rdx
    jne .bad
    lea rax,[rel direct_initrd_load_file]
    mov [rel direct_initrd_interface],rax
    mov rax,[rel boot_services]
    lea rcx,[rel direct_initrd_handle]
    lea rdx,[rel device_path_guid]
    lea r8,[rel direct_initrd_path]
    lea r9,[rel direct_load_file2_guid]
    PBM_FW_ENTER 48
    lea r10,[rel direct_initrd_interface]
    mov [rsp+32],r10
    mov qword [rsp+40],0
    call [rax+0x148]                 ; InstallMultipleProtocolInterfaces
    PBM_FW_LEAVE 48
    test rax,rax
    jnz .bad
    cmp qword [rel direct_initrd_handle],0
    je .bad
.ok:
    xor eax,eax
    jmp .out
.bad:
    mov eax,1
.out:
    add rsp,16
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Returns nonzero if a callback may still refer to the authenticated buffer.
; Caller then latches the existing fatal/nonreturn policy and MUST NOT free it.
direct_rescue_cleanup:
    mov rcx,[rel direct_initrd_handle]
    test rcx,rcx
    jz .clear
    mov rax,[rel boot_services]
    lea rdx,[rel device_path_guid]
    lea r8,[rel direct_initrd_path]
    lea r9,[rel direct_load_file2_guid]
    PBM_FW_ENTER 48
    lea r10,[rel direct_initrd_interface]
    mov [rsp+32],r10
    mov qword [rsp+40],0
    call [rax+0x150]                 ; UninstallMultipleProtocolInterfaces
    PBM_FW_LEAVE 48
    test rax,rax
    jnz .out                         ; retain handle/interface/storage on error
.clear:
    mov qword [rel direct_initrd_handle],0
    mov qword [rel direct_initrd_address],0
    mov qword [rel direct_initrd_length],0
    mov qword [rel direct_cmdline],0
    xor eax,eax
.out:
    ret

; Only local assignments after durable attempt arming, no new firmware call.
; RAX = existing child LoadedImage. RAX is preserved.
direct_rescue_set_options:
    cmp byte [rel rescue_direct_uki],1
    jne .shim
    mov edx,[rel direct_cmdline_bytes]
    mov rcx,[rel direct_cmdline]
    jmp .set
.shim:
    mov edx,[rel direct_cmdline_bytes]
    add edx,ucs2_rescue_end-ucs2_rescue
    lea rcx,[rel direct_shim_options]
.set:
    mov [rax+48],edx
    mov [rax+56],rcx
    ret

; EFI_LOAD_FILE2_PROTOCOL.LoadFile(This, FilePath, BootPolicy, Size*, Buffer).
direct_initrd_load_file:
    mov r10,[rsp+40]                 ; actual MSABI fifth argument
    lea rax,[rel direct_initrd_interface]
    cmp rcx,rax
    jne .invalid
    test rdx,rdx
    jz .invalid
    test r9,r9
    jz .invalid
    test r8b,r8b
    jnz .unsupported
    cmp dword [rdx],0x0004ff7f       ; remaining path must be END_ENTIRE
    jne .not_found
    mov rax,[rel direct_initrd_address]
    test rax,rax
    jz .not_found
    mov r11,[rel direct_initrd_length]
    test r11,r11
    jz .not_found
    test r10,r10
    jz .small
    cmp [r9],r11
    jb .small
    push rdi                         ; MSABI nonvolatile, including RSI/RDI
    push rsi
    mov rdi,r10
    mov rsi,rax
    mov rcx,r11
    cld
    rep movsb
    pop rsi
    pop rdi
    mov [r9],r11
    xor eax,eax
    ret
.small:
    mov [r9],r11
    mov rax,0x8000000000000005       ; EFI_BUFFER_TOO_SMALL
    ret
.invalid:
    mov rax,0x8000000000000002
    ret
.unsupported:
    mov rax,0x8000000000000003
    ret
.not_found:
    mov rax,0x800000000000000e
    ret

%macro PBM_DIRECT_RESCUE_RDATA 0
align 8
direct_load_file2_guid:
    dd 0x4006c0c1
    dw 0xfcb3,0x403e
    db 0x99,0x6d,0x4a,0x6c,0x87,0x24,0xe0,0x6d
direct_initrd_path:
    db 4,3,20,0
    dd 0x5568e427
    dw 0x68fc,0x4f3d
    db 0xac,0x74,0xca,0x55,0x52,0x31,0xcc,0x68
    db 0x7f,0xff,4,0
%endmacro
%macro PBM_DIRECT_RESCUE_DATA 0
align 8
direct_initrd_handle: dq 0
direct_initrd_address: dq 0
direct_initrd_length: dq 0
direct_cmdline: dq 0
direct_initrd_interface: dq 0
direct_cmdline_bytes: dd 0
direct_shim_options: times 232 db 0 ; path(66 bytes incl space) + <=166-byte line; pinned line164
%endmacro
