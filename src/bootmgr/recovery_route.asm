;; MODULE bootmgr/recovery_route
;; LAYER 0
;; EXPORTS r5_route_open, r5_route_close, r5_read_exact, r5_route_validate, r5_option_revalidate, r5_get_request, r5_set_request, r5_delete_request, r5_set_bootnext, r5_bootnext_absent, r5_nv_name, r5_nv_guid, r5_bootnext_name, r5_global_guid
;; IMPORTS boot/header, bootmgr/recovery_grant, boot/smbios, core/lib/sha256
;; CAPS
;; OWNER saga:boot
; Same code in native pre-EBS admission and maintained Manager. Only exact
; read-only files on LoadedImage.DeviceHandle are opened. Signed sizes bound
; every read/hash (<=16MiB/file, <=4 components); no directory/BootOrder guess.
; Runtime effects below have NO authorization of their own: only the claimed
; owner-grant power transaction calls them, after the normal storage gates.
%include "boot/recovery_contract.inc"
%macro R5_FW_ENTER 0
    push rbp
    mov rbp,rsp
    and rsp,-16
    sub rsp,48
%endmacro
%macro R5_FW_LEAVE 0
    mov rsp,rbp
    pop rbp
%endmacro

r5_route_open:
    mov qword [rel r5_root],0
    mov rax,[rel boot_services]
    test rax,rax
    jz .no
    mov rcx,[rel image_handle]
    lea rdx,[rel r5_loaded_guid]
    lea r8,[rel r5_loaded]
    R5_FW_ENTER
    call [rax+0x98]
    R5_FW_LEAVE
    test rax,rax
    jnz .no
    mov rax,[rel r5_loaded]
    test rax,rax
    jz .no
    mov rax,[rax+24]
    mov [rel r5_device],rax
    mov rcx,rax
    lea rdx,[rel r5_fs_guid]
    lea r8,[rel r5_fs]
    mov rax,[rel boot_services]
    R5_FW_ENTER
    call [rax+0x98]
    R5_FW_LEAVE
    test rax,rax
    jnz .no
    mov rax,[rel r5_fs]
    mov rcx,rax
    lea rdx,[rel r5_root]
    R5_FW_ENTER
    call [rax+8]
    R5_FW_LEAVE
    test rax,rax
    jnz .no
    mov rcx,[rel r5_device]
    lea rdx,[rel r5_dp_guid]
    lea r8,[rel r5_device_path]
    mov rax,[rel boot_services]
    R5_FW_ENTER
    call [rax+0x98]
    R5_FW_LEAVE
    test rax,rax
    jnz .no
    mov eax,1
    ret
.no:
    xor eax,eax
    ret
r5_route_close:
    mov rcx,[rel r5_root]
    test rcx,rcx
    jz .out
    R5_FW_ENTER
    call [rcx+16]
    R5_FW_LEAVE
    mov qword [rel r5_root],0
.out:
    ret

; RDI=UTF16 path, RSI=destination, EDX=exact count, EAX=1 success.
; Internal root and file are private to this BSP-only finite transaction.
r5_read_exact:
    push rbx
    push r12
    push r13
    mov r12,rsi
    mov r13d,edx
    call r5_file_open
    test eax,eax
    jz .no
    mov [rel r5_io_size],r13
    mov rcx,[rel r5_file]
    lea rdx,[rel r5_io_size]
    mov r8,r12
    R5_FW_ENTER
    call [rcx+32]
    R5_FW_LEAVE
    test rax,rax
    jnz .close_bad
    cmp [rel r5_io_size],r13
    jne .close_bad
    call r5_file_eof
    mov ebx,eax
    jmp .close
.close_bad:
    xor ebx,ebx
.close:
    call r5_file_close
    and eax,ebx
    jmp .out
.no:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret
r5_file_open:
    mov qword [rel r5_file],0
    mov rcx,[rel r5_root]
    test rcx,rcx
    jz .no
    lea rdx,[rel r5_file]
    mov r8,rdi
    mov r9d,1
    R5_FW_ENTER
    mov qword [rsp+32],0
    call [rcx+8]
    R5_FW_LEAVE
    test rax,rax
    sete al
    movzx eax,al
    ret
.no:
    xor eax,eax
    ret
r5_file_close:
    mov rcx,[rel r5_file]
    R5_FW_ENTER
    call [rcx+16]
    R5_FW_LEAVE
    test rax,rax
    sete al
    movzx eax,al
    ret
r5_file_eof:
    mov qword [rel r5_io_size],1
    mov rcx,[rel r5_file]
    lea rdx,[rel r5_io_size]
    lea r8,[rel r5_chunk]
    R5_FW_ENTER
    call [rcx+32]
    R5_FW_LEAVE
    test rax,rax
    jnz .no
    cmp qword [rel r5_io_size],0
    sete al
    movzx eax,al
    ret
.no:
    xor eax,eax
    ret

; RDI=path, RSI=expected SHA32, RDX=exact unsigned size, bounded <=16MiB.
r5_file_hash:
    push rbx
    push r12
    push r13
    mov r12,rsi
    mov r13,rdx
    test r13,r13
    jz .no
    cmp r13,0x1000000
    ja .no
    call r5_file_open
    test eax,eax
    jz .no
    lea rdi,[rel r5_sha_ctx]
    call sha256_stream_init
.loop:
    test r13,r13
    jz .eof
    mov ebx,4096
    cmp r13,rbx
    cmovb rbx,r13
    mov [rel r5_io_size],rbx
    mov rcx,[rel r5_file]
    lea rdx,[rel r5_io_size]
    lea r8,[rel r5_chunk]
    R5_FW_ENTER
    call [rcx+32]
    R5_FW_LEAVE
    test rax,rax
    jnz .close_bad
    mov rdx,[rel r5_io_size]
    test rdx,rdx
    jz .close_bad
    cmp rdx,rbx
    ja .close_bad
    sub r13,rdx
    lea rdi,[rel r5_sha_ctx]
    lea rsi,[rel r5_chunk]
    call sha256_stream_update
    test rax,rax
    jnz .close_bad
    jmp .loop
.eof:
    call r5_file_eof
    test eax,eax
    jz .close_bad
    lea rdi,[rel r5_sha_ctx]
    lea rsi,[rel r5_file_digest]
    call sha256_stream_final
    test rax,rax
    jnz .close_bad
    lea rdi,[rel r5_file_digest]
    mov rsi,r12
    mov ecx,32
    call r5_equal
    mov ebx,eax
    jmp .close
.close_bad:
    xor ebx,ebx
.close:
    call r5_file_close
    and eax,ebx
    jmp .out
.no:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Grant signature/structure must already be verified. Match the actual node's
; raw nonempty SMBIOS type-1 UUID (not an AUTH2 ticket), loaded ESP device path,
; signed full firmware load option and every named chain/Rescue/descriptor byte.
r5_route_validate:
    push rbx
    cmp byte [rel smbios_sys_uuid_present],1
    jne .no
    lea rdi,[rel r5_grant+R5_NODE_UUID]
    lea rsi,[rel smbios_sys_uuid]
    mov ecx,16
    call r5_equal
    test eax,eax
    jz .no
    mov rsi,[rel r5_device_path]
    test rsi,rsi
    jz .no
    mov rdi,rsi
    movzx ecx,word [rel r5_grant+R5_MEDIUM_LEN]
    call r5_device_path_valid
    test eax,eax
    jz .no
    mov rsi,[rel r5_device_path]
    lea rdi,[rel r5_grant+R5_MEDIUM]
    movzx ecx,word [rel r5_grant+R5_MEDIUM_LEN]
    call r5_equal
    test eax,eax
    jz .no
    call r5_option_revalidate
    test eax,eax
    jz .no
    ; Require exactly one active namespace entry with this complete option.
    call r5_option_unique
    test eax,eax
    jz .no
    xor ebx,ebx
.component:
    imul edx,ebx,R5_COMPONENT_SIZE
    lea rax,[rel r5_grant+R5_COMPONENTS]
    add rax,rdx
    lea rdi,[rax+40]
    lea rsi,[rax+8]
    mov rdx,[rax]
    call r5_file_hash
    test eax,eax
    jz .no
    inc ebx
    cmp bl,[rel r5_grant+14]
    jb .component
    lea rdi,[rel r5_descriptor_path]
    lea rsi,[rel r5_grant+R5_DESCRIPTOR_SHA]
    mov edx,PBM_RECOVERY_SIZE
    call r5_file_hash
    test eax,eax
    jz .no
    lea rdi,[rel r5_rescue_path]
    lea rsi,[rel r5_grant+R5_RESCUE_SHA]
    mov rdx,[rel r5_grant+R5_RESCUE_SIZE]
    call r5_file_hash
    jmp .out
.no:
    xor eax,eax
.out:
    pop rbx
    ret

; Build the exact owner-named Boot####; no entry number guesses or BootOrder.
r5_option_name:
    movzx eax,word [rel r5_grant+R5_BOOTNUM]
    lea rdi,[rel r5_option_name_buf+14]
    mov ecx,4
.loop:
    mov edx,eax
    and edx,15
    lea r10,[rel r5_hex]
    mov dl,[r10+rdx]
    movzx edx,dl
    mov [rdi],dx
    sub rdi,2
    shr eax,4
    loop .loop
    ret

r5_option_revalidate:
    push rbx
    call r5_option_name
    lea rcx,[rel r5_option_name_buf]
    lea rdx,[rel r5_global_guid]
    lea r8,[rel r5_option_live]
    mov r9d,768
    call r5_get_variable
    test rax,rax
    jnz .no
    cmp dword [rel r5_attrs],7
    jne .no
    movzx ecx,word [rel r5_grant+R5_OPTION_LEN]
    cmp rcx,[rel r5_var_size]
    jne .no
    test dword [rel r5_option_live],1
    jz .no
    lea rdi,[rel r5_grant+R5_OPTION]
    lea rsi,[rel r5_option_live]
    call r5_equal
    test eax,eax
    jz .no
    ; EFI_LOAD_OPTION {attributes:u32, pathlen:u16, description:NUL16, DP}.
    ; No optional data: no unverified command/config arguments on reset.
    movzx ebx,word [rel r5_grant+R5_OPTION_LEN]
    mov ecx,6
.desc:
    lea eax,[rcx+2]
    cmp eax,ebx
    ja .no
    lea rdx,[rel r5_option_live]
    cmp word [rdx+rcx],0
    je .path
    add ecx,2
    jmp .desc
.path:
    add ecx,2
    movzx eax,word [rdx+4]
    cmp ax,[rel r5_grant+R5_DP_LEN]
    jne .no
    add eax,ecx
    cmp eax,ebx
    jne .no
    lea rbx,[rdx+rcx]
    mov rdi,rbx
    movzx ecx,word [rdx+4]
    call r5_device_path_valid
    test eax,eax
    jz .no
    ; Full DP = exact ESP path without END + one full MEDIA_FILEPATH + END.
    movzx ecx,word [rel r5_grant+R5_MEDIUM_LEN]
    sub ecx,4
    mov rdi,rbx
    lea rsi,[rel r5_grant+R5_MEDIUM]
    call r5_equal
    test eax,eax
    jz .no
    movzx eax,word [rel r5_grant+R5_MEDIUM_LEN]
    lea rbx,[rbx+rax-4]
    cmp word [rbx],0x0404
    jne .no
    movzx ecx,word [rbx+2]
    cmp ecx,6
    jb .no
    cmp ecx,260
    ja .no
    test ecx,1
    jnz .no
    ; Sum checked against signed DP len before any path comparison.
    movzx eax,word [rel r5_grant+R5_MEDIUM_LEN]
    add eax,ecx
    cmp ax,[rel r5_grant+R5_DP_LEN]
    jne .no
    cmp dword [rbx+rcx],0x0004ff7f
    jne .no
    sub ecx,4
    lea rdi,[rbx+4]
    lea rsi,[rel r5_grant+R5_COMPONENTS+40]
    call r5_equal
    jmp .out
.no:
    xor eax,eax
.out:
    pop rbx
    ret

; GetNextVariableName cap4096; malformed/oversized/nonterminating/unknown
; namespace refuses. Count matching ACTIVE exact options, not descriptions.
r5_option_unique:
    push rbx
    push r12
    xor ebx,ebx
    mov r12d,4096
    mov word [rel r5_enum_name],0
    lea rdi,[rel r5_enum_guid]
    mov ecx,16
    xor eax,eax
    rep stosb
.next:
    dec r12d
    jz .no
    mov qword [rel r5_enum_size],512
    lea rcx,[rel r5_enum_size]
    lea rdx,[rel r5_enum_name]
    lea r8,[rel r5_enum_guid]
    mov rax,[rel runtime_services]
    R5_FW_ENTER
    call [rax+0x50]
    R5_FW_LEAVE
    mov rdx,R5_EFI_NOT_FOUND
    cmp rax,rdx
    je .done
    test rax,rax
    jnz .no
    cmp qword [rel r5_enum_size],2
    jb .no
    cmp qword [rel r5_enum_size],512
    ja .no
    test byte [rel r5_enum_size],1
    jnz .no
    mov rax,[rel r5_enum_size]
    lea rdx,[rel r5_enum_name]
    cmp word [rdx+rax-2],0
    jne .no
    lea rdi,[rel r5_enum_guid]
    lea rsi,[rel r5_global_guid]
    mov ecx,16
    call r5_equal
    test eax,eax
    jz .next
    cmp qword [rel r5_enum_size],18
    jne .next
    cmp dword [rel r5_enum_name],0x006f0042
    jne .next
    cmp dword [rel r5_enum_name+4],0x0074006f
    jne .next
    ; Names other than Boot[0-9A-F]{4} are not load options.
    lea rdi,[rel r5_enum_name+8]
    mov ecx,4
.hex:
    movzx eax,word [rdi]
    cmp eax,'0'
    jb .next
    cmp eax,'9'
    jbe .digit
    cmp eax,'A'
    jb .next
    cmp eax,'F'
    ja .next
.digit:
    add rdi,2
    loop .hex
    lea rcx,[rel r5_enum_name]
    lea rdx,[rel r5_global_guid]
    lea r8,[rel r5_option_live]
    mov r9d,768
    call r5_get_variable
    test rax,rax
    jnz .no
    movzx ecx,word [rel r5_grant+R5_OPTION_LEN]
    cmp rcx,[rel r5_var_size]
    jne .next
    lea rdi,[rel r5_option_live]
    lea rsi,[rel r5_grant+R5_OPTION]
    call r5_equal
    test eax,eax
    jz .next
    inc ebx
    cmp ebx,1
    ja .no
    jmp .next
.done:
    xor eax,eax
    cmp ebx,1
    sete al
    jmp .out
.no:
    xor eax,eax
.out:
    pop r12
    pop rbx
    ret

; RCX=name,RDX=GUID,R8=dest,R9=capacity. RAX=EFI_STATUS, size/attrs exact.
r5_get_variable:
    mov [rel r5_var_size],r9
    mov dword [rel r5_attrs],0
    mov r10,r8
    lea r8,[rel r5_attrs]
    lea r9,[rel r5_var_size]
    mov rax,[rel runtime_services]
    test rax,rax
    jz .no
    R5_FW_ENTER
    mov [rsp+32],r10
    call [rax+0x48]
    R5_FW_LEAVE
    ret
.no:
    mov rax,-1
    ret
r5_bootnext_absent:
    lea rcx,[rel r5_bootnext_name]
    lea rdx,[rel r5_global_guid]
    lea r8,[rel r5_bootnext_live]
    mov r9d,2
    call r5_get_variable
    mov rdx,R5_EFI_NOT_FOUND
    cmp rax,rdx
    sete al
    movzx eax,al
    ret
r5_get_request:
    lea rcx,[rel r5_nv_name]
    lea rdx,[rel r5_nv_guid]
    lea r8,[rel r5_request]
    mov r9d,R5_REQUEST_SIZE
    call r5_get_variable
    ret
; RCX/RDX=name/GUID,R8=data,R9=size; attrs7. Exactly one attempt.
r5_set_variable:
    mov r10,r8
    mov r8d,7
    mov rax,[rel runtime_services]
    R5_FW_ENTER
    mov [rsp+32],r10
    call [rax+0x58]
    R5_FW_LEAVE
    ret
r5_set_request:
    lea rcx,[rel r5_nv_name]
    lea rdx,[rel r5_nv_guid]
    lea r8,[rel r5_request]
    mov r9d,R5_REQUEST_SIZE
    call r5_set_variable
    test rax,rax
    jnz .no
    ; Read into a distinct buffer, never overwrite expected bytes with reply.
    lea rcx,[rel r5_nv_name]
    lea rdx,[rel r5_nv_guid]
    lea r8,[rel r5_request_readback]
    mov r9d,R5_REQUEST_SIZE
    call r5_get_variable
    test rax,rax
    jnz .no
    cmp qword [rel r5_var_size],R5_REQUEST_SIZE
    jne .no
    cmp dword [rel r5_attrs],7
    jne .no
    lea rdi,[rel r5_request]
    lea rsi,[rel r5_request_readback]
    mov ecx,R5_REQUEST_SIZE
    jmp r5_equal
.no:
    xor eax,eax
    ret
r5_delete_request:
    lea rcx,[rel r5_nv_name]
    lea rdx,[rel r5_nv_guid]
    xor r8d,r8d
    xor r9d,r9d
    call r5_set_variable
    test rax,rax
    jnz .no
    call r5_get_request
    mov rdx,R5_EFI_NOT_FOUND
    cmp rax,rdx
    sete al
    movzx eax,al
    ret
.no:
    xor eax,eax
    ret
r5_set_bootnext:
    call r5_bootnext_absent
    test eax,eax
    jz .no
    lea rcx,[rel r5_bootnext_name]
    lea rdx,[rel r5_global_guid]
    lea r8,[rel r5_grant+R5_BOOTNUM]
    mov r9d,2
    call r5_set_variable
    test rax,rax
    jnz .no
    lea rcx,[rel r5_bootnext_name]
    lea rdx,[rel r5_global_guid]
    lea r8,[rel r5_bootnext_live]
    mov r9d,2
    call r5_get_variable
    test rax,rax
    jnz .no
    cmp qword [rel r5_var_size],2
    jne .no
    cmp dword [rel r5_attrs],7
    jne .no
    mov ax,[rel r5_bootnext_live]
    cmp ax,[rel r5_grant+R5_BOOTNUM]
    sete al
    movzx eax,al
    ret
.no:
    xor eax,eax
    ret

; EFI_GUID contains UINT32 Data1: firmware-facing instances need natural
; alignment independently of the preceding instruction/diagnostic layout.
align 4
r5_loaded_guid: dd 0x5b1b31a1
    dw 0x9562,0x11d2
    db 0x8e,0x3f,0,0xa0,0xc9,0x69,0x72,0x3b
r5_fs_guid: dd 0x964e5b22
    dw 0x6459,0x11d2
    db 0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b
r5_dp_guid: dd 0x09576e91
    dw 0x6d3f,0x11d2
    db 0x8e,0x39,0,0xa0,0xc9,0x69,0x72,0x3b
r5_global_guid: dd 0x8be4df61
    dw 0x93ca,0x11d2
    db 0xaa,0x0d,0,0xe0,0x98,0x03,0x2b,0x8c
; Existing PaOS health GUID. Ordinary names use the established PaOS storage class.
r5_nv_guid: dd 0xC4A7C2F1
    dw 0x4BB5,0x4AE8
    db 0x9C,0x4F,0x6F,0x76,0xF7,0xC2,0xA0,0x51
align 2
r5_nv_name: dw __utf16__('PaOSRecoveryRequest'),0
r5_bootnext_name: dw __utf16__('BootNext'),0
r5_grant_path: dw __utf16__('\EFI\PaOS\state\recovery-grant.bin'),0
r5_descriptor_path: dw __utf16__('\EFI\PaOS\rescue\rescue-descriptor.bin'),0
r5_rescue_path: dw __utf16__('\EFI\PaOS\rescue\paos-rescue.efi'),0
r5_manifest_path: dw __utf16__('\EFI\PaOS\vault\manifest.bin'),0
r5_state0_path: dw __utf16__('\EFI\PaOS\state\state0.bin'),0
r5_state1_path: dw __utf16__('\EFI\PaOS\state\state1.bin'),0
r5_hex: db '0123456789ABCDEF'
%macro R5_ROUTE_DATA 0
align 8
r5_root: dq 0
r5_file: dq 0
r5_fs: dq 0
r5_loaded: dq 0
r5_device: dq 0
r5_device_path: dq 0
r5_io_size: dq 0
r5_var_size: dq 0
r5_enum_size: dq 0
r5_attrs: dd 0
r5_option_name_buf: dw __utf16__('Boot0000'),0
r5_bootnext_live: dw 0
r5_enum_guid: times 16 db 0
r5_enum_name: times 512 db 0
r5_option_live: times 768 db 0
r5_request_readback: times R5_REQUEST_SIZE db 0
r5_file_digest: times 32 db 0
r5_sha_ctx: times 128 db 0
r5_chunk: times 4096 db 0
%endmacro
%ifndef R5_MANAGER_LINK
%include "core/abi/wdata.inc"
WDATA_DEFER R5_ROUTE_DATA
%endif
