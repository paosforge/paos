; ROOT94192: fixed read-only BOOT_MODE firmware observation. No SetVariable,
; selector, CMOS or reset action. All output sizes have constant upper bounds:
; 8192 data hex + 1024 BootOrder hex + <512 metadata fits bm_out_buf 10240.
BM_FW_MAX equ 1048576
BM_FW_CHUNK equ 4096

; RDI=original BOOT_MODE ARGT_TEXT. EAX=0 legacy, 1 handled FW observation.
bm_fw_observe:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov r12, rdi
    test rdi, rdi
    jz .legacy
    ; Only the extended form needs exact fresh-nonce grammar. Legacy stays ABI.
    xor ecx, ecx
.scan:
    cmp byte [rdi+rcx], 0
    je .legacy
    inc ecx
    cmp ecx, 32
    jb .scan
    cmp byte [rdi+32], 0
    je .legacy
    mov byte [rel bm_fw_state], 4 ; malformed request until fully validated
    mov qword [rel bm_fw_efi], 0
    mov qword [rel bm_fw_size], 0
    mov dword [rel bm_fw_attrs], 0
    mov dword [rel bm_fw_offset], 0
    mov byte [rel bm_fw_id], 0xff
    mov qword [rel bm_fw_order_size], 0
    xor ebx, ebx
.nonce:
    movzx eax, byte [r12+rbx]
    call bm_fw_nibble
    jc .emit
    inc ebx
    cmp ebx, 32
    jb .nonce
    cmp byte [r12+32], ' '
    jne .emit
    cmp byte [r12+33], 'F'
    jne .emit
    cmp byte [r12+34], 'W'
    jne .emit
    cmp byte [r12+35], ' '
    jne .emit
    movzx eax, byte [r12+36]
    call bm_fw_nibble
    jc .emit
    cmp eax, 10
    ja .emit
    mov [rel bm_fw_id], al
    cmp byte [r12+37], ' '
    jne .emit
    xor ebx, ebx
    xor ebp, ebp
.offset:
    movzx eax, byte [r12+38+rbx]
    call bm_fw_nibble
    jc .emit
    shl ebp, 4
    or ebp, eax
    inc ebx
    cmp ebx, 8
    jb .offset
    cmp byte [r12+46], 0
    jne .emit
    mov [rel bm_fw_offset], ebp
    test ebp, BM_FW_CHUNK-1
    jnz .emit
    cmp ebp, BM_FW_MAX
    jae .emit
    mov byte [rel bm_fw_state], 2 ; unavailable if runtime cannot safely execute
    cmp byte [rel pbm_runtime_read_mapped], 1
    jne .emit
    movzx ebx, byte [rel bm_fw_id]
    cmp ebx, 1
    jne .fixed
    ; Observe the current first BootOrder option, never choose a new default.
    lea rdi, [rel bm_fw_order_name]
    lea rsi, [rel bm_fw_global_guid]
    mov edx, 512
    lea r8, [rel bm_fw_order]
    call bm_fw_get
    cmp byte [rel bm_fw_state], 0
    jne .emit
    mov rax, [rel bm_fw_size]
    cmp rax, 2
    jb .malformed
    test al, 1
    jnz .malformed
    mov [rel bm_fw_order_size], rax
    mov eax, [rel bm_fw_attrs]
    mov [rel bm_fw_order_attrs], eax
    movzx eax, word [rel bm_fw_order]
    lea rdi, [rel bm_fw_default_name+8]
    mov ecx, 4
.make_name:
    rol ax, 4
    movzx edx, al
    and edx, 15
    lea rsi, [rel bm_fw_digits]
    mov dl, [rsi+rdx]
    mov [rdi], dl
    mov byte [rdi+1], 0
    add rdi, 2
    loop .make_name
    lea rdi, [rel bm_fw_default_name]
    lea rsi, [rel bm_fw_global_guid]
    mov edx, 4096
    jmp .read
.fixed:
    lea rax, [rel bm_fw_names]
    movsxd rdi, dword [rax+rbx*4]
    add rdi, rax
    lea rsi, [rel bm_fw_global_guid]
    cmp ebx, 7
    jb .guid_ready
    lea rsi, [rel bm_fw_security_guid]
    cmp ebx, 9
    jb .guid_ready
    lea rsi, [rel bm_fw_shim_guid]
.guid_ready:
    lea rax, [rel bm_fw_caps]
    mov edx, [rax+rbx*4]
.read:
    lea r8, [rel bm_fw_data]
    call bm_fw_get
    cmp byte [rel bm_fw_state], 0
    jne .emit
    mov eax, [rel bm_fw_offset]
    cmp rax, [rel bm_fw_size]
    jae .malformed
    lea rdi, [rel bm_fw_digest]
    lea rsi, [rel bm_fw_data]
    mov rdx, [rel bm_fw_size]
    call sha256_hash
    test eax, eax
    jz .emit
.malformed:
    mov byte [rel bm_fw_state], 4
.emit:
    lea rdi, [rel bm_fw_prefix]
    call bm_out_str
    movzx eax, byte [rel bm_fw_id]
    mov ecx, 2
    call bm_fw_num
    lea rdi, [rel bm_fw_off_text]
    call bm_out_str
    mov eax, [rel bm_fw_offset]
    mov ecx, 8
    call bm_fw_num
    lea rdi, [rel bm_fw_status_text]
    call bm_out_str
    movzx eax, byte [rel bm_fw_state]
    lea rdx, [rel bm_fw_states]
    movsxd rdi, dword [rdx+rax*4]
    add rdi, rdx
    call bm_out_str
    lea rdi, [rel bm_fw_efi_text]
    call bm_out_str
    mov rax, [rel bm_fw_efi]
    mov ecx, 16
    call bm_fw_num
    lea rdi, [rel bm_fw_attrs_text]
    call bm_out_str
    mov eax, [rel bm_fw_attrs]
    mov ecx, 8
    call bm_fw_num
    lea rdi, [rel bm_fw_size_text]
    call bm_out_str
    mov rax, [rel bm_fw_size]
    mov ecx, 16
    call bm_fw_num
    lea rdi, [rel bm_fw_hash_text]
    call bm_out_str
    cmp byte [rel bm_fw_state], 0
    jne .no_hash
    lea rdi, [rel bm_fw_digest]
    mov ecx, 32
    call bm_fw_bytes
    jmp .data
.no_hash:
    lea rdi, [rel bm_fw_dash]
    call bm_out_str
.data:
    lea rdi, [rel bm_fw_data_text]
    call bm_out_str
    cmp byte [rel bm_fw_state], 0
    jne .no_data
    mov eax, [rel bm_fw_offset]
    lea rdi, [rel bm_fw_data]
    add rdi, rax
    mov rcx, [rel bm_fw_size]
    sub rcx, rax
    cmp rcx, BM_FW_CHUNK
    jbe .data_ready
    mov ecx, BM_FW_CHUNK
.data_ready:
    call bm_fw_bytes
    jmp .order
.no_data:
    lea rdi, [rel bm_fw_dash]
    call bm_out_str
.order:
    lea rdi, [rel bm_fw_order_text]
    call bm_out_str
    cmp qword [rel bm_fw_order_size], 0
    je .no_order
    lea rdi, [rel bm_fw_order]
    mov rcx, [rel bm_fw_order_size]
    call bm_fw_bytes
    jmp .order_attrs
.no_order:
    lea rdi, [rel bm_fw_dash]
    call bm_out_str
.order_attrs:
    lea rdi, [rel bm_fw_order_attrs_text]
    call bm_out_str
    xor eax, eax
    cmp qword [rel bm_fw_order_size], 0
    je .oa
    mov eax, [rel bm_fw_order_attrs]
.oa:
    mov ecx, 8
    call bm_fw_num
    mov eax, 1
    jmp .out
.legacy:
    xor eax, eax
.out:
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; ASCII hex digit -> EAX nibble, CF=1 if malformed. No pointer scanning.
bm_fw_nibble:
    cmp al, '0'
    jb .bad
    cmp al, '9'
    jbe .decimal
    or al, 32
    cmp al, 'a'
    jb .bad
    cmp al, 'f'
    ja .bad
    sub eax, 'a'-10
    clc
    ret
.decimal:
    sub eax, '0'
    clc
    ret
.bad:
    stc
    ret

; Actual GetVariable only. RDI=name, RSI=guid, EDX=cap, R8=owned buffer.
; MS x64 ABI: aligned stack + 32B shadow + fifth argument. No persistent write.
bm_fw_get:
    push rbp
    mov rbp, rsp
    push rbx
    and rsp, -16
    sub rsp, 48
    mov ebx, edx
    mov qword [rel bm_fw_size], 0
    mov dword [rel bm_fw_attrs], 0
    mov qword [rel bm_fw_efi], 0
    mov byte [rel bm_fw_state], 2
    cmp byte [rel pbm_runtime_read_mapped], 1
    jne .out
    mov rax, [rel runtime_services]
    test rax, rax
    jz .out
    mov rax, [rax+0x48]
    test rax, rax
    jz .out
    mov [rel bm_fw_size], rbx
    mov [rsp+32], r8
    mov rcx, rdi
    mov rdx, rsi
    lea r8, [rel bm_fw_attrs]
    lea r9, [rel bm_fw_size]
    call rax
    mov [rel bm_fw_efi], rax
    mov byte [rel bm_fw_state], 0
    test rax, rax
    jz .success
    mov byte [rel bm_fw_state], 1
    mov rdx, 0x800000000000000e
    cmp rax, rdx
    je .absent
    mov byte [rel bm_fw_state], 2
    mov rdx, 0x8000000000000003
    cmp rax, rdx
    je .unavailable
    mov byte [rel bm_fw_state], 5
    mov rdx, 0x8000000000000005
    cmp rax, rdx
    jne .error
    cmp [rel bm_fw_size], rbx
    jbe .malformed
    mov byte [rel bm_fw_state], 3
    jmp .out
.success:
    cmp qword [rel bm_fw_size], 0
    je .malformed
    cmp [rel bm_fw_size], rbx
    jbe .out
.malformed:
    mov byte [rel bm_fw_state], 4
    jmp .out
.absent:
    mov qword [rel bm_fw_size], 0
    jmp .out
.error:
    mov byte [rel bm_fw_state], 5
    jmp .out
.unavailable:
    mov qword [rel bm_fw_size], 0
    mov dword [rel bm_fw_attrs], 0
.out:
    mov rbx, [rbp-8]
    mov rsp, rbp
    pop rbp
    ret

; Emit fixed-width numeric hex / raw byte hex without fmt's variable width.
bm_fw_num:
    mov r10, rax
    mov r9d, ecx
    lea ecx, [rcx*4-4]
    mov rdx, [rel bm_out_cur]
    lea r11, [rel bm_fw_digits]
.loop:
    mov rax, r10
    shr rax, cl
    and eax, 15
    mov al, [r11+rax]
    mov [rdx], al
    inc rdx
    sub ecx, 4
    dec r9d
    jnz .loop
    mov byte [rdx], 0
    mov [rel bm_out_cur], rdx
    ret
bm_fw_bytes:
    mov rdx, [rel bm_out_cur]
    lea r11, [rel bm_fw_digits]
    test ecx, ecx
    jz .done
.loop:
    movzx eax, byte [rdi]
    shr eax, 4
    mov al, [r11+rax]
    mov [rdx], al
    movzx eax, byte [rdi]
    and eax, 15
    mov al, [r11+rax]
    mov [rdx+1], al
    inc rdi
    add rdx, 2
    dec ecx
    jnz .loop
.done:
    mov byte [rdx], 0
    mov [rel bm_out_cur], rdx
    ret

%include "core/abi/wdata.inc"
%macro WDATA_svc_bootstate 0
align 8
bm_fw_efi: dq 0
bm_fw_size: dq 0
bm_fw_order_size: dq 0
bm_fw_attrs: dd 0
bm_fw_order_attrs: dd 0
bm_fw_offset: dd 0
bm_fw_id: db 0
bm_fw_state: db 0
bm_fw_digest: times 32 db 0
bm_fw_digits: db '0123456789ABCDEF'
bm_fw_global_guid: dd 0x8be4df61
    dw 0x93ca,0x11d2
    db 0xaa,0x0d,0x00,0xe0,0x98,0x03,0x2b,0x8c
bm_fw_security_guid: dd 0xd719b2cb
    dw 0x3d3a,0x4596
    db 0xa3,0xbc,0xda,0xd0,0x0e,0x67,0x65,0x6f
bm_fw_shim_guid: dd 0x605dab50
    dw 0xe046,0x4300
    db 0xab,0xb6,0x3d,0xd8,0x10,0xdd,0x8b,0x23
bm_fw_order_name: dw __utf16__('BootOrder'),0
bm_fw_default_name: dw __utf16__('Boot0000'),0
bm_fw_next_name: dw __utf16__('BootNext'),0
bm_fw_secure_name: dw __utf16__('SecureBoot'),0
bm_fw_setup_name: dw __utf16__('SetupMode'),0
bm_fw_pk_name: dw __utf16__('PK'),0
bm_fw_kek_name: dw __utf16__('KEK'),0
bm_fw_db_name: dw __utf16__('db'),0
bm_fw_dbx_name: dw __utf16__('dbx'),0
bm_fw_mok_name: dw __utf16__('MokList'),0
bm_fw_mokrt_name: dw __utf16__('MokListRT'),0
align 8
bm_fw_names: dd bm_fw_order_name - bm_fw_names,bm_fw_default_name - bm_fw_names,bm_fw_next_name - bm_fw_names,bm_fw_secure_name - bm_fw_names,bm_fw_setup_name - bm_fw_names,bm_fw_pk_name - bm_fw_names,bm_fw_kek_name - bm_fw_names,bm_fw_db_name - bm_fw_names,bm_fw_dbx_name - bm_fw_names,bm_fw_mok_name - bm_fw_names,bm_fw_mokrt_name - bm_fw_names
bm_fw_caps: dd 512,4096,2,1,1,BM_FW_MAX,BM_FW_MAX,BM_FW_MAX,BM_FW_MAX,BM_FW_MAX,BM_FW_MAX
bm_fw_prefix: db ' FWSTATE1 id=',0
bm_fw_off_text: db ' off=',0
bm_fw_status_text: db ' status=',0
bm_fw_efi_text: db ' efi=',0
bm_fw_attrs_text: db ' attrs=',0
bm_fw_size_text: db ' size=',0
bm_fw_hash_text: db ' hash=',0
bm_fw_data_text: db ' data=',0
bm_fw_order_text: db ' order=',0
bm_fw_order_attrs_text: db ' orderattrs=',0
bm_fw_dash: db '-',0
bm_fw_ok: db 'ok',0
bm_fw_absent: db 'absent',0
bm_fw_unavailable: db 'unavailable',0
bm_fw_limit: db 'limit',0
bm_fw_malformed: db 'malformed',0
bm_fw_error: db 'error',0
align 8
bm_fw_states: dd bm_fw_ok - bm_fw_states,bm_fw_absent - bm_fw_states,bm_fw_unavailable - bm_fw_states,bm_fw_limit - bm_fw_states,bm_fw_malformed - bm_fw_states,bm_fw_error - bm_fw_states
bm_fw_order: times 512 db 0
%endmacro
WDATA_DEFER WDATA_svc_bootstate
%macro WDATA_BSS_svc_bootstate 0
alignb 16
bm_fw_data: resb BM_FW_MAX
%endmacro
WDATA_BSS_DEFER WDATA_BSS_svc_bootstate
