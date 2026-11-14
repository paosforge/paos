; Best-effort durable image refusal. Existing launch/return policy unchanged.
; EDI=1 file validation,2 PAX1 preparation,3 LoadImage; RSI=EFI_STATUS for3.
; R15D=selected entry. Diagnostics use signed EXPECTED identity, not rejected
; bytes. No writes for Try/external/untrusted entries. At most one offer per
; Manager invocation, no erase/repair/retry. Unknown old record is preserved.
%include "boot/image_refusal.inc"
manager_image_refusal_record:
%ifdef PBM_FEATURE_MUTABLE
%ifdef PBM_OWNER_KEY
    pushfq
    push rbp
    mov rbp,rsp
    and rsp,-16
    push rbx
    push r12
    push r13
    push r14
    cmp byte [rel try_media_boot],0
    jne .out
    cmp byte [rel image_refusal_offered],0
    jne .out
    cmp r15d,1
    jb .out
    cmp r15d,3
    ja .out
    cmp edi,1
    jb .out
    cmp edi,3
    ja .out
    mov r12d,edi
    mov r13,rsi
    mov edi,r15d
    call integrity_vault_select_entry
    test rax,rax
    jz .out
    mov r14,rax
    mov rbx,[rel runtime_services]
    test rbx,rbx
    jz .out
    mov byte [rel image_refusal_offered],1
    mov byte [rel image_refusal_status],2
    lea rdi,[rel image_refusal_record]
    xor eax,eax
    mov ecx,16
    rep stosq
    mov dword [rel image_refusal_record],PBIR_MAGIC
    mov word [rel image_refusal_record+4],PBIR_VERSION
    mov word [rel image_refusal_record+6],PBIR_BYTES
    mov [rel image_refusal_record+8],r15b
    mov [rel image_refusal_record+9],r12b
    mov byte [rel image_refusal_record+10],255
    ; Descriptor trust has no manifest sequence. Zero explicitly means absent.
    cmp byte [rel manifest_verified],1
    jne .sequence_ready
    mov rax,[rel manifest+PBM_MANIFEST_SEQUENCE_OFF]
    mov [rel image_refusal_record+16],rax
.sequence_ready:
    mov eax,[r14+4]
    mov [rel image_refusal_record+24],rax
    lea rsi,[r14+16]
    lea rdi,[rel image_refusal_record+32]
    mov ecx,4
    rep movsq
    cmp r12d,3
    jne .crc
    mov [rel image_refusal_record+64],r13
.crc:
    lea rdi,[rel image_refusal_record]
    mov ecx,PBIR_CRC
    call crc32
    mov [rel image_refusal_record+PBIR_CRC],eax
    lea rdi,[rel image_refusal_record]
    call manager_image_refusal_valid
    test eax,eax
    jz .out
    call manager_image_refusal_read
    mov rdx,0x800000000000000e
    cmp rax,rdx
    je .write
    test rax,rax
    jnz .out
    cmp dword [rel image_refusal_attrs],7
    jne .out
    cmp qword [rel image_refusal_size],PBIR_BYTES
    jne .out
    lea rdi,[rel image_refusal_verify]
    call manager_image_refusal_valid
    test eax,eax
    jz .out
.write:
    mov byte [rel image_refusal_status],3
    lea rcx,[rel image_refusal_name]
    lea rdx,[rel b1_init_var_guid]
    mov r8d,7
    mov r9d,PBIR_BYTES
    PBM_FW_ENTER 40
    lea rax,[rel image_refusal_record]
    mov [rsp+32],rax
    call [rbx+0x58]
    PBM_FW_LEAVE 40
    test rax,rax
    jnz .out
    call manager_image_refusal_read
    test rax,rax
    jnz .out
    cmp dword [rel image_refusal_attrs],7
    jne .out
    cmp qword [rel image_refusal_size],PBIR_BYTES
    jne .out
    lea rdi,[rel image_refusal_record]
    lea rsi,[rel image_refusal_verify]
    mov edx,PBIR_BYTES
    call pbm_bytes_differ
    test eax,eax
    jnz .out
    mov byte [rel image_refusal_status],1
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    mov rsp,rbp
    pop rbp
    popfq
%endif
%endif
    ret

; RBX=runtime services. Get only exact owned name, bounded128 bytes.
manager_image_refusal_read:
    mov qword [rel image_refusal_size],PBIR_BYTES
    mov dword [rel image_refusal_attrs],0
    lea rcx,[rel image_refusal_name]
    lea rdx,[rel b1_init_var_guid]
    lea r8,[rel image_refusal_attrs]
    lea r9,[rel image_refusal_size]
    PBM_FW_ENTER 40
    lea rax,[rel image_refusal_verify]
    mov [rsp+32],rax
    call [rbx+0x48]
    PBM_FW_LEAVE 40
    ret
PBIR_VALIDATOR manager_image_refusal_valid,crc32,ecx
%macro PBM_IMAGE_REFUSAL_DATA 0
align 16
image_refusal_record: times PBIR_BYTES db 0
image_refusal_verify: times PBIR_BYTES db 0
image_refusal_size: dq PBIR_BYTES
image_refusal_attrs: dd 0
image_refusal_offered: db 0
image_refusal_status: db 0
%endmacro
image_refusal_name: dw 'P','a','O','S','I','m','a','g','e','R','e','f','u','s','a','l','R','e','c','o','r','d',0
