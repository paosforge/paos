; PBIR diagnostic ABI. Not a boot gate, promotion authority or journal.
%ifndef PAOS_IMAGE_REFUSAL_INC
%define PAOS_IMAGE_REFUSAL_INC 1
PBIR_MAGIC equ 0x52494250
PBIR_VERSION equ 1
PBIR_BYTES equ 128
PBIR_CRC equ 124
; Instantiate one shared strict validator with the caller's CRC length ABI.
; RDI=exact128B; EAX=1 valid/0 invalid. Callee-saved registers preserved.
%macro PBIR_VALIDATOR 3
%1:
    push rbx
    mov rbx,rdi
    cmp dword [rbx],PBIR_MAGIC
    jne .bad
    cmp word [rbx+4],PBIR_VERSION
    jne .bad
    cmp word [rbx+6],PBIR_BYTES
    jne .bad
    cmp byte [rbx+8],1
    jb .bad
    cmp byte [rbx+8],3
    ja .bad
    cmp byte [rbx+9],1
    jb .bad
    cmp byte [rbx+9],3
    ja .bad
    ; This producer has no explicit G milestone witness. Never infer from
    ; verification attempts, P phases, EFI_STATUS or its expected image hash.
    cmp word [rbx+10],0x00ff
    jne .bad
    cmp dword [rbx+12],0
    jne .bad
    cmp qword [rbx+24],0
    je .bad
    mov rax,[rbx+32]
    or rax,[rbx+40]
    or rax,[rbx+48]
    or rax,[rbx+56]
    jz .bad
    cmp byte [rbx+9],3
    je .efi
    cmp qword [rbx+64],0
    jne .bad
    jmp .tail
.efi:
    cmp qword [rbx+64],0
    je .bad
.tail:
    lea rdi,[rbx+72]
    xor eax,eax
    mov ecx,52
    repe scasb
    jne .bad
    mov rdi,rbx
    mov %3,PBIR_CRC
    call %2
    cmp eax,[rbx+PBIR_CRC]
    jne .bad
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret
%endmacro
%endif
