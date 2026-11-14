; P4 dedicated 4 KiB LoaderData page. Called with the paging entry's existing
; UEFI shadow space, before final GetMemoryMap/EBS. No physical address comes
; from a command; no general RAM is borrowed and no boot-critical allocation.
; Failure leaves an explicit absent probe, without changing the boot policy.
hp_mapping_reserve:
    sub  rsp, 40
    mov  rax, 0x7FFFFFFFFF           ; last address below the 512 GiB map ceiling
    mov  [rel hp_mapping_page], rax
    mov  rax, [rel boot_services]
    mov  ecx, 1                     ; AllocateMaxAddress
    mov  edx, 2                     ; EfiLoaderData
    mov  r8d, 1
    lea  r9, [rel hp_mapping_page]
    call [rax + 0x28]
    test rax, rax
    jz   .out
    mov  qword [rel hp_mapping_page], 0
.out:
    add  rsp, 40
    ret

; RDI=nonce -> EAX=0 verified,1 no high-page prerequisite,2 bad live mapping,
; 3 pattern mismatch; RDX=owned address, RCX=raw live PDE. Only our own page
; can be touched, and only after present/RW/PS/NX/WB and identity validation.
hp_mapping_probe:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    xor  r13d, r13d
    mov  rbx, [rel hp_mapping_page]
    mov  rax, 0x400000000
    cmp  rbx, rax
    jb   .absent
    test ebx, 0xFFF
    jnz  .bad
    mov  rax, 0x7FFFFFF000
    cmp  rbx, rax
    ja   .bad
    lea  rdx, [rbx + 4096]
    cmp  rdx, [rel inv_top_of_ram]
    ja   .bad
    mov  rdi, rbx
    call paging_pd_entry_ptr
    test rax, rax
    jz   .bad
    mov  r13, [rax]
    mov  eax, r13d
    and  eax, 0x109B                  ; P/RW/PS, no PWT/PCD for this RAM page
    cmp  eax, 0x83
    jne  .bad
    bt   r13, 63
    jnc  .bad
    mov  rax, 0x000FFFFFFFE00000
    mov  rdx, r13
    and  rdx, rax
    and  rax, rbx
    cmp  rdx, rax
    jne  .bad
    mov  rax, r12
    call .pattern
    jne  .mismatch
    mov  rax, r12
    not  rax
    call .pattern
    jne  .mismatch
    xor  eax, eax
    jmp  .out
.absent:
    mov  eax, 1
    jmp  .out
.bad:
    mov  eax, 2
    jmp  .out
.mismatch:
    mov  eax, 3
.out:
    mov  rdx, rbx
    mov  rcx, r13
    pop  r13
    pop  r12
    pop  rbx
    ret
.pattern:
    mov  rdi, rbx
    mov  ecx, 512
    rep stosq
    mfence
    mov  rdi, rbx
    mov  ecx, 512
    repe scasq
    ret
%macro WDATA_boot_hp_mapping 0
align 8
hp_mapping_page: dq 0
%endmacro
WDATA_DEFER WDATA_boot_hp_mapping
