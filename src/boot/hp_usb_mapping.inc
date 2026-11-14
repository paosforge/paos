; P4 dedicated 4 KiB LoaderData page. Called with the paging entry's existing
; UEFI shadow space, before final GetMemoryMap/EBS. No physical address comes
; from a command; no general RAM is borrowed and no boot-critical allocation.
; Failure leaves an explicit absent probe, without changing the boot policy.
hp_mapping_reserve:
    push rbx
    push rsi
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 104                   ; UEFI shadow, fifth argument, local map outputs
    mov  qword [rel hp_mapping_page], 0
    mov  rbx, [rel inv_map_buffer]
    test rbx, rbx
    jz   .out
    mov  qword [rsp + 48], INV_MAP_BYTES
    lea  rcx, [rsp + 48]             ; fresh map: earlier inventory may be stale
    mov  rdx, rbx
    lea  r8, [rsp + 56]
    lea  r9, [rsp + 64]
    lea  rax, [rsp + 72]
    mov  [rsp + 32], rax
    mov  rax, [rel boot_services]
    call [rax + 0x38]                ; GetMemoryMap, existing allocated buffer
    test rax, rax
    jnz  .out                       ; no growth allocation, no boot dependency
    mov  rcx, [rsp + 48]
    cmp  rcx, INV_MAP_BYTES
    ja   .out
    mov  r12, [rsp + 64]
    cmp  r12, 40                    ; EFI_MEMORY_DESCRIPTOR through Attribute
    jb   .out
    mov  rax, rcx
    xor  edx, edx
    div  r12
    test rax, rax
    jz   .out
    test rdx, rdx
    jnz  .out
    mov  r13, rbx
    add  r13, rcx
    jc   .out
    mov  r14, 0x8000000000           ; exclusive 512 GiB identity-map ceiling
    cmp  r14, [rel ident_bytes]
    cmova r14, [rel ident_bytes]
    cmp  r14, [rel inv_top_of_ram]
    cmova r14, [rel inv_top_of_ram]
    and  r14, -4096
    mov  rsi, 0x400000000            ; high-page prerequisite: at least 16 GiB
    cmp  r14, rsi
    jbe  .out
.descriptor:
    cmp  dword [rbx], 7             ; EfiConventionalMemory only
    jne  .next
    mov  rax, [rbx + 32]
    test al, 8                      ; write-back capable RAM
    jz   .next
    bt   rax, 63                    ; never EFI_MEMORY_RUNTIME
    jc   .next
    test eax, 0x23000               ; no WP, RP or RO protection
    jnz  .next
    mov  rdx, [rbx + 8]             ; PhysicalStart
    test edx, 0xFFF
    jnz  .next
    mov  rax, [rbx + 24]            ; NumberOfPages
    test rax, rax
    jz   .next
    mov  rcx, rax
    shr  rcx, 52
    jnz  .next
    shl  rax, 12
    add  rax, rdx
    jc   .next
    cmp  rax, r14
    cmova rax, r14
    cmp  rax, 4096
    jb   .next
    sub  rax, 4096
    cmp  rax, rdx                   ; whole page must remain in this descriptor
    jb   .next
    cmp  rax, rsi
    jb   .next
    mov  r15, rax
    mov  [rsp + 80], rax
    mov  ecx, 2                     ; AllocateAddress: MaxAddress is only a ceiling
    mov  edx, 2                     ; EfiLoaderData
    mov  r8d, 1
    lea  r9, [rsp + 80]
    mov  rax, [rel boot_services]
    call [rax + 0x28]               ; acquire ownership before any later access
    test rax, rax
    jnz  .next                      ; stale/unavailable extent: bounded next descriptor
    cmp  r15, [rsp + 80]
    jne  .out
    mov  [rel hp_mapping_page], r15
    jmp  .out
.next:
    add  rbx, r12
    cmp  rbx, r13
    jb   .descriptor
.out:
    add  rsp, 104
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rsi
    pop  rbx
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
