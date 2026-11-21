;; MODULE hv/isolated_vm_boot_tables
;; LAYER 5
;; EXPORTS isolated_vm_boot_tables
;; IMPORTS
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Native isolated-loader leaf, shared by app and tools. The caller has already
; proved stopped CPU/root custody and its own scrubbed RAM allocation. Guest
; arguments never reach this pointer/extent interface. No boot/admission credit.
%ifndef PAOS_ISOLATED_VM_BOOT_TABLES_CODE
%define PAOS_ISOLATED_VM_BOOT_TABLES_CODE 1

; RDI=own guest RAM HVA, RSI=RAM bytes ->EAX1/0. Refusal writes nothing.
; Guest tables: PML4 0x1000, PDPT0x2000, up to3 PDs0x3000..0x5fff.
; They map exactly own low GPA RAM in2MiB leaves. SLAT separately translates
; these GPAs into the caller's private RAM; native control is never mapped.
isolated_vm_boot_tables:
    test rdi,rdi
    jz .bad
    cmp rsi,0x4000000
    jb .bad
    mov eax,0xc0000000
    cmp rsi,rax
    ja .bad
    test rsi,0x1fffff
    jnz .bad
    mov rax,rdi
    add rax,rsi
    jc .bad
    mov r8,rdi
    mov r9,rsi
    lea rdi,[r8+0x1000]
    xor eax,eax
    mov ecx,0x5000/8
    cld
    rep stosq
    mov qword [r8+0x1000],0x2003
    lea rcx,[r9+0x3fffffff]
    shr rcx,30
    lea rdi,[r8+0x2000]
    mov eax,0x3003
.pdpt:
    stosq
    add rax,0x1000
    loop .pdpt
    lea rdi,[r8+0x3000]
    mov rcx,r9
    shr rcx,21
    mov eax,0x83
.leaf:
    stosq
    add rax,0x200000
    loop .leaf
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret
%endif
