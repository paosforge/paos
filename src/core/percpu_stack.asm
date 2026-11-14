;; MODULE core/percpu_stack
;; LAYER 1
;; EXPORTS percpu_stack_reserve, percpu_stack_kernel_top, percpu_stack_ist_top, percpu_stack_prepare_check, percpu_stack_seal, percpu_stack_check, percpu_stack_alloc, percpu_stack_base
;; IMPORTS boot/paging, boot/header, boot/gdt, core/smp, core/heap
;; CAPS
;; OWNER saga:boot
; Permanent CPU stack ownership. Firmware allocates one 4 MiB LoaderData region;
; an aligned 2 MiB interior holds 32 disjoint CPU slots and its own sparse PT.
; Nothing is returned to kmalloc or FreePages, including failed/offline slots.
; kfree cannot reclaim these addresses: they are outside the bump heap.
; Slot: lower guard | 16 KiB kernel | guard | 4 KiB IST1 | upper guard.
; CPU0 uses a separate 64 KiB kernel stack in the same region (loader retired
; immediately after EBS), keeping the BSP's deeper boot/control call chains.
; Preparation seals logical/hardware identity once, before online publication.
; A second preparation is refused for the rest of this boot, including failures.
PERCPU_STACK_CPUS       equ 32
PERCPU_STACK_ALLOC_SIZE equ 0x400000
PERCPU_STACK_STRIDE     equ 0x8000
PERCPU_STACK_PT         equ 0x100000
PERCPU_STACK_BSP_GUARD  equ 0x110000
PERCPU_STACK_BSP_LOW    equ 0x111000
PERCPU_STACK_BSP_TOP    equ 0x121000

; Called inside exit_boot_and_page's existing MS ABI shadow-space frame.
; Allocation failure follows its existing pre-EBS reset path; no unguarded
; fallback is silently admitted. The final firmware map includes this owner.
percpu_stack_reserve:
    mov  eax, 0xFFFFFFFF
    mov  [rel percpu_stack_alloc], rax
    mov  rax, [rel boot_services]
    mov  ecx, 1                         ; AllocateMaxAddress, below 4 GiB
    mov  edx, 2                         ; EfiLoaderData
    mov  r8d, PERCPU_STACK_ALLOC_SIZE / 4096
    lea  r9, [rel percpu_stack_alloc]
    push rbp
    mov  rbp, rsp
    and  rsp, -16
    sub  rsp, 32                        ; aligned MS ABI shadow space
    call [rax + 0x28]
    mov  rsp, rbp
    pop  rbp
    test rax, rax
    jnz  .bad
    mov  rax, [rel percpu_stack_alloc]
    add  rax, 0x1FFFFF
    and  rax, ~0x1FFFFF
    mov  [rel percpu_stack_base], rax
    lea  rdi, [rax + PERCPU_STACK_PT]
    xor  ecx, ecx
.pte:
    mov  rdx, rcx
    shl  rdx, 12
    add  rdx, rax
    or   rdx, 3                         ; supervisor RW, NX
    bts  rdx, 63
    cmp  ecx, 256                       ; first MiB: 32 CPU slots
    jae  .bsp_guard
    mov  r8d, ecx
    and  r8d, 7
    test r8d, r8d
    jz   .guard
    cmp  r8d, 5
    je   .guard
    cmp  r8d, 7
    je   .guard
.bsp_guard:
    cmp  ecx, PERCPU_STACK_BSP_GUARD / 4096
    je   .guard
    cmp  ecx, PERCPU_STACK_BSP_TOP / 4096
    jne  .store
.guard:
    xor  edx, edx
.store:
    mov  [rdi + rcx*8], rdx
    inc  ecx
    cmp  ecx, 512
    jb   .pte
    ; Only replace the identity huge leaf over our owned aligned interior.
    mov  rdi, rax
    call paging_pd_entry_ptr
    test rax, rax
    jz   .bad
    mov  rdx, [rax]
    mov  rcx, 0x000FFFFFFFE00087
    and  rdx, rcx
    mov  rcx, [rel percpu_stack_base]
    or   rcx, 0x83
    cmp  rdx, rcx
    jne  .bad
    add  rcx, PERCPU_STACK_PT - 0x80
    mov  [rax], rcx                     ; PT | P | RW, no PS; CR3 not yet live
    ; PMOD copied its private low tables before this allocation. Synchronize
    ; the arena leaf there too, or disable an overlapping module window.
    call percpu_stack_sync_sandbox
    jc   .bad
    mov  byte [rel percpu_stack_ready], 1
    clc
    ret
.bad:
    stc
    ret

; A PMOD sandbox executes host code on host stacks. Its copied PD must
; share this sparse leaf. If its fixed module VA would alias the arena,
; disable PMOD through the existing zero-base admission instead.
percpu_stack_sync_sandbox:
    mov  rax, [rel pmod_sandbox_pml4]
    test rax, rax
    jz   .ok
    mov  rdi, [rel percpu_stack_base]
    cmp  rdi, 0x40000000
    je   .disable
    call percpu_stack_live_pde
    test rax, rax
    jz   .bad
    mov  rdx, [rel percpu_stack_base]
    add  rdx, PERCPU_STACK_PT + 3
    mov  [rax], rdx
.ok:
    clc
    ret
.disable:
    mov  qword [rel pmod_region_base], 0
    mov  qword [rel pmod_region_phys], 0
    mov  qword [rel pmod_pt_addr], 0
    mov  qword [rel pmod_sandbox_pml4], 0
    jmp  .ok
.bad:
    stc
    ret

; EDI=dense CPU -> RAX=immutable kernel/IST top. Clobber RAX only.
percpu_stack_kernel_top:
    mov  eax, edi
    shl  rax, 15
    add  rax, [rel percpu_stack_base]
    add  rax, 0x5000
    test edi, edi
    jnz  .out
    mov  rax, [rel percpu_stack_base]
    add  rax, PERCPU_STACK_BSP_TOP
.out:
    ret
percpu_stack_ist_top:
    mov  eax, edi
    shl  rax, 15
    add  rax, [rel percpu_stack_base]
    add  rax, 0x7000
    ret

; EDI=CPU, RSI=proposed RSP0 -> CF. No mutable pointer is trusted as owner.
percpu_stack_prepare_check:
    cmp  edi, PERCPU_STACK_CPUS
    jae  .bad
    cmp  byte [rel percpu_stack_ready], 1
    jne  .bad
    lea  rax, [rel percpu_stack_sealed]
    cmp  byte [rax + rdi], 0
    jne  .bad
    call percpu_stack_kernel_top
    cmp  rax, rsi
    jne  .bad
    clc
    ret
.bad:
    stc
    ret
percpu_stack_seal:
    lea  rax, [rel cpu_apic_id]
    mov  edx, [rax + rdi*4]
    lea  rax, [rel percpu_stack_apic]
    mov  [rax + rdi*4], edx
    lea  rax, [rel percpu_stack_sealed]
    mov  byte [rax + rdi], 1             ; never cleared or released
    ret

; Separated only so the HOST assembly harness can substitute privileged CR3.
percpu_stack_root_matches:
    mov  rax, cr3
    and  rax, ~0xFFF
    cmp  rax, [rel pml4_addr]
    ret

; Walk the installed ancestors from the selected CR3 root. The reservation
; path uses paging's layout helper before CR3 activation; the witness must not
; infer live translation from that layout after boot.
; RAX=selected root, RDI=arena base -> RAX=PDE pointer or zero.
percpu_stack_live_pde:
    mov  rax, [rax]                      ; arena is always below 4 GiB
    mov  ecx, eax
    and  ecx, 0x87
    cmp  ecx, 3                         ; P + RW, supervisor, not a huge leaf
    jne  .bad
    mov  rcx, 0x000FFFFFFFFFF000
    and  rax, rcx
    mov  rdx, rdi
    shr  rdx, 30
    mov  rax, [rax + rdx*8]
    mov  edx, eax
    and  edx, 0x87
    cmp  edx, 3
    jne  .bad
    and  rax, rcx
    mov  rdx, rdi
    shr  rdx, 21
    and  edx, 511
    lea  rax, [rax + rdx*8]
    ret
.bad:
    xor  eax, eax
    ret

; Read-only resampling: CF=fail, EAX=held CPUs checked on success.
; ECX=failed-held, EDX=reason (0/5), EDI=failing CPU (-1 for global).
; Verifies actual TSS RSP0/IST1 and busy descriptor base, not a saved copy of
; the proposed stack pointers. Fixed disjoint strides + one-shot preparation
; and permanent non-heap ownership cover lifetime, not merely canary survival.
percpu_stack_check:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    xor  ebp, ebp                      ; failed CPUs retaining ownership
    xor  r13d, r13d                    ; all CPUs holding a stack
    mov  r12d, -1                       ; global failure has no CPU index
    cmp  byte [rel percpu_stack_ready], 1
    jne  .bad
    call percpu_stack_root_matches
    jne  .bad
    mov  r14, [rel percpu_stack_alloc]
    test r14, 0xFFF
    jnz  .bad
    test r14, r14
    jz   .bad
    lea  rax, [r14 + PERCPU_STACK_ALLOC_SIZE]
    mov  rdx, 0x100000000
    cmp  rax, rdx
    ja   .bad
    ; Firmware owners and bump heap must remain disjoint for the whole boot.
    cmp  rax, [rel heap_base]
    jbe  .disjoint
    mov  rdx, [rel heap_base]
    add  rdx, [rel heap_size]
    jc   .bad
    cmp  r14, rdx
    jb   .bad
.disjoint:
    add  r14, 0x1FFFFF
    and  r14, ~0x1FFFFF
    cmp  r14, [rel percpu_stack_base]
    jne  .bad
    lea  r15, [r14 + PERCPU_STACK_PT]
    mov  rdi, r14
    mov  rax, [rel pml4_addr]
    call percpu_stack_live_pde
    test rax, rax
    jz   .bad
    mov  rdx, 0x000FFFFFFFFFF087
    and  rdx, [rax]
    lea  rax, [r15 + 3]
    cmp  rax, rdx
    jne  .bad
    mov  rax, [rel pmod_sandbox_pml4]
    test rax, rax
    jz   .host_only
    mov  rdi, r14
    cmp  rdi, 0x40000000
    je   .bad                           ; active PMOD window aliases arena
    call percpu_stack_live_pde
    test rax, rax
    jz   .bad
    mov  rdx, 0x000FFFFFFFFFF087
    and  rdx, [rax]
    lea  rax, [r15 + 3]
    cmp  rax, rdx
    jne  .bad
.host_only:
    mov  eax, [rel smp_discovered_count]
    test eax, eax
    jz   .bad
    cmp  eax, PERCPU_STACK_CPUS
    ja   .bad
    cmp  byte [rel cpu_state], CPU_STATE_BSP
    jne  .bad
    xor  r12d, r12d
    xor  r13d, r13d
.cpu:
    lea  rax, [rel ap_stacks]
    cmp  qword [rax + r12*8], 0
    jne  .held
    ; A discovered CPU may never have been admitted/prepared (bounded trial),
    ; but a published online CPU may never lack an owned stack.
    lea  rax, [rel cpu_state]
    cmp  byte [rax + r12], CPU_STATE_BSP
    je   .bad
    cmp  byte [rax + r12], CPU_STATE_ONLINE
    je   .bad
    jmp  .next
.held:
    lea  rax, [rel cpu_state]
    movzx r11d, byte [rax + r12]         ; one state snapshot; AP may go online
    cmp  r11b, CPU_STATE_FAILED
    jne  .owner
    inc  ebp
.owner:
    lea  rax, [rel percpu_stack_sealed]
    cmp  byte [rax + r12], 1
    jne  .bad
    lea  rax, [rel cpu_apic_id]
    mov  eax, [rax + r12*4]
    lea  rdx, [rel percpu_stack_apic]
    cmp  eax, [rdx + r12*4]
    jne  .bad
    mov  edi, r12d
    call percpu_stack_kernel_top
    mov  r8, rax
    lea  rdx, [rel ap_stacks]
    cmp  rax, [rdx + r12*8]
    jne  .bad
    call percpu_stack_ist_top
    mov  r9, rax
    ; Resolve actual per-CPU descriptor/TSS owner in both supported banks.
    mov  eax, r12d
    cmp  eax, GDT_PERCPU_MAX
    jae  .extension
    imul rax, GDT_PERCPU_TSS_SIZE
    lea  rbx, [rel gdt_percpu_tss]
    add  rbx, rax
    mov  eax, r12d
    imul rax, GDT_PERCPU_TABLE_SIZE
    lea  rdx, [rel gdt_percpu_tables + 24]
    jmp  .descriptor
.extension:
    sub  eax, GDT_PERCPU_MAX
    imul rax, SMP_GDT_TSS_SIZE
    lea  rbx, [rel smp_gdt_ext_tss]
    add  rbx, rax
    mov  eax, r12d
    sub  eax, GDT_PERCPU_MAX
    imul rax, SMP_GDT_TABLE_SIZE
    lea  rdx, [rel smp_gdt_ext_tables + 24]
.descriptor:
    add  rdx, rax
    ; ONLINE/BSP must have loaded TR. A failed or still-pending CPU may
    ; retain a prepared available descriptor; its owner and guards still hold.
    movzx ecx, byte [rdx + 5]
    cmp  ecx, 0x8B
    je   .descriptor_base
    cmp  ecx, 0x89
    jne  .bad
    cmp  r11b, CPU_STATE_BSP
    je   .bad
    cmp  r11b, CPU_STATE_ONLINE
    je   .bad
.descriptor_base:
    movzx eax, word [rdx + 2]
    movzx ecx, byte [rdx + 4]
    shl  rcx, 16
    or   rax, rcx
    movzx ecx, byte [rdx + 7]
    shl  rcx, 24
    or   rax, rcx
    mov  ecx, [rdx + 8]
    shl  rcx, 32
    or   rax, rcx
    cmp  rax, rbx
    jne  .bad
    cmp  [rbx + 4], r8
    jne  .bad
    cmp  [rbx + 0x24], r9
    jne  .bad
    ; All kernel/IST pages identity-backed, RW+NX, supervisor-only. Lower
    ; and upper guards are genuinely non-present in the installed leaf table.
    mov  rdi, r8
    mov  esi, 4
    test r12d, r12d
    jnz  .kernel
    mov  esi, 16
    ; The checker itself must be on CPU0's permanently owned kernel stack.
    lea  rax, [r8 - 0x10000]
    cmp  rsp, rax
    jb   .bad
    cmp  rsp, r8
    jae  .bad
.kernel:
    call .range
    jc   .bad
    mov  rdi, r9
    mov  esi, 1
    call .range
    jc   .bad
    inc  r13d
.next:
    inc  r12d
    cmp  r12d, [rel smp_discovered_count]
    jb   .cpu
    mov  eax, r13d
    xor  edx, edx                      ; reason 0 = owned, sealed, guarded
    clc
    jmp  .out
.bad:
    xor  eax, eax
    mov  edx, 5                         ; census reason: arena owner/guard fault
    stc
.out:
    mov  ecx, ebp                       ; failed-held count (not itself failure)
    mov  edi, r12d                      ; failing CPU, -1 for a global fault
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret
; RDI=top, ESI=page count. Preserves R8/R9 (live expected kernel/IST tops).
.range:
    mov  rdx, rdi
    sub  rdx, r14
    shr  rdx, 12
    test byte [r15 + rdx*8], 1           ; guard immediately above top
    jnz  .range_bad
.page:
    sub  rdi, 4096
    dec  edx
    mov  rax, 0x800FFFFFFFFFF007
    and  rax, [r15 + rdx*8]
    mov  rcx, rdi
    or   rcx, 3
    bts  rcx, 63
    cmp  rax, rcx
    jne  .range_bad
    dec  esi
    jnz  .page
    test byte [r15 + rdx*8 - 8], 1      ; lower guard, not a painted canary
    jnz  .range_bad
    clc
    ret
.range_bad:
    stc
    ret

%include "core/abi/wdata.inc"
%macro WDATA_percpu_stack 0
align 8
percpu_stack_alloc: dq 0
percpu_stack_base: dq 0
percpu_stack_ready: db 0
percpu_stack_sealed: times PERCPU_STACK_CPUS db 0
align 4
percpu_stack_apic: times PERCPU_STACK_CPUS dd 0
%endmacro
WDATA_DEFER WDATA_percpu_stack
