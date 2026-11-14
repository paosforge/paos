;; MODULE hv/a1_reset_i219
;; LAYER 5
;; EXPORTS a1_reset_i219_phase
;; IMPORTS bus/pci_bdf, boot/paging, core/time
;; CAPS CAP_MMIO
;; OWNER rc-boot-claude
;; CONTEXT: bsp_only
; RDI=original resident R2 request320, RSI=private result256, EDX=256.
; EAX:0 phase observed,2 no device effect,3 attempted/uncertain contained.
; S1 implements op1 probe and op2 host quiesce ONLY, method20001. Ops3..5
; refuse before device access: an old clear CTRL.RST/LAN_INIT or guest report
; never establishes a new guest reset, ready service, reset-out or reclaim.
; No FLR/AF-FLR/SBR/PM/MAC/PHY reset, driver globals, DMA descriptor access,
; injection, mapping, allocator, claim release, or public entry is introduced.
;
; VM's sole dispatcher owns authenticated mode/profile, complete topology and
; requester/claim custody, producer fencing, exclusive original attempt and
; immutable resident storage. This leaf is NOT a pointer/permission API: it
; receives only those validated native operands, never guest data or copies as
; authority. VM freezes the result before reuse and retains containment/DMA.
; It may exercise this candidate only under a reviewed qualification packet;
; there is no routine admission or hardware-family qualification in this leaf.
;
; Local R2 offsets do not define VM's shared constants. Map READ=1,WRITE=2;
; actual UC/resource/identity leaves are independently checked. Only exact
; Dell8086:15d7,00:1f.6, current supplied revision/subsystem are accepted.
; Descriptor flush-required refuses instead of borrowing native ring custody.
; Readback slots/selectors and reason values: docs/a1_dell_i219_reset.md.

a1_reset_i219_phase:
    mov eax, 2
    cmp edx, 256
    jne .early
    test rsi, rsi
    jz .early
    test rsi, 7
    jnz .early
    mov r8, rsi
    add r8, 256
    jc .early
    test rdi, rdi
    jz .early
    test rdi, 7
    jnz .early
    mov r9, rdi
    add r9, 320
    jc .early
    cmp rsi, r9
    jae .separate
    cmp rdi, r8
    jb .early
.separate:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 488                     ; immutable request320,map64,scratch104
    mov r13, rsi
    mov rsi, rdi
    mov rdi, rsp
    mov ecx, 40
    cld
    rep movsq
    mov r12, rsp
    mov rdi, r13
    xor eax, eax
    mov ecx, 32
    rep stosq
    mov dword [r13], 'A1RS'
    mov dword [r13+4], (256<<16)|1
    mov dword [r13+16], 2
    mov dword [r13+28], 1
    cmp dword [r12], 'A1RQ'
    jne .done
    cmp dword [r12+4], (320<<16)|1
    jne .done
    mov eax, [r12+8]
    mov [r13+8], eax
    mov eax, [r12+12]
    mov [r13+12], eax
    mov eax, [r12+24]
    mov [r13+32], eax
    mov rax, [r12+40]
    mov [r13+40], rax
    mov rax, [r12+48]
    mov [r13+48], rax
    mov rax, [r12+56]
    mov [r13+56], rax
    mov rax, [r12+296]
    mov [r13+64], rax
    mov dword [r13+28], 2
    cmp dword [r12+8], 0x20001
    jne .done
    cmp dword [r12+12], 1
    je .supported
    cmp dword [r12+12], 2
    jne .done                        ; exhaustive before common writes/reads
.supported:
    mov dword [r13+28], 1
    cmp qword [r12+312], 0
    jne .done
    cmp qword [r12+40], 0
    je .done
    cmp qword [r12+48], 0
    je .done
    cmp qword [r12+56], 0
    je .done
    cmp qword [r12+296], 0
    je .done
    cmp dword [r12+20], 1
    jb .done
    cmp dword [r12+20], 4
    ja .done
    mov r14d, [r12+24]
    cmp r14d, 0xfe                   ; exact function, not arbitrary PCH scan
    jne .identity
    cmp dword [r12+28], 0x15d78086
    jne .identity
    mov eax, [r12+32]
    shr eax, 8
    cmp eax, 0x020000
    jne .identity
    cmp word [r12+36], 0x1028        ; exact supplied Dell subsystem rechecked
    jne .identity
    cmp dword [r12+100], 1
    jne .done
    mov rax, [r12+104]
    test rax, rax
    jz .done
    test al, 3
    jnz .done
    mov rcx, rax
    add rcx, 4
    jc .done
    lea rdx, [r13+256]
    cmp rax, rdx
    jae .scope_separate
    cmp rcx, r13
    ja .done
.scope_separate:
    cmp [rax], r14d                 ; consume immutable single-function scope
    jne .identity
    cmp qword [r12+72], 100000
    jb .budget
    cmp qword [r12+72], 10000000
    ja .budget
    cmp dword [r12+12], 2
    jne .map
    pushfq
    pop rax
    test eax, 0x200                 ; serialized BSP/IF0 effect phase
    jnz .done
    cmp qword [r12+128], 0           ; held original domain/custody, not permit
    je .done
.map:
    mov rsi, [r12+112]
    test rsi, rsi
    jz .bad_map
    test rsi, 7
    jnz .bad_map
    cmp dword [r12+120], 64
    jne .bad_map
    mov rax, rsi
    add rax, 64
    jc .bad_map
    lea rdx, [r13+256]
    cmp rsi, rdx
    jae .map_separate
    cmp rax, r13
    ja .bad_map
.map_separate:
    lea rdi, [rsp+320]
    mov ecx, 8
    rep movsq                       ; do not revisit a mutable map descriptor
    lea r15, [rsp+320]
    cmp dword [r15], 'A1MP'
    jne .bad_map
    cmp dword [r15+4], (64<<16)|1
    jne .bad_map
    mov rax, [r15+8]
    test rax, rax
    jz .bad_map
    cmp rax, [r12+304]
    jne .bad_map
    mov rax, [r15+40]
    cmp rax, [r12+40]
    jne .bad_map
    cmp [r15+48], r14d
    jne .bad_map
    cmp dword [r15+32], 0
    jne .bad_map
    cmp dword [r15+52], 0
    jne .bad_map
    cmp qword [r15+56], 0
    jne .bad_map
    mov eax, [r15+36]
    test eax, 1
    jz .bad_map
    cmp dword [r12+12], 2
    jne .map_extent
    and eax, 3
    cmp eax, 3
    jne .bad_map
.map_extent:
    cmp qword [r15+24], 0x382c
    jb .bad_map
    mov rbp, [r15+16]
    test rbp, rbp
    jz .bad_map
    test rbp, 0xfff
    jnz .bad_map
    mov rax, rbp
    add rax, [r15+24]
    jc .bad_map
    shr rax, 34
    jnz .bad_map                     ; only existing low16GiB identity slice
    xor esi, esi
    call a1i_cfg
    jc .budget
    xor ebx, ebx
    call a1i_sample
    cmp eax, [r12+28]
    jne .identity
    mov esi, 8
    call a1i_cfg
    jc .budget
    mov ebx, 1
    call a1i_sample
    cmp eax, [r12+32]
    jne .identity
    mov esi, 0x2c
    call a1i_cfg
    jc .budget
    mov ebx, 2
    call a1i_sample
    cmp eax, [r12+36]
    jne .identity
    mov esi, 0xc
    call a1i_cfg
    jc .budget
    cmp eax, -1
    je .unavailable
    test eax, 0x007f0000             ; endpoint, no bridge header
    jnz .identity
    mov esi, 0x10
    call a1i_cfg
    jc .budget
    mov ebx, 3
    call a1i_sample
    cmp eax, -1
    je .unavailable
    test eax, 7                     ; only original32-bit memory BAR0, no sizing
    jnz .bad_map
    mov [rsp+388], eax
    and eax, ~15
    cmp rax, rbp
    jne .bad_map
    mov esi, 4
    call a1i_cfg
    jc .budget
    mov ebx, 14
    call a1i_sample
    cmp eax, -1
    je .unavailable
    test eax, 2                     ; do not enable memory decoding for discovery
    jz .bad_map
    mov [rsp+384], eax
    movzx edx, ax
    mov [r13+72], edx
    mov esi, 0xe4
    call a1i_cfg
    jc .budget
    mov ebx, 4
    call a1i_sample
    cmp eax, -1
    je .unavailable
    test eax, 1<<8
    jnz .flush
    ; Every actual MMIO leaf touched, including an end crossing, must be
    ; firmware MMIO/reserved, identity-mapped and UC. Never edit page tables.
    mov rbx, rbp
    and rbx, -0x200000
.page:
    mov rdi, rbx
    call pci_mmio_resource_page
    test eax, eax
    jz .bad_map
    mov rdi, rbx
    call paging_pd_entry_ptr
    test rax, rax
    jz .bad_map
    mov rax, [rax]
    mov edx, eax
    and edx, 0x109b                 ; P/RW/large,PCD/PWT,PAT0 in actual PDE
    cmp edx, 0x9b
    jne .bad_map
    mov rdx, 0x000fffffffe00000
    and rax, rdx
    cmp rax, rbx
    jne .bad_map
    add rbx, 0x200000
    lea rax, [rbp+0x382b]
    cmp rbx, rax
    jbe .page
    call a1i_identity               ; bracket actual mapping before MMIO
    jc .done
    mov esi, 0
    mov ebx, 11
    call a1i_mmio_sample
    jc .done
    mov [rsp+392], eax
    test eax, (1<<26)|(1<<31)
    jnz .reset_busy
    mov esi, 8
    mov ebx, 6
    call a1i_mmio_sample
    jc .done
    mov esi, 0xd0
    mov ebx, 5
    call a1i_mmio_sample
    jc .done
    mov [r13+80], eax
    mov esi, 0x100
    mov ebx, 9
    call a1i_mmio_sample
    jc .done
    mov [rsp+396], eax
    mov esi, 0x400
    mov ebx, 10
    call a1i_mmio_sample
    jc .done
    mov [rsp+400], eax
    mov esi, 0x2828
    mov ebx, 7
    call a1i_mmio_sample
    jc .done
    mov [rsp+404], eax
    mov esi, 0x3828
    mov ebx, 8
    call a1i_mmio_sample
    jc .done
    mov [rsp+408], eax
    mov dword [r13+20], 1
    cmp dword [r12+12], 1
    je .probe_done
    ; Refuse before first effect unless the entire bounded200ms phase plus
    ; original reserve fits. No helper starts a fresh timeout window.
    call a1i_budget
    jc .budget
    mov rax, [r12+72]
    imul rax, 200
    cmp rdx, rax
    jb .budget
    mov dword [r13+28], 11
    mov esi, 0xd8
    mov edx, -1
    call a1i_write
    jc .done
    mov esi, 0xd0
    mov ebx, 13
    call a1i_mmio_sample
    jc .done
    mov [r13+84], eax
    test eax, eax
    jnz .done
    mov dword [r13+28], 12
    mov esi, 0x2828
    mov edx, [rsp+404]
    and edx, ~(1<<25)
    call a1i_write
    jc .done
    mov esi, 0x3828
    mov edx, [rsp+408]
    and edx, ~(1<<25)
    call a1i_write
    jc .done
    mov dword [rsp+416], 100
.queue_wait:
    mov esi, 0x2828
    mov ebx, 7
    call a1i_mmio_sample
    jc .done
    mov [rsp+424], eax
    mov esi, 0x3828
    mov ebx, 8
    call a1i_mmio_sample
    jc .done
    or eax, [rsp+424]
    test eax, 1<<25
    jz .queues_off
    call a1i_delay
    jc .done
    dec dword [rsp+416]
    jnz .queue_wait
    jmp .done
.queues_off:
    mov esi, 0x100
    mov edx, [rsp+396]
    and edx, ~2
    call a1i_write
    jc .done
    mov esi, 0x100
    mov ebx, 9
    call a1i_mmio_sample
    jc .done
    test eax, 2
    jnz .done
    mov esi, 0x400
    mov edx, [rsp+400]
    and edx, ~2
    call a1i_write
    jc .done
    mov esi, 0x400
    mov ebx, 10
    call a1i_mmio_sample
    jc .done
    test eax, 2
    jnz .done
    mov dword [r13+28], 13
    mov esi, 0
    mov edx, [rsp+392]
    or edx, 4
    call a1i_write
    jc .done
    mov esi, 0
    mov ebx, 11
    call a1i_mmio_sample
    jc .done
    test eax, 4
    jz .done
    mov dword [rsp+416], 800
.master_wait:
    mov esi, 8
    mov ebx, 12
    call a1i_mmio_sample
    jc .done
    test eax, 1<<19
    jz .master_off
    call a1i_delay
    jc .done
    dec dword [rsp+416]
    jnz .master_wait
    jmp .done
.master_off:
    call a1i_identity               ; no resetting device or changed ownership
    jc .done
    mov dword [r13+28], 14
    mov esi, 4
    call a1i_cfg
    jc .budget
    cmp eax, -1
    je .unavailable
    movzx eax, ax
    cmp ax, word [rsp+384]
    jne .identity
    and eax, ~4
    mov [rsp+420], eax
    call a1i_budget
    jc .budget
    mov edi, r14d
    mov esi, 4
    mov edx, [rsp+420]              ; Status W1C half is ZERO, no adjacent write
    call pci_bdf_write
    mov esi, 4
    call a1i_cfg
    jc .budget
    mov ebx, 15
    or esi, 0x40000000
    call a1i_sample
    cmp eax, -1
    je .unavailable
    movzx eax, ax
    mov [r13+76], eax
    cmp eax, [rsp+420]
    jne .done
    mov dword [r13+16], 0
    mov dword [r13+20], 2
    mov dword [r13+24], 5            ; attempted+hostquiesce, NEVER reset/ready
    mov dword [r13+28], 0
    jmp .done
.probe_done:
    mov dword [r13+16], 0
    mov dword [r13+28], 0
    jmp .done
.identity:
    mov dword [r13+28], 3
    jmp .done
.unavailable:
    mov dword [r13+28], 4
    jmp .done
.bad_map:
    mov dword [r13+28], 7
    jmp .done
.budget:
    mov dword [r13+28], 8
    jmp .done
.flush:
    mov dword [r13+28], 9
    jmp .done
.reset_busy:
    mov dword [r13+28], 10
.done:
    mov eax, [r13+16]
    add rsp, 488
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
.early:
    ret

; Only bounded original absolute budget; RDX=remaining after reserve.
; Every callable helper enters at RSP%16=8 and aligns before nested calls.
; LEA/POP cleanup preserves the carry returned to its caller on refusal.
a1i_budget:
    sub rsp, 8
    call tsc_now
    lea rsp, [rsp+8]
    cmp rax, [r12+64]
    jae .no
    mov rdx, [r12+64]
    sub rdx, rax
    cmp rdx, [r12+80]
    jbe .no
    sub rdx, [r12+80]
    clc
    ret
.no:
    stc
    ret

a1i_cfg:
    push rsi
    call a1i_budget
    mov rsi, [rsp]
    jc .out
    mov edi, r14d
    call pci_bdf_read
    clc
.out:
    pop rsi
    ret

; EBX is a fixed0..15 slot, ESI selector, EAX actual sample. Each slot's
; availability denotes an actual bounded read, not a preinitialized zero.
; Repeated polls replace their own slot, never truncate original observations.
a1i_sample:
    mov [r13+rbx*8+96], esi
    mov [r13+rbx*8+100], eax
    bt dword [r13+92], ebx
    jc .existing
    inc dword [r13+88]
    bts dword [r13+92], ebx
.existing:
    ret

a1i_mmio_sample:
    push rsi
    call a1i_budget
    mov rsi, [rsp]
    jc .budget
    mov eax, [rbp+rsi]
    or esi, 0x10000000
    call a1i_sample
    and esi, 0x0fffffff
    cmp eax, -1
    je .unavailable
    clc
    pop rsi
    ret
.budget:
    mov dword [r13+28], 8
    stc
    pop rsi
    ret
.unavailable:
    mov dword [r13+28], 4
    stc
    pop rsi
    ret

a1i_write:
    push rsi
    push rdx
    sub rsp, 8
    call a1i_budget
    lea rsp, [rsp+8]
    pop rdx
    pop rsi
    jc .budget
    mov dword [r13+16], 3
    mov dword [r13+24], 1            ; actual attempt follows, budget already held
    mov [rbp+rsi], edx
    clc
    ret
.budget:
    mov dword [r13+28], 8
    stc
    ret

a1i_delay:
    sub rsp, 8
    call a1i_budget
    jc .budget
    mov rax, [r12+72]
    ; Need at least100us before original reserve; do not borrow the reserve.
    add rax, 9
    xor edx, edx
    mov ecx, 10
    div rcx
    mov rcx, [r12+64]
    sub rcx, [r12+80]
    push rax
    push rcx
    call tsc_now
    pop rcx
    pop rdx
    sub rcx, rax
    jc .budget
    cmp rcx, rdx
    jb .budget
    mov edi, 100
    call tsc_delay_us
    clc
    lea rsp, [rsp+8]
    ret
.budget:
    mov dword [r13+28], 8
    stc
    lea rsp, [rsp+8]
    ret

; Recheck every live config fact used in map/identity admission. Preserve
; available contradictory raw identity/E4 in their fixed observation slots.
a1i_identity:
    sub rsp, 8
    xor esi, esi
    xor ebx, ebx
    call a1i_cfg
    jc .budget
    or esi, 0x40000000
    call a1i_sample
    cmp eax, [r12+28]
    jne .identity
    mov esi, 8
    mov ebx, 1
    call a1i_cfg
    jc .budget
    or esi, 0x40000000
    call a1i_sample
    cmp eax, [r12+32]
    jne .identity
    mov esi, 0x2c
    mov ebx, 2
    call a1i_cfg
    jc .budget
    or esi, 0x40000000
    call a1i_sample
    cmp eax, [r12+36]
    jne .identity
    mov esi, 0x10
    call a1i_cfg
    jc .budget
    cmp eax, [r12+388]
    jne .identity
    mov esi, 4
    call a1i_cfg
    jc .budget
    cmp eax, -1
    je .identity
    cmp ax, word [r12+384]
    jne .identity
    mov esi, 0xe4
    mov ebx, 4
    call a1i_cfg
    jc .budget
    or esi, 0x40000000
    call a1i_sample
    cmp eax, -1
    je .unavailable
    test eax, 1<<8
    jnz .flush
    clc
    lea rsp, [rsp+8]
    ret
.budget:
    mov dword [r13+28], 8
    stc
    lea rsp, [rsp+8]
    ret
.identity:
    mov dword [r13+28], 3
    stc
    lea rsp, [rsp+8]
    ret
.unavailable:
    mov dword [r13+28], 4
    stc
    lea rsp, [rsp+8]
    ret
.flush:
    mov dword [r13+28], 9
    stc
    lea rsp, [rsp+8]
    ret
