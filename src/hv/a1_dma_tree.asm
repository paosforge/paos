;; MODULE hv/a1_dma_tree
;; LAYER 5
;; EXPORTS a1_dma_tree_build, a1_dma_tree_check
;; IMPORTS hv/amdvi
;; CAPS
;; OWNER td-row3
;
; Unpublished AMD-Vi tables only. No allocator, DTE, MMIO, PCI, reset, command
; queue or START route. This primitive confers no assignment/DMA authority.
; The serialized native owner supplies immutable, resident plan128 and an
; exclusive, identity-addressed six-page allocation which is NOT hardware-live.
; It must prove allocation ownership, protected/native-DMA exclusion, signed
; profile and original START custody before any future install. Numeric
; generation/attempt operands compare identity, never authenticate that owner.
;
; Plan A1DT/v1/128 (all qwords except header):
; 0 magic, 4 u16 version, 6 u16 exact bytes; 8 generation, 16 attempt,
; 24 host RAM base, 32 compact RAM bytes, 40 table base, 48 exact table bytes,
; 56 IVMD count (must 0), 64..127 reserved zero. No pointer to reserved ranges.
; Guest RAM: 2MiB-aligned positive span <=4GiB; GPA3..4GiB stays unmapped.
; RAM above compact offset3GiB appears at GPA4GiB, as in amdvi_guest_expected.
; Current v1 has no 4KiB/split-leaf or reserved-DMA authority, including Reatan.
;
; Both APIs: RDI=plan, RSI=exact128, RDX=original generation,
; RCX=original attempt -> EAX0 success, 1 refusal. Preserve SysV callee-saved.
; Extents/identity/reserved fields/disjointness checked before any output write.
; Build writes exactly table24576; check only reads it and never follows its
; pointers. Neither dereferences guest RAM. Caller retains resources on failure.

A1DT_MAGIC equ 0x54443141             ; "A1DT"
A1DT_BYTES equ 128
A1DT_GEN equ 8
A1DT_ATTEMPT equ 16
A1DT_HOST equ 24
A1DT_RAM_BYTES equ 32
A1DT_TABLE equ 40
A1DT_TABLE_BYTES equ 48
A1DT_IVMD equ 56
A1DT_PAGES equ 6
A1DT_SIZE equ A1DT_PAGES*4096
A1DT_WORDS equ A1DT_SIZE/8

a1_dma_tree_build:
    push rbx
    push r12
    push r13
    call a1dt_validate
    test eax,eax
    jnz .out
    mov rbx,rdi
    mov r12,[rbx+A1DT_TABLE]
    xor r13d,r13d
.word:
    mov ecx,r13d
    call a1dt_expected
    mov [r12+r13*8],rax
    inc r13d
    cmp r13d,A1DT_WORDS ; construct every word
    jb .word
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

a1_dma_tree_check:
    push rbx
    push r12
    push r13
    call a1dt_validate
    test eax,eax
    jnz .out
    mov rbx,rdi
    mov r12,[rbx+A1DT_TABLE]
    xor r13d,r13d
.word:
    mov ecx,r13d
    call a1dt_expected
    cmp [r12+r13*8],rax
    jne .bad ; exact native table bytes
    inc r13d
    cmp r13d,A1DT_WORDS ; check every word
    jb .word
    xor eax,eax
    jmp .out
.bad:
    mov eax,1
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Private scalar-only preflight. No invalid address is dereferenced until its
; outer extent/alignment is checked. Resident mapped storage remains an owner
; obligation; canonicality is not a probe of arbitrary host virtual memory.
; Uses caller-saved registers only; preserves RDI for expected-word generation.
a1dt_validate:
    cmp rsi,A1DT_BYTES
    jne .no
    test rdx,rdx
    jz .no
    test rcx,rcx
    jz .no
    test rdi,rdi
    jz .no
    test rdi,7
    jnz .no
    mov rax,rdi
    add rax,A1DT_BYTES-1
    jc .no
    shr rax,47
    jnz .no
    cmp dword [rdi],A1DT_MAGIC
    jne .no
    cmp word [rdi+4],1
    jne .no
    cmp word [rdi+6],A1DT_BYTES
    jne .no
    cmp [rdi+A1DT_GEN],rdx
    jne .no ; original generation
    cmp [rdi+A1DT_ATTEMPT],rcx
    jne .no ; original attempt
    cmp qword [rdi+A1DT_TABLE_BYTES],A1DT_SIZE
    jne .no
    cmp qword [rdi+A1DT_IVMD],0
    jne .no ; no reserved-DMA authority
    mov ecx,64
.reserved:
    cmp qword [rdi+rcx],0
    jne .no ; reserved plan bytes
    add ecx,8
    cmp ecx,A1DT_BYTES
    jb .reserved
    mov r8,[rdi+A1DT_HOST]
    test r8,r8
    jz .no
    test r8,0x1fffff
    jnz .no
    mov r9,[rdi+A1DT_RAM_BYTES]
    test r9,r9
    jz .no
    test r9,0x1fffff
    jnz .no
    mov rax,0x100000000
    cmp r9,rax
    ja .no
    add r9,r8                         ; RAM exclusive end
    jc .no
    lea rax,[r9-1]
    shr rax,47
    jnz .no
    mov r10,[rdi+A1DT_TABLE]
    test r10,r10
    jz .no
    test r10,4095
    jnz .no
    mov r11,r10
    add r11,A1DT_SIZE                 ; table exclusive end
    jc .no
    lea rax,[r11-1]
    shr rax,47
    jnz .no
    cmp r10,r9
    jae .plan_ram
    cmp r8,r11
    jb .no ; output overlaps guest RAM
.plan_ram:
    lea rax,[rdi+A1DT_BYTES]
    cmp rdi,r9
    jae .plan_table
    cmp r8,rax
    jb .no ; plan overlaps guest RAM
.plan_table:
    cmp rdi,r11
    jae .yes
    cmp r10,rax
    jb .no ; output overlaps plan
.yes:
    xor eax,eax
    ret
.no:
    mov eax,1
    ret

; Expected qword at flat ECX in this unpublished six-page tree. Same compact
; RAM/device-hole geometry and native AMD encodings as amdvi_guest_expected;
; no hardware/global guest state is consulted or changed. RBX=validated plan.
a1dt_expected:
    xor eax,eax
    test ecx,ecx
    jnz .pdpt
    mov rax,[rbx+A1DT_TABLE]
    add rax,4096
    mov rdx,AMDVI_PDE_RW | (3<<9)
    or rax,rdx
    ret
.pdpt:
    cmp ecx,512
    jb .out
    cmp ecx,1024
    jae .leaf
    mov edx,ecx
    sub edx,512
    cmp edx,3
    je .out ; device hole
    jb .pd_index
    cmp edx,4
    jne .out
    dec edx
.pd_index:
    mov r8,[rbx+A1DT_RAM_BYTES]
    dec r8
    shr r8,30
    cmp rdx,r8
    ja .out
    shl rdx,12
    mov rax,[rbx+A1DT_TABLE]
    lea rax,[rax+rdx+8192]
    mov rdx,AMDVI_PDE_RW | (2<<9)
    or rax,rdx
    ret
.leaf:
    mov edx,ecx
    sub edx,1024
    shl rdx,21
    cmp rdx,[rbx+A1DT_RAM_BYTES]
    jae .out ; exact guest RAM extent
    mov rax,[rbx+A1DT_HOST]
    add rax,rdx
    mov rdx,AMDVI_PTE_LEAF
    or rax,rdx
.out:
    ret
