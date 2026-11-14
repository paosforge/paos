;; MODULE hv/amdvi_guest
;; LAYER 5
;; EXPORTS amdvi_guest_attach, amdvi_guest_detach, amdvi_guest_receipt
;; IMPORTS hv/amdvi, hv/amdvi_hda, hv/vtd, core/dma
;; CAPS CAP_MMIO
;; OWNER rc-codex-av
; Serialized VM owner only. Caller owns reset/quiesce and external group/ACS
; authority; IVRS singleton is not a claim about PCI peer isolation.
; DID4 maps guest GPA to contiguous owner-supplied host RAM, never identity
; host memory. Six compat-carved pages: PML4, PDPT, four PDs (2MiB leaves).
; No MSI aperture. QW2=1: IV=1, IntCtl=abort, IntTabLen=0.
AMDVI_DOM_GUEST equ 4
AMDVI_GUEST_LIVE equ 1
AMDVI_GUEST_RETIRED equ 2
AMDVI_GUEST_POISON equ 3

amdvi_guest_reset:
    mov qword [rel amdvi_guest_pages], 0
    mov qword [rel amdvi_guest_generation], 0
    mov qword [rel amdvi_guest_size], 0
    mov qword [rel amdvi_guest_host], 0
    mov dword [rel amdvi_guest_bdf], 0
    mov byte [rel amdvi_guest_state], 0
    ret

; RDI,RSI span; EAX1 if it intersects pinned guest RAM (including poison).
; Preserve arguments and other caller scratch. Retired spans are reusable.
amdvi_guest_range_overlap:
    xor eax,eax
    cmp byte [rel amdvi_guest_state],AMDVI_GUEST_LIVE
    je .check
    cmp byte [rel amdvi_guest_state],AMDVI_GUEST_POISON
    jne .out
.check:
    mov rdx,rdi
    add rdx,rsi
    jc .yes
    cmp rdx,[rel amdvi_guest_host]
    jbe .out
    mov rdx,[rel amdvi_guest_host]
    add rdx,[rel amdvi_guest_size]
    cmp rdi,rdx
    jae .out
.yes: mov eax,1
.out: ret

; Called before mutation. Trusted VM allocation plus explicit exclusion of all
; live native/HDA DMA records and IOMMU structures. No guest RAM is dereferenced.
amdvi_guest_ram_ok:
    push rbx
    push r12
    push r13
    mov r12,rdx
    mov r13,rdx
    test rdx,rdx
    jz .no
    test rdx,0x1fffff
    jnz .no
    test rsi,rsi
    jz .no
    test rsi,0x1fffff
    jnz .no
    mov rax,0x100000000
    cmp rsi,rax
    ja .no
    add r13,rsi
    jc .no
    mov rax,r13
    dec rax
    shr rax,47                         ; directly addressable lower canonical RAM
    jnz .no
    xor ebx,ebx
.record:
    cmp ebx,DMA_IOMMU_SLOTS
    jae .structures
    mov edi,ebx
    call dma_iommu_record
    inc ebx
    test rdx,rdx
    jz .record
    cmp rax,r13
    jae .record
    add rax,rdx
    jc .no
    cmp rax,r12
    ja .no
    jmp .record
.structures:
    mov rax,[rel amdvi_devtab]
    mov edx,AMDVI_DEVTAB_BYTES
    call .overlap
    jc .no
    mov rax,[rel amdvi_pool]
    mov edx,AMDVI_POOL_BYTES
    call .overlap
    jc .no
    call amdvi_mmio_span
    mov edx,eax
    mov rax,[rel amdvi_mmio]
    call .overlap
    jc .no
    mov eax,1
    jmp .out
.overlap:
    cmp rax,r13
    jae .clear
    add rax,rdx
    jc .hit
    cmp rax,r12
    ja .hit
.clear: clc
    ret
.hit: stc
    ret
.no: xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Expected qword at flat index ECX in our six-page tree. RAX result.
amdvi_guest_expected:
    xor eax,eax
    test ecx,ecx
    jnz .pdpt
    mov rax,[rel amdvi_guest_pages]
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
    mov r8,[rel amdvi_guest_size]
    dec r8
    shr r8,30
    cmp rdx,r8
    ja .out
    shl rdx,12
    mov rax,[rel amdvi_guest_pages]
    lea rax,[rax+rdx+8192]
    mov rdx,AMDVI_PDE_RW | (2<<9)
    or rax,rdx
    ret
.leaf:
    mov edx,ecx
    sub edx,1024
    shl rdx,21
    cmp rdx,[rel amdvi_guest_size]
    jae .out
    mov rax,[rel amdvi_guest_host]
    add rax,rdx
    mov rdx,AMDVI_PTE_LEAF
    or rax,rdx
.out: ret

; QW0 RSI, QW1 RCX; stored DeviceID. QW0 last; no V=0 passthrough.
amdvi_guest_dte_set:
    mov eax,[rel amdvi_guest_bdf]
    shl eax,5
    add rax,[rel amdvi_devtab]
    mov qword [rax+24],0
    mov qword [rax+16],1
    mov [rax+8],rcx
    mov [rax],rsi
    clflush [rax]
    mfence
    ret

; Explicit interrupt cache eviction, AMD command type5 / DeviceID low16.
; Linux6.6.32 build_inv_irt independently specifies the same zeroed encoding.
amdvi_guest_flush:
    push rbx
    lea rdi,[rel amdvi_cmd_lock]
    call spin_acquire
    mov edi,[rel amdvi_guest_bdf]
    call amdvi_enc_inv_dte
    call amdvi_cmd_put
    test eax,eax
    jz .out
    mov edi,[rel amdvi_guest_bdf]
    mov rax,5<<60
    or rdi,rax
    xor esi,esi
    call amdvi_cmd_put
    test eax,eax
    jz .out
    mov edi,AMDVI_DOM_GUEST
    call amdvi_enc_inv_pages
    call amdvi_cmd_put
    test eax,eax
    jz .out
    call amdvi_cmd_sync
.out:
    mov ebx,eax
    lea rdi,[rel amdvi_cmd_lock]
    call spin_release
    mov eax,ebx
    pop rbx
    ret

amdvi_guest_poison:
    sub rsp,8
    mov byte [rel amdvi_guest_state],AMDVI_GUEST_POISON
    mov esi,AMDVI_DTE_BLOCKED
    xor ecx,ecx
    call amdvi_guest_dte_set
    call amdvi_guest_flush                 ; best effort, pages/RAM remain pinned
    add rsp,8
    mov eax,-1
    ret

; EDI DeviceID, RSI bytes, RDX host base, RCX START generation -> EAX0/-1.
; Precondition refusal does not steal native/HDA ownership. After committing
; the block, every failure poisons; no path restores the compatibility DTE.
; Restart may reuse only this owner's exact retired requester and blocked DTE,
; with a newer generation. Caller still owns fresh group/reset/quiesce custody.
amdvi_guest_attach:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12d,edi
    mov r13,rsi
    mov r14,rdx
    mov r15,rcx
    cmp edi,0xffff
    ja .no
    cmp byte [rel amdvi_guest_state],AMDVI_GUEST_LIVE
    je .no
    cmp byte [rel amdvi_guest_state],AMDVI_GUEST_POISON
    je .no
    test rcx,rcx
    jz .no
    cmp rcx,[rel amdvi_guest_generation]
    jbe .no
    call amdvi_hda_enforcing
    test eax,eax
    jz .no
    mov edi,r12d
    call amdvi_hda_ecam_uc ; RCQ-36: a guest-only boot never ran the native attach's mark
    mov edi,r12d
    call vtd_hda_ats_state
    cmp eax,1
    ja .no
    mov edi,r12d
    call amdvi_hda_scope
    test eax,eax
    jz .no
    cmp byte [rel amdvi_guest_state],AMDVI_GUEST_RETIRED
    jne .compat
    cmp r12d,[rel amdvi_guest_bdf]
    jne .compat                          ; a different requester still needs original compat
    ; Successful detach retained this exact BDF and generation, verified blocked
    ; DMA/interrupts, invalidated translations and scrubbed its retired tables.
    ; Do not restore broad compat, or accept an externally altered retired DTE.
    mov eax,r12d
    shl eax,5
    add rax,[rel amdvi_devtab]
    cmp qword [rax],AMDVI_DTE_BLOCKED
    jne .no
    cmp qword [rax+8],0
    jne .no
    cmp qword [rax+16],1
    jne .no
    cmp qword [rax+24],0
    jne .no
    jmp .ram
.compat:
    ; Boot only assigns compat DTEs to IVHD-covered IDs. Exact four-qword
    ; compatibility readback is therefore also positive coverage admission.
    mov edi,r12d
    mov rsi,[rel amdvi_compat_qw0]
    mov ecx,AMDVI_DOM_COMPAT
    call amdvi_hda_dte_ok
    test eax,eax
    jz .no
.ram:
    mov rsi,r13
    mov rdx,r14
    call amdvi_guest_ram_ok
    test eax,eax
    jz .no
    cmp qword [rel amdvi_guest_pages],0
    jne .commit
    mov eax,[rel amdvi_pool_next]
    add eax,6
    cmp eax,AMDVI_POOL_PAGES
    ja .no
    mov ebx,6
.allocate:
    call amdvi_take_page
    cmp ebx,6
    jne .next
    mov [rel amdvi_guest_pages],rax
.next:
    dec ebx
    jnz .allocate
.commit:
    mov [rel amdvi_guest_bdf],r12d
    mov [rel amdvi_guest_generation],r15
    mov [rel amdvi_guest_size],r13
    mov [rel amdvi_guest_host],r14
    mov byte [rel amdvi_guest_state],AMDVI_GUEST_POISON
    mov esi,AMDVI_DTE_BLOCKED
    xor ecx,ecx
    call amdvi_guest_dte_set
    call amdvi_guest_flush
    test eax,eax
    jz .poison
    mov edi,AMDVI_DOM_COMPAT
    call amdvi_flush_domain
    test eax,eax
    jz .poison
    xor ebx,ebx
.build:
    mov ecx,ebx
    call amdvi_guest_expected
    mov rdi,[rel amdvi_guest_pages]
    mov [rdi+rbx*8],rax
    clflush [rdi+rbx*8]
    inc ebx
    cmp ebx,3072
    jb .build
    mfence
    mov rsi,[rel amdvi_guest_pages]
    mov rax,AMDVI_DTE_XLATE
    or rsi,rax
    mov ecx,AMDVI_DOM_GUEST
    call amdvi_guest_dte_set
    call amdvi_guest_flush
    test eax,eax
    jz .poison
    mov byte [rel amdvi_guest_state],AMDVI_GUEST_LIVE
    call amdvi_guest_live
    test eax,eax
    jz .poison
    xor eax,eax
    jmp .out
.poison:
    call amdvi_guest_poison
    jmp .out
.no: mov eax,-1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Full bounded live census including every unused upper slot and leaf.
amdvi_guest_live:
    push rbx
    cmp byte [rel amdvi_guest_state],AMDVI_GUEST_LIVE
    jne .no
    call amdvi_hda_enforcing
    test eax,eax
    jz .no
    mov rax,[rel amdvi_guest_pages]
    test rax,4095
    jnz .no
    sub rax,[rel amdvi_pool]
    jc .no
    shr rax,12
    add rax,6
    cmp eax,[rel amdvi_pool_next]
    ja .no
    cmp rax,AMDVI_POOL_PAGES
    ja .no
    mov eax,[rel amdvi_guest_bdf]
    shl eax,5
    add rax,[rel amdvi_devtab]
    mov rdx,[rel amdvi_guest_pages]
    mov rcx,AMDVI_DTE_XLATE
    or rdx,rcx
    cmp [rax],rdx
    jne .no
    cmp qword [rax+8],AMDVI_DOM_GUEST
    jne .no
    cmp qword [rax+16],1
    jne .no
    cmp qword [rax+24],0
    jne .no
    xor ebx,ebx
.entry:
    mov ecx,ebx
    call amdvi_guest_expected
    mov rdi,[rel amdvi_guest_pages]
    cmp [rdi+rbx*8],rax
    jne .no
    inc ebx
    cmp ebx,3072
    jb .entry
    mov eax,1
    jmp .out
.no: xor eax,eax
.out: pop rbx
    ret

; RDI writable64B owned by caller. Eight qwords: state, generation, DeviceID,
; raw DTE0(root/mode/IR/IW/V/TV), DTE1(DID), DTE2(interrupts), 2MiB leaf count,
; sticky event count. EAX1 requires fresh live enforcement + exact tree/DTE.
; Refused/retired/poison receipts have zero leaves and return EAX0.
amdvi_guest_receipt:
    push r12
    push r13
    sub rsp,8
    mov r12,rdi
    call amdvi_guest_live
    mov r13d,eax
    movzx eax,byte [rel amdvi_guest_state]
    mov [r12],rax
    mov rax,[rel amdvi_guest_generation]
    mov [r12+8],rax
    mov eax,[rel amdvi_guest_bdf]
    mov [r12+16],rax
    xor edx,edx
    mov [r12+24],rdx
    mov [r12+32],rdx
    mov [r12+40],rdx
    mov [r12+48],rdx
    cmp qword [rel amdvi_guest_pages],0
    je .events
    shl eax,5
    add rax,[rel amdvi_devtab]
    mov rdx,[rax]
    mov [r12+24],rdx
    mov rdx,[rax+8]
    mov [r12+32],rdx
    mov rdx,[rax+16]
    mov [r12+40],rdx
    test r13d,r13d
    jz .events
    mov rax,[rel amdvi_guest_size]
    shr rax,21
    mov [r12+48],rax
.events:
    mov eax,[rel amdvi_events]
    mov [r12+56],rax
    mov eax,r13d
    add rsp,8
    pop r13
    pop r12
    ret

; Caller has stopped guest, cleared MEM/BME and held reset before this call.
amdvi_guest_detach:
    push rbx
    cmp byte [rel amdvi_guest_state],AMDVI_GUEST_LIVE
    jne .no
    cmp edi,[rel amdvi_guest_bdf]
    jne .no
    cmp rsi,[rel amdvi_guest_generation]
    jne .no
    call amdvi_hda_enforcing
    test eax,eax
    jz .poison
    mov byte [rel amdvi_guest_state],AMDVI_GUEST_POISON
    mov esi,AMDVI_DTE_BLOCKED
    xor ecx,ecx
    call amdvi_guest_dte_set
    call amdvi_guest_flush
    test eax,eax
    jz .poison
    call amdvi_hda_enforcing
    test eax,eax
    jz .poison
    mov eax,[rel amdvi_guest_bdf]
    shl eax,5
    add rax,[rel amdvi_devtab]
    cmp qword [rax],AMDVI_DTE_BLOCKED
    jne .poison
    cmp qword [rax+8],0
    jne .poison
    cmp qword [rax+16],1
    jne .poison
    cmp qword [rax+24],0
    jne .poison
    mov rdi,[rel amdvi_guest_pages]
    mov ecx,6*4096/8
    xor eax,eax
    cld
    rep stosq
    mov rdi,[rel amdvi_guest_pages]
    mov ecx,6*4096/64
.flush:
    clflush [rdi]
    add rdi,64
    loop .flush
    mfence
    mov byte [rel amdvi_guest_state],AMDVI_GUEST_RETIRED
    xor eax,eax
    pop rbx
    ret
.poison:
    call amdvi_guest_poison
    pop rbx
    ret
.no: mov eax,-1
    pop rbx
    ret

%include "core/abi/wdata.inc"
%macro WDATA_hv_amdvi_guest 0
alignb 8
amdvi_guest_pages: resq 1
amdvi_guest_generation: resq 1
amdvi_guest_size: resq 1
amdvi_guest_host: resq 1
amdvi_guest_bdf: resd 1
amdvi_guest_state: resb 1
%endmacro
WDATA_BSS_DEFER WDATA_hv_amdvi_guest
