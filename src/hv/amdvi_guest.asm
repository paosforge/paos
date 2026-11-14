;; MODULE hv/amdvi_guest
;; LAYER 5
;; EXPORTS amdvi_guest_group_detach, amdvi_guest_group_retired, amdvi_guest_group_attach, amdvi_guest_group_live, amdvi_guest_attach, amdvi_guest_detach, amdvi_guest_receipt, amdvi_guest_tree_ok
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
    mov byte [rel amdvi_guest_custody], 0
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
    jne .group
.check:
    mov rdx,rdi
    add rdx,rsi
    jc .yes
    cmp rdx,[rel amdvi_guest_host]
    jbe .group
    mov rdx,[rel amdvi_guest_host]
    add rdx,[rel amdvi_guest_size]
    cmp rdi,rdx
    jae .group
.yes: mov eax,1
    ret
.group: jmp amdvg_range_overlap

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
    cmp edx,3
    je .out                              ; never DMA-map the device hole
    jb .pd_index
    cmp edx,4
    jne .out
    dec edx                              ; fourth compact PD backs GPA4GiB
.pd_index:
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
    ; The only guest DTE writer. Custody is set only just after LIVE; poison,
    ; detach and .commit each reach here before any table, page or RAM change,
    ; so clearing it here invalidates it before every mutation (AV110948).
    mov byte [rel amdvi_guest_custody],0
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
    call amdvg_held
    test eax,eax
    jnz .no
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
    ; Final-flush custody (SEC110926 item 3, AV110948): this exact mapping was
    ; installed and its INV_DTE/INV_IRT/INV_PAGES completed (amdvi_cmd_sync) and
    ; re-read live. Never rewritten here after; any later mutation clears it.
    mov eax,[rel amdvi_guest_bdf]
    mov [rel amdvi_guest_custody_bdf],eax
    mov rax,[rel amdvi_guest_generation]
    mov [rel amdvi_guest_custody_gen],rax
    mov rax,[rel amdvi_guest_pages]
    mov [rel amdvi_guest_custody_root],rax
    mov rax,[rel amdvi_guest_host]
    mov [rel amdvi_guest_custody_host],rax
    mov rax,[rel amdvi_guest_size]
    mov [rel amdvi_guest_custody_size],rax
    mov byte [rel amdvi_guest_custody],1
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
    cmp byte [rel amdvi_guest_state],AMDVI_GUEST_LIVE
    jne .no
    sub rsp,8
    call amdvi_hda_enforcing
    add rsp,8
    test eax,eax
    jz .no
    jmp amdvi_guest_tree_ok
.no: xor eax,eax
    ret

; Pure half of amdvi_guest_live: bounded pool page, exact four-qword DTE and all
; 3072 table entries (unused slots included) -> EAX 1/0. No state, enforcement,
; event, MMIO or memory write; callers check state and enforcement themselves.
amdvi_guest_tree_ok:
    push rbx
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

%include "hv/iommu_guest_group.inc"

; Backend retirement does not release claims or guest RAM. Only C's verified
; final release sets amdvg_released; mutable common state is never authority.
amdvg_held:
 xor eax,eax
 cmp byte [rel amdvg_state],0
 je .out
 cmp byte [rel amdvg_state],AMDVI_GUEST_RETIRED
 jne .yes
 cmp byte [rel amdvg_released],1
 je .out
.yes: mov eax,1
.out: ret

amdvg_range_overlap:
 push rdx
 call amdvg_held
 test eax,eax
 jz .out
 mov rax,[rel amdvg_identity+PG_RAM]
 mov rdx,[rel amdvg_identity+PG_BYTES]
 call iommu_guest_group_overlap
.out:
 pop rdx
 ret

; Observation only: never call amdvi_hda_enforcing here, because it drains
; the event log. Reject pending/malformed rings and retained fault history.
amdvg_enforcing:
 cmp byte [rel amdvi_owned],1
 jne .no
 cmp byte [rel amdvi_enabled],1
 jne .no
 mov rax,[rel amdvi_mmio]
 test rax,rax
 jz .no
 mov edx,[rax+AMDVI_R_CTRL]
 and edx,AMDVI_CTRL_EN | AMDVI_CTRL_CMDBUF | AMDVI_CTRL_EVTLOG
 cmp edx,AMDVI_CTRL_EN | AMDVI_CTRL_CMDBUF | AMDVI_CTRL_EVTLOG
 jne .no
 mov rdx,[rel amdvi_devtab]
 test rdx,rdx
 jz .no
 test rdx,4095
 jnz .no
 or rdx,AMDVI_DEVTAB_SIZE
 cmp [rax+AMDVI_R_DEVTAB],rdx
 jne .no
 mov rdx,[rel amdvi_cmdbuf]
 test rdx,rdx
 jz .no
 test rdx,4095
 jnz .no
 mov rcx,AMDVI_RING_LEN
 or rdx,rcx
 cmp [rax+AMDVI_R_CMD],rdx
 jne .no
 mov rdx,[rel amdvi_evtlog]
 test rdx,rdx
 jz .no
 test rdx,4095
 jnz .no
 mov rcx,AMDVI_EVT_LEN
 or rdx,rcx
 cmp [rax+AMDVI_R_EVT],rdx
 jne .no
 test qword [rax+AMDVI_R_EXCL],1
 jnz .no
 mov edx,[rax+AMDVI_R_STATUS]
 and edx,AMDVI_STS_CMD_RUN | AMDVI_STS_EVT_RUN | AMDVI_STS_EVT_OVF
 cmp edx,AMDVI_STS_CMD_RUN | AMDVI_STS_EVT_RUN
 jne .no
 cmp dword [rel amdvi_events],0
 jne .no
 mov rdx,[rax+AMDVI_R_EVT_HEAD]
 cmp rdx,AMDVI_EVT_MASK
 ja .no
 test dl,15
 jnz .no
 cmp rdx,[rax+AMDVI_R_EVT_TAIL]
 jne .no
 mov rdx,[rax+AMDVI_R_CMD_HEAD]
 cmp rdx,AMDVI_RING_MASK
 ja .no
 test dl,15
 jnz .no
 cmp rdx,[rax+AMDVI_R_CMD_TAIL]
 jne .no
 mov eax,1
 ret
.no: xor eax,eax
 ret

amdvg_ram_ok:
 push r12
 mov r12,rdi
 mov rsi,[r12+PG_BYTES]
 mov rdx,[r12+PG_RAM]
 call amdvi_guest_ram_ok
 test eax,eax
 jz .out
 mov rdi,r12
 call iommu_guest_group_wdata_ok
 test eax,eax
 jz .out
 lea rax,[rel pcia_grp]
 mov edx,PCIA_GRP_BYTES
 mov rdi,r12
 call iommu_guest_group_disjoint
 test eax,eax
 jz .out
 mov rax,[rel amdvi_cmdbuf]
 mov edx,4096
 mov rdi,r12
 call iommu_guest_group_disjoint
 test eax,eax
 jz .out
 mov rax,[rel amdvi_evtlog]
 mov edx,AMDVI_EVT_PAGES*4096
 mov rdi,r12
 call iommu_guest_group_disjoint
 test eax,eax
 jz .out
 mov rax,[rel amdvi_cw]
 mov edx,8
 mov rdi,r12
 call iommu_guest_group_disjoint
 test eax,eax
 jz .out
 lea rax,[rel amdvi_alias]
 mov edx,AMDVI_ALIAS_MAX*8
 mov rdi,r12
 call iommu_guest_group_disjoint
 test eax,eax
 jz .out
 lea rax,[rel amdvi_ivmd]
 mov edx,AMDVI_IVMD_MAX*24
 mov rdi,r12
 call iommu_guest_group_disjoint
 test eax,eax
 jz .out
 lea rax,[rel amdvg_begin]
 lea rdx,[rel amdvg_end]
 sub rdx,rax
 mov rdi,r12
 call iommu_guest_group_disjoint
.out: pop r12
 ret

; Pure ABI shape; neither common state nor diagnostic flags grant custody.
amdvg_shape_ok:
 lea rax,[rel pcia_grp]
 cmp rdi,rax
 jne .no
 mov eax,[rel hv_linux_start_consumed]
 test eax,eax
 jz .no
 cmp [rdi+PG_GEN],rax
 jne .no
 jmp amdvg_shape_fields
.no: xor eax,eax
 ret

; Shape of our immutable old capture, never the overwritten common record.
; Only a strictly newer consumed START can observe it for reuse preparation.
amdvg_saved_ok:
 lea rax,[rel amdvg_identity]
 cmp rdi,rax
 jne .no
 lea rax,[rel pcia_grp]
 cmp rax,[rel amdvg_record]
 jne .no
 mov rax,[rdi+PG_GEN]
 test rax,rax
 jz .no
 mov edx,[rel hv_linux_start_consumed]
 cmp rax,rdx
 jae .no
 cmp byte [rel amdvg_state],AMDVI_GUEST_RETIRED
 jne .no
 cmp byte [rel amdvg_released],1
 jne .no
 cmp byte [rel amdvg_completed],0
 jne .no
 movzx ecx,byte [rdi+PG_COUNT]
 cmp ecx,2
 jb .no
 cmp ecx,PCIA_GRP_MAX
 ja .no
 mov eax,1
 shl eax,cl
 dec eax
 cmp al,[rel amdvg_retired_mask]
 jne .no
 jmp amdvg_shape_fields
.no: xor eax,eax
 ret

amdvg_shape_fields:
 push rbx
 cmp dword [rdi+PG_MAGIC],PCIA_GRP_MAGIC
 jne .no
 movzx ecx,byte [rdi+PG_COUNT]
 cmp ecx,2
 jb .no
 cmp ecx,PCIA_GRP_MAX
 ja .no
 movzx eax,byte [rdi+PG_SEL]
 cmp eax,ecx
 jae .no
 cmp byte [rdi+PG_BACKEND],PGB_AMDVI
 jne .no
 cmp word [rdi+PG_SEGMENT],0
 jne .no
 cmp dword [rdi+PG_ATTEMPT],0
 je .no
 xor ecx,ecx
.members:
 mov eax,ecx
 shl eax,4
 lea r8,[rdi+rax+PG_MEMBERS]
 movzx edx,byte [rdi+PG_COUNT]
 cmp ecx,edx
 jae .unused
 cmp dword [r8+PGM_BK],ecx
 jne .no
 cmp word [r8+PGM_RSVD],0
 jne .no
 cmp word [r8+PGM_CLASS],0x0200
 je .role
 cmp word [r8+PGM_CLASS],0x0280
 jne .no
.role:
 movzx eax,byte [rdi+PG_SEL]
 xor edx,edx
 cmp eax,ecx
 setne dl
 cmp [r8+PGM_ROLE],dl
 jne .no
 test ecx,ecx
 jz .method
 mov ax,[r8+PGM_BDF]
 cmp ax,[r8-PGM_BYTES+PGM_BDF]
 jbe .no
.method:
 cmp byte [r8+PGM_RMETHOD],PGRM_FLR
 je .flr
 cmp byte [r8+PGM_RMETHOD],PGRM_SBR
 jne .no
 cmp word [r8+PGM_RDOMAIN],0xffff
 je .no
 jmp .next
.flr:
 cmp word [r8+PGM_RDOMAIN],0xffff
 jne .no
 jmp .next
.unused:
 cmp qword [r8],0
 jne .no
 cmp qword [r8+8],0
 jne .no
.next:
 inc ecx
 cmp ecx,PCIA_GRP_MAX
 jb .members
 mov eax,1
 jmp .out
.no: xor eax,eax
.out: pop rbx
 ret

amdvg_identity_ok:
 push rbx
 call amdvg_shape_ok
 test eax,eax
 jz .out
 cmp rdi,[rel amdvg_record]
 jne .no
 lea rbx,[rel amdvg_identity]
 mov eax,[rdi]
 cmp [rbx],eax
 jne .no
 mov eax,[rdi+5]
 cmp [rbx+5],eax
 jne .no
 mov rax,[rdi+PG_GEN]
 cmp [rbx+PG_GEN],rax
 jne .no
 mov rax,[rdi+PG_RAM]
 cmp [rbx+PG_RAM],rax
 jne .no
 mov rax,[rdi+PG_BYTES]
 cmp [rbx+PG_BYTES],rax
 jne .no
 mov eax,[rdi+PG_ATTEMPT]
 cmp [rbx+PG_ATTEMPT],eax
 jne .no
 mov ax,[rdi+PG_SEGMENT]
 cmp [rbx+PG_SEGMENT],ax
 jne .no
 xor ecx,ecx
.member:
 mov eax,ecx
 shl eax,4
 lea r8,[rdi+rax+PG_MEMBERS]
 lea r9,[rbx+rax+PG_MEMBERS]
 mov rax,[r8]
 cmp [r9],rax
 jne .no
 mov eax,[r8+PGM_RSVD]
 cmp [r9+PGM_RSVD],eax
 jne .no
 mov eax,[r8+PGM_BK]
 cmp [r9+PGM_BK],eax
 jne .no
 inc ecx
 cmp ecx,PCIA_GRP_MAX
 jb .member
 mov eax,1
 jmp .out
.no: xor eax,eax
.out: pop rbx
 ret

; Public install entry: fresh original A/C custody is provided only by C3.
; The private core supplies actual contexts, completion and whole-group census.
; EAX0 publishes MAPPED; A alone advances to LIVE. Released original slots
; may be reused under a strictly newer START; poison and held state cannot.
amdvi_guest_group_attach:
 push r12
 mov r12,rdi
 call amdvg_shape_ok
 test eax,eax
 jz .no
 cmp byte [r12+PG_STATE],PGS_RESET_IN
 jne .no
 cmp byte [rel amdvg_state],0
 je .admit
 mov rdi,r12
 call amdvi_guest_group_reuse_ready
 test eax,eax
 jnz .no
.admit:
 mov rdi,r12
 call nica_grp_backend_admit
 cmp eax,1
 jne .no
 mov rdi,r12
 call amdvg_attach_core
 test eax,eax
 jnz .out
 ; Fresh original admission and B observation both follow native completion.
 mov rdi,r12
 call nica_grp_backend_admit
 cmp eax,1
 jne .poison
 mov rdi,r12
 call amdvg_census
 test eax,eax
 jz .poison
 cmp byte [r12+PG_STATE],PGS_RESET_IN
 jne .poison
 mov byte [r12+PG_STATE],PGS_MAPPED
 xor eax,eax
 jmp .out
.poison:
 mov byte [rel amdvg_state],AMDVI_GUEST_POISON
 mov byte [r12+PG_STATE],PGS_POISON
 cmp byte [r12+PG_FAIL_STEP],0
 jne .no
 mov byte [r12+PG_FAIL_ORD],0xff
 mov byte [r12+PG_FAIL_STEP],PGX_READBACK
.no: mov eax,-1
.out:
 pop r12
 ret

; Public detach consumes original C outbound/A custody before and after
; actual native retirement. C alone retires claims/common state and RAM.
amdvi_guest_group_detach:
 push r12
 mov r12,rdi
 call amdvg_identity_ok
 test eax,eax
 jz .no
 cmp byte [r12+PG_STATE],PGS_RELEASING
 jne .no
 cmp byte [rel amdvg_state],AMDVI_GUEST_LIVE
 jne .no
 mov rdi,r12
 call nica_grp_backend_detach_admit
 cmp eax,1
 jne .no
 mov rdi,r12
 call amdvg_retire_core
 test eax,eax
 jnz .poison
 mov rdi,r12
 call nica_grp_backend_detach_admit
 cmp eax,1
 jne .poison
 mov rdi,r12
 call amdvg_retired_ok
 test eax,eax
 jz .poison
 xor eax,eax
 jmp .out
.poison:
 mov byte [rel amdvg_state],AMDVI_GUEST_POISON
 mov byte [r12+PG_STATE],PGS_POISON
 cmp byte [r12+PG_FAIL_STEP],0
 jne .no
 mov byte [r12+PG_FAIL_ORD],0xff
 mov byte [r12+PG_FAIL_STEP],PGX_READBACK
.no: mov eax,-1
.out: pop r12
 ret

; Pure original B retirement observation, native return convention 0/-1.
; This supplies no A/C authority and changes no lifecycle state or resource.
amdvi_guest_group_retired:
 sub rsp,8
 call amdvg_retired_ok
 test eax,eax
 setz al
 movzx eax,al
 neg eax
 add rsp,8
 ret

amdvg_retired_ok:
 push r12
 mov r12,rdi
 mov esi,7
 call amdvg_census_mode
 test eax,eax
 jz .out
 mov rdi,r12
 call amdvg_identity_ok
 test eax,eax
 jz .out
 cmp byte [r12+PG_STATE],PGS_RELEASING
 jne .no
 cmp byte [rel amdvg_state],AMDVI_GUEST_RETIRED
 jne .no
 cmp byte [rel amdvg_released],0
 jne .no
 cmp byte [rel amdvg_completed],0
 jne .no
 movzx ecx,byte [r12+PG_COUNT]
 mov eax,1
 shl eax,cl
 dec eax
 cmp al,[rel amdvg_retired_mask]
 jne .no
 mov eax,1
 jmp .out
.no: xor eax,eax
.out: pop r12
 ret

; Pure old released native observation for a newer START. No A/C admission,
; rearm, mapping, compatibility restore, allocation or lifecycle write occurs.
; The new record can differ: this proves only the original installation free.
amdvi_guest_group_reuse_ready:
 push r12
 mov r12,rdi
 call amdvg_new_start_ok
 test eax,eax
 jz .no
 lea rdi,[rel amdvg_identity]
 mov esi,8
 call amdvg_census_mode
 test eax,eax
 jz .no
 lea rdi,[rel amdvg_identity]
 call amdvg_saved_ok
 test eax,eax
 jz .no
 mov rdi,r12
 call amdvg_new_start_ok
 test eax,eax
 jz .no
 xor eax,eax
 jmp .out
.no: mov eax,-1
.out: pop r12
 ret

amdvg_new_start_ok:
 push r12
 mov r12,rdi
 call amdvg_shape_ok
 test eax,eax
 jz .out
 cmp byte [r12+PG_STATE],PGS_RESERVED
 je .yes
 cmp byte [r12+PG_STATE],PGS_RESET_IN
 jne .no
.yes: mov eax,1
 jmp .out
.no: xor eax,eax
.out: pop r12
 ret

amdvi_guest_group_live:
 sub rsp,8
 call amdvg_census
 test eax,eax
 setz al
 movzx eax,al
 neg eax
 add rsp,8
 ret

amdvg_census:
 xor esi,esi
 jmp amdvg_census_mode

; Private observing modes; none grants A/C authority or completion provenance.
; Mode7 observes original RETIRED+full retirement mask with blocked+zero.
; Mode8 reads the saved released capture after a strictly newer START.
; 1/2 retirement: blocked DTEs, expected/zero tree, common RELEASING.
; 3/4/5/6 installation: blocked+zero / blocked+tree / mapped+tree /
; original compat+zero, common RESET_IN. Only mode5 permits partial completion.
amdvg_census_mode:
 push rbx
 push r12
 push r13
 push r14
 sub rsp,8
 mov r12,rdi
 mov r14d,esi
 cmp r14d,8
 je .saved_released
 call amdvg_identity_ok
 test eax,eax
 jz .no
 test r14d,r14d
 jnz .retiring
 cmp byte [rel amdvg_state],AMDVI_GUEST_LIVE
 jne .no
 movzx ecx,byte [r12+PG_COUNT]
 mov eax,1
 shl eax,cl
 dec eax
 cmp al,[rel amdvg_completed]
 jne .no
 jmp .singleton
.saved_released:
 call amdvg_saved_ok
 test eax,eax
 jz .no
 mov r14d,2
 jmp .empty_completed
.retiring:
 cmp r14d,7
 je .retired
 cmp r14d,6
 ja .no
 cmp byte [rel amdvg_state],AMDVI_GUEST_POISON
 jne .no
 cmp r14d,2
 ja .install_phase
.retire_phase:
 cmp byte [r12+PG_STATE],PGS_RELEASING
 jne .no
 jmp .empty_completed
.retired:
 cmp byte [rel amdvg_state],AMDVI_GUEST_RETIRED
 jne .no
 cmp byte [rel amdvg_released],0
 jne .no
 movzx ecx,byte [r12+PG_COUNT]
 mov eax,1
 shl eax,cl
 dec eax
 cmp al,[rel amdvg_retired_mask]
 jne .no
 mov r14d,2
 jmp .retire_phase
.install_phase:
 cmp byte [r12+PG_STATE],PGS_RESET_IN
 jne .no
 cmp r14d,5
 jne .empty_completed
 movzx ecx,byte [r12+PG_COUNT]
 mov eax,1
 shl eax,cl
 dec eax
 not eax
 test al,[rel amdvg_completed]
 jnz .no
 jmp .singleton
.empty_completed:
 cmp byte [rel amdvg_completed],0
 jne .no
.singleton:
 cmp byte [rel amdvi_guest_state],AMDVI_GUEST_LIVE
 je .no
 cmp byte [rel amdvi_guest_state],AMDVI_GUEST_POISON
 je .no
 mov rax,[rel amdvi_mmio]
 cmp rax,[rel amdvg_unit]
 jne .no
 mov rax,[rel amdvi_devtab]
 cmp rax,[rel amdvg_root]
 jne .no
 mov rax,[rel amdvi_pool]
 cmp rax,[rel amdvg_pool]
 jne .no
 mov rax,[rel amdvi_cmdbuf]
 cmp rax,[rel amdvg_cmd]
 jne .no
 mov rax,[rel amdvi_evtlog]
 cmp rax,[rel amdvg_evt]
 jne .no
 mov rax,[rel amdvi_cw]
 cmp rax,[rel amdvg_cw]
 jne .no
 call amdvg_enforcing
 test eax,eax
 jz .no
 mov rax,[rel amdvg_pages]
 test rax,4095
 jnz .no
 sub rax,[rel amdvi_pool]
 jc .no
 shr rax,12
 add rax,6
 cmp rax,AMDVI_POOL_PAGES
 ja .no
 mov edx,[rel amdvi_pool_next]
 cmp rdx,AMDVI_POOL_PAGES
 ja .no
 cmp rax,rdx
 ja .no
 cmp dword [rel amdvi_alias_n],AMDVI_ALIAS_MAX
 ja .no
 cmp dword [rel amdvi_ivmd_n],AMDVI_IVMD_MAX
 ja .no
 xor ebx,ebx
.member:
 mov eax,ebx
 shl eax,4
 lea r13,[r12+rax+PG_MEMBERS]
 mov rdi,r13
 call iommu_guest_group_member_quiet
 test eax,eax
 jz .no
 movzx edi,word [r13+PGM_BDF]
 call amdvi_hda_scope
 test eax,eax
 jz .no
 movzx eax,word [r13+PGM_BDF]
 shl eax,5
 add rax,[rel amdvi_devtab]
 lea rdx,[rel amdvg_contexts]
 cmp rax,[rdx+rbx*8]
 jne .no
 cmp r14d,6
 je .compat
 test r14d,r14d
 jz .mapped
 cmp r14d,5
 jne .blocked
.mapped:
 mov rdx,[rel amdvg_pages]
 mov rcx,AMDVI_DTE_XLATE
 or rdx,rcx
 cmp [rax],rdx
 jne .no
 cmp qword [rax+8],AMDVI_DOM_GUEST
 jne .no
 jmp .interrupts
.compat:
 mov rdx,[rel amdvi_compat_qw0]
 cmp [rax],rdx
 jne .no
 cmp qword [rax+8],AMDVI_DOM_COMPAT
 jne .no
 cmp qword [rax+16],0
 jne .no
 cmp qword [rax+24],0
 jne .no
 jmp .next_member
.blocked:
 cmp qword [rax],AMDVI_DTE_BLOCKED
 jne .no
 cmp qword [rax+8],0
 jne .no
.interrupts:
 cmp qword [rax+16],1
 jne .no
 cmp qword [rax+24],0
 jne .no
.next_member:
 inc ebx
 movzx eax,byte [r12+PG_COUNT]
 cmp ebx,eax
 jb .member
 mov rdi,r12
 call amdvg_ram_ok
 test eax,eax
 jz .no
 xor ebx,ebx
.entry:
 xor eax,eax
 cmp r14d,2
 je .tree_value
 cmp r14d,3
 je .tree_value
 cmp r14d,6
 je .tree_value
 mov ecx,ebx
 call amdvg_expected
.tree_value:
 mov rdi,[rel amdvg_pages]
 cmp [rdi+rbx*8],rax
 jne .no
 inc ebx
 cmp ebx,3072
 jb .entry
 mov eax,1
 jmp .out
.no: xor eax,eax
.out:
 add rsp,8
 pop r14
 pop r13
 pop r12
 pop rbx
 ret

; One native requester's DTE, interrupt-cache and DID4 invalidations under the
; canonical command lock. A queued descriptor is not completion: cmd_sync's
; own token must be observed. No singleton identity or completion is borrowed.
amdvg_flush_member:
 push rbx
 mov ebx,edi
 lea rdi,[rel amdvi_cmd_lock]
 call spin_acquire
 mov edi,ebx
 call amdvi_enc_inv_dte
 call amdvi_cmd_put
 test eax,eax
 jz amdvg_flush_finish.out
 mov edi,ebx
 mov rax,5<<60
 or rdi,rax
 xor esi,esi
 call amdvi_cmd_put
 test eax,eax
 jz amdvg_flush_finish.out
 mov edi,AMDVI_DOM_GUEST
 call amdvi_enc_inv_pages
 call amdvi_cmd_put
 test eax,eax
 jz amdvg_flush_finish.out
 call amdvi_cmd_sync
 test eax,eax
 jz amdvg_flush_finish.out
 jmp amdvg_flush_finish

amdvg_flush_compat:
 push rbx
 lea rdi,[rel amdvi_cmd_lock]
 call spin_acquire
 mov edi,AMDVI_DOM_COMPAT
 call amdvi_enc_inv_pages
 call amdvi_cmd_put
 test eax,eax
 jz amdvg_flush_finish.out
 call amdvi_cmd_sync
 test eax,eax
 jz amdvg_flush_finish.out
amdvg_flush_finish:
 ; COMPLETION_WAIT's store can become visible before the head register has
 ; advanced past that command. Bound this transition while holding the same
 ; lock; the observing census requires an actually empty, well-formed ring.
 mov rdx,[rel amdvg_unit]
 cmp rdx,[rel amdvi_mmio]
 jne .fail
 mov ecx,AMDVI_WAIT_SPINS
.drain:
 mov rax,[rdx+AMDVI_R_CMD_HEAD]
 cmp rax,AMDVI_RING_MASK
 ja .fail
 test al,15
 jnz .fail
 cmp rax,[rdx+AMDVI_R_CMD_TAIL]
 je .done
 test dword [rdx+AMDVI_R_STATUS],AMDVI_STS_CMD_RUN
 jz .fail
 pause
 dec ecx
 jnz .drain
.fail:
 xor eax,eax
 jmp .out
.done:
 mov eax,1
.out:
 mov ebx,eax
 lea rdi,[rel amdvi_cmd_lock]
 call spin_release
 mov eax,ebx
 pop rbx
 ret

; B5 private first-install operation. The public wrapper consumes original C3 admission.
; Original A/C exclusive claims, CPU-off and positive inbound reset must be
; consumed by the public wrapper BEFORE this call. Common RESET_IN is only
; an internal sequencing check, not that authority.
; RDI == &pcia_grp -> EAX0/-1. Failed preflight is inert. After capture every
; uncertainty is whole-group POISON with allocations/RAM held; no unwind.
amdvg_attach_core:
 push rbx
 push r12
 push r13
 push r14
 push r15
 sub rsp,16
 mov qword [rsp],0             ; per-call first-install/reuse branch
 mov r12,rdi
 call amdvg_shape_ok
 test eax,eax
 jz .no
 cmp byte [r12+PG_STATE],PGS_RESET_IN
 jne .no
 cmp byte [rel amdvg_state],0
 jne .reuse_preflight
 cmp byte [rel amdvi_guest_state],AMDVI_GUEST_LIVE
 je .no
 cmp byte [rel amdvi_guest_state],AMDVI_GUEST_POISON
 je .no
 call amdvg_enforcing
 test eax,eax
 jz .no
 mov rax,[rel amdvi_pool]
 test rax,rax
 jz .no
 test rax,4095
 jnz .no
 mov eax,[rel amdvi_pool_next]
 cmp eax,AMDVI_POOL_PAGES-6
 ja .no
 cmp dword [rel amdvi_alias_n],AMDVI_ALIAS_MAX
 ja .no
 cmp dword [rel amdvi_ivmd_n],AMDVI_IVMD_MAX
 ja .no
 mov rdi,r12
 call amdvg_ram_ok
 test eax,eax
 jz .no
 xor ebx,ebx
.preflight:
 mov eax,ebx
 shl eax,4
 lea r13,[r12+rax+PG_MEMBERS]
 mov rdi,r13
 call iommu_guest_group_member_quiet
 test eax,eax
 jz .no
 movzx edi,word [r13+PGM_BDF]
 call amdvi_hda_scope
 test eax,eax
 jz .no
 movzx edi,word [r13+PGM_BDF]
 mov rsi,[rel amdvi_compat_qw0]
 mov ecx,AMDVI_DOM_COMPAT
 call amdvi_hda_dte_ok
 test eax,eax
 jz .no
 inc ebx
 movzx eax,byte [r12+PG_COUNT]
 cmp ebx,eax
 jb .preflight
 ; Freeze the entire original identity and all resources before any DTE store.
 mov [rel amdvg_record],r12
 mov rsi,r12
 lea rdi,[rel amdvg_identity]
 mov ecx,PCIA_GRP_BYTES/8
 cld
 rep movsq
 mov rax,[rel amdvi_mmio]
 mov [rel amdvg_unit],rax
 mov rax,[rel amdvi_devtab]
 mov [rel amdvg_root],rax
 mov rax,[rel amdvi_pool]
 mov [rel amdvg_pool],rax
 mov rax,[rel amdvi_cmdbuf]
 mov [rel amdvg_cmd],rax
 mov rax,[rel amdvi_evtlog]
 mov [rel amdvg_evt],rax
 mov rax,[rel amdvi_cw]
 mov [rel amdvg_cw],rax
 xor ebx,ebx
.capture_members:
 mov eax,ebx
 shl eax,4
 movzx eax,word [r12+rax+PG_MEMBERS+PGM_BDF]
 shl eax,5
 add rax,[rel amdvg_root]
 lea rdx,[rel amdvg_contexts]
 mov [rdx+rbx*8],rax
 inc ebx
 movzx eax,byte [r12+PG_COUNT]
 cmp ebx,eax
 jb .capture_members
 mov byte [rel amdvg_state],AMDVI_GUEST_POISON
 mov byte [rel amdvg_released],0
 mov byte [rel amdvg_completed],0
 mov byte [rel amdvg_retired_mask],0
 mov byte [rel amdvg_blocked_mask],0
 mov ebx,0xff
 mov r15d,PGX_MAP
 mov eax,[rel amdvi_pool_next]
 shl rax,12
 add rax,[rel amdvg_pool]
 mov r14,rax
 mov [rel amdvg_pages],rax
 mov r13d,6
.allocate:
 call amdvi_take_page
 cmp rax,r14
 jne .poison
 add r14,4096
 dec r13d
 jnz .allocate
 mov r14,[rel amdvg_pages]
 mov rdi,r12
 mov esi,6
 call amdvg_census_mode
 test eax,eax
 jz .poison
 ; Block ALL old requesters before the first invalidate. Keep the tree zero
 ; until each member's real completion/readback and the old DID1 completion.
 xor ebx,ebx
.block_all:
 lea rax,[rel amdvg_contexts]
 mov rax,[rax+rbx*8]
 mov qword [rax],AMDVI_DTE_BLOCKED
 mov qword [rax+8],0
 mov qword [rax+16],1
 mov qword [rax+24],0
 clflush [rax]
 inc ebx
 movzx eax,byte [r12+PG_COUNT]
 cmp ebx,eax
 jb .block_all
 mfence
 xor ebx,ebx
.old_member:
 mov r13d,3
 call .check
 test eax,eax
 jz .poison
 mov eax,ebx
 shl eax,4
 movzx edi,word [r12+rax+PG_MEMBERS+PGM_BDF]
 mov r15d,PGX_INVALIDATE
 call amdvg_flush_member
 test eax,eax
 jz .poison
 call .check
 test eax,eax
 jz .poison
 mov ecx,ebx
 mov eax,1
 shl eax,cl
 or [rel amdvg_blocked_mask],al
 inc ebx
 movzx ecx,byte [r12+PG_COUNT]
 cmp ebx,ecx
 jb .old_member
 mov eax,1
 shl eax,cl
 dec eax
 cmp al,[rel amdvg_blocked_mask]
 jne .poison
 cmp qword [rsp],1
 je .reuse_build
 mov ebx,0xff
 mov r15d,PGX_INVALIDATE
 call amdvg_flush_compat
 test eax,eax
 jz .poison
 call .check
 test eax,eax
 jz .poison
.reuse_build:
 xor ebx,ebx
.build:
 mov ecx,ebx
 call amdvg_expected
 mov [r14+rbx*8],rax
 clflush [r14+rbx*8]
 inc ebx
 cmp ebx,3072
 jb .build
 mfence
 mov ebx,0xff
 mov r13d,4
 call .check
 test eax,eax
 jz .poison
 xor ebx,ebx
.install_all:
 lea rax,[rel amdvg_contexts]
 mov rax,[rax+rbx*8]
 mov rdx,AMDVI_DTE_XLATE
 or rdx,r14
 mov [rax],rdx
 mov qword [rax+8],AMDVI_DOM_GUEST
 mov qword [rax+16],1
 mov qword [rax+24],0
 clflush [rax]
 inc ebx
 movzx eax,byte [r12+PG_COUNT]
 cmp ebx,eax
 jb .install_all
 mfence
 xor ebx,ebx
.new_member:
 mov r13d,5
 call .check
 test eax,eax
 jz .poison
 mov eax,ebx
 shl eax,4
 movzx edi,word [r12+rax+PG_MEMBERS+PGM_BDF]
 mov r15d,PGX_INVALIDATE
 call amdvg_flush_member
 test eax,eax
 jz .poison
 call .check
 test eax,eax
 jz .poison
 mov ecx,ebx
 mov eax,1
 shl eax,cl
 or [rel amdvg_completed],al
 mov eax,ebx
 shl eax,4
 or byte [r12+rax+PG_MEMBERS+PGM_FLAGS],PGF_MAPPED
 inc ebx
 movzx ecx,byte [r12+PG_COUNT]
 cmp ebx,ecx
 jb .new_member
 mov eax,1
 shl eax,cl
 dec eax
 cmp al,[rel amdvg_completed]
 jne .poison
 mov byte [rel amdvg_state],AMDVI_GUEST_LIVE
 mov ebx,0xff
 mov r15d,PGX_READBACK
 mov rdi,r12
 call amdvg_census
 test eax,eax
 jz .poison
 xor eax,eax
 jmp .out
.check:
 sub rsp,8
 mov r15d,PGX_READBACK
 mov rdi,r12
 mov esi,r13d
 call amdvg_census_mode
 test eax,eax
 jz .checked
 cmp r14,[rel amdvg_pages]
 jne .bad_check
 add rsp,8
 ret
.bad_check:
 xor eax,eax
.checked:
 add rsp,8
 ret
.poison:
 mov byte [rel amdvg_state],AMDVI_GUEST_POISON
 mov byte [r12+PG_STATE],PGS_POISON
 cmp byte [r12+PG_FAIL_STEP],0
 jne .no
 mov [r12+PG_FAIL_ORD],bl
 mov [r12+PG_FAIL_STEP],r15b
.no: mov eax,-1
.out:
 add rsp,16
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbx
 ret

; Reuse keeps original native DTE slots; fresh A/C validates this START.
.reuse_preflight:
 mov rdi,r12
 call amdvi_guest_group_reuse_ready
 test eax,eax
 jnz .no
 movzx eax,byte [r12+PG_COUNT]
 cmp al,[rel amdvg_identity+PG_COUNT]
 jne .no
 xor ebx,ebx
.reuse_member_shape:
 mov eax,ebx
 shl eax,4
 lea rdx,[rel amdvg_identity+PG_MEMBERS]
 mov cx,[r12+rax+PG_MEMBERS+PGM_BDF]
 cmp cx,[rdx+rax+PGM_BDF]
 jne .no
 inc ebx
 movzx eax,byte [r12+PG_COUNT]
 cmp ebx,eax
 jb .reuse_member_shape
 mov rdi,r12
 call amdvg_ram_ok
 test eax,eax
 jz .no
 ; Repeat the old native proof after new-range/slot preflight, then capture
 ; this START. From this point uncertainty poisons and holds the NEW span.
 mov rdi,r12
 call amdvi_guest_group_reuse_ready
 test eax,eax
 jnz .no
 mov rsi,r12
 lea rdi,[rel amdvg_identity]
 mov ecx,PCIA_GRP_BYTES/8
 cld
 rep movsq
 mov byte [rel amdvg_state],AMDVI_GUEST_POISON
 mov byte [rel amdvg_released],0
 mov byte [rel amdvg_completed],0
 mov byte [rel amdvg_retired_mask],0
 mov byte [rel amdvg_blocked_mask],0
 mov qword [rsp],1
 mov r14,[rel amdvg_pages]
 xor ebx,ebx
 ; No compatibility mapping or allocation is restored. Fresh blocked-phase
 ; waits precede the new tree, then fresh mapped-phase waits prove install.
 jmp .old_member

; B3 private retirement operation, not the public detach/admission interface.
; The public B wrapper consumes C's original exclusive claims, CPU-off
; and outbound-reset custody before and after actual retirement.
; RDI == &pcia_grp, common RELEASING, backend LIVE -> EAX0/-1.
; Every requester is blocked BEFORE any invalidation. Every real completion
; AND fresh whole-group readback precedes the corresponding private bit. Only
; after all bits are positive may shared pages be scrubbed. C alone releases
; claims and sets released=1/common RETIRED; this operation never does either.
amdvg_retire_core:
 push rbx
 push r12
 push r13
 push r14
 push r15
 lea rax,[rel pcia_grp]
 cmp rdi,rax
 jne .no
 cmp rdi,[rel amdvg_record]
 jne .no
 cmp byte [rdi+PG_STATE],PGS_RELEASING
 jne .no
 cmp byte [rel amdvg_state],AMDVI_GUEST_LIVE
 jne .no
 mov r12,rdi
 mov ebx,0xff
 mov r15d,PGX_READBACK
 call amdvg_census
 test eax,eax
 jz .poison
 mov r14,[rel amdvg_pages]
 mov byte [rel amdvg_state],AMDVI_GUEST_POISON
 mov byte [rel amdvg_released],0
 mov byte [rel amdvg_completed],0
 mov byte [rel amdvg_retired_mask],0
 xor ebx,ebx
.block_all:
 lea rax,[rel amdvg_contexts]
 mov rax,[rax+rbx*8]
 mov qword [rax],AMDVI_DTE_BLOCKED
 mov qword [rax+8],0
 mov qword [rax+16],1
 mov qword [rax+24],0
 clflush [rax]
 inc ebx
 movzx eax,byte [r12+PG_COUNT]
 cmp ebx,eax
 jb .block_all
 mfence
 xor ebx,ebx
.member:
 mov r15d,PGX_READBACK
 mov rdi,r12
 mov esi,1
 call amdvg_census_mode
 test eax,eax
 jz .poison
 cmp r14,[rel amdvg_pages]
 jne .poison
 mov eax,ebx
 shl eax,4
 movzx edi,word [r12+rax+PG_MEMBERS+PGM_BDF]
 mov r15d,PGX_INVALIDATE
 call amdvg_flush_member
 test eax,eax
 jz .poison
 mov r15d,PGX_READBACK
 mov rdi,r12
 mov esi,1
 call amdvg_census_mode
 test eax,eax
 jz .poison
 cmp r14,[rel amdvg_pages]
 jne .poison
 mov ecx,ebx
 mov eax,1
 shl eax,cl
 or [rel amdvg_retired_mask],al
 mov eax,ebx
 shl eax,4
 or byte [r12+rax+PG_MEMBERS+PGM_FLAGS],PGF_RETIRED
 inc ebx
 movzx ecx,byte [r12+PG_COUNT]
 cmp ebx,ecx
 jb .member
 mov eax,1
 shl eax,cl
 dec eax
 cmp al,[rel amdvg_retired_mask]
 jne .poison
 ; All requester caches have actually completed and all DTEs read blocked.
 ; The common six pages can now be erased, never before this boundary.
 mov rdi,r14
 mov ecx,6*4096/8
 xor eax,eax
 cld
 rep stosq
 mov rdi,r14
 mov ecx,6*4096/64
.flush_tree:
 clflush [rdi]
 add rdi,64
 loop .flush_tree
 mfence
 mov ebx,0xff
 mov r15d,PGX_RETIRE
 mov rdi,r12
 mov esi,2
 call amdvg_census_mode
 test eax,eax
 jz .poison
 cmp r14,[rel amdvg_pages]
 jne .poison
 mov byte [rel amdvg_state],AMDVI_GUEST_RETIRED
 xor eax,eax
 jmp .out
.poison:
 mov byte [rel amdvg_state],AMDVI_GUEST_POISON
 mov byte [r12+PG_STATE],PGS_POISON
 cmp byte [r12+PG_FAIL_STEP],0
 jne .no
 mov [r12+PG_FAIL_ORD],bl
 mov [r12+PG_FAIL_STEP],r15b
.no: mov eax,-1
.out:
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbx
 ret

amdvg_expected:
    xor eax,eax
    test ecx,ecx
    jnz .pdpt
    mov rax,[rel amdvg_pages]
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
    je .out                              ; never DMA-map the device hole
    jb .pd_index
    cmp edx,4
    jne .out
    dec edx                              ; fourth compact PD backs GPA4GiB
.pd_index:
    mov r8,[rel amdvg_identity+PG_BYTES]
    dec r8
    shr r8,30
    cmp rdx,r8
    ja .out
    shl rdx,12
    mov rax,[rel amdvg_pages]
    lea rax,[rax+rdx+8192]
    mov rdx,AMDVI_PDE_RW | (2<<9)
    or rax,rdx
    ret
.leaf:
    mov edx,ecx
    sub edx,1024
    shl rdx,21
    cmp rdx,[rel amdvg_identity+PG_BYTES]
    jae .out
    mov rax,[rel amdvg_identity+PG_RAM]
    add rax,rdx
    mov rdx,AMDVI_PTE_LEAF
    or rax,rdx
.out: ret

%include "core/abi/wdata.inc"
%macro WDATA_hv_amdvi_guest 0
alignb 8
amdvi_guest_pages: resq 1
amdvi_guest_generation: resq 1
amdvi_guest_size: resq 1
amdvi_guest_host: resq 1
amdvi_guest_bdf: resd 1
amdvi_guest_state: resb 1
alignb 8
amdvg_begin:
amdvg_record: resq 1
amdvg_unit: resq 1
amdvg_root: resq 1
amdvg_pages: resq 1
amdvg_pool: resq 1
amdvg_cmd: resq 1
amdvg_evt: resq 1
amdvg_cw: resq 1

amdvg_contexts: resq PCIA_GRP_MAX
amdvg_identity: resb PCIA_GRP_BYTES
amdvg_state: resb 1
amdvg_completed: resb 1
amdvg_released: resb 1              ; only C's verified final claim release sets 1
amdvg_retired_mask: resb 1          ; actual per-requester completion AND blocked readback
amdvg_blocked_mask: resb 1          ; old mapping completion AND zero-tree readback
amdvg_end:

alignb 8
amdvi_guest_custody_gen: resq 1
amdvi_guest_custody_root: resq 1
amdvi_guest_custody_host: resq 1
amdvi_guest_custody_size: resq 1
amdvi_guest_custody_bdf: resd 1
amdvi_guest_custody: resb 1
%endmacro
WDATA_BSS_DEFER WDATA_hv_amdvi_guest
