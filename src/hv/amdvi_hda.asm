;; MODULE hv/amdvi_hda
;; LAYER 5
;; EXPORTS amdvi_scope_snapshot, amdvi_hda_attach, amdvi_hda_receipt, amdvi_hda_live_receipt, amdvi_enforcing_regs
;; IMPORTS hv/amdvi, hv/vtd, boot/paging, bus/acpi, bus/pci_bdf, core/dma
;; CAPS CAP_MMIO
;; OWNER rc-codex-av
; Included by amdvi.asm. Host HDA only: tag 1 / DID 3, never guest assignment.
; Existing compat DID 1 still reaches ordinary DMA buffers, as on VT-d.
; DID 3 restricts what HDA can address; DID 2 and DID 3 are disjoint.
; All new IOPT pages come from the existing bounded, compat-carved arena.
; V=0 is AMD passthrough: EVERY failed transition leaves V=TV=1, IR=IW=0.
; One serialized controller owner; no IRQ or other mapper changes tag 1 during
; attach/receipt. Each invalidation retains the existing lock through CW.
AMDVI_DOM_HDA equ 3
AMDVI_HDA_OK equ 1
AMDVI_HDA_POISON equ 3
; amdvi_hda_attach refusal reasons in EAX (and the refused receipt line): the VTD_HDA_R_* number wherever the
; meaning is the same, so a core/dma caller decodes either owner alike; 3 stays core/dma DMA_DOM_R_UNBOUND's
; value. AMD-only causes take the values above VTD_HDA_R_LAST.
AMDVI_HDA_R_POISONED       equ 1
AMDVI_HDA_R_ATTACHED       equ 2
AMDVI_HDA_R_NO_ENFORCEMENT equ 3
AMDVI_HDA_R_NOT_FOUND      equ 4
AMDVI_HDA_R_CLASS          equ 5
AMDVI_HDA_R_BAR            equ 7
AMDVI_HDA_R_NOT_QUIESCED   equ 9
AMDVI_HDA_R_ATS_ENABLED    equ 10
AMDVI_HDA_R_INVAL_TIMEOUT  equ 13
AMDVI_HDA_R_READBACK       equ 14
AMDVI_HDA_R_DISJOINT       equ 18
AMDVI_HDA_R_NOT_ATTACHED   equ 21
AMDVI_HDA_R_ATS_UNREAD     equ 23
AMDVI_HDA_R_SCOPE          equ 24
AMDVI_HDA_R_COMPAT_DTE     equ 25
AMDVI_HDA_R_SERIAL         equ 26
AMDVI_HDA_R_RECHECK        equ 27
AMDVI_HDA_R_MAP            equ 28          ; a later map/unmap failure poisoned the attached domain
AMDVI_HDA_R_LAST           equ 29          ; "unknown"
AMDVI_HDA_NAME_STRIDE      equ 16

amdvi_hda_reset:
    mov qword [rel amdvi_hda_root], 0
    mov qword [rel amdvi_hda_serial], 0
    mov qword [rel amdvi_hda_mmio], 0
    mov dword [rel amdvi_hda_mapped], 0
    mov dword [rel amdvi_hda_bdf], 0
    mov byte [rel amdvi_hda_state], 0
    mov byte [rel amdvi_hda_reason], 0
    ret

; Live enforcement, not cached boot success. Event history is sticky here:
; an already consumed fault cannot become a clean receipt on a later poll.
; The register half is amdvi_enforcing_regs (pure); this caller then consumes
; the event log, so terminal predicates use the regs half plus their own
; non-consuming peek instead (SEC110926 item 4).
amdvi_hda_enforcing:
    sub rsp, 8
    call amdvi_enforcing_regs
    add rsp, 8
    test eax, eax
    jz .no
    sub rsp, 8
    call amdvi_event_check
    add rsp, 8
    test eax, eax
    jnz .no
    cmp dword [rel amdvi_events], 0
    jne .no
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

; Pure: the owning unit's enforcement registers only -> EAX 1/0. Reads module
; fields and MMIO; writes nothing (no event consume, observer or sticky state).
amdvi_enforcing_regs:
    cmp byte [rel amdvi_owned], 1
    jne .no
    cmp byte [rel amdvi_enabled], 1
    jne .no
    mov rax, [rel amdvi_mmio]
    test rax, rax
    jz .no
    mov edx, [rax + AMDVI_R_CTRL]
    and edx, AMDVI_CTRL_EN | AMDVI_CTRL_CMDBUF | AMDVI_CTRL_EVTLOG
    cmp edx, AMDVI_CTRL_EN | AMDVI_CTRL_CMDBUF | AMDVI_CTRL_EVTLOG
    jne .no
    mov rdx, [rel amdvi_devtab]
    or rdx, AMDVI_DEVTAB_SIZE
    cmp [rax + AMDVI_R_DEVTAB], rdx
    jne .no
    mov rdx, [rel amdvi_cmdbuf]
    mov rcx, AMDVI_RING_LEN
    or rdx, rcx
    cmp [rax + AMDVI_R_CMD], rdx
    jne .no
    mov rdx, [rel amdvi_evtlog]
    mov rcx, AMDVI_EVT_LEN
    or rdx, rcx
    cmp [rax + AMDVI_R_EVT], rdx
    jne .no
    test qword [rax + AMDVI_R_EXCL], 1
    jnz .no
    mov edx, [rax + AMDVI_R_STATUS]
    and edx, AMDVI_STS_CMD_RUN | AMDVI_STS_EVT_RUN
    cmp edx, AMDVI_STS_CMD_RUN | AMDVI_STS_EVT_RUN
    jne .no
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

; Range admission before allocating a table. Only page-aligned, nonzero,
; <=1MiB, 48-bit ranges. No IOMMU structures/MMIO or existing native leaf.
; The native map hook symmetrically rejects existing HDA leaves.
amdvi_hda_range_ok:
    push rbx
    push r12
    push r13
    mov r12, rdi
    mov r13, rdi
    call amdvi_guest_range_overlap
    test eax,eax
    jnz .no
    test rdi, rdi
    jz .no
    test rdi, 4095
    jnz .no
    test rsi, rsi
    jz .no
    test rsi, 4095
    jnz .no
    cmp rsi, 0x100000
    ja .no
    add r13, rsi
    jc .no
    mov rax, r13
    dec rax
    shr rax, 48
    jnz .no
    xor ebx, ebx
.record:
    cmp ebx, DMA_IOMMU_SLOTS
    jae .pages
    mov edi, ebx
    call dma_iommu_record
    inc ebx
    test rdx, rdx
    jz .record
    cmp ecx, 1
    je .record
    cmp rax, r13
    jae .record
    add rax, rdx
    jc .no
    cmp rax, r12
    ja .no                            ; even an unmapped native record owns its span
    jmp .record
.pages:
    mov rbx, r12
.page:
    cmp rbx, r13
    jae .yes
    mov rdi, rbx
    call amdvi_native_leaf_ptr
    test rax, rax
    jnz .no
    mov rax, [rel amdvi_devtab]
    lea rdx, [rax + AMDVI_DEVTAB_BYTES]
    cmp rbx, rax
    jb .arena
    cmp rbx, rdx
    jb .no
.arena:
    mov rax, [rel amdvi_pool]
    lea rdx, [rax + AMDVI_POOL_BYTES]
    cmp rbx, rax
    jb .mmio
    cmp rbx, rdx
    jb .no
.mmio:
    mov rax, [rel amdvi_mmio]
    lea rdx, [rax + AMDVI_MMIO_BYTES]
    cmp rbx, rax
    jb .next
    cmp rbx, rdx
    jb .no
.next:
    add rbx, 4096
    jmp .page
.yes:
    mov eax, 1
    jmp .out
.no:
    xor eax, eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

amdvi_hda_map_range:
    push r12
    push r13
    sub rsp, 8
    mov r12, rdi
    mov r13, rsi
    cmp byte [rel amdvi_hda_state], AMDVI_HDA_POISON
    je .no
    cmp qword [rel amdvi_hda_serial], -1
    je .no
    call amdvi_hda_enforcing
    test eax, eax
    jz .no
    mov rdi, r12
    mov rsi, r13
    call amdvi_hda_range_ok
    test eax, eax
    jz .no
    cmp qword [rel amdvi_hda_root], 0
    jne .map
    call amdvi_take_page
    test rax, rax
    jz .no
    mov [rel amdvi_hda_root], rax
.map:
    mov rdi, r12
    mov rsi, r13
    call amdvi_hda_map_pages
    test rax, rax
    jz .poison
    inc qword [rel amdvi_hda_serial]
    jmp .out
.poison:
    mov byte [rel amdvi_hda_reason], AMDVI_HDA_R_MAP
    call amdvi_hda_poison
.no:
    xor eax, eax
.out:
    add rsp, 8
    pop r13
    pop r12
    ret

amdvi_hda_unmap_range:
    push r12
    push r13
    sub rsp, 8
    mov r12, rdi
    mov r13, rsi
    cmp byte [rel amdvi_hda_state], AMDVI_HDA_POISON
    je .no
    cmp qword [rel amdvi_hda_serial], -1
    je .no
    call amdvi_hda_enforcing
    test eax, eax
    jz .no
    mov rdi, r12
    mov rsi, r13
    call amdvi_hda_unmap_pages
    test eax, eax
    jz .poison
    inc qword [rel amdvi_hda_serial]
    jmp .out
.poison:
    mov byte [rel amdvi_hda_reason], AMDVI_HDA_R_MAP
    call amdvi_hda_poison
.no:
    xor eax, eax
.out:
    add rsp, 8
    pop r13
    pop r12
    ret

; Never make a poisoned requester pass through or restore its compat entry.
; Invalidations are best effort on this failure path; no success is returned,
; controller claims and storage remain pinned by the HDA owner.
amdvi_hda_poison:
    sub rsp, 8
    cmp byte [rel amdvi_hda_state], AMDVI_HDA_OK
    je .block
    cmp byte [rel amdvi_hda_state], AMDVI_HDA_POISON
    jne .mark
.block:
    mov edi, [rel amdvi_hda_bdf]
    mov esi, AMDVI_DTE_BLOCKED
    xor ecx, ecx
    call amdvi_dte_set
    mfence
    mov edi, [rel amdvi_hda_bdf]
    call amdvi_flush_dte
    mov edi, AMDVI_DOM_HDA
    call amdvi_flush_domain
.mark:
    mov byte [rel amdvi_hda_state], AMDVI_HDA_POISON
    add rsp, 8
    ret

; Full bounded census. Every table is an allocated arena page. Every upper
; entry has the exact next level/RW/present form, every leaf is a 4KiB identity
; leaf with the exact permissions. Reject huge leaves, malformed links, alias
; leaves, and repeated/aliased empty-table expansion through the page budget.
; R11=root -> EAX1/0, EDX=leaf count. This also bounds receipt work.
amdvi_hda_tree_check:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov r12d, AMDVI_POOL_PAGES
    xor r13d, r13d
    xor r14d, r14d
    mov ebx, 39
    mov r15, r11
    test r15, r15
    jz .empty
    call amdvi_hda_tree_level
    jmp .out
.empty:
    mov eax, 1
.out:
    mov edx, r13d
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

amdvi_hda_tree_level:
    test r12d, r12d
    jz .no
    dec r12d
    test r15, 4095
    jnz .no
    mov rax, r15
    sub rax, [rel amdvi_pool]
    jc .no
    shr rax, 12
    cmp eax, [rel amdvi_pool_next]
    jae .no
    cmp rax, AMDVI_POOL_PAGES
    jae .no
    xor ebp, ebp
.entry:
    cmp ebp, 512
    jae .yes
    mov rax, [r15 + rbp*8]
    test rax, rax
    jz .next
    mov ecx, ebx
    mov rdx, rbp
    shl rdx, cl
    or rdx, r14
    cmp ebx, 12
    je .leaf
    mov r8, AMDVI_ADDR_MASK
    mov r9, rax
    and r9, r8
    ; shifts are 39/30/21: explicitly 3/2/1, never a huge leaf.
    mov ecx, 3 << 9
    cmp ebx, 39
    je .form
    mov ecx, 2 << 9
    cmp ebx, 30
    je .form
    mov ecx, 1 << 9
.form:
    mov r8, AMDVI_PDE_RW
    or r8, rcx
    or r8, r9
    cmp rax, r8
    jne .no
    push rbx
    push rbp
    push r14
    push r15
    mov r14, rdx
    mov r15, r9
    sub ebx, 9
    sub rsp, 8
    call amdvi_hda_tree_level
    add rsp, 8
    pop r15
    pop r14
    pop rbp
    pop rbx
    test eax, eax
    jz .no
    jmp .next
.leaf:
    mov rcx, AMDVI_PTE_LEAF
    or rcx, rdx
    cmp rax, rcx
    jne .no
    inc r13d
.next:
    inc ebp
    jmp .entry
.yes:
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

; Two-way valid-set equality. Counts plus exact tree census reject extra HDA
; leaves; every recorded HDA page must exist only in DID3. Tag0 records must
; be absent there. The range admission excludes every trusted IOMMU page.
amdvi_hda_disjoint:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov r11, [rel amdvi_native_root]
    call amdvi_hda_tree_check
    test eax, eax
    jz .no
    cmp edx, [rel amdvi_native_mapped]
    jne .no
    mov r11, [rel amdvi_hda_root]
    call amdvi_hda_tree_check
    test eax, eax
    jz .no
    cmp edx, [rel amdvi_hda_mapped]
    jne .no
    xor ebp, ebp
    xor r12d, r12d
.record:
    cmp r12d, DMA_IOMMU_SLOTS
    jae .done
    mov edi, r12d
    call dma_iommu_record
    test rdx, rdx
    jz .next_record
    cmp ecx, 1
    ja .no
    mov ebx, ecx
    test rax, 4095
    jnz .no
    test rdx, 4095
    jnz .no
    cmp rdx, 0x100000
    ja .no
    mov r14, rax
    mov r15, rax
    add r15, rdx
    jc .no
.page:
    cmp r14, r15
    jae .next_record
    mov rdi, r14
    call amdvi_hda_leaf_ptr
    test ebx, ebx
    jnz .hda
    test rax, rax
    jnz .no
    jmp .next_page
.hda:
    test rax, rax
    jz .no
    inc ebp
    mov rdi, r14
    call amdvi_native_leaf_ptr
    test rax, rax
    jnz .no
.next_page:
    add r14, 4096
    jmp .page
.next_record:
    inc r12d
    jmp .record
.done:
    test ebp, ebp
    jz .no
    cmp ebp, [rel amdvi_hda_mapped]
    jne .no
    mov eax, 1
    jmp .out
.no:
    xor eax, eax
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Full BDF identity, class0403/progIF00 or80, Intel/AMD vendor, type0 header,
; exact memory BAR. Reuse VT-d's read-only, architecture-neutral MCFG ATS
; capability reader; AMD requires positively absent/disabled (0/1), and refuses
; unreadable/enabled (2/3). No ATS or PCI config writes. The reader only reads an
; ECAM page whose identity leaf is UC, and the boot identity map is WB (0x83), so
; the requester's ECAM page is made UC first (RCQ-36: without it every AMD target
; read UNREAD and attach always refused).
; EDI=BDF, RSI=MMIO -> EAX1/0; on 0, EDX = the failing check's AMDVI_HDA_R_*.
; Preserves the caller's selected BDF/MMIO.
amdvi_hda_identity:
    push r12
    push r13
    push r14
    mov r12d, edi
    mov r13, rsi
    cmp edi, 0xFFFF
    ja .not_found
    test rsi, rsi
    jz .not_found
    test rsi, 4095
    jnz .not_found
    xor esi, esi
    call pci_bdf_read
    cmp ax, 0x1022
    je .vendor
    cmp ax, 0x8086
    jne .not_found
.vendor:
    mov edi, r12d
    mov esi, 8
    call pci_bdf_read
    shr eax, 8
    and eax, 0xFFFF7F
    cmp eax, 0x040300
    jne .class
    mov edi, r12d
    mov esi, 12
    call pci_bdf_read
    shr eax, 16
    test eax, 0x7F
    jnz .class
    mov edi, r12d
    mov esi, 16
    call pci_bdf_read
    test al, 1
    jnz .bar_bad
    mov r14d, eax
    and r14d, 0xFFFFFFF0
    and eax, 6
    jz .bar
    cmp eax, 4
    jne .bar_bad
    mov edi, r12d
    mov esi, 20
    call pci_bdf_read
    shl rax, 32
    or r14, rax
.bar:
    cmp r14, r13
    jne .bar_bad
    mov edi, r12d
    call amdvi_hda_ecam_uc               ; unmarked -> the reader stays UNREAD -> refuse
    mov edi, r12d
    call vtd_hda_ats_state
    cmp eax, 1
    jbe .ok
    mov edx, AMDVI_HDA_R_ATS_UNREAD
    cmp eax, 2
    je .no
    mov edx, AMDVI_HDA_R_ATS_ENABLED
    jmp .no
.ok:
    mov eax, 1
    jmp .out
.not_found:
    mov edx, AMDVI_HDA_R_NOT_FOUND
    jmp .no
.class:
    mov edx, AMDVI_HDA_R_CLASS
    jmp .no
.bar_bad:
    mov edx, AMDVI_HDA_R_BAR
.no:
    xor eax, eax
.out:
    pop r14
    pop r13
    pop r12
    ret

; EDI=BDF -> EAX 1 when the 2 MiB identity page holding the function's segment-0
; ECAM page lies wholly inside the bus range of the MCFG window that holds the bus
; (so no RAM or foreign MMIO shares it) and is now UC through mmio_mark_uc; else 0,
; nothing changed (no window, a page crossing the window, no reader-visible leaf,
; above the 16 GiB map). Clobbers RAX RCX RDX RSI RDI R8-R11. Callers: amdvi_hda_identity,
; amdvi_guest_attach.
amdvi_hda_ecam_uc:
    cmp edi, 0xFFFF
    ja .no
    mov r10d, [rel acpi_mcfg_count]
    lea r9, [rel acpi_mcfg_entries]
    xor r8d, r8d
    mov eax, edi
    shr eax, 8                            ; bus
.mcfg:
    cmp r8d, r10d
    jae .no
    mov edx, r8d
    shl edx, 4
    cmp word [r9 + rdx + 8], 0            ; segment 0
    jne .next
    cmp al, [r9 + rdx + 10]
    jb .next
    cmp al, [r9 + rdx + 11]
    jbe .window
.next:
    inc r8d
    jmp .mcfg
.window:
    mov rsi, [r9 + rdx]                   ; bus-0 base
    movzx ecx, byte [r9 + rdx + 10]
    shl rcx, 20
    add rcx, rsi                          ; first byte of the window's start bus
    jc .no
    movzx r11d, byte [r9 + rdx + 11]
    inc r11d
    shl r11, 20
    add r11, rsi                          ; exclusive end after its end bus
    jc .no
    mov eax, edi
    shl rax, 12                           ; bus<<20 | dev<<15 | fn<<12
    add rax, rsi
    jc .no
    and rax, ~0x1FFFFF
    cmp rax, rcx
    jb .no
    lea rdx, [rax + 0x200000]
    cmp rdx, r11
    ja .no
    mov rdi, rax
    call paging_pd_entry_ptr              ; the leaf vtd_hda_ats_state will check
    test rax, rax
    jz .no
    mov ecx, [rax]
    and ecx, 0x83
    cmp ecx, 0x83                         ; present 2 MiB leaf only, never a split table
    jne .no
    jmp mmio_mark_uc                      ; EAX 0 above the 16 GiB map / not present
.no:
    xor eax, eax
    ret

; No alias source/range and no IVMD unity exception may name this requester.
; EDI requester -> EAX 1 allowed / 0 refused, unchanged predicate.
; Secondary read-only result: R8 matched parsed entry, R9D kind (1 alias
; range, 2 alias requester field, 3 IVMD), ECX one-based parsed ordinal.
; R8/R9 are zero on no match. Tables are immutable after IVRS ownership.
amdvi_hda_scope:
    xor r8d, r8d
    xor r9d, r9d
    xor ecx, ecx
.alias:
    cmp ecx, [rel amdvi_alias_n]
    jae .ivmd_start
    lea rax, [rel amdvi_alias]
    lea rax, [rax + rcx*8]
    inc ecx
    cmp di, [rax + 4]
    je .alias_id
    cmp di, [rax]
    jb .alias
    cmp di, [rax + 2]
    jbe .alias_range
    jmp .alias
.alias_id:
    mov r9d, 2
    jmp .matched
.alias_range:
    mov r9d, 1
    jmp .matched
.ivmd_start:
    xor ecx, ecx
.ivmd:
    cmp ecx, [rel amdvi_ivmd_n]
    jae .yes
    imul eax, ecx, 24
    lea rdx, [rel amdvi_ivmd]
    add rax, rdx
    inc ecx
    cmp di, [rax]
    jb .ivmd
    cmp di, [rax + 2]
    jbe .ivmd_match
    jmp .ivmd
.ivmd_match:
    mov r9d, 3
.matched:
    mov r8, rax
    xor eax, eax
    ret
.yes:
    mov eax, 1
    ret

; Passive NAS1 v1 snapshot, EDI requester, RSI fixed48 output -> EAX48 or0.
; Uses the SAME predicate over the ownership-time immutable parsed tables;
; no second firmware/PCI scan and no admission, reset or IOMMU writes.
; Zero whole output first. Counts are parser-bounded; reject corrupt counts
; before calling the evaluator, and never expose a pointer or stale record.
; +0 magic NAS1 +4 version16 +6 size16 +8 requester16 +10 kind8
; +11 selected IVHD type8 +12 zero-based parsed ordinal32
; +16 alias count32 +20 IVMD count32 +24 raw parsed entry24.
; Alias entries are8 bytes followed by16 zero bytes. IVMD entries contain
; first16,last16,normalized flags32,aligned base64,length64 (not raw firmware).
amdvi_scope_snapshot:
    push rbx
    push r12
    sub rsp, 8
    mov rbx, rsi
    mov r12d, edi
    mov rdi, rsi
    xor eax, eax
    mov ecx, 6
    cld
    rep stosq
    cmp r12d, 65535
    ja .none
    cmp dword [rel amdvi_alias_n], AMDVI_ALIAS_MAX
    ja .none
    cmp dword [rel amdvi_ivmd_n], AMDVI_IVMD_MAX
    ja .none
    mov edi, r12d
    call amdvi_hda_scope
    test eax, eax
    jnz .none
    test r8, r8
    jz .none
    mov word [rbx+4], 1
    mov word [rbx+6], 48
    mov [rbx+8], r12w
    mov [rbx+10], r9b
    mov rax, [rel amdvi_ivhd]
    test rax, rax
    jz .no_type
    mov al, [rax]
    mov [rbx+11], al
.no_type:
    dec ecx
    mov [rbx+12], ecx
    mov eax, [rel amdvi_alias_n]
    mov [rbx+16], eax
    mov eax, [rel amdvi_ivmd_n]
    mov [rbx+20], eax
    mov rax, [r8]
    mov [rbx+24], rax
    cmp r9d, 3
    jne .publish
    mov rax, [r8+8]
    mov [rbx+32], rax
    mov rax, [r8+16]
    mov [rbx+40], rax
.publish:
    mov dword [rbx], 0x3153414e       ; NAS1 valid last
    mov eax, 48
    jmp .out
.none:
    xor eax, eax
.out:
    add rsp, 8
    pop r12
    pop rbx
    ret

; Shared HDA quiesce predicate: CRST0/CORBRUN0/RIRBDMA0/DPLoff and RUN0 in
; all GCAP-counted descriptors. The owner holds reset throughout transfer.
amdvi_hda_quiesced:
    test dword [rdi + 8], 1
    jnz .no
    test byte [rdi + 0x4C], 2
    jnz .no
    test byte [rdi + 0x5C], 2
    jnz .no
    test dword [rdi + 0x70], 1
    jnz .no
    movzx eax, word [rdi]
    mov ecx, eax
    shr ecx, 8
    and ecx, 15
    mov edx, eax
    shr edx, 12
    and edx, 15
    add ecx, edx
    shr eax, 3
    and eax, 31
    add ecx, eax
    cmp ecx, 30
    ja .no
    lea rax, [rdi + 0x80]
.sd:
    test ecx, ecx
    jz .yes
    test byte [rax], 2
    jnz .no
    add rax, 0x20
    dec ecx
    jmp .sd
.yes:
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

; Exact DTE through the LIVE register's verified table. All four qwords
; matter (especially I/ATS and suppression/permission flags).
; EDI=BDF, RSI=expected qw0, ECX=domain -> EAX1/0.
amdvi_hda_dte_ok:
    mov eax, edi
    shl eax, 5
    add rax, [rel amdvi_devtab]
    cmp [rax], rsi
    jne .no
    cmp [rax + 8], rcx
    jne .no
    cmp qword [rax + 16], 0
    jne .no
    cmp qword [rax + 24], 0
    jne .no
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

; EDI=BDF, RSI=HDA MMIO, EDX=tag1 -> EAX0 attached, else an AMDVI_HDA_R_* reason.
; Precondition refusal changes no DTE and records its reason for the receipt line;
; a refusal on an already attached or poisoned function keeps the recorded cause.
; Once blocked, any uncertainty is sticky poison, never rollback to the broad
; compat domain.
amdvi_hda_attach:
    push r12
    push r13
    sub rsp, 8
    mov r12d, edi
    mov r13, rsi
    mov eax, AMDVI_HDA_R_NO_ENFORCEMENT
    cmp edx, 1
    jne .refuse
    mov eax, AMDVI_HDA_R_ATTACHED
    cmp byte [rel amdvi_hda_state], AMDVI_HDA_OK
    je .out
    mov eax, AMDVI_HDA_R_POISONED
    cmp byte [rel amdvi_hda_state], 0
    jne .out
    mov eax, AMDVI_HDA_R_SERIAL
    cmp qword [rel amdvi_hda_serial], -1
    je .refuse
    call amdvi_hda_enforcing
    test eax, eax
    mov eax, AMDVI_HDA_R_NO_ENFORCEMENT
    jz .refuse
    mov edi, r12d
    mov rsi, r13
    call amdvi_hda_identity
    test eax, eax
    mov eax, edx
    jz .refuse
    mov edi, r12d
    call amdvi_hda_scope
    test eax, eax
    mov eax, AMDVI_HDA_R_SCOPE
    jz .refuse
    mov edi, r12d
    mov rsi, [rel amdvi_compat_qw0]
    mov ecx, AMDVI_DOM_COMPAT
    call amdvi_hda_dte_ok
    test eax, eax
    mov eax, AMDVI_HDA_R_COMPAT_DTE
    jz .refuse
    mov rdi, r13
    call amdvi_hda_quiesced
    test eax, eax
    mov eax, AMDVI_HDA_R_NOT_QUIESCED
    jz .refuse
    call amdvi_hda_disjoint
    test eax, eax
    mov eax, AMDVI_HDA_R_DISJOINT
    jz .refuse
    ; ---- commit boundary: only valid blocked or valid isolated from here ----
    mov [rel amdvi_hda_bdf], r12d
    mov [rel amdvi_hda_mmio], r13
    mov byte [rel amdvi_hda_state], AMDVI_HDA_POISON
    mov byte [rel amdvi_hda_reason], AMDVI_HDA_R_INVAL_TIMEOUT
    mov edi, r12d
    mov esi, AMDVI_DTE_BLOCKED
    xor ecx, ecx
    call amdvi_dte_set
    mfence
    mov edi, r12d
    call amdvi_flush_dte
    test eax, eax
    jz .poison
    mov edi, AMDVI_DOM_COMPAT
    call amdvi_flush_domain
    test eax, eax
    jz .poison
    mov edi, r12d
    mov rsi, [rel amdvi_hda_root]
    mov rax, AMDVI_DTE_XLATE
    or rsi, rax
    mov ecx, AMDVI_DOM_HDA
    call amdvi_dte_set
    mfence
    mov edi, r12d
    call amdvi_flush_dte
    test eax, eax
    jz .poison
    mov edi, AMDVI_DOM_HDA
    call amdvi_flush_domain
    test eax, eax
    jz .poison
    mov byte [rel amdvi_hda_reason], AMDVI_HDA_R_NO_ENFORCEMENT
    call amdvi_hda_enforcing
    test eax, eax
    jz .poison
    mov byte [rel amdvi_hda_reason], AMDVI_HDA_R_READBACK
    mov edi, r12d
    mov rsi, [rel amdvi_hda_root]
    mov rax, AMDVI_DTE_XLATE
    or rsi, rax
    mov ecx, AMDVI_DOM_HDA
    call amdvi_hda_dte_ok
    test eax, eax
    jz .poison
    mov byte [rel amdvi_hda_reason], AMDVI_HDA_R_NOT_QUIESCED
    mov rdi, r13
    call amdvi_hda_quiesced
    test eax, eax
    jz .poison
    inc qword [rel amdvi_hda_serial]
    mov byte [rel amdvi_hda_state], AMDVI_HDA_OK   ; the reason byte is read only when state != OK
    xor eax, eax
    jmp .out
.poison:
    call amdvi_hda_poison
    movzx eax, byte [rel amdvi_hda_reason]
    jmp .out
.refuse:
    mov [rel amdvi_hda_reason], al
.out:
    add rsp, 8
    pop r13
    pop r12
    ret

amdvi_hda_receipt:
    xor r10d, r10d
    jmp amdvi_hda_receipt_body
amdvi_hda_live_receipt:
    mov r10d, 1
amdvi_hda_receipt_body:
    push r12
    mov r12d, r10d
    cmp edi, 1
    jne .no
    cmp byte [rel amdvi_hda_state], AMDVI_HDA_OK
    jne .no
    call amdvi_hda_enforcing
    test eax, eax
    jz .no
    mov edi, [rel amdvi_hda_bdf]
    mov rsi, [rel amdvi_hda_mmio]
    call amdvi_hda_identity
    test eax, eax
    jz .no
    mov edi, [rel amdvi_hda_bdf]
    call amdvi_hda_scope
    test eax, eax
    jz .no
    mov edi, [rel amdvi_hda_bdf]
    mov rsi, [rel amdvi_hda_root]
    mov rax, AMDVI_DTE_XLATE
    or rsi, rax
    mov ecx, AMDVI_DOM_HDA
    call amdvi_hda_dte_ok
    test eax, eax
    jz .no
    call amdvi_hda_disjoint
    test eax, eax
    jz .no
    test r12d, r12d
    jnz .yes
    mov rdi, [rel amdvi_hda_mmio]
    call amdvi_hda_quiesced
    test eax, eax
    jz .no
.yes:
    mov eax, 1
    lea rsi, [rel str_amdvi_hda_ok]
    mov rdx, [rel amdvi_hda_serial]
    pop r12
    ret
.no:
    movzx eax, byte [rel amdvi_hda_reason]
    mov edx, AMDVI_HDA_R_RECHECK
    cmp byte [rel amdvi_hda_state], AMDVI_HDA_OK
    cmove eax, edx
    mov edx, AMDVI_HDA_R_NOT_ATTACHED
    test eax, eax
    cmovz eax, edx
    mov edx, AMDVI_HDA_R_LAST
    cmp eax, edx
    cmova eax, edx
    imul eax, eax, AMDVI_HDA_NAME_STRIDE
    lea rdx, [rel amdvi_hda_reason_names]
    add rdx, rax
    lea rsi, [rel str_amdvi_hda_refused]
    lea rdi, [rel amdvi_hda_line]
    cld
.prefix:
    lodsb
    stosb
    test al, al
    jnz .prefix
    dec rdi
    mov rsi, rdx
.name:
    lodsb
    stosb
    test al, al
    jnz .name
    xor eax, eax
    xor edx, edx
    lea rsi, [rel amdvi_hda_line]
    pop r12
    ret

; Private 4 KiB map/unmap engines; callers validate tag, bounds and ownership.
amdvi_hda_leaf_slot:
    mov  r11, [rel amdvi_hda_root]
    mov  ecx, 39
    mov  r9d, 3 << 9                    ; fixed four-level tree: next 3, 2, 1
.walk:
    test r11, r11
    jz   .none
    mov  rax, rdi
    shr  rax, cl
    and  eax, 0x1FF
    lea  rax, [r11 + rax*8]
    cmp  ecx, 12
    je   .ret
    mov  r10, [rax]
    test r10b, 1
    jz   .none
    mov  r11d, r10d
    and  r11d, 7 << 9
    cmp  r11d, r9d                      ; do not interpret skipped/reserved levels as links
    jne  .none
    mov  r11, AMDVI_ADDR_MASK
    and  r11, r10
    sub  ecx, 9
    sub  r9d, 1 << 9
    jmp  .walk
.none:
    xor  eax, eax
.ret:
    ret

; RDI = IOVA -> RAX = &present 4 KiB leaf, else 0.
amdvi_hda_leaf_ptr:
    sub rsp, 8
    call amdvi_hda_leaf_slot
    add rsp, 8
    test rax, rax
    jz   .none
    test byte [rax], 1
    jz   .none
    ret
.none:
    xor  eax, eax
    ret

; Private map engine. Wrapper admits ranges, ensures root and accounts serial.
amdvi_hda_map_pages:
    push rbx
    push r12
    push r13
    push r14
    push r15
    test rdi, 0x0FFF
    jnz  .bad
    test rsi, rsi
    jz   .bad
    test rsi, 0x0FFF
    jnz  .bad
    mov  r12, rdi
    mov  r13, rdi
    add  r13, rsi
    jc   .bad
    mov  r14, rdi
.preflight:
    cmp  r14, r13
    jae  .pages
    ; A bidirectional leaf is usable only when every present upper link
    ; grants both IR and IW. Check the whole span before allocation or writes;
    ; the ordinary ownership walker must still find restricted live leaves.
    mov  r15, [rel amdvi_hda_root]
    mov  ecx, 39
    mov  r9d, 3 << 9
.permission:
    test r15, r15
    jz   .bad
    mov  rax, r14
    shr  rax, cl
    and  eax, 0x1FF
    mov  rax, [r15 + rax*8]
    test al, 1
    jz   .leaf_check                     ; absent path will be created RW
    bt   rax, 61                         ; IR accumulates across the path
    jnc  .bad
    bt   rax, 62                         ; IW accumulates across the path
    jnc  .bad
    mov  edx, eax
    and  edx, 7 << 9
    cmp  edx, r9d
    jne  .bad                           ; only follow exact next 3, 2, 1
    mov  r15, AMDVI_ADDR_MASK
    and  r15, rax
    sub  ecx, 9
    sub  r9d, 1 << 9
    cmp  ecx, 12
    jne  .permission
.leaf_check:
    mov  rdi, r14
    call amdvi_hda_leaf_ptr
    test rax, rax
    jnz  .bad
    add  r14, 4096
    jmp  .preflight
.pages:
    mov  r14, r12
.page:
    cmp  r14, r13
    jae  .mapped
    mov  r15, [rel amdvi_hda_root]
    mov  r8d, 39
    mov  r9d, 3 << 9                     ; the next table's level
.level:
    mov  ecx, r8d
    mov  rax, r14
    shr  rax, cl
    and  eax, 0x1FF
    lea  rbx, [r15 + rax*8]
    cmp  r8d, 12
    je   .leaf
    mov  r15, [rbx]
    test r15b, 1
    jnz  .have
    call amdvi_take_page
    test rax, rax
    jz   .rollback
    mov  r15, rax
    mov  rdx, AMDVI_PDE_RW
    or   rax, rdx
    or   rax, r9
    mov  [rbx], rax
    clflush [rbx]
    jmp  .down
.have:
    mov  eax, r15d
    and  eax, 7 << 9
    cmp  eax, r9d                       ; construction descends exactly one level
    jne  .rollback
.down:
    mov  rax, AMDVI_ADDR_MASK
    and  r15, rax
    sub  r8d, 9
    sub  r9d, 1 << 9
    jmp  .level
.leaf:
    mov  rax, [rbx]
    test al, 1
    jz   .new_leaf
    mov  rdx, AMDVI_ADDR_MASK
    and  rax, rdx
    cmp  rax, r14
    jne  .rollback                       ; never admit an alias
    jmp  .next
.new_leaf:
    mov  rax, AMDVI_PTE_LEAF
    or   rax, r14
    mov  [rbx], rax
    clflush [rbx]
    inc  dword [rel amdvi_hda_mapped]
.next:
    add  r14, 4096
    jmp  .page
.mapped:
    mfence
    mov  edi, AMDVI_DOM_HDA
    call amdvi_flush_domain
    test eax, eax
    jz   .rollback
    mov  rax, r12
    jmp  .out
.rollback:
    ; No device has this IOVA yet: remove exactly this request's leaves.
    mov  r14, r12
.rollback_page:
    cmp  r14, r13
    jae  .rollback_flush
    mov  rdi, r14
    call amdvi_hda_leaf_ptr
    test rax, rax
    jz   .rollback_next
    mov  rdx, [rax]
    mov  rcx, AMDVI_ADDR_MASK
    and  rdx, rcx
    cmp  rdx, r14
    jne  .rollback_next
    mov  qword [rax], 0
    clflush [rax]
    cmp  dword [rel amdvi_hda_mapped], 0
    je   .rollback_next
    dec  dword [rel amdvi_hda_mapped]
.rollback_next:
    add  r14, 4096
    jmp  .rollback_page
.rollback_flush:
    mfence
    mov  edi, AMDVI_DOM_HDA
    call amdvi_flush_domain              ; best effort; the result stays failure
.bad:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
.refuse:
    xor  eax, eax
    ret

; Private unmap engine; record retires only after completed invalidation.
amdvi_hda_unmap_pages:
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 8
    test rdi, 0x0FFF
    jnz  .bad
    test rsi, rsi
    jz   .bad
    test rsi, 0x0FFF
    jnz  .bad
    mov  r12, rdi
    mov  r13, rdi
    add  r13, rsi
    jc   .bad
    mov  rbx, AMDVI_PTE_LEAF             ; exact encoding reconstructed on flush failure
    mov  r14, r12
.preflight:
    cmp  r14, r13
    jae  .clear_start
    mov  rdi, r14
    call amdvi_hda_leaf_ptr
    test rax, rax
    jz   .bad
    ; No journal retains arbitrary leaf flags. Refuse the entire span before
    ; clearing if failure restoration could change permissions or metadata.
    mov  rdx, r14
    or   rdx, rbx
    cmp  [rax], rdx
    jne  .bad
    add  r14, 4096
    jmp  .preflight
.clear_start:
    mov  r14, r12
.clear:
    cmp  r14, r13
    jae  .flush
    mov  rdi, r14
    call amdvi_hda_leaf_ptr
    mov  qword [rax], 0
    clflush [rax]
    cmp  dword [rel amdvi_hda_mapped], 0
    je   .clear_next
    dec  dword [rel amdvi_hda_mapped]
.clear_next:
    add  r14, 4096
    jmp  .clear
.flush:
    mfence
    mov  edi, AMDVI_DOM_HDA
    call amdvi_flush_domain
    test eax, eax
    jz   .restore
    mov  eax, 1
    jmp  .out
.restore:
    ; The record remains live: restore exactly the canonical encoding admitted
    ; across the entire span by preflight. Flush failure is never success.
    mov  r14, r12
.restore_page:
    cmp  r14, r13
    jae  .restore_flush
    mov  rdi, r14
    call amdvi_hda_leaf_slot
    test rax, rax
    jz   .bad
    mov  rdx, AMDVI_PTE_LEAF
    or   rdx, r14
    mov  [rax], rdx
    clflush [rax]
    inc  dword [rel amdvi_hda_mapped]
    add  r14, 4096
    jmp  .restore_page
.restore_flush:
    mfence
    mov  edi, AMDVI_DOM_HDA
    call amdvi_flush_domain              ; best effort; the mapping stays live
.bad:
    xor  eax, eax
.out:
    add rsp, 8
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
.refuse:
    xor  eax, eax
    ret

str_amdvi_hda_ok: db "[PAOS64] amdvi.hda state=ok did=3 tag=1 enforcing=1 pages=4k disjoint=1",0
str_amdvi_hda_refused: db "[PAOS64] amdvi.hda state=refused enforcing=0 reason=",0
; AMDVI_HDA_R_* names, fixed stride (no pointer table); unused numbers read "unknown".
amdvi_hda_reason_names:
    db "ok", 0
    times 13 db 0
%assign amdvi_hda_r 1
%rep AMDVI_HDA_R_LAST
  %if amdvi_hda_r == AMDVI_HDA_R_POISONED
    db "poisoned", 0
    times 7 db 0
  %elif amdvi_hda_r == AMDVI_HDA_R_ATTACHED
    db "attached", 0
    times 7 db 0
  %elif amdvi_hda_r == AMDVI_HDA_R_NO_ENFORCEMENT
    db "no_enforcement", 0
    times 1 db 0
  %elif amdvi_hda_r == AMDVI_HDA_R_NOT_FOUND
    db "not_found", 0
    times 6 db 0
  %elif amdvi_hda_r == AMDVI_HDA_R_CLASS
    db "class", 0
    times 10 db 0
  %elif amdvi_hda_r == AMDVI_HDA_R_BAR
    db "bar", 0
    times 12 db 0
  %elif amdvi_hda_r == AMDVI_HDA_R_NOT_QUIESCED
    db "not_quiesced", 0
    times 3 db 0
  %elif amdvi_hda_r == AMDVI_HDA_R_ATS_ENABLED
    db "ats_enabled", 0
    times 4 db 0
  %elif amdvi_hda_r == AMDVI_HDA_R_INVAL_TIMEOUT
    db "inval_timeout", 0
    times 2 db 0
  %elif amdvi_hda_r == AMDVI_HDA_R_READBACK
    db "readback", 0
    times 7 db 0
  %elif amdvi_hda_r == AMDVI_HDA_R_DISJOINT
    db "disjoint", 0
    times 7 db 0
  %elif amdvi_hda_r == AMDVI_HDA_R_NOT_ATTACHED
    db "not_attached", 0
    times 3 db 0
  %elif amdvi_hda_r == AMDVI_HDA_R_ATS_UNREAD
    db "ats_unread", 0
    times 5 db 0
  %elif amdvi_hda_r == AMDVI_HDA_R_SCOPE
    db "scope", 0
    times 10 db 0
  %elif amdvi_hda_r == AMDVI_HDA_R_COMPAT_DTE
    db "compat_dte", 0
    times 5 db 0
  %elif amdvi_hda_r == AMDVI_HDA_R_SERIAL
    db "serial", 0
    times 9 db 0
  %elif amdvi_hda_r == AMDVI_HDA_R_RECHECK
    db "recheck", 0
    times 8 db 0
  %elif amdvi_hda_r == AMDVI_HDA_R_MAP
    db "map", 0
    times 12 db 0
  %else
    db "unknown", 0
    times 8 db 0
  %endif
  %assign amdvi_hda_r amdvi_hda_r + 1
%endrep
%if $ - amdvi_hda_reason_names != (AMDVI_HDA_R_LAST + 1) * AMDVI_HDA_NAME_STRIDE
  %error "amdvi_hda_reason_names stride"
%endif
%if amdvi_hda_reason_names - str_amdvi_hda_refused + AMDVI_HDA_NAME_STRIDE > 80
  %error "amdvi_hda_line too small"
%endif
%include "core/abi/wdata.inc"
%macro WDATA_hv_amdvi_hda 0
alignb 8
amdvi_hda_root: resq 1
amdvi_hda_serial: resq 1
amdvi_hda_mmio: resq 1
amdvi_hda_mapped: resd 1
amdvi_hda_bdf: resd 1
amdvi_hda_state: resb 1
%endmacro
WDATA_BSS_DEFER WDATA_hv_amdvi_hda
; RCQ-36 S-AMDREASON: the last attach/poison cause and the built refused line.
%macro WDATA_hv_amdvi_hda_reason 0
amdvi_hda_reason: resb 1
amdvi_hda_line: resb 80                 ; 52 B prefix + a 15 B name + NUL
%endmacro
WDATA_BSS_DEFER WDATA_hv_amdvi_hda_reason
