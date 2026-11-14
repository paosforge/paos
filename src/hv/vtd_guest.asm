;; MODULE hv/vtd_guest
;; LAYER 5
;; EXPORTS vtd_guest_group_detach, vtd_guest_group_retired, vtd_guest_group_attach, vtd_guest_group_live, vtd_guest_attach, vtd_guest_detach, vtd_guest_receipt
;; IMPORTS hv/vtd, bus/pci_bdf, core/dma
;; CAPS CAP_MMIO
;; OWNER rc-codex-av
; Explicit serialized VM owner; HDA only. Caller holds reset, stops guest and
; owns positive PCI group/ACS authority. No profile, vPCI, IRQ inject or START.
; DID17 avoids existing network DID16. Six carved pages, RW GPA->host 2MiB
; leaves; no MSI aperture. IR enabled, CFI clear, all IRTEs absent.
VTDG_DID equ 17
VTDG_LIVE equ 1
VTDG_RETIRED equ 2
VTDG_POISON equ 3

vtdg_reset:
    mov qword [rel vtdg_ctx], 0
    mov qword [rel vtdg_pages], 0
    mov qword [rel vtdg_generation], 0
    mov qword [rel vtdg_size], 0
    mov qword [rel vtdg_host], 0
    mov dword [rel vtdg_bdf], 0
    mov byte [rel vtdg_state], 0
    ret


vtdg_range_overlap:
    xor eax,eax
    cmp byte [rel vtdg_state],VTDG_LIVE
    je .check
    cmp byte [rel vtdg_state],VTDG_POISON
    jne .group
.check:
    mov rdx,rdi
    add rdx,rsi
    jc .yes
    cmp rdx,[rel vtdg_host]
    jbe .group
    mov rdx,[rel vtdg_host]
    add rdx,[rel vtdg_size]
    cmp rdi,rdx
    jae .group
.yes: mov eax,1
    ret
.group: jmp vtdgg_range_overlap


vtdg_expected:
    xor eax,eax
    test ecx,ecx
    jnz .pdpt
    mov rax,[rel vtdg_pages]
    add rax,4096
    mov rdx,3
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
    mov r8,[rel vtdg_size]
    dec r8
    shr r8,30
    cmp rdx,r8
    ja .out
    shl rdx,12
    mov rax,[rel vtdg_pages]
    lea rax,[rax+rdx+8192]
    mov rdx,3
    or rax,rdx
    ret
.leaf:
    mov edx,ecx
    sub edx,1024
    shl rdx,21
    cmp rdx,[rel vtdg_size]
    jae .out
    mov rax,[rel vtdg_host]
    add rax,rdx
    mov rdx,0x83
    or rax,rdx
.out: ret

; Fresh enforcement and fault history, not cached boot success.
vtdg_enforcing:
 cmp byte [rel vtd_native_ready],1
 jne .no
 cmp byte [rel vtd_enabled],1
 jne .no
 cmp byte [rel vtd_qi_on],1
 jne .no
 mov rax,[rel vtd_native_pool_base]
 test rax,rax
 jz .no
 test rax,4095
 jnz .no
 mov rax,[rel vtd_unitb_base]
 test rax,rax
 jz .no
 test dword [rax+VTD_REG_GSTS],VTD_GSTS_TES
 jz .no
 mov rdx,[rel vtd_root]
 test rdx,rdx
 jz .no
 cmp [rax+VTD_REG_RTADDR],rdx
 jne .no
 test dword [rax+VTD_REG_FSTS],0xff
 jnz .no
 cmp byte [rel vtdg_fault_latched],0
 jne .no                             ; a fault some clear wiped still counts
 cmp dword [rel vtd_fault_count],0
 jne .no
 bt qword [rel vtd_cap],34
 jnc .no
 bt qword [rel vtd_cap],10
 jnc .no
 mov eax,1
 ret
.no: xor eax,eax
 ret

; MSI writes must reach no IRTE or compatibility interrupt path. Observe only.
vtdg_interrupt_ok:
 cmp byte [rel vtd_ir_on],1
 jne .no
 mov rdx,[rel vtd_unitb_base]
 test rdx,rdx
 jz .no
 mov eax,[rdx+VTD_REG_GSTS]
 and eax,VTD_GSTS_IRES|VTD_GSTS_QIES|VTD_GSTS_CFIS
 cmp eax,VTD_GSTS_IRES|VTD_GSTS_QIES
 jne .no
 mov rax,[rel vtd_irt]
 test rax,rax
 jz .no
 test rax,4095
 jnz .no
 mov rcx,rax
 or rcx,VTD_IRT_S
 cmp [rdx+VTD_REG_IRTA],rcx
 jne .no
 mov ecx,512
.entry:
 cmp qword [rax],0
 jne .no
 add rax,8
 loop .entry
 mov eax,1
 ret
.no: xor eax,eax
 ret

; Trusted contiguous RAM, disjoint from every existing DMA record and metadata.
vtdg_ram_ok:
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
 shr rax,47
 jnz .no
 xor ebx,ebx
.record:
 cmp ebx,DMA_IOMMU_SLOTS
 jae .metadata
 mov edi,ebx
 call dma_iommu_record
 inc ebx
 test rdx,rdx
 jz .record
 call .overlap
 jc .no
 jmp .record
.metadata:
 mov rax,[rel vtd_native_pool_base]
 mov edx,VTD_NATIVE_POOL_BYTES
 call .overlap
 jc .no
 mov rax,[rel vtd_root]
 mov edx,4096
 call .overlap
 jc .no
 mov rax,[rel vtd_shared_ctx]
 call .overlap
 jc .no
 mov rax,[rel vtd_unitb_base]
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

; Exact saved LIVE root entry and exact context; no stale cached pointer proof.
vtdg_context_ok:
 sub rsp,8
 mov edi,[rel vtdg_bdf]
 call vtd_hda_ctx_entry
 test rax,rax
 jz .no
 cmp rax,[rel vtdg_ctx]
 jne .no
 cmp qword [rdx+8],0
 jne .no
 or rcx,1
 cmp [rdx],rcx
 jne .no
 mov rdx,[rel vtdg_pages]
 or rdx,1
 cmp [rax],rdx
 jne .no
 cmp qword [rax+8],(VTDG_DID<<8)|2
 jne .no
 mov eax,1
 jmp .out
.no: xor eax,eax
.out: add rsp,8
 ret

; EDI old/new DID. Same device-selective CC, CM negative cache, domain IOTLB
; and hardware-supported DR/DW hints as native HDA. Every completion required.
vtdg_flush:
 push rbx
 mov ebx,edi
 mov esi,[rel vtdg_bdf]
 call vtd_dev_cc
 test eax,eax
 jz .out
 bt qword [rel vtd_cap],7
 jnc .iotlb
 xor edi,edi
 mov esi,[rel vtdg_bdf]
 call vtd_dev_cc
 test eax,eax
 jz .out
.iotlb:
 mov esi,1
 call vtd_drain_hint
 mov edi,ebx
 call vtd_native_iotlb_invalidate.domain
.out: pop rbx
 ret

vtdg_block:
 sub rsp,8
 mov rax,[rel vtdg_ctx]
 test rax,rax
 jz .live
 mov qword [rax],0
 mov qword [rax+8],0
 clflush [rax]
.live:
 mov edi,[rel vtdg_bdf]
 call vtd_hda_ctx_entry             ; also block the current root after drift
 test rax,rax
 jz .out
 mov qword [rax],0
 mov qword [rax+8],0
 clflush [rax]
.out:
 mfence
 add rsp,8
 ret

; EDI = the FSTS fault bits vtd_clear_faults is about to clear (bit 1 also set
; when any FRCD F bit was). A fault cleared while the guest domain is live is
; latched for the boot, so its release poisons as AMD's sticky amdvi_events
; does. Touches EAX only.
vtdg_fault_note:
 test edi,0xff
 jz .out
 cmp byte [rel vtdg_state],VTDG_LIVE
 je .latch
 cmp byte [rel vtdgg_state],VTDG_LIVE
 je .latch
 cmp byte [rel vtdgg_state],VTDG_POISON
 jne .out
.latch:
 mov byte [rel vtdg_fault_latched],1
.out: ret

vtdg_poison:
 sub rsp,8
 mov byte [rel vtdg_state],VTDG_POISON
 call vtdg_block
 mov edi,VTDG_DID
 call vtdg_flush                     ; best effort; pages and RAM remain pinned
 add rsp,8
 mov eax,-1
 ret

; EDI segment0 BDF, RSI RAM bytes, RDX host base, RCX nonzero increasing START.
; Precondition refusal does not steal native/HDA ownership. After blocking,
; every uncertain transition poisons; never restore compatibility mapping.
vtd_guest_attach:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,8
 mov r12d,edi
 mov r13,rsi
 mov r14,rdx
 mov r15,rcx
 call vtdgg_held
 test eax,eax
 jnz .no
 cmp edi,0xffff
 ja .no
 cmp byte [rel vtdg_state],VTDG_LIVE
 je .no
 cmp byte [rel vtdg_state],VTDG_POISON
 je .no
 cmp byte [rel vtd_owner_guest],0
 jne .no
 test rcx,rcx
 jz .no
 cmp rcx,[rel vtdg_generation]
 jbe .no
 call vtdg_enforcing
 test eax,eax
 jz .no
 mov edi,r12d
 call vtd_hda_iso
 test eax,eax
 jnz .no
 mov edi,r12d
 call vtd_hda_foreign_drhd
 test eax,eax
 jnz .no
 mov edi,r12d
 call vtd_hda_ats_state
 cmp eax,1
 ja .no
 mov edi,r12d
 mov esi,8
 call pci_bdf_read
 shr eax,8
 and eax,0xffff7f
 %ifidn RCQ50_G0_FLR_LAB,1
 cmp eax,0x020000                    ; RCQ-50 G0 lab: the one pinned FLR endpoint (pci_assign)
 jne .class_hda
 mov edi,r12d
 xor esi,esi
 call pci_bdf_read
 cmp eax,0x10c98086
 jne .no
 jmp .class_ok
.class_hda:
 %endif
 %ifdef PAOS_NIC_ASSIGNMENT
 cmp eax,0x020000                    ; selected Ethernet NIC, exact custody+FLR gate
 je .nic_selected
 cmp eax,0x028000                    ; opt-in wireless; identical exact ARMED/reset custody predicate
 jne .nic_class_hda
.nic_selected:
 mov edi,r12d
 mov rsi,r15
 call nic_assignment_admit
 cmp eax,1
 je .class_ok
 ; Exceptional first attach is Ethernet/Intel only. Wi-Fi remains strict.
 mov edi,r12d
 mov esi,8
 call pci_bdf_read
 shr eax,8
 cmp eax,0x020000
 jne .no
 mov edi,r12d
 mov rsi,r15
 call nic_assignment_isolation_admit
 cmp eax,1
 jne .no
 jmp .class_ok
.nic_class_hda:
 %endif
 cmp eax,0x040300
 jne .no
.class_ok:
 mov edi,r12d
 mov esi,0x0c
 call pci_bdf_read
 shr eax,16
 test eax,0x7f
 jnz .no
 mov edi,r12d
 mov esi,4
 call pci_bdf_read
 test al,4                           ; caller disabled BME and holds HDA reset
 jnz .no
 mov edi,r12d
 call vtd_hda_ctx_entry
 test rax,rax
 jz .no
 mov rbp,rax
 cmp byte [rel vtdg_state],VTDG_RETIRED
 jne .compat
 cmp r12d,[rel vtdg_bdf]
 jne .compat
 cmp rax,[rel vtdg_ctx]
 jne .no
 cmp qword [rax],0
 jne .no
 cmp qword [rax+8],0
 jne .no
 jmp .root
.compat:
 mov rbx,[rel vtd_id_pml4]
 or rbx,1
 cmp [rax],rbx
 jne .no
 cmp qword [rax+8],0x102
 jne .no
.root:
 cmp qword [rdx+8],0
 jne .no
 mov rax,rcx
 or rax,1
 cmp [rdx],rax
 jne .no
 mov rsi,r13
 mov rdx,r14
 call vtdg_ram_ok
 test eax,eax
 jz .no
 ; All six tree pages must be available before allocation; optional seventh
 ; clones only this bus's shared context. No allocation while live/poisoned.
 mov edi,r12d
 call vtd_hda_ctx_entry
 mov ebx,6
 cmp rcx,[rel vtd_shared_ctx]
 jne .capacity
 inc ebx
.capacity:
 cmp qword [rel vtdg_pages],0
 je .count
 sub ebx,6
.count:
 add ebx,[rel vtd_native_pool_next]
 cmp ebx,VTD_NATIVE_POOL_PAGES
 ja .no
 cmp byte [rel vtd_ir_on],1
 je .ir
 mov rbx,[rel vtd_unitb_base]
 call vtd_ir_enable                  ; existing canonical host-IRQ checks/QI/IEC
 test eax,eax
 jz .no
.ir:
 call vtdg_interrupt_ok
 test eax,eax
 jz .no
 cmp qword [rel vtdg_pages],0
 jne .private
 mov ebx,6
.allocate:
 call vtd_native_take_page
 test rax,rax
 jz .no
 cmp ebx,6
 jne .next
 mov [rel vtdg_pages],rax
.next: dec ebx
 jnz .allocate
.private:
 mov edi,r12d
 call vtd_hda_ctx_entry
 mov rbp,rax
 cmp rcx,[rel vtd_shared_ctx]
 jne .commit
 mov [rsp],rdx                      ; live root entry address
 call vtd_native_take_page
 test rax,rax
 jz .no
 mov rbx,rax
 mov rsi,[rel vtd_shared_ctx]
 mov rdi,rax
 mov ecx,512
 cld
 rep movsq
 mov rdi,rbx
 call vtd_flush_page
 mfence
 mov rdx,[rsp]
 mov rax,rbx
 or rax,1
 mov [rdx],rax
 mov qword [rdx+8],0
 clflush [rdx]
 mfence
 mov eax,r12d
 and eax,255
 shl eax,4
 lea rbp,[rbx+rax]
.commit:
 mov [rel vtdg_ctx],rbp
 mov [rel vtdg_bdf],r12d
 mov [rel vtdg_generation],r15
 mov [rel vtdg_size],r13
 mov [rel vtdg_host],r14
 mov byte [rel vtdg_state],VTDG_POISON
 call vtdg_block
 ; First remove old DID1 and drain it before publishing GPA mappings.
 mov edi,VTD_DID_IDENTITY
 mov esi,r12d
 call vtd_dev_cc
 test eax,eax
 jz .poison
 mov esi,1
 call vtd_drain_hint
 mov edi,VTD_DID_IDENTITY
 call vtd_native_iotlb_invalidate.domain
 test eax,eax
 jz .poison
 xor ebx,ebx
.build:
 mov ecx,ebx
 call vtdg_expected
 mov rdi,[rel vtdg_pages]
 mov [rdi+rbx*8],rax
 clflush [rdi+rbx*8]
 inc ebx
 cmp ebx,3072
 jb .build
 mfence
 mov rax,[rel vtdg_pages]
 or rax,1
 mov qword [rbp+8],(VTDG_DID<<8)|2
 mov [rbp],rax
 clflush [rbp]
 mfence
 mov edi,VTDG_DID
 call vtdg_flush
 test eax,eax
 jz .poison
 mov byte [rel vtdg_state],VTDG_LIVE
 call vtdg_live
 test eax,eax
 jz .poison
 xor eax,eax
 jmp .out
.poison: call vtdg_poison
 jmp .out
.no: mov eax,-1
.out:
 add rsp,8
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

vtdg_live:
 push rbx
 cmp byte [rel vtdg_state],VTDG_LIVE
 jne .no
 call vtdg_enforcing
 test eax,eax
 jz .no
 call vtdg_interrupt_ok
 test eax,eax
 jz .no
 mov rax,[rel vtdg_pages]
 test rax,4095
 jnz .no
 sub rax,[rel vtd_native_pool_base]
 jc .no
 shr rax,12
 add rax,6
 cmp eax,[rel vtd_native_pool_next]
 ja .no
 cmp rax,VTD_NATIVE_POOL_PAGES
 ja .no
 call vtdg_context_ok
 test eax,eax
 jz .no
 xor ebx,ebx
.entry:
 mov ecx,ebx
 call vtdg_expected
 mov rdi,[rel vtdg_pages]
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

; Writable owned64B: state,generation,BDF,context0,context1,IR policy(1),
; leaf count,sticky fault count. Return1 only fresh live full-tree/IR census.
vtd_guest_receipt:
 push r12
 push r13
 sub rsp,8
 mov r12,rdi
 call vtdg_live
 mov r13d,eax
 movzx eax,byte [rel vtdg_state]
 mov [r12],rax
 mov rax,[rel vtdg_generation]
 mov [r12+8],rax
 mov eax,[rel vtdg_bdf]
 mov [r12+16],rax
 xor eax,eax
 mov [r12+24],rax
 mov [r12+32],rax
 mov [r12+40],rax
 mov [r12+48],rax
 mov rdx,[rel vtdg_ctx]
 test rdx,rdx
 jz .faults
 mov rax,[rdx]
 mov [r12+24],rax
 mov rax,[rdx+8]
 mov [r12+32],rax
 test r13d,r13d
 jz .faults
 mov qword [r12+40],1
 mov rax,[rel vtdg_size]
 shr rax,21
 mov [r12+48],rax
.faults:
 mov eax,[rel vtd_fault_count]
 mov [r12+56],rax
 mov eax,r13d
 add rsp,8
 pop r13
 pop r12
 ret

; VM actually stopped and BME clear/reset held. Identity refusal is inert.
vtd_guest_detach:
 push rbx
 cmp byte [rel vtdg_state],VTDG_LIVE
 jne .no
 cmp edi,[rel vtdg_bdf]
 jne .no
 cmp rsi,[rel vtdg_generation]
 jne .no
 call vtdg_enforcing
 test eax,eax
 jz .poison
 call vtdg_context_ok
 test eax,eax
 jz .poison
 mov byte [rel vtdg_state],VTDG_POISON
 call vtdg_block
 mov edi,VTDG_DID
 call vtdg_flush
 test eax,eax
 jz .poison
 call vtdg_enforcing
 test eax,eax
 jz .poison
 mov edi,[rel vtdg_bdf]
 call vtd_hda_ctx_entry
 test rax,rax
 jz .poison
 cmp rax,[rel vtdg_ctx]
 jne .poison
 cmp qword [rdx+8],0
 jne .poison
 or rcx,1
 cmp [rdx],rcx
 jne .poison
 cmp qword [rax],0
 jne .poison
 cmp qword [rax+8],0
 jne .poison
 mov rdi,[rel vtdg_pages]
 mov ecx,6*4096/8
 xor eax,eax
 cld
 rep stosq
 mov rdi,[rel vtdg_pages]
 mov ebx,6
.flush:
 push rdi
 call vtd_flush_page
 pop rdi
 add rdi,4096
 dec ebx
 jnz .flush
 mfence
 mov byte [rel vtdg_state],VTDG_RETIRED
 xor eax,eax
 pop rbx
 ret
.poison: call vtdg_poison
 pop rbx
 ret
.no: mov eax,-1
 pop rbx
 ret

%include "hv/iommu_guest_group.inc"

; B owns both completion and final C-release custody. A common RETIRED flag
; alone cannot release a span. Unknown states retain resources as poison does.
vtdgg_held:
 xor eax,eax
 cmp byte [rel vtdgg_state],0
 je .out
 cmp byte [rel vtdgg_state],VTDG_RETIRED
 jne .yes
 cmp byte [rel vtdgg_released],1
 je .out
.yes: mov eax,1
.out: ret

vtdgg_range_overlap:
 push rdx
 call vtdgg_held
 test eax,eax
 jz .out
 mov rax,[rel vtdgg_identity+PG_RAM]
 mov rdx,[rel vtdgg_identity+PG_BYTES]
 call iommu_guest_group_overlap
.out:
 pop rdx
 ret

vtdgg_ram_ok:
 push r12
 mov r12,rdi
 mov rsi,[r12+PG_BYTES]
 mov rdx,[r12+PG_RAM]
 call vtdg_ram_ok
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
 mov rax,[rel vtd_unitb_base]
 mov edx,0x5000
 mov rdi,r12
 call iommu_guest_group_disjoint
 test eax,eax
 jz .out
 mov rax,[rel vtd_irt]
 mov edx,4096
 mov rdi,r12
 call iommu_guest_group_disjoint
 test eax,eax
 jz .out
 mov rax,[rel vtd_qi_queue]
 mov edx,4096
 mov rdi,r12
 call iommu_guest_group_disjoint
 test eax,eax
 jz .out
 mov rax,[rel vtd_qi_status]
 mov edx,4096
 mov rdi,r12
 call iommu_guest_group_disjoint
 test eax,eax
 jz .out
 lea rax,[rel vtdgg_begin]
 lea rdx,[rel vtdgg_end]
 sub rdx,rax
 mov rdi,r12
 call iommu_guest_group_disjoint
.out: pop r12
 ret

; Exact private capture, never a caller copy or diagnostic reconstruction.
; State, failure tags and step flags are mutable lifecycle diagnostics. All
; other bytes (including every reserved/unused member byte) stay frozen.

; Pure ABI shape; neither common state nor diagnostic flags grant custody.
vtdgg_shape_ok:
 lea rax,[rel pcia_grp]
 cmp rdi,rax
 jne .no
 mov eax,[rel hv_linux_start_consumed]
 test eax,eax
 jz .no
 cmp [rdi+PG_GEN],rax
 jne .no
 jmp vtdgg_shape_fields
.no: xor eax,eax
 ret

; Shape of our immutable old capture, never the overwritten common record.
; Only a strictly newer consumed START can observe it for reuse preparation.
vtdgg_saved_ok:
 lea rax,[rel vtdgg_identity]
 cmp rdi,rax
 jne .no
 lea rax,[rel pcia_grp]
 cmp rax,[rel vtdgg_record]
 jne .no
 mov rax,[rdi+PG_GEN]
 test rax,rax
 jz .no
 mov edx,[rel hv_linux_start_consumed]
 cmp rax,rdx
 jae .no
 cmp byte [rel vtdgg_state],VTDG_RETIRED
 jne .no
 cmp byte [rel vtdgg_released],1
 jne .no
 cmp byte [rel vtdgg_completed],0
 jne .no
 movzx ecx,byte [rdi+PG_COUNT]
 cmp ecx,2
 jb .no
 cmp ecx,PCIA_GRP_MAX
 ja .no
 mov eax,1
 shl eax,cl
 dec eax
 cmp al,[rel vtdgg_retired_mask]
 jne .no
 jmp vtdgg_shape_fields
.no: xor eax,eax
 ret

vtdgg_shape_fields:
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
 cmp byte [rdi+PG_BACKEND],PGB_VTD
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

vtdgg_identity_ok:
 push rbx
 call vtdgg_shape_ok
 test eax,eax
 jz .out
 cmp rdi,[rel vtdgg_record]
 jne .no
 lea rbx,[rel vtdgg_identity]
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
vtd_guest_group_attach:
 push r12
 mov r12,rdi
 call vtdgg_shape_ok
 test eax,eax
 jz .no
 cmp byte [r12+PG_STATE],PGS_RESET_IN
 jne .no
 cmp byte [rel vtdgg_state],0
 je .admit
 mov rdi,r12
 call vtd_guest_group_reuse_ready
 test eax,eax
 jnz .no
.admit:
 mov rdi,r12
 call nica_grp_backend_admit
 cmp eax,1
 jne .no
 mov rdi,r12
 call vtdgg_attach_core
 test eax,eax
 jnz .out
 ; Fresh original admission and B observation both follow native completion.
 mov rdi,r12
 call nica_grp_backend_admit
 cmp eax,1
 jne .poison
 mov rdi,r12
 call vtdgg_census
 test eax,eax
 jz .poison
 cmp byte [r12+PG_STATE],PGS_RESET_IN
 jne .poison
 mov byte [r12+PG_STATE],PGS_MAPPED
 xor eax,eax
 jmp .out
.poison:
 mov byte [rel vtdgg_state],VTDG_POISON
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
vtd_guest_group_detach:
 push r12
 mov r12,rdi
 call vtdgg_identity_ok
 test eax,eax
 jz .no
 cmp byte [r12+PG_STATE],PGS_RELEASING
 jne .no
 cmp byte [rel vtdgg_state],VTDG_LIVE
 jne .no
 mov rdi,r12
 call nica_grp_backend_detach_admit
 cmp eax,1
 jne .no
 mov rdi,r12
 call vtdgg_retire_core
 test eax,eax
 jnz .poison
 mov rdi,r12
 call nica_grp_backend_detach_admit
 cmp eax,1
 jne .poison
 mov rdi,r12
 call vtdgg_retired_ok
 test eax,eax
 jz .poison
 xor eax,eax
 jmp .out
.poison:
 mov byte [rel vtdgg_state],VTDG_POISON
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
vtd_guest_group_retired:
 sub rsp,8
 call vtdgg_retired_ok
 test eax,eax
 setz al
 movzx eax,al
 neg eax
 add rsp,8
 ret

vtdgg_retired_ok:
 push r12
 mov r12,rdi
 mov esi,7
 call vtdgg_census_mode
 test eax,eax
 jz .out
 mov rdi,r12
 call vtdgg_identity_ok
 test eax,eax
 jz .out
 cmp byte [r12+PG_STATE],PGS_RELEASING
 jne .no
 cmp byte [rel vtdgg_state],VTDG_RETIRED
 jne .no
 cmp byte [rel vtdgg_released],0
 jne .no
 cmp byte [rel vtdgg_completed],0
 jne .no
 movzx ecx,byte [r12+PG_COUNT]
 mov eax,1
 shl eax,cl
 dec eax
 cmp al,[rel vtdgg_retired_mask]
 jne .no
 mov eax,1
 jmp .out
.no: xor eax,eax
.out: pop r12
 ret

; Pure old released native observation for a newer START. No A/C admission,
; rearm, mapping, compatibility restore, allocation or lifecycle write occurs.
; The new record can differ: this proves only the original installation free.
vtd_guest_group_reuse_ready:
 push r12
 mov r12,rdi
 call vtdgg_new_start_ok
 test eax,eax
 jz .no
 lea rdi,[rel vtdgg_identity]
 mov esi,8
 call vtdgg_census_mode
 test eax,eax
 jz .no
 lea rdi,[rel vtdgg_identity]
 call vtdgg_saved_ok
 test eax,eax
 jz .no
 mov rdi,r12
 call vtdgg_new_start_ok
 test eax,eax
 jz .no
 xor eax,eax
 jmp .out
.no: mov eax,-1
.out: pop r12
 ret

vtdgg_new_start_ok:
 push r12
 mov r12,rdi
 call vtdgg_shape_ok
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

vtd_guest_group_live:
 sub rsp,8
 call vtdgg_census
 test eax,eax
 setz al
 movzx eax,al
 neg eax
 add rsp,8
 ret

vtdgg_census:
 xor esi,esi
 jmp vtdgg_census_mode

; Private observations: retirement blocked+tree (1), blocked+zero (2);
; installation blocked+zero (3), blocked+tree (4), mapped+tree (5),
; original compat+zero (6). Installation is RESET_IN, retirement RELEASING.
; Mode7 observes original RETIRED+full retirement mask with blocked+zero.
; Mode8 reads the saved released capture after a strictly newer START.
; No census mode grants A/C authority or supplies completion provenance.
vtdgg_census_mode:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 mov r12,rdi
 mov ebp,esi
 cmp ebp,8
 je .saved_released
 call vtdgg_identity_ok
 test eax,eax
 jz .no
 test ebp,ebp
 jnz .retiring
 cmp byte [rel vtdgg_state],VTDG_LIVE
 jne .no
 movzx ecx,byte [r12+PG_COUNT]
 mov eax,1
 shl eax,cl
 dec eax
 cmp al,[rel vtdgg_completed]
 jne .no
 jmp .singleton
.saved_released:
 call vtdgg_saved_ok
 test eax,eax
 jz .no
 mov ebp,2
 jmp .empty_completed
.retiring:
 cmp ebp,7
 je .retired
 cmp ebp,6
 ja .no
 cmp byte [rel vtdgg_state],VTDG_POISON
 jne .no
 cmp ebp,2
 ja .install_phase
.retire_phase:
 cmp byte [r12+PG_STATE],PGS_RELEASING
 jne .no
 jmp .empty_completed
.retired:
 cmp byte [rel vtdgg_state],VTDG_RETIRED
 jne .no
 cmp byte [rel vtdgg_released],0
 jne .no
 movzx ecx,byte [r12+PG_COUNT]
 mov eax,1
 shl eax,cl
 dec eax
 cmp al,[rel vtdgg_retired_mask]
 jne .no
 mov ebp,2
 jmp .retire_phase
.install_phase:
 cmp byte [r12+PG_STATE],PGS_RESET_IN
 jne .no
 cmp ebp,5
 jne .empty_completed
 movzx ecx,byte [r12+PG_COUNT]
 mov eax,1
 shl eax,cl
 dec eax
 not eax
 test al,[rel vtdgg_completed]
 jnz .no
 jmp .singleton
.empty_completed:
 cmp byte [rel vtdgg_completed],0
 jne .no
.singleton:
 cmp byte [rel vtdg_state],VTDG_LIVE
 je .no
 cmp byte [rel vtdg_state],VTDG_POISON
 je .no
 mov rax,[rel vtd_unitb_base]
 cmp rax,[rel vtdgg_unit]
 jne .no
 mov rax,[rel vtd_root]
 cmp rax,[rel vtdgg_root]
 jne .no
 mov rax,[rel vtd_native_pool_base]
 cmp rax,[rel vtdgg_pool]
 jne .no
 mov rax,[rel vtd_irt]
 cmp rax,[rel vtdgg_irt]
 jne .no
 mov rax,[rel vtd_qi_queue]
 cmp rax,[rel vtdgg_queue]
 jne .no
 mov rax,[rel vtd_qi_status]
 cmp rax,[rel vtdgg_status]
 jne .no
 call vtdg_enforcing
 test eax,eax
 jz .no
 call vtdg_interrupt_ok
 test eax,eax
 jz .no
 mov rax,[rel vtdgg_pages]
 test rax,4095
 jnz .no
 sub rax,[rel vtd_native_pool_base]
 jc .no
 shr rax,12
 add rax,6
 cmp rax,VTD_NATIVE_POOL_PAGES
 ja .no
 mov edx,[rel vtd_native_pool_next]
 cmp edx,VTD_NATIVE_POOL_PAGES
 ja .no
 cmp rax,rdx
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
 call vtd_hda_foreign_drhd
 test eax,eax
 jnz .no
 movzx edi,word [r13+PGM_BDF]
 call vtd_hda_ctx_entry
 test rax,rax
 jz .no
 lea r8,[rel vtdgg_contexts]
 cmp rax,[r8+rbx*8]
 jne .no
 cmp qword [rdx+8],0
 jne .no
 or rcx,1
 cmp [rdx],rcx
 jne .no
 cmp ebp,6
 je .compat
 test ebp,ebp
 jz .mapped
 cmp ebp,5
 jne .blocked
.mapped:
 mov rdx,[rel vtdgg_pages]
 or rdx,1
 cmp [rax],rdx
 jne .no
 cmp qword [rax+8],(VTDG_DID<<8)|2
 jne .no
 jmp .context_span
.compat:
 mov rdx,[rel vtd_id_pml4]
 or rdx,1
 cmp [rax],rdx
 jne .no
 cmp qword [rax+8],0x102
 jne .no
 jmp .context_span
.blocked:
 cmp qword [rax],0
 jne .no
 cmp qword [rax+8],0
 jne .no
.context_span:
 ; A context outside the native arena must not overlap guest-reachable RAM.
 mov r14,rax
 and r14,-4096
 mov rax,[r12+PG_RAM]
 mov rdx,rax
 add rdx,[r12+PG_BYTES]
 jc .no
 lea rcx,[r14+4096]
 cmp r14,rdx
 jae .next
 cmp rcx,rax
 ja .no
.next:
 inc ebx
 movzx eax,byte [r12+PG_COUNT]
 cmp ebx,eax
 jb .member
 mov rdi,r12
 call vtdgg_ram_ok
 test eax,eax
 jz .no

 xor ebx,ebx
.entry:
 xor eax,eax
 cmp ebp,2
 je .tree_value
 cmp ebp,3
 je .tree_value
 cmp ebp,6
 je .tree_value
 mov ecx,ebx
 call vtdgg_expected
.tree_value:
 mov rdi,[rel vtdgg_pages]
 cmp [rdi+rbx*8],rax
 jne .no
 inc ebx
 cmp ebx,3072
 jb .entry
 mov eax,1
 jmp .out
.no: xor eax,eax
.out:
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

; EDI exact member BDF. Device-selective DID17 context invalidation, optional
; CM negative-DID0 invalidation, and domain DID17 IOTLB with supported DR/DW.
; Every canonical helper must observe its own completed QI wait token. Never
; borrow singleton identity or mutate its capture. IRTEs remain all absent.
vtdgg_flush_member:
 push rbx
 mov ebx,edi
 mov esi,ebx
 mov edi,VTDG_DID
 call vtd_dev_cc
 test eax,eax
 jz .out
 bt qword [rel vtd_cap],7
 jnc .iotlb
 xor edi,edi
 mov esi,ebx
 call vtd_dev_cc
 test eax,eax
 jz .out
.iotlb:
 mov esi,1
 call vtd_drain_hint
 mov edi,VTDG_DID
 call vtd_native_iotlb_invalidate.domain
.out:
 pop rbx
 ret

; B6 private first-install producer. Common RESET_IN is sequencing only;
; the public wrapper consumes original exclusive claims, CPU-off
; and positive inbound reset. No direct public core export.
; RDI == &pcia_grp -> EAX0/-1. Inert preflight precedes capture/allocation.
; Each distinct bus gets one private clone even if its old page was already
; private. This preserves every unrelated function and handles shared aliases
; without changing any source context page. Six tree pages plus at most eight
; clones remain held on every uncertain/post-capture failure.
vtdgg_attach_core:
 push rbx
 push r12
 push r13
 push r14
 push r15
 sub rsp,16
 mov qword [rsp],0             ; per-call first-install/reuse branch
 mov r12,rdi
 call vtdgg_shape_ok
 test eax,eax
 jz .no
 cmp byte [r12+PG_STATE],PGS_RESET_IN
 jne .no
 cmp byte [rel vtdgg_state],0
 jne .reuse_preflight
 cmp byte [rel vtdg_state],VTDG_LIVE
 je .no
 cmp byte [rel vtdg_state],VTDG_POISON
 je .no
 call vtdg_enforcing
 test eax,eax
 jz .no
 call vtdg_interrupt_ok
 test eax,eax
 jz .no
 mov rdi,r12
 call vtdgg_ram_ok
 test eax,eax
 jz .no
 xor ebx,ebx
 mov r14d,6
 mov r15d,-1
.preflight:
 mov eax,ebx
 shl eax,4
 lea r13,[r12+rax+PG_MEMBERS]
 mov rdi,r13
 call iommu_guest_group_member_quiet
 test eax,eax
 jz .no
 movzx edi,word [r13+PGM_BDF]
 call vtd_hda_foreign_drhd
 test eax,eax
 jnz .no
 movzx edi,word [r13+PGM_BDF]
 call vtd_hda_ctx_entry
 test rax,rax
 jz .no
 mov r8,[rel vtd_id_pml4]
 or r8,1
 cmp [rax],r8
 jne .no
 cmp qword [rax+8],0x102
 jne .no
 cmp qword [rdx+8],0
 jne .no
 mov rax,rcx
 or rax,1
 cmp [rdx],rax
 jne .no
 mov rax,rcx
 mov edx,4096
 mov rdi,r12
 call iommu_guest_group_disjoint
 test eax,eax
 jz .no
 movzx eax,word [r13+PGM_BDF]
 shr eax,8
 cmp eax,r15d
 je .same_bus
 mov r15d,eax
 inc r14d
.same_bus:
 inc ebx
 movzx eax,byte [r12+PG_COUNT]
 cmp ebx,eax
 jb .preflight
 mov eax,[rel vtd_native_pool_next]
 cmp eax,VTD_NATIVE_POOL_PAGES
 ja .no
 add rax,r14
 cmp rax,VTD_NATIVE_POOL_PAGES
 ja .no
 ; Freeze the exact original identity/resources before any allocation or root
 ; store. No diagnostic flag supplies custody or completion authority.
 mov [rel vtdgg_record],r12
 mov rsi,r12
 lea rdi,[rel vtdgg_identity]
 mov ecx,PCIA_GRP_BYTES/8
 cld
 rep movsq
 mov rax,[rel vtd_unitb_base]
 mov [rel vtdgg_unit],rax
 mov rax,[rel vtd_root]
 mov [rel vtdgg_root],rax
 mov rax,[rel vtd_native_pool_base]
 mov [rel vtdgg_pool],rax
 mov rax,[rel vtd_irt]
 mov [rel vtdgg_irt],rax
 mov rax,[rel vtd_qi_queue]
 mov [rel vtdgg_queue],rax
 mov rax,[rel vtd_qi_status]
 mov [rel vtdgg_status],rax
 mov byte [rel vtdgg_state],VTDG_POISON
 mov byte [rel vtdgg_released],0
 mov byte [rel vtdgg_completed],0
 mov byte [rel vtdgg_retired_mask],0
 mov byte [rel vtdgg_blocked_mask],0
 xor ebx,ebx
 mov r15d,PGX_READBACK
.capture_members:
 mov eax,ebx
 shl eax,4
 movzx edi,word [r12+rax+PG_MEMBERS+PGM_BDF]
 call vtd_hda_ctx_entry
 test rax,rax
 jz .poison
 lea rdx,[rel vtdgg_contexts]
 mov [rdx+rbx*8],rax
 lea rdx,[rel vtdgg_sources]
 mov [rdx+rbx*8],rcx
 inc ebx
 movzx eax,byte [r12+PG_COUNT]
 cmp ebx,eax
 jb .capture_members
 mov ebx,0xff
 mov r15d,PGX_MAP
 mov eax,[rel vtd_native_pool_next]
 shl rax,12
 add rax,[rel vtdgg_pool]
 mov r14,rax
 mov [rel vtdgg_pages],rax
 mov r13d,6
.allocate:
 call vtd_native_take_page
 cmp rax,r14
 jne .poison
 add r14,4096
 dec r13d
 jnz .allocate
 xor ebx,ebx
.clone_bus:
 test ebx,ebx
 jz .new_bus
 mov eax,ebx
 shl eax,4
 movzx ecx,word [r12+rax+PG_MEMBERS+PGM_BDF]
 movzx edx,word [r12+rax+PG_MEMBERS-PGM_BYTES+PGM_BDF]
 shr ecx,8
 shr edx,8
 cmp ecx,edx
 je .have_clone
.new_bus:
 call vtd_native_take_page
 cmp rax,r14
 jne .poison
 add r14,4096
 mov r13,rax
 lea rax,[rel vtdgg_sources]
 mov rsi,[rax+rbx*8]
 mov rdi,r13
 mov ecx,512
 cld
 rep movsq
 mov rdi,r13
 call vtd_flush_page
.have_clone:
 lea rax,[rel vtdgg_clones]
 mov [rax+rbx*8],r13
 inc ebx
 movzx eax,byte [r12+PG_COUNT]
 cmp ebx,eax
 jb .clone_bus
 mfence
 mov r14,[rel vtdgg_pages]
 mov ebx,0xff
 mov r13d,6
 call .check
 test eax,eax
 jz .poison
 ; Every private clone is blocked first. Only then publish the bus roots;
 ; source pages remain untouched, including aliased compatibility templates.
 xor ebx,ebx
.block_all:
 mov eax,ebx
 shl eax,4
 movzx eax,word [r12+rax+PG_MEMBERS+PGM_BDF]
 and eax,255
 shl eax,4
 lea rdx,[rel vtdgg_clones]
 add rax,[rdx+rbx*8]
 lea rdx,[rel vtdgg_contexts]
 mov [rdx+rbx*8],rax
 mov qword [rax],0
 mov qword [rax+8],0
 clflush [rax]
 inc ebx
 movzx eax,byte [r12+PG_COUNT]
 cmp ebx,eax
 jb .block_all
 mfence
 xor ebx,ebx
.publish_all:
 mov eax,ebx
 shl eax,4
 movzx ecx,word [r12+rax+PG_MEMBERS+PGM_BDF]
 shr ecx,8
 test ebx,ebx
 jz .publish_bus
 movzx edx,word [r12+rax+PG_MEMBERS-PGM_BYTES+PGM_BDF]
 shr edx,8
 cmp ecx,edx
 je .next_bus
.publish_bus:
 shl ecx,4
 add rcx,[rel vtdgg_root]
 lea rax,[rel vtdgg_sources]
 mov rax,[rax+rbx*8]
 or rax,1
 cmp [rcx],rax
 jne .poison
 cmp qword [rcx+8],0
 jne .poison
 lea rax,[rel vtdgg_clones]
 mov rax,[rax+rbx*8]
 or rax,1
 mov [rcx],rax
 mov qword [rcx+8],0
 clflush [rcx]
.next_bus:
 inc ebx
 movzx eax,byte [r12+PG_COUNT]
 cmp ebx,eax
 jb .publish_all
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
 cmp qword [rsp],1
 je .reuse_flush
 call vtdgg_flush_old_member
 jmp .old_flushed
.reuse_flush:
 call vtdgg_flush_member
.old_flushed:
 test eax,eax
 jz .poison
 call .check
 test eax,eax
 jz .poison
 mov ecx,ebx
 mov eax,1
 shl eax,cl
 or [rel vtdgg_blocked_mask],al
 inc ebx
 movzx ecx,byte [r12+PG_COUNT]
 cmp ebx,ecx
 jb .old_member
 mov eax,1
 shl eax,cl
 dec eax
 cmp al,[rel vtdgg_blocked_mask]
 jne .poison
 ; All old DID1 device contexts AND domain IOTLB invalidations completed
 ; their own fresh QI waits. Only now build the six guest translation pages.
 xor ebx,ebx
.build:
 mov ecx,ebx
 call vtdgg_expected
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
 lea rax,[rel vtdgg_contexts]
 mov rax,[rax+rbx*8]
 mov rdx,r14
 or rdx,1
 mov qword [rax+8],(VTDG_DID<<8)|2
 mov [rax],rdx
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
 call vtdgg_flush_member
 test eax,eax
 jz .poison
 call .check
 test eax,eax
 jz .poison
 mov ecx,ebx
 mov eax,1
 shl eax,cl
 or [rel vtdgg_completed],al
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
 cmp al,[rel vtdgg_completed]
 jne .poison
 mov byte [rel vtdgg_state],VTDG_LIVE
 mov ebx,0xff
 mov r15d,PGX_READBACK
 mov rdi,r12
 call vtdgg_census
 test eax,eax
 jz .poison
 xor eax,eax
 jmp .out
.check:
 sub rsp,8
 mov r15d,PGX_READBACK
 mov rdi,r12
 mov esi,r13d
 call vtdgg_census_mode
 test eax,eax
 jz .checked
 cmp r14,[rel vtdgg_pages]
 jne .bad_check
 add rsp,8
 ret
.bad_check:
 xor eax,eax
.checked:
 add rsp,8
 ret
.poison:
 mov byte [rel vtdgg_state],VTDG_POISON
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

; Reuse keeps original native context slots; fresh A/C validates this START.
.reuse_preflight:
 mov rdi,r12
 call vtd_guest_group_reuse_ready
 test eax,eax
 jnz .no
 movzx eax,byte [r12+PG_COUNT]
 cmp al,[rel vtdgg_identity+PG_COUNT]
 jne .no
 xor ebx,ebx
.reuse_member_shape:
 mov eax,ebx
 shl eax,4
 lea rdx,[rel vtdgg_identity+PG_MEMBERS]
 mov cx,[r12+rax+PG_MEMBERS+PGM_BDF]
 cmp cx,[rdx+rax+PGM_BDF]
 jne .no
 ; Existing context pages are retained, so exclude them from NEW guest RAM.
 lea rax,[rel vtdgg_contexts]
 mov rax,[rax+rbx*8]
 and rax,-4096
 mov edx,4096
 mov rdi,r12
 call iommu_guest_group_disjoint
 test eax,eax
 jz .no
 inc ebx
 movzx eax,byte [r12+PG_COUNT]
 cmp ebx,eax
 jb .reuse_member_shape
 mov rdi,r12
 call vtdgg_ram_ok
 test eax,eax
 jz .no
 ; Repeat the old native proof after new-range/slot preflight, then capture
 ; this START. From this point uncertainty poisons and holds the NEW span.
 mov rdi,r12
 call vtd_guest_group_reuse_ready
 test eax,eax
 jnz .no
 mov rsi,r12
 lea rdi,[rel vtdgg_identity]
 mov ecx,PCIA_GRP_BYTES/8
 cld
 rep movsq
 mov byte [rel vtdgg_state],VTDG_POISON
 mov byte [rel vtdgg_released],0
 mov byte [rel vtdgg_completed],0
 mov byte [rel vtdgg_retired_mask],0
 mov byte [rel vtdgg_blocked_mask],0
 mov qword [rsp],1
 mov r14,[rel vtdgg_pages]
 xor ebx,ebx
 ; No compatibility mapping or allocation is restored. Fresh blocked-phase
 ; waits precede the new tree, then fresh mapped-phase waits prove install.
 jmp .old_member

; Actual old-DID1 removal. Keep CM negative-DID0 handling, supported DR/DW
; and the canonical QI producer/fresh-token waits; never borrow DID17 or a
; singleton's capture to claim the old compatibility domain has drained.
vtdgg_flush_old_member:
 push rbx
 mov ebx,edi
 mov esi,ebx
 mov edi,VTD_DID_IDENTITY
 call vtd_dev_cc
 test eax,eax
 jz .out
 bt qword [rel vtd_cap],7
 jnc .iotlb
 xor edi,edi
 mov esi,ebx
 call vtd_dev_cc
 test eax,eax
 jz .out
.iotlb:
 mov esi,1
 call vtd_drain_hint
 mov edi,VTD_DID_IDENTITY
 call vtd_native_iotlb_invalidate.domain
.out:
 pop rbx
 ret

; B4 private retirement operation, not the public detach/admission interface.
; The public B wrapper consumes C's original exclusive claims, CPU-off
; and outbound-reset custody before and after actual retirement.
; RDI == &pcia_grp, common RELEASING, backend LIVE -> EAX0/-1.
; Every requester is blocked BEFORE any invalidation. Every real completion
; AND fresh whole-group readback precedes the corresponding private bit. Only
; after all bits are positive may shared pages be scrubbed. C alone releases
; claims and sets released=1/common RETIRED; this operation never does either.
vtdgg_retire_core:
 push rbx
 push r12
 push r13
 push r14
 push r15
 lea rax,[rel pcia_grp]
 cmp rdi,rax
 jne .no
 cmp rdi,[rel vtdgg_record]
 jne .no
 cmp byte [rdi+PG_STATE],PGS_RELEASING
 jne .no
 cmp byte [rel vtdgg_state],VTDG_LIVE
 jne .no
 mov r12,rdi
 mov ebx,0xff
 mov r15d,PGX_READBACK
 call vtdgg_census
 test eax,eax
 jz .poison
 mov r14,[rel vtdgg_pages]
 mov byte [rel vtdgg_state],VTDG_POISON
 mov byte [rel vtdgg_released],0
 mov byte [rel vtdgg_completed],0
 mov byte [rel vtdgg_retired_mask],0
 xor ebx,ebx
.block_all:
 lea rax,[rel vtdgg_contexts]
 mov rax,[rax+rbx*8]
 mov qword [rax],0
 mov qword [rax+8],0
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
 call vtdgg_census_mode
 test eax,eax
 jz .poison
 cmp r14,[rel vtdgg_pages]
 jne .poison
 mov eax,ebx
 shl eax,4
 movzx edi,word [r12+rax+PG_MEMBERS+PGM_BDF]
 mov r15d,PGX_INVALIDATE
 call vtdgg_flush_member
 test eax,eax
 jz .poison
 mov r15d,PGX_READBACK
 mov rdi,r12
 mov esi,1
 call vtdgg_census_mode
 test eax,eax
 jz .poison
 cmp r14,[rel vtdgg_pages]
 jne .poison
 mov ecx,ebx
 mov eax,1
 shl eax,cl
 or [rel vtdgg_retired_mask],al
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
 cmp al,[rel vtdgg_retired_mask]
 jne .poison
 ; All requester caches have actually completed and all contexts read blocked.
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
 call vtdgg_census_mode
 test eax,eax
 jz .poison
 cmp r14,[rel vtdgg_pages]
 jne .poison
 mov byte [rel vtdgg_state],VTDG_RETIRED
 xor eax,eax
 jmp .out
.poison:
 mov byte [rel vtdgg_state],VTDG_POISON
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

vtdgg_expected:
    xor eax,eax
    test ecx,ecx
    jnz .pdpt
    mov rax,[rel vtdgg_pages]
    add rax,4096
    mov rdx,3
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
    mov r8,[rel vtdgg_identity+PG_BYTES]
    dec r8
    shr r8,30
    cmp rdx,r8
    ja .out
    shl rdx,12
    mov rax,[rel vtdgg_pages]
    lea rax,[rax+rdx+8192]
    mov rdx,3
    or rax,rdx
    ret
.leaf:
    mov edx,ecx
    sub edx,1024
    shl rdx,21
    cmp rdx,[rel vtdgg_identity+PG_BYTES]
    jae .out
    mov rax,[rel vtdgg_identity+PG_RAM]
    add rax,rdx
    mov rdx,0x83
    or rax,rdx
.out: ret

%include "core/abi/wdata.inc"
%macro WDATA_hv_vtd_guest 0
alignb 8
vtdg_pages: resq 1
vtdg_generation: resq 1
vtdg_size: resq 1
vtdg_host: resq 1
vtdg_ctx: resq 1
vtdg_bdf: resd 1
vtdg_state: resb 1
vtdg_fault_latched: resb 1          ; never reset in a boot
alignb 8
vtdgg_begin:
vtdgg_record: resq 1
vtdgg_unit: resq 1
vtdgg_root: resq 1
vtdgg_pages: resq 1
vtdgg_pool: resq 1
vtdgg_irt: resq 1
vtdgg_queue: resq 1
vtdgg_status: resq 1

vtdgg_contexts: resq PCIA_GRP_MAX
vtdgg_sources: resq PCIA_GRP_MAX     ; original per-member context table page
vtdgg_clones: resq PCIA_GRP_MAX      ; final per-member cloned bus page
vtdgg_identity: resb PCIA_GRP_BYTES
vtdgg_state: resb 1
vtdgg_completed: resb 1
vtdgg_released: resb 1              ; only C's verified final claim release sets 1
vtdgg_retired_mask: resb 1          ; actual per-member completion AND blocked readback
vtdgg_blocked_mask: resb 1          ; actual old-DID completion AND blocked readback
vtdgg_end:
%endmacro
WDATA_BSS_DEFER WDATA_hv_vtd_guest
