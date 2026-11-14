;; MODULE hv/vtd_guest
;; LAYER 5
;; EXPORTS vtd_guest_attach, vtd_guest_detach, vtd_guest_receipt
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
    jne .out
.check:
    mov rdx,rdi
    add rdx,rsi
    jc .yes
    cmp rdx,[rel vtdg_host]
    jbe .out
    mov rdx,[rel vtdg_host]
    add rdx,[rel vtdg_size]
    cmp rdi,rdx
    jae .out
.yes: mov eax,1
.out: ret


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
 jne .out
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
%endmacro
WDATA_BSS_DEFER WDATA_hv_vtd_guest
