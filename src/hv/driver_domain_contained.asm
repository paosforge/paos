;; MODULE hv/driver_domain_contained
;; LAYER 5
;; EXPORTS nd_contained, nd_contained_shared, nd_contained_power_ok
;; IMPORTS hv/driver_domain, hv/vmx, hv/nic_assignment, hv/vtd_guest, hv/vtd, hv/pci_assign, hv/amdvi, hv/driver_domain_contained_amdvi, hv/guest_power, core/memory_budget, bus/pci_bdf
;; CAPS extension
;; OWNER rc-vm-claude
;; CONTEXT: bsp_only
; ROOT109983 (3), SEC109985/109986, SEC110010 (B), SEC110926. Called by
; nd_quiesce on its quarantine exits and the dedicated fresh power helper. Its own module so that every harness that runs
; driver_domain_return.asm keeps one stub instead of the VT-d/NIC leaf state.
; SEC110010 shape 2: a quarantined domain whose NIC can't reach host memory
; before PLTRST. RDI = the generation nd_quiesce sampled. Everything is read now
; (no receipt or cached verdict); no device, IOMMU or allocator write.
; EAX 0 contained, else the first failed predicate:
;   1 no recognized enforcing IOMMU owner
;   2 not quarantined (state 6, terminal 1, released 0) or another generation
;   3 a CPU is live
;   4 the NIC is not this domain's poisoned device (state, BDF, generation)
;   5 another guest-owned function is live (DID 0x10, net mode, HDA/FLR)
;   6 the DID 17 domain is not this device's (state LIVE, generation, BDF, span)
;   7 the context entry read from the tables is not the exact LIVE DID 17 one
;   8 a DID 17 table page lies inside the DID 17 span (guest RAM)
;   9 ATS enabled or unread
;   10 GSTS.TES clear
;   11 COMMAND has BME, MEM or IO set, or the read failed
;   12 AMD shape-1 backend custody, compat DTE or enforcement refuses
;   13 shape-1 original/current custody or retained native tuple disagrees
;   14 shape-1 fresh disarm, identity, capability or reset topology refuses
;   15 shape-1 Intel backend has prior custody, fault or noncanonical host entry
%include "hv/pcia_grp.inc"

nd_contained:
    push rbx
    mov rbx,rdi
    call nd_contained_common
    test eax,eax
    jnz .out
    call pcia_grp_any_held
    test eax,eax
    jnz .group
    mov rdi,rbx
    call nd_contained_shared
    test eax,eax
    jnz .out
    ; Positive original refusal selects its own proof; never fallback from a
    ; failed shape-2 predicate. A partial/stale shape-1 tuple refuses there.
    cmp byte [rel nica_admission_first_custody],1
    jne .shape2
    cmp byte [rel nica_admission_pre_domain_refusal],1
    je .shape1
.shape2:
    mov eax,1
    cmp byte [rel amdvi_owned],0
    jne .amdvi
    cmp byte [rel vtd_enabled],1
    jne .out
    cmp qword [rel vtd_unitb_base],0
    je .out
    mov eax,6
    cmp byte [rel vtdg_state],VTDG_LIVE
    jne .out
    cmp rbx,[rel vtdg_generation]
    jne .out
    mov ecx,[rel nica_bdf]
    cmp ecx,[rel vtdg_bdf]
    jne .out
    mov rcx,[rel nica_ram]
    cmp rcx,[rel vtdg_host]
    jne .out
    mov rcx,[rel nica_bytes]
    cmp rcx,[rel vtdg_size]
    jne .out
    test rcx,rcx
    jz .out
    call vtdg_context_ok            ; root entry, context pointer, qword0 pages|P (TT 0), qword1 0x1102
    test eax,eax
    mov eax,7
    jz .out
    mov rdi,[rel vtdg_pages]
    mov esi,6*4096
    call vtdg_range_overlap
    test eax,eax
    jnz .in_span
    mov rdi,[rel vtdg_ctx]
    and rdi,-4096
    mov esi,4096
    call vtdg_range_overlap
    test eax,eax
    jnz .in_span
    mov rdi,[rel vtd_root]
    mov esi,4096
    call vtdg_range_overlap
    test eax,eax
    jnz .in_span
    mov edi,[rel nica_bdf]
    call vtd_hda_ats_state
    cmp eax,VTD_HDA_ATS_DISABLED     ; absent 0 or disabled 1; unread 2 / enabled 3 refuse
    mov eax,9
    ja .out
    mov rcx,[rel vtd_unitb_base]
    mov ecx,[rcx+VTD_REG_GSTS]
    test ecx,VTD_GSTS_TES
    mov eax,10
    jz .out
    mov edi,[rel nica_bdf]
    mov esi,4
    call pci_bdf_read
    mov ecx,eax
    mov eax,11
    cmp ecx,-1
    je .out
    test ecx,7                       ; IO, MEM, BME
    jnz .out
    xor eax,eax
.out:
    pop rbx
    ret
.in_span:
    mov eax,8
    jmp .out

.group:
    mov rdi,rbx
    pop rbx
    jmp nd_contained_group

.shape1:
    pop rbx
    jmp nd_contained_shape1

.amdvi:
    pop rbx                      ; tail handoff preserves RDI/gen and stack
    jmp nd_contained_amdvi

; Shared pure custody half, codes 2..5 (VM110945). No backend/device writes.
; RDI generation -> EAX 0 or first refusal. Callee-saved registers preserved.
nd_contained_common:
    push rbx
    mov rbx,rdi
    mov eax,2
    cmp dword [rel nd_state],6
    jne .out
    cmp dword [rel nd_terminal],1
    jne .out
    cmp dword [rel nd_released],0
    jne .out
    test rbx,rbx
    jz .out
    cmp rbx,[rel nd_generation]
    jne .out
    mov eax,3
    mov cl,[rel hv_linux_running]
    or cl,[rel hv_linux_start_active]
    or cl,[rel hv_linux_vmx_live]
    or cl,[rel hv_linux_run_req]
    jnz .out
    cmp qword [rel hv_svm_cur_vmcb],0
    jne .out
    xor eax,eax
.out:
    pop rbx
    ret

nd_contained_shared:
    push rbx
    mov rbx,rdi
    call nd_contained_common
    test eax,eax
    jnz .out
    mov eax,4
    cmp byte [rel nic_assignment_state],NICA_POISON
    jne .out
    mov ecx,[rel nica_bdf]
    cmp ecx,[rel nd_bdf]
    jne .out
    cmp rbx,[rel nica_gen]
    jne .out
    mov eax,5
    cmp byte [rel vtd_owner_guest],0
    jne .out
    cmp byte [rel vtd_network_mode],0
    jne .out
    cmp byte [rel pcia_state],0
    jne .out
    xor eax,eax
.out:
    pop rbx
    ret

; W4c-2 D: no singleton field or passive receipt grants group authority.
; Common terminal/CPU predicates already ran. RDI is the sampled nd START.
; The original A dispatch verifies immutable identity, every held reservation,
; the frozen native owner and the current B all-member mapping/quiet census.
; A failed group proof never falls back to the singleton terminal shapes.
nd_contained_group:
    push rbx
    mov rbx,rdi
    mov eax,5
    cmp byte [rel vtd_owner_guest],0
    jne .out
    cmp byte [rel vtd_network_mode],0
    jne .out
    cmp byte [rel pcia_state],0
    jne .out
    cmp byte [rel nic_assignment_state],0
    jne .out
    mov eax,4
    lea rdi,[rel pcia_grp]
    cmp rbx,[rdi+PG_GEN]
    jne .out
    mov ecx,[rel hv_linux_start_consumed]
    cmp rbx,rcx
    jne .out
    cmp byte [rdi+PG_COUNT],2
    jb .out
    cmp byte [rdi+PG_COUNT],PCIA_GRP_MAX
    ja .out
    movzx ecx,byte [rdi+PG_SEL]
    cmp cl,[rdi+PG_COUNT]
    jae .out
    shl ecx,4
    movzx ecx,word [rdi+rcx+PG_MEMBERS+PGM_BDF]
    cmp ecx,[rel nd_bdf]
    jne .out
    mov eax,6
    mov rcx,[rdi+PG_RAM]
    cmp rcx,[rel nd_ram]
    jne .out
    cmp rcx,[rel hv_linux_ram]
    jne .out
    mov rcx,[rdi+PG_BYTES]
    test rcx,rcx
    jz .out
    cmp rcx,[rel nd_ram_bytes]
    jne .out
    cmp rcx,[rel hv_linux_ram_bytes]
    jne .out
    call pcia_grp_live
    test eax,eax
    mov eax,7
    jnz .out
    xor eax,eax
.out:
    pop rbx
    ret

; SEC110926 / ROOT110935 / VM110945. Never-guest terminal alternative.
; Both authority bytes come from AV's actual first-custody pre-domain boundary,
; not NAA1 or this predicate. The immutable original attempt is 1; release may
; advance the last-reset counter. Current disarm and the original refusal must
; independently agree. No nica_attach_failed dependency (release consumes it).
; RDI=START -> EAX0 or13..15/12. Shared2..5 already ran. Pure, IF0 BSP only.
nd_contained_shape1:
    push rbx
    sub rsp,16
    mov rbx,rdi
    mov eax,13
    cmp byte [rel nica_admission_first_custody],1
    jne .out
    cmp byte [rel nica_admission_pre_domain_refusal],1
    jne .out
    cmp rbx,[rel nica_admission_start]
    jne .out
    mov ecx,[rel hv_linux_start_consumed]
    cmp rbx,rcx
    jne .out
    mov ecx,[rel nica_bdf]
    cmp ecx,[rel nica_admission_bdf]
    jne .out
    cmp dword [rel nica_admission_attempt],1
    jne .out
    cmp dword [rel nica_nics+48],0
    jne .out
    cmp byte [rel nica_admission_kind],0
    jne .out
    cmp dword [rel nica_admission_prepared],0
    jne .out
    cmp dword [rel nica_admission_failure],0
    jne .out
    cmp dword [rel nica_admission_result],0
    jne .out
    cmp dword [rel nica_admission_phase],9
    jne .out
    mov ecx,[rel nica_admission_command]
    and ecx,0x407
    cmp ecx,0x400
    jne .out
    cmp byte [rel nica_unproven_latch],0
    jne .out
    cmp byte [rel nica_reset_ok],0
    jne .out
    cmp dword [rel nica_method],2
    jne .out
    cmp dword [rel nica_reset_record],1
    jne .out
    cmp dword [rel nica_reset_record+4],64
    jne .out
    cmp dword [rel nica_reset_record+8],2
    jne .out
    cmp dword [rel nica_reset_record+12],0
    jne .out
    mov ecx,[rel nica_bdf]
    cmp ecx,[rel nica_reset_record+16]
    jne .out
    cmp rbx,[rel nica_reset_record+24]
    jne .out
    cmp dword [rel nica_reset_record+60],9
    jne .out
    mov ecx,[rel nica_reset_record+56]
    test ecx,ecx
    jz .out
    cmp ecx,[rel nica_reset_attempt]
    jne .out
    mov ecx,[rel nica_reset_record+52]
    and ecx,0x407
    cmp ecx,0x400
    jne .out
    ; Native geometry is still the capture that nd_prepare reserved. The
    ; terminal power wrapper separately resolves the actual allocator token.
    mov rcx,[rel nica_ram]
    test rcx,rcx
    jz .out
    cmp rcx,[rel nd_ram]
    jne .out
    cmp rcx,[rel hv_linux_ram]
    jne .out
    mov rcx,[rel nica_bytes]
    test rcx,rcx
    jz .out
    cmp rcx,[rel nd_ram_bytes]
    jne .out
    cmp rcx,[rel hv_linux_ram_bytes]
    jne .out
    call nd_shape1_disarmed
    test eax,eax
    mov eax,14
    jz .out
    cmp byte [rel amdvi_owned],0
    jne .amd
    mov eax,1
    cmp byte [rel vtd_enabled],1
    jne .out
    cmp qword [rel vtd_unitb_base],0
    je .out
    call nd_shape1_intel_ok
    jmp .out
.amd:
    mov edi,[rel nica_bdf]
    mov rsi,rbx
    call nd_shape1_amdvi_ok
.out:
    add rsp,16
    pop rbx
    ret

; A backend reset is boot initialization only. Require the complete unused
; tuple, not just state0: LIVE/POISON/RETIRED or any previous generation refuses.
; vtdg_enforcing reads actual RTADDR/TES/FSTS and sticky fault history; it does
; not consume or clear faults. Follow the actual root/context and require exact
; canonical DID1, TT0, including reserved/root high bits, not a masked match.
nd_shape1_intel_ok:
    push rbx
    call vtdg_enforcing
    test eax,eax
    mov eax,15
    jz .out
    cmp byte [rel vtdg_state],0
    jne .out
    mov rcx,[rel vtdg_generation]
    or rcx,[rel vtdg_pages]
    or rcx,[rel vtdg_ctx]
    or rcx,[rel vtdg_host]
    or rcx,[rel vtdg_size]
    jnz .out
    cmp dword [rel vtdg_bdf],0
    jne .out
    mov rdx,[rel vtd_root]
    test rdx,4095
    jnz .out
    mov ecx,[rel nica_bdf]
    shr ecx,8
    and ecx,0xff
    shl ecx,4
    add rdx,rcx
    mov rcx,[rdx]
    mov rbx,rcx
    and rbx,-4096
    or rbx,1
    cmp rcx,rbx
    jne .out
    cmp qword [rdx+8],0
    jne .out
    and rcx,-4096
    jz .out
    mov edx,[rel nica_bdf]
    and edx,0xff
    shl edx,4
    add rcx,rdx
    mov rdx,[rel vtd_id_pml4]
    test rdx,rdx
    jz .out
    test rdx,4095
    jnz .out
    or rdx,1
    cmp [rcx],rdx
    jne .out
    cmp qword [rcx+8],0x102
    jne .out
    xor eax,eax
.out:
    pop rbx
    ret

; Pure standard-capability walk. It checks the entire chain (including
; duplicate MSI/MSI-X/PCIe, cycles, alignment, bounds and unread payloads).
; MSI and MSI-X disabled (MSI-X function-mask may reset clear at SBR). No call to the writing
; nica_interrupts_off/nica_disable or the observation-writing group gate.
nd_shape1_disarmed:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,16
    mov r12d,[rel nica_bdf]
    mov edi,r12d
    mov esi,4
    call pci_bdf_read
    cmp eax,-1
    je .no
    mov ecx,eax
    and ecx,0x407
    cmp ecx,0x400
    jne .no
    test eax,1<<20                    ; Capability List supported
    jz .no
    ; Original immutable function identity, class/revision and subsystem ID.
    xor ebx,ebx
.identity:
    mov edi,r12d
    lea rdx,[rel nica_nics+64]
    lea rax,[rel nd_shape1_identity_offsets]
    mov esi,[rax+rbx*4]
    mov ecx,[rdx+rsi]
    mov [rsp],ecx
    call pci_bdf_read
    cmp eax,-1
    je .no
    cmp eax,[rsp]
    jne .no
    inc ebx
    cmp ebx,3
    jb .identity
    mov edi,r12d
    mov esi,0x0c
    call pci_bdf_read
    cmp eax,-1
    je .no
    xor eax,[rel nica_nics+64+0x0c]
    test eax,0xff0000                  ; exact header byte (incl multifunction)
    jnz .no
    mov edi,r12d
    call vtd_hda_ats_state
    cmp eax,VTD_HDA_ATS_DISABLED
    ja .no
    mov edi,r12d
    mov esi,0x34
    call pci_bdf_read
    cmp eax,-1
    je .no
    test eax,0xffffff00
    jnz .no
    movzx ebx,al
    xor r13d,r13d                     ; seen PCIe/MSI/MSI-X bits
    xor r14d,r14d                     ; visited dword positions
.cap:
    test ebx,ebx
    jz .end
    cmp ebx,0x40
    jb .no
    cmp ebx,0xfc
    ja .no
    test bl,3
    jnz .no
    mov ecx,ebx
    shr ecx,2
    bts r14,rcx
    jc .no
    mov edi,r12d
    mov esi,ebx
    call pci_bdf_read
    cmp eax,-1
    je .no
    mov r15d,eax
    shr r15d,8
    and r15d,0xff
    test al,al
    jz .no
    cmp al,0xff
    je .no
    cmp al,0x10
    je .pcie
    cmp al,5
    je .msi
    cmp al,0x11
    je .msix
    jmp .next
.pcie:
    bts r13d,0
    jc .no
    cmp ebx,[rel nica_cap]
    jne .no
    cmp ebx,0xf4
    ja .no
    mov edi,r12d
    lea esi,[rbx+4]
    call pci_bdf_read
    cmp eax,-1
    je .no
    test eax,1<<28                    ; this original SBR function is not FLR
    jnz .no
    mov edi,r12d
    lea esi,[rbx+8]
    call pci_bdf_read
    cmp eax,-1
    je .no
    test eax,(1<<21)|(1<<15)           ; TP or FLR initiate still set
    jnz .no
    jmp .next
.msi:
    bts r13d,1
    jc .no
    test eax,1<<16                    ; MSI Enable
    jnz .no
    mov ecx,eax
    shr ecx,17
    and ecx,7                         ; Multiple Message Capable
    cmp ecx,5
    ja .no
    mov edx,eax
    shr edx,20
    and edx,7                         ; Multiple Message Enable <= Capable
    cmp edx,ecx
    ja .no
    mov ecx,8                         ; last dword, 32-bit address/no mask
    test eax,1<<23                    ; 64-bit capable
    jz .msi_mask
    add ecx,4
.msi_mask:
    test eax,1<<24                    ; per-vector mask + pending registers
    jz .payload
    add ecx,8
    jmp .payload
.msix:
    bts r13d,2
    jc .no
    test eax,1<<31                    ; MSI-X Enable; disabled is sufficient
    jnz .no
    mov ecx,8                         ; complete Table + PBA descriptors
.payload:
    add ecx,ebx
    cmp ecx,0xfc
    ja .no
    mov [rsp+4],ecx
    mov [rsp+8],ebx
.payload_read:
    add dword [rsp+8],4
    mov ecx,[rsp+8]
    shr ecx,2
    bts r14,rcx
    jc .no
    mov edi,r12d
    mov esi,[rsp+8]
    call pci_bdf_read
    cmp eax,-1
    je .no
    mov ecx,[rsp+8]
    cmp ecx,[rsp+4]
    jb .payload_read
.next:
    mov ebx,r15d
    jmp .cap
.end:
    test r13d,1                       ; PCIe TP/reset proof must exist
    jz .no
    call nd_shape1_topology_ok
    jmp .out
.no:
    xor eax,eax
.out:
    add rsp,16
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Saved SBR admission was exactly one direct root bridge with secondary ==
; subordinate and no other function. Re-read that complete topology, compare
; original bridge identity tuple and control without publishing observations.
nd_shape1_topology_ok:
    push rbx
    push r12
    push r13
    sub rsp,16
    mov r12d,[rel nica_bdf]
    shr r12d,8
    and r12d,0xff
    jz .no
    xor r13d,r13d
    xor ebx,ebx
.bridge:
    mov edi,ebx
    xor esi,esi
    call pci_bdf_read
    cmp eax,-1
    je .next
    test ax,ax
    jz .no
    cmp ax,-1
    je .no
    mov edi,ebx
    mov esi,8
    call pci_bdf_read
    cmp eax,-1
    je .no
    shr eax,16
    cmp eax,0x0604
    jne .next
    mov edi,ebx
    mov esi,0x18
    call pci_bdf_read
    cmp eax,-1
    je .no
    mov ecx,eax
    shr ecx,8
    and ecx,0xff
    cmp r12d,ecx
    jb .next
    mov edx,eax
    shr edx,16
    and edx,0xff
    cmp r12d,edx
    ja .next
    cmp ecx,r12d
    jne .no
    cmp edx,r12d
    jne .no
    test al,al
    jnz .no
    cmp ebx,[rel nica_bridge]
    jne .no
    cmp eax,[rel nica_bridge_buses]
    jne .no
    cmp eax,[rel nica_reset_record+32]
    jne .no
    inc r13d
    cmp r13d,1
    jne .no
    mov edi,ebx
    mov esi,0x0c
    call pci_bdf_read
    cmp eax,-1
    je .no
    shr eax,16
    and eax,0x7f
    cmp eax,1
    jne .no
    mov edi,ebx
    mov esi,0x3c
    call pci_bdf_read
    cmp eax,-1
    je .no
    test eax,0x400000
    jnz .no
    and eax,~0x04000000               ; Bridge Control W1C status is not authority
    mov ecx,[rel nica_bridge_control]
    and ecx,~0x04000000
    cmp eax,ecx
    jne .no
.next:
    inc ebx
    cmp ebx,256
    jb .bridge
    cmp r13d,1
    jne .no
    xor ebx,ebx
.function:
    mov edi,r12d
    shl edi,8
    or edi,ebx
    mov [rsp],edi
    xor esi,esi
    call pci_bdf_read
    mov ecx,[rsp]
    cmp ecx,[rel nica_bdf]
    je .target
    cmp eax,-1
    jne .no
    jmp .function_next
.target:
    cmp eax,[rel nica_nics+64]
    jne .no
.function_next:
    inc ebx
    cmp ebx,256
    jb .function
    mov eax,1
    jmp .out
.no:
    xor eax,eax
.out:
    add rsp,16
    pop r13
    pop r12
    pop rbx
    ret

nd_shape1_identity_offsets: dd 0,8,0x2c

; VM110873/SEC110893. RDI=the caller's bound START. EAX=0 ready, else 1.
; EDX=0 for containment/START failure, or the failed ownership/census ordinal.
; Caller runs at IF0 and separately checks native APP VM + storage/controllers.
; No STOP, lifetime change, passive observation record, device/IOMMU write or
; cached authorization. mb_allocation_read uses its existing bounded try-lock
; and copies only to this stack frame; BUSY/unknown refuses, never retries.
; Unlike NIC DMA RAM, the allocation includes HV_LINUX_CTRL_BYTES before RAM.
; Bind the exact allocator prefix AND nd_prepare's captured native geometry.
nd_contained_power_ok:
    push rbx
    sub rsp,80
    mov rbx,rdi
    call nd_contained
    xor edx,edx
    test eax,eax
    jnz .refused
    mov eax,[rel hv_linux_start_consumed]
    cmp rax,rbx
    jne .refused
    ; Preserve the span from the authority route just proved above. The
    ; allocator snapshot is 64 bytes; these two private stack words survive it.
    call pcia_grp_any_held
    test eax,eax
    jz .singleton_span
    mov rax,[rel pcia_grp+PG_RAM]
    mov rcx,[rel pcia_grp+PG_BYTES]
    jmp .span
.singleton_span:
    mov rax,[rel nica_ram]
    mov rcx,[rel nica_bytes]
.span:
    mov [rsp+64],rax
    mov [rsp+72],rcx
    mov edi,MB_OWNER_HV_LINUX
    mov rsi,[rel hv_linux_mb_gen]
    mov rdx,[rel hv_linux_mb_token]
    mov rcx,rsp
    mov r8d,MB_ALLOCATION_BYTES   ; actual owner/gen/token/geometry
    call mb_allocation_read
    mov edx,16
    test eax,eax
    jnz .ownership_refused
    cmp qword [rsp+MB_REC_KIND],MB_KIND_GUEST
    jne .ownership_refused
    mov edx,17
    mov rax,[rel hv_linux_region]
    cmp rax,[rsp+MB_REC_BASE]
    jne .ownership_refused
    cmp rax,[rel nd_region]
    jne .ownership_refused
    add rax,HV_LINUX_CTRL_BYTES
    jc .ownership_refused
    cmp rax,[rel hv_linux_ram]
    jne .ownership_refused
    cmp rax,[rel nd_ram]
    jne .ownership_refused
    cmp rax,[rsp+64]
    jne .ownership_refused
    mov edx,18
    mov rax,[rel hv_linux_region_capacity]
    cmp rax,[rsp+MB_REC_BYTES]
    jne .ownership_refused
    cmp rax,[rel nd_capacity]
    jne .ownership_refused
    sub rax,HV_LINUX_CTRL_BYTES
    jc .ownership_refused
    mov rcx,[rsp+72]
    test rcx,rcx
    jz .ownership_refused
    cmp rax,rcx
    jb .ownership_refused
    cmp rcx,[rel hv_linux_ram_bytes]
    jne .ownership_refused
    cmp rcx,[rel nd_ram_bytes]
    jne .ownership_refused
    mov edx,19
    mov rax,[rel hv_linux_region_resident]
    cmp rax,[rsp+MB_REC_RESIDENT]
    jne .ownership_refused
    cmp rax,rcx
    jne .ownership_refused
    xor r10d,r10d                ; no failed ownership ordinal
    jmp .census
.ownership_refused:
    mov r10d,edx                 ; inject failure at its proper census position
.census:
    ; The shared scan reports earlier unrelated blockers before this failure.
    mov r11d,0x800f8000           ; private mode + exactly census bits 15..19
    add rsp,80
    pop rbx
    jmp hv_guest_power_s5_inactive.contained
.refused:
    mov eax,1
    add rsp,80
    pop rbx
    ret
