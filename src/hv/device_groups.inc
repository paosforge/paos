; RCQ-18: read-only, saved conservative native device-group inventory.
; Included in hv/vtd. Commands run serialized on the BSP, like VTD POLICY.
; Never consumed by assignment. No configuration data, MMIO, DMA or owner writes.
%include "core/abi/pci_claim.inc"
%include "core/abi/wdata.inc"
DG_MAX equ DA_SNAP_MAX
DG_PAGE equ 2
DG_NO_IOMMU equ 1
DG_NO_BACKEND equ 2
DG_NATIVE_INCOMPLETE equ 4
DG_SCAN_OVERFLOW equ 8
DG_TOPOLOGY_CHANGED equ 16
DG_DUPLICATE equ 32
DG_GROUP_UNKNOWN equ 64
DG_CONFIG_UNKNOWN equ 128
DG_SEGMENT_UNKNOWN equ 256
DG_S_UNKNOWN equ 64

%macro DG_PUT 1
    lea  rdi, [rel %1]
    call vtd_out_str
%endmacro

; Fresh scan callback. Reuse the original native snapshot's typed facts, but
; reconcile every BDF and bridge window against a new real PCI sweep. New or
; vanished functions are observable, not silently declared complete. DA_S_ACS
; is never synthesized: mechanism1 cannot prove extended ACS.
vtd_groups_scan_cb:
    push rbx
    push r12
    push r13
    mov  ebx, edi
    shl  ebx, 8
    shl  esi, 3
    or   ebx, esi
    or   ebx, edx
    inc  dword [rel dg_observed]
    mov  r12d, [rel dg_n]
    cmp  r12d, DG_MAX
    jae  .overflow
    lea  r13, [rel dg_snap]
    lea  r13, [r13 + r12*8]
    mov  qword [r13], 0
    mov  [r13], bx
    mov  edi, ebx
    call vtd_iso_snap_find
    test rax, rax
    jz   .new
    mov  rax, [rax]
    mov  [r13], rax
    jmp  .header
.new:
    or   dword [rel dg_issues], DG_TOPOLOGY_CHANGED
.header:
    mov  edi, ebx
    mov  esi, 0x0C
    call pci_bdf_read
    shr  eax, 16
    and  eax, 0x7F
    cmp  eax, 1
    je   .bridge
    test eax, eax
    jnz  .config_bad
    test byte [r13 + 2], DA_S_BRIDGE
    jz   .count
    and  byte [r13 + 2], ~DA_S_BRIDGE
    jmp  .changed
.bridge:
    test byte [r13 + 2], DA_S_BRIDGE
    jnz  .bridge_read
    or   dword [rel dg_issues], DG_TOPOLOGY_CHANGED
    or   byte [r13 + 2], DA_S_BRIDGE
.bridge_read:
    mov  edi, ebx
    mov  esi, 0x18
    call pci_bdf_read
    shr  eax, 8
    cmp  al, [r13 + 3]
    je   .secondary
    or   dword [rel dg_issues], DG_TOPOLOGY_CHANGED
.secondary:
    mov  [r13 + 3], al
    shr  eax, 8
    cmp  al, [r13 + 4]
    je   .subordinate
    or   dword [rel dg_issues], DG_TOPOLOGY_CHANGED
.subordinate:
    mov  [r13 + 4], al
    jmp  .count
.changed:
    or   dword [rel dg_issues], DG_TOPOLOGY_CHANGED
    jmp  .count
.config_bad:
    or   byte [r13 + 2], DG_S_UNKNOWN
    or   dword [rel dg_issues], DG_CONFIG_UNKNOWN
.count:
    inc  dword [rel dg_n]
    jmp  .out
.overflow:
    or   dword [rel dg_issues], DG_SCAN_OVERFLOW
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Read-only capture. vtd_iso_snapshot refreshes its usual working topology;
; last assignment verdict/record and all assignment/domain ownership stay intact.
vtd_groups_capture:
    push rbx
    push r12
    mov  dword [rel dg_n], 0
    mov  dword [rel dg_observed], 0
    mov  dword [rel dg_issues], 0
    mov  dword [rel dg_claim_issues], 0
    mov  byte [rel dg_claims_complete], 1
    mov  byte [rel dg_host], 0
    cmp  qword [rel vtd_unitb_base], 0
    jne  .iommu
    or   dword [rel dg_issues], DG_NO_IOMMU
    jmp  .backend
.iommu:
    or   byte [rel dg_host], DA_H_IOMMU
.backend:
    cmp  byte [rel vtd_ready], 1
    je   .ready
    or   dword [rel dg_issues], DG_NO_BACKEND
    jmp  .snapshot
.ready:
    or   byte [rel dg_host], DA_H_BACKEND
.snapshot:
    ; The native CF8 snapshot covers segment zero only. Other accepted MCFG
    ; segments, or corrupt bounded metadata, cannot silently disappear.
    mov  ecx, [rel acpi_mcfg_count]
    cmp  ecx, 4                         ; bus/acpi AF_MAX_MCFG
    ja   .segment_unknown
    lea  rdx, [rel acpi_mcfg_entries]
.mcfg:
    test ecx, ecx
    jz   .native_snapshot
    cmp  word [rdx + 8], 0
    jne  .segment_unknown
    add  rdx, 16
    dec  ecx
    jmp  .mcfg
.segment_unknown:
    or   dword [rel dg_issues], DG_SEGMENT_UNKNOWN
.native_snapshot:
    call vtd_iso_snapshot
    cmp  byte [rel vtd_iso_incomplete], 0
    je   .counts
    or   dword [rel dg_issues], DG_NATIVE_INCOMPLETE
.counts:
    mov  eax, [rel vtd_iso_snap_n]
    cmp  eax, [rel vtd_bdf_count]
    je   .duplicates
    or   dword [rel dg_issues], DG_TOPOLOGY_CHANGED
.duplicates:
    ; The original builder finds the first BDF; it cannot certify duplicate facts.
    xor  ebx, ebx
    lea  r12, [rel vtd_iso_snap]
.outer:
    cmp  ebx, [rel vtd_iso_snap_n]
    jae  .scan
    movzx edx, word [r12 + rbx*8]
    xor  ecx, ecx
.inner:
    cmp  ecx, ebx
    jae  .next
    cmp  dx, [r12 + rcx*8]
    je   .duplicate
    inc  ecx
    jmp  .inner
.duplicate:
    or   dword [rel dg_issues], DG_DUPLICATE
.next:
    inc  ebx
    jmp  .outer
.scan:
    lea  rdi, [rel vtd_groups_scan_cb]
    call pci_scan_with_filter
    mov  eax, [rel dg_observed]
    cmp  eax, [rel vtd_iso_snap_n]
    je   .claims
    or   dword [rel dg_issues], DG_TOPOLOGY_CHANGED
.claims:
    call vtd_groups_rmrr_check
    lea  rdi, [rel dg_claims]
    call pci_claim_snapshot
    mov  [rel dg_claim_n], eax
    mov  [rel dg_claim_issues], edx
    test edx, edx
    jz   .owner
    mov  byte [rel dg_claims_complete], 0
.owner:
    mov  al, [rel vtd_owner_guest]
    mov  [rel dg_guest], al
    mov  eax, [rel vtd_secondary_bdf]
    mov  [rel dg_guest_bdf], eax
    call vtd_groups_build
    inc  dword [rel dg_gen]
    jnz  .out
    inc  dword [rel dg_gen]              ; generation0 is never a saved capture
.out:
    pop  r12
    pop  rbx
    ret

; EAX=index -> EAX=root. Parents only decrease, bounded by DG_MAX.
vtd_groups_root:
    lea  rdx, [rel dg_parent]
.next:
    mov  ecx, [rdx + rax*4]
    cmp  eax, ecx
    je   .out
    mov  eax, ecx
    jmp  .next
.out:
    ret

; EDI/ESI=two indices. Merge actual shared-member identities, never counts.
vtd_groups_union:
    push rbx
    mov  eax, edi
    call vtd_groups_root
    mov  ebx, eax
    mov  eax, esi
    call vtd_groups_root
    cmp  eax, ebx
    jae  .ordered
    xchg eax, ebx
.ordered:
    lea  rdx, [rel dg_parent]
    mov  [rdx + rax*4], ebx
    pop  rbx
    ret

; EDI=BDF -> EAX=index or -1. Exact identity within the captured native list.
vtd_groups_find:
    xor  eax, eax
    lea  rdx, [rel dg_snap]
.next:
    cmp  eax, [rel dg_n]
    jae  .none
    cmp  di, [rdx + rax*8]
    je   .out
    inc  eax
    jmp  .next
.none:
    mov  eax, -1
.out:
    ret

; Original devassign rules produce every endpoint's view. Union overlapping
; explicit member BDFs conservatively. A builder refusal/overflow never creates
; a fake complete singleton. Unknown/orphan bridges remain visible too.
vtd_groups_build:
    push rbx
    push r12
    push r13
    xor  ebx, ebx
    lea  r12, [rel dg_snap]
.init:
    cmp  ebx, [rel dg_n]
    jae  .build_start
    lea  rax, [rel dg_parent]
    mov  [rax + rbx*4], ebx
    lea  rax, [rel dg_known]
    mov  byte [rax + rbx], 0
    lea  rax, [rel dg_flags]
    movzx ecx, byte [r12 + rbx*8 + 2]
    xor  edx, edx
    test cl, DA_S_PROTECTED
    jz   .rmrr
    or   dl, DA_F_PROTECTED
.rmrr:
    test cl, DA_S_RMRR
    jz   .flags
    or   dl, DA_F_RMRR
.flags:
    mov  [rax + rbx], dl
    lea  rax, [rel dg_verdict]
    mov  byte [rax + rbx], ISO_TRUNC_ACPI
    inc  ebx
    jmp  .init
.build_start:
    xor  ebx, ebx
.target:
    cmp  ebx, [rel dg_n]
    jae  .normalize
    test byte [r12 + rbx*8 + 2], DA_S_BRIDGE
    jnz  .next_target
    lea  rdi, [rel dg_record]
    mov  rsi, r12
    mov  edx, [rel dg_n]
    movzx ecx, word [r12 + rbx*8]
    movzx r8d, byte [rel dg_host]
    test dword [rel dg_issues], ~(DG_NO_IOMMU | DG_NO_BACKEND)
    jz   .facts
    or   r8d, DA_H_INCOMPLETE
.facts:
    call devassign_build_facts
    test eax, eax
    jnz  .failed
    lea  rdi, [rel dg_record]
    call devassign_classify
    lea  rdx, [rel dg_verdict]
    mov  [rdx + rbx], al
    lea  rdx, [rel dg_known]
    mov  byte [rdx + rbx], 1
    lea  rdx, [rel dg_flags]
    mov  al, [rel dg_record + 16 + 6]
    or   [rdx + rbx], al               ; inherited RMRR/alias from real builder
    xor  r13d, r13d
.member:
    movzx eax, byte [rel dg_record + 3]
    cmp  r13d, eax
    jae  .next_target
    lea  rdx, [rel dg_record + 16]
    cmp  byte [rdx + r13*8 + 7], 1
    jne  .next_member                 ; chain ancestor outside this group
    movzx edi, word [rdx + r13*8 + 2]
    rol  di, 8
    call vtd_groups_find
    cmp  eax, -1
    je   .member_missing
    mov  esi, eax
    lea  rdx, [rel dg_known]
    mov  byte [rdx + rax], 1
    mov  edi, ebx
    call vtd_groups_union
    jmp  .next_member
.member_missing:
    or   dword [rel dg_issues], DG_GROUP_UNKNOWN
.next_member:
    inc  r13d
    jmp  .member
.failed:
    lea  rdx, [rel dg_verdict]
    mov  [rdx + rbx], al
    or   dword [rel dg_issues], DG_GROUP_UNKNOWN
.next_target:
    inc  ebx
    jmp  .target
.normalize:
    xor  ebx, ebx
.norm:
    cmp  ebx, [rel dg_n]
    jae  .done
    lea  rdx, [rel dg_known]
    cmp  byte [rdx + rbx], 1
    je   .root
    or   dword [rel dg_issues], DG_GROUP_UNKNOWN
.root:
    mov  eax, ebx
    call vtd_groups_root
    lea  rdx, [rel dg_parent]
    mov  [rdx + rbx*4], eax
    call vtd_groups_claim_member
    inc  ebx
    jmp  .norm
.done:
    pop  r13
    pop  r12
    pop  rbx
    ret

; EBX=member. Exact bounded claim join; duplicate/invalid claims are unknown.
; No claim is unrecorded, never proof of absent native support. Guest custody
; is separately snapshotted; a historical BOUND record cannot override it.
vtd_groups_claim_member:
    lea  rax, [rel dg_claim_reason]
    mov  byte [rax + rbx], 0             ; unrecorded
    lea  rax, [rel dg_driver]
    mov  dword [rax + rbx*4], 0
    lea  rax, [rel dg_state]
    mov  dword [rax + rbx*4], 0
    lea  rax, [rel dg_snap]
    movzx r9d, word [rax + rbx*8]
    lea  r8, [rel dg_claims]
    mov  ecx, [rel dg_claim_n]
    xor  r10d, r10d
    xor  r11d, r11d
.loop:
    test ecx, ecx
    jz   .joined
    cmp  [r8], r9d
    jne  .next
    inc  r10d
    mov  r11, r8
.next:
    add  r8, 16
    dec  ecx
    jmp  .loop
.joined:
    cmp  r10d, 0
    je   .incomplete
    mov  esi, 2                         ; duplicate
    cmp  r10d, 1
    jne  .unknown
    mov  esi, 3                         ; invalid_count
    test dword [rel dg_claim_issues], 2 ; corrupt count cannot certify any claim
    jnz  .unknown
    mov  esi, 4                         ; invalid_driver
    mov  eax, [r11 + 4]
    cmp  eax, 1
    jb   .unknown
    cmp  eax, PCI_DRV_LAST
    ja   .unknown
    mov  esi, 5                         ; invalid_state
    mov  edx, [r11 + 8]
    cmp  edx, PCI_CLAIM_BOUND
    je   .store
    cmp  edx, PCI_CLAIM_FAILED
    jne  .unknown
.store:
    lea  r8, [rel dg_claim_reason]
    mov  byte [r8 + rbx], 1              ; recorded
    lea  r8, [rel dg_driver]
    mov  [r8 + rbx*4], eax
    lea  r8, [rel dg_state]
    mov  [r8 + rbx*4], edx
    cmp  dword [rel dg_claim_issues], 0
    jne  .incomplete
    ret
.unknown:
    lea  rax, [rel dg_claim_reason]
    mov  [rax + rbx], sil
    lea  rax, [rel dg_state]
    mov  dword [rax + rbx*4], 3
.incomplete:
    mov  byte [rel dg_claims_complete], 0
    ret

; Inventory-only group summary from explicit flags and original verdicts.
; EBX=member, no conclusion from member count. Never an assignment decision.
vtd_groups_reason:
    test dword [rel dg_issues], DG_NO_IOMMU
    jnz  .iommu
    test dword [rel dg_issues], DG_NO_BACKEND
    jnz  .backend
    cmp  dword [rel dg_issues], 0
    jne  .unknown
    lea  r8, [rel dg_parent]
    mov  r9d, [r8 + rbx*4]
    lea  r10, [rel dg_flags]
    lea  r11, [rel dg_verdict]
    xor  ecx, ecx
    xor  edx, edx
    xor  esi, esi
.next:
    cmp  ecx, [rel dg_n]
    jae  .flags
    cmp  [r8 + rcx*4], r9d
    jne  .advance
    or   dl, [r10 + rcx]
    cmp  byte [r11 + rcx], ISO_SHARED_DMA
    jne  .advance
    mov  esi, ISO_SHARED_DMA
.advance:
    inc  ecx
    jmp  .next
.flags:
    test dl, DA_F_RMRR
    jnz  .rmrr
    test dl, DA_F_PROTECTED
    jnz  .protected
    test dl, DA_F_ALIAS
    jnz  .alias
    mov  eax, esi
    ret
.iommu: mov eax, ISO_NO_IOMMU
    ret
.backend: mov eax, ISO_UNSUP_BACKEND
    ret
.unknown: mov eax, ISO_TRUNC_ACPI
    ret
.rmrr: mov eax, ISO_RMRR
    ret
.protected: mov eax, ISO_PROTECTED
    ret
.alias: mov eax, ISO_ALIAS
    ret

; Inventory-only completeness of the protected DMAR/RMRR facts. The original
; marker safely ignores an absent scope path; an inventory cannot call that
; complete. Check copied header/checksum/structure tails, then resolve every
; segment-zero RMRR PCI scope to an actually captured function. No live ACPI.
vtd_groups_rmrr_check:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  ecx, [rel vtd_dmar_snap_len]
    cmp  ecx, 48
    jb   .bad
    cmp  ecx, VTD_DMAR_SNAP_PAGES * 4096
    ja   .bad
    mov  r12, [rel vtd_dmar_snap]
    test r12, r12
    jz   .bad
    cmp  dword [r12], 'DMAR'
    jne  .bad
    cmp  [r12 + 4], ecx
    jne  .bad
    lea  r13, [r12 + rcx]
    xor  eax, eax
    xor  edx, edx
.checksum:
    add  al, [r12 + rdx]
    inc  edx
    loop .checksum
    test al, al
    jnz  .bad
    add  r12, 48
.structure:
    cmp  r12, r13
    je   .out
    lea  rax, [r12 + 4]
    cmp  rax, r13
    ja   .bad
    movzx r14d, word [r12 + 2]
    cmp  r14d, 8
    jb   .bad
    lea  rax, [r12 + r14]
    cmp  rax, r13
    ja   .bad
    cmp  word [r12], 0
    jne  .rmrr
    cmp  r14d, 16
    jb   .bad
    cmp  word [r12 + 6], 0
    je   .advance
    or   dword [rel dg_issues], DG_SEGMENT_UNKNOWN
    jmp  .advance
.rmrr:
    cmp  word [r12], 1
    jne  .advance
    cmp  r14d, 24
    jb   .bad
    cmp  word [r12 + 6], 0
    jne  .bad                         ; foreign segment is outside native view
    lea  r15, [r12 + 24]
.scope:
    lea  rax, [r12 + r14]
    cmp  r15, rax
    je   .advance
    lea  rdx, [r15 + 8]
    cmp  rdx, rax
    ja   .bad
    movzx ebx, byte [r15 + 1]
    cmp  ebx, 8
    jb   .bad
    cmp  ebx, 6 + 2 * DA_CHAIN_MAX
    ja   .bad
    test ebx, 1
    jnz  .bad
    lea  rdx, [r15 + rbx]
    cmp  rdx, rax
    ja   .bad
    cmp  word [r15 + 2], 0
    jne  .bad
    cmp  byte [r15 + 4], 0
    jne  .bad
    movzx eax, byte [r15]
    cmp  eax, 1
    je   .resolve
    cmp  eax, 2
    jne  .bad
.resolve:
    ; Validate each path pair and intermediate bridge against captured facts.
    ; The original resolver masks pairs and reads secondary bus; those reads
    ; alone cannot prove that a path hop really is a bridge.
    movzx r8d, byte [r15 + 5]
    mov  r9d, 6
.path:
    cmp  byte [r15 + r9], 31
    ja   .bad
    cmp  byte [r15 + r9 + 1], 7
    ja   .bad
    mov  edi, r8d
    shl  edi, 8
    movzx eax, byte [r15 + r9]
    shl  eax, 3
    or   edi, eax
    movzx eax, byte [r15 + r9 + 1]
    or   edi, eax
    call vtd_groups_find
    cmp  eax, -1
    je   .bad
    lea  rdx, [rel dg_snap]
    lea  rdx, [rdx + rax*8]
    add  r9d, 2
    cmp  r9d, ebx
    jae  .final_kind
    test byte [rdx + 2], DA_S_BRIDGE
    jz   .bad
    movzx r8d, byte [rdx + 3]
    test r8d, r8d
    jz   .bad
    cmp  r8b, [rdx + 4]
    ja   .bad
    jmp  .path
.final_kind:
    movzx eax, byte [rdx + 2]
    and  eax, DA_S_BRIDGE
    cmp  byte [r15], 2
    je   .final_bridge
    test eax, eax
    jnz  .bad
    jmp  .resolved
.final_bridge:
    test eax, eax
    jz   .bad
.resolved:
    mov  rdi, r15
    call vtd_iso_scope_bdf
    cmp  eax, -1
    je   .bad
    mov  edi, eax
    call vtd_groups_find
    cmp  eax, -1
    je   .bad
    add  r15, rbx
    jmp  .scope
.advance:
    add  r12, r14
    jmp  .structure
.bad:
    or   dword [rel dg_issues], DG_NATIVE_INCOMPLETE
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Strict unsigned decimal token, <=10 digits and UINT32_MAX. RDI advances to
; space/NUL; EDX=1 success, else0. No unbounded atoi or cursor multiplication.
vtd_groups_number:
    xor  eax, eax
    xor  ecx, ecx
.digit:
    movzx edx, byte [rdi]
    sub  edx, '0'
    cmp  edx, 9
    ja   .end
    cmp  ecx, 10
    jae  .bad
    cmp  eax, 429496729
    ja   .bad
    jne  .add
    cmp  edx, 5
    ja   .bad
.add:
    imul eax, eax, 10
    add  eax, edx
    inc  rdi
    inc  ecx
    jmp  .digit
.end:
    test ecx, ecx
    jz   .bad
    cmp  byte [rdi], 0
    je   .ok
    cmp  byte [rdi], ' '
    jne  .bad
.ok:
    mov  edx, 1
    ret
.bad:
    xor  edx, edx
    ret

; RDI="GROUPS [generation cursor]". Bare command refreshes once; pages use
; only the immutable saved dataset, including owner/claim facts. Stale pages
; refuse rather than joining a different capture. Existing VTD staging saves
; each readable page until consumed by its ordinary reply envelope.
vtd_groups_request:
    push rbx
    push r12
    add  rdi, 6
.spaces:
    cmp  byte [rdi], ' '
    jne  .args
    inc  rdi
    jmp  .spaces
.args:
    cmp  byte [rdi], 0
    jne  .generation
    call vtd_groups_capture
    xor  edi, edi
    call vtd_groups_render
    jmp  .out
.generation:
    call vtd_groups_number
    test edx, edx
    jz   .bad
    test eax, eax
    jz   .bad
    cmp  eax, [rel dg_gen]
    jne  .bad
    cmp  byte [rdi], ' '
    jne  .bad
.gap:
    cmp  byte [rdi], ' '
    jne  .cursor
    inc  rdi
    jmp  .gap
.cursor:
    call vtd_groups_number
    test edx, edx
    jz   .bad
    cmp  eax, [rel dg_n]
    ja   .bad
    mov  ebx, eax
.tail:
    cmp  byte [rdi], ' '
    jne  .end
    inc  rdi
    jmp  .tail
.end:
    cmp  byte [rdi], 0
    jne  .bad
    mov  edi, ebx
    call vtd_groups_render
    jmp  .out
.bad:
    call vtd_out_reset
    DG_PUT dg_s_error
.out:
    pop  r12
    pop  rbx
    ret

; EDI=packed BDF -> canonical segment-zero bb:dd.f. Never inferred from count.
vtd_groups_bdf:
    push rbx
    mov  ebx, edi
    DG_PUT dg_s_segment
    mov  edi, ebx
    shr  edi, 8
    call vtd_out_hex_byte
    DG_PUT dg_s_colon
    mov  edi, ebx
    shr  edi, 3
    and  edi, 31
    call vtd_out_hex_byte
    DG_PUT dg_s_dot
    mov  edi, ebx
    and  edi, 7
    call vtd_out_dec
    pop  rbx
    ret

; EDI=cursor -> max2 complete rows, <1200B (ordinary UDP envelope budget).
; Header complete means bounded native membership facts, never isolation or
; assignability. ACS is unknown and permission remains none even if eligible.
vtd_groups_render:
    push rbx
    push r12
    push r13
    mov  ebx, edi
    lea  r12d, [ebx + DG_PAGE]
    cmp  r12d, [rel dg_n]
    jbe  .limit
    mov  r12d, [rel dg_n]
.limit:
    call vtd_out_reset
    DG_PUT dg_s_head
    mov  edi, [rel dg_gen]
    call vtd_out_dec
    DG_PUT dg_s_cursor
    mov  edi, ebx
    call vtd_out_dec
    DG_PUT dg_s_next
    cmp  r12d, [rel dg_n]
    jae  .end_page
    mov  edi, r12d
    call vtd_out_dec
    jmp  .header
.end_page:
    DG_PUT dg_s_end
.header:
    DG_PUT dg_s_observed
    mov  edi, [rel dg_observed]
    call vtd_out_dec
    DG_PUT dg_s_retained
    mov  edi, [rel dg_n]
    call vtd_out_dec
    DG_PUT dg_s_complete
    xor  edi, edi
    cmp  dword [rel dg_issues], 0
    sete dil
    call vtd_out_dec
    DG_PUT dg_s_claims_complete
    movzx edi, byte [rel dg_claims_complete]
    call vtd_out_dec
    DG_PUT dg_s_claim_issues
    mov  edi, [rel dg_claim_issues]
    call vtd_out_dec
    DG_PUT dg_s_issues
    xor  r13d, r13d
.issue:
    cmp  r13d, 9
    jae  .rows
    mov  eax, [rel dg_issues]
    bt   eax, r13d
    jnc  .issue_next
    mov  eax, r13d
    imul eax, 24
    lea  rdi, [rel dg_issue_names]
    add  rdi, rax
    call vtd_out_str
.issue_next:
    inc  r13d
    jmp  .issue
.rows:
    DG_PUT dg_s_eol
.row:
    cmp  ebx, r12d
    jae  .out
    DG_PUT dg_s_group
    lea  rax, [rel dg_known]
    cmp  byte [rax + rbx], 1
    jne  .unknown_group
    lea  rax, [rel dg_parent]
    mov  eax, [rax + rbx*4]
    lea  rdx, [rel dg_snap]
    movzx edi, word [rdx + rax*8]
    call vtd_groups_bdf
    jmp  .member
.unknown_group:
    DG_PUT dg_s_unknown
.member:
    DG_PUT dg_s_member
    lea  r13, [rel dg_snap]
    lea  r13, [r13 + rbx*8]
    movzx edi, word [r13]
    call vtd_groups_bdf
    DG_PUT dg_s_kind
    test byte [r13 + 2], DG_S_UNKNOWN
    jnz  .kind_unknown
    test byte [r13 + 2], DA_S_BRIDGE
    jz   .endpoint
    DG_PUT dg_s_bridge
    jmp  .driver
.kind_unknown:
    DG_PUT dg_s_unknown
    jmp  .driver
.endpoint:
    DG_PUT dg_s_endpoint
.driver:
    DG_PUT dg_s_driver
    lea  rax, [rel dg_driver]
    mov  edi, [rax + rbx*4]
    test edi, edi
    jz   .driver_unknown
    call pci_claim_drv_name
    mov  rdi, rax
    call vtd_out_str
    jmp  .claim
.driver_unknown:
    DG_PUT dg_s_unknown
.claim:
    DG_PUT dg_s_claim
    lea  rax, [rel dg_state]
    mov  eax, [rax + rbx*4]
    lea  rdi, [rel dg_s_unrecorded]
    test eax, eax
    jz   .claim_emit
    lea  rdi, [rel dg_s_bound]
    cmp  eax, PCI_CLAIM_BOUND
    je   .claim_emit
    lea  rdi, [rel dg_s_failed]
    cmp  eax, PCI_CLAIM_FAILED
    je   .claim_emit
    lea  rdi, [rel dg_s_unknown]
.claim_emit:
    call vtd_out_str
    DG_PUT dg_s_owner
    cmp  byte [rel dg_guest], 1
    jne  .native
    movzx eax, word [r13]
    cmp  eax, [rel dg_guest_bdf]
    jne  .native
    DG_PUT dg_s_guest
    jmp  .protected
.native:
    lea  rax, [rel dg_state]
    cmp  dword [rax + rbx*4], PCI_CLAIM_BOUND
    jne  .owner_unknown
    DG_PUT dg_s_native_claim
    jmp  .protected
.owner_unknown:
    DG_PUT dg_s_unknown
.protected:
    DG_PUT dg_s_claim_reason
    lea  rax, [rel dg_claim_reason]
    movzx eax, byte [rax + rbx]
    imul eax, 16
    lea  rdi, [rel dg_claim_reason_names]
    add  rdi, rax
    call vtd_out_str
    DG_PUT dg_s_lifeline
    lea  rax, [rel dg_flags]
    movzx edi, byte [rax + rbx]
    shr  edi, 2
    and  edi, 1
    call vtd_out_dec
    DG_PUT dg_s_rmrr
    test dword [rel dg_issues], DG_NATIVE_INCOMPLETE | DG_TOPOLOGY_CHANGED | DG_CONFIG_UNKNOWN
    jnz  .rmrr_unknown
    lea  rax, [rel dg_flags]
    movzx edi, byte [rax + rbx]
    shr  edi, 1
    and  edi, 1
    call vtd_out_dec
    jmp  .reason
.rmrr_unknown:
    DG_PUT dg_s_unknown
.reason:
    DG_PUT dg_s_reason
    lea  rax, [rel dg_verdict]
    movzx eax, byte [rax + rbx]
    test byte [r13 + 2], DA_S_BRIDGE
    jnz  .bridge_reason
    cmp  eax, ISO_SEGMENT
    ja   .bridge_reason
    imul eax, VTD_ISO_NAME_STRIDE
    lea  rdi, [rel vtd_iso_reason_names]
    add  rdi, rax
    call vtd_out_str
    jmp  .row_end
.bridge_reason:
    DG_PUT dg_s_topology_only
.row_end:
    DG_PUT dg_s_group_reason
    call vtd_groups_reason
    imul eax, VTD_ISO_NAME_STRIDE
    lea  rdi, [rel vtd_iso_reason_names]
    add  rdi, rax
    call vtd_out_str
    DG_PUT dg_s_group_complete
    xor  edi, edi
    cmp  dword [rel dg_issues], 0
    sete dil
    call vtd_out_dec
    DG_PUT dg_s_eol
    inc  ebx
    jmp  .row
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

%macro WDATA_hv_groups 0
align 8
dg_gen: dd 0
dg_n: dd 0
dg_observed: dd 0
dg_issues: dd 0
dg_claim_n: dd 0
dg_claim_issues: dd 0
dg_guest_bdf: dd 0
dg_host: db 0
dg_claims_complete: db 0
dg_guest: db 0
align 8
dg_snap: times DG_MAX * DA_SNAP_SZ db 0
dg_parent: times DG_MAX dd 0
dg_known: times DG_MAX db 0
dg_flags: times DG_MAX db 0
dg_verdict: times DG_MAX db 0
dg_claim_reason: times DG_MAX db 0
align 4
dg_driver: times DG_MAX dd 0
dg_state: times DG_MAX dd 0
dg_claims: times 32 * 16 db 0
dg_record: times DA_REC_BYTES db 0
%endmacro
WDATA_DEFER WDATA_hv_groups

dg_s_keyword: db "GROUPS", 0
dg_s_head: db " VTD GROUPS read_only=1 assignment=none source=native_devassign acs=unknown gen=", 0
dg_s_cursor: db " cursor=", 0
dg_s_next: db " next=", 0
dg_s_end: db "end", 0
dg_s_observed: db " observed=", 0
dg_s_retained: db " retained=", 0
dg_s_complete: db " complete=", 0
dg_s_claims_complete: db " claims_complete=", 0
dg_s_issues: db " issues=", 0
dg_s_group: db " group=", 0
dg_s_member: db " member=", 0
dg_s_segment: db "0000:", 0
dg_s_colon: db ":", 0
dg_s_dot: db ".", 0
dg_s_kind: db " kind=", 0
dg_s_bridge: db "bridge", 0
dg_s_endpoint: db "endpoint", 0
dg_s_driver: db " driver=", 0
dg_s_claim: db " claim=", 0
dg_s_unrecorded: db "unrecorded", 0
dg_s_bound: db "bound", 0
dg_s_failed: db "failed", 0
dg_s_unknown: db "unknown", 0
dg_s_owner: db " owner=", 0
dg_s_guest: db "guest", 0
dg_s_native_claim: db "native-claim", 0
dg_s_lifeline: db " lifeline=", 0
dg_s_rmrr: db " rmrr=", 0
dg_s_reason: db " reason=", 0
dg_s_group_reason: db " group_reason=", 0
dg_s_group_complete: db " group_complete=", 0
dg_s_topology_only: db "topology_only", 0
dg_s_eol: db 13,10,0
dg_s_error: db " VTD GROUPS ERR usage=GROUPS_[generation_cursor] stale_or_invalid_page=1",13,10,0
dg_issue_names:
    db "no_iommu,",0
    times 14 db 0
    db "unsupported_backend,",0
    times 3 db 0
    db "native_incomplete,",0
    times 5 db 0
    db "scan_overflow,",0
    times 9 db 0
    db "topology_changed,",0
    times 6 db 0
    db "duplicate,",0
    times 13 db 0
    db "group_unknown,",0
    times 9 db 0
    db "config_unknown,",0
    times 8 db 0
    db "segment_unknown,",0
    times 7 db 0

dg_s_claim_issues: db " claim_issues=",0
dg_s_claim_reason: db " claim_reason=",0
dg_claim_reason_names:
    db "unrecorded",0
    times 5 db 0
    db "recorded",0
    times 7 db 0
    db "duplicate",0
    times 6 db 0
    db "invalid_count",0
    times 2 db 0
    db "invalid_driver",0
    times 1 db 0
    db "invalid_state",0
    times 2 db 0
