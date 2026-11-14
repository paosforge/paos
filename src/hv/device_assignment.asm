;; MODULE hv/device_assignment
;; LAYER 5
;; EXPORTS devassign_group_classify, devassign_classify, devassign_build_facts, iommu_isolation_topology_kat
;; IMPORTS boot/serial
;; CAPS
;; OWNER saga:device_assignment_portability
;;
;; Task3250 (device assignment I0): read-only PCIe/IOMMU isolation-topology
;; classifier. Given a bounded, in-memory topology fact record (IOMMU presence,
;; remap-backend support, ACPI completeness, and a flat device array carrying
;; segment/bus/devfn, parent bridge index, kind, DMA/RMRR/alias/protected flags,
;; and ACS isolation-group id), it returns ONE stable reason code for a target
;; device: eligible, or a fail-closed refusal (no-IOMMU, unsupported backend,
;; truncated ACPI, topology cycle, RMRR, alias ambiguity, protected-lifeline
;; peer, shared DMA requester, or segment confusion).
;;
;; READ-ONLY: this module inspects fact bytes only. It NEVER writes PCI config,
;; touches a BAR/command register, invalidates VT-d, attaches a domain, resets,
;; or reports final handoff — those are I1..I8. Isolation is not assignability;
;; eligible is a precondition, never a handoff.
;;
;; RCQ-19 S1 (root 2026-10-08 15:36): hv/vtd.asm calls this classifier as a
;; REFUSING precondition before it touches the function it would assign. It
;; snapshots the live functions (vtd_iso_snapshot) and devassign_build_facts
;; turns that snapshot into the fact record below: the target, its bridge chain
;; to a root bus, and every function that shares its isolation group.
;;
;; The QEMU content-KAT proves the classifier on synthetic hostile topology
;; fixtures (mirrors Task3470 storage_inventory_kat: pure classify fn over static
;; fixtures + a [PAOS64] ... KAT PASS [marker] line). The metal leg (DEVASSIGN
;; CHECK verb) later observes the live Lenovo topology; that is not this rung.

; ---- reason codes (eligible = 0; every refusal is a distinct nonzero code) ----
ISO_ELIGIBLE      equ 0
ISO_NO_IOMMU      equ 1
ISO_UNSUP_BACKEND equ 2
ISO_TRUNC_ACPI    equ 3
ISO_CYCLE         equ 4
ISO_RMRR          equ 5
ISO_ALIAS         equ 6
ISO_PROTECTED     equ 7
ISO_SHARED_DMA    equ 8
ISO_SEGMENT       equ 9

; ---- device fact flags / kinds ----
DA_F_DMA          equ 1        ; device is itself a DMA requester
DA_F_RMRR         equ 2        ; device has an ACPI RMRR reserved range
DA_F_PROTECTED    equ 4        ; device is a protected-role lifeline (target or peer)
DA_F_ALIAS        equ 8        ; device has an ambiguous multifunction/requester alias
DA_K_ENDPOINT     equ 0
DA_K_BRIDGE       equ 1
DA_ROOT           equ 0xFF     ; parent_idx sentinel: attached to host root

; ---- record layout ----
;   topology header (16 bytes):
;     +0 byte iommu_present   +1 byte backend_supported
;     +2 byte acpi_truncated  +3 byte n_dev   +4 byte target_idx   (+5..15 rsvd)
;   device record (8 bytes), array starts at topo+16:
;     +0 word segment  +2 byte bus  +3 byte devfn  +4 byte parent_idx
;     +5 byte kind     +6 byte flags +7 byte group (ACS isolation group id)

; devassign_classify(RDI = topology fact record) -> EAX = ISO_* reason code.
; Read-only: it reads the fact bytes and returns; it writes nothing anywhere.
; Fails closed — any ambiguity yields a refusal, never a false "eligible".
devassign_classify:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    movzx eax, byte [r12 + 0]        ; IOMMU must be present
    test al, al
    jz   .no_iommu
    movzx eax, byte [r12 + 1]        ; remap backend must be supported
    test al, al
    jz   .no_backend
    movzx eax, byte [r12 + 2]        ; ACPI facts must be complete
    test al, al
    jnz  .trunc
    movzx r13d, byte [r12 + 3]       ; n_dev
    movzx r14d, byte [r12 + 4]       ; target_idx
    lea  r15, [r12 + 16]             ; device-record array base
    mov  eax, r14d
    shl  eax, 3
    lea  rbx, [r15 + rax]            ; rbx = target record
    ; bounded parent-chain walk — a malformed parent index or a loop fails closed.
    mov  ecx, r14d                   ; cur idx
    xor  edx, edx                    ; steps taken
.cyc:
    mov  eax, ecx
    shl  eax, 3
    movzx eax, byte [r15 + rax + 4]  ; parent_idx of cur
    cmp  al, DA_ROOT
    je   .cyc_ok
    cmp  al, r13b                    ; parent must index a real device
    jae  .cycle
    movzx ecx, al
    inc  edx
    cmp  edx, r13d                   ; more hops than devices => a cycle
    ja   .cycle
    jmp  .cyc
.cyc_ok:
    movzx eax, byte [rbx + 6]        ; target's own facts
    test al, DA_F_RMRR
    jnz  .rmrr
    test al, DA_F_ALIAS
    jnz  .alias
    test al, DA_F_PROTECTED
    jnz  .protected                      ; the target itself may be a lifeline
    movzx r8d, byte [rbx + 7]        ; target isolation group
    movzx r9d, word [rbx + 0]        ; target segment
    xor  ecx, ecx
.grp:
    cmp  ecx, r13d
    jae  .eligible                   ; scanned every device, no unsafe peer
    cmp  ecx, r14d
    je   .grp_next                   ; skip the target itself
    mov  eax, ecx
    shl  eax, 3
    lea  r10, [r15 + rax]            ; peer record
    movzx eax, byte [r10 + 7]
    cmp  eax, r8d
    jne  .grp_next                   ; different isolation group
    movzx eax, word [r10 + 0]        ; same-group peer must share the segment
    cmp  eax, r9d
    jne  .segment
    movzx eax, byte [r10 + 6]        ; peer facts
    test al, DA_F_PROTECTED
    jnz  .protected                  ; a lifeline peer refuses first
    movzx esi, byte [r10 + 5]        ; peer kind
    cmp  esi, DA_K_BRIDGE
    jne  .peer_ep
    test al, DA_F_DMA
    jz   .grp_next                   ; a topology-only parent bridge is safe
    jmp  .shared
.peer_ep:
    test al, DA_F_DMA
    jnz  .shared                     ; an unrelated DMA requester breaks isolation
.grp_next:
    inc  ecx
    jmp  .grp
.eligible:   xor eax, eax
             jmp .out
.no_iommu:   mov eax, ISO_NO_IOMMU
             jmp .out
.no_backend: mov eax, ISO_UNSUP_BACKEND
             jmp .out
.trunc:      mov eax, ISO_TRUNC_ACPI
             jmp .out
.cycle:      mov eax, ISO_CYCLE
             jmp .out
.rmrr:       mov eax, ISO_RMRR
             jmp .out
.alias:      mov eax, ISO_ALIAS
             jmp .out
.protected:  mov eax, ISO_PROTECTED
             jmp .out
.shared:     mov eax, ISO_SHARED_DMA
             jmp .out
.segment:    mov eax, ISO_SEGMENT
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; W4c-2 A: shared-fact group classifier. This is additive: singleton
; devassign_classify and its ISO8 decision above remain byte-for-byte.
%include "hv/pcia_grp.inc"
; RDI bounded fact record -> EAX ISO_*. No config access or caller write.
; Class, original claims and reset scope are A's separate live prerequisites.
devassign_group_classify:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    cmp byte [r12], 1
    jne .iommu
    cmp byte [r12+1], 1
    jne .backend
    cmp byte [r12+2], 0
    jne .trunc
    movzx r13d, byte [r12+3]
    cmp r13d, 1
    jb .trunc
    cmp r13d, 32
    ja .trunc
    movzx eax, byte [r12+4]
    cmp eax, r13d
    jae .trunc
    lea r14, [r12+16]
    lea rax, [r14+rax*8]
    cmp byte [rax+5], DA_K_ENDPOINT
    jne .alias
    test byte [rax+6], DA_F_DMA
    jz .alias
    movzx r15d, byte [rax+7]
    xor ebx, ebx
    xor ebp, ebp
.member:
    cmp ebx, r13d
    jae .count
    lea r8, [r14+rbx*8]
    cmp byte [r8+7], r15b
    jne .next
    cmp word [r8], 0
    jne .segment
    test byte [r8+6], DA_F_RMRR
    jnz .rmrr
    test byte [r8+6], DA_F_ALIAS
    jnz .alias
    mov ecx, ebx
    xor edx, edx
.parent:
    movzx eax, byte [r14+rcx*8+4]
    cmp eax, DA_ROOT
    je .parent_ok
    cmp eax, r13d
    jae .cycle
    cmp byte [r14+rax*8+5], DA_K_BRIDGE
    jne .cycle
    mov ecx, eax
    inc edx
    cmp edx, r13d
    jae .cycle
    jmp .parent
.parent_ok:
    test byte [r8+6], DA_F_DMA
    jz .bridge
    cmp byte [r8+5], DA_K_ENDPOINT
    jne .alias
    test byte [r8+6], DA_F_PROTECTED
    jnz .claimed
    inc ebp
    cmp ebp, PCIA_GRP_MAX
    ja .overflow
    jmp .next
.bridge:
    cmp byte [r8+5], DA_K_BRIDGE
    jne .alias
.next:
    inc ebx
    jmp .member
.count:
    cmp ebp, 2
    jb .singleton
    xor eax, eax
    jmp .out
.iommu: mov eax, ISO_NO_IOMMU
    jmp .out
.backend: mov eax, ISO_UNSUP_BACKEND
    jmp .out
.trunc: mov eax, ISO_TRUNC_ACPI
    jmp .out
.cycle: mov eax, ISO_CYCLE
    jmp .out
.rmrr: mov eax, ISO_RMRR
    jmp .out
.alias: mov eax, ISO_ALIAS
    jmp .out
.segment: mov eax, ISO_SEGMENT
    jmp .out
.claimed: mov eax, ISO_GRP_CLAIMED
    jmp .out
.overflow: mov eax, ISO_GRP_OVERFLOW
    jmp .out
.singleton: mov eax, ISO_SHARED_DMA   ; route singleton through its old API
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; ---- live-topology snapshot (input to devassign_build_facts) ----
;   one 8-byte entry per present function:
;     +0 word bdf (bus<<8 | dev<<3 | fn)  +2 byte DA_S_* flags
;     +3 byte secondary bus  +4 byte subordinate bus (bridges only)  +5..7 rsvd
DA_SNAP_SZ        equ 8
DA_SNAP_MAX       equ 128      ; more live functions than this = incomplete facts
DA_REC_MAX        equ 32       ; fact-record device capacity (n_dev is one byte)
DA_REC_BYTES      equ 16 + DA_REC_MAX * 8
DA_CHAIN_MAX      equ 8        ; bridges between the target and a root bus
DA_RANGE_MAX      equ 24       ; bus windows that make up one isolation group
DA_S_BRIDGE       equ 1        ; type-1 header (has a secondary/subordinate window)
DA_S_PCIE         equ 2        ; has a PCI Express capability
DA_S_ACS          equ 4        ; ACS request/completion redirect proven on this port
DA_S_PROTECTED    equ 8        ; lifeline function (command NIC, boot storage, xHCI)
DA_S_RMRR         equ 16       ; named by an RMRR device scope (a bridge scope covers its window)
DA_S_PCI_BRIDGE   equ 32       ; PCIe<->PCI(-X) bridge: requesters below alias to it
DA_H_IOMMU        equ 1        ; header facts passed in R8D
DA_H_BACKEND      equ 2
DA_H_INCOMPLETE   equ 4

; RAX = snapshot index of a bridge: append its bus window to the group.
%macro DA_ADD_WINDOW 0
    movzx r10d, byte [rbp + 9]
    cmp  r10d, DA_RANGE_MAX
    jae  .trunc
    mov  r11b, [r13 + rax*8 + 3]
    mov  [rbp + 16 + r10*2], r11b
    mov  r11b, [r13 + rax*8 + 4]
    mov  [rbp + 17 + r10*2], r11b
    inc  byte [rbp + 9]
%endmacro

; Retain every emitted member's native reservation/requester scope facts.
; The old singleton already rejects DMA peers. Trusted/shared consumers also
; need these flags on nonselected bridges/endpoints, not only on the target.
; R13/RCX identify the original snapshot member; R8D accumulates DA_F_*.
%macro DA_MEMBER_SCOPE_FLAGS 0
    test byte [r13 + rcx*8 + 2], DA_S_RMRR
    jz %%bridge
    or   r8d, DA_F_RMRR
%%bridge:
    test byte [r13 + rcx*8 + 2], DA_S_BRIDGE
    jz %%done
    test byte [r13 + rcx*8 + 2], DA_S_PCIE
    jz %%alias
    test byte [r13 + rcx*8 + 2], DA_S_PCI_BRIDGE
    jz %%done
%%alias:
    or   r8d, DA_F_ALIAS
%%done:
%endmacro

; devassign_build_facts(RDI = record out [DA_REC_BYTES], RSI = snapshot,
;   EDX = entries, ECX = target bdf, R8D = DA_H_* facts) -> EAX = 0 when the
;   record is built (classify it next), else a builder refusal: ISO_TRUNC_ACPI
;   (target absent, too many functions or group members), ISO_CYCLE (two
;   bridges claim one bus, a window that does not contain the target, or a chain
;   deeper than DA_CHAIN_MAX), ISO_ALIAS (the target is itself a bridge).
; Group rule, fail-closed (never smaller than Linux's iommu_group):
;   - behind a bridge, everything inside the parent's window is in the group;
;   - a port without proven ACS widens the group to its own parent's window;
;     at the top of the chain (a root port) it adds its sibling functions and
;     their windows instead;
;   - a target on a root bus shares its group with its sibling functions.
; Every non-bridge member is a DMA requester (Bus Master can be enabled at any
; time); a member bridge is topology-only. A chain bridge without a PCIe
; capability, or a PCIe<->PCI bridge, aliases the target's requester ID. An RMRR
; on the target or on any chain bridge marks the target RMRR. Read-only.
devassign_build_facts:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 64                         ; [0..7] chain idx, [8] k, [9] windows,
    mov  rbp, rsp                        ; [10] sibling dev, [12] target idx, [16..] windows
    mov  r12, rdi
    mov  r13, rsi
    mov  r14d, edx
    movzx r15d, cx
    xor  eax, eax
    mov  [r12], rax
    mov  [r12 + 8], rax
    mov  eax, r8d
    and  eax, 1
    mov  [r12 + 0], al                   ; iommu_present
    mov  eax, r8d
    shr  eax, 1
    and  eax, 1
    mov  [r12 + 1], al                   ; backend_supported
    mov  eax, r8d
    shr  eax, 2
    and  eax, 1
    mov  [r12 + 2], al                   ; facts incomplete
    cmp  r14d, DA_SNAP_MAX
    ja   .trunc
    xor  ecx, ecx
.find:
    cmp  ecx, r14d
    jae  .trunc
    movzx eax, word [r13 + rcx*8]
    cmp  eax, r15d
    je   .found
    inc  ecx
    jmp  .find
.found:
    mov  [rbp + 12], ecx
    test byte [r13 + rcx*8 + 2], DA_S_BRIDGE
    jnz  .alias                          ; a bridge is never an assignable requester
    ; Chain: the unique bridge whose secondary bus is the current bus, upward.
    mov  byte [rbp + 8], 0
    mov  r9d, r15d
    shr  r9d, 8
.hop:
    mov  edx, -1
    xor  ecx, ecx
.hop_scan:
    cmp  ecx, r14d
    jae  .hop_scanned
    test byte [r13 + rcx*8 + 2], DA_S_BRIDGE
    jz   .hop_next
    movzx eax, byte [r13 + rcx*8 + 3]
    cmp  eax, r9d
    jne  .hop_next
    cmp  edx, -1
    jne  .cycle                          ; two bridges claim one bus
    mov  edx, ecx
.hop_next:
    inc  ecx
    jmp  .hop_scan
.hop_scanned:
    cmp  edx, -1
    je   .chain_done                     ; nobody claims it: a root bus
    movzx ecx, byte [rbp + 8]
    cmp  ecx, DA_CHAIN_MAX
    jae  .cycle
    mov  eax, r15d
    shr  eax, 8                          ; the target bus must sit inside the window
    movzx esi, byte [r13 + rdx*8 + 3]
    cmp  eax, esi
    jb   .cycle
    movzx esi, byte [r13 + rdx*8 + 4]
    cmp  eax, esi
    ja   .cycle
    movzx esi, word [r13 + rdx*8]
    shr  esi, 8                          ; the bridge's own bus
    cmp  esi, r9d
    je   .cycle                          ; a bridge on its own secondary bus
    mov  [rbp + rcx], dl
    inc  byte [rbp + 8]
    mov  r9d, esi
    jmp  .hop
.chain_done:
    ; Group windows.
    mov  byte [rbp + 9], 0
    mov  word [rbp + 10], 0xFFFF         ; sibling device (bus<<8 | dev<<3): none
    cmp  byte [rbp + 8], 0
    jne  .grp_port
    mov  eax, r15d
    and  eax, 0xFFF8
    mov  [rbp + 10], ax                  ; root-bus target: its sibling functions
    jmp  .grp_siblings
.grp_port:
    movzx eax, byte [rbp + 0]
    DA_ADD_WINDOW                        ; everything behind the parent port
    xor  ebx, ebx
.grp_up:
    movzx eax, byte [rbp + rbx]
    test byte [r13 + rax*8 + 2], DA_S_ACS
    jnz  .grp_done                       ; isolation proven at this port
    lea  edx, [rbx + 1]
    movzx ecx, byte [rbp + 8]
    cmp  edx, ecx
    jae  .grp_top
    movzx eax, byte [rbp + rdx]
    DA_ADD_WINDOW                        ; no ACS: the parent's whole window
    inc  ebx
    jmp  .grp_up
.grp_top:
    movzx eax, word [r13 + rax*8]
    and  eax, 0xFFF8
    mov  [rbp + 10], ax                  ; root port without ACS: its siblings
.grp_siblings:
    xor  ecx, ecx
.sib:
    cmp  ecx, r14d
    jae  .grp_done
    test byte [r13 + rcx*8 + 2], DA_S_BRIDGE
    jz   .sib_next
    movzx eax, word [r13 + rcx*8]
    and  eax, 0xFFF8
    cmp  ax, [rbp + 10]
    jne  .sib_next
    mov  eax, ecx
    DA_ADD_WINDOW                        ; and whatever sits behind a sibling port
.sib_next:
    inc  ecx
    jmp  .sib
.grp_done:
    ; Target flags: DMA and its own lifeline role, plus RMRR/alias from the chain.
    mov  ecx, [rbp + 12]
    mov  ebx, DA_F_DMA
    ; Preserve the selected function's own lifeline role, just as for peers.
    test byte [r13 + rcx*8 + 2], DA_S_PROTECTED
    jz   .t_reservations
    or   ebx, DA_F_PROTECTED
.t_reservations:
    test byte [r13 + rcx*8 + 2], DA_S_RMRR
    jz   .t_chain
    or   ebx, DA_F_RMRR
.t_chain:
    xor  edx, edx
.t_flags:
    movzx eax, byte [rbp + 8]
    cmp  edx, eax
    jae  .t_write
    movzx eax, byte [rbp + rdx]
    movzx eax, byte [r13 + rax*8 + 2]
    test al, DA_S_RMRR
    jz   .t_alias
    or   ebx, DA_F_RMRR                  ; a bridge-scope RMRR covers its window
.t_alias:
    test al, DA_S_PCIE
    jz   .t_aliased                      ; conventional PCI bridge
    test al, DA_S_PCI_BRIDGE
    jz   .t_next
.t_aliased:
    or   ebx, DA_F_ALIAS
.t_next:
    inc  edx
    jmp  .t_flags
.t_write:
    mov  ecx, [rbp + 12]
    movzx eax, word [r13 + rcx*8]
    mov  esi, DA_ROOT
    cmp  byte [rbp + 8], 0
    je   .t_put
    mov  esi, 1                          ; record 1 is the parent bridge
.t_put:
    mov  edx, DA_K_ENDPOINT
    mov  r8d, ebx
    mov  r9d, 1
    lea  rdi, [r12 + 16]
    call .put
    ; Records 1..k: the chain, each pointing at the next bridge up.
    xor  ebx, ebx
.c_put:
    movzx ecx, byte [rbp + 8]
    cmp  ebx, ecx
    jae  .peers
    movzx ecx, byte [rbp + rbx]
    xor  r8d, r8d
    test byte [r13 + rcx*8 + 2], DA_S_PROTECTED
    jz   .c_grp
    mov  r8d, DA_F_PROTECTED
.c_grp:
    DA_MEMBER_SCOPE_FLAGS
    mov  r9d, 1
    test ebx, ebx
    jz   .c_parent                       ; the parent port is a topology-only member
    movzx eax, word [r13 + rcx*8]
    call .in_group
    mov  r9d, 2
    test eax, eax
    jz   .c_parent
    mov  r9d, 1
.c_parent:
    lea  esi, [rbx + 2]
    lea  eax, [rbx + 1]
    movzx edx, byte [rbp + 8]
    cmp  eax, edx
    jb   .c_emit
    mov  esi, DA_ROOT
.c_emit:
    movzx eax, word [r13 + rcx*8]
    mov  edx, DA_K_BRIDGE
    lea  rdi, [r12 + 24 + rbx*8]
    call .put
    inc  ebx
    jmp  .c_put
.peers:
    ; Every other group member, in snapshot order.
    movzx ebx, byte [rbp + 8]
    inc  ebx
    xor  ecx, ecx
.p_scan:
    cmp  ecx, r14d
    jae  .p_done
    cmp  ecx, [rbp + 12]
    je   .p_next
    xor  edx, edx
.p_chain:
    movzx eax, byte [rbp + 8]
    cmp  edx, eax
    jae  .p_test
    movzx eax, byte [rbp + rdx]
    cmp  eax, ecx
    je   .p_next                         ; already a chain record
    inc  edx
    jmp  .p_chain
.p_test:
    movzx eax, word [r13 + rcx*8]
    call .in_group
    test eax, eax
    jz   .p_next
    cmp  ebx, DA_REC_MAX
    jae  .trunc
    xor  r8d, r8d
    mov  edx, DA_K_BRIDGE
    test byte [r13 + rcx*8 + 2], DA_S_BRIDGE
    jnz  .p_prot
    mov  edx, DA_K_ENDPOINT
    mov  r8d, DA_F_DMA
.p_prot:
    test byte [r13 + rcx*8 + 2], DA_S_PROTECTED
    jz   .p_emit
    or   r8d, DA_F_PROTECTED
.p_emit:
    DA_MEMBER_SCOPE_FLAGS
    movzx eax, word [r13 + rcx*8]
    mov  esi, DA_ROOT
    mov  r9d, 1
    lea  rdi, [r12 + 16 + rbx*8]
    call .put
    inc  ebx
.p_next:
    inc  ecx
    jmp  .p_scan
.p_done:
    mov  [r12 + 3], bl                   ; n_dev
    mov  byte [r12 + 4], 0               ; target_idx
    xor  eax, eax
    jmp  .done
.trunc:
    mov  eax, ISO_TRUNC_ACPI
    jmp  .done
.cycle:
    mov  eax, ISO_CYCLE
    jmp  .done
.alias:
    mov  eax, ISO_ALIAS
.done:
    add  rsp, 64
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; RDI = record slot: EAX = bdf, ESI = parent, EDX = kind, R8D = flags, R9D = group.
.put:
    mov  word [rdi], 0
    mov  [rdi + 3], al
    shr  eax, 8
    mov  [rdi + 2], al
    mov  [rdi + 4], sil
    mov  [rdi + 5], dl
    mov  [rdi + 6], r8b
    mov  [rdi + 7], r9b
    ret

; EAX = bdf -> EAX = 1 when it lies in a group window or is a listed sibling.
; Clobbers EDX, R10, R11 only.
.in_group:
    movzx edx, ah
    movzx r10d, byte [rbp + 9]
    xor  r11d, r11d
.ig_win:
    cmp  r11d, r10d
    jae  .ig_sib
    cmp  dl, [rbp + 16 + r11*2]
    jb   .ig_next
    cmp  dl, [rbp + 17 + r11*2]
    jbe  .ig_yes
.ig_next:
    inc  r11d
    jmp  .ig_win
.ig_sib:
    and  eax, 0xFFF8
    cmp  ax, [rbp + 10]
    je   .ig_yes
    xor  eax, eax
    ret
.ig_yes:
    mov  eax, 1
    ret

; iommu_isolation_topology_kat — content KAT over deterministic hostile fixtures.
; Every classification is asserted against its expected reason; only an all-pass
; emits the marker. The fixtures are static fact records (never live hardware),
; and a post-run sentinel proves the classifier mutated nothing.
iommu_isolation_topology_kat:
    push rbx
    ; positive: a lone isolated endpoint is eligible
    lea  rdi, [rel da_fx_isolated]
    call devassign_classify
    cmp  eax, ISO_ELIGIBLE
    jne  .fail
    ; positive: endpoint whose only group peer is a topology-only parent bridge
    lea  rdi, [rel da_fx_bridge_only]
    call devassign_classify
    cmp  eax, ISO_ELIGIBLE
    jne  .fail
    ; positive: isolated endpoint on a nonzero segment is still eligible
    lea  rdi, [rel da_fx_seg1]
    call devassign_classify
    cmp  eax, ISO_ELIGIBLE
    jne  .fail
    ; positive: Lenovo secondary RTL 0000:01:00.0 under a topology-only bridge
    lea  rdi, [rel da_fx_rtl]
    call devassign_classify
    cmp  eax, ISO_ELIGIBLE
    jne  .fail
    ; negative: the selected endpoint itself is a protected lifeline
    lea  rdi, [rel da_fx_protected_target]
    call devassign_classify
    cmp  eax, ISO_PROTECTED
    jne  .fail
    ; negative: unrelated DMA requester in the same group
    lea  rdi, [rel da_fx_shared]
    call devassign_classify
    cmp  eax, ISO_SHARED_DMA
    jne  .fail
    ; negative: ambiguous multifunction alias
    lea  rdi, [rel da_fx_alias]
    call devassign_classify
    cmp  eax, ISO_ALIAS
    jne  .fail
    ; negative: device carries an RMRR reserved range
    lea  rdi, [rel da_fx_rmrr]
    call devassign_classify
    cmp  eax, ISO_RMRR
    jne  .fail
    ; negative: no IOMMU at all
    lea  rdi, [rel da_fx_no_iommu]
    call devassign_classify
    cmp  eax, ISO_NO_IOMMU
    jne  .fail
    ; negative: IOMMU present but the remap backend is unsupported
    lea  rdi, [rel da_fx_no_backend]
    call devassign_classify
    cmp  eax, ISO_UNSUP_BACKEND
    jne  .fail
    ; negative: truncated ACPI facts
    lea  rdi, [rel da_fx_trunc]
    call devassign_classify
    cmp  eax, ISO_TRUNC_ACPI
    jne  .fail
    ; negative: parent-chain cycle
    lea  rdi, [rel da_fx_cycle]
    call devassign_classify
    cmp  eax, ISO_CYCLE
    jne  .fail
    ; negative: segment confusion within one group
    lea  rdi, [rel da_fx_segconf]
    call devassign_classify
    cmp  eax, ISO_SEGMENT
    jne  .fail
    ; negative: Lenovo onboard HDA 0000:00:1f.3 shares a protected lifeline closure
    lea  rdi, [rel da_fx_hda]
    call devassign_classify
    cmp  eax, ISO_PROTECTED
    jne  .fail
    ; zero-mutation sentinel: re-classify and prove the fixture bytes are intact
    lea  rdi, [rel da_fx_isolated]
    call devassign_classify
    cmp  eax, ISO_ELIGIBLE
    jne  .fail
    lea  rbx, [rel da_fx_isolated]
    cmp  byte [rbx + 16 + 6], 0      ; dev0 flags byte untouched by the read-only fn
    jne  .fail
    lea  rdi, [rel str_iso_topo_kat]
    call serial_string
.fail:
    pop  rbx
    ret

; ---- static hostile-topology fixtures (fact records, never live hardware) ----
%macro pcieiso_hdr 5
    db %1, %2, %3, %4, %5
    times 11 db 0
%endmacro
%macro pcieiso_dev 7
    dw %1
    db %2, %3, %4, %5, %6, %7
%endmacro

align 8
; lone isolated endpoint -> eligible
da_fx_isolated:
    pcieiso_hdr 1,1,0,1,0
    pcieiso_dev 0,0x00,0x10,DA_ROOT,DA_K_ENDPOINT,0,1
; endpoint + topology-only parent bridge in same group -> eligible
da_fx_bridge_only:
    pcieiso_hdr 1,1,0,2,1
    pcieiso_dev 0,0x00,0x08,DA_ROOT,DA_K_BRIDGE,0,5
    pcieiso_dev 0,0x01,0x00,0,DA_K_ENDPOINT,0,5
; isolated endpoint on nonzero segment -> eligible (must not reject seg!=0)
da_fx_seg1:
    pcieiso_hdr 1,1,0,1,0
    pcieiso_dev 1,0x00,0x10,DA_ROOT,DA_K_ENDPOINT,0,2
; Lenovo secondary RTL 01:00.0 (a DMA requester) under topology-only bridge -> eligible
da_fx_rtl:
    pcieiso_hdr 1,1,0,2,1
    pcieiso_dev 0,0x00,0x08,DA_ROOT,DA_K_BRIDGE,0,7
    pcieiso_dev 0,0x01,0x00,0,DA_K_ENDPOINT,DA_F_DMA,7
; selected protected endpoint -> refused (even with no same-group peers)
da_fx_protected_target:
    pcieiso_hdr 1,1,0,1,0
    pcieiso_dev 0,0x01,0x00,DA_ROOT,DA_K_ENDPOINT,DA_F_DMA|DA_F_PROTECTED,7
; unrelated DMA requester shares the group -> refused (shared DMA)
da_fx_shared:
    pcieiso_hdr 1,1,0,2,0
    pcieiso_dev 0,0x02,0x00,DA_ROOT,DA_K_ENDPOINT,0,3
    pcieiso_dev 0,0x02,0x01,DA_ROOT,DA_K_ENDPOINT,DA_F_DMA,3
; ambiguous multifunction alias -> refused
da_fx_alias:
    pcieiso_hdr 1,1,0,1,0
    pcieiso_dev 0,0x03,0x00,DA_ROOT,DA_K_ENDPOINT,DA_F_ALIAS,7
; RMRR reserved range -> refused
da_fx_rmrr:
    pcieiso_hdr 1,1,0,1,0
    pcieiso_dev 0,0x04,0x00,DA_ROOT,DA_K_ENDPOINT,DA_F_RMRR,8
; no IOMMU -> refused
da_fx_no_iommu:
    pcieiso_hdr 0,1,0,1,0
    pcieiso_dev 0,0x05,0x00,DA_ROOT,DA_K_ENDPOINT,0,1
; unsupported remap backend -> refused
da_fx_no_backend:
    pcieiso_hdr 1,0,0,1,0
    pcieiso_dev 0,0x05,0x00,DA_ROOT,DA_K_ENDPOINT,0,1
; truncated ACPI -> refused
da_fx_trunc:
    pcieiso_hdr 1,1,1,1,0
    pcieiso_dev 0,0x05,0x00,DA_ROOT,DA_K_ENDPOINT,0,1
; parent-chain cycle (dev0<->dev1) -> refused
da_fx_cycle:
    pcieiso_hdr 1,1,0,2,0
    pcieiso_dev 0,0x06,0x00,1,DA_K_ENDPOINT,0,4
    pcieiso_dev 0,0x06,0x08,0,DA_K_ENDPOINT,0,4
; segment confusion: same group spans two segments -> refused
da_fx_segconf:
    pcieiso_hdr 1,1,0,2,0
    pcieiso_dev 0,0x00,0x00,DA_ROOT,DA_K_ENDPOINT,0,6
    pcieiso_dev 1,0x00,0x00,DA_ROOT,DA_K_ENDPOINT,0,6
; Lenovo onboard HDA 00:1f.3 closure includes protected lifeline peers -> refused
da_fx_hda:
    pcieiso_hdr 1,1,0,3,0
    pcieiso_dev 0,0x00,0xFB,DA_ROOT,DA_K_ENDPOINT,DA_F_DMA,9
    pcieiso_dev 0,0x00,0xF8,DA_ROOT,DA_K_ENDPOINT,DA_F_PROTECTED|DA_F_DMA,9
    pcieiso_dev 0,0x00,0xF9,DA_ROOT,DA_K_BRIDGE,DA_F_PROTECTED,9

%unmacro pcieiso_hdr 5
%unmacro pcieiso_dev 7

str_iso_topo_kat: db "[PAOS64] iommu: isolation topology hostile-fixture KAT PASS [iommu.isolation.topology.kat]", 13, 10, 0
