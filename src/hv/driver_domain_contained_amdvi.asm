;; MODULE hv/driver_domain_contained_amdvi
;; LAYER 5
;; EXPORTS nd_contained_amdvi, nd_shape1_amdvi_ok
;; IMPORTS hv/driver_domain_contained, hv/nic_assignment, hv/amdvi_guest, hv/amdvi_hda, hv/amdvi, hv/vtd, bus/pci_bdf
;; CAPS extension
;; OWNER rc-amd-claude
;; CONTEXT: bsp_only
; ROOT110901/110935, SEC110926 (PREDICATE.md 2c8a68ea), AMD110907/110921/110930.
; The AMD-Vi counterparts of nd_contained's terminal predicates. Every value is
; read now: no receipt, no cached verdict, and no device, IOMMU, event-log,
; observer or allocator write. Callers are VM's nd_contained dispatch only.
;
; nd_contained_amdvi(RDI gen) -> EAX 0, or the first failed code. Reached by
; tail jump under amdvi_owned after VM's shape-1 dispatch (VM110945 (iii)).
; Shape 2 on AMD-Vi: the release poisoned the NIC BEFORE pcia_iommu_detach, so
; the backend still holds its exact LIVE DID 4 translation into the domain's
; own RAM. A detach/receipt failure leaves backend POISON with a BLOCKED DTE:
; that is not this shape and refuses at 6.
;   2-5 nd_contained_shared (VM): quarantine/terminal/released/gen, no live CPU,
;       leaf POISON at nd_bdf/gen, no other guest-owned function
;   6  backend is not this NIC's LIVE domain (state, BDF, generation, RAM, size)
;   7  not the installed mapping: attach final-flush custody missing or for
;      other fields, or the DTE / 3072-entry tree differs (amdvi_guest_tree_ok)
;   8  the image (including private ownership/custody metadata), a table page,
;      device table, arena (command/event/completion) or MMIO meets NIC RAM
;   9  ATS enabled or unread on the NIC
;   10 enforcement: unit registers (EN/CMDBUF/EVTLOG, bases, run, exclusion)
;      not exact, or an event is pending, overflowed or already counted
;   11 COMMAND has IO, MEM or BME set (a failed all-ones read has them set)
nd_contained_amdvi:
    push rbx
    push r12
    sub  rsp, 8
    mov  rbx, rdi
    call nd_contained_shared             ; codes 2-5, pure (VM)
    test eax, eax
    jnz  .out
    ; A held whole-group owner is another guest-owned assignment. AV's
    ; original backend remains the authority; its observer record is unused.
    call amdvg_held
    test eax,eax
    jnz .other_guest
    ; 6: the backend's LIVE domain is exactly this poisoned NIC's custody.
    mov  eax, 6
    cmp  byte [rel amdvi_guest_state], AMDVI_GUEST_LIVE
    jne  .out
    mov  ecx, [rel nica_bdf]
    cmp  ecx, [rel amdvi_guest_bdf]
    jne  .out
    cmp  rbx, [rel amdvi_guest_generation]
    jne  .out
    mov  rcx, [rel nica_ram]
    cmp  rcx, [rel amdvi_guest_host]
    jne  .out
    mov  rcx, [rel nica_bytes]
    test rcx, rcx
    jz   .out
    cmp  rcx, [rel amdvi_guest_size]
    jne  .out
    ; 7: the mapping the attach's completed flush installed, still in place.
    mov  eax, 7
    cmp  byte [rel amdvi_guest_custody], 1
    jne  .out
    mov  ecx, [rel amdvi_guest_bdf]
    cmp  ecx, [rel amdvi_guest_custody_bdf]
    jne  .out
    cmp  rbx, [rel amdvi_guest_custody_gen]
    jne  .out
    mov  rcx, [rel amdvi_guest_pages]
    cmp  rcx, [rel amdvi_guest_custody_root]
    jne  .out
    mov  rcx, [rel amdvi_guest_host]
    cmp  rcx, [rel amdvi_guest_custody_host]
    jne  .out
    mov  rcx, [rel amdvi_guest_size]
    cmp  rcx, [rel amdvi_guest_custody_size]
    jne  .out
    call amdvi_guest_tree_ok             ; pure: pool page, exact DTE, 3072 entries
    test eax, eax
    mov  eax, 7
    jz   .out
    ; 8: IOMMU metadata outside the guest's reach. The table pages need no own
    ; check: amdvi_guest_tree_ok has just bounded them inside the pool arena.
    ; Include all image bytes through deferred BSS, not only allocated tables:
    ; otherwise a consistent tree could expose the private custody record that
    ; supplies this predicate's own authority (SEC110926 item 2).
    lea  rdi, [rel code_start]
    mov  esi, wdata_bss_end - code_start
    call ndca_in_span
    test eax, eax
    jnz  .in_span
    mov  rdi, [rel amdvi_devtab]
    mov  esi, AMDVI_DEVTAB_BYTES
    call ndca_in_span
    test eax, eax
    jnz  .in_span
    mov  rdi, [rel amdvi_pool]
    mov  esi, AMDVI_POOL_BYTES
    call ndca_in_span
    test eax, eax
    jnz  .in_span
    mov  rdi, [rel amdvi_cmdbuf]
    mov  esi, 4096
    call ndca_in_span
    test eax, eax
    jnz  .in_span
    mov  rdi, [rel amdvi_evtlog]
    mov  esi, AMDVI_EVT_PAGES*4096
    call ndca_in_span
    test eax, eax
    jnz  .in_span
    mov  rdi, [rel amdvi_cw]
    mov  esi, 8
    call ndca_in_span
    test eax, eax
    jnz  .in_span
    mov  rax, [rel amdvi_mmio]
    test rax, rax
    jz   .in_span
    call amdvi_mmio_span                 ; reads EFR/IVHD only
    mov  esi, eax
    mov  rdi, [rel amdvi_mmio]
    call ndca_in_span
    test eax, eax
    jnz  .in_span
    ; 9: no address translation services on the NIC.
    mov  edi, [rel nica_bdf]
    call vtd_hda_ats_state               ; ECAM read; 0 absent, 1 disabled, 2 unread, 3 on
    cmp  eax, 1                          ; VTD_HDA_ATS_DISABLED, as amdvi_guest/amdvi_hda
    mov  eax, 9
    ja   .out
    ; 10: the owning unit enforces now, and no event is pending or counted.
    call ndca_enforcing_now
    test eax, eax
    mov  eax, 10
    jz   .out
    ; 11: the NIC can't master or decode.
    mov  edi, [rel nica_bdf]
    mov  esi, 4
    call pci_bdf_read
    mov  ecx, eax
    mov  eax, 11
    test ecx, 7                          ; IO, MEM, BME; a failed (all-ones) read has them set
    jnz  .out
    xor  eax, eax
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret
.other_guest:
    mov  eax, 5
    jmp  .out
.in_span:
    mov  eax, 8
    jmp  .out

; nd_shape1_amdvi_ok(EDI BDF, RSI gen) -> EAX 0, or 12. The AMD-only fresh reads
; for VM's shape-1 exit (SEC110926 shape 1, AMD110941): the guest backend has
; never been used this boot; the NIC is in no IVRS alias or IVMD range, so its own DTE is
; the only one its requests use; that DTE is exactly the canonical compat DID 1
; entry; and the
; unit enforces with no pending or counted event. Callee-saved preserved.
; A blocked DTE is refused: no original per-requester completed-invalidation
; witness exists for a blocked never-guest mapping (SEC110926). Exact bytes in
; RAM alone cannot prove what the unit cached. The covered compat form is the
; boot mapping whose full invalidation completed before amdvi_owned was set.
nd_shape1_amdvi_ok:
    push rbx
    push r12
    sub  rsp, 8
    mov  ebx, edi
    mov  r12, rsi
    cmp  byte [rel amdvi_owned], 1
    jne  .no
    test r12, r12
    jz   .no
    cmp  ebx, 0xffff
    ja   .no
    ; Backend unused this boot: amdvi_guest_reset runs only in ownership init,
    ; so state 0 with generation/pages 0 means no guest domain was ever built.
    ; LIVE, POISON and RETIRED all refuse (SEC110926: no guest POISON/RETIRED).
    cmp  byte [rel amdvi_guest_state], 0
    jne  .no
    cmp  qword [rel amdvi_guest_generation], 0
    jne  .no
    cmp  qword [rel amdvi_guest_pages], 0
    jne  .no
    ; AV's whole-group backend is independently retained. Require its entire
    ; private tuple unused too: even RETIRED/released history is not never-guest.
    lea  rdx,[rel amdvg_begin]
    mov  ecx,amdvg_end-amdvg_begin
.group_unused:
    cmp  byte [rdx],0
    jne  .no
    inc  rdx
    dec  ecx
    jnz  .group_unused
    mov  edi, ebx
    call amdvi_hda_scope                 ; pure: no alias, no IVMD range
    test eax, eax
    jz   .no
    mov  edi, ebx
    mov  rsi, [rel amdvi_compat_qw0]
    mov  ecx, AMDVI_DOM_COMPAT
    call amdvi_hda_dte_ok                ; pure exact four qwords
    test eax, eax
    jz   .no
.dte_ok:
    call ndca_enforcing_now
    test eax, eax
    jz   .no
    xor  eax, eax
    jmp  .out
.no:
    mov  eax, 12
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; Pure enforcement: amdvi_enforcing_regs, then a non-consuming event peek. A
; pending entry, overflow or already counted event refuses and stays for its
; real consumer (amdvi_event_check). -> EAX 1/0.
ndca_enforcing_now:
    sub  rsp, 8
    call amdvi_enforcing_regs
    add  rsp, 8
    test eax, eax
    jz   .no
    mov  rdx, [rel amdvi_mmio]
    ; Read complete offsets before comparing. Masking first could turn equal
    ; malformed/out-of-ring pointers (or unread high bits) into an empty log.
    mov  rax, [rdx + AMDVI_R_EVT_HEAD]
    mov  rcx, [rdx + AMDVI_R_EVT_TAIL]
    mov  r8, rax
    or   r8, rcx
    test r8b, 15
    jnz  .no
    cmp  rax, AMDVI_EVT_PAGES*4096
    jae  .no
    cmp  rcx, AMDVI_EVT_PAGES*4096
    jae  .no
    cmp  eax, ecx
    jne  .no
    test dword [rdx + AMDVI_R_STATUS], AMDVI_STS_EVT_OVF
    jnz  .no
    cmp  dword [rel amdvi_events], 0
    jne  .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; RDI base, ESI bytes -> EAX 1 when [base, base+bytes) meets the NIC's RAM span
; [nica_ram, nica_ram+nica_bytes), or either range overflows or is empty/null.
ndca_in_span:
    mov  eax, 1
    test rdi, rdi
    jz   .out
    mov  esi, esi
    test rsi, rsi
    jz   .out
    mov  rdx, rdi
    add  rdx, rsi
    jc   .out
    mov  rcx, [rel nica_ram]
    mov  r8, rcx
    add  r8, [rel nica_bytes]
    jc   .out
    cmp  rdx, rcx
    jbe  .clear
    cmp  rdi, r8
    jae  .clear
    ret
.clear:
    xor  eax, eax
.out:
    ret
