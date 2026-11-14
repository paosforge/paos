;; MODULE bus/acpi
%include "core/abi/build_profile.inc"
;; LAYER 2
;; EXPORTS acpi_ownership_snapshot, power_button_ownership_state, power_button_ownership_pm1, acpi_selftest, acpi_irqmap_report, acpi_irqmap_parse, acpi_irqmap_complete, acpi_irqmap_io, acpi_irqmap_io_count, acpi_find_table, acpi_dsdt_contains_pair, acpi_xsdt, acpi_madt, smp_selftest_after_acpi, acpi_table_state, acpi_table_present, acpi_root_state, acpi_apic_count, acpi_apic_ids, acpi_mcfg_count, acpi_mcfg_entries, acpi_fadt_revision, acpi_hpet_base, acpi_hpet_period, acpi_hpet_period_state, acpi_kat_ok, acpi_state_name, acpi_fixed_button_decode, acpi_fixed_button_init, acpi_fixed_button_poll, acpi_fixed_button_state, acpi_fixed_button_disarm, acpi_sci_prepare, acpi_sci_hold, acpi_sci_check, acpi_sci_release, acpi_sci_contain
;; IMPORTS bus/hest, core/mca_cmci, boot/serial, boot/header, boot/paging, core/lib/fmt, core/time
;; CAPS io
;; OWNER saga:bus
; AF0 / 3029. Port of the existing rev>=2/GUID/XSDT sequence and Classic
; drivers/acpi_pm table layouts. HPET period is CAP_ID[63:32], not a table field
; (recipes/timing_tsc_hpet). No AML or WDAT. The separate RCQ27 fixed-button
; observer acknowledges only qualified enabled PWRBTN_STS; it has no power policy.
;
; Every header and requested full extent need a retained UEFI RAM descriptor.
; A numerical identity-map limit alone does not prove a RAM address readable.
; Walk budgets: 256 config/XSDT entries, 64 KiB/table (DSDT only: 1 MiB), 1 MiB/lookup,
; 32 inventory APIC IDs, four MCFG allocations. Failure publishes no partial inventory.
; A fully validated >32-CPU MADT retains its pointer for SMP's bounded-prefix
; overflow path, with inventory state OVER_BUDGET/count=0 (never VALID/exact).
; Its full tail is checked for malformed/duplicate entries before returning;
; prior-entry rescans have a separate 1 MiB work ceiling, with no new storage.
; Unrequested bodies (including AML/vendor data) are never read or checksummed.
; ACPI SDTs may be unaligned: byte layouts are distinct from GAS/MMIO alignment.

EST_NUM_TABLES equ 104
EST_CFG_TABLE equ 112
CFG_ENTRY_SIZE equ 24
RSDP_REV equ 15
RSDP_XSDT_ADDR equ 24
ACPI_HDR_LEN equ 36
AF_MAX_TABLE equ 65536
; The DSDT has its own bound; no other table or readable-range/aggregate budget
; is expanded. Real captured DSDTs (gauntlet_v2/tests/fixtures/acpi_targets):
; HP 59,675 B, Dell 175,220 B, Beelink 668,308 B - the Beelink was refused at the
; former 256 KiB, so ACPI S5 fell back to ResetSystem(shutdown) there (RCQ-27
; slice 3/4). 1 MiB is ~1.5x the largest fleet DSDT. Cost of the larger bound: one
; byte-checksum pass and one linear _S5 scan over at most 1 MiB, both only on the
; S5/table-validation path; no new mapping (acpi_range still requires the whole
; table inside one RAM-type memory-map region of the existing identity map).
AF_MAX_DSDT equ 1048576
AF_MAX_ENTRIES equ 256
AF_MAX_APICS equ 32
AF_MADT_COMPARE_BYTES equ 1048576
AF_MAX_MCFG equ 4
AF_ABSENT equ 0
AF_VALID equ 1
AF_SIGNATURE equ 2
AF_CHECKSUM equ 3
AF_LENGTH equ 4
AF_BUDGET equ 5
AF_ADDRESS equ 6
AF_DUPLICATE equ 7
AF_ENTRY equ 8
AF_UNSUPPORTED equ 9

; RDI=start, RSI=length, EDX=0 RAM / 1 qualified HPET/MADT MMIO. CF=unreadable.
; Firmware map buffer/size/stride come from the owned EBS capture, not ACPI.
; RAM must have a covering descriptor. GetMemoryMap need not enumerate device
; MMIO (including OVMF's HPET). For mode 1 the unique, checksum-valid HPET GAS or MADT IOAPIC
; supplies the resource; the whole extent must fit our 16 GiB identity map and
; must not overlap RAM/unusable/other non-MMIO descriptors, even partially.
; A covering reserved/MMIO descriptor is accepted too. Only qualified HPET/SCI decoders and the exact-table-pinned HP S5 resource use
; mode 1, after GAS/MADT type/alignment checks; table reads always require mode 0.
; Fixture ranges are private, exact, and enabled only during the boot KAT.
acpi_range:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    test rsi, rsi
    jz   .bad
    add  r12, rsi
    jc   .bad
    cmp  qword [rel acpi_fixture_lo], 0
    je   .firmware
    cmp  rdi, [rel acpi_fixture_lo]
    jb   .bad
    cmp  r12, [rel acpi_fixture_hi]
    ja   .bad
    jmp  .ok
.firmware:
    cmp  rdi, 4096
    jb   .bad
    mov  rax, 0x400000000
    cmp  r12, rax
    ja   .bad
    mov  rbx, [rel mmap_buffer]
    test rbx, rbx
    jz   .bad
    mov  r13, [rel mmap_size]
    test r13, r13
    jz   .bad
    cmp  r13, 65536
    ja   .bad
    add  r13, rbx
    jc   .bad
    cmp  r13, rax
    ja   .bad
    mov  rcx, [rel mmap_desc_size]
    cmp  rcx, 40
    jb   .bad
    cmp  rcx, 256
    ja   .bad
    ; Reject a partial descriptor before an early RAM match can hide it.
    mov  rax, [rel mmap_size]
    push rdx
    xor  edx, edx
    div  rcx
    test rdx, rdx
    pop  rdx
    jnz  .bad
.next:
    mov  rax, r13
    sub  rax, rbx
    cmp  rax, rcx
    jb   .map_end
    mov  r8, [rbx + 8]
    test r8d, 4095                     ; UEFI physical descriptors are pages
    jnz  .bad
    mov  r9, [rbx + 24]
    mov  rax, r9
    shr  rax, 52
    jnz  .bad
    shl  r9, 12
    add  r9, r8
    jc   .bad
    cmp  r12, r8
    jbe  .skip
    cmp  rdi, r9
    jae  .skip
    ; Intersecting descriptor: MMIO must never alias owned RAM or an invalid
    ; region. Check every intersection, including descriptors starting inside
    ; the requested extent (a start-address-only test would miss those).
    mov  eax, [rbx]
    test edx, edx
    jnz  .mmio_type
    cmp  eax, 1
    jb   .skip
    cmp  eax, 10
    ja   .skip
    cmp  eax, 8                         ; EfiUnusableMemory
    je   .skip
    jmp  .extent
.mmio_type:
    test eax, eax                       ; firmware-reserved or EfiMMIO
    jz   .extent
    cmp  eax, 11
    jne  .bad
.extent:
    cmp  rdi, r8
    jb   .bad
    cmp  r12, r9
    ja   .bad
    test edx, edx
    jz   .ok
.skip:
    add  rbx, rcx
    jmp  .next
.map_end:
    ; Only a validated device GAS can authorize MMIO absent from GetMemoryMap.
    ; An unreported SDT/RSDP/config pointer remains a hard refusal.
    test edx, edx
    jz   .bad
.ok:
    clc
    jmp  .out
.bad:
    stc
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=already range-checked bytes, ECX=count>0 -> AL=8-bit checksum.
acpi_checksum:
    xor  eax, eax
.loop:
    add  al, [rdi]
    inc  rdi
    dec  ecx
    jnz  .loop
    ret

; RDI=SDT, ESI=expected signature (0 accepts printable unknown signatures).
; EAX=state, ECX=validated length. No data is consumed before range validation.
acpi_validate_sdt:
    push rbx
    push r12
    mov  rbx, rdi
    mov  r12d, esi
    mov  esi, ACPI_HDR_LEN
    xor  edx, edx
    call acpi_range
    jc   .address
    mov  eax, [rbx]
    test r12d, r12d
    jz   .printable
    cmp  eax, r12d
    jne  .signature
.printable:
    mov  ecx, 4
.sig_byte:
    cmp  al, 0x20
    jb   .signature
    cmp  al, 0x7e
    ja   .signature
    shr  eax, 8
    loop .sig_byte
    mov  r12d, [rbx + 4]
    cmp  r12d, ACPI_HDR_LEN
    jb   .length
    mov  ecx, AF_MAX_TABLE
    cmp  dword [rbx], 'DSDT'
    jne  .table_limit
    mov  ecx, AF_MAX_DSDT
.table_limit:
    cmp  r12d, ecx
    ja   .budget
    mov  rdi, rbx
    mov  esi, r12d
    xor  edx, edx
    call acpi_range
    jc   .address
    mov  rdi, rbx
    mov  ecx, r12d
    call acpi_checksum
    test al, al
    jnz  .checksum
    mov  eax, AF_VALID
    mov  ecx, r12d
    jmp  .out
.signature:
    mov  eax, AF_SIGNATURE
    jmp  .out
.checksum:
    mov  eax, AF_CHECKSUM
    jmp  .out
.length:
    mov  eax, AF_LENGTH
    jmp  .out
.budget:
    mov  eax, AF_BUDGET
    jmp  .out
.address:
    mov  eax, AF_ADDRESS
.out:
    pop  r12
    pop  rbx
    ret

; EDI=signature -> RAX=unique valid SDT or 0, EDX=state, ECX=present.
; Validates the cached root again, then visits every child (duplicates cannot
; hide behind an early first-match return). Validate each header's address and
; signature, then validate/checksum only matching bodies. Lenovo's archived
; LUFT is 216258 bytes: spending the 64 KiB budget on that unrelated vendor
; table made all four AF0 measurements OVER_BUDGET. Unknown bodies have no
; bearing on the requested table's validity and must not consume its budget.
acpi_find_table:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 32
    mov  r12d, edi
    mov  qword [rsp], 0                  ; candidate pointer
    mov  dword [rsp + 8], AF_ABSENT       ; first child error
    mov  dword [rsp + 12], 0             ; matching headers, including invalid
    mov  dword [rsp + 16], 0x100000      ; aggregate checksum budget
    mov  r13, [rel acpi_xsdt]
    test r13, r13
    jnz  .root
    movzx edx, byte [rel acpi_root_state]
    jmp  .none
.root:
    mov  rdi, r13
    mov  esi, 'XSDT'
    call acpi_validate_sdt
    cmp  eax, AF_VALID
    jne  .root_bad
    sub  ecx, ACPI_HDR_LEN
    test ecx, 7
    jnz  .root_length
    shr  ecx, 3
    cmp  ecx, AF_MAX_ENTRIES
    ja   .root_budget
    mov  r14d, ecx
    xor  ebx, ebx
.walk:
    cmp  ebx, r14d
    jae  .done
    mov  rbp, [r13 + ACPI_HDR_LEN + rbx*8]
    mov  rdi, rbp
    mov  esi, ACPI_HDR_LEN
    xor  edx, edx
    call acpi_range
    jc   .child_address
    ; A corrupt/unreadable signature can conceal another requested instance,
    ; so header failures still refuse the lookup. Nonmatching bodies cannot.
    mov  eax, [rbp]
    mov  ecx, 4
.child_signature_byte:
    cmp  al, 0x20
    jb   .child_signature
    cmp  al, 0x7e
    ja   .child_signature
    shr  eax, 8
    loop .child_signature_byte
    cmp  [rbp], r12d
    jne  .next
    inc  dword [rsp + 12]
.extent:
    mov  eax, [rbp + 4]
    mov  ecx, AF_MAX_TABLE
    cmp  dword [rbp], 'DSDT'
    jne  .child_limit
    mov  ecx, AF_MAX_DSDT
.child_limit:
    cmp  eax, ecx
    ja   .child_budget
    cmp  eax, [rsp + 16]
    ja   .child_budget
    sub  [rsp + 16], eax
    mov  rdi, rbp
    xor  esi, esi
    call acpi_validate_sdt
    cmp  eax, AF_VALID
    jne  .child_bad
    cmp  [rbp], r12d
    jne  .next
    mov  [rsp], rbp
    jmp  .next
.child_address:
    mov  eax, AF_ADDRESS
    jmp  .child_bad
.child_signature:
    mov  eax, AF_SIGNATURE
    jmp  .child_bad
.child_budget:
    mov  eax, AF_BUDGET
.child_bad:
    cmp  dword [rsp + 8], AF_ABSENT
    jne  .next
    mov  [rsp + 8], eax
.next:
    inc  ebx
    jmp  .walk
.done:
    mov  edx, AF_DUPLICATE
    cmp  dword [rsp + 12], 1
    ja   .none
    mov  edx, [rsp + 8]
    cmp  edx, AF_ABSENT
    jne  .none
    mov  rax, [rsp]
    test rax, rax
    jz   .none
    mov  edx, AF_VALID
    jmp  .return
.root_length:
    mov  eax, AF_LENGTH
    jmp  .root_bad
.root_budget:
    mov  eax, AF_BUDGET
.root_bad:
    mov  edx, eax
.none:
    ; A null cache can never earn VALID, even if a stale root-state byte says
    ; otherwise (e.g. between clearing a fixture and live rediscovery).
    cmp  edx, AF_VALID
    jne  .refused
    mov  edx, AF_ADDRESS
.refused:
    xor  eax, eax
.return:
    xor  ecx, ecx
    cmp  dword [rsp + 12], 0
    setne cl
    add  rsp, 32
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Clear only AF0's inventory. Task1274's watchdog state is never touched.
acpi_inventory_clear:
    lea  rdi, [rel acpi_inventory]
    mov  ecx, acpi_inventory_end - acpi_inventory
    xor  eax, eax
    rep  stosb
    ret

; Collect the four tables via the exported lookup and parse only full valid
; extents. Local APIC + x2APIC entry layouts match core/smp's proven parser;
; retain firmware order/full 32-bit IDs, only flags.enabled rows.
acpi_collect:
    push rbx
    push r12
    push r13
    call acpi_inventory_clear
    xor  ebx, ebx
.table:
    lea  rax, [rel acpi_signatures]
    mov  edi, [rax + rbx*4]
    call acpi_find_table
    lea  rsi, [rel acpi_table_state]
    mov  [rsi + rbx], dl
    lea  rsi, [rel acpi_table_present]
    mov  [rsi + rbx], cl
    lea  rsi, [rel acpi_table_ptrs]
    mov  [rsi + rbx*8], rax
    cmp  edx, AF_VALID
    jne  .next_table
    mov  r12, rax
    mov  r13d, [rax + 4]
    add  r13, rax
    test ebx, ebx
    jz   .madt
    cmp  ebx, 1
    je   .mcfg
    cmp  ebx, 2
    je   .fadt
    jmp  .hpet
.madt:
    cmp  dword [r12 + 4], 44
    jb   .short
    mov  r8d, AF_MADT_COMPARE_BYTES
    add  r12, 44
.madt_next:
    cmp  r12, r13
    je   .madt_done
    mov  rax, r13
    sub  rax, r12
    cmp  rax, 2
    jb   .entry_bad
    movzx ecx, byte [r12 + 1]
    cmp  ecx, 2
    jb   .entry_bad
    cmp  rcx, rax
    ja   .entry_bad
    cmp  byte [r12], 0
    je   .lapic
    cmp  byte [r12], 9
    jne  .madt_advance
    cmp  ecx, 16
    jb   .entry_bad
    test dword [r12 + 8], 1
    jz   .madt_advance
    mov  eax, [r12 + 4]
    jmp  .apic_add
.lapic:
    cmp  ecx, 8
    jb   .entry_bad
    test dword [r12 + 4], 1
    jz   .madt_advance
    movzx eax, byte [r12 + 3]
.apic_add:
    lea  rdi, [rel acpi_apic_ids]
    xor  edx, edx
.apic_duplicate:
    cmp  edx, [rel acpi_apic_count]
    jae  .apic_store
    cmp  eax, [rdi + rdx*4]
    je   .duplicate
    inc  edx
    jmp  .apic_duplicate
.apic_store:
    cmp  edx, AF_MAX_APICS
    jae  .apic_overflow
    mov  [rdi + rdx*4], eax
    inc  dword [rel acpi_apic_count]
    jmp  .madt_advance
.apic_overflow:
    ; Inventory capacity is not table invalidity. Keep scanning the complete
    ; checksum/range-validated table so a hostile tail cannot be admitted just
    ; because core/smp itself stops at enabled unique row 33. The first 32 IDs
    ; remain private until .madt_done clears their observable count.
    mov  byte [rel acpi_table_state], AF_BUDGET
    mov  r9, [rel acpi_madt]
    add  r9, 44
.apic_prior:
    cmp  r9, r12
    jae  .madt_advance
    ; Every prior row passed the main structural checks. Charge its full
    ; extent even when disabled/unknown, preventing unbounded quadratic work.
    movzx r10d, byte [r9 + 1]
    sub  r8d, r10d
    jc   .budget
    cmp  byte [r9], 0
    je   .apic_prior_lapic
    cmp  byte [r9], 9
    jne  .apic_prior_next
    test dword [r9 + 8], 1
    jz   .apic_prior_next
    mov  r11d, [r9 + 4]
    jmp  .apic_prior_compare
.apic_prior_lapic:
    test dword [r9 + 4], 1
    jz   .apic_prior_next
    movzx r11d, byte [r9 + 3]
.apic_prior_compare:
    cmp  eax, r11d
    je   .duplicate
.apic_prior_next:
    add  r9, r10
    jmp  .apic_prior
.madt_advance:
    add  r12, rcx
    jmp  .madt_next
.madt_done:
    cmp  dword [rel acpi_apic_count], 0
    je   .entry_bad
    cmp  byte [rel acpi_table_state], AF_BUDGET
    jne  .next_table
    ; Full validation succeeded, but never export a partial APIC inventory.
    ; acpi_madt alone remains usable by SMP's explicit degraded-capacity path.
    mov  dword [rel acpi_apic_count], 0
    jmp  .next_table
.mcfg:
    mov  eax, [r12 + 4]
    cmp  eax, 60                         ; 44-byte prefix + >=1 allocation
    jb   .short
    sub  eax, 44
    test eax, 15
    jnz  .entry_bad
    shr  eax, 4
    cmp  eax, AF_MAX_MCFG
    ja   .budget
    mov  [rel acpi_mcfg_count], eax
    add  r12, 44
    lea  rdi, [rel acpi_mcfg_entries]
    xor  r8d, r8d
.mcfg_next:
    cmp  r12, r13
    je   .next_table
    mov  rax, [r12]                     ; segment bus-0 ECAM base
    test rax, rax
    jz   .entry_bad
    test eax, 0xFFFFF                    ; 1 MiB bus alignment
    jnz  .entry_bad
    movzx ecx, byte [r12 + 11]
    cmp  cl, [r12 + 10]
    jb   .entry_bad
    inc  ecx
    shl  rcx, 20
    add  rcx, rax
    jc   .entry_bad                      ; ECAM described only, never read here
    cmp  dword [r12 + 12], 0
    jne  .entry_bad
    xor  edx, edx
.mcfg_overlap:
    cmp  edx, r8d
    jae  .mcfg_store
    mov  esi, edx
    shl  esi, 4
    mov  ax, [rdi + rsi + 8]
    cmp  ax, [r12 + 8]
    jne  .mcfg_other
    mov  al, [rdi + rsi + 10]
    cmp  al, [r12 + 11]
    ja   .mcfg_other
    mov  al, [rdi + rsi + 11]
    cmp  al, [r12 + 10]
    jae  .duplicate
.mcfg_other:
    inc  edx
    jmp  .mcfg_overlap
.mcfg_store:
    mov  eax, r8d
    shl  eax, 4
    mov  rcx, [r12]
    mov  [rdi + rax], rcx
    mov  rcx, [r12 + 8]
    mov  [rdi + rax + 8], rcx
    inc  r8d
    add  r12, 16
    jmp  .mcfg_next
.fadt:
    ; ACPI 1 FADT minimum. AF0 captures presence/revision only, never PM/reset.
    cmp  dword [r12 + 4], 116
    jb   .short
    mov  al, [r12 + 8]
    test al, al
    jz   .entry_bad
    mov  [rel acpi_fadt_revision], al
    jmp  .next_table
.hpet:
    cmp  dword [r12 + 4], 56
    jb   .short
    cmp  byte [r12 + 40], 0              ; GAS SystemMemory only
    jne  .unsupported
    cmp  byte [r12 + 42], 0              ; bit offset
    jne  .unsupported
    cmp  byte [r12 + 41], 0              ; firmware often leaves width unspecified
    je   .hpet_width
    cmp  byte [r12 + 41], 64
    jne  .unsupported
.hpet_width:
    cmp  byte [r12 + 43], 0              ; undefined access size or a QWORD
    je   .hpet_address
    cmp  byte [r12 + 43], 4
    jne  .unsupported
.hpet_address:
    mov  rdi, [r12 + 44]
    test rdi, rdi
    jz   .entry_bad
    test edi, 1023                      ; HPET block alignment, not SDT alignment
    jnz  .entry_bad
    mov  [rel acpi_hpet_base], rdi
    mov  esi, 8
    mov  edx, 1
    call acpi_range
    mov  byte [rel acpi_hpet_period_state], AF_ADDRESS
    jc   .next_table                    ; valid table, period explicitly unknown
    mov  rdi, [rel acpi_hpet_base]
    mov  rax, [rdi]                     ; ONE read-only CAP_ID load; no timer arm
    shr  rax, 32
    mov  byte [rel acpi_hpet_period_state], AF_ENTRY
    test eax, eax
    jz   .next_table
    cmp  eax, 100000000                 ; HPET spec: period <= 100ns
    ja   .next_table
    mov  [rel acpi_hpet_period], eax
    mov  byte [rel acpi_hpet_period_state], AF_VALID
    jmp  .next_table
.short:
    mov  edx, AF_LENGTH
    jmp  .reject
.entry_bad:
    mov  edx, AF_ENTRY
    jmp  .reject
.budget:
    mov  edx, AF_BUDGET
    jmp  .reject
.duplicate:
    mov  edx, AF_DUPLICATE
    jmp  .reject
.unsupported:
    mov  edx, AF_UNSUPPORTED
.reject:
    lea  rax, [rel acpi_table_state]
    mov  [rax + rbx], dl
    lea  rax, [rel acpi_table_ptrs]
    mov  qword [rax + rbx*8], 0
    ; Counters make partially written arrays unobservable after any refusal.
    test ebx, ebx
    jnz  .clear_mcfg
    mov  dword [rel acpi_apic_count], 0
.clear_mcfg:
    cmp  ebx, 1
    jne  .next_table
    mov  dword [rel acpi_mcfg_count], 0
.next_table:
    inc  ebx
    cmp  ebx, 4
    jb   .table
    pop  r13
    pop  r12
    pop  rbx
    ret

; EDI=state -> RAX=NUL-terminated stable reason (offset table, never dq pointer).
acpi_state_name:
    cmp  edi, AF_UNSUPPORTED
    jbe  .known
    mov  edi, AF_ENTRY
.known:
    lea  rdx, [rel acpi_state_offsets]
    movzx eax, word [rdx + rdi*2]
    lea  rdx, [rel acpi_state_strings]
    add  rax, rdx
    ret

; RDI=first token, RSI=second token, EDX=common token length (1..8).
; Return EAX=1 only when one validated DSDT contains both tokens. This is a
; deliberately narrow AML identity predicate: consumers still must verify their
; exact PCI route before touching device MMIO. The FADT and DSDT checksums and
; the DSDT-specific 256-KiB ceiling bound every byte inspected here.
acpi_dsdt_contains_pair:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13, rsi
    mov  r14d, edx
    test r14d, r14d
    jz   .no
    cmp  r14d, 8
    ja   .no
    mov  edi, 'FACP'
    call acpi_find_table
    test rax, rax
    jz   .no
    mov  rbx, rax
    cmp  ecx, 44                            ; legacy DSDT pointer through byte 43
    jb   .no
    cmp  ecx, 148                           ; X_DSDT pointer through byte 147
    jb   .legacy
    mov  rbx, [rbx + 140]
    test rbx, rbx
    jnz  .validate
    mov  rbx, rax
.legacy:
    mov  ebx, [rbx + 40]
    test rbx, rbx
    jz   .no
.validate:
    mov  rdi, rbx
    mov  esi, 'DSDT'
    call acpi_validate_sdt
    cmp  eax, AF_VALID
    jne  .no
    sub  ecx, ACPI_HDR_LEN
    lea  rdi, [rbx + ACPI_HDR_LEN]
    mov  rsi, r12
    mov  edx, r14d
    call acpi_mem_has_token
    test eax, eax
    jz   .no
    mov  rdi, rbx
    add  rdi, ACPI_HDR_LEN
    mov  ecx, [rbx + 4]
    sub  ecx, ACPI_HDR_LEN
    mov  rsi, r13
    mov  edx, r14d
    call acpi_mem_has_token
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=validated bytes, ECX=extent, RSI=token, EDX=token length 1..8.
acpi_mem_has_token:
    test edx, edx
    jz   .absent
    cmp  edx, 8
    ja   .absent
    cmp  ecx, edx
    jb   .absent
    sub  ecx, edx
    inc  ecx
.candidate:
    mov  r8, rdi
    mov  r9, rsi
    mov  r10d, edx
.byte:
    mov  al, [r8]
    cmp  al, [r9]
    jne  .next
    inc  r8
    inc  r9
    dec  r10d
    jnz  .byte
    mov  eax, 1
    ret
.next:
    inc  rdi
    dec  ecx
    jnz  .candidate
.absent:
    xor  eax, eax
    ret

acpi_selftest:
    push rbx
    push r12
    push r13
    call iommu_isolation_topology_kat        ; Task3250: read-only PCIe/IOMMU isolation topology content KAT (iommu.isolation.topology.kat)
    call shared_surface_portal_kat           ; Task3456: shared surface/portal widget type + slot-14 handle ABI content KAT
    call memory_observability_kat            ; Task1481: memory observability content KAT
    call login_owner_label_migration_kat     ; Task3472: login owner label migration KAT
%if !PAOS_PUBLIC_BUILD
    call kde_phone_identity_kat              ; Task3330: KDE phone-link identity KATs
%endif
    call backup_export_kat                   ; Task1230a: BACKUP EXPORT seal KAT
    cmp  byte [rel acpi_kat_done], 1
    je   .live
    call acpi_parser_kat
.live:
    mov  qword [rel acpi_fixture_lo], 0
    mov  qword [rel acpi_fixture_hi], 0
    mov  qword [rel acpi_xsdt], 0
    mov  qword [rel acpi_xsdt_n], 0
    mov  byte [rel acpi_root_state], AF_ABSENT
    mov  rbx, [rel system_table]
    mov  rdi, rbx
    mov  esi, 120
    xor  edx, edx
    call acpi_range
    jc   .address
    mov  r13, [rbx + EST_NUM_TABLES]
    cmp  r13, AF_MAX_ENTRIES
    ja   .budget
    test r13, r13
    jz   .report
    mov  r12, [rbx + EST_CFG_TABLE]
    imul rsi, r13, CFG_ENTRY_SIZE
    mov  rdi, r12
    xor  edx, edx
    call acpi_range
    jc   .address
    xor  ebx, ebx
.cfg:
    cmp  rbx, r13
    jae  .report
    imul rax, rbx, CFG_ENTRY_SIZE
    lea  rdx, [r12 + rax]
    mov  rax, 0x11D3E4F18868E871
    cmp  [rdx], rax
    jne  .cfg_next
    mov  rax, 0x81883CC7800022BC
    cmp  [rdx + 8], rax
    je   .rsdp
.cfg_next:
    inc  ebx
    jmp  .cfg
.rsdp:
    mov  r12, [rdx + 16]
    mov  rdi, r12
    mov  esi, 36
    xor  edx, edx
    call acpi_range
    jc   .address
    mov  rax, 0x2052545020445352
    cmp  [r12], rax
    jne  .signature
    cmp  byte [r12 + RSDP_REV], 2
    jb   .signature
    mov  rdi, r12
    mov  ecx, 20
    call acpi_checksum
    test al, al
    jnz  .checksum
    mov  r13d, [r12 + 20]
    cmp  r13d, 36
    jb   .length
    cmp  r13d, 4096
    ja   .budget
    mov  rdi, r12
    mov  esi, r13d
    xor  edx, edx
    call acpi_range
    jc   .address
    mov  rdi, r12
    mov  ecx, r13d
    call acpi_checksum
    test al, al
    jnz  .checksum
    lea  rdi, [rel str_acpi_rsdp]
    call serial_string
    mov  rdi, r12
    call acpi_serial_hex
    call serial_newline
    mov  r13, [r12 + RSDP_XSDT_ADDR]
    mov  rdi, r13
    mov  esi, 'XSDT'
    call acpi_validate_sdt
    cmp  eax, AF_VALID
    jne  .root_bad
    sub  ecx, ACPI_HDR_LEN
    test ecx, 7
    jnz  .length
    shr  ecx, 3
    cmp  ecx, AF_MAX_ENTRIES
    ja   .budget
    mov  [rel acpi_xsdt_n], rcx
    mov  [rel acpi_xsdt], r13
    mov  byte [rel acpi_root_state], AF_VALID
    lea  rdi, [rel str_acpi_xsdt]
    call serial_string
    mov  rdi, [rel acpi_xsdt_n]
    call acpi_serial_dec
    call serial_newline
    jmp  .report
.address:
    mov  eax, AF_ADDRESS
    jmp  .root_bad
.signature:
    mov  eax, AF_SIGNATURE
    jmp  .root_bad
.checksum:
    mov  eax, AF_CHECKSUM
    jmp  .root_bad
.length:
    mov  eax, AF_LENGTH
    jmp  .root_bad
.budget:
    mov  eax, AF_BUDGET
.root_bad:
    mov  [rel acpi_root_state], al
.report:
    call acpi_collect
    call acpi_serial_inventory
    cmp  byte [rel acpi_kat_ok], 1
    jne  .out
    lea  rdi, [rel str_acpi_verified]
    call serial_string
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

acpi_serial_dec:
    lea  rsi, [rel acpi_numbuf]
    call fmt_dec
    lea  rdi, [rel acpi_numbuf]
    jmp  serial_string
acpi_serial_hex:
    lea  rsi, [rel acpi_numbuf]
    xor  edx, edx
    call fmt_hex
    lea  rdi, [rel acpi_numbuf]
    jmp  serial_string

; Each table gets a bounded loud record, including absence and unknown period.
acpi_serial_inventory:
    push rbx
    push r12
    lea  rdi, [rel str_acpi_root]
    call serial_string
    movzx edi, byte [rel acpi_root_state]
    call acpi_state_name
    mov  rdi, rax
    call serial_string
    call serial_newline
    xor  ebx, ebx
.table:
    lea  rdi, [rel str_acpi_live]
    call serial_string
    lea  rdi, [rel acpi_names]
    imul rax, rbx, 5
    add  rdi, rax
    call serial_string
    lea  rdi, [rel str_acpi_state]
    call serial_string
    lea  rax, [rel acpi_table_state]
    movzx edi, byte [rax + rbx]
    call acpi_state_name
    mov  rdi, rax
    call serial_string
    lea  rdi, [rel str_acpi_values]
    call serial_string
    lea  rax, [rel acpi_table_state]
    cmp  byte [rax + rbx], AF_VALID
    jne  .unknown
    test ebx, ebx
    jz   .apics
    cmp  ebx, 1
    je   .ecams
    cmp  ebx, 2
    je   .revision
    mov  rdi, [rel acpi_hpet_base]
    call acpi_serial_hex
    lea  rdi, [rel str_acpi_comma]
    call serial_string
    cmp  byte [rel acpi_hpet_period_state], AF_VALID
    jne  .unknown
    mov  edi, [rel acpi_hpet_period]
    call acpi_serial_dec
    jmp  .record_end
.revision:
    movzx edi, byte [rel acpi_fadt_revision]
    call acpi_serial_dec
    jmp  .record_end
.apics:
    xor  r12d, r12d
.apic:
    lea  rax, [rel acpi_apic_ids]
    mov  edi, [rax + r12*4]
    call acpi_serial_dec
    inc  r12d
    cmp  r12d, [rel acpi_apic_count]
    jae  .record_end
    lea  rdi, [rel str_acpi_comma]
    call serial_string
    jmp  .apic
.ecams:
    xor  r12d, r12d
.ecam:
    mov  eax, r12d
    shl  eax, 4
    lea  rdx, [rel acpi_mcfg_entries]
    mov  rdi, [rdx + rax]
    call acpi_serial_hex
    lea  rdi, [rel str_acpi_comma]
    call serial_string
    mov  eax, r12d
    shl  eax, 4
    lea  rdx, [rel acpi_mcfg_entries]
    movzx edi, word [rdx + rax + 8]
    call acpi_serial_dec
    lea  rdi, [rel str_acpi_comma]
    call serial_string
    mov  eax, r12d
    shl  eax, 4
    lea  rdx, [rel acpi_mcfg_entries]
    movzx edi, byte [rdx + rax + 10]
    call acpi_serial_dec
    lea  rdi, [rel str_acpi_comma]
    call serial_string
    mov  eax, r12d
    shl  eax, 4
    lea  rdx, [rel acpi_mcfg_entries]
    movzx edi, byte [rdx + rax + 11]
    call acpi_serial_dec
    inc  r12d
    cmp  r12d, [rel acpi_mcfg_count]
    jae  .record_end
    lea  rdi, [rel str_acpi_semicolon]
    call serial_string
    jmp  .ecam
.unknown:
    lea  rdi, [rel str_acpi_unknown]
    call serial_string
.record_end:
    lea  rdi, [rel str_acpi_continuing]
    call serial_string
    inc  ebx
    cmp  ebx, 4
    jb   .table
    pop  r12
    pop  rbx
    ret

; Pre-SMP entry remains idempotent. KATs run before live discovery, never after
; consumers can see synthetic topology.
smp_selftest_after_acpi:
    call acpi_selftest
    xor eax,eax
    cmp byte [rel acpi_root_state],AF_VALID
    jne .hest_store                     ; failed root discovery is not absent HEST
    mov edi,'HEST'
    call acpi_find_table
    mov rdi,rax
    xor esi,esi
    test rax,rax
    jz .hest_policy
    mov esi,[rax+4]                       ; lookup already range/checksum qualified
.hest_policy:
    call hest_cmci_policy
.hest_store:
    mov [rel mca_cmci_policy],eax          ; immutable before AP startup
    jmp  smp_selftest

; KAT implementation is below the inventory; all pointers are built with LEA.
; AF0 mutable storage: bounded inventory + 1024-byte reusable fixture.
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_bus_acpi_0 0
acpi_xsdt: dq 0
acpi_xsdt_n: dq 0
acpi_root_state: db AF_ABSENT
acpi_kat_done: db 0
acpi_kat_ok: db 0
acpi_fixture_lo: dq 0
acpi_fixture_hi: dq 0
acpi_inventory:
acpi_table_ptrs:
acpi_madt: dq 0
    times 3 dq 0
acpi_table_state: times 4 db 0
acpi_table_present: times 4 db 0
acpi_apic_count: dd 0
acpi_apic_ids: times AF_MAX_APICS dd 0
acpi_mcfg_count: dd 0
acpi_mcfg_entries: times AF_MAX_MCFG*16 db 0
acpi_fadt_revision: db 0
acpi_hpet_base: dq 0
acpi_hpet_period: dd 0
acpi_hpet_period_state: db 0
acpi_inventory_end:
acpi_numbuf: times 24 db 0
acpi_signatures: dd 'APIC', 'MCFG', 'FACP', 'HPET'
acpi_names: db 'MADT',0,'MCFG',0,'FADT',0,'HPET',0
acpi_state_offsets:
    dw acpi_state_strings.absent-acpi_state_strings, acpi_state_strings.valid-acpi_state_strings
    dw acpi_state_strings.signature-acpi_state_strings, acpi_state_strings.checksum-acpi_state_strings
    dw acpi_state_strings.length-acpi_state_strings, acpi_state_strings.budget-acpi_state_strings
    dw acpi_state_strings.address-acpi_state_strings, acpi_state_strings.duplicate-acpi_state_strings
    dw acpi_state_strings.entry-acpi_state_strings, acpi_state_strings.unsupported-acpi_state_strings
acpi_state_strings:
.absent: db 'ABSENT',0
.valid: db 'VALID',0
.signature: db 'BAD_SIGNATURE',0
.checksum: db 'BAD_CHECKSUM',0
.length: db 'BAD_LENGTH',0
.budget: db 'OVER_BUDGET',0
.address: db 'BAD_ADDRESS',0
.duplicate: db 'DUPLICATE',0
.entry: db 'BAD_ENTRY',0
.unsupported: db 'UNSUPPORTED',0
str_acpi_rsdp: db "[PAOS64] M2 acpi: RSDP found [acpi.rsdp.found] at 0x",0
str_acpi_xsdt: db "[PAOS64] M2 acpi: XSDT walk [acpi.xsdt.walk] entries=",0
str_acpi_live: db "[PAOS64] ACPI LIVE ",0
str_acpi_root: db "[PAOS64] ACPI ROOT state=",0
str_acpi_values: db " values=",0
str_acpi_unknown: db "unknown",0
str_acpi_comma: db ",",0
str_acpi_semicolon: db ";",0
str_acpi_state: db " state=",0
str_acpi_continuing: db " continuing=1",13,10,0
str_acpi_verified: db "[PAOS64] M2 acpi: bounded live table verification PASS [acpi.table.live_verified]",13,10,0
%endmacro
WDATA_DEFER WDATA_bus_acpi_0

; Generated byte fixtures: same acpi_collect -> acpi_find_table ->
; acpi_validate_sdt path as firmware. Every hostile case returns and is logged
; before normal boot continues. The host checks actual values AND the later
; normal boot marker, never credits this self-report alone.
AF_KAT_COUNT equ 20
acpi_parser_kat:
    push rbx
    push r12
    push r13
    mov  byte [rel acpi_kat_done], 1
    mov  byte [rel acpi_kat_ok], 0
    xor  ebx, ebx
.case:
    call acpi_fixture_build
    ; EAX mutation selector is compile-time bounded and not remotely exposed.
    test ebx, ebx
    jz   .parse
    cmp  ebx, 1
    je   .absent
    cmp  ebx, 2
    je   .duplicate
    cmp  ebx, 3
    je   .signature
    cmp  ebx, 4
    je   .checksum
    cmp  ebx, 5
    je   .length
    cmp  ebx, 6
    je   .budget
    cmp  ebx, 7
    je   .zero_entry
    cmp  ebx, 8
    je   .long_entry
    cmp  ebx, 9
    je   .address
    cmp  ebx, 10
    je   .duplicate_apic
    cmp  ebx, 11
    je   .mcfg_range
    cmp  ebx, 12
    je   .gas
    cmp  ebx, 13
    je   .period
    cmp  ebx, 14
    je   .xsdt_tail
    cmp  ebx, 15
    je   .child_signature
    cmp  ebx, 16
    je   .xsdt_budget
    cmp  ebx, 18
    jae  .large_vendor
    ; A header straddling the exact readable fixture boundary.
    lea  rax, [rel acpi_fixture_data + 1020]
    mov  [rel acpi_fixture_root + 36], rax
    jmp  .root_checksum
.large_vendor:
    ; Header only, in the existing scratch arena. There is deliberately no
    ; 216258-byte body to read: a nonmatching LUFT must not be dereferenced.
    lea  rax, [rel acpi_fixture_data + 800]
    mov  dword [rax], 'LUFT'
    mov  dword [rax + 4], 216258
    mov  [rel acpi_fixture_root + 68], rax
    mov  dword [rel acpi_fixture_root + 4], 76
    cmp  ebx, 18
    je   .root_checksum
    ; A large nonmatching header must not hide a later requested duplicate.
    lea  rax, [rel acpi_fixture_madt]
    mov  [rel acpi_fixture_root + 76], rax
    mov  dword [rel acpi_fixture_root + 4], 84
    jmp  .root_checksum
.absent:
    mov  dword [rel acpi_fixture_root + 4], 60 ; HPET absent, three entries
    jmp  .root_checksum
.duplicate:
    lea  rax, [rel acpi_fixture_madt]
    mov  [rel acpi_fixture_root + 68], rax
    mov  dword [rel acpi_fixture_root + 4], 76
    jmp  .root_checksum
.signature:
    mov  byte [rel acpi_fixture_root], '!'
    jmp  .root_checksum
.checksum:
    xor  byte [rel acpi_fixture_madt + 9], 1
    jmp  .parse
.length:
    mov  dword [rel acpi_fixture_madt + 4], 35
    jmp  .parse
.budget:
    mov  dword [rel acpi_fixture_madt + 4], AF_MAX_TABLE + 1
    jmp  .parse
.zero_entry:
    mov  byte [rel acpi_fixture_madt + 45], 0
    jmp  .madt_checksum
.long_entry:
    mov  byte [rel acpi_fixture_madt + 45], 255
    jmp  .madt_checksum
.address:
    mov  qword [rel acpi_fixture_root + 36], -16
    jmp  .root_checksum
.duplicate_apic:
    mov  byte [rel acpi_fixture_madt + 55], 0
    jmp  .madt_checksum
.mcfg_range:
    mov  byte [rel acpi_fixture_mcfg + 54], 8
    mov  byte [rel acpi_fixture_mcfg + 55], 7
    lea  rdi, [rel acpi_fixture_mcfg]
    call acpi_fixture_checksum
    jmp  .parse
.gas:
    mov  byte [rel acpi_fixture_hpet + 40], 1 ; SystemIO cannot be MMIO-read
    lea  rdi, [rel acpi_fixture_hpet]
    call acpi_fixture_checksum
    jmp  .parse
.period:
    mov  dword [rel acpi_fixture_data + 4], 0
    jmp  .parse
.xsdt_tail:
    mov  dword [rel acpi_fixture_root + 4], 69
    jmp  .root_checksum
.child_signature:
    mov  byte [rel acpi_fixture_madt], 0
    jmp  .madt_checksum
.xsdt_budget:
    ; Header exceeds the SDT byte budget: refuse before touching the body.
    ; The independent host matrix also covers 257 actual XSDT entries.
    mov  dword [rel acpi_fixture_root + 4], AF_MAX_TABLE + 1
    jmp  .parse
.madt_checksum:
    lea  rdi, [rel acpi_fixture_madt]
    call acpi_fixture_checksum
    jmp  .parse
.root_checksum:
    lea  rdi, [rel acpi_fixture_root]
    call acpi_fixture_checksum
.parse:
    call acpi_collect
    lea  rax, [rel acpi_kat_expected]
    movzx r12d, byte [rax + rbx*2]
    movzx r13d, byte [rax + rbx*2 + 1]
    lea  rax, [rel acpi_table_state]
    cmp  [rax + r12], r13b
    jne  .fail
    cmp  ebx, 13
    jne  .check_normal
    cmp  byte [rel acpi_hpet_period_state], AF_ENTRY
    jne  .fail
    cmp  dword [rel acpi_hpet_period], 0
    jne  .fail
.check_normal:
    cmp  ebx, 18
    je   .check_values
    test ebx, ebx
    jnz  .check_refusal
.check_values:
    cmp  dword [rel acpi_table_state], 0x01010101
    jne  .fail
    cmp  dword [rel acpi_table_present], 0x01010101
    jne  .fail
    cmp  dword [rel acpi_apic_count], 3
    jne  .fail
    cmp  dword [rel acpi_apic_ids], 0
    jne  .fail
    cmp  dword [rel acpi_apic_ids + 4], 4
    jne  .fail
    cmp  dword [rel acpi_apic_ids + 8], 0x123
    jne  .fail
    cmp  dword [rel acpi_mcfg_count], 1
    jne  .fail
    mov  eax, 0xE0000000
    cmp  [rel acpi_mcfg_entries], rax
    jne  .fail
    cmp  dword [rel acpi_mcfg_entries + 8], 0xFF000000
    jne  .fail
    cmp  byte [rel acpi_fadt_revision], 6
    jne  .fail
    lea  rax, [rel acpi_fixture_data]
    cmp  [rel acpi_hpet_base], rax
    jne  .fail
    cmp  dword [rel acpi_hpet_period], 10000000
    jne  .fail
    cmp  byte [rel acpi_hpet_period_state], AF_VALID
    jne  .fail
    jmp  .record
.check_refusal:
    cmp  r13d, AF_VALID
    je   .record
    lea  rax, [rel acpi_table_ptrs]
    cmp  qword [rax + r12*8], 0
    jne  .fail
    test r12d, r12d
    jnz  .record
    cmp  dword [rel acpi_apic_count], 0
    jne  .fail
.record:
    lea  rdi, [rel str_acpi_kat_case]
    call serial_string
    mov  edi, ebx
    call acpi_serial_dec
    lea  rdi, [rel str_acpi_state]
    call serial_string
    mov  edi, r13d
    call acpi_state_name
    mov  rdi, rax
    call serial_string
    lea  rdi, [rel str_acpi_continuing]
    call serial_string
    inc  ebx
    cmp  ebx, AF_KAT_COUNT
    jb   .case
    mov  byte [rel acpi_kat_ok], 1
    jmp  .out
.fail:
    lea  rdi, [rel str_acpi_kat_fail]
    call serial_string
    mov  edi, ebx
    call acpi_serial_dec
    call serial_newline
.out:
    ; No fixture pointers can escape to SMP/DMAR, even on KAT failure.
    mov  qword [rel acpi_fixture_lo], 0
    mov  qword [rel acpi_fixture_hi], 0
    mov  qword [rel acpi_xsdt], 0
    call acpi_inventory_clear
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=owned fixture SDT. Only called for known fixture lengths <=116.
acpi_fixture_checksum:
    push rbx
    mov  rbx, rdi
    mov  byte [rdi + 9], 0
    mov  ecx, [rdi + 4]
    call acpi_checksum
    neg  al
    mov  [rbx + 9], al
    pop  rbx
    ret

acpi_fixture_build:
    lea  rdi, [rel acpi_fixture_data]
    mov  [rel acpi_fixture_lo], rdi
    lea  rax, [rdi + 1024]
    mov  [rel acpi_fixture_hi], rax
    xor  eax, eax
    mov  ecx, 1024
    rep  stosb
    mov  dword [rel acpi_fixture_data], 0x8086A201
    mov  dword [rel acpi_fixture_data + 4], 10000000
    lea  rax, [rel acpi_fixture_root]
    mov  [rel acpi_xsdt], rax
    mov  byte [rel acpi_root_state], AF_VALID
    mov  dword [rel acpi_fixture_root], 'XSDT'
    mov  dword [rel acpi_fixture_root + 4], 68
    lea  rax, [rel acpi_fixture_madt]
    mov  [rel acpi_fixture_root + 36], rax
    lea  rax, [rel acpi_fixture_mcfg]
    mov  [rel acpi_fixture_root + 44], rax
    lea  rax, [rel acpi_fixture_fadt]
    mov  [rel acpi_fixture_root + 52], rax
    lea  rax, [rel acpi_fixture_hpet]
    mov  [rel acpi_fixture_root + 60], rax
    lea  rdi, [rel acpi_fixture_root]
    call acpi_fixture_checksum
    mov  dword [rel acpi_fixture_madt], 'APIC'
    mov  dword [rel acpi_fixture_madt + 4], 84
    mov  dword [rel acpi_fixture_madt + 36], 0xFEE00000
    mov  word [rel acpi_fixture_madt + 44], 0x0800
    mov  dword [rel acpi_fixture_madt + 48], 1
    mov  dword [rel acpi_fixture_madt + 52], 0x04010800
    mov  dword [rel acpi_fixture_madt + 56], 1
    mov  word [rel acpi_fixture_madt + 60], 0x1009
    mov  dword [rel acpi_fixture_madt + 64], 0x123
    mov  dword [rel acpi_fixture_madt + 68], 1
    mov  word [rel acpi_fixture_madt + 76], 0x0800 ; disabled row ignored
    lea  rdi, [rel acpi_fixture_madt]
    call acpi_fixture_checksum
    mov  dword [rel acpi_fixture_mcfg], 'MCFG'
    mov  dword [rel acpi_fixture_mcfg + 4], 60
    mov  dword [rel acpi_fixture_mcfg + 44], 0xE0000000
    mov  byte [rel acpi_fixture_mcfg + 55], 255
    lea  rdi, [rel acpi_fixture_mcfg]
    call acpi_fixture_checksum
    mov  dword [rel acpi_fixture_fadt], 'FACP'
    mov  dword [rel acpi_fixture_fadt + 4], 116
    mov  byte [rel acpi_fixture_fadt + 8], 6
    lea  rdi, [rel acpi_fixture_fadt]
    call acpi_fixture_checksum
    mov  dword [rel acpi_fixture_hpet], 'HPET'
    mov  dword [rel acpi_fixture_hpet + 4], 56
    mov  byte [rel acpi_fixture_hpet + 41], 64
    lea  rax, [rel acpi_fixture_data]
    mov  [rel acpi_fixture_hpet + 44], rax
    lea  rdi, [rel acpi_fixture_hpet]
    jmp  acpi_fixture_checksum

; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_bus_acpi_1 0
acpi_kat_expected:
    db 0,AF_VALID, 3,AF_ABSENT, 0,AF_DUPLICATE, 0,AF_SIGNATURE
    db 0,AF_CHECKSUM, 0,AF_LENGTH, 0,AF_BUDGET, 0,AF_ENTRY
    db 0,AF_ENTRY, 0,AF_ADDRESS, 0,AF_DUPLICATE, 1,AF_ENTRY
    db 3,AF_UNSUPPORTED, 3,AF_VALID, 0,AF_LENGTH, 0,AF_SIGNATURE
    db 0,AF_BUDGET, 0,AF_ADDRESS
    db 0,AF_VALID, 0,AF_DUPLICATE
str_acpi_kat_case: db "[PAOS64] ACPI KAT case=",0
str_acpi_kat_fail: db "[PAOS64] ACPI KAT FAIL case=",0
; code_start is PE RVA 0x1000 (boot/header.asm), unlike the file's +0x200.
; Align relative to that runtime page: plain ALIGN would leave the synthetic
; HPET at VA mod 1024 == 512 and reject the valid case on every product boot.
times ((-($ - code_start)) & 1023) db 0
acpi_fixture_data: times 64 db 0
acpi_fixture_root: times 96 db 0
acpi_fixture_madt: times 128 db 0
acpi_fixture_mcfg: times 128 db 0
acpi_fixture_fadt: times 160 db 0
acpi_fixture_hpet: times 448 db 0
%endmacro
WDATA_DEFER WDATA_bus_acpi_1

; ---- RCQ-12 S-IRQMAP: read-only native interrupt-routing map -----------------
; One boot line naming how this platform routes interrupt sources, from the
; validated MADT/FADT plus each IOAPIC's version register. PaOS programs the 8259
; (core/time) and the LAPIC (core/smp) and never an IOAPIC redirection entry, so
; the line says redirection=unowned. A malformed MADT, an IOSAPIC/platform-source
; model or overlapping IOAPIC GSI ranges print madt=invalid: never a partial map.
IRQMAP_MAX_IOAPICS equ 8
IRQMAP_UNREAD equ 0xffffffff

; acpi_irqmap_parse(RDI=MADT) -> CF=1 invalid. Pure: fills the irqmap state only.
acpi_irqmap_parse:
    push rbx
    push r12
    lea  rax, [rel acpi_irqmap_state]
    mov  ecx, acpi_irqmap_state_end - acpi_irqmap_state
.clear:
    mov  byte [rax + rcx - 1], 0
    dec  ecx
    jnz  .clear
    mov  eax, [rdi + 4]
    cmp  eax, 44
    jb   .bad
    lea  r9, [rdi + rax]
    mov  eax, [rdi + 40]
    and  al, 1                             ; PCAT_COMPAT
    mov  [rel acpi_irqmap_pcat], al
    lea  r8, [rdi + 44]
    mov  ebx, AF_MAX_ENTRIES
.record:
    cmp  r8, r9
    je   .done
    dec  ebx
    js   .bad
    mov  rax, r9
    sub  rax, r8
    cmp  rax, 2
    jb   .bad
    movzx ecx, byte [r8 + 1]
    cmp  ecx, 2
    jb   .bad
    cmp  rcx, rax
    ja   .bad
    movzx eax, byte [r8]
    cmp  eax, 1
    je   .ioapic
    cmp  eax, 2
    je   .iso
    cmp  eax, 3
    je   .nmi
    cmp  eax, 4
    je   .lnmi
    cmp  eax, 6                            ; IOSAPIC / platform interrupt sources: unowned models
    je   .bad
    cmp  eax, 8
    je   .bad
.next:
    add  r8, rcx
    jmp  .record
.ioapic:
    cmp  ecx, 12
    jne  .bad
    mov  edx, [rel acpi_irqmap_io_count]
    cmp  edx, IRQMAP_MAX_IOAPICS
    jae  .bad
    mov  eax, [r8 + 4]
    cmp  eax, 4096
    jb   .bad
    test eax, 4095
    jnz  .bad
    lea  r10, [rel acpi_irqmap_io]
    xor  r11d, r11d
.io_dup:
    cmp  r11d, edx
    jae  .io_store
    mov  r12d, r11d
    shl  r12d, 4
    cmp  eax, [r10 + r12]
    je   .bad
    inc  r11d
    jmp  .io_dup
.io_store:
    shl  edx, 4
    add  r10, rdx
    mov  [r10], eax
    mov  eax, [r8 + 8]
    mov  [r10 + 4], eax
    mov  dword [r10 + 8], IRQMAP_UNREAD
    mov  al, [r8 + 2]
    mov  [r10 + 12], al
    inc  dword [rel acpi_irqmap_io_count]
    jmp  .next
.iso:
    cmp  ecx, 10
    jne  .bad
    cmp  byte [r8 + 2], 0                  ; ISA bus only
    jne  .bad
    movzx edx, byte [r8 + 3]
    cmp  edx, 16
    jae  .bad
    bts  dword [rel acpi_irqmap_iso_mask], edx
    jc   .bad
    movzx eax, word [r8 + 8]
    test eax, ~15
    jnz  .bad
    mov  r10d, eax
    and  r10d, 3
    cmp  r10d, 2                           ; reserved polarity
    je   .bad
    mov  r10d, eax
    and  r10d, 12
    cmp  r10d, 8                           ; reserved trigger mode
    je   .bad
    lea  r10, [rel acpi_irqmap_iso_flags]
    mov  [r10 + rdx*2], ax
    mov  eax, [r8 + 4]
    lea  r10, [rel acpi_irqmap_iso_gsi]
    mov  [r10 + rdx*4], eax
    jmp  .next
.nmi:
    cmp  ecx, 8
    jne  .bad
    inc  dword [rel acpi_irqmap_nmi]
    jmp  .next
.lnmi:
    cmp  ecx, 6
    jne  .bad
    inc  dword [rel acpi_irqmap_lnmi]
    jmp  .next
.done:
    mov  byte [rel acpi_irqmap_complete], 1 ; VM 106840/SEC 106852: whole MADT read, sole writer
    clc
    pop  r12
    pop  rbx
    ret
.bad:
    stc
    pop  r12
    pop  rbx
    ret

; acpi_irqmap_read_versions -> CF=1 when two readable IOAPICs overlap in GSI.
; Each IOAPIC must be a qualified MMIO extent (acpi_range mode 1); its version is
; read through the selector-preserving acpi_sci_io_read. Unreadable -> end stays
; IRQMAP_UNREAD and the line prints "unread" for it.
acpi_irqmap_read_versions:
    push rbx
    push r12
    push r13
    xor  ebx, ebx
.ioapic:
    cmp  ebx, [rel acpi_irqmap_io_count]
    jae  .overlap
    mov  eax, ebx
    shl  eax, 4
    lea  r12, [rel acpi_irqmap_io]
    add  r12, rax
    mov  edi, [r12]
    mov  esi, 32                           ; selector and window
    mov  edx, 1
    call acpi_range
    jc   .next
    mov  edi, [r12]
    mov  esi, 1                            ; IOAPICVER
    call acpi_sci_io_read
    cmp  eax, IRQMAP_UNREAD
    je   .next
    shr  eax, 16
    and  eax, 255
    cmp  eax, 119                          ; 8-bit IOREGSEL redirection register extent
    ja   .next
    add  eax, [r12 + 4]
    jc   .next
    mov  [r12 + 8], eax                    ; inclusive GSI end
.next:
    inc  ebx
    jmp  .ioapic
.overlap:
    xor  ebx, ebx
    lea  r12, [rel acpi_irqmap_io]
.outer:
    cmp  ebx, [rel acpi_irqmap_io_count]
    jae  .ok
    mov  eax, ebx
    shl  eax, 4
    cmp  dword [r12 + rax + 8], IRQMAP_UNREAD
    je   .outer_next
    lea  r13d, [rbx + 1]
.inner:
    cmp  r13d, [rel acpi_irqmap_io_count]
    jae  .outer_next
    mov  ecx, r13d
    shl  ecx, 4
    cmp  dword [r12 + rcx + 8], IRQMAP_UNREAD
    je   .inner_next
    mov  edx, [r12 + rax + 8]              ; a.end < b.base or b.end < a.base: separate
    cmp  edx, [r12 + rcx + 4]
    jb   .inner_next
    mov  edx, [r12 + rcx + 8]
    cmp  edx, [r12 + rax + 4]
    jb   .inner_next
    stc
    jmp  .out
.inner_next:
    inc  r13d
    jmp  .inner
.outer_next:
    inc  ebx
    jmp  .outer
.ok:
    clc
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; The two privileged reads, isolated. EAX: 0 disabled, 1 xAPIC, 2 x2APIC.
acpi_irqmap_lapic_mode:
    mov  ecx, 0x1b                         ; IA32_APIC_BASE
    rdmsr
    xor  ecx, ecx
    bt   eax, 11
    jnc  .mode
    inc  ecx
    bt   eax, 10
    adc  ecx, 0
.mode:
    mov  eax, ecx
    ret
; EAX = master IMR | slave IMR << 8 (read only; no command word is written).
acpi_irqmap_imr:
    xor  eax, eax
    in   al, 0xa1
    shl  eax, 8
    in   al, 0x21
    ret

acpi_irqmap_hex2:                          ; EDI=byte -> two hex digits
    lea  rsi, [rel acpi_numbuf]
    mov  edx, 2
    call fmt_hex
    lea  rdi, [rel acpi_numbuf]
    jmp  serial_string

acpi_irqmap_report:
    push rbx
    push r12
    push r13
    lea  rdi, [rel str_irqmap_head]
    call serial_string
    call acpi_irqmap_lapic_mode
    lea  rdi, [rel str_irqmap_lapic_off]
    cmp  eax, 1
    jb   .lapic
    lea  rdi, [rel str_irqmap_lapic_x]
    je   .lapic
    lea  rdi, [rel str_irqmap_lapic_x2]
.lapic:
    call serial_string
    call acpi_irqmap_imr
    mov  ebx, eax
    lea  rdi, [rel str_irqmap_imr]
    call serial_string
    movzx edi, bl
    call acpi_irqmap_hex2
    lea  rdi, [rel str_irqmap_slash]
    call serial_string
    movzx edi, bh
    call acpi_irqmap_hex2
    lea  rax, [rel acpi_table_state]
    cmp  byte [rax], AF_VALID
    je   .madt
    lea  rdi, [rel str_irqmap_absent]
    cmp  byte [rax], AF_ABSENT
    je   .tail
.invalid:
    lea  rdi, [rel str_irqmap_invalid]
.tail:
    call serial_string
    jmp  .end
.madt:
    mov  rdi, [rel acpi_madt]
    call acpi_irqmap_parse
    jc   .invalid
    call acpi_irqmap_read_versions
    jc   .invalid
    lea  rdi, [rel str_irqmap_pcat]
    call serial_string
    movzx edi, byte [rel acpi_irqmap_pcat]
    call acpi_serial_dec
    lea  rdi, [rel str_irqmap_ioapics]
    call serial_string
    mov  edi, [rel acpi_irqmap_io_count]
    call acpi_serial_dec
    xor  ebx, ebx
.io:
    cmp  ebx, [rel acpi_irqmap_io_count]
    jae  .iso
    mov  eax, ebx
    shl  eax, 4
    lea  r12, [rel acpi_irqmap_io]
    add  r12, rax
    lea  rdi, [rel str_irqmap_io]
    call serial_string
    mov  edi, ebx
    call acpi_serial_dec
    lea  rdi, [rel str_irqmap_eq]
    call serial_string
    movzx edi, byte [r12 + 12]
    call acpi_serial_dec
    lea  rdi, [rel str_irqmap_at]
    call serial_string
    mov  edi, [r12]
    call acpi_serial_hex
    lea  rdi, [rel str_irqmap_gsi]
    call serial_string
    mov  edi, [r12 + 4]
    call acpi_serial_dec
    lea  rdi, [rel str_irqmap_dash]
    call serial_string
    lea  rdi, [rel str_irqmap_unread]
    cmp  dword [r12 + 8], IRQMAP_UNREAD
    je   .io_end
    mov  edi, [r12 + 8]
    call acpi_serial_dec
    jmp  .io_next
.io_end:
    call serial_string
.io_next:
    inc  ebx
    jmp  .io
.iso:
    lea  rdi, [rel str_irqmap_iso]
    call serial_string
    cmp  dword [rel acpi_irqmap_iso_mask], 0
    jne  .iso_list
    lea  rdi, [rel str_irqmap_none]
    call serial_string
    jmp  .nmi
.iso_list:
    xor  ebx, ebx
    xor  r13d, r13d                        ; printed count, for separators
.iso_src:
    cmp  ebx, 16
    jae  .nmi
    bt   dword [rel acpi_irqmap_iso_mask], ebx
    jnc  .iso_next
    test r13d, r13d
    jz   .iso_first
    lea  rdi, [rel str_acpi_comma]
    call serial_string
.iso_first:
    inc  r13d
    mov  edi, ebx
    call acpi_serial_dec
    lea  rdi, [rel str_irqmap_gt]
    call serial_string
    lea  rax, [rel acpi_irqmap_iso_gsi]
    mov  edi, [rax + rbx*4]
    call acpi_serial_dec
    lea  rdi, [rel str_irqmap_flags]
    call serial_string
    lea  rax, [rel acpi_irqmap_iso_flags]
    movzx edi, word [rax + rbx*2]
    call acpi_serial_hex
.iso_next:
    inc  ebx
    jmp  .iso_src
.nmi:
    lea  rdi, [rel str_irqmap_nmi]
    call serial_string
    mov  edi, [rel acpi_irqmap_nmi]
    call acpi_serial_dec
    lea  rdi, [rel str_irqmap_lnmi]
    call serial_string
    mov  edi, [rel acpi_irqmap_lnmi]
    call acpi_serial_dec
    lea  rdi, [rel str_irqmap_sci]
    call serial_string
    lea  rax, [rel acpi_table_state]
    cmp  byte [rax + 2], AF_VALID
    jne  .sci_unknown
    lea  rax, [rel acpi_table_ptrs]
    mov  rax, [rax + 16]
    cmp  dword [rax + 4], 48
    jb   .sci_unknown
    movzx ebx, word [rax + 46]             ; FADT SCI_INT
    mov  r12d, ebx                         ; GSI
    cmp  ebx, 16
    jae  .sci_print
    bt   dword [rel acpi_irqmap_iso_mask], ebx
    jnc  .sci_print
    lea  rax, [rel acpi_irqmap_iso_gsi]
    mov  r12d, [rax + rbx*4]
.sci_print:
    mov  edi, ebx
    call acpi_serial_dec
    lea  rdi, [rel str_irqmap_gt]
    call serial_string
    mov  edi, r12d
    call acpi_serial_dec
    lea  rdi, [rel str_irqmap_covered]
    call serial_string
    xor  r13d, r13d
    xor  r8d, r8d                          ; an unread IOAPIC leaves coverage unknown
.cover:
    cmp  r13d, [rel acpi_irqmap_io_count]
    jae  .cover_pic
    mov  eax, r13d
    shl  eax, 4
    lea  rcx, [rel acpi_irqmap_io]
    add  rcx, rax
    cmp  dword [rcx + 8], IRQMAP_UNREAD
    je   .cover_unread
    cmp  r12d, [rcx + 4]
    jb   .cover_next
    cmp  r12d, [rcx + 8]
    ja   .cover_next
    lea  rdi, [rel str_irqmap_io_bare]
    call serial_string
    mov  edi, r13d
    call acpi_serial_dec
    jmp  .redir
.cover_unread:
    mov  r8d, 1
.cover_next:
    inc  r13d
    jmp  .cover
.cover_pic:
    lea  rdi, [rel str_acpi_unknown]
    test r8d, r8d
    jnz  .cover_out
    lea  rdi, [rel str_irqmap_none]
    cmp  dword [rel acpi_irqmap_io_count], 0  ; as the SCI owner: the 8259 route only without IOAPICs
    jne  .cover_out
    cmp  byte [rel acpi_irqmap_pcat], 1
    jne  .cover_out
    cmp  ebx, 16
    jae  .cover_out
    cmp  r12d, ebx
    jne  .cover_out
    lea  rdi, [rel str_irqmap_pic]
.cover_out:
    call serial_string
    jmp  .redir
.sci_unknown:
    lea  rdi, [rel str_acpi_unknown]
    call serial_string
.redir:
    lea  rdi, [rel str_irqmap_redir]
    call serial_string
.end:
    call serial_newline
    pop  r13
    pop  r12
    pop  rbx
    ret

str_irqmap_head: db "[PAOS64] irqmap v=1", 0
str_irqmap_lapic_off: db " lapic=disabled", 0
str_irqmap_lapic_x: db " lapic=xapic", 0
str_irqmap_lapic_x2: db " lapic=x2apic", 0
str_irqmap_imr: db " imr=", 0
str_irqmap_slash: db "/", 0
str_irqmap_absent: db " madt=absent", 0
str_irqmap_invalid: db " madt=invalid", 0
str_irqmap_pcat: db " pcat=", 0
str_irqmap_ioapics: db " ioapics=", 0
str_irqmap_io: db " io", 0
str_irqmap_io_bare: db "io", 0
str_irqmap_eq: db "=", 0
str_irqmap_at: db "@0x", 0
str_irqmap_gsi: db ":gsi", 0
str_irqmap_dash: db "-", 0
str_irqmap_unread: db "unread", 0
str_irqmap_iso: db " iso=", 0
str_irqmap_none: db "none", 0
str_irqmap_gt: db ">", 0
str_irqmap_flags: db "/0x", 0
str_irqmap_nmi: db " nmi=", 0
str_irqmap_lnmi: db " lnmi=", 0
str_irqmap_sci: db " sci=", 0
str_irqmap_covered: db " covered=", 0
str_irqmap_pic: db "pic", 0
str_irqmap_redir: db " redirection=unowned", 0

%macro WDATA_bus_acpi_irqmap 0
align 8
acpi_irqmap_state:
acpi_irqmap_io: times IRQMAP_MAX_IOAPICS*16 db 0  ; addr, gsi base, inclusive gsi end, id
acpi_irqmap_iso_gsi: times 16 dd 0
acpi_irqmap_iso_flags: times 16 dw 0
acpi_irqmap_io_count: dd 0
acpi_irqmap_iso_mask: dd 0
acpi_irqmap_nmi: dd 0
acpi_irqmap_lnmi: dd 0
acpi_irqmap_pcat: db 0
acpi_irqmap_complete: db 0             ; 1 only after a whole MADT parse (cleared with the state)
acpi_irqmap_state_end:
%endmacro
WDATA_DEFER WDATA_bus_acpi_irqmap

; RCQ-27 generic FADT fixed-feature button. Qualified native event arming;
; no AML/control-method button, SCI mode transition or platform assumption.
; BEGIN SCI POLLED ROUTE
; The native kernel has no SCI ISR. A fixed-event polling owner must hold the
; firmware-described SCI route masked before ACPI_ENABLE, not enable an unknown
; inherited interrupt. No vector/destination/trigger/polarity or unrelated IRQ is
; programmed. Discovery is bounded and read-only until the complete plan passes.
; EDI=qualified FADT SCI_INT. EAX=0 prepared, -1 unknown/unsupported.
acpi_sci_prepare:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12d, edi
    mov byte [rel acpi_sci_held], 0
    mov byte [rel acpi_sci_io_changed], 0
    mov byte [rel acpi_sci_pic_changed], 0
    mov word [rel acpi_sci_pic_port], 0
    mov qword [rel acpi_sci_io_base], 0
    mov dword [rel acpi_sci_count], 0
    mov dword [rel acpi_sci_iso_seen], 0
    mov dword [rel acpi_sci_nmi_count], 0
    test r12d, r12d
    jz .bad
    lea rdi, [rel acpi_sci_isa]
    xor ecx, ecx
.isa:
    mov [rdi+rcx*4], ecx
    inc ecx
    cmp ecx, 16
    jb .isa
    mov edi, 'APIC'
    call acpi_find_table
    test rax, rax
    jz .bad
    mov r13, rax
    mov rdi, rax
    mov esi, 'APIC'
    call acpi_validate_sdt
    cmp eax, AF_VALID
    jne .bad
    cmp ecx, 44
    jb .bad
    lea r14, [r13+rcx]
    test dword [r13+40], 1            ; PCAT_COMPAT: SCI_INT is an ISA source
    jz .no_pic
    cmp r12d, 16
    jae .bad
    ; Native PIT/keyboard/cascade/mouse routes are never claimed as SCI.
    mov eax, 0x1007
    bt eax, r12d
    jc .bad
    mov eax, r12d
    and eax, 7
    mov ecx, eax
    mov eax, 1
    shl eax, cl
    mov [rel acpi_sci_pic_bit], al
    mov eax, 0x21
    cmp r12d, 8
    jb .pic_port
    mov eax, 0xa1
.pic_port:
    mov [rel acpi_sci_pic_port], ax
.no_pic:
    lea r15, [r13+44]
    mov ebx, AF_MAX_ENTRIES
.record:
    cmp r15, r14
    je .parsed
    ja .bad
    dec ebx
    js .bad
    lea rax, [r15+2]
    cmp rax, r14
    ja .bad
    movzx ecx, byte [r15+1]
    cmp ecx, 2
    jb .bad
    lea rax, [r15+rcx]
    cmp rax, r14
    ja .bad
    cmp byte [r15], 1
    je .ioapic
    cmp byte [r15], 2
    je .iso
    cmp byte [r15], 3
    je .nmi
    cmp byte [r15], 6                ; IOSAPIC/platform-source models unowned
    je .bad
    cmp byte [r15], 8
    je .bad
.next:
    movzx eax, byte [r15+1]
    add r15, rax
    jmp .record
.ioapic:
    cmp ecx, 12
    jne .bad
    mov eax, [rel acpi_sci_count]
    cmp eax, 8
    jae .bad
    shl eax, 4
    lea rdi, [rel acpi_sci_controllers]
    add rdi, rax
    mov eax, [r15+4]
    cmp eax, 4096
    jb .bad
    test eax, 4095
    jnz .bad
    mov [rdi], rax
    mov eax, [r15+8]
    mov [rdi+8], eax
    inc dword [rel acpi_sci_count]
    jmp .next
.nmi:
    cmp ecx, 8
    jne .bad
    mov eax, [rel acpi_sci_nmi_count]
    cmp eax, 32
    jae .bad
    lea rdi, [rel acpi_sci_nmis]
    mov edx, [r15+4]
    mov [rdi+rax*4], edx
    inc dword [rel acpi_sci_nmi_count]
    jmp .next
.iso:
    cmp ecx, 10
    jne .bad
    cmp byte [r15+2], 0              ; ISA bus only
    jne .bad
    movzx ecx, byte [r15+3]
    cmp ecx, 16
    jae .bad
    bts dword [rel acpi_sci_iso_seen], ecx
    jc .bad
    movzx eax, word [r15+8]
    test eax, ~15
    jnz .bad
    mov edx, eax
    and edx, 3
    cmp edx, 2
    je .bad
    and eax, 12
    cmp eax, 8
    je .bad
    cmp ecx, r12d
    jne .iso_store
    ; An explicit MADT override may describe an active-high level SCI (Dell
    ; Latitude 5490: flags 0x000d). Both defined polarities are admissible;
    ; reserved encodings were rejected above. This polling owner changes only
    ; the mask, preserving inherited polarity/trigger/vector/destination.
    cmp eax, 4
    je .bad
.iso_store:
    lea rdi, [rel acpi_sci_isa]
    mov eax, [r15+4]
    mov [rdi+rcx*4], eax
    jmp .next
.parsed:
    cmp word [rel acpi_sci_pic_port], 0
    je .gsi
    lea rdi, [rel acpi_sci_isa]
    mov eax, [rdi+r12*4]
    mov r13d, r12d                  ; original ISA source for alias exclusion
    mov r12d, eax
    jmp .aliases
.gsi:
    mov r13d, -1                    ; non-PCAT SCI_INT already is a GSI
.aliases:
    xor ecx, ecx
    lea rdi, [rel acpi_sci_nmis]
.nmi_alias:
    cmp ecx, [rel acpi_sci_nmi_count]
    jae .isa_aliases
    cmp r12d, [rdi+rcx*4]
    je .bad
    inc ecx
    jmp .nmi_alias
.isa_aliases:
    xor ecx, ecx
    lea rdi, [rel acpi_sci_isa]
.alias:
    cmp ecx, r13d
    je .alias_next
    cmp r12d, [rdi+rcx*4]
    je .bad                         ; never mask a different ISA owner's route
.alias_next:
    inc ecx
    cmp ecx, 16
    jb .alias
    mov [rel acpi_sci_gsi], r12d
    xor ebx, ebx
.controller:
    cmp ebx, [rel acpi_sci_count]
    jae .controllers_done
    mov eax, ebx
    shl eax, 4
    lea r15, [rel acpi_sci_controllers]
    add r15, rax
    mov rdi, [r15]
    mov esi, 32                     ; selector and window within qualified MMIO
    mov edx, 1
    call acpi_range
    jc .bad
    mov rdi, [r15]
    mov esi, 1                      ; IOAPICVER, no redirection mutation
    call acpi_sci_io_read
    test al, al
    jz .bad
    cmp al, 255
    je .bad
    shr eax, 16
    and eax, 255
    cmp eax, 119                    ; 8-bit IOREGSEL redirection register extent
    ja .bad
    add eax, [r15+8]
    jc .bad
    mov [r15+12], eax               ; inclusive GSI end
    xor ecx, ecx
.overlap:
    cmp ecx, ebx
    jae .coverage
    mov eax, ecx
    shl eax, 4
    lea rdi, [rel acpi_sci_controllers]
    add rdi, rax
    mov rax, [rdi]
    cmp rax, [r15]
    je .bad
    mov eax, [rdi+12]
    cmp eax, [r15+8]
    jb .separate
    mov eax, [r15+12]
    cmp eax, [rdi+8]
    jae .bad
.separate:
    inc ecx
    jmp .overlap
.coverage:
    cmp r12d, [r15+8]
    jb .controller_next
    cmp r12d, [r15+12]
    ja .controller_next
    mov rax, [r15]
    mov [rel acpi_sci_io_base], rax
    mov eax, r12d
    sub eax, [r15+8]
    lea eax, [rax*2+0x10]
    mov [rel acpi_sci_io_index], eax
.controller_next:
    inc ebx
    jmp .controller
.controllers_done:
    cmp qword [rel acpi_sci_io_base], 0
    jne .ok
    cmp dword [rel acpi_sci_count], 0
    jne .bad                         ; no controller covers the SCI GSI
    cmp word [rel acpi_sci_pic_port], 0
    je .bad
    cmp r12d, r13d
    jne .bad                         ; PIC-only route must be identity
.ok:
    xor eax, eax
    jmp .out
.bad:
    mov eax, -1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Caller serializes the whole handoff with IF saved/clear. Record only mask bits
; introduced by this owner; unrelated live mask bits survive both RMW and unwind.
acpi_sci_hold:
    push rbx
    movzx edi, word [rel acpi_sci_pic_port]
    test edi, edi
    jz .io
    call acpi_sci_read8
    mov [rel acpi_sci_pic_old], al
    test al, [rel acpi_sci_pic_bit]
    jnz .io
    mov byte [rel acpi_sci_pic_changed], 1
    or al, [rel acpi_sci_pic_bit]
    movzx esi, al
    movzx edi, word [rel acpi_sci_pic_port]
    call acpi_sci_write8
.io:
    cmp qword [rel acpi_sci_io_base], 0
    je .held
    mov rdi, [rel acpi_sci_io_base]
    mov esi, [rel acpi_sci_io_index]
    call acpi_sci_io_read
    mov [rel acpi_sci_io_old], eax
    mov ebx, eax
    mov rdi, [rel acpi_sci_io_base]
    mov esi, [rel acpi_sci_io_index]
    inc esi
    call acpi_sci_io_read
    mov [rel acpi_sci_io_high], eax
    test ebx, 0x10000
    jnz .held
    mov byte [rel acpi_sci_io_changed], 1
    mov edi, [rel acpi_sci_io_index]
    mov esi, ebx
    or esi, 0x10000
    call acpi_sci_io_write
.held:
    mov byte [rel acpi_sci_held], 1
    call acpi_sci_check
    test eax, eax
    jz .out
    call acpi_sci_release             ; no firmware command has been issued yet
    test eax, eax
    jnz .unknown
    mov eax, -1
    jmp .out
.unknown:
    mov eax, -2
.out:
    pop rbx
    ret

; EAX=0 only while the SCI masks and inherited configuration still hold.
acpi_sci_check:
    cmp byte [rel acpi_sci_held], 1
    jne .bad
    movzx edi, word [rel acpi_sci_pic_port]
    test edi, edi
    jz .io
    call acpi_sci_read8
    test al, [rel acpi_sci_pic_bit]
    jz .bad
.io:
    cmp qword [rel acpi_sci_io_base], 0
    je .ok
    mov rdi, [rel acpi_sci_io_base]
    mov esi, [rel acpi_sci_io_index]
    call acpi_sci_io_read
    test eax, 0x10000
    jz .bad
    xor eax, [rel acpi_sci_io_old]
    and eax, ~0x15000                ; mask + read-only delivery/remote IRR bits
    jnz .bad
    mov rdi, [rel acpi_sci_io_base]
    mov esi, [rel acpi_sci_io_index]
    inc esi
    call acpi_sci_io_read
    cmp eax, [rel acpi_sci_io_high]
    jne .bad
.ok:
    xor eax, eax
    ret
.bad:
    mov eax, -1
    ret

; Safe only before a mode command, after observed legacy rollback, or for an
; inherited ACPI mode with no newly enabled fixed event. Restore only our masks.
acpi_sci_release:
    push rbx
    xor ebx, ebx
    cmp byte [rel acpi_sci_io_changed], 1
    jne .pic
    mov rdi, [rel acpi_sci_io_base]
    mov esi, [rel acpi_sci_io_index]
    call acpi_sci_io_read
    mov esi, eax
    and esi, ~0x10000
    mov edi, [rel acpi_sci_io_index]
    call acpi_sci_io_write
    mov rdi, [rel acpi_sci_io_base]
    mov esi, [rel acpi_sci_io_index]
    call acpi_sci_io_read
    test eax, 0x10000
    jnz .io_failed
    mov byte [rel acpi_sci_io_changed], 0
    jmp .pic
.io_failed:
    mov ebx, -1
.pic:
    cmp byte [rel acpi_sci_pic_changed], 1
    jne .out
    movzx edi, word [rel acpi_sci_pic_port]
    call acpi_sci_read8
    movzx ecx, byte [rel acpi_sci_pic_bit]
    not ecx
    and eax, ecx
    mov esi, eax
    movzx edi, word [rel acpi_sci_pic_port]
    call acpi_sci_write8
    movzx edi, word [rel acpi_sci_pic_port]
    call acpi_sci_read8
    test al, [rel acpi_sci_pic_bit]
    jnz .pic_failed
    mov byte [rel acpi_sci_pic_changed], 0
    jmp .out
.pic_failed:
    mov ebx, -1
.out:
    test ebx, ebx
    jnz .result
    mov byte [rel acpi_sci_held], 0
.result:
    mov eax, ebx
    pop rbx
    ret

; Cleanup could not establish ownership. Contain only the prepared SCI route;
; preserve its saved preimage for diagnosis instead of recapturing it as ours.
acpi_sci_contain:
    movzx edi, word [rel acpi_sci_pic_port]
    test edi, edi
    jz .io
    call acpi_sci_read8
    or al, [rel acpi_sci_pic_bit]
    movzx esi, al
    movzx edi, word [rel acpi_sci_pic_port]
    call acpi_sci_write8
.io:
    cmp qword [rel acpi_sci_io_base], 0
    je .out
    mov rdi, [rel acpi_sci_io_base]
    mov esi, [rel acpi_sci_io_index]
    call acpi_sci_io_read
    mov esi, eax
    or esi, 0x10000
    mov edi, [rel acpi_sci_io_index]
    call acpi_sci_io_write
.out:
    ret

; Only these leaves touch PIC / IOAPIC. Preserve IOREGSEL and incoming IF even
; outside the caller's handoff section. Production accesses are 32-bit MMIO.
acpi_sci_read8:
    mov edx, edi
    xor eax, eax
    in al, dx
    ret
acpi_sci_write8:
    mov edx, edi
    mov eax, esi
    out dx, al
    ret
acpi_sci_io_read:
    pushfq
    cli
    mov ecx, [rdi]
    mov [rdi], esi
    mov eax, [rdi+16]
    mov [rdi], ecx
    popfq
    ret
; EDI=qualified selector, ESI=value; base is from the complete prepared plan.
acpi_sci_io_write:
    pushfq
    cli
    mov rdx, [rel acpi_sci_io_base]
    mov ecx, [rdx]
    mov [rdx], edi
    mov [rdx+16], esi
    mov [rdx], ecx
    popfq
    ret

%macro WDATA_bus_acpi_sci 0
align 8
acpi_sci_io_base: dq 0
acpi_sci_controllers: times 8*16 db 0
acpi_sci_isa: times 16 dd 0
acpi_sci_nmis: times 32 dd 0
acpi_sci_nmi_count: dd 0
acpi_sci_io_index: dd 0
acpi_sci_io_old: dd 0
acpi_sci_io_high: dd 0
acpi_sci_count: dd 0
acpi_sci_gsi: dd 0
acpi_sci_iso_seen: dd 0
acpi_sci_pic_port: dw 0
acpi_sci_pic_bit: db 0
acpi_sci_pic_old: db 0
acpi_sci_pic_changed: db 0
acpi_sci_io_changed: db 0
acpi_sci_held: db 0
%endmacro
WDATA_DEFER WDATA_bus_acpi_sci
; END SCI POLLED ROUTE

ACPI_BUTTON_BIT equ 0x100
ACPI_BUTTON_MS equ 100
; RDI=qualified FADT, RSI=available full extent -> packed PM1a/b event IO ports
; or -2 unsupported/malformed. V1 supports 4-byte blocks (16-bit status/enable),
; GAS SystemIO,width32,offset0,access0/2/3. Admit access3 for the event block;
; its status/enable halves still use word IO (ACPI6.5 4.8.1.1,4.8.3.1.1-2).
; MMIO/other widths are explicit
; refusals: no numerical address is mistaken for an authorized mapping.
acpi_fixed_button_decode:
    cld
    test rdi, rdi
    jz .bad
    mov rax, rdi
    add rax, rsi
    jc .bad
    cmp rsi, 116
    jb .bad
    cmp dword [rdi], 'FACP'
    jne .bad
    mov r8d, [rdi+4]
    cmp r8d, 116
    jb .bad
    cmp r8d, AF_MAX_TABLE
    ja .bad
    cmp r8, rsi
    ja .bad
    cmp byte [rdi+88], 4
    jne .bad
    test dword [rdi+112], 0x100010       ; HW_REDUCED or control-method button
    jnz .bad
    mov eax, [rdi+56]
    mov edx, 148
    call .select
    test rax, rax
    jle .bad                           ; mandatory PM1a, never truncate -2
    mov r11d, eax
    mov eax, [rdi+60]
    mov edx, 160
    call .select
    cmp rax, -2
    je .bad
    test eax, eax
    jz .pack
    mov ecx, eax
    sub ecx, r11d
    add ecx, 3
    cmp ecx, 6
    jbe .bad                           ; two four-byte event blocks overlap
.pack:
    shl eax, 16
    or eax, r11d
    ret
.select:
    cmp r8d, edx
    jbe .port
    lea ecx, [rdx+12]
    cmp r8d, ecx
    jb .invalid                        ; partial GAS is not absence
    mov rcx, [rdi+rdx+4]
    test rcx, rcx
    jz .port                           ; zero X address -> independent legacy
    mov rax, rcx
    cmp byte [rdi+rdx], 1
    jne .invalid
    cmp byte [rdi+rdx+1], 32
    jne .invalid
    cmp byte [rdi+rdx+2], 0
    jne .invalid
    cmp byte [rdi+rdx+3], 0
    je .port
    cmp byte [rdi+rdx+3], 2
    je .port
    cmp byte [rdi+rdx+3], 3
    jne .invalid                       ; word IO never spans status and enable
.port:
    test rax, rax
    jz .selected
    cmp rax, 0xfffc
    ja .invalid                        ; entire status+enable block fits IO
.selected:
    ret
.invalid:
    mov rax, -2
    ret
.bad:
    mov rax, -2
    ret

; Once per boot, qualified unique FADT + existing full checksum/range parser.
acpi_fixed_button_init:
    push rbx
    cmp byte [rel acpi_fixed_button_state], 0
    jne .state
    mov byte [rel acpi_fixed_button_state], 2
    mov edi, 'FACP'
    call acpi_find_table
    test rax, rax
    jz .state
    mov rbx, rax
    mov rdi, rax
    mov esi, 'FACP'
    call acpi_validate_sdt
    cmp eax, AF_VALID
    jne .state
    mov rdi, rbx
    mov esi, ecx
    call acpi_fixed_button_decode
    cmp rax, -2
    je .state
    mov [rel acpi_fixed_button_ports], eax
    call acpi_fixed_button_arm
    test rax, rax
    jnz .state
    mov byte [rel acpi_fixed_button_state], 1
.state:
    mov rax, -2
    cmp byte [rel acpi_fixed_button_state], 1
    jne .out
    xor eax, eax
.out:
    pop rbx
    ret

; At most two qualified blocks. Preserve every unrelated enable bit; on
; readback refusal attempt rollback of only newly owned button enables. Clear an
; observed stale button status before newly enabling it, never other W1C bits.
; State remains unsupported until both blocks qualify; reentry cannot poll a
; partially armed device. An already enabled pending event is left for poll.
acpi_fixed_button_arm:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r14d, [rel acpi_fixed_button_ports]
    mov ebx, r14d
    xor r12d, r12d                    ; enables introduced by this attempt
    xor r13d, r13d
.block:
    movzx edi, bx
    test edi, edi
    jz .next
    add edi, 2
    call acpi_fixed_button_read16
    test eax, ACPI_BUTTON_BIT
    jnz .next
    mov r15d, eax
    movzx edi, bx
    call acpi_fixed_button_read16
    test eax, ACPI_BUTTON_BIT
    jz .enable
    movzx edi, bx
    mov esi, ACPI_BUTTON_BIT
    call acpi_fixed_button_write16
.enable:
    bts r12d, r13d
    mov [rel acpi_fixed_button_owned], r12b
    movzx edi, bx
    add edi, 2
    mov esi, r15d
    or esi, ACPI_BUTTON_BIT
    call acpi_fixed_button_write16
    movzx edi, bx
    add edi, 2
    call acpi_fixed_button_read16
    test eax, ACPI_BUTTON_BIT
    jz .refuse
.next:
    shr ebx, 16
    inc r13d
    cmp r13d, 2
    jb .block
    mov [rel acpi_fixed_button_owned], r12b
    xor eax, eax
    jmp .out
.refuse:
    mov ebx, r14d
    xor r13d, r13d
.rollback:
    bt r12d, r13d
    jnc .rollback_next
    movzx edi, bx
    add edi, 2
    call acpi_fixed_button_read16
    mov esi, eax
    and esi, ~ACPI_BUTTON_BIT
    movzx edi, bx
    add edi, 2
    call acpi_fixed_button_write16
.rollback_next:
    shr ebx, 16
    inc r13d
    cmp r13d, 2
    jb .rollback
    mov rax, -2
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Retire only PWRBTN_EN bits introduced by this owner. Never clear an inherited
; enable or unrelated event bit. Caller has stopped polling and serialized IF.
acpi_fixed_button_disarm:
    push rbx
    push r12
    xor r12d, r12d
    mov ebx, [rel acpi_fixed_button_ports]
.block:
    movzx eax, byte [rel acpi_fixed_button_owned]
    bt eax, r12d
    jnc .next
    movzx edi, bx
    add edi, 2
    call acpi_fixed_button_read16
    mov esi, eax
    and esi, ~ACPI_BUTTON_BIT
    movzx edi, bx
    add edi, 2
    call acpi_fixed_button_write16
    movzx edi, bx
    add edi, 2
    call acpi_fixed_button_read16
    test eax, ACPI_BUTTON_BIT
    jnz .failed
.next:
    shr ebx, 16
    inc r12d
    cmp r12d, 2
    jb .block
    mov byte [rel acpi_fixed_button_owned], 0
    mov byte [rel acpi_fixed_button_state], 2
    xor eax, eax
    jmp .out
.failed:
    mov eax, -1
.out:
    pop r12
    pop rbx
    ret

; Native access seams: only qualified 16-bit IO ports reach these. Host controls
; replace these two leaves with isolated RW enable / W1C status registers.
acpi_fixed_button_read16:
    mov edx, edi
    xor eax, eax
    in ax, dx
    ret
acpi_fixed_button_write16:
    mov edx, edi
    mov eax, esi
    out dx, ax
    ret

; ->1 one new observed enabled press,0 none/debounced,-2 unsupported,-8 clock.
; At most four reads/two W1C writes per100ms. Held/reasserted status is acked,
; but requests no second prompt until an observed clear sample rearms the edge.
acpi_fixed_button_poll:
    cld
    push rbx
    push r12
    push r13
    mov al, 1
    xchg al, [rel acpi_fixed_button_busy]
    test al, al
    jnz .busy
    mov rax, -2
    cmp byte [rel acpi_fixed_button_state], 1
    jne .out
    call boot_ms_now
    test rax, rax
    jz .clock
    cmp rax, [rel acpi_fixed_button_clock]
    jb .clock
    mov [rel acpi_fixed_button_clock], rax
    cmp rax, [rel acpi_fixed_button_next]
    jb .none
    add rax, ACPI_BUTTON_MS
    jc .clock
    mov [rel acpi_fixed_button_next], rax
    xor r12d, r12d
    mov ebx, [rel acpi_fixed_button_ports]
    mov r13d, 2
.block:
    movzx edi, bx
    test edi, edi
    jz .next
    call acpi_fixed_button_read16
    test eax, ACPI_BUTTON_BIT
    jz .next
    movzx edi, bx
    add edi, 2
    call acpi_fixed_button_read16
    test eax, ACPI_BUTTON_BIT
    jz .next
    movzx edi, bx
    mov esi, ACPI_BUTTON_BIT
    call acpi_fixed_button_write16       ; only observed supported W1C bit
    mov r12d, 1
.next:
    shr ebx, 16
    dec r13d
    jnz .block
    test r12d, r12d
    jz .release
    xor eax, eax
    cmp byte [rel acpi_fixed_button_latched], 0
    setz al
    mov byte [rel acpi_fixed_button_latched], 1
    jmp .out
.release:
    mov byte [rel acpi_fixed_button_latched], 0
.none:
    xor eax, eax
    jmp .out
.clock:
    mov rax, -8
.out:
    mov byte [rel acpi_fixed_button_busy], 0
.return:
    pop r13
    pop r12
    pop rbx
    cld
    ret
.busy:
    mov rax, -3
    jmp .return

%macro WDATA_bus_acpi_fixed_button 0
align 8
acpi_fixed_button_state: db 0           ;0unknown,1supported,2unsupported
acpi_fixed_button_latched: db 0
acpi_fixed_button_busy: db 0
acpi_fixed_button_owned: db 0
align 4
acpi_fixed_button_ports: dd 0
acpi_fixed_button_clock: dq 0
acpi_fixed_button_next: dq 0
%endmacro
WDATA_DEFER WDATA_bus_acpi_fixed_button

; Read-only projection of the existing admitted working-state ownership.
; The policy in gui/power_exec still exclusively sets these facts. No ACPI
; enable, SCI hold, port discovery or event acknowledgement occurs here.
; EAX=state | fresh SCI_EN<<8; states other than2 perform no port I/O.
acpi_ownership_snapshot:
    movzx eax, byte [rel power_button_ownership_state]
    cmp  eax, 2
    jne  .out
    movzx edi, word [rel power_button_ownership_pm1]
    call acpi_fixed_button_read16
    and  eax, 1
    shl  eax, 8
    or   eax, 2
.out:
    ret
%macro WDATA_bus_acpi_ownership 0
align 4
power_button_ownership_pm1: dd 0
power_button_ownership_state: db 0
%endmacro
WDATA_DEFER WDATA_bus_acpi_ownership
