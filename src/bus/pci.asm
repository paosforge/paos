;; MODULE bus/pci
;; LAYER 2
;; EXPORTS pci_cfg_quarantine, pci_inventory_read32, pci_inventory_diag_begin, pci_inventory_diag_finish, pci_inventory_diag_active, pci_inventory_diag_done, pci_inventory_diag_original, pci_inventory_diag_first, pci_inventory_diag_repeat, pci_ecam_resolve_span, pci_ext_find_cap, pci_aer_snapshot, pci_cfg_read32, pci_cfg_write32, pci_scan_with_filter, pci_cfg_same_bar_roundtrip, pci_selftest, pci_lock_audit, pci_dev_count
;; IMPORTS boot/serial, core/lib/fmt, core/lock
;; CAPS
;; OWNER saga:bus
;; LOCK: pci_lock PROTECTS pci_dev_count
; ============================================================================
; bus/pci.asm — PCI configuration-space enumeration (legacy CF8/CFC mechanism).
;
; The bus-layer root: a callback-driven sweep of every (bus,dev,fn) that a present
; function exists at, so higher layers (dev/net, dev/blk, ...) discover their chips
; by class/vendor without each re-walking config space. Uses the legacy port-I/O
; config mechanism (0xCF8 address / 0xCFC data) — universally present on x86 and
; sufficient for QEMU's i440fx/q35 and every target box; MCFG/ECAM (MMIO config,
; needs ACPI) is a later increment, not required to enumerate.
;
; Multi-function aware: fn0's header-type bit7 says "this device has functions
; 1..7"; without it we would miss the AHCI/SMBus/etc. functions PIIX-class bridges
; pack behind one device. Absent functions read vendor==0xFFFF and are skipped.
;
; The scan is a PURE enumerator: it calls a caller-supplied filter callback per
; present function and holds NO device table itself (that's each class core's job).
; ============================================================================

PCI_CFG_ADDR      equ 0xCF8                 ; config address port (dword)
PCI_CFG_DATA      equ 0xCFC                 ; config data port (dword)
PCI_ENABLE        equ 0x80000000            ; CONFIG_ADDRESS enable bit (bit31)
PCI_VENDOR_NONE   equ 0xFFFF                 ; absent function reads all-ones vendor

; HP242 lab recorder of config writes to the selected xHCI function. Absent
; unless the lab build selects it (validated in hp_ep0_witness_lab_profile.inc).
%ifndef PAOS_LAB_HP_PCICMD_PROVENANCE
%define PAOS_LAB_HP_PCICMD_PROVENANCE 0
%endif

; PCI_CFG_SERIALIZATION_BEGIN
; The CF8 selector is shared by all CPUs. Keep selection+data indivisible and
; exclude local interrupts while holding it (an ISR must not wait on its own
; interrupted holder). No callback or wait other than the finite port pair.
%macro PCI_CFG_ENTER 0
    pushfq
    cli
%%spin:
    mov eax,1
    xchg eax,[rel pci_cfg_io_lock]
    test eax,eax
    jz %%held
    pause
    jmp %%spin
%%held:
%endmacro
%macro PCI_CFG_LEAVE 0
    mov dword [rel pci_cfg_io_lock],0
    popfq
%endmacro
; PCI_CFG_SERIALIZATION_END

; pci_cfg_read32(EDI=bus, ESI=dev, EDX=fn, ECX=offset) -> EAX = config dword.
;   Builds CONFIG_ADDRESS = enable | bus<<16 | dev<<11 | fn<<8 | (offset & 0xFC),
;   writes it to 0xCF8, reads the dword back from 0xCFC.
;   clobbers: RAX,R8,RDX (port dx). Inputs otherwise preserved.
pci_cfg_read32:
    PCI_CFG_ENTER
%if PAOS_LAB_HP_PCICMD_PROVENANCE
    lock inc dword [rel pci_lab_cfg_seq]    ; before this CF8 selection
    lock inc dword [rel pci_lab_cfg_inflight]
%endif
    mov  eax, edi
    shl  eax, 16                            ; bus << 16
    mov  r8d, esi
    shl  r8d, 11                            ; dev << 11
    or   eax, r8d
    mov  r8d, edx
    shl  r8d, 8                             ; fn << 8  (edx consumed before dx reuse)
    or   eax, r8d
    mov  r8d, ecx
    and  r8d, 0xFC                          ; offset dword-aligned
    or   eax, r8d
    or   eax, PCI_ENABLE
    mov  dx, PCI_CFG_ADDR
    out  dx, eax                            ; select the config dword
    mov  dx, PCI_CFG_DATA
    in   eax, dx                            ; read it back
%if PAOS_LAB_HP_PCICMD_PROVENANCE
    lock dec dword [rel pci_lab_cfg_inflight]
%endif
    PCI_CFG_LEAVE
    ret

; pci_cfg_write32(EDI=bus, ESI=dev, EDX=fn, ECX=offset, R8D=value) -> writes value.
;   Mirrors pci_cfg_read32: builds CONFIG_ADDRESS = enable | bus<<16 | dev<<11 |
;   fn<<8 | (offset & 0xFC), writes it to 0xCF8, then writes the dword to 0xCFC.
;   This is the sanctioned way for L3 device backends (e1000e/rtl8168/ahci/nvme) to
;   set the PCI Command register bus-master + memory-space bits before DMA.
;   clobbers: RAX,R9,RDX (port dx). Value in R8D + other inputs otherwise preserved.
pci_cfg_write32:
%if PAOS_LAB_HP_PCICMD_PROVENANCE
    call pci_lab_cfgw_record                ; before either port write
%endif
    PCI_CFG_ENTER
%if PAOS_LAB_HP_PCICMD_PROVENANCE
    push rdx                                ; fn, for an overlap record
    push r10
    mov  r10d, 1
    lock xadd [rel pci_lab_cfg_inflight], r10d
    push r10                                ; other accesses already in flight
    mov  r10d, 1
    lock xadd [rel pci_lab_cfg_seq], r10d
    inc  r10d                               ; sequence including this selection
%endif
    push r8
    mov eax,edi
    shl eax,8
    mov r9d,esi
    shl r9d,3
    or eax,r9d
    or eax,edx
    cmp eax,65535
    ja .unfenced
    lea r9,[rel pci_cfg_quarantined]
    bt qword [r9],rax
    jnc .unfenced
    mov eax,ecx
    and eax,0xfc
    cmp eax,4
    jne .suppressed
    and r8d,0xfff8                        ; no RW1C status, IO/MEM/BME off
    or r8d,0x400                          ; INTx disabled
.unfenced:
    mov  eax, edi
    shl  eax, 16                            ; bus << 16
    mov  r9d, esi
    shl  r9d, 11                            ; dev << 11
    or   eax, r9d
    mov  r9d, edx
    shl  r9d, 8                             ; fn << 8  (edx consumed before dx reuse)
    or   eax, r9d
    mov  r9d, ecx
    and  r9d, 0xFC                          ; offset dword-aligned
    or   eax, r9d
    or   eax, PCI_ENABLE
    mov  dx, PCI_CFG_ADDR
    out  dx, eax                            ; select the config dword
    mov  eax, r8d                           ; value to write
    mov  dx, PCI_CFG_DATA
    out  dx, eax                            ; write it to config data
.suppressed:
    pop r8
%if PAOS_LAB_HP_PCICMD_PROVENANCE
    lock dec dword [rel pci_lab_cfg_inflight]
    cmp  r10d, [rel pci_lab_cfg_seq]
    jne  .lab_overlap                       ; another access began in this window
    cmp  dword [rsp], 0
    je   .lab_alone                         ; and none was in flight at entry
.lab_overlap:
    call pci_lab_cfgw_overlap
.lab_alone:
    add  rsp, 8
    pop  r10
    pop  rdx
%endif
    PCI_CFG_LEAVE
    ret

%if PAOS_LAB_HP_PCICMD_PROVENANCE
; pci_lab_cfgw_overlap — another pci_cfg_read32/write32 was in flight at this
;   write's entry or began before its data write, so CF8 may have been
;   reselected and the data gone to another function. Records {TSC, caller,
;   intended CONFIG_ADDRESS | 1, value} in a 4-slot ring. Frame: our return,
;   in-flight count, saved R10, saved fn, caller's return.
;   clobbers: RDX (pci_cfg_write32 clobbers it; its exit pop restores fn).
pci_lab_cfgw_overlap:
    push rax
    push rcx
    push r9
    mov  eax, edi
    shl  eax, 16
    mov  r9d, esi
    shl  r9d, 11
    or   eax, r9d
    mov  r9d, [rsp+48]                      ; fn (above RAX, RCX, R9, return, count, R10)
    shl  r9d, 8
    or   eax, r9d
    and  ecx, 0xFC
    or   eax, ecx
    or   eax, PCI_ENABLE | 1                ; bit0: overlapped (never set in CF8 addresses)
    mov  r9d, eax
    mov  eax, 1
    lock xadd [rel pci_lab_cfgw_overlaps], eax
    and  eax, PCI_LAB_CFGW_OVL_SLOTS - 1
    shl  eax, 5
    lea  rcx, [rel pci_lab_cfgw_ovl_ring]
    add  rcx, rax
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [rcx], rax
    mov  rax, [rsp+64]                      ; caller, above saved interrupt flags
    mov  [rcx+8], rax
    mov  [rcx+16], r9
    mov  eax, r8d
    mov  [rcx+24], rax
    pop  r9
    pop  rcx
    pop  rax
    ret

; pci_lab_cfgw_record — entered from pci_cfg_write32 with its inputs. When the
;   write's function (CONFIG_ADDRESS with offset 0) equals one of the
;   PCI_LAB_CFGW_ARMED pci_lab_cfgw_armed entries (0 = empty), takes a ring slot with lock xadd and stores TSC, pci_cfg_write32's caller
;   return address, the exact CONFIG_ADDRESS and the value. 16 slots wrap; the
;   total keeps counting. No port, MMIO, IF or serial access.
;   clobbers: RAX,R9 (pci_cfg_write32 clobbers both). Other inputs preserved.
pci_lab_cfgw_record:
    mov  r9d, [rel pci_lab_cfgw_armed]
    test r9d, r9d
    jz   .out                               ; disarmed
    push rcx
    push rdx
    mov  eax, edi
    shl  eax, 16                            ; same packing as pci_cfg_write32
    mov  ecx, esi
    shl  ecx, 11
    or   eax, ecx
    mov  ecx, edx
    shl  ecx, 8
    or   eax, ecx
    or   eax, PCI_ENABLE
    lea  rcx, [rel pci_lab_cfgw_armed]
    mov  r9d, PCI_LAB_CFGW_ARMED
.match:
    cmp  eax, [rcx]
    je   .hit
    add  rcx, 4
    dec  r9d
    jnz  .match
    jmp  .done                              ; not an armed function
.hit:
    mov  r9d, [rsp+8]                       ; caller's offset (saved RCX)
    and  r9d, 0xFC
    or   r9d, eax                           ; exact CONFIG_ADDRESS
    mov  eax, 1
    lock xadd [rel pci_lab_cfgw_total], eax
    and  eax, PCI_LAB_CFGW_SLOTS - 1
    shl  eax, 5                             ; 32-byte slot
    lea  rcx, [rel pci_lab_cfgw_ring]
    add  rcx, rax
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  [rcx], rax
    mov  rax, [rsp+24]                      ; above RDX, RCX and our return
    mov  [rcx+8], rax
    mov  [rcx+16], r9
    mov  eax, r8d
    mov  [rcx+24], rax
.done:
    pop  rdx
    pop  rcx
.out:
    ret
%endif

; pci_cfg_quarantine(RDI=first packed BDF, RSI=last inclusive) -> EAX1/0.
; Boot-local monotonic fence; no unquarantine API. Serializing publication with
; each writer drains earlier accesses. A later driver restore cannot re-enable
; decode/bus mastering or change BARs/reset state in this function range.
pci_cfg_quarantine:
    cmp rdi,65535
    ja .bad
    cmp rsi,65535
    ja .bad
    cmp rdi,rsi
    ja .bad
    PCI_CFG_ENTER
    mov rax,rdi
    lea r9,[rel pci_cfg_quarantined]
.loop:
    bts qword [r9],rax
    inc eax
    cmp eax,esi
    jbe .loop
    PCI_CFG_LEAVE
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; pci_ecam_resolve_span(RDI=trusted immutable mapped allocation array,
;   RSI=count0..4, RDX=segment0..65535, RCX=bus0..255,
;   R8=device0..31, R9=function0..7) -> RAX=physical function base,
;   ECX=4096, EDX=0 RESOLVED. Refusals clear RAX/ECX; EDX=1 ABSENT,
;   2 MALFORMED metadata/overlap/overflow, 3 BAD_REQUEST.
; Allocation wire is the existing ACPI MCFG 16-byte entry: Q base, W segment,
; B start, B end, D reserved0. Base corresponds to bus ZERO, not start bus.
; Validates the whole <=4-entry list before returning any candidate: nonzero
; 1MiB-aligned bases, ordered bus bounds, reserved0, nonwrapping exclusive
; allocation ends, disjoint physical ranges and same-segment bus ranges.
; Array pointer/span/lifetime must already be admitted by caller. No mapping,
; physical-width or firmware/resource ownership inference, device dereference,
; config read, AER enable or live caller. Only internal arithmetic groundwork.
pci_ecam_resolve_span:
    cmp rsi, 4
    ja .bad_request
    cmp rdx, 65535
    ja .bad_request
    cmp rcx, 255
    ja .bad_request
    cmp r8, 31
    ja .bad_request
    cmp r9, 7
    ja .bad_request
    test rsi, rsi
    jz .absent_empty
    test rdi, rdi
    jz .bad_request
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov rbx, rdi                       ; array
    mov rbp, rsi                       ; bounded count
    mov r12, rdx                       ; requested segment
    mov r13, rcx                       ; requested bus
    mov r14, rcx
    shl r14, 20
    shl r8, 15
    or r14, r8
    shl r9, 12
    or r14, r9                         ; bus0-relative function offset
    xor r15d, r15d                     ; unpublished match
    xor r10d, r10d                     ; current index
.next:
    mov rdi, r10
    shl rdi, 4
    add rdi, rbx
    mov rax, [rdi]
    test rax, rax
    jz .malformed
    test eax, 0xfffff
    jnz .malformed
    cmp dword [rdi+12], 0
    jne .malformed
    movzx ecx, byte [rdi+10]
    movzx edx, byte [rdi+11]
    cmp ecx, edx
    ja .malformed
    mov r8, rcx
    shl r8, 20
    add r8, rax                        ; actual allocation start
    jc .malformed
    inc edx
    mov r9, rdx
    shl r9, 20
    add r9, rax                        ; exclusive allocation end
    jc .malformed
    xor r11d, r11d
.previous:
    cmp r11, r10
    jae .select
    mov rsi, r11
    shl rsi, 4
    add rsi, rbx
    movzx ecx, byte [rsi+11]
    inc ecx
    shl rcx, 20
    add rcx, [rsi]                     ; prior entry already validated
    cmp r8, rcx
    jae .logical_overlap
    movzx ecx, byte [rsi+10]
    shl rcx, 20
    add rcx, [rsi]
    cmp rcx, r9
    jb .malformed                      ; intersecting physical apertures
.logical_overlap:
    mov ax, [rsi+8]
    cmp ax, [rdi+8]
    jne .other
    mov al, [rsi+10]
    cmp al, [rdi+11]
    ja .other
    mov al, [rdi+10]
    cmp al, [rsi+11]
    jbe .malformed                     ; overlapping buses in one segment
.other:
    inc r11d
    jmp .previous
.select:
    movzx eax, word [rdi+8]
    cmp rax, r12
    jne .advance
    movzx eax, byte [rdi+10]
    cmp r13, rax
    jb .advance
    movzx eax, byte [rdi+11]
    cmp r13, rax
    ja .advance
    mov r15, [rdi]
    add r15, r14                       ; contained by validated allocation
.advance:
    inc r10d
    cmp r10, rbp
    jb .next
    test r15, r15
    jz .absent
    mov rax, r15
    mov ecx, 4096
    xor edx, edx
    jmp .restore
.absent:
    mov edx, 1
    jmp .clear
.malformed:
    mov edx, 2
.clear:
    xor eax, eax
    xor ecx, ecx
.restore:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.absent_empty:
    mov edx, 1
    xor eax, eax
    xor ecx, ecx
    ret
.bad_request:
    mov edx, 3
    xor eax, eax
    xor ecx, ecx
    ret

; Additional caller-clobbered diagnostic results (both walker and AER snapshot):
; R8..R11 hold eight little-endian dwords, low then high per register:
; reason, attempted/rejected offset, last available header, its offset,
; exact reader EDX, header-valid(0/1), callback read count, reserved0.
; Only EDX=0 makes a header available, including raw all-ones. Reader failure
; retains the prior available header; raw EAX on reader error is unspecified.
; Reason: 0 none, 1 reader error, 2 all-ones header, 3 offset<100, 4 offset>ffc,
; 5 alignment, 6 walk budget, 7 cycle, 8 prefix span, 9 matched-next alignment,
; 10 matched-next<100, 11 prefix overlap, 12 header changed, 13 policy changed,
; 14 bad request. These diagnostics do not qualify a refusal or prove an event.
; Reason0 with ABSENT describes the existing qualified zero header/next result.
; No extra reads, retry or shared diagnostic state; each call overwrites results.
;
; pci_ext_find_cap(RDI=reader, RSI=opaque context, RDX=cap ID, RCX=min version)
;   Internal read-only extended-capability header walker. Reader is trusted code:
;     reader(RDI=context, ESI=dword offset) -> EAX=header, EDX=0 success/!0 error.
;   Reader preserves SysV callee-saved registers; other volatiles may change.
;   Return RAX=offset, ECX=raw header only on EDX=0 FOUND; otherwise both zero.
;   EDX: 0 FOUND, 1 ABSENT, 2 MALFORMED, 3 READ_ERROR, 4 BAD_REQUEST.
;   Desired ID must be 1..0xfffe and minimum version 1..15, full-width checked.
;   Starts at 0x100, admits aligned headers through 0xffc, and visits each dword
;   at most once using a per-call 128-byte bitmap. A zero header/next ends a list;
;   all-ones is an unavailable read, never evidence of absence or hardware quiet.
;   The first matching header with sufficient version is returned. Unknown IDs
;   and lower versions are skipped; unvisited suffixes and capability body spans
;   are NOT validated. 960 reads maximum, no allocation, retry, wait or recursion.
;   Used by pci_aer_snapshot below. Qualified extended config transport, mapping,
;   identity, ownership and error delivery remain separate work.
;   The legacy config accessor cannot supply this reader: it aliases above 256B.
pci_ext_find_cap:
    test rdi, rdi
    jz   .bad_request
    cmp  rdx, 1
    jb   .bad_request
    cmp  rdx, 0xfffe
    ja   .bad_request
    cmp  rcx, 1
    jb   .bad_request
    cmp  rcx, 15
    ja   .bad_request
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r13, rdi                           ; reader
    mov  r12, rsi                           ; context survives reader clobbers
    mov  r14d, edx                          ; desired ID
    mov  r15d, ecx                          ; minimum version
    sub  rsp, 168                          ; bitmap128 + diagnostic32 + alignment
    mov  rdi, rsp
    xor  eax, eax
    mov  ecx, 20
    rep stosq
    mov  ebx, 0x100
    mov  ebp, 960                          ; (4096-256)/4 header locations
.walk:
    mov  [rsp+132], ebx                    ; attempted/rejected config offset
    cmp  ebx, 0x100
    jb   .below
    cmp  ebx, 0xffc
    ja   .above
    test ebx, 3
    jnz  .unaligned
    test ebp, ebp
    jz   .budget
    dec  ebp
    mov  eax, ebx
    shr  eax, 2
    bts  qword [rsp], rax                   ; absolute dword index, within128B
    jc   .cycle                            ; reject cycle before duplicate read
    mov  rdi, r12
    mov  esi, ebx
    call r13
    mov  [rsp+144], edx                    ; exact reader result, even on error
    inc  dword [rsp+152]                   ; no additional config access
    test edx, edx
    jnz  .read_error
    mov  [rsp+136], eax                    ; last available extended header
    mov  [rsp+140], ebx
    mov  dword [rsp+148], 1
    cmp  eax, -1
    je   .all_ones
    test eax, eax
    jz   .absent
    mov  ecx, eax
    and  ecx, 0xffff
    cmp  ecx, r14d
    jne  .next
    mov  ecx, eax
    shr  ecx, 16
    and  ecx, 15
    cmp  ecx, r15d
    jb   .next
    mov  ecx, eax                          ; exact matched header
    mov  eax, ebx
    xor  edx, edx                          ; FOUND
    jmp  .done
.next:
    shr  eax, 20
    and  eax, 0xffc                        ; PCI_EXT_CAP_NEXT reserved low2 bits
    mov  ebx, eax
    test ebx, ebx
    jz   .absent
    jmp  .walk
.absent:
    mov  edx, 1
    jmp  .refuse
.below:
    mov  dword [rsp+128], 3
    jmp  .malformed
.above:
    mov  dword [rsp+128], 4
    jmp  .malformed
.unaligned:
    mov  dword [rsp+128], 5
    jmp  .malformed
.budget:
    mov  dword [rsp+128], 6
    jmp  .malformed
.cycle:
    mov  dword [rsp+128], 7
.malformed:
    mov  edx, 2
    jmp  .refuse
.all_ones:
    mov  dword [rsp+128], 2
    jmp  .unreadable
.read_error:
    mov  dword [rsp+128], 1
.unreadable:
    mov  edx, 3
.refuse:
    xor  eax, eax
    xor  ecx, ecx
.done:
    mov  r8, [rsp+128]
    mov  r9, [rsp+136]
    mov  r10, [rsp+144]
    mov  r11, [rsp+152]
    add  rsp, 168
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret
.bad_request:
    mov  r8d, 14
    xor  r9d, r9d
    xor  r10d, r10d
    xor  r11d, r11d
    xor  eax, eax
    xor  ecx, ecx
    mov  edx, 4
    ret

; pci_aer_snapshot(RDI=reader, RSI=context, RDX=output, RCX=capacity) -> EAX=status.
;   Same trusted reader ABI as pci_ext_find_cap; context may be null. Output is
;   caller-owned writable PRIVATE storage (64 bytes minimum), not a shared record.
;   Status: 0 READ, 1 ABSENT, 2 MALFORMED, 3 READ_ERROR, 4 BAD_REQUEST, 5 CHANGED.
;   Every refusal leaves output untouched. Success writes exactly 64 bytes:
;     +0 cap offset, +4 header, +8 Uncorrectable Status, +12 Mask, +16 Severity,
;     +20 Correctable Status, +24 Mask, +28 AER Capabilities/Control,
;     +32..47 four raw Header Log dwords, +48 unmasked correctable bits,
;     +52 unmasked nonfatal bits, +56 unmasked fatal bits, +60 reserved zero.
;   Finds ID1/version>=1; bounds the common prefix through cap+0x28 inclusive.
;   Matched next header must be aligned/in range and outside this prefix. The
;   suffix is not walked/validated. Rechecks header, masks and severity before
;   publication; changed policy fails closed without retry. At most 974 reads.
;   Status/log reads are sequential, NOT an atomic hardware event or event count.
;   No clear/ack, reporting enable, recovery, root-port registers or MMIO here.
;   Raw reserved bits are retained; derived bitmaps apply the raw masks/severity,
;   not a claim that every bit is a defined error. Header Log validity is not
;   inferred. Qualified transport/identity/ownership remain the caller's job.
pci_aer_snapshot:
    test rdi, rdi
    jz   .bad_request
    test rdx, rdx
    jz   .bad_request
    cmp  rcx, 64
    jb   .bad_request
    mov  rax, rdx
    add  rax, 63
    jc   .bad_request
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 104                          ; private record64 + diagnostic32 + alignment
    mov  r12, rdi                          ; reader
    mov  r13, rsi                          ; opaque context
    mov  r14, rdx                          ; output, untouched until publication
    mov  edx, 1                            ; AER extended capability
    mov  ecx, 1
    call pci_ext_find_cap
    mov  [rsp+64], r8
    mov  [rsp+72], r9
    mov  [rsp+80], r10
    mov  [rsp+88], r11
    test edx, edx
    jnz  .walker_refused
    mov  ebx, eax                          ; cap offset
    cmp  ebx, 0xfd4                        ; cap+0x28 dword fits through 0xfff
    ja   .prefix_span
    mov  eax, ecx
    shr  eax, 20
    and  eax, 0xffc                        ; reserved NEXT bits are ignored
    test eax, eax
    jz   .span_valid
    test eax, 3
    jnz  .next_unaligned
    cmp  eax, 0x100
    jb   .next_below
    cmp  eax, ebx
    jb   .span_valid
    lea  edx, [rbx+0x2c]
    cmp  eax, edx
    jb   .next_overlap                     ; next aliases this common prefix
.span_valid:
    mov  [rsp], ebx
    mov  [rsp+4], ecx
    mov  ebp, 4                            ; register offset relative to AER
.read_body:
    lea  esi, [rbx+rbp]
    mov  rdi, r13
    call .read_config
    test edx, edx
    jnz  .read_error
    mov  [rsp+rbp+4], eax                  ; +4 -> output+8; +0x28 -> +44
    add  ebp, 4
    cmp  ebp, 0x28
    jbe  .read_body
    mov  rdi, r13
    mov  esi, ebx
    call .read_config
    test edx, edx
    jnz  .read_error
    mov  [rsp+72], eax                     ; header recheck is itself available
    mov  [rsp+76], ebx
    cmp  eax, -1
    je   .all_ones
    cmp  eax, [rsp+4]
    jne  .header_changed
    ; Re-read Mask/Severity and Correctable Mask. Status can change naturally;
    ; these policy registers must match the policy used for pending bitmaps.
    mov  ebp, 8
.check_policy:
    lea  esi, [rbx+rbp]
    mov  rdi, r13
    call .read_config
    test edx, edx
    jnz  .read_error
    cmp  eax, [rsp+rbp+4]
    jne  .policy_changed
    cmp  ebp, 8
    je   .check_severity
    cmp  ebp, 12
    je   .check_correctable_mask
    mov  eax, [rsp+24]
    not  eax
    and  eax, [rsp+20]
    mov  [rsp+48], eax
    mov  eax, [rsp+12]
    not  eax
    and  eax, [rsp+8]                      ; unmasked uncorrectable status
    mov  ecx, [rsp+16]
    mov  edx, eax
    and  edx, ecx
    mov  [rsp+56], edx
    not  ecx
    and  eax, ecx
    mov  [rsp+52], eax
    mov  dword [rsp+60], 0
    mov  rdi, r14
    mov  rsi, rsp
    mov  ecx, 8
    rep movsq
    xor  eax, eax
    jmp  .done
.check_severity:
    mov  ebp, 12
    jmp  .check_policy
.check_correctable_mask:
    mov  ebp, 20
    jmp  .check_policy
.walker_refused:
    mov  eax, edx
    jmp  .done
.prefix_span:
    mov  dword [rsp+64], 8
    jmp  .malformed
.next_unaligned:
    mov  dword [rsp+64], 9
    jmp  .malformed
.next_below:
    mov  dword [rsp+64], 10
    jmp  .malformed
.next_overlap:
    mov  dword [rsp+64], 11
.malformed:
    mov  eax, 2
    jmp  .done
.all_ones:
    mov  dword [rsp+64], 2
    jmp  .unreadable
.read_error:
    mov  dword [rsp+64], 1
.unreadable:
    mov  eax, 3
    jmp  .done
.header_changed:
    mov  dword [rsp+64], 12
    jmp  .changed
.policy_changed:
    mov  dword [rsp+64], 13
.changed:
    mov  eax, 5
.done:
    mov  r8, [rsp+64]
    mov  r9, [rsp+72]
    mov  r10, [rsp+80]
    mov  r11, [rsp+88]
    add  rsp, 104
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret
; Record the same callback, not another access. Parent RSP is local RSP+8;
; R15 survives the trusted reader's permitted clobbers, retaining exact offset.
.read_config:
    mov  r15d, esi
    sub  rsp, 8
    call r12
    add  rsp, 8
    mov  [rsp+8+68], r15d
    mov  [rsp+8+80], edx
    inc  dword [rsp+8+88]
    ret
.bad_request:
    mov  r8d, 14
    xor  r9d, r9d
    xor  r10d, r10d
    xor  r11d, r11d
    mov  eax, 4
    ret

; pci_scan_with_filter(RDI=callback) — sweep bus 0..255, dev 0..31, fn 0..7.
;   For each PRESENT function calls callback(EDI=bus,ESI=dev,EDX=fn,ECX=vendev),
;   where vendev = dword at config offset 0 (vendor in low 16, device in high 16).
;   The callback follows SysV internal ABI (preserves RBX,RBP,R12-R15 — this scan
;   keeps its loop state there). Multi-function scan only when fn0 header-type bit7.
pci_scan_with_filter:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r15, rdi                           ; r15 = callback
    xor  r12d, r12d                         ; r12 = bus
.bus_loop:
    xor  r13d, r13d                         ; r13 = dev
.dev_loop:
    ; --- function 0 ---
    mov  edi, r12d
    mov  esi, r13d
    xor  edx, edx                           ; fn 0
    xor  ecx, ecx                           ; offset 0 (vendor/device)
    call pci_inventory_read32
    mov  r14d, eax                          ; r14 = vendev(fn0)
    mov  ebp, eax
    and  ebp, 0xFFFF
    cmp  ebp, PCI_VENDOR_NONE
    je   .next_dev                          ; no function 0 -> no device here
    ; present: fire callback for fn0
    mov  edi, r12d
    mov  esi, r13d
    xor  edx, edx
    mov  ecx, r14d
    call r15
    ; --- multifunction? header type (offset 0x0C, byte 2) bit7 ---
    mov  edi, r12d
    mov  esi, r13d
    xor  edx, edx
    mov  ecx, 0x0C
    call pci_inventory_read32
    shr  eax, 16                            ; byte 2 = header type -> low byte of eax
    test al, 0x80
    jz   .next_dev                          ; single-function device
    ; --- functions 1..7 ---
    mov  ebx, 1                             ; fn index
.fn_loop:
    mov  edi, r12d
    mov  esi, r13d
    mov  edx, ebx
    xor  ecx, ecx
    call pci_inventory_read32
    mov  ebp, eax
    and  ebp, 0xFFFF
    cmp  ebp, PCI_VENDOR_NONE
    je   .fn_next                           ; this function absent
    mov  edi, r12d
    mov  esi, r13d
    mov  edx, ebx
    mov  ecx, eax
    call r15
.fn_next:
    inc  ebx
    cmp  ebx, 8
    jb   .fn_loop
.next_dev:
    ; Finish the diagnostic at this device's enumeration boundary, even when
    ; fn0 was absent/single-function. No extra IO for ordinary inventories or
    ; other callers. All original scan reads/decisions have already occurred.
    test r12d, r12d
    jnz .diag_done
    cmp r13d, 3
    jne .diag_done
    call pci_inventory_diag_finish
.diag_done:
    inc  r13d
    cmp  r13d, 32
    jb   .dev_loop
    inc  r12d
    cmp  r12d, 256
    jb   .bus_loop
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Optional, synchronous PCISCAN CFG instrumentation. Does NOT replace the
; config backend or change scan admission. No hardware read status is supplied
; by CF8/CFC: raw zero/all-ones/stability are never classified as read success.
; All storage is private to the one non-interleaved command dispatch.
; Wrapper preserves the pci_cfg_read32 ABI (except its declared volatiles).
pci_inventory_read32:
    cmp byte [rel pci_inventory_diag_active], 1
    jne pci_cfg_read32
    test edi, edi
    jnz pci_cfg_read32
    cmp esi, 3
    jne pci_cfg_read32
    cmp edx, 7
    ja pci_cfg_read32
    cmp ecx, 0
    je .offset0
    cmp ecx, 8
    je .offset8
    cmp ecx, 12
    jne pci_cfg_read32
    mov eax, 2
    jmp .index
.offset0:
    xor eax, eax
    jmp .index
.offset8:
    mov eax, 1
.index:
    push rbx
    imul ebx, edx, 3
    add ebx, eax
    call pci_cfg_read32
    ; Retain the FIRST actual scan/PCISCAN callback read, not the later repeat.
    bts qword [rel pci_inventory_diag_original], rbx
    jc .done
    lea r8, [rel pci_inventory_diag_first]
    mov [r8+rbx*4], eax
.done:
    pop rbx
    ret

; Called only AFTER a valid CFG argument, before its ordinary full walk.
pci_inventory_diag_begin:
    mov qword [rel pci_inventory_diag_original], 0
    mov byte [rel pci_inventory_diag_done], 0
    mov byte [rel pci_inventory_diag_active], 1
    ret

; Capture any not-consumed DWORDs as supplementary (original bit remains zero)
; and one repeat of every offset, exactly 24..48 additional CF8 reads maximum.
; This is at the end of 00:03's scan, not after scanning all the other buses.
; No mapping/config writes or guessed physical addresses/ECAM dereferences.
pci_inventory_diag_finish:
    cmp byte [rel pci_inventory_diag_active], 1
    jne .idle
    mov byte [rel pci_inventory_diag_active], 0
    push rbx
    push r12
    push r13
    push r14
    push r15
    xor r12d, r12d                       ; fn 0..7
    lea r14, [rel pci_inventory_diag_first]
    lea r15, [rel pci_inventory_diag_repeat]
.fn:
    xor r13d, r13d                       ; offsets 00/08/0c
.offset:
    imul ebx, r12d, 3
    add ebx, r13d
    bt qword [rel pci_inventory_diag_original], rbx
    jc .repeat
    xor edi, edi
    mov esi, 3
    mov edx, r12d
    lea rcx, [rel pci_inventory_diag_offsets]
    movzx ecx, byte [rcx+r13]
    call pci_cfg_read32
    mov [r14+rbx*4], eax
.repeat:
    xor edi, edi
    mov esi, 3
    mov edx, r12d
    lea rcx, [rel pci_inventory_diag_offsets]
    movzx ecx, byte [rcx+r13]
    call pci_cfg_read32
    mov [r15+rbx*4], eax
    inc r13d
    cmp r13d, 3
    jb .offset
    inc r12d
    cmp r12d, 8
    jb .fn
    mov byte [rel pci_inventory_diag_done], 1
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
.idle:
    ret

align 8
pci_inventory_diag_original: dq 0
pci_inventory_diag_active: db 0
pci_inventory_diag_done: db 0
pci_inventory_diag_offsets: db 0,8,12
align 4
pci_inventory_diag_first: times 24 dd 0
pci_inventory_diag_repeat: times 24 dd 0

; pci_count_cb — filter used by the self-test: count every present function.
;   (EDI,ESI,EDX,ECX) ignored; must preserve RBX,RBP,R12-R15 (scan loop state).
pci_count_cb:
    inc  qword [rel pci_dev_count]
    ; Record a known Intel NIC BAR for the SAFE config-space round-trip below.
    ; QEMU e1000 (100e) and Lenovo I219-V (15bc) both expose MMIO BAR0 at 0x10.
    ; ECX = vendev (vendor low16, device high16).
    cmp  ecx, 0x100E8086
    je   .record_safe_bar
    cmp  ecx, 0x15BC8086
    jne  .anchor_checks
.record_safe_bar:
    cmp  qword [rel pci_safe_bar_bdf], -1    ; first match only
    jne  .anchor_checks
    mov  r8d, edi
    shl  r8d, 16                             ; bus  << 16
    mov  r9d, esi
    shl  r9d, 8                              ; dev  << 8
    or   r8d, r9d
    or   r8d, edx                            ; | fn
    mov  [rel pci_safe_bar_bdf], r8           ; packed (bus<<16)|(dev<<8)|fn
.anchor_checks:
    ; Lenovo M720s witness: UHD630, xHCI, SATA, I219-V, and NVMe.
    cmp  ecx, 0x3E918086
    jne  .anchor_xhci
    or   byte [rel pci_lenovo_anchor_mask], 0x01
    jmp  .cb_ret
.anchor_xhci:
    cmp  ecx, 0xA36D8086
    jne  .anchor_sata
    or   byte [rel pci_lenovo_anchor_mask], 0x02
    jmp  .cb_ret
.anchor_sata:
    cmp  ecx, 0xA3528086
    jne  .anchor_i219
    or   byte [rel pci_lenovo_anchor_mask], 0x04
    jmp  .cb_ret
.anchor_i219:
    cmp  ecx, 0x15BC8086
    jne  .anchor_nvme
    or   byte [rel pci_lenovo_anchor_mask], 0x08
    jmp  .cb_ret
.anchor_nvme:
    cmp  ecx, 0xF1A68086
    jne  .cb_ret
    or   byte [rel pci_lenovo_anchor_mask], 0x10
.cb_ret:
    ret

; pci_selftest — run a full scan counting present functions, assert N>=1, and
;   emit the enumeration marker "[PAOS64] PCI scan: N devices found".
pci_selftest:
    mov  qword [rel pci_dev_count], 0
    mov  qword [rel pci_safe_bar_bdf], -1
    mov  byte [rel pci_lenovo_anchor_mask], 0
    lea  rdi, [rel pci_count_cb]
    call pci_scan_with_filter
    mov  rax, [rel pci_dev_count]
    test rax, rax
    jz   .none                              ; a PCI machine has >=1 function
    lea  rdi, [rel str_pci_pfx]
    call serial_string
    mov  rdi, [rel pci_dev_count]
    lea  rsi, [rel pci_numbuf]
    call fmt_dec
    lea  rdi, [rel pci_numbuf]
    call serial_string
    lea  rdi, [rel str_pci_sfx]
    call serial_string
    cmp  byte [rel pci_lenovo_anchor_mask], 0x1F
    jne  .no_lenovo_marker
    lea  rdi, [rel str_pci_lenovo]
    call serial_string                       ; earned only from all five M720s IDs
.no_lenovo_marker:
    call pci_write_selftest                  ; safe same-value BAR write/read-back
    ret
.none:
    lea  rdi, [rel str_pci_none]
    call serial_string
    ret

; pci_cfg_same_bar_roundtrip — idempotent config-space write proof for 1117b.
;   Read BAR0 (offset 0x10) from the known Intel NIC, write back the EXACT dword
;   just read, then independently read it again. This never touches the
;   Command/Status dword (Status is W1C), never performs BAR sizing, and never
;   toggles MSI/MSI-X or live-device state.
;   Returns CF=0 on exact read-back; CF=1 if no suitable BAR or mismatch.
;   Retains before/after in pci_safe_bar_{before,after} for command projection.
pci_cfg_same_bar_roundtrip:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rax, [rel pci_safe_bar_bdf]
    cmp  rax, -1
    je   .roundtrip_fail
    mov  r12d, eax
    shr  r12d, 16
    and  r12d, 0xFF                          ; r12 = bus
    mov  r13d, eax
    shr  r13d, 8
    and  r13d, 0xFF                          ; r13 = dev
    mov  r14d, eax
    and  r14d, 0xFF                          ; r14 = fn
    ; Read the assigned BAR value. Reject absent, unassigned, and I/O BARs.
    mov  edi, r12d
    mov  esi, r13d
    mov  edx, r14d
    mov  ecx, 0x10
    call pci_cfg_read32
    mov  r15d, eax
    mov  [rel pci_safe_bar_before], eax
    test eax, eax
    jz   .roundtrip_fail
    cmp  eax, 0xFFFFFFFF
    je   .roundtrip_fail
    test al, 1                               ; BAR0 must be memory, not I/O
    jnz  .roundtrip_fail
    ; Idempotent store: write the exact assigned BAR dword back unchanged.
    mov  edi, r12d
    mov  esi, r13d
    mov  edx, r14d
    mov  ecx, 0x10
    mov  r8d, r15d
    call pci_cfg_write32
    ; Independently select and read the same dword.
    mov  edi, r12d
    mov  esi, r13d
    mov  edx, r14d
    mov  ecx, 0x10
    call pci_cfg_read32
    mov  [rel pci_safe_bar_after], eax
    cmp  eax, r15d
    jne  .roundtrip_fail
    clc
    jmp  .roundtrip_done
.roundtrip_fail:
    stc
.roundtrip_done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Emit the existing cfg-write marker only after the safe same-value proof.
pci_write_selftest:
    call pci_cfg_same_bar_roundtrip
    jc   .wr_done
    lea  rdi, [rel str_pci_wr_ok]
    call serial_string
.wr_done:
    ret

; ============================================================================
; 1075 SMP lock-SITE retro-audit. bus/pci shipped (1005) before the 1003 lock
; discipline; its scan-result state (pci_dev_count, mutated by the scan callback
; pci_count_cb) had no declared protecting lock. pci_lock is that retro-declared
; lock, reusing the ONE spin primitive (core/lock.asm). pci_lock_audit exercises
; the SITE once around a guarded write of pci_dev_count. Returns EAX = exercised
; count (1); the bus coverage line is aggregated + printed by hal_lock_audit.
; ============================================================================
pci_lock_acquire:
    lea  rdi, [rel pci_lock]
    call spin_acquire
    ret
pci_lock_release:
    lea  rdi, [rel pci_lock]
    call spin_release
    ret
pci_lock_audit:
    call pci_lock_acquire                    ; --- enter the critical section ---
    inc  qword [rel pci_dev_count]            ; guarded shared write ...
    dec  qword [rel pci_dev_count]            ; ... restored (net-zero)
    inc  qword [rel pci_audit_exercised]      ; count the real acquire/release cycle
    call pci_lock_release                     ; --- leave the critical section ---
    mov  eax, 1
    ret

; --- bus/pci data ---
pci_lock:            db 0                     ; retro-declared lock over pci_dev_count (1075)
align 8
pci_audit_exercised: dq 0
pci_dev_count: dq 0
pci_safe_bar_bdf: dq -1                       ; packed Intel NIC BDF, -1 = none
pci_safe_bar_before: dd 0                     ; BAR0 before exact same-value write
pci_safe_bar_after:  dd 0                     ; independent BAR0 read-back
pci_lenovo_anchor_mask: db 0                  ; all five real M720s IDs observed
%if PAOS_LAB_HP_PCICMD_PROVENANCE
PCI_LAB_CFGW_SLOTS equ 16
PCI_LAB_CFGW_ARMED equ 4
align 8
pci_lab_cfgw_armed: times PCI_LAB_CFGW_ARMED dd 0 ; CONFIG_ADDRESS functions, [0]=0 disarmed
pci_lab_cfgw_total: dd 0                      ; recorded writes, ring index source
pci_lab_cfgw_handoff_tsc: dq 0                ; armed function's legacy handoff done
pci_lab_cfgw_ring: times PCI_LAB_CFGW_SLOTS * 32 db 0 ; TSC, caller, address, value
PCI_LAB_CFGW_OVL_SLOTS equ 4
pci_lab_cfg_seq: dd 0                         ; CF8 selections by pci_cfg_read32/write32
pci_lab_cfg_inflight: dd 0                    ; accesses between entry and data access
pci_lab_cfgw_overlaps: dd 0                   ; writes whose window saw another selection
pci_lab_cfgw_ovl_ring: times PCI_LAB_CFGW_OVL_SLOTS * 32 db 0
%endif
pci_numbuf:    times 24 db 0
str_pci_pfx:   db "[PAOS64] M2 pci: scan complete [pci.scan.complete] devices=", 0
str_pci_sfx:   db "", 13, 10, 0
str_pci_none:  db "[PAOS64] M2 pci: enumeration FAILED (0 present functions)", 13, 10, 0
str_pci_wr_ok: db "[PAOS64] M2 pci: cfg write32 read-back verified [pci.cfg.write.ok]", 13, 10, 0
str_pci_lenovo: db "[PAOS64] M2 pci: Lenovo M720s anchor inventory verified [pci.scan.baremetal]", 13, 10, 0

; Containment state is zero-filled at boot, isolated from translated code.
%include "core/abi/wdata.inc"
%macro WDATA_pci_config_guard 0
alignb 8
pci_cfg_quarantined: resb 8192
%endmacro
WDATA_BSS_DEFER WDATA_pci_config_guard
