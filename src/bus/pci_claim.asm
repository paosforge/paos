;; MODULE bus/pci_claim
;; LAYER 2
;; EXPORTS pci_claim_snapshot, pci_claim, pci_claim_bdf3, pci_claim_packed16, pci_claim_find, pci_claim_count, pci_claim_drv_name, pci_claim_tbl, pci_claim_n, pci_claim_dropped
;; IMPORTS core/lock
;; CAPS
;; OWNER saga:bus
;; LOCK: pci_claim_lock PROTECTS pci_claim_tbl, pci_claim_n, pci_claim_dropped
; ============================================================================
; bus/pci_claim.asm — RCQ-29 hardware report: which driver took which PCI function.
;
; bus/pci is a pure enumerator and keeps no device table (pci.asm:22), and each
; driver records its own BDF in its own format.  So a report could only guess
; "driver chosen / missing" from class codes.  Instead every PCI driver states
; it: once it has taken a function (BOUND), or matched one and then given up
; (FAILED), it calls pci_claim with its driver id.  Nothing else reads or acts
; on this table; it is a record for the read-only hardware report
; (svc/hw_report).  A function no driver claimed is reported as driver=none.
;
; Entry (16 bytes): +0 dd bdf (bus<<8 | dev<<3 | fn), +4 dd driver id,
;                   +8 dd state, +12 dd claim sequence.
; A second claim of the same BDF replaces the first (a driver that binds, then
; fails, ends FAILED); the table holds PCI_CLAIM_MAX functions and counts the rest.
; ============================================================================

%include "core/abi/pci_claim.inc" ; PCI_CLAIM_BOUND/FAILED, PCI_DRV_* (append-only ids)

PCI_CLAIM_MAX     equ 32
PCI_CLAIM_ENT     equ 16

; pci_claim(EDI=bus, ESI=dev, EDX=fn, ECX=driver id, R8D=state).
;   Records or replaces the claim for that function.  Preserves every general
;   register (drivers call it from the middle of their bind paths); flags clobbered.
pci_claim:
    push rax
    push rbx
    push rdi
    push r9
    push r10
    mov  ebx, edi
    and  ebx, 0xFF
    shl  ebx, 8
    mov  eax, esi
    and  eax, 0x1F
    shl  eax, 3
    or   ebx, eax
    mov  eax, edx
    and  eax, 7
    or   ebx, eax                           ; ebx = packed bdf
    lea  rdi, [rel pci_claim_lock]
    call spin_acquire
    lea  r9, [rel pci_claim_tbl]
    mov  r10d, [rel pci_claim_n]
    xor  eax, eax
.find:
    cmp  eax, r10d
    jae  .append
    cmp  [r9], ebx
    je   .store
    add  r9, PCI_CLAIM_ENT
    inc  eax
    jmp  .find
.append:
    cmp  r10d, PCI_CLAIM_MAX
    jae  .full
    inc  dword [rel pci_claim_n]
.store:
    mov  [r9], ebx
    mov  [r9 + 4], ecx
    mov  [r9 + 8], r8d
    inc  dword [rel pci_claim_seq]
    mov  eax, [rel pci_claim_seq]
    mov  [r9 + 12], eax
    jmp  .out
.full:
    inc  dword [rel pci_claim_dropped]
.out:
    lea  rdi, [rel pci_claim_lock]
    call spin_release
    pop  r10
    pop  r9
    pop  rdi
    pop  rbx
    pop  rax
    ret

; pci_claim_bdf3(RDI=&{dd bus, dd dev, dd fn}, ECX=driver id, R8D=state) — the
;   form most drivers keep their BDF in.  Preserves every general register.
pci_claim_bdf3:
    push rdi
    push rsi
    push rdx
    mov  rdx, rdi
    mov  edi, [rdx]
    mov  esi, [rdx + 4]
    mov  edx, [rdx + 8]
    call pci_claim
    pop  rdx
    pop  rsi
    pop  rdi
    ret

; pci_claim_packed16(EDI=bus<<16 | dev<<8 | fn, ECX=driver id, R8D=state) — the
;   rtl8125/rtl8126 BDF form.  Preserves every general register.
pci_claim_packed16:
    push rdi
    push rsi
    push rdx
    mov  edx, edi
    and  edx, 0xFF
    mov  esi, edi
    shr  esi, 8
    and  esi, 0xFF
    shr  edi, 16
    and  edi, 0xFF
    call pci_claim
    pop  rdx
    pop  rsi
    pop  rdi
    ret

; pci_claim_find(EDI=packed bdf) -> EAX = driver id (0 = unclaimed), EDX = state.
;   clobbers RAX, RDX, RCX, R8, RDI.
pci_claim_find:
    push rdi
    lea  rdi, [rel pci_claim_lock]
    call spin_acquire
    pop  rdi
    lea  r8, [rel pci_claim_tbl]
    mov  ecx, [rel pci_claim_n]
    xor  eax, eax
    xor  edx, edx
.loop:
    test ecx, ecx
    jz   .done
    cmp  [r8], edi
    je   .hit
    add  r8, PCI_CLAIM_ENT
    dec  ecx
    jmp  .loop
.hit:
    mov  eax, [r8 + 4]
    mov  edx, [r8 + 8]
.done:
    push rax
    lea  rdi, [rel pci_claim_lock]
    call spin_release
    pop  rax
    ret

; pci_claim_snapshot(RDI=512-byte destination) -> EAX=count<=32,
; EDX bit0=dropped claims, bit1=invalid/overflowed count. Read-only under the
; existing claim lock. The caller validates identities/states and duplicates.
pci_claim_snapshot:
    push rbx
    push r12
    mov  rbx, rdi
    lea  rdi, [rel pci_claim_lock]
    call spin_acquire
    xor  edx, edx
    cmp  dword [rel pci_claim_dropped], 0
    setne dl
    mov  r12d, [rel pci_claim_n]
    cmp  r12d, PCI_CLAIM_MAX
    jbe  .copy
    mov  r12d, PCI_CLAIM_MAX
    or   edx, 2
.copy:
    mov  rdi, rbx
    lea  rsi, [rel pci_claim_tbl]
    lea  ecx, [r12d * 2]
    cld
    rep  movsq
    lea  rdi, [rel pci_claim_lock]
    call spin_release
    mov  eax, r12d
    pop  r12
    pop  rbx
    ret

; pci_claim_count -> EAX = claims recorded (not counting dropped ones).
pci_claim_count:
    mov  eax, [rel pci_claim_n]
    ret

; pci_claim_drv_name(EDI=driver id) -> RAX = NUL-terminated name ("?" if unknown).
;   Names are fixed 8-byte slots (no absolute pointers in data: the image relocates).
pci_claim_drv_name:
    lea  rax, [rel pci_claim_str_unknown]
    cmp  edi, 1
    jb   .out
    cmp  edi, PCI_DRV_LAST
    ja   .out
    lea  rax, [rel pci_claim_names]
    lea  rax, [rax + rdi*8 - 8]
.out:
    ret

; --- bus/pci_claim data ---
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
%macro WDATA_bus_pci_claim_0 0
pci_claim_lock:    db 0
align 8
pci_claim_n:       dd 0
pci_claim_dropped: dd 0
pci_claim_seq:     dd 0
align 8
pci_claim_tbl:     times PCI_CLAIM_MAX * PCI_CLAIM_ENT db 0
%endmacro
WDATA_DEFER WDATA_bus_pci_claim_0

pci_claim_names:                    ; PCI_DRV_* order, 8 bytes each (7 chars + NUL)
    db "ahci", 0, 0, 0, 0
    db "nvme", 0, 0, 0, 0
    db "vmd", 0, 0, 0, 0, 0
    db "e1000e", 0, 0
    db "rtl8125", 0
    db "rtl8126", 0
    db "rtl8168", 0
    db "xhci", 0, 0, 0, 0
pci_claim_str_unknown: db "?", 0
