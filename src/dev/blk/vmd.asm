;; MODULE dev/blk/vmd
;; LAYER 3
;; EXPORTS vmd_child_identity_snapshot, vmd_selected_owner_snapshot, vmd_selected_owner_current, vmd_selected_root_snapshot, vmd_domain_create, vmd_find_child, vmd_selftest, vmd_root_count, vmd_child_count, vmd_bridge_count, vmd_refused_count, vmd_bus_start, vmd_ecam_base, vmd_ecam_mapped
;; IMPORTS boot/native_driver_gate, bus/pci, boot/serial, boot/paging, core/heap, core/lib/mem, bus/pci_claim
;; CAPS mmio
;; OWNER saga:storage
%include "core/abi/pci_claim.inc" ; RCQ-29 hardware report: bind outcome ids/states
; ============================================================================
; dev/blk/vmd.asm - Intel VMD (Volume Management Device) DOMAIN driver in front
; of the ahci/nvme block backends (desktop finding, 2026-09-08).
;
; Why: a board that maps its SATA/NVMe controllers under the Intel VMD root
; (MSI Z890: root 8086:ad0b at 00:0e.0, the AHCI shown as "RST VMD Managed
; Controller" class 0880) hides them from the legacy CF8/CFC bus walk that
; dev/blk/ahci and dev/blk/nvme use. Their real config space lives ONLY in the
; VMD root BAR0 (CFGBAR = the child domain ECAM) and their BARs inside the
; root MEMBAR1 (32-bit) / MEMBAR2 (64-bit) windows. Peter ruled (9/08) that
; VMD-on is a normal user configuration, so PaOS changes, not the BIOS.
;
; What: (1) find a VMD root on the legacy bus (class 0104 / Intel / exact
; device-ID table); (2) enable it, size its CFGBAR, read VMCAP/VMCONFIG (the
; bus-offset setting is reported, not trusted: the ECAM is walked by INDEX, so
; the "setting 3" that Linux <= 6.8 refuses is harmless here); (3) walk the
; child ECAM exactly like the root walk - vendor, multi-function header, class -
; and for every class 01/06/01 (AHCI) or 01/08/02 (NVMe) function read the
; ABAR / BAR0, require it to be identity-reachable, set Memory Space + Bus
; Master through the child ECAM (16-bit Command write, never the RW1C Status
; half), and publish a child record; (4) dev/blk/ahci and dev/blk/nvme fall
; back to vmd_find_child when the legacy scan found nothing. Polling only: no
; child MSI/MSI-X is ever enabled, so the VMD interrupt remap is not needed.
;
; Reachability: boot/paging maps a 2 GiB window around a >16 GiB CFGBAR pre-EBS
; (the desktop CFGBAR is at 448 GiB; MEMBAR2 sits in the same window). A
; CFGBAR the window does not cover is refused loudly and no child is published.
;
; KAT: every boot first walks a 16 KiB synthetic child ECAM (64-byte functions;
; the walker takes its geometry as shifts) holding a good AHCI, a bridge, a
; 64-bit NVMe, an AHCI with an I/O BAR (refused) and a multi-function device
; whose fn1 NVMe BAR sits at 448 GiB (refused: no window in KAT mode). It also
; checks the enable RMW landed only on accepted children, then RESETS every
; table so synthetic children can never leak into the real scan.
; ============================================================================

VMD_CLASS24          equ 0x010400            ; class 01 / subclass 04 (RAID) / progIF 00
VMD_VENDOR_INTEL     equ 0x8086
VMD_ID_COUNT         equ 10
VMD_MAX_CHILDREN     equ 8
VMD_MAX_BUSES        equ 32                  ; 32 MiB CFGBAR = 32 x 1 MiB ECAM buses (cap)
VMD_REG_VMCAP        equ 0x40
VMD_REG_VMCONFIG     equ 0x44
VMD_CLASS_AHCI       equ 0x010601
VMD_CLASS_NVME       equ 0x010802
VMD_IDENTITY_GB      equ 16                  ; boot/paging identity map = 0..16 GiB
VMD_FLAG_KAT         equ 1                   ; walker: ignore the paging window (deterministic KAT)
VMD_ECAM_FN_SHIFT    equ 12                  ; real ECAM: bus<<20 | dev<<15 | fn<<12
VMD_ECAM_DEV_SHIFT   equ 15
VMD_ECAM_BUS_SHIFT   equ 20
VMD_KAT_FN_SHIFT     equ 6                   ; synthetic image: 64-byte functions
VMD_KAT_DEV_SHIFT    equ 9
VMD_KAT_BUS_SHIFT    equ 14
VMD_KAT_IMAGE_BYTES  equ (1 << VMD_KAT_BUS_SHIFT)   ; one bus = 16 KiB
                                                  ; (zeroed kernel-heap buffer, vmd_kat_base;
                                                  ;  was 16 KiB of image zero bytes)
%include "core/abi/heap_once.inc"
%include "core/abi/vmd_selected_owner.inc"
%include "core/abi/vmd_selected_root.inc"

struc vmd_child
  .cfg:      resq 1                          ; ECAM config base of the function
  .bar:      resq 1                          ; ABAR (AHCI BAR5) or BAR0 (NVMe), identity-reachable
  .class24:  resd 1                          ; class|sub|progif
  .bdf:      resd 1                          ; bus_index<<16 | dev<<8 | fn (bus index is ECAM-relative)
  .active:   resb 1
  .pci_id:   resd 1                          ; actual vendor/device read during walk (C3)
  .revision: resb 1                          ; actual class-register revision byte
  .pad:      resb 2
endstruc

; ---------------------------------------------------------------------------
; vmd_domain_create - KAT, then the real root scan + child ECAM walk. Called
; by fs/blockdev before nvme_blk_create / ahci_blk_create. Never fatal: with
; no root it prints one line and returns; with an unreachable CFGBAR it
; publishes nothing (VMD=1 VMD_CHILDREN=0 in STATUS says so).
; ---------------------------------------------------------------------------
vmd_domain_create:
    push rbx
    push r12
    push r13
    push r14
    push r15
    call vmd_selftest                       ; RAM-only KAT; leaves every table reset
    call vmd_reset_state
    lea  rdi, [rel vmd_detect_cb]
    call pci_scan_with_filter
    cmp  byte [rel vmd_root_count], 0
    je   .no_root

    ; --- the CFGBAR (child ECAM) must be identity-reachable ---
    mov  rax, [rel vmd_root_bar0]
    mov  [rel vmd_ecam_base], rax
    test rax, rax
    jz   .ecam_unmapped
    mov  rcx, rax
    shr  rcx, 30                            ; GiB index
    cmp  rcx, VMD_IDENTITY_GB
    jb   .ecam_ok
    mov  rdx, [rel vmd_window_gb]           ; boot/paging: 2 GiB window start (GiB index), 0 = none
    test rdx, rdx
    jz   .ecam_unmapped
    cmp  rcx, rdx
    je   .ecam_ok
    inc  rdx
    cmp  rcx, rdx
    jne  .ecam_unmapped
.ecam_ok:
    mov  byte [rel vmd_ecam_mapped], 1
    call vmd_size_cfgbar                    ; decode off -> size -> restore (nvme_remap sequence)

    ; --- enable Memory Space + Bus Master on the root ---
    mov  edi, [rel vmd_root_bus]
    mov  esi, [rel vmd_root_dev]
    mov  edx, [rel vmd_root_fn]
    mov  ecx, 0x04
    call pci_cfg_read32
    or   eax, 0x0006
    mov  r8d, eax
    mov  edi, [rel vmd_root_bus]
    mov  esi, [rel vmd_root_dev]
    mov  edx, [rel vmd_root_fn]
    mov  ecx, 0x04
    call pci_cfg_write32

    ; --- VMCAP / VMCONFIG (bus restriction + bus-offset setting: reported) ---
    mov  edi, [rel vmd_root_bus]
    mov  esi, [rel vmd_root_dev]
    mov  edx, [rel vmd_root_fn]
    mov  ecx, VMD_REG_VMCAP
    call pci_cfg_read32
    mov  [rel vmd_vmcap], eax
    mov  edi, [rel vmd_root_bus]
    mov  esi, [rel vmd_root_dev]
    mov  edx, [rel vmd_root_fn]
    mov  ecx, VMD_REG_VMCONFIG
    call pci_cfg_read32
    mov  [rel vmd_vmconfig], eax
    call vmd_decode_bus_start

    ; --- walk the child ECAM by index ---
    mov  rdi, [rel vmd_ecam_base]
    movzx esi, byte [rel vmd_ecam_buses]
    mov  edx, VMD_ECAM_FN_SHIFT
    mov  ecx, VMD_ECAM_DEV_SHIFT
    mov  r8d, VMD_ECAM_BUS_SHIFT
    xor  r9d, r9d
    call vmd_walk
    ; Only this original real-domain walk can publish provenance. The KAT
    ; calls the unchanged walker directly and never sets this completion bit.
    cmp byte [rel vmd_owner_overflow], 0
    jne .owner_unavailable
    cmp qword [rel vmd_owner_epoch], 0
    je .owner_unavailable
    call vmd_root_owner_publish           ; RAM only, same original real walk
    mov byte [rel vmd_owner_ready], 1
.owner_unavailable:
    lea  rdi, [rel vmd_root_bus]            ; RCQ-29 hardware report: VMD took the root
    mov  ecx, PCI_DRV_VMD
    mov  r8d, PCI_CLAIM_BOUND
    call pci_claim_bdf3
    jmp  .report

.ecam_unmapped:
    lea  rdi, [rel vmd_root_bus]            ; matched, child ECAM unreachable
    mov  ecx, PCI_DRV_VMD
    mov  r8d, PCI_CLAIM_FAILED
    call pci_claim_bdf3
    mov  byte [rel vmd_ecam_mapped], 0
    lea  rdi, [rel str_vmd_unmapped]
    call serial_string
    mov  rdi, [rel vmd_ecam_base]
    call serial_hex64
    lea  rdi, [rel str_vmd_eol]
    call serial_string
    jmp  .report

.no_root:
    lea  rdi, [rel str_vmd_none]
    call serial_string
    jmp  .out

.report:
    call vmd_print_report
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; vmd_detect_cb - pci_scan_with_filter callback (EDI=bus ESI=dev EDX=fn
; ECX=vendev). Intel + exact VMD device ID + class 01/04/00. First root wins;
; every root is counted. Records BAR0 (CFGBAR, 64-bit), MEMBAR1, MEMBAR2.
; ---------------------------------------------------------------------------
vmd_detect_cb:
    push r12                              ; keep original3 BDF stack offsets
    push r13
    push rdi
    push rsi
    push rdx
    mov r12d, ecx                         ; original scanner ID, never reread
    cmp  cx, VMD_VENDOR_INTEL
    jne  .pop
    mov  eax, ecx
    shr  eax, 16                            ; device id
    lea  r8, [rel vmd_id_table]
    xor  r9d, r9d
.id:
    cmp  r9d, VMD_ID_COUNT
    jae  .pop
    cmp  ax, [r8 + r9*2]
    je   .id_ok
    inc  r9d
    jmp  .id
.id_ok:
    mov  ecx, 0x08
    call pci_cfg_read32                     ; clobbers RAX,R8,RDX
    mov r13d, eax                         ; same original class/revision read
    shr  eax, 8
    cmp  eax, VMD_CLASS24
    jne  .pop
    ; A VMD root BDF alone cannot identify a boot child. This backend walks
    ; and enables ALL matching children, and no verified child-route binding
    ; exists. Unknown (-1) denies selected mode before BARs/ECAM/Command writes;
    ; normal keeps the proven root/child path unchanged.
    mov rsi, -1
    mov edi, 5
    call native_driver_gate
    jc .pop
    inc  byte [rel vmd_root_count]
    cmp  byte [rel vmd_root_count], 1
    jne  .pop                               ; first root wins (v1)
    mov [rel vmd_root_owner_record+VSR_PCI_ID], r12d
    mov [rel vmd_root_owner_record+VSR_CLASSREV], r13d
    mov rax, [rel vmd_owner_epoch]
    mov [rel vmd_root_owner_record+VSR_DOMAIN], rax
    mov  eax, [rsp + 16]
    mov  [rel vmd_root_bus], eax
    mov [rel vmd_root_owner_record+VSR_BUS], eax
    mov  eax, [rsp + 8]
    mov  [rel vmd_root_dev], eax
    mov [rel vmd_root_owner_record+VSR_DEV], eax
    mov  eax, [rsp + 0]
    mov  [rel vmd_root_fn], eax
    mov [rel vmd_root_owner_record+VSR_FN], eax
    ; BAR0 (0x10/0x14) = CFGBAR
    mov  edi, [rel vmd_root_bus]
    mov  esi, [rel vmd_root_dev]
    mov  edx, [rel vmd_root_fn]
    mov  ecx, 0x10
    call pci_cfg_read32
    mov  r10d, eax
    mov  edi, [rel vmd_root_bus]
    mov  esi, [rel vmd_root_dev]
    mov  edx, [rel vmd_root_fn]
    mov  ecx, 0x14
    call pci_cfg_read32
    mov  r11d, eax
    mov  eax, r10d
    and  eax, 0x06
    cmp  eax, 0x04                          ; 10b = 64-bit memory BAR
    je   .b0_64
    xor  r11d, r11d
.b0_64:
    shl  r11, 32
    and  r10d, 0xFFFFFFF0
    or   r11, r10
    mov  [rel vmd_root_bar0], r11
    ; MEMBAR1 (0x18, 32-bit)
    mov  edi, [rel vmd_root_bus]
    mov  esi, [rel vmd_root_dev]
    mov  edx, [rel vmd_root_fn]
    mov  ecx, 0x18
    call pci_cfg_read32
    and  eax, 0xFFFFFFF0
    mov  [rel vmd_root_membar1], rax
    ; MEMBAR2 (0x20/0x24, 64-bit)
    mov  edi, [rel vmd_root_bus]
    mov  esi, [rel vmd_root_dev]
    mov  edx, [rel vmd_root_fn]
    mov  ecx, 0x20
    call pci_cfg_read32
    mov  r10d, eax
    mov  edi, [rel vmd_root_bus]
    mov  esi, [rel vmd_root_dev]
    mov  edx, [rel vmd_root_fn]
    mov  ecx, 0x24
    call pci_cfg_read32
    mov  r11d, eax
    mov  eax, r10d
    and  eax, 0x06
    cmp  eax, 0x04
    je   .b2_64
    xor  r11d, r11d
.b2_64:
    shl  r11, 32
    and  r10d, 0xFFFFFFF0
    or   r11, r10
    mov  [rel vmd_root_membar2], r11
.pop:
    pop  rdx
    pop  rsi
    pop  rdi
    pop r13
    pop r12
    ret

; ---------------------------------------------------------------------------
; vmd_size_cfgbar - standard BAR sizing with memory decode disabled (the
; proven nvme_remap_bar_if_high sequence): Command.bit1 off, write all-ones
; to BAR0 low, read the size mask, restore BAR0, restore Command.
; -> vmd_ecam_buses = size >> 20, clamped to [1, VMD_MAX_BUSES].
; ---------------------------------------------------------------------------
vmd_size_cfgbar:
    push rbx
    push r12
    push r13
    mov  edi, [rel vmd_root_bus]
    mov  esi, [rel vmd_root_dev]
    mov  edx, [rel vmd_root_fn]
    mov  ecx, 0x04
    call pci_cfg_read32
    mov  ebx, eax                           ; original Command|Status
    mov  r8d, eax
    and  r8d, 0xFFFFFFFD                    ; memory decode off while sizing
    mov  edi, [rel vmd_root_bus]
    mov  esi, [rel vmd_root_dev]
    mov  edx, [rel vmd_root_fn]
    mov  ecx, 0x04
    call pci_cfg_write32
    mov  edi, [rel vmd_root_bus]
    mov  esi, [rel vmd_root_dev]
    mov  edx, [rel vmd_root_fn]
    mov  ecx, 0x10
    call pci_cfg_read32
    mov  r12d, eax                          ; original BAR0 low
    mov  r8d, 0xFFFFFFFF
    mov  edi, [rel vmd_root_bus]
    mov  esi, [rel vmd_root_dev]
    mov  edx, [rel vmd_root_fn]
    mov  ecx, 0x10
    call pci_cfg_write32
    mov  edi, [rel vmd_root_bus]
    mov  esi, [rel vmd_root_dev]
    mov  edx, [rel vmd_root_fn]
    mov  ecx, 0x10
    call pci_cfg_read32
    mov  r13d, eax                          ; size mask
    mov  r8d, r12d
    mov  edi, [rel vmd_root_bus]
    mov  esi, [rel vmd_root_dev]
    mov  edx, [rel vmd_root_fn]
    mov  ecx, 0x10
    call pci_cfg_write32                    ; restore BAR0 low
    mov  r8d, ebx
    mov  edi, [rel vmd_root_bus]
    mov  esi, [rel vmd_root_dev]
    mov  edx, [rel vmd_root_fn]
    mov  ecx, 0x04
    call pci_cfg_write32                    ; restore Command
    mov  eax, r13d
    and  eax, 0xFFFFFFF0
    not  eax
    inc  eax                                ; size in bytes; 0 = 4 GiB or more
    shr  eax, 20                            ; -> buses
    test eax, eax
    jnz  .have
    mov  eax, VMD_MAX_BUSES
.have:
    cmp  eax, VMD_MAX_BUSES
    jbe  .cap
    mov  eax, VMD_MAX_BUSES
.cap:
    test eax, eax
    jnz  .store
    mov  eax, 1
.store:
    mov  [rel vmd_ecam_buses], al
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; vmd_decode_bus_start - VMCAP.BUS_RESTRICT (bit0) selects VMCONFIG[9:8]:
; 0 -> 0, 1 -> 128, 2 -> 224, 3 -> undefined for Linux <= 6.8 ("Unknown Bus
; Offset Setting (3)"). The walk is by ECAM index, so this only labels the
; report; setting 3 is recorded as start 0 and flagged probed.
; ---------------------------------------------------------------------------
vmd_decode_bus_start:
    mov  eax, [rel vmd_vmcap]
    test al, 0x01
    jz   .zero
    mov  eax, [rel vmd_vmconfig]
    shr  eax, 8
    and  eax, 0x03
    mov  [rel vmd_bus_start_setting], al
    cmp  al, 1
    je   .s128
    cmp  al, 2
    je   .s224
    cmp  al, 3
    je   .s3
.zero:
    mov  word [rel vmd_bus_start], 0
    ret
.s128:
    mov  word [rel vmd_bus_start], 128
    ret
.s224:
    mov  word [rel vmd_bus_start], 224
    ret
.s3:
    mov  word [rel vmd_bus_start], 0
    mov  byte [rel vmd_bus_start_probed], 1
    ret

; ---------------------------------------------------------------------------
; vmd_walk(RDI=ecam base, ESI=bus count, EDX=fn shift, ECX=dev shift,
;          R8D=bus shift, R9D=flags) -> EAX = children published.
; Pure walk over (bus_index, dev, fn); multi-function only when fn0 has
; header-type bit7. Bridges are counted. AHCI (01/06/01) takes BAR5, NVMe
; (01/08/02) takes BAR0(+BAR1 when 64-bit). A BAR that is I/O, zero, or not
; identity-reachable is refused. Accepted children get Memory Space + Bus
; Master through a 16-bit Command write and a record.
; ---------------------------------------------------------------------------
vmd_walk:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 48
    mov  [rsp], rdi                         ; base
    mov  [rsp + 8], esi                     ; buses
    mov  [rsp + 12], edx                    ; fn shift
    mov  [rsp + 16], ecx                    ; dev shift
    mov  [rsp + 20], r8d                    ; bus shift
    mov  [rsp + 24], r9d                    ; flags
    xor  r12d, r12d                         ; bus index
.bus:
    cmp  r12d, dword [rsp + 8]
    jae  .done
    xor  r13d, r13d                         ; dev
.dev:
    cmp  r13d, 32
    jae  .next_bus
    xor  r14d, r14d                         ; fn
    mov  r15d, 1                            ; fn limit (8 after a multi-function fn0)
.fn:
    cmp  r14d, r15d
    jae  .next_dev
    mov  rbx, [rsp]
    mov  eax, r12d
    mov  ecx, dword [rsp + 20]
    shl  rax, cl
    add  rbx, rax
    mov  eax, r13d
    mov  ecx, dword [rsp + 16]
    shl  rax, cl
    add  rbx, rax
    mov  eax, r14d
    mov  ecx, dword [rsp + 12]
    shl  rax, cl
    add  rbx, rax                           ; rbx = config base of (bus,dev,fn)
    mov  eax, [rbx]                         ; vendor | device
    mov  [rsp + 28], eax                   ; retain the existing identity read
    cmp  ax, 0xFFFF
    je   .next_fn
    test ax, ax
    jz   .next_fn
    test r14d, r14d
    jnz  .classify
    movzx eax, byte [rbx + 0x0E]            ; header type (fn0)
    test al, 0x80
    jz   .classify
    mov  r15d, 8
.classify:
    mov  eax, [rbx + 0x08]
    mov  [rsp + 32], al                    ; retain revision from existing read
    shr  eax, 8                             ; class|sub|progif
    mov  edx, eax
    shr  edx, 8                             ; class|sub
    cmp  edx, 0x0604
    jne  .not_bridge
    inc  byte [rel vmd_bridge_count]
    jmp  .next_fn
.not_bridge:
    cmp  eax, VMD_CLASS_AHCI
    je   .ahci
    cmp  eax, VMD_CLASS_NVME
    je   .nvme
    jmp  .next_fn
.ahci:
    mov  edx, [rbx + 0x24]                  ; BAR5 = ABAR (32-bit memory BAR)
    test dl, 0x01
    jnz  .refuse                            ; an I/O BAR is not an ABAR
    and  edx, 0xFFFFFFF0
    jmp  .publish
.nvme:
    mov  edx, [rbx + 0x10]                  ; BAR0 low
    test dl, 0x01
    jnz  .refuse
    mov  ecx, edx
    and  ecx, 0x06
    cmp  ecx, 0x04                          ; 64-bit BAR: BAR1 is the high dword
    jne  .nvme32
    mov  ecx, [rbx + 0x14]
    shl  rcx, 32
    and  edx, 0xFFFFFFF0
    or   rdx, rcx
    jmp  .publish
.nvme32:
    and  edx, 0xFFFFFFF0
.publish:
    test rdx, rdx
    jz   .refuse                            ; unprogrammed BAR
    mov  rcx, rdx
    shr  rcx, 30
    cmp  rcx, VMD_IDENTITY_GB
    jb   .reachable
    test dword [rsp + 24], VMD_FLAG_KAT
    jnz  .refuse                            ; KAT: no window exists by definition
    mov  r8, [rel vmd_window_gb]
    test r8, r8
    jz   .refuse
    cmp  rcx, r8
    je   .reachable
    inc  r8
    cmp  rcx, r8
    jne  .refuse
.reachable:
    movzx ecx, byte [rel vmd_child_count]
    cmp  ecx, VMD_MAX_CHILDREN
    jae  .refuse
    mov  r8w, [rbx + 0x04]                  ; Command (16-bit: never touch RW1C Status)
    or   r8w, 0x0006                        ; Memory Space + Bus Master
    mov  [rbx + 0x04], r8w
    imul ecx, ecx, vmd_child_size
    lea  r8, [rel vmd_children]
    add  r8, rcx
    mov  [r8 + vmd_child.cfg], rbx
    mov  [r8 + vmd_child.bar], rdx
    mov  [r8 + vmd_child.class24], eax
    mov  ecx, r12d
    shl  ecx, 16
    mov  r9d, r13d
    shl  r9d, 8
    or   ecx, r9d
    or   ecx, r14d
    mov  [r8 + vmd_child.bdf], ecx
    mov  ecx, [rsp + 28]
    mov  [r8 + vmd_child.pci_id], ecx
    mov  cl, [rsp + 32]
    mov  [r8 + vmd_child.revision], cl
    mov  byte [r8 + vmd_child.active], 1
    inc  byte [rel vmd_child_count]
    jmp  .next_fn
.refuse:
    inc  byte [rel vmd_refused_count]
.next_fn:
    inc  r14d
    jmp  .fn
.next_dev:
    inc  r13d
    jmp  .dev
.next_bus:
    inc  r12d
    jmp  .bus
.done:
    movzx eax, byte [rel vmd_child_count]
    add  rsp, 48
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; vmd_find_child(EDI=class24) -> RAX = BAR (0 = none), RDX = ECAM config base.
; ---------------------------------------------------------------------------
vmd_find_child:
    ; Stale/KAT inventory is never boot-child authority in selected mode.
    push rdi
    push rsi
    mov edi, 5
    mov rsi, -1
    call native_driver_gate
    pop rsi
    pop rdi
    jnc .policy_allowed
    xor eax, eax
    xor edx, edx
    ret
.policy_allowed:
    lea  rcx, [rel vmd_children]
    xor  edx, edx
.n:
    cmp  edx, VMD_MAX_CHILDREN
    jae  .none
    cmp  byte [rcx + vmd_child.active], 1
    jne  .adv
    cmp  [rcx + vmd_child.class24], edi
    jne  .adv
    mov  rax, [rcx + vmd_child.bar]
    mov  rdx, [rcx + vmd_child.cfg]
    ret
.adv:
    add  rcx, vmd_child_size
    inc  edx
    jmp  .n
.none:
    xor  eax, eax
    xor  edx, edx
    ret

; C3 cached child record, index0..7, RSI=32B trusted output. No config I/O.
; Preserves child-domain BDF (ECAM-relative), full cached ID/class/revision.
vmd_child_identity_snapshot:
    cmp edi,VMD_MAX_CHILDREN
    jae .none
    movzx eax,byte [rel vmd_child_count]
    cmp edi,eax
    jae .none
    shl edi,5
    lea rdx,[rel vmd_children]
    add rdx,rdi
    cmp byte [rdx+vmd_child.active],1
    jne .none
    mov rax,[rdx]
    mov [rsi],rax
    mov rax,[rdx+8]
    mov [rsi+8],rax
    mov rax,[rdx+16]
    mov [rsi+16],rax
    mov rax,[rdx+24]
    mov [rsi+24],rax
    mov eax,1
    ret
.none:
    xor eax,eax
    ret

; RAM-only original selection capture. EDI=class24, RSI=original selected cfg,
; RDX=original selected BAR, RCX=trusted128B output. EAX=1 retained /0 missing.
; No hardware reads/writes and no new child admission. Attach epoch left0 for
; the original AHCI selection publisher. Duplicate or inconsistent RAM refuses.
vmd_selected_owner_snapshot:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rsi
    mov r13, rdx
    mov r15, rcx
    mov ebx, edi
    mov rdi, rcx
    mov ecx, VSO_BYTES/8
    xor eax, eax
    cld
    rep stosq
    cmp ebx, VMD_CLASS_AHCI
    jne .none
    cmp byte [rel vmd_owner_ready], 1
    jne .none
    cmp byte [rel vmd_owner_overflow], 0
    jne .none
    cmp qword [rel vmd_owner_epoch], 0
    je .none
    cmp byte [rel vmd_ecam_mapped], 1
    jne .none
    cmp byte [rel vmd_root_count], 0
    je .none
    cmp dword [rel vmd_root_bus], 255
    ja .none
    cmp dword [rel vmd_root_dev], 31
    ja .none
    cmp dword [rel vmd_root_fn], 7
    ja .none
    mov rax, [rel vmd_ecam_base]
    test rax, rax
    jz .none
    cmp rax, [rel vmd_root_bar0]
    jne .none
    movzx eax, byte [rel vmd_ecam_buses]
    dec eax
    cmp eax, VMD_MAX_BUSES-1
    ja .none
    test r12, r12
    jz .none
    test r13, r13
    jz .none
    test r13b, 15
    jnz .none
    mov rax, r13
    shr rax, 32                          ; actual AHCI BAR5 source is32bit
    jnz .none
    movzx ecx, byte [rel vmd_child_count]
    test ecx, ecx
    jz .none
    cmp ecx, VMD_MAX_CHILDREN
    ja .none
    xor r14d, r14d
    xor ebx, ebx
    xor eax, eax
    lea rdx, [rel vmd_children]
.scan:
    cmp byte [rdx+vmd_child.active], 1
    jne .next
    cmp dword [rdx+vmd_child.class24], VMD_CLASS_AHCI
    jne .next
    cmp [rdx+vmd_child.cfg], r12
    jne .next
    cmp [rdx+vmd_child.bar], r13
    jne .next
    test rbx, rbx
    jnz .none                            ; ambiguous original selection
    mov rbx, rdx
    mov r14d, eax                        ; original index below, EAX starts0
.next:
    add rdx, vmd_child_size
    inc eax
    cmp eax, ecx
    jb .scan
    test rbx, rbx
    jz .none
    mov eax, [rbx+vmd_child.pci_id]
    test ax, ax
    jz .none
    cmp ax, 0xffff
    je .none
    mov eax, [rbx+vmd_child.bdf]
    test eax, ~0x00ff1f07
    jnz .none
    mov edx, eax
    shr edx, 16
    movzx ecx, byte [rel vmd_ecam_buses]
    cmp edx, ecx
    jae .none
    shl rdx, VMD_ECAM_BUS_SHIFT
    mov ecx, eax
    shr ecx, 8
    and ecx, 31
    shl rcx, VMD_ECAM_DEV_SHIFT
    add rdx, rcx
    and eax, 7
    shl rax, VMD_ECAM_FN_SHIFT
    add rdx, rax
    add rdx, [rel vmd_ecam_base]
    jc .none
    cmp rdx, r12
    jne .none
    mov rax, [rel vmd_owner_epoch]
    mov [r15+VSO_DOMAIN], rax
    mov [r15+VSO_CFG], r12
    mov [r15+VSO_BAR], r13
    mov rax, [rel vmd_ecam_base]
    mov [r15+VSO_ECAM], rax
    mov rax, [rel vmd_root_bar0]
    mov [r15+VSO_ROOTBAR], rax
    mov rax, [rel vmd_window_gb]
    mov [r15+VSO_WINDOW_GB], rax
    mov eax, [rel vmd_root_bus]
    mov [r15+VSO_ROOT_BUS], eax
    mov eax, [rel vmd_root_dev]
    mov [r15+VSO_ROOT_DEV], eax
    mov eax, [rel vmd_root_fn]
    mov [r15+VSO_ROOT_FN], eax
    mov eax, [rbx+vmd_child.bdf]
    mov [r15+VSO_CHILD_BDF], eax
    mov eax, [rbx+vmd_child.pci_id]
    mov [r15+VSO_PCI_ID], eax
    mov eax, [rbx+vmd_child.class24]
    mov [r15+VSO_CLASS], eax
    movzx eax, byte [rbx+vmd_child.revision]
    mov [r15+VSO_REVISION], eax
    mov [r15+VSO_INDEX], r14d
    movzx eax, byte [rel vmd_ecam_mapped]
    mov [r15+VSO_MAPPED], eax
    movzx eax, byte [rel vmd_ecam_buses]
    mov [r15+VSO_BUSES], eax
    movzx eax, word [rel vmd_bus_start]
    mov [r15+VSO_BUS_START], eax
    movzx eax, byte [rel vmd_bus_start_setting]
    mov [r15+VSO_SETTING], eax
    movzx eax, byte [rel vmd_bus_start_probed]
    mov [r15+VSO_PROBED], eax
    movzx eax, byte [rel vmd_root_count]
    mov [r15+VSO_ROOT_COUNT], eax
    mov eax, [rel vmd_vmcap]
    mov [r15+VSO_VMCAP], eax
    mov eax, [rel vmd_vmconfig]
    mov [r15+VSO_VMCONFIG], eax
    mov dword [r15+VSO_SCHEMA], VSO_VERSION
    mov dword [r15+VSO_FLAGS], 1
    mov eax, 1
    jmp .out
.none:
    xor eax, eax
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; RDI=retained128B record. EAX=1 same original RAM lifetime /0 stale or unknown.
; Compare a new RAM-only image, excluding AHCI's separate attach epoch. This
; cannot establish current PCI identity, mapping admission, or quiescence.
vmd_selected_owner_current:
    push rbx
    sub rsp, VSO_BYTES
    mov rbx, rdi
    mov edi, [rbx+VSO_CLASS]
    mov rsi, [rbx+VSO_CFG]
    mov rdx, [rbx+VSO_BAR]
    mov rcx, rsp
    call vmd_selected_owner_snapshot
    cmp eax, 1
    jne .out
    xor ecx, ecx
.compare:
    cmp ecx, VSO_ATTACH
    je .next
    mov rax, [rsp+rcx]
    cmp rax, [rbx+rcx]
    jne .stale
.next:
    add ecx, 8
    cmp ecx, VSO_BYTES
    jb .compare
    mov eax, 1
    jmp .out
.stale:
    xor eax, eax
.out:
    add rsp, VSO_BYTES
    pop rbx
    ret

; ---------------------------------------------------------------------------
; Complete only the root selected by this original real-domain walk. The
; callback captured ID/class/BDF/epoch, and these mapping values are the
; original domain's values. No extra config access, admission or effect.
vmd_root_owner_publish:
    push rax
    mov rax, [rel vmd_owner_epoch]
    cmp [rel vmd_root_owner_record+VSR_DOMAIN], rax
    jne .out
    mov rax, [rel vmd_root_bar0]
    mov [rel vmd_root_owner_record+VSR_CFGBAR], rax
    mov rax, [rel vmd_ecam_base]
    mov [rel vmd_root_owner_record+VSR_ECAM], rax
    mov rax, [rel vmd_window_gb]
    mov [rel vmd_root_owner_record+VSR_WINDOW_GB], rax
    mov dword [rel vmd_root_owner_record+VSR_FLAGS], 1
    mov dword [rel vmd_root_owner_record+VSR_SCHEMA], 1
.out:
    pop rax
    ret

; RDI=trusted distinct64B output. EAX0=missing/zero,1=same original RAM
; lifetime,2=stale/inconsistent with original bytes preserved. All are only
; provenance, never current hardware admission. Synchronous BSP lifecycle
; matches domain_create and the accepted selected-child record. No I/O.
vmd_selected_root_snapshot:
    push rbx
    mov rbx, rdi
    mov ecx, VSR_BYTES/8
    xor eax, eax
    cld
    rep stosq
    cmp dword [rel vmd_root_owner_record+VSR_SCHEMA], 0
    je .out
    mov rdi, rbx
    lea rsi, [rel vmd_root_owner_record]
    mov ecx, VSR_BYTES/8
    rep movsq
    mov eax, 2
    cmp dword [rbx+VSR_SCHEMA], 1
    jne .out
    cmp dword [rbx+VSR_FLAGS], 1
    jne .out
    cmp dword [rbx+VSR_RESERVED], 0
    jne .out
    cmp byte [rel vmd_owner_ready], 1
    jne .out
    cmp byte [rel vmd_owner_overflow], 0
    jne .out
    mov rdx, [rbx+VSR_DOMAIN]
    test rdx, rdx
    jz .out
    cmp rdx, [rel vmd_owner_epoch]
    jne .out
    cmp byte [rel vmd_root_count], 0
    je .out
    mov ecx, [rbx+VSR_BUS]
    cmp ecx, 255
    ja .out
    cmp ecx, [rel vmd_root_bus]
    jne .out
    mov ecx, [rbx+VSR_DEV]
    cmp ecx, 31
    ja .out
    cmp ecx, [rel vmd_root_dev]
    jne .out
    mov ecx, [rbx+VSR_FN]
    cmp ecx, 7
    ja .out
    cmp ecx, [rel vmd_root_fn]
    jne .out
    mov ecx, [rbx+VSR_CLASSREV]
    shr ecx, 8
    cmp ecx, VMD_CLASS24
    jne .out
    mov ecx, [rbx+VSR_PCI_ID]
    cmp cx, VMD_VENDOR_INTEL
    jne .out
    shr ecx, 16
    lea rdx, [rel vmd_id_table]
    xor r8d, r8d
.id:
    cmp r8d, VMD_ID_COUNT
    jae .out
    cmp cx, [rdx+r8*2]
    je .mapping
    inc r8d
    jmp .id
.mapping:
    mov rdx, [rbx+VSR_CFGBAR]
    test rdx, rdx
    jz .out
    test edx, 0xfffff
    jnz .out
    cmp rdx, [rel vmd_root_bar0]
    jne .out
    cmp rdx, [rbx+VSR_ECAM]
    jne .out
    cmp rdx, [rel vmd_ecam_base]
    jne .out
    cmp byte [rel vmd_ecam_mapped], 1
    jne .out
    movzx ecx, byte [rel vmd_ecam_buses]
    dec ecx
    cmp ecx, VMD_MAX_BUSES-1
    ja .out
    mov rcx, [rbx+VSR_WINDOW_GB]
    cmp rcx, [rel vmd_window_gb]
    jne .out
    shr rdx, 30
    cmp rdx, VMD_IDENTITY_GB
    jb .valid
    test rcx, rcx
    jz .out
    cmp rdx, rcx
    je .valid
    inc rcx
    cmp rdx, rcx
    jne .out
.valid:
    mov eax, 1
.out:
    pop rbx
    ret

; vmd_reset_state - zero every table and counter, invalidate saved provenance.
; ---------------------------------------------------------------------------
vmd_reset_state:
    push rdi
    push rcx
    push rax
    lea rdi, [rel vmd_root_owner_record]
    mov ecx, VSR_BYTES/8
    xor eax, eax
    rep stosq
    mov byte [rel vmd_owner_ready], 0
    cmp qword [rel vmd_owner_epoch], -1
    je .owner_exhausted
    inc qword [rel vmd_owner_epoch]
    jmp .owner_invalid
.owner_exhausted:
    mov byte [rel vmd_owner_overflow], 1  ; sticky: never recycle a lifetime
.owner_invalid:
    lea  rdi, [rel vmd_children]
    mov  ecx, (VMD_MAX_CHILDREN * vmd_child_size) / 8
    xor  eax, eax
    rep  stosq
    mov  byte [rel vmd_child_count], 0
    mov  byte [rel vmd_bridge_count], 0
    mov  byte [rel vmd_refused_count], 0
    mov  byte [rel vmd_root_count], 0
    mov  byte [rel vmd_ecam_mapped], 0
    mov  byte [rel vmd_ecam_buses], 0
    mov  byte [rel vmd_bus_start_setting], 0
    mov  byte [rel vmd_bus_start_probed], 0
    mov  word [rel vmd_bus_start], 0
    mov  qword [rel vmd_ecam_base], 0
    mov  qword [rel vmd_root_bar0], 0
    mov  qword [rel vmd_root_membar1], 0
    mov  qword [rel vmd_root_membar2], 0
    mov  dword [rel vmd_vmcap], 0
    mov  dword [rel vmd_vmconfig], 0
    pop  rax
    pop  rcx
    pop  rdi
    ret

; ---------------------------------------------------------------------------
; vmd_selftest - the synthetic child-ECAM KAT (see the header). EAX=0 pass.
; ---------------------------------------------------------------------------
vmd_selftest:
    push rbx
    push r12
    call vmd_reset_state
    call vmd_kat_base                       ; RAM-only synthetic bus on the kernel heap
    test rax, rax
    jz   .nomem
    mov  rbx, rax
    mov  rdi, rax
    mov  ecx, VMD_KAT_IMAGE_BYTES / 8
    mov  rax, -1                            ; absent functions read all-ones
    rep  stosq
    ; dev0 fn0: AHCI, 32-bit ABAR 0x8C001000 -> accepted
    mov  rdi, rbx
    mov  dword [rdi + 0x00], 0x28228086
    mov  dword [rdi + 0x04], 0x00100000     ; Status=0x0010 | Command=0 (Mem+BM clear)
    mov  dword [rdi + 0x08], 0x01060100
    mov  dword [rdi + 0x0C], 0x00000000     ; header type 0 (single function)
    mov  dword [rdi + 0x24], 0x8C001000
    ; dev1 fn0: PCIe bridge -> counted, not a child
    lea  rdi, [rbx + (1 << VMD_KAT_DEV_SHIFT)]
    mov  dword [rdi + 0x00], 0x1BC08086
    mov  dword [rdi + 0x04], 0x00100000
    mov  dword [rdi + 0x08], 0x06040000
    mov  dword [rdi + 0x0C], 0x00010000     ; header type 1
    ; dev2 fn0: NVMe, 64-bit BAR0 0x8C100000 -> accepted
    lea  rdi, [rbx + (2 << VMD_KAT_DEV_SHIFT)]
    mov  dword [rdi + 0x00], 0xA80A144D
    mov  dword [rdi + 0x04], 0x00100000
    mov  dword [rdi + 0x08], 0x01080200
    mov  dword [rdi + 0x0C], 0x00000000
    mov  dword [rdi + 0x10], 0x8C100004
    mov  dword [rdi + 0x14], 0x00000000
    ; dev3 fn0: AHCI with an I/O BAR5 -> refused
    lea  rdi, [rbx + (3 << VMD_KAT_DEV_SHIFT)]
    mov  dword [rdi + 0x00], 0x28228086
    mov  dword [rdi + 0x04], 0x00100000
    mov  dword [rdi + 0x08], 0x01060100
    mov  dword [rdi + 0x0C], 0x00000000
    mov  dword [rdi + 0x24], 0x0000C001
    ; dev4 fn0: multi-function xHCI (not storage); fn1: NVMe with BAR0 at 448 GiB -> refused (KAT: no window)
    lea  rdi, [rbx + (4 << VMD_KAT_DEV_SHIFT)]
    mov  dword [rdi + 0x00], 0x7AE08086
    mov  dword [rdi + 0x04], 0x00100000
    mov  dword [rdi + 0x08], 0x0C033000
    mov  dword [rdi + 0x0C], 0x00800000     ; header type 0x80 (multi-function)
    lea  rdi, [rbx + (4 << VMD_KAT_DEV_SHIFT) + (1 << VMD_KAT_FN_SHIFT)]
    mov  dword [rdi + 0x00], 0xA80A144D
    mov  dword [rdi + 0x04], 0x00100000
    mov  dword [rdi + 0x08], 0x01080200
    mov  dword [rdi + 0x0C], 0x00000000
    mov  dword [rdi + 0x10], 0x22000004
    mov  dword [rdi + 0x14], 0x00000070
    ; walk the one synthetic bus
    mov  rdi, rbx
    mov  esi, 1
    mov  edx, VMD_KAT_FN_SHIFT
    mov  ecx, VMD_KAT_DEV_SHIFT
    mov  r8d, VMD_KAT_BUS_SHIFT
    mov  r9d, VMD_FLAG_KAT
    call vmd_walk
    ; --- grade ---
    xor  r12d, r12d
    cmp  byte [rel vmd_child_count], 2
    je   .c_ok
    or   r12d, 1
.c_ok:
    cmp  byte [rel vmd_bridge_count], 1
    je   .b_ok
    or   r12d, 2
.b_ok:
    cmp  byte [rel vmd_refused_count], 2
    je   .r_ok
    or   r12d, 4
.r_ok:
    mov  edi, VMD_CLASS_AHCI
    call vmd_find_child
    mov  ecx, 0x8C001000
    cmp  rax, rcx
    je   .a_ok
    or   r12d, 8
.a_ok:
    mov  edi, VMD_CLASS_NVME
    call vmd_find_child
    mov  ecx, 0x8C100000
    cmp  rax, rcx
    je   .n_ok
    or   r12d, 16
.n_ok:
    movzx eax, word [rbx + 0x04]            ; accepted AHCI: Mem+BM set by the walk
    and  eax, 0x0006
    cmp  eax, 0x0006
    je   .e_ok
    or   r12d, 32
.e_ok:
    movzx eax, word [rbx + (3 << VMD_KAT_DEV_SHIFT) + 0x04]   ; refused AHCI: untouched
    and  eax, 0x0006
    jz   .e2_ok
    or   r12d, 64
.e2_ok:
    call vmd_reset_state                    ; synthetic children never reach the real scan
    test r12d, r12d
    jnz  .fail
    lea  rdi, [rel str_vmd_kat_pass]
    call serial_string
    xor  eax, eax
    jmp  .out
.nomem:
    mov  r12d, 0x80                         ; bit 7: heap refused the synthetic image
.fail:
    lea  rdi, [rel str_vmd_kat_fail]
    call serial_string
    mov  rdi, r12
    call serial_hex64
    lea  rdi, [rel str_vmd_eol]
    call serial_string
    mov  eax, -1
.out:
    pop  r12
    pop  rbx
    ret

; vmd_kat_base -> RAX = the zeroed VMD_KAT_IMAGE_BYTES synthetic ECAM bus, or 0 if
; the heap refused. Preserves every register except RAX. First use is
; vmd_domain_create (fs/blockdev, long after PH_HEAP_INIT).
HEAP_ONCE_ACCESSOR vmd_kat_base, vmd_kat_ptr, VMD_KAT_IMAGE_BYTES, str_vmd_kat_nomem

; ---------------------------------------------------------------------------
; vmd_print_report - one summary line, then one line per published child.
; ---------------------------------------------------------------------------
vmd_print_report:
    push rbx
    push r12
    lea  rdi, [rel str_vmd_root]
    call serial_string
    mov  edi, [rel vmd_root_bus]
    call vmd_put_dec
    lea  rdi, [rel str_vmd_colon]
    call serial_string
    mov  edi, [rel vmd_root_dev]
    call vmd_put_dec
    lea  rdi, [rel str_vmd_dot]
    call serial_string
    mov  edi, [rel vmd_root_fn]
    call vmd_put_dec
    lea  rdi, [rel str_vmd_ecam]
    call serial_string
    mov  rdi, [rel vmd_ecam_base]
    call serial_hex64
    lea  rdi, [rel str_vmd_membar1]
    call serial_string
    mov  rdi, [rel vmd_root_membar1]
    call serial_hex64
    lea  rdi, [rel str_vmd_membar2]
    call serial_string
    mov  rdi, [rel vmd_root_membar2]
    call serial_hex64
    lea  rdi, [rel str_vmd_mapped]
    call serial_string
    movzx edi, byte [rel vmd_ecam_mapped]
    call vmd_put_dec
    lea  rdi, [rel str_vmd_buses]
    call serial_string
    movzx edi, byte [rel vmd_ecam_buses]
    call vmd_put_dec
    lea  rdi, [rel str_vmd_bus_start]
    call serial_string
    movzx edi, word [rel vmd_bus_start]
    call vmd_put_dec
    lea  rdi, [rel str_vmd_setting]
    call serial_string
    movzx edi, byte [rel vmd_bus_start_setting]
    call vmd_put_dec
    lea  rdi, [rel str_vmd_probed]
    call serial_string
    movzx edi, byte [rel vmd_bus_start_probed]
    call vmd_put_dec
    lea  rdi, [rel str_vmd_children]
    call serial_string
    movzx edi, byte [rel vmd_child_count]
    call vmd_put_dec
    lea  rdi, [rel str_vmd_bridges]
    call serial_string
    movzx edi, byte [rel vmd_bridge_count]
    call vmd_put_dec
    lea  rdi, [rel str_vmd_refused]
    call serial_string
    movzx edi, byte [rel vmd_refused_count]
    call vmd_put_dec
    lea  rdi, [rel str_vmd_eol]
    call serial_string
    ; per child
    lea  rbx, [rel vmd_children]
    xor  r12d, r12d
.child:
    cmp  r12d, VMD_MAX_CHILDREN
    jae  .done
    cmp  byte [rbx + vmd_child.active], 1
    jne  .next
    lea  rdi, [rel str_vmd_child]
    call serial_string
    mov  edi, [rbx + vmd_child.bdf]
    call serial_hex64
    lea  rdi, [rel str_vmd_class]
    call serial_string
    mov  edi, [rbx + vmd_child.class24]
    call serial_hex64
    lea  rdi, [rel str_vmd_bar]
    call serial_string
    mov  rdi, [rbx + vmd_child.bar]
    call serial_hex64
    lea  rdi, [rel str_vmd_cfg]
    call serial_string
    mov  rdi, [rbx + vmd_child.cfg]
    call serial_hex64
    lea  rdi, [rel str_vmd_eol]
    call serial_string
.next:
    add  rbx, vmd_child_size
    inc  r12d
    jmp  .child
.done:
    pop  r12
    pop  rbx
    ret

; vmd_put_dec(RDI=value) - decimal via serial_string (no upward import).
vmd_put_dec:
    push rbx
    lea  rbx, [rel vmd_numbuf + 23]
    mov  byte [rbx], 0
    mov  rax, rdi
    mov  ecx, 10
.d:
    xor  edx, edx
    div  rcx
    add  dl, 0x30
    dec  rbx
    mov  [rbx], dl
    test rax, rax
    jnz  .d
    mov  rdi, rbx
    call serial_string
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; data (no absolute addresses: constants and zeroed tables only)
; ---------------------------------------------------------------------------
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_dev_blk_vmd_0 0
align 8
vmd_children:       times (VMD_MAX_CHILDREN * vmd_child_size) db 0
vmd_kat_ptr:        dq 0                ; -> heap synthetic ECAM bus (vmd_kat_base)
vmd_id_table:       dw 0x201d, 0x28c0, 0x467f, 0x4c3d, 0x9a0b, 0xa77f, 0x7d0b, 0xad0b, 0xb60b, 0xb06f
vmd_root_bar0:      dq 0
vmd_root_owner_record: times VSR_BYTES db 0
vmd_owner_epoch:    dq 0
vmd_owner_ready:    db 0
vmd_owner_overflow: db 0
align 8
vmd_root_membar1:   dq 0
vmd_root_membar2:   dq 0
vmd_ecam_base:      dq 0
vmd_root_bus:       dd 0
vmd_root_dev:       dd 0
vmd_root_fn:        dd 0
vmd_vmcap:          dd 0
vmd_vmconfig:       dd 0
vmd_bus_start:      dw 0
vmd_root_count:     db 0
vmd_child_count:    db 0
vmd_bridge_count:   db 0
vmd_refused_count:  db 0
vmd_ecam_mapped:    db 0
vmd_ecam_buses:     db 0
vmd_bus_start_setting: db 0
vmd_bus_start_probed:  db 0
vmd_numbuf:         times 24 db 0

str_vmd_none:      db "[PAOS64] L3 vmd: no Intel VMD root on the legacy bus (storage enumerates directly)", 13, 10, 0
str_vmd_unmapped:  db "[PAOS64] L3 vmd: VMD root found but its child ECAM is not identity-reachable (no boot/paging window) ecam=", 0
str_vmd_kat_pass:  db "[PAOS64] L3 vmd: synthetic child-ECAM walk KAT PASS children=2 bridges=1 refused=2 enable_rmw=verified", 13, 10, 0
str_vmd_kat_fail:  db "[PAOS64] L3 vmd: synthetic child-ECAM walk KAT FAIL bits=", 0
str_vmd_root:      db "[PAOS64] L3 vmd: root bdf=", 0
str_vmd_colon:     db ":", 0
str_vmd_dot:       db ".", 0
str_vmd_ecam:      db " ecam=", 0
str_vmd_membar1:   db " membar1=", 0
str_vmd_membar2:   db " membar2=", 0
str_vmd_mapped:    db " ecam_mapped=", 0
str_vmd_buses:     db " buses=", 0
str_vmd_bus_start: db " bus_start=", 0
str_vmd_setting:   db " setting=", 0
str_vmd_probed:    db " setting3_probed=", 0
str_vmd_children:  db " children=", 0
str_vmd_bridges:   db " bridges=", 0
str_vmd_refused:   db " refused=", 0
str_vmd_child:     db "[PAOS64] L3 vmd: child bdf=", 0
str_vmd_class:     db " class=", 0
str_vmd_bar:       db " bar=", 0
str_vmd_cfg:       db " cfg=", 0
str_vmd_eol:       db 13, 10, 0
str_vmd_kat_nomem: db "[PAOS64] L3 vmd: heap refused the synthetic ECAM image", 13, 10, 0
; layout: keep the module a whole number of pages so nothing after it changes
; page phase (TCG regression lesson, 2026-09-07); tuned after the first build.
vmd_layout_pad:    times 671 db 0    ; 19809 + 671 = 20480 = 5 pages
%endmacro
WDATA_DEFER WDATA_dev_blk_vmd_0
