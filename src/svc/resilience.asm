;; MODULE svc/resilience
;; LAYER 5
;; EXPORTS resilience_init, resilience_selftest, resilience_declare, aer_capture, iommu_capture, iommu_capture_live, iommu_fault_count, iommu_sec_reset, iommu_sec_drain, iommu_sec_enqueue_amd, res_out_cur, res_out_kind, res_out_error, res_read_req, res_read_arg, res_out_buf, res_out_ready
;; IMPORTS svc/aer_poll, svc/aer_dma_probe, boot/serial, core/lib/fmt, core/lib/mem, core/diag, svc/command, svc/command_audit, bus/pci, bus/pci_bdf, bus/pci_contain, hv/amdvi
;; CAPS
;; OWNER saga:resilience
; ============================================================================
; svc/resilience.asm — PCIe AER + IOMMU/VT-d DMAR fault + root-port completion-timeout
;   (CTO) handlers (contract 1066). Extends the C38 fault-handler surface
;   (fault_handlers_hardy: MCE/NMI/#DF/#GP/stack-guard) to the transport-layer error
;   classes named in CLAUDE.md's open crash/fault-handler TODO. RESILIENCE: no fault
;   class hard-hangs — a triggered PCIe/IOMMU error is CAUGHT + LOGGED + CONTAINED.
;
; LAYER NOTE (why svc/, not core/ as the contract's code_locations suggested): this
; module PROJECTS verbs through svc/command (command_register_verb, cmd_handler_prologue)
; and stages replies for svc/command_udp — an upward core->svc dependency is a layer
; violation. svc/thermal.asm sits in svc/ for exactly this reason (it is conceptually a
; "core resilience" feature too). code_locations are a STARTING list (M16), not gospel.
;
; THREE error classes, one shared capture path (the un-fakeable content, §3.11):
;
;   (1) PCIe AER (Advanced Error Reporting): resilience_init walks the PCIe capability
;       of every bus-0 function to find ROOT PORTS (real enumeration via pci_cfg_read32),
;       installs the AER handler (aer_capture) and remembers a REAL source BDF. A caught
;       error's RECORD = {random tag + error class + source BDF} is appended to the
;       persistent C2 diag ring (reused, not re-invented) and the host stays live.
;       -> [aer.handler.registered]
;
;   (2) IOMMU / VT-d DMAR fault: the fault-recording ring + handler (iommu_capture) are
;       installed. A bad DMA (an untranslated / permission-violating address) is CAUGHT,
;       its record {faulting BDF + fault address + tag} LOGGED, and CONTAINED (the DMA is
;       blocked, not a corruption/hang) — this is the exact class behind the June
;       "pre-dmar1 untranslated DMA" resets, turned into a caught+contained event. VT-d
;       presence is best-effort; a firmware-disabled VT-d degrades to "not present"
;       (documented, never an assert). -> [iommu.fault.registered]
;
;   (3) root-port completion-timeout (CTO): for each PCIe root port, read DevCap2 CTO
;       Ranges Supported (cap+0x24) and write a bounded supported CTO value into DevCtl2
;       (cap+0x28) so a completion that never returns TIMES OUT (surfacing as an AER
;       completion-timeout record) instead of hanging the fabric. -> [pcie.cto.configured]
;
;   (4) resilience_selftest: inject a SIMULATED error through the SAME capture path a real
;       interrupt would use and prove it was caught + contained (host still answerable).
;       -> [aer.contained.selftest]
;
; CONTENT-GRADE, NOT LATCH (§3.11): the live verbs AERINJECT/IOMMUINJECT/PCIECTOINJECT
; push a caller-supplied RANDOM tag through the capture path; AERLOG/IOMMULOG read that
; exact tag back out of the stored record (a latch cannot fake a random tag it never
; received) beside a plausible class/BDF/address. STATUS stays alive throughout
; (containment). A FATAL injection takes the contain/isolate-or-panic-with-diag path,
; never a silent hard hang (the NEGATIVE GATE).
;
; QEMU (i440fx/q35-TCG) has no faithful AER/DMAR silicon; the 4 boot markers are a BUILD
; GATE (the code path ran), exactly like thermal's synthetic-sensor KAT. The random-tag
; round-trip + real BDF is the BARE-METAL content grade.
; ============================================================================

; --- PCIe capability walk constants (legacy config space, first 256 bytes) ---
PCI_STATUS_DW      equ 0x04    ; dword @0x04: [16..31]=Status; bit20 (Status bit4)=Cap List
PCI_STATUS_CAPLIST equ (1 << 20)
PCI_CAP_PTR        equ 0x34    ; byte: pointer to first capability (& 0xFC)
PCIE_CAP_ID        equ 0x10    ; PCI Express capability ID
PCIE_CAP_REG_OFF   equ 0x02    ; PCIe Capabilities register (word) within the cap
PCIE_PORTTYPE_ROOT equ 0x4     ; Device/Port Type = Root Port of PCIe Root Complex
PCIE_DEVCAP2_OFF   equ 0x24    ; Device Capabilities 2 (dword): [3:0]=CTO Ranges Supported
PCIE_DEVCTL2_OFF   equ 0x28    ; Device Control 2 (dword): [3:0]=CTO Value, [4]=CTO Disable
CTO_VAL_RANGE_A    equ 0x2     ; 1ms-10ms  (range A, DevCap2 bit0)
CTO_VAL_RANGE_B    equ 0x6     ; 65ms-210ms (range B, DevCap2 bit1)
CTO_US_RANGE_A     equ 10000   ; upper bound of range A, microseconds (report)
CTO_US_RANGE_B     equ 210000  ; upper bound of range B, microseconds (report)
CTO_US_DEFAULT     equ 50000   ; default range upper bound (50ms) when nothing written

; --- error-class ids (self-describing taxonomy carried in the record) ---
AER_CLASS_CORR     equ 1       ; correctable
AER_CLASS_UNCORR   equ 2       ; uncorrectable-nonfatal
AER_CLASS_CTO      equ 3       ; completion-timeout (surfaced via AER)
AER_CLASS_FATAL    equ 4       ; fatal / uncontainable -> contain-or-panic-with-diag

; --- diag-ring record kinds (thermal used 4; fault dumps use 1/2/3) ---
DIAG_KIND_AER      equ 5
DIAG_KIND_IOMMU    equ 6

; ---------------------------------------------------------------------------
; resilience_init — enumerate PCIe root ports (real), install the AER + IOMMU/DMAR
;   handlers, and configure a bounded root-port CTO. Emits three build-gate markers.
;   ALWAYS arms (present-or-degraded, honest) — never faults on a box without PCIe
;   root ports (QEMU) or with VT-d disabled. clobbers: caller-saved.
; ---------------------------------------------------------------------------
resilience_init:
    push rbx
    call aer_poll_init                      ; separate boot-local hardware observations
    call iommu_sec_reset                    ; new boot-local producer epoch
    mov  qword [rel aer_rep_bdf], -1
    mov  dword [rel aer_rootport_count], 0
    ; install the AER + IOMMU handler function pointers (the capture path a real
    ; interrupt would invoke). The injection surface drives this SAME path so the
    ; catch/log/contain LOGIC is proven; live-MSI delivery from a faulty device is a
    ; documented follow-up (test_gaps: "live hardware AER injection").
    lea  rax, [rel aer_capture]
    mov  [rel aer_handler_ptr], rax
    lea  rax, [rel iommu_capture]
    mov  [rel iommu_handler_ptr], rax
    ; --- (1)+(3): walk bus 0 for PCIe root ports; remember a real BDF + configure CTO ---
    call resilience_enum_bus0
    ; AER handler is registered on the enumerated surface (present-or-degraded)
    lea  rdi, [rel str_aer_reg]
    call serial_string
    mov  byte [rel aer_m_registered], 1
    ; --- (2): IOMMU/VT-d DMAR fault-recording ring + handler installed. VT-d presence
    ;   is best-effort; a firmware-disabled unit degrades to "not present" (documented).
    mov  byte [rel iommu_present], 0            ; honest default: not detected (no ACPI DMAR walk here)
    lea  rdi, [rel str_iommu_reg]
    call serial_string
    mov  byte [rel iommu_m_registered], 1
    ; --- (3) marker: CTO policy configured (bounded), reporting the real root-port count ---
    lea  rdi, [rel str_cto_cfg]
    call serial_string
    mov  byte [rel cto_m_configured], 1
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; resilience_enum_bus0 — self-contained bus-0 scan (root ports live on bus 0). For
;   each present function, walk its capability list for the PCIe cap; a Root Port is
;   counted, its BDF remembered (preferred over a generic device), and a bounded CTO
;   value written to DevCtl2 from the DevCap2 ranges it advertises. Applied means
;   the last verified port read back its selected value with Disable clear; it is
;   not all-port coverage or evidence of an actual completion-timeout event. Each
;   access is bounded; the CTO write uses a spec-defined value the port supports.
;   clobbers: caller-saved (uses rbx=dev, r12=fn, r13=cap ptr, r14=scratch, r15=bdf).
; ---------------------------------------------------------------------------
resilience_enum_bus0:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    xor  ebx, ebx                               ; dev = 0
.dev_loop:
    xor  r12d, r12d                             ; fn = 0
.fn_loop:
    ; vendor/device at offset 0
    xor  edi, edi                               ; bus 0
    mov  esi, ebx                               ; dev
    mov  edx, r12d                              ; fn
    xor  ecx, ecx                               ; offset 0
    call pci_cfg_read32
    mov  r14d, eax
    and  r14d, 0xFFFF
    cmp  r14d, PCI_VENDOR_NONE
    je   .next_fn                               ; absent function
    ; packed bdf = (bus<<16)|(dev<<8)|fn  (bus 0)
    mov  r15d, ebx
    shl  r15d, 8
    or   r15d, r12d
    ; remember the FIRST present device as a fallback rep BDF (until a root port wins)
    cmp  qword [rel aer_rep_bdf], -1
    jne  .have_rep
    mov  [rel aer_rep_bdf], r15
.have_rep:
    ; capability list present? (Status bit4)
    xor  edi, edi
    mov  esi, ebx
    mov  edx, r12d
    mov  ecx, PCI_STATUS_DW
    call pci_cfg_read32
    test eax, PCI_STATUS_CAPLIST
    jz   .next_fn
    ; first cap pointer
    xor  edi, edi
    mov  esi, ebx
    mov  edx, r12d
    mov  ecx, PCI_CAP_PTR
    call pci_cfg_read32
    and  eax, 0xFC
    mov  r13d, eax                              ; r13 = cap ptr
    xor  ebp, ebp                               ; walk guard (bounded)
.cap_walk:
    test r13d, r13d
    jz   .next_fn                               ; end of list
    cmp  r13d, 0x40
    jb   .next_fn                               ; caps live at >=0x40; malformed -> stop
    inc  ebp
    cmp  ebp, 48
    ja   .next_fn                               ; bounded (never loop forever on bad hw)
    ; read cap dword: al=cap id, [15:8]=next
    xor  edi, edi
    mov  esi, ebx
    mov  edx, r12d
    mov  ecx, r13d
    and  ecx, 0xFC
    call pci_cfg_read32
    mov  r14d, eax                              ; cap header dword
    cmp  al, PCIE_CAP_ID
    je   .found_pcie
    shr  r14d, 8
    and  r14d, 0xFC
    mov  r13d, r14d                             ; next cap ptr
    jmp  .cap_walk
.found_pcie:
    ; PCIe Capabilities register at cap+0x02 -> high word of the cap header dword
    mov  r14d, eax
    shr  r14d, 16                               ; PCIe Caps register (word)
    shr  r14d, 4
    and  r14d, 0xF                              ; Device/Port Type
    cmp  r14d, PCIE_PORTTYPE_ROOT
    jne  .next_fn                               ; a PCIe endpoint, not a root port
    ; --- a real root port: count it, prefer its BDF, configure bounded CTO ---
    inc  dword [rel aer_rootport_count]
    mov  [rel aer_rep_bdf], r15                 ; a root port is the best source BDF
    ; Bind actual root ports, including v1, using segment0 packed dev:5/fn:3.
    ; Keep the original cap header intact for the existing CTO version check.
    push rax
    mov edi,ebx
    shl edi,3
    or edi,r12d
    call aer_poll_bind_root
    pop rax
    ; DevCap2/DevCtl2 exist only in PCIe capability version 2 or later.
    ; Keep discovery on older ports, but never access their absent registers.
    shr  eax, 16
    and  eax, 0xF
    cmp  eax, 2
    jb   .next_fn
    ; The sanctioned legacy accessor masks offsets to the first 256 bytes.
    ; Require the complete DevCtl2 dword before forming either v2 offset.
    cmp  r13d, 0xFC - PCIE_DEVCTL2_OFF
    ja   .next_fn
    ; DevCap2 (cap+0x24): CTO Ranges Supported (bits 3:0)
    lea  ecx, [r13 + PCIE_DEVCAP2_OFF]
    and  ecx, 0xFC
    xor  edi, edi
    mov  esi, ebx
    mov  edx, r12d
    call pci_cfg_read32
    mov  r14d, eax
    and  r14d, 0x0F                             ; ranges supported bitmask
    ; DevCtl2 (cap+0x28): select CTO Value (bits 3:0) and enable timeout (bit4=0).
    lea  ecx, [r13 + PCIE_DEVCTL2_OFF]
    and  ecx, 0xFC
    xor  edi, edi
    mov  esi, ebx
    mov  edx, r12d
    call pci_cfg_read32
    and  eax, 0xFFFFFFE0                        ; clear CTO Value + Disable; preserve unrelated controls
    ; choose a supported bounded value: prefer range A (1ms-10ms), else range B
    test r14d, 0x1                              ; range A supported?
    jz   .try_b
    or   eax, CTO_VAL_RANGE_A
    mov  ebp, CTO_US_RANGE_A                    ; candidate bound, publish only after readback
    jmp  .cto_write
.try_b:
    test r14d, 0x2                              ; range B supported?
    jz   .cto_default
    or   eax, CTO_VAL_RANGE_B
    mov  ebp, CTO_US_RANGE_B
    jmp  .cto_write
.cto_default:
    ; advertises no supplemental ranges -> keep default (0x0 = 50us-50ms), still bounded
    mov  ebp, CTO_US_DEFAULT
.cto_write:
    ; write DevCtl2 back (bounded, spec-defined value)
    mov  r14d, eax
    and  r14d, 0x1F                            ; expected timeout value + Disable
    mov  r8d, eax
    lea  ecx, [r13 + PCIE_DEVCTL2_OFF]
    and  ecx, 0xFC
    xor  edi, edi
    mov  esi, ebx
    mov  edx, r12d
    call pci_cfg_write32
    ; A write attempt alone is not hardware acceptance. Restore fn after the
    ; accessor's DX clobber and read the same control dword. Other controls and
    ; status bits may change independently; compare only CTO Value + Disable.
    lea  ecx, [r13 + PCIE_DEVCTL2_OFF]
    and  ecx, 0xFC
    xor  edi, edi
    mov  esi, ebx
    mov  edx, r12d
    call pci_cfg_read32
    and  eax, 0x1F
    cmp  eax, r14d
    jne  .next_fn                             ; retain any earlier verified port
    mov  [rel cto_us], ebp
    mov  byte [rel cto_applied], 1
.next_fn:
    inc  r12d
    cmp  r12d, 8
    jb   .fn_loop
    inc  ebx
    cmp  ebx, 32
    jb   .dev_loop
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; aer_capture(RDI=tag ptr, RSI=class id) — THE AER catch/log path (a real interrupt or
;   the injection surface calls this). Copies the tag into the last-record slot beside
;   a plausible class + the real enumerated source BDF, bumps the count, and appends the
;   record to the persistent C2 diag ring. This software observation (also used by
;   selftest/injection) establishes neither hardware origin nor containment. BSP
;   serialized, like the retained ring; clobbers: caller-saved. EAX=1 captured,
;   0 refused (NULL tag or unregistered full-width class), with no mutation.
;   Current callers are software selftest/injection only; class totals do not
;   establish real corrected-error observations or a live AER delivery path.
; ---------------------------------------------------------------------------
aer_capture:
    cmp  rsi, AER_CLASS_CORR
    jb   .refused
    cmp  rsi, AER_CLASS_FATAL
    ja   .refused
    test rdi, rdi
    jz   .refused
    push rbx
    push r12
    mov  r12, rsi                               ; class id
    ; bounded copy of the tag (max 31 chars + NUL)
    lea  rbx, [rel aer_last_tag]
    xor  ecx, ecx
.cp:
    mov  al, [rdi + rcx]
    mov  [rbx + rcx], al
    test al, al
    jz   .cpd
    inc  ecx
    cmp  ecx, 31
    jb   .cp
    mov  byte [rbx + 31], 0
.cpd:
    mov  [rel aer_last_class], r12d
    mov  rax, [rel aer_rep_bdf]
    mov  [rel aer_last_bdf], rax
    ; MAX is a retained lower bound, never absence. Last identity still updates.
    cmp  qword [rel aer_count], -1
    je   .counted
    inc  qword [rel aer_count]
.counted:
    ; Each admitted software observation contributes to exactly one class.
    ; Total and class saturate independently; a saturated class must not prevent
    ; another class or the fresh last-record identity from being recorded.
    lea  rax, [rel aer_class_counts]
    lea  rcx, [r12 - AER_CLASS_CORR]
    cmp  qword [rax + rcx * 8], -1
    je   .class_counted
    inc  qword [rax + rcx * 8]
.class_counted:
    ; append to the persistent diag ring: kind=AER, arg=count, a=class, b=bdf, tag
    mov  edi, DIAG_KIND_AER
    ; Fixed diag arg32 carries min(total, UINT32_MAX), not a wrapped low word.
    mov  rax, [rel aer_count]
    mov  esi, -1
    cmp  rax, rsi
    jae  .diag_count
    mov  esi, eax
.diag_count:
    mov  edx, r12d                              ; a = class
    mov  rcx, [rel aer_rep_bdf]                 ; b = source bdf
    xor  r8d, r8d                               ; c = 0
    lea  r9, [rel aer_last_tag]
    call diag_ring_append
    pop  r12
    pop  rbx
    mov  eax, 1
    ret
.refused:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; iommu_capture(RDI=tag) remains the synthetic compatibility injection used by
; IOMMUINJECT. iommu_capture_live(RDI=tag, RSI=BDF, RDX=fault address,
; RCX=nonzero FRCD reason byte) records
; an actual FRCD decoded by the VT-d owner. Both share the same bounded
; persistent-ring path; only the live entry may assert that DMAR is present.
; ---------------------------------------------------------------------------
iommu_capture:
    mov  rsi, [rel aer_rep_bdf]
    rdtsc
    shl  rax, 12
    or   rax, 0x1000
    mov  rdx, rax
    jmp  iommu_capture_record

iommu_capture_live:
    ; Live callers: BSP registry DMAVIOL and Intel DMAVIOLA, after native FRCD validation.
    ; No IRQ/AP caller or installed live interrupt entry exists. Like diag, this
    ; queue is BSP-owned; do not call this entry from an ISR/AP. Capture never
    ; enters the audit spine, allocates, waits or touches hardware.
    push rdi
    push rsi
    push rdx
    mov  rdi, rsi
    mov  rsi, rcx
    call iommu_sec_enqueue
    pop  rdx
    pop  rsi
    pop  rdi
    mov  byte [rel iommu_present], 1

iommu_capture_record:
    push rbx
    push r12
    push r13
    mov  r12, rsi
    mov  r13, rdx
    lea  rbx, [rel iommu_last_tag]
    xor  ecx, ecx
.cp:
    mov  al, [rdi + rcx]
    mov  [rbx + rcx], al
    test al, al
    jz   .cpd
    inc  ecx
    cmp  ecx, 31
    jb   .cp
    mov  byte [rbx + 31], 0
.cpd:
    mov  [rel iommu_last_bdf], r12
    mov  [rel iommu_last_addr], r13
    ; MAX is a retained lower bound, never absence. Last identity still updates.
    cmp  qword [rel iommu_count], -1
    je   .counted
    inc  qword [rel iommu_count]
.counted:
    mov  edi, DIAG_KIND_IOMMU
    ; Fixed diag arg32 carries min(total, UINT32_MAX), not a wrapped low word.
    mov  rax, [rel iommu_count]
    mov  esi, -1
    cmp  rax, rsi
    jae  .diag_count
    mov  esi, eax
.diag_count:
    xor  edx, edx
    mov  rcx, [rel iommu_last_bdf]              ; b = faulting bdf
    mov  r8, [rel iommu_last_addr]              ; c = fault address
    lea  r9, [rel iommu_last_tag]
    call diag_ring_append
    pop  r13
    pop  r12
    pop  rbx
    ret

; Native observation queue: eight numeric records, consumed two per idle
; watch. Identity is boot-local epoch16:serial32, never recycled. Reset drops
; pending records explicitly and advances epoch; overflow freezes admission.
; Observed/drop totals saturate and survive producer reset. KAT brackets neither
; enqueue nor drain, so an earlier real pending event survives their restore.
IOMMU_SEC_N equ 8
IOMMU_SEC_SZ equ 16
IOMMU_SEC_BUDGET equ 2
IOMMU_SEC_AMD_CODE equ (4 << 16) | 2

iommu_sec_reset:
    cmp  byte [rel audit_sec_test_active], 0
    jne  .out
    mov  eax, [rel iommu_sec_pending]
    add  [rel iommu_sec_drops], rax
    jnc  .drop_ok
    mov  qword [rel iommu_sec_drops], -1
.drop_ok:
    mov  dword [rel iommu_sec_pending], 0
    mov  dword [rel iommu_sec_head], 0
    mov  dword [rel iommu_sec_tail], 0
    mov  dword [rel iommu_sec_serial], 0
    cmp  qword [rel iommu_sec_epoch], 65535
    jae  .frozen
    inc  qword [rel iommu_sec_epoch]
    mov  byte [rel iommu_sec_frozen], 0
    jmp  .clear
.frozen:
    mov  byte [rel iommu_sec_frozen], 1
.clear:
    lea  rdi, [rel iommu_sec_amd_generation]
    xor  esi, esi
    mov  edx, IOMMU_SEC_N * 8
    sub  rsp, 8
    call memset
    add  rsp, 8
    lea  rdi, [rel iommu_sec_queue]
    xor  esi, esi
    mov  edx, IOMMU_SEC_N * IOMMU_SEC_SZ
    jmp  memset
.out:
    ret

; RDI=BDF (full64 range checked), RSI=FRCD reason (1..255).
iommu_sec_enqueue:
    cmp  byte [rel audit_sec_test_active], 0
    jne  .out
    cmp  rdi, 65535
    ja   .drop
    test rsi, rsi
    jz   .drop
    cmp  rsi, 255
    ja   .drop
    cmp  byte [rel iommu_sec_frozen], 0
    jne  .drop
    cmp  qword [rel iommu_sec_epoch], 0
    je   .drop
    cmp  qword [rel iommu_sec_epoch], 65535
    ja   .drop
    cmp  qword [rel iommu_sec_observed], -1
    je   .freeze
    cmp  dword [rel iommu_sec_serial], -1
    je   .freeze
    inc  dword [rel iommu_sec_serial]
    add  qword [rel iommu_sec_observed], 1
    jnc  .counted
    mov  qword [rel iommu_sec_observed], -1
.counted:
    cmp  dword [rel iommu_sec_pending], IOMMU_SEC_N
    jae  .drop
    mov  eax, [rel iommu_sec_head]
    cmp  eax, IOMMU_SEC_N
    jae  .drop
    shl  eax, 4
    lea  rdx, [rel iommu_sec_queue]
    add  rdx, rax
    mov  rax, [rel iommu_sec_epoch]
    shl  rax, 32
    mov  ecx, [rel iommu_sec_serial]
    or   rax, rcx
    mov  [rdx], rax
    mov  [rdx + 8], edi
    mov  [rdx + 12], esi
    inc  dword [rel iommu_sec_head]
    and  dword [rel iommu_sec_head], IOMMU_SEC_N - 1
    inc  dword [rel iommu_sec_pending]
    ret
.freeze:
    mov  byte [rel iommu_sec_frozen], 1
.drop:
    add  qword [rel iommu_sec_drops], 1
    jnc  .out
    mov  qword [rel iommu_sec_drops], -1
.out:
    ret


; Native AMD consumer only: RDI=requester, RSI=2(IOPF) or0(summary-only),
; RDX=1..255 consumed records/one unknown overflow episode, RCX=owner generation.
; Shared serial/epoch prevent cross-backend collisions; old VT-d encoder/body
; and16B queue stride are untouched. A64B sidecar pins AMD owner generations.
iommu_sec_enqueue_amd:
    cmp  byte [rel audit_sec_test_active], 0
    jne  .out
    cmp  rdi, 65535
    ja   .out
    test rsi, rsi
    jz   .type_ok
    cmp  rsi, 2
    jne  .out
.type_ok:
    test rdx, rdx
    jz   .out
    cmp  rdx, 255
    ja   .out
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    call amdvi_observation_publishing
    test rax, rax
    jz   .done
    cmp  rax, r15
    jne  .done
    cmp  rax, -1
    je   .done
    cmp  byte [rel iommu_sec_frozen], 0
    jne  .drop_all
    cmp  qword [rel iommu_sec_epoch], 0
    je   .drop_all
    cmp  qword [rel iommu_sec_epoch], 65535
    ja   .drop_all
    cmp  qword [rel iommu_sec_observed], -1
    je   .freeze
    cmp  dword [rel iommu_sec_serial], -1
    je   .freeze
    mov  rax, [rel iommu_sec_observed]
    add  rax, r14
    jc   .total_exhausted
    mov  [rel iommu_sec_observed], rax
    test r13, r13
    jz   .drop_all                          ; unsupported/unknown: aggregate only
    inc  dword [rel iommu_sec_serial]
    cmp  dword [rel iommu_sec_pending], IOMMU_SEC_N
    jae  .drop_all
    mov  ebx, [rel iommu_sec_head]
    cmp  ebx, IOMMU_SEC_N
    jae  .drop_all
    lea  rdx, [rel iommu_sec_amd_generation]
    mov  [rdx + rbx*8], r15
    shl  ebx, 4
    lea  rdx, [rel iommu_sec_queue]
    add  rdx, rbx
    mov  rax, [rel iommu_sec_epoch]
    shl  rax, 32
    mov  ecx, [rel iommu_sec_serial]
    or   rax, rcx
    mov  [rdx], rax
    mov  [rdx + 8], r12d
    mov  dword [rdx + 12], IOMMU_SEC_AMD_CODE
    inc  dword [rel iommu_sec_head]
    and  dword [rel iommu_sec_head], IOMMU_SEC_N - 1
    inc  dword [rel iommu_sec_pending]
    dec  r14                               ; first detail retained, rest unknown/discarded
    jmp  .drop_all
.total_exhausted:
    mov  qword [rel iommu_sec_observed], -1
.freeze:
    mov  byte [rel iommu_sec_frozen], 1
.drop_all:
    mov  rdi, r14
    call iommu_sec_amd_drop
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
.out:
    ret

; RDI=lost details, saturating. Unknown overflow is a lower bound of one lost
; record per sticky episode, not a claim of an exact hardware loss count.
iommu_sec_amd_drop:
    add  [rel iommu_sec_drops], rdi
    jnc  .out
    mov  qword [rel iommu_sec_drops], -1
.out:
    ret

; BSP idle only. Public total includes observations whose detail queue overflowed;
; drop count describes lost detail, never successful DMA enforcement. No hardware
; sampling occurs here. Pop/clear before publication prevents stale re-delivery.
iommu_sec_drain:
    cmp  byte [rel audit_sec_test_active], 0
    jne  .out
    push rbx
    mov  rdi, [rel iommu_sec_observed]
    mov  rsi, [rel iommu_sec_drops]
    call audit_sec_iommu_sync
    mov  ebx, IOMMU_SEC_BUDGET
.loop:
    cmp  dword [rel iommu_sec_pending], 0
    je   .done
    cmp  dword [rel iommu_sec_pending], IOMMU_SEC_N
    ja   .corrupt
    mov  eax, [rel iommu_sec_tail]
    cmp  eax, IOMMU_SEC_N
    jae  .corrupt
    lea  rcx, [rel iommu_sec_amd_generation]
    mov  r8, [rcx + rax*8]
    mov  qword [rcx + rax*8], 0
    shl  eax, 4
    lea  rcx, [rel iommu_sec_queue]
    add  rcx, rax
    mov  rdi, [rcx]
    mov  esi, [rcx + 8]
    mov  edx, [rcx + 12]
    mov  qword [rcx], 0
    mov  qword [rcx + 8], 0
    inc  dword [rel iommu_sec_tail]
    and  dword [rel iommu_sec_tail], IOMMU_SEC_N - 1
    dec  dword [rel iommu_sec_pending]
    cmp  edx, IOMMU_SEC_AMD_CODE
    je   .amd
    call audit_sec_iommu_event
    jmp  .next
.amd:
    push rdi
    push rsi
    push r8
    sub  rsp, 8
    call amdvi_observation_generation
    add  rsp, 8
    pop  r8
    pop  rsi
    pop  rdi
    test rax, rax
    jz   .amd_stale
    cmp  rax, r8
    jne  .amd_stale
    mov  edx, 2
    call audit_sec_iommu_amd_event
    jmp  .next
.amd_stale:
    mov  edi, 1
    call iommu_sec_amd_drop
    mov  rdi, [rel iommu_sec_observed]
    mov  rsi, [rel iommu_sec_drops]
    call audit_sec_iommu_sync            ; publish newly discarded stale detail this tick
.next:
    dec  ebx
    jnz  .loop
.done:
    pop  rbx
.out:
    ret
.corrupt:
    ; Invalid metadata cannot index memory or fabricate an observation.
    call iommu_sec_reset
    jmp  .done

; iommu_fault_count() -> RAX=saturating saved observations; MAX is a lower bound.
iommu_fault_count:
    mov  rax, [rel iommu_count]
    ret

; ---------------------------------------------------------------------------
; resilience_selftest — boot BUILD-GATE: inject a synthetic AER through the SAME capture
;   path and prove it was caught + contained (aer_count advanced AND the host self-test
;   returned — no hang). Emits aer.contained.selftest. clobbers: caller-saved.
; ---------------------------------------------------------------------------
resilience_selftest:
    push rbx
    mov  rbx, [rel aer_count]
    lea  rdi, [rel str_selftest_tag]
    mov  esi, AER_CLASS_UNCORR
    call aer_capture                            ; simulated uncorrectable-nonfatal
    ; contained proof: the capture returned AND advanced the count
    mov  rax, [rel aer_count]
    cmp  rax, rbx
    jbe  .fail                                  ; count did not advance -> not captured
    lea  rdi, [rel str_selftest_ok]
    call serial_string
    mov  byte [rel aer_m_selftest], 1
    pop  rbx
    ret
.fail:
    lea  rdi, [rel str_selftest_fail]
    call serial_string
    pop  rbx
    ret

; ===========================================================================
; UDP/registry PROJECTION — six live verbs. Thin handlers: drive the capture path or
; stage a record line into res_out_buf (framed verbatim by command_udp's udp_send_reply,
; the same staging pattern gov/reinit/thermal use). The raw tag round-trips via ARG=.
; ===========================================================================

; resilience_declare — register the six verbs through the SAME command_register_verb
;   (additive, §9.4 degenerate-Nth seam). clobbers: caller-saved.
resilience_declare:
    lea  rdi, [rel str_verb_aerdmatest]
    lea  rsi, [rel cmd_verb_aerdmatest]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1                            ; owner-mutating; never a read selector
    call command_register_verb
    lea  rdi, [rel str_verb_aerinject]
    lea  rsi, [rel cmd_verb_aerinject]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1                                  ; mutates the AER record ring
    call command_register_verb
    lea  rdi, [rel str_verb_aerlog]
    lea  rsi, [rel cmd_verb_aerlog]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_verb_iommuinject]
    lea  rsi, [rel cmd_verb_iommuinject]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1
    call command_register_verb
    lea  rdi, [rel str_verb_iommulog]
    lea  rsi, [rel cmd_verb_iommulog]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_verb_pciecto]
    lea  rsi, [rel cmd_verb_pciecto]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_verb_pciectoinject]
    lea  rsi, [rel cmd_verb_pciectoinject]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1
    call command_register_verb
    ret

; Exact fixed fixture preparation. Normal registry capability checks apply.
cmd_verb_aerdmatest:
    call cmd_handler_prologue
    push rdi
    push rsi
    call res_read_begin
    cmp byte [rel res_out_error],0
    jne .bad
    mov rax,'prepare/'
    cmp [rel res_read_arg],rax
    jne .bad
    cmp dword [rel res_read_arg+8],'0020'
    jne .bad
    cmp byte [rel res_read_arg+12],0
    jne .bad
    call aer_dma_prepare
    lea rdi,[rel str_aer_dma_prepare]
    call res_out_str
    xor edi,edi
    call aer_dma_page
    mov edi,[rax]
    call res_out_dec
    cmp byte [rel res_out_error],0
    jne .bad
    mov byte [rel res_out_ready],1
    pop rsi
    pop rdi
    mov rax,[rdi+REQ_ARG]
    mov [rsi+RSP_VAL],rax
    mov qword [rsi+RSP_CODE],CMDE_OK
    ret
.bad:
    call res_out_reset
    pop rsi
    pop rdi
    mov qword [rsi+RSP_CODE],CMDE_BADARG
    ret

; --- VERB: AERINJECT <tag> | --fatal <tag> — drive the AER catch path. A "--fatal"
;   arg takes the NEGATIVE-GATE contain/isolate-or-panic-with-diag path (never a silent
;   hang); otherwise capture an uncorrectable-nonfatal record carrying the tag.
cmd_verb_aerinject:
    call cmd_handler_prologue
    push rdi
    push rsi
    mov  rdi, [rdi + REQ_ARG]                   ; raw arg token ptr
    ; fatal? arg begins with "--"
    cmp  byte [rdi], '-'
    jne  .normal
    cmp  byte [rdi + 1], '-'
    jne  .normal
    ; --- NEGATIVE GATE: fatal/uncontainable -> contain + isolate + diag (stay alive) ---
    mov  esi, AER_CLASS_FATAL
    call aer_capture                            ; log the fatal record too (diag ring)
    mov  byte [rel aer_isolated], 1
    call res_out_reset
    lea  rdi, [rel str_ro_fatal]                ; "fatal contained isolate device diag_dumped ..."
    call res_out_str
    jmp  .staged
.normal:
    mov  esi, AER_CLASS_UNCORR
    call aer_capture
    call res_out_reset
    lea  rdi, [rel str_ro_aerinj]
    call res_out_str
    lea  rdi, [rel aer_last_tag]
    call res_out_str
.staged:
    mov  byte [rel res_out_ready], 1
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; --- VERB: AERLOG <last|stats|hw/BBBB|poll/BBBB|ctrl/BBBB|stop/BBBB> — last retains its existing wire grammar.
; Exact stats projects boot-local SOFTWARE observation counts by class, including
; selftest/injection. No device read, interrupt, error clear or containment credit.
; hw/BBBB (four hex digits, segment0 packed BDF) requests a bounded read-only
; hardware sample. Its separate grammar cannot be decoded as a software record.
cmd_verb_aerlog:
    call cmd_handler_prologue
    push rdi
    push rsi
    call res_read_begin
    cmp  byte [rel res_out_error], 0
    jne  .bad
    cmp dword [rel res_read_arg],'ring'
    jne .dma
    cmp byte [rel res_read_arg+4],'/'
    jne .bad
    call res_emit_aer_ring
    test eax,eax
    jz .bad
    jmp .publish
.dma:
    cmp word [rel res_read_arg],'dm'
    jne .stop
    cmp byte [rel res_read_arg+2],'a'
    jne .bad
    call res_emit_aer_dma
    test eax,eax
    jz .bad
    jmp .publish
.stop:
    cmp dword [rel res_read_arg], 'stop'
    jne .poll
    cmp byte [rel res_read_arg+4], '/'
    jne .poll
    call res_emit_aer_stop
    test eax,eax
    jz .bad
    jmp .publish
.poll:
    cmp dword [rel res_read_arg], 'poll'
    jne .hardware
    cmp byte [rel res_read_arg+4], '/'
    jne .hardware
    call res_emit_aer_poll
    test eax,eax
    jz .bad
    jmp .publish
.hardware:
    cmp dword [rel res_read_arg], 'ctrl'
    jne .hardware_status
    cmp byte [rel res_read_arg+4], '/'
    jne .hardware_status
    call res_emit_aer_control
    test eax,eax
    jz .bad
    jmp .publish
.hardware_status:
    cmp  word [rel res_read_arg], 'hw'
    jne  .software
    cmp  byte [rel res_read_arg+2], '/'
    jne  .software
    call res_emit_aer_hardware
    test eax, eax
    jz   .bad
    jmp  .publish
.software:
    cmp  dword [rel res_read_arg], 'stat'
    jne  .last
    cmp  word [rel res_read_arg + 4], 's'    ; exact trailing NUL, not statsX
    jne  .last
    call res_emit_aer_counts
    jmp  .publish
.last:
    cmp  qword [rel aer_count], 0
    je   .class_ok
    cmp  dword [rel aer_last_class], AER_CLASS_CORR
    jb   .bad
    cmp  dword [rel aer_last_class], AER_CLASS_FATAL
    ja   .bad
.class_ok:
    ; A corrupt unterminated saved tag must not cross its 32-byte object.
    lea  rdx, [rel aer_last_tag]
    xor  ecx, ecx
.tag:
    cmp  byte [rdx + rcx], 0
    je   .tag_ok
    inc  ecx
    cmp  ecx, 32
    jb   .tag
    jmp  .bad
.tag_ok:
    lea  rdi, [rel str_ro_aerlast]              ; "aer_last class="
    call res_out_str
    call res_emit_aer_class                     ; corr | uncorr-nonfatal | completion-timeout | fatal
    lea  rdi, [rel str_ro_bdf]                  ; " bdf=0x"
    call res_out_str
    mov  rdi, [rel aer_last_bdf]
    call res_out_hex
    lea  rdi, [rel str_ro_tag]                  ; " tag="
    call res_out_str
    lea  rdi, [rel aer_last_tag]
    call res_out_str
    lea  rdi, [rel str_ro_count]                ; " count="
    call res_out_str
    mov  rdi, [rel aer_count]
    call res_out_dec
    mov  rdi, [rel aer_count]
    call res_out_count_quality
.publish:
    cmp  byte [rel res_out_error], 0
    jne  .bad
    mov  byte [rel res_out_kind], 1
    mov  byte [rel res_out_ready], 1
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret
.bad:
    call res_out_reset
    pop  rsi
    pop  rdi
    mov  qword [rsi + RSP_CODE], CMDE_BADARG
    ret

; Owner-authenticated current hardware records only. Exact head or 16 hex
; sequence grammar; no addresses, scans or retries. Copy96B is local to call.
res_emit_aer_ring:
    push rbx
    push rbp
    push r12
    sub rsp,96
    cmp dword [rel res_read_arg+5],'head'
    jne .sequence
    cmp byte [rel res_read_arg+9],0
    jne .bad
    mov rdi,-1
    jmp .read
.sequence:
    xor ebx,ebx
    mov ebp,5
    lea r12,[rel res_read_arg]
.parse:
    movzx eax,byte [r12+rbp]
    sub eax,'0'
    cmp eax,9
    jbe .digit
    movzx eax,byte [r12+rbp]
    or eax,32
    sub eax,'a'
    cmp eax,5
    ja .bad
    add eax,10
.digit:
    shl rbx,4
    or rbx,rax
    inc ebp
    cmp ebp,21
    jb .parse
    cmp byte [r12+21],0
    jne .bad
    cmp rbx,-1
    je .bad                            ; sentinel is admitted only as ring/head
    mov rdi,rbx
.read:
    mov rsi,rsp
    mov edx,96
    call diag_live_record_copy
    mov ebx,eax
    lea rdi,[rel str_aer_ring]
    call res_out_str
    mov edi,ebx
    call res_out_dec
    test ebx,ebx
    jnz .unavailable
    lea rdi,[rel str_aer_hw_data]
    call res_out_str
    cmp byte [rel res_out_error],0
    jne .bad
    mov rdi,[rel res_out_cur]
    lea rax,[rel res_out_buf+255]
    sub rax,rdi
    cmp rax,192
    jb .bad
    mov rsi,rsp
    mov ecx,96
.hexbyte:
    movzx eax,byte [rsi]
    shr eax,4
    call .nibble
    movzx eax,byte [rsi]
    and eax,15
    call .nibble
    inc rsi
    loop .hexbyte
    mov byte [rdi],0
    mov [rel res_out_cur],rdi
    lea rdi,[rel str_aer_ring_scope]
    jmp .scope
.unavailable:
    lea rdi,[rel str_aer_ring_unavailable]
.scope:
    call res_out_str
    mov eax,1
    jmp .done
.bad:
    xor eax,eax
.done:
    add rsp,96
    pop r12
    pop rbp
    pop rbx
    ret
.nibble:
    add al,'0'
    cmp al,'9'
    jbe .put
    add al,'a'-'9'-1
.put:
    stosb
    ret

; AERLOG poll/BBBB reads retained boot-local hardware observations, no I/O.
; Last reader refusal and retained older data coexist explicitly; no-event is
; unobserved, never proof of quiet. MAX n is a saturated lower bound.
res_emit_aer_poll:
    push rbx
    push rbp
    sub rsp,8
    xor ebx,ebx
    mov ebp,5
    lea rdx,[rel res_read_arg]
.parse:
    movzx eax,byte [rdx+rbp]
    sub eax,'0'
    cmp eax,9
    jbe .digit
    movzx eax,byte [rdx+rbp]
    or eax,32
    sub eax,'a'
    cmp eax,5
    ja .bad
    add eax,10
.digit:
    shl ebx,4
    or ebx,eax
    inc ebp
    cmp ebp,9
    jb .parse
    cmp byte [rel res_read_arg+9],0
    jne .bad
    mov edi,ebx
    call aer_poll_lookup
    mov rbp,rax
    lea rdi,[rel str_aer_poll]
    call res_out_str
    mov edi,ebx
    call res_out_hex
    lea rdi,[rel str_aer_hw_status]
    call res_out_str
    mov edi,11                            ; not bound (not sampled zero)
    test rbp,rbp
    jz .status
    mov edi,[rbp+AER_POLL_STATUS]
.status:
    call res_out_dec
    lea rdi,[rel str_aer_poll_count]
    call res_out_str
    xor edi,edi
    test rbp,rbp
    jz .count
    mov rdi,[rbp+AER_POLL_COUNT]
.count:
    call res_out_hex
    lea rdi,[rel str_aer_poll_time]
    call res_out_str
    xor edi,edi
    test rbp,rbp
    jz .time
    mov rdi,[rbp+AER_POLL_EVENT_US]
.time:
    call res_out_hex
    test rbp,rbp
    jz .unobserved
    test qword [rbp+AER_POLL_FLAGS],2
    jz .unobserved
    lea rdi,[rel str_aer_hw_data]
    call res_out_str
    xor ebx,ebx
.data:
    mov edi,[rbp+AER_POLL_EVENT+rbx*4]
    call res_out_hex
    inc ebx
    cmp ebx,16
    jae .retained
    lea rdi,[rel str_aer_hw_slash]
    call res_out_str
    jmp .data
.retained:
    lea rdi,[rel str_aer_poll_retained]
    jmp .scope
.unobserved:
    lea rdi,[rel str_aer_poll_unobserved]
.scope:
    call res_out_str
    lea rdi,[rel str_aer_poll_blind]
    call res_out_str
    test rbp,rbp
    jz .blind_unknown
    test qword [rbp+AER_POLL_FLAGS],1
    jz .blind_unknown
    mov edi,[rbp+AER_POLL_BLIND]
    call res_out_hex
    jmp .blind_done
.blind_unknown:
    lea rdi,[rel str_aer_poll_unknown]
    call res_out_str
.blind_done:
    test rbp,rbp
    jz .boot_done
    cmp qword [rbp+AER_BOOT_VALID],0
    je .boot_done
    lea rdi,[rel str_aer_boot]
    call res_out_str
    xor ebx,ebx
.boot_header:
    mov rdi,[rbp+AER_BOOT_VALID+rbx*8]
    call res_out_hex
    lea rdi,[rel str_aer_hw_slash]
    call res_out_str
    inc ebx
    cmp ebx,4
    jb .boot_header
    xor ebx,ebx
.boot_raw:
    mov edi,[rbp+AER_BOOT_RAW+rbx*4]
    call res_out_hex
    inc ebx
    cmp ebx,16
    jae .boot_root_begin
    lea rdi,[rel str_aer_hw_slash]
    call res_out_str
    jmp .boot_raw
.boot_root_begin:
    xor ebx,ebx
.boot_root:
    lea rdi,[rel str_aer_hw_slash]
    call res_out_str
    mov rdi,[rbp+AER_BOOT_ROOT_FLAGS+rbx*8]
    call res_out_hex
    inc ebx
    cmp ebx,4
    jb .boot_root
.boot_done:
    xor ebx,ebx
    test rbp,rbp
    jz .q_begin
    mov edi,[rbp]
    call aer_poll_coverage_lookup
    mov rbx,rax
.q_begin:
    lea rdi,[rel str_aer_qv]
    call res_out_str
    xor ebp,ebp
.q_next:
    lea rdx,[rel aer_q_fields]
    movsxd rdi,dword [rdx+rbp*8]
    lea rdi,[rdi+rdx]
    call res_out_str
    xor edi,edi
    test rbx,rbx
    jnz .q_value
    test ebp,ebp
    jnz .q_emit
    mov edi,11
    jmp .q_emit
.q_value:
    lea rdx,[rel aer_q_fields]
    movzx eax,byte [rdx+rbp*8+4]
    mov rdi,[rbx+rax]
    cmp byte [rdx+rbp*8+5],4
    jne .q_emit
    mov edi,edi
.q_emit:
    call res_out_hex
    inc ebp
    cmp ebp,12
    jb .q_next
    mov eax,1
    jmp .done
.bad:
    xor eax,eax
.done:
    add rsp,8
    pop rbp
    pop rbx
    ret

 ; AERLOG stop/BBBB is a retained configuration-stop outcome, never a DMA
; cessation claim. Exact 16 raw dwords are read without I/O or state mutation.
; Fixed64B RAM pages only. No implicit tick, allocation or device I/O.
res_emit_aer_dma:
    push rbx
    push rbp
    sub rsp,8
    movzx ebx,byte [rel res_read_arg+3]
    sub ebx,'0'
    cmp ebx,7
    ja .bad
    cmp byte [rel res_read_arg+4],'/'
    jne .bad
    cmp dword [rel res_read_arg+5],'0020'
    jne .bad
    cmp byte [rel res_read_arg+9],0
    jne .bad
    mov edi,ebx
    call aer_dma_page
    test rax,rax
    jz .bad
    mov rbp,rax
    lea rdi,[rel str_aer_dma]
    call res_out_str
    mov edi,ebx
    call res_out_dec
    lea rdi,[rel str_aer_hw_data]
    call res_out_str
    xor ebx,ebx
.data:
    mov edi,[rbp+rbx*4]
    call res_out_hex
    inc ebx
    cmp ebx,16
    je .yes
    lea rdi,[rel str_aer_hw_slash]
    call res_out_str
    jmp .data
.yes:
    mov eax,1
    jmp .done
.bad:
    xor eax,eax
.done:
    add rsp,8
    pop rbp
    pop rbx
    ret

res_emit_aer_stop:
    push rbx
    push rbp
    sub rsp,8
    xor ebx,ebx
    mov ebp,5
    lea rdx,[rel res_read_arg]
.parse:
    movzx eax,byte [rdx+rbp]
    sub eax,'0'
    cmp eax,9
    jbe .digit
    movzx eax,byte [rdx+rbp]
    or eax,32
    sub eax,'a'
    cmp eax,5
    ja .bad
    add eax,10
.digit:
    shl ebx,4
    or ebx,eax
    inc ebp
    cmp ebp,9
    jb .parse
    cmp byte [rel res_read_arg+9],0
    jne .bad
    cmp ebx,255
    ja .bad
    mov edi,ebx
    call pci_contain_lookup
    mov rbp,rax
    lea rdi,[rel str_aer_stop]
    call res_out_str
    mov edi,ebx
    call res_out_hex
    lea rdi,[rel str_aer_hw_status]
    call res_out_str
    xor edi,edi
    test rbp,rbp
    jz .status
    mov edi,[rbp]
.status:
    call res_out_dec
    test rbp,rbp
    jz .scope
    lea rdi,[rel str_aer_hw_data]
    call res_out_str
    xor ebx,ebx
.data:
    mov edi,[rbp+rbx*4]
    call res_out_hex
    inc ebx
    cmp ebx,16
    jae .scope
    lea rdi,[rel str_aer_hw_slash]
    call res_out_str
    jmp .data
.scope:
    lea rdi,[rel str_aer_stop_scope]
    call res_out_str
    mov eax,1
    jmp .done
.bad:
    xor eax,eax
.done:
    add rsp,8
    pop rbp
    pop rbx
    ret

; New hardware view only. No software counters, ring records or isolation flags
; change. status0 carries exactly16 raw hex dwords in pci_aer_snapshot wire order;
; all refusals omit data (a stale private sample cannot become apparent quiet).
; diag_v1 appends the eight diagnostic dwords documented at pci_ext_find_cap;
; diagnostics describe this same bounded access, never qualify an unavailable BDF.
; See bus/pci_bdf status0..9; pending bitmaps are samples, not physical totals.
res_emit_aer_hardware:
    push rbx
    push rbp
    sub rsp, 8
    xor ebx, ebx
    mov ebp, 3
    lea rdx, [rel res_read_arg]
.parse:
    movzx eax, byte [rdx+rbp]
    sub eax, '0'
    cmp eax, 9
    jbe .digit
    movzx eax, byte [rdx+rbp]
    or eax, 32
    sub eax, 'a'
    cmp eax, 5
    ja .bad
    add eax, 10
.digit:
    shl ebx, 4
    or ebx, eax
    inc ebp
    cmp ebp, 7
    jb .parse
    cmp byte [rel res_read_arg+7], 0
    jne .bad
    mov edi, ebx
    lea rsi, [rel res_aer_hw_sample]
    call pci_ecam_aer_snapshot
    mov [rel res_aer_hw_diag], r8
    mov [rel res_aer_hw_diag+8], r9
    mov [rel res_aer_hw_diag+16], r10
    mov [rel res_aer_hw_diag+24], r11
    mov ebp, eax
    lea rdi, [rel str_aer_hw]
    call res_out_str
    mov edi, ebx
    call res_out_hex
    lea rdi, [rel str_aer_hw_status]
    call res_out_str
    mov edi, ebp
    call res_out_dec
    test ebp, ebp
    jnz .unavailable
    lea rdi, [rel str_aer_hw_data]
    call res_out_str
    xor ebx, ebx
.data:
    lea rax, [rel res_aer_hw_sample]
    mov edi, [rax+rbx*4]
    call res_out_hex
    inc ebx
    cmp ebx, 16
    jae .sampled
    lea rdi, [rel str_aer_hw_slash]
    call res_out_str
    jmp .data
.sampled:
    lea rdi, [rel str_aer_hw_scope]
    jmp .scope
.unavailable:
    lea rdi, [rel str_aer_hw_unavailable]
    cmp ebp,12
    jne .scope
    lea rdi,[rel str_aer_hw_not_applicable]
.scope:
    call res_out_str
    lea rdi, [rel str_aer_hw_diag]
    call res_out_str
    xor ebx, ebx
.diagnostic:
    lea rax, [rel res_aer_hw_diag]
    mov edi, [rax+rbx*4]
    call res_out_hex
    inc ebx
    cmp ebx, 8
    jae .diagnostic_done
    lea rdi, [rel str_aer_hw_slash]
    call res_out_str
    jmp .diagnostic
.diagnostic_done:
    mov eax, 1
    jmp .done
.bad:
    xor eax, eax
.done:
    add rsp, 8
    pop rbp
    pop rbx
    ret

; Read-only qualified PCIe/AER controls; separate grammar, no IRQ route claim.
res_emit_aer_control:
    push rbx
    push rbp
    sub rsp, 8
    xor ebx, ebx
    mov ebp, 5
    lea rdx, [rel res_read_arg]
.parse:
    movzx eax, byte [rdx+rbp]
    sub eax, '0'
    cmp eax, 9
    jbe .digit
    movzx eax, byte [rdx+rbp]
    or eax, 32
    sub eax, 'a'
    cmp eax, 5
    ja .bad
    add eax, 10
.digit:
    shl ebx, 4
    or ebx, eax
    inc ebp
    cmp ebp, 9
    jb .parse
    cmp byte [rel res_read_arg+9], 0
    jne .bad
    mov edi, ebx
    lea rsi, [rel res_aer_ctl_sample]
    call pci_ecam_aer_control_snapshot
    mov ebp, eax
    test eax,eax
    jnz .report
    ; All qualified AER functions join read coverage, including endpoints.
    ; This does not grant reporting/IRQ or widen configuration containment.
    mov edi,ebx
    call aer_poll_bind                    ; bounded retained observation only
.report:
    lea rdi, [rel str_aer_ctl]
    call res_out_str
    mov edi, ebx
    call res_out_hex
    lea rdi, [rel str_aer_hw_status]
    call res_out_str
    mov edi, ebp
    call res_out_dec
    test ebp, ebp
    jnz .unavailable
    lea rdi, [rel str_aer_hw_data]
    call res_out_str
    xor ebx, ebx
.data:
    lea rax, [rel res_aer_ctl_sample]
    mov edi, [rax+rbx*4]
    call res_out_hex
    inc ebx
    cmp ebx, 16
    jae .sampled
    lea rdi, [rel str_aer_hw_slash]
    call res_out_str
    jmp .data
.sampled:
    lea rdi, [rel str_aer_ctl_scope]
    jmp .scope
.unavailable:
    lea rdi, [rel str_aer_ctl_unavailable]
.scope:
    call res_out_str
    mov eax, 1
    jmp .done
.bad:
    xor eax, eax
.done:
    add rsp, 8
    pop rbp
    pop rbx
    ret

; Bounded read-only scalar projection. All five counters at MAX are lower bounds
; (even an exact MAX is conservatively labelled); zero never means hardware quiet.
; Same BSP-serialized ownership as aer_capture, no atomic cross-CPU snapshot.
res_emit_aer_counts:
    push rbx
    push r12
    lea  rdi, [rel str_ro_aercounts]
    call res_out_str
    mov  rdi, [rel aer_count]
    call res_out_dec
    lea  rdi, [rel str_ro_aercorrected]
    call res_out_str
    mov  rdi, [rel aer_class_counts]
    call res_out_dec
    lea  rdi, [rel str_ro_aernonfatal]
    call res_out_str
    mov  rdi, [rel aer_class_counts + 8]
    call res_out_dec
    lea  rdi, [rel str_ro_aertimeout]
    call res_out_str
    mov  rdi, [rel aer_class_counts + 16]
    call res_out_dec
    lea  rdi, [rel str_ro_aerfatal]
    call res_out_str
    mov  rdi, [rel aer_class_counts + 24]
    call res_out_dec
    mov  rdi, [rel aer_count]
    cmp  rdi, -1
    je   .quality
    lea  rbx, [rel aer_class_counts]
    xor  r12d, r12d
.scan:
    cmp  qword [rbx + r12 * 8], -1
    je   .lower
    inc  r12d
    cmp  r12d, 4
    jb   .scan
    xor  edi, edi
    jmp  .quality
.lower:
    mov  rdi, -1
.quality:
    call res_out_count_quality
    pop  r12
    pop  rbx
    ret

; --- VERB: IOMMUINJECT <tag> — drive the DMAR fault catch path (bad DMA blocked+logged).
cmd_verb_iommuinject:
    call cmd_handler_prologue
    push rdi
    push rsi
    mov  rdi, [rdi + REQ_ARG]
    call iommu_capture
    call res_out_reset
    lea  rdi, [rel str_ro_iommuinj]
    call res_out_str
    lea  rdi, [rel iommu_last_tag]
    call res_out_str
    mov  byte [rel res_out_ready], 1
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; --- VERB: IOMMULOG <last> — read back the last DMAR fault record: faulting BDF + fault
;   address + the exact stored tag. Content the probe grades.
cmd_verb_iommulog:
    call cmd_handler_prologue
    push rdi
    push rsi
    call res_read_begin
    call res_out_amdvi_lab_event
    test eax,eax
    jnz .formatted
    lea  rdx, [rel iommu_last_tag]
    xor  ecx, ecx
.tag:
    cmp  byte [rdx + rcx], 0
    je   .tag_ok
    inc  ecx
    cmp  ecx, 32
    jb   .tag
    jmp  .bad
.tag_ok:
    lea  rdi, [rel str_ro_dmarlast]             ; "dmar_fault bdf=0x"
    call res_out_str
    mov  rdi, [rel iommu_last_bdf]
    call res_out_hex
    lea  rdi, [rel str_ro_faddr]                ; " fault_addr=0x"
    call res_out_str
    mov  rdi, [rel iommu_last_addr]
    call res_out_hex
    lea  rdi, [rel str_ro_tag]                  ; " tag="
    call res_out_str
    lea  rdi, [rel iommu_last_tag]
    call res_out_str
    lea  rdi, [rel str_ro_present]              ; " vtd_present="
    call res_out_str
    movzx edi, byte [rel iommu_present]
    call res_out_dec
    lea  rdi, [rel str_ro_count]
    call res_out_str
    mov  rdi, [rel iommu_count]
    call res_out_dec
    mov  rdi, [rel iommu_count]
    call res_out_count_quality
.formatted:
    cmp  byte [rel res_out_error], 0
    jne  .bad
    mov  byte [rel res_out_kind], 3
    mov  byte [rel res_out_ready], 1
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

.bad:
    call res_out_reset
    pop  rsi
    pop  rdi
    mov  qword [rsi + RSP_CODE], CMDE_BADARG
    ret

; --- VERB: PCIECTO <status> — report the configured bounded completion-timeout.
cmd_verb_pciecto:
    call cmd_handler_prologue
    push rdi
    push rsi
    call res_read_begin
    lea  rdi, [rel str_ro_cto]                  ; "cto=on timeout_us="
    call res_out_str
    mov  edi, [rel cto_us]                       ; dword (32-bit) — read as edi, zero-extends
    call res_out_dec
    lea  rdi, [rel str_ro_ctorp]                ; " rootports="
    call res_out_str
    mov  edi, [rel aer_rootport_count]
    call res_out_dec
    lea  rdi, [rel str_ro_ctoapplied]           ; " applied="
    call res_out_str
    movzx edi, byte [rel cto_applied]
    call res_out_dec
    cmp  byte [rel res_out_error], 0
    jne  .bad
    mov  byte [rel res_out_kind], 2
    mov  byte [rel res_out_ready], 1
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret
.bad:
    call res_out_reset
    pop  rsi
    pop  rdi
    mov  qword [rsi + RSP_CODE], CMDE_BADARG
    ret

; --- VERB: PCIECTOINJECT <tag> — a completion that never returns: the CTO fires and is
;   surfaced as an AER completion-timeout record carrying the tag (read via AERLOG last).
cmd_verb_pciectoinject:
    call cmd_handler_prologue
    push rdi
    push rsi
    mov  rdi, [rdi + REQ_ARG]
    mov  esi, AER_CLASS_CTO
    call aer_capture                            ; CTO surfaces through the AER record ring
    call res_out_reset
    lea  rdi, [rel str_ro_ctoinj]
    call res_out_str
    lea  rdi, [rel aer_last_tag]
    call res_out_str
    mov  byte [rel res_out_ready], 1
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; res_emit_aer_class — append the human class string for aer_last_class.
res_emit_aer_class:
    mov  eax, [rel aer_last_class]
    cmp  eax, AER_CLASS_CORR
    je   .corr
    cmp  eax, AER_CLASS_CTO
    je   .cto
    cmp  eax, AER_CLASS_FATAL
    je   .fatal
    lea  rdi, [rel str_cls_uncorr]
    jmp  .emit
.corr:
    lea  rdi, [rel str_cls_corr]
    jmp  .emit
.cto:
    lea  rdi, [rel str_cls_cto]
    jmp  .emit
.fatal:
    lea  rdi, [rel str_cls_fatal]
.emit:
    call res_out_str
    ret

; RDI=full64 retained total. MAX conservatively means lower bound even when
; the exact MAXth capture was the last one; no extra hidden overflow state.
res_out_count_quality:
    cmp  rdi, -1
    lea  rdi, [rel str_ro_count_exact]
    jne  .emit
    lea  rdi, [rel str_ro_count_lower]
.emit:
    jmp  res_out_str

; --- staged-reply buffer helpers (mirror the thermal/gov/reinit staging pattern) ---
res_out_reset:
    lea  rax, [rel res_out_buf]
    mov  [rel res_out_cur], rax
    mov  byte [rel res_out_buf], 0
    mov  byte [rel res_out_ready], 0
    mov  byte [rel res_out_kind], 0
    mov  byte [rel res_out_error], 0
    mov  byte [rel res_read_arg], 0
    mov  qword [rel res_read_req + 0], 0
    mov  qword [rel res_read_req + 8], 0
    mov  qword [rel res_read_req + 16], 0
    mov  qword [rel res_read_req + 24], 0
    mov  qword [rel res_read_req + 32], 0
    mov  qword [rel res_read_req + 40], 0
    mov  qword [rel res_read_req + 48], 0
    ret

; RDI admitted request. Copy ABI and a bounded argument before
; publishing. Selector is earned only at the successful read handler's end.
res_read_begin:
    call res_out_reset
    lea  rdx, [rel res_read_req]
    mov  ecx, REQ_SZ / 8
.req:
    mov  rax, [rdi + rcx * 8 - 8]
    mov  [rdx + rcx * 8 - 8], rax
    loop .req
    mov  rdi, [rdi + REQ_ARG]
    test rdi, rdi
    jz   .done
    lea  rdx, [rel res_read_arg]
    xor  ecx, ecx
.arg:
    mov  al, [rdi + rcx]
    mov  [rdx + rcx], al
    test al, al
    jz   .done
    inc  ecx
    cmp  ecx, 64
    jb   .arg
    mov  byte [rdx + 63], 0
    mov  byte [rel res_out_error], 1
.done:
    ret

; Shared serializer is bounded for the actual read and legacy diagnostic users.
; Numeric formatting uses the existing 24-byte scratch before bounded append.
res_out_str:
    mov  rsi, [rel res_out_cur]
    lea  rcx, [rel res_out_buf + 1023]
.cp:
    mov  al, [rdi]
    test al, al
    jz   .done
    cmp  rsi, rcx
    jae  .overflow
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .cp
.overflow:
    mov  byte [rel res_out_error], 1
.done:
    mov  byte [rsi], 0
    mov  [rel res_out_cur], rsi
    ret
res_out_dec:
    lea  rsi, [rel res_numbuf]
    call fmt_dec
    lea  rdi, [rel res_numbuf]
    jmp  res_out_str
res_out_hex:
    lea  rsi, [rel res_numbuf]
    xor  edx, edx
    call fmt_hex
    lea  rdi, [rel res_numbuf]
    jmp  res_out_str

; --- svc/resilience data (RW under our page tables, in-image) ------------------

; Lab-only actual AMD event fields are separate from legacy synthetic DMAR tags.
; No unsupported event type is interpreted as an IO_PAGE_FAULT address.
res_out_amdvi_lab_event:
    push rbx
    call amdvi_lab_event_snapshot
    test rax,rax
    jz .absent
    mov rbx,rax
    lea rdi,[rel str_ro_amd_state]
    call res_out_str
    mov rdi,[rbx]
    call res_out_hex
    lea rdi,[rel str_ro_amd_head]
    call res_out_str
    mov rdi,[rbx+24]
    call res_out_hex
    lea rdi,[rel str_ro_amd_tail]
    call res_out_str
    mov rdi,[rbx+32]
    call res_out_hex
    lea rdi,[rel str_ro_amd_status]
    call res_out_str
    mov rdi,[rbx+40]
    call res_out_hex
    cmp qword [rbx],2
    jne .done
    lea rdi,[rel str_ro_amd_type]
    call res_out_str
    mov rdi,[rbx+8]
    shr rdi,60
    call res_out_hex
    lea rdi,[rel str_ro_amd_header]
    call res_out_str
    mov rdi,[rbx+8]
    call res_out_hex
    ; Type2's DeviceID/address are the requested IO_PAGE_FAULT witness.
    mov rax,[rbx+8]
    shr rax,60
    cmp eax,2
    jne .done
    lea rdi,[rel str_ro_amd_devid]
    call res_out_str
    movzx edi,word [rbx+8]
    call res_out_hex
    lea rdi,[rel str_ro_amd_addr]
    call res_out_str
    mov rdi,[rbx+16]
    call res_out_hex
.done:
    mov eax,1
    pop rbx
    ret
.absent:
    xor eax,eax
    pop rbx
    ret
str_ro_amd_state: db "amdvi_state=0x",0
str_ro_amd_head: db " amdvi_head=0x",0
str_ro_amd_tail: db " amdvi_tail=0x",0
str_ro_amd_status: db " amdvi_status=0x",0
str_ro_amd_type: db " amdvi_type=0x",0
str_ro_amd_header: db " amdvi_header=0x",0
str_ro_amd_devid: db " amdvi_devid=0x",0
str_ro_amd_addr: db " amdvi_addr=0x",0

align 8
aer_handler_ptr:    dq 0                ; installed AER catch path (aer_capture)
iommu_handler_ptr:  dq 0                ; installed DMAR catch path (iommu_capture)
aer_rep_bdf:        dq -1               ; a REAL enumerated source BDF (root port preferred)
aer_last_bdf:       dq 0                ; source BDF of the last captured AER record
aer_count:          dq 0               ; saturating saved AER observations (includes selftest)
aer_class_counts:   times 4 dq 0       ; CORR/UNCORR/CTO/FATAL software observations, saturating
iommu_last_bdf:     dq 0                ; faulting BDF of the last DMAR record
iommu_last_addr:    dq 0                ; faulting address of the last DMAR record
iommu_count:        dq 0               ; saturating saved DMAR observations (includes injection)
res_out_cur:        dq 0                ; live staged-reply cursor
aer_rootport_count: dd 0               ; real PCIe root ports found on bus 0
aer_last_class:     dd 0               ; class id of the last captured AER record
cto_us:             dd 50000           ; default, or last readback-verified port bound (us)
aer_m_registered:   db 0               ; aer.handler.registered earned
iommu_m_registered: db 0               ; iommu.fault.registered earned
cto_m_configured:   db 0               ; pcie.cto.configured earned
aer_m_selftest:     db 0               ; aer.contained.selftest earned
aer_isolated:       db 0               ; a fatal error isolated the offending device
iommu_present:      db 0               ; VT-d DMAR unit detected (best-effort; degrade honest)
cto_applied:        db 0               ; at least one real root port read back bounded, enabled CTO
res_out_kind:       db 0               ; 0 unrelated, 1 AERLOG, 2 PCIECTO, 3 IOMMULOG
res_out_error:      db 0               ; bounded read publication error
align 8
res_read_req:       times REQ_SZ db 0
res_read_arg:       times 64 db 0
res_out_ready:      db 0               ; a per-command reply line is staged in res_out_buf
res_numbuf:         times 24 db 0
align 8
aer_last_tag:       times 32 db 0       ; the exact random tag of the last AER record (un-fakeable)
iommu_last_tag:     times 32 db 0
res_out_buf:        times 1024 db 0
align 8
res_aer_ctl_sample: times 64 db 0      ; private BSP control sample
res_aer_hw_diag:    times 32 db 0      ; private BSP diagnostics, no qualification
res_aer_hw_sample:  times 64 db 0      ; private BSP sample, never software totals

; --- boot markers (serial + BOOTLOG content-grade) ---
str_aer_reg:      db "[PAOS64] P3 resilience: PCIe AER handler installed on enumerated root ports [aer.handler.registered]", 13, 10, 0
str_iommu_reg:    db "[PAOS64] P3 resilience: IOMMU/VT-d DMAR fault-recording ring + handler installed [iommu.fault.registered]", 13, 10, 0
str_cto_cfg:      db "[PAOS64] P3 resilience: root-port completion-timeout configured (bounded) [pcie.cto.configured]", 13, 10, 0
str_selftest_ok:  db "[PAOS64] P3 resilience: simulated PCIe error caught + contained (host live) [aer.contained.selftest]", 13, 10, 0
str_selftest_fail: db "[PAOS64] P3 resilience: FAIL selftest capture did not advance", 13, 10, 0
str_selftest_tag: db "SELFTEST-boot", 0

; --- verb names (matched verbatim by command_lookup) ---
str_verb_aerinject:     db "AERINJECT", 0
str_verb_aerdmatest: db "AERDMATEST",0
str_aer_dma_prepare: db "aer_dma_prepare_v1 state=",0
str_aer_dma: db "aer_dma_v2 page=",0
str_aer_ring: db "aer_ring_v1 status=",0
str_aer_ring_scope: db " scope=current-hardware",0
str_aer_ring_unavailable: db " scope=unavailable",0
str_verb_aerlog:        db "AERLOG", 0
str_verb_iommuinject:   db "IOMMUINJECT", 0
str_verb_iommulog:      db "IOMMULOG", 0
str_verb_pciecto:       db "PCIECTO", 0
str_verb_pciectoinject: db "PCIECTOINJECT", 0

; --- staged UDP reply fragments ---
str_ro_aerinj:   db "aer.injected tag=", 0
str_ro_fatal:    db "fatal contained isolate device diag_dumped (no hard hang)", 0
str_ro_aerlast:  db "aer_last class=", 0
str_aer_stop: db "aer_stop_v1 bdf=",0
str_aer_stop_scope: db " scope=config-stop dma=unobserved",0
aer_q_fields:
    dd str_aer_qs-aer_q_fields
    db 64,4,0,0
    dd str_aer_qa-aer_q_fields
    db 0,8,0,0
    dd str_aer_qp-aer_q_fields
    db 8,8,0,0
    dd str_aer_qfirst-aer_q_fields
    db 16,8,0,0
    dd str_aer_qlast-aer_q_fields
    db 24,8,0,0
    dd str_aer_qfail-aer_q_fields
    db 32,8,0,0
    dd str_aer_qus-aer_q_fields
    db 40,4,0,0
    dd str_aer_qcs-aer_q_fields
    db 44,4,0,0
    dd str_aer_qroot-aer_q_fields
    db 52,4,0,0
    dd str_aer_qrs-aer_q_fields
    db 48,4,0,0
    dd str_aer_qtype-aer_q_fields
    db 56,4,0,0
    dd str_aer_qid-aer_q_fields
    db 60,4,0,0
str_aer_qv: db ' qv=1',0
str_aer_qs: db ' qs=',0
str_aer_qa: db ' qa=',0
str_aer_qp: db ' qp=',0
str_aer_qfirst: db ' qfirst=',0
str_aer_qlast: db ' qlast=',0
str_aer_qfail: db ' qfail=',0
str_aer_qus: db ' qus=',0
str_aer_qcs: db ' qcs=',0
str_aer_qroot: db ' qroot=',0
str_aer_qrs: db ' qrs=',0
str_aer_qtype: db ' qtype=',0
str_aer_qid: db ' qid=',0
str_aer_poll: db "aer_poll_v2 bdf=",0
str_aer_boot: db " boot_v1=",0
str_aer_poll_blind: db " blind=",0
str_aer_poll_unknown: db "unknown",0
str_aer_poll_count: db " n=",0
str_aer_poll_time: db " t=",0
str_aer_poll_retained: db " record=retained",0
str_aer_poll_unobserved: db " record=unobserved",0
str_aer_ctl: db "aer_ctl_v1 seg=0 bdf=0x",0
str_aer_ctl_scope: db " scope=sample irq_route=unknown",0
str_aer_ctl_unavailable: db " scope=unavailable irq_route=unknown",0
str_aer_hw: db "aer_hw_v1 seg=0 bdf=0x", 0
str_aer_hw_diag: db " diag_v1=", 0
str_aer_hw_status: db " status=", 0
str_aer_hw_data: db " data=", 0
str_aer_hw_slash: db "/", 0
str_aer_hw_scope: db " scope=sample containment=unknown", 0
str_aer_hw_not_applicable: db ' scope=not-applicable containment=unknown',0
str_aer_hw_unavailable: db " scope=unavailable containment=unknown", 0
str_ro_aercounts: db "aer_counts_v1 source=software total=", 0
str_ro_aercorrected: db " corrected=", 0
str_ro_aernonfatal: db " nonfatal=", 0
str_ro_aertimeout: db " timeout=", 0
str_ro_aerfatal: db " fatal=", 0
str_ro_bdf:      db " bdf=0x", 0
str_ro_tag:      db " tag=", 0
str_ro_count:    db " count=", 0
str_ro_count_exact: db " count_q=exact", 0
str_ro_count_lower: db " count_q=lower_bound", 0
str_ro_iommuinj: db "dmar.injected tag=", 0
str_ro_dmarlast: db "dmar_fault bdf=0x", 0
str_ro_faddr:    db " fault_addr=0x", 0
str_ro_present:  db " vtd_present=", 0
str_ro_cto:      db "cto=on timeout_us=", 0
str_ro_ctorp:    db " rootports=", 0
str_ro_ctoapplied: db " applied=", 0
str_ro_ctoinj:   db "cto.injected tag=", 0
str_cls_corr:    db "correctable", 0
str_cls_uncorr:  db "uncorr-nonfatal", 0
str_cls_cto:     db "completion-timeout", 0
str_cls_fatal:   db "fatal", 0

; Preallocated zero-fill state; no raw image buffer bytes.
%include "core/abi/wdata.inc"
%macro WDATA_svc_resilience_iommu 0
alignb 8
iommu_sec_epoch:    resq 1
iommu_sec_observed: resq 1
iommu_sec_drops:    resq 1
iommu_sec_serial:   resd 1
iommu_sec_pending:  resd 1
iommu_sec_head:     resd 1
iommu_sec_tail:     resd 1
iommu_sec_frozen:   resb 1
alignb 8
iommu_sec_queue:    resb IOMMU_SEC_N * IOMMU_SEC_SZ
iommu_sec_amd_generation: resq IOMMU_SEC_N
%endmacro
WDATA_BSS_DEFER WDATA_svc_resilience_iommu
