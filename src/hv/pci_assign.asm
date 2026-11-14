;; MODULE hv/pci_assign
;; LAYER 5
;; EXPORTS pcia_grp, pcia_grp_admit, pcia_grp_receipt, pcia_grp_reserved, pcia_grp_claims_retire, pcia_grp_attach, pcia_grp_live, pcia_grp_detach, pcia_grp_any_held, pcia_root_scope, pcia_group_snapshot, pcia_group_record_peek, pcia_a1_group_capture, pcia_render_stat, pcia_render_gate, hv_vpci_in, hv_vpci_out, pcia_vpci_in, pcia_vpci_out, pcia_owns_cfg, pcia_shadow_init, pcia_shadow_reset, pcia_state, pcia_bdf, pcia_attach, pcia_release, pcia_try_inject_irq, pcia_guest_owned, pcia_power_observation, pcia_playback_source
;; IMPORTS hv/nd_isolation, bus/acpi, hv/nic_assignment, hv/vmx, hv/vtd, hv/vtd_guest, hv/amdvi, hv/amdvi_guest, hv/amdvi_hda, hv/device_assignment, hv/slat_mmio, hv/hv_ops, hv/vm_profile, bus/pci, bus/pci_bdf, boot/paging, boot/serial, dev/snd/hda_runtime, core/time, bus/pci_claim
;; CAPS
;; OWNER saga:audio
; RCQ-36 V2 (V2_DESIGN.md section 2): the guest's conf1 view of ONE assigned
; host PCI function, independent of the CPU backend and the IOMMU.
;
; The guest sees bus 0 only: 00:00.0 the proven synthetic host bridge, 00:01.0
; the assigned function, nothing else. Every config dword is classified by a
; fixed rule below; nothing the guest writes reaches the device except the
; Command register's MEM and BME bits (INTx-disable forced, I/O never), and
; only while the function is ATTACHED to a live guest domain.
;
;   0x00 vendor/device, 0x08 class/rev, 0x2C subsystem   real (attach snapshot)
;   0x04 command        guest shadow; status = real minus the capability bit
;   0x0C cacheline/lat  guest shadow; header type 0, BIST 0
;   0x10..0x24 BARs     fixed guest GPA per memory BAR (32-bit, non-prefetch)
;                       sizing probe answers the real size; any other value
;                       is counted and ignored: the SLAT never moves
;   0x30 ROM, 0x34 caps, 0x28, 0x38  zero (MSI/MSI-X/PM/PCIe hidden)
;   0x3C                line = PCIA_GUEST_IRQ, pin INTA, writes ignored
;   0x40..0xFF          guest shadow (seeded from the snapshot), never forwarded
;
; Write bounds are SEC-D1's (hv/vtd vtd_vpci_out): no string OUTS, size codes
; 1/2/4 bytes only, no dword-crossing access, BAR writes dword-only.
; The rules are data so a later whole-GPU assignment (RCQ-50) extends the
; tables (64-bit BAR pairs, shadow MSI capability) instead of the branches.
;
; Calls: hv/vmx PIO exit at a stopped vCPU, EDX=port, R8D=exit qualification
; (bits 2:0 size-1, bit 4 string), guest RAX in hv_linux_gpr. IN returns ECX.
; Clobbers RAX, RCX, RDX, RSI, RDI, R9 like vtd_vpci_*.

PCIA_IDLE       equ 0
PCIA_ARMED      equ 1
PCIA_ATTACHED   equ 2
PCIA_RELEASING  equ 3
PCIA_POISON     equ 4
PCIA_GUEST_IRQ  equ 6                    ; master PIC line (VTD_NET_GUEST_IRQ precedent)
PCIA_BARS       equ 6
PCIA_CMD_GUEST  equ 0x0547               ; IO|MEM|BME|PARITY|SERR|INTxDIS: what the guest may set
PCIA_CMD_FWD    equ 0x0006               ; MEM|BME reach the device
PCIA_CMD_INTXD  equ 0x0400
PCIA_CMD_MEM    equ 0x0002

; RCQ-36 V2 c2: one host HDA function assigned to the audio-hda guest.
; The guest BAR sits at a fixed GPA in PDPT[3] (PD index 129): clear of the
; virtio-mmio pages (0xD0000000..0xD0005FFF), the framebuffer (0xC0000000 +
; 2 MiB) and guest RAM (below 0xC0000000).
PCIA_BAR_GPA    equ 0xD0200000
PCIA_BAR_MAX    equ 0x100000                 ; an HDA register BAR is 16 KiB; inside one host 2 MiB page
PCIA_POOL_PAGES equ 2                        ; SLAT tables for the BAR (one PT; spare)
PCIA_QUIESCE_POLLS equ 100000                ; bounded UC readbacks while CRST settles
PCIA_PCM_BYTES  equ 96000                    ; hda_probe_generate: 0.5 s 48 kHz stereo S16LE
PCIA_TAIL_BYTES equ 16384                    ; then 4096 silent frames (85 ms): the STOP after DRAIN drops
                                             ; what the device read past its position (QEMU c2run3: 41 ms)
; pcia_err: the first refusal of the last attach (0 = attached)
PCIA_E_STATE    equ 1                        ; not idle, or this boot already assigned it
PCIA_E_NATIVE   equ 2                        ; a native HDA owner holds the controller
PCIA_E_NONE     equ 3                        ; no Intel/AMD class-0403 function
PCIA_E_MANY     equ 4                        ; more than one: never guess which
PCIA_E_IDENTITY equ 5                        ; vendor/class/type/BAR/ATS (amdvi_hda_identity)
PCIA_E_MAP      equ 6                        ; BAR not in a live UC host 2 MiB leaf
PCIA_E_BAR      equ 7                        ; sizing: not a power of two 4 KiB..PCIA_BAR_MAX in that leaf
PCIA_E_QUIESCE  equ 8                        ; decode/reset/engines did not read back stopped
PCIA_E_SHADOW   equ 9                        ; pcia_shadow_init refused the shape
PCIA_E_IOMMU    equ 10                       ; no guest IOMMU domain for it (amdvi_guest / vtd_guest)
PCIA_E_RECEIPT  equ 11                       ; the domain receipt is not live
PCIA_E_SLAT     equ 12                       ; hv_slat_map_mmio refused the BAR
PCIA_E_PCM      equ 13                       ; kmalloc refused the owned PCM (before any device access)
PCIA_E_GROUP    equ 14                       ; its isolation group is not this function alone (pcia_group_gate)

; RCQ-50 G0 (lab only, default OFF: no byte in either floor). The flr-lab profile sets
; VP_DEV_PCIFLR beside VP_DEV_PCIHDA: the same assigned-function seam, but the function is
; the one exact pinned PCIe endpoint (QEMU igb 8086:10c9) that no native driver claimed
; (bus/pci_claim: e1000e binds the first Intel class-0200 function, so order matters),
; reset by Function Level Reset at attach and at release. A release whose FLR, restore
; and readback are all proven returns the function to IDLE and unclaimed, so the next
; START may assign it again; the HDA kind stays sticky for the boot. No PCM, no INTx.
%ifidn RCQ50_G0_FLR_LAB,1
PCIA_KIND_HDA   equ 0
PCIA_KIND_FLR   equ 1
PCIA_DEV_PCIFLR equ 2048                     ; == VP_DEV_PCIFLR (hv/vm_profile)
PCIA_FLR_VENDEV equ 0x10C98086               ; device:vendor dword, exact
PCIA_CAP_PCIE   equ 0x10
PCIA_FLR_TP_POLLS equ 100                    ; 1 ms each: Transactions Pending must clear
PCIA_FLR_ID_POLLS equ 1000                   ; 1 ms each after the 100 ms: the function answers again
PCIA_E_RESET    equ 15                       ; no FLR capability, or the reset/restore did not read back
%endif

; hv/vmx PIO seam. EAX/flags are the only state the decision itself uses.
hv_vpci_out:
%ifdef PAOS_NIC_ASSIGNMENT
    cmp byte [rel nic_assignment_state], 0
    jne nic_assignment_vpci_out
%endif
    call pcia_owns_cfg
    test eax, eax
    jnz  pcia_vpci_out
    jmp  vtd_vpci_out

hv_vpci_in:
%ifdef PAOS_NIC_ASSIGNMENT
    cmp byte [rel nic_assignment_state], 0
    jne nic_assignment_vpci_in
%endif
    call pcia_owns_cfg
    test eax, eax
    jnz  pcia_vpci_in
    jmp  vtd_vpci_in

; EAX=1 only while a live guest owns the shadow; the VT-d path keeps its own.
pcia_owns_cfg:
    xor  eax, eax
    cmp  byte [rel pcia_state], PCIA_ATTACHED
    sete al
    ret

; RDI=256-byte real config snapshot, RSI=dd[6] BAR sizes (0 = absent or the
; upper half of a 64-bit pair), RDX=dd[6] guest GPAs, ECX=host BDF.
; EAX=0 loaded (pcia_state untouched: the attach owner publishes ATTACHED), -1 on
; any shape this module cannot present exactly; the shadow is then zero.
pcia_shadow_init:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  ebx, ecx
    call pcia_shadow_reset
    mov  al, [r12 + 0x0E]
    and  al, 0x7F
    jnz  .bad                            ; type-0 functions only
    xor  ecx, ecx
.bar:
    cmp  ecx, PCIA_BARS
    jae  .bars_ok
    mov  eax, [r13 + rcx*4]
    test eax, eax
    jz   .bar_next
    cmp  eax, 16
    jb   .bad
    lea  edx, [rax - 1]
    test eax, edx
    jnz  .bad                            ; power of two
    mov  edx, [r12 + 0x10 + rcx*4]
    test edx, 1
    jnz  .bad                            ; I/O BARs are never presented
    mov  edx, [r14 + rcx*4]
    test edx, edx
    jz   .bad
    lea  r9d, [rax - 1]
    test edx, r9d
    jnz  .bad                            ; GPA naturally aligned
    add  edx, eax
    jc   .bad                            ; below 4 GiB, no wrap
.bar_next:
    inc  ecx
    jmp  .bar
.bars_ok:
    lea  rdi, [rel pcia_cfg_snap]
    mov  rsi, r12
    mov  ecx, 256
    cld
    rep  movsb
    lea  rdi, [rel pcia_cfg_shadow + 0x40]
    lea  rsi, [r12 + 0x40]
    mov  ecx, 0xC0
    rep  movsb
    mov  ax, [r12 + 0x0C]
    mov  [rel pcia_cfg_shadow + 0x0C], ax
    lea  rdi, [rel pcia_bar_size]
    mov  rsi, r13
    mov  ecx, PCIA_BARS * 4
    rep  movsb
    lea  rdi, [rel pcia_bar_gpa]
    mov  rsi, r14
    mov  ecx, PCIA_BARS * 4
    rep  movsb
    mov  [rel pcia_bdf], ebx
    xor  eax, eax
    jmp  .out
.bad:
    call pcia_shadow_reset
    mov  eax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

pcia_shadow_reset:
    push rdi
    push rcx
    push rax
    lea  rdi, [rel pcia_shadow]
    mov  ecx, pcia_shadow_end - pcia_shadow
    xor  eax, eax
    cld
    rep  stosb
    pop  rax
    pop  rcx
    pop  rdi
    ret

; EAX=config byte offset for guest 00:01.0 from CONFIG_ADDRESS and the data
; port (EDX), 1 for the host bridge 00:00.0 (EAX bit 8 set), or -1.
pcia_target:
    mov  eax, [rel pcia_addr]
    test eax, 0x80000000
    jz   .bad
    test eax, 0x7F000000                 ; reserved / AMD extended-register bits: never alias 0-0xFF
    jnz  .bad
    test eax, 0x00FF0700                 ; bus 0, function 0 only
    jnz  .bad
    mov  ecx, eax
    shr  ecx, 11
    and  ecx, 0x1F
    cmp  ecx, 1
    ja   .bad
    and  eax, 0xFC
    lea  eax, [rax + rdx - 0xCFC]
    test ecx, ecx
    jnz  .out
    or   eax, 0x100                      ; host bridge
.out:
    ret
.bad:
    mov  eax, -1
    ret

; ESI=dword-aligned offset (< 0x100) -> EAX=guest-visible dword.
pcia_cfg_dword:
    cmp  esi, 0x04
    je   .cmd
    cmp  esi, 0x0C
    je   .hdr
    cmp  esi, 0x10
    jb   .real
    cmp  esi, 0x24
    jbe  .bar
    cmp  esi, 0x2C
    je   .real
    cmp  esi, 0x3C
    je   .irq
    cmp  esi, 0x40
    jb   .zero
    lea  rdi, [rel pcia_cfg_shadow]
    mov  eax, [rdi + rsi]
    ret
.real:
    lea  rdi, [rel pcia_cfg_snap]
    mov  eax, [rdi + rsi]
    ret
.cmd:
    mov  eax, [rel pcia_cfg_snap + 4]
    and  eax, 0xFFEF0000                 ; real status, capability list hidden
    movzx edi, word [rel pcia_cfg_shadow + 4]
    or   eax, edi
    ret
.hdr:
    movzx eax, word [rel pcia_cfg_shadow + 0x0C]
    ret
.irq:
    mov  eax, (1 << 8) | PCIA_GUEST_IRQ
    ret
.bar:
    mov  edi, esi
    sub  edi, 0x10
    shr  edi, 2
    lea  rax, [rel pcia_bar_probe]
    cmp  byte [rax + rdi], 1
    jne  .bar_value
    mov  byte [rax + rdi], 0
    lea  rax, [rel pcia_bar_size]
    mov  eax, [rax + rdi*4]
    test eax, eax
    jz   .zero
    dec  eax
    not  eax
    and  eax, 0xFFFFFFF0
    ret
.bar_value:
    lea  rax, [rel pcia_bar_size]
    cmp  dword [rax + rdi*4], 0
    je   .zero
    lea  rax, [rel pcia_bar_gpa]
    mov  eax, [rax + rdi*4]
    ret
.zero:
    xor  eax, eax
    ret

pcia_vpci_in:
    cmp  edx, 0xCF8
    jne  .data
    mov  ecx, [rel pcia_addr]
    ret
.data:
    cmp  edx, 0xCFC
    jb   .ones
    cmp  edx, 0xCFF
    ja   .ones
    call pcia_target
    test eax, eax
    js   .ones
    mov  ecx, eax
    and  ecx, 3
    shl  ecx, 3                          ; byte lane shift
    mov  esi, eax
    and  esi, 0xFC
    test eax, 0x100
    jnz  .bridge
    push rcx
    call pcia_cfg_dword
    pop  rcx
    shr  eax, cl
    mov  ecx, eax
    ret
.bridge:
    xor  eax, eax
    test esi, esi
    jnz  .bridge_class
    mov  eax, 0x71908086                 ; hv/vtd's proven synthetic host bridge
    jmp  .bridge_out
.bridge_class:
    cmp  esi, 0x08
    jne  .bridge_out
    mov  eax, 0x06000000
.bridge_out:
    shr  eax, cl
    mov  ecx, eax
    ret
.ones:
    mov  ecx, 0xFFFFFFFF
    ret

pcia_vpci_out:
    cmp  edx, 0xCF8
    jne  .data
    mov  eax, [rel hv_linux_gpr]
    mov  [rel pcia_addr], eax
    ret
.data:
    cmp  edx, 0xCFC
    jb   .done
    cmp  edx, 0xCFF
    ja   .done
    test r8d, 0x10
    jnz  .refused                        ; string OUTS: data is guest memory
    mov  r9d, r8d
    and  r9d, 7                          ; size - 1
    cmp  r9d, 2
    je   .refused
    cmp  r9d, 3
    ja   .refused
    call pcia_target
    test eax, eax
    js   .done
    test eax, 0x100
    jnz  .done                           ; host bridge: read-only
    mov  ecx, eax
    and  ecx, 3
    add  ecx, r9d
    cmp  ecx, 3
    ja   .refused                        ; crosses its dword
    mov  esi, eax                        ; byte offset
    mov  ecx, [rel hv_linux_gpr]         ; value, low bytes significant
    cmp  esi, 0x40
    jae  .shadow
    cmp  esi, 0x10
    jb   .low
    cmp  esi, 0x27
    jbe  .bar
    jmp  .ignored                        ; 0x28..0x3F: fixed
.low:
    cmp  esi, 0x04
    jb   .ignored
    cmp  esi, 0x06
    jb   .cmd
    cmp  esi, 0x0C
    jb   .ignored                        ; status (RW1C) and class: fixed
    cmp  esi, 0x0E
    jb   .shadow                         ; cacheline / latency timer
    jmp  .ignored
.cmd:
    ; Merge exactly the bytes written into the 16-bit command shadow.
    movzx eax, word [rel pcia_cfg_shadow + 4]
    cmp  esi, 0x05
    je   .cmd_hi
    cmp  r9d, 0
    je   .cmd_lo
    mov  ax, cx                          ; word or dword at 0x04
    jmp  .cmd_store
.cmd_lo:
    mov  al, cl
    jmp  .cmd_store
.cmd_hi:
    mov  ah, cl
.cmd_store:
    and  eax, PCIA_CMD_GUEST
    mov  [rel pcia_cfg_shadow + 4], ax
    inc  dword [rel pcia_cmd_writes]
    cmp  byte [rel pcia_state], PCIA_ATTACHED
    jne  .done
    and  eax, PCIA_CMD_FWD
    or   eax, PCIA_CMD_INTXD             ; physical INTx stays off: PaOS polls
    mov  edx, eax                        ; status half 0: its RW1C bits are untouched
    mov  edi, [rel pcia_bdf]
    mov  esi, 4
    mov  [rel pcia_cmd_forwarded], dx
    jmp  pci_bdf_write
.bar:
    test esi, 3
    jnz  .refused
    cmp  r9d, 3
    jne  .refused                        ; BAR programming is dword-only
    mov  edi, esi
    sub  edi, 0x10
    shr  edi, 2
    cmp  ecx, 0xFFFFFFFF
    jne  .bar_value
    lea  rax, [rel pcia_bar_probe]
    mov  byte [rax + rdi], 1
    ret
.bar_value:
    inc  dword [rel pcia_bar_writes]
    lea  rax, [rel pcia_bar_size]
    cmp  dword [rax + rdi*4], 0
    je   .bar_unused
    lea  rax, [rel pcia_bar_gpa]
    mov  edx, ecx
    and  edx, 0xFFFFFFF0
    cmp  edx, [rax + rdi*4]
    je   .done                           ; restoring the presented address
    jmp  .bar_foreign
.bar_unused:
    test ecx, ecx
    jz   .done
.bar_foreign:
    inc  dword [rel pcia_bar_foreign]    ; never moves the SLAT
    mov  [rel pcia_bar_last], ecx
    ret
.shadow:
    lea  rdi, [rel pcia_cfg_shadow]
    add  rdi, rsi
    cmp  r9d, 0
    je   .sh_byte
    cmp  r9d, 1
    je   .sh_word
    mov  [rdi], ecx
    ret
.sh_byte:
    mov  [rdi], cl
    ret
.sh_word:
    mov  [rdi], cx
    ret
.ignored:
    inc  dword [rel pcia_fixed_writes]
    ret
.refused:
    inc  dword [rel pcia_refused_writes]
.done:
    ret

; ---------------------------------------------------------------------------
; RCQ-36 V2 c2: attach / release of the one host HDA function.
;
; The selected profile (VP_DEV_PCIHDA) is the operator's intent; the function
; is not named by the operator: it is the only Intel/AMD class-0403 function
; on the host, and two or more refuse. Order (hv_linux_prepare, vCPU never
; run, guest RAM loaded and its SLAT built):
;   1. idle and never assigned this boot;
;   2. scan, 256-byte config snapshot, BAR0 memory, amdvi_hda_identity, BAR in
;      a live UC host 2 MiB leaf, then hda_probe_guest_claim: refused while a
;      native owner (hda_runtime probe, hda_loopback_native) holds it, and from
;      here every native owner refuses it for the rest of the boot;
;   3. Command decode off + INTx disable (read back), BAR0 sized and restored;
;   4. MEM only: INTCTL 0, every stream RUN 0, CORB/RIRB/DPL off, CRST 0 until
;      amdvi_hda_quiesced; decode off again;
;   5. shadow (pcia_shadow_init), guest IOMMU domain over exactly guest RAM
;      (pcia_iommu_attach at this START generation) and its live receipt;
;   6. BAR -> PCIA_BAR_GPA UC through hv_slat_map_mmio from the caller's pool.
; A refusal before 5 leaves the function decoded off, in reset, unassigned.
; A refusal at or after the IOMMU call releases (step R) and may poison.
;
; Release (vCPU actually stopped; hv_guest_linux_start and prepare .fail):
;   R. RELEASING (no forwarding, no INTx), MEM only so BME drops at once,
;      quiesce as 4, decode off with readback, pcia_iommu_detach. IDLE only
;      if every step read back; otherwise POISON (sticky; the domain stays
;      blocked). The function never returns to a native owner this boot: the
;      guest-domain detach (AMD-Vi DTE, VT-d context) leaves it blocked, never
;      the compatibility domain.
; Every entry is serialized by the VM owner at stopped-vCPU boundaries.
; ---------------------------------------------------------------------------

; pci_scan_with_filter callback: EDI bus, ESI dev, EDX fn, ECX vendev.
pcia_scan_cb:
    cmp  cx, 0x8086
    je   .vendor
    cmp  cx, 0x1022
    jne  .out
.vendor:
    push r12
    mov  r12d, edi
    shl  r12d, 8
    shl  esi, 3
    or   r12d, esi
    or   r12d, edx                       ; packed BDF
    mov  edi, r12d
    mov  esi, 8
    call pci_bdf_read
    shr  eax, 8
    and  eax, 0xFFFF7F                   ; HDA prog-IF 00 or 80 (hdar_pci_cb's class rule)
    cmp  eax, 0x040300
    jne  .pop
    inc  dword [rel pcia_candidates]
    mov  [rel pcia_sel_bdf], r12d
.pop:
    pop  r12
.out:
    ret

; RDI = HDA register VA (identity, UC). EAX = 1 once the controller reads back
; stopped and in reset (amdvi_hda_quiesced), 0 if it does not within the bound.
pcia_hda_quiesce:
    push rbx
    mov  rbx, rdi
    mov  dword [rbx + 0x20], 0           ; INTCTL: no interrupt source
    movzx eax, word [rbx]                ; GCAP: ISS + OSS + BSS descriptors
    mov  ecx, eax
    shr  ecx, 8
    and  ecx, 15
    mov  edx, eax
    shr  edx, 12
    and  edx, 15
    add  ecx, edx
    shr  eax, 3
    and  eax, 31
    add  ecx, eax
    cmp  ecx, 30
    ja   .no
    lea  rdx, [rbx + 0x80]
.sd:
    test ecx, ecx
    jz   .engines
    mov  al, [rdx]
    and  al, 0xFD                        ; SDnCTL.RUN = 0
    mov  [rdx], al
    add  rdx, 0x20
    dec  ecx
    jmp  .sd
.engines:
    mov  byte [rbx + 0x4C], 0            ; CORBCTL.CORBRUN
    mov  byte [rbx + 0x5C], 0            ; RIRBCTL.RIRBDMAEN / RINTCTL
    mov  dword [rbx + 0x70], 0           ; DPLBASE: no position-buffer DMA
    mov  dword [rbx + 0x74], 0
    mov  eax, [rbx + 8]
    and  eax, ~1
    mov  [rbx + 8], eax                  ; GCTL.CRST = 0: held in reset
    mov  r8d, PCIA_QUIESCE_POLLS
.wait:
    mov  rdi, rbx
    call amdvi_hda_quiesced
    test eax, eax
    jnz  .out
    pause
    dec  r8d
    jnz  .wait
.no:
    xor  eax, eax
.out:
    pop  rbx
    ret

; EDI = BDF, EDX = Command value (Status half 0: its RW1C bits stay) -> EAX =
; Command readback & (IO|MEM|BME).
pcia_command:
    push rbx
    mov  ebx, edi
    mov  esi, 4
    call pci_bdf_write
    mov  edi, ebx
    mov  esi, 4
    call pci_bdf_read
    and  eax, 7
    pop  rbx
    ret

; The guest IOMMU domain behind one seam with one ABI: AMD-Vi's amdvi_guest_*
; when AMD-Vi owns the IOMMU, else the VT-d twin vtd_guest_* (DID17) when
; VT-d is enabled; each re-checks its own full enforcement. Receipt qword 0 is
; the state in both (0 unused, 1 live, 2 retired, 3 poison).
; EDI BDF, RSI bytes, RDX host base, RCX START generation -> EAX 0 / -1.
pcia_iommu_attach:
    cmp  byte [rel amdvi_owned], 1
    je   amdvi_guest_attach
    cmp  byte [rel vtd_enabled], 1
    je   vtd_guest_attach
    mov  eax, -1
    ret

; EDI BDF, RSI generation -> EAX 0 retired / nonzero.
pcia_iommu_detach:
    cmp  byte [rel amdvi_owned], 1
    je   amdvi_guest_detach
    cmp  byte [rel vtd_enabled], 1
    je   vtd_guest_detach
    mov  eax, -1
    ret

; RDI = 64-byte receipt -> EAX 1 live.
pcia_iommu_receipt:
    cmp  byte [rel amdvi_owned], 1
    je   amdvi_guest_receipt
    cmp  byte [rel vtd_enabled], 1
    je   vtd_guest_receipt
.none:
    push rdi
    mov  ecx, 8
    xor  eax, eax
    cld
    rep  stosq
    pop  rdi
    ret

; pcia_iso_cb: pci_scan_with_filter callback (EDI bus, ESI dev, EDX fn) that appends
; one hv/device_assignment snapshot entry per present function (DA_SNAP_SZ: +0 word
; BDF, +2 DA_S_* flags, +3 secondary bus, +4 subordinate bus). Config mechanism #1
; reads the header and PCIe capability. U3a: only while the AMD-Vi owner is active and
; only for a type-1 PCIe Root Port (port type 4), the existing admitted ECAM transport
; reads the ACS extended capability (pci_ecam_acs_snapshot), fresh at every gate. DA_S_ACS
; is set iff that read succeeds AND ACS Capability and ACS Control both hold SV|RR|CR|UF
; AND ACS Control has Direct Translated P2P (DT, bit 6) clear. This is stricter than Linux,
; whose pci_acs_flags_enabled treats a bit absent from Capability as enabled: such a port
; stays unproven here. Port type is device-reported, and devassign_build_facts stops
; widening at the FIRST chain port with DA_S_ACS (device_assignment.asm .grp_done), so
; pcia_group_gate then keeps the flag only on a port no snapshot bridge window covers: the
; top of the chain. Switch/PCI bridges never get the flag; absent, partial, unread,
; changed or unadmitted ACS leaves every port widening its group (fail-closed, as
; vtd_iso_snapshot). ACS Control is never written. More than DA_SNAP_MAX functions marks
; the facts incomplete.
PCIA_ACS_REQUIRED equ 0x1D             ; SV(0) | RR(2) | CR(3) | UF(4)
PCIA_ACS_DT       equ 0x40             ; ACS Control: Direct Translated P2P enable
pcia_iso_cb:
    push rbx
    push r12
    sub  rsp, 72                         ; private ACS sample64, aligned calls
    mov  ebx, edi
    shl  ebx, 8
    shl  esi, 3
    or   ebx, esi
    or   ebx, edx                        ; packed BDF
    mov  eax, [rel pcia_iso_n]
    cmp  eax, DA_SNAP_MAX
    jb   .room
    mov  byte [rel pcia_iso_incomplete], 1
    jmp  .out
.room:
    lea  r12, [rel pcia_iso_snap]
    lea  r12, [r12 + rax*DA_SNAP_SZ]
    mov  qword [r12], 0
    mov  [r12], bx
    inc  dword [rel pcia_iso_n]
    mov  edi, ebx
    mov  esi, 0x0C
    call pci_bdf_read
    shr  eax, 16
    and  eax, 0x7F                       ; header type
    cmp  eax, 1
    jne  .caps
    or   byte [r12 + 2], DA_S_BRIDGE
    mov  edi, ebx
    mov  esi, 0x18
    call pci_bdf_read
    shr  eax, 8
    mov  [r12 + 3], al                   ; secondary bus
    shr  eax, 8
    mov  [r12 + 4], al                   ; subordinate bus
.caps:
    mov  edi, ebx
    mov  esi, 0x10                       ; PCI Express capability
    call pci_find_cap
    test eax, eax
    jz   .out
    or   byte [r12 + 2], DA_S_PCIE
    mov  esi, eax
    mov  edi, ebx
    call pci_bdf_read
    shr  eax, 20
    and  eax, 0xF                        ; device/port type
    cmp  eax, 4                          ; PCIe Root Port
    je   .root_port
    cmp  eax, 7                          ; PCIe to PCI/PCI-X bridge
    je   .pci_bridge
    cmp  eax, 8                          ; PCI/PCI-X to PCIe bridge
    jne  .out
.pci_bridge:
    or   byte [r12 + 2], DA_S_PCI_BRIDGE
    jmp  .out
.root_port:
    cmp  byte [rel amdvi_owned], 1       ; no owner / VT-d: no ECAM read, no proof
    jne  .out
    test byte [r12 + 2], DA_S_BRIDGE
    jz   .out
    mov  edi, ebx
    mov  rsi, rsp
    call pci_ecam_acs_snapshot
    test eax, eax
    jnz  .out                            ; absent/unread/changed/unadmitted: no proof
    mov  eax, [rsp + 8]                  ; ACS Capability low16, Control high16
    mov  edx, eax
    and  eax, PCIA_ACS_REQUIRED
    cmp  eax, PCIA_ACS_REQUIRED
    jne  .out
    shr  edx, 16
    and  edx, PCIA_ACS_REQUIRED | PCIA_ACS_DT
    cmp  edx, PCIA_ACS_REQUIRED          ; all four on, DT off
    jne  .out
    or   byte [r12 + 2], DA_S_ACS
.out:
    add  rsp, 72
    pop  r12
    pop  rbx
    ret

; pcia_group_gate(EDI = packed BDF) -> EAX = ISO_ELIGIBLE (0) when hv/device_assignment
; classifies the function alone in its fail-closed isolation group (no sibling function
; on a root bus, nothing else in a bridge window that lacks proven ACS, no aliasing
; bridge on its path) and no firmware DMA reservation names it, else that ISO_*
; refusal; pcia_iso_reason keeps it. Read-only.
;   VT-d: the unit's ownership-time snapshot (vtd_iso_snapshot, as vtd_iso_check), which
;         carries the boot DMAR's RMRR scopes (ISO_RMRR) and PaOS's lifeline functions.
;   AMD-Vi: the conf1 walk (pcia_iso_cb) plus, for type-1 PCIe Root Ports only, a fresh
;         ECAM ACS read (U3a); then DA_S_ACS is kept only at the top of the chain (no
;         snapshot bridge window covers the port's bus). Afterwards no IVHD alias and no
;         IVMD unity range may name the requester (amdvi_hda_scope), else ISO_RMRR.
;   Neither owner: the conf1 walk with no IOMMU fact (ISO_NO_IOMMU).
pcia_group_gate:
    push rbx
    push r12
    sub  rsp, 8
    mov  ebx, edi
    xor  r8d, r8d
    cmp  byte [rel amdvi_owned], 1
    je   .amd
    cmp  byte [rel vtd_enabled], 1
    jne  .walk                           ; no guest IOMMU owner: ISO_NO_IOMMU
    call vtd_iso_snapshot                ; the host facts exactly as vtd_iso_check takes them
    xor  r8d, r8d
    cmp  qword [rel vtd_unitb_base], 0
    je   .vtd_unit
    or   r8d, DA_H_IOMMU
.vtd_unit:
    cmp  byte [rel vtd_ready], 1
    jne  .vtd_backend
    or   r8d, DA_H_BACKEND
.vtd_backend:
    cmp  byte [rel vtd_iso_incomplete], 0
    je   .vtd_facts
    or   r8d, DA_H_INCOMPLETE
.vtd_facts:
    lea  rsi, [rel vtd_iso_snap]
    mov  edx, [rel vtd_iso_snap_n]
    jmp  .facts
.amd:
    mov  r8d, DA_H_IOMMU | DA_H_BACKEND
.walk:
    mov  r12d, r8d
    mov  dword [rel pcia_iso_n], 0
    mov  byte [rel pcia_iso_incomplete], 0
    lea  rdi, [rel pcia_iso_cb]
    call pci_scan_with_filter
    cmp  byte [rel amdvi_owned], 1
    jne  .acs_checked
    call .acs_top_only
.acs_checked:
    mov  r8d, r12d
    test r8d, r8d
    jz   .walk_facts                     ; no owner: incompleteness changes nothing
    cmp  byte [rel pcia_iso_incomplete], 0
    je   .walk_facts
    or   r8d, DA_H_INCOMPLETE
.walk_facts:
    lea  rsi, [rel pcia_iso_snap]
    mov  edx, [rel pcia_iso_n]
.facts:
    lea  rdi, [rel pcia_iso_record]
    mov  ecx, ebx
    call devassign_build_facts
    test eax, eax
    jnz  .out
    lea  rdi, [rel pcia_iso_record]
    call devassign_classify
    cmp  eax, ISO_PROTECTED
    je   .protected_facts
    test eax, eax
    jnz  .out
    cmp  byte [rel amdvi_owned], 1
    jne  .out
    mov  edi, ebx
    call amdvi_hda_scope
    cmp  eax, 1
    mov  eax, ISO_ELIGIBLE
    je   .out
    mov  eax, ISO_RMRR                   ; an IVMD unity range or an IVHD alias names it
.out:
    xor  ecx, ecx
    xor  edx, edx
    jmp  .return
.protected_facts:
    ; Secondary read-only result belongs to THIS completed calculation only.
    ; Primary ISO7 and ordinary output-buffer refusal remain unchanged.
    lea  rcx, [rel pcia_iso_record]
    mov  edx, DA_REC_BYTES
.return:
    mov  [rel pcia_iso_reason], al
    add  rsp, 8
    pop  r12
    pop  rbx
    ret
; U3a (SEC 106248 S1): the builder stops at the first DA_S_ACS chain port, which is only
; Linux-equivalent at the top of the chain. A device below any bridge can claim port type
; 4, so clear DA_S_ACS on every entry whose own bus lies inside some snapshot bridge's
; [secondary, subordinate] window (stricter than a secondary-bus match). Clobbers RAX,
; RCX, RDX, RSI, RDI, R8, R9.
.acs_top_only:
    mov  ecx, [rel pcia_iso_n]
    lea  rsi, [rel pcia_iso_snap]
    xor  r8d, r8d
.acs_i:
    cmp  r8d, ecx
    jae  .acs_ret
    lea  rdi, [rsi + r8*DA_SNAP_SZ]
    test byte [rdi + 2], DA_S_ACS
    jz   .acs_next_i
    movzx eax, byte [rdi + 1]            ; the port's own bus
    xor  r9d, r9d
.acs_j:
    cmp  r9d, ecx
    jae  .acs_next_i
    lea  rdx, [rsi + r9*DA_SNAP_SZ]
    test byte [rdx + 2], DA_S_BRIDGE
    jz   .acs_next_j
    cmp  al, [rdx + 3]                   ; below secondary: not inside
    jb   .acs_next_j
    cmp  al, [rdx + 4]                   ; above subordinate: not inside
    ja   .acs_next_j
    and  byte [rdi + 2], ~DA_S_ACS & 0xFF
    jmp  .acs_next_i
.acs_next_j:
    inc  r9d
    jmp  .acs_j
.acs_next_i:
    inc  r8d
    jmp  .acs_i
.acs_ret:
    ret

; Read-only copy of the existing common group verdict and its complete facts.
; EDI=segment0 BDF, RSI=out DA_REC_BYTES, RDX=capacity -> ISO_*.
; Refusal never copies working facts into RSI. ISO7 alone returns secondary
; RCX=current completed DA_REC pointer, EDX=272; other results clear the pair.
; Pointer is BSP-local scratch, valid only until the next group calculation.
; No caller can shrink the group.
pcia_group_snapshot:
    push r12
    cmp edi,0xFFFF
    ja .bad
    test rsi,rsi
    jz .bad
    cmp rdx,DA_REC_BYTES
    jb .bad
    mov r12,rsi
    call pcia_group_gate
    test eax,eax
    jnz .out
    movzx r8d,byte [rel pcia_iso_record+3]
    cmp r8d,DA_REC_MAX
    ja .bad
    mov rdi,r12
    mov ecx,DA_REC_BYTES/8
    xor eax,eax
    cld
    rep stosq
    mov rdi,r12
    lea rsi,[rel pcia_iso_record]
    lea ecx,[r8d+2]                  ; header + exactly the current records
    cld
    rep movsq
    xor eax,eax
    xor ecx,ecx
    xor edx,edx
    jmp .out
.bad:
    xor ecx,ecx
    xor edx,edx
    mov eax,ISO_TRUNC_ACPI
.out:
    pop r12
    ret

; NDISO1 (ROOT110035): pcia_group_record_peek(EDI=segment0 BDF) -> RAX = the
; completed fact record of the LAST group calculation when that calculation
; was a group verdict (pcia_iso_reason ISO7/ISO8: a builder refusal 3/4/6 leaves
; the previous header over partly rewritten entries, VM110051) built for
; exactly this target (record 0 = EDI, segment 0, target_idx 0, 1 <= n_dev <=
; DA_REC_MAX), else 0. Read-only and BSP-local: valid only until the next group
; gate. Evidence for the isolation-refusal message only, never an admission
; input; the ISO7-only RCX contract of pcia_group_snapshot is unchanged.
; Clobbers RAX, RCX.
pcia_group_record_peek:
    xor eax,eax
    cmp edi,0xFFFF
    ja .out
    movzx ecx,byte [rel pcia_iso_reason]
    cmp ecx,ISO_PROTECTED
    jb .out
    cmp ecx,ISO_SHARED_DMA
    ja .out
    movzx ecx,byte [rel pcia_iso_record+3]
    test ecx,ecx
    jz .out
    cmp ecx,DA_REC_MAX
    ja .out
    cmp byte [rel pcia_iso_record+4],0
    jne .out
    cmp word [rel pcia_iso_record+16],0
    jne .out
    movzx ecx,byte [rel pcia_iso_record+16+2]
    shl ecx,8
    mov cl,[rel pcia_iso_record+16+3]
    cmp ecx,edi
    jne .out
    lea rax,[rel pcia_iso_record]
.out:
    ret

; Fresh raw common facts for the eventual A1 caller, NOT admission authority.
; RDI=exact uint64 segment0 BDF, RSI=private resident native out272,
; RDX=exact uint64 bytes272 -> EAX=0 CAPTURED / ISO_* / A1C_E_ARGUMENT.
; Success EDX=original singleton ISO0/7/8, ECX=0. Refusal clears both and
; leaves output untouched. The original ISO7/8 refusal is never erased.
; Caller serializes on BSP and owns resident output, original signed START,
; selected config/claims and remaining policy/topology/reset/mapping/return
; joins. Copies of facts are observations, not original START custody.
; Each call runs the real common gate anew; retained diagnostic facts are
; never consulted. AMD requester alias/IVMD scope is mandatory even where
; singleton ISO7/8 returned before that check. No second scanner or device
; write, policy selection, claim, reset or attach is introduced here.
A1C_E_ARGUMENT equ 32
pcia_a1_group_capture:
    mov eax, A1C_E_ARGUMENT
    cmp rdi, 0xFFFF
    ja .early
    cmp rdx, DA_REC_BYTES
    jne .early
    test rsi, rsi
    jz .early
    test rsi, 7
    jnz .early
    mov r8, rsi
    add r8, DA_REC_BYTES
    jc .early
    mov rax, rsi
    shl rax, 16
    sar rax, 16
    cmp rax, rsi
    jne .argument
    lea rcx, [r8-1]
    mov rax, rcx
    shl rax, 16
    sar rax, 16
    cmp rax, rcx
    jne .argument
    ; Output must not overwrite the common working facts, even on success.
    lea r9, [rel pcia_iso_record]
    lea r10, [r9+DA_REC_BYTES]
    cmp rsi, r10
    jae .separate
    cmp r9, r8
    jb .argument
.separate:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 280                       ; private DA272 and aligned native calls
    mov rbp, rsp
    mov r12d, edi
    mov r13, rsi
    mov edi, r12d
    call pcia_group_gate               ; THIS invocation, never record_peek
    mov r14d, eax
    test eax, eax
    jz .completed
    cmp eax, ISO_PROTECTED
    je .completed
    cmp eax, ISO_SHARED_DMA
    jne .refuse
.completed:
    lea r15, [rel pcia_iso_record]
    cmp byte [r15], 1
    jne .iommu
    cmp byte [r15+1], 1
    jne .backend
    cmp byte [r15+2], 0
    jne .incomplete
    movzx ebx, byte [r15+3]
    test ebx, ebx
    jz .incomplete
    cmp ebx, DA_REC_MAX
    ja .incomplete
    cmp byte [r15+4], 0
    jne .incomplete                    ; native builder's selected record0
    cmp byte [r15+5], 0
    jne .incomplete
    cmp word [r15+6], 0
    jne .incomplete
    cmp qword [r15+8], 0
    jne .incomplete
    cmp word [r15+16], 0
    jne .segment
    movzx eax, byte [r15+18]
    shl eax, 8
    mov al, [r15+19]
    cmp eax, r12d
    jne .incomplete
    ; Preserve the header and every CURRENT member. Unused stale slots are
    ; not facts: normalize only that unused tail, as pcia_group_snapshot does.
    mov rdi, rbp
    xor eax, eax
    mov ecx, DA_REC_BYTES/8
    cld
    rep stosq
    mov rdi, rbp
    mov rsi, r15
    lea ecx, [rbx+2]
    rep movsq
    cmp byte [rel amdvi_owned], 1
    je .amd_scope
    cmp byte [rel amdvi_owned], 0
    jne .backend
    cmp byte [rel vtd_enabled], 1
    jne .backend
    jmp .publish
.amd_scope:
    mov edi, r12d
    call amdvi_hda_scope               ; actual alias source/range and IVMD
    cmp eax, 1
    jne .rmrr
.publish:
    mov rdi, r13
    mov rsi, rbp
    mov ecx, DA_REC_BYTES/8
    cld
    rep movsq
    mov edx, r14d                      ; original isolation reason disclosed
    xor ecx, ecx
    xor eax, eax                       ; CAPTURED, not ELIGIBLE
    jmp .return
.iommu: mov eax, ISO_NO_IOMMU
    jmp .refuse
.backend: mov eax, ISO_UNSUP_BACKEND
    jmp .refuse
.incomplete: mov eax, ISO_TRUNC_ACPI
    jmp .refuse
.segment: mov eax, ISO_SEGMENT
    jmp .refuse
.rmrr: mov eax, ISO_RMRR
.refuse:
    xor ecx, ecx
    xor edx, edx
.return:
    add rsp, 280
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.argument:
    mov eax, A1C_E_ARGUMENT
.early:
    xor ecx, ecx
    xor edx, edx
    ret

; pcia_attach(RDI = SLAT root (PML4), RSI = PCIA_POOL_PAGES zeroable table
; pages) -> EAX 0 attached, -1 refused (pcia_err says why).
pcia_attach:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 152                        ; [0] receipt 64, [64] sizes dd[6], [88] GPAs dd[6], [112] pool descriptor 32
    mov  r12, rdi
    mov  r13, rsi
    mov  dword [rel pcia_err], PCIA_E_STATE
%ifdef PAOS_NIC_ASSIGNMENT
    cmp byte [rel nic_assignment_state], 0
    jne .refuse
%endif
    cmp  byte [rel pcia_state], PCIA_IDLE
    jne  .refuse
    cmp  byte [rel pcia_claimed], 0
    jne  .refuse
    %ifidn RCQ50_G0_FLR_LAB,1
    mov  byte [rel pcia_kind], PCIA_KIND_HDA
    test dword [rel vm_profile_dev_mask], PCIA_DEV_PCIFLR
    jz   .kind_hda
    mov  byte [rel pcia_kind], PCIA_KIND_FLR
.kind_hda:
    %endif
    mov  dword [rel pcia_candidates], 0
    mov  dword [rel pcia_sel_bdf], 0
    lea  rdi, [rel pcia_scan_cb]
    %ifidn RCQ50_G0_FLR_LAB,1
    cmp  byte [rel pcia_kind], PCIA_KIND_FLR
    jne  .scan
    lea  rdi, [rel pcia_flr_scan_cb]
.scan:
    %endif
    call pci_scan_with_filter
    mov  dword [rel pcia_err], PCIA_E_NONE
    mov  eax, [rel pcia_candidates]
    test eax, eax
    jz   .refuse
    mov  dword [rel pcia_err], PCIA_E_MANY
    cmp  eax, 1
    jne  .refuse
    mov  r14d, [rel pcia_sel_bdf]
    ; The guest IOMMU owners leave positive group/ACS authority to their caller
    ; (vtd_guest, amdvi_guest headers). Read-only, before the PCM, the identity's
    ; ECAM mark, the claim and any write: refuse unless the function is alone in
    ; its fail-closed isolation group.
    mov  dword [rel pcia_err], PCIA_E_GROUP
    mov  edi, r14d
    call pcia_group_gate
    test eax, eax
    jnz  .group_refused
    ; The owned PCM lives on the heap, not in the image: the Manager's PAX1 profile
    ; loads PaOS at 1 MiB, and QEMU OVMF's reserved 8 MiB page refuses SizeOfImage > 7 MiB.
    ; Taken after only config reads, before any config write.
    %ifidn RCQ50_G0_FLR_LAB,1
    cmp  byte [rel pcia_kind], PCIA_KIND_FLR
    je   .pcm_ready                      ; the endpoint is no player: no owned PCM
    %endif
    mov  dword [rel pcia_err], PCIA_E_PCM
    cmp  qword [rel pcia_pcm], 0
    jne  .pcm_ready
    mov  edi, PCIA_PCM_BYTES + PCIA_TAIL_BYTES
    call kmalloc                         ; once per boot, never freed: it outlives every player read
    test rax, rax
    jz   .refuse
    mov  [rel pcia_pcm], rax
.pcm_ready:
    xor  ebx, ebx
.snap:
    mov  edi, r14d
    mov  esi, ebx
    call pci_bdf_read
    lea  rdx, [rel pcia_snap_tmp]
    mov  [rdx + rbx], eax
    add  ebx, 4
    cmp  ebx, 256
    jb   .snap
    mov  dword [rel pcia_err], PCIA_E_BAR
    mov  eax, [rel pcia_snap_tmp + 0x10]
    test al, 1
    jnz  .refuse                         ; never an I/O BAR
    mov  r15d, eax
    and  r15d, 0xFFFFFFF0
    and  eax, 6
    jz   .bar32
    cmp  eax, 4
    jne  .refuse
    mov  eax, [rel pcia_snap_tmp + 0x14]
    shl  rax, 32
    or   r15, rax
.bar32:
    test r15, r15
    jz   .refuse
    mov  dword [rel pcia_err], PCIA_E_IDENTITY
    mov  edi, r14d
    mov  rsi, r15
    %ifidn RCQ50_G0_FLR_LAB,1
    cmp  byte [rel pcia_kind], PCIA_KIND_FLR
    jne  .identity_hda
    call pcia_flr_identity
    test eax, eax
    jz   .refuse
    mov  dword [rel pcia_err], PCIA_E_RESET
    mov  edi, r14d
    call pcia_flr_cap                    ; the release must be provable before anything is assigned
    test eax, eax
    jz   .refuse
    jmp  .identity_ok
.identity_hda:
    %endif
    call amdvi_hda_identity              ; architecture-neutral reader (incl. ATS absent/disabled)
    test eax, eax
    jz   .refuse
.identity_ok:
    mov  dword [rel pcia_err], PCIA_E_MAP
    mov  rdi, r15
    call paging_pd_entry_ptr
    test rax, rax
    jz   .refuse
    mov  rax, [rax]
    mov  ecx, eax
    and  ecx, 0x93
    cmp  ecx, 0x93                       ; P|RW|PCD|PS
    jne  .refuse
    bt   rax, 63
    jnc  .refuse                         ; NX
    mov  rcx, 0x000FFFFFFFE00000
    and  rax, rcx
    and  rcx, r15
    cmp  rax, rcx
    jne  .refuse                         ; identity
    ; From here this boot's native owners refuse the controller.
    mov  dword [rel pcia_err], PCIA_E_NATIVE
    %ifidn RCQ50_G0_FLR_LAB,1
    cmp  byte [rel pcia_kind], PCIA_KIND_FLR
    jne  .claim_hda
    cmp  dword [rel pci_claim_dropped], 0
    jne  .refuse                         ; the claim record may have lost a native claim
    mov  edi, r14d
    call pci_claim_find                  ; a native driver bound or tried it (e1000e takes any Intel 0200)
    test eax, eax
    jnz  .refuse
    jmp  .claimed
.claim_hda:
    %endif
    call hda_probe_guest_claim
    test rax, rax
    jnz  .refuse
.claimed:
    mov  byte [rel pcia_claimed], 1
    mov  [rel pcia_dev_bdf], r14d
    mov  [rel pcia_mmio], r15
    mov  dword [rel pcia_err], PCIA_E_QUIESCE
    mov  edi, r14d
    mov  edx, PCIA_CMD_INTXD
    call pcia_command
    test eax, eax
    jnz  .refuse
    mov  dword [rel pcia_err], PCIA_E_BAR
    mov  edi, r14d
    mov  esi, 0x10
    mov  edx, 0xFFFFFFFF
    call pci_bdf_write
    mov  edi, r14d
    mov  esi, 0x10
    call pci_bdf_read
    mov  ebx, eax
    mov  edi, r14d
    mov  esi, 0x10
    mov  edx, [rel pcia_snap_tmp + 0x10]
    call pci_bdf_write
    mov  edi, r14d
    mov  esi, 0x10
    call pci_bdf_read
    cmp  eax, [rel pcia_snap_tmp + 0x10]
    jne  .refuse                         ; the BAR did not come back
    and  ebx, 0xFFFFFFF0
    neg  ebx                             ; size = two's complement of the mask
    jz   .refuse
    lea  eax, [rbx - 1]
    test eax, ebx
    jnz  .refuse
    cmp  ebx, 0x1000
    jb   .refuse
    cmp  ebx, PCIA_BAR_MAX
    ja   .refuse
    mov  eax, r15d
    and  eax, 0x1FFFFF
    add  eax, ebx
    cmp  eax, 0x200000
    ja   .refuse                         ; the whole BAR inside the checked host leaf
    mov  [rel pcia_mmio_size], ebx
    %ifidn RCQ50_G0_FLR_LAB,1
    cmp  byte [rel pcia_kind], PCIA_KIND_FLR
    jne  .quiesce_hda
    mov  dword [rel pcia_err], PCIA_E_RESET
    mov  edi, r14d
    call pcia_flr                        ; a clean function: reset, snapshot restored, read back
    test eax, eax
    jz   .refuse
    jmp  .quiesced
.quiesce_hda:
    %endif
    mov  dword [rel pcia_err], PCIA_E_QUIESCE
    mov  edi, r14d
    mov  edx, PCIA_CMD_INTXD | PCIA_CMD_MEM
    call pcia_command
    cmp  eax, PCIA_CMD_MEM
    jne  .refuse_decode
    mov  rdi, r15
    call pcia_hda_quiesce
    mov  ebp, eax
    mov  edi, r14d
    mov  edx, PCIA_CMD_INTXD
    call pcia_command
    test eax, eax
    jnz  .refuse
    test ebp, ebp
    jz   .refuse
.quiesced:
    mov  dword [rel pcia_err], PCIA_E_SHADOW
    lea  rdi, [rsp + 64]
    xor  eax, eax
    mov  ecx, 48
    cld
    rep  stosb
    mov  eax, [rel pcia_mmio_size]
    mov  [rsp + 64], eax
    mov  dword [rsp + 88], PCIA_BAR_GPA
    lea  rdi, [rel pcia_snap_tmp]
    lea  rsi, [rsp + 64]
    lea  rdx, [rsp + 88]
    mov  ecx, r14d
    call pcia_shadow_init
    test eax, eax
    jnz  .refuse
    mov  dword [rel pcia_err], PCIA_E_IOMMU
    mov  eax, [rel hv_linux_start_consumed]
    mov  [rel pcia_gen], rax
    mov  edi, r14d
    mov  rsi, [rel hv_linux_ram_bytes]
    mov  rdx, [rel hv_linux_ram]
    mov  rcx, rax
    call pcia_iommu_attach
    test eax, eax
    jnz  .iommu_refused
    mov  byte [rel pcia_iommu_live], 1
    mov  dword [rel pcia_err], PCIA_E_RECEIPT
    mov  rdi, rsp
    call pcia_iommu_receipt
    test eax, eax
    jz   .release
    mov  dword [rel pcia_err], PCIA_E_SLAT
    lea  r8, [rsp + 112]
    mov  [r8], r13
    mov  dword [r8 + 8], PCIA_POOL_PAGES
    mov  dword [r8 + 12], 0
    mov  dword [r8 + 16], 0              ; 4 KiB/2 MiB leaves only
    mov  rdi, r12
    mov  esi, PCIA_BAR_GPA
    mov  rdx, r15
    mov  ecx, [rel pcia_mmio_size]
    call hv_slat_map_mmio
    test eax, eax
    jnz  .release
    mov  eax, [rsp + 112 + 20]
    add  eax, [rsp + 112 + 24]
    mov  [rel pcia_leaves], eax
    add  [rel vm_profile_live_leaves], eax ; PD index 129 is outside the display census
    mov  dword [rel pcia_err], 0
    mov  byte [rel pcia_state], PCIA_ATTACHED
    %ifidn RCQ50_G0_FLR_LAB,1
    cmp  byte [rel pcia_kind], PCIA_KIND_FLR
    jne  .tone
    lea  rdi, [rel str_pcia_flr_attached]
    jmp  .announce
.tone:
    %endif
    mov  rdi, [rel pcia_pcm]
    call hda_probe_generate              ; the player's owned immutable source for this START
    mov  rdi, [rel pcia_pcm]
    add  rdi, PCIA_PCM_BYTES
    xor  eax, eax
    mov  ecx, PCIA_TAIL_BYTES
    rep  stosb                           ; silent tail, rewritten every START
    lea  rdi, [rel str_pcia_attached]
.announce:
    call serial_string
    mov  edi, r14d
    call serial_hex64
    call serial_newline
    xor  eax, eax
    jmp  .out
.release:
    mov  byte [rel pcia_state], PCIA_RELEASING
    call pcia_release_body
    jmp  .fail
.iommu_refused:
    mov  rdi, rsp
    call pcia_iommu_receipt
    cmp  qword [rsp], 0
    je   .refuse_shadow                  ; nothing committed: the domain never changed
    mov  byte [rel pcia_state], PCIA_POISON
.refuse_shadow:
    call pcia_shadow_reset
    jmp  .fail
.group_refused:
    lea  rdi, [rel str_pcia_group]
    call serial_string
    movzx edi, byte [rel pcia_iso_reason]
    call serial_hex64
    call serial_newline
    jmp  .refuse
.refuse_decode:
    mov  edi, r14d
    mov  edx, PCIA_CMD_INTXD
    call pcia_command
.refuse:
.fail:
    lea  rdi, [rel str_pcia_refused]
    call serial_string
    mov  edi, [rel pcia_err]
    call serial_hex64
    call serial_newline
    mov  eax, -1
.out:
    add  rsp, 152
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; pcia_release -> EAX 0 idle (also when nothing was assigned), -1 poisoned.
; Only after the vCPU has actually stopped.
pcia_release:
    cmp  byte [rel pcia_state], PCIA_ATTACHED
    je   .go
    xor  eax, eax
    cmp  byte [rel pcia_state], PCIA_POISON
    jne  .out
    mov  eax, -1
.out:
    ret
.go:
    mov  byte [rel pcia_state], PCIA_RELEASING ; vPCI stops forwarding, no INTx
pcia_release_body:
    push rbx
    push r12
    sub  rsp, 8
    mov  r12d, [rel pcia_dev_bdf]
    %ifidn RCQ50_G0_FLR_LAB,1
    cmp  byte [rel pcia_kind], PCIA_KIND_FLR
    jne  .stop_hda
    mov  edi, r12d
    call pcia_flr                        ; MEM/BME off, reset, restore: while the guest domain still holds it
    mov  ebx, eax
    test eax, eax
    jz   .iommu
    lea  rdi, [rel str_pcia_flr_reset]
    call serial_string
    mov  edi, [rel pcia_bar_writes]      ; the guest's own config traffic this START
    call serial_hex64
    lea  rdi, [rel str_pcia_flr_cmd]
    call serial_string
    mov  edi, [rel pcia_cmd_writes]
    call serial_hex64
    call serial_newline
    jmp  .iommu
.stop_hda:
    %endif
    mov  edi, r12d
    mov  edx, PCIA_CMD_INTXD | PCIA_CMD_MEM ; BME off at once; MEM for the register stop
    call pcia_command
    xor  ebx, ebx
    cmp  eax, PCIA_CMD_MEM
    jne  .decode_off
    mov  rdi, [rel pcia_mmio]
    call pcia_hda_quiesce
    mov  ebx, eax
.decode_off:
    mov  edi, r12d
    mov  edx, PCIA_CMD_INTXD
    call pcia_command
    test eax, eax
    jz   .iommu
    xor  ebx, ebx
.iommu:
    cmp  byte [rel pcia_iommu_live], 1
    jne  .shadow
    mov  edi, r12d
    mov  rsi, [rel pcia_gen]
    call pcia_iommu_detach               ; the guest is stopped, MEM/BME off, reset held
    mov  byte [rel pcia_iommu_live], 0
    test eax, eax
    jz   .shadow
    xor  ebx, ebx
.shadow:
    call pcia_shadow_reset
    test ebx, ebx
    jz   .poison
    %ifidn RCQ50_G0_FLR_LAB,1
    cmp  byte [rel pcia_kind], PCIA_KIND_FLR
    jne  .idle
    mov  byte [rel pcia_claimed], 0      ; proven reset: the next START may assign it again
.idle:
    %endif
    mov  byte [rel pcia_state], PCIA_IDLE
    lea  rdi, [rel str_pcia_released]
    call serial_string
    xor  eax, eax
    jmp  .done
.poison:
    mov  byte [rel pcia_state], PCIA_POISON
    lea  rdi, [rel str_pcia_poisoned]
    call serial_string
    mov  eax, -1
.done:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; pcia_try_inject_irq -> EAX 1 when the assigned function's level line was
; queued on master-PIC line PCIA_GUEST_IRQ. Polled: the device's real INTx
; stays disabled; the line is high while GIE and an enabled status bit are
; set, and Linux's level handler masks/unmasks it, so a line that is still
; high after the unmask is offered again and a cleared one is not.
pcia_try_inject_irq:
%ifdef PAOS_NIC_ASSIGNMENT
    cmp byte [rel nic_assignment_state], 0
    jne nic_assignment_irq
%endif
    xor  eax, eax
    cmp  byte [rel pcia_state], PCIA_ATTACHED
    jne  .out
    %ifidn RCQ50_G0_FLR_LAB,1
    cmp  byte [rel pcia_kind], PCIA_KIND_FLR
    je   .out                            ; no line: its registers are not HDA's
    %endif
    movzx ecx, word [rel pcia_cfg_shadow + 4]
    test ecx, PCIA_CMD_MEM
    jz   .out
    test ecx, PCIA_CMD_INTXD
    jnz  .out                            ; the guest disabled its own INTx
    mov  rdx, [rel pcia_mmio]
    mov  ecx, [rdx + 0x20]               ; INTCTL
    test ecx, ecx
    jns  .out                            ; GIE
    and  ecx, [rdx + 0x24]               ; INTSTS: enabled status bits
    and  ecx, 0x7FFFFFFF
    jz   .out
    inc  dword [rel pcia_irq_high]
    mov  edi, PCIA_GUEST_IRQ
    call hv_pic_try_inject
    add  [rel pcia_irq_injected], eax
.out:
    ret

; EAX nonzero while a function is assigned or poisoned (guest power refuses).
; Touches EAX only.
pcia_guest_owned:
    ; Invalidate even when NIC delegation wins: no stale HDA sample may stand
    ; for that independently owned class. No device read/write or admission.
    mov dword [rel pcia_power_observation],0
    ; Whole-group reservations remain guest-owned even after POISON and
    ; independently of the singleton leaf. Never make an empty passive record
    ; or a failed common query mean free; only A's private held set owns this.
    call pcia_grp_any_held
    test eax,eax
    jnz .group_owned
%ifdef PAOS_NIC_ASSIGNMENT
    cmp byte [rel nic_assignment_state], 0
    jne nic_assignment_owned
%endif
    xor  eax, eax
    cmp  byte [rel pcia_state], PCIA_IDLE
    setne al
    ; Record this actual assignment predicate, not a later resample/census.
    ; Preserve the original EAX-only ABI and comparison flags. BSP caller with
    ; IF clear consumes this immediately; no callback, release or owner change.
    pushfq
    push rax
    mov [rel pcia_power_observation+4],eax
    movzx eax,byte [rel pcia_state]
    mov [rel pcia_power_observation+8],eax
    mov eax,[rel pcia_dev_bdf]       ; physical owner survives shadow reset
    mov [rel pcia_power_observation+12],eax
    mov rax,[rel pcia_gen]           ; original IOMMU START generation, not boot age
    mov [rel pcia_power_observation+16],rax
    xor eax,eax                     ; HDA unless the compiled FLR kind says otherwise
%ifidn RCQ50_G0_FLR_LAB,1
    movzx eax,byte [rel pcia_kind]
%endif
    mov [rel pcia_power_observation+24],eax
    movzx eax,byte [rel pcia_claimed]
    mov [rel pcia_power_observation+28],eax
    mov dword [rel pcia_power_observation],1 ; publish complete last
    pop rax
    popfq
    ret
.group_owned:
    ret

; RAX = owned immutable PCM for this START's player (0 unless attached),
; EDX = its bytes: the tone and its silent tail.
pcia_playback_source:
    xor  eax, eax
    xor  edx, edx
    cmp  byte [rel pcia_state], PCIA_ATTACHED
    jne  .out
    %ifidn RCQ50_G0_FLR_LAB,1
    cmp  byte [rel pcia_kind], PCIA_KIND_FLR
    je   .out
    %endif
    mov  rax, [rel pcia_pcm]
    mov  edx, PCIA_PCM_BYTES + PCIA_TAIL_BYTES
.out:
    ret

%ifidn RCQ50_G0_FLR_LAB,1
; pci_scan_with_filter callback: the one exact pinned endpoint (ECX = vendev).
pcia_flr_scan_cb:
    cmp  ecx, PCIA_FLR_VENDEV
    jne  .out
    shl  edi, 8
    shl  esi, 3
    or   edi, esi
    or   edi, edx                        ; packed BDF
    inc  dword [rel pcia_candidates]
    mov  [rel pcia_sel_bdf], edi
.out:
    ret

; EDI = BDF, RSI = BAR0 host address -> EAX 1 when it is still the pinned endpoint, a
; single-function type-0 header, BAR0 that memory address, and its ATS absent or
; disabled through the function's ECAM page (amdvi_hda_identity's ATS rule); else 0.
pcia_flr_identity:
    push r12
    push r13
    mov  r12d, edi
    mov  r13, rsi
    xor  esi, esi
    call pci_bdf_read
    cmp  eax, PCIA_FLR_VENDEV
    jne  .no
    mov  edi, r12d
    mov  esi, 0x0C
    call pci_bdf_read
    shr  eax, 16
    test al, 0xFF                        ; header type 0, not multi-function
    jnz  .no
    mov  edi, r12d
    mov  esi, 0x10
    call pci_bdf_read
    test al, 1
    jnz  .no
    and  eax, 0xFFFFFFF0
    cmp  rax, r13                        ; the pin is a 32-bit BAR (attach read the same dword)
    jne  .no
    mov  edi, r12d
    call amdvi_hda_ecam_uc
    mov  edi, r12d
    call vtd_hda_ats_state
    cmp  eax, 1
    ja   .no
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    ret

; EDI = BDF -> EAX = the PCIe capability offset when DevCap advertises FLR and the TSC is
; calibrated (every FLR wait is bounded by it), else 0. The capability and its
; Device Control/Status dword must fit the conventional 256-byte snapshot.
pcia_flr_cap:
    push rbx
    push r12
    sub  rsp, 8
    xor  eax, eax
    cmp  qword [rel tsc_khz], 0
    je   .out
    mov  r12d, edi
    mov  esi, PCIA_CAP_PCIE
    call pci_find_cap
    mov  ebx, eax
    cmp  eax, 0x40                      ; below this is the conventional header
    jb   .none
    cmp  eax, 0xF4                      ; cap+8 dword ends no later than 0xFF
    ja   .none
    mov  edi, r12d
    lea  esi, [rbx + 4]
    call pci_bdf_read                    ; Device Capabilities
    bt   eax, 28                         ; Function Level Reset Capability
    mov  eax, ebx
    jc   .out
.none:
    xor  eax, eax
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; pcia_flr(EDI = BDF) -> EAX 1 proven, 0 not. Decode and bus mastering off (read back),
; Transactions Pending clear within 100 ms, Initiate FLR, 100 ms, the function answers
; with its attach vendev within 1 s, then cacheline/latency, BARs, interrupt line and
; Device Control are restored from the attach snapshot (pcia_snap_tmp). Writable
; cacheline/latency, interrupt line, Device Control (without Initiate FLR), every
; BAR and the vendev read back equal; Command last at INTx-disable only.
pcia_flr:
    push rbx
    push r12
    push r13
    mov  r12d, edi
    call pcia_flr_cap
    test eax, eax
    jz   .out
    mov  r13d, eax
    mov  edi, r12d
    mov  edx, PCIA_CMD_INTXD
    call pcia_command
    test eax, eax
    jnz  .no
    mov  ebx, PCIA_FLR_TP_POLLS
.tp:
    mov  edi, r12d
    lea  esi, [r13 + 8]
    call pci_bdf_read                    ; Device Control | Device Status << 16
    bt   eax, 21                         ; Transactions Pending
    jnc  .tp_clear
    mov  edi, 1000
    call tsc_delay_us
    dec  ebx
    jnz  .tp
    jmp  .no
.tp_clear:
    and  eax, 0xFFFF                     ; the RW1C status half writes 0
    or   eax, 0x8000                     ; Initiate Function Level Reset
    mov  edx, eax
    mov  edi, r12d
    lea  esi, [r13 + 8]
    call pci_bdf_write
    mov  edi, 100000
    call tsc_delay_us                    ; no config request for 100 ms after the reset
    mov  ebx, PCIA_FLR_ID_POLLS
.id:
    mov  edi, r12d
    xor  esi, esi
    call pci_bdf_read
    cmp  eax, [rel pcia_snap_tmp]
    je   .restore
    mov  edi, 1000
    call tsc_delay_us
    dec  ebx
    jnz  .id
    jmp  .no
.restore:
    mov  ebx, 0x0C
.restore_next:
    mov  edi, r12d
    mov  esi, ebx
    lea  rax, [rel pcia_snap_tmp]
    mov  edx, [rax + rbx]
    call pci_bdf_write
    add  ebx, 4
    cmp  ebx, 0x28                       ; 0x0C, then BAR0..BAR5
    jb   .restore_next
    mov  edi, r12d
    mov  esi, 0x3C
    mov  edx, [rel pcia_snap_tmp + 0x3C]
    call pci_bdf_write
    mov  edi, r12d
    lea  esi, [r13 + 8]
    lea  rax, [rel pcia_snap_tmp]
    movzx edx, word [rax + r13 + 8]
    and  edx, 0x7FFF                     ; Device Control as attached, never a second FLR
    call pci_bdf_write
    mov  edi, r12d
    lea  esi, [r13 + 8]
    call pci_bdf_read
    and  eax, 0x7FFF                     ; ignore Device Status and Initiate FLR
    lea  rdx, [rel pcia_snap_tmp]
    movzx edx, word [rdx + r13 + 8]
    and  edx, 0x7FFF
    cmp  eax, edx
    jne  .no
    mov  edi, r12d
    mov  esi, 0x0C
    call pci_bdf_read
    and  eax, 0xFFFF                     ; cacheline/latency; header/BIST are read-only
    movzx edx, word [rel pcia_snap_tmp + 0x0C]
    cmp  eax, edx
    jne  .no
    mov  edi, r12d
    mov  esi, 0x3C
    call pci_bdf_read
    and  eax, 0xFF                       ; writable interrupt line only
    movzx edx, byte [rel pcia_snap_tmp + 0x3C]
    cmp  eax, edx
    jne  .no
    mov  ebx, 0x10
.verify:
    mov  edi, r12d
    mov  esi, ebx
    call pci_bdf_read
    lea  rdx, [rel pcia_snap_tmp]
    cmp  eax, [rdx + rbx]
    jne  .no
    add  ebx, 4
    cmp  ebx, 0x28
    jb   .verify
    mov  edi, r12d
    xor  esi, esi
    call pci_bdf_read
    cmp  eax, [rel pcia_snap_tmp]
    jne  .no
    mov  edi, r12d
    mov  edx, PCIA_CMD_INTXD
    call pcia_command
    test eax, eax
    jnz  .no
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

str_pcia_flr_attached: db "PCIA: assigned FLR endpoint bdf=", 0
str_pcia_flr_reset: db "PCIA: FLR reset proven, snapshot restored; guest bar_writes=", 0
str_pcia_flr_cmd:  db " cmd_writes=", 0
%endif
str_pcia_attached: db "PCIA: assigned HDA function bdf=", 0
str_pcia_refused:  db "PCIA: assignment refused err=", 0
str_pcia_group:    db "PCIA: isolation group not this function alone iso=", 0
str_pcia_released: db "PCIA: released", 13, 10, 0
str_pcia_poisoned: db "PCIA: release not proven, function poisoned", 13, 10, 0

; Read-only UDP observation. Errors use their unsigned u32 bit pattern.
pcia_render_stat:
    lea  rdi, [rel str_pcia_obs_pcia_gen]
    call hv_out_str
    mov  eax, [rel pcia_gen]
    call hv_out_dec
    lea  rdi, [rel str_pcia_obs_pcia_state]
    call hv_out_str
    movzx eax, byte [rel pcia_state]
    call hv_out_dec
    lea  rdi, [rel str_pcia_obs_pcia_bdf]
    call hv_out_str
    mov  eax, [rel pcia_dev_bdf]
    call hv_out_dec
    lea  rdi, [rel str_pcia_obs_pcia_err]
    call hv_out_str
    mov  eax, [rel pcia_err]
    call hv_out_dec
    ret

str_pcia_obs_pcia_gen: db " pcia_gen=", 0
str_pcia_obs_pcia_state: db " pcia_state=", 0
str_pcia_obs_pcia_bdf: db " pcia_bdf=", 0
str_pcia_obs_pcia_err: db " pcia_err=", 0

; GUESTVM GATE (root 74353, VM 74359): this machine's assignment isolation verdict for its
; HDA function without a START. Read-only: pcia_scan_cb and pcia_group_gate read config
; space and fill RAM snapshots only; no claim, decode, reset, domain, pcia_err or pcia_gen
; change. Refused unless pcia is IDLE and unclaimed, so a live or spent attach's selection
; is never overwritten. iso= is the device_assignment ISO_* code (0 = eligible), present
; only for exactly one candidate, the same rule as pcia_attach (PCIA_E_NONE / _MANY).
pcia_render_gate:
    push rbx
    lea  rdi, [rel str_pcia_gate]
    call hv_out_str
    cmp  byte [rel pcia_state], PCIA_IDLE
    jne  .busy
    cmp  byte [rel pcia_claimed], 0
    jne  .busy
    xor  ebx, ebx                        ; backend, pcia_group_gate's order
    cmp  byte [rel amdvi_owned], 1
    je   .amd
    cmp  byte [rel vtd_enabled], 1
    jne  .backend
    mov  ebx, 2
    jmp  .backend
.amd:
    mov  ebx, 1
.backend:
    lea  rdi, [rel str_pcia_gate_backend]
    call hv_out_str
    mov  eax, ebx
    call hv_out_dec
    mov  dword [rel pcia_candidates], 0
    mov  dword [rel pcia_sel_bdf], 0
    lea  rdi, [rel pcia_scan_cb]
    call pci_scan_with_filter
    lea  rdi, [rel str_pcia_gate_candidates]
    call hv_out_str
    mov  eax, [rel pcia_candidates]
    call hv_out_dec
    cmp  dword [rel pcia_candidates], 1
    jne  .none
    lea  rdi, [rel str_pcia_gate_bdf]
    call hv_out_str
    mov  eax, [rel pcia_sel_bdf]
    call hv_out_dec
    mov  edi, [rel pcia_sel_bdf]
    call pcia_group_gate
    mov  ebx, eax
    lea  rdi, [rel str_pcia_gate_iso]
    call hv_out_str
    mov  eax, ebx
    call hv_out_dec
    pop  rbx
    ret
.none:
    lea  rdi, [rel str_pcia_gate_iso_none]
    call hv_out_str
    pop  rbx
    ret
.busy:
    lea  rdi, [rel str_pcia_gate_busy]
    call hv_out_str
    movzx eax, byte [rel pcia_state]
    call hv_out_dec
    lea  rdi, [rel str_pcia_gate_claimed]
    call hv_out_str
    movzx eax, byte [rel pcia_claimed]
    call hv_out_dec
    pop  rbx
    ret

str_pcia_gate:            db " GUESTVM GATE", 0   ; ARG echo adds no separator
str_pcia_gate_backend:    db " backend=", 0
str_pcia_gate_candidates: db " candidates=", 0
str_pcia_gate_bdf:        db " bdf=", 0
str_pcia_gate_iso:        db " iso=", 0
str_pcia_gate_iso_none:   db " iso=none", 0
str_pcia_gate_busy:       db " REFUSED busy pcia_state=", 0
str_pcia_gate_claimed:    db " claimed=", 0

%include "hv/pcia_grp_authority.inc" ; original per-endpoint reservations
%include "hv/pcia_group.inc"         ; native whole-group admission/root scope

%include "hv/pcia_grp.inc"           ; guarded; harnesses that assemble this file whole see PCIA_GRP_BYTES
%include "core/abi/wdata.inc"
%macro WDATA_hv_pci_assign 0
alignb 8
pcia_state:          resb 1              ; owned by the attach/release path, never by reset
alignb 8
pcia_shadow:
pcia_bdf:            resd 1
pcia_addr:           resd 1
pcia_cmd_writes:     resd 1
pcia_bar_writes:     resd 1
pcia_bar_foreign:    resd 1
pcia_bar_last:       resd 1
pcia_fixed_writes:   resd 1
pcia_refused_writes: resd 1
pcia_cmd_forwarded:  resw 1
alignb 4
pcia_bar_size:       resd PCIA_BARS
pcia_bar_gpa:        resd PCIA_BARS
pcia_bar_probe:      resb PCIA_BARS
alignb 8
pcia_cfg_snap:       resb 256
pcia_cfg_shadow:     resb 256
pcia_shadow_end:
%endmacro
WDATA_BSS_DEFER WDATA_hv_pci_assign

; RCQ-36 V2 c2: attach/release state, outside the shadow that reset clears.
%macro WDATA_hv_pci_assign_c2 0
alignb 8
pcia_mmio:           resq 1              ; identity UC VA == HPA of BAR0
pcia_gen:            resq 1              ; START generation of the IOMMU domain
pcia_pcm:            resq 1              ; kmalloc'd tone + silent tail (PCIA_PCM_BYTES + PCIA_TAIL_BYTES)
pcia_dev_bdf:        resd 1
pcia_sel_bdf:        resd 1
pcia_candidates:     resd 1
pcia_mmio_size:      resd 1
pcia_err:            resd 1
pcia_leaves:         resd 1
pcia_irq_high:       resd 1
pcia_irq_injected:   resd 1
pcia_claimed:        resb 1              ; sticky for the boot: native owners refuse
pcia_iommu_live:     resb 1
%ifidn RCQ50_G0_FLR_LAB,1
pcia_kind:           resb 1              ; latched by each attach, read by its release
%endif
alignb 8
pcia_snap_tmp:       resb 256
%endmacro
WDATA_BSS_DEFER WDATA_hv_pci_assign_c2

; RCQ-36 group gate: the read-only topology snapshot and fact record.
%macro WDATA_hv_pci_assign_iso 0
alignb 8
pcia_iso_snap:       resb DA_SNAP_MAX * DA_SNAP_SZ
pcia_iso_record:     resb DA_REC_BYTES
pcia_iso_n:          resd 1
pcia_iso_incomplete: resb 1
pcia_iso_reason:     resb 1
%endmacro
WDATA_BSS_DEFER WDATA_hv_pci_assign_iso

; W4c-2 (ABI v1, hv/pcia_grp.inc): the one private whole-group owner record. Mutating
; group entry points accept only this exact address; zero is PGS_FREE. Written only by
; the owning W4c-2 steps (VM A admit, AV B/C); nothing writes it in this build.
%macro WDATA_hv_pcia_grp 0
alignb 64
pcia_grp:            resb PCIA_GRP_BYTES
%endmacro
WDATA_BSS_DEFER WDATA_hv_pcia_grp

; Last exact pcia_guest_owned predicate only; never a DMA retirement receipt.
; u32 version,owned,state,physical BDF; u64 START generation; u32 kind,claimed.
%macro WDATA_hv_pci_power_observation 0
alignb 8
pcia_power_observation: resb 32
%endmacro
WDATA_BSS_DEFER WDATA_hv_pci_power_observation
