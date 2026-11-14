;; MODULE boot/rescue0_snp
;; LAYER 0
;; EXPORTS rescue0_snp_discover, rescue0_snp_report, rescue0_snp_ran, rescue0_snp_status, rescue0_snp_count, rescue0_snp_recorded, rescue0_snp_rows, rescue0_snp_text
;; IMPORTS boot/serial, boot/header
;; CAPS
;; OWNER saga:boot
; ============================================================================
; boot/rescue0_snp.asm -- Rescue-0 rung R0-0: READ-ONLY firmware SNP discovery.
;
; PETER DECISION 2026-09-30 22:31 (RESCUE0_STATUS_20260930.md), scope item 1:
; "R0-0: read-only SNP discovery plus a public R0STAT". Design study:
; gauntlet_v2/docs/RESCUE0_DESIGN_20260930.md §1.3 / §2.1 step 1-2 (discover and
; record only; NOT steps 3-6).
;
; rescue0_snp_discover runs PRE-ExitBootServices from the tail of
; secureboot_snapshot (svc/command_auth.asm; header.asm is not edited). It:
;   1. LocateHandleBuffer(ByProtocol, EFI_SIMPLE_NETWORK_PROTOCOL)  (BS +0x138)
;   2. per handle (at most R0_SNP_MAX rows; the total count is always kept):
;        HandleProtocol(SNP)  (BS +0x98) -> Revision, Mode*; copies from Mode:
;        State, HwAddressSize, MaxPacketSize, CurrentAddress, PermanentAddress,
;        IfType, MediaPresentSupported, MediaPresent (Mode fields as the
;        firmware last cached them; GetStatus is NOT called)
;        HandleProtocol(DevicePath) -> bounded walk: PCI node count, last
;        PCI node dev/fn
;        LocateDevicePath(PciIo) (BS +0xB8) on a COPY of the path pointer ->
;        HandleProtocol(PciIo) -> GetLocation (+112) and one config-space
;        dword read at offset 0 (Pci.Read +48: vendor/device id)
;   3. a second pass re-reads every Mode.State (state_end) to show the pass
;      left the firmware state as it found it
;   4. FreePool(handle buffer) (BS +0x48), then clears every firmware pointer
;      it held so nothing stale survives EBS
;   5. renders the record ONCE into rescue0_snp_text; the boot marker and the
;      R0STAT verb both project those same bytes.
;
; Record text (space-separated key=value; one line; R0STAT appends it as is):
;   snp=present|absent|no_boot_services|locate_error snp_efi=<status hex>
;   snp_count=<handles> snp_recorded=<rows, <= 4>, then per row i:
;   snp<i>.flags=<R0F_* hex> .mac .perm (HwAddressSize bytes) .if (IfType)
;   .mps/.mp (MediaPresentSupported/MediaPresent) .state/.state_end (Mode.State
;   0 Stopped, 1 Started, 2 Initialized; first read / after the pass) .maxpkt
;   .hwlen .pci=<seg:bus:dev.fn|none> .id=<vendor:device|none> .direct
;   .dp=<nodes>/<pci nodes>/<tail type>.<tail subtype>; finally text_trunc=0|1.
;   A row whose identity equals earlier row k prints only snp<i>.same=<k> and
;   its own .dp (one NIC usually shows as MAC + IPv4 + IPv6 child handles).
;
; NEVER called: SNP Start/Stop/Initialize/Reset/Shutdown/ReceiveFilters/
; StationAddress/Statistics/NvData/GetStatus/Transmit/Receive, OpenProtocol
; EXCLUSIVE/BY_DRIVER, ConnectController/DisconnectController, any variable
; service. No network frame is sent or received; no listener is created.
; Every failure degrades to a recorded status; the boot always continues.
; ============================================================================

R0_SNP_MAX        equ 8            ; rows kept; duplicate-identity rows render compactly
R0_SNP_SCAN_LIMIT equ 64           ; > this many SNP handles = anomalous: record count, keep no rows
R0_DP_MAX_NODES   equ 32           ; device path walk bound
R0_DP_MAX_NODE    equ 1024         ; per-node length bound
R0_ROW            equ 128
R0_TEXT_MAX       equ 1024

; row layout
R0R_FLAGS   equ 0                  ; dd R0F_*
R0R_STATE   equ 4                  ; dd Mode.State at first read
R0R_STATE2  equ 8                  ; dd Mode.State re-read after the whole pass
R0R_HWSIZE  equ 12                 ; dd Mode.HwAddressSize
R0R_MAXPKT  equ 16                 ; dd Mode.MaxPacketSize
R0R_IFTYPE  equ 20                 ; db Mode.IfType
R0R_MPS     equ 21                 ; db Mode.MediaPresentSupported
R0R_MP      equ 22                 ; db Mode.MediaPresent
R0R_DPPCI   equ 23                 ; db PCI nodes on the device path
R0R_DPDEV   equ 24                 ; db last device-path PCI node: device
R0R_DPFN    equ 25                 ; db last device-path PCI node: function
R0R_BUS     equ 26                 ; db PciIo.GetLocation bus
R0R_DEV     equ 27                 ; db PciIo.GetLocation device
R0R_FN      equ 28                 ; db PciIo.GetLocation function
R0R_DPN     equ 29                 ; db device path nodes before End (walk-bounded)
R0R_DPTT    equ 30                 ; db last node before End: type
R0R_DPTS    equ 31                 ; db last node before End: subtype
R0R_SEG     equ 32                 ; dd PciIo.GetLocation segment
R0R_VID     equ 36                 ; dw config 0x00
R0R_DID     equ 38                 ; dw config 0x02
R0R_REV     equ 40                 ; dq SNP Revision
R0R_CUR     equ 48                 ; 32 B Mode.CurrentAddress
R0R_PERM    equ 80                 ; 32 B Mode.PermanentAddress
R0R_MODEP   equ 112                ; dq Mode* (pre-EBS only; zeroed before return)

R0F_PROTO   equ 1                  ; HandleProtocol(SNP) returned an interface
R0F_MODE    equ 2                  ; Mode* non-NULL, fields copied
R0F_DP      equ 4                  ; device path present
R0F_PCI     equ 8                  ; PciIo located on the path, GetLocation ok
R0F_PCIID   equ 16                 ; config dword 0 read ok
R0F_DIRECT  equ 32                 ; the PciIo handle is the NIC itself (rest of path = MAC/End)

; Provenance (ADMIN 2026-10-01 08:21: core license undecided, so implemented from the UEFI
; specification itself, 2.10; no iPXE code or structure; iPXE ROMs are QEMU test fixtures only):
;   §4.4 EFI Boot Services Table: slot offsets FreePool 0x48, HandleProtocol 0x98,
;        LocateDevicePath 0xB8, LocateHandleBuffer 0x138
;   §7.2 Memory Allocation Services (FreePool); §7.3 Protocol Handler Services (HandleProtocol,
;        LocateHandleBuffer ByProtocol, LocateDevicePath)
;   §10.2-10.3 Device Path Protocol + nodes (generic header; Hardware/PCI node dev/fn)
;   §14.4 EFI PCI I/O Protocol (Pci.Read +48, GetLocation +112)
;   §24.1 Simple Network Protocol (EFI_SIMPLE_NETWORK_PROTOCOL.Mode +120; EFI_SIMPLE_NETWORK_MODE
;        field offsets below)
; SNP Mode offsets (UEFI 2.x EFI_SIMPLE_NETWORK_MODE)
SNPM_STATE  equ 0
SNPM_HWSIZE equ 4
SNPM_MAXPKT equ 12
SNPM_CUR    equ 552
SNPM_PERM   equ 616
SNPM_IFTYPE equ 648
SNPM_MPS    equ 651
SNPM_MP     equ 652
SNP_MODE_PTR equ 120               ; EFI_SIMPLE_NETWORK_PROTOCOL.Mode

; ---------------------------------------------------------------------------
; rescue0_snp_discover -- pre-EBS, read-only. The frame is realigned (RBP
;   anchor, AND RSP,-16, 128 B) so every firmware call site has RSP%16 = 0, the
;   32 B shadow space and the 5th-argument slot whatever the caller's residue.
;   Preserves callee-saved registers. Never fatal.
; locals: [rsp+32] 5th arg, [rsp+48] count, [rsp+56] buffer, [rsp+64] iface,
;         [rsp+72] dp cursor, [rsp+80] pci handle, [rsp+88] seg, [rsp+96] bus,
;         [rsp+104] dev, [rsp+112] fn / config dword
; ---------------------------------------------------------------------------
rescue0_snp_discover:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    and  rsp, -16                       ; self-align: entry residue differs by route
    sub  rsp, 128
    mov  byte [rel rescue0_snp_ran], 0
    mov  qword [rel rescue0_snp_status], -1
    mov  dword [rel rescue0_snp_count], 0
    mov  dword [rel rescue0_snp_recorded], 0
    lea  rdi, [rel rescue0_snp_rows]
    xor  eax, eax
    mov  ecx, (R0_SNP_MAX * R0_ROW) / 8
    rep  stosq
    mov  rbx, [rel boot_services]
    test rbx, rbx
    jz   .render
    mov  qword [rsp + 48], 0
    mov  qword [rsp + 56], 0
    mov  ecx, 2                         ; ByProtocol
    lea  rdx, [rel r0_snp_guid]
    xor  r8d, r8d                       ; SearchKey = NULL
    lea  r9, [rsp + 48]
    lea  rax, [rsp + 56]
    mov  [rsp + 32], rax
    call [rbx + 0x138]                  ; LocateHandleBuffer
    mov  [rel rescue0_snp_status], rax
    test rax, rax
    jnz  .render                        ; EFI_NOT_FOUND = no SNP (count stays 0)
    mov  r13, [rsp + 48]
    mov  r14, [rsp + 56]
    test r14, r14
    jz   .render
    mov  rax, r13
    mov  ecx, 0x7FFFFFFF
    cmp  rax, rcx
    jbe  .count_ok
    mov  eax, ecx                       ; saturate an absurd count
.count_ok:
    mov  [rel rescue0_snp_count], eax
    cmp  r13, R0_SNP_SCAN_LIMIT
    ja   .free                          ; anomalous inventory: keep the count only
    cmp  r13, R0_SNP_MAX
    jbe  .bounded
    mov  r13d, R0_SNP_MAX
.bounded:
    mov  [rel rescue0_snp_recorded], r13d
    xor  r12d, r12d
.handle:
    cmp  r12, r13
    jae  .second_pass
    lea  r15, [rel rescue0_snp_rows]
    mov  rax, r12
    shl  rax, 7                         ; * R0_ROW
    add  r15, rax
    ; --- SNP interface + Mode fields (plain loads; no SNP function is called)
    mov  qword [rsp + 64], 0
    mov  rcx, [r14 + r12*8]
    lea  rdx, [rel r0_snp_guid]
    lea  r8, [rsp + 64]
    call [rbx + 0x98]                   ; HandleProtocol(SNP)
    test rax, rax
    jnz  .devpath
    mov  rax, [rsp + 64]
    test rax, rax
    jz   .devpath
    or   dword [r15 + R0R_FLAGS], R0F_PROTO
    mov  rcx, [rax]
    mov  [r15 + R0R_REV], rcx
    mov  rsi, [rax + SNP_MODE_PTR]
    test rsi, rsi
    jz   .devpath
    or   dword [r15 + R0R_FLAGS], R0F_MODE
    mov  [r15 + R0R_MODEP], rsi
    mov  eax, [rsi + SNPM_STATE]
    mov  [r15 + R0R_STATE], eax
    mov  eax, [rsi + SNPM_HWSIZE]
    mov  [r15 + R0R_HWSIZE], eax
    mov  eax, [rsi + SNPM_MAXPKT]
    mov  [r15 + R0R_MAXPKT], eax
    mov  al, [rsi + SNPM_IFTYPE]
    mov  [r15 + R0R_IFTYPE], al
    mov  al, [rsi + SNPM_MPS]
    mov  [r15 + R0R_MPS], al
    mov  al, [rsi + SNPM_MP]
    mov  [r15 + R0R_MP], al
    xor  ecx, ecx
.mac_copy:
    mov  rax, [rsi + SNPM_CUR + rcx]
    mov  [r15 + R0R_CUR + rcx], rax
    mov  rax, [rsi + SNPM_PERM + rcx]
    mov  [r15 + R0R_PERM + rcx], rax
    add  ecx, 8
    cmp  ecx, 32
    jb   .mac_copy
.devpath:
    mov  qword [rsp + 72], 0
    mov  rcx, [r14 + r12*8]
    lea  rdx, [rel r0_dp_guid]
    lea  r8, [rsp + 72]
    call [rbx + 0x98]                   ; HandleProtocol(DevicePath)
    test rax, rax
    jnz  .next_handle
    mov  rdi, [rsp + 72]
    test rdi, rdi
    jz   .next_handle
    or   dword [r15 + R0R_FLAGS], R0F_DP
    mov  rsi, r15
    call r0_dp_pci_nodes                ; bounded walk, row PCI-node fields
    ; LocateDevicePath(PciIo, &dp, &handle): the path pointer is a COPY in a
    ; local; firmware advances it to the unmatched remainder.
    mov  qword [rsp + 80], 0
    lea  rcx, [rel r0_pciio_guid]
    lea  rdx, [rsp + 72]
    lea  r8, [rsp + 80]
    call [rbx + 0xB8]                   ; LocateDevicePath
    test rax, rax
    jnz  .next_handle
    mov  rcx, [rsp + 80]
    test rcx, rcx
    jz   .next_handle
    ; remainder = End node or a MAC/VLAN node -> the PCI function is the NIC
    mov  rdx, [rsp + 72]
    test rdx, rdx
    jz   .pciio
    movzx eax, byte [rdx]
    cmp  al, 0x7F
    je   .direct
    cmp  al, 3
    jne  .pciio
    movzx eax, byte [rdx + 1]
    cmp  al, 11                         ; MSG_MAC_ADDR_DP
    je   .direct
    cmp  al, 20                         ; MSG_VLAN_DP
    jne  .pciio
.direct:
    or   dword [r15 + R0R_FLAGS], R0F_DIRECT
.pciio:
    mov  qword [rsp + 64], 0
    mov  rcx, [rsp + 80]
    lea  rdx, [rel r0_pciio_guid]
    lea  r8, [rsp + 64]
    call [rbx + 0x98]                   ; HandleProtocol(PciIo)
    test rax, rax
    jnz  .next_handle
    mov  rcx, [rsp + 64]
    test rcx, rcx
    jz   .next_handle
    mov  qword [rsp + 88], 0
    mov  qword [rsp + 96], 0
    mov  qword [rsp + 104], 0
    mov  qword [rsp + 112], 0
    lea  rdx, [rsp + 88]
    lea  r8, [rsp + 96]
    lea  r9, [rsp + 104]
    lea  rax, [rsp + 112]
    mov  [rsp + 32], rax
    call [rcx + 112]                    ; PciIo.GetLocation(This,&Seg,&Bus,&Dev,&Fn)
    test rax, rax
    jnz  .next_handle
    or   dword [r15 + R0R_FLAGS], R0F_PCI
    mov  eax, [rsp + 88]
    mov  [r15 + R0R_SEG], eax
    mov  al, [rsp + 96]
    mov  [r15 + R0R_BUS], al
    mov  al, [rsp + 104]
    mov  [r15 + R0R_DEV], al
    mov  al, [rsp + 112]
    mov  [r15 + R0R_FN], al
    mov  dword [rsp + 112], 0xFFFFFFFF
    mov  rcx, [rsp + 64]
    mov  edx, 2                         ; EfiPciIoWidthUint32
    xor  r8d, r8d                       ; config offset 0 (vendor | device << 16)
    mov  r9d, 1                         ; count
    lea  rax, [rsp + 112]
    mov  [rsp + 32], rax
    call [rcx + 48]                     ; PciIo.Pci.Read (config space read)
    test rax, rax
    jnz  .next_handle
    mov  eax, [rsp + 112]
    mov  [r15 + R0R_VID], eax           ; VID (lo word) + DID (hi word)
    or   dword [r15 + R0R_FLAGS], R0F_PCIID
.next_handle:
    inc  r12
    jmp  .handle
.second_pass:
    ; Re-read every Mode.State after the whole pass, then drop the pointer.
    xor  r12d, r12d
.state_again:
    cmp  r12, r13
    jae  .free
    lea  r15, [rel rescue0_snp_rows]
    mov  rax, r12
    shl  rax, 7
    add  r15, rax
    mov  rsi, [r15 + R0R_MODEP]
    test rsi, rsi
    jz   .state_next
    mov  eax, [rsi + SNPM_STATE]
    mov  [r15 + R0R_STATE2], eax
    mov  qword [r15 + R0R_MODEP], 0
.state_next:
    inc  r12
    jmp  .state_again
.free:
    mov  rcx, r14
    call [rbx + 0x48]                   ; FreePool(handle buffer)
.render:
    mov  byte [rel rescue0_snp_ran], 1
    call r0_render
    lea  rsp, [rbp - 40]
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; r0_dp_pci_nodes(RDI=device path, RSI=row): bounded walk; counts nodes and
; Hardware/PCI nodes (type 1 / subtype 1), keeps the last PCI node's
; device/function and the type/subtype of the last node before End (tells a
; MAC child from a VLAN/IP child or a bare PCI handle).
r0_dp_pci_nodes:
    xor  ecx, ecx
.node:
    cmp  ecx, R0_DP_MAX_NODES
    jae  .done
    movzx eax, byte [rdi]
    cmp  al, 0x7F                       ; END_DEVICE_PATH_TYPE
    je   .done
    movzx edx, word [rdi + 2]
    cmp  edx, 4
    jb   .done
    cmp  edx, R0_DP_MAX_NODE
    ja   .done
    inc  byte [rsi + R0R_DPN]
    mov  [rsi + R0R_DPTT], al
    mov  r8b, [rdi + 1]
    mov  [rsi + R0R_DPTS], r8b
    cmp  al, 1                          ; HARDWARE_DEVICE_PATH
    jne  .advance
    cmp  byte [rdi + 1], 1              ; HW_PCI_DP
    jne  .advance
    cmp  edx, 6
    jb   .advance
    inc  byte [rsi + R0R_DPPCI]
    mov  al, [rdi + 4]                  ; Function
    mov  [rsi + R0R_DPFN], al
    mov  al, [rdi + 5]                  ; Device
    mov  [rsi + R0R_DPDEV], al
.advance:
    add  rdi, rdx
    inc  ecx
    jmp  .node
.done:
    ret

; ---------------------------------------------------------------------------
; rescue0_snp_report -- the boot marker. Projects the rendered record verbatim.
; ---------------------------------------------------------------------------
rescue0_snp_report:
    lea  rdi, [rel str_r0_marker_pre]
    call serial_string
    lea  rdi, [rel rescue0_snp_text]
    call serial_string
    lea  rdi, [rel str_r0_marker_post]
    call serial_string
    ret

; ---------------------------------------------------------------------------
; r0_render -- render the record once into rescue0_snp_text (bounded, NUL-
;   terminated; overflow sets text_trunc=1 at the end). Pure; no firmware calls.
; ---------------------------------------------------------------------------
r0_render:
    push rbx
    push r12
    push r13
    lea  rax, [rel rescue0_snp_text]
    mov  [rel r0t_cur], rax
    mov  byte [rax], 0
    mov  byte [rel r0t_over], 0
    lea  rdi, [rel str_r0_snp]
    call r0t_str
    mov  rax, [rel rescue0_snp_status]
    lea  rdi, [rel str_r0_present]
    test rax, rax
    jz   .kind
    lea  rdi, [rel str_r0_absent]
    mov  rcx, 0x800000000000000E        ; EFI_NOT_FOUND
    cmp  rax, rcx
    je   .kind
    lea  rdi, [rel str_r0_nobs]
    cmp  rax, -1
    je   .kind
    lea  rdi, [rel str_r0_error]
.kind:
    call r0t_str
    lea  rdi, [rel str_r0_efi]
    call r0t_str
    mov  rdi, [rel rescue0_snp_status]
    call r0t_hex
    lea  rdi, [rel str_r0_count]
    call r0t_str
    mov  edi, [rel rescue0_snp_count]
    call r0t_dec
    lea  rdi, [rel str_r0_recorded]
    call r0t_str
    mov  edi, [rel rescue0_snp_recorded]
    call r0t_dec
    xor  r12d, r12d
.row:
    cmp  r12d, [rel rescue0_snp_recorded]
    jae  .tail
    lea  rbx, [rel rescue0_snp_rows]
    mov  eax, r12d
    shl  eax, 7
    add  rbx, rax
    ; A row whose identity fields equal an earlier row's (same NIC seen via a
    ; MAC/IPv4/IPv6 child handle) renders as same=<k> plus its own dp field.
    mov  edi, r12d
    call r0_row_twin
    test eax, eax
    js   .full_row
    mov  r13d, eax
    mov  edi, r12d
    lea  rsi, [rel str_r0_f_same]
    call r0t_key
    mov  edi, r13d
    call r0t_dec
    jmp  .dp_field
.full_row:
    ; flags (raw) so a reader can tell absent data from a zero value
    mov  edi, r12d
    lea  rsi, [rel str_r0_f_flags]
    call r0t_key
    mov  edi, [rbx + R0R_FLAGS]
    call r0t_hex
    test dword [rbx + R0R_FLAGS], R0F_MODE
    jz   .pci
    mov  edi, r12d
    lea  rsi, [rel str_r0_f_cur]
    call r0t_key
    lea  rdi, [rbx + R0R_CUR]
    mov  esi, [rbx + R0R_HWSIZE]
    call r0t_mac
    mov  edi, r12d
    lea  rsi, [rel str_r0_f_perm]
    call r0t_key
    lea  rdi, [rbx + R0R_PERM]
    mov  esi, [rbx + R0R_HWSIZE]
    call r0t_mac
    mov  edi, r12d
    lea  rsi, [rel str_r0_f_iftype]
    call r0t_key
    movzx edi, byte [rbx + R0R_IFTYPE]
    call r0t_dec
    mov  edi, r12d
    lea  rsi, [rel str_r0_f_mps]
    call r0t_key
    movzx edi, byte [rbx + R0R_MPS]
    call r0t_dec
    mov  edi, r12d
    lea  rsi, [rel str_r0_f_mp]
    call r0t_key
    movzx edi, byte [rbx + R0R_MP]
    call r0t_dec
    mov  edi, r12d
    lea  rsi, [rel str_r0_f_state]
    call r0t_key
    mov  edi, [rbx + R0R_STATE]
    call r0t_dec
    mov  edi, r12d
    lea  rsi, [rel str_r0_f_state2]
    call r0t_key
    mov  edi, [rbx + R0R_STATE2]
    call r0t_dec
    mov  edi, r12d
    lea  rsi, [rel str_r0_f_maxpkt]
    call r0t_key
    mov  edi, [rbx + R0R_MAXPKT]
    call r0t_dec
    mov  edi, r12d
    lea  rsi, [rel str_r0_f_hwsize]
    call r0t_key
    mov  edi, [rbx + R0R_HWSIZE]
    call r0t_dec
.pci:
    mov  edi, r12d
    lea  rsi, [rel str_r0_f_pci]
    call r0t_key
    test dword [rbx + R0R_FLAGS], R0F_PCI
    jnz  .pci_loc
    lea  rdi, [rel str_r0_none]
    call r0t_str
    jmp  .pci_id
.pci_loc:
    mov  edi, [rbx + R0R_SEG]
    mov  esi, 4
    call r0t_hexw
    lea  rdi, [rel str_r0_colon]
    call r0t_str
    movzx edi, byte [rbx + R0R_BUS]
    mov  esi, 2
    call r0t_hexw
    lea  rdi, [rel str_r0_colon]
    call r0t_str
    movzx edi, byte [rbx + R0R_DEV]
    mov  esi, 2
    call r0t_hexw
    lea  rdi, [rel str_r0_dot]
    call r0t_str
    movzx edi, byte [rbx + R0R_FN]
    mov  esi, 1
    call r0t_hexw
.pci_id:
    mov  edi, r12d
    lea  rsi, [rel str_r0_f_pciid]
    call r0t_key
    test dword [rbx + R0R_FLAGS], R0F_PCIID
    jnz  .pci_id_val
    lea  rdi, [rel str_r0_none]
    call r0t_str
    jmp  .pci_direct
.pci_id_val:
    movzx edi, word [rbx + R0R_VID]
    mov  esi, 4
    call r0t_hexw
    lea  rdi, [rel str_r0_colon]
    call r0t_str
    movzx edi, word [rbx + R0R_DID]
    mov  esi, 4
    call r0t_hexw
.pci_direct:
    mov  edi, r12d
    lea  rsi, [rel str_r0_f_direct]
    call r0t_key
    mov  edi, [rbx + R0R_FLAGS]
    shr  edi, 5                         ; R0F_DIRECT
    and  edi, 1
    call r0t_dec
    ; dp=<nodes>/<pci nodes>/<tail type>.<tail subtype>
.dp_field:
    mov  edi, r12d
    lea  rsi, [rel str_r0_f_dppci]
    call r0t_key
    movzx edi, byte [rbx + R0R_DPN]
    call r0t_dec
    lea  rdi, [rel str_r0_slash]
    call r0t_str
    movzx edi, byte [rbx + R0R_DPPCI]
    call r0t_dec
    lea  rdi, [rel str_r0_slash]
    call r0t_str
    movzx edi, byte [rbx + R0R_DPTT]
    call r0t_dec
    lea  rdi, [rel str_r0_dot]
    call r0t_str
    movzx edi, byte [rbx + R0R_DPTS]
    call r0t_dec
    inc  r12d
    jmp  .row
.tail:
    lea  rdi, [rel str_r0_trunc]
    call r0t_str_force
    pop  r13
    pop  r12
    pop  rbx
    ret

; r0_row_twin(EDI=row) -> EAX = lowest earlier row with identical identity
; bytes [0, R0R_DPN) and [R0R_SEG, R0R_MODEP), else -1. Device-path tail
; fields (R0R_DPN..R0R_DPTS) are excluded on purpose.
r0_row_twin:
    lea  r8, [rel rescue0_snp_rows]
    mov  eax, edi
    shl  eax, 7
    lea  r9, [r8 + rax]                 ; this row
    xor  eax, eax                       ; candidate k
.cand:
    cmp  eax, edi
    jae  .none
    mov  ecx, eax
    shl  ecx, 7
    lea  r10, [r8 + rcx]
    xor  ecx, ecx
.lo:
    cmp  ecx, R0R_DPN
    jae  .hi_start
    mov  dl, [r9 + rcx]
    cmp  dl, [r10 + rcx]
    jne  .next
    inc  ecx
    jmp  .lo
.hi_start:
    mov  ecx, R0R_SEG
.hi:
    cmp  ecx, R0R_MODEP
    jae  .found
    mov  dl, [r9 + rcx]
    cmp  dl, [r10 + rcx]
    jne  .next
    inc  ecx
    jmp  .hi
.next:
    inc  eax
    jmp  .cand
.none:
    mov  eax, -1
.found:
    ret

; r0t_key(EDI=row index, RSI=" name=" suffix) -> appends " snp<i>.<name>="
r0t_key:
    push rsi
    push rdi
    lea  rdi, [rel str_r0_rowpre]
    call r0t_str
    pop  rdi
    call r0t_dec
    pop  rdi
    jmp  r0t_str

; r0t_str(RDI=NUL string): bounded append; sets r0t_over on clip.
r0t_str:
    mov  rsi, [rel r0t_cur]
    lea  rdx, [rel rescue0_snp_text + R0_TEXT_MAX - 24]
.loop:
    mov  al, [rdi]
    test al, al
    jz   .done
    cmp  rsi, rdx
    jae  .over
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .loop
.over:
    mov  byte [rel r0t_over], 1
.done:
    mov  byte [rsi], 0
    mov  [rel r0t_cur], rsi
    ret

; r0t_str_force: final " text_trunc=<0|1>" field, written into the reserved tail.
r0t_str_force:
    mov  rsi, [rel r0t_cur]
.loop:
    mov  al, [rdi]
    test al, al
    jz   .flag
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .loop
.flag:
    mov  al, [rel r0t_over]
    add  al, '0'
    mov  [rsi], al
    mov  byte [rsi + 1], 0
    inc  rsi
    mov  [rel r0t_cur], rsi
    ret

; r0t_dec(RDI=unsigned value): decimal.
r0t_dec:
    sub  rsp, 40
    mov  rax, rdi
    lea  r8, [rsp + 32]
    mov  byte [r8], 0
    mov  ecx, 10
.digit:
    xor  edx, edx
    div  rcx
    add  dl, '0'
    dec  r8
    mov  [r8], dl
    test rax, rax
    jnz  .digit
    mov  rdi, r8
    call r0t_str
    add  rsp, 40
    ret

; r0t_hex(RDI=value): minimal lowercase hex.
r0t_hex:
    mov  esi, 1
; r0t_hexw(RDI=value, ESI=min digits 1..16): lowercase hex, zero-padded.
r0t_hexw:
    sub  rsp, 40
    lea  r8, [rsp + 32]
    mov  byte [r8], 0
    lea  r9, [rel r0_hexdig]
    xor  ecx, ecx
.nib:
    mov  eax, edi
    and  eax, 15
    mov  al, [r9 + rax]
    dec  r8
    mov  [r8], al
    inc  ecx
    shr  rdi, 4
    jnz  .nib
    cmp  ecx, esi
    jb   .nib
    mov  rdi, r8
    call r0t_str
    add  rsp, 40
    ret

; r0t_mac(RDI=address bytes, ESI=HwAddressSize): "aa:bb:..", length clamped
; to 1..32 (a zero size renders the 6-byte Ethernet prefix).
r0t_mac:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12d, esi
    test r12d, r12d
    jnz  .clamp
    mov  r12d, 6
.clamp:
    cmp  r12d, 32
    jbe  .go
    mov  r12d, 32
.go:
    xor  r13d, r13d
.byte:
    cmp  r13d, r12d
    jae  .done
    test r13d, r13d
    jz   .hex
    lea  rdi, [rel str_r0_colon]
    call r0t_str
.hex:
    movzx edi, byte [rbx + r13]
    mov  esi, 2
    call r0t_hexw
    inc  r13d
    jmp  .byte
.done:
    pop  r13
    pop  r12
    pop  rbx
    ret

; --- GUIDs (EFI_GUID byte layout) ---
align 8
r0_snp_guid:   dd 0xA19832B9          ; EFI_SIMPLE_NETWORK_PROTOCOL_GUID
               dw 0xAC25, 0x11D3
               db 0x9A, 0x2D, 0x00, 0x90, 0x27, 0x3F, 0xC1, 0x4D
r0_dp_guid:    dd 0x09576E91          ; EFI_DEVICE_PATH_PROTOCOL_GUID
               dw 0x6D3F, 0x11D2
               db 0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B
r0_pciio_guid: dd 0x4CF5B200          ; EFI_PCI_IO_PROTOCOL_GUID
               dw 0x68B8, 0x4CA5
               db 0x9E, 0xEC, 0xB2, 0x3E, 0x3F, 0x50, 0x02, 0x9A

r0_hexdig:          db "0123456789abcdef"
str_r0_marker_pre:  db "[PAOS64] rescue0 R0-0 snp discovery (read-only, pre-EBS): ", 0
str_r0_marker_post: db " [rescue0.snp.discovery]", 13, 10, 0
str_r0_snp:         db "snp=", 0
str_r0_present:     db "present", 0
str_r0_absent:      db "absent", 0
str_r0_nobs:        db "no_boot_services", 0
str_r0_error:       db "locate_error", 0
str_r0_efi:         db " snp_efi=", 0
str_r0_count:       db " snp_count=", 0
str_r0_recorded:    db " snp_recorded=", 0
str_r0_rowpre:      db " snp", 0
str_r0_f_flags:     db ".flags=", 0
str_r0_f_cur:       db ".mac=", 0
str_r0_f_perm:      db ".perm=", 0
str_r0_f_iftype:    db ".if=", 0
str_r0_f_mps:       db ".mps=", 0
str_r0_f_mp:        db ".mp=", 0
str_r0_f_state:     db ".state=", 0
str_r0_f_state2:    db ".state_end=", 0
str_r0_f_maxpkt:    db ".maxpkt=", 0
str_r0_f_hwsize:    db ".hwlen=", 0
str_r0_f_pci:       db ".pci=", 0
str_r0_f_pciid:     db ".id=", 0
str_r0_f_direct:    db ".direct=", 0
str_r0_f_dppci:     db ".dp=", 0
str_r0_f_same:      db ".same=", 0
str_r0_slash:       db "/", 0
str_r0_none:        db "none", 0
str_r0_colon:       db ":", 0
str_r0_dot:         db ".", 0
str_r0_trunc:       db " text_trunc=", 0

align 8
rescue0_snp_status:   dq -1           ; LocateHandleBuffer EFI status; -1 = not run
r0t_cur:              dq 0
rescue0_snp_count:    dd 0            ; SNP handles the firmware reported
rescue0_snp_recorded: dd 0            ; rows kept (<= R0_SNP_MAX)
rescue0_snp_ran:      db 0            ; 1 once the pre-EBS pass completed
r0t_over:             db 0
align 8
rescue0_snp_rows:     times (R0_SNP_MAX * R0_ROW) db 0
rescue0_snp_text:     times R0_TEXT_MAX db 0
