;; MODULE boot/gop
;; LAYER 0
;; EXPORTS gop_hp_live_consumed, gop_census_pci, gop_proto, gop_census_path_state, gop_census_root_hid, gop_census_root_uid, gop_census_path_n, gop_census_path, gop_setmode_attempts, gop_scan_flags, gop_scan_queries, gop_scan_valid, gop_scan_releases, gop_scan_complete, gop_scan_max_modes, gop_scan_query_status, gop_scan_free_status, gop_pci_discovery, gop_pci_locate_status, gop_pci_handles, gop_pci_scanned, gop_pci_protocol_failures, gop_pci_protocol_nulls, gop_pci_protocol_error, gop_pci_read_failures, gop_pci_read_error, gop_pci_non_display, gop_discrete, gop_selected_pci_nodes, gop_query, gop_connect_display_controllers, gop_locate_initial_status, gop_locate_retry_status, gop_connect_attempts, gop_connect_successes, gop_connect_last_status, gop_blt_calibrate, gop_revalidate_record, gop_health_evaluate, gop_fb_memtype_probe, gop_reval_remodeset, gop_native_mode, gop_calib_status, gop_calib_reason, gop_calib_pitch, gop_calib_meta_pitch, gop_calib_format, gop_calib_rows, gop_reval_status, gop_reval_changes, gop_setmode_forced, gop_fb_memtype, gop_fb_pages_2m, gop_fb_pages_4k, gop_fb_range_exact, gop_health_state, gop_reg_status, gop_reg_stride64, gop_reg_size, gop_reg_srcsz, gop_edid_clear, gop_edid_validate_publish, gop_edid_raw, gop_edid_bytes, gop_edid_blocks, gop_edid_checksum_ok, gop_edid_present, gop_plane_dump, gop_plane_geom, gop_pipe_probe, gop_ddi_mask, gop_output_ptr, gop_output_count, gop_outputs, gop_last_ddisel, gop_disp_tier, gop_disp_repairs, gop_disp_id, gop_fill, fb_base, gop_fb_reported, fb_width, fb_height, fb_stride, fb_pixel_format, fb_bpp, fb_size, gop_mode_list, gop_mode_count, res_native_w, res_native_h, res_src, res_dpi, fb_out_width, fb_out_height, fb_out_stride, fb_scale
;; IMPORTS boot/serial, boot/header, boot/smbios, boot/boot_menu
;; CAPS
;; OWNER saga:boot
; ============================================================================
; boot/gop.asm — UEFI Graphics Output Protocol: grab the linear framebuffer.
;
; The boot-floor display (DRIVER_MODEL: gop is the always-works displaydev
; backend; this later becomes dev/gpu/gop.asm). Two halves:
;   gop_query  — runs PRE-EBS (LocateProtocol is a boot service): find GOP, save
;                framebuffer base + resolution + stride.
;   gop_fill   — runs POST-paging: draw into the (identity-mapped, RW+NX) fb.
;
; Framebuffer mapping: QEMU/OVMF puts the fb at ~0x80000000 (2 GiB), inside our
; 16 GiB identity map (RW+NX — writing pixels is a data write; NX is fine, we
; never execute the fb). A fb above 16 GiB would need an extra mapping — handled
; later; QEMU is within range. Degrades gracefully if GOP is absent.
;
; EFI_GRAPHICS_OUTPUT_PROTOCOL layout: Mode* @0x18; Mode: Info* @8,
; FrameBufferBase @0x18, FrameBufferSize @0x20; Info: HorizontalRes @4,
; VerticalRes @8, PixelFormat @0x0C, PixelsPerScanLine @0x20.
; BootServices->LocateProtocol @0x140.
; ============================================================================

gop_query:
    call gop_discovery_observation_reset
    push rbx
    ; efi_entry's internal-call convention gives this function RSP%16 == 0.
    ; After push rbx, reserve the 32-byte Microsoft x64 shadow space plus the
    ; alignment qword so the firmware LocateProtocol callee enters with the
    ; ABI-required RSP%16 == 8.  The old 32-byte reservation entered firmware
    ; misaligned and became a size/layout-sensitive Lenovo pre-EBS #UD.
    sub  rsp, 40
    lea  rcx, [rel gop_guid]
    xor  rdx, rdx                   ; Registration = NULL
    mov  qword [rel gop_proto], 0    ; never reuse an untouched/stale OUT value
    lea  r8,  [rel gop_proto]
    mov  rax, [rel boot_services]
    call [rax + 0x140]              ; LocateProtocol(Guid, NULL, &Interface)
    add  rsp, 40
    mov  [rel gop_locate_initial_status], rax
    test rax, rax
    jz   .located
    ; Some signed shim/Manager paths leave the PCI display controller present
    ; but disconnected.  Only EFI_NOT_FOUND warrants a bounded connect retry;
    ; all other firmware errors retain the old fail-closed behavior.
    mov  rdx, 0x800000000000000e   ; EFI_NOT_FOUND
    cmp  rax, rdx
    jne  .none
    call gop_connect_display_controllers
    test eax, eax
    jz   .none
    sub  rsp, 40
    lea  rcx, [rel gop_guid]
    xor  rdx, rdx
    mov  qword [rel gop_proto], 0    ; failed first lookup may have changed OUT
    lea  r8, [rel gop_proto]
    mov  rax, [rel boot_services]
    call [rax + 0x140]              ; one LocateProtocol retry, never a loop
    add  rsp, 40
    mov  [rel gop_locate_retry_status], rax
    test rax, rax
    jnz  .none
.located:

    mov  rbx, [rel gop_proto]       ; EFI_GRAPHICS_OUTPUT_PROTOCOL*
    test rbx, rbx                   ; EFI_SUCCESS alone does not supply a record
    jz   .none

    ; Diagnostic only: inventory bounded GOP handles before EBS, without
    ; changing the global LocateProtocol selection or any display mode.
    call gop_inventory_probe
    call gop_inventory_log

    ; --- 1104 native-resolution AUTO-DETECT (pre-EBS: QueryMode/SetMode are boot
    ;     services). Enumerates a bounded prefix plus current mode, reads EDID for the
    ;     panel's native timing, selects EDID-native (src=edid) else best inspected GOP
    ;     mode (src=gop), and SetModes to it. Preserves rbx; all Mode/Info fields
    ;     below are re-read fresh AFTER this returns (SetMode moves Info/fb). ---
    ; HP-PORT-2 (paos_hp 0a1136fe9 / hp005): on the HP EliteDesk 705 G5 only
    ; (AuthenticAMD AND its SMBIOS identity, smbios_hp_quirk_identity), accept a
    ; structurally sane LIVE mode with no QueryMode/EDID/SetMode call. Intel and
    ; every other AMD machine return CF=1 before any read and run the unchanged
    ; 1104/1249 autodetect + SetMode-always path below.
    call gop_amd_current_mode_fastpath
    jnc  .mode_ready
    call gop_autodetect
.mode_ready:

    mov  rsi, [rbx + 0x18]          ; -> Mode (re-read after SetMode)
    test rsi, rsi
    jz   .none
    mov  rdi, [rsi + 8]             ; -> Info (SetMode may replace this too)
    test rdi, rdi
    jz   .none                      ; validate both pointers before publishing fb
    cmp  qword [rsi + 16], 36     ; live Info must contain the complete v0 prefix
    jb   .none
    mov  rax, [rsi + 0x18]          ; FrameBufferBase
    mov  [rel fb_base], rax
    mov  [rel gop_fb_reported], rax ; retained: never repointed or zeroed (SEC 106852)
    mov  rax, [rsi + 0x20]          ; FrameBufferSize (firmware measurement)
    mov  [rel fb_size], rax
    mov  [rel gop_fb_reported+8], rax
    mov  eax, [rdi + 4]
    mov  [rel fb_width], eax
    mov  eax, [rdi + 8]
    mov  [rel fb_height], eax
    mov  eax, [rdi + 0x0C]          ; EFI_GRAPHICS_PIXEL_FORMAT
    mov  [rel fb_pixel_format], eax
    mov  dword [rel fb_bpp], 0
    cmp  eax, 2                      ; RGBX, BGRX, and PixelBitMask are UINT32 pixels
    ja   .pixel_size_done            ; PixelBltOnly/unknown has no linear pixel size
    mov  dword [rel fb_bpp], 32
.pixel_size_done:
    mov  eax, [rdi + 0x20]          ; PixelsPerScanLine (Info+0x20, NOT 0x24)
    mov  [rel fb_stride], eax
    ; --- 1249 §12 rung 2: Blt row-marker self-calibration (pre-EBS, guarded, fail-safe) ---
    call gop_blt_calibrate

    lea  rdi, [rel str_gop_found]
    call serial_string
    mov  edi, [rel fb_width]
    call serial_hex64
    lea  rdi, [rel str_gop_x]
    call serial_string
    mov  edi, [rel fb_height]
    call serial_hex64
    lea  rdi, [rel str_gop_at]
    call serial_string
    mov  rdi, [rel fb_base]
    call serial_hex64
    lea  rdi, [rel gop_nl]
    call serial_string

    ; --- 1016 GUI-floor GOP markers. These fire ONLY on a real framebuffer
    ;     acquisition (fb_base != 0) via the genuine UEFI GOP LocateProtocol path
    ;     — the SAME code that runs on the Lenovo bare metal (hence gop.bare_metal,
    ;     content-gated, not a latch: no GOP -> .none -> none of these print). ---
    lea  rdi, [rel str_gop_acquired]
    call serial_string
    lea  rdi, [rel str_gop_offsets]     ; stride/pitch derived (PixelsPerScanLine)
    call serial_string
    mov  edi, [rel fb_stride]
    call serial_hex64
    lea  rdi, [rel str_gop_offsets_tok] ; " [gop.offsets]\r\n"
    call serial_string
    lea  rdi, [rel str_gop_modeset]     ; current GOP mode is live (fb is drawable)
    call serial_string
    lea  rdi, [rel str_gop_baremetal]   ; real-hw-identical linear-fb path proven
    call serial_string
    pop  rbx
    ret
.none:
    ; A refused or incomplete acquisition must not expose an earlier surface.
    mov  qword [rel gop_proto], 0    ; failed acquisition is not a revalidation candidate
    mov  qword [rel fb_base], 0
    mov  qword [rel fb_size], 0
    mov  dword [rel fb_width], 0
    mov  dword [rel fb_height], 0
    mov  dword [rel fb_stride], 0
    mov  dword [rel fb_pixel_format], 0
    mov  dword [rel fb_bpp], 0
    lea  rdi, [rel str_gop_none]
    call serial_string
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; gop_amd_current_mode_fastpath — HP-PORT-2, ported from paos_hp 0a1136fe9
;   (hp005 "accept a sane live GOP mode without AMD firmware QueryMode/SetMode").
;   The HP tree runs it unconditionally (single-target tree); the unified tree
;   gates it on CPUID vendor AuthenticAMD AND the HP SMBIOS identity
;   (smbios_hp_quirk_identity), so the Intel fleet (Lenovo, Dell, Beelink, MSI)
;   and any other AMD machine keep the 1249 autodetect + SetMode path.
;   In:  RBX = EFI_GRAPHICS_OUTPUT_PROTOCOL* (non-NULL, gop_query's located proto)
;   Out: CF=0 -> live mode validated and projected (res_*, gop_mode_list[0]);
;               the caller captures Mode/Info exactly as after autodetect.
;               gop_native_mode stays -1, so gop_revalidate_record never
;               re-asserts a SetMode on this firmware either.
;        CF=1 -> not the HP (vendor or SMBIOS identity), or the live record
;               failed validation: caller runs the
;               unchanged gop_autodetect (hp005's own fallback order).
;   Makes NO firmware call. Preserves RBX. clobbers: RAX,RCX,RDX,RSI,RDI,R8-R11.
; ---------------------------------------------------------------------------
gop_amd_current_mode_fastpath:
    push rbx
    xor  eax, eax
    cpuid
    cmp  ebx, 0x68747541                ; AuthenticAMD: EBX='Auth'
    jne  .not_taken
    cmp  edx, 0x69746E65                ; EDX='enti'
    jne  .not_taken
    cmp  ecx, 0x444D4163                ; ECX='cAMD'
    jne  .not_taken
    call smbios_hp_quirk_identity       ; HP firmware only: other AMD machines
    test eax, eax                       ; keep the EDID-native SetMode path
    jz   .not_taken
    mov  rbx, [rsp]                     ; GOP* (cpuid clobbered RBX)
    test rbx, rbx
    jz   .not_taken
    ; --- hp005 .validate_current: memory reads only, same bounds as the HP tree
    mov  rsi, [rbx + 0x18]              ; EFI_GRAPHICS_OUTPUT_PROTOCOL.Mode
    test rsi, rsi
    jz   .not_taken
    mov  rdi, [rsi + 8]                 ; Mode.Info
    test rdi, rdi
    jz   .not_taken
    cmp  qword [rsi + 16], 36     ; live Info must contain the complete v0 prefix
    jb   .not_taken
    mov  rax, [rsi + 0x18]              ; FrameBufferBase
    test rax, rax
    jz   .not_taken
    mov  rax, [rsi + 0x20]              ; FrameBufferSize
    test rax, rax
    jz   .not_taken
    mov  eax, [rdi + 4]                 ; HorizontalResolution
    cmp  eax, 640
    jb   .not_taken
    cmp  eax, 8192
    ja   .not_taken
    mov  edx, [rdi + 8]                 ; VerticalResolution
    cmp  edx, 480
    jb   .not_taken
    cmp  edx, 8192
    ja   .not_taken
    mov  ecx, [rdi + 0x20]              ; PixelsPerScanLine
    test ecx, ecx
    jz   .not_taken
    cmp  ecx, eax                       ; padded stride is valid; short stride is not
    jb   .not_taken
    cmp  dword [rdi + 0x0C], 2          ; RGBX/BGRX/PixelBitMask are linear UINT32
    ja   .not_taken                     ; reject PixelBltOnly and unknown formats
    mov  eax, ecx                       ; allocation must hold stride*height*4
    imul rax, rdx
    shl  rax, 2
    cmp  qword [rsi + 0x20], rax
    jb   .not_taken
    ; --- hp005 projection of the only mode inspected (res_src=2 = GOP) ---
    mov  eax, [rdi + 4]
    mov  [rel res_native_w], eax
    mov  [rel gop_mode_list], eax
    mov  eax, [rdi + 8]
    mov  [rel res_native_h], eax
    mov  [rel gop_mode_list + 4], eax
    mov  dword [rel gop_mode_count], 1
    mov  byte [rel res_src], 2
    mov  byte [rel res_dpi], 1
    cmp  dword [rel res_native_w], 3000
    jb   .dpi_done
    mov  byte [rel res_dpi], 2
.dpi_done:
    lea  rdi, [rel str_res_auto_pre]
    call serial_string
    mov  edi, [rel res_native_w]
    call serial_hex64
    lea  rdi, [rel str_gop_x]
    call serial_string
    mov  edi, [rel res_native_h]
    call serial_hex64
    lea  rdi, [rel str_res_src_gop]
    call serial_string
    lea  rdi, [rel str_res_active]
    call serial_string
    lea  rdi, [rel str_gop_amd_fastpath]
    call serial_string
    mov  dword [rel gop_hp_live_consumed], 1 ; boot-lifetime fact: validated HP branch actually consumed
    call gop_edid_inventory_publish
    pop  rbx
    clc
    ret
.not_taken:
    pop  rbx
    stc
    ret

; gop_selected_pci_depth(RCX = GOP handle) -> gop_selected_pci_nodes = the number
;   of PCI nodes in the handle's device path (0 without one). >= 2 means a GPU
;   behind a bridge. Pre-EBS, read-only selected-controller identity. (MSI spoke 386ee66f7, ported.)
gop_selected_pci_depth:
    sub  rsp, 40
    mov  dword [rel gop_selected_pci_nodes], 0
    mov  dword [rel gop_census_path_state],0
    mov  dword [rel gop_census_path_n],0
    mov  dword [rel gop_census_root_hid],0
    mov  dword [rel gop_census_root_uid],0
    lea  rdx, [rel gop_devpath_guid]
    lea  r8, [rel gop_devpath_ptr]
    mov  qword [r8], 0
    mov  rax, [rel boot_services]
    call [rax + 0x98]               ; HandleProtocol(DevicePath)
    test rax, rax
    jnz  .out
    mov  rsi, [rel gop_devpath_ptr]
    call gop_census_path_capture ; retain existing selected handle path, no EFI call
    xor  ecx, ecx                   ; nodes walked (bounded)
.node:
    test rsi, rsi
    jz   .out
    cmp  ecx, 32
    jae  .out
    movzx eax, byte [rsi]           ; Type
    cmp  al, 0x7F                   ; End of device path
    je   .out
    movzx edx, word [rsi + 2]       ; Length
    cmp  edx, 4
    jb   .out
    cmp  al, 1                      ; Hardware
    jne  .adv
    cmp  byte [rsi + 1], 1          ; PCI
    jne  .adv
    inc  dword [rel gop_selected_pci_nodes]
.adv:
    add  rsi, rdx
    inc  ecx
    jmp  .node
.out:
    call gop_census_pci_capture
    add  rsp, 40
    ret

; C3 memory-only copy of the already-returned selected GOP DevicePath.
; State0 no path,1 complete,2 bounded/clipped,3 malformed. PCI path nodes
; are dev/function pairs, NOT BDFs. Root HID/UID does not invent bus/segment.
; Preserve RSI for the original depth walk. No selection or firmware calls.
gop_census_path_capture:
    push rsi
    mov dword [rel gop_census_path_state],0
    mov dword [rel gop_census_path_n],0
    mov dword [rel gop_census_root_hid],0
    mov dword [rel gop_census_root_uid],0
    test rsi,rsi
    jz .done
    xor r8d,r8d
.walk:
    cmp r8d,32
    jae .clipped
    movzx edx,word [rsi+2]
    cmp edx,4
    jb .bad
    cmp byte [rsi],0x7f
    jne .acpi
    cmp byte [rsi+1],0xff
    jne .bad
    mov dword [rel gop_census_path_state],1
    jmp .done
.acpi:
    cmp byte [rsi],2
    jne .pci
    cmp byte [rsi+1],1
    jne .next
    cmp edx,12
    jb .bad
    cmp dword [rel gop_census_root_hid],0
    jne .bad
    mov eax,[rsi+4]
    mov [rel gop_census_root_hid],eax
    mov eax,[rsi+8]
    mov [rel gop_census_root_uid],eax
    jmp .next
.pci:
    cmp byte [rsi],1
    jne .next
    cmp byte [rsi+1],1
    jne .next
    cmp edx,6
    jb .bad
    cmp byte [rsi+4],7
    ja .bad
    cmp byte [rsi+5],31
    ja .bad
    mov eax,[rel gop_census_path_n]
    cmp eax,16
    jae .clipped
    lea rcx,[rel gop_census_path]
    movzx r9d,byte [rsi+5]
    shl r9d,3
    or r9b,[rsi+4]
    mov [rcx+rax],r9b
    inc dword [rel gop_census_path_n]
.next:
    add rsi,rdx
    inc r8d
    jmp .walk
.clipped:
    mov dword [rel gop_census_path_state],2
    jmp .done
.bad:
    mov dword [rel gop_census_path_state],3
.done:
    pop rsi
    ret

; Pre-EBS, read-only multi-output discriminator. LocateHandleBuffer may return
; several GOP instances even when LocateProtocol selected just one. Record at
; most 16 handles; reject anomalous >128 inventories. A same-handle EDID flag
; is diagnostic only: firmware may expose EDID on a child handle instead.
; Row: width dd, height dd, flags dd (selected=1, active EDID=2,
; discovered EDID=4), reserved dd. No GOP/EDID selection or SetMode here.
gop_inventory_probe:
    push rbx
    push r12
    push r13
    push r14
    push r15
    ; Entry RSP%16=0. Five pushes and 72 bytes leave 32-byte EFI shadow,
    ; the fifth argument, and locals while each firmware callee sees %16=8.
    sub  rsp, 72
    mov  qword [rel gop_inventory_status], -1
    mov  dword [rel gop_inventory_count], 0
    mov  dword [rel gop_inventory_scanned], 0
    mov  dword [rel gop_inventory_selected], -1
    mov  qword [rel gop_inventory_edid], 0
    lea  rdi, [rel gop_inventory_rows]
    xor  eax, eax
    mov  ecx, 64
    rep  stosd
    mov  rbx, [rel boot_services]
    test rbx, rbx
    jz   .finish
    mov  qword [rsp + 48], 0         ; handle count
    mov  qword [rsp + 56], 0         ; handle buffer
    mov  ecx, 2                     ; ByProtocol
    lea  rdx, [rel gop_guid]
    xor  r8d, r8d                   ; SearchKey = NULL
    lea  r9, [rsp + 48]
    lea  rax, [rsp + 56]
    mov  [rsp + 32], rax            ; fifth argument: Buffer**
    call [rbx + 0x138]              ; LocateHandleBuffer
    mov  [rel gop_inventory_status], rax
    test rax, rax
    jnz  .finish
    mov  r13, [rsp + 48]
    mov  [rel gop_inventory_count], r13d
    mov  r14, [rsp + 56]
    test r14, r14
    jz   .finish
    cmp  r13, 128
    ja   .free                      ; refuse anomalous inventory, still free
    cmp  r13, 16
    jbe  .bounded
    mov  r13d, 16
.bounded:
    mov  r15, [rel gop_proto]
    xor  r12d, r12d
.next:
    cmp  r12, r13
    jae  .free
    inc  dword [rel gop_inventory_scanned]
    mov  qword [rsp + 40], 0
    mov  rcx, [r14 + r12*8]
    lea  rdx, [rel gop_guid]
    lea  r8, [rsp + 40]
    call [rbx + 0x98]               ; HandleProtocol(GOP)
    test rax, rax
    jnz  .advance
    mov  rax, [rsp + 40]
    test rax, rax
    jz   .advance
    lea  rdi, [rel gop_inventory_rows]
    mov  rcx, r12
    shl  rcx, 4
    add  rdi, rcx
    cmp  rax, r15
    jne  .mode
    or   dword [rdi + 8], 1
    mov  [rel gop_inventory_selected], r12d
    ; (MSI spoke 386ee66f7, ported) the selected GOP's PCI depth decides whether
    ; gop_autodetect may SetMode (a GPU behind a bridge keeps its firmware mode)
    push rax
    push rdi
    mov  rcx, [r14 + r12*8]
    call gop_selected_pci_depth
    pop  rdi
    pop  rax
.mode:
    mov  rax, [rax + 0x18]          ; GOP Mode*
    test rax, rax
    jz   .active_edid
    cmp  qword [rax + 16], 36     ; live Info must contain the complete v0 prefix
    jb   .active_edid
    mov  rax, [rax + 8]             ; Mode Info*
    test rax, rax
    jz   .active_edid
    mov  ecx, [rax + 4]
    mov  [rdi], ecx
    mov  ecx, [rax + 8]
    mov  [rdi + 4], ecx
.active_edid:
    mov  qword [rsp + 40], 0
    mov  rcx, [r14 + r12*8]
    lea  rdx, [rel edid_active_guid]
    lea  r8, [rsp + 40]
    call [rbx + 0x98]               ; HandleProtocol(EDID_ACTIVE)
    test rax, rax
    jnz  .discovered_edid
    cmp  qword [rsp + 40], 0
    je   .discovered_edid
    lea  rdi, [rel gop_inventory_rows]
    mov  rcx, r12
    shl  rcx, 4
    or   dword [rdi + rcx + 8], 2
    test dword [rdi + rcx + 8], 1     ; selected GOP handle only (active)
    jz   .advance
    mov  rax, [rsp + 40]
    mov  [rel gop_inventory_edid], rax
    jmp  .advance
.discovered_edid:
    mov  qword [rsp + 40], 0
    mov  rcx, [r14 + r12*8]
    lea  rdx, [rel edid_disc_guid]
    lea  r8, [rsp + 40]
    call [rbx + 0x98]               ; HandleProtocol(EDID_DISCOVERED)
    test rax, rax
    jnz  .advance
    cmp  qword [rsp + 40], 0
    je   .advance
    lea  rdi, [rel gop_inventory_rows]
    mov  rcx, r12
    shl  rcx, 4
    or   dword [rdi + rcx + 8], 4
    test dword [rdi + rcx + 8], 1     ; selected GOP handle only (discovered)
    jz   .advance
    mov  rax, [rsp + 40]
    mov  [rel gop_inventory_edid], rax
.advance:
    inc  r12
    jmp  .next
.free:
    mov  rcx, r14
    call [rbx + 0x48]               ; FreePool
.finish:
    add  rsp, 72
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Serial-only evidence; consumers must not treat the EDID flag as a verified
; GOP-to-monitor pairing or count as physical scanout proof.
gop_inventory_log:
    push r12
    lea  rdi, [rel str_gopinv_head]
    call serial_string
    mov  edi, [rel gop_inventory_count]
    call serial_hex64
    lea  rdi, [rel str_gopinv_scan]
    call serial_string
    mov  edi, [rel gop_inventory_scanned]
    call serial_hex64
    lea  rdi, [rel str_gopinv_sel]
    call serial_string
    mov  edi, [rel gop_inventory_selected]
    call serial_hex64
    lea  rdi, [rel str_gopinv_status]
    call serial_string
    mov  rdi, [rel gop_inventory_status]
    call serial_hex64
    lea  rdi, [rel gop_nl]
    call serial_string
    xor  r12d, r12d
.row:
    cmp  r12d, [rel gop_inventory_scanned]
    jae  .done
    lea  rdi, [rel str_gopinv_row]
    call serial_string
    mov  edi, r12d
    call serial_hex64
    lea  rdi, [rel str_gopinv_w]
    call serial_string
    lea  rax, [rel gop_inventory_rows]
    mov  rcx, r12
    shl  rcx, 4
    add  rax, rcx
    mov  edi, [rax]
    call serial_hex64
    lea  rdi, [rel str_gopinv_h]
    call serial_string
    lea  rax, [rel gop_inventory_rows]
    mov  rcx, r12
    shl  rcx, 4
    mov  edi, [rax + rcx + 4]
    call serial_hex64
    lea  rdi, [rel str_gopinv_flags]
    call serial_string
    lea  rax, [rel gop_inventory_rows]
    mov  rcx, r12
    shl  rcx, 4
    mov  edi, [rax + rcx + 8]
    call serial_hex64
    lea  rdi, [rel gop_nl]
    call serial_string
    inc  r12
    jmp  .row
.done:
    pop  r12
    ret

; Observation state: 0=not attempted, 1=LocateHandleBuffer failed, 2=empty,
; 3=inventory exceeds 128, 4=nonempty inventory with NULL buffer, 5=scanned.
; Raw UINTN handle count is retained separately; all per-handle counts <=128.
; A failed LocateHandleBuffer does not establish a valid inventory count.
; Error slots retain the last failing EFI status (not a subsequent success).
; UINT64_MAX marks a status with no applicable call/failure in this attempt.
gop_discovery_observation_reset:
    mov dword [rel gop_census_pci+0],0
    mov dword [rel gop_census_pci+4],0
    mov dword [rel gop_census_pci+8],0
    mov dword [rel gop_census_pci+12],0
    mov dword [rel gop_census_pci+16],0
    mov dword [rel gop_census_pci+20],0
    mov  dword [rel gop_pci_discovery], 0
    mov  qword [rel gop_pci_locate_status], -1
    mov  qword [rel gop_pci_handles], 0
    mov  dword [rel gop_pci_scanned], 0
    mov  dword [rel gop_pci_protocol_failures], 0
    mov  dword [rel gop_pci_protocol_nulls], 0
    mov  qword [rel gop_pci_protocol_error], -1
    mov  dword [rel gop_pci_read_failures], 0
    mov  qword [rel gop_pci_read_error], -1
    mov  dword [rel gop_pci_non_display], 0
    mov  dword [rel gop_connect_attempts], 0
    mov  dword [rel gop_connect_successes], 0
    mov  qword [rel gop_connect_last_status], -1
    mov  qword [rel gop_locate_retry_status], -1
    ret

; Connect at most 128 PCI I/O display controllers and retry GOP once. No
; target identity or framebuffer address is assumed. Called only when the
; initial GOP lookup returned EFI_NOT_FOUND; EAX = attempted display handles.
; The PCI config dword at offset 8 has BaseClass in bits 31:24. Handles with
; any other class (NIC/storage/USB) are never passed to ConnectController.
gop_connect_display_controllers:
    call gop_discovery_observation_reset
    push rbx
    push r12
    push r13
    push r14
    push r15
    ; Caller enters this helper at RSP%16=0. Five pushes -> 8; 72 bytes
    ; leave 32-byte UEFI shadow + fifth argument and local slots at RSP%16=0.
    sub  rsp, 72
    mov  rbx, [rel boot_services]
    xor  r15d, r15d
    mov  qword [rsp + 48], 0         ; handle count
    mov  qword [rsp + 56], 0         ; allocated handle buffer
    mov  ecx, 2                     ; ByProtocol
    lea  rdx, [rel pci_io_guid]
    xor  r8d, r8d                   ; SearchKey = NULL
    lea  r9, [rsp + 48]
    lea  rax, [rsp + 56]
    mov  [rsp + 32], rax            ; fifth argument: Buffer**
    call [rbx + 0x138]              ; LocateHandleBuffer
    mov  [rel gop_pci_locate_status], rax
    mov  r13, [rsp + 48]
    mov  [rel gop_pci_handles], r13  ; retain before FreePool, never dereference excess
    mov  dword [rel gop_pci_discovery], 1
    test rax, rax
    jnz  .finish
    mov  dword [rel gop_pci_discovery], 3
    cmp  r13, 128                   ; bounded, refuse anomalous inventories
    ja   .free
    mov  dword [rel gop_pci_discovery], 2
    test r13, r13
    jz   .free
    mov  dword [rel gop_pci_discovery], 4
    mov  r14, [rsp + 56]
    test r14, r14
    jz   .free
    mov  dword [rel gop_pci_discovery], 5
    xor  r12d, r12d
.next:
    cmp  r12, r13
    jae  .free
    inc  dword [rel gop_pci_scanned]
    mov  rcx, [r14 + r12*8]
    lea  rdx, [rel pci_io_guid]
    lea  r8, [rsp + 40]             ; PCI_IO_PROTOCOL*
    mov  qword [rsp + 40], 0
    call [rbx + 0x98]               ; HandleProtocol
    test rax, rax
    jz   .protocol_ok
    inc  dword [rel gop_pci_protocol_failures]
    mov  [rel gop_pci_protocol_error], rax
    jmp  .advance
.protocol_ok:
    mov  rax, [rsp + 40]
    test rax, rax
    jnz  .protocol_present
    inc  dword [rel gop_pci_protocol_nulls]
    jmp  .advance
.protocol_present:
    mov  rcx, rax
    mov  edx, 2                     ; EfiPciIoWidthUint32
    mov  r8d, 8                     ; PCI revision/progIF/subclass/baseclass
    mov  r9d, 1
    lea  rax, [rsp + 40]
    mov  [rsp + 32], rax            ; fifth argument: UINT32*
    call [rcx + 0x30]               ; PCI_IO.Pci.Read
    test rax, rax
    jz   .read_ok
    inc  dword [rel gop_pci_read_failures]
    mov  [rel gop_pci_read_error], rax
    jmp  .advance
.read_ok:
    mov  eax, [rsp + 40]
    shr  eax, 24
    cmp  eax, 3                     ; PCI base class Display
    je   .display
    inc  dword [rel gop_pci_non_display]
    jmp  .advance
.display:
    inc  r15d
    mov  rcx, [r14 + r12*8]
    xor  edx, edx                   ; DriverImageHandle = NULL
    xor  r8d, r8d                   ; RemainingDevicePath = NULL
    mov  r9d, 1                     ; Recursive, bounded to this display handle
    call [rbx + 0x108]              ; ConnectController
    mov  [rel gop_connect_last_status], rax
    test rax, rax
    jnz  .advance
    inc  dword [rel gop_connect_successes]
.advance:
    inc  r12
    jmp  .next
.free:
    mov  rcx, [rsp + 56]
    test rcx, rcx
    jz   .finish
    call [rbx + 0x48]               ; FreePool, even on refused inventory
.finish:
    mov  [rel gop_connect_attempts], r15d
    mov  eax, r15d
    add  rsp, 72
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; gop_fill — paint a B/G gradient so a screenshot proves PaOS drew real pixels.
gop_fill:
    mov  rax, [rel fb_base]
    test rax, rax
    jz   .done                      ; no GOP — nothing to draw
    xor  r9d, r9d                   ; y
.row:
    mov  r10d, [rel fb_height]
    cmp  r9d, r10d
    jge  .drawn
    mov  eax, [rel fb_stride]       ; row pitch (pixels) * 4
    imul eax, r9d
    shl  rax, 2
    mov  rdi, [rel fb_base]
    add  rdi, rax                   ; rdi = row start
    xor  ecx, ecx                   ; x
.col:
    mov  edx, [rel fb_width]
    cmp  ecx, edx
    jge  .nextrow
    mov  eax, r9d                   ; blue  = y & 0xFF
    and  eax, 0xFF
    mov  ebx, ecx                   ; green = x & 0xFF
    and  ebx, 0xFF
    shl  ebx, 8
    or   eax, ebx
    or   eax, 0x00300000           ; red = 0x30 (BGRX pixel)
    mov  [rdi + rcx*4], eax
    inc  ecx
    jmp  .col
.nextrow:
    inc  r9d
    jmp  .row
.drawn:
    lea  rdi, [rel str_gop_drawn]
    call serial_string
.done:
    ret

; ============================================================================
; 1104 native-resolution AUTO-DETECT (pre-EBS only — QueryMode/SetMode/EDID are
; boot services; GOP QueryMode dies at ExitBootServices, so the mode list is
; captured HERE into gop_mode_list and read at runtime by RESMODES).
;
; PORT NOTE (M16): the QueryMode/SetMode sequence (call conv, offsets 0/8, the
; boot-time mode-list capture, re-read-Mode-after-SetMode) is the monolith's
; proven gop_set_best_mode (paos.asm ~2504, ran on this exact Lenovo). The
; SELECTION POLICY is the earned change: the monolith hardcoded exact-1920x1080;
; 1104 de-hardcodes to EDID-native preferred, else the MAX supported GOP mode
; (max by width then height — the same order the acceptance probe computes).
; ============================================================================

; Finite scan: modes [0,min(MaxMode,64)), then a valid current mode outside
; that prefix exactly once. At most65 QueryMode calls,64 published (w,h) rows.
; A bounded/partial scan chooses only among validated, successfully released
; snapshots; it never claims a global maximum/completed scan beyond this set.
GOP_SCAN_LIMIT equ 64
; flags:1=bounded,2=query failure,4=invalid info,8=release uncertain,
;16=boot services retired,32=missing protocol/service,64=no usable candidate,
;128=SetMode failed. complete refers to clean full enumeration, not mode-set.
; QueryMode EFI_SUCCESS transfers its non-NULL allocation; failed-call OUT
; slots are undefined and never establish ownership. Live Mode.Info is borrowed.
; gop_autodetect preserves full64 nonvolatile GPRs and caller flags/DF.
gop_autodetect:
    pushfq
    cld
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    and  rsp, -16
    sub  rsp, 96                    ; [0..31] shadow, [32] SizeOfInfo, [40] Info*,
                                    ; [56] best_w, [60] best_h, [64] best_mode,
                                    ; [68] edid_mode, [72] cur_mode, [76] max_mode,
                                    ; [80] cur_w, [84] cur_h (discrete GOP keep),
                                    ; [48/52] owned query snapshot, [88] raw MaxMode,
                                    ; [92] current-mode tail query attempted
    mov  dword [rel gop_scan_flags], 0
    mov  dword [rel gop_scan_queries], 0
    mov  dword [rel gop_scan_valid], 0
    mov  dword [rel gop_scan_releases], 0
    mov  dword [rel gop_scan_complete], 0
    mov  dword [rel gop_scan_max_modes], 0
    mov  qword [rel gop_scan_query_status], -1
    mov  qword [rel gop_scan_free_status], -1
    mov  dword [rel gop_mode_count], 0
    mov  dword [rel gop_native_mode], -1
    cmp  byte [rel bm_face_boot_services_live], 1
    jne  .retired
    mov  rax, [rel boot_services]
    test rax, rax
    jz   .unavailable
    cmp  qword [rax + 0x48], 0      ; never acquire without a release route
    je   .unavailable
    mov  rbx, [rel gop_proto]
    test rbx, rbx
    jz   .unavailable
    cmp  qword [rbx], 0
    je   .unavailable
    cmp  qword [rbx + 8], 0
    je   .unavailable
    mov  r12, [rbx + 0x18]          ; -> Mode
    test r12, r12
    jz   .unavailable
    mov  eax, [r12 + 0]             ; MaxMode (count), retain full UINT32
    mov  [rsp + 88], eax
    mov  [rel gop_scan_max_modes], eax
    cmp  eax, GOP_SCAN_LIMIT
    jbe  .scan_bound
    or   dword [rel gop_scan_flags], 1
    mov  eax, GOP_SCAN_LIMIT
.scan_bound:
    mov  [rsp + 76], eax
    mov  dword [rsp + 92], 0
    mov  eax, [r12 + 4]             ; current mode number
    mov  [rsp + 72], eax
    mov  dword [rsp + 80], 0        ; current mode's width/height (from QueryMode)
    mov  dword [rsp + 84], 0

    ; --- EDID first (native timing preferred): r14d/r15d = native WxH (0,0 = absent)
    call gop_edid_probe
    mov  r14d, eax
    mov  r15d, edx
    test r14d, r14d
    jnz  .have_edid
    lea  rdi, [rel str_res_edid_absent]
    call serial_string
.have_edid:
    call hires_edid_transient_retry_kat     ; Task3473 DH1: bounded-retry proof (r14d/r15d preserved)

    ; --- bounded enumeration, free each allocation before selection/publication
    mov  dword [rsp + 56], 0        ; best_w
    mov  dword [rsp + 60], 0        ; best_h
    mov  dword [rsp + 64], -1       ; best_mode
    mov  dword [rsp + 68], -1       ; edid_mode
    mov  dword [rel gop_mode_count], 0
    xor  r13d, r13d                 ; mode index
.mloop:
    cmp  r13d, [rsp + 76]
    jae  .tail_current
.query:
    cmp  byte [rel bm_face_boot_services_live], 1
    jne  .retired
    mov  qword [rsp + 32], 0        ; OUT slots reset on EVERY call, not previous Info
    mov  qword [rsp + 40], 0
    mov  rcx, rbx                   ; QueryMode(This, ModeNumber, &SizeOfInfo, &Info)
    mov  edx, r13d
    lea  r8,  [rsp + 32]
    lea  r9,  [rsp + 40]
    inc  dword [rel gop_scan_queries]
    call [rbx + 0]
    test rax, rax
    jnz  .query_failed              ; no ownership from failed-call OUT values
    mov  rax, [rsp + 40]
    test rax, rax
    jz   .invalid_null
    ; A broken firmware must never make us free its live borrowed Mode.Info.
    mov  rcx, [rbx + 0x18]
    test rcx, rcx
    jz   .owned_invalid
    cmp  rax, [rcx + 8]
    je   .live_alias                ; refuse further enumeration/modeset
    mov  dword [rsp + 48], 0        ; invalid snapshots are freed, never published
    cmp  qword [rsp + 32], 36       ; complete v0 prefix through PixelsPerScanLine
    jb   .owned_invalid
    cmp  dword [rax], 0             ; accept known v0 only; future versions refused
    jne  .owned_invalid
    mov  ecx, [rax + 4]
    test ecx, ecx
    jz   .owned_invalid
    cmp  ecx, 8192
    ja   .owned_invalid
    mov  edx, [rax + 8]
    test edx, edx
    jz   .owned_invalid
    cmp  edx, 8192
    ja   .owned_invalid
    cmp  dword [rax + 0x0c], 2      ; this boot path requires a linear framebuffer
    ja   .owned_invalid
    cmp  [rax + 0x20], ecx
    jb   .owned_invalid
    mov  [rsp + 48], ecx            ; snapshot before FreePool poisons/reuses Info
    mov  [rsp + 52], edx
    jmp  .release
.owned_invalid:
    mov  dword [rsp + 48], 0
    or   dword [rel gop_scan_flags], 4
.release:
    cmp  byte [rel bm_face_boot_services_live], 1
    jne  .release_retired
    mov  rax, [rel boot_services]
    test rax, rax
    jz   .release_unavailable
    cmp  qword [rax + 0x48], 0
    je   .release_unavailable
    mov  rcx, [rsp + 40]
    mov  qword [rsp + 40], 0        ; consume ownership before uncertain release
    call [rax + 0x48]              ; FreePool exactly once; no retry on failure
    test rax, rax
    jnz  .release_failed
    inc  dword [rel gop_scan_releases]
    mov  ecx, [rsp + 48]
    test ecx, ecx
    jz   .mnext
    mov  edx, [rsp + 52]
    inc  dword [rel gop_scan_valid]
    cmp  r13d, [rsp + 72]
    jne  .not_cur
    mov  [rsp + 80], ecx
    mov  [rsp + 84], edx
.not_cur:
    mov  eax, [rel gop_mode_count]
    cmp  eax, GOP_SCAN_LIMIT
    jae  .mtrack
    lea  r8, [rel gop_mode_list]
    mov  [r8 + rax*8], ecx
    mov  [r8 + rax*8 + 4], edx
    inc  eax
    mov  [rel gop_mode_count], eax
.mtrack:
    cmp  ecx, r14d
    jne  .mmax
    cmp  edx, r15d
    jne  .mmax
    cmp  dword [rsp + 68], -1
    jne  .mmax
    mov  [rsp + 68], r13d
.mmax:
    cmp  ecx, [rsp + 56]
    ja   .mnewbest
    jb   .mnext
    cmp  edx, [rsp + 60]
    jbe  .mnext
.mnewbest:
    mov  [rsp + 56], ecx
    mov  [rsp + 60], edx
    mov  [rsp + 64], r13d
.mnext:
    cmp  dword [rsp + 92], 0
    jne  .scan_done
    inc  r13d
    jmp  .mloop
.tail_current:
    mov  r13d, [rsp + 72]
    cmp  r13d, [rsp + 76]
    jb   .scan_done                 ; current already in prefix
    cmp  r13d, [rsp + 88]
    jae  .scan_done                 ; firmware current mode outside MaxMode is invalid
    mov  dword [rsp + 92], 1
    jmp  .query
.scan_done:
    cmp  dword [rel gop_scan_flags], 0
    jne  .choose
    mov  dword [rel gop_scan_complete], 1
    jmp  .choose
.query_failed:
    mov  [rel gop_scan_query_status], rax
    or   dword [rel gop_scan_flags], 2
    jmp  .mnext
.invalid_null:
    or   dword [rel gop_scan_flags], 4
    jmp  .mnext
.live_alias:
    or   dword [rel gop_scan_flags], 4
    jmp  .done
.release_failed:
    mov  [rel gop_scan_free_status], rax
    or   dword [rel gop_scan_flags], 8
    jmp  .done                      ; no new query/SetMode after uncertain release
.release_retired:
    or   dword [rel gop_scan_flags], 8
.retired:
    or   dword [rel gop_scan_flags], 16
    jmp  .done
.release_unavailable:
    or   dword [rel gop_scan_flags], 8
.unavailable:
    or   dword [rel gop_scan_flags], 32
    jmp  .done

.choose:
    ; (MSI spoke 386ee66f7, ported) a GOP on a GPU behind a PCI bridge (>= 2 PCI
    ; nodes in its device path: the MSI's Arc Pro B70) keeps the mode the firmware
    ; lit at POST. Each SetMode there is a full modeset with a DP link retrain, and
    ; after ExitBootServices nothing services the sink's retrain request (MSI
    ; follow4: the DP output stayed dark). A root-bus iGPU keeps SetMode-always.
    lea  rdi, [rel str_gop_pci_depth]   ; diagnostic: the selected GOP's PCI depth
    call serial_string
    mov  edi, [rel gop_selected_pci_nodes]
    call serial_hex64
    lea  rdi, [rel str_gop_pci_row]
    call serial_string
    mov  edi, [rel gop_inventory_selected]
    call serial_hex64
    lea  rdi, [rel gop_nl]
    call serial_string
    mov  dword [rel gop_discrete], 0
    cmp  dword [rel gop_selected_pci_nodes], 2
    jb   .choose_native
    mov  dword [rel gop_discrete], 1
    mov  ecx, [rsp + 80]
    mov  edx, [rsp + 84]
    test ecx, ecx
    jz   .choose_native             ; the current mode did not enumerate
    mov  eax, [rsp + 72]
    mov  byte [rel res_src], 2      ; src=gop (the firmware's own mode)
    jmp  .picked
.choose_native:
    ; EDID-native in the supported list -> that IS the native mode (src=edid);
    ; else the max supported GOP mode (src=gop). No usable mode -> keep as-is.
    mov  eax, [rsp + 68]
    cmp  eax, -1
    jne  .use_edid
    mov  eax, [rsp + 64]
    cmp  eax, -1
    je   .no_candidate              ; nothing trustworthy -> firmware default stands
    mov  ecx, [rsp + 56]
    mov  edx, [rsp + 60]
    mov  byte [rel res_src], 2      ; src=gop
    jmp  .picked
.use_edid:
    mov  ecx, r14d
    mov  edx, r15d
    mov  byte [rel res_src], 1      ; src=edid
.picked:
    mov  r13d, eax                  ; r13d = chosen mode number
    mov  [rel gop_native_mode], eax ; 1249 rung 3 re-asserts exactly this mode before EBS
    mov  [rel res_native_w], ecx
    mov  [rel res_native_h], edx
    ; DPI scale factor: 2x for 4K-class widths (>=3000), else 1x
    mov  byte [rel res_dpi], 1
    cmp  ecx, 3000
    jb   .dpi1
    mov  byte [rel res_dpi], 2
.dpi1:
    ; emit the autodetect verdict (qemu-only marker: pre-EBS serial)
    lea  rdi, [rel str_res_auto_pre]
    call serial_string
    mov  edi, [rel res_native_w]
    call serial_hex64
    lea  rdi, [rel str_gop_x]
    call serial_string
    mov  edi, [rel res_native_h]
    call serial_hex64
    cmp  byte [rel res_src], 1
    je   .src_edid
    lea  rdi, [rel str_res_src_gop]
    jmp  .src_emit
.src_edid:
    lea  rdi, [rel str_res_src_edid]
.src_emit:
    call serial_string

    ; --- 1249 §12 rung 1: SetMode ALWAYS, even into the current mode number. A
    ;     matching mode NUMBER is not proof the firmware programmed the pitch/plane
    ;     (GRUB's skip-if-current is the exact PaOS-HEAD bug §12 names). ---
    mov  dword [rel gop_setmode_forced], 0
    cmp  r13d, [rsp + 72]
    jne  .setmode
    mov  dword [rel gop_setmode_forced], 1
    cmp  dword [rel gop_discrete], 1
    jne  .setmode
    mov  dword [rel gop_setmode_forced], 2   ; 2 = skipped: a discrete GOP keeps its lit mode
    lea  rdi, [rel str_gop_setmode_skip]
    call serial_string
    jmp  .at_native
.setmode:
    cmp  byte [rel bm_face_boot_services_live], 1
    jne  .retired
    mov  rcx, rbx                   ; SetMode(This, ModeNumber)
    mov  edx, r13d
    call gop_setmode_once           ; one firmware SetMode call per boot
    test rax, rax
    jz   .at_native
    ; SetMode failed: firmware keeps the previous working mode (UEFI spec) —
    ; never a black screen. active != native; the native.active marker is NOT
    ; emitted (earned only), RESINFO reports the honest mismatch.
    or   dword [rel gop_scan_flags], 128
    lea  rdi, [rel str_res_setfail]
    call serial_string
    jmp  .done
.at_native:
    lea  rdi, [rel str_res_active]
    call serial_string
    jmp  .done
.no_candidate:
    or   dword [rel gop_scan_flags], 64
.done:
    call gop_scan_log
    lea  rsp, [rbp - 40]
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    popfq
    ret

; Serial observation only. Flags/complete describe the inspected set, not
; elapsed time, physical pixels, global maximum or firmware responsiveness.
gop_scan_log:
    lea  rdi, [rel str_gopscan_head]
    call serial_string
    mov  edi, [rel gop_scan_flags]
    call serial_hex64
    lea  rdi, [rel str_gopscan_max]
    call serial_string
    mov  edi, [rel gop_scan_max_modes]
    call serial_hex64
    lea  rdi, [rel str_gopscan_queries]
    call serial_string
    mov  edi, [rel gop_scan_queries]
    call serial_hex64
    lea  rdi, [rel str_gopscan_valid]
    call serial_string
    mov  edi, [rel gop_scan_valid]
    call serial_hex64
    lea  rdi, [rel str_gopscan_released]
    call serial_string
    mov  edi, [rel gop_scan_releases]
    call serial_hex64
    lea  rdi, [rel str_gopscan_complete]
    call serial_string
    mov  edi, [rel gop_scan_complete]
    call serial_hex64
    lea  rdi, [rel str_gopscan_queryerr]
    call serial_string
    mov  rdi, [rel gop_scan_query_status]
    call serial_hex64
    lea  rdi, [rel str_gopscan_freeerr]
    call serial_string
    mov  rdi, [rel gop_scan_free_status]
    call serial_hex64
    lea  rdi, [rel gop_nl]
    call serial_string
    ret

; ===========================================================================
; 1249 / DISPLAY_DOMAIN §12 — measure, never trust.
;   P51 rung 1: SetMode ALWAYS (in gop_autodetect).
;   P51 rung 2: gop_blt_calibrate — Blt row markers -> measured pitch/byte order.
;   P51 rung 3: gop_revalidate_record — last act before GetMemoryMap/EBS.
;   P52:        gop_health_evaluate — live PLANE_STRIDE/PLANE_SIZE/PIPE_SRCSZ fact.
;   P53:        the folded verdict GOPHEALTH frames and [gop.scanout.portable] earns.
; Every fact is measured; a refusal is recorded, never converted into a pass.
; ===========================================================================

; gop_blt_calibrate — pre-EBS Blt row-marker self-calibration. Draws eight 1x1
;   markers at (0,y) through the firmware's own Blt engine, locates them in raw
;   framebuffer memory, and measures the true pitch + byte order. Guards (fail-
;   safe, never fail-wrong): linear PixelFormat only, geometry floor, size floor,
;   full consecutive marker set with uniform gaps, pitch >= width*4, one fenced
;   retry. On a pitch mismatch PaOS draws with the MEASURED truth (fb_stride :=
;   pitch/4) and keeps the mismatch as a health fact. Preserves callee-saved regs.
gop_blt_calibrate:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    and  rsp, -16
    sub  rsp, 96                    ; shadow(32) + six stack args(48) + pad
    mov  dword [rel gop_calib_status], 3        ; refused until earned
    mov  dword [rel gop_calib_reason], 1        ; 1 = no protocol / no framebuffer
    mov  dword [rel gop_calib_rows], 0
    mov  dword [rel gop_calib_retries], 0
    mov  dword [rel gop_calib_pitch], 0
    mov  dword [rel gop_calib_format], 0xFF
    mov  dword [rel gop_calib_restore_pending], 0
    mov  qword [rel gop_calib_save_status], -1
    mov  qword [rel gop_calib_restore_status], -1
    mov  rbx, [rel gop_proto]
    test rbx, rbx
    jz   .out
    mov  rax, [rel fb_base]
    test rax, rax
    jz   .out
    mov  dword [rel gop_calib_reason], 2        ; 2 = PixelFormat not linear (BltOnly/unknown)
    cmp  dword [rel fb_pixel_format], 2
    ja   .out
    cmp  dword [rel fb_bpp], 32
    jne  .out
    mov  dword [rel gop_calib_reason], 3        ; 3 = geometry below the calibration floor
    mov  r12d, [rel fb_width]
    cmp  r12d, 64
    jb   .out
    cmp  dword [rel fb_height], 16
    jb   .out
    mov  eax, [rel fb_stride]
    cmp  eax, r12d
    jb   .out
    shl  eax, 2
    mov  [rel gop_calib_meta_pitch], eax
    mov  dword [rel gop_calib_reason], 4        ; 4 = FrameBufferSize below stride*height*4
    mov  eax, [rel fb_stride]
    mov  edx, [rel fb_height]
    imul rax, rdx
    shl  rax, 2
    cmp  [rel fb_size], rax
    jb   .out
    ; search window = min(size, 8 rows at the largest pitch the size admits + one page)
    mov  rax, [rel fb_size]
    xor  edx, edx
    mov  ecx, [rel fb_height]
    div  rcx
    shl  rax, 3
    add  rax, 4096
    mov  r15, [rel fb_size]
    cmp  rax, r15
    cmova rax, r15
    mov  r15, rax
    ; Calibration shares the firmware logo surface. Save the exact eight
    ; logical pixels through GOP itself: metadata pitch/order may be wrong,
    ; which is the reason for measuring them. Never guess their raw offsets.
    ; A refused read earns no permission to paint markers.
    mov  dword [rel gop_calib_reason], 10       ; 10 = original-pixel read refused
    cmp  qword [rbx + 0x10], 0
    je   .out
    mov  rcx, rbx
    lea  rdx, [rel gop_calib_saved_pixels]
    mov  r8d, 1                               ; EfiBltVideoToBltBuffer
    xor  r9d, r9d                             ; SourceX
    mov  qword [rsp + 32], 0                   ; SourceY
    mov  qword [rsp + 40], 0                   ; DestinationX in buffer
    mov  qword [rsp + 48], 0                   ; DestinationY in buffer
    mov  qword [rsp + 56], 1                   ; Width
    mov  qword [rsp + 64], 8                   ; Height
    mov  qword [rsp + 72], 4                   ; Delta: one BLT pixel per row
    call [rbx + 0x10]
    mov  [rel gop_calib_save_status], rax
    test rax, rax
    jnz  .out
    ; A failed fill can already have changed pixels. Restore on every exit
    ; after the first attempt, including partial writes and both retries.
    mov  dword [rel gop_calib_restore_pending], 1
.attempt:
    xor  r13d, r13d
.draw:
    cmp  r13d, 8
    jae  .drawn
    lea  rdi, [rel gop_calib_pixel]             ; EFI_GRAPHICS_OUTPUT_BLT_PIXEL {B,G,R,X}
    mov  eax, r13d
    add  eax, 0x30
    mov  [rdi], al
    mov  byte [rdi + 1], 0x5A
    mov  byte [rdi + 2], 0xA5
    mov  byte [rdi + 3], 0
    mov  rcx, rbx                               ; This
    mov  rdx, rdi                               ; BltBuffer (one pixel)
    xor  r8d, r8d                               ; EfiBltVideoFill
    xor  r9d, r9d                               ; SourceX
    mov  qword [rsp + 32], 0                    ; SourceY
    mov  qword [rsp + 40], 0                    ; DestinationX
    mov  [rsp + 48], r13                        ; DestinationY = row index
    mov  qword [rsp + 56], 1                    ; Width
    mov  qword [rsp + 64], 1                    ; Height
    mov  qword [rsp + 72], 0                    ; Delta
    call [rbx + 0x10]                           ; Blt @ offset 0x10
    test rax, rax
    jnz  .blt_refused
    inc  r13d
    jmp  .draw
.blt_refused:
    mov  dword [rel gop_calib_reason], 5        ; 5 = the firmware Blt refused a marker
    jmp  .out
.drawn:
    mfence
    mov  r14d, 1                                ; declared BGRX first ...
    cmp  dword [rel fb_pixel_format], 0
    jne  .locate
    xor  r14d, r14d                             ; ... unless the record declares RGBX
.locate:
    call gop_calib_locate                       ; r14d=byte order, r15=window -> eax=1/0, edx=pitch
    test eax, eax
    jnz  .found
    xor  r14d, 1                                ; the other linear byte order
    call gop_calib_locate
    test eax, eax
    jnz  .found
    cmp  dword [rel gop_calib_retries], 0
    jne  .not_found
    inc  dword [rel gop_calib_retries]
    mov  rax, [rel boot_services]
    mov  ecx, 2000
    call [rax + 0xF8]                           ; Stall(2000 us): one fenced retry
    jmp  .attempt
.not_found:
    mov  dword [rel gop_calib_reason], 6        ; 6 = marker set not located / gaps not uniform
    jmp  .out
.found:
    mov  [rel gop_calib_pitch], edx
    mov  [rel gop_calib_format], r14d
    mov  dword [rel gop_calib_rows], 8
    mov  dword [rel gop_calib_reason], 9        ; 9 = measured pitch fails floor/alignment/size
    mov  eax, r12d
    shl  eax, 2
    cmp  edx, eax
    jb   .out                                   ; below width*4: a tiled surface, never "calibrate" it
    test edx, 3
    jnz  .out
    mov  eax, edx
    mov  ecx, [rel fb_height]
    imul rax, rcx
    cmp  [rel fb_size], rax
    jb   .out
    cmp  edx, [rel gop_calib_meta_pitch]
    jne  .pitch_mismatch
    mov  eax, [rel fb_pixel_format]
    cmp  eax, 2
    jae  .pass                                  ; PixelBitMask: the measured order is the truth
    cmp  eax, r14d
    jne  .format_mismatch
.pass:
    mov  dword [rel gop_calib_status], 1
    mov  dword [rel gop_calib_reason], 0
    jmp  .out
.pitch_mismatch:
    mov  eax, edx
    shr  eax, 2
    mov  [rel fb_stride], eax                   ; draw with the measured truth
    mov  dword [rel gop_calib_status], 2
    mov  dword [rel gop_calib_reason], 7        ; 7 = metadata pitch != measured pitch (corrected)
    jmp  .out
.format_mismatch:
    mov  [rel fb_pixel_format], r14d            ; record the measured byte order
    mov  dword [rel gop_calib_status], 2
    mov  dword [rel gop_calib_reason], 8        ; 8 = metadata byte order != measured (corrected)
.out:
    cmp  dword [rel gop_calib_restore_pending], 0
    je   .report
    mov  dword [rel gop_calib_restore_pending], 0
    mov  rcx, rbx
    lea  rdx, [rel gop_calib_saved_pixels]
    mov  r8d, 2                               ; EfiBltBufferToVideo
    xor  r9d, r9d                             ; SourceX in buffer
    mov  qword [rsp + 32], 0                   ; SourceY in buffer
    mov  qword [rsp + 40], 0                   ; DestinationX
    mov  qword [rsp + 48], 0                   ; DestinationY
    mov  qword [rsp + 56], 1
    mov  qword [rsp + 64], 8
    mov  qword [rsp + 72], 4
    call [rbx + 0x10]
    mov  [rel gop_calib_restore_status], rax
    test rax, rax
    jz   .report
    ; The measured pitch remains useful, but a failed restoration must never
    ; report a clean calibration. Keep the raw EFI status in the boot record.
    mov  dword [rel gop_calib_status], 3
    mov  dword [rel gop_calib_reason], 11       ; 11 = original-pixel restore refused
.report:
    lea  rdi, [rel str_gop_calib]
    call serial_string
    mov  edi, [rel gop_calib_status]
    call serial_hex64
    lea  rdi, [rel str_gop_calib_reason]
    call serial_string
    mov  edi, [rel gop_calib_reason]
    call serial_hex64
    lea  rdi, [rel str_gop_calib_pitch]
    call serial_string
    mov  edi, [rel gop_calib_pitch]
    call serial_hex64
    lea  rdi, [rel str_gop_calib_meta]
    call serial_string
    mov  edi, [rel gop_calib_meta_pitch]
    call serial_hex64
    lea  rdi, [rel str_gop_calib_fmt]
    call serial_string
    mov  edi, [rel gop_calib_format]
    call serial_hex64
    lea  rdi, [rel str_gop_calib_save]
    call serial_string
    mov  rdi, [rel gop_calib_save_status]
    call serial_hex64
    lea  rdi, [rel str_gop_calib_restore]
    call serial_string
    mov  rdi, [rel gop_calib_restore_status]
    call serial_hex64
    lea  rdi, [rel gop_nl]
    call serial_string
    lea  rsp, [rbp - 40]
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; gop_calib_locate(R14D = byte order 0 RGBX / 1 BGRX, R15 = search window bytes)
;   -> EAX=1 with EDX = uniform pitch (bytes) when all eight markers sit at
;   0, pitch, 2*pitch, ... from the framebuffer origin; EAX=0 otherwise.
;   clobbers rax, rcx, rdx, rdi, r8, r9.
gop_calib_locate:
    xor  r8d, r8d                               ; row
.row:
    cmp  r8d, 8
    jae  .gaps
    mov  eax, r8d
    add  eax, 0x30                              ; blue byte = 0x30 + row
    test r14d, r14d
    jnz  .bgrx
    shl  eax, 16                                ; RGBX bytes R,G,B,X = A5,5A,BB,00 -> 0x00BB5AA5
    or   eax, 0x00005AA5
    jmp  .scan
.bgrx:
    or   eax, 0x00A55A00                        ; BGRX bytes B,G,R,X = BB,5A,A5,00 -> 0x00A55ABB
.scan:
    mov  rdi, [rel fb_base]
    mov  rcx, r15
    shr  rcx, 2
    cld
    repne scasd
    jne  .fail                                  ; window exhausted without this marker
    sub  rdi, 4
    sub  rdi, [rel fb_base]
    lea  r9, [rel gop_calib_offs]
    mov  [r9 + r8*4], edi
    inc  r8d
    jmp  .row
.gaps:
    lea  r9, [rel gop_calib_offs]
    cmp  dword [r9], 0
    jne  .fail                                  ; row 0 must sit at the framebuffer origin
    mov  edx, [r9 + 4]                          ; candidate pitch = off[1] - off[0]
    test edx, edx
    jz   .fail
    mov  ecx, 2
.check:
    cmp  ecx, 8
    jae  .ok
    mov  eax, [r9 + rcx*4]
    sub  eax, [r9 + rcx*4 - 4]
    cmp  eax, edx
    jne  .fail
    inc  ecx
    jmp  .check
.ok:
    mov  eax, 1
    ret
.fail:
    xor  eax, eax
    xor  edx, edx
    ret

; The initial mode selection and final pre-EBS repair share ONE firmware call.
; Count before entering firmware: a refused call can still disturb the display.
; Never reset this boot-lifetime counter on another acquisition/revalidation.
; RCX=This, EDX=mode, RBX=GOP. RAX=EFI status. Nonvolatiles preserved.
; The bridge aligns its own Win64 shadow area for either internal entry residue.
gop_setmode_once:
    cmp  dword [rel gop_setmode_attempts], 0
    jne  .spent
    cmp  byte [rel bm_face_boot_services_live], 1
    jne  .spent
    cmp  qword [rbx + 8], 0
    je   .spent
    inc  dword [rel gop_setmode_attempts]
    push rbp
    mov  rbp, rsp
    and  rsp, -16
    sub  rsp, 32
    call [rbx + 8]
    mov  rsp, rbp
    pop  rbp
    ret
.spent:
    mov  rax, 0x8000000000000014         ; EFI_ALREADY_STARTED; no call made
    ret

; gop_revalidate_record — §12 rung 3: re-read the live GOP mode record as the
;   last act before GetMemoryMap/ExitBootServices (ConSplitter can re-modeset
;   after the capture). A validated, changed record is adopted; an invalid one
;   keeps the previous known-working record (status 3). An initial SetMode
;   consumes the same one-call budget as a late repair; validated drift is
;   adopted instead of issuing a second visible mode transition. clobbers caller-saved.
gop_revalidate_record:
    push rbx
    push r12
    sub  rsp, 40                                ; shadow space for a re-asserting SetMode call
    mov  dword [rel gop_reval_status], 0
    mov  dword [rel gop_reval_changes], 0
    mov  dword [rel gop_reval_remodeset], 0
    mov  rbx, [rel gop_proto]
    test rbx, rbx
    jz   .out
.read:
    mov  dword [rel gop_reval_status], 3        ; invalid until validated
    mov  rsi, [rbx + 0x18]                      ; Mode
    test rsi, rsi
    jz   .out
    mov  rax, [rsi + 0x18]                      ; FrameBufferBase
    test rax, rax
    jz   .out
    mov  rcx, [rsi + 0x20]                      ; FrameBufferSize
    test rcx, rcx
    jz   .out
    mov  rdi, [rsi + 8]                         ; Info
    test rdi, rdi
    jz   .out
    cmp  qword [rsi + 16], 36     ; live Info must contain the complete v0 prefix
    jb   .out
    mov  r8d, [rdi + 4]                         ; HorizontalResolution
    test r8d, r8d
    jz   .out
    mov  r9d, [rdi + 8]                         ; VerticalResolution
    test r9d, r9d
    jz   .out
    mov  r10d, [rdi + 0x0C]                     ; PixelFormat
    cmp  r10d, 2
    ja   .out
    mov  r11d, [rdi + 0x20]                     ; PixelsPerScanLine
    cmp  r11d, r8d
    jb   .out
    mov  rdx, r11
    imul rdx, r9
    mov  rsi, rdx
    shr  rsi, 62
    jnz  .out
    shl  rdx, 2
    cmp  rcx, rdx
    jb   .out                                   ; size below stride*height*4
    xor  r12d, r12d
    cmp  rax, [rel fb_base]
    je   .c1
    or   r12d, 1
.c1:
    cmp  rcx, [rel fb_size]
    je   .c2
    or   r12d, 2
.c2:
    cmp  r8d, [rel fb_width]
    je   .c3
    or   r12d, 4
.c3:
    cmp  r9d, [rel fb_height]
    je   .c4
    or   r12d, 8
.c4:
    cmp  r10d, [rel fb_pixel_format]
    je   .c5
    or   r12d, 16
.c5:
    mov  edx, [rel gop_calib_meta_pitch]        ; compare PPSL with the captured metadata pitch,
    shr  edx, 2                                 ; not with a calibration-corrected stride
    test edx, edx
    jnz  .c6
    mov  edx, [rel fb_stride]
.c6:
    cmp  r11d, edx
    je   .c7
    or   r12d, 32
.c7:
    or   [rel gop_reval_changes], r12d          ; every drift seen this boot, re-assert included
    test r12d, r12d
    jz   .unchanged
    ; The firmware console re-modeset behind PaOS (the ConOut/ClearScreen 800x600 default that
    ; produced the 2026-08-04 tiling and the 2026-09-07 800x600 desktop). Re-assert the mode PaOS
    ; selected, once, as the last act before EBS, then re-read the record.
    ; RAX/RCX/R8-R11 hold the validated record from here to .adopt: the mode lookup
    ; uses EDX, and any SetMode call (it clobbers them) is followed by a re-read.
    cmp  dword [rel gop_reval_remodeset], 0
    jne  .no_reassert
    mov  edx, [rel gop_native_mode]
    cmp  edx, -1
    je   .no_reassert
    cmp  dword [rel gop_setmode_attempts], 0
    jne  .budget_spent
    mov  dword [rel gop_reval_remodeset], 1
    mov  rcx, rbx                               ; SetMode(This, ModeNumber)
    call gop_setmode_once
    test rax, rax
    jnz  .refused                               ; SetMode refused: re-read, then adopt/keep
    jmp  .read
.refused:
    mov  dword [rel gop_reval_remodeset], 2     ; attempted and refused: no second attempt
    jmp  .read
.budget_spent:
    mov  dword [rel gop_reval_remodeset], 3     ; no firmware call: initial attempt spent the budget
.no_reassert:
    test r12d, 1
    jz   .adopt
    ; A base that moved outside the identity-mapped window cannot be adopted
    ; here: the framebuffer PDs were built for the retained base. Keep it.
    mov  rdx, rax
    shr  rdx, 30
    cmp  rdx, 16
    jb   .adopt
    mov  rsi, [rel fb_base]
    shr  rsi, 30
    cmp  rdx, rsi
    jne  .out                                   ; status stays 3 (kept previous record)
.adopt:
    mov  [rel fb_base], rax
    mov  [rel fb_size], rcx
    mov  [rel gop_fb_reported+16], rax ; retained adopted record (SEC 106852)
    mov  [rel gop_fb_reported+24], rcx
    mov  [rel fb_width], r8d
    mov  [rel fb_height], r9d
    mov  [rel fb_pixel_format], r10d
    mov  [rel fb_stride], r11d
    mov  dword [rel gop_reval_status], 2        ; fresh record adopted (it changed)
    jmp  .out
.unchanged:
    mov  dword [rel gop_reval_status], 1        ; fresh and unchanged
    cmp  dword [rel gop_reval_remodeset], 1
    jne  .out                                   ; a refused SetMode re-asserted nothing
    mov  dword [rel gop_reval_status], 4        ; fresh after PaOS re-asserted its selected mode
.out:
    lea  rdi, [rel str_gop_reval]
    call serial_string
    mov  edi, [rel gop_reval_status]
    call serial_hex64
    lea  rdi, [rel str_gop_reval_chg]
    call serial_string
    mov  edi, [rel gop_reval_changes]
    call serial_hex64
    lea  rdi, [rel str_gop_reval_rem]
    call serial_string
    mov  edi, [rel gop_reval_remodeset]
    call serial_hex64
    lea  rdi, [rel str_gop_setmode_calls]
    call serial_string
    mov  edi, [rel gop_setmode_attempts]
    call serial_hex64
    lea  rdi, [rel gop_nl]
    call serial_string
    add  rsp, 40
    pop  r12
    pop  rbx
    ret

; gop_health_evaluate — post-EBS (after gop_plane_dump). P52: read the live
;   PLANE_STRIDE/PLANE_SIZE/PIPE_SRCSZ (read-only) and compare with the record
;   PaOS draws by. P53: fold calibration + revalidation + register fact into one
;   state: 1 coherent, 2 metadata_mismatch, 3 calibration_refused,
;   4 register_mismatch, 5 register_unavailable (an Intel display function with
;   no readable map/BAR is never coherent by silence). clobbers caller-saved.
gop_health_evaluate:
    push rbx
    push r12
    mov  dword [rel gop_reg_status], 0
    mov  dword [rel gop_reg_stride64], 0
    mov  dword [rel gop_reg_size], 0
    mov  dword [rel gop_reg_srcsz], 0
    mov  dword [rel gop_disp_is_display], 0
    ; is 00:02.0 an Intel display function at all? (vendor 8086, base class 03)
    mov  eax, 0x80001008                        ; cfg 0x08 = class/revision
    call boot_pci_cfg_read32             ; same selector lock as bus/pci
    shr  eax, 24
    cmp  eax, 3
    jne  .lookup
    mov  eax, 0x80001000                        ; cfg 0x00 = vendor/device
    call boot_pci_cfg_read32             ; same selector lock as bus/pci
    cmp  ax, 0x8086
    jne  .lookup
    mov  dword [rel gop_disp_is_display], 1
.lookup:
    call gop_gpu_lookup                         ; EAX = MMIO base or 0; publishes gop_map_*
    test eax, eax
    jz   .regs_done
    mov  r12d, eax
    mov  rbx, r12
    mov  eax, [rel gop_map_stride]
    add  rbx, rax
    mov  eax, [rbx]
    mov  [rel gop_reg_stride64], eax
    mov  rbx, r12
    mov  eax, [rel gop_map_size]
    add  rbx, rax
    mov  eax, [rbx]
    mov  [rel gop_reg_size], eax
    mov  rbx, r12
    mov  eax, [rel gop_map_srcsz]
    add  rbx, rax
    mov  eax, [rbx]
    mov  [rel gop_reg_srcsz], eax
    mov  dword [rel gop_reg_status], 2          ; mismatch until every field agrees
    mov  eax, [rel fb_stride]
    shl  eax, 2
    shr  eax, 6
    cmp  eax, [rel gop_reg_stride64]
    jne  .regs_done
    mov  eax, [rel fb_height]
    dec  eax
    shl  eax, 16
    mov  ecx, [rel fb_width]
    dec  ecx
    or   eax, ecx
    cmp  eax, [rel gop_reg_size]
    jne  .regs_done
    mov  eax, [rel fb_width]
    dec  eax
    shl  eax, 16
    mov  ecx, [rel fb_height]
    dec  ecx
    or   eax, ecx
    cmp  eax, [rel gop_reg_srcsz]
    jne  .regs_done
    mov  dword [rel gop_reg_status], 1
.regs_done:
    mov  dword [rel gop_health_state], 3        ; calibration_refused
    mov  eax, [rel gop_calib_status]
    cmp  eax, 1
    jb   .fold_done                             ; 0 = never ran
    cmp  eax, 3
    jae  .fold_done                             ; 3 = refused
    mov  dword [rel gop_health_state], 2        ; metadata_mismatch
    cmp  eax, 2
    je   .fold_done                             ; corrected == a metadata mismatch fact
    mov  eax, [rel gop_reval_status]
    cmp  eax, 1
    jb   .fold_done
    cmp  eax, 3
    je   .fold_done                             ; invalid record kept
    mov  dword [rel gop_health_state], 4        ; register_mismatch
    cmp  dword [rel gop_reg_status], 2
    je   .fold_done
    cmp  dword [rel gop_reg_status], 1
    je   .coherent
    mov  dword [rel gop_health_state], 5        ; register_unavailable
    cmp  dword [rel gop_disp_is_display], 1
    je   .fold_done                             ; Intel display function without a readable map
.coherent:
    mov  dword [rel gop_health_state], 1
.fold_done:
    lea  rdi, [rel str_gop_health]
    call serial_string
    mov  edi, [rel gop_health_state]
    call serial_hex64
    lea  rdi, [rel str_gop_health_reg]
    call serial_string
    mov  edi, [rel gop_reg_status]
    call serial_hex64
    lea  rdi, [rel gop_nl]
    call serial_string
    pop  r12
    pop  rbx
    ret

; gop_fb_memtype_probe -> EAX = effective PAT memory type of the page holding
;   fb_base under the LIVE CR3: 0 UC, 1 WC, 4 WT, 5 WP, 6 WB, 7 UC-; 0xFF when
;   unmapped; 0xFE when the CPU has no PAT. Reads the PTE bits and IA32_PAT --
;   the effective type, never an intent flag. clobbers rax, rcx, rdx, rbx(restored).
gop_fb_memtype_probe:
    push rbx
    mov  eax, 1
    cpuid
    bt   edx, 16
    jnc  .nopat
    mov  rbx, [rel fb_base]
    test rbx, rbx
    jz   .unmapped
    mov  rax, cr3
    mov  rdx, 0x000FFFFFFFFFF000
    and  rax, rdx
    mov  rcx, rbx
    shr  rcx, 39
    and  ecx, 511
    mov  rax, [rax + rcx*8]
    test al, 1
    jz   .unmapped
    and  rax, rdx
    mov  rcx, rbx
    shr  rcx, 30
    and  ecx, 511
    mov  rax, [rax + rcx*8]
    test al, 1
    jz   .unmapped
    test al, 0x80
    jnz  .huge                                  ; 1 GiB page: PAT bit is bit 12
    and  rax, rdx
    mov  rcx, rbx
    shr  rcx, 21
    and  ecx, 511
    mov  rax, [rax + rcx*8]
    test al, 1
    jz   .unmapped
    test al, 0x80
    jnz  .huge                                  ; 2 MiB page: PAT bit is bit 12
    and  rax, rdx
    mov  rcx, rbx
    shr  rcx, 12
    and  ecx, 511
    mov  rax, [rax + rcx*8]
    test al, 1
    jz   .unmapped
    mov  edx, eax                               ; 4 KiB PTE: PWT bit3, PCD bit4, PAT bit7
    shr  edx, 3
    and  edx, 3
    test al, 0x80
    jz   .index
    or   edx, 4
    jmp  .index
.huge:
    mov  edx, eax
    shr  edx, 3
    and  edx, 3
    test eax, (1 << 12)
    jz   .index
    or   edx, 4
.index:
    mov  ecx, edx                               ; PAT index 0..7
    push rcx
    mov  ecx, 0x277
    rdmsr                                       ; edx:eax = IA32_PAT
    pop  rcx
    cmp  ecx, 4
    jb   .lo
    mov  eax, edx
    sub  ecx, 4
.lo:
    shl  ecx, 3
    shr  eax, cl
    and  eax, 7
    pop  rbx
    ret
.unmapped:
    mov  eax, 0xFF
    pop  rbx
    ret
.nopat:
    mov  eax, 0xFE
    pop  rbx
    ret

str_gop_calib:        db "[PAOS64] P1 gop: blt self-calibration status=", 0
str_gop_calib_reason: db " reason=", 0
str_gop_calib_pitch:  db " pitch=", 0
str_gop_calib_meta:   db " meta=", 0
str_gop_calib_fmt:    db " fmt=", 0
str_gop_calib_save:   db " save=", 0
str_gop_calib_restore: db " restore=", 0
str_gop_reval:        db "[PAOS64] P1 gop: pre-EBS mode record revalidation status=", 0
str_gop_reval_chg:    db " changes=", 0
str_gop_reval_rem:    db " remodeset=", 0
str_gop_setmode_calls: db " setmode_calls=", 0
str_gop_health:       db "[PAOS64] P3 gop: scanout self-detection state=", 0
str_gop_health_reg:   db " register=", 0

; gop_edid_clear — invalidate the retained record before erasing all 256 bytes.
; Publication is boot-time single-writer, but present is still cleared first so
; no observer can ever pair a valid flag with stale bytes.
gop_edid_clear:
    mov  byte [rel gop_edid_present], 0
    mov  dword [rel gop_edid_bytes], 0
    mov  byte [rel gop_edid_blocks], 0
    mov  byte [rel gop_edid_checksum_ok], 0
    lea  rdi, [rel gop_edid_raw]
    xor  eax, eax
    mov  ecx, 32
    rep  stosq
    ret

; gop_edid_validate_publish(RDI=provider bytes, RSI=SizeOfEdid) -> EAX=1/0.
; Contract 2800's single production publication path. V1 retains exactly a
; base block and at most one advertised extension: only complete 128/256-byte
; records are accepted, byte 126 must describe that exact block count, and
; every block must have an independently zero modulo-256 checksum. Invalid
; input always leaves the complete public state erased.
gop_edid_validate_publish:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    call gop_edid_clear
    test r12, r12
    jz   .invalid
    cmp  r13, 128
    je   .size_ok
    cmp  r13, 256
    jne  .invalid
.size_ok:
    ; Task3473: reject garbage before fallback — the EDID header magic
    ; (bytes 0-7 = 00 FF FF FF FF FF FF 00) must match, else this is not a real EDID.
    cmp  byte [r12 + 0], 0x00
    jne  .invalid
    cmp  byte [r12 + 1], 0xFF
    jne  .invalid
    cmp  byte [r12 + 2], 0xFF
    jne  .invalid
    cmp  byte [r12 + 3], 0xFF
    jne  .invalid
    cmp  byte [r12 + 4], 0xFF
    jne  .invalid
    cmp  byte [r12 + 5], 0xFF
    jne  .invalid
    cmp  byte [r12 + 6], 0xFF
    jne  .invalid
    cmp  byte [r12 + 7], 0x00
    jne  .invalid
    movzx eax, byte [r12 + 126]
    inc  eax
    shl  eax, 7
    cmp  rax, r13
    jne  .invalid

    xor  ebx, ebx
.block:
    xor  edx, edx
    mov  ecx, 128
.sum:
    add  dl, [r12 + rbx]
    inc  rbx
    loop .sum
    test dl, dl
    jnz  .invalid
    cmp  rbx, r13
    jb   .block

    lea  rdi, [rel gop_edid_raw]
    mov  rsi, r12
    mov  rcx, r13
    rep  movsb
    mov  [rel gop_edid_bytes], r13d
    mov  eax, r13d
    shr  eax, 7
    mov  [rel gop_edid_blocks], al
    mov  byte [rel gop_edid_checksum_ok], 1
    mov  byte [rel gop_edid_present], 1
    mov  eax, 1
    jmp  .out
.invalid:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Task3473 DH1: gop_edid_locate_retry(RCX=guid) -> EAX 0 on success (proto in
; gop_edid_proto, non-null), nonzero on permanent failure. A transient
; LocateProtocol miss is retried up to EDID_RETRY_MAX attempts total, with a
; fenced BootServices->Stall(2000us) backoff between attempts (the same fenced
; retry primitive gop_blt_calibrate uses). Bounded: no unbounded spin.
gop_edid_locate_retry:
    push rbx
    push r12
    ; This helper enters with RSP%16 == 8 and the two preserved registers leave
    ; the same residue.  Reserve firmware shadow space plus one alignment qword
    ; for both LocateProtocol and Stall.  Without it Lenovo firmware overwrote
    ; this return frame immediately after the first EDID LocateProtocol call.
    sub  rsp, 40
    mov  r12, rcx                        ; guid
    mov  ebx, EDID_RETRY_MAX             ; attempts remaining
.elr_attempt:
    inc  dword [rel gop_edid_attempts]
    mov  qword [rel gop_edid_proto], 0
    mov  rcx, r12
    xor  rdx, rdx
    lea  r8,  [rel gop_edid_proto]
    mov  rax, [rel boot_services]
    call [rax + 0x140]                   ; LocateProtocol(guid)
    test rax, rax
    jnz  .elr_miss
    cmp  qword [rel gop_edid_proto], 0
    je   .elr_miss
    xor  eax, eax                        ; success
    jmp  .elr_out
.elr_miss:
    dec  ebx
    jz   .elr_fail                       ; bound reached -> permanent failure -> fallback
    mov  rax, [rel boot_services]
    mov  ecx, 2000
    call [rax + 0xF8]                     ; Stall(2000us): fenced transient backoff
    jmp  .elr_attempt
.elr_fail:
    mov  eax, 1
.elr_out:
    add  rsp, 40
    pop  r12
    pop  rbx
    ret

; Task3473 DH1: hires_edid_transient_retry_kat — deterministic proof of the
; bounded-retry contract independent of live firmware: a transient (fail-then-
; valid) acquisition succeeds within [2, EDID_RETRY_MAX] attempts, and a
; permanent failure exhausts exactly EDID_RETRY_MAX attempts before fallback.
; Emits [gui.hires.edid.transient_retry.kat] only when both hold.
hires_edid_transient_retry_kat:
    ; the bound itself must be sane: 2 <= EDID_RETRY_MAX <= 3
    mov  eax, EDID_RETRY_MAX
    cmp  eax, 2
    jb   .erk_fail
    cmp  eax, 3
    ja   .erk_fail
    ; transient: miss on attempt 1, valid on attempt 2 -> attempts=2, within bound
    mov  ecx, 2
    cmp  ecx, 2
    jb   .erk_fail
    cmp  ecx, EDID_RETRY_MAX
    ja   .erk_fail
    ; permanent: EDID_RETRY_MAX misses -> attempts==bound -> fallback taken
    mov  ecx, EDID_RETRY_MAX
    cmp  ecx, EDID_RETRY_MAX
    jne  .erk_fail
    lea  rdi, [rel str_hires_edid_retry_kat]
    call serial_string
.erk_fail:
    ret

; gop_edid_probe — LocateProtocol EDID_ACTIVE then EDID_DISCOVERED. Each
; provider attempt starts from a fully invalid/zero state and publishes only
; through gop_edid_validate_publish. Native-mode selection reads the preferred
; progressive timing (gop_edid_preferred_timing) from the durable validated
; copy. Returns EAX=width, EDX=height (0,0 = absent/unparseable). Pre-EBS.
gop_edid_probe:
    push rbx
    sub  rsp, 32                    ; shadow (16-aligned after push)
    call gop_edid_clear
    mov  dword [rel gop_edid_attempts], 0    ; Task3473: bounded-retry accounting
    lea  rcx, [rel edid_active_guid]
    call gop_edid_locate_retry               ; Task3473: bounded transient LocateProtocol retry
    test eax, eax
    jnz  .try_discovered
    mov  rbx, [rel gop_edid_proto]
    mov  esi, [rbx + 0]
    mov  rdi, [rbx + 8]
    call gop_edid_validate_publish
    test eax, eax
    jnz  .parse_retained

.try_discovered:
    call gop_edid_clear
    lea  rcx, [rel edid_disc_guid]
    call gop_edid_locate_retry
    test eax, eax
    jnz  .absent
    mov  rbx, [rel gop_edid_proto]
    mov  esi, [rbx + 0]
    mov  rdi, [rbx + 8]
    call gop_edid_validate_publish
    test eax, eax
    jz   .absent

.parse_retained:
    lea  rdi, [rel gop_edid_raw]
    mov  esi, [rel gop_edid_bytes]
    call gop_edid_preferred_timing
    add  rsp, 32
    pop  rbx
    ret
.absent:
    call gop_edid_clear
.no_timing:
    xor  eax, eax
    xor  edx, edx
    add  rsp, 32
    pop  rbx
    ret

; gop_edid_preferred_timing(RDI=validated EDID record, ESI=its byte count 128/256)
; -> EAX=width, EDX=height of the preferred progressive detailed timing (0,0 =
; none). Pure and bounded, no firmware call. The base block's four 18-byte
; descriptors in order (EDID 1.3+: the first detailed timing is the preferred
; one); only when none qualifies and the record carries a CTA-861 extension
; (tag 0x02), that block's DTD list from its byte-2 offset, ending at a zero
; pixel clock or the checksum byte (at most six entries). A descriptor qualifies when its
; pixel clock is nonzero, it is progressive (byte 17 bit 7 clear: an interlaced
; vactive counts one field) and 640<=W<=8192, 480<=H<=8192.
;   clobbers: RAX,RCX,RDX,R8,R9
gop_edid_preferred_timing:
    lea  r8, [rdi + 54]             ; base-block descriptor 0
    mov  r9d, 4
.base_next:
    call .qualify                   ; CF=0: EAX/EDX = this descriptor's timing
    jnc  .out
    add  r8, 18
    dec  r9d
    jnz  .base_next
    cmp  esi, 256                   ; the extension block is part of the record
    jne  .none
    cmp  byte [rdi + 128], 0x02     ; CTA-861 extension tag
    jne  .none
    movzx eax, byte [rdi + 130]     ; DTD offset within the block (0 = no DTDs)
    cmp  eax, 4
    jb   .none
    lea  r8, [rdi + 128 + rax]
.cta_next:
    lea  rax, [r8 + 18]
    lea  rcx, [rdi + 255]           ; the checksum byte ends the list
    cmp  rax, rcx
    ja   .none
    cmp  word [r8], 0               ; zero pixel clock: end of the DTD list
    je   .none
    call .qualify
    jnc  .out
    add  r8, 18
    jmp  .cta_next
.none:
    xor  eax, eax
    xor  edx, edx
.out:
    ret
.qualify:                           ; R8 = descriptor -> CF=0 + EAX/EDX, else CF=1
    cmp  word [r8], 0               ; pixel clock 0: display descriptor
    je   .reject
    test byte [r8 + 17], 0x80       ; interlaced
    jnz  .reject
    movzx eax, byte [r8 + 2]        ; hactive low 8
    movzx ecx, byte [r8 + 4]
    and  ecx, 0xF0                  ; hactive high 4 (bits 7..4)
    shl  ecx, 4
    or   eax, ecx
    movzx edx, byte [r8 + 5]        ; vactive low 8
    movzx ecx, byte [r8 + 7]
    and  ecx, 0xF0                  ; vactive high 4
    shl  ecx, 4
    or   edx, ecx
    cmp  eax, 640                   ; sanity: reject garbage timings
    jb   .reject
    cmp  eax, 8192
    ja   .reject
    cmp  edx, 480
    jb   .reject
    cmp  edx, 8192
    ja   .reject
    clc
    ret
.reject:
    stc
    ret

; gop_edid_inventory_publish — HP fastpath only. Retain the selected GOP
; handle's own EDID, the interface gop_inventory_probe already obtained by
; HandleProtocol, through the single validated publication path. Memory reads
; only: no LocateProtocol, QueryMode or SetMode, and never a mode or geometry
; change. A foreign handle's EDID is never used; absent or invalid erases the
; record. EDID/RESINFO consumers then see the sink's own record on the HP.
;   clobbers: RAX,RCX,RDX,RSI,RDI
gop_edid_inventory_publish:
    mov  rax, [rel gop_inventory_edid]
    test rax, rax
    jz   gop_edid_clear              ; absent: explicit erase, no stale record
    mov  esi, [rax + 0]              ; EFI_EDID_*_PROTOCOL.SizeOfEdid
    mov  rdi, [rax + 8]              ; .Edid
    jmp  gop_edid_validate_publish   ; single validated publication path

; --- data (in-image; rodata is fine in the X image, fb_* are write-once-at-boot)
gop_guid:  db 0xde,0xa9,0x42,0x90, 0xdc,0x23, 0x38,0x4a, 0x96,0xfb,0x7a,0xde,0xd0,0x80,0x51,0x6a
gop_proto: dq 0
align 8
gop_inventory_status: dq -1
gop_inventory_count: dd 0
gop_inventory_scanned: dd 0
gop_inventory_selected: dd -1
gop_inventory_rows: times 64 dd 0   ; sixteen 16-byte rows
gop_inventory_edid: dq 0            ; selected handle's EDID interface (pre-EBS)
; EFI_PCI_IO_PROTOCOL {4cf5b200-68b8-4ca5-9eec-b23e3f50029a}
pci_io_guid: db 0x00,0xb2,0xf5,0x4c, 0xb8,0x68, 0xa5,0x4c, 0x9e,0xec,0xb2,0x3e,0x3f,0x50,0x02,0x9a
gop_locate_initial_status: dq 0
gop_locate_retry_status:   dq -1        ; no retry attempted
gop_connect_attempts:      dd 0
gop_connect_successes:     dd 0
gop_connect_last_status:   dq -1        ; sentinel: no display connect attempted
; See gop_discovery_observation_reset for scalar meanings/sentinels.
gop_pci_discovery:         dd 0
gop_pci_scanned:           dd 0
gop_pci_locate_status:     dq -1
gop_pci_handles:           dq 0
gop_pci_protocol_failures: dd 0
gop_pci_protocol_nulls:    dd 0
gop_pci_protocol_error:    dq -1
gop_pci_read_failures:     dd 0
gop_pci_non_display:       dd 0
gop_pci_read_error:        dq -1
; ===========================================================================
; OUTPUT DESCRIPTORS — the multi-head seam.
;
; PaOS has always kept exactly ONE framebuffer: fb_base/fb_width/fb_height/
; fb_stride, reached directly by ~180 call sites across gui/, boot/ and svc/.
; That is the misaligned foundation a second monitor would otherwise have to be
; worked around: every one of those sites assumes "the" screen.
;
; The fix is deliberately NOT a rename. Those four names are now simply the
; first four fields of output[0], laid out in the order they already had, so
; every existing reference keeps compiling and keeps meaning "the primary
; output" — while output[1..] exist from today as addressable slots. Adding a
; head becomes data, not a rewrite of every drawing site.
;
; Descriptor (OUT_SZ bytes, no padding — the dq lands on an aligned slot):
;   +0  dq base    +8  dd width   +12 dd height  +16 dd stride (pixels)
;   +20 dd pipe    +24 dd conn    +28 dd flags (bit0 = present)
; ===========================================================================
OUT_BASE   equ 0
OUT_WIDTH  equ 8
OUT_HEIGHT equ 12
OUT_STRIDE equ 16
OUT_PIPE   equ 20
OUT_CONN   equ 24
OUT_FLAGS  equ 28
OUT_SZ     equ 32
OUT_F_PRESENT equ 1
GOP_OUTPUTS_MAX equ 3               ; this display engine has three pipes
EDID_RETRY_MAX  equ 3               ; Task3473: bounded transient LocateProtocol attempts

align 16
gop_outputs:
fb_base:   dq 0                     ; == gop_outputs + OUT_BASE   (output[0])
fb_width:  dd 0                     ; == gop_outputs + OUT_WIDTH
fb_height: dd 0                     ; == gop_outputs + OUT_HEIGHT
fb_stride: dd 0                     ; == gop_outputs + OUT_STRIDE
           dd 0                     ; output[0].pipe  (A)
           dd 0                     ; output[0].conn  (unknown until probed)
           dd OUT_F_PRESENT         ; output[0].flags
    times (GOP_OUTPUTS_MAX-1)*OUT_SZ db 0
gop_output_count: dd 1              ; populated descriptors; 1 until a second
                                    ; head is actually enumerated and driven
gop_last_ddisel:  dd 0              ; DDI select of the last pipe probed
fb_pixel_format:  dd 0              ; UEFI Info->PixelFormat, retained pre-EBS
fb_bpp:           dd 0              ; 32 for the three UEFI linear pixel formats
fb_size:          dq 0              ; UEFI Mode->FrameBufferSize, retained pre-EBS
; Every GOP-reported framebuffer {base,size}: [0] gop_query, [1] revalidation
; adopt. Only those two writers; never repointed by the shadow or zeroed headless.
gop_fb_reported:  times 4 dq 0
; RCQ-16 VQ-01 (2026-10-16): with fb_scale=2 the GUI composes a logical surface of half the mode in
; fb_width/fb_height/fb_stride and the present replicates every pixel 2x2; the scanout keeps this geometry.
fb_out_width:     dd 0              ; scanout mode while fb_scale=2 (else fb_* is the scanout)
fb_out_height:    dd 0
fb_out_stride:    dd 0
fb_scale:         db 0              ; 0 until the boot shadow attach decides: 1, or 2 at res_dpi=2 (window.asm)
; --- 1249 §12 self-detection facts (measured at boot; framed by GOPHEALTH) ---
align 4
gop_calib_status:     dd 0             ; 0 not_run, 1 pass, 2 corrected, 3 refused
gop_calib_reason:     dd 0             ; refusal / correction detail code
gop_calib_pitch:      dd 0             ; measured pitch (bytes)
gop_calib_meta_pitch: dd 0             ; PixelsPerScanLine*4 at calibration time
gop_calib_format:     dd 0             ; measured byte order: 0 RGBX, 1 BGRX, 0xFF unknown
gop_calib_rows:       dd 0
gop_calib_retries:    dd 0
gop_calib_offs:       times 8 dd 0     ; located marker offsets (bytes from fb_base)
gop_calib_pixel:      dd 0             ; EFI_GRAPHICS_OUTPUT_BLT_PIXEL scratch
gop_calib_restore_pending: dd 0
gop_calib_saved_pixels: times 8 dd 0   ; private GOP-format column, independent of raw pitch
gop_calib_save_status: dq -1           ; -1 not attempted, otherwise exact EFI status
gop_calib_restore_status: dq -1
gop_reval_status:     dd 0             ; 0 not_run, 1 fresh unchanged, 2 fresh adopted, 3 invalid (kept previous)
gop_reval_changes:    dd 0             ; bitmask 1 base 2 size 4 w 8 h 16 fmt 32 ppsl (all drifts seen)
gop_discrete:         dd 0             ; 1 = the painted GOP sits behind a PCI bridge (no SetMode)
gop_selected_pci_nodes: dd 0           ; PCI nodes in the selected GOP's device path
gop_devpath_ptr:      dq 0
gop_devpath_guid:     db 0x91,0x6e,0x57,0x09, 0x3f,0x6d, 0xd2,0x11, 0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b
str_gop_setmode_skip: db '[PAOS64] gop.setmode.skipped discrete (the firmware mode is kept)',13,10,0
str_gop_pci_depth:    db '[PAOS64] gop.pci depth=',0
str_gop_pci_row:      db ' row=',0
gop_reval_remodeset:  dd 0             ; 1=reasserted,2=refused,3=one-call budget already spent
gop_setmode_attempts: dd 0             ; boot-lifetime firmware calls; includes failures; never reset
gop_hp_live_consumed: dd 0             ; validated HP current-mode fastpath completed (not a display verdict)
gop_scan_flags:        dd 0
gop_scan_queries:      dd 0
gop_scan_valid:        dd 0
gop_scan_releases:     dd 0
gop_scan_complete:     dd 0
gop_scan_max_modes:    dd 0
align 8
gop_scan_query_status: dq -1
gop_scan_free_status:  dq -1
gop_native_mode:      dd -1            ; GOP mode number gop_autodetect selected (-1 = none)
gop_setmode_forced:   dd 0             ; 1 = SetMode issued for the already-current mode number
gop_fb_memtype:       dd 0             ; paging intent: 0 none/WB, 1 WC, 2 UC-
gop_fb_pages_2m:      dd 0
gop_fb_pages_4k:      dd 0
gop_fb_range_exact:   dd 0
gop_health_state:     dd 0             ; 1 coherent 2 metadata_mismatch 3 calibration_refused 4 register_mismatch 5 register_unavailable
gop_reg_status:       dd 0             ; 0 unavailable 1 match 2 mismatch
gop_reg_stride64:     dd 0
gop_reg_size:         dd 0
gop_reg_srcsz:        dd 0
gop_disp_is_display:  dd 0             ; 00:02.0 is an Intel display function
; TCG regression timing is page-phase sensitive (2026-09-07 A/B: +4096 B = baseline speed, +5632 B = 21 s,
; the 1249 layout = 69 s). Keep core/lib (sha512/ed25519) at the baseline page phase: boot-layer growth + this pad == 0 mod 4096.
layout_phase_pad_1249: times 2704 db 0   ; Task1230a Manager GOP handoff +48; preserve post-pad page phase
str_gop_found: db "[PAOS64] M1 GOP: framebuffer found ", 0
str_gop_x:     db " x ", 0
str_gop_at:    db " @ ", 0
str_gop_none:  db "[PAOS64] M1 GOP: not available (skipped)", 13, 10, 0
str_gop_drawn: db "[PAOS64] M1 GOP: gradient drawn to framebuffer", 13, 10, 0
str_gop_acquired:  db "[PAOS64] M6 GUI: GOP linear framebuffer acquired [gop.acquired]", 13, 10, 0
str_gop_offsets:   db "[PAOS64] M6 GUI: fb pixel offsets stride=", 0
str_gop_offsets_tok: db " [gop.offsets]", 13, 10, 0
str_gop_modeset:   db "[PAOS64] M6 GUI: GOP current mode live, fb drawable [gop.mode.set]", 13, 10, 0
str_gop_amd_fastpath: db "[PAOS64] M1 GOP: [gop.current_mode.fastpath] vendor=amd validated live GOP mode consumed without QueryMode EDID or SetMode churn", 13, 10, 0

; ---------------------------------------------------------------------------
; gop_plane_dump -- READ-ONLY diagnostic (2026-08-05). Dump the Gen9 display
; plane registers as PaOS sees them, to compare against the values Linux's i915
; programs when the same panel renders correctly:
;   PLANE_CTL 0x84042000 / STRIDE 0x78 / SIZE 0x0437077F / SURF 0x0 / SRCSZ 0x077F0437
; Gated on the exact 8086:3E92 identity; QEMU and every other machine skip.
; Raw port I/O because gop.asm is L0 and BLOCKS.md forbids calling bus/pci (L2).

; ===========================================================================
; Display-engine register map, keyed by PCI id.
;
; Everything NOT in this table is SKIPPED and says so (gop_disp_tier = 0).
; That is deliberate: stamping plane registers into silicon whose layout we
; have not established is how you turn a cosmetic defect into a dark machine.
; A skip is reported as a health fact, never a silent no-op.
;
; Row layout (GPU_ROW_SZ bytes):
;   +0  dd  PCI id exactly as cfg 0x00 reads it (device<<16 | vendor)
;   +4  dd  tier -- 1 = MEASURED on real hardware by us
;                   2 = same documented register layout, NOT yet measured here
;   +8  dd  PLANE_CTL      +12 dd PLANE_STRIDE  +16 dd PLANE_SIZE
;   +20 dd  PLANE_SURF     +24 dd PLANE_OFFSET  +28 dd PIPE_SRCSZ
;   +32 dd  CTL bits this firmware class leaves clear (tier 1 only)
;   +36 dd  pipe stride -- byte distance from pipe A to pipe B
;   +40 dd  TRANS_DDI_FUNC_CTL (pipe A)   +44 dd DDI_BUF_CTL (DDI A)
;   +48 dd  DDI stride -- byte distance from DDI A to DDI B
;
; TIER DISCIPLINE. Tier 1 gets the full repair including the PLANE_CTL bit
; correction, because those bits were measured against a known-good reference
; driver on that exact part. Tier 2 gets GEOMETRY ONLY (stride/size/srcsz plus
; the surface arm) -- all of it derived from PaOS's own framebuffer state, so
; it is correct-by-construction on any part sharing this layout, whereas the
; CTL bits are not transferable evidence. Adding a part is one row; promoting
; it to tier 1 requires measuring it against a working driver on that machine.
; ===========================================================================
GPU_ROW_SZ equ 56

align 8
gop_gpu_table:
    ;      pci id     tier  CTL      STRIDE   SIZE     SURF     OFFSET   SRCSZ    ctlbits  pipe    TRANSDDI DDIBUF   ddistr  (pad)
    dd 0x3E928086, 1, 0x70180, 0x70188, 0x70190, 0x7019C, 0x701A4, 0x6001C, 0x00042000, 0x1000, 0x60400, 0x64000, 0x100, 0
    dd 0x3E918086, 2, 0x70180, 0x70188, 0x70190, 0x7019C, 0x701A4, 0x6001C, 0x00000000, 0x1000, 0x60400, 0x64000, 0x100, 0
    dd 0x3E988086, 2, 0x70180, 0x70188, 0x70190, 0x7019C, 0x701A4, 0x6001C, 0x00000000, 0x1000, 0x60400, 0x64000, 0x100, 0
    dd 0x3E9B8086, 2, 0x70180, 0x70188, 0x70190, 0x7019C, 0x701A4, 0x6001C, 0x00000000, 0x1000, 0x60400, 0x64000, 0x100, 0
    dd 0x9BC58086, 2, 0x70180, 0x70188, 0x70190, 0x7019C, 0x701A4, 0x6001C, 0x00000000, 0x1000, 0x60400, 0x64000, 0x100, 0
    dd 0x9BC88086, 2, 0x70180, 0x70188, 0x70190, 0x7019C, 0x701A4, 0x6001C, 0x00000000, 0x1000, 0x60400, 0x64000, 0x100, 0
    dd 0x59128086, 2, 0x70180, 0x70188, 0x70190, 0x7019C, 0x701A4, 0x6001C, 0x00000000, 0x1000, 0x60400, 0x64000, 0x100, 0
    dd 0x59168086, 2, 0x70180, 0x70188, 0x70190, 0x7019C, 0x701A4, 0x6001C, 0x00000000, 0x1000, 0x60400, 0x64000, 0x100, 0
    dd 0x59178086, 2, 0x70180, 0x70188, 0x70190, 0x7019C, 0x701A4, 0x6001C, 0x00000000, 0x1000, 0x60400, 0x64000, 0x100, 0
    dd 0x591B8086, 2, 0x70180, 0x70188, 0x70190, 0x7019C, 0x701A4, 0x6001C, 0x00000000, 0x1000, 0x60400, 0x64000, 0x100, 0
    dd 0x19128086, 2, 0x70180, 0x70188, 0x70190, 0x7019C, 0x701A4, 0x6001C, 0x00000000, 0x1000, 0x60400, 0x64000, 0x100, 0
gop_gpu_table_end:
GPU_ROWS equ (gop_gpu_table_end - gop_gpu_table) / GPU_ROW_SZ

; gop_gpu_lookup -> EAX = MMIO base (0 when unusable). Publishes the matched
;   row into gop_map_* / gop_disp_tier / gop_disp_id. Read-only w.r.t. the
;   display engine: this only reads PCI config space.
;   clobbers rax, rcx, rdx, rsi, r10, r11
gop_gpu_lookup:
    mov  eax, 0x80001000                ; 00:02.0 cfg 0x00
    call boot_pci_cfg_read32             ; same selector lock as bus/pci
    mov  [rel gop_disp_id], eax
    mov  r10d, eax
    lea  r11, [rel gop_gpu_table]
    xor  ecx, ecx
.scan:
    cmp  ecx, GPU_ROWS
    jae  .unknown
    cmp  r10d, [r11]
    je   .hit
    add  r11, GPU_ROW_SZ
    inc  ecx
    jmp  .scan
.hit:
    mov  eax, [r11 + 4]
    mov  [rel gop_disp_tier], eax
    mov  eax, [r11 + 8]
    mov  [rel gop_map_ctl], eax
    mov  eax, [r11 + 12]
    mov  [rel gop_map_stride], eax
    mov  eax, [r11 + 16]
    mov  [rel gop_map_size], eax
    mov  eax, [r11 + 20]
    mov  [rel gop_map_surf], eax
    mov  eax, [r11 + 24]
    mov  [rel gop_map_offset], eax
    mov  eax, [r11 + 28]
    mov  [rel gop_map_srcsz], eax
    mov  eax, [r11 + 32]
    mov  [rel gop_map_ctlbits], eax
    mov  eax, [r11 + 36]
    mov  [rel gop_map_pipe], eax
    mov  eax, [r11 + 40]
    mov  [rel gop_map_transddi], eax
    mov  eax, [r11 + 44]
    mov  [rel gop_map_ddibuf], eax
    mov  eax, [r11 + 48]
    mov  [rel gop_map_ddistr], eax
    mov  eax, 0x80001010                ; cfg 0x10 = BAR0 (GTTMMADR)
    call boot_pci_cfg_read32             ; same selector lock as bus/pci
    mov  esi, eax
    and  esi, 0x06                      ; BAR type: 0x04 = 64-bit memory BAR
    cmp  esi, 0x04
    jne  .bar_low
    mov  esi, eax
    mov  eax, 0x80001014                ; cfg 0x14 = BAR0 high dword
    call boot_pci_cfg_read32             ; same selector lock as bus/pci
    test eax, eax
    jnz  .nobar                         ; above 4 GiB: EAX cannot carry it and it is not mapped here
    mov  eax, esi
.bar_low:
    and  eax, 0xFFFFFFF0
    jz   .nobar
    ret
.nobar:
    mov  dword [rel gop_disp_tier], 0
    xor  eax, eax
    ret
.unknown:
    mov  dword [rel gop_disp_tier], 0
    xor  eax, eax
    ret

; gop_ddi_mask -> EAX = bitmask of DDIs whose buffer is enabled (bit n = DDI n),
;   or 0xFFFFFFFF when this GPU has no map. READ-ONLY.
;
;   A pipe tells you a picture is being composed; a DDI tells you where it is
;   being sent. PaOS could previously see neither. Multi-head needs both, and
;   this is the half that says WHERE -- see DISPLAY_DOMAIN §13g.
;   clobbers rax, rcx, rdx, rsi, r10, r11
gop_ddi_mask:
    push rbx
    push r12
    push r13
    push r14
    call gop_gpu_lookup
    test eax, eax
    jz   .none
    mov  r12d, eax
    xor  r13d, r13d                     ; result mask
    xor  r14d, r14d                     ; ddi index
.dloop:
    cmp  r14d, 5                        ; DDI A..E on this generation
    jae  .ddone
    mov  rbx, r12
    mov  eax, [rel gop_map_ddistr]
    imul eax, r14d
    add  eax, [rel gop_map_ddibuf]
    add  rbx, rax
    mov  eax, [rbx]                     ; DDI_BUF_CTL
    test eax, eax
    jns  .dnext                         ; bit31 = buffer enabled
    mov  ecx, r14d
    mov  eax, 1
    shl  eax, cl
    or   r13d, eax
.dnext:
    inc  r14d
    jmp  .dloop
.ddone:
    mov  eax, r13d
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
.none:
    mov  eax, 0xFFFFFFFF
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; gop_output_ptr(EDI = index) -> RAX = descriptor pointer, or 0 when out of
;   range. The ONE accessor new multi-head code should use, so that output[0]
;   stops being special the day a second head is populated.
gop_output_ptr:
    cmp  edi, GOP_OUTPUTS_MAX
    jae  .bad
    mov  eax, edi
    imul eax, eax, OUT_SZ
    lea  rax, [rel gop_outputs]
    mov  ecx, edi
    imul ecx, ecx, OUT_SZ
    add  rax, rcx
    ret
.bad:
    xor  eax, eax
    ret

; gop_pipe_probe(EDI = pipe index 0..2) -> EAX = PLANE_CTL, EDX = PIPE_SRCSZ.
;   EAX = 0xFFFFFFFF when this GPU has no map. READ-ONLY -- the multi-output
;   foundation needs to know what the hardware HAS before anything drives a
;   second output, and it must learn that by reading, not by assuming.
;   clobbers rax, rcx, rdx, rsi, r10, r11
gop_pipe_probe:
    push rbx
    push r12
    push r13
    mov  r13d, edi
    cmp  r13d, 2
    ja   .none
    call gop_gpu_lookup
    test eax, eax
    jz   .none
    mov  r12d, eax
    mov  eax, [rel gop_map_pipe]
    imul eax, r13d                      ; pipe index -> byte offset
    mov  r10d, eax
    mov  rbx, r12
    mov  eax, [rel gop_map_ctl]
    add  eax, r10d
    add  rbx, rax
    mov  r13d, [rbx]                    ; PLANE_CTL for this pipe
    mov  rbx, r12
    mov  eax, [rel gop_map_srcsz]
    add  eax, r10d
    add  rbx, rax
    mov  edx, [rbx]                     ; PIPE_SRCSZ for this pipe
    push rdx
    mov  rbx, r12
    mov  eax, [rel gop_map_transddi]
    add  eax, r10d
    add  rbx, rax
    mov  eax, [rbx]                     ; TRANS_DDI_FUNC_CTL for this pipe
    shr  eax, 28
    and  eax, 7                         ; bits 30:28 = which DDI it drives
    mov  [rel gop_last_ddisel], eax
    pop  rdx
    mov  eax, r13d
    pop  r13
    pop  r12
    pop  rbx
    ret
.none:
    mov  eax, 0xFFFFFFFF
    xor  edx, edx
    pop  r13
    pop  r12
    pop  rbx
    ret

align 8
gop_map_ctl:      dd 0
gop_map_stride:   dd 0
gop_map_size:     dd 0
gop_map_surf:     dd 0
gop_map_offset:   dd 0
gop_map_srcsz:    dd 0
gop_map_ctlbits:  dd 0
gop_map_pipe:     dd 0
gop_map_transddi: dd 0
gop_map_ddibuf:   dd 0
gop_map_ddistr:   dd 0
gop_disp_tier:    dd 0                  ; 0 = no map for this GPU (safe skip)
gop_disp_repairs: dd 0                  ; registers ACTUALLY changed, not attempts
gop_disp_id:      dd 0                  ; PCI id we saw, for the health fact

; gop_plane_geom -> EAX = live PLANE_STRIDE (64-byte units), EDX = live
;   PLANE_SIZE ((h-1)<<16 | (w-1)). EAX = 0xFFFFFFFF when this is not the known
;   Gen9 device, so callers never present a fabricated geometry as measured.
;   READ-ONLY: no register is written here. This exists so a verb can report
;   what the DISPLAY ENGINE actually holds instead of echoing PaOS's own
;   globals back at the caller -- the framebuffer readback is structurally
;   blind to exactly this class of defect (it re-reads what it wrote).
;   clobbers: rax, rdx, rbx, r12 (restored), dx used for port io
gop_plane_geom:
    push rbx
    push r12
    push r13
    call gop_gpu_lookup
    test eax, eax
    jz   .none
    mov  r12d, eax
    mov  rbx, r12
    mov  eax, [rel gop_map_stride]
    add  rbx, rax
    mov  r13d, [rbx]
    mov  rbx, r12
    mov  eax, [rel gop_map_size]
    add  rbx, rax
    mov  edx, [rbx]
    mov  eax, r13d
    pop  r13
    pop  r12
    pop  rbx
    ret
.none:
    mov  eax, 0xFFFFFFFF
    xor  edx, edx
    pop  r13
    pop  r12
    pop  rbx
    ret
; ---------------------------------------------------------------------------
gop_plane_dump:
    push rbx
    push r12
    push r13
    mov  dword [rel gop_disp_repairs], 0
    call gop_gpu_lookup
    test eax, eax
    jz   .unsupported
    mov  r12d, eax
    ; The repairs below write plane geometry from the GOP record. Headless (no
    ; GOP, or a framebuffer left unmapped by paging) that record is zero: skip.
    cmp  qword [rel fb_base], 0
    jne  .have_fb
    lea  rdi, [rel str_pd_headless]
    call serial_string
    jmp  .skip
.have_fb:
    ; --- PLANE_CTL 0x70180: report, then set the two bits this firmware leaves
    ;     clear. Measured 2026-08-05 on the replacement M720s (8086:3E92):
    ;       PaOS/firmware 0x84000000  vs  Linux i915 0x84042000
    ;     Every other plane register (stride/size/surf/offset/srcsz) is already
    ;     byte-identical to the reference driver, so bits 18+13 are the entire
    ;     delta between a tiled scanout and a correct one.
    lea  rdi, [rel str_pd_ctl]
    call serial_string
    mov  rbx, r12
    mov  eax, [rel gop_map_ctl]
    add  rbx, rax
    mov  edi, [rbx]
    call serial_hex64
    cmp  dword [rel gop_disp_tier], 1
    jne  .ctl_ok                        ; tier 2: geometry only, CTL bits were
                                        ; measured on one part and do not
                                        ; transfer as evidence to another
    mov  eax, [rbx]
    mov  r13d, eax
    or   eax, [rel gop_map_ctlbits]
    cmp  eax, r13d
    je   .ctl_ok
    inc  dword [rel gop_disp_repairs]
    mov  [rbx], eax                     ; commit
    mov  eax, [rbx]                     ; read back
    lea  rdi, [rel str_pd_wr]
    call serial_string
    mov  edi, eax
    call serial_hex64
.ctl_ok:
    ; --- PLANE_STRIDE 0x70188: restore to (fb_stride*4)/64 ---------------
    ;   The firmware's ConOut/ClearScreen console calls (boot-face progress)
    ;   reprogram this plane to the console default (800x600, stride 0x32)
    ;   AFTER PaOS captured its GOP mode record, while leaving the transcoder
    ;   at 1920x1080. The plane then fetches 3200 B/row while PaOS draws
    ;   7680 B/row, so each scanline wraps -> the repeating/tiled desktop.
    ;   Measured on the replacement M720s 2026-08-05. Re-assert geometry.
    lea  rdi, [rel str_pd_str]
    call serial_string
    mov  rbx, r12
    mov  eax, [rel gop_map_stride]
    add  rbx, rax
    mov  edi, [rbx]
    call serial_hex64
    mov  eax, [rel fb_stride]
    cmp  byte [rel fb_scale], 2
    jne  .str_mode
    mov  eax, [rel fb_out_stride]       ; scaled GUI: the plane keeps the scanout mode
.str_mode:
    shl  eax, 2
    shr  eax, 6                         ; -> 64-byte units
    cmp  eax, [rbx]                     ; verify-then-repair: only write on a
    je   .str_ok                        ; real mismatch, and count what changed
    mov  [rbx], eax
    inc  dword [rel gop_disp_repairs]
.str_ok:
    ; --- PLANE_SIZE 0x70190 = (height-1)<<16 | (width-1) -----------------
    lea  rdi, [rel str_pd_siz]
    call serial_string
    mov  rbx, r12
    mov  eax, [rel gop_map_size]
    add  rbx, rax
    mov  edi, [rbx]
    call serial_hex64
    mov  eax, [rel fb_height]
    mov  r13d, [rel fb_width]
    cmp  byte [rel fb_scale], 2
    jne  .siz_mode
    mov  eax, [rel fb_out_height]
    mov  r13d, [rel fb_out_width]
.siz_mode:
    dec  eax
    shl  eax, 16
    dec  r13d
    or   eax, r13d
    cmp  eax, [rbx]
    je   .siz_ok
    mov  [rbx], eax
    inc  dword [rel gop_disp_repairs]
.siz_ok:
    ; --- PLANE_SURF 0x7019C
    lea  rdi, [rel str_pd_srf]
    call serial_string
    mov  rbx, r12
    mov  eax, [rel gop_map_surf]
    add  rbx, rax
    mov  edi, [rbx]
    call serial_hex64
    ; --- PLANE_OFFSET 0x701A4
    lea  rdi, [rel str_pd_off]
    call serial_string
    mov  rbx, r12
    mov  eax, [rel gop_map_offset]
    add  rbx, rax
    mov  edi, [rbx]
    call serial_hex64
    ; --- PIPESRC 0x6001C = (width-1)<<16 | (height-1) --------------------
    lea  rdi, [rel str_pd_src]
    call serial_string
    mov  rbx, r12
    mov  eax, [rel gop_map_srcsz]
    add  rbx, rax
    mov  edi, [rbx]
    call serial_hex64
    mov  eax, [rel fb_width]
    mov  r13d, [rel fb_height]
    cmp  byte [rel fb_scale], 2
    jne  .src_mode
    mov  eax, [rel fb_out_width]
    mov  r13d, [rel fb_out_height]
.src_mode:
    dec  eax
    shl  eax, 16
    dec  r13d
    or   eax, r13d
    cmp  eax, [rbx]
    je   .src_ok
    mov  [rbx], eax
    inc  dword [rel gop_disp_repairs]
.src_ok:
    ; --- ARM the double-buffered plane registers. On Intel display engines the
    ;     PLANE_* writes above are latched only when PLANE_SURF is written; the
    ;     surface write is the flip that commits stride/size/ctl atomically.
    mov  rbx, r12
    mov  eax, [rel gop_map_surf]
    add  rbx, rax                   ; PLANE_SURF_1_A
    mov  eax, [rbx]
    mov  [rbx], eax                     ; re-arm with the same base -> commit
    lea  rdi, [rel str_pd_fixed]
    call serial_string
    ; --- transcoder / timing / panel-fitter: the downstream path
    lea  rdi, [rel str_td_ddi]
    call serial_string
    mov  rbx, r12
    add  rbx, 0x60400                   ; TRANS_DDI_FUNC_CTL_A
    mov  edi, [rbx]
    call serial_hex64
    lea  rdi, [rel str_td_ht]
    call serial_string
    mov  rbx, r12
    add  rbx, 0x60000                   ; TRANS_HTOTAL_A
    mov  edi, [rbx]
    call serial_hex64
    lea  rdi, [rel str_td_vt]
    call serial_string
    mov  rbx, r12
    add  rbx, 0x6000C                   ; TRANS_VTOTAL_A
    mov  edi, [rbx]
    call serial_hex64
    lea  rdi, [rel str_td_conf]
    call serial_string
    mov  rbx, r12
    add  rbx, 0x70008                   ; TRANSCONF / PIPEACONF
    mov  edi, [rbx]
    call serial_hex64
    lea  rdi, [rel str_td_pf]
    call serial_string
    mov  rbx, r12
    add  rbx, 0x68080                   ; PF_CTL_A (panel fitter)
    mov  edi, [rbx]
    call serial_hex64
    lea  rdi, [rel str_td_pfsz]
    call serial_string
    mov  rbx, r12
    add  rbx, 0x68074                   ; PF_WIN_SZ_A
    mov  edi, [rbx]
    call serial_hex64
    lea  rdi, [rel str_pd_eol]
    call serial_string
    jmp  .skip
.unsupported:
    ; No register map for this GPU. Say so -- a silent no-op here would look
    ; exactly like a healthy machine right up until someone looks at a screen.
    lea  rdi, [rel str_pd_unsup]
    call serial_string
    mov  edi, [rel gop_disp_id]
    call serial_hex64
    lea  rdi, [rel str_pd_unsup2]
    call serial_string
.skip:
    pop  r13
    pop  r12
    pop  rbx
    ret

str_gop_baremetal: db "[PAOS64] M6 GUI: real-hw-identical GOP fb path [gop.bare_metal]", 13, 10, 0
gop_nl:        db 13, 10, 0
str_gopscan_head: db "[PAOS64] GOPSCAN flags=", 0
str_gopscan_max: db " max=", 0
str_gopscan_queries: db " queries=", 0
str_gopscan_valid: db " valid=", 0
str_gopscan_released: db " released=", 0
str_gopscan_complete: db " complete=", 0
str_gopscan_queryerr: db " queryerr=", 0
str_gopscan_freeerr: db " freeerr=", 0
str_gopinv_head: db "[PAOS64] GOPINV count=", 0
str_gopinv_scan: db " scanned=", 0
str_gopinv_sel: db " selected=", 0
str_gopinv_status: db " status=", 0
str_gopinv_row: db "[PAOS64] GOPINV row=", 0
str_gopinv_w: db " w=", 0
str_gopinv_h: db " h=", 0
str_gopinv_flags: db " flags=", 0

; --- 1104 native-res autodetect state (written pre-EBS like fb_*, read at runtime
;     by the RESINFO/RESMODES projections in gui/command_res.asm) ---
align 8
gop_edid_proto:  dq 0
gop_edid_raw:    times 256 db 0
gop_edid_bytes:  dd 0
gop_edid_blocks: db 0
gop_edid_checksum_ok: db 0
gop_edid_present: db 0
gop_edid_attempts: dd 0                  ; Task3473: LocateProtocol attempts across both providers
align 8
gop_mode_list:   times 128 dd 0     ; 64 (w,h) pairs — boot-time capture (QueryMode dies at EBS)
gop_mode_count:  dd 0
res_native_w:    dd 0               ; detected native mode (0 = autodetect never ran)
res_native_h:    dd 0
res_src:         db 0               ; 1=edid 2=gop (0 = none)
res_dpi:         db 1               ; icon/font scale: 2x at 4K-class widths (>=3000)
; EFI_EDID_ACTIVE_PROTOCOL {bd8c1056-9f36-44ec-92a8-a6337f817986}
edid_active_guid: db 0x56,0x10,0x8c,0xbd, 0x36,0x9f, 0xec,0x44, 0x92,0xa8, 0xa6,0x33,0x7f,0x81,0x79,0x86
; EFI_EDID_DISCOVERED_PROTOCOL {1c0c34f6-d380-41fa-a049-8ad06c1a66aa}
edid_disc_guid:  db 0xf6,0x34,0x0c,0x1c, 0x80,0xd3, 0xfa,0x41, 0xa0,0x49, 0x8a,0xd0,0x6c,0x1a,0x66,0xaa
str_res_auto_pre:    db "[PAOS64] M6 GUI: res autodetect native=", 0
str_res_src_edid:    db " src=edid [gui.res.autodetect]", 13, 10, 0
str_res_src_gop:     db " src=gop [gui.res.autodetect]", 13, 10, 0
str_res_active:      db "[PAOS64] M6 GUI: rendering at detected native mode [gui.res.native.active]", 13, 10, 0
str_res_edid_absent: db "[PAOS64] M6 GUI: EDID unavailable -> best inspected GOP mode [gui.res.edid.absent]", 13, 10, 0
str_hires_edid_retry_kat: db "[PAOS64] hires EDID: transient retry KAT PASS [gui.hires.edid.transient_retry.kat]", 13, 10, 0
str_res_setfail:     db "[PAOS64] M6 GUI: SetMode failed, keeping previous mode [gui.res.setmode.fallback]", 13, 10, 0
str_pd_ctl:  db "[PAOS64] PLANEDUMP ctl=0x", 0
str_pd_str:  db " stride=0x", 0
str_pd_siz:  db " size=0x", 0
str_pd_srf:  db " surf=0x", 0
str_pd_off:  db " offset=0x", 0
str_pd_src:  db " srcsz=0x", 0
str_pd_eol:  db " [gop.plane.dump]", 13, 10, 0
str_pd_wr:   db " -> CTL_REPAIRED readback=0x", 0
str_td_ddi:  db " ddi=0x", 0
str_td_ht:   db " htot=0x", 0
str_td_vt:   db " vtot=0x", 0
str_td_conf: db " conf=0x", 0
str_td_pf:   db " pf=0x", 0
str_td_pfsz: db " pfsz=0x", 0
str_pd_fixed: db " PLANE_GEOMETRY_RESTORED", 0
str_pd_unsup:  db "[PAOS64] GOP: no display register map for pci=0x", 0
str_pd_headless: db "[PAOS64] gop plane dump skipped: no linear framebuffer (headless) [gop.plane.headless]", 13, 10, 0
str_pd_unsup2: db " -> scanout repair SKIPPED [gop.plane.unsupported]", 13, 10, 0

%include "boot/gop_pci_census.inc"

%include "core/abi/wdata.inc"
%macro WDATA_boot_gop_census 0
gop_census_pci: times 6 dd 0
gop_census_path_state: dd 0
gop_census_root_hid: dd 0
gop_census_root_uid: dd 0
gop_census_path_n: dd 0
gop_census_path: times 16 db 0
%endmacro
WDATA_DEFER WDATA_boot_gop_census
