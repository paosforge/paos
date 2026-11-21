;; MODULE dev/net/cdc_ecm
;; LAYER 3
;; EXPORTS cdc_ecm_port_owned, cdc_ecm_selftest, cdc_ecm_create, cdc_ecm_frame_stats, cdc_ecm_usb_counters
;; IMPORTS boot/native_driver_gate, usb/enum, net/netdev, boot/serial, core/lib/fmt, core/lib/str, dev/net/ax88179, dev/net/ax88179b, dev/net/ax88179b_attach
;; CAPS
;; OWNER saga:net
%include "boot/native_driver_gate.inc"
; ============================================================================
; dev/net/cdc_ecm.asm — USB CDC-ECM Ethernet backend (the FIRST USB-NIC on the
; rework's netdev_ops seam). Post-USB-enum class consumer (like dev/usb/hid): it
; iterates the usb/enum device table, GET_DESCRIPTOR(CONFIG)s each device, walks
; the config for a CDC-ECM comm interface (class 0x02 / subclass 0x06) + its
; paired CDC-DATA interface (class 0x0A) alt-setting carrying two BULK endpoints,
; then binds it: SET_CONFIGURATION -> SET_INTERFACE(data,alt) -> configure the
; bulk endpoints -> SET_ETHERNET_PACKET_FILTER -> register on netdev_ops.
;
; Data path: tx = usbhc_ops.bulk_out(port,out_ep,frame,len); rx_poll =
; usbhc_ops.bulk_in(port,in_ep,buf,cap). CDC-ECM carries RAW Ethernet frames on
; the bulk pipes (no per-frame class header, unlike NCM/RNDIS).
;
; HC op calling convention is SELF-LESS (xhci_op_* read RSI/RDX/RCX/R8, not RDI):
;   control : RSI=usb_setup*, RDX=dev_addr(port), RCX=buf, R8=cap  -> RAX len/-1
;   bulk_in : RSI=port, RDX=ep_addr, RCX=buf, R8=len               -> RAX len/-1
;   bulk_out: RSI=port, RDX=ep_addr, RCX=buf, R8=len               -> RAX len/-1
;   configure_ep: RSI=port, RDX=usb_endpoint_desc*                 -> RAX 0/-1
; QEMU: `-device usb-net,netdev=X` exposes a CDC-ECM configuration (walked here,
; not hardcoded). Metal (Task follow-on): ASIX AX88179 rides this same seam.
; ============================================================================

; --- USB constants ---
CDCE_DT_CONFIG        equ 2
CDCE_DT_STRING        equ 3
CDCE_DT_INTERFACE     equ 4
CDCE_DT_ENDPOINT      equ 5
CDCE_DT_CS_INTERFACE  equ 0x24
CDCE_ECM_FUNC_SUBTYPE equ 0x0F        ; Ethernet Networking functional descriptor
CDCE_CLASS_COMM       equ 0x02        ; CDC control interface class
CDCE_SUBCLASS_ECM     equ 0x06        ; Ethernet Control Model
CDCE_CLASS_DATA       equ 0x0A        ; CDC data interface class
CDCE_XFER_BULK        equ 0x02        ; bmAttributes & 0x03
CDCE_EP_IN            equ 0x80        ; bEndpointAddress direction bit

; --- USB request codes / bmRequestType ---
CDCE_REQ_GET_DESCRIPTOR    equ 6
CDCE_REQ_SET_CONFIGURATION equ 9
CDCE_REQ_SET_INTERFACE     equ 11
CDCE_REQ_SET_ETH_FILTER    equ 0x43   ; CDC ECM SET_ETHERNET_PACKET_FILTER
CDCE_RT_H2D_STD_DEV        equ 0x00   ; host->dev, standard, device
CDCE_RT_D2H_STD_DEV        equ 0x80   ; dev->host, standard, device
CDCE_RT_H2D_STD_IF         equ 0x01   ; host->dev, standard, interface
CDCE_RT_H2D_CLASS_IF       equ 0x21   ; host->dev, class, interface
; SET_ETHERNET_PACKET_FILTER wValue bits: PROMISCUOUS|ALL_MCAST|DIRECTED|BROADCAST|MCAST
CDCE_PKT_FILTER            equ 0x000C   ; SEC-S7a: DIRECTED|BROADCAST only (no PROMISCUOUS/ALL_MCAST)

; ============================================================================
; cdc_ecm_selftest — probe + bind + register. Called from boot AFTER
; usb_enum_selftest (the device table must be populated). Degrade-never-wedge:
; no adapter -> skip marker, boot continues on the other NICs / loopnet.
; ============================================================================
cdc_ecm_selftest:
    NATIVE_DRIVER_REFUSE 10, 0
    push rbx
    push r12
    push r13
    push r14
    push r15
    ; --- iterate the enumerated USB device table ---
    call usb_dev_count
    mov  r15d, eax                     ; r15 = device count
    xor  r14d, r14d                    ; r14 = index
.dev_loop:
    cmp  r14d, r15d
    jae  .none
    mov  edi, r14d
    call usb_dev_is_null
    test eax, eax
    jnz  .dev_next
    mov  edi, r14d
    call usb_dev_hc                    ; RAX = hc dev*
    test rax, rax
    jz   .dev_next
    mov  [rel cdc_ecm_hc], rax
    mov  rbx, [rax + dev.ops]          ; usbhc_ops*
    mov  [rel cdc_ecm_hcops], rbx
    mov  edi, r14d
    call usb_dev_addr                  ; RAX = root-hub port (dev_addr)
    test eax, eax
    jz   .dev_next
    mov  [rel cdc_ecm_port], al
    ; Never reconfigure a bound vendor port, even if its cached identity differs
    ; from the vendor driver's fresh read. Reserve legacy identities after a
    ; failed bind too; other ASIX devices may expose standard class functions.
    mov  rdi, [rel cdc_ecm_hc]
    movzx esi, byte [rel cdc_ecm_port]
    call ax88179_port_owned
    test eax, eax
    jnz  .dev_next
    call ax88179b_port_owned              ; failed newer attempts retain the HC/port claim
    test eax, eax
    jnz  .dev_next
    mov  edi, r14d
    call usb_dev_desc_ptr              ; RAX = cached device descriptor (0 = none)
    test rax, rax
    jz   .vid_ok
    mov  rdi, rax
    mov  esi, 18
    call ax88179_claims_desc
    test eax, eax
    jnz  .dev_next
    call ax88179b_claims_desc              ; reserve exact newer profile even if its HC cannot bind
    test eax, eax
    jnz  .dev_next
    mov  rax, rdi                     ; predicate preserves pointer for config count
.vid_ok:
    ; --- try the device's own configuration indices (at most 4) for a CDC-ECM
    ;     interface set. An index >= bNumConfigurations is a Request Error the
    ;     device answers with a STALL (USB 2.0 9.4.3), so read the count first;
    ;     without a cached device descriptor only index 0 is certain to exist. ---
    mov  byte [rel cdc_ecm_ncfg], 1
    test rax, rax
    jz   .ncfg_ok
    movzx ecx, byte [rax + 17]         ; bNumConfigurations
    test ecx, ecx
    jz   .ncfg_ok
    cmp  ecx, 4
    jbe  .ncfg_store
    mov  ecx, 4
.ncfg_store:
    mov  [rel cdc_ecm_ncfg], cl
.ncfg_ok:
    xor  r13d, r13d                    ; r13 = config descriptor index
.cfg_loop:
    movzx eax, byte [rel cdc_ecm_ncfg]
    cmp  r13d, eax
    jae  .dev_next
    mov  dl, r13b
    call cdc_ecm_get_config_desc       ; -> RAX = bytes read (0 = fail)
    cmp  rax, 9                        ; failed or shorter than a config header: never a walk length
    jl   .dev_next
    mov  r12, rax                      ; preserve full completion width for admission
    call cdc_ecm_walk_config           ; -> RAX=1 found (fills port/config/data_if/eps), 0 no
    test rax, rax
    jnz  .bind
    inc  r13d
    jmp  .cfg_loop
.dev_next:
    inc  r14d
    jmp  .dev_loop

.bind:
    ; RCQ-10 (as ax88179 4fcd9b8a6): the bind is all-or-nothing. The first failed
    ; step stops all further transfers, is reported, and leaves the device
    ; unregistered with cdc_ecm_present=0; the boot continues to the onboard NICs.
    ; --- SET_CONFIGURATION(cdc_ecm_config) ---
    mov  byte [rel cdc_ecm_bind_step], 1
    movzx edx, byte [rel cdc_ecm_config]
    call cdc_ecm_set_configuration
    test rax, rax
    js   .bind_failed
    ; --- SET_INTERFACE(data_if, data_alt) to enable the bulk endpoints ---
    mov  byte [rel cdc_ecm_bind_step], 2
    call cdc_ecm_set_interface
    test rax, rax
    js   .bind_failed
    ; --- configure the two bulk endpoints via the HC seam ---
    mov  byte [rel cdc_ecm_bind_step], 3
    lea  rdx, [rel cdc_ecm_in_ep_desc]
    call cdc_ecm_configure_ep
    mov  [rel cdc_ecm_cfg_in_rc], eax
    test rax, rax
    js   .bind_failed
    mov  byte [rel cdc_ecm_bind_step], 4
    lea  rdx, [rel cdc_ecm_out_ep_desc]
    call cdc_ecm_configure_ep
    mov  [rel cdc_ecm_cfg_out_rc], eax
    test rax, rax
    js   .bind_failed
    ; --- read the device MAC (ECM iMACAddress string descriptor) ---
    mov  byte [rel cdc_ecm_bind_step], 5
    call cdc_ecm_read_mac
    test rax, rax
    js   .bind_failed
    ; --- SET_ETHERNET_PACKET_FILTER so we actually receive frames ---
    mov  byte [rel cdc_ecm_bind_step], 6
    call cdc_ecm_set_packet_filter
    cmp  rax, -2                       ; STALL: the optional request is unsupported, default filter
    je   .filter_ok                    ; stays (Linux cdc_ether ignores it too); a timeout is fatal
    test rax, rax
    js   .bind_failed
.filter_ok:
    mov  byte [rel cdc_ecm_present], 1
    ; --- register on the netdev seam ---
    call cdc_ecm_create
    ; --- earned marker + diag. HONEST: the registered marker is earned ONLY when
    ;     netdev_register actually took the handle; a rejecting table (full) prints
    ;     its own marker so a "registered" line can never mask an unselectable NIC. ---
    cmp  dword [rel cdc_ecm_reg_rc], 0
    jl   .reg_rejected
    lea  rdi, [rel str_cdce_registered]
    call serial_string
    call cdc_ecm_emit_diag
    jmp  .done
.reg_rejected:
    lea  rdi, [rel str_cdce_reg_rejected]
    call serial_string
    call cdc_ecm_emit_diag
    jmp  .done

.bind_failed:
    lea  rdi, [rel str_cdce_bind_failed]
    call serial_string
    movzx edi, byte [rel cdc_ecm_bind_step]
    call serial_hex64
    lea  rdi, [rel str_cdce_bind_failed_tail]
    call serial_string
    jmp  .done
.none:
    lea  rdi, [rel str_cdce_skipped]
    call serial_string
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; cdc_ecm_get_config_desc(DL = config index) -> RAX = bytes read into cfgbuf.
; Two reads would be cleaner (9 bytes -> wTotalLength) but QEMU/most devices
; return the full config in one shot; we request the whole buffer capacity and
; trust the returned length: the bytes the device actually sent (the HC seam
; subtracts the short-packet residual), so the walk never reaches a stale tail.
; ---------------------------------------------------------------------------
cdc_ecm_get_config_desc:
    push rbx
    movzx ebx, dl
    lea  rdi, [rel cdc_ecm_setup]
    mov  byte [rdi + usb_setup.bmRequestType], CDCE_RT_D2H_STD_DEV
    mov  byte [rdi + usb_setup.bRequest], CDCE_REQ_GET_DESCRIPTOR
    ; wValue = (CONFIG<<8) | index
    mov  eax, (CDCE_DT_CONFIG << 8)
    or   eax, ebx
    mov  word [rdi + usb_setup.wValue], ax
    mov  word [rdi + usb_setup.wIndex], 0
    mov  word [rdi + usb_setup.wLength], CDCE_CFGBUF_SZ
    ; issue control: RSI=setup, RDX=port, RCX=buf, R8=cap
    mov  rsi, rdi
    movzx edx, byte [rel cdc_ecm_port]
    lea  rcx, [rel cdc_ecm_cfgbuf]
    mov  r8d, CDCE_CFGBUF_SZ
    mov  rax, [rel cdc_ecm_hcops]
    mov  rax, [rax + usbhc_ops.control]
    call rax
%ifdef PAOS_LAB_EP0_PROBE
    call cdc_ecm_lab_cfg_line
%endif
    test rax, rax
    js   .fail
    pop  rbx
    ret
.fail:
    xor  eax, eax
    pop  rbx
    ret

%ifdef PAOS_LAB_EP0_PROBE
; cdc_ecm_lab_cfg_line(RAX = control rc, EBX = index) -> RAX preserved. Lab only:
; "CDCECMCFG port= idx= rc= total=" (total = the buffer's wTotalLength), so a run
; shows which indices were asked for and whether rc covered only fresh bytes.
cdc_ecm_lab_cfg_line:
    push rax
    lea  rdi, [rel str_cdce_lab_port]
    call serial_string
    movzx edi, byte [rel cdc_ecm_port]
    call serial_hex64
    lea  rdi, [rel str_cdce_lab_idx]
    call serial_string
    mov  edi, ebx
    call serial_hex64
    lea  rdi, [rel str_cdce_lab_rc]
    call serial_string
    mov  edi, [rsp]
    call serial_hex64
    lea  rdi, [rel str_cdce_lab_total]
    call serial_string
    movzx edi, word [rel cdc_ecm_cfgbuf + 2]
    call serial_hex64
    lea  rdi, [rel str_cdce_lab_nl]
    call serial_string
    pop  rax
    ret
str_cdce_lab_port:  db "CDCECMCFG port=", 0
str_cdce_lab_idx:   db " idx=", 0
str_cdce_lab_rc:    db " rc=", 0
str_cdce_lab_total: db " total=", 0
str_cdce_lab_nl:    db 13, 10, 0
%endif

; ---------------------------------------------------------------------------
; cdc_ecm_walk_config(R12 = cfg length) -> RAX = 1 if a complete CDC-ECM set
; (owned comm IF class2/sub6 + Union-named data IF alt with 2 bulk eps) found; fills
; cdc_ecm_config / cdc_ecm_data_if / cdc_ecm_data_alt / in_ep / out_ep + the two
; endpoint-descriptor copies for configure_ep. Bounded TLV walk.
; ---------------------------------------------------------------------------
cdc_ecm_walk_config:
    push rbx
    push r13
    push r14
    ; reset findings
    mov  byte [rel cdc_ecm_have_comm], 0
    mov  byte [rel cdc_ecm_have_union], 0
    mov  byte [rel cdc_ecm_have_ethernet], 0
    mov  byte [rel cdc_ecm_have_data], 0
    mov  byte [rel cdc_ecm_in_ep], 0
    mov  byte [rel cdc_ecm_out_ep], 0
    mov  byte [rel cdc_ecm_in_ep_valid], 0
    mov  byte [rel cdc_ecm_out_ep_valid], 0
    mov  byte [rel cdc_ecm_imac_idx], 0
    ; config value from the header (offset 5)
    lea  rbx, [rel cdc_ecm_cfgbuf]
    cmp  r12, 9
    jb   .wl_fail
    cmp  r12, CDCE_CFGBUF_SZ
    ja   .wl_fail
    cmp  byte [rbx], 9
    jne  .wl_fail
    cmp  byte [rbx + 1], CDCE_DT_CONFIG
    jne  .wl_fail
    cmp  byte [rbx + 5], 0
    je   .wl_fail
    movzx ecx, word [rbx + 2]          ; walk only the declared complete configuration
    cmp  ecx, 9
    jb   .wl_fail
    cmp  rcx, r12
    ja   .wl_fail
    movzx eax, byte [rbx + 5]
    mov  [rel cdc_ecm_config], al
    ; walk TLVs: rbx = ptr, r14 = end
    lea  r14, [rbx + rcx]
    xor  r13d, r13d                    ; 1 = owned data alt, 2 = selected comm IF
.wl:
    cmp  rbx, r14
    je   .wl_done
    lea  rax, [rbx + 2]
    cmp  rax, r14
    ja   .wl_fail
    movzx eax, byte [rbx]              ; bLength
    cmp  eax, 2
    jb   .wl_fail
    lea  rcx, [rbx + rax]
    cmp  rcx, r14
    ja   .wl_fail                      ; no field read or EP copy outside this record
    movzx ecx, byte [rbx + 1]          ; bDescriptorType
    cmp  ecx, CDCE_DT_INTERFACE
    je   .wl_iface
    cmp  ecx, CDCE_DT_ENDPOINT
    je   .wl_endp
    cmp  ecx, CDCE_DT_CS_INTERFACE
    je   .wl_csif
    jmp  .wl_next
.wl_csif:
    cmp  eax, 3
    jb   .wl_fail
    cmp  r13d, 2
    jne  .wl_next                     ; class descriptors belong to this interface
    movzx edx, byte [rbx + 2]
    cmp  edx, 6                       ; CDC Union functional descriptor
    jne  .wl_ethernet
    cmp  eax, 5                       ; supported shape: exactly one subordinate
    jne  .wl_fail
    cmp  byte [rel cdc_ecm_have_union], 0
    jne  .wl_fail                     ; ambiguous duplicate union is unsupported
    mov  dl, [rbx + 3]
    cmp  dl, [rel cdc_ecm_comm_if]
    jne  .wl_fail                     ; controlling interface must be our comm IF
    mov  dl, [rbx + 4]
    cmp  dl, [rel cdc_ecm_comm_if]
    je   .wl_fail
    mov  [rel cdc_ecm_union_slave], dl
    mov  byte [rel cdc_ecm_have_union], 1
    jmp  .wl_next
.wl_ethernet:
    cmp  edx, CDCE_ECM_FUNC_SUBTYPE
    jne  .wl_next
    cmp  eax, 4
    jb   .wl_fail
    cmp  byte [rel cdc_ecm_have_ethernet], 0
    jne  .wl_fail
    mov  dl, [rbx + 3]                ; owned iMACAddress (zero retains LAA fallback)
    mov  [rel cdc_ecm_imac_idx], dl
    mov  byte [rel cdc_ecm_have_ethernet], 1
    jmp  .wl_next
.wl_iface:
    cmp  eax, 9
    jb   .wl_fail
    ; bInterfaceNumber@2 bAlternateSetting@3 bNumEndpoints@4 bClass@5 bSubClass@6
    xor  r13d, r13d                    ; leaving any prior data-IF context
    movzx edx, byte [rbx + 5]          ; class
    cmp  edx, CDCE_CLASS_COMM
    jne  .wl_chk_data
    movzx edx, byte [rbx + 6]
    cmp  edx, CDCE_SUBCLASS_ECM
    jne  .wl_next
    cmp  byte [rbx + 3], 0             ; select the default comm alternate only
    jne  .wl_next
    cmp  byte [rel cdc_ecm_have_comm], 0
    jne  .wl_next                     ; first ECM function only
    mov  dl, [rbx + 2]
    mov  [rel cdc_ecm_comm_if], dl
    mov  byte [rel cdc_ecm_have_comm], 1
    mov  r13d, 2
    jmp  .wl_next
.wl_chk_data:
    cmp  edx, CDCE_CLASS_DATA
    jne  .wl_next
    cmp  byte [rel cdc_ecm_have_union], 1
    jne  .wl_next
    mov  dl, [rbx + 2]
    cmp  dl, [rel cdc_ecm_union_slave]
    jne  .wl_next                     ; never borrow a foreign function's data IF
    movzx edx, byte [rbx + 4]          ; bNumEndpoints
    cmp  edx, 2
    jb   .wl_next                      ; alt 0 (no endpoints) -> not the data alt
    ; Keep the first complete pair with its interface/alternate. A later
    ; candidate may replace only an incomplete pair, never combine with it.
    cmp  byte [rel cdc_ecm_in_ep_valid], 1
    jne  .wl_data_candidate
    cmp  byte [rel cdc_ecm_out_ep_valid], 1
    je   .wl_next
.wl_data_candidate:
    mov  byte [rel cdc_ecm_in_ep_valid], 0
    mov  byte [rel cdc_ecm_out_ep_valid], 0
    ; this is the data-IF alt carrying bulk eps -> record it + arm endpoint capture
    movzx eax, byte [rbx + 2]
    mov  [rel cdc_ecm_data_if], al
    movzx eax, byte [rbx + 3]
    mov  [rel cdc_ecm_data_alt], al
    mov  byte [rel cdc_ecm_have_data], 1
    mov  r13d, 1
    jmp  .wl_next
.wl_endp:
    cmp  eax, 7
    jb   .wl_fail
    cmp  r13d, 1                      ; only capture endpoints of our data-IF alt
    jne  .wl_next
    ; bEndpointAddress@2 bmAttributes@3
    movzx edx, byte [rbx + 3]
    and  edx, 0x03
    cmp  edx, CDCE_XFER_BULK
    jne  .wl_next
    movzx eax, byte [rbx + 2]          ; bEndpointAddress
    test al, CDCE_EP_IN
    jz   .wl_out
    ; IN endpoint
    mov  [rel cdc_ecm_in_ep], al
    mov  byte [rel cdc_ecm_in_ep_valid], 1
    ; copy the endpoint descriptor for configure_ep
    lea  rdi, [rel cdc_ecm_in_ep_desc]
    call cdc_ecm_copy_ep_desc
    jmp  .wl_next
.wl_out:
    mov  [rel cdc_ecm_out_ep], al
    mov  byte [rel cdc_ecm_out_ep_valid], 1
    lea  rdi, [rel cdc_ecm_out_ep_desc]
    call cdc_ecm_copy_ep_desc
.wl_next:
    movzx eax, byte [rbx]              ; advance by bLength
    add  rbx, rax
    jmp  .wl
.wl_done:
    ; Success requires one associated comm/union/ethernet/data function.
    xor  eax, eax
    cmp  byte [rel cdc_ecm_have_comm], 1
    jne  .wl_ret
    cmp  byte [rel cdc_ecm_have_union], 1
    jne  .wl_ret
    cmp  byte [rel cdc_ecm_have_ethernet], 1
    jne  .wl_ret
    cmp  byte [rel cdc_ecm_have_data], 1
    jne  .wl_ret
    cmp  byte [rel cdc_ecm_in_ep_valid], 1
    jne  .wl_ret
    cmp  byte [rel cdc_ecm_out_ep_valid], 1
    jne  .wl_ret
    mov  eax, 1
    jmp  .wl_ret
.wl_fail:
    xor  eax, eax                     ; malformed tail cannot publish a valid prefix
.wl_ret:
    pop  r14
    pop  r13
    pop  rbx
    ret

; copy a 7-byte endpoint descriptor from [rbx] to [rdi] (bounded).
cdc_ecm_copy_ep_desc:
    push rsi
    push rcx
    mov  rsi, rbx
    mov  ecx, usb_endpoint_desc_size
    cmp  ecx, 7
    jbe  .cp
    mov  ecx, 7
.cp:
    rep  movsb
    pop  rcx
    pop  rsi
    ret

; ---------------------------------------------------------------------------
; Small control-transfer helpers (no data stage unless noted).
; ---------------------------------------------------------------------------
; cdc_ecm_set_configuration(DL = config value)
cdc_ecm_set_configuration:
    lea  rdi, [rel cdc_ecm_setup]
    mov  byte [rdi + usb_setup.bmRequestType], CDCE_RT_H2D_STD_DEV
    mov  byte [rdi + usb_setup.bRequest], CDCE_REQ_SET_CONFIGURATION
    movzx eax, dl
    mov  word [rdi + usb_setup.wValue], ax
    mov  word [rdi + usb_setup.wIndex], 0
    mov  word [rdi + usb_setup.wLength], 0
    jmp  cdc_ecm_ctrl_nodata

; cdc_ecm_set_interface — SET_INTERFACE(cdc_ecm_data_if, cdc_ecm_data_alt)
cdc_ecm_set_interface:
    lea  rdi, [rel cdc_ecm_setup]
    mov  byte [rdi + usb_setup.bmRequestType], CDCE_RT_H2D_STD_IF
    mov  byte [rdi + usb_setup.bRequest], CDCE_REQ_SET_INTERFACE
    movzx eax, byte [rel cdc_ecm_data_alt]
    mov  word [rdi + usb_setup.wValue], ax
    movzx eax, byte [rel cdc_ecm_data_if]
    mov  word [rdi + usb_setup.wIndex], ax
    mov  word [rdi + usb_setup.wLength], 0
    jmp  cdc_ecm_ctrl_nodata

; cdc_ecm_set_packet_filter — CDC class request on the comm interface
cdc_ecm_set_packet_filter:
    lea  rdi, [rel cdc_ecm_setup]
    mov  byte [rdi + usb_setup.bmRequestType], CDCE_RT_H2D_CLASS_IF
    mov  byte [rdi + usb_setup.bRequest], CDCE_REQ_SET_ETH_FILTER
    mov  word [rdi + usb_setup.wValue], CDCE_PKT_FILTER
    movzx eax, byte [rel cdc_ecm_comm_if]
    mov  word [rdi + usb_setup.wIndex], ax
    mov  word [rdi + usb_setup.wLength], 0
    jmp  cdc_ecm_ctrl_nodata

; issue the setup packet in cdc_ecm_setup with no data stage.
cdc_ecm_ctrl_nodata:
    lea  rsi, [rel cdc_ecm_setup]
    movzx edx, byte [rel cdc_ecm_port]
    xor  ecx, ecx
    xor  r8d, r8d
    mov  rax, [rel cdc_ecm_hcops]
    mov  rax, [rax + usbhc_ops.control]
    call rax
    ret

; cdc_ecm_configure_ep(RDX = usb_endpoint_desc*) via the HC seam.
cdc_ecm_configure_ep:
    movzx esi, byte [rel cdc_ecm_port]
    mov  rax, [rel cdc_ecm_hcops]
    mov  rax, [rax + usbhc_ops.configure_ep]
    call rax
    ret

; cdc_ecm_read_mac — GET_DESCRIPTOR(STRING, iMACAddress) then parse the 12
; UTF-16LE hex chars into cdc_ecm_mac[6]. Falls back to a locally-administered
; MAC (…:EC) only when no string index is supplied. A malformed advertised
; string fails binding rather than publishing a fabricated address.
cdc_ecm_read_mac:
    push rbx
    ; default LAA fallback
    mov  byte [rel cdc_ecm_mac + 0], 0x02
    mov  byte [rel cdc_ecm_mac + 1], 0x00
    mov  byte [rel cdc_ecm_mac + 2], 0x00
    mov  byte [rel cdc_ecm_mac + 3], 0x00
    mov  byte [rel cdc_ecm_mac + 4], 0x00
    mov  byte [rel cdc_ecm_mac + 5], 0xEC
    movzx ebx, byte [rel cdc_ecm_imac_idx]
    test bl, bl
    jz   .done                          ; no string index -> keep LAA (unchanged)
    ; GET_DESCRIPTOR(STRING index=bl, langid 0x0409) into strbuf
    lea  rdi, [rel cdc_ecm_setup]
    mov  byte [rdi + usb_setup.bmRequestType], CDCE_RT_D2H_STD_DEV
    mov  byte [rdi + usb_setup.bRequest], CDCE_REQ_GET_DESCRIPTOR
    mov  eax, (CDCE_DT_STRING << 8)
    or   eax, ebx
    mov  word [rdi + usb_setup.wValue], ax
    mov  word [rdi + usb_setup.wIndex], 0x0409
    mov  word [rdi + usb_setup.wLength], 64
    mov  rsi, rdi
    movzx edx, byte [rel cdc_ecm_port]
    lea  rcx, [rel cdc_ecm_strbuf]
    mov  r8d, 64
    mov  rax, [rel cdc_ecm_hcops]
    mov  rax, [rax + usbhc_ops.control]
    call rax
    cmp  rax, 26                         ; 2-byte header + 12 UTF-16 chars actually received
    jl   .fail                          ; -1/-2 or short: the advertised MAC never arrived
    cmp  rax, 64                         ; full-width completion must fit submitted buffer
    ja   .fail
    cmp  byte [rel cdc_ecm_strbuf], 26    ; exactly twelve Unicode characters
    jne  .fail
    cmp  byte [rel cdc_ecm_strbuf + 1], CDCE_DT_STRING
    jne  .fail
    ; string descriptor: [0]=bLength [1]=0x03, then UTF-16LE chars. 12 hex chars.
    lea  rsi, [rel cdc_ecm_strbuf + 2]   ; first UTF-16 char low byte
    lea  rdi, [rel cdc_ecm_mac]
    xor  ecx, ecx                        ; byte index 0..5
.mac_byte:
    cmp  ecx, 6
    jae  .done
    cmp  byte [rsi + 1], 0               ; ASCII hex requires zero UTF-16 high bytes
    jne  .fail
    cmp  byte [rsi + 3], 0
    jne  .fail
    ; high nibble
    movzx eax, byte [rsi]
    call cdc_ecm_hexval
    js   .fail
    shl  al, 4
    mov  dl, al
    add  rsi, 2                          ; skip UTF-16 high byte
    movzx eax, byte [rsi]
    call cdc_ecm_hexval
    js   .fail
    or   dl, al
    add  rsi, 2
    mov  [rdi + rcx], dl
    inc  ecx
    jmp  .mac_byte
.done:
    xor  eax, eax
    pop  rbx
    ret
.fail:
    mov  rax, -1
    pop  rbx
    ret

; cdc_ecm_hexval(EAX = char) -> EAX = 0..15, SF set when not hex
cdc_ecm_hexval:
    sub  eax, '0'
    cmp  eax, 9
    jbe  .ok
    or   eax, 0x20
    sub  eax, 'a' - '0'
    cmp  eax, 5
    ja   .bad
    add  eax, 10
.ok:
    test eax, eax
    ret
.bad:
    mov  eax, -1
    test eax, eax
    ret

; ============================================================================
; cdc_ecm_create — build the netdev_ops vtable (runtime VAs) + register.
; ============================================================================
cdc_ecm_create:
    NATIVE_DRIVER_REFUSE 10
    lea  rdi, [rel cdc_ecm_ops]
    lea  rax, [rel cdc_ecm_init]
    mov  [rdi + netdev_ops.init], rax
    lea  rax, [rel cdc_ecm_start]
    mov  [rdi + netdev_ops.start], rax
    lea  rax, [rel cdc_ecm_stop]
    mov  [rdi + netdev_ops.stop], rax
    lea  rax, [rel cdc_ecm_tx]
    mov  [rdi + netdev_ops.tx], rax
    lea  rax, [rel cdc_ecm_rx_poll]
    mov  [rdi + netdev_ops.rx_poll], rax
    lea  rax, [rel cdc_ecm_link_status]
    mov  [rdi + netdev_ops.link_status], rax
    lea  rax, [rel cdc_ecm_get_mac]
    mov  [rdi + netdev_ops.get_mac], rax
    lea  rax, [rel cdc_ecm_recover]
    mov  [rdi + netdev_ops.recover], rax
    lea  rdi, [rel cdc_ecm_dev]
    lea  rax, [rel cdc_ecm_ops]
    mov  [rdi + dev.ops], rax
    lea  rax, [rel str_cdce_name]
    mov  [rel cdc_ecm_info + netdev_info.name], rax   ; runtime address (abs_ptr_check)
    lea  rax, [rel cdc_ecm_info]
    mov  [rdi + dev.info], rax
    mov  qword [rdi + dev.priv], 0
    ; RCQ-10: one tier below PRIO_NATIVE, as ax88179 (4fcd9b8a6). This class
    ; driver registers during USB bring-up, before the onboard RTL8168, and
    ; egress-select keeps the first of equal priorities. Still a native member
    ; (net tile WARMING) and still the egress on a box without an onboard NIC.
    mov  dword [rdi + dev.prio], PRIO_NATIVE_EXPERIMENTAL
    mov  dword [rdi + dev.health], HEALTH_OK
    mov  dword [rdi + dev.class], CLASS_NET
    mov  dword [rdi + dev.flags], 0
    lea  rax, [rel str_cdce_name]
    mov  [rdi + dev.name], rax
    mov  rax, [rel cdc_ecm_hcops]              ; RCQ-10: the GONE watch (netdev_usbnic_*)
    mov  [rel cdc_ecm_watch + usbnic_watch.hcops], rax
    mov  rax, [rel cdc_ecm_hc]
    mov  [rel cdc_ecm_watch + usbnic_watch.hc], rax
    movzx eax, byte [rel cdc_ecm_port]
    mov  [rel cdc_ecm_watch + usbnic_watch.port], eax
    call netdev_register
    mov  [rel cdc_ecm_reg_rc], eax      ; slot index, or -1 = REJECTED (table full / bad handle)
    ret

; --- netdev_ops implementations ---------------------------------------------
cdc_ecm_init:
    NATIVE_DRIVER_REFUSE 10
    xor  eax, eax
    ret
cdc_ecm_start:
    xor  eax, eax
    ret
cdc_ecm_stop:
    xor  eax, eax
    ret

; tx(self, RSI=frame, RDX=len) -> RAX 0 ok / -1
; BEGIN FRAME STATS -- pure selected-device software readout.
; RDI=self; EAX=0, RDX=RX, RCX=TX, or -1. Aligned qword observations pair
; with LOCK increments; no transactional cross-counter or hardware-read claim.
cdc_ecm_frame_stats:
    lea  rax, [rel cdc_ecm_dev]
    cmp  rdi, rax
    jne  .unavailable
    lea  rax, [rel cdc_ecm_ops]
    cmp  [rdi + dev.ops], rax
    jne  .unavailable
    mov  rdx, [rel cdc_ecm_stat_rx_frames]
    mov  rcx, [rel cdc_ecm_stat_tx_frames]
    xor  eax, eax
    ret
.unavailable:
    mov  rdx, -1
    mov  rcx, -1
    mov  eax, -1
    ret
; END FRAME STATS

; cdc_ecm_usb_counters(RDI=handle, RSI=out 10 qwords) -> EAX 0, or -1 when RDI is
;   not this backend's static device (out untouched). NETCFG USB SHOW readout
;   (ROOT118715): pointer equality only, no transfer, no health or watch change.
;   out: 0 rx_calls 1 rx_frames 2 rx_errors 3 rx_last_rc 4 rx_gated
;        5 tx_calls 6 tx_frames 7 tx_last_rc 8 dev.health 9 watch.streak
cdc_ecm_usb_counters:
    lea  rax, [rel cdc_ecm_dev]
    cmp  rdi, rax
    jne  .unavailable
    mov  eax, [rel cdc_ecm_rx_calls]
    mov  [rsi + 0], rax
    mov  rax, [rel cdc_ecm_stat_rx_frames]
    mov  [rsi + 8], rax
    mov  eax, [rel cdc_ecm_rx_errors]
    mov  [rsi + 16], rax
    mov  rax, [rel cdc_ecm_rx_last_rc]
    mov  [rsi + 24], rax
    mov  eax, [rel cdc_ecm_rx_gated]
    mov  [rsi + 32], rax
    mov  eax, [rel cdc_ecm_tx_calls]
    mov  [rsi + 40], rax
    mov  rax, [rel cdc_ecm_stat_tx_frames]
    mov  [rsi + 48], rax
    mov  rax, [rel cdc_ecm_tx_last_rc]
    mov  [rsi + 56], rax
    mov  eax, [rel cdc_ecm_dev + dev.health]
    mov  [rsi + 64], rax
    mov  eax, [rel cdc_ecm_watch + usbnic_watch.streak]
    mov  [rsi + 72], rax
    xor  eax, eax
    ret
.unavailable:
    mov  eax, -1
    ret

cdc_ecm_tx:
    cmp  dword [rel cdc_ecm_dev + dev.health], HEALTH_DEAD
    je   .err                           ; RCQ-10: never a transfer to a GONE device (DEGRADED still sends)
    test rdx, rdx
    jz   .err                           ; invalid caller input is not a device failure
    cmp  rdx, CDCE_RX_MAX               ; one transfer fits the common HC buffer
    ja   .err
    push rsi
    push rdx
    mov  rcx, rsi                       ; buf
    mov  r8, rdx                        ; len
    movzx esi, byte [rel cdc_ecm_port]  ; port
    movzx edx, byte [rel cdc_ecm_out_ep]; ep
    mov  rax, [rel cdc_ecm_hcops]
    mov  rax, [rax + usbhc_ops.bulk_out]
    call rax
    pop  rdx
    pop  rsi
    push rax
    push rdx
    cmp  rax, rdx                       ; RCQ-10: success = the complete transfer (as the stats)
    sete dl
    movzx edx, dl
    lea  rdi, [rel cdc_ecm_dev]
    lea  rsi, [rel cdc_ecm_watch]
    call netdev_usbnic_io               ; a failed TX may mean GONE / DEGRADED
    pop  rdx
    pop  rax
    cmp  rax, rdx                    ; complete original transfer, not short/error
    jne  .stat_tx_done
    test rdx, rdx
    jz   .stat_tx_done
    lock inc qword [rel cdc_ecm_stat_tx_frames]
.stat_tx_done:
    inc  dword [rel cdc_ecm_tx_calls]
    mov  [rel cdc_ecm_tx_last_rc], rax
    mov  [rel cdc_ecm_tx_last_len], rdx
    cmp  byte [rel cdc_ecm_tx_reported], 4
    jae  .rc
    inc  byte [rel cdc_ecm_tx_reported]
    push rdx
    push rax
    lea  rdi, [rel str_cdce_tx_first]   ; BOUNDED (4 per boot): first TX outcomes through this backend
    call serial_string
    mov  rdi, [rel cdc_ecm_tx_last_rc]
    call serial_hex64
    lea  rdi, [rel str_cdce_len]
    call serial_string
    mov  rdi, [rel cdc_ecm_tx_last_len]
    call serial_hex64
    call serial_newline
    pop  rax
    pop  rdx
.rc:
    cmp  rax, rdx                       ; short/overlong transfers fail the caller too
    jne  .err
    xor  eax, eax
    ret
.err:
    mov  rax, -1
    ret

; rx_poll(self, RSI=buf, RDX=cap) -> RAX = len (0 none / -1 err)
; Clamp to the common HC buffer, and validate the actual completion against
; the submitted caller capacity before treating it as a received frame.
cdc_ecm_rx_poll:
    test rdx, rdx
    jnz  .nonempty
    xor  eax, eax
    ret
.nonempty:
    push rsi
    push rdx
    lea  rdi, [rel cdc_ecm_dev]
    lea  rsi, [rel cdc_ecm_watch]
    call netdev_usbnic_poll             ; RCQ-10: rate-limited CCS; GONE -> nothing, no transfer
    pop  rdx
    pop  rsi
    test rax, rax
    jz   .present
    inc  dword [rel cdc_ecm_rx_gated]   ; GONE gate: no transfer (USB SHOW RXGATE)
    xor  eax, eax
    ret
.present:
    cmp  rdx, CDCE_RX_MAX
    jbe  .cap_ok
    mov  rdx, CDCE_RX_MAX
.cap_ok:
    mov  [rel cdc_ecm_rx_last_buf], rsi ; (diag) the HC call clobbers RSI
    mov  rcx, rsi                       ; buf
    mov  r8, rdx                        ; cap
    movzx esi, byte [rel cdc_ecm_port]
    movzx edx, byte [rel cdc_ecm_in_ep]
    mov  rax, [rel cdc_ecm_hcops]
    mov  rax, [rax + usbhc_ops.bulk_in_poll]   ; non-blocking RX: 0 = nothing yet
    test rax, rax
    jnz  .call
    mov  rax, [rel cdc_ecm_hcops]
    mov  rax, [rax + usbhc_ops.bulk_in]        ; HC without a poll op: blocking fallback
.call:
    push r8                            ; HC may clobber argument registers
    call rax
    pop  r8
    test rax, rax
    js   .rx_count_checked
    cmp  rax, r8
    jbe  .rx_count_checked
    mov  rax, -1                       ; no frame/diagnostic access beyond submitted capacity
.rx_count_checked:
    inc  dword [rel cdc_ecm_rx_calls]
    test rax, rax
    jz   .rx_ret                        ; 0 = nothing queued (the idle case) -> silent
    jns  .rx_err_counted
    inc  dword [rel cdc_ecm_rx_errors]  ; refused/error completion (USB SHOW RXERR)
.rx_err_counted:
    push rax
    xor  edx, edx
    test rax, rax
    js   .rx_noted
    mov  edx, 1
.rx_noted:
    lea  rdi, [rel cdc_ecm_dev]
    lea  rsi, [rel cdc_ecm_watch]
    call netdev_usbnic_rx               ; RCQ-10: RX never re-promotes a DEGRADED member
    pop  rax
    mov  [rel cdc_ecm_rx_last_rc], rax
    cmp  byte [rel cdc_ecm_rx_reported], 4
    jae  .rx_ret
    inc  byte [rel cdc_ecm_rx_reported]
    push rax
    lea  rdi, [rel str_cdce_rx_first]   ; BOUNDED (4 per boot): first non-idle rx_poll outcomes
    call serial_string
    mov  rdi, [rel cdc_ecm_rx_last_rc]
    call serial_hex64
    cmp  qword [rel cdc_ecm_rx_last_rc], 14
    jl   .rx_noet                      ; an error completion owns no Ethernet header
    lea  rdi, [rel str_cdce_et]
    call serial_string
    mov  rsi, [rel cdc_ecm_rx_last_buf]
    movzx edi, word [rsi + 12]          ; ethertype (wire order: 0x0008=IPv4, 0x0608=ARP)
    call serial_hex64
.rx_noet:
    call serial_newline
    pop  rax
.rx_ret:
    test rax, rax
    jle  .stat_rx_done                ; empty/error are not delivered frames
    lock inc qword [rel cdc_ecm_stat_rx_frames]
.stat_rx_done:
    ret

; link_status(self) -> RAX bit0=up | speed<<8. v1: up @ 1Gbps iff bound.
cdc_ecm_link_status:
    xor  eax, eax
    cmp  byte [rel cdc_ecm_present], 1
    jne  .ret
    cmp  dword [rel cdc_ecm_dev + dev.health], HEALTH_DEAD
    je   .ret                           ; RCQ-10: GONE reads down (v1 link is static: no link-up evidence)
    mov  eax, (1000 << 8) | 1
.ret:
    ret

; get_mac(self, RSI=out6) -> RAX 0
cdc_ecm_get_mac:
    lea  rax, [rel cdc_ecm_mac]
    mov  ecx, 6
.cp:
    mov  dl, [rax]
    mov  [rsi], dl
    inc  rax
    inc  rsi
    dec  ecx
    jnz  .cp
    xor  eax, eax
    ret

cdc_ecm_recover:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; cdc_ecm_emit_diag — one content-graded serial line (debuggable, un-latchable).
; ---------------------------------------------------------------------------
cdc_ecm_emit_diag:
    lea  rdi, [rel str_cdce_diag]
    call serial_string
    movzx edi, byte [rel cdc_ecm_port]
    call serial_hex64
    lea  rdi, [rel str_cdce_diag_cfg]
    call serial_string
    movzx edi, byte [rel cdc_ecm_config]
    call serial_hex64
    lea  rdi, [rel str_cdce_diag_if]
    call serial_string
    movzx edi, byte [rel cdc_ecm_data_if]
    call serial_hex64
    lea  rdi, [rel str_cdce_diag_in]
    call serial_string
    movzx edi, byte [rel cdc_ecm_in_ep]
    call serial_hex64
    lea  rdi, [rel str_cdce_diag_out]
    call serial_string
    movzx edi, byte [rel cdc_ecm_out_ep]
    call serial_hex64
    lea  rdi, [rel str_cdce_diag_mac]
    call serial_string
    mov  edi, [rel cdc_ecm_mac]
    call serial_hex64
    lea  rdi, [rel str_cdce_diag_cfgin]
    call serial_string
    mov  edi, [rel cdc_ecm_cfg_in_rc]
    call serial_hex64
    lea  rdi, [rel str_cdce_diag_cfgout]
    call serial_string
    mov  edi, [rel cdc_ecm_cfg_out_rc]
    call serial_hex64
    lea  rdi, [rel str_cdce_diag_regrc]
    call serial_string
    mov  edi, [rel cdc_ecm_reg_rc]
    call serial_hex64
    lea  rdi, [rel str_cdce_diag_imac]
    call serial_string
    movzx edi, byte [rel cdc_ecm_imac_idx]
    call serial_hex64
    lea  rdi, [rel str_cdce_diag_str]
    call serial_string
    mov  rdi, [rel cdc_ecm_strbuf]       ; raw bytes 0..7 of the MAC string descriptor read
    call serial_hex64
    call serial_newline
    ret

; cdc_ecm_port_owned(RDI=hc dev*, ESI=root port) -> EAX 1 when this driver bound that
;   controller/port. Read-only; lets a later class binder (dev/blk/usb_msd)
;   never take a device this driver owns.
cdc_ecm_port_owned:
    xor  eax, eax
    cmp  byte [rel cdc_ecm_present], 1
    jne  .out
    cmp  [rel cdc_ecm_hc], rdi
    jne  .out
    cmp  [rel cdc_ecm_port], sil
    jne  .out
    mov  eax, 1
.out:
    ret

; --- data (in-image writable) ------------------------------------------------
CDCE_CFGBUF_SZ  equ 256
CDCE_RX_MAX     equ 2048        ; == XHCI_INTR_REPORT_BYTES (2048 since usbnic-late-bind); single-bulk-xfer cap, holds a full 1514B frame
cdc_ecm_hc:            dq 0
cdc_ecm_watch:         times usbnic_watch_size db 0   ; RCQ-10 GONE watch (filled at create)
cdc_ecm_hcops:         dq 0
cdc_ecm_port:          db 0
cdc_ecm_config:        db 0
cdc_ecm_data_if:       db 0
cdc_ecm_data_alt:      db 0
cdc_ecm_in_ep:         db 0
cdc_ecm_out_ep:        db 0
cdc_ecm_in_ep_valid:   db 0
cdc_ecm_out_ep_valid:  db 0
cdc_ecm_have_comm:     db 0
cdc_ecm_comm_if:       db 0
cdc_ecm_have_union:    db 0
cdc_ecm_union_slave:   db 0
cdc_ecm_have_ethernet: db 0
cdc_ecm_have_data:     db 0
cdc_ecm_present:       db 0
cdc_ecm_imac_idx:      db 0
cdc_ecm_ncfg:          db 0            ; configuration indices to probe (bNumConfigurations, <= 4)
align 4
cdc_ecm_cfg_in_rc:     dd 0
cdc_ecm_cfg_out_rc:    dd 0
cdc_ecm_reg_rc:        dd 0            ; netdev_register rc: slot index or -1 (rejected/full)
cdc_ecm_bind_step:     db 0            ; RCQ-10: bind step reached (1 SET_CONFIG .. 6 packet filter)
cdc_ecm_tx_calls:      dd 0
cdc_ecm_rx_calls:      dd 0
cdc_ecm_rx_errors:     dd 0
cdc_ecm_rx_gated:      dd 0
cdc_ecm_tx_reported:   db 0
cdc_ecm_rx_reported:   db 0
cdc_ecm_tx_last_rc:    dq 0
cdc_ecm_tx_last_len:   dq 0
cdc_ecm_rx_last_rc:    dq 0
cdc_ecm_rx_last_buf:   dq 0
cdc_ecm_mac:           times 6 db 0
align 4
align 8
cdc_ecm_stat_rx_frames: dq 0
cdc_ecm_stat_tx_frames: dq 0
cdc_ecm_dev:           times dev_size db 0
cdc_ecm_ops:           times netdev_ops_size db 0
cdc_ecm_setup:         times usb_setup_size db 0
cdc_ecm_in_ep_desc:    times 8 db 0
cdc_ecm_out_ep_desc:   times 8 db 0
cdc_ecm_cfgbuf:        times CDCE_CFGBUF_SZ db 0
cdc_ecm_strbuf:        times 64 db 0
cdc_ecm_info:
    dq 0                                   ; .name: set at register time (org 0 image: no static pointers)
    dd 1500
    db 64
    dd 0
    dd 0
str_cdce_name:  db "cdc_ecm", 0

str_cdce_registered: db "[PAOS64] L2 netdev: USB CDC-ECM Ethernet bound via netdev_ops HANDLE [netdev.cdc_ecm.registered]", 13, 10, 0
str_cdce_bind_failed: db "[PAOS64] L2 netdev: cdc_ecm bind FAILED step=", 0
str_cdce_bind_failed_tail: db " - not registered, onboard NICs unaffected [netdev.cdc_ecm.bind.failed]", 13, 10, 0
str_cdce_skipped:    db "[PAOS64] L2 netdev: cdc_ecm skipped (no CDC-ECM adapter enumerated) [netdev.cdc_ecm.skipped]", 13, 10, 0
str_cdce_diag:       db "[PAOS64] L2 netdev: cdc_ecm.diag port=", 0
str_cdce_diag_cfg:   db " cfg=", 0
str_cdce_diag_if:    db " data_if=", 0
str_cdce_diag_in:    db " in_ep=", 0
str_cdce_diag_out:   db " out_ep=", 0
str_cdce_diag_mac:   db " mac0_3=", 0
str_cdce_diag_cfgin: db " cfg_in_rc=", 0
str_cdce_diag_cfgout: db " cfg_out_rc=", 0
str_cdce_diag_regrc:  db " reg_rc=", 0
str_cdce_diag_imac:   db " imac_idx=", 0
str_cdce_diag_str:    db " str0_7=", 0
str_cdce_reg_rejected: db "[PAOS64] L2 netdev: cdc_ecm bound on USB but netdev_register REJECTED the handle (table full?) - NOT selectable [netdev.cdc_ecm.reg_rejected]", 13, 10, 0
str_cdce_tx_first:    db "[PAOS64] L2 netdev: cdc_ecm.tx.first bulk_out_rc=", 0
str_cdce_len:         db " len=", 0
str_cdce_rx_first:    db "[PAOS64] L2 netdev: cdc_ecm.rx.first bulk_in_rc=", 0
str_cdce_et:          db " et=", 0
