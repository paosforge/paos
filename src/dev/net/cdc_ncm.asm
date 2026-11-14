;; MODULE dev/net/cdc_ncm
;; LAYER 3
;; EXPORTS cdc_ncm_selftest, cdc_ncm_ntb_parse, cdc_ncm_frame_stats
;; IMPORTS boot/native_driver_gate, usb/enum, net/netdev, boot/serial, core/lib/fmt, dev/net/cdc_ecm, dev/net/ax88179, dev/net/ax88179b, dev/net/ax88179b_attach
;; CAPS
;; OWNER saga:net
%include "boot/native_driver_gate.inc"
;; LOCK: cdc_ncm_tx_busy PROTECTS cdc_ncm_txbuf, cdc_ncm_tx_len, cdc_ncm_tx_seq
; ============================================================================
; dev/net/cdc_ncm.asm — USB CDC-NCM 1.0 Ethernet backend (RCQ-10). A generic
; class driver: any NCM function (the owned Plugable RTL8156B 0bda:8156 exposes
; one as configuration 2 beside its vendor configuration) gives a target a
; network independent of its onboard chip. Post-USB-enum consumer like cdc_ecm,
; probed after ax88179 and cdc_ecm; a port cdc_ecm bound is never touched.
;
; Bind is all-or-nothing exactly like ax88179/cdc_ecm (RCQ-10): every step is
; checked, the first failure stops all further transfers, prints one
; [netdev.cdc_ncm.bind.failed] step= marker and registers nothing. Registration
; is PRIO_NATIVE_EXPERIMENTAL: an onboard NIC wins egress, a USB-only box still
; selects this backend.
;
; Framing (NCM 1.0 section 3, 16-bit NTBs only): TX sends one datagram per NTB
; (NTH16 + NDP16 + datagram, honouring the device's wNdpOutAlignment and
; wNdpOutDivisor/PayloadRemainder from GET_NTB_PARAMETERS, 6.2.1). RX validates
; an entire NTB before delivering any datagram from it and drops a malformed
; block whole; every read is bounded by the received length. The device's NTB
; IN size is set to the 2048-byte xHCI bulk buffer (SET_NTB_INPUT_SIZE, 6.2.7)
; so an NTB never spans two bulk transfers. Up to 32 unique NCM0 NDP16 tables
; are followed in link order, with at most CNCM_MAX_DGRAMS frames in total.
;
; HC op calling convention is SELF-LESS (see cdc_ecm.asm): control RSI=setup,
; RDX=port, RCX=buf, R8=cap; bulk RSI=port, RDX=ep, RCX=buf, R8=len;
; configure_ep RSI=port, RDX=usb_endpoint_desc*.
; ============================================================================

CNCM_DT_CONFIG        equ 2
CNCM_DT_STRING        equ 3
CNCM_DT_INTERFACE     equ 4
CNCM_DT_ENDPOINT      equ 5
CNCM_DT_CS_INTERFACE  equ 0x24
CNCM_FD_UNION         equ 0x06        ; union functional descriptor (CDC 1.2 5.2.3.8)
CNCM_FD_ETHERNET      equ 0x0F        ; Ethernet networking functional descriptor (ECM 5.4)
CNCM_FD_NCM           equ 0x1A        ; NCM functional descriptor (NCM 5.2.1)
CNCM_CLASS_COMM       equ 0x02
CNCM_SUBCLASS_NCM     equ 0x0D
CNCM_CLASS_DATA       equ 0x0A
CNCM_XFER_BULK        equ 0x02
CNCM_EP_IN            equ 0x80
CNCM_CAP_FILTER       equ 0x01        ; bmNetworkCapabilities D0: SetEthernetPacketFilter
CNCM_CAP_INSIZE8      equ 0x20        ; D5: 8-byte SET_NTB_INPUT_SIZE (with wNtbInMaxDatagrams)

CNCM_REQ_GET_DESCRIPTOR    equ 6
CNCM_REQ_SET_CONFIGURATION equ 9
CNCM_REQ_SET_INTERFACE     equ 11
CNCM_REQ_SET_ETH_FILTER    equ 0x43
CNCM_REQ_GET_NTB_PARAMS    equ 0x80   ; NCM 6.2.1
CNCM_REQ_SET_NTB_INSIZE    equ 0x86   ; NCM 6.2.7
CNCM_RT_H2D_STD_DEV        equ 0x00
CNCM_RT_D2H_STD_DEV        equ 0x80
CNCM_RT_H2D_STD_IF         equ 0x01
CNCM_RT_H2D_CLASS_IF       equ 0x21
CNCM_RT_D2H_CLASS_IF       equ 0xA1
CNCM_PKT_FILTER            equ 0x000E ; ALL_MULTICAST | DIRECTED | BROADCAST

CNCM_NTH16_SIG   equ 0x484D434E       ; "NCMH" (3.2.1)
CNCM_NDP16_SIG   equ 0x304D434E       ; "NCM0", no CRC (3.3.1); CRC mode is never negotiated
CNCM_NTH16_LEN   equ 12
CNCM_NDP16_ONE   equ 16               ; NDP16 header + one datagram entry + terminator
CNCM_MAX_DGRAMS  equ 32               ; datagrams accepted from one NTB
CNCM_ETH_MIN     equ 14
CNCM_ETH_MAX     equ 1514
CNCM_NTB_IN      equ 2048             ; == XHCI_INTR_REPORT_BYTES: one NTB per bulk transfer
CNCM_NTB_OUT     equ 2048             ; xHCI bulk OUT cap
CNCM_MOD_MAX     equ 64               ; largest NDP alignment / payload divisor supported

; NTB parameter structure (NCM 6.2.1 Table 6-3)
NTBP_FORMATS     equ 2
NTBP_IN_MAX      equ 4
NTBP_OUT_MAX     equ 16
NTBP_OUT_DIV     equ 20
NTBP_OUT_REM     equ 22
NTBP_OUT_ALIGN   equ 24
NTBP_SIZE        equ 28

; ============================================================================
; cdc_ncm_selftest — probe + bind + register, after ax88179 and cdc_ecm.
; ============================================================================
cdc_ncm_selftest:
    NATIVE_DRIVER_REFUSE 10, 0
    push rbx
    push r12
    push r13
    push r14
    push r15
    call usb_dev_count
    mov  r15d, eax
    xor  r14d, r14d
.dev_loop:
    cmp  r14d, r15d
    jae  .none
    mov  edi, r14d
    call usb_dev_is_null
    test eax, eax
    jnz  .dev_next
    mov  edi, r14d
    call usb_dev_hc
    test rax, rax
    jz   .dev_next
    mov  [rel cdc_ncm_hc], rax
    mov  rbx, [rax + dev.ops]
    mov  [rel cdc_ncm_hcops], rbx
    mov  edi, r14d
    call usb_dev_addr
    test eax, eax
    jz   .dev_next
    mov  [rel cdc_ncm_port], al
    mov  rdi, [rel cdc_ncm_hc]
    movzx esi, byte [rel cdc_ncm_port]
    call ax88179_port_owned            ; vendor owner wins even across descriptor differences
    test eax, eax
    jnz  .dev_next
    call ax88179b_port_owned
    test eax, eax
    jnz  .dev_next
    call cdc_ecm_port_owned            ; the ECM class driver already bound this function
    test eax, eax
    jnz  .dev_next
    mov  edi, r14d
    call usb_dev_desc_ptr
    mov  byte [rel cdc_ncm_ncfg], 1
    test rax, rax
    jz   .cfg_start
    mov  rdi, rax
    mov  esi, 18
    call ax88179_claims_desc           ; reserve legacy profiles, not the entire vendor
    test eax, eax
    jnz  .dev_next
    call ax88179b_claims_desc
    test eax, eax
    jnz  .dev_next
    mov  rax, rdi                     ; predicate preserves pointer for config count
    movzx ecx, byte [rax + 17]         ; bNumConfigurations
    test ecx, ecx
    jz   .cfg_start
    cmp  ecx, 4
    jbe  .ncfg
    mov  ecx, 4
.ncfg:
    mov  [rel cdc_ncm_ncfg], cl
.cfg_start:
    xor  r13d, r13d                    ; configuration index
.cfg_loop:
    movzx eax, byte [rel cdc_ncm_ncfg]
    cmp  r13d, eax
    jae  .dev_next
    mov  edx, r13d
    call cdc_ncm_get_config_desc
    cmp  rax, 9                        ; failed or shorter than a config header: never walked
    jl   .dev_next
    mov  r12, rax                      ; preserve full completion width for admission
    call cdc_ncm_walk_config
    test eax, eax
    jnz  .bind
    inc  r13d
    jmp  .cfg_loop
.dev_next:
    inc  r14d
    jmp  .dev_loop

.bind:
    ; 1. SET_CONFIGURATION(bConfigurationValue of the NCM configuration)
    mov  byte [rel cdc_ncm_bind_step], 1
    lea  rdi, [rel cdc_ncm_setup]
    mov  byte [rdi + usb_setup.bmRequestType], CNCM_RT_H2D_STD_DEV
    mov  byte [rdi + usb_setup.bRequest], CNCM_REQ_SET_CONFIGURATION
    movzx eax, byte [rel cdc_ncm_config]
    mov  word [rdi + usb_setup.wValue], ax
    mov  word [rdi + usb_setup.wIndex], 0
    call cdc_ncm_ctrl_nodata
    test rax, rax
    js   .bind_failed
    ; 2. SET_INTERFACE(data, 0): NTB parameters are set while the data interface is idle (7.2)
    mov  byte [rel cdc_ncm_bind_step], 2
    xor  edx, edx
    call cdc_ncm_set_interface
    test rax, rax
    js   .bind_failed
    ; 3. GET_NTB_PARAMETERS (6.2.1): NTB16 required; OUT alignment/divisor sanitised as Linux does
    mov  byte [rel cdc_ncm_bind_step], 3
    call cdc_ncm_get_ntb_params
    test rax, rax
    js   .bind_failed
    ; 4. SET_NTB_INPUT_SIZE (6.2.7): never larger than one xHCI bulk transfer
    mov  byte [rel cdc_ncm_bind_step], 4
    cmp  dword [rel cdc_ncm_ntbp + NTBP_IN_MAX], CNCM_NTB_IN
    jbe  .insize_ok
    call cdc_ncm_set_input_size
    test rax, rax
    js   .bind_failed
.insize_ok:
    ; 5. SET_INTERFACE(data, alt) enables the bulk endpoints
    mov  byte [rel cdc_ncm_bind_step], 5
    movzx edx, byte [rel cdc_ncm_data_alt]
    call cdc_ncm_set_interface
    test rax, rax
    js   .bind_failed
    ; 6/7. configure the bulk IN and OUT endpoints
    mov  byte [rel cdc_ncm_bind_step], 6
    lea  rdx, [rel cdc_ncm_in_ep_desc]
    call cdc_ncm_configure_ep
    test rax, rax
    js   .bind_failed
    mov  byte [rel cdc_ncm_bind_step], 7
    lea  rdx, [rel cdc_ncm_out_ep_desc]
    call cdc_ncm_configure_ep
    test rax, rax
    js   .bind_failed
    ; 8. MAC from the iMACAddress string
    mov  byte [rel cdc_ncm_bind_step], 8
    call cdc_ncm_read_mac
    test rax, rax
    js   .bind_failed
    ; 9. SET_ETHERNET_PACKET_FILTER when the function advertises it; a STALL keeps
    ;    the default filter (as cdc_ecm), a timeout is a failure
    mov  byte [rel cdc_ncm_bind_step], 9
    test byte [rel cdc_ncm_caps], CNCM_CAP_FILTER
    jz   .filter_ok
    lea  rdi, [rel cdc_ncm_setup]
    mov  byte [rdi + usb_setup.bmRequestType], CNCM_RT_H2D_CLASS_IF
    mov  byte [rdi + usb_setup.bRequest], CNCM_REQ_SET_ETH_FILTER
    mov  word [rdi + usb_setup.wValue], CNCM_PKT_FILTER
    movzx eax, byte [rel cdc_ncm_comm_if]
    mov  word [rdi + usb_setup.wIndex], ax
    call cdc_ncm_ctrl_nodata
    cmp  rax, -2
    je   .filter_ok
    test rax, rax
    js   .bind_failed
.filter_ok:
    mov  byte [rel cdc_ncm_present], 1
    call cdc_ncm_create
    cmp  dword [rel cdc_ncm_reg_rc], 0
    jl   .reg_rejected
    lea  rdi, [rel str_cncm_registered]
    call serial_string
    call cdc_ncm_emit_diag
    jmp  .done
.reg_rejected:
    lea  rdi, [rel str_cncm_reg_rejected]
    call serial_string
    jmp  .done
.bind_failed:
    lea  rdi, [rel str_cncm_bind_failed]
    call serial_string
    movzx edi, byte [rel cdc_ncm_bind_step]
    call serial_hex64
    lea  rdi, [rel str_cncm_bind_failed_tail]
    call serial_string
    jmp  .done
.none:
    lea  rdi, [rel str_cncm_skipped]
    call serial_string
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; EDX = configuration index -> RAX = bytes read into cdc_ncm_cfgbuf (negative on failure)
cdc_ncm_get_config_desc:
    lea  rdi, [rel cdc_ncm_setup]
    mov  byte [rdi + usb_setup.bmRequestType], CNCM_RT_D2H_STD_DEV
    mov  byte [rdi + usb_setup.bRequest], CNCM_REQ_GET_DESCRIPTOR
    mov  eax, (CNCM_DT_CONFIG << 8)
    or   eax, edx
    mov  word [rdi + usb_setup.wValue], ax
    mov  word [rdi + usb_setup.wIndex], 0
    mov  word [rdi + usb_setup.wLength], CNCM_CFGBUF_SZ
    lea  rcx, [rel cdc_ncm_cfgbuf]
    mov  r8d, CNCM_CFGBUF_SZ
    jmp  cdc_ncm_ctrl

; R12 = config length -> EAX = 1 when one complete NCM function was found:
; default comm 02/0D (first one only) carrying union + Ethernet + NCM functional
; descriptors, and the data interface the union names, in an alternate setting
; with one bulk IN and one bulk OUT endpoint. Bounded TLV walk.
cdc_ncm_walk_config:
    push rbx
    push r13
    push r14
    xor  eax, eax
    mov  byte [rel cdc_ncm_have_comm], al
    mov  byte [rel cdc_ncm_have_data], al
    mov  byte [rel cdc_ncm_in_valid], al
    mov  byte [rel cdc_ncm_out_valid], al
    mov  byte [rel cdc_ncm_imac_idx], al
    mov  byte [rel cdc_ncm_caps], al
    mov  byte [rel cdc_ncm_have_union], al
    mov  byte [rel cdc_ncm_have_ethernet], al
    mov  byte [rel cdc_ncm_have_ncm], al
    lea  rbx, [rel cdc_ncm_cfgbuf]
    cmp  r12, 9
    jb   .fail
    cmp  r12, CNCM_CFGBUF_SZ
    ja   .fail
    cmp  byte [rbx], 9
    jne  .fail
    cmp  byte [rbx + 1], CNCM_DT_CONFIG
    jne  .fail
    cmp  byte [rbx + 5], 0
    je   .fail
    movzx ecx, word [rbx + 2]
    cmp  ecx, 9
    jb   .fail
    cmp  rcx, r12
    ja   .fail
    movzx eax, byte [rbx + 5]
    mov  [rel cdc_ncm_config], al
    lea  r14, [rbx + rcx]              ; ignore bytes outside declared configuration
    xor  r13d, r13d                    ; 1 = inside our comm IF, 2 = inside our data alt
.wl:
    cmp  rbx, r14
    je   .done
    lea  rax, [rbx + 2]
    cmp  rax, r14
    ja   .fail
    movzx eax, byte [rbx]
    cmp  eax, 2
    jb   .fail                         ; malformed / zero length
    lea  rcx, [rbx + rax]
    cmp  rcx, r14
    ja   .fail                         ; malformed tail cannot publish a valid prefix
    movzx ecx, byte [rbx + 1]
    cmp  ecx, CNCM_DT_INTERFACE
    je   .iface
    cmp  ecx, CNCM_DT_CS_INTERFACE
    je   .cs
    cmp  ecx, CNCM_DT_ENDPOINT
    je   .endp
    jmp  .next
.iface:
    xor  r13d, r13d
    cmp  eax, 9
    jb   .fail
    movzx edx, byte [rbx + 5]
    cmp  edx, CNCM_CLASS_COMM
    jne  .data_if
    cmp  byte [rbx + 6], CNCM_SUBCLASS_NCM
    jne  .next
    cmp  byte [rbx + 3], 0             ; only default comm alternate is activated
    jne  .next
    cmp  byte [rel cdc_ncm_have_comm], 1
    je   .next                         ; first NCM function only
    mov  byte [rel cdc_ncm_have_comm], 1
    mov  dl, [rbx + 2]
    mov  [rel cdc_ncm_comm_if], dl
    mov  r13d, 1
    jmp  .next
.data_if:
    cmp  edx, CNCM_CLASS_DATA
    jne  .next
    cmp  byte [rel cdc_ncm_have_union], 1
    jne  .next
    ; A nominal data alternate is not a complete endpoint pair. Try later
    ; alternates until both directions exist in the same interface context.
    cmp  byte [rel cdc_ncm_in_valid], 1
    jne  .data_candidate
    cmp  byte [rel cdc_ncm_out_valid], 1
    je   .next                         ; first complete pair keeps its alternate
.data_candidate:
    mov  dl, [rbx + 2]
    cmp  dl, [rel cdc_ncm_union_slave]
    jne  .next                         ; only the data interface our union names
    cmp  byte [rbx + 4], 2
    jb   .next                         ; alt 0 carries no endpoints
    mov  byte [rel cdc_ncm_in_valid], 0
    mov  byte [rel cdc_ncm_out_valid], 0
    mov  [rel cdc_ncm_data_if], dl
    mov  dl, [rbx + 3]
    mov  [rel cdc_ncm_data_alt], dl
    mov  byte [rel cdc_ncm_have_data], 1
    mov  r13d, 2
    jmp  .next
.cs:
    cmp  eax, 3
    jb   .fail
    cmp  r13d, 1
    jne  .next
    movzx edx, byte [rbx + 2]
    cmp  edx, CNCM_FD_UNION
    jne  .not_union
    cmp  eax, 5
    jne  .fail                        ; supported union: exactly one subordinate
    cmp  byte [rel cdc_ncm_have_union], 0
    jne  .fail                        ; duplicate unions cannot replace ownership
    mov  dl, [rbx + 3]
    cmp  dl, [rel cdc_ncm_comm_if]
    jne  .fail                        ; our union must be mastered by this comm IF
    mov  dl, [rbx + 4]
    cmp  dl, [rel cdc_ncm_comm_if]
    je   .fail                        ; data subordinate cannot be its own master
    mov  [rel cdc_ncm_union_slave], dl
    mov  byte [rel cdc_ncm_have_union], 1
    jmp  .next
.not_union:
    cmp  edx, CNCM_FD_ETHERNET
    jne  .not_eth
    cmp  eax, 13                      ; complete Ethernet functional descriptor
    jb   .fail
    cmp  byte [rel cdc_ncm_have_ethernet], 0
    jne  .fail
    mov  dl, [rbx + 3]
    mov  [rel cdc_ncm_imac_idx], dl
    mov  byte [rel cdc_ncm_have_ethernet], 1
    jmp  .next
.not_eth:
    cmp  edx, CNCM_FD_NCM
    jne  .next
    cmp  eax, 6
    jb   .fail
    cmp  byte [rel cdc_ncm_have_ncm], 0
    jne  .fail
    mov  dl, [rbx + 5]
    mov  [rel cdc_ncm_caps], dl
    mov  byte [rel cdc_ncm_have_ncm], 1
    jmp  .next
.endp:
    cmp  eax, 7
    jb   .fail
    cmp  r13d, 2
    jne  .next
    movzx edx, byte [rbx + 3]
    and  edx, 3
    cmp  edx, CNCM_XFER_BULK
    jne  .next
    test byte [rbx + 2], CNCM_EP_IN
    jz   .out_ep
    cmp  byte [rel cdc_ncm_in_valid], 1
    je   .next
    mov  dl, [rbx + 2]
    mov  [rel cdc_ncm_in_ep], dl
    mov  byte [rel cdc_ncm_in_valid], 1
    lea  rdi, [rel cdc_ncm_in_ep_desc]
    call cdc_ncm_copy_ep
    jmp  .next
.out_ep:
    cmp  byte [rel cdc_ncm_out_valid], 1
    je   .next
    mov  dl, [rbx + 2]
    mov  [rel cdc_ncm_out_ep], dl
    mov  byte [rel cdc_ncm_out_valid], 1
    lea  rdi, [rel cdc_ncm_out_ep_desc]
    call cdc_ncm_copy_ep
.next:
    movzx eax, byte [rbx]
    add  rbx, rax
    jmp  .wl
.done:
    xor  eax, eax
    cmp  byte [rel cdc_ncm_have_comm], 1
    jne  .ret
    cmp  byte [rel cdc_ncm_have_union], 1
    jne  .ret
    cmp  byte [rel cdc_ncm_have_ethernet], 1
    jne  .ret
    cmp  byte [rel cdc_ncm_have_ncm], 1
    jne  .ret
    cmp  byte [rel cdc_ncm_have_data], 1
    jne  .ret
    cmp  byte [rel cdc_ncm_in_valid], 1
    jne  .ret
    cmp  byte [rel cdc_ncm_out_valid], 1
    jne  .ret
    mov  eax, 1
    jmp  .ret
.fail:
    xor  eax, eax
.ret:
    pop  r14
    pop  r13
    pop  rbx
    ret

cdc_ncm_copy_ep:                       ; RBX = endpoint descriptor, RDI = 7-byte copy
    mov  ecx, 7
.cp:
    mov  al, [rbx + rcx - 1]
    mov  [rdi + rcx - 1], al
    dec  ecx
    jnz  .cp
    ret

; EDX = alternate setting of the data interface
cdc_ncm_set_interface:
    lea  rdi, [rel cdc_ncm_setup]
    mov  byte [rdi + usb_setup.bmRequestType], CNCM_RT_H2D_STD_IF
    mov  byte [rdi + usb_setup.bRequest], CNCM_REQ_SET_INTERFACE
    mov  word [rdi + usb_setup.wValue], dx
    movzx eax, byte [rel cdc_ncm_data_if]
    mov  word [rdi + usb_setup.wIndex], ax
cdc_ncm_ctrl_nodata:
    lea  rdi, [rel cdc_ncm_setup]
    mov  word [rdi + usb_setup.wLength], 0
    xor  ecx, ecx
    xor  r8d, r8d
cdc_ncm_ctrl:                          ; RDI = setup, RCX = buf, R8 = cap
    mov  rsi, rdi
    movzx edx, byte [rel cdc_ncm_port]
    mov  rax, [rel cdc_ncm_hcops]
    mov  rax, [rax + usbhc_ops.control]
    jmp  rax

; -> RAX 0 / -1. Reads and validates the NTB parameters (6.2.1).
cdc_ncm_get_ntb_params:
    lea  rdi, [rel cdc_ncm_setup]
    mov  byte [rdi + usb_setup.bmRequestType], CNCM_RT_D2H_CLASS_IF
    mov  byte [rdi + usb_setup.bRequest], CNCM_REQ_GET_NTB_PARAMS
    mov  word [rdi + usb_setup.wValue], 0
    movzx eax, byte [rel cdc_ncm_comm_if]
    mov  word [rdi + usb_setup.wIndex], ax
    mov  word [rdi + usb_setup.wLength], NTBP_SIZE
    lea  rcx, [rel cdc_ncm_ntbp]
    mov  r8d, NTBP_SIZE
    call cdc_ncm_ctrl
    cmp  rax, NTBP_SIZE                ; exact full-width count, bounded by submitted capacity
    jne  .fail
    cmp  word [rel cdc_ncm_ntbp], NTBP_SIZE ; NCM 6.2.1: fixed structure length
    jne  .fail
    cmp  dword [rel cdc_ncm_ntbp + NTBP_IN_MAX], CNCM_NTB_IN
    jb   .fail                         ; 6.2.7 requires an IN NTB size of at least 2048
    test word [rel cdc_ncm_ntbp + NTBP_FORMATS], 1
    jz   .fail                         ; NTB-16 is mandatory
    ; wNdpOutAlignment: 0 -> 4; must be a power of two; below 4 -> 4; above CNCM_MOD_MAX unsupported
    movzx eax, word [rel cdc_ncm_ntbp + NTBP_OUT_ALIGN]
    test eax, eax
    jnz  .align_set
    mov  eax, 4
.align_set:
    lea  ecx, [rax - 1]
    test eax, ecx
    jnz  .fail
    cmp  eax, 4
    jae  .align_floor
    mov  eax, 4
.align_floor:
    cmp  eax, CNCM_MOD_MAX
    ja   .fail
    mov  [rel cdc_ncm_tx_align], eax
    ; wNdpOutDivisor: 0 -> 4; power of two up to CNCM_MOD_MAX; remainder >= divisor -> 0
    movzx eax, word [rel cdc_ncm_ntbp + NTBP_OUT_DIV]
    test eax, eax
    jnz  .div_set
    mov  eax, 4
.div_set:
    lea  ecx, [rax - 1]
    test eax, ecx
    jnz  .fail
    cmp  eax, CNCM_MOD_MAX
    ja   .fail
    mov  [rel cdc_ncm_tx_div], eax
    movzx ecx, word [rel cdc_ncm_ntbp + NTBP_OUT_REM]
    cmp  ecx, eax
    jb   .rem_ok
    xor  ecx, ecx
.rem_ok:
    mov  [rel cdc_ncm_tx_rem], ecx
    ; dwNtbOutMaxSize must carry one MTU frame in our layout: NDP at the
    ; alignment, at most divisor-1 bytes of payload padding, 1514 bytes, and the
    ; pad byte. Smaller (including 0) would register a NIC that refuses every TX.
    mov  eax, [rel cdc_ncm_tx_align]
    lea  ecx, [rax + CNCM_NTH16_LEN - 1]
    neg  eax
    and  ecx, eax
    add  ecx, [rel cdc_ncm_tx_div]
    add  ecx, CNCM_NDP16_ONE + CNCM_ETH_MAX   ; + (divisor - 1) + 1 pad byte
    mov  eax, [rel cdc_ncm_ntbp + NTBP_OUT_MAX]
    cmp  eax, ecx
    jb   .fail
    mov  [rel cdc_ncm_tx_max], eax
    xor  eax, eax
    ret
.fail:
    mov  rax, -1
    ret

; SET_NTB_INPUT_SIZE(CNCM_NTB_IN), 8-byte form when bmNetworkCapabilities D5 is set.
cdc_ncm_set_input_size:
    mov  dword [rel cdc_ncm_insize], CNCM_NTB_IN
    mov  dword [rel cdc_ncm_insize + 4], 0       ; wNtbInMaxDatagrams 0 = no limit, reserved
    lea  rdi, [rel cdc_ncm_setup]
    mov  byte [rdi + usb_setup.bmRequestType], CNCM_RT_H2D_CLASS_IF
    mov  byte [rdi + usb_setup.bRequest], CNCM_REQ_SET_NTB_INSIZE
    mov  word [rdi + usb_setup.wValue], 0
    movzx eax, byte [rel cdc_ncm_comm_if]
    mov  word [rdi + usb_setup.wIndex], ax
    mov  r8d, 4
    test byte [rel cdc_ncm_caps], CNCM_CAP_INSIZE8
    jz   .len
    mov  r8d, 8
.len:
    mov  word [rdi + usb_setup.wLength], r8w
    lea  rcx, [rel cdc_ncm_insize]
    push rbx
    mov  ebx, r8d                      ; retain requested data-stage size across HC call
    call cdc_ncm_ctrl
    cmp  rax, rbx                      ; short, negative or impossible completion fails
    pop  rbx
    jne  .fail
    xor  eax, eax
    ret
.fail:
    mov  rax, -1
    ret

cdc_ncm_configure_ep:                  ; RDX = endpoint descriptor
    movzx esi, byte [rel cdc_ncm_port]
    mov  rax, [rel cdc_ncm_hcops]
    mov  rax, [rax + usbhc_ops.configure_ep]
    jmp  rax

; -> RAX 0 / -1. The NCM function must name its MAC (iMACAddress, 12 hex digits).
cdc_ncm_read_mac:
    push rbx
    movzx ebx, byte [rel cdc_ncm_imac_idx]
    test ebx, ebx
    jz   .fail
    lea  rdi, [rel cdc_ncm_setup]
    mov  byte [rdi + usb_setup.bmRequestType], CNCM_RT_D2H_STD_DEV
    mov  byte [rdi + usb_setup.bRequest], CNCM_REQ_GET_DESCRIPTOR
    mov  eax, (CNCM_DT_STRING << 8)
    or   eax, ebx
    mov  word [rdi + usb_setup.wValue], ax
    mov  word [rdi + usb_setup.wIndex], 0x0409
    mov  word [rdi + usb_setup.wLength], 64
    lea  rcx, [rel cdc_ncm_strbuf]
    mov  r8d, 64
    call cdc_ncm_ctrl
    cmp  rax, 26                       ; header + 12 UTF-16 digits actually received
    jl   .fail
    cmp  rax, 64                       ; full-width completion must fit submitted buffer
    ja   .fail
    cmp  byte [rel cdc_ncm_strbuf], 26  ; exactly twelve Unicode characters
    jne  .fail
    cmp  byte [rel cdc_ncm_strbuf + 1], CNCM_DT_STRING
    jne  .fail
    lea  rsi, [rel cdc_ncm_strbuf + 2]
    xor  ecx, ecx
.byte:
    cmp  ecx, 6
    jae  .ok
    cmp  byte [rsi + 1], 0              ; ASCII hex requires zero UTF-16 high bytes
    jne  .fail
    cmp  byte [rsi + 3], 0
    jne  .fail
    movzx eax, byte [rsi]
    call cdc_ncm_hexval
    js   .fail
    shl  eax, 4
    mov  edx, eax
    movzx eax, byte [rsi + 2]
    call cdc_ncm_hexval
    js   .fail
    or   eax, edx
    lea  rdi, [rel cdc_ncm_mac]
    mov  [rdi + rcx], al
    add  rsi, 4
    inc  ecx
    jmp  .byte
.ok:
    xor  eax, eax
    pop  rbx
    ret
.fail:
    mov  rax, -1
    pop  rbx
    ret

cdc_ncm_hexval:                        ; EAX = char -> EAX = 0..15, SF set when not hex
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

cdc_ncm_create:
    NATIVE_DRIVER_REFUSE 10
    lea  rdi, [rel cdc_ncm_ops]
    lea  rax, [rel cdc_ncm_nop]
    mov  [rdi + netdev_ops.init], rax
    mov  [rdi + netdev_ops.start], rax
    mov  [rdi + netdev_ops.stop], rax
    mov  [rdi + netdev_ops.recover], rax
    lea  rax, [rel cdc_ncm_tx]
    mov  [rdi + netdev_ops.tx], rax
    lea  rax, [rel cdc_ncm_rx_poll]
    mov  [rdi + netdev_ops.rx_poll], rax
    lea  rax, [rel cdc_ncm_link_status]
    mov  [rdi + netdev_ops.link_status], rax
    lea  rax, [rel cdc_ncm_get_mac]
    mov  [rdi + netdev_ops.get_mac], rax
    lea  rdi, [rel cdc_ncm_dev]
    lea  rax, [rel cdc_ncm_ops]
    mov  [rdi + dev.ops], rax
    lea  rax, [rel str_cncm_name]
    mov  [rel cdc_ncm_info + netdev_info.name], rax   ; runtime address (abs_ptr_check)
    lea  rax, [rel cdc_ncm_info]
    mov  [rdi + dev.info], rax
    mov  qword [rdi + dev.priv], 0
    ; As ax88179/cdc_ecm (RCQ-10): a USB NIC never outranks a bound onboard NIC.
    mov  dword [rdi + dev.prio], PRIO_NATIVE_EXPERIMENTAL
    mov  dword [rdi + dev.health], HEALTH_OK
    mov  dword [rdi + dev.class], CLASS_NET
    mov  dword [rdi + dev.flags], 0
    lea  rax, [rel str_cncm_name]
    mov  [rdi + dev.name], rax
    mov  rax, [rel cdc_ncm_hcops]              ; RCQ-10: the GONE watch (netdev_usbnic_*)
    mov  [rel cdc_ncm_watch + usbnic_watch.hcops], rax
    mov  rax, [rel cdc_ncm_hc]
    mov  [rel cdc_ncm_watch + usbnic_watch.hc], rax
    movzx eax, byte [rel cdc_ncm_port]
    mov  [rel cdc_ncm_watch + usbnic_watch.port], eax
    call netdev_register
    mov  [rel cdc_ncm_reg_rc], eax
    ret

cdc_ncm_nop:
    xor  eax, eax
    ret

; tx(self, RSI=frame, RDX=len) -> RAX 0 / -1. One datagram per NTB16:
; NTH16 at 0, NDP16 at wNdpOutAlignment, the datagram at the first offset that
; satisfies offset % wNdpOutDivisor == wNdpOutPayloadRemainder (3.3.4), and one
; pad byte when the block is a multiple of wMaxPacketSize (a short packet ends
; the transfer without a ZLP).
cdc_ncm_tx:
    push rbx
    push r12
    push r13
    push r14
    cmp  dword [rel cdc_ncm_dev + dev.health], HEALTH_DEAD
    je   .fail                         ; RCQ-10: never a transfer to a GONE device (DEGRADED still sends)
    mov  r12, rsi
    mov  r13, rdx
    test r13, r13
    jz   .fail
    cmp  r13, CNCM_ETH_MAX
    ja   .fail
    mov  eax, [rel cdc_ncm_tx_align]
    lea  ebx, [rax + CNCM_NTH16_LEN - 1]
    neg  eax
    and  ebx, eax                      ; NDP offset
    lea  r14d, [rbx + CNCM_NDP16_ONE]  ; first candidate datagram offset
    mov  ecx, [rel cdc_ncm_tx_div]
    dec  ecx
.align_dg:
    mov  eax, r14d
    and  eax, ecx
    cmp  eax, [rel cdc_ncm_tx_rem]
    je   .dg_ok
    inc  r14d
    jmp  .align_dg
.dg_ok:
    lea  rdx, [r14 + r13]              ; block length
    movzx ecx, word [rel cdc_ncm_out_ep_desc + 4]
    and  ecx, 0x7FF
    jz   .sized
    mov  rax, rdx
    push rdx
    xor  edx, edx
    div  rcx
    test rdx, rdx
    pop  rdx
    jnz  .sized
    inc  rdx                           ; no transfer ever ends on a packet boundary
.sized:
    cmp  rdx, CNCM_NTB_OUT
    ja   .fail
    mov  eax, [rel cdc_ncm_tx_max]
    cmp  rdx, rax
    ja   .fail                         ; above dwNtbOutMaxSize: never sent
    ; Own all TX staging through HC completion, health note and length comparison.
    ; Refuse overlap without spinning while an interrupted owner may be waiting.
    lock bts dword [rel cdc_ncm_tx_busy], 0
    jc   .fail                         ; caller contention is not a USB device failure
    mov  [rel cdc_ncm_tx_len], rdx
    lea  rdi, [rel cdc_ncm_txbuf]
    mov  rcx, rdx
    xor  eax, eax
    rep  stosb
    lea  rdi, [rel cdc_ncm_txbuf]
    mov  dword [rdi], CNCM_NTH16_SIG
    mov  word [rdi + 4], CNCM_NTH16_LEN
    mov  ax, [rel cdc_ncm_tx_seq]
    mov  [rdi + 6], ax
    mov  rax, [rel cdc_ncm_tx_len]
    mov  [rdi + 8], ax
    mov  [rdi + 10], bx
    mov  dword [rdi + rbx], CNCM_NDP16_SIG
    mov  word [rdi + rbx + 4], CNCM_NDP16_ONE
    mov  [rdi + rbx + 8], r14w
    mov  [rdi + rbx + 10], r13w        ; entry 1; next NDP index and the terminator stay zero
    lea  rdi, [rdi + r14]
    mov  rsi, r12
    mov  rcx, r13
    rep  movsb
    inc  word [rel cdc_ncm_tx_seq]
    movzx esi, byte [rel cdc_ncm_port]
    movzx edx, byte [rel cdc_ncm_out_ep]
    lea  rcx, [rel cdc_ncm_txbuf]
    mov  r8, [rel cdc_ncm_tx_len]
    mov  rax, [rel cdc_ncm_hcops]
    mov  rax, [rax + usbhc_ops.bulk_out]
    call rax
    cmp  rax, [rel cdc_ncm_tx_len]
    je   .tx_count_checked
    mov  rax, -1                       ; only an exact completion may recover USB health
.tx_count_checked:
    push rax
    xor  edx, edx
    test rax, rax
    js   .noted
    mov  edx, 1
.noted:
    lea  rdi, [rel cdc_ncm_dev]
    lea  rsi, [rel cdc_ncm_watch]
    call netdev_usbnic_io              ; RCQ-10: a failed transfer may mean GONE
    pop  rax
    cmp  rax, [rel cdc_ncm_tx_len]
    jne  .tx_failed
    lock inc qword [rel cdc_ncm_stat_tx_frames]
    xor  eax, eax
.tx_release:
    mov  dword [rel cdc_ncm_tx_busy], 0
    jmp  .out
.tx_failed:
    mov  rax, -1
    jmp  .tx_release
.fail:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; cdc_ncm_ntb_parse(RDI=ntb, RSI=received length) -> RAX = datagram count (0 for an
; empty NTB) with cdc_ncm_rx_ent = {u16 index, u16 length} pairs, or -1: the whole
; NTB is malformed and must be dropped. Every read is inside [ntb, ntb+length):
;   NTH16 (3.2.1): signature, wHeaderLength 12, 12 <= wBlockLength <= length,
;     wNdpIndex >= 12, 4-aligned, NDP16 header inside the block;
;   NDP16 (3.3.1): "NCM0", wLength >= 16 and 4-aligned, NDP inside the block;
;   entries: a (0,0) terminator inside wLength; each datagram index >= 12,
;     index + length <= wBlockLength, Ethernet-sized; at most CNCM_MAX_DGRAMS.
; Follow at most 32 unique NDP16 tables, accumulating the same bounded entry
; array. A bad tail or repeated table drops the whole NTB before rx_poll delivers
; any frame. The 64-byte local visited list also bounds empty-table chains.
cdc_ncm_ntb_parse:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 64                       ; 32 u16 visited NDP offsets
    mov  r12, rdi
    mov  r13, rsi
    cmp  r13, CNCM_NTH16_LEN
    jb   .bad
    cmp  dword [r12], CNCM_NTH16_SIG
    jne  .bad
    cmp  word [r12 + 4], CNCM_NTH16_LEN
    jne  .bad
    movzx r14d, word [r12 + 8]         ; wBlockLength
    cmp  r14, CNCM_NTH16_LEN
    jb   .bad
    cmp  r14, r13
    ja   .bad
    movzx ebx, word [r12 + 10]         ; wNdpIndex
    xor  r10d, r10d                    ; number of visited tables
    xor  edx, edx                      ; aggregate datagram count
    lea  rdi, [rel cdc_ncm_rx_ent]
.ndp:
    cmp  ebx, CNCM_NTH16_LEN
    jb   .bad
    test ebx, 3
    jnz  .bad
    lea  eax, [rbx + 8]
    cmp  rax, r14
    ja   .bad
    cmp  r10d, 32
    jae  .bad
    xor  ecx, ecx
.visited:
    cmp  ecx, r10d
    jae  .new_table
    cmp  bx, [rsp + rcx * 2]
    je   .bad                          ; self-cycle or cycle through an earlier table
    inc  ecx
    jmp  .visited
.new_table:
    mov  [rsp + r10 * 2], bx
    inc  r10d
    cmp  dword [r12 + rbx], CNCM_NDP16_SIG
    jne  .bad
    movzx r15d, word [r12 + rbx + 4]   ; NDP wLength
    cmp  r15d, CNCM_NDP16_ONE
    jb   .bad
    test r15d, 3
    jnz  .bad
    lea  eax, [rbx + r15]
    cmp  rax, r14
    ja   .bad
    movzx r11d, word [r12 + rbx + 6]   ; next table, validated on the next iteration
    cmp  r10d, 1
    jne  .entries
    test r11d, r11d
    jz   .entries
    inc  qword [rel cdc_ncm_rx_chained]
.entries:
    lea  rsi, [r12 + rbx + 8]          ; first datagram pointer entry
    lea  ecx, [r15 - 8]
    shr  ecx, 2                        ; entries inside wLength
.entry:
    test ecx, ecx
    jz   .bad                          ; no terminator inside the NDP
    movzx eax, word [rsi]              ; wDatagramIndex
    movzx r8d, word [rsi + 2]          ; wDatagramLength
    mov  r9d, eax
    or   r9d, r8d
    jz   .next_table                   ; the (0,0) terminator
    test eax, eax
    jz   .bad
    test r8d, r8d
    jz   .bad
    cmp  edx, CNCM_MAX_DGRAMS
    jae  .bad
    cmp  eax, CNCM_NTH16_LEN
    jb   .bad
    lea  r9d, [rax + r8]
    cmp  r9, r14
    ja   .bad
    cmp  r8d, CNCM_ETH_MIN
    jb   .bad
    cmp  r8d, CNCM_ETH_MAX
    ja   .bad
    mov  [rdi + rdx * 4], ax
    mov  [rdi + rdx * 4 + 2], r8w
    inc  edx
    add  rsi, 4
    dec  ecx
    jmp  .entry
.next_table:
    mov  ebx, r11d
    test ebx, ebx
    jnz  .ndp
    mov  eax, edx
    jmp  .out
.bad:
    inc  qword [rel cdc_ncm_rx_malformed]
    mov  rax, -1
.out:
    add  rsp, 64
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; rx_poll(self, RSI=buf, RDX=cap) -> RAX = frame length, 0 = nothing. Datagrams
; of the current NTB are delivered one per call; a new NTB is fetched (bulk IN,
; non-blocking) and validated whole only when the previous one is drained.
cdc_ncm_rx_poll:
    push rbx
    push r12
    push r13
    mov  r12, rsi
    mov  r13, rdx
    lea  rdi, [rel cdc_ncm_dev]
    lea  rsi, [rel cdc_ncm_watch]
    call netdev_usbnic_poll            ; RCQ-10: rate-limited CCS; GONE -> nothing, no transfer
    test rax, rax
    jnz  .none
.next:
    mov  ebx, [rel cdc_ncm_rx_next]
    cmp  ebx, [rel cdc_ncm_rx_count]
    jb   .deliver
    xor  eax, eax
    mov  [rel cdc_ncm_rx_count], eax
    mov  [rel cdc_ncm_rx_next], eax
    movzx esi, byte [rel cdc_ncm_port]
    movzx edx, byte [rel cdc_ncm_in_ep]
    lea  rcx, [rel cdc_ncm_ntb]
    mov  r8d, CNCM_NTB_IN
    mov  rax, [rel cdc_ncm_hcops]
    mov  rax, [rax + usbhc_ops.bulk_in_poll]
    test rax, rax
    jnz  .poll
    mov  rax, [rel cdc_ncm_hcops]
    mov  rax, [rax + usbhc_ops.bulk_in]
.poll:
    call rax
    test rax, rax
    jz   .none                         ; nothing yet: not a transfer result
    js   .rx_count_checked
    cmp  rax, CNCM_NTB_IN
    jbe  .rx_count_checked
    mov  rax, -1                       ; invalid completion must follow USB error evidence
.rx_count_checked:
    push rax
    xor  edx, edx
    test rax, rax
    js   .rx_noted
    mov  edx, 1
.rx_noted:
    lea  rdi, [rel cdc_ncm_dev]
    lea  rsi, [rel cdc_ncm_watch]
    call netdev_usbnic_rx              ; RCQ-10: RX never re-promotes a DEGRADED member
    pop  rax
    test rax, rax
    jle  .none
    cmp  rax, CNCM_NTB_IN
    ja   .none
    lea  rdi, [rel cdc_ncm_ntb]
    mov  rsi, rax
    call cdc_ncm_ntb_parse
    test rax, rax
    jle  .none                         ; malformed (dropped whole) or empty
    mov  [rel cdc_ncm_rx_count], eax
    jmp  .next
.deliver:
    inc  dword [rel cdc_ncm_rx_next]
    lea  rax, [rel cdc_ncm_rx_ent]
    movzx ecx, word [rax + rbx * 4 + 2]
    cmp  rcx, r13
    ja   .next                         ; larger than the caller's buffer: skipped
    movzx esi, word [rax + rbx * 4]
    lea  rax, [rel cdc_ncm_ntb]
    add  rsi, rax
    mov  rdi, r12
    mov  rax, rcx
    rep  movsb
    lock inc qword [rel cdc_ncm_stat_rx_frames]
    jmp  .out
.none:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; BEGIN FRAME STATS -- pure selected-device software readout (as cdc_ecm).
; RDI=self; EAX=0, RDX=RX, RCX=TX, or -1 for a handle that is not this backend.
cdc_ncm_frame_stats:
    lea  rax, [rel cdc_ncm_dev]
    cmp  rdi, rax
    jne  .unavailable
    lea  rax, [rel cdc_ncm_ops]
    cmp  [rdi + dev.ops], rax
    jne  .unavailable
    mov  rdx, [rel cdc_ncm_stat_rx_frames]
    mov  rcx, [rel cdc_ncm_stat_tx_frames]
    xor  eax, eax
    ret
.unavailable:
    mov  rdx, -1
    mov  rcx, -1
    mov  eax, -1
    ret
; END FRAME STATS

cdc_ncm_link_status:                   ; up @ 1 Gb/s while bound (v1, as cdc_ecm)
    xor  eax, eax
    cmp  byte [rel cdc_ncm_present], 1
    jne  .ret
    cmp  dword [rel cdc_ncm_dev + dev.health], HEALTH_DEAD
    je   .ret                          ; RCQ-10: GONE reads down (v1 link is static: no link-up evidence)
    mov  eax, (1000 << 8) | 1
.ret:
    ret

cdc_ncm_get_mac:                       ; RSI = out6
    lea  rax, [rel cdc_ncm_mac]
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

cdc_ncm_emit_diag:
    lea  rdi, [rel str_cncm_diag]
    call serial_string
    movzx edi, byte [rel cdc_ncm_port]
    call serial_hex64
    lea  rdi, [rel str_cncm_diag_cfg]
    call serial_string
    movzx edi, byte [rel cdc_ncm_config]
    call serial_hex64
    lea  rdi, [rel str_cncm_diag_ntb]
    call serial_string
    mov  edi, [rel cdc_ncm_tx_align]
    shl  edi, 16
    or   edi, [rel cdc_ncm_tx_div]
    shl  rdi, 16
    or   edi, [rel cdc_ncm_tx_rem]
    call serial_hex64
    lea  rdi, [rel str_cncm_diag_mac]
    call serial_string
    mov  edi, [rel cdc_ncm_mac]
    call serial_hex64
    call serial_newline
    ret

; --- data (in-image writable, as cdc_ecm) -------------------------------------
CNCM_CFGBUF_SZ  equ 512
cdc_ncm_hc:            dq 0
cdc_ncm_watch:         times usbnic_watch_size db 0   ; RCQ-10 GONE watch (filled at create)
cdc_ncm_hcops:         dq 0
cdc_ncm_port:          db 0
cdc_ncm_config:        db 0
cdc_ncm_comm_if:       db 0
cdc_ncm_data_if:       db 0
cdc_ncm_data_alt:      db 0
cdc_ncm_in_ep:         db 0
cdc_ncm_out_ep:        db 0
cdc_ncm_in_valid:      db 0
cdc_ncm_out_valid:     db 0
cdc_ncm_have_comm:     db 0
cdc_ncm_have_data:     db 0
cdc_ncm_have_union:    db 0
cdc_ncm_have_ethernet: db 0
cdc_ncm_have_ncm:      db 0
cdc_ncm_union_slave:   db 0
cdc_ncm_imac_idx:      db 0
cdc_ncm_caps:          db 0
cdc_ncm_ncfg:          db 0
cdc_ncm_present:       db 0
cdc_ncm_bind_step:     db 0
align 4
cdc_ncm_reg_rc:        dd 0
cdc_ncm_tx_align:      dd 4
cdc_ncm_tx_div:        dd 4
cdc_ncm_tx_rem:        dd 0
cdc_ncm_tx_max:        dd 0
cdc_ncm_rx_count:      dd 0
cdc_ncm_rx_next:       dd 0
cdc_ncm_insize:        dd 0, 0
cdc_ncm_tx_seq:        dw 0
cdc_ncm_mac:           times 6 db 0
align 8
cdc_ncm_tx_busy:       dd 0             ; atomic nonblocking owner of shared TX state
align 8
cdc_ncm_tx_len:        dq 0
cdc_ncm_stat_rx_frames: dq 0
cdc_ncm_stat_tx_frames: dq 0
cdc_ncm_rx_malformed:  dq 0
cdc_ncm_rx_chained:    dq 0              ; NTBs whose first NDP has a nonzero next link
cdc_ncm_dev:           times dev_size db 0
cdc_ncm_ops:           times netdev_ops_size db 0
cdc_ncm_setup:         times usb_setup_size db 0
cdc_ncm_in_ep_desc:    times 8 db 0
cdc_ncm_out_ep_desc:   times 8 db 0
cdc_ncm_ntbp:          times NTBP_SIZE db 0
align 4
cdc_ncm_rx_ent:        times (CNCM_MAX_DGRAMS * 2) dw 0
cdc_ncm_strbuf:        times 64 db 0
cdc_ncm_cfgbuf:        times CNCM_CFGBUF_SZ db 0
align 64
cdc_ncm_ntb:           times CNCM_NTB_IN db 0
cdc_ncm_txbuf:         times CNCM_NTB_OUT db 0
cdc_ncm_info:
    dq 0                                   ; .name: set at register time (org 0 image: no static pointers)
    dd 1500
    db 64
    dd 0
    dd 0
str_cncm_name:  db "cdc_ncm", 0
str_cncm_registered: db "[PAOS64] L2 netdev: USB CDC-NCM Ethernet bound via netdev_ops HANDLE [netdev.cdc_ncm.registered]", 13, 10, 0
str_cncm_skipped:    db "[PAOS64] L2 netdev: cdc_ncm skipped (no CDC-NCM function enumerated) [netdev.cdc_ncm.skipped]", 13, 10, 0
str_cncm_bind_failed: db "[PAOS64] L2 netdev: cdc_ncm bind FAILED step=", 0
str_cncm_bind_failed_tail: db " - not registered, onboard NICs unaffected [netdev.cdc_ncm.bind.failed]", 13, 10, 0
str_cncm_reg_rejected: db "[PAOS64] L2 netdev: cdc_ncm bound on USB but netdev_register REJECTED the handle [netdev.cdc_ncm.reg_rejected]", 13, 10, 0
str_cncm_diag:       db "[PAOS64] L2 netdev: cdc_ncm.diag port=", 0
str_cncm_diag_cfg:   db " cfg=", 0
str_cncm_diag_ntb:   db " ntb_align_div_rem=", 0
str_cncm_diag_mac:   db " mac0_3=", 0
