;; MODULE usb/enum
;; LAYER 4
;; EXPORTS usb_dev_boot_path_exact, usb_hc_members_snapshot, usb_dev_release_child, usb_dev_probe_next_hub_port, usb_dev_probe_next_root, usb_dev_refresh_root, usb_hc_register, usb_hub_record, usb_enumerate_all, usb_enum_selftest, usb_find_interrupt_in_ep, usb_dev_count, usb_dev_addr, usb_dev_desc_ptr, usb_dev_hc, usb_dev_is_null, usb_nulldev_register, usb_dev_topo_ptr, usb_hub_enumerate_all, usb_hub_gate_kat, usb_hub_route_extend, usb_hub_child_tt, usb_hub_admit, usb_hub_desc_parse, usb_boot_media_snapshot, usb_boot_path_parse, usb_boot_path_match
;; IMPORTS dev/usb/xhci, boot/serial, core/lib/fmt, core/lib/str, core/lib/mem, core/time
;; CAPS
;; OWNER saga:usb
; ============================================================================
; usb/enum.asm — THE USB DEVICE-ENUMERATION SEAM (contract 1031, DRIVER_MODEL.md
; §1 "usb_control_request is ONE upper-half", driver_classes.inc usbhc_ops).
;
; UNLIKE the block/net class cores that PORT backends into an existing seam, this
; ESTABLISHES the USB enumeration seam itself: a generic port-scan -> address ->
; GET_DESCRIPTOR flow that runs against ANY registered host-controller backend
; through the fixed usbhc_ops vtable. The xHCI controller (dev/usb/xhci.asm) and a
; degenerate virtual usb_nulldev BOTH register here and are enumerated by the SAME
; core — the nulldev proves the core is generic + unedited (DRIVER_MODEL §7: the
; fake backend is both the QEMU-no-hardware target AND the reference implementation).
;
; THE seam contract a backend fills (usbhc_ops, driver_classes.inc):
;   .port_status(self, RSI=port)            -> RAX = USB_PORT_* status bits
;   .control    (self, RSI=setup*, RDX=addr, RCX=buf, R8=buflen) -> RAX = len / -1
; (.control's data-buffer convention — RCX=buf, R8=cap — is the additive
;  concretization of the header's shared control transfer, which left the data
;  sink unspecified. Task2903 appends endpoint operations to the vtable; both
;  current implementors initialize every tail slot explicitly.)
;
; A backend also carries its root-hub port count in dev.flags low 16 bits (0 = probe
; port 1 only). The core reads the 18-byte DEVICE DESCRIPTOR off each connected port
; and content-validates it (bLength=0x12, bDescriptorType=0x01) before recording —
; a stub emitting the marker cannot fabricate a self-consistent descriptor + VID:PID.
;
; Fault rule (driver_classes.inc §1): every port is bounded — a STALL / short read /
; bad descriptor SKIPS that slot and the loop continues (one bad device never wedges
; the bus). No controller / no device -> zero real devices -> caller prints the
; documented skip; the seam never hangs.
; ============================================================================

; ---- abstract port-status bits (the seam's normalized view; backends map hw->this)
USB_PORT_CONNECT   equ (1 << 0)      ; a device is attached to this port
USB_PORT_ENABLED   equ (1 << 1)      ; port enabled / link trained

; ---- device descriptor byte offsets (USB 2.0 §9.6.1) -----------------------
USBD_BLENGTH       equ 0
USBD_BTYPE         equ 1
USBD_CLASS         equ 4
USBD_IDVENDOR      equ 8
USBD_IDPRODUCT     equ 10
USBD_TYPE_DEVICE   equ 0x01
USBD_LEN_DEVICE    equ 0x12          ; 18 bytes

; ---- common descriptor grammar (USB 2.0 9.6) ------------------------------
USBD_TYPE_ENDPOINT equ 0x05
USB_EP_DIR_IN      equ 0x80
USB_EP_NUM_MASK    equ 0x0F
USB_EP_XFER_MASK   equ 0x03
USB_EP_XFER_ISO    equ 0x01
USB_EP_XFER_BULK   equ 0x02
USB_EP_XFER_INTR   equ 0x03
USB_EP_MAX_PACKET  equ 1024          ; bounded high-speed interrupt payload

; ---- enumerated-device table -----------------------------------------------
USB_MAX_HC         equ 6             ; registered host controllers (4 xHCI + nulldev + spare)
USB_MAX_DEV        equ 16            ; root devices + bounded hub descendants (HUB0)

usb_hc_members_snapshot:
    jmp usb_hc_members_snapshot_impl

%include "usb/hc_members.inc"

struc usbdev
  .valid:  resb 1                    ; 1 = a validated device lives here
  .isnull: resb 1                    ; 1 = came from usb_nulldev (degenerate 2nd)
  .addr:   resb 1                    ; backend-neutral address: root port, or a hub-child token
  .pad:    resb 1
  .desc:   resb 18                   ; the raw 18-byte DEVICE DESCRIPTOR read off the wire
  .tail:   resb 2                    ; align the retained controller handle
  .hc:     resq 1                    ; exact usbhc dev that enumerated this device
  .topo:   resb usb_topo_size        ; HUB0: route/depth/parent/TT (zero for the nulldev)
endstruc
USBDEV_SZ          equ usbdev_size

; ---------------------------------------------------------------------------
; usb_find_interrupt_in_ep(RDI=descriptor blob, ESI=blob length,
;                          EDX=zero-based match ordinal) -> RAX=raw 7-byte
; endpoint descriptor / 0. Walks only complete, forward-moving descriptors.
; A zero/one-byte bLength, truncated record, endpoint zero, OUT endpoint,
; non-interrupt type, zero/oversize packet, or zero interval cannot escape the
; caller's blob and cannot be returned as a usable endpoint.
; ---------------------------------------------------------------------------
usb_find_interrupt_in_ep:
    test rdi, rdi
    jz   .not_found
    cmp  esi, 2
    jb   .not_found
    xor  ecx, ecx                    ; byte offset
    xor  r8d, r8d                    ; matching endpoint ordinal
.next:
    mov  eax, esi
    sub  eax, ecx
    cmp  eax, 2
    jb   .not_found                  ; no complete descriptor header remains
    lea  r9, [rdi + rcx]
    movzx eax, byte [r9 + usb_endpoint_desc.bLength]
    cmp  eax, 2
    jb   .not_found                  ; cannot make forward progress
    mov  r10d, ecx
    add  r10d, eax
    cmp  r10d, esi
    ja   .not_found                  ; descriptor crosses the bounded blob
    cmp  byte [r9 + usb_endpoint_desc.bDescriptorType], USBD_TYPE_ENDPOINT
    jne  .advance
    cmp  eax, usb_endpoint_desc_size
    jb   .advance
    movzx r11d, byte [r9 + usb_endpoint_desc.bEndpointAddress]
    test r11b, USB_EP_DIR_IN
    jz   .advance
    test r11b, 0x70                 ; bEndpointAddress bits 6:4 are reserved
    jnz  .advance
    mov  eax, r11d
    and  eax, USB_EP_NUM_MASK
    jz   .advance                    ; endpoint zero is control-only
    movzx eax, byte [r9 + usb_endpoint_desc.bmAttributes]
    and  eax, USB_EP_XFER_MASK
    cmp  eax, USB_EP_XFER_INTR
    jne  .advance
    movzx eax, word [r9 + usb_endpoint_desc.wMaxPacketSize]
    mov  r11d, eax
    shr  eax, 11
    and  eax, 3
    test eax, eax
    jnz  .advance                    ; this minimum seam does not configure HB transactions
    mov  eax, r11d
    and  eax, 0x07FF                 ; payload bits; transactions are separate
    test eax, eax
    jz   .advance
    cmp  eax, USB_EP_MAX_PACKET
    ja   .advance
    cmp  byte [r9 + usb_endpoint_desc.bInterval], 0
    je   .advance
    cmp  r8d, edx
    je   .found
    inc  r8d
.advance:
    mov  ecx, r10d
    cmp  ecx, esi
    jb   .next
.not_found:
    xor  eax, eax
    ret
.found:
    mov  rax, r9
    ret

; ---------------------------------------------------------------------------
; usb_hc_register(RDI = struct dev* of a CLASS_USBHC backend) -> RAX = REG_OK / -1.
;   Appends the controller handle to the enum registry (the sanctioned L3->L4 edge).
;   Registration order == enumeration order, so PRIO_NATIVE controllers register
;   BEFORE the nulldev and get the low device slots (the probe grades the first,
;   real, slot). clobbers: RAX,RCX,R8.
; ---------------------------------------------------------------------------
usb_hc_register:
    mov  ecx, [rel usb_hc_count]
    cmp  ecx, USB_MAX_HC
    jae  .full
    ; validate the handle is non-null and tagged CLASS_USBHC
    test rdi, rdi
    jz   .reject
    cmp  dword [rdi + dev.class], CLASS_USBHC
    jne  .reject
    lea  r8, [rel usb_hc_arr]
    mov  [r8 + rcx*8], rdi
    inc  ecx
    mov  [rel usb_hc_count], ecx
    xor  eax, eax                    ; REG_OK
    ret
.full:
.reject:
    mov  eax, -1
    ret

; ---------------------------------------------------------------------------
; usb_hc_nports(RDI = hc dev*) -> RAX = root-hub port count (>=1). dev.flags low
;   16 bits carry it; 0 is treated as 1 (probe at least port 1). clobbers: RAX.
; ---------------------------------------------------------------------------
usb_hc_nports:
    movzx eax, word [rdi + dev.flags]
    test eax, eax
    jnz  .have
    mov  eax, 1
.have:
    ret

; ---------------------------------------------------------------------------
; usb_enum_one_hc(RDI = hc dev*) — port-scan one controller, enumerate every
;   connected port's device (bounded), record validated descriptors. clobbers:
;   caller-saved. Uses r12=hc, r13=port, r14=nports, r15=ops.
; ---------------------------------------------------------------------------
usb_enum_one_hc:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi                    ; hc dev*
    call usb_hc_nports
    mov  r14d, eax                   ; nports
    mov  r15, [r12 + dev.ops]        ; usbhc_ops vtable
    mov  r13d, 1                     ; port index (1-based)
.port_loop:
    cmp  r13d, r14d
    ja   .done
    cmp  dword [rel usb_dev_n], USB_MAX_DEV
    jae  .done                       ; table full -> stop (bounded)
    ; --- port status ---
    mov  rdi, r12
    mov  esi, r13d
    call [r15 + usbhc_ops.port_status]
    test eax, USB_PORT_CONNECT
    jz   .next_port                  ; nothing attached here
    ; --- GET_DESCRIPTOR(device, 18) via the shared control transfer ---
    lea  rdi, [rel usb_setup_getdesc]
    mov  word [rdi + usb_setup.wValue], 0x0100   ; (type=DEVICE<<8) | index 0
    mov  word [rdi + usb_setup.wLength], USBD_LEN_DEVICE
    mov  byte [rdi + usb_setup.bmRequestType], 0x80   ; device->host, standard, device
    mov  byte [rdi + usb_setup.bRequest], 6            ; GET_DESCRIPTOR
    mov  word [rdi + usb_setup.wIndex], 0
    mov  rdi, r12                    ; self
    lea  rsi, [rel usb_setup_getdesc]
    mov  edx, r13d                   ; dev_addr = port (backend maps port->slot)
    lea  rcx, [rel usb_scratch_desc]
    mov  r8d, USBD_LEN_DEVICE
    call [r15 + usbhc_ops.control]
    cmp  eax, USBD_LEN_DEVICE
    je   .desc_read
    ; short / stall / error -> skip this port (isolate), but SAY so: which port, what rc
    push rax
    lea  rdi, [rel str_usb_port_skipped]
    call serial_string
    mov  edi, r13d
    call serial_hex64
    lea  rdi, [rel str_usb_port_rc]
    call serial_string
    pop  rax
    mov  edi, eax
    call serial_hex64
    lea  rdi, [rel str_usb_port_nl]
    call serial_string
    jmp  .next_port
.desc_read:
    ; --- content-validate the descriptor before recording ---
    cmp  byte [rel usb_scratch_desc + USBD_BLENGTH], USBD_LEN_DEVICE
    jne  .next_port
    cmp  byte [rel usb_scratch_desc + USBD_BTYPE], USBD_TYPE_DEVICE
    jne  .next_port
    ; --- record into the device table ---
    mov  ebx, [rel usb_dev_n]
    mov  eax, USBDEV_SZ
    mul  ebx                         ; eax = index * size (ebx < 16, size 48 -> fits)
    lea  rdi, [rel usb_dev_tbl]
    add  rdi, rax                    ; -> table slot
    mov  byte [rdi + usbdev.valid], 1
    mov  al, byte [r12 + dev.flags + 3]   ; high byte of flags: 1 if this hc is the nulldev
    mov  [rdi + usbdev.isnull], al
    mov  byte [rdi + usbdev.addr], r13b
    mov  [rdi + usbdev.hc], r12
    ; copy the 18 descriptor bytes verbatim
    push rdi
    add  rdi, usbdev.desc
    lea  rsi, [rel usb_scratch_desc]
    mov  edx, USBD_LEN_DEVICE
    call memcpy
    pop  rdi
    ; HUB0: retain the backend's topology (route 0 / depth 0 on a root port).
    ; A backend without the op (the nulldev) leaves the zeroed record.
    push rdi
    lea  rdx, [rdi + usbdev.topo]
    mov  rdi, r12
    mov  esi, r13d
    call [r15 + usbhc_ops.topology]
    pop  rdi
    test rax, rax
    jnz  .topo_done
    call usb_topo_line               ; RDI = entry
.topo_done:
    inc  dword [rel usb_dev_n]
    ; --- earned markers (fire once a real validated descriptor was read) ---
    mov  byte [rel usb_m_enum], 1
    mov  byte [rel usb_m_desc], 1
.next_port:
    inc  r13d
    jmp  .port_loop
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; usb_enumerate_all — run the generic enum core over every registered controller,
;   in registration order (real controllers first, nulldev last). clobbers:
;   caller-saved.
; ---------------------------------------------------------------------------
usb_enumerate_all:
    mov  dword [rel usb_probe_hc], 0
    mov  dword [rel usb_probe_port], 1
    push rbx
    push r12
    xor  ebx, ebx
.loop:
    cmp  ebx, [rel usb_hc_count]
    jae  .done
    lea  r12, [rel usb_hc_arr]
    mov  rdi, [r12 + rbx*8]
    call usb_enum_one_hc
    inc  ebx
    jmp  .loop
.done:
    pop  r12
    pop  rbx
    ret

; usb_dev_refresh_root(RDI=hc, ESI=known root port) -> EAX=index+1 / 0.
; Caller owns retirement/class custody. Refresh ONE existing unambiguous real
; root entry, never append or touch peers. Wire descriptor and current topology
; are committed together only after complete validation. No class/config writes.
usb_dev_refresh_root:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 64
    mov  r12, rdi
    mov  r13d, esi
    test rdi, rdi
    jz   .fail
    test esi, esi
    jz   .fail
    cmp  esi, 255
    ja   .fail
    call usb_hc_nports
    cmp  r13d, eax
    ja   .fail
    cmp  dword [rel usb_dev_n], USB_MAX_DEV
    ja   .fail
    xor  ebx, ebx
    xor  r14d, r14d
    xor  r15d, r15d
.find:
    cmp  ebx, [rel usb_dev_n]
    jae  .found
    imul eax, ebx, USBDEV_SZ
    lea  rdx, [rel usb_dev_tbl]
    add  rdx, rax
    cmp  byte [rdx + usbdev.valid], 1
    jne  .next
    cmp  byte [rdx + usbdev.isnull], 0
    jne  .next
    cmp  [rdx + usbdev.hc], r12
    jne  .next
    cmp  [rdx + usbdev.addr], r13b
    jne  .next
    cmp  byte [rdx + usbdev.topo + usb_topo.depth], 0
    jne  .fail
    cmp  word [rdx + usbdev.topo + usb_topo.parent_slot], 0
    jne  .fail
    cmp  dword [rdx + usbdev.topo + usb_topo.route], 0
    jne  .fail
    test r14, r14
    jnz  .fail                      ; ambiguous inventory never picks an owner
    mov  r14, rdx
    lea  r15d, [ebx + 1]
.next:
    inc  ebx
    jmp  .find
.found:
    test r14, r14
    jz   .fail
    mov  rbx, [r12 + dev.ops]
    test rbx, rbx
    jz   .fail
    cmp  qword [rbx + usbhc_ops.topology], 0
    je   .fail
    cmp  qword [rbx + usbhc_ops.port_status], 0
    je   .fail
    cmp  qword [rbx + usbhc_ops.control], 0
    je   .fail
    mov  rdi, r12
    mov  esi, r13d
    call [rbx + usbhc_ops.port_status]
    test eax, USB_PORT_CONNECT
    jz   .fail
    mov  rax, 0x0012000001000680
    mov  [rsp + 24], rax ; GET_DESCRIPTOR(device,18)
    mov  rdi, r12
    lea  rsi, [rsp + 24]
    mov  edx, r13d
    mov  rcx, rsp
    mov  r8d, USBD_LEN_DEVICE
    call [rbx + usbhc_ops.control]
    cmp  rax, USBD_LEN_DEVICE
    jne  .fail
    cmp  byte [rsp + USBD_BLENGTH], USBD_LEN_DEVICE
    jne  .fail
    cmp  byte [rsp + USBD_BTYPE], USBD_TYPE_DEVICE
    jne  .fail
    mov  qword [rsp + 32], 0
    mov  qword [rsp + 40], 0
    mov  rdi, r12
    mov  esi, r13d
    lea  rdx, [rsp + 32]
    call [rbx + usbhc_ops.topology]
    test rax, rax
    jnz  .fail
    cmp  byte [rsp + 32 + usb_topo.slot], 0
    je   .fail
    cmp  [rsp + 32 + usb_topo.root], r13b
    jne  .fail
    cmp  byte [rsp + 32 + usb_topo.depth], 0
    jne  .fail
    cmp  dword [rsp + 32 + usb_topo.parent_slot], 0 ; parents and TT absent
    jne  .fail
    cmp  dword [rsp + 32 + usb_topo.route], 0
    jne  .fail
    movzx eax, byte [rsp + 32 + usb_topo.speed]
    cmp  eax, USB_SPEED_FULL
    jb   .fail
    cmp  eax, USB_SPEED_SUPER
    ja   .fail
    mov  rax, [rsp]
    mov  [r14 + usbdev.desc], rax
    mov  rax, [rsp + 8]
    mov  [r14 + usbdev.desc + 8], rax
    mov  ax, [rsp + 16]
    mov  [r14 + usbdev.desc + 16], ax
    mov  rax, [rsp + 32]
    mov  [r14 + usbdev.topo], rax
    mov  rax, [rsp + 40]
    mov  [r14 + usbdev.topo + 8], rax
    mov  eax, r15d
    jmp  .out
.fail:
    xor  eax, eax
.out:
    add  rsp, 64
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; usb_dev_probe_root(RDI=registered hc, ESI=previously unknown root) -> index+1 / 0.
; Existing inventory excludes all peer classes before any device contact. Stage
; exact descriptor and root topology on stack; append only after both validate.
usb_dev_probe_root:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 64
    mov  r12, rdi
    mov  r13d, esi
    test rdi, rdi
    jz   .fail
    test esi, esi
    jz   .fail
    cmp  esi, 255
    ja   .fail
    mov  ecx, [rel usb_hc_count]
    cmp  ecx, USB_MAX_HC
    ja   .fail
    xor  edx, edx
    lea  r8, [rel usb_hc_arr]
.registered:
    test ecx, ecx
    jz   .registration_done
    cmp  [r8], r12
    jne  .registration_next
    inc  edx
.registration_next:
    add  r8, 8
    dec  ecx
    jmp  .registered
.registration_done:
    cmp  edx, 1
    jne  .fail                      ; exact registered handle, before dereference
    cmp  dword [r12 + dev.class], CLASS_USBHC
    jne  .fail
    cmp  byte [r12 + dev.flags + 3], 0
    jne  .fail                      ; never probe the synthetic nulldev
    call usb_hc_nports
    cmp  r13d, eax
    ja   .fail
    mov  r15d, [rel usb_dev_n]
    cmp  r15d, USB_MAX_DEV
    jae  .fail
    xor  ebx, ebx
.find:
    cmp  ebx, r15d
    jae  .found
    imul eax, ebx, USBDEV_SZ
    lea  rdx, [rel usb_dev_tbl]
    add  rdx, rax
    cmp  byte [rdx + usbdev.valid], 1
    jne  .next
    cmp  [rdx + usbdev.hc], r12
    jne  .next
    cmp  [rdx + usbdev.addr], r13b
    je   .fail                      ; every known class/child/null entry owns its address
.next:
    inc  ebx
    jmp  .find
.found:
    imul eax, r15d, USBDEV_SZ
    lea  r14, [rel usb_dev_tbl]
    add  r14, rax
    mov  rbx, [r12 + dev.ops]
    test rbx, rbx
    jz   .fail
    cmp  qword [rbx + usbhc_ops.topology], 0
    je   .fail
    cmp  qword [rbx + usbhc_ops.port_status], 0
    je   .fail
    cmp  qword [rbx + usbhc_ops.control], 0
    je   .fail
    mov  rdi, r12
    mov  esi, r13d
    call [rbx + usbhc_ops.port_status]
    test eax, USB_PORT_CONNECT
    jz   .fail
    mov  rax, 0x0012000001000680
    mov  [rsp + 24], rax ; GET_DESCRIPTOR(device,18)
    mov  rdi, r12
    lea  rsi, [rsp + 24]
    mov  edx, r13d
    mov  rcx, rsp
    mov  r8d, USBD_LEN_DEVICE
    call [rbx + usbhc_ops.control]
    cmp  rax, USBD_LEN_DEVICE
    jne  .fail
    cmp  byte [rsp + USBD_BLENGTH], USBD_LEN_DEVICE
    jne  .fail
    cmp  byte [rsp + USBD_BTYPE], USBD_TYPE_DEVICE
    jne  .fail
    mov  qword [rsp + 32], 0
    mov  qword [rsp + 40], 0
    mov  rdi, r12
    mov  esi, r13d
    lea  rdx, [rsp + 32]
    call [rbx + usbhc_ops.topology]
    test rax, rax
    jnz  .fail
    cmp  byte [rsp + 32 + usb_topo.slot], 0
    je   .fail
    cmp  [rsp + 32 + usb_topo.root], r13b
    jne  .fail
    cmp  byte [rsp + 32 + usb_topo.depth], 0
    jne  .fail
    cmp  dword [rsp + 32 + usb_topo.parent_slot], 0 ; parents and TT absent
    jne  .fail
    cmp  dword [rsp + 32 + usb_topo.route], 0
    jne  .fail
    movzx eax, byte [rsp + 32 + usb_topo.speed]
    cmp  eax, USB_SPEED_FULL
    jb   .fail
    cmp  eax, USB_SPEED_SUPER
    ja   .fail
    mov  rax, [rsp]
    mov  [r14 + usbdev.desc], rax
    mov  rax, [rsp + 8]
    mov  [r14 + usbdev.desc + 8], rax
    mov  ax, [rsp + 16]
    mov  [r14 + usbdev.desc + 16], ax
    mov  rax, [rsp + 32]
    mov  [r14 + usbdev.topo], rax
    mov  rax, [rsp + 40]
    mov  [r14 + usbdev.topo + 8], rax
    mov  byte [r14 + usbdev.isnull], 0
    mov  [r14 + usbdev.addr], r13b
    mov  byte [r14 + usbdev.pad], 0
    mov  word [r14 + usbdev.tail], 0
    mov  [r14 + usbdev.hc], r12
    mov  byte [r14 + usbdev.valid], 1 ; publish only fully validated wire data
    inc  r15d
    mov  [rel usb_dev_n], r15d
    mov  eax, r15d
    jmp  .out
.fail:
    xor  eax, eax
.out:
    add  rsp, 64
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Cooperative discovery examines one registry/port position per call. Known
; entries are skipped without I/O by probe_root; no bus-wide reinitialization.
usb_dev_probe_next_root:
    push rbx
    push r12
    push r13
    mov  ecx, [rel usb_hc_count]
    test ecx, ecx
    jz   .fail
    cmp  ecx, USB_MAX_HC
    ja   .fail
    mov  ebx, [rel usb_probe_hc]
    cmp  ebx, ecx
    jb   .index_ok
    xor  ebx, ebx
.index_ok:
    lea  rax, [rel usb_hc_arr]
    mov  r12, [rax + rbx*8]
    test r12, r12
    jz   .next_hc
    cmp  dword [r12 + dev.class], CLASS_USBHC
    jne  .next_hc
    cmp  byte [r12 + dev.flags + 3], 0
    jne  .next_hc
    mov  rdi, r12
    call usb_hc_nports
    cmp  eax, 255
    jbe  .port_limit
    mov  eax, 255
.port_limit:
    mov  r13d, [rel usb_probe_port]
    test r13d, r13d
    jz   .first_port
    cmp  r13d, eax
    jbe  .port_ok
.first_port:
    mov  r13d, 1
.port_ok:
    cmp  r13d, eax
    jae  .last_port
    lea  edx, [r13d + 1]
    mov  [rel usb_probe_port], edx
    mov  [rel usb_probe_hc], ebx
    jmp  .probe
.last_port:
    inc  ebx
    mov  [rel usb_probe_hc], ebx
    mov  dword [rel usb_probe_port], 1
.probe:
    mov  rdi, r12
    mov  esi, r13d
    call usb_dev_probe_root
    jmp  .out
.next_hc:
    inc  ebx
    mov  [rel usb_probe_hc], ebx
    mov  dword [rel usb_probe_port], 1
.fail:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret


; Cooperative discovery visits ONE port of a previously configured hub.
; Historical diagnostic records never grant live ownership. Only a retained
; generation plus exact current native topology can admit downstream traffic.
usb_dev_probe_next_hub_port:
    push rbx
    push r12
    push r13
    mov  r12d, [rel usb_dev_n]
    test r12d, r12d
    jz   .fail
    cmp  r12d, USB_MAX_DEV
    ja   .fail                       ; a full table may still hold a released child row
    mov  ebx, [rel usb_hub_probe_index]
    mov  r13d, r12d
.find:
    cmp  ebx, r12d
    jb   .index
    xor  ebx, ebx
.index:
    imul eax, ebx, USBDEV_SZ
    lea  rdx, [rel usb_dev_tbl]
    add  rdx, rax
    cmp  byte [rdx + usbdev.valid], 1
    jne  .next
    cmp  byte [rdx + usbdev.isnull], 0
    jne  .next
    cmp  byte [rdx + usbdev.desc + USBD_CLASS], USB_CLASS_HUB
    jne  .next
    lea  rcx, [rel usb_hub_owner_generation]
    cmp  dword [rcx + rbx*4], 0
    je   .next
    movzx eax, byte [rdx + usbdev.topo + usb_topo.hub_ports]
    test eax, eax
    jz   .next
    cmp  eax, 15
    ja   .next
    mov  edx, [rel usb_hub_probe_port]
    test edx, edx
    jz   .first
    cmp  edx, eax
    jbe  .port
.first:
    mov  edx, 1
.port:
    cmp  edx, eax
    jae  .last
    lea  eax, [rdx + 1]
    mov  [rel usb_hub_probe_port], eax
    mov  [rel usb_hub_probe_index], ebx
    jmp  .probe
.last:
    lea  eax, [rbx + 1]
    mov  [rel usb_hub_probe_index], eax
    mov  dword [rel usb_hub_probe_port], 1
.probe:
    mov  edi, ebx
    mov  esi, edx
    call usb_dev_probe_hub_port
    jmp  .out
.next:
    inc  ebx
    dec  r13d
    jnz  .find
    mov  [rel usb_hub_probe_index], ebx
.fail:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; EDI=known configured hub row, ESI=unused downstream port -> index+1 /0.
; Existing native AND inventory routes are excluded before any reset. A row
; released by confirmed child retirement is reused for its exact route; room is
; decided before any port request. After complete port status, debounce, one
; bounded reset, and recovery, descriptor and topology are staged together;
; failed admission leaves inventory intact.
usb_dev_probe_hub_port:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 72
    mov  r14d, esi
    cmp  edi, [rel usb_dev_n]
    jae  .child_fail
    cmp  dword [rel usb_dev_n], USB_MAX_DEV
    ja   .child_fail
    lea  rax, [rel usb_hub_owner_generation]
    mov  eax, [rax + rdi*4]
    mov  [rsp + 52], eax
    imul eax, edi, USBDEV_SZ
    lea  rbx, [rel usb_dev_tbl]
    add  rbx, rax
    mov  r12, [rbx + usbdev.hc]
    movzx r13d, byte [rbx + usbdev.addr]
    mov  rdi, r12
    mov  esi, r13d
    mov  edx, r14d
    mov  ecx, [rsp + 52]
    lea  r8, [rbx + usbdev.topo]
    call xhci_hub_port_available
    cmp  eax, 1
    jne  .child_fail
    mov  edi, [rbx + usbdev.topo + usb_topo.route]
    movzx esi, byte [rbx + usbdev.topo + usb_topo.depth]
    mov  edx, r14d
    call usb_hub_route_extend
    mov  [rsp + 48], eax
    and  eax, 0x000fffff
    lea  rdx, [rel usb_dev_tbl]
    mov  ecx, [rel usb_dev_n]
    mov  dword [rsp + 60], 0
.owned:
    cmp  [rdx + usbdev.hc], r12
    jne  .owned_next
    mov  r8b, [rbx + usbdev.topo + usb_topo.root]
    cmp  [rdx + usbdev.topo + usb_topo.root], r8b
    jne  .owned_next
    cmp  [rdx + usbdev.topo + usb_topo.route], eax
    jne  .owned_next
    cmp  byte [rdx + usbdev.valid], 1
    je   .child_fail                 ; unsupported or unconfirmed inventory still owns it
    cmp  byte [rdx + usbdev.valid], 0
    jne  .owned_next
    cmp  byte [rdx + usbdev.isnull], 0
    jne  .owned_next
    cmp  byte [rdx + usbdev.topo + usb_topo.depth], 0
    je   .owned_next
    mov  r8d, [rel usb_dev_n]
    sub  r8d, ecx
    inc  r8d
    mov  [rsp + 60], r8d             ; reuse the released row of this exact route
.owned_next:
    add  rdx, USBDEV_SZ
    loop .owned
    cmp  dword [rsp + 60], 0
    jne  .room
    cmp  dword [rel usb_dev_n], USB_MAX_DEV
    jae  .child_fail                 ; no released row and no room: no port request
.room:
    ; Preserve the firmware boot-media path before any port request.
    lea  rdi, [rel usb_boot_snap]
    movzx esi, byte [rbx + usbdev.topo + usb_topo.root]
    mov  edx, [rsp + 48]
    and  edx, 0x000fffff
    mov  ecx, [rsp + 48]
    shr  ecx, 24
    movzx r8d, byte [rbx + usbdev.topo + usb_topo.pci_dev]
    shl  r8d, 3
    movzx eax, byte [rbx + usbdev.topo + usb_topo.pci_fn]
    or   r8d, eax
    call usb_boot_path_match
    test eax, eax
    jnz  .child_fail
    mov  [rel usb_hub_hc], r12
    mov  esi, r13d
    mov  r8d, r14d
    call usb_hub_port_status
    jc   .child_fail
    test eax, USB_HUB_PS_CONNECTION
    jz   .child_fail
    mov  edi, USB_HUB_DEBOUNCE_MS * 1000
    call tsc_delay_us
    mov  esi, r13d
    mov  r8d, r14d
    call usb_hub_port_status
    jc   .child_fail
    test eax, USB_HUB_PS_CONNECTION
    jz   .child_fail
    mov  esi, r13d
    mov  edx, USB_HUB_REQ_SET_FEATURE
    mov  ecx, USB_HUB_FEAT_PORT_RESET
    mov  r8d, r14d
    call usb_hub_port_feature
    test rax, rax
    jnz  .child_fail
    mov  ebp, USB_HUB_RESET_POLLS
.reset:
    mov  edi, 10000
    call tsc_delay_us
    mov  esi, r13d
    mov  r8d, r14d
    call usb_hub_port_status
    jc   .child_fail
    test eax, USB_HUB_PS_CONNECTION
    jz   .child_fail
    test eax, USB_HUB_PS_RESET
    jnz  .wait
    test eax, USB_HUB_PS_ENABLE
    jnz  .enabled
.wait:
    dec  ebp
    jnz  .reset
    jmp  .child_fail
.enabled:
    mov  ebp, eax
    mov  esi, r13d
    mov  edx, USB_HUB_REQ_CLEAR_FEATURE
    mov  ecx, USB_HUB_FEAT_C_RESET
    mov  r8d, r14d
    call usb_hub_port_feature
    mov  edi, USB_HUB_RECOVERY_MS * 1000
    call tsc_delay_us
    mov  ecx, USB_SPEED_SUPER
    cmp  byte [rbx + usbdev.topo + usb_topo.speed], USB_SPEED_SUPER
    je   .speed
    mov  ecx, USB_SPEED_LOW
    test ebp, USB_HUB_PS_LOW_SPEED
    jnz  .speed
    mov  ecx, USB_SPEED_HIGH
    test ebp, USB_HUB_PS_HIGH_SPEED
    jnz  .speed
    mov  ecx, USB_SPEED_FULL
.speed:
    mov  [rsp + 56], ecx
    mov  rdi, r12
    mov  esi, r13d
    mov  edx, r14d
    mov  rax, [r12 + dev.ops]
    call [rax + usbhc_ops.hub_address_child]
    test rax, rax
    jle  .child_fail
    cmp  rax, 255
    ja   .child_fail
    mov  r15d, eax
    mov  qword [rsp], 0
    mov  qword [rsp + 8], 0
    mov  word [rsp + 16], 0
    mov  rdi, rsp
    mov  esi, r15d
    mov  edx, (USB_HUB_REQ_GET_DESCRIPTOR << 8) | 0x80
    mov  ecx, 0x0100
    xor  r8d, r8d
    mov  r9d, USBD_LEN_DEVICE
    call usb_hub_request
    cmp  rax, USBD_LEN_DEVICE
    jne  .child_fail
    cmp  byte [rsp], USBD_LEN_DEVICE
    jne  .child_fail
    cmp  byte [rsp + 1], USBD_TYPE_DEVICE
    jne  .child_fail
    mov  qword [rsp + 24], 0
    mov  qword [rsp + 32], 0
    mov  rdi, r12
    mov  esi, r15d
    lea  rdx, [rsp + 24]
    mov  rax, [r12 + dev.ops]
    call [rax + usbhc_ops.topology]
    test rax, rax
    jnz  .child_fail
    cmp  byte [rsp + 24 + usb_topo.slot], 0
    je   .child_fail
    mov  al, [rbx + usbdev.topo + usb_topo.slot]
    cmp  [rsp + 24 + usb_topo.parent_slot], al
    jne  .child_fail
    cmp  [rsp + 24 + usb_topo.parent_port], r14b
    jne  .child_fail
    mov  al, [rbx + usbdev.topo + usb_topo.root]
    cmp  [rsp + 24 + usb_topo.root], al
    jne  .child_fail
    mov  eax, [rsp + 48]
    mov  edx, eax
    shr  edx, 24
    cmp  [rsp + 24 + usb_topo.depth], dl
    jne  .child_fail
    and  eax, 0x000fffff
    cmp  [rsp + 24 + usb_topo.route], eax
    jne  .child_fail
    mov  eax, [rsp + 56]
    cmp  [rsp + 24 + usb_topo.speed], al
    jne  .child_fail
    movzx edi, byte [rbx + usbdev.topo + usb_topo.slot]
    movzx esi, byte [rbx + usbdev.topo + usb_topo.speed]
    movzx edx, word [rbx + usbdev.topo + usb_topo.tt_slot]
    mov  ecx, r14d
    mov  r8d, [rsp + 56]
    call usb_hub_child_tt
    test rax, rax
    js   .child_fail
    cmp  [rsp + 24 + usb_topo.tt_slot], ax
    jne  .child_fail
    mov  eax, [rsp + 60]
    test eax, eax
    jnz  .publish
    mov  eax, [rel usb_dev_n]
    cmp  eax, USB_MAX_DEV
    jae  .child_fail
    inc  eax
.publish:
    lea  edx, [eax - 1]
    imul edx, edx, USBDEV_SZ
    lea  rdi, [rel usb_dev_tbl]
    add  rdi, rdx
    mov  rdx, [rsp]
    mov  [rdi + usbdev.desc], rdx
    mov  rdx, [rsp + 8]
    mov  [rdi + usbdev.desc + 8], rdx
    mov  dx, [rsp + 16]
    mov  [rdi + usbdev.desc + 16], dx
    mov  rdx, [rsp + 24]
    mov  [rdi + usbdev.topo], rdx
    mov  rdx, [rsp + 32]
    mov  [rdi + usbdev.topo + 8], rdx
    mov  [rdi + usbdev.hc], r12
    mov  [rdi + usbdev.addr], r15b
    mov  byte [rdi + usbdev.isnull], 0
    mov  byte [rdi + usbdev.pad], 0
    mov  word [rdi + usbdev.tail], 0
    mov  byte [rdi + usbdev.valid], 1
    cmp  eax, [rel usb_dev_n]
    jbe  .out                        ; a reused row keeps the inventory count
    mov  [rel usb_dev_n], eax
    jmp  .out
.child_fail:
    xor  eax, eax
.out:
    add  rsp, 72
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; RDI=hc dev*, ESI=child token, only after a confirmed child Disable Slot.
; Releases exactly one downstream inventory row with that controller and
; address so live hub discovery can reuse its route. Root rows keep their
; reconnect path; ambiguous or absent inventory releases nothing. EAX=1/0.
usb_dev_release_child:
    xor  r8d, r8d
    lea  rdx, [rel usb_dev_tbl]
    mov  ecx, [rel usb_dev_n]
    test ecx, ecx
    jz   .rel_none
    cmp  ecx, USB_MAX_DEV
    ja   .rel_none
.rel_scan:
    cmp  byte [rdx + usbdev.valid], 1
    jne  .rel_next
    cmp  byte [rdx + usbdev.isnull], 0
    jne  .rel_next
    cmp  [rdx + usbdev.hc], rdi
    jne  .rel_next
    cmp  [rdx + usbdev.addr], sil
    jne  .rel_next
    cmp  byte [rdx + usbdev.topo + usb_topo.depth], 0
    je   .rel_next
    test r8, r8
    jnz  .rel_none                   ; ambiguous inventory releases nothing
    mov  r8, rdx
.rel_next:
    add  rdx, USBDEV_SZ
    dec  ecx
    jnz  .rel_scan
    test r8, r8
    jz   .rel_none
    mov  byte [r8 + usbdev.valid], 0
    mov  eax, 1
    ret
.rel_none:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; accessors used by the L5 USBLIST/USBDESC verb projection (svc/command_usb.asm).
; ---------------------------------------------------------------------------
; usb_dev_count() -> RAX = number of enumerated devices.
usb_dev_count:
    mov  eax, [rel usb_dev_n]
    ret

; usb_dev_addr(RDI = index) -> RAX = root-hub port (0 if out of range/invalid).
usb_dev_addr:
    cmp  edi, [rel usb_dev_n]
    jae  .none
    mov  eax, USBDEV_SZ
    mul  edi
    lea  rcx, [rel usb_dev_tbl]
    add  rcx, rax
    cmp  byte [rcx + usbdev.valid], 1
    jne  .none
    movzx eax, byte [rcx + usbdev.addr]
    ret
.none:
    xor  eax, eax
    ret

; usb_dev_hc(RDI = index) -> RAX = retained host-controller dev / 0.
usb_dev_hc:
    cmp  edi, [rel usb_dev_n]
    jae  .none
    mov  eax, USBDEV_SZ
    mul  edi
    lea  rcx, [rel usb_dev_tbl]
    add  rcx, rax
    cmp  byte [rcx + usbdev.valid], 1
    jne  .none
    mov  rax, [rcx + usbdev.hc]
    ret
.none:
    xor  eax, eax
    ret

; usb_dev_is_null(RDI = index) -> RAX = 1 if this slot is the usb_nulldev, else 0.
usb_dev_is_null:
    cmp  edi, [rel usb_dev_n]
    jae  .no
    mov  eax, USBDEV_SZ
    mul  edi
    lea  rcx, [rel usb_dev_tbl]
    add  rcx, rax
    movzx eax, byte [rcx + usbdev.isnull]
    ret
.no:
    xor  eax, eax
    ret

; usb_dev_topo_ptr(RDI = index) -> RAX = ptr to the entry's usb_topo, or 0.
usb_dev_topo_ptr:
    cmp  edi, [rel usb_dev_n]
    jae  .none
    mov  eax, USBDEV_SZ
    mul  edi
    lea  rcx, [rel usb_dev_tbl]
    add  rcx, rax
    cmp  byte [rcx + usbdev.valid], 1
    jne  .none
    lea  rax, [rcx + usbdev.topo]
    ret
.none:
    xor  eax, eax
    ret

; usb_dev_desc_ptr(RDI = index) -> RAX = ptr to the 18-byte descriptor, or 0.
usb_dev_desc_ptr:
    cmp  edi, [rel usb_dev_n]
    jae  .none
    mov  eax, USBDEV_SZ
    mul  edi
    lea  rcx, [rel usb_dev_tbl]
    add  rcx, rax
    cmp  byte [rcx + usbdev.valid], 1
    jne  .none
    lea  rax, [rcx + usbdev.desc]
    ret
.none:
    xor  eax, eax
    ret

; ===========================================================================
; usb_nulldev — the degenerate virtual USB host controller (DRIVER_MODEL §7 fake
;   backend). Reports ONE connected port and answers a canned, self-consistent
;   18-byte DEVICE DESCRIPTOR (VID:PID 0000:0000). It rides the SAME usbhc_ops
;   vtable + the SAME enum core — no special-casing in usb_enum_one_hc (if the core
;   had to be edited to accept it, the seam would be broken). Registered LAST so it
;   never steals a real device's grading slot.
; ===========================================================================
; usb_nulldev_port_status(self, RSI=port) -> RAX = status. Port 1 is "connected".
usb_nulldev_port_status:
    cmp  esi, 1
    jne  .empty
    mov  eax, USB_PORT_CONNECT | USB_PORT_ENABLED
    ret
.empty:
    xor  eax, eax
    ret

; usb_nulldev_control(self, RSI=setup*, RDX=addr, RCX=buf, R8=cap) -> RAX = len/-1.
;   Only answers GET_DESCRIPTOR(device); copies the canned 18-byte descriptor.
usb_nulldev_control:
    cmp  byte [rsi + usb_setup.bRequest], 6      ; GET_DESCRIPTOR
    jne  .stall
    cmp  r8d, USBD_LEN_DEVICE
    jb   .stall
    push rdi
    mov  rdi, rcx                                 ; dest buf
    lea  rsi, [rel usb_nulldev_desc]
    mov  edx, USBD_LEN_DEVICE
    call memcpy
    pop  rdi
    mov  eax, USBD_LEN_DEVICE
    ret
.stall:
    mov  eax, -1
    ret

; usb_nulldev_noop(self,...) -> 0 (init/start/stop/bulk are inert for the fake).
usb_nulldev_noop:
    xor  eax, eax
    ret

; The fake has no transferable endpoints.  Unsupported additive endpoint ops
; return AGAIN/error instead of pretending a queue or Configure Endpoint ran.
usb_nulldev_again:
    mov  rax, -1
    ret

; usb_nulldev_register — build the fake HC handle + register it behind the seam.
;   clobbers: RAX,RCX,R8,RDI.
usb_nulldev_register:
    lea  rdi, [rel usb_nulldev_ops]
    lea  rax, [rel usb_nulldev_noop]
    mov  [rdi + usbhc_ops.init], rax
    mov  [rdi + usbhc_ops.start], rax
    mov  [rdi + usbhc_ops.stop], rax
    lea  rax, [rel usb_nulldev_port_status]
    mov  [rdi + usbhc_ops.port_status], rax
    lea  rax, [rel usb_nulldev_control]
    mov  [rdi + usbhc_ops.control], rax
    lea  rax, [rel usb_nulldev_noop]
    mov  [rdi + usbhc_ops.bulk_in], rax
    mov  [rdi + usbhc_ops.bulk_out], rax
    lea  rax, [rel usb_nulldev_again]
    mov  [rdi + usbhc_ops.configure_ep], rax
    mov  qword [rdi + usbhc_ops.configure_ep_ss], 0 ; optional SS geometry absent
    mov  [rdi + usbhc_ops.interrupt_in_queue], rax
    mov  [rdi + usbhc_ops.interrupt_in_poll], rax
    mov  [rdi + usbhc_ops.hub_configure], rax       ; HUB0: no hub/topology support
    mov  [rdi + usbhc_ops.hub_address_child], rax
    mov  [rdi + usbhc_ops.topology], rax
    lea  rdi, [rel usb_nulldev_dev]
    lea  rax, [rel usb_nulldev_ops]
    mov  [rdi + dev.ops], rax
    mov  qword [rdi + dev.info], 0
    mov  qword [rdi + dev.priv], 0
    mov  dword [rdi + dev.prio], PRIO_DOMAIN         ; lowest — never preferred over real
    mov  dword [rdi + dev.health], HEALTH_OK
    mov  dword [rdi + dev.class], CLASS_USBHC
    ; flags: low16 = 1 port; byte[3] = 1 marks this hc as the nulldev (isnull tag source)
    mov  dword [rdi + dev.flags], 0x01000001
    mov  qword [rdi + dev.next], 0
    lea  rax, [rel str_usb_nulldev_name]
    mov  [rdi + dev.name], rax
    call usb_hc_register
    ret

; ---------------------------------------------------------------------------
; usb_enum_selftest — the boot entry: enumerate every registered controller, emit
;   the enumeration markers when a validated descriptor was read, and print the
;   documented skip line when NO real (non-null) device exists. Called from
;   boot/header AFTER the controllers register (xhci_usb_selftest + nulldev). The
;   xhci.controller.up marker is owned by the xhci backend; enum owns enum.device
;   + descriptor.read. clobbers: caller-saved.
; ---------------------------------------------------------------------------
usb_enum_selftest:
    push rbx
    ; ensure the degenerate 2nd is present behind the SAME seam
    call usb_nulldev_register
    call usb_enumerate_all
    ; HUB0: the generic hub class runs over the root inventory (BFS: children
    ; append behind their parent), then its pure gates are content-graded.
    call usb_hub_enumerate_all
    call usb_hub_gate_kat
    ; enum.device / descriptor.read markers (set inside the core when earned)
    cmp  byte [rel usb_m_enum], 1
    jne  .no_enum
    lea  rdi, [rel str_m_usb_enum]
    call serial_string
.no_enum:
    cmp  byte [rel usb_m_desc], 1
    jne  .no_desc
    lea  rdi, [rel str_m_usb_desc]
    call serial_string
.no_desc:
    ; documented skip: if NO real (non-null) device enumerated, print the SKIP line
    ; the probe greps (never a false PASS). Count real devices.
    xor  ebx, ebx                    ; index
    xor  ecx, ecx                    ; real count
.count:
    cmp  ebx, [rel usb_dev_n]
    jae  .counted
    mov  edi, ebx
    push rcx
    call usb_dev_is_null
    pop  rcx
    test eax, eax
    jnz  .cnext
    inc  ecx
.cnext:
    inc  ebx
    jmp  .count
.counted:
    test ecx, ecx
    jnz  .have_real
    lea  rdi, [rel str_usb_skipped]
    call serial_string
.have_real:
    pop  rbx
    ret

; ===========================================================================
; HUB0 usb_hub_enumeration_core — the GENERIC hub class (port-and-generalize of
; the MSI Task1192 USB2 hub path, which was first-tier only and pinned to one
; MSI hub port). Everything protocol-level lives here and runs through the
; usbhc_ops seam; the backend (dev/usb/xhci) owns only Slot-Context work:
; .hub_configure (Hub/ports/TTT), .hub_address_child (route string + parent +
; TT fields -> Address Device) and .topology (read-only identity).
;
; Policy (no pinned ports): every admitted hub is configured, every downstream
; port is powered and scanned, every connected port is reset ONCE and its
; device addressed — EXCEPT a port on the firmware's boot-media path (captured
; pre-EBS from LoadedImage's DevicePath), which is never re-reset. Bounds:
; USB_HUB_MAX_DEPTH hub tiers (USB 2.0 4.1.1; one route nibble per tier),
; USB_HUB_MAX_PORTS per hub, USB_HUB_MAX_HUBS hubs, USB_MAX_DEV devices and the
; backend's slot budget. Every wait is a bounded poll; every refusal is a
; serial line, never a hang. Hub hot-plug/detach (change handling after boot)
; is HUB1.
; ===========================================================================

USB_CLASS_HUB              equ 9
USB_HUB_DT_USB2            equ 0x29
USB_HUB_DT_SS              equ 0x2A
USB_HUB_MAX_DEPTH          equ 5
USB_HUB_MAX_PORTS          equ 15
USB_HUB_MAX_HUBS           equ 6
USB_HUB_CFG_CAP            equ 128
USB_HUB_REQ_GET_STATUS     equ 0
USB_HUB_REQ_CLEAR_FEATURE  equ 1
USB_HUB_REQ_SET_FEATURE    equ 3
USB_HUB_REQ_GET_DESCRIPTOR equ 6
USB_HUB_REQ_SET_CONFIG     equ 9
USB_HUB_REQ_SET_HUB_DEPTH  equ 12
USB_HUB_FEAT_PORT_RESET    equ 4
USB_HUB_FEAT_PORT_POWER    equ 8
USB_HUB_FEAT_C_CONNECTION  equ 16
USB_HUB_FEAT_C_ENABLE      equ 17
USB_HUB_FEAT_C_RESET       equ 20
USB_HUB_PS_CONNECTION      equ (1 << 0)
USB_HUB_PS_ENABLE          equ (1 << 1)
USB_HUB_PS_RESET           equ (1 << 4)
USB_HUB_PS_LOW_SPEED       equ (1 << 9)
USB_HUB_PS_HIGH_SPEED      equ (1 << 10)
USB_HUB_PC_CONNECTION      equ (1 << 16)
USB_HUB_PC_ENABLE          equ (1 << 17)
USB_HUB_RESET_POLLS        equ 20       ; x 10 ms
USB_HUB_SETTLE_POLLS       equ 10       ; x 10 ms, first connect after power-good
USB_HUB_STATUS_POLLS       equ 4        ; x 16 ms, first status-change bitmap
USB_HUB_PGOOD_MIN_MS       equ 100      ; external hub power-good floor
USB_HUB_DEBOUNCE_MS        equ 100      ; USB 2.0 7.1.7.3 TATTDB
USB_HUB_RECOVERY_MS        equ 10       ; TRSTRCY

; refusal reasons (usb_hub_reason_names order)
USB_HUB_OK                 equ 0
USB_HUB_R_DEPTH            equ 1
USB_HUB_R_ZERO_PORTS       equ 2
USB_HUB_R_WIDE             equ 3
USB_HUB_R_SPEED            equ 4
USB_HUB_R_PROTO            equ 5
USB_HUB_R_BUDGET           equ 6
USB_HUB_R_CONFIG           equ 7
USB_HUB_R_DESC             equ 8
USB_HUB_R_HUB_CTX          equ 9
USB_HUB_R_SET_DEPTH        equ 10

; ---------------------------------------------------------------------------
; usb_hub_route_extend(EDI=parent route, ESI=parent depth, EDX=downstream port)
;   -> RAX = child route | (child depth << 24), or -1. Pure. Refuses port 0 or
;   > 15, a parent already at USB_HUB_MAX_DEPTH (a 6th tier has no route
;   nibble), and a malformed parent route (a zero nibble inside its depth or a
;   nonzero nibble above it).
; ---------------------------------------------------------------------------
usb_hub_route_extend:
    test edx, edx
    jz   .bad
    cmp  edx, USB_HUB_MAX_PORTS
    ja   .bad
    cmp  esi, USB_HUB_MAX_DEPTH
    jae  .bad
    xor  r8d, r8d
.nibble:
    cmp  r8d, esi
    jae  .above
    lea  ecx, [r8d * 4]
    mov  eax, edi
    shr  eax, cl
    test eax, 0x0F
    jz   .bad
    inc  r8d
    jmp  .nibble
.above:
    lea  ecx, [esi * 4]
    mov  eax, edi
    shr  eax, cl
    test eax, eax
    jnz  .bad
    mov  eax, edx
    shl  eax, cl
    or   eax, edi
    lea  edx, [esi + 1]
    shl  edx, 24
    or   eax, edx
    ret
.bad:
    mov  rax, -1
    ret

; ---------------------------------------------------------------------------
; usb_hub_admit(EDI=hub depth, ESI=downstream ports, EDX=hub speed) -> EAX =
;   USB_HUB_OK or a refusal reason. Pure. A hub at depth USB_HUB_MAX_DEPTH (the
;   6th non-root hub) could only have children at an illegal 7th tier.
; ---------------------------------------------------------------------------
usb_hub_admit:
    cmp  edx, USB_SPEED_FULL
    je   .speed_ok
    cmp  edx, USB_SPEED_HIGH
    je   .speed_ok
    cmp  edx, USB_SPEED_SUPER
    je   .speed_ok
    mov  eax, USB_HUB_R_SPEED
    ret
.speed_ok:
    cmp  edi, USB_HUB_MAX_DEPTH
    jae  .depth
    test esi, esi
    jz   .zero
    cmp  esi, USB_HUB_MAX_PORTS
    ja   .wide
    xor  eax, eax
    ret
.depth:
    mov  eax, USB_HUB_R_DEPTH
    ret
.zero:
    mov  eax, USB_HUB_R_ZERO_PORTS
    ret
.wide:
    mov  eax, USB_HUB_R_WIDE
    ret

; ---------------------------------------------------------------------------
; usb_hub_child_tt(EDI=parent slot, ESI=parent speed, EDX=parent TT (slot |
;   port << 8), ECX=downstream port, R8D=child speed) -> RAX = child TT (slot |
;   port << 8; 0 = none) or -1. Pure. A LS/FS child of a HS hub uses that hub's
;   TT; one deeper behind a FS hub inherits the parent's TT; HS/SS children
;   have none. SuperSpeed and USB2 never mix on one hub.
; ---------------------------------------------------------------------------
usb_hub_child_tt:
    cmp  r8d, USB_SPEED_SUPER
    je   .child_ss
    cmp  esi, USB_SPEED_SUPER
    je   .bad
    cmp  r8d, USB_SPEED_HIGH
    je   .child_hs
    cmp  r8d, USB_SPEED_FULL
    je   .child_lsfs
    cmp  r8d, USB_SPEED_LOW
    jne  .bad
.child_lsfs:
    cmp  esi, USB_SPEED_HIGH
    je   .own_tt
    cmp  esi, USB_SPEED_FULL
    jne  .bad
    movzx eax, dx
    ret
.own_tt:
    test edi, edi
    jz   .bad
    cmp  edi, 255
    ja   .bad
    test ecx, ecx
    jz   .bad
    cmp  ecx, USB_HUB_MAX_PORTS
    ja   .bad
    mov  eax, ecx
    shl  eax, 8
    or   eax, edi
    ret
.child_hs:
    cmp  esi, USB_SPEED_HIGH
    jne  .bad
    xor  eax, eax
    ret
.child_ss:
    cmp  esi, USB_SPEED_SUPER
    jne  .bad
    xor  eax, eax
    ret
.bad:
    mov  rax, -1
    ret

; ---------------------------------------------------------------------------
; usb_hub_desc_parse(RDI=descriptor, ESI=bytes held, EDX=USB_HUB_DT_USB2|_SS,
;   RCX=4-dword out {ports, TT think time, power-good ms, characteristics})
;   -> EAX 0/-1. Pure; nothing is written on refusal. USB2 0x29: 7 fixed bytes
;   + DeviceRemovable (ceil((n+1)/8)) [+ legacy PortPwrCtrlMask, which real hubs
;   and QEMU size differently]; SS 0x2A: exactly 12 bytes. bNbrPorts 0 refused
;   (zero-port hub); the route-nibble width is policy (usb_hub_admit).
; ---------------------------------------------------------------------------
usb_hub_desc_parse:
    test rdi, rdi
    jz   .bad
    test rcx, rcx
    jz   .bad
    cmp  esi, 7
    jb   .bad
    movzx eax, byte [rdi]
    cmp  eax, esi
    ja   .bad                        ; claims more than was read
    cmp  [rdi + 1], dl
    jne  .bad
    movzx r8d, byte [rdi + 2]
    test r8d, r8d
    jz   .bad
    cmp  edx, USB_HUB_DT_SS
    je   .ss
    cmp  edx, USB_HUB_DT_USB2
    jne  .bad
    lea  r9d, [r8d + 8]
    shr  r9d, 3                      ; DeviceRemovable bytes
    lea  r10d, [r9d + 7]
    cmp  eax, r10d
    jb   .bad
    lea  r10d, [r9d * 2 + 7]
    cmp  eax, r10d
    ja   .bad
    movzx r10d, word [rdi + 3]
    mov  r11d, r10d
    shr  r11d, 5
    and  r11d, 3                     ; TT think time (HS hubs)
    jmp  .emit
.ss:
    cmp  eax, 12
    jne  .bad
    movzx r10d, word [rdi + 3]
    xor  r11d, r11d
.emit:
    movzx eax, byte [rdi + 5]
    shl  eax, 1                      ; bPwrOn2PwrGood, 2 ms units
    mov  [rcx], r8d
    mov  [rcx + 4], r11d
    mov  [rcx + 8], eax
    mov  [rcx + 12], r10d
    xor  eax, eax
    ret
.bad:
    mov  eax, -1
    ret

; ---------------------------------------------------------------------------
; Boot-media identity (the policy that replaces MSI's pinned hub port).
; Snapshot record (12 bytes): +0 parsed, +1 USB node count, +2 controller PCI
; dev<<3|fn, +3 pad, +4.. zero-based USB ParentPortNumber chain (root first).
; ---------------------------------------------------------------------------

; usb_boot_path_parse(RDI=EFI device path, RSI=snapshot out) -> EAX 0/-1. Pure,
;   bounded (64 nodes / 1024 bytes / 8 USB nodes). Unparseable -> zero record.
usb_boot_path_parse:
    mov  dword [rsi], 0
    mov  qword [rsi + 4], 0
    test rdi, rdi
    jz   .bad
    xor  r8d, r8d                    ; bytes walked
    xor  r9d, r9d                    ; nodes walked
    xor  r10d, r10d                  ; 0x100 | last PCI dev<<3|fn before USB
    xor  r11d, r11d                  ; USB nodes
.node:
    cmp  r9d, 64
    jae  .bad
    movzx eax, byte [rdi]
    cmp  eax, 0x7F
    je   .end
    movzx ecx, word [rdi + 2]
    cmp  ecx, 4
    jb   .bad
    add  r8d, ecx
    cmp  r8d, 1024
    ja   .bad
    cmp  eax, 1                      ; Hardware
    jne  .messaging
    cmp  byte [rdi + 1], 1           ; PCI
    jne  .next
    cmp  ecx, 6
    jb   .bad
    test r11d, r11d
    jnz  .next
    movzx eax, byte [rdi + 5]        ; Device
    and  eax, 0x1F
    shl  eax, 3
    movzx edx, byte [rdi + 4]        ; Function
    and  edx, 7
    or   eax, edx
    or   eax, 0x100
    mov  r10d, eax
    jmp  .next
.messaging:
    cmp  eax, 3
    jne  .next
    cmp  byte [rdi + 1], 5           ; USB(ParentPortNumber, Interface)
    jne  .next
    cmp  ecx, 6
    jb   .bad
    test r10d, r10d
    jz   .bad
    cmp  r11d, 8
    jae  .bad
    mov  al, [rdi + 4]
    mov  [rsi + 4 + r11], al
    inc  r11d
.next:
    add  rdi, rcx
    inc  r9d
    jmp  .node
.end:
    mov  byte [rsi], 1
    mov  [rsi + 1], r11b
    mov  [rsi + 2], r10b
    xor  eax, eax
    ret
.bad:
    mov  dword [rsi], 0
    mov  qword [rsi + 4], 0
    mov  eax, -1
    ret

; usb_boot_path_match(RDI=snapshot, ESI=root port, EDX=route, ECX=depth,
;   R8D=controller dev<<3|fn) -> EAX 0 not on the boot path / 1 the boot-media
;   port itself / 2 a hub port upstream of the boot media. Pure.
usb_boot_path_match:
    cmp  byte [rdi], 1
    jne  .none
    movzx r9d, byte [rdi + 1]
    test r9d, r9d
    jz   .none
    cmp  [rdi + 2], r8b
    jne  .none
    mov  r11d, ecx
    lea  eax, [r11d + 1]
    cmp  eax, r9d
    ja   .none
    lea  eax, [esi - 1]
    cmp  [rdi + 4], al
    jne  .none
    xor  r10d, r10d
.hop:
    cmp  r10d, r11d
    jae  .on_path
    lea  ecx, [r10d * 4]
    mov  eax, edx
    shr  eax, cl
    and  eax, 0x0F
    dec  eax
    cmp  [rdi + 5 + r10], al
    jne  .none
    inc  r10d
    jmp  .hop
.on_path:
    lea  eax, [r11d + 1]
    cmp  eax, r9d
    je   .exact
    mov  eax, 2
    ret
.exact:
    mov  eax, 1
    ret
.none:
    xor  eax, eax
    ret

; usb_dev_boot_path_exact(EDI=enum row) -> EAX 1 exact boot medium, 0 other.
; Existing firmware snapshot + current row; no wire traffic or ownership.
; Full controller BDF is checked separately by the storage caller. The old
; matcher returns 2 for an upstream hub: that is deliberately not admission.
usb_dev_boot_path_exact:
    sub rsp, 8
    call usb_dev_topo_ptr
    test rax, rax
    jz .none
    cmp byte [rax + usb_topo.slot], 0
    je .none
    movzx ecx, byte [rax + usb_topo.depth]
    cmp ecx, 5
    ja .none
    mov edx, [rax + usb_topo.route]
    ; Reject route bits outside the advertised depth, not a masked alias.
    mov r9d, ecx
    shl ecx, 2
    mov r10d, edx
    shr r10d, cl
    test r10d, r10d
    jnz .none
    mov ecx, r9d
    mov r10d, edx
.route_hop:
    test r9d, r9d
    jz .route_valid
    test r10b, 0x0f
    jz .none
    shr r10d, 4
    dec r9d
    jmp .route_hop
.route_valid:
    movzx esi, byte [rax + usb_topo.root]
    test esi, esi
    jz .none
    movzx r8d, byte [rax + usb_topo.pci_dev]
    cmp r8d, 31
    ja .none
    shl r8d, 3
    movzx r9d, byte [rax + usb_topo.pci_fn]
    cmp r9d, 7
    ja .none
    or r8d, r9d
    lea rdi, [rel usb_boot_snap]
    call usb_boot_path_match
    cmp eax, 1
    sete al
    movzx eax, al
    add rsp, 8
    ret
.none:
    xor eax, eax
    add rsp, 8
    ret

; usb_boot_media_snapshot — PRE-EBS (boot services live, early trap armed):
;   HandleProtocol(LoadedImage) -> DeviceHandle -> HandleProtocol(DevicePath)
;   -> usb_boot_path_parse. Read-only; any failure leaves "not parsed", which
;   simply means no hub port is treated as boot media. Self-aligning frame.
usb_boot_media_snapshot:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    and  rsp, -16
    sub  rsp, 48
    lea  rsi, [rel usb_boot_snap]
    mov  dword [rsi], 0
    mov  qword [rsi + 4], 0
    mov  rbx, [rel boot_services]
    test rbx, rbx
    jz   .out
    mov  qword [rsp + 32], 0
    mov  rcx, [rel image_handle]
    lea  rdx, [rel usb_boot_li_guid]
    lea  r8, [rsp + 32]
    call [rbx + 0x98]                ; HandleProtocol(ImageHandle, LoadedImage)
    mov  [rel usb_boot_status], rax
    test rax, rax
    jnz  .out
    mov  rax, [rsp + 32]
    test rax, rax
    jz   .out
    mov  rcx, [rax + 24]             ; EFI_LOADED_IMAGE.DeviceHandle
    test rcx, rcx
    jz   .out
    mov  qword [rsp + 40], 0
    lea  rdx, [rel usb_boot_dp_guid]
    lea  r8, [rsp + 40]
    call [rbx + 0x98]                ; HandleProtocol(DeviceHandle, DevicePath)
    mov  [rel usb_boot_status], rax
    test rax, rax
    jnz  .out
    mov  rdi, [rsp + 40]
    lea  rsi, [rel usb_boot_snap]
    call usb_boot_path_parse
.out:
    lea  rsp, [rbp - 16]
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ---------------------------------------------------------------------------
; Wire helpers over the current hub's controller (usb_hub_hc).
; usb_hub_request(RDI=buf, ESI=addr, EDX=bmRequestType|bRequest<<8, ECX=wValue,
;   R8D=wIndex, R9D=wLength) -> RAX = backend control result.
; ---------------------------------------------------------------------------
usb_hub_request:
    push rbx
    lea  rbx, [rel usb_hub_setup]
    mov  [rbx + usb_setup.bmRequestType], dl
    mov  [rbx + usb_setup.bRequest], dh
    mov  [rbx + usb_setup.wValue], cx
    mov  [rbx + usb_setup.wIndex], r8w
    mov  [rbx + usb_setup.wLength], r9w
    mov  rcx, rdi
    mov  r8d, r9d
    mov  edx, esi
    mov  rsi, rbx
    mov  rdi, [rel usb_hub_hc]
    mov  rax, [rdi + dev.ops]
    call [rax + usbhc_ops.control]
    pop  rbx
    ret

; usb_hub_port_feature(ESI=hub addr, EDX=request, ECX=feature, R8D=port) -> RAX.
usb_hub_port_feature:
    shl  edx, 8
    or   edx, 0x23
    xor  edi, edi
    xor  r9d, r9d
    jmp  usb_hub_request

; usb_hub_port_status(ESI=hub addr, R8D=port) -> EAX status|change<<16, CF=0;
;   CF=1 on a failed/short transfer.
usb_hub_port_status:
    mov  dword [rel usb_hub_status], 0
    lea  rdi, [rel usb_hub_status]
    mov  edx, (USB_HUB_REQ_GET_STATUS << 8) | 0xA3
    xor  ecx, ecx
    mov  r9d, 4
    call usb_hub_request
    cmp  rax, 4
    jne  .fail
    mov  eax, [rel usb_hub_status]
    clc
    ret
.fail:
    stc
    ret

; usb_hub_topo_refresh(RBX=entry) — re-read the backend topology into the row.
usb_hub_topo_refresh:
    mov  rdi, [rbx + usbdev.hc]
    movzx esi, byte [rbx + usbdev.addr]
    lea  rdx, [rbx + usbdev.topo]
    mov  rax, [rdi + dev.ops]
    jmp  [rax + usbhc_ops.topology]

; ---------------------------------------------------------------------------
; usb_hub_enumerate_all — BFS over the device table. Children append behind
;   their parent, so nested hubs are reached in tier order; the table bound
;   USB_MAX_DEV ends the walk. clobbers: caller-saved.
; ---------------------------------------------------------------------------
usb_hub_enumerate_all:
    push rbx
    push r12
    call usb_hub_bootmedia_line
    xor  ebx, ebx
.next:
    cmp  ebx, [rel usb_dev_n]
    jae  .done
    mov  eax, ebx
    imul eax, USBDEV_SZ
    lea  r12, [rel usb_dev_tbl]
    add  r12, rax
    cmp  byte [r12 + usbdev.valid], 1
    jne  .advance
    cmp  byte [r12 + usbdev.isnull], 0
    jne  .advance
    cmp  byte [r12 + usbdev.topo + usb_topo.slot], 0
    je   .advance                    ; backend without topology: no hub class
    cmp  byte [r12 + usbdev.desc + USBD_CLASS], USB_CLASS_HUB
    jne  .advance
    mov  edi, ebx
    call usb_hub_configure_one
.advance:
    inc  ebx
    jmp  .next
.done:
    cmp  dword [rel usb_hub_count], 0
    je   .no_hub
    lea  rdi, [rel str_m_usb_hub_enum]
    call serial_string
.no_hub:
    cmp  dword [rel usb_hub_children], 0
    je   .no_child
    lea  rdi, [rel str_m_usb_hub_child]
    call serial_string
.no_child:
    cmp  dword [rel usb_hub_refused_depth], 0
    je   .out
    lea  rdi, [rel str_m_usb_hub_depth]
    call serial_string
.out:
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; usb_hub_configure_one(EDI = device-table index of an addressed hub).
;   rbx = hub row, r12d = hub addr, r13d/r15 scratch, r14d = port, ebp = status.
; ---------------------------------------------------------------------------
usb_hub_configure_one:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8
    mov  eax, edi
    imul eax, USBDEV_SZ
    lea  rbx, [rel usb_dev_tbl]
    add  rbx, rax
    mov  rax, [rbx + usbdev.hc]
    mov  [rel usb_hub_hc], rax
    movzx r12d, byte [rbx + usbdev.addr]
    lea  rdi, [rel usb_hub_cur]
    mov  ecx, usb_hub_cur_end - usb_hub_cur
    xor  eax, eax
    rep  stosb

    ; ---- admission before any wire traffic: tier depth + speed + protocol
    movzx edi, byte [rbx + usbdev.topo + usb_topo.depth]
    mov  esi, 1
    movzx edx, byte [rbx + usbdev.topo + usb_topo.speed]
    call usb_hub_admit
    test eax, eax
    jnz  .refuse
    movzx ecx, byte [rbx + usbdev.desc + 6]      ; bDeviceProtocol
    movzx edx, byte [rbx + usbdev.topo + usb_topo.speed]
    mov  eax, USB_HUB_R_PROTO
    cmp  edx, USB_SPEED_FULL
    jne  .proto_hs
    test ecx, ecx
    jnz  .refuse
    jmp  .proto_ok
.proto_hs:
    cmp  edx, USB_SPEED_HIGH
    jne  .proto_ss
    cmp  ecx, 1
    jb   .refuse
    cmp  ecx, 2
    ja   .refuse
    jmp  .proto_ok
.proto_ss:
    cmp  ecx, 3
    jne  .refuse
.proto_ok:
    mov  eax, USB_HUB_R_BUDGET
    cmp  dword [rel usb_hub_count], USB_HUB_MAX_HUBS
    jae  .refuse

    ; ---- configuration descriptor (two bounded reads) + SET_CONFIGURATION
    lea  rdi, [rel usb_hub_cfg]
    mov  esi, r12d
    mov  edx, (USB_HUB_REQ_GET_DESCRIPTOR << 8) | 0x80
    mov  ecx, 0x0200
    xor  r8d, r8d
    mov  r9d, 9
    call usb_hub_request
    mov  r13d, eax
    mov  eax, USB_HUB_R_CONFIG
    cmp  r13d, 9
    jne  .refuse
    cmp  byte [rel usb_hub_cfg + 1], 2
    jne  .refuse
    movzx r13d, word [rel usb_hub_cfg + 2]
    cmp  r13d, 9
    jb   .refuse
    cmp  r13d, USB_HUB_CFG_CAP
    ja   .refuse
    lea  rdi, [rel usb_hub_cfg]
    mov  ecx, USB_HUB_CFG_CAP
    xor  eax, eax
    rep  stosb
    lea  rdi, [rel usb_hub_cfg]
    mov  esi, r12d
    mov  edx, (USB_HUB_REQ_GET_DESCRIPTOR << 8) | 0x80
    mov  ecx, 0x0200
    xor  r8d, r8d
    mov  r9d, r13d
    call usb_hub_request
    cmp  eax, r13d
    mov  eax, USB_HUB_R_CONFIG
    jne  .refuse
    cmp  word [rel usb_hub_cfg + 2], r13w
    jne  .refuse
    lea  rdi, [rel usb_hub_cfg]
    mov  esi, r13d
    xor  edx, edx
    call usb_find_interrupt_in_ep     ; the status-change endpoint (optional)
    mov  [rel usb_hub_cur_epdesc], rax
    xor  edi, edi
    mov  esi, r12d
    mov  edx, (USB_HUB_REQ_SET_CONFIG << 8)
    movzx ecx, byte [rel usb_hub_cfg + 5]
    xor  r8d, r8d
    xor  r9d, r9d
    call usb_hub_request
    test rax, rax
    mov  eax, USB_HUB_R_CONFIG
    jnz  .refuse

    ; ---- hub class descriptor (USB2 0x29 / SuperSpeed 0x2A)
    lea  rdi, [rel usb_hub_desc]
    xor  eax, eax
    mov  ecx, 16
    rep  stosb
    mov  r13d, 11
    mov  r15d, USB_HUB_DT_USB2
    cmp  byte [rbx + usbdev.topo + usb_topo.speed], USB_SPEED_SUPER
    jne  .desc_read
    mov  r13d, 12
    mov  r15d, USB_HUB_DT_SS
.desc_read:
    lea  rdi, [rel usb_hub_desc]
    mov  esi, r12d
    mov  edx, (USB_HUB_REQ_GET_DESCRIPTOR << 8) | 0xA0
    mov  ecx, r15d
    shl  ecx, 8
    xor  r8d, r8d
    mov  r9d, r13d
    call usb_hub_request
    ; 0.0.51 gate (2026-10-02): since 27770d782 a control IN returns the bytes actually
    ; RECEIVED, not wLength. A USB2 hub sends bDescLength (7 + DeviceRemovable +
    ; PortPwrCtrlMask; 9 for QEMU's 8-port hub) of the 11 asked for, so the old
    ; "== wLength" test refused every hub. Hand the received count to the
    ; length-aware parser; a failed transfer (-1/-2), fewer than 7 bytes or more
    ; than asked for refuses; a SuperSpeed hub descriptor stays exactly 12.
    mov  ecx, eax
    mov  eax, USB_HUB_R_DESC
    test rcx, rcx
    js   .refuse
    cmp  ecx, r13d
    ja   .refuse
    cmp  ecx, 7
    jb   .refuse
    cmp  r15d, USB_HUB_DT_SS
    jne  .desc_len_ok
    cmp  ecx, r13d
    jne  .refuse
.desc_len_ok:
    mov  r13d, ecx
    lea  rdi, [rel usb_hub_desc]
    mov  esi, r13d
    mov  edx, r15d
    lea  rcx, [rel usb_hub_geom]
    call usb_hub_desc_parse
    test eax, eax
    mov  eax, USB_HUB_R_DESC
    jnz  .refuse
    ; post-descriptor admission: zero-port and wider-than-a-route-nibble hubs
    movzx edi, byte [rbx + usbdev.topo + usb_topo.depth]
    mov  esi, [rel usb_hub_geom]
    movzx edx, byte [rbx + usbdev.topo + usb_topo.speed]
    call usb_hub_admit
    test eax, eax
    jnz  .refuse

    ; ---- SuperSpeed hubs learn their tier before power-on (USB 3.x 10.14.2.9)
    cmp  byte [rbx + usbdev.topo + usb_topo.speed], USB_SPEED_SUPER
    jne  .status_ep
    xor  edi, edi
    mov  esi, r12d
    mov  edx, (USB_HUB_REQ_SET_HUB_DEPTH << 8) | 0x20
    movzx ecx, byte [rbx + usbdev.topo + usb_topo.depth]
    xor  r8d, r8d
    xor  r9d, r9d
    call usb_hub_request
    test rax, rax
    mov  eax, USB_HUB_R_SET_DEPTH
    jnz  .refuse

.status_ep:
    ; ---- status-change interrupt-IN endpoint (degrades to bounded polling)
    mov  rdx, [rel usb_hub_cur_epdesc]
    test rdx, rdx
    jz   .hub_ctx
    mov  rdi, [rel usb_hub_hc]
    mov  esi, r12d
    mov  rax, [rdi + dev.ops]
    call [rax + usbhc_ops.configure_ep]
    test rax, rax
    jnz  .hub_ctx
    mov  rax, [rel usb_hub_cur_epdesc]
    mov  al, [rax + usb_endpoint_desc.bEndpointAddress]
    mov  [rel usb_hub_cur_ep], al
.hub_ctx:
    ; ---- controller-side hub geometry (Slot Context Hub/ports/TTT)
    mov  rdi, [rel usb_hub_hc]
    mov  esi, r12d
    mov  edx, [rel usb_hub_geom]
    mov  ecx, [rel usb_hub_geom + 4]
    xor  r8d, r8d                      ; default alternate setting: single TT
    mov  rax, [rdi + dev.ops]
    call [rax + usbhc_ops.hub_configure]
    test rax, rax
    mov  eax, USB_HUB_R_HUB_CTX
    jnz  .refuse
    call usb_hub_topo_refresh

    ; ---- power every downstream port, then one power-good delay
.power:
    mov  r14d, 1
.power_one:
    cmp  r14d, [rel usb_hub_geom]
    ja   .powered
    mov  esi, r12d
    mov  edx, USB_HUB_REQ_SET_FEATURE
    mov  ecx, USB_HUB_FEAT_PORT_POWER
    mov  r8d, r14d
    call usb_hub_port_feature
    test rax, rax
    jnz  .power_next
    inc  dword [rel usb_hub_cur_powered]
.power_next:
    inc  r14d
    jmp  .power_one
.powered:
    mov  edi, [rel usb_hub_geom + 8]
    cmp  edi, USB_HUB_PGOOD_MIN_MS
    jae  .pgood
    mov  edi, USB_HUB_PGOOD_MIN_MS
.pgood:
    imul edi, 1000
    call tsc_delay_us

    ; ---- first status-change bitmap through the interrupt-IN endpoint. One TD
    ;      of ceil((ports + 1) / 8) bytes is armed only now, so it reports the
    ;      change bits accumulated across the whole power-on (bit n = port n).
    movzx edx, byte [rel usb_hub_cur_ep]
    test edx, edx
    jz   .settle
    mov  ecx, [rel usb_hub_geom]
    add  ecx, 8
    shr  ecx, 3
    mov  rdi, [rel usb_hub_hc]
    mov  esi, r12d
    mov  rax, [rdi + dev.ops]
    call [rax + usbhc_ops.interrupt_in_queue]
    test rax, rax
    jz   .bitmap_armed
    mov  byte [rel usb_hub_cur_ep], 0  ; queue refused -> bounded polling only
    jmp  .settle
.bitmap_armed:
    mov  r14d, USB_HUB_STATUS_POLLS
.bitmap_poll:
    mov  rdi, [rel usb_hub_hc]
    mov  esi, r12d
    movzx edx, byte [rel usb_hub_cur_ep]
    lea  rcx, [rel usb_hub_bitmap]
    mov  r8d, 8
    lea  r9, [rel usb_hub_meta]
    mov  rax, [rdi + dev.ops]
    call [rax + usbhc_ops.interrupt_in_poll]
    test rax, rax
    js   .bitmap_wait
    mov  byte [rel usb_hub_cur_bitmap_ok], 1
    movzx eax, word [rel usb_hub_bitmap]
    mov  [rel usb_hub_cur_bitmap], eax
    jmp  .settle
.bitmap_wait:
    mov  edi, 16000
    call tsc_delay_us
    dec  r14d
    jnz  .bitmap_poll

    ; ---- settle: wait (bounded) for a first connection after power-good
.settle:
    mov  r13d, USB_HUB_SETTLE_POLLS
.settle_round:
    mov  r14d, 1
.settle_port:
    cmp  r14d, [rel usb_hub_geom]
    ja   .settle_wait
    mov  esi, r12d
    mov  r8d, r14d
    call usb_hub_port_status
    jc   .settle_next
    test eax, USB_HUB_PS_CONNECTION
    jnz  .scan
.settle_next:
    inc  r14d
    jmp  .settle_port
.settle_wait:
    dec  r13d
    jz   .scan
    mov  edi, 10000
    call tsc_delay_us
    jmp  .settle_round

    ; ---- per-port scan
.scan:
    mov  r14d, 1
.port:
    cmp  r14d, [rel usb_hub_geom]
    ja   .scan_done
    mov  edi, [rbx + usbdev.topo + usb_topo.route]
    movzx esi, byte [rbx + usbdev.topo + usb_topo.depth]
    mov  edx, r14d
    call usb_hub_route_extend
    test rax, rax
    js   .port_depth
    mov  r15d, eax
    ; boot-media policy: never re-reset a port on the firmware's boot path
    lea  rdi, [rel usb_boot_snap]
    movzx esi, byte [rbx + usbdev.topo + usb_topo.root]
    mov  edx, r15d
    and  edx, 0x000FFFFF
    mov  ecx, r15d
    shr  ecx, 24
    movzx r8d, byte [rbx + usbdev.topo + usb_topo.pci_dev]
    shl  r8d, 3
    movzx eax, byte [rbx + usbdev.topo + usb_topo.pci_fn]
    or   r8d, eax
    call usb_boot_path_match
    test eax, eax
    jz   .port_live
    inc  dword [rel usb_hub_cur_preserved]
    lea  rsi, [rel str_usb_hub_st_boot]
    mov  edx, 1
    call usb_hub_port_line
    jmp  .port_next
.port_live:
    mov  esi, r12d
    mov  r8d, r14d
    call usb_hub_port_status
    jc   .port_status_fail
    mov  ebp, eax
    test ebp, USB_HUB_PC_CONNECTION
    jz   .ack_enable
    mov  esi, r12d
    mov  edx, USB_HUB_REQ_CLEAR_FEATURE
    mov  ecx, USB_HUB_FEAT_C_CONNECTION
    mov  r8d, r14d
    call usb_hub_port_feature
.ack_enable:
    test ebp, USB_HUB_PC_ENABLE
    jz   .acked
    mov  esi, r12d
    mov  edx, USB_HUB_REQ_CLEAR_FEATURE
    mov  ecx, USB_HUB_FEAT_C_ENABLE
    mov  r8d, r14d
    call usb_hub_port_feature
.acked:
    test ebp, USB_HUB_PS_CONNECTION
    jnz  .connected
    inc  dword [rel usb_hub_cur_empty]
    jmp  .port_next
.connected:
    inc  dword [rel usb_hub_cur_connected]
    cmp  byte [rel usb_hub_cur_debounced], 0
    jne  .budget
    mov  byte [rel usb_hub_cur_debounced], 1
    mov  edi, USB_HUB_DEBOUNCE_MS * 1000
    call tsc_delay_us
.budget:
    cmp  dword [rel usb_dev_n], USB_MAX_DEV
    jae  .port_budget
    ; reset exactly once, bounded
    mov  esi, r12d
    mov  edx, USB_HUB_REQ_SET_FEATURE
    mov  ecx, USB_HUB_FEAT_PORT_RESET
    mov  r8d, r14d
    call usb_hub_port_feature
    test rax, rax
    jnz  .port_status_fail
    mov  r13d, USB_HUB_RESET_POLLS
.reset_poll:
    mov  edi, 10000
    call tsc_delay_us
    mov  esi, r12d
    mov  r8d, r14d
    call usb_hub_port_status
    jc   .port_status_fail
    mov  ebp, eax
    test ebp, USB_HUB_PS_CONNECTION
    jz   .port_disabled
    test ebp, USB_HUB_PS_RESET
    jnz  .reset_again
    test ebp, USB_HUB_PS_ENABLE
    jnz  .reset_done
.reset_again:
    dec  r13d
    jnz  .reset_poll
    jmp  .port_disabled
.reset_done:
    mov  esi, r12d
    mov  edx, USB_HUB_REQ_CLEAR_FEATURE
    mov  ecx, USB_HUB_FEAT_C_RESET
    mov  r8d, r14d
    call usb_hub_port_feature
    mov  edi, USB_HUB_RECOVERY_MS * 1000
    call tsc_delay_us
    mov  ecx, USB_SPEED_SUPER
    cmp  byte [rbx + usbdev.topo + usb_topo.speed], USB_SPEED_SUPER
    je   .speed_ready
    mov  ecx, USB_SPEED_LOW
    test ebp, USB_HUB_PS_LOW_SPEED
    jnz  .speed_ready
    mov  ecx, USB_SPEED_HIGH
    test ebp, USB_HUB_PS_HIGH_SPEED
    jnz  .speed_ready
    mov  ecx, USB_SPEED_FULL
.speed_ready:
    mov  rdi, [rel usb_hub_hc]
    mov  esi, r12d
    mov  edx, r14d
    mov  rax, [rdi + dev.ops]
    call [rax + usbhc_ops.hub_address_child]
    test rax, rax
    jle  .port_address_fail
    mov  r13d, eax                     ; child neutral address
    lea  rdi, [rel usb_scratch_desc]
    xor  eax, eax
    mov  ecx, 32
    rep  stosb
    lea  rdi, [rel usb_scratch_desc]
    mov  esi, r13d
    mov  edx, (USB_HUB_REQ_GET_DESCRIPTOR << 8) | 0x80
    mov  ecx, 0x0100
    xor  r8d, r8d
    mov  r9d, USBD_LEN_DEVICE
    call usb_hub_request
    cmp  rax, USBD_LEN_DEVICE
    jne  .port_desc_fail
    cmp  byte [rel usb_scratch_desc + USBD_BLENGTH], USBD_LEN_DEVICE
    jne  .port_desc_fail
    cmp  byte [rel usb_scratch_desc + USBD_BTYPE], USBD_TYPE_DEVICE
    jne  .port_desc_fail
    cmp  dword [rel usb_dev_n], USB_MAX_DEV
    jae  .port_budget
    ; append the child row only after route, slot and descriptor all held
    mov  eax, [rel usb_dev_n]
    imul eax, USBDEV_SZ
    lea  r15, [rel usb_dev_tbl]
    add  r15, rax
    mov  byte [r15 + usbdev.valid], 1
    mov  byte [r15 + usbdev.isnull], 0
    mov  [r15 + usbdev.addr], r13b
    mov  rax, [rel usb_hub_hc]
    mov  [r15 + usbdev.hc], rax
    lea  rdi, [r15 + usbdev.desc]
    lea  rsi, [rel usb_scratch_desc]
    mov  edx, USBD_LEN_DEVICE
    call memcpy
    mov  rdi, [rel usb_hub_hc]
    mov  esi, r13d
    lea  rdx, [r15 + usbdev.topo]
    mov  rax, [rdi + dev.ops]
    call [rax + usbhc_ops.topology]
    inc  dword [rel usb_dev_n]
    inc  dword [rel usb_hub_cur_enumerated]
    inc  dword [rel usb_hub_children]
    mov  rdi, r15
    call usb_hub_child_line
    jmp  .port_next
.port_depth:
    inc  dword [rel usb_hub_cur_refused]
    lea  rsi, [rel str_usb_hub_st_depth]
    mov  edx, 2
    call usb_hub_port_line
    jmp  .port_next
.port_budget:
    inc  dword [rel usb_hub_cur_refused]
    lea  rsi, [rel str_usb_hub_st_budget]
    mov  edx, 3
    call usb_hub_port_line
    jmp  .port_next
.port_disabled:
    inc  dword [rel usb_hub_cur_disabled]
    lea  rsi, [rel str_usb_hub_st_disabled]
    mov  edx, 4
    call usb_hub_port_line
    jmp  .port_next
.port_address_fail:
    inc  dword [rel usb_hub_cur_failed]
    lea  rsi, [rel str_usb_hub_st_address]
    mov  edx, 5
    call usb_hub_port_line
    jmp  .port_next
.port_desc_fail:
    inc  dword [rel usb_hub_cur_failed]
    lea  rsi, [rel str_usb_hub_st_desc]
    mov  edx, 6
    call usb_hub_port_line
    jmp  .port_next
.port_status_fail:
    inc  dword [rel usb_hub_cur_failed]
    lea  rsi, [rel str_usb_hub_st_status]
    mov  edx, 7
    call usb_hub_port_line
.port_next:
    inc  r14d
    jmp  .port
.scan_done:
    inc  dword [rel usb_hub_count]
    call usb_hub_line
    ; Remember this configured owner's generation separately from diagnostics.
    mov  rax, rbx
    lea  rdx, [rel usb_dev_tbl]
    sub  rax, rdx
    xor  edx, edx
    mov  ecx, USBDEV_SZ
    div  ecx
    mov  [rsp], eax
    mov  rdi, [rbx + usbdev.hc]
    call xhci_hc_generation
    cmp  eax, -1
    je   .out
    mov  edx, [rsp]
    lea  rcx, [rel usb_hub_owner_generation]
    mov  [rcx + rdx*4], eax
    jmp  .out
.refuse:
    mov  [rel usb_hub_cur_reason], eax
    inc  dword [rel usb_hub_refused]
    cmp  eax, USB_HUB_R_DEPTH
    jne  .refuse_line
    inc  dword [rel usb_hub_refused_depth]
.refuse_line:
    call usb_hub_refused_line
.out:
    call usb_hub_record_save           ; persistent, read-only diagnosis (USBPORTS)
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; ---------------------------------------------------------------------------
; RCQ-09 Reatan hub child: a target without serial still has to say why a hub
; child is missing. One record per hub configure attempt this boot (scanned or
; refused), kept after the scan (usb_hub_cur is per-hub scratch): vid/pid, controller index
; (usb_hc_arr order), root/depth/speed, refusal reason (0 = scanned), confirmed
; ports, hub_ctx, and the per-port outcome counts (saturating bytes). The first
; USB_HUB_REC_MAX are kept; every hub is counted. Read-only for USBPORTS.
; ---------------------------------------------------------------------------
USB_HUB_REC_MAX  equ 8
USB_HUB_REC_SZ   equ 19
; record: +0 vid(w) +2 pid(w) +4 root +5 depth +6 speed +7 reason +8 ports +9 hub_ctx
;         +10 powered +11 connected +12 empty +13 disabled +14 failed(+refused) +15 enumerated
;         +16 controller index (0xFF = not registered) +17 last non-enumerated port
;         +18 its outcome (usb_hub_cur_last_state)

; usb_hub_record_save(RBX = hub row) - append this hub's record (bounded). clobbers RAX,RCX,RDX,RDI.
usb_hub_record_save:
    inc  dword [rel usb_hub_rec_seen]
    mov  eax, [rel usb_hub_rec_n]
    cmp  eax, USB_HUB_REC_MAX
    jae  .full
    inc  dword [rel usb_hub_rec_n]
    imul eax, eax, USB_HUB_REC_SZ
    lea  rdi, [rel usb_hub_rec]
    add  rdi, rax
    mov  ax, [rbx + usbdev.desc + USBD_IDVENDOR]
    mov  [rdi], ax
    mov  ax, [rbx + usbdev.desc + USBD_IDPRODUCT]
    mov  [rdi + 2], ax
    mov  al, [rbx + usbdev.topo + usb_topo.root]
    mov  [rdi + 4], al
    mov  al, [rbx + usbdev.topo + usb_topo.depth]
    mov  [rdi + 5], al
    mov  al, [rbx + usbdev.topo + usb_topo.speed]
    mov  [rdi + 6], al
    mov  eax, [rel usb_hub_cur_reason]
    mov  [rdi + 7], al
    mov  al, [rbx + usbdev.topo + usb_topo.hub_ports]
    mov  [rdi + 8], al
    mov  al, [rbx + usbdev.topo + usb_topo.hub_ctx]
    mov  [rdi + 9], al
    mov  edx, [rel usb_hub_cur_powered]
    mov  ecx, 10
    call .sat
    mov  edx, [rel usb_hub_cur_connected]
    mov  ecx, 11
    call .sat
    mov  edx, [rel usb_hub_cur_empty]
    mov  ecx, 12
    call .sat
    mov  edx, [rel usb_hub_cur_disabled]
    mov  ecx, 13
    call .sat
    mov  edx, [rel usb_hub_cur_failed]
    add  edx, [rel usb_hub_cur_refused]
    mov  ecx, 14
    call .sat
    mov  edx, [rel usb_hub_cur_enumerated]
    mov  ecx, 15
    call .sat
    mov  byte [rdi + 16], 0xFF
    mov  rax, [rbx + usbdev.hc]
    lea  rdx, [rel usb_hc_arr]
    xor  ecx, ecx
.hc:
    cmp  ecx, [rel usb_hc_count]
    jae  .last
    cmp  rax, [rdx + rcx*8]
    je   .hc_found
    inc  ecx
    jmp  .hc
.hc_found:
    mov  [rdi + 16], cl
.last:
    mov  al, [rel usb_hub_cur_last_port]
    mov  [rdi + 17], al
    mov  al, [rel usb_hub_cur_last_state]
    mov  [rdi + 18], al
.full:
    ret
.sat:                                   ; [rdi + ecx] = min(edx, 255)
    cmp  edx, 255
    jbe  .sat_store
    mov  edx, 255
.sat_store:
    mov  [rdi + rcx], dl
    ret

; usb_hub_record(EDI = index) -> RAX = record pointer (0 past the kept records),
;   EDX = hubs seen this boot (>= kept). clobbers RCX.
usb_hub_record:
    mov  edx, [rel usb_hub_rec_seen]
    xor  eax, eax
    cmp  edi, [rel usb_hub_rec_n]
    jae  .none
    imul eax, edi, USB_HUB_REC_SZ
    lea  rcx, [rel usb_hub_rec]
    add  rax, rcx
.none:
    ret

; ---------------------------------------------------------------------------
; Serial projection (the external oracle parses these lines).
; ---------------------------------------------------------------------------
; usb_hub_put_hex(EDI=value, ESI=nibbles) — "0x" + fixed-width lowercase hex.
usb_hub_put_hex:
    push rbx
    push r12
    mov  ebx, edi
    mov  r12d, esi
    mov  edi, '0'
    call serial_char
    mov  edi, 'x'
    call serial_char
.nibble:
    dec  r12d
    js   .done
    lea  ecx, [r12d * 4]
    mov  eax, ebx
    shr  eax, cl
    and  eax, 0x0F
    lea  edi, [eax + '0']
    cmp  eax, 10
    jb   .emit
    lea  edi, [eax + 'a' - 10]
.emit:
    call serial_char
    jmp  .nibble
.done:
    pop  r12
    pop  rbx
    ret

; usb_hub_kv_dec(RDI=" key=" string, ESI=value)
usb_hub_kv_dec:
    push rsi
    call serial_string
    pop  rdi
    jmp  serial_decimal

; usb_hub_topo_fields(RDI=usbdev row): addr slot root route depth speed.
usb_hub_topo_fields:
    push rbx
    mov  rbx, rdi
    lea  rdi, [rel str_usb_hub_k_addr]
    movzx esi, byte [rbx + usbdev.addr]
    call usb_hub_kv_dec
    lea  rdi, [rel str_usb_hub_k_slot]
    movzx esi, byte [rbx + usbdev.topo + usb_topo.slot]
    call usb_hub_kv_dec
    lea  rdi, [rel str_usb_hub_k_root]
    movzx esi, byte [rbx + usbdev.topo + usb_topo.root]
    call usb_hub_kv_dec
    lea  rdi, [rel str_usb_hub_k_route]
    call serial_string
    mov  edi, [rbx + usbdev.topo + usb_topo.route]
    mov  esi, 5
    call usb_hub_put_hex
    lea  rdi, [rel str_usb_hub_k_depth]
    movzx esi, byte [rbx + usbdev.topo + usb_topo.depth]
    call usb_hub_kv_dec
    lea  rdi, [rel str_usb_hub_k_speed]
    movzx esi, byte [rbx + usbdev.topo + usb_topo.speed]
    call usb_hub_kv_dec
    pop  rbx
    ret

; usb_hub_ident_fields(RDI=usbdev row): vidpid + class, then CRLF.
usb_hub_ident_fields:
    push rbx
    mov  rbx, rdi
    lea  rdi, [rel str_usb_hub_k_vidpid]
    call serial_string
    movzx edi, word [rbx + usbdev.desc + USBD_IDVENDOR]
    mov  esi, 4
    call usb_hub_put_hex
    mov  edi, ':'
    call serial_char
    movzx edi, word [rbx + usbdev.desc + USBD_IDPRODUCT]
    mov  esi, 4
    call usb_hub_put_hex
    lea  rdi, [rel str_usb_hub_k_class]
    call serial_string
    movzx edi, byte [rbx + usbdev.desc + USBD_CLASS]
    mov  esi, 2
    call usb_hub_put_hex
    lea  rdi, [rel str_usb_port_nl]
    call serial_string
    pop  rbx
    ret

; usb_topo_line(RDI=row) — root-port inventory row (route 0 / depth 0).
usb_topo_line:
    push rbx
    mov  rbx, rdi
    lea  rdi, [rel str_usb_topo_pfx]
    call serial_string
    mov  rdi, rbx
    call usb_hub_topo_fields
    mov  rdi, rbx
    call usb_hub_ident_fields
    pop  rbx
    ret

; usb_hub_child_line(RDI=row)
usb_hub_child_line:
    push rbx
    mov  rbx, rdi
    lea  rdi, [rel str_usb_hub_child_pfx]
    call serial_string
    mov  rdi, rbx
    call usb_hub_topo_fields
    lea  rdi, [rel str_usb_hub_k_pslot]
    movzx esi, byte [rbx + usbdev.topo + usb_topo.parent_slot]
    call usb_hub_kv_dec
    lea  rdi, [rel str_usb_hub_k_pport]
    movzx esi, byte [rbx + usbdev.topo + usb_topo.parent_port]
    call usb_hub_kv_dec
    lea  rdi, [rel str_usb_hub_k_tt]
    movzx esi, byte [rbx + usbdev.topo + usb_topo.tt_slot]
    call usb_hub_kv_dec
    mov  edi, '/'
    call serial_char
    movzx edi, byte [rbx + usbdev.topo + usb_topo.tt_port]
    call serial_decimal
    mov  rdi, rbx
    call usb_hub_ident_fields
    pop  rbx
    ret

; usb_hub_line — per-hub summary (RBX = hub row, r12d = addr in caller).
usb_hub_line:
    push rbx
    lea  rdi, [rel str_usb_hub_hub_pfx]
    call serial_string
    mov  rdi, rbx
    call usb_hub_topo_fields
    lea  rdi, [rel str_usb_hub_k_proto]
    movzx esi, byte [rbx + usbdev.desc + 6]
    call usb_hub_kv_dec
    lea  rdi, [rel str_usb_hub_k_ports]
    mov  esi, [rel usb_hub_geom]
    call usb_hub_kv_dec
    lea  rdi, [rel str_usb_hub_k_ttt]
    mov  esi, [rel usb_hub_geom + 4]
    call usb_hub_kv_dec
    lea  rdi, [rel str_usb_hub_k_pgood]
    mov  esi, [rel usb_hub_geom + 8]
    call usb_hub_kv_dec
    lea  rdi, [rel str_usb_hub_k_powered]
    mov  esi, [rel usb_hub_cur_powered]
    call usb_hub_kv_dec
    lea  rdi, [rel str_usb_hub_k_hubctx]
    movzx esi, byte [rbx + usbdev.topo + usb_topo.hub_ctx]
    call usb_hub_kv_dec
    lea  rdi, [rel str_usb_hub_k_ep]
    call serial_string
    movzx edi, byte [rel usb_hub_cur_ep]
    mov  esi, 2
    call usb_hub_put_hex
    lea  rdi, [rel str_usb_hub_k_bitmap]
    call serial_string
    cmp  byte [rel usb_hub_cur_bitmap_ok], 1
    jne  .no_bitmap
    mov  edi, [rel usb_hub_cur_bitmap]
    mov  esi, 4
    call usb_hub_put_hex
    jmp  .counts
.no_bitmap:
    lea  rdi, [rel str_usb_hub_none]
    call serial_string
.counts:
    lea  rdi, [rel str_usb_hub_k_connected]
    mov  esi, [rel usb_hub_cur_connected]
    call usb_hub_kv_dec
    lea  rdi, [rel str_usb_hub_k_enumerated]
    mov  esi, [rel usb_hub_cur_enumerated]
    call usb_hub_kv_dec
    lea  rdi, [rel str_usb_hub_k_empty]
    mov  esi, [rel usb_hub_cur_empty]
    call usb_hub_kv_dec
    lea  rdi, [rel str_usb_hub_k_disabled]
    mov  esi, [rel usb_hub_cur_disabled]
    call usb_hub_kv_dec
    lea  rdi, [rel str_usb_hub_k_preserved]
    mov  esi, [rel usb_hub_cur_preserved]
    call usb_hub_kv_dec
    lea  rdi, [rel str_usb_hub_k_refused]
    mov  esi, [rel usb_hub_cur_refused]
    call usb_hub_kv_dec
    lea  rdi, [rel str_usb_hub_k_failed]
    mov  esi, [rel usb_hub_cur_failed]
    call usb_hub_kv_dec
    lea  rdi, [rel str_usb_port_nl]
    call serial_string
    pop  rbx
    ret

; usb_hub_refused_line (RBX = hub row; usb_hub_cur_reason set)
usb_hub_refused_line:
    lea  rdi, [rel str_usb_hub_refused_pfx]
    call serial_string
    mov  rdi, rbx
    call usb_hub_topo_fields
    lea  rdi, [rel str_usb_hub_k_reason]
    call serial_string
    mov  eax, [rel usb_hub_cur_reason]
    cmp  eax, USB_HUB_R_SET_DEPTH
    jbe  .named
    xor  eax, eax
.named:
    lea  rdx, [rel usb_hub_reason_names]
    movsxd rdi, dword [rdx + rax * 4]   ; rel32 from the table (org 0 image: no absolute pointers)
    add  rdi, rdx
    call serial_string
    lea  rdi, [rel str_usb_port_nl]
    jmp  serial_string

; usb_hub_port_line(RSI=state string, EDX=state code 1..7 in str_usb_hub_st_* order;
;   RBX=hub row, R14D=port) - also kept as this hub's last port outcome (record).
usb_hub_port_line:
    mov  [rel usb_hub_cur_last_port], r14b
    mov  [rel usb_hub_cur_last_state], dl
    push rsi
    lea  rdi, [rel str_usb_hub_port_pfx]
    call serial_string
    lea  rdi, [rel str_usb_hub_k_hubslot]
    movzx esi, byte [rbx + usbdev.topo + usb_topo.slot]
    call usb_hub_kv_dec
    lea  rdi, [rel str_usb_hub_k_port]
    mov  esi, r14d
    call usb_hub_kv_dec
    lea  rdi, [rel str_usb_hub_k_state]
    call serial_string
    pop  rdi
    call serial_string
    lea  rdi, [rel str_usb_port_nl]
    jmp  serial_string

; usb_hub_bootmedia_line — the pre-EBS boot-media identity, once per boot.
usb_hub_bootmedia_line:
    push rbx
    lea  rdi, [rel str_usb_hub_boot_pfx]
    movzx esi, byte [rel usb_boot_snap]
    call usb_hub_kv_dec
    lea  rdi, [rel str_usb_hub_k_nodes]
    movzx esi, byte [rel usb_boot_snap + 1]
    call usb_hub_kv_dec
    lea  rdi, [rel str_usb_hub_k_devfn]
    call serial_string
    movzx edi, byte [rel usb_boot_snap + 2]
    mov  esi, 2
    call usb_hub_put_hex
    lea  rdi, [rel str_usb_hub_k_path]
    call serial_string
    xor  ebx, ebx
.hop:
    cmp  bl, [rel usb_boot_snap + 1]
    jae  .done
    test ebx, ebx
    jz   .digit
    mov  edi, '.'
    call serial_char
.digit:
    lea  rax, [rel usb_boot_snap + 4]
    movzx edi, byte [rax + rbx]
    inc  edi                         ; one-based, like the root port / hub port
    call serial_decimal
    inc  ebx
    jmp  .hop
.done:
    lea  rdi, [rel str_usb_port_nl]
    call serial_string
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; usb_hub_gate_kat — content KAT over the pure gates that the live hub path
;   calls (route/depth, admission, descriptor grammar, TT selection and the
;   boot-media path). QEMU cannot present a 6th nested hub ("usb hub chain too
;   deep"), a zero-port hub or a >15-port hub, so those refusals are graded
;   here on the same functions. Emits one receipt + marker only when every
;   vector holds; otherwise the FAIL line names the pass mask.
; ---------------------------------------------------------------------------
usb_hub_gate_kat:
    push rbx
    xor  ebx, ebx
    ; v0: first tier
    xor  edi, edi
    xor  esi, esi
    mov  edx, 3
    call usb_hub_route_extend
    cmp  rax, 0x3 | (1 << 24)
    jne  .v1
    or   ebx, 1 << 0
.v1:    ; v1: fifth tier (the deepest legal device)
    mov  edi, 0x5432
    mov  esi, 4
    mov  edx, 6
    call usb_hub_route_extend
    cmp  rax, 0x65432 | (5 << 24)
    jne  .v2
    or   ebx, 1 << 1
.v2:    ; v2: a sixth tier has no route nibble
    mov  edi, 0x65432
    mov  esi, 5
    mov  edx, 1
    call usb_hub_route_extend
    cmp  rax, -1
    jne  .v3
    or   ebx, 1 << 2
.v3:    ; v3: port 0 and port 16 refused
    xor  edi, edi
    xor  esi, esi
    xor  edx, edx
    call usb_hub_route_extend
    cmp  rax, -1
    jne  .v4
    xor  edi, edi
    xor  esi, esi
    mov  edx, 16
    call usb_hub_route_extend
    cmp  rax, -1
    jne  .v4
    or   ebx, 1 << 3
.v4:    ; v4: malformed parent route (zero nibble inside, nibble above depth)
    xor  edi, edi
    mov  esi, 1
    mov  edx, 2
    call usb_hub_route_extend
    cmp  rax, -1
    jne  .v5
    mov  edi, 0x21
    mov  esi, 1
    mov  edx, 2
    call usb_hub_route_extend
    cmp  rax, -1
    jne  .v5
    or   ebx, 1 << 4
.v5:    ; v5: hub admission at depth 4 vs over-depth at 5
    mov  edi, 4
    mov  esi, 4
    mov  edx, USB_SPEED_HIGH
    call usb_hub_admit
    test eax, eax
    jnz  .v6
    mov  edi, 5
    mov  esi, 4
    mov  edx, USB_SPEED_HIGH
    call usb_hub_admit
    cmp  eax, USB_HUB_R_DEPTH
    jne  .v6
    or   ebx, 1 << 5
.v6:    ; v6: zero-port, 16-port and low-speed hubs refused
    xor  edi, edi
    xor  esi, esi
    mov  edx, USB_SPEED_FULL
    call usb_hub_admit
    cmp  eax, USB_HUB_R_ZERO_PORTS
    jne  .v7
    xor  edi, edi
    mov  esi, 16
    mov  edx, USB_SPEED_FULL
    call usb_hub_admit
    cmp  eax, USB_HUB_R_WIDE
    jne  .v7
    xor  edi, edi
    mov  esi, 4
    mov  edx, USB_SPEED_LOW
    call usb_hub_admit
    cmp  eax, USB_HUB_R_SPEED
    jne  .v7
    or   ebx, 1 << 6
.v7:    ; v7: USB2 descriptors — QEMU 8-port (10 B) and a 4-port HS hub (9 B)
    lea  rdi, [rel usb_hub_kat_d29_q8]
    mov  esi, 11
    mov  edx, USB_HUB_DT_USB2
    lea  rcx, [rel usb_hub_kat_geom]
    call usb_hub_desc_parse
    test eax, eax
    jnz  .v8
    cmp  dword [rel usb_hub_kat_geom], 8
    jne  .v8
    cmp  dword [rel usb_hub_kat_geom + 8], 2
    jne  .v8
    lea  rdi, [rel usb_hub_kat_d29_hs4]
    mov  esi, 9
    mov  edx, USB_HUB_DT_USB2
    lea  rcx, [rel usb_hub_kat_geom]
    call usb_hub_desc_parse
    test eax, eax
    jnz  .v8
    cmp  dword [rel usb_hub_kat_geom], 4
    jne  .v8
    cmp  dword [rel usb_hub_kat_geom + 4], 3
    jne  .v8
    cmp  dword [rel usb_hub_kat_geom + 8], 100
    jne  .v8
    or   ebx, 1 << 7
.v8:    ; v8: zero-port, wrong-type, over-claimed and short USB2 descriptors
    lea  rdi, [rel usb_hub_kat_d29_zero]
    mov  esi, 9
    mov  edx, USB_HUB_DT_USB2
    lea  rcx, [rel usb_hub_kat_geom]
    call usb_hub_desc_parse
    cmp  eax, -1
    jne  .v9
    lea  rdi, [rel usb_hub_kat_d29_hs4]
    mov  esi, 9
    mov  edx, USB_HUB_DT_SS
    lea  rcx, [rel usb_hub_kat_geom]
    call usb_hub_desc_parse
    cmp  eax, -1
    jne  .v9
    lea  rdi, [rel usb_hub_kat_d29_hs4]
    mov  esi, 8
    mov  edx, USB_HUB_DT_USB2
    lea  rcx, [rel usb_hub_kat_geom]
    call usb_hub_desc_parse
    cmp  eax, -1
    jne  .v9
    lea  rdi, [rel usb_hub_kat_d29_short]
    mov  esi, 11
    mov  edx, USB_HUB_DT_USB2
    lea  rcx, [rel usb_hub_kat_geom]
    call usb_hub_desc_parse
    cmp  eax, -1
    jne  .v9
    or   ebx, 1 << 8
.v9:    ; v9: SuperSpeed 0x2A (12 B exact) accepted, 9-byte form refused
    lea  rdi, [rel usb_hub_kat_d2a]
    mov  esi, 12
    mov  edx, USB_HUB_DT_SS
    lea  rcx, [rel usb_hub_kat_geom]
    call usb_hub_desc_parse
    test eax, eax
    jnz  .v10
    cmp  dword [rel usb_hub_kat_geom], 4
    jne  .v10
    cmp  dword [rel usb_hub_kat_geom + 4], 0
    jne  .v10
    lea  rdi, [rel usb_hub_kat_d2a_bad]
    mov  esi, 12
    mov  edx, USB_HUB_DT_SS
    lea  rcx, [rel usb_hub_kat_geom]
    call usb_hub_desc_parse
    cmp  eax, -1
    jne  .v10
    or   ebx, 1 << 9
.v10:   ; v10: TT selection
    mov  edi, 3
    mov  esi, USB_SPEED_HIGH
    xor  edx, edx
    mov  ecx, 2
    mov  r8d, USB_SPEED_FULL
    call usb_hub_child_tt
    cmp  rax, 0x0203
    jne  .v11
    mov  edi, 5
    mov  esi, USB_SPEED_FULL
    mov  edx, 0x0203
    mov  ecx, 1
    mov  r8d, USB_SPEED_LOW
    call usb_hub_child_tt
    cmp  rax, 0x0203
    jne  .v11
    mov  edi, 3
    mov  esi, USB_SPEED_HIGH
    xor  edx, edx
    mov  ecx, 1
    mov  r8d, USB_SPEED_HIGH
    call usb_hub_child_tt
    test rax, rax
    jnz  .v11
    mov  edi, 1
    mov  esi, USB_SPEED_FULL
    xor  edx, edx
    mov  ecx, 1
    mov  r8d, USB_SPEED_FULL
    call usb_hub_child_tt
    test rax, rax
    jnz  .v11
    or   ebx, 1 << 10
.v11:   ; v11: SuperSpeed/USB2 never mix on one hub; SS-under-SS has no TT
    mov  edi, 3
    mov  esi, USB_SPEED_HIGH
    xor  edx, edx
    mov  ecx, 1
    mov  r8d, USB_SPEED_SUPER
    call usb_hub_child_tt
    cmp  rax, -1
    jne  .v12
    mov  edi, 3
    mov  esi, USB_SPEED_SUPER
    xor  edx, edx
    mov  ecx, 1
    mov  r8d, USB_SPEED_HIGH
    call usb_hub_child_tt
    cmp  rax, -1
    jne  .v12
    mov  edi, 3
    mov  esi, USB_SPEED_SUPER
    xor  edx, edx
    mov  ecx, 1
    mov  r8d, USB_SPEED_SUPER
    call usb_hub_child_tt
    test rax, rax
    jnz  .v12
    or   ebx, 1 << 11
.v12:   ; v12: boot-media device path: PCI(3,0)/USB(0)/USB(3) = root 1, hub port 4
    lea  rdi, [rel usb_hub_kat_dp]
    lea  rsi, [rel usb_hub_kat_snap]
    call usb_boot_path_parse
    test eax, eax
    jnz  .v13
    cmp  dword [rel usb_hub_kat_snap], 0x00180201   ; parsed, 2 nodes, devfn 03.0
    jne  .v13
    cmp  word [rel usb_hub_kat_snap + 4], 0x0300
    jne  .v13
    lea  rdi, [rel usb_hub_kat_snap]
    mov  esi, 1
    mov  edx, 0x4
    mov  ecx, 1
    mov  r8d, 0x18
    call usb_boot_path_match
    cmp  eax, 1                      ; the boot-media port itself
    jne  .v13
    lea  rdi, [rel usb_hub_kat_snap]
    mov  esi, 1
    xor  edx, edx
    xor  ecx, ecx
    mov  r8d, 0x18
    call usb_boot_path_match
    cmp  eax, 2                      ; the hub upstream of it
    jne  .v13
    lea  rdi, [rel usb_hub_kat_snap]
    mov  esi, 1
    mov  edx, 0x3
    mov  ecx, 1
    mov  r8d, 0x18
    call usb_boot_path_match
    test eax, eax                    ; a sibling port is NOT boot media
    jnz  .v13
    lea  rdi, [rel usb_hub_kat_snap]
    mov  esi, 1
    mov  edx, 0x4
    mov  ecx, 1
    mov  r8d, 0x10
    call usb_boot_path_match
    test eax, eax                    ; another controller is NOT boot media
    jnz  .v13
    or   ebx, 1 << 12
.v13:   ; v13: a non-USB boot path (SATA) never matches
    lea  rdi, [rel usb_hub_kat_dp_sata]
    lea  rsi, [rel usb_hub_kat_snap]
    call usb_boot_path_parse
    test eax, eax
    jnz  .verdict
    cmp  byte [rel usb_hub_kat_snap + 1], 0
    jne  .verdict
    lea  rdi, [rel usb_hub_kat_snap]
    mov  esi, 1
    xor  edx, edx
    xor  ecx, ecx
    movzx r8d, byte [rel usb_hub_kat_snap + 2]
    call usb_boot_path_match
    test eax, eax
    jnz  .verdict
    or   ebx, 1 << 13
.verdict:
    mov  [rel usb_hub_kat_mask], ebx
    cmp  ebx, USB_HUB_KAT_ALL
    jne  .fail
    lea  rdi, [rel str_usb_hub_kat_line]
    call serial_string
    lea  rdi, [rel str_m_usb_hub_kat]
    call serial_string
    jmp  .out
.fail:
    lea  rdi, [rel str_usb_hub_kat_fail]
    call serial_string
    mov  edi, ebx
    mov  esi, 4
    call usb_hub_put_hex
    lea  rdi, [rel str_usb_port_nl]
    call serial_string
.out:
    pop  rbx
    ret
USB_HUB_KAT_ALL equ 0x3FFF

; ---- module data ----------------------------------------------------------
align 8
usb_hc_arr:      times USB_MAX_HC dq 0
usb_hc_count:    dd 0
usb_probe_hc:    dd 0
usb_probe_port:  dd 1
usb_dev_n:       dd 0
usb_m_enum:      db 0                ; marker flags (ride every BOOTLOG reply once set)
usb_m_desc:      db 0
align 8
usb_dev_tbl:     times (USB_MAX_DEV * USBDEV_SZ) db 0
usb_scratch_desc: times 32 db 0      ; landing buffer for one GET_DESCRIPTOR
usb_setup_getdesc: times 8 db 0      ; the 8-byte SETUP packet (built per call)

; the nulldev's fixed device handle + ops + canned descriptor
align 8
usb_nulldev_dev:  times DEV_SIZE db 0
usb_nulldev_ops:  times (usbhc_ops_size) db 0
usb_nulldev_desc:
    db 0x12          ; bLength = 18
    db 0x01          ; bDescriptorType = DEVICE
    db 0x00, 0x02    ; bcdUSB = 2.00
    db 0x00          ; bDeviceClass (0 = per-interface)
    db 0x00          ; bDeviceSubClass
    db 0x00          ; bDeviceProtocol
    db 0x40          ; bMaxPacketSize0 = 64
    db 0x00, 0x00    ; idVendor = 0000
    db 0x00, 0x00    ; idProduct = 0000
    db 0x00, 0x01    ; bcdDevice = 1.00
    db 0x00          ; iManufacturer
    db 0x00          ; iProduct
    db 0x00          ; iSerialNumber
    db 0x01          ; bNumConfigurations = 1

str_usb_nulldev_name: db "usb_nulldev", 0

; boot serial markers (registered in regression_tests.txt)
str_m_usb_enum:  db "[PAOS64] P2 usb-enum: USB device enumerated (address-device succeeded) [usb.enum.device]", 13, 10, 0
str_m_usb_desc:  db "[PAOS64] P2 usb-enum: USB device descriptor read (GET_DESCRIPTOR control xfer) [usb.descriptor.read]", 13, 10, 0
str_usb_skipped: db "[PAOS64] P2 usb-enum: xhci: skipped (no USB)", 13, 10, 0
str_usb_port_skipped: db "[PAOS64] P2 usb-enum: connected port skipped port=", 0
str_usb_port_rc:      db " control_rc=", 0
str_usb_port_nl:      db 13, 10, 0

; ---- HUB0 hub-class state + projection strings ---------------------------
align 8
usb_hub_hc:          dq 0
usb_hub_count:       dd 0           ; hubs configured and scanned this boot
usb_hub_children:    dd 0           ; devices enumerated behind a hub
usb_hub_refused:     dd 0
usb_hub_refused_depth: dd 0
usb_hub_owner_generation: times USB_MAX_DEV dd 0
usb_hub_probe_index: dd 0
usb_hub_probe_port: dd 1
usb_hub_rec_n:       dd 0           ; hub records kept for USBPORTS (RCQ-09)
usb_hub_rec_seen:    dd 0           ; hubs configured or refused (kept or not)
usb_hub_rec:         times USB_HUB_REC_MAX * USB_HUB_REC_SZ db 0
usb_hub_kat_mask:    dd 0
align 8
usb_hub_cur:                        ; per-hub scratch, zeroed per hub
usb_hub_cur_epdesc:    dq 0
usb_hub_cur_reason:    dd 0
usb_hub_cur_bitmap:    dd 0
usb_hub_cur_powered:   dd 0
usb_hub_cur_connected: dd 0
usb_hub_cur_enumerated: dd 0
usb_hub_cur_empty:     dd 0
usb_hub_cur_disabled:  dd 0
usb_hub_cur_preserved: dd 0
usb_hub_cur_refused:   dd 0
usb_hub_cur_failed:    dd 0
usb_hub_cur_ep:        db 0
usb_hub_cur_bitmap_ok: db 0
usb_hub_cur_debounced: db 0
usb_hub_cur_last_port: db 0           ; last port that did not enumerate (0 = none)
usb_hub_cur_last_state: db 0          ; its outcome: 1 boot 2 depth 3 budget 4 disabled
                                      ; 5 address 6 descriptor 7 status
align 8
usb_hub_cur_end:
usb_hub_geom:        times 4 dd 0   ; ports, TT think time, power-good ms, characteristics
usb_hub_status:      dd 0
usb_hub_setup:       times usb_setup_size db 0
align 8
usb_hub_bitmap:      times 8 db 0
usb_hub_meta:        times usb_intr_completion_size db 0
usb_hub_desc:        times 16 db 0
usb_hub_cfg:         times USB_HUB_CFG_CAP db 0

; boot-media snapshot (pre-EBS): parsed, usb nodes, devfn, pad, port chain[8]
align 8
usb_boot_snap:       times 12 db 0
align 8
usb_boot_status:     dq 0
usb_boot_li_guid:    dd 0x5B1B31A1
                     dw 0x9562, 0x11D2
                     db 0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B
usb_boot_dp_guid:    dd 0x09576E91
                     dw 0x6D3F, 0x11D2
                     db 0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B

; gate-KAT vectors
usb_hub_kat_geom:    times 4 dd 0
usb_hub_kat_snap:    times 12 db 0
usb_hub_kat_d29_q8:  db 0x0A, 0x29, 0x08, 0x0A, 0x00, 0x01, 0x00, 0x00, 0x00, 0xFF, 0x00
usb_hub_kat_d29_hs4: db 0x09, 0x29, 0x04, 0xE9, 0x00, 0x32, 0x64, 0x00, 0xFF
usb_hub_kat_d29_zero: db 0x09, 0x29, 0x00, 0x0A, 0x00, 0x01, 0x00, 0x00, 0xFF
usb_hub_kat_d29_short: db 0x08, 0x29, 0x08, 0x0A, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00
usb_hub_kat_d2a:     db 0x0C, 0x2A, 0x04, 0x09, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
usb_hub_kat_d2a_bad: db 0x09, 0x2A, 0x04, 0x09, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
usb_hub_kat_dp:      db 0x02, 0x01, 0x0C, 0x00, 0xD0, 0x41, 0x03, 0x0A, 0x00, 0x00, 0x00, 0x00
                     db 0x01, 0x01, 0x06, 0x00, 0x00, 0x03
                     db 0x03, 0x05, 0x06, 0x00, 0x00, 0x00
                     db 0x03, 0x05, 0x06, 0x00, 0x03, 0x00
                     db 0x7F, 0xFF, 0x04, 0x00
usb_hub_kat_dp_sata: db 0x02, 0x01, 0x0C, 0x00, 0xD0, 0x41, 0x03, 0x0A, 0x00, 0x00, 0x00, 0x00
                     db 0x01, 0x01, 0x06, 0x00, 0x02, 0x1F
                     db 0x03, 0x12, 0x0A, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00
                     db 0x7F, 0xFF, 0x04, 0x00

align 8
usb_hub_reason_names:                   ; rel32 offsets from this table (was dq: unresolved in an org 0 image)
    dd str_usb_hub_rs_none - usb_hub_reason_names, str_usb_hub_rs_depth - usb_hub_reason_names
    dd str_usb_hub_rs_zero - usb_hub_reason_names, str_usb_hub_rs_wide - usb_hub_reason_names
    dd str_usb_hub_rs_speed - usb_hub_reason_names, str_usb_hub_rs_proto - usb_hub_reason_names
    dd str_usb_hub_rs_budget - usb_hub_reason_names, str_usb_hub_rs_config - usb_hub_reason_names
    dd str_usb_hub_rs_desc - usb_hub_reason_names, str_usb_hub_rs_hubctx - usb_hub_reason_names
    dd str_usb_hub_rs_setdepth - usb_hub_reason_names
str_usb_hub_rs_none:     db "none", 0
str_usb_hub_rs_depth:    db "over_depth", 0
str_usb_hub_rs_zero:     db "zero_ports", 0
str_usb_hub_rs_wide:     db "too_many_ports", 0
str_usb_hub_rs_speed:    db "speed", 0
str_usb_hub_rs_proto:    db "protocol", 0
str_usb_hub_rs_budget:   db "hub_budget", 0
str_usb_hub_rs_config:   db "configuration", 0
str_usb_hub_rs_desc:     db "hub_descriptor", 0
str_usb_hub_rs_hubctx:   db "slot_context", 0
str_usb_hub_rs_setdepth: db "set_hub_depth", 0

str_usb_topo_pfx:        db "USBTOPO", 0
str_usb_hub_hub_pfx:     db "USBHUB hub", 0
str_usb_hub_child_pfx:   db "USBHUB child", 0
str_usb_hub_refused_pfx: db "USBHUB refused", 0
str_usb_hub_port_pfx:    db "USBHUB port", 0
str_usb_hub_boot_pfx:    db "USBHUB bootmedia parsed=", 0
str_usb_hub_k_addr:      db " addr=", 0
str_usb_hub_k_slot:      db " slot=", 0
str_usb_hub_k_root:      db " root=", 0
str_usb_hub_k_route:     db " route=", 0
str_usb_hub_k_depth:     db " depth=", 0
str_usb_hub_k_speed:     db " speed=", 0
str_usb_hub_k_pslot:     db " parent_slot=", 0
str_usb_hub_k_pport:     db " parent_port=", 0
str_usb_hub_k_tt:        db " tt=", 0
str_usb_hub_k_vidpid:    db " vidpid=", 0
str_usb_hub_k_class:     db " class=", 0
str_usb_hub_k_proto:     db " proto=", 0
str_usb_hub_k_ports:     db " ports=", 0
str_usb_hub_k_ttt:       db " ttt=", 0
str_usb_hub_k_pgood:     db " pgood_ms=", 0
str_usb_hub_k_powered:   db " powered=", 0
str_usb_hub_k_hubctx:    db " hub_ctx=", 0
str_usb_hub_k_ep:        db " status_ep=", 0
str_usb_hub_k_bitmap:    db " bitmap=", 0
str_usb_hub_none:        db "none", 0
str_usb_hub_k_connected: db " connected=", 0
str_usb_hub_k_enumerated: db " enumerated=", 0
str_usb_hub_k_empty:     db " empty=", 0
str_usb_hub_k_disabled:  db " disabled=", 0
str_usb_hub_k_preserved: db " preserved=", 0
str_usb_hub_k_refused:   db " refused=", 0
str_usb_hub_k_failed:    db " failed=", 0
str_usb_hub_k_reason:    db " reason=", 0
str_usb_hub_k_hubslot:   db " hub_slot=", 0
str_usb_hub_k_port:      db " port=", 0
str_usb_hub_k_state:     db " state=", 0
str_usb_hub_k_nodes:     db " usb_nodes=", 0
str_usb_hub_k_devfn:     db " devfn=", 0
str_usb_hub_k_path:      db " path=", 0
str_usb_hub_st_boot:     db "preserved_boot_media", 0
str_usb_hub_st_depth:    db "refused_over_depth", 0
str_usb_hub_st_budget:   db "refused_device_budget", 0
str_usb_hub_st_disabled: db "disabled_after_reset", 0
str_usb_hub_st_address:  db "address_refused", 0
str_usb_hub_st_desc:     db "descriptor_refused", 0
str_usb_hub_st_status:   db "status_failed", 0
str_usb_hub_kat_line:    db "USBHUBKAT route=ok tier5=ok tier6=refused port0=refused port16=refused malformed_route=refused admit=ok over_depth=refused zero_ports=refused wide_hub=refused ls_hub=refused desc29=ok desc29_bad=refused desc2a=ok desc2a_bad=refused tt=ok ss_mix=refused boot_path=exact,upstream,sibling_no,foreign_no sata_path=no pass=0x3fff", 13, 10, 0
str_usb_hub_kat_fail:    db "USBHUBKAT FAIL pass=", 0
str_m_usb_hub_kat:   db "[PAOS64] P2 usb-hub: hub route/depth/descriptor/TT/boot-media gate KAT PASS [usb.hub.gate.kat]", 13, 10, 0
str_m_usb_hub_enum:  db "[PAOS64] P2 usb-hub: hub class configured; downstream ports powered and scanned [usb.hub.enum]", 13, 10, 0
str_m_usb_hub_child: db "[PAOS64] P2 usb-hub: device enumerated behind a hub (route string addressed) [usb.hub.child]", 13, 10, 0
str_m_usb_hub_depth: db "[PAOS64] P2 usb-hub: over-depth hub refused fail-closed [usb.hub.depth.refused]", 13, 10, 0
