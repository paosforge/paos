;; MODULE dev/usb/hid
;; LAYER 3
;; EXPORTS usb_hid_owned_reject_arm, usb_hid_owned_reject_status, usb_hid_owned_snapshot, usb_hid_owned_prepare, usb_hid_owned_reprobe, usb_hid_census_snapshot, usb_hid_binding_snapshot, hid_touchpad_parse, hid_touchpad_consume, hid_pointer_publish, hid_pointer_retire, usb_hid_keyboard_locks, usb_hid_port_owned, usb_hid_set1_to_usage, usb_hid_enum_selftest, usb_hid_kind_live, usb_hid_input_selftest, usb_hid_init, usb_hid_selftest, usb_hid_logic_selftest, usb_hid_reset, usb_hid_detach, usb_hid_consume_interrupt, usb_hid_active_count, usb_hid_refused_wrong_slot, usb_hid_refused_stale, usb_hid_refused_duplicate, usb_hid_refused_absolute, usb_hid_refused_rollover, usb_hid_refused_malformed, usb_hid_mouse_reports, usb_hid_last_mouse_raw, usb_hid_poll_ticks, usb_hid_observation_snapshot, usb_hid_observation_pop
;; IMPORTS core/lib/sha256, dev/input/hid_rdesc, dev/usb/xhci, usb/enum, dev/input/ps2, core/time, core/sched, boot/serial
;; CAPS CAP_IRQ
;; OWNER saga:usb_stack
; ============================================================================
; Native USB HID boot/report keyboard, relative mouse, absolute tablet and bounded touchpad consumers.
;
; The Task2903 xHCI endpoint seam remains the sole owner of Configure Endpoint,
; rings, immutable report bytes, completion filtering, and requeue.  This file
; owns only class setup, strict descriptor/report validation, and translation into the
; already-shipped kbd_ring / clamped GUI pointer seams.
; ============================================================================

USB_HID_CONFIG_CAP       equ 512
USB_HID_KIND_KBD         equ 1
USB_HID_KIND_MOUSE       equ 2
USB_HID_KIND_REPORT      equ 3
USB_HID_PTR_RETIRED      equ (1 << 17) ; RCQ-09: buttons-up of a retired source (ps2 -> WM_PTR_RETIRED)
USB_HID_REPORT_DESC_CAP  equ 256
USB_HID_REPORT_WIRE_CAP  equ 32
USB_HID_REPORT_BITS      equ 248
USB_HID_REPORT_MAP_SIZE  equ 272
USB_HID_MULTI_REPORTS    equ 4
USB_HID_MULTI_RECORD     equ 288
USB_HID_MULTI_SIZE       equ 1168
USB_HID_LED_RECORD       equ 32
USB_HID_LED_CONTEXT      equ 128
USB_HID_LED_RETRIES      equ 3
USB_HID_LED_BACKOFF      equ 16
USB_HID_KBD_REPORT_LEN   equ 8
USB_HID_MOUSE_REPORT_MIN equ 3    ; HID boot mouse: buttons, X, Y
USB_HID_MOUSE_REPORT_MAX equ 5    ; observed relative wheel/pan gadget
USB_HID_POLL_TICKS       equ 10000
; Consumer states: one per bound supported interface, first-free allocation. Four
; covers a KVM's emulated keyboard+mouse gadget plus a physical keyboard and
; mouse on the same host controller (Lenovo M720s, 2026-09-07).
USB_HID_RECONNECT_BACKOFF equ 64       ; one retained root per 64 resident passes
USB_HID_MAX_STATES       equ 4
; RCQ-09 software typematic for boot keyboards (PS/2 repeats in hardware).
; Fixed defaults; no settings store. A repeat may only use the lower half of
; the shared kbd ring so a later release batch (<= 32 bytes) always fits.
USB_HID_REPEAT_DELAY_US  equ 500000
USB_HID_REPEAT_PERIOD_US equ 33333    ; ~30 Hz
USB_HID_REPEAT_RESERVE   equ 32

USB_DT_CONFIG            equ 2
USB_DT_INTERFACE         equ 4
USB_REQ_GET_DESCRIPTOR   equ 6
USB_REQ_SET_CONFIGURATION equ 9
USB_HID_REQ_SET_IDLE      equ 0x0A
USB_HID_REQ_SET_PROTOCOL  equ 0x0B

struc usb_hid_state
  .active:        resb 1
  .kind:          resb 1
  .port:          resb 1
  .interface:     resb 1
  .ep_addr:       resb 1
  .slot:          resb 1
  .protocol:      resb 1            ; 0 boot /1 keyboard /2 mouse /3 numbered set /4 touchpad
  .wire_len:      resb 1
  .generation:    resd 1
  .last_sequence: resd 1
  .hc:            resq 1
  .ops:           resq 1
  .previous:      resb USB_HID_KBD_REPORT_LEN
  .report:        resb USB_HID_KBD_REPORT_LEN
  .meta:          resb usb_intr_completion_size
endstruc

; Release all class ownership before an xHCI generation can advance.
; Header-call adapters.  src/paos.asm redirects the existing enum and late
; input calls here so Task2904 composes without editing the boot-header owner.
usb_hid_enum_selftest:
    call usb_enum_selftest
    ; W3 (MSI spoke packet 0005): the READ-ONLY mass-storage class bind runs while
    ; EP0 control transfers still complete (after usb_hid_init they time out in
    ; QEMU on every slot; see the 0005 header). It takes only a pure MSC-BOT device.
    call usb_msd_init
    jmp  usb_hid_init

usb_hid_input_selftest:
    sub  rsp, 8
    mov  ecx, [rel usb_hid_obs_test_depth]
    mov  [rsp], rcx
    mov  dword [rel usb_hid_obs_test_depth], 1
    call usb_hid_input_selftest_body
    mov  ecx, [rsp]
    mov  [rel usb_hid_obs_test_depth], ecx
    add  rsp, 8
    ret

usb_hid_input_selftest_body:
    ; Empty boots need the resident too: the first HID may arrive later.
    call usb_hid_start_task
    test rax, rax
    jnz  .logic_and_ps2
    ; One interface needs resident service; only the paired proof needs two.
    cmp  byte [rel usb_hid_active_count], 2
    jb   .logic_and_ps2
    jmp  usb_hid_selftest
.logic_and_ps2:
    call usb_hid_logic_selftest
    jmp  ps2_input_selftest

; Arm the resident class consumer before the positive receipt loop.  One
; bounded cooperative dispatch proves the worker can actually run; afterwards
; the normal idle-loop sched_yield keeps it servicing Task2903 completions.
usb_hid_start_task:
    cmp  byte [rel usb_hid_task_started], 1
    jne  .spawn
    cmp  byte [rel usb_hid_task_running], 1
    je   .ready
    jmp  .fail
.spawn:
    lea  rdi, [rel usb_hid_task]
    call sched_spawn
    cmp  eax, -1
    je   .fail
    mov  byte [rel usb_hid_task_started], 1
    mov  ecx, 16
.dispatch:
    cmp  byte [rel usb_hid_task_running], 1
    je   .ready
    push rcx
    call sched_yield
    pop  rcx
    loop .dispatch
.fail:
    mov  rax, -1
    ret
.ready:
    xor  eax, eax
    ret

usb_hid_task:
    mov  byte [rel usb_hid_task_running], 1
.poll:
    call usb_hid_resident_tick
    call sched_yield
    jmp  .poll

; Only the cooperative resident invokes reconnect/LED work; input/KAT/IRQ
; publication paths never perform a control transfer. One retained root per
; reconnect backoff and at most one LED output attempt per pass.
usb_hid_resident_tick:
    call usb_hid_poll_all
    call usb_hid_reconnect_tick
    call usb_hid_discovery_tick
    jmp  usb_hid_led_tick

usb_hid_reset:
    push rbx
    push r12
    sub  rsp, 8
    call usb_hid_obs_reset
    call usb_hid_reconnect_reset
    mov  qword [rel usb_hid_repeat_owner], 0
    lea  rbx, [rel usb_hid_states]
    mov  r12d, USB_HID_MAX_STATES
.next:
    mov  rdi, rbx
    call usb_hid_release_state
    add  rbx, usb_hid_state_size
    dec  r12d
    jnz  .next
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; active: 0 free, 1 bound, 2 retired with an unpublished release. A retired
; keyboard keeps its accepted report and slot until a whole release fits.
; The resident poll retries it without touching its obsolete HC/ops pointers.
usb_hid_release_state:
    push rbx
    mov  rbx, rdi
    call usb_hid_led_clear_state       ; retire output even if key releases must wait
    cmp  byte [rbx + usb_hid_state.active], 1
    jne  .obs_unchanged
    call usb_hid_obs_reset
.obs_unchanged:
    cmp  [rel usb_hid_repeat_owner], rbx
    jne  .owned
    mov  qword [rel usb_hid_repeat_owner], 0   ; disconnect/detach/generation: stop repeat
.owned:
    cmp  byte [rbx + usb_hid_state.active], 1
    jne  .retired
    mov  byte [rbx + usb_hid_state.active], 2
    cmp  byte [rel usb_hid_active_count], 0
    je   .retired
    dec  byte [rel usb_hid_active_count]
.retired:
    cmp  byte [rbx + usb_hid_state.active], 2
    jne  .clear
    cmp  byte [rbx + usb_hid_state.kind], USB_HID_KIND_KBD
    je   .release_keys
.release_pointer:
    mov  rdi, rbx
    call usb_hid_report_map_for_state
    test rax, rax
    jz   .clear
    lea  rdx, [rel usb_hid_pointer_buttons]
    cmp  byte [rdx + rcx], 0
    je   .clear
    mov  edi, ecx
    call hid_pointer_retire             ; RCQ-09: no hand released them, no click
    test eax, eax
    jz   .out
    jmp  .clear
.release_keys:
    sub  rsp, 16
    mov  qword [rsp], 0
    mov  rdi, rbx
    mov  rdx, rsp
    mov  byte [rel usb_hid_retiring], 1 ; RCQ-09: its breaks are KO_RETIRED, no tap
    call usb_hid_consume_keyboard
    mov  byte [rel usb_hid_retiring], 0
    add  rsp, 16
    test eax, eax
    jz   .out                         ; retain custody; bounded retry next poll
    jmp  .release_pointer             ; mixed keyboard/mouse IDs also own buttons
.clear:
    mov  rdi, rbx
    call usb_hid_multi_context
    test rax, rax
    jz   .clear_state
    mov  rdi, rax
    mov  ecx, USB_HID_MULTI_SIZE / 8
    xor  eax, eax
    rep  stosq
.clear_state:
    mov  rdi, rbx
    mov  rcx, usb_hid_state_size / 8
    xor  eax, eax
    rep  stosq
.out:
    pop  rbx
    ret

; Legacy port-only detach retires every matching consumer (all controllers).
; In: ESI=root-hub port. Normal polling retires the exact state/HC identity.
; Pending states retain custody until publication, before their state is reused.
usb_hid_detach:
    push rbx
    push r12
    mov  r12d, esi
    lea  rbx, [rel usb_hid_states]
    mov  ecx, USB_HID_MAX_STATES
.next:
    cmp  byte [rbx + usb_hid_state.active], 0
    je   .advance
    cmp  byte [rbx + usb_hid_state.port], r12b
    jne  .advance
    push rcx
    mov  rdi, rbx
    call usb_hid_release_state
    pop  rcx
.advance:
    add  rbx, usb_hid_state_size
    loop .next
    pop  r12
    pop  rbx
    ret

; GET_DESCRIPTOR(CONFIGURATION) in two bounded reads.  The returned buffer is
; accepted only when the on-wire header and wTotalLength agree exactly.
; In: RDI=hc, ESI=port. Out: EAX=validated length / 0.
usb_hid_fetch_config:
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 24                    ; stable nine-byte first-read header
    mov  byte [rel usb_hid_kbd_candidate], 0
    mov  byte [rel usb_hid_mouse_candidate], 0
    mov  byte [rel usb_hid_report_candidate], 0
    mov  word [rel usb_hid_report_descriptor_len], 0
    mov  r12, rdi
    mov  r13d, esi
    lea  rbx, [rel usb_hid_setup]
    mov  byte [rbx + usb_setup.bmRequestType], 0x80
    mov  byte [rbx + usb_setup.bRequest], USB_REQ_GET_DESCRIPTOR
    mov  word [rbx + usb_setup.wValue], (USB_DT_CONFIG << 8)
    mov  word [rbx + usb_setup.wIndex], 0
    mov  word [rbx + usb_setup.wLength], 9
    mov  rdi, r12
    mov  rsi, rbx
    mov  edx, r13d
    lea  rcx, [rel usb_hid_config]
    mov  r8d, 9
    mov  rax, [r12 + dev.ops]
    call [rax + usbhc_ops.control]
    cmp  rax, 9
    jne  .fail
    cmp  byte [rel usb_hid_config], 9
    jb   .fail
    cmp  byte [rel usb_hid_config + 1], USB_DT_CONFIG
    jne  .fail
    movzx eax, word [rel usb_hid_config + 2]
    cmp  eax, 9
    jb   .fail
    cmp  eax, USB_HID_CONFIG_CAP
    ja   .fail
    movzx ecx, byte [rel usb_hid_config]
    cmp  ecx, eax
    ja   .fail
    mov  r14d, eax
    mov  rax, [rel usb_hid_config]
    mov  [rsp], rax
    mov  al, [rel usb_hid_config + 8]
    mov  [rsp + 8], al
    mov  word [rbx + usb_setup.wLength], r14w
    mov  rdi, r12
    mov  rsi, rbx
    mov  edx, r13d
    lea  rcx, [rel usb_hid_config]
    mov  r8d, r14d
    mov  rax, [r12 + dev.ops]
    call [rax + usbhc_ops.control]
    cmp  rax, r14
    jne  .fail
    mov  rax, [rsp]
    cmp  [rel usb_hid_config], rax
    jne  .fail
    mov  al, [rsp + 8]
    cmp  [rel usb_hid_config + 8], al
    jne  .fail
    mov  eax, r14d
    jmp  .out
.fail:
    xor  eax, eax
.out:
    add  rsp, 24
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Legacy classifier/KAT entry retains the first candidate of each kind.
; Discovery uses the bounded iterator entry: ECX >= 9 is a descriptor cursor.
; It publishes candidates for exactly one default interface, in wire order,
; after validating the WHOLE configuration. EAX is the next cursor (len at end,
; zero on invalid config). Every refused interface advances independently.
; Scratch candidates are copied into private state maps before the next call.
usb_hid_scan_config_at:
    mov  [rel usb_hid_scan_cursor], ecx
    jmp  usb_hid_scan_config.entry
usb_hid_scan_config:
    mov  dword [rel usb_hid_scan_cursor], 0
.entry:
    push rbx
    push r12
    push r13
    push r14
    mov  r13d, [rel usb_hid_scan_cursor]
    xor  r14d, r14d                  ; iterator selected one default interface
    mov  r12d, edx
    mov  byte [rel usb_hid_kbd_candidate], 0
    mov  byte [rel usb_hid_mouse_candidate], 0
    mov  byte [rel usb_hid_report_candidate], 0
    mov  word [rel usb_hid_report_descriptor_len], 0
    call usb_hid_config_validate
    test eax, eax
    jz   .invalid                   ; no effects/candidates from an invalid tail
    xor  r8d, r8d                    ; offset
    xor  r9d, r9d                    ; current kind
    xor  r10d, r10d                  ; current interface
.next:
    mov  eax, esi
    sub  eax, r8d
    cmp  eax, 2
    jb   .done
    lea  r11, [rdi + r8]
    movzx eax, byte [r11]
    cmp  eax, 2
    jb   .done
    mov  edx, r8d
    add  edx, eax
    cmp  edx, esi
    ja   .done
    cmp  byte [r11 + 1], USB_DT_INTERFACE
    jne  .endpoint
    xor  r9d, r9d
    test r13d, r13d
    jz   .classify
    cmp  r8d, r13d
    jb   .advance                   ; earlier interfaces never leak candidates
    test r14d, r14d
    jnz  .done                      ; stop at the first following interface/alternate
    cmp  byte [r11 + 3], 0
    jne  .advance                   ; never activate an alternate implicitly
    mov  r14d, 1
.classify:
    cmp  eax, 9
    jb   .advance
    cmp  byte [r11 + 3], 0           ; alternate setting zero only
    jne  .advance
    cmp  byte [r11 + 5], 3           ; HID class
    jne  .advance
    cmp  byte [r11 + 6], 1           ; boot subclass rejects usb-tablet
    jne  .nonboot
    movzx r10d, byte [r11 + 2]
    cmp  byte [r11 + 7], 1
    je   .kbd
    cmp  byte [r11 + 7], 2
    je   .mouse
    jmp  .advance
.kbd:
    mov  r9d, USB_HID_KIND_KBD
    jmp  .advance
.mouse:
    mov  r9d, USB_HID_KIND_MOUSE
    jmp  .advance
.nonboot:
    cmp  byte [r11 + 6], 0
    jne  .absolute
    cmp  byte [r11 + 7], 0
    jne  .absolute
    movzx r10d, byte [r11 + 2]
    mov  r9d, USB_HID_KIND_REPORT
    mov  word [rel usb_hid_report_descriptor_current], 0
.absolute:
    inc  qword [rel usb_hid_refused_absolute] ; legacy counter: refused by boot classifier
    jmp  .advance
.endpoint:
    cmp  r9d, USB_HID_KIND_REPORT
    jne  .not_report_descriptor
    cmp  byte [r11 + 1], 0x21
    jne  .not_report_descriptor
    cmp  byte [r11], 9
    jne  .advance
    cmp  byte [r11 + 5], 1
    jne  .advance
    cmp  byte [r11 + 6], 0x22
    jne  .advance
    mov  ax, [r11 + 7]
    mov  [rel usb_hid_report_descriptor_current], ax
    jmp  .advance
.not_report_descriptor:
    test r9d, r9d
    jz   .advance
    cmp  byte [r11 + 1], USBD_TYPE_ENDPOINT
    jne  .advance
    cmp  eax, usb_endpoint_desc_size
    jb   .advance
    movzx ecx, byte [r11 + usb_endpoint_desc.bEndpointAddress]
    test cl, USB_EP_DIR_IN
    jz   .advance
    test cl, 0x70
    jnz  .advance
    mov  ebx, ecx
    and  ebx, USB_EP_NUM_MASK
    jz   .advance
    movzx ebx, byte [r11 + usb_endpoint_desc.bmAttributes]
    and  ebx, USB_EP_XFER_MASK
    cmp  ebx, USB_EP_XFER_INTR
    jne  .advance
    movzx ebx, word [r11 + usb_endpoint_desc.wMaxPacketSize]
    test ebx, ebx
    jz   .advance
    cmp  ebx, USB_EP_MAX_PACKET
    ja   .advance
    cmp  byte [r11 + usb_endpoint_desc.bInterval], 0
    je   .advance
    cmp  r9d, USB_HID_KIND_REPORT
    je   .save_report
    cmp  r9d, USB_HID_KIND_KBD
    jne  .save_mouse
    cmp  byte [rel usb_hid_kbd_candidate], 0
    jne  .advance
    mov  byte [rel usb_hid_kbd_candidate], 1
    mov  [rel usb_hid_kbd_interface], r10b
    mov  eax, [r11]
    mov  [rel usb_hid_kbd_ep], eax
    mov  eax, [r11 + 3]
    mov  [rel usb_hid_kbd_ep + 3], eax
    cmp  r12d, USB_SPEED_SUPER
    jne  .saved_kbd
    mov  eax, [r11 + 7]
    mov  [rel usb_hid_kbd_ep + 7], eax
    mov  ax, [r11 + 11]
    mov  [rel usb_hid_kbd_ep + 11], ax
.saved_kbd:
    jmp  .advance
.save_report:
    cmp  byte [rel usb_hid_report_candidate], 0
    jne  .advance
    movzx eax, word [rel usb_hid_report_descriptor_current]
    test eax, eax
    jz   .advance
    cmp  eax, USB_HID_REPORT_DESC_CAP
    ja   .advance
    mov  [rel usb_hid_report_descriptor_len], ax
    mov  byte [rel usb_hid_report_candidate], 1
    mov  [rel usb_hid_report_interface], r10b
    mov  eax, [r11]
    mov  [rel usb_hid_report_ep], eax
    mov  eax, [r11 + 3]
    mov  [rel usb_hid_report_ep + 3], eax
    cmp  r12d, USB_SPEED_SUPER
    jne  .advance
    mov  eax, [r11 + 7]
    mov  [rel usb_hid_report_ep + 7], eax
    mov  ax, [r11 + 11]
    mov  [rel usb_hid_report_ep + 11], ax
    jmp  .advance
.save_mouse:
    cmp  byte [rel usb_hid_mouse_candidate], 0
    jne  .advance
    mov  byte [rel usb_hid_mouse_candidate], 1
    mov  [rel usb_hid_mouse_interface], r10b
    mov  eax, [r11]
    mov  [rel usb_hid_mouse_ep], eax
    mov  eax, [r11 + 3]
    mov  [rel usb_hid_mouse_ep + 3], eax
    cmp  r12d, USB_SPEED_SUPER
    jne  .saved_mouse
    mov  eax, [r11 + 7]
    mov  [rel usb_hid_mouse_ep + 7], eax
    mov  ax, [r11 + 11]
    mov  [rel usb_hid_mouse_ep + 11], ax
.saved_mouse:
.advance:
    mov  r8d, edx
    jmp  .next
.done:
    mov  r14d, r8d                   ; return next descriptor cursor across validation
    cmp  byte [rel usb_hid_report_candidate], 1
    jne  .out
    mov  edx, r12d
    call usb_hid_report_validate_interface
    test eax, eax
    jnz  .out
    mov  byte [rel usb_hid_report_candidate], 0
    jmp  .out
.invalid:
    xor  r14d, r14d
.out:
    mov  eax, r14d
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; USB 2.0 9.5, 9.6.3/5/6 and HID 1.11 6.2.1/7.1.1. No I/O or
; candidate writes here. Extended descriptors are skipped by their actual length.
; Exact framing/counts and endpoint ownership cover unsupported classes too;
; only alt-zero boot interfaces need the supported HID interrupt-IN profile.
; In RDI=blob, ESI=actual extent, EDX=addressed speed. Out EAX=1/0.
; RDI/ESI preserved.
; Stack: endpoint interface owners[32 words], per-alt
; endpoint bitmap, remaining count, interface(-1 initially), kind, IN count,
; HID count, alt-zero count, endpoint-started flag, HID-class flag. <=512 bytes => bounded walk
; and bounded duplicate (interface,alternate) prefix walks, no device allocation.
usb_hid_config_validate:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 112
    mov  r12, rsp
    mov  r13, rdi
    mov  r14d, esi
    cmp  esi, 9
    jb   .fail
    cmp  esi, USB_HID_CONFIG_CAP
    ja   .fail
    mov  rax, rdi
    add  rax, r14
    jc   .fail
    xor  eax, eax
    mov  ecx, 14
    mov  rdi, r12
    rep  stosq
    mov  [r12 + 100], edx           ; addressed topology speed, never descriptor bcdUSB
    mov  dword [r12 + 72], -1
    cmp  byte [r13], 9
    jb   .fail
    cmp  byte [r13 + 1], USB_DT_CONFIG
    jne  .fail
    movzx eax, word [r13 + 2]
    cmp  eax, r14d
    jne  .fail
    cmp  byte [r13 + 4], 0
    je   .fail
    cmp  byte [r13 + 5], 1           ; existing configuration-one policy
    jne  .fail
    mov  al, [r13 + 7]
    and  al, 0x9F
    cmp  al, 0x80
    jne  .fail
    movzx ebx, byte [r13]
    cmp  ebx, r14d
    ja   .fail
.next:
    cmp  ebx, r14d
    je   .end
    mov  eax, r14d
    sub  eax, ebx
    cmp  eax, 2
    jb   .fail
    lea  r15, [r13 + rbx]
    movzx eax, byte [r15]
    cmp  eax, 2
    jb   .fail
    lea  r8d, [rbx + rax]
    cmp  r8d, r14d
    ja   .fail
    cmp  dword [r12 + 100], USB_SPEED_SUPER
    jne  .not_orphan_companion
    cmp  byte [r15 + 1], 0x30
    je   .fail                      ; companions consumed only with their endpoint
.not_orphan_companion:
    cmp  byte [r15 + 1], USB_DT_CONFIG
    je   .fail                      ; no second envelope inside this configuration
    cmp  byte [r15 + 1], USB_DT_INTERFACE
    je   .interface
    cmp  byte [r15 + 1], USBD_TYPE_ENDPOINT
    je   .endpoint
    cmp  byte [r15 + 1], 0x21
    jne  .advance                   ; preserve well-framed unknown descriptors
    cmp  dword [r12 + 96], 0
    je   .advance
    cmp  dword [r12 + 92], 0
    jne  .fail                      ; HID descriptor precedes this interface's endpoints
    cmp  dword [r12 + 84], 0
    jne  .fail
    cmp  eax, 6
    jb   .fail
    movzx ecx, byte [r15 + 5]
    test ecx, ecx
    jz   .fail
    lea  edx, [rcx + rcx*2 + 6]
    cmp  eax, edx
    jb   .fail
    xor  edx, edx
    lea  r9, [r15 + 6]
.hid_entry:
    cmp  word [r9 + 1], 0
    je   .fail
    cmp  byte [r9], 0x22
    jne  .hid_next
    inc  edx
.hid_next:
    add  r9, 3
    dec  ecx
    jnz  .hid_entry
    cmp  edx, 1
    jne  .fail
    mov  dword [r12 + 84], 1
    jmp  .advance
.interface:
    cmp  eax, 9
    jb   .fail
    call .finish_interface
    test eax, eax
    jz   .fail
    movzx ecx, byte [r15 + 2]
    cmp  cl, [r13 + 4]
    jae  .fail                      ; zero-based interface number within bNumInterfaces
    mov  [r12 + 72], ecx
    movzx edx, byte [r15 + 4]
    mov  [r12 + 68], edx
    mov  dword [r12 + 64], 0
    mov  dword [r12 + 76], 0
    mov  dword [r12 + 80], 0
    mov  dword [r12 + 84], 0
    mov  dword [r12 + 92], 0
    cmp  byte [r15 + 5], 3
    sete byte [r12 + 96]
    movzx edx, byte [r13]
.pair:
    cmp  edx, ebx
    jae  .pair_done
    lea  r9, [r13 + rdx]
    cmp  byte [r9 + 1], USB_DT_INTERFACE
    jne  .pair_next
    mov  ax, [r9 + 2]
    cmp  ax, [r15 + 2]
    je   .fail                      ; duplicate (interface,alternate), any class
.pair_next:
    movzx eax, byte [r9]
    add  edx, eax
    jmp  .pair
.pair_done:
    cmp  byte [r15 + 3], 0
    jne  .advance                   ; framed and counted, never selected via SET_INTERFACE
    inc  dword [r12 + 88]
    cmp  byte [r15 + 5], 3
    jne  .advance
    cmp  byte [r15 + 6], 1
    jne  .advance
    movzx eax, byte [r15 + 7]
    cmp  eax, USB_HID_KIND_KBD
    je   .boot
    cmp  eax, USB_HID_KIND_MOUSE
    jne  .advance
.boot:
    mov  [r12 + 76], eax
    jmp  .advance
.endpoint:
    cmp  dword [r12 + 100], USB_SPEED_SUPER
    jne  .endpoint_framed
    cmp  eax, usb_endpoint_desc_size
    jne  .fail                      ; bounded SS profile: exact seven-byte endpoint
    lea  ecx, [r8 + 6]
    cmp  ecx, r14d
    ja   .fail                      ; prove all companion bytes before reading
    cmp  byte [r13 + r8], 6
    jne  .fail
    cmp  byte [r13 + r8 + 1], 0x30
    jne  .fail                      ; must immediately follow, never search ahead
    mov  r8d, ecx                    ; consume exactly one associated companion
.endpoint_framed:
    cmp  eax, usb_endpoint_desc_size
    jb   .fail
    cmp  dword [r12 + 72], -1
    je   .fail                      ; no endpoint without an owning interface
    cmp  dword [r12 + 68], 0
    je   .fail
    dec  dword [r12 + 68]
    mov  dword [r12 + 92], 1
    movzx ecx, byte [r15 + 2]
    test cl, 0x70
    jnz  .fail
    mov  edx, ecx
    and  edx, USB_EP_NUM_MASK
    jz   .fail
    test cl, USB_EP_DIR_IN
    jz   .ep_index
    add  edx, 16
.ep_index:
    bts  dword [r12 + 64], edx
    jc   .fail                      ; no repeated address in one alternate setting
    mov  eax, [r12 + 72]
    inc  eax
    movzx ecx, word [r12 + rdx*2]
    test ecx, ecx
    jz   .ep_claim
    cmp  ecx, eax
    jne  .fail                      ; only alternates of SAME interface may share endpoints
.ep_claim:
    mov  [r12 + rdx*2], ax
    cmp  dword [r12 + 76], 0
    je   .advance
    mov  rdi, r15
    mov  esi, [r12 + 76]
    mov  edx, [r12 + 100]
    cmp  edx, USB_SPEED_SUPER
    jne  .usb2_endpoint
    call usb_hid_config_validate_ss_endpoint
    jmp  .endpoint_validated
.usb2_endpoint:
    call usb_hid_config_validate_endpoint
.endpoint_validated:
    test eax, eax
    jz   .fail
    test byte [r15 + 2], USB_EP_DIR_IN
    jz   .advance                   ; optional interrupt OUT is counted, never queued here
    inc  dword [r12 + 80]
.advance:
    mov  ebx, r8d
    jmp  .next
.end:
    call .finish_interface
    test eax, eax
    jz   .fail
    movzx eax, byte [r13 + 4]
    cmp  eax, [r12 + 88]
    jne  .fail                      ; every interface has exactly one default alternate
    mov  eax, 1
    jmp  .out
.finish_interface:
    xor  eax, eax
    cmp  dword [r12 + 68], 0
    jne  .finished
    cmp  dword [r12 + 96], 0
    je   .finished_ok
    cmp  dword [r12 + 84], 1
    jne  .finished
    cmp  dword [r12 + 76], 0
    je   .finished_ok
    cmp  dword [r12 + 80], 1
    jne  .finished
.finished_ok:
    mov  eax, 1
.finished:
    ret
.fail:
    xor  eax, eax
.out:
    mov  rdi, r13
    mov  esi, r14d
    add  rsp, 112
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Supported single-packet USB 2 boot profile (USB 2.0 5.7.3/4, 9.6.6).
; RDI=endpoint, ESI=kind, EDX=addressed speed. EAX=1/0; only EAX/ECX clobbered.
; This seven-byte validator never reads USB3 companions; the bounded SS entry
; validates those separately before sharing only the HS packet/interval bounds.
; Optional OUT is legal but cannot be selected and need not fit an input report.
usb_hid_config_validate_endpoint:
    cmp  byte [rdi + 1], USBD_TYPE_ENDPOINT
    jne  .fail
    cmp  byte [rdi], usb_endpoint_desc_size
    jb   .fail
    movzx eax, byte [rdi + 2]
    test al, 0x70
    jnz  .fail
    and  eax, USB_EP_NUM_MASK
    jz   .fail
    cmp  byte [rdi + 3], USB_EP_XFER_INTR
    jne  .fail                       ; USB2 interrupt attribute bits 7:2 reserved
    movzx eax, word [rdi + 4]
    test eax, eax
    jz   .fail
    movzx ecx, byte [rdi + 6]
    test ecx, ecx
    jz   .fail
    cmp  edx, USB_SPEED_LOW
    je   .low
    cmp  edx, USB_SPEED_FULL
    je   .full
    cmp  edx, USB_SPEED_HIGH
    jne  .fail                       ; no unknown/SuperSpeed geometry inference
    cmp  ecx, 16
    ja   .fail
    cmp  eax, 1024
    ja   .fail                       ; includes all transaction/reserved packet bits
    jmp  .report
.low:
    cmp  ecx, 10
    jb   .fail                       ; 5.7.4 narrows low-speed interval to 10..255
    cmp  eax, 8
    ja   .fail
    jmp  .report
.full:
    cmp  eax, 64
    ja   .fail
.report:
    test byte [rdi + 2], USB_EP_DIR_IN
    jz   .ok
    cmp  esi, USB_HID_KIND_REPORT
    je   .ok
    cmp  esi, USB_HID_KIND_KBD
    jne  .mouse
    cmp  eax, USB_HID_KBD_REPORT_LEN
    jb   .fail
    jmp  .ok
.mouse:
    cmp  esi, USB_HID_KIND_MOUSE
    jne  .fail
    cmp  eax, USB_HID_MOUSE_REPORT_MIN
    jb   .fail
.ok:
    mov  eax, 1
    ret
.fail:
    xor  eax, eax
    ret

; Bounded SS boot profile: caller proves thirteen readable bytes first.
; Up to three packets/service. USB 3.2 4.4.7.1,9.6.6/7; xHCI 4.8.2/6.2.3.
; Preserve all but EAX/ECX, as the USB2 endpoint validator does.
usb_hid_config_validate_ss_endpoint:
    cmp  byte [rdi], 7
    jne  .fail
    cmp  byte [rdi + 7], 6
    jne  .fail
    cmp  byte [rdi + 8], 0x30
    jne  .fail
    cmp  byte [rdi + 9], 2           ; USB3.2 4.4.7.1: at most three packets
    ja   .fail                      ; bMaxBurst is zero based, not general 0..15
    cmp  byte [rdi + 10], 0          ; interrupt companion attributes reserved
    jne  .fail
    cmp  byte [rdi + 9], 0
    je   .packet_ready
    cmp  word [rdi + 4], 1024        ; bursts > one require full-sized packets
    jne  .fail
.packet_ready:
    push rdx
    mov  edx, USB_SPEED_HIGH         ; shared MPS/interval/report bounds, no USB2 bits
    call usb_hid_config_validate_endpoint
    pop  rdx
    test eax, eax
    jz   .fail
    movzx eax, byte [rdi + 9]
    inc  eax
    movzx ecx, word [rdi + 4]
    imul ecx, eax                    ; validated 1..1024 * 1..3, at most 3072
    jo   .fail
    movzx eax, word [rdi + 11]
    test eax, eax
    jz   .fail
    cmp  eax, ecx
    ja   .fail                      ; explicit service budget <= burst capacity
    test byte [rdi + 2], USB_EP_DIR_IN
    jz   .ok
    cmp  esi, USB_HID_KIND_REPORT
    je   .ok
    cmp  esi, USB_HID_KIND_KBD
    jne  .mouse
    cmp  eax, USB_HID_KBD_REPORT_LEN
    jb   .fail
    jmp  .ok
.mouse:
    cmp  eax, USB_HID_MOUSE_REPORT_MIN
    jb   .fail
    movzx ecx, word [rdi + 4]
    cmp  ecx, USB_HID_MOUSE_REPORT_MAX
    jbe  .mouse_budget
    mov  ecx, USB_HID_MOUSE_REPORT_MAX
.mouse_budget:
    cmp  eax, ecx
    jb   .fail                      ; selected TD must fit service budget
.ok:
    mov  eax, 1
    ret
.fail:
    xor  eax, eax
    ret

; Exact no-data setup request. In RDI=hc, ESI=port, EDX=request,
; ECX=wValue, R8D=wIndex, R9D=bmRequestType. Out RAX backend status.
usb_hid_control_nodata:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13d, esi
    lea  rbx, [rel usb_hid_setup]
    mov  [rbx + usb_setup.bmRequestType], r9b
    mov  [rbx + usb_setup.bRequest], dl
    mov  [rbx + usb_setup.wValue], cx
    mov  [rbx + usb_setup.wIndex], r8w
    mov  word [rbx + usb_setup.wLength], 0
    mov  rdi, r12
    mov  rsi, rbx
    mov  edx, r13d
    xor  ecx, ecx
    xor  r8d, r8d
    mov  rax, [r12 + dev.ops]
    call [rax + usbhc_ops.control]
    pop  r13
    pop  r12
    pop  rbx
    ret

; Return an inactive state, refusing a second owner of the same input kind.
; In EDX=kind. Out RAX=state/0.
usb_hid_alloc_state:
    lea  rax, [rel usb_hid_states]
    xor  ecx, ecx
.next:
    cmp  byte [rax + usb_hid_state.active], 0
    je   .found                      ; only free, never retired pending release
    add  rax, usb_hid_state_size     ; mouse binds alongside the first one
    inc  ecx
    cmp  ecx, USB_HID_MAX_STATES
    jb   .next
    xor  eax, eax
.found:
    ret

; Configure one boot interface, queue the first immutable interrupt report, and
; publish consumer ownership only after every step succeeds.
; In RDI=hc, ESI=port, EDX=kind, ECX=interface, R8=endpoint, R9D=speed.
usb_hid_configure_interface:
    cmp  r9d, USB_SPEED_SUPER
    jne  usb_hid_configure_interface_common
    mov  rax, -1                    ; legacy seven-byte entry never reads a companion
    ret

; Explicit bounded entry: R10D is the readable endpoint+companion extent.
usb_hid_configure_interface_bounded:
    cmp  r9d, USB_SPEED_SUPER
    jne  usb_hid_configure_interface_common
    cmp  r10d, 13
    je   usb_hid_configure_interface_common
    mov  rax, -1
    ret
usb_hid_configure_interface_common:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 16
    mov  r12, rdi
    mov  r13d, esi
    mov  r14d, edx
    mov  r15d, ecx
    mov  [rsp], r8
    mov  [rsp + 8], r9d
    test r8, r8
    jz   .fail
    test byte [r8 + usb_endpoint_desc.bEndpointAddress], USB_EP_DIR_IN
    jz   .fail
    mov  rdi, r8
    mov  esi, r14d
    mov  edx, r9d
    cmp  edx, USB_SPEED_SUPER
    jne  .usb2_preflight
    call usb_hid_config_validate_ss_endpoint
    test eax, eax
    jz   .fail
    mov  rax, [r12 + dev.ops]
    cmp  qword [rax + usbhc_ops.configure_ep_ss], 0
    je   .fail
    jmp  .preflight_done
.usb2_preflight:
    call usb_hid_config_validate_endpoint
    test eax, eax
    jz   .fail
.preflight_done:
    cmp  r14d, USB_HID_KIND_REPORT
    jne  .report_preflight_done
    movzx eax, byte [rel usb_hid_report_candidate_map]
    test eax, eax
    jz   .fail
    mov  r11, [rsp]
    movzx ecx, word [r11 + 4]
    cmp  eax, ecx
    ja   .fail
    cmp  dword [rsp + 8], USB_SPEED_SUPER
    jne  .report_preflight_done
    movzx ecx, word [r11 + 11]
    cmp  eax, ecx
    ja   .fail
.report_preflight_done:
    mov  edx, r14d
    call usb_hid_alloc_state
    test rax, rax
    jz   .fail
    mov  rbx, rax
    cmp  dword [rsp + 8], USB_SPEED_SUPER
    jne  .class_requests
    ; Actual SS context takes the validated service budget before HID requests.
    mov  rax, [r12 + dev.ops]
    mov  rdi, r12
    mov  esi, r13d
    mov  rdx, [rsp]
    mov  ecx, 13
    call [rax + usbhc_ops.configure_ep_ss]
    test rax, rax
    jnz  .fail
.class_requests:
    cmp  r14d, USB_HID_KIND_REPORT
    je   .report_protocol
    mov  rdi, r12
    mov  esi, r13d
    mov  edx, USB_HID_REQ_SET_PROTOCOL
    xor  ecx, ecx                    ; Boot protocol
    mov  r8d, r15d
    mov  r9d, 0x21
    call usb_hid_control_nodata
    test rax, rax
    jnz  .fail

.report_protocol:
    mov  rdi, r12
    mov  esi, r13d
    mov  edx, USB_HID_REQ_SET_IDLE
    xor  ecx, ecx                    ; duration=0, report id=0
    mov  r8d, r15d
    mov  r9d, 0x21
    call usb_hid_control_nodata
    test rax, rax
    jz   .idle_ok
    cmp  rax, -2                     ; HID permits SET_IDLE STALL
    jne  .fail
    inc  qword [rel usb_hid_idle_stalls]
.idle_ok:
    cmp  dword [rsp + 8], USB_SPEED_SUPER
    je   .configured
    mov  rax, [r12 + dev.ops]
    mov  rdi, r12
    mov  esi, r13d
    mov  rdx, [rsp]
    call [rax + usbhc_ops.configure_ep]
    test rax, rax
    jnz  .fail
.configured:

    mov  rdi, r12
    mov  esi, r13d
    call xhci_hid_slot_for_port      ; any xHCI controller (RCQ-09): EAX slot, EDX its generation
    test eax, eax
    jz   .fail                       ; not an xHCI backend, or no slot
    mov  [rbx + usb_hid_state.generation], edx
    mov  [rbx + usb_hid_state.slot], al
    mov  [rbx + usb_hid_state.port], r13b
    mov  [rbx + usb_hid_state.kind], r14b
    mov  [rbx + usb_hid_state.interface], r15b
    mov  r11, [rsp]
    mov  al, [r11 + usb_endpoint_desc.bEndpointAddress]
    mov  [rbx + usb_hid_state.ep_addr], al
    mov  [rbx + usb_hid_state.hc], r12
    mov  rax, [r12 + dev.ops]
    mov  [rbx + usb_hid_state.ops], rax

    cmp  r14d, USB_HID_KIND_REPORT
    jne  .boot_queue
    mov  byte [rbx + usb_hid_state.kind], USB_HID_KIND_KBD
    mov  byte [rbx + usb_hid_state.protocol], 1
    cmp  byte [rel usb_hid_report_candidate_map + 5], 4
    je   .touchpad_kind
    cmp  byte [rel usb_hid_report_candidate_map + 5], 3
    je   .multi_kind
    cmp  byte [rel usb_hid_report_candidate_map + 5], 2
    jne  .report_kind_ready
    mov  byte [rbx + usb_hid_state.kind], USB_HID_KIND_MOUSE
    mov  byte [rbx + usb_hid_state.protocol], 2
    jmp  .report_kind_ready
.touchpad_kind:
    mov  byte [rbx + usb_hid_state.kind], USB_HID_KIND_MOUSE
    mov  byte [rbx + usb_hid_state.protocol], 4
    jmp  .report_kind_ready
.multi_kind:
    mov  byte [rbx + usb_hid_state.protocol], 3
    cmp  byte [rel usb_hid_multi_candidate + 2], 1
    je   .report_kind_ready
    mov  byte [rbx + usb_hid_state.kind], USB_HID_KIND_MOUSE
.report_kind_ready:
    mov  al, [rel usb_hid_report_candidate_map]
    mov  [rbx + usb_hid_state.wire_len], al
    mov  rdi, rbx
    call usb_hid_report_install
    test eax, eax
    jz   .fail_clear
    mov  rax, [rbx + usb_hid_state.ops]
    movzx ecx, byte [rbx + usb_hid_state.wire_len]
    jmp  .have_len
.boot_queue:
    mov  ecx, USB_HID_KBD_REPORT_LEN
    cmp  r14d, USB_HID_KIND_KBD
    je   .have_len
    ; A boot mouse may still emit a relative wheel extension after a
    ; successful SET_PROTOCOL(0). Queue up to five bytes in one packet;
    ; three/four-byte endpoints use their exact packet size. A shorter
    ; three/four-byte completion also fits. Never guess across packets.
    mov  ecx, USB_HID_MOUSE_REPORT_MAX
    mov  r11, [rsp]
    movzx edx, word [r11 + usb_endpoint_desc.wMaxPacketSize]
    cmp  edx, USB_HID_MOUSE_REPORT_MAX
    jae  .have_len
    mov  ecx, edx                    ; one packet: three or four bytes
.have_len:
    mov  rdi, r12
    mov  esi, r13d
    movzx edx, byte [rbx + usb_hid_state.ep_addr]
    call [rax + usbhc_ops.interrupt_in_queue]
    test rax, rax
    jnz  .fail_clear
    call usb_hid_obs_reset                 ; publish a fresh observation epoch
    mov  byte [rbx + usb_hid_state.active], 1
    call usb_hid_census_record           ; sidecar only, no class/controller effects
    call usb_hid_owned_record           ; actual successful inventory bind only
    inc  byte [rel usb_hid_active_count]
    mov  rdi, rbx
    call usb_hid_led_install            ; immutable layout only, no I/O on bind
    lea  rdi, [rel str_usb_hid_bound]
    call serial_string
    movzx edi, byte [rbx + usb_hid_state.kind]
    call serial_decimal
    lea  rdi, [rel str_usb_hid_bound_port]
    call serial_string
    movzx edi, byte [rbx + usb_hid_state.port]
    call serial_decimal
    lea  rdi, [rel str_usb_hid_bound_slot]
    call serial_string
    movzx edi, byte [rbx + usb_hid_state.slot]
    call serial_decimal
    lea  rdi, [rel str_usb_hid_bound_ep]
    call serial_string
    movzx edi, byte [rbx + usb_hid_state.ep_addr]
    call serial_decimal
    lea  rdi, [rel str_usb_hid_bound_end]
    call serial_string
    xor  eax, eax
    jmp  .out
.fail_clear:
    mov  rdi, rbx
    call usb_hid_release_state
.fail:
    mov  eax, -1
.out:
    add  rsp, 16
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; A rejected nonboot profile must not suppress an unrelated boot interface.
; Whole-configuration framing/ownership was already checked. This second pure
; walk validates only the chosen nonboot interface's complete endpoint profile.
; RDI=blob, ESI=extent, EDX=speed -> EAX=1/0; preserves RDI/RSI.
usb_hid_report_validate_interface:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rdi
    push rsi
    sub  rsp, 8
    mov  r12, rdi
    mov  r13d, esi
    mov  r14d, edx
    xor  r15d, r15d
    xor  ebx, ebx
    mov  qword [rsp], 0              ; selected flag, invalid endpoint flag
.next:
    cmp  r15d, r13d
    jae  .end
    lea  rdi, [r12 + r15]
    cmp  byte [rdi + 1], USB_DT_INTERFACE
    jne  .endpoint
    cmp  dword [rsp], 1
    je   .end
    cmp  byte [rdi + 3], 0
    jne  .advance
    mov  al, [rel usb_hid_report_interface]
    cmp  [rdi + 2], al
    jne  .advance
    mov  dword [rsp], 1
    jmp  .advance
.endpoint:
    cmp  dword [rsp], 1
    jne  .advance
    cmp  byte [rdi + 1], USBD_TYPE_ENDPOINT
    jne  .advance
    test byte [rdi + 2], USB_EP_DIR_IN
    jz   .geometry
    inc  ebx
.geometry:
    mov  esi, USB_HID_KIND_REPORT
    mov  edx, r14d
    cmp  edx, USB_SPEED_SUPER
    jne  .usb2
    call usb_hid_config_validate_ss_endpoint
    jmp  .checked
.usb2:
    call usb_hid_config_validate_endpoint
.checked:
    test eax, eax
    jnz  .advance
    mov  dword [rsp + 4], 1
.advance:
    movzx eax, byte [r12 + r15]
    add  r15d, eax
    jmp  .next
.end:
    xor  eax, eax
    cmp  dword [rsp], 1
    jne  .out
    cmp  dword [rsp + 4], 0
    jne  .out
    cmp  ebx, 1
    jne  .out
    inc  eax
.out:
    add  rsp, 8
    pop  rsi
    pop  rdi
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; HID 1.11 6.2.2,7.1.1,8; Usage Tables 1.21 pages 01/07/08.
; Finite profile documented in usb_hid_report_keyboard.md. No I/O in parser.
; RDI=descriptor, ESI=exact fetched length -> EAX=1/0. Candidate map's
; length is committed last. Unsupported items never acquire an input binding.
; Candidate map: bytes 0 wire length, 1 ID (0=none), 2 array byte offset,
; 3 array count, 4 maximum selector; 16..271 bit -> usage map. Zero is
; constant padding, FF marks array bits. Tail stays zero for byte alignment.
; Stack dwords: 0 page,4 logical min,8 logical max,12 size,16 count,
; 20/24 local usage min/max,28 local mask,32 collection state,36 input bits,
; 40 key mode,44 ID present,52 output bits,56 LED present,60 allow output-only;
; 64..95 seen usages. Header6..9: output wire length, ID, Num/Caps masks.
; 96 local list count,100..131 ordered usages (maximum32 per Main).
; 144 global depth,152..279 four 32-byte global snapshots.
; Only the numbered projector admits an output-only ID, alongside real Input.
usb_hid_report_parse_for_output:
    mov  r11d, 1
    jmp  usb_hid_report_parse.entry

usb_hid_report_parse:
    xor  r11d, r11d
.entry:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 288
    mov  r12, rdi
    mov  r13d, esi
    lea  r15, [rel usb_hid_report_candidate_map]
    mov  rdi, r15
    xor  eax, eax
    mov  ecx, USB_HID_REPORT_MAP_SIZE
    rep  stosb
    mov  rdi, rsp
    mov  ecx, 18
    rep  stosq
    mov  dword [rsp + 144], 0
    mov  [rsp + 60], r11d
    test r12, r12
    jz   .fail
    test r13d, r13d
    jz   .fail
    cmp  r13d, USB_HID_REPORT_DESC_CAP
    ja   .fail
    mov  rax, r12
    add  rax, r13
    jc   .fail
    xor  r14d, r14d
.next:
    cmp  r14d, r13d
    je   .end
    movzx ebx, byte [r12 + r14]
    inc  r14d
    cmp  ebx, 0xA4
    je   .global_push
    cmp  ebx, 0xB4
    je   .global_pop
    cmp  ebx, 0xC0
    je   .end_collection
    mov  ecx, ebx
    and  ecx, 3
    test ecx, ecx
    jz   .fail
    cmp  ecx, 2
    ja   .fail                       ; no long/reserved/four-byte items
    mov  eax, r13d
    sub  eax, r14d
    cmp  eax, ecx
    jb   .fail
    movzx edx, byte [r12 + r14]
    cmp  ecx, 1
    je   .value
    movzx edx, word [r12 + r14]
.value:
    add  r14d, ecx
    cmp  edx, 255
    ja   .fail                       ; no extended page/usages or signed ranges
    and  ebx, 0xFC
    cmp  ebx, 0x04
    je   .page
    cmp  ebx, 0x14
    je   .minimum
    cmp  ebx, 0x24
    je   .maximum
    cmp  ebx, 0x74
    je   .size
    cmp  ebx, 0x94
    je   .count
    cmp  ebx, 0x84
    je   .id
    cmp  ebx, 0x08
    je   .usage
    cmp  ebx, 0x18
    je   .usage_min
    cmp  ebx, 0x28
    je   .usage_max
    cmp  ebx, 0xA0
    je   .collection
    cmp  ebx, 0x80
    je   .input
    cmp  ebx, 0x90
    je   .output
    jmp  .fail                       ; Feature, delimiters, units, unknowns
.global_push:
    mov  eax, [rsp + 144]
    cmp  eax, 4
    jae  .fail                       ; finite global stack capacity
    shl  eax, 5
    lea  rdi, [rsp + rax + 152]
    mov  edx, [rsp + 0]
    mov  [rdi + 0], edx
    mov  edx, [rsp + 4]
    mov  [rdi + 4], edx
    mov  edx, [rsp + 8]
    mov  [rdi + 8], edx
    mov  edx, [rsp + 12]
    mov  [rdi + 12], edx
    mov  edx, [rsp + 16]
    mov  [rdi + 16], edx
    movzx edx, byte [r15 + 1]
    mov  [rdi + 24], edx
    inc  dword [rsp + 144]
    jmp  .next
.global_pop:
    mov  eax, [rsp + 144]
    test eax, eax
    jz   .fail                       ; global stack underflow
    dec  eax
    shl  eax, 5
    lea  rdi, [rsp + rax + 152]
    cmp  dword [rsp + 28], 0
    je   .global_page_ready
    mov  edx, [rdi]
    cmp  edx, [rsp]
    jne  .fail                       ; pending locals retain their declaration page
.global_page_ready:
    movzx edx, byte [r15 + 1]
    cmp  edx, [rdi + 24]
    jne  .fail                       ; single-map scope cannot restore another report ID
    mov  edx, [rdi + 0]
    mov  [rsp + 0], edx
    mov  edx, [rdi + 4]
    mov  [rsp + 4], edx
    mov  edx, [rdi + 8]
    mov  [rsp + 8], edx
    mov  edx, [rdi + 12]
    mov  [rsp + 12], edx
    mov  edx, [rdi + 16]
    mov  [rsp + 16], edx
    dec  dword [rsp + 144]
    jmp  .next
.page:
    cmp  edx, 1
    je   .save_page
    cmp  edx, 7
    je   .save_page
    cmp  edx, 8
    jne  .fail
.save_page:
    cmp  dword [rsp + 28], 0
    je   .page_unqualified
    cmp  edx, [rsp]
    jne  .fail                       ; local usages retain their declaration page
.page_unqualified:
    mov  [rsp], edx
    jmp  .next
.minimum:
    test edx, edx
    jnz  .fail
    mov  [rsp + 4], edx
    jmp  .next
.maximum:
    mov  [rsp + 8], edx
    jmp  .next
.size:
    test edx, edx
    jz   .fail
    cmp  edx, 8
    ja   .fail
    mov  [rsp + 12], edx
    jmp  .next
.count:
    test edx, edx
    jz   .fail
    cmp  edx, USB_HID_REPORT_BITS
    ja   .fail
    mov  [rsp + 16], edx
    jmp  .next
.id:
    test edx, edx
    jz   .fail                       ; Report ID zero is reserved
    cmp  dword [rsp + 44], 0
    jne  .fail                       ; exactly one ID declaration
    cmp  dword [rsp + 36], 0
    jne  .fail                       ; no unnumbered input preceding a numbered report
    cmp  dword [rsp + 52], 0
    jne  .fail
    mov  dword [rsp + 44], 1
    mov  [r15 + 1], dl
    jmp  .next
.usage:
    cmp  dword [rsp + 28], 0
    je   .usage_first
    cmp  dword [rsp + 28], 4
    jne  .fail                       ; list/range mixtures remain unsupported
    jmp  .usage_append
.usage_first:
    mov  [rsp + 20], edx
    mov  dword [rsp + 28], 4
.usage_append:
    mov  eax, [rsp + 96]
    cmp  eax, 32
    jae  .fail
    mov  [rsp + rax + 100], dl
    inc  dword [rsp + 96]
    jmp  .next
.usage_min:
    cmp  dword [rsp + 28], 0
    jne  .fail
    mov  [rsp + 20], edx
    mov  dword [rsp + 28], 1
    jmp  .next
.usage_max:
    cmp  dword [rsp + 28], 1
    jne  .fail
    cmp  edx, [rsp + 20]
    jb   .fail
    mov  [rsp + 24], edx
    mov  dword [rsp + 28], 3
    jmp  .next
.collection:
    cmp  edx, 1
    jne  .fail
    cmp  dword [rsp + 32], 0
    jne  .fail                       ; one top-level Application; no nested collections
    cmp  dword [rsp], 1
    jne  .fail
    cmp  dword [rsp + 28], 4
    jne  .fail
    cmp  dword [rsp + 96], 1
    jne  .fail                       ; one Application usage, not an alias list
    cmp  dword [rsp + 20], 6
    jne  .fail                       ; Generic Desktop / Keyboard, not arbitrary HID
    mov  dword [rsp + 32], 1
    jmp  .main_done
.end_collection:
    cmp  dword [rsp + 28], 0
    jne  .fail
    cmp  dword [rsp + 32], 1
    jne  .fail
    mov  dword [rsp + 32], 2
    jmp  .main_done
.input:
    cmp  dword [rsp + 32], 1
    jne  .fail
    mov  r9d, edx                    ; flags, exact supported Input encodings only
    mov  eax, [rsp + 12]
    mul  dword [rsp + 16]
    test edx, edx
    jnz  .fail
    test eax, eax
    jz   .fail
    mov  r10d, eax
    add  eax, [rsp + 36]
    jc   .fail
    cmp  eax, USB_HID_REPORT_BITS
    ja   .fail
    mov  r8d, eax                    ; exclusive bit extent
    mov  r11d, [rsp + 36]
    cmp  r9d, 1
    je   .input_done                 ; constant padding; map remains zero
    cmp  r9d, 3
    je   .input_done
    cmp  dword [rsp], 7
    jne  .fail
    cmp  r9d, 2
    je   .variable
    test r9d, r9d
    jnz  .fail                       ; relative, null, buffered, reserved flags refused
    cmp  dword [rsp + 28], 3
    jne  .fail                       ; arrays retain identity usage ranges
    cmp  dword [rsp + 12], 8
    jne  .fail
    ; Array slot capacity follows the validated report bit extent.
    test r11d, 7
    jnz  .fail
    cmp  dword [rsp + 40], 0
    jne  .fail                       ; no ambiguous second array or array/bitmap mix
    cmp  dword [rsp + 20], 0
    jne  .fail                       ; identity array index -> usage mapping only
    mov  eax, [rsp + 24]
    cmp  eax, 4
    jb   .fail
    cmp  eax, 0x65
    ja   .fail
    cmp  eax, [rsp + 8]
    jne  .fail
    mov  [r15 + 4], al
    mov  eax, r11d
    shr  eax, 3
    mov  [r15 + 2], al
    mov  eax, [rsp + 16]
    mov  [r15 + 3], al
    mov  dword [rsp + 40], 2
.array_map:
    mov  byte [r15 + r11 + 16], 255
    inc  r11d
    cmp  r11d, r8d
    jb   .array_map
    jmp  .input_done
.variable:
    cmp  dword [rsp + 12], 1
    jne  .fail
    cmp  dword [rsp + 8], 1
    jne  .fail
    cmp  dword [rsp + 28], 4
    je   .variable_list
    cmp  dword [rsp + 28], 3
    jne  .fail
    mov  eax, [rsp + 24]
    sub  eax, [rsp + 20]
    inc  eax
    cmp  eax, [rsp + 16]
    jne  .fail                       ; no repeated last usage / ambiguous variable map
    mov  ecx, [rsp + 20]
    cmp  ecx, 0xE0
    jae  .modifiers
    cmp  ecx, 4
    jb   .fail
    cmp  dword [rsp + 24], 0x64
    ja   .fail
    cmp  dword [rsp + 40], 2
    je   .fail
    mov  dword [rsp + 40], 1
    jmp  .variable_map
.modifiers:
    cmp  dword [rsp + 24], 0xE7
    ja   .fail
.variable_map:
    bts  [rsp + 64], ecx
    jc   .fail                       ; each usage occurs once across all variable fields
    mov  [r15 + r11 + 16], cl
    inc  ecx
    inc  r11d
    cmp  r11d, r8d
    jb   .variable_map
    jmp  .input_done
.variable_list:
    mov  eax, [rsp + 96]
    cmp  eax, [rsp + 16]
    jne  .fail                       ; no implicit repeat or ignored extra usages
    xor  r9d, r9d
.list_field:
    movzx ecx, byte [rsp + r9 + 100]
    cmp  ecx, 0xE0
    jae  .list_modifier
    cmp  ecx, 4
    jb   .fail
    cmp  ecx, 0x64
    ja   .fail
    cmp  dword [rsp + 40], 2
    je   .fail                       ; key bitmap cannot mix with an array
    mov  dword [rsp + 40], 1
    jmp  .list_map
.list_modifier:
    cmp  ecx, 0xE7
    ja   .fail
.list_map:
    bts  [rsp + 64], ecx
    jc   .fail                       ; shared list/range duplicate usage custody
    mov  [r15 + r11 + 16], cl         ; declaration order is wire bit order
    inc  r9d
    inc  r11d
    cmp  r11d, r8d
    jb   .list_field
.input_done:
    mov  [rsp + 36], r8d
    jmp  .main_done
.output:
    cmp  dword [rsp + 32], 1
    jne  .fail
    mov  r9d, edx
    mov  eax, [rsp + 12]
    mul  dword [rsp + 16]
    test edx, edx
    jnz  .fail
    test eax, eax
    jz   .fail
    add  eax, [rsp + 52]
    cmp  eax, 8
    ja   .fail                       ; optional single-byte LED output declaration only
    cmp  r9d, 1
    je   .output_done
    cmp  r9d, 3
    je   .output_done
    cmp  r9d, 2
    jne  .fail
    cmp  dword [rsp + 56], 0
    jne  .fail
    cmp  dword [rsp], 8
    jne  .fail
    cmp  dword [rsp + 12], 1
    jne  .fail
    cmp  dword [rsp + 8], 1
    jne  .fail
    cmp  dword [rsp + 28], 3
    jne  .fail
    cmp  dword [rsp + 20], 1
    jne  .fail
    cmp  dword [rsp + 24], 5
    ja   .fail
    mov  ecx, [rsp + 24]
    cmp  ecx, [rsp + 16]
    jne  .fail
    mov  dword [rsp + 56], 1
    mov  ecx, [rsp + 52]             ; payload offset, independent of Input bits
    mov  edx, 1
    shl  edx, cl
    mov  [r15 + 8], dl
    cmp  dword [rsp + 24], 2
    jb   .output_done
    shl  edx, 1
    mov  [r15 + 9], dl
.output_done:
    mov  [rsp + 52], eax
.main_done:
    mov  dword [rsp + 20], 0
    mov  dword [rsp + 24], 0
    mov  dword [rsp + 28], 0          ; HID local items reset after every Main item
    mov  dword [rsp + 96], 0
    jmp  .next
.end:
    cmp  dword [rsp + 144], 0
    jne  .fail                       ; unfinished global scopes never publish a map
    cmp  dword [rsp + 32], 2
    jne  .fail
    cmp  dword [rsp + 28], 0
    jne  .fail
    cmp  dword [rsp + 40], 0
    jne  .input_profile
    cmp  dword [rsp + 60], 1
    jne  .fail                       ; modifiers alone are not a keyboard key profile
    cmp  dword [rsp + 36], 0
    jne  .fail
    cmp  dword [rsp + 56], 1
    jne  .fail
    mov  byte [r15 + 5], 4           ; output-only numbered record, no Input authority
    jmp  .output_profile
.input_profile:
    mov  eax, [rsp + 36]
    add  eax, 7
    shr  eax, 3
    add  eax, [rsp + 44]
    cmp  eax, USB_HID_REPORT_WIRE_CAP
    ja   .fail
    mov  [r15], al                    ; publish only a complete verified map
.output_profile:
    cmp  dword [rsp + 56], 1
    jne  .success
    ; Absolute LED payload is one byte, with undeclared high bits zero padding.
    mov  eax, [rsp + 44]
    inc  eax
    mov  [r15 + 6], al
    mov  al, [r15 + 1]
    mov  [r15 + 7], al
.success:
    mov  eax, 1
    jmp  .out
.fail:
    mov  byte [r15], 0
    xor  eax, eax
.out:
    add  rsp, 288
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; HID1.11 6.2.2,8; HUT Generic Desktop Mouse/Pointer,X/Y/Wheel,Buttons.
; Strict unitless relative profile (usb_hid_report_mouse.md). RDI=descriptor,
; ESI=exact length -> EAX=1/0. Shares the bounded candidate/storage mechanism.
; Mouse map: 0 wire length (commit last),1 ID,5 protocol2,6 field mask.
; Six16-byte records at16: X,Y,wheel,buttons1..3; dwords offset,width,min,max.
; Bytes128..159 mark data bits; all other input bits must be zero padding.
; Stack: page,min,max,size,count,depth,application state,bits,ID seen,physical
; seen,local count,range min,max,local mask,logical presence,field mask;
;64..75 explicit usages. Locals reset at every Main item.
;80 global depth,84 absolute profile,88..215 four 32-byte global snapshots.
; Absolute entry accepts nonnegative X/Y; wheel stays signed and relative.
; Physical ranges are descriptive only, units/scales remain unsupported.
usb_hid_tablet_report_parse:
    mov  eax, 1
    jmp  usb_hid_mouse_report_parse.start

usb_hid_mouse_report_parse:
    xor  eax, eax
.start:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 224
    mov  [rsp + 84], eax
    mov  r12, rdi
    mov  r13d, esi
    lea  r15, [rel usb_hid_report_candidate_map]
    mov  rdi, r15
    xor  eax, eax
    mov  ecx, USB_HID_REPORT_MAP_SIZE
    rep  stosb
    mov  rdi, rsp
    mov  ecx, 10
    rep  stosq
    mov  dword [rsp + 80], 0
    test r12, r12
    jz   .fail
    test r13d, r13d
    jz   .fail
    cmp  r13d, USB_HID_REPORT_DESC_CAP
    ja   .fail
    mov  rax, r12
    add  rax, r13
    jc   .fail
    xor  r14d, r14d
.next:
    cmp  r14d, r13d
    je   .end
    movzx ebx, byte [r12 + r14]
    inc  r14d
    cmp  ebx, 0xA4
    je   .global_push
    cmp  ebx, 0xB4
    je   .global_pop
    cmp  dword [rsp + 24], 2
    je   .fail                       ; only stack items may follow final collection
    cmp  ebx, 0xC0
    je   .close
    mov  ecx, ebx
    and  ecx, 3
    test ecx, ecx
    jz   .fail
    cmp  ecx, 2
    ja   .fail                       ; long/four-byte/reserved items unsupported
    mov  eax, r13d
    sub  eax, r14d
    cmp  eax, ecx
    jb   .fail
    movzx edx, byte [r12 + r14]
    cmp  ecx, 1
    je   .value
    movzx edx, word [r12 + r14]
.value:
    add  r14d, ecx
    and  ebx, 0xFC
    cmp  ebx, 0x14
    je   .minimum
    cmp  ebx, 0x24
    je   .maximum
    cmp  ebx, 0x34                   ; Physical Minimum (no conversion units)
    je   .physical_range
    cmp  ebx, 0x44                   ; Physical Maximum
    je   .physical_range
    cmp  edx, 255
    jbe  .short_value
    ; Only the absolute profile accepts the two-byte Consumer AC Pan usage.
    cmp  dword [rsp + 84], 1
    jne  .fail
    cmp  dword [rsp], 0x0c
    jne  .fail
    cmp  ebx, 0x08
    jne  .fail
    cmp  edx, 0x0238
    jne  .fail
    jmp  .usage
.short_value:
    cmp  ebx, 0x04
    je   .page
    cmp  ebx, 0x74
    je   .size
    cmp  ebx, 0x94
    je   .count
    cmp  ebx, 0x84
    je   .id
    cmp  ebx, 0x08
    je   .usage
    cmp  ebx, 0x18
    je   .range_min
    cmp  ebx, 0x28
    je   .range_max
    cmp  ebx, 0xA0
    je   .collection
    cmp  ebx, 0x80
    je   .input
    jmp  .fail                       ; no Output/Feature/units/scales
.physical_range:
    cmp  dword [rsp + 84], 1
    jne  .fail                       ; original relative profile stays strict
    jmp  .next                       ; positions use the validated logical bounds
.global_push:
    mov  eax, [rsp + 80]
    cmp  eax, 4
    jae  .fail                       ; finite global stack capacity
    shl  eax, 5
    lea  rdi, [rsp + rax + 88]
    mov  edx, [rsp + 0]
    mov  [rdi + 0], edx
    mov  edx, [rsp + 4]
    mov  [rdi + 4], edx
    mov  edx, [rsp + 8]
    mov  [rdi + 8], edx
    mov  edx, [rsp + 12]
    mov  [rdi + 12], edx
    mov  edx, [rsp + 16]
    mov  [rdi + 16], edx
    mov  edx, [rsp + 56]
    mov  [rdi + 20], edx
    movzx edx, byte [r15 + 1]
    mov  [rdi + 24], edx
    inc  dword [rsp + 80]
    jmp  .next
.global_pop:
    mov  eax, [rsp + 80]
    test eax, eax
    jz   .fail                       ; global stack underflow
    dec  eax
    shl  eax, 5
    lea  rdi, [rsp + rax + 88]
    cmp  dword [rsp + 52], 0
    je   .global_page_ready
    mov  edx, [rdi]
    cmp  edx, [rsp]
    jne  .fail                       ; pending locals retain their declaration page
.global_page_ready:
    movzx edx, byte [r15 + 1]
    cmp  edx, [rdi + 24]
    jne  .fail                       ; single-map scope cannot restore another report ID
    mov  edx, [rdi + 0]
    mov  [rsp + 0], edx
    mov  edx, [rdi + 4]
    mov  [rsp + 4], edx
    mov  edx, [rdi + 8]
    mov  [rsp + 8], edx
    mov  edx, [rdi + 12]
    mov  [rsp + 12], edx
    mov  edx, [rdi + 16]
    mov  [rsp + 16], edx
    mov  edx, [rdi + 20]
    mov  [rsp + 56], edx
    dec  dword [rsp + 80]
    jmp  .next
.page:
    cmp  edx, 1
    je   .page_ok
    cmp  edx, 9
    je   .page_ok
    cmp  dword [rsp + 84], 1
    jne  .fail
    cmp  edx, 0x0c                   ; absolute pointer: bounded auxiliary AC Pan
    jne  .fail
.page_ok:
    cmp  dword [rsp + 52], 0
    je   .save_page
    cmp  edx, [rsp]
    jne  .fail                       ; locals retain their declared page
.save_page:
    mov  [rsp], edx
    jmp  .next
.minimum:
    cmp  ecx, 1
    jne  .minimum16
    movsx edx, dl
    jmp  .min_save
.minimum16:
    movsx edx, dx
.min_save:
    mov  [rsp + 4], edx
    mov  dword [rsp + 56], 1          ; new min requires a following max
    jmp  .next
.maximum:
    test dword [rsp + 56], 1
    jz   .fail
    cmp  dword [rsp + 4], 0
    jge  .max_save
    cmp  ecx, 1
    jne  .maximum16
    movsx edx, dl
    jmp  .max_save
.maximum16:
    movsx edx, dx
.max_save:
    mov  [rsp + 8], edx
    or   dword [rsp + 56], 2
    jmp  .next
.size:
    test edx, edx
    jz   .fail
    cmp  edx, 16
    ja   .fail
    mov  [rsp + 12], edx
    jmp  .next
.count:
    test edx, edx
    jz   .fail
    cmp  edx, USB_HID_REPORT_BITS
    ja   .fail
    mov  [rsp + 16], edx
    jmp  .next
.id:
    test edx, edx
    jz   .fail
    cmp  dword [rsp + 32], 0
    jne  .fail
    cmp  dword [rsp + 28], 0
    jne  .fail
    mov  [r15 + 1], dl
    mov  dword [rsp + 32], 1
    jmp  .next
.usage:
    test dword [rsp + 52], 6
    jnz  .fail
    mov  eax, [rsp + 40]
    cmp  eax, 3
    jae  .fail
    mov  [rsp + rax*4 + 64], edx
    inc  dword [rsp + 40]
    or   dword [rsp + 52], 1
    jmp  .next
.range_min:
    cmp  dword [rsp + 52], 0
    jne  .fail
    mov  [rsp + 44], edx
    mov  dword [rsp + 52], 2
    jmp  .next
.range_max:
    cmp  dword [rsp + 52], 2
    jne  .fail
    cmp  edx, [rsp + 44]
    jb   .fail
    mov  [rsp + 48], edx
    mov  dword [rsp + 52], 6
    jmp  .next
.collection:
    cmp  dword [rsp], 1
    jne  .fail
    cmp  dword [rsp + 52], 1
    jne  .fail
    cmp  dword [rsp + 40], 1
    jne  .fail
    cmp  dword [rsp + 20], 0
    jne  .physical
    cmp  dword [rsp + 24], 0
    jne  .fail
    cmp  edx, 1                      ; Mouse Application
    jne  .fail
    cmp  dword [rsp + 64], 2
    jne  .fail
    mov  dword [rsp + 24], 1
    jmp  .open
.physical:
    cmp  dword [rsp + 20], 1
    jne  .fail
    cmp  dword [rsp + 36], 0
    jne  .fail
    test edx, edx                    ; optional single Pointer Physical
    jnz  .fail
    cmp  dword [rsp + 64], 1
    jne  .fail
    mov  dword [rsp + 36], 1
.open:
    inc  dword [rsp + 20]
    jmp  .clear_locals
.close:
    cmp  dword [rsp + 52], 0
    jne  .fail
    cmp  dword [rsp + 20], 0
    je   .fail
    dec  dword [rsp + 20]
    jnz  .clear_locals
    mov  dword [rsp + 24], 2
    jmp  .clear_locals
.input:
    cmp  dword [rsp + 20], 0
    je   .fail
    mov  eax, [rsp + 12]
    test eax, eax
    jz   .fail
    mov  ecx, [rsp + 16]
    test ecx, ecx
    jz   .fail
    imul eax, ecx
    add  eax, [rsp + 28]
    cmp  eax, USB_HID_REPORT_BITS
    ja   .fail
    mov  r11d, eax                   ; next bit offset
    cmp  edx, 1
    je   .padding
    cmp  edx, 3
    je   .padding
    cmp  dword [rsp + 56], 3
    jne  .fail
    cmp  dword [rsp + 52], 1
    jne  .input_range
    cmp  ecx, [rsp + 40]
    jne  .fail                       ; no implicit repeated last Usage
    jmp  .fields
.input_range:
    cmp  dword [rsp + 52], 6
    jne  .fail
    mov  eax, [rsp + 48]
    sub  eax, [rsp + 44]
    inc  eax
    cmp  ecx, eax
    jne  .fail
.fields:
    xor  r8d, r8d
.field:
    cmp  dword [rsp + 52], 1
    jne  .range_usage
    mov  eax, [rsp + r8*4 + 64]
    jmp  .have_usage
.range_usage:
    mov  eax, [rsp + 44]
    add  eax, r8d
.have_usage:
    cmp  dword [rsp], 9
    jne  .axis
    cmp  edx, 2                      ; Buttons Data/Variable/Absolute
    jne  .fail
    cmp  dword [rsp + 12], 1
    jne  .fail
    cmp  dword [rsp + 4], 0
    jne  .fail
    cmp  dword [rsp + 8], 1
    jne  .fail
    cmp  eax, 1
    jb   .fail
    cmp  eax, 3
    jbe  .primary_button
    cmp  dword [rsp + 84], 1
    jne  .fail                       ; relative profile retains three buttons
    cmp  eax, 8
    ja   .fail
    add  eax, 12                     ; private duplicate bits16..20, not GUI flags
    bts  dword [rsp + 60], eax
    jc   .fail
    mov  eax, [rsp + 12]
    imul eax, r8d
    add  eax, [rsp + 28]
    mov  ecx, [rsp + 12]
    jmp  .cover_field               ; validated one-bit auxiliary button
.primary_button:
    add  eax, 2                      ; field indexes3..5
    jmp  .store_field
.axis:
    cmp  dword [rsp], 1
    jne  .pan_axis
    cmp  dword [rsp + 84], 1
    jne  .relative_axis
    cmp  eax, 0x38
    je   .relative_axis              ; wheel is never absolute
    cmp  edx, 2                      ; X/Y Data/Variable/Absolute, linear
    jne  .fail
    cmp  eax, 0x30
    je   .absolute_x
    cmp  eax, 0x31
    jne  .fail
    mov  eax, 1
    jmp  .absolute_range
.absolute_x:
    xor  eax, eax
.absolute_range:
    cmp  dword [rsp + 4], 0
    jne  .fail
    cmp  dword [rsp + 8], 0
    jle  .fail
    mov  ecx, [rsp + 12]
    mov  r9d, 1
    shl  r9d, cl
    dec  r9d
    cmp  [rsp + 8], r9d
    ja   .fail                       ; nonnegative bounds fit unsigned width
    jmp  .store_field
.relative_axis:
    cmp  edx, 6                      ; axes Data/Variable/Relative, linear
    jne  .fail
    cmp  eax, 0x30
    je   .x
    cmp  eax, 0x31
    je   .y
    cmp  eax, 0x38
    jne  .fail
    cmp  dword [rsp + 12], 8         ; wheel seam signed8, never truncate
    ja   .fail
    mov  eax, 2
    jmp  .axis_range
.x:
    xor  eax, eax
    jmp  .axis_range
.y:
    mov  eax, 1
.axis_range:
    cmp  dword [rsp + 4], 0
    jge  .fail
    cmp  dword [rsp + 8], 0
    jle  .fail
    mov  ecx, [rsp + 12]
    dec  ecx
    mov  r9d, 1
    shl  r9d, cl
    mov  r10d, r9d
    neg  r10d
    cmp  [rsp + 4], r10d
    jl   .fail                       ; logical bounds must fit signed width
    dec  r9d
    cmp  [rsp + 8], r9d
    jg   .fail
    jmp  .store_field
.pan_axis:
    cmp  dword [rsp + 84], 1
    jne  .fail
    cmp  dword [rsp], 0x0c
    jne  .fail
    cmp  eax, 0x0238                 ; only Consumer AC Pan, no arbitrary usage
    jne  .fail
    cmp  edx, 6                      ; signed relative linear data
    jne  .fail
    cmp  dword [rsp + 12], 8
    ja   .fail
    mov  byte [r15 + 8], 1           ; auxiliary field validated, not published as wheel
    mov  eax, 9                     ; auxiliary pan map at160, outside coverage128..159
    jmp  .axis_range
.store_field:
    bts  dword [rsp + 60], eax
    jc   .fail                       ; duplicate usages/fields are ambiguous
    shl  eax, 4
    lea  rdi, [r15 + rax + 16]
    mov  eax, [rsp + 12]
    imul eax, r8d
    add  eax, [rsp + 28]
    mov  [rdi], eax
    mov  ecx, [rsp + 12]
    mov  [rdi + 4], ecx
    mov  ecx, [rsp + 4]
    mov  [rdi + 8], ecx
    mov  ecx, [rsp + 8]
    mov  [rdi + 12], ecx
    mov  ecx, [rsp + 12]
.cover_field:
.cover:
    bts  dword [r15 + 128], eax      ; memory bit string, max247
    inc  eax
    dec  ecx
    jnz  .cover
.next_ignored_button:
    inc  r8d
    cmp  r8d, [rsp + 16]
    jb   .field
    jmp  .input_done
.padding:
    cmp  dword [rsp + 52], 0
    jne  .fail
.input_done:
    mov  [rsp + 28], r11d
.clear_locals:
    mov  dword [rsp + 40], 0
    mov  dword [rsp + 52], 0
    jmp  .next
.end:
    cmp  dword [rsp + 80], 0
    jne  .fail                       ; unfinished global scopes never publish a map
    cmp  dword [rsp + 24], 2
    jne  .fail
    cmp  dword [rsp + 52], 0
    jne  .fail
    mov  eax, [rsp + 60]
    and  eax, 3
    cmp  eax, 3                      ; both X and Y required
    jne  .fail
    mov  eax, [rsp + 28]
    add  eax, 7
    shr  eax, 3
    add  eax, [rsp + 32]
    cmp  eax, USB_HID_REPORT_WIRE_CAP
    ja   .fail
    mov  edx, [rsp + 60]
    mov  [r15 + 6], dl
    mov  edx, [rsp + 84]
    mov  [r15 + 7], dl               ; absolute coordinates, same mouse custody
    mov  byte [r15 + 5], 2
    mov  [r15], al                   ; whole map committed last
    mov  eax, 1
    jmp  .out
.fail:
    mov  byte [r15], 0
    xor  eax, eax
.out:
    add  rsp, 224
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=real state,RDX=wire,ECX=exact length,RSI=12byte normalized dx/dy/flags.
; Pure bounded extraction. Caller has already validated immutable custody.
usb_hid_mouse_report_decode:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 32
    mov  r12, rdx
    mov  r13, rsi
    mov  ebx, ecx
    call usb_hid_report_map_for_wire
    test rax, rax
    jz   .fail
    mov  r15, rax
    cmp  byte [r15 + 5], 2
    jne  .fail
    movzx eax, byte [r15]
    test eax, eax
    jz   .fail
    cmp  eax, ebx
    jne  .fail
    movzx eax, byte [r15 + 1]
    test eax, eax
    jz   .payload
    cmp  [r12], al
    jne  .fail
    inc  r12
    dec  ebx
.payload:
    ; Auxiliary AC Pan has no horizontal-scroll consumer yet. Validate every
    ; declared bit and signed bound before ignoring it; never turn it into wheel.
    cmp  byte [r15 + 8], 1
    jne  .aux_done
    lea  rdi, [r15 + 160]
    xor  r8d, r8d
    xor  r9d, r9d
.aux_bit:
    mov  eax, [rdi]
    add  eax, r8d
    mov  ecx, eax
    and  ecx, 7
    shr  eax, 3
    movzx edx, byte [r12 + rax]
    shr  edx, cl
    and  edx, 1
    mov  ecx, r8d
    shl  edx, cl
    or   r9d, edx
    inc  r8d
    cmp  r8d, [rdi + 4]
    jb   .aux_bit
    mov  ecx, 32
    sub  ecx, [rdi + 4]
    shl  r9d, cl
    sar  r9d, cl
    cmp  r9d, [rdi + 8]             ; ignored pan still obeys declared bounds
    jl   .fail
    cmp  r9d, [rdi + 12]
    jg   .fail
.aux_done:
    shl  ebx, 3
    xor  r8d, r8d
.padding:
    bt   dword [r15 + 128], r8d
    jc   .next_pad
    mov  eax, r8d
    shr  eax, 3
    movzx edx, byte [r12 + rax]
    mov  ecx, r8d
    and  ecx, 7
    shr  edx, cl
    test edx, 1
    jnz  .fail                       ; declared and implicit padding zero
.next_pad:
    inc  r8d
    cmp  r8d, ebx
    jb   .padding
    xor  eax, eax
    mov  [rsp], rax
    mov  [rsp + 8], rax
    mov  [rsp + 16], rax             ; six decoded fields, private until valid
    xor  r14d, r14d
.field:
    movzx eax, byte [r15 + 6]
    bt   eax, r14d
    jnc  .next_field
    mov  eax, r14d
    shl  eax, 4
    lea  rdi, [r15 + rax + 16]
    xor  r8d, r8d
    xor  r9d, r9d
.bit:
    mov  eax, [rdi]
    add  eax, r8d
    mov  ecx, eax
    and  ecx, 7
    shr  eax, 3
    movzx edx, byte [r12 + rax]
    shr  edx, cl
    and  edx, 1
    mov  ecx, r8d
    shl  edx, cl
    or   r9d, edx
    inc  r8d
    cmp  r8d, [rdi + 4]
    jb   .bit
    cmp  r14d, 3
    jae  .bounds
    cmp  r14d, 2
    jae  .signed                     ; wheel retains its signed relative meaning
    cmp  byte [r15 + 7], 1
    je   .bounds
.signed:
    mov  ecx, 32
    sub  ecx, [rdi + 4]
    shl  r9d, cl
    sar  r9d, cl                    ; signed width, no fixed boot positions
.bounds:
    cmp  r9d, [rdi + 8]
    jl   .fail
    cmp  r9d, [rdi + 12]
    jg   .fail
    cmp  r14d, 2
    jae  .store
    cmp  byte [r15 + 7], 1
    jne  .store
    mov  eax, r9d
    imul eax, 32767
    xor  edx, edx
    div  dword [rdi + 12]            ; each axis -> common unsigned 0..32767
    mov  r9d, eax
.store:
    mov  [rsp + r14*4], r9d
.next_field:
    inc  r14d
    cmp  r14d, 6
    jb   .field
    mov  eax, [rsp]
    mov  [r13], eax
    mov  eax, [rsp + 4]
    mov  [r13 + 4], eax
    mov  eax, [rsp + 8]
    and  eax, 255
    shl  eax, 8
    mov  edx, [rsp + 12]
    or   eax, edx
    mov  edx, [rsp + 16]
    shl  edx, 1
    or   eax, edx
    mov  edx, [rsp + 20]
    shl  edx, 2
    or   eax, edx
    cmp  byte [r15 + 7], 1
    jne  .flags_ready
    or   eax, (1 << 16)              ; native pointer queue: normalized absolute
.flags_ready:
    mov  [r13 + 8], eax
    mov  eax, 1
    jmp  .out
.fail:
    xor  eax, eax
.out:
    add  rsp, 32
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Bounded whole-descriptor projection. All numbered layouts must pass an
; existing strict profile; none are ignored. Globals retain HID scope, locals
; reset at each Main. Physical Pointer is validated before flattening it.
; HID1.11 sections6.2.2.7/8; finite policy in usb_hid_multi_report.md.
; Context: count,max wire,has keyboard,repeat ID,has mouse;16-byte header.
; Four288-byte records: existing272-byte map,accepted8-byte keys,sequence,gen.
;112 global depth,120..247 four 32-byte global snapshots.
usb_hid_multi_parse:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 256
    mov  r12, rdi
    mov  r13d, esi
    lea  r15, [rel usb_hid_multi_candidate]
    mov  rdi, r15
    xor  eax, eax
    mov  ecx, USB_HID_MULTI_SIZE
    rep  stosb
    mov  rdi, rsp
    mov  ecx, 14
    rep  stosq
    mov  byte [rel usb_hid_report_candidate_map], 0
    mov  dword [rsp + 112], 0
    test r12, r12
    jz   .fail
    test r13d, r13d
    jz   .fail
    cmp  r13d, USB_HID_REPORT_DESC_CAP
    ja   .fail
    mov  rax, r12
    add  rax, r13
    jc   .fail
    xor  r14d, r14d
.next:
    cmp  r14d, r13d
    je   .end
    movzx ebx, byte [r12 + r14]
    inc  r14d
    cmp  ebx, 0xA4
    je   .global_push
    cmp  ebx, 0xB4
    je   .global_pop
    cmp  ebx, 0xC0
    je   .close
    mov  ecx, ebx
    and  ecx, 3
    test ecx, ecx
    jz   .fail
    cmp  ecx, 2
    ja   .fail
    mov  eax, r13d
    sub  eax, r14d
    cmp  eax, ecx
    jb   .fail
    movzx edx, byte [r12 + r14]
    cmp  ecx, 1
    je   .value
    movzx edx, word [r12 + r14]
.value:
    add  r14d, ecx
    and  ebx, 0xFC
    cmp  ebx, 0x14
    je   .minimum
    cmp  ebx, 0x24
    je   .maximum
    cmp  edx, 255
    ja   .fail
    cmp  ebx, 0x04
    je   .page
    cmp  ebx, 0x74
    je   .size
    cmp  ebx, 0x94
    je   .count
    cmp  ebx, 0x84
    je   .id
    cmp  ebx, 0x08
    je   .local
    cmp  ebx, 0x18
    je   .local
    cmp  ebx, 0x28
    je   .local
    cmp  ebx, 0xA0
    je   .collection
    cmp  ebx, 0x80
    je   .main
    cmp  ebx, 0x90
    je   .main
    jmp  .fail                       ; Feature/units/scales/unknowns refuse all
.global_push:
    mov  eax, [rsp + 112]
    cmp  eax, 4
    jae  .fail                       ; finite global stack capacity
    shl  eax, 5
    lea  rdi, [rsp + rax + 120]
    mov  edx, [rsp + 0]
    mov  [rdi + 0], edx
    mov  edx, [rsp + 4]
    mov  [rdi + 4], edx
    mov  edx, [rsp + 8]
    mov  [rdi + 8], edx
    mov  edx, [rsp + 12]
    mov  [rdi + 12], edx
    mov  edx, [rsp + 16]
    mov  [rdi + 16], edx
    mov  edx, [rsp + 96]
    mov  [rdi + 20], edx
    mov  edx, [rsp + 32]
    mov  [rdi + 24], edx
    inc  dword [rsp + 112]
    jmp  .next
.global_pop:
    mov  eax, [rsp + 112]
    test eax, eax
    jz   .fail                       ; global stack underflow
    dec  eax
    shl  eax, 5
    lea  rdi, [rsp + rax + 120]
    cmp  dword [rsp + 36], 0
    je   .global_page_ready
    mov  edx, [rdi]
    cmp  edx, [rsp]
    jne  .fail                       ; pending locals retain their declaration page
.global_page_ready:
    mov  edx, [rdi + 0]
    mov  [rsp + 0], edx
    mov  edx, [rdi + 4]
    mov  [rsp + 4], edx
    mov  edx, [rdi + 8]
    mov  [rsp + 8], edx
    mov  edx, [rdi + 12]
    mov  [rsp + 12], edx
    mov  edx, [rdi + 16]
    mov  [rsp + 16], edx
    mov  edx, [rdi + 20]
    mov  [rsp + 96], edx
    mov  edx, [rdi + 24]
    mov  [rsp + 32], edx
    dec  dword [rsp + 112]
    jmp  .next
.page:
    cmp  dword [rsp + 36], 0
    je   .page_save
    cmp  edx, [rsp]
    jne  .fail                       ; locals keep their declaration page
.page_save:
    mov  [rsp], edx
    jmp  .next
.minimum:
    cmp  ecx, 1
    jne  .min16
    movsx edx, dl
    jmp  .min_save
.min16:
    movsx edx, dx
.min_save:
    mov  [rsp + 4], edx
    mov  dword [rsp + 96], 1
    jmp  .next
.maximum:
    test dword [rsp + 96], 1
    jz   .fail
    cmp  dword [rsp + 4], 0
    jge  .max_save
    cmp  ecx, 1
    jne  .max16
    movsx edx, dl
    jmp  .max_save
.max16:
    movsx edx, dx
.max_save:
    mov  [rsp + 8], edx
    or   dword [rsp + 96], 2
    jmp  .next
.size:
    test edx, edx
    jz   .fail
    cmp  edx, 16
    ja   .fail
    mov  [rsp + 12], edx
    jmp  .next
.count:
    test edx, edx
    jz   .fail
    cmp  edx, USB_HID_REPORT_BITS
    ja   .fail
    mov  [rsp + 16], edx
    jmp  .next
.id:
    test edx, edx
    jz   .fail
    cmp  dword [rsp + 20], 0
    je   .fail                       ; numbered profile IDs inside Application
    xor  eax, eax
.id_find:
    cmp  al, [r15]
    jae  .id_new
    imul edi, eax, USB_HID_MULTI_RECORD
    cmp  [r15 + rdi + 17], dl
    je   .id_found
    inc  eax
    jmp  .id_find
.id_new:
    cmp  eax, USB_HID_MULTI_REPORTS
    jae  .fail
    imul edi, eax, USB_HID_MULTI_RECORD
    mov  [r15 + rdi + 17], dl
    inc  byte [r15]
.id_found:
    inc  eax
    mov  [rsp + 32], eax
    jmp  .next
.local:
    mov  eax, [rsp + 36]
    lea  edi, [rax + rcx + 1]
    cmp  edi, 32
    ja   .fail
    mov  [rsp + 36], edi
    or   ebx, ecx
    mov  [rsp + rax + 64], bl
    mov  [rsp + rax + 65], dl
    cmp  ecx, 1
    je   .next
    mov  [rsp + rax + 66], dh
    jmp  .next
.collection:
    cmp  dword [rsp], 1
    jne  .fail
    mov  ecx, [rsp + 36]
    cmp  ecx, 2
    je   .collection8
    cmp  ecx, 3
    jne  .fail
    cmp  byte [rsp + 64], 0x0A
    jne  .fail
    cmp  byte [rsp + 66], 0
    jne  .fail
    jmp  .collection_usage
.collection8:
    cmp  byte [rsp + 64], 0x09
    jne  .fail
.collection_usage:
    movzx eax, byte [rsp + 65]
    cmp  dword [rsp + 20], 0
    jne  .physical
    cmp  edx, 1
    jne  .fail
    cmp  eax, 6
    je   .keyboard
    cmp  eax, 2
    jne  .fail
    mov  dword [rsp + 24], 2
    jmp  .application
.keyboard:
    mov  dword [rsp + 24], 1
.application:
    inc  dword [rsp + 28]
    mov  dword [rsp + 44], 0
    jmp  .open
.physical:
    cmp  dword [rsp + 20], 1
    jne  .fail
    cmp  dword [rsp + 24], 2
    jne  .fail
    cmp  dword [rsp + 44], 0
    jne  .fail
    test edx, edx
    jnz  .fail
    cmp  eax, 1
    jne  .fail
    mov  dword [rsp + 44], 1
.open:
    inc  dword [rsp + 20]
    jmp  .clear_locals
.close:
    cmp  dword [rsp + 36], 0
    jne  .fail
    cmp  dword [rsp + 20], 0
    je   .fail
    dec  dword [rsp + 20]
    jmp  .clear_locals
.main:
    cmp  dword [rsp + 20], 0
    je   .fail
    mov  eax, [rsp + 32]
    test eax, eax
    jz   .fail                       ; no numbered/unnumbered mixture
    test edx, 1
    jnz  .logical_ready              ; constant padding needs no logical range
    cmp  dword [rsp + 96], 3
    jne  .fail
.logical_ready:
    dec  eax
    imul r8d, eax, USB_HID_MULTI_RECORD
    lea  r8, [r15 + r8 + 16]
    shl  eax, 8
    lea  rdi, [rel usb_hid_multi_project]
    add  rdi, rax
    mov  eax, [rsp + 24]
    cmp  byte [r8 + 5], 0
    jne  .same_application
    mov  [r8 + 5], al
    mov  ecx, [rsp + 28]
    mov  [r8 + 276], ecx
    mov  dword [r8 + 272], 8
    mov  dword [rdi], 0x06090105    ; UsagePage1, UsageKeyboard
    cmp  eax, 1
    je   .prefix
    mov  byte [rdi + 3], 2
.prefix:
    mov  word [rdi + 4], 0x01A1
    mov  byte [rdi + 6], 0x85
    mov  al, [r8 + 1]
    mov  [rdi + 7], al
    jmp  .append
.same_application:
    cmp  [r8 + 5], al
    jne  .fail
    mov  eax, [rsp + 28]
    cmp  [r8 + 276], eax
    jne  .fail                       ; one report cannot span Applications
.append:
    mov  eax, [r8 + 272]
    mov  ecx, [rsp + 36]
    lea  esi, [rax + rcx + 15]       ; include final EndCollection
    cmp  esi, USB_HID_REPORT_DESC_CAP
    ja   .fail
    dec  esi
    mov  [r8 + 272], esi
    add  rdi, rax
    mov  byte [rdi], 0x05
    mov  al, [rsp]
    mov  [rdi + 1], al
    mov  byte [rdi + 2], 0x16
    mov  ax, [rsp + 4]
    mov  [rdi + 3], ax
    mov  byte [rdi + 5], 0x26
    mov  ax, [rsp + 8]
    mov  [rdi + 6], ax
    mov  byte [rdi + 8], 0x75
    mov  al, [rsp + 12]
    mov  [rdi + 9], al
    mov  byte [rdi + 10], 0x95
    mov  al, [rsp + 16]
    mov  [rdi + 11], al
    add  rdi, 12
    lea  rsi, [rsp + 64]
    rep  movsb
    or   ebx, 1
    mov  [rdi], bl
    mov  [rdi + 1], dl
.clear_locals:
    mov  dword [rsp + 36], 0
    jmp  .next
.end:
    cmp  dword [rsp + 112], 0
    jne  .fail                       ; unfinished global scopes never publish a map
    cmp  dword [rsp + 20], 0
    jne  .fail
    cmp  dword [rsp + 36], 0
    jne  .fail
    cmp  byte [r15], 0
    je   .fail
    xor  r14d, r14d
.validate:
    imul ebx, r14d, USB_HID_MULTI_RECORD
    lea  rbx, [r15 + rbx + 16]
    cmp  byte [rbx + 5], 0
    je   .fail                       ; every declared ID needs supported Input
    mov  eax, r14d
    shl  eax, 8
    lea  rdi, [rel usb_hid_multi_project]
    add  rdi, rax
    mov  esi, [rbx + 272]
    mov  byte [rdi + rsi], 0xC0
    inc  esi
    cmp  byte [rbx + 5], 2
    je   .parse_mouse
    call usb_hid_report_parse_for_output
    jmp  .parsed
.parse_mouse:
    call usb_hid_mouse_report_parse
.parsed:
    test eax, eax
    jz   .fail
    mov  rdi, rbx
    lea  rsi, [rel usb_hid_report_candidate_map]
    mov  ecx, USB_HID_REPORT_MAP_SIZE
    rep  movsb
    xor  eax, eax
    mov  [rbx + 272], rax
    mov  [rbx + 280], rax
    cmp  byte [rbx + 5], 4
    je   .validated
    cmp  byte [rbx + 5], 2
    je   .mouse_capability
    mov  byte [r15 + 2], 1
    jmp  .maximum_wire
.mouse_capability:
    mov  byte [r15 + 4], 1
.maximum_wire:
    mov  al, [rbx]
    cmp  al, [r15 + 1]
    jbe  .validated
    mov  [r15 + 1], al
.validated:
    inc  r14d
    movzx eax, byte [r15]
    cmp  r14d, eax
    jb   .validate
    cmp  byte [r15 + 1], 0
    je   .fail                       ; Output alone never acquires an input binding
    lea  rdi, [rel usb_hid_report_candidate_map]
    xor  eax, eax
    mov  ecx, USB_HID_REPORT_MAP_SIZE
    rep  stosb
    mov  al, [r15 + 1]
    mov  [rel usb_hid_report_candidate_map], al
    mov  byte [rel usb_hid_report_candidate_map + 5], 3
    mov  eax, 1
    jmp  .out
.fail:
    mov  byte [rel usb_hid_report_candidate_map], 0
    mov  byte [r15], 0
    xor  eax, eax
.out:
    add  rsp, 256
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Configured interface recipient. Exact descriptor length from validated HID
; descriptor; no truncation accepted. Non-boot devices stay in report protocol.
; In RDI=hc, ESI=port. Out EAX=1/0.
usb_hid_report_fetch:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13d, esi
    mov  byte [rel usb_hid_report_candidate_map], 0
    movzx ebx, word [rel usb_hid_report_descriptor_len]
    test ebx, ebx
    jz   .fail
    cmp  ebx, USB_HID_REPORT_DESC_CAP
    ja   .fail
    lea  rsi, [rel usb_hid_setup]
    mov  byte [rsi], 0x81
    mov  byte [rsi + 1], USB_REQ_GET_DESCRIPTOR
    mov  word [rsi + 2], 0x2200
    movzx eax, byte [rel usb_hid_report_interface]
    mov  [rsi + 4], ax
    mov  [rsi + 6], bx
    mov  rdi, r12
    mov  edx, r13d
    lea  rcx, [rel usb_hid_report_descriptor]
    mov  r8d, ebx
    mov  rax, [r12 + dev.ops]
    call [rax + usbhc_ops.control]
    cmp  rax, rbx
    jne  .fail
    lea  rdi, [rel usb_hid_report_descriptor]
    mov  esi, ebx
    call usb_hid_report_parse
    test eax, eax
    jnz  .out
    lea  rdi, [rel usb_hid_report_descriptor]
    mov  esi, ebx
    call usb_hid_mouse_report_parse
    test eax, eax
    jnz  .out
    lea  rdi, [rel usb_hid_report_descriptor]
    mov  esi, ebx
    call usb_hid_tablet_report_parse
    test eax, eax
    jnz  .out
    lea  rdi, [rel usb_hid_report_descriptor]
    mov  esi, ebx
    call usb_hid_multi_parse
    test eax, eax
    jnz  .out
    lea  rdi, [rel usb_hid_report_descriptor]
    mov  esi, ebx
    call usb_hid_touchpad_parse
    jmp  .out
.fail:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

 ; Strict touchpad map: header[16], unchanged shared layout[128], proof[64].
usb_hid_touchpad_parse:
    lea  rdx, [rel usb_hid_report_candidate_map]
    jmp  hid_touchpad_parse

; Transport-neutral finite map builder: RDI descriptor, ESI extent, RDX map272.
; EAX=1 only for a complete supported parallel TouchPad descriptor.
hid_touchpad_parse:
    push rbx
    mov  rbx, rdx
    push rdi
    xor  eax, eax
    mov  rdi, rbx
    mov  ecx, USB_HID_REPORT_MAP_SIZE
    rep  stosb
    pop  rdi
    test rdi, rdi
    jz   .fail
    test esi, esi
    jz   .fail
    cmp  esi, 256
    ja   .fail
    mov  eax, esi
    add  rax, rdi
    jc   .fail
    lea  rdx, [rbx + 16]
    lea  r8, [rbx + 144]
    call hid_rdesc_parse_touchpad
    test eax, eax
    jnz  .fail
    movzx eax, word [rbx + 16 + 40]
    add  eax, 7
    shr  eax, 3
    mov  dl, [rbx + 16 + 4]
    mov  [rbx + 1], dl
    test dl, dl
    jz   .length
    inc  eax
.length:
    cmp  eax, USB_HID_REPORT_WIRE_CAP
    ja   .fail
    mov  byte [rbx + 5], 4
    mov  [rbx], al
    mov  eax, 1
    pop  rbx
    ret
.fail:
    mov  rdi, rbx
    xor  eax, eax
    mov  ecx, USB_HID_REPORT_MAP_SIZE
    rep  stosb
    pop  rbx
    ret

; Extract a proved unsigned field, including non-byte-aligned coordinates.
; RDI=payload, ESI=bit offset, EDX=width1..16 -> EAX. No extra byte read.
usb_hid_touchpad_bits:
    xor  r8d, r8d
    xor  r9d, r9d
.bit:
    mov  eax, esi
    add  eax, r8d
    mov  ecx, eax
    and  ecx, 7
    shr  eax, 3
    movzx eax, byte [rdi + rax]
    shr  eax, cl
    and  eax, 1
    mov  ecx, r8d
    shl  eax, cl
    or   r9d, eax
    inc  r8d
    cmp  r8d, edx
    jb   .bit
    mov  eax, r9d
    ret

; Complete parallel contacts only. RDI=real state,RDX=wire,ECX=length.
; Validate every slot before publishing or changing an anchor. One contact ID
; remains primary across slot reordering. Lift/ID replacement re-anchors; no
; tap, scroll, pinch or other synthesized gesture. Units are descriptor units
; fed through the existing relative pointer speed/clamp/authority seam.
usb_hid_touchpad_consume:
    push rbx
    push r12
    push r13
    sub  rsp, 16
    mov  r12, rdi
    mov  r13, rdx
    mov  [rsp], ecx
    call usb_hid_report_map_for_state
    test rax, rax
    jz   .out
    lea  rdi, [r12 + usb_hid_state.previous]
    mov  rsi, rax
    mov  rdx, r13
    mov  ecx, [rsp]
    lea  r8, [rel usb_hid_pointer_publish]
    mov  r9, r12
    call hid_touchpad_consume
    test eax, eax
    jz   .out
    inc  qword [rel usb_hid_mouse_reports]
.out:
    add  rsp, 16
    pop  r13
    pop  r12
    pop  rbx
    ret

; Shared adapter: RDI anchor8, RSI proved map272, RDX wire, ECX extent,
; R8 native accepted-publication function(ctx,dx,dy,buttons), R9 ctx.
; Caller serializes and owns map/anchor/custody. Commit only after sink accepts.
hid_touchpad_consume:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 144
    mov  r12, rdi
    mov  r13, rdx
    mov  ebx, ecx
    mov  r14, rsi
    mov  [rsp + 112], r8
    mov  [rsp + 120], r9
    cmp  byte [r14 + 5], 4
    jne  .fail
    movzx eax, byte [r14]
    cmp  ebx, eax
    jne  .fail
    movzx eax, byte [r14 + 1]
    test eax, eax
    jz   .payload
    cmp  [r13], al
    jne  .fail
    inc  r13
    dec  ebx
.payload:
    shl  ebx, 3
    xor  r15d, r15d
.padding:
    bt   dword [r14 + 144], r15d
    jc   .next_pad
    mov  rdi, r13
    mov  esi, r15d
    mov  edx, 1
    call usb_hid_touchpad_bits
    test eax, eax
    jnz  .fail
.next_pad:
    inc  r15d
    cmp  r15d, ebx
    jb   .padding
    mov  rdi, r13
    movzx esi, word [r14 + 16 + 36]
    movzx edx, byte [r14 + 16 + 38]
    call usb_hid_touchpad_bits
    cmp  eax, [r14 + 144 + 52]
    ja   .fail
    movzx edx, byte [r14 + 16 + 35]
    cmp  eax, edx
    ja   .fail                    ; no hybrid/serial contact frames
    mov  [rsp + 80], eax          ; reported count
    mov  dword [rsp + 84], 0      ; actual active count
    xor  r15d, r15d
.slot:
    mov  ebx, r15d
    shl  ebx, 4
    lea  r10, [r14 + rbx + 16 + 48]
    mov  rdi, r13
    movzx esi, word [r10]
    mov  edx, 1
    call usb_hid_touchpad_bits
    mov  [rsp + rbx + 12], eax
    add  [rsp + 84], eax
    mov  rdi, r13
    movzx esi, word [r10 + 2]
    movzx edx, byte [r10 + 4]
    call usb_hid_touchpad_bits
    cmp  eax, [r14 + 144 + 32 + r15*4]
    ja   .fail
    mov  [rsp + rbx + 8], eax
    mov  rdi, r13
    movzx esi, word [r10 + 6]
    movzx edx, byte [r10 + 8]
    call usb_hid_touchpad_bits
    cmp  eax, [r14 + 16 + 16]
    jl   .fail
    cmp  eax, [r14 + 16 + 20]
    jg   .fail
    mov  [rsp + rbx], eax
    mov  rdi, r13
    movzx esi, word [r10 + 10]
    movzx edx, byte [r10 + 9]
    call usb_hid_touchpad_bits
    cmp  eax, [r14 + 16 + 24]
    jl   .fail
    cmp  eax, [r14 + 16 + 28]
    jg   .fail
    mov  [rsp + rbx + 4], eax
    cmp  dword [rsp + rbx + 12], 0
    je   .slot_next
    xor  ecx, ecx
.unique:
    cmp  ecx, ebx
    jae  .slot_next
    cmp  dword [rsp + rcx + 12], 0
    je   .unique_next
    mov  eax, [rsp + rcx + 8]
    cmp  eax, [rsp + rbx + 8]
    je   .fail
.unique_next:
    add  ecx, 16
    jmp  .unique
.slot_next:
    inc  r15d
    movzx eax, byte [r14 + 16 + 35]
    cmp  r15d, eax
    jb   .slot
    mov  eax, [rsp + 80]
    cmp  eax, [rsp + 84]
    jne  .fail
    xor  ebx, ebx
    mov  r15d, -1                 ; chosen complete contact / none
.choose:
    cmp  dword [rsp + rbx + 12], 0
    je   .choose_next
    cmp  r15d, -1
    jne  .prior
    mov  r15d, ebx
.prior:
    cmp  byte [r12 + 5], 1
    jne  .choose_next
    movzx eax, byte [r12 + 4]
    cmp  eax, [rsp + rbx + 8]
    jne  .choose_next
    mov  r15d, ebx
    jmp  .chosen
.choose_next:
    add  ebx, 16
    movzx eax, byte [r14 + 16 + 35]
    shl  eax, 4
    cmp  ebx, eax
    jb   .choose
.chosen:
    mov  dword [rsp + 88], 0      ; buttons
    movzx edx, byte [r14 + 16 + 5]
    test edx, edx
    jz   .motion
    mov  rdi, r13
    movzx esi, word [r14 + 16 + 6]
    call usb_hid_touchpad_bits
    mov  [rsp + 88], eax
.motion:
    xor  esi, esi
    xor  edx, edx
    cmp  r15d, -1
    je   .publish
    cmp  byte [r12 + 5], 1
    jne  .publish
    movzx eax, byte [r12 + 4]
    cmp  eax, [rsp + r15 + 8]
    jne  .publish
    mov  esi, [rsp + r15]
    movzx eax, word [r12]
    sub  esi, eax
    mov  edx, [rsp + r15 + 4]
    movzx eax, word [r12 + 2]
    sub  edx, eax
.publish:
    mov  rdi, [rsp + 120]
    mov  ecx, [rsp + 88]
    call [rsp + 112]
    test eax, eax
    jz   .fail                    ; full native ring cannot commit anchor/buttons
    mov  byte [r12 + 5], 0
    cmp  r15d, -1
    je   .accepted
    mov  eax, [rsp + r15]
    mov  [r12], ax
    mov  eax, [rsp + r15 + 4]
    mov  [r12 + 2], ax
    mov  al, [rsp + r15 + 8]
    mov  [r12 + 4], al
    mov  byte [r12 + 5], 1
.accepted:
    mov  eax, 1
    jmp  .out
.fail:
    xor  eax, eax
.out:
    add  rsp, 144
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=state,ESI=dx,EDX=dy,ECX=buttons|wheel. Accepted per-state buttons
; union across independent native HID pointer states; wheel stays per-event.
; Only successful native publication commits custody. Synthetic boot KATs
; retain their original pointer sink without acquiring physical ownership.
usb_hid_pointer_publish:
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 8
    mov  r12d, esi
    mov  r13d, edx
    mov  r14d, ecx
    call usb_hid_report_map_for_state
    test rax, rax
    jz   .synthetic
    mov  edi, ecx
    mov  esi, r12d
    mov  edx, r13d
    mov  ecx, r14d
    call hid_pointer_publish
    test eax, eax
    jnz  .out
    mov  byte [rel usb_hid_obs_reason], 0 ; native pressure, not malformed wire
    jmp  .out
.synthetic:
    mov  edi, r12d
    mov  esi, r13d
    mov  edx, r14d
    call ps2_pointer_post
    mov  eax, 1
.out:
    add  rsp, 8
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; hid_pointer_retire(EDI source) -> EAX accepted. RCQ-09 (root 13:30:07): the
; buttons-up of a source that left (USB retirement, I2C session detach), marked
; USB_HID_PTR_RETIRED so the GUI ends the held gesture and fires nothing.
hid_pointer_retire:
    xor  esi, esi
    xor  edx, edx
    mov  ecx, USB_HID_PTR_RETIRED
    jmp  hid_pointer_publish.marked

; Shared accepted button custody, USB sources0..3 and one explicit I2C source4.
; EDI source, ESI dx, EDX dy, ECX buttons|wheel -> EAX accepted.
; Every transport uses the same native queue and authority capture. Retirement
; retains its slot until a zero-button publication fits. No separate authority.
hid_pointer_publish:
    cmp  edi, USB_HID_MAX_STATES
    ja   .bad
    lea  rax, [rel usb_hid_pointer_cancel]
    cmp  byte [rax + rdi], 0
    jne  .bad                         ; cancellation must precede a new gesture
    and  ecx, ~USB_HID_PTR_RETIRED      ; a report never carries the retirement mark
.marked:
    cmp  edi, USB_HID_MAX_STATES
    ja   .bad
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 8
    mov  ebx, edi
    mov  r12d, esi
    mov  r13d, edx
    mov  r14d, ecx
    mov  [rsp], ecx
    and  ecx, 7
    xor  eax, eax
    lea  rdi, [rel usb_hid_pointer_buttons]
.union:
    cmp  eax, ebx
    je   .next
    or   cl, [rdi + rax]
.next:
    inc  eax
    cmp  eax, USB_HID_MAX_STATES + 1
    jb   .union
    and  r14d, ~7
    or   ecx, r14d
    mov  edi, r12d
    mov  esi, r13d
    mov  edx, ecx
    call ps2_pointer_try_post
    test eax, eax
    jz   .pressure
    mov  eax, [rsp]
    and  eax, 7
    lea  rdx, [rel usb_hid_pointer_buttons]
    mov  [rdx + rbx], al
    lea  rdx, [rel usb_hid_pointer_cancel]
    mov  byte [rdx + rbx], 0
    mov  eax, 1
    jmp  .out
.pressure:
    ; Retain only a cancellation bit, never raw motion/wheel or its authority.
    ; Accepted custody changes only when the zero-motion retired release fits.
    mov  edx, [rsp]
    not  edx
    lea  rcx, [rel usb_hid_pointer_buttons]
    and  dl, [rcx + rbx]
    and  edx, 7
    jz   .refused
    lea  rcx, [rel usb_hid_pointer_cancel]
    mov  byte [rcx + rbx], 1
.refused:
    xor  eax, eax
.out:
    add  rsp, 8
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
.bad:
    xor  eax, eax
    ret

; Retry at most one cancellation per source in the existing cooperative poll.
; A retired marker cancels GUI gesture state without granting a click/presence.
hid_pointer_cancel_tick:
    push rbx
    xor  ebx, ebx
.next:
    lea  rax, [rel usb_hid_pointer_cancel]
    cmp  byte [rax + rbx], 0
    je   .advance
    mov  edi, ebx
    call hid_pointer_retire
.advance:
    inc  ebx
    cmp  ebx, USB_HID_MAX_STATES + 1
    jb   .next
    pop  rbx
    ret

; State ABI is unchanged; maps and wire buffers are private to each real slot.
; Reject out-of-array/misaligned synthetic pointers before map access.
; RDI=state -> RAX=map/0, ECX=index. Clobbers RDX.
usb_hid_report_map_for_state:
    mov  rax, rdi
    lea  rdx, [rel usb_hid_states]
    sub  rax, rdx
    jc   .fail
    cmp  rax, USB_HID_MAX_STATES * usb_hid_state_size
    jae  .fail
    xor  edx, edx
    mov  ecx, usb_hid_state_size
    div  rcx
    test edx, edx
    jnz  .fail
    mov  ecx, eax
    imul eax, USB_HID_REPORT_MAP_SIZE
    lea  rdx, [rel usb_hid_report_maps]
    add  rax, rdx
    ret
.fail:
    xor  eax, eax
    ret

; Router-owned snapshot. The class never toggles locks from raw USB reports.
; EDI bit0 NumLock, bit1 CapsLock. No I/O, no key-ring access, no new authority.
usb_hid_keyboard_locks:
    and  edi, 3
    mov  [rel usb_hid_led_locks], dil
    mov  byte [rel usb_hid_led_locks_valid], 1
    ret

; Private sidecar, leaving the 64-byte input custody ABI and capacities intact.
; RDI=real state -> RAX=128-byte context/0, ECX=index, RDX=epoch address.
; Four 32-byte records: length,ID,NumMask,CapsMask,desired,completed,valid,
; attempts; dword cooldown at8; qword last actual transfer result at16.
usb_hid_led_context:
    call usb_hid_report_map_for_state
    test rax, rax
    jz   .out
    lea  rdx, [rel usb_hid_led_epochs]
    lea  rdx, [rdx + rcx*8]
    shl  ecx, 7
    lea  rax, [rel usb_hid_led_states]
    add  rax, rcx
.out:
    ret

usb_hid_led_clear_state:
    call usb_hid_led_context
    test rax, rax
    jz   .out
    inc  qword [rdx]                 ; fence reuse, even within the same HC generation
    mov  rdi, rax
    xor  eax, eax
    mov  ecx, USB_HID_LED_CONTEXT / 8
    rep  stosq
.out:
    ret

; Bind copies only the verified finite Output layout. No inferred report ID.
usb_hid_led_install:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    call usb_hid_led_clear_state
    mov  rdi, r12
    call usb_hid_led_context
    test rax, rax
    jz   .out
    mov  rbx, rax
    cmp  byte [r12 + usb_hid_state.protocol], 0
    jne  .report
    cmp  byte [r12 + usb_hid_state.kind], USB_HID_KIND_KBD
    jne  .out
    mov  dword [rbx], 0x02010001      ; boot: length1, ID0, Num bit0, Caps bit1
    jmp  .out
.report:
    cmp  byte [r12 + usb_hid_state.protocol], 3
    je   .multi
    cmp  byte [r12 + usb_hid_state.protocol], 1
    jne  .out                        ; a mouse header is not an LED map
    mov  rdi, r12
    call usb_hid_report_map_for_state
    mov  eax, [rax + 6]
    mov  [rbx], eax
    jmp  .out
.multi:
    mov  rdi, r12
    call usb_hid_multi_context
    movzx r13d, byte [rax]
    add  rax, 16
.next:
    cmp  byte [rax + 5], 2
    je   .advance
    mov  edx, [rax + 6]
    mov  [rbx], edx
.advance:
    add  rbx, USB_HID_LED_RECORD
    add  rax, USB_HID_MULTI_RECORD
    dec  r13d
    jnz  .next
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=state -> EAX1 current /0 obsolete. No control submission here.
; RESOURCE's existing controller ops remain the lifecycle/power boundary.
usb_hid_led_current:
    push rbx
    mov  rbx, rdi
    cmp  byte [rbx + usb_hid_state.active], 1
    jne  .no
    mov  rdi, [rbx + usb_hid_state.hc]
    call xhci_hc_generation
    cmp  eax, [rbx + usb_hid_state.generation]
    jne  .no
    mov  rdi, [rbx + usb_hid_state.hc]
    mov  rax, [rdi + dev.ops]
    cmp  rax, [rbx + usb_hid_state.ops]
    jne  .no
    cmp  qword [rax + usbhc_ops.control], 0
    je   .no
    movzx esi, byte [rbx + usb_hid_state.port]
    call [rax + usbhc_ops.port_status]
    cmp  rax, -1
    je   .no                         ; backend unavailable/fenced, not a live port
    test eax, USB_PORT_CONNECT
    jz   .no
    mov  rdi, [rbx + usb_hid_state.hc]
    movzx esi, byte [rbx + usb_hid_state.port]
    call xhci_hid_slot_for_port
    cmp  al, [rbx + usb_hid_state.slot]
    jne  .no
    test eax, eax
    jz   .no
    cmp  edx, [rbx + usb_hid_state.generation]
    jne  .no
    mov  eax, 1
    pop  rbx
    ret
.no:
    xor  eax, eax
    pop  rbx
    ret

; One EP0 attempt per cooperative pass, round-robin over 4 states *4 IDs.
; Optional failures leave input and siblings live. Three attempts per failing
; record, separated by cooperative passes; retirement lasts until rebind.
usb_hid_led_tick:
    cmp  byte [rel usb_hid_led_locks_valid], 1
    jne  .return
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 32                     ; setup8, data2, desired1; epoch8 at16
    mov  r15d, USB_HID_MAX_STATES * USB_HID_MULTI_REPORTS
.scan:
    mov  eax, [rel usb_hid_led_cursor]
    lea  ecx, [rax + 1]
    and  ecx, 15
    mov  [rel usb_hid_led_cursor], ecx
    mov  edx, eax
    shr  edx, 2
    shl  edx, 6
    lea  r12, [rel usb_hid_states]
    add  r12, rdx
    mov  edx, eax
    shl  edx, 5
    lea  rbx, [rel usb_hid_led_states]
    add  rbx, rdx
    cmp  byte [r12 + usb_hid_state.active], 1
    jne  .next
    cmp  byte [rbx], 0
    je   .next
    xor  edx, edx
    movzx eax, byte [rel usb_hid_led_locks]
    test al, 1
    jz   .caps
    or   dl, [rbx + 2]
.caps:
    test al, 2
    jz   .desired
    or   dl, [rbx + 3]
.desired:
    mov  [rbx + 4], dl               ; desired encoded payload, never completion
    cmp  byte [rbx + 6], 1
    jne  .pending
    cmp  dl, [rbx + 5]
    je   .next                       ; coalesce even unsupported lock-bit changes
.pending:
    cmp  byte [rbx + 7], USB_HID_LED_RETRIES
    jae  .next                       ; bounded retirement, no input suppression
    cmp  dword [rbx + 8], 0
    je   .ready
    dec  dword [rbx + 8]
    jmp  .next
.ready:
    mov  rdi, r12
    call usb_hid_led_current
    test eax, eax
    jz   .next
    mov  rdi, r12
    call usb_hid_led_context
    mov  r13, rdx
    mov  rax, [rdx]
    mov  [rsp + 16], rax
    mov  qword [rsp], 0
    mov  word [rsp], 0x0921          ; class/interface SET_REPORT (HID1.11 7.2.2)
    mov  al, [rbx + 1]
    mov  [rsp + 2], al
    mov  byte [rsp + 3], 2           ; Output report type, not Input
    mov  al, [r12 + usb_hid_state.interface]
    mov  [rsp + 4], al
    movzx r14d, byte [rbx]
    mov  [rsp + 6], r14w
    mov  byte [rsp + 8], 0
    mov  byte [rsp + 9], 0
    mov  al, [rbx + 4]
    mov  [rsp + 10], al              ; submitted snapshot; do not commit a later desire
    cmp  r14d, 1
    je   .unnumbered
    mov  dl, [rbx + 1]
    mov  [rsp + 8], dl
    mov  [rsp + 9], al
    jmp  .submit
.unnumbered:
    mov  [rsp + 8], al
.submit:
    inc  byte [rbx + 7]
    mov  dword [rbx + 8], USB_HID_LED_BACKOFF
    mov  rax, [r12 + usb_hid_state.ops]
    mov  rdi, [r12 + usb_hid_state.hc]
    mov  rsi, rsp
    movzx edx, byte [r12 + usb_hid_state.port]
    lea  rcx, [rsp + 8]
    mov  r8d, r14d
    call [rax + usbhc_ops.control]   ; actual controller data-out path, bounded wait
    mov  [rsp + 24], rax
    mov  rax, [rsp + 16]
    cmp  rax, [r13]
    jne  .out                        ; detach/reuse: never modify replacement custody
    mov  rdi, r12
    call usb_hid_led_current
    test eax, eax
    jz   .out
    mov  rax, [rsp + 24]
    mov  [rbx + 16], rax             ; retain full-width actual status/length
    cmp  rax, r14
    jne  .out                        ; STALL/error/short/foreign high bits: not completed
    mov  al, [rsp + 10]
    mov  [rbx + 5], al
    mov  byte [rbx + 6], 1
    mov  byte [rbx + 7], 0
    mov  dword [rbx + 8], 0
    jmp  .out
.next:
    dec  r15d
    jnz  .scan
.out:
    add  rsp, 32
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
.return:
    ret

; RDI=state -> RAX=private wire buffer/0, preserves all nonvolatile registers.
usb_hid_report_buffer_for_state:
    call usb_hid_report_map_for_state
    test rax, rax
    jz   .out
    shl  ecx, 5
    lea  rax, [rel usb_hid_report_buffers]
    add  rax, rcx
.out:
    ret

usb_hid_report_install:
    push rdi
    call usb_hid_report_map_for_state
    test rax, rax
    jz   .fail
    mov  rdi, rax
    lea  rsi, [rel usb_hid_report_candidate_map]
    mov  ecx, USB_HID_REPORT_MAP_SIZE
    rep  movsb
    pop  rdi
    push rdi
    call usb_hid_multi_context
    test rax, rax
    jz   .fail
    mov  rdi, rax
    xor  eax, eax
    mov  ecx, USB_HID_MULTI_SIZE / 8
    rep  stosq
    cmp  byte [rel usb_hid_report_candidate_map + 5], 3
    jne  .ok
    sub  rdi, USB_HID_MULTI_SIZE
    lea  rsi, [rel usb_hid_multi_candidate]
    mov  ecx, USB_HID_MULTI_SIZE
    rep  movsb
.ok:
    mov  eax, 1
.fail:
    pop  rdi
    ret

; Same checked physical-state index as the existing single map ABI.
usb_hid_multi_context:
    call usb_hid_report_map_for_state
    test rax, rax
    jz   .out
    imul eax, ecx, USB_HID_MULTI_SIZE
    lea  rdx, [rel usb_hid_multi_states]
    add  rax, rdx
.out:
    ret

; RDI=physical state,RDX=wire,ECX=length -> selected private map/0.
; Unknown IDs and mismatched exact lengths never select any map.
usb_hid_report_map_for_wire:
    cmp  byte [rdi + usb_hid_state.protocol], 3
    je   usb_hid_multi_select
    jmp  usb_hid_report_map_for_state

usb_hid_multi_select:
    push rbx
    push r12
    mov  r12, rdx
    mov  ebx, ecx
    cmp  ebx, 2
    jb   .fail
    call usb_hid_multi_context
    test rax, rax
    jz   .fail
    movzx ecx, byte [rax]
    test ecx, ecx
    jz   .fail
    cmp  ecx, USB_HID_MULTI_REPORTS
    ja   .fail
    add  rax, 16
.next:
    mov  dl, [r12]
    cmp  [rax + 1], dl
    jne  .advance
    movzx edx, byte [rax]
    cmp  edx, ebx
    jne  .fail
    jmp  .out
.advance:
    add  rax, USB_HID_MULTI_RECORD
    loop .next
.fail:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

; RDI=physical state,RDX=wire,ECX=length,ESI=owned endpoint sequence.
; Parent.previous is the accepted keyboard union; each ID keeps its own report.
; Only a whole successful common-ring transaction advances either accepted state.
usb_hid_multi_consume:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 64
    mov  r12, rdi
    mov  r13, rdx
    mov  r14d, ecx
    mov  [rsp + 40], esi
    call usb_hid_multi_select
    test rax, rax
    jz   .unselected
    mov  r15, rax
    mov  eax, [rsp + 40]
    mov  [r12 + usb_hid_state.last_sequence], eax
    mov  [r15 + 280], eax
    mov  eax, [r12 + usb_hid_state.generation]
    mov  [r15 + 284], eax
    mov  rdi, r12
    mov  rdx, r13
    mov  ecx, r14d
    mov  rsi, rsp
    cmp  byte [r15 + 5], 2
    je   .mouse
    call usb_hid_report_decode
    test eax, eax
    jz   .fail
    mov  rdi, r12
    call usb_hid_multi_context
    mov  r13, rax
    mov  qword [rsp + 16], 0          ; prospective parent keyboard union
    xor  r14d, r14d                  ; distinct union key count
    lea  rbx, [r13 + 16]
.union_report:
    cmp  byte [rbx + 5], 4
    je   .union_next
    cmp  byte [rbx + 5], 2
    je   .union_next
    lea  r8, [rbx + 272]
    cmp  rbx, r15
    jne  .report_ready
    mov  r8, rsp
.report_ready:
    mov  al, [r8]
    or   [rsp + 16], al
    mov  r9d, 2
.union_key:
    movzx eax, byte [r8 + r9]
    test eax, eax
    jz   .key_next
    cmp  eax, 0x32
    jne  .canonical
    mov  eax, 0x31
.canonical:
    xor  ecx, ecx
.find_key:
    cmp  ecx, r14d
    jae  .new_key
    cmp  [rsp + rcx + 18], al
    je   .key_next
    inc  ecx
    jmp  .find_key
.new_key:
    cmp  r14d, 6
    jae  .fail                       ; refuse entire report; never truncate union
    mov  [rsp + r14 + 18], al
    inc  r14d
.key_next:
    inc  r9d
    cmp  r9d, 8
    jb   .union_key
.union_next:
    add  rbx, USB_HID_MULTI_RECORD
    movzx eax, byte [r13]
    imul eax, USB_HID_MULTI_RECORD
    lea  rax, [r13 + rax + 16]
    cmp  rbx, rax
    jb   .union_report
    mov  rax, [rel usb_hid_repeat_due]
    mov  [rsp + 32], rax
    mov  rax, [rel usb_hid_repeat_owner]
    mov  [rsp + 48], rax
    movzx eax, word [rel usb_hid_repeat_key]
    mov  [rsp + 56], eax
    mov  rdi, r12
    lea  rdx, [rsp + 16]
    call usb_hid_consume_keyboard
    test eax, eax
    jz   .fail
    mov  rax, [rsp]
    mov  [r15 + 272], rax            ; accepted per-ID keys commit with union
    cmp  [rel usb_hid_repeat_owner], r12
    jne  .ok
    cmp  [rsp + 48], r12
    jne  .new_repeat
    movzx eax, word [rel usb_hid_repeat_key]
    cmp  eax, [rsp + 56]
    jne  .new_repeat
    mov  rax, [rel usb_hid_repeat_due]
    cmp  rax, [rsp + 32]
    jne  .new_repeat
    mov  al, [r15 + 1]
    cmp  [r13 + 3], al
    jne  .ok
    movzx edi, byte [rel usb_hid_repeat_key]
    movzx esi, byte [rel usb_hid_repeat_key + 1]
    call usb_hid_set1_to_usage
    mov  rsi, rsp
    call usb_hid_usage_present
    test eax, eax
    jnz  .ok
    mov  qword [rel usb_hid_repeat_owner], 0 ; no repeat transfer to overlapping ID
    jmp  .ok
.new_repeat:
    mov  al, [r15 + 1]
    mov  [r13 + 3], al
.ok:
    mov  eax, 1
    jmp  .out
.mouse:
    call usb_hid_mouse_report_decode
    test eax, eax
    jz   .fail
    mov  edi, [rsp]
    mov  esi, [rsp + 4]
    mov  edx, [rsp + 8]
    mov  ecx, edx
    mov  edx, esi
    mov  esi, edi
    mov  rdi, r12
    call usb_hid_pointer_publish
    inc  qword [rel usb_hid_mouse_reports]
    test eax, eax
    jz   .out                       ; preserve native publication refusal
    jmp  .ok
.fail:
    ; Known malformed keyboard input stops only its own repeat, just as the
    ; single-report path does. Unknown IDs/lengths never reach this branch.
    cmp  byte [r15 + 5], 2
    je   .unselected
    cmp  [rel usb_hid_repeat_owner], r12
    jne  .unselected
    mov  rdi, r12
    call usb_hid_multi_context
    mov  dl, [r15 + 1]
    cmp  [rax + 3], dl
    jne  .unselected
    mov  qword [rel usb_hid_repeat_owner], 0
.unselected:
    xor  eax, eax
.out:
    add  rsp, 64
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=real state, RDX=immutable wire bytes, ECX=exact length,
; RSI=eight-byte normalized output (caller scratch). Out EAX=1/0.
; Only after slot/endpoint/generation/sequence/length ownership was validated.
usb_hid_report_decode:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdx
    mov  r13, rsi
    mov  r14d, ecx
    call usb_hid_report_map_for_wire
    test rax, rax
    jz   .fail
    mov  r15, rax
    movzx eax, byte [r15]
    test eax, eax
    jz   .fail
    cmp  eax, r14d
    jne  .fail
    mov  al, [r15 + 1]
    test al, al
    jz   .unnumbered
    cmp  [r12], al
    jne  .fail
    inc  r12
    dec  r14d
.unnumbered:
    mov  qword [r13], 0
    shl  r14d, 3
    xor  ebx, ebx
    xor  r11d, r11d                  ; normalized key count
.bit:
    cmp  ebx, r14d
    jae  .array
    mov  eax, ebx
    shr  eax, 3
    movzx edx, byte [r12 + rax]
    mov  ecx, ebx
    and  ecx, 7
    shr  edx, cl
    and  edx, 1
    movzx eax, byte [r15 + rbx + 16]
    cmp  eax, 255
    je   .next
    test eax, eax
    jnz  .usage
    test edx, edx
    jnz  .fail                       ; explicit and implicit padding must remain zero
    jmp  .next
.usage:
    test edx, edx
    jz   .next
    cmp  eax, 0xE0
    jb   .key
    sub  eax, 0xE0
    mov  ecx, eax
    mov  eax, 1
    shl  eax, cl
    or   [r13], al
    jmp  .next
.key:
    cmp  r11d, 6
    jae  .fail                       ; existing atomic held-state capacity, no truncation
    mov  [r13 + r11 + 2], al
    inc  r11d
.next:
    inc  ebx
    jmp  .bit
.array:
    movzx ebx, byte [r15 + 3]
    test ebx, ebx
    jz   .ok
    movzx r8d, byte [r15 + 2]
    xor  r9d, r9d
.array_next:
    movzx eax, byte [r12 + r8]
    test eax, eax
    jz   .array_advance
    cmp  eax, 4
    jb   .fail                       ; ErrorRollOver, POSTFail, ErrorUndefined
    cmp  al, [r15 + 4]
    ja   .fail
    cmp  eax, 0x64
    ja   .fail                       ; Application has no existing Set-1 translation
    xor  ecx, ecx
.duplicate:
    cmp  ecx, r11d
    jae  .array_key
    cmp  [r13 + rcx + 2], al
    je   .fail
    inc  ecx
    jmp  .duplicate
.array_key:
    cmp  r11d, 6
    jae  .fail                       ; sparse arrays still share six held-key slots
    mov  [r13 + r11 + 2], al
    inc  r11d
.array_advance:
    inc  r8d
    inc  r9d
    cmp  r9d, ebx
    jb   .array_next
.ok:
    mov  eax, 1
    jmp  .out
.fail:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

usb_hid_init:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 16
    call usb_hid_reset
    lea  rdi, [rel usb_hid_reset]
    call xhci_interrupt_set_reset_hook
    lea  r12, [rel usb_hid_states]
    mov  ecx, USB_HID_MAX_STATES
.check_retired:
    cmp  byte [r12 + usb_hid_state.active], 0
    jne  .discover                    ; boot KAT scratch must not erase custody
    add  r12, usb_hid_state_size
    loop .check_retired
    call usb_hid_reset_detach_kat
    call usb_hid_hostile_kat
.discover:
    call usb_dev_count
    mov  r15d, eax
    xor  ebx, ebx
.device:
    cmp  ebx, r15d
    jae  .done
    call .bind_device
    inc  ebx
    jmp  .device
.done:
    cmp  byte [rel usb_hid_active_count], 2
    jb   .out
    lea  rdi, [rel str_usb_hid_ready]
    call serial_string
.out:
    add  rsp, 16
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
; Shared one-device binder. RBX=index; independent descriptor scratch, never
; reset class state or enumerate peers. Extra eight bytes preserve call alignment.
.bind_device:
    sub  rsp, 24
    mov  edi, ebx
    call usb_hid_owned_block_index
    test eax, eax
    jnz .next
    mov  edi, ebx
    call usb_dev_is_null
    test eax, eax
    jnz  .next
    mov  edi, ebx
    call usb_dev_hc
    test rax, rax
    jz   .next
    mov  r12, rax
    mov  edi, ebx
    call usb_dev_addr
    test eax, eax
    jz   .next
    mov  r13d, eax
    mov  edi, ebx
    call usb_dev_topo_ptr
    test rax, rax
    jz   .next
    movzx edx, byte [rax + usb_topo.speed]
    mov  [rsp], edx
    mov  rdi, r12
    mov  esi, r13d
    call usb_hid_fetch_config
    test eax, eax
    jz   .next
    mov  r14d, eax
    cmp  byte [rel usb_hid_config + 5], 1
    jne  .next                      ; this rung's bounded SET_CONFIGURATION(1)
    mov  dword [rsp + 4], 9          ; descriptor cursor, not interface-number ordering
    mov  byte [rsp + 8], 0           ; one SET_CONFIGURATION per device
.interface_loop:
    mov  ecx, [rsp + 4]
    cmp  ecx, r14d
    jae  .next
    lea  rdi, [rel usb_hid_config]
    mov  esi, r14d
    mov  edx, [rsp]
    call usb_hid_scan_config_at
    test eax, eax
    jz   .next
    mov  [rsp + 4], eax
    cmp  byte [rel usb_hid_kbd_candidate], 1
    je   .set_config
    cmp  byte [rel usb_hid_mouse_candidate], 1
    je   .set_config
    cmp  byte [rel usb_hid_report_candidate], 1
    jne  .interface_loop
.set_config:
    call usb_hid_alloc_state
    test rax, rax
    jnz  .capacity_ready
    inc  qword [rel usb_hid_capacity_refusals]
    jmp  .interface_loop            ; live and retired states retain their custody
.capacity_ready:
    cmp  dword [rsp], USB_SPEED_SUPER
    jne  .backend_ready
    mov  rax, [r12 + dev.ops]
    cmp  qword [rax + usbhc_ops.configure_ep_ss], 0
    je   .next                      ; capability before SET_CONFIGURATION/class effects
.backend_ready:
    cmp  byte [rsp + 8], 1
    je   .bind
    mov  rdi, r12
    mov  esi, r13d
    mov  edx, USB_REQ_SET_CONFIGURATION
    mov  ecx, 1
    xor  r8d, r8d
    xor  r9d, r9d
    call usb_hid_control_nodata
    test rax, rax
    jnz  .next
    mov  byte [rsp + 8], 1
.bind:
    cmp  byte [rel usb_hid_kbd_candidate], 1
    jne  .report_keyboard
    mov  rdi, r12
    mov  esi, r13d
    mov  edx, USB_HID_KIND_KBD
    movzx ecx, byte [rel usb_hid_kbd_interface]
    lea  r8, [rel usb_hid_kbd_ep]
    mov  r9d, [rsp]
    mov  r10d, 13
    call usb_hid_configure_census_bounded
    jmp  .bind_result
.report_keyboard:
    cmp  byte [rel usb_hid_report_candidate], 1
    jne  .mouse
    mov  rdi, r12
    mov  esi, r13d
    call usb_hid_report_fetch
    test eax, eax
    jz   .refused
.report_bind:
    mov  rdi, r12
    mov  esi, r13d
    mov  edx, USB_HID_KIND_REPORT
    movzx ecx, byte [rel usb_hid_report_interface]
    lea  r8, [rel usb_hid_report_ep]
    mov  r9d, [rsp]
    mov  r10d, 13
    call usb_hid_configure_census_bounded
    jmp  .bind_result
.mouse:
    cmp  byte [rel usb_hid_mouse_candidate], 1
    jne  .interface_loop
    mov  rdi, r12
    mov  esi, r13d
    mov  edx, USB_HID_KIND_MOUSE
    movzx ecx, byte [rel usb_hid_mouse_interface]
    lea  r8, [rel usb_hid_mouse_ep]
    mov  r9d, [rsp]
    mov  r10d, 13
    call usb_hid_configure_census_bounded
.bind_result:
    test rax, rax
    jz   .interface_loop
.refused:
    inc  qword [rel usb_hid_interface_refusals] ; API/profile refusal never accepts a state
    jmp  .interface_loop
.next:
    add  rsp, 24
    ret

; EDI=refreshed inventory index. Reuse the boot binder without its reset/KATs
; or whole-inventory walk. All supported interfaces share one configuration.
usb_hid_bind_device:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 16
    mov  ebx, edi
    call usb_hid_init.bind_device
    add  rsp, 16
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Four bounded tombstones: hc qword, generation dword, port byte, active byte.
; Only successful backend root retirement earns one. No arbitrary port scan,
; child-hub rebinding, or access to another class's live port is introduced.
usb_hid_reconnect_reset:
    lea  rdi, [rel usb_hid_reconnect_roots]
    mov  ecx, USB_HID_MAX_STATES * 2
    xor  eax, eax
    rep  stosq
    mov  dword [rel usb_hid_reconnect_cursor], 0
    mov  dword [rel usb_hid_reconnect_passes], 0
    mov  dword [rel usb_hid_discovery_passes], 0
    ret

; RDI=old class state, after confirmed Disable Slot and before class release.
usb_hid_reconnect_note:
    mov  r8, [rdi + usb_hid_state.hc]
    movzx r9d, byte [rdi + usb_hid_state.port]
    mov  r10d, [rdi + usb_hid_state.generation]
    lea  rax, [rel usb_hid_reconnect_roots]
    xor  edx, edx
    mov  ecx, USB_HID_MAX_STATES
.next:
    cmp  byte [rax + 13], 1
    jne  .free
    cmp  [rax], r8
    jne  .advance
    cmp  [rax + 12], r9b
    je   .record
    jmp  .advance
.free:
    test rdx, rdx
    cmovz rdx, rax
.advance:
    add  rax, 16
    loop .next
    mov  rax, rdx
    test rax, rax
    jz   .out
.record:
    mov  [rax], r8
    mov  [rax + 8], r10d
    mov  [rax + 12], r9b
    mov  byte [rax + 13], 1
.out:
    ret

; Resident-only bounded reconnect work. Release queues have already been polled.
; One remembered root per backoff, round-robin; no global init/reset or task spawn.
usb_hid_reconnect_tick:
    inc  dword [rel usb_hid_reconnect_passes]
    cmp  dword [rel usb_hid_reconnect_passes], USB_HID_RECONNECT_BACKOFF
    jb   .out
    mov  dword [rel usb_hid_reconnect_passes], 0
    push rbx
    push r12
    push r13
    mov  eax, [rel usb_hid_reconnect_cursor]
    mov  edx, eax
    inc  edx
    and  edx, USB_HID_MAX_STATES - 1
    mov  [rel usb_hid_reconnect_cursor], edx
    shl  eax, 4
    lea  rbx, [rel usb_hid_reconnect_roots]
    add  rbx, rax
    cmp  byte [rbx + 13], 1
    jne  .done
    mov  r12, [rbx]
    movzx r13d, byte [rbx + 12]
    mov  rdi, r12
    call xhci_hc_generation
    cmp  eax, [rbx + 8]
    jne  .forget
    mov  rdi, r12
    mov  esi, r13d
    call usb_hid_port_owned
    test eax, eax
    jnz  .done                      ; bound/pending release custody always wins
    mov rdi,r12
    mov esi,r13d
    call usb_hid_owned_block_root
    test eax,eax
    jnz .done
    mov  rax, [r12 + dev.ops]
    mov  rdi, r12
    mov  esi, r13d
    call [rax + usbhc_ops.port_status]
    test eax, USB_PORT_CONNECT
    jnz  .refresh
    ; A refused/unsupported replacement may have acquired EP0. Retire it on
    ; observed removal too; failed retirement keeps DMA quarantined in backend.
    mov  rdi, r12
    mov  esi, r13d
    call xhci_hid_root_retire
    test eax, eax
    jnz  .forget
    jmp  .done
.refresh:
    mov  rdi, r12
    mov  esi, r13d
    call usb_dev_refresh_root
    test eax, eax
    jz   .done
    lea  edi, [eax - 1]
    call usb_hid_bind_device
    mov  rdi, r12
    mov  esi, r13d
    call usb_hid_port_owned
    test eax, eax
    jz   .done                      ; descriptor/class/capacity refusal can retry
.forget:
    mov  byte [rbx + 13], 0
.done:
    pop  r13
    pop  r12
    pop  rbx
.out:
    ret

; One unknown root, then one unused configured-hub port per backoff while
; a class state is free. Pending releases retain capacity; existing devices
; (including storage and unsupported peers) are never reset/re-enumerated.
usb_hid_discovery_tick:
    inc  dword [rel usb_hid_discovery_passes]
    cmp  dword [rel usb_hid_discovery_passes], USB_HID_RECONNECT_BACKOFF
    jb   .out
    mov  dword [rel usb_hid_discovery_passes], 0
    lea  rax, [rel usb_hid_states]
    mov  ecx, USB_HID_MAX_STATES
.free:
    cmp  byte [rax + usb_hid_state.active], 0
    je   .probe
    add  rax, usb_hid_state_size
    loop .free
    ret
.probe:
    sub  rsp, 8
    call usb_dev_probe_next_root
    test eax, eax
    jnz  .bind
    call usb_dev_probe_next_hub_port
    test eax, eax
    jz   .done
.bind:
    lea  edi, [eax - 1]
    call usb_hid_bind_device
.done:
    add  rsp, 8
.out:
    ret

; C3: native binder provenance wrapper. Other direct test/explicit configure
; entries retain unknown interface identity instead of borrowing stale config.
usb_hid_configure_census_bounded:
    mov byte [rel usb_hid_census_pending],1
    sub rsp,8
    call usb_hid_configure_interface_bounded
    add rsp,8
    mov byte [rel usb_hid_census_pending],0
    ret

; RBX=successfully published state. Copy actual selected interface bytes from
; the binder's validated configuration before the shared scratch is reused.
; This is observational sidecar state only; no ABI/layout or ownership change.
usb_hid_census_record:
    push rbx
    push r12
    sub rsp,8
    mov r12,rbx
    lea rax,[rel usb_hid_states]
    sub rbx,rax
    mov rax,rbx
    xor edx,edx
    mov ecx,usb_hid_state_size
    div rcx
    lea rbx,[rel usb_hid_census_interfaces]
    lea rbx,[rbx+rax*4]
    mov dword [rbx],0
    cmp byte [rel usb_hid_census_pending],1
    jne .done
    lea rdi,[rel usb_hid_config]
    movzx esi,word [rdi+2]
    cmp esi,USB_HID_CONFIG_CAP
    ja .done
    cmp esi,9
    jb .done
    xor ecx,ecx
.walk:
    mov eax,esi
    sub eax,ecx
    cmp eax,2
    jb .done
    movzx eax,byte [rdi+rcx]
    cmp eax,2
    jb .done
    lea edx,[rcx+rax]
    cmp edx,esi
    ja .done
    cmp byte [rdi+rcx+1],USB_DT_INTERFACE
    jne .next
    cmp eax,9
    jb .done
    mov al,[r12+usb_hid_state.interface]
    cmp [rdi+rcx+2],al
    jne .next
    cmp byte [rdi+rcx+3],0
    jne .next
    movzx eax,byte [rdi+rcx+5]
    shl eax,16
    movzx edx,byte [rdi+rcx+6]
    shl edx,8
    or eax,edx
    movzx edx,byte [rdi+rcx+7]
    or eax,edx
    or eax,0x80000000
    mov [rbx],eax
    jmp .done
.next:
    mov ecx,edx
    jmp .walk
.done:
    add rsp,8
    pop r12
    pop rbx
    ret

; C3 cached state prefix + HC pointer + actual interface class24 in 32B output.
; Pointer is internal join-only: the owner report never serializes addresses.
usb_hid_census_snapshot:
    mov qword [rsi],0
    mov qword [rsi+8],0
    mov qword [rsi+16],0
    mov qword [rsi+24],-1
    dec edi
    cmp edi,USB_HID_MAX_STATES
    jae .none
    imul eax,edi,usb_hid_state_size
    lea r8,[rel usb_hid_states]
    add r8,rax
    movzx ecx,byte [r8+usb_hid_state.active]
    dec ecx
    cmp ecx,1
    ja .none
    mov rax,[r8]
    mov [rsi],rax
    mov rax,[r8+8]
    mov [rsi+8],rax
    mov rax,[r8+usb_hid_state.hc]
    mov [rsi+16],rax
    lea r8,[rel usb_hid_census_interfaces]
    mov eax,[r8+rdi*4]
    test eax,0x80000000
    jz .known_state
    and eax,0xffffff
    mov [rsi+24],eax
.known_state:
    mov eax,1
    ret
.none:
    xor eax,eax
    ret

; usb_hid_binding_snapshot(EDI=state ordinal1..4, RSI=16-byte output) -> EAX1/0.
; Cached cooperative-BSP observation only: no controller/device calls or state writes.
; Public record is active/kind/port/interface/ep/slot/protocol/wire_len bytes,
; then generation and last_sequence u32. No pointers, reports or key state.
; Inactive/invalid records are zero; active2 retains pending-release custody.
usb_hid_binding_snapshot:
    test rsi, rsi
    jz   .none
    mov  qword [rsi], 0
    mov  qword [rsi + 8], 0
    dec  edi
    cmp  edi, USB_HID_MAX_STATES
    jae  .none
    imul eax, edi, usb_hid_state_size
    lea  r8, [rel usb_hid_states]
    add  r8, rax
    movzx ecx, byte [r8 + usb_hid_state.active]
    dec  ecx
    cmp  ecx, 1
    ja   .none
    mov  rax, [r8]
    mov  rdx, [r8 + 8]
    mov  [rsi], rax
    mov  [rsi + 8], rdx
    mov  eax, 1
    ret
.none:
    xor  eax, eax
    ret

; usb_hid_port_owned(RDI=hc dev*, ESI=root port) -> EAX 1 when a bound or
;   retired-pending HID state holds that controller/port. Read-only; lets a later class
;   binder (dev/blk/usb_msd) never take a device HID already owns. Clobbers RCX.
usb_hid_port_owned:
    lea  rax, [rel usb_hid_states]
    mov  ecx, USB_HID_MAX_STATES
.next:
    cmp  byte [rax + usb_hid_state.active], 0
    je   .advance
    cmp  [rax + usb_hid_state.hc], rdi
    jne  .advance
    cmp  [rax + usb_hid_state.port], sil
    jne  .advance
    mov  eax, 1
    ret
.advance:
    add  rax, usb_hid_state_size
    dec  ecx
    jnz  .next
    xor  eax, eax
    ret

; usb_hid_find_state_kind(EDI=kind) -> RAX=active state / 0.
usb_hid_find_state_kind:
    lea  rax, [rel usb_hid_states]
    mov  ecx, USB_HID_MAX_STATES
.next:
    cmp  byte [rax + usb_hid_state.active], 1
    jne  .advance
    cmp  byte [rax + usb_hid_state.kind], dil
    je   .found
.advance:
    add  rax, usb_hid_state_size
    loop .next
    xor  eax, eax
.found:
    ret

; usb_hid_kind_live(EDI=kind) -> EAX=1 when an active bound interface of that
; kind exists AND the resident class consumer task is dispatching (the path
; that feeds the shared scancode ring / pointer post ring), else 0. Read-only
; boot-timeline predicate; clobbers RCX,RDX.
usb_hid_kind_live:
    cmp  byte [rel usb_hid_task_running], 1
    jne  .no
    cmp  edi, USB_HID_KIND_KBD
    je   .scan
    cmp  edi, USB_HID_KIND_MOUSE
    jne  .no
.scan:
    lea  rax, [rel usb_hid_states]
    lea  rdx, [rel usb_hid_multi_states]
    mov  ecx, USB_HID_MAX_STATES
.next:
    cmp  byte [rax + usb_hid_state.active], 1
    jne  .advance
    cmp  byte [rax + usb_hid_state.protocol], 3
    jne  .single
    cmp  edi, USB_HID_KIND_KBD
    jne  .mouse
    cmp  byte [rdx + 2], 1
    je   .yes
    jmp  .advance
.mouse:
    cmp  byte [rdx + 4], 1
    je   .yes
    jmp  .advance
.single:
    cmp  [rax + usb_hid_state.kind], dil
    je   .yes
.advance:
    add  rax, usb_hid_state_size
    add  rdx, USB_HID_MULTI_SIZE
    loop .next
.no:
    xor  eax, eax
    ret
.yes:
    mov  eax, 1
    ret

; Poll one endpoint through Task2903.  The endpoint seam copies immutable bytes
; and metadata, clears ownership, and requeues before this consumer is called.
usb_hid_poll_state:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    cmp  byte [r12 + usb_hid_state.active], 2
    je   .release                    ; no old HC dereference while retiring
    cmp  byte [r12 + usb_hid_state.active], 1
    jne  .none
    mov  rdi, [r12 + usb_hid_state.hc]
    call xhci_hc_generation          ; this state's own controller (RCQ-09 multi-instance)
    cmp  eax, [r12 + usb_hid_state.generation]
    jne  .release
    mov  rbx, [r12 + usb_hid_state.ops]
    mov  rdi, [r12 + usb_hid_state.hc]
    movzx esi, byte [r12 + usb_hid_state.port]
    call [rbx + usbhc_ops.port_status]
    test eax, USB_PORT_CONNECT
    jnz  .connected
    mov  rdi, [r12 + usb_hid_state.hc]
    movzx esi, byte [r12 + usb_hid_state.port]
    call xhci_hid_root_retire         ; confirmed disable before endpoint storage reuse
    test eax, eax
    jnz  .release                    ; failed retirement cannot earn a rebind
    test edx, edx
    jnz  .child_retired              ; child teardown never earns a root record
    mov  rdi, r12
    call usb_hid_reconnect_note
    jmp  .release
.connected:
    ; One selected class state per 64 poll passes, round-robin. Root states
    ; return unknown without I/O; downstream checks never run on every pass.
    mov  rax, [rel usb_hid_poll_ticks]
    test al, 63
    jnz  .consume
    shr  rax, 6
    and  eax, USB_HID_MAX_STATES - 1
    imul rax, usb_hid_state_size
    lea  rdx, [rel usb_hid_states]
    add  rax, rdx
    cmp  rax, r12
    jne  .consume
    mov  rdi, [r12 + usb_hid_state.hc]
    movzx esi, byte [r12 + usb_hid_state.port]
    call xhci_hid_child_connected
    test eax, eax
    jnz  .consume                    ; connected or unknown keeps custody
    mov  rdi, [r12 + usb_hid_state.hc]
    movzx esi, byte [r12 + usb_hid_state.port]
    call xhci_hid_root_retire
    test eax, eax
    jnz  .release                    ; unconfirmed child disable keeps its row
.child_retired:
    ; Confirmed child Disable Slot frees only that inventory route for live
    ; hub discovery; a child still never earns a root reconnect record.
    mov  rdi, [r12 + usb_hid_state.hc]
    movzx esi, byte [r12 + usb_hid_state.port]
    call usb_dev_release_child
    jmp  .release
.consume:
    lea  r13, [r12 + usb_hid_state.report]
    cmp  byte [r12 + usb_hid_state.protocol], 0
    je  .wire_ready
    mov  rdi, r12
    call usb_hid_report_buffer_for_state
    test rax, rax
    jz   .release
    mov  r13, rax
.wire_ready:
    mov  rdi, [r12 + usb_hid_state.hc]
    movzx esi, byte [r12 + usb_hid_state.port]
    movzx edx, byte [r12 + usb_hid_state.ep_addr]
    mov  rcx, r13
    mov  r8d, USB_HID_KBD_REPORT_LEN
    cmp  byte [r12 + usb_hid_state.protocol], 0
    je  .cap_ready
    movzx r8d, byte [r12 + usb_hid_state.wire_len]
.cap_ready:
    lea  r9, [r12 + usb_hid_state.meta]
    call [rbx + usbhc_ops.interrupt_in_poll]
    test rax, rax
    js   .none
    mov  ecx, eax
    mov  rdi, r12
    lea  rsi, [r12 + usb_hid_state.meta]
    mov  rdx, r13
    mov  [rel usb_hid_obs_live_state], r12
    call usb_hid_consume_interrupt
    mov  qword [rel usb_hid_obs_live_state], 0
    jmp  .out
.release:
    mov  rdi, r12
    call usb_hid_release_state
.none:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

usb_hid_poll_all:
    push rbx
    inc  qword [rel usb_hid_poll_ticks]      ; INPUTSTAT: poll passes (rate = dticks/dt)
    lea  rbx, [rel usb_hid_states]
    mov  ecx, USB_HID_MAX_STATES
.next:
    push rcx
    mov  rdi, rbx
    call usb_hid_poll_state
    pop  rcx
    add  rbx, usb_hid_state_size
    loop .next
    call hid_pointer_cancel_tick
    pop  rbx
    jmp  usb_hid_repeat_tick             ; after this pass's reports (a release cancels first)

; Software typematic, driven only by the existing HID poll pass (usb_hid_task /
; boot proof). At most one repeat per pass and never a catch-up burst; the make
; goes through the same kbd ring producer as PS/2 hardware typematic.
; Clock loss/regression or unrepresentable next deadline cancels this press;
; only a fresh committed make may arm a new bounded initial delay.
usb_hid_repeat_tick:
    mov  rax, [rel usb_hid_repeat_owner]
    test rax, rax
    jz   .out
    cmp  byte [rax + usb_hid_state.active], 1
    jne  .cancel
    call time_monotonic_now_us           ; RAX us; 0 = no calibrated TSC
    test rax, rax
    jz   .cancel                         ; unavailable/zero clock invalidates this press
    cmp  rax, [rel usb_hid_repeat_last]
    jb   .cancel                         ; monotonic regression invalidates this press
    mov  [rel usb_hid_repeat_last], rax    ; include nondue polls in regression detection
    cmp  rax, [rel usb_hid_repeat_due]
    jb   .out
    mov  rcx, [rel usb_hid_repeat_due]
    mov  rdx, rax
    sub  rdx, rcx                        ; now >= due: unsigned lateness cannot wrap
    cmp  rdx, USB_HID_REPEAT_PERIOD_US
    jb   .advance                       ; retain cadence when less than one period late
    mov  rcx, rax                       ; late pass: next one period from now
.advance:
    add  rcx, USB_HID_REPEAT_PERIOD_US
    jc   .cancel                         ; checked for both due and late-now bases
    mov  [rel usb_hid_repeat_due], rcx
    jmp  usb_hid_held_repeat_publish
.out:
    ret
.cancel:
    mov  qword [rel usb_hid_repeat_owner], 0
    mov  qword [rel usb_hid_repeat_due], 0
    mov  qword [rel usb_hid_repeat_last], 0
    ret

; usb_hid_repeat_note(RDI=state): after a committed report batch. The last make
; in the batch is the newest press: any newest press (a modifier or lock too,
; as with PS/2 typematic) stops the old repeat and arms a new one only for a
; repeatable key. Otherwise the repeating key's own break stops it.
usb_hid_repeat_note:
    xor  r8d, r8d                        ; last make: 0x10000 | E0<<8 | code; Pause=0x20000
    xor  r9d, r9d                        ; R9D: E0 prefix pending
    xor  r10d, r10d                      ; bounded E1 suffix bytes remaining
    xor  ecx, ecx
    lea  rsi, [rel usb_hid_scancode_batch]
.scan:
    cmp  cl, [rel usb_hid_batch_count]
    jae  .scanned
    movzx eax, byte [rsi + rcx]
    inc  ecx
    test r10d, r10d
    jz   .prefix
    dec  r10d
    jmp  .scan
.prefix:
    cmp  al, 0xE1
    je   .pause
    cmp  al, 0xE0
    jne  .code
    mov  r9d, 1
    jmp  .scan
.pause:
    mov  r10d, 5                    ; skip Pause suffix: never Ctrl/NumLock
    xor  r9d, r9d
    mov  r8d, 0x20000                ; newest make cancels repeat, never arms one
    jmp  .scan
.code:
    test al, 0x80
    jnz  .break
    mov  r8d, r9d
    shl  r8d, 8
    or   r8d, eax
    or   r8d, 0x10000
    xor  r9d, r9d
    jmp  .scan
.break:
    cmp  [rel usb_hid_repeat_owner], rdi
    jne  .break_done
    and  eax, 0x7F
    mov  edx, r9d
    shl  edx, 8
    or   edx, eax                        ; E0<<8 | code of this break
    cmp  dx, [rel usb_hid_repeat_key]
    jne  .break_done
    mov  qword [rel usb_hid_repeat_owner], 0 ; the repeating key was released
.break_done:
    xor  r9d, r9d
    jmp  .scan
.scanned:
    test r8d, r8d
    jz   .out
    mov  qword [rel usb_hid_repeat_owner], 0 ; a newer press ends the old repeat
    cmp  r8d, 0x20000
    je   .out
    mov  eax, r8d
    and  eax, 0x1FF                      ; E0<<8 | code
    lea  rsi, [rel usb_hid_repeat_never]
.never:
    movzx edx, word [rsi]
    test edx, edx
    jz   .repeatable
    cmp  eax, edx
    je   .out                            ; modifier, Win, lock key, PrintScreen
    add  rsi, 2
    jmp  .never
.repeatable:
    push rdi
    push r8
    call time_monotonic_now_us
    pop  r8
    pop  rdi
    test rax, rax
    jz   .out                            ; no calibrated clock: no typematic
    mov  rcx, rax
    add  rax, USB_HID_REPEAT_DELAY_US
    jc   .out                            ; no owner if initial delay cannot fit
    mov  [rel usb_hid_repeat_last], rcx
    mov  [rel usb_hid_repeat_due], rax
    mov  [rel usb_hid_repeat_key], r8w   ; E0<<8 | code
    mov  [rel usb_hid_repeat_owner], rdi
.out:
    ret

; Append one byte to the transaction-local scancode batch.
usb_hid_batch_byte:
    movzx ecx, byte [rel usb_hid_batch_count]
    cmp  ecx, 32
    jae  .fail
    lea  rdx, [rel usb_hid_scancode_batch]
    mov  [rdx + rcx], al
    inc  byte [rel usb_hid_batch_count]
    mov  eax, 1
    ret
.fail:
    xor  eax, eax
    ret

; Translate a usage and append its complete Set-1 make/break sequence.
; In AL=usage, DL=0 make / 1 break, CL=current boot-report modifiers.
; Out EAX=1 appended / 0 unsupported/full. PrintScreen uses post-transition
; modifiers for both edges; every alias maps to the same semantic key.
usb_hid_append_usage:
    push rbx
    push r12
    push r13
    movzx ebx, al
    mov  r12b, dl
    cmp  ebx, 255
    ja   .fail
    cmp  ebx, 0x46                   ; PrintScreen has modifier-dependent sequences
    je   .print
    cmp  ebx, 0x48                   ; Pause has one six-byte make and no break
    je   .pause
    lea  rax, [rel usb_hid_to_scancode]
    mov  al, [rax + rbx]
    test al, al
    jz   .fail
    mov  r13b, al
    xor  ecx, ecx
    cmp  ebx, 0x49                   ; Insert..Up are E0-prefixed
    jb   .keypad_extended
    cmp  ebx, 0x52
    jbe  .extended
.keypad_extended:
    cmp  ebx, 0x54                   ; keypad slash
    je   .extended
    cmp  ebx, 0x58                   ; keypad enter
    jne  .emit_code
.extended:
    mov  al, 0xE0
    call usb_hid_batch_byte
    test eax, eax
    jz   .fail
.emit_code:
    mov  al, r13b
    test r12b, r12b
    jz   .append
    or   al, 0x80
.append:
    call usb_hid_batch_byte
    test eax, eax
    jz   .fail
    mov  eax, 1
    jmp  .out
.print:
    ; Microsoft Keyboard Scan Code Specification 1.3a p22, note 4.
    ; Alt takes precedence over Shift/Ctrl. Fake shifts belong only to the
    ; ordinary form; reserve its entire sequence before touching the batch.
    mov  ebx, 4
    mov  r13d, 0x37E02AE0             ; E0 2A E0 37 (little endian)
    test r12b, r12b
    jz   .print_mods
    mov  r13d, 0xAAE0B7E0             ; E0 B7 E0 AA
.print_mods:
    test cl, 0x44                     ; either Alt
    jnz  .print_alt
    test cl, 0x33                     ; either Ctrl or Shift
    jz   .print_admit
    mov  ebx, 2
    mov  r13d, 0x37E0                 ; E0 37
    test r12b, r12b
    jz   .print_admit
    mov  r13d, 0xB7E0                 ; E0 B7
    jmp  .print_admit
.print_alt:
    mov  ebx, 1
    mov  r13d, 0x54                   ; SysRq
    test r12b, r12b
    jz   .print_admit
    mov  r13d, 0xD4
.print_admit:
    movzx ecx, byte [rel usb_hid_batch_count]
    lea  eax, [rcx + rbx]
    cmp  eax, 32                     ; all or none, including fake-shift suffix
    ja   .fail
    lea  rdx, [rel usb_hid_scancode_batch]
    cmp  ebx, 4
    je   .print_four
    cmp  ebx, 2
    je   .print_two
    mov  [rdx + rcx], r13b
    jmp  .print_done
.print_four:
    mov  [rdx + rcx], r13d
    jmp  .print_done
.print_two:
    mov  [rdx + rcx], r13w
.print_done:
    mov  [rel usb_hid_batch_count], al
    mov  eax, 1
    jmp  .out
.pause:
    test r12b, r12b
    jnz  .pause_ok                   ; Set-1 Pause is make-only; remember release
    movzx ecx, byte [rel usb_hid_batch_count]
    cmp  ecx, 26                    ; preflight all six before any batch write
    ja   .fail
    mov  al, 0xE1
    call usb_hid_batch_byte
    mov  al, 0x1D
    call usb_hid_batch_byte
    mov  al, 0x45
    call usb_hid_batch_byte
    mov  al, 0xE1
    call usb_hid_batch_byte
    mov  al, 0x9D
    call usb_hid_batch_byte
    mov  al, 0xC5                   ; final Pause suffix
    call usb_hid_batch_byte
.pause_ok:
    mov  eax, 1
    jmp  .out
.fail:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; RCQ-38 L0: the inverse of usb_hid_append_usage for one make.
; usb_hid_set1_to_usage(EDI=Set-1 make 0x01..0x7F, ESI=nonzero when E0-prefixed)
; -> EAX = the lowest page-7 usage of that semantic make, 0 = none
; (modifiers, Pause, breaks and unmapped codes). PrintScreen terminal E0 37
; and plain SysRq 54 both map to usage46; fake shifts do not map.
; Clobbers RAX, RCX, RDX, RSI, R8.
usb_hid_set1_to_usage:
    xor  eax, eax
    test esi, esi
    setnz al
    mov  esi, eax
    xor  eax, eax
    test edi, edi
    jz   .out
    cmp  edi, 0x7F
    ja   .out
    cmp  edi, 0x54                   ; plain Alt+PrintScreen / SysRq alias
    jne  .table
    test esi, esi
    jnz  .out
    mov  eax, 0x46
    ret
.table:
    lea  r8, [rel usb_hid_to_scancode]
    mov  ecx, 1
.scan:
    movzx edx, byte [r8 + rcx]
    cmp  edx, edi
    jne  .next
    xor  edx, edx
    cmp  ecx, 0x46                   ; PrintScreen
    je   .extended
    cmp  ecx, 0x49                   ; Insert..Up
    jb   .keypad
    cmp  ecx, 0x52
    jbe  .extended
.keypad:
    cmp  ecx, 0x54                   ; keypad slash
    je   .extended
    cmp  ecx, 0x58                   ; keypad enter
    jne  .match
.extended:
    mov  edx, 1
.match:
    cmp  edx, esi
    je   .found
.next:
    inc  ecx
    cmp  ecx, 256
    jb   .scan
    ret
.found:
    mov  eax, ecx
.out:
    ret

; Return EAX=1 when AL occurs in the six usage slots at RSI.
usb_hid_usage_present:
    mov  dl, al
    cmp  dl, 0x32
    jne  .canonical
    mov  dl, 0x31
.canonical:
    mov  ecx, 6
.next:
    mov  al, [rsi + rcx + 1]         ; slots 2..7
    cmp  al, 0x32
    jne  .compare
    mov  al, 0x31
.compare:
    cmp  al, dl
    je   .yes
    loop .next
    xor  eax, eax
    ret
.yes:
    mov  eax, 1
    ret

; Other USB keyboards' accepted modifier union (RDI excluded), EAX out.
; The PS/2 ring labels both IRQ1 and USB as KO_HUMAN; this USB union cannot
; distinguish a concurrently held PS/2 key. Never clear the global parser.
usb_hid_held_modifiers:
    lea  rsi, [rel usb_hid_states]
    mov  ecx, USB_HID_MAX_STATES
    xor  eax, eax
.next:
    cmp  rsi, rdi
    je   .advance
    cmp  byte [rsi + usb_hid_state.active], 0
    je   .advance
    cmp  byte [rsi + usb_hid_state.kind], USB_HID_KIND_KBD
    jne  .advance
    or   al, [rsi + usb_hid_state.previous]
.advance:
    add  rsi, usb_hid_state_size
    loop .next
    ret

; AL usage, RDI excluded state -> EAX present in another accepted USB report.
; Pause is make-only, so each device's fresh press remains an independent pulse.
usb_hid_held_other_usage:
    cmp  al, 0x48
    je   .no
    push rbx
    push r12
    push r13
    movzx r12d, al
    mov  r13, rdi
    lea  rbx, [rel usb_hid_states]
.next:
    cmp  rbx, r13
    je   .advance
    cmp  byte [rbx + usb_hid_state.active], 0
    je   .advance
    cmp  byte [rbx + usb_hid_state.kind], USB_HID_KIND_KBD
    jne  .advance
    mov  eax, r12d
    lea  rsi, [rbx + usb_hid_state.previous]
    call usb_hid_usage_present
    test eax, eax
    jnz  .out
.advance:
    add  rbx, usb_hid_state_size
    lea  rax, [rel usb_hid_states + USB_HID_MAX_STATES * usb_hid_state_size]
    cmp  rbx, rax
    jb   .next
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret
.no:
    xor  eax, eax
    ret

; AL usage, RSI report, EBX current slot -> EAX semantic alias before slot.
; Avoid two copies of 2B when the same accepted report contains both 31/32.
usb_hid_held_prior:
    mov  dl, al
    cmp  dl, 0x32
    jne  .canonical
    mov  dl, 0x31
.canonical:
    mov  ecx, 2
.next:
    cmp  ecx, ebx
    jae  .no
    mov  al, [rsi + rcx]
    cmp  al, 0x32
    jne  .compare
    mov  al, 0x31
.compare:
    cmp  al, dl
    je   .yes
    inc  ecx
    jmp  .next
.no:
    xor  eax, eax
    ret
.yes:
    mov  eax, 1
    ret

; Cancel the repeat owner when its key leaves its physical report but another
; USB device suppresses the aggregate break. No repeat transfer/fallback.
usb_hid_held_repeat_release:
    cmp  [rel usb_hid_repeat_owner], rdi
    jne  .out
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rdx
    movzx edi, byte [rel usb_hid_repeat_key]
    movzx esi, byte [rel usb_hid_repeat_key + 1]
    call usb_hid_set1_to_usage
    mov  ebx, eax
    mov  rsi, r13
    call usb_hid_usage_present
    test eax, eax
    jnz  .done
    mov  eax, ebx
    mov  rdi, r12
    call usb_hid_held_other_usage
    test eax, eax
    jz   .done                       ; normal emitted break handled by repeat_note
    mov  qword [rel usb_hid_repeat_owner], 0
.done:
    pop  r13
    pop  r12
    pop  rbx
.out:
    ret

; Repeat's E0 pair also shares IRQ1's producer. Preserve the half-ring
; reserve and publish under one interrupt mask, without using the report batch.
usb_hid_held_repeat_publish:
    pushfq
    cli
    movzx edx, word [rel usb_hid_repeat_key]
    shr  edx, 8                          ; 1 for an E0 key
    movzx ecx, byte [rel kbd_count]
    lea  ecx, [ecx + edx + 1]
    cmp  ecx, KBD_RING_LEN - USB_HID_REPEAT_RESERVE
    ja   .out                            ; consumer behind: skip, keep release room
    test edx, edx
    jz   .code
    mov  al, 0xE0
    call ps2_kbd_push_scancode
.code:
    mov  al, [rel usb_hid_repeat_key]
    call ps2_kbd_push_scancode
.out:
    popfq
    ret

; Whole common-ring transaction. IRQ1 shares this producer: capacity check
; and every byte must be under the same saved interrupt mask. No yield here.
usb_hid_held_commit:
    push rbx
    pushfq
    cli
    movzx eax, byte [rel kbd_count]      ; occupancy, not the circular write index
    movzx ecx, byte [rel usb_hid_batch_count]
    add  eax, ecx
    cmp  eax, KBD_RING_LEN
    ja   .malformed
    xor  ebx, ebx
.commit_loop:
    cmp  bl, [rel usb_hid_batch_count]
    jae  .remember
    lea  rax, [rel usb_hid_scancode_batch]
    mov  al, [rax + rbx]
    cmp  byte [rel usb_hid_retiring], 0
    jne  .retired
    call ps2_kbd_push_scancode
    inc  ebx
    jmp  .commit_loop
.retired:
    call ps2_kbd_push_retired
    inc  ebx
    jmp  .commit_loop
.remember:
    mov  eax, 1
    jmp  .out
.malformed:
    xor  eax, eax
.out:
    popfq
    pop  rbx
    ret

; Strict 8-byte boot-keyboard decode.  Validation builds a private transaction
; first, so a rollover, duplicate usage, unsupported usage, or full common ring
; cannot partially advance kbd_head.
usb_hid_consume_keyboard:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi                    ; state
    mov  r13, rdx                    ; report
    lea  r14, [r12 + usb_hid_state.previous]
    cmp  byte [r13 + 1], 0
    jne  .malformed

    ; Reject rollover/error usages and duplicate nonzero usages before output.
    mov  ebx, 2
.validate_outer:
    cmp  ebx, 8
    jae  .modifiers
    movzx eax, byte [r13 + rbx]
    test eax, eax
    jz   .validate_next
    cmp  eax, 3
    jbe  .rollover
    mov  ecx, ebx
    inc  ecx
.validate_inner:
    cmp  ecx, 8
    jae  .validate_next
    cmp  [r13 + rcx], al
    je   .malformed
    inc  ecx
    jmp  .validate_inner
.validate_next:
    inc  ebx
    jmp  .validate_outer

.modifiers:
    mov  byte [rel usb_hid_batch_count], 0
    mov  rdi, r12
    call usb_hid_held_modifiers
    movzx r15d, byte [r13]
    or   r15d, eax                    ; post-transition aggregate modifiers
    or   al, [r14]                    ; pre-transition aggregate modifiers
    xor  eax, r15d
    mov  [rel usb_hid_modifier_changed], al
    xor  ebx, ebx
.modifier_loop:
    cmp  ebx, 8
    jae  .released_keys
    movzx eax, byte [rel usb_hid_modifier_changed]
    mov  ecx, ebx
    mov  edx, 1
    shl  edx, cl
    test eax, edx
    jz   .modifier_next
    lea  rax, [rel usb_hid_modifier_e0]
    cmp  byte [rax + rbx], 0
    je   .modifier_code
    mov  al, 0xE0
    call usb_hid_batch_byte
    test eax, eax
    jz   .malformed
.modifier_code:
    lea  rax, [rel usb_hid_modifier_scancode]
    mov  al, [rax + rbx]
    mov  ecx, ebx
    mov  edx, 1
    shl  edx, cl
    test r15d, edx
    jnz  .modifier_emit
    or   al, 0x80
.modifier_emit:
    call usb_hid_batch_byte
    test eax, eax
    jz   .malformed
.modifier_next:
    inc  ebx
    jmp  .modifier_loop

.released_keys:
    mov  ebx, 2
.released_loop:
    cmp  ebx, 8
    jae  .pressed_keys
    mov  al, [r14 + rbx]
    test al, al
    jz   .released_next
    mov  rsi, r14
    call usb_hid_held_prior
    test eax, eax
    jnz  .released_next
    mov  al, [r14 + rbx]
    mov  rsi, r13
    call usb_hid_usage_present
    test eax, eax
    jnz  .released_next
    mov  al, [r14 + rbx]
    mov  rdi, r12
    call usb_hid_held_other_usage
    test eax, eax
    jnz  .released_next
    mov  al, [r14 + rbx]
    mov  dl, 1
    mov  ecx, r15d                   ; modifiers already emitted for this report
    call usb_hid_append_usage
    test eax, eax
    jz   .malformed
.released_next:
    inc  ebx
    jmp  .released_loop

.pressed_keys:
    mov  ebx, 2
.pressed_loop:
    cmp  ebx, 8
    jae  .commit
    mov  al, [r13 + rbx]
    test al, al
    jz   .pressed_next
    mov  rsi, r13
    call usb_hid_held_prior
    test eax, eax
    jnz  .pressed_next
    mov  al, [r13 + rbx]
    mov  rsi, r14
    call usb_hid_usage_present
    test eax, eax
    jnz  .pressed_next
    mov  al, [r13 + rbx]
    mov  rdi, r12
    call usb_hid_held_other_usage
    test eax, eax
    jnz  .pressed_next
    mov  al, [r13 + rbx]
    xor  edx, edx
    mov  ecx, r15d                   ; modifiers already emitted for this report
    call usb_hid_append_usage
    test eax, eax
    jz   .malformed
.pressed_next:
    inc  ebx
    jmp  .pressed_loop

.commit:
    call usb_hid_held_commit
    test eax, eax
    jz   .malformed
    mov  rdi, r12
    mov  rdx, r13
    call usb_hid_held_repeat_release
.remember:
    mov  rdi, r14
    mov  rsi, r13
    mov  ecx, USB_HID_KBD_REPORT_LEN
    rep  movsb
    mov  rdi, r12
    call usb_hid_repeat_note
    mov  eax, 1
    jmp  .out
.rollover:
    inc  qword [rel usb_hid_refused_rollover]
    mov  byte [rel usb_hid_obs_reason], 5
    jmp  .refused
.malformed:
    inc  qword [rel usb_hid_refused_malformed]
.refused:
    cmp  [rel usb_hid_repeat_owner], r12
    jne  .refused_out
    mov  qword [rel usb_hid_repeat_owner], 0 ; error/rollover report: stop repeat
.refused_out:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Three-byte boot or four/five-byte relative report. High button bits are reserved;
; deltas are signed eight-bit quantities and feed the common clamped pointer.
; The optional wheel byte (3) is forwarded to the pointer seam; pan is ignored.
; ECX = report length. Preserves R8.
usb_hid_consume_mouse:
    push rdi
    push r8
    mov  r8d, ecx                       ; report length (CL is reused below)
    movzx eax, byte [rdx]
    mov  [rel usb_hid_last_mouse_raw], al     ; INPUTSTAT evidence: the last raw boot-mouse report
    mov  cl, [rdx + 1]
    mov  [rel usb_hid_last_mouse_raw + 1], cl
    mov  cl, [rdx + 2]
    mov  [rel usb_hid_last_mouse_raw + 2], cl
    inc  qword [rel usb_hid_mouse_reports]
    test al, 0xF8
    jnz  .malformed
    ; 2026-10-01 (usage suite CON-02; MSI tree TRM-04 port): a report longer
    ; than the 3-byte boot core carries the wheel in byte 3 (as Linux usbmouse
    ; reads boot reports); + = away from the user. It rides in bits 8..15.
    cmp  r8d, 4
    mov  r8d, 0
    jb   .no_wheel
    movzx r8d, byte [rdx + 3]
    shl  r8d, 8
.no_wheel:
    movsx edi, byte [rdx + 1]
    movsx esi, byte [rdx + 2]
    mov  edx, eax
    or   edx, r8d
    mov  ecx, edx
    mov  edx, esi
    mov  esi, edi
    mov  rdi, [rsp + 8]
    call usb_hid_pointer_publish
    test eax, eax
    jnz  .published
    mov  byte [rel usb_hid_obs_reason], 0 ; host ring full, not malformed wire
.published:
    pop  r8
    pop  rdi
    ret
.malformed:
    inc  qword [rel usb_hid_refused_malformed]
    pop  r8
    pop  rdi
    xor  eax, eax
    ret

; Consume an immutable Task2903 completion. In RDI=state, RSI=metadata,
; RDX=report bytes, ECX=copied length. Out EAX=1 accepted / 0 refused.
usb_hid_consume_interrupt:
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 16
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  ebx, ecx
    mov  byte [rel usb_hid_obs_reason], 4
    cmp  byte [r12 + usb_hid_state.active], 1
    jne  .malformed
    mov  al, [r12 + usb_hid_state.slot]
    cmp  [r13 + usb_intr_completion.slot], al
    jne  .wrong_slot
    mov  al, [r12 + usb_hid_state.ep_addr]
    cmp  [r13 + usb_intr_completion.ep_addr], al
    jne  .wrong_slot
    and  eax, USB_EP_NUM_MASK
    shl  eax, 1
    inc  eax                         ; interrupt-IN DCI = endpoint*2 + 1
    cmp  [r13 + usb_intr_completion.dci], al
    jne  .wrong_slot
    mov  eax, [r12 + usb_hid_state.generation]
    cmp  [r13 + usb_intr_completion.generation], eax
    jne  .stale
    push rax
    mov  rdi, [r12 + usb_hid_state.hc]
    call xhci_hc_generation          ; this state's own controller (RCQ-09 multi-instance)
    mov  ecx, eax
    pop  rax
    cmp  eax, ecx
    jne  .stale
    cmp  byte [r13 + usb_intr_completion.cycle], 1
    ja   .malformed
    mov  eax, [r13 + usb_intr_completion.sequence]
    test eax, eax
    jz   .duplicate
    cmp  eax, [r12 + usb_hid_state.last_sequence]
    jbe  .duplicate
    cmp  [r13 + usb_intr_completion.length], ebx
    jne  .malformed
    test ebx, ebx
    jz   .empty_report               ; zero-length completion: no report, not malformed
    cmp  byte [r12 + usb_hid_state.protocol], 3
    je   .multi
    cmp  byte [r12 + usb_hid_state.kind], USB_HID_KIND_KBD
    jne  .mouse_len
    cmp  byte [r12 + usb_hid_state.protocol], 1
    jne  .boot_len
    movzx eax, byte [r12 + usb_hid_state.wire_len]
    cmp  ebx, eax
    jne  .malformed
    jmp  .sequence_owned
.boot_len:
    cmp  ebx, USB_HID_KBD_REPORT_LEN
    jne  .malformed
    jmp  .sequence_owned
.mouse_len:
    cmp  byte [r12 + usb_hid_state.protocol], 4
    jne  .mouse_protocol
    movzx eax, byte [r12 + usb_hid_state.wire_len]
    cmp  ebx, eax
    jne  .malformed
    jmp  .sequence_owned
.mouse_protocol:
    cmp  byte [r12 + usb_hid_state.kind], USB_HID_KIND_MOUSE
    jne  .malformed
    cmp  byte [r12 + usb_hid_state.protocol], 2
    jne  .boot_mouse_len
    movzx eax, byte [r12 + usb_hid_state.wire_len]
    cmp  ebx, eax
    jne  .malformed
    jmp  .sequence_owned
.boot_mouse_len:
    cmp  ebx, USB_HID_MOUSE_REPORT_MIN
    jb   .malformed
    cmp  ebx, USB_HID_MOUSE_REPORT_MAX
    ja   .malformed
.sequence_owned:
    mov  eax, [r13 + usb_intr_completion.sequence]
    mov  [r12 + usb_hid_state.last_sequence], eax
    cmp  byte [r12 + usb_hid_state.kind], USB_HID_KIND_KBD
    jne  .mouse
    mov  rdi, r12
    mov  rdx, r14
    cmp  byte [r12 + usb_hid_state.protocol], 1
    jne  .normalized
    mov  rsi, rsp
    mov  ecx, ebx
    call usb_hid_report_decode
    test eax, eax
    jz   .malformed
    mov  rdi, r12
    mov  rdx, rsp
.normalized:
    call usb_hid_consume_keyboard
    jmp  .out
.mouse:
    cmp  byte [r12 + usb_hid_state.protocol], 4
    je   .touchpad
    mov  rdi, r12
    mov  rdx, r14
    mov  ecx, ebx
    cmp  byte [r12 + usb_hid_state.protocol], 2
    jne  .boot_mouse
    mov  rsi, rsp
    call usb_hid_mouse_report_decode
    test eax, eax
    jz   .malformed
    mov  edi, [rsp]
    mov  esi, [rsp + 4]
    mov  edx, [rsp + 8]
    mov  ecx, edx
    mov  edx, esi
    mov  esi, edi
    mov  rdi, r12
    call usb_hid_pointer_publish    ; same bounded ring and clamped GUI seam
    inc  qword [rel usb_hid_mouse_reports]
    test eax, eax
    jnz  .out
    jmp  .observed                   ; host ring full, not hostile wire
.touchpad:
    mov  rdi, r12
    mov  rdx, r14
    mov  ecx, ebx
    call usb_hid_touchpad_consume
    test eax, eax
    jnz  .out
    cmp  byte [rel usb_hid_obs_reason], 0
    je   .observed                   ; anchor/custody retained under host pressure
    jmp  .malformed
.boot_mouse:
    call usb_hid_consume_mouse
    jmp  .out
.multi:
    mov  rdi, r12
    mov  esi, [r13 + usb_intr_completion.sequence]
    mov  rdx, r14
    mov  ecx, ebx
    call usb_hid_multi_consume
    test eax, eax
    jnz  .out
    cmp  byte [rel usb_hid_obs_reason], 0
    je   .observed                   ; known pointer report refused by native ring
    inc  qword [rel usb_hid_refused_malformed]
    jmp  .out                         ; unknown ID cannot cancel another ID's repeat
.empty_report:
    ; A validated owner's zero-length completion (a device ending a max-packet
    ; report with a ZLP: Short Packet, residual == TD; seen after every GLKVM
    ; report on HP) carries no report. Like Linux hid-core's empty report it
    ; changes no key, pointer, repeat or refusal state and publishes nothing.
    mov  eax, [r13 + usb_intr_completion.sequence]
    mov  [r12 + usb_hid_state.last_sequence], eax ; consumed: a replay is a duplicate
    xor  eax, eax
    jmp  .observed
.wrong_slot:
    mov  byte [rel usb_hid_obs_reason], 1
    inc  qword [rel usb_hid_refused_wrong_slot]
    xor  eax, eax
    jmp  .out
.stale:
    mov  byte [rel usb_hid_obs_reason], 2
    inc  qword [rel usb_hid_refused_stale]
    xor  eax, eax
    jmp  .out
.duplicate:
    mov  byte [rel usb_hid_obs_reason], 3
    inc  qword [rel usb_hid_refused_duplicate]
    xor  eax, eax
    jmp  .out
.malformed:
    inc  qword [rel usb_hid_refused_malformed]
    cmp  [rel usb_hid_repeat_owner], r12
    jne  .malformed_out
    mov  qword [rel usb_hid_repeat_owner], 0
.malformed_out:
    xor  eax, eax
.out:
    test eax, eax
    jnz  .observed
    push rax
    mov  rdi, r12
    movzx esi, byte [rel usb_hid_obs_reason]
    call usb_hid_obs_enqueue
    pop  rax
.observed:
    test eax,eax
    jz .owned_done
    push rax
    mov rdi,r12
    call usb_hid_owned_traffic
    pop rax
.owned_done:
    add  rsp, 16
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Observation-only lower-layer queue. Current poll task is cooperative on the
; BSP; no yield, IRQ/AP caller or audit call occurs between live marker, consume
; and enqueue. The exported snapshot/pop run on BSP idle, never in an ISR.
; No reports, usages, hardware/USB serials, pointers or addresses are exported.
USB_HID_OBS_N equ 8
USB_HID_OBS_SZ equ 24

; Reset/release/rebind invalidate all pending binding detail, never total/seen.
; Synthetic boot brackets preserve observations and their epoch.
usb_hid_obs_reset:
    cmp  dword [rel usb_hid_obs_test_depth], 0
    jne  .out
    mov  eax, [rel usb_hid_obs_pending]
    add  [rel usb_hid_obs_drops], rax
    jnc  .drop_ok
    mov  qword [rel usb_hid_obs_drops], -1
.drop_ok:
    mov  dword [rel usb_hid_obs_pending], 0
    mov  dword [rel usb_hid_obs_head], 0
    mov  dword [rel usb_hid_obs_tail], 0
    mov  dword [rel usb_hid_obs_serial], 0
    mov  qword [rel usb_hid_obs_live_state], 0
    cmp  qword [rel usb_hid_obs_epoch], 65535
    jae  .frozen
    inc  qword [rel usb_hid_obs_epoch]
    mov  byte [rel usb_hid_obs_frozen], 0
    jmp  .clear
.frozen:
    mov  byte [rel usb_hid_obs_frozen], 1
.clear:
    lea  rdi, [rel usb_hid_obs_queue]
    mov  ecx, USB_HID_OBS_N * USB_HID_OBS_SZ / 8
    xor  eax, eax
    cld
    rep  stosq
.out:
    ret

; RDI=state, ESI=reason1wrongsource/2stale/3duplicate/4malformed/5rollover.
; Only the real poll-state bracket can produce. A private KAT/foreign state or
; unsupported kind cannot grant provenance, even with matching raw counters.
usb_hid_obs_enqueue:
    cmp  dword [rel usb_hid_obs_test_depth], 0
    jne  .out
    cmp  [rel usb_hid_obs_live_state], rdi
    jne  .out
    lea  rax, [rel usb_hid_states]
    mov  rdx, rdi
    sub  rdx, rax
    jc   .out
    cmp  rdx, USB_HID_MAX_STATES * usb_hid_state_size
    jae  .out
    mov  rax, rdx
    xor  edx, edx
    mov  ecx, usb_hid_state_size
    div  rcx
    test rdx, rdx
    jnz  .out
    mov  r9d, eax                          ; bounded binding ordinal0..3
    cmp  byte [rdi + usb_hid_state.active], 1
    jne  .out
    cmp  byte [rdi + usb_hid_state.kind], 1
    jb   .out
    cmp  byte [rdi + usb_hid_state.kind], 2
    ja   .out
    cmp  qword [rdi + usb_hid_state.hc], 0
    je   .out
    cmp  byte [rdi + usb_hid_state.slot], 0
    je   .out
    cmp  byte [rdi + usb_hid_state.port], 0
    je   .out
    test byte [rdi + usb_hid_state.ep_addr], 0x80
    jz   .out
    test byte [rdi + usb_hid_state.ep_addr], USB_EP_NUM_MASK
    jz   .out
    cmp  esi, 1
    jb   .out
    cmp  esi, 5
    ja   .out
    cmp  byte [rel usb_hid_obs_frozen], 0
    jne  .drop
    cmp  qword [rel usb_hid_obs_epoch], 0
    je   .drop
    cmp  qword [rel usb_hid_obs_epoch], 65535
    ja   .drop
    cmp  qword [rel usb_hid_obs_total], -1
    je   .freeze
    cmp  dword [rel usb_hid_obs_serial], -1
    je   .freeze
    inc  dword [rel usb_hid_obs_serial]
    inc  qword [rel usb_hid_obs_total]
    cmp  dword [rel usb_hid_obs_pending], USB_HID_OBS_N
    jae  .drop
    mov  eax, [rel usb_hid_obs_head]
    cmp  eax, USB_HID_OBS_N
    jae  .drop
    imul eax, USB_HID_OBS_SZ
    lea  r8, [rel usb_hid_obs_queue]
    add  r8, rax
    mov  rax, [rel usb_hid_obs_epoch]
    shl  rax, 32
    mov  edx, [rel usb_hid_obs_serial]
    or   rax, rdx
    mov  [r8], rax
    movzx eax, byte [rdi + usb_hid_state.kind]
    shl  eax, 8
    lea  eax, [rax + r9 + 1]
    mov  [r8 + 8], eax
    mov  [r8 + 12], esi
    mov  eax, [rdi + usb_hid_state.generation]
    mov  [r8 + 16], eax
    movzx eax, byte [rdi + usb_hid_state.slot]
    mov  [r8 + 20], al
    movzx eax, byte [rdi + usb_hid_state.port]
    mov  [r8 + 21], al
    movzx eax, byte [rdi + usb_hid_state.ep_addr]
    mov  [r8 + 22], al
    movzx eax, byte [rdi + usb_hid_state.kind]
    mov  [r8 + 23], al
    inc  dword [rel usb_hid_obs_head]
    and  dword [rel usb_hid_obs_head], USB_HID_OBS_N - 1
    inc  dword [rel usb_hid_obs_pending]
    ret
.freeze:
    mov  byte [rel usb_hid_obs_frozen], 1
.drop:
    add  qword [rel usb_hid_obs_drops], 1
    jnc  .out
    mov  qword [rel usb_hid_obs_drops], -1
.out:
    ret

; RAX total, RDX detail drops, RCX current epoch, RSI pending. Read-only.
usb_hid_observation_snapshot:
    mov  rax, [rel usb_hid_obs_total]
    mov  rdx, [rel usb_hid_obs_drops]
    mov  rcx, [rel usb_hid_obs_epoch]
    mov  esi, [rel usb_hid_obs_pending]
    ret

; EAX1 record,0 empty,-1 discarded. RDX id48,ECX subject,ESI reason.
; One attempt only: BSP caller bounds drain budget. Validate against the still
; bound state before exporting. Slot generation/owner loss cannot replay detail.
usb_hid_observation_pop:
    cmp  dword [rel usb_hid_obs_test_depth], 0
    jne  .empty
    cmp  dword [rel usb_hid_obs_pending], 0
    je   .empty
    cmp  dword [rel usb_hid_obs_pending], USB_HID_OBS_N
    ja   .corrupt
    mov  eax, [rel usb_hid_obs_tail]
    cmp  eax, USB_HID_OBS_N
    jae  .corrupt
    imul eax, USB_HID_OBS_SZ
    lea  r10, [rel usb_hid_obs_queue]
    add  r10, rax
    mov  rdx, [r10]
    mov  ecx, [r10 + 8]
    mov  esi, [r10 + 12]
    mov  r8d, [r10 + 16]
    mov  r9d, [r10 + 20]
    mov  qword [r10], 0
    mov  qword [r10 + 8], 0
    mov  qword [r10 + 16], 0
    inc  dword [rel usb_hid_obs_tail]
    and  dword [rel usb_hid_obs_tail], USB_HID_OBS_N - 1
    dec  dword [rel usb_hid_obs_pending]
    mov  rax, rdx
    shr  rax, 32
    cmp  rax, [rel usb_hid_obs_epoch]
    jne  .stale
    movzx eax, cl
    dec  eax
    cmp  eax, USB_HID_MAX_STATES
    jae  .stale
    imul eax, usb_hid_state_size
    lea  r10, [rel usb_hid_states]
    add  r10, rax
    cmp  byte [r10 + usb_hid_state.active], 1
    jne  .stale
    cmp  [r10 + usb_hid_state.generation], r8d
    jne  .stale
    movzx eax, byte [r10 + usb_hid_state.slot]
    movzx edi, byte [r10 + usb_hid_state.port]
    shl  edi, 8
    or   eax, edi
    movzx edi, byte [r10 + usb_hid_state.ep_addr]
    shl  edi, 16
    or   eax, edi
    movzx edi, byte [r10 + usb_hid_state.kind]
    shl  edi, 24
    or   eax, edi
    cmp  eax, r9d
    jne  .stale
    push rdx
    push rcx
    push rsi
    push r8
    push r10
    mov  rdi, [r10 + usb_hid_state.hc]
    call xhci_hc_generation               ; software owner generation, no MMIO
    mov  edi, eax
    pop  r10
    pop  r8
    pop  rsi
    pop  rcx
    pop  rdx
    cmp  edi, r8d
    jne  .stale
    mov  eax, 1
    ret
.corrupt:
    sub  rsp, 8
    call usb_hid_obs_reset
    add  rsp, 8
.stale:
    add  qword [rel usb_hid_obs_drops], 1
    jnc  .discard
    mov  qword [rel usb_hid_obs_drops], -1
.discard:
    mov  eax, -1
    ret
.empty:
    xor  eax, eax
    ret

; Deterministic state-lifetime KAT: detach releases only its consumer and reset
; releases both before reuse. It runs before real discovery.
usb_hid_reset_detach_kat:
    sub  rsp, 8
    mov  ecx, [rel usb_hid_obs_test_depth]
    mov  [rsp], rcx
    mov  dword [rel usb_hid_obs_test_depth], 1
    call usb_hid_reset_detach_kat_body
    mov  ecx, [rsp]
    mov  [rel usb_hid_obs_test_depth], ecx
    add  rsp, 8
    ret

usb_hid_reset_detach_kat_body:
    lea  rdi, [rel usb_hid_states]
    mov  ecx, (USB_HID_MAX_STATES * usb_hid_state_size) / 8
    xor  eax, eax
    rep  stosq
    lea  rax, [rel usb_hid_states]
    mov  byte [rax + usb_hid_state.active], 1
    mov  byte [rax + usb_hid_state.port], 3
    add  rax, usb_hid_state_size
    mov  byte [rax + usb_hid_state.active], 1
    mov  byte [rax + usb_hid_state.port], 4
    mov  byte [rel usb_hid_active_count], 2
    mov  esi, 3
    call usb_hid_detach
    cmp  byte [rel usb_hid_active_count], 1
    jne  .reset
    cmp  byte [rel usb_hid_states + usb_hid_state.active], 0
    jne  .reset
    cmp  byte [rel usb_hid_states + usb_hid_state_size + usb_hid_state.active], 1
    jne  .reset
    mov  byte [rel usb_hid_detach_kat_ok], 1
.reset:
    call usb_hid_reset
    cmp  byte [rel usb_hid_active_count], 0
    jne  .out
    cmp  byte [rel usb_hid_states + usb_hid_state.active], 0
    jne  .out
    cmp  byte [rel usb_hid_states + usb_hid_state_size + usb_hid_state.active], 0
    jne  .out
    mov  byte [rel usb_hid_reset_kat_ok], 1
.out:
    ret

; R8D = controller 0's generation, whichever controller is live: the KAT state
; is bound to xhci_hcdev, so its stamp must be that controller's (RCQ-09).
; Preserves every other register.
usb_hid_kat_generation:
    push rax
    push rcx
    push rdx
    push rdi
    lea  rdi, [rel xhci_hcdev]
    call xhci_hc_generation
    mov  r8d, eax
    pop  rdi
    pop  rdx
    pop  rcx
    pop  rax
    ret

; Build metadata for the synthetic hostile-report state.
; In EAX=sequence, ECX=length.
usb_hid_kat_meta:
    lea  rdx, [rel usb_hid_kat_state]
    lea  rsi, [rdx + usb_hid_state.meta]
    mov  byte [rsi + usb_intr_completion.slot], 7
    mov  byte [rsi + usb_intr_completion.dci], 3
    mov  byte [rsi + usb_intr_completion.ep_addr], 0x81
    mov  byte [rsi + usb_intr_completion.cycle], 1
    call usb_hid_kat_generation
    mov  [rsi + usb_intr_completion.generation], r8d
    mov  [rsi + usb_intr_completion.sequence], eax
    mov  [rsi + usb_intr_completion.length], ecx
    ret

; Hostile report KAT. Every refusal is checked against unchanged common input
; state; accepted reports are all-zero no-ops.
usb_hid_hostile_kat:
    sub  rsp, 8
    mov  ecx, [rel usb_hid_obs_test_depth]
    mov  [rsp], rcx
    mov  dword [rel usb_hid_obs_test_depth], 1
    call usb_hid_hostile_kat_body
    mov  ecx, [rsp]
    mov  [rel usb_hid_obs_test_depth], ecx
    add  rsp, 8
    ret

usb_hid_hostile_kat_body:
    push rbx
    push r12
    lea  rdi, [rel usb_hid_kat_state]
    mov  ecx, usb_hid_state_size / 8
    xor  eax, eax
    rep  stosq
    lea  r12, [rel usb_hid_kat_state]
    mov  byte [r12 + usb_hid_state.active], 1
    mov  byte [r12 + usb_hid_state.kind], USB_HID_KIND_KBD
    mov  byte [r12 + usb_hid_state.slot], 7
    mov  byte [r12 + usb_hid_state.ep_addr], 0x81
    call usb_hid_kat_generation
    mov  [r12 + usb_hid_state.generation], r8d
    lea  rax, [rel xhci_hcdev]          ; RCQ-09: the generation check reads this state's controller
    mov  [r12 + usb_hid_state.hc], rax  ; (controller 0, whose generation is stamped above)
    movzx ebx, byte [rel kbd_head]
    mov  eax, [rel gui_cursor_x]
    mov  [rel usb_hid_kat_cursor_x], eax
    mov  eax, [rel gui_cursor_y]
    mov  [rel usb_hid_kat_cursor_y], eax
    lea  rdi, [rel usb_hid_test_report]
    mov  ecx, 9
    xor  eax, eax
    rep  stosb

    ; wrong slot
    mov  eax, 1
    mov  ecx, USB_HID_KBD_REPORT_LEN
    call usb_hid_kat_meta
    mov  byte [rsi + usb_intr_completion.slot], 6
    mov  rdi, r12
    lea  rdx, [rel usb_hid_test_report]
    call usb_hid_consume_interrupt
    test eax, eax
    jnz  .out

    ; stale generation
    mov  eax, 1
    mov  ecx, USB_HID_KBD_REPORT_LEN
    call usb_hid_kat_meta
    inc  dword [rsi + usb_intr_completion.generation]
    mov  rdi, r12
    lea  rdx, [rel usb_hid_test_report]
    call usb_hid_consume_interrupt
    test eax, eax
    jnz  .out

    ; one valid no-op followed by the exact duplicate completion
    mov  eax, 1
    mov  ecx, USB_HID_KBD_REPORT_LEN
    call usb_hid_kat_meta
    mov  rdi, r12
    lea  rdx, [rel usb_hid_test_report]
    call usb_hid_consume_interrupt
    cmp  eax, 1
    jne  .out
    mov  eax, 1
    mov  ecx, USB_HID_KBD_REPORT_LEN
    call usb_hid_kat_meta
    mov  rdi, r12
    lea  rdx, [rel usb_hid_test_report]
    call usb_hid_consume_interrupt
    test eax, eax
    jnz  .out

    ; rollover/error usage and both truncated/oversized report sizes
    mov  byte [rel usb_hid_test_report + 2], 1
    mov  eax, 2
    mov  ecx, USB_HID_KBD_REPORT_LEN
    call usb_hid_kat_meta
    mov  rdi, r12
    lea  rdx, [rel usb_hid_test_report]
    call usb_hid_consume_interrupt
    test eax, eax
    jnz  .out
    mov  byte [rel usb_hid_test_report + 2], 0
    mov  eax, 3
    mov  ecx, USB_HID_KBD_REPORT_LEN - 1
    call usb_hid_kat_meta
    mov  rdi, r12
    lea  rdx, [rel usb_hid_test_report]
    call usb_hid_consume_interrupt
    test eax, eax
    jnz  .out
    mov  eax, 4
    mov  ecx, USB_HID_KBD_REPORT_LEN + 1
    call usb_hid_kat_meta
    mov  rdi, r12
    lea  rdx, [rel usb_hid_test_report]
    call usb_hid_consume_interrupt
    test eax, eax
    jnz  .out

    ; A HID-class absolute/tablet interface is not a boot-protocol candidate.
    lea  rdi, [rel usb_hid_test_tablet]
    mov  esi, usb_hid_test_tablet_end - usb_hid_test_tablet
    mov  edx, USB_SPEED_FULL
    call usb_hid_scan_config
    cmp  byte [rel usb_hid_kbd_candidate], 0
    jne  .out
    cmp  byte [rel usb_hid_mouse_candidate], 0
    jne  .out

    ; A real boot-interface gadget delivered five bytes on Lenovo. Exercise
    ; all three accepted lengths through this same completion validator, then
    ; reject adjacent malformed lengths without changing the pointer.
    mov  byte [r12 + usb_hid_state.kind], USB_HID_KIND_MOUSE
    mov  eax, 5
    mov  ecx, USB_HID_MOUSE_REPORT_MIN
    call usb_hid_kat_meta
    mov  rdi, r12
    lea  rdx, [rel usb_hid_test_report]
    call usb_hid_consume_interrupt
    cmp  eax, 1
    jne  .out
    mov  eax, 6
    mov  ecx, USB_HID_MOUSE_REPORT_MAX
    call usb_hid_kat_meta
    mov  rdi, r12
    lea  rdx, [rel usb_hid_test_report]
    call usb_hid_consume_interrupt
    cmp  eax, 1
    jne  .out
    mov  eax, 7
    mov  ecx, 4
    call usb_hid_kat_meta
    mov  rdi, r12
    lea  rdx, [rel usb_hid_test_report]
    call usb_hid_consume_interrupt
    cmp  eax, 1
    jne  .out
    mov  eax, 8
    mov  ecx, USB_HID_MOUSE_REPORT_MIN - 1
    call usb_hid_kat_meta
    mov  rdi, r12
    lea  rdx, [rel usb_hid_test_report]
    call usb_hid_consume_interrupt
    test eax, eax
    jnz  .out
    mov  eax, 9
    mov  ecx, 6
    call usb_hid_kat_meta
    mov  rdi, r12
    lea  rdx, [rel usb_hid_test_report]
    call usb_hid_consume_interrupt
    test eax, eax
    jnz  .out

    cmp  qword [rel usb_hid_refused_wrong_slot], 1
    jb   .out
    cmp  qword [rel usb_hid_refused_stale], 1
    jb   .out
    cmp  qword [rel usb_hid_refused_duplicate], 1
    jb   .out
    cmp  qword [rel usb_hid_refused_rollover], 1
    jb   .out
    cmp  qword [rel usb_hid_refused_malformed], 4
    jb   .out
    cmp  qword [rel usb_hid_refused_absolute], 1
    jb   .out
    movzx eax, byte [rel kbd_head]
    cmp  eax, ebx
    jne  .out
    mov  eax, [rel gui_cursor_x]
    cmp  eax, [rel usb_hid_kat_cursor_x]
    jne  .out
    mov  eax, [rel gui_cursor_y]
    cmp  eax, [rel usb_hid_kat_cursor_y]
    jne  .out
    mov  byte [rel usb_hid_hostile_kat_ok], 1
.out:
    lea  rdi, [rel usb_hid_kat_state]
    mov  ecx, usb_hid_state_size / 8
    xor  eax, eax
    rep  stosq
    pop  r12
    pop  rbx
    ret

usb_hid_emit_marker:
    cmp  byte [rel usb_hid_marker_emitted], 1
    je   .out
    mov  byte [rel usb_hid_marker_emitted], 1
    lea  rdi, [rel str_usb_hid_marker]
    call serial_string
.out:
    ret

; Default regression proof is deliberately logic-only: it may emit the shared
; marker after a real xHCI/non-null USB provenance boot and all refusal KATs,
; but never emits the live HID receipt. The external positive profile requires
; both the attached usb-kbd/usb-mouse devices and that receipt.
usb_hid_logic_selftest:
    push rbx
    cmp  byte [rel usb_hid_hostile_kat_ok], 1
    jne  .out
    cmp  byte [rel usb_hid_reset_kat_ok], 1
    jne  .out
    cmp  byte [rel usb_hid_detach_kat_ok], 1
    jne  .out
    cmp  dword [rel xhci_found], 1
    jne  .out
    lea  rax, [rel usb_hid_to_scancode]
    cmp  byte [rax + 0x4F], 0x4D     ; Right -> E0 4D / E0 CD
    jne  .out
    call usb_dev_count
    mov  ecx, eax
    xor  ebx, ebx
.device:
    cmp  ebx, ecx
    jae  .out
    push rcx
    mov  edi, ebx
    call usb_dev_is_null
    pop  rcx
    test eax, eax
    jz   .pass
    inc  ebx
    jmp  .device
.pass:
    call usb_hid_emit_marker
.out:
    pop  rbx
    ret

; Live positive proof. Injection is requested only after POLL_READY, then exact
; common-seam effects and unchanged PS/2 IRQ counters earn the receipt.
usb_hid_selftest:
    sub  rsp, 8
    mov  ecx, [rel usb_hid_obs_test_depth]
    mov  [rsp], rcx
    mov  dword [rel usb_hid_obs_test_depth], 1
    call usb_hid_selftest_body
    mov  ecx, [rsp]
    mov  [rel usb_hid_obs_test_depth], ecx
    add  rsp, 8
    ret

usb_hid_selftest_body:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  edi, USB_HID_KIND_KBD
    call usb_hid_find_state_kind
    test rax, rax
    jz   .out
    mov  r12, rax
    mov  edi, USB_HID_KIND_MOUSE
    call usb_hid_find_state_kind
    test rax, rax
    jz   .out
    mov  r13, rax
    mov  al, [r12 + usb_hid_state.slot]
    cmp  al, [r13 + usb_hid_state.slot]
    je   .out
    cmp  byte [rel usb_hid_hostile_kat_ok], 1
    jne  .out
    cmp  byte [rel usb_hid_reset_kat_ok], 1
    jne  .out
    cmp  byte [rel usb_hid_detach_kat_ok], 1
    jne  .out
    cmp  byte [rel usb_hid_task_running], 1
    jne  .out                         ; receipt requires a dispatched resident poller
    movzx eax, byte [rel kbd_head]
    cmp  eax, KBD_RING_LEN - 4
    ja   .out
    mov  [rel usb_hid_proof_kbd_head], al
    mov  eax, [rel gui_cursor_x]
    mov  [rel usb_hid_proof_cursor_x], eax
    mov  eax, [rel gui_cursor_y]
    mov  [rel usb_hid_proof_cursor_y], eax
    mov  rax, [rel ps2_kbd_irq_count]
    mov  [rel usb_hid_proof_ps2_kbd], rax
    mov  rax, [rel ps2_mouse_irq_count]
    mov  [rel usb_hid_proof_ps2_mouse], rax
    lea  rdi, [rel str_usb_hid_poll_ready]
    call serial_string
    mov  r15, [rel timer_ticks]
    ; Task2317: confirmed-healthy boots cap the USB-HID arrival window (no-input
    ; by cap == ready); trial/ambiguous/first/unhealthy and QEMU force-full keep
    ; the full USB_HID_POLL_TICKS window + timeout diagnostic. Shares the readiness
    ; state with the PS/2 path — only one of the two input selftests runs per boot.
    mov  byte [rel boot_input_ready_flag], 0
    mov  byte [rel boot_input_short_cap], 0
    mov  rax, USB_HID_POLL_TICKS
    cmp  byte [rel boot_budget_force_full], 1
    je   .usb_cap_add
    cmp  byte [rel boot_budget_class], 0        ; BOOT_CLASS_CONFIRMED
    jne  .usb_cap_add
    mov  rax, 100                               ; ~100 ms confirmed cap
    mov  byte [rel boot_input_short_cap], 1
.usb_cap_add:
    add  r15, rax
.poll:
    call usb_hid_poll_all
    ; Boot owns the pointer consumer until the ordinary GUI loop takes over.
    ; The resident USB worker remains a producer and never pumps or draws.
    call ps2_pointer_pump
    movzx eax, byte [rel usb_hid_proof_kbd_head]
    add  eax, 4
    cmp  [rel kbd_head], al
    jne  .wait
    lea  rbx, [rel kbd_ring]
    movzx ecx, byte [rel usb_hid_proof_kbd_head]
    cmp  byte [rbx + rcx], 0xE0
    jne  .wait
    cmp  byte [rbx + rcx + 1], 0x4D
    jne  .wait
    cmp  byte [rbx + rcx + 2], 0xE0
    jne  .wait
    cmp  byte [rbx + rcx + 3], 0xCD
    jne  .wait
    mov  eax, [rel usb_hid_proof_cursor_x]
    add  eax, 17
    cmp  [rel gui_cursor_x], eax
    jne  .wait
    mov  eax, [rel usb_hid_proof_cursor_y]
    sub  eax, 9
    cmp  [rel gui_cursor_y], eax
    jne  .wait
    cmp  dword [rel gui_cursor_btn], 1
    jne  .wait
    mov  rax, [rel ps2_kbd_irq_count]
    cmp  rax, [rel usb_hid_proof_ps2_kbd]
    jne  .out
    mov  rax, [rel ps2_mouse_irq_count]
    cmp  rax, [rel usb_hid_proof_ps2_mouse]
    jne  .out
    lea  rdi, [rel str_usb_hid_receipt]
    call serial_string
    movzx edi, byte [r12 + usb_hid_state.slot]
    call serial_decimal
    lea  rdi, [rel str_usb_hid_comma]
    call serial_string
    movzx edi, byte [r13 + usb_hid_state.slot]
    call serial_decimal
    lea  rdi, [rel str_usb_hid_receipt_tail]
    call serial_string
    call usb_hid_emit_marker
    mov  byte [rel boot_input_ready_flag], 1
    jmp  .out
.wait:
    cmp  qword [rel timer_ticks], r15
    jb   .poll
    cmp  byte [rel boot_input_short_cap], 1
    je   .usb_cap_ready              ; confirmed cap: no-input-by-cap is READY, not a fail
    mov  rdi, r12
    mov  rsi, r13
    call usb_hid_timeout_diag
    jmp  .out
.usb_cap_ready:
    mov  byte [rel boot_input_ready_flag], 1
.out:
    ; Task2317: deterministic grader KAT (both legs) + readiness marker on ready.
    call boot_input_grader_kat
    cmp  byte [rel boot_input_ready_flag], 1
    jne  .out_pop
    lea  rdi, [rel str_boot_input_ready]
    call serial_string
.out_pop:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; usb_hid_diag_ep(RDI = state) -> EAX = its endpoint's pending | completed << 8, read
;   on the state's OWN controller (made live), 0 if not xHCI or not found; RDX = that
;   controller's queued, RCX = its completed TDs (0 / 0 when not xHCI). clobbers: c-s.
;   Every controller numbers slots from 1, so a lookup on whichever controller
;   happened to be live finds the wrong endpoint or none (RCQ-09 multi-instance).
usb_hid_diag_ep:
    push rbx
    mov  rbx, rdi
    mov  rdi, [rbx + usb_hid_state.hc]
    call xhci_hc_instance
    cmp  eax, -1
    je   .none
    mov  rdi, [rbx + usb_hid_state.hc]
    call xhci_inst_live_for
    movzx esi, byte [rbx + usb_hid_state.slot]
    movzx edx, byte [rbx + usb_hid_state.ep_addr]
    call xhci_interrupt_find_by_ep
    xor  ebx, ebx
    test rax, rax
    jz   .counters
    movzx ebx, byte [rax + xhci_intr_ep.pending]
    movzx ecx, byte [rax + xhci_intr_ep.completed]
    shl  ecx, 8
    or   ebx, ecx
.counters:
    mov  eax, ebx
    mov  rdx, [rel xhci_intr_queued]
    mov  rcx, [rel xhci_intr_completed]
    pop  rbx
    ret
.none:
    xor  eax, eax
    xor  edx, edx
    xor  ecx, ecx
    pop  rbx
    ret

; Timeout evidence spans producer, completion, ownership, decoder, and common
; seam state so a red profile points to one layer instead of inviting guesses.
; q= / c= total the keyboard's and the mouse's controllers (one controller once).
usb_hid_timeout_diag:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  rdi, r12
    call usb_hid_diag_ep
    mov  [rel usb_hid_diag_kep], eax
    mov  r14, rdx
    mov  r15, rcx
    mov  rdi, r13
    call usb_hid_diag_ep
    mov  [rel usb_hid_diag_mep], eax
    mov  rax, [r13 + usb_hid_state.hc]
    cmp  rax, [r12 + usb_hid_state.hc]
    je   .totals
    add  r14, rdx
    add  r15, rcx
.totals:
    lea  rdi, [rel str_usb_hid_diag_q]
    call serial_string
    mov  rdi, r14
    call serial_decimal
    lea  rdi, [rel str_usb_hid_diag_c]
    call serial_string
    mov  rdi, r15
    call serial_decimal
    lea  rdi, [rel str_usb_hid_diag_kseq]
    call serial_string
    mov  edi, [r12 + usb_hid_state.last_sequence]
    call serial_decimal
    lea  rdi, [rel str_usb_hid_diag_mseq]
    call serial_string
    mov  edi, [r13 + usb_hid_state.last_sequence]
    call serial_decimal
    lea  rdi, [rel str_usb_hid_diag_klen]
    call serial_string
    mov  edi, [r12 + usb_hid_state.meta + usb_intr_completion.length]
    call serial_decimal
    lea  rdi, [rel str_usb_hid_diag_mlen]
    call serial_string
    mov  edi, [r13 + usb_hid_state.meta + usb_intr_completion.length]
    call serial_decimal
    lea  rdi, [rel str_usb_hid_diag_mraw]
    call serial_string
    movzx edi, byte [r13 + usb_hid_state.report]
    call serial_decimal
    lea  rdi, [rel str_usb_hid_diag_slash]
    call serial_string
    movzx edi, byte [r13 + usb_hid_state.report + 1]
    call serial_decimal
    lea  rdi, [rel str_usb_hid_diag_slash]
    call serial_string
    movzx edi, byte [r13 + usb_hid_state.report + 2]
    call serial_decimal
    lea  rdi, [rel str_usb_hid_diag_kep]
    call serial_string
    mov  edi, [rel usb_hid_diag_kep]
    call serial_decimal
    lea  rdi, [rel str_usb_hid_diag_mep]
    call serial_string
    mov  edi, [rel usb_hid_diag_mep]
    call serial_decimal
    lea  rdi, [rel str_usb_hid_diag_head]
    call serial_string
    movzx edi, byte [rel kbd_head]
    call serial_decimal
    lea  rdi, [rel str_usb_hid_diag_x]
    call serial_string
    mov  edi, [rel gui_cursor_x]
    call serial_decimal
    lea  rdi, [rel str_usb_hid_diag_y]
    call serial_string
    mov  edi, [rel gui_cursor_y]
    call serial_decimal
    lea  rdi, [rel str_usb_hid_diag_btn]
    call serial_string
    mov  edi, [rel gui_cursor_btn]
    call serial_decimal
    lea  rdi, [rel str_usb_hid_diag_wrong]
    call serial_string
    mov  rdi, [rel usb_hid_refused_wrong_slot]
    call serial_decimal
    lea  rdi, [rel str_usb_hid_diag_stale]
    call serial_string
    mov  rdi, [rel usb_hid_refused_stale]
    call serial_decimal
    lea  rdi, [rel str_usb_hid_diag_dup]
    call serial_string
    mov  rdi, [rel usb_hid_refused_duplicate]
    call serial_decimal
    lea  rdi, [rel str_usb_hid_diag_bad]
    call serial_string
    mov  rdi, [rel usb_hid_refused_malformed]
    call serial_decimal
    call serial_newline
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

%ifdef PAOS_LAB_EP0_PROBE
; ---------------------------------------------------------------------------
; usb_ep0_lab_probe (lab only: PAOS_LAB_EP0_PROBE) runs after the last USB class
; probe (cdc_ecm). On every enumerated device's own control pipe:
;   pre   GET_DESCRIPTOR(DEVICE, 18) returns 18 (a post-init EP0 transfer);
;   stall GET_DESCRIPTOR(CONFIGURATION, index = bNumConfigurations, 9) STALLs (-2):
;         a nonexistent index is a Request Error (USB 2.0 9.4.3, 9.2.7);
;   post  GET_DESCRIPTOR(DEVICE, 18) returns the same 18 bytes.
;   short GET_DESCRIPTOR(CONFIGURATION, 0, 255) into a canary-filled 256-byte
;         buffer returns exactly wTotalLength, the canary intact past it (0008).
; Standard read-only requests only. Lines per device, then the verdicts.
; ---------------------------------------------------------------------------
usb_ep0_lab_probe:
    push rbx
    push r12
    push r13
    push r14
    push r15
    xor  ebx, ebx                    ; device index
    xor  r14d, r14d                  ; devices probed
    xor  r15d, r15d                  ; devices passed
    mov  dword [rel usb_ep0_lab_short_pass], 0
.dev:
    call usb_dev_count
    cmp  ebx, eax
    jae  .verdict
    mov  edi, ebx
    call usb_dev_is_null
    test eax, eax
    jnz  .next
    mov  edi, ebx
    call usb_dev_hc
    test rax, rax
    jz   .next
    mov  r12, rax
    mov  edi, ebx
    call usb_dev_addr
    test eax, eax
    jz   .next
    mov  r13d, eax
    mov  edi, ebx
    call usb_dev_desc_ptr            ; enumeration's cached device descriptor
    test rax, rax
    jz   .next
    movzx eax, byte [rax + 17]       ; bNumConfigurations
    mov  [rel usb_ep0_lab_ncfg], eax
    inc  r14d
    lea  rdi, [rel usb_ep0_lab_pre_desc]
    xor  eax, eax
    mov  ecx, 18
    rep  stosb
    lea  rdi, [rel usb_ep0_lab_post_desc]
    mov  ecx, 18
    rep  stosb
    mov  esi, 0x0100
    mov  edx, 18
    lea  rcx, [rel usb_ep0_lab_pre_desc]
    call usb_ep0_lab_get
    mov  [rel usb_ep0_lab_rc_pre], eax
    mov  esi, [rel usb_ep0_lab_ncfg]
    and  esi, 0xFF
    or   esi, 0x0200
    mov  edx, 9
    lea  rcx, [rel usb_ep0_lab_cfg]
    call usb_ep0_lab_get
    mov  [rel usb_ep0_lab_rc_stall], eax
    mov  esi, 0x0100
    mov  edx, 18
    lea  rcx, [rel usb_ep0_lab_post_desc]
    call usb_ep0_lab_get
    mov  [rel usb_ep0_lab_rc_post], eax
    lea  rsi, [rel usb_ep0_lab_pre_desc]
    lea  rdi, [rel usb_ep0_lab_post_desc]
    mov  ecx, 18
    repe cmpsb
    sete al
    movzx eax, al
    mov  [rel usb_ep0_lab_same], eax
    xor  eax, eax
    cmp  dword [rel usb_ep0_lab_rc_pre], 18
    jne  .graded
    cmp  dword [rel usb_ep0_lab_rc_stall], -2
    jne  .graded
    cmp  dword [rel usb_ep0_lab_rc_post], 18
    jne  .graded
    cmp  dword [rel usb_ep0_lab_same], 1
    jne  .graded
    cmp  word [rel usb_ep0_lab_pre_desc], 0x0112   ; bLength 18, bDescriptorType DEVICE
    jne  .graded
    mov  eax, 1
.graded:
    mov  [rel usb_ep0_lab_ok], eax
    add  r15d, eax
    lea  rdi, [rel str_ep0_lab_port]
    call serial_string
    mov  edi, r13d
    call serial_hex64
    lea  rdi, [rel str_ep0_lab_hid]
    call serial_string
    mov  rdi, r12
    mov  esi, r13d
    call usb_hid_port_owned
    mov  edi, eax
    call serial_hex64
    lea  rdi, [rel str_ep0_lab_pre]
    call serial_string
    mov  edi, [rel usb_ep0_lab_rc_pre]
    call serial_hex64
    lea  rdi, [rel str_ep0_lab_stall]
    call serial_string
    mov  edi, [rel usb_ep0_lab_rc_stall]
    call serial_hex64
    lea  rdi, [rel str_ep0_lab_post]
    call serial_string
    mov  edi, [rel usb_ep0_lab_rc_post]
    call serial_hex64
    lea  rdi, [rel str_ep0_lab_same]
    call serial_string
    mov  edi, [rel usb_ep0_lab_same]
    call serial_hex64
    lea  rdi, [rel str_ep0_lab_pass]
    cmp  dword [rel usb_ep0_lab_ok], 1
    je   .say
    lea  rdi, [rel str_ep0_lab_fail]
.say:
    call serial_string
    call usb_ep0_lab_short
.next:
    inc  ebx
    jmp  .dev
.verdict:
    lea  rdi, [rel str_ep0_short_sum]
    call serial_string
    mov  edi, r14d
    call serial_hex64
    lea  rdi, [rel str_ep0_lab_sum_passed]
    call serial_string
    mov  edi, [rel usb_ep0_lab_short_pass]
    call serial_hex64
    lea  rdi, [rel str_ep0_short_sum_fail]
    test r14d, r14d
    jz   .short_say
    cmp  r14d, [rel usb_ep0_lab_short_pass]
    jne  .short_say
    lea  rdi, [rel str_ep0_short_sum_pass]
.short_say:
    call serial_string
    lea  rdi, [rel str_ep0_lab_sum]
    call serial_string
    mov  edi, r14d
    call serial_hex64
    lea  rdi, [rel str_ep0_lab_sum_passed]
    call serial_string
    mov  edi, r15d
    call serial_hex64
    lea  rdi, [rel str_ep0_lab_sum_fail]
    test r14d, r14d
    jz   .sum_say
    cmp  r14d, r15d
    jne  .sum_say
    lea  rdi, [rel str_ep0_lab_sum_pass]
.sum_say:
    call serial_string
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; usb_ep0_lab_short(R12 = hc dev*, R13D = root port) — the probe's short-read step:
;   one "USBEP0SHORT port= rc= total= canary= PASS|FAIL" line.
usb_ep0_lab_short:
    lea  rdi, [rel usb_ep0_lab_long]
    mov  al, 0xA5
    mov  ecx, 256
    rep  stosb
    mov  esi, 0x0200
    mov  edx, 255
    lea  rcx, [rel usb_ep0_lab_long]
    mov  r8d, 256
    call usb_ep0_lab_get_cap
    mov  [rel usb_ep0_lab_rc_short], eax
    movzx ecx, word [rel usb_ep0_lab_long + 2]      ; wTotalLength
    mov  [rel usb_ep0_lab_total], ecx
    xor  edx, edx
    cmp  eax, 255
    ja   .canary_done                 ; failure codes and over-reports skip the scan
    lea  rdi, [rel usb_ep0_lab_long]
    add  rdi, rax
    mov  ecx, 256
    sub  ecx, eax
    mov  al, 0xA5
    repe scasb
    jne  .canary_done
    mov  edx, 1
.canary_done:
    mov  [rel usb_ep0_lab_canary], edx
    xor  eax, eax
    mov  ecx, [rel usb_ep0_lab_rc_short]
    cmp  ecx, [rel usb_ep0_lab_total]
    jne  .graded
    cmp  ecx, 9
    jb   .graded
    cmp  dword [rel usb_ep0_lab_canary], 1
    jne  .graded
    mov  eax, 1
.graded:
    add  [rel usb_ep0_lab_short_pass], eax
    push rax
    lea  rdi, [rel str_ep0_short_port]
    call serial_string
    mov  edi, r13d
    call serial_hex64
    lea  rdi, [rel str_ep0_short_rc]
    call serial_string
    mov  edi, [rel usb_ep0_lab_rc_short]
    call serial_hex64
    lea  rdi, [rel str_ep0_short_total]
    call serial_string
    mov  edi, [rel usb_ep0_lab_total]
    call serial_hex64
    lea  rdi, [rel str_ep0_short_canary]
    call serial_string
    mov  edi, [rel usb_ep0_lab_canary]
    call serial_hex64
    pop  rax
    lea  rdi, [rel str_ep0_lab_pass]
    test eax, eax
    jnz  .say
    lea  rdi, [rel str_ep0_lab_fail]
.say:
    jmp  serial_string

; usb_ep0_lab_get(R12 = hc dev*, R13D = root port, ESI = wValue, EDX = wLength,
;   RCX = 18-byte buffer) -> RAX = the control seam's result (len / -1 / -2).
;   usb_ep0_lab_get_cap takes the buffer capacity in R8D instead.
usb_ep0_lab_get:
    mov  r8d, 18
usb_ep0_lab_get_cap:
    lea  rax, [rel usb_ep0_lab_setup]
    mov  byte [rax + usb_setup.bmRequestType], 0x80
    mov  byte [rax + usb_setup.bRequest], 6
    mov  word [rax + usb_setup.wValue], si
    mov  word [rax + usb_setup.wIndex], 0
    mov  word [rax + usb_setup.wLength], dx
    mov  rsi, rax
    mov  rdi, r12
    mov  edx, r13d
    mov  rax, [r12 + dev.ops]
    jmp  [rax + usbhc_ops.control]

str_ep0_lab_port:  db "USBEP0PROBE port=", 0
str_ep0_lab_hid:   db " hid=", 0
str_ep0_lab_pre:   db " pre=", 0
str_ep0_lab_stall: db " stall=", 0
str_ep0_lab_post:  db " post=", 0
str_ep0_lab_same:  db " same=", 0
str_ep0_lab_pass:  db " PASS", 13, 10, 0
str_ep0_lab_fail:  db " FAIL", 13, 10, 0
str_ep0_lab_sum:   db "USBEP0PROBE devices=", 0
str_ep0_lab_sum_passed: db " passed=", 0
str_ep0_lab_sum_pass: db " PASS [lab.usb.xhci.ep0.halt.recovery]", 13, 10, 0
str_ep0_lab_sum_fail: db " FAIL [lab.usb.xhci.ep0.halt.recovery]", 13, 10, 0
str_ep0_short_port:   db "USBEP0SHORT port=", 0
str_ep0_short_rc:     db " rc=", 0
str_ep0_short_total:  db " total=", 0
str_ep0_short_canary: db " canary=", 0
str_ep0_short_sum:    db "USBEP0SHORT devices=", 0
str_ep0_short_sum_pass: db " PASS [lab.usb.xhci.ep0.short_read]", 13, 10, 0
str_ep0_short_sum_fail: db " FAIL [lab.usb.xhci.ep0.short_read]", 13, 10, 0
%endif

%ifndef PAOS_USB_HID_TOKEN
%define PAOS_USB_HID_TOKEN "0000000000000000"
%endif

%include "dev/usb/hid_owned.inc"

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_dev_usb_hid_0 0
align 8
usb_hid_owned_serial: dq 0
usb_hid_owned_records: times (USB_HID_MAX_STATES * 96) db 0
usb_hid_owned_holds: times (USB_HID_MAX_STATES * 112) db 0
usb_hid_owned_indices: times USB_HID_MAX_STATES dd 0
usb_hid_owned_eligible: times USB_HID_MAX_STATES db 0
usb_hid_owned_enum_index: dd 0
usb_hid_owned_allow_hc: dq 0
usb_hid_owned_allow_root: dd 0
align 16
usb_hid_pointer_buttons: times (USB_HID_MAX_STATES + 1) db 0
usb_hid_pointer_cancel: times (USB_HID_MAX_STATES + 1) db 0
align 8
usb_hid_led_epochs: times USB_HID_MAX_STATES dq 0
usb_hid_led_states: times (USB_HID_MAX_STATES * USB_HID_LED_CONTEXT) db 0
usb_hid_led_cursor: dd 0
usb_hid_led_locks: db 0
usb_hid_led_locks_valid: db 0
align 8
usb_hid_reconnect_roots: times (USB_HID_MAX_STATES * 16) db 0
usb_hid_reconnect_cursor: dd 0
usb_hid_reconnect_passes: dd 0
usb_hid_discovery_passes: dd 0
align 8
usb_hid_states: times (USB_HID_MAX_STATES * usb_hid_state_size) db 0
usb_hid_states_end:
usb_hid_kat_state: times usb_hid_state_size db 0
usb_hid_scan_cursor: dd 0              ; discovery scratch, never accepted state
usb_hid_capacity_refusals: dq 0        ; no free HID slot, live/retired custody retained
usb_hid_interface_refusals: dq 0       ; report profile or class/endpoint/queue refusal
usb_hid_report_candidate: db 0
usb_hid_report_interface: db 0
usb_hid_report_descriptor_len: dw 0
usb_hid_report_descriptor_current: dw 0
usb_hid_report_candidate_map: times USB_HID_REPORT_MAP_SIZE db 0
usb_hid_multi_candidate: times USB_HID_MULTI_SIZE db 0
usb_hid_multi_states: times (USB_HID_MAX_STATES * USB_HID_MULTI_SIZE) db 0
usb_hid_multi_project: times (USB_HID_MULTI_REPORTS * USB_HID_REPORT_DESC_CAP) db 0
usb_hid_report_maps: times (USB_HID_MAX_STATES * USB_HID_REPORT_MAP_SIZE) db 0
usb_hid_report_buffers: times (USB_HID_MAX_STATES * USB_HID_REPORT_WIRE_CAP) db 0
usb_hid_report_descriptor: times USB_HID_REPORT_DESC_CAP db 0
usb_hid_report_ep: times (usb_endpoint_desc_size + 6) db 0
usb_hid_config: times USB_HID_CONFIG_CAP db 0
usb_hid_setup: times usb_setup_size db 0
usb_hid_kbd_ep: times (usb_endpoint_desc_size + 6) db 0
usb_hid_mouse_ep: times (usb_endpoint_desc_size + 6) db 0
usb_hid_test_report: times 9 db 0
usb_hid_scancode_batch: times 32 db 0

usb_hid_test_tablet:
    db 9, USB_DT_CONFIG, 34, 0, 1, 1, 0, 0x80, 50
    db 9, USB_DT_INTERFACE, 0, 0, 1, 3, 0, 0, 0
    db 9, 0x21, 0x11, 1, 0, 1, 0x22, 63, 0
    db 7, USBD_TYPE_ENDPOINT, 0x81, USB_EP_XFER_INTR, 8, 0, 10
usb_hid_test_tablet_end:

usb_hid_to_scancode:
    db 0x00,0x00,0x00,0x00,0x1E,0x30,0x2E,0x20
    db 0x12,0x21,0x22,0x23,0x17,0x24,0x25,0x26
    db 0x32,0x31,0x18,0x19,0x10,0x13,0x1F,0x14
    db 0x16,0x2F,0x11,0x2D,0x15,0x2C,0x02,0x03
    db 0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B
    db 0x1C,0x01,0x0E,0x0F,0x39,0x0C,0x0D,0x1A
    db 0x1B,0x2B,0x2B,0x27,0x28,0x29,0x33,0x34
    db 0x35,0x3A,0x3B,0x3C,0x3D,0x3E,0x3F,0x40
    db 0x41,0x42,0x43,0x44,0x57,0x58,0x37,0x46
    db 0x00,0x52,0x47,0x49,0x53,0x4F,0x51,0x4D
    db 0x4B,0x50,0x48,0x45,0x35,0x37,0x4A,0x4E
    db 0x1C,0x4F,0x50,0x51,0x4B,0x4C,0x4D,0x47
    db 0x48,0x49,0x52,0x53
    db 0x56                             ; 0x64 Non-US \| (ISO B00), Set-1 56 (RCQ-38 L0)
    db 0,0,0                            ; 0x65 Application, 0x66 Power, 0x67 keypad =: none
    db 0x64,0x65,0x66,0x67,0x68,0x69    ; 0x68..0x73 F13..F24, the IBM Set-1 makes (RCQ-51): F23 6E
    db 0x6A,0x6B,0x6C,0x6D,0x6E,0x76    ;   is the Copilot key's (Win+Shift+F23); the router decides
    times (0x87 - 0x74) db 0
    db 0x73,0x70,0x7D,0x79,0x7B         ; 0x87..0x8B JIS Ro, Kana, Yen, Henkan, Muhenkan
    times (256 - 0x8C) db 0

usb_hid_modifier_scancode: db 0x1D,0x2A,0x38,0x5B,0x1D,0x36,0x38,0x5C
usb_hid_modifier_e0:       db 0,0,0,1,1,0,1,1
; Set-1 makes (E0<<8 | code) that never repeat: Ctrl, Shift, Alt, Win,
; CapsLock, NumLock, ScrollLock, PrintScreen/SysRq and fake Shift.
; This is the USB repeat policy; Pause is handled as one E1 make.
usb_hid_repeat_never: dw 0x1D,0x2A,0x36,0x38,0x11D,0x138,0x15B,0x15C,0x3A,0x45,0x46,0x137,0x54,0x12A,0x136,0

align 8
usb_hid_refused_wrong_slot: dq 0
usb_hid_refused_stale:      dq 0
usb_hid_refused_duplicate:  dq 0
usb_hid_refused_absolute:   dq 0
usb_hid_refused_rollover:   dq 0
usb_hid_refused_malformed:  dq 0
usb_hid_idle_stalls:        dq 0
usb_hid_mouse_reports:      dq 0        ; every boot-mouse report seen (accepted or refused)
usb_hid_poll_ticks:         dq 0        ; usb_hid_poll_all passes since boot
usb_hid_repeat_owner:       dq 0        ; state owning the repeating key, 0 = none
usb_hid_repeat_due:         dq 0        ; monotonic us of the next repeat
usb_hid_repeat_last:        dq 0        ; latest valid sample for this armed press
usb_hid_repeat_key:         dw 0        ; Set-1 make of the repeating key: E0<<8 | code
usb_hid_last_mouse_raw:     times 4 db 0 ; buttons, dx, dy of the last report
usb_hid_proof_ps2_kbd:      dq 0
usb_hid_proof_ps2_mouse:    dq 0
usb_hid_kat_cursor_x:       dd 0
usb_hid_kat_cursor_y:       dd 0
usb_hid_proof_cursor_x:     dd 0
usb_hid_proof_cursor_y:     dd 0
usb_hid_diag_kep:           dd 0
usb_hid_diag_mep:           dd 0
usb_hid_active_count:       db 0
usb_hid_kbd_candidate:      db 0
usb_hid_mouse_candidate:    db 0
usb_hid_kbd_interface:      db 0
usb_hid_mouse_interface:    db 0
usb_hid_batch_count:        db 0
usb_hid_modifier_changed:   db 0
usb_hid_reset_kat_ok:       db 0
usb_hid_detach_kat_ok:      db 0
usb_hid_hostile_kat_ok:     db 0
usb_hid_marker_emitted:     db 0
usb_hid_proof_kbd_head:     db 0
usb_hid_task_started:       db 0
usb_hid_task_running:       db 0
usb_hid_retiring:           db 0        ; RCQ-09: 1 while usb_hid_release_state commits a retired keyboard's breaks

str_usb_hid_ready: db "USBHID READY", 13, 10, 0
str_usb_hid_bound: db "USBHID bound kind=", 0
str_usb_hid_bound_port: db " port=", 0
str_usb_hid_bound_slot: db " slot=", 0
str_usb_hid_bound_ep: db " ep=", 0
str_usb_hid_bound_end: db 13, 10, 0
str_usb_hid_poll_ready: db "USBHID POLL_READY", 13, 10, 0
str_usb_hid_receipt: db "USBHID token=", PAOS_USB_HID_TOKEN, " slots=", 0
str_usb_hid_comma: db ",", 0
str_usb_hid_receipt_tail: db " kbd=e04d mouse_dx=17 mouse_dy=-9 buttons=1 usb_kbd=1 usb_mouse=1 ps2_kbd_delta=0 ps2_mouse_delta=0 wrong_slot=refused stale=refused duplicate=refused absolute=refused rollover=refused malformed=refused", 13, 10, 0
str_usb_hid_marker: db "[PAOS64] usb: boot keyboard and relative mouse content KAT PASS [usb.hid.boot.input.kat]", 13, 10, 0
str_usb_hid_diag_q: db "USBHID DIAG q=", 0
str_usb_hid_diag_c: db " c=", 0
str_usb_hid_diag_kseq: db " kseq=", 0
str_usb_hid_diag_mseq: db " mseq=", 0
str_usb_hid_diag_klen: db " klen=", 0
str_usb_hid_diag_mlen: db " mlen=", 0
str_usb_hid_diag_mraw: db " mraw=", 0
str_usb_hid_diag_slash: db "/", 0
str_usb_hid_diag_kep: db " kep_pc=", 0
str_usb_hid_diag_mep: db " mep_pc=", 0
str_usb_hid_diag_head: db " head=", 0
str_usb_hid_diag_x: db " x=", 0
str_usb_hid_diag_y: db " y=", 0
str_usb_hid_diag_btn: db " btn=", 0
str_usb_hid_diag_wrong: db " wrong=", 0
str_usb_hid_diag_stale: db " stale=", 0
str_usb_hid_diag_dup: db " dup=", 0
str_usb_hid_diag_bad: db " bad=", 0
%endmacro
WDATA_DEFER WDATA_dev_usb_hid_0
%ifdef PAOS_LAB_EP0_PROBE
%macro WDATA_dev_usb_hid_lab_ep0 0
align 16
usb_ep0_lab_pre_desc:  times 18 db 0
align 16
usb_ep0_lab_post_desc: times 18 db 0
align 16
usb_ep0_lab_cfg:       times 18 db 0
align 8
usb_ep0_lab_setup:     times usb_setup_size db 0
usb_ep0_lab_ncfg:      dd 0
usb_ep0_lab_rc_pre:    dd 0
usb_ep0_lab_rc_stall:  dd 0
usb_ep0_lab_rc_post:   dd 0
usb_ep0_lab_same:      dd 0
usb_ep0_lab_ok:        dd 0
usb_ep0_lab_rc_short:  dd 0
usb_ep0_lab_total:     dd 0
usb_ep0_lab_canary:    dd 0
usb_ep0_lab_short_pass: dd 0
align 16
usb_ep0_lab_long:      times 256 db 0
%endmacro
WDATA_DEFER WDATA_dev_usb_hid_lab_ep0
%endif

%macro WDATA_dev_usb_hid_obs 0
alignb 8
usb_hid_obs_epoch: resq 1
usb_hid_obs_total: resq 1
usb_hid_obs_drops: resq 1
usb_hid_obs_live_state: resq 1
usb_hid_obs_serial: resd 1
usb_hid_obs_pending: resd 1
usb_hid_obs_head: resd 1
usb_hid_obs_tail: resd 1
usb_hid_obs_test_depth: resd 1
usb_hid_obs_reason: resb 1
usb_hid_obs_frozen: resb 1
alignb 8
usb_hid_obs_queue: resb USB_HID_OBS_N * USB_HID_OBS_SZ
%endmacro
WDATA_BSS_DEFER WDATA_dev_usb_hid_obs

%macro WDATA_dev_usb_hid_census 0
align 4
usb_hid_census_interfaces: times USB_HID_MAX_STATES dd 0
usb_hid_census_pending: db 0
%endmacro
WDATA_DEFER WDATA_dev_usb_hid_census
