;; MODULE hv/guestinput
%include "hv/guest_power.inc"

;; LAYER 5
;; EXPORTS guestinput_verb, guestinput_state_zero, guestinput_device_reset, guestinput_mmio_write, guestinput_pump, guestinput_try_inject_irq, guestinput_post_key, guestinput_post_pointer, guestinput_post_wheel, guestinput_post_pause, guestinput_release_all, guestinput_release_retry, guestinput_release_blocked, guestinput_render_stat, gi_live, gi_posted, gi_delivered, gi_dropped, gi_refused, gi_owner_epoch
;; IMPORTS hv/guest_power, hv/vmx, hv/hv_ops, hv/vm_profile
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; ============================================================================
; RCQ-23 S1: one virtio-input keyboard+pointer for the desktop-linux guest.
;
; Device: GPA 0xD0002000 (third virtio-mmio page, control+HV_GUESTIN_PAGE),
; PIC IRQ1, DeviceID 18, queues 0=eventq (device->driver) / 1=statusq.
; Same trap contract as the console and net pages: guest reads hit the register
; page, every store exits and is decoded. virtio-input's config select/subsel
; are byte stores (writeb), so this page is the one place a decoded 88 /r store
; is accepted (vmx.asm hv_linux_virtio_mmio refuses byte stores elsewhere).
;
; What the guest is told (config space, fixed):
;   ID_NAME "PaOS desktop input", ID_DEVIDS bus 6 (virtual) vendor 0x5041
;   product 0x0023 version 1; EV_KEY bits 1..127 + BTN_LEFT/RIGHT/MIDDLE;
;   EV_ABS bits ABS_X/ABS_Y with ranges 0..VP_FB_WIDTH-1 / 0..VP_FB_HEIGHT-1,
;   one guest pixel per unit; EV_REL REL_WHEEL, signed wheel notches.
;   No other relative axis and no LEDs.
;
; Event path: PaOS posts whole event groups (each ends with EV_SYN) into a
; single-producer ring (the desktop window and the owner-signed GUESTVM INPUT
; verb, both in the idle context). guestinput_pump, at a clean VM-exit resume,
; moves events into device-writable eventq buffers and raises IRQ1. A group is
; posted whole or not at all: if the ring cannot take it, it is dropped and
; counted. Capture-loss releases instead retain a bounded retry obligation and
; block external input until the final SYN is delivered. Nothing is posted unless the driver is live (DRIVER_OK + both queues).
; ============================================================================

GI_QMAX          equ 64
GI_RELEASE_BUDGET equ 8                    ; whole release groups per idle/pump
GI_RING          equ 256                   ; host event ring entries (power of two)
GI_EV_BYTES      equ 8                     ; struct virtio_input_event: le16 type, le16 code, le32 value
GI_CFG           equ 0x100                 ; virtio_input_config in the register page
GI_CFG_U         equ 0x108                 ; its union
GI_CFG_U_BYTES   equ 128
GI_IRQ_MASK      equ 0x02                  ; PIC line 1
GI_IRQ_LINE      equ 1

GI_EV_SYN        equ 0
GI_EV_KEY        equ 1
GI_EV_REL        equ 2
GI_REL_WHEEL     equ 8
GI_EV_ABS        equ 3
GI_BTN_LEFT      equ 0x110
GI_KEY_MAX       equ 127                   ; highest key code PaOS can produce

GI_CFG_ID_NAME   equ 0x01
GI_CFG_ID_DEVIDS equ 0x03
GI_CFG_EV_BITS   equ 0x11
GI_CFG_ABS_INFO  equ 0x12

; ---------------------------------------------------------------------------
; Device state
; ---------------------------------------------------------------------------
guestinput_state_zero:
    HV_POWER_WORK guestinput_state_zero, 0, hv_guest_power_admit
    inc  qword [rel gi_owner_epoch]         ; outside cleared state: revoke old snapshots
    push rdi
    push rcx
    lea  rdi, [rel gi_state_begin]
    mov  ecx, gi_state_end - gi_state_begin
    xor  eax, eax
    cld
    rep  stosb
    pop  rcx
    pop  rdi
    ret

; guestinput_device_reset — a fresh register page and state for a new START.
guestinput_device_reset:
    HV_POWER_WORK guestinput_device_reset, 0, hv_guest_power_admit
    call guestinput_state_zero
    mov  rdx, [rel hv_linux_region]
    test rdx, rdx
    jz   .done
    lea  rdi, [rdx + HV_GUESTIN_PAGE]
    push rdi
    mov  ecx, 4096 / 8
    xor  eax, eax
    cld
    rep  stosq
    pop  rdx
    mov  dword [rdx + 0x000], 0x74726976    ; "virt"
    mov  dword [rdx + 0x004], 2             ; modern transport
    mov  dword [rdx + 0x008], 18            ; virtio-input
    mov  dword [rdx + 0x00C], 0x536F6150    ; "PaOS"
    mov  dword [rdx + 0x034], GI_QMAX
.done:
    ret

gi_page:
    mov  rax, [rel hv_linux_region]
    lea  rax, [rax + HV_GUESTIN_PAGE]
    ret

guestinput_raise_irq:
    or   dword [rel gi_isr], 1
    call gi_page
    mov  edx, [rel gi_isr]
    mov  [rax + 0x60], edx
    mov  byte [rel gi_irq_pending], 1
    ret

gi_eval_live:
    cmp  byte [rel gi_driver_ok], 1
    jne  .no
    cmp  byte [rel gi_q_ready], 1
    jne  .no
    cmp  byte [rel gi_q_ready + 1], 1
    jne  .no
    mov  byte [rel gi_live], 1
    ret
.no:
    mov  byte [rel gi_live], 0
    ret

; guestinput_mmio_write(EDI=offset in page, ESI=value, EDX=store width 1|4).
guestinput_mmio_write:
    HV_POWER_WORK guestinput_mmio_write, 0, hv_guest_power_io_admit
    cmp  edi, 0x050
    je   .epoch_ok
    cmp  edi, 0x064
    je   .epoch_ok
    inc  qword [rel gi_owner_epoch]         ; configuration/reset revokes any private group
.epoch_ok:
    push rbx
    inc  dword [rel gi_mmio_writes]
    call gi_page
    mov  rbx, rax
    cmp  edx, 1
    je   .byte_store
    cmp  edx, 4
    jne  .bad
    cmp  edi, GI_CFG
    jae  .bad                               ; config is select/subsel bytes only
    cmp  edi, 0x014
    je   .dfsel
    cmp  edi, 0x020
    je   .drvfeat
    cmp  edi, 0x024
    je   .drvfsel
    cmp  edi, 0x030
    je   .qsel
    cmp  edi, 0x038
    je   .qnum
    cmp  edi, 0x044
    je   .qready
    cmp  edi, 0x050
    je   .notify
    cmp  edi, 0x064
    je   .intack
    cmp  edi, 0x070
    je   .status
    cmp  edi, 0x080
    je   .desc_lo
    cmp  edi, 0x084
    je   .desc_hi
    cmp  edi, 0x090
    je   .avail_lo
    cmp  edi, 0x094
    je   .avail_hi
    cmp  edi, 0x0A0
    je   .used_lo
    cmp  edi, 0x0A4
    je   .used_hi
    jmp  .done                              ; read-only or reserved register: ignored
.byte_store:
    cmp  edi, GI_CFG
    je   .cfg_select
    cmp  edi, GI_CFG + 1
    je   .cfg_subsel
.bad:
    inc  dword [rel gi_bad_writes]
    jmp  .done
.cfg_select:
    mov  [rel gi_cfg_sel], sil
    mov  [rbx + GI_CFG], sil
    call gi_cfg_fill
    jmp  .done
.cfg_subsel:
    mov  [rel gi_cfg_sub], sil
    mov  [rbx + GI_CFG + 1], sil
    call gi_cfg_fill
    jmp  .done
.dfsel:
    xor  eax, eax
    cmp  esi, 1
    jne  .df_store
    mov  eax, 1                             ; VIRTIO_F_VERSION_1 (bit 32); no other feature
.df_store:
    mov  [rbx + 0x010], eax
    jmp  .done
.drvfeat:
    mov  eax, [rel gi_drvfsel]
    cmp  eax, 1
    ja   .done
    lea  rdx, [rel gi_drvfeat]
    mov  [rdx + rax*4], esi
    jmp  .done
.drvfsel:
    mov  [rel gi_drvfsel], esi
    jmp  .done
.qsel:
    mov  [rel gi_qsel], esi
    cmp  esi, 2
    jae  .qsel_bad
    mov  dword [rbx + 0x034], GI_QMAX
    lea  rdx, [rel gi_q_ready]
    movzx eax, byte [rdx + rsi]
    mov  [rbx + 0x044], eax
    jmp  .done
.qsel_bad:
    mov  dword [rbx + 0x034], 0
    mov  dword [rbx + 0x044], 0
    jmp  .done
.qnum:
    mov  eax, [rel gi_qsel]
    cmp  eax, 2
    jae  .done
    lea  rdx, [rel gi_q_num]
    mov  [rdx + rax*4], esi                 ; validated (power of two, <= QMAX) at use
    jmp  .done
.qready:
    mov  eax, [rel gi_qsel]
    cmp  eax, 2
    jae  .done
    and  esi, 1
    lea  rdx, [rel gi_q_ready]
    mov  [rdx + rax], sil
    mov  [rbx + 0x044], esi
    call gi_eval_live
    jmp  .done
.notify:
    inc  dword [rel gi_notifies]
    cmp  esi, 1
    jne  .done                              ; eventq refills are consumed by the pump
    call gi_serve_status
    jmp  .done
.intack:
    mov  eax, esi
    not  eax
    and  [rel gi_isr], eax
    mov  eax, [rel gi_isr]
    mov  [rbx + 0x060], eax
    mov  byte [rel gi_irq_injected], 0
    test eax, eax
    jnz  .done
    mov  byte [rel gi_irq_pending], 0
    jmp  .done
.status:
    mov  [rbx + 0x070], esi
    test esi, esi
    jnz  .status_set
    ; Device reset by the driver: queues, interrupt and every pending event go.
    xor  eax, eax
    mov  [rbx + 0x060], eax
    mov  [rbx + 0x044], eax
    mov  [rel gi_isr], eax
    mov  [rel gi_q_ready], ax
    mov  [rel gi_q_lastav], eax
    mov  [rel gi_q_usedidx], eax
    mov  [rel gi_driver_ok], al
    mov  [rel gi_live], al
    mov  [rel gi_irq_pending], al
    mov  [rel gi_irq_injected], al
    mov  [rel gi_release_pending], al
    mov  [rel gi_ptr_buttons], al           ; F8: a reset driver holds nothing
    mov  [rel gi_keys_down], rax
    mov  [rel gi_keys_down + 8], rax
    mov  eax, [rel gi_head]
    sub  eax, [rel gi_tail]
    add  [rel gi_canceled], eax
    mov  eax, [rel gi_head]
    mov  [rel gi_tail], eax
    jmp  .done
.status_set:
    test esi, 4                             ; DRIVER_OK
    jz   .done
    mov  byte [rel gi_driver_ok], 1
    call gi_eval_live
    jmp  .done
.desc_lo:
    lea  rdx, [rel gi_q_desc]
    jmp  .addr_lo
.desc_hi:
    lea  rdx, [rel gi_q_desc]
    jmp  .addr_hi
.avail_lo:
    lea  rdx, [rel gi_q_avail]
    jmp  .addr_lo
.avail_hi:
    lea  rdx, [rel gi_q_avail]
    jmp  .addr_hi
.used_lo:
    lea  rdx, [rel gi_q_used]
    jmp  .addr_lo
.used_hi:
    lea  rdx, [rel gi_q_used]
.addr_hi:
    mov  eax, [rel gi_qsel]
    cmp  eax, 2
    jae  .done
    mov  [rdx + rax*8 + 4], esi
    jmp  .done
.addr_lo:
    mov  eax, [rel gi_qsel]
    cmp  eax, 2
    jae  .done
    mov  [rdx + rax*8], esi
.done:
    pop  rbx
    ret

; gi_cfg_fill — answer the (select, subsel) the driver just wrote: the size
; byte and the union, all other config bytes zero. RBX = register page.
gi_cfg_fill:
    inc  dword [rel gi_cfg_selects]
    lea  rdi, [rbx + GI_CFG + 2]            ; size, reserved[5], union
    mov  ecx, GI_CFG_U + GI_CFG_U_BYTES - GI_CFG - 2
    xor  eax, eax
    cld
    rep  stosb
    movzx eax, byte [rel gi_cfg_sel]
    movzx edx, byte [rel gi_cfg_sub]
    cmp  eax, GI_CFG_ID_NAME
    je   .name
    cmp  eax, GI_CFG_ID_DEVIDS
    je   .devids
    cmp  eax, GI_CFG_EV_BITS
    je   .ev_bits
    cmp  eax, GI_CFG_ABS_INFO
    je   .abs_info
    ret                                     ; size 0: nothing to say
.name:
    test edx, edx
    jnz  .out
    lea  rsi, [rel str_gi_name]
    lea  rdi, [rbx + GI_CFG_U]
    mov  ecx, str_gi_name_len
    rep  movsb
    mov  byte [rbx + GI_CFG + 2], str_gi_name_len
    ret
.devids:
    test edx, edx
    jnz  .out
    mov  word [rbx + GI_CFG_U + 0], 6       ; BUS_VIRTUAL
    mov  word [rbx + GI_CFG_U + 2], 0x5041
    mov  word [rbx + GI_CFG_U + 4], 0x0023
    mov  word [rbx + GI_CFG_U + 6], 1
    mov  byte [rbx + GI_CFG + 2], 8
    ret
.ev_bits:
    cmp  edx, GI_EV_KEY
    je   .key_bits
    cmp  edx, GI_EV_REL
    je   .rel_bits
    cmp  edx, GI_EV_ABS
    jne  .out
    mov  byte [rbx + GI_CFG_U], 0x03        ; ABS_X | ABS_Y
    mov  byte [rbx + GI_CFG + 2], 1
    ret
.rel_bits:
    mov  byte [rbx + GI_CFG_U + GI_REL_WHEEL / 8], 1
    mov  byte [rbx + GI_CFG + 2], GI_REL_WHEEL / 8 + 1
    ret
.key_bits:
    ; Codes 1..127 (every Set-1 key PaOS translates) and the three buttons.
    mov  byte [rbx + GI_CFG_U], 0xFE
    lea  rdi, [rbx + GI_CFG_U + 1]
    mov  ecx, (GI_KEY_MAX + 1) / 8 - 1
    mov  al, 0xFF
    rep  stosb
    mov  byte [rbx + GI_CFG_U + GI_BTN_LEFT / 8], 0x07
    mov  byte [rbx + GI_CFG + 2], GI_BTN_LEFT / 8 + 1
    ret
.abs_info:
    mov  eax, VP_FB_WIDTH - 1
    test edx, edx                           ; ABS_X
    jz   .abs
    mov  eax, VP_FB_HEIGHT - 1
    cmp  edx, 1                             ; ABS_Y
    jne  .out
.abs:
    mov  dword [rbx + GI_CFG_U + 0], 0      ; min
    mov  [rbx + GI_CFG_U + 4], eax          ; max
    mov  byte [rbx + GI_CFG + 2], 20        ; min, max, fuzz, flat, res
.out:
    ret

; gi_queue(ESI=queue) -> RAX=avail HVA, RDX=used HVA, R8=desc HVA,
; R9D=queue size, or RAX=0 when the queue is unusable. Validates the size
; (power of two, 1..QMAX) and every ring through the bounded GPA->HVA lookup.
gi_queue:
    push rbx
    push r12
    push r13
    push r14
    mov  ebx, esi
    lea  rax, [rel gi_q_ready]
    cmp  byte [rax + rbx], 1
    jne  .bad
    lea  rax, [rel gi_q_num]
    mov  r12d, [rax + rbx*4]
    test r12d, r12d
    jz   .bad
    cmp  r12d, GI_QMAX
    ja   .bad
    lea  eax, [r12 - 1]
    test eax, r12d
    jnz  .bad
    lea  rax, [rel gi_q_avail]
    mov  rdi, [rax + rbx*8]
    lea  esi, [r12 * 2 + 6]
    call hv_linux_gpa2hva
    test rax, rax
    jz   .bad
    mov  r13, rax
    lea  rax, [rel gi_q_used]
    mov  rdi, [rax + rbx*8]
    lea  esi, [r12 * 8 + 6]
    call hv_linux_gpa2hva
    test rax, rax
    jz   .bad
    mov  r14, rax
    lea  rax, [rel gi_q_desc]
    mov  rdi, [rax + rbx*8]
    mov  esi, r12d
    shl  esi, 4
    call hv_linux_gpa2hva
    test rax, rax
    jz   .bad
    mov  r8, rax
    mov  rdi, r13
    lea  esi, [r12*2 + 6]
    mov  rdx, r14
    lea  ecx, [r12*8 + 6]
    call gi_apart
    test eax, eax
    jz   .bad
    mov  rdi, r13
    lea  esi, [r12*2 + 6]
    mov  rdx, r8
    mov  ecx, r12d
    shl  ecx, 4
    call gi_apart
    test eax, eax
    jz   .bad
    mov  rdi, r14
    lea  esi, [r12*8 + 6]
    call gi_apart
    test eax, eax
    jz   .bad
    mov  rax, r13
    mov  rdx, r14
    mov  r9d, r12d
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; gi_apart(RDI/RSI and RDX/RCX extents) -> EAX=1 disjoint, 0 overlap.
; Inputs were translated in full; also reject endpoint carry. Only RAX/R10/R11
; are scratch, so event destination and descriptor ID can survive the checks.
gi_apart:
    mov  r10, rdi
    add  r10, rsi
    jc   .bad
    mov  r11, rdx
    add  r11, rcx
    jc   .bad
    cmp  rdi, r11
    jae  .ok
    cmp  rdx, r10
    jae  .ok
.bad:
    xor  eax, eax
    ret
.ok:
    mov  eax, 1
    ret

; Call-local status completion facts. No guest HVA survives this notification.
struc GI_STATUS_WORK
.ram:       resq 1
.bytes:     resq 1
.region:    resq 1
.epoch:     resq 1
.gen:       resd 1
.status:    resd 1
.queues:    resb 56                         ; both GPAs and sizes, as for eventq
.lastav:    resw 1
.usedidx:   resw 1
.meta:      resb 6 * 16                     ; full translated metadata extents
.size:      resd 1
.count:     resd 1
.ids:       resd GI_QMAX                    ; status payload is never read
endstruc
GI_STATUS_ALLOC equ ((GI_STATUS_WORK_size + 15) & ~15) + 8

; RBP=private status snapshot. Only caller-saved registers are scratch.
gi_status_current:
    cmp  byte [rel hv_linux_running], 1
    jne  .bad
    test dword [rel vm_profile_live_devices], VP_DEV_INPUT
    jz   .bad
    cmp  byte [rel gi_live], 1
    jne  .bad
    cmp  byte [rel gi_driver_ok], 1
    jne  .bad
    cmp  word [rel gi_q_ready], 0x0101
    jne  .bad
    mov  rax, [rel gi_owner_epoch]
    cmp  rax, [rbp + GI_STATUS_WORK.epoch]
    jne  .bad
    mov  eax, [rel hv_linux_start_consumed]
    cmp  eax, [rbp + GI_STATUS_WORK.gen]
    jne  .bad
    mov  rax, [rel hv_linux_ram]
    test rax, rax
    jz   .bad
    cmp  rax, [rbp + GI_STATUS_WORK.ram]
    jne  .bad
    mov  rax, [rel hv_linux_ram_bytes]
    cmp  rax, [rbp + GI_STATUS_WORK.bytes]
    jne  .bad
    mov  rax, [rel hv_linux_region]
    test rax, rax
    jz   .bad
    cmp  rax, [rbp + GI_STATUS_WORK.region]
    jne  .bad
    mov  eax, [rax + HV_GUESTIN_PAGE + 0x070]
    test eax, 0x80                         ; FAILED cannot publish completions
    jnz  .bad
    test eax, 4
    jz   .bad
    cmp  eax, [rbp + GI_STATUS_WORK.status]
    jne  .bad
    lea  rsi, [rel gi_q_desc]
    lea  rdi, [rbp + GI_STATUS_WORK.queues]
    mov  ecx, 7
    cld
    repe cmpsq
    jne  .bad
    mov  ax, [rel gi_q_lastav + 2]
    cmp  ax, [rbp + GI_STATUS_WORK.lastav]
    jne  .bad
    mov  ax, [rel gi_q_usedidx + 2]
    cmp  ax, [rbp + GI_STATUS_WORK.usedidx]
    jne  .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; statusq carries LED updates PaOS has no use for. Return bounded available
; IDs unread, but only to the same live owner and unchanged isolated queues.
gi_serve_status:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, GI_STATUS_ALLOC
    mov  rbp, rsp
    mov  rax, [rel hv_linux_ram]
    mov  [rbp + GI_STATUS_WORK.ram], rax
    mov  rax, [rel hv_linux_ram_bytes]
    mov  [rbp + GI_STATUS_WORK.bytes], rax
    mov  rax, [rel hv_linux_region]
    test rax, rax
    jz   .out
    mov  [rbp + GI_STATUS_WORK.region], rax
    mov  eax, [rax + HV_GUESTIN_PAGE + 0x070]
    mov  [rbp + GI_STATUS_WORK.status], eax
    mov  rax, [rel gi_owner_epoch]
    mov  [rbp + GI_STATUS_WORK.epoch], rax
    mov  eax, [rel hv_linux_start_consumed]
    mov  [rbp + GI_STATUS_WORK.gen], eax
    mov  ax, [rel gi_q_lastav + 2]
    mov  [rbp + GI_STATUS_WORK.lastav], ax
    mov  ax, [rel gi_q_usedidx + 2]
    mov  [rbp + GI_STATUS_WORK.usedidx], ax
    lea  rsi, [rel gi_q_desc]
    lea  rdi, [rbp + GI_STATUS_WORK.queues]
    mov  ecx, 7
    cld
    rep  movsq
    call gi_status_current
    test eax, eax
    jz   .out
    xor  r13d, r13d
.queue:
    mov  esi, r13d
    call gi_queue
    test rax, rax
    jz   .out
    imul ebx, r13d, 48
    lea  rbx, [rbp + rbx + GI_STATUS_WORK.meta]
    mov  [rbx], rax                        ; avail, used, desc full HVA extents
    lea  eax, [r9*2 + 6]
    mov  [rbx + 8], rax
    mov  [rbx + 16], rdx
    lea  eax, [r9*8 + 6]
    mov  [rbx + 24], rax
    mov  [rbx + 32], r8
    mov  eax, r9d
    shl  eax, 4
    mov  [rbx + 40], rax
    mov  [rbp + GI_STATUS_WORK.size], r9d  ; queue 1 wins on the second pass
    call gi_status_current                 ; translations may revoke ownership
    test eax, eax
    jz   .out
    inc  r13d
    cmp  r13d, 2
    jb   .queue
    xor  r13d, r13d
.meta_outer:
    lea  r14d, [r13 + 1]
.meta_inner:
    mov  eax, r13d
    shl  eax, 4
    mov  rdi, [rbp + rax + GI_STATUS_WORK.meta]
    mov  rsi, [rbp + rax + GI_STATUS_WORK.meta + 8]
    mov  eax, r14d
    shl  eax, 4
    mov  rdx, [rbp + rax + GI_STATUS_WORK.meta]
    mov  rcx, [rbp + rax + GI_STATUS_WORK.meta + 8]
    call gi_apart
    test eax, eax
    jz   .out
    inc  r14d
    cmp  r14d, 6
    jb   .meta_inner
    inc  r13d
    cmp  r13d, 5
    jb   .meta_outer
    mov  r12d, [rbp + GI_STATUS_WORK.size]
    mov  rbx, [rbp + GI_STATUS_WORK.meta + 48]
    movzx eax, word [rbx + 2]
    movzx ecx, word [rbp + GI_STATUS_WORK.lastav]
    sub  eax, ecx
    and  eax, 0xFFFF
    cmp  eax, r12d
    ja   .out                              ; stale/overrun producer, no metadata write
    mov  r15d, eax
    xor  r14d, r14d
    lfence
.stage:
    cmp  r14d, r15d
    jae  .staged
    movzx ecx, word [rbp + GI_STATUS_WORK.lastav]
    add  ecx, r14d
    lea  eax, [r12 - 1]
    and  ecx, eax
    movzx edx, word [rbx + 4 + rcx*2]
    cmp  edx, r12d
    jae  .staged                           ; retain the earlier valid bounded prefix
    mov  [rbp + r14*4 + GI_STATUS_WORK.ids], edx
    inc  r14d
    jmp  .stage
.staged:
    test r14d, r14d
    jz   .out
    mov  [rbp + GI_STATUS_WORK.count], r14d
    call gi_status_current
    test eax, eax
    jz   .out
    ; Serialized BSP, stopped vCPU: no translation/callback/yield from the
    ; final owner check through used entries, publication, counters and IRQ.
    mov  r12, [rbp + GI_STATUS_WORK.meta + 64]
    xor  r13d, r13d
.status_commit:
    movzx eax, word [rbp + GI_STATUS_WORK.usedidx]
    add  eax, r13d
    mov  ecx, [rbp + GI_STATUS_WORK.size]
    dec  ecx
    and  eax, ecx
    mov  edx, [rbp + r13*4 + GI_STATUS_WORK.ids]
    mov  [r12 + 4 + rax*8], edx
    mov  dword [r12 + 8 + rax*8], 0
    inc  r13d
    cmp  r13d, [rbp + GI_STATUS_WORK.count]
    jb   .status_commit
    mov  ax, [rbp + GI_STATUS_WORK.usedidx]
    add  ax, r13w
    sfence
    mov  [r12 + 2], ax
    mov  [rel gi_q_usedidx + 2], ax
    add  [rbp + GI_STATUS_WORK.lastav], r13w
    mov  ax, [rbp + GI_STATUS_WORK.lastav]
    mov  [rel gi_q_lastav + 2], ax
    add  [rel gi_status_used], r13d
    call guestinput_raise_irq
.out:
    add  rsp, GI_STATUS_ALLOC
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Private, call-local group facts. No guest address survives a pump/retry.
struc GI_GROUP_WORK
.ram:       resq 1
.bytes:     resq 1
.region:    resq 1
.epoch:     resq 1
.gen:       resd 1
.head:      resd 1
.tail:      resd 1
.lastav:    resw 1
.usedidx:   resw 1
.queues:    resb 56                         ; both desc/avail/used GPAs and sizes
.meta:      resb 6 * 16                     ; HVA/extent for both queues
.count:     resd 1
.size:      resd 1
.status:    resd 1
.ids:       resq 1
.events:    resb GI_QMAX * 32               ; HVA, full extent, event, original ID
endstruc
GI_GROUP_ALLOC equ ((GI_GROUP_WORK_size + 15) & ~15) + 8

; Private helper, RBP=work. Only RAX/RCX/RDX/RSI/RDI/R8-R11 scratch.
; Called before reading owner metadata and immediately before a no-yield commit.
gi_group_current:
    cmp  byte [rel hv_linux_running], 1
    jne  .bad
    test dword [rel vm_profile_live_devices], VP_DEV_INPUT
    jz   .bad
    cmp  byte [rel gi_live], 1
    jne  .bad
    cmp  byte [rel gi_driver_ok], 1
    jne  .bad
    cmp  word [rel gi_q_ready], 0x0101
    jne  .bad
    mov  rax, [rel gi_owner_epoch]
    cmp  rax, [rbp + GI_GROUP_WORK.epoch]
    jne  .bad
    mov  eax, [rel hv_linux_start_consumed]
    cmp  eax, [rbp + GI_GROUP_WORK.gen]
    jne  .bad
    mov  rax, [rel hv_linux_ram]
    cmp  rax, [rbp + GI_GROUP_WORK.ram]
    jne  .bad
    mov  rax, [rel hv_linux_ram_bytes]
    cmp  rax, [rbp + GI_GROUP_WORK.bytes]
    jne  .bad
    mov  rax, [rel hv_linux_region]
    test rax, rax
    jz   .bad
    cmp  rax, [rbp + GI_GROUP_WORK.region]
    jne  .bad
    mov  eax, [rax + HV_GUESTIN_PAGE + 0x070]
    test eax, 0x80                         ; FAILED cannot own event publication
    jnz  .bad
    test eax, 4                            ; current DRIVER_OK, no new feature promise
    jz   .bad
    cmp  eax, [rbp + GI_GROUP_WORK.status]
    jne  .bad
    lea  rsi, [rel gi_q_desc]
    lea  rdi, [rbp + GI_GROUP_WORK.queues]
    mov  ecx, 7
    cld
    repe cmpsq
    jne  .bad
    mov  eax, [rel gi_tail]
    cmp  eax, [rbp + GI_GROUP_WORK.tail]
    jne  .bad
    mov  eax, [rel gi_head]
    cmp  eax, [rbp + GI_GROUP_WORK.head]
    jne  .bad
    mov  ax, [rel gi_q_lastav]
    cmp  ax, [rbp + GI_GROUP_WORK.lastav]
    jne  .bad
    mov  ax, [rel gi_q_usedidx]
    cmp  ax, [rbp + GI_GROUP_WORK.usedidx]
    jne  .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; guestinput_pump — serialized idle/BSP, stopped vCPU, no yield in commit.
; Scan/snapshot one complete SYN_REPORT group, validate every selected buffer,
; then commit the whole group. A blocked/invalid group keeps its entire FIFO
; prefix and release obligation; independent earlier groups may progress.
; At most eventq size events and GI_RING host scan entries per invocation.
guestinput_pump:
    HV_POWER_WORK guestinput_pump, 0, hv_guest_power_io_admit
    call guestinput_release_blocked
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, GI_GROUP_ALLOC
    mov  rbp, rsp
    xor  r15d, r15d                        ; total committed events this call
    mov  qword [rbp + GI_GROUP_WORK.ids], 0
    mov  rax, [rel hv_linux_ram]
    mov  [rbp + GI_GROUP_WORK.ram], rax
    mov  rax, [rel hv_linux_ram_bytes]
    mov  [rbp + GI_GROUP_WORK.bytes], rax
    mov  rax, [rel hv_linux_region]
    test rax, rax
    jz   .out
    mov  [rbp + GI_GROUP_WORK.region], rax
    mov  eax, [rax + HV_GUESTIN_PAGE + 0x070]
    mov  [rbp + GI_GROUP_WORK.status], eax
    mov  rax, [rel gi_owner_epoch]
    mov  [rbp + GI_GROUP_WORK.epoch], rax
    mov  eax, [rel hv_linux_start_consumed]
    mov  [rbp + GI_GROUP_WORK.gen], eax
    mov  eax, [rel gi_head]
    mov  [rbp + GI_GROUP_WORK.head], eax
    mov  eax, [rel gi_tail]
    mov  [rbp + GI_GROUP_WORK.tail], eax
    mov  ax, [rel gi_q_lastav]
    mov  [rbp + GI_GROUP_WORK.lastav], ax
    mov  ax, [rel gi_q_usedidx]
    mov  [rbp + GI_GROUP_WORK.usedidx], ax
    lea  rsi, [rel gi_q_desc]
    lea  rdi, [rbp + GI_GROUP_WORK.queues]
    mov  ecx, 7
    cld
    rep  movsq
    call gi_group_current
    test eax, eax
    jz   .out
    mov  eax, [rbp + GI_GROUP_WORK.head]
    sub  eax, [rbp + GI_GROUP_WORK.tail]
    jz   .out
    cmp  eax, GI_RING
    ja   .out
    xor  r13d, r13d
.queue:
    mov  esi, r13d
    call gi_queue
    test rax, rax
    jz   .out
    imul ebx, r13d, 48
    lea  rbx, [rbp + rbx + GI_GROUP_WORK.meta]
    mov  [rbx], rax                        ; avail, used, descriptor table
    lea  eax, [r9*2 + 6]
    mov  [rbx + 8], rax
    mov  [rbx + 16], rdx
    lea  eax, [r9*8 + 6]
    mov  [rbx + 24], rax
    mov  [rbx + 32], r8
    mov  eax, r9d
    shl  eax, 4
    mov  [rbx + 40], rax
    test r13d, r13d
    jnz  .queue_next
    mov  [rbp + GI_GROUP_WORK.size], r9d
.queue_next:
    inc  r13d
    cmp  r13d, 2
    jb   .queue
    call gi_group_current                 ; translation may have revoked ownership
    test eax, eax
    jz   .out
    xor  r13d, r13d
.meta_outer:
    lea  r14d, [r13 + 1]
.meta_inner:
    mov  eax, r13d
    shl  eax, 4
    mov  rdi, [rbp + rax + GI_GROUP_WORK.meta]
    mov  rsi, [rbp + rax + GI_GROUP_WORK.meta + 8]
    mov  eax, r14d
    shl  eax, 4
    mov  rdx, [rbp + rax + GI_GROUP_WORK.meta]
    mov  rcx, [rbp + rax + GI_GROUP_WORK.meta + 8]
    call gi_apart
    test eax, eax
    jz   .out
    inc  r14d
    cmp  r14d, 6
    jb   .meta_inner
    inc  r13d
    cmp  r13d, 5
    jb   .meta_outer
    mov  r12d, [rbp + GI_GROUP_WORK.size]
.group:
    xor  r14d, r14d
    mov  eax, [rbp + GI_GROUP_WORK.head]
    sub  eax, [rbp + GI_GROUP_WORK.tail]
    jz   .done
    mov  r13d, eax                         ; remaining published host events
.scan:
    cmp  r14d, r13d
    jae  .done                             ; no SYN in published range
    lea  eax, [r14 + r15]
    cmp  eax, r12d
    jae  .done                             ; whole group exceeds remaining budget
    mov  eax, [rbp + GI_GROUP_WORK.tail]
    add  eax, r14d
    and  eax, GI_RING - 1
    lea  rdx, [rel gi_ring]
    mov  rcx, [rdx + rax*8]
    lea  eax, [r14 + r15]
    shl  eax, 5
    mov  [rbp + rax + GI_GROUP_WORK.events + 16], rcx
    inc  r14d
    test ecx, ecx                         ; type=EV_SYN, code=SYN_REPORT
    jnz  .scan
    mov  [rbp + GI_GROUP_WORK.count], r14d
    mov  rbx, [rbp + GI_GROUP_WORK.meta]
    movzx eax, word [rbx + 2]
    movzx ecx, word [rbp + GI_GROUP_WORK.lastav]
    sub  eax, ecx
    and  eax, 0xFFFF
    cmp  eax, r12d
    ja   .done                             ; stale/overrun available producer
    cmp  eax, r14d
    jb   .done                             ; no prefix effect on missing tail buffer
    lfence
    xor  r13d, r13d
.buffer:
    movzx ecx, word [rbp + GI_GROUP_WORK.lastav]
    add  ecx, r13d
    lea  eax, [r12 - 1]
    and  ecx, eax
    mov  rax, [rbp + GI_GROUP_WORK.meta]
    movzx edx, word [rax + 4 + rcx*2]
    cmp  edx, r12d
    jae  .done
    bts  [rbp + GI_GROUP_WORK.ids], rdx
    jc   .done                             ; all selected groups own distinct descriptor IDs
    lea  ebx, [r13 + r15]
    shl  ebx, 5
    lea  rbx, [rbp + rbx + GI_GROUP_WORK.events]
    mov  [rbx + 24], edx
    mov  ecx, edx
    shl  ecx, 4
    mov  rax, [rbp + GI_GROUP_WORK.meta + 32]
    cmp  word [rax + rcx + 12], 2           ; WRITE only, no NEXT/INDIRECT/reserved bits
    jne  .done
    mov  esi, [rax + rcx + 8]
    cmp  esi, GI_EV_BYTES
    jb   .done
    mov  [rbx + 8], rsi                    ; validate the full declared extent
    mov  rdi, [rax + rcx]
    call hv_linux_gpa2hva
    test rax, rax
    jz   .done
    mov  [rbx], rax
    xor  r14d, r14d
.dest_meta:
    mov  eax, r14d
    shl  eax, 4
    mov  rdx, [rbp + rax + GI_GROUP_WORK.meta]
    mov  rcx, [rbp + rax + GI_GROUP_WORK.meta + 8]
    mov  rdi, [rbx]
    mov  rsi, [rbx + 8]
    call gi_apart
    test eax, eax
    jz   .done
    inc  r14d
    cmp  r14d, 6
    jb   .dest_meta
    xor  r14d, r14d
.dest_other:
    lea  eax, [r13 + r15]
    cmp  r14d, eax
    jae  .buffer_next
    mov  eax, r14d
    shl  eax, 5
    mov  rdx, [rbp + rax + GI_GROUP_WORK.events]
    mov  rcx, [rbp + rax + GI_GROUP_WORK.events + 8]
    mov  rdi, [rbx]
    mov  rsi, [rbx + 8]
    call gi_apart
    test eax, eax
    jz   .done
    inc  r14d
    jmp  .dest_other
.buffer_next:
    inc  r13d
    cmp  r13d, [rbp + GI_GROUP_WORK.count]
    jb   .buffer
    call gi_group_current
    test eax, eax
    jz   .out                              ; obsolete group has no payload/tail effects
    xor  r13d, r13d
.commit:
    lea  eax, [r13 + r15]
    shl  eax, 5
    lea  rbx, [rbp + rax + GI_GROUP_WORK.events]
    mov  rax, [rbx]
    mov  rcx, [rbx + 16]
    mov  [rax], rcx                        ; frozen event into frozen destination
    movzx eax, word [rbp + GI_GROUP_WORK.usedidx]
    add  eax, r13d
    lea  ecx, [r12 - 1]
    and  eax, ecx
    mov  rdx, [rbp + GI_GROUP_WORK.meta + 16]
    mov  ecx, [rbx + 24]
    mov  [rdx + 4 + rax*8], ecx
    mov  dword [rdx + 8 + rax*8], GI_EV_BYTES
    inc  r13d
    cmp  r13d, [rbp + GI_GROUP_WORK.count]
    jb   .commit
    ; No calls/yields from the final owner check through publication and tail.
    add  [rbp + GI_GROUP_WORK.usedidx], r13w
    add  [rbp + GI_GROUP_WORK.lastav], r13w
    sfence
    mov  ax, [rbp + GI_GROUP_WORK.usedidx]
    mov  [rdx + 2], ax                     ; the entire SYN-terminated group at once
    mov  [rel gi_q_usedidx], ax
    mov  ax, [rbp + GI_GROUP_WORK.lastav]
    mov  [rel gi_q_lastav], ax
    add  [rbp + GI_GROUP_WORK.tail], r13d
    mov  eax, [rbp + GI_GROUP_WORK.tail]
    mov  [rel gi_tail], eax
    add  [rel gi_delivered], r13d
    add  r15d, r13d
    jmp  .group
.done:
    test r15d, r15d
    jz   .out
    call gi_group_current
    test eax, eax
    jz   .out                              ; never signal a replaced owner
    call guestinput_raise_irq              ; one IRQ for all complete groups this call
.out:
    add  rsp, GI_GROUP_ALLOC
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    jmp  guestinput_release_retry           ; room freed: bounded cooperative producer

; PIC IRQ1, the same IF/shadow/entry gate ladder as the console and net lines.
guestinput_try_inject_irq:
    HV_POWER_WORK guestinput_try_inject_irq, 0, hv_guest_power_io_admit
    cmp  byte [rel gi_irq_pending], 1
    jne  .no
    cmp  byte [rel gi_irq_injected], 0
    jne  .no
    mov  edi, GI_IRQ_LINE
    call hv_pic_try_inject
    test eax, eax
    jz   .no
    mov  byte [rel gi_irq_injected], 1
    inc  dword [rel gi_irqs]
    ret
.no:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; Producer side (PaOS idle context only). Each call posts one whole group.
; ---------------------------------------------------------------------------

; gi_reserve(ECX=events) -> EAX=1 when the driver is live and the ring has room.
gi_reserve:
    cmp  byte [rel gi_live], 1
    jne  .refused
    test dword [rel vm_profile_live_devices], VP_DEV_INPUT
    jz   .refused
    mov  eax, [rel gi_head]
    sub  eax, [rel gi_tail]
    cmp  eax, GI_RING
    ja   .full
    add  eax, ecx
    cmp  eax, GI_RING
    ja   .full
    mov  eax, 1
    ret
.refused:
    cmp  byte [rel gi_release_pending], 1
    je   .wait
    inc  dword [rel gi_refused]
    xor  eax, eax
    ret
.full:
    cmp  byte [rel gi_release_pending], 1
    je   .wait                              ; retained releases are neither lost nor refused
    add  [rel gi_dropped], ecx
.wait:
    xor  eax, eax
    ret

; gi_put(EDI=type, ESI=code, EDX=value) — stage at gi_stage (not yet visible).
gi_put:
    mov  eax, [rel gi_stage]
    and  eax, GI_RING - 1
    lea  rcx, [rel gi_ring]
    mov  [rcx + rax*8], di
    mov  [rcx + rax*8 + 2], si
    mov  [rcx + rax*8 + 4], edx
    inc  dword [rel gi_stage]
    inc  dword [rel gi_posted]
    ret

; gi_publish — EV_SYN, then make the staged group visible to the pump at once.
gi_publish:
    xor  edi, edi
    xor  esi, esi
    xor  edx, edx
    call gi_put
    mov  eax, [rel gi_stage]
    mov  [rel gi_head], eax                 ; x86 TSO: payload stores precede this
    ret

; guestinput_post_key(EDI=Linux key code 1..127, ESI=value 0 up / 1 down /
; 2 repeat) -> EAX=1 posted, 0 refused or dropped.
guestinput_post_key:
    HV_POWER_CHECK hv_guest_power_admit, guestinput_post_key_power_refused
    call guestinput_release_blocked
    test eax, eax
    jz   gi_post_key
    inc  dword [rel gi_refused]             ; external input blocked behind old release
    xor  eax, eax
    ret

gi_post_key:                             ; internal release producer bypasses the gate
    cmp  edi, 1
    jb   .bad
    cmp  edi, GI_KEY_MAX
    ja   .bad
    cmp  esi, 2
    ja   .bad
    push rbx
    push r12
    mov  ebx, edi
    mov  r12d, esi
    mov  ecx, 2
    call gi_reserve
    test eax, eax
    jz   .out
    mov  eax, [rel gi_head]
    mov  [rel gi_stage], eax
    mov  edi, GI_EV_KEY
    mov  esi, ebx
    mov  edx, r12d
    call gi_put
    call gi_publish
    ; Track what the guest believes is held, so a release can be complete.
    lea  rcx, [rel gi_keys_down]
    test r12d, r12d
    jz   .up
    bts  [rcx], ebx
    jmp  .ok
.up:
    btr  [rcx], ebx
.ok:
    mov  eax, 1
.out:
    pop  r12
    pop  rbx
    ret
.bad:
    xor  eax, eax
    ret
guestinput_post_key_power_refused:
    xor eax, eax
    ret


; guestinput_post_pause -> EAX=1 iff the complete KEY_PAUSE tap was posted.
; Pause has no separate Set-1 break. Reserve down/SYN/up/SYN before writing,
; then publish once: neither queue pressure nor capture loss can strand a down.
; BSP-only, bounded, no yield, same power/release admission as other input.
guestinput_post_pause:
    HV_POWER_CHECK hv_guest_power_admit, guestinput_post_pause_power_refused
    call guestinput_release_blocked
    test eax, eax
    jnz  .refused
    cmp  byte [rel hv_linux_running], 1
    jne  .refused
    bt   qword [rel gi_keys_down + 8], 55    ; KEY_PAUSE119 already held by another producer
    jc   .refused
    mov  ecx, 4
    call gi_reserve
    test eax, eax
    jz   .out
    mov  eax, [rel gi_head]
    mov  [rel gi_stage], eax
    mov  edi, GI_EV_KEY
    mov  esi, 119                           ; Linux KEY_PAUSE
    mov  edx, 1
    call gi_put
    xor  edi, edi
    xor  esi, esi
    xor  edx, edx
    call gi_put                            ; first SYN stays unpublished
    mov  edi, GI_EV_KEY
    mov  esi, 119
    xor  edx, edx
    call gi_put
    call gi_publish                        ; final SYN, one head store for all four
    mov  eax, 1
.out:
    ret
.refused:
    inc  dword [rel gi_refused]
guestinput_post_pause_power_refused:
    xor  eax, eax
    ret

; guestinput_post_pointer(EDI=x, ESI=y, EDX=buttons: 1 left, 2 right, 4 middle)
; -> EAX=1 posted. x/y are clamped to the display; changed buttons follow ABS.
guestinput_post_pointer:
    HV_POWER_CHECK hv_guest_power_admit, guestinput_post_pointer_power_refused
    call guestinput_release_blocked
    test eax, eax
    jz   gi_post_pointer
    inc  dword [rel gi_refused]             ; external input blocked behind old release
    xor  eax, eax
    ret

gi_post_pointer:                             ; internal release producer bypasses the gate
    push rbx
    push r12
    push r13
    test edi, edi
    jns  .x_low
    xor  edi, edi
.x_low:
    cmp  edi, VP_FB_WIDTH - 1
    jle  .x_ok
    mov  edi, VP_FB_WIDTH - 1
.x_ok:
    test esi, esi
    jns  .y_low
    xor  esi, esi
.y_low:
    cmp  esi, VP_FB_HEIGHT - 1
    jle  .y_ok
    mov  esi, VP_FB_HEIGHT - 1
.y_ok:
    mov  ebx, edi
    mov  r12d, esi
    and  edx, 7
    mov  r13d, edx
    mov  ecx, 6                             ; ABS_X, ABS_Y, up to 3 buttons, SYN
    call gi_reserve
    test eax, eax
    jz   .out
    mov  [rel gi_ptr_x], ebx                ; last successfully queued position
    mov  [rel gi_ptr_y], r12d
    mov  eax, [rel gi_head]
    mov  [rel gi_stage], eax
    mov  edi, GI_EV_ABS
    xor  esi, esi                           ; ABS_X
    mov  edx, ebx
    call gi_put
    mov  edi, GI_EV_ABS
    mov  esi, 1                             ; ABS_Y
    mov  edx, r12d
    call gi_put
    xor  ebx, ebx                           ; button index 0..2
.button:
    cmp  ebx, 3
    jae  .publish
    movzx eax, byte [rel gi_ptr_buttons]
    xor  eax, r13d
    bt   eax, ebx
    jnc  .button_next
    mov  edi, GI_EV_KEY
    lea  esi, [rbx + GI_BTN_LEFT]
    xor  edx, edx
    bt   r13d, ebx
    setc dl
    call gi_put
.button_next:
    inc  ebx
    jmp  .button
.publish:
    mov  [rel gi_ptr_buttons], r13b
    call gi_publish
    mov  eax, 1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret
guestinput_post_pointer_power_refused:
    xor eax, eax
    ret


; guestinput_post_wheel(EDI=signed32 notches, -128..127 except0) -> EAX=1 posted.
; Same signed8 units/direction as the native human wheel seam; upper32 argument
; bits are ignored, as for other EDI producers. A refused wheel is never retried.
; Existing release barrier orders every wheel after all previously owed all-ups.
guestinput_post_wheel:
    HV_POWER_CHECK hv_guest_power_admit, guestinput_post_wheel_power_refused
    call guestinput_release_blocked
    test eax, eax
    jnz  .refused
    test edi, edi
    jz   .bad
    cmp  edi, -128
    jl   .bad
    cmp  edi, 127
    jg   .bad
    cmp  byte [rel hv_linux_running], 1
    jne  .refused
    push rbx
    mov  ebx, edi
    mov  ecx, 2                           ; exactly REL_WHEEL plus SYN_REPORT
    call gi_reserve
    test eax, eax
    jz   .out
    mov  eax, [rel gi_head]
    mov  [rel gi_stage], eax
    mov  edi, GI_EV_REL
    mov  esi, GI_REL_WHEEL
    mov  edx, ebx
    call gi_put
    call gi_publish                       ; publish only the complete group
    mov  eax, 1
.out:
    pop  rbx
    ret
.refused:
    inc  dword [rel gi_refused]
.bad:
guestinput_post_wheel_power_refused:
    xor  eax, eax
    ret

; Capture-loss obligation: the existing key bitmap/buttons are the exact
; outstanding up set. While pending, external posts and desktop recapture wait
; until *all* releases and their SYNs have reached guest buffers (head == tail).
; Each retry posts at most eight complete groups; a blocked reserve stops
; immediately. A pump calls once. A tick can also discover capture loss, so it
; calls at most twice (16 groups total). No driver kicks, waits, overwritten entries or retry drops.
;
; START consumed generation plus backing-region identity bind the obligation.
; A stopped/replaced guest cancels its queued events and held state; a temporary
; unavailable driver or bad queue keeps the obligation. Device/status reset
; explicitly cancels it. Only the idle/BSP owner touches this state.
;
; guestinput_release_blocked -> EAX=1 pending, 0 clear. Preserves input arguments
; and all registers except RAX, so public posting and the pointer gate can use it.
guestinput_release_blocked:
    cmp byte [rel hv_guest_power_fenced], 0
    je .power_open
    mov eax, 1
    ret
.power_open:
    cmp  byte [rel gi_release_pending], 1
    jne  .clear
    cmp  byte [rel hv_linux_running], 1
    jne  .cancel
    test dword [rel vm_profile_live_devices], VP_DEV_INPUT
    jz   .cancel
    mov  eax, [rel hv_linux_start_consumed]
    cmp  eax, [rel gi_release_gen]
    jne  .cancel
    mov  rax, [rel hv_linux_region]
    cmp  rax, [rel gi_release_region]
    jne  .cancel
    mov  rax, [rel hv_linux_ram]
    cmp  rax, [rel gi_release_ram]
    jne  .cancel
    mov  rax, [rel hv_linux_ram_bytes]
    cmp  rax, [rel gi_release_bytes]
    jne  .cancel
    mov  eax, 1
    ret
.cancel:
    mov  eax, [rel gi_head]
    sub  eax, [rel gi_tail]
    add  [rel gi_canceled], eax
    mov  eax, [rel gi_head]
    mov  [rel gi_tail], eax
    xor  eax, eax
    mov  [rel gi_release_pending], al
    mov  [rel gi_ptr_buttons], al
    mov  [rel gi_keys_down], rax
    mov  [rel gi_keys_down + 8], rax
    mov  [rel gi_live], al                   ; require fresh device bring-up
    mov  [rel gi_driver_ok], al
    mov  [rel gi_q_ready], ax
    mov  [rel gi_irq_pending], al
    mov  [rel gi_irq_injected], al
.clear:
    xor  eax, eax
    ret

; guestinput_release_all -> EAX=whole release groups posted this call.
; Repeated capture-loss requests never rebind an existing obligation.
guestinput_release_all:
    HV_POWER_WORK guestinput_release_all, 0, hv_guest_power_io_admit
    cmp  byte [rel gi_release_pending], 1
    je   guestinput_release_retry
    mov  rax, [rel gi_keys_down]
    or   rax, [rel gi_keys_down + 8]
    movzx ecx, byte [rel gi_ptr_buttons]
    or   rax, rcx
    mov  ecx, [rel gi_head]
    sub  ecx, [rel gi_tail]
    or   rax, rcx
    jz   .empty
    mov  eax, [rel hv_linux_start_consumed]
    mov  [rel gi_release_gen], eax
    mov  rax, [rel hv_linux_region]
    mov  [rel gi_release_region], rax
    mov  rax, [rel hv_linux_ram]
    mov  [rel gi_release_ram], rax
    mov  rax, [rel hv_linux_ram_bytes]
    mov  [rel gi_release_bytes], rax
    mov  byte [rel gi_release_pending], 1
    jmp  guestinput_release_retry
.empty:
    xor  eax, eax
    ret

; guestinput_release_retry -> EAX=groups posted (0..8), preserves RBX/R12-R15.
; An unavailable driver returns immediately with held state and pending intact.
guestinput_release_retry:
    HV_POWER_WORK guestinput_release_retry, 0, hv_guest_power_io_admit
    push rbx
    push r12
    xor  r12d, r12d
    call guestinput_release_blocked
    test eax, eax
    jz   .out
    cmp  byte [rel gi_live], 1
    jne  .out
    mov  ebx, 1
.key:
    cmp  ebx, GI_KEY_MAX
    ja   .buttons
    lea  rcx, [rel gi_keys_down]
    bt   [rcx], ebx
    jnc  .key_next
    mov  edi, ebx
    xor  esi, esi
    call gi_post_key
    test eax, eax
    jz   .out                               ; no capacity: one attempt, then yield
    inc  r12d
    cmp  r12d, GI_RELEASE_BUDGET
    jae  .out
.key_next:
    inc  ebx
    jmp  .key
.buttons:
    cmp  byte [rel gi_ptr_buttons], 0
    je   .drained
    mov  edi, [rel gi_ptr_x]
    mov  esi, [rel gi_ptr_y]
    xor  edx, edx
    call gi_post_pointer
    test eax, eax
    jz   .out
    inc  r12d
.drained:
    mov  eax, [rel gi_head]
    cmp  eax, [rel gi_tail]
    jne  .out                               ; SYN must reach the guest before recapture
    mov  byte [rel gi_release_pending], 0
.out:
    mov  eax, r12d
    pop  r12
    pop  rbx
    ret

; guestinput_render_stat — appended to GUESTVM STAT when the profile has input.
guestinput_render_stat:
    test dword [rel vm_profile_live_devices], VP_DEV_INPUT
    jz   .ret
    lea  rdi, [rel str_gi_k_live]
    movzx eax, byte [rel gi_live]
    call gi_out_kv
    lea  rdi, [rel str_gi_k_posted]
    mov  eax, [rel gi_posted]
    call gi_out_kv
    lea  rdi, [rel str_gi_k_delivered]
    mov  eax, [rel gi_delivered]
    call gi_out_kv
    lea  rdi, [rel str_gi_k_dropped]
    mov  eax, [rel gi_dropped]
    call gi_out_kv
    lea  rdi, [rel str_gi_k_refused]
    mov  eax, [rel gi_refused]
    call gi_out_kv
    lea  rdi, [rel str_gi_k_pending]
    movzx eax, byte [rel gi_release_pending]
    call gi_out_kv
    lea  rdi, [rel str_gi_k_canceled]
    mov  eax, [rel gi_canceled]
    call gi_out_kv
    lea  rdi, [rel str_gi_k_irqs]
    mov  eax, [rel gi_irqs]
    call gi_out_kv
    lea  rdi, [rel str_gi_k_cfg]
    mov  eax, [rel gi_cfg_selects]
    call gi_out_kv
    lea  rdi, [rel str_gi_k_bad]
    mov  eax, [rel gi_bad_writes]
    call gi_out_kv
.ret:
    ret

gi_out_kv:
    push rax
    call hv_out_str
    pop  rax
    jmp  hv_out_dec

; ---------------------------------------------------------------------------
; GUESTVM INPUT KEY <code> | PTR <x> <y> <buttons> (owner-signed like every
; GUESTVM sub-verb). Posts through the same producer path as the desktop
; window, so it witnesses the device without a keyboard or a GLKVM. KEY posts
; a press group and a release group. Fixed-key bounded reply.
; ---------------------------------------------------------------------------
; guestinput_verb(RDI=text after INPUT)
guestinput_verb:
    push rbx
    push r12
    push r13
    push r14
    mov  rbx, rdi
    call hv_out_reset
    lea  rdi, [rel str_gi_verb_head]
    call hv_out_str
    mov  rdi, rbx
    call gi_skip_spaces
    mov  rbx, rax
    mov  rdi, rbx
    lea  rsi, [rel str_gi_tok_key]
    call hv_tok_is
    test al, al
    jnz  .key
    mov  rdi, rbx
    lea  rsi, [rel str_gi_tok_ptr]
    call hv_tok_is
    test al, al
    jnz  .ptr
    jmp  .usage
.key:
    lea  rdi, [rbx + 3]
    call gi_parse_num
    jc   .usage
    mov  r12d, eax
    mov  rdi, rdx
    call gi_at_end
    jnz  .usage
    cmp  r12d, 1
    jb   .usage
    cmp  r12d, GI_KEY_MAX
    ja   .usage
    mov  edi, r12d
    mov  esi, 1
    call guestinput_post_key
    test eax, eax
    jz   .refused
    mov  edi, r12d
    xor  esi, esi
    call guestinput_post_key
    test eax, eax
    jz   .refused
    lea  rdi, [rel str_gi_key_ok]
    mov  eax, r12d
    call gi_out_kv
    jmp  .counters
.ptr:
    lea  rdi, [rbx + 3]
    call gi_parse_num
    jc   .usage
    mov  r12d, eax
    mov  rdi, rdx
    call gi_parse_num
    jc   .usage
    mov  r13d, eax
    mov  rdi, rdx
    call gi_parse_num
    jc   .usage
    mov  r14d, eax
    mov  rdi, rdx
    call gi_at_end
    jnz  .usage
    cmp  r12d, VP_FB_WIDTH
    jae  .usage
    cmp  r13d, VP_FB_HEIGHT
    jae  .usage
    cmp  r14d, 7
    ja   .usage
    mov  edi, r12d
    mov  esi, r13d
    mov  edx, r14d
    call guestinput_post_pointer
    test eax, eax
    jz   .refused
    lea  rdi, [rel str_gi_ptr_ok]
    call hv_out_str
    jmp  .counters
.refused:
    lea  rdi, [rel str_gi_refused]
    call hv_out_str
    jmp  .counters
.usage:
    lea  rdi, [rel str_gi_usage]
    call hv_out_str
.counters:
    call guestinput_render_stat
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

gi_skip_spaces:
    mov  rax, rdi
.skip:
    cmp  byte [rax], ' '
    jne  .out
    inc  rax
    jmp  .skip
.out:
    ret

; gi_at_end(RDI) -> ZF=1 when only spaces remain.
gi_at_end:
    call gi_skip_spaces
    cmp  byte [rax], 0
    ret

; gi_parse_num(RDI=text) -> EAX=value, RDX=just past it; CF when there is no
; number or it has more than five digits. Leading spaces are skipped.
gi_parse_num:
    call gi_skip_spaces
    mov  rdx, rax
    xor  eax, eax
    xor  ecx, ecx                           ; digits
.digit:
    movzx r8d, byte [rdx]
    sub  r8d, '0'
    cmp  r8d, 9
    ja   .end
    cmp  ecx, 5
    jae  .bad
    imul eax, eax, 10
    add  eax, r8d
    inc  ecx
    inc  rdx
    jmp  .digit
.end:
    test ecx, ecx
    jz   .bad
    movzx r8d, byte [rdx]
    test r8d, r8d
    jz   .ok
    cmp  r8d, ' '
    jne  .bad
.ok:
    clc
    ret
.bad:
    stc
    ret

str_gi_name:        db "PaOS desktop input"
str_gi_name_len     equ $ - str_gi_name
str_gi_k_live:      db " in_live=", 0
str_gi_k_posted:    db " in_posted=", 0
str_gi_k_delivered: db " in_delivered=", 0
str_gi_k_dropped:   db " in_dropped=", 0
str_gi_k_refused:   db " in_refused=", 0
str_gi_k_irqs:      db " in_irqs=", 0
str_gi_k_cfg:       db " in_cfg=", 0
str_gi_k_bad:       db " in_bad_writes=", 0
str_gi_k_pending:   db " in_release_pending=", 0
str_gi_k_canceled:  db " in_canceled=", 0
str_gi_verb_head:   db "GUESTINPUT", 0
str_gi_tok_key:     db "KEY", 0
str_gi_tok_ptr:     db "PTR", 0
str_gi_key_ok:      db " input=ok key=", 0
str_gi_ptr_ok:      db " input=ok ptr=1", 0
str_gi_refused:     db " input=ERR not_live_or_full", 0
str_gi_usage:       db " input=ERR usage KEY <1..127> | PTR <x> <y> <0..7>", 0

%include "core/abi/wdata.inc"
%macro WDATA_hv_guestinput_0 0
align 8
gi_owner_epoch: dq 0                       ; survives state_zero
gi_state_begin:
gi_q_desc:        dq 0, 0
gi_q_avail:       dq 0, 0
gi_q_used:        dq 0, 0
gi_q_num:         dd 0, 0
gi_q_lastav:      dw 0, 0                  ; eventq, statusq
gi_q_usedidx:     dw 0, 0
gi_qsel:          dd 0
gi_drvfsel:       dd 0
gi_drvfeat:       dd 0, 0
gi_isr:           dd 0
gi_head:          dd 0                     ; producer: published events
gi_tail:          dd 0                     ; consumer: delivered events
gi_stage:         dd 0                     ; producer: staged, not yet published
gi_posted:        dd 0
gi_delivered:     dd 0
gi_dropped:       dd 0
gi_refused:       dd 0
gi_irqs:          dd 0
gi_mmio_writes:   dd 0
gi_notifies:      dd 0
gi_cfg_selects:   dd 0
gi_bad_writes:    dd 0
gi_status_used:   dd 0
gi_canceled:      dd 0                     ; queued events discarded by lifetime/reset
gi_release_gen:   dd 0
gi_release_region: dq 0
gi_release_ram:   dq 0
gi_release_bytes: dq 0
gi_ptr_x:         dd 0
gi_ptr_y:         dd 0
gi_keys_down:     times 16 db 0            ; bit per key code 0..127
gi_q_ready:       db 0, 0
gi_driver_ok:     db 0
gi_live:          db 0
gi_irq_pending:   db 0
gi_irq_injected:  db 0
gi_cfg_sel:       db 0
gi_cfg_sub:       db 0
gi_ptr_buttons:   db 0
gi_release_pending: db 0
gi_state_end:
align 8
gi_ring:          times GI_RING dq 0
%endmacro
WDATA_DEFER WDATA_hv_guestinput_0
