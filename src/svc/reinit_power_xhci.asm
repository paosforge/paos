;; MODULE svc/reinit_power_xhci
;; LAYER 5
;; EXPORTS reinit_power_xhci_register, reinit_power_xhci_gate, reinit_power_xhci_admit
;; IMPORTS svc/reinit_power, dev/usb/xhci, usb/enum, bus/pci, core/lib/mem
;; CAPS
;; OWNER saga:resource
;; CONTEXT: bsp_only
; Trusted, explicit, one-controller lifetime. No boot/wire attachment. See
; docs/reinit_power_xhci.md for the finite profile and retained DMA custody.
%include "core/abi/driver_power.inc"

%macro XP_COMPARE 3
    lea rdi, [rel %1]
    lea rsi, [rel %2]
    mov edx, %3
    call memcmp
    test eax, eax
    jnz .bad
%endmacro
%macro XP_COPY 3
    lea rdi, [rel %1]
    lea rsi, [rel %2]
    mov edx, %3
    call memcpy
%endmacro

; Read only after the software binding passes. PCI identity/command/BAR are
; pinned too: a live BAR rebind must fail before touching its former mapping.
xp_pci:
    mov edi, [rel xhci_bus]
    mov esi, [rel xhci_dev]
    mov edx, [rel xhci_fn]
    jmp pci_cfg_read32

; Read-only admission preserves every register except RAX/flags. Used before
; all ordinary work; the exact full64 issued token API also rejects stale work.
reinit_power_xhci_gate:
    push rsi
    mov rsi, [rel reinit_power_xhci_context]
    test rsi, rsi
    jz .legacy
    mov rsi, [rsi + dp_context.token]
    call reinit_power_xhci_admit
    pop rsi
    ret
.legacy:
    xor eax, eax
    pop rsi
    ret
reinit_power_xhci_admit:             ; RSI = work's original full64 issued token
    push rbx
    push rcx
    push rdx
    push rdi
    push rsi
    push r8
    push r9
    push r10
    push r11
    mov rdi, [rel reinit_power_xhci_context]
    test rdi, rdi
    jz .invalid
    lea rdx, [rel xhci_hcdev]
    mov rcx, [rel xp_generation]
    call reinit_power_admit
    test rax, rax
    jnz .out
    call xp_binding
    test rax, rax
    jnz .out
    call xp_hardware                  ; PCI rebind fails before backend MMIO
    jmp .out
.invalid:
    mov rax, DP_INVALID
.out:
    pop r11
    pop r10
    pop r9
    pop r8
    pop rsi
    pop rdi
    pop rdx
    pop rcx
    pop rbx
    ret

; Pinned static allocation profile; no scratchpads/DbC/secondary interrupter,
; no outstanding synchronous command, no dynamically switched controller.
xp_binding:
    push rbx
    cmp dword [rel xhci_inst_n], 1
    jne .bad
    cmp dword [rel xhci_inst_cur], 0
    jne .bad
    XP_COMPARE xhci_region, xp_binding_image, xhci_cmd_idx - xhci_region
    mov eax, [rel xhci_generation]
    cmp rax, [rel xp_generation]
    jne .bad
    mov rax, [rel xhci_xfer_dma]
    cmp rax, [rel xp_xfer]
    jne .bad
    XP_COMPARE xhci_hcdev, xp_device, DEV_SIZE
    XP_COMPARE xhci_ops, xp_ops, usbhc_ops_size
    XP_COMPARE usb_hc_arr, xp_registry, USB_MAX_HC * 8 + 4
    XP_COMPARE xhci_port_slot, xp_ports, (XHCI_PORT_COUNT + XHCI_SLOT_COUNT) * 4
    XP_COMPARE xhci_slot_topo, xp_topology, XHCI_SLOT_COUNT * usb_topo_size
    XP_COMPARE xhci_slot_speed, xp_speed, XHCI_SLOT_COUNT * 8
    cmp byte [rel xhci_cmd_ring_dead], 0
    jne .bad
    cmp qword [rel xhci_cmd_out_trb], 0
    jne .bad
    cmp dword [rel xhci_slot_quar], 0
    jne .bad
    cmp dword [rel xhci_slot_parked], 0
    jne .bad
    xor ebx, ebx
.ep:
    lea rdi, [rel xhci_intr_states]
    lea rsi, [rel xp_endpoints]
    add rdi, rbx
    add rsi, rbx
    mov edx, 2                       ; active/configured
    call memcmp
    test eax, eax
    jnz .bad
    lea rdi, [rel xhci_intr_states + xhci_intr_ep.slot]
    lea rsi, [rel xp_endpoints + xhci_intr_ep.slot]
    add rdi, rbx
    add rsi, rbx
    mov edx, xhci_intr_ep.exact_len - xhci_intr_ep.slot
    call memcmp
    test eax, eax
    jnz .bad
    lea rdi, [rel xhci_intr_states]
    lea rsi, [rel xp_endpoints]
    add rdi, rbx
    add rsi, rbx
    mov eax, [rdi + xhci_intr_ep.generation]
    cmp eax, [rsi + xhci_intr_ep.generation]
    jne .bad
    mov rax, [rdi + xhci_intr_ep.ring]
    cmp rax, [rsi + xhci_intr_ep.ring]
    jne .bad
    mov rax, [rdi + xhci_intr_ep.report]
    cmp rax, [rsi + xhci_intr_ep.report]
    jne .bad
    mov ax, [rdi + xhci_intr_ep.ss_payload]
    cmp ax, [rsi + xhci_intr_ep.ss_payload]
    jne .bad
    add ebx, xhci_intr_ep_size
    cmp ebx, XHCI_INTR_STATE_COUNT * xhci_intr_ep_size
    jb .ep
    xor eax, eax
    pop rbx
    ret
.bad:
    mov rax, DP_CHANGED
    pop rbx
    ret

; Fresh readonly PCI, registers, ports and no error/reset. Values that legitimately
; move while draining (ERDP, event positions) are frozen only after actual halt.
xp_hardware:
    push rbx
    xor ebx, ebx
.pci:
    lea rax, [rel xp_pci_offsets]
    mov ecx, [rax + rbx*4]
    call xp_pci
    lea rdx, [rel xp_pci_values]
    cmp eax, [rdx + rbx*4]
    jne .bad
    inc ebx
    cmp ebx, 5
    jb .pci
    xor ebx, ebx
.ext:
    cmp ebx, [rel xp_ext_count]
    jae .ext_done
    lea rax, [rel xp_ext_offsets]
    mov esi, [rax + rbx*4]
    call xh_rd
    lea rdx, [rel xp_ext_values]
    cmp eax, [rdx + rbx*4]
    jne .bad
    inc ebx
    jmp .ext
.ext_done:
    xor ebx, ebx
.reg:
    lea rax, [rel xp_reg_offsets]
    mov esi, [rax + rbx*4]
    call xh_rd
    lea rdx, [rel xp_reg_values]
    cmp eax, [rdx + rbx*4]
    jne .bad
    inc ebx
    cmp ebx, XP_REG_COUNT
    jb .reg
    mov esi, [rel xhci_op]
    add esi, XHCI_USBSTS
    call xh_rd
    test eax, (1 << 2) | (1 << 11) | (1 << 12)
    jnz .bad
    xor ebx, ebx
.port:
    mov esi, ebx
    shl esi, 4
    add esi, [rel xhci_op]
    add esi, XHCI_PORTSC_BASE
    call xh_rd
    lea rdx, [rel xp_portsc]
    cmp eax, [rdx + rbx*4]             ; includes change/reset bits: no ack/clear
    jne .bad
    inc ebx
    cmp ebx, [rel xhci_maxports]
    jb .port
    xor eax, eax
    pop rbx
    ret
.bad:
    mov rax, DP_CHANGED
    pop rbx
    ret

; Explicit BSP registration pins actual native lifetime, never attaches a fake
; controller or turns on PCI decoding. Failure publishes no attachment.
reinit_power_xhci_register:           ; RDI = initialized caller-owned context
    push rbx
    push r12
    push r13
    mov r12, rdi
    mov rax, DP_BUSY
    cmp qword [rel reinit_power_xhci_context], 0
    jne .out
    cmp dword [rel xhci_inst_n], 1
    jne .unsupported
    cmp dword [rel xhci_inst_cur], 0
    jne .unsupported
    cmp word [rel xhci_scratch_count], 0
    jne .unsupported
    cmp qword [rel xhci_dma_set], 0
    jne .unsupported
    cmp qword [rel xhci_scratch_pages], 0
    jne .unsupported
    cmp dword [rel xhci_generation], 0
    je .unsupported
    cmp dword [rel xhci_maxports], 1
    jb .unsupported
    cmp dword [rel xhci_maxports], 32
    ja .unsupported
    cmp dword [rel xhci_maxslots], XHCI_MAX_SLOTS_EN
    jne .unsupported
    cmp dword [rel xhci_ctxsz], 32
    je .ctx_ok
    cmp dword [rel xhci_ctxsz], 64
    jne .unsupported
.ctx_ok:
    ; Static resources must be the original aligned buffers, not aliases.
%assign n 0
%rep 8
    lea rdx, [rel xp_static_table + n*16]
    mov rax, [rdx]
    add rax, rdx                      ; variable offset from its live table cell
    mov rcx, [rdx + 8]
    lea rdx, [rdx + rcx + 8]          ; buffer offset from its own live cell
    cmp [rax], rdx
    jne .unsupported
%assign n n+1
%endrep
    mov rax, [rel xhci_xfer_dma]
    test rax, rax
    jz .unsupported
    test rax, 63
    jnz .unsupported
    lea rdx, [rel xhci_dcbaa_buf]
    lea rcx, [rel xhci_scratch_arr + XHCI_SCRATCH_MAX * 8]
    lea rsi, [rax + XHCI_XFER_DMA_BYTES]
    cmp rsi, rax
    jbe .unsupported
    cmp rsi, rdx
    jbe .xfer_ok
    cmp rax, rcx
    jb .unsupported
.xfer_ok:
    cmp qword [rel xhci_region], 0
    je .unsupported
    cmp qword [rel xhci_region + 8], 0x1000
    jb .unsupported
    cmp qword [rel xhci_region + 8], 0x100000
    ja .unsupported
    ; Software offsets must stay within the existing mapped BAR.
    mov eax, [rel xhci_op]
    cmp eax, 0x20
    jb .unsupported
    test eax, 3
    jnz .unsupported
    add eax, XHCI_PORTSC_BASE + 32*16
    cmp rax, [rel xhci_region + 8]
    ja .unsupported
    mov eax, [rel xhci_rt]
    test eax, 31
    jnz .unsupported
    add eax, 0x40
    cmp rax, [rel xhci_region + 8]
    ja .unsupported
    mov eax, [rel xhci_db]
    test eax, 3
    jnz .unsupported
    add eax, 4 * XHCI_SLOT_COUNT
    cmp rax, [rel xhci_region + 8]
    ja .unsupported
    ; Only this actual registered controller, exactly once (other classes may
    ; coexist). Preserve the whole registry and vtable/device as lifetime pins.
    mov ecx, [rel usb_hc_count]
    test ecx, ecx
    jz .unsupported
    cmp ecx, USB_MAX_HC
    ja .unsupported
    xor ebx, ebx
    xor edx, edx
.registry:
    lea rax, [rel usb_hc_arr]
    mov rax, [rax + rbx*8]
    lea rsi, [rel xhci_hcdev]
    cmp rax, rsi
    jne .next_hc
    inc edx
.next_hc:
    inc ebx
    cmp ebx, ecx
    jb .registry
    cmp edx, 1
    jne .unsupported
    cmp dword [rel xhci_hcdev + dev.class], CLASS_USBHC
    jne .unsupported
    cmp dword [rel xhci_hcdev + dev.health], HEALTH_OK
    jne .unsupported
    lea rax, [rel xhci_ops]
    cmp [rel xhci_hcdev + dev.ops], rax
    jne .unsupported
    lea rax, [rel xhci_thunks + XT_INTR_POLL * XHCI_THUNK_SZ]
    cmp [rel xhci_ops + usbhc_ops.interrupt_in_poll], rax
    jne .unsupported
    ; Endpoint rings/reports must be the real private xfer allocation layout.
    xor ebx, ebx
    mov r13, [rel xhci_xfer_dma]
.endpoint:
    imul eax, ebx, xhci_intr_ep_size
    lea rdi, [rel xhci_intr_states]
    add rdi, rax
    mov eax, ebx
    shl eax, 10
    add rax, r13
    cmp [rdi + xhci_intr_ep.ring], rax
    jne .unsupported
    mov eax, ebx
    shl eax, 11
    add rax, XHCI_INTR_STATE_COUNT * XHCI_INTR_RING_BYTES
    add rax, r13
    cmp [rdi + xhci_intr_ep.report], rax
    jne .unsupported
    cmp byte [rdi + xhci_intr_ep.pending], 1
    ja .unsupported
    cmp byte [rdi + xhci_intr_ep.completed], 1
    ja .unsupported
    mov al, [rdi + xhci_intr_ep.pending]
    and al, [rdi + xhci_intr_ep.completed]
    jnz .unsupported
    cmp byte [rdi + xhci_intr_ep.active], 0
    jne .active_ep
    cmp word [rdi + xhci_intr_ep.pending], 0
    jne .unsupported
    jmp .endpoint_next
.active_ep:
    cmp byte [rdi + xhci_intr_ep.active], 1
    jne .unsupported
    cmp byte [rdi + xhci_intr_ep.configured], 1
    jne .unsupported
    cmp byte [rdi + xhci_intr_ep.attributes], USB_EP_XFER_INTR
    jne .unsupported
    test byte [rdi + xhci_intr_ep.ep_addr], 0x80
    jz .unsupported
    cmp word [rdi + xhci_intr_ep.mps], 0
    je .unsupported
    cmp word [rdi + xhci_intr_ep.segments], 1
    ja .unsupported
    cmp byte [rdi + xhci_intr_ep.slot], 1
    jb .unsupported
    cmp byte [rdi + xhci_intr_ep.slot], XHCI_MAX_SLOTS_EN
    ja .unsupported
    mov eax, [rel xhci_generation]
    cmp [rdi + xhci_intr_ep.generation], eax
    jne .unsupported
.endpoint_next:
    inc ebx
    cmp ebx, XHCI_INTR_STATE_COUNT
    jb .endpoint
    XP_COPY xp_binding_image, xhci_region, xhci_cmd_idx - xhci_region
    XP_COPY xp_device, xhci_hcdev, DEV_SIZE
    XP_COPY xp_ops, xhci_ops, usbhc_ops_size
    XP_COPY xp_registry, usb_hc_arr, USB_MAX_HC * 8 + 4
    XP_COPY xp_ports, xhci_port_slot, (XHCI_PORT_COUNT + XHCI_SLOT_COUNT) * 4
    XP_COPY xp_topology, xhci_slot_topo, XHCI_SLOT_COUNT * usb_topo_size
    XP_COPY xp_speed, xhci_slot_speed, XHCI_SLOT_COUNT * 8
    XP_COPY xp_endpoints, xhci_intr_states, XHCI_INTR_STATE_COUNT * xhci_intr_ep_size
    mov eax, [rel xhci_generation]
    mov [rel xp_generation], rax
    mov rax, [rel xhci_xfer_dma]
    mov [rel xp_xfer], rax
    call xp_binding
    test rax, rax
    jnz .out
    ; Fresh PCI identity: memory decode + bus mastering already enabled; no
    ; config writes. BAR0/1 are pinned together and must match actual mapping.
    xor ebx, ebx
.pci:
    lea rax, [rel xp_pci_offsets]
    mov ecx, [rax + rbx*4]
    call xp_pci
    lea rdx, [rel xp_pci_values]
    mov [rdx + rbx*4], eax
    inc ebx
    cmp ebx, 5
    jb .pci
    cmp word [rel xp_pci_values], 0xFFFF
    je .unsupported
    mov eax, [rel xp_pci_values + 4]
    and eax, 6
    cmp eax, 6
    jne .unsupported
    mov eax, [rel xp_pci_values + 8]
    shr eax, 8
    cmp eax, 0x0C0330
    jne .unsupported
    mov eax, [rel xp_pci_values + 12]
    mov edx, eax
    and edx, 7
    cmp edx, 4
    je .bar64
    test edx, edx
    jnz .unsupported
    xor edx, edx
    jmp .bar
.bar64:
    mov edx, [rel xp_pci_values + 16]
.bar:
    shl rdx, 32
    and eax, 0xFFFFFFF0
    or rax, rdx
    cmp rax, [rel xhci_region]
    jne .unsupported
    xor esi, esi
    call xh_rd
    movzx eax, al
    cmp eax, [rel xhci_op]
    jne .unsupported
    mov esi, XHCI_HCSPARAMS1
    call xh_rd
    mov edx, eax
    shr edx, 8
    and edx, 0x7FF
    cmp edx, 1                       ; exactly one interrupter
    jne .unsupported
    shr eax, 24
    cmp eax, [rel xhci_maxports]
    jne .unsupported
    mov esi, XHCI_HCCPARAMS1
    call xh_rd
    mov edx, eax
    and edx, 4
    shr edx, 2
    inc edx
    shl edx, 5
    cmp edx, [rel xhci_ctxsz]
    jne .unsupported
    shr eax, 16
    shl eax, 2
    mov esi, eax
    mov ebx, 32
    mov dword [rel xp_ext_count], 0
.ext:
    test esi, esi
    jz .caps_done
    mov r13d, esi
    lea rax, [rsi + 4]
    cmp rax, [rel xhci_region + 8]
    ja .unsupported
    call xh_rd
    mov ecx, [rel xp_ext_count]
    lea rdx, [rel xp_ext_offsets]
    mov [rdx + rcx*4], esi
    lea rdx, [rel xp_ext_values]
    mov [rdx + rcx*4], eax
    inc dword [rel xp_ext_count]
    movzx edx, al
    cmp edx, 1                       ; legacy ownership (readonly)
    je .ext_next
    cmp edx, 2                       ; supported protocol (readonly)
    jne .unsupported                ; includes DbC: R/S does not stop its DMA
.ext_next:
    shr eax, 8
    and eax, 255
    jz .caps_done
    lea esi, [r13 + rax*4]
    cmp esi, r13d
    jbe .unsupported
    dec ebx
    jnz .ext
    jmp .unsupported
.caps_done:
    ; Capture readonly register addresses, including capability identity and
    ; original DMA bindings. Never trust a cached health byte as readiness.
    lea rdi, [rel xp_reg_offsets]
    xor eax, eax
    stosd                            ; CAPLENGTH + version
    mov eax, 4
    stosd
    mov eax, 8
    stosd
    mov eax, 0x10
    stosd
    mov eax, 0x14
    stosd
    mov eax, 0x18
    stosd
    mov eax, [rel xhci_op]
    add eax, XHCI_DCBAAP
    stosd
    add eax, 4
    stosd
    mov eax, [rel xhci_op]
    add eax, XHCI_CONFIG
    stosd
    mov eax, [rel xhci_rt]
    add eax, XHCI_ERSTSZ
    stosd
    mov eax, [rel xhci_rt]
    add eax, XHCI_ERSTBA
    stosd
    add eax, 4
    stosd
    mov eax, [rel xhci_op]
    add eax, XHCI_CRCR
    stosd
    add eax, 4
    stosd
    xor ebx, ebx
.reg:
    lea rdx, [rel xp_reg_offsets]
    mov esi, [rdx + rbx*4]
    call xh_rd
    lea rdx, [rel xp_reg_values]
    mov [rdx + rbx*4], eax
    inc ebx
    cmp ebx, XP_REG_COUNT
    jb .reg
    mov eax, [rel xp_reg_values + 4*4]
    and eax, ~3
    cmp eax, [rel xhci_db]
    jne .unsupported
    mov eax, [rel xp_reg_values + 5*4]
    and eax, ~31
    cmp eax, [rel xhci_rt]
    jne .unsupported
    mov rax, [rel xp_reg_values + 6*4]
    cmp rax, [rel xhci_dcbaa]
    jne .unsupported
    mov rax, [rel xp_reg_values + 10*4]
    cmp rax, [rel xhci_erst]
    jne .unsupported
    cmp dword [rel xp_reg_values + 9*4], 1
    jne .unsupported
    cmp dword [rel xp_reg_values + 8*4], XHCI_MAX_SLOTS_EN
    jne .unsupported
    test dword [rel xp_reg_values + 12*4], 0x0E ; no active/abort/stop command
    jnz .unsupported
    xor ebx, ebx
.port:
    mov esi, ebx
    shl esi, 4
    add esi, [rel xhci_op]
    add esi, XHCI_PORTSC_BASE
    call xh_rd
    test eax, 0x80FE0010              ; reset/change pending => no lifecycle effects
    jnz .unsupported
    lea rdx, [rel xp_portsc]
    mov [rdx + rbx*4], eax
    inc ebx
    cmp ebx, [rel xhci_maxports]
    jb .port
    call xp_running
    test rax, rax
    jnz .out
    lea rsi, [rel xp_declaration]
    lea rax, [rel xhci_hcdev]
    mov [rsi + dp_driver.owner], rax
    lea rax, [rel xp_generation]
    mov [rsi + dp_driver.generation_ptr], rax
    mov rax, [rax]
    mov [rsi + dp_driver.generation], rax
    lea rax, [rel xp_callback]
    mov [rsi + dp_driver.callback], rax
    mov rdi, r12
    call reinit_power_register
    test rax, rax
    jnz .out
    mov [rel reinit_power_xhci_context], r12
    jmp .out
.unsupported:
    mov rax, DP_UNSUPPORTED
.out:
    pop r13
    pop r12
    pop rbx
    cld
    ret

; Actual state samples, no wait loops, no destructive commands.
xp_running:
    mov esi, [rel xhci_op]
    add esi, XHCI_USBCMD
    call xh_rd
    test eax, ~5
    jnz .bad
    test eax, 1
    jz .bad
    mov esi, [rel xhci_op]
    add esi, XHCI_USBSTS
    call xh_rd
    test eax, (1 << 0) | (1 << 2) | (1 << 11) | (1 << 12)
    jnz .bad
    xor eax, eax
    ret
.bad:
    mov rax, DP_FAILED
    ret

; Freeze all original software and DMA bytes only after observed HCH. Compare
; only on resume: do not overwrite changed resources with a cached image.
xp_freeze:
    push rbx
    lea rdi, [rel xp_frozen_image]
    call xhci_inst_copy_out
    XP_COPY xp_frozen_static, xhci_dcbaa_buf, XP_STATIC_BYTES
    lea rdi, [rel xp_frozen_xfer]
    mov rsi, [rel xp_xfer]
    mov edx, XHCI_XFER_DMA_BYTES
    call memcpy
    pop rbx
    ret
xp_frozen:
    push rbx
    mov esi, [rel xhci_rt]
    add esi, XHCI_ERDP
    call xh_rd
    and eax, ~8
    cmp eax, [rel xp_erdp]
    jne .bad
    add esi, 4
    call xh_rd
    cmp eax, [rel xp_erdp + 4]
    jne .bad
    lea rdi, [rel xp_compare_image]
    call xhci_inst_copy_out
    XP_COMPARE xp_compare_image, xp_frozen_image, XHCI_INST_BYTES
    XP_COMPARE xhci_dcbaa_buf, xp_frozen_static, XP_STATIC_BYTES
    mov rdi, [rel xp_xfer]
    lea rsi, [rel xp_frozen_xfer]
    mov edx, XHCI_XFER_DMA_BYTES
    call memcmp
    test eax, eax
    jnz .bad
    xor eax, eax
    pop rbx
    ret
.bad:
    mov rax, DP_CHANGED
    pop rbx
    ret

xp_callback:
    push rbx
    push r12
    push r13
    mov r12d, esi
    mov r13, rdx
    cmp rcx, [rel reinit_power_xhci_context]
    jne .changed
    lea rax, [rel xhci_hcdev]
    cmp rdi, rax
    jne .changed
    ; A clock/deadline or class uncertainty is terminal custody. Generic
    ; recovery must never turn an early drain timeout into apparent readiness.
    cmp dword [rcx + dp_context.error], 0
    je .error_ok
    cmp dword [rcx + dp_context.error], DP_CANCELLED
    jne .failed
    cmp byte [rel xp_phase], 0
    jne .failed
.error_ok:
    call xp_binding
    test rax, rax
    jnz .changed
    call xp_hardware
    test rax, rax
    jnz .changed
    cmp r12d, DP_FENCE
    je .fence
    cmp r13, [rel xp_token]
    jne .dispatch
    lea rdi, [rel xp_compare_image]
    call xhci_inst_copy_out
    XP_COMPARE xp_compare_image, xp_owned_image, XHCI_INST_BYTES
.dispatch:
    cmp r13, [rel xp_token]
    jne .untouched                   ; cancel before this owner's FENCE
    cmp r12d, DP_STOP
    je .stop
    cmp r12d, DP_RESTORE
    je .restore
    cmp r12d, DP_VERIFY
    jne .failed
    call xp_running
    test rax, rax
    jnz .failed
    cmp byte [rel xp_phase], 0
    je .ready                        ; cancellation before stop effects
    cmp byte [rel xp_phase], 4
    jne .failed
    call xp_frozen
    test rax, rax
    jnz .changed
    mov esi, [rel xhci_op]
    call xh_rd
    cmp eax, [rel xp_command]
    jne .changed
    mov esi, [rel xhci_rt]
    add esi, XHCI_IMAN
    call xh_rd
    and eax, 2
    cmp eax, [rel xp_iman]
    jne .changed
.ready:
    mov byte [rel xp_phase], 0
    mov edx, DP_ACK_FENCED | DP_ACK_READY
    xor eax, eax
    jmp .out
.untouched:
    cmp r12d, DP_RESTORE
    je .untouched_restore
    cmp r12d, DP_VERIFY
    jne .failed
    call xp_running
    test rax, rax
    jnz .failed
    jmp .ready
.untouched_restore:
    mov edx, DP_ACK_FENCED
    xor eax, eax
    jmp .out
.fence:
    call xp_running
    test rax, rax
    jnz .failed
    mov [rel xp_token], r13
    mov byte [rel xp_phase], 0
    mov esi, [rel xhci_op]
    call xh_rd
    mov [rel xp_command], eax
    mov esi, [rel xhci_rt]
    add esi, XHCI_IMAN
    call xh_rd
    and eax, 2
    mov [rel xp_iman], eax
    lea rdi, [rel xp_owned_image]
    call xhci_inst_copy_out
    mov edx, DP_ACK_FENCED
    xor eax, eax
    jmp .out
.stop:
    cmp byte [rel xp_phase], 1
    je .halt_wait
    cmp byte [rel xp_phase], 2
    je .paused
    cmp byte [rel xp_phase], 0
    jne .failed
    call xp_running
    test rax, rax
    jnz .failed
    ; At most one event per callback. Only successful owned interrupt TDs may
    ; be routed/committed. PSC, commands, errors and unknown work retain head.
    mov eax, [rel xhci_evt_idx]
    cmp eax, XHCI_RING_TRBS
    jae .failed
    shl eax, 4
    mov rbx, [rel xhci_evt_ring]
    add rbx, rax
    mov eax, [rbx + 12]
    and eax, 1
    cmp eax, [rel xhci_evt_ccs]
    jne .empty
    mov eax, [rbx + 12]
    shr eax, 10
    and eax, 63
    cmp eax, XHCI_TRB_XFER_EVENT
    jne .failed
    mov eax, [rbx + 8]
    shr eax, 24
    cmp eax, 1
    je .route
    cmp eax, 13
    jne .failed
.route:
    call xhci_interrupt_route_event
    cmp eax, 1
    jne .failed
    mov edi, 1
    call xhci_event_commit
    jmp .pending
.empty:
    lea rdx, [rel xhci_intr_states]
    mov ecx, XHCI_INTR_STATE_COUNT
.pending_scan:
    cmp byte [rdx + xhci_intr_ep.pending], 0
    jne .pending
    add rdx, xhci_intr_ep_size
    loop .pending_scan
    mov esi, [rel xhci_op]
    call xh_rd
    cmp eax, [rel xp_command]
    jne .changed
    mov esi, [rel xhci_rt]
    add esi, XHCI_IMAN
    call xh_rd
    mov edx, eax
    and edx, 2
    cmp edx, [rel xp_iman]
    jne .changed
    test eax, 1                       ; unowned interrupt cannot be erased
    jnz .failed
    mov esi, [rel xhci_op]
    add esi, XHCI_CRCR
    call xh_rd
    test eax, 8
    jnz .failed
    mov esi, [rel xhci_rt]
    add esi, XHCI_IMAN
    call xh_rd
    ; Disable both actual IRQ source gates, then request halt. Preserve every
    ; other command bit, write zero to RW1C IP rather than clearing ownership.
    mov edx, eax
    and edx, ~3
    call xh_wr
    mov esi, [rel xhci_op]
    mov edx, [rel xp_command]
    and edx, ~5
    call xh_wr
    mov byte [rel xp_phase], 1
    jmp .pending
.halt_wait:
    mov esi, [rel xhci_op]
    call xh_rd
    test eax, 7
    jnz .failed
    mov esi, [rel xhci_rt]
    add esi, XHCI_IMAN
    call xh_rd
    test eax, 3
    jnz .failed
    mov esi, [rel xhci_op]
    add esi, XHCI_USBSTS
    call xh_rd
    test eax, 1
    jz .pending
    mov esi, [rel xhci_op]
    add esi, XHCI_CRCR
    call xh_rd
    test eax, 8                       ; command-ring running still unsafe
    jnz .failed
    ; No new phase-owned event may have appeared during the halt handshake.
    mov eax, [rel xhci_evt_idx]
    shl eax, 4
    mov rdx, [rel xhci_evt_ring]
    mov eax, [rdx + rax + 12]
    and eax, 1
    cmp eax, [rel xhci_evt_ccs]
    je .failed
    mov esi, [rel xhci_rt]
    add esi, XHCI_ERDP
    call xh_rd
    and eax, ~8
    mov [rel xp_erdp], eax
    add esi, 4
    call xh_rd
    mov [rel xp_erdp + 4], eax
    call xp_freeze
    lea rdi, [rel xp_owned_image]
    call xhci_inst_copy_out
    mov byte [rel xp_phase], 2
.paused:
    mov edx, DP_ACK_FENCED | DP_ACK_DRAINED | DP_ACK_IRQ_STOPPED | DP_ACK_DMA_STOPPED
    xor eax, eax
    jmp .out
.restore:
    cmp byte [rel xp_phase], 0
    je .restore_none
    cmp byte [rel xp_phase], 2
    je .restore_start
    cmp byte [rel xp_phase], 3
    jne .failed
    call xp_running
    test rax, rax
    jnz .pending                     ; same controller, wait actual HCH clear
    call xp_frozen
    test rax, rax
    jnz .changed
    mov byte [rel xp_phase], 4
.restore_none:
    mov edx, DP_ACK_FENCED
    xor eax, eax
    jmp .out
.restore_start:
    call xp_frozen
    test rax, rax
    jnz .changed
    mov esi, [rel xhci_op]
    call xh_rd
    test eax, 7
    jnz .failed
    mov esi, [rel xhci_op]
    add esi, XHCI_USBSTS
    call xh_rd
    test eax, 1
    jz .failed
    mov esi, [rel xhci_rt]
    add esi, XHCI_IMAN
    mov edx, [rel xp_iman]            ; never acknowledge an interrupt here
    call xh_wr
    mov esi, [rel xhci_op]
    mov edx, [rel xp_command]
    call xh_wr
    mov byte [rel xp_phase], 3
.pending:
    lea rdi, [rel xp_owned_image]
    call xhci_inst_copy_out
    mov eax, DP_PENDING
    xor edx, edx
    jmp .out
.bad:
.changed:
    mov rax, DP_CHANGED
    xor edx, edx
    jmp .out
.failed:
    mov rax, DP_FAILED
    xor edx, edx
.out:
    pop r13
    pop r12
    pop rbx
    cld
    ret

XP_REG_COUNT equ 14
XP_STATIC_BYTES equ xhci_scratch_arr - xhci_dcbaa_buf + XHCI_SCRATCH_MAX * 8
align 8
reinit_power_xhci_context: dq 0
xp_generation: dq 0
xp_xfer: dq 0
xp_token: dq 0
xp_erdp: dq 0
xp_command: dd 0
xp_iman: dd 0
xp_phase: db 0
align 8
xp_declaration:
    dd DP_VERSION, DP_USB
    dq 0, 0, 0, 0
    dd 0, DP_CAP_IRQ | DP_CAP_DMA
xp_pci_offsets: dd 0, 4, 8, 0x10, 0x14
xp_pci_values: times 5 dd 0
xp_ext_count: dd 0
xp_ext_offsets: times 32 dd 0
xp_ext_values: times 32 dd 0
xp_reg_offsets: times XP_REG_COUNT dd 0
xp_reg_values: times XP_REG_COUNT dd 0
xp_portsc: times 32 dd 0
xp_static_table:
    ; Signed offsets from each cell, resolved only at the live image base.
    dq xhci_dcbaa - $, xhci_dcbaa_buf - ($ + 8), xhci_cmd_ring - ($ + 16), xhci_cmd_buf - ($ + 24)
    dq xhci_evt_ring - $, xhci_evt_buf - ($ + 8), xhci_erst - ($ + 16), xhci_erst_buf - ($ + 24)
    dq xhci_in_ctx_base - $, xhci_in_ctx_buf - ($ + 8), xhci_out_ctx - ($ + 16), xhci_out_ctx_buf - ($ + 24)
    dq xhci_ep0_base - $, xhci_ep0_buf - ($ + 8), xhci_scr_arr_base - ($ + 16), xhci_scratch_arr - ($ + 24)
%macro WDATA_xhci_power 0
alignb 64
xp_binding_image: resb xhci_cmd_idx - xhci_region
xp_device: resb DEV_SIZE
xp_ops: resb usbhc_ops_size
xp_registry: resb USB_MAX_HC * 8 + 4
xp_ports: resb (XHCI_PORT_COUNT + XHCI_SLOT_COUNT) * 4
xp_topology: resb XHCI_SLOT_COUNT * usb_topo_size
xp_speed: resb XHCI_SLOT_COUNT * 8
xp_endpoints: resb XHCI_INTR_STATE_COUNT * xhci_intr_ep_size
xp_frozen_image: resb XHCI_INST_BYTES
xp_compare_image: resb XHCI_INST_BYTES
xp_owned_image: resb XHCI_INST_BYTES
xp_frozen_static: resb XP_STATIC_BYTES
xp_frozen_xfer: resb XHCI_XFER_DMA_BYTES
%endmacro
WDATA_BSS_DEFER WDATA_xhci_power
