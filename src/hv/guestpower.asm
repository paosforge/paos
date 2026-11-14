;; MODULE hv/guestpower
;; LAYER 5
;; EXPORTS guestpower_selected, guestpower_live, guestpower_mapped, guestpower_device_reset, guestpower_state_zero, guestpower_start, guestpower_mmio_write, guestpower_pump, guestpower_irq, guestpower_hlt_exit, guestpower_retired, nd_power_request, nd_power_state, nd_power_clean, nd_power_clean_generation, nd_power_clean_ms
;; IMPORTS hv/driver_domain, hv/vmx, hv/vm_profile, hv/hv_ops, boot/header
;; CAPS
;; OWNER rc-vm-claude
;; CONTEXT: bsp_only
; T5-1.C10b-1a: the driver domain's paos.power port and the clean HLT rule.
; Not hv/guest_power (driver_power v1 co-resident quiesce); no shared state.
;
; Device: modern virtio-console (device 3), VERSION_1 + MULTIPORT only, one
; port (id 0) named "paos.power", never a console. GPA 0xD0009000, IRQ5
; shared (each handler reads its own InterruptStatus). Selected only for the
; exact driver-domain closure armed by nd_begin (SEC 107064 B1); no profile bit.
; Host-to-guest only. The single line is built here from nd_generation and
; nd_nonce, never from guest bytes:
;   PAOS_POWER_V1 shutdown <decimal generation> <16 lowercase hex>\n  (<=51 B)
; The nonce has no exposure beyond the existing cmdline (paos.ndnonce=) and
; NDINFO, and nothing from the guest is ever authenticated by it here.
; Guest port bytes are counted (saturating) and discarded. Control messages
; are accepted for port 0 only. Any malformed chain, control message or
; feature/queue violation fails the device (status 128) until the guest resets
; it. Queue discipline is a copy of guestrestore's: each descriptor is read
; once into private memory, every span is range-checked against live guest RAM
; and kept disjoint from its queue's metadata, and each queue walk is bounded
; by QMAX per pump.
;
; Authority (S3): only nd_power_request arms the HLT rule, for exactly the
; current generation. START, STOP, failure, restart and a device failure
; disarm it. Neither an MMIO write nor a guest message arms anything.
; Clean (S4) is guest-asserted: an armed request, then a BSP guest HLT at CPL0
; with IF=0, RFLAGS.VM=0, no event injection pending and no event being
; delivered. It grants nothing and skips no teardown: the rule only sets
; nd_state 3 and hv_linux_stop_req, and nd_backend_stopped stays the sole
; retirement (S5). The clean exports are written there, at .retired, only when
; the marker equals nd_generation, and zeroed only at the next START.
;
; Resource trace: register page +8B000 after Wi-Fi +8A000, GPA 0xD0009000.
GPW_QUEUES equ 4
GPW_QMAX equ 64
GPW_SEGS equ 8
GPW_FEAT_MULTIPORT equ 2
GPW_CTRL_BYTES equ 8
GPW_LINE_MAX equ 64                   ; I3 bound; the longest line is 51 B
GPW_TX_DISCARD_MAX equ 4096           ; per-chain bound for discarded port bytes
GPW_IRQ equ 5
GPW_BAD_ID equ 0xFFFFFFFF
GPW_EV_DEVICE_READY equ 0
GPW_EV_PORT_ADD equ 1
GPW_EV_PORT_READY equ 3
GPW_EV_PORT_OPEN equ 6
GPW_EV_PORT_NAME equ 7
GPW_PEND_ADD equ 1
GPW_PEND_NAME equ 2
GPW_PEND_OPEN equ 4
GPW_OWNER_BYTES equ 48
GPW_RFLAGS_IF equ 1 << 9
GPW_RFLAGS_VM equ 1 << 17

%if (HV_GUESTPWR_PAGE & 0xFFF) || HV_GUESTPWR_PAGE != HV_GUESTWIFI_PAGE + 0x1000 || HV_GUESTPWR_PAGE < VST_END || HV_GUESTPWR_PAGE + 0x1000 > HV_NIC_POOL
    %error "paos.power backing must follow the Wi-Fi page, below the NIC pool"
%endif

struc GPW_WORK
    .meta: resq 6                     ; desc/avail/used HVA,length
    .segs: resq GPW_SEGS * 2          ; payload HVA,length
    .desc: resq 2                     ; one private descriptor copy
    .seen: resq 1
    .total: resq 1
    .num: resd 1
    .head: resd 1
    .count: resd 1
    .q: resd 1
    .msg: resb 80                     ; private control/line bytes
endstruc

; EAX=1 only for the exact driver-domain closure on its own admission path:
; the profile mask is one of the two frozen masks, equals the admitted
; nd_devices, belongs to nd_profile, and the domain is armed or attached.
; Never VP_DEV_NIC alone, never a caller flag. Clobbers EAX only.
guestpower_selected:
    mov  eax, [rel vm_profile_dev_mask]
    cmp  eax, VP_DEV_NICDOMAIN
    je   .mask
    cmp  eax, VP_DEV_WIFIDOMAIN
    jne  .no
.mask:
    cmp  eax, [rel nd_devices]
    jne  .no
    mov  rax, [rel vm_profile_active]
    test rax, rax
    jz   .no
    cmp  rax, [rel nd_profile]
    jne  .no
    cmp  dword [rel nd_state], 1
    jb   .no
    cmp  dword [rel nd_state], 2
    ja   .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; Only current private reservation arithmetic, never a guest register address.
gpw_page_hva:
    mov  rax, [rel hv_linux_region]
    test rax, rax
    jz   .bad
    mov  rdx, [rel hv_linux_region_capacity]
    cmp  rdx, HV_LINUX_CTRL_BYTES
    jb   .bad
    add  rdx, rax
    jc   .bad
    add  rax, HV_GUESTPWR_PAGE
    jc   .bad
    ret
.bad:
    xor  eax, eax
    ret

; RDI=48 private bytes. Binds START, the attached domain, backend and backing.
; EAX=success; no guest pointer is dereferenced.
gpw_owner_read:
    cmp  byte [rel hv_linux_stop_req], 0
    jne  .bad
    cmp  byte [rel hv_linux_start_active], 1
    jne  .bad
    cmp  byte [rel guestpower_live], 1
    jne  .bad
    cmp  dword [rel nd_state], 2
    jne  .bad
    mov  eax, [rel hv_linux_start_gen]
    test eax, eax
    jz   .bad
    cmp  eax, [rel hv_linux_start_consumed]
    jne  .bad
    cmp  eax, [rel vm_profile_gen]
    jne  .bad
    cmp  rax, [rel nd_generation]
    jne  .bad
    mov  [rdi], rax
    mov  rax, [rel nd_profile]
    test rax, rax
    jz   .bad
    mov  [rdi + 8], rax
    mov  rax, [rel hv_ops_active]
    test rax, rax
    jz   .bad
    mov  [rdi + 16], rax
    mov  rax, [rel hv_linux_region]
    test rax, rax
    jz   .bad
    mov  [rdi + 24], rax
    mov  rax, [rel hv_linux_ram]
    test rax, rax
    jz   .bad
    mov  [rdi + 32], rax
    mov  rax, [rel gpw_page]
    mov  [rdi + 40], rax
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; EAX=1 only while the bound START/domain/backing receipt is unchanged.
gpw_current:
    cmp  byte [rel hv_linux_running], 1
    jne  .bad
    cmp  qword [rel gpw_page], 0
    je   .bad
    sub  rsp, GPW_OWNER_BYTES + 8
    mov  rdi, rsp
    call gpw_owner_read
    test eax, eax
    jz   .out
    lea  rsi, [rel gpw_owner]
    mov  rdi, rsp
    mov  ecx, GPW_OWNER_BYTES / 8
    cld
    repe cmpsq
    sete al
    movzx eax, al
.out:
    add  rsp, GPW_OWNER_BYTES + 8
    ret
.bad:
    xor  eax, eax
    ret

; Revoke addresses, queues and pending control. The request is not touched:
; a guest reset or a stale receipt never arms or disarms a shutdown.
gpw_device_zero:
    pushfq
    cld
    call gpw_page_hva
    test rax, rax
    jz   .private
    cmp  rax, [rel gpw_page]
    jne  .private
    mov  dword [rax + 0x60], 0
    mov  dword [rax + 0x70], 0
.private:
    lea  rdi, [rel gpw_state]
    mov  ecx, gpw_state_end - gpw_state
    xor  eax, eax
    rep  stosb
    popfq
    ret

; STOP, failure and restart (S3): revoke the device and disarm the request.
; A recorded clean result stays for 1b to read until the next START.
guestpower_state_zero:
    call gpw_device_zero
    mov  dword [rel gpw_req_state], 0
    mov  qword [rel gpw_req_gen], 0
    mov  qword [rel gpw_marker], 0
    ret

; START only: everything above, plus the previous START's clean result.
guestpower_start:
    call guestpower_state_zero
    mov  byte [rel nd_power_clean], 0
    mov  qword [rel nd_power_clean_generation], 0
    mov  qword [rel nd_power_clean_ms], 0
    mov  qword [rel gpw_tx_discarded], 0    ; diagnostics are per START
    mov  dword [rel gpw_ctl_from_guest], 0
    mov  dword [rel gpw_ctl_to_guest], 0
    mov  dword [rel gpw_lines], 0
    ret

; Fresh register page bound to the current START. EAX=1 bound, 0 refused.
guestpower_device_reset:
    pushfq
    cld
    call gpw_device_zero
    call gpw_page_hva
    test rax, rax
    jz   .out
    mov  [rel gpw_page], rax
    lea  rdi, [rel gpw_owner]
    call gpw_owner_read
    test eax, eax
    jz   .refuse
    mov  rdi, [rel gpw_page]
    mov  ecx, 4096 / 8
    xor  eax, eax
    rep  stosq
    mov  rax, [rel gpw_page]
    mov  dword [rax], 0x74726976      ; "virt"
    mov  dword [rax + 4], 2
    mov  dword [rax + 8], 3           ; virtio-console
    mov  dword [rax + 12], 0x50614f53
    mov  dword [rax + 0x10], GPW_FEAT_MULTIPORT
    mov  dword [rax + 0x34], GPW_QMAX
    mov  dword [rax + 0x104], 1       ; max_nr_ports; cols/rows/emerg_wr zero
    mov  eax, 1
    jmp  .out
.refuse:
    call gpw_device_zero
    xor  eax, eax
.out:
    popfq
    ret

; Device failure: revoke addresses/bytes, retain only a FAILED register, and
; disarm a request that has not fired (S3).
gpw_fail:
    cmp  dword [rel gpw_req_state], 1
    jb   .device
    cmp  dword [rel gpw_req_state], 2
    ja   .device
    mov  dword [rel gpw_req_state], 0
    mov  qword [rel gpw_req_gen], 0
.device:
    sub  rsp, 8                             ; callee entry stays 16-aligned
    call guestpower_device_reset
    add  rsp, 8
    test eax, eax
    jz   .out
    mov  dword [rel gpw_status], 128
    mov  rax, [rel gpw_page]
    mov  dword [rax + 0x70], 128
.out:
    ret

; MMIO store EDI=page offset, ESI=value (dword only via the shared decoder).
guestpower_mmio_write:
    pushfq
    cld
    push rbx
    push r12
    push r13
    sub  rsp, 8
    mov  r12d, edi
    mov  r13d, esi
    call gpw_current
    test eax, eax
    jz   .revoke
    mov  rbx, [rel gpw_page]
    cmp  dword [rel gpw_status], 128
    jne  .live
    cmp  r12d, 0x70                   ; FAILED accepts only a reset
    jne  .done
    test r13d, r13d
    jnz  .done
.live:
    cmp  r12d, 0x70
    je   .status
    cmp  r12d, 0x64
    je   .ack
    cmp  r12d, 0x50
    je   .notify
    cmp  r12d, 0x14
    je   .fsel
    cmp  r12d, 0x20
    je   .feature
    cmp  r12d, 0x24
    je   .dfsel
    cmp  r12d, 0x30
    je   .qsel
    cmp  r12d, 0x44
    je   .ready
    cmp  r12d, 0x38
    je   .config_write
    cmp  r12d, 0x80
    je   .config_write
    cmp  r12d, 0x84
    je   .config_write
    cmp  r12d, 0x90
    je   .config_write
    cmp  r12d, 0x94
    je   .config_write
    cmp  r12d, 0xa0
    je   .config_write
    cmp  r12d, 0xa4
    je   .config_write
    jmp  .done
.fsel:
    xor  eax, eax
    cmp  r13d, 1
    ja   .fsel_store
    mov  eax, 1                       ; VIRTIO_F_VERSION_1
    je   .fsel_store
    mov  eax, GPW_FEAT_MULTIPORT
.fsel_store:
    mov  [rbx + 0x10], eax
    jmp  .done
.dfsel:
    mov  [rel gpw_dfsel], r13d
    jmp  .done
.feature:
    test dword [rel gpw_status], 8
    jnz  .fail                        ; accepted negotiation is immutable
    mov  eax, [rel gpw_dfsel]
    cmp  eax, 1
    ja   .feature_high
    lea  rdx, [rel gpw_drvfeat]
    mov  [rdx + rax*4], r13d
    jmp  .done
.feature_high:
    test r13d, r13d
    jnz  .fail
    jmp  .done
.qsel:
    mov  [rel gpw_qsel], r13d
    xor  eax, eax
    xor  edx, edx
    cmp  r13d, GPW_QUEUES
    jae  .qview
    mov  eax, GPW_QMAX
    lea  rcx, [rel gpw_q_ready]
    movzx edx, byte [rcx + r13]
.qview:
    mov  [rbx + 0x34], eax
    mov  [rbx + 0x44], edx
    jmp  .done
.config_write:
    mov  ecx, [rel gpw_qsel]
    cmp  ecx, GPW_QUEUES
    jae  .done
    lea  rdx, [rel gpw_q_ready]
    cmp  byte [rdx + rcx], 0
    jne  .fail                        ; no reconfiguration of a live queue
    cmp  r12d, 0x38
    je   .qnum
    mov  eax, r12d
    sub  eax, 0x80
    shr  eax, 4                       ; 0 desc, 1 avail, 2 used
    lea  rdx, [rel gpw_q_addr]
    imul eax, eax, GPW_QUEUES * 8
    add  rdx, rax
    test r12d, 4
    jnz  .addr_hi
    mov  [rdx + rcx*8], r13d
    jmp  .done
.addr_hi:
    mov  [rdx + rcx*8 + 4], r13d
    jmp  .done
.qnum:
    lea  rdx, [rel gpw_q_num]
    mov  [rdx + rcx*4], r13d
    jmp  .done
.ready:
    mov  ecx, [rel gpw_qsel]
    cmp  ecx, GPW_QUEUES
    jae  .done
    cmp  r13d, 1
    jne  .fail                        ; no negotiated RING_RESET
    lea  rdx, [rel gpw_q_ready]
    cmp  byte [rdx + rcx], 0
    jne  .done
    mov  eax, [rel gpw_status]
    and  eax, ~4
    cmp  eax, 11                      ; FEATURES_OK|DRIVER|ACKNOWLEDGE
    jne  .fail
    lea  rax, [rel gpw_q_num]
    mov  eax, [rax + rcx*4]
    test eax, eax
    jz   .fail
    cmp  eax, GPW_QMAX
    ja   .fail
    lea  r8d, [eax - 1]
    test eax, r8d
    jnz  .fail
    mov  byte [rdx + rcx], 1
    mov  dword [rbx + 0x44], 1
    jmp  .done
.status:
    test r13d, r13d
    jnz  .status_nonzero
    call guestpower_device_reset
    jmp  .done
.status_nonzero:
    mov  eax, [rel gpw_status]
    mov  edx, eax
    or   edx, r13d
    cmp  edx, r13d
    jne  .fail                        ; only reset may clear status bits
    test r13d, ~0x0F
    jnz  .fail
    cmp  r13d, 1
    je   .store
    cmp  r13d, 3
    je   .store
    cmp  r13d, 11
    je   .features_ok
    cmp  r13d, 15
    jne  .fail
    test eax, 8
    jz   .fail
    jmp  .store
.features_ok:
    ; Exactly VERSION_1 + MULTIPORT. Without MULTIPORT Linux would turn
    ; this device into another console; that shape is never offered.
    cmp  dword [rel gpw_drvfeat], GPW_FEAT_MULTIPORT
    jne  .fail
    cmp  dword [rel gpw_drvfeat + 4], 1
    jne  .fail
.store:
    mov  [rel gpw_status], r13d
    mov  [rbx + 0x70], r13d
    jmp  .done
.ack:
    mov  eax, r13d
    not  eax
    and  [rel gpw_isr], eax
    mov  eax, [rel gpw_isr]
    mov  [rbx + 0x60], eax
    test eax, eax
    jnz  .done
    mov  byte [rel gpw_irq_pend], 0
    mov  byte [rel gpw_irq_inj], 0
    jmp  .done
.notify:
    cmp  r13d, GPW_QUEUES
    jae  .done
    call guestpower_pump
    jmp  .done
.fail:
    call gpw_fail
    jmp  .done
.revoke:
    call gpw_device_zero
.done:
    add  rsp, 8
    pop  r13
    pop  r12
    pop  rbx
    popfq
    ret

; RDI=full64 GPA, RSI=full64 length -> RAX=HVA or zero. Clobbers RAX,RDX.
gpw_range:
    test rsi, rsi
    jz   .bad
    mov  rax, rdi
    add  rax, rsi
    jc   .bad
    cmp  rax, [rel hv_linux_ram_bytes]
    ja   .bad
    mov  rax, [rel hv_linux_ram]
    add  rax, rdi
    jc   .bad
    mov  rdx, rax
    add  rdx, rsi
    jc   .bad
    ret
.bad:
    xor  eax, eax
    ret

; RBP=work, RAX=start, RSI=length, RDI=span array, ECX=count -> EDX=disjoint.
gpw_disjoint:
    mov  edx, 1
    lea  r8, [rax + rsi]
.loop:
    test ecx, ecx
    jz   .out
    mov  r9, [rdi]
    cmp  r9, r8
    jae  .next
    add  r9, [rdi + 8]
    cmp  rax, r9
    jb   .bad
.next:
    add  rdi, 16
    dec  ecx
    jmp  .loop
.bad:
    xor  edx, edx
.out:
    ret

; RBP=work, EDI=queue. Validates and records the ready queue's metadata.
; EAX=1 ok, 0 malformed (caller fails the device).
gpw_meta:
    push rbx
    push r12
    mov  ebx, edi
    mov  [rbp + GPW_WORK.q], edi
    lea  rax, [rel gpw_q_ready]
    cmp  byte [rax + rbx], 1
    jne  .bad
    lea  rax, [rel gpw_q_num]
    mov  r12d, [rax + rbx*4]
    mov  [rbp + GPW_WORK.num], r12d
    ; desc: 16-aligned, num*16
    lea  rax, [rel gpw_q_addr]
    mov  rdi, [rax + rbx*8]
    test dil, 15
    jnz  .bad
    mov  esi, r12d
    shl  esi, 4
    call gpw_range
    test rax, rax
    jz   .bad
    mov  [rbp + GPW_WORK.meta], rax
    mov  [rbp + GPW_WORK.meta + 8], rsi
    ; avail: 2-aligned, 6 + num*2
    lea  rax, [rel gpw_q_addr + GPW_QUEUES * 8]
    mov  rdi, [rax + rbx*8]
    test dil, 1
    jnz  .bad
    lea  esi, [r12d*2 + 6]
    call gpw_range
    test rax, rax
    jz   .bad
    push rdi
    lea  rdi, [rbp + GPW_WORK.meta]
    mov  ecx, 1
    call gpw_disjoint
    pop  rdi
    test edx, edx
    jz   .bad
    mov  [rbp + GPW_WORK.meta + 16], rax
    mov  [rbp + GPW_WORK.meta + 24], rsi
    ; used: 4-aligned, 6 + num*8
    lea  rax, [rel gpw_q_addr + GPW_QUEUES * 16]
    mov  rdi, [rax + rbx*8]
    test dil, 3
    jnz  .bad
    lea  esi, [r12d*8 + 6]
    call gpw_range
    test rax, rax
    jz   .bad
    lea  rdi, [rbp + GPW_WORK.meta]
    mov  ecx, 2
    call gpw_disjoint
    test edx, edx
    jz   .bad
    mov  [rbp + GPW_WORK.meta + 32], rax
    mov  [rbp + GPW_WORK.meta + 40], rsi
    mov  eax, 1
    pop  r12
    pop  rbx
    ret
.bad:
    xor  eax, eax
    pop  r12
    pop  rbx
    ret

; RBP=work after gpw_meta. EAX=1 head taken into work.head, 0 none, -1 bad.
gpw_next_head:
    mov  ecx, [rbp + GPW_WORK.q]
    mov  rdx, [rbp + GPW_WORK.meta + 16]
    movzx eax, word [rdx + 2]
    lea  r8, [rel gpw_q_last]
    movzx r9d, word [r8 + rcx*2]
    sub  ax, r9w
    jz   .none
    movzx eax, ax
    cmp  eax, [rbp + GPW_WORK.num]
    ja   .bad                         ; overrun/stale avail is not a head
    lfence
    mov  eax, [rbp + GPW_WORK.num]
    dec  eax
    and  eax, r9d
    movzx eax, word [rdx + rax*2 + 4]
    cmp  eax, [rbp + GPW_WORK.num]
    jae  .bad
    mov  [rbp + GPW_WORK.head], eax
    mov  eax, 1
    ret
.none:
    xor  eax, eax
    ret
.bad:
    mov  eax, -1
    ret

; RBP=work with head. EDI=2 writable chain required, 0 readable. Each
; descriptor is copied once; no indirect/unknown flags. EAX=1 ok, 0 bad.
gpw_chain:
    push rbx
    push r12
    push r13
    mov  r13d, edi
    mov  qword [rbp + GPW_WORK.seen], 0
    mov  qword [rbp + GPW_WORK.total], 0
    mov  dword [rbp + GPW_WORK.count], 0
    mov  ebx, [rbp + GPW_WORK.head]
.walk:
    cmp  ebx, [rbp + GPW_WORK.num]
    jae  .bad
    bts  qword [rbp + GPW_WORK.seen], rbx
    jc   .bad
    cmp  dword [rbp + GPW_WORK.count], GPW_SEGS
    jae  .bad
    mov  rsi, [rbp + GPW_WORK.meta]
    mov  eax, ebx
    shl  eax, 4
    mov  rcx, [rsi + rax]
    mov  [rbp + GPW_WORK.desc], rcx
    mov  rcx, [rsi + rax + 8]
    mov  [rbp + GPW_WORK.desc + 8], rcx
    movzx eax, word [rbp + GPW_WORK.desc + 12]
    mov  edx, eax
    and  edx, ~1
    cmp  edx, r13d                    ; exact direction; no INDIRECT/reserved
    jne  .bad
    mov  rdi, [rbp + GPW_WORK.desc]
    mov  esi, [rbp + GPW_WORK.desc + 8]
    call gpw_range
    test rax, rax
    jz   .bad
    lea  rdi, [rbp + GPW_WORK.meta]
    mov  ecx, 3
    call gpw_disjoint
    test edx, edx
    jz   .bad
    lea  rdi, [rbp + GPW_WORK.segs]
    mov  ecx, [rbp + GPW_WORK.count]
    call gpw_disjoint
    test edx, edx
    jz   .bad
    mov  ecx, [rbp + GPW_WORK.count]
    shl  ecx, 4
    mov  [rbp + GPW_WORK.segs + rcx], rax
    mov  [rbp + GPW_WORK.segs + rcx + 8], rsi
    inc  dword [rbp + GPW_WORK.count]
    add  [rbp + GPW_WORK.total], rsi
    test word [rbp + GPW_WORK.desc + 12], 1
    jz   .ok
    movzx ebx, word [rbp + GPW_WORK.desc + 14]
    jmp  .walk
.ok:
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; RBP=work. Copies ECX private bytes from work.msg into the writable segments.
; Caller proved total >= ECX.
gpw_fill:
    lea  rsi, [rbp + GPW_WORK.msg]
    xor  r8d, r8d
.seg:
    test ecx, ecx
    jz   .out
    mov  eax, r8d
    shl  eax, 4
    mov  rdi, [rbp + GPW_WORK.segs + rax]
    mov  rdx, [rbp + GPW_WORK.segs + rax + 8]
    cmp  rdx, rcx
    jbe  .bounded
    mov  edx, ecx
.bounded:
    sub  ecx, edx
    xchg rcx, rdx
    rep  movsb
    mov  rcx, rdx
    inc  r8d
    jmp  .seg
.out:
    ret

; RBP=work. Copies the first min(total,ECX) readable bytes into work.msg.
; EAX=bytes copied.
gpw_gather:
    lea  rdi, [rbp + GPW_WORK.msg]
    xor  r8d, r8d
    xor  r9d, r9d
.seg:
    test ecx, ecx
    jz   .out
    cmp  r8d, [rbp + GPW_WORK.count]
    jae  .out
    mov  eax, r8d
    shl  eax, 4
    mov  rsi, [rbp + GPW_WORK.segs + rax]
    mov  rdx, [rbp + GPW_WORK.segs + rax + 8]
    cmp  rdx, rcx
    jbe  .bounded
    mov  edx, ecx
.bounded:
    sub  ecx, edx
    add  r9d, edx
    xchg rcx, rdx
    rep  movsb
    mov  rcx, rdx
    inc  r8d
    jmp  .seg
.out:
    mov  eax, r9d
    ret

; RBP=work with head. EDX=written length. Publishes used.idx last.
gpw_used:
    mov  ecx, [rbp + GPW_WORK.q]
    mov  r8, [rbp + GPW_WORK.meta + 32]
    lea  r9, [rel gpw_q_usedidx]
    movzx eax, word [r9 + rcx*2]
    mov  r10d, [rbp + GPW_WORK.num]
    dec  r10d
    and  r10d, eax
    mov  r11d, [rbp + GPW_WORK.head]
    mov  [r8 + r10*8 + 4], r11d
    mov  [r8 + r10*8 + 8], edx
    inc  ax
    mov  [r9 + rcx*2], ax
    sfence
    mov  [r8 + 2], ax
    lea  r9, [rel gpw_q_last]
    inc  word [r9 + rcx*2]
    mov  byte [rel gpw_used_any], 1
    ret

; Saturating u32 increment of [RDI]. Clobbers EAX.
gpw_count32:
    mov  eax, [rdi]
    inc  eax
    jz   .out
    mov  [rdi], eax
.out:
    ret

; Guest control messages (queue 3). EAX=1 ok, 0 malformed.
gpw_serve_control_tx:
    push rbx
    mov  ebx, GPW_QMAX
.loop:
    test ebx, ebx
    jz   .ok
    dec  ebx
    mov  edi, 3
    call gpw_meta
    test eax, eax
    jz   .bad
    call gpw_next_head
    test eax, eax
    jz   .ok
    js   .bad
    xor  edi, edi
    call gpw_chain
    test eax, eax
    jz   .bad
    cmp  qword [rbp + GPW_WORK.total], GPW_CTRL_BYTES
    jne  .bad
    mov  ecx, GPW_CTRL_BYTES
    call gpw_gather
    xor  edx, edx
    call gpw_used
    lea  rdi, [rel gpw_ctl_from_guest]
    call gpw_count32
    mov  eax, [rbp + GPW_WORK.msg]          ; id
    movzx ecx, word [rbp + GPW_WORK.msg + 4] ; event
    movzx edx, word [rbp + GPW_WORK.msg + 6] ; value
    cmp  ecx, GPW_EV_DEVICE_READY
    je   .device_ready
    test eax, eax                           ; only port 0 exists
    jnz  .bad
    cmp  ecx, GPW_EV_PORT_READY
    je   .port_ready
    cmp  ecx, GPW_EV_PORT_OPEN
    je   .port_open
    jmp  .bad
.device_ready:
    cmp  eax, GPW_BAD_ID
    jne  .bad
    cmp  edx, 1
    jne  .bad
    cmp  byte [rel gpw_dev_ready], 0
    jne  .bad
    mov  byte [rel gpw_dev_ready], 1
    or   byte [rel gpw_pending], GPW_PEND_ADD
    jmp  .loop
.port_ready:
    cmp  byte [rel gpw_dev_ready], 1
    jne  .bad
    cmp  edx, 1
    jne  .bad                               ; guest refused its own port
    cmp  byte [rel gpw_port_ready], 0
    jne  .loop                              ; repeated READY is harmless
    mov  byte [rel gpw_port_ready], 1
    or   byte [rel gpw_pending], GPW_PEND_NAME | GPW_PEND_OPEN
    jmp  .loop
.port_open:
    cmp  byte [rel gpw_port_ready], 1
    jne  .bad
    cmp  edx, 1
    ja   .bad
    mov  [rel gpw_guest_open], dl
    jmp  .loop
.ok:
    mov  eax, 1
    pop  rbx
    ret
.bad:
    xor  eax, eax
    pop  rbx
    ret

; Discard guest port bytes (queue 1). EAX=1 ok, 0 malformed. Saturating count.
gpw_serve_port_tx:
    push rbx
    mov  ebx, GPW_QMAX
.loop:
    test ebx, ebx
    jz   .ok
    dec  ebx
    mov  edi, 1
    call gpw_meta
    test eax, eax
    jz   .bad
    call gpw_next_head
    test eax, eax
    jz   .ok
    js   .bad
    xor  edi, edi
    call gpw_chain
    test eax, eax
    jz   .bad
    mov  rax, [rbp + GPW_WORK.total]
    cmp  rax, GPW_TX_DISCARD_MAX
    ja   .bad
    add  [rel gpw_tx_discarded], rax
    jnc  .counted
    mov  qword [rel gpw_tx_discarded], -1   ; S2: saturate, never wrap
.counted:
    xor  edx, edx
    call gpw_used
    jmp  .loop
.ok:
    mov  eax, 1
    pop  rbx
    ret
.bad:
    xor  eax, eax
    pop  rbx
    ret

; Deliver host control messages in protocol order (queue 2).
; EAX=1 ok (possibly still pending for lack of buffers), 0 malformed.
gpw_serve_control_rx:
.next:
    movzx eax, byte [rel gpw_pending]
    test eax, eax
    jz   .ok
    mov  edi, 2
    call gpw_meta
    test eax, eax
    jz   .bad
    call gpw_next_head
    test eax, eax
    jz   .ok                                ; wait for a posted buffer
    js   .bad
    mov  edi, 2
    call gpw_chain
    test eax, eax
    jz   .bad
    mov  dword [rbp + GPW_WORK.msg], 0      ; port id 0
    movzx eax, byte [rel gpw_pending]
    test eax, GPW_PEND_ADD
    jz   .name
    mov  dword [rbp + GPW_WORK.msg + 4], GPW_EV_PORT_ADD
    and  byte [rel gpw_pending], ~GPW_PEND_ADD
    mov  ecx, GPW_CTRL_BYTES
    jmp  .deliver
.name:
    test eax, GPW_PEND_NAME
    jz   .open
    mov  dword [rbp + GPW_WORK.msg + 4], GPW_EV_PORT_NAME
    lea  rsi, [rel gpw_port_name]
    lea  rdi, [rbp + GPW_WORK.msg + GPW_CTRL_BYTES]
    mov  ecx, gpw_port_name_end - gpw_port_name
    rep  movsb
    and  byte [rel gpw_pending], ~GPW_PEND_NAME
    mov  ecx, GPW_CTRL_BYTES + gpw_port_name_end - gpw_port_name
    jmp  .deliver
.open:
    mov  dword [rbp + GPW_WORK.msg + 4], GPW_EV_PORT_OPEN | (1 << 16)
    and  byte [rel gpw_pending], ~GPW_PEND_OPEN
    mov  ecx, GPW_CTRL_BYTES
.deliver:
    mov  eax, ecx
    cmp  rax, [rbp + GPW_WORK.total]
    ja   .bad                               ; Linux posts PAGE_SIZE buffers
    push rcx
    call gpw_fill
    pop  rdx
    call gpw_used
    lea  rdi, [rel gpw_ctl_to_guest]
    call gpw_count32
    jmp  .next
.ok:
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; RDI=dest (at least GPW_LINE_MAX bytes). Builds the one fixed line from
; nd_generation and nd_nonce only. EAX=length, or 0 when either is not the
; grammar (generation 1..2^32-1, 16 lowercase hex). Clobbers RCX,RDX,RSI,R8-R10.
gpw_build_line:
    mov  r10, rdi
    lea  rsi, [rel gpw_line_head]
    mov  ecx, gpw_line_head_end - gpw_line_head
    cld
    rep  movsb
    mov  rax, [rel nd_generation]
    test rax, rax
    jz   .bad
    mov  edx, 0xFFFFFFFF
    cmp  rax, rdx
    ja   .bad
    ; decimal, no leading zero: digits into the tail of the buffer, then moved
    lea  r9, [r10 + GPW_LINE_MAX]
    mov  r8d, 10
.decimal:
    xor  edx, edx
    div  r8
    add  dl, '0'
    dec  r9
    mov  [r9], dl
    test rax, rax
    jnz  .decimal
    lea  rcx, [r10 + GPW_LINE_MAX]
    sub  rcx, r9
    mov  rsi, r9
    rep  movsb                              ; forward copy never overtakes rsi
    mov  byte [rdi], ' '
    inc  rdi
    lea  rsi, [rel nd_nonce]
    mov  ecx, 16
.nonce:
    mov  al, [rsi]
    cmp  al, '0'
    jb   .bad
    cmp  al, '9'
    jbe  .hex
    cmp  al, 'a'
    jb   .bad
    cmp  al, 'f'
    ja   .bad
.hex:
    mov  [rdi], al
    inc  rsi
    inc  rdi
    dec  ecx
    jnz  .nonce
    mov  byte [rdi], 10
    inc  rdi
    mov  rax, rdi
    sub  rax, r10
    cmp  eax, GPW_LINE_MAX
    ja   .bad
    ret
.bad:
    xor  eax, eax
    ret

; Deliver the one requested line on port 0 (queue 0).
; EAX=1 ok (delivered or still waiting), 0 malformed.
gpw_serve_line:
    cmp  byte [rel gpw_notify_req], 1
    jne  .ok
    cmp  byte [rel gpw_guest_open], 1
    jne  .ok                                ; deferred until the listener opens it
    mov  edi, 0
    call gpw_meta
    test eax, eax
    jz   .bad
    call gpw_next_head
    test eax, eax
    jz   .ok                                ; deferred until a buffer is posted
    js   .bad
    mov  edi, 2
    call gpw_chain
    test eax, eax
    jz   .bad
    cmp  dword [rel gpw_req_state], 1
    jne  .refused
    cmp  dword [rel nd_state], 2
    jne  .refused
    mov  rax, [rel gpw_req_gen]
    test rax, rax
    jz   .refused
    cmp  rax, [rel nd_generation]
    jne  .refused
    lea  rdi, [rbp + GPW_WORK.msg]
    call gpw_build_line
    test eax, eax
    jz   .refused
    cmp  rax, [rbp + GPW_WORK.total]
    ja   .bad                               ; Linux posts PAGE_SIZE buffers
    mov  ecx, eax
    push rax
    push rax
    call gpw_fill
    pop  rdx
    pop  rax
    call gpw_used
    mov  byte [rel gpw_notify_req], 0
    mov  dword [rel gpw_req_state], 2       ; taken: used ring is past the line
    lea  rdi, [rel gpw_lines]
    call gpw_count32
    jmp  .ok
.refused:
    ; No line for a request that is no longer this attached generation's.
    mov  byte [rel gpw_notify_req], 0
    mov  dword [rel gpw_req_state], 0
    mov  qword [rel gpw_req_gen], 0
.ok:
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; Stopped-vCPU worker: guest control, discarded port bytes, host control and
; the one pending line. Bounded by QMAX per queue; scrubs its private bytes.
guestpower_pump:
    cmp  qword [rel gpw_page], 0
    je   .idle                              ; never selected: nothing to revoke
    pushfq
    cld
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rax, rsp
    and  rsp, -16
    sub  rsp, GPW_WORK_size + 16
    mov  [rsp + GPW_WORK_size], rax
    mov  rbp, rsp
    mov  rdi, rsp
    mov  ecx, GPW_WORK_size
    xor  eax, eax
    rep  stosb
    call gpw_current
    test eax, eax
    jz   .revoke
    cmp  dword [rel gpw_status], 15
    jne  .out
    mov  byte [rel gpw_used_any], 0
    lea  rax, [rel gpw_q_ready]
    cmp  byte [rax + 3], 1
    jne  .port_tx
    call gpw_serve_control_tx
    test eax, eax
    jz   .fail
.port_tx:
    lea  rax, [rel gpw_q_ready]
    cmp  byte [rax + 1], 1
    jne  .control_rx
    call gpw_serve_port_tx
    test eax, eax
    jz   .fail
.control_rx:
    lea  rax, [rel gpw_q_ready]
    cmp  byte [rax + 2], 1
    jne  .line
    call gpw_serve_control_rx
    test eax, eax
    jz   .fail
.line:
    lea  rax, [rel gpw_q_ready]
    cmp  byte [rax], 1
    jne  .irq
    call gpw_serve_line
    test eax, eax
    jz   .fail
.irq:
    cmp  byte [rel gpw_used_any], 1
    jne  .out
    or   dword [rel gpw_isr], 1
    mov  rax, [rel gpw_page]
    mov  ecx, [rel gpw_isr]
    mov  [rax + 0x60], ecx
    mov  byte [rel gpw_irq_pend], 1
    jmp  .out
.fail:
    call gpw_fail
    jmp  .out
.revoke:
    call gpw_device_zero
.out:
    mov  rdi, rbp
    mov  ecx, GPW_WORK_size
    xor  eax, eax
    rep  stosb
    mov  rsp, [rbp + GPW_WORK_size]
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    popfq
.idle:
    ret

; EAX=nonzero only when IRQ5 was injected for this device.
guestpower_irq:
    cmp  qword [rel gpw_page], 0
    je   .none
    pushfq
    cld
    call gpw_current
    test eax, eax
    jz   .revoke
    cmp  byte [rel gpw_irq_pend], 1
    jne  .no
    cmp  byte [rel gpw_irq_inj], 0
    jne  .no
    cmp  dword [rel gpw_status], 15
    jne  .no
    mov  edi, GPW_IRQ
    call hv_pic_try_inject
    test eax, eax
    jz   .out
    mov  byte [rel gpw_irq_inj], 1
    jmp  .out
.revoke:
    call gpw_device_zero
.no:
    xor  eax, eax
.out:
    popfq
    ret
.none:
    xor  eax, eax
    ret

; The clean HLT rule (C10b-1a; SEC 107064 S3-S6, amended 107089). Called only
; from the BSP HLT exit after the instruction is skipped. EAX=1 when it fired:
; it then set only the marker, power state 3, nd_state 3 and stop_req, and
; the caller resumes into the normal STOP path (nd_backend_stopped retires).
; EAX=0 leaves every state untouched and the HLT is handled as before.
guestpower_hlt_exit:
    sub  rsp, 8
    cmp  dword [rel vcb_handoff_active], 0
    jne  .no                                ; BSP only
    mov  eax, [rel gpw_req_state]
    cmp  eax, 1
    jb   .no
    cmp  eax, 2
    ja   .no
    cmp  dword [rel nd_state], 2
    jne  .no
    mov  rax, [rel nd_generation]
    test rax, rax
    jz   .no
    cmp  rax, [rel gpw_req_gen]
    jne  .no                                ; armed for this generation only
    mov  ecx, [rel hv_linux_start_gen]
    cmp  rax, rcx
    jne  .no
    cmp  byte [rel guestpower_live], 1
    jne  .no
    mov  edi, VMXF_GUEST_CS_SEL             ; CPL from CS.RPL, never SS AR (SVM reads 0)
    call hv_guest_read
    test eax, 3
    jnz  .no
    mov  edi, VMXF_G_RFLAGS                 ; VMCB save-area RFLAGS on SVM
    call hv_guest_read
    test eax, GPW_RFLAGS_IF
    jnz  .no
    test eax, GPW_RFLAGS_VM                 ; CS&3 is not the CPL in virtual-8086 mode
    jnz  .no
    mov  edi, VMXF_ENTRY_INTR               ; EVENTINJ.V on SVM
    call hv_guest_read
    test eax, 0x80000000
    jnz  .no
    mov  edi, VMXF_IDT_VEC_INFO             ; EXITINTINFO.V on SVM
    call hv_guest_read
    test eax, 0x80000000
    jnz  .no
    mov  rax, [rel nd_generation]
    mov  [rel gpw_marker], rax
    mov  dword [rel gpw_req_state], 3
    mov  dword [rel nd_state], 3
    mov  byte [rel hv_linux_stop_req], 1
    mov  eax, 1
    add  rsp, 8
    ret
.no:
    xor  eax, eax
    add  rsp, 8
    ret

; NAL1 byte 241 (SEC 107097 condition 1): EAX=1 exactly when the actual EPT/NPT
; PT entry 9 is present and maps this START's paos.power backing page by address
; equality; else 0. Never reads the selection, the mask or guestpower_live.
; Clobbers RAX, RCX, RDX only.
guestpower_mapped:
    mov  rdx, [rel hv_linux_region]
    test rdx, rdx
    jz   .no
    mov  rax, [rdx + HV_VCON_EPT_PT + 9 * 8]
    test eax, 1                             ; EPT read / NPT present
    jz   .no
    mov  rcx, 0x000FFFFFFFFFF000
    and  rax, rcx
    lea  rcx, [rdx + HV_GUESTPWR_PAGE]
    cmp  rax, rcx
    jne  .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; Called only from nd_backend_stopped .retired, after nd_state 4 (S5). Writes
; the clean exports only when the marker equals nd_generation. Preserves every
; callee-saved register.
guestpower_retired:
    cmp  dword [rel nd_state], 4
    jne  .out
    mov  rax, [rel gpw_marker]
    test rax, rax
    jz   .out
    cmp  rax, [rel nd_generation]
    jne  .out
    cmp  dword [rel gpw_req_state], 3
    jne  .out
    sub  rsp, 8
    call boot_ms_now
    add  rsp, 8
    mov  [rel nd_power_clean_ms], rax
    mov  rax, [rel gpw_marker]
    mov  [rel nd_power_clean_generation], rax
    mov  byte [rel nd_power_clean], 1
    mov  qword [rel gpw_marker], 0
.out:
    ret

; nd_power_request(RDI=generation u64, RSI=16-byte ASCII nonce) -> EAX
; 0 queued and armed, 1 not attached, 2 not this START, 3 no live paos.power
; device, 4 outstanding/other, 5 port not open. Codes 1-5 change nothing.
; BSP only; never blocks or yields; preserves every callee-saved register.
nd_power_request:
    pushfq
    cld
    push rbx
    push r12
    push r13
    sub  rsp, GPW_LINE_MAX + 8           ; keeps calls 16-aligned
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13d, 1
    cmp  dword [rel nd_state], 2
    jne  .out
    mov  r13d, 2
    test rbx, rbx
    jz   .out
    cmp  rbx, [rel nd_generation]
    jne  .out
    test r12, r12
    jz   .out
    mov  rsi, r12
    lea  rdi, [rel nd_nonce]
    mov  ecx, 16
    repe cmpsb
    jne  .out
    mov  r13d, 3
    cmp  byte [rel guestpower_live], 1
    jne  .out
    call gpw_current
    test eax, eax
    jz   .out
    cmp  dword [rel gpw_status], 15
    jne  .out
    mov  r13d, 4
    cmp  dword [rel gpw_req_state], 0
    jne  .out
    mov  rdi, rsp
    call gpw_build_line
    mov  rdi, rsp
    mov  ecx, GPW_LINE_MAX
    mov  edx, eax
    xor  eax, eax
    rep  stosb                              ; scratch line never kept
    test edx, edx
    jz   .out
    mov  r13d, 5
    cmp  byte [rel gpw_guest_open], 1
    jne  .out
    mov  [rel gpw_req_gen], rbx
    mov  dword [rel gpw_req_state], 1
    mov  byte [rel gpw_notify_req], 1
    xor  r13d, r13d
.out:
    mov  eax, r13d
    add  rsp, GPW_LINE_MAX + 8
    pop  r13
    pop  r12
    pop  rbx
    popfq
    ret

; nd_power_state -> EAX 0 none, 1 queued, 2 taken, 3 clean exit observed.
; Read-only; reports on the current generation only.
nd_power_state:
    mov  rax, [rel nd_generation]
    test rax, rax
    jz   .none
    cmp  rax, [rel gpw_req_gen]
    jne  .none
    mov  eax, [rel gpw_req_state]
    ret
.none:
    xor  eax, eax
    ret

gpw_port_name: db "paos.power"
gpw_port_name_end:
gpw_line_head: db "PAOS_POWER_V1 shutdown "
gpw_line_head_end:

%include "core/abi/wdata.inc"
%macro WDATA_hv_guestpower 0
align 8
nd_power_clean_generation: dq 0
nd_power_clean_ms: dq 0
gpw_req_gen: dq 0
gpw_marker: dq 0
gpw_tx_discarded: dq 0
gpw_req_state: dd 0
gpw_ctl_from_guest: dd 0
gpw_ctl_to_guest: dd 0
gpw_lines: dd 0
nd_power_clean: db 0
guestpower_live: db 0                   ; PT entry 9 is this page (B1); the only datum
align 8
gpw_state:
gpw_page: dq 0
gpw_owner: times GPW_OWNER_BYTES db 0
gpw_q_addr: times GPW_QUEUES * 3 dq 0       ; desc[4], avail[4], used[4]
gpw_q_num: times GPW_QUEUES dd 0
gpw_drvfeat: times 2 dd 0
gpw_dfsel: dd 0
gpw_qsel: dd 0
gpw_status: dd 0
gpw_isr: dd 0
gpw_q_last: times GPW_QUEUES dw 0
gpw_q_usedidx: times GPW_QUEUES dw 0
gpw_q_ready: times GPW_QUEUES db 0
gpw_dev_ready: db 0
gpw_port_ready: db 0
gpw_guest_open: db 0
gpw_pending: db 0
gpw_notify_req: db 0
gpw_used_any: db 0
gpw_irq_pend: db 0
gpw_irq_inj: db 0
gpw_state_end:
%endmacro
WDATA_DEFER WDATA_hv_guestpower
