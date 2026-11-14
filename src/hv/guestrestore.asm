;; MODULE hv/guestrestore
%include "hv/guest_power.inc"

;; LAYER 5
;; EXPORTS guestrestore_device_reset, guestrestore_state_zero, guestrestore_mmio_write, guestrestore_pump, guestrestore_try_inject_irq, guestrestore_verb, grs_status, grs_guest_open
;; IMPORTS hv/guest_power, hv/vmx, hv/vm_profile, hv/hv_ops, core/csprng, core/time
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Opt-in private snapshot-restore control port (RCQ-18, spec 7.6.2 D4).
; Modern virtio-console (device 3), VERSION_1 + MULTIPORT only, one port (id 0)
; named "paos.restore" and never a console. The guest restore hook opens
; /dev/virtio-ports/paos.restore and accepts exactly one line per restore:
;   PAOS_RESTORE_V1 <uuid-v4> <10-digit UTC seconds> <64 lowercase hex seed>
; The seed is fresh CSPRNG output per line, generated at the stopped-vCPU
; delivery boundary, and scrubbed after the copy. It is never stored beyond
; that copy, logged or rendered. Guest-to-host port bytes are counted and
; discarded: the port is host-to-guest control only.
;
; Queues: 0 port receiveq (host->guest), 1 port transmitq, 2 control receiveq
; (host->guest), 3 control transmitq. Profile+START owns the device, backing,
; queues and IRQ5 (shared with the console's virtio-mmio line; both handlers
; read their own InterruptStatus). Neither an MMIO write nor a guest control
; message creates authority. Single resident vCPU: every queue walk runs at a
; stopped-vCPU exit. Each descriptor is read once into private memory; every
; span is range-checked against live guest RAM and kept disjoint from its
; queue's metadata. Any malformed chain, control message or feature/queue
; violation fails the device (status 128) until the guest resets it.
;
; Resource trace: register page +22000 after entropy +21000, GPA 0xD0005000.
GRS_QUEUES equ 4
GRS_QMAX equ 64
GRS_SEGS equ 8
GRS_FEAT_MULTIPORT equ 2
GRS_CTRL_BYTES equ 8
GRS_LINE_BYTES equ 129                ; 15+1+36+1+10+1+64 + LF
GRS_TX_DISCARD_MAX equ 4096           ; per-chain bound for discarded port bytes
GRS_IRQ equ 5
GRS_BAD_ID equ 0xFFFFFFFF
GRS_EV_DEVICE_READY equ 0
GRS_EV_PORT_ADD equ 1
GRS_EV_PORT_READY equ 3
GRS_EV_PORT_OPEN equ 6
GRS_EV_PORT_NAME equ 7
GRS_PEND_ADD equ 1
GRS_PEND_NAME equ 2
GRS_PEND_OPEN equ 4
GRS_OWNER_BYTES equ 72
GRS_WALL_MIN equ 1577836800
GRS_WALL_MAX equ 4102444800

struc GRS_WORK
    .meta: resq 6                     ; desc/avail/used HVA,length
    .segs: resq GRS_SEGS * 2          ; payload HVA,length
    .desc: resq 2                     ; one private descriptor copy
    .seen: resq 1
    .total: resq 1
    .num: resd 1
    .head: resd 1
    .count: resd 1
    .q: resd 1
    .msg: resb 160                    ; private control/line bytes
endstruc

; Only current private reservation arithmetic, never a guest register address.
guestrestore_page:
    mov  rax, [rel hv_linux_region]
    test rax, rax
    jz   .bad
    mov  rdx, [rel hv_linux_region_capacity]
    cmp  rdx, HV_LINUX_CTRL_BYTES
    jb   .bad
    add  rdx, rax
    jc   .bad
    add  rax, HV_GUESTRST_PAGE
    jc   .bad
    ret
.bad:
    xor  eax, eax
    ret

; RDI=72 private bytes. Binds START generation, profile, backend and backing.
; EAX=success; no guest pointer is dereferenced.
guestrestore_owner_read:
    cmp  byte [rel hv_linux_stop_req], 0
    jne  .bad
    cmp  byte [rel hv_linux_start_active], 1
    jne  .bad
    mov  eax, [rel hv_linux_start_gen]
    test eax, eax
    jz   .bad
    cmp  eax, [rel hv_linux_start_consumed]
    jne  .bad
    cmp  eax, [rel vm_profile_gen]
    jne  .bad
    mov  [rdi], rax
    mov  rax, [rel vm_profile_active]
    test rax, rax
    jz   .bad
    mov  [rdi + 8], rax
    mov  eax, [rel vm_profile_dev_mask]
    test eax, VP_DEV_RESTORE
    jz   .bad
    test eax, VP_DEV_CONSOLE
    jz   .bad
    cmp  eax, [rel vm_profile_live_devices]
    jne  .bad
    mov  [rdi + 16], rax
    mov  rax, [rel hv_ops_active]
    test rax, rax
    jz   .bad
    mov  [rdi + 24], rax
    mov  rax, [rel hv_linux_region]
    test rax, rax
    jz   .bad
    mov  [rdi + 32], rax
    mov  rdx, [rel hv_linux_region_capacity]
    mov  [rdi + 40], rdx
    add  rdx, rax
    jc   .bad
    add  rax, HV_LINUX_CTRL_BYTES
    jc   .bad
    cmp  rax, [rel hv_linux_ram]
    jne  .bad
    mov  [rdi + 48], rax
    mov  rcx, [rel hv_linux_ram_bytes]
    test rcx, rcx
    jz   .bad
    mov  [rdi + 56], rcx
    add  rax, rcx
    jc   .bad
    cmp  rax, rdx
    ja   .bad
    mov  rax, [rel grs_page]
    mov  [rdi + 64], rax
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; EAX=1 only while the bound START/profile/backing receipt is unchanged.
guestrestore_current:
    cmp  byte [rel hv_linux_running], 1
    jne  .bad
    cmp  qword [rel grs_page], 0
    je   .bad
    sub  rsp, GRS_OWNER_BYTES + 8
    mov  rdi, rsp
    call guestrestore_owner_read
    test eax, eax
    jz   .out
    lea  rsi, [rel grs_owner]
    mov  rdi, rsp
    mov  ecx, GRS_OWNER_BYTES / 8
    repe cmpsq
    sete al
    movzx eax, al
.out:
    add  rsp, GRS_OWNER_BYTES + 8
    ret
.bad:
    xor  eax, eax
    ret

; Revoke addresses, queues, pending control and any staged line bytes.
; Lifetime counters and the last public generation stay for STAT.
guestrestore_state_zero:
    HV_POWER_WORK guestrestore_state_zero, 0, hv_guest_power_admit
    pushfq
    cld
    call guestrestore_page
    test rax, rax
    jz   .private
    cmp  rax, [rel grs_page]
    jne  .private
    mov  dword [rax + 0x60], 0
    mov  dword [rax + 0x70], 0
.private:
    inc  qword [rel grs_epoch]
    lea  rdi, [rel grs_state]
    mov  ecx, grs_state_end - grs_state
    xor  eax, eax
    rep  stosb
    popfq
    ret

; Fresh register page bound to the current START. EAX=1 bound, 0 refused.
guestrestore_device_reset:
    HV_POWER_WORK guestrestore_device_reset, 0, hv_guest_power_admit
    pushfq
    cld
    call guestrestore_state_zero
    call guestrestore_page
    test rax, rax
    jz   .out
    mov  [rel grs_page], rax
    lea  rdi, [rel grs_owner]
    call guestrestore_owner_read
    test eax, eax
    jz   .refuse
    mov  rdi, [rel grs_page]
    mov  ecx, 4096 / 8
    xor  eax, eax
    rep  stosq
    mov  rax, [rel grs_page]
    mov  dword [rax], 0x74726976      ; "virt"
    mov  dword [rax + 4], 2
    mov  dword [rax + 8], 3           ; virtio-console
    mov  dword [rax + 12], 0x50614f53
    mov  dword [rax + 0x10], GRS_FEAT_MULTIPORT
    mov  dword [rax + 0x34], GRS_QMAX
    mov  dword [rax + 0x104], 1       ; max_nr_ports; cols/rows/emerg_wr zero
    mov  eax, 1
    jmp  .out
.refuse:
    call guestrestore_state_zero
    xor  eax, eax
.out:
    popfq
    ret

; Device failure: revoke addresses/bytes, retain only a FAILED register.
guestrestore_fail:
    call guestrestore_device_reset
    test eax, eax
    jz   .out
    mov  dword [rel grs_status], 128
    mov  rax, [rel grs_page]
    mov  dword [rax + 0x70], 128
.out:
    ret

; MMIO store EDI=page offset, ESI=value (dword only via the shared decoder).
guestrestore_mmio_write:
    HV_POWER_WORK guestrestore_mmio_write, 0, hv_guest_power_io_admit
    pushfq
    cld
    push rbx
    push r12
    push r13
    sub  rsp, 8
    mov  r12d, edi
    mov  r13d, esi
    call guestrestore_current
    test eax, eax
    jz   .revoke
    mov  rbx, [rel grs_page]
    cmp  dword [rel grs_status], 128
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
    mov  eax, GRS_FEAT_MULTIPORT
.fsel_store:
    mov  [rbx + 0x10], eax
    jmp  .done
.dfsel:
    mov  [rel grs_dfsel], r13d
    jmp  .done
.feature:
    test dword [rel grs_status], 8
    jnz  .fail                        ; accepted negotiation is immutable
    mov  eax, [rel grs_dfsel]
    cmp  eax, 1
    ja   .feature_high
    lea  rdx, [rel grs_drvfeat]
    mov  [rdx + rax*4], r13d
    jmp  .done
.feature_high:
    test r13d, r13d
    jnz  .fail
    jmp  .done
.qsel:
    mov  [rel grs_qsel], r13d
    xor  eax, eax
    xor  edx, edx
    cmp  r13d, GRS_QUEUES
    jae  .qview
    mov  eax, GRS_QMAX
    lea  rcx, [rel grs_q_ready]
    movzx edx, byte [rcx + r13]
.qview:
    mov  [rbx + 0x34], eax
    mov  [rbx + 0x44], edx
    jmp  .done
.config_write:
    mov  ecx, [rel grs_qsel]
    cmp  ecx, GRS_QUEUES
    jae  .done
    lea  rdx, [rel grs_q_ready]
    cmp  byte [rdx + rcx], 0
    jne  .fail                        ; no reconfiguration of a live queue
    cmp  r12d, 0x38
    je   .qnum
    mov  eax, r12d
    sub  eax, 0x80
    shr  eax, 4                       ; 0 desc, 1 avail, 2 used
    lea  rdx, [rel grs_q_addr]
    imul eax, eax, GRS_QUEUES * 8
    add  rdx, rax
    test r12d, 4
    jnz  .addr_hi
    mov  [rdx + rcx*8], r13d
    jmp  .done
.addr_hi:
    mov  [rdx + rcx*8 + 4], r13d
    jmp  .done
.qnum:
    lea  rdx, [rel grs_q_num]
    mov  [rdx + rcx*4], r13d
    jmp  .done
.ready:
    mov  ecx, [rel grs_qsel]
    cmp  ecx, GRS_QUEUES
    jae  .done
    cmp  r13d, 1
    jne  .fail                        ; no negotiated RING_RESET
    lea  rdx, [rel grs_q_ready]
    cmp  byte [rdx + rcx], 0
    jne  .done
    mov  eax, [rel grs_status]
    and  eax, ~4
    cmp  eax, 11                      ; FEATURES_OK|DRIVER|ACKNOWLEDGE
    jne  .fail
    lea  rax, [rel grs_q_num]
    mov  eax, [rax + rcx*4]
    test eax, eax
    jz   .fail
    cmp  eax, GRS_QMAX
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
    call guestrestore_device_reset
    jmp  .done
.status_nonzero:
    mov  eax, [rel grs_status]
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
    ; this device into a second console; that shape is never offered.
    cmp  dword [rel grs_drvfeat], GRS_FEAT_MULTIPORT
    jne  .fail
    cmp  dword [rel grs_drvfeat + 4], 1
    jne  .fail
.store:
    mov  [rel grs_status], r13d
    mov  [rbx + 0x70], r13d
    jmp  .done
.ack:
    mov  eax, r13d
    not  eax
    and  [rel grs_isr], eax
    mov  eax, [rel grs_isr]
    mov  [rbx + 0x60], eax
    test eax, eax
    jnz  .done
    mov  byte [rel grs_irq_pend], 0
    mov  byte [rel grs_irq_inj], 0
    jmp  .done
.notify:
    cmp  r13d, GRS_QUEUES
    jae  .done
    call guestrestore_pump
    jmp  .done
.fail:
    call guestrestore_fail
    jmp  .done
.revoke:
    call guestrestore_state_zero
.done:
    add  rsp, 8
    pop  r13
    pop  r12
    pop  rbx
    popfq
    ret

; RDI=full64 GPA, RSI=full64 length -> RAX=HVA or zero. Clobbers RAX,RDX.
grs_range:
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
grs_disjoint:
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
grs_meta:
    push rbx
    push r12
    mov  ebx, edi
    mov  [rbp + GRS_WORK.q], edi
    lea  rax, [rel grs_q_ready]
    cmp  byte [rax + rbx], 1
    jne  .bad
    lea  rax, [rel grs_q_num]
    mov  r12d, [rax + rbx*4]
    mov  [rbp + GRS_WORK.num], r12d
    ; desc: 16-aligned, num*16
    lea  rax, [rel grs_q_addr]
    mov  rdi, [rax + rbx*8]
    test dil, 15
    jnz  .bad
    mov  esi, r12d
    shl  esi, 4
    call grs_range
    test rax, rax
    jz   .bad
    mov  [rbp + GRS_WORK.meta], rax
    mov  [rbp + GRS_WORK.meta + 8], rsi
    ; avail: 2-aligned, 6 + num*2
    lea  rax, [rel grs_q_addr + GRS_QUEUES * 8]
    mov  rdi, [rax + rbx*8]
    test dil, 1
    jnz  .bad
    lea  esi, [r12d*2 + 6]
    call grs_range
    test rax, rax
    jz   .bad
    push rdi
    lea  rdi, [rbp + GRS_WORK.meta]
    mov  ecx, 1
    call grs_disjoint
    pop  rdi
    test edx, edx
    jz   .bad
    mov  [rbp + GRS_WORK.meta + 16], rax
    mov  [rbp + GRS_WORK.meta + 24], rsi
    ; used: 4-aligned, 6 + num*8
    lea  rax, [rel grs_q_addr + GRS_QUEUES * 16]
    mov  rdi, [rax + rbx*8]
    test dil, 3
    jnz  .bad
    lea  esi, [r12d*8 + 6]
    call grs_range
    test rax, rax
    jz   .bad
    lea  rdi, [rbp + GRS_WORK.meta]
    mov  ecx, 2
    call grs_disjoint
    test edx, edx
    jz   .bad
    mov  [rbp + GRS_WORK.meta + 32], rax
    mov  [rbp + GRS_WORK.meta + 40], rsi
    mov  eax, 1
    pop  r12
    pop  rbx
    ret
.bad:
    xor  eax, eax
    pop  r12
    pop  rbx
    ret

; RBP=work after grs_meta. EAX=1 head taken into work.head, 0 none, -1 bad.
grs_next_head:
    mov  ecx, [rbp + GRS_WORK.q]
    mov  rdx, [rbp + GRS_WORK.meta + 16]
    movzx eax, word [rdx + 2]
    lea  r8, [rel grs_q_last]
    movzx r9d, word [r8 + rcx*2]
    sub  ax, r9w
    jz   .none
    movzx eax, ax
    cmp  eax, [rbp + GRS_WORK.num]
    ja   .bad                         ; overrun/stale avail is not a head
    lfence
    mov  eax, [rbp + GRS_WORK.num]
    dec  eax
    and  eax, r9d
    movzx eax, word [rdx + rax*2 + 4]
    cmp  eax, [rbp + GRS_WORK.num]
    jae  .bad
    mov  [rbp + GRS_WORK.head], eax
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
grs_chain:
    push rbx
    push r12
    push r13
    mov  r13d, edi
    mov  qword [rbp + GRS_WORK.seen], 0
    mov  qword [rbp + GRS_WORK.total], 0
    mov  dword [rbp + GRS_WORK.count], 0
    mov  ebx, [rbp + GRS_WORK.head]
.walk:
    cmp  ebx, [rbp + GRS_WORK.num]
    jae  .bad
    bts  qword [rbp + GRS_WORK.seen], rbx
    jc   .bad
    cmp  dword [rbp + GRS_WORK.count], GRS_SEGS
    jae  .bad
    mov  rsi, [rbp + GRS_WORK.meta]
    mov  eax, ebx
    shl  eax, 4
    mov  rcx, [rsi + rax]
    mov  [rbp + GRS_WORK.desc], rcx
    mov  rcx, [rsi + rax + 8]
    mov  [rbp + GRS_WORK.desc + 8], rcx
    movzx eax, word [rbp + GRS_WORK.desc + 12]
    mov  edx, eax
    and  edx, ~1
    cmp  edx, r13d                    ; exact direction; no INDIRECT/reserved
    jne  .bad
    mov  rdi, [rbp + GRS_WORK.desc]
    mov  esi, [rbp + GRS_WORK.desc + 8]
    call grs_range
    test rax, rax
    jz   .bad
    lea  rdi, [rbp + GRS_WORK.meta]
    mov  ecx, 3
    call grs_disjoint
    test edx, edx
    jz   .bad
    lea  rdi, [rbp + GRS_WORK.segs]
    mov  ecx, [rbp + GRS_WORK.count]
    call grs_disjoint
    test edx, edx
    jz   .bad
    mov  ecx, [rbp + GRS_WORK.count]
    shl  ecx, 4
    mov  [rbp + GRS_WORK.segs + rcx], rax
    mov  [rbp + GRS_WORK.segs + rcx + 8], rsi
    inc  dword [rbp + GRS_WORK.count]
    add  [rbp + GRS_WORK.total], rsi
    test word [rbp + GRS_WORK.desc + 12], 1
    jz   .ok
    movzx ebx, word [rbp + GRS_WORK.desc + 14]
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
grs_fill:
    lea  rsi, [rbp + GRS_WORK.msg]
    xor  r8d, r8d
.seg:
    test ecx, ecx
    jz   .out
    mov  eax, r8d
    shl  eax, 4
    mov  rdi, [rbp + GRS_WORK.segs + rax]
    mov  rdx, [rbp + GRS_WORK.segs + rax + 8]
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
grs_gather:
    lea  rdi, [rbp + GRS_WORK.msg]
    xor  r8d, r8d
    xor  r9d, r9d
.seg:
    test ecx, ecx
    jz   .out
    cmp  r8d, [rbp + GRS_WORK.count]
    jae  .out
    mov  eax, r8d
    shl  eax, 4
    mov  rsi, [rbp + GRS_WORK.segs + rax]
    mov  rdx, [rbp + GRS_WORK.segs + rax + 8]
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
grs_used:
    mov  ecx, [rbp + GRS_WORK.q]
    mov  r8, [rbp + GRS_WORK.meta + 32]
    lea  r9, [rel grs_q_usedidx]
    movzx eax, word [r9 + rcx*2]
    mov  r10d, [rbp + GRS_WORK.num]
    dec  r10d
    and  r10d, eax
    mov  r11d, [rbp + GRS_WORK.head]
    mov  [r8 + r10*8 + 4], r11d
    mov  [r8 + r10*8 + 8], edx
    inc  ax
    mov  [r9 + rcx*2], ax
    sfence
    mov  [r8 + 2], ax
    lea  r9, [rel grs_q_last]
    inc  word [r9 + rcx*2]
    mov  byte [rel grs_used_any], 1
    ret

; Guest control messages (queue 3). EAX=1 ok, 0 malformed.
grs_serve_control_tx:
    push rbx
    mov  ebx, GRS_QMAX
.loop:
    test ebx, ebx
    jz   .ok
    dec  ebx
    mov  edi, 3
    call grs_meta
    test eax, eax
    jz   .bad
    call grs_next_head
    test eax, eax
    jz   .ok
    js   .bad
    xor  edi, edi
    call grs_chain
    test eax, eax
    jz   .bad
    cmp  qword [rbp + GRS_WORK.total], GRS_CTRL_BYTES
    jne  .bad
    mov  ecx, GRS_CTRL_BYTES
    call grs_gather
    xor  edx, edx
    call grs_used
    mov  eax, [rbp + GRS_WORK.msg]          ; id
    movzx ecx, word [rbp + GRS_WORK.msg + 4] ; event
    movzx edx, word [rbp + GRS_WORK.msg + 6] ; value
    inc  dword [rel grs_ctl_from_guest]
    cmp  ecx, GRS_EV_DEVICE_READY
    je   .device_ready
    test eax, eax                           ; only port 0 exists
    jnz  .bad
    cmp  ecx, GRS_EV_PORT_READY
    je   .port_ready
    cmp  ecx, GRS_EV_PORT_OPEN
    je   .port_open
    jmp  .bad
.device_ready:
    cmp  eax, GRS_BAD_ID
    jne  .bad
    cmp  edx, 1
    jne  .bad
    cmp  byte [rel grs_dev_ready], 0
    jne  .bad
    mov  byte [rel grs_dev_ready], 1
    or   byte [rel grs_pending], GRS_PEND_ADD
    jmp  .loop
.port_ready:
    cmp  byte [rel grs_dev_ready], 1
    jne  .bad
    cmp  edx, 1
    jne  .bad                               ; guest refused its own port
    cmp  byte [rel grs_port_ready], 0
    jne  .loop                              ; repeated READY is harmless
    mov  byte [rel grs_port_ready], 1
    or   byte [rel grs_pending], GRS_PEND_NAME | GRS_PEND_OPEN
    jmp  .loop
.port_open:
    cmp  byte [rel grs_port_ready], 1
    jne  .bad
    cmp  edx, 1
    ja   .bad
    mov  [rel grs_guest_open], dl
    jmp  .loop
.ok:
    mov  eax, 1
    pop  rbx
    ret
.bad:
    xor  eax, eax
    pop  rbx
    ret

; Discard guest port bytes (queue 1). EAX=1 ok, 0 malformed.
grs_serve_port_tx:
    push rbx
    mov  ebx, GRS_QMAX
.loop:
    test ebx, ebx
    jz   .ok
    dec  ebx
    mov  edi, 1
    call grs_meta
    test eax, eax
    jz   .bad
    call grs_next_head
    test eax, eax
    jz   .ok
    js   .bad
    xor  edi, edi
    call grs_chain
    test eax, eax
    jz   .bad
    mov  rax, [rbp + GRS_WORK.total]
    cmp  rax, GRS_TX_DISCARD_MAX
    ja   .bad
    add  [rel grs_port_discarded], rax
    xor  edx, edx
    call grs_used
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
grs_serve_control_rx:
.next:
    movzx eax, byte [rel grs_pending]
    test eax, eax
    jz   .ok
    mov  edi, 2
    call grs_meta
    test eax, eax
    jz   .bad
    call grs_next_head
    test eax, eax
    jz   .ok                                ; wait for a posted buffer
    js   .bad
    mov  edi, 2
    call grs_chain
    test eax, eax
    jz   .bad
    mov  dword [rbp + GRS_WORK.msg], 0      ; port id 0
    movzx eax, byte [rel grs_pending]
    test eax, GRS_PEND_ADD
    jz   .name
    mov  dword [rbp + GRS_WORK.msg + 4], GRS_EV_PORT_ADD
    and  byte [rel grs_pending], ~GRS_PEND_ADD
    mov  ecx, GRS_CTRL_BYTES
    jmp  .deliver
.name:
    test eax, GRS_PEND_NAME
    jz   .open
    mov  dword [rbp + GRS_WORK.msg + 4], GRS_EV_PORT_NAME
    lea  rsi, [rel grs_port_name]
    lea  rdi, [rbp + GRS_WORK.msg + GRS_CTRL_BYTES]
    mov  ecx, grs_port_name_end - grs_port_name
    rep  movsb
    and  byte [rel grs_pending], ~GRS_PEND_NAME
    mov  ecx, GRS_CTRL_BYTES + grs_port_name_end - grs_port_name
    jmp  .deliver
.open:
    mov  dword [rbp + GRS_WORK.msg + 4], GRS_EV_PORT_OPEN | (1 << 16)
    and  byte [rel grs_pending], ~GRS_PEND_OPEN
    mov  ecx, GRS_CTRL_BYTES
.deliver:
    mov  eax, ecx
    cmp  rax, [rbp + GRS_WORK.total]
    ja   .bad                               ; Linux posts PAGE_SIZE buffers
    push rcx
    call grs_fill
    pop  rdx
    call grs_used
    inc  dword [rel grs_ctl_to_guest]
    jmp  .next
.ok:
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; Hex nibble AL (0..15) -> AL lowercase ASCII.
grs_hex:
    and  al, 15
    add  al, '0'
    cmp  al, '9'
    jbe  .out
    add  al, 'a' - '9' - 1
.out:
    ret

; RBP=work. Build the restore line in work.msg from fresh CSPRNG bytes and
; the valid wall clock. EAX=1 built, 0 refused (nothing staged survives).
grs_build_line:
    push rbx
    push r12
    cmp  byte [rel time_wall_valid], 1
    jne  .bad
    call time_wall_now_s
    cmp  rax, GRS_WALL_MIN
    jb   .bad
    mov  rcx, GRS_WALL_MAX
    cmp  rax, rcx
    ja   .bad
    mov  r12, rax
    lea  rdi, [rel grs_random]
    mov  esi, 48                            ; 16 UUID + 32 seed bytes
    call csprng_generate
    test rax, rax
    jnz  .bad
    lea  rbx, [rel grs_random]
    and  byte [rbx + 6], 0x0F               ; UUID version 4
    or   byte [rbx + 6], 0x40
    and  byte [rbx + 8], 0x3F               ; RFC variant
    or   byte [rbx + 8], 0x80
    lea  rdi, [rbp + GRS_WORK.msg]
    lea  rsi, [rel grs_line_head]
    mov  ecx, grs_line_head_end - grs_line_head
    rep  movsb
    xor  ecx, ecx
.uuid:
    cmp  ecx, 4
    je   .dash
    cmp  ecx, 6
    je   .dash
    cmp  ecx, 8
    je   .dash
    cmp  ecx, 10
    jne  .uuid_byte
.dash:
    mov  byte [rdi], '-'
    inc  rdi
.uuid_byte:
    mov  al, [rbx + rcx]
    shr  al, 4
    call grs_hex
    stosb
    mov  al, [rbx + rcx]
    call grs_hex
    stosb
    inc  ecx
    cmp  ecx, 16
    jb   .uuid
    ; Public generation copy for STAT/receipt matching.
    lea  rsi, [rbp + GRS_WORK.msg + grs_line_head_end - grs_line_head]
    push rdi
    lea  rdi, [rel grs_last_generation]
    mov  ecx, 36
    rep  movsb
    pop  rdi
    mov  byte [rdi], ' '
    inc  rdi
    mov  rax, r12
    mov  ecx, 10
    lea  r8, [rdi + 9]
.digits:
    xor  edx, edx
    mov  r9d, 10
    div  r9
    add  dl, '0'
    mov  [r8], dl
    dec  r8
    loop .digits
    add  rdi, 10
    mov  byte [rdi], ' '
    inc  rdi
    mov  ecx, 16
.seed:
    mov  al, [rbx + rcx]
    shr  al, 4
    call grs_hex
    stosb
    mov  al, [rbx + rcx]
    call grs_hex
    stosb
    inc  ecx
    cmp  ecx, 48
    jb   .seed
    mov  byte [rdi], 10
    mov  [rel grs_last_wall], r12
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    lea  rdi, [rel grs_random]
    mov  ecx, 48
    push rax
    xor  eax, eax
    rep  stosb
    pop  rax
    pop  r12
    pop  rbx
    ret

; Deliver one requested restore line on port 0 (queue 0).
; EAX=1 ok (delivered or still waiting), 0 malformed.
grs_serve_notify:
    cmp  byte [rel grs_notify_req], 1
    jne  .ok
    cmp  byte [rel grs_guest_open], 1
    jne  .ok                                ; deferred until the hook opens it
    mov  edi, 0
    call grs_meta
    test eax, eax
    jz   .bad
    call grs_next_head
    test eax, eax
    jz   .ok                                ; deferred until a buffer is posted
    js   .bad
    mov  edi, 2
    call grs_chain
    test eax, eax
    jz   .bad
    cmp  qword [rbp + GRS_WORK.total], GRS_LINE_BYTES
    jb   .bad                               ; Linux posts PAGE_SIZE buffers
    call grs_build_line
    test eax, eax
    jz   .refused
    mov  ecx, GRS_LINE_BYTES
    call grs_fill
    mov  edx, GRS_LINE_BYTES
    call grs_used
    mov  byte [rel grs_notify_req], 0
    inc  dword [rel grs_notified]
    jmp  .ok
.refused:
    mov  byte [rel grs_notify_req], 0
    inc  dword [rel grs_notify_refused]
.ok:
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; Stopped-vCPU worker: guest control, discarded port bytes, host control and
; one pending restore line. Bounded per call; scrubs all private bytes.
guestrestore_pump:
    HV_POWER_WORK guestrestore_pump, 0, hv_guest_power_io_admit
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
    sub  rsp, GRS_WORK_size + 16
    mov  [rsp + GRS_WORK_size], rax
    mov  rbp, rsp
    mov  rdi, rsp
    mov  ecx, GRS_WORK_size
    xor  eax, eax
    rep  stosb
    call guestrestore_current
    test eax, eax
    jz   .revoke
    cmp  dword [rel grs_status], 15
    jne  .out
    mov  byte [rel grs_used_any], 0
    lea  rax, [rel grs_q_ready]
    cmp  byte [rax + 3], 1
    jne  .port_tx
    call grs_serve_control_tx
    test eax, eax
    jz   .fail
.port_tx:
    lea  rax, [rel grs_q_ready]
    cmp  byte [rax + 1], 1
    jne  .control_rx
    call grs_serve_port_tx
    test eax, eax
    jz   .fail
.control_rx:
    lea  rax, [rel grs_q_ready]
    cmp  byte [rax + 2], 1
    jne  .notify
    call grs_serve_control_rx
    test eax, eax
    jz   .fail
.notify:
    lea  rax, [rel grs_q_ready]
    cmp  byte [rax], 1
    jne  .irq
    call grs_serve_notify
    test eax, eax
    jz   .fail
.irq:
    cmp  byte [rel grs_used_any], 1
    jne  .out
    or   dword [rel grs_isr], 1
    mov  rax, [rel grs_page]
    mov  ecx, [rel grs_isr]
    mov  [rax + 0x60], ecx
    mov  byte [rel grs_irq_pend], 1
    jmp  .out
.fail:
    call guestrestore_fail
    jmp  .out
.revoke:
    call guestrestore_state_zero
.out:
    mov  rdi, rbp
    mov  ecx, GRS_WORK_size
    xor  eax, eax
    rep  stosb
    mov  rsp, [rbp + GRS_WORK_size]
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    popfq
    ret

guestrestore_try_inject_irq:
    HV_POWER_WORK guestrestore_try_inject_irq, 0, hv_guest_power_io_admit
    pushfq
    cld
    call guestrestore_current
    test eax, eax
    jz   .revoke
    cmp  byte [rel grs_irq_pend], 1
    jne  .no
    cmp  byte [rel grs_irq_inj], 0
    jne  .no
    cmp  dword [rel grs_status], 15
    jne  .no
    mov  edi, GRS_IRQ
    call hv_pic_try_inject
    test eax, eax
    jz   .out
    mov  byte [rel grs_irq_inj], 1
    jmp  .out
.revoke:
    call guestrestore_state_zero
.no:
    xor  eax, eax
.out:
    popfq
    ret

; ---------------------------------------------------------------------------
; GUESTVM RESTOREPORT [NOTIFY] (owner-signed like every GUESTVM sub-verb).
; NOTIFY only queues one request; the line and its seed are generated at the
; next stopped-vCPU delivery boundary once the guest hook has the port open.
; guestrestore_verb(RDI=text after RESTOREPORT)
; ---------------------------------------------------------------------------
guestrestore_verb:
    push rbx
    mov  rbx, rdi
    call hv_out_reset
    lea  rdi, [rel str_grs_head]
    call hv_out_str
    mov  rdi, rbx
    call hv_skip_spaces
    mov  rbx, rax
    cmp  byte [rbx], 0
    je   .stat
    mov  rdi, rbx
    lea  rsi, [rel str_grs_notify]
    call hv_tok_is
    test al, al
    jz   .usage
    lea  rdi, [rbx + 6]
    call hv_skip_spaces
    cmp  byte [rax], 0
    jne  .usage
    call guestrestore_current
    test eax, eax
    jz   .refused
    cmp  dword [rel grs_status], 15
    jne  .refused
    cmp  byte [rel grs_notify_req], 0
    jne  .refused                           ; one request at a time
    cmp  byte [rel time_wall_valid], 1
    jne  .refused
    mov  byte [rel grs_notify_req], 1
    lea  rdi, [rel str_grs_queued]
    call hv_out_str
    jmp  .stat
.refused:
    lea  rdi, [rel str_grs_refused]
    call hv_out_str
    jmp  .stat
.usage:
    lea  rdi, [rel str_grs_usage]
    call hv_out_str
.stat:
    lea  rdi, [rel str_grs_selected]
    call hv_out_str
    xor  eax, eax
    test dword [rel vm_profile_dev_mask], VP_DEV_RESTORE
    setnz al
    call hv_out_dec
    lea  rdi, [rel str_grs_status]
    call hv_out_str
    mov  eax, [rel grs_status]
    call hv_out_dec
    lea  rdi, [rel str_grs_dev_ready]
    call hv_out_str
    movzx eax, byte [rel grs_dev_ready]
    call hv_out_dec
    lea  rdi, [rel str_grs_port_ready]
    call hv_out_str
    movzx eax, byte [rel grs_port_ready]
    call hv_out_dec
    lea  rdi, [rel str_grs_open]
    call hv_out_str
    movzx eax, byte [rel grs_guest_open]
    call hv_out_dec
    lea  rdi, [rel str_grs_pending]
    call hv_out_str
    movzx eax, byte [rel grs_notify_req]
    call hv_out_dec
    lea  rdi, [rel str_grs_notified]
    call hv_out_str
    mov  eax, [rel grs_notified]
    call hv_out_dec
    lea  rdi, [rel str_grs_notify_refused]
    call hv_out_str
    mov  eax, [rel grs_notify_refused]
    call hv_out_dec
    lea  rdi, [rel str_grs_ctl]
    call hv_out_str
    mov  eax, [rel grs_ctl_from_guest]
    call hv_out_dec
    lea  rdi, [rel str_grs_ctl_out]
    call hv_out_str
    mov  eax, [rel grs_ctl_to_guest]
    call hv_out_dec
    lea  rdi, [rel str_grs_discarded]
    call hv_out_str
    mov  eax, [rel grs_port_discarded]
    call hv_out_dec
    cmp  dword [rel grs_notified], 0
    je   .out
    lea  rdi, [rel str_grs_generation]
    call hv_out_str
    lea  rdi, [rel grs_last_generation]
    call hv_out_str
    lea  rdi, [rel str_grs_wall]
    call hv_out_str
    mov  rax, [rel grs_last_wall]
    call hv_out_dec
.out:
    pop  rbx
    ret

grs_port_name: db "paos.restore"
grs_port_name_end:
grs_line_head: db "PAOS_RESTORE_V1 "
grs_line_head_end:
str_grs_head: db " GUESTVM RESTOREPORT", 0
str_grs_notify: db "NOTIFY", 0
str_grs_queued: db " notify_queued=1", 0
str_grs_refused: db " notify_queued=0", 0
str_grs_usage: db " usage=RESTOREPORT[NOTIFY]", 0
str_grs_selected: db " selected=", 0
str_grs_status: db " status=", 0
str_grs_dev_ready: db " device_ready=", 0
str_grs_port_ready: db " port_ready=", 0
str_grs_open: db " guest_open=", 0
str_grs_pending: db " notify_pending=", 0
str_grs_notified: db " notified=", 0
str_grs_notify_refused: db " refused=", 0
str_grs_ctl: db " control_in=", 0
str_grs_ctl_out: db " control_out=", 0
str_grs_discarded: db " port_discarded=", 0
str_grs_generation: db " last_generation=", 0
str_grs_wall: db " last_wall_s=", 0

%include "core/abi/wdata.inc"
%macro WDATA_hv_guestrestore 0
alignb 16
; Lifetime public counters/receipt outside the resettable device.
grs_epoch: resq 1
grs_last_wall: resq 1
grs_port_discarded: resq 1
grs_notified: resd 1
grs_notify_refused: resd 1
grs_ctl_from_guest: resd 1
grs_ctl_to_guest: resd 1
grs_last_generation: resb 37            ; 36 public UUID bytes + NUL
alignb 16
grs_random: resb 48                     ; scrubbed on every build path
alignb 8
grs_state:
grs_page: resq 1
grs_owner: resb GRS_OWNER_BYTES
grs_q_addr: resq GRS_QUEUES * 3         ; desc[4], avail[4], used[4]
grs_q_num: resd GRS_QUEUES
grs_drvfeat: resd 2
grs_dfsel: resd 1
grs_qsel: resd 1
grs_status: resd 1
grs_isr: resd 1
grs_q_last: resw GRS_QUEUES
grs_q_usedidx: resw GRS_QUEUES
grs_q_ready: resb GRS_QUEUES
grs_dev_ready: resb 1
grs_port_ready: resb 1
grs_guest_open: resb 1
grs_pending: resb 1
grs_notify_req: resb 1
grs_used_any: resb 1
grs_irq_pend: resb 1
grs_irq_inj: resb 1
grs_state_end:
%endmacro
WDATA_BSS_DEFER WDATA_hv_guestrestore
