;; MODULE hv/guestentropy
%include "hv/guest_power.inc"

;; LAYER 5
;; EXPORTS guestentropy_device_reset, guestentropy_state_zero, guestentropy_mmio_write, guestentropy_pump, guestentropy_try_inject_irq
;; IMPORTS hv/guest_power, hv/vmx, hv/vm_profile, hv/hv_ops, hv/guestnet, hv/domain_channel, dev/net/virtio_domain, core/csprng, core/time
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Optional modern virtio-rng (device 4), one writable split queue, VERSION_1
; only. No indirect/event-index feature. Profile+START owns the device, backing,
; queue and IRQ3; neither an MMIO write nor a driver assertion creates authority.
; Single resident vCPU: guest RAM is quiescent during this bounded exit worker.
; Snapshot the entire descriptor table, validate every destination (including
; unused tail capacity), then generate privately, recheck ownership and publish.
; No entropy service state/seed escapes. No allocation or private lock loop.
;
; Resource trace: console +5000, EPT PD/PT +6000/+7000, net +8000,
; VT-d pool +9000..+18fff, input +19000, SVM host/IOPM/MSRPM +1a000..+1ffff,
; sound +20000, entropy +21000. IRQ0/1/5/6 belong to timer/input/console/net.
; IRQ3 has no other virtual source. Both Intel EPT and SVM NPF go through
; hv_linux_exit_dispatch -> hv_linux_virtio_mmio -> this same store handler.
GR_QMAX equ 64
GR_MAX equ 256
GR_QUOTA equ 4096
GR_SECOND equ 1000000
GR_OWNER_BYTES equ 112
struc GR_WORK
    .meta: resq 6                    ; HVA,length for descriptor/avail/used
    .segments: resq GR_QMAX * 2       ; destination HVA,length; disjoint
    .table: resq GR_QMAX * 2          ; complete private descriptor table
    .seen: resq 1
    .count: resd 1
    .head: resd 1
    .total: resd 1
    .index: resd 1
    .epoch: resq 1
    .last: resd 1
    .used: resd 1
    .config: resq 4
    .padding: resq 1                  ; keep external call stack 16-byte aligned
endstruc

; Only current private reservation arithmetic, never a guest register address.
guestentropy_page:
    mov  rax, [rel hv_linux_region]
    test rax, rax
    jz   .bad
    mov  rdx, [rel hv_linux_region_capacity]
    cmp  rdx, HV_LINUX_CTRL_BYTES
    jb   .bad
    add  rdx, rax
    jc   .bad
    add  rax, HV_GUESTRNG_PAGE
    jc   .bad
    ret
.bad:
    xor  eax, eax
    ret

; Private owner receipt. Caller supplies 112 private bytes. Queue reset cannot
; renew its START authority; selected profile must match both START generations.
; RDI=receipt; EAX=success. No guest pointer is dereferenced here.
guestentropy_owner_read:
    cmp  byte [rel hv_linux_stop_req], 0
    jne  .bad
    mov  eax, [rel hv_linux_start_gen]
    test eax, eax
    jz   .bad
    cmp  eax, [rel hv_linux_start_consumed]
    jne  .bad
    cmp  eax, [rel vm_profile_gen]
    jne  .bad
    mov  [rdi + 64], rax
    mov  rax, [rel vm_profile_active]
    test rax, rax
    jz   .bad
    mov  [rdi + 40], rax
    mov  eax, [rel vm_profile_dev_mask]
    test eax, VP_DEV_ENTROPY
    jz   .bad
    cmp  eax, [rel vm_profile_live_devices]
    jne  .bad
    mov  [rdi + 72], rax
    mov  rax, [rel hv_ops_active]
    test rax, rax
    jz   .bad
    mov  [rdi + 32], rax
    mov  rax, [rel hv_linux_region]
    test rax, rax
    jz   .bad
    mov  [rdi + 16], rax
    mov  rdx, [rel hv_linux_region_capacity]
    mov  [rdi + 24], rdx
    add  rdx, rax
    jc   .bad
    add  rax, HV_LINUX_CTRL_BYTES
    jc   .bad
    cmp  rax, [rel hv_linux_ram]
    jne  .bad
    mov  [rdi], rax
    mov  rcx, [rel hv_linux_ram_bytes]
    test rcx, rcx
    jz   .bad
    mov  [rdi + 8], rcx
    add  rax, rcx
    jc   .bad
    cmp  rax, rdx
    ja   .bad
    mov  rax, [rel guestnet_domain_ctx]
    mov  [rdi + 48], rax
    mov  qword [rdi + 56], 0
    test rax, rax
    jz   .no_domain
    cmp  byte [rel domain_capstone_active], 1
    jne  .bad
    cmp  dword [rax + virtio_domain_ctx.lifecycle], DOMAIN_LIFE_RUNNING
    jne  .bad
    mov  rax, [rax + virtio_domain_ctx.rx_ring]
    test rax, rax
    jz   .bad
    mov  [rdi + 56], rax
.no_domain:
    ; Domain binding epoch also fences detach/rebind to the same address.
    mov  rax, [rel guestnet_ring_epoch]
    mov  [rdi + 80], rax
    mov  rax, [rel gr_epoch]
    mov  [rdi + 88], rax
    cmp  byte [rel hv_linux_start_active], 1
    jne  .bad
    movzx eax, byte [rel hv_linux_start_active]
    mov  [rdi + 96], rax
    mov  rax, [rel gr_page]
    mov  [rdi + 104], rax
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

guestentropy_current:
    mov  rax, [rel guestnet_domain_ctx]
    cmp  rax, [rel gr_owner + 48]
    jne  .bad                       ; reject replacement before dereferencing it
    cmp  byte [rel hv_linux_running], 1
    jne  .bad
    sub  rsp, GR_OWNER_BYTES + 8
    mov  rdi, rsp
    call guestentropy_owner_read
    test eax, eax
    jz   .out
    lea  rsi, [rel gr_owner]
    mov  rdi, rsp
    mov  ecx, GR_OWNER_BYTES / 8
    repe cmpsq
    sete al
    movzx eax, al
.out:
    add  rsp, GR_OWNER_BYTES + 8
    ret
.bad:
    xor  eax, eax
    ret

; Revocation deliberately does NOT reset global exposure history. Rebind/START,
; QueueReady=0 and failed provider calls cannot grant another quota window.
guestentropy_state_zero:
    HV_POWER_WORK guestentropy_state_zero, 0, hv_guest_power_admit
    pushfq
    cld
    call guestentropy_page
    test rax, rax
    jz   .private
    cmp  rax, [rel gr_page]
    jne  .private
    mov  dword [rax + 0x60], 0
    mov  dword [rax + 0x70], 0
.private:
    inc  qword [rel gr_epoch]
    lea  rdi, [rel gr_state]
    mov  ecx, gr_state_end - gr_state
    xor  eax, eax
    rep  stosb
    popfq
    ret

guestentropy_device_reset:
    HV_POWER_WORK guestentropy_device_reset, 0, hv_guest_power_admit
    pushfq
    cld
    call guestentropy_state_zero
    call guestentropy_page
    test rax, rax
    jz   .out
    mov  [rel gr_page], rax
    lea  rdi, [rel gr_owner]
    call guestentropy_owner_read
    test eax, eax
    jz   .refuse
    mov  rdi, [rel gr_page]
    mov  ecx, 4096 / 8
    xor  eax, eax
    rep  stosq
    mov  rax, [rel gr_page]
    mov  dword [rax], 0x74726976
    mov  dword [rax + 4], 2
    mov  dword [rax + 8], 4
    mov  dword [rax + 12], 0x50614f53
    mov  dword [rax + 0x34], GR_QMAX
    mov  eax, 1
    jmp  .out
.refuse:
    call guestentropy_state_zero
    xor  eax, eax
.out:
    popfq
    ret

; MMIO store EDI=page offset, ESI=value. The shared decoder admits dword
; stores only. Unknown fields are ignored, never written into the register page.
guestentropy_mmio_write:
    HV_POWER_WORK guestentropy_mmio_write, 0, hv_guest_power_io_admit
    pushfq
    cld
    push rbx
    push r12
    push r13
    sub  rsp, 8
    mov  r12d, edi
    mov  r13d, esi
    call guestentropy_current
    test eax, eax
    jz   .revoke
    mov  rbx, [rel gr_page]
    cmp  r12d, 0x70
    je   .status
    cmp  r12d, 0x64
    je   .ack
    cmp  r12d, 0x50
    je   .notify
    cmp  r12d, 0x14
    je   .fsel
    cmp  r12d, 0x24
    je   .dfsel
    cmp  r12d, 0x20
    je   .feature
    cmp  r12d, 0x30
    je   .qsel
    cmp  r12d, 0x44
    je   .ready
    ; Only writable queue configuration fields reach the ready gate.
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
.config_write:
    ; Queue address/size changes after ready poison the device until reset.
    cmp  byte [rel gr_ready], 0
    jne  .fail
    cmp  dword [rel gr_qsel], 0
    jne  .done
    cmp  r12d, 0x38
    je   .qnum
    cmp  r12d, 0x80
    je   .desclo
    cmp  r12d, 0x84
    je   .deschi
    cmp  r12d, 0x90
    je   .availlo
    cmp  r12d, 0x94
    je   .availhi
    cmp  r12d, 0xa0
    je   .usedlo
    cmp  r12d, 0xa4
    je   .usedhi
    jmp  .done
.fsel:
    mov  dword [rbx + 0x10], 0
    cmp  r13d, 1
    jne  .done
    mov  dword [rbx + 0x10], 1       ; only VIRTIO_F_VERSION_1
    jmp  .done
.dfsel:
    mov  [rel gr_dfsel], r13d
    jmp  .done
.feature:
    test dword [rel gr_status], 8
    jnz  .fail
    cmp  dword [rel gr_dfsel], 0
    jne  .highfeature
    test r13d, r13d
    jnz  .fail
    jmp  .done
.highfeature:
    cmp  dword [rel gr_dfsel], 1
    jne  .unsupported
    cmp  r13d, 1
    jne  .fail
    mov  byte [rel gr_version], 1
    jmp  .done
.unsupported:
    test r13d, r13d
    jnz  .fail
    jmp  .done
.qsel:
    mov  [rel gr_qsel], r13d
    xor  eax, eax
    test r13d, r13d
    jnz  .qview
    mov  eax, GR_QMAX
.qview:
    mov  [rbx + 0x34], eax
    xor  eax, eax
    test r13d, r13d
    jnz  .qview_ready
    movzx eax, byte [rel gr_ready]
.qview_ready:
    mov  [rbx + 0x44], eax
    jmp  .done
.qnum:
    mov  [rel gr_num], r13d
    jmp  .done
.desclo:
    mov  [rel gr_desc], r13d
    jmp  .done
.deschi:
    mov  [rel gr_desc + 4], r13d
    jmp  .done
.availlo:
    mov  [rel gr_avail], r13d
    jmp  .done
.availhi:
    mov  [rel gr_avail + 4], r13d
    jmp  .done
.usedlo:
    mov  [rel gr_used], r13d
    jmp  .done
.usedhi:
    mov  [rel gr_used + 4], r13d
    jmp  .done
.ready:
    cmp  dword [rel gr_qsel], 0
    jne  .done
    cmp  r13d, 1
    jne  .fail                    ; no negotiated RING_RESET
    cmp  byte [rel gr_ready], 0
    jne  .done
    cmp  dword [rel gr_status], 11
    jne  .fail
    mov  eax, [rel gr_num]
    test eax, eax
    jz   .fail
    cmp  eax, GR_QMAX
    ja   .fail
    lea  edx, [eax - 1]
    test eax, edx
    jnz  .fail
    mov  byte [rel gr_ready], 1
    mov  dword [rbx + 0x44], 1
    jmp  .done
.status:
    test r13d, r13d
    jnz  .status_nonzero
    call guestentropy_device_reset
    jmp  .done
.status_nonzero:
    mov  eax, [rel gr_status]
    test eax, 128
    jnz  .done
    mov  edx, eax
    or   edx, r13d
    cmp  edx, r13d
    jne  .fail
    cmp  r13d, 1
    je   .store
    cmp  r13d, 3
    je   .store
    cmp  r13d, 11
    je   .modern
    cmp  r13d, 15
    jne  .fail
    test eax, 8
    jz   .fail
.modern:
    cmp  byte [rel gr_version], 1
    jne  .fail
    cmp  eax, 3
    jb   .fail
.store:
    mov  [rel gr_status], r13d
    mov  [rbx + 0x70], r13d
    jmp  .done
.ack:
    test r13d, 1
    jz   .done
    mov  byte [rel gr_irq], 0
    mov  dword [rbx + 0x60], 0
    jmp  .done
.notify:
    test r13d, r13d
    jnz  .done
    call guestentropy_pump
    jmp  .done
.fail:
    ; Failure revokes addresses and bytes, retaining only a FAILED register.
    call guestentropy_device_reset
    test eax, eax
    jz   .done
    mov  dword [rel gr_status], 128
    mov  rax, [rel gr_page]
    mov  dword [rax + 0x70], 128
    jmp  .done
.revoke:
    call guestentropy_state_zero
.done:
    add  rsp, 8
    pop  r13
    pop  r12
    pop  rbx
    popfq
    ret

; RDI=full64 GPA, RSI=full64 length -> RAX=HVA or zero. Checked live backing
; itself is authenticated in current(); endpoint equality is legal.
guestentropy_range:
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

; RDI=span array, ECX=count, RAX=start, RSI=length -> EDX=disjoint.
; All endpoints were range-checked before insertion.
guestentropy_disjoint:
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

; Global conservative rolling exposure bucket. It requires a full quiet second
; after the last charge before replenishing, so every sliding monotonic second
; contains <=4096 bytes (stronger than an aligned-window limit). Unknown/backward
; time defers. Charges precede the provider and survive all owner resets/failures.
; ESI=bytes -> EAX=admitted. Called only after whole-chain preflight.
guestentropy_budget:
    push rbx
    mov  ebx, esi
    call time_monotonic_now_us
    test rax, rax
    jz   .bad
    cmp  rax, [rel gr_clock_last]
    jb   .bad
    mov  [rel gr_clock_last], rax
    mov  rdx, rax
    sub  rdx, [rel gr_charge_time]
    cmp  rdx, GR_SECOND
    jb   .same
    mov  dword [rel gr_spent], 0
.same:
    mov  ecx, [rel gr_spent]
    add  ecx, ebx
    cmp  ecx, GR_QUOTA
    ja   .bad
    mov  [rel gr_spent], ecx
    mov  [rel gr_charge_time], rax
    mov  eax, 1
    pop  rbx
    ret
.bad:
    xor  eax, eax
    pop  rbx
    ret

guestentropy_pump:
    HV_POWER_WORK guestentropy_pump, 0, hv_guest_power_io_admit
    pushfq
    cld
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rax, rsp
    and  rsp, -16                    ; legacy exit helpers also use internal call frames
    sub  rsp, GR_WORK_size + 16
    mov  [rsp + GR_WORK_size], rax
    mov  rbp, rsp
    mov  rdi, rsp
    mov  ecx, GR_WORK_size
    xor  eax, eax
    rep  stosb
    call guestentropy_current
    test eax, eax
    jz   .revoke
    cmp  dword [rel gr_status], 15
    jne  .out
    cmp  byte [rel gr_ready], 1
    jne  .out
    mov  rax, [rel gr_epoch]
    mov  [rbp + GR_WORK.epoch], rax
    movzx eax, word [rel gr_last]
    mov  [rbp + GR_WORK.last], eax
    movzx eax, word [rel gr_usedidx]
    mov  [rbp + GR_WORK.used], eax
    xor  ecx, ecx
.config:
    lea  rdx, [rel gr_desc]
    mov  rax, [rdx + rcx*8]
    mov  [rbp + GR_WORK.config + rcx*8], rax
    inc  ecx
    cmp  ecx, 4
    jb   .config
    mov  r14d, [rel gr_num]
    xor  ebx, ebx
.metadata:
    lea  rdi, [rel gr_desc]
    mov  rdi, [rdi + rbx*8]
    test ebx, ebx
    jnz  .other_alignment
    test dil, 15
    jnz  .out
    mov  esi, r14d
    shl  esi, 4
    jmp  .meta_range
.other_alignment:
    cmp  ebx, 1
    jne  .used_meta
    test dil, 1
    jnz  .out
    lea  esi, [r14d*2 + 6]
    jmp  .meta_range
.used_meta:
    test dil, 3
    jnz  .out
    lea  esi, [r14d*8 + 6]
.meta_range:
    call guestentropy_range
    test rax, rax
    jz   .out
    lea  rdi, [rbp + GR_WORK.meta]
    mov  ecx, ebx
    call guestentropy_disjoint
    test edx, edx
    jz   .out
    mov  ecx, ebx
    shl  ecx, 4
    mov  [rbp + GR_WORK.meta + rcx], rax
    mov  [rbp + GR_WORK.meta + rcx + 8], rsi
    inc  ebx
    cmp  ebx, 3
    jb   .metadata
    mov  r12, [rbp + GR_WORK.meta + 16]
    movzx eax, word [r12 + 2]
    movzx ecx, word [rel gr_last]
    sub  ax, cx
    jz   .out
    cmp  ax, r14w
    ja   .out
    mov  eax, [rbp + GR_WORK.last]
    lea  ecx, [r14d - 1]
    and  eax, ecx
    movzx eax, word [r12 + rax*2 + 4]
    cmp  eax, r14d
    jae  .out
    mov  [rbp + GR_WORK.head], eax
    mov  [rbp + GR_WORK.index], eax
    ; Snapshot all entries once. Subsequent decisions never re-fetch guest
    ; addresses/flags/next pointers, including after the service call.
    mov  rsi, [rbp + GR_WORK.meta]
    lea  rdi, [rbp + GR_WORK.table]
    mov  ecx, r14d
    shl  ecx, 1
    rep  movsq
.chain:
    mov  eax, [rbp + GR_WORK.index]
    cmp  eax, r14d
    jae  .out
    bts  qword [rbp + GR_WORK.seen], rax
    jc   .out
    shl  eax, 4
    lea  r13, [rbp + GR_WORK.table + rax]
    movzx eax, word [r13 + 12]
    and  eax, ~1
    cmp  eax, 2                       ; WRITE required; no indirect/unknown bits
    jne  .out
    mov  rdi, [r13]
    mov  esi, [r13 + 8]
    call guestentropy_range
    test rax, rax
    jz   .out
    lea  rdi, [rbp + GR_WORK.meta]
    mov  ecx, 3
    call guestentropy_disjoint
    test edx, edx
    jz   .out
    lea  rdi, [rbp + GR_WORK.segments]
    mov  ecx, [rbp + GR_WORK.count]
    call guestentropy_disjoint
    test edx, edx
    jz   .out
    mov  ecx, [rbp + GR_WORK.count]
    shl  ecx, 4
    mov  [rbp + GR_WORK.segments + rcx], rax
    mov  [rbp + GR_WORK.segments + rcx + 8], rsi
    inc  dword [rbp + GR_WORK.count]
    ; Saturating capacity: the unfilled tail is still fully validated.
    add  esi, [rbp + GR_WORK.total]
    jc   .saturate
    cmp  esi, GR_MAX
    jbe  .total
.saturate:
    mov  esi, GR_MAX
.total:
    mov  [rbp + GR_WORK.total], esi
    test word [r13 + 12], 1
    jz   .preflight_done
    movzx eax, word [r13 + 14]
    mov  [rbp + GR_WORK.index], eax
    jmp  .chain
.preflight_done:
    call guestentropy_current
    test eax, eax
    jz   .revoke
    mov  esi, [rbp + GR_WORK.total]
    call guestentropy_budget
    test eax, eax
    jz   .out
    lea  rdi, [rel gr_scratch]
    mov  esi, [rbp + GR_WORK.total]
    call csprng_generate                 ; unchanged keep serialization/health
    test rax, rax
    jnz  .provider_failed
    call guestentropy_current
    test eax, eax
    jz   .revoke
    mov  rax, [rbp + GR_WORK.epoch]
    cmp  rax, [rel gr_epoch]
    jne  .revoke
    cmp  dword [rel gr_status], 15
    jne  .revoke
    cmp  byte [rel gr_ready], 1
    jne  .revoke
    xor  ecx, ecx
.config_current:
    lea  rdx, [rel gr_desc]
    mov  rax, [rdx + rcx*8]
    cmp  rax, [rbp + GR_WORK.config + rcx*8]
    jne  .revoke
    inc  ecx
    cmp  ecx, 4
    jb   .config_current
    movzx eax, word [rel gr_last]
    cmp  eax, [rbp + GR_WORK.last]
    jne  .revoke
    movzx eax, word [rel gr_usedidx]
    cmp  eax, [rbp + GR_WORK.used]
    jne  .revoke
    cmp  byte [rel gr_version], 1
    jne  .revoke
    ; Monotonic uncertainty after the provider also refuses publication.
    call time_monotonic_now_us
    cmp  rax, [rel gr_clock_last]
    jb   .out
    test rax, rax
    jz   .out
    mov  [rel gr_clock_last], rax
    mov  [rel gr_charge_time], rax
    ; The same resident vCPU remains stopped; no external call from here to
    ; used.idx. Write payload and one used element, then publish the index last.
    lea  rsi, [rel gr_scratch]
    mov  r15d, [rbp + GR_WORK.total]
    xor  ebx, ebx
.copy:
    mov  eax, ebx
    shl  eax, 4
    mov  rdi, [rbp + GR_WORK.segments + rax]
    mov  rcx, [rbp + GR_WORK.segments + rax + 8]
    cmp  rcx, r15
    jbe  .bounded
    mov  ecx, r15d
.bounded:
    sub  r15d, ecx
    rep  movsb
    inc  ebx
    test r15d, r15d
    jnz  .copy
    mov  r12, [rbp + GR_WORK.meta + 32]
    mov  eax, [rbp + GR_WORK.used]
    lea  ecx, [r14d - 1]
    and  eax, ecx
    mov  edx, [rbp + GR_WORK.head]
    mov  [r12 + rax*8 + 4], edx
    mov  edx, [rbp + GR_WORK.total]
    mov  [r12 + rax*8 + 8], edx
    mov  eax, [rbp + GR_WORK.used]
    inc  ax
    mov  [rel gr_usedidx], ax
    mov  [r12 + 2], ax
    inc  word [rel gr_last]
    mov  rax, [rbp + GR_WORK.meta + 16]
    test word [rax], 1                ; VIRTQ_AVAIL_F_NO_INTERRUPT
    jnz  .out
    mov  byte [rel gr_irq], 1
    mov  rax, [rel gr_page]
    mov  dword [rax + 0x60], 1
    jmp  .out
.provider_failed:
    call guestentropy_device_reset
    test eax, eax
    jz   .out
    mov  dword [rel gr_status], 128
    mov  rax, [rel gr_page]
    mov  dword [rax + 0x70], 128
    jmp  .out
.revoke:
    call guestentropy_state_zero
.out:
    lea  rdi, [rel gr_scratch]
    mov  ecx, GR_MAX
    xor  eax, eax
    rep  stosb
    mov  rdi, rbp
    mov  ecx, GR_WORK_size
    rep  stosb
    mov  rsp, [rbp + GR_WORK_size]
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    popfq
    ret

guestentropy_try_inject_irq:
    HV_POWER_WORK guestentropy_try_inject_irq, 0, hv_guest_power_io_admit
    pushfq
    cld
    call guestentropy_current
    test eax, eax
    jz   .revoke
    cmp  byte [rel gr_irq], 1
    jne  .no
    cmp  dword [rel gr_status], 15
    jne  .revoke
    mov  edi, 3
    call hv_pic_try_inject
    jmp  .out
.revoke:
    call guestentropy_state_zero
.no:
    xor  eax, eax
.out:
    popfq
    ret

%include "core/abi/wdata.inc"
%macro WDATA_hv_guestentropy 0
align 16
; Global service exposure state deliberately outside the resettable device.
gr_clock_last: dq 0
gr_charge_time: dq 0
gr_spent: dd 0
align 8
gr_epoch: dq 0
gr_state:
gr_page: dq 0
gr_owner: times GR_OWNER_BYTES db 0
gr_desc: dq 0
gr_avail: dq 0
gr_used: dq 0
gr_num: dd 0
gr_qsel: dd 0
gr_dfsel: dd 0
gr_status: dd 0
gr_last: dw 0
gr_usedidx: dw 0
gr_ready: db 0
gr_version: db 0
gr_irq: db 0
align 16
gr_scratch: times GR_MAX db 0
gr_state_end:
%endmacro
WDATA_DEFER WDATA_hv_guestentropy
