;; MODULE hv/guestsound
%include "hv/guest_power.inc"
;; LAYER 5
;; EXPORTS guestsound_device_reset, guestsound_state_zero, guestsound_mmio_write, guestsound_pump, guestsound_try_inject_irq, guestsound_offer, guestsound_native_current, guestsound_retire
;; IMPORTS hv/guest_power, hv/vmx, hv/vm_profile, hv/hv_ops, hv/guestnet, dev/net/virtio_domain, snd/mixer, media/pcm_stream
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Virtio1.2 section5.14: device25, queues control/event/TX/RX. VERSION_1
; only; one output stream, S16LE stereo48000; no events/jacks/chmaps/capture.
; Serialized resident BSP, guest RAM quiescent during each bounded call.
; At most one4096-byte private TX. Copy != consumption != played. No clocks,
; callbacks, DMA, hardware or automatic sink. Unwired native sink backpressures.
; Native caller owns stable mapped CPU context/PCM/ring and real quiescence
; receipts (media/pcm_stream contract). Offer uses snd/mixer at unity; retire
; requires native EOF retirement AND quiescence, not just copied bytes.
; Reset/RELEASE discard private copies and invalidate native receipts. A native
; owner checks native_current before each grant; on refusal it stops/quiesces
; its own sink before recycling its own ring. STOP also refuses further grants.
; Allocation inspected on f462a766: +20000 follows SVM MSRPM1e000..1ffff;
; MMIO d0004000, PIC7 and profilebit64 have no existing virtual producer.
GS_QMAX equ 64
GS_MAX equ 4096
GS_OWNER_BYTES equ 112
struc GS_QUEUE
 .desc: resq 1
 .avail: resq 1
 .used: resq 1
 .num: resd 1
 .ready: resd 1
 .last: resw 1
 .usedidx: resw 1
 .pad: resd 1
endstruc
guestsound_page:
    mov  rax, [rel hv_linux_region]
    test rax, rax
    jz   .bad
    mov  rdx, [rel hv_linux_region_capacity]
    cmp  rdx, HV_LINUX_CTRL_BYTES
    jb   .bad
    add  rdx, rax
    jc   .bad
    add  rax, HV_GUESTSND_PAGE
    jc   .bad
    ret
.bad:
    xor  eax, eax
    ret

; Private owner receipt. Caller supplies 112 private bytes. Queue reset cannot
; renew its START authority; selected profile must match both START generations.
; RDI=receipt; EAX=success. No guest pointer is dereferenced here.
guestsound_owner_read:
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
    test eax, VP_DEV_SOUND
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
    mov  rax, [rel gs_epoch]
    mov  [rdi + 88], rax
    cmp  byte [rel hv_linux_start_active], 1
    jne  .bad
    movzx eax, byte [rel hv_linux_start_active]
    mov  [rdi + 96], rax
    mov  rax, [rel gs_page]
    mov  [rdi + 104], rax
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

guestsound_current:
    mov  rax, [rel guestnet_domain_ctx]
    cmp  rax, [rel gs_owner + 48]
    jne  .bad                       ; reject replacement before dereferencing it
    cmp  byte [rel hv_linux_running], 1
    jne  .bad
    sub  rsp, GS_OWNER_BYTES + 8
    mov  rdi, rsp
    call guestsound_owner_read
    test eax, eax
    jz   .out
    lea  rsi, [rel gs_owner]
    mov  rdi, rsp
    mov  ecx, GS_OWNER_BYTES / 8
    repe cmpsq
    sete al
    movzx eax, al
.out:
    add  rsp, GS_OWNER_BYTES + 8
    ret
.bad:
    xor  eax, eax
    ret

guestsound_state_zero:
    HV_POWER_WORK guestsound_state_zero, 0, hv_guest_power_admit
    pushfq
    cld
    call guestsound_page
    test rax, rax
    jz   .private
    cmp  rax, [rel gs_page]
    jne  .private
    mov  dword [rax + 0x60], 0
    mov  dword [rax + 0x70], 0
.private:
    inc  qword [rel gs_epoch]
    lea  rdi, [rel gs_state]
    mov  ecx, gs_state_end - gs_state
    xor  eax, eax
    rep  stosb
    popfq
    ret

guestsound_device_reset:
    HV_POWER_WORK guestsound_device_reset, 0, hv_guest_power_admit
    pushfq
    cld
    call guestsound_state_zero
    call guestsound_page
    test rax, rax
    jz   .out
    mov  [rel gs_page], rax
    lea  rdi, [rel gs_owner]
    call guestsound_owner_read
    test eax, eax
    jz   .refuse
    mov  rdi, [rel gs_page]
    mov  ecx, 4096 / 8
    xor  eax, eax
    rep  stosq
    mov  rax, [rel gs_page]
    mov  dword [rax], 0x74726976
    mov  dword [rax + 4], 2
    mov  dword [rax + 8], 25
    mov  dword [rax + 12], 0x50614f53
    mov  dword [rax + 0x34], GS_QMAX
    mov  dword [rax + 0x104], 1    ; streams=1 (jacks/chmaps remain0)
    mov  eax, 1
    jmp  .out
.refuse:
    call guestsound_state_zero
    xor  eax, eax
.out:
    popfq
    ret

; EDI=register offset, ESI=value. Queue views never supply authority.
guestsound_mmio_write:
    HV_POWER_WORK guestsound_mmio_write, 0, hv_guest_power_io_admit
    pushfq
    cld
    push rbx
    push r12
    push r13
    push r14
    mov r12d,edi
    mov r13d,esi
    call guestsound_current
    test eax,eax
    jz .revoke
    mov rbx,[rel gs_page]
    cmp r12d,0x70
    je .status
    cmp r12d,0x14
    je .fsel
    cmp r12d,0x24
    je .dfsel
    cmp r12d,0x20
    je .feature
    cmp r12d,0x30
    je .qsel
    cmp r12d,0x64
    je .ack
    cmp r12d,0x50
    je .notify
    cmp dword [rel gs_qsel],4
    jae .done
    mov eax,[rel gs_qsel]
    imul eax,GS_QUEUE_size
    lea r14,[rel gs_queues]
    add r14,rax
    cmp r12d,0x44
    je .ready
    cmp r12d,0x38
    je .config
    cmp r12d,0x80
    jb .done
    cmp r12d,0xa4
    ja .done
    mov eax,r12d
    and eax,15
    cmp eax,4
    ja .done
    test eax,3
    jnz .done
.config:
    cmp dword [r14+GS_QUEUE.ready],0
    jne .fail
    cmp r12d,0x38
    jne .addr
    mov [r14+GS_QUEUE.num],r13d
    jmp .done
.addr:
    mov eax,r12d
    sub eax,0x80
    shr eax,1
    and eax,-8
    test r12d,4
    jz .lo
    add eax,4
.lo:
    mov [r14+rax],r13d
    jmp .done
.ready:
    cmp r13d,1
    jne .fail
    cmp dword [rel gs_status],11
    jne .fail
    mov eax,[r14+GS_QUEUE.num]
    test eax,eax
    jz .fail
    cmp eax,GS_QMAX
    ja .fail
    lea edx,[eax-1]
    test eax,edx
    jnz .fail
    mov dword [r14+GS_QUEUE.ready],1
    jmp .qview
.fsel:
    mov dword [rbx+0x10],0
    cmp r13d,1
    jne .done
    mov dword [rbx+0x10],1
    jmp .done
.dfsel:
    mov [rel gs_dfsel],r13d
    jmp .done
.feature:
    test dword [rel gs_status],8
    jnz .fail
    cmp dword [rel gs_dfsel],1
    jne .zero_feature
    cmp r13d,1
    jne .fail
    mov byte [rel gs_version],1
    jmp .done
.zero_feature:
    test r13d,r13d
    jnz .fail
    jmp .done
.qsel:
    mov [rel gs_qsel],r13d
.qview:
    xor eax,eax
    xor edx,edx
    cmp dword [rel gs_qsel],4
    jae .view_store
    mov eax,[rel gs_qsel]
    imul eax,GS_QUEUE_size
    lea rdx,[rel gs_queues]
    mov edx,[rdx+rax+GS_QUEUE.ready]
    mov eax,GS_QMAX
.view_store:
    mov [rbx+0x34],eax
    mov [rbx+0x44],edx
    jmp .done
.status:
    test r13d,r13d
    jnz .nonzero
    call guestsound_device_reset
    jmp .done
.nonzero:
    mov eax,[rel gs_status]
    test eax,128
    jnz .done
    mov edx,eax
    or edx,r13d
    cmp edx,r13d
    jne .fail
    cmp r13d,1
    je .store
    cmp r13d,3
    je .store
    cmp r13d,11
    je .modern
    cmp r13d,15
    jne .fail
    test eax,8
    jz .fail
.modern:
    cmp byte [rel gs_version],1
    jne .fail
    cmp eax,3
    jb .fail
.store:
    mov [rel gs_status],r13d
    mov [rbx+0x70],r13d
    jmp .done
.ack:
    test r13d,1
    jz .done
    mov byte [rel gs_irq],0
    mov dword [rbx+0x60],0
    jmp .done
.notify:
    cmp r13d,4
    jae .done
    call guestsound_pump
    jmp .done
.fail:
    call guestsound_device_reset
    test eax,eax
    jz .done
    mov dword [rel gs_status],128
    mov rax,[rel gs_page]
    mov dword [rax+0x70],128
    jmp .done
.revoke:
    call guestsound_state_zero
.done:
    pop r14
    pop r13
    pop r12
    pop rbx
    popfq
    ret

guestsound_range:
    test rsi,rsi
    jz .bad
    cmp rsi,0x100000
    ja .bad
    jmp hv_linux_gpa2hva              ; actual shared translator, full GPA
.bad:
    xor eax,eax
    ret

; RDI=span array, ECX=count, RAX=start, RSI=length; EDX=disjoint.
; Previously range-checked endpoints, all in the same contiguous guest backing.
guestsound_disjoint:
    mov edx,1
    lea r8,[rax+rsi]
.loop:
    test ecx,ecx
    jz .out
    mov r9,[rdi]
    cmp r9,r8
    jae .next
    add r9,[rdi+8]
    cmp rax,r9
    jb .bad
.next:
    add rdi,16
    dec ecx
    jmp .loop
.bad:
    xor edx,edx
.out:
    ret

; Validate ALL ready queues' metadata, including inactive event/RX queues.
; Private list holds their pairwise disjoint descriptor/avail/used spans.
guestsound_metadata:
    mov dword [rel gs_nmeta],0
    xor r12d,r12d
.queue:
    imul eax,r12d,GS_QUEUE_size
    lea r13,[rel gs_queues]
    add r13,rax
    cmp dword [r13+GS_QUEUE.ready],0
    je .nextq
    xor r14d,r14d
.span:
    mov rdi,[r13+r14*8]
    mov esi,[r13+GS_QUEUE.num]
    test r14d,r14d
    jnz .ring
    test dil,15
    jnz .bad
    shl esi,4
    jmp .range
.ring:
    cmp r14d,1
    jne .used
    test dil,1
    jnz .bad
    lea esi,[rsi*2+6]
    jmp .range
.used:
    test dil,3
    jnz .bad
    lea esi,[rsi*8+6]
.range:
    mov r15,rsi
    call guestsound_range
    test rax,rax
    jz .bad
    mov rsi,r15
    mov ecx,[rel gs_nmeta]
    lea rdi,[rel gs_meta]
    call guestsound_disjoint
    test edx,edx
    jz .bad
    mov ecx,[rel gs_nmeta]
    shl ecx,4
    lea rdi,[rel gs_meta]
    mov [rdi+rcx],rax
    mov [rdi+rcx+8],r15
    inc dword [rel gs_nmeta]
    ; Remember only current used/avail/desc HVAs; metadata list is dense.
    mov eax,r12d
    imul eax,24
    lea rdi,[rel gs_mapped]
    add rdi,rax
    lea rdx,[rel gs_meta]
    mov rax,[rdx+rcx]
    mov [rdi+r14*8],rax
    inc r14d
    cmp r14d,3
    jb .span
.nextq:
    inc r12d
    cmp r12d,4
    jb .queue
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; EDI=queue0/2. Snapshot whole table; validate all chain capacity and aliasing
; before reading request or writing any guest output. At most64 descriptors,
; total readable<=4120, writable<=4096. No indirect or read-after-write.
guestsound_chain:
    mov [rel gs_workq],edi
    imul eax,edi,GS_QUEUE_size
    lea rbx,[rel gs_queues]
    add rbx,rax
    cmp dword [rbx+GS_QUEUE.ready],1
    jne .empty
    imul eax,edi,24
    lea r12,[rel gs_mapped]
    add r12,rax
    mov rax,[r12+8]
    movzx edx,word [rax+2]
    sub dx,[rbx+GS_QUEUE.last]
    jz .empty
    mov ecx,[rbx+GS_QUEUE.num]
    cmp edx,ecx
    ja .bad
    dec ecx
    movzx edx,word [rbx+GS_QUEUE.last]
    and edx,ecx
    movzx r13d,word [rax+rdx*2+4]
    cmp r13d,[rbx+GS_QUEUE.num]
    jae .bad
    mov [rel gs_head],r13d
    mov rsi,[r12]
    lea rdi,[rel gs_table]
    mov ecx,[rbx+GS_QUEUE.num]
    shl ecx,1
    rep movsq
    mov qword [rel gs_seen],0
    mov dword [rel gs_nseg],0
    mov dword [rel gs_rbytes],0
    mov dword [rel gs_wbytes],0
    mov dword [rel gs_write_seen],0
.walk:
    bts qword [rel gs_seen],r13
    jc .bad
    mov eax,r13d
    shl eax,4
    lea r14,[rel gs_table]
    add r14,rax
    movzx edx,word [r14+12]
    test edx,~3
    jnz .bad
    test edx,2
    jz .read
    mov dword [rel gs_write_seen],1
    mov eax,[rel gs_wbytes]
    add eax,[r14+8]
    jc .bad
    cmp eax,GS_MAX
    ja .bad
    mov [rel gs_wbytes],eax
    jmp .span
.read:
    cmp dword [rel gs_write_seen],0
    jne .bad
    mov eax,[rel gs_rbytes]
    add eax,[r14+8]
    jc .bad
    cmp eax,GS_MAX+24
    ja .bad
    mov [rel gs_rbytes],eax
.span:
    mov rdi,[r14]
    mov esi,[r14+8]
    call guestsound_range
    test rax,rax
    jz .bad
    mov esi,[r14+8]
    lea rdi,[rel gs_meta]
    mov ecx,[rel gs_nmeta]
    call guestsound_disjoint
    test edx,edx
    jz .bad
    lea rdi,[rel gs_segments]
    mov ecx,[rel gs_nseg]
    call guestsound_disjoint
    test edx,edx
    jz .bad
    cmp byte [rel gs_pending],0
    je .store
    lea rdi,[rel gs_pending_spans]
    mov ecx,[rel gs_pending_count]
    call guestsound_disjoint
    test edx,edx
    jz .bad
.store:
    mov ecx,[rel gs_nseg]
    shl ecx,4
    lea rdi,[rel gs_segments]
    mov [rdi+rcx],rax
    mov [rdi+rcx+8],rsi
    shr ecx,4
    lea rdi,[rel gs_flags]
    movzx edx,word [r14+12]
    mov [rdi+rcx],dl
    inc dword [rel gs_nseg]
    test edx,1
    jz .gather
    movzx r13d,word [r14+14]
    cmp r13d,[rbx+GS_QUEUE.num]
    jae .bad
    cmp dword [rel gs_nseg],GS_QMAX
    jb .walk
    jmp .bad
.gather:
    xor r13d,r13d
    lea rdi,[rel gs_request]
.copy:
    lea rax,[rel gs_flags]
    test byte [rax+r13],2
    jnz .valid
    mov eax,r13d
    shl eax,4
    lea rdx,[rel gs_segments]
    mov rsi,[rdx+rax]
    mov rcx,[rdx+rax+8]
    rep movsb
    inc r13d
    cmp r13d,[rel gs_nseg]
    jb .copy
.valid:
    mov eax,1
    ret
.bad:
    mov eax,-1
    ret
.empty:
    xor eax,eax
    ret

; Scatter ESI=response length from gs_response to current chain; all output
; capacity and metadata validated by chain(). Advance used only after bytes.
guestsound_complete:
    mov r15d,esi
    lea r12,[rel gs_response]
    xor r13d,r13d
.scatter:
    lea rax,[rel gs_flags]
    test byte [rax+r13],2
    jz .next
    mov eax,r13d
    shl eax,4
    lea rdx,[rel gs_segments]
    mov rdi,[rdx+rax]
    mov rcx,[rdx+rax+8]
    cmp rcx,rsi
    cmova rcx,rsi
    sub rsi,rcx
    mov r14,rsi
    mov rsi,r12
    add r12,rcx
    rep movsb
    mov rsi,r14
    test rsi,rsi
    jz .used
.next:
    inc r13d
    jmp .scatter
.used:
    mov eax,[rel gs_workq]
    imul ecx,eax,24
    lea rdi,[rel gs_mapped]
    mov rdi,[rdi+rcx+16]
    imul eax,GS_QUEUE_size
    lea rbx,[rel gs_queues]
    add rbx,rax
    mov ecx,[rbx+GS_QUEUE.num]
    dec ecx
    movzx edx,word [rbx+GS_QUEUE.usedidx]
    and ecx,edx
    mov eax,[rel gs_head]
    mov [rdi+rcx*8+4],eax
    mov [rdi+rcx*8+8],r15d
    inc dx
    mov [rbx+GS_QUEUE.usedidx],dx
    mov [rdi+2],dx
    inc word [rbx+GS_QUEUE.last]
    mov rax,[rel gs_page]
    mov dword [rax+0x60],1
    mov byte [rel gs_irq],1
    ret

; Complete retained TX with EAX=virtio status. Never reads guest descriptors
; again; immutable checked response spans and current START own these stores.
guestsound_finish_tx:
    mov [rel gs_response],eax
    mov dword [rel gs_response+4],0 ; latency0 only AFTER true consumption/cancel
    mov dword [rel gs_workq],2
    mov eax,[rel gs_pending_head]
    mov [rel gs_head],eax
    mov ecx,[rel gs_pending_count]
    mov [rel gs_nseg],ecx
    shl ecx,1
    lea rsi,[rel gs_pending_spans]
    lea rdi,[rel gs_segments]
    rep movsq
    mov ecx,[rel gs_pending_count]
    lea rsi,[rel gs_pending_flags]
    lea rdi,[rel gs_flags]
    rep movsb
    mov rax,[rel gs_pending_used]
    mov [rel gs_mapped+2*24+16],rax
    ; Acceptance advanced private avail index; completion must not do so twice.
    dec word [rel gs_queues+2*GS_QUEUE_size+GS_QUEUE.last]
    mov esi,8
    call guestsound_complete
    mov byte [rel gs_pending],0
    mov byte [rel gs_offered],0
    mov dword [rel gs_pcm_bytes],0
    lea rdi,[rel gs_pcm]
    mov ecx,GS_MAX/8
    xor eax,eax
    rep stosq
    ret

; One control and one TX per pump. Other queues have no negotiated producer.
guestsound_pump:
    HV_POWER_WORK guestsound_pump, 0, hv_guest_power_io_admit
    pushfq
    cld
    cmp qword [rel gs_page],0
    je .absent                       ; omitted device must not churn power epoch
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,8
    call guestsound_current
    test eax,eax
    jz .revoke
    cmp dword [rel gs_status],15
    jne .out
    call guestsound_metadata
    test eax,eax
    jz .out
    xor edi,edi
    call guestsound_chain
    cmp eax,1
    jne .tx
    cmp dword [rel gs_wbytes],4
    jb .tx
    ; A RELEASE can complete retained TX. Save control chain first.
    mov ecx,[rel gs_nseg]
    mov [rel gs_ctrl_count],ecx
    shl ecx,1
    lea rsi,[rel gs_segments]
    lea rdi,[rel gs_ctrl_spans]
    rep movsq
    mov ecx,[rel gs_nseg]
    lea rsi,[rel gs_flags]
    lea rdi,[rel gs_ctrl_flags]
    rep movsb
    mov eax,[rel gs_head]
    mov [rel gs_ctrl_head],eax
    call guestsound_control
    mov [rel gs_response],eax
    mov r15d,edx
    test eax,eax
    jz .tx                           ; RELEASE waits for bounded TX drain
    mov ecx,[rel gs_ctrl_count]
    shl ecx,1
    lea rsi,[rel gs_ctrl_spans]
    lea rdi,[rel gs_segments]
    rep movsq
    mov ecx,[rel gs_ctrl_count]
    lea rsi,[rel gs_ctrl_flags]
    lea rdi,[rel gs_flags]
    rep movsb
    mov eax,[rel gs_ctrl_head]
    mov [rel gs_head],eax
    mov dword [rel gs_workq],0
    mov esi,r15d
    call guestsound_complete
.tx:
    cmp byte [rel gs_pending],0
    jne .out                         ; real backpressure, no clock completion
    mov edi,2
    call guestsound_chain
    cmp eax,1
    jne .out
    cmp dword [rel gs_wbytes],8
    jb .out
    cmp dword [rel gs_rbytes],8
    jb .badtx
    cmp dword [rel gs_request],0
    jne .badtx
    mov eax,[rel gs_stream]
    cmp eax,2
    je .txstate
    cmp eax,3
    jne .badtx
.txstate:
    mov ecx,[rel gs_rbytes]
    sub ecx,4
    test ecx,3
    jnz .badtx
    cmp ecx,[rel gs_buffer_bytes]
    ja .badtx
    mov [rel gs_pcm_bytes],ecx
    lea rsi,[rel gs_request+4]
    lea rdi,[rel gs_pcm]
    rep movsb
    mov ecx,[rel gs_nseg]
    mov [rel gs_pending_count],ecx
    shl ecx,1
    lea rsi,[rel gs_segments]
    lea rdi,[rel gs_pending_spans]
    rep movsq
    mov ecx,[rel gs_nseg]
    lea rsi,[rel gs_flags]
    lea rdi,[rel gs_pending_flags]
    rep movsb
    mov eax,[rel gs_head]
    mov [rel gs_pending_head],eax
    mov rax,[rel gs_mapped+2*24+16]
    mov [rel gs_pending_used],rax
    inc qword [rel gs_ticket]
    mov byte [rel gs_pending],1
    inc word [rel gs_queues+2*GS_QUEUE_size+GS_QUEUE.last]
    jmp .out
.badtx:
    mov dword [rel gs_response],0x8003
    mov dword [rel gs_response+4],0
    mov esi,8
    call guestsound_complete
    jmp .out
.revoke:
    call guestsound_state_zero
.out:
    ; Request/table are transient and never retained as native PCM authority.
    lea rdi,[rel gs_work]
    mov ecx,gs_work_end-gs_work
    xor eax,eax
    rep stosb
    add rsp,8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    popfq
    ret
.absent:
    xor eax,eax
    popfq
    ret

; RAX=status, EDX=response length. Headers, payload and response capacity were
; preflighted. Stream states:0 released,1 parameters,2 prepared,3 running,4 stopped.
guestsound_control:
    mov edx,4
    mov eax,0x8001
    cmp dword [rel gs_rbytes],8
    jb .out
    mov ecx,[rel gs_request]
    cmp ecx,0x100
    je .info
    cmp ecx,0x101
    je .params
    cmp dword [rel gs_rbytes],8
    jne .out
    cmp dword [rel gs_request+4],0
    jne .out
    cmp ecx,0x102
    je .prepare
    cmp ecx,0x103
    je .release
    cmp ecx,0x104
    je .start
    cmp ecx,0x105
    je .stop
    mov eax,0x8002
    ret
.info:
    cmp dword [rel gs_rbytes],16
    jne .out
    cmp dword [rel gs_request+4],0
    jne .out
    cmp dword [rel gs_request+8],1
    jne .out
    cmp dword [rel gs_request+12],32
    jne .out
    cmp dword [rel gs_wbytes],36
    jb .out
    lea rdi,[rel gs_response+4]
    xor eax,eax
    mov ecx,4
    rep stosq
    mov qword [rel gs_response+12],1<<5 ; S16
    mov qword [rel gs_response+20],1<<7 ;48000Hz
    mov word [rel gs_response+29],0x0202 ;direction0,channels2..2
    mov edx,36
    jmp .ok
.params:
    cmp dword [rel gs_rbytes],24
    jne .out
    cmp dword [rel gs_request+4],0
    jne .out
    cmp dword [rel gs_stream],2
    ja .out
    cmp byte [rel gs_pending],0
    jne .out
    cmp dword [rel gs_request+16],0
    jne .unsupported
    cmp dword [rel gs_request+20],0x00070502 ;2channels,format5,rate7,pad0
    jne .unsupported
    mov ecx,[rel gs_request+8]
    cmp ecx,4
    jb .out
    cmp ecx,GS_MAX
    ja .out
    test ecx,3
    jnz .out
    mov esi,[rel gs_request+12]
    cmp esi,4
    jb .out
    cmp esi,ecx
    ja .out
    test esi,3
    jnz .out
    mov eax,ecx
    xor edx,edx
    div esi
    test edx,edx
    jnz .invalid
    mov [rel gs_buffer_bytes],ecx
    mov dword [rel gs_stream],1
    jmp .ok4
.prepare:
    ; RELEASE retains valid parameters; reset clears buffer_bytes. Both a
    ; configured release (state0) and SET_PARAMS/PREPARE may prepare again.
    cmp dword [rel gs_stream],2
    ja .out
    cmp dword [rel gs_buffer_bytes],0
    je .out
    cmp byte [rel gs_pending],0
    jne .out
.prepared:
    mov dword [rel gs_stream],2
    jmp .ok
.start:
    cmp dword [rel gs_stream],2
    je .started
    cmp dword [rel gs_stream],4
    jne .out
.started:
    mov dword [rel gs_stream],3
    jmp .ok
.stop:
    cmp dword [rel gs_stream],3
    jne .out
    mov dword [rel gs_stream],4
    jmp .ok
.release:
    cmp dword [rel gs_stream],1
    jb .out
    cmp dword [rel gs_stream],3
    je .out
    cmp byte [rel gs_pending],0
    je .released
    mov eax,0x8003
    call guestsound_finish_tx          ; pending IO BEFORE RELEASE response
.released:
    cmp dword [rel gs_queues+2*GS_QUEUE_size+GS_QUEUE.ready],0
    je .release_done
    mov rax,[rel gs_mapped+2*24+8]
    mov ax,[rax+2]
    cmp ax,[rel gs_queues+2*GS_QUEUE_size+GS_QUEUE.last]
    jne .draining
.release_done:
    mov dword [rel gs_stream],0
    jmp .ok4
.draining:
    xor eax,eax                       ; no control completion while TX remains
    ret
.unsupported:
    mov eax,0x8002
    ret
.invalid:
    mov eax,0x8001
    mov edx,4
    ret
.ok4:
    mov edx,4
.ok:
    mov eax,0x8000
.out:
    ret
; Trusted caller-owned CPU spans, serialized with the guest BSP. Check arithmetic
; and exclude the entire guest reservation and all device-private storage. Mapping
; is the native caller's contract, as in snd/mixer and media/pcm_stream.
guestsound_native_span:
    test rdi,rdi
    jz .bad
    test rsi,rsi
    jz .bad
    mov rax,rdi
    add rax,rsi
    jc .bad
    mov rdx,[rel hv_linux_region]
    cmp rdx,rax
    jae .private
    add rdx,[rel hv_linux_region_capacity]
    cmp rdi,rdx
    jb .bad
.private:
    lea rdx,[rel gs_private_begin]
    cmp rdx,rax
    jae .ok
    lea rdx,[rel gs_private_end]
    cmp rdi,rdx
    jb .bad
.ok:
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; RDI=initialized caller-owned media_pcm_stream (phaseEMPTY). Native PCM output
; capacity<=4096 and ring16384; context matches pending bytes and START/ticket.
; Fill caller PCM with the existing unity mixer, then begin the existing feeder.
; No guest completion. Returns0 accepted, -1 unavailable/invalid. The caller
; services the feeder with real grants and retirement, then calls retire below.
; A rejected feeder begin may have copied native PCM, never publishes guest used.
guestsound_offer:
    HV_POWER_WORK guestsound_offer, -1, hv_guest_power_io_admit
    pushfq
    cld
    push rbx
    push rbp
    push r12
    push r13
    sub rsp,96
    mov rbp,rsp
    mov rbx,rdi
    call guestsound_current
    test eax,eax
    jz .stale
    cmp dword [rel gs_stream],3
    jne .bad
    cmp byte [rel gs_pending],1
    jne .bad
    cmp byte [rel gs_offered],0
    jne .bad
    mov rdi,rbx
    mov esi,media_pcm_stream_size
    call guestsound_native_span
    test eax,eax
    jz .bad
    test bl,7
    jnz .bad
    cmp dword [rbx+media_pcm_stream.version],1
    jne .bad
    cmp dword [rbx+media_pcm_stream.phase],0
    jne .bad
    mov eax,[rel hv_linux_start_gen]
    cmp [rbx+media_pcm_stream.generation],rax
    jne .bad
    mov rax,[rel gs_ticket]
    cmp [rbx+media_pcm_stream.epoch],rax
    jne .bad
    mov r12d,[rel gs_pcm_bytes]
    cmp [rbx+media_pcm_stream.bytes],r12
    jne .bad
    mov rax,r12
    shr rax,2
    cmp [rbx+media_pcm_stream.frames],rax
    jne .bad
    cmp dword [rbx+media_pcm_stream.rate],48000
    jne .bad
    cmp dword [rbx+media_pcm_stream.channels],2
    jne .bad
    cmp dword [rbx+media_pcm_stream.frame_bytes],4
    jne .bad
    cmp dword [rbx+media_pcm_stream.format],1
    jne .bad
    cmp qword [rbx+media_pcm_stream.ring_bytes],16384
    jne .bad
    mov rdi,[rbx+media_pcm_stream.pcm]
    mov rsi,[rbx+media_pcm_stream.capacity]
    cmp rsi,GS_MAX
    ja .bad
    cmp rsi,r12
    jb .bad
    call guestsound_native_span
    test eax,eax
    jz .bad
    mov rdi,[rbx+media_pcm_stream.ring]
    mov esi,16384
    call guestsound_native_span
    test eax,eax
    jz .bad
    ; Block48 and stream40 are stack private; native output must not aliasctx.
    mov rax,[rbx+media_pcm_stream.pcm]
    mov [rbp],rax
    mov rdx,[rbx+media_pcm_stream.capacity]
    mov [rbp+8],rdx
    add rdx,rax
    cmp rbx,rdx
    jae .separate
    lea rcx,[rbx+media_pcm_stream_size]
    cmp rax,rcx
    jb .bad
.separate:
    lea rax,[rbp+48]
    mov [rbp+16],rax
    mov dword [rbp+24],1
    mov dword [rbp+28],2
    mov rax,r12
    shr rax,2
    mov [rbp+32],rax
    mov dword [rbp+40],48000
    mov dword [rbp+44],0
    lea rdx,[rel gs_pcm]
    mov [rbp+48],rdx
    mov [rbp+56],rax
    mov qword [rbp+64],0
    mov dword [rbp+72],32768
    mov dword [rbp+76],0
    mov dword [rbp+80],48000
    mov dword [rbp+84],2
    mov rdi,rbp
    call snd_mix_s16
    test rax,rax
    jnz .bad
    mov rdi,rbx
    call media_pcm_stream_begin
    test rax,rax
    jnz .bad
    call guestsound_current
    test eax,eax
    jz .stale
    mov [rel gs_native_ctx],rbx
    mov byte [rel gs_offered],1
    xor eax,eax
    jmp .out
.stale:
    call guestsound_state_zero
.bad:
    mov rax,-1
.out:
    add rsp,96
    pop r13
    pop r12
    pop rbp
    pop rbx
    popfq
    ret

; RDI=same stable native context. EAX=1 only while the offered ticket may
; receive native service grants. Serialized caller checks before EACH service;
; 0 requires caller-owned stop/quiescence, never another PCM grant. No DMA owner
; is installed here, so this is not a hardware stop receipt.
guestsound_native_current:
    HV_POWER_WORK guestsound_native_current, 0, hv_guest_power_io_admit
    pushfq
    cld
    push rbx
    sub rsp,8
    mov rbx,rdi
    call guestsound_current
    test eax,eax
    jz .out
    xor eax,eax
    cmp dword [rel gs_stream],3
    jne .out
    cmp byte [rel gs_pending],1
    jne .out
    cmp byte [rel gs_offered],1
    jne .out
    cmp rbx,[rel gs_native_ctx]
    jne .out
    mov eax,[rel hv_linux_start_gen]
    cmp [rbx+media_pcm_stream.generation],rax
    jne .no
    mov rax,[rel gs_ticket]
    cmp [rbx+media_pcm_stream.epoch],rax
    jne .no
    mov eax,1
    jmp .out
.no:
    xor eax,eax
.out:
    add rsp,8
    pop rbx
    popfq
    ret

; RDI=same native context, RSI=real kind2 quiescence receipt. No receipt is
; generated by this module. Only EOF, complete audio retirement and quiescence
; release guest TX custody. Native cancelled/faulted bytes need guest RELEASE
; (IO_ERR), not fabricated OK. A STOP retains data until drain or RELEASE.
guestsound_retire:
    HV_POWER_WORK guestsound_retire, -1, hv_guest_power_io_admit
    pushfq
    cld
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx,rdi
    mov r12,rsi
    sub rsp,8
    call guestsound_current
    test eax,eax
    jz .stale
    cmp byte [rel gs_pending],1
    jne .bad
    cmp byte [rel gs_offered],1
    jne .bad
    cmp rbx,[rel gs_native_ctx]
    jne .bad
    mov rdi,r12
    mov esi,media_pcm_stream_receipt_size
    call guestsound_native_span
    test eax,eax
    jz .bad
    mov eax,[rel hv_linux_start_gen]
    cmp [rbx+media_pcm_stream.generation],rax
    jne .bad
    mov rax,[rel gs_ticket]
    cmp [rbx+media_pcm_stream.epoch],rax
    jne .bad
    cmp dword [rbx+media_pcm_stream.phase],4
    jne .bad
    cmp qword [rbx+media_pcm_stream.reason],0
    jne .bad
    mov eax,[rel gs_pcm_bytes]
    cmp [rbx+media_pcm_stream.bytes],rax
    jne .bad
    shr eax,2
    cmp [rbx+media_pcm_stream.copied_frames],rax
    jne .bad
    mov rax,[r12+media_pcm_stream_receipt.retired]
    cmp rax,[rbx+media_pcm_stream.last_audio]
    jbe .bad
    mov rdi,rbx
    mov rsi,r12
    call media_pcm_stream_release
    test rax,rax
    jnz .bad
    call guestsound_current
    test eax,eax
    jz .stale
    mov eax,0x8000
    call guestsound_finish_tx
    xor eax,eax
    jmp .out
.stale:
    call guestsound_state_zero
.bad:
    mov rax,-1
.out:
    add rsp,8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    popfq
    ret

guestsound_try_inject_irq:
    HV_POWER_WORK guestsound_try_inject_irq, 0, hv_guest_power_io_admit
    pushfq
    cld
    cmp qword [rel gs_page],0
    je .no                           ; stable absent-device receipt
    call guestsound_current
    test eax,eax
    jz .revoke
    cmp byte [rel gs_irq],1
    jne .no
    cmp dword [rel gs_status],15
    jne .no
    mov edi,7
    call hv_pic_try_inject
    popfq
    ret
.revoke:
    call guestsound_state_zero
.no:
    xor eax,eax
    popfq
    ret

%include "core/abi/wdata.inc"
%macro WDATA_hv_guestsound 0
align 16
gs_private_begin:
gs_epoch: dq 0
gs_ticket: dq 0                    ; monotonic per accepted TX, never reset
gs_state:
gs_page: dq 0
gs_owner: times GS_OWNER_BYTES db 0
gs_qsel: dd 0
gs_dfsel: dd 0
gs_status: dd 0
gs_stream: dd 0
gs_buffer_bytes: dd 0
gs_pcm_bytes: dd 0
gs_version: db 0
gs_irq: db 0
gs_pending: db 0
gs_offered: db 0
align 8
gs_native_ctx: dq 0
gs_pending_used: dq 0
gs_pending_head: dd 0
gs_pending_count: dd 0
gs_queues: times 4*GS_QUEUE_size db 0
gs_ctrl_ready equ gs_queues+GS_QUEUE.ready
gs_tx_ready equ gs_queues+2*GS_QUEUE_size+GS_QUEUE.ready
gs_pending_spans: times GS_QMAX*16 db 0
gs_pending_flags: times GS_QMAX db 0
gs_pcm: times GS_MAX db 0
gs_work:
gs_nmeta: dd 0
gs_workq: dd 0
gs_nseg: dd 0
gs_head: dd 0
gs_rbytes: dd 0
gs_wbytes: dd 0
gs_write_seen: dd 0
gs_ctrl_head: dd 0
gs_ctrl_count: dd 0
align 8
gs_seen: dq 0
gs_meta: times 12*16 db 0
gs_mapped: times 4*24 db 0
gs_table: times GS_QMAX*16 db 0
gs_segments: times GS_QMAX*16 db 0
gs_flags: times GS_QMAX db 0
gs_ctrl_spans: times GS_QMAX*16 db 0
gs_ctrl_flags: times GS_QMAX db 0
gs_request: times GS_MAX+24 db 0
gs_response: times 40 db 0
gs_work_end:
gs_state_end:
gs_private_end:
%endmacro
WDATA_DEFER WDATA_hv_guestsound
