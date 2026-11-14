;; MODULE hv/guestfilesystem
;; LAYER 5
;; EXPORTS guestfilesystem_reset, guestfilesystem_zero, guestfilesystem_mmio_write, guestfilesystem_pump, guestfilesystem_irq
;; IMPORTS hv/filesystem_domain, hv/filesystem_queue, hv/filesystem_wire, hv/vmx, fs/guest_volume
;; CAPS CAP_BLOCK_READ, CAP_BLOCK_WRITE
;; OWNER saga:hv
;; CONTEXT: bsp_only
; F11 modern virtio-console (hvc1) plus partition-scoped virtio-block. The
; timer+ordinary hvc0+FILESYSTEM profile is the ONLY closure. One vCPU, no DMA,
; indirect descriptors, network, shared RPC dispatcher or external disk names.
GF_BLOCK_FEATURES equ (1<<1)|(1<<2)|(1<<9) ; SIZE_MAX, SEG_MAX, FLUSH
GF_CON_PAGE equ HV_GUESTFSC_PAGE
GF_BLK_PAGE equ HV_GUESTFSB_PAGE
%if GF_CON_PAGE < VST_END || GF_BLK_PAGE+4096 > 0x200000
 %error "F11 backing overlaps S7 private control objects"
%endif
struc GF_DEVICE
 .page: resq 1
 .fsel: resd 1
 .dfsel: resd 1
 .low: resd 1
 .high: resd 1
 .status: resd 1
 .qsel: resd 1
 .nqueues: resd 1
 .isr: resd 1
 .queues: resb 2*FSQ_size
endstruc

; Only called by actual terminal cleanup, or before first guest entry.
guestfilesystem_zero:
    lea rdi,[rel gf_storage]
    mov ecx,gf_storage_end-gf_storage
    xor eax,eax
    cld
    rep stosb
    ret

guestfilesystem_reset:
    push rbx
    call guestfilesystem_zero
    mov rax,[rel hv_linux_region_capacity]
    cmp rax,GF_BLK_PAGE+4096
    jb .bad
    mov rbx,[rel hv_linux_region]
    test rbx,rbx
    jz .bad
    mov rdi,rbx
    add rdi,GF_CON_PAGE
    jc .bad
    mov [rel gf_console+GF_DEVICE.page],rdi
    mov ecx,8192/8
    xor eax,eax
    cld
    rep stosq
    lea rax,[rbx+GF_BLK_PAGE]
    mov [rel gf_block+GF_DEVICE.page],rax
    mov dword [rel gf_console+GF_DEVICE.nqueues],2
    mov dword [rel gf_block+GF_DEVICE.nqueues],1
    mov rax,[rel gf_console+GF_DEVICE.page]
    mov dword [rax],0x74726976
    mov dword [rax+4],2
    mov dword [rax+8],3
    mov dword [rax+12],0x50614f53
    mov dword [rax+0x34],FSQ_MAX
    mov rax,[rel gf_block+GF_DEVICE.page]
    mov dword [rax],0x74726976
    mov dword [rax+4],2
    mov dword [rax+8],2
    mov dword [rax+12],0x50614f53
    mov dword [rax+0x10],GF_BLOCK_FEATURES ; bounded Linux BIO shape, no RO bit
    mov dword [rax+0x34],FSQ_MAX
    mov rdx,[rel fsg_volume+24]   ; partition capacity, no GPT/host exposure
    mov [rax+0x100],rdx
    mov dword [rax+0x108],4096    ; size_max bounds each data segment
    mov dword [rax+0x10c],1       ; seg_max: one data segment per chain
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop rbx
    ret

; EDI=offset from D0006000, ESI=decoded dword. No guest pointer follows a
; refused owner. Queue reset/config writes cannot repair a consumed exchange.
guestfilesystem_mmio_write:
    push rbx
    push rbp
    push r12
    push r13
    sub rsp,8
    mov r12d,edi
    mov r13d,esi
    call fsg_current
    test eax,eax
    jz .fault
    lea rbx,[rel gf_console]
    cmp r12d,4096
    jb .device
    sub r12d,4096
    lea rbx,[rel gf_block]
.device:
    cmp r12d,4096
    jae .fault
    mov rbp,[rbx+GF_DEVICE.page]
    test rbp,rbp
    jz .fault
    cmp r12d,0x70
    je .status
    cmp r12d,0x64
    je .ack
    cmp r12d,0x50
    je .out                       ; pump at the common clean exit boundary
    cmp r12d,0x14
    je .fsel
    cmp r12d,0x24
    je .dfsel
    cmp r12d,0x20
    je .features
    cmp r12d,0x30
    je .qsel
    mov eax,[rbx+GF_DEVICE.qsel]
    cmp eax,[rbx+GF_DEVICE.nqueues]
    jae .out
    imul eax,FSQ_size
    lea rdx,[rbx+GF_DEVICE.queues+rax]
    cmp r12d,0x44
    je .ready
    cmp dword [rdx+FSQ.ready],0
    jne .fault
    cmp r12d,0x38
    je .num
    cmp r12d,0x80
    je .desc_lo
    cmp r12d,0x84
    je .desc_hi
    cmp r12d,0x90
    je .avail_lo
    cmp r12d,0x94
    je .avail_hi
    cmp r12d,0xa0
    je .used_lo
    cmp r12d,0xa4
    je .used_hi
    jmp .out
.desc_lo: mov [rdx+FSQ.desc],r13d
    jmp .out
.desc_hi: mov [rdx+FSQ.desc+4],r13d
    jmp .out
.avail_lo: mov [rdx+FSQ.avail],r13d
    jmp .out
.avail_hi: mov [rdx+FSQ.avail+4],r13d
    jmp .out
.used_lo: mov [rdx+FSQ.used],r13d
    jmp .out
.used_hi: mov [rdx+FSQ.used+4],r13d
    jmp .out
.num:
    test r13d,r13d
    jz .fault
    cmp r13d,FSQ_MAX
    ja .fault
    lea eax,[r13d-1]
    test eax,r13d
    jnz .fault
    mov [rdx+FSQ.num],r13d
    jmp .out
.ready:
    cmp r13d,1
    jne .fault                    ; no live queue disable/re-enable shortcut
    cmp dword [rdx+FSQ.ready],0
    jne .fault
    mov dword [rdx+FSQ.ready],1
    mov [rbp+0x44],r13d
    jmp .out
.qsel:
    mov [rbx+GF_DEVICE.qsel],r13d
    xor eax,eax
    xor ecx,ecx
    cmp r13d,[rbx+GF_DEVICE.nqueues]
    jae .selected
    imul eax,r13d,FSQ_size
    mov ecx,[rbx+GF_DEVICE.queues+rax+FSQ.ready]
    mov eax,FSQ_MAX
.selected:
    mov [rbp+0x34],eax
    mov [rbp+0x44],ecx
    jmp .out
.fsel:
    mov [rbx+GF_DEVICE.fsel],r13d
    xor eax,eax
    cmp r13d,1
    jne .low_features
    mov eax,1                     ; VERSION_1 required
    jmp .feature_page
.low_features:
    test r13d,r13d
    jnz .feature_page
    lea rdx,[rel gf_block]
    cmp rbx,rdx
    jne .feature_page
    mov eax,GF_BLOCK_FEATURES
.feature_page:
    mov [rbp+0x10],eax
    jmp .out
.dfsel:
    mov [rbx+GF_DEVICE.dfsel],r13d
    jmp .out
.features:
    test dword [rbx+GF_DEVICE.status],8
    jnz .fault
    cmp dword [rbx+GF_DEVICE.dfsel],0
    je .low
    cmp dword [rbx+GF_DEVICE.dfsel],1
    jne .out
    mov [rbx+GF_DEVICE.high],r13d
    jmp .out
.low:
    mov [rbx+GF_DEVICE.low],r13d
    jmp .out
.status:
    test r13d,r13d
    jnz .nonzero_status
    cmp dword [rbx+GF_DEVICE.status],0
    jne .fault
    jmp .out
.nonzero_status:
    test r13d,~15
    jnz .fault
    mov eax,[rbx+GF_DEVICE.status]
    and eax,r13d
    cmp eax,[rbx+GF_DEVICE.status]
    jne .fault
    test r13d,8
    jz .status_store
    cmp dword [rbx+GF_DEVICE.high],1
    jne .fault
    mov eax,[rbx+GF_DEVICE.low]
    lea rdx,[rel gf_block]
    cmp rbx,rdx
    jne .console_features
    test eax,~GF_BLOCK_FEATURES
    jnz .fault
    jmp .status_store
.console_features:
    test eax,eax
    jnz .fault
.status_store:
    mov [rbx+GF_DEVICE.status],r13d
    mov [rbp+0x70],r13d
    jmp .out
.ack:
    mov eax,r13d
    not eax
    and [rbx+GF_DEVICE.isr],eax
    mov eax,[rbx+GF_DEVICE.isr]
    mov [rbp+0x60],eax
    jmp .out
.fault:
    call fsg_fault
.out:
    add rsp,8
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; RDI=device ->mark actual used-ring activity. Shared level IRQ5. Suppressing
; an avail IRQ is an optimization only; Linux may poll the used index instead.
gf_raise:
    or dword [rdi+GF_DEVICE.isr],1
    mov rax,[rdi+GF_DEVICE.page]
    mov dword [rax+0x60],1
    ret

gf_frame_begin:
    cmp qword [rel fsg_frame_deadline],0
    jne .ok
    mov rax,[rel fsg_clock]
    add rax,2000000                ; actual first transport byte, never renewed
    jc .bad
    cmp rax,[rel fsg_deadline]
    jbe .store
    mov rax,[rel fsg_deadline]
.store:
    mov [rel fsg_frame_deadline],rax
.ok:
    xor eax,eax
    ret
.bad:
    mov eax,-1
    ret

; hvc1 RX: one bounded direct chain per exit, partial framing supported.
gf_console_rx:
    sub rsp,8
    call fsg_current
    test eax,eax
    jz .fault
    cmp dword [rel fsg_pending],1
    jne .out
    cmp dword [rel fsg_tx_offset],256
    jae .out
    lea rdi,[rel gf_console+GF_DEVICE.queues]
    lea rsi,[rel gf_work]
    call fsq_prepare
    test eax,eax
    jz .out
    js .fault
    xor ebx,ebx
.flags:
    cmp ebx,[rel gf_work+FSQ_WORK.count]
    jae .copy_begin
    lea rax,[rel gf_work+FSQ_WORK.flags]
    test word [rax+rbx*2],2
    jz .fault
    inc ebx
    jmp .flags
.copy_begin:
    call gf_frame_begin
    test eax,eax
    jnz .fault
    mov r12d,256
    sub r12d,[rel fsg_tx_offset]
    cmp r12d,[rel gf_work+FSQ_WORK.total]
    jbe .bounded
    mov r12d,[rel gf_work+FSQ_WORK.total]
.bounded:
    mov r13d,r12d
    mov esi,[rel fsg_tx_offset]
    lea rax,[rel fsg_request]
    add rsi,rax
    xor ebx,ebx
.copy:
    mov eax,ebx
    shl eax,4
    lea rdx,[rel gf_work+FSQ_WORK.span]
    mov rdi,[rdx+rax]
    mov rcx,[rdx+rax+8]
    cmp rcx,r12
    jbe .piece
    mov ecx,r12d
.piece:
    sub r12d,ecx
    cld
    rep movsb
    inc ebx
    test r12d,r12d
    jnz .copy
    lea rdi,[rel gf_work]
    mov esi,r13d
    call fsq_finish
    test eax,eax
    jnz .fault
    add [rel fsg_tx_offset],r13d
    lea rdi,[rel gf_console]
    call gf_raise
.out:
    add rsp,8
    ret
.fault:
    add rsp,8
    jmp fsg_fault

; hvc1 TX: gather at most256B of reply, never log channel bytes as console.
gf_console_tx:
    sub rsp,8
    call fsg_current
    test eax,eax
    jz .fault
    lea rdi,[rel gf_console+GF_DEVICE.queues+FSQ_size]
    lea rsi,[rel gf_work]
    call fsq_prepare
    test eax,eax
    jz .out
    js .fault
    cmp dword [rel fsg_pending],1
    jne .fault
    cmp dword [rel fsg_tx_offset],256
    jne .fault
    mov r12d,[rel gf_work+FSQ_WORK.total]
    mov eax,256
    sub eax,[rel fsg_rx_offset]
    cmp r12d,eax
    ja .fault
    xor ebx,ebx
.flags:
    cmp ebx,[rel gf_work+FSQ_WORK.count]
    jae .copy_begin
    lea rax,[rel gf_work+FSQ_WORK.flags]
    test word [rax+rbx*2],2
    jnz .fault
    inc ebx
    jmp .flags
.copy_begin:
    xor ebx,ebx
    mov edi,[rel fsg_rx_offset]
    lea rax,[rel fsg_response]
    add rdi,rax
.copy:
    mov eax,ebx
    shl eax,4
    lea rdx,[rel gf_work+FSQ_WORK.span]
    mov rsi,[rdx+rax]
    mov rcx,[rdx+rax+8]
    cld
    rep movsb
    inc ebx
    cmp ebx,[rel gf_work+FSQ_WORK.count]
    jb .copy
    lea rdi,[rel gf_work]
    xor esi,esi                    ; device reads, no writable bytes
    call fsq_finish
    test eax,eax
    jnz .fault
    add [rel fsg_rx_offset],r12d
    lea rdi,[rel gf_console]
    call gf_raise
    cmp dword [rel fsg_rx_offset],256
    jne .out
    lea rdi,[rel fsg_response]
    lea rsi,[rel fsg_request]
    call fsc_wire_reply
    test eax,eax
    jnz .fault
    mov dword [rel fsg_pending],0
    mov dword [rel fsg_ready],1
    mov qword [rel fsg_frame_deadline],0
.out:
    add rsp,8
    ret
.fault:
    add rsp,8
    jmp fsg_fault

; One block request per exit, <=4096B. All backend buffers are private. An
; unknown/failed write is frozen once; guest retries never reach a backend.
gf_block_step:
    sub rsp,8
    call fsg_current
    test eax,eax
    jz .fault
    lea rdi,[rel gf_block+GF_DEVICE.queues]
    lea rsi,[rel gf_work]
    call fsq_prepare
    test eax,eax
    jz .out
    js .fault
    cmp qword [rel gf_work+FSQ_WORK.span+8],16
    jne .fault
    cmp word [rel gf_work+FSQ_WORK.flags],1
    jne .fault
    mov rsi,[rel gf_work+FSQ_WORK.span]
    lea rdi,[rel gf_header]
    mov ecx,2
    cld
    rep movsq
    cmp dword [rel gf_header+4],0
    jne .fault
    mov eax,[rel gf_header]
    mov [rel gf_opcode],eax
    cmp eax,4
    je .flush
    cmp eax,1
    ja .fault
    cmp dword [rel gf_work+FSQ_WORK.count],3
    jne .fault
    cmp word [rel gf_work+FSQ_WORK.flags+4],2
    jne .fault
    cmp qword [rel gf_work+FSQ_WORK.span+40],1
    jne .fault
    mov rax,[rel gf_work+FSQ_WORK.span+24]
    test rax,511
    jnz .fault
    test rax,rax
    jz .fault
    cmp rax,4096
    ja .fault
    mov [rel gf_bytes],eax
    cmp dword [rel gf_opcode],0
    je .read
    cmp word [rel gf_work+FSQ_WORK.flags+2],1
    jne .fault
    mov rsi,[rel gf_work+FSQ_WORK.span+16]
    lea rdi,[rel gf_bounce]
    mov ecx,[rel gf_bytes]
    rep movsb                       ; immutable snapshot before write admission
    call fsg_current
    test eax,eax
    jz .fault
    call gf_io_args
    call guest_volume_write
    jmp .backend_done
.read:
    cmp word [rel gf_work+FSQ_WORK.flags+2],3
    jne .fault
    call gf_io_args
    call guest_volume_read
    jmp .backend_done
.flush:
    test dword [rel gf_block+GF_DEVICE.low],1<<9
    jz .fault
    cmp qword [rel gf_header+8],0
    jne .fault
    cmp dword [rel gf_work+FSQ_WORK.count],2
    jne .fault
    cmp word [rel gf_work+FSQ_WORK.flags+2],2
    jne .fault
    cmp qword [rel gf_work+FSQ_WORK.span+24],1
    jne .fault
    mov dword [rel gf_bytes],0
    mov rdi,[rel fsg_handle]
    call guest_volume_flush
.backend_done:
    test rax,rax
    jnz .fault
    ; Clock and full owner after actual IO, before ANY guest write/index.
    call fsg_current
    test eax,eax
    jz .fault
    cmp dword [rel gf_opcode],0
    jne .status
    mov rdi,[rel gf_work+FSQ_WORK.span+16]
    lea rsi,[rel gf_bounce]
    mov ecx,[rel gf_bytes]
    cld
    rep movsb
.status:
    mov eax,[rel gf_work+FSQ_WORK.count]
    dec eax
    shl eax,4
    lea rdx,[rel gf_work+FSQ_WORK.span]
    mov rax,[rdx+rax]
    mov byte [rax],0                ; VIRTIO_BLK_S_OK only after actual callback
    mov esi,1
    cmp dword [rel gf_opcode],0
    jne .finish
    add esi,[rel gf_bytes]
.finish:
    lea rdi,[rel gf_work]
    call fsq_finish
    test eax,eax
    jnz .fault
    lea rdi,[rel gf_block]
    call gf_raise
    jmp .out
.fault:
    call fsg_fault
.out:
    lea rdi,[rel gf_bounce]
    mov ecx,4096/8
    xor eax,eax
    cld
    rep stosq
    add rsp,8
    ret

gf_io_args:
    mov rdi,[rel fsg_handle]
    mov rsi,[rel gf_header+8]
    mov edx,[rel gf_bytes]
    shr edx,9
    lea rcx,[rel gf_bounce]
    ret

guestfilesystem_pump:
    push rbx
    push r12
    push r13
    cmp dword [rel gf_console+GF_DEVICE.status],15
    jne .block
    call gf_console_rx
    call fsg_current
    test eax,eax
    jz .out
    call gf_console_tx
.block:
    call fsg_current
    test eax,eax
    jz .out
    cmp dword [rel gf_block+GF_DEVICE.status],15
    jne .out
    call gf_block_step
.out:
    pop r13
    pop r12
    pop rbx
    ret

guestfilesystem_irq:
    sub rsp,8
    call fsg_current
    test eax,eax
    jz .no
    mov eax,[rel gf_console+GF_DEVICE.isr]
    or eax,[rel gf_block+GF_DEVICE.isr]
    jz .no
    mov edi,5
    call hv_pic_try_inject
    jmp .out
.no:
    xor eax,eax
.out:
    add rsp,8
    ret

%include "core/abi/wdata.inc"
%macro WDATA_hv_guestfilesystem 0
align 16
gf_storage:
gf_console: times GF_DEVICE_size db 0
gf_block: times GF_DEVICE_size db 0
gf_work: times FSQ_WORK_size db 0
gf_header: times 16 db 0
gf_opcode: dd 0
gf_bytes: dd 0
align 16
gf_bounce: times 4096 db 0
gf_storage_end:
%endmacro
WDATA_DEFER WDATA_hv_guestfilesystem
