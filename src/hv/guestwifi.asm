;; MODULE hv/guestwifi
;; LAYER 5
;; EXPORTS guestwifi_reset, guestwifi_zero, guestwifi_mmio_write, guestwifi_pump, guestwifi_irq, guestwifi_config_capture, guestwifi_config_current
;; IMPORTS hv/wifi_channel, hv/filesystem_queue, hv/vmx
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; A distinct private modern virtio-console, GPA D0008000 / IRQ5 / hvc1.
; Never uses public console queues/capture/logging, PIN, or F11 authority.
; FSQ bounds every direct chain; private READY/ACK64 and request256 only.
GW_PAGE equ 0x8a000
%if GW_PAGE < VST_END || GW_PAGE+4096 > 0x90000
 %error "WiFi private backing overlaps control or NIC pool"
%endif
struc GW_DEVICE
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

guestwifi_zero:
    lea rdi,[rel gw_storage]
    mov ecx,gw_storage_end-gw_storage
    xor eax,eax
    cld
    rep stosb
    ret

guestwifi_reset:
    sub rsp,8
    call guestwifi_zero
    cmp qword [rel hv_linux_region_capacity],GW_PAGE+4096
    jb .bad
    mov rax,[rel hv_linux_region]
    test rax,rax
    jz .bad
    add rax,GW_PAGE
    jc .bad
    mov [rel gw_device+GW_DEVICE.page],rax
    mov rdi,rax
    mov ecx,4096/8
    xor eax,eax
    cld
    rep stosq
    mov rax,[rel gw_device+GW_DEVICE.page]
    mov dword [rax],0x74726976
    mov dword [rax+4],2
    mov dword [rax+8],3
    mov dword [rax+12],0x50614f53
    mov dword [rax+0x34],FSQ_MAX
    mov dword [rel gw_device+GW_DEVICE.nqueues],2
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    add rsp,8
    ret

; READY freezes the two queue configurations. Used indices may advance, but
; queue addresses/extent/readiness cannot be substituted under a native offer.
guestwifi_config_capture:
    lea rsi,[rel gw_device+GW_DEVICE.queues]
    lea rdi,[rel gw_config]
    mov ecx,4
    cld
    rep movsq
    add rsi,FSQ_size-32
    mov ecx,4
    rep movsq
    ret

guestwifi_config_current:
    cmp dword [rel gw_device+GW_DEVICE.status],15
    jne .bad
    lea rdi,[rel gw_config]
    lea rsi,[rel gw_device+GW_DEVICE.queues]
    mov ecx,4
    cld
    repe cmpsq
    jne .bad
    add rsi,FSQ_size-32
    mov ecx,4
    repe cmpsq
    jne .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

guestwifi_mmio_write:
    push rbx
    push rbp
    push r12
    push r13
    sub rsp,8
    mov r12d,edi
    mov r13d,esi
    call wfc_current
    test eax,eax
    jz .fault
    lea rbx,[rel gw_device]
    cmp r12d,4096
    jae .fault
    mov rbp,[rbx+GW_DEVICE.page]
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
    mov eax,[rbx+GW_DEVICE.qsel]
    cmp eax,[rbx+GW_DEVICE.nqueues]
    jae .out
    imul eax,FSQ_size
    lea rdx,[rbx+GW_DEVICE.queues+rax]
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
    mov [rbx+GW_DEVICE.qsel],r13d
    xor eax,eax
    xor ecx,ecx
    cmp r13d,[rbx+GW_DEVICE.nqueues]
    jae .selected
    imul eax,r13d,FSQ_size
    mov ecx,[rbx+GW_DEVICE.queues+rax+FSQ.ready]
    mov eax,FSQ_MAX
.selected:
    mov [rbp+0x34],eax
    mov [rbp+0x44],ecx
    jmp .out
.fsel:
    mov [rbx+GW_DEVICE.fsel],r13d
    xor eax,eax
    cmp r13d,1
    jne .low_features
    mov eax,1                     ; VERSION_1 required
    jmp .feature_page
.low_features:
    test r13d,r13d
    jnz .feature_page
.feature_page:
    mov [rbp+0x10],eax
    jmp .out
.dfsel:
    mov [rbx+GW_DEVICE.dfsel],r13d
    jmp .out
.features:
    test dword [rbx+GW_DEVICE.status],8
    jnz .fault
    cmp dword [rbx+GW_DEVICE.dfsel],0
    je .low
    cmp dword [rbx+GW_DEVICE.dfsel],1
    jne .out
    mov [rbx+GW_DEVICE.high],r13d
    jmp .out
.low:
    mov [rbx+GW_DEVICE.low],r13d
    jmp .out
.status:
    test r13d,r13d
    jnz .nonzero_status
    cmp dword [rbx+GW_DEVICE.status],0
    jne .fault
    jmp .out
.nonzero_status:
    test r13d,~15
    jnz .fault
    mov eax,[rbx+GW_DEVICE.status]
    and eax,r13d
    cmp eax,[rbx+GW_DEVICE.status]
    jne .fault
    test r13d,8
    jz .status_store
    cmp dword [rbx+GW_DEVICE.high],1
    jne .fault
    mov eax,[rbx+GW_DEVICE.low]
    test eax,eax
    jnz .fault
.status_store:
    mov [rbx+GW_DEVICE.status],r13d
    mov [rbp+0x70],r13d
    jmp .out
.ack:
    mov eax,r13d
    not eax
    and [rbx+GW_DEVICE.isr],eax
    mov eax,[rbx+GW_DEVICE.isr]
    mov [rbp+0x60],eax
    jmp .out
.fault:
    call gw_fault
.out:
    add rsp,8
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret


gw_raise:
    or dword [rel gw_device+GW_DEVICE.isr],1
    mov rax,[rel gw_device+GW_DEVICE.page]
    mov dword [rax+0x60],1
    ret

gw_fault:
    cmp dword [rel wfc_state],3
    jae .cancel
    mov dword [rel wfc_state],3
.cancel:
    jmp wfc_cancel

; Guest RX: only the one native request. No copies until actual READY,
; opaque-intent admission and final native wfc_submit have all succeeded.
gw_rx:
    sub rsp,8
    cmp dword [rel wfc_state],4
    jne .out
    cmp dword [rel wfc_tx_offset],256
    jae .out
    call wfc_current
    test eax,eax
    jz .fault
    lea rdi,[rel gw_device+GW_DEVICE.queues]
    lea rsi,[rel gw_work]
    call fsq_prepare
    test eax,eax
    jz .out
    js .fault
    xor ebx,ebx
.flags:
    cmp ebx,[rel gw_work+FSQ_WORK.count]
    jae .begin
    lea rax,[rel gw_work+FSQ_WORK.flags]
    test word [rax+rbx*2],2
    jz .fault
    inc ebx
    jmp .flags
.begin:
    call wfc_current
    test eax,eax
    jz .fault
    mov r12d,256
    sub r12d,[rel wfc_tx_offset]
    cmp r12d,[rel gw_work+FSQ_WORK.total]
    jbe .bounded
    mov r12d,[rel gw_work+FSQ_WORK.total]
.bounded:
    mov r13d,r12d
    mov esi,[rel wfc_tx_offset]
    lea rax,[rel wfc_request]
    add rsi,rax
    xor ebx,ebx
.copy:
    mov eax,ebx
    shl eax,4
    lea rdx,[rel gw_work+FSQ_WORK.span]
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
    call wfc_current
    test eax,eax
    jz .fault
    lea rdi,[rel gw_work]
    mov esi,r13d
    call fsq_finish
    test eax,eax
    jnz .fault
    add [rel wfc_tx_offset],r13d
    cmp dword [rel wfc_tx_offset],256
    jne .raise
    ; ACK matching needs only identity/id/revision. Drop native SSID/PSK now.
    lea rdi,[rel wfc_request+104]
    mov ecx,64/8
    xor eax,eax
    rep stosq
.raise:
    call gw_raise
.out:
    add rsp,8
    ret
.fault:
    call gw_fault
    jmp .out

; Guest TX: exactly READY64 before a local grant, or ACK64 after all request
; bytes have been published. Private bytes never enter hv_vcon capture.
gw_tx:
    sub rsp,8
    cmp dword [rel wfc_state],1
    je .phase
    cmp dword [rel wfc_state],4
    jne .out
    cmp dword [rel wfc_tx_offset],256
    jne .out
.phase:
    call wfc_current
    test eax,eax
    jz .fault
    lea rdi,[rel gw_device+GW_DEVICE.queues+FSQ_size]
    lea rsi,[rel gw_work]
    call fsq_prepare
    test eax,eax
    jz .out
    js .fault
    mov r12d,[rel gw_work+FSQ_WORK.total]
    mov eax,64
    sub eax,[rel gw_rx_offset]
    cmp r12d,eax
    ja .fault
    xor ebx,ebx
.flags:
    cmp ebx,[rel gw_work+FSQ_WORK.count]
    jae .copy_begin
    lea rax,[rel gw_work+FSQ_WORK.flags]
    test word [rax+rbx*2],2
    jnz .fault
    inc ebx
    jmp .flags
.copy_begin:
    xor ebx,ebx
    mov edi,[rel gw_rx_offset]
    lea rax,[rel gw_frame]
    add rdi,rax
.copy:
    mov eax,ebx
    shl eax,4
    lea rdx,[rel gw_work+FSQ_WORK.span]
    mov rsi,[rdx+rax]
    mov rcx,[rdx+rax+8]
    cld
    rep movsb
    inc ebx
    cmp ebx,[rel gw_work+FSQ_WORK.count]
    jb .copy
    call wfc_current
    test eax,eax
    jz .fault
    lea rdi,[rel gw_work]
    xor esi,esi
    call fsq_finish
    test eax,eax
    jnz .fault
    add [rel gw_rx_offset],r12d
    call gw_raise
    cmp dword [rel gw_rx_offset],64
    jne .out
    lea rdi,[rel gw_frame]
    cmp dword [rel wfc_state],1
    jne .reply
    call wfc_ready
    jmp .checked
.reply:
    call wfc_reply
.checked:
    test eax,eax
    jnz .fault
    mov dword [rel gw_rx_offset],0
    lea rdi,[rel gw_frame]
    mov ecx,8
    xor eax,eax
    rep stosq
.out:
    add rsp,8
    ret
.fault:
    call gw_fault
    jmp .out

guestwifi_pump:
    push rbx
    push r12
    push r13
    cmp dword [rel gw_device+GW_DEVICE.status],15
    jne .out
    call gw_tx
    call gw_rx
.out:
    pop r13
    pop r12
    pop rbx
    ret

guestwifi_irq:
    sub rsp,8
    cmp dword [rel wfc_state],1
    jb .no
    cmp dword [rel wfc_state],5
    ja .no
    call wfc_current
    test eax,eax
    jz .no
    cmp dword [rel gw_device+GW_DEVICE.isr],0
    je .no
    mov edi,5
    call hv_pic_try_inject
    jmp .out
.no:
    xor eax,eax
.out:
    add rsp,8
    ret

%include "core/abi/wdata.inc"
%macro WDATA_hv_guestwifi 0
align 16
gw_storage:
gw_device: times GW_DEVICE_size db 0
gw_config: times 64 db 0
gw_work: times FSQ_WORK_size db 0
gw_rx_offset: dd 0
gw_frame: times 64 db 0
gw_storage_end:
%endmacro
WDATA_DEFER WDATA_hv_guestwifi
