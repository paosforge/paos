;; MODULE hv/app_vm_devices
;; LAYER 5
;; EXPORTS app_vm_ingress_observe, avm_halted, app_vm_devices_init, app_vm_devices_pio, app_vm_devices_poll, avm_console, avm_console_bytes, avm_console_overflow
;; IMPORTS hv/app_runtime_observer, hv/app_account_transport, hv/app_widget_transport, hv/app_vm_cpu, hv/app_vm_payload, hv/app_vm, hv/guest_transport, hv/chat_transport, hv/app_network, hv/app_clock, hv/updater_io_transport, hv/settings_update_service, core/time
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
%include "hv/app_vm_cpu.inc"

; Private legacy PIC/PIT/UART/CMOS only. No PCI/MMIO/NIC/DMA/AP device and no
; physical IN/OUT instructions. Dedicated payload PIO exposes only exact bytes
; already copied/hashed from the actual signed native app object.
; Bundle ingress timing for the launch measurement, trusted out24: bundle bytes,
; first guest length read, last byte read (raw microseconds, 0 not reached).
; Read only; two port exits per byte make this part of click-to-first-WAIT.
app_vm_ingress_observe:
    cmp esi,24
    jne .bad
    test rdi,rdi
    jz .bad
    mov rax,[rel avm_payload_bytes]
    mov [rdi],rax
    mov rax,[rel avmd_ingress_begin_us]
    mov [rdi+8],rax
    mov rax,[rel avmd_ingress_end_us]
    mov [rdi+16],rax
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

app_vm_devices_init:
    sub rsp,8
    call updater_io_transport_retire
%ifdef APP_RUNTIME_OBSERVER_ABI_V1
    call app_runtime_observer_reset
%endif
    call app_network_retire
    add rsp,8
    lea rdi,[rel avmd_state_begin]
    xor eax,eax
    mov ecx,(avmd_state_end-avmd_state_begin)/8
    cld
    rep stosq
    mov byte [rel avmd_pic_mask],0xff
    mov byte [rel avmd_pic_mask+1],0xff
    mov byte [rel avmd_pic_base],0x20
    mov byte [rel avmd_pic_base+1],0x28
    mov byte [rel avmd_uart_lcr],3
    mov dword [rel avmd_pit_div],65536
    mov dword [rel avmd_pit_div+4],65536
    mov byte [rel avmd_pit_rw],3
    mov byte [rel avmd_pit_rw+1],3
    mov byte [rel avmd_pit_mode],3
    mov byte [rel avmd_pit_mode+1],3
    mov byte [rel avm_halted],0
    mov byte [rel avm_dispatch_fault],0
    ret

; Native periodic clock/PIC admission before each turn. Never consume IRQ0
; while another event is queued or guest IF/shadow blocks. ->1 runnable/0 idle.
app_vm_devices_poll:
    push rbx
    call time_monotonic_now_us
    cmp byte [rel avmd_pit_armed],0
    je .pending
    cmp rax,[rel avmd_pit_due]
    jb .pending
    mov byte [rel avmd_pic_pending],1
    cmp byte [rel avmd_pit_mode],0
    jne .periodic
    mov byte [rel avmd_pit_armed],0
    jmp .pending
.periodic:
    add rax,[rel avmd_pit_period]
    jc .clock_bad
    mov [rel avmd_pit_due],rax
.pending:
    cmp byte [rel avmd_pic_pending],1
    jne .runnable
    test byte [rel avmd_pic_mask],1
    jnz .runnable
    test byte [rel avmd_pic_isr],1
    jnz .runnable
    mov edi,0x4016
    call app_vm_field_read
    test eax,0x80000000
    jnz .runnable
    mov edi,0x6820
    call app_vm_field_read
    test eax,1<<9
    jz .runnable
    mov edi,0x4824
    call app_vm_field_read
    test eax,3
    jnz .runnable
    movzx esi,byte [rel avmd_pic_base]
    or esi,0x80000000
    mov edi,0x4016
    call app_vm_field_write
    cmp eax,1
    jne .clock_bad
    mov byte [rel avmd_pic_pending],0
    or byte [rel avmd_pic_isr],1
    mov byte [rel avm_halted],0
.runnable:
    xor eax,eax
    cmp byte [rel avm_halted],0
    sete al
    pop rbx
    ret
.clock_bad:
    mov byte [rel avm_dispatch_fault],1
    xor eax,eax
    pop rbx
    ret

; EDI actual normalized exit qualification, ESI actual guest EAX ->EAX1/0,
; EDX bounded IN result. Foreign driver/root cannot invoke payload ingress:
; app_vm_exit_endpoint proves a real closed app CPU exit, not wire metadata.
app_vm_devices_pio:
    push rbx
    push r12
    push r13
    mov ebx,edi
    mov r12d,esi
    call app_vm_exit_endpoint
    test rax,rax
    jz .exit_refused
    mov eax,ebx
    and eax,0xffff
    and eax,~0x4f                  ; size+IN+immediate only
    test eax,eax
    jnz .bad                       ; no string/REP/reserved qualification
    mov eax,ebx
    and eax,7
    cmp eax,0
    je .size_ok
    cmp eax,1
    je .size_ok
    cmp eax,3
    jne .bad
.size_ok:
    mov r13d,ebx
    shr r13d,16
    cmp r13d,0x50e0
    je .updater_service
    cmp r13d,0x50e4
    je .updater_service
    cmp r13d,0x50e8
    je .updater_io
    cmp r13d,0x50ec
    je .updater_io
%ifdef APP_RUNTIME_OBSERVER_ABI_V1
    cmp r13d,0x50d0
    je .runtime_observer
    cmp r13d,0x50d4
    je .runtime_observer
%endif
%ifdef APP_ACCOUNT_PRIVATE_ABI_V1
    cmp r13d,0x50c0
    je .account_private
    cmp r13d,0x50c4
    je .account_private
%endif
    cmp r13d,0x50b0
    je .clock
    cmp r13d,0x50b4
    je .clock
    cmp r13d,0x50b8
    je .clock
    cmp r13d,0x5090
    je .network
    cmp r13d,0x5094
    je .network
    cmp r13d,0x5070
    je .chat
    cmp r13d,0x5074
    je .chat
    cmp r13d,0x5078
    je .chat
    cmp r13d,0x5040
    je .transport
    cmp r13d,0x5044
    je .transport
    cmp r13d,0x5060
    je .snapshot
    cmp r13d,0x5064
    je .snapshot
    cmp r13d,0x5068
    je .widget
    cmp r13d,0x506c
    je .widget
    cmp r13d,0x5050
    je .offset
    cmp r13d,0x5054
    je .payload_byte
    cmp r13d,0x5058
    je .payload_len
    ; Every legacy private device uses scalar byte I/O.
    test ebx,7
    jnz .pci
    cmp r13d,0x20
    je .pic_command0
    cmp r13d,0xa0
    je .pic_command1
    cmp r13d,0x21
    je .pic_data0
    cmp r13d,0xa1
    je .pic_data1
    cmp r13d,0x43
    je .pit_control
    cmp r13d,0x40
    je .pit0
    cmp r13d,0x42
    je .pit2
    cmp r13d,0x61
    je .speaker
    cmp r13d,0x70
    je .cmos_index
    cmp r13d,0x71
    je .cmos_data
    cmp r13d,0x80
    je .zero
    cmp r13d,0x92
    je .a20
    cmp r13d,0x3f8
    jb .pci
    cmp r13d,0x3ff
    jbe .uart
.pci:
    ; No physical config access. Width-correct all-ones means absent device.
    cmp r13d,0xcf8
    jb .unknown
    cmp r13d,0xcff
    ja .unknown
    mov edx,-1
    jmp .ok
.unknown:
    ; Firmware legacy probes see absent bytes; writes cannot escape to host.
    mov edx,0xff
    jmp .ok
.exit_refused:
    mov eax,ebx
    shr eax,16
    cmp eax,0x50e8
    je .retire_io
    cmp eax,0x50ec
    jne .bad
.retire_io:
    call updater_io_transport_retire
    jmp .bad
.updater_service:
    mov edi,ebx
    mov esi,r12d
    call settings_update_service_pio
    cmp eax,1
    jne .bad
    jmp .ok
.updater_io:
    mov edi,ebx
    mov esi,r12d
    call updater_io_transport_pio
    cmp eax,1
    jne .bad
    jmp .ok
%ifdef APP_RUNTIME_OBSERVER_ABI_V1
.runtime_observer:
    mov edi,ebx
    mov esi,r12d
    call app_runtime_observer_pio
    cmp eax,1
    jne .bad
    jmp .ok
%endif
%ifdef APP_ACCOUNT_PRIVATE_ABI_V1
.account_private:
    mov edi,ebx
    mov esi,r12d
    call app_account_private_pio
    cmp eax,1
    jne .bad
    jmp .ok
%endif
.clock:
    mov edi,ebx
    mov esi,r12d
    call app_clock_pio
    cmp eax,1
    jne .bad
    jmp .ok
.network:
    mov edi,ebx
    mov esi,r12d
    call app_network_pio
    cmp eax,1
    jne .bad
    jmp .ok
.chat:
    mov edi,ebx
    mov esi,r12d
    call chat_vm_pio
    cmp eax,1
    jne .bad
    jmp .ok
.transport:
    mov edi,ebx
    mov esi,r12d
    call guest_transport_app_pio
    cmp eax,1
    jne .bad
    jmp .ok
.snapshot:
    mov edi,ebx
    mov esi,r12d
    call snapshot_app_pio
    cmp eax,1
    jne .bad
    jmp .ok
.widget:
    mov edi,ebx
    mov esi,r12d
    call app_widget_app_pio
    cmp eax,1
    jne .bad
    jmp .ok
.offset:
    mov eax,ebx
    and eax,0xffbf
    cmp eax,3                      ; exact OUT32 only
    jne .bad
    mov eax,r12d
    cmp rax,[rel avm_payload_bytes]
    ja .bad
    mov [rel avmd_payload_cursor],rax
    xor edx,edx
    jmp .ok
.payload_byte:
    mov eax,ebx
    and eax,0xffbf
    cmp eax,8                      ; exact IN8 only
    jne .bad
    mov rcx,[rel avmd_payload_cursor]
    cmp rcx,[rel avm_payload_bytes]
    jae .bad
    mov rax,[rel avm_base]
    movzx edx,byte [rax+rcx+AVM_PAYLOAD]
    inc rcx
    mov [rel avmd_payload_cursor],rcx
    cmp rcx,[rel avm_payload_bytes]
    jne .ok
    cmp qword [rel avmd_ingress_end_us],0
    jne .ok
    mov r12d,edx
    call time_monotonic_now_us
    mov [rel avmd_ingress_end_us],rax    ; the last byte of the bundle left native
    mov edx,r12d
    jmp .ok
.payload_len:
    mov eax,ebx
    and eax,0xffbf
    cmp eax,11                     ; exact IN32 only
    jne .bad
    cmp qword [rel avmd_ingress_begin_us],0
    jne .payload_len_value
    call time_monotonic_now_us
    mov [rel avmd_ingress_begin_us],rax  ; the guest first asked for the bundle
.payload_len_value:
    mov edx,[rel avm_payload_bytes]
    jmp .ok
.pic_command0:
    xor ecx,ecx
    jmp .pic_command
.pic_command1:
    mov ecx,1
.pic_command:
    test ebx,8
    jnz .pic_read
    test r12b,0x10
    jnz .pic_init
    test r12b,0x20
    jnz .pic_eoi
    mov eax,r12d
    and eax,0x18
    cmp eax,8
    jne .zero
    lea rax,[rel avmd_pic_read_isr]
    mov edx,r12d
    and edx,1
    mov [rax+rcx],dl
    jmp .zero
.pic_init:
    lea rax,[rel avmd_pic_phase]
    mov byte [rax+rcx],1
    lea rax,[rel avmd_pic_isr]
    mov byte [rax+rcx],0
    jmp .zero
.pic_eoi:
    lea rax,[rel avmd_pic_isr]
    mov byte [rax+rcx],0
    jmp .zero
.pic_read:
    lea rax,[rel avmd_pic_read_isr]
    cmp byte [rax+rcx],0
    je .pic_irr
    lea rax,[rel avmd_pic_isr]
    movzx edx,byte [rax+rcx]
    jmp .ok
.pic_irr:
    xor edx,edx
    test ecx,ecx
    jnz .ok
    movzx edx,byte [rel avmd_pic_pending]
    jmp .ok
.pic_data0:
    xor ecx,ecx
    jmp .pic_data
.pic_data1:
    mov ecx,1
.pic_data:
    lea rax,[rel avmd_pic_mask]
    test ebx,8
    jz .pic_data_write
    movzx edx,byte [rax+rcx]
    jmp .ok
.pic_data_write:
    lea rdx,[rel avmd_pic_phase]
    movzx esi,byte [rdx+rcx]
    test esi,esi
    jz .pic_mask
    cmp esi,1
    jne .pic_next
    lea rax,[rel avmd_pic_base]
    mov r8d,r12d
    and r8d,0xf8
    mov [rax+rcx],r8b
.pic_next:
    inc byte [rdx+rcx]
    cmp byte [rdx+rcx],4
    jb .zero
    mov byte [rdx+rcx],0
    jmp .zero
.pic_mask:
    mov [rax+rcx],r12b
    jmp .zero
.pit_control:
    test ebx,8
    jnz .zero
    mov eax,r12d
    shr eax,6
    cmp eax,3
    je .zero                       ; read-back command: no mutation
    cmp eax,1
    je .zero                       ; no channel1 device
    shr eax,1                      ; channel0->0 channel2->1
    mov ecx,eax
    mov edx,r12d
    shr edx,4
    and edx,3
    jz .pit_latch
    lea rax,[rel avmd_pit_rw]
    mov [rax+rcx],dl
    lea rax,[rel avmd_pit_write_phase]
    mov byte [rax+rcx],0
    lea rax,[rel avmd_pit_mode]
    mov edx,r12d
    shr edx,1
    and edx,7
    cmp edx,6
    jb .mode
    sub edx,4
.mode:
    mov [rax+rcx],dl
    jmp .zero
.pit_latch:
    push rcx
    call avmd_pit_counter
    pop rcx
    lea rax,[rel avmd_pit_latch]
    mov [rax+rcx*2],dx
    lea rax,[rel avmd_pit_latched]
    mov byte [rax+rcx],1
    lea rax,[rel avmd_pit_read_phase]
    mov byte [rax+rcx],0
    jmp .zero
.pit0:
    xor ecx,ecx
    jmp .pit_data
.pit2:
    mov ecx,1
.pit_data:
    test ebx,8
    jnz .pit_read
    lea rax,[rel avmd_pit_rw]
    cmp byte [rax+rcx],3
    jne .pit_single
    lea rax,[rel avmd_pit_write_phase]
    cmp byte [rax+rcx],0
    jne .pit_high
    mov byte [rax+rcx],1
    lea rax,[rel avmd_pit_load]
    mov [rax+rcx*2],r12b
    jmp .zero
.pit_high:
    mov byte [rax+rcx],0
    lea rax,[rel avmd_pit_load]
    mov [rax+rcx*2+1],r12b
    movzx edx,word [rax+rcx*2]
    jmp .pit_arm
.pit_single:
    mov edx,r12d
    and edx,0xff
    cmp byte [rax+rcx],2
    jne .pit_arm
    shl edx,8
.pit_arm:
    test edx,edx
    jnz .nonzero
    mov edx,65536
.nonzero:
    lea rax,[rel avmd_pit_div]
    mov [rax+rcx*4],edx
    push rcx
    push rdx
    call time_monotonic_now_us
    pop rdx
    pop rcx
    lea r8,[rel avmd_pit_start]
    mov [r8+rcx*8],rax
    test ecx,ecx
    jnz .zero
    mov r8,rax
    mov eax,edx
    imul rax,rax,1000000
    add rax,1193181
    xor edx,edx
    mov esi,1193182
    div rsi
    mov [rel avmd_pit_period],rax
    add rax,r8
    jc .bad
    mov [rel avmd_pit_due],rax
    mov byte [rel avmd_pit_armed],1
    jmp .zero
.pit_read:
    lea rax,[rel avmd_pit_latched]
    cmp byte [rax+rcx],1
    jne .pit_unlatched
    lea rax,[rel avmd_pit_latch]
    movzx edx,word [rax+rcx*2]
    jmp .pit_read_value
.pit_unlatched:
    push rcx
    call avmd_pit_counter
    pop rcx
.pit_read_value:
    lea rax,[rel avmd_pit_read_phase]
    cmp byte [rax+rcx],0
    jne .pit_read_high
    mov byte [rax+rcx],1
    and edx,0xff
    jmp .ok
.pit_read_high:
    mov byte [rax+rcx],0
    lea rax,[rel avmd_pit_latched]
    mov byte [rax+rcx],0
    shr edx,8
    and edx,0xff
    jmp .ok
.speaker:
    test ebx,8
    jnz .speaker_read
    mov [rel avmd_speaker],r12b
    jmp .zero
.speaker_read:
    mov ecx,1
    call avmd_pit_counter
    test edx,edx
    movzx edx,byte [rel avmd_speaker]
    jnz .speaker_low
    or edx,0x20
.speaker_low:
    xor byte [rel avmd_refresh],0x10
    or dl,[rel avmd_refresh]
    jmp .ok
.cmos_index:
    test ebx,8
    jnz .zero
    and r12d,0x7f
    mov [rel avmd_cmos],r12b
    jmp .zero
.cmos_data:
    test ebx,8
    jz .zero
    movzx eax,byte [rel avmd_cmos]
    lea rcx,[rel avmd_cmos_image]
    movzx edx,byte [rcx+rax]
    jmp .ok
.uart:
    sub r13d,0x3f8
    test ebx,8
    jnz .uart_read
    cmp r13d,3
    je .uart_lcr
    test r13d,r13d
    jnz .zero
    test byte [rel avmd_uart_lcr],0x80
    jnz .zero                      ; divisor, not output
    mov eax,[rel avm_console_bytes]
    cmp eax,8192
    jae .uart_overflow
    lea rdx,[rel avm_console]
    mov [rdx+rax],r12b
    inc dword [rel avm_console_bytes]
    jmp .zero
.uart_overflow:
    mov byte [rel avm_console_overflow],1
    jmp .zero
.uart_lcr:
    mov [rel avmd_uart_lcr],r12b
    jmp .zero
.uart_read:
    cmp r13d,5
    je .uart_ready
    cmp r13d,2
    je .uart_noirq
    cmp r13d,3
    jne .zero
    movzx edx,byte [rel avmd_uart_lcr]
    jmp .ok
.uart_ready:
    mov edx,0x60
    jmp .ok
.uart_noirq:
    mov edx,1
    jmp .ok
.a20:
    mov edx,2
    jmp .ok
.zero:
    xor edx,edx
.ok:
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
    xor edx,edx
.out:
    pop r13
    pop r12
    pop rbx
    ret

; ECX private channel0/2 index ->EDX current count. Actual native monotonic
; time, bounded arithmetic; no host PIT reads or shared driver timer mutation.
avmd_pit_counter:
    push rbx
    mov ebx,ecx
    call time_monotonic_now_us
    lea rcx,[rel avmd_pit_start]
    sub rax,[rcx+rbx*8]
    jc .zero
    cmp rax,1000000000             ; >1000s needs only a bounded wrap result
    jbe .elapsed
    xor edx,edx
    mov ecx,1000000000
    div rcx
    mov rax,rdx
.elapsed:
    imul rax,rax,1193182
    xor edx,edx
    mov ecx,1000000
    div rcx
    lea rcx,[rel avmd_pit_div]
    mov ecx,[rcx+rbx*4]
    test ecx,ecx
    jz .zero
    lea r8,[rel avmd_pit_mode]
    cmp byte [r8+rbx],0
    jne .periodic
    cmp rax,rcx
    jae .zero
    sub rcx,rax
    mov edx,ecx
    jmp .out
.periodic:
    xor edx,edx
    div rcx
    sub ecx,edx
    mov edx,ecx
    jmp .out
.zero:
    xor edx,edx
.out:
    pop rbx
    ret

avmd_cmos_image:
    db 0,0,0,0,0,0,5,0x30,0x10,0x26,0x26,2,0,0x80
    times 128-14 db 0
%include "core/abi/wdata.inc"
%macro WDATA_hv_app_vm_devices 0
align 8
avmd_state_begin:
avmd_payload_cursor: dq 0
avmd_ingress_begin_us: dq 0
avmd_ingress_end_us: dq 0
avmd_pit_start: times 2 dq 0
avmd_pit_due: dq 0
avmd_pit_period: dq 0
avmd_pit_div: times 2 dd 0
avmd_pit_load: times 2 dw 0
avmd_pit_latch: times 2 dw 0
avmd_pit_mode: times 2 db 0
avmd_pit_rw: times 2 db 0
avmd_pit_write_phase: times 2 db 0
avmd_pit_read_phase: times 2 db 0
avmd_pit_latched: times 2 db 0
avmd_pit_armed: db 0
avmd_speaker: db 0
avmd_refresh: db 0
avmd_pic_mask: times 2 db 0
avmd_pic_base: times 2 db 0
avmd_pic_phase: times 2 db 0
avmd_pic_isr: times 2 db 0
avmd_pic_read_isr: times 2 db 0
avmd_pic_pending: db 0
avmd_uart_lcr: db 0
avmd_cmos: db 0
avm_console_bytes: dd 0
avm_console_overflow: db 0
avm_console: times 8192 db 0
align 8
avmd_state_end:
%endmacro
WDATA_DEFER WDATA_hv_app_vm_devices

; Device reset cannot clear a retained updater IO lifetime or uncertainty.
%include "hv/updater_io_transport.asm"
