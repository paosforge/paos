;; MODULE hv/tools_vm_devices
;; LAYER 5
;; EXPORTS tools_vm_devices_reset, tools_vm_devices_turn, tools_vm_exit_endpoint, tools_vm_endpoint, tvm_console, tvm_console_bytes, tvm_console_overflow, tvmd_guest_ended
;; IMPORTS hv/tools_vm_memory, hv/tools_vm_cpu, hv/tools_vm_stream, hv/tools_vm_mmio, hv/tools_vm_console, hv/vcpu_ap_xstate, core/time
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Creator: Claude / rc-vm-claude. Tools closed-exit dispatch and private legacy
; PIC/PIT/CMOS/diagnostic-UART devices, statically bound to tools storage.
; Shared source with the app (hv/app_vm_devices, hv/app_vm_dispatch); none of
; the app's PIO services (payload, updater, observer, account, clock, network,
; chat, transport, snapshot, widget) is assembled here. Every other port reads
; absent and writes are dropped; string/REP or reserved forms are a terminal
; fault. No PCI/NIC/DMA device, no physical IN/OUT, no host MSR access.
; The AV hostname stream ports reach only hv/tools_vm_stream; the one trapped
; register window (reason 48) reaches only hv/tools_vm_mmio, whose device is
; hv/tools_vm_console on private PIC line 5. No lifecycle/admission state
; change, Terminal route or entropy here. The serial
; bytes are diagnostic only: never commands or proof.
%include "hv/tools_vm.inc"
%include "hv/app_vm_cpu.inc"

; Aliases only around the shared code; deferred storage below uses literal
; tvm names (deferring alias-dependent data would corrupt the app instance).
%define PAOS_TOOLS_DEVICES_INSTANCE 1
%define app_vm_cpu_stop tools_vm_cpu_stop
%define app_vm_cpuid_query tools_vm_cpuid_query
%define app_vm_devices_init tvm_devices_init_bound
%define app_vm_devices_pio tvm_devices_pio_bound
%define app_vm_devices_poll tvm_devices_poll_bound
%define app_vm_dispatch tvm_dispatch_bound
%define app_vm_exit_endpoint tools_vm_exit_endpoint
%define app_vm_field_read tools_vm_field_read
%define app_vm_field_write tools_vm_field_write
%define avm_arch tvm_arch
%define avm_base tvm_base
%define avm_console tvm_console
%define avm_console_bytes tvm_console_bytes
%define avm_console_overflow tvm_console_overflow
%define avm_cpu_live tvm_cpu_live
%define avm_debug tvm_debug
%define avm_dispatch_fault tvm_dispatch_fault
%define avm_exit tvm_exit
%define avm_gpr tvm_gpr
%define avm_guest_aux tvm_guest_aux
%define avm_halted tvm_halted
%define avm_roots_retired tvm_roots_retired
%define avm_svm tvm_svm
%define avm_xstate tvm_xstate
%define avmd_cmos tvmd_cmos
%define avmd_cmos_image tvmd_cmos_image
%define avmd_gpr_map tvmd_gpr_map
%define avmd_guest_ended tvmd_guest_ended
%define avmd_msr_ids tvmd_msr_ids
%define avmd_msr_read tvmd_msr_read
%define avmd_msr_slot tvmd_msr_slot
%define avmd_msr_write tvmd_msr_write
%define avmd_pic_base tvmd_pic_base
%define avmd_pic_irr tvmd_pic_irr
%define avmd_pic_isr tvmd_pic_isr
%define avmd_pic_mask tvmd_pic_mask
%define avmd_pic_pending tvmd_pic_pending
%define avmd_pic_phase tvmd_pic_phase
%define avmd_pic_read_isr tvmd_pic_read_isr
%define avmd_pit_armed tvmd_pit_armed
%define avmd_pit_counter tvmd_pit_counter
%define avmd_pit_div tvmd_pit_div
%define avmd_pit_due tvmd_pit_due
%define avmd_pit_latch tvmd_pit_latch
%define avmd_pit_latched tvmd_pit_latched
%define avmd_pit_load tvmd_pit_load
%define avmd_pit_mode tvmd_pit_mode
%define avmd_pit_period tvmd_pit_period
%define avmd_pit_read_phase tvmd_pit_read_phase
%define avmd_pit_rw tvmd_pit_rw
%define avmd_pit_start tvmd_pit_start
%define avmd_pit_write_phase tvmd_pit_write_phase
%define avmd_refresh tvmd_refresh
%define avmd_speaker tvmd_speaker
%define avmd_state_begin tvmd_state_begin
%define avmd_state_end tvmd_state_end
%define avmd_uart_dll tvmd_uart_dll
%define avmd_uart_dlm tvmd_uart_dlm
%define avmd_uart_ier tvmd_uart_ier
%define avmd_uart_lcr tvmd_uart_lcr
%define avmd_uart_mcr tvmd_uart_mcr
%define avmd_uart_scr tvmd_uart_scr
%define avmd_uart_thre tvmd_uart_thre
%define avmd_vio_isr tvmc_isr
%define avmi_cr4_fixed tvmi_cr4_fixed

%include "hv/app_vm_devices.asm"
%include "hv/app_vm_dispatch.asm"

%undef app_vm_cpu_stop
%undef app_vm_cpuid_query
%undef app_vm_devices_init
%undef app_vm_devices_pio
%undef app_vm_devices_poll
%undef app_vm_dispatch
%undef app_vm_exit_endpoint
%undef app_vm_field_read
%undef app_vm_field_write
%undef avm_arch
%undef avm_base
%undef avm_console
%undef avm_console_bytes
%undef avm_console_overflow
%undef avm_cpu_live
%undef avm_debug
%undef avm_dispatch_fault
%undef avm_exit
%undef avm_gpr
%undef avm_guest_aux
%undef avm_halted
%undef avm_roots_retired
%undef avm_svm
%undef avm_xstate
%undef avmd_cmos
%undef avmd_cmos_image
%undef avmd_gpr_map
%undef avmd_guest_ended
%undef avmd_msr_ids
%undef avmd_msr_read
%undef avmd_msr_slot
%undef avmd_msr_write
%undef avmd_pic_base
%undef avmd_pic_irr
%undef avmd_pic_isr
%undef avmd_pic_mask
%undef avmd_pic_pending
%undef avmd_pic_phase
%undef avmd_pic_read_isr
%undef avmd_pit_armed
%undef avmd_pit_counter
%undef avmd_pit_div
%undef avmd_pit_due
%undef avmd_pit_latch
%undef avmd_pit_latched
%undef avmd_pit_load
%undef avmd_pit_mode
%undef avmd_pit_period
%undef avmd_pit_read_phase
%undef avmd_pit_rw
%undef avmd_pit_start
%undef avmd_pit_write_phase
%undef avmd_refresh
%undef avmd_speaker
%undef avmd_state_begin
%undef avmd_state_end
%undef avmd_uart_dll
%undef avmd_uart_dlm
%undef avmd_uart_ier
%undef avmd_uart_lcr
%undef avmd_uart_mcr
%undef avmd_uart_scr
%undef avmd_uart_thre
%undef avmd_vio_isr
%undef avmi_cr4_fixed
%undef PAOS_TOOLS_DEVICES_INSTANCE

; Only while the actual tools exit is closed and its native turn owns it, with
; the original allocation still held and CPU/root custody retired. A stopped or
; READY instance, an app/driver exit, a host caller or guest assertion gets 0.
; ->RAX tools_vm_endpoint, EDX original START; or 0/0. Preserves RDI/RSI.
tools_vm_exit_endpoint:
    cmp byte [rel tvm_exit_open],1
    jne .bad
    cmp qword [rel tvm_state],TVM_RUNNING
    jne .bad
    push rdi
    push rsi
    sub rsp,8
    mov rdi,[rel tvm_start]
    mov rsi,[rel tvm_token]
    call tvm_memory_stopped
    add rsp,8
    pop rsi
    pop rdi
    test eax,eax
    jz .bad
    lea rax,[rel tools_vm_endpoint]
    mov edx,[rel tvm_start]
    ret
.bad:
    xor eax,eax
    xor edx,edx
    ret

; RDI original START, RSI token ->1 private devices reset /0 unchanged. Only
; with CPU/root custody retired; the later lifecycle calls it before READY.
tools_vm_devices_reset:
    sub rsp,8
    call tvm_memory_stopped
    test eax,eax
    jz .bad
    cmp byte [rel tvm_exit_open],0
    jne .bad
    call tvm_devices_init_bound
    call tools_vm_mmio_reset
    call tools_vm_console_reset
    add rsp,8
    mov eax,1
    ret
.bad:
    add rsp,8
    xor eax,eax
    ret

; RDI original START, RSI token. One bounded native turn: private PIT/PIC
; admission, then at most one closed CPU turn (IF0, caller flags preserved),
; then that exit's dispatch with the exit endpoint open only for it.
; ->1 turned and dispatched /2 idle (nothing runnable) /0 refused or terminal
; fault. Refusal never retires, frees or scrubs: lifecycle owns retirement.
tools_vm_devices_turn:
    push rbx
    push r12
    push r13
    mov r12,rdi
    mov r13,rsi
    mov byte [rel tvm_exit_open],0
    call tvm_memory_stopped
    test eax,eax
    jz .bad
    cmp qword [rel tvm_state],TVM_RUNNING
    jne .bad
    cmp byte [rel tvm_dispatch_fault],0
    jne .bad
    mov rdi,r12
    mov rsi,r13
    call tools_vm_console_pump       ; CPU stopped: RX input and held-back TX
    call tvm_devices_poll_bound
    cmp byte [rel tvm_dispatch_fault],0
    jne .bad
    test eax,eax
    jz .idle
    pushfq
    pop rbx
    cli
    mov rdi,r12
    mov rsi,r13
    call tools_vm_cpu_turn
    push rbx
    popfq
    cmp eax,1
    jne .bad
    mov rdi,r12
    mov rsi,r13
    call tvm_memory_stopped
    test eax,eax
    jz .bad
    mov byte [rel tvm_exit_open],1
    call tvm_dispatch_bound
    mov byte [rel tvm_exit_open],0
    cmp eax,1
    jne .bad
    jmp .out
.idle:
    mov eax,2
    jmp .out
.bad:
    mov byte [rel tvm_exit_open],0
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

tools_vm_endpoint: dq 0x314d56534c4f4f54  ; 'TOOLSVM1', distinct from the app's
; Assembly fails unless tools RUNNING is the state the shared CPU turn admits.
times -((TVM_RUNNING-AVM_RUNNING)*(TVM_RUNNING-AVM_RUNNING)) db 0

%include "core/abi/wdata.inc"
%macro WDATA_hv_tools_vm_devices 0
align 8
tvmd_state_begin:
tvmd_pit_start: times 2 dq 0
tvmd_pit_due: dq 0
tvmd_pit_period: dq 0
tvmd_pit_div: times 2 dd 0
tvmd_pit_load: times 2 dw 0
tvmd_pit_latch: times 2 dw 0
tvmd_pit_mode: times 2 db 0
tvmd_pit_rw: times 2 db 0
tvmd_pit_write_phase: times 2 db 0
tvmd_pit_read_phase: times 2 db 0
tvmd_pit_latched: times 2 db 0
tvmd_pit_armed: db 0
tvmd_speaker: db 0
tvmd_refresh: db 0
tvmd_pic_mask: times 2 db 0
tvmd_pic_base: times 2 db 0
tvmd_pic_phase: times 2 db 0
tvmd_pic_isr: times 2 db 0
tvmd_pic_read_isr: times 2 db 0
tvmd_pic_pending: db 0
tvmd_uart_lcr: db 0
tvmd_uart_ier: db 0
tvmd_uart_mcr: db 0
tvmd_uart_scr: db 0
tvmd_uart_thre: db 0
tvmd_uart_dll: db 0
tvmd_uart_dlm: db 0
tvmd_cmos: db 0
tvm_console_bytes: dd 0
tvm_console_overflow: db 0
tvm_console: times 8192 db 0
tvmd_guest_ended: db 0
align 8
tvmd_state_end:
tvm_halted: db 0
tvm_dispatch_fault: db 0
tvm_exit_open: db 0
; Snapshot disjointness loads this span with ECX. Reject empty, reversed
; or truncated layouts at WDATA expansion, after both labels are defined.
times (((tvm_exit_open+1-tvmd_state_begin) <= 0) || ((tvm_exit_open+1-tvmd_state_begin) > 0xffffffff)) * -1 db 0
%endmacro
WDATA_DEFER WDATA_hv_tools_vm_devices
