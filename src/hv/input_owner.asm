;; MODULE hv/input_owner
;; LAYER 5
;; EXPORTS hv_pin_bind, hv_pin_check, hv_pin_request, hv_pin_pump, hv_pin_take, hv_pin_stop, hv_pin_retire, hv_pin_receive, hv_pin_backend_stopped, hvp_bound
;; IMPORTS hv/vmx, hv/input_domain, hv/vm_profile, hv/vtd, core/time
;; CAPS extension
;; OWNER saga:vm
; PIN1 controller over the existing console only. Every entry is serialized at
; a stopped-vCPU host boundary, never from IRQ, never yields or enters a guest.
; Bind AFTER signed profile/START and both console queues are live. No boot hook,
; peer discovery, PCI assignment or physical input publication is implied.
; A fault/STOP retains exclusive ownership and RAM until the backend's exact
; terminal receipt; a peer STOP reply is deliberately insufficient.

; RDI=actual START(u32 zero extended), RSI=actual console reset epoch,
; RDX=nonzero session communicated by the owning guest launcher.
hv_pin_bind:
    push rbx
    push r12
    push r13
    mov rbx,rdi
    mov r12,rsi
    mov r13,rdx
    cmp byte [rel hvp_bound],0
    jne .busy
    test rdi,rdi
    jz .invalid
    mov eax,edi
    cmp rax,rdi
    jne .invalid
    test rdx,rdx
    jz .invalid
    cmp rsi,[rel hv_vcon_epoch]
    jne .stale
    cmp edi,[rel hv_linux_start_consumed]
    jne .stale
    cmp dword [rel vm_profile_dev_mask],VP_DEV_PINDOMAIN
    jne .invalid
    cmp qword [rel vm_profile_active],0
    je .invalid
    mov [rel hvp_work + HV_VCON_RX_WORK.generation],edi
    mov rax,[rel hv_linux_region]
    mov [rel hvp_work + HV_VCON_RX_WORK.region],rax
    mov rax,[rel hv_linux_ram]
    mov [rel hvp_work + HV_VCON_RX_WORK.ram],rax
    mov rax,[rel hv_linux_ram_bytes]
    mov [rel hvp_work + HV_VCON_RX_WORK.ram_bytes],rax
    lea rdi,[rel hvp_work]
    call hv_vcon_owner_take
    test eax,eax
    jz .stale
    call hv_pin_context
    test eax,eax
    jz .busy
    mov rdi,rbx
    mov rsi,r12
    mov rdx,r13
    lea rcx,[rel hv_pin_send]
    call pind_bind
    test eax,eax
    jnz .out
    mov [rel hvp_gen],rbx
    mov qword [rel hvp_stopped_gen],0
    mov byte [rel hvp_fault],0
    mov byte [rel hvp_bound],1          ; publish only after actual client binds
    jmp .out
.busy: mov eax,-16
    jmp .out
.invalid: mov eax,-22
    jmp .out
.stale: mov eax,-116
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Internal context predicate, including the retained complete owner snapshot.
; A PIN1 console is never simultaneously text/CDP/GWS/PAD/media/warm or VT-d.
hv_pin_context:
    cmp byte [rel hvp_fault],0
    jne .bad
    cmp byte [rel hv_linux_running],1
    jne .bad
    cmp byte [rel hv_linux_stop_req],0
    jne .bad
    cmp byte [rel hv_guest_power_fenced],0
    jne .bad
    cmp byte [rel hv_vcon_ready],1
    jne .bad
    cmp word [rel hv_vcon_q_ready],0x0101
    jne .bad
    cmp dword [rel vm_profile_live_devices],VP_DEV_PINDOMAIN
    jne .bad
    cmp byte [rel cdp_bound],0
    jne .bad
    cmp byte [rel gws_bound],0
    jne .bad
    cmp byte [rel padc_bound],0
    jne .bad
    cmp byte [rel hvw_bound],0
    jne .bad
    cmp byte [rel vtd_owner_guest],0
    jne .bad
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    cmp byte [rel hv_vcon_pmr_bound],0
    jne .bad
%endif
%endif
    mov eax,[rel hv_linux_start_consumed]
    cmp eax,[rel hvp_work + HV_VCON_RX_WORK.generation]
    jne .bad
    mov rax,[rel hv_linux_region]
    test rax,rax
    jz .bad
    cmp rax,[rel hvp_work + HV_VCON_RX_WORK.region]
    jne .bad
    mov rax,[rel hv_linux_ram]
    test rax,rax
    jz .bad
    cmp rax,[rel hvp_work + HV_VCON_RX_WORK.ram]
    jne .bad
    mov rax,[rel hv_linux_ram_bytes]
    test rax,rax
    jz .bad
    cmp rax,[rel hvp_work + HV_VCON_RX_WORK.ram_bytes]
    jne .bad
    lea rdi,[rel hvp_work]
    jmp hv_vcon_owner_current
.bad: xor eax,eax
    ret

; RDI exact caller generation. Stale callers never poison another owner.
; A separate DOMAIN consumer must call this immediately before its pind_take
; composition within the SAME serialized, no-yield stopped-vCPU boundary.
hv_pin_check:
    cmp byte [rel hvp_bound],1
    jne .stale
    cmp rdi,[rel hvp_gen]
    jne .stale
    sub rsp,8
    call hv_pin_context
    add rsp,8
    test eax,eax
    jz hv_pin_fault
    xor eax,eax
    ret
.stale: mov eax,-116
    ret

hv_pin_fault:
    mov byte [rel hvp_fault],1
    mov byte [rel hv_linux_stop_req],1
    mov eax,-5
    ret

hv_pin_now:
    sub rsp,8
    call time_monotonic_now_us
    add rsp,8
    xor edx,edx
    mov ecx,1000
    div rcx
    ret

; RDI=gen, ESI=op(1 POLL/2 protocol STOP), EDX=source. No guest execution.
hv_pin_request:
    push rbx
    push r12
    push r13
    mov rbx,rdi
    mov r12d,esi
    mov r13d,edx
    call hv_pin_check
    test eax,eax
    jnz .out
    call hv_pin_now
    mov rcx,rax
    mov rdi,rbx
    mov esi,r12d
    mov edx,r13d
    call pind_request
    cmp dword [rel pind_state],PIND_FAULT
    jne .out
    call hv_pin_fault
.out:
    pop r13
    pop r12
    pop rbx
    ret

; RDI=gen. One bounded service opportunity, no retry on unknown acceptance.
hv_pin_pump:
    push rbx
    mov rbx,rdi
    call hv_pin_check
    test eax,eax
    jnz .out
    call hv_pin_now
    mov rsi,rax
    mov rdi,rbx
    call pind_pump
    test eax,eax
    jns .out
    call hv_pin_fault
.out: pop rbx
    ret

; PIN1's only native queue sender. Returns 0 ONLY for definitely no acceptance
; with a still-current owner; drift around publication is UNKNOWN, never retry.
hv_pin_send:
    push rbx
    push r12
    push r13
    mov rbx,rdi
    mov r12d,esi
    call hv_pin_context
    test eax,eax
    jz .unknown
    cmp r12d,64
    jne .unknown
    mov rdi,rbx
    mov esi,r12d
    call hv_vcon_rx_bytes.private_pin
    mov r13d,eax
    call hv_pin_context
    test eax,eax
    jz .unknown
    mov eax,r13d
    jmp .out
.unknown:
    call hv_pin_fault
    mov eax,-1
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Internal TX dispatch: ECX=bounded private snapshot length, not guest memory.
; An unbound private profile drops data here and can never fall back to text.
hv_pin_receive:
    cmp byte [rel hvp_bound],1
    jne .out
    push rbx
    mov ebx,ecx
    mov rdi,[rel hvp_gen]
    call hv_pin_check
    test eax,eax
    jnz .restore
    call hv_pin_now
    mov rsi,rax
    mov rdi,[rel hvp_gen]
    lea rdx,[rel hv_vcon_txbuf]
    mov ecx,ebx
    call pind_receive
    test eax,eax
    jns .restore
    call hv_pin_fault
.restore: pop rbx
.out: ret

; RDI=gen, RSI=owned disjoint native output, EDX=capacity. Complete PIN1 only.
hv_pin_take:
    push rbx
    push r12
    push r13
    mov rbx,rdi
    mov r12,rsi
    mov r13d,edx
    call hv_pin_check
    test eax,eax
    jnz .out
    ; Do not allow a native consumer to overwrite this controller's custody.
    mov rax,r12
    add rax,r13
    jc .invalid
    lea rcx,[rel hvp_storage_end]
    cmp r12,rcx
    jae .take
    lea rcx,[rel hvp_storage]
    cmp rax,rcx
    ja .invalid
.take:
    call hv_pin_now
    mov rsi,rax
    mov rdi,rbx
    mov rdx,r12
    mov ecx,r13d
    call pind_take
    cmp dword [rel pind_state],PIND_FAULT
    jne .out
    call hv_pin_fault
    jmp .out
.invalid: mov eax,-22
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Exact native stop request. Blocks every delivery now, retaining all custody.
hv_pin_stop:
    cmp byte [rel hvp_bound],1
    jne .stale
    cmp rdi,[rel hvp_gen]
    jne .stale
    call hv_pin_fault
    xor eax,eax
    ret
.stale: mov eax,-116
    ret

; Internal backend terminal path ONLY, after CPU return and before profile/RAM
; teardown. Still-live VMX/SVM, power quarantine or changed START earns nothing.
hv_pin_backend_stopped:
    cmp byte [rel hvp_bound],1
    jne .out
    cmp byte [rel hv_linux_running],0
    jne .out
    cmp byte [rel hv_linux_vmx_live],0
    jne .out
    cmp byte [rel hv_guest_power_fenced],0
    jne .out
    mov eax,[rel hv_linux_start_consumed]
    cmp rax,[rel hvp_gen]
    jne .out
    cmp eax,[rel hv_linux_start_gen]
    jne .out
    mov [rel hvp_stopped_gen],rax
.out: ret

; Exact receipt required, not ACK/status text. Cleared before RAM is released.
hv_pin_retire:
    cmp byte [rel hvp_bound],1
    jne .stale
    cmp rdi,[rel hvp_gen]
    jne .stale
    cmp rdi,[rel hvp_stopped_gen]
    jne .busy
    mov eax,[rel hv_linux_start_consumed]
    cmp rax,rdi
    jne .busy
    cmp eax,[rel hv_linux_start_gen]
    jne .busy
    cmp byte [rel hv_linux_running],0
    jne .busy
    cmp byte [rel hv_linux_vmx_live],0
    jne .busy
    cmp byte [rel hv_guest_power_fenced],0
    jne .busy
    sub rsp,8
    call pind_retire
    add rsp,8
    test eax,eax
    jnz .out
    pushfq
    cld
    lea rdi,[rel hvp_storage]
    mov ecx,hvp_storage_end-hvp_storage
    rep stosb
    popfq
.out: ret
.busy: mov eax,-16
    ret
.stale: mov eax,-116
    ret

%include "core/abi/wdata.inc"
%macro WDATA_hv_input_owner 0
alignb 8
hvp_storage:
hvp_gen: resq 1
hvp_stopped_gen: resq 1
hvp_work: resb HV_VCON_RX_WORK_size
hvp_fault: resb 1
hvp_bound: resb 1
hvp_storage_end:
%endmacro
WDATA_BSS_DEFER WDATA_hv_input_owner
