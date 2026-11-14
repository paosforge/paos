;; MODULE hv/wifi_channel
;; LAYER 5
;; EXPORTS wfc_state, wfc_prepare, wfc_current, wfc_snapshot, wfc_submit, wfc_cancel, wfc_backend_stopped, wfc_retire_step, wfc_tick, wfc_ready, wfc_reply
;; IMPORTS hv/vmx, hv/vm_profile, hv/driver_domain, hv/wifi_wire, hv/guestwifi, sec/wifi_store, core/csprng, boot/header, hv/nic_assignment
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Kernel-private one-shot receiver. Never a command or public console getter.
; State0 idle,1 waiting READY,2 ready,3 offered,4 sending/waiting ACK,
; 5 association observed,6 retired,7 stopped/uncertain/quarantined,8 RAM scrub.
; The sole vCPU is stopped at every entry. No callback yields. Queue metadata,
; all RAM/control/backend/START identities and local OWNER are rechecked after
; callbacks and before guest writes. ACK never retires native memory/custody.
WFC_MASK equ 0x18007

; Called once by the loader after actual NIC attach, before first CPU entry.
wfc_prepare:
    push rbx
    cmp dword [rel wfc_state],0
    je .idle
    cmp dword [rel wfc_state],6
    jne .bad
.idle:
    cmp qword [rel wfc_epoch],-1
    je .bad
    cmp dword [rel vm_profile_dev_mask],WFC_MASK
    jne .bad
    cmp dword [rel vm_profile_live_devices],WFC_MASK
    jne .bad
    cmp byte [rel hv_linux_running],0
    jne .bad
    cmp byte [rel hv_linux_vmx_live],0
    jne .bad
    cmp qword [rel hv_svm_cur_vmcb],0
    jne .bad
    call nd_owner_map
    test eax,eax
    jz .bad
    cmp dword [rel nd_state],2
    jne .bad
    call wfc_scrub
    inc qword [rel wfc_epoch]
%macro WFC_CAPTURE 2
    mov rax,[rel %1]
    mov [rel %2],rax
%endmacro
    WFC_CAPTURE nd_generation,wfc_generation
    WFC_CAPTURE vm_profile_active,wfc_profile
    WFC_CAPTURE hv_ops_active,wfc_backend
    WFC_CAPTURE hv_linux_ram,wfc_ram
    WFC_CAPTURE hv_linux_ram_bytes,wfc_ram_bytes
    WFC_CAPTURE hv_linux_region,wfc_region
    WFC_CAPTURE hv_linux_region_capacity,wfc_capacity
%unmacro WFC_CAPTURE 2
    mov eax,[rel nd_bdf]
    mov [rel wfc_bdf],eax
    lea rdi,[rel wfc_nonce]
    lea rsi,[rel nd_nonce]
    mov ecx,17
    cld
    rep movsb
    mov dword [rel wfc_state],1
    mov qword [rel wfc_deadline],0
    mov qword [rel wfc_last_ms],0
    call guestwifi_reset
    test eax,eax
    jz .fault
    mov eax,1
    jmp .out
.fault:
    mov dword [rel wfc_state],3
    call wfc_cancel
.bad:
    xor eax,eax
.out:
    pop rbx
    ret

; Exact retained native identity, without requiring the CPU still be live.
wfc_owner:
    cmp dword [rel vm_profile_dev_mask],WFC_MASK
    jne .bad
    mov eax,[rel hv_linux_start_consumed]
    cmp rax,[rel wfc_generation]
    jne .bad
    cmp eax,[rel hv_linux_start_gen]
    jne .bad
    cmp eax,[rel vm_profile_gen]
    jne .bad
    cmp rax,[rel nd_generation]
    jne .bad
    mov eax,[rel nd_bdf]
    cmp eax,[rel wfc_bdf]
    jne .bad
%macro WFC_SAME 2
    mov rax,[rel %1]
    cmp rax,[rel %2]
    jne .bad
%endmacro
    WFC_SAME vm_profile_active,wfc_profile
    WFC_SAME hv_ops_active,wfc_backend
    WFC_SAME hv_linux_ram,wfc_ram
    WFC_SAME hv_linux_ram_bytes,wfc_ram_bytes
    WFC_SAME hv_linux_region,wfc_region
    WFC_SAME hv_linux_region_capacity,wfc_capacity
    WFC_SAME nd_nonce,wfc_nonce
    WFC_SAME nd_nonce+8,wfc_nonce+8
%unmacro WFC_SAME 2
    mov rax,[rel wfc_profile]
    test rax,rax
    jz .bad
    cmp dword [rax+VP_DEVICES],WFC_MASK
    jne .bad
    cmp dword [rax+VP_VCPUS],1
    jne .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

wfc_clock:
    sub rsp,8
    call boot_ms_now
    add rsp,8
    test rax,rax
    jz .bad
    cmp rax,[rel wfc_last_ms]
    jb .bad
    mov [rel wfc_last_ms],rax
    cmp qword [rel wfc_deadline],0
    je .ok
    cmp rax,[rel wfc_deadline]
    jae .bad
.ok:
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Current transport only. Local OWNER binding is checked independently while
; an offer/request exists. No queue descriptor is touched after false.
wfc_current:
    sub rsp,8
    cmp dword [rel wfc_state],1
    jb .bad
    cmp dword [rel wfc_state],5
    ja .bad
    call wfc_owner
    test eax,eax
    jz .bad
    call nd_current
    test eax,eax
    jz .bad
    call wfc_clock
    test eax,eax
    jz .bad
    cmp dword [rel wfc_state],3
    jb .ok
    call guestwifi_config_current
    test eax,eax
    jz .bad
    lea rdi,[rel wfc_context_check]
    mov esi,128
    call wifi_owner_context_snapshot
    test eax,eax
    jnz .bad
    lea rdi,[rel wfc_context]
    lea rsi,[rel wfc_context_check]
    mov ecx,16
    cld
    repe cmpsq
    jne .bad
    cmp dword [rel wfc_state],3
    jb .bad
    cmp dword [rel wfc_state],5
    ja .bad
    call guestwifi_config_current
    test eax,eax
    jz .bad
    ; Charge full context callback cost and recheck identity after it.
    call wfc_owner
    test eax,eax
    jz .bad
    call wfc_clock
    jmp .out
.ok:
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    add rsp,8
    ret

; Complete private64 READY already copied from actual queue. Never a grant.
wfc_ready:
    sub rsp,8
    cmp dword [rel wfc_state],1
    jne .bad
    mov esi,64
    mov rdx,[rel wfc_generation]
    lea rcx,[rel wfc_nonce]
    call wfw_ready_validate
    test eax,eax
    jnz .bad
    call wfc_current
    test eax,eax
    jz .bad
    call guestwifi_config_capture
    mov dword [rel wfc_state],2
    xor eax,eax
    jmp .out
.bad:
    mov eax,-1
.out:
    add rsp,8
    ret

; RDI=private out256,RSI=256,RDX=capturedOWNER,RCX=capturedepoch.
; One metadata-only template per START. Does not read encrypted WiFi profile.
; INPUT's opaque intent consumer fills only profile id/revision/SSID/PSK and
; guest budget, after storage/local context equality; wfc_submit rechecks all.
wfc_snapshot:
    push rbx
    push r12
    push r13
    mov rbx,rdi
    mov r12,rdx
    mov r13,rcx
    test rbx,rbx
    jz .bad
    cmp rsi,256
    jne .bad
    mov ecx,32
    xor eax,eax
    cld
    rep stosq
    cmp dword [rel wfc_state],2
    jne .bad
    cmp r12,1                      ; PRIN_OWNER, captured local epoch below
    jne .bad
    call wfc_current
    test eax,eax
    jz .bad
    mov rax,[rel wfc_last_ms]
    add rax,4000                   ; charge entire snapshot/context/CSPRNG cost
    jc .fault
    mov [rel wfc_deadline],rax
    lea rdi,[rel wfc_context]
    mov esi,128
    call wifi_owner_context_snapshot
    test eax,eax
    jnz .fault
    cmp r12,[rel wfc_context+8]
    jne .fault
    cmp r13,[rel wfc_context+16]
    jne .fault
    mov dword [rel wfc_template],'WFA1'
    mov dword [rel wfc_template+4],(256<<16)|1
    mov rax,[rel wfc_generation]
    mov [rel wfc_template+8],rax
    lea rdi,[rel wfc_template+16]
    mov esi,16
    call csprng_generate
    test eax,eax
    jnz .fault
    mov rax,[rel wfc_template+16]
    or rax,[rel wfc_template+24]
    jz .fault
    call wfc_current
    test eax,eax
    jz .fault
    lea rdi,[rel wfc_template+32]
    lea rsi,[rel wfc_nonce]
    mov ecx,16
    rep movsb
    mov eax,[rel wfc_bdf]
    mov [rel wfc_template+48],eax
    mov dword [rel wfc_template+52],1
    mov [rel wfc_template+56],r13
    mov rax,[rel wfc_deadline]
    mov [rel wfc_template+64],rax
    lea rdi,[rel wfc_template+168]
    lea rsi,[rel wfc_context+32]
    mov ecx,8                      ; committed ownerhash32 + node digest32
    rep movsq
    mov dword [rel wfc_state],3
    call wfc_current
    test eax,eax
    jz .fault
    mov rdi,rbx
    lea rsi,[rel wfc_template]
    mov ecx,32
    rep movsq
    xor eax,eax
    jmp .out
.fault:
    mov dword [rel wfc_state],3
    call wfc_cancel
.bad:
    mov eax,3
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Kernel-only, exact private frame256 ->0/-1; no external pointer retained.
; No second offer/submit or repair after any attempt. Queue writes are deferred
; to clean stopped-vCPU pump, never performed inside a store/auth callback.
wfc_submit:
    push rbx
    mov rbx,rdi
    cmp rsi,256
    jne .bad
    test rbx,rbx
    jz .bad
    cmp dword [rel wfc_state],3
    jne .bad
    call wfc_current
    test eax,eax
    jz .fault
    lea rdi,[rel wfc_request]
    mov rsi,rbx
    mov ecx,32
    cld
    rep movsq
    lea rdi,[rel wfc_request]
    mov esi,256
    call wfw_request_validate
    test eax,eax
    jnz .fault
    lea rdi,[rel wfc_request]
    lea rsi,[rel wfc_template]
    mov ecx,9                      ; exact native header, tuple, epoch, cutoff
    repe cmpsq
    jne .fault
    lea rdi,[rel wfc_request+168]
    lea rsi,[rel wfc_template+168]
    mov ecx,8
    repe cmpsq
    jne .fault
    call wfc_current
    test eax,eax
    jz .fault
    mov rax,[rel wfc_deadline]
    sub rax,[rel wfc_last_ms]
    mov edx,[rel wfc_request+100]
    cmp rdx,rax
    ja .fault                      ; guest cannot extend native absolute cutoff
    mov dword [rel wfc_state],4
    mov dword [rel wfc_tx_offset],0
    mov dword [rel wfc_rx_offset],0
    xor eax,eax
    jmp .out
.fault:
    call wfc_cancel
.bad:
    mov eax,-1
.out:
    pop rbx
    ret

; RDI=private ACK64. Association is a raw observation; refuse/uncertain STOP.
wfc_reply:
    sub rsp,8
    cmp dword [rel wfc_state],4
    jne .bad
    cmp dword [rel wfc_tx_offset],256
    jne .bad
    mov esi,64
    lea rdx,[rel wfc_request]
    call wfw_reply_validate
    test eax,eax
    jnz .bad
    mov eax,[rdi+32]
    test eax,eax
    jnz .bad
    call wfc_current
    test eax,eax
    jz .bad
    mov dword [rel wfc_state],5
    mov qword [rel wfc_deadline],0
    lea rdi,[rel wfc_template]
    mov ecx,512/8
    xor eax,eax
    rep stosq
    xor eax,eax
    jmp .out
.bad:
    call wfc_cancel
    mov eax,-1
.out:
    add rsp,8
    ret

; Cancellation never frees RAM or NIC ownership. Foreign identity gets no STOP
; and remains quarantined. A ready/no-secret receiver survives local intent
; cancellation; any offer or delivered secret stops the exact original guest.
wfc_cancel:
    sub rsp,8
    cmp dword [rel wfc_state],3
    jb .out
    cmp dword [rel wfc_state],6
    jae .out
    mov dword [rel wfc_state],7
    call wfc_scrub
    call wfc_owner
    test eax,eax
    jz .out
    mov rdi,[rel wfc_generation]
    lea rsi,[rel wfc_nonce]
    call nd_stop
.out:
    add rsp,8
    ret

wfc_scrub:
    lea rdi,[rel wfc_secret]
    mov ecx,wfc_secret_end-wfc_secret
    xor eax,eax
    cld
    rep stosb
    ret

; Native CPU/DMA retirement, checked before every RAM write. A peer ACK or
; zero guest flags never substitutes for original NIC release.
wfc_cpu_off:
    cmp byte [rel hv_linux_running],0
    jne .bad
    cmp byte [rel hv_linux_vmx_live],0
    jne .bad
    cmp qword [rel hv_svm_cur_vmcb],0
    jne .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

wfc_nd_retired:
    cmp dword [rel nd_state],4
    jne .bad
    cmp dword [rel nd_terminal],1
    jne .bad
    cmp dword [rel nd_released],1
    jne .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

wfc_retire_safe:
    sub rsp,8
    call wfc_cpu_off
    test eax,eax
    jz .bad
    call wfc_owner
    test eax,eax
    jz .bad
    call wfc_nd_retired
    test eax,eax
    jz .bad
    call nic_assignment_owned
    test eax,eax
    jnz .bad
    call wfc_cpu_off
    test eax,eax
    jz .bad
    call wfc_nd_retired
    test eax,eax
    jz .bad
    call wfc_owner
    test eax,eax
    jz .bad
    ; Exactly the original reservation's guest RAM, never control or foreign RAM.
    mov rax,[rel wfc_region]
    test rax,rax
    jz .bad
    add rax,0x200000
    jc .bad
    cmp rax,[rel wfc_ram]
    jne .bad
    mov rdx,[rel wfc_ram_bytes]
    test rdx,rdx
    jz .bad
    test edx,4095
    jnz .bad
    mov ecx,0xc0000000
    cmp rdx,rcx
    ja .bad
    add rax,rdx
    jc .bad
    mov rdx,[rel wfc_region]
    add rdx,[rel wfc_capacity]
    jc .bad
    cmp rax,rdx
    ja .bad
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    add rsp,8
    ret

; Called AFTER nd_backend_stopped, BEFORE pair/device/memory release. Initialize
; the bounded scrub once; memory and the exact profile stay held until state6.
wfc_backend_stopped:
    sub rsp,8
    cmp dword [rel wfc_state],0
    je .ok
    cmp dword [rel wfc_state],6
    je .ok
    call wfc_retire_safe
    test eax,eax
    jz .bad
    cmp dword [rel wfc_state],8
    je .ok
    call wfc_scrub
    call guestwifi_zero
    mov qword [rel wfc_scrub_offset],0
    mov dword [rel wfc_state],8
.ok:
    xor eax,eax
    jmp .out
.bad:
    call wfc_retire_fault
    mov eax,-1
.out:
    add rsp,8
    ret

; One <=2MiB quantum per caller turn. The loader yields between these calls,
; retaining start_active and the original profile/RAM/backend tuple.
wfc_retire_step:
    sub rsp,8
    cmp dword [rel wfc_state],0
    je .ok
    cmp dword [rel wfc_state],6
    je .ok
    cmp dword [rel wfc_state],8
    jne .bad
    call wfc_retire_safe
    test eax,eax
    jz .bad
    cmp dword [rel wfc_state],8
    jne .bad
    mov rax,[rel wfc_scrub_offset]
    mov rdx,[rel wfc_ram_bytes]
    cmp rax,rdx
    ja .bad
    sub rdx,rax
    jz .complete
    cmp rdx,0x200000
    jbe .quantum
    mov edx,0x200000
.quantum:
    mov rdi,[rel wfc_ram]
    add rdi,rax
    mov rcx,rdx
    shr rcx,3
    xor eax,eax
    cld
    rep stosq
    add [rel wfc_scrub_offset],rdx
    mov rax,[rel wfc_scrub_offset]
    cmp rax,[rel wfc_ram_bytes]
    jne .ok
.complete:
    mov dword [rel wfc_state],6
.ok:
    xor eax,eax
    jmp .out
.bad:
    call wfc_retire_fault
    mov eax,-1
.out:
    add rsp,8
    ret

wfc_retire_fault:
    mov dword [rel wfc_state],7
    mov byte [rel hv_guest_power_fenced],1
    jmp wfc_scrub

wfc_tick:
    sub rsp,8
    cmp dword [rel wfc_state],0
    je .out
    cmp dword [rel wfc_state],6
    jae .out
    call wfc_current
    test eax,eax
    jz .fault
    call guestwifi_pump
    jmp .out
.fault:
    ; Transport faults before local Apply also stop this exact START.
    cmp dword [rel wfc_state],3
    jae .cancel
    mov dword [rel wfc_state],3
.cancel:
    call wfc_cancel
.out:
    add rsp,8
    ret

%include "core/abi/wdata.inc"
%macro WDATA_hv_wifi_channel 0
align 16
wfc_state: dd 0
wfc_bdf: dd 0
wfc_epoch: dq 0
wfc_generation: dq 0
wfc_profile: dq 0
wfc_backend: dq 0
wfc_ram: dq 0
wfc_ram_bytes: dq 0
wfc_region: dq 0
wfc_capacity: dq 0
wfc_nonce: times 17 db 0
align 8
wfc_last_ms: dq 0
wfc_deadline: dq 0
wfc_scrub_offset: dq 0
wfc_tx_offset: dd 0
wfc_rx_offset: dd 0
wfc_secret:
wfc_context: times 128 db 0
wfc_context_check: times 128 db 0
wfc_template: times 256 db 0
wfc_request: times 256 db 0
wfc_secret_end:
%endmacro
WDATA_DEFER WDATA_hv_wifi_channel
