;; MODULE hv/driver_domain
;; LAYER 5
;; EXPORTS nd_begin, nd_prepare, nd_current, nd_stop, nd_backend_stopped, nd_tick, nd_snapshot, nd_cmdline, nd_reserve_allowed
;; IMPORTS hv/filesystem_domain, hv/vmx, hv/vm_profile, hv/nic_selection, hv/nic_assignment, boot/header, boot/native_driver_preload, boot/native_driver_gate, hv/wifi_channel
;; CAPS extension
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Selected physical NIC, one full Linux guest, exact signed profile/START.
; All entrypoints are native owner APIs; no guest datum grants DMA authority.
; State 0 idle,1 armed,2 attached,3 stopping,4 retired,5 preSTART failure,
; 6 quarantine. Reuse requires a fresh nonce and actual terminal retirement.
; boot_ms_now uses the first kernel boot timestamp, not admission-relative time.
ND_BOOT_MS equ 120000
ND_CALL_MS equ 4000
ND_STATUS_BYTES equ 2048

; Validate native-authored nonce: exactly16 lowerhex+NUL, nonzero.
nd_nonce_valid:
    test rdi,rdi
    jz .bad
    xor ecx,ecx
    xor edx,edx
.loop:
    mov al,[rdi+rcx]
    cmp al,'0'
    jb .bad
    cmp al,'9'
    jbe .digit
    cmp al,'a'
    jb .bad
    cmp al,'f'
    ja .bad
.digit:
    cmp al,'0'
    je .next
    inc edx
.next:
    inc ecx
    cmp ecx,16
    jb .loop
    cmp byte [rdi+16],0
    jne .bad
    test edx,edx
    setnz al
    movzx eax,al
    ret
.bad:
    xor eax,eax
    ret

; Every callback cost is charged before publication. Clock rollback refuses.
nd_clock:
    sub rsp,8
    call boot_ms_now
    add rsp,8
    test rax,rax
    jz .bad
    cmp rax,[rel nd_clock_ms]
    jb .bad
    cmp dword [rel nd_operational],1
    je .measured
    cmp rax,ND_BOOT_MS
    jae .bad
.measured:
    mov [rel nd_clock_ms],rax
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; RDI=trusted built-in profile,ESI=full segment0 packed physicalBDF,
; RDX=nonce17 ->START/0. Selector is read-only; actual attach is loader-owned.
nd_begin:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    mov rbx,rdi
    mov r12d,esi
    mov r13,rdx
    ; Private association RAM remains reserved through bounded terminal scrub.
    mov eax,[rel wfc_state]
    test eax,eax
    jz .wifi_idle
    cmp eax,6
    jne .bad
.wifi_idle:
    ; A retained filesystem START owns the shared loader/profile until retire.
    cmp dword [rel fsg_state],0
    jne .bad
    mov eax,[rel nd_state]
    cmp eax,0
    je .idle
    cmp eax,4
    je .idle
    cmp eax,5
    jne .bad
.idle:
%macro ND_IDLE_BYTE 1
    cmp byte [rel %1],0
    jne .bad
%endmacro
    ND_IDLE_BYTE hv_linux_running
    ND_IDLE_BYTE hv_linux_start_active
    ND_IDLE_BYTE hv_linux_run_req
    ND_IDLE_BYTE hv_linux_vmx_live
    ND_IDLE_BYTE hvp_bound
    ND_IDLE_BYTE hvw_bound
    ND_IDLE_BYTE cdp_bound
    ND_IDLE_BYTE gws_bound
    ND_IDLE_BYTE padc_bound
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    ND_IDLE_BYTE hv_vcon_pmr_bound
%endif
%endif
%unmacro ND_IDLE_BYTE 1
    cmp qword [rel hv_svm_cur_vmcb],0
    jne .bad
    mov dword [rel nd_operational],0
    mov rdi,r13
    call nd_nonce_valid
    test eax,eax
    jz .bad
    lea rdi,[rel nd_nonce]
    mov rsi,r13
    mov ecx,16
    cld
    repe cmpsb
    je .bad                         ; native never reoffers the preceding nonce
    mov rdi,rbx
    call vp_pair_trusted
    test eax,eax
    jnz .bad
    mov eax,[rbx+VP_DEVICES]
    cmp eax,VP_DEV_NICDOMAIN
    je .mask_ok
    cmp eax,0x18007                 ; exact NIC + private Wi-Fi page closure
    jne .bad
.mask_ok:
    cmp dword [rbx+VP_VCPUS],1
    jne .bad
    cmp r12d,0xffff
    ja .bad
    call nd_clock
    test eax,eax
    jz .bad
    mov r14,[rel nd_clock_ms]
    mov edi,r12d
    lea rsi,[rel nd_selector]
    mov edx,592
    call nic_select_snapshot
    test eax,eax
    jnz .bad
    mov edi,r12d
    lea rsi,[rel nd_selector_check]
    mov edx,592
    call nic_select_snapshot
    test eax,eax
    jnz .bad
    lea rdi,[rel nd_selector]
    lea rsi,[rel nd_selector_check]
    mov ecx,74
    cld
    repe cmpsq
    jne .bad
    cmp r12d,[rel nd_selector+8]
    jne .bad
    call nd_clock
    test eax,eax
    jz .bad
    mov rax,[rel nd_clock_ms]
    sub rax,r14
    cmp rax,ND_CALL_MS
    jae .bad
    mov ebp,[rel hv_linux_start_gen]
    inc ebp
    jz .bad
    mov eax,[rbx+VP_DEVICES]
    mov [rel nd_devices],eax        ; immutable admitted closure, not a later selection
    mov [rel nd_profile],rbx
    mov [rel nd_bdf],r12d
    lea rdi,[rel nd_nonce]
    mov rsi,r13
    mov ecx,17
    rep movsb
    mov dword [rel nd_state],1
    mov dword [rel nd_fault],0
    mov dword [rel nd_terminal],0
    mov dword [rel nd_released],0
    mov dword [rel nd_attached],0
    mov [rel nd_generation],rbp
    mov byte [rel nd_start_authority],1
    mov rdi,rbx
    mov esi,ebp
    call vm_profile_request
    test eax,eax
    jnz .prestart_failed
    call hv_guest_linux_request_start
    mov byte [rel nd_start_authority],0
    cmp eax,ebp
    jne .prestart_failed
    mov [rel vm_profile_gen],eax
    cmp byte [rel hv_linux_task_started],1
    je .accepted
    lea rdi,[rel hv_guest_linux_task]
    call sched_spawn
    cmp eax,-1
    je .withdraw
    mov byte [rel hv_linux_task_started],1
.accepted:
    call nd_build_ready
    call virtio_domain_capstone_bootstrap
    test eax,eax
    jnz .network_failed
    call nd_clock
    test eax,eax
    jz .network_failed
    mov rax,[rel nd_clock_ms]
    sub rax,r14
    cmp rax,ND_CALL_MS
    jae .network_failed
    mov rax,rbp
    jmp .out
.network_failed:
    mov rdi,rbp
    lea rsi,[rel nd_nonce]
    call nd_stop
    jmp .bad
.withdraw:
    cmp ebp,[rel hv_linux_start_gen]
    jne .quarantine
    cmp byte [rel hv_linux_start_active],0
    jne .quarantine
    mov byte [rel hv_linux_run_req],0
    mov dword [rel nd_state],5
    mov edi,ebp
    call vm_profile_pair_finish
.prestart_failed:
    mov byte [rel nd_start_authority],0
    mov dword [rel nd_state],5
    jmp .bad
.quarantine:
    mov dword [rel nd_state],6
.bad:
    xor eax,eax
.out:
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Loader-only capture BEFORE attach. Postcallback identity/fullcost checked.
; RDI=actual built SLAT root ->1 prepared/0 terminal failure requested.
nd_prepare:
    push rbx
    push r12
    sub rsp,8
    mov rbx,rdi
    cmp dword [rel nd_state],1
    jne .bad
    call nd_owner
    test eax,eax
    jz .fault
    cmp byte [rel hv_linux_start_active],1
    jne .fault
    cmp byte [rel hv_linux_stop_req],0
    jne .fault
    mov eax,[rel vm_profile_live_devices]
    or eax,0x8000
    cmp eax,[rel nd_devices]
    jne .fault
    call nd_clock
    test eax,eax
    jz .fault
    mov r12,[rel nd_clock_ms]
%macro ND_CAPTURE 2
    mov rax,[rel %1]
    mov [rel %2],rax
%endmacro
    ND_CAPTURE hv_ops_active,nd_backend
    ND_CAPTURE hv_linux_ram,nd_ram
    ND_CAPTURE hv_linux_ram_bytes,nd_ram_bytes
    ND_CAPTURE hv_linux_region,nd_region
    ND_CAPTURE hv_linux_region_capacity,nd_capacity
%unmacro ND_CAPTURE 2
    mov edi,[rel nd_bdf]
    lea rsi,[rel nd_selector_check]
    mov edx,592
    call nic_select_snapshot
    test eax,eax
    jnz .fault
    lea rdi,[rel nd_selector]
    lea rsi,[rel nd_selector_check]
    mov ecx,74
    cld
    repe cmpsq
    jne .fault
    mov rax,[rel nd_region]
    test rax,rax
    jz .fault
    mov rdx,[rel nd_capacity]
    cmp rdx,0xa0000
    jb .fault
    lea rdi,[rax+HV_NIC_POOL]
    mov esi,HV_NIC_POOL_PAGES*4096
    mov [rel nd_pool],rdi
    mov dword [rel nd_pool+8],HV_NIC_POOL_PAGES
    mov dword [rel nd_pool+12],0
    mov qword [rel nd_pool+16],0
    mov qword [rel nd_pool+24],0
    mov ecx,esi
    xor eax,eax
    cld
    rep stosb
    mov rdi,rbx
    lea rsi,[rel nd_pool]
    lea rdx,[rel nd_selector]
    mov rcx,[rel nd_generation]
    ; Even failed attach may hold reset/IOMMU custody. Release exactly once
    ; at the actual backend terminal hook; failure is never inferred clean.
    mov dword [rel nd_attached],1
    cmp dword [rel nd_devices],0x18007 ; frozen opt-in profile, never a public caller flag
    jne .attach_ethernet
    call nic_assignment_attach_wifi
    jmp .attach_result
.attach_ethernet:
    call nic_assignment_attach
.attach_result:
    test eax,eax
    jnz .fault
    call nd_owner_map
    test eax,eax
    jz .fault
    call nd_clock
    test eax,eax
    jz .fault
    mov rax,[rel nd_clock_ms]
    sub rax,r12
    cmp rax,ND_CALL_MS
    jae .fault
    or dword [rel vm_profile_live_devices],0x8000
    mov dword [rel nd_state],2
    mov eax,1
    jmp .out
.fault:
    call nd_fault_stop
.bad:
    xor eax,eax
.out:
    add rsp,8
    pop r12
    pop rbx
    ret

; Exact original identity: no flag or receipt substitutes for the loader tuple.
nd_owner:
    mov eax,[rel hv_linux_start_consumed]
    cmp rax,[rel nd_generation]
    jne .bad
    cmp eax,[rel hv_linux_start_gen]
    jne .bad
    cmp eax,[rel vm_profile_gen]
    jne .bad
    mov rax,[rel vm_profile_active]
    cmp rax,[rel nd_profile]
    jne .bad
    test rax,rax
    jz .bad
    mov edx,[rel nd_devices]
    cmp [rel vm_profile_dev_mask],edx
    jne .bad
    cmp [rax+VP_DEVICES],edx
    jne .bad
    cmp dword [rax+VP_VCPUS],1
    jne .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

nd_owner_map:
    sub rsp,8
    call nd_owner
    add rsp,8
    test eax,eax
    jz .bad
%macro ND_SAME 2
    mov rax,[rel %1]
    cmp rax,[rel %2]
    jne .bad
%endmacro
    ND_SAME hv_ops_active,nd_backend
    ND_SAME hv_linux_ram,nd_ram
    ND_SAME hv_linux_ram_bytes,nd_ram_bytes
    ND_SAME hv_linux_region,nd_region
    ND_SAME hv_linux_region_capacity,nd_capacity
%unmacro ND_SAME 2
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

nd_current:
    cmp dword [rel nd_state],2
    jne .bad
    cmp byte [rel hv_linux_running],1
    jne .bad
    cmp byte [rel hv_linux_start_active],1
    jne .bad
    cmp byte [rel hv_linux_stop_req],0
    jne .bad
    mov eax,[rel nd_devices]
    cmp [rel vm_profile_live_devices],eax
    jne .bad
    sub rsp,8
    call nd_owner_map
    test eax,eax
    jz .fail
    lea rdi,[rel nd_live_receipt]
    call nic_assignment_receipt
    cmp eax,1
    jne .missing_receipt
    cmp qword [rel nd_live_receipt],1
    jne .missing_receipt
    mov rax,[rel nd_generation]
    cmp rax,[rel nd_live_receipt+8]
    jne .missing_receipt
    mov eax,[rel nd_bdf]
    cmp rax,[rel nd_live_receipt+16]
    jne .missing_receipt
    call nd_owner_map
    test eax,eax
    jz .fail
    call nd_clock
    jmp .fail
.missing_receipt:
    xor eax,eax
.fail:
    add rsp,8
    ret
.bad:
    xor eax,eax
    ret

; RDI=exact START,RSI=exact nonce17 ->0/-1. No foreign STOP publication.
nd_stop:
    push rbx
    cmp rdi,[rel nd_generation]
    jne .bad
    test rsi,rsi
    jz .bad
    cmp byte [rsi+16],0
    jne .bad
    lea rdi,[rel nd_nonce]
    mov ecx,16
    cld
    repe cmpsb
    jne .bad
    mov eax,[rel nd_state]
    cmp eax,1
    jb .bad
    cmp eax,3
    ja .bad
    mov eax,[rel hv_linux_start_gen]
    cmp rax,[rel nd_generation]
    jne .quarantine
    mov dword [rel nd_state],3
    mov byte [rel hv_linux_stop_req],1
    cmp byte [rel hv_linux_start_active],0
    jne .ok
    mov eax,[rel hv_linux_start_consumed]
    cmp rax,[rel nd_generation]
    je .ok
    mov eax,[rel hv_linux_start_gen]
    cmp rax,[rel nd_generation]
    jne .quarantine
    cmp dword [rel nd_attached],0
    jne .quarantine
    mov byte [rel hv_linux_run_req],0
    mov dword [rel nd_state],4
    mov edi,eax
    call vm_profile_pair_finish
    mov dword [rel nd_terminal],1
    mov dword [rel nd_released],1
    mov dword [rel nd_state],4
    call nd_transport_retire
.ok:
    xor eax,eax
    jmp .out
.quarantine:
    mov dword [rel nd_state],6
.bad:
    mov eax,-1
.out:
    pop rbx
    ret

nd_fault_stop:
    mov dword [rel nd_fault],1
    mov rdi,[rel nd_generation]
    lea rsi,[rel nd_nonce]
    jmp nd_stop

nd_tick:
    mov eax,[rel nd_state]
    cmp eax,1
    je .armed
    cmp eax,2
    jne .out
    sub rsp,8
    call nd_current
    test eax,eax
    jnz .done
    call nd_fault_stop
.done:
    add rsp,8
.out:
    ret
.armed:
    sub rsp,8
    call nd_clock
    test eax,eax
    jnz .done
    call nd_fault_stop
    jmp .done

; Called ONLY by original native terminal path, before RAM release.
nd_backend_stopped:
    mov eax,[rel nd_state]
    cmp eax,1
    jb .out
    cmp eax,3
    ja .out
    mov eax,[rel hv_linux_start_consumed]
    cmp rax,[rel nd_generation]
    jne .out
    sub rsp,8
    cmp byte [rel hv_linux_running],0
    jne .uncertain
    cmp byte [rel hv_linux_vmx_live],0
    jne .uncertain
    cmp qword [rel hv_svm_cur_vmcb],0
    jne .uncertain
    mov dword [rel nd_terminal],1
    mov byte [rel hv_linux_stop_req],1
    cmp dword [rel nd_attached],0
    je .retired
    call nd_owner_map
    test eax,eax
    jz .uncertain
    mov edi,[rel nd_bdf]
    mov rsi,[rel nd_generation]
    call nic_assignment_release
    test eax,eax
    jnz .uncertain
.retired:
    mov dword [rel nd_released],1
    mov dword [rel nd_state],4
    call nd_transport_retire
    add rsp,8
.out:
    ret
.uncertain:
    mov dword [rel nd_state],6
    add rsp,8
    ret

; Shared allocator may reserve only the exact original loader; DMA/reuse while
; running, stopping or quarantined refuses. Terminal state permits ordinary use.
; Profile writes share custody; only this original admission may select.
nd_profile_allowed:
    mov eax,[rel wfc_state]
    test eax,eax
    jz .wifi_idle
    cmp eax,6
    jne .no
.wifi_idle:
    mov eax,[rel nd_state]
    test eax,eax
    jz .yes
    cmp eax,4
    je .yes
    cmp eax,5
    je .yes
    cmp eax,1
    jne .no
    cmp byte [rel nd_start_authority],1
    jne .no
.yes:
    mov eax,1
    ret
.no:
    xor eax,eax
    ret

nd_reserve_allowed:
    mov eax,[rel wfc_state]
    test eax,eax
    jz .wifi_idle
    cmp eax,6
    jne .no
.wifi_idle:
    mov eax,[rel nd_state]
    test eax,eax
    jz .yes
    cmp eax,4
    je .yes
    cmp eax,5
    je .yes
    cmp eax,1
    jne .no
    cmp byte [rel hv_linux_start_active],1
    jne .no
    mov eax,[rel hv_linux_start_consumed]
    cmp rax,[rel nd_generation]
    jne .no
    cmp eax,[rel hv_linux_start_gen]
    jne .no
    cmp eax,[rel vm_profile_gen]
    jne .no
    mov rax,[rel vm_profile_active]
    cmp rax,[rel nd_profile]
    jne .no
    test rax,rax
    jz .no
    mov edx,[rel nd_devices]
    cmp [rel vm_profile_dev_mask],edx
    jne .no
    cmp [rax+VP_DEVICES],edx
    jne .no
    cmp dword [rax+VP_VCPUS],1
    jne .no
.yes:
    mov eax,1
    ret
.no:
    xor eax,eax
    ret

; RDI=exact nonce17,RSI=private2048 output,EDX=2048 ->2048/-1.
; No guest claim becomes native readiness; these are separate raw observations.
nd_snapshot:
    push rbx
    push r12
    sub rsp,8
    mov rbx,rsi
    cmp edx,ND_STATUS_BYTES
    jne .bad
    test rbx,rbx
    jz .bad
    mov rsi,rdi
    test rsi,rsi
    jz .bad
    cmp byte [rsi+16],0
    jne .bad
    lea rdi,[rel nd_nonce]
    mov ecx,16
    cld
    repe cmpsb
    jne .bad
    cmp dword [rel nd_snapshot_sequence],0xffffffff
    je .bad
    mov rdi,rbx
    xor eax,eax
    mov ecx,ND_STATUS_BYTES/8
    rep stosq
    mov dword [rbx],0x3153444e
    mov word [rbx+4],2
    mov word [rbx+6],ND_STATUS_BYTES
    inc dword [rel nd_snapshot_sequence]
    mov eax,[rel nd_snapshot_sequence]
    mov [rbx+8],eax
    mov eax,[rel nd_state]
    mov [rbx+12],eax
    mov eax,[rel nd_terminal]
    mov edx,[rel nd_released]
    shl edx,1
    or eax,edx
    mov edx,[rel nd_fault]
    shl edx,2
    or eax,edx
    mov [rbx+16],eax
    mov eax,[rel nd_fault]
    mov [rbx+20],eax
    mov rax,[rel nd_generation]
    mov [rbx+24],rax
    lea rdi,[rbx+32]
    lea rsi,[rel nd_nonce]
    mov ecx,16
    rep movsb
    mov eax,[rel nd_bdf]
    mov [rbx+48],eax
    mov eax,[rel hv_linux_start_gen]
    mov [rbx+52],eax
    mov eax,[rel hv_linux_start_consumed]
    mov [rbx+56],eax
    mov eax,[rel vm_profile_gen]
    mov [rbx+60],eax
    call boot_ms_now
    mov [rbx+64],rax
    mov qword [rbx+72],ND_BOOT_MS
    mov rax,[rel nd_ram_bytes]
    mov [rbx+80],rax
    movzx eax,byte [rel hv_linux_running]
    mov [rbx+88],al
    mov al,[rel hv_linux_start_active]
    mov [rbx+89],al
    mov al,[rel hv_linux_stop_req]
    mov [rbx+90],al
    mov al,[rel hv_linux_kboot]
    mov [rbx+91],al
    mov al,[rel hv_vcon_q_ready]
    mov [rbx+92],al
    mov ax,[rel guestnet_q_ready]
    mov [rbx+94],ax
    mov eax,[rel vm_profile_dev_mask]
    mov [rbx+96],eax
    mov eax,[rel vm_profile_live_devices]
    mov [rbx+100],eax
    mov eax,[rel nd_operational]
    mov [rbx+104],eax
    mov rax,[rel nd_bridge_ms]
    mov [rbx+112],rax
    mov rsi,[rel nd_profile]
    test rsi,rsi
    jz .no_profile
    lea rdi,[rbx+128]
    mov ecx,35
    rep movsq
.no_profile:
    lea rsi,[rel nd_selector]
    lea rdi,[rbx+448]
    mov ecx,74
    rep movsq
    cmp dword [rel nd_attached],0
    je .done
    lea rdi,[rbx+1088]
    call nic_assignment_receipt
    mov [rbx+1040],eax
.done:
    ; NDS1 v2 retains the same eight-page envelope. Effective native policy
    ; and gate counters are observations, never successful-device counts.
    mov rax,[rel native_driver_selected_policy]
    mov [rbx+1152],rax
    mov rax,[rel native_driver_boot_bdf]
    mov [rbx+1160],rax
    lea rsi,[rel native_driver_permitted]
    lea rdi,[rbx+1168]
    mov ecx,11
    cld
    rep movsq
    lea rsi,[rel native_driver_blocked]
    mov ecx,11
    rep movsq
    mov eax,ND_STATUS_BYTES
    jmp .out
.bad:
    mov eax,-1
.out:
    add rsp,8
    pop r12
    pop rbx
    ret

; Boot arguments authored from native custody; PCI function presented at00:01.0.
nd_cmdline:
    cmp dword [rel nd_state],1
    jne .bad
    mov eax,[rel hv_linux_start_consumed]
    ; Composer runs in exact loader; HOST may inspect the armed fixed identity.
    mov rax,[rel vm_profile_active]
    cmp rax,[rel nd_profile]
    jne .bad
    lea rdi,[rel nd_bootparam]
    lea rsi,[rel nd_prefix]
    mov ecx,nd_prefix_end-nd_prefix
    cld
    rep movsb
    lea rdx,[rel nd_hex]
    mov eax,[rel nd_bdf]
    mov ecx,eax
    shr eax,8
    mov r8d,eax
    shr eax,4
    mov al,[rdx+rax]
    stosb
    and r8d,15
    mov al,[rdx+r8]
    stosb
    mov al,':'
    stosb
    mov eax,ecx
    shr eax,3
    and eax,31
    mov r8d,eax
    shr eax,4
    mov al,[rdx+rax]
    stosb
    and r8d,15
    mov al,[rdx+r8]
    stosb
    mov al,'.'
    stosb
    mov eax,ecx
    and eax,7
    add al,'0'
    stosb
    lea rsi,[rel nd_start_prefix]
    mov ecx,nd_start_prefix_end-nd_start_prefix
    rep movsb
    mov rax,[rel nd_generation]
    mov r8d,10
    xor ecx,ecx
.decimal:
    xor edx,edx
    div r8
    add dl,'0'
    push rdx
    inc ecx
    test rax,rax
    jnz .decimal
.digits:
    pop rax
    stosb
    loop .digits
    lea rsi,[rel nd_nonce_prefix]
    mov ecx,nd_nonce_prefix_end-nd_nonce_prefix
    rep movsb
    lea rsi,[rel nd_nonce]
    mov ecx,17
    rep movsb
    lea rax,[rel nd_bootparam]
    ret
.bad:
    xor eax,eax
    ret
nd_prefix: db ' paos.ndbdf=0000:00:01.0 paos.ndphysical=0000:'
nd_prefix_end:
nd_start_prefix: db ' paos.ndstart='
nd_start_prefix_end:
nd_nonce_prefix: db ' paos.ndnonce='
nd_nonce_prefix_end:
nd_hex: db '0123456789abcdef'

%include "core/abi/wdata.inc"
%macro WDATA_hv_driver_domain 0
align 16
nd_storage:
nd_state: dd 0
nd_fault: dd 0
nd_bdf: dd 0
nd_devices: dd 0
nd_terminal: dd 0
nd_released: dd 0
nd_attached: dd 0
nd_snapshot_sequence: dd 0
nd_start_authority: db 0
align 8
nd_generation: dq 0
nd_clock_ms: dq 0
nd_profile: dq 0
nd_backend: dq 0
nd_ram: dq 0
nd_ram_bytes: dq 0
nd_region: dq 0
nd_capacity: dq 0
nd_pool: times 32 db 0
nd_nonce: times 17 db 0
nd_bootparam: times 160 db 0
align 16
nd_selector: times 592 db 0
nd_selector_check: times 592 db 0
nd_storage_end:
%endmacro
WDATA_DEFER WDATA_hv_driver_domain
