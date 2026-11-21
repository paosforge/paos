;; MODULE hv/driver_domain
;; LAYER 5
;; EXPORTS nd_begin, nd_prepare, nd_current, nd_stop, nd_backend_stopped, nd_tick, nd_snapshot, nd_cmdline, nd_reserve_allowed
;; IMPORTS boot/serial, core/lib/fmt, hv/driver_domain_restart, core/memory_budget, hv/filesystem_domain, hv/vmx, hv/vm_profile, hv/nic_selection, hv/a1_nic_selection, hv/nic_assignment, boot/header, boot/native_driver_preload, boot/native_driver_gate, hv/wifi_channel, hv/guestpower, hv/nd_isolation
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
ND_A1_PRIVATE_QWORDS equ (320+64+256+8)/8 ; nd_a1_request/map/result/scope
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
    ; Original boot keeps its absolute120s limit. Only an exact explicitly
    ; selected post-ACK restart may use its bounded existing return reserve.
    push rax
    call nd_restart_clock
    mov edx,eax
    pop rax
    test edx,edx
    js .bad
    jnz .measured
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
    push r15
    sub rsp,8
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
    xor r15d,r15d                   ; legacy singleton mode0
    mov rax,[rel native_driver_selected_policy]
    cmp rax,2                       ; immutable build selector, NOT runtime MODE
    je .a1_select
    cmp rax,1
    ja .bad                         ; unknown build never falls back
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
    jmp .selected
.a1_select:
    mov rdi,rbx
    mov esi,r12d
    lea rdx,[rel nd_a1_candidate]
    call nd_a1_capture
    test eax,eax
    jnz .bad
    mov rdi,rbx
    mov esi,r12d
    lea rdx,[rel nd_a1_check]
    call nd_a1_capture
    test eax,eax
    jnz .bad
    lea rdi,[rel nd_a1_candidate]
    lea rsi,[rel nd_a1_check]
    mov ecx,76                      ; full608, includes original ISO/group/claims
    cld
    repe cmpsq
    jne .bad
    cmp qword [rel nd_attempt],-1
    je .bad                         ; native attempt never wraps or aliases
    mov r15d,1                      ; MODE1 only after actual signed policy
.selected:
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
    mov [rel nd_mode],r15d           ; frozen with this original START tuple
    mov dword [rel nd_a1_error],0
    lea rdi,[rel nd_a1_request]      ; no preceding attempt's R2 operands/result
    xor eax,eax
    mov ecx,ND_A1_PRIVATE_QWORDS
    cld
    rep stosq
    test r15d,r15d
    jz .mode_bound
    inc qword [rel nd_attempt]
    lea rsi,[rel nd_a1_candidate]
    lea rdi,[rel nd_a1_original]
    mov ecx,76
    rep movsq
    ; A1NS is never a NICS singleton or a stale preceding legacy selection.
    lea rdi,[rel nd_selector]
    xor eax,eax
    mov ecx,148
    rep stosq
.mode_bound:
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
    add rsp,8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; RDI=exact signed profile,ESI=BDF,RDX=private608. Recheck immutable
; build selection on every native capture. No profile include means refusal.
nd_a1_capture:
    cmp qword [rel native_driver_selected_policy],2
    jne .policy
%ifdef PAOS_DRIVER_DOMAIN_PROFILE_INC
    mov ecx,608
    jmp a1_nic_snapshot
%endif
.policy:
    mov eax,41                      ; A1N_E_POLICY; never singleton fallback
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
    cmp dword [rel nd_mode],1
    je .a1_prepare
    cmp dword [rel nd_mode],0
    jne .fault
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
.a1_prepare:
    mov rdi,[rel nd_profile]
    mov esi,[rel nd_bdf]
    lea rdx,[rel nd_a1_check]
    call nd_a1_capture
    test eax,eax
    jnz .a1_refused
    lea rdi,[rel nd_a1_original]
    lea rsi,[rel nd_a1_check]
    mov ecx,76
    cld
    repe cmpsq
    mov eax,43                      ; A1N_E_CHANGED; retain original608 intact
    jne .a1_refused
    call nd_owner                   ; full native tuple after the capture
    test eax,eax
    jz .fault
    call nd_clock
    test eax,eax
    jz .fault
    mov rax,[rel nd_clock_ms]
    sub rax,r12
    cmp rax,ND_CALL_MS
    jae .fault
    ; Original R2 op1 once: family config/MMIO READS only, A1RS retained.
    mov rdi,r12
    call nd_a1_probe
    test eax,eax
    jnz .a1_refused
    call nd_clock
    test eax,eax
    jz .fault
    mov rax,[rel nd_clock_ms]
    sub rax,r12
    cmp rax,ND_CALL_MS
    jae .fault
    ; Actual A1 assignment/reset/map backend is not implemented yet (VM/AMD).
    ; Stop this original START BEFORE pool clearing/device/DMA writes. Do not
    ; feed608 into legacy592, invoke a legacy reset, or infer custody release.
    mov eax,46                      ; A1 assignment supplier unavailable
.a1_refused:
    mov [rel nd_a1_error],eax
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
    cmp dword [rel nd_mode],0        ; legacy receipt never establishes A1 ready
    jne .bad
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
    je nd_stop_loader_returned           ; ROOT 121790 b1 (after nd_backend_stopped)
    mov eax,[rel hv_linux_start_gen]
    cmp rax,[rel nd_generation]
    jne .quarantine
    cmp dword [rel nd_attached],0
    jne .quarantine
    ; No task consumed this START. Withdraw only while every CPU/root receipt
    ; is actually off; a contradictory receipt retains the pending STOP.
    cmp byte [rel hv_linux_running],0
    jne .quarantine
    cmp byte [rel hv_linux_vmx_live],0
    jne .quarantine
    cmp qword [rel hv_svm_cur_vmcb],0
    jne .quarantine
    mov byte [rel hv_linux_run_req],0
    mov dword [rel nd_state],4
    mov edi,eax
    call vm_profile_pair_finish
    mov dword [rel nd_terminal],1
    mov dword [rel nd_released],1
    mov dword [rel nd_state],4
    call nd_transport_retire
    mov byte [rel hv_linux_stop_req],0   ; original unconsumed START withdrawn
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
    mov edi,ND_FS_START                 ; nd_prepare; nd_a1_error names an A1 refusal
nd_fault_stop_from:
    call nd_fault_record
    mov dword [rel nd_fault],1
    mov rdi,[rel nd_generation]
    lea rsi,[rel nd_nonce]
    jmp nd_stop

; ROOT 121790 (a). EDI caller: ND_FS_START (nd_prepare), ND_FS_CURRENT (an
; attached domain is no longer current, nd_tick), ND_FS_CLOCK (the clock failed
; while armed, nd_tick). The first fault-stop of this START keeps the caller,
; nd_state, nd_a1_error, the loader/stop/run receipts, the loader phase and the
; boot ms, all read
; before nd_stop changes any of them. It prints them once, as one serial line,
; and NDSTAT1 carries them while the fault bit is set. Observation only:
; no STOP, retire, return or custody decision reads this record.
nd_fault_record:
    mov rax,[rel nd_generation]
    test rax,rax
    jz .out
    cmp rax,[rel nd_fs_generation]
    je .out                             ; first fault-stop of this START only
    push rbx
    push rbp
    sub rsp,208                         ; entry 0 mod 16, two pushes: calls stay ABI-aligned
    mov [rel nd_fs_generation],rax
    mov [rel nd_fs_caller],dil
    mov eax,[rel nd_state]
    mov [rel nd_fs_state],al
    xor ebx,ebx
    cmp byte [rel hv_linux_start_active],0
    je .stop_req
    or ebx,ND_FS_START_ACTIVE
.stop_req:
    cmp byte [rel hv_linux_stop_req],0
    je .running
    or ebx,ND_FS_STOP_REQ
.running:
    cmp byte [rel hv_linux_running],0
    je .consumed
    or ebx,ND_FS_RUNNING
.consumed:
    mov eax,[rel hv_linux_start_consumed]
    cmp rax,[rel nd_generation]
    jne .vmx
    or ebx,ND_FS_CONSUMED
.vmx:
    cmp byte [rel hv_linux_vmx_live],0
    je .vmcb
    or ebx,ND_FS_VMX_LIVE
.vmcb:
    cmp qword [rel hv_svm_cur_vmcb],0
    je .flags
    or ebx,ND_FS_VMCB
.flags:
    mov [rel nd_fs_flags],bl
    xor eax,eax                         ; loader phase only for this START's own prepare
    mov ecx,[rel hv_linux_load_gen]
    cmp rcx,[rel nd_generation]
    jne .phase
    movzx eax,byte [rel hv_linux_load_phase]
.phase:
    mov [rel nd_fs_phase],al
    mov eax,[rel nd_a1_error]
    mov [rel nd_fs_a1_error],eax
    call boot_ms_now
    mov [rel nd_fs_ms],rax
    mov rsi,rsp
    lea rdi,[rel nd_fs_caller_str]
    movzx edx,byte [rel nd_fs_caller]
    call nd_fs_put
    lea rdi,[rel nd_fs_state_str]
    movzx edx,byte [rel nd_fs_state]
    call nd_fs_put
    lea rdi,[rel nd_fs_a1_str]
    mov edx,[rel nd_fs_a1_error]
    call nd_fs_put
    lea rbp,[rel nd_fs_flag_strs]
    xor ebx,ebx
.flag:
    mov rdi,rbp
    movzx edx,byte [rel nd_fs_flags]
    mov ecx,ebx
    shr edx,cl
    and edx,1
    call nd_fs_put
    add rbp,ND_FS_FLAG_STR
    inc ebx
    cmp ebx,ND_FS_FLAG_COUNT
    jb .flag
    lea rdi,[rel nd_fs_ms_str]
    mov rdx,[rel nd_fs_ms]
    call nd_fs_put
    lea rdi,[rel nd_fs_phase_str]
    movzx edx,byte [rel nd_fs_phase]
    call nd_fs_put
    lea rdi,[rel nd_fs_tail]
.tail:
    mov al,[rdi]
    mov [rsi],al
    inc rdi
    inc rsi
    test al,al
    jnz .tail
    mov rdi,rsp
    call serial_string                  ; one call: no other CPU splits the line
    add rsp,208
    pop rbp
    pop rbx
.out:
    ret

; RDI NUL-terminated label, RSI output, RDX value ->RSI past the decimal.
nd_fs_put:
    mov al,[rdi]
    test al,al
    jz .number
    mov [rsi],al
    inc rdi
    inc rsi
    jmp nd_fs_put
.number:
    push rsi
    mov rdi,rdx
    call fmt_dec
    pop rsi
    add rsi,rax
    ret

nd_tick:
    mov eax,[rel nd_state]
    cmp eax,1
    je .armed
    cmp eax,2
    jne .out
    sub rsp,8
    call nd_current
    test eax,eax
    jz .fault
    call nd_power_tick                 ; T5-1.C10b-1b bounded Shut down (VM 106671 Q1)
    jmp .done
.fault:
    mov edi,ND_FS_CURRENT
    call nd_fault_stop_from
.done:
    add rsp,8
.out:
    ret
.armed:
    sub rsp,8
    call nd_clock
    test eax,eax
    jnz .done
    mov edi,ND_FS_CLOCK
    call nd_fault_stop_from
    jmp .done

; Called ONLY by original native terminal path, before RAM release, and by
; nd_stop for this START's loader that returned before that path (ROOT 121790 b1).
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
    cmp eax,[rel hv_linux_start_gen]
    jne .uncertain                     ; old terminal cannot spend a new STOP
    cmp byte [rel hv_linux_running],0
    jne .uncertain
    cmp byte [rel hv_linux_vmx_live],0
    jne .uncertain
    cmp qword [rel hv_svm_cur_vmcb],0
    jne .uncertain
    mov dword [rel nd_terminal],1
    ; Terminal fences teardown. Do not re-publish a STOP consumed by the vCPU.
    cmp dword [rel nd_attached],0
    je .retired
    cmp dword [rel nd_mode],0
    jne .uncertain                  ; no A1 -> legacy release fallback
    call nd_owner_map
    test eax,eax
    jz .uncertain
    mov edi,[rel nd_bdf]
    mov rsi,[rel nd_generation]
    call nic_assignment_release
    test eax,eax
    jnz .uncertain
.retired:
    mov eax,[rel hv_linux_start_gen]
    cmp rax,[rel nd_generation]
    jne .uncertain
    mov dword [rel nd_released],1
    mov dword [rel nd_state],4
    call nd_transport_retire
    call guestpower_retired             ; C10b-1a S5: clean only here, marker == nd_generation
    mov byte [rel hv_linux_stop_req],0   ; exact CPU-off/released generation only
    add rsp,8
.out:
    ret
.uncertain:
    mov dword [rel nd_state],6
    add rsp,8
    ret

; ROOT 121790 (b1), nd_stop's tail (rbx pushed; returns through nd_stop.ok, so
; nd_stop keeps its lines and the U1 receipt's citations hold). This START's
; loader has returned (start_active 0, consumed == START). Through its .done it
; already ran nd_backend_stopped and left 4 or 6, so nd_state 3 here means it
; left before .done (an early hv_guest_linux_start refusal, before any RAM, pair
; or device binding): nothing later retires this START, and a fault-stop or a
; return waits on it to the budget (Reatan 786 refused: nd_state 3, terminal 0).
; nd_backend_stopped's own predicates decide: CPU/VMCS/VMCB receipts off ->
; terminal, released, 4; a receipt still held, or a failed release -> 6.
nd_stop_loader_returned:
    ; Re-read after consumed: the loader publishes active before consumed
    ; (vmx.asm hv_guest_linux_task), so active 0 now, after consumed == START,
    ; is its own clear on return, never a loader preempted between the two.
    cmp byte [rel hv_linux_start_active],0
    jne nd_stop.ok
    call nd_backend_stopped
    jmp nd_stop.ok

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
    mov word [rbx+4],9
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
    ; ROOT 121790 (a), only while the fault bit is set and only for this START's
    ; own first fault-stop: +108 caller, +109 nd_state then, +110 receipts then,
    ; +111 loader phase then (this START only), +120 nd_a1_error then, +124 boot
    ; ms (low 32). Zero otherwise, as before.
    cmp dword [rel nd_fault],0
    je .no_fault_record
    mov rax,[rel nd_generation]
    cmp rax,[rel nd_fs_generation]
    jne .no_fault_record
    mov al,[rel nd_fs_caller]
    mov [rbx+108],al
    mov al,[rel nd_fs_state]
    mov [rbx+109],al
    mov al,[rel nd_fs_flags]
    mov [rbx+110],al
    mov al,[rel nd_fs_phase]
    mov [rbx+111],al
    mov eax,[rel nd_fs_a1_error]
    mov [rbx+120],eax
    mov eax,[rel nd_fs_ms]
    mov [rbx+124],eax
.no_fault_record:
    mov rsi,[rel nd_profile]
    test rsi,rsi
    jz .no_profile
    lea rdi,[rbx+128]
    mov ecx,35
    rep movsq
.no_profile:
    cmp dword [rel nd_mode],1
    je .a1_status
    lea rsi,[rel nd_selector]
    lea rdi,[rbx+448]
    mov ecx,74
    rep movsq
    cmp dword [rel nd_attached],0
    je .done
    lea rdi,[rbx+1088]
    call nic_assignment_receipt
    mov [rbx+1040],eax
    ; NDS1 v5: this START's raw attach reason (6 BAR admission, 3 reset; a
    ; selector/group code passes through), read only with the reset record.
    mov eax,[rel nic_assignment_error]
    mov [rbx+1044],eax
.done:
    ; NDS1 v4: retain the original reset attempt, including failed attach.
    ; Passive copy only: no new reset, group scan, refresh or custody change.
    lea rdi,[rbx+1344]
    call nic_assignment_reset_observation
    ; NDS1 v6 (R2, ROOT108305 B): the same attempt's passive NLK1 root-port
    ; Link Status record. Copy only: no PCI access, reset or custody change.
    lea rdi,[rbx+1408]
    call nic_assignment_link_observation
    ; NDS1 v7 (R2b, ROOT108718/108722): the same attempt's passive NRT1
    ; config-retention record. Copy only: no PCI access, reset or custody change.
    lea rdi,[rbx+1472]
    call nic_assignment_retention_observation
    jmp .policy_status
.a1_status:
    ; Different version: no copied NICS/legacy reset/group receipts. Existing
    ; v9 consumers must not mistake A1 for isolated/attached. Full original
    ; A1NS608 stays in native custody for the eventual qualified backend.
    mov word [rbx+4],11
    ; v11: this START's original R2 op1 A1RS256 (zero if never dispatched),
    ; retained exactly as the leaf left it, refusals included; then the
    ; selected function's ORIGINAL A1NS config256, the facts a leaf that
    ; refuses before reading still leaves for R2 (AMD118432).
    lea rsi,[rel nd_a1_result]
    lea rdi,[rbx+448]
    mov ecx,32
    rep movsq
    lea rsi,[rel nd_a1_original]
    add rsi,64                       ; A1NS config256
    mov ecx,32
    rep movsq                        ; rdi continues at +704
    mov eax,[rel nd_mode]
    mov [rbx+2032],eax
    mov eax,[rel nd_a1_error]
    mov [rbx+2036],eax
    mov rax,[rel nd_attempt]
    mov [rbx+2040],rax
.policy_status:
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
    ; NDS1 v3: actual allocator/loader readback in existing page6. This is
    ; passive: never START/STOP, acquire, release, map or refresh a lifetime.
    ; Keep both native tuples so the consumer can detect drift independently.
    mov dword [rbx+1536],0x314c414e       ; NAL1
    mov word [rbx+1540],1
    mov word [rbx+1542],256
    mov al,[rel hv_linux_running]
    mov [rbx+1548],al
    mov al,[rel hv_linux_start_active]
    mov [rbx+1549],al
    mov al,[rel hv_linux_vmx_live]
    mov [rbx+1550],al
    mov al,[rel hv_linux_task_started]
    mov [rbx+1551],al
%macro NAL_COPY 2
    mov rax,[rel %1]
    mov [rbx+1536+%2],rax
%endmacro
    NAL_COPY nd_generation,16
    NAL_COPY hv_linux_mb_gen,24
    NAL_COPY hv_linux_mb_token,32
    NAL_COPY hv_linux_region,40
    NAL_COPY hv_linux_region_capacity,48
    NAL_COPY hv_linux_region_resident,56
    NAL_COPY hv_linux_ram,64
    NAL_COPY hv_linux_ram_bytes,72
    NAL_COPY nd_ram,80
    NAL_COPY nd_ram_bytes,88
    NAL_COPY nd_region,96
    NAL_COPY nd_capacity,104
    mov eax,[rel hv_linux_start_gen]
    mov [rbx+1648],eax
    mov eax,[rel hv_linux_start_consumed]
    mov [rbx+1652],eax
    mov eax,[rel vm_profile_gen]
    mov [rbx+1656],eax
    mov eax,[rel vm_profile_live_devices]
    mov [rbx+1660],eax
    mov edi,1                          ; MB_OWNER_HV_LINUX
    mov rsi,[rel hv_linux_mb_gen]
    mov rdx,[rel hv_linux_mb_token]
    lea rcx,[rbx+1664]
    mov r8d,56                         ; MB_ALLOCATION_BYTES
    call mb_allocation_read
    mov [rbx+1544],eax                 ; busy/absent is preserved, never retried
    mov eax,[rel hv_linux_kernel_size]
    mov [rbx+1720],eax
    mov eax,[rel hv_linux_initrd_size]
    mov [rbx+1724],eax
    NAL_COPY hv_linux_initrd_gpa,192
    mov eax,[rel vm_profile_live_mmio]
    mov [rbx+1736],eax
    mov eax,[rel vm_profile_live_leaves]
    mov [rbx+1740],eax
    NAL_COPY vm_profile_live_reserve,208
    NAL_COPY hv_svm_cur_vmcb,216
    NAL_COPY hv_linux_eptp,224
%unmacro NAL_COPY 2
    call boot_ms_now
    mov [rbx+1768],rax
    mov al,[rel hv_linux_run_req]
    mov [rbx+1776],al
    call guestpower_mapped             ; NAL1 241: actual PT[9] is the paos.power page (SEC107097)
    mov [rbx+1777],al
    cmp dword [rel nd_mode],1
    je .status_complete             ; no stale legacy NAA1/GRF1/GRR1 on A1
    lea rdi,[rbx+1792]              ; NAA1 passive original admission, v8 only
    call nic_assignment_admission_observation
    ; NDS1 v9 keeps eight pages. GRF1 occupies old reserved408..439;
    ; GRR1 occupies old reserved1856..2031. Same START/selected BDF only.
    mov rdi,[rel nd_generation]
    mov esi,[rel nd_bdf]
    lea rdx,[rbx+408]
    lea rcx,[rbx+1856]
    call ndiso_group_snapshot
.status_complete:
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
ND_FS_START equ 1
ND_FS_CURRENT equ 2
ND_FS_CLOCK equ 3
ND_FS_START_ACTIVE equ 1                ; hv_linux_start_active
ND_FS_STOP_REQ equ 2                    ; hv_linux_stop_req
ND_FS_RUNNING equ 4                     ; hv_linux_running
ND_FS_CONSUMED equ 8                    ; hv_linux_start_consumed == this START
ND_FS_VMX_LIVE equ 16                   ; hv_linux_vmx_live
ND_FS_VMCB equ 32                       ; hv_svm_cur_vmcb != 0
ND_FS_FLAG_COUNT equ 6
ND_FS_FLAG_STR equ 16
nd_fs_caller_str: db '[PAOS64] nd.fault_stop caller=',0
nd_fs_state_str: db ' state=',0
nd_fs_a1_str: db ' a1_error=',0
nd_fs_flag_strs:                        ; bit order, ND_FS_FLAG_STR bytes each
    db ' start_active=',0,0
    db ' stop_req=',0,0,0,0,0,0
    db ' running=',0,0,0,0,0,0,0
    db ' consumed=',0,0,0,0,0,0
    db ' vmx_live=',0,0,0,0,0,0
    db ' vmcb=',0,0,0,0,0,0,0,0,0,0
nd_fs_ms_str: db ' ms=',0
nd_fs_phase_str: db ' load_phase=',0
nd_fs_tail: db ' [nd.fault_stop]',13,10,0
times (nd_fs_ms_str-nd_fs_flag_strs-ND_FS_FLAG_COUNT*ND_FS_FLAG_STR) * -1 db 0
times (nd_fs_flag_strs+ND_FS_FLAG_COUNT*ND_FS_FLAG_STR-nd_fs_ms_str) * -1 db 0

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
nd_mode: dd 0                       ; 0 legacy,1 signed A1; immutable per START
nd_a1_error: dd 0
nd_attempt: dq 0                    ; native monotonic A1 attempt; retained on STOP
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
nd_a1_original: times 608 db 0
nd_a1_candidate: times 608 db 0
nd_a1_check: times 608 db 0
; Original R2 op1 operands/result (driver_domain_a1probe); contiguous, cleared
; on every START. A1RS is an observation, never attach/reset authority.
nd_a1_request: times 320 db 0
nd_a1_map: times 64 db 0
nd_a1_result: times 256 db 0
nd_a1_scope: dq 0
; ROOT 121790 (a): this START's first fault-stop (nd_fault_record). Observation only.
nd_fs_generation: dq 0
nd_fs_ms: dq 0
nd_fs_a1_error: dd 0
nd_fs_caller: db 0
nd_fs_state: db 0
nd_fs_flags: db 0
nd_fs_phase: db 0                       ; hv_linux_load_phase when load_gen == START, else 0
nd_storage_end:
%endmacro
WDATA_DEFER WDATA_hv_driver_domain
