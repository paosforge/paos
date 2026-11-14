;; MODULE hv/app_vm
;; LAYER 5
;; EXPORTS app_vm_updater_role, app_vm_updater_observe_idle, app_vm_updater_prepare, app_vm_updater_exit, app_vm_updater_current, app_vm_updater_revoke, app_vm_updater_stopped, app_vm_recipient_revoke, app_vm_power_inactive, app_vm_prepare_without_isolation, app_vm_runnable, app_vm_prepare, app_vm_activate, app_vm_stop, app_vm_quiesce, app_vm_tick, app_vm_status, app_vm_snapshot, app_vm_endpoint_current, app_vm_exit_endpoint, app_vm_endpoint, avm_instance
;; IMPORTS hv/app_runtime, hv/app_vm_memory, hv/app_vm_payload, hv/app_vm_boot, hv/app_vm_cpu, hv/app_vm_intel, hv/app_vm_dispatch, hv/app_vm_devices, hv/app_network, hv/guest_request, hv/vmx, svc/app_script, core/time, core/smp, sec/session
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; One native instance, private CPU/RAM/devices and actual signed source bytes.
; Admission/setters require local OWNER; getters are non-yielding and grant-free
; because the actual GUES request resolver must read them during authorization.
%include "hv/app_vm.inc"
%include "hv/vcpu_svm.inc"

; Passive native terminal custody: trusted disjoint RDI256B, ESI=256.
; All24 actual scalar operands are captured once, even after a first blocker.
; Compare the snapshot only; no pointer chasing or lifecycle mutation.
; Original CPU identity helper retains its LAPIC/MSR boundary; no device inventory.
; EAX0 only exact inactive/BSP;1 refusal. EDX firstordinal1..24/25 context,
; FFFFFFFF invalid output (no writes). Version1 means all raw fields observed.
app_vm_power_inactive:
    test rdi,rdi
    jz .invalid
    cmp esi,256
    jne .invalid
    push rbx
    mov rbx,rdi
    call smp_current_logical
    mov qword [rbx],1
    mov [rbx+24],rax
    mov rax,qword [rel avm_state]
    mov [rbx+32],rax
    movzx eax,byte [rel avm_busy]
    mov [rbx+40],rax
    mov rax,qword [rel avm_token]
    mov [rbx+48],rax
    mov rax,qword [rel avm_base]
    mov [rbx+56],rax
    mov rax,qword [rel avm_capacity]
    mov [rbx+64],rax
    mov rax,qword [rel avm_ram]
    mov [rbx+72],rax
    mov rax,qword [rel avm_ram_bytes]
    mov [rbx+80],rax
    mov rax,qword [rel avm_clear_offset]
    mov [rbx+88],rax
    mov rax,qword [rel avm_root]
    mov [rbx+96],rax
    mov rax,qword [rel avm_cpu_ready]
    mov [rbx+104],rax
    mov rax,qword [rel avm_cpu_live]
    mov [rbx+112],rax
    mov rax,qword [rel avm_roots_retired]
    mov [rbx+120],rax
    movzx eax,byte [rel avm_bound]
    mov [rbx+128],rax
    movzx eax,byte [rel avm_exit_open]
    mov [rbx+136],rax
    movzx eax,byte [rel avm_payload_valid]
    mov [rbx+144],rax
    mov rax,qword [rel avm_boot_phase]
    mov [rbx+152],rax
    mov rax,qword [rel avm_runtime_gen]
    mov [rbx+160],rax
    movzx eax,byte [rel avmi_selected]
    mov [rbx+168],rax
    mov rax,qword [rel avm_svm+VSP_LIVE]
    mov [rbx+176],rax
    mov rax,qword [rel avm_svm+VSP_ACTIVE]
    mov [rbx+184],rax
    mov rax,qword [rel avm_handle]
    mov [rbx+192],rax
    mov rax,qword [rel avm_payload_bytes]
    mov [rbx+200],rax
    mov rax,qword [rel avm_session]
    mov [rbx+208],rax
    mov rax,qword [rel avm_owner]
    mov [rbx+216],rax
    mov rax,[rel avm_instance]
    mov [rbx+224],rax
    mov rax,[rel avm_start]
    mov [rbx+232],rax
    mov qword [rbx+240],0
    mov qword [rbx+248],0
    mov edx,25
    cmp qword [rbx+24],0
    jne .refused
    mov edx,1
    cmp qword [rbx+32],0
    jne .refused
    mov edx,2
    cmp qword [rbx+40],0
    jne .refused
    mov edx,3
    cmp qword [rbx+48],0
    jne .refused
    mov edx,4
    cmp qword [rbx+56],0
    jne .refused
    mov edx,5
    cmp qword [rbx+64],0
    jne .refused
    mov edx,6
    cmp qword [rbx+72],0
    jne .refused
    mov edx,7
    cmp qword [rbx+80],0
    jne .refused
    mov edx,8
    cmp qword [rbx+88],0
    jne .refused
    mov edx,9
    cmp qword [rbx+96],0
    jne .refused
    mov edx,10
    cmp qword [rbx+104],0
    jne .refused
    mov edx,11
    cmp qword [rbx+112],0
    jne .refused
    mov edx,12
    cmp qword [rbx+120],1
    jne .refused
    mov edx,13
    cmp qword [rbx+128],0
    jne .refused
    mov edx,14
    cmp qword [rbx+136],0
    jne .refused
    mov edx,15
    cmp qword [rbx+144],0
    jne .refused
    mov edx,16
    cmp qword [rbx+152],0
    jne .refused
    mov edx,17
    cmp qword [rbx+160],0
    jne .refused
    mov edx,18
    cmp qword [rbx+168],0
    jne .refused
    mov edx,19
    cmp qword [rbx+176],0
    jne .refused
    mov edx,20
    cmp qword [rbx+184],0
    jne .refused
    mov edx,21
    cmp qword [rbx+192],0
    jne .refused
    mov edx,22
    cmp qword [rbx+200],0
    jne .refused
    mov edx,23
    cmp qword [rbx+208],0
    jne .refused
    mov edx,24
    cmp qword [rbx+216],0
    jne .refused
    xor eax,eax
    xor edx,edx
    jmp .result
.refused:
    mov eax,1
.result:
    mov [rbx+8],rax
    mov [rbx+16],rdx
    pop rbx
    ret
.invalid:
    mov eax,1
    mov edx,0xffffffff
    ret

; RDI actual staged handle, RSI requested 2MiB-shaped RAM (0=automatic).
; Automatic RAM = signed runtime floor + 4x verified bundle bytes, rounded
; up to 2MiB. The runtime recipe includes kernel expansion/initrd/working RAM.
; Bundle bytes get copying/parser workspace; neither caller nor guest sets pins.
; Returns a nonreused instance/0; the broker retains its original hard bounds.
; No allocation/clear loop hidden here. READY is published only by native tick.
; Negative admission is deny-only: withhold isolation from this request, never
; disable a live CPU/root, change the driver or borrow local OWNER authority.
; RDX=1 only when the exact current signed descriptor reached isolation refusal.
; Native service admission only; no command, guest setter or public PIO path.
; The signed bundle remains the original native job identity, never executed
; by the dedicated updater PID1. Absent reviewed runtime qualification refuses.
app_vm_updater_prepare:
%ifndef PAOS_UPDATER_RUNTIME_PROFILE_INC
    xor eax,eax
    ret
%else
    mov edx,3
    jmp avm_prepare_restricted
%endif
app_vm_prepare_without_isolation:
    xor edx,edx
    jmp avm_prepare_restricted
app_vm_prepare:
    mov edx,1
avm_prepare_restricted:
    push rbx
    push r12
    push r13
    push r14
    mov r14d,edx
    mov r12,rdi
    mov r13,rsi
    cmp qword [rel avm_state],AVM_EMPTY
    jne .bad
    cmp byte [rel avm_busy],0
    jne .bad
    call avm_local
    test eax,eax
    jz .bad
    test r12,r12
    jz .bad
    cmp qword [rel avm_instance],-2
    jae .bad
    mov eax,[rel avm_start]
    cmp eax,0xfffffffe
    jae .bad
    mov byte [rel avm_busy],1
    mov rdi,r12
    lea rsi,[rel avm_admission]
    mov edx,384
    call app_script_descriptor
    cmp eax,1
    jne .unlock_bad
    cmp qword [rel avm_admission],1
    jne .unlock_bad
    cmp r12,[rel avm_admission+8]
    jne .unlock_bad
    ; Shared actual admission floor. A verified file is not permission to run
    ; without its own isolated VM. Normal callers always request isolation;
    ; the deny-only entry cannot reach RAM acquisition or any VM publication.
    test r14d,1
    jz .isolation_bad
%ifdef PAOS_UPDATER_RUNTIME_PROFILE_INC
    cmp r14d,3
    jne .application_runtime
    call app_runtime_select_updater
    jmp .runtime_selected
.application_runtime:
    call app_runtime_select_application
.runtime_selected:
    cmp eax,1
    jne .unlock_bad
    cmp r14d,3
    jne .runtime_floor_ready
    call app_runtime_memory
    cmp rax,AVM_RAM_MIN
    jb .unlock_bad
    cmp rax,AVM_RAM_MAX
    ja .unlock_bad
    test r13,r13
    jz .runtime_floor_ready
    cmp r13,rax
    jb .unlock_bad
.runtime_floor_ready:
%endif
    test r13,r13
    jnz .ram_ready
    call app_runtime_memory
    cmp rax,AVM_RAM_MIN
    jb .unlock_bad
    cmp rax,AVM_RAM_MAX
    ja .unlock_bad
    mov r13,rax
    mov rax,[rel avm_admission+16]
    cmp rax,656
    jb .unlock_bad
    cmp rax,AVM_PAYLOAD_MAX
    ja .unlock_bad
    shl rax,2
    add r13,rax
    jc .unlock_bad
    add r13,0x1fffff
    jc .unlock_bad
    and r13,-0x200000
    cmp r13,AVM_RAM_MAX
    ja .unlock_bad
.ram_ready:
    mov rbx,[rel session_bound_pid]
    mov [rel avm_admission_owner],rbx
    mov rbx,[rel session_authority_epoch]
    mov [rel avm_admission_session],rbx
    mov [rel avm_admission_handle],r12
    inc qword [rel avm_instance]
    inc qword [rel avm_start]
    mov byte [rel avm_updater_valid],0
    mov byte [rel avm_updater_role],0
    cmp r14d,3
    jne .role_ready
    mov byte [rel avm_updater_role],1
.role_ready:
    mov qword [rel avm_state],AVM_PREPARING
    mov rdi,r13
    mov esi,[rel avm_start]
    call app_vm_memory_acquire
    cmp eax,1
    jne .no_memory
    mov byte [rel avm_bound],0
    mov byte [rel avm_exit_open],0
    mov qword [rel avm_boot_phase],0
    mov qword [rel avm_runtime_gen],0
    call time_monotonic_now_us
    add rax,30000000
    jc .retire_bad
    mov [rel avm_prepare_deadline],rax
    mov byte [rel avm_busy],0
    mov rax,[rel avm_instance]
    jmp .out
.retire_bad:
    call avm_retire
    jmp .unlock_bad
.no_memory:
    mov qword [rel avm_state],AVM_EMPTY
.unlock_bad:
    mov byte [rel avm_busy],0
.bad:
    xor eax,eax
    xor edx,edx
    jmp .out
.isolation_bad:
    mov byte [rel avm_busy],0
    xor eax,eax
    mov edx,1
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; The first and every following native operation remains bound to the actual
; unlocked session and exact staged descriptor, including during initial scrub.
avm_admission_current:
    cmp byte [rel session_locked],SESSION_UNLOCKED
    jne .bad
    cmp qword [rel session_key_handle],0
    je .bad
    mov rax,[rel avm_admission_owner]
    test rax,rax
    jz .bad
    cmp rax,[rel session_bound_pid]
    jne .bad
    mov rax,[rel avm_admission_session]
    test rax,rax
    jz .bad
    cmp rax,-1
    je .bad
    cmp rax,[rel session_authority_epoch]
    jne .bad
    cmp rax,[rel session_authority]
    jne .bad
    mov rdi,[rel avm_admission_handle]
    lea rsi,[rel avm_admission_check]
    mov edx,384
    call app_script_native_descriptor
    cmp eax,1
    jne .bad
    lea rdi,[rel avm_admission]
    lea rsi,[rel avm_admission_check]
    mov ecx,384/8
    cld
    repe cmpsq
    jne .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Pure native admission floor, never used by readonly proof getters.
avm_local:
    cmp dword [rel cmd_dispatch_depth],0
    jne .bad
    cmp byte [rel command_auth_remote_active],0
    jne .bad
    call smp_current_logical
    test eax,eax
    jnz .bad
    call session_shell_local_authority
    test rax,rax
    setnz al
    movzx eax,al
    ret
.bad:
    xor eax,eax
    ret

; RDI instance ->1 actual READY activation /0. No implicit grant or form load.
app_vm_activate:
    push rbx
    mov rbx,rdi
    cmp byte [rel avm_busy],0
    jne .bad
    cmp qword [rel avm_state],AVM_READY
    jne .bad
    cmp rbx,[rel avm_instance]
    jne .bad
    call avm_local
    test eax,eax
    jz .bad
    mov rdi,rbx
    lea rsi,[rel avm_snapshot_check]
    mov edx,128
    call app_vm_snapshot
    cmp eax,1
    jne .bad
    call app_vm_payload_hash
    cmp eax,1
    jne .retire
    call app_vm_boot_current
    cmp eax,1
    jne .retire
    mov qword [rel avm_state],AVM_RUNNING
    mov eax,1
    pop rbx
    ret
.retire:
    call avm_retire
.bad:
    xor eax,eax
    pop rbx
    ret

; Trusted native retained recipient snapshot128 ONLY, never a guest/public
; stop or new admission. RDI original128, ESI128 ->1 contained /0 refused.
; Revocation works after OWNER/binding loss and inside an already closed native
; app exit (avm_busy may be1). Original CPU/root custody is retired before any
; return claiming1. Unknown custody takes the unchanged terminal CPU stop.
; No yield, CPU entry, synchronous scrub/free or replacement fallback.
app_vm_recipient_revoke:
    push rbx
    mov rbx,rdi
    test rbx,rbx
    jz .bad
    cmp esi,128
    jne .bad
    call smp_current_logical
    test eax,eax
    jnz .bad
    cmp qword [rbx],1
    jne .bad
    lea rax,[rel app_vm_endpoint]
    cmp [rbx+16],rax
    jne .bad
    mov rax,[rbx+56]
    test rax,rax
    jz .bad
    cmp rax,[rel avm_instance]
    jne .bad
    mov rax,[rbx+24]
    test rax,rax
    jz .bad
    cmp rax,[rel avm_start]
    jne .bad
    mov rax,[rel avm_state]
    cmp rax,AVM_EMPTY
    je .closed
    cmp rax,AVM_SCRUBBING
    je .closed
    cmp rax,AVM_READY
    je .retire
    cmp rax,AVM_RUNNING
    jne .bad
.retire:
    call avm_retire
.closed:
    ; Also validate repeat/after-scrub observations; no unknown means inactive.
    cmp qword [rel avm_cpu_live],0
    jne app_vm_cpu_stop
    cmp qword [rel avm_roots_retired],1
    jne app_vm_cpu_stop
    cmp qword [rel avm_svm+VSP_LIVE],0
    jne app_vm_cpu_stop
    cmp qword [rel avm_svm+VSP_ACTIVE],0
    jne app_vm_cpu_stop
    cmp byte [rel avmi_selected],0
    jne app_vm_cpu_stop
    cmp qword [rel avm_cpu_ready],0
    jne app_vm_cpu_stop
    cmp byte [rel avm_bound],0
    jne .bad
    cmp byte [rel avm_exit_open],0
    jne .bad
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; Local OWNER instance-specific stop. Internal revoke needs no local admission.
app_vm_stop:
    push rbx
    mov rbx,rdi
    cmp byte [rel avm_busy],0
    jne .bad
    cmp rbx,[rel avm_instance]
    jne .bad
    test rbx,rbx
    jz .bad
    call avm_local
    test eax,eax
    jz .bad
    call avm_retire
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; Exact native removal observation. RDI mapped caller-owned digest32, RSI
; current nonzero owner epoch -> EAX1 retired/absent,2 pending,0 refused.
; Mapping is the trusted native caller's contract; reject wrap, noncanonical
; spans and both VM reservations before reading. No grant/persistence effects.
; Captured digest/owner/session/instance/START survives scrub until terminal1.
; A pending continuation never follows a replacement, even the same digest.
; Terminal1 ends the capsule: the captain stops polling that operation, and a
; later fresh confirmed REMOVING may capture a new same-digest instance.
; Progress is ONLY the existing cooperative tick, never a synchronous scrub.
app_vm_quiesce:
    cld
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,32
    mov r12,rdi
    mov r13,rsi
    xor r15d,r15d
    cmp byte [rel avm_busy],0
    jne .bad
    call avm_local
    test eax,eax
    jz .bad
    test r13,r13
    jz .bad
    cmp r13,-1
    je .bad
    cmp r13,[rel session_authority_epoch]
    jne .bad
    mov rbx,[rel session_bound_pid]
    test r12,r12
    jz .bad
    mov r14,r12
    add r14,32
    jc .bad
    mov rax,r12
    shl rax,16
    sar rax,16
    cmp rax,r12
    jne .bad
    lea rax,[r14-1]
    mov rdx,rax
    shl rax,16
    sar rax,16
    cmp rax,rdx
    jne .bad
    mov rdx,[rel avm_base]
    mov rcx,[rel avm_capacity]
    call avm_quiesce_disjoint
    test eax,eax
    jz .bad
    mov rdx,[rel hv_linux_region]
    mov rcx,[rel hv_linux_region_capacity]
    call avm_quiesce_disjoint
    test eax,eax
    jz .bad
    lea rdx,[rel avm_quiesce_private_begin]
    mov ecx,avm_quiesce_private_end-avm_quiesce_private_begin
    call avm_quiesce_disjoint
    test eax,eax
    jz .bad
    mov rsi,r12
    mov rdi,rsp
    mov ecx,4
    rep movsq
    ; First test a retained continuation, before deciding the requested digest
    ; is absent. Changed instance/START is a refusal, never a new stop target.
    cmp byte [rel avm_quiesce_valid],1
    jne .lookup
    cmp rbx,[rel avm_quiesce_owner]
    jne .lookup
    cmp r13,[rel avm_quiesce_epoch]
    jne .lookup
    mov rdi,rsp
    lea rsi,[rel avm_quiesce_digest]
    mov ecx,4
    repe cmpsq
    jne .lookup
    mov rax,[rel avm_instance]
    cmp rax,[rel avm_quiesce_instance]
    jne .bad
    mov eax,[rel avm_start]
    cmp eax,[rel avm_quiesce_start]
    jne .bad
    mov r15d,1
    jmp .matched
.lookup:
    cmp qword [rel avm_state],AVM_EMPTY
    je .empty
    mov rdi,rsp
    lea rsi,[rel avm_admission+32]
    mov ecx,4
    repe cmpsq
    jne .absent
    cmp rbx,[rel avm_admission_owner]
    jne .bad
    cmp r13,[rel avm_admission_session]
    jne .bad
    cmp qword [rel avm_instance],0
    je .bad
    cmp dword [rel avm_start],0
    je .bad
    mov rsi,rsp
    lea rdi,[rel avm_quiesce_digest]
    mov ecx,4
    rep movsq
    mov [rel avm_quiesce_owner],rbx
    mov [rel avm_quiesce_epoch],r13
    mov rax,[rel avm_instance]
    mov [rel avm_quiesce_instance],rax
    mov eax,[rel avm_start]
    mov [rel avm_quiesce_start],eax
    mov byte [rel avm_quiesce_valid],1
    mov r15d,1
.matched:
    cmp rbx,[rel avm_admission_owner]
    jne .bad
    cmp r13,[rel avm_admission_session]
    jne .bad
    mov rdi,rsp
    lea rsi,[rel avm_admission+32]
    mov ecx,4
    repe cmpsq
    jne .bad
    mov rax,[rel avm_state]
    cmp rax,AVM_EMPTY
    je .empty
    cmp rax,AVM_RETIRING
    je .pending
    cmp rax,AVM_SCRUBBING
    je .pending
    cmp rax,AVM_PREPARING
    jb .bad
    cmp rax,AVM_RUNNING
    ja .bad
    mov byte [rel avm_busy],1
    call avm_retire
    mov byte [rel avm_busy],0
.pending:
    mov eax,2
    jmp .out
.empty:
    ; EMPTY alone is not proof of release if any custody marker remains.
    cmp qword [rel avm_token],0
    jne .bad
    cmp qword [rel avm_base],0
    jne .bad
    cmp qword [rel avm_capacity],0
    jne .bad
    cmp qword [rel avm_ram],0
    jne .bad
    cmp qword [rel avm_ram_bytes],0
    jne .bad
    cmp qword [rel avm_root],0
    jne .bad
    cmp qword [rel avm_cpu_ready],0
    jne .bad
    cmp qword [rel avm_cpu_live],0
    jne .bad
    cmp qword [rel avm_roots_retired],1
    jne .bad
    cmp byte [rel avm_bound],0
    jne .bad
    cmp byte [rel avm_exit_open],0
    jne .bad
    cmp byte [rel avm_payload_valid],0
    jne .bad
    test r15d,r15d
    jz .absent
    mov byte [rel avm_quiesce_valid],0
.absent:
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    add rsp,32
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    cld
    ret

; R12..R14 request half-open span; RDX/RCX excluded base/capacity.
; Invalid reservation geometry is refused without dereferencing the request.
avm_quiesce_disjoint:
    test rcx,rcx
    jz .yes
    test rdx,rdx
    jz .bad
    add rcx,rdx
    jc .bad
    cmp r14,rdx
    jbe .yes
    cmp r12,rcx
    jb .bad
.yes:
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Invalidate authority FIRST, then CPU/root retirement, then bounded full scrub.
; An uncertain live CPU/root is terminal and retains its broker record.
avm_retire:
    mov byte [rel avm_exit_open],0
    cmp qword [rel avm_state],AVM_EMPTY
    je .out
    cmp qword [rel avm_state],AVM_SCRUBBING
    je .out
    cmp qword [rel avm_state],AVM_FAULT
    je .out
    mov qword [rel avm_state],AVM_RETIRING
    cmp byte [rel avm_bound],1
    jne .payload
    call guest_request_retire
    mov byte [rel avm_bound],0
.payload:
    call app_vm_payload_retire
    call app_vm_cpu_retire
    cmp eax,1
    jne app_vm_cpu_stop
    ; Native device/console staging lives outside the broker span. Wipe it
    ; only after authority and CPU custody close, before returning to the UI.
    call app_vm_devices_init
    mov qword [rel avm_boot_phase],0
    mov qword [rel avm_runtime_gen],0
    mov qword [rel avm_clear_offset],0
    mov qword [rel avm_state],AVM_SCRUBBING
.out:
    ret

; Main loop depth0 only. <=1MiB clear/read OR <=64 closed CPU turns in
; 2ms (+ at most one already entered backend turn). Every reentry checks
; original admission/binding/runtime. Input and recovery run between batches.
app_vm_tick:
    cmp byte [rel avm_busy],0
    jne .out
    cmp dword [rel cmd_dispatch_depth],0
    jne .out
    cmp byte [rel command_auth_remote_active],0
    jne .out
    push rbx
    push r12
    push r13
    call smp_current_logical
    test eax,eax
    jnz .pop
    mov byte [rel avm_busy],1
    mov byte [rel avm_exit_open],0
    call app_network_tick              ; original network retirement, even EMPTY
    mov ebx,64
    call time_monotonic_now_us
    add rax,2000
    jc .retire
    mov r13,rax
    cmp qword [rel avm_state],AVM_EMPTY
    je .done
    cmp qword [rel avm_state],AVM_FAULT
    je .done
    cmp qword [rel avm_state],AVM_SCRUBBING
    je .scrub
    call avm_admission_current
    cmp eax,1
    jne .retire
    mov rax,[rel avm_state]
    cmp rax,AVM_READY
    je .check_binding
    cmp rax,AVM_RUNNING
    je .check_binding
    call time_monotonic_now_us
    cmp rax,[rel avm_prepare_deadline]
    jae .retire
    cmp qword [rel avm_state],AVM_PREPARING
    jne .loading
    call app_vm_memory_clear
    cmp eax,2
    je .done
    cmp eax,1
    jne .retire
    mov qword [rel avm_state],AVM_LOADING
    mov rdi,[rel avm_admission_handle]
    call app_vm_payload_load
    cmp eax,1
    jne .retire
    call app_vm_boot_begin
    cmp eax,1
    jne .retire
    jmp .done
.loading:
    cmp qword [rel avm_state],AVM_LOADING
    jne .retire
    call app_vm_boot_tick
    cmp eax,2
    je .done
    cmp eax,1
    jne .retire
    ; Actual backend preparation requires IF0. Preserve the native caller's
    ; flags; normal restore is reachable only after CPU/root custody retired.
    pushfq
    pop r12
    cli
    call app_vm_cpu_prepare
    mov ebx,eax
    push r12
    popfq
    cmp ebx,1
    jne .retire
    call avm_ready_publish
    cmp eax,1
    jne .retire
    jmp .done
.check_binding:
    mov rdi,[rel avm_instance]
    lea rsi,[rel avm_snapshot_check]
    mov edx,128
    call app_vm_snapshot
    cmp eax,1
    jne .retire
    call app_vm_boot_current
    cmp eax,1
    jne .retire
    cmp qword [rel avm_state],AVM_READY
    je .done
.guest_turn:
    call app_vm_devices_poll
    cmp byte [rel avm_dispatch_fault],0
    jne .retire
    test eax,eax
    jz .done
    pushfq
    pop r12
    cli
    call app_vm_cpu_turn
    push r12
    popfq
    cmp eax,1
    jne .retire
    mov byte [rel avm_exit_open],1
    call app_vm_dispatch
    mov byte [rel avm_exit_open],0
    cmp eax,1
    jne .retire
    dec ebx
    jz .done
    call time_monotonic_now_us
    cmp rax,r13
    jae .done
    call avm_admission_current
    cmp eax,1
    jne .retire
    jmp .check_binding
.retire:
    call avm_retire
    jmp .done
.scrub:
    call app_vm_memory_clear
    cmp eax,2
    je .done
    cmp eax,1
    jne .fault
    call app_vm_memory_release
    cmp eax,1
    jne .fault
    mov qword [rel avm_state],AVM_EMPTY
    mov byte [rel avm_bound],0
    ; Keep last instance solely for status(EMPTY). No authority getter accepts
    ; EMPTY, and the next prepare increments instance and START without reuse.
    jmp .done
.fault:
    mov qword [rel avm_state],AVM_FAULT
.done:
    mov byte [rel avm_exit_open],0
    mov byte [rel avm_busy],0
.pop:
    pop r13
    pop r12
    pop rbx
.out:
    ret

; Read-only native idle hint, never an authorization or guest wakeup. The
; device poll in tick alone wakes an actual guest HLT on its virtual IRQ.
; Preparation/loading/scrubbing also have bounded work ready for the next sweep.
app_vm_runnable:
    cmp byte [rel avm_busy],0
    jne .bad
    cmp dword [rel cmd_dispatch_depth],0
    jne .bad
    cmp byte [rel command_auth_remote_active],0
    jne .bad
    push rbx
    call smp_current_logical
    test eax,eax
    jnz .pop_bad
    mov rbx,[rel avm_state]
    cmp rbx,AVM_SCRUBBING
    je .yes
    cmp rbx,AVM_PREPARING
    je .admit
    cmp rbx,AVM_LOADING
    je .admit
    cmp rbx,AVM_RUNNING
    jne .pop_bad
    cmp byte [rel avm_halted],0
    jne .pop_bad
.admit:
    call avm_admission_current
    cmp eax,1
    jne .pop_bad
.yes:
    mov eax,1
    pop rbx
    ret
.pop_bad:
    pop rbx
.bad:
    xor eax,eax
    ret

; Closed native preparation completion. No CPU entry or grant; actual backend
; must already have produced READY state, and source/runtime remain current.
avm_ready_publish:
    cmp qword [rel avm_state],AVM_LOADING
    jne .bad
    cmp qword [rel avm_cpu_ready],1
    jne .bad
    cmp qword [rel avm_cpu_live],0
    jne .bad
    cmp qword [rel avm_roots_retired],1
    jne .bad
    cmp qword [rel avm_boot_phase],5
    jne .bad
    call app_vm_payload_current
    cmp eax,1
    jne .bad
    call app_vm_boot_current
    cmp eax,1
    jne .bad
    call app_vm_devices_init
    mov qword [rel avm_state],AVM_READY
    lea rdi,[rel app_vm_endpoint]
    mov esi,[rel avm_start]
    call guest_request_bind
    test rax,rax
    jz .bad
    mov byte [rel avm_bound],1
    lea rdi,[rel app_vm_endpoint]
    mov esi,[rel avm_start]
    lea rdx,[rel avm_binding]
    mov ecx,48
    call guest_request_binding_copy
    ret
.bad:
    xor eax,eax
    ret

; Native status, no admission/authority. Exact last instance includes EMPTY.
app_vm_status:
    test rdi,rdi
    jz .bad
    cmp rdi,[rel avm_instance]
    jne .bad
    mov rax,[rel avm_state]
    ret
.bad:
    mov rax,-1
    ret

; Endpoint native liveness, independent of adapter binding for initial bind.
; RDI exact endpoint, ESI START ->EAX1/0, ALL other registers preserved.
app_vm_endpoint_current:
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    lea rax,[rel app_vm_endpoint]
    cmp rdi,rax
    jne .bad
    test esi,esi
    jz .bad
    cmp esi,[rel avm_start]
    jne .bad
    mov rax,[rel avm_state]
    cmp rax,AVM_READY
    je .state
    cmp rax,AVM_RUNNING
    jne .bad
.state:
    cmp qword [rel avm_instance],0
    je .bad
    cmp qword [rel avm_cpu_ready],1
    jne .bad
    cmp qword [rel avm_cpu_live],0
    jne .bad
    cmp qword [rel avm_roots_retired],1
    jne .bad
    call app_vm_payload_current
    cmp eax,1
    jne .bad
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

; RDI instance, RSI native output, EDX exact128 ->1/0. No grant/yield/entry.
; The full binding and bundle proof are copied from actual native producers.
app_vm_snapshot:
    push rbx
    push r12
    mov r12,rsi
    cmp edx,128
    jne .bad
    test r12,r12
    jz .bad
    mov rax,r12
    add rax,128
    jc .bad
    test rdi,rdi
    jz .bad
    cmp rdi,[rel avm_instance]
    jne .bad
    cmp byte [rel avm_bound],1
    jne .bad
    lea rdi,[rel app_vm_endpoint]
    mov esi,[rel avm_start]
    lea rdx,[rel avm_binding_check]
    mov ecx,48
    call guest_request_binding_copy
    cmp eax,1
    jne .bad
    lea rdi,[rel avm_binding]
    lea rsi,[rel avm_binding_check]
    mov ecx,6
    cld
    repe cmpsq
    jne .bad
    mov rbx,[rel avm_base]
    mov qword [r12],1
    mov rax,[rel avm_binding]
    mov [r12+8],rax
    lea rax,[rel app_vm_endpoint]
    mov [r12+16],rax
    mov rax,[rel avm_start]
    mov [r12+24],rax
    mov rax,[rel avm_binding+32]
    mov [r12+32],rax
    mov rax,[rel avm_session]
    mov [r12+40],rax
    mov rax,[rel avm_owner]
    mov [r12+48],rax
    mov rax,[rel avm_instance]
    mov [r12+56],rax
    mov rax,[rbx+AVM_DESCRIPTOR+32]
    mov [r12+64],rax
    mov rax,[rbx+AVM_DESCRIPTOR+40]
    mov [r12+72],rax
    mov rax,[rbx+AVM_DESCRIPTOR+48]
    mov [r12+80],rax
    mov rax,[rbx+AVM_DESCRIPTOR+56]
    mov [r12+88],rax
    mov rax,[rel avm_handle]
    mov [r12+96],rax
    mov rax,[rel avm_runtime_gen]
    mov [r12+104],rax
    mov qword [r12+112],0
    mov qword [r12+120],0
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r12
    pop rbx
    ret

; Only while the actual app exit is closed and its native dispatcher owns it.
; A stopped READY VM, driver exit, host caller or guest assertion gets zero.
app_vm_exit_endpoint:
    cmp byte [rel avm_exit_open],1
    jne .bad
    cmp qword [rel avm_state],AVM_RUNNING
    jne .bad
    push rdi
    push rsi
    lea rdi,[rel app_vm_endpoint]
    mov esi,[rel avm_start]
    call app_vm_endpoint_current
    pop rsi
    pop rdi
    test eax,eax
    jz .bad
    lea rax,[rel app_vm_endpoint]
    mov edx,[rel avm_start]
    ret
.bad:
    xor eax,eax
    xor edx,edx
    ret

; All updater queries use native mapped buffers, exact128; refusal leaves
; caller output untouched. Identity is the original snapshot128, including
; immutable bundle identity and nonreused instance/START/runtime generation.
; Runtime trust is the signed dedicated PID1 pair, never a guest PID assertion.
app_vm_updater_exit:
    push rbx
    mov rbx,rdi
    call avm_updater_buffer
    cmp eax,1
    jne .bad
    call avm_updater_observe
    cmp eax,1
    jne .bad
    cmp byte [rel avm_updater_valid],1
    jne .capture
    lea rdi,[rel avm_updater_check]
    call avm_updater_equal
    cmp eax,1
    jne .bad
    jmp .copy
.capture:
    lea rdi,[rel avm_updater_identity]
    lea rsi,[rel avm_updater_check]
    mov ecx,16
    cld
    rep movsq
    mov byte [rel avm_updater_valid],1
.copy:
    mov rdi,rbx
    lea rsi,[rel avm_updater_identity]
    mov ecx,16
    cld
    rep movsq
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; Native BSP-only observation, outside guest dispatch. RDI native output128,
; ESI exact128 ->1 same current run /2 exact stopped root /0 unknown/refused.
; Original identity MUST have been captured by the qualified closed exit.
; This getter cannot mint that identity or authorize IO, completion or custody.
; Output is unchanged on refusal; private/VM aliases use the same span guard.
app_vm_updater_observe_idle:
%ifndef PAOS_UPDATER_RUNTIME_PROFILE_INC
    xor eax,eax
    ret
%else
    push rbx
    sub rsp,128
    mov rbx,rdi
    call avm_updater_buffer
    cmp eax,1
    jne .bad
    call smp_current_logical
    test eax,eax
    jnz .bad
    cmp byte [rel avm_updater_valid],1
    jne .bad
    cmp byte [rel avm_updater_role],1
    jne .bad
    cmp byte [rel avm_busy],0
    jne .bad
    ; A stack copy passes the existing stopped-root input-span guard without
    ; exposing the private identity or writing the proposed output early.
    mov rdi,rsp
    lea rsi,[rel avm_updater_identity]
    mov ecx,16
    cld
    rep movsq
    mov rdi,rsp
    mov esi,128
    call app_vm_updater_stopped
    cmp eax,1
    je .stopped
    cmp byte [rel avm_exit_open],0
    jne .bad
    cmp qword [rel avm_state],AVM_RUNNING
    jne .bad
    cmp qword [rel avm_svm+VSP_ACTIVE],0
    jne .bad
    lea rdi,[rel app_vm_endpoint]
    mov esi,[rel avm_start]
    call app_vm_endpoint_current
    cmp eax,1
    jne .bad
    call app_vm_boot_current
    cmp eax,1
    jne .bad
    mov rdi,[rel avm_runtime_gen]
    call app_runtime_updater_current
    cmp eax,1
    jne .bad
    mov rdi,[rel avm_instance]
    lea rsi,[rel avm_updater_check]
    mov edx,128
    call app_vm_snapshot
    cmp eax,1
    jne .bad
    lea rdi,[rel avm_updater_check]
    call avm_updater_equal
    cmp eax,1
    jne .bad
    mov edx,1
    jmp .copy
.stopped:
    mov edx,2
.copy:
    mov rdi,rbx
    lea rsi,[rel avm_updater_identity]
    mov ecx,16
    cld
    rep movsq
    mov eax,edx
    jmp .out
.bad:
    xor eax,eax
.out:
    add rsp,128
    pop rbx
    ret
%endif

; Passive native dispatch classification only, never a currentness grant.
; Exact0 ordinary,1 retained updater; any other value remains unknown/denied.
; Independent original128/40 and runtime checks remain mandatory for all IO.
app_vm_updater_role:
    movzx eax,byte [rel avm_updater_role]
    ret

; Per-effect authority: actual current qualified runtime AND exact original
; recipient AND the original closed VM exit. A cached receipt alone grants0.
app_vm_updater_current:
    push rbx
    mov rbx,rdi
    call avm_updater_buffer
    cmp eax,1
    jne .bad
    mov rdi,rbx
    call avm_updater_equal
    cmp eax,1
    jne .bad
    call avm_updater_observe
    cmp eax,1
    jne .bad
    lea rdi,[rel avm_updater_check]
    call avm_updater_equal
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; Retained identity can contain its own original CPU even after session loss.
; Existing recipient retirement closes binding/CPU/root before returning1.
; No replacement fallback, retry, synchronous wipe or memory-free assertion.
app_vm_updater_revoke:
    push rbx
    mov rbx,rdi
    call avm_updater_buffer
    cmp eax,1
    jne .bad
    mov rdi,rbx
    call avm_updater_equal
    cmp eax,1
    jne .bad
    cmp byte [rel avm_updater_role],1
    jne .bad
    mov rdi,rbx
    mov esi,128
    call app_vm_recipient_revoke
    cmp eax,1
    jne .bad
    mov rdi,rbx
    mov esi,128
    call app_vm_updater_stopped
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; Passive exact stopped-root receipt. SCRUBBING is permitted; memory custody
; remains owned until ordinary tick actually wipes/releases it. Unknown denies.
app_vm_updater_stopped:
    push rbx
    mov rbx,rdi
    call avm_updater_buffer
    cmp eax,1
    jne .bad
    mov rdi,rbx
    call avm_updater_equal
    cmp eax,1
    jne .bad
    call smp_current_logical
    test eax,eax
    jnz .bad
    cmp byte [rel avm_updater_role],1
    jne .bad
    mov rax,[rbx+56]
    cmp rax,[rel avm_instance]
    jne .bad
    mov rax,[rbx+24]
    cmp rax,[rel avm_start]
    jne .bad
    mov rax,[rel avm_state]
    cmp rax,AVM_EMPTY
    je .closed
    cmp rax,AVM_SCRUBBING
    jne .bad
.closed:
    cmp qword [rel avm_cpu_live],0
    jne .bad
    cmp qword [rel avm_roots_retired],1
    jne .bad
    cmp qword [rel avm_svm+VSP_LIVE],0
    jne .bad
    cmp qword [rel avm_svm+VSP_ACTIVE],0
    jne .bad
    cmp byte [rel avmi_selected],0
    jne .bad
    cmp qword [rel avm_cpu_ready],0
    jne .bad
    cmp byte [rel avm_bound],0
    jne .bad
    cmp byte [rel avm_exit_open],0
    jne .bad
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; Actual current closed exit plus runtime role and loader revalidation.
; Original boot descriptor is compared by the unchanged native boot producer.
avm_updater_observe:
%ifndef PAOS_UPDATER_RUNTIME_PROFILE_INC
    xor eax,eax
    ret
%else
    sub rsp,8
    cmp byte [rel avm_updater_role],1
    jne .bad
    call smp_current_logical
    test eax,eax
    jnz .bad
    call app_vm_exit_endpoint
    test rax,rax
    jz .bad
    call app_vm_boot_current
    cmp eax,1
    jne .bad
    mov rdi,[rel avm_runtime_gen]
    call app_runtime_updater_current
    cmp eax,1
    jne .bad
    mov rdi,[rel avm_instance]
    lea rsi,[rel avm_updater_check]
    mov edx,128
    call app_vm_snapshot
    cmp eax,1
    jne .bad
    add rsp,8
    ret
.bad:
    xor eax,eax
    add rsp,8
    ret
%endif

; Compare every byte of the retained original, never just a caller tuple.
avm_updater_equal:
    cmp byte [rel avm_updater_valid],1
    jne .bad
    lea rsi,[rel avm_updater_identity]
    mov ecx,16
    cld
    repe cmpsq
    jne .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Reject wrap/noncanonical/VM-memory/native-private aliases before dereference.
; Mapping outside these protected spans is the trusted native caller contract.
avm_updater_buffer:
    push r12
    push r14
    mov r12,rdi
    cmp esi,128
    jne .bad
    test r12,r12
    jz .bad
    mov r14,r12
    add r14,128
    jc .bad
    mov rax,r12
    shl rax,16
    sar rax,16
    cmp rax,r12
    jne .bad
    lea rdx,[r14-1]
    mov rax,rdx
    shl rax,16
    sar rax,16
    cmp rax,rdx
    jne .bad
    mov rdx,[rel avm_base]
    mov rcx,[rel avm_capacity]
    call avm_quiesce_disjoint
    test eax,eax
    jz .bad
    mov rdx,[rel hv_linux_region]
    mov rcx,[rel hv_linux_region_capacity]
    call avm_quiesce_disjoint
    test eax,eax
    jz .bad
    lea rdx,[rel avm_private_begin]
    mov ecx,avm_private_end-avm_private_begin
    call avm_quiesce_disjoint
    test eax,eax
    jz .bad
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    mov rdi,r12
    pop r14
    pop r12
    ret

%include "core/abi/wdata.inc"
%macro WDATA_hv_app_vm 0
align 8
avm_private_begin:
app_vm_endpoint: dq 0x31564d5050414150
avm_instance: dq 0
avm_admission_handle: dq 0
avm_admission_owner: dq 0
avm_admission_session: dq 0
avm_prepare_deadline: dq 0
avm_admission: times 384 db 0
avm_admission_check: times 384 db 0
avm_binding: times 48 db 0
avm_binding_check: times 48 db 0
avm_snapshot_check: times 128 db 0
avm_quiesce_private_begin:
avm_quiesce_digest: times 32 db 0
avm_quiesce_owner: dq 0
avm_quiesce_epoch: dq 0
avm_quiesce_instance: dq 0
avm_quiesce_start: dd 0
avm_quiesce_valid: db 0
avm_quiesce_private_end:
avm_busy: db 0
avm_bound: db 0
avm_exit_open: db 0
avm_updater_role: db 0
avm_updater_valid: db 0
align 8
avm_updater_identity: times 128 db 0
avm_updater_check: times 128 db 0
avm_private_end:
%endmacro
WDATA_DEFER WDATA_hv_app_vm
