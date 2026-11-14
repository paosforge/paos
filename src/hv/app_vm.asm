;; MODULE hv/app_vm
;; LAYER 5
;; EXPORTS app_vm_runnable, app_vm_prepare, app_vm_activate, app_vm_stop, app_vm_tick, app_vm_status, app_vm_snapshot, app_vm_endpoint_current, app_vm_exit_endpoint, app_vm_endpoint, avm_instance
;; IMPORTS hv/app_runtime, hv/app_vm_memory, hv/app_vm_payload, hv/app_vm_boot, hv/app_vm_cpu, hv/app_vm_dispatch, hv/app_vm_devices, hv/guest_request, svc/app_script, core/time, core/smp, sec/session
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; One native instance, private CPU/RAM/devices and actual signed source bytes.
; Admission/setters require local OWNER; getters are non-yielding and grant-free
; because the actual GUES request resolver must read them during authorization.
%include "hv/app_vm.inc"

; RDI actual staged handle, RSI requested 2MiB-shaped RAM (0=automatic).
; Automatic RAM = signed runtime floor + 4x verified bundle bytes, rounded
; up to 2MiB. The runtime recipe includes kernel expansion/initrd/working RAM.
; Bundle bytes get copying/parser workspace; neither caller nor guest sets pins.
; Returns a nonreused instance/0; the broker retains its original hard bounds.
; No allocation/clear loop hidden here. READY is published only by native tick.
app_vm_prepare:
    push rbx
    push r12
    push r13
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
.out:
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

%include "core/abi/wdata.inc"
%macro WDATA_hv_app_vm 0
align 8
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
avm_busy: db 0
avm_bound: db 0
avm_exit_open: db 0
%endmacro
WDATA_DEFER WDATA_hv_app_vm
