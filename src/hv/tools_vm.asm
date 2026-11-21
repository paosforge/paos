;; MODULE hv/tools_vm
;; LAYER 5
;; EXPORTS tools_vm_prepare, tools_vm_activate, tools_vm_stop, tools_vm_tick, tools_vm_status, tools_vm_snapshot, tools_vm_snapshot_current, tools_vm_console_input, tools_vm_console_output, tools_vm_terminal_attach, tools_vm_terminal_status, tools_vm_terminal_poll, tools_vm_terminal_write, tools_vm_terminal_read, tools_vm_terminal_resize, tools_vm_terminal_detach
;; IMPORTS hv/tools_vm_memory, hv/tools_vm_cpu, hv/tools_vm_devices, hv/tools_vm_stream, hv/tools_vm_console, hv/tools_vm_mmio, hv/app_vm_memory, hv/vmx, sec/session, svc/command, svc/command_auth, core/smp, core/time
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Creator: Claude / rc-vm-claude. Native tools instance lifecycle and AV's
; broker snapshot/currentness facade. Admission and stop need the genuine
; local unlocked owner; owner/session are captured once at admission and
; every later operation rechecks them. Lock, owner or session change, STOP,
; deadline and every refusal retire through ONE path: authority first, the AV
; hostname stream fenced (AV's stream retire, via tools_vm_stream_retire) before CPU retirement,
; private device wipe, scrub and release. A new instance starts only after the
; stream has been fenced and wiped, with a strictly greater START that is
; never reset within a boot. No guest, remote or command request reaches any
; entry; the snapshot is values only and grants nothing. The console facade
; moves data bytes only, for the same admitted owner. D5a adds public
; Terminal's binding facade (tools_vm_terminal_*); its caller is D5c. No runtime loader exists in this slice: LOADING completes only when
; a later signed-runtime producer publishes boot phase 5.
%include "hv/tools_vm.inc"
%include "hv/tools_stream_abi.inc"
%include "core/abi/wdata.inc"

; Pure native admission floor: BSP, no command dispatch, remote request or
; injected input, unlocked keyed session ->RAX owner PID, RDX session /0/0.
tvm_local:
    cmp dword [rel cmd_dispatch_depth],0
    jne .bad
    cmp byte [rel command_auth_remote_active],0
    jne .bad
    sub rsp,8
    call smp_current_logical
    test eax,eax
    jnz .pop_bad
    call session_shell_local_authority
    add rsp,8
    ret
.pop_bad:
    add rsp,8
.bad:
    xor eax,eax
    xor edx,edx
    ret

; The captured owner/session is still the actual unlocked keyed session.
tvm_admission_current:
    cmp byte [rel session_locked],SESSION_UNLOCKED
    jne .bad
    cmp qword [rel session_key_handle],0
    je .bad
    mov rax,[rel tvm_owner]
    test rax,rax
    jz .bad
    cmp rax,[rel session_bound_pid]
    jne .bad
    mov rax,[rel tvm_session]
    test rax,rax
    jz .bad
    cmp rax,-1
    je .bad
    cmp rax,[rel session_authority_epoch]
    jne .bad
    cmp rax,[rel session_authority]
    jne .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; RDI native RAM choice (0 = 2GiB default, or exact 2/3GiB; never a guest,
; remote or command value) ->RAX new instance /0 unchanged. The AV stream is
; fenced and wiped BEFORE a START exists, so nothing from an earlier instance
; can reach this one. Instance and START exhaustion refuse rather than wrap.
tools_vm_prepare:
    push rbx
    push r12
    push r13
    mov r12,rdi
    test r12,r12
    jz .choice
    mov eax,TVM_RAM_DEFAULT
    cmp r12,rax
    je .choice
    mov eax,TVM_RAM_LARGE
    cmp r12,rax
    jne .bad
.choice:
    cmp qword [rel tvm_state],TVM_EMPTY
    jne .bad
    cmp byte [rel tvm_busy],0
    jne .bad
    call tvm_local
    test rax,rax
    jz .bad
    mov rbx,rax
    mov r13,rdx
    cmp qword [rel tvm_instance],-2
    jae .bad
    mov eax,0xfffffffe
    cmp [rel tvm_start],rax
    jae .bad
    mov byte [rel tvm_busy],1
    call tools_vm_stream_retire
    cmp eax,1
    jne .unlock_bad
    mov rsi,[rel tvm_start]
    inc rsi
    mov rdi,r12
    call tools_vm_memory_acquire
    cmp eax,1
    jne .unlock_bad
    ; The allocation now holds the new START; publish the identity with it.
    inc qword [rel tvm_instance]
    mov [rel tvm_owner],rbx
    mov [rel tvm_session],r13
    mov qword [rel tvm_boot_phase],0
    call time_monotonic_now_us
    mov rdx,TVM_PREPARE_US
    add rax,rdx
    jc .retire_bad
    mov [rel tvm_deadline],rax
    mov byte [rel tvm_busy],0
    mov rax,[rel tvm_instance]
    jmp .out
.retire_bad:
    call tvm_retire
.unlock_bad:
    mov byte [rel tvm_busy],0
.bad:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

; RDI exact instance ->1 READY published RUNNING /0. Local owner only.
tools_vm_activate:
    push rbx
    mov rbx,rdi
    cmp byte [rel tvm_busy],0
    jne .bad
    cmp qword [rel tvm_state],TVM_READY
    jne .bad
    test rbx,rbx
    jz .bad
    cmp rbx,[rel tvm_instance]
    jne .bad
    call tvm_local
    test rax,rax
    jz .bad
    call tvm_admission_current
    test eax,eax
    jz .bad
    cmp qword [rel tvm_serial],-2
    jae .bad
    mov rdi,[rel tvm_start]
    mov rsi,[rel tvm_token]
    call tvm_memory_stopped
    test eax,eax
    jz .bad
    inc qword [rel tvm_serial]
    mov qword [rel tvm_state],TVM_RUNNING
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; RDI exact instance ->1 retirement begun (or already closed) /0. Local only.
tools_vm_stop:
    push rbx
    mov rbx,rdi
    cmp byte [rel tvm_busy],0
    jne .bad
    test rbx,rbx
    jz .bad
    cmp rbx,[rel tvm_instance]
    jne .bad
    call tvm_local
    test rax,rax
    jz .bad
    call tvm_retire
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; RDI exact instance ->RAX state (including EMPTY after release) /-1.
tools_vm_status:
    test rdi,rdi
    jz .bad
    cmp rdi,[rel tvm_instance]
    jne .bad
    mov rax,[rel tvm_state]
    ret
.bad:
    mov rax,-1
    ret

; Authority first (RUNNING/exit closed), then the AV stream fence. Only a
; fenced stream lets CPU retirement, device wipe and scrub proceed; an
; unfenced one stays RETIRING (no turn, no exit, allocation held) and every
; later tick retries the fence. Uncertain CPU custody is the terminal stop.
tvm_retire:
    mov byte [rel tvm_exit_open],0
    mov rax,[rel tvm_state]
    cmp rax,TVM_EMPTY
    je .out
    cmp rax,TVM_SCRUBBING
    je .out
    cmp rax,TVM_FAULT
    je .out
    mov qword [rel tvm_state],TVM_RETIRING
    sub rsp,8
    call tools_vm_stream_retire
    cmp eax,1
    jne .pop_out
    mov rdi,[rel tvm_start]
    mov rsi,[rel tvm_token]
    call tools_vm_cpu_retire
    cmp eax,1
    jne tools_vm_cpu_stop
    mov rdi,[rel tvm_start]
    mov rsi,[rel tvm_token]
    call tools_vm_devices_reset
    cmp eax,1
    jne .fault
    mov rdi,[rel tvm_start]
    mov rsi,[rel tvm_token]
    call tools_vm_memory_scrub
    cmp eax,1
    jne .fault
    mov qword [rel tvm_boot_phase],0
    jmp .pop_out
.fault:
    mov qword [rel tvm_state],TVM_FAULT
.pop_out:
    add rsp,8
.out:
    ret

; Main loop depth 0 only. <=1MiB clear OR <=64 closed tools CPU turns in
; 2ms. Owner/session/lock is rechecked before the first and every later turn;
; any loss retires before the next tools effect.
tools_vm_tick:
    cmp byte [rel tvm_busy],0
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
    mov byte [rel tvm_busy],1
    mov byte [rel tvm_exit_open],0
    mov ebx,TVM_TURNS
    call time_monotonic_now_us
    add rax,TVM_TURN_US
    jc .retire
    mov r13,rax
    mov rax,[rel tvm_state]
    cmp rax,TVM_EMPTY
    je .done
    cmp rax,TVM_FAULT
    je .done
    cmp rax,TVM_SCRUBBING
    je .scrub
    cmp rax,TVM_RETIRING
    je .retire
    call tvm_admission_current
    cmp eax,1
    jne .retire
    mov rax,[rel tvm_state]
    cmp rax,TVM_READY
    je .done
    cmp rax,TVM_RUNNING
    je .turn
    call time_monotonic_now_us
    cmp rax,[rel tvm_deadline]
    jae .retire
    cmp qword [rel tvm_state],TVM_PREPARING
    jne .loading
    mov rdi,[rel tvm_start]
    mov rsi,[rel tvm_token]
    call tools_vm_memory_clear
    cmp eax,2
    je .done
    cmp eax,1
    jne .retire
    mov rdi,[rel tvm_start]
    mov rsi,[rel tvm_token]
    call tools_vm_memory_load
    cmp eax,1
    jne .retire
    jmp .done
.loading:
    cmp qword [rel tvm_state],TVM_LOADING
    jne .retire
    cmp qword [rel tvm_boot_phase],5
    jne .done                           ; the signed-runtime producer owns boot
    pushfq
    pop r12
    cli
    mov rdi,[rel tvm_start]
    mov rsi,[rel tvm_token]
    call tools_vm_cpu_prepare
    mov ebx,eax
    push r12
    popfq
    cmp ebx,1
    jne .retire
    call tvm_ready_publish
    cmp eax,1
    jne .retire
    jmp .done
.turn:
    mov rdi,[rel tvm_start]
    mov rsi,[rel tvm_token]
    call tools_vm_devices_turn
    cmp eax,2
    je .done
    cmp eax,1
    jne .retire
    dec ebx
    jz .done
    call time_monotonic_now_us
    cmp rax,r13
    jae .done
    call tvm_admission_current
    cmp eax,1
    jne .retire
    cmp qword [rel tvm_state],TVM_RUNNING
    jne .retire
    jmp .turn
.retire:
    call tvm_retire
    jmp .done
.scrub:
    mov rdi,[rel tvm_start]
    mov rsi,[rel tvm_token]
    call tools_vm_memory_clear
    cmp eax,2
    je .done
    cmp eax,1
    jne .fault
    mov rdi,[rel tvm_start]
    mov rsi,[rel tvm_token]
    call tools_vm_memory_release
    cmp eax,1
    jne .fault
    ; Keep instance/START/serial for status and nonreuse; drop the binding.
    mov qword [rel tvm_owner],0
    mov qword [rel tvm_session],0
    mov qword [rel tvm_deadline],0
    jmp .done
.fault:
    mov qword [rel tvm_state],TVM_FAULT
.done:
    mov byte [rel tvm_exit_open],0
    mov byte [rel tvm_busy],0
.pop:
    pop r13
    pop r12
    pop rbx
.out:
    ret

; LOADING with the CPU prepared and stopped and boot published: private
; devices reset before READY. No CPU entry, grant or stream binding here.
tvm_ready_publish:
    cmp qword [rel tvm_state],TVM_LOADING
    jne .bad
    cmp qword [rel tvm_cpu_ready],1
    jne .bad
    cmp qword [rel tvm_boot_phase],5
    jne .bad
    sub rsp,8
    mov rdi,[rel tvm_start]
    mov rsi,[rel tvm_token]
    call tools_vm_devices_reset
    add rsp,8
    cmp eax,1
    jne .bad
    mov qword [rel tvm_state],TVM_READY
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; RDI private 128-byte destination ->1 filled /0 untouched. Actual RUNNING
; tools with its original allocation held and CPU/root custody retired.
tvm_snapshot_build:
    push rbx
    mov rbx,rdi
    cmp qword [rel tvm_state],TVM_RUNNING
    jne .bad
    cmp qword [rel tvm_instance],0
    je .bad
    cmp qword [rel tvm_serial],0
    je .bad
    cmp qword [rel tvm_owner],0
    je .bad
    cmp qword [rel tvm_session],0
    je .bad
    mov rdi,[rel tvm_start]
    mov rsi,[rel tvm_token]
    call tvm_memory_stopped
    test eax,eax
    jz .bad
    mov rdi,rbx
    xor eax,eax
    mov ecx,TVS_BYTES/8
    cld
    rep stosq
    mov qword [rbx+TVS_SCHEMA],1
    mov rax,[rel tvm_instance]
    mov [rbx+TVS_INSTANCE],rax
    mov eax,[rel tvm_start]
    mov [rbx+TVS_START],eax
    mov dword [rbx+TVS_STATE],TVM_RUNNING
    mov rax,[rel tvm_owner]
    mov [rbx+TVS_OWNER],rax
    mov rax,[rel tvm_session]
    mov [rbx+TVS_SESSION],rax
    mov qword [rbx+TVS_DEVICES],TVM_DEVICES
    mov rax,[rel tvm_serial]
    mov [rbx+TVS_SERIAL],rax
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; R12..R14 half-open request; RDX/RCX excluded base/capacity ->1 disjoint.
; Invalid reservation geometry refuses without touching the request.
tvm_disjoint:
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

; R12..R14 half-open native request ->EAX 1 when it is disjoint from tools,
; app and driver guest/control RAM and from every tools private block.
; Leaf apart from tvm_disjoint; R12/R14 unchanged.
tvm_private_disjoint:
    mov rdx,[rel tvm_base]
    mov rcx,[rel tvm_capacity]
    call tvm_disjoint
    test eax,eax
    jz .bad
    mov rdx,[rel avm_base]
    mov rcx,[rel avm_capacity]
    call tvm_disjoint
    test eax,eax
    jz .bad
    mov rdx,[rel hv_linux_region]
    mov rcx,[rel hv_linux_region_capacity]
    call tvm_disjoint
    test eax,eax
    jz .bad
    lea rdx,[rel tvm_life_begin]
    mov ecx,tvm_life_end-tvm_life_begin
    call tvm_disjoint
    test eax,eax
    jz .bad
    lea rdx,[rel tvms_state]
    lea rcx,[rel tvms_reply]
    add rcx,TSTREAM_RECORD_MAX+8
    sub rcx,rdx
    call tvm_disjoint
    test eax,eax
    jz .bad
    ; SEC R1: the sibling memory, CPU and device custody blocks are private too.
    lea rdx,[rel tvm_state]
    mov ecx,tvm_memory_end-tvm_state
    call tvm_disjoint
    test eax,eax
    jz .bad
    lea rdx,[rel tvm_cpu_storage_begin]
    mov ecx,tvm_cpu_storage_end-tvm_cpu_storage_begin
    call tvm_disjoint
    test eax,eax
    jz .bad
    lea rdx,[rel tvmd_state_begin]
    mov ecx,tvm_exit_open+1-tvmd_state_begin
    call tvm_disjoint
    test eax,eax
    jz .bad
    ; D5a: the D4b console rings/descriptor copies and the D4a decoder too.
    lea rdx,[rel tvmc_state_begin]
    mov ecx,tvmc_state_end-tvmc_state_begin
    call tvm_disjoint
    test eax,eax
    jz .bad
    lea rdx,[rel tvmm_rip]
    mov ecx,tvmm_ilen_mismatch+8-tvmm_rip
    call tvm_disjoint
    test eax,eax
    jz .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; RDI native buffer, RSI length (nonzero) ->EAX 1 when both ends are
; canonical, it does not wrap and it is tvm_private_disjoint /0.
tvm_native_span:
    push r12
    push r14
    sub rsp,8
    mov r12,rdi
    test r12,r12
    jz .bad
    test rsi,rsi
    jz .bad
    mov r14,r12
    add r14,rsi
    jc .bad
    mov rax,r12
    shl rax,16
    sar rax,16
    cmp rax,r12
    jne .bad
    lea rcx,[r14-1]
    mov rdx,rcx
    shl rcx,16
    sar rcx,16
    cmp rcx,rdx
    jne .bad
    call tvm_private_disjoint
    jmp .out
.bad:
    xor eax,eax
.out:
    add rsp,8
    pop r14
    pop r12
    ret

; AV broker callback. RDI native output, ESI exactly 128 ->1 /0 output
; untouched. SysV, no yield, no authority. The output must be canonical and
; disjoint from tools, app and driver guest/control RAM and from the tools
; lifecycle, stream, memory, CPU and device private state; the genuine owner
; and session must still be current.
tools_vm_snapshot:
    push r12
    push r13
    push r14
    mov r12,rdi
    cmp esi,TVS_BYTES
    jne .bad
    test r12,r12
    jz .bad
    mov r14,r12
    add r14,TVS_BYTES
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
    call tvm_private_disjoint
    test eax,eax
    jz .bad
    ; SEC n1: a lock, owner or session change refuses at once, not at the next tick.
    call tvm_admission_current
    test eax,eax
    jz .bad
    ; tvm_snapshot_build makes every check before its first write, so a
    ; refusal leaves the validated disjoint output untouched.
    mov rdi,r12
    call tvm_snapshot_build
    cmp eax,1
    jne .bad
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r14
    pop r13
    pop r12
    ret

; AV broker callback. RDI original snapshot128 ->1 only while the same
; RUNNING instance/START/serial holds its allocation and the genuine local
; unlocked owner and session equal those captured at admission. Locked,
; relocked, replaced, stopped or released refuses. SysV, no yield, no writes
; outside private check storage.
tools_vm_snapshot_current:
    push rbx
    mov rbx,rdi
    test rbx,rbx
    jz .bad
    mov rax,rbx
    add rax,TVS_BYTES
    jc .bad
    ; SEC n2: both ends of the caller's record are canonical before any read.
    dec rax
    mov rdx,rax
    shl rax,16
    sar rax,16
    cmp rax,rdx
    jne .bad
    mov rax,rbx
    shl rax,16
    sar rax,16
    cmp rax,rbx
    jne .bad
    call tvm_local
    test rax,rax
    jz .bad
    call tvm_admission_current
    test eax,eax
    jz .bad
    lea rdi,[rel tvm_snapshot_check]
    call tvm_snapshot_build
    cmp eax,1
    jne .bad
    mov rsi,rbx
    lea rdi,[rel tvm_snapshot_check]
    mov ecx,TVS_BYTES/8
    cld
    repe cmpsq
    jne .bad
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; Original RDI START, RSI token, RDX native buffer, RCX length (1..ring)
; ->EAX bytes moved /0. Input fills the console's private RX ring; output
; drains its TX ring. Only the local unlocked owner of this RUNNING instance,
; rechecked on every call (lock, owner, session, epoch, START, token). The
; bytes are data only: never a command, authorization or proof (T5, V6).
tools_vm_console_input:
    xor r8d,r8d
    jmp tvm_console_io
tools_vm_console_output:
    mov r8d,1
tvm_console_io:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx,rdi
    mov r12,rsi
    mov r13,rdx
    mov r14,rcx
    mov r15d,r8d
    test r14,r14
    jz .bad
    cmp r14,TVM_CONSOLE_RING
    ja .bad
    test r13,r13
    jz .bad
    mov rax,r13                      ; both ends canonical before any access
    add rax,r14
    jc .bad
    dec rax
    mov rdx,rax
    shl rax,16
    sar rax,16
    cmp rax,rdx
    jne .bad
    mov rax,r13
    shl rax,16
    sar rax,16
    cmp rax,r13
    jne .bad
    cmp byte [rel tvm_busy],0
    jne .bad
    call tvm_local
    test rax,rax
    jz .bad
    call tvm_admission_current
    test eax,eax
    jz .bad
    cmp qword [rel tvm_state],TVM_RUNNING
    jne .bad
    cmp rbx,[rel tvm_start]
    jne .bad
    cmp r12,[rel tvm_token]
    jne .bad
    mov rdi,r13
    mov esi,r14d
    test r15d,r15d
    jnz .output
    call tvmc_input
    jmp .out
.output:
    call tvmc_drain
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; D5a: public Terminal's binding to the tools console (SEC 121451 F1-F3).
; One binding: Terminal window owner, START, instance and activation serial.
; Every entry rechecks it with the BSP-local unlocked owner and session
; captured at admission, RUNNING and not busy. Terminal never holds the token
; or any guest address and gets bytes only, 1..256 per call, into or out of
; native memory disjoint from every guest and tools private block (F1, F2).
; TX bytes are untrusted guest output for Terminal's VT parser only. The
; binding never defers, blocks or outlives retirement (F3): a lock, owner or
; session change, STOP or a new instance makes every later entry refuse.

; RDI owner, ESI START ->EAX 1 current /0. Preserves all but RAX, R8-R11,
; flags. A caller that is not the bound owner/START changes nothing. For the
; bound one, a binding no longer current (STOP, retire, replacement, lock,
; owner or session change) is cleared on that first call with its rings
; wiped (SEC 121684 E2/E3), so every later call refuses and read returns -1.
; Busy and the caller's own context (AP, command dispatch, remote) are
; checked first and refuse without clearing (SEC 121723 K1): no unbind runs
; outside the BSP main loop.
tools_vm_terminal_status:
tools_vm_terminal_poll:                ; no pump: the per-turn device pump retries TX
tvm_term_current:
    push rcx
    push rdx
    push rsi
    push rdi
    sub rsp,8
    test rdi,rdi
    jz .bad
    cmp rdi,[rel tvm_term_owner]
    jne .bad
    test esi,esi
    jz .bad
    mov eax,esi
    cmp rax,[rel tvm_term_start]
    jne .bad
    cmp byte [rel tvm_busy],0
    jne .bad
    call tvm_term_context
    test eax,eax
    jz .bad
    mov rax,[rel tvm_term_start]
    cmp rax,[rel tvm_start]
    jne .stale
    cmp qword [rel tvm_state],TVM_RUNNING
    jne .stale
    mov rax,[rel tvm_instance]
    cmp rax,[rel tvm_term_instance]
    jne .stale
    mov rax,[rel tvm_serial]
    cmp rax,[rel tvm_term_serial]
    jne .stale
    call tvm_admission_current
    test eax,eax
    jz .stale
    mov eax,1
    jmp .out
.stale:
    call tvm_term_unbind
.bad:
    xor eax,eax
.out:
    add rsp,8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    ret

; BSP main-loop caller only: no command dispatch, no remote request, no
; injected input, CPU 0 ->EAX 1 /0. These are tvm_local's non-session terms;
; its session terms (unlocked, key, bound owner, authority == epoch) are all
; in tvm_admission_current, which runs after the liveness checks so that a
; lock or session change clears the binding (E2) and the caller's context
; never does (K1).
tvm_term_context:
    cmp dword [rel cmd_dispatch_depth],0
    jne .bad
    cmp byte [rel command_auth_remote_active],0
    jne .bad
    cmp byte [rel session_injected_input],0
    jne .bad
    sub rsp,8
    call smp_current_logical
    add rsp,8
    test eax,eax
    jnz .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Clear the binding and wipe both private console rings: no later window,
; even one given a recycled owner value, inherits a binding, typed input or
; pending output (E3). Never touches the instance, its CPU or its queues.
tvm_term_unbind:
    sub rsp,8
    xor eax,eax
    mov [rel tvm_term_owner],rax
    mov [rel tvm_term_start],rax
    mov [rel tvm_term_instance],rax
    mov [rel tvm_term_serial],rax
    call tvmc_unbind
    add rsp,8
    ret

; RDI nonzero Terminal window owner ->EAX the RUNNING instance's START, the
; Terminal's generation /0 unchanged. One live binding: a second attach,
; even by the same owner, refuses until detach or the instance is gone. A
; new binding starts with empty rings (E3).
tools_vm_terminal_attach:
    push rbx
    mov rbx,rdi
    test rbx,rbx
    jz .bad
    cmp qword [rel tvm_term_owner],0
    je .fresh
    mov rdi,[rel tvm_term_owner]
    mov esi,[rel tvm_term_start]
    call tvm_term_current
    test eax,eax
    jnz .bad
.fresh:
    cmp byte [rel tvm_busy],0
    jne .bad
    cmp qword [rel tvm_state],TVM_RUNNING
    jne .bad
    call tvm_local
    test rax,rax
    jz .bad
    call tvm_admission_current
    test eax,eax
    jz .bad
    cmp qword [rel tvm_start],0
    je .bad
    call tvm_term_unbind
    mov rax,[rel tvm_start]
    mov [rel tvm_term_start],rax
    mov rax,[rel tvm_instance]
    mov [rel tvm_term_instance],rax
    mov rax,[rel tvm_serial]
    mov [rel tvm_term_serial],rax
    mov [rel tvm_term_owner],rbx        ; publish last
    mov eax,[rel tvm_term_start]
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; RDI owner, ESI START, RDX native bytes, ECX 1..256 ->EAX 1 the whole event
; is in the private RX ring /0 nothing stored. Never a prefix.
tools_vm_terminal_write:
    push rbx
    push r12
    sub rsp,8
    mov r12,rdx
    mov ebx,ecx
    call tvm_term_current
    test eax,eax
    jz .bad
    test ebx,ebx
    jz .bad
    cmp ebx,256
    ja .bad
    mov rdi,r12
    mov esi,ebx
    call tvm_native_span
    test eax,eax
    jz .bad
    mov eax,[rel tvmc_rx_len]
    cmp eax,TVM_CONSOLE_RING
    ja .bad
    mov edx,TVM_CONSOLE_RING
    sub edx,eax
    cmp edx,ebx
    jb .bad
    mov rdi,r12
    mov esi,ebx
    call tvmc_input
    cmp eax,ebx
    jne .bad
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    add rsp,8
    pop r12
    pop rbx
    ret

; RDI owner, ESI START, RDX native out, ECX 1..256 ->EAX TX bytes, oldest
; first (0 none yet) /-1 binding not current or bad request: Terminal ends.
tools_vm_terminal_read:
    push rbx
    push r12
    sub rsp,8
    mov r12,rdx
    mov ebx,ecx
    call tvm_term_current
    test eax,eax
    jz .bad
    test ebx,ebx
    jz .bad
    cmp ebx,256
    ja .bad
    mov rdi,r12
    mov esi,ebx
    call tvm_native_span
    test eax,eax
    jz .bad
    mov rdi,r12
    mov esi,ebx
    call tvmc_drain
    jmp .out
.bad:
    mov eax,-1
.out:
    add rsp,8
    pop r12
    pop rbx
    ret

; RDI owner, ESI START, EDX cols, ECX rows (1..0xffff each) ->EAX 1 /0. The
; size reaches the console only on a current binding (SEC 121684 Z4); the
; same pair again is accepted and changes nothing.
tools_vm_terminal_resize:
    push rbx
    push r12
    sub rsp,8
    mov ebx,edx
    mov r12d,ecx
    call tvm_term_current
    test eax,eax
    jz .bad
    lea eax,[rbx-1]
    cmp eax,0xfffe
    ja .bad
    lea eax,[r12-1]
    cmp eax,0xfffe
    ja .bad
    mov edi,ebx
    mov esi,r12d
    call tvmc_resize
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    add rsp,8
    pop r12
    pop rbx
    ret

; RDI owner, ESI START: clears only this Terminal binding and its rings, from
; the BSP main loop while not busy (K1). It never stops, retires or holds
; the instance.
tools_vm_terminal_detach:
    sub rsp,8
    test rdi,rdi
    jz .out
    cmp rdi,[rel tvm_term_owner]
    jne .out
    mov eax,esi
    cmp rax,[rel tvm_term_start]
    jne .out
    cmp byte [rel tvm_busy],0
    jne .out
    call tvm_term_context
    test eax,eax
    jz .out
    call tvm_term_unbind
.out:
    add rsp,8
    ret

%macro WDATA_hv_tools_vm 0
align 8
tvm_life_begin:
tvm_instance: dq 0
tvm_serial: dq 0
tvm_owner: dq 0
tvm_session: dq 0
tvm_deadline: dq 0
tvm_term_owner: dq 0                 ; D5a Terminal binding: owner window,
tvm_term_start: dq 0                 ; START, instance and activation serial
tvm_term_instance: dq 0
tvm_term_serial: dq 0
tvm_snapshot_check: times TVS_BYTES db 0
tvm_busy: db 0
tvm_life_pad: times 7 db 0          ; explicit zero: no NOP alignment fill
tvm_life_end:
; Snapshot disjointness loads this span with ECX. Reject empty, reversed
; or truncated layouts at WDATA expansion, after both labels are defined.
times (((tvm_life_end-tvm_life_begin) <= 0) || ((tvm_life_end-tvm_life_begin) > 0xffffffff)) * -1 db 0
%endmacro
WDATA_DEFER WDATA_hv_tools_vm
