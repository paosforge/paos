;; MODULE svc/reinit_power_loopnet
;; LAYER 5
;; EXPORTS reinit_power_loopnet_register, reinit_power_loopnet_tx
;; IMPORTS svc/reinit_power, net/netdev, dev/net/loopnet, core/lib/mem
;; CAPS
;; OWNER saga:resource
;; CONTEXT: bsp_only
; Explicit, opt-in reference for the existing synchronous software netdev.
; No boot registration, replacement registry, physical NIC, IRQ/DMA/flush or
; firmware claims. Caller pins its plan for this device lifetime, including
; DEGRADED custody. No detach/rebind/reset while outstanding handles exist.
%include "core/abi/driver_power.inc"

; RDI=initialized plan, ESI=dependency kind bitmap of already registered participants.
; Existing class registration is mandatory; publishing admission is LAST.
reinit_power_loopnet_register:
    cld
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12d, esi
    mov rax, DP_BUSY
    cmp qword [rel loopnet_power_gate], 0
    jne .out
    cmp qword [rel reinit_power_loopnet_context], 0
    jne .out
    lea rdi, [rel loopnet_dev]
    lea rsi, [rel loopnet_ops]
    call netdev_power_member
    test rax, rax
    jz .unsupported
    lea r13, [rel reinit_power_loopnet_declaration]
    mov dword [r13 + dp_driver.version], DP_VERSION
    mov dword [r13 + dp_driver.kind], DP_NETWORK
    lea rcx, [rel loopnet_dev]
    mov [r13 + dp_driver.owner], rcx
    mov [r13 + dp_driver.generation_ptr], rax
    mov [r13 + dp_driver.generation], rdx
    lea rcx, [rel reinit_power_loopnet_callback]
    mov [r13 + dp_driver.callback], rcx
    mov [r13 + dp_driver.dependencies], r12d
    mov dword [r13 + dp_driver.capabilities], 0
    mov rdi, rbx
    mov rsi, r13
    call reinit_power_register
    test rax, rax
    jnz .out
    mov eax, [rbx + dp_context.count]
    dec eax
    mov [rel reinit_power_loopnet_index], eax
    shl rax, 6
    lea rax, [rbx + rax + dp_context.slots]
    mov [rel reinit_power_loopnet_slot], rax
    lea rdi, [rel reinit_power_loopnet_ops]
    lea rsi, [rel loopnet_ops]
    mov edx, netdev_ops_size
    call memcpy
    mov [rel reinit_power_loopnet_context], rbx
    lea rax, [rel reinit_power_loopnet_gate]
    mov [rel loopnet_power_gate], rax
    xor eax, eax
    jmp .out
.unsupported:
    mov rax, DP_UNSUPPORTED
.out:
    pop r13
    pop r12
    pop rbx
    cld
    ret

; Revalidate class membership BEFORE dereferencing its generation; immutable
; ops and declaration snapshots prevent same-handle replacement from earning
; a software stop/ready acknowledgement. No driver op or unbounded scan.
reinit_power_loopnet_identity:
    push rbx
    mov rbx, [rel reinit_power_loopnet_context]
    test rbx, rbx
    jz .bad
    cmp dword [rbx + dp_context.version], DP_VERSION
    jne .bad
    mov eax, [rel reinit_power_loopnet_index]
    cmp dword [rbx + dp_context.count], DP_LIMIT
    ja .bad
    cmp eax, [rbx + dp_context.count]
    jae .bad
    lea rdi, [rel loopnet_dev]
    lea rsi, [rel loopnet_ops]
    call netdev_power_member
    cmp rax, [rel reinit_power_loopnet_declaration + dp_driver.generation_ptr]
    jne .bad
    test rax, rax
    jz .bad
    cmp rdx, [rel reinit_power_loopnet_declaration + dp_driver.generation]
    jne .bad
    mov rax, [rel reinit_power_loopnet_slot]
    lea rsi, [rel reinit_power_loopnet_declaration]
    cmp [rax + dp_slot.declaration], rsi
    jne .bad
    lea rdi, [rax + dp_slot.driver]
    mov edx, dp_driver_size
    call memcmp
    test eax, eax
    jnz .bad
    lea rdi, [rel loopnet_ops]
    lea rsi, [rel reinit_power_loopnet_ops]
    mov edx, netdev_ops_size
    call memcmp
    test eax, eax
    jnz .bad
    xor eax, eax
    jmp .out
.bad:
    mov rax, DP_CHANGED
.out:
    pop rbx
    ret

; Optional backend admission hook. All ordinary TX uses the REAL coordinator.
; A VERIFY callback may consume ONE exact internal probe while the coordinator
; holds its try-only busy flag. This is not public new work: it is synchronous,
; exact-frame scoped, and cannot survive the callback, phase, token or epoch.
reinit_power_loopnet_gate:
    cld
    push rbx
    push r12
    push r13
    lea rax, [rel loopnet_dev]
    cmp rdi, rax
    jne .changed
    mov r12, rsi
    mov r13, rdx
    call reinit_power_loopnet_identity
    test rax, rax
    jnz .out
    mov rbx, [rel reinit_power_loopnet_context]
    cmp byte [rel reinit_power_loopnet_probe], 1
    jne .ordinary
    mov byte [rel reinit_power_loopnet_probe], 0
    lea rax, [rel reinit_power_loopnet_frame]
    cmp r12, rax
    jne .changed
    cmp r13, 64
    jne .changed
    cmp byte [rbx + dp_context.busy], 1
    jne .changed
    cmp dword [rbx + dp_context.phase], DP_VERIFY
    jne .changed
    mov eax, [rbx + dp_context.state]
    cmp eax, DP_RESUMING
    je .probe_token
    cmp eax, DP_RECOVERING
    jne .changed
.probe_token:
    mov rax, [rel reinit_power_loopnet_probe_token]
    cmp rax, [rbx + dp_context.token]
    jne .changed
    xor eax, eax
    jmp .out
.ordinary:
    mov rdi, rbx
    mov rsi, [rbx + dp_context.token]
    lea rdx, [rel loopnet_dev]
    mov rcx, [rel reinit_power_loopnet_declaration + dp_driver.generation]
    call reinit_power_admit
    jmp .out
.changed:
    mov rax, DP_CHANGED
.out:
    pop r13
    pop r12
    pop rbx
    cld
    ret

; Token-bearing work entry: RDI=issued plan token, RSI=frame, RDX=length.
; A stale queued caller is refused before the real backend frame mutation.
reinit_power_loopnet_tx:
    cld
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    mov r13, rdx
    call reinit_power_loopnet_identity
    test rax, rax
    jnz .out
    mov rdi, [rel reinit_power_loopnet_context]
    mov rsi, rbx
    lea rdx, [rel loopnet_dev]
    mov rcx, [rel reinit_power_loopnet_declaration + dp_driver.generation]
    call reinit_power_admit
    test rax, rax
    jnz .out
    lea rdi, [rel loopnet_dev]
    mov rsi, r12
    mov rdx, r13
    call loopnet_tx
.out:
    pop r13
    pop r12
    pop rbx
    cld
    ret

; Real coordinator callback. At most one bounded software operation per phase.
reinit_power_loopnet_callback:
    cld
    push rbx
    push r12
    push r13
    lea rax, [rel loopnet_dev]
    cmp rdi, rax
    jne .changed
    mov rbx, [rel reinit_power_loopnet_context]
    cmp rcx, rbx
    jne .changed
    test rbx, rbx
    jz .changed
    cmp byte [rbx + dp_context.busy], 1
    jne .changed
    cmp rdx, [rbx + dp_context.token]
    jne .changed
    cmp r8, [rel reinit_power_loopnet_declaration + dp_driver.generation]
    jne .changed
    cmp esi, [rbx + dp_context.phase]
    jne .changed
    mov r12d, esi
    mov r13, rdx
    call reinit_power_loopnet_identity
    test rax, rax
    jnz .changed
    cmp r12d, DP_FENCE
    je .fence
    cmp r12d, DP_STOP
    je .stop
    cmp r12d, DP_RESTORE
    je .restore
    cmp r12d, DP_VERIFY
    jne .changed
    mov eax, [rbx + dp_context.state]
    cmp eax, DP_RESUMING
    je .verify
    cmp eax, DP_RECOVERING
    jne .changed
.verify:
    mov rax, [rel loopnet_tx_frames]
    mov [rel reinit_power_loopnet_before], rax
    mov [rel reinit_power_loopnet_probe_token], r13
    mov byte [rel reinit_power_loopnet_probe], 1
    lea rdi, [rel loopnet_dev]
    lea rsi, [rel reinit_power_loopnet_frame]
    mov edx, 64
    call loopnet_tx
    mov byte [rel reinit_power_loopnet_probe], 0
    test rax, rax
    jnz .failed
    mov rax, [rel reinit_power_loopnet_before]
    inc rax
    cmp rax, [rel loopnet_tx_frames]
    jne .failed
    mov edx, DP_ACK_FENCED | DP_ACK_READY
    jmp .ok
.fence:
    cmp dword [rbx + dp_context.state], DP_QUIESCING
    jne .changed
    mov [rel reinit_power_loopnet_token], r13
    ; Synchronous TX has no outstanding ring/work after this return.
    mov edx, DP_ACK_FENCED
    jmp .ok
.stop:
    cmp dword [rbx + dp_context.state], DP_QUIESCING
    jne .changed
    cmp r13, [rel reinit_power_loopnet_token]
    jne .changed
    lea rdi, [rel loopnet_dev]
    call loopnet_stop
    test rax, rax
    jnz .failed
    cmp byte [rel loopnet_power_running], 0
    jne .failed
    mov edx, DP_ACK_FENCED | DP_ACK_DRAINED
    jmp .ok
.restore:
    mov eax, [rbx + dp_context.state]
    cmp eax, DP_RESUMING
    je .restore_token
    cmp eax, DP_RECOVERING
    jne .changed
.restore_token:
    cmp r13, [rel reinit_power_loopnet_token]
    jne .changed
    lea rdi, [rel loopnet_dev]
    call loopnet_start
    test rax, rax
    jnz .failed
    cmp byte [rel loopnet_power_running], 1
    jne .failed
    mov edx, DP_ACK_FENCED
.ok:
    xor eax, eax
    jmp .out
.changed:
    mov rax, DP_CHANGED
    jmp .error
.failed:
    mov rax, DP_FAILED
.error:
    xor edx, edx
.out:
    pop r13
    pop r12
    pop rbx
    cld
    ret

%macro WDATA_svc_reinit_power_loopnet 0
align 8
reinit_power_loopnet_context: dq 0
reinit_power_loopnet_slot: dq 0
reinit_power_loopnet_declaration: times dp_driver_size db 0
reinit_power_loopnet_ops: times netdev_ops_size db 0
reinit_power_loopnet_token: dq 0
reinit_power_loopnet_probe_token: dq 0
reinit_power_loopnet_before: dq 0
reinit_power_loopnet_index: dd 0
reinit_power_loopnet_probe: db 0
reinit_power_loopnet_frame: times 64 db 0
%endmacro
WDATA_DEFER WDATA_svc_reinit_power_loopnet
