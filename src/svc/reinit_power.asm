;; MODULE svc/reinit_power
;; LAYER 5
;; EXPORTS reinit_power_init, reinit_power_register, reinit_power_begin, reinit_power_step, reinit_power_resume, reinit_power_cancel, reinit_power_admit
;; IMPORTS core/time, core/lib/mem
;; CAPS
;; OWNER saga:resource
;; CONTEXT: bsp_only
; Caller-owned bounded power plan attached to existing driver lifecycle objects,
; NOT a replacement device registry. No boot/firmware/MMIO call sites.
; All declarations/owners/generation words and context remain pinned until a
; terminal RUNNING result. DEGRADED retains custody indefinitely for its owner.
%include "core/abi/driver_power.inc"

%macro DP_ENTER 0
    cld
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov rbx, rdi
%endmacro
%macro DP_EXIT 0
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    cld
    ret
%endmacro

; RDI=zeroed caller-owned dp_context. Never reset an existing lifetime/token.
reinit_power_init:
    cld
    test rdi, rdi
    jz .bad
    cmp dword [rdi + dp_context.version], 0
    jne .bad
    mov dword [rdi + dp_context.version], DP_VERSION
    mov dword [rdi + dp_context.state], DP_RUNNING
    mov qword [rdi + dp_context.token], 1
    xor eax, eax
    ret
.bad:
    mov rax, DP_INVALID
    ret

; Try-only, recursive calls fail without spinning or disturbing outer custody.
reinit_power_enter:
    test rbx, rbx
    jz .bad
    cmp dword [rbx + dp_context.version], DP_VERSION
    jne .bad
    mov al, 1
    xchg al, [rbx + dp_context.busy]
    test al, al
    jnz .busy
    cmp dword [rbx + dp_context.count], DP_LIMIT
    ja .corrupt
    xor eax, eax
    ret
.corrupt:
    mov byte [rbx + dp_context.busy], 0
.bad:
    mov rax, DP_INVALID
    ret
.busy:
    mov rax, DP_BUSY
    ret

; R12=slot. Every callback revalidates both pinned declaration and class token.
reinit_power_identity:
    mov rsi, [r12 + dp_slot.declaration]
    test rsi, rsi
    jz .bad
    lea rdi, [r12 + dp_slot.driver]
    mov edx, dp_driver_size
    sub rsp, 8
    call memcmp
    add rsp, 8
    test eax, eax
    jnz .bad
    mov rax, [r12 + dp_slot.driver + dp_driver.generation_ptr]
    mov rdx, [r12 + dp_slot.driver + dp_driver.generation]
    cmp [rax], rdx
    jne .bad
    mov rax, [r12 + dp_slot.driver + dp_driver.callback]
    lea rdx, [rel code_start]
    cmp rax, rdx
    jb .bad
    lea rdx, [rel wdata_region]
    cmp rax, rdx
    jae .bad
    xor eax, eax
    ret
.bad:
    mov rax, DP_CHANGED
    ret

; Acknowledgements belong to pinned lifetimes. Another cooperative callback or
; caller can advance an earlier participant's epoch after it completed. Recheck
; the whole bounded group before publishing PAUSED or RUNNING, not only the
; participant just called. No driver operation; R12 identifies a stale slot.
reinit_power_terminal_identity:
    sub rsp, 8
    xor r13d, r13d
.next:
    cmp r13d, [rbx + dp_context.count]
    jae .ok
    mov r12, r13
    shl r12, 6
    lea r12, [rbx + r12 + dp_context.slots]
    call reinit_power_identity
    test rax, rax
    jnz .out
    inc r13d
    jmp .next
.ok:
    xor eax, eax
.out:
    add rsp, 8
    ret

; RDI=context, RSI=pinned trusted dp_driver. Dependency order is supplied by
; existing class owners: dependencies must already be attached, hence no cycles.
reinit_power_register:
    DP_ENTER
    mov r13, rsi
    call reinit_power_enter
    test rax, rax
    jnz .out
    mov rbp, DP_INVALID
    cmp dword [rbx + dp_context.state], DP_RUNNING
    jne .done
    cmp dword [rbx + dp_context.count], DP_LIMIT
    jae .done
    test r13, r13
    jz .done
    cmp dword [r13 + dp_driver.version], DP_VERSION
    jne .done
    cmp dword [r13 + dp_driver.kind], DP_GUEST
    ja .done
    cmp qword [r13 + dp_driver.owner], 0
    je .done
    mov rax, [r13 + dp_driver.generation_ptr]
    test rax, rax
    jz .done
    mov rdx, [r13 + dp_driver.generation]
    test rdx, rdx
    jz .done
    cmp [rax], rdx
    jne .done
    mov eax, [r13 + dp_driver.capabilities]
    test eax, ~7
    jnz .done
    mov ecx, [r13 + dp_driver.kind]
    mov r14d, 1
    shl r14d, cl
    test [rbx + dp_context.members], r14d
    jnz .done
    mov eax, [rbx + dp_context.members]
    not eax
    test [r13 + dp_driver.dependencies], eax
    jnz .done
    xor r11d, r11d
.owners:
    cmp r11d, [rbx + dp_context.count]
    jae .callback
    mov eax, r11d
    shl rax, 6
    mov rdx, [r13 + dp_driver.owner]
    cmp [rbx + rax + dp_context.slots + dp_slot.driver + dp_driver.owner], rdx
    je .done                              ; one lifetime owner, one attachment
    inc r11d
    jmp .owners
.callback:
    mov rax, [r13 + dp_driver.callback]
    lea rdx, [rel code_start]
    cmp rax, rdx
    jb .done
    lea rdx, [rel wdata_region]
    cmp rax, rdx
    jae .done
    mov r12d, [rbx + dp_context.count]
    shl r12, 6
    lea r12, [rbx + r12 + dp_context.slots]
    mov [r12 + dp_slot.declaration], r13
    lea rdi, [r12 + dp_slot.driver]
    mov rsi, r13
    mov edx, dp_driver_size
    call memcpy
    mov qword [r12 + dp_slot.flags], 0
    or [rbx + dp_context.members], r14d
    inc dword [rbx + dp_context.count]
    xor ebp, ebp
.done:
    mov rax, rbp
    mov byte [rbx + dp_context.busy], 0
.out:
    DP_EXIT

; Clock provenance is monotonic within the pinned context lifetime.
reinit_power_clock:
    sub rsp, 8
    call boot_ms_now
    add rsp, 8
    test rax, rax
    jz .bad                            ; zero cannot establish a bounded transition clock
    cmp rax, [rbx + dp_context.clock_last]
    jb .bad
    mov [rbx + dp_context.clock_last], rax
    clc
    ret
.bad:
    stc
    ret

; RDI=context, ESI=DP_POWER_QUIESCE, EDX=required kind mask, RCX=timeout ms.
; Missing participant / overflow / stale owner refuses before fencing any work.
reinit_power_begin:
    DP_ENTER
    mov r13d, esi
    mov r14d, edx
    mov r15, rcx
    call reinit_power_enter
    test rax, rax
    jnz .out
    mov rbp, DP_INVALID
    cmp dword [rbx + dp_context.state], DP_RUNNING
    jne .done
    cmp r13d, DP_POWER_QUIESCE
    jne .unsupported
    test r14d, r14d
    jz .done
    mov eax, [rbx + dp_context.members]
    and eax, r14d
    cmp eax, r14d
    jne .unsupported
    test r15, r15
    jz .done
    cmp r15, DP_MAX_MS
    ja .done
    cmp qword [rbx + dp_context.token], -1
    je .done
    xor r13d, r13d
.validate:
    cmp r13d, [rbx + dp_context.count]
    jae .clock
    mov r12, r13
    shl r12, 6
    lea r12, [rbx + r12 + dp_context.slots]
    call reinit_power_identity
    test rax, rax
    jnz .changed
    inc r13d
    jmp .validate
.clock:
    call reinit_power_clock
    jc .clock_bad
    add rax, r15
    jc .clock_bad
    mov [rbx + dp_context.deadline], rax
    mov [rbx + dp_context.required], r14d
    mov dword [rbx + dp_context.intent], DP_POWER_QUIESCE
    inc qword [rbx + dp_context.token]
    mov dword [rbx + dp_context.error], 0
    mov dword [rbx + dp_context.cancel], 0
    mov dword [rbx + dp_context.cursor], 0
    mov dword [rbx + dp_context.phase], DP_FENCE
    xor ecx, ecx
.clear:
    cmp ecx, [rbx + dp_context.count]
    jae .publish
    mov eax, ecx
    shl rax, 6
    mov qword [rbx + rax + dp_context.slots + dp_slot.flags], 0
    inc ecx
    jmp .clear
.publish:
    mov dword [rbx + dp_context.state], DP_QUIESCING
    mov ebp, DP_PENDING
    jmp .done
.unsupported:
    mov rbp, DP_UNSUPPORTED
    jmp .done
.changed:
    mov rbp, DP_CHANGED
    jmp .done
.clock_bad:
    mov rbp, DP_CLOCK
.done:
    mov rax, rbp
    mov byte [rbx + dp_context.busy], 0
.out:
    DP_EXIT

; RDI=context, RSI=timeout. Only an explicitly PAUSED plan can start resume.
reinit_power_resume:
    DP_ENTER
    mov r15, rsi
    call reinit_power_enter
    test rax, rax
    jnz .out
    mov rbp, DP_INVALID
    cmp dword [rbx + dp_context.state], DP_PAUSED
    jne .done
    test r15, r15
    jz .done
    cmp r15, DP_MAX_MS
    ja .done
    call reinit_power_clock
    jc .clock_bad
    add rax, r15
    jc .clock_bad
    mov [rbx + dp_context.deadline], rax
    mov dword [rbx + dp_context.state], DP_RESUMING
    mov dword [rbx + dp_context.phase], DP_RESTORE
    mov dword [rbx + dp_context.cursor], 0
    mov dword [rbx + dp_context.cancel], 0
    mov ebp, DP_PENDING
    jmp .done
.clock_bad:
    mov dword [rbx + dp_context.state], DP_DEGRADED
    mov dword [rbx + dp_context.error], DP_CLOCK
    mov rbp, DP_CLOCK
.done:
    mov rax, rbp
    mov byte [rbx + dp_context.busy], 0
.out:
    DP_EXIT

reinit_power_cancel:
    DP_ENTER
    call reinit_power_enter
    test rax, rax
    jnz .out
    mov rax, DP_INVALID
    cmp dword [rbx + dp_context.state], DP_QUIESCING
    jne .done
    mov dword [rbx + dp_context.cancel], 1
    mov eax, DP_PENDING
.done:
    mov byte [rbx + dp_context.busy], 0
.out:
    DP_EXIT

; Error EBP starts one finite recovery. There is no transactional HW rollback.
reinit_power_recover:
    mov [rbx + dp_context.error], ebp
    cmp ebp, DP_CLOCK
    je .degraded
    mov rax, [rbx + dp_context.clock_last]
    add rax, DP_RECOVERY_MS
    jc .degraded
    mov [rbx + dp_context.deadline], rax
    mov dword [rbx + dp_context.state], DP_RECOVERING
    mov dword [rbx + dp_context.phase], DP_RESTORE
    mov dword [rbx + dp_context.cursor], 0
    ret
.degraded:
    mov dword [rbx + dp_context.state], DP_DEGRADED
    ret

; R12=current slot. Dependencies that remain paused/uncertain cannot be used.
reinit_power_dependencies:
    mov r10d, [r12 + dp_slot.driver + dp_driver.dependencies]
    xor ecx, ecx
.next:
    cmp ecx, [rbx + dp_context.count]
    jae .ok
    mov eax, ecx
    shl rax, 6
    lea r9, [rbx + rax + dp_context.slots]
    mov edx, [r9 + dp_slot.driver + dp_driver.kind]
    bt r10d, edx
    jnc .advance
    mov eax, [r9 + dp_slot.flags]
    test eax, DP_S_UNCERTAIN
    jnz .bad
    test eax, DP_S_PAUSED
    jz .advance
    test eax, DP_S_RESTORED
    jz .bad
.advance:
    inc ecx
    jmp .next
.ok:
    xor eax, eax
    ret
.bad:
    mov rax, DP_UNRESOLVED
    ret

; One step: bounded metadata scans over <=8 slots and AT MOST ONE callback. No wait.
reinit_power_step:
    DP_ENTER
    call reinit_power_enter
    test rax, rax
    jnz .out
    mov rbp, DP_INVALID
    mov eax, [rbx + dp_context.state]
    cmp eax, DP_QUIESCING
    je .clock
    cmp eax, DP_RESUMING
    je .clock
    cmp eax, DP_RECOVERING
    je .clock
    cmp eax, DP_DEGRADED
    jne .terminal
    movsxd rbp, dword [rbx + dp_context.error]
    jmp .done
.terminal:
    cmp eax, DP_RUNNING
    je .result
    cmp eax, DP_PAUSED
    jne .done
.result:
    movsxd rbp, dword [rbx + dp_context.error]
    jmp .done
.clock:
    call reinit_power_clock
    jc .clock_bad
    cmp rax, [rbx + dp_context.deadline]
    jae .timeout
    cmp dword [rbx + dp_context.state], DP_QUIESCING
    jne .select
    cmp dword [rbx + dp_context.cancel], 0
    jne .cancelled
.select:
    mov r13d, [rbx + dp_context.cursor]
    mov r14d, [rbx + dp_context.phase]
    cmp r13d, [rbx + dp_context.count]
    jae .phase_end
    mov r12, r13
    shl r12, 6
    lea r12, [rbx + r12 + dp_context.slots]
    cmp r14d, DP_RESTORE
    jb .identity
    test dword [r12 + dp_slot.flags], DP_S_UNCERTAIN
    jz .dependencies
    cmp r14d, DP_RESTORE
    jne .advance
    test dword [r12 + dp_slot.flags], DP_S_PAUSED
    jz .advance                            ; pending STOP never earns PAUSED
.dependencies:
    call reinit_power_dependencies
    test rax, rax
    jnz .unresolved
    cmp r14d, DP_RESTORE
    jne .identity
    test dword [r12 + dp_slot.flags], DP_S_PAUSED
    jz .advance                            ; only actually paused may restore
.identity:
    call reinit_power_identity
    test rax, rax
    jnz .changed
    ; A pending/failed stop or restore is uncertain until explicit completion.
    cmp r14d, DP_STOP
    je .uncertain
    cmp r14d, DP_RESTORE
    jne .invoke
.uncertain:
    or dword [r12 + dp_slot.flags], DP_S_UNCERTAIN
.invoke:
    mov rdi, [r12 + dp_slot.driver + dp_driver.owner]
    mov esi, r14d
    mov rdx, [rbx + dp_context.token]
    mov rcx, rbx
    mov r8, [r12 + dp_slot.driver + dp_driver.generation]
    call [r12 + dp_slot.driver + dp_driver.callback]
    cld
    mov r15, rax
    mov ebp, edx                         ; independent acknowledgment bits
    call reinit_power_identity           ; owner may change during callback
    test rax, rax
    jnz .changed
    cmp r15, DP_PENDING
    je .pending
    test r15, r15
    jnz .callback_error
    mov eax, DP_ACK_FENCED
    cmp r14d, DP_FENCE
    je .ack
    cmp r14d, DP_VERIFY
    jne .stopped_ack
    or eax, DP_ACK_READY
    jmp .ack
.stopped_ack:
    cmp r14d, DP_RESTORE
    je .ack
    or eax, DP_ACK_DRAINED
    mov edx, [r12 + dp_slot.driver + dp_driver.capabilities]
    shl edx, 2                          ; IRQ/DMA/FLUSH -> explicit ack bits
    or eax, edx
.ack:
    and ebp, eax
    cmp ebp, eax
    jne .bad_ack
    mov [r12 + dp_slot.ack], ebp
    and dword [r12 + dp_slot.flags], ~DP_S_UNCERTAIN
    mov eax, 1
    mov ecx, r14d
    dec ecx
    shl eax, cl                         ; FENCED/PAUSED/RESTORED/VERIFIED
    or [r12 + dp_slot.flags], eax
.advance:
    cmp r14d, DP_STOP
    jne .forward
    dec dword [rbx + dp_context.cursor]
    jmp .pending
.forward:
    inc dword [rbx + dp_context.cursor]
.pending:
    mov ebp, DP_PENDING
    jmp .done
.phase_end:
    cmp r14d, DP_FENCE
    jne .not_fence
    mov eax, [rbx + dp_context.count]
    dec eax
    mov [rbx + dp_context.cursor], eax
    mov dword [rbx + dp_context.phase], DP_STOP
    jmp .pending
.not_fence:
    cmp r14d, DP_STOP
    jne .not_stop
    call reinit_power_terminal_identity
    test rax, rax
    jnz .changed
    mov dword [rbx + dp_context.state], DP_PAUSED
    xor ebp, ebp
    jmp .done
.not_stop:
    cmp r14d, DP_RESTORE
    jne .finish
    mov dword [rbx + dp_context.phase], DP_VERIFY
    mov dword [rbx + dp_context.cursor], 0
    jmp .pending
.finish:
    xor ecx, ecx
.verify_all:
    cmp ecx, [rbx + dp_context.count]
    jae .running
    mov eax, ecx
    shl rax, 6
    test dword [rbx + rax + dp_context.slots + dp_slot.flags], DP_S_VERIFIED
    jz .degraded
    inc ecx
    jmp .verify_all
.running:
    call reinit_power_terminal_identity
    test rax, rax
    jnz .terminal_changed
    mov dword [rbx + dp_context.state], DP_RUNNING
    movsxd rbp, dword [rbx + dp_context.error]
    jmp .done
.terminal_changed:
    or dword [r12 + dp_slot.flags], DP_S_UNCERTAIN
    cmp dword [rbx + dp_context.error], 0
    jne .degraded
    mov dword [rbx + dp_context.error], DP_CHANGED
    jmp .degraded
.unresolved:
    mov ebp, DP_UNRESOLVED
    jmp .slot_error
.changed:
    mov ebp, DP_CHANGED
    jmp .slot_error
.bad_ack:
    mov ebp, DP_BAD_ACK
    jmp .slot_error
.callback_error:
    mov ebp, DP_FAILED
    cmp r15, DP_UNSUPPORTED
    jne .slot_error
    mov ebp, DP_UNSUPPORTED
    cmp r14d, DP_STOP
    jne .slot_error
    and dword [r12 + dp_slot.flags], ~DP_S_UNCERTAIN ; explicit no-effect refusal
    jmp .fail
.slot_error:
    or dword [r12 + dp_slot.flags], DP_S_UNCERTAIN
.fail:
    cmp dword [rbx + dp_context.state], DP_QUIESCING
    jne .recovery_error
    call reinit_power_recover
    cmp dword [rbx + dp_context.state], DP_DEGRADED
    je .degraded_result
    jmp .pending
.recovery_error:
    cmp dword [rbx + dp_context.error], 0
    jne .advance
    mov [rbx + dp_context.error], ebp
    jmp .advance
.clock_bad:
    mov ebp, DP_CLOCK
    jmp .time_failure
.timeout:
    mov ebp, DP_TIMEOUT
.time_failure:
    cmp dword [rbx + dp_context.state], DP_QUIESCING
    jne .time_degraded
    call reinit_power_recover
    cmp dword [rbx + dp_context.state], DP_DEGRADED
    je .degraded_result
    jmp .pending
.cancelled:
    mov ebp, DP_CANCELLED
    call reinit_power_recover
    cmp dword [rbx + dp_context.state], DP_DEGRADED
    je .degraded_result
    jmp .pending
.time_degraded:
    mov [rbx + dp_context.error], ebp
.degraded:
    mov dword [rbx + dp_context.state], DP_DEGRADED
    cmp dword [rbx + dp_context.error], 0
    jne .degraded_result
    mov dword [rbx + dp_context.error], DP_UNRESOLVED
.degraded_result:
    movsxd rbp, dword [rbx + dp_context.error]
.done:
    mov rax, rbp
    mov byte [rbx + dp_context.busy], 0
.out:
    DP_EXIT

; RDI=context, RSI=issued token, RDX=owner, RCX=class generation -> 0/-error.
; Drivers gate ALL new-work entrypoints with this before ownership acceptance.
reinit_power_admit:
    DP_ENTER
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    call reinit_power_enter
    test rax, rax
    jnz .out
    mov rbp, DP_CHANGED
    cmp r13, [rbx + dp_context.token]
    jne .done
    mov rbp, DP_BUSY
    cmp dword [rbx + dp_context.state], DP_RUNNING
    jne .done
    mov rbp, DP_CHANGED
    xor r13d, r13d
.next:
    cmp r13d, [rbx + dp_context.count]
    jae .done
    mov r12, r13
    shl r12, 6
    lea r12, [rbx + r12 + dp_context.slots]
    inc r13d
    cmp [r12 + dp_slot.driver + dp_driver.owner], r14
    jne .next
    cmp [r12 + dp_slot.driver + dp_driver.generation], r15
    jne .done
    call reinit_power_identity
    mov rbp, rax
.done:
    mov rax, rbp
    mov byte [rbx + dp_context.busy], 0
.out:
    DP_EXIT
