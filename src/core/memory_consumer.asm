;; MODULE core/memory_consumer
;; LAYER 1
;; EXPORTS mbc_begin, mbc_action, mbc_revoke, mbc_poll, mbc_snapshot
;; IMPORTS core/memory_budget
;; CAPS
;; OWNER saga:core
;; LOCK: mbc_lock PROTECTS mbc_binding, mbc_job, mbc_phase, mbc_error, mbc_last, mbc_flags, mbc_progress, mbc_cancel, mbc_last_tick, mbc_work_until, mbc_cleanup_until, mbc_owned_token, mbc_extra_token, mbc_base, mbc_bytes
; Finite trusted-kernel CPU-only optional storage. No command registration or
; scheduler attachment: a future caller must enforce live principal/session
; authority, original transport/cutoffs and settled-BSP service. Never hand
; these spans to APs, translations or devices. One page/allocator step per poll.
%include "core/abi/memory_budget.inc"
%include "core/abi/memory_consumer.inc"

; Internal short nonblocking consumer guard, independent of allocator lock.
mbc_enter:
    mov r11d, 1
    xchg r11d, [rel mbc_lock]
    mov eax, MB_E_BUSY
    test r11d, r11d
    jnz .out
    xor eax, eax
.out:
    ret
mbc_leave:
    mov dword [rel mbc_lock], 0
    ret

; mbc_begin(RDI=trusted nonzero binding,RSI=monotonic ms,
; RDX=work cutoff,RCX=cleanup cutoff)->EAX=status,RDX=opaque uint32 job.
; Bounds are inherited absolute cutoffs, never durations added to a live run.
; One active job; monotonically increasing generation never wraps/reuses.
mbc_begin:
    push rbx
    mov rbx, rdx
    call mbc_enter
    test eax, eax
    jnz .out
    mov eax, MB_E_INPUT
    test rdi, rdi
    jz .leave
    cmp rbx, rsi
    jbe .leave
    cmp rcx, rbx
    jbe .leave
    mov rax, rbx
    sub rax, rsi
    cmp rax, MBC_WORK_MAX_MS
    ja .input
    mov rax, rcx
    sub rax, rbx
    cmp rax, MBC_CLEANUP_MAX_MS
    ja .input
    mov eax, MB_E_BUSY
    cmp qword [rel mbc_owned_token], 0
    jne .leave
    cmp qword [rel mbc_phase], MBC_IDLE
    je .ready
    cmp qword [rel mbc_phase], MBC_DONE
    jne .leave
.ready:
    mov eax, MB_E_TOKEN
    mov r11d, -1
    cmp [rel mbc_job], r11
    jae .leave
    inc qword [rel mbc_job]
    mov [rel mbc_binding], rdi
    mov [rel mbc_last_tick], rsi
    mov [rel mbc_work_until], rbx
    mov [rel mbc_cleanup_until], rcx
    mov qword [rel mbc_phase], MBC_ACQUIRE_WORK
    mov qword [rel mbc_error], 0
    mov qword [rel mbc_last], 0
    mov qword [rel mbc_flags], 0
    mov qword [rel mbc_progress], 0
    mov qword [rel mbc_cancel], 0
    xor eax, eax
    jmp .leave
.input:
    mov eax, MB_E_INPUT
.leave:
    call mbc_leave
.out:
    xor edx, edx
    test eax, eax
    jnz .ret
    mov rdx, [rel mbc_job]
.ret:
    pop rbx
    ret

; mbc_action(RDI=approved current binding,RSI=exact job,RDX=action).
; The caller owns request-nonce deduplication and live authority on EVERY call.
; No action directly touches memory or releases it from a command frame.
mbc_action:
    sub rsp, 8
    call mbc_enter
    test eax, eax
    jnz .out
    mov eax, MB_E_STALE
    test rdi, rdi
    jz .leave
    cmp rdi, [rel mbc_binding]
    jne .leave
    cmp rsi, [rel mbc_job]
    jne .leave
    cmp qword [rel mbc_phase], MBC_IDLE
    je .leave
    cmp qword [rel mbc_phase], MBC_DONE
    jae .leave
    cmp edx, MBC_ACT_CANCEL
    jne .advance
    cmp rdx, MBC_ACT_CANCEL
    jne .bad
    mov qword [rel mbc_cancel], 1
    xor eax, eax
    jmp .leave
.advance:
    cmp qword [rel mbc_cancel], 0
    jne .bad
    cmp rdx, MBC_ACT_PROBE
    jne .release
    cmp qword [rel mbc_phase], MBC_HELD
    jne .bad
    mov qword [rel mbc_phase], MBC_PROBE
    jmp .ok
.release:
    cmp rdx, MBC_ACT_RELEASE
    jne .retry
    cmp qword [rel mbc_phase], MBC_REFUSED
    jne .bad
    mov qword [rel mbc_phase], MBC_SCRUB_WORK
    jmp .ok
.retry:
    cmp rdx, MBC_ACT_RETRY
    jne .finish
    cmp qword [rel mbc_phase], MBC_RELEASED
    jne .bad
    mov qword [rel mbc_phase], MBC_ACQUIRE_STAGED
    jmp .ok
.finish:
    cmp rdx, MBC_ACT_FINISH
    jne .bad
    cmp qword [rel mbc_phase], MBC_RETRY_HELD
    jne .bad
    mov qword [rel mbc_phase], MBC_SCRUB0
.ok:
    xor eax, eax
    jmp .leave
.bad:
    mov eax, MB_E_STATE
.leave:
    call mbc_leave
.out:
    add rsp, 8
    ret

; Trusted authority revocation: prohibit more work and schedule cleanup.
; This does not pretend to validate a principal; the security caller does.
mbc_revoke:
    mov rsi, [rel mbc_job]
    mov edx, MBC_ACT_CANCEL
    jmp mbc_action

; mbc_poll(RDI=trusted monotonic ms). At most one page initialization/check/
; scrub OR one allocator transition. Must run on serialized settled BSP turns.
; No AP, DMA or guest user exists, so stopping this service quiesces all users.
mbc_poll:
    push rbx
    call mbc_enter
    test eax, eax
    jnz .out
    mov rbx, [rel mbc_phase]
    test rbx, rbx
    jz .idle
    cmp rbx, MBC_DONE
    jae .idle
    cmp rdi, [rel mbc_last_tick]
    jae .clock_ok
    mov eax, MBC_E_CLOCK
    call mbc_fail
    jmp .deadlines
.clock_ok:
    mov [rel mbc_last_tick], rdi
.deadlines:
    cmp rdi, [rel mbc_cleanup_until]
    jb .work_deadline
    mov eax, MBC_E_DEADLINE
    call mbc_fail
    cmp qword [rel mbc_owned_token], 0
    je .done
    mov qword [rel mbc_phase], MBC_STRANDED
    jmp .leave
.work_deadline:
    cmp rdi, [rel mbc_work_until]
    jb .cancel
    mov eax, MBC_E_DEADLINE
    call mbc_fail
.cancel:
    cmp qword [rel mbc_cancel], 0
    je .dispatch
    cmp qword [rel mbc_error], 0
    jne .retire
    mov qword [rel mbc_error], MBC_E_CANCELLED
.retire:
    cmp rbx, MBC_SCRUB0
    jae .dispatch
    cmp qword [rel mbc_owned_token], 0
    je .done
    mov rbx, MBC_SCRUB0
    mov [rel mbc_phase], rbx
.dispatch:
    cmp rbx, MBC_ACQUIRE_WORK
    je .acquire_work
    cmp rbx, MBC_PROBE
    je .probe
    cmp rbx, MBC_ACQUIRE_STAGED
    je .acquire_staged
    cmp rbx, MBC_RELEASE_WORK
    je .release_work
    cmp rbx, MBC_RELEASE
    je .release_final
    cmp rbx, MBC_INIT_WORK
    je .fill
    cmp rbx, MBC_INIT_STAGED0
    je .fill
    cmp rbx, MBC_INIT_STAGED1
    je .fill_second
    cmp rbx, MBC_CHECK_WORK
    je .check
    cmp rbx, MBC_CHECK_STAGED0
    je .check
    cmp rbx, MBC_CHECK_STAGED1
    je .check_second
    cmp rbx, MBC_SCRUB_WORK
    je .scrub
    cmp rbx, MBC_SCRUB0
    je .scrub
    cmp rbx, MBC_SCRUB1
    je .scrub_second
.idle:
    xor eax, eax
    jmp .leave
.acquire_work:
    mov edx, MB_KIND_OPTIONAL_WORK
    mov ecx, 4096
    jmp .acquire
.probe:
.acquire_staged:
    mov edx, MB_KIND_OPTIONAL_STAGED
    mov ecx, 8192
.acquire:
    mov edi, MB_OWNER_OPTIONAL_CPU
    mov rsi, [rel mbc_job]
    mov r8d, 4096
    xor r9d, r9d
    mov r10d, MBC_CEILING
    call mb_acquire_bounded
    mov [rel mbc_last], rax
    cmp rbx, MBC_PROBE
    jne .acquired
    cmp eax, MB_E_QUOTA
    je .quota
    ; Unexpected success is still an owned allocation. We already hold WORK,
    ; so never discard either key. Correct allocator policy prevents this;
    ; quarantine the extra key and let caller see STRANDED, not fake cleanup.
    test eax, eax
    jnz .failed
    mov [rel mbc_extra_token], rdx
    add [rel mbc_bytes], r9             ; report all custody, including the anomalous span
    mov qword [rel mbc_phase], MBC_STRANDED
    mov eax, MB_E_STATE
    call mbc_fail
    jmp .leave
.quota:
    or qword [rel mbc_flags], MBC_F_QUOTA
    mov qword [rel mbc_phase], MBC_REFUSED
    jmp .progress
.acquired:
    test eax, eax
    jnz .failed
    mov [rel mbc_owned_token], rdx
    mov [rel mbc_base], r8
    mov [rel mbc_bytes], r9
    cmp rbx, MBC_ACQUIRE_WORK
    jne .staged
    mov qword [rel mbc_phase], MBC_INIT_WORK
    jmp .progress
.staged:
    or qword [rel mbc_flags], MBC_F_RETRY
    mov qword [rel mbc_phase], MBC_INIT_STAGED0
    jmp .progress
.fill_second:
    mov edx, 4096
    jmp .fill_at
.fill:
    xor edx, edx
.fill_at:
    mov rdi, [rel mbc_base]
    add rdi, rdx
    mov rax, MBC_PATTERN
    xor rax, [rel mbc_job]
    xor rax, rdx
    mov ecx, 512
    cld
    rep stosq
    jmp .next
.check_second:
    mov edx, 4096
    jmp .check_at
.check:
    xor edx, edx
.check_at:
    mov rdi, [rel mbc_base]
    add rdi, rdx
    mov rax, MBC_PATTERN
    xor rax, [rel mbc_job]
    xor rax, rdx
    mov ecx, 512
    cld
    repe scasq
    jne .content
    cmp rbx, MBC_CHECK_WORK
    je .held
    cmp rbx, MBC_CHECK_STAGED1
    jne .next
    or qword [rel mbc_flags], MBC_F_CHECKED
    mov qword [rel mbc_phase], MBC_RETRY_HELD
    jmp .progress
.held:
    mov qword [rel mbc_phase], MBC_HELD
    jmp .progress
.scrub_second:
    mov edx, 4096
    jmp .scrub_at
.scrub:
    xor edx, edx
.scrub_at:
    mov rdi, [rel mbc_base]
    add rdi, rdx
    xor eax, eax
    mov ecx, 512
    cld
    rep stosq
    cmp rbx, MBC_SCRUB_WORK
    je .next
    cmp rbx, MBC_SCRUB1
    je .final_release_phase
    cmp qword [rel mbc_bytes], 4096
    ja .next
.final_release_phase:
    mov qword [rel mbc_phase], MBC_RELEASE
    jmp .progress
.release_work:
.release_final:
    mov edi, MB_OWNER_OPTIONAL_CPU
    mov rsi, [rel mbc_job]
    mov rdx, [rel mbc_owned_token]
    call mb_release
    mov [rel mbc_last], rax
    test eax, eax
    jnz .release_refused
    mov qword [rel mbc_owned_token], 0
    mov qword [rel mbc_base], 0
    mov qword [rel mbc_bytes], 0
    cmp rbx, MBC_RELEASE_WORK
    jne .done
    or qword [rel mbc_flags], MBC_F_WORK_RELEASED
    mov qword [rel mbc_phase], MBC_RELEASED
    jmp .progress
.release_refused:
    cmp eax, MB_E_BUSY
    je .leave                         ; retry one transition next poll, before cutoff
    call mbc_fail
    mov qword [rel mbc_phase], MBC_STRANDED
    jmp .leave
.content:
    mov eax, MBC_E_CONTENT
.failed:
    call mbc_fail                     ; next poll performs bounded cleanup
    jmp .leave
.next:
    inc qword [rel mbc_phase]
.progress:
    inc qword [rel mbc_progress]
    xor eax, eax
    jmp .leave
.done:
    mov qword [rel mbc_phase], MBC_DONE
    or qword [rel mbc_flags], MBC_F_CLEAN
    jmp .progress
.leave:
    call mbc_leave
.out:
    pop rbx
    ret

; Preserve first failure; never clear ownership or claim release here.
mbc_fail:
    cmp qword [rel mbc_error], 0
    jne .seen
    mov [rel mbc_error], rax
.seen:
    mov qword [rel mbc_cancel], 1
    ret

; mbc_snapshot(RDI=trusted72B output)->EAX=status. Untouched on BUSY/input.
mbc_snapshot:
    sub rsp, 8
    test rdi, rdi
    jz .input
    call mbc_enter
    test eax, eax
    jnz .out
%macro MBC_COPY_FIELD 2
    mov rax, [rel %2]
    mov [rdi + %1], rax
%endmacro
    MBC_COPY_FIELD MBC_SUM_JOB, mbc_job
    MBC_COPY_FIELD MBC_SUM_PHASE, mbc_phase
    MBC_COPY_FIELD MBC_SUM_ERROR, mbc_error
    MBC_COPY_FIELD MBC_SUM_LAST, mbc_last
    MBC_COPY_FIELD MBC_SUM_FLAGS, mbc_flags
    MBC_COPY_FIELD MBC_SUM_PROGRESS, mbc_progress
    MBC_COPY_FIELD MBC_SUM_OWNED, mbc_bytes
    MBC_COPY_FIELD MBC_SUM_WORK_UNTIL, mbc_work_until
    MBC_COPY_FIELD MBC_SUM_CLEANUP_UNTIL, mbc_cleanup_until
    xor eax, eax
    call mbc_leave
    jmp .out
.input:
    mov eax, MB_E_INPUT
.out:
    add rsp, 8
    ret

%include "core/abi/wdata.inc"
%macro WDATA_core_memory_consumer 0
mbc_lock: dd 0
    align 8, db 0
mbc_binding: dq 0
mbc_job: dq 0
mbc_phase: dq 0
mbc_error: dq 0
mbc_last: dq 0
mbc_flags: dq 0
mbc_progress: dq 0
mbc_cancel: dq 0
mbc_last_tick: dq 0
mbc_work_until: dq 0
mbc_cleanup_until: dq 0
mbc_owned_token: dq 0
mbc_extra_token: dq 0
mbc_base: dq 0
mbc_bytes: dq 0
%endmacro
WDATA_DEFER WDATA_core_memory_consumer
