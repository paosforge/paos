;; MODULE svc/command_memory_consumer
;; LAYER 5
;; EXPORTS memcon_declare, memcon_idle, memcon_text, memcon_summary, memcon_out_ready
;; IMPORTS svc/runtime_failure_sources, core/memory_consumer, core/time, svc/command, svc/command_auth, sec/principal, sec/owner_store, svc/lab_return, svc/recovery_controller, core/reset_wipe
;; CAPS
;; OWNER saga:core
; MEMCON BEGIN | STATUS/PROBE/RELEASE/RETRY/CANCEL/FINISH <16 hex job>.
; Every form is OWNER MUTATE, including status. The registry/public wrapper
; consumes a fresh AUTH2 sequence before this handler; SSH/local/injected
; authority is deliberately not a signed operation nonce. No public exception.
; Only CPU scratch, fixed sizes/kinds in core/memory_consumer; no caller spans.
;
; A remote job retains scalar OWNER + native owner-record generation/state,
; never a request/ticket pointer, storage SPECIAL intent or local login epoch.
; Owner-store replacement/failure, standing capability loss, expiry or CANCEL
; retires this incarnation permanently. Local desktop locking neither grants
; nor revokes a separately authenticated remote service. Cleanup needs no user
; authority, but remains bounded by the original and any shorter return cap.
%include "core/abi/memory_consumer.inc"

memcon_declare:
    lea rdi, [rel memcon_name]
    lea rsi, [rel cmd_verb_memcon]
    xor edx, edx
    mov ecx, ARGT_TEXT
    xor r8d, r8d
    mov r9d, 1
    jmp command_register_verb

cmd_verb_memcon:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13, rsi
    mov byte [rel memcon_out_ready], 0
    mov qword [r13+RSP_ACCEPTED], 0
    mov qword [r13+RSP_JOBID], 0
    mov qword [r13+RSP_VAL], 0
    mov qword [r13+RSP_EXPECTED], 0
    cmp byte [rel cmd_in_dispatch], 1
    jne .denied
    cmp dword [rel cmd_dispatch_depth], 1
    jne .denied
    cmp qword [r12+REQ_PRINCIPAL], CMD_PRINCIPAL_OWNER
    jne .denied
    call command_auth_owner_request
    cmp eax, 1                         ; consumed AUTH2, not SSH's transport grant
    jne .denied
    mov rdx, [rel command_auth_remote_ticket]
    mov rax, CMD_AUTH_CAP_MUTATE
    cmp [rdx+AUTH_T_CAP], rax
    jne .denied
    mov rax, [rdx+AUTH_T_SEQ]
    cmp rax, [rel command_auth_last_sequence]
    jne .denied
    test rax, rax
    jz .denied
    mov r14, rax                       ; scalar nonce for a successful new binding
    mov r15, [rdx+AUTH_T_EXPIRES]       ; copy before the request unwinds
    call memcon_authority
    test eax, eax
    jz .denied
    mov rbx, [r12+REQ_ARG]
    test rbx, rbx
    jz .badarg
    xor ecx, ecx
.length:
    cmp ecx, 40
    jae .badarg
    cmp byte [rbx+rcx], 0
    je .bounded
    inc ecx
    jmp .length
.bounded:
    lea rdi, [rel memcon_begin_word]
    mov rsi, rbx
    call strcmp
    test eax, eax
    jz .begin
    ; Match an entire fixed action followed by exactly one opaque uint32 job.
    xor r12d, r12d
.word:
    lea rdi, [rel memcon_words]
    mov eax, r12d
    shl eax, 4
    add rdi, rax
    mov rsi, rbx
.compare:
    mov al, [rdi]
    test al, al
    jz .matched
    cmp al, [rsi]
    jne .next_word
    inc rdi
    inc rsi
    jmp .compare
.next_word:
    inc r12d
    cmp r12d, 6
    jb .word
    jmp .badarg
.matched:
    cmp byte [rsi], ' '
    jne .badarg
    inc rsi
    xor ebx, ebx
    mov ecx, 16
.hex:
    movzx eax, byte [rsi]
    sub eax, '0'
    cmp eax, 9
    jbe .digit
    movzx eax, byte [rsi]
    or eax, 32
    sub eax, 'a'
    cmp eax, 5
    ja .badarg
    add eax, 10
.digit:
    shl rbx, 4
    or rbx, rax
    inc rsi
    dec ecx
    jnz .hex
    cmp byte [rsi], 0
    jne .badarg
    test rbx, rbx
    jz .stale
    mov eax, -1
    cmp rbx, rax
    ja .stale
    cmp rbx, [rel memcon_job]
    jne .stale
    call memcon_validate
    test eax, eax
    jz .revoked
    ; STATUS is protected by the same nonce gate, but can observe a retired job.
    test r12d, r12d
    jz .snapshot
    cmp byte [rel memcon_revoked], 0
    jne .denied
    call memcon_clock
    jc .revoke_deny
    cmp rax, [rel memcon_work_until]
    jae .revoke_deny
    mov r14, rax
    call memcon_return_cap
    cmp rax, [rel memcon_return_until]
    jae .action_cap
    mov [rel memcon_return_until], rax
    jmp .revoke_deny
.action_cap:
    cmp r14, [rel memcon_return_until]
    jae .revoke_deny
    mov rdi, [rel memcon_binding]
    mov rsi, rbx
    mov edx, r12d                      ; word order equals MBC_ACT_* enum
    call mbc_action                    ; schedules only; never polls in this frame
    test eax, eax
    jnz .core_error
    cmp r12d, MBC_ACT_CANCEL
    jne .snapshot
    mov byte [rel memcon_revoked], 1
    jmp .snapshot
.revoked:
    call memcon_revoke
    test r12d, r12d
    jz .snapshot
    jmp .denied
.revoke_deny:
    call memcon_revoke
    jmp .denied
.begin:
    call memcon_clock
    jc .denied
    mov rbx, rax                       ; now ms
    ; Work <=30s, cleanup <=15s after work; inherit earlier native return caps.
    call memcon_return_cap
    mov r12, rax                       ; original maximum cleanup boundary
    call time_wall_now_s
    test rax, rax
    jz .denied
    cmp r15, rax
    jbe .denied
    sub r15, rax
    cmp r15, 30
    jbe .ttl
    mov r15d, 30
.ttl:
    imul r15, 1000
    add r15, rbx
    jc .denied
    cmp r15, r12
    jb .work_bound
    lea r15, [r12-1]                   ; at least one cleanup millisecond
.work_bound:
    cmp r15, rbx
    jbe .denied
    lea rcx, [r15+MBC_CLEANUP_MAX_MS]
    cmp rcx, r15
    jb .denied
    cmp rcx, r12
    cmova rcx, r12
    mov rdi, r14
    mov rsi, rbx
    mov rdx, r15
    call mbc_begin
    test eax, eax
    jnz .core_error
    mov [rel memcon_job], rdx
    mov [rel memcon_binding], r14
    mov [rel memcon_work_until], r15
    mov [rel memcon_return_until], r12
    mov rax, [rel ows_generation]
    mov [rel memcon_generation], rax
    mov al, [rel ows_state]
    mov [rel memcon_owner_state], al
    mov qword [rel memcon_principal], PRIN_OWNER
    mov byte [rel memcon_revoked], 0
    mov byte [rel memcon_cleanup_blocked], 0
    jmp .snapshot
.snapshot:
    lea rdi, [rel memcon_summary]
    call mbc_snapshot
    test eax, eax
    jnz .core_error
    lea rdi,[rel memcon_summary]
    call runtime_failure_memory_source
    call memcon_render
    mov byte [rel memcon_out_ready], 1
    mov rax, [rel memcon_summary+MBC_SUM_JOB]
    mov [r13+RSP_VAL], rax
    mov qword [r13+RSP_CODE], CMDE_OK
    lea rax, [rel memcon_text]
    mov [r13+RSP_HINT], rax
    xor eax, eax
    jmp .out
.stale:
    mov eax, MB_E_STALE
.core_error:
    mov [r13+RSP_EXPECTED], rax
    mov eax, CMDE_BADJOB
    jmp .error
.badarg:
    mov eax, CMDE_BADARG
    jmp .error
.denied:
    mov eax, CMDE_AUTHDENY
.error:
    mov [r13+RSP_CODE], rax
    lea rdx, [rel memcon_usage]
    mov [r13+RSP_HINT], rdx
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Current native owner incarnation, independent of the local desktop principal.
memcon_authority:
    cmp byte [rel reset_wipe_done], 0
    jne .no
    mov al, [rel ows_state]
    cmp al, OWS_LOADED
    je .caps
    cmp al, OWS_UNOWNED                ; clean absence: existing compiled RSA owner
    jne .no
.caps:
    cmp qword [rel ows_generation], -1
    je .no
    mov edi, PRIN_OWNER
    call principal_capabilities
    mov rdx, CMD_AUTH_CAP_MUTATE
    and rax, rdx
    cmp rax, rdx
    sete al
    movzx eax, al
    ret
.no:
    xor eax, eax
    ret

memcon_validate:
    call memcon_authority
    test eax, eax
    jz .no
    cmp qword [rel memcon_principal], PRIN_OWNER
    jne .no
    mov rax, [rel ows_generation]
    cmp rax, [rel memcon_generation]
    jne .no
    mov al, [rel ows_state]
    cmp al, [rel memcon_owner_state]
    jne .no
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

memcon_revoke:
    mov byte [rel memcon_revoked], 1    ; sticky even if native authority returns
    mov rdi, [rel memcon_binding]
    jmp mbc_revoke

; Real monotonic sample; CF signals unavailable. Core handles rollback itself.
memcon_clock:
    cmp qword [rel tsc_khz], 0
    je .bad
    call time_monotonic_now_us
    test rax, rax
    jz .bad
    xor edx, edx
    mov ecx, 1000
    div rcx
    cmp rax, [rel memcon_last_ms]
    jb .bad
    mov [rel memcon_last_ms], rax
    clc
    ret
.bad:
    stc
    ret

; Earliest existing absolute return deadline, floored into the same ms domain.
; Cancel/contact never extends a job which already inherited an earlier cap.
memcon_return_cap:
    mov rax, -1
    mov rdx, [rel lab_return_deadline_us]
    test rdx, rdx
    jz .controller
    cmp rax, rdx
    cmova rax, rdx
.controller:
    mov rdx, [rel rc_absolute_us]
    test rdx, rdx
    jz .silence
    cmp rax, rdx
    cmova rax, rdx
.silence:
    mov rdx, [rel rc_deadline_us]
    test rdx, rdx
    jz .convert
    cmp rax, rdx
    cmova rax, rdx
.convert:
    xor edx, edx
    mov ecx, 1000
    div rcx
    ret

; Sole production service call: normal serialized BSP idle, after input, session
; lock and independent return handling; never a command frame or safe_halt.
; One core poll maximum. No scheduler loop, callback, private executor or wait.
memcon_idle:
    cmp dword [rel cmd_dispatch_depth], 0
    jne .out
    cmp byte [rel command_auth_remote_active], 0
    jne .out
    cmp qword [rel memcon_binding], 0
    je .out
    push rbx
    cmp byte [rel memcon_revoked], 0
    jne .retire
    call memcon_validate
    test eax, eax
    jnz .clock
.retire:
    call memcon_revoke
    cmp eax, MB_E_BUSY
    je .busy
.clock:
    call memcon_clock
    jc .clock_lost
    mov rbx, rax
    call memcon_return_cap
    cmp rax, [rel memcon_return_until]
    jae .cap_kept
    mov [rel memcon_return_until], rax ; a later controller cannot extend custody
    call memcon_revoke
    cmp eax, MB_E_BUSY
    je .busy
.cap_kept:
    cmp rbx, [rel memcon_return_until]
    jae .expired                      ; no cleanup work beyond an inherited cap
    mov rdi, rbx
    call mbc_poll
.busy:
    pop rbx
.out:
    ret
.clock_lost:
    call memcon_revoke
    mov byte [rel memcon_cleanup_blocked], 1
    ; No invented elapsed time or cleanup on an unavailable clock. Keys remain.
    pop rbx
    ret
.expired:
    call memcon_revoke
    mov byte [rel memcon_cleanup_blocked], 1
    pop rbx
    ret

; Bounded public shape: nine scalar snapshot words as fixed-width hex, plus
; sticky adapter retirement/cleanup-blocked bits. No raw keys or addresses.
memcon_render:
    lea rdi, [rel memcon_text]
    lea rsi, [rel memcon_prefix]
.prefix:
    lodsb
    test al, al
    jz .fields
    stosb
    jmp .prefix
.fields:
    lea rsi, [rel memcon_summary]
    mov r8d, 9
.field:
    lodsq
    mov ecx, 16
.nibble:
    rol rax, 4
    mov edx, eax
    and edx, 15
    add dl, '0'
    cmp dl, '9'
    jbe .put
    add dl, 'a'-'9'-1
.put:
    mov [rdi], dl
    inc rdi
    dec ecx
    jnz .nibble
    mov byte [rdi], ' '
    inc rdi
    dec r8d
    jnz .field
    lea rsi, [rel memcon_retired_label]
.suffix:
    lodsb
    test al, al
    jz .bits
    stosb
    jmp .suffix
.bits:
    mov al, [rel memcon_revoked]
    add al, '0'
    stosb
    mov al, [rel memcon_cleanup_blocked]
    add al, '0'
    stosb
    mov byte [rdi], 0
    ret

memcon_name: db "MEMCON",0
memcon_begin_word: db "BEGIN",0
memcon_words:
    db "STATUS",0
    times 16-7 db 0
    db "PROBE",0
    times 16-6 db 0
    db "RELEASE",0
    times 16-8 db 0
    db "RETRY",0
    times 16-6 db 0
    db "CANCEL",0
    times 16-7 db 0
    db "FINISH",0
    times 16-7 db 0
memcon_usage: db "MEMCON BEGIN|STATUS/PROBE/RELEASE/RETRY/CANCEL/FINISH <16hex job>; AUTH2 OWNER MUTATE",0
memcon_prefix: db "MEMCON job,phase,error,last,flags,progress,owned,work_ms,cleanup_ms=",0
memcon_retired_label: db "retired,cleanup_blocked=",0
%include "core/abi/wdata.inc"
%macro WDATA_svc_command_memory_consumer 0
align 8
memcon_binding: dq 0
memcon_job: dq 0
memcon_principal: dq 0
memcon_generation: dq 0
memcon_work_until: dq 0
memcon_return_until: dq 0
memcon_last_ms: dq 0
memcon_owner_state: db 0
memcon_revoked: db 0
memcon_cleanup_blocked: db 0
memcon_out_ready: db 0
align 8
memcon_summary: times MBC_SUM_SIZE db 0
memcon_text: times 256 db 0
%endmacro
WDATA_DEFER WDATA_svc_command_memory_consumer
