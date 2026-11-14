; Original owner SHUTDOWN rail, optionally coupled to the next BOOT WIN ACK,
; or to BOOT LINUX after a visible native local confirmation.
; prepare/cancel/arm never execute. A 30-second plan is committed only by the
; next admitted owner sequence, exact selected route, after its real ACK was sent.
; The existing idle tick executes power_execute(kind). Missing/mismatched/late
; commit leaves the ordinary BOOT reset/recovery path intact; no retry.
PR_IDLE equ 0
PR_PREPARED equ 1
PR_ARMED equ 2
PR_CANCELLED equ 3
PR_EXPIRED equ 4
PR_COMMITTED equ 5
PR_LOCAL_PROMPT equ 6
PR_LOCAL_CONFIRMED equ 7
PR_DISARMED equ 8                      ; ROOT108445: a BOOT WIN reset spent this arm
PR_PREPARE_RESTART equ 1
PR_PREPARE_SHUTDOWN equ 2
PR_ARM equ 3
PR_CANCEL equ 4
PR_PREPARE_LINUX equ 5
PR_MILLISECONDS equ 30000

; RDI original SHUTDOWN argument; RAX 0 = legacy grammar, else sd_out_buf.
command_power_return_request:
    push rbx
    push r12
    mov rbx,rdi
    xor ecx,ecx
.nonce:
    mov al,[rbx+rcx]
    call sd_nonce_char
    jc .suffix
    cmp ecx,SD_NONCE_MAX
    jae .legacy
    lea rdx,[rel pr_req_nonce]
    mov [rdx+rcx],al
    inc ecx
    jmp .nonce
.suffix:
    test ecx,ecx
    jz .legacy
    lea rdx,[rel pr_req_nonce]
    mov byte [rdx+rcx],0
    lea r12,[rbx+rcx]
    lea rdi,[rel pr_s_prepare_restart]
    mov rsi,r12
    call sd_streq
    mov ebx,PR_PREPARE_RESTART
    test eax,eax
    jnz .recognized
    lea rdi,[rel pr_s_prepare_shutdown]
    mov rsi,r12
    call sd_streq
    mov ebx,PR_PREPARE_SHUTDOWN
    test eax,eax
    jnz .recognized
    lea rdi,[rel pr_s_prepare_linux]
    mov rsi,r12
    call sd_streq
    mov ebx,PR_PREPARE_LINUX
    test eax,eax
    jnz .recognized
    lea rdi,[rel pr_s_arm_arg]
    mov rsi,r12
    call sd_streq
    mov ebx,PR_ARM
    test eax,eax
    jnz .recognized
    lea rdi,[rel pr_s_cancel_arg]
    mov rsi,r12
    call sd_streq
    mov ebx,PR_CANCEL
    test eax,eax
    jz .legacy
.recognized:
    call command_auth_owner_request
    test eax,eax
    jz .owner
    call pr_expire
    cmp byte [rel sd_state],SD_PENDING
    je .busy
    cmp byte [rel sd_state],SD_EXECUTING
    je .busy
    cmp ebx,PR_ARM
    je .arm
    cmp ebx,PR_CANCEL
    je .cancel
    ; Preparation must not destroy an existing live plan or its expiry.
    cmp byte [rel pr_state],PR_PREPARED
    je .same_prepare
    cmp byte [rel pr_state],PR_ARMED
    je .busy
    cmp byte [rel pr_state],PR_LOCAL_PROMPT
    je .busy
    cmp byte [rel pr_state],PR_LOCAL_CONFIRMED
    je .busy
    lea rdi,[rel pr_req_nonce]
    lea rsi,[rel pr_nonce]
    call sd_streq
    test eax,eax
    jnz .spent                         ; same terminal nonce never re-arms
    cmp byte [rel pbm_manager_launch],1
    jne .prepare
    cmp byte [rel pbm_reason],PBM_REASON_TRIAL
    jne .prepare
    cmp byte [rel pbm_strong_health_published],1
    jne .trial
.prepare:
    mov qword [rel pr_terminal],0
    mov byte [rel pr_linux],0
    mov eax,ebx
    inc eax                            ; requested POWER_RESTART2/SHUTDOWN3
    cmp ebx,PR_PREPARE_LINUX
    jne .prepared_kind
    mov byte [rel pr_linux],1
    mov eax,2                          ; same guarded warm restart, Linux BootNext
.prepared_kind:
    mov [rel pr_kind],al
    mov rax,[rel command_auth_last_sequence]
    mov [rel pr_prepare_sequence],rax
    lea rsi,[rel pr_req_nonce]
    lea rdi,[rel pr_nonce]
    mov ecx,SD_NONCE_MAX+1
    rep movsb
    call boot_ms_now
    add rax,PR_MILLISECONDS
    jc .spent
    mov [rel pr_deadline],rax
    mov byte [rel pr_state],PR_PREPARED
    jmp .prepared
.same_prepare:
    lea rdi,[rel pr_req_nonce]
    lea rsi,[rel pr_nonce]
    call sd_streq
    test eax,eax
    jz .busy
    mov eax,ebx
    inc eax
    cmp ebx,PR_PREPARE_LINUX
    jne .same_kind
    cmp byte [rel pr_linux],1
    jne .spent
    mov eax,2
.same_kind:
    cmp al,[rel pr_kind]
    jne .spent
    cmp ebx,PR_PREPARE_LINUX
    je .prepared
    cmp byte [rel pr_linux],0
    jne .spent
.prepared:
    lea rdi,[rel pr_s_prepared]
    jmp .state_kind
.arm:
    call pr_nonce_matches
    test eax,eax
    jz .spent
    mov al,PR_PREPARED
    cmp byte [rel pr_linux],0
    je .arm_state
    mov al,PR_LOCAL_CONFIRMED           ; no remote command can set this state
.arm_state:
    cmp byte [rel pr_state],al
    jne .spent
    mov rax,[rel command_auth_last_sequence]
    inc rax
    jz .spent
    mov [rel pr_next_sequence],rax
    mov byte [rel pr_state],PR_ARMED
    lea rdi,[rel pr_s_armed]
.state_kind:
    call sd_out_str
    lea rdi,[rel pr_nonce]
    call sd_out_str
    lea rdi,[rel pr_s_shutdown]
    cmp byte [rel pr_kind],2
    jne .kind
    lea rdi,[rel pr_s_restart]
.kind:
    cmp byte [rel pr_linux],0
    je .emit_kind
    lea rdi,[rel pr_s_linux]
.emit_kind:
    call sd_out_str
    jmp .handled
.cancel:
    call pr_nonce_matches
    test eax,eax
    jz .spent
    cmp byte [rel pr_state],PR_CANCELLED
    je .cancelled
    cmp byte [rel pr_state],PR_PREPARED
    je .cancel_live
    cmp byte [rel pr_state],PR_LOCAL_PROMPT
    je .cancel_live
    cmp byte [rel pr_state],PR_LOCAL_CONFIRMED
    je .cancel_live
    cmp byte [rel pr_state],PR_ARMED
    jne .spent
.cancel_live:
    mov byte [rel pr_state],PR_CANCELLED
.cancelled:
    lea rdi,[rel pr_s_cancelled]
    call sd_out_str
    lea rdi,[rel pr_nonce]
    call sd_out_str
    jmp .handled
.owner:
    lea r12,[rel sd_s_r_owner]
    jmp .refused
.busy:
    lea r12,[rel sd_s_r_busy]
    jmp .refused
.trial:
    lea r12,[rel sd_s_r_trial]
    jmp .refused
.spent:
    lea r12,[rel pr_s_spent]
.refused:
    inc dword [rel sd_refused_count]
    lea rdi,[rel sd_s_refused]
    call sd_out_str
    mov rdi,r12
    call sd_out_str
.handled:
    lea rax,[rel sd_out_buf]
    jmp .out
.legacy:
    xor eax,eax
.out:
    pop r12
    pop rbx
    ret

pr_nonce_matches:
    lea rdi,[rel pr_req_nonce]
    lea rsi,[rel pr_nonce]
    jmp sd_streq

pr_expire:
    cmp byte [rel pr_state],PR_PREPARED
    je .check
    cmp byte [rel pr_state],PR_ARMED
    je .check
    cmp byte [rel pr_state],PR_LOCAL_PROMPT
    je .check
    cmp byte [rel pr_state],PR_LOCAL_CONFIRMED
    jne .out
.check:
    call boot_ms_now
    cmp rax,[rel pr_deadline]
    jb .out
    mov byte [rel pr_state],PR_EXPIRED
.out:
    ret

command_power_return_busy:
    call pr_expire
    xor eax,eax
    cmp byte [rel pr_state],PR_PREPARED
    je .yes
    cmp byte [rel pr_state],PR_ARMED
    je .yes
    cmp byte [rel pr_state],PR_LOCAL_PROMPT
    je .yes
    cmp byte [rel pr_state],PR_LOCAL_CONFIRMED
    jne .out
.yes:
    mov eax,1
.out:
    ret

; Private GUI read only. A returned Linux executor can address only the
; original locally confirmed Terminal while this exact plan still executes.
; No state change, admission, retry, or promise that the window is still live.
command_power_return_terminal:
    xor eax,eax
    cmp byte [rel pr_linux],1
    jne .out
    cmp byte [rel pr_kind],2
    jne .out
    cmp byte [rel sd_kind],2
    jne .out
    cmp byte [rel pr_state],PR_COMMITTED
    jne .out
    cmp byte [rel sd_state],SD_EXECUTING
    jne .out
    mov rax,[rel pr_terminal]
.out:
    ret

; Private Terminal ABI, never a command/UDP entry. Its caller first checks the
; complete line/answer with keyprov_line_owner_equivalent. Window instance
; binds the answer to this one visible prompt; a new plan clears that binding.
; Local input cannot execute or arm anything: the next signed BOOT LINUX still
; owns BootNext, owner/replay admission, actual ACK and depth-zero retirement.
; RDI Terminal instance -> EAX1 prompt bound, otherwise no change.
command_power_return_local_begin:
    push rbx
    mov rbx,rdi
    call pr_expire
    cmp byte [rel pr_linux],1
    jne .no
    cmp byte [rel pr_state],PR_PREPARED
    jne .no
    test rbx,rbx
    jz .no
    mov [rel pr_terminal],rbx
    mov byte [rel pr_state],PR_LOCAL_PROMPT
    mov edi,8
    xor r8d,r8d
    call pr_local_trace
    mov eax,1
    jmp .out
.no:
    xor eax,eax
.out:
    pop rbx
    ret

; RDI same Terminal instance, ESI yes(1)/cancel(0), EDX input provenance:
; 1 physical human, 2 owner-equivalent injection, 0 unauthorized answer.
; The provenance comes from the native key path, never caller evidence JSON.
command_power_return_local_answer:
    push rbx
    push r12
    push r13
    mov rbx,rdi
    mov r12d,esi
    mov r13d,edx
    call pr_expire
    cmp byte [rel pr_linux],1
    jne .no
    cmp byte [rel pr_state],PR_LOCAL_PROMPT
    jne .no
    cmp rbx,[rel pr_terminal]
    jne .no
    cmp r12d,1
    ja .no
    ; Any unauthorized answer cancels, never leaves a confirmable prompt.
    cmp r13d,1
    je .authorized
    cmp r13d,2
    jne .unowned
.authorized:
    mov edi,9
    mov byte [rel pr_state],PR_CANCELLED
    test r12d,r12d
    jz .record
    mov edi,10
    mov byte [rel pr_state],PR_LOCAL_CONFIRMED
.record:
    mov r8d,r13d
    call pr_local_trace
    mov eax,1
    jmp .out
.unowned:
    mov byte [rel pr_state],PR_CANCELLED
    mov edi,9
    xor r8d,r8d
    call pr_local_trace
.no:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

pr_local_trace:
    xor esi,esi
    xor edx,edx
    mov ecx,4
    jmp command_power_return_trace

; ROOT108445: a signed BOOT WIN asks for a reboot to Windows and keeps it.
; Called after the BOOT ACK, before command_power_return_commit. An ARMED plan
; met by the exact verb BOOT WIN is disarmed (terminal; the nonce stays spent)
; with one serial record, whatever its kind, owner or sequence, and EAX1 tells
; the caller to leave bm_reboot_pending for the ordinary .reboot_fire path.
; Anything else returns EAX0 and changes nothing beyond the ordinary pr_expire
; (BOOT LINUX keeps its own commit).
; RDI verb, RSI argument.
command_power_return_bootwin:
    push rbx
    push r12
    mov rbx,rdi
    mov r12,rsi
    call pr_expire
    cmp byte [rel pr_state],PR_ARMED
    jne .no
    mov rdi,rbx
    lea rsi,[rel pr_s_boot]
    call sd_streq
    test eax,eax
    jz .no
    mov rdi,r12
    lea rsi,[rel pr_s_win]
    call sd_streq
    test eax,eax
    jz .no
    mov byte [rel pr_state],PR_DISARMED
    lea rdi,[rel pr_s_disarmed]
    call serial_string
    lea rdi,[rel pr_nonce]
    call serial_string
    lea rdi,[rel pr_s_kind]
    call serial_string
    movzx edi,byte [rel pr_kind]
    call serial_hex64
    lea rdi,[rel pr_s_disarm_linux]
    call serial_string
    movzx edi,byte [rel pr_linux]
    call serial_hex64
    lea rdi,[rel pr_s_disarm_by]
    call serial_string
    mov eax,1
    jmp .out
.no:
    xor eax,eax
.out:
    pop r12
    pop rbx
    ret

; Called only after real BOOT WIN/LINUX ACK send, before remote_end/scrub. The caller
; also requires bm_reboot_pending and no REBOOT/DBPUTKILL pending flags.
; EAX1 consumes that reset in favor of the depth-zero idle executor; EAX0 keeps
; the ordinary reset. No physical result is asserted here.
command_power_return_commit:
    push rbx
    push r12
    mov rbx,rdi
    mov r12,rsi
    call pr_expire
    cmp byte [rel pr_state],PR_ARMED
    jne .no
    mov byte [rel pr_state],PR_EXPIRED ; any attempted join spends this arm
    call command_auth_owner_request
    test eax,eax
    jz .no
    mov rax,[rel command_auth_last_sequence]
    cmp rax,[rel pr_next_sequence]
    jne .no
    mov rdi,rbx
    lea rsi,[rel pr_s_boot]
    call sd_streq
    test eax,eax
    jz .no
    mov rdi,r12
    lea rsi,[rel pr_s_win]
    cmp byte [rel pr_linux],0
    je .commit_route
    lea rsi,[rel pr_s_linux_arg]
.commit_route:
    call sd_streq
    test eax,eax
    jz .no
    cmp byte [rel sd_state],SD_PENDING
    je .no
    cmp byte [rel sd_state],SD_EXECUTING
    je .no
    lea rsi,[rel pr_nonce]
    lea rdi,[rel sd_nonce]
    mov ecx,SD_NONCE_MAX+1
    rep movsb
    mov al,[rel pr_kind]
    mov [rel sd_kind],al
    mov qword [rel sd_reason],0
    mov byte [rel sd_state],SD_PENDING
    mov byte [rel pr_state],PR_COMMITTED
    inc dword [rel sd_accepted_count]
    lea rdi,[rel pr_s_committed]
    call serial_string
    lea rdi,[rel sd_nonce]
    call serial_string
    lea rdi,[rel pr_s_kind]
    call serial_string
    movzx edi,byte [rel sd_kind]
    call serial_hex64
    lea rdi,[rel sd_s_crlf]
    call serial_string
    mov edi,1
    call command_power_return_event
    mov eax,1
    jmp .out
.no:
    xor eax,eax
.out:
    pop r12
    pop rbx
    ret

; Passive terminal evidence for the original committed plan only. Stage1 commit,
; 2 executor take, 3 actual storage outcome (result0 completed,1 disk refusal,
; 2 guest refusal/no storage attempted), 4 warm reset attempt, 5 PM1 S5 attempt,
; 6 firmware shutdown attempt, 7 executor returned failure. Attempts never mean
; physical completion. Serial can drop/interleave: readers require intact lines.
; EDI stage, ESI AHCI completed, EDX AHCI failed, ECX NVMe outcome, R8D result.
; Preserve ALL registers/flags: observing cannot change retirement/firmware I/O.
; The fixed record is <=434 bytes (32-byte nonce,64-byte build,11 u64s).
; Format via canonical fmt_* on a private 512-byte stack buffer, then issue ONE
; serial_string so unrelated CPU output cannot interleave between its fields.
%macro PR_TEXT 1
    lea rdi,[rel %1]
    mov rsi,rbp
    call fmt_str
    add rbp,rax
%endmacro
%macro PR_HEX 0
    mov rsi,rbp
    mov edx,16
    call fmt_hex
    add rbp,rax
%endmacro
command_power_return_trace:
    pushfq
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbp,rsp
    sub rsp,528
    and rsp,-16                       ; original ASM callers have mixed alignment
    mov [rsp+512],rbp                  ; restore exact incoming frame at .out
    ; Readiness11/12, diagnostic13 and refusal14 observe only this Linux executor.
    cmp edi,11
    jb .local_gate
    cmp edi,14
    ja .out
    cmp byte [rel pr_linux],1
    jne .out
    cmp byte [rel pr_kind],2
    jne .out
    cmp byte [rel pr_state],PR_COMMITTED
    jne .out
    cmp byte [rel sd_state],SD_EXECUTING
    jne .out
    jmp .bound
.local_gate:
    ; Only private local events8..10 may observe the nonexecuting plan.
    cmp edi,8
    jb .execution
    cmp edi,10
    ja .out
    cmp byte [rel pr_linux],1
    jne .out
    jmp .bound
.execution:
    cmp byte [rel pr_state],PR_COMMITTED
    jne .out
    cmp byte [rel sd_state],SD_PENDING
    jne .executing
    cmp edi,1
    je .bound
    jmp .out
.executing:
    cmp byte [rel sd_state],SD_EXECUTING
    jne .out
.bound:
    mov r12d,edi
    mov r13d,esi
    mov r14d,edx
    cmp edi,13
    jne .saved_width
    mov r14,rdx                         ; stage13 is a full-width returned end
.saved_width:
    mov r15d,ecx
    mov ebx,r8d
    mov qword [rsp+520],0               ; one additive actual-state record
.render:
    mov rbp,rsp
    cmp qword [rsp+520],0
    jne .state_head
    cmp r12d,14
    jne .diagnostic_head
    PR_TEXT pr_r_trace
    jmp .trace_head
.state_head:
    PR_TEXT pr_q_trace
    jmp .trace_head
.diagnostic_head:
    cmp r12d,13
    jne .readiness_head
    PR_TEXT pr_d_trace
    jmp .trace_head
.readiness_head:
    cmp r12d,11
    jb .ordinary_head
    PR_TEXT pr_o_trace
    jmp .trace_head
.ordinary_head:
    cmp r12d,8
    jb .execution_head
    PR_TEXT pr_s_local_trace
    jmp .trace_head
.execution_head:
    PR_TEXT pr_s_trace
.trace_head:
    PR_TEXT pr_nonce
    PR_TEXT pr_s_build
    PR_TEXT paos_build_hex
    PR_TEXT pr_s_boot_id
    PR_TEXT pr_s_hex
    mov rdi,[rel boot_tsc_start]
    PR_HEX
    PR_TEXT pr_s_boot_nonce
    PR_TEXT pr_s_hex
    mov edi,[rel boot_nonce]
    PR_HEX
    PR_TEXT pr_s_seq
    PR_TEXT pr_s_hex
    mov rdi,[rel pr_next_sequence]
    cmp r12d,11
    jae .trace_sequence
    cmp r12d,8
    jb .trace_sequence
    mov rdi,[rel pr_prepare_sequence]
.trace_sequence:
    PR_HEX
    PR_TEXT pr_s_kind
    PR_TEXT pr_s_hex
    movzx edi,byte [rel pr_kind]
    PR_HEX
    PR_TEXT pr_s_stage
    PR_TEXT pr_s_hex
    mov rdi,r12
    PR_HEX
    cmp qword [rsp+520],0
    jne .state_fields
    cmp r12d,11
    jae .readiness_fields
    PR_TEXT pr_s_ahci
    PR_TEXT pr_s_hex
    mov rdi,r13
    PR_HEX
    PR_TEXT pr_s_failed
    PR_TEXT pr_s_hex
    mov rdi,r14
    PR_HEX
    PR_TEXT pr_s_nvme
    PR_TEXT pr_s_hex
    mov rdi,r15
    PR_HEX
    PR_TEXT pr_s_result
    PR_TEXT pr_s_hex
    mov rdi,rbx
    PR_HEX
    jmp .time_fields
.state_fields:
    PR_TEXT pr_q_sd_state
    PR_TEXT pr_s_hex
    movzx edi,byte [rel sd_state]
    PR_HEX
    PR_TEXT pr_q_sd_kind
    PR_TEXT pr_s_hex
    movzx edi,byte [rel sd_kind]
    PR_HEX
    PR_TEXT pr_q_accepted
    PR_TEXT pr_s_hex
    mov edi,[rel sd_accepted_count]
    PR_HEX
    jmp .time_fields
.readiness_fields:
    cmp r12d,13
    je .diagnostic_fields
    PR_TEXT pr_o_outcome
    PR_TEXT pr_s_hex
    mov rdi,r13
    PR_HEX
    PR_TEXT pr_o_blocker
    PR_TEXT pr_s_hex
    mov rdi,r14
    PR_HEX
    jmp .time_fields
.diagnostic_fields:
    PR_TEXT pr_d_bytes
    PR_TEXT pr_s_hex
    mov rdi,r13
    PR_HEX
    PR_TEXT pr_d_end
    PR_TEXT pr_s_hex
    mov rdi,r14
    PR_HEX
.time_fields:
    PR_TEXT pr_s_ms
    PR_TEXT pr_s_hex
    call boot_ms_now
    mov rdi,rax
    PR_HEX
    PR_TEXT pr_s_until
    PR_TEXT pr_s_hex
    mov rdi,[rel pr_deadline]
    PR_HEX
    PR_TEXT sd_s_crlf
    mov rdi,rsp
    call serial_string
    call serial_drain_poll
    cmp qword [rsp+520],0
    jne .out
    cmp r12d,8
    je .state_snapshot
    cmp r12d,9
    je .state_snapshot
    cmp r12d,14
    jne .out
.state_snapshot:
    mov qword [rsp+520],1
    jmp .render
.out:
    mov rsp,[rsp+512]
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    popfq
    ret
; Stage13: ESI=actual diag_persist_flush RCX bytes, RDX=full-width RDI end.
; Count0/end0 means unavailable, not completed. This post-flush UART record
; cannot prove it survives in the same retained ring, disk durability or reset.
; POWERREF1 stage14 is the actual driver return3/4 before CLI/storage/wipe/
; reset. It says nothing about earlier retirement or a preselected BootNext.
pr_r_trace: db '[PAOS64] POWERREF1 nonce=',0
; Additional POWERSTATE1 snapshots leave the accepted POWERLOCAL1 format
; untouched. These are actual executor state/counters, not independent proof
; of intact keys, domain state, storage durability or firmware variables.
pr_q_trace: db '[PAOS64] POWERSTATE1 nonce=',0
pr_q_sd_state: db ' sd_state=',0
pr_q_sd_kind: db ' sd_kind=',0
pr_q_accepted: db ' accepted=',0
pr_d_trace: db '[PAOS64] POWERDIAG1 nonce=',0
pr_d_bytes: db ' bytes=',0
pr_d_end: db ' end=',0
pr_o_trace: db '[PAOS64] POWEROWN1 nonce=',0
pr_o_outcome: db ' outcome=',0
pr_o_blocker: db ' blocker=',0
; POWEROWN1 stage11=actual domain preparation EAX; stage12=actual guest
; readiness EAX/EDX. This passive witness has no storage/physical authority.
; Passive original BOOT LINUX per-device witness. RDI=actual driver record,
; ESI=logical slot. No input here grants execution authority. Preserve every
; register/flag and render ONE bounded (<850 byte) line in a private 1KiB buffer.
command_power_return_ahci:
    pushfq
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbp,rsp
    sub rsp,1040
    and rsp,-16
    mov [rsp+1024],rbp
    cmp byte [rel pr_linux],1
    jne .out
    cmp byte [rel pr_kind],2
    jne .out
    cmp byte [rel pr_state],PR_COMMITTED
    jne .out
    cmp byte [rel sd_state],SD_EXECUTING
    jne .out
    cmp esi,8
    jae .out
    cmp dword [rdi],1
    jne .out
    mov r12,rdi
    mov r13d,esi
    mov rbp,rsp
    PR_TEXT pr_a_trace
    PR_TEXT pr_nonce
    PR_TEXT pr_s_build
    PR_TEXT paos_build_hex
    PR_TEXT pr_s_boot_id
    PR_TEXT pr_s_hex
    mov rdi,[rel boot_tsc_start]
    PR_HEX
    PR_TEXT pr_s_boot_nonce
    PR_TEXT pr_s_hex
    mov edi,[rel boot_nonce]
    PR_HEX
    PR_TEXT pr_s_seq
    PR_TEXT pr_s_hex
    mov rdi,[rel pr_next_sequence]
    PR_HEX
    PR_TEXT pr_a_slot
    PR_TEXT pr_s_hex
    mov rdi,r13
    PR_HEX
    PR_TEXT pr_a_port
    PR_TEXT pr_s_hex
    mov edi,[r12+4]
    PR_HEX
    PR_TEXT pr_a_bdf
    PR_TEXT pr_s_hex
    mov edi,[r12+8]
    PR_HEX
    PR_TEXT pr_a_owner
    PR_TEXT pr_s_hex
    mov edi,[r12+12]
    PR_HEX
    PR_TEXT pr_a_poison_before
    PR_TEXT pr_s_hex
    mov edi,[r12+16]
    PR_HEX
    PR_TEXT pr_a_before_valid
    PR_TEXT pr_s_hex
    mov edi,[r12+20]
    PR_HEX
    PR_TEXT pr_a_ci_before
    PR_TEXT pr_s_hex
    mov edi,[r12+24]
    PR_HEX
    PR_TEXT pr_a_sact_before
    PR_TEXT pr_s_hex
    mov edi,[r12+28]
    PR_HEX
    PR_TEXT pr_a_tfd_before
    PR_TEXT pr_s_hex
    mov edi,[r12+32]
    PR_HEX
    PR_TEXT pr_a_attempt
    PR_TEXT pr_s_hex
    mov edi,[r12+36]
    PR_HEX
    PR_TEXT pr_a_outcome
    PR_TEXT pr_s_hex
    mov edi,[r12+40]
    PR_HEX
    PR_TEXT pr_a_after_valid
    PR_TEXT pr_s_hex
    mov edi,[r12+44]
    PR_HEX
    PR_TEXT pr_a_ci_after
    PR_TEXT pr_s_hex
    mov edi,[r12+48]
    PR_HEX
    PR_TEXT pr_a_sact_after
    PR_TEXT pr_s_hex
    mov edi,[r12+52]
    PR_HEX
    PR_TEXT pr_a_tfd_after
    PR_TEXT pr_s_hex
    mov edi,[r12+56]
    PR_HEX
    PR_TEXT pr_a_poison_after
    PR_TEXT pr_s_hex
    mov edi,[r12+60]
    PR_HEX
    PR_TEXT pr_s_ms
    PR_TEXT pr_s_hex
    call boot_ms_now
    mov rdi,rax
    PR_HEX
    PR_TEXT pr_s_until
    PR_TEXT pr_s_hex
    mov rdi,[rel pr_deadline]
    PR_HEX
    PR_TEXT sd_s_crlf
    mov rdi,rsp
    call serial_string
    call serial_drain_poll
.out:
    mov rsp,[rsp+1024]
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    popfq
    ret

pr_a_trace: db '[PAOS64] POWERAHCI1 nonce=',0
pr_a_slot: db ' slot=',0
pr_a_port: db ' port=',0
pr_a_bdf: db ' bdf=',0
pr_a_owner: db ' owner=',0
pr_a_poison_before: db ' poison_before=',0
pr_a_before_valid: db ' before_valid=',0
pr_a_ci_before: db ' ci_before=',0
pr_a_sact_before: db ' sact_before=',0
pr_a_tfd_before: db ' tfd_before=',0
pr_a_attempt: db ' attempt=',0
pr_a_outcome: db ' outcome=',0
pr_a_after_valid: db ' after_valid=',0
pr_a_ci_after: db ' ci_after=',0
pr_a_sact_after: db ' sact_after=',0
pr_a_tfd_after: db ' tfd_after=',0
pr_a_poison_after: db ' poison_after=',0
; Passive NVMe observation: RDI=original 34-qword record, ESI=actual saved
; terminal u32 decision. Present1 keeps POWERNVME1 byte-compatible; present0
; emits additive POWERNVME2, including refusals/unknowns, never PCI absence or
; invented Flush success. Preserves every register/flag and existing guards;
; fixed 2KiB private buffer, no MMIO or new launch/return authority.
command_power_return_nvme:
    pushfq
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbp,rsp
    sub rsp,2064
    and rsp,-16
    mov [rsp+2048],rbp
    cmp byte [rel pr_linux],1
    jne .out
    cmp byte [rel pr_kind],2
    jne .out
    cmp byte [rel pr_state],PR_COMMITTED
    jne .out
    cmp byte [rel sd_state],SD_EXECUTING
    jne .out
    cmp qword [rdi],1
    ja .out                            ; malformed present is never inactive
    mov r12,rdi
    mov r13d,esi                        ; preserve actual u32 through text formatting
    mov rbp,rsp
    cmp qword [r12],1
    je .present_head
    PR_TEXT pr_n_zero_trace
    jmp .identity
.present_head:
    PR_TEXT pr_n_trace
.identity:
    PR_TEXT pr_nonce
    PR_TEXT pr_s_build
    PR_TEXT paos_build_hex
    PR_TEXT pr_s_boot_id
    PR_TEXT pr_s_hex
    mov rdi,[rel boot_tsc_start]
    PR_HEX
    PR_TEXT pr_s_boot_nonce
    PR_TEXT pr_s_hex
    mov edi,[rel boot_nonce]
    PR_HEX
    PR_TEXT pr_s_seq
    PR_TEXT pr_s_hex
    mov rdi,[rel pr_next_sequence]
    PR_HEX
    cmp qword [r12],0
    jne .device_fields                 ; preserve every existing present1 wire byte
    PR_TEXT pr_n_present
    PR_TEXT pr_s_hex
    mov rdi,[r12]
    PR_HEX
    PR_TEXT pr_n_terminal
    PR_TEXT pr_s_hex
    mov rdi,r13
    PR_HEX
.device_fields:
    PR_TEXT pr_n_bdf
    PR_TEXT pr_s_hex
    mov rdi,[r12+8]
    PR_HEX
    PR_TEXT pr_n_bar
    PR_TEXT pr_s_hex
    mov rdi,[r12+16]
    PR_HEX
    PR_TEXT pr_n_owner
    PR_TEXT pr_s_hex
    mov rdi,[r12+24]
    PR_HEX
    PR_TEXT pr_n_nsid
    PR_TEXT pr_s_hex
    mov rdi,[r12+32]
    PR_HEX
    PR_TEXT pr_n_sector
    PR_TEXT pr_s_hex
    mov rdi,[r12+40]
    PR_HEX
    PR_TEXT pr_n_health
    PR_TEXT pr_s_hex
    mov rdi,[r12+48]
    PR_HEX
    PR_TEXT pr_n_poison_before
    PR_TEXT pr_s_hex
    mov rdi,[r12+56]
    PR_HEX
    PR_TEXT pr_n_io_before
    PR_TEXT pr_s_hex
    mov rdi,[r12+64]
    PR_HEX
    PR_TEXT pr_n_admin_before
    PR_TEXT pr_s_hex
    mov rdi,[r12+72]
    PR_HEX
    PR_TEXT pr_n_sqt_before
    PR_TEXT pr_s_hex
    mov rdi,[r12+80]
    PR_HEX
    PR_TEXT pr_n_sqh_before
    PR_TEXT pr_s_hex
    mov rdi,[r12+88]
    PR_HEX
    PR_TEXT pr_n_aqt_before
    PR_TEXT pr_s_hex
    mov rdi,[r12+96]
    PR_HEX
    PR_TEXT pr_n_aqh_before
    PR_TEXT pr_s_hex
    mov rdi,[r12+104]
    PR_HEX
    PR_TEXT pr_n_cid_before
    PR_TEXT pr_s_hex
    mov rdi,[r12+112]
    PR_HEX
    PR_TEXT pr_n_before_valid
    PR_TEXT pr_s_hex
    mov rdi,[r12+120]
    PR_HEX
    PR_TEXT pr_n_cc_before
    PR_TEXT pr_s_hex
    mov rdi,[r12+128]
    PR_HEX
    PR_TEXT pr_n_csts_before
    PR_TEXT pr_s_hex
    mov rdi,[r12+136]
    PR_HEX
    PR_TEXT pr_n_flush_attempt
    PR_TEXT pr_s_hex
    mov rdi,[r12+144]
    PR_HEX
    PR_TEXT pr_n_flush_result
    PR_TEXT pr_s_hex
    mov rdi,[r12+152]
    PR_HEX
    PR_TEXT pr_n_io_after
    PR_TEXT pr_s_hex
    mov rdi,[r12+160]
    PR_HEX
    PR_TEXT pr_n_admin_after
    PR_TEXT pr_s_hex
    mov rdi,[r12+168]
    PR_HEX
    PR_TEXT pr_n_sqt_after
    PR_TEXT pr_s_hex
    mov rdi,[r12+176]
    PR_HEX
    PR_TEXT pr_n_sqh_after
    PR_TEXT pr_s_hex
    mov rdi,[r12+184]
    PR_HEX
    PR_TEXT pr_n_aqt_after
    PR_TEXT pr_s_hex
    mov rdi,[r12+192]
    PR_HEX
    PR_TEXT pr_n_aqh_after
    PR_TEXT pr_s_hex
    mov rdi,[r12+200]
    PR_HEX
    PR_TEXT pr_n_cid_after
    PR_TEXT pr_s_hex
    mov rdi,[r12+208]
    PR_HEX
    PR_TEXT pr_n_poison_after_flush
    PR_TEXT pr_s_hex
    mov rdi,[r12+216]
    PR_HEX
    PR_TEXT pr_n_shutdown_attempt
    PR_TEXT pr_s_hex
    mov rdi,[r12+224]
    PR_HEX
    PR_TEXT pr_n_shutdown_result
    PR_TEXT pr_s_hex
    mov rdi,[r12+232]
    PR_HEX
    PR_TEXT pr_n_after_valid
    PR_TEXT pr_s_hex
    mov rdi,[r12+240]
    PR_HEX
    PR_TEXT pr_n_cc_after
    PR_TEXT pr_s_hex
    mov rdi,[r12+248]
    PR_HEX
    PR_TEXT pr_n_csts_after
    PR_TEXT pr_s_hex
    mov rdi,[r12+256]
    PR_HEX
    PR_TEXT pr_n_poison_after
    PR_TEXT pr_s_hex
    mov rdi,[r12+264]
    PR_HEX
    PR_TEXT pr_s_ms
    PR_TEXT pr_s_hex
    call boot_ms_now
    mov rdi,rax
    PR_HEX
    PR_TEXT pr_s_until
    PR_TEXT pr_s_hex
    mov rdi,[rel pr_deadline]
    PR_HEX
    PR_TEXT sd_s_crlf
    mov rdi,rsp
    call serial_string
    call serial_drain_poll
.out:
    mov rsp,[rsp+2048]
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    popfq
    ret

pr_n_trace: db '[PAOS64] POWERNVME1 nonce=',0
pr_n_zero_trace: db '[PAOS64] POWERNVME2 nonce=',0
pr_n_present: db ' present=',0
pr_n_terminal: db ' terminal=',0
pr_n_bdf: db ' bdf=',0
pr_n_bar: db ' bar=',0
pr_n_owner: db ' owner=',0
pr_n_nsid: db ' nsid=',0
pr_n_sector: db ' sector=',0
pr_n_health: db ' health=',0
pr_n_poison_before: db ' poison_before=',0
pr_n_io_before: db ' io_before=',0
pr_n_admin_before: db ' admin_before=',0
pr_n_sqt_before: db ' sqt_before=',0
pr_n_sqh_before: db ' sqh_before=',0
pr_n_aqt_before: db ' aqt_before=',0
pr_n_aqh_before: db ' aqh_before=',0
pr_n_cid_before: db ' cid_before=',0
pr_n_before_valid: db ' before_valid=',0
pr_n_cc_before: db ' cc_before=',0
pr_n_csts_before: db ' csts_before=',0
pr_n_flush_attempt: db ' flush_attempt=',0
pr_n_flush_result: db ' flush_result=',0
pr_n_io_after: db ' io_after=',0
pr_n_admin_after: db ' admin_after=',0
pr_n_sqt_after: db ' sqt_after=',0
pr_n_sqh_after: db ' sqh_after=',0
pr_n_aqt_after: db ' aqt_after=',0
pr_n_aqh_after: db ' aqh_after=',0
pr_n_cid_after: db ' cid_after=',0
pr_n_poison_after_flush: db ' poison_after_flush=',0
pr_n_shutdown_attempt: db ' shutdown_attempt=',0
pr_n_shutdown_result: db ' shutdown_result=',0
pr_n_after_valid: db ' after_valid=',0
pr_n_cc_after: db ' cc_after=',0
pr_n_csts_after: db ' csts_after=',0
pr_n_poison_after: db ' poison_after=',0
; RDI separate original 40B lifetime snapshot, ESI actual saved terminal u32.
; Passive export only, same original guards before record access. All GPRs and
; flags preserved. Fixed 2KiB private buffer; no live device reads or decisions.
command_power_return_nvme_lifetime:
    pushfq
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbp,rsp
    sub rsp,2064
    and rsp,-16
    mov [rsp+2048],rbp
    cmp byte [rel pr_linux],1
    jne .out
    cmp byte [rel pr_kind],2
    jne .out
    cmp byte [rel pr_state],PR_COMMITTED
    jne .out
    cmp byte [rel sd_state],SD_EXECUTING
    jne .out
    mov r12,rdi
    mov r13d,esi
    mov rbp,rsp
    PR_TEXT pr_l_trace
    PR_TEXT pr_nonce
    PR_TEXT pr_s_build
    PR_TEXT paos_build_hex
    PR_TEXT pr_s_boot_id
    PR_TEXT pr_s_hex
    mov rdi,[rel boot_tsc_start]
    PR_HEX
    PR_TEXT pr_s_boot_nonce
    PR_TEXT pr_s_hex
    mov edi,[rel boot_nonce]
    PR_HEX
    PR_TEXT pr_s_seq
    PR_TEXT pr_s_hex
    mov rdi,[rel pr_next_sequence]
    PR_HEX
    PR_TEXT pr_n_terminal
    PR_TEXT pr_s_hex
    mov rdi,r13
    PR_HEX
    PR_TEXT pr_l_available
    PR_TEXT pr_s_hex
    mov rdi,[r12]
    PR_HEX
    PR_TEXT pr_n_present
    PR_TEXT pr_s_hex
    mov rdi,[r12+8]
    PR_HEX
    PR_TEXT pr_l_observed
    PR_TEXT pr_s_hex
    mov rdi,[r12+16]
    PR_HEX
    ; Read only the fixed 15 captured comparison results, never live operands.
    xor ebx,ebx
    xor ecx,ecx
.bits:
    movzx edx,byte [r12+rcx+24]
    shl rdx,cl
    or rbx,rdx
    inc ecx
    cmp ecx,15
    jb .bits
    PR_TEXT pr_l_nonzero
    PR_TEXT pr_s_hex
    mov rdi,rbx
    PR_HEX
    PR_TEXT pr_s_ms
    PR_TEXT pr_s_hex
    call boot_ms_now
    mov rdi,rax
    PR_HEX
    PR_TEXT pr_s_until
    PR_TEXT pr_s_hex
    mov rdi,[rel pr_deadline]
    PR_HEX
    PR_TEXT sd_s_crlf
    mov rdi,rsp
    call serial_string
    call serial_drain_poll
.out:
    mov rsp,[rsp+2048]
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    popfq
    ret

pr_l_trace: db '[PAOS64] POWERNVMELIFE1 nonce=',0
pr_l_available: db ' present_available=',0
pr_l_observed: db ' observed=',0
pr_l_nonzero: db ' nonzero=',0

; RDI separate original 64B Flush completion snapshot, ESI saved terminal.
; Same original guards, identity and timing; no live CQ/MMIO/global inference.
command_power_return_nvme_completion:
    pushfq
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbp,rsp
    sub rsp,2064
    and rsp,-16
    mov [rsp+2048],rbp
    cmp byte [rel pr_linux],1
    jne .out
    cmp byte [rel pr_kind],2
    jne .out
    cmp byte [rel pr_state],PR_COMMITTED
    jne .out
    cmp byte [rel sd_state],SD_EXECUTING
    jne .out
    mov r12,rdi
    mov r13d,esi
    mov rbp,rsp
    PR_TEXT pr_cq_trace
    PR_TEXT pr_nonce
    PR_TEXT pr_s_build
    PR_TEXT paos_build_hex
    PR_TEXT pr_s_boot_id
    PR_TEXT pr_s_hex
    mov rdi,[rel boot_tsc_start]
    PR_HEX
    PR_TEXT pr_s_boot_nonce
    PR_TEXT pr_s_hex
    mov edi,[rel boot_nonce]
    PR_HEX
    PR_TEXT pr_s_seq
    PR_TEXT pr_s_hex
    mov rdi,[rel pr_next_sequence]
    PR_HEX
    PR_TEXT pr_n_terminal
    PR_TEXT pr_s_hex
    mov rdi,r13
    PR_HEX
    PR_TEXT pr_cq_submitted
    PR_TEXT pr_s_hex
    mov rdi,[r12+0]
    PR_HEX
    PR_TEXT pr_cq_expected_cid
    PR_TEXT pr_s_hex
    mov rdi,[r12+8]
    PR_HEX
    PR_TEXT pr_cq_expected_sqhd
    PR_TEXT pr_s_hex
    mov rdi,[r12+16]
    PR_HEX
    PR_TEXT pr_cq_observed
    PR_TEXT pr_s_hex
    mov rdi,[r12+24]
    PR_HEX
    PR_TEXT pr_cq_cid
    PR_TEXT pr_s_hex
    mov rdi,[r12+32]
    PR_HEX
    PR_TEXT pr_cq_sqid
    PR_TEXT pr_s_hex
    mov rdi,[r12+40]
    PR_HEX
    PR_TEXT pr_cq_sqhd
    PR_TEXT pr_s_hex
    mov rdi,[r12+48]
    PR_HEX
    PR_TEXT pr_cq_status
    PR_TEXT pr_s_hex
    mov rdi,[r12+56]
    PR_HEX
    PR_TEXT pr_s_ms
    PR_TEXT pr_s_hex
    call boot_ms_now
    mov rdi,rax
    PR_HEX
    PR_TEXT pr_s_until
    PR_TEXT pr_s_hex
    mov rdi,[rel pr_deadline]
    PR_HEX
    PR_TEXT sd_s_crlf
    mov rdi,rsp
    call serial_string
    call serial_drain_poll
.out:
    mov rsp,[rsp+2048]
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    popfq
    ret


pr_cq_trace: db '[PAOS64] POWERNVMECQ1 nonce=',0
pr_cq_submitted: db ' submitted=',0
pr_cq_expected_cid: db ' expected_cid=',0
pr_cq_expected_sqhd: db ' expected_sqhd=',0
pr_cq_observed: db ' observed=',0
pr_cq_cid: db ' cid=',0
pr_cq_sqid: db ' sqid=',0
pr_cq_sqhd: db ' sqhd=',0
pr_cq_status: db ' status=',0

; Original terminal NIC report, not an inventory or electrical-off witness.
; RDI=trusted original32B report, ESI=independently saved actualu32return.
; Only the existing committed shutdown plan emits. Linux warm-return kind2 and
; all existing reporters retain their guards/bytes. All guards precede pointer
; access; no live device, PCI or MMIO read and no execution/consent authority.
; Same native report/terminal result on the original committed local Linux2
; warm-return path. Separate entry preserves shutdown3 guards/wire bytes.
command_power_return_nic_warm:
    pushfq
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbp,rsp
    sub rsp,1040
    and rsp,-16
    mov [rsp+1024],rbp
    cmp byte [rel pr_linux],1
    jne command_power_return_nic.out
    cmp byte [rel pr_kind],2
    jne command_power_return_nic.out
    cmp byte [rel pr_state],PR_COMMITTED
    jne command_power_return_nic.out
    cmp byte [rel sd_state],SD_EXECUTING
    jne command_power_return_nic.out
    jmp command_power_return_nic.emit

command_power_return_nic:
    pushfq
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbp,rsp
    sub rsp,1040
    and rsp,-16
    mov [rsp+1024],rbp
    cmp byte [rel pr_linux],0
    jne .out
    cmp byte [rel pr_kind],3
    jne .out
    cmp byte [rel pr_state],PR_COMMITTED
    jne .out
    cmp byte [rel sd_state],SD_EXECUTING
    jne .out
.emit:
    cld
    mov r12,rdi
    mov r13d,esi
    mov rbp,rsp
    PR_TEXT pr_nic_trace
    PR_TEXT pr_nonce
    PR_TEXT pr_s_build
    PR_TEXT paos_build_hex
    PR_TEXT pr_s_boot_id
    PR_TEXT pr_s_hex
    mov rdi,[rel boot_tsc_start]
    PR_HEX
    PR_TEXT pr_s_boot_nonce
    PR_TEXT pr_s_hex
    mov edi,[rel boot_nonce]
    PR_HEX
    PR_TEXT pr_s_seq
    PR_TEXT pr_s_hex
    mov rdi,[rel pr_next_sequence]
    PR_HEX
    PR_TEXT pr_s_kind
    PR_TEXT pr_s_hex
    movzx edi,byte [rel pr_kind]        ; guarded original kind2 or3
    PR_HEX
    PR_TEXT pr_s_result
    PR_TEXT pr_s_hex
    mov rdi,r13
    PR_HEX
    PR_TEXT pr_nic_report_result
    PR_TEXT pr_s_hex
    mov edi,[r12+0]
    PR_HEX
    PR_TEXT pr_nic_stage
    PR_TEXT pr_s_hex
    mov edi,[r12+4]
    PR_HEX
    PR_TEXT pr_nic_pm_before
    PR_TEXT pr_s_hex
    mov edi,[r12+8]
    PR_HEX
    PR_TEXT pr_nic_pm_after
    PR_TEXT pr_s_hex
    mov edi,[r12+12]
    PR_HEX
    PR_TEXT pr_nic_command_after
    PR_TEXT pr_s_hex
    mov edi,[r12+16]
    PR_HEX
    PR_TEXT pr_nic_master_polls
    PR_TEXT pr_s_hex
    mov edi,[r12+20]
    PR_HEX
    PR_TEXT pr_nic_reserved0
    PR_TEXT pr_s_hex
    mov edi,[r12+24]
    PR_HEX
    PR_TEXT pr_nic_reserved1
    PR_TEXT pr_s_hex
    mov edi,[r12+28]
    PR_HEX
    PR_TEXT pr_s_ms
    PR_TEXT pr_s_hex
    call boot_ms_now
    mov rdi,rax
    PR_HEX
    PR_TEXT pr_s_until
    PR_TEXT pr_s_hex
    mov rdi,[rel pr_deadline]
    PR_HEX
    PR_TEXT sd_s_crlf
    mov rdi,rsp
    call serial_string
    call serial_drain_poll
.out:
    mov rsp,[rsp+1024]
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    popfq
    ret

pr_nic_trace: db '[PAOS64] POWERNIC1 nonce=',0
pr_nic_report_result: db ' report_result=',0
pr_nic_stage: db ' stage=',0
pr_nic_pm_before: db ' pm_before=',0
pr_nic_pm_after: db ' pm_after=',0
pr_nic_command_after: db ' command_after=',0
pr_nic_master_polls: db ' master_polls=',0
pr_nic_reserved0: db ' reserved0=',0
pr_nic_reserved1: db ' reserved1=',0

; Passive original native terminal report. RDI trusted64B/160B/128B/96B/256B, ESI actualu32,
; EDX family1=8168/2=8125/3=I219/4=8126/5=nativeHDA/6=foregroundHDAguard/7=inactiveAHCI/8=AHCItable/9=xHCIcommand/10=xHCIISO/11=xHCIterminal/12=AHCIterminal/13=AHCIVMDroute/14=appVMcustody, ECX final aggregateu32. Fixed shapes are selected
; only after original private identity/plan guards, before any pointer access.
; Raw availability/stage operands retain their driver's ABI; zeros alone are
; not observations. No live device read, decision or consent authority here.
; Family15: original foreground HDA terminal, two separately emitted40dword
; subrecords from the same call. No inference from either raw record here.
; Family16: original82540 terminal160B/schema1,40dwords; unknown bus completion retained.
; Maximum64 zeroextended dwords plus identity/timing fit the private2048B line.
command_power_return_native_nic:
    pushfq
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbp,rsp
    sub rsp,2064
    and rsp,-16
    mov [rsp+2048],rbp
    cmp edx,1
    je .family_ok
    cmp edx,2
    je .family_ok
    cmp edx,3
    je .family_ok
    cmp edx,4
    je .family_ok
    cmp edx,5
    je .family_ok
    cmp edx,6
    je .family_ok
    cmp edx,7
    je .family_ok
    cmp edx,8
    je .family_ok
    cmp edx,9
    je .family_ok
    cmp edx,10
    je .family_ok
    cmp edx,11
    je .family_ok
    cmp edx,12
    je .family_ok
    cmp edx,13
    je .family_ok
    cmp edx,14
    je .family_ok
    cmp edx,15
    je .family_ok
    cmp edx,16
    jne .out
.family_ok:
    cmp byte [rel pr_state],PR_COMMITTED
    jne .out
    cmp byte [rel sd_state],SD_EXECUTING
    jne .out
    cmp byte [rel pr_kind],3
    je .shutdown
    cmp byte [rel pr_kind],2
    jne .out
    cmp byte [rel pr_linux],1
    jne .out
    jmp .emit
.shutdown:
    cmp byte [rel pr_linux],0
    jne .out
.emit:
    cld
    mov r12,rdi
    mov r13d,esi
    mov r14d,edx
    mov r15d,ecx
    mov rbp,rsp
    PR_TEXT pr_native_trace
    PR_TEXT pr_nonce
    PR_TEXT pr_s_build
    PR_TEXT paos_build_hex
    PR_TEXT pr_s_boot_id
    PR_TEXT pr_s_hex
    mov rdi,[rel boot_tsc_start]
    PR_HEX
    PR_TEXT pr_s_boot_nonce
    PR_TEXT pr_s_hex
    mov edi,[rel boot_nonce]
    PR_HEX
    PR_TEXT pr_s_seq
    PR_TEXT pr_s_hex
    mov rdi,[rel pr_next_sequence]
    PR_HEX
    PR_TEXT pr_s_kind
    PR_TEXT pr_s_hex
    movzx edi,byte [rel pr_kind]
    PR_HEX
    PR_TEXT pr_native_family
    PR_TEXT pr_s_hex
    mov edi,r14d
    PR_HEX
    PR_TEXT pr_s_result
    PR_TEXT pr_s_hex
    mov edi,r13d
    PR_HEX
    PR_TEXT pr_native_aggregate
    PR_TEXT pr_s_hex
    mov edi,r15d
    PR_HEX
    cmp r14d,14
    je .words64
    cmp r14d,6
    je .words24
    cmp r14d,3
    je .words32
    cmp r14d,4
    je .words32
    cmp r14d,7
    je .words16
    cmp r14d,8
    je .words16
    cmp r14d,9
    je .words16
    cmp r14d,1
    jne .words40
.words16:
    mov r14d,16
    jmp .words
.words40:
    mov r14d,40
    jmp .words
.words64:
    mov r14d,64
    jmp .words
.words24:
    mov r14d,24
    jmp .words
.words32:
    mov r14d,32
.words:
    PR_TEXT pr_native_words
    PR_TEXT pr_s_hex
    mov edi,r14d
    PR_HEX
    PR_TEXT pr_native_data
    xor ebx,ebx
.field:
    test ebx,ebx
    jz .value
    PR_TEXT pr_native_slash
.value:
    PR_TEXT pr_s_hex
    mov edi,[r12+rbx*4]
    PR_HEX
    inc ebx
    cmp ebx,r14d
    jb .field
    PR_TEXT pr_s_ms
    PR_TEXT pr_s_hex
    call boot_ms_now
    mov rdi,rax
    PR_HEX
    PR_TEXT pr_s_until
    PR_TEXT pr_s_hex
    mov rdi,[rel pr_deadline]
    PR_HEX
    PR_TEXT sd_s_crlf
    mov rdi,rsp
    call serial_string
    call serial_drain_poll
.out:
    mov rsp,[rsp+2048]
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    popfq
    ret

pr_native_trace: db '[PAOS64] POWERNATIVE1 nonce=',0
pr_native_family: db ' family=',0
pr_native_aggregate: db ' aggregate=',0
pr_native_words: db ' words=',0
pr_native_data: db ' data=',0
pr_native_slash: db '/',0

; Actual original pure work predicates, not an inventory or global idle proof.
; EDI=actual u32 vfs_copy_busy, ESI=actual u32 storage_access_binding_busy,
; EDX=explicit observed mask (bit0 VFS, bit1 storage). Caller supplies 3 only
; after both calls. Passive original committed local Linux2 scope only;
; preserve all registers/flags and existing lifecycle/consent authority.
command_power_return_work:
    pushfq
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbp,rsp
    sub rsp,1040
    and rsp,-16
    mov [rsp+1024],rbp
    cmp byte [rel pr_linux],1
    jne .out
    cmp byte [rel pr_kind],2
    jne .out
    cmp byte [rel pr_state],PR_COMMITTED
    jne .out
    cmp byte [rel sd_state],SD_EXECUTING
    jne .out
    cld
    mov r12d,edi
    mov r13d,esi
    mov r14d,edx
    mov rbp,rsp
    PR_TEXT pr_work_trace
    PR_TEXT pr_nonce
    PR_TEXT pr_s_build
    PR_TEXT paos_build_hex
    PR_TEXT pr_s_boot_id
    PR_TEXT pr_s_hex
    mov rdi,[rel boot_tsc_start]
    PR_HEX
    PR_TEXT pr_s_boot_nonce
    PR_TEXT pr_s_hex
    mov edi,[rel boot_nonce]
    PR_HEX
    PR_TEXT pr_s_seq
    PR_TEXT pr_s_hex
    mov rdi,[rel pr_next_sequence]
    PR_HEX
    PR_TEXT pr_s_kind
    PR_TEXT pr_s_hex
    mov edi,2
    PR_HEX
    PR_TEXT pr_work_observed
    PR_TEXT pr_s_hex
    mov rdi,r14
    PR_HEX
    PR_TEXT pr_work_vfs
    PR_TEXT pr_s_hex
    mov rdi,r12
    PR_HEX
    PR_TEXT pr_work_storage
    PR_TEXT pr_s_hex
    mov rdi,r13
    PR_HEX
    PR_TEXT pr_s_ms
    PR_TEXT pr_s_hex
    call boot_ms_now
    mov rdi,rax
    PR_HEX
    PR_TEXT pr_s_until
    PR_TEXT pr_s_hex
    mov rdi,[rel pr_deadline]
    PR_HEX
    PR_TEXT sd_s_crlf
    mov rdi,rsp
    call serial_string
    call serial_drain_poll
.out:
    mov rsp,[rsp+1024]
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    popfq
    ret

pr_work_trace: db '[PAOS64] POWERWORK1 nonce=',0
pr_work_observed: db ' observed=',0
pr_work_vfs: db ' vfs=',0
pr_work_storage: db ' storage=',0

%unmacro PR_TEXT 1
%unmacro PR_HEX 0

; No controller outcomes are implied by these lifecycle events.
command_power_return_event:
    push rsi
    push rdx
    push rcx
    push r8
    xor esi,esi
    xor edx,edx
    mov ecx,4
    xor r8d,r8d
    sub rsp,8
    call command_power_return_trace
    add rsp,8
    pop r8
    pop rcx
    pop rdx
    pop rsi
    ret

pr_s_hex: db '0x',0
pr_s_trace: db '[PAOS64] POWERRET1 nonce=',0
pr_s_local_trace: db '[PAOS64] POWERLOCAL1 nonce=',0
pr_s_build: db ' build=',0
pr_s_boot_id: db ' boot=',0
pr_s_boot_nonce: db ' bn=',0
pr_s_seq: db ' seq=',0
pr_s_stage: db ' stage=',0
pr_s_ahci: db ' ahci=',0
pr_s_failed: db ' failed=',0
pr_s_nvme: db ' nvme=',0
pr_s_result: db ' result=',0
pr_s_ms: db ' ms=',0
pr_s_until: db ' until=',0

pr_s_prepare_restart: db ' prepare-return-restart',0
pr_s_prepare_linux: db ' prepare-return-linux',0
pr_s_prepare_shutdown: db ' prepare-return-shutdown',0
pr_s_arm_arg: db ' arm-return',0
pr_s_cancel_arg: db ' cancel-return',0
pr_s_prepared: db 'prepared ',0
pr_s_armed: db 'armed ',0
pr_s_cancelled: db 'cancelled ',0
pr_s_restart: db ' restart',0
pr_s_shutdown: db ' shutdown',0
pr_s_linux: db ' linux',0
pr_s_linux_arg: db 'LINUX',0
pr_s_spent: db 'plan-spent-or-expired (prepare a fresh nonce)',0
pr_s_boot: db 'BOOT',0
pr_s_win: db 'WIN',0
pr_s_committed: db '[PAOS64] power.return.commit nonce=',0
pr_s_kind: db ' kind=',0
pr_s_disarmed: db '[PAOS64] power.return.disarmed nonce=',0
pr_s_disarm_linux: db ' linux=',0
pr_s_disarm_by: db ' by=BOOT-WIN reset=direct',13,10,0
%macro WDATA_svc_power_return_0 0
alignb 8
pr_deadline: resq 1
pr_next_sequence: resq 1
pr_prepare_sequence: resq 1
pr_terminal: resq 1
pr_linux: resb 1
pr_state: resb 1
pr_kind: resb 1
pr_nonce: resb SD_NONCE_MAX+1
pr_req_nonce: resb SD_NONCE_MAX+1
%endmacro
WDATA_BSS_DEFER WDATA_svc_power_return_0
