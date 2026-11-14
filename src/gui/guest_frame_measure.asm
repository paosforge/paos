;; MODULE gui/guest_frame_measure
;; LAYER 6
;; EXPORTS guest_frame_measure_init, guest_frame_measure_tick
;; IMPORTS gui/guest_desktop, gui/chat_app, core/smp, core/time, core/lib/sha256, svc/command, sec/session
;; CAPS
;; OWNER rc-codex-av
;; CONTEXT: bsp_only (idle/owner command; bounded SHA uses BSP compression scratch)
; Actual creator: rc-codex-av / OpenAI Codex. T1-5 S1b, LIVE ledger74091.
; FRAMECOPY START <16 lowercase hex nonce>
; FRAMECOPY STATUS <same nonce> <trial0..5>
; FRAMECOPY CANCEL <same nonce>
; One captured native packed rectangle is held across three single/parallel
; pairs. No raw pointer or guest write interface. Capture is a temporal sample.
; Existing stage checks bind guest/window/surface/session before EVERY turn.
; COPY alone is timed; SHA256 and byte comparison are bounded and outside it.
; A failure transfers a live job to existing quarantine before any buffer reuse.
FM_WAIT equ 1
FM_SOURCE equ 2
FM_POISON equ 3
FM_BEGIN equ 4
FM_RUNNING equ 5
FM_OUTPUT equ 6
FM_DONE equ 7
FM_FAILED equ 8
FM_HASH_BYTES equ 4096
struc fm_record
 .us: resq 1
 .digest: resb 32
 .chunks: resq MAXCORE
 .job: resq 1
 .bsp: resq 1
 .count: resq 1
 .online: resq 1
endstruc

guest_frame_measure_init:
    lea rdi, [rel fm_verb]
    lea rsi, [rel fm_command]
    xor edx, edx
    mov ecx, ARGT_TEXT
    xor r8d, r8d
    mov r9d, 1                         ; owner/MUTATE through canonical registry
    jmp command_register_verb

fm_command:
    call cmd_handler_prologue
    cld
    push rbx
    push rbp
    push r12
    push r13
    push r14
    mov r12, rdi
    mov r13, rsi
    call session_shell_request_principal
    cmp rax, CMD_PRINCIPAL_OWNER         ; full authenticated frame, not ambient owner
    jne .deny
    call session_shell_require_unlocked
    test eax, eax
    jnz .deny
    mov rbx, [r12 + REQ_ARG]
    test rbx, rbx
    jz .bad
    xor eax, eax
.arg_length:
    cmp byte [rbx + rax], 0
    je .arg_end
    inc eax
    cmp eax, 26
    jb .arg_length
    jmp .bad
.arg_end:
    cmp eax, 22
    jb .bad
    xor ebp, ebp                       ; 0 START, 1 STATUS, 2 CANCEL
    cmp dword [rbx], 'STAR'
    jne .status
    cmp eax, 22
    jne .bad
    cmp word [rbx + 4], 'T '
    jne .bad
    add rbx, 6
    jmp .nonce
.status:
    inc ebp
    cmp dword [rbx], 'STAT'
    jne .cancel
    cmp eax, 25
    jne .bad
    cmp word [rbx + 4], 'US'
    jne .bad
    cmp byte [rbx + 6], ' '
    jne .bad
    add rbx, 7
    jmp .nonce
.cancel:
    inc ebp
    cmp eax, 23
    jne .bad
    cmp dword [rbx], 'CANC'
    jne .bad
    cmp word [rbx + 4], 'EL'
    jne .bad
    cmp byte [rbx + 6], ' '
    jne .bad
    add rbx, 7
.nonce:
    xor ecx, ecx
.nonce_loop:
    mov al, [rbx + rcx]
    cmp al, '0'
    jb .bad
    cmp al, '9'
    jbe .digit
    cmp al, 'a'
    jb .bad
    cmp al, 'f'
    ja .bad
.digit:
    inc ecx
    cmp ecx, 16
    jb .nonce_loop
    xor r14d, r14d
    cmp ebp, 1
    jne .end_arg
    cmp byte [rbx + 16], ' '
    jne .bad
    movzx r14d, byte [rbx + 17]
    sub r14d, '0'
    cmp r14d, 5
    ja .bad
    cmp byte [rbx + 18], 0
    jne .bad
    jmp .parsed
.end_arg:
    cmp byte [rbx + 16], 0
    jne .bad
.parsed:
    test ebp, ebp
    jz .start
    cmp byte [rel fm_state], 0
    je .bad
    mov rax, [rbx]
    cmp rax, [rel fm_nonce]
    jne .bad
    mov rax, [rbx + 8]
    cmp rax, [rel fm_nonce + 8]
    jne .bad
    cmp ebp, 2
    jne .reply
    cmp byte [rel fm_state], FM_DONE
    jae .reply
    call fm_abort
    jmp .reply
.start:
    movzx eax, byte [rel fm_state]
    test eax, eax
    jz .available
    cmp eax, FM_DONE
    jb .bad                            ; never overwrite an active owner
.available:
    call guest_desktop_show             ; existing START/display only; never starts guest
    test eax, eax
    jnz .bad
    cmp byte [rel gd_stage_state], GD_ST_DISABLED
    je .bad
    mov rax, [rbx]
    mov [rel fm_nonce], rax
    mov rax, [rbx + 8]
    mov [rel fm_nonce + 8], rax
    lea rdi, [rel fm_records]
    xor eax, eax
    mov ecx, (fm_record_size * 6) / 8
    rep stosq
    mov qword [rel fm_trial], 0
    mov qword [rel fm_cursor], 0
    mov qword [rel fm_len], 0
    mov qword [rel fm_width], 0
    mov qword [rel fm_height], 0
    lea rdi, [rel fm_source_digest]
    mov ecx, 4
    rep stosq
    mov rax, [rel session_authority_epoch]
    mov [rel fm_epoch], rax
    call time_monotonic_now_us
    test rax, rax
    jz .bad
    add rax, 60000000
    jc .bad
    mov [rel fm_deadline], rax
    mov byte [rel fm_state], FM_WAIT
.reply:
    call fm_reply
    mov byte [rel chat_out_ready], 1
    mov qword [r13 + RSP_CODE], CMDE_OK
    mov qword [r13 + RSP_VAL], 0
    jmp .out
.deny:
    mov qword [r13 + RSP_CODE], CMDE_CAPDENY
    jmp .out
.bad:
    mov qword [r13 + RSP_CODE], CMDE_BADARG
.out:
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Returns EAX=1 if this turn belongs to measurement (skip ordinary desktop
; housekeeping). WAIT permits native capture; at BEGIN it freezes S and takes
; custody before the ordinary owner can publish an async job.
guest_frame_measure_tick:
    push rbx
    push rbp
    push r12
    movzx eax, byte [rel fm_state]
    test eax, eax
    jz .inactive
    cmp eax, FM_DONE
    jae .inactive
    call gd_locked                       ; idle has no command authority frame
    test eax, eax
    jnz .fail
    mov rax, [rel session_authority_epoch]
    cmp rax, [rel fm_epoch]
    jne .fail
    call time_monotonic_now_us
    test rax, rax
    jz .fail
    cmp rax, [rel fm_deadline]
    jae .fail
    cmp byte [rel fm_state], FM_WAIT
    jne .owned
    cmp byte [rel gd_stage_state], GD_ST_DISABLED
    je .fail
    cmp byte [rel gd_stage_state], GD_ST_BEGIN
    jne .inactive                       ; let normal CAPTURE make bounded progress
    mov rdi, [rel gd_stage_len]
    test rdi, rdi
    jz .fail
    mov [rel fm_len], rdi
    mov qword [rel gd_stage_job], 0      ; prior ordinary job was already released
    mov rax, [rel gd_stage_view + GV_SW]
    mov [rel fm_width], rax
    mov rax, [rel gd_stage_view + GV_SH]
    mov [rel fm_height], rax
    lea rdi, [rel fm_sha]
    call sha256_stream_init
    mov byte [rel fm_state], FM_SOURCE
.owned:
    mov edi, [rel gd_stage_slot]
    call gd_stage_still_ours
    test eax, eax
    jz .fail
    mov rax, [rel fm_len]
    cmp rax, [rel gd_stage_len]
    jne .fail
    movzx eax, byte [rel fm_state]
    cmp eax, FM_SOURCE
    je .hash
    cmp eax, FM_OUTPUT
    je .hash
    cmp eax, FM_POISON
    je .poison
    cmp eax, FM_BEGIN
    je .begin
    cmp eax, FM_RUNNING
    jne .fail
    call time_monotonic_now_us
    mov rdx, rax
    mov rdi, [rel gd_stage_job]
    lea rsi, [rel gd_stage_blk]
    call smp_par_step
    cmp eax, SMP_PC_PENDING
    je .active
    cmp eax, SMP_PC_COMPLETE
    jne .fail
    cmp edx, 1
    jne .fail
    call fm_record_ptr
    mov rbp, rax
    mov rax, [rel smp_pc_finished_us]
    sub rax, [rel fm_started_us]
    jc .fail
    mov [rbp + fm_record.us], rax
    mov rax, [rel gd_stage_job]
    mov [rbp + fm_record.job], rax
    mov eax, [rel smp_pc_bsp]
    mov [rbp + fm_record.bsp], rax
    mov eax, [rel smp_pc_count]
    mov [rbp + fm_record.count], rax
    mov eax, [rel smp_pc_online]
    mov [rbp + fm_record.online], rax
    lea rsi, [rel smp_pc_cpu_chunks]
    lea rdi, [rbp + fm_record.chunks]
    mov ecx, MAXCORE
    rep movsq                          ; actual terminal retirement precedes read
    mov rdi, [rel gd_stage_job]
    lea rsi, [rel gd_stage_blk]
    call smp_par_release
    test eax, eax
    jz .fail
    mov qword [rel gd_stage_job], 0
    lea rdi, [rel fm_sha]
    call sha256_stream_init
    mov qword [rel fm_cursor], 0
    mov byte [rel fm_state], FM_OUTPUT
    jmp .active
.begin:
    sub rsp, SMP_PF_CTX_SZ
    mov rax, [rel gd_stage_d]
    mov [rsp + SMP_PF_CTX_DST], rax
    mov rax, [rel gd_stage_s]
    mov [rsp + SMP_PF_CTX_SRC], rax
    mov rax, [rel fm_len]
    mov [rsp + SMP_PF_CTX_LEN], rax
    mov qword [rsp + SMP_PF_CTX_CHUNK], GD_STAGE_CHUNK
    mov qword [rsp + SMP_PF_CTX_FILL], 0
    call time_monotonic_now_us
    mov [rel fm_started_us], rax
    mov r8, rax
    mov r9, rax
    add r9, GD_STAGE_BUDGET_US
    lea rcx, [rel gd_stage_blk]
    mov edi, SMP_PF_BODY_COPY
    mov rsi, rsp
    mov rdx, [rel gd_stage_chunks]
    test byte [rel fm_trial], 1
    jnz .parallel
    call smp_par_begin_single
    jmp .begun
.parallel:
    call smp_par_begin
.begun:
    lea rsp, [rsp + SMP_PF_CTX_SZ]
    jc .fail
    mov [rel gd_stage_job], rax
    mov byte [rel fm_state], FM_RUNNING
    jmp .active
.poison:
    mov rdx, [rel fm_len]
    sub rdx, [rel fm_cursor]
    cmp rdx, FM_HASH_BYTES
    jbe .poison_size
    mov edx, FM_HASH_BYTES
.poison_size:
    mov rsi, [rel gd_stage_s]
    mov rdi, [rel gd_stage_d]
    mov rcx, [rel fm_cursor]
    add rsi, rcx
    add rdi, rcx
    mov rcx, rdx
.poison_loop:
    lodsb
    not al
    stosb                               ; each D byte differs before every trial
    loop .poison_loop
    add [rel fm_cursor], rdx
    mov rax, [rel fm_cursor]
    cmp rax, [rel fm_len]
    jb .active
    mov byte [rel fm_state], FM_BEGIN
    jmp .active
.hash:
    mov r12, [rel fm_len]
    sub r12, [rel fm_cursor]
    cmp r12, FM_HASH_BYTES
    jbe .hash_size
    mov r12d, FM_HASH_BYTES
.hash_size:
    mov rsi, [rel gd_stage_s]
    add rsi, [rel fm_cursor]
    cmp byte [rel fm_state], FM_SOURCE
    je .hash_update
    mov rdi, [rel gd_stage_d]
    add rdi, [rel fm_cursor]
    mov rcx, r12
    repe cmpsb                          ; independent full-byte comparison
    jne .fail
    mov rsi, [rel gd_stage_d]
    add rsi, [rel fm_cursor]
.hash_update:
    lea rdi, [rel fm_sha]
    mov rdx, r12
    call sha256_stream_update
    test rax, rax
    jnz .fail
    add [rel fm_cursor], r12
    mov rax, [rel fm_cursor]
    cmp rax, [rel fm_len]
    jb .active
    lea rsi, [rel fm_source_digest]
    cmp byte [rel fm_state], FM_SOURCE
    je .hash_final
    call fm_record_ptr
    lea rsi, [rax + fm_record.digest]
.hash_final:
    lea rdi, [rel fm_sha]
    call sha256_stream_final
    test rax, rax
    jnz .fail
    cmp byte [rel fm_state], FM_SOURCE
    je .next
    call fm_record_ptr
    lea rdi, [rax + fm_record.digest]
    lea rsi, [rel fm_source_digest]
    mov ecx, 32
    repe cmpsb
    jne .fail
    inc qword [rel fm_trial]
    cmp qword [rel fm_trial], 6
    jb .next
    mov byte [rel fm_state], FM_DONE
    mov byte [rel gd_stage_state], GD_ST_READY
    jmp .active                         ; ordinary presentation on a later tick
.next:
    mov qword [rel fm_cursor], 0
    mov byte [rel fm_state], FM_POISON
.active:
    mov eax, 1
    jmp .out
.fail:
    call fm_abort
    jmp .active
.inactive:
    xor eax, eax
.out:
    pop r12
    pop rbp
    pop rbx
    ret

fm_abort:
    cmp byte [rel fm_state], FM_WAIT
    je .done                            ; ordinary stage still owns its work
    mov rdi, [rel gd_stage_job]
    test rdi, rdi
    jz .scrub
    lea rsi, [rel gd_stage_blk]
    call smp_par_cancel
    mov byte [rel gd_stage_state], GD_ST_QUARANTINED
    jmp .done                           ; existing owner polls actual retirement
.scrub:
    call gd_stage_discard               ; existing guard-checked bounded scrub
.done:
    mov byte [rel fm_state], FM_FAILED
    ret

fm_record_ptr:
    mov rax, [rel fm_trial]
    imul rax, fm_record_size
    lea rdx, [rel fm_records]
    add rax, rdx
    ret

; One small reply per requested trial; CPU chunks belong to exactly that job.
; Fixed 32 slots keep the reply below the transport's bounded arena.
fm_reply:
    call chat_out_reset
    lea rdi, [rel fm_prefix]
    call chat_put_str
    lea rdi, [rel fm_nonce]
    call chat_put_str
    lea rdi, [rel fm_state_key]
    call chat_put_str
    movzx edi, byte [rel fm_state]
    call chat_put_dec
    lea rdi, [rel fm_completed_key]
    call chat_put_str
    mov rdi, [rel fm_trial]
    call chat_put_dec
    lea rdi, [rel fm_len_key]
    call chat_put_str
    mov rdi, [rel fm_len]
    call chat_put_dec
    lea rdi, [rel fm_width_key]
    call chat_put_str
    mov rdi, [rel fm_width]
    call chat_put_dec
    lea rdi, [rel fm_height_key]
    call chat_put_str
    mov rdi, [rel fm_height]
    call chat_put_dec
    lea rdi, [rel fm_source_key]
    call chat_put_str
    lea rdi, [rel fm_source_digest]
    call fm_hex32
    lea rdi, [rel fm_trial_key]
    call chat_put_str
    mov rdi, r14
    call chat_put_dec
    mov rbp, r14
    imul rbp, fm_record_size
    lea rax, [rel fm_records]
    add rbp, rax
    lea rdi, [rel fm_us_key]
    call chat_put_str
    mov rdi, [rbp + fm_record.us]
    call chat_put_dec
    lea rdi, [rel fm_digest_key]
    call chat_put_str
    lea rdi, [rbp + fm_record.digest]
    call fm_hex32
    lea rdi, [rel fm_bsp_key]
    call chat_put_str
    mov rdi, [rbp + fm_record.bsp]
    call chat_put_dec
    lea rdi, [rel fm_count_key]
    call chat_put_str
    mov rdi, [rbp + fm_record.count]
    call chat_put_dec
    lea rdi, [rel fm_job_key]
    call chat_put_str
    mov rdi, [rbp + fm_record.job]
    call chat_put_dec
    lea rdi, [rel fm_online_key]
    call chat_put_str
    mov rdi, [rbp + fm_record.online]
    call chat_put_dec
    lea rdi, [rel fm_chunks_key]
    call chat_put_str
    xor ebx, ebx
.cpu:
    test ebx, ebx
    jz .number
    mov edi, ','
    call fm_put_char
.number:
    mov rdi, [rbp + fm_record.chunks + rbx*8]
    call chat_put_dec
    inc ebx
    cmp ebx, MAXCORE
    jb .cpu
    ret
fm_hex32:
    push rbx
    push rbp
    push r12
    mov rbx, rdi
    xor ebp, ebp
.hex:
    movzx r12d, byte [rbx + rbp]
    mov edi, r12d
    shr edi, 4
    call .digit
    mov edi, r12d
    and edi, 15
    call .digit
    inc ebp
    cmp ebp, 32
    jb .hex
    pop r12
    pop rbp
    pop rbx
    ret
.digit:
    lea rax, [rel fm_digits]
    movzx edi, byte [rax + rdi]
    jmp fm_put_char

fm_put_char:
    mov [rel fm_char], dil
    lea rdi, [rel fm_char]
    jmp chat_put_str

fm_verb: db 'FRAMECOPY',0
fm_digits: db '0123456789abcdef'
fm_prefix: db 'FRAMECOPY nonce=',0
fm_state_key: db ' state=',0
fm_completed_key: db ' completed=',0
fm_len_key: db ' len=',0
fm_width_key: db ' width=',0
fm_height_key: db ' height=',0
fm_source_key: db ' source=',0
fm_trial_key: db ' trial=',0
fm_us_key: db ' us=',0
fm_digest_key: db ' digest=',0
fm_bsp_key: db ' bsp=',0
fm_count_key: db ' count=',0
fm_job_key: db ' job=',0
fm_online_key: db ' online=',0
fm_chunks_key: db ' chunks=',0
%macro WDATA_guest_frame_measure 0
alignb 8
fm_records: resb fm_record_size * 6
fm_sha: resb S256_CTX_SZ
fm_source_digest: resb 32
fm_nonce: resb 17
alignb 8
fm_trial: resq 1
fm_cursor: resq 1
fm_epoch: resq 1
fm_deadline: resq 1
fm_len: resq 1
fm_width: resq 1
fm_height: resq 1
fm_started_us: resq 1
fm_state: resb 1
fm_char: resb 2
%endmacro
WDATA_BSS_DEFER WDATA_guest_frame_measure
