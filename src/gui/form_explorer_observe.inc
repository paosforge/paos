; EXPLOREROBS <16 lowercase hex nonce>. The standard dispatcher supplies owner
; authentication, replay, capability and transport identity. This handler adds
; the unchanged workspace gate and exact request OWNER, then reads only cache.
form_cmd_verb_explorerobs:
    call form_verb_unlocked
    test eax, eax
    jnz  .ret
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r13, rsi
    call cmd_handler_prologue
    call form_out_reset
    mov  rdi, rbx
    call session_shell_request_principal
    cmp  rax, PRIN_OWNER
    jne  .refused
    call form_exp_instance_select_command
    test eax, eax
    jz   .refused
    call form_exp_observe_valid
    test eax, eax
    jz   .refused
    mov  r12, [rbx + REQ_ARG]
    test r12, r12
    jz   .bad_args
    xor  ecx, ecx
.nonce:
    mov  al, [r12 + rcx]
    cmp  al, '0'
    jb   .bad_args
    cmp  al, '9'
    jbe  .next
    cmp  al, 'a'
    jb   .bad_args
    cmp  al, 'f'
    ja   .bad_args
.next:
    inc  ecx
    cmp  ecx, 16
    jb   .nonce
    cmp  byte [r12 + 16], 0
    jne  .bad_args
    lea  rdi, [rel str_explorerobs_head]
    call form_out_put_str
    mov  rdi, r12
    mov  esi, 16
    call form_out_put_n
    mov  rax, [rel form_exp_observation + EXP_OBS_PHASE]
    lea  rdi, [rel str_explorerobs_none]
    test rax, rax
    jz   .last
    lea  rdi, [rel str_explorerobs_selected]
    cmp  eax, 1
    je   .phase
    lea  rdi, [rel str_explorerobs_deleted]
    cmp  eax, 3
    je   .phase
    lea  rdi, [rel str_explorerobs_created]
    cmp  eax, 5
    je   .phase
    lea  rdi, [rel str_explorerobs_moved]
    cmp  eax, 6
    je   .phase
    lea  rdi, [rel str_explorerobs_renamed]
    cmp  eax, 4
    je   .phase
    lea  rdi, [rel str_explorerobs_accepted]
.phase:
    call form_out_put_str
    lea  r12, [rel form_exp_observation]
%macro EXP_OBS_DEC 2
    lea  rdi, [rel %1]
    call form_out_put_str
    mov  rdi, [r12 + %2]
    call form_out_put_dec
%endmacro
%macro EXP_OBS_HEX 3
    lea  rdi, [rel %1]
    call form_out_put_str
    lea  rdi, [r12 + %2]
    mov  edx, %3
    call form_exp_observe_put_hex
%endmacro
    EXP_OBS_DEC str_explorerobs_seq, EXP_OBS_SEQ
    EXP_OBS_DEC str_explorerobs_job, EXP_OBS_JOB
    EXP_OBS_DEC str_explorerobs_ms, EXP_OBS_MS
    EXP_OBS_DEC str_explorerobs_win, EXP_OBS_SRC_STAMP + 48
    EXP_OBS_DEC str_explorerobs_widget, EXP_OBS_SRC_STAMP + 64
    EXP_OBS_DEC str_explorerobs_owner, EXP_OBS_SRC_STAMP + 8
    EXP_OBS_DEC str_explorerobs_epoch, EXP_OBS_SRC_STAMP + 16
    EXP_OBS_DEC str_explorerobs_src_mount, EXP_OBS_SRC_STAMP + 40
    EXP_OBS_HEX str_explorerobs_src_label, EXP_OBS_SRC_STAMP + 80, 15
    EXP_OBS_HEX str_explorerobs_src, EXP_OBS_SRC_PATH, FORM_FS_CWD_MAX - 1
    cmp  qword [r12 + EXP_OBS_PHASE], 6
    je   .destination
    cmp  qword [r12 + EXP_OBS_PHASE], 5
    je   .destination
    cmp  qword [r12 + EXP_OBS_PHASE], 4
    je   .destination
    cmp  qword [r12 + EXP_OBS_PHASE], 2
    je   .destination
    cmp  qword [r12 + EXP_OBS_PHASE], 3
    je   .operation_nonce
    jmp  .ready
.destination:
    EXP_OBS_DEC str_explorerobs_dst_mount, EXP_OBS_DST_STAMP + 40
    EXP_OBS_HEX str_explorerobs_dst_label, EXP_OBS_DST_STAMP + 80, 15
    EXP_OBS_HEX str_explorerobs_dst, EXP_OBS_DST_PATH, FORM_FS_CWD_MAX - 1
.operation_nonce:
    lea  rdi, [rel str_explorerobs_op_nonce]
    call form_out_put_str
    lea  rdi, [r12 + EXP_OBS_NONCE]
    mov  esi, 16
    call form_out_put_n
    jmp  .ready
.bad_args:
    lea  rdi, [rel str_explorerobs_args]
    jmp  .error
.refused:
    lea  rdi, [rel str_explorerobs_refused]
.error:
    mov  qword [r13 + RSP_CODE], CMDE_AUTHDENY
    call form_out_put_str
    jmp  .publish
.last:
    call form_out_put_str
    lea  rdi, [rel str_explorerobs_seq]
    call form_out_put_str
    mov  rdi, [rel form_exp_paste_seq]
    call form_out_put_dec
.ready:
    mov  qword [r13 + RSP_CODE], CMDE_OK
.publish:
    mov  qword [r13 + RSP_VAL], 0
    mov  byte [rel form_out_ready], 1
    pop  r13
    pop  r12
    pop  rbx
.ret:
    ret

; Hex encodes complete owned bytes, stopping at NUL and the explicit bound.
; Worst-case whole record is <1024 bytes, below the existing1472-byte form rail.
form_exp_observe_put_hex:
    mov  r8, [rel form_out_cur]
    lea  r9, [rel str_explorerobs_digits]
.next:
    test edx, edx
    jz   .out
    movzx eax, byte [rdi]
    test al, al
    jz   .out
    mov  ecx, eax
    shr  eax, 4
    mov  al, [r9 + rax]
    mov  [r8], al
    and  ecx, 15
    mov  al, [r9 + rcx]
    mov  [r8 + 1], al
    add  r8, 2
    inc  rdi
    dec  edx
    jmp  .next
.out:
    mov  byte [r8], 0
    mov  [rel form_out_cur], r8
    ret
