; Private cached witness of actual guarded Explorer gestures. No control API.
; Called only after Ctrl+C selection or deferred FSCOPY acceptance. All private
; pointers/keys remain RAM-only; the readonly command projects named values.
EXP_OBS_SIZE equ 496
EXP_OBS_PHASE equ 0
EXP_OBS_SEQ equ 8
EXP_OBS_JOB equ 16
EXP_OBS_MS equ 24
EXP_OBS_SRC_PATH equ 120
EXP_OBS_DST_PATH equ 200
EXP_OBS_NONCE equ 280
EXP_OBS_SRC_STAMP equ 304
EXP_OBS_DST_STAMP equ 400

form_exp_observe_reset:
    push rdi
    push rcx
    lea  rdi, [rel form_exp_observation]
    mov  ecx, EXP_OBS_SIZE / 8
    xor  eax, eax
    rep  stosq
    pop  rcx
    pop  rdi
    ret

; EDI=1 selected, 2 copy accepted, 6 synchronous Move completed. Preserve the input path's saved state.
form_exp_observe_capture:
    push rbx
    push r12
    mov  ebx, edi
    call form_exp_observe_reset
    lea  r12, [rel form_exp_observation]
    lea  rdi, [r12 + EXP_OBS_SRC_STAMP]
    lea  rsi, [rel form_exp_file_stamp]
    mov  ecx, 12
    rep  movsq
    lea  rdi, [r12 + EXP_OBS_SRC_PATH]
    lea  rsi, [rel form_exp_file_src]
    mov  ecx, FORM_FS_CWD_MAX
    call form_exp_observe_copy_z
    mov  rax, [rel form_exp_paste_seq]
    mov  [r12 + EXP_OBS_SEQ], rax
    cmp  ebx, 6
    je   .destination
    cmp  ebx, 2
    jne  .publish
.destination:
    lea  rdi, [r12 + EXP_OBS_DST_STAMP]
    lea  rsi, [rel form_exp_dest_stamp]
    mov  ecx, 12
    rep  movsq
    lea  rdi, [r12 + EXP_OBS_DST_PATH]
    lea  rsi, [rel form_exp_file_dst]
    mov  ecx, FORM_FS_CWD_MAX
    call form_exp_observe_copy_z
    lea  rdi, [r12 + EXP_OBS_NONCE]
    lea  rsi, [rel form_exp_paste_nonce]
    mov  ecx, 17
    call form_exp_observe_copy_z
    mov  rax, [rel form_exp_paste_seq]
    mov  [r12 + EXP_OBS_SEQ], rax
    cmp  ebx, 6
    je   .publish                    ; synchronous Move has no copy job
    mov  rax, [rel form_exp_owned_job]
    mov  [r12 + EXP_OBS_JOB], rax
.publish:
    call boot_ms_now
    mov  [r12 + EXP_OBS_MS], rax
    mov  [r12 + EXP_OBS_PHASE], rbx       ; publish only the completed snapshot
    pop  r12
    pop  rbx
    ret

form_exp_observe_copy_z:
    lodsb
    stosb
    test al, al
    jz   .out
    loop form_exp_observe_copy_z
.out:
    ret

; Publish only after the real deferred FSDEL returned its exact fresh success.
; Reuse the public cache shape; this action has no asynchronous copy job.
form_exp_observe_delete:
    push r12
    call form_exp_observe_reset
    lea  r12, [rel form_exp_observation]
    lea  rdi, [r12 + EXP_OBS_SRC_STAMP]
    lea  rsi, [rel form_exp_delete_stamp]
    mov  ecx, 12
    rep  movsq
    lea  rdi, [r12 + EXP_OBS_SRC_PATH]
    lea  rsi, [rel form_exp_delete_path]
    mov  ecx, FORM_FS_CWD_MAX
    call form_exp_observe_copy_z
    lea  rdi, [r12 + EXP_OBS_NONCE]
    lea  rsi, [rel form_exp_delete_nonce]
    mov  ecx, 17
    call form_exp_observe_copy_z
    mov  rax, [rel form_exp_paste_seq]
    mov  [r12 + EXP_OBS_SEQ], rax
    call boot_ms_now
    mov  [r12 + EXP_OBS_MS], rax
    mov  qword [r12 + EXP_OBS_PHASE], 3
    pop  r12
    ret

form_exp_observe_rename:
    push r12
    call form_exp_observe_reset
    lea  r12, [rel form_exp_observation]
    lea  rdi, [r12 + EXP_OBS_SRC_STAMP]
    lea  rsi, [rel form_exp_rename_stamp]
    mov  ecx, 12
    rep  movsq
    lea  rdi, [r12 + EXP_OBS_SRC_PATH]
    lea  rsi, [rel form_exp_rename_path]
    mov  ecx, FORM_FS_CWD_MAX
    call form_exp_observe_copy_z
    lea  rdi, [r12 + EXP_OBS_DST_STAMP]
    lea  rsi, [rel form_exp_rename_stamp]
    mov  ecx, 12
    rep  movsq
    lea  rdi, [r12 + EXP_OBS_DST_PATH]
    lea  rsi, [rel form_exp_rename_dst]
    mov  ecx, FORM_FS_CWD_MAX
    call form_exp_observe_copy_z
    lea  rdi, [r12 + EXP_OBS_NONCE]
    lea  rsi, [rel form_exp_rename_nonce]
    mov  ecx, 17
    call form_exp_observe_copy_z
    mov  rax, [rel form_exp_paste_seq]
    mov  [r12 + EXP_OBS_SEQ], rax
    call boot_ms_now
    mov  [r12 + EXP_OBS_MS], rax
    mov  qword [r12 + EXP_OBS_PHASE], 4
    pop  r12
    ret

; Readonly lifetime check. Does not use session_shell_local_authority: a remote
; OWNER read must not impersonate local input. The command separately verifies
; the actual request principal and the established unlocked session gate.
form_exp_observe_valid:
    cmp  qword [rel session_bound_pid], PRIN_OWNER
    jne  .bad
    cmp  byte [rel session_injected_input], 0
    jne  .bad
    mov  rax, [rel session_authority]
    test rax, rax
    jz   .bad
    cmp  rax, [rel session_authority_epoch]
    jne  .bad
    cmp  qword [rel form_exp_observation + EXP_OBS_PHASE], 0
    je   .ok                           ; honest absence, not an old job lookup
    push r12
    lea  r12, [rel form_exp_observation + EXP_OBS_SRC_STAMP]
    cmp  qword [r12 + 8], PRIN_OWNER
    jne  .bad_pop
    cmp  rax, [r12 + 16]
    jne  .bad_pop
    mov  rax, [rel session_key_handle]
    cmp  rax, [r12 + 56]
    jne  .bad_pop
    mov  rcx, [r12 + 48]
    cmp  rcx, WM_MAX
    jae  .bad_pop
    cmp  ecx, [rel wm_focus]
    jne  .bad_pop
    cmp  ecx, [rel form_active_slot + FORM_EXPLORER_INDEX*4]
    jne  .bad_pop
    lea  rax, [rel wm_state]
    cmp  dword [rax + rcx*4], WM_VISIBLE
    jne  .bad_pop
    mov  edi, [r12 + 64]
    call form_exp_copy_focus
    test eax, eax
    jz   .bad_pop
    call form_exp_observe_mount_valid
    test eax, eax
    jz   .bad_pop
    cmp  qword [rel form_exp_observation + EXP_OBS_PHASE], 1
    je   .ok_pop
    cmp  qword [rel form_exp_observation + EXP_OBS_PHASE], 3
    je   .ok_pop
    cmp  qword [rel form_exp_observation + EXP_OBS_PHASE], 5
    je   .destination
    cmp  qword [rel form_exp_observation + EXP_OBS_PHASE], 6
    je   .destination
    cmp  qword [rel form_exp_observation + EXP_OBS_PHASE], 4
    je   .destination
    cmp  qword [rel form_exp_observation + EXP_OBS_PHASE], 2
    jne  .bad_pop
.destination:
    lea  r12, [rel form_exp_observation + EXP_OBS_DST_STAMP]
    call form_exp_observe_mount_valid
    test eax, eax
    jz   .bad_pop
.ok_pop:
    pop  r12
.ok:
    mov  eax, 1
    ret
.bad_pop:
    pop  r12
.bad:
    xor  eax, eax
    ret

; R12=original stamp. No mount selection, media read, job refresh or grant.
form_exp_observe_mount_valid:
    mov  edi, [r12 + 40]
    call vfs_mount_ptr
    test rax, rax
    jz   .bad
    mov  rcx, [rax]
    cmp  rcx, [r12 + 24]
    jne  .bad
    mov  rcx, [rax + 8]
    cmp  rcx, [r12 + 32]
    jne  .bad
    mov  rdx, [rax + 16]
    cmp  rdx, [r12 + 72]
    jne  .bad
    xor  ecx, ecx
.name:
    cmp  ecx, 16
    jae  .bad
    mov  al, [rdx + rcx]
    cmp  al, [r12 + 80 + rcx]
    jne  .bad
    test al, al
    jz   .label
    inc  ecx
    jmp  .name
.label:
    jmp  form_exp_file_label
.bad:
    xor  eax, eax
    ret
