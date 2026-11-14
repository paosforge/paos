; Only the existing guarded physical context-menu Refresh calls this helper.
; No mutation/selection/remount; same original VFS directory read as painting,
; executed synchronously so a redraw cannot masquerade as enumeration.
form_exp_rescan:
    push rbx
    lea  rbx, [rel form_exp_rescan_record]
    inc  qword [rbx]
    mov  eax, [rel form_exp_context_win]
    mov  [rbx + 8], rax
    lea  rdx, [rel wm_gen]
    mov  eax, [rdx + rax*4]
    mov  [rbx + 16], rax
    mov  qword [rbx + 24], PRIN_OWNER
    mov  rax, [rel form_exp_context_epoch]
    mov  [rbx + 32], rax
    mov  rax, [rel form_exp_context_key]
    mov  [rbx + 40], rax             ; private, never serialized
    mov  rax, [rel form_exp_context_mount]
    mov  [rbx + 48], rax
    lea  rdi, [rbx + 144]
    lea  rsi, [rel form_fs_cwd]
    mov  ecx, FORM_FS_CWD_MAX
    rep  movsb
    call boot_ms_now
    mov  [rbx + 56], rax
    mov  edi, [rel vfs_disk_handle]
    call vfs_mount_ptr
    mov  rdi, rax
    call fat32_disk_list_observe
    mov  [rbx + 72], rax
    mov  qword [rel form_fsroot_snapshot_ms], 0
    call form_fsroot_refresh
    mov  edi, [rel vfs_disk_handle]
    call vfs_mount_ptr
    mov  rdi, rax
    call fat32_disk_list_observe
    mov  [rbx + 80], rax
    mov  [rbx + 88], rdx
    mov  [rbx + 96], rcx
    mov  [rbx + 120], r8
    mov  [rbx + 128], r9
    mov  [rbx + 136], r10
    mov  eax, [rel form_fsroot_result + fs_list_result.count]
    mov  [rbx + 104], rax
    mov  eax, [rel form_fsroot_result + fs_list_result.truncated]
    mov  [rbx + 112], rax
    cmp  dword [rel form_fsroot_rc], 0
    je   .identity
    mov  qword [rbx + 96], -1
.identity:
    mov  eax, [rel vfs_disk_handle]
    cmp  rax, [rbx + 48]
    jne  .foreign
    mov  edi, eax
    call vfs_mount_ptr
    test rax, rax
    jz   .foreign
    mov  rcx, [rax + fsmount.ops]
    cmp  rcx, [rel form_exp_context_ops]
    jne  .foreign
    mov  rcx, [rax + fsmount.priv]
    cmp  rcx, [rel form_exp_context_priv]
    je   .done
.foreign:
    mov  qword [rbx + 120], 2        ; available identity contradiction
.done:
    call boot_ms_now
    mov  [rbx + 64], rax
    pop  rbx
    ret

; Pure cached readout. Unsupported/missing history serializes seq=0; consumers
; keep it U. This handler cannot Refresh, list, read storage or create a witness.
%ifndef EXPLORER_RESCAN_NO_COMMAND
form_cmd_verb_explorerscan:
    call form_verb_unlocked
    test eax, eax
    jnz  .ret
    push rbx
    push r12
    push r13
    push r14
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
    ; Read-only authenticated remote commands use the cached owner lifetime,
    ; never the local physical-input authority helper (which rejects remote).
    cmp  qword [rel session_bound_pid], PRIN_OWNER
    jne  .refused
    cmp  byte [rel session_injected_input], 0
    jne  .refused
    mov  rax, [rel session_authority]
    test rax, rax
    jz   .refused
    cmp  rax, [rel session_authority_epoch]
    jne  .refused
    lea  rbx, [rel form_exp_rescan_record]
    cmp  qword [rbx], 0
    je   .emit
    cmp  qword [rbx + 24], PRIN_OWNER
    jne  .refused
    cmp  rax, [rbx + 32]
    jne  .refused
    mov  rax, [rel session_key_handle]
    cmp  rax, [rbx + 40]
    jne  .refused
    mov  ecx, [rel wm_focus]
    cmp  ecx, WM_MAX
    jae  .refused
    lea  rax, [rel wm_state]
    cmp  dword [rax + rcx*4], WM_VISIBLE
    jne  .refused
    cmp  rcx, [rbx + 8]
    jne  .refused
    lea  rax, [rel wm_gen]
    mov  eax, [rax + rcx*4]
    cmp  rax, [rbx + 16]
    jne  .refused
.emit:
    lea  rdi, [rel str_explorerscan_head]
    call form_out_put_str
    mov  rdi, r12
    mov  esi, 16
    call form_out_put_n
    lea  r14, [rel str_explorerscan_fields]
    xor  r12d, r12d
.field:
    mov  rdi, r14
    call form_out_put_str
    ; Skip the private key field at record+40.
    mov  eax, r12d
    cmp  eax, 5
    jb   .offset
    inc  eax
.offset:
    mov  rdi, [rbx + rax*8]
    call form_out_put_dec
.next_string:
    cmp  byte [r14], 0
    lea  r14, [r14 + 1]
    jne  .next_string
    inc  r12d
    cmp  r12d, 17
    jb   .field
    lea  rdi, [rel str_explorerscan_path]
    call form_out_put_str
    lea  rdi, [rbx + 144]
    mov  edx, FORM_FS_CWD_MAX - 1
    call form_exp_observe_put_hex
    mov  qword [r13 + RSP_CODE], CMDE_OK
    jmp  .publish
.bad_args:
    lea  rdi, [rel str_explorerobs_args]
    jmp  .error
.refused:
    lea  rdi, [rel str_explorerobs_refused]
.error:
    mov  qword [r13 + RSP_CODE], CMDE_AUTHDENY
    call form_out_put_str
.publish:
    mov  qword [r13 + RSP_VAL], 0
    mov  byte [rel form_out_ready], 1
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
.ret:
    ret
%endif
