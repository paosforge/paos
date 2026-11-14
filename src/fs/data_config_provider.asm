;; MODULE fs/data_config_provider
;; LAYER 4
;; EXPORTS data_config_bind, data_config_current, data_config_read, data_config_write
;; IMPORTS fs/data_config_authority, fs/fat32_disk, fs/blockdev, fs/storage_access, fs/vfs, core/heap, core/lib/mem
;; CAPS
;; OWNER saga:fs_wave
; Explicit DATA configuration IO; included by fs/fat32_disk, not a second backend.
; No compiled COG descriptor or currently-selected-media inference.
; Public ABI and proof limits: gauntlet_v2/docs/data_config_provider.md.
%ifndef DATA_CONFIG_PROVIDER_INCLUDED
%define DATA_CONFIG_PROVIDER_INCLUDED 1
FD_DATA_SOURCE equ 0xFFFFFFF0
FD_DATA_MAX equ 8 * 1024 * 1024 + 512
FD_DATA_TOKEN equ 112
FD_DATA_APP_MAX equ 1024 * 1024
FD_DATA_DAILY_CLASS equ 257              ; distinct purpose, NOT byte maximum
FD_DATA_DAILY_MAX equ 256
FD_DATA_UPDATES_MAX equ 256              ; dedicated local Updates consent only
FD_DATA_DOC_MAX equ 4224                 ; native public-documents aggregate only

; RDI=registered exact read-only selected mount handle, RSI=descriptor[56],
; RDX=out token[112] -> 0 / -1 refused / -2 busy. No writes or recovery here.
data_config_bind:
    push rdi
    push rsi
    push rdx
    call fd_scratch_owner
    pop rdx
    pop rsi
    pop rdi
    test rax, rax
    jnz .no
    call fd_data_bind_common
    test rax, rax
    jnz .out
    mov qword [rel fd_data_owned_token], 0
.out:
    ret
.no:
    mov rax, -1
    ret

; Private body: ordinary entry above or sealed-role entry in authority leaf.
fd_data_bind_common:
    push rbx
    push r12
    push r13
    push r14
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    test r13, r13
    jz .fail
    test r14, r14
    jz .fail
    call vfs_copy_busy
    test eax, eax
    jnz .busy
    call storage_access_binding_busy
    test eax, eax
    jnz .busy
    cmp dword [rel fd_cp_phase], FD_CP_IDLE
    jne .busy
    cmp byte [rel fd_data_active], 0
    jne .busy
    cmp dword [rel fd_dir_gate], 0
    jne .busy
    cmp qword [rel fd_data_serial], -1
    je .fail                           ; never reuse a binding after wrap
    mov rdi, r12
    call vfs_mount_ptr
    test rax, rax
    jz .fail
    lea rdx, [rel fd_selected_ops]
    cmp [rax + fsmount.ops], rdx
    jne .fail
    lea rdx, [rel fd_selected_ctx]
    cmp [rax + fsmount.priv], rdx
    jne .fail
    mov rdi, rdx
    call fd_selected_current
    test rax, rax
    jnz .fail
    cmp dword [rel fd_selected_ctx + FD_MOUNTED], 1
    jne .fail
    cmp byte [rel fd_selected_ctx + FD_PART_ESP], 0
    jne .fail
    cmp dword [r13 + 52], 0
    jne .fail
    cmp dword [r13 + 48], 0
    je .fail
    mov rax, [r13]
    or rax, [r13 + 8]
    jz .fail
    mov rax, [r13 + 16]
    or rax, [r13 + 24]
    jz .fail
    lea rdi, [rel fd_selected_ctx]
    mov rsi, r13
    call fat32_disk_identity_matches
    test rax, rax
    jnz .fail
    mov eax, [rel fd_selected_ctx + FD_PART_INDEX]
    cmp eax, 128
    jae .fail
    shl eax, 7
    lea rbx, [rel fd_selected_entries]
    add rbx, rax
    mov rax, 0x4433b9e5ebd0a0a2       ; Microsoft Basic Data, never an ESP
    cmp [rbx], rax
    jne .fail
    mov rax, 0xc79926b7b668c087
    cmp [rbx + 8], rax
    jne .fail
    cmp qword [rbx + 48], 0
    jne .fail
    ; Parse the current BPB through the native parser, rather than pairing
    ; old cached geometry with a newly sampled BPB. The selected GPT snapshot
    ; below must still match before this new binding can be published.
    lea rdi, [rel fd_data_probe]
    lea rsi, [rel fd_selected_ctx]
    mov edx, FD_CTX_SIZE
    call memcpy
    mov rdi, [rel fd_selected_ctx + FD_DEV]
    mov rsi, [rel fd_selected_ctx + FD_PART_LBA]
    mov edx, 1
    lea rcx, [rel fd_data_boot]
    call blk_read
    test rax, rax
    jnz .fail
    lea rbx, [rel fd_data_boot]
    call fd_is_fat32_bpb
    test eax, eax
    jnz .fail
    lea rdi, [rel fd_data_probe]
    lea rsi, [rel fd_data_boot]
    call fd_validate_bpb
    test rax, rax
    jnz .fail
    lea rdi, [rel fd_data_probe]
    mov rsi, r13
    call fat32_disk_identity_matches
    test rax, rax
    jnz .fail
    cmp dword [rel fd_data_probe + FD_NFATS], 2
    jne .fail
    ; Rebind invalidates the old token before changing private state.
    mov dword [rel fd_data_ctx + FD_MOUNTED], 0
    inc qword [rel fd_data_serial]
    lea rdi, [rel fd_data_ctx]
    lea rsi, [rel fd_data_probe]
    mov edx, FD_CTX_SIZE
    call memcpy
    mov byte [rel fd_data_ctx + FD_EXACT_BOUND], 0
    mov dword [rel fd_data_ctx + FD_TX_BUSY], 0
    mov dword [rel fd_data_ctx + FD_SWEEP_DONE], 0
    mov dword [rel fd_data_ctx + FD_SWEEP_CLUSTER], 0
    mov rax, [rel fd_selected_generation]
    mov [rel fd_data_generation], rax
    mov rax, [rel fd_selected_max]
    mov [rel fd_data_max], rax
    mov rax, [rel fd_data_ctx + FD_DEV]
    mov rdx, [rax + dev.info]
    mov [rel fd_data_info], rdx
    mov rdx, [rax + dev.ops]
    mov [rel fd_data_devops], rdx
    lea rdi, [rel fd_data_header]
    lea rsi, [rel fd_selected_gpt_saved]
    mov edx, 512
    call memcpy
    mov eax, [rel fd_data_header + 80]
    add eax, 3
    shr eax, 2
    cmp eax, 32
    ja .invalidate
    test eax, eax
    jz .invalidate
    mov [rel fd_data_table_sectors], eax
    shl eax, 9
    mov edx, eax
    lea rdi, [rel fd_data_entries]
    lea rsi, [rel fd_selected_entries]
    call memcpy
    call fd_data_metadata
    test rax, rax
    jnz .invalidate
    lea rdi, [rel fd_data_ops]
    xor esi, esi
    mov edx, fs_ops_size
    call memset
    lea rax, [rel str_fd_data_name]
    mov [rel fd_data_ops + fs_ops.name], rax
    lea rax, [rel fd_data_mount]
    mov [rel fd_data_ops + fs_ops.mount], rax
    lea rax, [rel fd_data_stat]
    mov [rel fd_data_ops + fs_ops.stat], rax
    lea rax, [rel fd_data_read_at]
    mov [rel fd_data_ops + fs_ops.read_at], rax
    mov edi, [rel fd_data_handle]
    test edi, edi
    jnz .existing
    lea rdi, [rel fd_data_ops]
    lea rsi, [rel fd_data_ctx]
    lea rdx, [rel str_fd_data_name]
    call vfs_register_mount
    test rax, rax
    js .invalidate
    inc eax
    mov [rel fd_data_handle], eax
.existing:
    mov edi, [rel fd_data_handle]
    dec edi
    call vfs_mount_ptr
    test rax, rax
    jz .invalidate
    lea rdx, [rel fd_data_ops]
    cmp [rax + fsmount.ops], rdx
    jne .invalidate
    lea rdx, [rel fd_data_ctx]
    cmp [rax + fsmount.priv], rdx
    jne .invalidate
    mov qword [rel fd_data_binding], 1
    mov rdx, [rel fd_data_serial]
    mov [rel fd_data_binding + 8], rdx
    mov edi, [rel fd_data_handle]
    dec edi
    mov [rel fd_data_binding + 16], rdi
    mov [rel fd_data_binding + 24], rax
    lea rdx, [rel fd_data_ops]
    mov [rel fd_data_binding + 32], rdx
    mov rdx, [rel fd_data_generation]
    mov [rel fd_data_binding + 40], rdx
    mov rdx, [rel fd_data_ctx + FD_PART_LBA]
    mov [rel fd_data_binding + 48], rdx
    lea rdi, [rel fd_data_binding + 56]
    mov rsi, r13
    mov edx, 56
    call memcpy
    mov rdi, r14
    lea rsi, [rel fd_data_binding]
    mov edx, FD_DATA_TOKEN
    call memcpy
    xor eax, eax
    jmp .out
.invalidate:
    mov dword [rel fd_data_ctx + FD_MOUNTED], 0
.fail:
    mov rax, -1
    jmp .out
.busy:
    mov rax, -2
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; RDI=token[112]. The token is identity, never write authority.
data_config_current:
    push rbx
    test rdi, rdi
    jz .fail
    lea rsi, [rel fd_data_binding]
    mov edx, FD_DATA_TOKEN
    call memcmp
    test rax, rax
    jnz .fail
    mov edi, [rel fd_data_handle]
    dec edi
    call vfs_mount_ptr
    test rax, rax
    jz .fail
    cmp rax, [rel fd_data_binding + 24]
    jne .fail
    lea rdx, [rel fd_data_ops]
    cmp [rax + fsmount.ops], rdx
    jne .fail
    lea rdx, [rel fd_data_ctx]
    cmp [rax + fsmount.priv], rdx
    jne .fail
    call fd_data_metadata
    test rax, rax
    jnz .out
    cmp qword [rel fd_data_owned_token], 0
    je .out
    call fd_data_role_current
    jmp .out
.fail:
    mov rax, -1
.out:
    pop rbx
    ret

; RDI=name11 -> EAX purpose class, or 0. Daily uses a distinct class;
; fd_data_size_limit maps it to its byte maximum at the three size checks.
; Other historical classes equal their byte maximum. Exact length is 11; no Z/path parsing.
fd_data_policy:
    push rbx
    mov rbx, rdi
    lea rsi, [rel fd_data_cfg]
    mov edx, 11
    call memcmp
    test rax, rax
    jz .cfg
    mov rdi, rbx
    lea rsi, [rel fd_data_cfg_v2]
    mov edx, 11
    call memcmp
    test rax, rax
    jz .cfg
    mov rdi, rbx
    lea rsi, [rel fd_data_updates]
    mov edx, 11
    call memcmp
    test rax, rax
    jz .updates
    mov rdi, rbx
    lea rsi, [rel fd_data_daily]
    mov edx, 11
    call memcmp
    test rax, rax
    jz .daily
    mov rdi, rbx
    lea rsi, [rel fd_data_learn0]
    mov edx, 11
    call memcmp
    test rax, rax
    jz .learn
    mov rdi, rbx
    lea rsi, [rel fd_data_learn1]
    mov edx, 11
    call memcmp
    test rax, rax
    jz .learn
    mov rdi, rbx
    lea rsi, [rel fd_data_apps]
    mov edx, 11
    call memcmp
    test rax, rax
    jz .apps
    mov rdi, rbx
    lea rsi, [rel fd_data_docs]
    mov edx, 11
    call memcmp
    test rax, rax
    jnz .bad
    mov eax, FD_DATA_DOC_MAX
    jmp .out
.apps:
    mov eax, FD_DATA_APP_MAX
    jmp .out
.learn:
    mov eax, FD_DATA_MAX
    jmp .out
.daily:
    mov eax, FD_DATA_DAILY_CLASS
    jmp .out
.updates:
    mov eax, FD_DATA_UPDATES_MAX
    jmp .out
.cfg:
    mov eax, 1024
    jmp .out
.bad:
    xor eax, eax
.out:
    pop rbx
    ret

; EAX=purpose class -> EAX actual byte maximum. Not an admission checker.
fd_data_size_limit:
    cmp eax, FD_DATA_DAILY_CLASS
    jne .out
    mov eax, FD_DATA_DAILY_MAX
.out:
    ret

; 1 admitted provider name, -1 refused provider, 0 unrelated legacy context.
fd_data_name_gate:
    push rdi
    push rsi
    push rdx
    push rcx
    lea rax, [rel fd_dir_ctx]
    cmp rsi, rax
    jne .context
    cmp dword [rel fd_dir_gate], 1
    jne .other
    mov rsi, [rel fd_dir_owner]
.context:
    lea rax, [rel fd_data_ctx]
    cmp rsi, rax
    jne .other
    cmp byte [rel fd_data_active], 1
    jne .no
    call fd_data_policy
    test eax, eax
    jz .no
    cmp dword [rel fd_data_mode], 6
    jne .not_daily
    cmp eax, FD_DATA_DAILY_CLASS
    jne .no
    jmp .allowed
.not_daily:
    cmp eax, FD_DATA_DAILY_CLASS
    je .no
    cmp dword [rel fd_data_mode], 1
    jne .not_learned
    cmp eax, FD_DATA_MAX
    jne .no
.not_learned:
    cmp dword [rel fd_data_mode], 2
    jne .not_local
    cmp eax, 1024
    jne .no
.not_local:
    cmp dword [rel fd_data_mode], 5
    jne .not_updates
    cmp eax, FD_DATA_UPDATES_MAX
    jne .no
    jmp .allowed
.not_updates:
    cmp dword [rel fd_data_mode], 4
    jne .not_docs
    cmp eax, FD_DATA_DOC_MAX
    jne .no
    jmp .allowed
.not_docs:
    cmp eax, FD_DATA_DOC_MAX
    je .no
    cmp dword [rel fd_data_mode], 3
    jne .not_app
    cmp eax, FD_DATA_APP_MAX
    jne .no
    jmp .allowed
.not_app:
    cmp eax, FD_DATA_APP_MAX
    je .no
.allowed:
    mov eax, 1
    jmp .out
.no:
    mov rax, -1
    jmp .out
.other:
    xor eax, eax
.out:
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    ret

fd_data_mount:                          ; no remount or generation refresh
    mov rdi, [rdi + fsmount.priv]
    jmp fd_data_current
fd_data_stat:
    call fd_data_io_gate
    test rax, rax
    jnz .out
    jmp fat32_disk_stat
.out:
    ret
fd_data_read_at:
    call fd_data_io_gate
    test rax, rax
    jnz .out
    jmp fat32_disk_read_at
.out:
    ret
fd_data_io_gate:
    push rdi
    push rsi
    push rdx
    push rcx
    push r8
    mov rdi, rsi
    call fd_data_policy
    test eax, eax
    jz .fail
    call fd_data_metadata
    jmp .out
.fail:
    mov rax, -1
.out:
    pop r8
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    ret

; Whole-record read, exact EOF, cap and per-name bound; public, no write grant.
data_config_read:                      ; RDI=token, RSI=name11, RDX=buf, RCX=cap
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 16
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    test r13, r13
    jz .fail
    test r14, r14
    jz .fail
    call data_config_current
    test rax, rax
    jnz .fail
    mov rdi, r13
    call fd_data_policy
    test eax, eax
    jz .fail
    call fd_data_size_limit
    mov ebx, eax
    mov rdi, [rel fd_data_binding + 24]
    mov rsi, r13
    mov rdx, rsp
    call fat32_disk_stat
    test rax, rax
    jnz .stat_failed
    mov rax, [rsp]
    test rax, rax
    jz .fail
    cmp rax, rbx
    ja .fail
    cmp rax, r15
    ja .fail
    mov rbx, rax
    mov rdi, [rel fd_data_binding + 24]
    mov rsi, r13
    xor edx, edx
    mov rcx, r14
    mov r8, rbx
    call fat32_disk_read_at
    cmp rax, rbx
    jne .fail
    mov rdi, r12
    call data_config_current
    test rax, rax
    jnz .fail
    mov rax, rbx
    jmp .out
.stat_failed:
    cmp dword [rel fat32_disk_last_error], FD_ERR_NOT_FOUND
    jne .fail
    ; Lookup skips non-files. A separate native, read-only conflict scan
    ; must prove no live entry of ANY type before publishing confirmed ENOENT.
    lea rdi, [rel fd_data_ctx]
    mov rsi, r13
    call fd_probe_slot
    test rax, rax
    jnz .fail
    mov rdi, r12
    call data_config_current
    test rax, rax
    jnz .fail
    mov rax, -4
    jmp .out
.fail:
    mov rax, -1
.out:
    add rsp, 16
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Synchronous BSP whole-record atomic publish through the real copy journal.
; 0 = flush + reopen byte-equal; -1 pre-effect refusal; -2 busy;
; -3 uncertain after any effect attempt. Caller must reopen, never auto-retry.
data_config_write:                     ; ordinary request authority only
    xor r10d, r10d
    jmp fd_data_write_common

; R10D mode: 0 request, 1 learned, 2 local CFG, 3 app, 4 docs, 5 Updates.
fd_data_write_common:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    sub rsp, 32
    mov [rsp + 24], r11
    mov [rsp], r10
    mov [rsp + 8], r8
    mov [rsp + 16], r9
    mov rdi, r13
    call fd_data_authorize_start
    test rax, rax
    jnz .refuse
    test r13, r13
    jz .refuse
    test r14, r14
    jz .refuse
    test r15, r15
    jz .refuse
    mov rdi, r12
    call data_config_current
    test rax, rax
    jnz .refuse
    mov rdi, r13
    call fd_data_policy
    test eax, eax
    jz .refuse
    call fd_data_size_limit
    cmp r15, rax
    ja .refuse
    call vfs_copy_busy
    test eax, eax
    jnz .busy
    call storage_access_binding_busy
    test eax, eax
    jnz .busy
    cmp dword [rel fd_cp_phase], FD_CP_IDLE
    jne .busy
    mov al, 1
    xchg al, [rel fd_data_active]
    test al, al
    jnz .busy
    mov rax, [rsp]
    mov [rel fd_data_mode], eax
    mov rax, [rsp + 8]
    mov [rel fd_data_local_pid], rax
    mov rax, [rsp + 16]
    mov [rel fd_data_local_authority], rax
    mov rax, [rsp + 24]
    mov [rel fd_data_local_check], rax
    mov qword [rel fd_data_owned_op], 0
    mov qword [rel fd_data_effects], 0
    mov byte [rel fd_data_io_failed], 0
    mov rax, [rel blk_flush_failures]
    mov [rel fd_data_flush_before], rax
    cmp dword [rel fd_data_mode], 0
    je .request_ready
    call fd_data_owned_begin
    test rax, rax
    jnz .failed_active
.request_ready:
    ; One lazy reusable bounded snapshot: native kfree is not a reclaiming
    ; allocator. No per-write bump leak and no mutable consumer source in IO.
    cmp qword [rel fd_data_buffer], 0
    jne .allocated
    mov edi, FD_DATA_MAX
    call kmalloc
    test rax, rax
    jz .failed_active
    mov [rel fd_data_buffer], rax
.allocated:
    mov rdi, [rel fd_data_buffer]
    xor esi, esi
    lea rdx, [r15 + 511]
    and rdx, -512
    call memset
    mov rdi, [rel fd_data_buffer]
    mov rsi, r14
    mov rdx, r15
    call memcpy
    lea rdi, [rel fd_cp_name]
    mov rsi, r13
    mov edx, 11
    call memcpy
    ; Reserve the shared directory view before any journal recovery writes.
    mov eax, 1
    xchg eax, [rel fd_dir_gate]
    test eax, eax
    jnz .failed_active
    mov byte [rel fd_dir_inside], 0
    mov byte [rel fd_dir_view_valid], 0
    lea rbx, [rel fd_data_ctx]
    mov [rel fd_dir_owner], rbx
    ; Narrow authority never resolves a pre-existing journal of ANY scope.
    ; The new transaction below is created only after this read-only preflight.
    cmp dword [rel fd_data_mode], 0
    je .recovery_ready
    call fd_data_clean_root
    test rax, rax
    jnz .failed_gate
.recovery_ready:
    ; writer_enter yields after a bounded sweep. Complete only its pending
    ; root recovery, with fresh authorization on every effect; do not retry IO.
    mov ebp, 262144
.recover:
    mov rdi, rbx
    call fd_writer_enter
    test rax, rax
    jz .locked
    cmp dword [rel fat32_disk_last_error], FD_ERR_BUSY
    jne .failed_gate
    cmp dword [rbx + FD_TX_BUSY], 0
    jne .failed_gate
    dec ebp
    jnz .recover
    jmp .failed_gate
.locked:
    mov rdi, rbx
    mov esi, [rbx + FD_ROOT_CLUSTER]
    call fd_cp_view
    test rax, rax
    jnz .failed_locked
    ; Initialize the copy engine's per-file state; no tree, ask, retry or queue.
    mov dword [rel fd_tree_on], 0
    mov qword [rel fd_tree_base], 0
    mov byte [rel fd_cp_cmp_on], 0
    mov byte [rel fd_cp_src_retry_pending], 0
    mov byte [rel fd_cp_src_retried], 0
    mov byte [rel fd_cp_src_fault], 0
    mov byte [rel fd_cp_repl], 0
    mov byte [rel fd_cp_swapped], 0
    mov byte [rel fd_cp_old_case], 0
    mov dword [rel fd_cp_kept], 0
    mov dword [rel fd_cp_wrt], 0
    mov dword [rel fd_cp_error], 0
    mov dword [rel fd_cp_mode], FS_CMODE_FORCE
    mov dword [rel fd_cp_alloc_hint], 2
    mov dword [rel fd_cp_src_head], FD_DATA_SOURCE
    mov [rel fd_cp_total], r15
    mov rax, [rbx + FD_DEV]
    mov [rel fd_cp_dev], rax
    mov rdx, [rax + dev.info]
    mov [rel fd_cp_info], rdx
    mov rdx, [rdx + blk_info.media_generation]
    mov [rel fd_cp_generation], rdx
    lea rdi, [rel fd_data_job]
    xor esi, esi
    mov edx, fs_copy_job_size
    call memset
    lea rdi, [rel fd_dir_ctx]
    lea rsi, [rel fd_cp_name]
    call fd_probe_slot
    test rax, rax
    js .failed_locked
    jz .arm
    mov rdi, rbx
    call fd_cp_older                     ; FORCE still validates old regular file/chain
    cmp eax, 1
    jne .failed_locked
    mov eax, [rel fd_cp_old_size]
    mov r14d, eax
    mov rdi, r13
    call fd_data_policy
    call fd_data_size_limit
    cmp r14, rax
    ja .failed_locked
.arm:
    mov rdi, rbx
    call fd_cp_arm
    test rax, rax
    jnz .failed_locked
    lea rax, [rel fd_data_job]
    mov [rel fd_cp_job], rax
    mov [rel fd_cp_ctx], rbx
    mov [rel fd_data_job + fs_copy_job.total], r15
    mov dword [rel fd_data_job + fs_copy_job.state], FS_JOB_RUNNING
    call fd_cp_file_start
    mov rdi, rbx
    call fd_cp_view_release
    mov dword [rel fd_dir_gate], 0
    ; Finite bound covers both max-sized chains, verification and recovery.
    mov ebp, 262144
.step:
    call fd_cp_step
    cmp dword [rel fd_cp_phase], FD_CP_IDLE
    je .finished
    dec ebp
    jnz .step
    mov dword [rel fd_cp_phase], FD_CP_IDLE ; preserve disk journal, stop all effects
    mov dword [rbx + FD_TX_BUSY], 0
    mov dword [rbx + FD_MOUNTED], 0
    jmp .failed_active
.finished:
    cmp byte [rel fd_data_io_failed], 0
    jne .failed_active
    cmp dword [rel fd_data_job + fs_copy_job.state], FS_JOB_DONE
    jne .failed_active
    cmp dword [rel fd_data_job + fs_copy_job.durable], FS_DUR_UNCERTAIN
    je .failed_active
    mov rax, [rel blk_flush_failures]
    cmp rax, [rel fd_data_flush_before]
    jne .failed_active
    mov rdi, rbx
    call fd_flush
    test rax, rax
    jnz .failed_active
    ; Reopen the published name with current binding, exact size and bytes.
    mov rdi, r12
    call data_config_current
    test rax, rax
    jnz .failed_active
    sub rsp, 16
    mov rdi, [rel fd_data_binding + 24]
    mov rsi, r13
    mov rdx, rsp
    call fat32_disk_stat
    test rax, rax
    jnz .bad_stat
    cmp [rsp], r15
    jne .bad_stat
    add rsp, 16
    xor ebp, ebp
.readback:
    mov r14, r15
    sub r14, rbp
    cmp r14, 4096
    jbe .read_size
    mov r14d, 4096
.read_size:
    mov rdi, [rel fd_data_binding + 24]
    mov rsi, r13
    mov rdx, rbp
    lea rcx, [rel fd_cp_vbuf]
    mov r8, r14
    call fat32_disk_read_at
    cmp rax, r14
    jne .failed_active
    lea rdi, [rel fd_cp_vbuf]
    mov rsi, [rel fd_data_buffer]
    add rsi, rbp
    mov rdx, r14
    call memcmp
    test rax, rax
    jnz .failed_active
    add rbp, r14
    cmp rbp, r15
    jb .readback
    mov rdi, r12
    call data_config_current
    test rax, rax
    jnz .failed_active
    cmp byte [rel fd_data_io_failed], 0
    jne .failed_active
    call fd_data_authorize_effect
    test rax, rax
    jnz .failed_active
    lock inc qword [rel vfs_write_generation]
    call fd_data_authority_end
    mov byte [rel fd_data_active], 0
    xor eax, eax
    jmp .out
.bad_stat:
    add rsp, 16
    jmp .failed_active
.failed_locked:
    mov dword [rbx + FD_TX_BUSY], 0
    mov rdi, rbx
    call fd_cp_view_release
.failed_gate:
    mov dword [rel fd_dir_gate], 0
    mov qword [rel fd_dir_owner], 0
.failed_active:
    call fd_data_authority_end
    mov byte [rel fd_data_active], 0
    cmp qword [rel fd_data_effects], 0
    je .refuse
    lock inc qword [rel vfs_write_generation]
    mov rax, -3
    jmp .out
.refuse:
    mov rax, -1
    jmp .out
.busy:
    mov rax, -2
.out:
    add rsp, 32
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Every actual write/flush reaches this, including recovery and directory views.
; An unrelated context sees no new policy. Preserve all operation arguments.
fd_data_write_gate:
    push rdi
    push rsi
    push rdx
    push rcx
    push r8
    push r9
    push r10
    push r11
    lea rax, [rel fd_dir_ctx]
    cmp rdi, rax
    jne .context
    cmp dword [rel fd_dir_gate], 1
    jne .other
    mov rdi, [rel fd_dir_owner]
.context:
    lea rax, [rel fd_data_ctx]
    cmp rdi, rax
    jne .other
    cmp byte [rel fd_data_active], 1
    jne .fail
    call fd_data_authorize_effect
    test rax, rax
    jnz .out
    call fd_data_metadata
    test rax, rax
    jnz .out
    mov rdi, [rel fd_data_ctx + FD_DEV]
    mov rsi, [rel fd_data_ctx + FD_PART_LBA]
    mov rdx, [rel fd_data_ctx + FD_PART_SECTORS]
    cmp dword [rel fd_data_mode], 0
    jne .owned
    lea r8, [rel str_fd_data_gate]
    call storage_access_require_request
    test rax, rax
    jnz .out
    mov rdi, [rel fd_data_ctx + FD_DEV]
    mov rsi, [rel fd_data_ctx + FD_PART_LBA]
    mov rdx, [rel fd_data_ctx + FD_PART_SECTORS]
    call storage_access_write_admitted
    jmp .out
.owned:
    mov r8, [rel fd_data_owned_op]
    call storage_access_owned_admitted
    jmp .out
.other:
    xor eax, eax
    jmp .out
.fail:
    mov rax, -1
.out:
    pop r11
    pop r10
    pop r9
    pop r8
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    ret

; Exact private root or its currently locked directory view. RDI preserved.
fd_data_context:
    lea rax, [rel fd_data_ctx]
    cmp rdi, rax
    je .yes
    lea rax, [rel fd_dir_ctx]
    cmp rdi, rax
    jne .no
    cmp dword [rel fd_dir_gate], 1
    jne .no
    lea rax, [rel fd_data_ctx]
    cmp [rel fd_dir_owner], rax
    jne .no
.yes:
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

; Even a best-effort FSInfo error must not become provider durable success.
fd_data_io_result:
    pushfq
    cmp byte [rel fd_data_active], 1
    jne .out
    test rax, rax
    jz .out
    mov byte [rel fd_data_io_failed], 1
.out:
    popfq
    ret

; Existing physical chokes keep all registers. Count attempts, not successes.
fd_data_effect_write:
    pushfq
    push rax
    lea rax, [rel fd_data_ctx]
    cmp r12, rax
    je .effect
    lea rax, [rel fd_dir_ctx]
    cmp r12, rax
    jne .out
    lea rax, [rel fd_data_ctx]
    cmp [rel fd_dir_owner], rax
    jne .out
.effect:
    inc qword [rel fd_data_effects]
.out:
    pop rax
    popfq
    ret
fd_data_effect_flush:
    pushfq
    push rax
    push rdi
    mov rdi, rbx
    call fd_data_context
    pop rdi
    test eax, eax
    jz .out
    inc qword [rel fd_data_effects]
.out:
    pop rax
    popfq
    ret

; Copy/verify the private memory snapshot through normal FAT sector IO.
; RDI=ctx EDX=destination cluster RCX=sectors R8D=0 copy / 1 compare.
fd_data_sectors:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r15, rcx
    mov ebp, r8d
    mov esi, edx
    call fd_cluster_lba
    cmp rax, -1
    je .fail
    mov r13, rax
    mov r14, [rel fd_cp_done]
    test ebp, ebp
    jz .buffer
    mov r14, [rel fd_cp_vdone]
.buffer:
    add r14, [rel fd_data_buffer]
.loop:
    test r15, r15
    jz .ok
    mov rbx, r15
    cmp rbx, 8
    jbe .size
    mov ebx, 8
.size:
    mov rdi, r12
    mov rsi, r13
    mov rdx, rbx
    test ebp, ebp
    jnz .compare
    mov rcx, r14
    call fd_write_sectors
    test rax, rax
    jnz .fail
    jmp .next
.compare:
    lea rcx, [rel fd_cp_vbuf]
    call fd_read_sectors
    test rax, rax
    jnz .fail
    lea rdi, [rel fd_cp_vbuf]
    mov rsi, r14
    mov rdx, rbx
    shl rdx, 9
    call memcmp
    test rax, rax
    jnz .fail
.next:
    add r13, rbx
    sub r15, rbx
    shl rbx, 9
    add r14, rbx
    jmp .loop
.ok:
    xor eax, eax
    jmp .out
.fail:
    mov rax, -1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

fd_data_current:
    push rbx
    push r12
    push rdi
    push rsi
    push rdx
    push rcx
    push r8
    push r9
    push r10
    push r11
    lea rax, [rel fd_dir_ctx]
    cmp rdi, rax
    jne .context
    cmp dword [rel fd_dir_gate], 1
    jne .ok
    mov rdi, [rel fd_dir_owner]
.context:
    lea rax, [rel fd_data_ctx]
    cmp rdi, rax
    jne .ok
    cmp dword [rdi + FD_MOUNTED], 1
    jne .fail
    mov r12, [rdi + FD_DEV]
    xor ebx, ebx
.next:
    mov rdi, rbx
    mov esi, BLKCAP_READ | BLKCAP_WRITE | BLKCAP_FLUSH
    xor edx, edx
    call blk_iter_after
    test rax, rax
    jz .fail
    mov rbx, rax
    cmp rbx, r12
    jne .next
    mov rax, [rbx + dev.info]
    cmp rax, [rel fd_data_info]
    jne .fail
    test rax, rax
    jz .fail
    mov rdx, [rbx + dev.ops]
    cmp rdx, [rel fd_data_devops]
    jne .fail
    cmp dword [rax + blk_info.sector_size], 512
    jne .fail
    cmp dword [rax + blk_info.logical_sector_bytes], 512
    jne .fail
    test dword [rax + blk_info.flags], BLKF_RO
    jnz .fail
    mov rdx, [rel fd_data_max]
    cmp rdx, [rax + blk_info.lba_max]
    jne .fail
    mov rdx, [rel fd_data_generation]
    test rdx, rdx
    jz .fail
    cmp rdx, [rax + blk_info.media_generation]
    jne .fail
    cmp rdx, [rel fd_data_ctx + FD_MOUNT_GEN]
    jne .fail
.ok:
    xor eax, eax
    jmp .out
.fail:
    mov dword [rel fd_data_ctx + FD_MOUNTED], 0
    mov rax, -1
.out:
    pop r11
    pop r10
    pop r9
    pop r8
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    pop r12
    pop rbx
    ret

; Compare the complete validated primary GPT/header/table and accepted BPB.
; Native reads go straight through blk_read; no recursion through read custody.
; No identity refresh is possible. 1..32 sectors, each at most one sector/IO.
fd_data_metadata:
    push rbx
    push r12
    lea rdi, [rel fd_data_ctx]
    call fd_data_current
    test rax, rax
    jnz .out
    mov rdi, [rel fd_data_ctx + FD_DEV]
    mov esi, 1
    mov edx, 1
    lea rcx, [rel fd_data_check]
    call blk_read
    test rax, rax
    jnz .fail
    lea rdi, [rel fd_data_check]
    lea rsi, [rel fd_data_header]
    mov edx, 512
    call memcmp
    test rax, rax
    jnz .fail
    xor ebx, ebx
.table:
    mov rdi, [rel fd_data_ctx + FD_DEV]
    mov rsi, [rel fd_data_header + 72]
    add rsi, rbx
    mov edx, 1
    lea rcx, [rel fd_data_check]
    call blk_read
    test rax, rax
    jnz .fail
    mov eax, ebx
    shl eax, 9
    lea rsi, [rel fd_data_entries]
    add rsi, rax
    lea rdi, [rel fd_data_check]
    mov edx, 512
    call memcmp
    test rax, rax
    jnz .fail
    inc ebx
    cmp ebx, [rel fd_data_table_sectors]
    jb .table
    mov rdi, [rel fd_data_ctx + FD_DEV]
    mov rsi, [rel fd_data_ctx + FD_PART_LBA]
    mov edx, 1
    lea rcx, [rel fd_data_check]
    call blk_read
    test rax, rax
    jnz .fail
    lea rdi, [rel fd_data_check]
    lea rsi, [rel fd_data_boot]
    mov edx, 512
    call memcmp
    test rax, rax
    jnz .fail
    lea rdi, [rel fd_data_ctx]
    call fd_data_current                ; identity again after every bounded read set
    jmp .out
.fail:
    mov dword [rel fd_data_ctx + FD_MOUNTED], 0
    mov rax, -1
.out:
    pop r12
    pop rbx
    ret


%include "fs/data_config_authority.asm"
%include "sec/data_config_local.asm"

str_fd_data_name: db 'data-config',0
str_fd_data_gate: db 'fs.data.owner_config',0
fd_data_cfg: db 'PAOS    CFG'
fd_data_cfg_v2: db 'PAOS2   CFG'
fd_data_updates: db 'UPDATE  CFG'
fd_data_daily: db 'UPDAILY CFG'
fd_data_learn0: db 'DDLEARN0BIN'
fd_data_learn1: db 'DDLEARN1BIN'
fd_data_apps: db 'PAOSAPPSBIN'
fd_data_docs: db 'PAOSDOCSBIN'
%macro WDATA_BSS_fs_data_config 0
alignb 8
fd_data_ctx: resb FD_CTX_SIZE
fd_data_probe: resb FD_CTX_SIZE
fd_data_ops: resb fs_ops_size
fd_data_info: resq 1
fd_data_devops: resq 1
fd_data_generation: resq 1
fd_data_max: resq 1
fd_data_serial: resq 1
fd_data_effects: resq 1
fd_data_flush_before: resq 1
fd_data_buffer: resq 1
fd_data_binding: resb FD_DATA_TOKEN
fd_data_job: resb fs_copy_job_size
fd_data_handle: resd 1
fd_data_table_sectors: resd 1
fd_data_active: resb 1
fd_data_io_failed: resb 1
alignb 8
fd_data_header: resb 512
fd_data_entries: resb 16384
fd_data_boot: resb 512
fd_data_check: resb 512
%endmacro
WDATA_BSS_DEFER WDATA_BSS_fs_data_config
%endif
