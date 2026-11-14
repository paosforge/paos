;; MODULE svc/command_fs_errors
;; LAYER 5
;; OWNER saga:fs_wave
; Included by command_fs; shares its imports and request context.
; Typed namespace refusals. These are observations, never write authority.
; RDI returns a static wire suffix. Mount selection/admission stays in command_fs.
fs_mutation_reason:
    mov edi, [rel vfs_disk_handle]
    call vfs_mount_ptr
    test rax, rax
    jz .unknown
    mov rax, [rax + fsmount.ops]
    mov rax, [rax + fs_ops.mutate_path]
    lea rdx, [rel fat32_disk_mutate_path]
    cmp rax, rdx
    je fs_fat_mutation_reason
    lea rdx, [rel ext_op_mutate_path]
    cmp rax, rdx
    je .ext
    lea rdx, [rel exf_a_mutate_path]
    cmp rax, rdx
    je .exfat
    lea rdx, [rel nt_op_mutate_path]
    cmp rax, rdx
    jne .unknown
    mov eax, [rel nt_path_refusal]
    lea rdi, [rel fs_tx_path_long]
    cmp eax, NT_PATH_LONG
    je .out
    lea rdi, [rel fs_tx_name]
    cmp eax, NT_PATH_NAME
    je .out
    lea rdi, [rel fs_tx_missing]
    cmp eax, NT_PATH_MISSING
    je .out
    jmp .unknown
.exfat:
    ; Only the selected, completed native callback's unambiguous facts.
    ; An unarmed mount or backend READONLY error is not proof of read-only
    ; media. Authority, stale identity and uncertain I/O retain the fallback.
    mov eax, [rel exfat_disk_last_error]
    lea rdi, [rel fs_tx_missing]
    cmp eax, EXF_E_NOTFOUND
    je .out
    lea rdi, [rel fs_tx_full]
    cmp eax, EXF_E_NOSPACE
    je .out
    lea rdi, [rel fs_tx_exists]
    cmp eax, EXF_E_EXISTS
    je .out
    lea rdi, [rel fs_tx_name]
    cmp eax, EXF_E_NAME_INVALID
    je .out
    lea rdi, [rel fs_tx_path_long]
    cmp eax, EXF_E_PATH_LONG
    je .out
    jmp .unknown
.ext:
    mov eax, [rel ext4_disk_last_error]
    lea rdi, [rel fs_tx_missing]
    cmp eax, EXT_E_NOTFOUND
    je .out
    lea rdi, [rel fs_tx_name]
    cmp eax, EXT_E_BADPATH
    je .out
    lea rdi, [rel fs_tx_not_dir]
    cmp eax, EXT_E_NOTDIR
    je .out
    lea rdi, [rel fs_tx_not_empty]
    cmp eax, EXT_E_NOTEMPTY
    je .out
    lea rdi, [rel fs_tx_full]
    cmp eax, EXT_E_NOSPACE
    je .out
    lea rdi, [rel fs_tx_exact]
    cmp eax, EXT_E_NOTARMED
    je .out
    cmp eax, EXT_E_WGATE
    je .out
    cmp eax, EXT_E_DENIED
    je .out
    ; EXT_E_EXISTS aliases EXT_E_BUSY: the legacy value cannot distinguish
    ; them. Never claim an existence or space fact from that ambiguous value.
.unknown:
    lea rdi, [rel fs_tx_io]
.out:
    ret

; A zero operation slot or absent arm is not proof of read-only media. Only
; the actual FSFATRO registered table/context or current exFAT block RO flag,
; with the same request authority as selection, earns this observation.
; No hardware write, descriptor setter or new authority.
fs_mutation_mount_reason:
    call storage_access_request_owner
    cmp eax, 1
    jne .exact
    call storage_access_request_intent
    cmp eax, SA_INTENT_SPECIAL
    jne .exact
    mov edi, [rel vfs_disk_handle]
    call vfs_mount_ptr
    test rax, rax
    jz .exact
    lea rdx, [rel fd_selected_ops]
    cmp [rax + fsmount.ops], rdx
    jne .exfat
    lea rdi, [rel fd_selected_ctx]
    cmp [rax + fsmount.priv], rdi
    jne .exact
    cmp dword [rdi + FD_MOUNTED], 1
    jne .exact
    call fd_selected_current
    test rax, rax
    jnz .exact
    lea rdi, [rel fs_tx_read_only]
    ret
.exfat:
    mov rdi, rax
    call exfat_disk_mount_readonly
    cmp eax, 1
    jne .exact
    lea rdi, [rel fs_tx_read_only]
    ret
.exact:
    lea rdi, [rel fs_tx_exact]
    ret

fs_fat_mutation_reason:
    lea  rdi, [rel fs_tx_io]
    mov  eax, [rel fat32_disk_last_error]
    cmp  eax, FD_ERR_ALLOWLIST
    jne  .not_allow
    lea  rdi, [rel fs_tx_allow]
.not_allow:
    cmp  eax, FD_ERR_VOLUME_RO
    jne  .not_volume
    lea  rdi, [rel fs_tx_volume]
.not_volume:
    cmp  eax, FD_ERR_BAD_ARG
    jne  .not_name
    lea  rdi, [rel fs_tx_name]
.not_name:
    cmp  eax, FD_ERR_NOT_EXACT
    jne  .not_exact
    lea  rdi, [rel fs_tx_exact]
.not_exact:
    cmp  eax, FD_ERR_EXISTS
    jne  .not_exists
    lea  rdi, [rel fs_tx_exists]
.not_exists:
    cmp  eax, FD_ERR_BUSY
    jne  .not_busy
    lea  rdi, [rel fs_tx_busy]
.not_busy:
    cmp  eax, FD_ERR_NOT_FOUND
    jne  .not_missing
    lea  rdi, [rel fs_tx_missing]
.not_missing:
    cmp  eax, FD_ERR_NOT_DIR
    jne  .not_dir
    lea  rdi, [rel fs_tx_not_dir]
.not_dir:
    cmp  eax, FD_ERR_NOT_EMPTY
    jne  .not_empty
    lea  rdi, [rel fs_tx_not_empty]
.not_empty:
    cmp  eax, FD_ERR_CROSS_DIR
    jne  .not_cross
    lea  rdi, [rel fs_tx_cross]
.not_cross:
    cmp  eax, FD_ERR_NO_SPACE
    jne  .out
    lea  rdi, [rel fs_tx_full]
.out:
    ret

fs_tx_path_long: db " ERR path_too_long",0
fs_tx_read_only: db " ERR read_only",0
