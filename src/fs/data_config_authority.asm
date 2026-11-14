;; MODULE fs/data_config_authority
;; LAYER 4
;; EXPORTS data_config_bind_provisioned, data_config_write_learned, data_config_write_local_guarded
;; IMPORTS fs/data_config_provider, fs/fat32_disk, fs/vol_owner_data, fs/storage_access, fs/blockdev, fs/vfs, core/lib/mem
;; CAPS
;; OWNER saga:fs_wave
;; CONTEXT: bsp_only
; Included by the sole DATA provider. No serialized or caller request grant.

; Read binding from the current sealed role, never a compiled descriptor.
data_config_bind_provisioned:             ; RDI=out112
    push rbx
    push r12
    push r13
    sub rsp, 128
    mov r12, rdi
    test r12, r12
    jz .no
    mov rdi, rsp
    call vol_owner_data_identity
    test eax, eax
    jnz .no
    mov rdi, rsp
    call fd_data_select_sealed
    test rax, rax
    js .out
    mov r13, [rel vfs_disk_handle]
    mov edi, r13d
    call vol_owner_data_bind
    test rax, rax
    jz .no
    mov rbx, rax
    ; Role may have changed while probing. Compare the complete sealed identity.
    lea rdi, [rsp + 64]
    call vol_owner_data_identity
    test eax, eax
    jnz .no
    mov rdi, rsp
    lea rsi, [rsp + 64]
    mov edx, 64
    call memcmp
    test rax, rax
    jnz .no
    lea rdi, [rel fd_selected_ctx + FD_DISK_GUID]
    mov rsi, rsp
    mov edx, 32
    call memcmp
    test rax, rax
    jnz .no
    mov eax, [rel fd_selected_ctx + FD_VOLUME_ID]
    cmp eax, [rsp + 48]
    jne .no
    ; Construct descriptor56 from the verified selected BPB and sealed identity.
    lea rdi, [rsp + 64]
    mov rsi, rsp
    mov edx, 32
    call memcpy
    mov rax, [rsp + 40]
    mov [rsp + 96], rax
    mov eax, [rel fd_selected_ctx + FD_CLUSTER_COUNT]
    mov edx, [rel fd_selected_ctx + FD_SPC]
    imul rax, rdx
    mov [rsp + 104], rax
    mov eax, [rsp + 48]
    mov [rsp + 112], eax
    mov dword [rsp + 116], 0
    mov edi, r13d
    lea rsi, [rsp + 64]
    mov rdx, r12
    call fd_data_bind_common
    test rax, rax
    jnz .out
    mov [rel fd_data_owned_token], rbx
    call fd_data_role_current
    test rax, rax
    jz .out
    mov dword [rel fd_data_ctx + FD_MOUNTED], 0
.no:
    mov rax, -1
.out:
    add rsp, 128
    pop r13
    pop r12
    pop rbx
    ret

; Private selector entrance. Its arguments are obtained AGAIN from the sealed
; role in this call, then enter the same complete clone/GPT/BPB selector body.
fd_data_select_sealed:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 56
    sub rsp, 64
    mov rdi, rsp
    call vol_owner_data_identity
    test eax, eax
    jnz .no
    mov r14, [rsp + 32]
    mov r15, [rsp + 40]
    ; Copy the GUID into stable private storage for the common selector.
    lea rdi, [rel fd_data_select_guid]
    lea rsi, [rsp + 16]
    mov edx, 16
    call memcpy
    add rsp, 64
    call fd_ro_diag_reset
    lea r12, [rel fd_data_select_guid]
    mov [rsp + 32], r12
    mov r13d, -1                         ; no compiled maximum assertion
    jmp fat32_disk_select_ro_exact.authorized
.no:
    add rsp, 64
    jmp fat32_disk_select_ro_exact.auth

data_config_write_learned:
    mov r10d, 1
    jmp fd_data_write_common

; Only sec/data_config_local's fixed live checker may call this internal ABI.
; R11=immutable checker; no pointer/authority is stored beyond this operation.
data_config_write_local_guarded:
    mov r10d, 2
    jmp fd_data_write_common

; R10 mode, RDI=name, R8/R9=captured local tuple, R11=live checker.
; Preserve the operation's arguments and mode until the common body saves them.
fd_data_authorize_start:
    push r8
    push r9
    push r10
    push r11
    test r10d, r10d
    jz .request
    test rdi, rdi
    jz .no
    push rdi
    call fd_data_policy
    pop rdi
    mov r10, [rsp + 8]
    cmp r10d, 1
    jne .local
    cmp eax, FD_DATA_MAX
    jne .no
    jmp .role
.local:
    cmp r10d, 2
    jne .no
    cmp eax, 1024
    jne .no
    mov r11, [rsp]
    mov r9, [rsp + 16]
    mov r8, [rsp + 24]
    test r11, r11
    jz .no
    call r11
    test rax, rax
    jnz .out
.role:
    call fd_data_role_current
    jmp .out
.request:
    call fd_scratch_owner
    jmp .out
.no:
    mov rax, -1
.out:
    pop r11
    pop r10
    pop r9
    pop r8
    ret

fd_data_role_current:
    mov rdi, [rel fd_data_ctx + FD_DEV]
    mov rsi, [rel fd_data_ctx + FD_PART_LBA]
    mov rdx, [rel fd_data_ctx + FD_PART_SECTORS]
    mov rcx, [rel fd_data_owned_token]
    test rcx, rcx
    jz .no
    call vol_owner_data_check
    test eax, eax
    jnz .no
    xor eax, eax
    ret
.no:
    mov rax, -1
    ret

fd_data_authorize_effect:
    cmp dword [rel fd_data_mode], 0
    je fd_scratch_owner
    cmp dword [rel fd_data_mode], 1
    je fd_data_role_current
    cmp dword [rel fd_data_mode], 2
    jne .no
    mov r8, [rel fd_data_local_pid]
    mov r9, [rel fd_data_local_authority]
    mov rax, [rel fd_data_local_check]
    test rax, rax
    jz .no
    call rax
    test rax, rax
    jnz .no
    jmp fd_data_role_current
.no:
    mov rax, -1
    ret

fd_data_owned_begin:
    call fd_data_authorize_effect
    test rax, rax
    jnz .no
    mov rdi, [rel fd_data_ctx + FD_DEV]
    mov rsi, [rel fd_data_ctx + FD_PART_LBA]
    mov rdx, [rel fd_data_ctx + FD_PART_SECTORS]
    mov rcx, [rel fd_data_owned_token]
    call storage_access_owned_op_begin
    test rax, rax
    jz .no
    mov [rel fd_data_owned_op], rax
    xor eax, eax
    ret
.no:
    mov rax, -1
    ret

fd_data_authority_end:
    mov rdi, [rel fd_data_owned_op]
    call storage_access_owned_op_end
    mov qword [rel fd_data_owned_op], 0
    mov dword [rel fd_data_mode], 0
    mov qword [rel fd_data_local_pid], 0
    mov qword [rel fd_data_local_authority], 0
    mov qword [rel fd_data_local_check], 0
    ret

; Called only at the central physical write, after its per-effect gate.
; R12=context, IO arguments preserved on generic return; R11D=owned offer.
fd_data_owned_write:
    push rdi
    mov rdi, r12
    call fd_data_context
    pop rdi
    test eax, eax
    jz .generic
    cmp byte [rel fd_data_active], 1
    jne .generic
    cmp dword [rel fd_data_mode], 0
    je .generic
    mov r8, [rel fd_data_owned_op]
    call blk_write_owned
    mov r11d, 1                          ; even failure: never generic fallback
    ret
.generic:
    xor r11d, r11d
    ret

; Read-only scan before narrow authority enters any recovery. No journal of
; any kind is sufficient proof of narrow filename scope, so all remain pending.
; Bounded scan follows the complete live root chain, refusing malformed/cyclic
; or oversized directories. This does not mark sweep complete or mutate media.
fd_data_clean_root:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    lea r12, [rel fd_data_ctx]
    mov r13d, [r12 + FD_ROOT_CLUSTER]
    xor r15d, r15d
.cluster:
    cmp r15d, FD_DIR_MAX_CLUSTERS
    jae .no
    xor ecx, ecx
.seen:
    cmp ecx, r15d
    jae .remember
    lea rdx, [rel fd_data_seen]
    cmp [rdx + rcx * 4], r13d
    je .no
    inc ecx
    jmp .seen
.remember:
    lea rdx, [rel fd_data_seen]
    mov [rdx + r15 * 4], r13d
    inc r15d
    mov rdi, r12
    mov esi, r13d
    call fd_cluster_lba
    cmp rax, -1
    je .no
    mov r14, rax
    xor ebp, ebp
.sector:
    mov rdi, r12
    lea rsi, [r14 + rbp]
    mov edx, 1
    lea rcx, [rel fd_data_scan]
    call fd_read_sectors
    test rax, rax
    jnz .no
    xor ebx, ebx
.entry:
    lea rdx, [rel fd_data_scan]
    add rdx, rbx
    cmp byte [rdx], 0
    je .ok
    cmp byte [rdx], 0xE5
    je .next
    cmp byte [rdx + 11], 0x0F
    je .next
    cmp word [rdx + 12], FD_TX_MAGIC
    je .no
    cmp word [rdx + 12], FD_DG_MAGIC
    je .no
    cmp word [rdx + 12], FD_CP_MAGIC
    je .no
.next:
    add ebx, 32
    cmp ebx, 512
    jb .entry
    inc ebp
    cmp ebp, [r12 + FD_SPC]
    jb .sector
    mov rdi, r12
    mov esi, r13d
    call fd_next_cluster
    mov r13d, eax
    mov esi, eax
    mov rdi, r12
    call fd_classify_next
    cmp eax, 1
    je .ok
    test eax, eax
    jz .cluster
.no:
    mov rax, -1
    jmp .out
.ok:
    xor eax, eax
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

%macro WDATA_BSS_fs_data_authority 0
alignb 8
fd_data_owned_token: resq 1
fd_data_owned_op: resq 1
fd_data_mode: resd 1
alignb 8
fd_data_local_pid: resq 1
fd_data_local_authority: resq 1
fd_data_local_check: resq 1
fd_data_select_guid: resb 16
fd_data_scan: resb 512
fd_data_seen: resd FD_DIR_MAX_CLUSTERS
%endmacro
WDATA_BSS_DEFER WDATA_BSS_fs_data_authority
