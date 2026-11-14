;; MODULE fs/fat32_probe_window
;; LAYER 4
;; EXPORTS fat32_probe_window_begin, fat32_probe_window_read, fat32_probe_window_write, fat32_probe_window_flush, fat32_probe_window_end
;; IMPORTS fs/fat32_disk, fs/vol_owner, fs/storage_access, fs/blockdev, fs/vfs, core/lib/mem
;; CAPS
;; OWNER saga:fs_wave
;; CONTEXT: bsp_only
; One synchronous request owns a fresh file, not raw free space. No selection,
; adoption, arm, recovery, replacement, cleanup, retry, DATA role or 4Kn grant.
; Caller must finally END before yielding/returning from the original request.

fat32_probe_window_begin:                 ; EDI=armed scratch handle, RSI=nonce,
                                        ; RDX=2048 initial bytes, RCX=out64
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov ebp, edi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    test r15, r15
    jz .no
    mov rdi, r15
    xor esi, esi
    mov edx, 64
    call memset
    cmp byte [rel fpw_active], 0
    jne .busy
    test r13, r13
    jz .no
    test r14, r14
    jz .no
    mov rax, 0x7FFFFFFFFFFFFFFF
    cmp [rel fpw_serial], rax
    jae .no                              ; never issue zero/negative/reused handles
    call fd_scratch_owner
    test rax, rax
    jnz .no
    call vfs_copy_busy
    test eax, eax
    jnz .busy
    call storage_access_binding_busy
    test eax, eax
    jnz .busy
    cmp dword [rel fd_cp_phase], FD_CP_IDLE
    jne .busy
    cmp qword [rel fd_scratch_job_tag], 0
    jne .busy
    cmp dword [rel fd_dir_gate], 0
    jne .busy
    cmp dword [rel fd_scratch_ctx + FD_TX_BUSY], 0
    jne .busy
    mov edi, ebp
    call vfs_mount_ptr
    test rax, rax
    jz .no
    mov r12, rax
    lea rax, [rel fd_scratch_ops]
    cmp [r12 + fsmount.ops], rax
    jne .no
    lea rax, [rel fd_scratch_ctx]
    cmp [r12 + fsmount.priv], rax
    jne .no
    cmp dword [rax + FD_SPC], 4
    jb .no                               ; one allocated cluster must contain all4
    mov rdi, rax
    call fd_scratch_write_gate
    test rax, rax
    jnz .no
    ; Snapshot caller memory before the allocator/shared scratch can touch it.
    lea rdi, [rel fpw_payload]
    mov rsi, r14
    mov edx, 2048
    call memcpy
    mov [rel fpw_mount], r12
    mov [rel fpw_nonce], r13
    mov edi, ebp
    call vol_owner_bind_mount
    test rax, rax
    jz .no
    mov rcx, rax
    mov rdi, [rel fd_scratch_ctx + FD_DEV]
    mov rsi, [rel fd_scratch_ctx + FD_PART_LBA]
    mov rdx, [rel fd_scratch_ctx + FD_PART_SECTORS]
    call storage_access_owned_op_begin
    test rax, rax
    jz .no
    mov [rel fpw_op], rax
    mov byte [rel fpw_active], 1
    mov byte [rel fpw_effect], 0
    mov byte [rel fpw_failed], 0
    mov dword [rel fd_dir_gate], 1
    mov dword [rel fd_scratch_ctx + FD_TX_BUSY], 1
    ; Read-only full root scan refuses every pending transaction. Do not run or
    ; mark a recovery sweep under this fresh-file authority.
    call fpw_clean_root
    test rax, rax
    jnz .failed
    ; FSWxxxxx.TST, exact11 bytes. A low20 nonce collision REFUSES (no overwrite).
    lea rdi, [rel fpw_name]
    mov word [rdi], 'FS'
    mov byte [rdi + 2], 'W'
    mov word [rdi + 8], 'TS'
    mov byte [rdi + 10], 'T'
    mov byte [rdi + 11], 0
    mov rax, [rel fpw_nonce]
    mov ecx, 5
.hex:
    mov edx, eax
    and edx, 15
    lea rsi, [rel fpw_hex]
    mov dl, [rsi + rdx]
    mov [rdi + rcx + 2], dl
    shr rax, 4
    dec ecx
    jnz .hex
    mov rdi, r12
    lea rsi, [rel fpw_name]
    lea rdx, [rel fpw_payload]
    mov ecx, 256
    call fd_create_locked                ; existing allocator/collision/dual FAT
    cmp rax, -1
    je .failed
    mov [rel fpw_cluster], eax
    lea rdi, [rel fd_scratch_ctx]
    mov esi, eax
    call fd_cluster_lba
    cmp rax, -1
    je .failed
    mov [rel fpw_first], rax
    lea rdi, [rel fd_scratch_ctx]
    mov rsi, rax
    mov edx, 4
    lea rcx, [rel fpw_payload]
    call fd_write_sectors                ; only this newly allocated cluster
    test rax, rax
    jnz .failed
    lea rdi, [rel fd_scratch_ctx]
    call fd_flush
    test rax, rax
    jnz .failed
    ; Reopen exact fresh file before extending its size within that cluster.
    lea rdi, [rel fd_scratch_ctx]
    lea rsi, [rel fpw_name]
    call fd_lookup
    test rax, rax
    jnz .failed
    mov eax, [rel fpw_cluster]
    cmp eax, [rel fd_found_cluster]
    jne .failed
    cmp qword [rel fd_found_size], 256
    jne .failed
    test byte [rel fd_found_attr], 0x18
    jnz .failed
    lea rdi, [rel fd_scratch_ctx]
    mov rsi, [rel fd_found_dir_lba]
    mov edx, [rel fd_found_dir_off]
    add edx, 28
    lea rcx, [rel fpw_size]
    mov r8d, 4
    call fd_dir_patch                    ; initialized bytes durable BEFORE size
    test rax, rax
    jnz .failed
    lea rdi, [rel fd_scratch_ctx]
    call fd_flush
    test rax, rax
    jnz .failed
    mov rdi, r12
    lea rsi, [rel fpw_name]
    xor edx, edx
    lea rcx, [rel fpw_verify]
    mov r8d, 2048
    call fat32_disk_read_at
    cmp rax, 2048
    jne .failed
    lea rdi, [rel fpw_payload]
    lea rsi, [rel fpw_verify]
    mov edx, 2048
    call memcmp
    test rax, rax
    jnz .failed
    call fpw_current
    test rax, rax
    jnz .failed
    inc qword [rel fpw_serial]
    mov rbx, [rel fpw_serial]
    mov rax, [rel fd_scratch_ctx + FD_DEV]
    mov [r15], rax
    mov rdx, [rax + dev.info]
    mov rax, [rel fpw_first]
    mov [r15 + 8], rax
    mov qword [r15 + 16], 4
    mov rax, [rdx + blk_info.media_generation]
    mov [r15 + 24], rax
    mov dword [r15 + 32], 512
    mov eax, [rdx + blk_info.physical_sector_bytes]
    mov [r15 + 36], eax
    mov eax, [rdx + blk_info.max_transfer_sectors]
    mov [r15 + 40], rax
    lea rdi, [r15 + 48]
    lea rsi, [rel fpw_name]
    mov edx, 11
    call memcpy
    mov rax, rbx
    jmp .out
.failed:
    call fpw_failure
    mov rbx, rax
    call fpw_close
    mov rax, rbx
    jmp .out
.busy:
    mov rax, -2
    jmp .out
.no:
    mov rax, -1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Handle + current identity, exact fresh file extent and current OWNER/SPECIAL.
fpw_handle:
    cmp byte [rel fpw_active], 1
    jne .no
    test rdi, rdi
    jz .no
    cmp rdi, [rel fpw_serial]
    jne .no
    jmp fpw_current
.no:
    mov rax, -1
    ret
fpw_current:
    lea rdi, [rel fd_scratch_ctx]
    call fd_scratch_write_gate
    test rax, rax
    jnz .no
    cmp dword [rel fd_dir_gate], 1
    jne .no
    cmp dword [rel fd_scratch_ctx + FD_TX_BUSY], 1
    jne .no
    lea rdi, [rel fd_scratch_ctx]
    call fd_read_cache_drop               ; mapping uses fresh dirent and FAT
    mov rdi, [rel fpw_mount]
    lea rax, [rel fd_scratch_ops]
    cmp [rdi + fsmount.ops], rax
    jne .no
    lea rax, [rel fd_scratch_ctx]
    cmp [rdi + fsmount.priv], rax
    jne .no
    lea rsi, [rel fpw_name]
    mov edx, 11
    lea rcx, [rel fpw_map]
    mov r8d, 1
    call fat32_disk_file_extents
    cmp rax, 1
    jne .no
    cmp qword [rel fpw_map + fs_extent_map.size], 2048
    jne .no
    mov rax, [rel fpw_first]
    cmp [rel fpw_map + fs_extent_map.ext], rax
    jne .no
    cmp qword [rel fpw_map + fs_extent_map.ext + 8], 4
    jne .no
    xor eax, eax
    ret
.no:
    mov rax, -1
    ret

fat32_probe_window_read:                  ; handle, relative0..3, count1..4, buf
    push rbx
    push r12
    push r13
    mov rbx, rsi
    mov r12, rdx
    mov r13, rcx
    call fpw_handle
    test rax, rax
    jnz .no
    test r13, r13
    jz .refused
    test r12, r12
    jz .refused
    cmp rbx, 3
    ja .refused
    cmp r12, 4
    ja .refused
    lea rax, [rbx + r12]
    cmp rax, 4
    ja .refused
    lea rdi, [rel fd_scratch_ctx]
    mov rsi, [rel fpw_first]
    add rsi, rbx
    mov rdx, r12
    mov rcx, r13
    call fd_read_sectors
    test rax, rax
    jnz .no
    call fpw_current                     ; include post-transfer custody
    test rax, rax
    jnz .no
    xor eax, eax
    jmp .out
.no:
    call fpw_failure
    jmp .out
.refused:
    mov rax, -1                         ; known pre-transfer arguments: no taint
.out:
    pop r13
    pop r12
    pop rbx
    ret

fat32_probe_window_write:                 ; handle, count1|2, buf; fixed offset1
    push r12
    push r13
    mov r12, rsi
    mov r13, rdx
    call fpw_handle
    test rax, rax
    jnz .no
    test r13, r13
    jz .refused
    cmp r12, 1
    jb .refused
    cmp r12, 2
    ja .refused
    lea rdi, [rel fd_scratch_ctx]
    mov rsi, [rel fpw_first]
    inc rsi
    mov rdx, r12
    mov rcx, r13
    call fd_write_sectors
    test rax, rax
    jnz .no
    call fpw_current
    test rax, rax
    jnz .no
    xor eax, eax
    jmp .out
.no:
    call fpw_failure
    jmp .out
.refused:
    mov rax, -1                         ; known pre-transfer arguments: no taint
.out:
    pop r13
    pop r12
    ret

fat32_probe_window_flush:                 ; handle
    call fpw_handle
    test rax, rax
    jnz fpw_failure
    lea rdi, [rel fd_scratch_ctx]
    call fd_flush
    test rax, rax
    jnz fpw_failure
    call fpw_current
    test rax, rax
    jnz fpw_failure
    ret

fat32_probe_window_end:                   ; terminal cleanup needs no live grant
    cmp byte [rel fpw_active], 1
    jne .no
    test rdi, rdi
    jz .no
    cmp rdi, [rel fpw_serial]
    jne .no
    push rbx
    xor ebx, ebx
    cmp byte [rel fpw_failed], 0
    jne .uncertain
    call fpw_current
    test rax, rax
    jz .close
.uncertain:
    mov rbx, -3
.close:
    call fpw_close
    mov rax, rbx
    pop rbx
    ret
.no:
    mov rax, -1
    ret
fpw_close:
    mov rdi, [rel fpw_op]
    call storage_access_owned_op_end
    mov qword [rel fpw_op], 0
    mov byte [rel fpw_active], 0
    mov dword [rel fd_scratch_ctx + FD_TX_BUSY], 0
    mov dword [rel fd_dir_gate], 0
    ret
fpw_failure:
    mov rax, -1
    cmp byte [rel fpw_active], 1
    jne .out
    mov byte [rel fpw_failed], 1
    cmp byte [rel fpw_effect], 0
    je .out
    mov rax, -3                         ; no retry/recovery/cleanup after effect
.out:
    ret

; Physical hooks are inert for all other contexts and preserve IO arguments.
fpw_context:                             ; RDI=ctx -> EAX active exact context?
    xor eax, eax
    cmp byte [rel fpw_active], 1
    jne .out
    lea rax, [rel fd_scratch_ctx]
    cmp rdi, rax
    sete al
    movzx eax, al
.out:
    ret
fpw_gate:
    call fpw_context
    test eax, eax
    jz .out
    push rdi
    push rsi
    push rdx
    push rcx
    push r8
    push r9
    push r10
    push r11
    cmp byte [rel fpw_failed], 0
    jne .no
    mov rdi, [rel fd_scratch_ctx + FD_DEV]
    mov rsi, [rel fd_scratch_ctx + FD_PART_LBA]
    mov rdx, [rel fd_scratch_ctx + FD_PART_SECTORS]
    mov r8, [rel fpw_op]
    call storage_access_owned_admitted
    jmp .restore
.no:
    mov rax, -1
.restore:
    pop r11
    pop r10
    pop r9
    pop r8
    pop rcx
    pop rdx
    pop rsi
    pop rdi
.out:
    ret
fpw_owned_write:                         ; R12=ctx, actual physical IO args
    xor r11d, r11d
    cmp byte [rel fpw_active], 1
    jne .out
    lea rax, [rel fd_scratch_ctx]
    cmp r12, rax
    jne .out
    mov byte [rel fpw_effect], 1
    mov r8, [rel fpw_op]
    call blk_write_owned
    mov r11d, 1                         ; failure NEVER falls back to generic IO
.out:
    ret
fpw_effect_flush:                        ; RBX=ctx
    cmp byte [rel fpw_active], 1
    jne .out
    lea rax, [rel fd_scratch_ctx]
    cmp rbx, rax
    jne .out
    mov byte [rel fpw_effect], 1
.out:
    ret
fpw_io_result:                           ; preserve RAX physical return value
    test rax, rax
    jz .out
    cmp byte [rel fpw_active], 1
    jne .out
    mov byte [rel fpw_failed], 1
.out:
    ret

fpw_clean_root:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    lea r12, [rel fd_scratch_ctx]
    mov r13d, [r12 + FD_ROOT_CLUSTER]
    xor r15d, r15d
.cluster:
    cmp r15d, FD_DIR_MAX_CLUSTERS
    jae .no
    xor ecx, ecx
.seen:
    cmp ecx, r15d
    jae .remember
    lea rdx, [rel fpw_seen]
    cmp [rdx + rcx * 4], r13d
    je .no
    inc ecx
    jmp .seen
.remember:
    lea rdx, [rel fpw_seen]
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
    lea rcx, [rel fpw_scan]
    call fd_read_sectors
    test rax, rax
    jnz .no
    xor ebx, ebx
.entry:
    lea rdx, [rel fpw_scan]
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


fpw_hex: db '0123456789ABCDEF'
fpw_size: dd 2048
%macro WDATA_BSS_fs_fat32_probe_window 0
alignb 8
fpw_serial: resq 1
fpw_op: resq 1
fpw_mount: resq 1
fpw_nonce: resq 1
fpw_first: resq 1
fpw_cluster: resd 1
fpw_active: resb 1
fpw_effect: resb 1
fpw_failed: resb 1
fpw_name: resb 12
alignb 8
fpw_map: resb fs_extent_map_size + 16
fpw_seen: resd FD_DIR_MAX_CLUSTERS
fpw_scan: resb 512
fpw_payload: resb 2048
fpw_verify: resb 2048
%endmacro
WDATA_BSS_DEFER WDATA_BSS_fs_fat32_probe_window
