;; MODULE fs/fat32_copy_observation
;; LAYER 4
;; EXPORTS fat32_copy_cut_observe
;; IMPORTS fs/blockdev, fs/vfs
;; CAPS
;; OWNER saga:fs_wave
; Read-only, no I/O and no grant. RDI=current job, RSI=96-byte output.
; 8 qwords: generation/start/sectors/journal LBA+offset/destination LBA+offset/serial;
; then on-media disk GUID[16], partition GUID[16]. Never exports pointers.
; This is only the held FAT scratch BEGIN journal, not a completion/durability
; claim. The consumer must read and validate the actual journal sector too.
fat32_copy_cut_observe:
    push rbx
    push rbp
    push r12
    push r13
    mov r12, rdi
    mov r13, rsi
    test rdi, rdi
    jz .fail
    test rsi, rsi
    jz .fail
    cmp rdi, [rel fd_cp_job]
    jne .fail
    lea rax, [rel vfs_copy_job]
    cmp rdi, rax
    jne .fail
    cmp qword [rdi + fs_copy_job.id], 0
    je .fail
    cmp dword [rdi + fs_copy_job.state], FS_JOB_RUNNING
    jne .fail
    cmp dword [rdi + fs_copy_job.paused], 1
    jne .fail
    cmp dword [rdi + fs_copy_job.tree], 0
    jne .fail
    cmp qword [rdi + fs_copy_job.done], 0
    jne .fail
    cmp dword [rel fd_cp_phase], FD_CP_COPY
    jne .fail
    cmp qword [rel fd_cp_done], 0
    jne .fail
    cmp dword [rel fd_cp_head], 0
    jne .fail
    cmp byte [rel fd_cp_repl], 0
    jne .fail
    cmp word [rel fd_cp_rec + 12], FD_CP_MAGIC
    jne .fail
    mov rax, [rel fd_cp_total]
    test rax, rax
    jz .fail
    cmp rax, [rdi + fs_copy_job.total]
    jne .fail
    cmp eax, [rel fd_cp_rec + 28]
    jne .fail
    shr rax, 32
    jnz .fail
    lea rbp, [rel fd_scratch_ctx]
    cmp rbp, [rel fd_cp_ctx]
    jne .fail
    cmp byte [rel fd_scratch_armed], 1
    jne .fail
    cmp qword [rel fd_scratch_job_tag], 0
    je .fail
    cmp dword [rbp + FD_MOUNTED], 1
    jne .fail
    cmp dword [rbp + FD_TX_BUSY], 1
    jne .fail
    mov edi, [r12 + fs_copy_job.mount]
    call vfs_mount_ptr
    test rax, rax
    jz .fail
    cmp rbp, [rax + fsmount.priv]
    jne .fail
    lea rdx, [rel fd_scratch_ops]
    cmp rdx, [rax + fsmount.ops]
    jne .fail
    cmp rdx, [rel vfs_copy_live_ops]
    jne .fail
    cmp rbp, [rel vfs_copy_live_priv]
    jne .fail
    lea rdx, [rel small_copy_fat_dispatch]
    cmp rdx, [rel vfs_copy_live_entry]
    jne .fail
    xor ebx, ebx
.next:
    mov rdi, rbx
    mov esi, BLKCAP_READ | BLKCAP_WRITE | BLKCAP_FLUSH
    xor edx, edx
    call blk_iter_after
    test rax, rax
    jz .fail
    mov rbx, rax
    cmp rax, [rbp + FD_DEV]
    jne .next
    cmp rax, [rel fd_cp_dev]
    jne .fail
    cmp rax, [r12 + fs_copy_job.dev]
    jne .fail
    mov rdx, [rax + dev.ops]
    cmp rdx, [rel fd_scratch_devops]
    jne .fail
    mov rax, [rax + dev.info]
    test rax, rax
    jz .fail
    cmp rax, [rel fd_cp_info]
    jne .fail
    cmp rax, [rel fd_scratch_info]
    jne .fail
    test dword [rax + blk_info.flags], BLKF_RO
    jnz .fail
    cmp dword [rax + blk_info.sector_size], 512
    jne .fail
    cmp dword [rax + blk_info.logical_sector_bytes], 512
    jne .fail
    mov rdx, [rax + blk_info.lba_max]
    cmp rdx, [rel fd_scratch_max]
    jne .fail
    mov rdx, [rax + blk_info.media_generation]
    test rdx, rdx
    jz .fail
    cmp rdx, [rel fd_cp_generation]
    jne .fail
    cmp rdx, [rel fd_scratch_generation]
    jne .fail
    cmp rdx, [rbp + FD_MOUNT_GEN]
    jne .fail
    mov [r13], rdx
    mov rax, [rbp + FD_PART_LBA]
    mov [r13 + 8], rax
    mov rcx, [rbp + FD_PART_SECTORS]
    mov [r13 + 16], rcx
    add rcx, rax
    jc .fail
    mov rdx, [rel fd_cp_rec_lba]
    cmp rdx, rax
    jb .fail
    cmp rdx, rcx
    jae .fail
    mov [r13 + 24], rdx
    mov edx, [rel fd_cp_rec_off]
    cmp edx, 480
    ja .fail
    test edx, 31
    jnz .fail
    mov [r13 + 32], rdx
    mov rdx, [rel fd_cp_dst_lba]
    cmp rdx, rax
    jb .fail
    cmp rdx, rcx
    jae .fail
    mov [r13 + 40], rdx
    mov edx, [rel fd_cp_dst_off]
    cmp edx, 480
    ja .fail
    test edx, 31
    jnz .fail
    mov [r13 + 48], rdx
    mov eax, [rbp + FD_VOLUME_ID]
    mov [r13 + 56], rax
    mov rax, [rbp + FD_DISK_GUID]
    mov [r13 + 64], rax
    mov rax, [rbp + FD_DISK_GUID + 8]
    mov [r13 + 72], rax
    mov rax, [rbp + FD_PART_GUID]
    mov [r13 + 80], rax
    mov rax, [rbp + FD_PART_GUID + 8]
    mov [r13 + 88], rax
    xor eax, eax
    jmp .out
.fail:
    mov rax, -1
.out:
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
