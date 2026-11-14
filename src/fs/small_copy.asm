;; MODULE fs/small_copy
;; LAYER 4
;; EXPORTS small_copy, small_copy_between, small_copy_fat_dispatch
;; IMPORTS fs/vfs, fs/ntfs_disk, fs/fat32_disk, fs/ext4_disk, fs/ext4_copy, fs/exfat_disk, core/lib/mem
;; CAPS
;; OWNER saga:fs_wave
; Bounded plain-file copy into native NTFS, armed FAT scratch or registered armed exFAT.
; BEGIN calls the existing CREATE transaction under this request's authority.
; Unflagged STEP/CANCEL only re-resolve and compare. The explicit partial hold
; stages a private NT/exFAT CREATE; STEP uses a fresh guarded native RENAME.
; No original write authority or grant is retained.
; One BSP VFS job; 0..256B NTFS/exFAT, 1..256B FAT, new bounded native path. Original
; FAT same-volume copy remains selectable through small_copy_fat_dispatch.
%include "core/abi/wdata.inc"
SC_MAX equ 256
SC_EXF_HOLD_MAX equ 0xffff             ; full job ID must fit the native 8.3 leaf
SC_ID_BYTES equ 1024
SC_E_CHANGED equ 17
%if NT_SRC_FIELDS != 16 || NT_MAX_RUNS != 64
 %error "small_copy NTFS token layout must be updated"
%endif
%if ext_ctx.meta_buf > 64 || ext_ctx.found_ino - ext_ctx.name > 96
 %error "small_copy ext geometry token layout must be updated"
%endif
struc sc_token
 .mount: resq 1
 .ops: resq 1
 .ctx: resq 1
 .dev: resq 1
 .devops: resq 1
 .devpriv: resq 1
 .info: resq 1
 .kind: resq 1                      ; 1 NTFS, 2 FAT, 3 ext3/4 source, 4 exFAT
 .opstable: resb fs_ops_size
 .blk: resb blk_info_size
 .native: resb 2048                 ; fixed bounded immutable native geometry
endstruc

small_copy_fat_dispatch:
    cmp ecx, FS_COPY_STEP
    je .retained
    cmp ecx, FS_COPY_CANCEL
    je .retained
    ; VFS reuses its one job address. A new legacy BEGIN must retire our
    ; completed pointer before the original FAT engine reuses that record.
    cmp ecx, FS_COPY_BEGIN
    je .begin
    cmp ecx, FS_COPY_BEGIN_CARRIED   ; a queued scratch BEGIN under its carry (rc-sec 105819 C9)
    jne fd_scratch_copy
.begin:
    mov qword [rel sc_job], 0
    jmp fd_scratch_copy              ; original admission/engine unchanged
.retained:
    cmp r8, [rel sc_job]
    jne fd_scratch_copy
    cmp rdi, [rel sc_dest + sc_token.mount]
    jne fd_scratch_copy
    jmp small_copy

small_copy:
    cmp ecx, FS_COPY_BEGIN
    jne sc_resume
    mov r10, rdi                    ; same native NTFS mount
    jmp sc_begin
small_copy_between:
    cmp ecx, FS_COPY_BEGIN
    jne sc_no
sc_begin:
    test r9d, ~FS_COPY_HOLD_PARTIAL ; no carried/tree/replace/queue modes
    jnz sc_no
    mov [rel sc_hold], r9d
    test r8, r8
    jz sc_no
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov rbx, r8
    mov rbp, rdi
    mov r12, r10
    mov r13, rsi
    mov r14, rdx
    mov rax, [rel sc_job]
    test rax, rax
    jz .free
    cmp dword [rax + fs_copy_job.state], FS_JOB_DONE
    jb .bad                          ; never replace live verification
.free:
    mov qword [rel sc_job], 0
    mov byte [rel sc_partial_state], 0
    ; Destination must be an exact native writable descriptor, not a table
    ; with lookalike callbacks or an arbitrary FAT context.
    lea rax, [rel nt_ops]
    cmp [rbp + fsmount.ops], rax
    je .nt
    lea rax, [rel fd_scratch_ops]
    cmp [rbp + fsmount.ops], rax
    jne .exfat
    lea rax, [rel fd_scratch_ctx]
    cmp [rbp + fsmount.priv], rax
    jne .bad
    jmp .dest
.exfat:
    mov rdi, rbp
    call exfat_disk_copy_device    ; exact original registered mount/context
    test rax, rax
    jz .bad
    jmp .dest
.nt:
    lea rax, [rel nt_ctx]
    cmp [rbp + fsmount.priv], rax
    jne .bad
.dest:
    cmp dword [rel sc_hold], 0
    je .hold_checked
    ; Exact native NT/exFAT destination and VFS pending admission only.
    lea rax, [rel nt_ops]
    cmp [rbp + fsmount.ops], rax
    je .hold_native
    lea rax, [rel exf_ops]
    cmp [rbp + fsmount.ops], rax
    jne .bad
.hold_native:
    cmp rbx, [rel vfs_partial_job]
    jne .bad
    cmp qword [rel vfs_partial_record + fs_copy_partial.stage], 1
    jne .bad
.hold_checked:
    mov rdi, rbp
    lea rsi, [rel sc_dest]
    call sc_snapshot
    test rax, rax
    jnz .bad
    mov rdi, r12
    lea rsi, [rel sc_source]
    call sc_snapshot
    test rax, rax
    jnz .bad
    cmp rbp, r12
    je .paths
    ; Cross-volume names/partitions cannot prove different devices.
    mov rax, [rel sc_source + sc_token.dev]
    mov rdx, [rel sc_dest + sc_token.dev]
    cmp rax, rdx
    je .bad
    mov rcx, [rax + dev.info]
    cmp rcx, [rdx + dev.info]
    je .bad
    mov rcx, [rax + dev.ops]
    test rcx, rcx
    jz .paths
    cmp rcx, [rdx + dev.ops]
    jne .paths
    mov rcx, [rax + dev.priv]
    cmp rcx, [rdx + dev.priv]
    jne .paths
    mov rax, [rax + dev.info]
    mov rdx, [rdx + dev.info]
    mov eax, [rax + blk_info.unit]
    cmp eax, [rdx + blk_info.unit]
    je .bad
.paths:
    call sc_bind_reads
    test rax, rax
    jnz .bad
    mov rsi, r13
    lea rdi, [rel sc_srcpath]
    call sc_path
    test eax, eax
    js .bad
    mov [rel sc_srclen], eax
    mov rsi, r14
    lea rdi, [rel sc_dstpath]
    call sc_path
    test eax, eax
    js .bad
    mov [rel sc_dstlen], eax
    ; Source: exact regular-file stat, <=256 bytes, exact read and identity.
    lea rdi, [rel sc_source]
    lea rsi, [rel sc_srcpath]
    mov edx, [rel sc_srclen]
    lea rcx, [rel sc_source_id]
    call sc_stat
    test rax, rax
    js .bad
    mov [rel sc_length], rax
    ; fd_create_locked deliberately refuses an empty CREATE. Preserve that
    ; profile and refuse it before accepting a job or entering mutation.
    test rax, rax
    jnz .size_ok
    cmp dword [rel sc_hold], 0
    jne .bad
    cmp qword [rel sc_dest + sc_token.kind], 2
    je .bad
.size_ok:
    lea rdi, [rel sc_source]
    lea rsi, [rel sc_srcpath]
    mov edx, [rel sc_srclen]
    lea rcx, [rel sc_bytes]
    call sc_read
    test rax, rax
    jnz .bad
    call sc_check_source
    test rax, rax
    jnz .bad
    ; Destination must not already exist. The native CREATE rechecks absence
    ; and ordinary-parent/scratch namespace under actual current OWNER.
    lea rdi, [rel sc_dest]
    call sc_current
    test rax, rax
    jnz .bad
    mov rdi, rbp
    lea rsi, [rel sc_dstpath]
    mov edx, [rel sc_dstlen]
    lea rcx, [rel sc_statbuf]
    mov rax, [rbp + fsmount.ops]
    call [rax + fs_ops.stat_path]
    test rax, rax
    jz .bad
    lea rdi, [rel sc_dest]
    call sc_current
    test rax, rax
    jnz .bad
    mov rdi, rbp
    mov rax, [rbp + fsmount.ops]
    call [rax + fs_ops.mutate_armed]
    cmp eax, 1
    jne .bad
    cmp qword [rel sc_dest + sc_token.kind], 2
    jne .authority
    call fd_scratch_owner              ; hint alone never represents OWNER/intent
    test rax, rax
    jnz .bad
.authority:
    cmp dword [rel sc_hold], 0
    je .private_path_ready
    call sc_private_path
    test rax, rax
    jnz .bad
    mov rdi, rbp
    lea rsi, [rel sc_partpath]
    mov edx, [rel sc_partlen]
    lea rcx, [rel sc_statbuf]
    mov rax, [rbp + fsmount.ops]
    call [rax + fs_ops.stat_path]
    test rax, rax
    jz .bad                           ; never adopt/delete/overwrite a stale partial
    lea rdi, [rel sc_dest]
    call sc_current
    test rax, rax
    jnz .bad
.private_path_ready:
    ; Mark the retained job before any possible partial publication. A failed
    ; CREATE is a failed/uncertain job, not an unsupported no-effects refusal.
    mov [rel sc_job], rbx
    mov byte [rel sc_failed], 1
    mov byte [rel sc_dest_bound], 0
    mov rax, [rel sc_dest + sc_token.dev]
    mov [rbx + fs_copy_job.dev], rax
    mov rax, [rel sc_length]
    mov [rbx + fs_copy_job.total], rax
    mov qword [rbx + fs_copy_job.done], 0
    mov dword [rbx + fs_copy_job.error], 0
    mov dword [rbx + fs_copy_job.state], FS_JOB_VERIFYING
    mov dword [rbx + fs_copy_job.preserved], FS_PRES_NONE
    mov dword [rbx + fs_copy_job.kept], 1
    mov rdi, rbp
    lea rsi, [rel sc_dstpath]
    cmp dword [rel sc_hold], 0
    je .create_path
    lea rsi, [rel sc_partpath]
.create_path:
    lea rdx, [rel sc_bytes]
    mov rcx, [rel sc_length]
    mov r8d, FS_MUT_CREATE
    mov rax, [rbp + fsmount.ops]
    call [rax + fs_ops.mutate_path]   ; actual flush/readback, no new transport
    test rax, rax
    js .accepted
    mov byte [rel sc_failed], 0
    ; Capture newly published identity now, without refreshing old geometry.
    call sc_check_source
    test rax, rax
    jnz .failed
    lea rdi, [rel sc_dest]
    lea rsi, [rel sc_dstpath]
    mov edx, [rel sc_dstlen]
    cmp dword [rel sc_hold], 0
    je .stat_destination
    lea rsi, [rel sc_partpath]
    mov edx, [rel sc_partlen]
.stat_destination:
    lea rcx, [rel sc_dest_id]
    call sc_stat
    cmp rax, [rel sc_length]
    jne .failed
    mov byte [rel sc_dest_bound], 1
    cmp dword [rel sc_hold], 0
    je .accepted
    lea rdi, [rel sc_dest]
    lea rsi, [rel sc_partpath]
    mov edx, [rel sc_partlen]
    lea rcx, [rel sc_dest_id]
    call sc_check_file                 ; exact flushed private bytes and reference
    test rax, rax
    jnz .failed
    mov dword [rbx + fs_copy_job.state], FS_JOB_RUNNING
    mov rdi, rbx
    lea rsi, [rel sc_partpath]
    mov rdx, [rel sc_length]
    mov ecx, 3
    call vfs_copy_partial_ready
    test rax, rax
    jnz .failed
    mov byte [rel sc_partial_state], 1
    jmp .accepted
.failed:
    mov byte [rel sc_failed], 1
    mov dword [rbx + fs_copy_job.state], FS_JOB_VERIFYING
.accepted:
    xor eax, eax
    jmp .out
.bad:
    mov rax, -1
.out:
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

sc_resume:
    cmp ecx, FS_COPY_STEP
    je .op
    cmp ecx, FS_COPY_CANCEL
    jne sc_no
.op:
    mov [rel sc_resume_op], ecx
    test r8, r8
    jz sc_no
    cmp r8, [rel sc_job]
    jne sc_no
    cmp rdi, [rel sc_dest + sc_token.mount]
    jne sc_no
    push rbx
    mov rbx, r8
    cmp byte [rel sc_partial_state], 1
    je .private
    cmp byte [rel sc_partial_state], 2
    jne .published
    mov dword [rbx + fs_copy_job.state], FS_JOB_CANCELLED
    xor eax, eax
    pop rbx
    ret
.private:
    cmp dword [rbx + fs_copy_job.state], FS_JOB_RUNNING
    jne .badop
    cmp dword [rel sc_resume_op], FS_COPY_CANCEL
    jne .continue
    mov byte [rel sc_partial_state], 2
    mov dword [rbx + fs_copy_job.state], FS_JOB_CANCELLING
    xor eax, eax                       ; leave private file for explicit later cleanup
    pop rbx
    ret
.continue:
    cmp dword [rbx + fs_copy_job.paused], 0
    jne .badop
    cmp byte [rel sc_failed], 0
    jne .failed
    cmp byte [rel sc_dest_bound], 1
    jne .failed
    call sc_check_source
    test rax, rax
    jnz .failed
    lea rdi, [rel sc_dest]
    lea rsi, [rel sc_partpath]
    mov edx, [rel sc_partlen]
    lea rcx, [rel sc_dest_id]
    call sc_check_file
    test rax, rax
    jnz .failed
    ; The original CREATE authority is never carried. Normal native RENAME
    ; demands fresh current OWNER/SPECIAL intent at every physical write retry.
    mov rdi, [rel sc_dest + sc_token.mount]
    lea rsi, [rel sc_partpath]
    lea rdx, [rel sc_dstpath]
    xor ecx, ecx
    mov r8d, FS_MUT_RENAME
    mov rax, [rel sc_dest + sc_token.ops]
    call [rax + fs_ops.mutate_path]
    test rax, rax
    jnz .failed
    ; NT keeps its reference across rename. exFAT's exact path/set trace
    ; deliberately changes. Only a successful original guarded native RENAME
    ; may bind that new trace, before the same full identity/read checks below.
    cmp qword [rel sc_dest + sc_token.kind], 4
    jne .rename_bound
    lea rdi, [rel sc_dest]
    lea rsi, [rel sc_dstpath]
    mov edx, [rel sc_dstlen]
    lea rcx, [rel sc_dest_id]
    call sc_stat
    cmp rax, [rel sc_length]
    jne .failed
.rename_bound:
    mov byte [rel sc_partial_state], 0
    mov dword [rbx + fs_copy_job.state], FS_JOB_VERIFYING
.published:
    cmp dword [rbx + fs_copy_job.state], FS_JOB_VERIFYING
    jne .badop
    cmp byte [rel sc_failed], 0
    jne .failed
    cmp byte [rel sc_dest_bound], 1
    jne .failed
    call sc_check_source
    test rax, rax
    jnz .failed
    lea rdi, [rel sc_dest]
    lea rsi, [rel sc_dstpath]
    mov edx, [rel sc_dstlen]
    lea rcx, [rel sc_dest_id]
    call sc_check_file
    test rax, rax
    jnz .failed
    ; CANCEL after synchronous commit is honestly too late. It reaches DONE
    ; only with the same independent readback, never CANCELLED or a rollback.
    mov rax, [rel sc_length]
    mov [rbx + fs_copy_job.done], rax
    mov dword [rbx + fs_copy_job.state], FS_JOB_DONE
    xor eax, eax                    ; VFS computes declared FLUSH durability
    pop rbx
    ret
.failed:
    mov dword [rbx + fs_copy_job.error], SC_E_CHANGED
    mov dword [rbx + fs_copy_job.state], FS_JOB_FAILED
    mov dword [rbx + fs_copy_job.durable], FS_DUR_UNCERTAIN
    xor eax, eax
    pop rbx
    ret
.badop:
    pop rbx
sc_no:
    mov rax, -1
    ret

; Private sibling name derives from the full upcoming nonwrapping VFS job ID.
; It is still a normal supported FSW*.TST file, never an ownership marker.
sc_private_path:
    mov ecx, [rel sc_dstlen]
    lea rsi, [rel sc_dstpath]
.slash:
    dec ecx
    cmp byte [rsi + rcx], '/'
    jne .slash
    inc ecx
    cmp ecx, NT_MUT_PATH_MAX - 24
    ja sc_no
    mov [rel sc_partlen], ecx
    lea rdi, [rel sc_partpath]
    lea rsi, [rel sc_dstpath]
    mov edx, ecx
    sub rsp, 8
    call memcpy
    add rsp, 8
    mov ecx, [rel sc_partlen]
    lea rdi, [rel sc_partpath]
    lea rdi, [rdi + rcx]
    mov dword [rdi], 'FSWP'
    mov rax, [rel vfs_partial_record + fs_copy_partial.id]
    mov ecx, 16
    cmp qword [rel sc_dest + sc_token.kind], 4
    jne .hex
    ; Native exFAT CREATE/RENAME accepts 8.3 only. Represent the ENTIRE
    ; admitted ID, never truncate it or weaken that writer's name grammar.
    test rax, rax
    jz sc_no
    cmp rax, SC_EXF_HOLD_MAX
    ja sc_no
    shl rax, 48
    mov ecx, 4
.hex:
    rol rax, 4
    mov edx, eax
    and edx, 15
    add dl, '0'
    cmp dl, '9'
    jbe .digit
    add dl, 7
.digit:
    mov [rdi + 4], dl
    inc rdi
    loop .hex
    mov dword [rdi + 4], '.TST'
    mov byte [rdi + 8], 0
    mov eax, 24
    cmp qword [rel sc_dest + sc_token.kind], 4
    jne .length
    mov eax, 12
.length:
    add [rel sc_partlen], eax
    xor eax, eax
    ret

; Absolute bounded Z path -> length/-1. Native mutation enforces its own
; scratch spelling and ordinary-parent profile too; no truncated/aliased path.
sc_path:
    test rsi, rsi
    jz sc_no
    cmp byte [rsi], '/'
    jne sc_no
    xor ecx, ecx
.loop:
    mov al, [rsi + rcx]
    mov [rdi + rcx], al
    test al, al
    jz .end
    cmp al, 0x20
    jb sc_no
    cmp al, 0x7f
    jae sc_no
    cmp al, '\'
    je sc_no
    cmp al, ':'
    je sc_no
    inc ecx
    cmp ecx, SC_MAX
    jb .loop
    jmp sc_no
.end:
    cmp ecx, 1
    jbe sc_no
    mov eax, ecx
    ret

; Snapshot only pure state. Unknown/foreign descriptors have no admission.
; Token geometry excludes mutable caches, authority, journal and namespace
; state; file tokens below bind the namespace/file identity separately.
sc_snapshot:                          ; RDI=mount, RSI=token ->0/-1
    push rbx
    push rbp
    push r12
    push r13
    push r14
    mov rbx, rdi
    mov rbp, rsi
    test rbx, rbx
    jz .bad
    mov rdi, rbp
    xor esi, esi
    mov edx, sc_token_size
    call memset
    mov [rbp + sc_token.mount], rbx
    mov r12, [rbx + fsmount.ops]
    mov r13, [rbx + fsmount.priv]
    test r12, r12
    jz .bad
    test r13, r13
    jz .bad
    mov [rbp + sc_token.ops], r12
    mov [rbp + sc_token.ctx], r13
    lea rax, [rel nt_ops]
    cmp r12, rax
    je .nt
    lea rax, [rel ext_ops]
    cmp r12, rax
    je .ext
    lea rax, [rel exf_ops]
    cmp r12, rax
    je .exfat
    ; New copy source/destination uses only the explicitly admitted FAT
    ; scratch descriptor. Existing legacy FAT copy/read adapters stay intact.
    lea rax, [rel fd_scratch_ops]
    lea rdx, [rel fd_scratch_ctx]
    cmp r12, rax
    jne .bad
.fatctx:
    cmp r13, rdx
    jne .bad
    cmp dword [r13 + FD_MOUNTED], 1
    jne .bad
    cmp dword [r13 + FD_VOLUME_ID], 0
    je .bad
    mov qword [rbp + sc_token.kind], 2
    lea rdi, [rbp + sc_token.native]
    mov rsi, r13
    mov edx, 80
    call memcpy
    mov eax, [r13 + FD_VOLUME_ID]
    mov [rbp + sc_token.native + 80], eax
    lea rdi, [rbp + sc_token.native + 88]
    lea rsi, [r13 + FD_DISK_GUID]
    mov edx, 32                       ; full disk/partition GUIDs, no lookup cache
    call memcpy
    mov r14, [r13 + FD_DEV]
    mov rax, [r13 + FD_MOUNT_GEN]
    mov [rbp + sc_token.native + 120], rax
    jmp .device
.nt:
    lea rax, [rel nt_ctx]
    cmp r13, rax
    jne .bad
    cmp byte [rel nt_mounted], 1
    jne .bad
    cmp qword [rel nt_serial], 0
    je .bad
    mov qword [rbp + sc_token.kind], 1
    lea r8, [rel nt_dev]
    lea r9, [rel nt_src_fields]
    lea r10, [rbp + sc_token.native]
    mov ecx, NT_SRC_FIELDS
.fields:
    movsxd rdx, dword [r9]
    mov eax, [r8 + rdx]
    cmp dword [r9 + 4], 4
    je .save
    mov rax, [r8 + rdx]
.save:
    mov [r10], rax
    add r9, 8
    add r10, 8
    loop .fields
    lea rdi, [rbp + sc_token.native + 128]
    lea rsi, [rel nt_mft_runs]
    mov edx, NT_MAX_RUNS * 16
    call memcpy
    lea rdi, [rbp + sc_token.native + 1152]
    lea rsi, [rel nt_boot_buf]
    mov edx, 512
    call memcpy
    mov r14, [rel nt_dev]
    mov rax, [rel nt_mount_generation]
    jmp .device
.ext:
    cmp dword [r13 + ext_ctx.mounted], 1
    jne .bad
    mov eax, [r13 + ext_ctx.kind]
    cmp eax, 3
    je .extok
    cmp eax, 4
    jne .bad
.extok:
    mov qword [rbp + sc_token.kind], 3
    lea rdi, [rbp + sc_token.native]
    mov rsi, r13
    mov edx, ext_ctx.meta_buf          ; immutable qword geometry prefix
    call memcpy
    lea rdi, [rbp + sc_token.native + 64]
    lea rsi, [r13 + ext_ctx.name]
    mov edx, ext_ctx.found_ino - ext_ctx.name
    call memcpy
    lea rdi, [rbp + sc_token.native + 160]
    lea rsi, [r13 + ext_ctx.read_generation]
    mov edx, 32                       ; full UUID + mount epoch
    call memcpy
    mov rax, [r13 + ext_ctx.read_uuid]
    or rax, [r13 + ext_ctx.read_uuid + 8]
    jz .bad
    mov r14, [r13 + ext_ctx.dev]
    mov rax, [r13 + ext_ctx.read_generation]
    jmp .device
.exfat:
    mov rdi, rbx
    lea rsi, [rbp + sc_token.native]
    call exfat_disk_copy_snapshot    ; original immutable metadata BEFORE pointers
    test rax, rax
    jz .bad
    mov r14, rax
    mov qword [rbp + sc_token.kind], 4
    mov rax, rdx
.device:
    test r14, r14
    jz .bad
    test rax, rax
    jz .bad
    mov rdx, [r14 + dev.info]
    test rdx, rdx
    jz .bad
    cmp rax, [rdx + blk_info.media_generation]
    jne .bad
    cmp dword [rdx + blk_info.sector_size], 512
    jne .bad
    mov [rbp + sc_token.dev], r14
    mov [rbp + sc_token.info], rdx
    mov rax, [r14 + dev.ops]
    mov [rbp + sc_token.devops], rax
    mov rax, [r14 + dev.priv]
    mov [rbp + sc_token.devpriv], rax
    lea rdi, [rbp + sc_token.blk]
    mov rsi, rdx
    mov edx, blk_info_size
    call memcpy
    lea rdi, [rbp + sc_token.opstable]
    mov rsi, r12
    mov edx, fs_ops_size
    call memcpy
    xor eax, eax
    jmp .out
.bad:
    mov rax, -1
.out:
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

sc_current:                            ; RDI=retained token ->0/-1, no I/O
    push rbx
    mov rbx, rdi
    mov rdi, [rbx + sc_token.mount]
    lea rsi, [rel sc_now]
    call sc_snapshot
    test rax, rax
    jnz .out
    mov rdi, rbx
    lea rsi, [rel sc_now]
    mov edx, sc_token_size
    call memcmp
.out:
    pop rbx
    ret

; Retain existing read-only per-transfer guards, never a write capability.
; There is one VFS job; these source-reader tokens cannot overlap another copy.
sc_bind_reads:
    push rbx
    push r12
    mov byte [rel ext_cp_guard_active], 0
    mov qword [rel nt_src_reading], 0
    lea rbx, [rel sc_source]
    cmp qword [rbx + sc_token.kind], 1
    je .nt
    lea rbx, [rel sc_dest]
    cmp qword [rbx + sc_token.kind], 1
    jne .ext
.nt:
    mov rdi, [rbx + sc_token.mount]
    call ntfs_disk_source_bind
    test rax, rax
    jnz .out
.ext:
    lea rbx, [rel sc_source]
    cmp qword [rbx + sc_token.kind], 3
    jne .fat
    mov rax, [rbx + sc_token.mount]
    mov [rel ext_cp_source_mount], rax
    mov byte [rel ext_cp_source_kind], 0
    call ext_cp_bind_source
    test rax, rax
    jnz .out
.fat:
    mov qword [rel sc_fat_token], 0
    lea rbx, [rel sc_source]
    cmp qword [rbx + sc_token.kind], 2
    je .fat_bind
    lea rbx, [rel sc_dest]
    cmp qword [rbx + sc_token.kind], 2
    jne .exfat
.fat_bind:
    mov [rel sc_fat_token], rbx
    mov rdi, rbx
    call sc_fat_read_bpb
    test rax, rax
    jnz .out
    mov r12, [rbx + sc_token.ctx]
    ; The first fresh BPB must agree with the mounted immutable geometry.
    cmp word [rel sc_bpb_now + 510], 0xaa55
    jne .bad
    cmp word [rel sc_bpb_now + 11], 512
    jne .bad
    movzx eax, byte [rel sc_bpb_now + 13]
    cmp eax, [r12 + FD_SPC]
    jne .bad
    movzx eax, byte [rel sc_bpb_now + 16]
    cmp eax, [r12 + FD_NFATS]
    jne .bad
    mov eax, [rel sc_bpb_now + 32]
    cmp rax, [r12 + FD_TOTAL_SECTORS]
    jne .bad
    mov eax, [rel sc_bpb_now + 36]
    cmp rax, [r12 + FD_FAT_SECTORS]
    jne .bad
    mov ecx, [r12 + FD_NFATS]
    imul rax, rcx
    movzx edx, word [rel sc_bpb_now + 14]
    add rdx, [r12 + FD_PART_LBA]
    jc .bad
    cmp rdx, [r12 + FD_FAT_LBA]
    jne .bad
    add rax, rdx
    jc .bad
    cmp rax, [r12 + FD_DATA_LBA]
    jne .bad
    mov eax, [rel sc_bpb_now + 44]
    cmp eax, [r12 + FD_ROOT_CLUSTER]
    jne .bad
    mov eax, [rel sc_bpb_now + 67]
    cmp eax, [r12 + FD_VOLUME_ID]
    jne .bad
    lea rdi, [rel sc_bpb_saved]
    lea rsi, [rel sc_bpb_now]
    mov edx, 512
    call memcpy
.exfat:
    lea rbx, [rel sc_source]
    cmp qword [rbx + sc_token.kind], 4
    je .exfat_source
    lea rbx, [rel sc_dest]
    cmp qword [rbx + sc_token.kind], 4
    jne .ok
    jmp .exfat_bind
.exfat_source:
    cmp qword [rel sc_dest + sc_token.kind], 4
    jne .exfat_bind
    mov rax, [rbx + sc_token.mount]
    cmp rax, [rel sc_dest + sc_token.mount]
    jne .bad                        ; one original exFAT reader context per job
.exfat_bind:
    mov rdi, [rbx + sc_token.mount]
    call exfat_disk_source_bind
    test rax, rax
    jnz .out
.ok:
    xor eax, eax
    jmp .out
.bad:
    mov rax, -1
.out:
    pop r12
    pop rbx
    ret

sc_fat_read_bpb:                       ; RDI=token, actual custody/bounds
    push rbx
    mov rbx, rdi
    call sc_current
    test rax, rax
    jnz .out
    mov rdi, [rbx + sc_token.ctx]
    mov rsi, [rdi + FD_PART_LBA]
    mov edx, 1
    lea rcx, [rel sc_bpb_now]
    call fd_read_sectors
    test rax, rax
    jnz .out
    mov rdi, rbx
    call sc_current
.out:
    pop rbx
    ret

sc_io_begin:                           ; RDI=token, fresh read caches/media
    push rbx
    push r12
    mov rbx, rdi
    call sc_current
    test rax, rax
    jnz .out
    cmp qword [rbx + sc_token.kind], 1
    jne .ext
    call ntfs_disk_source_current
    test rax, rax
    jnz .out
    mov qword [rel nt_src_reading], 1
    jmp .ok
.ext:
    cmp qword [rbx + sc_token.kind], 3
    jne .fat
    mov r12, [rbx + sc_token.ctx]
    call ext_cp_source_current
    test rax, rax
    jnz .out
    mov byte [rel ext_cp_guard_active], 1
    jmp .ok
.fat:
    cmp qword [rbx + sc_token.kind], 4
    jne .fat_read
    call exfat_disk_copy_read_begin
    test rax, rax
    jnz .out
    jmp .ok
.fat_read:
    mov rdi, rbx
    call sc_fat_read_bpb
    test rax, rax
    jnz .out
    lea rdi, [rel sc_bpb_saved]
    lea rsi, [rel sc_bpb_now]
    mov edx, 512
    call memcmp
    test rax, rax
    jnz .out
    mov rdi, [rbx + sc_token.ctx]
    call fd_read_cache_drop
.ok:
    xor eax, eax
.out:
    pop r12
    pop rbx
    ret

sc_io_end:                             ; always disable scoped read guards
    mov qword [rel nt_src_reading], 0
    mov qword [rel exf_src_reading], 0
    mov byte [rel ext_cp_guard_active], 0
    call sc_io_begin                   ; fresh BPB/UUID again after callback
    push rax
    mov qword [rel nt_src_reading], 0
    mov qword [rel exf_src_reading], 0
    mov byte [rel ext_cp_guard_active], 0
    pop rax
    ret

; Stat/read compare callbacks are strictly read-only and bracketed by pure
; token checks. Native readers retain all physical bounds/refusal behavior.
; Full padded identities: NTFS reference, FAT entry/namespace, ext inode, or
; original exFAT ordered ancestor/entry/link transcript (overflow refuses).
sc_stat:                               ; token,path,len,id ->size/-1
    push rbx
    push rbp
    push r12
    push r13
    push r14
    mov rbx, rdi
    mov rbp, rsi
    mov r12d, edx
    mov r13, rcx
    mov rdi, r13
    xor esi, esi
    mov edx, SC_ID_BYTES
    call memset
    mov rdi, rbx
    call sc_io_begin
    test rax, rax
    jnz .bad
    cmp qword [rbx + sc_token.kind], 4
    jne .ordinary
    mov rsi, rbp
    mov edx, r12d
    mov r8, r13
    call exfat_disk_copy_stat
    mov r14, rax
    mov rdi, rbx
    call sc_io_end
    test rax, rax
    jnz .bad
    cmp r14, SC_MAX
    ja .bad
    jmp .check
.ordinary:
    lea rdi, [rel sc_statbuf]
    xor esi, esi
    mov edx, fs_stat_size
    call memset
    mov rdi, [rbx + sc_token.mount]
    mov rsi, rbp
    mov edx, r12d
    lea rcx, [rel sc_statbuf]
    mov rax, [rbx + sc_token.ops]
    call [rax + fs_ops.stat_path]
    push rax
    mov rdi, rbx
    call sc_io_end
    pop rdx
    or rax, rdx
    jnz .bad
    cmp dword [rel sc_statbuf + fs_stat.reserved], 0
    jne .bad
    mov r14, [rel sc_statbuf + fs_stat.size]
    cmp r14, SC_MAX
    ja .bad
    mov rdi, r13
    xor esi, esi
    mov edx, SC_ID_BYTES
    call memset
    cmp qword [rbx + sc_token.kind], 1
    jne .fat
    mov rax, [rel nt_found_ref]
    mov [r13], rax
    movzx eax, word [rel nt_found_sequence]
    mov [r13 + 8], rax
    jmp .check
.fat:
    cmp qword [rbx + sc_token.kind], 2
    jne .ext
    mov rdi, r13
    lea rsi, [rel fd_source_entry]
    mov edx, 32
    call memcpy
    mov rax, [rbx + sc_token.ctx]
    mov rax, [rax + FD_NAMESPACE_GEN]
    mov [r13 + 32], rax
    mov rax, [rel fd_found_dir_lba]
    mov [r13 + 40], rax
    mov eax, [rel fd_found_dir_off]
    mov [r13 + 48], rax
    jmp .check
.ext:
    mov rdi, r13
    mov rsi, [rbx + sc_token.ctx]
    add rsi, ext_ctx.inode
    mov edx, EXT_SLOT
    call memcpy
.check:
    mov rdi, rbx
    call sc_current
    test rax, rax
    jnz .bad
    mov rax, r14
    jmp .out
.bad:
    mov rax, -1
.out:
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

sc_read:                               ; token,path,len,buffer ->0/-1
    push rbx
    push rbp
    push r12
    push r13
    mov rbx, rdi
    mov rbp, rsi
    mov r12d, edx
    mov r13, rcx
    call sc_io_begin
    test rax, rax
    jnz .bad
    mov rdi, [rbx + sc_token.mount]
    mov rsi, rbp
    mov edx, r12d
    xor ecx, ecx
    mov r8, r13
    mov r9, [rel sc_length]
    mov rax, [rbx + sc_token.ops]
    call [rax + fs_ops.read_at_path]
    mov rbp, rax
    mov rdi, rbx
    call sc_io_end
    test rax, rax
    jnz .bad
    cmp rbp, [rel sc_length]
    jne .bad
    jmp .out
.bad:
    mov rax, -1
.out:
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

sc_check_source:
    lea rdi, [rel sc_source]
    lea rsi, [rel sc_srcpath]
    mov edx, [rel sc_srclen]
    lea rcx, [rel sc_source_id]
    ; fall through
sc_check_file:                         ; same sc_stat ABI ->0/-1
    push rbx
    push rbp
    push r12
    push r13
    mov rbx, rdi
    mov rbp, rsi
    mov r12d, edx
    mov r13, rcx
    lea rcx, [rel sc_id_now]
    call sc_stat
    cmp rax, [rel sc_length]
    jne .bad
    mov rdi, r13
    lea rsi, [rel sc_id_now]
    mov edx, SC_ID_BYTES
    call memcmp
    test rax, rax
    jnz .bad
    mov rdi, rbx
    mov rsi, rbp
    mov edx, r12d
    lea rcx, [rel sc_check_bytes]
    call sc_read
    test rax, rax
    jnz .bad
    lea rdi, [rel sc_bytes]
    lea rsi, [rel sc_check_bytes]
    mov rdx, [rel sc_length]
    call memcmp
    test rax, rax
    jnz .bad
    ; Re-resolve after reading too (same bytes from a substituted file do not
    ; prove the original file). No retained caches can establish completion.
    mov rdi, rbx
    mov rsi, rbp
    mov edx, r12d
    lea rcx, [rel sc_id_now]
    call sc_stat
    cmp rax, [rel sc_length]
    jne .bad
    mov rdi, r13
    lea rsi, [rel sc_id_now]
    mov edx, SC_ID_BYTES
    call memcmp
    jmp .out
.bad:
    mov rax, -1
.out:
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

%macro WDATA_BSS_fs_small_copy 0
alignb 8
sc_hold: resd 1
sc_resume_op: resd 1
sc_partial_state: resb 1
alignb 8
sc_job: resq 1
sc_partlen: resd 1
sc_partpath: resb SC_MAX
sc_fat_token: resq 1
sc_bpb_saved: resb 512
sc_bpb_now: resb 512
sc_length: resq 1
sc_srclen: resd 1
sc_dstlen: resd 1
sc_failed: resb 1
sc_dest_bound: resb 1
alignb 8
sc_source: resb sc_token_size
sc_dest: resb sc_token_size
sc_now: resb sc_token_size
sc_srcpath: resb SC_MAX
sc_dstpath: resb SC_MAX
sc_bytes: resb SC_MAX
sc_check_bytes: resb SC_MAX
sc_statbuf: resb fs_stat_size
sc_source_id: resb SC_ID_BYTES
sc_dest_id: resb SC_ID_BYTES
sc_id_now: resb SC_ID_BYTES
%endmacro
WDATA_BSS_DEFER WDATA_BSS_fs_small_copy
