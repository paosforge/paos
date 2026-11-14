;; MODULE fs/ext4_copy
;; LAYER 4
;; EXPORTS ext_op_copy, ext_op_copy_between, ext_cp_guard_read, ext_cp_guard_fat_read
;; IMPORTS fs/exfat_disk, fs/ntfs_disk, fs/fat32_disk, fs/ext4_disk, fs/ext4_write, fs/ext4_ns, fs/vfs, core/lib/mem, core/heap
;; CAPS CAP_BLOCK_READ, CAP_BLOCK_WRITE
;; OWNER saga:rcq20_filesystems
; ============================================================================
; fs/ext4_copy.asm — RCQ-20 copy job for armed ext4 mounts (fs_ops.copy; the
; VFS job contract in fs/vfs: BEGIN / STEP / CANCEL, one job at a time).
;
; Same-volume files/trees, plus explicitly bound ext4/FAT32/NTFS/exFAT regular sources on distinct devices.
; Every byte moves through the E2a/E2b transaction engine, so
; each STEP is at most one bounded journaled transaction under the per-transaction
; storage gate, and a crash at any point leaves an e2fsck-clean volume.
;
; TREE=1 uses this same per-file engine under one shared job/window. BEGIN only
; validates source/destination and ancestry. Each STEP scans a bounded directory
; slice, makes one directory, or advances one journaled file phase. Directory
; byte cursors run to the real end, independent of Explorer's listing capacity.
; Depth is bounded by FS_TREE_DEPTH_MAX. Unsupported nodes are refused, never
; followed. DONE/FILES count committed children; cancellation/failure preserves
; them and reclaims only the current marked partial. TOTAL is unknown until the
; walk ends. A same-volume ext4 source changed mid-copy is recopied once after
; reclaim; a second change is listed. Cancel/stranded partials never start a recopy.
; There is no whole-tree atomicity or restart/resume claim.
;
;   BEGIN   (file) checks only, writes nothing. The source must be a regular file and the
;           destination must not exist (RCQ-20 S4 keep-both: BEGIN first moves the
;           destination to the first free "stem (k).ext", k 2..9, see ext_cp_pick;
;           everything below then applies to that name). The source is snapshotted (inode number + a
;           crc32c over its inode with atime and the checksum fields cleared: size,
;           times, flags and the extent root, which copy-on-write writes always
;           change). The copy is built as <dst dir>/.paoscopy-<tag>, tag =
;           crc32c(dst leaf) | 1. A file there with that marker (i_generation = tag)
;           is a stale partial of an earlier attempt and is reclaimed by SETUP; any
;           other file there (or the source itself) refuses EXISTS.
;   STEP    SETUP:  a stale partial loses a piece per step (truncate), then is
;                   deleted; then the new partial is created in one transaction with
;                   the source's mode and i_generation = tag (the marker). The piece
;                   starts at EXT_CP_TRIM and halves whenever a step's trim or
;                   delete is refused TOOBIG (too many groups for one transaction;
;                   refused before any write): that step writes nothing and the
;                   next one tries the smaller piece. A step never chains.
;           COPY:   (a chunk whose source blocks are all holes is skipped: the copy keeps
;                   the source's holes; a trailing hole costs one truncate-grow step)
;                   re-check the source snapshot and the partial (inode, marker,
;                   size), read <= EXT_CP_STEP bytes, append them (one transaction).
;           VERIFY: re-check, then compare <= EXT_CP_STEP bytes of the committed
;                   partial with the source.
;           COMMIT: the step after the last verify renames the partial onto the
;                   destination (one transaction, no replace): the destination
;                   appears complete or not at all.
;           RECLAIM (cancel or failure): the marked partial is removed (truncated
;                   in pieces first when large, as SETUP); a file that is no
;                   longer ours is left alone.
;   CANCEL  COPY/VERIFY -> RECLAIM, state CANCELLING.
;
; Storage authority (SEC-S6 job window). BEGIN runs inside the owner's request
; and takes a job window over the partition (ext_w_job_open: permitted only
; where the per-transaction gate would permit under that request's intent); a
; refusal refuses BEGIN with DENIED. Each STEP runs from the idle tick: it
; first checks the window is this mount's, on the same medium
; (ext_w_job_step_begin, else DENIED and the window closes), and its one
; transaction presents the window for exactly the blocks it writes. Every step
; exit drops the step's request grant (ext_w_job_step_done); DONE, CANCELLED,
; FAILED, a disarm and the next BEGIN end the window (ext_w_job_close).
;
; Restart: the job lives in memory only. After a crash or reboot the marked
; partial is all that remains, and the next BEGIN for the same destination
; removes it (RCQ-20 S3: deleting it records FS_REC_RECLAIMED, whether SETUP or
; the retry's own cancel/failure reclaim deletes it; there is no mount-time
; scan). Nothing unmarked is ever deleted.
; ============================================================================

EXT_CP_STEP          equ 262144              ; bytes copied or verified per STEP (one journaled append)
EXT_CP_TRIM          equ 67108864            ; reclaim truncates a larger partial in pieces of at most this
EXT_CP_HOLE_MAX      equ 1073741824          ; a COPY step skips at most this much of a source hole
EXT_CP_HOLE_MAPS     equ 64                  ; and follows the hole past its chunk with at most this many ext_map calls
EXT_CP_TAG_SEED      equ 0x50414F53          ; "PAOS"
EXT_E_SOURCE_CHANGED equ 17                  ; the source changed while it was being copied
EXT_CP_IDLE          equ 0
EXT_CP_COPY          equ 1
EXT_CP_VERIFY        equ 2
EXT_CP_RECLAIM       equ 3
EXT_CP_SETUP         equ 4
EXT_CP_ORPHAN        equ 6                   ; E2r: the committed copy replaced a file too large for the commit:
                                             ; its blocks are freed off the orphan list, a piece per step
EXT_CP_COMPARE       equ 5                   ; smart copy C: an existing same-size destination file read
                                             ;   against the source; nothing created until they differ

; ext_op_copy(RDI=fsmount, RSI=src Z path, RDX=dst Z path, ECX=FS_COPY_*,
;   R8=fs_copy_job*) -> RAX 0 / -1 (BEGIN only: ext4_disk_last_error says why)
ext_op_copy:
    cmp  ecx, FS_COPY_STEP
    je   .step
    cmp  ecx, FS_COPY_CANCEL
    je   .cancel
    cmp  ecx, FS_COPY_BEGIN
    je   .begin
    cmp  ecx, FS_COPY_BEGIN_CARRIED
    jne  .unsupported
.begin:
    mov  byte [rel ext_cp_guard_active], 0
    mov  qword [rel ext_cp_incoming], 0
    sub  rsp, 8
    call ext_tree_forget                 ; a dropped VFS job never lends its resources
    add  rsp, 8
    mov  byte [rel ext_cp_carried], 0
    cmp  ecx, FS_COPY_BEGIN
    je   .selected
    cmp  ecx, FS_COPY_BEGIN_CARRIED      ; RCQ-20 S5c: vfs_copy_dequeue only, for an ext4 record
    jne  .unsupported
    mov  byte [rel ext_cp_carried], 1    ; the same BEGIN; only its window comes from the job's carry
.selected:
    test r9d, FS_COPY_TREE
    jnz  ext_tree_begin
    jmp  ext_cp_begin
.step:
    cmp  dword [rel ext_tree_active], 0
    jne  ext_tree_step
    jmp  ext_cp_step
.cancel:
    cmp  dword [rel ext_tree_active], 0
    jne  ext_tree_cancel
    jmp  ext_cp_cancel
.unsupported:
    mov  dword [rel ext4_disk_last_error], EXT_E_UNSUPPORTED
    mov  rax, -1
    ret

; Explicit ext3/ext4/FAT32/NTFS/exFAT regular-file copy on DISTINCT devices, plus
; bounded native FAT32 trees. Source is read-only; only destination owner
; arm/request opens a write window. No cross-volume carry or source mutation.
; ext3 uses the same qualified journal writer and indirect-block mapping as
; same-volume copy. Kind admission does not replace its writer/job guards.
ext_op_copy_between:
    mov  dword [rel ext4_disk_last_error], EXT_E_UNSUPPORTED
    cmp  ecx, FS_COPY_BEGIN
    jne  .bad
    mov  eax, r9d
    and  eax, ~(FS_CMODE_MASK | FS_COPY_TREE)
    jnz  .bad
    mov  eax, r9d
    and  eax, FS_CMODE_MASK
    cmp  eax, FS_CMODE_KEEPBOTH | FS_CMODE_SKIPSAME
    ja   .bad
    lea  rax, [rel ext_ops]
    cmp  [rdi + fsmount.ops], rax
    jne  .bad
    mov  r11, [rdi + fsmount.priv]
    test r11, r11
    jz   .bad
    cmp  dword [r11 + ext_ctx.kind], 3
    je   .destination_kind
    cmp  dword [r11 + ext_ctx.kind], 4
    jne  .bad
.destination_kind:
    cmp  [r10 + fsmount.ops], rax
    jne  .fat_source
    test r9d, FS_COPY_TREE
    jnz  .bad                           ; cross trees require native FAT32/NTFS
    mov  rax, [r10 + fsmount.priv]
    test rax, rax
    jz   .bad
    cmp  dword [rax + ext_ctx.mounted], 1
    jne  .bad
    cmp  dword [rax + ext_ctx.kind], 3
    je   .source_kind
    cmp  dword [rax + ext_ctx.kind], 4
    jne  .bad
.source_kind:
    mov  rax, [rax + ext_ctx.dev]
    jmp  .canonical
.fat_source:
    push rdi
    mov  rdi, r10
    call fat32_disk_source_device         ; pure native table/context admission
    pop  rdi
    test rax, rax
    jnz  .canonical
    push rdi
    mov  rdi, r10
    call ntfs_disk_source_device          ; exact native table/context; no display-type trust
    pop  rdi
    test rax, rax
    jnz  .canonical
    push rdi
    mov  rdi, r10
    call exfat_disk_source_device
    pop  rdi
    test rax, rax
    jz   .bad
    test r9d, FS_COPY_TREE
    jnz  .bad                           ; exFAT adapter remains regular-file only
.canonical:
    ; Reject another handle on the same canonical backend route/unit or info.
    ; Names and partition offsets cannot establish a distinct source device.
    test rax, rax
    jz   .bad
    mov  r11, [rdi + fsmount.priv]
    mov  r11, [r11 + ext_ctx.dev]
    test r11, r11
    jz   .bad
    push rdx
    push rcx
    mov  rdx, [rax + dev.info]
    test rdx, rdx
    jz   .alias                          ; malformed source has no canonical unit
    cmp  rdx, [r11 + dev.info]
    je   .alias
    mov  rcx, [rax + dev.ops]
    test rcx, rcx
    jz   .distinct
    cmp  rcx, [r11 + dev.ops]
    jne  .distinct
    mov  rcx, [rax + dev.priv]
    cmp  rcx, [r11 + dev.priv]
    jne  .distinct
    mov  ecx, [rdx + blk_info.unit]
    mov  rdx, [r11 + dev.info]
    test rdx, rdx
    jz   .alias
    cmp  ecx, [rdx + blk_info.unit]
    jne  .distinct
.alias:
    pop  rcx
    pop  rdx
    jmp  .bad
.distinct:
    pop  rcx
    pop  rdx
.device:
    mov  r11, [rdi + fsmount.priv]
    cmp  rax, [r11 + ext_ctx.dev]
    je   .bad                            ; no same-medium aliases, even disjoint partitions
    ; Ordinary BEGIN forgets any dropped tree too; keep its register ABI.
    push r10
    call ext_tree_forget
    pop  r10
    mov  [rel ext_cp_incoming], r10
    mov  byte [rel ext_cp_carried], 0
    test r9d, FS_COPY_TREE
    jz   ext_cp_begin
    mov  dword [rel ext_tree_source_kind], 1
    push rdi
    mov  rdi, r10
    call ntfs_disk_source_device
    pop  rdi
    test rax, rax
    jz   .tree_kind
    mov  dword [rel ext_tree_source_kind], 2
.tree_kind:
    jmp  ext_tree_begin
.bad:
    mov  rax, -1
    ret

; ---------------------------------------------------------------- BEGIN
ext_cp_begin:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8
    mov  rbp, rdi                        ; fsmount
    mov  r13, rsi
    mov  r14, rdx
    mov  rbx, r8                         ; job
    mov  rax, [rel ext_cp_incoming]
    mov  [rel ext_cp_source_mount], rax
    mov  byte [rel ext_cp_source_kind], 0
    mov byte [rel ext_cp_hold_partial], 0
    test r9d, FS_COPY_HOLD_PARTIAL
    jz .partial_mode
    cmp r9d, FS_COPY_HOLD_PARTIAL
    jne .fail
    cmp rbx, [rel vfs_partial_job]
    jne .fail
    cmp qword [rel vfs_partial_record + fs_copy_partial.stage], 1
    jne .fail
    mov byte [rel ext_cp_hold_partial], 1
    and r9d, ~FS_COPY_HOLD_PARTIAL
.partial_mode:
    mov  [rel ext_cp_policy], r9d        ; FS_CMODE_*
    lea  rax, [rel ext_cp_policy]
    mov  [rel vfs_copy_policy_ptr], rax  ; E2: an answer reaches this job's decisions from here
    mov  dword [rel ext_cp_kept], 0      ; a refuse job
    mov  byte [rel ext_cp_cmp_on], 0     ; smart copy C
    mov  byte [rel ext_cp_cmp_refused], 0
    mov  dword [rel ext_cp_victim], 0    ; E2r: set only when an older file is to be replaced
    mov  dword [rel vfs_copy_replace_verdict], -1
    cmp  dword [rel ext_tree_child], 0
    jne  .kept_window
    call ext_w_job_close                 ; no job is live: a window left by a dropped one ends
.kept_window:
    cmp  dword [rel ext_cp_phase], EXT_CP_IDLE
    je   .idle
    ; the VFS starts a job only when none is live, so a non-idle phase is a job it
    ; dropped (vfs_copy_op .lost): forget it
    mov  dword [rel ext_cp_phase], EXT_CP_IDLE
.idle:
    mov  rdi, rbp
    call ext_w_enter                     ; armed and not dead
    test rax, rax
    jz   .fail
    mov  r12, rax
    cmp  qword [rel ext_cp_source_mount], 0
    je   .bound
    call ext_cp_bind_source
    test rax, rax
    jnz  .fail
.bound:
    lea  rdi, [rel ext_cp_src]
    mov  rsi, r13
    call ext_cp_copy_path
    test rax, rax
    js   .fail
    mov  [rel ext_cp_src_len], eax
    lea  rdi, [rel ext_cp_dst]
    mov  rsi, r14
    call ext_cp_copy_path
    test rax, rax
    js   .fail
    mov  [rel ext_cp_dst_len], eax
    test dword [rel ext_cp_policy], FS_CMODE_SKIPSAME
    jz   .policy
    lea  rsi, [rel ext_cp_dst]
    call ext_cp_resolve                  ; smart copy C: an existing regular file there may be compared
    test rax, rax
    jz   .existing
    cmp  dword [rel ext4_disk_last_error], EXT_E_NOTFOUND
    jne  .fail
    jmp  .policy
.existing:
    movzx eax, word [r12 + ext_ctx.inode + EI_MODE]
    and  eax, EXT_S_IFMT
    cmp  eax, EXT_S_IFREG
    jne  .policy                         ; anything else: the conflict the policy decides
    test dword [r12 + ext_ctx.inode + EI_FLAGS], EXT_FL_REFUSED
    jnz  .policy
    mov  eax, [r12 + ext_ctx.inode + EXT_SLOT_INO]
    mov  [rel ext_cp_cmp_ino], eax
    mov  eax, [r12 + ext_ctx.inode + EI_SIZE_LO]
    mov  edx, [r12 + ext_ctx.inode + EI_SIZE_HI]
    shl  rdx, 32
    or   rax, rdx
    mov  [rel ext_cp_cmp_size], rax
    call ext_cp_snapshot
    mov  [rel ext_cp_cmp_snap], eax
    lea  rdi, [rel ext_cp_cmp]
    lea  rsi, [rel ext_cp_dst]
    call ext_cp_copy_path
    mov  [rel ext_cp_cmp_len], eax
    mov  byte [rel ext_cp_cmp_on], 1     ; compared once the source's size is known (.source_ready)
.policy:
    test dword [rel ext_cp_policy], FS_CMODE_KEEPBOTH
    jz   .picked
    call ext_cp_pick                     ; RCQ-20 S4: ext_cp_dst = the first free k-th name
    test rax, rax
    jnz  .fail                           ; a typed refusal or I/O: nothing written
.picked:
    mov  r15d, [rel ext_cp_dst_len]
    ; the destination's last '/': the partial lives in the same directory
    lea  rsi, [rel ext_cp_dst]
    mov  ecx, r15d
.slash:
    dec  ecx
    js   .badpath
    cmp  byte [rsi + rcx], '/'
    jne  .slash
    mov  r13d, ecx                       ; index of the last '/'
    lea  rdi, [rsi + rcx + 1]
    mov  esi, r15d
    sub  esi, ecx
    dec  esi
    jz   .badpath                        ; "/dir/" has no leaf
    mov  edx, EXT_CP_TAG_SEED
    call ext_crc32c
    or   eax, 1
    mov  [rel ext_cp_tag], eax
    lea  eax, [r13d + 1 + 10 + 8]        ; "<dir>/" + ".paoscopy-" + 8 hex
    cmp  eax, EXT_PATH_MAX
    jae  .badpath
    mov  [rel ext_cp_part_len], eax
    lea  rdi, [rel ext_cp_part]
    lea  rsi, [rel ext_cp_dst]
    lea  edx, [r13d + 1]
    call memcpy
    lea  rdi, [rel ext_cp_part]
    lea  rdi, [rdi + r13 + 1]
    lea  rsi, [rel str_ecp_name]
    mov  edx, 10
    call memcpy
    lea  rdi, [rel ext_cp_part]
    lea  rdi, [rdi + r13 + 11]
    mov  eax, [rel ext_cp_tag]
    lea  r8, [rel str_ecp_hex]
    mov  ecx, 8
.hex:
    rol  eax, 4
    mov  edx, eax
    and  edx, 15
    mov  dl, [r8 + rdx]
    mov  [rdi], dl
    inc  rdi
    dec  ecx
    jnz  .hex
    mov  byte [rdi], 0
    ; the source: a regular file, snapshotted
    mov  byte [rel ext_cp_mt_on], 0     ; E2t: no source mtime known yet
    mov  r15, r12                       ; destination context survives source snapshot
    cmp  qword [rel ext_cp_source_mount], 0
    je   .source_ctx
    mov  byte [rel ext_cp_guard_active], 1
    mov  r12, [rel ext_cp_source_ctx]
    call ext_cp_source_current
    test rax, rax
    jnz  .fail
.source_ctx:
    cmp  byte [rel ext_cp_source_kind], 0
    je   .ext_source
    lea  rsi, [rel ext_cp_src]
    mov  edx, [rel ext_cp_src_len]
    mov  ecx, 1                          ; bind a fresh regular-file entry/chain
    cmp  byte [rel ext_cp_source_kind], 3
    je   .exfat_stat
    cmp  byte [rel ext_cp_source_kind], 2
    je   .nt_stat
    call fat32_disk_source_stat
    jmp  .source_stat
.exfat_stat:
    call exfat_disk_source_stat
    jmp  .source_stat
.nt_stat:
    call ntfs_disk_source_stat
.source_stat:
    cmp  rax, -1
    je   .source_changed
    mov  [rel ext_cp_size], rax
    mov  dword [rel ext_cp_mode], 0x81A4  ; new file 0644; foreign mode/ACL are not preserved
    call ext_cp_take_foreign_mt          ; E2t: the mtime is (when the source has one)
    jmp  .source_ready
.source_changed:
    mov  dword [rel ext4_disk_last_error], EXT_E_SOURCE_CHANGED
    jmp  .fail
.ext_source:
    lea  rsi, [rel ext_cp_src]
    call ext_cp_resolve
    test rax, rax
    jnz  .fail
    movzx eax, word [r12 + ext_ctx.inode + EI_MODE]
    mov  ecx, eax
    and  eax, EXT_S_IFMT
    cmp  eax, EXT_S_IFREG
    je   .regular
    mov  ecx, EXT_E_ISDIR
    cmp  eax, EXT_S_IFDIR
    je   .refuse
    mov  ecx, EXT_E_UNSUPPORTED
    jmp  .refuse
.regular:
    and  ecx, 0x0FFF
    or   ecx, 0x8000
    mov  [rel ext_cp_mode], ecx
    mov  eax, [r12 + ext_ctx.inode + EXT_SLOT_INO]
    mov  [rel ext_cp_src_ino], eax
    mov  eax, [r12 + ext_ctx.inode + EI_SIZE_LO]
    mov  edx, [r12 + ext_ctx.inode + EI_SIZE_HI]
    shl  rdx, 32
    or   rax, rdx
    mov  [rel ext_cp_size], rax
    call ext_cp_snapshot
    mov  [rel ext_cp_snap], eax
    call ext_cp_take_ext_mt              ; E2t: i_mtime (+ extra) of the source inode
.source_ready:
    mov  r12, r15                       ; every destination operation uses its own context
    call ext_cp_mt_fit                   ; E2t: a time the destination cannot encode is unknown
    cmp  byte [rel ext_cp_cmp_on], 0
    je   .conflict
    mov  rax, [rel ext_cp_cmp_size]
    cmp  rax, [rel ext_cp_size]
    je   .no_conflict                    ; smart copy C: compared first (keep-both's name picked above)
    mov  byte [rel ext_cp_cmp_on], 0     ; another size: a plain conflict
.conflict:
    ; conflict: the destination must not exist (E2r: or is an older file this copy replaces)
    lea  rsi, [rel ext_cp_dst]
    call ext_cp_resolve
    test rax, rax
    jz   .dst_exists
    cmp  dword [rel ext4_disk_last_error], EXT_E_NOTFOUND
    jne  .fail
.no_conflict:
    ; a partial for this destination: ours (marked) is a stale retry that SETUP
    ; reclaims; anything else (or the source itself) stays and refuses
    mov  dword [rel ext_cp_part_ino], 0
    mov  byte [rel ext_cp_stale], 0
    mov  qword [rel ext_cp_trim], EXT_CP_TRIM
    lea  rsi, [rel ext_cp_part]
    call ext_cp_resolve
    test rax, rax
    jnz  .no_partial
    call ext_cp_is_marked
    jne  .exists
    mov  eax, [r12 + ext_ctx.inode + EXT_SLOT_INO]
    cmp  qword [rel ext_cp_source_mount], 0
    jne  .different_volume
    cmp  eax, [rel ext_cp_src_ino]
    je   .exists                         ; never reclaim the source being copied
.different_volume:
    mov  [rel ext_cp_part_ino], eax      ; the stale partial: SETUP removes it
    mov  byte [rel ext_cp_stale], 1      ; (or the live reclaim, if the retry ends first)
    jmp  .buffer
.no_partial:
    cmp  dword [rel ext4_disk_last_error], EXT_E_NOTFOUND
    jne  .fail
.buffer:
    cmp  qword [rel ext_cp_buf], 0
    jne  .have_buf
    mov  edi, 2 * EXT_CP_STEP
    call kmalloc
    test rax, rax
    jz   .toobig
    mov  [rel ext_cp_buf], rax
.have_buf:
    cmp  dword [rel ext_tree_child], 0
    jne  .window                        ; the parent tree owns the unchanged window
    cmp  byte [rel ext_cp_carried], 0
    jne  .carried
    call ext_w_job_open                  ; the steps' storage window, under THIS request's intent
    test rax, rax
    jnz  .fail
.window:
    xor  eax, eax
    mov  [rel ext_cp_done], rax
    mov  [rel ext_cp_vdone], rax
    mov  [rel ext_cp_psize], rax
    mov  rax, [rel ext_cp_size]
    mov  [rbx + fs_copy_job.total], rax
    mov  qword [rbx + fs_copy_job.done], 0
    mov  dword [rbx + fs_copy_job.error], 0
    mov  dword [rbx + fs_copy_job.state], FS_JOB_RUNNING
    mov  rax, [r12 + ext_ctx.dev]
    mov  [rbx + fs_copy_job.dev], rax    ; the VFS judges durability on this device
    mov  dword [rbx + fs_copy_job.preserved], FS_PRES_EXT4
    cmp  byte [rel ext_cp_source_kind], 0
    je   .preserved
    mov  dword [rbx + fs_copy_job.preserved], FS_PRES_FAT ; data,size,mtime
.preserved:
    mov  eax, [rel ext_cp_kept]
    mov  [rbx + fs_copy_job.kept], eax
    mov  dword [rel ext_cp_phase], EXT_CP_SETUP
    cmp  byte [rel ext_cp_cmp_on], 0
    je   .phased
    mov  dword [rel ext_cp_phase], EXT_CP_COMPARE   ; C: nothing created until a difference
.phased:
    lea  rdi, [rel ext_cp_src]          ; owned top-level or real tree child source path
    lea  rsi, [rel ext_cp_phase]
    mov  edx, (1 << EXT_CP_COPY) | (1 << EXT_CP_VERIFY) | (1 << EXT_CP_SETUP) | (1 << EXT_CP_COMPARE)
    call vfs_copy_item_note
    xor  eax, eax
    jmp  .out
.dst_exists:
    test dword [rel ext_cp_policy], FS_CMODE_REPLACE
    jz   .exists
    call ext_cp_older                    ; E2r: the existing destination against the source's mtime
    cmp  eax, 1
    jne  .not_replaced
    mov  eax, [r12 + ext_ctx.inode + EXT_SLOT_INO]
    mov  [rel ext_cp_victim], eax        ; replaced at the commit, if still this file, unchanged
    call ext_cp_snapshot
    mov  [rel ext_cp_victim_snap], eax
    jmp  .no_conflict
.not_replaced:
    mov  [rel vfs_copy_replace_verdict], eax   ; 0 newer or within 2 s (skipped) / 2 undecided (it asks)
.exists:
    mov  dword [rel vfs_copy_differs], 1 ; E2: an ask item's skip-same answer cannot settle it
    mov  ecx, EXT_E_EXISTS
    jmp  .refuse
.badpath:
    mov  ecx, EXT_E_BADPATH
    jmp  .refuse
.toobig:
    mov  ecx, EXT_E_TOOBIG
    jmp  .refuse
.carried:
    mov  rdi, rbx                        ; RCQ-20 S5c: the window (or owned BEGIN) the job's carry decided,
    call ext_w_job_open_carried          ;   never this tick's request state
    test rax, rax
    jnz  .fail
    jmp  .window
.unsupported:
    mov  ecx, EXT_E_UNSUPPORTED
.refuse:
    mov  [rel ext4_disk_last_error], ecx
.fail:
    mov  byte [rel ext_cp_guard_active], 0
    mov  rax, -1
.out:
    test rax, rax
    jns  .returned
    mov  edi, [rel ext4_disk_last_error]
    mov  esi, FS_PRES_EXT4
    call vfs_copy_begin_failure
.returned:
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; ---------------------------------------------------------------- STEP
ext_cp_step:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8
    mov  rbp, rdi                        ; fsmount (the VFS resolves it per step)
    mov  rbx, r8                         ; job
    cmp  dword [rel ext_cp_phase], EXT_CP_IDLE
    je   .ok
    ; every phase: an armed mount and the job's own window on the same medium
    mov  rdi, rbp
    call ext_w_enter
    test rax, rax
    jz   .no_window
    mov  r12, rax
    call ext_w_job_step_begin
    test rax, rax
    jnz  .no_window
    mov  eax, [rel ext_cp_phase]
    cmp  eax, EXT_CP_SETUP
    je   .setup
    cmp  eax, EXT_CP_COPY
    je   .copy
    cmp  eax, EXT_CP_VERIFY
    je   .verify
    cmp  eax, EXT_CP_RECLAIM
    je   .reclaim
    cmp  eax, EXT_CP_COMPARE
    je   .compare
    cmp  eax, EXT_CP_ORPHAN
    je   .orphan
    jmp  .ok
; Smart copy C: the existing destination file read against the source, a chunk per step;
; nothing is created until they differ. Equal to the end: DONE with SKIPPED_SAME (a tree
; counts it). A difference, or a destination changed meanwhile: keep-both copies under the
; name picked at BEGIN (SETUP on), refuse fails exists (a tree lists it).
.compare:
    call ext_cp_check_source
    test rax, rax
    jnz  .failed
    lea  rsi, [rel ext_cp_cmp]
    call ext_cp_resolve
    test rax, rax
    jz   .cmp_have
    cmp  dword [rel ext4_disk_last_error], EXT_E_NOTFOUND
    je   .differs                        ; gone meanwhile: not equal
    jmp  .failed
.cmp_have:
    mov  eax, [r12 + ext_ctx.inode + EXT_SLOT_INO]
    cmp  eax, [rel ext_cp_cmp_ino]
    jne  .differs
    call ext_cp_snapshot
    cmp  eax, [rel ext_cp_cmp_snap]
    jne  .differs                        ; changed meanwhile: not provably equal
    mov  r13, [rel ext_cp_size]
    sub  r13, [rel ext_cp_vdone]
    jz   .same
    cmp  r13, EXT_CP_STEP
    jbe  .cchunk
    mov  r13d, EXT_CP_STEP
.cchunk:
    lea  rsi, [rel ext_cp_src]
    mov  edx, [rel ext_cp_src_len]
    mov  r14, [rel ext_cp_buf]
    mov  rcx, [rel ext_cp_vdone]
    call ext_cp_read
    test rax, rax
    jnz  .failed_source
    lea  rsi, [rel ext_cp_cmp]
    mov  edx, [rel ext_cp_cmp_len]
    mov  r14, [rel ext_cp_buf]
    add  r14, EXT_CP_STEP
    mov  rcx, [rel ext_cp_vdone]
    call ext_cp_read                     ; the existing file, read on the destination
    test rax, rax
    jnz  .failed
    mov  rdi, [rel ext_cp_buf]
    lea  rsi, [rdi + EXT_CP_STEP]
    mov  rdx, r13
    call memcmp
    test rax, rax
    jnz  .differs
    add  [rel ext_cp_vdone], r13
    jmp  .ok
.same:
    mov  byte [rel ext_cp_cmp_on], 0
    mov  dword [rbx + fs_copy_job.same], 1
    xor  eax, eax
    mov  [rbx + fs_copy_job.total], rax  ; nothing copied: DONE=TOTAL=0
    mov  [rbx + fs_copy_job.done], rax
    mov  eax, FS_JOB_DONE
    jmp  .finish
.differs:
    mov  byte [rel ext_cp_cmp_on], 0
    test dword [rel ext_cp_policy], FS_CMODE_REPLACE
    jz   .differs_keepboth
    lea  rsi, [rel ext_cp_dst]
    call ext_cp_resolve                  ; fresh destination facts after the read-only compare
    test rax, rax
    jz   .differs_older
    cmp  dword [rel ext4_disk_last_error], EXT_E_NOTFOUND
    jne  .failed
    jmp  .differs_copy                   ; now free: ordinary safe creation
.differs_older:
    call ext_cp_older                    ; same eligibility/time/alias checks as BEGIN
    cmp  eax, 1
    je   .differs_replace
    test eax, eax
    jz   .differs_not_older
    mov  dword [rel vfs_copy_replace_verdict], 2
    mov  qword [rbx + fs_copy_job.total], 0 ; undecided: do not add comparison bytes to a waiting parent
    jmp  .differs_refused
.differs_replace:
    mov  eax, [r12 + ext_ctx.inode + EXT_SLOT_INO]
    mov  [rel ext_cp_victim], eax
    call ext_cp_snapshot
    mov  [rel ext_cp_victim_snap], eax   ; existing rename-over rechecks this exact victim at commit
    jmp  .differs_copy
.differs_not_older:
    mov  dword [rbx + fs_copy_job.skipped], 1
    xor  eax, eax
    mov  [rbx + fs_copy_job.total], rax
    mov  [rbx + fs_copy_job.done], rax
    mov  eax, FS_JOB_DONE
    jmp  .finish
.differs_keepboth:
    test dword [rel ext_cp_policy], FS_CMODE_KEEPBOTH
    jz   .differs_refused
.differs_copy:
    mov  qword [rel ext_cp_vdone], 0
    mov  dword [rel ext_cp_phase], EXT_CP_SETUP
    jmp  .ok
.differs_refused:
    mov  byte [rel ext_cp_cmp_refused], 1
    cmp  dword [rel ext_tree_child], 0
    jne  .cmp_differs
    mov  dword [rel vfs_copy_differs], 1 ; E2: an ask item's skip-same answer found it different
.cmp_differs:
    mov  dword [rel ext4_disk_last_error], EXT_E_EXISTS
    jmp  .failed
; a stale partial goes first, a bounded piece per step; then our partial is created
.setup:
    call ext_cp_check_source
    test rax, rax
    jnz  .failed
    cmp  dword [rel ext_cp_part_ino], 0
    je   .create
    lea  rsi, [rel ext_cp_part]
    call ext_cp_resolve
    test rax, rax
    jz   .stale_have
    cmp  dword [rel ext4_disk_last_error], EXT_E_NOTFOUND
    jne  .failed
    mov  dword [rel ext_cp_part_ino], 0  ; already gone
    jmp  .ok
.stale_have:
    mov  eax, [r12 + ext_ctx.inode + EXT_SLOT_INO]
    cmp  eax, [rel ext_cp_part_ino]
    jne  .stale_changed
    call ext_cp_is_marked
    jne  .stale_changed
    call ext_cp_trim_or_delete           ; one transaction
    test rax, rax
    jnz  .failed
    jmp  .ok
.stale_changed:
    mov  dword [rel ext4_disk_last_error], EXT_E_EXISTS   ; someone else's file took the name
    jmp  .failed
.create:
    mov  eax, [rel ext_cp_mode]
    mov  [rel ext_ns_create_mode], eax
    mov  eax, [rel ext_cp_tag]
    mov  [rel ext_ns_create_gen], eax
    mov  rdi, rbp
    lea  rsi, [rel ext_cp_part]
    xor  edx, edx
    xor  ecx, ecx
    mov  r8d, FS_MUT_CREATE
    call ext_ns_mutate                   ; mode + marker land in the same transaction
    mov  dword [rel ext_ns_create_mode], 0
    mov  dword [rel ext_ns_create_gen], 0
    test rax, rax
    jnz  .failed
    lea  rsi, [rel ext_cp_part]
    call ext_cp_resolve
    test rax, rax
    jnz  .failed
    mov  eax, [r12 + ext_ctx.inode + EXT_SLOT_INO]
    mov  [rel ext_cp_part_ino], eax
    mov  byte [rel ext_cp_stale], 0      ; from here the partial is this job's own
    mov  dword [rel ext_cp_phase], EXT_CP_COPY
    jmp  .ok
.copy:
    mov  rdi, [rel ext_cp_psize]         ; the partial ends after its last written chunk
    call ext_cp_validate
    test rax, rax
    jnz  .failed
    mov  r13, [rel ext_cp_size]
    sub  r13, [rel ext_cp_done]
    jnz  .sized
    ; everything copied but a trailing hole: one sparse truncate-grow, then verify
    mov  rcx, [rel ext_cp_size]
    cmp  [rel ext_cp_psize], rcx
    jae  .to_verify
    mov  edi, [rbx + fs_copy_job.mount]
    lea  rsi, [rel ext_cp_part]
    mov  edx, [rel ext_cp_part_len]
    call ext4_disk_truncate              ; one transaction
    test rax, rax
    jnz  .failed
    mov  rax, [rel ext_cp_size]
    mov  [rel ext_cp_psize], rax
    jmp  .to_verify
.sized:
    cmp  r13, EXT_CP_STEP
    jbe  .chunk
    mov  r13d, EXT_CP_STEP
.chunk:
    mov  rcx, [rel ext_cp_done]
    call ext_cp_src_hole
    test rax, rax
    js   .failed_source
    jnz  .hole_run                       ; a hole in the source stays a hole
    lea  rsi, [rel ext_cp_src]
    mov  edx, [rel ext_cp_src_len]
    mov  r14, [rel ext_cp_buf]
    mov  rcx, [rel ext_cp_done]
    call ext_cp_read
    test rax, rax
    jnz  .failed_source
    mov  rdi, rbp
    lea  rsi, [rel ext_cp_part]
    mov  edx, [rel ext_cp_part_len]
    mov  rcx, [rel ext_cp_done]
    mov  r8, [rel ext_cp_buf]
    mov  r9, r13
    call ext_op_write_at_path            ; one journaled append (past a skipped hole: a hole)
    cmp  rax, r13
    jne  .failed
    mov  rax, [rel ext_cp_done]
    add  rax, r13
    mov  [rel ext_cp_psize], rax
    add [rel ext_cp_done], r13
    mov [rbx + fs_copy_job.done], rax
    cmp byte [rel ext_cp_hold_partial], 1
    jne .append_advanced
    mov byte [rel ext_cp_hold_partial], 0
    mov rdi, rbx
    lea rsi, [rel ext_cp_part]
    mov rdx, rax
    mov ecx, 2
    call vfs_copy_partial_ready
    test rax, rax
    jnz .failed
    jmp .ok                            ; first durable append held before verify/rename
.append_advanced:
    jmp .advanced
.hole_run:
    ; skip the whole hole run (RDX = its end), not just this chunk: clamped to
    ; the size, at most EXT_CP_HOLE_MAX, and chunk-aligned unless it ends the file
    mov  rax, [rel ext_cp_size]
    cmp  rdx, rax
    jbe  .hole_in_file
    mov  rdx, rax                        ; the hole runs past the end of the file
.hole_in_file:
    mov  rax, [rel ext_cp_done]
    add  rax, EXT_CP_HOLE_MAX
    cmp  rdx, rax
    jbe  .hole_bounded
    mov  rdx, rax
.hole_bounded:
    cmp  rdx, [rel ext_cp_size]
    jae  .hole_len
    and  rdx, -EXT_CP_STEP               ; done stays on a chunk boundary
.hole_len:
    sub  rdx, [rel ext_cp_done]
    cmp  rdx, r13
    jbe  .advance                        ; never less than the chunk just checked
    mov  r13, rdx
.advance:
    add  [rel ext_cp_done], r13
    mov  rax, [rel ext_cp_done]
    mov  [rbx + fs_copy_job.done], rax
.advanced:
    cmp  rax, [rel ext_cp_size]
    jb   .ok
    mov  rcx, [rel ext_cp_psize]
    cmp  rcx, [rel ext_cp_size]
    jb   .ok                             ; a trailing hole: the next step grows the partial
.to_verify:
    cmp byte [rel ext_cp_hold_partial], 0
    je .partial_written
    mov dword [rel ext4_disk_last_error], EXT_E_UNSUPPORTED
    jmp .failed                       ; empty/all-hole has no durable append witness
.partial_written:
    mov  rax, [rel ext_cp_size]
    mov  [rbx + fs_copy_job.done], rax
    mov  qword [rel ext_cp_vdone], 0
    mov  dword [rel ext_cp_phase], EXT_CP_VERIFY
    mov  dword [rbx + fs_copy_job.state], FS_JOB_VERIFYING
    jmp  .ok
.verify:
    mov  rdi, [rel ext_cp_size]
    call ext_cp_validate
    test rax, rax
    jnz  .failed
    mov  r13, [rel ext_cp_size]
    sub  r13, [rel ext_cp_vdone]
    jz   .commit
    cmp  r13, EXT_CP_STEP
    jbe  .vchunk
    mov  r13d, EXT_CP_STEP
.vchunk:
    lea  rsi, [rel ext_cp_src]
    mov  edx, [rel ext_cp_src_len]
    mov  r14, [rel ext_cp_buf]
    mov  rcx, [rel ext_cp_vdone]
    call ext_cp_read
    test rax, rax
    jnz  .failed
    lea  rsi, [rel ext_cp_part]
    mov  edx, [rel ext_cp_part_len]
    mov  r14, [rel ext_cp_buf]
    add  r14, EXT_CP_STEP
    mov  rcx, [rel ext_cp_vdone]
    call ext_cp_read                        ; the committed partial, read back
    test rax, rax
    jnz  .failed
    mov  rdi, [rel ext_cp_buf]
    lea  rsi, [rdi + EXT_CP_STEP]
    mov  rdx, r13
    call memcmp
    test rax, rax
    jnz  .mismatch
    add  [rel ext_cp_vdone], r13
    jmp  .ok
.mismatch:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
    jmp  .failed
.commit:
    cmp  dword [rel ext_cp_victim], 0
    je   .commit_go
    lea  rsi, [rel ext_cp_dst]           ; E2r: the file to replace is still the one BEGIN judged older,
    call ext_cp_resolve                  ;   unchanged (an edit meanwhile is never overwritten)
    test rax, rax
    jz   .victim_there
    cmp  dword [rel ext4_disk_last_error], EXT_E_NOTFOUND
    jne  .failed
    mov  dword [rel ext_cp_victim], 0    ; deleted meanwhile: a plain commit (its rename never replaces)
    mov  dword [rel ext4_disk_last_error], EXT_E_NONE
    jmp  .commit_go
.victim_there:
    mov  eax, [r12 + ext_ctx.inode + EXT_SLOT_INO]
    cmp  eax, [rel ext_cp_victim]
    jne  .victim_changed
    call ext_cp_snapshot
    cmp  eax, [rel ext_cp_victim_snap]
    jne  .victim_changed
.commit_go:
    mov  eax, [rel ext_cp_victim]
    mov  [rel ext_ns_rename_replace], eax ; E2r: rename over exactly that inode (0: no replace)
    mov  al, [rel ext_cp_mt_on]          ; E2t: the rename writes the source mtime in its transaction
    mov  [rel ext_ns_rename_mt_on], al
    mov  rax, [rel ext_cp_mt_s]
    mov  [rel ext_ns_rename_mt_s], rax
    mov  eax, [rel ext_cp_mt_ns]
    mov  [rel ext_ns_rename_mt_ns], eax
    mov  rdi, rbp
    lea  rsi, [rel ext_cp_part]
    lea  rdx, [rel ext_cp_dst]
    xor  ecx, ecx
    mov  r8d, FS_MUT_RENAME
    call ext_ns_mutate                   ; THE commit: one transaction (E2r: the old file goes in it)
    mov  byte [rel ext_ns_rename_mt_on], 0   ; only this commit's rename
    mov  dword [rel ext_ns_rename_replace], 0
    test rax, rax
    jnz  .failed
    cmp  dword [rel ext_cp_victim], 0
    je   .repl_counted
    inc  dword [rbx + fs_copy_job.replaced]   ; E2r-b: FSJOB REPLACED, counted at the swap
.repl_counted:
    mov  eax, [rel ext_ns_orphan_ino]
    test eax, eax
    jz   .committed
    mov  [rel ext_cp_orphan], eax        ; E2r: the replaced file is on the orphan list
    mov  dword [rel ext_cp_phase], EXT_CP_ORPHAN
    jmp  .ok
.committed:
    mov  eax, FS_JOB_DONE
    jmp  .finish
.victim_changed:
    mov  dword [rel ext4_disk_last_error], EXT_E_EXISTS
    jmp  .failed
; E2r: the committed copy's replaced file, too large for the commit, freed a piece per step. A refusal
; leaves it on the orphan list for the next arm (ext_ns_orphans), Linux or e2fsck; the copy stays DONE.
.orphan:
    mov  esi, [rel ext_cp_orphan]
    call ext_ns_orphan_step              ; at most one transaction
    test rax, rax
    jz   .orphan_done
    jns  .ok
    call ext_cp_note_error
.orphan_done:
    mov  dword [rel ext_cp_orphan], 0
    mov  eax, FS_JOB_DONE
    jmp  .finish
; cancel or failure: remove our marked partial, a bounded piece per step
.reclaim:
    lea  rsi, [rel ext_cp_part]
    call ext_cp_resolve
    test rax, rax
    jz   .reclaim_have
    cmp  dword [rel ext4_disk_last_error], EXT_E_NOTFOUND
    je   .reclaimed                      ; already gone
    jmp  .reclaim_failed
.reclaim_have:
    mov  eax, [r12 + ext_ctx.inode + EXT_SLOT_INO]
    cmp  eax, [rel ext_cp_part_ino]
    jne  .reclaimed                      ; not ours any more: left alone
    call ext_cp_is_marked
    jne  .reclaimed
    call ext_cp_trim_or_delete           ; one transaction
    test rax, rax
    jnz  .reclaim_failed
    cmp  dword [rel ext_cp_part_ino], 0
    jne  .ok                             ; trimmed: the rest next step
.reclaimed:
    mov  eax, [rel ext_cp_target]
    jmp  .finish
.reclaim_failed:
    call ext_cp_note_error
    mov  byte [rel ext_cp_stranded], 1   ; smart copy B: never listed as one bad file
    mov  eax, FS_JOB_FAILED              ; the marked partial stays for the next BEGIN
    jmp  .finish
.failed_source:
    mov  byte [rel ext_cp_src_fault], 1  ; smart copy B: a read of the source, not of the partial
.failed:
    call ext_cp_note_error
    mov  dword [rel ext_cp_target], FS_JOB_FAILED
    mov  dword [rel ext_cp_phase], EXT_CP_RECLAIM
    mov  dword [rbx + fs_copy_job.state], FS_JOB_CANCELLING
    jmp  .ok
.no_window:
    cmp  dword [rel ext_cp_phase], EXT_CP_RECLAIM
    je   .reclaim_failed
    jmp  .failed
.finish:
    mov  byte [rel ext_cp_guard_active], 0
    mov  [rbx + fs_copy_job.state], eax
    cmp  dword [rel ext_tree_child], 0
    jne  .child_finished
    call ext_w_job_close                 ; DONE / CANCELLED / FAILED: the window ends
    mov  dword [rel ext_cp_phase], EXT_CP_IDLE
    mov  rdi, [rel ext_cp_buf]
    mov  qword [rel ext_cp_buf], 0
    test rdi, rdi
    jz   .ok
    call kfree
    jmp  .ok
.child_finished:
    mov  dword [rel ext_cp_phase], EXT_CP_IDLE
.ok:
    call ext_w_job_step_done             ; every exit: the step's request grant goes, the field clears
    xor  eax, eax
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; ---------------------------------------------------------------- CANCEL
ext_cp_cancel:
    mov  eax, [rel ext_cp_phase]
    cmp  eax, EXT_CP_SETUP
    je   .accept
    cmp  eax, EXT_CP_COMPARE             ; smart copy C: nothing created; RECLAIM finds no partial
    je   .accept
    cmp  eax, EXT_CP_COPY
    je   .accept
    cmp  eax, EXT_CP_VERIFY
    je   .accept
    xor  eax, eax                        ; reclaiming or idle: the state already says
    ret
.accept:
    mov  dword [rel ext_cp_target], FS_JOB_CANCELLED
    mov  dword [rel ext_cp_phase], EXT_CP_RECLAIM
    mov  dword [r8 + fs_copy_job.state], FS_JOB_CANCELLING
    xor  eax, eax
    ret

; ---------------------------------------------------------------- helpers
; ext_cp_trim_or_delete(R12=ctx, RBP=fsmount, RBX=job; ctx.inode = our marked
;   partial) -> 0/-1: at most one transaction. A partial larger than the piece
;   (ext_cp_trim) loses the piece from its end; a smaller one is deleted
;   (ext_cp_part_ino = 0). Refused TOOBIG (before any write), the piece halves
;   (a delete's to half the file) and the step returns 0 having written
;   nothing; a piece below one block is a real refusal.
ext_cp_trim_or_delete:
    mov  eax, [r12 + ext_ctx.inode + EI_SIZE_LO]
    mov  edx, [r12 + ext_ctx.inode + EI_SIZE_HI]
    shl  rdx, 32
    or   rax, rdx
    mov  rcx, [rel ext_cp_trim]
    cmp  rax, rcx
    jbe  .delete
    sub  rax, rcx
    mov  rcx, rax
    mov  edi, [rbx + fs_copy_job.mount]
    lea  rsi, [rel ext_cp_part]
    mov  edx, [rel ext_cp_part_len]
    call ext4_disk_truncate
    mov  rcx, [rel ext_cp_trim]
    jmp  .refused
.delete:
    push rax                             ; the partial's size
    mov  rdi, rbp
    lea  rsi, [rel ext_cp_part]
    xor  edx, edx
    xor  ecx, ecx
    mov  r8d, FS_MUT_DELETE
    call ext_ns_mutate
    pop  rcx
    test rax, rax
    jnz  .refused
    mov  dword [rel ext_cp_part_ino], 0
    cmp  byte [rel ext_cp_stale], 0
    je   .deleted
    ; RCQ-20 S3: an earlier attempt's stale partial is gone, whether SETUP or this retry's own
    ; cancel/failure reclaim deleted it. That attempt never committed (a commit is one rename).
    mov  byte [rel ext_cp_stale], 0
    mov  edi, FS_REC_RECLAIMED
    mov  esi, FS_PRES_EXT4
    xor  edx, edx
    call vfs_copy_note_recovery
.deleted:
    xor  eax, eax
    ret
.refused:
    test rax, rax
    jz   .out
    cmp  dword [rel ext4_disk_last_error], EXT_E_TOOBIG
    jne  .fail
    shr  rcx, 1                          ; too many groups for one transaction: a smaller piece
    mov  edx, [r12 + ext_ctx.block_bytes]
    cmp  rcx, rdx
    jb   .fail
    mov  [rel ext_cp_trim], rcx
    xor  eax, eax
.out:
    ret
.fail:
    mov  rax, -1
    ret

; ext_cp_note_error(RBX=job): the first failure's reason stays in the job.
ext_cp_note_error:
    cmp  dword [rbx + fs_copy_job.error], 0
    jne  .out
    mov  eax, [rel ext4_disk_last_error]
    test eax, eax
    jnz  .set
    mov  eax, EXT_E_IO
.set:
    mov  [rbx + fs_copy_job.error], eax
.out:
    ret

; ext_cp_copy_path(RDI=own buffer, RSI=Z path) -> RAX = length / -1 (BADPATH)
ext_cp_copy_path:
    test rsi, rsi
    jz   .bad
    xor  ecx, ecx
.byte:
    cmp  ecx, EXT_PATH_MAX
    jae  .bad
    mov  al, [rsi + rcx]
    mov  [rdi + rcx], al
    test al, al
    jz   .done
    inc  ecx
    jmp  .byte
.done:
    mov  eax, ecx
    ret
.bad:
    mov  dword [rel ext4_disk_last_error], EXT_E_BADPATH
    mov  rax, -1
    ret

; ext_cp_resolve(R12=ctx, RSI=one of our NUL-terminated paths) -> RAX 0 (ctx.inode) / -1
ext_cp_resolve:
    xor  edx, edx
.len:
    cmp  byte [rsi + rdx], 0
    je   ext_resolve
    inc  edx
    jmp  .len

; ext_cp_pick(R12=ctx; ext_cp_dst/_len = the requested destination) -> RAX 0 /
;   -1 (vfs_copy_refusal or ext4_disk_last_error). RCQ-20 S4 keep-both, in BEGIN:
;   reads only. Keeps the name when nothing is there (ext_cp_kept 1), else moves
;   ext_cp_dst to the first free "stem (k).ext", k 2..FS_KEPT_MAX. ext starts at the
;   leaf's last '.', unless that is its first byte (".rc" -> ".rc (2)"). Taken =
;   anything resolves there (a file, a directory, a symlink: nothing is followed).
;   The partial's tag then comes from the chosen leaf, so a crashed keep-both
;   attempt's retry picks the same k and reclaims its own partial. COMMIT stays the
;   no-replace rename: a name taken after BEGIN fails the job with EXISTS, never a
;   re-pick. ext_cp_part (built after the pick) holds the requested path meanwhile.
ext_cp_pick:
    push rbx
    push rbp
    push r13
    push r14
    push r15
    mov  r15d, 1
    mov  r13d, [rel ext_cp_dst_len]
    lea  rsi, [rel ext_cp_dst]
    mov  ecx, r13d
.slash:
    dec  ecx
    js   .picked                         ; no leaf: BEGIN refuses the path itself
    cmp  byte [rsi + rcx], '/'
    jne  .slash
    lea  ebx, [ecx + 1]                  ; the leaf's start
    mov  r14d, r13d
    sub  r14d, ebx                       ; its length
    jz   .picked
    mov  ebp, r13d                       ; where " (k)" goes: before the extension, else the end
    mov  ecx, r13d
.dot:
    dec  ecx
    cmp  ecx, ebx
    jbe  .dotted                         ; a leading '.' belongs to the stem
    cmp  byte [rsi + rcx], '.'
    jne  .dot
    mov  ebp, ecx
.dotted:
    call ext_cp_resolve
    test rax, rax
    jnz  .free                           ; k 1: the requested name
    cmp  r14d, EXT_NAME_MAX - 4
    ja   .unrepresentable                ; " (k)" would pass the 255-byte name limit
    lea  eax, [r13d + 4]
    cmp  eax, EXT_PATH_MAX
    jae  .unrepresentable
    lea  rdi, [rel ext_cp_part]
    lea  rsi, [rel ext_cp_dst]
    lea  edx, [r13d + 1]
    call memcpy
.next:
    inc  r15d
    cmp  r15d, FS_KEPT_MAX
    ja   .exhausted
    lea  rdi, [rel ext_cp_dst]
    add  rdi, rbp
    mov  byte [rdi], ' '
    mov  byte [rdi + 1], '('
    lea  eax, [r15d + '0']
    mov  [rdi + 2], al
    mov  byte [rdi + 3], ')'
    add  rdi, 4
    lea  rsi, [rel ext_cp_part]
    add  rsi, rbp
    mov  edx, r13d
    sub  edx, ebp
    inc  edx                             ; the extension and the NUL
    call memcpy
    lea  rsi, [rel ext_cp_dst]
    call ext_cp_resolve
    test rax, rax
    jz   .next
.free:
    cmp  dword [rel ext4_disk_last_error], EXT_E_NOTFOUND
    jne  .fail
    cmp  r15d, 1
    je   .picked
    lea  eax, [r13d + 4]
    mov  [rel ext_cp_dst_len], eax
.picked:
    mov  [rel ext_cp_kept], r15d
    xor  eax, eax
    jmp  .out
.exhausted:
    mov  dword [rel vfs_copy_refusal], FS_CREF_EXHAUSTED
    jmp  .fail
.unrepresentable:
    mov  dword [rel vfs_copy_refusal], FS_CREF_UNREPRESENTABLE
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbp
    pop  rbx
    ret

; ext_cp_is_marked(R12=ctx; ctx.inode resolved) -> ZF set when it is a regular
;   file carrying this job's marker generation
ext_cp_is_marked:
    movzx eax, word [r12 + ext_ctx.inode + EI_MODE]
    and  eax, EXT_S_IFMT
    cmp  eax, EXT_S_IFREG
    jne  .out
    mov  eax, [r12 + ext_ctx.inode + EI_GENERATION]
    cmp  eax, [rel ext_cp_tag]
.out:
    ret

; ext_cp_snapshot(R12=ctx; ctx.inode resolved) -> EAX = crc32c over the inode copy
;   with atime and the checksum fields cleared
ext_cp_snapshot:
    sub  rsp, EXT_INODE_COPY + 8
    mov  rdi, rsp
    lea  rsi, [r12 + ext_ctx.inode]
    mov  edx, EXT_INODE_COPY
    call memcpy
    mov  dword [rsp + EI_ATIME], 0
    mov  word [rsp + EI_CSUM_LO], 0
    mov  edx, [r12 + ext_ctx.inode_size]
    cmp  edx, EXT_INODE_COPY
    jbe  .len
    mov  edx, EXT_INODE_COPY
.len:
    cmp  edx, EI_ATIME_EXTRA + 4
    jb   .crc
    mov  word [rsp + EI_CSUM_HI], 0
    mov  dword [rsp + EI_ATIME_EXTRA], 0
.crc:
    mov  rdi, rsp
    mov  esi, edx
    mov  edx, EXT_CP_TAG_SEED
    call ext_crc32c
    add  rsp, EXT_INODE_COPY + 8
    ret

; ext_cp_validate(R12=ctx, RDI=expected partial size) -> RAX 0 / -1 (error set):
;   the source is the snapshotted file, unchanged; the partial is ours, intact.
ext_cp_validate:
    push rbx
    mov  rbx, rdi
    call ext_cp_check_source
    test rax, rax
    jnz  .fail
    lea  rsi, [rel ext_cp_part]
    call ext_cp_resolve
    test rax, rax
    jnz  .partial
    mov  eax, [r12 + ext_ctx.inode + EXT_SLOT_INO]
    cmp  eax, [rel ext_cp_part_ino]
    jne  .partial
    call ext_cp_is_marked
    jne  .partial
    mov  eax, [r12 + ext_ctx.inode + EI_SIZE_LO]
    mov  edx, [r12 + ext_ctx.inode + EI_SIZE_HI]
    shl  rdx, 32
    or   rax, rdx
    cmp  rax, rbx
    jne  .partial
    xor  eax, eax
    pop  rbx
    ret
.partial:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT   ; our partial was changed under us
.fail:
    mov  rax, -1
    pop  rbx
    ret

; ext_cp_src_hole(R12=ctx, RCX=offset, R13=bytes) -> RAX 1 when every source
;   block in [offset, offset+bytes) is a hole, 0 when any is mapped, -1 error.
;   On a hole, RDX = where the hole is known to end (bytes, >= offset+bytes):
;   the walk follows it past the chunk, bounded by the size, EXT_CP_HOLE_MAX
;   and EXT_CP_HOLE_MAPS ext_map calls (an indirect map reports a hole one
;   subtree at a time). Data, an error or a bound past the chunk just ends the
;   walk there: the next step decides that range itself.
ext_cp_src_hole:
    cmp  byte [rel ext_cp_source_kind], 0
    jne  ext_cp_source_token             ; foreign sources copy logical bytes; no hole-layout claim
    push r12
    cmp  qword [rel ext_cp_source_mount], 0
    je   .local
    mov  r12, [rel ext_cp_source_ctx]
.local:
    call ext_cp_src_hole_local
    cmp  qword [rel ext_cp_source_mount], 0
    je   .out
    push rax
    push rdx
    call ext_cp_source_token
    test rax, rax
    pop  rdx
    pop  rax
    jz   .out
    mov  rax, -1
.out:
    pop  r12
    ret
ext_cp_src_hole_local:
    push rbx
    push r14
    push r15
    sub  rsp, 16                         ; [rsp] = ext_map calls left for the walk
    mov  rbx, rcx
    lea  rsi, [rel ext_cp_src]
    call ext_cp_resolve                  ; ctx.inode = the source
    test rax, rax
    jnz  .fail
    mov  ecx, [r12 + ext_ctx.block_shift]
    mov  r14, rbx
    shr  r14, cl                         ; first logical block
    lea  r15, [rbx + r13 - 1]
    shr  r15, cl
    inc  r15                             ; end (exclusive)
.block:
    cmp  r14, r15
    jae  .walk
    lea  rdi, [r12 + ext_ctx.inode]
    mov  rsi, r14
    call ext_map
    test rax, rax
    js   .fail
    jnz  .data
    test rdx, rdx
    jz   .data                           ; never trust an empty run: copy it
    add  r14, rdx                        ; the whole hole run
    jmp  .block
.walk:
    ; the chunk is a hole: follow it further, so the step can skip all of it
    mov  rax, rbx
    add  rax, EXT_CP_HOLE_MAX
    cmp  rax, [rel ext_cp_size]
    jbe  .walk_lim
    mov  rax, [rel ext_cp_size]
.walk_lim:
    mov  ecx, [r12 + ext_ctx.block_shift]
    mov  edx, 1
    shl  rdx, cl
    lea  r15, [rax + rdx - 1]
    shr  r15, cl                         ; walk no further than this block
    mov  qword [rsp], EXT_CP_HOLE_MAPS
.walk_next:
    cmp  r14, r15
    jae  .hole
    sub  qword [rsp], 1
    jb   .hole                           ; out of map calls for this step
    lea  rdi, [r12 + ext_ctx.inode]
    mov  rsi, r14
    call ext_map
    test rax, rax
    jnz  .hole                           ; data or an error: the known hole ends here
    test rdx, rdx
    jz   .hole
    add  r14, rdx
    jmp  .walk_next
.hole:
    mov  ecx, [r12 + ext_ctx.block_shift]
    mov  rdx, r14
    shl  rdx, cl                         ; the hole run's end, in bytes
    mov  eax, 1
    jmp  .out
.data:
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    add  rsp, 16
    pop  r15
    pop  r14
    pop  rbx
    ret

; ext_cp_check_source(R12=ctx) -> RAX 0 / -1: the source is the snapshotted
;   file, unchanged (else SOURCE_CHANGED)
ext_cp_check_source:
    cmp  byte [rel ext_cp_source_kind], 3
    je   ext_cp_check_exfat_source
    cmp  byte [rel ext_cp_source_kind], 2
    je   ext_cp_check_nt_source
    cmp  byte [rel ext_cp_source_kind], 1
    je   ext_cp_check_fat_source
    push r12
    cmp  qword [rel ext_cp_source_mount], 0
    je   .local
    mov  r12, [rel ext_cp_source_ctx]
    call ext_cp_source_current
    test rax, rax
    jnz  .out
.local:
    call ext_cp_check_source_local
    test rax, rax
    jnz  .out
    cmp  qword [rel ext_cp_source_mount], 0
    je   .out
    call ext_cp_source_token
.out:
    pop  r12
    ret
ext_cp_check_exfat_source:
    lea  rsi, [rel ext_cp_src]
    mov  edx, [rel ext_cp_src_len]
    xor  ecx, ecx
    call exfat_disk_source_stat
    jmp  ext_cp_check_foreign_size
ext_cp_check_nt_source:
    lea  rsi, [rel ext_cp_src]
    mov  edx, [rel ext_cp_src_len]
    xor  ecx, ecx
    call ntfs_disk_source_stat
    jmp  ext_cp_check_foreign_size
ext_cp_check_fat_source:
    lea  rsi, [rel ext_cp_src]
    mov  edx, [rel ext_cp_src_len]
    xor  ecx, ecx
    call fat32_disk_source_stat
ext_cp_check_foreign_size:
    cmp  rax, -1
    je   .changed
    cmp  rax, [rel ext_cp_size]
    jne  .changed
    xor  eax, eax
    ret
.changed:
    mov  dword [rel ext4_disk_last_error], EXT_E_SOURCE_CHANGED
    mov  rax, -1
    ret
ext_cp_check_source_local:
    lea  rsi, [rel ext_cp_src]
    call ext_cp_resolve
    test rax, rax
    jz   .src
    cmp  dword [rel ext4_disk_last_error], EXT_E_NOTFOUND
    je   .changed
    mov  rax, -1
    ret
.src:
    mov  eax, [r12 + ext_ctx.inode + EXT_SLOT_INO]
    cmp  eax, [rel ext_cp_src_ino]
    jne  .changed
    call ext_cp_snapshot
    cmp  eax, [rel ext_cp_snap]
    jne  .changed
    xor  eax, eax
    ret
.changed:
    mov  dword [rel ext4_disk_last_error], EXT_E_SOURCE_CHANGED
    mov  rax, -1
    ret

; ext_cp_read(RBP=fsmount, RSI=path, EDX=len, RCX=offset, R13=bytes, R14=buffer)
;   -> RAX 0 / -1: exactly R13 bytes, else the read failed
ext_cp_read:
    cmp  qword [rel ext_cp_source_mount], 0
    je   .destination
    lea  rax, [rel ext_cp_src]
    cmp  rsi, rax
    jne  .destination
    push r12
    push rdx
    call ext_cp_source_token
    pop  rdx
    test rax, rax
    jnz  .source_token_bad
    mov  r12, [rel ext_cp_source_ctx]
    mov  rdi, [rel ext_cp_source_mount]
    mov  r8, r14
    mov  r9, r13
    cmp  byte [rel ext_cp_source_kind], 3
    je   .exfat_read
    cmp  byte [rel ext_cp_source_kind], 2
    je   .nt_read
    cmp  byte [rel ext_cp_source_kind], 1
    jne  .ext_read
    call fat32_disk_read_at_path
    jmp  .source_read
.exfat_read:
    call exfat_disk_source_read
    jmp  .native_result
.nt_read:
    call ntfs_disk_source_read
.native_result:
    cmp  rax, -2                       ; full native file/path identity failed during this logical read
    jne  .source_read
    mov  dword [rel ext4_disk_last_error], EXT_E_SOURCE_CHANGED
    jmp  .source_token_bad
.ext_read:
    call ext_op_read_at_path
.source_read:
    cmp  rax, r13
    jne  .source_short
    call ext_cp_source_token
    pop  r12
    ret
.source_token_bad:
    pop  r12
    ret
.source_short:
    call ext_cp_source_token
    pop  r12
    test rax, rax
    jnz  .fail
    cmp  byte [rel ext_cp_source_kind], 0
    je   .short
    mov  dword [rel ext4_disk_last_error], EXT_E_IO
    jmp  .fail
.destination:
    mov  rdi, rbp
    mov  r8, r14
    mov  r9, r13
    call ext_op_read_at_path
    cmp  rax, r13
    jne  .short
    xor  eax, eax
    ret
.short:
    cmp  dword [rel ext4_disk_last_error], EXT_E_NONE
    jne  .fail
    mov  dword [rel ext4_disk_last_error], EXT_E_IO
.fail:
    mov  rax, -1
    ret

; ext_raw_read uses this at EVERY source transfer, including single-sector
; fallback. Preserve its argument registers. A generation change during a
; multi-transfer file read must not read another block from the replacement.
; RBX=device -> RAX 0 / -1. Inactive for legacy reads and destination devices.
; FAT reads retain their source context in R12, including when its dev field
; moves. Guard that context rather than accidentally bypassing a changed dev.
ext_cp_guard_fat_read:
    cmp  byte [rel ext_cp_guard_active], 0
    je   .ok
    cmp  byte [rel ext_cp_source_kind], 1
    jne  .ok
    cmp  r12, [rel ext_cp_source_ctx]
    jne  .ok
    push rdx
    call ext_cp_source_token
    pop  rdx
    ret
.ok:
    xor  eax, eax
    ret
ext_cp_guard_read:
    call ext_w_job_guard_read
    test rax, rax
    jnz  .out
    cmp  byte [rel ext_cp_guard_active], 0
    je   .ok
    cmp  rbx, [rel ext_cp_source_dev]
    jne  .ok
    push rdx
    call ext_cp_source_token
    pop  rdx
.out:
    ret
.ok:
    xor  eax, eax
    ret

; Bind immutable source context, registered route/geometry, partition and UUID.
; A generation alone does not identify a backend/unit or sector interpretation.
; Destination writer/job gate continues to own destination authority and custody.
ext_cp_bind_source:
    push r12
    mov  rax, [rel ext_cp_source_mount]
    mov  r12, [rax + fsmount.priv]
    mov  [rel ext_cp_source_ctx], r12
    lea  rdx, [rel ext_ops]
    cmp  [rax + fsmount.ops], rdx
    je   .ext
    mov  byte [rel ext_cp_source_kind], 1
    mov  rdi, rax
    call fat32_disk_source_device
    test rax, rax
    jz   .nt
    mov  [rel ext_cp_source_dev], rax
    cmp  dword [rel ext_tree_source_kind], 0
    je   .fat_bind
    cmp  dword [rel ext_tree_active], 0
    je   .fat_bind
    call fat32_disk_source_token         ; child retains original tree media/namespace custody
    jmp  .fat_bound
.fat_bind:
    mov  rdi, [rel ext_cp_source_mount]
    call fat32_disk_source_bind
.fat_bound:
    test rax, rax
    jnz  .bad
    pop  r12
    ret
.nt:
    mov  byte [rel ext_cp_source_kind], 2
    mov  rdi, [rel ext_cp_source_mount]
    call ntfs_disk_source_device
    test rax, rax
    jz   .exfat
    mov  [rel ext_cp_source_dev], rax
    cmp  dword [rel ext_tree_source_kind], 2
    jne  .nt_bind
    cmp  dword [rel ext_tree_active], 0
    je   .nt_bind
    call ntfs_disk_source_token          ; retain original tree custody across children
    jmp  .nt_bound
.nt_bind:
    mov  rdi, [rel ext_cp_source_mount]
    call ntfs_disk_source_bind
.nt_bound:
    test rax, rax
    jnz  .bad
    pop  r12
    ret
.exfat:
    mov  byte [rel ext_cp_source_kind], 3
    mov  rdi, [rel ext_cp_source_mount]
    call exfat_disk_source_device
    test rax, rax
    jz   .bad
    mov  [rel ext_cp_source_dev], rax
    mov  rdi, [rel ext_cp_source_mount]
    call exfat_disk_source_bind
    test rax, rax
    jnz  .bad
    pop  r12
    ret
.ext:
    mov  rax, [r12 + ext_ctx.dev]
    mov  [rel ext_cp_source_dev], rax
    mov  rdx, [rax + dev.ops]
    mov  [rel ext_cp_source_ops], rdx
    mov  rdx, [rax + dev.priv]
    mov  [rel ext_cp_source_priv], rdx
    mov  rax, [rax + dev.info]
    test rax, rax
    jz   .bad
    mov  [rel ext_cp_source_info], rax
    cmp  dword [rax + blk_info.sector_size], 512
    jne  .bad
    mov  edx, [rax + blk_info.unit]
    mov  [rel ext_cp_source_unit], edx
    mov  rdx, [rax + blk_info.lba_max]
    mov  [rel ext_cp_source_max], rdx
    lea  rsi, [rax + blk_info.logical_sector_bytes]
    lea  rdi, [rel ext_cp_source_blkgeo]
    mov  edx, blk_info_size - blk_info.logical_sector_bytes
    call memcpy
    mov  rax, [rel ext_cp_source_info]
    mov  rax, [rax + blk_info.media_generation]
    test rax, rax
    jz   .bad
    cmp  rax, [r12 + ext_ctx.read_generation]
    jne  .bad
    mov  [rel ext_cp_source_gen], rax
    mov  rax, [r12 + ext_ctx.part_lba]
    mov  [rel ext_cp_source_lba], rax
    mov  rax, [r12 + ext_ctx.part_sectors]
    mov  [rel ext_cp_source_sectors], rax
    lea  rdi, [rel ext_cp_source_uuid]
    lea  rsi, [r12 + ext_ctx.read_uuid]
    mov  edx, 16
    call memcpy
    call ext_cp_source_current
    pop  r12
    ret
.bad:
    mov  dword [rel ext4_disk_last_error], EXT_E_SOURCE_CHANGED
    mov  rax, -1
    pop  r12
    ret

; Pure state check BEFORE source IO and again after it. No foreign medium reads.
ext_cp_source_token:
    cmp  byte [rel ext_cp_source_kind], 3
    je   .exfat
    cmp  byte [rel ext_cp_source_kind], 2
    je   .nt
    cmp  byte [rel ext_cp_source_kind], 1
    jne  .ext
    call fat32_disk_source_token        ; preserves all except RAX/RDX, as this ABI requires
    jmp  .foreign
.exfat:
    call exfat_disk_source_token
    jmp  .foreign
.nt:
    call ntfs_disk_source_token
.foreign:
    test rax, rax
    jnz  .bad
    ret
.ext:
    mov  rax, [rel ext_cp_source_mount]
    lea  rdx, [rel ext_ops]
    cmp  [rax + fsmount.ops], rdx
    jne  .bad
    mov  rdx, [rax + fsmount.priv]
    cmp  rdx, [rel ext_cp_source_ctx]
    jne  .bad
    cmp  dword [rdx + ext_ctx.mounted], 1
    jne  .bad
    mov  rax, [rdx + ext_ctx.dev]
    cmp  rax, [rel ext_cp_source_dev]
    jne  .bad
    mov  rax, [rax + dev.ops]
    cmp  rax, [rel ext_cp_source_ops]
    jne  .bad
    mov  rax, [rdx + ext_ctx.dev]
    mov  rax, [rax + dev.priv]
    cmp  rax, [rel ext_cp_source_priv]
    jne  .bad
    mov  rax, [rdx + ext_ctx.dev]
    mov  rax, [rax + dev.info]
    cmp  rax, [rel ext_cp_source_info]
    jne  .bad
    test rax, rax
    jz   .bad
    cmp  dword [rax + blk_info.sector_size], 512
    jne  .bad
    push rdx
    mov  edx, [rax + blk_info.unit]
    cmp  edx, [rel ext_cp_source_unit]
    pop  rdx
    jne  .bad
    push rdx
    mov  rdx, [rax + blk_info.lba_max]
    cmp  rdx, [rel ext_cp_source_max]
    pop  rdx
    jne  .bad
    mov  rax, [rax + blk_info.media_generation]
    test rax, rax
    jz   .bad
    cmp  rax, [rel ext_cp_source_gen]
    jne  .bad
    mov  rax, [rdx + ext_ctx.part_lba]
    cmp  rax, [rel ext_cp_source_lba]
    jne  .bad
    mov  rax, [rdx + ext_ctx.part_sectors]
    cmp  rax, [rel ext_cp_source_sectors]
    jne  .bad
    ; Preserve this token's ABI: only RAX/RDX may change. Geometry includes
    ; transfer limits/capabilities and generation, checked on each real read
    ; and again before falling back after a refused multi-sector transfer.
    push rdi
    push rsi
    push rcx
    push rdx
    lea  rdi, [rel ext_cp_source_blkgeo]
    mov  rsi, [rel ext_cp_source_info]
    add  rsi, blk_info.logical_sector_bytes
    mov  edx, blk_info_size - blk_info.logical_sector_bytes
    call memcmp
    pop  rdx
    pop  rcx
    pop  rsi
    pop  rdi
    test rax, rax
    jnz  .bad
    xor  eax, eax
    ret
.bad:
    mov  dword [rel ext4_disk_last_error], EXT_E_SOURCE_CHANGED
    mov  rax, -1
    ret

; Fresh inode/map caches plus UUID check; caller has source R12.
ext_cp_source_current:
    cmp  byte [rel ext_cp_source_kind], 3
    je   .exfat
    cmp  byte [rel ext_cp_source_kind], 2
    je   .nt
    cmp  byte [rel ext_cp_source_kind], 1
    jne  .ext
    call fat32_disk_source_current
    jmp  .foreign
.exfat:
    call exfat_disk_source_current
    jmp  .foreign
.nt:
    call ntfs_disk_source_current
.foreign:
    test rax, rax
    jnz  .bad
    ret
.ext:
    call ext_cp_source_token
    test rax, rax
    jnz  .out
    mov  rdi, [r12 + ext_ctx.dev]
    mov  rsi, [r12 + ext_ctx.part_lba]
    add  rsi, 2
    mov  edx, 2
    lea  rcx, [rel ext_cp_source_sb]
    ; The refresh obeys the same device limit and bounded single-sector
    ; fallback as file/metadata reads. Initial bind precedes the job's read
    ; guard, so enable it locally too: no second transfer after custody loss.
    movzx eax, byte [rel ext_cp_guard_active]
    push rax
    mov  byte [rel ext_cp_guard_active], 1
    call ext_raw_read
    pop  rdx
    mov  [rel ext_cp_guard_active], dl
    test rax, rax
    jnz  .bad
    lea  rdi, [rel ext_cp_source_uuid]
    lea  rsi, [rel ext_cp_source_sb + ESB_UUID]
    mov  edx, 16
    call memcmp
    test rax, rax
    jnz  .bad
    mov  qword [r12 + ext_ctx.meta_tag], -1
    mov  qword [r12 + ext_ctx.ibuf_tag], -1
    jmp  ext_cp_source_token
.bad:
    mov  dword [rel ext4_disk_last_error], EXT_E_SOURCE_CHANGED
    mov  rax, -1
.out:
    ret

; ---------------------------------------------------------------- TREE
; The shared job has one window. A child uses the original file engine and a
; private job record; only its successful no-replace rename increments FILES.
; Directories become visible one at a time. Cancellation keeps committed
; children and reclaims only the current marked file: never a tree rollback.
%include "fs/fat32_source.inc"
%include "fs/ntfs_tree_source.inc"

ET_SRC       equ 0
ET_DST       equ EXT_PATH_MAX
ET_CURSOR    equ 2 * EXT_PATH_MAX
ET_SIZE      equ ET_CURSOR + 8
ET_SRCINO    equ ET_SIZE + 8
ET_DSTINO    equ ET_SRCINO + 4
ET_SNAP      equ ET_DSTINO + 4
ET_MODE      equ ET_SNAP + 4
ET_BLOCK     equ ET_MODE + 4
ET_CRC       equ ET_BLOCK + 8
ET_FAT       equ ET_CRC + 8 ; private union: FAT32 or NTFS read-only cursor
ET_FRAME     equ ET_FAT + NTT_SIZE ; foreign cursors share the frame, NTFS is larger
ET_MKDIR     equ 1
ET_WALK      equ 2
ET_WALK_K    equ 16

; Forget only when the VFS admits a new BEGIN (there is no live job). Preserve
; all BEGIN arguments, including the carried decision pointer in the job.
ext_tree_forget:
    mov  byte [rel ext_cp_guard_active], 0
    push rdi
    push rsi
    push rdx
    push rcx
    push r8
    push r9
    sub  rsp, 8
    call ntfs_disk_source_tree_forget
    call ext_w_job_close
    mov  rdi, [rel ext_cp_buf]
    mov  qword [rel ext_cp_buf], 0
    test rdi, rdi
    jz   .freed
    call kfree
.freed:
    mov  dword [rel ext_cp_phase], EXT_CP_IDLE
    mov  dword [rel ext_tree_active], 0
    mov  dword [rel ext_tree_child], 0
    mov  dword [rel ext_tree_source_kind], 0
    add  rsp, 8
    pop  r9
    pop  r8
    pop  rcx
    pop  rdx
    pop  rsi
    pop  rdi
    ret

; Copy an absolute path and remove trailing slashes, keeping "/" itself.
ext_tree_path:
    call ext_cp_copy_path
    test rax, rax
    js   .out
    cmp  byte [rdi], '/'
    jne  .bad
.trim:
    cmp  eax, 1
    jbe  .out
    cmp  byte [rdi + rax - 1], '/'
    jne  .out
    dec  eax
    mov  byte [rdi + rax], 0
    jmp  .trim
.bad:
    mov  dword [rel ext4_disk_last_error], EXT_E_BADPATH
    mov  rax, -1
.out:
    ret

ext_tree_begin:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8
    mov  rbp, rdi
    mov  rbx, r8
    mov  r13, rsi
    mov  r14, rdx
    and  r9d, FS_CMODE_MASK
    mov  [rel ext_cp_policy], r9d
    lea  rax, [rel ext_cp_policy]
    mov  [rel vfs_copy_policy_ptr], rax  ; E2: the walk's children inherit it at each BEGIN
    mov  dword [rel ext_cp_kept], 0
    lea  rdi, [rel ext_tree_levels]
    xor  esi, esi
    mov  edx, FS_TREE_DEPTH_MAX * ET_FRAME
    call memset
    lea  r15, [rel ext_tree_levels]
    mov  qword [r15 + ET_BLOCK], -1
    mov  rdi, rbp
    call ext_w_enter
    test rax, rax
    jz   .fail
    mov  r12, rax
    lea  rdi, [rel ext_cp_src]
    mov  rsi, r13
    call ext_tree_path
    test rax, rax
    js   .fail
    lea  rdi, [rel ext_cp_dst]
    mov  rsi, r14
    call ext_tree_path
    test rax, rax
    js   .fail
    mov  [rel ext_cp_dst_len], eax
    cmp  dword [rel ext_tree_source_kind], 0
    je   .local_source
    mov  rax, [rel ext_cp_incoming]
    mov  [rel ext_cp_source_mount], rax
    call ext_cp_bind_source
    test rax, rax
    jnz  .fail
    mov  byte [rel ext_cp_guard_active], 1
    lea  rdi, [r15 + ET_FAT]
    lea  rsi, [rel ext_cp_src]
    mov  ecx, 1
    call ext_tree_foreign_dir
    test rax, rax
    jnz  .fail
    mov  eax, [r15 + ET_FAT + FT_HEAD]
    cmp  dword [rel ext_tree_source_kind], 2
    jne  .source_id
    mov  eax, [r15 + ET_FAT + NTT_REF]
.source_id:
    mov  [r15 + ET_SRCINO], eax
    mov  dword [r15 + ET_MODE], 0x41ED ; new directory 0755, no foreign metadata claim
    jmp  .parent                       ; distinct devices: no same-volume ancestry question
.local_source:
    lea  rsi, [rel ext_cp_src]
    call ext_cp_resolve
    test rax, rax
    jnz  .fail
    movzx eax, word [r12 + ext_ctx.inode + EI_MODE]
    and  eax, EXT_S_IFMT
    cmp  eax, EXT_S_IFDIR
    jne  .notdir
    test dword [r12 + ext_ctx.inode + EI_FLAGS], EXT_FL_REFUSED
    jnz  .unsupported
    call ext_tree_save_source
    test rax, rax
    jnz  .fail
    ; Identity is refused even under keep-both; never turn "copy onto self"
    ; into a differently named copy by applying the conflict policy first.
    lea  rsi, [rel ext_cp_dst]
    call ext_cp_resolve
    test rax, rax
    jnz  .dst_missing
    mov  eax, [r12 + ext_ctx.inode + EXT_SLOT_INO]
    cmp  eax, [r15 + ET_SRCINO]
    je   .inside
    jmp  .parent
.dst_missing:
    cmp  dword [rel ext4_disk_last_error], EXT_E_NOTFOUND
    jne  .fail
.parent:
    lea  rsi, [rel ext_cp_dst]
    mov  ecx, [rel ext_cp_dst_len]
.slash:
    dec  ecx
    js   .badpath
    cmp  byte [rsi + rcx], '/'
    jne  .slash
    lea  eax, [rcx + 1]
    cmp  eax, [rel ext_cp_dst_len]
    jae  .badpath
    mov  r13d, ecx
    test ecx, ecx
    jnz  .parent_len
    mov  r13d, 1
.parent_len:
    lea  rdi, [rel ext_cp_part]
    mov  edx, r13d
    call memcpy
    lea  rsi, [rel ext_cp_part]
    mov  byte [rsi + r13], 0
    call ext_cp_resolve
    test rax, rax
    jnz  .fail
    movzx eax, word [r12 + ext_ctx.inode + EI_MODE]
    and  eax, EXT_S_IFMT
    cmp  eax, EXT_S_IFDIR
    jne  .notdir
    cmp  dword [rel ext_tree_source_kind], 0
    jne  .different_devices
    mov  edi, [r12 + ext_ctx.inode + EXT_SLOT_INO]
    mov  esi, [r15 + ET_SRCINO]
    call ext_ns_is_below                  ; actual '..' ancestry, not a lexical prefix
    cmp  rax, 1
    je   .inside
    test rax, rax
    jnz  .fail
.different_devices:
    mov  dword [rel ext_tree_merge_ino], 0
    test dword [rel ext_cp_policy], FS_CMODE_SKIPSAME | FS_CMODE_ASK | FS_CMODE_REPLACE
    jz   .tree_policy                    ; (E2r-b2: a replace-older tree merges as well)
    lea  rsi, [rel ext_cp_dst]
    call ext_cp_resolve                  ; smart copy C: an existing DIRECTORY there is merged into
    test rax, rax
    jz   .tree_existing
    cmp  dword [rel ext4_disk_last_error], EXT_E_NOTFOUND
    jne  .fail
    jmp  .tree_policy
.tree_existing:
    movzx eax, word [r12 + ext_ctx.inode + EI_MODE]
    and  eax, EXT_S_IFMT
    cmp  eax, EXT_S_IFDIR
    jne  .tree_policy                    ; anything else: the conflict the policy decides
    mov  eax, [r12 + ext_ctx.inode + EXT_SLOT_INO]
    mov  [rel ext_tree_merge_ino], eax
    cmp  dword [rel ext_tree_source_kind], 0
    jne  .merged
    mov  edi, eax
    mov  esi, [r15 + ET_SRCINO]
    call ext_ns_is_below                  ; never into the source or below it
    cmp  rax, 1
    je   .inside
    test rax, rax
    jnz  .fail
    jmp  .merged
.tree_policy:
    test dword [rel ext_cp_policy], FS_CMODE_KEEPBOTH
    jz   .picked
    call ext_cp_pick
    test rax, rax
    jnz  .fail
.picked:
    lea  rsi, [rel ext_cp_dst]
    call ext_cp_resolve
    test rax, rax
    jz   .exists
    cmp  dword [rel ext4_disk_last_error], EXT_E_NOTFOUND
    jne  .fail
.merged:
    lea  rdi, [r15 + ET_SRC]
    lea  rsi, [rel ext_cp_src]
    call ext_cp_copy_path
    lea  rdi, [r15 + ET_DST]
    lea  rsi, [rel ext_cp_dst]
    call ext_cp_copy_path
    mov  edi, 2 * EXT_CP_STEP
    call kmalloc
    test rax, rax
    jz   .toobig
    mov  [rel ext_cp_buf], rax
    cmp  byte [rel ext_cp_carried], 0
    jne  .carried
    call ext_w_job_open
    jmp  .opened
.carried:
    mov  rdi, rbx
    call ext_w_job_open_carried
.opened:
    test rax, rax
    jnz  .fail
    mov  qword [rel ext_tree_base], 0
    mov  dword [rel ext_tree_stop], 0
    mov  dword [rel ext_tree_depth], 1
    mov  dword [rel ext_tree_phase], ET_MKDIR
    mov  eax, [rel ext_tree_merge_ino]
    test eax, eax
    jz   .fresh
    mov  [r15 + ET_DSTINO], eax          ; smart copy C: level 1 is the existing directory
    mov  dword [rel ext_tree_phase], ET_WALK
.fresh:
    mov  dword [rel ext_tree_active], 1
    mov  qword [rbx + fs_copy_job.done], 0
    mov  qword [rbx + fs_copy_job.total], FS_TOTAL_UNKNOWN
    mov  dword [rbx + fs_copy_job.state], FS_JOB_RUNNING
    mov  dword [rbx + fs_copy_job.error], 0
    mov  dword [rbx + fs_copy_job.tree], 1
    mov  dword [rbx + fs_copy_job.files], 0
    mov  dword [rbx + fs_copy_job.skipped], 0
    mov  dword [rbx + fs_copy_job.preserved], FS_PRES_EXT4
    cmp  dword [rel ext_tree_source_kind], 0
    je   .preserved
    mov  dword [rbx + fs_copy_job.preserved], FS_PRES_FAT
.preserved:
    mov  eax, [rel ext_cp_kept]
    mov  [rbx + fs_copy_job.kept], eax
    mov  rax, [r12 + ext_ctx.dev]
    mov  [rbx + fs_copy_job.dev], rax
    xor  eax, eax
    jmp  .out
.inside:
    mov  dword [rel vfs_copy_refusal], FS_CREF_INSIDE_SRC
.badpath:
    mov  dword [rel ext4_disk_last_error], EXT_E_BADPATH
    jmp  .fail
.exists:
    mov  dword [rel ext4_disk_last_error], EXT_E_EXISTS
    jmp  .fail
.notdir:
    mov  dword [rel ext4_disk_last_error], EXT_E_NOTDIR
    jmp  .fail
.unsupported:
    mov  dword [rel ext4_disk_last_error], EXT_E_UNSUPPORTED
    jmp  .fail
.toobig:
    mov  dword [rel ext4_disk_last_error], EXT_E_TOOBIG
.fail:
    call ext_tree_forget
    mov  rax, -1
.out:
    test rax, rax
    jns  .returned
    mov  edi, [rel ext4_disk_last_error]
    mov  esi, FS_PRES_EXT4
    call vfs_copy_begin_failure
.returned:
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Save the directory identity/snapshot/mode in R15's frame. Snapshot excludes
; atime as in the existing file engine; a cached source block also has a CRC.
ext_tree_foreign_dir:
    cmp  dword [rel ext_tree_source_kind], 2
    jne  .fat
    jmp  ntfs_disk_source_dir
.fat:
    jmp  fat32_disk_source_dir

ext_tree_save_source:
    cmp  dword [rel ext_tree_source_kind], 0
    je   .local
    lea  rdi, [r15 + ET_FAT]
    lea  rsi, [rel ext_tree_next_src]
    mov  ecx, 1
    call ext_tree_foreign_dir
    test rax, rax
    jnz  .out
    mov  eax, [r15 + ET_FAT + FT_HEAD]
    cmp  dword [rel ext_tree_source_kind], 2
    jne  .source_id
    mov  eax, [r15 + ET_FAT + NTT_REF]
.source_id:
    mov  [r15 + ET_SRCINO], eax
    mov  dword [r15 + ET_MODE], 0x41ED
    xor  eax, eax
.out:
    ret
.local:
    mov  eax, [r12 + ext_ctx.inode + EXT_SLOT_INO]
    mov  [r15 + ET_SRCINO], eax
    lea  rdi, [r12 + ext_ctx.inode]
    call ext_inode_size
    mov  ecx, [r12 + ext_ctx.block_bytes]
    dec  ecx
    test rax, rcx
    jnz  .corrupt
    cmp  rax, EXT_DIR_MAX_BYTES
    ja   .corrupt
    mov  [r15 + ET_SIZE], rax
    movzx eax, word [r12 + ext_ctx.inode + EI_MODE]
    mov  [r15 + ET_MODE], eax
    call ext_cp_snapshot
    mov  [r15 + ET_SNAP], eax
    xor  eax, eax
    ret
.corrupt:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
    mov  rax, -1
    ret

ext_tree_frame_ptr:
    mov  eax, [rel ext_tree_depth]
    dec  eax
    imul eax, ET_FRAME
    lea  r15, [rel ext_tree_levels]
    add  r15, rax
    ret

; Read one directory block of ctx.inode. Verify its checksum and compare a
; resumed block with the stored content CRC, including on an unseeded clock.
ext_tree_read_block:
    push rbx
    push r13
    mov  r13, rsi
    lea  rdi, [r12 + ext_ctx.dino]
    lea  rsi, [r12 + ext_ctx.inode]
    mov  edx, EXT_SLOT
    call memcpy
    lea  rdi, [r12 + ext_ctx.dino]
    mov  rsi, r13
    call ext_map
    test rax, rax
    js   .fail
    jz   .corrupt
    mov  rsi, rax
    mov  edx, 1
    mov  rcx, [r12 + ext_ctx.dir_buf]
    call ext_read_blocks
    test rax, rax
    jnz  .fail
    mov  rsi, r13
    call ext_dir_tail_ok
    jc   .corrupt
    mov  rdi, [r12 + ext_ctx.dir_buf]
    mov  esi, [r12 + ext_ctx.block_bytes]
    mov  edx, EXT_CP_TAG_SEED
    call ext_crc32c
    cmp  r13, [r15 + ET_BLOCK]
    jne  .new
    cmp  eax, [r15 + ET_CRC]
    jne  .changed
.new:
    mov  [r15 + ET_BLOCK], r13
    mov  [r15 + ET_CRC], eax
    xor  eax, eax
    jmp  .out
.changed:
    mov  dword [rel ext4_disk_last_error], EXT_E_SOURCE_CHANGED
    jmp  .fail
.corrupt:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
.fail:
    mov  rax, -1
.out:
    pop  r13
    pop  rbx
    ret

; Revalidate the at-most-eight active source and destination directory paths.
; Never follow a replacement destination directory into another namespace.
ext_tree_check_frames:
    push r13
    push r14
    push r15
    xor  r14d, r14d
.next:
    imul eax, r14d, ET_FRAME
    lea  r15, [rel ext_tree_levels]
    add  r15, rax
    cmp  dword [rel ext_tree_source_kind], 0
    je   .local_source
    lea  rdi, [r15 + ET_FAT]
    lea  rsi, [r15 + ET_SRC]
    xor  ecx, ecx
    call ext_tree_foreign_dir
    test rax, rax
    jnz  .fail
    jmp  .destination
.local_source:
    lea  rsi, [r15 + ET_SRC]
    call ext_cp_resolve
    test rax, rax
    jnz  .changed
    mov  eax, [r12 + ext_ctx.inode + EXT_SLOT_INO]
    cmp  eax, [r15 + ET_SRCINO]
    jne  .changed
    call ext_cp_snapshot
    cmp  eax, [r15 + ET_SNAP]
    jne  .changed
    mov  rsi, [r15 + ET_BLOCK]
    cmp  rsi, -1
    je   .destination
    call ext_tree_read_block
    test rax, rax
    jnz  .fail
.destination:
    cmp  dword [r15 + ET_DSTINO], 0
    je   .advance
    lea  rsi, [r15 + ET_DST]
    call ext_cp_resolve
    test rax, rax
    jnz  .bad_dst
    mov  eax, [r12 + ext_ctx.inode + EXT_SLOT_INO]
    cmp  eax, [r15 + ET_DSTINO]
    jne  .bad_dst
    movzx eax, word [r12 + ext_ctx.inode + EI_MODE]
    and  eax, EXT_S_IFMT
    cmp  eax, EXT_S_IFDIR
    jne  .bad_dst
.advance:
    inc  r14d
    cmp  r14d, [rel ext_tree_depth]
    jb   .next
    xor  eax, eax
    jmp  .out
.bad_dst:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
    jmp  .fail
.changed:
    cmp  dword [rel ext4_disk_last_error], EXT_E_IO
    je   .fail
    mov  dword [rel ext4_disk_last_error], EXT_E_SOURCE_CHANGED
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    ret

; RDI=output, RSI=parent, RDX=name bytes, ECX=length. All byte names supported
; by ext4 (except NUL, '/', '.' and '..') survive; paths remain bounded.
ext_tree_join:
    push rbx
    push r13
    push r14
    mov  rbx, rdi
    mov  r13, rdx
    mov  r14d, ecx
    xor  edx, edx
.length:
    cmp  byte [rsi + rdx], 0
    je   .sized
    inc  edx
    jmp  .length
.sized:
    lea  eax, [rdx + r14 + 1]
    cmp  eax, EXT_PATH_MAX
    jae  .bad
    push rdx
    call memcpy
    pop  rdx
    lea  rdi, [rbx + rdx]
    cmp  rdx, 1
    jne  .slash
    cmp  byte [rbx], '/'
    je   .name
.slash:
    mov  byte [rdi], '/'
    inc  rdi
.name:
    push rdi
    mov  rsi, r13
    mov  edx, r14d
    call memcpy
    pop  rdi
    mov  byte [rdi + r14], 0
    xor  eax, eax
    jmp  .out
.bad:
    mov  dword [rel ext4_disk_last_error], EXT_E_BADPATH
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  rbx
    ret

; R15=current frame, ctx.inode=resolved source directory. Resume by byte offset,
; at most one block and ET_WALK_K records per call: 1 entry, 0 end, 2 yield.
; Explorer's listing capacity has no role in the traversal.
ext_tree_next:
    cmp  dword [rel ext_tree_source_kind], 0
    jne  ext_tree_next_foreign
    push rbx
    push r13
    push r14
    mov  rax, [r15 + ET_CURSOR]
    cmp  rax, [r15 + ET_SIZE]
    jae  .end
    mov  ecx, [r12 + ext_ctx.block_bytes]
    dec  ecx
    test [r15 + ET_SIZE], rcx
    jnz  .corrupt
    cmp  qword [r15 + ET_SIZE], EXT_DIR_MAX_BYTES
    ja   .corrupt
    mov  ecx, [r12 + ext_ctx.block_shift]
    shr  rax, cl
    mov  rsi, rax
    call ext_tree_read_block
    test rax, rax
    jnz  .fail
    mov  r13d, ET_WALK_K
.entry:
    mov  rbx, [r15 + ET_CURSOR]
    mov  ecx, [r12 + ext_ctx.block_bytes]
    dec  ecx
    and  ebx, ecx
    lea  eax, [rbx + 8]
    cmp  eax, [r12 + ext_ctx.block_bytes]
    ja   .corrupt
    mov  r14, [r12 + ext_ctx.dir_buf]
    add  r14, rbx
    movzx ecx, word [r14 + 4]
    cmp  ecx, 8
    jb   .corrupt
    test ecx, 3
    jnz  .corrupt
    lea  eax, [rbx + rcx]
    cmp  eax, [r12 + ext_ctx.block_bytes]
    ja   .corrupt
    movzx edx, byte [r14 + 6]
    lea  eax, [rdx + 8]
    cmp  eax, ecx
    ja   .corrupt
    add  [r15 + ET_CURSOR], rcx
    mov  eax, [r14]
    test eax, eax
    jz   .skip
    cmp  eax, [r12 + ext_ctx.inodes_count]
    ja   .corrupt
    test edx, edx
    jz   .corrupt
    cmp  byte [r14 + 8], '.'
    jne  .scan
    cmp  edx, 1
    je   .skip
    cmp  edx, 2
    jne  .scan
    cmp  byte [r14 + 9], '.'
    je   .skip
.scan:
    xor  ecx, ecx
.byte:
    cmp  ecx, edx
    jae  .name_ok
    mov  al, [r14 + rcx + 8]
    test al, al
    jz   .corrupt
    cmp  al, '/'
    je   .corrupt
    inc  ecx
    jmp  .byte
.name_ok:
    mov  eax, [r14]
    mov  [rel ext_tree_next_ino], eax
    movzx eax, byte [r14 + 7]
    mov  [rel ext_tree_next_type], eax
    push rdx
    mov  ecx, edx
    lea  rdi, [rel ext_tree_next_src]
    lea  rsi, [r15 + ET_SRC]
    lea  rdx, [r14 + 8]
    call ext_tree_join
    pop  rcx
    test rax, rax
    jnz  .fail
    lea  rdi, [rel ext_tree_next_dst]
    lea  rsi, [r15 + ET_DST]
    lea  rdx, [r14 + 8]
    call ext_tree_join
    test rax, rax
    jnz  .fail
    mov  eax, 1
    jmp  .out
.skip:
    mov  rax, [r15 + ET_CURSOR]
    cmp  rax, [r15 + ET_SIZE]
    jae  .end
    mov  ecx, [r12 + ext_ctx.block_bytes]
    dec  ecx
    test rax, rcx
    jz   .yield
    dec  r13d
    jnz  .entry
.yield:
    mov  eax, 2
    jmp  .out
.end:
    xor  eax, eax
    jmp  .out
.corrupt:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
.fail:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  rbx
    ret

; Adapt the native FAT cursor's complete name into both bounded owned paths.
ext_tree_next_foreign:
    push r13
    push r14
    push rbx
    lea  rdi, [r15 + ET_FAT]
    cmp  dword [rel ext_tree_source_kind], 2
    jne  .fat_next
    lea  rsi, [r15 + ET_SRC]
    call ntfs_disk_source_next
    jmp  .next_done
.fat_next:
    call fat32_disk_source_next
.next_done:
    cmp  eax, 1
    jne  .out
    mov  [rel ext_tree_next_ino], r8d
    mov  [rel ext_tree_next_type], r9d
    mov  r13, rdx
    mov  r14d, ecx
    lea  rdi, [rel ext_tree_next_src]
    lea  rsi, [r15 + ET_SRC]
    call ext_tree_join
    test rax, rax
    jnz  .out
    lea  rdi, [rel ext_tree_next_dst]
    lea  rsi, [r15 + ET_DST]
    mov  rdx, r13
    mov  ecx, r14d
    call ext_tree_join
    test rax, rax
    jnz  .out
    mov  eax, 1
.out:
    pop  rbx
    pop  r14
    pop  r13
    ret

ext_tree_step:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8
    mov  rbp, rdi
    mov  rbx, r8
    cmp  dword [rel ext_tree_source_kind], 0
    je   .source_guarded
    cmp  dword [rel ext_cp_phase], EXT_CP_RECLAIM
    je   .source_guarded                ; destination-only reclaim must survive lost source custody
    mov  byte [rel ext_cp_guard_active], 1 ; child terminal closes its read guard
    call ext_cp_source_token
    test rax, rax
    jnz  .changed
.source_guarded:
    cmp  dword [rel ext_tree_stop], 0
    jne  .cancelled
    call ext_w_enter
    test rax, rax
    jz   .no_window
    mov  r12, rax
    call ext_w_job_step_begin
    test rax, rax
    jnz  .no_window
    cmp  dword [rel ext_cp_phase], EXT_CP_RECLAIM
    je   .child
    call ext_tree_check_frames
    test rax, rax
    jnz  .failed
    cmp  dword [rel ext_tree_child], 0
    jne  .child
    call ext_tree_frame_ptr
    cmp  dword [rel ext_tree_phase], ET_MKDIR
    jne  .walk
    mov  eax, [r15 + ET_MODE]
    mov  [rel ext_ns_create_mode], eax
    mov  rdi, rbp
    lea  rsi, [r15 + ET_DST]
    xor  edx, edx
    xor  ecx, ecx
    mov  r8d, FS_MUT_MKDIR
    call ext_ns_mutate                  ; exactly one existing transaction
    mov  dword [rel ext_ns_create_mode], 0
    test rax, rax
    jnz  .failed
    lea  rsi, [r15 + ET_DST]
    call ext_cp_resolve
    test rax, rax
    jnz  .failed
    mov  eax, [r12 + ext_ctx.inode + EXT_SLOT_INO]
    mov  [r15 + ET_DSTINO], eax
    mov  dword [rel ext_tree_phase], ET_WALK
    jmp  .out
.walk:
    cmp  dword [rel ext_tree_source_kind], 0
    jne  .source_ready
    lea  rsi, [r15 + ET_SRC]
    call ext_cp_resolve
    test rax, rax
    jnz  .failed
.source_ready:
    call ext_tree_next
    test rax, rax
    js   .failed
    jz   .pop
    cmp  eax, 2
    je   .out
    cmp  dword [rel ext_tree_source_kind], 0
    je   .local_node
    lea  rdi, [r15 + ET_FAT]
    lea  rsi, [rel ext_tree_next_src]
    cmp  dword [rel ext_tree_source_kind], 2
    jne  .fat_node
    call ntfs_disk_source_node
    jmp  .node_checked
.fat_node:
    call fat32_disk_source_node
.node_checked:
    test rax, rax
    jnz  .node_refused
    test dword [rel ext_tree_next_type], 0x10
    jnz  .directory
    jmp  .file
.local_node:
    lea  rsi, [rel ext_tree_next_src]
    call ext_cp_resolve
    test rax, rax
    jnz  .failed
    mov  eax, [r12 + ext_ctx.inode + EXT_SLOT_INO]
    cmp  eax, [rel ext_tree_next_ino]
    jne  .changed
    lea  rdi, [r12 + ext_ctx.inode]
    mov  edx, [rel ext_tree_next_type]
    call ext_ftype_ok
    jc   .corrupt
    test dword [r12 + ext_ctx.inode + EI_FLAGS], EXT_FL_REFUSED
    jnz  .unsupported
    movzx eax, word [r12 + ext_ctx.inode + EI_MODE]
    and  eax, EXT_S_IFMT
    cmp  eax, EXT_S_IFDIR
    je   .directory
    cmp  eax, EXT_S_IFREG
    jne  .unsupported                   ; symlinks/devices/FIFOs are never followed
.file:
    mov  byte [rel ext_tree_retried], 0   ; E3a: one fresh attempt per walked file
.child_begin:
    mov  byte [rel ext_cp_src_fault], 0  ; smart copy B: this child's own outcome only
    mov  byte [rel ext_cp_stranded], 0
    mov  byte [rel ext_tree_cancel_seen], 0
    lea  rdi, [rel ext_tree_job]
    xor  esi, esi
    mov  edx, fs_copy_job_size
    call memset
    mov  eax, [rbx + fs_copy_job.mount]
    mov  [rel ext_tree_job + fs_copy_job.mount], eax
    mov  dword [rel ext_tree_child], 1
    mov  rdi, rbp
    lea  rsi, [rel ext_tree_next_src]
    lea  rdx, [rel ext_tree_next_dst]
    lea  r8, [rel ext_tree_job]
    xor  r9d, r9d                      ; inside a new tree: no per-child keep-both
    test dword [rel ext_cp_policy], FS_CMODE_SKIPSAME | FS_CMODE_ASK | FS_CMODE_REPLACE
    jz   .child_policy                 ; (E2: an ask walk's children decide as it does; E2r-b2 replace-older too)
    mov  r9d, [rel ext_cp_policy]      ; smart copy C: a merged tree's files meet existing ones
.child_policy:
    call ext_cp_begin                  ; no mutation and no new window
    test rax, rax
    jnz  .child_begin_failed
    mov  rax, [rel ext_cp_size]
    add  rax, [rel ext_tree_base]
    jc   .progress_overflow
    cmp  rax, FS_TOTAL_UNKNOWN          ; reserve the wire's unknown sentinel
    je   .progress_overflow
    cmp  dword [rbx + fs_copy_job.files], -1
    jne  .out
.progress_overflow:
    mov  dword [rel ext_tree_child], 0 ; BEGIN has not published a partial or done IO
    jmp  .too_deep                      ; typed size/counter overflow, keep committed siblings
.child_begin_failed:
    mov  dword [rel ext_tree_child], 0
    mov  ecx, [rel ext4_disk_last_error] ; smart copy B: refused at its BEGIN, nothing written
    test dword [rel ext_cp_policy], FS_CMODE_SKIPSAME | FS_CMODE_ASK | FS_CMODE_REPLACE
    jz   .child_refused
    cmp  dword [rel vfs_copy_refusal], 0
    jne  .child_name_refused             ; smart copy C: keep-both found no free name
    cmp  ecx, EXT_E_EXISTS
    jne  .child_refused
    test dword [rel ext_cp_policy], FS_CMODE_REPLACE
    jz   .dir_conflict                   ; C: a conflict the policy refuses
    cmp  dword [rel vfs_copy_replace_verdict], 0
    jne  .dir_conflict                   ; E2r-b2: undecided: it waits (or is listed)
    inc  dword [rbx + fs_copy_job.skipped]   ; E2r-b2: the destination is not older: SKIPPED, nothing written
    jmp  .out
.child_refused:
    cmp  ecx, EXT_E_SOURCE_CHANGED
    je   .skip_node
    cmp  ecx, EXT_E_UNSUPPORTED
    je   .skip_node
    cmp  ecx, EXT_E_ISDIR
    je   .skip_node
    cmp  ecx, EXT_E_BADPATH
    je   .skip_node
    cmp  ecx, EXT_E_NOTFOUND
    je   .skip_node
    cmp  ecx, EXT_E_RANGE
    je   .skip_node
    jmp  .failed
.node_refused:                           ; smart copy B: a FAT32/NTFS node refused before any write
    mov  ecx, [rel ext4_disk_last_error]
    cmp  ecx, EXT_E_SOURCE_CHANGED
    je   .skip_node
    cmp  ecx, EXT_E_UNSUPPORTED
    je   .skip_node
    jmp  .failed
.deep_node:                              ; smart copy B: neither it nor anything below is made
    mov  ecx, EXT_E_TOOBIG
    mov  [rel ext4_disk_last_error], ecx
.skip_node:                              ; smart copy B: ECX = why; listed, and the walk goes on
    call ext_tree_fail_note
    test eax, eax
    jz   .failed                         ; FS_FAIL_RUN with no commit between: not one bad file
    jmp  .out
.directory:
    mov  eax, [rel ext_tree_depth]
    cmp  eax, FS_TREE_DEPTH_MAX
    jae  .deep_node
    xor  ecx, ecx
    lea  rdx, [rel ext_tree_levels]
    mov  esi, [r12 + ext_ctx.inode + EXT_SLOT_INO]
    cmp  dword [rel ext_tree_source_kind], 0
    je   .cycle
    mov  esi, [rel ext_tree_next_ino]
.cycle:
    cmp  esi, [rdx + ET_SRCINO]
    je   .corrupt
    add  rdx, ET_FRAME
    inc  ecx
    cmp  ecx, eax
    jb   .cycle
    add  r15, ET_FRAME
    mov  rdi, r15
    xor  esi, esi
    mov  edx, ET_FRAME
    call memset
    mov  qword [r15 + ET_BLOCK], -1
    call ext_tree_save_source
    test rax, rax
    jnz  .failed
    lea  rdi, [r15 + ET_SRC]
    lea  rsi, [rel ext_tree_next_src]
    call ext_cp_copy_path
    lea  rdi, [r15 + ET_DST]
    lea  rsi, [rel ext_tree_next_dst]
    call ext_cp_copy_path
    test dword [rel ext_cp_policy], FS_CMODE_SKIPSAME | FS_CMODE_ASK | FS_CMODE_REPLACE
    jnz  .dir_probe
.dir_push:
    inc  dword [rel ext_tree_depth]
    mov  dword [rel ext_tree_phase], ET_MKDIR
    jmp  .out
.dir_probe:                              ; smart copy C: an existing directory there is merged into
    lea  rsi, [r15 + ET_DST]
    call ext_cp_resolve
    test rax, rax
    jz   .dir_existing
    cmp  dword [rel ext4_disk_last_error], EXT_E_NOTFOUND
    je   .dir_push
    jmp  .failed
.dir_existing:
    movzx eax, word [r12 + ext_ctx.inode + EI_MODE]
    and  eax, EXT_S_IFMT
    cmp  eax, EXT_S_IFDIR
    jne  .dir_taken
    mov  eax, [r12 + ext_ctx.inode + EXT_SLOT_INO]
    mov  [r15 + ET_DSTINO], eax
    cmp  dword [rel ext_tree_source_kind], 0
    jne  .dir_merge
    mov  edi, eax
    mov  esi, [rel ext_tree_levels + ET_SRCINO]
    call ext_ns_is_below                 ; never into the tree's source or below it
    test rax, rax
    js   .failed
    jnz  .dir_taken_conflict
.dir_merge:
    inc  dword [rel ext_tree_depth]
    mov  dword [rel ext_tree_phase], ET_WALK
    jmp  .out
.dir_taken:
    test dword [rel ext_cp_policy], FS_CMODE_KEEPBOTH
    jz   .dir_taken_conflict
    lea  rdi, [rel ext_cp_dst]
    lea  rsi, [r15 + ET_DST]
    call ext_cp_copy_path
    mov  [rel ext_cp_dst_len], eax
    call ext_cp_pick                     ; keep-both, as BEGIN's (nothing written)
    test rax, rax
    jnz  .dir_pick_refused
    lea  rdi, [r15 + ET_DST]
    lea  rsi, [rel ext_cp_dst]
    call ext_cp_copy_path
    jmp  .dir_push
.dir_pick_refused:
    cmp  dword [rel vfs_copy_refusal], 0
    je   .failed
.child_name_refused:
    mov  dword [rel vfs_copy_refusal], 0
    jmp  .dir_conflict
.dir_taken_conflict:
    mov  byte [rel ext_tree_cdir], 1     ; E2: an ask walk's item is a directory
.dir_conflict:                           ; C: listed, never a failure run; nothing below it is copied
    mov  ecx, EXT_E_EXISTS
    call ext_tree_conflict_note
    jmp  .out
.pop:
    dec  dword [rel ext_tree_depth]
    jnz  .out
    mov  rax, [rel ext_tree_base]
    mov  [rbx + fs_copy_job.total], rax
    mov  eax, FS_JOB_DONE
    jmp  .finish
.child:
    call ext_w_job_step_done             ; the file engine owns its own STEP grant
.run_child:
    mov  rdi, rbp
    lea  r8, [rel ext_tree_job]
    call ext_cp_step
    mov  eax, [rel ext_tree_job + fs_copy_job.error]
    test eax, eax
    jz   .child_state
    cmp  dword [rbx + fs_copy_job.error], 0
    jne  .child_state
    mov  [rbx + fs_copy_job.error], eax
.child_state:
    mov  eax, [rel ext_tree_job + fs_copy_job.state]
    cmp  eax, FS_JOB_DONE
    je   .committed
    cmp  eax, FS_JOB_DONE
    ja   .child_ended
    mov  [rbx + fs_copy_job.state], eax
    mov  rax, [rel ext_tree_base]
    add  rax, [rel ext_tree_job + fs_copy_job.done]
    mov  [rbx + fs_copy_job.done], rax
    jmp  .return
.child_ended:                            ; smart copy B: a child that failed on its own source,
    cmp  eax, FS_JOB_FAILED              ;   its partial reclaimed: listed, and the walk goes on
    jne  .finish
    cmp  byte [rel ext_cp_stranded], 0
    jne  .finish                         ; its marked partial stays: not one bad file
    mov  ecx, [rel ext_tree_job + fs_copy_job.error]
    cmp  ecx, EXT_E_SOURCE_CHANGED
    jne  .child_no_retry
    cmp  dword [rel ext_tree_source_kind], 0
    jne  .child_no_retry                 ; foreign custody keeps its existing terminal/list behavior
    cmp  qword [rel ext_cp_source_mount], 0
    jne  .child_no_retry                 ; E3a is same-volume ext4 only
    cmp  byte [rel ext_tree_cancel_seen], 0
    jne  .child_no_retry                 ; accepted cancel must never start another copy
    cmp  byte [rel ext_tree_retried], 0
    jne  .child_no_retry                 ; changed twice: list it once, keep walking
    mov  byte [rel ext_tree_retried], 1
    call ext_tree_check_frames          ; reclaim skipped frame checks; re-establish the walk first
    test rax, rax
    jnz  .failed
    mov  dword [rbx + fs_copy_job.error], 0
    mov  dword [rbx + fs_copy_job.state], FS_JOB_RUNNING
    mov  rax, [rel ext_tree_base]
    mov  [rbx + fs_copy_job.done], rax    ; discarded partial bytes never become committed progress
    jmp  .child_begin                    ; fresh source/destination facts, same policy, no new window
.child_no_retry:
    cmp  byte [rel ext_cp_cmp_refused], 0
    jne  .child_conflict                 ; smart copy C: it differs and the policy refuses
    cmp  byte [rel ext_cp_src_fault], 0
    jne  .child_listed
    cmp  ecx, EXT_E_SOURCE_CHANGED
    je   .child_listed
    cmp  ecx, EXT_E_UNSUPPORTED
    jne  .finish
.child_listed:
    call ext_tree_fail_note
    cmp  byte [rel ext_tree_cancel_seen], 0
    jne  .child_cancelled                ; an FSCANCEL met its reclaim: listed, and the tree ends
    test eax, eax
    jnz  .child_skipped
    mov  eax, FS_JOB_FAILED
    jmp  .finish
.child_conflict:
    call ext_tree_conflict_note
    cmp  byte [rel ext_tree_cancel_seen], 0
    jne  .child_cancelled
    jmp  .child_skipped
.child_cancelled:
    mov  dword [rbx + fs_copy_job.error], 0
    mov  eax, FS_JOB_CANCELLED
    jmp  .finish
.child_skipped:
    mov  dword [rel ext_tree_child], 0
    mov  dword [rbx + fs_copy_job.error], 0
    mov  dword [rbx + fs_copy_job.state], FS_JOB_RUNNING
    mov  rax, [rel ext_tree_base]
    mov  [rbx + fs_copy_job.done], rax
    jmp  .return
.committed:
    cmp  dword [rel ext_tree_job + fs_copy_job.same], 0
    jne  .child_same
    cmp  dword [rel ext_tree_job + fs_copy_job.skipped], 0
    jne  .child_not_older
    mov  eax, [rel ext_tree_job + fs_copy_job.replaced]
    add  [rbx + fs_copy_job.replaced], eax   ; E2r-b2: a child that replaced an older file
    mov  rax, [rel ext_tree_job + fs_copy_job.total]
    add  [rel ext_tree_base], rax
    mov  dword [rbx + fs_copy_job.fail_run], 0   ; smart copy B: a commit ends a run of failures
    inc  dword [rbx + fs_copy_job.files]
    mov  rax, [rel ext_tree_base]
    mov  [rbx + fs_copy_job.done], rax
    mov  dword [rbx + fs_copy_job.state], FS_JOB_RUNNING
    mov  dword [rel ext_tree_child], 0
    jmp  .return
.child_same:                             ; smart copy C: equal and left alone: counted, nothing copied
    inc  dword [rbx + fs_copy_job.same]
    jmp  .child_nocopy
.child_not_older:
    inc  dword [rbx + fs_copy_job.skipped]
.child_nocopy:
    mov  dword [rbx + fs_copy_job.fail_run], 0
    mov  rax, [rel ext_tree_base]
    mov  [rbx + fs_copy_job.done], rax
    mov  dword [rbx + fs_copy_job.state], FS_JOB_RUNNING
    mov  dword [rel ext_tree_child], 0
    jmp  .return
.no_window:
    cmp  dword [rel ext_tree_child], 0
    jne  .run_child                     ; existing reclaim/denied lifetime remains authoritative
    jmp  .failed
.changed:
    mov  dword [rel ext4_disk_last_error], EXT_E_SOURCE_CHANGED
    jmp  .failed
.corrupt:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
    jmp  .failed
.unsupported:
    mov  ecx, EXT_E_UNSUPPORTED          ; smart copy B: a node never followed is listed, not an end
    mov  [rel ext4_disk_last_error], ecx
    jmp  .skip_node
.too_deep:
    mov  dword [rel ext4_disk_last_error], EXT_E_TOOBIG
.failed:
    call ext_cp_note_error
    cmp  dword [rel ext_tree_child], 0
    je   .failed_now
    mov  eax, [rbx + fs_copy_job.error]
    mov  [rel ext_tree_job + fs_copy_job.error], eax
    mov  dword [rel ext_cp_target], FS_JOB_FAILED
    mov  dword [rel ext_cp_phase], EXT_CP_RECLAIM
    mov  dword [rel ext_tree_job + fs_copy_job.state], FS_JOB_CANCELLING
    mov  dword [rbx + fs_copy_job.state], FS_JOB_CANCELLING
    jmp  .out
.failed_now:
    mov  eax, FS_JOB_FAILED
    jmp  .finish
.cancelled:
    mov  eax, FS_JOB_CANCELLED
.finish:
    mov  [rbx + fs_copy_job.state], eax
    mov  rax, [rel ext_tree_base]         ; terminal progress counts committed files only
    mov  [rbx + fs_copy_job.done], rax
    call ext_tree_forget                 ; window/grant/buffer close on every terminal path
    jmp  .return
.out:
    call ext_w_job_step_done
.return:
    xor  eax, eax
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; ext_tree_fail_note(RBX=tree job, ECX=error) -> RAX 1 the walk goes on / 0 it ends. Smart copy B:
;   lists the node ext_tree_next_src names (its source path) through vfs_copy_fail_note.
ext_tree_fail_note:
    push rcx
    lea  rsi, [rel ext_tree_next_src]
    xor  edx, edx
.len:
    cmp  byte [rsi + rdx], 0
    je   .note
    inc  edx
    cmp  edx, EXT_PATH_MAX
    jb   .len
.note:
    pop  rcx
    mov  rdi, rbx
    cmp  ecx, EXT_E_SOURCE_CHANGED
    je   vfs_copy_source_note          ; E3: exhausted recopy is an item outcome
    jmp  vfs_copy_fail_note

; ext_tree_conflict_note(RBX=tree job, ECX=error) -> RAX 1. Smart copy C: a conflict the policy refuses,
;   listed and counted as ext_tree_fail_note does, but never part of a run of failures (not a fault).
;   E2: under FS_CMODE_ASK it waits instead (ext_tree_wait), listed only when it cannot.
ext_tree_conflict_note:
    push rbp
    push r12
    sub  rsp, 8
    mov  r12d, ecx
    movzx edi, byte [rel ext_tree_cdir]
    mov  byte [rel ext_tree_cdir], 0
    test dword [rel ext_cp_policy], FS_CMODE_ASK | FS_CMODE_REPLACE
    jz   .listed                         ; (E2r-b2: a replace-older tree asks too)
    call ext_tree_wait
    cmp  eax, 1
    je   .out
.listed:
    mov  ebp, [rbx + fs_copy_job.fail_run]
    mov  ecx, r12d
    call ext_tree_fail_note
    mov  [rbx + fs_copy_job.fail_run], ebp
.out:
    mov  eax, 1
    add  rsp, 8
    pop  r12
    pop  rbp
    ret

; ext_tree_wait(RBX=tree job, EDI = 1 a directory / 0 a file) -> EAX 1 taken by the job's WAITING list
;   (vfs_copy_wait_note) / 2 not. E2: the entry's source and destination paths as the walk named them.
ext_tree_wait:
    sub  rsp, 8
    mov  esi, FS_WK_FILE
    test edi, edi
    jz   .kind
    mov  esi, FS_WK_DIR
.kind:
    lea  rdx, [rel ext_tree_next_src]
    xor  ecx, ecx
.slen:
    cmp  byte [rdx + rcx], 0
    je   .dst
    inc  ecx
    cmp  ecx, EXT_PATH_MAX
    jb   .slen
.dst:
    lea  r8, [rel ext_tree_next_dst]
    xor  r9d, r9d
.dlen:
    cmp  byte [r8 + r9], 0
    je   .note
    inc  r9d
    cmp  r9d, EXT_PATH_MAX
    jb   .dlen
.note:
    mov  rdi, rbx
    call vfs_copy_wait_note
    add  rsp, 8
    ret

ext_tree_cancel:
    cmp  dword [rel ext_tree_child], 0
    jne  .child
    mov  dword [rel ext_tree_stop], FS_JOB_CANCELLED
    jmp  .state
.child:
    mov  byte [rel ext_tree_cancel_seen], 1   ; smart copy B: a failed child's reclaim ends the tree
    push r8
    lea  r8, [rel ext_tree_job]
    call ext_cp_cancel
    pop  r8
.state:
    mov  dword [r8 + fs_copy_job.state], FS_JOB_CANCELLING
    xor  eax, eax
    ret

; ext_cp_take_foreign_mt: E2t (root 2026-10-17 21:04:41: every copy carries the source mtime), the bound
;   FAT32/NTFS/exFAT source's modification time (UTC) into ext_cp_mt_*; unknown: nothing carried, the new
;   file keeps the copy's own stamp. Clobbers RAX, RCX, RDX, RSI, RDI, R8-R11.
ext_cp_take_foreign_mt:
    cmp  byte [rel ext_cp_source_kind], 3
    je   .exfat
    cmp  byte [rel ext_cp_source_kind], 2
    je   .ntfs
    call fat32_disk_source_mtime
    jmp  .got
.exfat:
    call exfat_disk_source_mtime
    jmp  .got
.ntfs:
    call ntfs_disk_source_mtime
.got:
    jc   .out
    call ext_cp_set_mt
.out:
    ret

; ext_cp_older(R12 = destination ctx, ctx.inode = the existing destination; the source's time taken) -> EAX
;   1 older: replace it / 0 newer or within 2 s / 2 undecided: a time unknown on either side, or not a file
;   this copy may replace (not regular, a refused flag, the source itself). E2r (root 2026-10-17 21:04:41).
;   E2r-b: under FS_CMODE_FORCE a file it may replace is 1 whatever the times. Clobbers RCX, RDX, R8.
ext_cp_older:
    movzx eax, word [r12 + ext_ctx.inode + EI_MODE]
    and  eax, EXT_S_IFMT
    cmp  eax, EXT_S_IFREG
    jne  .undecided
    test dword [r12 + ext_ctx.inode + EI_FLAGS], EXT_W_FL_REFUSED
    jnz  .undecided                      ; immutable / append-only / a flag the writer refuses
    cmp  qword [rel ext_cp_source_mount], 0
    jne  .times
    mov  eax, [r12 + ext_ctx.inode + EXT_SLOT_INO]
    cmp  eax, [rel ext_cp_src_ino]
    je   .undecided                      ; the source itself (another name of it)
.times:
    test dword [rel ext_cp_policy], FS_CMODE_FORCE
    jnz  .forced                         ; E2r-b: FSANSWER EACH= replace: the user's choice, no time compare
    cmp  byte [rel ext_cp_mt_on], 0
    je   .undecided                      ; the source's time is unknown
    call ext_cp_inode_mt
    mov  rcx, rax
    mov  r8d, edx
    mov  rax, [rel ext_cp_mt_s]
    mov  edx, [rel ext_cp_mt_ns]
    jmp  vfs_mtime_older
.undecided:
    mov  eax, 2
    ret
.forced:
    mov  eax, 1
    ret

; ext_cp_inode_mt(R12 = ctx, ctx.inode) -> RAX = i_mtime with i_mtime_extra's epoch bits, EDX = its
;   nanoseconds when the inode's extra area holds them (both 0: never stamped). Clobbers RCX.
ext_cp_inode_mt:
    movsxd rax, dword [r12 + ext_ctx.inode + EI_MTIME]
    xor  edx, edx
    cmp  dword [r12 + ext_ctx.inode_size], 128
    jbe  .base
    movzx ecx, word [r12 + ext_ctx.inode + EI_EXTRA_ISIZE]
    cmp  ecx, EI_MTIME_EXTRA - 0x80 + 4
    jb   .base
    mov  edx, [r12 + ext_ctx.inode + EI_MTIME_EXTRA]
    mov  ecx, edx
    and  ecx, 3
    shl  rcx, 32
    add  rax, rcx                        ; epoch bits beyond the signed 32-bit field
    shr  edx, 2                          ; nanoseconds
.base:
    ret

; ext_cp_take_ext_mt(R12 = the source's context, its inode resolved): E2t, i_mtime with i_mtime_extra's
;   epoch bits and nanoseconds when the inode's extra area holds them. 0 (never stamped): nothing carried.
;   Clobbers RAX, RCX, RDX.
ext_cp_take_ext_mt:
    call ext_cp_inode_mt
    test rax, rax
    jnz  .known
    test edx, edx
    jz   .out
.known:
    call ext_cp_set_mt
.out:
    ret

; ext_cp_mt_fit(R12 = the destination's context): E2t (SOURCE review F1, 2026-10-18 00:31): a source mtime the
;   destination's new inode cannot encode is unknown (nothing carried, never wrapped; the copy keeps its own
;   stamp). i_mtime is signed 32-bit seconds; i_mtime_extra's two epoch bits extend it to 2^31-1 + 3 * 2^32
;   (2446-05-10) when the new inode has that field: ext_ns gives it min(inode size - 128, EI_EXTRA_DEFAULT)
;   extra bytes, so an inode size of at least 140. Below 1901-12-13 (-2^31) never fits. Clobbers RAX, RCX.
ext_cp_mt_fit:
    cmp  byte [rel ext_cp_mt_on], 0
    je   .out
    mov  rax, [rel ext_cp_mt_s]
    cmp  rax, -0x80000000
    jl   .unknown
    mov  ecx, 0x7FFFFFFF                 ; no i_mtime_extra: the signed 32-bit field only
    cmp  dword [r12 + ext_ctx.inode_size], 128 + EI_MTIME_EXTRA - 0x80 + 4
    jb   .max
    mov  rcx, 0x37FFFFFFF                ; 2^31-1 + 3 * 2^32
.max:
    cmp  rax, rcx
    jle  .out
.unknown:
    mov  byte [rel ext_cp_mt_on], 0
.out:
    ret

; ext_cp_set_mt(RAX = Unix seconds, EDX = nanoseconds): the copy's commit writes them (E2t).
ext_cp_set_mt:
    mov  [rel ext_cp_mt_s], rax
    mov  [rel ext_cp_mt_ns], edx
    mov  byte [rel ext_cp_mt_on], 1
    ret

str_ecp_name:   db ".paoscopy-"
str_ecp_hex:    db "0123456789abcdef"

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
%macro WDATA_fs_ext4_copy 0
ext_cp_phase:      resd 1                  ; EXT_CP_*
ext_cp_target:     resd 1                  ; FS_JOB_CANCELLED / FS_JOB_FAILED after reclaim
ext_cp_tag:        resd 1                  ; marker: crc32c(dst leaf) | 1 = the partial's i_generation
ext_cp_mode:       resd 1
ext_cp_src_ino:    resd 1
ext_cp_part_ino:   resd 1
ext_cp_snap:       resd 1
ext_cp_src_len:    resd 1
ext_cp_dst_len:    resd 1
ext_cp_part_len:   resd 1
ext_cp_size:       resq 1
ext_cp_mt_s:       resq 1                  ; E2t: the source's mtime, Unix seconds
ext_cp_mt_ns:      resd 1                  ;   and nanoseconds
ext_cp_mt_on:      resb 1                  ;   1 = known: the commit writes it
ext_cp_victim:     resd 1                  ; E2r: the older destination file the commit replaces (0 none)
ext_cp_victim_snap: resd 1                 ;   its inode snapshot at BEGIN (ext_cp_snapshot)
ext_cp_orphan:     resd 1                  ;   the replaced file still on the orphan list (EXT_CP_ORPHAN)
alignb 8
ext_cp_done:       resq 1
ext_cp_psize:      resq 1                  ; the partial's size: end of its last written chunk
ext_cp_vdone:      resq 1
ext_cp_trim:       resq 1                  ; reclaim piece: EXT_CP_TRIM at BEGIN, halved on TOOBIG
ext_cp_buf:        resq 1                  ; 2 * EXT_CP_STEP while a job is live
ext_cp_src:        resb EXT_PATH_MAX
ext_cp_dst:        resb EXT_PATH_MAX
ext_cp_part:       resb EXT_PATH_MAX
%endmacro
WDATA_BSS_DEFER WDATA_fs_ext4_copy
; RCQ-20 S3: its own block (WDATA_fs_ext4_copy's layout is pinned by the zero-storage move)
%macro WDATA_BSS_fs_ext4_copy_s3 0
ext_cp_stale:      resb 1                  ; ext_cp_part_ino is an earlier attempt's partial
%endmacro
WDATA_BSS_DEFER WDATA_BSS_fs_ext4_copy_s3
; RCQ-20 S4: its own block, like S3's
%macro WDATA_BSS_fs_ext4_copy_s4 0
ext_cp_hold_partial: resb 1
alignb 4
ext_cp_policy:     resd 1                  ; FS_CMODE_* of the BEGIN
ext_cp_kept:       resd 1                  ; 0 refuse; keep-both: the k of ext_cp_dst
%endmacro
WDATA_BSS_DEFER WDATA_BSS_fs_ext4_copy_s4
; RCQ-20 S5c: its own block, like S3's and S4's
%macro WDATA_BSS_fs_ext4_copy_s5c 0
ext_cp_carried:    resb 1                  ; 1: this BEGIN is the dequeue's FS_COPY_BEGIN_CARRIED
%endmacro
WDATA_BSS_DEFER WDATA_BSS_fs_ext4_copy_s5c
; Smart copy C: its own block, like S3's and S4's
%macro WDATA_BSS_fs_ext4_copy_same 0
ext_cp_cmp_size:   resq 1                  ; the existing destination file's size at BEGIN
ext_cp_cmp_ino:    resd 1                  ; its inode, and its snapshot: changed meanwhile = not equal
ext_cp_cmp_snap:   resd 1
ext_cp_cmp_len:    resd 1
ext_tree_merge_ino: resd 1                 ; the existing top directory a tree merges into (0 made)
ext_cp_cmp_on:     resb 1                  ; the file job compares an existing destination first
ext_cp_cmp_refused: resb 1                 ; it differed and the policy refused (a tree lists it)
ext_cp_cmp:        resb EXT_PATH_MAX       ; the existing file's path (keep-both moves ext_cp_dst away)
%endmacro
WDATA_BSS_DEFER WDATA_BSS_fs_ext4_copy_same
%macro WDATA_BSS_fs_ext4_copy_tree 0
ext_tree_source_kind: resd 1              ; 0 local ext4, 1 FAT32, 2 NTFS; separate regular enum
ext_tree_active:    resd 1
ext_tree_child:     resd 1
ext_tree_depth:     resd 1
ext_tree_phase:     resd 1
ext_tree_stop:      resd 1
ext_tree_next_ino:  resd 1
ext_tree_next_type: resd 1
ext_tree_base:      resq 1
ext_tree_job:       resb fs_copy_job_size
ext_tree_levels:    resb FS_TREE_DEPTH_MAX * ET_FRAME
ext_tree_next_src:  resb EXT_PATH_MAX
ext_tree_next_dst:  resb EXT_PATH_MAX
ext_tree_cdir:      resb 1               ; E2: the conflict being noted is a directory's
%endmacro
WDATA_BSS_DEFER WDATA_BSS_fs_ext4_copy_tree
; Smart copy B: its own block, like S3's and S4's
%macro WDATA_BSS_fs_ext4_copy_fail 0
ext_cp_src_fault:     resb 1              ; the live child failed reading its source
ext_cp_stranded:      resb 1              ; its reclaim failed: the marked partial stays
ext_tree_retried: resb 1                  ; E3a: current walked file already had its one recopy
ext_tree_cancel_seen: resb 1              ; FSCANCEL reached a live child
%endmacro
WDATA_BSS_DEFER WDATA_BSS_fs_ext4_copy_fail

%macro WDATA_BSS_fs_ext4_cross_copy 0
alignb 8
ext_cp_guard_active: resb 1
ext_cp_source_kind:   resb 1             ; 0=ext, 1=FAT32, 2=NTFS, 3=exFAT
alignb 8
ext_cp_incoming:       resq 1
ext_cp_source_mount:   resq 1
ext_cp_source_ctx:     resq 1
ext_cp_source_dev:     resq 1
ext_cp_source_ops:     resq 1
ext_cp_source_priv:    resq 1
ext_cp_source_info:    resq 1
ext_cp_source_max:     resq 1
ext_cp_source_unit:    resd 1
alignb 8
ext_cp_source_blkgeo:  resb blk_info_size - blk_info.logical_sector_bytes
ext_cp_source_gen:     resq 1
ext_cp_source_lba:     resq 1
ext_cp_source_sectors: resq 1
ext_cp_source_uuid:    resb 16
ext_cp_source_sb:      resb 1024
%endmacro
WDATA_BSS_DEFER WDATA_BSS_fs_ext4_cross_copy
