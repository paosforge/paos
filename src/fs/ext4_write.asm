;; MODULE fs/ext4_write
;; LAYER 4
;; EXPORTS ext4_disk_arm, ext4_disk_disarm, ext4_disk_truncate, ext_op_write_at_path, ext_op_mutate_path, ext_op_mutate_armed, ext_w_mark_ptr, ext_w_mark_ino, ext_w_carry_record, ext_w_carry_check, ext_w_put_mtime
;; IMPORTS fs/ext4_disk, fs/vfs, fs/blockdev, fs/storage_access, fs/vol_owner, core/lib/mem, core/heap, core/time, boot/serial, boot/header
;; CAPS CAP_BLOCK_READ, CAP_BLOCK_WRITE
;; OWNER saga:rcq20_filesystems
;; CONTEXT: bsp_only  (RCQ-21 SA2b: owned-mode transactions call the BSP-only owned-write API; job state is unlocked)
; ============================================================================
; fs/ext4_write.asm — RCQ-20 E2a: journaled content writes for regular,
; extent-mapped files on ext4 volumes mounted by fs/ext4_disk.
;
; AUTHORITY. Nothing is written until ext4_disk_arm(handle, uuid) binds this
;   mount to the exact superblock UUID, device and partition window. Arming
;   and EVERY later transaction call storage_access_require_request for the
;   whole partition window: a Linux partition classifies SENSITIVE, so it needs
;   the request-scoped SPECIAL intent (owner-signed request) and is audited by
;   that gate; only RAM/QEMU-scratch media pass implicitly. Each transaction
;   also re-reads the on-disk superblock and journal superblock and refuses if
;   the UUID, state, features, geometry or journal position moved since arm.
;
; WRITE GATE (arm and every transaction; EXT_E_WGATE): clean state, no
;   RECOVER, internal journal (inode 8, no external device), EXTENTS present,
;   incompat within {FILETYPE, EXTENTS, 64BIT, FLEX_BG, EA_INODE, CSUM_SEED,
;   LARGEDIR}, ro_compat within {SPARSE_SUPER, LARGE_FILE, HUGE_FILE,
;   DIR_NLINK, EXTRA_ISIZE, METADATA_CSUM} (so GDT_CSUM-only, quota, project,
;   orphan-present, verity, shared-blocks and read-only volumes are refused),
;   no FAST_COMMIT; journal superblock v1/v2, matching block size, EMPTY
;   (s_start == 0), no error, jbd2 incompat within {REVOKE, 64BIT, CSUM_V3},
;   no compat/ro_compat bits, a verified CSUM_V3 checksum when present.
;
; ONE OPERATION = ONE BOUNDED TRANSACTION, ALL-OLD OR ALL-NEW.
;   Data is copy-on-write: every rewritten logical block gets a freshly
;   allocated physical block, written before the commit. Metadata (inode-table
;   block, extent-tree blocks, block bitmaps, descriptor blocks, superblock)
;   is assembled in a bounded transaction cache (EXT_TXN_MAX blocks, one jbd2
;   descriptor) and then:
;     1. new data blocks written;
;     2. the on-disk superblock gains RECOVER; FLUSH;
;     3. journal superblock -> s_start = s_first, s_sequence = T; descriptor
;        + metadata copies (0xC03B3998-leading blocks escaped); FLUSH;
;        commit block; FLUSH;
;     4. checkpoint: metadata to its home blocks; FLUSH;
;     5. journal superblock -> s_start = 0, s_sequence = T+1; FLUSH;
;        superblock RECOVER cleared; FLUSH.
;   A cut before the commit is durable leaves the old state (the new data
;   lives only in blocks the committed bitmaps still call free); after it, jbd2
;   recovery (Linux, e2fsck) replays T. Each transaction restarts at s_first
;   with a fresh sequence after the journal was emptied, so stale descriptors
;   never replay and no revoke records are needed. Allocation never reuses a
;   block freed in the same transaction (all allocations precede all frees).
;   The extent tree of the file is rebuilt from its (bounded) extent list at
;   minimum depth on every operation, reusing its old tree blocks.
;
; OPERATIONS (regular, extent-mapped files only; others EXT_E_UNSUPPORTED):
;   write_at_path (overwrite / append / extend with holes), mutate_path
;   FS_MUT_UPDATE (replace the whole content), ext4_disk_truncate (shrink
;   frees blocks and zeroes the new tail; grow leaves a hole). Namespace
;   operations, ext3 indirect maps and ext2 are later slices (E2b/E2c).
;   Inode timestamps are not updated (no wall clock contract here).
;
; OWNED MODE (RCQ-21 SA2b; rc-sec ruling RCQ-21-SA2b-writer-design 16:00:57). An
;   ext volume the owner adopted (FSOWN ADOPT, a SPECIAL owner act) and armed by
;   the verified OWNER principal binds at arm (vol_owner_bind_mount) instead of
;   taking the request grant. Every transaction - request-driven ones only for the
;   OWNER, copy STEPs under the job BEGIN the OWNER started - then opens its own
;   owned op over the partition window (storage_access_owned_op_begin: the whole
;   volume re-probed), writes only through blk_write_owned (re-probed per write; a
;   refusal is final, never retried) and ends the op with the transaction
;   (ext_w_invalidate). No token, a DUP, a refused probe or any other principal
;   takes the gates above unchanged: never an upgrade. Compiled out of a public
;   build while the public owner-identity HOLD stands.
; ============================================================================

%define EXT_W_OWNED 1
%ifdef PAOS_PUBLIC_BUILD
%if PAOS_PUBLIC_BUILD != 0
%define EXT_W_OWNED 0
%endif
%endif

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place

EXT_TXN_MAX          equ 40                   ; metadata blocks per transaction
EXT_XL_MAX           equ 1024                 ; extents per file this slice rewrites
EXT_TL_MAX           equ 2048                 ; tree blocks per file (extent nodes; indirect blocks for E2c)
EXT_IND_BUF          equ 4096                 ; indirect-map writes: block sizes up to 4 KiB
EXT_E_NOJOURNAL      equ 18                   ; ext2 (no journal): writes are not offered
EXT_NR_MAX           equ 256                  ; newly allocated data runs per operation
EXT_FR_MAX           equ 3200                 ; runs freed per operation
EXT_TG_MAX           equ 40                   ; block groups touched per operation
EXT_W_MAX_BLOCKS     equ 16384                ; rewritten data blocks per operation
EXT_SZ_MAX           equ 8192                 ; system-zone runs collected BEFORE merging (up to 3 per
                                              ; group plus backups and journal runs): a volume with more
                                              ; than about 2700 groups (~340 GiB at 4 KiB) is refused at
                                              ; arm (fails closed); merged runs are far fewer
EXT_DI_MAX           equ 8                    ; inodes changed by one operation
EXT_DB_MAX           equ 16                   ; directory blocks changed by one operation
EXT_DI_MTIME         equ 1                    ; dirty-inode flags: content or entries changed
EXT_DI_NEW           equ 2                    ;   created in this transaction (a/c/m/crtime)
EI_ATIME             equ 0x08
EI_CTIME             equ 0x0C
EI_MTIME             equ 0x10
EI_CTIME_EXTRA       equ 0x84
EI_MTIME_EXTRA       equ 0x88
EI_ATIME_EXTRA       equ 0x8C
EI_CRTIME            equ 0x90
EI_CRTIME_EXTRA      equ 0x94
EI_FILE_ACL_LO       equ 0x68                 ; the inode's extended-attribute block
EI_FILE_ACL_HI       equ 0x76
EGD_FREE_INODES_LO   equ 0x0E
EGD_USED_DIRS_LO     equ 0x10
EGD_IBITMAP_CSUM_LO  equ 0x1A
EGD_ITABLE_UNUSED_LO equ 0x1C
EGD_FREE_INODES_HI   equ 0x2E
EGD_USED_DIRS_HI     equ 0x30
EGD_ITABLE_UNUSED_HI equ 0x32
EGD_IBITMAP_CSUM_HI  equ 0x3A
ESB_FREE_INODES      equ 0x10
ESB_RESERVED_GDT     equ 0xCE
EXT_RO_SPARSE_SUPER  equ 0x1
EXT_COMPAT_SPARSE_SUPER2 equ 0x200
EGD_IBITMAP_LO       equ 0x04
EGD_IBITMAP_HI       equ 0x24
EXT_UNINIT_MAX       equ 32767
EXT_INIT_MAX         equ 32768

EXT_W_IN_ALLOWED     equ 0x2 | 0x40 | 0x80 | 0x200 | 0x400 | 0x2000 | 0x4000
EXT_W_RO_ALLOWED     equ 0x1 | 0x2 | 0x8 | 0x20 | 0x40 | 0x400
EXT_RO_LARGE_FILE    equ 0x2
EXT_RO_HUGE_FILE     equ 0x8
EXT_COMPAT_FAST_COMMIT equ 0x400
ESB_FREE_LO          equ 0x0C
ESB_FREE_HI          equ 0x158
ESB_JOURNAL_INUM     equ 0xE0
ESB_LAST_ORPHAN      equ 0xE8                 ; head of the orphan list (inode number, 0 = none)
EI_DTIME             equ 0x14                 ; on an orphan: the next orphan's number
EXT_W_PIECE          equ 1 << 30              ; a large shrink frees at most this much per transaction (halved on TOOBIG)
ESB_JOURNAL_DEV      equ 0xE4
EXT_JOURNAL_INO      equ 8

EGD_BITMAP_LO        equ 0x00
EGD_FREE_LO          equ 0x0C
EGD_BBITMAP_CSUM_LO  equ 0x18
EGD_BITMAP_HI        equ 0x20
EGD_FREE_HI          equ 0x2C
EGD_BBITMAP_CSUM_HI  equ 0x38
EGD_BLOCK_UNINIT     equ 2

EXT_W_FL_REFUSED     equ EXT_FL_REFUSED | 0x10 | 0x20 | 0x40000 | 0x100000 | 0x200000
                     ; + immutable, append-only, huge_file, verity, EA inode

; jbd2 (big-endian on disk; constants below are the little-endian dword view)
JBD2_MAGIC_LE        equ 0x98393BC0           ; bytes C0 3B 39 98
JBD2_MAGIC           equ 0xC03B3998
JBD2_DESCRIPTOR      equ 1
JBD2_COMMIT          equ 2
JBD2_FLAG_ESCAPE     equ 1
JBD2_FLAG_SAME_UUID  equ 2
JBD2_FLAG_LAST_TAG   equ 8
JBD2_IN_REVOKE       equ 1
JBD2_IN_64BIT        equ 2
JBD2_IN_CSUM_V3      equ 0x10
JSB_BLOCKTYPE        equ 0x04
JSB_BLOCKSIZE        equ 0x0C
JSB_MAXLEN           equ 0x10
JSB_FIRST            equ 0x14
JSB_SEQUENCE         equ 0x18
JSB_START            equ 0x1C
JSB_ERRNO            equ 0x20
JSB_COMPAT           equ 0x24
JSB_INCOMPAT         equ 0x28
JSB_ROCOMPAT         equ 0x2C
JSB_UUID             equ 0x30
JSB_CSUM_TYPE        equ 0x50
JSB_CHECKSUM         equ 0xFC

EXT_MODE_WRITE       equ 0
EXT_MODE_UPDATE      equ 1
EXT_MODE_TRUNC       equ 2

struc ext_wks
  .txn_n:        resd 1
  .xl_n:         resd 1
  .xl2_n:        resd 1
  .tl_n:         resd 1
  .nr_n:         resd 1
  .fr_n:         resd 1
  .tg_n:         resd 1
  .depth:        resd 1
  .leaves:       resd 1
  .idxblocks:    resd 1
  .ntree:        resd 1
  .mode:         resd 1
  .free_delta:   resq 1
  .w_off:        resq 1
  .w_buf:        resq 1
  .w_len:        resq 1
  .content_size: resq 1
  .new_size:     resq 1
  .cut:          resq 1
  .ra_lo:        resq 1
  .ra_hi:        resq 1
  .rb_lo:        resq 1
  .rb_hi:        resq 1
  .prev_end:     resq 1
  .rm:           resq 6                   ; up to 3 removed intervals [lo,hi), sorted
  .rm_n:         resq 1
  .jmap0:        resq 1                   ; journal superblock home
  .sz_n:         resq 1
  .tig_n:        resd 1                   ; groups whose inode bitmap this operation touched
  .di_n:         resd 1
  .db_n:         resd 1
  .ns_pad:       resd 1
  .ifree_delta:  resq 1
  .tig:          resd EXT_TG_MAX
  .di_ino:       resd EXT_DI_MAX
  .di_ptr:       resq EXT_DI_MAX
  .di_flags:     resd EXT_DI_MAX          ; EXT_DI_* per dirty inode (timestamps at ext_w_end)
  .ind:          resd 1                   ; 1 = the collected inode is indirect-mapped (E2c)
  .open:         resd 1                   ; 1 between a successful ext_w_begin and its end/abort
  .owned_handle: resq 1                   ; RCQ-21 SA2b: this transaction's owned op (0 = none)
  .job_tag:      resq 1                   ; this transaction's job window (ext_w_job_mode) / 0: request gate
  .ind_n:        resd 1                   ; indirect nodes opened by the serializer
  .tlk:          resq EXT_TL_MAX          ; indirect: position key of each old node in .tl
  .ntk:          resq EXT_TL_MAX          ; indirect: position key of each needed node in .nt
  .iw_key:       resq 6                   ; indirect walk: open node per position slot (-1 none)
  .iw_idx:       resd 6                   ;   its index in .nt
  .iw_buf:       resb 6 * EXT_IND_BUF     ;   its new content
  .db_seed:      resd EXT_DB_MAX
  .db_ptr:       resq EXT_DB_MAX
  .leaf_ptr:     resq 1                   ; namespace operations: the last path component
  .leaf_len:     resq 1
  .par_ptr:      resq 1
  .par_len:      resq 1
  .tmp_ext:      resq 2
  .sleaf_ptr:    resq 1                   ; RENAME: the source name
  .sleaf_len:    resq 1
  .pslot:        resb EXT_SLOT            ; parent directory (source side)
  .p2slot:       resb EXT_SLOT            ; parent directory (rename destination side)
  .cslot:        resb EXT_SLOT            ; the child being created/removed/moved
  .vslot:        resb EXT_SLOT            ; RENAME over a name (E2r): the file it replaces
  .sz_per:       resq 1                   ; superblock + GDT + reserved-GDT blocks per backup group
  .sz:           resq EXT_SZ_MAX * 2      ; system zones {start, end) sorted, merged
  .txn_blk:      resq EXT_TXN_MAX
  .jmap:         resq EXT_TXN_MAX + 2
  .tl:           resq EXT_TL_MAX          ; old tree blocks
  .nt:           resq EXT_TL_MAX          ; new tree blocks
  .tg:           resd EXT_TG_MAX
  .xl:           resb EXT_XL_MAX * 16     ; {lblk d, len w, uninit w, pblk q}
  .xl2:          resb EXT_XL_MAX * 16
  .nr:           resb EXT_NR_MAX * 16
  .fr:           resb EXT_FR_MAX * 16     ; {pblk q, count q}
  .bounce:       resb EXT_BUF_BYTES
  .desc:         resb EXT_BUF_BYTES
  .commit:       resb EXT_BUF_BYTES
  .jsb:          resb EXT_BUF_BYTES       ; journal superblock as last written
  .sbo:          resb EXT_BUF_BYTES       ; committed superblock block (step 2)
  .bufs:         resb EXT_TXN_MAX * EXT_BUF_BYTES
endstruc

; ---------------------------------------------------------------------------
; ext4_disk_arm(RDI=VFS handle, RSI=16-byte volume UUID) -> RAX 0 / -1.
;   Binds write authority to this mount's exact UUID, device and partition
;   window after the write gate and the storage-access gate pass.
; ---------------------------------------------------------------------------
ext4_disk_arm:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  dword [rel ext4_disk_last_error], EXT_E_NONE
    mov  r13, rsi
    call ext_w_ctx_of
    test rax, rax
    jz   .wgate
    mov  r12, rax
    mov  dword [r12 + ext_ctx.armed], 0
    cmp  [rel ext_w_job_ctx], r12
    jne  .no_job
    call ext_w_job_close                 ; any (re-)arm is a disarm first: the copy window ends
.no_job:
    mov  qword [r12 + ext_ctx.owned_token], 0   ; any (re-)arm starts unbound
    test r13, r13
    jz   .wgate
    cmp  qword [r12 + ext_ctx.wks], 0
    jne  .have_wks
    mov  rdi, ext_wks_size
    call kmalloc
    test rax, rax
    jz   .wgate
    mov  rdx, rax                        ; kmalloc does not zero (UEFI pool): the workspace starts all zero, so
    mov  rdi, rax                        ; nothing is read before it is written (open/tig_n: no transaction for
    xor  eax, eax                        ; the reader's INODE_UNINIT check; owned_handle: no op until one opens)
    mov  ecx, ext_wks_size
    cld
    rep  stosb
    mov  rax, rdx
    mov  [r12 + ext_ctx.wks], rax
.have_wks:
    mov  rsi, r13
    call ext_w_check_sb
    test rax, rax
    jnz  .fail
    mov  esi, EXT_JOURNAL_INO
    lea  rdi, [r12 + ext_ctx.jino]
    call ext_read_inode
    test rax, rax
    jnz  .wgate
    movzx eax, word [r12 + ext_ctx.jino + EI_MODE]
    and  eax, EXT_S_IFMT
    cmp  eax, EXT_S_IFREG
    jne  .wgate
    ; extent- or indirect-mapped (ext3) journal: ext_map and ext_w_collect read both
    mov  edi, 1                          ; adopt the sequence found
    call ext_w_check_jsb
    test rax, rax
    jnz  .fail
    call ext_w_build_sysmap
    test rax, rax
    jnz  .fail
%if EXT_W_OWNED
    call ext_w_arm_owned                 ; owner-adopted and armed by the OWNER: owned mode, no request grant
    test rax, rax
    jnz  .bound
%endif
    call ext_w_storage_gate
    test rax, rax
    jnz  .fail
.bound:
    lea  rdi, [r12 + ext_ctx.arm_uuid]
    mov  rsi, r13
    mov  edx, 16
    call memcpy
    mov  dword [r12 + ext_ctx.wdead], 0
    mov  dword [r12 + ext_ctx.armed], 1
    call ext_ns_orphans                  ; finish an interrupted large delete (the orphan list)
    test rax, rax
    jz   .orphans_done
    mov  dword [r12 + ext_ctx.armed], 0
    jmp  .fail
.orphans_done:
    lea  rdi, [rel str_ew_armed]
    call serial_string
    mov  rdi, [r12 + ext_ctx.name]
    call serial_string
    lea  rdi, [rel str_ew_crlf]
    call serial_string
    xor  eax, eax
    jmp  .out
.wgate:
    mov  dword [rel ext4_disk_last_error], EXT_E_WGATE
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ext_op_mutate_armed(RDI=fsmount) -> RAX 1 while this mount is armed and no
;   commit has failed on it, else 0. A pure state read (no IO, no gate): the
;   fs_ops.mutate_armed admission hint for command_fs. Authority is still
;   enforced per transaction by ext_w_begin (storage gate + re-validation).
ext_op_mutate_armed:
    xor  eax, eax
    mov  rcx, [rdi + fsmount.priv]
    test rcx, rcx
    jz   .out
    cmp  dword [rcx + ext_ctx.mounted], 1
    jne  .out
    cmp  dword [rcx + ext_ctx.armed], 1
    jne  .out
    cmp  dword [rcx + ext_ctx.wdead], 0
    jne  .out
    mov  eax, 1
.out:
    ret

; ext4_disk_disarm(RDI=VFS handle) -> RAX 0 / -1
ext4_disk_disarm:
    call ext_w_ctx_of
    test rax, rax
    jz   .fail
    mov  dword [rax + ext_ctx.armed], 0
    mov  qword [rax + ext_ctx.owned_token], 0   ; and its binding
    cmp  [rel ext_w_job_ctx], rax
    jne  .ok
    call ext_w_job_close                 ; a disarm ends the copy job's window at once
.ok:
    xor  eax, eax
    ret
.fail:
    mov  rax, -1
    ret

; ext_w_ctx_of(RDI=VFS handle) -> RAX = mounted ext ctx / 0
ext_w_ctx_of:
    call vfs_mount_ptr
    test rax, rax
    jz   .none
    lea  rcx, [rel ext_ops]
    cmp  [rax + fsmount.ops], rcx
    jne  .none
    mov  rax, [rax + fsmount.priv]
    test rax, rax
    jz   .none
    cmp  dword [rax + ext_ctx.mounted], 1
    jne  .none
    ret
.none:
    xor  eax, eax
    ret

; ext_w_storage_gate(R12=ctx) -> RAX 0 / -1 (EXT_E_DENIED). The whole
;   partition window, under the current request's intent.
ext_w_storage_gate:
%if EXT_W_OWNED == 0
    ; Peter decision 10 (LEDGER 85949, 87106): a public 0.1 build has no adopted ext volume, so all ext is foreign and read-only.
    mov  dword [rel ext4_disk_last_error], EXT_E_DENIED
    mov  rax, -1
    ret
%endif
    mov  rdi, [r12 + ext_ctx.dev]
    mov  rsi, [r12 + ext_ctx.part_lba]
    mov  rdx, [r12 + ext_ctx.part_sectors]
    lea  r8, [rel str_ew_caller]
    call storage_access_require_request
    test rax, rax
    jz   .ok
    mov  dword [rel ext4_disk_last_error], EXT_E_DENIED
    mov  rax, -1
.ok:
    ret

%if EXT_W_OWNED
; ext_w_arm_owned(R12=ctx) -> RAX 1: owned mode (ctx.owned_token = the binding) / 0: the request gate decides.
;   Both are needed: a request from the verified OWNER principal (rc-sec S1) and a unique, live binding of this
;   mount to an adopted volume (vol_owner_bind_mount: the full identity probe). SYSTEM, ADVISOR, the AI hook, an
;   injected line, a DUP or a refused probe take ext_w_storage_gate unchanged (rc-sec Q2).
ext_w_arm_owned:
    call storage_access_request_owner
    test eax, eax
    jz   .legacy
    mov  edi, [r12 + ext_ctx.handle]
    call vol_owner_bind_mount
    test rax, rax
    jz   .legacy
    mov  [r12 + ext_ctx.owned_token], rax
    mov  eax, 1
    ret
.legacy:
    xor  eax, eax
    ret

; ext_w_owned_begin(R12=ctx) -> RAX 1: this transaction's owned op is open (wks.owned_handle) / 0: not owned
;   mode, or not an owner context (the legacy gates decide, so a non-owner still needs SPECIAL) / -1: owned and
;   refused (EXT_E_DENIED, nothing written). The authority is either a copy STEP of this mount's owned job (its
;   BEGIN was the OWNER's request) under IMPLICIT intent, or a request from the verified OWNER principal.
ext_w_owned_begin:
    cmp  qword [r12 + ext_ctx.owned_token], 0
    je   .legacy
    cmp  dword [rel ext_w_job_step], 1
    jne  .request
    cmp  [rel ext_w_job_ctx], r12
    jne  .request
    cmp  qword [rel ext_w_job_tag], 0
    jne  .request                        ; a granted window is a legacy job
    call storage_access_request_intent
    cmp  eax, SA_INTENT_IMPLICIT
    je   .open
.request:
    call storage_access_request_owner
    test eax, eax
    jz   .legacy
.open:
    mov  rdi, [r12 + ext_ctx.dev]
    mov  rsi, [r12 + ext_ctx.part_lba]
    mov  rdx, [r12 + ext_ctx.part_sectors]
    mov  rcx, [r12 + ext_ctx.owned_token]
    call storage_access_owned_op_begin   ; the whole window, the whole volume re-probed now
    test rax, rax
    jz   .refused
    mov  rcx, [r12 + ext_ctx.wks]
    mov  [rcx + ext_wks.owned_handle], rax
    mov  eax, 1
    ret
.refused:
    mov  dword [rel ext4_disk_last_error], EXT_E_DENIED
    mov  rax, -1
    ret
.legacy:
    xor  eax, eax
    ret

; ext_w_owned_handle(R12=ctx) -> R8 = the open transaction's owned op / 0. Preserves everything else.
ext_w_owned_handle:
    mov  r8, [r12 + ext_ctx.wks]
    test r8, r8
    jz   .out
    mov  r8, [r8 + ext_wks.owned_handle]
.out:
    ret
%endif

; ext_w_check_sb(R12=ctx, RSI=expected UUID) -> RAX 0 / -1 (EXT_E_WGATE).
;   Re-reads the live superblock: same UUID, clean, no RECOVER, unchanged
;   features/geometry, valid checksum, write allowlists, internal journal.
ext_w_check_sb:
    push rbx
    push r13
    mov  r13, rsi
    mov  rdi, [r12 + ext_ctx.dev]
    mov  rsi, [r12 + ext_ctx.part_lba]
    add  rsi, 2
    mov  edx, 2
    lea  rcx, [rel ext_sb_buf]
    call ext_raw_read
    test rax, rax
    jnz  .io
    lea  rbx, [rel ext_sb_buf]
    cmp  word [rbx + ESB_MAGIC], EXT_MAGIC
    jne  .gate
    lea  rdi, [rbx + ESB_UUID]
    mov  rsi, r13
    mov  edx, 16
    call memcmp
    test rax, rax
    jnz  .gate
    movzx eax, word [rbx + ESB_STATE]
    and  eax, EXT_STATE_VALID | EXT_STATE_ERROR
    cmp  eax, EXT_STATE_VALID
    jne  .gate
    mov  eax, [rbx + ESB_INCOMPAT]
    cmp  eax, [r12 + ext_ctx.incompat]
    jne  .gate                           ; includes RECOVER appearing
    test eax, ~EXT_W_IN_ALLOWED
    jnz  .gate                           ; ext3 (no EXTENTS) is written through indirect maps (E2c)
    mov  eax, [rbx + ESB_RO_COMPAT]
    cmp  eax, [r12 + ext_ctx.ro_compat]
    jne  .gate
    test eax, ~EXT_W_RO_ALLOWED
    jnz  .gate
    mov  eax, [rbx + ESB_COMPAT]
    test eax, EXT_COMPAT_JOURNAL
    jz   .nojournal                      ; ext2: no journal, no crash story: refused, not degraded
    test eax, EXT_COMPAT_FAST_COMMIT | EXT_COMPAT_SPARSE_SUPER2
    jnz  .gate
    cmp  dword [rbx + ESB_JOURNAL_INUM], EXT_JOURNAL_INO
    jne  .gate
    cmp  dword [rbx + ESB_JOURNAL_DEV], 0
    jne  .gate
    mov  eax, [rbx + ESB_BLOCKS_LO]
    test dword [r12 + ext_ctx.incompat], EXT_IN_64BIT
    jz   .blocks
    mov  ecx, [rbx + ESB_BLOCKS_HI]
    shl  rcx, 32
    or   rax, rcx
.blocks:
    cmp  rax, [r12 + ext_ctx.blocks_count]
    jne  .gate
    test dword [r12 + ext_ctx.ro_compat], EXT_RO_METADATA_CSUM
    jz   .ok
    mov  rdi, rbx
    mov  esi, ESB_CSUM
    mov  edx, 0xFFFFFFFF
    call ext_crc32c
    cmp  eax, [rbx + ESB_CSUM]
    jne  .gate
.ok:
    xor  eax, eax
    jmp  .out
.io:
    mov  dword [rel ext4_disk_last_error], EXT_E_IO
    mov  rax, -1
    jmp  .out
.nojournal:
    mov  dword [rel ext4_disk_last_error], EXT_E_NOJOURNAL
    mov  rax, -1
    jmp  .out
.gate:
    mov  dword [rel ext4_disk_last_error], EXT_E_WGATE
    mov  rax, -1
.out:
    pop  r13
    pop  rbx
    ret

; ext_w_check_jsb(R12=ctx, EDI=1 adopt sequence / 0 require ctx.j_seq) -> 0/-1.
;   Reads the journal superblock (journal logical block 0) into wks.jsb and
;   validates it; fills the ctx.j_* fields.
ext_w_check_jsb:
    push rbx
    push r13
    push r15
    mov  r13d, edi
    mov  r15, [r12 + ext_ctx.wks]
    lea  rdi, [r12 + ext_ctx.jino]
    xor  esi, esi
    call ext_map
    test rax, rax
    jle  .gate
    mov  [r15 + ext_wks.jmap0], rax
    mov  rsi, rax
    mov  edx, 1
    lea  rcx, [r15 + ext_wks.jsb]
    call ext_read_blocks
    test rax, rax
    jnz  .io
    lea  rbx, [r15 + ext_wks.jsb]
    cmp  dword [rbx], JBD2_MAGIC_LE
    jne  .gate
    mov  eax, [rbx + JSB_BLOCKTYPE]
    bswap eax
    cmp  eax, 3
    jb   .gate
    cmp  eax, 4
    ja   .gate
    mov  eax, [rbx + JSB_BLOCKSIZE]
    bswap eax
    cmp  eax, [r12 + ext_ctx.block_bytes]
    jne  .gate
    mov  eax, [rbx + JSB_START]
    test eax, eax
    jnz  .gate                           ; the journal must be empty
    mov  eax, [rbx + JSB_ERRNO]
    test eax, eax
    jnz  .gate
    mov  eax, [rbx + JSB_COMPAT]
    or   eax, [rbx + JSB_ROCOMPAT]
    jnz  .gate
    mov  eax, [rbx + JSB_INCOMPAT]
    bswap eax
    test eax, ~(JBD2_IN_REVOKE | JBD2_IN_64BIT | JBD2_IN_CSUM_V3)
    jnz  .gate
    mov  ecx, eax
    xor  edx, edx
    test ecx, JBD2_IN_CSUM_V3
    jz   .no_csum
    mov  edx, 1
.no_csum:
    mov  [r12 + ext_ctx.j_csum3], edx
    mov  edx, 8
    test ecx, JBD2_IN_64BIT
    jz   .tag
    mov  edx, 12
.tag:
    cmp  dword [r12 + ext_ctx.j_csum3], 1
    jne  .tag_set
    mov  edx, 16
.tag_set:
    mov  [r12 + ext_ctx.j_tagbytes], edx
    test ecx, JBD2_IN_64BIT
    jnz  .wide
    mov  rax, [r12 + ext_ctx.blocks_count]
    shr  rax, 32
    jnz  .gate                           ; 64-bit block numbers need journal 64BIT
.wide:
    mov  eax, [rbx + JSB_MAXLEN]
    bswap eax
    mov  [r12 + ext_ctx.j_maxlen], eax
    mov  ecx, [rbx + JSB_FIRST]
    bswap ecx
    mov  [r12 + ext_ctx.j_first], ecx
    test ecx, ecx
    jz   .gate
    lea  edx, [ecx + EXT_TXN_MAX + 2]
    cmp  edx, eax
    ja   .gate                           ; too small for one bounded transaction
    lea  rdi, [r12 + ext_ctx.jino]
    call ext_inode_size
    mov  ecx, [r12 + ext_ctx.block_shift]
    shr  rax, cl
    mov  edx, [r12 + ext_ctx.j_maxlen]
    cmp  rdx, rax
    ja   .gate                           ; the journal inode must hold s_maxlen blocks
    cmp  dword [r12 + ext_ctx.j_csum3], 1
    jne  .seq
    cmp  byte [rbx + JSB_CSUM_TYPE], 4    ; JBD2_CRC32C_CHKSUM
    jne  .gate
    mov  rdi, rbx
    call ext_w_jsb_csum
    cmp  eax, [rbx + JSB_CHECKSUM]
    jne  .gate
    lea  rdi, [rbx + JSB_UUID]
    mov  esi, 16
    mov  edx, 0xFFFFFFFF
    call ext_crc32c
    mov  [r12 + ext_ctx.j_seed], eax
.seq:
    mov  eax, [rbx + JSB_SEQUENCE]
    bswap eax
    test r13d, r13d
    jnz  .adopt
    cmp  eax, [r12 + ext_ctx.j_seq]
    jne  .gate                           ; someone else used the journal since arm
.adopt:
    mov  [r12 + ext_ctx.j_seq], eax
    xor  eax, eax
    jmp  .out
.io:
    mov  dword [rel ext4_disk_last_error], EXT_E_IO
    mov  rax, -1
    jmp  .out
.gate:
    mov  dword [rel ext4_disk_last_error], EXT_E_WGATE
    mov  rax, -1
.out:
    pop  r15
    pop  r13
    pop  rbx
    ret

; ext_w_jsb_csum(RDI=journal superblock) -> EAX = big-endian-stored checksum
;   (crc32c(~0) over the 1024-byte superblock with s_checksum taken as zero).
ext_w_jsb_csum:
    push rbx
    mov  rbx, rdi
    mov  esi, JSB_CHECKSUM
    mov  edx, 0xFFFFFFFF
    call ext_crc32c
    mov  edi, eax
    mov  esi, 4
    call ext_crc_zero
    lea  rdi, [rbx + JSB_CHECKSUM + 4]
    mov  esi, 1024 - JSB_CHECKSUM - 4
    mov  edx, eax
    call ext_crc32c
    bswap eax
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; Operations
; ---------------------------------------------------------------------------
; write_at_path(self, RSI=path, EDX=len, RCX=off, R8=buf, R9=n) -> n / -1
ext_op_write_at_path:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rcx                        ; offset
    mov  r13, r8                         ; buffer
    mov  r14, r9                         ; length
    call ext_w_enter
    test rax, rax
    jz   .fail
    mov  r12, rax
    call ext_w_resolve_file
    test rax, rax
    jnz  .fail
    test r14, r14
    jz   .zero
    mov  rax, rbx
    add  rax, r14
    jc   .range
    mov  r15, [r12 + ext_ctx.wks]
    mov  dword [r15 + ext_wks.mode], EXT_MODE_WRITE
    mov  [r15 + ext_wks.w_off], rbx
    mov  [r15 + ext_wks.w_buf], r13
    mov  [r15 + ext_wks.w_len], r14
    lea  rdi, [r12 + ext_ctx.inode]
    call ext_inode_size
    mov  [r15 + ext_wks.content_size], rax
    mov  rcx, rbx
    add  rcx, r14
    cmp  rcx, rax
    jae  .grow
    mov  rcx, rax
.grow:
    mov  [r15 + ext_wks.new_size], rcx
    mov  rcx, 1
    shl  rcx, 32
    mov  [r15 + ext_wks.cut], rcx        ; nothing cut
    mov  ecx, [r12 + ext_ctx.block_shift]
    mov  rax, rbx
    shr  rax, cl
    mov  [r15 + ext_wks.rb_lo], rax
    lea  rax, [rbx + r14 - 1]
    shr  rax, cl
    inc  rax
    mov  [r15 + ext_wks.rb_hi], rax
    ; the old EOF block, when the write starts past it, keeps zeros past EOF
    mov  rdi, [r15 + ext_wks.content_size]
    mov  rsi, [r15 + ext_wks.rb_lo]
    call ext_w_tail_range
    call ext_w_apply
    test rax, rax
    jnz  .fail
.zero:
    mov  rax, r14
    jmp  .out
.range:
    mov  dword [rel ext4_disk_last_error], EXT_E_RANGE
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; mutate_path(self, RSI=NUL-terminated path, RDX=data, RCX=len, R8D=FS_MUT_*) -> 0/-1.
;   Only FS_MUT_UPDATE (replace the whole content) belongs to E2a.
ext_op_mutate_path:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r13, rdx
    mov  r14, rcx
    cmp  r8d, FS_MUT_UPDATE
    je   .update
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    jmp  ext_ns_mutate                   ; CREATE/DELETE/RENAME/MKDIR/RMDIR (fs/ext4_ns)
.update:
    test rsi, rsi
    jz   .badpath
    xor  edx, edx
.len:
    cmp  edx, EXT_PATH_MAX
    jae  .badpath                        ; a NUL must appear within EXT_PATH_MAX bytes
    cmp  byte [rsi + rdx], 0
    je   .have_len
    inc  edx
    jmp  .len
.have_len:
    call ext_w_enter
    test rax, rax
    jz   .fail
    mov  r12, rax
    call ext_w_resolve_file
    test rax, rax
    jnz  .fail
    mov  r15, [r12 + ext_ctx.wks]
    mov  dword [r15 + ext_wks.mode], EXT_MODE_UPDATE
    mov  qword [r15 + ext_wks.w_off], 0
    mov  [r15 + ext_wks.w_buf], r13
    mov  [r15 + ext_wks.w_len], r14
    mov  qword [r15 + ext_wks.content_size], 0
    mov  [r15 + ext_wks.new_size], r14
    mov  qword [r15 + ext_wks.cut], 0
    mov  qword [r15 + ext_wks.rb_lo], 0
    mov  rax, r14
    mov  ecx, [r12 + ext_ctx.block_bytes]
    dec  rcx
    add  rax, rcx
    jc   .range
    mov  ecx, [r12 + ext_ctx.block_shift]
    shr  rax, cl
    mov  [r15 + ext_wks.rb_hi], rax
    mov  qword [r15 + ext_wks.ra_lo], 0
    mov  qword [r15 + ext_wks.ra_hi], 0
    call ext_w_apply
    test rax, rax
    jnz  .fail
    xor  eax, eax
    jmp  .out
.range:
    mov  dword [rel ext4_disk_last_error], EXT_E_RANGE
    jmp  .fail
.badpath:
    mov  dword [rel ext4_disk_last_error], EXT_E_BADPATH
    jmp  .fail
.unsupported:
    mov  dword [rel ext4_disk_last_error], EXT_E_UNSUPPORTED
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ext4_disk_truncate(RDI=VFS handle, RSI=path, EDX=len, RCX=new size) -> 0/-1
ext4_disk_truncate:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r13, rcx
    mov  dword [rel ext4_disk_last_error], EXT_E_NONE
    push rsi
    push rdx
    call ext_w_ctx_of
    pop  rdx
    pop  rsi
    test rax, rax
    jz   .gate
    mov  r12, rax
    call ext_w_check_armed
    test rax, rax
    jnz  .fail
    call ext_w_resolve_file
    test rax, rax
    jnz  .fail
    lea  rdi, [r12 + ext_ctx.inode]
    call ext_inode_size
    mov  r14, rax                        ; old size
    cmp  r13, r14
    je   .done
    mov  rcx, r13
    call ext_w_truncate_slot
    test rax, rax
    jz   .done
    cmp  r13, r14
    jae  .fail                           ; a grow is one transaction
    cmp  dword [rel ext4_disk_last_error], EXT_E_TOOBIG
    jne  .fail
    call ext_w_multi_txn_ok
    test rax, rax
    jz   .toobig                         ; a copy STEP runs at most one transaction
    ; too much to free in one transaction: bounded pieces from the end, each
    ; one transaction (an interruption leaves a size between old and new)
    mov  esi, [r12 + ext_ctx.inode + EXT_SLOT_INO]
    mov  rdx, r13
    call ext_w_shrink
    test rax, rax
    jnz  .fail
    mov  dword [rel ext4_disk_last_error], EXT_E_NONE
.done:
    xor  eax, eax
    jmp  .out
.toobig:
    mov  dword [rel ext4_disk_last_error], EXT_E_TOOBIG
    jmp  .fail
.gate:
    mov  dword [rel ext4_disk_last_error], EXT_E_NOTARMED
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ext_w_truncate_slot(R12=ctx, RCX=new size; ctx.inode = the file) -> RAX 0/-1.
;   One transaction: the file becomes RCX bytes (TOOBIG, before any write, when
;   the blocks it frees do not fit one transaction).
ext_w_truncate_slot:
    push r13
    push r14
    push r15
    mov  r13, rcx
    lea  rdi, [r12 + ext_ctx.inode]
    call ext_inode_size
    mov  r14, rax                        ; old size
    cmp  r13, r14
    je   .done
    mov  r15, [r12 + ext_ctx.wks]
    mov  dword [r15 + ext_wks.mode], EXT_MODE_TRUNC
    mov  qword [r15 + ext_wks.w_len], 0
    mov  qword [r15 + ext_wks.w_off], 0
    mov  qword [r15 + ext_wks.w_buf], 0
    mov  [r15 + ext_wks.content_size], r14
    mov  [r15 + ext_wks.new_size], r13
    mov  qword [r15 + ext_wks.rb_lo], 0
    mov  qword [r15 + ext_wks.rb_hi], 0
    mov  rax, 1
    shl  rax, 32
    mov  [r15 + ext_wks.cut], rax
    mov  ecx, [r12 + ext_ctx.block_shift]
    cmp  r13, r14
    ja   .grow
    ; shrink: everything from ceil(N/bs) goes; the new last block keeps zeros past N
    mov  rax, r13
    mov  edx, [r12 + ext_ctx.block_bytes]
    dec  rdx
    add  rax, rdx
    shr  rax, cl
    mov  [r15 + ext_wks.cut], rax
    mov  rdi, r13
    mov  rsi, rax
    inc  rsi                             ; "write starts past" = any block after the tail
    call ext_w_tail_range
    jmp  .apply
.grow:
    mov  rdi, r14
    mov  rsi, -1
    call ext_w_tail_range
.apply:
    call ext_w_apply
    jmp  .out
.done:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    ret

; ext_w_shrink(R12=ctx, ESI=inode, RDX=target size) -> RAX 0/-1: the file
;   (also one on the orphan list) shrinks to RDX in bounded pieces from the
;   end, each piece one transaction freeing at most EXT_W_PIECE bytes. A piece
;   refused TOOBIG (before any write) is halved and retried; a single block
;   that does not fit is a real refusal. Each piece re-reads the inode.
ext_w_shrink:
    push rbx
    push r13
    push r14
    push r15
    mov  ebx, esi
    mov  r13, rdx                        ; target size
    mov  r14, EXT_W_PIECE                ; bytes per piece
.piece:
    mov  esi, ebx
    lea  rdi, [r12 + ext_ctx.inode]
    call ext_read_inode_any
    test rax, rax
    jnz  .fail
    test dword [r12 + ext_ctx.inode + EI_FLAGS], EXT_W_FL_REFUSED
    jnz  .unsupported
    lea  rdi, [r12 + ext_ctx.inode]
    call ext_inode_size
    cmp  rax, r13
    jbe  .done
    mov  rcx, rax
    sub  rcx, r14
    jb   .last                           ; less than one piece left
    mov  eax, [r12 + ext_ctx.block_bytes]
    neg  rax
    and  rcx, rax                        ; a mid-chain cut is on a block boundary
    cmp  rcx, r13
    ja   .cut
.last:
    mov  rcx, r13
.cut:
    call ext_w_truncate_slot
    test rax, rax
    jnz  .refused
    cmp  dword [rel ext_w_dry_run], 0
    jne  .done                           ; a probe stops at the first piece that fits
    cmp  r14, EXT_W_PIECE
    jae  .piece
    shl  r14, 1                          ; it fitted: try a larger piece next
    jmp  .piece
.refused:
    cmp  dword [rel ext4_disk_last_error], EXT_E_TOOBIG
    jne  .fail
    mov  eax, [r12 + ext_ctx.block_bytes]
    cmp  r14, rax
    jbe  .fail                           ; not even one block fits
    shr  r14, 1
    jmp  .piece
.unsupported:
    mov  dword [rel ext4_disk_last_error], EXT_E_UNSUPPORTED
.fail:
    mov  rax, -1
    jmp  .out
.done:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

; ext_w_shrink_probe(R12=ctx, ESI=inode, RDX=target size) -> RAX 0/-1: does
;   ext_w_shrink's first piece fit one transaction? The same pieces, each one
;   built and checked up to its first write, then abandoned: nothing is
;   written. Only the first piece can fail where a one-block piece later would
;   not: it alone also frees the blocks mapped past i_size, and the extent and
;   tree-block limits count the whole file, so they only ease as it shrinks.
;   So a large delete proves here that its chain can finish before the name
;   goes (TOOBIG / UNSUPPORTED: a clean refusal).
ext_w_shrink_probe:
    mov  dword [rel ext_w_dry_run], 1
    call ext_w_shrink
    mov  dword [rel ext_w_dry_run], 0
    ret

; ext_w_dry(EDI=1/0): from now on ext_w_end builds and checks each transaction
;   up to capacity and abandons it, writing nothing (a probe); 0 ends that.
ext_w_dry:
    mov  [rel ext_w_dry_run], edi
    ret

; ext_w_multi_txn_ok() -> RAX 1 when the caller may run several transactions
;   for one operation (a large delete or shrink), 0 inside a copy STEP, which
;   runs at most one transaction under its job window.
ext_w_multi_txn_ok:
    xor  eax, eax
    cmp  dword [rel ext_w_job_step], 0
    jne  .out
    inc  eax
.out:
    ret

; ext_w_enter(RDI=fsmount) -> RAX = ctx / 0 (error set). Preserves RSI/RDX.
ext_w_enter:
    mov  dword [rel ext4_disk_last_error], EXT_E_NONE
    mov  rax, [rdi + fsmount.priv]
    test rax, rax
    jz   .no
    cmp  dword [rax + ext_ctx.mounted], 1
    jne  .no
    push rax
    push rsi
    push rdx
    push r12
    mov  r12, rax
    call ext_w_check_armed
    pop  r12
    pop  rdx
    pop  rsi
    test rax, rax
    pop  rax
    jnz  .zero
    ret
.no:
    mov  dword [rel ext4_disk_last_error], EXT_E_NOTARMED
.zero:
    xor  eax, eax
    ret

; ext_w_check_armed(R12=ctx) -> RAX 0 / -1
ext_w_check_armed:
    cmp  dword [r12 + ext_ctx.armed], 1
    jne  .not
    cmp  dword [r12 + ext_ctx.wdead], 0
    jne  .dead
    xor  eax, eax
    ret
.not:
    mov  dword [rel ext4_disk_last_error], EXT_E_NOTARMED
    mov  rax, -1
    ret
.dead:
    mov  dword [rel ext4_disk_last_error], EXT_E_DEAD
    mov  rax, -1
    ret

; ext_w_resolve_file(R12=ctx, RSI=path, EDX=len) -> 0/-1; ctx.inode = a
;   writable regular extent-mapped file.
ext_w_resolve_file:
    call ext_resolve
    test rax, rax
    jnz  .fail
    movzx eax, word [r12 + ext_ctx.inode + EI_MODE]
    and  eax, EXT_S_IFMT
    cmp  eax, EXT_S_IFREG
    je   .regular
    mov  ecx, EXT_E_ISDIR
    cmp  eax, EXT_S_IFDIR
    je   .refuse
    mov  ecx, EXT_E_UNSUPPORTED
    jmp  .refuse
.regular:
    mov  eax, [r12 + ext_ctx.inode + EI_FLAGS]
    mov  ecx, EXT_E_UNSUPPORTED
    test eax, EXT_W_FL_REFUSED
    jnz  .refuse                         ; extent- and indirect-mapped files are both written
    xor  eax, eax
    ret
.refuse:
    mov  [rel ext4_disk_last_error], ecx
.fail:
    mov  rax, -1
    ret

; ext_w_tail_range(R12=ctx, RDI=old size, RSI=first rewritten block or -1)
;   Sets ra = [S/bs, S/bs+1) when S is mid-block, that block lies before RSI
;   and it holds initialized data: its bytes past S become zeros. Else ra empty.
ext_w_tail_range:
    push rbx
    push r13
    push r15
    mov  r15, [r12 + ext_ctx.wks]
    mov  qword [r15 + ext_wks.ra_lo], 0
    mov  qword [r15 + ext_wks.ra_hi], 0
    mov  ecx, [r12 + ext_ctx.block_bytes]
    dec  rcx
    test rdi, rcx
    jz   .out
    mov  ecx, [r12 + ext_ctx.block_shift]
    mov  rbx, rdi
    shr  rbx, cl
    cmp  rbx, rsi
    jae  .out
    mov  r13, rsi
    lea  rdi, [r12 + ext_ctx.inode]
    mov  rsi, rbx
    call ext_map
    test rax, rax
    jle  .out                            ; hole/uninit (zeros already) or corrupt (apply re-checks)
    mov  [r15 + ext_wks.ra_lo], rbx
    inc  rbx
    mov  [r15 + ext_wks.ra_hi], rbx
.out:
    pop  r15
    pop  r13
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; ext_w_apply(R12=ctx; wks parameters set) -> RAX 0 / -1. One transaction.
; ---------------------------------------------------------------------------
ext_w_apply:
    call ext_w_begin
    test rax, rax
    jnz  .fail
    call ext_w_content
    test rax, rax
    jnz  .fail
    jmp  ext_w_end
.fail:
    call ext_w_invalidate
    mov  rax, -1
    ret

; ext_w_begin(R12=ctx) -> 0/-1: per-transaction authority, live volume
;   re-validation, the system-zone map, and an empty transaction.
ext_w_begin:
    push r15
    mov  r15, [r12 + ext_ctx.wks]
    mov  qword [r15 + ext_wks.job_tag], 0
%if EXT_W_OWNED
    cmp  qword [r15 + ext_wks.owned_handle], 0
    jne  .leaked                         ; every exit ends its op: a leftover one is refused, never presented
    call ext_w_owned_begin               ; owned mode: this transaction's own owned op
    test rax, rax
    js   .fail
    jnz  .gated
%endif
    call ext_w_job_mode                  ; a copy step under IMPLICIT intent: its window
    test rax, rax
    jz   .request
    mov  [r15 + ext_wks.job_tag], rax    ; every write is checked against it (ext_w_end, ext_dev_write)
    jmp  .gated
.request:
    call ext_w_storage_gate
    test rax, rax
    jnz  .fail
.gated:
    lea  rsi, [r12 + ext_ctx.arm_uuid]
    call ext_w_check_sb
    test rax, rax
    jnz  .fail
    xor  edi, edi
    call ext_w_check_jsb
    test rax, rax
    jnz  .fail
    call ext_w_build_sysmap              ; metadata never becomes allocatable, whatever a bitmap says
    test rax, rax
    jnz  .fail
    xor  eax, eax
    mov  [r15 + ext_wks.txn_n], eax
    mov  [r15 + ext_wks.nr_n], eax
    mov  [r15 + ext_wks.fr_n], eax
    mov  [r15 + ext_wks.tg_n], eax
    mov  [r15 + ext_wks.tig_n], eax
    mov  [r15 + ext_wks.di_n], eax
    mov  [r15 + ext_wks.db_n], eax
    mov  [r15 + ext_wks.xl_n], eax       ; no file is being rewritten yet
    mov  [r15 + ext_wks.tl_n], eax
    mov  [r15 + ext_wks.free_delta], rax
    mov  [r15 + ext_wks.ifree_delta], rax
    mov  dword [r15 + ext_wks.open], 1
    jmp  .out
%if EXT_W_OWNED
.leaked:
    mov  dword [rel ext4_disk_last_error], EXT_E_DENIED
%endif
.fail:
    call ext_w_invalidate
    mov  rax, -1
.out:
    pop  r15
    ret

; ext_w_content(R12=ctx; ctx.inode = the regular file, wks parameters set)
;   -> 0/-1: copy-on-write data runs, the rebuilt extent tree and the inode,
;   all inside the open transaction. Frees are queued, applied by ext_w_end.
ext_w_content:
    push rbx
    push r15
    mov  r15, [r12 + ext_ctx.wks]
    mov  rax, [r15 + ext_wks.new_size]
    mov  ecx, [r12 + ext_ctx.block_shift]
    mov  rdx, rax
    shr  rdx, cl
    shr  rdx, 32
    jnz  .toobig                         ; logical blocks are 32-bit
    mov  rdx, rax
    shr  rdx, 31
    jz   .size_ok
    test dword [r12 + ext_ctx.ro_compat], EXT_RO_LARGE_FILE
    jz   .toobig
.size_ok:
    mov  rax, [r15 + ext_wks.rb_hi]
    sub  rax, [r15 + ext_wks.rb_lo]
    add  rax, [r15 + ext_wks.ra_hi]
    sub  rax, [r15 + ext_wks.ra_lo]
    cmp  rax, EXT_W_MAX_BLOCKS
    ja   .toobig
    mov  dword [r15 + ext_wks.nr_n], 0
    lea  rdi, [r12 + ext_ctx.inode]
    call ext_w_collect
    test rax, rax
    jnz  .fail
    mov  rsi, [r15 + ext_wks.ra_lo]
    mov  rdx, [r15 + ext_wks.ra_hi]
    call ext_w_alloc_range
    test rax, rax
    jnz  .fail
    mov  rsi, [r15 + ext_wks.rb_lo]
    mov  rdx, [r15 + ext_wks.rb_hi]
    call ext_w_alloc_range
    test rax, rax
    jnz  .fail
    call ext_w_rebuild_list
    test rax, rax
    jnz  .fail
    call ext_w_layout
    test rax, rax
    jnz  .fail
    mov  esi, [r12 + ext_ctx.inode + EXT_SLOT_INO]
    call ext_w_inode_txn
    test rax, rax
    jz   .fail
    mov  rbx, rax
    mov  rdi, rbx
    call ext_w_serialize
    test rax, rax
    jnz  .fail
    mov  rdi, rbx
    call ext_w_finish_inode
    jmp  .out
.toobig:
    mov  dword [rel ext4_disk_last_error], EXT_E_TOOBIG
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  rbx
    ret

; ext_w_end(R12=ctx) -> 0/-1: queued frees, every checksum, the superblock,
;   capacity, the copy-on-write data, then the jbd2 commit. Under
;   ext_w_dry_run it stops after capacity and abandons the transaction (0).
ext_w_end:
    call ext_w_apply_frees
    test rax, rax
    jnz  .fail
    call ext_w_finish_dirty
    test rax, rax
    jnz  .fail
    call ext_w_finish_groups
    test rax, rax
    jnz  .fail
    call ext_w_finish_sb
    test rax, rax
    jnz  .fail
    call ext_w_capacity
    test rax, rax
    jnz  .fail
    cmp  dword [rel ext_w_dry_run], 0
    jne  .dry                            ; a probe: it fits, and nothing is written
    call ext_w_job_prepass               ; job window: every block refused before the first write
    test rax, rax
    jnz  .fail
    call ext_w_write_data
    test rax, rax
    jnz  .fail
    call ext_w_commit
    test rax, rax
    jnz  .fail
    call ext_w_invalidate
    xor  eax, eax
    ret
.dry:
    call ext_w_invalidate
    xor  eax, eax
    ret
.fail:
    call ext_w_invalidate
    mov  rax, -1
    ret

; ext_w_inode_txn(R12=ctx, ESI=inode number) -> RAX = the on-disk inode inside
;   the transaction (its checksum is recomputed by ext_w_end) / 0.
ext_w_inode_txn:
    push rbx
    push r13
    push r15
    mov  r15, [r12 + ext_ctx.wks]
    mov  r13d, esi
    call ext_inode_loc
    cmp  rax, -1
    je   .fail
    mov  rbx, rdx
    mov  rsi, rax
    xor  edx, edx
    call ext_txn_slot
    test rax, rax
    jz   .fail
    add  rbx, rax
    xor  ecx, ecx
.seen:
    cmp  ecx, [r15 + ext_wks.di_n]
    jae  .add
    cmp  [r15 + ext_wks.di_ino + rcx * 4], r13d
    je   .done
    inc  ecx
    jmp  .seen
.add:
    cmp  ecx, EXT_DI_MAX
    jae  .toobig
    mov  [r15 + ext_wks.di_ino + rcx * 4], r13d
    mov  [r15 + ext_wks.di_ptr + rcx * 8], rbx
    mov  dword [r15 + ext_wks.di_flags + rcx * 4], 0
    inc  dword [r15 + ext_wks.di_n]
.done:
    mov  rax, rbx
    jmp  .out
.toobig:
    mov  dword [rel ext4_disk_last_error], EXT_E_TOOBIG
.fail:
    xor  eax, eax
.out:
    pop  r15
    pop  r13
    pop  rbx
    ret

; ext_w_mark_dirblock(R12=ctx, RDI=directory block in the transaction,
;   ESI=its directory's checksum seed) -> 0/-1
ext_w_mark_dirblock:
    mov  r8, [r12 + ext_ctx.wks]
    xor  ecx, ecx
.seen:
    cmp  ecx, [r8 + ext_wks.db_n]
    jae  .add
    cmp  [r8 + ext_wks.db_ptr + rcx * 8], rdi
    je   .ok
    inc  ecx
    jmp  .seen
.add:
    cmp  ecx, EXT_DB_MAX
    jae  .toobig
    mov  [r8 + ext_wks.db_ptr + rcx * 8], rdi
    mov  [r8 + ext_wks.db_seed + rcx * 4], esi
    inc  dword [r8 + ext_wks.db_n]
.ok:
    xor  eax, eax
    ret
.toobig:
    mov  dword [rel ext4_disk_last_error], EXT_E_TOOBIG
    mov  rax, -1
    ret

; ext_w_finish_dirty(R12=ctx) -> 0: directory-leaf tails, then inode checksums
;   (metadata_csum only).
ext_w_finish_dirty:
    call ext_w_stamp_times
    test dword [r12 + ext_ctx.ro_compat], EXT_RO_METADATA_CSUM
    jz   .ok
    push rbx
    push r15
    mov  r15, [r12 + ext_ctx.wks]
    xor  ebx, ebx
.db:
    cmp  ebx, [r15 + ext_wks.db_n]
    jae  .inodes
    mov  rdi, [r15 + ext_wks.db_ptr + rbx * 8]
    mov  esi, [r12 + ext_ctx.block_bytes]
    sub  esi, 12
    mov  edx, [r15 + ext_wks.db_seed + rbx * 4]
    call ext_crc32c
    mov  rdi, [r15 + ext_wks.db_ptr + rbx * 8]
    mov  ecx, [r12 + ext_ctx.block_bytes]
    mov  [rdi + rcx - 4], eax
    inc  ebx
    jmp  .db
.inodes:
    xor  ebx, ebx
.di:
    cmp  ebx, [r15 + ext_wks.di_n]
    jae  .done
    mov  rdi, [r15 + ext_wks.di_ptr + rbx * 8]
    mov  esi, [r15 + ext_wks.di_ino + rbx * 4]
    call ext_inode_csum
    mov  rdi, [r15 + ext_wks.di_ptr + rbx * 8]
    mov  [rdi + EI_CSUM_LO], ax
    test ecx, ecx
    jz   .next
    shr  eax, 16
    mov  [rdi + EI_CSUM_HI], ax
.next:
    inc  ebx
    jmp  .di
.done:
    pop  r15
    pop  rbx
.ok:
    xor  eax, eax
    ret

; ext_w_mark_ptr(R12=ctx, RDI=inode in the transaction, ESI=EXT_DI_*): record
;   what changed on a dirty inode, for its timestamps at ext_w_end.
ext_w_mark_ptr:
    mov  r8, [r12 + ext_ctx.wks]
    xor  ecx, ecx
.find:
    cmp  ecx, [r8 + ext_wks.di_n]
    jae  .out
    cmp  [r8 + ext_wks.di_ptr + rcx * 8], rdi
    je   .hit
    inc  ecx
    jmp  .find
.hit:
    or   [r8 + ext_wks.di_flags + rcx * 4], esi
.out:
    ret

; ext_w_mark_ino(R12=ctx, ESI=inode, EDX=EXT_DI_*) -> RAX 0 / -1: the inode
;   joins the transaction (if not already) with those flags.
ext_w_mark_ino:
    push rbx
    mov  ebx, edx
    call ext_w_inode_txn
    test rax, rax
    jz   .fail
    mov  rdi, rax
    mov  esi, ebx
    call ext_w_mark_ptr
    xor  eax, eax
    pop  rbx
    ret
.fail:
    mov  rax, -1
    pop  rbx
    ret

; ext_w_stamp_times(R12=ctx): one wall-clock reading for the whole transaction.
;   Every live dirty inode gets ctime; EXT_DI_MTIME adds mtime; EXT_DI_NEW sets
;   atime, ctime, mtime and crtime. The *_extra words carry the epoch bits and
;   nanoseconds when the inode's extra area holds them. An unseeded wall clock
;   (time_wall_now_us = 0) leaves every time as it is: never an invented time.
ext_w_stamp_times:
    push rbx
    push r13
    push r14
    push r15
    mov  r15, [r12 + ext_ctx.wks]
    call time_wall_now_us
    test rax, rax
    jz   .out
    xor  edx, edx
    mov  rcx, 1000000
    div  rcx
    mov  r13, rax                        ; Unix seconds
    imul edx, edx, 1000                  ; nanoseconds
    shl  edx, 2
    movsxd rcx, r13d
    mov  r8, r13
    sub  r8, rcx
    shr  r8, 32                          ; epoch bits beyond the signed 32-bit field
    and  r8d, 3
    or   edx, r8d
    mov  r14d, edx                       ; *_extra
    xor  ebx, ebx
.inode:
    cmp  ebx, [r15 + ext_wks.di_n]
    jae  .out
    mov  rdi, [r15 + ext_wks.di_ptr + rbx * 8]
    cmp  word [rdi + EI_LINKS], 0
    je   .next                           ; a released inode stays zeroed
    xor  r9d, r9d                        ; usable extra bytes
    cmp  dword [r12 + ext_ctx.inode_size], 128
    jbe  .base
    movzx r9d, word [rdi + EI_EXTRA_ISIZE]
.base:
    mov  ecx, [r15 + ext_wks.di_flags + rbx * 4]
    mov  [rdi + EI_CTIME], r13d
    cmp  r9d, EI_CTIME_EXTRA - 0x80 + 4
    jb   .m
    mov  [rdi + EI_CTIME_EXTRA], r14d
.m:
    test ecx, EXT_DI_MTIME | EXT_DI_NEW
    jz   .next
    mov  [rdi + EI_MTIME], r13d
    cmp  r9d, EI_MTIME_EXTRA - 0x80 + 4
    jb   .a
    mov  [rdi + EI_MTIME_EXTRA], r14d
.a:
    test ecx, EXT_DI_NEW
    jz   .next
    mov  [rdi + EI_ATIME], r13d
    cmp  r9d, EI_ATIME_EXTRA - 0x80 + 4
    jb   .next
    mov  [rdi + EI_ATIME_EXTRA], r14d
    cmp  r9d, EI_CRTIME - 0x80 + 4
    jb   .next
    mov  [rdi + EI_CRTIME], r13d
    cmp  r9d, EI_CRTIME_EXTRA - 0x80 + 4
    jb   .next
    mov  [rdi + EI_CRTIME_EXTRA], r14d
.next:
    inc  ebx
    jmp  .inode
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

; ext_w_put_mtime(R12=ctx, RDI=inode inside the open transaction, RAX=Unix seconds, EDX=nanoseconds):
;   i_mtime, and i_mtime_extra (epoch bits, nanoseconds<<2) when the inode's extra area holds it, encoded
;   as ext_w_stamp_times encodes the wall. E2t (root 2026-10-17 21:04:41: a copy carries the source mtime).
;   The caller marks no EXT_DI_MTIME for that inode, so ext_w_end keeps it. Clobbers RCX, RDX, R8.
ext_w_put_mtime:
    mov  [rdi + EI_MTIME], eax
    movsxd rcx, eax
    mov  r8, rax
    sub  r8, rcx
    shr  r8, 32                          ; epoch bits beyond the signed 32-bit field
    and  r8d, 3
    shl  edx, 2
    or   edx, r8d
    cmp  dword [r12 + ext_ctx.inode_size], 128
    jbe  .out
    movzx ecx, word [rdi + EI_EXTRA_ISIZE]
    cmp  ecx, EI_MTIME_EXTRA - 0x80 + 4
    jb   .out
    mov  [rdi + EI_MTIME_EXTRA], edx
.out:
    ret

; ext_w_invalidate(R12=ctx): reader caches may hold pre-transaction blocks.
ext_w_invalidate:
    mov  qword [r12 + ext_ctx.meta_tag], -1
    mov  qword [r12 + ext_ctx.ibuf_tag], -1
    mov  rax, [r12 + ext_ctx.wks]
    test rax, rax
    jz   .out
    mov  dword [rax + ext_wks.open], 0   ; the transaction is over (committed or abandoned)
    mov  qword [rax + ext_wks.job_tag], 0
%if EXT_W_OWNED
    push rdi
    mov  rdi, [rax + ext_wks.owned_handle]
    mov  qword [rax + ext_wks.owned_handle], 0
    call storage_access_owned_op_end     ; and its owned op (preserves every register; 0 is a no-op)
    pop  rdi
%endif
.out:
    ret

; ext_w_uninit_inode_ok(R12=ctx, R13D=group) -> CF clear when an open writer
;   transaction has materialized this INODE_UNINIT group's inode bitmap (so its
;   inodes may now be located); preserves everything but RAX/RCX/flags
ext_w_uninit_inode_ok:
    mov  rax, [r12 + ext_ctx.wks]
    test rax, rax
    jz   .no
    cmp  dword [rax + ext_wks.open], 0
    je   .no
    xor  ecx, ecx
.find:
    cmp  ecx, [rax + ext_wks.tig_n]
    jae  .no
    cmp  [rax + ext_wks.tig + rcx * 4], r13d
    je   .yes
    inc  ecx
    jmp  .find
.yes:
    clc
    ret
.no:
    stc
    ret

; ---------------------------------------------------------------------------
; System zones (the ext4 "system zone": blocks no bitmap may hand out)
; ---------------------------------------------------------------------------
; ext_w_build_sysmap(R12=ctx; ext_sb_buf = live superblock, jino/j_maxlen set)
;   -> 0/-1. Superblock + GDT + reserved-GDT of every backup group, every
;   group's block bitmap, inode bitmap and inode table (from checksum-verified
;   descriptors), every journal block and journal tree block; sorted, merged.
ext_w_build_sysmap:
    push rbx
    push rbp
    push r13
    push r14
    push r15
    mov  r15, [r12 + ext_ctx.wks]
    mov  qword [r15 + ext_wks.sz_n], 0
    mov  eax, [r12 + ext_ctx.group_count]
    mov  ecx, [r12 + ext_ctx.desc_size]
    imul rax, rcx
    mov  ecx, [r12 + ext_ctx.block_bytes]
    lea  rax, [rax + rcx - 1]
    mov  ecx, [r12 + ext_ctx.block_shift]
    shr  rax, cl                         ; GDT blocks
    movzx ecx, word [rel ext_sb_buf + ESB_RESERVED_GDT]
    lea  rax, [rax + rcx + 1]
    mov  [r15 + ext_wks.sz_per], rax
    xor  ebx, ebx                        ; group
.group:
    cmp  ebx, [r12 + ext_ctx.group_count]
    jae  .journal
    mov  eax, ebx
    mov  ecx, [r12 + ext_ctx.blocks_per_g]
    imul rax, rcx
    add  rax, [r12 + ext_ctx.first_data]
    mov  r13, rax                        ; group start
    mov  esi, ebx
    call ext_w_is_backup
    jnc  .descriptors
    mov  rsi, r13
    mov  rdx, r13
    add  rdx, [r15 + ext_wks.sz_per]
    cmp  rdx, [r12 + ext_ctx.blocks_count]
    jbe  .backup
    mov  rdx, [r12 + ext_ctx.blocks_count]
.backup:
    call ext_w_sys_add
    test rax, rax
    jnz  .fail
.descriptors:
    mov  esi, ebx
    call ext_gd_read                     ; checksum-verified
    test rax, rax
    jz   .fail
    mov  r14, rax
    mov  esi, EGD_BITMAP_LO
    mov  edx, EGD_BITMAP_HI
    mov  ecx, 1
    call .add_field
    jnz  .fail
    mov  esi, EGD_IBITMAP_LO
    mov  edx, EGD_IBITMAP_HI
    mov  ecx, 1
    call .add_field
    jnz  .fail
    mov  esi, EGD_ITABLE_LO
    mov  edx, EGD_ITABLE_HI
    mov  ecx, [r12 + ext_ctx.it_blocks]
    call .add_field
    jnz  .fail
    inc  ebx
    jmp  .group
.journal:
    xor  r13d, r13d                      ; journal logical block
.jrun:
    cmp  r13d, [r12 + ext_ctx.j_maxlen]
    jae  .jtree
    lea  rdi, [r12 + ext_ctx.jino]
    mov  rsi, r13
    call ext_map
    test rax, rax
    jle  .gate                           ; the journal must be fully mapped
    mov  ecx, [r12 + ext_ctx.j_maxlen]
    sub  rcx, r13
    cmp  rdx, rcx
    jbe  .jlen
    mov  rdx, rcx
.jlen:
    add  r13, rdx
    mov  rsi, rax
    add  rdx, rax
    call ext_w_sys_add
    test rax, rax
    jnz  .fail
    jmp  .jrun
.jtree:
    lea  rdi, [r12 + ext_ctx.jino]
    call ext_w_collect                   ; scratch use of wks.xl/tl (refilled per operation)
    test rax, rax
    jnz  .fail
    xor  ebx, ebx
.jt:
    cmp  ebx, [r15 + ext_wks.tl_n]
    jae  .sort
    mov  rsi, [r15 + ext_wks.tl + rbx * 8]
    lea  rdx, [rsi + 1]
    call ext_w_sys_add
    test rax, rax
    jnz  .fail
    inc  ebx
    jmp  .jt
.sort:
    ; insertion sort by start (input is nearly ordered), then merge adjacent runs; two
    ; metadata structures never share a block, so an overlap means a forged descriptor
    ; (e.g. a bitmap pointer aimed at the superblock or an inode table): CORRUPT
    mov  r13, [r15 + ext_wks.sz_n]
    mov  ebx, 1
.outer:
    cmp  rbx, r13
    jae  .merge
    mov  rbp, rbx
.inner:
    test rbp, rbp
    jz   .next
    mov  rax, rbp
    shl  rax, 4
    lea  rdi, [r15 + ext_wks.sz + rax]
    mov  rcx, [rdi]
    cmp  rcx, [rdi - 16]
    jae  .next
    mov  rdx, [rdi - 16]
    mov  [rdi], rdx
    mov  [rdi - 16], rcx
    mov  rcx, [rdi + 8]
    mov  rdx, [rdi - 8]
    mov  [rdi + 8], rdx
    mov  [rdi - 8], rcx
    dec  rbp
    jmp  .inner
.next:
    inc  rbx
    jmp  .outer
.merge:
    test r13, r13
    jz   .ok
    xor  ebp, ebp                        ; write index
    mov  ebx, 1                          ; read index
.m:
    cmp  rbx, r13
    jae  .merged
    mov  rax, rbx
    shl  rax, 4
    mov  rcx, [r15 + ext_wks.sz + rax]
    mov  rdx, [r15 + ext_wks.sz + rax + 8]
    mov  rax, rbp
    shl  rax, 4
    lea  rdi, [r15 + ext_wks.sz + rax]
    cmp  rcx, [rdi + 8]
    ja   .new
    jb   .overlap                        ; shares a block with the previous run
    mov  [rdi + 8], rdx                  ; adjacent: one run
.absorbed:
    inc  rbx
    jmp  .m
.new:
    inc  rbp
    mov  [rdi + 16], rcx
    mov  [rdi + 24], rdx
    inc  rbx
    jmp  .m
.merged:
    inc  rbp
    mov  [r15 + ext_wks.sz_n], rbp
.ok:
    xor  eax, eax
    jmp  .out
.overlap:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
    jmp  .fail
.gate:
    mov  dword [rel ext4_disk_last_error], EXT_E_WGATE
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbp
    pop  rbx
    ret
.add_field:                              ; R14=descriptor, ESI=lo, EDX=hi offset, ECX=length -> ZF set on success
    push rcx
    mov  eax, [r14 + rsi]
    test dword [r12 + ext_ctx.incompat], EXT_IN_64BIT
    jz   .lo
    cmp  dword [r12 + ext_ctx.desc_size], 64
    jb   .lo
    mov  edx, [r14 + rdx]
    shl  rdx, 32
    or   rax, rdx
.lo:
    pop  rcx
    mov  rsi, rax
    lea  rdx, [rax + rcx]
    test rsi, rsi
    jz   .bad_field
    call ext_w_sys_add
    test rax, rax
    ret
.bad_field:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
    or   eax, 1                          ; ZF clear
    ret

; ext_w_sys_add(R12=ctx, RSI=start, RDX=end) -> RAX 0/-1
ext_w_sys_add:
    mov  r8, [r12 + ext_ctx.wks]
    cmp  rsi, rdx
    jae  .ok
    cmp  rdx, [r12 + ext_ctx.blocks_count]
    ja   .corrupt
    mov  rcx, [r8 + ext_wks.sz_n]
    cmp  rcx, EXT_SZ_MAX
    jae  .toobig
    shl  rcx, 4
    mov  [r8 + ext_wks.sz + rcx], rsi
    mov  [r8 + ext_wks.sz + rcx + 8], rdx
    inc  qword [r8 + ext_wks.sz_n]
.ok:
    xor  eax, eax
    ret
.toobig:
    mov  dword [rel ext4_disk_last_error], EXT_E_TOOBIG
    mov  rax, -1
    ret
.corrupt:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
    mov  rax, -1
    ret

; ext_w_is_backup(R12=ctx, ESI=group) -> CF set when the group holds a
;   superblock/GDT backup: 0, 1 and powers of 3, 5, 7 (sparse_super), else all.
ext_w_is_backup:
    cmp  esi, 1
    jbe  .yes
    test dword [r12 + ext_ctx.ro_compat], EXT_RO_SPARSE_SUPER
    jz   .yes
    mov  ecx, 3
.base:
    mov  eax, ecx
.power:
    cmp  rax, rsi
    je   .yes
    ja   .next_base
    imul rax, rcx
    jmp  .power
.next_base:
    add  ecx, 2
    cmp  ecx, 7
    jbe  .base
    clc
    ret
.yes:
    stc
    ret

; ext_w_in_zone(R12=ctx, RSI=block) -> CF set inside a system zone (binary search)
ext_w_in_zone:
    mov  r9, [r12 + ext_ctx.wks]
    xor  r10d, r10d                      ; lo
    mov  r11, [r9 + ext_wks.sz_n]        ; hi
.search:
    cmp  r10, r11
    jae  .no
    lea  rax, [r10 + r11]
    shr  rax, 1
    mov  rcx, rax
    shl  rcx, 4
    cmp  rsi, [r9 + ext_wks.sz + rcx]
    jb   .left
    cmp  rsi, [r9 + ext_wks.sz + rcx + 8]
    jb   .yes
    lea  r10, [rax + 1]
    jmp  .search
.left:
    mov  r11, rax
    jmp  .search
.no:
    clc
    ret
.yes:
    stc
    ret

; ext_w_is_system(R12=ctx, RSI=block) -> CF set when the block is fs metadata,
;   already in this transaction, or mapped by the file being rewritten
;   (its extents or extent-tree blocks).
ext_w_is_system:
    call ext_w_in_zone
    jc   .yes
    mov  r9, [r12 + ext_ctx.wks]
    xor  ecx, ecx
.txn:
    cmp  ecx, [r9 + ext_wks.txn_n]
    jae  .extents
    cmp  rsi, [r9 + ext_wks.txn_blk + rcx * 8]
    je   .yes
    inc  ecx
    jmp  .txn
.extents:
    xor  ecx, ecx
    lea  r10, [r9 + ext_wks.xl]
.ext:
    cmp  ecx, [r9 + ext_wks.xl_n]
    jae  .tree
    mov  rax, [r10 + 8]
    cmp  rsi, rax
    jb   .ext_next
    movzx edx, word [r10 + 4]
    add  rax, rdx
    cmp  rsi, rax
    jb   .yes
.ext_next:
    add  r10, 16
    inc  ecx
    jmp  .ext
.tree:
    xor  ecx, ecx
.tl:
    cmp  ecx, [r9 + ext_wks.tl_n]
    jae  .no
    cmp  rsi, [r9 + ext_wks.tl + rcx * 8]
    je   .yes
    inc  ecx
    jmp  .tl
.no:
    clc
    ret
.yes:
    stc
    ret

; ---------------------------------------------------------------------------
; Transaction cache
; ---------------------------------------------------------------------------
; ext_txn_slot(R12=ctx, RSI=block, EDX=0 load / 1 new-zeroed) -> RAX buffer / 0.
;   A "new" block already in the transaction is refused CORRUPT: two structures
;   would claim one block, and zeroing would erase what the other wrote.
ext_txn_slot:
    push rbx
    push r13
    push r14
    push r15
    mov  r15, [r12 + ext_ctx.wks]
    mov  r13, rsi
    mov  r14d, edx
    xor  ebx, ebx
.find:
    cmp  ebx, [r15 + ext_wks.txn_n]
    jae  .add
    cmp  [r15 + ext_wks.txn_blk + rbx * 8], r13
    je   .found
    inc  ebx
    jmp  .find
.found:
    test r14d, r14d
    jnz  .corrupt                        ; "new" for a block this transaction already holds
    call .buf
    jmp  .out
.add:
    cmp  ebx, EXT_TXN_MAX
    jae  .toobig
    mov  rsi, r13
    call ext_block_ok_any
    jc   .corrupt
    mov  [r15 + ext_wks.txn_blk + rbx * 8], r13
    inc  dword [r15 + ext_wks.txn_n]
    call .buf
    push rax
    test r14d, r14d
    jnz  .zeroed
    mov  rsi, r13
    mov  edx, 1
    mov  rcx, rax
    call ext_read_blocks
    test rax, rax
    pop  rax
    jz   .out
    dec  dword [r15 + ext_wks.txn_n]
    xor  eax, eax
    jmp  .out
.zeroed:
    mov  rdi, rax
    xor  esi, esi
    mov  edx, [r12 + ext_ctx.block_bytes]
    call memset
    pop  rax
    jmp  .out
.toobig:
    mov  dword [rel ext4_disk_last_error], EXT_E_TOOBIG
    xor  eax, eax
    jmp  .out
.corrupt:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret
.buf:                                    ; EBX = index -> RAX = its buffer
    mov  eax, ebx
    shl  rax, 12
    lea  rax, [r15 + ext_wks.bufs + rax]
    ret

; ext_block_ok_any(R12=ctx, RSI=block) -> CF clear when block < blocks_count
;   (block 0 holds the 4 KiB-block superblock, so it is legal here).
ext_block_ok_any:
    cmp  rsi, [r12 + ext_ctx.blocks_count]
    jae  .bad
    clc
    ret
.bad:
    stc
    ret

; ---------------------------------------------------------------------------
; Groups, bitmaps, allocation
; ---------------------------------------------------------------------------
; ext_w_gd(R12=ctx, ESI=group) -> RAX = descriptor inside the transaction / 0.
ext_w_gd:
    push rbx
    mov  eax, esi
    mov  ecx, [r12 + ext_ctx.desc_size]
    imul rax, rcx
    mov  rbx, rax
    mov  ecx, [r12 + ext_ctx.block_bytes]
    dec  ecx
    and  rbx, rcx
    mov  ecx, [r12 + ext_ctx.block_shift]
    shr  rax, cl
    mov  rsi, rax
    add  rsi, [r12 + ext_ctx.gdt_block]
    xor  edx, edx
    call ext_txn_slot
    test rax, rax
    jz   .out
    add  rax, rbx
.out:
    pop  rbx
    ret

; ext_w_bitmap_blk(R12=ctx, RDI=descriptor) -> RAX = block bitmap block / 0
ext_w_bitmap_blk:
    mov  eax, [rdi + EGD_BITMAP_LO]
    test dword [r12 + ext_ctx.incompat], EXT_IN_64BIT
    jz   .lo
    cmp  dword [r12 + ext_ctx.desc_size], 64
    jb   .lo
    mov  ecx, [rdi + EGD_BITMAP_HI]
    shl  rcx, 32
    or   rax, rcx
.lo:
    test rax, rax
    jz   .bad
    cmp  rax, [r12 + ext_ctx.blocks_count]
    jae  .bad
    ret
.bad:
    xor  eax, eax
    ret

; ext_w_touch(R12=ctx, ESI=group) -> RAX = bitmap inside the transaction / 0.
;   The first touch verifies the committed descriptor and bitmap checksums. A
;   BLOCK_UNINIT group (no bitmap on disk yet) is materialized instead: its
;   metadata from the system-zone map plus padding, cross-checked against the
;   descriptor's free count, and the flag cleared in the same transaction.
ext_w_touch:
    push rbx
    push r13
    push r14
    push r15
    mov  r15, [r12 + ext_ctx.wks]
    mov  r13d, esi
    xor  ebx, ebx
.seen:
    cmp  ebx, [r15 + ext_wks.tg_n]
    jae  .first
    cmp  [r15 + ext_wks.tg + rbx * 4], r13d
    je   .known
    inc  ebx
    jmp  .seen
.known:
    mov  esi, r13d
    call ext_w_gd
    test rax, rax
    jz   .fail
    mov  rdi, rax
    call ext_w_bitmap_blk
    test rax, rax
    jz   .corrupt
    mov  rsi, rax
    xor  edx, edx
    call ext_txn_slot
    jmp  .out
.first:
    cmp  ebx, EXT_TG_MAX
    jae  .toobig
    mov  esi, r13d
    call ext_gd_read                     ; verified committed descriptor
    test rax, rax
    jz   .fail
    test word [rax + EGD_FLAGS], EGD_BLOCK_UNINIT
    jz   .initialized
    test dword [r12 + ext_ctx.ro_compat], EXT_RO_METADATA_CSUM
    jz   .initialized                    ; without group checksums the flag means nothing (Linux)
    mov  esi, r13d
    call ext_w_init_block_bitmap
    test rax, rax
    jz   .fail
    mov  rbx, rax
    jmp  .add
.initialized:
    mov  esi, r13d
    call ext_w_gd
    test rax, rax
    jz   .fail
    mov  r14, rax
    mov  rdi, rax
    call ext_w_bitmap_blk
    test rax, rax
    jz   .corrupt
    mov  rsi, rax
    xor  edx, edx
    call ext_txn_slot
    test rax, rax
    jz   .fail
    mov  rbx, rax
    test dword [r12 + ext_ctx.ro_compat], EXT_RO_METADATA_CSUM
    jz   .add
    mov  rdi, rbx
    mov  esi, [r12 + ext_ctx.blocks_per_g]
    shr  esi, 3
    mov  edx, [r12 + ext_ctx.csum_seed]
    call ext_crc32c
    movzx ecx, word [r14 + EGD_BBITMAP_CSUM_LO]
    cmp  dword [r12 + ext_ctx.desc_size], EGD_BBITMAP_CSUM_HI + 4
    jb   .lo_only
    movzx edx, word [r14 + EGD_BBITMAP_CSUM_HI]
    shl  edx, 16
    or   ecx, edx
    cmp  eax, ecx
    jne  .corrupt
    jmp  .add
.lo_only:
    cmp  ax, cx
    jne  .corrupt
.add:
    mov  ecx, [r15 + ext_wks.tg_n]
    mov  [r15 + ext_wks.tg + rcx * 4], r13d
    inc  dword [r15 + ext_wks.tg_n]
    mov  rax, rbx
    jmp  .out
.toobig:
    mov  dword [rel ext4_disk_last_error], EXT_E_TOOBIG
    jmp  .fail
.unsupported:
    mov  dword [rel ext4_disk_last_error], EXT_E_UNSUPPORTED
    jmp  .fail
.corrupt:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
.fail:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

; ext_w_init_block_bitmap(R12=ctx, ESI=BLOCK_UNINIT group) -> RAX = its bitmap
;   in the transaction / 0. Bits: every system-zone block inside the group
;   (superblock/GDT backups, reserved GDT, any group's bitmaps and inode table
;   placed here, journal), and the padding past the group's last block. The
;   free bits must equal the descriptor's free count (else CORRUPT); the flag
;   is cleared in the transaction's descriptor.
ext_w_init_block_bitmap:
    push rbx
    push rbp
    push r13
    push r14
    push r15
    mov  r13d, esi
    mov  r15, [r12 + ext_ctx.wks]
    call ext_w_gd                        ; the descriptor inside the transaction
    test rax, rax
    jz   .fail
    mov  r14, rax
    mov  rdi, rax
    call ext_w_bitmap_blk
    test rax, rax
    jz   .corrupt
    mov  rsi, rax
    mov  edx, 1
    call ext_txn_slot                    ; a fresh, zeroed bitmap
    test rax, rax
    jz   .fail
    mov  rbx, rax
    ; the group's blocks: [start, start + n)
    mov  eax, r13d
    mov  ecx, [r12 + ext_ctx.blocks_per_g]
    imul rax, rcx
    add  rax, [r12 + ext_ctx.first_data]
    mov  rbp, rax                        ; start
    mov  rdx, [r12 + ext_ctx.blocks_count]
    sub  rdx, rax
    jbe  .corrupt
    cmp  rdx, rcx
    jbe  .n
    mov  rdx, rcx
.n:
    mov  r9, rdx                         ; n
    ; system-zone runs that reach into the group
    xor  ecx, ecx
.run:
    cmp  rcx, [r15 + ext_wks.sz_n]
    jae  .pad
    mov  rax, rcx
    shl  rax, 4
    mov  r10, [r15 + ext_wks.sz + rax]       ; lo
    mov  r11, [r15 + ext_wks.sz + rax + 8]   ; hi (exclusive)
    inc  rcx
    lea  rax, [rbp + r9]
    cmp  r10, rax
    jae  .run
    cmp  r11, rbp
    jbe  .run
    cmp  r10, rbp
    jae  .lo_in
    mov  r10, rbp
.lo_in:
    cmp  r11, rax
    jbe  .hi_in
    mov  r11, rax
.hi_in:
    sub  r10, rbp
    sub  r11, rbp
.bit:
    cmp  r10, r11
    jae  .run
    bts  [rbx], r10
    inc  r10
    jmp  .bit
.pad:
    mov  r10, r9
    mov  r11d, [r12 + ext_ctx.block_bytes]
    shl  r11, 3
.padbit:
    cmp  r10, r11
    jae  .count
    bts  [rbx], r10
    inc  r10
    jmp  .padbit
.count:
    xor  r10d, r10d
    xor  eax, eax                        ; free bits
.cbit:
    cmp  r10, r9
    jae  .check
    bt   [rbx], r10
    adc  rax, 0
    inc  r10
    jmp  .cbit
.check:
    neg  rax
    add  rax, r9                         ; n - used = free
    push rax
    mov  rdi, r14
    call ext_w_gd_free
    pop  rcx
    cmp  rax, rcx
    jne  .corrupt                        ; the descriptor and the metadata layout disagree
    and  word [r14 + EGD_FLAGS], ~EGD_BLOCK_UNINIT
    mov  rax, rbx
    jmp  .out
.corrupt:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
.fail:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbp
    pop  rbx
    ret

; ext_w_gd_free(R12=ctx, RDI=descriptor) -> RAX = free-block count
ext_w_gd_free:
    movzx eax, word [rdi + EGD_FREE_LO]
    cmp  dword [r12 + ext_ctx.desc_size], 64
    jb   .out
    movzx ecx, word [rdi + EGD_FREE_HI]
    shl  ecx, 16
    or   eax, ecx
.out:
    ret

; ext_w_gd_free_add(R12=ctx, RDI=descriptor, RSI=signed delta)
ext_w_gd_free_add:
    push rdi
    call ext_w_gd_free
    pop  rdi
    add  rax, rsi
    mov  [rdi + EGD_FREE_LO], ax
    cmp  dword [r12 + ext_ctx.desc_size], 64
    jb   .out
    shr  eax, 16
    mov  [rdi + EGD_FREE_HI], ax
.out:
    ret

; ext_w_group_bits(R12=ctx, ESI=group) -> RAX = blocks in the group
ext_w_group_bits:
    mov  eax, esi
    mov  ecx, [r12 + ext_ctx.blocks_per_g]
    imul rax, rcx
    add  rax, [r12 + ext_ctx.first_data]
    mov  rdx, [r12 + ext_ctx.blocks_count]
    sub  rdx, rax
    mov  eax, ecx
    cmp  rdx, rax
    jae  .out
    mov  rax, rdx
.out:
    ret

; ext_w_alloc(R12=ctx, RSI=goal, RDX=want) -> RAX = first block of a free run
;   (now marked used in the transaction), RDX = its length (1..want); RAX = 0
;   when no block is free (EXT_E_NOSPACE) or on error.
ext_w_alloc:
    push rbx
    push rbp
    push r13
    push r14
    push r15
    sub  rsp, 24                         ; [rsp] g0, [rsp+8] bit0, [rsp+16] iteration
    mov  r13, rdx                        ; want
    mov  rax, rsi
    sub  rax, [r12 + ext_ctx.first_data]
    jb   .goal0
    cmp  rsi, [r12 + ext_ctx.blocks_count]
    jae  .goal0
    xor  edx, edx
    mov  ecx, [r12 + ext_ctx.blocks_per_g]
    div  rcx
    mov  [rsp], rax
    mov  [rsp + 8], rdx
    jmp  .start
.goal0:
    mov  qword [rsp], 0
    mov  qword [rsp + 8], 0
.start:
    mov  qword [rsp + 16], 0
.group:
    mov  rax, [rsp + 16]
    mov  ecx, [r12 + ext_ctx.group_count]
    cmp  rax, rcx
    ja   .nospace
    add  rax, [rsp]
    xor  edx, edx
    div  rcx
    mov  r14d, edx                       ; group
    mov  esi, r14d
    call ext_w_group_bits
    mov  rbp, rax                        ; scan end
    xor  ebx, ebx                        ; scan start
    cmp  qword [rsp + 16], 0
    jne  .wrap_check
    mov  rbx, [rsp + 8]
    jmp  .scan_group
.wrap_check:
    mov  eax, [r12 + ext_ctx.group_count]
    cmp  [rsp + 16], rax
    jne  .scan_group
    mov  rbp, [rsp + 8]                  ; last pass: the goal group's head
.scan_group:
    cmp  rbx, rbp
    jae  .next_group
    mov  esi, r14d
    call ext_gd_read
    test rax, rax
    jz   .fail
    mov  esi, r14d                       ; BLOCK_UNINIT groups too: ext_w_touch materializes them
    call ext_w_gd
    test rax, rax
    jz   .fail
    mov  rdi, rax
    call ext_w_gd_free
    test rax, rax
    jz   .next_group
    mov  esi, r14d
    call ext_w_touch
    test rax, rax
    jz   .fail
    mov  r15, rax                        ; bitmap
.find:
    cmp  rbx, rbp
    jae  .next_group
    mov  rax, rbx
    shr  rax, 3
    mov  ecx, ebx
    and  ecx, 7
    jnz  .bit
    cmp  byte [r15 + rax], 0xFF
    jne  .bit
    add  rbx, 8
    jmp  .find
.bit:
    movzx edx, byte [r15 + rax]
    bt   edx, ecx
    jnc  .found
    inc  rbx
    jmp  .find
.found:
    xor  r8d, r8d                        ; run length
.run:
    cmp  r8, r13
    jae  .taken
    lea  rax, [rbx + r8]
    cmp  rax, rbp
    jae  .taken
    mov  ecx, eax
    shr  rax, 3
    and  ecx, 7
    mov  dl, 1
    shl  dl, cl
    test [r15 + rax], dl
    jnz  .taken                          ; next block in use: the run ends
    ; A free bit on filesystem metadata, a block of this transaction or of the
    ; file being rewritten means the bitmap lies (e.g. a forged freeb): refuse.
    push rax
    push rdx
    push r8
    mov  eax, r14d
    mov  ecx, [r12 + ext_ctx.blocks_per_g]
    imul rax, rcx
    add  rax, [r12 + ext_ctx.first_data]
    add  rax, rbx
    add  rax, r8
    mov  rsi, rax
    call ext_w_is_system
    pop  r8
    pop  rdx
    pop  rax
    jc   .bitmap_lies
    or   [r15 + rax], dl                 ; claimed in the transaction bitmap
    inc  r8
    jmp  .run
.bitmap_lies:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
    jmp  .fail
.taken:
    push r8
    mov  esi, r14d
    call ext_w_gd
    pop  r8
    test rax, rax
    jz   .fail
    push r8
    mov  rdi, rax
    mov  rsi, r8
    neg  rsi
    call ext_w_gd_free_add
    pop  r8
    mov  r15, [r12 + ext_ctx.wks]
    sub  [r15 + ext_wks.free_delta], r8
    mov  eax, r14d
    mov  ecx, [r12 + ext_ctx.blocks_per_g]
    imul rax, rcx
    add  rax, [r12 + ext_ctx.first_data]
    add  rax, rbx
    mov  rdx, r8
    jmp  .out
.next_group:
    inc  qword [rsp + 16]
    jmp  .group
.nospace:
    mov  dword [rel ext4_disk_last_error], EXT_E_NOSPACE
.fail:
    xor  eax, eax
    xor  edx, edx
.out:
    add  rsp, 24
    pop  r15
    pop  r14
    pop  r13
    pop  rbp
    pop  rbx
    ret

; ext_w_free(R12=ctx, RSI=first block, RDX=count) -> RAX 0 / -1. Every block
;   must currently be marked used (a double free is corruption).
ext_w_free:
    push rbx
    push r13
    push r14
    push r15
    mov  rbx, rsi
    mov  r13, rdx
.block:
    test r13, r13
    jz   .ok
    mov  rax, rbx
    sub  rax, [r12 + ext_ctx.first_data]
    jb   .corrupt
    cmp  rbx, [r12 + ext_ctx.blocks_count]
    jae  .corrupt
    mov  rsi, rbx
    call ext_w_in_zone
    jc   .corrupt                        ; an extent claiming fs metadata
    mov  rax, rbx
    sub  rax, [r12 + ext_ctx.first_data]
    xor  edx, edx
    mov  ecx, [r12 + ext_ctx.blocks_per_g]
    div  rcx
    mov  r14d, eax                       ; group
    mov  r15, rdx                        ; bit
    mov  esi, r14d
    call ext_w_touch
    test rax, rax
    jz   .fail
    mov  rdx, r15
    shr  rdx, 3
    mov  ecx, r15d
    and  ecx, 7
    mov  r8b, 1
    shl  r8b, cl
    test [rax + rdx], r8b
    jz   .corrupt                        ; freeing a free block
    not  r8b
    and  [rax + rdx], r8b
    mov  esi, r14d
    call ext_w_gd
    test rax, rax
    jz   .fail
    mov  rdi, rax
    mov  esi, 1
    call ext_w_gd_free_add
    mov  rax, [r12 + ext_ctx.wks]
    inc  qword [rax + ext_wks.free_delta]
    inc  rbx
    dec  r13
    jmp  .block
.ok:
    xor  eax, eax
    jmp  .out
.corrupt:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

; ext_w_goal(R12=ctx, RSI=logical block) -> RAX = physical goal: right after
;   the old extent preceding it, else the inode's own group.
ext_w_goal:
    mov  r8, [r12 + ext_ctx.wks]
    mov  ecx, [r8 + ext_wks.xl_n]
    lea  r9, [r8 + ext_wks.xl]
    xor  eax, eax
.scan:
    test ecx, ecx
    jz   .done
    mov  edx, [r9]
    cmp  rdx, rsi
    jae  .done
    movzx r10d, word [r9 + 4]
    mov  rax, [r9 + 8]
    mov  r11, rsi
    sub  r11, rdx
    cmp  r11, r10
    jbe  .in
    mov  r11, r10
.in:
    add  rax, r11
    add  r9, 16
    dec  ecx
    jmp  .scan
.done:
    test rax, rax
    jnz  .out
    mov  eax, [r12 + ext_ctx.inode + EXT_SLOT_INO]
    dec  eax
    xor  edx, edx
    div  dword [r12 + ext_ctx.inodes_per_g]
    mov  ecx, [r12 + ext_ctx.blocks_per_g]
    imul rax, rcx
    add  rax, [r12 + ext_ctx.first_data]
.out:
    ret

; ext_w_alloc_range(R12=ctx, RSI=lo, RDX=hi) -> RAX 0 / -1. Appends newly
;   allocated runs covering logical [lo,hi) to wks.nr.
ext_w_alloc_range:
    push rbx
    push r13
    push r14
    push r15
    mov  r15, [r12 + ext_ctx.wks]
    mov  rbx, rsi
    mov  r13, rdx
    cmp  rbx, r13
    jae  .ok
    call ext_w_goal
    mov  r14, rax
.run:
    cmp  rbx, r13
    jae  .ok
    mov  ecx, [r15 + ext_wks.nr_n]
    cmp  ecx, EXT_NR_MAX
    jae  .toobig
    mov  rdx, r13
    sub  rdx, rbx
    cmp  rdx, EXT_INIT_MAX
    jbe  .want
    mov  edx, EXT_INIT_MAX
.want:
    mov  rsi, r14
    call ext_w_alloc
    test rax, rax
    jz   .fail
    mov  ecx, [r15 + ext_wks.nr_n]
    shl  rcx, 4
    lea  r8, [r15 + ext_wks.nr + rcx]
    mov  [r8], ebx
    mov  [r8 + 4], dx
    mov  word [r8 + 6], 0
    mov  [r8 + 8], rax
    inc  dword [r15 + ext_wks.nr_n]
    add  rbx, rdx
    lea  r14, [rax + rdx]
    jmp  .run
.ok:
    xor  eax, eax
    jmp  .out
.toobig:
    mov  dword [rel ext4_disk_last_error], EXT_E_TOOBIG
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; Extent lists
; ---------------------------------------------------------------------------
; ext_w_collect(R12=ctx, RDI=slot) -> 0/-1: every leaf extent in order into
;   wks.xl, every non-root tree block into wks.tl, with the reader's checks.
ext_w_collect:
    push rbx
    push r13
    push r14
    push r15
    mov  r15, [r12 + ext_ctx.wks]
    mov  r14, rdi
    xor  eax, eax
    mov  [r15 + ext_wks.xl_n], eax
    mov  [r15 + ext_wks.tl_n], eax
    mov  [r15 + ext_wks.prev_end], rax
    mov  [r15 + ext_wks.ind], eax
    test dword [r14 + EI_FLAGS], EXT_FL_EXTENTS
    jnz  .extents
    call ext_w_collect_ind               ; ext3 / legacy indirect map (E2c)
    test rax, rax
    jnz  .out
    call ext_w_check_map
    jmp  .out
.extents:
    mov  eax, [r14 + EXT_SLOT_SEED]
    mov  [r12 + ext_ctx.map_seed], eax
    lea  rdi, [r14 + EI_BLOCK]
    mov  esi, -1
    mov  edx, 4
    call ext_w_node
    test rax, rax
    js   .fail
    mov  r13d, eax                       ; children's depth
    xor  ebx, ebx                        ; level start
.level:
    mov  ecx, [r15 + ext_wks.tl_n]
    cmp  ebx, ecx
    jae  .ok
    mov  r14d, ecx                       ; level end
.node:
    cmp  ebx, r14d
    jae  .next_level
    mov  rsi, [r15 + ext_wks.tl + rbx * 8]
    call ext_meta
    test rax, rax
    jz   .fail
    mov  rdi, rax
    mov  esi, r13d
    mov  eax, [r12 + ext_ctx.block_bytes]
    sub  eax, 12
    xor  edx, edx
    mov  ecx, 12
    div  ecx
    mov  edx, eax
    call ext_w_node
    test rax, rax
    js   .fail
    inc  ebx
    jmp  .node
.next_level:
    dec  r13d
    jmp  .level
.ok:
    call ext_w_check_map
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

; ext_w_node(R12=ctx, RDI=node, ESI=expected depth or -1 (root), EDX=capacity)
;   -> RAX = depth of this node's children (depth-1), or 0 for a leaf; -1 bad.
ext_w_node:
    push rbx
    push r13
    push r14
    push r15
    mov  r15, [r12 + ext_ctx.wks]
    mov  rbx, rdi
    cmp  word [rbx], EXT_EH_MAGIC
    jne  .corrupt
    movzx eax, word [rbx + 4]            ; max
    cmp  eax, edx
    ja   .corrupt
    movzx r13d, word [rbx + 2]           ; entries
    cmp  r13d, eax
    ja   .corrupt
    movzx r14d, word [rbx + 6]           ; depth
    cmp  esi, -1
    je   .root
    cmp  r14d, esi
    jne  .corrupt
    test dword [r12 + ext_ctx.ro_compat], EXT_RO_METADATA_CSUM
    jz   .checked
    imul esi, eax, 12
    add  esi, 12
    mov  rdi, rbx
    mov  edx, [r12 + ext_ctx.map_seed]
    call ext_crc32c
    movzx ecx, word [rbx + 4]
    imul ecx, ecx, 12
    cmp  eax, [rbx + rcx + 12]
    jne  .corrupt
    jmp  .checked
.root:
    cmp  r14d, EXT_DEPTH_MAX
    ja   .corrupt
.checked:
    lea  rbx, [rbx + 12]
    test r14d, r14d
    jz   .leaf
    test r13d, r13d
    jz   .corrupt
    mov  r8d, -1                         ; previous ei_block
.idx:
    test r13d, r13d
    jz   .idx_done
    mov  eax, [rbx]
    cmp  r8d, -1
    je   .idx_first
    cmp  eax, r8d
    jbe  .corrupt
.idx_first:
    mov  r8d, eax
    mov  eax, [rbx + 4]
    movzx esi, word [rbx + 8]
    shl  rsi, 32
    or   rsi, rax
    call ext_block_ok
    jc   .corrupt
    mov  ecx, [r15 + ext_wks.tl_n]
    cmp  ecx, EXT_TL_MAX
    jae  .toobig
    xor  edx, edx
.dup:
    cmp  edx, ecx
    jae  .unique
    cmp  [r15 + ext_wks.tl + rdx * 8], rsi
    je   .corrupt                        ; one block referenced twice
    inc  edx
    jmp  .dup
.unique:
    mov  [r15 + ext_wks.tl + rcx * 8], rsi
    inc  dword [r15 + ext_wks.tl_n]
    add  rbx, 12
    dec  r13d
    jmp  .idx
.idx_done:
    lea  eax, [r14d - 1]
    jmp  .out
.leaf:
    test r13d, r13d
    jz   .leaf_done
    mov  ecx, [r15 + ext_wks.xl_n]
    cmp  ecx, EXT_XL_MAX
    jae  .toobig
    mov  eax, [rbx]                      ; ee_block
    movzx edx, word [rbx + 4]
    xor  r8d, r8d
    cmp  edx, EXT_UNINIT_LEN
    jbe  .len_ok
    sub  edx, EXT_UNINIT_LEN
    mov  r8d, 1
.len_ok:
    test edx, edx
    jz   .corrupt
    cmp  rax, [r15 + ext_wks.prev_end]
    jb   .corrupt
    lea  r9, [rax + rdx]
    mov  r10, 1
    shl  r10, 32
    cmp  r9, r10
    ja   .corrupt
    mov  [r15 + ext_wks.prev_end], r9
    movzx esi, word [rbx + 6]
    shl  rsi, 32
    mov  r10d, [rbx + 8]
    or   rsi, r10
    call ext_block_ok
    jc   .corrupt
    lea  r10, [rsi + rdx]
    cmp  r10, [r12 + ext_ctx.blocks_count]
    ja   .corrupt
    shl  rcx, 4
    lea  r10, [r15 + ext_wks.xl + rcx]
    mov  [r10], eax
    mov  [r10 + 4], dx
    mov  [r10 + 6], r8w
    mov  [r10 + 8], rsi
    inc  dword [r15 + ext_wks.xl_n]
    add  rbx, 12
    dec  r13d
    jmp  .leaf
.leaf_done:
    xor  eax, eax
    jmp  .out
.toobig:
    mov  dword [rel ext4_disk_last_error], EXT_E_TOOBIG
    mov  rax, -1
    jmp  .out
.corrupt:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

; ext_w_rebuild_list(R12=ctx) -> 0/-1. xl minus the removed intervals (ra, rb,
;   [cut, 2^32)) -> xl2, removed physical blocks -> fr; then xl = merge(xl2,
;   nr) with contiguous neighbours coalesced.
ext_w_rebuild_list:
    push rbx
    push r13
    push r14
    push r15
    mov  r15, [r12 + ext_ctx.wks]
    ; removed intervals, sorted by start (ra <= rb <= cut is not guaranteed)
    xor  ecx, ecx
    mov  rax, [r15 + ext_wks.ra_lo]
    cmp  rax, [r15 + ext_wks.ra_hi]
    jae  .no_ra
    mov  [r15 + ext_wks.rm], rax
    mov  rax, [r15 + ext_wks.ra_hi]
    mov  [r15 + ext_wks.rm + 8], rax
    inc  ecx
.no_ra:
    mov  rax, [r15 + ext_wks.rb_lo]
    cmp  rax, [r15 + ext_wks.rb_hi]
    jae  .no_rb
    mov  rdx, rcx
    shl  rdx, 4
    mov  [r15 + ext_wks.rm + rdx], rax
    mov  rax, [r15 + ext_wks.rb_hi]
    mov  [r15 + ext_wks.rm + rdx + 8], rax
    inc  ecx
.no_rb:
    mov  rax, [r15 + ext_wks.cut]
    mov  rdx, 1
    shl  rdx, 32
    cmp  rax, rdx
    jae  .no_cut
    mov  r8, rcx
    shl  r8, 4
    mov  [r15 + ext_wks.rm + r8], rax
    mov  [r15 + ext_wks.rm + r8 + 8], rdx
    inc  ecx
.no_cut:
    mov  [r15 + ext_wks.rm_n], rcx
    ; insertion sort (<= 3 entries) by start
    mov  r8d, 1
.sort_outer:
    cmp  r8, rcx
    jae  .sorted
    mov  r9, r8
.sort_inner:
    test r9, r9
    jz   .sort_next
    mov  r10, r9
    shl  r10, 4
    mov  rax, [r15 + ext_wks.rm + r10]
    cmp  rax, [r15 + ext_wks.rm + r10 - 16]
    jae  .sort_next
    mov  rdx, [r15 + ext_wks.rm + r10 - 16]
    mov  [r15 + ext_wks.rm + r10], rdx
    mov  [r15 + ext_wks.rm + r10 - 16], rax
    mov  rax, [r15 + ext_wks.rm + r10 + 8]
    mov  rdx, [r15 + ext_wks.rm + r10 - 8]
    mov  [r15 + ext_wks.rm + r10 + 8], rdx
    mov  [r15 + ext_wks.rm + r10 - 8], rax
    dec  r9
    jmp  .sort_inner
.sort_next:
    inc  r8
    jmp  .sort_outer
.sorted:
    mov  dword [r15 + ext_wks.xl2_n], 0
    xor  ebx, ebx                        ; old extent index
.extent:
    cmp  ebx, [r15 + ext_wks.xl_n]
    jae  .merge
    mov  rax, rbx
    shl  rax, 4
    lea  r13, [r15 + ext_wks.xl + rax]   ; old extent
    mov  r14d, [r13]                     ; c = start
    xor  r9d, r9d                        ; interval index
.interval:
    cmp  r9, [r15 + ext_wks.rm_n]
    jae  .rest
    mov  r10, r9
    shl  r10, 4
    mov  r8, [r15 + ext_wks.rm + r10]    ; x0
    mov  r11, [r15 + ext_wks.rm + r10 + 8] ; x1
    mov  eax, [r13]
    movzx edx, word [r13 + 4]
    add  rax, rdx                        ; end
    cmp  r11, r14
    jbe  .next_interval
    cmp  r8, rax
    jae  .next_interval
    cmp  r8, r14
    jbe  .no_keep
    push r9
    push rax
    push r8
    push r11
    mov  rsi, r14
    mov  rdx, r8
    sub  rdx, r14
    call ext_w_keep_piece
    mov  r10, rax
    pop  r11
    pop  r8
    pop  rax
    pop  r9
    test r10, r10
    js   .fail
    mov  eax, [r13]
    movzx edx, word [r13 + 4]
    add  rax, rdx
.no_keep:
    ; freed = [max(c,x0), min(end,x1))
    mov  rsi, r14
    cmp  r8, rsi
    jbe  .fs
    mov  rsi, r8
.fs:
    mov  rdx, rax
    cmp  r11, rdx
    jae  .fe
    mov  rdx, r11
.fe:
    push r9
    push rdx
    sub  rdx, rsi
    mov  ecx, [r13]
    mov  rax, rsi
    sub  rax, rcx
    mov  rsi, [r13 + 8]
    add  rsi, rax                        ; physical start of the freed piece
    call ext_w_add_free
    pop  r14                             ; c = fe
    pop  r9
    test rax, rax
    js   .fail
.next_interval:
    inc  r9
    jmp  .interval
.rest:
    mov  eax, [r13]
    movzx edx, word [r13 + 4]
    add  rax, rdx
    cmp  r14, rax
    jae  .extent_done
    mov  rsi, r14
    mov  rdx, rax
    sub  rdx, r14
    call ext_w_keep_piece
    test rax, rax
    js   .fail
.extent_done:
    inc  ebx
    jmp  .extent
.merge:
    ; xl = merge(xl2, nr), both sorted and disjoint
    mov  dword [r15 + ext_wks.xl_n], 0
    xor  r13d, r13d                      ; xl2 index
    xor  r14d, r14d                      ; nr index
.pick:
    cmp  r13d, [r15 + ext_wks.xl2_n]
    jae  .take_nr
    cmp  r14d, [r15 + ext_wks.nr_n]
    jae  .take_xl2
    mov  eax, r13d
    shl  rax, 4
    mov  ecx, [r15 + ext_wks.xl2 + rax]
    mov  edx, r14d
    shl  rdx, 4
    cmp  ecx, [r15 + ext_wks.nr + rdx]
    jb   .take_xl2
.take_nr:
    cmp  r14d, [r15 + ext_wks.nr_n]
    jae  .merged
    mov  eax, r14d
    shl  rax, 4
    lea  rsi, [r15 + ext_wks.nr + rax]
    inc  r14d
    jmp  .append
.take_xl2:
    mov  eax, r13d
    shl  rax, 4
    lea  rsi, [r15 + ext_wks.xl2 + rax]
    inc  r13d
.append:
    call ext_w_append_extent
    test rax, rax
    js   .fail
    jmp  .pick
.merged:
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

; ext_w_keep_piece(R15=wks, R13=old extent, RSI=logical start, RDX=length) -> 0/-1
ext_w_keep_piece:
    mov  ecx, [r15 + ext_wks.xl2_n]
    cmp  ecx, EXT_XL_MAX
    jae  .toobig
    shl  rcx, 4
    lea  r8, [r15 + ext_wks.xl2 + rcx]
    mov  [r8], esi
    mov  [r8 + 4], dx
    mov  ax, [r13 + 6]
    mov  [r8 + 6], ax
    mov  eax, [r13]
    mov  rcx, rsi
    sub  rcx, rax
    mov  rax, [r13 + 8]
    add  rax, rcx
    mov  [r8 + 8], rax
    inc  dword [r15 + ext_wks.xl2_n]
    xor  eax, eax
    ret
.toobig:
    mov  dword [rel ext4_disk_last_error], EXT_E_TOOBIG
    mov  rax, -1
    ret

; ext_w_add_free(R15=wks, RSI=physical start, RDX=count) -> 0/-1 (coalescing)
ext_w_add_free:
    test rdx, rdx
    jz   .ok
    mov  ecx, [r15 + ext_wks.fr_n]
    test ecx, ecx
    jz   .new
    lea  r8, [rcx - 1]
    shl  r8, 4
    lea  r8, [r15 + ext_wks.fr + r8]
    mov  rax, [r8]
    add  rax, [r8 + 8]
    cmp  rax, rsi
    jne  .new
    add  [r8 + 8], rdx
    jmp  .ok
.new:
    cmp  ecx, EXT_FR_MAX
    jae  .toobig
    shl  rcx, 4
    mov  [r15 + ext_wks.fr + rcx], rsi
    mov  [r15 + ext_wks.fr + rcx + 8], rdx
    inc  dword [r15 + ext_wks.fr_n]
.ok:
    xor  eax, eax
    ret
.toobig:
    mov  dword [rel ext4_disk_last_error], EXT_E_TOOBIG
    mov  rax, -1
    ret

; ext_w_append_extent(R15=wks, RSI=extent) -> 0/-1: appends to wks.xl,
;   extending the last entry when it is logically and physically contiguous
;   with the same state and the result fits one extent.
ext_w_append_extent:
    mov  ecx, [r15 + ext_wks.xl_n]
    test ecx, ecx
    jz   .new
    lea  r8, [rcx - 1]
    shl  r8, 4
    lea  r8, [r15 + ext_wks.xl + r8]
    mov  ax, [r8 + 6]
    cmp  ax, [rsi + 6]
    jne  .new
    mov  eax, [r8]
    movzx edx, word [r8 + 4]
    add  eax, edx
    cmp  eax, [rsi]
    jne  .new
    mov  rax, [r8 + 8]
    add  rax, rdx
    cmp  rax, [rsi + 8]
    jne  .new
    movzx eax, word [rsi + 4]
    add  eax, edx
    mov  edx, EXT_INIT_MAX
    cmp  word [r8 + 6], 0
    je   .limit
    mov  edx, EXT_UNINIT_MAX
.limit:
    cmp  eax, edx
    ja   .new
    mov  [r8 + 4], ax
    xor  eax, eax
    ret
.new:
    cmp  ecx, EXT_XL_MAX
    jae  .toobig
    shl  rcx, 4
    lea  r8, [r15 + ext_wks.xl + rcx]
    mov  rax, [rsi]
    mov  [r8], rax
    mov  rax, [rsi + 8]
    mov  [r8 + 8], rax
    inc  dword [r15 + ext_wks.xl_n]
    xor  eax, eax
    ret
.toobig:
    mov  dword [rel ext4_disk_last_error], EXT_E_TOOBIG
    mov  rax, -1
    ret

; ext_w_layout(R12=ctx) -> 0/-1. Minimum-depth tree for wks.xl; reuses the
;   old tree blocks, allocates the shortfall, queues leftovers for freeing.
ext_w_layout:
    mov  rax, [r12 + ext_ctx.wks]
    cmp  dword [rax + ext_wks.ind], 0
    jne  ext_w_layout_ind
    push rbx
    push r13
    push r14
    push r15
    mov  r15, [r12 + ext_ctx.wks]
    mov  eax, [r12 + ext_ctx.block_bytes]
    sub  eax, 12
    xor  edx, edx
    mov  ecx, 12
    div  ecx
    mov  r13d, eax                       ; entries per tree block
    mov  ecx, [r15 + ext_wks.xl_n]
    xor  eax, eax
    mov  [r15 + ext_wks.leaves], eax
    mov  [r15 + ext_wks.idxblocks], eax
    mov  [r15 + ext_wks.depth], eax
    cmp  ecx, 4
    jbe  .sized
    lea  eax, [rcx + r13 - 1]
    xor  edx, edx
    div  r13d
    mov  [r15 + ext_wks.leaves], eax
    mov  dword [r15 + ext_wks.depth], 1
    cmp  eax, 4
    jbe  .sized
    lea  eax, [rax + r13 - 1]
    xor  edx, edx
    div  r13d
    mov  [r15 + ext_wks.idxblocks], eax
    mov  dword [r15 + ext_wks.depth], 2
    cmp  eax, 4
    ja   .toobig
.sized:
    mov  eax, [r15 + ext_wks.leaves]
    add  eax, [r15 + ext_wks.idxblocks]
    mov  [r15 + ext_wks.ntree], eax
    cmp  eax, EXT_TL_MAX
    ja   .toobig
    ; reuse
    xor  ebx, ebx
.reuse:
    cmp  ebx, [r15 + ext_wks.ntree]
    jae  .leftover
    cmp  ebx, [r15 + ext_wks.tl_n]
    jae  .alloc
    mov  rax, [r15 + ext_wks.tl + rbx * 8]
    mov  [r15 + ext_wks.nt + rbx * 8], rax
    inc  ebx
    jmp  .reuse
.alloc:
    ; goal: just past the last data extent, else the inode's group
    mov  rsi, -1
    shr  rsi, 32
    call ext_w_goal
    mov  rsi, rax
    mov  edx, 1
    call ext_w_alloc
    test rax, rax
    jz   .fail
    mov  [r15 + ext_wks.nt + rbx * 8], rax
    inc  ebx
    jmp  .reuse
.leftover:
    cmp  ebx, [r15 + ext_wks.tl_n]
    jae  .ok
    mov  rsi, [r15 + ext_wks.tl + rbx * 8]
    mov  edx, 1
    call ext_w_add_free
    test rax, rax
    js   .fail
    inc  ebx
    jmp  .leftover
.ok:
    xor  eax, eax
    jmp  .out
.toobig:
    mov  dword [rel ext4_disk_last_error], EXT_E_TOOBIG
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

; ext_w_ea_block(R12=ctx, RDI=inode) -> RAX = its extended-attribute block
;   (i_file_acl; the high half only on a 64bit volume, as the kernel reads it)
ext_w_ea_block:
    mov  eax, [rdi + EI_FILE_ACL_LO]
    test dword [r12 + ext_ctx.incompat], EXT_IN_64BIT
    jz   .out
    movzx ecx, word [rdi + EI_FILE_ACL_HI]
    shl  rcx, 32
    or   rax, rcx
.out:
    ret

; ext_w_check_map(R12=ctx, R15=wks; xl/tl just collected) -> 0/-1: no block
;   of the file's map is used twice. Tree blocks are distinct, no tree block
;   lies inside a data run, and data runs are physically disjoint; else
;   CORRUPT before anything is written or freed (a forged map would otherwise
;   free a block that is still in use).
ext_w_check_map:
    push rbx
    push r13
    xor  ebx, ebx
.run:
    cmp  ebx, [r15 + ext_wks.xl_n]
    jae  .nodes
    mov  rax, rbx
    shl  rax, 4
    mov  r9, [r15 + ext_wks.xl + rax + 8]
    movzx r10d, word [r15 + ext_wks.xl + rax + 4]
    add  r10, r9                         ; [r9, r10)
    lea  r13d, [rbx + 1]
.other:
    cmp  r13d, [r15 + ext_wks.xl_n]
    jae  .run_next
    mov  rax, r13
    shl  rax, 4
    mov  r8, [r15 + ext_wks.xl + rax + 8]
    cmp  r8, r10
    jae  .other_next
    movzx r11d, word [r15 + ext_wks.xl + rax + 4]
    add  r11, r8
    cmp  r9, r11
    jb   .corrupt                        ; two runs share a block
.other_next:
    inc  r13d
    jmp  .other
.run_next:
    inc  ebx
    jmp  .run
.nodes:
    xor  ebx, ebx
.node:
    cmp  ebx, [r15 + ext_wks.tl_n]
    jae  .ok
    mov  rax, [r15 + ext_wks.tl + rbx * 8]
    xor  r13d, r13d
.twin:
    cmp  r13d, ebx
    jae  .in_data
    cmp  [r15 + ext_wks.tl + r13 * 8], rax
    je   .corrupt                        ; one tree block referenced twice
    inc  r13d
    jmp  .twin
.in_data:
    xor  r13d, r13d
.data:
    cmp  r13d, [r15 + ext_wks.xl_n]
    jae  .node_next
    mov  rcx, r13
    shl  rcx, 4
    mov  r8, [r15 + ext_wks.xl + rcx + 8]
    cmp  rax, r8
    jb   .data_next
    movzx r9d, word [r15 + ext_wks.xl + rcx + 4]
    add  r9, r8
    cmp  rax, r9
    jb   .corrupt                        ; a tree block that is also file data
.data_next:
    inc  r13d
    jmp  .data
.node_next:
    inc  ebx
    jmp  .node
.ok:
    xor  eax, eax
    jmp  .out
.corrupt:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
    mov  rax, -1
.out:
    pop  r13
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; Indirect maps (E2c: ext3, and legacy indirect-mapped files on ext4)
; ---------------------------------------------------------------------------
; i_block[0..11] map logical blocks 0..11; [12] an IND block (P = bs/4
; pointers), [13] a DIND block, [14] a TIND block. A node is identified by
; its position: slot 0 = IND, 1 = DIND, 2 = a DIND child, 3 = TIND, 4 = a
; TIND child, 5 = a TIND grandchild; key = slot << 40 | index. Runs go to
; wks.xl exactly as extents do, so allocation, copy-on-write and freeing are
; the E2a code. The serializer rebuilds every node in memory and journals only
; nodes whose pointers changed: an old node keeps its block at its position.

; ext_w_ind_ptr_ok(R12=ctx, RSI=block) -> CF clear when first_data <= block < blocks_count
ext_w_ind_ptr_ok:
    cmp  rsi, [r12 + ext_ctx.first_data]
    jb   .bad
    cmp  rsi, [r12 + ext_ctx.blocks_count]
    jae  .bad
    clc
    ret
.bad:
    stc
    ret

; ext_w_collect_ind(R12=ctx, R14=slot, R15=wks; lists reset) -> 0/-1
ext_w_collect_ind:
    push rbx
    mov  dword [r15 + ext_wks.ind], 1
    cmp  dword [r12 + ext_ctx.block_bytes], EXT_IND_BUF
    ja   .unsupported
    xor  ebx, ebx
.direct:
    cmp  ebx, 12
    jae  .trees
    mov  edi, ebx
    mov  esi, [r14 + EI_BLOCK + rbx * 4]
    call ext_w_ind_leaf
    test rax, rax
    jnz  .out
    inc  ebx
    jmp  .direct
.trees:
    mov  ebx, [r12 + ext_ctx.block_bytes]
    shr  ebx, 2                          ; P
    mov  esi, [r14 + EI_BLOCK + 48]
    mov  edx, 1
    mov  ecx, 12
    xor  r8d, r8d                        ; slot 0
    call ext_w_ind_node_collect
    test rax, rax
    jnz  .out
    mov  esi, [r14 + EI_BLOCK + 52]
    mov  edx, 2
    lea  rcx, [rbx + 12]
    mov  r8, 1 << 40                     ; slot 1
    call ext_w_ind_node_collect
    test rax, rax
    jnz  .out
    mov  esi, [r14 + EI_BLOCK + 56]
    mov  edx, 3
    mov  rcx, rbx
    imul rcx, rbx
    lea  rcx, [rcx + rbx + 12]
    mov  r8, 3 << 40                     ; slot 3
    call ext_w_ind_node_collect
    jmp  .out
.unsupported:
    mov  dword [rel ext4_disk_last_error], EXT_E_UNSUPPORTED
    mov  rax, -1
.out:
    pop  rbx
    ret

; ext_w_ind_node_collect(R12, R15, ESI=node block (0 = absent), EDX=height
;   (1 = its pointers are data), RCX=first logical block, R8=key) -> 0/-1
ext_w_ind_node_collect:
    test esi, esi
    jnz  .present
    xor  eax, eax
    ret
.present:
    push rbx
    push rbp
    push r13
    push r14
    sub  rsp, 8
    mov  ebx, esi
    mov  ebp, edx
    mov  r13, rcx
    mov  r14, r8
    mov  rsi, rbx
    call ext_w_ind_ptr_ok
    jc   .corrupt
    mov  eax, [r15 + ext_wks.tl_n]
    cmp  eax, EXT_TL_MAX
    jae  .toobig
    mov  [r15 + ext_wks.tl + rax * 8], rbx
    mov  [r15 + ext_wks.tlk + rax * 8], r14
    inc  dword [r15 + ext_wks.tl_n]
    mov  qword [rsp], 0
.entry:
    mov  rcx, [rsp]
    mov  eax, [r12 + ext_ctx.block_bytes]
    shr  eax, 2
    cmp  ecx, eax
    jae  .ok
    mov  rsi, rbx
    call ext_meta                        ; re-read: a child read may have replaced it
    test rax, rax
    jz   .fail
    mov  rcx, [rsp]
    mov  esi, [rax + rcx * 4]
    test esi, esi
    jz   .next
    cmp  ebp, 1
    jne  .child
    lea  rdi, [r13 + rcx]
    call ext_w_ind_leaf
    test rax, rax
    jnz  .fail
    jmp  .next
.child:
    mov  r9d, esi                        ; child block
    mov  edx, [r12 + ext_ctx.block_bytes]
    shr  edx, 2                          ; P
    mov  rax, rcx
    imul rax, rdx                        ; i * P
    cmp  ebp, 3
    jne  .span
    imul rax, rdx                        ; i * P^2 under a TIND
.span:
    lea  r10, [r13 + rax]                ; child's first logical block
    mov  rax, r14
    shr  rax, 40
    inc  eax                             ; child slot
    shl  rax, 40
    mov  r8, r14
    shl  r8, 24
    shr  r8, 24                          ; parent index
    imul r8, rdx
    add  r8, rcx
    or   r8, rax                         ; child key = slot+1 << 40 | index * P + i
    mov  esi, r9d
    lea  edx, [rbp - 1]
    mov  rcx, r10
    call ext_w_ind_node_collect
    test rax, rax
    jnz  .fail
.next:
    inc  qword [rsp]
    jmp  .entry
.toobig:
    mov  dword [rel ext4_disk_last_error], EXT_E_TOOBIG
    jmp  .fail
.corrupt:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
.fail:
    mov  rax, -1
    jmp  .out
.ok:
    xor  eax, eax
.out:
    add  rsp, 8
    pop  r14
    pop  r13
    pop  rbp
    pop  rbx
    ret

; ext_w_ind_leaf(R12, R15, RDI=logical block, ESI=pointer; 0 = hole) -> 0/-1
ext_w_ind_leaf:
    test esi, esi
    jz   .ok
    mov  rax, rdi
    shr  rax, 32
    jnz  .corrupt                        ; past 2^32 logical blocks
    mov  esi, esi
    call ext_w_ind_ptr_ok
    jc   .corrupt
    lea  rax, [r15 + ext_wks.tmp_ext]
    mov  [rax], edi
    mov  word [rax + 4], 1
    mov  word [rax + 6], 0
    mov  [rax + 8], rsi
    mov  rsi, rax
    jmp  ext_w_append_extent             ; merges contiguous blocks into one run
.ok:
    xor  eax, eax
    ret
.corrupt:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
    mov  rax, -1
    ret

; ext_w_layout_ind(R12=ctx) -> 0/-1: the nodes wks.xl needs (in walk order,
;   keys in wks.ntk); a node keeps its old block at the same position, others
;   are allocated; old nodes no longer needed are queued for freeing.
ext_w_layout_ind:
    push rbx
    push r13
    push r15
    mov  r15, [r12 + ext_ctx.wks]
    xor  edi, edi
    call ext_w_ind_walk                  ; count: ntree + ntk
    test rax, rax
    jnz  .fail
    xor  ebx, ebx
.node:
    cmp  ebx, [r15 + ext_wks.ntree]
    jae  .leftover
    mov  rax, [r15 + ext_wks.ntk + rbx * 8]
    xor  ecx, ecx
.find:
    cmp  ecx, [r15 + ext_wks.tl_n]
    jae  .alloc
    cmp  [r15 + ext_wks.tlk + rcx * 8], rax
    je   .reuse
    inc  ecx
    jmp  .find
.reuse:
    mov  rax, [r15 + ext_wks.tl + rcx * 8]
    mov  [r15 + ext_wks.nt + rbx * 8], rax
    mov  qword [r15 + ext_wks.tlk + rcx * 8], -1   ; claimed
    inc  ebx
    jmp  .node
.alloc:
    mov  rsi, -1
    shr  rsi, 32
    call ext_w_goal
    mov  rsi, rax
    mov  edx, 1
    call ext_w_alloc
    test rax, rax
    jz   .fail
    mov  rcx, rax
    shr  rcx, 32
    jnz  .toobig                         ; an indirect pointer is 32 bits
    mov  [r15 + ext_wks.nt + rbx * 8], rax
    inc  ebx
    jmp  .node
.leftover:
    xor  ebx, ebx
.old:
    cmp  ebx, [r15 + ext_wks.tl_n]
    jae  .ok
    cmp  qword [r15 + ext_wks.tlk + rbx * 8], -1
    je   .old_next
    mov  rsi, [r15 + ext_wks.tl + rbx * 8]
    mov  edx, 1
    call ext_w_add_free
    test rax, rax
    js   .fail
.old_next:
    inc  ebx
    jmp  .old
.ok:
    xor  eax, eax
    jmp  .out
.toobig:
    mov  dword [rel ext4_disk_last_error], EXT_E_TOOBIG
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r13
    pop  rbx
    ret

; ext_w_serialize_ind(R12=ctx, RDI=inode inside the transaction) -> 0/-1
ext_w_serialize_ind:
    push rdi
    xor  esi, esi
    lea  rdi, [rdi + EI_BLOCK]
    mov  edx, 60
    call memset                          ; i_block: rebuilt from wks.xl
    pop  rdi
    jmp  ext_w_ind_walk

; ext_w_ind_walk(R12=ctx, RDI=inode in the transaction, or 0 = count only)
;   -> 0/-1. Visits every mapped logical block of wks.xl in order.
ext_w_ind_walk:
    push rbx
    push rbp
    push r13
    push r14
    push r15
    mov  rbp, rdi
    mov  r15, [r12 + ext_ctx.wks]
    xor  eax, eax
.reset:
    mov  qword [r15 + ext_wks.iw_key + rax * 8], -1
    inc  eax
    cmp  eax, 6
    jb   .reset
    mov  dword [r15 + ext_wks.ind_n], 0
    test rbp, rbp
    jnz  .walk
    mov  dword [r15 + ext_wks.ntree], 0
.walk:
    xor  ebx, ebx                        ; run
.run:
    cmp  ebx, [r15 + ext_wks.xl_n]
    jae  .end
    mov  rax, rbx
    shl  rax, 4
    lea  r14, [r15 + ext_wks.xl + rax]
    xor  r13d, r13d                      ; block within the run
.block:
    movzx eax, word [r14 + 4]
    cmp  r13d, eax
    jae  .next_run
    mov  edi, [r14]
    add  rdi, r13
    mov  rsi, [r14 + 8]
    add  rsi, r13
    call ext_w_ind_put
    test rax, rax
    jnz  .out
    inc  r13d
    jmp  .block
.next_run:
    inc  ebx
    jmp  .run
.end:
    test rbp, rbp
    jz   .ok
    xor  ebx, ebx
.close:
    cmp  qword [r15 + ext_wks.iw_key + rbx * 8], -1
    je   .close_next
    mov  edi, ebx
    call ext_w_ind_close
    test rax, rax
    jnz  .out
.close_next:
    inc  ebx
    cmp  ebx, 6
    jb   .close
.ok:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbp
    pop  rbx
    ret

; ext_w_ind_put(R12, R15, RBP=inode or 0, RDI=logical block, RSI=physical) -> 0/-1
ext_w_ind_put:
    push rbx
    push r13
    push r14
    mov  rbx, rsi
    shr  rsi, 32
    jnz  .toobig                         ; an indirect pointer is 32 bits
    mov  r13, rdi
    mov  r14d, [r12 + ext_ctx.block_bytes]
    shr  r14d, 2                         ; P
    cmp  r13, 12
    jae  .ind
    test rbp, rbp
    jz   .ok
    mov  [rbp + EI_BLOCK + r13 * 4], ebx
    jmp  .ok
.ind:
    sub  r13, 12
    cmp  r13, r14
    jae  .dind
    xor  edi, edi                        ; slot 0, index 0, parent = i_block[12]
    xor  esi, esi
    mov  edx, -1
    mov  ecx, 12
    call ext_w_ind_open
    test rax, rax
    jz   .fail
    jmp  .leaf
.dind:
    sub  r13, r14
    mov  rax, r14
    imul rax, r14
    cmp  r13, rax
    jae  .tind
    mov  edi, 1
    xor  esi, esi
    mov  edx, -1
    mov  ecx, 13
    call ext_w_ind_open
    test rax, rax
    jz   .fail
    mov  rax, r13
    xor  edx, edx
    div  r14                             ; rax = child, rdx = pointer
    mov  r13, rdx
    mov  edi, 2
    mov  rsi, rax
    mov  edx, 1
    mov  ecx, eax
    call ext_w_ind_open
    test rax, rax
    jz   .fail
    jmp  .leaf
.tind:
    sub  r13, rax                        ; rax = P^2
    imul rax, r14                        ; P^3
    cmp  r13, rax
    jae  .toobig
    mov  edi, 3
    xor  esi, esi
    mov  edx, -1
    mov  ecx, 14
    call ext_w_ind_open
    test rax, rax
    jz   .fail
    mov  rax, r13
    xor  edx, edx
    div  r14                             ; rax = x / P (grandchild index), rdx = pointer
    push rdx
    push rax
    xor  edx, edx
    div  r14                             ; rax = child index, rdx = grandchild within child
    push rdx
    mov  edi, 4
    mov  rsi, rax
    mov  edx, 3
    mov  ecx, eax
    call ext_w_ind_open
    pop  rcx                             ; position inside the child
    pop  rsi                             ; grandchild key index
    pop  r13                             ; pointer position
    test rax, rax
    jz   .fail
    mov  edi, 5
    mov  edx, 4
    call ext_w_ind_open
    test rax, rax
    jz   .fail
.leaf:
    test rbp, rbp
    jz   .ok
    mov  [rax + r13 * 4], ebx
.ok:
    xor  eax, eax
    jmp  .out
.toobig:
    mov  dword [rel ext4_disk_last_error], EXT_E_TOOBIG
.fail:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  rbx
    ret

; ext_w_ind_open(R12, R15, RBP=inode or 0, EDI=slot, RSI=index, EDX=parent
;   slot or -1 (the inode), ECX=pointer position in the parent) -> RAX = the
;   node's new content buffer (count mode: 1) / 0
ext_w_ind_open:
    push rbx
    push r13
    push r14
    mov  ebx, edi
    mov  r13d, edx
    mov  r14d, ecx
    mov  rax, rbx
    shl  rax, 40
    or   rax, rsi                        ; key
    cmp  [r15 + ext_wks.iw_key + rbx * 8], rax
    je   .current
    push rax
    test rbp, rbp
    jz   .count
    cmp  qword [r15 + ext_wks.iw_key + rbx * 8], -1
    je   .fresh
    mov  edi, ebx
    call ext_w_ind_close                 ; the previous node at this position is complete
    test rax, rax
    jnz  .fail_pop
.fresh:
    pop  rax
    mov  [r15 + ext_wks.iw_key + rbx * 8], rax
    mov  ecx, [r15 + ext_wks.ind_n]
    cmp  ecx, [r15 + ext_wks.ntree]
    jae  .corrupt                        ; the count pass planned fewer nodes
    cmp  [r15 + ext_wks.ntk + rcx * 8], rax
    jne  .corrupt
    mov  [r15 + ext_wks.iw_idx + rbx * 4], ecx
    inc  dword [r15 + ext_wks.ind_n]
    mov  rdx, [r15 + ext_wks.nt + rcx * 8]    ; its block
    test r13d, r13d
    js   .in_inode
    mov  rax, r13
    imul rax, rax, EXT_IND_BUF
    lea  rax, [r15 + ext_wks.iw_buf + rax]
    mov  [rax + r14 * 4], edx
    jmp  .linked
.in_inode:
    mov  [rbp + EI_BLOCK + r14 * 4], edx
.linked:
    mov  rax, rbx
    imul rax, rax, EXT_IND_BUF
    lea  rdi, [r15 + ext_wks.iw_buf + rax]
    push rdi
    xor  esi, esi
    mov  edx, [r12 + ext_ctx.block_bytes]
    call memset
    pop  rax
    jmp  .out
.count:
    pop  rax
    mov  [r15 + ext_wks.iw_key + rbx * 8], rax
    mov  ecx, [r15 + ext_wks.ntree]
    cmp  ecx, EXT_TL_MAX
    jae  .toobig
    mov  [r15 + ext_wks.ntk + rcx * 8], rax
    inc  dword [r15 + ext_wks.ntree]
    mov  eax, 1
    jmp  .out
.current:
    mov  eax, 1
    test rbp, rbp
    jz   .out
    mov  rax, rbx
    imul rax, rax, EXT_IND_BUF
    lea  rax, [r15 + ext_wks.iw_buf + rax]
    jmp  .out
.toobig:
    mov  dword [rel ext4_disk_last_error], EXT_E_TOOBIG
    xor  eax, eax
    jmp  .out
.fail_pop:
    add  rsp, 8
    xor  eax, eax
    jmp  .out
.corrupt:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
    xor  eax, eax
.out:
    pop  r14
    pop  r13
    pop  rbx
    ret

; ext_w_ind_close(R12, R15, EDI=slot) -> 0/-1: the node's rebuilt content goes
;   into the transaction unless it is an old node at its old position whose
;   pointers did not change (then it is not touched at all).
ext_w_ind_close:
    push rbx
    push r13
    push r14
    mov  eax, edi
    imul rax, rax, EXT_IND_BUF
    lea  rbx, [r15 + ext_wks.iw_buf + rax]
    mov  ecx, [r15 + ext_wks.iw_idx + rdi * 4]
    mov  r13, [r15 + ext_wks.nt + rcx * 8]    ; block
    xor  ecx, ecx
.old:
    cmp  ecx, [r15 + ext_wks.tl_n]
    jae  .write                          ; a newly allocated node
    cmp  [r15 + ext_wks.tl + rcx * 8], r13
    je   .compare
    inc  ecx
    jmp  .old
.compare:
    mov  rsi, r13
    call ext_meta
    test rax, rax
    jz   .fail
    mov  rdi, rax
    mov  rsi, rbx
    mov  edx, [r12 + ext_ctx.block_bytes]
    call memcmp
    test rax, rax
    jz   .ok                             ; unchanged: no journal block
.write:
    mov  rsi, r13
    mov  edx, 1
    call ext_txn_slot
    test rax, rax
    jz   .fail
    mov  rdi, rax
    mov  rsi, rbx
    mov  edx, [r12 + ext_ctx.block_bytes]
    call memcpy
.ok:
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  rbx
    ret

; ext_w_apply_frees(R12=ctx) -> 0/-1 (after every allocation of this operation)
ext_w_apply_frees:
    push rbx
    push r15
    mov  r15, [r12 + ext_ctx.wks]
    xor  ebx, ebx
.run:
    cmp  ebx, [r15 + ext_wks.fr_n]
    jae  .ok
    mov  rax, rbx
    shl  rax, 4
    mov  rsi, [r15 + ext_wks.fr + rax]
    mov  rdx, [r15 + ext_wks.fr + rax + 8]
    call ext_w_free
    test rax, rax
    jnz  .fail
    inc  ebx
    jmp  .run
.ok:
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  rbx
    ret

; ext_w_put_extent(RDI=dest, RSI=list entry) — on-disk ext4_extent
ext_w_put_extent:
    mov  eax, [rsi]
    mov  [rdi], eax
    movzx eax, word [rsi + 4]
    cmp  word [rsi + 6], 0
    je   .init
    add  eax, EXT_UNINIT_LEN
.init:
    mov  [rdi + 4], ax
    mov  rax, [rsi + 8]
    mov  [rdi + 8], eax
    shr  rax, 32
    mov  [rdi + 6], ax
    ret

; ext_w_put_index(RDI=dest, ESI=first logical block, RDX=child block)
ext_w_put_index:
    mov  [rdi], esi
    mov  [rdi + 4], edx
    shr  rdx, 32
    mov  [rdi + 8], dx
    mov  word [rdi + 10], 0
    ret

; ext_w_put_header(RDI=node, ESI=entries, EDX=max, ECX=depth)
ext_w_put_header:
    mov  word [rdi], EXT_EH_MAGIC
    mov  [rdi + 2], si
    mov  [rdi + 4], dx
    mov  [rdi + 6], cx
    mov  dword [rdi + 8], 0
    ret

; ext_w_tail(R12=ctx, RDI=tree block) — metadata_csum extent tail
ext_w_tail:
    test dword [r12 + ext_ctx.ro_compat], EXT_RO_METADATA_CSUM
    jz   .out
    push rbx
    mov  rbx, rdi
    movzx esi, word [rbx + 4]
    imul esi, esi, 12
    add  esi, 12
    mov  edx, [r12 + ext_ctx.inode + EXT_SLOT_SEED]
    call ext_crc32c
    movzx ecx, word [rbx + 4]
    imul ecx, ecx, 12
    mov  [rbx + rcx + 12], eax
    pop  rbx
.out:
    ret

; ext_w_serialize(R12=ctx, RDI=inode inside the transaction) -> 0/-1
ext_w_serialize:
    mov  rax, [r12 + ext_ctx.wks]
    cmp  dword [rax + ext_wks.ind], 0
    jne  ext_w_serialize_ind
    push rbx
    push rbp
    push r13
    push r14
    push r15
    mov  rbp, rdi
    mov  r15, [r12 + ext_ctx.wks]
    mov  eax, [r12 + ext_ctx.block_bytes]
    sub  eax, 12
    xor  edx, edx
    mov  ecx, 12
    div  ecx
    mov  r13d, eax                       ; per-block capacity
    ; ---- leaves ----
    xor  ebx, ebx                        ; leaf index
.leaf:
    cmp  ebx, [r15 + ext_wks.leaves]
    jae  .leaves_done
    mov  rsi, [r15 + ext_wks.nt + rbx * 8]
    mov  edx, 1
    call ext_txn_slot
    test rax, rax
    jz   .fail
    mov  r14, rax
    mov  eax, ebx
    imul eax, r13d                       ; first extent of this leaf
    mov  ecx, [r15 + ext_wks.xl_n]
    sub  ecx, eax
    cmp  ecx, r13d
    jbe  .count
    mov  ecx, r13d
.count:
    push rax
    push rcx
    mov  rdi, r14
    mov  esi, ecx
    mov  edx, r13d
    xor  ecx, ecx
    call ext_w_put_header
    pop  rcx
    pop  rax
    lea  rdi, [r14 + 12]
.leaf_entry:
    test ecx, ecx
    jz   .leaf_tail
    mov  rsi, rax
    shl  rsi, 4
    lea  rsi, [r15 + ext_wks.xl + rsi]
    push rax
    push rcx
    push rdi
    call ext_w_put_extent
    pop  rdi
    pop  rcx
    pop  rax
    add  rdi, 12
    inc  eax
    dec  ecx
    jmp  .leaf_entry
.leaf_tail:
    mov  rdi, r14
    call ext_w_tail
    inc  ebx
    jmp  .leaf
.leaves_done:
    ; ---- index blocks (depth 2) ----
    xor  ebx, ebx
.ib:
    cmp  ebx, [r15 + ext_wks.idxblocks]
    jae  .root
    mov  eax, [r15 + ext_wks.leaves]
    add  eax, ebx
    mov  rsi, [r15 + ext_wks.nt + rax * 8]
    mov  edx, 1
    call ext_txn_slot
    test rax, rax
    jz   .fail
    mov  r14, rax
    mov  eax, ebx
    imul eax, r13d                       ; first leaf under this index block
    mov  ecx, [r15 + ext_wks.leaves]
    sub  ecx, eax
    cmp  ecx, r13d
    jbe  .icount
    mov  ecx, r13d
.icount:
    push rax
    push rcx
    mov  rdi, r14
    mov  esi, ecx
    mov  edx, r13d
    mov  ecx, 1
    call ext_w_put_header
    pop  rcx
    pop  rax
    lea  rdi, [r14 + 12]
.ib_entry:
    test ecx, ecx
    jz   .ib_tail
    call .leaf_index
    add  rdi, 12
    inc  eax
    dec  ecx
    jmp  .ib_entry
.ib_tail:
    mov  rdi, r14
    call ext_w_tail
    inc  ebx
    jmp  .ib
.root:
    ; ---- the in-inode root ----
    lea  rdi, [rbp + EI_BLOCK]
    xor  esi, esi
    mov  edx, 60
    call memset
    lea  rdi, [rbp + EI_BLOCK]
    mov  ecx, [r15 + ext_wks.depth]
    mov  esi, [r15 + ext_wks.xl_n]
    cmp  ecx, 1
    jne  .root_d
    mov  esi, [r15 + ext_wks.leaves]
.root_d:
    cmp  ecx, 2
    jne  .root_h
    mov  esi, [r15 + ext_wks.idxblocks]
.root_h:
    mov  r14d, esi
    mov  edx, 4
    call ext_w_put_header
    lea  rdi, [rbp + EI_BLOCK + 12]
    xor  eax, eax
    mov  ecx, [r15 + ext_wks.depth]
    test ecx, ecx
    jz   .root_extents
    cmp  ecx, 1
    je   .root_leaves
    ; depth 2: one entry per index block
.root_ib:
    cmp  eax, r14d
    jae  .done
    push rax
    push rdi
    mov  ecx, eax
    imul ecx, r13d                       ; its first leaf
    imul ecx, r13d                       ; that leaf's first extent
    shl  rcx, 4
    mov  esi, [r15 + ext_wks.xl + rcx]
    mov  ecx, [r15 + ext_wks.leaves]
    add  ecx, eax
    mov  rdx, [r15 + ext_wks.nt + rcx * 8]
    call ext_w_put_index
    pop  rdi
    pop  rax
    add  rdi, 12
    inc  eax
    jmp  .root_ib
.root_leaves:
    cmp  eax, r14d
    jae  .done
    call .leaf_index
    add  rdi, 12
    inc  eax
    jmp  .root_leaves
.root_extents:
    cmp  eax, r14d
    jae  .done
    mov  rsi, rax
    shl  rsi, 4
    lea  rsi, [r15 + ext_wks.xl + rsi]
    push rax
    push rdi
    call ext_w_put_extent
    pop  rdi
    pop  rax
    add  rdi, 12
    inc  eax
    jmp  .root_extents
.done:
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbp
    pop  rbx
    ret
.leaf_index:                             ; RDI=dest, EAX=leaf index (kept)
    push rax
    push rcx
    push rdi
    mov  ecx, eax
    imul ecx, r13d
    shl  rcx, 4
    mov  esi, [r15 + ext_wks.xl + rcx]
    mov  rdx, [r15 + ext_wks.nt + rax * 8]
    call ext_w_put_index
    pop  rdi
    pop  rcx
    pop  rax
    ret

; ext_w_finish_inode(R12=ctx, RDI=inode inside the transaction) -> 0/-1:
;   size, i_blocks, EXTENTS flag, checksum.
ext_w_finish_inode:
    push rbx
    push r15
    mov  rbx, rdi
    mov  r15, [r12 + ext_ctx.wks]
    mov  rax, [r15 + ext_wks.new_size]
    mov  [rbx + EI_SIZE_LO], eax
    shr  rax, 32
    mov  [rbx + EI_SIZE_HI], eax
    cmp  dword [r15 + ext_wks.ind], 0
    jne  .mapped                         ; an indirect-mapped inode stays indirect-mapped
    or   dword [rbx + EI_FLAGS], EXT_FL_EXTENTS
.mapped:
    ; i_blocks (512-byte units) = (mapped blocks + tree blocks) * bs/512
    xor  eax, eax
    mov  ecx, [r15 + ext_wks.xl_n]
    lea  rdx, [r15 + ext_wks.xl]
.sum:
    test ecx, ecx
    jz   .summed
    movzx r8d, word [rdx + 4]
    add  rax, r8
    add  rdx, 16
    dec  ecx
    jmp  .sum
.summed:
    mov  ecx, [r15 + ext_wks.ntree]
    add  rax, rcx
    push rax
    mov  rdi, rbx
    call ext_w_ea_block
    mov  rcx, rax
    pop  rax
    test rcx, rcx
    jz   .no_ea
    inc  rax                             ; the extended-attribute block is the inode's too
.no_ea:
    mov  ecx, [r12 + ext_ctx.spb_shift]
    shl  rax, cl
    mov  rdx, rax
    shr  rdx, 32
    jz   .fits
    test dword [r12 + ext_ctx.ro_compat], EXT_RO_HUGE_FILE
    jz   .toobig
    cmp  rdx, 0xFFFF
    ja   .toobig
.fits:
    mov  [rbx + EI_BLOCKS_LO], eax
    mov  [rbx + EI_BLOCKS_HI], dx        ; osd2.l_i_blocks_high (base inode)
    mov  rdi, rbx
    mov  esi, EXT_DI_MTIME
    call ext_w_mark_ptr                  ; content changed: mtime at ext_w_end
    ; the checksum is sealed by ext_w_finish_dirty (the inode is in the dirty list)
    xor  eax, eax
    jmp  .out
.toobig:
    mov  dword [rel ext4_disk_last_error], EXT_E_TOOBIG
    mov  rax, -1
.out:
    pop  r15
    pop  rbx
    ret

; ext_w_finish_groups(R12=ctx) -> 0/-1: bitmap + descriptor checksums
ext_w_finish_groups:
    push rbx
    push r13
    push r14
    push r15
    mov  r15, [r12 + ext_ctx.wks]
    test dword [r12 + ext_ctx.ro_compat], EXT_RO_METADATA_CSUM
    jz   .ok
    xor  ebx, ebx
.group:
    cmp  ebx, [r15 + ext_wks.tg_n]
    jae  .ok
    mov  r13d, [r15 + ext_wks.tg + rbx * 4]
    mov  esi, r13d
    call ext_w_gd
    test rax, rax
    jz   .fail
    mov  r14, rax
    mov  rdi, rax
    call ext_w_bitmap_blk
    test rax, rax
    jz   .fail
    mov  rsi, rax
    xor  edx, edx
    call ext_txn_slot
    test rax, rax
    jz   .fail
    mov  rdi, rax
    mov  esi, [r12 + ext_ctx.blocks_per_g]
    shr  esi, 3
    mov  edx, [r12 + ext_ctx.csum_seed]
    call ext_crc32c
    mov  [r14 + EGD_BBITMAP_CSUM_LO], ax
    cmp  dword [r12 + ext_ctx.desc_size], EGD_BBITMAP_CSUM_HI + 4
    jb   .gd
    shr  eax, 16
    mov  [r14 + EGD_BBITMAP_CSUM_HI], ax
.gd:
    mov  rdi, r14
    mov  esi, r13d
    call ext_gd_csum
    mov  [r14 + EGD_CHECKSUM], ax
    inc  ebx
    jmp  .group
.ok:
    ; inode bitmaps (E2b): bitmap checksum, then the descriptor checksum again
    test dword [r12 + ext_ctx.ro_compat], EXT_RO_METADATA_CSUM
    jz   .done
    xor  ebx, ebx
.igroup:
    cmp  ebx, [r15 + ext_wks.tig_n]
    jae  .done
    mov  r13d, [r15 + ext_wks.tig + rbx * 4]
    mov  esi, r13d
    call ext_w_gd
    test rax, rax
    jz   .fail
    mov  r14, rax
    mov  rdi, rax
    call ext_w_ibitmap_blk
    test rax, rax
    jz   .fail
    mov  rsi, rax
    xor  edx, edx
    call ext_txn_slot
    test rax, rax
    jz   .fail
    mov  rdi, rax
    mov  esi, [r12 + ext_ctx.inodes_per_g]
    shr  esi, 3
    mov  edx, [r12 + ext_ctx.csum_seed]
    call ext_crc32c
    mov  [r14 + EGD_IBITMAP_CSUM_LO], ax
    cmp  dword [r12 + ext_ctx.desc_size], 64
    jb   .igd
    shr  eax, 16
    mov  [r14 + EGD_IBITMAP_CSUM_HI], ax
.igd:
    mov  rdi, r14
    mov  esi, r13d
    call ext_gd_csum
    mov  [r14 + EGD_CHECKSUM], ax
    inc  ebx
    jmp  .igroup
.done:
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

; ext_w_sb_ptr(R12=ctx) -> RAX = superblock inside the transaction / 0
ext_w_sb_ptr:
    mov  rsi, [r12 + ext_ctx.sb_blk]
    xor  edx, edx
    call ext_txn_slot
    test rax, rax
    jz   .out
    mov  ecx, [r12 + ext_ctx.sb_off]
    add  rax, rcx
.out:
    ret

; ext_w_sb_seal(R12=ctx, RDI=superblock) — recompute its checksum
ext_w_sb_seal:
    test dword [r12 + ext_ctx.ro_compat], EXT_RO_METADATA_CSUM
    jz   .out
    push rbx
    mov  rbx, rdi
    mov  esi, ESB_CSUM
    mov  edx, 0xFFFFFFFF
    call ext_crc32c
    mov  [rbx + ESB_CSUM], eax
    pop  rbx
.out:
    ret

; ext_w_finish_sb(R12=ctx) -> 0/-1: free count += delta, RECOVER set (it is
;   cleared again after the checkpoint), checksum.
ext_w_finish_sb:
    push rbx
    push r15
    mov  r15, [r12 + ext_ctx.wks]
    call ext_w_sb_ptr
    test rax, rax
    jz   .fail
    mov  rbx, rax
    mov  eax, [rbx + ESB_FREE_LO]
    test dword [r12 + ext_ctx.incompat], EXT_IN_64BIT
    jz   .lo
    mov  ecx, [rbx + ESB_FREE_HI]
    shl  rcx, 32
    or   rax, rcx
.lo:
    add  rax, [r15 + ext_wks.free_delta]
    mov  [rbx + ESB_FREE_LO], eax
    test dword [r12 + ext_ctx.incompat], EXT_IN_64BIT
    jz   .inodes
    shr  rax, 32
    mov  [rbx + ESB_FREE_HI], eax
.inodes:
    mov  eax, [rbx + ESB_FREE_INODES]
    add  rax, [r15 + ext_wks.ifree_delta]
    mov  [rbx + ESB_FREE_INODES], eax
.flag:
    or   dword [rbx + ESB_INCOMPAT], EXT_IN_RECOVER
    mov  rdi, rbx
    call ext_w_sb_seal
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  rbx
    ret

; ext_w_capacity(R12=ctx) -> 0/-1: one descriptor, journal room, mapped journal.
ext_w_capacity:
    push rbx
    push r15
    mov  r15, [r12 + ext_ctx.wks]
    mov  eax, [r12 + ext_ctx.block_bytes]
    sub  eax, 12 + 16                    ; header + the one UUID
    cmp  dword [r12 + ext_ctx.j_csum3], 1
    jne  .tags
    sub  eax, 4                          ; descriptor tail
.tags:
    xor  edx, edx
    div  dword [r12 + ext_ctx.j_tagbytes]
    mov  ecx, [r15 + ext_wks.txn_n]
    test ecx, ecx
    jz   .toobig
    cmp  ecx, eax
    ja   .toobig
    ; journal blocks first .. first+n+1 must be mapped, initialized blocks
    xor  ebx, ebx
.map:
    mov  eax, [r15 + ext_wks.txn_n]
    add  eax, 2
    cmp  ebx, eax
    jae  .ok
    mov  esi, [r12 + ext_ctx.j_first]
    add  rsi, rbx
    lea  rdi, [r12 + ext_ctx.jino]
    call ext_map
    test rax, rax
    jle  .gate
    mov  [r15 + ext_wks.jmap + rbx * 8], rax
    inc  ebx
    jmp  .map
.ok:
    xor  eax, eax
    jmp  .out
.toobig:
    mov  dword [rel ext4_disk_last_error], EXT_E_TOOBIG
    mov  rax, -1
    jmp  .out
.gate:
    mov  dword [rel ext4_disk_last_error], EXT_E_WGATE
    mov  rax, -1
.out:
    pop  r15
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; Job windows (SEC-S6): the copy job's background steps
; ---------------------------------------------------------------------------
; A copy STEP runs from the idle tick under IMPLICIT intent, where the
; per-transaction gate refuses a SENSITIVE volume. BEGIN, inside the owner's
; request, takes a job window over this mount's partition window
; (ext_w_job_open). A STEP sets ext_w_job_step around its one transaction
; (ext_w_job_step_begin / _done). ext_w_begin then latches the window's tag into
; wks.job_tag INSTEAD of calling ext_w_storage_gate, which never sees a tag, and
; only while the intent is IMPLICIT, so a request never borrows the job.
; ext_w_end presents every block the transaction will write before the first
; write (ext_w_job_prepass), and ext_dev_write presents the exact absolute range
; of each blk_write. Arm, every non-copy writer, and a copy step under a request
; keep ext_w_storage_gate. The window ends on DONE / CANCELLED / FAILED, disarm,
; the next BEGIN, and a changed medium (ext_w_job_close).

; ext_w_job_open(R12=ctx) -> RAX 0 / -1 (EXT_E_DENIED): a window over ctx's
;   partition, permitted only as storage_access_require_request permits under
;   the current request's intent.
ext_w_job_open:
    push rbx
    call ext_w_job_close                 ; one window at a time
    mov  rax, [r12 + ext_ctx.dev]
    mov  rbx, [rax + dev.info]
    test rbx, rbx
    jz   .denied
    mov  rbx, [rbx + blk_info.media_generation]
%if EXT_W_OWNED
    cmp  qword [r12 + ext_ctx.owned_token], 0
    je   .grant
    call storage_access_request_owner    ; an owned job: BEGIN is the OWNER's request (rc-sec S1)
    test eax, eax
    jnz  .owned                          ; no window: every STEP opens its own owned op
.grant:
%endif
    mov  rdi, [r12 + ext_ctx.dev]
    mov  rsi, [r12 + ext_ctx.part_lba]
    mov  rdx, [r12 + ext_ctx.part_sectors]
    lea  r8, [rel str_ew_job_caller]
    call storage_access_job_grant        ; tag > 0 / -1
    cmp  rax, -1
    je   .denied
    test rax, rax
    jz   .denied
    mov  [rel ext_w_job_tag], rax
%if EXT_W_OWNED
.owned:
%endif
    mov  [rel ext_w_job_ctx], r12
    mov  rax, [r12 + ext_ctx.dev]
    mov  [rel ext_w_job_dev], rax
    mov  [rel ext_w_job_gen], rbx
    call ext_w_job_capture
    xor  eax, eax
    jmp  .out
.denied:
    mov  dword [rel ext4_disk_last_error], EXT_E_DENIED
    mov  rax, -1
.out:
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; RCQ-20 S5c: a queued copy's carried decision (rc-sec rev 3 6454fc74; root 14:09:28)
; ---------------------------------------------------------------------------
; An ext4 FSCOPY that arrives while a job is live may queue only from a CONSOLE
; frame of the OWNER (the command layer refuses a remote frame first). Its
; decision is recorded as an fs_copy_carry: no window, no owned op and no grant
; at enqueue (R1). The dequeue's BEGIN is decided from that record, passed as an
; argument, and never from request state (R2: sa_request_owner/_intent are never
; read or written on this path). The carry is spent once, before any check.

; ext_w_carry_record(RDI=fsmount, RSI=fs_copy_carry) -> RAX 0 recorded / -1 this
;   enqueue carries nothing (not an armed live ext4 mount, not the OWNER's request,
;   owned ops latched, an unreadable generation or class, or a SENSITIVE window
;   without SPECIAL intent where BEGIN would ask the gate). Writes the carry only
;   on success. The caller refuses the enqueue (job_active) on -1. A public build
;   (EXT_W_OWNED 0) always answers -1: it reads no owned-API symbol.
ext_w_carry_record:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, fs_copy_carry_size + 8
    mov  [rsp + fs_copy_carry_size], rsi
    mov  rbx, rdi
    mov  r13, rsp                        ; publish nothing until every check holds
    mov  rax, [rbx + fsmount.ops]
    lea  rcx, [rel ext_ops]
    cmp  rax, rcx
    jne  .no                             ; not an ext4 mount
    mov  rdi, rbx
    call ext_w_enter                     ; mounted, armed and not dead
    test rax, rax
    jz   .no
    mov  r12, rax
%if EXT_W_OWNED
    call storage_access_request_owner
    cmp  eax, 1
    jne  .no                             ; only the OWNER's own request carries (rev 3 C1)
%else
    jmp  .no                             ; a public build has no owner identity (the HOLD): nothing carries
%endif
    call storage_access_owned_latched
    test eax, eax
    jnz  .no                             ; (h)
    mov  rax, [r12 + ext_ctx.dev]
    test rax, rax
    jz   .no
    mov  rcx, [rax + dev.info]
    test rcx, rcx
    jz   .no
    mov  r14, [rcx + blk_info.media_generation]
    test r14, r14
    jz   .no                             ; unreadable or 0: refused at enqueue (rev 3 C3 (b))
    ; Snapshot before the classification read; a route change during that
    ; read must not be published as the owner's carried decision.
    mov  rax, [r12 + ext_ctx.dev]
    mov  [r13 + fs_copy_carry.dev], rax
    mov  rdx, [r12 + ext_ctx.part_lba]
    mov  [r13 + fs_copy_carry.part_lba], rdx
    mov  rdx, [r12 + ext_ctx.part_sectors]
    mov  [r13 + fs_copy_carry.part_sectors], rdx
    mov  rdx, [rax + dev.ops]
    mov  [r13 + fs_copy_carry.ops], rdx
    mov  rdx, [rax + dev.priv]
    mov  [r13 + fs_copy_carry.priv], rdx
    mov  rsi, [rax + dev.info]
    mov  [r13 + fs_copy_carry.info], rsi
    add  rsi, blk_info.sector_size
    lea  rdi, [r13 + fs_copy_carry.geometry]
    mov  edx, blk_info_size - blk_info.sector_size
    call memcpy
    call storage_access_request_intent
    mov  r15d, eax
    mov  rdi, [r12 + ext_ctx.dev]
    mov  rsi, [r12 + ext_ctx.part_lba]
    mov  rdx, [r12 + ext_ctx.part_sectors]
    call storage_access_classify         ; a read of LBA 1: no grant, no window
    cmp  eax, SA_CLASS_UNKNOWN
    je   .no
%if EXT_W_OWNED
    cmp  qword [r12 + ext_ctx.owned_token], 0
    jne  .classed                        ; an owned BEGIN asks no gate: its OWNER request decides
%endif
    cmp  eax, SA_CLASS_SENSITIVE
    jne  .classed
    cmp  r15d, SA_INTENT_SPECIAL
    jne  .no                             ; as the gate would refuse this window under this intent (rev 3 (d))
.classed:
    mov  [r13 + fs_copy_carry.class], eax
    mov  rdi, r13
    mov  r8, r12
    call ext_w_carry_route_check
    test eax, eax
    jnz  .no
    mov  [r13 + fs_copy_carry.intent], r15d
    mov  dword [r13 + fs_copy_carry.owner], 1
    mov  [r13 + fs_copy_carry.ctx], r12
    mov  rax, [r12 + ext_ctx.dev]
    mov  [r13 + fs_copy_carry.dev], rax
    mov  rax, [r12 + ext_ctx.part_lba]
    mov  [r13 + fs_copy_carry.part_lba], rax
    mov  rax, [r12 + ext_ctx.part_sectors]
    mov  [r13 + fs_copy_carry.part_sectors], rax
    mov  [r13 + fs_copy_carry.gen], r14
    mov  rax, [r12 + ext_ctx.owned_token]
    mov  [r13 + fs_copy_carry.owned_token], rax
    call boot_ms_now
    mov  [r13 + fs_copy_carry.t_enqueue], rax
    inc  qword [rel ext_w_carry_seq]     ; 64-bit: never reissued
    mov  rax, [rel ext_w_carry_seq]
    mov  [r13 + fs_copy_carry.id], rax
    mov  dword [r13 + fs_copy_carry.kind], FS_CARRY_EXT4
    mov  rdi, [rsp + fs_copy_carry_size]
    mov  rsi, r13
    mov  edx, fs_copy_carry_size
    call memcpy
    xor  eax, eax
    jmp  .out
.no:
    mov  rax, -1
.out:
    add  rsp, fs_copy_carry_size + 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ext_w_carry_check(RDI=fs_copy_carry) -> EAX 0 it still holds / the FS_CREF_* it
;   no longer holds by: mount_changed (another device, partition window or media
;   generation, or a generation that cannot be read), arm_changed (disarmed, dead,
;   or another owned token), carry_expired (older than FS_CARRY_MAX_AGE_MS). The
;   dequeue (stamp op 3), the sweep (op 4) and ext_w_job_open_carried all ask it.
;   Clobbers RAX, RCX, RDX, R8.
ext_w_carry_check:
    mov  r8, [rdi + fs_copy_carry.ctx]
    test r8, r8
    jz   .mount
    cmp  dword [r8 + ext_ctx.mounted], 1
    jne  .mount
    mov  rax, [r8 + ext_ctx.dev]
    cmp  rax, [rdi + fs_copy_carry.dev]
    jne  .mount
    mov  rcx, [r8 + ext_ctx.part_lba]
    cmp  rcx, [rdi + fs_copy_carry.part_lba]
    jne  .mount
    mov  rcx, [r8 + ext_ctx.part_sectors]
    cmp  rcx, [rdi + fs_copy_carry.part_sectors]
    jne  .mount
    test rax, rax
    jz   .mount
    call ext_w_carry_route_check
    test eax, eax
    jnz  .mount
    mov  rax, [r8 + ext_ctx.dev]
    mov  rax, [rax + dev.info]
    test rax, rax
    jz   .mount
    mov  rax, [rax + blk_info.media_generation]
    test rax, rax
    jz   .mount                          ; a failed read counts as changed
    cmp  rax, [rdi + fs_copy_carry.gen]
    jne  .mount
    cmp  dword [r8 + ext_ctx.armed], 1
    jne  .arm
    cmp  dword [r8 + ext_ctx.wdead], 0
    jne  .arm
    mov  rax, [r8 + ext_ctx.owned_token]
    cmp  rax, [rdi + fs_copy_carry.owned_token]
    jne  .arm                            ; disarm + arm again: another token (rev 3 C3 (e))
    push rdi
    call boot_ms_now
    pop  rdi
    sub  rax, [rdi + fs_copy_carry.t_enqueue]
    cmp  rax, FS_CARRY_MAX_AGE_MS
    ja   .expired                        ; (g) a carry never outlives its window
    xor  eax, eax
    ret
.mount:
    mov  eax, FS_CREF_MOUNT_CHANGED
    ret
.arm:
    mov  eax, FS_CREF_ARM_CHANGED
    ret
.expired:
    mov  eax, FS_CREF_CARRY_EXPIRED
    ret

; RDI=carried decision, R8=its context. Same address/generation cannot
; authorize a substituted backend route or geometry. No I/O or authority here.
; Preserves RDI/R8; clobbers RAX,RCX,RDX (private to carry predicates).
ext_w_carry_route_check:
    mov  rax, [r8 + ext_ctx.dev]
    cmp  rax, [rdi + fs_copy_carry.dev]
    jne  .bad
    test rax, rax
    jz   .bad
    mov  rcx, [rax + dev.ops]
    cmp  rcx, [rdi + fs_copy_carry.ops]
    jne  .bad
    mov  rcx, [rax + dev.priv]
    cmp  rcx, [rdi + fs_copy_carry.priv]
    jne  .bad
    mov  rdx, [rax + dev.info]
    cmp  rdx, [rdi + fs_copy_carry.info]
    jne  .bad
    test rdx, rdx
    jz   .bad
    mov  rcx, [r8 + ext_ctx.part_lba]
    cmp  rcx, [rdi + fs_copy_carry.part_lba]
    jne  .bad
    mov  rcx, [r8 + ext_ctx.part_sectors]
    cmp  rcx, [rdi + fs_copy_carry.part_sectors]
    jne  .bad
    xor  ecx, ecx
.bytes:
    mov  al, [rdx + rcx + blk_info.sector_size]
    cmp  al, [rdi + rcx + fs_copy_carry.geometry]
    jne  .bad
    inc  ecx
    cmp  ecx, blk_info_size - blk_info.sector_size
    jb   .bytes
    xor  eax, eax
    ret
.bad:
    mov  eax, FS_CREF_MOUNT_CHANGED
    ret

; ext_w_job_open_carried(R12=ctx, RDI=the job: .carry -> its fs_copy_carry) -> RAX 0
;   / -1 (EXT_E_DENIED; vfs_copy_refusal names mount_changed, arm_changed,
;   carry_expired or class_changed when that is why). ext_w_job_open for the
;   dequeue's FS_COPY_BEGIN_CARRIED: the job's .carry is cleared and the carry
;   itself zeroed before any check, an id at or below the last spent one is
;   refused (take-once), and then C3: the carry still holds (ext_w_carry_check),
;   owned ops not latched (h), the same class (c), and the window under the
;   CARRIED intent (d) or, for an owned mount, the same arm (e) with no window.
ext_w_job_open_carried:
    push rbx
    push r13
    sub  rsp, fs_copy_carry_size + 8
    mov  rbx, [rdi + fs_copy_job.carry]
    mov  qword [rdi + fs_copy_job.carry], 0   ; consumed before any check (rev 3 C2, C4a (i))
    call ext_w_job_close                 ; one window at a time
    test rbx, rbx
    jz   .denied
    mov  rdi, rsp
    mov  rsi, rbx
    mov  edx, fs_copy_carry_size
    call memcpy
    mov  rdi, rbx
    xor  esi, esi
    mov  edx, fs_copy_carry_size
    call memset                          ; the carry reads zero from here on
    mov  rbx, rsp                        ; the spent copy
    cmp  dword [rbx + fs_copy_carry.kind], FS_CARRY_EXT4
    jne  .denied
    mov  rax, [rbx + fs_copy_carry.id]
    cmp  rax, [rel ext_w_carry_spent]
    jbe  .denied                         ; an id at or below the last spent one never begins
    mov  [rel ext_w_carry_spent], rax
    cmp  dword [rbx + fs_copy_carry.owner], 1
    jne  .denied
    cmp  [rbx + fs_copy_carry.ctx], r12
    jne  .mount
    mov  rdi, rbx
    call ext_w_carry_check               ; (a) (b) (e) (g)
    test eax, eax
    jnz  .typed
    call storage_access_owned_latched
    test eax, eax
    jnz  .denied                         ; (h)
    mov  rdi, [rbx + fs_copy_carry.dev]
    mov  rsi, [rbx + fs_copy_carry.part_lba]
    mov  rdx, [rbx + fs_copy_carry.part_sectors]
    call storage_access_classify
    cmp  eax, [rbx + fs_copy_carry.class]
    mov  eax, FS_CREF_CLASS_CHANGED
    jne  .typed                          ; (c) a read fault classifies UNKNOWN, never the recorded class
    mov  rdi, rbx
    call ext_w_carry_check               ; classification I/O cannot change the carried route/arm
    test eax, eax
    jnz  .typed
%if EXT_W_OWNED
    cmp  qword [rbx + fs_copy_carry.owned_token], 0
    jne  .owned                          ; (e) held by ext_w_carry_check: the same arm; no window
%endif
    mov  rdi, [rbx + fs_copy_carry.dev]
    mov  rsi, [rbx + fs_copy_carry.part_lba]
    mov  rdx, [rbx + fs_copy_carry.part_sectors]
    mov  ecx, [rbx + fs_copy_carry.intent]
    lea  r8, [rel str_ew_job_carried]
    call storage_access_job_grant_carried   ; (d) tag > 0 / -1, under the CARRIED intent
    cmp  rax, -1
    je   .denied
    test rax, rax
    jz   .denied
    mov  [rel ext_w_job_tag], rax
%if EXT_W_OWNED
.owned:
%endif
    mov  [rel ext_w_job_ctx], r12
    mov  rax, [rbx + fs_copy_carry.dev]
    mov  [rel ext_w_job_dev], rax
    mov  rax, [rbx + fs_copy_carry.gen]
    mov  [rel ext_w_job_gen], rax
    call ext_w_job_capture
    xor  eax, eax
    jmp  .out
.mount:
    mov  eax, FS_CREF_MOUNT_CHANGED
.typed:
    mov  [rel vfs_copy_refusal], eax
.denied:
    mov  dword [rel ext4_disk_last_error], EXT_E_DENIED
    mov  rax, -1
.out:
    add  rsp, fs_copy_carry_size + 8
    pop  r13
    pop  rbx
    ret

; ext_w_job_close() - ends the window, with any request grant it left on the
;   device. Clobbers RAX, RCX, RDI, R8-R11.
ext_w_job_close:
    mov  dword [rel ext_w_job_step], 0
%if EXT_W_OWNED
    xor  eax, eax
    cmp  [rel ext_w_job_tag], rax
    je   .forget                         ; an owned job (or none) has no window: it just ends
%endif
    mov  rdi, [rel ext_w_job_tag]
    test rdi, rdi
    jz   .out
    call storage_access_job_revoke
    xor  eax, eax
    mov  [rel ext_w_job_tag], rax
%if EXT_W_OWNED
.forget:
%endif
    mov  [rel ext_w_job_ctx], rax
    mov  [rel ext_w_job_dev], rax
    mov  [rel ext_w_job_gen], rax
.out:
    ret

; ext_w_job_step_begin(R12=ctx) -> RAX 0, ext_w_job_step = 1: this STEP may
;   present the window (this mount, same device, same medium) / -1
;   (EXT_E_DENIED): no window; one on another medium is closed.
ext_w_job_step_begin:
    mov  dword [rel ext_w_job_step], 0
%if EXT_W_OWNED
    cmp  qword [rel ext_w_job_tag], 0
    jne  .window
    cmp  qword [rel ext_w_job_ctx], 0
    jne  .same                           ; an owned job: the same mount/device/medium checks
.window:
%endif
    cmp  qword [rel ext_w_job_tag], 0
    je   .none
%if EXT_W_OWNED
.same:
%endif
    cmp  [rel ext_w_job_ctx], r12
    jne  .close
    call ext_w_job_custody
    test rax, rax
    jnz  .close
    mov  rax, [r12 + ext_ctx.dev]
    cmp  rax, [rel ext_w_job_dev]
    jne  .close
    mov  rax, [rax + dev.info]
    test rax, rax
    jz   .close
    mov  rax, [rax + blk_info.media_generation]
    cmp  rax, [rel ext_w_job_gen]
    jne  .close
    mov  dword [rel ext_w_job_step], 1
    xor  eax, eax
    ret
.close:
    call ext_w_job_close
.none:
    mov  dword [rel ext4_disk_last_error], EXT_E_DENIED
    mov  rax, -1
    ret

; A live copy window authorizes one immutable destination route, geometry and
; partition. A generation alone cannot distinguish a substituted backend/unit.
; Capture runs only after normal or carried BEGIN obtained its existing window.
; No authority is granted here. Helpers preserve every register except RAX.
ext_w_job_capture:
    push rdi
    push rsi
    push rdx
    push rcx
    mov  rax, [r12 + ext_ctx.dev]
    mov  rdx, [rax + dev.ops]
    mov  [rel ext_w_job_ops], rdx
    mov  rdx, [rax + dev.priv]
    mov  [rel ext_w_job_priv], rdx
    mov  rsi, [rax + dev.info]
    mov  [rel ext_w_job_info], rsi
    add  rsi, blk_info.sector_size
    lea  rdi, [rel ext_w_job_geometry]
    mov  edx, blk_info_size - blk_info.sector_size
    call memcpy
    mov  rax, [r12 + ext_ctx.part_lba]
    mov  [rel ext_w_job_lba], rax
    mov  rax, [r12 + ext_ctx.part_sectors]
    mov  [rel ext_w_job_sectors], rax
    pop  rcx
    pop  rdx
    pop  rsi
    pop  rdi
    ret

; R12=context. Inactive for other contexts/non-job writes. Keep a lost route
; bound until the ordinary job failure closes the window: never reclaim a
; partial on a replacement destination, even when it has the same UUID.
ext_w_job_custody:
    push rdi
    push rsi
    push rdx
    push rcx
    cmp  qword [rel ext_w_job_ctx], 0
    je   .ok
    cmp  [rel ext_w_job_ctx], r12
    jne  .ok
    cmp  dword [r12 + ext_ctx.mounted], 1
    jne  .bad
    mov  rax, [r12 + ext_ctx.dev]
    cmp  rax, [rel ext_w_job_dev]
    jne  .bad
    test rax, rax
    jz   .bad
    mov  rdx, [rax + dev.ops]
    cmp  rdx, [rel ext_w_job_ops]
    jne  .bad
    mov  rdx, [rax + dev.priv]
    cmp  rdx, [rel ext_w_job_priv]
    jne  .bad
    mov  rsi, [rax + dev.info]
    cmp  rsi, [rel ext_w_job_info]
    jne  .bad
    test rsi, rsi
    jz   .bad
    mov  rax, [r12 + ext_ctx.part_lba]
    cmp  rax, [rel ext_w_job_lba]
    jne  .bad
    mov  rax, [r12 + ext_ctx.part_sectors]
    cmp  rax, [rel ext_w_job_sectors]
    jne  .bad
    add  rsi, blk_info.sector_size
    lea  rdi, [rel ext_w_job_geometry]
    mov  edx, blk_info_size - blk_info.sector_size
    call memcmp
    test rax, rax
    jnz  .bad
.ok:
    xor  eax, eax
    jmp  .out
.bad:
    mov  dword [rel ext4_disk_last_error], EXT_E_DENIED
    mov  rax, -1
.out:
    pop  rcx
    pop  rdx
    pop  rsi
    pop  rdi
    ret

; ext_raw_read holds its device in RBX and uses R12 as an LBA. Cover both the
; original device and a changed context device, without guarding source I/O.
ext_w_job_guard_read:
    push r12
    mov  r12, [rel ext_w_job_ctx]
    test r12, r12
    jz   .ok
    cmp  rbx, [rel ext_w_job_dev]
    je   .check
    cmp  rbx, [r12 + ext_ctx.dev]
    jne  .ok
.check:
    call ext_w_job_custody
    pop  r12
    ret
.ok:
    xor  eax, eax
    pop  r12
    ret

; Check before AND after every physical write/flush. This includes a refused
; multi-transfer, each single-sector retry and the final successful transfer.
; A change during I/O is uncertain: fail into the existing transaction-dead
; policy, never fall back to or claim durability on the replacement route.
ext_w_job_write:
%if EXT_W_OWNED == 0
    mov  dword [rel ext4_disk_last_error], EXT_E_DENIED
    mov  rax, -1
    ret
%endif
    call ext_w_job_custody
    test rax, rax
    jnz  .out
    call blk_write
    push rax
    call ext_w_job_custody
    test rax, rax
    jnz  .changed
    pop  rax
    ret
.changed:
    add  rsp, 8
.out:
    ret
%if EXT_W_OWNED
ext_w_job_write_owned:
    call ext_w_job_custody
    test rax, rax
    jnz  .out
    call blk_write_owned
    push rax
    call ext_w_job_custody
    test rax, rax
    jnz  .changed
    pop  rax
    ret
.changed:
    add  rsp, 8
.out:
    ret
%endif
ext_w_job_flush:
    call ext_w_job_custody
    test rax, rax
    jnz  .out
    call blk_flush
    push rax
    call ext_w_job_custody
    test rax, rax
    jnz  .changed
    pop  rax
    ret
.changed:
    add  rsp, 8
.out:
    ret


; ext_w_job_step_done() - every STEP's exit: the per-call field is cleared and
;   the request grant the step's writes left is dropped (the window stays).
;   Preserves RAX.
ext_w_job_step_done:
    push rax
    mov  dword [rel ext_w_job_step], 0
    mov  rdi, [rel ext_w_job_tag]
    test rdi, rdi
    jz   .out
    call storage_access_job_step_end
.out:
    pop  rax
    ret

; ext_w_job_mode(R12=ctx) -> RAX = the window's tag when this transaction is a
;   copy STEP's on its own mount under IMPLICIT intent / 0 (the request gate).
ext_w_job_mode:
    cmp  dword [rel ext_w_job_step], 1
    jne  .no
    cmp  [rel ext_w_job_ctx], r12
    jne  .no
    call storage_access_request_intent
    cmp  eax, SA_INTENT_IMPLICIT
    jne  .no
    mov  rax, [rel ext_w_job_tag]
    ret
.no:
    xor  eax, eax
    ret

; ext_w_job_check(R12=ctx, RSI=first block, RDX=blocks) -> RAX 0 / -1: the
;   blocks' absolute range lies inside the transaction's window (recorded as
;   the request grant: the next write records its own).
ext_w_job_check:
    test rdx, rdx
    jz   .corrupt
    mov  rax, rsi
    add  rax, rdx
    jc   .corrupt
    cmp  rax, [r12 + ext_ctx.blocks_count]
    ja   .corrupt
    mov  ecx, [r12 + ext_ctx.spb_shift]
    shl  rsi, cl
    shl  rdx, cl
    add  rsi, [r12 + ext_ctx.part_lba]
    mov  rdi, [r12 + ext_ctx.dev]
    mov  rcx, [r12 + ext_ctx.wks]
    mov  rcx, [rcx + ext_wks.job_tag]
    call storage_access_job_require
    test rax, rax
    jnz  .denied
    ret
.denied:
    mov  dword [rel ext4_disk_last_error], EXT_E_DENIED
    mov  rax, -1
    ret
.corrupt:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
    mov  rax, -1
    ret

; ext_w_job_prepass(R12=ctx) -> RAX 0 / -1. Job transactions only: every block
;   ext_w_write_data and ext_w_commit will write - the new data runs, the
;   superblock, the journal superblock, descriptor + copies + commit, and each
;   copy's home - is presented before the first write; any refusal refuses the
;   transaction with nothing written.
ext_w_job_prepass:
    push rbx
    push r15
    mov  r15, [r12 + ext_ctx.wks]
    xor  eax, eax
    cmp  qword [r15 + ext_wks.job_tag], 0
    je   .out
    xor  ebx, ebx
.run:
    cmp  ebx, [r15 + ext_wks.nr_n]
    jae  .fixed
    mov  eax, ebx
    shl  rax, 4
    lea  rax, [r15 + ext_wks.nr + rax]
    mov  rsi, [rax + 8]                  ; physical block
    movzx edx, word [rax + 4]            ; count
    call ext_w_job_check
    test rax, rax
    jnz  .out
    inc  ebx
    jmp  .run
.fixed:
    mov  rsi, [r12 + ext_ctx.sb_blk]
    mov  edx, 1
    call ext_w_job_check
    test rax, rax
    jnz  .out
    mov  rsi, [r15 + ext_wks.jmap0]
    mov  edx, 1
    call ext_w_job_check
    test rax, rax
    jnz  .out
    xor  ebx, ebx
.journal:
    mov  rsi, [r15 + ext_wks.jmap + rbx * 8]   ; descriptor, copies, commit
    mov  edx, 1
    call ext_w_job_check
    test rax, rax
    jnz  .out
    inc  ebx
    mov  eax, [r15 + ext_wks.txn_n]
    inc  eax
    cmp  ebx, eax
    jbe  .journal
    xor  ebx, ebx
.home:
    cmp  ebx, [r15 + ext_wks.txn_n]
    jae  .done
    mov  rsi, [r15 + ext_wks.txn_blk + rbx * 8]
    mov  edx, 1
    call ext_w_job_check
    test rax, rax
    jnz  .out
    inc  ebx
    jmp  .home
.done:
    xor  eax, eax
.out:
    pop  r15
    pop  rbx
    ret

; ext_w_job_present(R12=ctx, RSI=absolute lba, RDX=sectors) -> RAX 0 / -1. In
;   a job transaction the exact range blk_write will see must lie inside the
;   window (and becomes the device's request grant); otherwise a no-op (the
;   transaction passed ext_w_storage_gate). Preserves RSI, RDX, RCX; clobbers
;   RDI, R8-R11.
ext_w_job_present:
    mov  rax, [r12 + ext_ctx.wks]
    test rax, rax
    jz   .free
    cmp  dword [rax + ext_wks.open], 0
    je   .free
    push rcx
    mov  rcx, [rax + ext_wks.job_tag]
    test rcx, rcx
    jz   .free_pop
    mov  rdi, [r12 + ext_ctx.dev]
    call storage_access_job_require      ; 0 / -1
    pop  rcx
    ret
.free_pop:
    pop  rcx
.free:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; Media writes (partition window only)
; ---------------------------------------------------------------------------
; ext_dev_write(R12=ctx, RSI=absolute lba, RDX=count, RCX=buf) -> 0/-1.
;   Never outside the mounted partition; at most ctx.xfer sectors per call,
;   a refused call falls back to single sectors with a bounded retry.
ext_dev_write:
    push rbx
    push r13
    push r14
    push r15
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    test r14, r14
    jz   .fail
    cmp  r13, [r12 + ext_ctx.part_lba]
    jb   .fail
    mov  rax, r13
    add  rax, r14
    jc   .fail
    mov  rdx, [r12 + ext_ctx.part_lba]
    add  rdx, [r12 + ext_ctx.part_sectors]
    cmp  rax, rdx
    ja   .fail
.chunk:
    test r14, r14
    jz   .ok
    mov  ebx, [r12 + ext_ctx.xfer]
    cmp  rbx, r14
    jbe  .sized
    mov  rbx, r14
.sized:
    mov  rsi, r13
    mov  rdx, rbx
    call ext_w_job_present               ; a job transaction: exactly this range, else nothing
    test rax, rax
    jnz  .denied
%if EXT_W_OWNED
    call ext_w_owned_handle              ; an owned transaction writes only through its owned op
    test r8, r8
    jz   .generic
    mov  rdi, [r12 + ext_ctx.dev]
    mov  rsi, r13
    mov  rdx, rbx
    mov  rcx, r15
    call ext_w_job_write_owned
    test rax, rax
    jz   .advance
    cmp  eax, BLK_ERR_WRITE_GATE          ; blockdev returns BLK_ERR_* in EAX (zero-extended)
    je   .denied                         ; owned: a refusal is final (no fallback, no retry)
    jmp  .one                            ; an I/O error: single sectors, as below
.generic:
%endif
    mov  rdi, [r12 + ext_ctx.dev]
    mov  rsi, r13
    mov  rdx, rbx
    mov  rcx, r15
    call ext_w_job_write
    test rax, rax
    jz   .advance
    ; single sectors, each retried a bounded number of times (same bytes)
.one:
    test rbx, rbx
    jz   .chunk
    mov  rsi, r13
    mov  edx, 1
    call ext_w_job_present
    test rax, rax
    jnz  .denied
    push rbx
    mov  ebx, 4
.again:
%if EXT_W_OWNED
    call ext_w_owned_handle
    test r8, r8
    jz   .again_generic
    mov  rdi, [r12 + ext_ctx.dev]
    mov  rsi, r13
    mov  edx, 1
    mov  rcx, r15
    call ext_w_job_write_owned
    test rax, rax
    jz   .sector_ok
    cmp  eax, BLK_ERR_WRITE_GATE
    je   .owned_refused                  ; owned: final
    dec  ebx
    jnz  .again                          ; an I/O error: the same bounded retry
    pop  rbx
    jmp  .fail
.owned_refused:
    pop  rbx
    jmp  .denied
.again_generic:
%endif
    mov  rdi, [r12 + ext_ctx.dev]
    mov  rsi, r13
    mov  edx, 1
    mov  rcx, r15
    call ext_w_job_write
    test rax, rax
    jz   .sector_ok
    dec  ebx
    jnz  .again
    pop  rbx
    jmp  .fail
.sector_ok:
    pop  rbx
    inc  r13
    add  r15, 512
    dec  r14
    dec  rbx
    jmp  .one
.advance:
    add  r13, rbx
    mov  rax, rbx
    shl  rax, 9
    add  r15, rax
    sub  r14, rbx
    jmp  .chunk
.ok:
    xor  eax, eax
    jmp  .out
.denied:
    mov  dword [rel ext4_disk_last_error], EXT_E_DENIED
    mov  rax, -1
    jmp  .out
.fail:
    mov  dword [rel ext4_disk_last_error], EXT_E_IO
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

; ext_write_block(R12=ctx, RSI=block, RCX=buf) -> 0/-1
ext_write_block:
    cmp  rsi, [r12 + ext_ctx.blocks_count]
    jae  .fail
    push rcx
    mov  ecx, [r12 + ext_ctx.spb_shift]
    shl  rsi, cl
    mov  edx, 1
    shl  edx, cl
    pop  rcx
    add  rsi, [r12 + ext_ctx.part_lba]
    jmp  ext_dev_write
.fail:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
    mov  rax, -1
    ret

; ext_w_flush(R12=ctx) -> 0/-1
ext_w_flush:
    mov  rdi, [r12 + ext_ctx.dev]
    call ext_w_job_flush
    test rax, rax
    jz   .ok
    mov  dword [rel ext4_disk_last_error], EXT_E_IO
    mov  rax, -1
.ok:
    ret

; ext_w_write_data(R12=ctx) -> 0/-1: every new run gets its composed content
;   (old bytes below the old size, the caller's bytes, zeros past the new size).
ext_w_write_data:
    push rbx
    push rbp
    push r13
    push r14
    push r15
    mov  r15, [r12 + ext_ctx.wks]
    xor  ebp, ebp                        ; run index
.run:
    cmp  ebp, [r15 + ext_wks.nr_n]
    jae  .ok
    mov  eax, ebp
    shl  rax, 4
    lea  rax, [r15 + ext_wks.nr + rax]
    mov  r13d, [rax]                     ; logical block
    movzx r14d, word [rax + 4]           ; count
    mov  rbx, [rax + 8]                  ; physical block
.block:
    test r14d, r14d
    jz   .next_run
    mov  rdi, r13
    call ext_w_compose                   ; -> RCX = source buffer
    test rax, rax
    jnz  .fail
    mov  rsi, rbx
    call ext_write_block
    test rax, rax
    jnz  .fail
    inc  r13
    inc  rbx
    dec  r14d
    jmp  .block
.next_run:
    inc  ebp
    jmp  .run
.ok:
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbp
    pop  rbx
    ret

; ext_w_compose(R12=ctx, RDI=logical block) -> RAX 0/-1, RCX = the block's new
;   content (the caller's buffer when it covers the block, else wks.bounce).
ext_w_compose:
    push rbx
    push r13
    push r14
    push r15
    mov  r15, [r12 + ext_ctx.wks]
    mov  ecx, [r12 + ext_ctx.block_shift]
    mov  rbx, rdi
    shl  rbx, cl                         ; block's first byte
    mov  r13d, [r12 + ext_ctx.block_bytes]
    lea  r14, [rbx + r13]                ; one past its last byte
    ; fully covered by caller data (and inside the new size)?
    mov  rax, [r15 + ext_wks.w_off]
    cmp  rbx, rax
    jb   .bounce
    add  rax, [r15 + ext_wks.w_len]
    cmp  r14, rax
    ja   .bounce
    cmp  r14, [r15 + ext_wks.new_size]
    ja   .bounce
    mov  rcx, rbx
    sub  rcx, [r15 + ext_wks.w_off]
    add  rcx, [r15 + ext_wks.w_buf]
    xor  eax, eax
    jmp  .out
.bounce:
    lea  rdi, [r15 + ext_wks.bounce]
    xor  esi, esi
    mov  edx, r13d
    call memset
    cmp  rbx, [r15 + ext_wks.content_size]
    jae  .overlay
    ; old content of this logical block, through the committed mapping
    mov  rsi, rbx
    mov  ecx, [r12 + ext_ctx.block_shift]
    shr  rsi, cl
    lea  rdi, [r12 + ext_ctx.inode]
    call ext_map
    test rax, rax
    js   .fail
    jz   .old_zero
    mov  rsi, rax
    mov  edx, 1
    lea  rcx, [r15 + ext_wks.bounce]
    call ext_read_blocks
    test rax, rax
    jnz  .fail
.old_zero:
    ; bytes at or past the old size are zeros
    mov  rax, [r15 + ext_wks.content_size]
    cmp  rax, r14
    jae  .overlay
    sub  rax, rbx
    lea  rdi, [r15 + ext_wks.bounce + rax]
    mov  edx, r13d
    sub  edx, eax
    xor  esi, esi
    call memset
.overlay:
    mov  rax, [r15 + ext_wks.w_len]
    test rax, rax
    jz   .tail
    mov  rsi, [r15 + ext_wks.w_off]
    cmp  rsi, rbx
    jae  .lo
    mov  rsi, rbx
.lo:
    mov  rdx, [r15 + ext_wks.w_off]
    add  rdx, rax
    cmp  rdx, r14
    jbe  .hi
    mov  rdx, r14
.hi:
    cmp  rsi, rdx
    jae  .tail
    sub  rdx, rsi                        ; length
    lea  rdi, [r15 + ext_wks.bounce]
    add  rdi, rsi
    sub  rdi, rbx
    sub  rsi, [r15 + ext_wks.w_off]
    add  rsi, [r15 + ext_wks.w_buf]
    call memcpy
.tail:
    mov  rax, [r15 + ext_wks.new_size]
    cmp  rax, r14
    jae  .done
    cmp  rax, rbx
    jae  .partial
    mov  rax, rbx
.partial:
    sub  rax, rbx
    lea  rdi, [r15 + ext_wks.bounce + rax]
    mov  edx, r13d
    sub  edx, eax
    xor  esi, esi
    call memset
.done:
    lea  rcx, [r15 + ext_wks.bounce]
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; jbd2 commit
; ---------------------------------------------------------------------------
; ext_w_jwrite(R12=ctx, EDX=journal-relative index, RCX=buf) -> 0/-1
ext_w_jwrite:
    mov  rax, [r12 + ext_ctx.wks]
    mov  rsi, [rax + ext_wks.jmap + rdx * 8]
    jmp  ext_write_block

; ext_w_be32(RDI=dest, ESI=value) — store big-endian
ext_w_be32:
    bswap esi
    mov  [rdi], esi
    ret

; ext_w_jsb_set(R12=ctx, EDI=s_start, ESI=s_sequence) -> RCX = wks.jsb updated
;   (checksummed when CSUM_V3)
ext_w_jsb_set:
    push rbx
    push r15
    mov  r15, [r12 + ext_ctx.wks]
    lea  rbx, [r15 + ext_wks.jsb]
    bswap edi
    mov  [rbx + JSB_START], edi
    bswap esi
    mov  [rbx + JSB_SEQUENCE], esi
    cmp  dword [r12 + ext_ctx.j_csum3], 1
    jne  .out
    mov  rdi, rbx
    call ext_w_jsb_csum
    mov  [rbx + JSB_CHECKSUM], eax
.out:
    mov  rcx, rbx
    pop  r15
    pop  rbx
    ret

; ext_w_commit(R12=ctx) -> 0/-1. Steps 2..5 of the module header.
ext_w_commit:
    push rbx
    push rbp
    push r13
    push r14
    push r15
    mov  r15, [r12 + ext_ctx.wks]
    mov  r13d, [r12 + ext_ctx.j_seq]     ; T
    ; ---- step 2: the on-disk superblock gains RECOVER (durable before any
    ;      journal content can be: "journal has data, flag clear" never exists) ----
    mov  rsi, [r12 + ext_ctx.sb_blk]
    mov  edx, 1
    lea  rcx, [r15 + ext_wks.sbo]
    call ext_read_blocks
    test rax, rax
    jnz  .dead
    mov  eax, [r12 + ext_ctx.sb_off]
    lea  rdi, [r15 + ext_wks.sbo + rax]
    or   dword [rdi + ESB_INCOMPAT], EXT_IN_RECOVER
    call ext_w_sb_seal
    mov  rsi, [r12 + ext_ctx.sb_blk]
    lea  rcx, [r15 + ext_wks.sbo]
    call ext_write_block
    test rax, rax
    jnz  .dead
    call ext_w_flush
    test rax, rax
    jnz  .dead
    ; ---- step 3: journal points at T, descriptor + copies, flush, commit, flush ----
    mov  edi, [r12 + ext_ctx.j_first]
    mov  esi, r13d
    call ext_w_jsb_set
    mov  rsi, [r15 + ext_wks.jmap0]
    call ext_write_block
    test rax, rax
    jnz  .dead
    lea  rdi, [r15 + ext_wks.desc]
    xor  esi, esi
    mov  edx, [r12 + ext_ctx.block_bytes]
    call memset
    lea  rdi, [r15 + ext_wks.desc]
    mov  esi, JBD2_MAGIC
    call ext_w_be32
    lea  rdi, [r15 + ext_wks.desc + 4]
    mov  esi, JBD2_DESCRIPTOR
    call ext_w_be32
    lea  rdi, [r15 + ext_wks.desc + 8]
    mov  esi, r13d
    call ext_w_be32
    lea  rbp, [r15 + ext_wks.desc + 12]  ; next tag
    xor  ebx, ebx
.copy:
    cmp  ebx, [r15 + ext_wks.txn_n]
    jae  .copies_done
    mov  eax, ebx
    shl  rax, 12
    lea  r14, [r15 + ext_wks.bufs + rax] ; the block as it will be checkpointed
    xor  r8d, r8d                        ; tag flags
    cmp  dword [r14], JBD2_MAGIC_LE
    jne  .plain
    lea  rdi, [r15 + ext_wks.bounce]
    mov  rsi, r14
    mov  edx, [r12 + ext_ctx.block_bytes]
    call memcpy
    lea  r14, [r15 + ext_wks.bounce]
    mov  dword [r14], 0                  ; escaped; replay restores the magic
    mov  r8d, JBD2_FLAG_ESCAPE
.plain:
    test ebx, ebx
    jz   .first
    or   r8d, JBD2_FLAG_SAME_UUID
.first:
    lea  eax, [ebx + 1]
    cmp  eax, [r15 + ext_wks.txn_n]
    jne  .not_last
    or   r8d, JBD2_FLAG_LAST_TAG
.not_last:
    mov  rdi, rbp
    mov  rsi, [r15 + ext_wks.txn_blk + rbx * 8]
    mov  edx, r8d
    mov  rcx, r14
    call ext_w_put_tag
    add  rbp, rax
    test ebx, ebx
    jnz  .tagged
    lea  rsi, [r15 + ext_wks.jsb + JSB_UUID]
    mov  rdi, rbp
    mov  edx, 16
    call memcpy
    add  rbp, 16
.tagged:
    lea  edx, [ebx + 1]
    mov  rcx, r14
    call ext_w_jwrite
    test rax, rax
    jnz  .dead
    inc  ebx
    jmp  .copy
.copies_done:
    cmp  dword [r12 + ext_ctx.j_csum3], 1
    jne  .desc_write
    lea  rdi, [r15 + ext_wks.desc]
    mov  esi, [r12 + ext_ctx.block_bytes]
    mov  edx, [r12 + ext_ctx.j_seed]
    call ext_crc32c
    bswap eax
    mov  ecx, [r12 + ext_ctx.block_bytes]
    mov  [r15 + ext_wks.desc + rcx - 4], eax
.desc_write:
    xor  edx, edx
    lea  rcx, [r15 + ext_wks.desc]
    call ext_w_jwrite
    test rax, rax
    jnz  .dead
    call ext_w_flush
    test rax, rax
    jnz  .dead
    lea  rdi, [r15 + ext_wks.commit]
    xor  esi, esi
    mov  edx, [r12 + ext_ctx.block_bytes]
    call memset
    lea  rdi, [r15 + ext_wks.commit]
    mov  esi, JBD2_MAGIC
    call ext_w_be32
    lea  rdi, [r15 + ext_wks.commit + 4]
    mov  esi, JBD2_COMMIT
    call ext_w_be32
    lea  rdi, [r15 + ext_wks.commit + 8]
    mov  esi, r13d
    call ext_w_be32
    cmp  dword [r12 + ext_ctx.j_csum3], 1
    jne  .commit_write
    lea  rdi, [r15 + ext_wks.commit]
    mov  esi, [r12 + ext_ctx.block_bytes]
    mov  edx, [r12 + ext_ctx.j_seed]
    call ext_crc32c
    bswap eax
    mov  [r15 + ext_wks.commit + 0x10], eax
.commit_write:
    mov  edx, [r15 + ext_wks.txn_n]
    inc  edx
    lea  rcx, [r15 + ext_wks.commit]
    call ext_w_jwrite
    test rax, rax
    jnz  .dead
    call ext_w_flush
    test rax, rax
    jnz  .dead
    ; ---- step 4: checkpoint ----
    xor  ebx, ebx
.home:
    cmp  ebx, [r15 + ext_wks.txn_n]
    jae  .homed
    mov  rsi, [r15 + ext_wks.txn_blk + rbx * 8]
    mov  eax, ebx
    shl  rax, 12
    lea  rcx, [r15 + ext_wks.bufs + rax]
    call ext_write_block
    test rax, rax
    jnz  .dead
    inc  ebx
    jmp  .home
.homed:
    call ext_w_flush
    test rax, rax
    jnz  .dead
    ; ---- step 5: empty journal (T+1), then clear RECOVER ----
    xor  edi, edi
    lea  esi, [r13d + 1]
    call ext_w_jsb_set
    mov  rsi, [r15 + ext_wks.jmap0]
    call ext_write_block
    test rax, rax
    jnz  .dead
    call ext_w_flush
    test rax, rax
    jnz  .dead
    lea  eax, [r13d + 1]
    mov  [r12 + ext_ctx.j_seq], eax
    call ext_w_sb_ptr
    test rax, rax
    jz   .dead
    and  dword [rax + ESB_INCOMPAT], ~EXT_IN_RECOVER
    mov  rdi, rax
    call ext_w_sb_seal
    mov  rsi, [r12 + ext_ctx.sb_blk]
    xor  edx, edx
    call ext_txn_slot
    mov  rcx, rax
    mov  rsi, [r12 + ext_ctx.sb_blk]
    call ext_write_block
    test rax, rax
    jnz  .dead
    call ext_w_flush
    test rax, rax
    jnz  .dead
    xor  eax, eax
    jmp  .out
.dead:
    ; The volume may now hold RECOVER and a committed or partial transaction:
    ; jbd2 recovery (Linux / e2fsck) owns it. No further writes this mount.
    mov  dword [r12 + ext_ctx.wdead], 1
    mov  dword [rel ext4_disk_last_error], EXT_E_IO
    lea  rdi, [rel str_ew_dead]
    call serial_string
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbp
    pop  rbx
    ret

; ext_w_put_tag(R12=ctx, RDI=dest, RSI=home block, EDX=flags, RCX=block as
;   written to the journal) -> RAX = tag size. CSUM_V3 tags carry
;   crc32c(seed, be32 T, block).
ext_w_put_tag:
    push rbx
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  r13, rsi
    mov  r14d, edx
    mov  r15, rcx
    mov  esi, r13d
    call ext_w_be32                      ; t_blocknr
    cmp  dword [r12 + ext_ctx.j_csum3], 1
    je   .v3
    lea  rdi, [rbx + 6]                  ; t_checksum (be16, 0), t_flags (be16)
    mov  eax, r14d
    xchg al, ah
    mov  [rdi], ax
    mov  eax, 8
    cmp  dword [r12 + ext_ctx.j_tagbytes], 12
    jne  .out
    lea  rdi, [rbx + 8]
    mov  rsi, r13
    shr  rsi, 32
    call ext_w_be32                      ; t_blocknr_high
    mov  eax, 12
    jmp  .out
.v3:
    lea  rdi, [rbx + 4]
    mov  esi, r14d
    call ext_w_be32                      ; t_flags
    lea  rdi, [rbx + 8]
    mov  rsi, r13
    shr  rsi, 32
    call ext_w_be32                      ; t_blocknr_high
    mov  edi, [r12 + ext_ctx.j_seq]
    bswap edi
    mov  esi, [r12 + ext_ctx.j_seed]
    call ext_crc_u32
    mov  rdi, r15
    mov  esi, [r12 + ext_ctx.block_bytes]
    mov  edx, eax
    call ext_crc32c
    lea  rdi, [rbx + 12]
    mov  esi, eax
    call ext_w_be32                      ; t_checksum
    mov  eax, 16
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

str_ew_caller:  db "ext4_write", 0
str_ew_job_caller: db "ext4_copy", 0
str_ew_job_carried: db "ext4_copy_carried", 0   ; RCQ-20 S5c: the gate marker names a carried BEGIN
str_ew_armed:   db "[PAOS64] [fs.ext4.write.armed] ", 0
str_ew_dead:    db "[PAOS64] [fs.ext4.write.dead] commit incomplete; jbd2 recovery owns the volume", 13, 10, 0
str_ew_crlf:    db 13, 10, 0

%macro WDATA_fs_ext4_write 0
ext_w_job_tag:  resq 1                  ; the copy job's storage window (storage_access tag) / 0 none
ext_w_job_ctx:  resq 1                  ;   its mount
ext_w_job_dev:  resq 1                  ;   its device
ext_w_job_gen:  resq 1                  ;   the medium's generation when it was granted
ext_w_job_step: resd 1                  ; 1 only while ext4_copy runs one STEP (the per-call field)
ext_w_dry_run:  resd 1                  ; 1 only inside ext_w_shrink_probe: ext_w_end writes nothing
%endmacro
WDATA_BSS_DEFER WDATA_fs_ext4_write
; RCQ-20 S5c: its own block (WDATA_fs_ext4_write's layout is pinned by the zero-storage move)
%macro WDATA_BSS_fs_ext4_write_s5c 0
alignb 8
ext_w_carry_seq:   resq 1               ; the last carry id issued (never reissued)
ext_w_carry_spent: resq 1               ; the last carry id a BEGIN spent: none at or below it begins
%endmacro
WDATA_BSS_DEFER WDATA_BSS_fs_ext4_write_s5c

; Separate additive block: preserve the established writer BSS layout.
%macro WDATA_fs_ext4_destination_custody 0
alignb 8
ext_w_job_ops:      resq 1
ext_w_job_priv:     resq 1
ext_w_job_info:     resq 1
ext_w_job_lba:      resq 1
ext_w_job_sectors:  resq 1
ext_w_job_geometry: resb blk_info_size - blk_info.sector_size
%endmacro
WDATA_BSS_DEFER WDATA_fs_ext4_destination_custody
