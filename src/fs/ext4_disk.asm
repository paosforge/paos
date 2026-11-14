;; MODULE fs/ext4_disk
;; LAYER 4
;; EXPORTS ext4_disk_select_removable_gpt_ro, ext4_disk_select_removable_mbr_ro, ext4_disk_source_device, ext4_disk_remount, ext4_disk_register, ext4_disk_handle, ext4_disk_last_error, ext4_disk_mount_count, ext4_disk_format_ops
;; IMPORTS fs/fs_identify, fs/ext4_refusal, fs/blockdev, fs/vfs, fs/ext4_copy, fs/ext4_write, fs/storage_access, core/lib/mem, core/heap, boot/serial
;; CAPS CAP_BLOCK_READ
;; OWNER saga:rcq20_filesystems
;; CONTEXT: bsp_only  (RCQ-21 SA2b: ext_ctx carries the owned-mode binding the writer presents)
; ============================================================================
; fs/ext4_disk.asm — native READ-ONLY ext2/ext3/ext4 backend on the VFS fs_ops
; seam (RCQ-20 slice E1, RC spec §7.5). Media only through the blk device
; handle in each mount's private context (ESSENCE E1/E5): no controller symbol,
; no module-global "current mount".
;
; DISCOVERY: every healthy registered block device with 512-byte logical
;   sectors; a superfloppy volume, MBR primaries (extended containers skipped)
;   and GPT entries are probed for the ext superblock magic 0xEF53 at partition
;   byte 1024. Up to EXT_MAX_MOUNTS volumes mount as "ext0", "ext1".
;
; FAIL-CLOSED MOUNT (marker [fs.ext4.refused] reason=... and no mount):
;   * s_state must be cleanly unmounted (VALID set, ERROR clear); rev 0 refused;
;   * incompat RECOVER (journal needs replay) refused; incompat must contain
;     FILETYPE and nothing outside {FILETYPE, EXTENTS, 64BIT, FLEX_BG, EA_INODE,
;     CSUM_SEED, LARGEDIR}: COMPRESSION, JOURNAL_DEV, META_BG, MMP, DIRDATA,
;     INLINE_DATA, ENCRYPT, CASEFOLD and unknown bits are refused;
;   * ro_compat outside the known read-safe set (BIGALLOC, SNAPSHOT, REPLICA,
;     BTREE_DIR, unknown) refused;
;   * metadata_csum volumes must carry a matching crc32c superblock checksum;
;   * geometry: 1/2/4 KiB blocks, exact s_first_data_block, the filesystem fits
;     the partition, group/descriptor/inode-table arithmetic bounded and in-fs,
;     and the root inode reads back as a directory.
;   Compat features are ignorable by definition for a reader.
;
; READ SEMANTICS: extent trees (magic, depth <= 5 and strictly decreasing,
;   entries <= max <= capacity, strictly ordered and non-overlapping, every
;   physical block inside the filesystem); ext2/ext3 direct/single/double/
;   triple indirect maps; holes and uninitialized extents read as zeros.
;   Directories are walked linearly (htree directories are linearly
;   compatible); every dirent is bounds-checked (rec_len >= 8, 4-aligned,
;   inside the block, name_len + 8 <= rec_len, inode <= s_inodes_count).
;   Paths are "/a/b/c" byte-exact (ext names are case-sensitive bytes); "." and
;   ".." components are refused and NO symlink is ever followed: a symlink,
;   device, FIFO or socket is listed with EXT_DIRENT_OTHER and stat reserved=2,
;   and reading it is refused. Inodes flagged compressed, encrypted or inline
;   are refused. metadata_csum volumes verify the superblock, every group
;   descriptor read, every inode, every extent-tree block and every directory
;   block admitted by the walker. Leaves require the exact 0xDE checksum tail;
;   indexed roots/interior nodes use their bounded dx_tail checksum layout.
;   Bitmaps are never read here.
;
; WRITE: this module never calls blk_write/flush. Content writes live in
;   fs/ext4_write.asm (RCQ-20 E2a) and need an explicit per-volume arm; an
;   unarmed mount stats FS_STAT_READONLY and every mutation returns -1.
; ============================================================================

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place

EXT_MAX_MOUNTS       equ 2
EXT_BUF_BYTES        equ 4096                 ; largest supported block
EXT_INODE_COPY       equ 256                  ; bytes of an inode kept per slot
EXT_SLOT             equ 264                  ; slot = inode copy + inode number + checksum seed
EXT_SLOT_INO         equ 256
EXT_SLOT_SEED        equ 260
EXT_PATH_MAX         equ 1024
EXT_NAME_MAX         equ 255
EXT_DIR_MAX_BYTES    equ 0x10000000           ; 256 MiB directory bound
EXT_DEPTH_MAX        equ 5
EXT_XFER_MAX         equ 8                    ; sectors per blk_read (the proven AHCI op)
EXT_DIRECT_BLOCKS    equ 64                   ; whole blocks read straight into a caller buffer
EXT_LIST_POOL_ENTRIES equ 66                  ; Explorer's 64 rows + "." + ".." (as fat32_disk)
EXT_LIST_NAMES_CAP   equ EXT_LIST_POOL_ENTRIES * (EXT_NAME_MAX + 1)
EXT_ROOT_INO         equ 2
EXT_GPT_MAX          equ 128
EXT_DIRENT_OTHER     equ 8                    ; fs_dirent.flags: not a file or directory; never opened

; ---- superblock (byte offsets inside the 1024-byte superblock) ----
ESB_INODES_COUNT     equ 0x00
ESB_BLOCKS_LO        equ 0x04
ESB_FIRST_DATA       equ 0x14
ESB_LOG_BLOCK        equ 0x18
ESB_BLOCKS_PER_G     equ 0x20
ESB_INODES_PER_G     equ 0x28
ESB_MAGIC            equ 0x38
ESB_STATE            equ 0x3A
ESB_REV              equ 0x4C
ESB_INODE_SIZE       equ 0x58
ESB_COMPAT           equ 0x5C
ESB_INCOMPAT         equ 0x60
ESB_RO_COMPAT        equ 0x64
ESB_UUID             equ 0x68
ESB_DESC_SIZE        equ 0xFE
ESB_BLOCKS_HI        equ 0x150
ESB_CSUM_TYPE        equ 0x175
ESB_CSUM             equ 0x3FC
ESB_CSUM_SEED        equ 0x270

EXT_MAGIC            equ 0xEF53
EXT_STATE_VALID      equ 1
EXT_STATE_ERROR      equ 2

EXT_COMPAT_JOURNAL   equ 0x4
EXT_IN_FILETYPE      equ 0x2
EXT_IN_RECOVER       equ 0x4
EXT_IN_EXTENTS       equ 0x40
EXT_IN_64BIT         equ 0x80
EXT_IN_FLEX_BG       equ 0x200
EXT_IN_CSUM_SEED     equ 0x2000
EXT_IN_ALLOWED       equ 0x2 | 0x40 | 0x80 | 0x200 | 0x400 | 0x2000 | 0x4000
EXT_RO_GDT_CSUM      equ 0x10
EXT_RO_METADATA_CSUM equ 0x400
EXT_RO_ALLOWED       equ 0x1 | 0x2 | 0x8 | 0x10 | 0x20 | 0x40 | 0x100 | 0x400 | 0x1000 | 0x2000 | 0x4000 | 0x8000 | 0x10000

; ---- inode ----
EI_MODE              equ 0x00
EI_SIZE_LO           equ 0x04
EI_LINKS             equ 0x1A
EI_FLAGS             equ 0x20
EI_BLOCK             equ 0x28
EI_SIZE_HI           equ 0x6C
EI_BLOCKS_LO         equ 0x1C
EI_GENERATION        equ 0x64
EI_BLOCKS_HI         equ 0x74
EI_CSUM_LO           equ 0x7C
EI_EXTRA_ISIZE       equ 0x80
EI_CSUM_HI           equ 0x82
EXT_FL_REFUSED       equ 0x4 | 0x200 | 0x800 | 0x10000000   ; compressed, compressed-blocks, encrypted, inline data
EXT_FL_EXTENTS       equ 0x80000
EXT_S_IFMT           equ 0xF000
EXT_S_IFREG          equ 0x8000
EXT_S_IFDIR          equ 0x4000

; ---- group descriptor ----
EGD_ITABLE_LO        equ 0x08
EGD_FLAGS            equ 0x12
EGD_ITABLE_HI        equ 0x28
EGD_CHECKSUM         equ 0x1E
EGD_INODE_UNINIT     equ 1
EXT_GD_FREE_LO       equ 0x0C                 ; free blocks (smart copy D: fs_info.free_clusters)
EXT_GD_FREE_HI       equ 0x2C

; ---- extent tree ----
EXT_EH_MAGIC         equ 0xF30A
EXT_UNINIT_LEN       equ 32768

; ---- mount refusal reasons (16-byte names in ext_reason_names) ----
EXT_R_SECTOR         equ 1                    ; reserved: non-512 devices are now skipped silently
EXT_R_REV            equ 2
EXT_R_STATE          equ 3
EXT_R_INCOMPAT       equ 4
EXT_R_RECOVER        equ 5
EXT_R_ROCOMPAT       equ 6
EXT_R_GEOMETRY       equ 7
EXT_R_CSUM           equ 8
EXT_R_ROOT           equ 9
EXT_R_NOMEM          equ 10
EXT_R_IO             equ 11
EXT_R_FILETYPE       equ 12
EXT_R_NOMOUNT        equ 13

; ---- per-operation errors (ext4_disk_last_error) ----
EXT_E_NONE           equ 0
EXT_E_NOTFOUND       equ 1
EXT_E_CORRUPT        equ 2
EXT_E_IO             equ 3
EXT_E_UNSUPPORTED    equ 4
EXT_E_RANGE          equ 5
EXT_E_NOTDIR         equ 6
EXT_E_BADPATH        equ 7
EXT_E_ISDIR          equ 8
EXT_E_NOTARMED       equ 9                    ; ext4_write: no explicit per-volume arm
EXT_E_WGATE          equ 10                   ; ext4_write: volume/journal outside the write gate
EXT_E_NOSPACE        equ 11
EXT_E_TOOBIG         equ 12                   ; exceeds one bounded transaction
EXT_E_DENIED         equ 13                   ; storage_access refused this request
EXT_E_DEAD           equ 14                   ; uncertain commit: independent return/recovery required
EXT_E_BUSY           equ 15                   ; live/queued copy or open writer

EXT_WALK_LOOKUP      equ 0
EXT_WALK_LIST        equ 1

; One mount's private context; three EXT_BUF_BYTES buffers follow it in the
; same allocation. Tags cache the block currently held by meta/ibuf.
struc ext_ctx
  .dev:            resq 1
  .part_lba:       resq 1
  .part_sectors:   resq 1
  .blocks_count:   resq 1
  .first_data:     resq 1
  .gdt_block:      resq 1
  .it_blocks:      resq 1                ; inode-table blocks per group
  .meta_buf:       resq 1                ; extent/indirect/descriptor blocks
  .meta_tag:       resq 1
  .ibuf:           resq 1                ; inode-table blocks
  .ibuf_tag:       resq 1
  .dir_buf:        resq 1                ; directory blocks and the data bounce
  .map_bound:      resq 1                ; ext_map: first logical block past the chosen subtree
  .name:           resq 1                ; -> "ext0"/"ext1"
  .scheme:         resd 1
  .block_bytes:    resd 1
  .block_shift:    resd 1
  .spb_shift:      resd 1                ; log2(sectors per block)
  .inodes_count:   resd 1
  .inodes_per_g:   resd 1
  .blocks_per_g:   resd 1
  .group_count:    resd 1
  .inode_size:     resd 1
  .desc_size:      resd 1
  .compat:         resd 1
  .incompat:       resd 1
  .ro_compat:      resd 1
  .volume_id:      resd 1
  .xfer:           resd 1
  .kind:           resd 1                ; 2/3/4
  .mounted:        resd 1
  .handle:         resd 1
  .found_ino:      resd 1
  .found_ftype:    resd 1
  .csum_seed:      resd 1                ; metadata_csum seed (s_checksum_seed or crc32c(uuid))
  .map_seed:       resd 1                ; ext_map: the mapped inode's checksum seed
  .sb_off:         resd 1                ; superblock byte offset inside .sb_blk
  .armed:          resd 1                ; ext4_write: explicit per-volume write arm
  .wdead:          resd 1                ; ext4_write: a commit could not be completed
  .j_first:        resd 1
  .j_maxlen:       resd 1
  .j_seq:          resd 1
  .j_tagbytes:     resd 1
  .j_csum3:        resd 1
  .j_seed:         resd 1
  .pad:            resd 1
  .sb_blk:         resq 1                ; block holding the primary superblock
  .wks:            resq 1                ; ext4_write workspace (kmalloc at arm)
  .owned_token:    resq 1                ; ext4_write: an owned arm's volume binding / 0 (every arm clears it first)
  .arm_uuid:       resb 16
  .dino:           resb EXT_SLOT         ; directory being walked
  .inode:          resb EXT_SLOT         ; resolved leaf / listed child
  .jino:           resb EXT_SLOT         ; journal inode (ext4_write)
  .read_generation: resq 1               ; medium observed before probing the mounted superblock
  .read_uuid:      resb 16               ; immutable mounted identity for cross-volume readers
  .remount_epoch:  resq 1               ; successful fresh context rebuilds, never an authority token
endstruc

EXT_CTX_ALLOC equ ext_ctx_size + 3 * EXT_BUF_BYTES

; ---------------------------------------------------------------------------
; ext4_disk_register() -> RAX = handle of the first ext mount / -1.
;   Probes every registered block device, mounts up to EXT_MAX_MOUNTS clean,
;   supported ext2/3/4 volumes read-only and registers each as a VFS mount.
;   Emits [fs.ext4.mounted] per mount, [fs.ext4.refused] per rejected volume,
;   [fs.ext4.skipped] when nothing mounted. Never writes.
; ---------------------------------------------------------------------------
ext4_disk_register:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  dword [rel ext4_disk_handle], -1
    mov  dword [rel ext4_disk_mount_count], 0
    call ext4_refusal_reset
    call ext_build_ops
    xor  r13d, r13d                      ; previous dev*
.dev:
    cmp  dword [rel ext4_disk_mount_count], EXT_MAX_MOUNTS
    jae  .done
    mov  rdi, r13
    xor  esi, esi                        ; every healthy device: pre-2912 backends declare no caps
    xor  edx, edx
    call blk_iter_after
    test rax, rax
    jz   .done
    mov  r13, rax
    mov  rdi, rax
    call ext_scan_device
    jmp  .dev
.done:
    cmp  dword [rel ext4_disk_mount_count], 0
    jne  .some
    lea  rdi, [rel str_ext_skipped]
    call serial_string
    mov  rax, -1
    jmp  .out
.some:
    movsxd rax, dword [rel ext4_disk_handle]
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ext4_disk_select_removable_mbr_ro(RDI=opaque row dev*) -> handle / -1,
; -2 busy. BSP only, non-reentrant, after boot registration. The Explorer caller
; owns its local owner/focus/frame gates. This helper only reads: no request
; authority, arm, recovery, write or flush. Append one uniquely identified 0x83
; MBR primary without resetting any existing ext2/3/4 context. GPT has its own entry.
; Separate GPT entry, retaining original eligibility and full native validator.
ext4_disk_select_removable_gpt_ro:
    mov byte [rel ext_sel_gpt],1
    jmp ext_sel_begin
ext4_disk_select_removable_mbr_ro:
    mov byte [rel ext_sel_gpt],0
ext_sel_begin:
    push rbx
    push r12
    push r13
    mov rbx,rdi
    mov al,[rel hv_linux_running]
    or al,[rel hv_linux_start_active]
    or al,[rel hv_linux_run_req]
    or al,[rel vtd_owner_guest]
    test al,al
    jnz .busy
    call vfs_copy_busy
    test eax,eax
    jnz .busy
    call storage_access_binding_busy
    test eax,eax
    jnz .busy
    cmp dword [rel ext4_disk_mount_count],EXT_MAX_MOUNTS
    jae .no
    ; Resolve the opaque row before dereferencing it, even on refusal.
    mov rdi,rbx
    call ext_sel_member
    test rax,rax
    jz .no
    mov rdi,rbx
    call ext_sel_context
    test rax,rax
    jnz .no
    mov rdi,rbx
    call guest_volume_native_allowed
    test rax,rax
    jnz .no
    mov rax,[rbx+dev.info]
    mov [rel ext_sel_identity],rax
    mov rdx,[rbx+dev.ops]
    mov [rel ext_sel_identity+8],rdx
    mov rdx,[rbx+dev.priv]
    mov [rel ext_sel_identity+16],rdx
    mov rdx,[rax+blk_info.media_generation]
    test rdx,rdx
    jz .no
    mov [rel ext_sel_identity+24],rdx
    mov rdx,[rax+blk_info.lba_max]
    mov [rel ext_sel_identity+32],rdx
    mov [rel ext_sel_device],rbx
    mov byte [rel ext_sel_reading],1
    call ext_sel_current
    test rax,rax
    jnz .no
    mov rdi,rbx
    xor esi,esi
    xor edx,edx
    lea rcx,[rel ext_sel_primary]
    lea r8,[rel ext_sel_current]
    call ext_sel_query
    test rax,rax
    jnz .no
    call ext_sel_current
    test rax,rax
    jnz .no
    mov rdi,rbx
    mov rsi,[rel ext_sel_primary+16]
    add rsi,2
    mov edx,2
    lea rcx,[rel ext_sel_sb]
    call ext_raw_read
    test rax,rax
    jnz .no
    cmp word [rel ext_sel_sb+ESB_MAGIC],EXT_MAGIC
    jne .no
    lea rdi,[rel ext_sb_buf]
    lea rsi,[rel ext_sel_sb]
    mov edx,1024
    call memcpy
    mov rax,[rel ext_sel_identity+24]
    mov [rel ext_probe_generation],rax
    mov r13d,[rel ext4_disk_mount_count]
    test r13d,r13d
    jnz .ops_ready
    call ext_build_ops
.ops_ready:
    mov rdi,rbx
    mov rsi,[rel ext_sel_primary+16]
    mov rdx,[rel ext_sel_primary+24]
    mov ecx,[rel ext_sel_primary+36]
    lea r8,[rel ext_sel_recheck]
    mov byte [rel ext_sel_reading],1
    call ext_try_mount_checked
    mov byte [rel ext_sel_reading],0
    mov eax,[rel ext4_disk_mount_count]
    sub eax,r13d
    cmp eax,1
    jne .no
    mov rdi,rbx
    call ext_sel_context
    test rax,rax
    jz .no
    mov r12,rax
    mov eax,[r12+ext_ctx.handle]
    mov [rel vfs_disk_handle],eax
    jmp .out
.busy:
    mov rax,-2
    jmp .out
.no:
    mov rax,-1
.out:
    mov byte [rel ext_sel_reading],0
    pop r13
    pop r12
    pop rbx
    ret

; RCX=out96; MBR retains original48. GPT has no loose-parser fallback.
ext_sel_query:
    cmp byte [rel ext_sel_gpt],0
    je .mbr
    mov esi,2
    jmp fs_identify_single_gpt_checked
.mbr:
    push rcx
    call fs_identify_primary_checked
    pop rcx
    test rax,rax
    jnz .out
    cmp dword [rcx+36],FS_SCHEME_MBR
    jne .no
    cmp dword [rcx+40],0x83
    jne .no
.out:
    ret
.no:
    mov rax,-1
    ret

; Opaque dev -> current native readable removable dev / 0. No media I/O.
ext_sel_member:
    push rbx
    push r12
    mov r12,rdi
    xor ebx,ebx
.next:
    mov rdi,rbx
    mov esi,BLKCAP_READ
    xor edx,edx
    call blk_iter_after
    test rax,rax
    jz .out
    mov rbx,rax
    cmp rax,r12
    jne .next
    mov rdx,[rax+dev.info]
    cmp byte [rdx+blk_info.removable],0
    jne .out
    test dword [rdx+blk_info.flags],BLKF_REMOVABLE
    jnz .out
    xor eax,eax
.out:
    pop r12
    pop rbx
    ret

; Compare original registry incarnation before following captured info/ops.
ext_sel_current:
    mov rdi,[rel ext_sel_device]
    call ext_sel_member
    test rax,rax
    jz .no
    mov rdx,[rax+dev.info]
    cmp rdx,[rel ext_sel_identity]
    jne .no
    mov rcx,[rax+dev.ops]
    cmp rcx,[rel ext_sel_identity+8]
    jne .no
    mov rcx,[rax+dev.priv]
    cmp rcx,[rel ext_sel_identity+16]
    jne .no
    mov rcx,[rdx+blk_info.media_generation]
    cmp rcx,[rel ext_sel_identity+24]
    jne .no
    mov rcx,[rdx+blk_info.lba_max]
    cmp rcx,[rel ext_sel_identity+32]
    jne .no
    cmp dword [rdx+blk_info.sector_size],512
    jne .no
    cmp dword [rdx+blk_info.logical_sector_bytes],512
    jne .no
    mov rdi,rax
    call guest_volume_native_allowed
    test rax,rax
    jnz .no
    xor eax,eax
    ret
.no:
    mov rax,-1
    ret

; Candidate is fully parsed but not published. Re-discover independently, then
; compare all 48 tuple bytes and the complete original superblock. No partial mount
; is visible if any parser-time device/table/boot identity changed.
ext_sel_recheck:
    call ext_sel_current
    test rax,rax
    jnz .out
    mov rdi,[rel ext_sel_device]
    xor esi,esi
    xor edx,edx
    lea rcx,[rel ext_sel_again]
    lea r8,[rel ext_sel_current]
    call ext_sel_query
    test rax,rax
    jnz .out
    lea rdi,[rel ext_sel_primary]
    lea rsi,[rel ext_sel_again]
    mov ecx,6
    cmp byte [rel ext_sel_gpt],0
    je .compare
    mov ecx,12
.compare:
    repe cmpsq
    jne .no
    call ext_sel_current
    test rax,rax
    jnz .out
    mov rdi,[rel ext_sel_device]
    mov rsi,[rel ext_sel_primary+16]
    add rsi,2
    mov edx,2
    lea rcx,[rel ext_sel_sb_again]
    call ext_raw_read
    test rax,rax
    jnz .out
    lea rdi,[rel ext_sel_sb]
    lea rsi,[rel ext_sel_sb_again]
    mov ecx,128
    repe cmpsq
    jne .no
    jmp ext_sel_current
.no:
    mov rax,-1
.out:
    ret

; Resolve one already published native ext context without changing it.
ext_sel_context:
    push rbx
    push r12
    mov r12,rdi
    xor ebx,ebx
.next:
    cmp ebx,VFS_MAX_MOUNTS
    jae .no
    mov edi,ebx
    call vfs_mount_ptr
    test rax,rax
    jz .more
    lea rdx,[rel ext_ops]
    cmp [rax+fsmount.ops],rdx
    jne .more
    mov rax,[rax+fsmount.priv]
    test rax,rax
    jz .more
    cmp dword [rax+ext_ctx.mounted],1
    jne .more
    cmp [rax+ext_ctx.dev],r12
    je .out
.more:
    inc ebx
    jmp .next
.no:
    xor eax,eax
.out:
    pop r12
    pop rbx
    ret

; ext4_disk_remount(EDI=existing handle, RSI=full16 UUID) -> positive epoch / -1.
; BSP command path only. No scan, new mount row, write, journal replay or grant.
; Reject live/queued copy and open/uncertain writer state. Drop old authority and
; unpublish the context BEFORE fresh I/O; any subsequent failure leaves it dead.
; Reuse the same bounded allocation/workspace, clearing ALL derived metadata,
; inode/directory/data caches, journal state and authority before normal mount.
; Stable device/media/full UUID/window/profile are required; no cache fallback.
ext4_disk_remount:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 112                       ; fixed anchor snapshot, never old cached metadata
    mov  r14d, edi
    mov  r13, rsi
    mov  dword [rel ext4_disk_last_error], EXT_E_DENIED
    call storage_access_request_owner
    cmp  eax, 1
    jne  .fail
    mov  edi, r14d
    call ext_w_ctx_of
    test rax, rax
    jz   .identity
    mov  r12, rax
    test r13, r13
    jz   .identity
    lea  rdi, [r12 + ext_ctx.read_uuid]
    mov  rsi, r13
    mov  edx, 16
    call memcmp
    test eax, eax
    jnz  .identity
    call vfs_copy_busy
    test eax, eax
    jnz  .busy
    cmp  [rel ext_w_job_ctx], r12
    je   .busy
    cmp  dword [r12 + ext_ctx.wdead], 0
    jne  .dead
    mov  rbx, [r12 + ext_ctx.wks]
    test rbx, rbx
    jz   .idle
    cmp  dword [rbx + ext_wks.open], 0
    jne  .busy
    cmp  qword [rbx + ext_wks.owned_handle], 0
    jne  .busy
    cmp  qword [rbx + ext_wks.job_tag], 0
    jne  .busy
.idle:
    mov  rax, [r12 + ext_ctx.remount_epoch]
    inc  rax
    test rax, rax                      ; clear INC overflow before signed positivity test
    jle  .identity                      ; no wrap or signed/zero epoch
    mov  [rsp + 72], rax
    mov  [rsp + 64], rbx
    mov  rax, [r12 + ext_ctx.dev]
    mov  [rsp], rax
    mov  rax, [r12 + ext_ctx.part_lba]
    mov  [rsp + 8], rax
    mov  rax, [r12 + ext_ctx.part_sectors]
    mov  [rsp + 16], rax
    mov  eax, [r12 + ext_ctx.scheme]
    mov  [rsp + 24], rax
    mov  rax, [r12 + ext_ctx.name]
    mov  [rsp + 32], rax
    mov  [rsp + 40], r14
    mov  eax, [r12 + ext_ctx.xfer]
    mov  [rsp + 48], rax
    mov  rax, [r12 + ext_ctx.read_generation]
    mov  [rsp + 56], rax
    lea  rdi, [rsp + 80]
    mov  rsi, r13
    mov  edx, 16
    call memcpy
    mov  dword [r12 + ext_ctx.armed], 0
    mov  qword [r12 + ext_ctx.owned_token], 0
    mov  dword [r12 + ext_ctx.mounted], 0
    lock inc qword [rel vfs_write_generation]
    call .medium
    test eax, eax
    jnz  .identity
    lea  rsi, [rsp + 80]
    call ext_w_check_sb                 ; actual reread, full UUID/clean/profile/checksum
    test rax, rax
    jnz  .fail                         ; never re-publish old context on error
    call .medium
    test eax, eax
    jnz  .identity
    mov  rdi, [rsp + 64]
    test rdi, rdi
    jz   .clear_ctx
    xor  esi, esi
    mov  edx, ext_wks_size
    call memset
.clear_ctx:
    mov  rdi, r12
    xor  esi, esi
    mov  edx, EXT_CTX_ALLOC
    call memset
    mov  rax, [rsp]
    mov  [r12 + ext_ctx.dev], rax
    mov  rax, [rsp + 8]
    mov  [r12 + ext_ctx.part_lba], rax
    mov  rax, [rsp + 16]
    mov  [r12 + ext_ctx.part_sectors], rax
    mov  eax, [rsp + 24]
    mov  [r12 + ext_ctx.scheme], eax
    mov  rax, [rsp + 32]
    mov  [r12 + ext_ctx.name], rax
    mov  eax, [rsp + 40]
    mov  [r12 + ext_ctx.handle], eax
    mov  eax, [rsp + 48]
    mov  [r12 + ext_ctx.xfer], eax
    mov  rax, [rsp + 56]
    mov  [r12 + ext_ctx.read_generation], rax
    mov  rax, [rsp + 64]
    mov  [r12 + ext_ctx.wks], rax
    lea  rdi, [r12 + ext_ctx.read_uuid]
    lea  rsi, [rsp + 80]
    mov  edx, 16
    call memcpy
    lea  rax, [r12 + ext_ctx_size]
    mov  [r12 + ext_ctx.meta_buf], rax
    add  rax, EXT_BUF_BYTES
    mov  [r12 + ext_ctx.ibuf], rax
    add  rax, EXT_BUF_BYTES
    mov  [r12 + ext_ctx.dir_buf], rax
    mov  qword [r12 + ext_ctx.meta_tag], -1
    mov  qword [r12 + ext_ctx.ibuf_tag], -1
    call ext_mount_ctx                 ; same fresh geometry/checksum/root validation as boot
    test eax, eax
    jnz  .identity
    call .medium
    test eax, eax
    jnz  .identity
    mov  rax, [rsp + 72]
    mov  [r12 + ext_ctx.remount_epoch], rax
    mov  dword [r12 + ext_ctx.mounted], 1
    jmp  .out
.medium:                               ; called with a return address above anchor frame
    mov  rax, [rsp + 8]
    mov  rax, [rax + dev.info]
    test rax, rax
    jz   .changed
    cmp  dword [rax + blk_info.sector_size], 512
    jne  .changed
    mov  rax, [rax + blk_info.media_generation]
    test rax, rax
    jz   .changed
    cmp  rax, [rsp + 64]                ; saved generation at caller rsp+56
    jne  .changed
    xor  eax, eax
    ret
.changed:
    mov  eax, -1
    ret
.busy:
    mov  dword [rel ext4_disk_last_error], EXT_E_BUSY
    jmp  .fail
.dead:
    mov  dword [rel ext4_disk_last_error], EXT_E_DEAD
    jmp  .fail
.identity:
    mov  dword [rel ext4_disk_last_error], EXT_E_WGATE
.fail:
    mov  rax, -1
.out:
    add  rsp, 112
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ext_scan_device(RDI=dev*): superfloppy, MBR primaries, GPT entries.
ext_scan_device:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    call blk_identify
    test rax, rax
    jnz  .out
    mov  rax, [r12 + dev.info]
    test rax, rax
    jz   .out
    mov  r15, [rax + blk_info.lba_max]
    inc  r15                             ; total sectors
    jz   .out
    ; A non-512 device is skipped before any read and without a marker: the
    ; sector arithmetic here is 512-byte only (GAP-04 geometry rule), and such
    ; a device is not known to hold an ext volume, so nothing is "refused".
    cmp  dword [rax + blk_info.sector_size], 512
    jne  .out
    mov  rdi, r12
    xor  esi, esi
    mov  edx, 1
    lea  rcx, [rel ext_scan_buf]
    call ext_raw_read
    test rax, rax
    jnz  .out
    ; A partition table wins: the superfloppy probe reads LBA 2..3, which on a
    ; GPT disk is entry space (a name starting U+EF53 must not hide the disk).
    cmp  word [rel ext_scan_buf + 510], 0xAA55
    jne  .superfloppy
    mov  rax, [rel ext_scan_buf + 446]
    or   rax, [rel ext_scan_buf + 454]
    or   rax, [rel ext_scan_buf + 462]
    or   rax, [rel ext_scan_buf + 470]
    or   rax, [rel ext_scan_buf + 478]
    or   rax, [rel ext_scan_buf + 486]
    or   rax, [rel ext_scan_buf + 494]
    or   rax, [rel ext_scan_buf + 502]
    jnz  .table                          ; a non-empty MBR (or the GPT protective entry)
.superfloppy:
    mov  rdi, r12
    xor  esi, esi
    mov  rdx, r15
    mov  ecx, FS_SCHEME_SUPERFLOPPY
    call ext_probe
    jmp  .out
.table:
    xor  r13d, r13d
.mbr:
    cmp  r13d, 4
    jae  .out
    mov  eax, r13d
    shl  eax, 4
    lea  rbx, [rel ext_scan_buf + 446]
    add  rbx, rax
    movzx eax, byte [rbx + 4]
    cmp  al, 0xEE
    je   .gpt
    test al, al
    jz   .mbr_next
    cmp  al, 0x05                        ; extended containers hold no filesystem
    je   .mbr_next
    cmp  al, 0x0F
    je   .mbr_next
    cmp  al, 0x85
    je   .mbr_next
    mov  esi, [rbx + 8]
    mov  edx, [rbx + 12]
    test esi, esi
    jz   .mbr_next
    test edx, edx
    jz   .mbr_next
    lea  rax, [rsi + rdx]
    cmp  rax, r15
    ja   .mbr_next
    mov  rdi, r12
    mov  ecx, FS_SCHEME_MBR
    call ext_probe
.mbr_next:
    inc  r13d
    jmp  .mbr
.gpt:
    mov  rdi, r12
    mov  esi, 1
    mov  edx, 1
    lea  rcx, [rel ext_scan_buf]
    call ext_raw_read
    test rax, rax
    jnz  .out
    mov  rax, 0x5452415020494645         ; "EFI PART"
    cmp  [rel ext_scan_buf], rax
    jne  .out
    cmp  dword [rel ext_scan_buf + 84], 128
    jne  .out
    mov  r14, [rel ext_scan_buf + 72]    ; entries LBA
    test r14, r14
    jz   .out
    mov  eax, [rel ext_scan_buf + 80]
    cmp  eax, EXT_GPT_MAX
    jbe  .count_ok
    mov  eax, EXT_GPT_MAX
.count_ok:
    mov  [rel ext_gpt_count], eax
    xor  r13d, r13d
.gpt_entry:
    cmp  r13d, [rel ext_gpt_count]
    jae  .out
    test r13d, 3
    jnz  .have_sector
    mov  esi, r13d
    shr  esi, 2
    add  rsi, r14
    jc   .out
    mov  rdi, r12
    mov  edx, 1
    lea  rcx, [rel ext_scan_buf]
    call ext_raw_read
    test rax, rax
    jnz  .out
.have_sector:
    mov  eax, r13d
    and  eax, 3
    shl  eax, 7
    lea  rbx, [rel ext_scan_buf]
    add  rbx, rax
    mov  rax, [rbx]
    or   rax, [rbx + 8]
    jz   .gpt_next
    mov  rsi, [rbx + 32]                 ; first LBA
    mov  rdx, [rbx + 40]                 ; last LBA (inclusive)
    test rsi, rsi
    jz   .gpt_next
    cmp  rdx, rsi
    jb   .gpt_next
    cmp  rdx, r15
    jae  .gpt_next
    sub  rdx, rsi
    inc  rdx
    mov  rdi, r12
    mov  ecx, FS_SCHEME_GPT
    call ext_probe
.gpt_next:
    inc  r13d
    jmp  .gpt_entry
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ext_probe(RDI=dev, RSI=part lba, RDX=sectors, ECX=scheme) -> RAX 1 = an ext
;   superblock was found (mounted or refused), 0 = not ext. Preserves
;   ext_scan_buf (the superblock goes to ext_sb_buf).
ext_probe:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15d, ecx
    xor  ebx, ebx
    cmp  r14, 8                          ; the 1024-byte superblock lives in sectors 2..3
    jb   .out
    mov  qword [rel ext_probe_generation], 0
    mov  rax, [r12 + dev.info]
    test rax, rax
    jz   .probe_read
    mov  rax, [rax + blk_info.media_generation]
    mov  [rel ext_probe_generation], rax
.probe_read:
    mov  rdi, r12
    lea  rsi, [r13 + 2]
    mov  edx, 2
    lea  rcx, [rel ext_sb_buf]
    call ext_raw_read
    test rax, rax
    jnz  .out
    cmp  word [rel ext_sb_buf + ESB_MAGIC], EXT_MAGIC
    jne  .out
    mov  ebx, 1
    cmp  dword [rel ext4_disk_mount_count], EXT_MAX_MOUNTS
    jae  .out
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, r14
    mov  ecx, r15d
    call ext_try_mount
.out:
    mov  eax, ebx
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ext_try_mount(RDI=dev, RSI=lba, RDX=sectors, ECX=scheme): superblock in
; ext_sb_buf. Mounts + registers, or emits the refusal. A refused context is
; kept as the spare for the next candidate (the heap is a bump allocator).
ext_try_mount:
    xor r8d,r8d                       ; ordinary scan has no late validator
; Internal R8=optional pre-publication read-only validator.
ext_try_mount_checked:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,16
    mov [rsp],r8
    mov  r13, rdi
    mov  r14, rsi
    mov  r15, rdx
    mov  ebx, ecx
    mov  r12, [rel ext_spare_ctx]
    test r12, r12
    jnz  .have_ctx
    mov  rdi, EXT_CTX_ALLOC
    call kmalloc
    test rax, rax
    jnz  .alloc_ok
    mov  rdi, r13
    mov  rsi, r14
    mov  edx, EXT_R_NOMEM
    call ext_emit_refused
    jmp  .out
.alloc_ok:
    mov  r12, rax
    mov  [rel ext_spare_ctx], rax
.have_ctx:
    mov  rdi, r12
    xor  esi, esi
    mov  edx, ext_ctx_size
    call memset
    lea  rax, [r12 + ext_ctx_size]
    mov  [r12 + ext_ctx.meta_buf], rax
    add  rax, EXT_BUF_BYTES
    mov  [r12 + ext_ctx.ibuf], rax
    add  rax, EXT_BUF_BYTES
    mov  [r12 + ext_ctx.dir_buf], rax
    mov  qword [r12 + ext_ctx.meta_tag], -1
    mov  qword [r12 + ext_ctx.ibuf_tag], -1
    mov  dword [r12 + ext_ctx.handle], -1
    mov  [r12 + ext_ctx.dev], r13
    mov  [r12 + ext_ctx.part_lba], r14
    mov  [r12 + ext_ctx.part_sectors], r15
    mov  [r12 + ext_ctx.scheme], ebx
    mov  rax, [rel ext_probe_generation]
    mov  [r12 + ext_ctx.read_generation], rax
    lea  rdi, [r12 + ext_ctx.read_uuid]
    lea  rsi, [rel ext_sb_buf + ESB_UUID]
    mov  edx, 16
    call memcpy
    mov  eax, [rel ext4_disk_mount_count]
    imul eax, eax, 5
    lea  rdx, [rel str_ext_mount_names]
    add  rax, rdx
    mov  [r12 + ext_ctx.name], rax
    mov  rax, [r13 + dev.info]
    mov  ecx, [rax + blk_info.max_transfer_sectors]
    cmp  qword [rax + blk_info.capabilities], 0
    je   .xfer_default                   ; pre-2912 backend: the field is not declared
    test ecx, ecx
    jz   .xfer_default
    cmp  ecx, EXT_XFER_MAX
    jbe  .xfer_set
.xfer_default:
    mov  ecx, EXT_XFER_MAX
.xfer_set:
    mov  [r12 + ext_ctx.xfer], ecx
    call ext_mount_ctx
    test eax, eax
    jz   .mounted
    mov  rdi, r13
    mov  rsi, r14
    mov  edx, eax
    call ext_emit_refused
    jmp  .out
.mounted:
    mov rax,[rsp]
    test rax,rax
    jz .publish
    call rax
    test rax,rax
    jnz .out
    cmp dword [rel ext4_disk_mount_count],EXT_MAX_MOUNTS
    jae .out
.publish:
    mov  dword [r12 + ext_ctx.mounted], 1
    lea  rdi, [rel ext_ops]
    mov  rsi, r12
    mov  rdx, [r12 + ext_ctx.name]
    call vfs_register_mount
    test rax, rax
    jns  .registered
    mov  dword [r12 + ext_ctx.mounted], 0
    mov  rdi, r13
    mov  rsi, r14
    mov  edx, EXT_R_NOMOUNT
    call ext_emit_refused
    jmp  .out
.registered:
    mov  [r12 + ext_ctx.handle], eax
    cmp  dword [rel ext4_disk_mount_count], 0
    jne  .not_first
    mov  [rel ext4_disk_handle], eax
.not_first:
    inc  dword [rel ext4_disk_mount_count]
    mov  qword [rel ext_spare_ctx], 0
    call ext_emit_mounted
.out:
    add rsp,16
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ext_mount_ctx(R12=ctx with dev/part set, superblock in ext_sb_buf)
;   -> EAX 0 = mountable / EXT_R_* refusal reason.
ext_mount_ctx:
    push rbx
    push r13
    push r14
    push r15
    mov  dword [rel ext4_disk_last_error], EXT_E_NONE
    lea  rbx, [rel ext_sb_buf]
    cmp  word [rbx + ESB_MAGIC], EXT_MAGIC
    jne  .geometry
    cmp  dword [rbx + ESB_REV], 1
    jb   .rev
    movzx eax, word [rbx + ESB_STATE]
    and  eax, EXT_STATE_VALID | EXT_STATE_ERROR
    cmp  eax, EXT_STATE_VALID
    jne  .state
    mov  eax, [rbx + ESB_INCOMPAT]
    mov  [r12 + ext_ctx.incompat], eax
    test eax, EXT_IN_RECOVER
    jnz  .recover
    test eax, ~EXT_IN_ALLOWED
    jnz  .incompat
    test eax, EXT_IN_FILETYPE
    jz   .filetype
    mov  eax, [rbx + ESB_RO_COMPAT]
    mov  [r12 + ext_ctx.ro_compat], eax
    test eax, ~EXT_RO_ALLOWED
    jnz  .rocompat
    mov  eax, [rbx + ESB_COMPAT]
    mov  [r12 + ext_ctx.compat], eax
    test dword [r12 + ext_ctx.ro_compat], EXT_RO_METADATA_CSUM
    jz   .csum_ok
    cmp  byte [rbx + ESB_CSUM_TYPE], 1   ; crc32c is the only defined type
    jne  .csum
    mov  rdi, rbx
    mov  esi, ESB_CSUM
    mov  edx, 0xFFFFFFFF
    call ext_crc32c
    cmp  eax, [rbx + ESB_CSUM]
    jne  .csum
.csum_ok:
    ; ---- block geometry ----
    mov  ecx, [rbx + ESB_LOG_BLOCK]
    cmp  ecx, 2
    ja   .geometry
    lea  eax, [ecx + 10]
    mov  [r12 + ext_ctx.block_shift], eax
    lea  eax, [ecx + 1]
    mov  [r12 + ext_ctx.spb_shift], eax
    mov  eax, 1024
    shl  eax, cl
    mov  [r12 + ext_ctx.block_bytes], eax
    mov  r13d, eax                       ; block bytes
    xor  edx, edx
    cmp  r13d, 1024
    jne  .fdb
    mov  edx, 1
.fdb:
    cmp  [rbx + ESB_FIRST_DATA], edx
    jne  .geometry
    mov  [r12 + ext_ctx.first_data], rdx
    mov  eax, [rbx + ESB_BLOCKS_LO]
    test dword [r12 + ext_ctx.incompat], EXT_IN_64BIT
    jz   .blocks_lo
    mov  ecx, [rbx + ESB_BLOCKS_HI]
    shl  rcx, 32
    or   rax, rcx
.blocks_lo:
    mov  [r12 + ext_ctx.blocks_count], rax
    cmp  rax, [r12 + ext_ctx.first_data]
    jbe  .geometry
    mov  rdx, [r12 + ext_ctx.part_sectors]
    mov  ecx, [r12 + ext_ctx.spb_shift]
    shr  rdx, cl                         ; whole blocks the partition can hold
    cmp  rax, rdx
    ja   .geometry
    ; groups
    mov  ecx, [rbx + ESB_BLOCKS_PER_G]
    test ecx, ecx
    jz   .geometry
    test ecx, 7
    jnz  .geometry
    mov  eax, r13d
    shl  eax, 3
    cmp  ecx, eax
    ja   .geometry
    mov  [r12 + ext_ctx.blocks_per_g], ecx
    mov  edx, [rbx + ESB_INODES_PER_G]
    test edx, edx
    jz   .geometry
    cmp  edx, eax
    ja   .geometry
    mov  [r12 + ext_ctx.inodes_per_g], edx
    mov  rax, [r12 + ext_ctx.blocks_count]
    sub  rax, [r12 + ext_ctx.first_data]
    mov  ecx, [r12 + ext_ctx.blocks_per_g]
    add  rax, rcx
    dec  rax
    xor  edx, edx
    div  rcx                             ; group count = ceil(data blocks / bpg)
    mov  ecx, 0xFFFFFFFF
    cmp  rax, rcx
    ja   .geometry
    mov  [r12 + ext_ctx.group_count], eax
    mov  r14, rax
    ; inodes
    mov  eax, [rbx + ESB_INODES_COUNT]
    cmp  eax, EXT_ROOT_INO
    jb   .geometry
    mov  [r12 + ext_ctx.inodes_count], eax
    mov  ecx, [r12 + ext_ctx.inodes_per_g]
    mov  rdx, r14
    imul rdx, rcx                        ; <= 2^32 * 2^15: no overflow
    cmp  rax, rdx
    ja   .geometry
    movzx eax, word [rbx + ESB_INODE_SIZE]
    cmp  eax, 128
    jb   .geometry
    cmp  eax, r13d
    ja   .geometry
    lea  ecx, [eax - 1]
    test eax, ecx
    jnz  .geometry
    mov  [r12 + ext_ctx.inode_size], eax
    mov  ecx, [r12 + ext_ctx.inodes_per_g]
    imul rax, rcx                        ; inode-table bytes per group
    lea  rax, [rax + r13 - 1]
    mov  ecx, [r12 + ext_ctx.block_shift]
    shr  rax, cl
    mov  [r12 + ext_ctx.it_blocks], rax
    ; descriptors
    mov  eax, 32
    test dword [r12 + ext_ctx.incompat], EXT_IN_64BIT
    jz   .desc_set
    movzx eax, word [rbx + ESB_DESC_SIZE]
    cmp  eax, 64
    jb   .geometry
    cmp  eax, 1024
    ja   .geometry
    lea  ecx, [eax - 1]
    test eax, ecx
    jnz  .geometry
.desc_set:
    mov  [r12 + ext_ctx.desc_size], eax
    mov  rcx, [r12 + ext_ctx.first_data]
    inc  rcx
    mov  [r12 + ext_ctx.gdt_block], rcx
    mov  rdx, r14
    imul rdx, rax                        ; descriptor table bytes (< 2^42)
    lea  rdx, [rdx + r13 - 1]
    mov  ecx, [r12 + ext_ctx.block_shift]
    shr  rdx, cl
    add  rdx, [r12 + ext_ctx.gdt_block]
    cmp  rdx, [r12 + ext_ctx.blocks_count]
    ja   .geometry
    mov  eax, [rbx + ESB_UUID]
    mov  [r12 + ext_ctx.volume_id], eax
    mov  eax, 1024
    mov  ecx, [r12 + ext_ctx.block_shift]
    shr  eax, cl
    mov  [r12 + ext_ctx.sb_blk], rax     ; 1 for 1 KiB blocks, else 0
    mov  eax, 1024
    mov  ecx, [r12 + ext_ctx.block_bytes]
    dec  ecx
    and  eax, ecx
    mov  [r12 + ext_ctx.sb_off], eax
    test dword [r12 + ext_ctx.ro_compat], EXT_RO_METADATA_CSUM
    jz   .seed_done
    mov  eax, [rbx + ESB_CSUM_SEED]
    test dword [r12 + ext_ctx.incompat], EXT_IN_CSUM_SEED
    jnz  .seed_set
    lea  rdi, [rbx + ESB_UUID]
    mov  esi, 16
    mov  edx, 0xFFFFFFFF
    call ext_crc32c
.seed_set:
    mov  [r12 + ext_ctx.csum_seed], eax
.seed_done:
    ; kind: ext4 when any ext4-only incompat feature is on, else ext3 with a journal, else ext2
    mov  dword [r12 + ext_ctx.kind], 4
    test dword [r12 + ext_ctx.incompat], EXT_IN_EXTENTS | EXT_IN_64BIT | EXT_IN_FLEX_BG
    jnz  .root
    mov  dword [r12 + ext_ctx.kind], 3
    test dword [r12 + ext_ctx.compat], EXT_COMPAT_JOURNAL
    jnz  .root
    mov  dword [r12 + ext_ctx.kind], 2
.root:
    mov  esi, EXT_ROOT_INO
    lea  rdi, [r12 + ext_ctx.inode]
    call ext_read_inode
    test rax, rax
    jnz  .bad_root
    movzx eax, word [r12 + ext_ctx.inode + EI_MODE]
    and  eax, EXT_S_IFMT
    cmp  eax, EXT_S_IFDIR
    jne  .bad_root
    xor  eax, eax
    jmp  .out
.bad_root:
    mov  eax, EXT_R_ROOT
    cmp  dword [rel ext4_disk_last_error], EXT_E_IO
    jne  .out
    mov  eax, EXT_R_IO
    jmp  .out
.rev:
    mov  eax, EXT_R_REV
    jmp  .out
.state:
    mov  eax, EXT_R_STATE
    jmp  .out
.recover:
    mov  eax, EXT_R_RECOVER
    jmp  .out
.incompat:
    mov  eax, EXT_R_INCOMPAT
    jmp  .out
.filetype:
    mov  eax, EXT_R_FILETYPE
    jmp  .out
.rocompat:
    mov  eax, EXT_R_ROCOMPAT
    jmp  .out
.csum:
    mov  eax, EXT_R_CSUM
    jmp  .out
.geometry:
    mov  eax, EXT_R_GEOMETRY
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

; ext_crc32c(RDI=buf, ESI=len, EDX=seed) -> EAX = raw CRC32C (Castagnoli,
; reflected, no final inversion: the form ext4 and jbd2 store). Table-driven;
; the 1 KiB table is built on first use. Clobbers RAX, RCX, RDX, RSI, RDI, R8.
ext_crc32c:
    cmp  byte [rel ext_crc_ready], 1
    je   .ready
    push rdi
    push rsi
    push rdx
    lea  r8, [rel ext_crc_table]
    xor  ecx, ecx
.entry:
    mov  eax, ecx
    mov  edx, 8
.bit:
    shr  eax, 1
    jnc  .no_poly
    xor  eax, 0x82F63B78
.no_poly:
    dec  edx
    jnz  .bit
    mov  [r8 + rcx * 4], eax
    inc  ecx
    cmp  ecx, 256
    jb   .entry
    mov  byte [rel ext_crc_ready], 1
    pop  rdx
    pop  rsi
    pop  rdi
.ready:
    lea  r8, [rel ext_crc_table]
    mov  eax, edx
.byte:
    test esi, esi
    jz   .done
    movzx ecx, byte [rdi]
    xor  ecx, eax
    and  ecx, 0xFF
    shr  eax, 8
    xor  eax, [r8 + rcx * 4]
    inc  rdi
    dec  esi
    jmp  .byte
.done:
    ret

; ext_crc_u32(EDI=value, ESI=seed) -> EAX = crc32c over the 4 little-endian bytes.
ext_crc_u32:
    sub  rsp, 8
    mov  [rsp], edi
    mov  edx, esi
    mov  rdi, rsp
    mov  esi, 4
    call ext_crc32c
    add  rsp, 8
    ret

; ext_crc_zero(EDI=crc, ESI=count) -> EAX = crc32c continued over count zero bytes.
ext_crc_zero:
    sub  rsp, 8
    mov  qword [rsp], 0
    mov  edx, edi
    mov  rdi, rsp
    call ext_crc32c
    add  rsp, 8
    ret

; ext_inode_csum(R12=ctx, RDI=raw on-disk inode (inode_size bytes), ESI=inode number)
;   -> EAX = metadata_csum checksum with both checksum fields taken as zero,
;      EDX = the inode's checksum seed (extent/dir tails). ECX = 1 when the
;      inode carries i_checksum_hi (stored value = EAX), 0 when only lo (= AX).
ext_inode_csum:
    push rbx
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  edi, esi
    mov  esi, [r12 + ext_ctx.csum_seed]
    call ext_crc_u32
    mov  edi, [rbx + EI_GENERATION]
    mov  esi, eax
    call ext_crc_u32
    mov  r14d, eax                       ; inode seed
    mov  rdi, rbx
    mov  esi, EI_CSUM_LO
    mov  edx, eax
    call ext_crc32c
    mov  edi, eax
    mov  esi, 2
    call ext_crc_zero
    xor  r15d, r15d                      ; hi present?
    mov  r13d, [r12 + ext_ctx.inode_size]
    cmp  r13d, 128
    jbe  .lo_only
    cmp  word [rbx + EI_EXTRA_ISIZE], 4
    jb   .lo_only
    mov  r15d, 1
    lea  rdi, [rbx + EI_CSUM_LO + 2]
    mov  esi, EI_CSUM_HI - EI_CSUM_LO - 2
    mov  edx, eax
    call ext_crc32c
    mov  edi, eax
    mov  esi, 2
    call ext_crc_zero
    lea  rdi, [rbx + EI_CSUM_HI + 2]
    mov  esi, r13d
    sub  esi, EI_CSUM_HI + 2
    mov  edx, eax
    call ext_crc32c
    jmp  .done
.lo_only:
    lea  rdi, [rbx + EI_CSUM_LO + 2]
    mov  esi, r13d
    sub  esi, EI_CSUM_LO + 2
    mov  edx, eax
    call ext_crc32c
.done:
    mov  edx, r14d
    mov  ecx, r15d
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

; ext_gd_csum(R12=ctx, RDI=descriptor, ESI=group) -> EAX = 16-bit metadata_csum
;   descriptor checksum (the bg_checksum field taken as zero).
ext_gd_csum:
    push rbx
    mov  rbx, rdi
    mov  edi, esi
    mov  esi, [r12 + ext_ctx.csum_seed]
    call ext_crc_u32
    mov  rdi, rbx
    mov  esi, EGD_CHECKSUM
    mov  edx, eax
    call ext_crc32c
    mov  edi, eax
    mov  esi, 2
    call ext_crc_zero
    lea  rdi, [rbx + EGD_CHECKSUM + 2]
    mov  esi, [r12 + ext_ctx.desc_size]
    sub  esi, EGD_CHECKSUM + 2
    mov  edx, eax
    call ext_crc32c
    and  eax, 0xFFFF
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; Media access
; ---------------------------------------------------------------------------
; ext_raw_read(RDI=dev, RSI=lba, RDX=count, RCX=buf) -> RAX 0/-1.
;   Range-checked against the device; at most EXT_XFER_MAX sectors per call;
;   a refused multi-sector call (NVMe accepts one block) falls back to single
;   sectors and is counted in ext_rd_fallback.
ext_raw_read:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rdx
    mov  r14, rcx
    call ext_sel_guard
    test rax,rax
    jnz .fail
    test r13, r13
    jz   .fail
    mov  rax, [rbx + dev.info]
    test rax, rax
    jz   .fail
    mov  rdx, r12
    add  rdx, r13
    jc   .fail
    dec  rdx
    cmp  rdx, [rax + blk_info.lba_max]
    ja   .fail
.chunk:
    test r13, r13
    jz   .ok
    ; at most EXT_XFER_MAX, and at most the device's declared transfer limit
    mov  rax, [rbx + dev.info]
    mov  ecx, EXT_XFER_MAX
    cmp  qword [rax + blk_info.capabilities], 0
    je   .limit
    mov  edx, [rax + blk_info.max_transfer_sectors]
    test edx, edx
    jz   .limit
    cmp  edx, ecx
    jae  .limit
    mov  ecx, edx
.limit:
    mov  r15, r13
    cmp  r15, rcx
    jbe  .sized
    mov  r15, rcx
.sized:
    call ext_cp_guard_read
    test rax, rax
    jnz  .fail
    mov  rdi, rbx
    mov  rsi, r12
    mov  rdx, r15
    mov  rcx, r14
    call ext_sel_block_read
    test rax, rax
    jnz  .read_refused
    call ext_cp_guard_read
    test rax, rax
    jnz  .fail
    jmp  .advance
.read_refused:
    cmp  r15, 1
    jbe  .fail
.one:
    test r15, r15
    jz   .fell_back
    call ext_cp_guard_read
    test rax, rax
    jnz  .fail
    mov  rdi, rbx
    mov  rsi, r12
    mov  edx, 1
    mov  rcx, r14
    call ext_sel_block_read
    test rax, rax
    jnz  .fail
    call ext_cp_guard_read
    test rax, rax
    jnz  .fail
    inc  r12
    add  r14, 512
    dec  r13
    dec  r15
    jmp  .one
.fell_back:
    inc  qword [rel ext_rd_fallback]
    jmp  .chunk
.advance:
    add  r12, r15
    mov  rax, r15
    shl  rax, 9
    add  r14, rax
    sub  r13, r15
    jmp  .chunk
.ok:
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Late selection guard around each native parser transfer, including fallback.
; Ordinary reads retain their existing guard and budget. Preserve IO arguments.
ext_sel_guard:
    cmp byte [rel ext_sel_reading],0
    je .ordinary
    push rdi
    push rsi
    push rdx
    push rcx
    call ext_sel_current
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    ret
.ordinary:
    xor eax,eax
    ret
ext_sel_block_read:
    call ext_sel_guard
    test rax,rax
    jnz .out
    call blk_read
    push rax
    call ext_sel_guard
    test rax,rax
    pop rax
    jz .out
    mov rax,-1
.out:
    ret

; ext_read_blocks(R12=ctx, RSI=first block, RDX=count, RCX=buf) -> RAX 0/-1.
;   Every block must lie inside the filesystem (and so inside the partition).
ext_read_blocks:
    test rdx, rdx
    jz   .fail
    mov  rax, rsi
    add  rax, rdx
    jc   .fail
    cmp  rax, [r12 + ext_ctx.blocks_count]
    ja   .fail
    push rcx
    mov  ecx, [r12 + ext_ctx.spb_shift]
    shl  rsi, cl
    shl  rdx, cl
    pop  rcx
    add  rsi, [r12 + ext_ctx.part_lba]
    mov  rdi, [r12 + ext_ctx.dev]
    call ext_raw_read
    test rax, rax
    jnz  .io
    ret
.io:
    mov  dword [rel ext4_disk_last_error], EXT_E_IO
    mov  rax, -1
    ret
.fail:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
    mov  rax, -1
    ret

; ext_meta(R12=ctx, RSI=block) -> RAX = meta_buf holding it / 0.
ext_meta:
    mov  rax, [r12 + ext_ctx.meta_buf]
    cmp  rsi, [r12 + ext_ctx.meta_tag]
    je   .out
    push rsi
    mov  qword [r12 + ext_ctx.meta_tag], -1
    mov  edx, 1
    mov  rcx, rax
    call ext_read_blocks
    pop  rsi
    test rax, rax
    jnz  .fail
    mov  [r12 + ext_ctx.meta_tag], rsi
    mov  rax, [r12 + ext_ctx.meta_buf]
.out:
    ret
.fail:
    xor  eax, eax
    ret

; ext_ibuf_block(R12=ctx, RSI=block) -> RAX = ibuf holding it / 0.
ext_ibuf_block:
    mov  rax, [r12 + ext_ctx.ibuf]
    cmp  rsi, [r12 + ext_ctx.ibuf_tag]
    je   .out
    push rsi
    mov  qword [r12 + ext_ctx.ibuf_tag], -1
    mov  edx, 1
    mov  rcx, rax
    call ext_read_blocks
    pop  rsi
    test rax, rax
    jnz  .fail
    mov  [r12 + ext_ctx.ibuf_tag], rsi
    mov  rax, [r12 + ext_ctx.ibuf]
.out:
    ret
.fail:
    xor  eax, eax
    ret

; ext_block_ok(R12=ctx, RSI=block) -> CF clear when 1 <= block < blocks_count.
ext_block_ok:
    test rsi, rsi
    jz   .bad
    cmp  rsi, [r12 + ext_ctx.blocks_count]
    jae  .bad
    clc
    ret
.bad:
    stc
    ret

; ---------------------------------------------------------------------------
; Inodes
; ---------------------------------------------------------------------------
; ext_inode_loc(R12=ctx, ESI=inode number) -> RAX = inode-table block, RDX =
;   byte offset of the inode inside it, or RAX = -1. Validates the number, the
;   descriptor (metadata_csum checksum, INODE_UNINIT) and the table bounds.
ext_inode_loc:
    push rbx
    push r13
    push r14
    mov  eax, esi
    test eax, eax
    jz   .corrupt
    cmp  eax, [r12 + ext_ctx.inodes_count]
    ja   .corrupt
    dec  eax
    xor  edx, edx
    div  dword [r12 + ext_ctx.inodes_per_g]
    cmp  eax, [r12 + ext_ctx.group_count]
    jae  .corrupt
    mov  r13d, eax                       ; group
    mov  r14d, edx                       ; index in group
    mov  esi, r13d
    call ext_gd_read
    test rax, rax
    jz   .fail
    mov  rbx, rax                        ; -> descriptor (meta_buf)
    test dword [r12 + ext_ctx.ro_compat], EXT_RO_GDT_CSUM | EXT_RO_METADATA_CSUM
    jz   .table
    test word [rbx + EGD_FLAGS], EGD_INODE_UNINIT
    jz   .table
    call ext_w_uninit_inode_ok           ; the writer materialized it in this open transaction
    jc   .corrupt                        ; else: a reference into an unused table
.table:
    mov  esi, [rbx + EGD_ITABLE_LO]
    test dword [r12 + ext_ctx.incompat], EXT_IN_64BIT
    jz   .table_lo
    cmp  dword [r12 + ext_ctx.desc_size], 64
    jb   .table_lo
    mov  eax, [rbx + EGD_ITABLE_HI]
    shl  rax, 32
    or   rsi, rax
.table_lo:
    test rsi, rsi
    jz   .corrupt
    mov  rax, rsi
    add  rax, [r12 + ext_ctx.it_blocks]
    jc   .corrupt
    cmp  rax, [r12 + ext_ctx.blocks_count]
    ja   .corrupt
    mov  eax, r14d
    mov  ecx, [r12 + ext_ctx.inode_size]
    imul rax, rcx                        ; byte offset in the table
    mov  rdx, rax
    mov  ecx, [r12 + ext_ctx.block_bytes]
    dec  ecx
    and  rdx, rcx
    mov  ecx, [r12 + ext_ctx.block_shift]
    shr  rax, cl
    add  rax, rsi
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

; ext_gd_read(R12=ctx, ESI=group) -> RAX = descriptor inside meta_buf / 0.
;   metadata_csum descriptors are checksum-verified.
ext_gd_read:
    push rbx
    push r13
    mov  r13d, esi
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
    call ext_meta
    test rax, rax
    jz   .out
    add  rbx, rax
    test dword [r12 + ext_ctx.ro_compat], EXT_RO_METADATA_CSUM
    jz   .ok
    mov  rdi, rbx
    mov  esi, r13d
    call ext_gd_csum
    cmp  ax, [rbx + EGD_CHECKSUM]
    jne  .bad
.ok:
    mov  rax, rbx
    jmp  .out
.bad:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
    xor  eax, eax
.out:
    pop  r13
    pop  rbx
    ret

; ext_read_inode(R12=ctx, ESI=inode number, RDI=slot) -> RAX 0/-1.
;   Copies min(inode_size, EXT_INODE_COPY) bytes (rest zeroed) and records the
;   inode number and checksum seed in the slot. metadata_csum inodes must
;   verify. Refuses an out-of-range number, a never-initialized table slot and
;   a free inode.
ext_read_inode:
    push rdi
    call ext_read_inode_any
    pop  rdi
    test rax, rax
    jnz  .out
    cmp  word [rdi + EI_LINKS], 0
    jne  .out
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT   ; a free inode is never a valid reference
    mov  rax, -1
.out:
    ret

; ext_read_inode_any(R12=ctx, ESI=inode number, RDI=slot) -> RAX 0/-1: as
;   ext_read_inode, but an inode with no links is read too (ext4_write: an
;   inode on the orphan list, unlinked but not yet freed).
ext_read_inode_any:
    push rbx
    push r13
    push r14
    push r15
    mov  r15, rdi
    mov  r13d, esi
    mov  [r15 + EXT_SLOT_INO], esi
    mov  dword [r15 + EXT_SLOT_SEED], 0
    call ext_inode_loc
    cmp  rax, -1
    je   .fail
    mov  rbx, rdx
    mov  rsi, rax
    call ext_ibuf_block
    test rax, rax
    jz   .fail
    add  rbx, rax                        ; -> on-disk inode
    test dword [r12 + ext_ctx.ro_compat], EXT_RO_METADATA_CSUM
    jz   .copy_in
    mov  rdi, rbx
    mov  esi, r13d
    call ext_inode_csum
    mov  [r15 + EXT_SLOT_SEED], edx
    test ecx, ecx
    jz   .lo
    movzx edx, word [rbx + EI_CSUM_HI]
    shl  edx, 16
    mov  dx, [rbx + EI_CSUM_LO]
    cmp  eax, edx
    jne  .corrupt
    jmp  .copy_in
.lo:
    cmp  ax, [rbx + EI_CSUM_LO]
    jne  .corrupt
.copy_in:
    mov  rsi, rbx
    mov  edx, [r12 + ext_ctx.inode_size]
    cmp  edx, EXT_INODE_COPY
    jbe  .copy
    mov  edx, EXT_INODE_COPY
.copy:
    push rdx
    mov  rdi, r15
    call memcpy
    pop  rdx
    cmp  edx, EXT_INODE_COPY
    jae  .copied
    lea  rdi, [r15 + rdx]
    mov  ecx, EXT_INODE_COPY
    sub  ecx, edx
    mov  edx, ecx
    xor  esi, esi
    call memset
.copied:
    ; i_size above the format maximum is corrupt (Linux s_maxbytes): extents
    ;   (2^32-1) blocks, indirect 12+p+p^2+p^3 blocks with p = block/4 (below
    ;   2^32 for the 1..4 KiB blocks mount admits). No clamp to the allocated
    ;   blocks: a sparse tail is legal.
    mov  rdi, r15
    call ext_inode_size
    mov  r14, rax
    mov  ecx, [r12 + ext_ctx.block_shift]
    mov  eax, 0xFFFFFFFF
    test dword [r15 + EI_FLAGS], EXT_FL_EXTENTS
    jnz  .size_max
    lea  ecx, [ecx - 2]
    mov  eax, 1
    shl  rax, cl                         ; p
    mov  rdx, rax
    imul rdx, rax                        ; p^2
    lea  rsi, [rax + rdx + 12]
    imul rdx, rax                        ; p^3
    lea  rax, [rsi + rdx]
    add  ecx, 2
.size_max:
    shl  rax, cl                         ; maximum bytes
    cmp  r14, rax
    ja   .corrupt
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

; ext_inode_size(RDI=slot) -> RAX = 64-bit i_size
ext_inode_size:
    mov  eax, [rdi + EI_SIZE_HI]
    shl  rax, 32
    mov  ecx, [rdi + EI_SIZE_LO]
    or   rax, rcx
    ret

; ext_ftype_ok(RDI=slot, EDX=dirent file_type) -> CF clear when consistent.
;   file_type 0 = unknown (accepted); 1..7 must match the inode's mode.
ext_ftype_ok:
    test edx, edx
    jz   .ok
    cmp  edx, 7
    ja   .bad
    movzx eax, word [rdi + EI_MODE]
    shr  eax, 12
    lea  rcx, [rel ext_ftype_mode]
    cmp  al, [rcx + rdx]
    jne  .bad
.ok:
    clc
    ret
.bad:
    stc
    ret

; ---------------------------------------------------------------------------
; Block mapping
; ---------------------------------------------------------------------------
; ext_map(R12=ctx, RDI=inode slot, RSI=logical block) -> RAX = physical block,
;   0 for a hole/uninitialized extent, -1 on corruption; RDX = run length (>= 1)
;   of blocks from RSI that share the answer (contiguous physical / hole).
ext_map:
    mov  rax, rsi
    shr  rax, 32
    jnz  .corrupt                        ; logical blocks are 32-bit
    test dword [rdi + EI_FLAGS], EXT_FL_EXTENTS
    jz   ext_map_indirect
    test dword [r12 + ext_ctx.incompat], EXT_IN_EXTENTS
    jz   .corrupt
    jmp  ext_map_extent
.corrupt:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
    mov  rax, -1
    ret

ext_map_extent:
    push rbx
    push rbp
    push r13
    push r14
    push r15
    mov  r13, rsi                        ; lblk
    mov  eax, [rdi + EXT_SLOT_SEED]
    mov  [r12 + ext_ctx.map_seed], eax
    lea  rbx, [rdi + EI_BLOCK]           ; node
    mov  r14d, 4                         ; capacity of the in-inode root
    mov  r15d, -1                        ; expected depth (-1 = root: any <= max)
    xor  ebp, ebp                        ; first logical block in the chosen subtree
    mov  rax, 1
    shl  rax, 32
    mov  [r12 + ext_ctx.map_bound], rax
.node:
    cmp  word [rbx], EXT_EH_MAGIC
    jne  .corrupt
    cmp  r14d, 4
    je   .tail_ok                        ; the in-inode root is covered by the inode checksum
    test dword [r12 + ext_ctx.ro_compat], EXT_RO_METADATA_CSUM
    jz   .tail_ok
    movzx eax, word [rbx + 4]
    cmp  eax, r14d
    ja   .corrupt
    imul esi, eax, 12
    add  esi, 12                         ; ext4_extent_tail follows eh_max entries
    mov  rdi, rbx
    mov  edx, [r12 + ext_ctx.map_seed]
    call ext_crc32c
    movzx ecx, word [rbx + 4]
    imul ecx, ecx, 12
    cmp  eax, [rbx + rcx + 12]
    jne  .corrupt
.tail_ok:
    movzx ecx, word [rbx + 2]            ; entries
    movzx eax, word [rbx + 4]            ; max
    cmp  eax, r14d
    ja   .corrupt
    cmp  ecx, eax
    ja   .corrupt
    movzx edx, word [rbx + 6]            ; depth
    cmp  r15d, -1
    jne  .expect
    cmp  edx, EXT_DEPTH_MAX
    ja   .corrupt
    jmp  .depth_ok
.expect:
    cmp  edx, r15d
    jne  .corrupt
.depth_ok:
    ; Validate every entry in this visited node before choosing data or a hole.
    ; A later reversed/overlapping entry must not hide behind an early return.
    call ext_map_node_validate
    jc   .corrupt
    test edx, edx
    jz   .leaf
    ; ---- index node: last entry with ei_block <= lblk ----
    test ecx, ecx
    jz   .corrupt
    lea  r8, [rbx + 12]
    xor  r9d, r9d                        ; chosen entry
    xor  r10d, r10d                      ; i
.idx:
    cmp  r10d, ecx
    jae  .idx_done
    mov  eax, [r8]
    cmp  rax, rbp
    jb   .corrupt                        ; child key precedes its parent interval
    cmp  rax, [r12 + ext_ctx.map_bound]
    jae  .corrupt                        ; child key belongs to a sibling subtree
    test r10d, r10d
    jz   .idx_first
    cmp  eax, r11d
    jbe  .corrupt                        ; strictly increasing
.idx_first:
    mov  r11d, eax
    cmp  rax, r13
    ja   .idx_bound
    mov  r9, r8
    add  r8, 12
    inc  r10d
    jmp  .idx
.idx_bound:
    cmp  rax, [r12 + ext_ctx.map_bound]
    jae  .idx_done
    mov  [r12 + ext_ctx.map_bound], rax
.idx_done:
    test r9, r9
    jz   .hole_to_bound                  ; lblk precedes the first child
    mov  ebp, [r9]                      ; selected child starts here
    mov  eax, [r9 + 4]
    movzx esi, word [r9 + 8]
    shl  rsi, 32
    or   rsi, rax
    call ext_block_ok
    jc   .corrupt
    dec  edx
    mov  r15d, edx                       ; the child's required depth
    call ext_meta
    test rax, rax
    jz   .fail
    mov  rbx, rax
    mov  eax, [r12 + ext_ctx.block_bytes]
    sub  eax, 12
    xor  edx, edx
    mov  ecx, 12
    div  ecx
    mov  r14d, eax
    jmp  .node
    ; ---- leaf: the extent containing lblk ----
.leaf:
    lea  r8, [rbx + 12]
    xor  r10d, r10d
    xor  r11d, r11d                      ; previous extent end
.ext:
    cmp  r10d, ecx
    jae  .hole_to_bound
    mov  eax, [r8]                       ; ee_block
    movzx edx, word [r8 + 4]             ; ee_len
    xor  r9d, r9d                        ; uninitialized?
    cmp  edx, EXT_UNINIT_LEN
    jbe  .len_ok
    sub  edx, EXT_UNINIT_LEN
    mov  r9d, 1
.len_ok:
    test edx, edx
    jz   .corrupt
    cmp  rax, rbp
    jb   .corrupt                        ; an extent cannot start before its parent
    cmp  rax, r11
    jb   .corrupt                        ; overlapping / out of order
    lea  r11, [rax + rdx]                ; end (<= 2^32 + 2^15)
    mov  rsi, 1
    shl  rsi, 32
    cmp  r11, rsi
    ja   .corrupt
    cmp  r11, [r12 + ext_ctx.map_bound]
    ja   .corrupt                        ; neither data nor holes may cross a sibling
    cmp  r13, rax
    jb   .hole_before
    cmp  r13, r11
    jb   .found
    add  r8, 12
    inc  r10d
    jmp  .ext
.hole_before:
    mov  rdx, rax
    sub  rdx, r13
    xor  eax, eax
    jmp  .out
.found:
    movzx esi, word [r8 + 6]
    shl  rsi, 32
    mov  ecx, [r8 + 8]
    or   rsi, rcx                        ; physical start
    call ext_block_ok
    jc   .corrupt
    lea  rcx, [rsi + rdx]
    cmp  rcx, [r12 + ext_ctx.blocks_count]
    ja   .corrupt                        ; the extent runs past the filesystem
    mov  rcx, r13
    sub  rcx, rax                        ; offset inside the extent
    sub  rdx, rcx                        ; run
    lea  rax, [rsi + rcx]
    test r9d, r9d
    jz   .out
    xor  eax, eax                        ; uninitialized: reads as zeros
    jmp  .out
.hole_to_bound:
    mov  rdx, [r12 + ext_ctx.map_bound]
    sub  rdx, r13
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
    pop  rbp
    pop  rbx
    ret

; ext_map_node_validate(RBX=node, ECX=entries, EDX=depth, RBP=parent lower,
;   R12=ctx with parent upper) -> CF on corruption. Preserves ECX/EDX and
;   callee-saved registers; no I/O, recursion or additional context state.
ext_map_node_validate:
    push rdx
    lea  r8, [rbx + 12]
    xor  r10d, r10d
    xor  r11d, r11d
    test edx, edx
    jz   .leaf
.index:
    cmp  r10d, ecx
    jae  .ok
    mov  eax, [r8]
    cmp  rax, rbp
    jb   .bad
    cmp  rax, [r12 + ext_ctx.map_bound]
    jae  .bad
    test r10d, r10d
    jz   .first_index
    cmp  rax, r11
    jbe  .bad                         ; all keys strictly increase
.first_index:
    mov  r11, rax
    movzx esi, word [r8 + 8]
    shl  rsi, 32
    mov  r9d, [r8 + 4]
    or   rsi, r9
    test rsi, rsi
    jz   .bad
    cmp  rsi, [r12 + ext_ctx.blocks_count]
    jae  .bad                        ; every child pointer is in-fs
    add  r8, 12
    inc  r10d
    jmp  .index
.leaf:
    cmp  r10d, ecx
    jae  .ok
    mov  eax, [r8]
    movzx edx, word [r8 + 4]
    cmp  edx, EXT_UNINIT_LEN
    jbe  .length
    sub  edx, EXT_UNINIT_LEN
.length:
    test edx, edx
    jz   .bad
    cmp  rax, rbp
    jb   .bad
    cmp  rax, r11
    jb   .bad                         ; all extents are disjoint and ordered
    lea  r11, [rax + rdx]
    mov  rsi, 1
    shl  rsi, 32
    cmp  r11, rsi
    ja   .bad
    cmp  r11, [r12 + ext_ctx.map_bound]
    ja   .bad                         ; full logical span inside parent
    movzx esi, word [r8 + 6]
    shl  rsi, 32
    mov  r9d, [r8 + 8]
    or   rsi, r9
    test rsi, rsi
    jz   .bad
    lea  r9, [rsi + rdx]
    cmp  r9, [r12 + ext_ctx.blocks_count]
    ja   .bad                         ; full physical span inside filesystem
    add  r8, 12
    inc  r10d
    jmp  .leaf
.ok:
    pop  rdx
    clc
    ret
.bad:
    pop  rdx
    stc
    ret

; ext_map_indirect: ext2/ext3 block map. i_block[0..11] direct, [12] single,
; [13] double, [14] triple indirect.
ext_map_indirect:
    push rbx
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  r13, rsi                        ; remaining index
    mov  r15d, [r12 + ext_ctx.block_shift]
    sub  r15d, 2                         ; log2(pointers per block)
    cmp  r13, 12
    jae  .indirect
    ; direct: run over the following direct pointers
    lea  r8, [rbx + EI_BLOCK]
    mov  ecx, 12
    jmp  .final
.indirect:
    sub  r13, 12
    xor  r14d, r14d                      ; level
.level:
    inc  r14d
    cmp  r14d, 3
    ja   .corrupt
    mov  eax, r15d
    imul eax, r14d
    mov  ecx, eax
    mov  eax, 1
    shl  rax, cl                         ; blocks under this root
    cmp  r13, rax
    jb   .have_root
    sub  r13, rax
    jmp  .level
.have_root:
    mov  esi, [rbx + EI_BLOCK + 44 + r14 * 4]   ; i_block[11 + level]
.descend:
    ; RSI = pointer covering 2^(r15*r14) blocks; r13 = index inside it
    test esi, esi
    jz   .hole_subtree
    call ext_block_ok
    jc   .corrupt
    call ext_meta
    test rax, rax
    jz   .fail
    dec  r14d
    mov  ecx, r15d
    imul ecx, r14d                       ; log2(blocks per child pointer)
    mov  rdx, r13
    shr  rdx, cl                         ; child index
    mov  rdi, 1
    shl  rdi, cl
    dec  rdi
    and  r13, rdi                        ; index inside the child
    test r14d, r14d
    jz   .leaf_block
    mov  esi, [rax + rdx * 4]
    jmp  .descend
.leaf_block:
    mov  r13, rdx                        ; index inside this last indirect block
    lea  r8, [rax]
    mov  ecx, [r12 + ext_ctx.block_bytes]
    shr  ecx, 2
    jmp  .final
.hole_subtree:
    mov  ecx, r15d
    imul ecx, r14d
    mov  rdx, 1
    shl  rdx, cl
    sub  rdx, r13                        ; rest of the empty subtree
    xor  eax, eax
    jmp  .out
.final:
    ; R8 = pointer array, ECX = its length, R13 = index: data block + contiguous run
    mov  esi, [r8 + r13 * 4]
    test esi, esi
    jnz  .data
    mov  edx, 1
.hole_run:                               ; extend over following zero pointers
    lea  rax, [r13 + rdx]
    cmp  rax, rcx
    jae  .hole_done
    cmp  dword [r8 + rax * 4], 0
    jne  .hole_done
    inc  rdx
    jmp  .hole_run
.hole_done:
    xor  eax, eax
    jmp  .out
.data:
    call ext_block_ok
    jc   .corrupt
    mov  edx, 1
.run:
    lea  rax, [r13 + rdx]
    cmp  rax, rcx
    jae  .run_done
    mov  eax, [r8 + rax * 4]
    lea  rdi, [rsi + rdx]
    cmp  rax, rdi
    jne  .run_done
    cmp  rdi, [r12 + ext_ctx.blocks_count]
    jae  .run_done
    inc  rdx
    jmp  .run
.run_done:
    mov  rax, rsi
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

; ---------------------------------------------------------------------------
; Directories and paths
; ---------------------------------------------------------------------------
; ext_dir_walk(R12=ctx, EDI=mode) over ctx.dino -> RAX 1 = found / listing
;   truncated, 0 = absent / complete listing, -1 = corrupt/IO. Always qualifies
;   the entire bounded stream before success; only the requested name is checked
;   for duplicate live entries (LIST makes no global uniqueness promise).
;   LOOKUP compares ext_comp_ptr/len; LIST appends to ext_list_*.
ext_dir_walk:
    push rbx
    push r13
    push r14
    push r15
    sub  rsp, 8
    mov  dword [rsp], 0                 ; LIST capacity reached, validation continues
    mov  dword [r12 + ext_ctx.found_ino], 0
    mov  dword [r12 + ext_ctx.found_ftype], 0
    mov  [rel ext_walk_mode], edi
    test dword [r12 + ext_ctx.dino + EI_FLAGS], EXT_FL_REFUSED
    jnz  .unsupported                    ; encrypted / inline / compressed directory
    lea  rdi, [r12 + ext_ctx.dino]
    call ext_inode_size
    mov  ecx, [r12 + ext_ctx.block_bytes]
    dec  ecx
    test rax, rcx
    jnz  .corrupt                        ; directories are whole blocks
    cmp  rax, EXT_DIR_MAX_BYTES
    ja   .corrupt
    mov  ecx, [r12 + ext_ctx.block_shift]
    shr  rax, cl
    mov  r13, rax                        ; blocks
    xor  r14d, r14d                      ; logical block
.block:
    cmp  r14, r13
    jae  .end
    lea  rdi, [r12 + ext_ctx.dino]
    mov  rsi, r14
    call ext_map
    test rax, rax
    js   .fail
    jz   .corrupt                        ; a directory hole is corruption
    mov  rsi, rax
    mov  edx, 1
    mov  rcx, [r12 + ext_ctx.dir_buf]
    call ext_read_blocks
    test rax, rax
    jnz  .fail
    mov  rsi, r14                     ; distinguish htree root from interior node
    call ext_dir_tail_ok
    jc   .corrupt
    mov  eax, [r12 + ext_ctx.block_bytes]
    mov  [rsp + 4], eax                 ; parse limit (dx slack stays in its record)
    test dword [r12 + ext_ctx.ro_compat], EXT_RO_METADATA_CSUM
    jz   .entries
    mov  rdi, [r12 + ext_ctx.dir_buf]
    lea  rdi, [rdi + rax - 12]
    cmp  dword [rdi], 0
    jne  .entries
    cmp  dword [rdi + 4], 0xDE00000C
    jne  .entries
    sub  dword [rsp + 4], 12            ; a leaf record may not swallow its CRC tail
.entries:
    xor  ebx, ebx                        ; offset in block
.entry:
    cmp  ebx, [rsp + 4]
    jae  .next_block
    lea  eax, [ebx + 8]
    cmp  eax, [rsp + 4]
    ja   .corrupt
    mov  r15, [r12 + ext_ctx.dir_buf]
    add  r15, rbx
    movzx ecx, word [r15 + 4]            ; rec_len
    cmp  ecx, 8
    jb   .corrupt
    test ecx, 3
    jnz  .corrupt
    lea  eax, [ebx + ecx]
    cmp  eax, [rsp + 4]
    ja   .corrupt
    movzx edx, byte [r15 + 6]            ; name_len
    lea  eax, [edx + 8]
    cmp  eax, ecx
    ja   .corrupt
    mov  eax, [r15]                      ; inode
    test eax, eax
    jz   .skip
    test edx, edx
    jz   .corrupt
    cmp  eax, [r12 + ext_ctx.inodes_count]
    ja   .corrupt
    ; Validate every live name, including entries beyond output capacity and
    ; names unrelated to a lookup. Deleted records and hidden dx slack stay opaque.
    cmp  byte [r15 + 7], 7
    ja   .corrupt
    xor  r8d, r8d
.name_byte:
    mov  al, [r15 + 8 + r8]
    test al, al
    jz   .corrupt
    cmp  al, '/'
    je   .corrupt
    inc  r8d
    cmp  r8d, edx
    jb   .name_byte
.name_done:
    push rcx
    cmp  dword [rel ext_walk_mode], EXT_WALK_LIST
    je   .list
    cmp  edx, [rel ext_comp_len]
    jne  .no_match
    lea  rdi, [r15 + 8]
    mov  rsi, [rel ext_comp_ptr]
    call memcmp
    test rax, rax
    jnz  .no_match
    pop  rcx
    cmp  dword [r12 + ext_ctx.found_ino], 0
    jne  .corrupt                       ; ambiguous even if both names use one inode
    mov  eax, [r15]
    mov  [r12 + ext_ctx.found_ino], eax
    movzx eax, byte [r15 + 7]
    mov  [r12 + ext_ctx.found_ftype], eax
    jmp  .skip                          ; provisional until the entire stream passes
.list:
    cmp  dword [rsp + 8], 0             ; saved rec_len is above our local flag
    jne  .list_full
    mov  rdi, r15
    call ext_list_emit
    pop  rcx
    test rax, rax
    js   .fail
    jz   .skip
    mov  dword [rsp], 1
    jmp  .skip
.list_full:
    pop  rcx
    jmp  .skip
.no_match:
    pop  rcx
.skip:
    add  ebx, ecx
    jmp  .entry
.next_block:
    inc  r14
    jmp  .block
.end:
    mov  eax, [rsp]
    cmp  dword [rel ext_walk_mode], EXT_WALK_LIST
    je   .out
    xor  eax, eax
    cmp  dword [r12 + ext_ctx.found_ino], 0
    setne al
    jmp  .out
.unsupported:
    mov  dword [rel ext4_disk_last_error], EXT_E_UNSUPPORTED
    jmp  .fail
.corrupt:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
.fail:
    mov  dword [r12 + ext_ctx.found_ino], 0
    mov  dword [r12 + ext_ctx.found_ftype], 0
    mov  rax, -1
.out:
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

; ext_dir_tail_ok(R12=ctx, RSI=logical directory block; dir_buf holds it)
;   -> CF on a missing/invalid metadata_csum leaf or htree checksum. An indexed
;   inode alone never exempts a leaf. Root/node forms must have their real
;   hidden-dirent layout, bounded dx count/limit, and matching dx_tail CRC.
ext_dir_tail_ok:
    test dword [r12 + ext_ctx.ro_compat], EXT_RO_METADATA_CSUM
    jz   .plain_ok
    push rbx
    push r13
    push r14
    mov  r14, rsi
    mov  rbx, [r12 + ext_ctx.dir_buf]
    mov  esi, [r12 + ext_ctx.block_bytes]
    lea  r8, [rbx + rsi - 12]
    cmp  dword [r8], 0
    jne  .index_form                  ; a leaf must carry the exact tail
    cmp  dword [r8 + 4], 0xDE00000C      ; rec_len 12, name_len 0, file_type 0xDE
    jne  .index_form
    mov  rdi, rbx
    sub  esi, 12
    mov  edx, [r12 + ext_ctx.dino + EXT_SLOT_SEED]
    call ext_crc32c
    mov  esi, [r12 + ext_ctx.block_bytes]
    cmp  eax, [rbx + rsi - 4]
    jne  .bad                         ; leaf CRC must match
    jmp  .good
.index_form:
    test dword [r12 + ext_ctx.dino + EI_FLAGS], 0x1000 ; EXT4_INDEX_FL
    jz   .bad
    test r14, r14
    jnz  .node
    ; dx_root: '.' then '..', with index information hidden by '..'.
    mov  eax, [r12 + ext_ctx.dino + EXT_SLOT_INO]
    test eax, eax
    jz   .bad
    cmp  [rbx], eax
    jne  .bad
    cmp  word [rbx + 4], 12
    jne  .bad
    cmp  word [rbx + 6], 0x0201
    jne  .bad
    cmp  byte [rbx + 8], '.'
    jne  .bad
    mov  eax, [rbx + 12]
    test eax, eax
    jz   .bad
    cmp  eax, [r12 + ext_ctx.inodes_count]
    ja   .bad
    mov  eax, [r12 + ext_ctx.block_bytes]
    sub  eax, 12
    cmp  [rbx + 16], ax
    jne  .bad
    cmp  word [rbx + 18], 0x0202
    jne  .bad
    cmp  word [rbx + 20], '..'
    jne  .bad
    cmp  dword [rbx + 24], 0
    jne  .bad
    cmp  byte [rbx + 29], 8            ; supported dx_root_info length
    jne  .bad
    mov  ecx, 32
    jmp  .dx_limits
.node:
    ; dx_node: a nameless unused record hides the entire index block.
    cmp  dword [rbx], 0
    jne  .bad
    mov  eax, [r12 + ext_ctx.block_bytes]
    cmp  [rbx + 4], ax
    jne  .bad
    cmp  word [rbx + 6], 0
    jne  .bad
    mov  ecx, 8
.dx_limits:
    mov  eax, [r12 + ext_ctx.block_bytes]
    sub  eax, 8
    sub  eax, ecx
    shr  eax, 3
    movzx esi, word [rbx + rcx]        ; limit, including the first entry
    test esi, esi
    jz   .bad
    cmp  esi, eax
    ja   .bad                         ; reserve all eight dx_tail bytes
    movzx edx, word [rbx + rcx + 2]    ; count
    test edx, edx
    jz   .bad
    cmp  edx, esi
    ja   .bad
    lea  r13, [rbx + rsi * 8]
    add  r13, rcx                     ; dx_tail follows limit entries
    lea  esi, [rcx + rdx * 8]         ; only used dx entries are hashed
    mov  rdi, rbx
    mov  edx, [r12 + ext_ctx.dino + EXT_SLOT_SEED]
    call ext_crc32c
    sub  rsp, 8
    mov  qword [rsp], 0                ; checksum is zero for calculation
    mov  edx, eax
    mov  rdi, r13
    mov  esi, 4                       ; dt_reserved is covered, even if nonzero
    call ext_crc32c
    mov  edx, eax
    lea  rdi, [rsp]
    mov  esi, 4
    call ext_crc32c
    add  rsp, 8
    cmp  eax, [r13 + 4]
    jne  .bad                         ; dx CRC must match
.good:
    pop  r14
    pop  r13
    pop  rbx
.plain_ok:
    clc
    ret
.bad:
    pop  r14
    pop  r13
    pop  rbx
    stc
    ret

; ext_list_emit(R12=ctx, RDI=raw dirent) -> RAX 0 = continue, 1 = caller's
;   capacity reached (truncated), -1 = corrupt. Skips "." and "..".
ext_list_emit:
    push rbx
    push r13
    push r14
    push r15
    mov  rbx, rdi
    movzx r13d, byte [rbx + 6]           ; name length
    cmp  byte [rbx + 8], '.'
    jne  .real
    cmp  r13d, 1
    je   .skip
    cmp  r13d, 2
    jne  .real
    cmp  byte [rbx + 9], '.'
    je   .skip
.real:
    ; names never contain NUL or '/'
    xor  ecx, ecx
.scan:
    cmp  ecx, r13d
    jae  .scanned
    mov  al, [rbx + 8 + rcx]
    test al, al
    jz   .corrupt
    cmp  al, '/'
    je   .corrupt
    inc  ecx
    jmp  .scan
.scanned:
    cmp  dword [rel vfs_list_skip], 0    ; smart copy D: FSCHECK pages a directory past its first entries
    je   .listed
    dec  dword [rel vfs_list_skip]
    jmp  .skip
.listed:
    mov  r15, [rel ext_list_result]
    mov  eax, [r15 + fs_list_result.count]
    cmp  eax, [rel ext_list_cap]
    jb   .room
    mov  dword [r15 + fs_list_result.truncated], 1
    mov  eax, 1
    jmp  .out
.room:
    imul rax, rax, fs_dirent_size
    mov  r14, [rel ext_list_ptr]
    add  r14, rax                        ; -> fs_dirent
    mov  esi, [rbx]
    lea  rdi, [r12 + ext_ctx.inode]
    call ext_read_inode
    test rax, rax
    jnz  .fail
    lea  rdi, [r12 + ext_ctx.inode]
    movzx edx, byte [rbx + 7]
    call ext_ftype_ok
    jc   .corrupt
    mov  rdi, r14
    xor  esi, esi
    mov  edx, fs_dirent_size
    call memset
    movzx eax, word [r12 + ext_ctx.inode + EI_MODE]
    and  eax, EXT_S_IFMT
    cmp  eax, EXT_S_IFDIR
    je   .dir
    cmp  eax, EXT_S_IFREG
    je   .reg
    mov  dword [r14 + fs_dirent.flags], EXT_DIRENT_OTHER
    jmp  .name
.dir:
    mov  dword [r14 + fs_dirent.flags], FS_DIRENT_DIR
    jmp  .name
.reg:
    lea  rdi, [r12 + ext_ctx.inode]
    call ext_inode_size
    mov  [r14 + fs_dirent.size], rax
.name:
    ; inline copy (at most 12 bytes, NUL-terminated by the memset)
    mov  edx, r13d
    cmp  edx, 12
    jbe  .inline_len
    mov  edx, 12
.inline_len:
    lea  rdi, [r14 + fs_dirent.name]
    lea  rsi, [rbx + 8]
    call memcpy
    cmp  r13d, 12
    jbe  .counted
    mov  eax, [rel ext_list_names_used]
    lea  edx, [rax + r13 + 1]
    cmp  edx, EXT_LIST_NAMES_CAP
    ja   .omitted
    mov  [rel ext_list_names_used], edx
    lea  rdi, [rel ext_list_names]
    add  rdi, rax
    push rdi
    lea  rsi, [rbx + 8]
    mov  edx, r13d
    call memcpy
    pop  rsi
    mov  byte [rsi + r13], 0
    mov  rdi, r14
    call vfs_dirent_set_long_name
    jmp  .counted
.omitted:
    or   dword [r14 + fs_dirent.flags], FS_DIRENT_LONG_OMITTED
    mov  dword [r15 + fs_list_result.names_short], 1
.counted:
    inc  dword [r15 + fs_list_result.count]
.skip:
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

; ext_resolve(R12=ctx, RSI=path bytes, EDX=len) -> RAX 0/-1; the leaf inode in
;   ctx.inode. "" and "/" are the root. Byte-exact components; "." / ".."
;   refused; nothing is followed through a non-directory (symlinks included).
ext_resolve:
    push rbx
    push r13
    push r14
    push r15
    cmp  edx, EXT_PATH_MAX
    ja   .badpath
    mov  rbx, rsi                        ; cursor
    mov  r13, rsi
    add  r13, rdx                        ; end
    mov  esi, EXT_ROOT_INO
    lea  rdi, [r12 + ext_ctx.inode]
    call ext_read_inode
    test rax, rax
    jnz  .fail
.comp:
    cmp  rbx, r13
    jae  .ok
    cmp  byte [rbx], '/'
    jne  .comp_start
    inc  rbx
    jmp  .comp
.comp_start:
    movzx eax, word [r12 + ext_ctx.inode + EI_MODE]
    and  eax, EXT_S_IFMT
    cmp  eax, EXT_S_IFDIR
    jne  .notdir
    xor  ecx, ecx
.clen:
    lea  rax, [rbx + rcx]
    cmp  rax, r13
    jae  .cdone
    mov  al, [rbx + rcx]
    cmp  al, '/'
    je   .cdone
    test al, al
    jz   .badpath
    inc  ecx
    cmp  ecx, EXT_NAME_MAX
    ja   .badpath
    jmp  .clen
.cdone:
    cmp  byte [rbx], '.'
    jne  .named
    cmp  ecx, 1
    je   .badpath
    cmp  ecx, 2
    jne  .named
    cmp  byte [rbx + 1], '.'
    je   .badpath
.named:
    mov  r14d, ecx
    mov  [rel ext_comp_ptr], rbx
    mov  [rel ext_comp_len], ecx
    lea  rdi, [r12 + ext_ctx.dino]
    lea  rsi, [r12 + ext_ctx.inode]
    mov  edx, EXT_SLOT
    call memcpy
    mov  edi, EXT_WALK_LOOKUP
    call ext_dir_walk
    test rax, rax
    js   .fail
    jz   .notfound
    mov  esi, [r12 + ext_ctx.found_ino]
    lea  rdi, [r12 + ext_ctx.inode]
    call ext_read_inode
    test rax, rax
    jnz  .fail
    lea  rdi, [r12 + ext_ctx.inode]
    mov  edx, [r12 + ext_ctx.found_ftype]
    call ext_ftype_ok
    jc   .corrupt
    add  rbx, r14
    jmp  .comp
.ok:
    xor  eax, eax
    jmp  .out
.notdir:
    mov  dword [rel ext4_disk_last_error], EXT_E_NOTDIR
    jmp  .fail
.notfound:
    mov  dword [rel ext4_disk_last_error], EXT_E_NOTFOUND
    jmp  .fail
.badpath:
    mov  dword [rel ext4_disk_last_error], EXT_E_BADPATH
    jmp  .fail
.corrupt:
    mov  dword [rel ext4_disk_last_error], EXT_E_CORRUPT
.fail:
    ; A failed component never leaves a reusable inode or provisional match.
    lea  rdi, [r12 + ext_ctx.inode]
    xor  esi, esi
    mov  edx, EXT_SLOT
    call memset
    mov  dword [r12 + ext_ctx.found_ino], 0
    mov  dword [r12 + ext_ctx.found_ftype], 0
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

; ext_file_read(R12=ctx, RSI=off, RDX=buf, RCX=len) over ctx.inode
;   -> RAX = len / -1. off+len must not overflow nor pass i_size.
ext_file_read:
    push rbx
    push r13
    push r14
    push r15
    mov  r13, rsi                        ; offset
    mov  r14, rdx                        ; destination
    mov  r15, rcx                        ; remaining
    xor  ebx, ebx                        ; done
    mov  eax, [r12 + ext_ctx.inode + EI_FLAGS]
    test eax, EXT_FL_REFUSED
    jnz  .unsupported
    lea  rdi, [r12 + ext_ctx.inode]
    call ext_inode_size
    mov  rdx, r13
    add  rdx, r15
    jc   .range
    cmp  rdx, rax
    ja   .range
.piece:
    test r15, r15
    jz   .done
    mov  rsi, r13
    mov  ecx, [r12 + ext_ctx.block_shift]
    shr  rsi, cl
    lea  rdi, [r12 + ext_ctx.inode]
    call ext_map
    test rax, rax
    js   .fail
    mov  r8d, [r12 + ext_ctx.block_bytes]
    dec  r8d
    and  r8, r13                         ; offset inside the block
    test rax, rax
    jnz  .data
    ; hole: zeros up to the end of the run
    mov  ecx, [r12 + ext_ctx.block_shift]
    shl  rdx, cl
    sub  rdx, r8                         ; bytes left in the hole run
    cmp  rdx, r15
    jbe  .zero
    mov  rdx, r15
.zero:
    push rdx
    mov  rdi, r14
    xor  esi, esi
    call memset
    pop  rdx
    jmp  .advance
.data:
    test r8, r8
    jnz  .bounce
    mov  ecx, [r12 + ext_ctx.block_bytes]
    cmp  r15, rcx
    jb   .bounce
    ; whole blocks straight into the caller's buffer
    mov  r9, r15
    mov  ecx, [r12 + ext_ctx.block_shift]
    shr  r9, cl
    cmp  rdx, r9
    jbe  .run_ok
    mov  rdx, r9
.run_ok:
    cmp  rdx, EXT_DIRECT_BLOCKS
    jbe  .direct
    mov  edx, EXT_DIRECT_BLOCKS
.direct:
    push rdx
    mov  rsi, rax
    mov  rcx, r14
    call ext_read_blocks
    pop  rdx
    test rax, rax
    jnz  .fail
    mov  ecx, [r12 + ext_ctx.block_shift]
    shl  rdx, cl
    jmp  .advance
.bounce:
    push r8
    mov  rsi, rax
    mov  edx, 1
    mov  rcx, [r12 + ext_ctx.dir_buf]
    call ext_read_blocks
    pop  r8
    test rax, rax
    jnz  .fail
    mov  edx, [r12 + ext_ctx.block_bytes]
    sub  rdx, r8
    cmp  rdx, r15
    jbe  .bounce_copy
    mov  rdx, r15
.bounce_copy:
    push rdx
    mov  rdi, r14
    mov  rsi, [r12 + ext_ctx.dir_buf]
    add  rsi, r8
    call memcpy
    pop  rdx
.advance:
    add  r13, rdx
    add  r14, rdx
    add  rbx, rdx
    sub  r15, rdx
    jmp  .piece
.done:
    mov  rax, rbx
    jmp  .out
.unsupported:
    mov  dword [rel ext4_disk_last_error], EXT_E_UNSUPPORTED
    jmp  .fail
.range:
    mov  dword [rel ext4_disk_last_error], EXT_E_RANGE
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; fs_ops
; ---------------------------------------------------------------------------
ext_build_ops:
    lea  rdi, [rel ext_ops]
    lea  rax, [rel str_ext_backend]
    mov  [rdi + fs_ops.name], rax
    lea  rax, [rel ext_op_mount]
    mov  [rdi + fs_ops.mount], rax
    lea  rax, [rel ext_op_readfile]
    mov  [rdi + fs_ops.readfile], rax
    lea  rax, [rel ext_op_stat]
    mov  [rdi + fs_ops.stat], rax
    lea  rax, [rel ext_op_read_at]
    mov  [rdi + fs_ops.read_at], rax
    lea  rax, [rel ext_op_info]
    mov  [rdi + fs_ops.info], rax
    lea  rax, [rel ext_op_list_root]
    mov  [rdi + fs_ops.list_root], rax
    lea  rax, [rel ext_op_stat_path]
    mov  [rdi + fs_ops.stat_path], rax
    lea  rax, [rel ext_op_replace_meta]
    mov  [rdi + fs_ops.replace_meta], rax
    lea  rax, [rel ext_op_read_at_path]
    mov  [rdi + fs_ops.read_at_path], rax
    lea  rax, [rel ext_op_list_dir]
    mov  [rdi + fs_ops.list_dir], rax
    ; RCQ-20 E2a (fs/ext4_write): armed-volume content writes. writefile/delete/
    ; write_at/update/rename/copy stay 0 and mutate_path accepts only FS_MUT_UPDATE.
    lea  rax, [rel ext_op_write_at_path]
    mov  [rdi + fs_ops.write_at_path], rax
    lea  rax, [rel ext_op_mutate_path]
    mov  [rdi + fs_ops.mutate_path], rax
    lea  rax, [rel ext_op_mutate_armed]   ; command_fs admits an ext mount only while armed
    mov  [rdi + fs_ops.mutate_armed], rax
    lea  rax, [rel ext_op_copy]           ; RCQ-20 copy job (fs/ext4_copy)
    mov  [rdi + fs_ops.copy], rax
    lea  rax, [rel ext_op_copy_between]
    mov  [rdi + fs_ops.copy_between], rax
    ret

; Pure read identity; unlike FSINFO this never walks group descriptors.
ext4_disk_source_device:             ; RDI=mount -> dev / 0
    lea  rax, [rel ext_ops]
    cmp  [rdi + fsmount.ops], rax
    jne  .bad
    mov  rax, [rdi + fsmount.priv]
    test rax, rax
    jz   .bad
    cmp  dword [rax + ext_ctx.mounted], 1
    jne  .bad
    mov  rax, [rax + ext_ctx.dev]
    ret
.bad:
    xor  eax, eax
    ret

; mount(RDI=fsmount) -> 0 when the private context finished mounting
ext_op_mount:
    mov  rax, [rdi + fsmount.priv]
    test rax, rax
    jz   .fail
    cmp  dword [rax + ext_ctx.mounted], 1
    jne  .fail
    xor  eax, eax
    ret
.fail:
    mov  rax, -1
    ret

; ext_op_enter: RDI=fsmount -> R12=ctx (caller saved r12), CF set when unmounted.
%macro EXT_ENTER 0
    mov  dword [rel ext4_disk_last_error], EXT_E_NONE
    mov  r12, [rdi + fsmount.priv]
    test r12, r12
    jz   .unmounted
    cmp  dword [r12 + ext_ctx.mounted], 1
    jne  .unmounted
%endmacro

; stat_path(self, RSI=path, EDX=len, RCX=fs_stat*) -> 0/-1
ext_op_stat_path:
    push rbx
    push r12
    mov  rbx, rcx
    EXT_ENTER
    test rbx, rbx
    jz   .unmounted
    call ext_resolve
    test rax, rax
    jnz  .fail
    mov  qword [rbx + fs_stat.size], 0
    mov  dword [rbx + fs_stat.flags], FS_STAT_READONLY
    cmp  dword [r12 + ext_ctx.armed], 1
    jne  .ro
    mov  dword [rbx + fs_stat.flags], 0  ; armed for E2a content writes
.ro:
    movzx eax, word [r12 + ext_ctx.inode + EI_MODE]
    and  eax, EXT_S_IFMT
    mov  ecx, 1
    cmp  eax, EXT_S_IFDIR
    je   .kind
    mov  ecx, 2
    cmp  eax, EXT_S_IFREG
    jne  .kind
    lea  rdi, [r12 + ext_ctx.inode]
    call ext_inode_size
    mov  [rbx + fs_stat.size], rax
    xor  ecx, ecx
.kind:
    mov  [rbx + fs_stat.reserved], ecx   ; bit 0 = directory, 2 = other (not readable)
    xor  eax, eax
    jmp  .out
.unmounted:
.fail:
    mov  rax, -1
.out:
    pop  r12
    pop  rbx
    ret

; replace_meta: readonly resolve + inode facts, available unarmed. No ext_cp_* state or writer entry.
ext_op_replace_meta:
    push rbx
    push r12
    mov  rbx, rcx
    EXT_ENTER
    test rbx, rbx
    jz   .unmounted
    call ext_resolve
    test rax, rax
    jnz  .fail
    mov  qword [rbx + fs_replace_meta.seconds], 0
    mov  dword [rbx + fs_replace_meta.ns], 0
    mov  dword [rbx + fs_replace_meta.flags], 0
    mov  eax, [r12 + ext_ctx.inode + EXT_SLOT_INO]
    mov  [rbx + fs_replace_meta.node], rax
    movzx eax, word [r12 + ext_ctx.inode + EI_MODE]
    and  eax, EXT_S_IFMT
    cmp  eax, EXT_S_IFREG
    jne  .ok
    mov  dword [rbx + fs_replace_meta.flags], FS_RMETA_REGULAR
    test dword [r12 + ext_ctx.inode + EI_FLAGS], EXT_W_FL_REFUSED
    jnz  .time
    or   dword [rbx + fs_replace_meta.flags], FS_RMETA_ELIGIBLE
.time:
    movsxd rax, dword [r12 + ext_ctx.inode + EI_MTIME]
    xor  edx, edx
    cmp  dword [r12 + ext_ctx.inode_size], 128
    jbe  .stamp
    movzx ecx, word [r12 + ext_ctx.inode + EI_EXTRA_ISIZE]
    cmp  ecx, EI_MTIME_EXTRA - 0x80 + 4
    jb   .stamp
    mov  edx, [r12 + ext_ctx.inode + EI_MTIME_EXTRA]
    mov  ecx, edx
    and  ecx, 3
    shl  rcx, 32
    add  rax, rcx
    shr  edx, 2
.stamp:
    mov  [rbx + fs_replace_meta.seconds], rax
    mov  [rbx + fs_replace_meta.ns], edx
.ok:
    xor  eax, eax
    jmp  .out
.unmounted:
.fail:
    mov  rax, -1
.out:
    pop  r12
    pop  rbx
    ret

; read_at_path(self, RSI=path, EDX=len, RCX=off, R8=buf, R9=len) -> len/-1
ext_op_read_at_path:
    push rbx
    push r12
    push r13
    push r14
    mov  rbx, rcx
    mov  r13, r8
    mov  r14, r9
    EXT_ENTER
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
.refuse:
    mov  [rel ext4_disk_last_error], ecx
    jmp  .fail
.regular:
    mov  rsi, rbx
    mov  rdx, r13
    mov  rcx, r14
    call ext_file_read
    jmp  .out
.unmounted:
.fail:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; list_dir(self, RSI=path, EDX=len, RCX=fs_dirent[], R8D=cap, R9=fs_list_result*) -> 0/-1
ext_op_list_dir:
    push rbx
    push r12
    push r13
    push r14
    mov  rbx, r9
    mov  r13, rcx
    mov  r14d, r8d
    EXT_ENTER
    test rbx, rbx
    jz   .unmounted
    mov  dword [rbx + fs_list_result.count], 0
    mov  dword [rbx + fs_list_result.truncated], 0
    mov  dword [rbx + fs_list_result.names_short], 0
    call ext_resolve
    test rax, rax
    jnz  .fail
    movzx eax, word [r12 + ext_ctx.inode + EI_MODE]
    and  eax, EXT_S_IFMT
    cmp  eax, EXT_S_IFDIR
    je   .dir
    mov  dword [rel ext4_disk_last_error], EXT_E_NOTDIR
    jmp  .fail
.dir:
    mov  [rel ext_list_ptr], r13
    mov  [rel ext_list_cap], r14d
    mov  [rel ext_list_result], rbx
    mov  dword [rel ext_list_names_used], 0
    lea  rdi, [r12 + ext_ctx.dino]
    lea  rsi, [r12 + ext_ctx.inode]
    mov  edx, EXT_SLOT
    call memcpy
    mov  edi, EXT_WALK_LIST
    call ext_dir_walk
    test rax, rax
    js   .fail
    xor  eax, eax
    jmp  .out
.unmounted:
.fail:
    test rbx, rbx
    jz   .no_result
    mov  dword [rbx + fs_list_result.count], 0
    mov  dword [rbx + fs_list_result.truncated], 0
    mov  dword [rbx + fs_list_result.names_short], 0
    mov  dword [rel ext_list_names_used], 0
.no_result:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; list_root(self, RSI=fs_dirent[], EDX=cap, RCX=fs_list_result*) -> 0/-1
ext_op_list_root:
    mov  r9, rcx
    mov  r8d, edx
    mov  rcx, rsi
    lea  rsi, [rel str_ext_root]
    mov  edx, 1
    jmp  ext_op_list_dir

; ext_name11_path(RSI=name11) -> RSI = "/BASE.EXT" in ext_n11_path, EDX = len.
;   Exact bytes (ext names are case-sensitive), trailing spaces trimmed.
;   Clobbers RAX, RCX, RDX, RDI, R10 only (callers keep R8/R9 live).
ext_name11_path:
    lea  rdi, [rel ext_n11_path]
    mov  byte [rdi], '/'
    mov  edx, 1
    mov  ecx, 8
.base_end:
    test ecx, ecx
    jz   .base
    cmp  byte [rsi + rcx - 1], ' '
    jne  .base
    dec  ecx
    jmp  .base_end
.base:
    xor  eax, eax
.base_copy:
    cmp  eax, ecx
    jae  .ext
    mov  r10b, [rsi + rax]
    mov  [rdi + rdx], r10b
    inc  edx
    inc  eax
    jmp  .base_copy
.ext:
    mov  ecx, 3
.ext_end:
    test ecx, ecx
    jz   .done
    cmp  byte [rsi + 8 + rcx - 1], ' '
    jne  .dot
    dec  ecx
    jmp  .ext_end
.dot:
    mov  byte [rdi + rdx], '.'
    inc  edx
    xor  eax, eax
.ext_copy:
    cmp  eax, ecx
    jae  .done
    mov  r10b, [rsi + 8 + rax]
    mov  [rdi + rdx], r10b
    inc  edx
    inc  eax
    jmp  .ext_copy
.done:
    mov  rsi, rdi
    ret

; stat(self, RSI=name11, RDX=fs_stat*) -> 0/-1
ext_op_stat:
    test rsi, rsi
    jz   .fail
    push rdi
    push rdx                             ; fs_stat*
    call ext_name11_path
    pop  rcx
    pop  rdi
    jmp  ext_op_stat_path
.fail:
    mov  rax, -1
    ret

; read_at(self, RSI=name11, RDX=off, RCX=buf, R8=len) -> len/-1
ext_op_read_at:
    test rsi, rsi
    jz   .fail
    mov  r9, r8                          ; len
    mov  r8, rcx                         ; buf
    push rdi
    push rdx                             ; offset
    call ext_name11_path                 ; keeps r8/r9
    pop  rcx
    pop  rdi
    jmp  ext_op_read_at_path
.fail:
    mov  rax, -1
    ret

; readfile(self, RSI=name11, RDX=buf, RCX=cap) -> len/-1 (the whole file must fit)
ext_op_readfile:
    push rbx
    push r12
    push r13
    push r14
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rdx
    mov  r14, rcx
    lea  rdx, [rel ext_stat_tmp]
    call ext_op_stat
    test rax, rax
    jnz  .fail
    test dword [rel ext_stat_tmp + fs_stat.reserved], 3
    jnz  .fail
    mov  r8, [rel ext_stat_tmp + fs_stat.size]
    cmp  r8, r14
    ja   .fail
    mov  rdi, rbx
    mov  rsi, r12
    xor  edx, edx
    mov  rcx, r13
    call ext_op_read_at
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; info(self, RSI=fs_info*) -> 0/-1
ext_op_info:
    push r12
    mov  rdx, rsi
    EXT_ENTER
    test rdx, rdx
    jz   .unmounted
    mov  eax, [r12 + ext_ctx.kind]
    lea  rcx, [rel str_ext_kind_names]
    lea  rax, [rcx + rax * 8 - 16]       ; "ext2"/"ext3"/"ext4" at 8-byte stride
    mov  [rdx + fs_info.backend], rax
    mov  rax, [r12 + ext_ctx.dev]
    mov  [rdx + fs_info.device], rax
    mov  qword [rdx + fs_info.part_type], 0x83
    mov  eax, [r12 + ext_ctx.volume_id]
    mov  [rdx + fs_info.volume_id], eax
    mov  eax, [r12 + ext_ctx.block_bytes]
    mov  [rdx + fs_info.cluster_bytes], eax
    mov  rax, [r12 + ext_ctx.blocks_count]
    mov  ecx, [r12 + ext_ctx.spb_shift]
    shl  rax, cl
    mov  [rdx + fs_info.total_sectors], rax
    mov  rax, [r12 + ext_ctx.part_lba]
    mov  [rdx + fs_info.part_start], rax
    mov  rax, [r12 + ext_ctx.part_sectors]
    mov  [rdx + fs_info.part_sectors], rax
    mov  eax, [r12 + ext_ctx.scheme]
    mov  [rdx + fs_info.scheme], eax
    mov  dword [rdx + fs_info.part_count], 1
    ; smart copy D: free blocks, the sum of the group descriptors' counts (each checksum-verified under
    ; metadata_csum); a descriptor that does not read leaves the count unknown (-1)
    mov  qword [rdx + fs_info.free_clusters], -1
    push rdx
    xor  r8d, r8d
    xor  r9d, r9d
.free_group:
    cmp  r9d, [r12 + ext_ctx.group_count]
    jae  .free_counted
    mov  esi, r9d
    push r8
    push r9
    call ext_gd_read
    pop  r9
    pop  r8
    test rax, rax
    jz   .free_unknown
    movzx ecx, word [rax + EXT_GD_FREE_LO]
    cmp  dword [r12 + ext_ctx.desc_size], 64
    jb   .free_lo
    movzx edx, word [rax + EXT_GD_FREE_HI]
    shl  edx, 16
    or   ecx, edx
.free_lo:
    add  r8, rcx
    inc  r9d
    jmp  .free_group
.free_counted:
    pop  rdx
    mov  [rdx + fs_info.free_clusters], r8
    jmp  .info_done
.free_unknown:
    pop  rdx
.info_done:
    xor  eax, eax
    pop  r12
    ret
.unmounted:
    mov  rax, -1
    pop  r12
    ret

; ---------------------------------------------------------------------------
; Markers
; ---------------------------------------------------------------------------
; ext_emit_mounted(R12=ctx)
ext_emit_mounted:
    lea  rdi, [rel str_ext_mounted]
    call serial_string
    mov  rdi, [r12 + ext_ctx.name]
    call serial_string
    lea  rdi, [rel str_ext_m_kind]
    call serial_string
    mov  eax, [r12 + ext_ctx.kind]
    lea  rdi, [rel str_ext_kind_names]
    lea  rdi, [rdi + rax * 8 - 16]
    call serial_string
    lea  rdi, [rel str_ext_m_dev]
    call serial_string
    mov  rdi, [r12 + ext_ctx.dev]
    call ext_emit_dev_name
    lea  rdi, [rel str_ext_m_lba]
    call serial_string
    mov  rdi, [r12 + ext_ctx.part_lba]
    call serial_hex64
    lea  rdi, [rel str_ext_m_blocks]
    call serial_string
    mov  rdi, [r12 + ext_ctx.blocks_count]
    call serial_hex64
    lea  rdi, [rel str_ext_m_bs]
    call serial_string
    mov  edi, [r12 + ext_ctx.block_bytes]
    call serial_hex64
    lea  rdi, [rel str_ext_m_incompat]
    call serial_string
    mov  edi, [r12 + ext_ctx.incompat]
    call serial_hex64
    lea  rdi, [rel str_ext_m_ro]
    call serial_string
    lea  rdi, [rel str_ext_crlf]
    call serial_string
    ret

; ext_emit_refused(RDI=dev, RSI=part lba, EDX=reason)
ext_emit_refused:
    push rbx
    push r13
    push r14
    mov  rbx, rdi
    mov  r13, rsi
    mov  r14d, edx
    mov  ecx, [rel ext_sb_buf + ESB_INCOMPAT]
    call ext4_refusal_record
    lea  rdi, [rel str_ext_refused]
    call serial_string
    mov  eax, r14d
    cmp  eax, EXT_R_NOMOUNT
    jbe  .named
    xor  eax, eax
.named:
    shl  eax, 4
    lea  rdi, [rel ext_reason_names]
    add  rdi, rax
    call serial_string
    lea  rdi, [rel str_ext_m_dev]
    call serial_string
    mov  rdi, rbx
    call ext_emit_dev_name
    lea  rdi, [rel str_ext_m_lba]
    call serial_string
    mov  rdi, r13
    call serial_hex64
    lea  rdi, [rel str_ext_m_incompat]
    call serial_string
    mov  edi, [rel ext_sb_buf + ESB_INCOMPAT]
    call serial_hex64
    lea  rdi, [rel str_ext_crlf]
    call serial_string
    pop  r14
    pop  r13
    pop  rbx
    ret

; ext_emit_dev_name(RDI=dev*)
ext_emit_dev_name:
    test rdi, rdi
    jz   .anon
    mov  rdi, [rdi + dev.name]
    test rdi, rdi
    jnz  .print
.anon:
    lea  rdi, [rel str_ext_anon]
.print:
    jmp  serial_string

; ---- read-only data ----
str_ext_backend:     db "ext", 0
str_ext_root:        db "/", 0
str_ext_anon:        db "?", 0
str_ext_mount_names: db "ext0", 0, "ext1", 0
str_ext_kind_names:  db "ext2", 0, 0, 0, 0, "ext3", 0, 0, 0, 0, "ext4", 0, 0, 0, 0
; dirent file_type 0..7 -> inode mode >> 12 (0 unused)
ext_ftype_mode:      db 0, 0x8, 0x4, 0x2, 0x6, 0x1, 0xC, 0xA
ext_reason_names:
    db "unknown", 0, 0, 0, 0, 0, 0, 0, 0, 0
    db "sector", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    db "rev0", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    db "state", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    db "incompat", 0, 0, 0, 0, 0, 0, 0, 0
    db "recover", 0, 0, 0, 0, 0, 0, 0, 0, 0
    db "rocompat", 0, 0, 0, 0, 0, 0, 0, 0
    db "geometry", 0, 0, 0, 0, 0, 0, 0, 0
    db "csum", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    db "root", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    db "nomem", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    db "io", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    db "nofiletype", 0, 0, 0, 0, 0, 0
    db "nomount", 0, 0, 0, 0, 0, 0, 0, 0, 0
%if ($ - ext_reason_names) != 16 * (EXT_R_NOMOUNT + 1)
    %error "ext_reason_names: one 16-byte row per EXT_R_* reason"
%endif
str_ext_mounted:     db "[PAOS64] [fs.ext4.mounted] ", 0
str_ext_m_kind:      db " kind=", 0
str_ext_m_dev:       db " dev=", 0
str_ext_m_lba:       db " lba=", 0
str_ext_m_blocks:    db " blocks=", 0
str_ext_m_bs:        db " bs=", 0
str_ext_m_incompat:  db " incompat=", 0
str_ext_m_ro:        db " ro=1", 0
str_ext_crlf:        db 13, 10, 0
str_ext_refused:     db "[PAOS64] [fs.ext4.refused] reason=", 0
str_ext_skipped:     db "[PAOS64] [fs.ext4.skipped] no mountable ext2/ext3/ext4 volume", 13, 10, 0

%macro WDATA_fs_ext4_disk 0
align 8
ext4_disk_handle:      dd -1
; ext4_disk_mount_count..ext_crc_table moved to WDATA_fs_ext4_disk_bss1 (zero-fill tail)
%endmacro
WDATA_DEFER WDATA_fs_ext4_disk
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER), in block order.
%macro WDATA_fs_ext4_disk_bss1 0
resb 4                 ; keeps ext4_disk_mount_count at its WDATA offset mod 64
ext4_disk_mount_count: resd 1
ext4_disk_last_error:  resd 1
ext_gpt_count:         resd 1
ext_walk_mode:         resd 1
ext_comp_len:          resd 1
ext_list_cap:          resd 1
ext_list_names_used:   resd 1
ext_comp_ptr:          resq 1
ext_list_ptr:          resq 1
ext_list_result:       resq 1
ext_spare_ctx:         resq 1
ext_rd_fallback:       resq 1
ext_stat_tmp:          resb fs_stat_size
ext_ops:               resb fs_ops_size
ext_n11_path:          resb 16
ext_scan_buf:          resb 512
ext_sb_buf:            resb 1024
ext_list_names:        resb EXT_LIST_NAMES_CAP
ext_crc_ready:         resb 1
alignb 4
ext_crc_table:         resd 256
%endmacro
WDATA_BSS_DEFER WDATA_fs_ext4_disk_bss1

%macro WDATA_BSS_ext_cross_probe 0
alignb 8
ext_probe_generation: resq 1
%endmacro
WDATA_BSS_DEFER WDATA_BSS_ext_cross_probe

; Read-only image capability query. No mount, media IO or authority change.
ext4_disk_format_ops:
    lea  rax, [rel ext_ops]
    ret

; Late selection holds only original read identity, never an authority token.
%macro WDATA_BSS_ext_late_selector 0
ext_sel_gpt: resb 1
ext_sel_reading: resb 1
alignb 8
ext_sel_device: resq 1
ext_sel_identity: resq 5
ext_sel_primary: resb 96
ext_sel_again: resb 96
ext_sel_sb: resb 1024
ext_sel_sb_again: resb 1024
%endmacro
WDATA_BSS_DEFER WDATA_BSS_ext_late_selector
