;; MODULE fs/fat32_disk
;; LAYER 4
;; EXPORTS fat32_disk_select_owned_ro, fat32_disk_owned_read_state, fat32_disk_is_boot_extent, update_esp_current, update_esp_readonly, update_esp_begin, update_esp_io, update_esp_freeze, update_esp_reclaim, fat32_disk_list_observe, fat32_disk_guest_source_open, fat32_disk_guest_source_hint, fat32_disk_read_device, fat32_disk_scratch_diagnostic, fat32_disk_scratch_arm, fat32_disk_scratch_off, fat32_disk_ro_diag, fat32_disk_select_ro_exact, fat32_disk_source_dir, fat32_disk_source_node, fat32_disk_source_next, fat32_disk_source_device, fat32_disk_source_bind, fat32_disk_source_token, fat32_disk_source_current, fat32_disk_source_stat, fat32_disk_read_at_path, fat32_disk_boot_esp_open, fat32_disk_dirs_lfn_kat, fat32_disk_register, fat32_disk_select_exact, fat32_disk_kat, fat32_disk_create_kat, fat32_disk_txn_kat, fat32_disk_idle_arm, fat32_disk_media_kat, fat32_disk_kat_mount, fat32_disk_kat_finish, fat32_disk_selected_dev, fat32_disk_selected_port, fat32_disk_selected_volume_id, fat32_disk_selection_reason, fat32_disk_last_error, fat32_disk_dirs_write_kat, fat32_disk_copy, fat32_disk_idle_observer, fat32_disk_part_type, fat32_disk_replay_state, fat32_disk_descriptor_absent, fat32_disk_source_mtime, fat32_disk_format_ops
;; IMPORTS fs/fs_identify, fs/guest_volume, fs/update_esp, fs/data_config_provider, core/lib/crc32, fs/ext4_copy, fs/blockdev, fs/storage_access, fs/vfs, fs/vol_owner, core/lib/mem, core/unicode_edit, core/cadence, core/time, boot/serial, boot/boot_esp_guid
;; CAPS
;; OWNER saga:fs_wave
; ============================================================================
; Physical FAT32 backend. Media is reachable ONLY through the struct dev*
; supplied in the backend context and blk_* class dispatch. No AHCI/NVMe symbol
; or chip global is imported. Writes additionally require the descriptor-exact
; DATA binding, and the volume rule's protected-name floor below.
; ============================================================================

FD_DEV            equ 0
FD_PART_LBA       equ 8
FD_PART_SECTORS   equ 16
FD_FAT_LBA        equ 24
FD_DATA_LBA       equ 32
FD_TOTAL_SECTORS  equ 40
FD_FAT_SECTORS    equ 48
FD_CLUSTER_COUNT  equ 56
FD_MAX_CLUSTER    equ 60
FD_ROOT_CLUSTER   equ 64
FD_SPC            equ 68
FD_CLUSTER_BYTES  equ 72
FD_MOUNTED        equ 76
FD_CACHE_START    equ 80
FD_CACHE_CLUSTER  equ 84
FD_CACHE_INDEX    equ 88
FD_CACHE_SIZE     equ 96
FD_VALID_START    equ 104
FD_VALID_SIZE     equ 112
FD_FAT_CACHE_LBA  equ 120
; Immutable-media name lookup cache.  STAT validates the chain once; sequential
; READAT chunks then reuse the same directory result instead of re-reading the
; root directory hundreds of times during a full-file hash.
FD_LOOKUP_SIZE    equ 128
FD_LOOKUP_CLUSTER equ 136
FD_LOOKUP_VALID   equ 140
FD_LOOKUP_NAME    equ 141                    ; exact 11-byte FAT short name
FD_LOOKUP_ATTR    equ 156                    ; cached on-disk attribute byte
FD_VOLUME_ID      equ 152                    ; BPB volume serial (stable identity)
FD_DISK_GUID      equ 160                    ; GPT header disk GUID, on-media bytes
FD_PART_GUID      equ 176                    ; GPT unique partition GUID, on-media bytes
FD_NFATS          equ 192                    ; validated BPB NumFATs
FD_FREE_VALID     equ 196                    ; cached full-FAT free count is exact
FD_FREE_COUNT     equ 200                    ; qword free data clusters
FD_EXACT_BOUND    equ 208                    ; descriptor identity match, not marker fallback
FD_PART_ESP       equ 209                    ; mounted GPT entry has the complete ESP type GUID
FD_SCAN_ERR       equ 210                    ; earlier GPT entry/BPB read failed this mount
FD_PART_INDEX     equ 212                    ; zero-based GPT entry, or -1 for MBR/superfloppy
FD_TX_BUSY        equ 216                    ; bounded try-lock, no concurrent writer
FD_SWEEP_CLUSTER  equ 220
FD_SWEEP_SECTOR   equ 224
FD_SWEEP_HOPS     equ 228
FD_SWEEP_DONE     equ 232
FD_FSINFO_DELTA   equ 236                    ; signed dword: net freed clusters not yet in FSInfo
FD_ORPHANS        equ 240                    ; reclaimed since mount
FD_NAMESPACE_GEN  equ 248                    ; changes at every mutation/remount
FD_MOUNT_GEN      equ 256                    ; registered medium whose geometry was mounted
FD_CTX_SIZE       equ 264

; fat32_disk_select_exact descriptor (generated from primary_target.json):
; disk GUID[16], partition GUID[16], partition sectors qword,
; filesystem sectors qword, FAT volume ID dword, reserved dword.
FD_EX_DISK_GUID     equ 0
FD_EX_PART_GUID     equ 16
FD_EX_PART_SECTORS  equ 32
FD_EX_FS_SECTORS    equ 40
FD_EX_VOLUME_ID     equ 48

FD_SELECT_NONE     equ 0
FD_SELECT_MARKER   equ 1
FD_SELECT_FALLBACK equ 2
FD_ESP_GUID_LO    equ 0x11D2F81FC12A7328     ; C12A7328-F81F-11D2-BA4B-00A0C93EC93B
FD_ESP_GUID_HI    equ 0x3BC93EC9A0004BBA     ; GUID in its on-media byte order

FD_DIR_MAX_CLUSTERS equ 64
FD_PATH_MAX         equ 1024
FD_PATH_DEPTH_MAX   equ 16
FD_LFN_MAX          equ 255                 ; UTF-16 units AND final UTF-8 bytes, independently bounded
FD_LFN_ENTRIES_MAX  equ 20
; One listing's exported names share this pool (each takes len+1 <= FD_LFN_MAX+1).
; Sized for the largest shipped caller cap, Explorer's FORM_FSROOT_LIST (64 rows
; + "." and ".."); FSLS asks for 64. So those listings always carry every long
; name. A caller asking for more gets the 8.3 alias + FS_DIRENT_LONG_OMITTED for
; an entry whose long name no longer fits. Cost: 16896 bytes of WDATA (was 1408).
; 66 is pinned by test_pool_covers_every_caller_cap (test_rc_fat32_list_longname_host.py), which
; reads both caller caps from their sources: raising either cap fails it until this follows.
FD_LIST_POOL_ENTRIES equ 66
FD_LIST_NAMES_CAP   equ FD_LIST_POOL_ENTRIES * (FD_LFN_MAX + 1)
FD_EOC_MIN          equ 0x0FFFFFF8
FD_RESERVED_MIN     equ 0x0FFFFFF0

FD_ERR_NONE         equ 0
FD_ERR_ALLOWLIST    equ 1
FD_ERR_NOT_EXACT    equ 2
FD_ERR_EXISTS       equ 3
FD_ERR_NO_SPACE     equ 4
FD_ERR_NOT_FOUND    equ 5
FD_ERR_BAD_ARG      equ 6
FD_ERR_IO           equ 7
FD_ERR_CHAIN_OR_IO  equ 8
FD_ERR_UNMOUNTED    equ 9
FD_ERR_BUSY         equ 10
FD_ERR_NOT_DIR      equ 11
FD_ERR_NOT_EMPTY    equ 12
FD_ERR_CROSS_DIR    equ 13
FD_ERR_NOT_READY    equ 14                  ; RCQ-20: the idle cadence that runs copy jobs is not armed
FD_ERR_TOO_DEEP     equ 15                  ; RCQ-20 S5b: a tree's directory below FS_TREE_DEPTH_MAX levels
FD_ERR_VOLUME_RO    equ 17                  ; T5-15.4: this volume is read-only to this request
FD_ERR_SOURCE_CHANGED equ 16                ; source identity/size/mtime changed during copy

FD_FAULT_NONE       equ 0
FD_FAULT_ALLOC      equ 1
FD_FAULT_DATA       equ 2
FD_FAULT_FAT1       equ 3

; Task2402: updates commit the fresh entry's name before retiring the old chain.
FD_TX_MAGIC        equ 0xA524
FD_TX_MAX_BYTES    equ 1024                 ; at most two clusters (wire cap remains 256)

; RCQ-20 copy job (fat32_disk_copy).
FD_CP_MAGIC        equ 0xC524               ; copy journal tag; never FD_TX_MAGIC
FD_CP_DST_SEC      equ 14                   ; u32 reserved destination sector, partition-relative
FD_CP_DST_IDX      equ 18                   ; u8 slot index in that sector
FD_CP_PREV         equ 22                   ; u32 reclaim: cluster whose free is pending
FD_CP_STEP_BYTES   equ 65536                ; data copied or verified per step
FD_CP_RECLAIM_STEP equ 64                   ; clusters reclaimed per pass
FD_CP_IDLE         equ 0
FD_CP_COPY         equ 1
FD_CP_VERIFY       equ 2
FD_CP_RECLAIM      equ 3
FD_CP_TREE         equ 4                    ; RCQ-20 S5b: a tree job between files: its walk advances
FD_CP_COMPARE      equ 5                    ; smart copy C: an existing same-size destination file read against
                                            ;   the source; nothing written (no journal) until they differ
FD_TREE_WALK_K     equ 16                   ; S5b: directory entries one walk step reads at most
; S5b: one level of the walk (fd_tree_lvl), the source directory first
FD_TL_FIRST        equ 0                    ; the source directory's first cluster
FD_TL_CL           equ 4                    ; the cluster being read
FD_TL_ENT          equ 8                    ; the next entry in it
FD_TL_N            equ 12                   ; clusters read so far (<= FD_DIR_MAX_CLUSTERS)
FD_TL_DST          equ 16                   ; the destination directory made for it
FD_TL_END          equ 20                   ; a 0x00 entry was seen: the rest is free until the EOC
FD_TL_SIZE         equ 32

%macro FD_TX_CUT 1
    cmp  byte [rel fd_tx_fault], %1
    jne  %%continue
    mov  byte [rel fd_tx_fault_seen], %1
    jmp  .unlock_fail
%%continue:
%endmacro

; Standalone legacy host fixtures retain descriptor-enabled semantics.
%ifndef COG_MODEL_ENABLED
%ifdef PAOS_PUBLIC_BUILD
%if PAOS_PUBLIC_BUILD != 0
%error "public build requires explicit COG_MODEL_ENABLED"
%endif
%endif
%define COG_MODEL_ENABLED 1
%endif
%ifdef PAOS_PUBLIC_BUILD
%if PAOS_PUBLIC_BUILD != 0 && COG_MODEL_ENABLED != 0
%error "public build requires COG_MODEL_ENABLED=0"
%endif
%endif

fat32_disk_register:
    call fat32_disk_select_volume_by_marker
    test rax, rax
    jnz  .fail
    call fat32_disk_build_ops
    lea  rdi, [rel fat32_disk_ops]
    lea  rsi, [rel fat32_disk_ctx]
    lea  rdx, [rel str_fd_mount_name]
    call vfs_register_mount
    test rax, rax
    js   .fail
    mov  byte [rel vfs_m_disk], 1
    push rax
    ; Bind writes here, after vfs_register_mount's remount has cleared the
    ; identity latch. Filesystem access must not depend on loading a model.
    ; These bytes come from the build's primary-target descriptor, not an
    ; example GUID or a controller global. Failure keeps the mount read-only.
%if COG_MODEL_ENABLED = 1
    lea  rdi, [rel fd_expected_data_volume]
    mov  rsi, [rel fat32_disk_selected_dev]
    call fat32_disk_select_exact
%endif
    ; Without descriptor identities, preserve generic reads but never invent
    ; the exact-volume authority needed to latch writes. Public write authority
    ; needs a separate explicit storage design, not a zero identity substitute.
    lea  rdi, [rel str_fd_mounted]
    call serial_string
    pop  rax
    ret
.fail:
    mov  rax, -1
    ret

; Select across every healthy AHCI *and* NVMe block handle by content.  The
; first valid FAT32 mount is eligible for no-marker fallback only if it is a
; GPT ESP and no earlier entry/BPB read failed. Marker selection is unchanged.
; AHCI is scanned first, then NVMe; explicit mounts retain generic FAT32 reads.
; This runtime-neutral scan reuses the Beelink bee017 metal-proven implementation
; from source commit d4a558ce5e0580ad238619e57bb48133c3fe92a6: Beelink's ESP is
; on nvme0, while Dell and Lenovo expose AHCI volumes.  Controller state remains
; opaque: enumeration and physical unit identity both come through blockdev.
fat32_disk_select_volume_by_marker:
    push rbx
    push r12
    push r13
    mov  byte [rel fat32_disk_selection_reason], FD_SELECT_NONE
    mov  qword [rel fat32_disk_selected_dev], 0
    mov  dword [rel fat32_disk_selected_port], 0xFFFFFFFF
    mov  dword [rel fat32_disk_selected_volume_id], 0
    xor  r12d, r12d                         ; previous registry handle
    xor  r13d, r13d                         ; first eligible ESP fallback saved
    xor  ebx, ebx                           ; scan phase: 0=ahci, 1=nvme
.next_device:
    lea  rdi, [rel str_fd_ahci_prefix]
    test ebx, ebx
    jz   .have_prefix
    lea  rdi, [rel str_fd_nvme_prefix]
.have_prefix:
    mov  esi, 4
    mov  rdx, r12
    call blk_find_prefix_after
    test rax, rax
    jz   .prefix_exhausted
    mov  r12, rax
    mov  [rel fat32_disk_ctx + FD_DEV], rax
    mov  dword [rel fat32_disk_ctx + FD_MOUNTED], 0
    mov  dword [rel fat32_disk_ctx + FD_CACHE_START], 0
    mov  dword [rel fat32_disk_ctx + FD_VALID_START], 0
    mov  byte [rel fat32_disk_ctx + FD_LOOKUP_VALID], 0
    mov  qword [rel fat32_disk_ctx + FD_FAT_CACHE_LBA], -1
    lea  rdi, [rel fat32_disk_ctx]
    call fat32_disk_mount_ctx
    test rax, rax
    jnz  .next_device
    cmp  byte [rel fat32_disk_ctx + FD_PART_ESP], 1
    jne  .ineligible_fallback
    cmp  byte [rel fat32_disk_ctx + FD_SCAN_ERR], 0
    jne  .ineligible_fallback
    test r13d, r13d
    jnz  .check_marker
    lea  rsi, [rel fat32_disk_ctx]
    lea  rdi, [rel fat32_disk_fallback_ctx]
    mov  ecx, FD_CTX_SIZE / 8
    cld
    rep  movsq
    mov  r13d, 1
    jmp  .check_marker
.ineligible_fallback:
    lea  rdi, [rel str_fd_fallback_skipped]
    call serial_string
    mov  rdi, [r12 + dev.name]
    call serial_string
    lea  rdi, [rel str_fd_fallback_entry]
    call serial_string
    mov  edi, [rel fat32_disk_ctx + FD_PART_INDEX]
    call serial_hex64
    call serial_newline
.check_marker:
    lea  rdi, [rel fat32_disk_ctx]
    lea  rsi, [rel fd_marker_name]
    call fd_lookup
    test rax, rax
    jnz  .next_device
    mov  byte [rel fat32_disk_selection_reason], FD_SELECT_MARKER
    lea  rdi, [rel fat32_disk_ctx]
    call fat32_disk_record_selection
    xor  eax, eax
    jmp  .out
.prefix_exhausted:
    test ebx, ebx
    jnz  .after_scan                        ; both ahci and nvme scanned
    mov  ebx, 1                             ; AHCI exhausted -> scan NVMe
    xor  r12d, r12d                         ; restart at registry head
    jmp  .next_device
.after_scan:
    test r13d, r13d
    jz   .fail
    lea  rsi, [rel fat32_disk_fallback_ctx]
    lea  rdi, [rel fat32_disk_ctx]
    mov  ecx, FD_CTX_SIZE / 8
    cld
    rep  movsq
    mov  byte [rel fat32_disk_selection_reason], FD_SELECT_FALLBACK
    lea  rdi, [rel fat32_disk_ctx]
    call fat32_disk_record_selection
    xor  eax, eax
    jmp  .out
.fail:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; fat32_disk_select_exact(RDI=descriptor, RSI=required dev*) -> 0 / -1.
; Mount only the AHCI device already selected by exact IDENTIFY model+serial,
; then retain it only when every on-media descriptor field AND the INITRD.GZ
; root marker agree.  A miss restores the generic mount selected during
; vfs_selftest, so non-cognition guests keep their old behavior and the primary
; system disk is not even mounted speculatively by the model path.
fat32_disk_select_exact:
    push rbx
    push r12
    push r13
    push r14
    mov  r13, rdi
    mov  r14, rsi
    test r13, r13
    jz   .fail_no_save
    test r14, r14
    jz   .fail_no_save
    lea  rsi, [rel fat32_disk_ctx]
    lea  rdi, [rel fat32_disk_saved_ctx]
    mov  ecx, FD_CTX_SIZE / 8
    cld
    rep  movsq
    mov  al, [rel fat32_disk_selection_reason]
    mov  [rel fat32_disk_saved_reason], al
    mov  eax, [rel fat32_disk_selected_port]
    mov  [rel fat32_disk_saved_port], eax
    mov  eax, [rel fat32_disk_selected_volume_id]
    mov  [rel fat32_disk_saved_volume_id], eax
    mov  rax, [rel fat32_disk_selected_dev]
    mov  [rel fat32_disk_saved_dev], rax
    mov  rax, r14
    mov  [rel fat32_disk_ctx + FD_DEV], rax
    lea  rdi, [rel fat32_disk_ctx]
    call fat32_disk_mount_ctx
    test rax, rax
    jnz  .restore_fail
    lea  rdi, [rel fat32_disk_ctx]
    mov  rsi, r13
    call fat32_disk_identity_matches
    test rax, rax
    jnz  .restore_fail
    lea  rdi, [rel fat32_disk_ctx]
    lea  rsi, [rel fd_marker_name]
    call fd_lookup
    test rax, rax
    jnz  .restore_fail
    mov  byte [rel fat32_disk_ctx + FD_EXACT_BOUND], 1
    mov  byte [rel fat32_disk_selection_reason], FD_SELECT_MARKER
    lea  rdi, [rel fat32_disk_ctx]
    call fat32_disk_record_selection
    xor  eax, eax
    jmp  .out
.restore_fail:
    lea  rsi, [rel fat32_disk_saved_ctx]
    lea  rdi, [rel fat32_disk_ctx]
    mov  ecx, FD_CTX_SIZE / 8
    cld
    rep  movsq
    mov  al, [rel fat32_disk_saved_reason]
    mov  [rel fat32_disk_selection_reason], al
    mov  eax, [rel fat32_disk_saved_port]
    mov  [rel fat32_disk_selected_port], eax
    mov  eax, [rel fat32_disk_saved_volume_id]
    mov  [rel fat32_disk_selected_volume_id], eax
    mov  rax, [rel fat32_disk_saved_dev]
    mov  [rel fat32_disk_selected_dev], rax
    ; The snapshot owns cache tags, but not the shared sector buffers that
    ; the failed remount/lookup overwrote. Never restore those tags as valid.
    lea  rdi, [rel fat32_disk_ctx]
    call fd_invalidate_caches
.fail_no_save:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

fat32_disk_identity_matches:
    xor  ecx, ecx
.disk_guid:
    cmp  ecx, 16
    jae  .part_begin
    mov  al, [rdi + FD_DISK_GUID + rcx]
    cmp  al, [rsi + FD_EX_DISK_GUID + rcx]
    jne  .fail
    inc  ecx
    jmp  .disk_guid
.part_begin:
    xor  ecx, ecx
.part_guid:
    cmp  ecx, 16
    jae  .sizes
    mov  al, [rdi + FD_PART_GUID + rcx]
    cmp  al, [rsi + FD_EX_PART_GUID + rcx]
    jne  .fail
    inc  ecx
    jmp  .part_guid
.sizes:
    mov  rax, [rdi + FD_PART_SECTORS]
    cmp  rax, [rsi + FD_EX_PART_SECTORS]
    jne  .fail
    ; Descriptor filesystem_bytes comes from df's usable FAT data-cluster
    ; count, not the BPB TotSec field (which also includes reserved/FAT areas).
    mov  eax, [rdi + FD_CLUSTER_COUNT]
    mov  ecx, [rdi + FD_SPC]
    imul rax, rcx
    jo   .fail
    cmp  rax, [rsi + FD_EX_FS_SECTORS]
    jne  .fail
    mov  eax, [rdi + FD_VOLUME_ID]
    cmp  eax, [rsi + FD_EX_VOLUME_ID]
    jne  .fail
    xor  eax, eax
    ret
.fail:
    mov  rax, -1
    ret

fat32_disk_record_selection:
    mov  eax, [rdi + FD_VOLUME_ID]
    mov  [rel fat32_disk_selected_volume_id], eax
    mov  rax, [rdi + FD_DEV]
    mov  [rel fat32_disk_selected_dev], rax
    test rax, rax
    jz   .unknown
    mov  rax, [rax + dev.info]
    test rax, rax
    jz   .unknown
    mov  eax, [rax + blk_info.unit]
    mov  [rel fat32_disk_selected_port], eax
    ret
.unknown:
    mov  qword [rel fat32_disk_selected_dev], 0
    mov  dword [rel fat32_disk_selected_port], 0xFFFFFFFF
    ret

fat32_disk_build_ops:
    lea  rax, [rel str_fd_backend]
    mov  [rel fat32_disk_ops + fs_ops.name], rax
    lea  rax, [rel fat32_disk_mount]
    mov  [rel fat32_disk_ops + fs_ops.mount], rax
    lea  rax, [rel fat32_disk_fail]
    mov  [rel fat32_disk_ops + fs_ops.readfile], rax
    lea  rax, [rel fat32_disk_writefile]
    mov  [rel fat32_disk_ops + fs_ops.writefile], rax
    lea  rax, [rel fat32_disk_delete]
    mov  [rel fat32_disk_ops + fs_ops.delete], rax
    lea  rax, [rel fat32_disk_stat]
    mov  [rel fat32_disk_ops + fs_ops.stat], rax
    lea  rax, [rel fat32_disk_read_at]
    mov  [rel fat32_disk_ops + fs_ops.read_at], rax
    lea  rax, [rel fat32_disk_info]
    mov  [rel fat32_disk_ops + fs_ops.info], rax
    lea  rax, [rel fat32_disk_list_root]
    mov  [rel fat32_disk_ops + fs_ops.list_root], rax
    lea  rax, [rel fat32_disk_update]
    mov  [rel fat32_disk_ops + fs_ops.update], rax
    lea  rax, [rel fat32_disk_rename]
    mov  [rel fat32_disk_ops + fs_ops.rename], rax
    lea  rax, [rel fat32_disk_stat_path]
    mov  [rel fat32_disk_ops + fs_ops.stat_path], rax
    lea  rax, [rel fat32_disk_replace_meta]
    mov  [rel fat32_disk_ops + fs_ops.replace_meta], rax
    lea  rax, [rel fat32_disk_read_at_path]
    mov  [rel fat32_disk_ops + fs_ops.read_at_path], rax
    lea  rax, [rel fat32_disk_list_dir]
    mov  [rel fat32_disk_ops + fs_ops.list_dir], rax
    lea  rax, [rel fat32_disk_mutate_path]
    mov  [rel fat32_disk_ops + fs_ops.mutate_path], rax
    lea  rax, [rel fat32_disk_copy]
    mov  [rel fat32_disk_ops + fs_ops.copy], rax
    lea  rax, [rel fat32_disk_file_extents]
    mov  [rel fat32_disk_ops + fs_ops.file_extents], rax
    lea  rax, [rel fat32_disk_extent_check]
    mov  [rel fat32_disk_ops + fs_ops.extent_check], rax
    ret

fat32_disk_fail:
    mov  rax, -1
    ret

; ============================================================================
; RCQ-38 G1b: the READ-ONLY boot-ESP locator (root 23:23:45; plan fs-evidence/RCQ-38-G1b).
; fat32_disk_boot_esp_open(RDI = the boot ESP's unique partition GUID, 16 on-media bytes)
;   -> RAX = vfs handle / -1 (E_NO_VOLUME to the caller). BSP only, non-reentrant.
; Every READ-capable block device is mounted in turn on fd_ro_ctx with the GPT filter
; set (reads only): exactly one entry of ESP type with this unique GUID, across all
; media, is admitted. None, or the same GUID on two media (a cloned disk, a RAM copy),
; refuses. The handle is a SEPARATE ctx with its own fs_ops table that carries only the
; read slots (every mutating slot stays 0, so vfs refuses before any backend code) and
; NO name (FSSEL, FSARM and FSOWN select by name, so the verbs never address it);
; fs_mutation_mount and fd_mutation_authorized refuse it by address, and so do the two
; physical chokepoints, fd_write_sectors and fd_flush. Opened once: the same GUID
; answers the same handle, any other GUID is refused.
fat32_disk_boot_esp_open:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  dword [rel fat32_disk_last_error], FD_ERR_BAD_ARG
    test r12, r12
    jz   .refuse
    mov  rax, [r12]
    or   rax, [r12 + 8]
    jz   .refuse                          ; a zero GUID names no partition
    mov  eax, [rel fd_ro_handle]
    test eax, eax
    jz   .scan
    mov  rax, [r12]                       ; open: only its own GUID, and the open handle stays
    cmp  rax, [rel fd_ro_guid]
    jne  .refuse
    mov  rax, [r12 + 8]
    cmp  rax, [rel fd_ro_guid + 8]
    jne  .refuse
    mov  eax, [rel fd_ro_handle]
    dec  eax
    jmp  .out
.scan:
    mov  rax, [r12]
    mov  [rel fd_ro_guid], rax
    mov  rax, [r12 + 8]
    mov  [rel fd_ro_guid + 8], rax
    lea  rax, [rel fd_ro_guid]
    mov  [rel fd_want_guid], rax
    mov  dword [rel fd_want_seen], 0      ; G1b (rc-sec b2): every scan counts afresh
    mov  byte [rel fd_want_fault], 0
    xor  ebx, ebx                         ; the previous device
    xor  r13d, r13d                       ; media holding the GUID
    xor  r14d, r14d                       ; the one that does
.next:
    mov  rdi, rbx
    mov  esi, BLKCAP_READ
    xor  edx, edx
    call blk_iter_after
    test rax, rax
    jz   .scanned
    mov  rbx, rax
    mov  [rel fd_ro_ctx + FD_DEV], rax
    lea  rdi, [rel fd_ro_ctx]
    call fat32_disk_mount_ctx
    test rax, rax
    jnz  .next
    inc  r13d
    mov  r14, rbx
    jmp  .next
.scanned:
    mov  qword [rel fd_want_guid], 0
    mov  dword [rel fd_ro_ctx + FD_MOUNTED], 0
    mov  dword [rel fat32_disk_last_error], FD_ERR_IO
    lea  rdi, [rel str_fd_esp_fault]
    cmp  byte [rel fd_want_fault], 0
    jne  .fail_log                        ; a medium could not be read or parsed: fail closed
    mov  dword [rel fat32_disk_last_error], FD_ERR_NOT_FOUND
    lea  rdi, [rel str_fd_esp_ambiguous]
    cmp  dword [rel fd_want_seen], 1
    ja   .fail_log                        ; the GUID named twice, on any media, mounting or not
    cmp  r13d, 1
    jne  .fail_none                       ; never named, or its one entry did not mount
    mov  [rel fd_ro_ctx + FD_DEV], r14
    call fd_ro_build_ops
    lea  rdi, [rel fd_ro_ops]
    lea  rsi, [rel fd_ro_ctx]
    xor  edx, edx                         ; no name: never selectable by FSSEL/FSARM/FSOWN
    call vfs_register_mount               ; mounts again through fd_ro_mount
    test rax, rax
    js   .fail
    inc  eax
    mov  [rel fd_ro_handle], eax
    dec  eax
    jmp  .out
.fail_none:
    lea  rdi, [rel str_fd_esp_none]
.fail_log:
    call serial_string                    ; rc-sec b4: why the consumer falls back to its built-ins
    call serial_newline
.fail:
    mov  qword [rel fd_ro_guid], 0
    mov  qword [rel fd_ro_guid + 8], 0
.refuse:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; The RO handle's .mount: always re-selects the entry with its own GUID.
fd_ro_mount:
    mov  rdi, [rdi + fsmount.priv]
    lea  rax, [rel fd_ro_guid]
    mov  [rel fd_want_guid], rax
    call fat32_disk_mount_ctx
    mov  qword [rel fd_want_guid], 0
    ret

; fd_want_fault_latch(R12=ctx): latch this scan's fault; the first medium that
; latched it is kept for the diagnostic. Written on every 0->1, so whenever the
; fault is set the device names this scan's medium. Clobbers RAX and flags only.
fd_want_fault_latch:
    cmp  byte [rel fd_want_fault], 0
    jne  .kept
    mov  rax, [r12 + FD_DEV]
    mov  [rel fd_want_fault_dev], rax
.kept:
    mov  byte [rel fd_want_fault], 1
    ret

; Serial diagnostic only: names the medium that latched the guest-source fault.
fd_guest_fault_dev_log:
    sub  rsp, 8
    lea  rdi, [rel str_fd_guest_fault_dev]
    call serial_string
    lea  rdi, [rel str_fd_guest_fault_noname]
    mov  rax, [rel fd_want_fault_dev]
    test rax, rax
    jz   .name
    mov  rax, [rax + dev.name]
    test rax, rax
    jz   .name
    mov  rdi, rax
.name:
    call serial_string
    call serial_newline
    add  rsp, 8
    ret

; Exact guest-source location from an untrusted hint; content authority stays
; with the signed VM profile. Separate unnamed RO context, BSP/non-reentrant.
; Same GUID is idempotent; another GUID cannot rebind an open handle.
fat32_disk_guest_source_open:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  dword [rel fat32_disk_last_error], FD_ERR_BAD_ARG
    test r12, r12
    jz   .refuse
    mov  rax, [r12]
    or   rax, [r12 + 8]
    jz   .refuse                          ; a zero GUID names no partition
    mov  eax, [rel fd_guest_handle]
    test eax, eax
    jz   .scan
    mov  rax, [r12]                       ; open: only its own GUID, and the open handle stays
    cmp  rax, [rel fd_guest_guid]
    jne  .refuse
    mov  rax, [r12 + 8]
    cmp  rax, [rel fd_guest_guid + 8]
    jne  .refuse
    mov  eax, [rel fd_guest_handle]
    dec  eax
    jmp  .out
.scan:
    mov  rax, [r12]
    mov  [rel fd_guest_guid], rax
    mov  rax, [r12 + 8]
    mov  [rel fd_guest_guid + 8], rax
    lea  rax, [rel fd_guest_guid]
    mov  [rel fd_want_guid], rax
    mov  dword [rel fd_want_seen], 0      ; G1b (rc-sec b2): every scan counts afresh
    mov  byte [rel fd_want_fault], 0
    xor  ebx, ebx                         ; the previous device
    xor  r13d, r13d                       ; media holding the GUID
    xor  r14d, r14d                       ; the one that does
.next:
    mov  rdi, rbx
    mov  esi, BLKCAP_READ
    xor  edx, edx
    call blk_iter_after
    test rax, rax
    jz   .scanned
    mov  rbx, rax
    mov  [rel fd_guest_ctx + FD_DEV], rax
    lea  rdi, [rel fd_guest_ctx]
    call fat32_disk_mount_ctx
    test rax, rax
    jnz  .next
    inc  r13d
    mov  r14, rbx
    jmp  .next
.scanned:
    mov  qword [rel fd_want_guid], 0
    mov  dword [rel fd_guest_ctx + FD_MOUNTED], 0
    mov  dword [rel fat32_disk_last_error], FD_ERR_IO
    lea  rdi, [rel str_fd_guest_fault]
    cmp  byte [rel fd_want_fault], 0
    jne  .fail_fault_log                        ; a medium could not be read or parsed: fail closed
    mov  dword [rel fat32_disk_last_error], FD_ERR_NOT_FOUND
    lea  rdi, [rel str_fd_guest_ambiguous]
    cmp  dword [rel fd_want_seen], 1
    ja   .fail_log                        ; the GUID named twice, on any media, mounting or not
    cmp  r13d, 1
    jne  .fail_none                       ; never named, or its one entry did not mount
    mov  [rel fd_guest_ctx + FD_DEV], r14
    call fd_guest_build_ops
    call vfs_register_guest_source        ; fixed unnamed RO backend, no write-generation barrier
    test rax, rax
    js   .fail
    inc  eax
    mov  [rel fd_guest_handle], eax
    dec  eax
    jmp  .out
.fail_none:
    lea  rdi, [rel str_fd_guest_none]
.fail_log:
    call serial_string                    ; diagnostic only; caller decides refusal, no fallback authority
    call serial_newline
    jmp  .fail
.fail_fault_log:
    call serial_string                    ; the unchanged cause line, then the medium that latched it
    call serial_newline
    call fd_guest_fault_dev_log           ; diagnostic only
.fail:
    mov  qword [rel fd_guest_guid], 0
    mov  qword [rel fd_guest_guid + 8], 0
.refuse:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; The RO handle's .mount: always re-selects the entry with its own GUID.
fd_guest_mount:
    mov  rdi, [rdi + fsmount.priv]
    lea  rax, [rel fd_guest_guid]
    mov  [rel fd_want_guid], rax
    call fat32_disk_mount_ctx
    mov  qword [rel fd_want_guid], 0
    ret

; fd_gpt_want_count(RDI = ctx; fd_gpt_entries_lba / fd_gpt_count set) -> EAX = the table's entries
; whose unique partition GUID is fd_want_guid's, of ANY type (a unique GUID twice in one table is
; ambiguous, as on two media: rc-sec 23:55:43 g3) / -1 on a read error. Reads fd_sector only.
fd_gpt_want_count:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    xor  r13d, r13d                       ; the entry index
    xor  r14d, r14d                       ; the matches
.loop:
    cmp  r13d, [rel fd_gpt_count]
    jae  .done
    mov  eax, r13d
    shl  rax, 7
    mov  rbx, rax
    shr  rax, 9
    add  rax, [rel fd_gpt_entries_lba]
    mov  rdi, r12
    mov  rsi, rax
    mov  edx, 1
    lea  rcx, [rel fd_sector]
    call fd_read_sectors
    test rax, rax
    jnz  .io
    and  ebx, 511
    lea  rcx, [rel fd_sector]
    add  rbx, rcx
    cmp  qword [rbx], 0
    je   .next                            ; an unused entry (mount_ctx's own test)
    mov  rcx, [rel fd_want_guid]
    mov  rax, [rbx + 16]
    cmp  rax, [rcx]
    jne  .next
    mov  rax, [rbx + 24]
    cmp  rax, [rcx + 8]
    jne  .next
    inc  r14d
.next:
    inc  r13d
    jmp  .loop
.done:
    mov  eax, r14d
    jmp  .out
.io:
    mov  eax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; The RO fs_ops table: an explicit list of READ slots; everything else stays 0.
fd_ro_build_ops:
    lea  rdi, [rel fd_ro_ops]
    xor  eax, eax
    mov  ecx, fs_ops_size / 8
    cld
    rep  stosq
    lea  rax, [rel str_fd_ro_backend]
    mov  [rel fd_ro_ops + fs_ops.name], rax
    lea  rax, [rel fd_ro_mount]
    mov  [rel fd_ro_ops + fs_ops.mount], rax
    lea  rax, [rel fat32_disk_stat]
    mov  [rel fd_ro_ops + fs_ops.stat], rax
    lea  rax, [rel fat32_disk_read_at]
    mov  [rel fd_ro_ops + fs_ops.read_at], rax
    lea  rax, [rel fat32_disk_info]
    mov  [rel fd_ro_ops + fs_ops.info], rax
    lea  rax, [rel fat32_disk_list_root]
    mov  [rel fd_ro_ops + fs_ops.list_root], rax
    lea  rax, [rel fat32_disk_stat_path]
    mov  [rel fd_ro_ops + fs_ops.stat_path], rax
    lea  rax, [rel fat32_disk_replace_meta]
    mov  [rel fd_ro_ops + fs_ops.replace_meta], rax
    lea  rax, [rel fat32_disk_read_at_path]
    mov  [rel fd_ro_ops + fs_ops.read_at_path], rax
    lea  rax, [rel fat32_disk_list_dir]
    mov  [rel fd_ro_ops + fs_ops.list_dir], rax
    lea  rax, [rel fat32_disk_file_extents]
    mov  [rel fd_ro_ops + fs_ops.file_extents], rax
    lea  rax, [rel fat32_disk_extent_check]
    mov  [rel fd_ro_ops + fs_ops.extent_check], rax
    ret

fd_guest_build_ops:
    lea  rdi, [rel fd_guest_ops]
    xor  eax, eax
    mov  ecx, fs_ops_size / 8
    cld
    rep  stosq
    lea  rax, [rel str_fd_ro_backend]
    mov  [rel fd_guest_ops + fs_ops.name], rax
    lea  rax, [rel fd_guest_mount]
    mov  [rel fd_guest_ops + fs_ops.mount], rax
    lea  rax, [rel fat32_disk_stat]
    mov  [rel fd_guest_ops + fs_ops.stat], rax
    lea  rax, [rel fat32_disk_read_at]
    mov  [rel fd_guest_ops + fs_ops.read_at], rax
    lea  rax, [rel fat32_disk_info]
    mov  [rel fd_guest_ops + fs_ops.info], rax
    lea  rax, [rel fat32_disk_list_root]
    mov  [rel fd_guest_ops + fs_ops.list_root], rax
    lea  rax, [rel fat32_disk_stat_path]
    mov  [rel fd_guest_ops + fs_ops.stat_path], rax
    lea  rax, [rel fat32_disk_replace_meta]
    mov  [rel fd_guest_ops + fs_ops.replace_meta], rax
    lea  rax, [rel fat32_disk_read_at_path]
    mov  [rel fd_guest_ops + fs_ops.read_at_path], rax
    lea  rax, [rel fat32_disk_list_dir]
    mov  [rel fd_guest_ops + fs_ops.list_dir], rax
    lea  rax, [rel fat32_disk_file_extents]
    mov  [rel fd_guest_ops + fs_ops.file_extents], rax
    lea  rax, [rel fat32_disk_extent_check]
    mov  [rel fd_guest_ops + fs_ops.extent_check], rax
    ret

; Validate the new source's complete bounded primary GPT before accepting or
; excluding this medium. No CRC-blind count truncation/overlap may hide a clone.
; RDI=guest ctx; fd_sector contains LBA1. Return 0/-1, preserve caller registers.
fd_guest_gpt_validate:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov r12,rdi
    lea rdi,[rel fd_guest_header]
    lea rsi,[rel fd_sector]
    mov edx,512
    call memcpy
    lea rbx,[rel fd_guest_header]
    cmp dword [rbx+8],0x10000
    jne .fail
    cmp dword [rbx+20],0
    jne .fail
    cmp qword [rbx+24],1
    jne .fail
    mov rax,[r12+FD_DEV]
    mov rax,[rax+dev.info]
    mov r15,[rax+blk_info.lba_max]
    cmp [rbx+32],r15
    jne .fail
    mov r13,[rbx+40]
    cmp r13,34
    jb .fail
    mov r14,[rbx+48]
    cmp r14,r13
    jb .fail
    cmp r14,r15
    jae .fail
    mov rax,[rbx+56]
    or rax,[rbx+64]
    jz .fail
    mov esi,[rbx+12]
    cmp esi,92
    jb .fail
    cmp esi,512
    ja .fail
    mov ebp,[rbx+16]
    mov dword [rbx+16],0
    mov rdi,rbx
    call hotpatch_crc32
    mov [rbx+16],ebp
    cmp eax,ebp
    jne .fail
    cmp dword [rbx+84],128
    jne .fail
    mov ebp,[rbx+80]
    test ebp,ebp
    jz .fail
    cmp ebp,128
    ja .fail
    mov rsi,[rbx+72]
    cmp rsi,2
    jb .fail
    mov edx,ebp
    add edx,3
    shr edx,2
    mov rax,rsi
    add rax,rdx
    jc .fail
    cmp rax,r13
    ja .fail
    mov rdi,r12
    lea rcx,[rel fd_guest_entries]
    call fd_read_sectors
    test rax,rax
    jnz .fail
    lea rdi,[rel fd_guest_entries]
    mov esi,ebp
    shl esi,7
    call hotpatch_crc32
    cmp eax,[rbx+88]
    jne .fail
    ; First prove every occupied extent is bounded and locate the requested GUID.
    lea rbx,[rel fd_guest_entries]
    xor r15d,r15d
    xor ecx,ecx
.entries:
    cmp ecx,ebp
    jae .overlap_begin
    mov rax,[rbx]
    or rax,[rbx+8]
    jz .next
    mov rax,[rbx+32]
    mov rdx,[rbx+40]
    cmp rax,r13
    jb .fail
    cmp rdx,rax
    jb .fail
    cmp rdx,r14
    ja .fail
    lea rsi,[rel fd_guest_guid]
    mov rax,[rbx+16]
    cmp rax,[rsi]
    jne .next
    mov rax,[rbx+24]
    cmp rax,[rsi+8]
    jne .next
    test r15,r15
    jnz .fail
    mov r15,rbx
.next:
    add rbx,128
    inc ecx
    jmp .entries
.overlap_begin:
    test r15,r15
    jz .ok
    lea rbx,[rel fd_guest_entries]
    xor ecx,ecx
.overlap:
    cmp ecx,ebp
    jae .ok
    cmp rbx,r15
    je .overlap_next
    mov rax,[rbx]
    or rax,[rbx+8]
    jz .overlap_next
    mov rax,[rbx+40]
    cmp rax,[r15+32]
    jb .overlap_next
    mov rax,[rbx+32]
    cmp rax,[r15+40]
    jbe .fail
.overlap_next:
    add rbx,128
    inc ecx
    jmp .overlap
.ok:
    lea rdi,[rel fd_sector]
    lea rsi,[rel fd_guest_header]
    mov edx,512
    call memcpy
    xor eax,eax
    jmp .out
.fail:
    mov rax,-1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Strict selector read from the already-open exact boot-ESP handle only.
; RDI=mount, RSI=path, EDX=len, RCX=64-byte output. 0=exact read,
; 1=this call's completed absence, -1=malformed/IO/short/wrong size/type.
; Never consult last_error. Drop resolver caches before proving presence/absence.
fat32_disk_guest_source_hint:
    push rbx
    push r12
    push r13
    mov rbx,rcx
    mov r12,rdi
    test rbx,rbx
    jz .fail
    call .clear
    lea rax,[rel fd_ro_ops]
    cmp [r12+fsmount.ops],rax
    jne .fail
    lea rax,[rel fd_ro_ctx]
    cmp [r12+fsmount.priv],rax
    jne .fail
    cmp dword [rax+FD_MOUNTED],1
    jne .fail
    test rsi,rsi
    jz .fail
    call fd_path_slice
    test rax,rax
    jnz .fail
    call fd_guest_path_preflight
    test rax,rax
    jnz .fail
    mov r13,rsi
    mov qword [rel fd_path_cache_ctx],0
    mov byte [rel fd_ro_ctx+FD_LOOKUP_VALID],0
    lea rdi,[rel fd_ro_ctx]
    mov byte [rel fd_resolve_strict],1
    call fat32_disk_resolve_path_lfn
    mov byte [rel fd_resolve_strict],0
    test rax,rax
    jz .present
    cmp byte [rel fd_resolve_absent],1
    jne .fail
    mov eax,1
    jmp .out
.present:
    test byte [rel fd_found_attr],0x18
    jnz .fail
    cmp qword [rel fd_found_size],64
    jne .fail
    mov rdi,r12
    mov rsi,r13
    xor edx,edx
    mov rcx,rbx
    mov r8d,64
    call fat32_disk_read_at
    cmp rax,64
    jne .fail
    xor eax,eax
    jmp .out
.fail:
    test rbx,rbx
    jz .failed
    call .clear
.failed:
    mov rax,-1
.out:
    pop r13
    pop r12
    pop rbx
    ret
.clear:
    mov qword [rbx],0
    mov qword [rbx+8],0
    mov qword [rbx+16],0
    mov qword [rbx+24],0
    mov qword [rbx+32],0
    mov qword [rbx+40],0
    mov qword [rbx+48],0
    mov qword [rbx+56],0
    ret

; Validate all component boundaries before any absence can short-circuit the
; path. RSI=bounded Z path, EDX=len; preserve them. General path character
; validation remains in the resolver; this rejects empty/dot/oversize/deep
; components even after a missing parent. No IO or cache state is consulted.
fd_guest_path_preflight:
    cmp byte [rsi],'/'
    jne .fail
    mov r8d,1
    xor r9d,r9d
    mov ecx,1
.scan:
    cmp ecx,edx
    jae .component
    cmp byte [rsi+rcx],'/'
    je .component
    inc ecx
    jmp .scan
.component:
    mov eax,ecx
    sub eax,r8d
    jz .fail
    cmp eax,FD_LFN_MAX
    ja .fail
    cmp eax,1
    jne .dotdot
    cmp byte [rsi+r8],'.'
    je .fail
.dotdot:
    cmp eax,2
    jne .depth
    cmp word [rsi+r8],0x2e2e
    je .fail
.depth:
    inc r9d
    cmp r9d,FD_PATH_DEPTH_MAX
    ja .fail
    cmp ecx,edx
    jae .ok
    inc ecx
    mov r8d,ecx
    jmp .scan
.ok:
    xor eax,eax
    ret
.fail:
    mov rax,-1
    ret

; Explicit OWNER/SPECIAL read binding only. RDI=16-byte on-media unique
; GPT partition GUID, RDX=start, RCX=count. Discover that exact identity over
; registered READ devices; no controller, device name or volume ranking.
; Independent of boot ESP and DATA contexts. Failed attempted rebind closes
; this context and selected disk; auth/busy refusals preserve the old binding.
; Same-request selector diagnostic schema for the synchronous BSP command.
; -1 = unavailable for bounded fields; full-width custody/capacity and IO_RC
; have explicit availability bits. No pointers; no independent readout API.
FD_RO_STEP_OFF equ 0
FD_RO_SCAN_INDEX equ 8
FD_RO_MATCHES equ 16
FD_RO_IO_LBA equ 24
FD_RO_IO_COUNT equ 32
FD_RO_IO_RC equ 40
FD_RO_IO_VALID equ 48
FD_RO_GEN_EXPECTED equ 56
FD_RO_GEN_BEFORE equ 64
FD_RO_GEN_AFTER equ 72
FD_RO_SSZ equ 80
FD_RO_LOGICAL equ 88
FD_RO_MAX equ 96
FD_RO_GPT_COUNT equ 104
FD_RO_GPT_SIZE equ 112
FD_RO_HEADER_CRC equ 120
FD_RO_HEADER_CALC equ 128
FD_RO_ARRAY_CRC equ 136
FD_RO_ARRAY_CALC equ 144
FD_RO_ENTRY_START equ 152
FD_RO_ENTRY_END equ 160
FD_RO_ENTRY_INDEX equ 168
FD_RO_MAX_EXPECTED equ 176
FD_RO_LOGICAL_EXPECTED equ 184
FD_RO_VALID_EXPECTED equ 192
FD_RO_VALID_GEOMETRY equ 200
FD_RO_VALID_BEFORE equ 208
FD_RO_VALID_AFTER equ 216
FD_RO_NAME equ 224
FD_RO_BYTES equ FD_RO_NAME + 64

%macro FD_RO_STEP 1
    mov qword [rel fd_ro_diag_step], %1 ; MOV preserves the predicate flags
%endmacro

fat32_disk_select_ro_exact:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 56
    call fd_ro_diag_reset
    mov  [rsp + 32], rdi
    mov  r12, rdi
    mov  r13d, esi
    mov  r14, rdx
    mov  r15, rcx
    cmp  byte [rel fd_select_press], 1  ; T5-15.4 press route: only its one caller sets it
    mov  byte [rel fd_select_press], 0
    je   .authorized
    call storage_access_request_owner
    cmp  eax, 1
    jne  .auth
    call storage_access_request_intent
    cmp  eax, SA_INTENT_SPECIAL
    je   .authorized
    call storage_access_request_local   ; read-only; only fat32_disk_local_arm reaches
    cmp  eax, 1                         ; here with this bit, naming a live removable mount
    jne  .auth
.authorized:
    call vfs_copy_busy
    test eax, eax
    jnz  .busy
    call storage_access_binding_busy
    test eax, eax
    jnz  .busy
    ; No operation can observe a partly rebound singleton. Old handles remain
    ; registered but this read context refuses while unmounted. Never restore
    ; an old context after a failure: it would silently select another volume.
    mov  byte [rel fd_ro_diag_active], 1
    lock inc qword [rel vfs_write_generation]
    mov  dword [rel vfs_disk_handle], -1
    call fd_selected_invalidate
    mov  rax, [rsp + 32]
    test rax, rax
    FD_RO_STEP 101
    jz   .fail
    mov  rdx, [rax]
    mov  rcx, [rax + 8]
    mov  [rel fd_selected_guid], rdx
    mov  [rel fd_selected_guid + 8], rcx
    or   rdx, rcx
    FD_RO_STEP 102
    jz   .fail
    test r15, r15
    FD_RO_STEP 103
    jz   .fail
    mov  rax, r15
    dec  rax
    add  rax, r14
    FD_RO_STEP 104
    jc   .fail
    mov  [rel fd_selected_start], r14
    mov  [rel fd_selected_sectors], r15
    xor  ebx, ebx
    xor  ebp, ebp                         ; matching media count
.find:
    mov  rdi, rbx
    mov  esi, BLKCAP_READ
    xor  edx, edx
    call blk_iter_after
    test rax, rax
    jz   .found
    mov  rbx, rax
    inc  qword [rel fat32_disk_ro_diag + FD_RO_SCAN_INDEX]
    call fd_ro_diag_device
    mov  [rel fd_selected_ctx + FD_DEV], rax
    mov  rdi, rax
    call blk_identify
    test rax, rax
    FD_RO_STEP 105
    jnz  .fail
    mov  rax, [rbx + dev.info]
    test rax, rax
    FD_RO_STEP 106
    jz   .fail
    call fd_ro_diag_geometry
    mov  edx, [rax + blk_info.sector_size]
    cmp  edx, 512
    je   .scan_geometry
    ; Probe only one complete, bounded native 4Kn sector. A non-GPT primary
    ; header establishes absence by the same rule as 512-byte media. A GPT
    ; on unsupported geometry still refuses: never skip a possible clone.
    cmp  edx, 4096
    FD_RO_STEP 107
    jne  .fail
    cmp  dword [rax + blk_info.logical_sector_bytes], 4096
    FD_RO_STEP 107
    jne  .fail
.scan_geometry:
    mov  [rel fd_selected_sector], edx
    mov  rdx, [rax + blk_info.media_generation]
    test rdx, rdx
    FD_RO_STEP 108
    jz   .fail
    mov  [rel fd_selected_generation], rdx
    mov  rdx, [rax + blk_info.lba_max]
    mov  [rel fd_selected_max], rdx
    mov  edx, [rax + blk_info.logical_sector_bytes]
    mov  [rel fd_selected_logical], edx
    ; Not GPT is absent, not a fallback. An unreadable medium or malformed GPT
    ; cannot establish uniqueness. Validate the complete supported table.
    lea  rdi, [rel fd_selected_ctx]
    mov  esi, 1
    mov  edx, 1
    lea  rcx, [rel fd_selected_header]
    call fd_read_sectors
    test rax, rax
    FD_RO_STEP 109
    jnz  .fail
    mov  rax, 0x5452415020494645
    cmp  [rel fd_selected_header], rax
    jne  .find
    cmp  dword [rel fd_selected_sector], 512
    FD_RO_STEP 107
    jne  .fail                            ; no unsupported GPT may hide a clone
    mov  edi, 1                           ; scanning: foreign geometry is searched, never selected
    call fd_selected_partition
    test rax, rax
    FD_RO_STEP 110
    js   .fail
    jnz  .find                            ; CRC-valid GPT with no matching GUID
    inc  ebp
    mov  [rel fat32_disk_ro_diag + FD_RO_MATCHES], rbp
    cmp  ebp, 1
    FD_RO_STEP 111
    jne  .fail                            ; cloned identity, no display-name tiebreak
    mov  rax, [rel fat32_disk_ro_diag + FD_RO_SCAN_INDEX]
    mov  [rsp + 8], rax
    mov  [rsp + 40], rbx
    call fd_ro_diag_candidate_save
    mov  rax, [rel fd_selected_generation]
    mov  [rsp], rax
    mov  rax, [rel fd_selected_max]
    mov  [rsp + 16], rax
    mov  eax, [rel fd_selected_logical]
    mov  [rsp + 24], eax
    jmp  .find
.found:
    mov  dword [rel fd_selected_sector], 512 ; every admissible candidate is 512-byte
    cmp  ebp, 1
    FD_RO_STEP 112
    jne  .fail
    mov  rax, [rsp + 8]
    mov  [rel fat32_disk_ro_diag + FD_RO_SCAN_INDEX], rax
    call fd_ro_diag_candidate_restore
    mov  rbp, [rsp + 40]
    mov  [rel fd_selected_ctx + FD_DEV], rbp
    mov  [rel fd_selected_start], r14
    mov  [rel fd_selected_sectors], r15
    mov  rax, [rsp]
    mov  [rel fd_selected_generation], rax
    mov  rax, [rsp + 16]
    mov  [rel fd_selected_max], rax
    mov  eax, [rsp + 24]
    mov  [rel fd_selected_logical], eax
    xor  edi, edi                         ; the selected medium: exact geometry only
    call fd_selected_partition
    test eax, eax
    FD_RO_STEP 113
    jnz  .fail
    lea  rax, [rel fd_selected_guid]
    mov  [rel fd_want_guid], rax
    mov  dword [rel fd_want_seen], 0
    mov  byte [rel fd_want_fault], 0
    lea  rdi, [rel fd_selected_ctx]
    call fat32_disk_mount_ctx
    mov  qword [rel fd_want_guid], 0
    test rax, rax
    FD_RO_STEP 114
    jnz  .fail
    cmp  byte [rel fd_want_fault], 0
    FD_RO_STEP 115
    jne  .fail
    mov  rax, [rel fd_selected_start]
    cmp  rax, [rel fd_selected_ctx + FD_PART_LBA]
    FD_RO_STEP 116
    jne  .fail
    mov  rax, [rel fd_selected_sectors]
    cmp  rax, [rel fd_selected_ctx + FD_PART_SECTORS]
    FD_RO_STEP 117
    jne  .fail
    lea  rdi, [rel fd_selected_ctx]
    call fd_selected_current
    test rax, rax
    FD_RO_STEP 118
    jnz  .fail
    mov  edi, [rel fd_selected_handle]
    test edi, edi
    jz   .register
    dec  edi
    call vfs_mount_ptr
    test rax, rax
    FD_RO_STEP 119
    jz   .fail
    lea  rdx, [rel fd_selected_ops]
    cmp  [rax + fsmount.ops], rdx
    FD_RO_STEP 120
    jne  .fail
    lea  rdx, [rel fd_selected_ctx]
    cmp  [rax + fsmount.priv], rdx
    FD_RO_STEP 121
    jne  .fail
    jmp  .publish
.register:
    call fd_selected_build_ops
    lea  rdi, [rel fd_selected_ops]
    lea  rsi, [rel fd_selected_ctx]
    lea  rdx, [rel str_fd_selected_name]
    call vfs_register_mount
    test rax, rax
    FD_RO_STEP 122
    js   .fail
    inc  eax
    mov  [rel fd_selected_handle], eax
.publish:
    lea  rdi, [rel fd_selected_ctx]
    call fd_read_cache_drop
    mov  eax, [rel fd_selected_handle]
    dec  eax
    mov  [rel vfs_disk_handle], eax
    jmp  .out
.fail:
    call fd_ro_diag_fail
    call fd_selected_invalidate
    mov  rax, -1
    jmp  .out
.busy:
    mov  rax, -2
    jmp  .out
.auth:
    mov  rax, -3
.out:
    mov  byte [rel fd_ro_diag_active], 0
    add  rsp, 56
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Bounded CRC-checked GPT validation for the explicit read-only binding.
; EDI = 1 while scanning the other media for a clone, 0 for the selected one.
; RAX = 0 the one exact entry, 1 absent, -1 refused (diag step).
fd_selected_partition:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 48                           ; GPT CRC/first/last/entries LBA, scan mode, foreign
    mov  [rsp + 32], dil
    mov  byte [rsp + 33], 0
    mov  r12, [rel fd_selected_start]
    mov  r13, [rel fd_selected_sectors]
    lea  r14, [r12 + r13 - 1]               ; overflow checked by caller
    xor  ebp, ebp                          ; number of exact supported matches
    mov  dword [rsp + 4], 0                ; occupied entries overlapping requested extent
    lea  rdi, [rel fd_selected_ctx]
    mov  esi, 1
    mov  edx, 1
    lea  rcx, [rel fd_selected_header]
    call fd_read_sectors
    test rax, rax
    FD_RO_STEP 207
    jnz  .fail
    lea  rbx, [rel fd_selected_header]
    mov  rax, 0x5452415020494645
    cmp  [rbx], rax
    FD_RO_STEP 208
    jne  .fail
    cmp  dword [rbx + 8], 0x10000
    FD_RO_STEP 209
    jne  .fail
    cmp  dword [rbx + 20], 0
    FD_RO_STEP 210
    jne  .fail
    cmp  qword [rbx + 24], 1
    FD_RO_STEP 211
    jne  .fail
    mov  rax, [rel fd_selected_ctx + FD_DEV]
    mov  rax, [rax + dev.info]
    mov  rax, [rax + blk_info.lba_max]
    cmp  [rbx + 32], rax
    je   .geometry_exact
    ; The header names another device extent: a raw member of a firmware RAID
    ; set carrying the volume's GPT (MSI VMD RAID0), or a resized clone. Such
    ; a medium is never selected. While scanning, its fully CRC-checked table
    ; is still searched: the requested GUID anywhere in it refuses (237).
    cmp  byte [rsp + 32], 0
    FD_RO_STEP 212
    je   .fail
    mov  byte [rsp + 33], 1
    lea  rdi, [rel str_fd_foreign_gpt]
    call serial_string
    mov  rdi, [rbx + 32]
    call serial_hex64
    lea  rdi, [rel str_fd_foreign_gpt_max]
    call serial_string
    mov  rdi, [rel fd_selected_ctx + FD_DEV]
    mov  rdi, [rdi + dev.info]
    mov  rdi, [rdi + blk_info.lba_max]
    call serial_hex64
    lea  rdi, [rel str_fd_foreign_gpt_tag]
    call serial_string
    call serial_newline
.geometry_exact:
    mov  esi, [rbx + 12]
    cmp  esi, 92
    FD_RO_STEP 213
    jb   .fail
    cmp  esi, 512
    FD_RO_STEP 214
    ja   .fail
    mov  r15d, [rbx + 16]
    mov  [rel fat32_disk_ro_diag + FD_RO_HEADER_CRC], r15
    mov  dword [rbx + 16], 0
    mov  rdi, rbx
    call hotpatch_crc32
    mov  [rel fat32_disk_ro_diag + FD_RO_HEADER_CALC], rax
    cmp  eax, r15d
    FD_RO_STEP 215
    jne  .fail
    mov  rax, [rbx + 40]                    ; first usable
    cmp  rax, 2
    FD_RO_STEP 216
    jb   .fail
    mov  [rsp + 8], rax
    mov  rax, [rbx + 48]                    ; last usable
    cmp  rax, [rbx + 32]
    FD_RO_STEP 217
    jae  .fail
    cmp  rax, [rsp + 8]
    FD_RO_STEP 218
    jb   .fail
    mov  [rsp + 16], rax
    mov  rax, [rbx + 56]
    or   rax, [rbx + 64]
    FD_RO_STEP 219
    jz   .fail
    mov  eax, [rbx + 80]
    mov  [rel fat32_disk_ro_diag + FD_RO_GPT_COUNT], rax
    mov  eax, [rbx + 84]
    mov  [rel fat32_disk_ro_diag + FD_RO_GPT_SIZE], rax
    cmp  dword [rbx + 84], 128
    FD_RO_STEP 220
    jne  .fail
    mov  r15d, [rbx + 80]
    test r15d, r15d
    FD_RO_STEP 221
    jz   .fail
    cmp  r15d, 128
    FD_RO_STEP 222
    ja   .fail
    mov  eax, [rbx + 88]
    mov  [rsp], eax                        ; array CRC
    mov  [rel fat32_disk_ro_diag + FD_RO_ARRAY_CRC], rax
    mov  rax, [rbx + 72]
    cmp  rax, 2
    FD_RO_STEP 223
    jb   .fail
    mov  [rsp + 24], rax
    mov  edx, r15d
    add  edx, 3
    shr  edx, 2                            ; ceil(entries*128/512)
    add  rax, rdx
    FD_RO_STEP 224
    jc   .fail
    cmp  rax, [rsp + 8]                    ; complete array before usable area
    FD_RO_STEP 225
    ja   .fail
    lea  rdi, [rel fd_selected_ctx]
    mov  rsi, [rsp + 24]
    lea  rcx, [rel fd_selected_entries]
    call fd_read_sectors
    test rax, rax
    FD_RO_STEP 226
    jnz  .fail
    lea  rdi, [rel fd_selected_entries]
    mov  esi, r15d
    shl  esi, 7
    call hotpatch_crc32
    mov  [rel fat32_disk_ro_diag + FD_RO_ARRAY_CALC], rax
    cmp  eax, [rsp]
    FD_RO_STEP 227
    jne  .fail
    lea  rbx, [rel fd_selected_entries]
.gpt_entry:
    mov  rax, [rbx]
    or   rax, [rbx + 8]
    jz   .gpt_next
    mov  rsi, [rbx + 32]
    mov  rdx, [rbx + 40]
    mov  [rel fat32_disk_ro_diag + FD_RO_ENTRY_START], rsi
    mov  [rel fat32_disk_ro_diag + FD_RO_ENTRY_END], rdx
    mov  rax, rbx
    lea  rcx, [rel fd_selected_entries]
    sub  rax, rcx
    shr  rax, 7
    mov  [rel fat32_disk_ro_diag + FD_RO_ENTRY_INDEX], rax
    cmp  rdx, rsi
    FD_RO_STEP 228
    jb   .fail
    cmp  rsi, [rsp + 8]
    FD_RO_STEP 229
    jb   .fail
    cmp  rdx, [rsp + 16]
    FD_RO_STEP 230
    ja   .fail
    cmp  rdx, r12
    jb   .overlap_counted
    cmp  rsi, r14
    ja   .overlap_counted
    inc  dword [rsp + 4]
.overlap_counted:
    ; The requested GUID must occur exactly once, even in another type or
    ; nonoverlapping extent. Every overlapping occupied entry must be it.
    mov  rax, [rbx + 16]
    cmp  rax, [rel fd_selected_guid]
    jne  .gpt_next
    mov  rax, [rbx + 24]
    cmp  rax, [rel fd_selected_guid + 8]
    jne  .gpt_next
    cmp  byte [rsp + 33], 0
    FD_RO_STEP 237
    jne  .fail                             ; the GUID on foreign geometry: neither ignored nor selected
    cmp  rsi, r12
    FD_RO_STEP 231
    jne  .fail
    cmp  rdx, r14
    FD_RO_STEP 232
    jne  .fail
    mov  rax, FD_ESP_GUID_LO
    cmp  [rbx], rax
    jne  .basic
    mov  rax, FD_ESP_GUID_HI
    cmp  [rbx + 8], rax
    je   .match
.basic:
    mov  rax, 0x4433b9e5ebd0a0a2
    cmp  [rbx], rax
    FD_RO_STEP 233
    jne  .fail
    mov  rax, 0xc79926b7b668c087
    cmp  [rbx + 8], rax
    FD_RO_STEP 234
    jne  .fail
.match:
    inc  ebp
    jmp  .gpt_next
.gpt_next:
    add  rbx, 128
    dec  r15d
    jnz  .gpt_entry
    test ebp, ebp
    jz   .absent
    cmp  ebp, 1
    FD_RO_STEP 235
    jne  .fail
    cmp  dword [rsp + 4], 1
    FD_RO_STEP 236
    jne  .fail
.ok:
    ; Retain the validated GPT before the shared scratch buffer reads PMBR.
    ; This snapshot grants no authority to the read-only selected mount.
    lea rdi, [rel fd_selected_gpt_saved]
    lea rsi, [rel fd_selected_header]
    mov edx, 512
    call memcpy
    mov eax, [rel fat32_disk_ro_diag + FD_RO_HEADER_CRC]
    mov [rel fd_selected_gpt_saved + 16], eax
    ; A fully CRC/geometry-checked table with no requested GUID proves absence
    ; independently of a stale PMBR. Only a matching medium can be admitted;
    ; it must still pass every protective/non-hybrid MBR check before use.
    lea  rdi, [rel fd_selected_ctx]
    xor  esi, esi
    mov  edx, 1
    lea  rcx, [rel fd_selected_header]
    call fd_read_sectors
    test rax, rax
    FD_RO_STEP 201
    jnz  .fail
    cmp  word [rel fd_selected_header + 510], 0xAA55
    FD_RO_STEP 202
    jne  .fail
    lea  rbx, [rel fd_selected_header + 446]
    cmp  byte [rbx + 4], 0xEE
    FD_RO_STEP 203
    jne  .fail
.protective:
    cmp  dword [rbx + 8], 1
    FD_RO_STEP 204
    jne  .fail
    ; Windows may retain the full-u32 protective sentinel on a smaller disk.
    ; It is not partition authority: all GPT CRC/geometry/exact-entry checks
    ; below remain mandatory, including rejection of hybrid MBR entries.
    cmp  dword [rbx + 12], 0xFFFFFFFF
    je   .protective_span_ok
    mov  rax, [rel fd_selected_ctx + FD_DEV]
    mov  rax, [rax + dev.info]
    mov  rax, [rax + blk_info.lba_max]
    mov  edx, 0xFFFFFFFF
    cmp  rax, rdx
    cmova rax, rdx
    cmp  eax, [rbx + 12]                  ; otherwise require exact capped span
    FD_RO_STEP 205
    jne  .fail
.protective_span_ok:
    mov  ecx, 3
.pmbr:
    add  rbx, 16
    cmp  byte [rbx + 4], 0
    FD_RO_STEP 206
    jne  .fail
    loop .pmbr
    xor  eax, eax
    jmp  .out
.absent:
    mov  eax, 1
    jmp  .out
.fail:
    call fd_ro_diag_fail
    mov  rax, -1
.out:
    add  rsp, 48
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret


; Fixed diagnostic state exists only for the synchronous selector call. The
; command serializes it immediately on -1, never via a history/readout API.
fd_ro_diag_reset:
    pushfq
    push rax
    push rcx
    push rdi
    lea  rdi, [rel fat32_disk_ro_diag]
    mov  rcx, FD_RO_BYTES / 8
    mov  rax, -1
    rep stosq
    mov  qword [rel fat32_disk_ro_diag + FD_RO_STEP_OFF], 0
    mov  qword [rel fat32_disk_ro_diag + FD_RO_MATCHES], 0
    mov  qword [rel fat32_disk_ro_diag + FD_RO_IO_VALID], 0
    mov  dword [rel fat32_disk_ro_diag + FD_RO_NAME], 0x616e
    mov  byte [rel fd_ro_diag_active], 0
    mov  qword [rel fd_ro_diag_step], 0
    pop  rdi
    pop  rcx
    pop  rax
    popfq
    ret

fd_ro_diag_fail:
    pushfq
    push rax
    cmp  byte [rel fd_ro_diag_active], 1
    jne  .out
    cmp  qword [rel fat32_disk_ro_diag + FD_RO_STEP_OFF], 0
    jne  .out
    mov  rax, [rel fd_ro_diag_step]
    mov  [rel fat32_disk_ro_diag + FD_RO_STEP_OFF], rax
.out:
    pop  rax
    popfq
    ret

fd_ro_diag_bpb_result:
    pushfq
    test eax, eax
    jz   .out
    call fd_ro_diag_fail
.out:
    popfq
    ret

; RBX is an actual healthy READ iterator result, before any transfer.
fd_ro_diag_device:
    pushfq
    push rax
    push rcx
    push rsi
    push rdi
    lea  rdi, [rel fat32_disk_ro_diag + FD_RO_IO_LBA]
    mov  rcx, (FD_RO_NAME - FD_RO_IO_LBA) / 8
    mov  rax, -1
    rep stosq
    mov  qword [rel fat32_disk_ro_diag + FD_RO_IO_VALID], 0
    mov  dword [rdi], 0x616e
    mov  rsi, [rbx + dev.name]
    test rsi, rsi
    jz   .out
    cmp  byte [rsi], 0
    je   .out
    mov  ecx, 63
.next:
    lodsb
    test al, al
    jz   .end
    cmp  al, 33
    jb   .unsafe
    cmp  al, 126
    ja   .unsafe
    cmp  al, '='
    jne  .put
.unsafe:
    mov  al, '?'
.put:
    stosb
    loop .next
.end:
    mov  byte [rdi], 0
.out:
    pop  rdi
    pop  rsi
    pop  rcx
    pop  rax
    popfq
    ret

; Save the already bounded name at the actual match. Restoring the candidate
; after scanning other devices must not dereference its potentially removed node.
fd_ro_diag_candidate_save:
    pushfq
    push rcx
    push rsi
    push rdi
    lea  rsi, [rel fat32_disk_ro_diag + FD_RO_NAME]
    lea  rdi, [rel fd_ro_diag_candidate_name]
    mov  ecx, 64 / 8
    rep movsq
    pop  rdi
    pop  rsi
    pop  rcx
    popfq
    ret

fd_ro_diag_candidate_restore:
    pushfq
    push rax
    push rcx
    push rsi
    push rdi
    lea  rdi, [rel fat32_disk_ro_diag + FD_RO_IO_LBA]
    mov  rcx, (FD_RO_NAME - FD_RO_IO_LBA) / 8
    mov  rax, -1
    rep stosq
    mov  qword [rel fat32_disk_ro_diag + FD_RO_IO_VALID], 0
    lea  rsi, [rel fd_ro_diag_candidate_name]
    mov  ecx, 64 / 8
    rep movsq
    pop  rdi
    pop  rsi
    pop  rcx
    pop  rax
    popfq
    ret

fd_ro_diag_guard_begin:
    pushfq
    push rax
    cmp  byte [rel fd_ro_diag_active], 1
    jne  .out
    cmp  qword [rel fat32_disk_ro_diag + FD_RO_STEP_OFF], 0
    jne  .out
    mov  qword [rel fat32_disk_ro_diag + FD_RO_GEN_AFTER], -1
    mov  qword [rel fat32_disk_ro_diag + FD_RO_VALID_AFTER], 0
    mov  qword [rel fat32_disk_ro_diag + FD_RO_VALID_EXPECTED], 1
    mov  rax, [rel fd_selected_generation]
    mov  [rel fat32_disk_ro_diag + FD_RO_GEN_EXPECTED], rax
    mov  rax, [rel fd_selected_max]
    mov  [rel fat32_disk_ro_diag + FD_RO_MAX_EXPECTED], rax
    mov  eax, [rel fd_selected_logical]
    mov  [rel fat32_disk_ro_diag + FD_RO_LOGICAL_EXPECTED], rax
.out:
    pop  rax
    popfq
    ret

; RAX is info from the actual selected-context registry/identify path.
fd_ro_diag_geometry:
    pushfq
    push rdx
    cmp  byte [rel fd_ro_diag_active], 1
    jne  .out
    cmp  qword [rel fat32_disk_ro_diag + FD_RO_STEP_OFF], 0
    jne  .out
    mov  qword [rel fat32_disk_ro_diag + FD_RO_VALID_GEOMETRY], 1
    mov  qword [rel fat32_disk_ro_diag + FD_RO_VALID_AFTER], 1
    mov  rdx, [rax + blk_info.media_generation]
    mov  [rel fat32_disk_ro_diag + FD_RO_GEN_AFTER], rdx
    mov  edx, [rax + blk_info.sector_size]
    mov  [rel fat32_disk_ro_diag + FD_RO_SSZ], rdx
    mov  edx, [rax + blk_info.logical_sector_bytes]
    mov  [rel fat32_disk_ro_diag + FD_RO_LOGICAL], rdx
    mov  rdx, [rax + blk_info.lba_max]
    mov  [rel fat32_disk_ro_diag + FD_RO_MAX], rdx
.out:
    pop  rdx
    popfq
    ret

fd_ro_diag_io_begin:
    pushfq
    push rax
    cmp  byte [rel fd_ro_diag_active], 1
    jne  .out
    cmp  qword [rel fat32_disk_ro_diag + FD_RO_STEP_OFF], 0
    jne  .out
    mov  [rel fat32_disk_ro_diag + FD_RO_IO_LBA], rsi
    mov  [rel fat32_disk_ro_diag + FD_RO_IO_COUNT], rdx
    mov  qword [rel fat32_disk_ro_diag + FD_RO_IO_VALID], 0
    mov  rax, [rel fat32_disk_ro_diag + FD_RO_GEN_AFTER]
    mov  [rel fat32_disk_ro_diag + FD_RO_GEN_BEFORE], rax
    mov  rax, [rel fat32_disk_ro_diag + FD_RO_VALID_AFTER]
    mov  [rel fat32_disk_ro_diag + FD_RO_VALID_BEFORE], rax
    mov  qword [rel fat32_disk_ro_diag + FD_RO_VALID_AFTER], 0
    mov  qword [rel fat32_disk_ro_diag + FD_RO_GEN_AFTER], -1
.out:
    pop  rax
    popfq
    ret

fd_ro_diag_io_end:
    pushfq
    cmp  byte [rel fd_ro_diag_active], 1
    jne  .out
    cmp  qword [rel fat32_disk_ro_diag + FD_RO_STEP_OFF], 0
    jne  .out
    mov  [rel fat32_disk_ro_diag + FD_RO_IO_RC], rax
    mov  qword [rel fat32_disk_ro_diag + FD_RO_IO_VALID], 1
.out:
    popfq
    ret

fd_selected_invalidate:
    mov  byte [rel fd_owned_active], 0
    mov  byte [rel fd_owned_dirty], 0
    mov  dword [rel fd_selected_sector], 512
    mov  dword [rel fd_selected_ctx + FD_MOUNTED], 0
    mov  qword [rel fd_selected_generation], 0
    lea  rdi, [rel fd_selected_ctx]
    jmp  fd_invalidate_caches

; Preserve all argument registers: usable at cached fs_ops and every actual
; sector transfer/fallback boundary. Re-find registry membership before any
; saved device pointer is dereferenced. No identity-only cache can survive a
; media generation, geometry, health or READ capability change.
fd_selected_current:
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
    lea  rax, [rel fd_selected_ctx]
    cmp  rdi, rax
    jne  .ok
    call fd_ro_diag_guard_begin
    mov  r12, [rdi + FD_DEV]
    xor  ebx, ebx
.next:
    mov  rdi, rbx
    mov  esi, BLKCAP_READ
    xor  edx, edx
    call blk_iter_after
    test rax, rax
    FD_RO_STEP 401
    jz   .fail
    mov  rbx, rax
    cmp  rbx, r12
    jne  .next
    mov  rax, [rbx + dev.info]
    test rax, rax
    FD_RO_STEP 402
    jz   .fail
    call fd_ro_diag_geometry
    mov  rdx, [rel fd_selected_generation]
    test rdx, rdx
    FD_RO_STEP 403
    jz   .fail
    cmp  rdx, [rax + blk_info.media_generation]
    FD_RO_STEP 404
    jne  .fail
    mov  edx, [rel fd_selected_sector]      ; 4096 only during the one-sector absence probe
    cmp  [rax + blk_info.sector_size], edx
    FD_RO_STEP 405
    jne  .fail
    mov  edx, [rel fd_selected_logical]
    cmp  edx, [rax + blk_info.logical_sector_bytes]
    FD_RO_STEP 406
    jne  .fail
    mov  rdx, [rel fd_selected_max]
    cmp  rdx, [rax + blk_info.lba_max]
    FD_RO_STEP 407
    jne  .fail
    ; A sealed read view must not survive release/reset/reload or owner lock.
    ; This getter only reads the cached catalog; no firmware or media I/O.
    cmp  byte [rel fd_owned_active], 1
    jne  .ok
    mov  edi, [rel fd_owned_index]
    lea  rsi, [rel fd_owned_token]
    call vol_owner_read_catalog
    cmp  eax, 1
    jne  .fail
    mov  rax, [rel fd_owned_token]
    cmp  rax, [rel fd_owned_read + 48]
    jne  .fail
    mov  rax, [rel fd_owned_token + 8]
    cmp  rax, [rel fd_owned_read + 56]
    jne  .fail
.ok:
    xor  eax, eax
    jmp  .out
.fail:
    call fd_ro_diag_fail
    call fd_selected_invalidate
    mov  rax, -1
.out:
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rcx
    pop  rdx
    pop  rsi
    pop  rdi
    pop  r12
    pop  rbx
    ret

; Both consumers' custody rules must hold around each physical read.
fd_read_custody:
    call ext_cp_guard_fat_read
    test rax, rax
    jnz  .out
    mov  rdi, r12
    call fd_selected_current
    test rax, rax
    jnz .out
    call fd_scratch_current
    test rax, rax
    jnz .out
    call fd_data_current
.out:
    ret

; This mount is published only after exact validation. An ordinary mount call
; may check/drop read caches, never choose a different medium or refresh its
; generation. New binding requires the explicit OWNER/SPECIAL API above.
fd_selected_mount:
    push rdi
    mov  rdi, [rdi + fsmount.priv]
    call fd_selected_current
    test rax, rax
    jnz  .out
    cmp  dword [rdi + FD_MOUNTED], 1
    jne  .fail
    call fd_invalidate_caches
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  rdi
    ret

fd_selected_build_ops:
    lea rdi, [rel fd_selected_ops]
    xor eax, eax
    mov ecx, fs_ops_size / 8
    rep stosq
    lea rax, [rel str_fd_selected_backend]
    mov [rel fd_selected_ops + fs_ops.name], rax
    lea rax, [rel fd_selected_mount]
    mov [rel fd_selected_ops + fs_ops.mount], rax
    lea rax, [rel fd_selected_stat]
    mov [rel fd_selected_ops + fs_ops.stat], rax
    lea rax, [rel fd_selected_read_at]
    mov [rel fd_selected_ops + fs_ops.read_at], rax
    lea rax, [rel fd_selected_info]
    mov [rel fd_selected_ops + fs_ops.info], rax
    lea rax, [rel fd_selected_list_root]
    mov [rel fd_selected_ops + fs_ops.list_root], rax
    lea rax, [rel fd_selected_stat_path]
    mov [rel fd_selected_ops + fs_ops.stat_path], rax
    lea rax, [rel fd_selected_replace_meta]
    mov [rel fd_selected_ops + fs_ops.replace_meta], rax
    lea rax, [rel fd_selected_read_at_path]
    mov [rel fd_selected_ops + fs_ops.read_at_path], rax
    lea rax, [rel fd_selected_list_dir]
    mov [rel fd_selected_ops + fs_ops.list_dir], rax
    lea rax, [rel fd_selected_file_extents]
    mov [rel fd_selected_ops + fs_ops.file_extents], rax
    lea rax, [rel fd_selected_extent_check]
    mov [rel fd_selected_ops + fs_ops.extent_check], rax
    ret
fd_selected_stat:
    push rdi
    mov rdi, [rdi + fsmount.priv]
    call fd_exact_read_current
    pop rdi
    test rax, rax
    jnz .fail
    jmp fat32_disk_stat
.fail:
    mov rax, -1
    ret
fd_selected_read_at:
    push rdi
    mov rdi, [rdi + fsmount.priv]
    call fd_exact_read_current
    pop rdi
    test rax, rax
    jnz .fail
    jmp fat32_disk_read_at
.fail:
    mov rax, -1
    ret
fd_selected_info:
    push rdi
    mov rdi, [rdi + fsmount.priv]
    call fd_exact_read_current
    pop rdi
    test rax, rax
    jnz .fail
    jmp fat32_disk_info
.fail:
    mov rax, -1
    ret
fd_selected_list_root:
    push rdi
    mov rdi, [rdi + fsmount.priv]
    call fd_exact_read_current
    pop rdi
    test rax, rax
    jnz .fail
    jmp fat32_disk_list_root
.fail:
    mov rax, -1
    ret
fd_selected_stat_path:
    push rdi
    mov rdi, [rdi + fsmount.priv]
    call fd_exact_read_current
    pop rdi
    test rax, rax
    jnz .fail
    jmp fat32_disk_stat_path
.fail:
    mov rax, -1
    ret
fd_selected_replace_meta:
    push rdi
    mov rdi, [rdi + fsmount.priv]
    call fd_selected_current
    pop rdi
    test rax, rax
    jnz .fail
    jmp fat32_disk_replace_meta
.fail:
    mov rax, -1
    ret
fd_selected_read_at_path:
    push rdi
    mov rdi, [rdi + fsmount.priv]
    call fd_exact_read_current
    pop rdi
    test rax, rax
    jnz .fail
    jmp fat32_disk_read_at_path
.fail:
    mov rax, -1
    ret
fd_selected_list_dir:
    push rdi
    mov rdi, [rdi + fsmount.priv]
    call fd_exact_read_current
    pop rdi
    test rax, rax
    jnz .fail
    jmp fat32_disk_list_dir
.fail:
    mov rax, -1
    ret
fd_selected_file_extents:
    push rdi
    mov rdi, [rdi + fsmount.priv]
    call fd_exact_read_current
    pop rdi
    test rax, rax
    jnz .fail
    jmp fat32_disk_file_extents
.fail:
    mov rax, -1
    ret
fd_selected_extent_check:
    push rdi
    mov rdi, [rdi + fsmount.priv]
    call fd_exact_read_current
    pop rdi
    test rax, rax
    jnz .fail
    jmp fat32_disk_extent_check
.fail:
    mov rax, -1
    ret

; Mutations are permitted only on the descriptor-exact DATA context.  The
; QEMU fixture has a separate, boot-local arm that can never name a real dev*.
fd_mutation_authorized:
    call ue_context
    test eax,eax
    jnz ue_mutation
    lea  rax, [rel fd_dir_ctx]
    cmp  rdi, rax
    jne  .ordinary
    cmp  dword [rel fd_dir_gate], 1
    jne  .fail
    mov  rdi, [rel fd_dir_owner]
    test rdi, rdi
    jz   .fail
    cmp  dword [rdi + FD_TX_BUSY], 1
    jne  .fail
    ; Only our internal, locked view can inherit the original DATA authority.
    jmp  fd_mutation_authorized
.ordinary:
    mov  dword [rel fat32_disk_last_error], FD_ERR_NOT_EXACT
    cmp  dword [rdi + FD_MOUNTED], 1
    jne  .fail
    lea  rax, [rel fd_kat_ctx]
    cmp  rdi, rax
    jne  .production
    cmp  byte [rel fd_kat_write_mode], 1
    jne  .fail
    jmp  .device
.production:
    lea  rax, [rel fd_media_ctx]
    cmp  rdi, rax
    jne  .data_context
    ; This private mount is armed only by the boot-local hypervisor fixture
    ; after exact media-signature and geometry validation. No verb can arm it.
    cmp  byte [rel fd_media_armed], 1
    jne  .fail
    mov  rax, [rdi + FD_DEV]
    cmp  rax, [rel fd_media_dev]
    jne  .fail
    jmp  .device
.data_context:
    lea  rax, [rel fd_scratch_ctx]
    cmp  rdi, rax
    jne  .descriptor_context
    call fd_scratch_write_gate
    test rax, rax
    jnz  .fail
    jmp  .device
.descriptor_context:
    lea  rax, [rel fd_data_ctx]
    cmp  rdi, rax
    jne  .legacy_descriptor
    call fd_data_write_gate
    test rax, rax
    jnz  .fail
    jmp  .device
.legacy_descriptor:
    lea  rax, [rel fat32_disk_ctx]
    cmp  rdi, rax
    jne  .fail
    cmp  byte [rdi + FD_EXACT_BOUND], 1
    jne  .fail
    mov  rax, [rdi + FD_DEV]
    cmp  rax, [rel fat32_disk_selected_dev]
    jne  .fail
    mov  eax, [rdi + FD_VOLUME_ID]
    cmp  eax, [rel fat32_disk_selected_volume_id]
    jne  .fail
.device:
    cmp  dword [rdi + FD_NFATS], 2
    jne  .fail
    lea  rax, [rel fd_kat_ctx]
    cmp  rdi, rax
    je   .pinned                         ; a KAT's RAM device has no identity to pin
    call fd_volume_pin
    test rax, rax
    jnz  .fail
.pinned:
    mov  rax, [rdi + FD_DEV]
    test rax, rax
    jz   .fail
    cmp  dword [rax + dev.health], HEALTH_OK
    jne  .fail
    mov  rax, [rax + dev.info]
    test rax, rax
    jz   .fail
    test dword [rax + blk_info.flags], BLKF_RO
    jnz  .fail
    mov  rax, [rax + blk_info.media_generation]
    test rax, rax
    jz   .fail                            ; unknown identity can be read, never written
    cmp  rax, [rdi + FD_MOUNT_GEN]
    jne  .fail                            ; old geometry is not authority over a new medium
    xor  eax, eax
    ret
.fail:
    mov  rax, -1
    ret

; RDI=ctx -> RAX 0 / -1. The MSI pin, at the one tail every FAT write passes. DATA
; and scratch both present their live GPT identity; anything else refuses on an MSI.
fd_volume_pin:
    push rdi
    push rsi
    push rdx
    push rcx
    push r8
    mov  r8, [rdi + FD_PART_SECTORS]
    mov  rcx, [rdi + FD_PART_LBA]
    lea  rsi, [rdi + FD_DISK_GUID]
    lea  rdx, [rdi + FD_PART_GUID]       ; live GPT identity for DATA and scratch alike
    mov  rdi, [rdi + FD_DEV]
    call volume_pin_admits
    pop  r8
    pop  rcx
    pop  rdx
    pop  rsi
    pop  rdi
    ret

; RDI=name11, RSI=ctx. T5-15.4 (root 88569, SEC 88677 V-C1): the VOLUME decides
; where a write may go, this floor decides only what a name may be. Service
; contexts pass through fd_data_name_gate. Every other context refuses PaOS's own
; stores and journals, here and not at the verb floor, because fd_tx_recover,
; copy, update and rename all arrive without passing a verb. Non-command VFS
; callers and journal names read from media take the same check.
fd_scratch_name_allowed:
    call ue_name_gate
    cmp eax,1
    je .yes
    test eax,eax
    js .no
    call fd_data_name_gate
    cmp eax, 1
    je .yes
    test eax, eax
    js .no
    lea  rax, [rel fd_dir_ctx]
    cmp  rsi, rax
    jne  .protected
    cmp  dword [rel fd_dir_gate], 1
    jne  .no
.protected:
    lea  rdx, [rel fd_protected_names]
    mov  ecx, FD_PROTECTED_COUNT
.entry:
    mov  rax, [rdi]
    cmp  rax, [rdx]
    jne  .other
    mov  eax, [rdi + 7]
    cmp  eax, [rdx + 7]
    je   .no
.other:
    add  rdx, 11
    dec  ecx
    jnz  .entry
    ; Canonical short name: a real base, then only the set fd_component_to_short
    ; produces, with padding only at the end of each part.
    xor  ecx, ecx
    xor  edx, edx
    cmp  byte [rdi], ' '
    je   .no
.char:
    cmp  ecx, 8
    jne  .same_part
    xor  edx, edx                         ; the extension has its own padding
.same_part:
    cmp  ecx, 11
    jae  .yes
    movzx eax, byte [rdi + rcx]
    cmp  al, ' '
    je   .padding
    test edx, edx
    jnz  .no
    cmp  al, '_'
    je   .next
    cmp  al, '-'
    je   .next
    cmp  al, '~'
    je   .next
    cmp  al, 'A'
    jb   .digit
    cmp  al, 'Z'
    jbe  .next
    jmp  .no
.digit:
    cmp  al, '0'
    jb   .no
    cmp  al, '9'
    ja   .no
.next:
    inc  ecx
    jmp  .char
.padding:
    mov  edx, 1
    inc  ecx
    jmp  .char
.yes:
    xor  eax, eax
    ret
.no:
    mov  dword [rel fat32_disk_last_error], FD_ERR_ALLOWLIST
    mov  rax, -1
    ret

; G1b (RDI = the writing ctx, preserved): a physical write on the medium the RO ctx reads
; drops the RO ctx's caches too (the DATA mount may BE the boot ESP). Its namespace
; generation moves, so a G3 map taken on the RO handle answers re-resolve.
fd_ro_alias_invalidate:
    push rdi
    lea  rdx, [rel fd_ro_ctx]
    call .one
    pop  rdi
    push rdi
    lea  rdx, [rel fd_selected_ctx]
    call .one
    pop  rdi
    push rdi
    lea  rdx, [rel fd_guest_ctx]
    call .one
    pop  rdi
    ret
.one:
    cmp  dword [rdx + FD_MOUNTED], 1
    jne  .out
    mov  rax, [rdi + FD_DEV]
    cmp  rax, [rdx + FD_DEV]
    jne  .out
    mov  rdi, rdx
    call fd_invalidate_caches
.out:
    ret

; Every media mutation crosses the namespace-generation boundary.
fd_invalidate_caches:
    inc  qword [rdi + FD_NAMESPACE_GEN]
fd_read_cache_drop:
    mov  qword [rel fd_path_cache_ctx], 0
    mov  dword [rdi + FD_CACHE_START], 0
    mov  dword [rdi + FD_VALID_START], 0
    mov  byte [rdi + FD_LOOKUP_VALID], 0
    mov  qword [rdi + FD_FAT_CACHE_LBA], -1
    ret

; Write only inside the selected filesystem extent.  Inputs are absolute LBAs
; derived from FD_PART_LBA/FD_FAT_LBA/FD_DATA_LBA, never raw caller LBAs.
fd_write_sectors:
    call ue_context
    test eax,eax
    jz .legacy
    mov eax,1
    jmp ue_sectors
.legacy:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    lea  rax, [rel fd_ro_ctx]
    cmp  r12, rax
    je   .read_only
    lea  rax, [rel fd_guest_ctx]
    cmp  r12, rax
    je   .read_only
    lea  rax, [rel fd_selected_ctx]
    cmp  r12, rax
    je   .read_only                       ; G1b: the boot-ESP handle never writes (by address)
    mov  rdi, r12
    call fd_scratch_write_gate             ; OWNER/SPECIAL + exact live metadata, never writer-grant bypass
    test rax, rax
    jnz  .read_only
    call fd_invalidate_caches             ; all four tags at EVERY physical mutation boundary
    call fd_ro_alias_invalidate           ; G1b: and the RO ctx's, when it reads this medium
    test r14, r14
    jz   .ok
    cmp  r13, [r12 + FD_PART_LBA]
    jb   .fail
    mov  rdx, r13
    add  rdx, r14
    jc   .fail
    mov  rax, [r12 + FD_PART_LBA]
    add  rax, [r12 + FD_TOTAL_SECTORS]
    jc   .fail
    cmp  rdx, rax
    ja   .fail
    dec  rdx
    mov  rax, [r12 + FD_DEV]
    test rax, rax
    jz   .fail
    mov  rax, [rax + dev.info]
    test rax, rax
    jz   .fail
    cmp  rdx, [rax + blk_info.lba_max]
    ja   .fail
.loop:
    test r14, r14
    jz   .ok
    mov  rbx, r14
    cmp  rbx, 8
    jbe  .chunk
    mov  ebx, 8
.chunk:
    sub  rsp, 16
    mov  [rsp], rbx
    mov  dword [rsp + 8], 3
    mov  rdi, r12
    call fd_data_context
    test eax, eax
    jnz  .single
    call fpw_context
    test eax, eax
    jz   .retry
.single:
    mov  dword [rsp + 8], 1
.retry:
    mov  rdi, r12
    call fd_scratch_write_gate
    test rax, rax
    jnz  .scratch_gate_failed
    mov  rdi, [r12 + FD_DEV]
    mov  rsi, r13
    mov  rdx, [rsp]
    mov  rcx, r15
    ; SEC-S6: FAT32 decides under its own policy (fd_mutation_authorized, the
    ; partition bound above), so blk_write admits it through a WRITER grant for
    ; exactly this call's range; it is revoked on return, whatever the result.
    call fd_data_effect_write
    call fpw_owned_write
    test r11d, r11d
    jnz .offered
    call fd_data_owned_write                ; R11D=1 offered owned path, even failure
    test r11d, r11d
    jnz .offered
    call storage_access_writer_grant        ; preserves all registers
    call blk_write
    call storage_access_writer_revoke       ; preserves RAX
.offered:
    call fd_data_io_result
    call fpw_io_result
    test rax, rax
    jz   .written
    dec  dword [rsp + 8]
    jnz  .retry
    add  rsp, 16
    jmp  .fail
.written:
    mov  rbx, [rsp]
    add  rsp, 16
    lea  rax, [rel fd_media_ctx]
    cmp  r12, rax
    jne  .advance
    lea  rdi, [rel str_fd_media_write]
    call serial_string
    mov  rdi, r13
    call serial_hex64
    call serial_newline
.advance:
    add  r13, rbx
    mov  rax, rbx
    shl  rax, 9
    add  r15, rax
    sub  r14, rbx
    jmp  .loop
.ok:
    xor  eax, eax
    jmp  .out
.scratch_gate_failed:
    add  rsp, 16
.read_only:
    mov  dword [rel fat32_disk_last_error], FD_ERR_NOT_EXACT
    mov  rax, -1
    jmp  .out
.fail:
    mov  dword [rel fat32_disk_last_error], FD_ERR_IO
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

fd_flush:
    call ue_context
    test eax,eax
    jnz ue_flush
    push rbx
    push r12
    mov  rbx, rdi
    lea  rcx, [rel fd_ro_ctx]
    cmp  rbx, rcx
    je   .read_only
    lea  rcx, [rel fd_guest_ctx]
    cmp  rbx, rcx
    je   .read_only
    lea  rcx, [rel fd_selected_ctx]
    cmp  rbx, rcx
    je   .read_only                       ; G1b: the boot-ESP handle never flushes (by address)
    call fd_scratch_write_gate
    test rax, rax
    jnz  .read_only
    mov  r12d, [rel fat32_disk_last_error]
    mov  rdi, rbx
    call fd_fsinfo_apply                  ; the FSInfo hint follows the FAT, before the device flush
    mov  [rel fat32_disk_last_error], r12d ; best effort: a hint I/O error never skips the flush
    mov  r12d, 3
    mov  rdi, rbx
    call fd_data_context
    test eax, eax
    jnz  .single
    call fpw_context
    test eax, eax
    jz   .retry
.single:
    mov  r12d, 1
.retry:
    mov  rdi, rbx
    call fd_scratch_write_gate
    test rax, rax
    jnz  .read_only
    mov  rdi, [rbx + FD_DEV]
    call fd_data_effect_flush
    call fpw_effect_flush
    call blk_flush
    call fd_data_io_result
    call fpw_io_result
    test rax, rax
    jz   .flushed
    dec  r12d
    jnz  .retry
    mov  dword [rel fat32_disk_last_error], FD_ERR_IO
    mov  rax, -1
    jmp  .out
.flushed:
    lea  rax, [rel fd_media_ctx]
    cmp  rbx, rax
    jne  .ok
    lea  rdi, [rel str_fd_media_flush]
    call serial_string
.ok:
    xor  eax, eax
    jmp  .out
.read_only:
    mov  dword [rel fat32_disk_last_error], FD_ERR_NOT_EXACT
    mov  rax, -1
.out:
    pop  r12
    pop  rbx
    ret

; Load one FAT sector from each copy and require byte identity before use.
fd_read_fat_pair:
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    mov  qword [r12 + FD_FAT_CACHE_LBA], -1 ; this read replaces fd_next_cluster's buffer
    mov  qword [rel fd_fat_owner], 0        ; G1b: for every ctx, not only this one
    cmp  dword [r12 + FD_NFATS], 2
    jb   .fail
    cmp  r13, [r12 + FD_FAT_SECTORS]
    jae  .fail
    mov  rsi, [r12 + FD_FAT_LBA]
    add  rsi, r13
    jc   .fail
    mov  rdi, r12
    mov  edx, 1
    lea  rcx, [rel fd_fat_sector]
    call fd_read_sectors
    test rax, rax
    jnz  .fail
    mov  rsi, [r12 + FD_FAT_LBA]
    add  rsi, [r12 + FD_FAT_SECTORS]
    jc   .fail
    add  rsi, r13
    jc   .fail
    mov  rdi, r12
    mov  edx, 1
    lea  rcx, [rel fd_fat2_sector]
    call fd_read_sectors
    test rax, rax
    jnz  .fail
    lea  rdi, [rel fd_fat_sector]
    lea  rsi, [rel fd_fat2_sector]
    mov  edx, 512
    call memcmp
    test rax, rax
    jnz  .fail
    xor  eax, eax
    jmp  .out
.fail:
    mov  dword [rel fat32_disk_last_error], FD_ERR_IO
    mov  rax, -1
.out:
    pop  r13
    pop  r12
    ret

fd_fat_get_pair:
    push rbx
    push r12
    mov  r12, rdi
    mov  ebx, esi
    cmp  ebx, 2
    jb   .fail
    cmp  ebx, [r12 + FD_MAX_CLUSTER]
    jae  .fail
    mov  esi, ebx
    shr  esi, 7
    mov  rdi, r12
    call fd_read_fat_pair
    test rax, rax
    jnz  .fail
    and  ebx, 127
    lea  rax, [rel fd_fat_sector]
    mov  eax, [rax + rbx*4]
    and  eax, 0x0FFFFFFF
    jmp  .out
.fail:
    mov  eax, 0xFFFFFFFF
.out:
    pop  r12
    pop  rbx
    ret

; Ordinary FAT mutation choke point (journal recovery has owned transitions).
; It attempts FAT2 even if FAT1 exhausts
; retries; no software return/branch is exposed between the mirror writes.
fd_fat_set_pair:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13d, esi
    mov  r14d, edx
    cmp  r13d, 2
    jb   .fail
    cmp  r13d, [r12 + FD_MAX_CLUSTER]
    jae  .fail
    mov  esi, r13d
    shr  esi, 7
    mov  r15d, esi
    mov  rdi, r12
    call fd_read_fat_pair
    test rax, rax
    jnz  .fail
    mov  ebx, r13d
    and  ebx, 127
    lea  rcx, [rel fd_fat_sector]
    mov  eax, [rcx + rbx*4]
    mov  edx, eax
    and  eax, 0xF0000000
    and  r14d, 0x0FFFFFFF
    or   eax, r14d
    mov  [rcx + rbx*4], eax
    xor  eax, eax
    test edx, 0x0FFFFFFF
    setz al                                 ; the entry was free
    xor  edx, edx
    test r14d, r14d
    setz dl                                 ; the entry becomes free
    sub  edx, eax
    mov  r14d, edx                          ; FSInfo free delta: -1 / 0 / +1
    ; Keep the old sector in fd_fat2_sector until both writes complete.  A
    ; failed mirror write must have an old image to restore, not just an ERR.
    xor  ebx, ebx
    mov  rdi, r12
    mov  rsi, [r12 + FD_FAT_LBA]
    add  rsi, r15
    mov  edx, 1
    lea  rcx, [rel fd_fat_sector]
    call fd_write_sectors                   ; FAT1
    or   ebx, eax
    ; Fault is latched at actual FAT1 completion, then delivered only after
    ; FAT2. This models a software interruption, not an atomic two-sector
    ; power-loss guarantee (FAT32 cannot provide that guarantee).
    lea  rax, [rel fd_media_ctx]
    cmp  r12, rax
    jne  .mirror
    cmp  byte [rel fd_fault_point], FD_FAULT_FAT1
    jne  .mirror
    mov  byte [rel fd_fault_seen], FD_FAULT_FAT1
.mirror:
    mov  rdi, r12
    mov  rsi, [r12 + FD_FAT_LBA]
    add  rsi, [r12 + FD_FAT_SECTORS]
    add  rsi, r15
    mov  edx, 1
    lea  rcx, [rel fd_fat_sector]
    call fd_write_sectors                   ; FAT2, unconditionally
    or   ebx, eax
    mov  rdi, r12
    call fd_invalidate_caches
    test ebx, ebx
    jnz  .restore_pair
    add  [r12 + FD_FSINFO_DELTA], r14d      ; both mirrors hold the change
    cmp  byte [rel fd_fault_seen], FD_FAULT_FAT1
    je   .fault_after_pair
    xor  eax, eax
    jmp  .out
.fault_after_pair:
    ; The injected "after FAT1" interruption becomes observable only after the
    ; choke point has finished FAT2, proving the no-return-between invariant.
    mov  dword [rel fat32_disk_last_error], FD_ERR_IO
    mov  rax, -1
    jmp  .out
.restore_pair:
    ; The directory commit has not occurred (create), or its tombstone is
    ; already durable (delete). Restore both original FAT sectors, then prove
    ; the bytes through fresh reads. Reuse the idle free-scan buffer as witness.
    lea  rdi, [rel fd_fat_scan1]
    lea  rsi, [rel fd_fat2_sector]
    mov  edx, 512
    call memcpy
    mov  rdi, r12
    mov  rsi, [r12 + FD_FAT_LBA]
    add  rsi, r15
    mov  edx, 1
    lea  rcx, [rel fd_fat_scan1]
    call fd_write_sectors
    mov  rdi, r12
    mov  rsi, [r12 + FD_FAT_LBA]
    add  rsi, [r12 + FD_FAT_SECTORS]
    add  rsi, r15
    mov  edx, 1
    lea  rcx, [rel fd_fat_scan1]
    call fd_write_sectors                    ; restore FAT2 even if FAT1 failed
    mov  rdi, r12
    call fd_flush
    test rax, rax
    jnz  .disable_writes
    mov  rdi, r12
    mov  rsi, r15
    call fd_read_fat_pair
    test rax, rax
    jnz  .disable_writes
    lea  rdi, [rel fd_fat_sector]
    lea  rsi, [rel fd_fat_scan1]
    mov  edx, 512
    call memcmp
    test rax, rax
    jz   .fail                              ; restored, but the operation still failed
.disable_writes:
    mov  byte [r12 + FD_EXACT_BOUND], 0      ; no subsequent physical writes on bad mirrors
    lea  rax, [rel fd_kat_ctx]
    cmp  r12, rax
    jne  .fail
    mov  byte [rel fd_kat_write_mode], 0
.fail:
    mov  dword [rel fat32_disk_last_error], FD_ERR_IO
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

fd_find_free_cluster:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    xor  r13d, r13d                       ; FAT sector
.sector:
    cmp  r13, [r12 + FD_FAT_SECTORS]
    jae  .full
    mov  rdi, r12
    mov  rsi, r13
    call fd_read_fat_pair
    test rax, rax
    jnz  .fail
    xor  r14d, r14d
.entry:
    cmp  r14d, 128
    jae  .next_sector
    mov  rax, r13
    shl  rax, 7
    add  eax, r14d
    mov  ebx, eax
    cmp  ebx, 2
    jb   .next_entry
    cmp  ebx, [r12 + FD_MAX_CLUSTER]
    jae  .full
    cmp  ebx, [r12 + FD_ROOT_CLUSTER]
    je   .next_entry
    cmp  ebx, [rel fd_tx_reservation]
    je   .next_entry
    lea  rdx, [rel fd_fat_sector]
    mov  eax, [rdx + r14*4]
    and  eax, 0x0FFFFFFF
    test eax, eax
    jz   .found
.next_entry:
    inc  r14d
    jmp  .entry
.next_sector:
    inc  r13
    jmp  .sector
.found:
    mov  eax, ebx
    jmp  .out
.full:
    mov  dword [r12 + FD_FREE_VALID], 1
    mov  qword [r12 + FD_FREE_COUNT], 0
    mov  dword [rel fat32_disk_last_error], FD_ERR_NO_SPACE
.fail:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Exact free count used by FSINFO.  Eight-sector batches keep the scan bounded
; without trusting the optional/stale BPB FSInfo hint, and every batch is
; byte-compared against FAT2 before it contributes to the count.
fd_count_free:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    xor  r13d, r13d
    xor  r15d, r15d
.batch:
    cmp  r13, [r12 + FD_FAT_SECTORS]
    jae  .done
    mov  r14, [r12 + FD_FAT_SECTORS]
    sub  r14, r13
    cmp  r14, 8
    jbe  .have_batch
    mov  r14d, 8
.have_batch:
    mov  rdi, r12
    mov  rsi, [r12 + FD_FAT_LBA]
    add  rsi, r13
    mov  rdx, r14
    lea  rcx, [rel fd_fat_scan1]
    call fd_read_sectors
    test rax, rax
    jnz  .fail
    mov  rdi, r12
    mov  rsi, [r12 + FD_FAT_LBA]
    add  rsi, [r12 + FD_FAT_SECTORS]
    add  rsi, r13
    mov  rdx, r14
    lea  rcx, [rel fd_fat_scan2]
    call fd_read_sectors
    test rax, rax
    jnz  .fail
    lea  rdi, [rel fd_fat_scan1]
    lea  rsi, [rel fd_fat_scan2]
    mov  rdx, r14
    shl  rdx, 9
    call memcmp
    test rax, rax
    jnz  .fail
    xor  ebp, ebp
.entry:
    mov  rax, r14
    shl  rax, 7
    cmp  rbp, rax
    jae  .next_batch
    mov  rax, r13
    shl  rax, 7
    add  eax, ebp
    cmp  eax, 2
    jb   .entry_next
    cmp  eax, [r12 + FD_MAX_CLUSTER]
    jae  .done
    cmp  eax, [r12 + FD_ROOT_CLUSTER]
    je   .entry_next
    lea  rdx, [rel fd_fat_scan1]
    mov  ebx, [rdx + rbp*4]
    and  ebx, 0x0FFFFFFF
    test ebx, ebx
    jnz  .entry_next
    inc  r15
.entry_next:
    inc  rbp
    jmp  .entry
.next_batch:
    add  r13, r14
    jmp  .batch
.done:
    mov  [r12 + FD_FREE_COUNT], r15
    mov  dword [r12 + FD_FREE_VALID], 1
    xor  eax, eax
    jmp  .out
.fail:
    mov  dword [r12 + FD_FREE_VALID], 0
    mov  dword [rel fat32_disk_last_error], FD_ERR_IO
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Find a reusable root slot while also refusing a duplicate live short name.
; Returns 0=slot, 1=duplicate, -1=I/O/corrupt/full.
fd_find_root_slot:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  r14d, [r12 + FD_ROOT_CLUSTER]
    xor  r15d, r15d
    mov  byte [rel fd_mut_slot_valid], 0
.cluster:
    cmp  r15d, FD_DIR_MAX_CLUSTERS
    jae  .fail
    lea  rdx, [rel fd_dir_seen]
    xor  ecx, ecx
.seen:
    cmp  ecx, r15d
    jae  .remember
    cmp  r14d, [rdx + rcx*4]
    je   .fail
    inc  ecx
    jmp  .seen
.remember:
    mov  [rdx + r15*4], r14d
    inc  r15d
    cmp  r14d, 2
    jb   .fail
    cmp  r14d, [r12 + FD_MAX_CLUSTER]
    jae  .fail
    mov  eax, r14d
    sub  eax, 2
    mov  ecx, [r12 + FD_SPC]
    imul rax, rcx
    jo   .fail
    add  rax, [r12 + FD_DATA_LBA]
    jc   .fail
    mov  rbp, rax
    xor  ebx, ebx
.sector:
    cmp  ebx, [r12 + FD_SPC]
    jae  .next_cluster
    mov  rdi, r12
    mov  rsi, rbp
    add  rsi, rbx
    mov  edx, 1
    lea  rcx, [rel fd_sector]
    call fd_read_sectors
    test rax, rax
    jnz  .fail
    xor  r10d, r10d
.entry:
    cmp  r10d, 16
    jae  .sector_next
    mov  eax, r10d
    shl  eax, 5
    lea  rdx, [rel fd_sector]
    add  rdx, rax
    cmp  byte [rdx], 0
    je   .end_of_dir
    cmp  byte [rdx], 0xE5
    je   .remember_free
    cmp  byte [rdx + 11], 0x0F
    je   .entry_next
    xor  ecx, ecx
.name:
    cmp  ecx, 11
    jae  .duplicate
    mov  al, [rdx + rcx]
    cmp  al, [r13 + rcx]
    jne  .entry_next
    inc  ecx
    jmp  .name
.remember_free:
    cmp  byte [rel fd_mut_slot_valid], 1
    je   .entry_next
    mov  rax, rbp
    add  rax, rbx
    mov  [rel fd_mut_dir_lba], rax
    mov  eax, r10d
    shl  eax, 5
    mov  [rel fd_mut_dir_off], eax
    mov  byte [rel fd_mut_slot_valid], 1
.entry_next:
    inc  r10d
    jmp  .entry
.end_of_dir:
    cmp  byte [rel fd_mut_slot_valid], 1
    je   .slot
    mov  rax, rbp
    add  rax, rbx
    mov  [rel fd_mut_dir_lba], rax
    mov  eax, r10d
    shl  eax, 5
    mov  [rel fd_mut_dir_off], eax
    mov  byte [rel fd_mut_slot_valid], 1
    jmp  .slot
.sector_next:
    inc  ebx
    jmp  .sector
.next_cluster:
    mov  rdi, r12
    mov  esi, r14d
    call fd_next_cluster
    mov  ebx, eax
    mov  rdi, r12
    mov  esi, ebx
    call fd_classify_next
    cmp  eax, 1
    je   .at_eoc
    test eax, eax
    jnz  .fail
    mov  r14d, ebx
    jmp  .cluster
.at_eoc:
    cmp  byte [rel fd_mut_slot_valid], 1
    je   .slot
    mov  dword [rel fat32_disk_last_error], FD_ERR_NO_SPACE
    jmp  .fail_raw
.duplicate:
    mov  rax, rbp
    add  rax, rbx
    mov  [rel fd_found_dir_lba], rax
    mov  eax, r10d
    shl  eax, 5
    mov  [rel fd_found_dir_off], eax
    mov  dword [rel fat32_disk_last_error], FD_ERR_EXISTS
    mov  eax, 1
    jmp  .out
.slot:
    xor  eax, eax
    jmp  .out
.fail:
    mov  dword [rel fat32_disk_last_error], FD_ERR_IO
.fail_raw:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Child-directory growth. Conflict probes are read-only, even when no slot
; exists yet. Only actual writers may turn that absence into more capacity.
FD_DG_MAGIC equ 0xD524
fd_probe_slot:
    call fd_find_root_slot
    cmp  rax, -1
    jne  .out
    cmp  dword [rel fat32_disk_last_error], FD_ERR_NO_SPACE
    jne  .out
    mov  dword [rel fat32_disk_last_error], FD_ERR_NONE
    xor  eax, eax                        ; absent, not a reserved writable slot
.out:
    ret

; RDI=view ctx, RSI=short name. Actual mutation sites only; caller holds the
; real writer and directory gate. ROOT needs an existing journal slot and is
; deliberately not bootstrapped by this child-directory operation.
fd_write_slot:
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    call fd_find_root_slot
    cmp  rax, -1
    jne  .out
    cmp  dword [rel fat32_disk_last_error], FD_ERR_NO_SPACE
    jne  .out
    lea  rax, [rel fd_dir_ctx]
    cmp  r12, rax
    jne  .full
    cmp  byte [rel fd_dir_view_valid], 1
    jne  .full
    mov  rdi, [rel fd_dir_owner]
    test rdi, rdi
    jz   .full
    cmp  dword [rdi + FD_TX_BUSY], 1
    jne  .full
    mov  esi, [r12 + FD_ROOT_CLUSTER]
    cmp  esi, [rdi + FD_ROOT_CLUSTER]
    je   .full
    call fd_grow_dir
    test rax, rax
    jnz  .out
    mov  rdi, r12
    call fd_invalidate_caches
    mov  rdi, r12
    mov  rsi, r13
    call fd_find_root_slot               ; the durable extension now owns a free slot
    jmp  .out
.full:
    mov  dword [rel fat32_disk_last_error], FD_ERR_NO_SPACE
    mov  rax, -1
.out:
    pop  r13
    pop  r12
    ret

; RDI=real writer, ESI=directory head. Reserve a free cluster, but publish a
; ROOT intent BEFORE zeroing, allocating or linking it. Its 32 bytes are:
; name[11], attr=hidden|system, magic[2], head[4], tail[4], new[4],
; old tail EOC[4], version[2]. No copy journal is armed during this operation.
fd_grow_dir:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  [rel fd_grow_rec + 14], esi
    mov  ebx, esi
    xor  r13d, r13d
.chain:
    inc  r13d
    cmp  r13d, FD_DIR_MAX_CLUSTERS
    jae  .full                          ; leave room for the new cluster
    lea  rdx, [rel fd_grow_seen]
    xor  ecx, ecx
.seen:
    lea  eax, [r13d - 1]
    cmp  ecx, eax
    jae  .remember
    cmp  ebx, [rdx + rcx*4]
    je   .io
    inc  ecx
    jmp  .seen
.remember:
    mov  [rdx + rcx*4], ebx
    mov  rdi, r12
    mov  esi, ebx
    call fd_fat_get_pair
    cmp  eax, 0x0FFFFFF8
    jae  .tail_check
    cmp  eax, 2
    jb   .io
    cmp  eax, [r12 + FD_MAX_CLUSTER]
    jae  .io
    mov  ebx, eax
    jmp  .chain
.tail_check:
    cmp  eax, 0x0FFFFFFF
    ja   .io
    mov  [rel fd_grow_rec + 18], ebx
    mov  [rel fd_grow_rec + 26], eax
    mov  rdi, r12
    call fd_find_free_cluster
    cmp  rax, -1
    je   .out
    mov  [rel fd_grow_rec + 22], eax
    mov  rdi, r12
    lea  rsi, [rel fd_grow_name]
    call fd_find_root_slot
    cmp  rax, 1
    je   .io                            ; recovery must have retired an earlier intent
    test rax, rax
    jnz  .out                           ; ROOT journal full: preserve NO_SPACE
    mov  rax, [rel fd_mut_dir_lba]
    mov  [rel fd_grow_lba], rax
    mov  eax, [rel fd_mut_dir_off]
    mov  [rel fd_grow_off], eax
    lea  rdi, [rel fd_grow_rec]
    lea  rsi, [rel fd_grow_name]
    mov  edx, 11
    call memcpy
    mov  byte [rel fd_grow_rec + 11], 6
    mov  word [rel fd_grow_rec + 12], FD_DG_MAGIC
    mov  word [rel fd_grow_rec + 30], 1
    mov  rdi, r12
    call fd_grow_validate                ; reject unrecoverable inputs before persisting an intent
    test rax, rax
    jnz  .io
    mov  rdi, r12
    call fd_cp_fsinfo_unknown
    test rax, rax
    jnz  .io
    mov  dword [r12 + FD_SWEEP_DONE], 0
    mov  dword [r12 + FD_SWEEP_CLUSTER], 0
    mov  dword [r12 + FD_FREE_VALID], 0
    mov  rdi, r12
    mov  rsi, [rel fd_grow_lba]
    mov  edx, [rel fd_grow_off]
    lea  rcx, [rel fd_grow_rec]
    mov  r8d, 32
    call fd_dir_patch                    ; durable intent before every growth FAT/data write
    test rax, rax
    jnz  .io
    mov  rdi, r12
    call fd_grow_finish
    jmp  .out
.full:
    mov  dword [rel fat32_disk_last_error], FD_ERR_NO_SPACE
    mov  rax, -1
    jmp  .out
.io:
    mov  dword [rel fat32_disk_last_error], FD_ERR_IO
    mov  rax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Root sweep only. Copy the fresh record before helpers reuse fd_sector.
fd_grow_recover:
    push r12
    mov  r12, rdi
    lea  rax, [rel fd_dir_ctx]
    cmp  r12, rax
    je   .bad                           ; the intent belongs to the real ROOT
    mov  [rel fd_grow_lba], rsi
    mov  [rel fd_grow_off], edx
    lea  rsi, [rel fd_sector]
    add  rsi, rdx
    lea  rdi, [rel fd_grow_rec]
    mov  edx, 32
    call memcpy
    lea  rdi, [rel fd_grow_rec]
    lea  rsi, [rel fd_grow_name]
    mov  edx, 11
    call memcmp
    test rax, rax
    jnz  .bad
    cmp  byte [rel fd_grow_rec + 11], 6
    jne  .bad
    cmp  word [rel fd_grow_rec + 30], 1
    jne  .bad
    mov  rdi, r12
    call fd_grow_finish
    jmp  .out
.bad:
    mov  dword [rel fat32_disk_last_error], FD_ERR_IO
    mov  rax, -1
.out:
    pop  r12
    ret

; Read a FAT sector pair, accepting ONLY this intent's two transitions:
; new: FREE <-> canonical EOC, tail: recorded EOC <-> new. All other bytes,
; including reserved high nibbles, must agree. No healing occurs while reading.
; RDI=real ctx, ESI=cluster -> EAX=FAT1 masked entry / FFFFFFFF on error.
fd_grow_get:
    push rbx
    push rbp
    push r12
    push r13
    mov  r12, rdi
    mov  ebx, esi
    cmp  ebx, 2
    jb   .bad
    cmp  ebx, [r12 + FD_MAX_CLUSTER]
    jae  .bad
    mov  r13d, ebx
    shr  r13d, 7
    cmp  r13, [r12 + FD_FAT_SECTORS]
    jae  .bad
    mov  qword [r12 + FD_FAT_CACHE_LBA], -1
    mov  qword [rel fd_fat_owner], 0
    mov  rsi, [r12 + FD_FAT_LBA]
    add  rsi, r13
    mov  edx, 1
    lea  rcx, [rel fd_fat_sector]
    call fd_read_sectors
    test rax, rax
    jnz  .bad
    mov  rdi, r12
    mov  rsi, [r12 + FD_FAT_LBA]
    add  rsi, [r12 + FD_FAT_SECTORS]
    add  rsi, r13
    mov  edx, 1
    lea  rcx, [rel fd_fat2_sector]
    call fd_read_sectors
    test rax, rax
    jnz  .bad
    shl  r13d, 7
    xor  ebp, ebp
.check:
    lea  rdx, [rel fd_fat_sector]
    lea  rcx, [rel fd_fat2_sector]
    mov  eax, [rdx + rbp*4]
    mov  edx, [rcx + rbp*4]
    mov  ecx, eax
    xor  ecx, edx
    test ecx, 0xF0000000
    jnz  .bad
    lea  ecx, [r13d + ebp]
    cmp  ecx, [rel fd_grow_rec + 22]
    je   .new
    cmp  ecx, [rel fd_grow_rec + 18]
    je   .tail
    cmp  eax, edx
    jne  .bad                           ; never heal an unrelated FAT entry
    jmp  .next
.new:
    and  eax, 0x0FFFFFFF
    and  edx, 0x0FFFFFFF
    test eax, eax
    jz   .new2
    cmp  eax, 0x0FFFFFFF
    jne  .bad
.new2:
    test edx, edx
    jz   .next
    cmp  edx, 0x0FFFFFFF
    jne  .bad
    jmp  .next
.tail:
    and  eax, 0x0FFFFFFF
    and  edx, 0x0FFFFFFF
    cmp  eax, [rel fd_grow_rec + 26]
    je   .tail2
    cmp  eax, [rel fd_grow_rec + 22]
    jne  .bad
.tail2:
    cmp  edx, [rel fd_grow_rec + 26]
    je   .next
    cmp  edx, [rel fd_grow_rec + 22]
    jne  .bad
.next:
    inc  ebp
    cmp  ebp, 128
    jb   .check
    and  ebx, 127
    lea  rax, [rel fd_fat_sector]
    mov  eax, [rax + rbx*4]
    and  eax, 0x0FFFFFFF
    jmp  .out
.bad:
    mov  eax, 0xFFFFFFFF
.out:
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Journal-owned FAT update. Keep each buffer's OTHER owned transition intact;
; write both mirrors even after a first-write failure, then flush at the caller.
fd_grow_set:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  ebx, esi
    mov  ebp, edx
    call fd_grow_get
    cmp  eax, 0xFFFFFFFF
    je   .bad
    mov  eax, ebx
    and  eax, 127
    lea  rdx, [rel fd_fat_sector]
    lea  rcx, [rel fd_fat2_sector]
    and  dword [rdx + rax*4], 0xF0000000
    or   [rdx + rax*4], ebp
    and  dword [rcx + rax*4], 0xF0000000
    or   [rcx + rax*4], ebp
    shr  ebx, 7
    mov  r13, [r12 + FD_FAT_LBA]
    add  r13, rbx
    mov  rdi, r12
    mov  rsi, r13
    mov  edx, 1
    lea  rcx, [rel fd_fat_sector]
    call fd_write_sectors
    mov  r14, rax
    mov  rdi, r12
    mov  rsi, r13
    add  rsi, [r12 + FD_FAT_SECTORS]
    mov  edx, 1
    lea  rcx, [rel fd_fat2_sector]
    call fd_write_sectors
    or   rax, r14
    jnz  .bad
    xor  eax, eax
    jmp  .out
.bad:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Complete empty capacity idempotently. No writer may use the new cluster
; until the intent's retirement flush succeeds, so replay may safely zero it.
fd_grow_validate:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    mov  r12, rdi
    lea  rbx, [rel fd_grow_rec]
    cmp  dword [r12 + FD_NFATS], 2
    jne  .bad
    mov  ebp, 14
.bounds:
    mov  eax, [rbx + rbp]
    cmp  eax, 2
    jb   .bad
    cmp  eax, [r12 + FD_MAX_CLUSTER]
    jae  .bad
    cmp  eax, [r12 + FD_ROOT_CLUSTER]
    je   .bad
    add  ebp, 4
    cmp  ebp, 26
    jb   .bounds
    mov  eax, [rbx + 22]
    cmp  eax, [rbx + 14]
    je   .bad
    cmp  eax, [rbx + 18]
    je   .bad
    cmp  dword [rbx + 26], 0x0FFFFFF8
    jb   .bad
    cmp  dword [rbx + 26], 0x0FFFFFFF
    ja   .bad
    ; Reject ownership of any ROOT chain cluster (not merely its head).
    mov  r14d, [r12 + FD_ROOT_CLUSTER]
    xor  r13d, r13d
.root:
    inc  r13d
    cmp  r13d, FD_DIR_MAX_CLUSTERS
    ja   .bad
    cmp  r14d, [rbx + 14]
    je   .bad
    cmp  r14d, [rbx + 18]
    je   .bad
    cmp  r14d, [rbx + 22]
    je   .bad
    mov  rdi, r12
    mov  esi, r14d
    call fd_grow_get
    cmp  eax, 0x0FFFFFF8
    jb   .root_link
    cmp  eax, 0x0FFFFFFF
    ja   .bad
    jmp  .dir_start
.root_link:
    cmp  eax, 2
    jb   .bad
    cmp  eax, [r12 + FD_MAX_CLUSTER]
    jae  .bad
    mov  r14d, eax
    jmp  .root
.dir_start:
    ; A real child directory's dot entry must bind the recorded head.
    mov  rdi, r12
    mov  esi, [rbx + 14]
    call fd_cluster_lba
    cmp  rax, -1
    je   .bad
    mov  rdi, r12
    mov  rsi, rax
    mov  edx, 1
    lea  rcx, [rel fd_sector]
    call fd_read_sectors
    test rax, rax
    jnz  .bad
    mov  rax, '.       '
    cmp  [rel fd_sector], rax
    jne  .bad
    cmp  word [rel fd_sector + 8], '  '
    jne  .bad
    cmp  byte [rel fd_sector + 10], ' '
    jne  .bad
    cmp  byte [rel fd_sector + 11], 0x10
    jne  .bad
    movzx eax, word [rel fd_sector + 20]
    shl  eax, 16
    mov  ax, [rel fd_sector + 26]
    cmp  eax, [rbx + 14]
    jne  .bad
    mov  r14d, eax
    xor  r13d, r13d
.chain:
    cmp  r13d, FD_DIR_MAX_CLUSTERS - 1
    jae  .bad
    lea  rdx, [rel fd_grow_seen]
    xor  ecx, ecx
.seen:
    cmp  ecx, r13d
    jae  .remember
    cmp  r14d, [rdx + rcx*4]
    je   .bad
    inc  ecx
    jmp  .seen
.remember:
    mov  [rdx + r13*4], r14d
    inc  r13d
    cmp  r14d, [rbx + 22]
    je   .bad
    mov  rdi, r12
    mov  esi, r14d
    call fd_grow_get
    cmp  eax, 0xFFFFFFFF
    je   .bad
    cmp  r14d, [rbx + 18]
    je   .new_check                      ; the tail's two mirror values were checked above
    cmp  eax, 2
    jb   .bad
    cmp  eax, [r12 + FD_MAX_CLUSTER]
    jae  .bad
    mov  r14d, eax
    jmp  .chain
.new_check:
    mov  rdi, r12
    mov  esi, [rbx + 22]
    call fd_grow_get
    cmp  eax, 0xFFFFFFFF
    je   .bad
    xor  eax, eax
    jmp  .out
.bad:
    mov  dword [rel fat32_disk_last_error], FD_ERR_IO
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Validated intent, then zero / allocate / link / retire, each durably ordered.
fd_grow_finish:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    mov  r12, rdi
    lea  rbx, [rel fd_grow_rec]
    call fd_grow_validate
    test rax, rax
    jnz  .bad
    mov  rdi, r12
    mov  esi, [rbx + 22]
    call fd_cluster_lba
    cmp  rax, -1
    je   .bad
    mov  r14, rax
    xor  ebp, ebp
    lea  rdi, [rel fd_grow_zero]
    xor  esi, esi
    mov  edx, 512
    call memset
.zero:
    mov  rdi, r12
    mov  rsi, r14
    add  rsi, rbp
    mov  edx, 1
    lea  rcx, [rel fd_grow_zero]
    call fd_write_sectors
    test rax, rax
    jnz  .bad
    inc  ebp
    cmp  ebp, [r12 + FD_SPC]
    jb   .zero
    mov  rdi, r12
    call fd_flush                       ; zero before the cluster becomes reachable
    test rax, rax
    jnz  .bad
    mov  rdi, r12
    mov  esi, [rbx + 22]
    mov  edx, 0x0FFFFFFF
    call fd_grow_set
    test rax, rax
    jnz  .bad
    mov  rdi, r12
    call fd_flush                       ; new EOC durable before linking the old tail
    test rax, rax
    jnz  .bad
    mov  rdi, r12
    mov  esi, [rbx + 18]
    mov  edx, [rbx + 22]
    call fd_grow_set
    test rax, rax
    jnz  .bad
    mov  rdi, r12
    call fd_flush                       ; both tail mirrors before retiring the intent
    test rax, rax
    jnz  .bad
    mov  rdi, r12
    mov  rsi, [rel fd_grow_lba]
    mov  edx, [rel fd_grow_off]
    xor  ecx, ecx
    call fd_name_commit                 ; retirement flush precedes all use of new slots
    test rax, rax
    jnz  .bad
    mov  dword [r12 + FD_FREE_VALID], 0
    mov  rdi, r12
    call fd_cp_views_invalidate
    mov  dword [rel fat32_disk_last_error], FD_ERR_NONE
    xor  eax, eax
    jmp  .out
.bad:
    mov  dword [rel fat32_disk_last_error], FD_ERR_IO
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

%macro WDATA_BSS_fs_fat32_dir_growth 0
alignb 8
fd_grow_lba: resq 1
fd_grow_off: resd 1
fd_grow_rec: resb 32
fd_grow_seen: resd FD_DIR_MAX_CLUSTERS
fd_grow_zero: resb 512
%endmacro
WDATA_BSS_DEFER WDATA_BSS_fs_fat32_dir_growth
fd_grow_name: db '~TMPGROW   '

fd_cluster_lba:
    cmp  esi, 2
    jb   .fail
    cmp  esi, [rdi + FD_MAX_CLUSTER]
    jae  .fail
    mov  eax, esi
    sub  eax, 2
    mov  ecx, [rdi + FD_SPC]
    imul rax, rcx
    jo   .fail
    add  rax, [rdi + FD_DATA_LBA]
    jc   .fail
    mov  rdx, rax
    add  rdx, rcx
    jc   .fail
    mov  rcx, [rdi + FD_PART_LBA]
    add  rcx, [rdi + FD_TOTAL_SECTORS]
    jc   .fail
    cmp  rdx, rcx
    ja   .fail
    ret
.fail:
    mov  dword [rel fat32_disk_last_error], FD_ERR_IO
    mov  rax, -1
    ret

fd_write_payload:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13d, esi
    mov  rbx, rdx
    mov  r14, rcx
    lea  rdi, [rel fd_sector]
    xor  esi, esi
    mov  edx, 512
    call memset
    lea  rdi, [rel fd_sector]
    mov  rsi, rbx
    mov  rdx, r14
    call memcpy
    mov  rdi, r12
    mov  esi, r13d
    call fd_cluster_lba
    cmp  rax, -1
    je   .fail
    mov  rdi, r12
    mov  rsi, rax
    mov  edx, 1
    lea  rcx, [rel fd_sector]
    call fd_write_sectors
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=ctx, RSI=sector, EDX=byte offset, RCX=source, R8D=length.
; Sector devices cannot issue an 11-byte I/O. Read the sector fresh, patch ONLY
; the requested bytes, then write/flush that sector. No stale 32-byte dirent is
; copied by a name commit. Durability assumes the device's sector atomicity;
; flush does not promise atomicity across the two separate FAT sectors.
fd_dir_patch:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  ebx, edx
    mov  r14, rcx
    mov  r15d, r8d
    lea  eax, [rbx + r15]
    cmp  eax, 512
    ja   .fail
    call fd_flush
    test rax, rax
    jnz  .fail
    mov  rdi, r12
    mov  rsi, r13
    mov  edx, 1
    lea  rcx, [rel fd_sector]
    call fd_read_sectors
    test rax, rax
    jnz  .fail
    lea  rdi, [rel fd_sector]
    add  rdi, rbx
    test r14, r14
    jnz  .copy
    ; DELETE uses the same 11-byte name commit, preserving the other ten bytes.
    mov  byte [rdi], 0xE5
    jmp  .write
.copy:
    mov  rsi, r14
    mov  edx, r15d
    call memcpy
.write:
    mov  rdi, r12
    mov  rsi, r13
    mov  edx, 1
    lea  rcx, [rel fd_sector]
    call fd_write_sectors
    test rax, rax
    jnz  .fail
    mov  rdi, r12
    call fd_flush
    jmp  .out
.fail:
    mov  dword [rel fat32_disk_last_error], FD_ERR_IO
    mov  rax, -1
.out:
    push rax
    mov  rdi, r12
    call fd_invalidate_caches
    pop  rax
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

fd_name_commit:
    mov  r8d, 11
    jmp  fd_dir_patch

; All writers serialize with the idle sweep. A remounted volume completes its
; bounded root scan before accepting writes; readers can already select the
; committed entry by its durable transaction tag.
; DATA (fat32_disk_ctx) takes one bounded step per writer; fat32_disk_idle_tick
; advances the rest between commands. No idle sweep reaches the armed scratch
; mount (its gate needs the live owner request the tick does not have), so for
; fd_scratch_ctx alone the writer runs its root sweep to completion here, after
; fd_mutation_authorized and under FD_TX_BUSY, within the same bound as the
; dir view's recovery in fat32_disk_mutate_path (ROOT on FS 105939, option A).
fd_writer_enter:
    push r12
    push rbx
    sub  rsp, 8
    mov  r12, rdi
    call fd_mutation_authorized
    test rax, rax
    jnz  .out
    mov  eax, 1
    xchg eax, [r12 + FD_TX_BUSY]
    test eax, eax
    jnz  .busy
    mov  ebx, 1                          ; one bounded step: every ctx the idle tick sweeps
    lea  rax, [rel fd_scratch_ctx]
    cmp  r12, rax
    jne  .sweep
    mov  ebx, FD_DIR_MAX_CLUSTERS * 128 + 64   ; scratch: the whole bounded root sweep
.sweep:
    cmp  dword [r12 + FD_SWEEP_DONE], 1
    je   .ok
    mov  rdi, r12
    call fd_sweep_step
    test rax, rax
    jnz  .release
    dec  ebx
    jnz  .sweep
    cmp  dword [r12 + FD_SWEEP_DONE], 1
    je   .ok
.release:
    mov  dword [r12 + FD_TX_BUSY], 0
.busy:
    mov  dword [rel fat32_disk_last_error], FD_ERR_BUSY
    mov  rax, -1
    jmp  .out
.ok:
    mov  rdi, r12
    call fd_invalidate_caches
    xor  eax, eax
.out:
    add  rsp, 8
    pop  rbx
    pop  r12
    ret

; Persistent recovery record in the fresh dirent (never in the original):
; name ~TMPPLAN until data is written, then ~TMPSWAP until the 11-byte commit.
; 12:magic u16, 14:old sector relative to partition u32, 18:old offset u16,
; 22:second fresh cluster u32 (0 for one cluster). Cluster/size use normal FAT
; fields. The intent is durable BEFORE allocating either FAT entry, so even
; allocation/data crash cuts have a discoverable owner. Reserved timestamps
; carry the record until cleanup; no unrelated scratch name can be in flight.
fat32_disk_update:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  rbp, rdi
    mov  r12, [rdi + fsmount.priv]
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    test r13, r13
    jz   .bad
    test r14, r14
    jz   .bad
    test r15, r15
    jz   .bad
    cmp  r15, FD_TX_MAX_BYTES
    ja   .bad
    mov  rdi, r13
    mov  rsi, r12
    call fd_scratch_name_allowed
    test rax, rax
    jnz  .fail
    mov  rdi, r12
    call fd_writer_enter
    test rax, rax
    jnz  .fail
    mov  rdi, r12
    mov  rsi, r13
    call fd_lookup
    test rax, rax
    jnz  .unlock_fail
    cmp  byte [rel fd_found_attr], 0x20   ; recovery's original-entry contract, before any write
    jne  .unlock_fail
    cmp  qword [rel fd_found_size], FD_TX_MAX_BYTES
    ja   .unlock_fail
    mov  rdi, r12
    mov  esi, [rel fd_found_cluster]
    mov  rdx, [rel fd_found_size]
    call fd_validate_file_chain
    test rax, rax
    jnz  .unlock_fail
    lea  rdi, [rel fd_tx_entry]
    xor  esi, esi
    mov  edx, 32
    call memset
    mov  rax, [rel fd_found_dir_lba]
    sub  rax, [r12 + FD_PART_LBA]
    mov  [rel fd_tx_entry + 14], eax
    mov  eax, [rel fd_found_dir_off]
    mov  [rel fd_tx_entry + 18], ax
    mov  word [rel fd_tx_entry + 12], FD_TX_MAGIC
    mov  byte [rel fd_tx_entry + 11], 0x20
    mov  [rel fd_tx_entry + 28], r15d
    ; Refuse a temp collision even on a mount whose idle scan has completed.
    mov  rdi, r12
    lea  rsi, [rel fd_tx_temp]
    call fd_probe_slot
    test rax, rax
    jnz  .unlock_fail
    mov  rdi, r12
    lea  rsi, [rel fd_tx_plan]
    call fd_write_slot
    test rax, rax
    jnz  .unlock_fail
    mov  rax, [rel fd_mut_dir_lba]
    mov  [rel fd_tx_lba], rax
    mov  eax, [rel fd_mut_dir_off]
    mov  [rel fd_tx_off], eax
    mov  rdi, r12
    call fd_find_free_cluster
    cmp  rax, -1
    je   .unlock_fail
    mov  ebx, eax
    mov  [rel fd_tx_entry + 26], ax
    shr  eax, 16
    mov  [rel fd_tx_entry + 20], ax
    cmp  r15d, [r12 + FD_CLUSTER_BYTES]
    jbe  .reserved
    mov  [rel fd_tx_reservation], ebx
    mov  rdi, r12
    call fd_find_free_cluster
    mov  dword [rel fd_tx_reservation], 0
    cmp  rax, -1
    je   .unlock_fail
    mov  [rel fd_tx_entry + 22], eax
.reserved:
    lea  rdi, [rel fd_tx_entry]
    lea  rsi, [rel fd_tx_plan]
    mov  edx, 11
    call memcpy
    mov  dword [r12 + FD_SWEEP_DONE], 0
    mov  dword [r12 + FD_SWEEP_CLUSTER], 0
    mov  dword [r12 + FD_FREE_VALID], 0
    mov  rdi, r12
    mov  rsi, [rel fd_tx_lba]
    mov  edx, [rel fd_tx_off]
    lea  rcx, [rel fd_tx_entry]
    mov  r8d, 32
    call fd_dir_patch                     ; durable allocation intent, not a final name
    test rax, rax
    jnz  .unlock_fail
    mov  esi, [rel fd_tx_entry + 22]
    test esi, esi
    jz   .head
    mov  rdi, r12
    mov  edx, 0x0FFFFFFF
    call fd_fat_set_pair
    test rax, rax
    jnz  .unlock_fail
.head:
    mov  edx, [rel fd_tx_entry + 22]
    test edx, edx
    jnz  .link
    mov  edx, 0x0FFFFFFF
.link:
    mov  rdi, r12
    mov  esi, ebx
    call fd_fat_set_pair
    test rax, rax
    jnz  .unlock_fail
    mov  rdi, r12
    call fd_flush
    test rax, rax
    jnz  .unlock_fail
    FD_TX_CUT 1
    xor  ebx, ebx                        ; byte offset, at most two sectors
.data:
    lea  rdi, [rel fd_sector]
    xor  esi, esi
    mov  edx, 512
    call memset
    mov  rdx, r15
    sub  rdx, rbx
    cmp  rdx, 512
    jbe  .copy_data
    mov  edx, 512
.copy_data:
    lea  rdi, [rel fd_sector]
    lea  rsi, [r14 + rbx]
    call memcpy
    movzx esi, word [rel fd_tx_entry + 20]
    shl  esi, 16
    mov  si, [rel fd_tx_entry + 26]
    mov  rdi, r12
    cmp  ebx, [r12 + FD_CLUSTER_BYTES]
    jb   .in_first
    mov  esi, [rel fd_tx_entry + 22]
.in_first:
    call fd_cluster_lba
    cmp  rax, -1
    je   .unlock_fail
    mov  edx, ebx
    cmp  edx, [r12 + FD_CLUSTER_BYTES]
    jb   .sector_offset
    sub  edx, [r12 + FD_CLUSTER_BYTES]
.sector_offset:
    shr  edx, 9
    lea  rsi, [rax + rdx]
    mov  rdi, r12
    mov  edx, 1
    lea  rcx, [rel fd_sector]
    call fd_write_sectors
    test rax, rax
    jnz  .unlock_fail
    add  ebx, 512
    cmp  rbx, r15
    jb   .data
    FD_TX_CUT 2
    mov  rdi, r12
    mov  rsi, [rel fd_tx_lba]
    mov  edx, [rel fd_tx_off]
    lea  rcx, [rel fd_tx_temp]
    call fd_name_commit                  ; data/FAT barrier, then ~TMPSWAP
    test rax, rax
    jnz  .unlock_fail
    FD_TX_CUT 3
    xor  ebx, ebx
.verify:
    mov  r8, r15
    sub  r8, rbx
    cmp  r8, 256
    jbe  .verify_chunk
    mov  r8d, 256
.verify_chunk:
    push r8
    mov  rdi, rbp
    lea  rsi, [rel fd_tx_temp]
    mov  rdx, rbx
    lea  rcx, [rel fd_verify_buf]
    call fat32_disk_read_at
    pop  rdx
    cmp  rax, rdx
    jne  .unlock_fail
    push rdx
    lea  rdi, [rel fd_verify_buf]
    lea  rsi, [r14 + rbx]
    call memcmp
    pop  rdx
    test rax, rax
    jnz  .unlock_fail
    add  rbx, rdx
    cmp  rbx, r15
    jb   .verify
    FD_TX_CUT 4
    mov  rdi, r12
    mov  rsi, [rel fd_tx_lba]
    mov  edx, [rel fd_tx_off]
    mov  rcx, r13
    call fd_name_commit                  ; THE commit: exactly 11 name bytes
    test rax, rax
    jnz  .unlock_fail
    FD_TX_CUT 5                         ; KAT: durable duplicate-name window
    mov  rdi, r12
    mov  rsi, [rel fd_tx_lba]
    mov  edx, [rel fd_tx_off]
    call fd_tx_recover                   ; bounded loser retirement, after commit flush
    test rax, rax
    jnz  .unlock_fail
    mov  dword [r12 + FD_SWEEP_DONE], 1
    xor  eax, eax
    jmp  .unlock
.bad:
    mov  dword [rel fat32_disk_last_error], FD_ERR_BAD_ARG
.fail:
    mov  rax, -1
    jmp  .out
.unlock_fail:
    mov  dword [rel fat32_disk_last_error], FD_ERR_IO
    mov  rax, -1
.unlock:
    mov  dword [r12 + FD_TX_BUSY], 0
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

fat32_disk_rename:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, [rdi + fsmount.priv]
    mov  r13, rsi
    mov  r14, rdx
    test r13, r13
    jz   .fail
    test r14, r14
    jz   .fail
    mov  rdi, r13
    mov  rsi, r12
    call fd_scratch_name_allowed
    test rax, rax
    jnz  .fail
    mov  rdi, r14
    mov  rsi, r12
    call fd_scratch_name_allowed
    test rax, rax
    jnz  .fail
    mov  rdi, r12
    call fd_writer_enter
    test rax, rax
    jnz  .fail
    mov  rdi, r12
    mov  rsi, r14
    call fd_lookup
    test rax, rax
    jz   .exists
    cmp  dword [rel fat32_disk_last_error], FD_ERR_NOT_FOUND
    jne  .unlock_fail
    mov  rdi, r12
    mov  rsi, r13
    call fd_lookup
    test rax, rax
    jnz  .unlock_fail
    mov  rdi, r12
    mov  esi, [rel fd_found_cluster]
    mov  rdx, [rel fd_found_size]
    call fd_validate_file_chain
    test rax, rax
    jnz  .unlock_fail
    mov  rdi, r12
    mov  rsi, [rel fd_found_dir_lba]
    mov  edx, [rel fd_found_dir_off]
    mov  rcx, r14
    call fd_name_commit
    jmp  .unlock
.exists:
    mov  dword [rel fat32_disk_last_error], FD_ERR_EXISTS
.unlock_fail:
    mov  rax, -1
.unlock:
    mov  dword [r12 + FD_TX_BUSY], 0
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Small validated dirent reader used only by recovery. No stale sector survives
; another block operation, and the caller's 32-byte record has its own storage.
fd_tx_read_entry:
    push rbx
    push r12
    mov  ebx, edx
    mov  r12, rcx
    test ebx, 31
    jnz  .fail
    cmp  ebx, 480
    ja   .fail
    mov  edx, 1
    lea  rcx, [rel fd_sector]
    call fd_read_sectors
    test rax, rax
    jnz  .fail
    mov  rdi, r12
    lea  rsi, [rel fd_sector]
    add  rsi, rbx
    mov  edx, 32
    call memcpy
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r12
    pop  rbx
    ret

fd_tx_head:
    movzx eax, word [rsi + 20]
    shl  eax, 16
    mov  ax, [rsi + 26]
    ret

; The old-entry pointer in a recovery record must refer to the bounded ROOT
; chain, not merely an arbitrary sector inside the DATA partition.
fd_root_contains:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13, rsi
    mov  ebx, [r12 + FD_ROOT_CLUSTER]
    mov  r14d, FD_DIR_MAX_CLUSTERS
.next:
    mov  rdi, r12
    mov  esi, ebx
    call fd_cluster_lba
    cmp  rax, -1
    je   .fail
    cmp  r13, rax
    jb   .advance
    mov  ecx, [r12 + FD_SPC]
    add  rax, rcx
    cmp  r13, rax
    jb   .yes
.advance:
    mov  rdi, r12
    mov  esi, ebx
    call fd_next_cluster
    mov  ebx, eax
    mov  rdi, r12
    mov  esi, ebx
    call fd_classify_next
    test eax, eax
    jnz  .fail
    dec  r14d
    jnz  .next
.fail:
    mov  rax, -1
    jmp  .out
.yes:
    xor  eax, eax
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Free a recorded pair idempotently. Validate BOTH links before changing either.
; Tail-first + a flush preserves the head's link until the tail is durably free;
; a crash after the head clears needs no lost next-pointer to resume cleanup.
fd_tx_free_pair:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  ebx, esi
    mov  r13d, edx
    test ebx, ebx
    jz   .empty
    cmp  ebx, [r12 + FD_ROOT_CLUSTER]
    je   .fail
    test r13d, r13d
    jz   .head_check
    cmp  r13d, ebx
    je   .fail
    cmp  r13d, [r12 + FD_ROOT_CLUSTER]
    je   .fail
    mov  esi, r13d
    call fd_fat_get_pair
    test eax, eax
    jz   .head_check
    cmp  eax, FD_EOC_MIN
    jb   .fail
    cmp  eax, 0x0FFFFFFF
    ja   .fail
.head_check:
    mov  rdi, r12
    mov  esi, ebx
    call fd_fat_get_pair
    test eax, eax
    jz   .free_tail
    test r13d, r13d
    jz   .eoc
    cmp  eax, r13d
    jne  .fail
    jmp  .free_tail
.eoc:
    cmp  eax, FD_EOC_MIN
    jb   .fail
    cmp  eax, 0x0FFFFFFF
    ja   .fail
.free_tail:
    test r13d, r13d
    jz   .free_head
    mov  rdi, r12
    mov  esi, r13d
    xor  edx, edx
    call fd_fat_set_pair
    test rax, rax
    jnz  .fail
    mov  rdi, r12
    call fd_flush
    test rax, rax
    jnz  .fail
.free_head:
    mov  rdi, r12
    mov  esi, ebx
    xor  edx, edx
    call fd_fat_set_pair
    test rax, rax
    jnz  .fail
    mov  rdi, r12
    call fd_flush
    jmp  .out
.empty:
    test r13d, r13d
    jnz  .fail
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=ctx, RSI=record sector, EDX=record offset. Bounded to the two clusters
; supported by this rung. A malformed record fails closed; it is not an excuse
; to free an arbitrary chain or overwrite a bystander entry.
fd_tx_recover:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  ebp, edx
    lea  rcx, [rel fd_tx_entry]
    call fd_tx_read_entry
    test rax, rax
    jnz  .fail
    cmp  word [rel fd_tx_entry + 12], FD_TX_MAGIC
    jne  .fail
    cmp  byte [rel fd_tx_entry + 11], 0x20
    jne  .fail
    cmp  dword [rel fd_tx_entry + 28], 0
    je   .fail
    cmp  dword [rel fd_tx_entry + 28], FD_TX_MAX_BYTES
    ja   .fail
    lea  rsi, [rel fd_tx_entry]
    call fd_tx_head
    mov  r14d, eax
    mov  r15d, [rel fd_tx_entry + 22]
    xor  ebx, ebx                       ; 0=abandoned, 1=committed
    lea  rdi, [rel fd_tx_entry]
    lea  rsi, [rel fd_tx_plan]
    mov  edx, 11
    call memcmp
    test rax, rax
    jz   .old_pointer
    lea  rdi, [rel fd_tx_entry]
    lea  rsi, [rel fd_tx_temp]
    mov  edx, 11
    call memcmp
    test rax, rax
    jz   .old_pointer
    lea  rdi, [rel fd_tx_entry]
    mov  rsi, r12
    call fd_scratch_name_allowed
    test rax, rax
    jnz  .fail
    inc  ebx
    mov  rdi, r12
    mov  esi, r14d
    mov  edx, [rel fd_tx_entry + 28]
    call fd_validate_file_chain          ; never retire the old file for partial new data
    test rax, rax
    jnz  .fail
.old_pointer:
    mov  esi, [rel fd_tx_entry + 14]
    add  rsi, [r12 + FD_PART_LBA]
    mov  [rel fd_tx_old_lba], rsi
    mov  rdi, r12
    call fd_root_contains
    test rax, rax
    jnz  .fail
    movzx edx, word [rel fd_tx_entry + 18]
    cmp  r13, [rel fd_tx_old_lba]
    jne  .different_slot
    cmp  ebp, edx
    je   .fail
.different_slot:
    mov  rdi, r12
    mov  rsi, [rel fd_tx_old_lba]
    lea  rcx, [rel fd_tx_old]
    call fd_tx_read_entry
    test rax, rax
    jnz  .fail
    cmp  byte [rel fd_tx_old], 0xE5
    jne  .old_live
    test ebx, ebx
    jz   .fail
    jmp  .clear_tag                      ; old tombstone durable, no second free
.old_live:
    lea  rdi, [rel fd_tx_old]
    mov  rsi, r12
    call fd_scratch_name_allowed
    test rax, rax
    jnz  .fail
    cmp  byte [rel fd_tx_old + 11], 0x20
    jne  .fail
    cmp  dword [rel fd_tx_old + 28], FD_TX_MAX_BYTES
    ja   .fail
    test ebx, ebx
    jz   .old_chain
    lea  rdi, [rel fd_tx_old]
    lea  rsi, [rel fd_tx_entry]
    mov  edx, 11
    call memcmp
    test rax, rax
    jnz  .fail
.old_chain:
    lea  rsi, [rel fd_tx_old]
    call fd_tx_head
    mov  [rel fd_tx_old_head], eax
    cmp  eax, r14d
    je   .fail
    test r15d, r15d
    jz   .no_new_tail
    cmp  eax, r15d
    je   .fail
.no_new_tail:
    mov  dword [rel fd_tx_old_tail], 0
    test eax, eax
    jnz  .old_nonempty
    cmp  dword [rel fd_tx_old + 28], 0
    jne  .fail
    jmp  .release
.old_nonempty:
    mov  rdi, r12
    mov  esi, eax
    call fd_fat_get_pair
    test eax, eax
    jz   .old_already_free
    cmp  eax, FD_EOC_MIN
    jae  .old_eoc
    cmp  eax, 2
    jb   .fail
    cmp  eax, [r12 + FD_MAX_CLUSTER]
    jae  .fail
    cmp  eax, r14d
    je   .fail
    cmp  eax, r15d
    je   .fail
    mov  edx, [rel fd_tx_old + 28]
    cmp  edx, [r12 + FD_CLUSTER_BYTES]
    jbe  .fail                           ; a one-cluster old file cannot own a tail
    mov  [rel fd_tx_old_tail], eax
    jmp  .release
.old_eoc:
    cmp  eax, 0x0FFFFFFF
    ja   .fail
    mov  edx, [rel fd_tx_old + 28]
    cmp  edx, [r12 + FD_CLUSTER_BYTES]
    ja   .fail
    jmp  .release
.old_already_free:
    test ebx, ebx
    jz   .fail                          ; an abort must preserve a valid old chain
.release:
    test ebx, ebx
    jnz  .retire_old
    ; The original must still fully validate before an abandoned reservation
    ; is reclaimed. This also rejects a cross-link between the two versions.
    mov  rdi, r12
    mov  esi, [rel fd_tx_old_head]
    mov  edx, [rel fd_tx_old + 28]
    call fd_validate_file_chain
    test rax, rax
    jnz  .fail
    mov  rdi, r12
    mov  esi, r14d
    mov  edx, r15d
    call fd_tx_free_pair
    test rax, rax
    jnz  .fail
    mov  rdi, r12
    mov  rsi, r13
    mov  edx, ebp
    xor  ecx, ecx
    call fd_name_commit
    jmp  .reclaimed
.retire_old:
    mov  rdi, r12
    mov  esi, [rel fd_tx_old_head]
    mov  edx, [rel fd_tx_old_tail]
    call fd_tx_free_pair
    test rax, rax
    jnz  .fail
    mov  rdi, r12
    mov  rsi, [rel fd_tx_old_lba]
    movzx edx, word [rel fd_tx_entry + 18]
    xor  ecx, ecx
    call fd_name_commit                 ; old tombstone only AFTER committed-name barrier
    test rax, rax
    jnz  .fail
.clear_tag:
    ; Retire the timestamp-carried record as well as its tag. The high cluster
    ; word at 20..21 is preserved from the freshly read committed entry.
    lea  rdi, [rel fd_tx_entry + 12]
    xor  esi, esi
    mov  edx, 8
    call memset
    lea  rdi, [rel fd_tx_entry + 22]
    xor  esi, esi
    mov  edx, 4
    call memset
    mov  rdi, r12
    mov  rsi, r13
    lea  edx, [rbp + 12]
    lea  rcx, [rel fd_tx_entry + 12]
    mov  r8d, 14
    call fd_dir_patch                   ; post-commit metadata cleanup, never the name commit
.reclaimed:
    test rax, rax
    jnz  .fail
    inc  qword [r12 + FD_ORPHANS]
    mov  dword [r12 + FD_FREE_VALID], 0
    xor  eax, eax
    jmp  .out
.fail:
    mov  dword [rel fat32_disk_last_error], FD_ERR_IO
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; One root sector OR one record reclamation per pass, <=64 root clusters.
; Called with FD_TX_BUSY held; no boot caller performs a whole physical scan.
fd_sweep_step:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    cmp  dword [r12 + FD_SWEEP_DONE], 1
    je   .ok
    mov  esi, [r12 + FD_SWEEP_CLUSTER]
    test esi, esi
    jnz  .cluster
    mov  esi, [r12 + FD_ROOT_CLUSTER]
    mov  [r12 + FD_SWEEP_CLUSTER], esi
    mov  dword [r12 + FD_SWEEP_SECTOR], 0
    mov  dword [r12 + FD_SWEEP_HOPS], 1
.cluster:
    cmp  dword [r12 + FD_SWEEP_HOPS], FD_DIR_MAX_CLUSTERS
    ja   .fail
    call fd_cluster_lba
    cmp  rax, -1
    je   .fail
    mov  esi, [r12 + FD_SWEEP_SECTOR]
    add  rsi, rax
    mov  r13, rsi
    mov  rdi, r12
    mov  edx, 1
    lea  rcx, [rel fd_sector]
    call fd_read_sectors
    test rax, rax
    jnz  .fail
    xor  ebx, ebx
.entry:
    lea  rdx, [rel fd_sector]
    add  rdx, rbx
    cmp  byte [rdx], 0
    je   .done
    cmp  byte [rdx], 0xE5
    je   .next_entry
    cmp  byte [rdx + 11], 0x0F
    je   .next_entry
    cmp  word [rdx + 12], FD_DG_MAGIC
    je   .grow_journal
    cmp  word [rdx + 12], FD_CP_MAGIC
    je   .copy_journal
    cmp  word [rdx + 12], FD_TX_MAGIC
    jne  .next_entry
    mov  rdi, r12
    mov  rsi, r13
    mov  edx, ebx
    call fd_tx_recover
    jmp  .out                          ; revisit sector after bounded mutation
.grow_journal:
    mov  rdi, r12
    mov  rsi, r13
    mov  edx, ebx
    call fd_grow_recover
    jmp  .out
.copy_journal:
    mov  rdi, r12
    mov  rsi, r13
    mov  edx, ebx
    call fd_cp_recover                 ; retire or reclaim one bounded batch, then revisit
    cmp  rax, 1
    je   .revisit                      ; more to reclaim: nothing is decided yet
    ; RCQ-20 S3: a journal this sweep found is an interrupted copy; record what recovery decided
    mov  edi, FS_REC_FAILED            ; malformed or I/O: failed closed
    xor  edx, edx
    test rax, rax
    jnz  .note
    mov  edi, FS_REC_RECLAIMED
    cmp  byte [rel fd_cp_committed], 1
    jne  .note
    mov  edi, FS_REC_COMMITTED
    lea  rdx, [rel fd_cp_dent]         ; the destination dirent recovery checked: its 8.3 leaf
.note:
    push rax
    mov  esi, FS_PRES_FAT
    call vfs_copy_note_recovery
    pop  rax
    cmp  rax, -1
    je   .out
.revisit:
    xor  eax, eax
    jmp  .out
.next_entry:
    add  ebx, 32
    cmp  ebx, 512
    jb   .entry
    inc  dword [r12 + FD_SWEEP_SECTOR]
    mov  eax, [r12 + FD_SWEEP_SECTOR]
    cmp  eax, [r12 + FD_SPC]
    jb   .ok
    mov  rdi, r12
    mov  esi, [r12 + FD_SWEEP_CLUSTER]
    call fd_next_cluster
    mov  ebx, eax
    mov  rdi, r12
    mov  esi, ebx
    call fd_classify_next
    cmp  eax, 1
    je   .done
    test eax, eax
    jnz  .fail
    mov  [r12 + FD_SWEEP_CLUSTER], ebx
    inc  dword [r12 + FD_SWEEP_HOPS]
    mov  dword [r12 + FD_SWEEP_SECTOR], 0
    jmp  .ok
.done:
    mov  dword [r12 + FD_SWEEP_DONE], 1
.ok:
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    push rax
    mov  rdi, r12
    call fd_invalidate_caches            ; shared sector buffers changed even on read-only passes
    pop  rax
    pop  r13
    pop  r12
    pop  rbx
    ret

; Settled storage producer (BOOTCLOCK v5, report-only, read-only). EAX=1 once
; the DATA crash-recovery root sweep is done (only an authorized, exact-bound
; volume can sweep). A descriptor build expects that volume, so an unswept one
; stays 0 whether it is unbound, unhealthy, read-only, changed or simply not
; yet bound: replay applies but is unresolved. 2 in a build with no exact DATA
; identity, or when the descriptor load attempt proved that exact disk absent
; (fat32_disk_descriptor_absent, set by the higher layer) and nothing is
; exact-bound: no PaOS DATA write and so no replay can exist. Clobbers EAX.
fat32_disk_replay_state:
    mov  eax, 1
    cmp  dword [rel fat32_disk_ctx + FD_SWEEP_DONE], 1
    je   .out
%if COG_MODEL_ENABLED = 1
    xor  eax, eax
    cmp  byte [rel fat32_disk_descriptor_absent], 1
    jne  .out
    cmp  byte [rel fat32_disk_ctx + FD_EXACT_BOUND], 0
    jne  .out
    mov  eax, 2
%else
    mov  eax, 2
%endif
.out:
    ret

; Link-map adapter at the existing late cadence rearm boundary: register only,
; with all physical reads/writes deferred to the ordinary idle driver.
fat32_disk_idle_arm:
    lea  rdi, [rel fd_tx_cadence]
    xor  esi, esi
    mov  edx, 10
    mov  rcx, [rel tsc_khz]
    imul rcx, rcx, 100
    lea  r8, [rel fat32_disk_idle_tick]
    call cadence_register_named
    cmp  eax, -1
    je   .out
    mov  byte [rel fd_cp_runner_armed], 1  ; copy jobs advance only on this cadence
    lea  rdi, [rel str_fd_tx_ready]
    call serial_string
.out:
    jmp  cadence_live_rearm

fat32_disk_idle_tick:
    call vfs_copy_tick                   ; a live copy job owns the writer between ticks
    call fd_scratch_copy_retire          ; also retire a VFS-lost binding without touching its journal
    mov  rax, [rel fat32_disk_idle_observer]
    test rax, rax
    jz   .no_observer
    call rax                             ; a higher layer's bounded observer (verb-registry census)
.no_observer:
    push r12
    lea  r12, [rel fat32_disk_ctx]
    cmp  dword [r12 + FD_SWEEP_DONE], 1
    je   .out
    mov  rdi, r12
    call fd_mutation_authorized
    test rax, rax
    jnz  .out
    mov  eax, 1
    xchg eax, [r12 + FD_TX_BUSY]
    test eax, eax
    jnz  .out
    mov  rdi, r12
    call fd_sweep_step
    mov  dword [r12 + FD_TX_BUSY], 0
.out:
    pop  r12
    ret

; ============================================================================
; RCQ-20 streaming copy job (fs_ops.copy). One job at a time; it owns the writer
; (FD_TX_BUSY) from BEGIN until DONE/CANCELLED/FAILED, and each STEP moves or
; verifies a bounded FD_CP_STEP_BYTES so the idle cadence never stalls.
;
; Crash consistency. The journal is a ROOT ~TMPPLAN dirent tagged FD_CP_MAGIC:
;   20/26 chain head (the reclaim cursor once reclaim starts)
;   28    total size
;   14/18 the reserved destination slot (partition-relative sector, index)
;   22    reclaim: the cluster whose free is pending
; It lives in ROOT even for a /FSWDIR* destination: the root sweep completes
; before any writer runs, so no allocation can reuse a cluster the journal still
; references (a subdirectory is swept only by its next mutation).
;   1. journal (barrier), then the destination slot pointer (barrier)
;   2. per cluster: reference it (journal head, or FAT[tail] + flush), then data;
;      a referenced cluster stays FAT-free until the next link or EOC, so
;      recovery's walk stops at the first free entry
;   3. FAT[tail]=EOC + flush, validate the chain, re-read and compare both chains
;   4. THE commit: one complete 32-byte dirent in the reserved slot (barrier)
;   5. tombstone the journal
; Recovery reads only the reserved slot: our head and size there means
; committed (retire the journal); anything else means abandoned (reclaim forward).
; ============================================================================
fat32_disk_copy:
    cmp  ecx, FS_COPY_STEP
    je   fd_cp_step
    cmp  ecx, FS_COPY_CANCEL
    je   fd_cp_cancel
    cmp  ecx, FS_COPY_BEGIN
    je   fd_cp_begin
    mov  dword [rel fat32_disk_last_error], FD_ERR_BAD_ARG
    mov  rax, -1
    ret

; The directory view and the real context share fd_sector/fd_fat_sector; any
; switch between them drops both cache tags.
fd_cp_views_invalidate:
    push rdi
    call fd_invalidate_caches
    lea  rdi, [rel fd_dir_ctx]
    call fd_invalidate_caches
    pop  rdi
    ret

; RDI=fsmount, RSI=source Z path, RDX=destination Z path, R8=fs_copy_job*,
; R9D=FS_CMODE_* | FS_COPY_TREE (RCQ-20 S5b: the source is a directory, copied
; into a NEW directory, see fd_cp_tree_begin).
fd_cp_begin:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r12, [rdi + fsmount.priv]
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, r8
    mov  dword [rel fd_cp_alloc_hint], 2 ; E5: search state belongs to this BEGIN, not a prior mount/job
    mov  eax, r9d
    and  eax, FS_CMODE_MASK
    mov  [rel fd_cp_mode], eax
    lea  rax, [rel fd_cp_mode]
    mov  [rel vfs_copy_policy_ptr], rax  ; E2: an answer reaches this job's decisions from here
    and  r9d, FS_COPY_TREE
    mov  [rel fd_tree_on], r9d           ; S5b: decided here, for this job only
    mov  qword [rel fd_tree_base], 0
    mov  byte [rel fd_cp_src_retried], 0
    mov  byte [rel fd_cp_src_retry_pending], 0
    mov  qword [rel fd_cp_src_lba], -1
    mov  dword [rel fd_cp_kept], 0       ; a refuse job
    mov  byte [rel fd_cp_cmp_on], 0      ; smart copy C: set only by fd_cp_same_probe
    mov  dword [rel fd_tree_merge_cl], 0
    mov  dword [rel fat32_disk_last_error], FD_ERR_NONE
    test r13, r13
    jz   .bad
    test r14, r14
    jz   .bad
    test r15, r15
    jz   .bad
    ; Read-only Unicode admission must not expand copy/write path policy.
    ; Preflight before writer_enter: its journal recovery may already write.
    mov  rdi, r13
    call fd_path_validate_ascii
    cmp  rax, -1
    je   .bad
    mov  rdi, r14
    call fd_path_validate_ascii
    cmp  rax, -1
    je   .bad
    cmp  byte [rel fd_cp_runner_armed], 1
    jne  .not_ready                      ; no idle cadence: a job would hold the writer forever
    cmp  dword [rel fd_cp_phase], FD_CP_IDLE
    jne  .busy
    mov  byte [rel fd_cp_repl], 0        ; E2r: set only when an older file is to be replaced
    mov  byte [rel fd_cp_old_case], 0
    mov  byte [rel fd_cp_swapped], 0
    mov  dword [rel vfs_copy_replace_verdict], -1
    ; A registered medium, not just its reusable dev pointer, owns this job.
    ; Capture before fd_writer_enter: its recovery may already write.
    mov  rax, [r12 + FD_DEV]
    test rax, rax
    jz   .medium
    mov  [rel fd_cp_dev], rax
    mov  rax, [rax + dev.info]
    test rax, rax
    jz   .medium
    mov  [rel fd_cp_info], rax
    mov  rax, [rax + blk_info.media_generation]
    test rax, rax
    jz   .medium
    mov  [rel fd_cp_generation], rax
    mov  eax, 1
    xchg eax, [rel fd_dir_gate]
    test eax, eax
    jnz  .busy
    mov  qword [rel fd_dir_owner], 0
    mov  byte [rel fd_dir_view_valid], 0
    mov  rdi, r12
    call fd_writer_enter                 ; ROOT recovery completes before any allocation
    test rax, rax
    jnz  .release_gate
    mov  [rel fd_dir_owner], r12
    mov  rdi, r12
    mov  rsi, r14
    lea  rdx, [rel fd_cp_name]
    call fd_mut_parent
    cmp  rax, -1
    je   .unlock
    mov  ebx, eax                        ; destination parent cluster
    ; The copy's own leaf takes the one name floor under the directory view.
    lea  rdi, [rel fd_cp_name]
    lea  rsi, [rel fd_dir_ctx]
    call fd_scratch_name_allowed
    test rax, rax
    jnz  .unlock
    mov  rdi, r12
    mov  esi, ebx
    call fd_cp_view                      ; the destination directory's view, validated and swept
    test rax, rax
    jnz  .unlock
.source:
    mov  rdi, r12
    call fd_cp_views_invalidate
    mov  rdi, r12
    mov  rsi, r13
    mov  byte [rel fd_scan_complete], 0
    mov  dword [rel fat32_disk_last_error], FD_ERR_CHAIN_OR_IO ; do not borrow an earlier authority check
    call fat32_disk_resolve_path_lfn
    test rax, rax
    jz   .source_found
    mov  dword [rel fat32_disk_last_error], FD_ERR_CHAIN_OR_IO ; discard a fast-path miss if its fallback did not complete
    cmp  byte [rel fd_scan_complete], 1
    jne  .unlock                        ; incomplete/corrupt/read failure is never absence
    cmp  byte [rel fd_scan_found], 0
    jne  .unlock
    mov  dword [rel fat32_disk_last_error], FD_ERR_NOT_FOUND
    jmp  .unlock
.source_found:
    cmp  dword [rel fd_tree_on], 0
    jne  .tree
    test byte [rel fd_found_attr], 0x18  ; a directory or volume label is not a file
    jnz  .bad_unlock
    mov  rax, [rel fd_found_dir_lba]
    mov  edx, [rel fd_found_dir_off]
    lea  rsi, [rel fd_source_entry]
    call fd_cp_source_save
    lea  rsi, [rel fd_source_entry]      ; the resolve above scanned (views invalidated): this file's entry
    call fd_cp_take_wrt                  ; E2t: its modification time, for the commit
    mov  eax, [rel fd_found_cluster]
    mov  [rel fd_cp_src_head], eax
    mov  rax, [rel fd_found_size]
    mov  [rel fd_cp_total], rax
    mov  rdi, r12
    mov  esi, [rel fd_cp_src_head]
    mov  rdx, rax
    call fd_validate_file_chain
    test rax, rax
    jnz  .unlock
    test dword [rel fd_cp_mode], FS_CMODE_SKIPSAME
    jz   .policy
    mov  [rel fd_cp_dstdir], ebx
    mov  rdi, r12
    call fd_cp_same_probe                ; smart copy C: an equal-size destination file is compared first
    test rax, rax
    js   .unlock
    cmp  eax, 1
    jne  .policy                         ; free, or a conflict the policy decides as before
    test dword [rel fd_cp_mode], FS_CMODE_KEEPBOTH
    jz   .job                            ; refuse: a difference fails the job, nothing written
    mov  rdi, r12
    mov  rsi, r14
    call fd_cp_pick                      ; keep-both's name, decided now; written only on a difference
    test rax, rax
    jnz  .unlock
    jmp  .job
.policy:
    test dword [rel fd_cp_mode], FS_CMODE_KEEPBOTH
    jz   .refuse_mode
    mov  rdi, r12
    mov  rsi, r14
    call fd_cp_pick                      ; RCQ-20 S4: fd_cp_name = the first free k-th name
    test rax, rax
    jnz  .unlock                         ; a typed refusal or I/O: nothing written
    jmp  .picked
.refuse_mode:
    mov  rdi, r12
    call fd_cp_views_invalidate
    lea  rdi, [rel fd_dir_ctx]
    lea  rsi, [rel fd_cp_name]
    call fd_probe_slot
    cmp  rax, 1
    je   .dst_exists                     ; an existing destination is never overwritten (E2r: unless older)
    test rax, rax
    jnz  .unlock
.picked:
    mov  rdi, r12
    call fd_cp_arm                       ; the journal and the reserved slot (or nothing written)
    test rax, rax
    jnz  .unlock
.job:
    mov  rax, [rel fd_cp_total]
    mov  [r15 + fs_copy_job.total], rax
    mov  qword [r15 + fs_copy_job.done], 0
    mov  dword [r15 + fs_copy_job.error], 0
    mov  dword [r15 + fs_copy_job.state], FS_JOB_RUNNING
    mov  rax, [r12 + FD_DEV]
    mov  [r15 + fs_copy_job.dev], rax    ; the VFS judges durability on this device
    mov  dword [r15 + fs_copy_job.preserved], FS_PRES_FAT
    mov  eax, [rel fd_cp_kept]
    mov  [r15 + fs_copy_job.kept], eax
    mov  [rel fd_cp_job], r15
    mov  [rel fd_cp_ctx], r12
    mov  rdi, r13
    lea  rsi, [rel fd_cp_phase]
    mov  edx, (1 << FD_CP_COPY) | (1 << FD_CP_VERIFY) | (1 << FD_CP_COMPARE)
    call vfs_copy_item_note
    cmp  byte [rel fd_cp_cmp_on], 0
    jne  .compare_first
    call fd_cp_file_start
    xor  eax, eax
    jmp  .release_view                   ; the job keeps FD_TX_BUSY between steps
.compare_first:
    call fd_cp_compare_start             ; smart copy C: no journal yet; a difference arms it (fd_tree_arm)
    xor  eax, eax
    jmp  .release_view
; RCQ-20 S5b: a tree. The source must be a directory (not a label); the destination parent
; is not the source or below it. The name check above already took the destination leaf.
; The top directory takes the request's conflict policy; then it is made, empty, and the
; job walks the source from its first entry. Nothing below the top is touched in BEGIN.
.tree:
    test byte [rel fd_found_attr], 0x08
    jnz  .not_dir
    test byte [rel fd_found_attr], 0x10
    jz   .not_dir
    mov  eax, [rel fd_found_cluster]
    mov  [rel fd_tree_src], eax
    mov  rdi, r12
    mov  esi, ebx
    mov  edx, eax
    call fd_tree_outside                 ; dst parent and each of its ancestors vs the source
    cmp  rax, 1
    je   .inside
    test rax, rax
    jnz  .io
    ; Every file the tree makes stays a path (FD_PATH_DEPTH_MAX components): a level k
    ; directory sits at depth parent+k, its files one below.
    mov  eax, FD_PATH_DEPTH_MAX - 1
    sub  eax, [rel fd_tree_dmax]
    cmp  eax, FS_TREE_DEPTH_MAX
    jle  .dmax
    mov  eax, FS_TREE_DEPTH_MAX
.dmax:
    cmp  eax, 1
    jl   .too_deep
    mov  [rel fd_tree_dmax], eax
    mov  rdi, r12
    mov  esi, [rel fd_tree_src]
    call fd_validate_dir_chain           ; the source directory's chain, to its EOC
    test rax, rax
    jnz  .io
    test dword [rel fd_cp_mode], FS_CMODE_SKIPSAME | FS_CMODE_ASK | FS_CMODE_REPLACE
    jz   .tree_policy
    mov  rdi, r12                        ; smart copy C (E2: and ask; E2r-b2: replace-older): an existing top DIRECTORY is merged into
    call fd_cp_views_invalidate
    lea  rdi, [rel fd_dir_ctx]
    lea  rsi, [rel fd_cp_name]
    call fd_probe_slot
    test rax, rax
    js   .unlock
    jz   .tree_policy                    ; free: made as without the flag
    mov  eax, [rel fd_found_dir_off]
    lea  rcx, [rel fd_sector]
    add  rcx, rax
    test byte [rcx + 11], 0x08
    jnz  .tree_policy                    ; a label or a file of that name: the policy decides
    test byte [rcx + 11], 0x10
    jz   .tree_policy
    movzx eax, word [rcx + 20]
    shl  eax, 16
    mov  ax, [rcx + 26]
    mov  rdi, r12
    mov  esi, eax
    call fd_tree_merge_ok                ; never the source or below it; its chain whole
    cmp  rax, 1
    je   .inside
    test rax, rax
    jnz  .io
    jmp  .tree_made
.tree_policy:
    test dword [rel fd_cp_mode], FS_CMODE_KEEPBOTH
    jz   .tree_refuse
    mov  rdi, r12
    mov  rsi, r14
    call fd_cp_pick                      ; the top directory's name, as a file's (S4)
    test rax, rax
    jnz  .unlock
    jmp  .tree_make
.tree_refuse:
    mov  rdi, r12
    call fd_cp_views_invalidate
    lea  rdi, [rel fd_dir_ctx]
    lea  rsi, [rel fd_cp_name]
    call fd_probe_slot
    cmp  rax, 1
    je   .exists
    test rax, rax
    jnz  .unlock
.tree_make:
    mov  rdi, r12
    call fd_cp_fsinfo_unknown            ; before the tree's first FAT change (its mkdirs flush it first)
    test rax, rax
    jnz  .unlock
    mov  rdi, r12
    call fd_cp_views_invalidate
    lea  rdi, [rel fd_dir_mount]
    lea  rsi, [rel fd_cp_name]
    call fd_mkdir_locked                 ; the top directory (taken meanwhile: EXISTS)
    test rax, rax
    jnz  .unlock
.tree_made:
    mov  dword [rel fd_tree_depth], 1
    mov  dword [rel fd_tree_stop], 0
    xor  ecx, ecx                        ; smart copy B: the source path names failed entries
    lea  rdx, [rel fd_tree_root]
.tree_root:
    mov  al, [r13 + rcx]
    mov  [rdx + rcx], al
    test al, al
    jz   .tree_rooted
    inc  ecx
    cmp  ecx, FS_FAIL_PATH + 1
    jb   .tree_root                      ; longer: every entry is counted, none listed
.tree_rooted:
    mov  [rel fd_tree_root_len], ecx
    lea  rdi, [rel fd_tree_lvl]
    mov  esi, [rel fd_tree_src]
    call fd_tree_level                   ; level 1: the source, into the directory just made
    mov  eax, [rel fd_tree_merge_cl]
    test eax, eax
    jz   .tree_dpath
    mov  [rel fd_tree_lvl + FD_TL_DST], eax   ; smart copy C: or into the existing one
.tree_dpath:
    mov  rsi, r14
    call fd_tree_dpath_begin             ; C: its destination path, for keep-both inside it
    mov  qword [r15 + fs_copy_job.total], FS_TOTAL_UNKNOWN   ; until the walk proves its end
    mov  qword [r15 + fs_copy_job.done], 0
    mov  dword [r15 + fs_copy_job.error], 0
    mov  dword [r15 + fs_copy_job.state], FS_JOB_RUNNING
    mov  rax, [r12 + FD_DEV]
    mov  [r15 + fs_copy_job.dev], rax
    mov  dword [r15 + fs_copy_job.preserved], FS_PRES_FAT
    mov  eax, [rel fd_cp_kept]
    mov  [r15 + fs_copy_job.kept], eax
    mov  dword [r15 + fs_copy_job.tree], 1
    mov  dword [r15 + fs_copy_job.files], 0
    mov  dword [r15 + fs_copy_job.skipped], 0
    mov  [rel fd_cp_job], r15
    mov  [rel fd_cp_ctx], r12
    mov  dword [rel fd_cp_phase], FD_CP_TREE
    xor  eax, eax
    jmp  .release_view
.inside:
    mov  dword [rel vfs_copy_refusal], FS_CREF_INSIDE_SRC
    mov  dword [rel fat32_disk_last_error], FD_ERR_BAD_ARG
    jmp  .unlock
.not_dir:
    mov  dword [rel fat32_disk_last_error], FD_ERR_NOT_DIR
    jmp  .unlock
.allowlist:
    mov  dword [rel fat32_disk_last_error], FD_ERR_ALLOWLIST
    jmp  .unlock
.too_deep:
    mov  dword [rel fat32_disk_last_error], FD_ERR_TOO_DEEP
    jmp  .unlock
.dst_exists:
    test dword [rel fd_cp_mode], FS_CMODE_REPLACE
    jz   .exists
    mov  rdi, r12
    call fd_cp_older                     ; E2r: the existing entry against the source's time
    test rax, rax
    js   .unlock
    cmp  eax, 1
    jne  .not_replaced
    jmp  .picked                         ; fd_cp_arm reserves the old file's own slot
.not_replaced:
    mov  [rel vfs_copy_replace_verdict], eax   ; 0 newer or within 2 s (skipped) / 2 undecided (it asks)
.exists:
    mov  dword [rel vfs_copy_differs], 1 ; E2: an ask item's skip-same answer cannot settle it
    mov  dword [rel fat32_disk_last_error], FD_ERR_EXISTS
    jmp  .unlock
.bad_unlock:
    mov  dword [rel fat32_disk_last_error], FD_ERR_BAD_ARG
    jmp  .unlock
.io:
    mov  dword [rel fat32_disk_last_error], FD_ERR_IO
.unlock:
    mov  dword [r12 + FD_TX_BUSY], 0
    mov  rax, -1
.release_view:
    push rax
    mov  rdi, r12
    call fd_cp_view_release
    pop  rax
.release_gate:
    mov  dword [rel fd_dir_gate], 0
    jmp  .out
.bad:
    mov  dword [rel fat32_disk_last_error], FD_ERR_BAD_ARG
    mov  rax, -1
    jmp  .out
.busy:
    mov  dword [rel fat32_disk_last_error], FD_ERR_BUSY
    mov  rax, -1
    jmp  .out
.not_ready:
    mov  dword [rel fat32_disk_last_error], FD_ERR_NOT_READY
    mov  rax, -1
    jmp  .out
.medium:
    mov  dword [rel vfs_copy_refusal], FS_CREF_MOUNT_CHANGED
    mov  dword [rel fat32_disk_last_error], FD_ERR_NOT_EXACT
    mov  rax, -1
.out:
    test rax, rax
    jns  .returned
    mov  edi, [rel fat32_disk_last_error]
    mov  esi, FS_PRES_FAT
    call vfs_copy_begin_failure
.returned:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; RDI = real ctx, ESI = a directory cluster. The internal view of that directory
; (fd_dir_ctx behind fd_dir_mount), its whole chain validated and its interrupted
; updates swept. The caller holds fd_dir_gate and the writer (fd_dir_owner = RDI).
; -> RAX 0 / -1 (FD_ERR_IO). The view stays valid either way: fd_cp_view_release.
fd_cp_view:
    push rbx
    push rbp
    push r12
    mov  r12, rdi
    mov  ebx, esi
    lea  rdi, [rel fd_dir_ctx]
    mov  rsi, r12
    mov  edx, FD_CTX_SIZE
    call memcpy
    mov  [rel fd_dir_ctx + FD_ROOT_CLUSTER], ebx
    mov  dword [rel fd_dir_ctx + FD_TX_BUSY], 0
    mov  dword [rel fd_dir_ctx + FD_SWEEP_DONE], 0
    mov  dword [rel fd_dir_ctx + FD_SWEEP_CLUSTER], 0
    lea  rax, [rel fd_dir_ctx]
    mov  [rel fd_dir_mount + fsmount.priv], rax
    mov  byte [rel fd_dir_view_valid], 1
    mov  rdi, r12
    call fd_cp_views_invalidate
    lea  rdi, [rel fd_dir_ctx]
    mov  esi, ebx
    call fd_validate_dir_chain
    test rax, rax
    jnz  .io
    mov  ebp, FD_DIR_MAX_CLUSTERS * 128 + 64
.recover:
    lea  rdi, [rel fd_dir_ctx]
    call fd_sweep_step                   ; interrupted updates in the destination directory
    test rax, rax
    jnz  .io
    cmp  dword [rel fd_dir_ctx + FD_SWEEP_DONE], 1
    je   .ok
    dec  ebp
    jnz  .recover
.io:
    mov  dword [rel fat32_disk_last_error], FD_ERR_IO
    mov  rax, -1
    jmp  .out
.ok:
    xor  eax, eax
.out:
    pop  r12
    pop  rbp
    pop  rbx
    ret

; RDI = real ctx: drop the view fd_cp_view built (its orphan count goes back to the
; real context) and both cache tags. The writer (FD_TX_BUSY) and the gate are the
; caller's. Preserves RAX's caller value only through the caller's own save.
fd_cp_view_release:
    push r12
    mov  r12, rdi
    cmp  byte [rel fd_dir_view_valid], 1
    jne  .views_done
    mov  rax, [rel fd_dir_ctx + FD_ORPHANS]
    mov  [r12 + FD_ORPHANS], rax
.views_done:
    mov  rdi, r12
    call fd_cp_views_invalidate
    mov  dword [r12 + FD_FREE_VALID], 0
    mov  byte [rel fd_dir_view_valid], 0
    mov  qword [rel fd_dir_owner], 0
    pop  r12
    ret

; RDI = real ctx, with fd_cp_name free in the view's directory, fd_cp_total and
; fd_cp_src_head set: write the ROOT journal (barrier), then reserve the
; destination slot after it (barrier). -> RAX 0 / -1 (fat32_disk_last_error);
; on -1 nothing is referenced and the journal, if written, is retired.
fd_cp_arm:
    push rbx
    push rbp
    push r12
    mov  r12, rdi
    lea  rdi, [rel fd_dir_ctx]
    lea  rsi, [rel fd_cp_name]
    call fd_write_slot                  ; finish growth before arming a copy journal
    cmp  rax, 1
    je   .capacity_ready                 ; replacement reuses its existing entry
    test rax, rax
    jnz  .fail
.capacity_ready:
    mov  rdi, r12
    call fd_cp_views_invalidate
    mov  rdi, r12
    lea  rsi, [rel fd_tx_plan]
    call fd_find_root_slot               ; the journal slot; a live ~TMPPLAN cannot survive the sweep
    test rax, rax
    jnz  .io
    mov  rax, [rel fd_mut_dir_lba]
    mov  [rel fd_cp_rec_lba], rax
    mov  eax, [rel fd_mut_dir_off]
    mov  [rel fd_cp_rec_off], eax
    ; Refuse early only when the exact free count is already known.
    mov  rax, [rel fd_cp_total]
    mov  ecx, [r12 + FD_CLUSTER_BYTES]
    add  rax, rcx
    dec  rax
    xor  edx, edx
    div  rcx
    cmp  dword [r12 + FD_FREE_VALID], 1
    jne  .space_unknown
    cmp  [r12 + FD_FREE_COUNT], rax
    jae  .space_unknown
    mov  dword [rel fat32_disk_last_error], FD_ERR_NO_SPACE
    jmp  .fail
.space_unknown:
    mov  rdi, r12
    call fd_cp_fsinfo_unknown            ; the FSInfo hint is stale once the FAT changes
    test rax, rax
    jnz  .io
    lea  rdi, [rel fd_cp_rec]
    xor  esi, esi
    mov  edx, 32
    call memset
    lea  rdi, [rel fd_cp_rec]
    lea  rsi, [rel fd_tx_plan]
    mov  edx, 11
    call memcpy
    mov  byte [rel fd_cp_rec + 11], 0x20
    mov  word [rel fd_cp_rec + 12], FD_CP_MAGIC
    mov  eax, [rel fd_cp_total]
    mov  [rel fd_cp_rec + 28], eax
    mov  dword [r12 + FD_SWEEP_DONE], 0  ; a stranded journal is swept before the next writer
    mov  dword [r12 + FD_SWEEP_CLUSTER], 0
    mov  dword [r12 + FD_FREE_VALID], 0
    mov  rdi, r12
    mov  rsi, [rel fd_cp_rec_lba]
    mov  edx, [rel fd_cp_rec_off]
    lea  rcx, [rel fd_cp_rec]
    mov  r8d, 32
    call fd_dir_patch                    ; barrier: the journal precedes every FAT change
    test rax, rax
    jnz  .io
    ; The journal took root's first free slot; reserve the destination after it.
    mov  rdi, r12
    call fd_cp_views_invalidate
    lea  rdi, [rel fd_dir_ctx]
    lea  rsi, [rel fd_cp_name]
    call fd_find_root_slot
    cmp  rax, 1
    je   .taken
    test rax, rax
    jnz  .retire
    cmp  byte [rel fd_cp_repl], 1
    je   .exists_retire                  ; E2r: the file BEGIN judged older is gone: nothing to replace
.reserve:
    mov  rax, [rel fd_mut_dir_lba]
    mov  [rel fd_cp_dst_lba], rax
    sub  rax, [r12 + FD_PART_LBA]
    mov  [rel fd_cp_rec + FD_CP_DST_SEC], eax
    mov  eax, [rel fd_mut_dir_off]
    mov  [rel fd_cp_dst_off], eax
    shr  eax, 5
    mov  [rel fd_cp_rec + FD_CP_DST_IDX], al
    mov  rdi, r12
    mov  rsi, [rel fd_cp_rec_lba]
    mov  edx, [rel fd_cp_rec_off]
    add  edx, FD_CP_DST_SEC
    lea  rcx, [rel fd_cp_rec + FD_CP_DST_SEC]
    mov  r8d, 5
    call fd_dir_patch                    ; barrier: recovery can find the commit slot
    test rax, rax
    jnz  .retire
    xor  eax, eax
    jmp  .out
.taken:
    cmp  byte [rel fd_cp_repl], 1
    jne  .exists_retire
    mov  rax, [rel fd_found_dir_lba]     ; E2r: the old file's own slot, where BEGIN judged it
    cmp  rax, [rel fd_cp_old_lba]
    jne  .exists_retire
    mov  [rel fd_mut_dir_lba], rax
    mov  eax, [rel fd_found_dir_off]
    cmp  eax, [rel fd_cp_old_off]
    jne  .exists_retire
    mov  [rel fd_mut_dir_off], eax
    jmp  .reserve
.exists_retire:
    mov  dword [rel fat32_disk_last_error], FD_ERR_EXISTS
.retire:
    ; No cluster is referenced yet: tombstone the empty journal now. If that
    ; write fails, the next writer's root sweep retires it instead.
    mov  ebp, [rel fat32_disk_last_error]
    mov  rdi, r12
    mov  rsi, [rel fd_cp_rec_lba]
    mov  edx, [rel fd_cp_rec_off]
    xor  ecx, ecx
    call fd_name_commit
    test rax, rax
    jnz  .retire_kept
    mov  dword [r12 + FD_SWEEP_DONE], 1
.retire_kept:
    mov  [rel fat32_disk_last_error], ebp
    jmp  .fail
.io:
    mov  dword [rel fat32_disk_last_error], FD_ERR_IO
.fail:
    mov  rax, -1
.out:
    pop  r12
    pop  rbp
    pop  rbx
    ret

; fd_cp_take_wrt(RSI = the source file's directory entry): fd_cp_wrt = its DIR_WrtTime | WrtDate<<16,
;   which the commit writes into the new entry unchanged (E2t, root 2026-10-17 21:04:41: every copy carries
;   the source mtime; same volume, same zone). 0 (no time) for an entry fat32_disk_update has tagged: its
;   bytes 14..25 hold that update's recovery record, not times. Clobbers EAX only.
fd_cp_take_wrt:
    xor  eax, eax
    cmp  word [rsi + 12], FD_TX_MAGIC
    je   .out
    mov  eax, [rsi + 22]
.out:
    mov  [rel fd_cp_wrt], eax
    ret

; The armed file's copy cursor: nothing referenced yet, the source from its head.
fd_cp_file_start:
    xor  eax, eax
    mov  [rel fd_cp_head], eax
    mov  [rel fd_cp_tail], eax
    mov  [rel fd_cp_done], rax
    mov  eax, [rel fd_cp_src_head]
    mov  [rel fd_cp_src], eax
    mov  dword [rel fd_cp_phase], FD_CP_COPY
    ret

; RDI = a fd_tree_lvl entry, ESI = its source directory's first cluster: read from its
; first entry, into the directory fd_mkdir_locked just made (fd_dirent_buf holds its entry).
fd_tree_level:
    mov  [rdi + FD_TL_FIRST], esi
    mov  [rdi + FD_TL_CL], esi
    mov  dword [rdi + FD_TL_ENT], 0
    mov  dword [rdi + FD_TL_N], 1
    mov  dword [rdi + FD_TL_END], 0
    movzx eax, word [rel fd_dirent_buf + 20]
    shl  eax, 16
    mov  ax, [rel fd_dirent_buf + 26]
    mov  [rdi + FD_TL_DST], eax
    ret

; RCQ-20 S4 keep-both, in BEGIN before the journal: nothing is written here.
; RDI = real context, RSI = destination Z path, fd_cp_name = its 8.3 leaf (allowed).
; Keeps the leaf when it is free (fd_cp_kept 1), else the first free BASE~k.EXT,
; k 2..FS_KEPT_MAX, BASE cut to 6 so the alias fits 8. Taken = any entry whose
; alias or long name equals the candidate, case-insensitively (the long-name
; resolver: the copy never shadows another file's visible name), or a live short
; entry in the destination directory (fd_find_root_slot, labels included). Each
; alias must pass the protected-name floor. The job holds the writer until its
; COMMIT, so nothing else can take the name in between.
; -> RAX 0 (fd_cp_name, fd_cp_kept) / -1 (vfs_copy_refusal or fat32_disk_last_error)
fd_cp_pick:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8
    mov  r12, rdi
    mov  r13, rsi
    xor  ecx, ecx
    xor  ebp, ebp                        ; the directory part: through the last '/'
.scan:
    mov  al, [r13 + rcx]
    test al, al
    jz   .scanned
    inc  ecx
    cmp  al, '/'
    jne  .scan
    mov  ebp, ecx
    jmp  .scan
.scanned:
    cmp  ebp, FD_PATH_MAX - 13           ; room for NAME.EXT + NUL
    ja   .unrepresentable
    lea  rdi, [rel fd_cp_buf]            ; the candidate's path (fd_cp_buf is idle until STEP)
    mov  rsi, r13
    mov  edx, ebp
    call memcpy
    lea  rbx, [rel fd_cp_req]
    mov  rdi, rbx
    lea  rsi, [rel fd_cp_name]
    mov  edx, 11
    call memcpy
    xor  r14d, r14d                      ; the base's length
.base:
    cmp  byte [rbx + r14], ' '
    je   .based
    inc  r14d
    cmp  r14d, 8
    jb   .base
.based:
    cmp  r14d, 6
    jbe  .cut
    mov  r14d, 6
.cut:
    mov  r15d, 1
    jmp  .check                          ; k 1: the requested leaf
.alias:
    lea  rdi, [rel fd_cp_name]
    mov  rsi, rbx
    mov  edx, 8
    call memcpy                          ; (the extension stays as requested)
    lea  rdi, [rel fd_cp_name]
    mov  byte [rdi + r14], '~'
    lea  eax, [r15d + '0']
    mov  [rdi + r14 + 1], al
    lea  ecx, [r14d + 2]
.pad:
    cmp  ecx, 8
    jae  .padded
    mov  byte [rdi + rcx], ' '
    inc  ecx
    jmp  .pad
.padded:
    lea  rsi, [rel fd_dir_ctx]
    call fd_scratch_name_allowed
    test rax, rax
    jnz  .unrepresentable
.check:
    lea  rdi, [rel fd_cp_name]
    lea  rsi, [rel fd_cp_buf]
    add  rsi, rbp
    call fd_short_to_name
    mov  rdi, r12
    call fd_cp_views_invalidate
    mov  byte [rel fd_scan_complete], 0
    mov  dword [rel fd_path_next_index], 0
    mov  rdi, r12
    lea  rsi, [rel fd_cp_buf]
    call fat32_disk_resolve_path_lfn
    test rax, rax
    jz   .taken
    ; The resolver's -1 sets no error. The name is free only when the leaf's
    ; directory was read to its end without a match: a read or chain fault or a
    ; duplicate-entry verdict is an I/O refusal, never a free name (srcreview F2).
    cmp  byte [rel fd_scan_complete], 1
    jne  .io
    mov  eax, [rel fd_path_next_index]
    cmp  eax, [rel fd_path_len]
    jne  .io                             ; (a miss above the leaf: the parent is held, defensive)
    mov  rdi, r12
    call fd_cp_views_invalidate
    lea  rdi, [rel fd_dir_ctx]
    lea  rsi, [rel fd_cp_name]
    call fd_probe_slot
    cmp  rax, 1
    je   .taken
    test rax, rax
    jnz  .fail
    mov  [rel fd_cp_kept], r15d
    mov  dword [rel fat32_disk_last_error], FD_ERR_NONE
    xor  eax, eax
    jmp  .out
.taken:
    inc  r15d
    cmp  r15d, FS_KEPT_MAX
    jbe  .alias
    mov  dword [rel vfs_copy_refusal], FS_CREF_EXHAUSTED
    jmp  .fail
.io:
    mov  dword [rel fat32_disk_last_error], FD_ERR_IO
    jmp  .fail
.unrepresentable:
    mov  dword [rel vfs_copy_refusal], FS_CREF_UNREPRESENTABLE
.fail:
    mov  rax, -1
.out:
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Cancel turns a live copy into a reclaim; steps finish it.
fd_cp_cancel:
    mov  eax, [rel fd_cp_phase]
    cmp  eax, FD_CP_TREE
    je   .between_files
    cmp  eax, FD_CP_COMPARE
    je   .comparing
    cmp  eax, FD_CP_RECLAIM
    je   .reclaiming
    cmp  eax, FD_CP_COPY
    je   .reclaim
    cmp  eax, FD_CP_VERIFY
    jne  .out
.reclaim:
    mov  dword [rel fd_cp_phase], FD_CP_RECLAIM
    mov  dword [rel fd_cp_target], FS_JOB_CANCELLED
.cancelling:
    mov  rax, [rel fd_cp_job]
    mov  dword [rax + fs_copy_job.state], FS_JOB_CANCELLING
.out:
    xor  eax, eax
    ret
.comparing:                              ; smart copy C: nothing written yet; the next step ends the job
    mov  byte [rel fd_cp_cmp_on], 0      ;   (a file job too: .tree ends it with fd_tree_stop)
    mov  dword [rel fd_cp_phase], FD_CP_TREE
.between_files:
    mov  dword [rel fd_tree_stop], FS_JOB_CANCELLED   ; S5b: the next step ends the tree
    jmp  .cancelling
.reclaiming:                             ; smart copy B: a failed tree file's reclaim; the walk
    cmp  dword [rel fd_tree_on], 0       ;   does not go on after it
    je   .out
    mov  dword [rel fd_tree_stop], FS_JOB_CANCELLED
    jmp  .out

; E3b: save the physical source slot, separate from mutable resolver globals.
; RAX=volume LBA, EDX=32-byte slot offset, RSI=entry. Ignore access/create
; timestamps when checking later, but bind alias, attributes, head, size, mtime.
fd_cp_source_save:
    push rdi
    push rcx
    cmp  rax, [rel fd_cp_src_lba]
    jne  .new
    cmp  edx, [rel fd_cp_src_off]
    jne  .new
    mov  rcx, [rsi]
    cmp  rcx, [rel fd_cp_src_entry]
    jne  .new
    mov  cx, [rsi + 8]
    cmp  cx, [rel fd_cp_src_entry + 8]
    jne  .new
    mov  cl, [rsi + 10]
    cmp  cl, [rel fd_cp_src_entry + 10]
    je   .save                          ; attributes may change; this is still the same source slot
.new:
    mov  byte [rel fd_cp_src_retried], 0  ; one fresh retry budget per source slot
.save:
    mov  [rel fd_cp_src_lba], rax
    mov  [rel fd_cp_src_off], edx
    lea  rdi, [rel fd_cp_src_entry]
    mov  ecx, 32
    rep movsb
    pop  rcx
    pop  rdi
    ret

; RDI=ctx, EAX=0 unchanged, 1 changed, -1 read/identity failure.
; A vanished/renamed/non-file slot is listed, never recopied as another file.
fd_cp_source_check:
    call ue_context
    test eax,eax
    jnz ue_guard
    lea rax, [rel fd_data_ctx]
    cmp rdi, rax
    jne .disk_source
    cmp byte [rel fd_data_active], 1
    jne .disk_source
    xor eax, eax                     ; immutable private snapshot, synchronous provider only
    ret
.disk_source:
    push rbx
    mov  rsi, [rel fd_cp_src_lba]
    mov  edx, 1
    lea  rcx, [rel fd_sector]
    call fd_read_sectors
    test rax, rax
    jnz  .io
    lea  rbx, [rel fd_sector]
    mov  eax, [rel fd_cp_src_off]
    add  rbx, rax
    mov  rax, [rbx]
    cmp  rax, [rel fd_cp_src_entry]
    jne  .gone
    mov  ax, [rbx + 8]
    cmp  ax, [rel fd_cp_src_entry + 8]
    jne  .gone
    mov  al, [rbx + 10]
    cmp  al, [rel fd_cp_src_entry + 10]
    jne  .gone
    mov  al, [rbx + 11]
    cmp  al, [rel fd_cp_src_entry + 11]
    je   .metadata
    test al, 0x18                       ; directory/volume alias no longer names our regular file
    jnz  .gone
    jmp  .changed                       ; ordinary flags changed: retry, never report vanished
.metadata:
    mov  ax, [rbx + 20]
    cmp  ax, [rel fd_cp_src_entry + 20]
    jne  .changed
    mov  eax, [rbx + 22]
    cmp  eax, [rel fd_cp_src_entry + 22]
    jne  .changed
    mov  ax, [rbx + 26]
    cmp  ax, [rel fd_cp_src_entry + 26]
    jne  .changed
    mov  eax, [rbx + 28]
    cmp  eax, [rel fd_cp_src_entry + 28]
    jne  .changed
    xor  eax, eax
    jmp  .out
.changed:
    mov  eax, 1
    jmp  .out
.gone:
    mov  dword [rel fat32_disk_last_error], FD_ERR_NOT_FOUND
    jmp  .bad
.io:
    mov  dword [rel fat32_disk_last_error], FD_ERR_IO
.bad:
    mov  rax, -1
.out:
    pop  rbx
    ret

; One bounded step of the live job.
fd_cp_step:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    cmp  dword [rel fd_cp_phase], FD_CP_IDLE
    je   .out
    mov  r12, [rel fd_cp_ctx]
    ; Every phase, including cancellation reclaim and the tree walk, runs
    ; outside BEGIN's request. Refuse stale custody before even reading the
    ; saved geometry. The original medium keeps its journal for remount recovery.
    mov  rax, [r12 + FD_DEV]
    cmp  rax, [rel fd_cp_dev]
    jne  .medium_lost
    test rax, rax
    jz   .medium_lost
    test dword [rax + dev.flags], BLKF_RO
    jnz  .medium_lost
    mov  rax, [rax + dev.info]
    cmp  rax, [rel fd_cp_info]
    jne  .medium_lost
    test rax, rax
    jz   .medium_lost
    mov  rax, [rax + blk_info.media_generation]
    test rax, rax
    jz   .medium_lost
    cmp  rax, [rel fd_cp_generation]
    jne  .medium_lost
    mov  rdi, r12
    call fd_mutation_authorized
    test rax, rax
    jnz  .medium_lost
    mov  dword [rel fat32_disk_last_error], FD_ERR_NONE
    mov  rdi, r12
    call fd_invalidate_caches            ; readers shared the sector/FAT buffers between steps
    mov  eax, FD_CP_STEP_BYTES
    xor  edx, edx
    div  dword [r12 + FD_CLUSTER_BYTES]
    test eax, eax
    jnz  .budget
    inc  eax
.budget:
    mov  ebp, eax                        ; clusters this step
    cmp  dword [rel fd_cp_phase], FD_CP_TREE
    je   .tree
    cmp  dword [rel fd_cp_phase], FD_CP_COMPARE
    je   .compare
    cmp  dword [rel fd_cp_phase], FD_CP_RECLAIM
    je   .reclaim
    ; COPY/VERIFY alone own an armed partial. COMPARE has no journal yet.
    mov  rdi, r12
    call fd_cp_source_check
    test eax, eax
    js   .failed_source
    jnz  .source_changed
    cmp  dword [rel fd_cp_phase], FD_CP_VERIFY
    je   .verify
.copy:
    mov  rax, [rel fd_cp_done]
    cmp  rax, [rel fd_cp_total]
    jae  .terminate
    test ebp, ebp
    jz   .progress
    mov  rdi, r12
    mov  esi, [rel fd_cp_tail]
    call fd_cp_alloc
    cmp  rax, -1
    je   .failed
    mov  ebx, eax
    mov  esi, [rel fd_cp_tail]
    test esi, esi
    jnz  .link
    ; First cluster: the journal references it before any data or FAT entry.
    mov  [rel fd_cp_head], ebx
    mov  [rel fd_cp_rec + 26], bx
    shr  eax, 16
    mov  [rel fd_cp_rec + 20], ax
    mov  dword [rel fd_cp_rec + FD_CP_PREV], 0
    mov  rdi, r12
    mov  rsi, [rel fd_cp_rec_lba]
    mov  edx, [rel fd_cp_rec_off]
    add  edx, 20
    lea  rcx, [rel fd_cp_rec + 20]
    mov  r8d, 8
    call fd_dir_patch                    ; barrier
    test rax, rax
    jnz  .failed
    jmp  .data
.link:
    mov  rdi, r12
    mov  edx, ebx
    call fd_fat_set_pair                 ; FAT1+FAT2: tail -> new (new is still free)
    test rax, rax
    jnz  .failed
    mov  rdi, r12
    call fd_flush                        ; barrier: every referenced cluster is reachable
    test rax, rax
    jnz  .failed
.data:
    mov  r13, [rel fd_cp_total]
    sub  r13, [rel fd_cp_done]
    mov  eax, [r12 + FD_CLUSTER_BYTES]
    cmp  r13, rax
    jbe  .sized
    mov  r13, rax                        ; bytes in this cluster
.sized:
    lea  rcx, [r13 + 511]
    shr  rcx, 9                          ; whole sectors; the last may be partial
    mov  rdi, r12
    mov  esi, [rel fd_cp_src]
    mov  edx, ebx
    xor  r8d, r8d
    call fd_cp_sectors                   ; (a source read fault sets fd_cp_src_fault)
    test rax, rax
    jnz  .failed_io                      ; a data read or write fault (as VERIFY's)
    mov  [rel fd_cp_tail], ebx
    add  [rel fd_cp_done], r13
    mov  rax, [rel fd_cp_done]
    cmp  rax, [rel fd_cp_total]
    jae  .copied
    mov  rdi, r12
    mov  esi, [rel fd_cp_src]
    call fd_cp_next_data
    cmp  rax, -1
    je   .failed_source
    mov  [rel fd_cp_src], eax
.copied:
    dec  ebp
    jmp  .copy
.terminate:
    mov  esi, [rel fd_cp_tail]
    test esi, esi
    jz   .chain_done                     ; an empty source has no chain
    mov  rdi, r12
    mov  edx, 0x0FFFFFFF
    call fd_fat_set_pair
    test rax, rax
    jnz  .failed
    mov  rdi, r12
    call fd_flush                        ; barrier: data and the terminated chain
    test rax, rax
    jnz  .failed
.chain_done:
    mov  rdi, r12
    mov  esi, [rel fd_cp_head]
    mov  rdx, [rel fd_cp_total]
    call fd_validate_file_chain
    test rax, rax
    jnz  .failed
    mov  eax, [rel fd_cp_src_head]
    mov  [rel fd_cp_src], eax
    mov  eax, [rel fd_cp_head]
    mov  [rel fd_cp_vdst], eax
    mov  qword [rel fd_cp_vdone], 0
    mov  dword [rel fd_cp_phase], FD_CP_VERIFY
    mov  rax, [rel fd_cp_job]
    mov  rcx, [rel fd_cp_total]
    add  rcx, [rel fd_tree_base]         ; 0 outside a tree
    mov  [rax + fs_copy_job.done], rcx
    mov  dword [rax + fs_copy_job.state], FS_JOB_VERIFYING
.verify:
    mov  rax, [rel fd_cp_vdone]
    cmp  rax, [rel fd_cp_total]
    jae  .commit
    test ebp, ebp
    jz   .progress
    mov  r13, [rel fd_cp_total]
    sub  r13, [rel fd_cp_vdone]
    mov  eax, [r12 + FD_CLUSTER_BYTES]
    cmp  r13, rax
    jbe  .vsized
    mov  r13, rax
.vsized:
    lea  rcx, [r13 + 511]
    shr  rcx, 9
    mov  rdi, r12
    mov  esi, [rel fd_cp_src]
    mov  edx, [rel fd_cp_vdst]
    mov  r8d, 1
    call fd_cp_sectors                   ; fresh reads of both chains
    test rax, rax
    jnz  .failed_io
    add  [rel fd_cp_vdone], r13
    mov  rax, [rel fd_cp_vdone]
    cmp  rax, [rel fd_cp_total]
    jae  .verified
    mov  rdi, r12
    mov  esi, [rel fd_cp_src]
    call fd_cp_next_data
    cmp  rax, -1
    je   .failed_io
    mov  [rel fd_cp_src], eax
    mov  rdi, r12
    mov  esi, [rel fd_cp_vdst]
    call fd_cp_next_data
    cmp  rax, -1
    je   .failed_io
    mov  [rel fd_cp_vdst], eax
.verified:
    dec  ebp
    jmp  .verify
.commit:
    cmp  byte [rel fd_cp_repl], 1
    jne  .commit_entry
    call fd_cp_repl_arm                  ; E2r: the old chain recorded (barrier) before its slot changes
    test rax, rax
    jnz  .failed
.commit_entry:
    lea  rdi, [rel fd_cp_dent]
    xor  esi, esi
    mov  edx, 32
    call memset
    lea  rdi, [rel fd_cp_dent]
    lea  rsi, [rel fd_cp_name]
    mov  edx, 11
    call memcpy
    mov  byte [rel fd_cp_dent + 11], 0x20
    mov  eax, [rel fd_cp_head]
    mov  [rel fd_cp_dent + 26], ax
    shr  eax, 16
    mov  [rel fd_cp_dent + 20], ax
    mov  eax, [rel fd_cp_total]
    mov  [rel fd_cp_dent + 28], eax
    mov  eax, [rel fd_cp_wrt]
    mov  [rel fd_cp_dent + 22], eax      ; E2t: the source's DIR_WrtTime/WrtDate (0: it had none)
    mov  al, [rel fd_cp_old_case]
    mov  [rel fd_cp_dent + 12], al       ; E2r: a replaced entry keeps its lower-case bits (0 otherwise)
    mov  rdi, r12
    mov  rsi, [rel fd_cp_dst_lba]
    mov  edx, [rel fd_cp_dst_off]
    lea  rcx, [rel fd_cp_dent]
    mov  r8d, 32
    call fd_dir_patch                    ; THE commit: one complete dirent, entry last
    test rax, rax
    jnz  .failed                         ; recovery reads the slot to learn whether it landed
    cmp  byte [rel fd_cp_repl], 1
    je   .swapped
    mov  rdi, r12
    mov  rsi, [rel fd_cp_rec_lba]
    mov  edx, [rel fd_cp_rec_off]
    xor  ecx, ecx
    call fd_name_commit                  ; retire the journal (post-commit cleanup)
    test rax, rax
    jnz  .committed                      ; the next root sweep retires it as committed
    mov  dword [r12 + FD_SWEEP_DONE], 1
.committed:
    cmp  dword [rel fd_tree_on], 0
    jne  .tree_committed
    mov  ebx, FS_JOB_DONE
    jmp  .finish
.tree_committed:
    call fd_tree_count                   ; FILES_DONE and the byte base, only after the commit
    mov  rax, [rel fd_cp_job]
    mov  dword [rax + fs_copy_job.state], FS_JOB_RUNNING
    mov  dword [rel fd_cp_phase], FD_CP_TREE
    jmp  .invalidate
.swapped:                                ; E2r: the old chain goes next, a batch per step through
    mov  byte [rel fd_cp_swapped], 1     ;   ~TMPREPL, then that record, then the plan; DONE after
    mov  dword [rel fd_cp_target], FS_JOB_DONE
    mov  dword [rel fd_cp_phase], FD_CP_RECLAIM
    mov  rax, [rel fd_cp_job]
    inc  dword [rax + fs_copy_job.replaced]   ; E2r-b: FSJOB REPLACED, counted at the swap
    jmp  .invalidate
.source_changed:
    mov  dword [rel fat32_disk_last_error], FD_ERR_SOURCE_CHANGED
    jmp  .failed_source
.failed_source:
    mov  byte [rel fd_cp_src_fault], 1   ; smart copy B: this file's own source chain
    jmp  .failed
.failed_io:
    mov  dword [rel fat32_disk_last_error], FD_ERR_IO
.failed:
    mov  eax, [rel fat32_disk_last_error]
    mov  [rel fd_cp_error], eax
    mov  rcx, [rel fd_cp_job]
    mov  [rcx + fs_copy_job.error], eax
    mov  dword [rel fd_cp_phase], FD_CP_RECLAIM
    mov  dword [rel fd_cp_target], FS_JOB_FAILED
    mov  dword [rcx + fs_copy_job.state], FS_JOB_CANCELLING
    jmp  .invalidate
.reclaim:
    mov  rdi, r12
    mov  rsi, [rel fd_cp_rec_lba]
    mov  edx, [rel fd_cp_rec_off]
    call fd_cp_recover
    cmp  rax, 1
    je   .invalidate
    test rax, rax
    jnz  .stranded
    mov  dword [r12 + FD_SWEEP_DONE], 1
    mov  ebx, [rel fd_cp_target]
    cmp  byte [rel fd_cp_swapped], 1
    je   .swap_done
    cmp  byte [rel fd_cp_committed], 1
    jne  .reclaimed
    mov  rax, [rel fd_cp_job]            ; the commit landed but its barrier failed:
    mov  dword [rax + fs_copy_job.durable], FS_DUR_UNCERTAIN   ; complete, durability unknown
    cmp  dword [rel fd_tree_on], 0
    jne  .tree_landed
    mov  ebx, FS_JOB_DONE
    jmp  .finish
.tree_landed:
    call fd_tree_count                   ; S5b: that file counts; the tree still ends with the target
    jmp  .finish
.reclaimed:                              ; smart copy B: a tree file that failed on its own source,
    cmp  dword [rel fd_tree_on], 0       ;   reclaimed whole: listed, and the walk goes on
    je   .finish
    cmp  ebx, FS_JOB_FAILED
    jne  .finish
    cmp  byte [rel fd_cp_src_fault], 0
    je   .finish
    cmp  dword [rel fd_cp_error], FD_ERR_SOURCE_CHANGED
    jne  .source_list
    cmp  byte [rel fd_cp_src_retried], 0
    jne  .source_list
    cmp  dword [rel fd_tree_stop], 0
    jne  .source_list
    ; The old journal is completely gone. Rewalk precisely the consumed slot
    ; to take fresh metadata and reapply the original destination policy.
    mov  byte [rel fd_cp_src_retried], 1
    mov  byte [rel fd_cp_src_retry_pending], 1
    mov  eax, [rel fd_tree_depth]
    dec  eax
    imul eax, FD_TL_SIZE
    lea  rcx, [rel fd_tree_lvl]
    dec  dword [rcx + rax + FD_TL_ENT]
    jmp  .source_continue
.source_list:
    mov  edi, [rel fd_cp_error]
    lea  rsi, [rel fd_tree_leaf]
    call fd_tree_fail_note
    test eax, eax
    jz   .finish
    mov  ebx, [rel fd_tree_stop]
    test ebx, ebx
    jnz  .finish                         ; cancelled while it was reclaimed
.source_continue:
    mov  rax, [rel fd_cp_job]
    mov  dword [rax + fs_copy_job.error], 0
    mov  dword [rax + fs_copy_job.state], FS_JOB_RUNNING
    mov  rcx, [rel fd_tree_base]
    mov  [rax + fs_copy_job.done], rcx
    mov  dword [rel fd_cp_error], 0
    mov  dword [rel fd_cp_phase], FD_CP_TREE
    jmp  .invalidate
.stranded:
    mov  dword [r12 + FD_SWEEP_DONE], 0  ; (also armed at BEGIN) the next writer sweeps first
    mov  ebx, FS_JOB_FAILED              ; the journal stays for the next root sweep
    cmp  byte [rel fd_cp_swapped], 1
    jne  .finish
    mov  ebx, FS_JOB_DONE                ; E2r: the swap landed; the old chain's ~TMPREPL waits for that sweep
.swap_done:
    mov  byte [rel fd_cp_swapped], 0
    cmp  dword [rel fd_tree_on], 0
    jne  .tree_committed
    jmp  .finish
.medium_lost:
    ; Do not reclaim through a changed medium or let the idle root sweeper
    ; follow our old journal there. Only an explicit mount can admit it again.
    mov  dword [r12 + FD_MOUNTED], 0
    mov  byte [r12 + FD_EXACT_BOUND], 0
    mov  dword [r12 + FD_SWEEP_DONE], 0
    mov  dword [rel fat32_disk_last_error], FD_ERR_NOT_EXACT
    mov  rax, [rel fd_cp_job]
    mov  dword [rax + fs_copy_job.error], FD_ERR_NOT_EXACT
    mov  dword [rax + fs_copy_job.durable], FS_DUR_NO
    mov  ebx, FS_JOB_FAILED
.finish:
    mov  rax, [rel fd_cp_job]
    mov  [rax + fs_copy_job.state], ebx
    cmp  dword [rel fd_tree_on], 0
    jne  .tree_done_bytes
    cmp  ebx, FS_JOB_DONE
    jne  .released
    mov  rcx, [rel fd_cp_total]
    mov  [rax + fs_copy_job.done], rcx
    jmp  .released
.tree_done_bytes:
    mov  rcx, [rel fd_tree_base]         ; S5b: the committed files' bytes, never a reclaimed one's
    mov  [rax + fs_copy_job.done], rcx
.released:
    mov  dword [rel fd_cp_phase], FD_CP_IDLE
    mov  dword [r12 + FD_FREE_VALID], 0
    mov  dword [r12 + FD_TX_BUSY], 0
    jmp  .invalidate
.progress:
    cmp  dword [rel fd_cp_phase], FD_CP_COPY
    jne  .invalidate
    mov  rax, [rel fd_cp_job]
    mov  rcx, [rel fd_cp_done]
    add  rcx, [rel fd_tree_base]
    mov  [rax + fs_copy_job.done], rcx
    jmp  .invalidate
; Smart copy C: an existing destination file of the source's size, read against the source a
; cluster at a time over the file's bytes only. Equal to its end: skipped (SKIPPED_SAME), nothing
; written. A difference: keep-both arms the copy under the name picked before the compare; refuse
; fails a file job (exists) and lists a tree's file. Its own reads may fault: a source read is one
; bad file in a tree (B), a destination read ends the job.
.compare:
    cmp  dword [rel fd_dir_gate], 0
    jne  .invalidate                     ; a synchronous view is live: wait a tick (a difference arms)
    mov  rax, [rel fd_cp_vdone]
    cmp  rax, [rel fd_cp_total]
    jae  .same
    test ebp, ebp
    jz   .invalidate
    mov  r13, [rel fd_cp_total]
    sub  r13, [rel fd_cp_vdone]
    mov  eax, [r12 + FD_CLUSTER_BYTES]
    cmp  r13, rax
    jbe  .csized
    mov  r13, rax
.csized:
    mov  [rel fd_cp_cmp_left], r13
    lea  rcx, [r13 + 511]
    shr  rcx, 9
    mov  rdi, r12
    mov  esi, [rel fd_cp_src]
    mov  edx, [rel fd_cp_vdst]
    mov  r8d, 2
    call fd_cp_sectors                   ; read-only: 1 they differ
    cmp  rax, 1
    je   .differs
    test rax, rax
    jnz  .compare_io
    add  [rel fd_cp_vdone], r13
    mov  rax, [rel fd_cp_vdone]
    cmp  rax, [rel fd_cp_total]
    jae  .compared
    mov  rdi, r12
    mov  esi, [rel fd_cp_src]
    call fd_cp_next_data
    cmp  rax, -1
    je   .compare_source
    mov  [rel fd_cp_src], eax
    mov  rdi, r12
    mov  esi, [rel fd_cp_vdst]
    call fd_cp_next_data
    cmp  rax, -1
    je   .compare_io
    mov  [rel fd_cp_vdst], eax
.compared:
    dec  ebp
    jmp  .compare
.same:
    mov  byte [rel fd_cp_cmp_on], 0
    mov  rax, [rel fd_cp_job]
    inc  dword [rax + fs_copy_job.same]
    cmp  dword [rel fd_tree_on], 0
    jne  .tree_same
    mov  qword [rel fd_cp_total], 0      ; a file job copied nothing: DONE=TOTAL=0, SKIPPED_SAME=1
    mov  qword [rax + fs_copy_job.total], 0
    mov  ebx, FS_JOB_DONE
    jmp  .finish
.tree_same:
    mov  dword [rax + fs_copy_job.fail_run], 0   ; both files read whole: not a failing medium
    mov  dword [rel fd_cp_phase], FD_CP_TREE
    jmp  .invalidate
.differs:
    mov  byte [rel fd_cp_cmp_on], 0
    test dword [rel fd_cp_mode], FS_CMODE_REPLACE
    jz   .differs_keepboth
    ; Reprobe the taken name and apply the existing older/eligibility/arm path.
    ; Mask only SKIPSAME during this synchronous call: no second compare loop.
    and  dword [rel fd_cp_mode], ~FS_CMODE_SKIPSAME
    mov  rdi, r12
    mov  esi, [rel fd_cp_dstdir]
    call fd_tree_file
    or   dword [rel fd_cp_mode], FS_CMODE_SKIPSAME
    test rax, rax
    jz   .differs_armed
    cmp  eax, 3
    je   .differs_not_older
    cmp  eax, 2
    jne  .differs_arm_failed
    mov  dword [rel vfs_copy_replace_verdict], 2
    mov  rax, [rel fd_cp_job]
    cmp  dword [rel fd_tree_on], 0
    jne  .differs_refused
    mov  qword [rax + fs_copy_job.total], 0 ; no copied bytes to fold into the waiting parent
    jmp  .differs_refused
.differs_not_older:
    cmp  dword [rel fd_tree_on], 0
    je   .differs_file_skip
    mov  dword [rel fd_cp_phase], FD_CP_TREE
    jmp  .tree_not_older
.differs_file_skip:
    mov  rax, [rel fd_cp_job]
    inc  dword [rax + fs_copy_job.skipped]
    mov  qword [rax + fs_copy_job.total], 0
    mov  qword [rel fd_cp_total], 0
    mov  ebx, FS_JOB_DONE
    jmp  .finish
.differs_keepboth:
    test dword [rel fd_cp_mode], FS_CMODE_KEEPBOTH
    jz   .differs_refused
    mov  rdi, r12
    mov  esi, [rel fd_cp_dstdir]
    call fd_tree_arm                     ; the journal and the slot, now
    test rax, rax
    jnz  .differs_arm_failed
.differs_armed:
    mov  dword [rel fat32_disk_last_error], FD_ERR_NONE
    call fd_cp_file_start
    jmp  .invalidate
.differs_arm_failed:
    cmp  dword [rel fd_tree_on], 0
    jne  .tree_failed                    ; a destination refusal at a file's arm ends a tree (as B)
    jmp  .compare_failed
.differs_refused:
    cmp  dword [rel fd_tree_on], 0
    jne  .compare_conflict
    mov  dword [rel vfs_copy_differs], 1 ; E2: an ask item's skip-same answer found it different
    mov  dword [rel fat32_disk_last_error], FD_ERR_EXISTS
    jmp  .compare_failed
.compare_conflict:
    mov  dword [rel fd_cp_phase], FD_CP_TREE
    jmp  .tree_conflict
.compare_source:
    mov  byte [rel fd_cp_src_fault], 1
.compare_io:
    mov  byte [rel fd_cp_cmp_on], 0
    mov  dword [rel fat32_disk_last_error], FD_ERR_IO
    cmp  dword [rel fd_tree_on], 0
    je   .compare_failed
    cmp  byte [rel fd_cp_src_fault], 0
    je   .tree_failed                    ; the destination's read: not one bad file
    mov  dword [rel fd_cp_phase], FD_CP_TREE
    mov  edi, FD_ERR_IO
    lea  rsi, [rel fd_tree_leaf]
    call fd_tree_fail_note
    test eax, eax
    jz   .tree_failed
    jmp  .invalidate
.compare_failed:                         ; a file job: nothing was written, nothing to reclaim
    mov  eax, [rel fat32_disk_last_error]
    mov  [rel fd_cp_error], eax
    mov  rcx, [rel fd_cp_job]
    mov  [rcx + fs_copy_job.error], eax
    mov  ebx, FS_JOB_FAILED
    jmp  .finish
; RCQ-20 S5b: a tree between files. One step does one of: read up to FD_TREE_WALK_K
; entries, make one directory and push it, or arm one file (its copy runs on the
; next steps, through the file phases above). A fault is never an end of directory:
; a level ends only at its chain's EOC, as fat32_disk_list_path.
.tree:
    cmp  dword [rel fd_tree_stop], 0
    jne  .tree_stopped
    cmp  dword [rel fd_dir_gate], 0
    jne  .invalidate                     ; a synchronous view is live: the walk waits a tick
    mov  r14d, FD_TREE_WALK_K
.tree_level:
    mov  ebp, -1                         ; no sector of this level in fd_sector yet
    mov  eax, [rel fd_tree_depth]
    dec  eax
    imul eax, eax, FD_TL_SIZE
    lea  r13, [rel fd_tree_lvl]
    add  r13, rax
    mov  rdi, r12
    mov  esi, [r13 + FD_TL_FIRST]
    call fd_validate_dir_chain           ; the whole chain again: a crafted change is a fault
    test rax, rax
    jnz  .tree_io
    cmp  byte [rel fd_cp_src_retry_pending], 0
    je   .tree_retry_ready
    mov  byte [rel fd_cp_src_retry_pending], 0
    mov  rdi, r12
    call fd_cp_source_check             ; the same slot can vanish while cleanup yielded
    test eax, eax
    js   .tree_retry_missing
.tree_retry_ready:
.tree_entry:
    mov  eax, [r12 + FD_CLUSTER_BYTES]
    shr  eax, 5
    cmp  [r13 + FD_TL_ENT], eax
    jb   .tree_read
    mov  rdi, r12
    mov  esi, [r13 + FD_TL_CL]
    call fd_next_cluster
    mov  r15d, eax
    mov  rdi, r12
    mov  esi, eax
    call fd_classify_next
    cmp  eax, 1
    je   .tree_pop                       ; this directory was read to its EOC
    test eax, eax
    jnz  .tree_io
    cmp  dword [r13 + FD_TL_N], FD_DIR_MAX_CLUSTERS
    jae  .tree_io
    inc  dword [r13 + FD_TL_N]
    mov  [r13 + FD_TL_CL], r15d
    mov  dword [r13 + FD_TL_ENT], 0
    mov  ebp, -1
.tree_read:
    mov  ebx, [r13 + FD_TL_ENT]
    inc  dword [r13 + FD_TL_ENT]         ; consumed, whatever it holds
    cmp  dword [r13 + FD_TL_END], 0
    jne  .tree_next                      ; past the 0x00 mark: free until the EOC
    mov  ecx, ebx
    shr  ecx, 4
    cmp  ecx, ebp
    je   .tree_entry_at                  ; that sector is still in fd_sector
    mov  ebp, ecx
    mov  rdi, r12
    mov  esi, [r13 + FD_TL_CL]
    call fd_cluster_lba
    cmp  rax, -1
    je   .tree_io
    mov  ecx, ebx
    shr  ecx, 4
    lea  rsi, [rax + rcx]
    mov  rdi, r12
    mov  edx, 1
    lea  rcx, [rel fd_sector]
    call fd_read_sectors
    test rax, rax
    jnz  .tree_io
.tree_entry_at:
    and  ebx, 15
    shl  ebx, 5
    lea  rax, [rel fd_sector]
    add  rbx, rax
    cmp  byte [rbx], 0
    je   .tree_end_mark
    cmp  byte [rbx], 0xE5
    je   .tree_next
    cmp  byte [rbx + 11], 0x0F
    je   .tree_next                      ; long-name parts: the 8.3 alias is copied (PRESERVED)
    test byte [rbx + 11], 0x08
    jnz  .tree_next                      ; the volume label
    mov  rdi, rbx
    call fd_short_is_dot
    test eax, eax
    jnz  .tree_next
    lea  rdi, [rel fd_cp_name]
    mov  rsi, rbx
    mov  edx, 11
    call memcpy
    mov  rax, [rel fd_cp_name]
    cmp  rax, [rel fd_tx_plan]
    je   .tree_skip                      ; an internal recovery name is never copied
    cmp  rax, [rel fd_tx_temp]
    je   .tree_skip
    cmp  rax, [rel fd_tx_repl]           ; E2r
    je   .tree_skip
    cmp  rax, [rel fd_grow_name]
    je   .tree_skip
    movzx eax, word [rbx + 20]
    shl  eax, 16
    mov  ax, [rbx + 26]
    mov  r15d, eax                       ; its first cluster
    test byte [rbx + 11], 0x10
    jnz  .tree_dir
    ; Keep the source slot separate from destination/journal lookup globals.
    push rbx
    mov  rdi, r12
    mov  esi, [r13 + FD_TL_CL]
    call fd_cluster_lba
    mov  edx, [r13 + FD_TL_ENT]
    dec  edx
    mov  ecx, edx
    shr  ecx, 4
    add  rax, rcx
    and  edx, 15
    shl  edx, 5
    mov  rsi, rbx
    call fd_cp_source_save
    pop  rbx
    mov  [rel fd_cp_src_head], r15d
    mov  eax, [rbx + 28]
    mov  [rel fd_cp_total], rax
    mov  rsi, rbx
    call fd_cp_take_wrt                  ; E2t: the walked entry's modification time
    lea  rdi, [rel fd_tree_leaf]         ; smart copy B: the name a failure is listed by
    lea  rsi, [rel fd_cp_name]
    mov  edx, 11
    call memcpy
    lea  rdi, [rel fd_tree_leaf]
    lea  rsi, [rel fd_tree_alias]
    call fd_short_to_name
    lea  rdi, [rel fd_tree_alias]
    lea  rsi, [rel fd_cp_phase]
    mov  edx, (1 << FD_CP_COPY) | (1 << FD_CP_VERIFY) | (1 << FD_CP_COMPARE)
    call vfs_copy_item_note
    mov  byte [rel fd_cp_src_fault], 0
    mov  rdi, r12
    mov  esi, [r13 + FD_TL_DST]
    call fd_tree_file                    ; the journal and the slot in that directory
    test rax, rax
    js   .tree_file_failed
    jnz  .tree_file_same                 ; smart copy C (FS_CMODE_SKIPSAME): nothing written
    mov  dword [rel fat32_disk_last_error], FD_ERR_NONE   ; this file's own errors only, as a BEGIN's
    call fd_cp_file_start
    jmp  .invalidate
.tree_file_same:
    cmp  eax, 3
    je   .tree_not_older
    cmp  eax, 1
    jne  .tree_conflict                  ; 2: a conflict the policy refuses
    call fd_cp_compare_start             ; 1: an equal-size file there, compared first
    jmp  .invalidate
.tree_retry_missing:
    inc  dword [r13 + FD_TL_ENT]        ; consume the old slot, never copy its new alias
    mov  edi, [rel fat32_disk_last_error]
    lea  rsi, [rel fd_tree_leaf]
    call fd_tree_fail_note
    test eax, eax
    jz   .tree_failed
    jmp  .invalidate
.tree_file_failed:                       ; smart copy B: its own source chain, nothing written: listed,
    cmp  byte [rel fd_cp_src_fault], 0   ;   and the walk goes on (a destination refusal still ends it)
    je   .tree_failed
    mov  edi, [rel fat32_disk_last_error]
    lea  rsi, [rel fd_tree_leaf]
    call fd_tree_fail_note
    test eax, eax
    jz   .tree_failed                    ; FS_FAIL_RUN with no commit between: not one bad file
    jmp  .invalidate
.tree_dir:
    mov  eax, [rel fd_tree_depth]
    cmp  eax, [rel fd_tree_dmax]
    jae  .tree_too_deep                  ; found at discovery: nothing below is made
    lea  rdx, [rel fd_tree_lvl]
    xor  ecx, ecx
.tree_cycle:
    cmp  r15d, [rdx + FD_TL_FIRST]
    je   .tree_io                        ; a directory naming one of its ancestors
    add  rdx, FD_TL_SIZE
    inc  ecx
    cmp  ecx, eax
    jb   .tree_cycle
    mov  rdi, r12
    mov  esi, r15d
    call fd_validate_dir_chain
    test rax, rax
    jnz  .tree_io
    lea  rdi, [rel fd_tree_leaf]         ; its source alias (smart copy C: keep-both may rename the copy)
    lea  rsi, [rel fd_cp_name]
    mov  edx, 11
    call memcpy
    mov  dword [rel fd_tree_merge_cl], 0
    mov  rdi, r12
    mov  esi, [r13 + FD_TL_DST]
    test dword [rel fd_cp_mode], FS_CMODE_SKIPSAME | FS_CMODE_ASK | FS_CMODE_REPLACE
    jnz  .tree_dir_probe                 ; E2r-b2: a replace-older tree merges as well
    call fd_tree_mkdir
    test rax, rax
    jnz  .tree_failed
    jmp  .tree_push
.tree_dir_probe:
    call fd_tree_dir_probe               ; C: made, merged into an existing directory, or refused
    test rax, rax
    js   .tree_failed
    cmp  eax, 2
    je   .tree_dir_conflict              ; nothing below it is copied
.tree_push:
    lea  rdi, [r13 + FD_TL_SIZE]
    mov  esi, r15d
    call fd_tree_level
    mov  eax, [rel fd_tree_merge_cl]
    test eax, eax
    jz   .tree_pushed
    mov  [r13 + FD_TL_SIZE + FD_TL_DST], eax   ; C: the level writes into the existing directory
.tree_pushed:
    mov  eax, [rel fd_tree_depth]
    lea  rcx, [rel fd_tree_dlen]
    mov  esi, [rcx + rax*4 - 4]
    mov  edi, eax
    call fd_tree_dpath_add               ; C: its destination path, for keep-both below it
    imul edi, [rel fd_tree_depth], 11    ; smart copy B: its path part for the failure list
    lea  rax, [rel fd_tree_names]
    add  rdi, rax
    lea  rsi, [rel fd_tree_leaf]
    mov  edx, 11
    call memcpy
    inc  dword [rel fd_tree_depth]
    jmp  .invalidate
.tree_dir_conflict:
    mov  byte [rel fd_tree_cdir], 1      ; E2: an ask walk's item is a directory
.tree_conflict:                          ; C: refused by the policy: listed, never a failure run
    mov  edi, FD_ERR_EXISTS
    lea  rsi, [rel fd_tree_leaf]
    call fd_tree_conflict_note
    jmp  .invalidate
.tree_skip:
    mov  rax, [rel fd_cp_job]
    inc  dword [rax + fs_copy_job.skipped]
    jmp  .tree_next
.tree_not_older:                         ; E2r-b2: the destination is not older: SKIPPED, the walk goes on
    mov  rax, [rel fd_cp_job]
    inc  dword [rax + fs_copy_job.skipped]
    jmp  .invalidate
.tree_end_mark:
    mov  dword [r13 + FD_TL_END], 1
.tree_next:
    dec  r14d
    jnz  .tree_entry
    jmp  .invalidate
.tree_pop:
    dec  dword [rel fd_tree_depth]
    jz   .tree_walked
    dec  r14d
    jnz  .tree_level
    jmp  .invalidate
.tree_walked:
    mov  rax, [rel fd_cp_job]            ; every directory read to its EOC: TOTAL is now exact
    mov  rcx, [rel fd_tree_base]
    mov  [rax + fs_copy_job.total], rcx
    mov  ebx, FS_JOB_DONE
    jmp  .finish
.tree_stopped:
    mov  ebx, [rel fd_tree_stop]
    jmp  .finish
.tree_too_deep:                          ; smart copy B: listed, neither it nor anything below is made
    mov  dword [rel fat32_disk_last_error], FD_ERR_TOO_DEEP
    mov  edi, FD_ERR_TOO_DEEP
    lea  rsi, [rel fd_cp_name]
    call fd_tree_fail_note
    test eax, eax
    jz   .tree_failed
    jmp  .invalidate
.tree_io:
    mov  dword [rel fat32_disk_last_error], FD_ERR_IO
.tree_failed:
    mov  eax, [rel fat32_disk_last_error]
    mov  [rel fd_cp_error], eax
    mov  rcx, [rel fd_cp_job]
    mov  [rcx + fs_copy_job.error], eax
    mov  ebx, FS_JOB_FAILED
    jmp  .finish
.invalidate:
    mov  rdi, r12
    call fd_invalidate_caches
.out:
    xor  eax, eax
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; RCQ-20 S5b: a committed (or landed) tree file: FILES_DONE+1, its bytes into the base.
fd_tree_count:
    mov  rax, [rel fd_cp_total]
    add  [rel fd_tree_base], rax
    mov  rcx, [rel fd_cp_job]
    inc  dword [rcx + fs_copy_job.files]
    mov  dword [rcx + fs_copy_job.fail_run], 0   ; smart copy B: a commit ends a run of failures
    mov  rax, [rel fd_tree_base]
    mov  [rcx + fs_copy_job.done], rax
    ret

; fd_tree_fail_note(EDI=error, RSI=the entry's 11-byte alias) -> RAX 1 the walk goes on / 0 it ends.
; Smart copy B: list one tree entry not copied by its source path (BEGIN's path, the aliases of the
; levels below it, the entry's), through vfs_copy_fail_note. Reads and writes no volume.
fd_tree_fail_note:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    mov  ebp, edi
    mov  r14, rsi
    lea  r12, [rel fd_tree_fpath]
    mov  ebx, [rel fd_tree_root_len]
    mov  rdi, r12
    lea  rsi, [rel fd_tree_root]
    mov  edx, ebx
    call memcpy
    mov  r13d, 1                         ; level 1 is the source itself
.level:
    cmp  r13d, [rel fd_tree_depth]
    jae  .leaf
    imul edi, r13d, 11
    lea  rax, [rel fd_tree_names]
    add  rdi, rax
    call .part
    inc  r13d
    jmp  .level
.leaf:
    mov  rdi, r14
    call .part
    mov  edx, ebx
    cmp  edx, FS_FAIL_PATH
    jbe  .note
    mov  edx, -1                         ; too long to list: counted only
.note:
    mov  rdi, [rel fd_cp_job]
    mov  rsi, r12
    mov  ecx, ebp
    cmp  ecx, FD_ERR_NOT_FOUND
    je   .source_item
    cmp  ecx, FD_ERR_SOURCE_CHANGED
    jne  .operational
.source_item:
    call vfs_copy_source_note          ; E3: expected source churn is not a device fault
    jmp  .noted
.operational:
    call vfs_copy_fail_note
.noted:
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret
.part:                                   ; RDI = an alias: append "/NAME.EXT", EBX bounded
    lea  rsi, [rel fd_tree_alias]
    call fd_short_to_name
    cmp  ebx, FS_FAIL_PATH
    ja   .over
    test ebx, ebx
    jz   .sep
    cmp  byte [r12 + rbx - 1], '/'
    je   .copy
.sep:
    mov  byte [r12 + rbx], '/'
    inc  ebx
.copy:
    lea  rsi, [rel fd_tree_alias]
.char:
    mov  al, [rsi]
    test al, al
    jz   .done
    cmp  ebx, FS_FAIL_PATH
    ja   .over
    mov  [r12 + rbx], al
    inc  ebx
    inc  rsi
    jmp  .char
.over:
    mov  ebx, FS_FAIL_PATH + 1
.done:
    ret

; RDI = real ctx, ESI = the destination parent's cluster, EDX = the source directory's.
; Walks '..' from the parent to the root. -> RAX 1 the parent is the source or below it,
; 0 not (fd_tree_dmax = the parent's depth below the root), -1 a read or a bad '..'.
fd_tree_outside:
    push rbx
    push rbp
    push r12
    push r13
    mov  r12, rdi
    mov  ebx, esi
    mov  r13d, edx
    xor  ebp, ebp
.up:
    cmp  ebx, r13d
    je   .inside
    cmp  ebx, [r12 + FD_ROOT_CLUSTER]
    je   .outside
    inc  ebp
    cmp  ebp, FD_PATH_DEPTH_MAX
    ja   .fail
    mov  rdi, r12
    mov  esi, ebx
    call fd_cluster_lba
    cmp  rax, -1
    je   .fail
    mov  rsi, rax
    mov  rdi, r12
    mov  edx, 1
    lea  rcx, [rel fd_sector]
    call fd_read_sectors
    test rax, rax
    jnz  .fail
    cmp  word [rel fd_sector + 32], '..'
    jne  .fail
    test byte [rel fd_sector + 43], 0x10
    jz   .fail
    movzx eax, word [rel fd_sector + 52]
    shl  eax, 16
    mov  ax, [rel fd_sector + 58]
    test eax, eax
    jnz  .parent
    mov  eax, [r12 + FD_ROOT_CLUSTER]    ; FAT32 '..' of a root child is zero
.parent:
    mov  ebx, eax
    jmp  .up
.outside:
    mov  [rel fd_tree_dmax], ebp
    xor  eax, eax
    jmp  .out
.inside:
    mov  eax, 1
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; RDI = real ctx, between a tree's steps (the job holds its FD_TX_BUSY): take the view
; gate for one destination directory and re-probe the mount's authority, as a BEGIN does.
; -> RAX 0 (gate held) / -1 (fat32_disk_last_error; nothing held).
fd_tree_enter:
    push r12
    mov  r12, rdi
    mov  eax, 1
    xchg eax, [rel fd_dir_gate]
    test eax, eax
    jnz  .busy
    mov  byte [rel fd_dir_view_valid], 0
    mov  byte [rel fd_dir_inside], 1     ; BEGIN proved the tree inside an FSWDIR* tree
    mov  [rel fd_dir_owner], r12
    mov  rdi, r12
    call fd_mutation_authorized
    test rax, rax
    jz   .out
    mov  qword [rel fd_dir_owner], 0
    mov  byte [rel fd_dir_inside], 0
    mov  dword [rel fd_dir_gate], 0
    jmp  .out
.busy:
    mov  dword [rel fat32_disk_last_error], FD_ERR_BUSY
    mov  rax, -1
.out:
    pop  r12
    ret

; RDI = real ctx: the view and the gate fd_tree_enter took. RAX is kept.
fd_tree_leave:
    push rax
    call fd_cp_view_release
    mov  byte [rel fd_dir_inside], 0
    mov  dword [rel fd_dir_gate], 0
    pop  rax
    ret

; RDI = real ctx, ESI = a destination directory (fd_cp_name, fd_cp_src_head and
; fd_cp_total name the file): arm that file as BEGIN arms one. -> RAX 0 armed / 1 compare first / 2 a
; conflict the policy refuses / 3 (E2r-b2, FS_CMODE_REPLACE) the destination is not older: nothing written / -1.
; Under FS_CMODE_REPLACE a taken name goes by fd_cp_older: older is armed into the old file's slot, undecided is
; the conflict 2 (it waits), an old chain that fails validation is -1 (as a single file's BEGIN refuses it).
fd_tree_file:
    push rbx
    push r12
    sub  rsp, 8
    mov  r12, rdi
    mov  ebx, esi
    call fd_tree_enter
    test rax, rax
    jnz  .out
    mov  rdi, r12
    mov  esi, ebx
    call fd_cp_view
    test rax, rax
    jnz  .leave
    mov  rdi, r12
    mov  esi, [rel fd_cp_src_head]
    mov  rdx, [rel fd_cp_total]
    call fd_validate_file_chain
    test rax, rax
    jz   .arm
    mov  byte [rel fd_cp_src_fault], 1   ; smart copy B: the source file's own chain
    jmp  .leave
.arm:
    mov  byte [rel fd_cp_repl], 0        ; E2r-b2: each tree file decides its own replace
    mov  byte [rel fd_cp_old_case], 0
    test dword [rel fd_cp_mode], FS_CMODE_SKIPSAME | FS_CMODE_ASK | FS_CMODE_REPLACE
    jz   .arm_now
    mov  [rel fd_cp_dstdir], ebx
    mov  rdi, r12
    call fd_cp_same_probe                ; smart copy C: 0 free / 1 compare first / 2 a conflict / -1
    test rax, rax
    js   .leave
    jz   .arm_now
    mov  [rsp], rax
    mov  ecx, [rel fd_cp_mode]
    and  ecx, FS_CMODE_SKIPSAME | FS_CMODE_REPLACE
    cmp  ecx, FS_CMODE_SKIPSAME | FS_CMODE_REPLACE
    jne  .replace_policy
    cmp  rax, 1
    je   .probed                         ; combined policy: complete byte equality decides first
.replace_policy:
    test dword [rel fd_cp_mode], FS_CMODE_REPLACE
    jz   .not_replace
    mov  byte [rel fd_cp_cmp_on], 0      ; E2r-b2: the name is taken; no compare, its time decides
    mov  rdi, r12
    call fd_cp_older                     ;   on fd_cp_same_probe's match (fd_sector, fd_found_dir_off)
    test rax, rax
    js   .leave                          ; a damaged old chain or I/O: never replaced; the tree fails as BEGIN refuses
    cmp  eax, 1
    je   .arm_now                        ; older: fd_cp_arm reserves the old file's own slot
    test eax, eax
    jnz  .repl_conflict                  ; undecided: it waits (or is listed)
    mov  eax, 3                          ; not older: skipped, nothing written
    jmp  .leave
.repl_conflict:
    mov  byte [rel fd_cp_repl], 0
    mov  dword [rel fat32_disk_last_error], FD_ERR_EXISTS
    mov  eax, 2
    jmp  .leave
.not_replace:
    test dword [rel fd_cp_mode], FS_CMODE_SKIPSAME
    jnz  .probe_policy
    mov  byte [rel fd_cp_cmp_on], 0      ; E2: an ask walk compares only under a skip-same answer:
    mov  qword [rsp], 2                  ;   the name is taken (keep-both's answer picks without one)
.probe_policy:
    test dword [rel fd_cp_mode], FS_CMODE_KEEPBOTH
    jz   .probed                         ; refuse: compare, or listed; nothing written either way
    mov  rdi, r12
    call fd_tree_pick                    ; keep-both's name, decided now (nothing written)
    test rax, rax
    jnz  .pick_refused
    cmp  qword [rsp], 1
    je   .probed                         ; the compare decides whether that name is ever written
.arm_now:
    mov  rdi, r12
    call fd_cp_arm                       ; a name taken in a new directory: EXISTS, nothing kept
    jmp  .leave
.pick_refused:
    cmp  dword [rel vfs_copy_refusal], 0
    je   .leave                          ; I/O
    mov  dword [rel vfs_copy_refusal], 0
    mov  byte [rel fd_cp_cmp_on], 0
    mov  eax, 2                          ; no free k-th name: listed as the conflict it is
    jmp  .leave
.probed:
    mov  rax, [rsp]
.leave:
    mov  rdi, r12
    call fd_tree_leave
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; RDI = real ctx, ESI = a destination directory: make fd_cp_name in it (fd_dirent_buf
; then holds its entry). -> RAX 0 / -1.
fd_tree_mkdir:
    push rbx
    push r12
    sub  rsp, 8
    mov  r12, rdi
    mov  ebx, esi
    call fd_tree_enter
    test rax, rax
    jnz  .out
    mov  rdi, r12
    mov  esi, ebx
    call fd_cp_view
    test rax, rax
    jnz  .leave
    mov  rdi, r12
    call fd_cp_views_invalidate
    lea  rdi, [rel fd_dir_mount]
    lea  rsi, [rel fd_cp_name]
    call fd_mkdir_locked
.leave:
    mov  rdi, r12
    call fd_tree_leave
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; ---- Smart copy C (FS_CMODE_SKIPSAME) ----
; fd_cp_same_probe(RDI = real ctx; fd_dir_ctx = the destination directory's view, fd_cp_name its
; leaf, fd_cp_total the source's size) -> RAX 0 the name is free, 1 an existing regular file of
; that size whose chain holds it (fd_cp_cmp_head, fd_cp_cmp_on: compare it first), 2 taken by
; anything else (a directory, a label, another size, a chain that does not hold its size: a
; conflict, never compared or written), -1 I/O. Reads only.
fd_cp_same_probe:
    push rbx
    push r12
    sub  rsp, 8
    mov  r12, rdi
    mov  byte [rel fd_cp_cmp_on], 0
    call fd_cp_views_invalidate
    lea  rdi, [rel fd_dir_ctx]
    lea  rsi, [rel fd_cp_name]
    call fd_probe_slot
    cmp  rax, 1
    jne  .out                            ; 0 free / -1 I/O
    mov  eax, [rel fd_found_dir_off]
    lea  rbx, [rel fd_sector]
    add  rbx, rax                        ; the existing entry, in fd_find_root_slot's sector
    mov  eax, 2
    test byte [rbx + 11], 0x18
    jnz  .out
    mov  ecx, [rbx + 28]
    cmp  rcx, [rel fd_cp_total]
    jne  .out
    movzx esi, word [rbx + 20]
    shl  esi, 16
    mov  si, [rbx + 26]
    mov  [rel fd_cp_cmp_head], esi
    mov  rdi, r12
    mov  rdx, [rel fd_cp_total]
    call fd_validate_file_chain
    test rax, rax
    mov  eax, 2
    jnz  .out
    mov  dword [rel fat32_disk_last_error], FD_ERR_NONE
    mov  byte [rel fd_cp_cmp_on], 1
    mov  eax, 1
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; The compare cursor: both chains from their heads (VERIFY's cursors, idle until a copy).
fd_cp_compare_start:
    mov  eax, [rel fd_cp_src_head]
    mov  [rel fd_cp_src], eax
    mov  eax, [rel fd_cp_cmp_head]
    mov  [rel fd_cp_vdst], eax
    mov  qword [rel fd_cp_vdone], 0
    mov  dword [rel fd_cp_phase], FD_CP_COMPARE
    ret

; RDI = real ctx, ESI = the destination directory of a compared file that differs: arm its copy
; there under fd_cp_name (keep-both's, picked before the compare). -> RAX 0 / -1.
fd_tree_arm:
    push rbx
    push r12
    sub  rsp, 8
    mov  r12, rdi
    mov  ebx, esi
    call fd_tree_enter
    test rax, rax
    jnz  .out
    mov  rdi, r12
    mov  esi, ebx
    call fd_cp_view
    test rax, rax
    jnz  .leave
    mov  rdi, r12
    call fd_cp_arm
.leave:
    mov  rdi, r12
    call fd_tree_leave
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; fd_tree_conflict_note(EDI=error, RSI=alias): fd_tree_fail_note for a conflict the policy refuses:
; listed and counted (FAILED), but it never ends the walk or adds to a run of failures (not a fault).
; E2: under FS_CMODE_ASK it waits instead (fd_tree_wait), listed only when it cannot.
fd_tree_conflict_note:
    push rbx
    push rbp
    push r12
    push r13
    sub  rsp, 8
    mov  r12d, edi
    mov  r13, rsi
    movzx ebp, byte [rel fd_tree_cdir]
    mov  byte [rel fd_tree_cdir], 0
    test dword [rel fd_cp_mode], FS_CMODE_ASK | FS_CMODE_REPLACE
    jz   .listed                         ; E2r-b2: a replace-older tree asks too (an undecided file)
    mov  edi, ebp
    mov  rsi, r13
    call fd_tree_wait
    cmp  eax, 1
    je   .out
.listed:
    mov  rbx, [rel fd_cp_job]
    mov  ebp, [rbx + fs_copy_job.fail_run]
    mov  edi, r12d
    mov  rsi, r13
    call fd_tree_fail_note
    mov  [rbx + fs_copy_job.fail_run], ebp
.out:
    add  rsp, 8
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; fd_tree_wait(EDI = 1 a directory / 0 a file, RSI = its 8.3 alias) -> EAX 1 taken by the job's WAITING list
; (vfs_copy_wait_note) / 2 not: the caller lists it. E2: the source path as fd_tree_fail_note builds it, the
; destination path as keep-both resolves it (fd_tree_dpath at this level, then the alias). Reads nothing.
fd_tree_wait:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    mov  ebp, edi
    mov  r14, rsi
    lea  r12, [rel fd_tree_fpath]
    mov  ebx, [rel fd_tree_root_len]
    mov  rdi, r12
    lea  rsi, [rel fd_tree_root]
    mov  edx, ebx
    call memcpy
    mov  r13d, 1                         ; level 1 is the source itself
.level:
    cmp  r13d, [rel fd_tree_depth]
    jae  .leaf
    imul edi, r13d, 11
    lea  rax, [rel fd_tree_names]
    add  rdi, rax
    call fd_tree_fail_note.part
    inc  r13d
    jmp  .level
.leaf:
    mov  rdi, r14
    call fd_tree_fail_note.part
    mov  r13d, ebx
    cmp  r13d, FS_WAIT_PATH
    ja   .cannot
    mov  eax, [rel fd_tree_depth]
    lea  rcx, [rel fd_tree_dlen]
    mov  ebx, [rcx + rax*4 - 4]
    cmp  ebx, FS_WAIT_PATH - 13          ; room for "/NAME.EXT"
    ja   .cannot
    lea  rdi, [rel fd_tree_wpath]
    lea  rsi, [rel fd_tree_dpath]
    mov  edx, ebx
    call memcpy
    mov  rdi, r14
    lea  rsi, [rel fd_tree_alias]
    call fd_short_to_name
    lea  rdx, [rel fd_tree_wpath]
    mov  byte [rdx + rbx], '/'
    inc  ebx
    lea  rsi, [rel fd_tree_alias]
.char:
    mov  al, [rsi]
    test al, al
    jz   .note
    mov  [rdx + rbx], al
    inc  ebx
    inc  rsi
    jmp  .char
.note:
    mov  rdi, [rel fd_cp_job]
    mov  esi, FS_WK_FILE
    test ebp, ebp
    jz   .kind
    mov  esi, FS_WK_DIR
.kind:
    lea  rdx, [rel fd_tree_fpath]
    mov  ecx, r13d
    lea  r8, [rel fd_tree_wpath]
    mov  r9d, ebx
    call vfs_copy_wait_note
    jmp  .out
.cannot:
    mov  eax, 2
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; RDI = real ctx, ESI = an existing destination directory a level would merge into. -> RAX 0 it
; may (fd_tree_merge_cl = ESI), 1 it is the tree's source or below it, -1 a read or a bad chain.
fd_tree_merge_ok:
    push rbx
    push rbp
    push r12
    mov  r12, rdi
    mov  ebx, esi
    mov  ebp, [rel fd_tree_dmax]
    mov  rdi, r12
    mov  esi, ebx
    mov  edx, [rel fd_tree_src]
    call fd_tree_outside                 ; '..' from the directory itself up to the root
    mov  [rel fd_tree_dmax], ebp         ; (fd_tree_outside rewrites it)
    cmp  rax, 1
    je   .out
    test rax, rax
    jnz  .io
    mov  rdi, r12
    mov  esi, ebx
    call fd_validate_dir_chain
    test rax, rax
    jnz  .io
    mov  [rel fd_tree_merge_cl], ebx
    jmp  .out
.io:
    mov  dword [rel fat32_disk_last_error], FD_ERR_IO
    mov  rax, -1
.out:
    pop  r12
    pop  rbp
    pop  rbx
    ret

; fd_tree_dpath_begin(RSI = BEGIN's destination Z path; fd_cp_name = the top directory's 8.3 name):
; fd_tree_dpath = the path of the directory a level writes (BEGIN's parent part, then each level's
; 8.3 name), which keep-both resolves names against (fd_tree_pick). Past FD_PATH_MAX - 32 bytes it is
; marked too long (FD_PATH_MAX + 1) and keep-both below it is name_unrepresentable.
fd_tree_dpath_begin:
    xor  ecx, ecx
    xor  edx, edx
.scan:
    mov  al, [rsi + rcx]
    test al, al
    jz   .scanned
    inc  ecx
    cmp  al, '/'
    jne  .scan
    lea  edx, [ecx - 1]
    jmp  .scan
.scanned:
    cmp  edx, FD_PATH_MAX - 32
    ja   .over
    push rdx
    lea  rdi, [rel fd_tree_dpath]
    call memcpy
    pop  rsi
    jmp  .add
.over:
    mov  esi, FD_PATH_MAX + 1
.add:
    xor  edi, edi
    jmp  fd_tree_dpath_add

; fd_tree_dpath_add(ESI = the current length, EDI = the new level's index; fd_cp_name its name):
; append "/NAME.EXT" and record the length as fd_tree_dlen[EDI].
fd_tree_dpath_add:
    push rbx
    push r12
    sub  rsp, 8
    mov  ebx, esi
    mov  r12d, edi
    cmp  ebx, FD_PATH_MAX - 32
    ja   .over
    lea  rdi, [rel fd_cp_name]
    lea  rsi, [rel fd_tree_alias]
    call fd_short_to_name
    lea  rdx, [rel fd_tree_dpath]
    mov  byte [rdx + rbx], '/'
    inc  ebx
    lea  rsi, [rel fd_tree_alias]
.char:
    mov  al, [rsi]
    test al, al
    jz   .done
    mov  [rdx + rbx], al
    inc  ebx
    inc  rsi
    jmp  .char
.over:
    mov  ebx, FD_PATH_MAX + 1
.done:
    lea  rax, [rel fd_tree_dlen]
    mov  [rax + r12*4], ebx
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; fd_tree_pick(RDI = real ctx), inside fd_tree_enter's gate with the current level's destination
; view held: keep-both for fd_cp_name there, as BEGIN's (fd_cp_pick against fd_tree_dpath).
; -> RAX 0 / -1 (vfs_copy_refusal: a typed refusal; else I/O). Nothing is written.
fd_tree_pick:
    push rbx
    push r12
    sub  rsp, 8
    mov  r12, rdi
    mov  eax, [rel fd_tree_depth]
    lea  rcx, [rel fd_tree_dlen]
    mov  ebx, [rcx + rax*4 - 4]
    cmp  ebx, FD_PATH_MAX - 32
    ja   .unrepresentable
    lea  rdi, [rel fd_tree_ppath]
    lea  rsi, [rel fd_tree_dpath]
    mov  edx, ebx
    call memcpy
    lea  rax, [rel fd_tree_ppath]
    mov  dword [rax + rbx], 0x782F       ; "/x": fd_cp_pick reads the directory part only
    mov  rdi, r12
    lea  rsi, [rel fd_tree_ppath]
    call fd_cp_pick
    jmp  .out
.unrepresentable:
    mov  dword [rel vfs_copy_refusal], FS_CREF_UNREPRESENTABLE
    mov  rax, -1
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; fd_tree_dir_probe(RDI = real ctx, ESI = the destination directory; fd_cp_name = a source
; directory's alias) -> RAX 0 made (fd_dirent_buf holds it; keep-both may have renamed it), 1 an
; existing directory of that name to merge into (fd_tree_merge_cl), 2 a conflict the policy
; refuses, or a directory that is the tree's source or below it (nothing written), -1.
fd_tree_dir_probe:
    push rbx
    push r12
    sub  rsp, 8
    mov  r12, rdi
    mov  ebx, esi
    call fd_tree_enter
    test rax, rax
    jnz  .out
    mov  rdi, r12
    mov  esi, ebx
    call fd_cp_view
    test rax, rax
    jnz  .leave
    mov  rdi, r12
    call fd_cp_views_invalidate
    lea  rdi, [rel fd_dir_ctx]
    lea  rsi, [rel fd_cp_name]
    call fd_probe_slot
    test rax, rax
    js   .leave
    jz   .make
    mov  eax, [rel fd_found_dir_off]
    lea  rcx, [rel fd_sector]
    add  rcx, rax
    test byte [rcx + 11], 0x08
    jnz  .conflict
    test byte [rcx + 11], 0x10
    jz   .conflict
    movzx eax, word [rcx + 20]
    shl  eax, 16
    mov  ax, [rcx + 26]
    mov  rdi, r12
    mov  esi, eax
    call fd_tree_merge_ok
    test rax, rax
    js   .leave
    jnz  .refused
    mov  eax, 1
    jmp  .leave
.conflict:
    test dword [rel fd_cp_mode], FS_CMODE_KEEPBOTH
    jz   .refused
    mov  rdi, r12
    call fd_tree_pick
    test rax, rax
    jz   .make
    cmp  dword [rel vfs_copy_refusal], 0
    je   .leave
    mov  dword [rel vfs_copy_refusal], 0
.refused:
    mov  eax, 2
    jmp  .leave
.make:
    mov  rdi, r12
    call fd_cp_fsinfo_unknown            ; a merge has changed no FAT so far
    test rax, rax
    jnz  .leave
    mov  rdi, r12
    call fd_cp_views_invalidate
    lea  rdi, [rel fd_dir_mount]
    lea  rsi, [rel fd_cp_name]
    call fd_mkdir_locked
.leave:
    mov  rdi, r12
    call fd_tree_leave
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; RDI=ctx, ESI=cluster -> RAX=next data cluster, or -1 when the chain ends or is bad.
fd_cp_next_data:
    cmp esi,UE_SOURCE
    jne .ue_legacy
    call ue_context
    test eax,eax
    jz .ue_legacy
    mov eax,UE_SOURCE
    ret
.ue_legacy:
    cmp esi, FD_DATA_SOURCE
    jne .disk_source
    lea rax, [rel fd_data_ctx]
    cmp rdi, rax
    jne .disk_source
    cmp byte [rel fd_data_active], 1
    jne .disk_source
    mov eax, FD_DATA_SOURCE
    ret
.disk_source:
    push rbx
    push r12
    mov  r12, rdi
    call fd_next_cluster
    mov  ebx, eax
    mov  rdi, r12
    mov  esi, eax
    call fd_classify_next
    test eax, eax
    jnz  .bad
    mov  eax, ebx
    jmp  .out
.bad:
    mov  dword [rel fat32_disk_last_error], FD_ERR_CHAIN_OR_IO
    mov  rax, -1
.out:
    pop  r12
    pop  rbx
    ret

; RDI=ctx, ESI=tail (referenced but still free in the FAT; 0 for a new chain)
; -> RAX=free cluster. Continue this job's search across file boundaries instead
; of rescanning the occupied prefix for every small file. The hint is only a
; starting position: fresh FAT1==FAT2 is still required for every sector, and a
; complete wrap revisits holes before the hint. Never return root or the live
; still-free tail. No allocation, metadata write or durability barrier is cached.
fd_cp_alloc:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r15d, esi
    mov  eax, [rel fd_cp_alloc_hint]
    cmp  eax, 2
    jb   .reset_hint
    cmp  eax, [r12 + FD_MAX_CLUSTER]
    jb   .hint
.reset_hint:
    mov  eax, 2
.hint:
    mov  r14d, eax
    and  r14d, 127                       ; first sector starts at the hinted entry
    mov  r13d, eax
    shr  r13d, 7
.start:
    mov  rbp, [r12 + FD_FAT_SECTORS]
    inc  rbp                             ; one lap plus the start sector again
.sector:
    mov  rdi, r12
    mov  esi, r13d
    call fd_read_fat_pair
    test rax, rax
    jnz  .fail
.entry:
    mov  ebx, r13d
    shl  ebx, 7
    add  ebx, r14d
    cmp  ebx, 2
    jb   .next_entry
    cmp  ebx, [r12 + FD_MAX_CLUSTER]
    jae  .wrap
    cmp  ebx, [r12 + FD_ROOT_CLUSTER]
    je   .next_entry
    cmp  ebx, r15d
    je   .next_entry
    lea  rdx, [rel fd_fat_sector]
    mov  eax, [rdx + r14*4]
    and  eax, 0x0FFFFFFF
    jz   .found
.next_entry:
    inc  r14d
    cmp  r14d, 128
    jb   .entry
    xor  r14d, r14d
    inc  r13d
    cmp  r13, [r12 + FD_FAT_SECTORS]
    jb   .lap
.wrap:
    xor  r13d, r13d
    xor  r14d, r14d
.lap:
    dec  rbp
    jnz  .sector
    mov  dword [rel fat32_disk_last_error], FD_ERR_NO_SPACE
    jmp  .fail_raw
.found:
    lea  eax, [rbx + 1]
    mov  [rel fd_cp_alloc_hint], eax     ; revalidated next call; tail remains caller-owned
    mov  eax, ebx
    jmp  .out
.fail:
    mov  dword [rel fat32_disk_last_error], FD_ERR_IO
.fail_raw:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; RDI=ctx, ESI=source cluster, EDX=destination cluster, RCX=sectors (1..SPC),
; R8D=0 copy source->destination, 1 compare them. RAX 0 / -1.
; Smart copy C: R8D=2 compares the first fd_cp_cmp_left bytes only (it counts down) and answers
; RAX 1 when they differ; a source read fault marks fd_cp_src_fault, as a copy's does.
fd_cp_sectors:
    cmp esi,UE_SOURCE
    jne .ue_legacy
    call ue_context
    test eax,eax
    jnz ue_memory_sectors
.ue_legacy:
    cmp esi, FD_DATA_SOURCE
    jne .disk_source
    lea rax, [rel fd_data_ctx]
    cmp rdi, rax
    jne .disk_source
    cmp byte [rel fd_data_active], 1
    je fd_data_sectors
.disk_source:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  ebx, edx
    mov  r15, rcx
    mov  ebp, r8d
    call fd_cluster_lba
    cmp  rax, -1
    je   .fail
    mov  r13, rax
    mov  rdi, r12
    mov  esi, ebx
    call fd_cluster_lba
    cmp  rax, -1
    je   .fail
    mov  r14, rax
.batch:
    test r15, r15
    jz   .ok
    mov  rbx, r15
    cmp  rbx, 8
    jbe  .io
    mov  ebx, 8
.io:
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, rbx
    lea  rcx, [rel fd_cp_buf]
    call fd_read_sectors
    test rax, rax
    jnz  .source
    mov  rdi, r12
    mov  rsi, r14
    mov  rdx, rbx
    test ebp, ebp
    jnz  .compare
    lea  rcx, [rel fd_cp_buf]
    call fd_write_sectors
    test rax, rax
    jnz  .fail
    jmp  .advance
.compare:
    lea  rcx, [rel fd_cp_vbuf]
    call fd_read_sectors
    test rax, rax
    jnz  .fail
    lea  rdi, [rel fd_cp_buf]
    lea  rsi, [rel fd_cp_vbuf]
    mov  rdx, rbx
    shl  rdx, 9
    cmp  ebp, 2
    jne  .cmp
    cmp  rdx, [rel fd_cp_cmp_left]
    jbe  .cmp_left
    mov  rdx, [rel fd_cp_cmp_left]       ; smart copy C: the file's bytes, never its last cluster's slack
.cmp_left:
    sub  [rel fd_cp_cmp_left], rdx
.cmp:
    call memcmp
    test rax, rax
    jz   .advance
    cmp  ebp, 2
    jne  .fail
    mov  eax, 1                          ; C: they differ (not a fault)
    jmp  .out
.advance:
    add  r13, rbx
    add  r14, rbx
    sub  r15, rbx
    jmp  .batch
.ok:
    xor  eax, eax
    jmp  .out
.source:
    cmp  ebp, 1
    je   .fail                           ; (VERIFY's re-read is not a copy's source fault)
    mov  byte [rel fd_cp_src_fault], 1   ; smart copy B: the source sector, not the destination
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; The FAT32 FSInfo free count is an optional hint. Ordinary mutations keep a
; known count exact through fd_fsinfo_apply. A copy or directory growth, whose
; journal recovery redoes FAT changes after a crash lost the pending delta,
; marks it unknown (0xFFFFFFFF, FAT spec) first, so fsck and other systems
; recount instead of trusting a stale value. Absent or malformed FSInfo is left
; alone. RAX 0 / -1 (I/O).
fd_cp_fsinfo_unknown:
    push rbx
    push r12
    mov  r12, rdi
    mov  rsi, [r12 + FD_PART_LBA]
    mov  edx, 1
    lea  rcx, [rel fd_sector]
    call fd_read_sectors
    test rax, rax
    jnz  .fail
    movzx ebx, word [rel fd_sector + 48]
    test ebx, ebx
    jz   .ok
    movzx eax, word [rel fd_sector + 14]  ; reserved sectors
    cmp  ebx, eax
    jae  .ok
    add  rbx, [r12 + FD_PART_LBA]
    mov  rdi, r12
    mov  rsi, rbx
    mov  edx, 1
    lea  rcx, [rel fd_sector]
    call fd_read_sectors
    test rax, rax
    jnz  .fail
    cmp  dword [rel fd_sector], 0x41615252
    jne  .ok
    cmp  dword [rel fd_sector + 484], 0x61417272
    jne  .ok
    cmp  dword [rel fd_sector + 488], 0xFFFFFFFF
    je   .ok
    mov  dword [rel fd_sector + 488], 0xFFFFFFFF
    mov  rdi, r12
    mov  rsi, rbx
    mov  edx, 1
    lea  rcx, [rel fd_sector]
    call fd_write_sectors                ; ordered by the journal's leading flush
    test rax, rax
    jnz  .fail
.ok:
    xor  eax, eax
    jmp  .out
.fail:
    mov  dword [rel fat32_disk_last_error], FD_ERR_IO
    mov  rax, -1
.out:
    pop  r12
    pop  rbx
    ret

; fd_fsinfo_apply(RDI=ctx) -> RAX 0 / -1 (I/O; fd_flush ignores it): fold
;   the clusters that fd_fat_set_pair freed (+) or took (-) since the last
;   flush into a known FSInfo free count. Unknown (0xFFFFFFFF), absent or malformed FSInfo is left
;   alone; a count that would leave 0..clusters becomes unknown. The delta is
;   consumed before any I/O, so a failed write is never replayed onto a hint.
;   Uses the last sector of fd_fat_scan1 (the free-scan batch is idle at
;   every flush; restore_pair uses only its first sector).
fd_fsinfo_apply:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    movsxd r13, dword [r12 + FD_FSINFO_DELTA]
    test r13, r13
    jz   .ok
    mov  dword [r12 + FD_FSINFO_DELTA], 0
    mov  rdi, r12
    mov  rsi, [r12 + FD_PART_LBA]
    mov  edx, 1
    lea  rcx, [rel fd_fat_scan1 + 3584]
    call fd_read_sectors
    test rax, rax
    jnz  .fail
    movzx ebx, word [rel fd_fat_scan1 + 3584 + 48]
    test ebx, ebx
    jz   .ok
    movzx eax, word [rel fd_fat_scan1 + 3584 + 14]  ; reserved sectors
    cmp  ebx, eax
    jae  .ok
    add  rbx, [r12 + FD_PART_LBA]
    mov  rdi, r12
    mov  rsi, rbx
    mov  edx, 1
    lea  rcx, [rel fd_fat_scan1 + 3584]
    call fd_read_sectors
    test rax, rax
    jnz  .fail
    lea  rcx, [rel fd_fat_scan1 + 3584]
    cmp  dword [rcx], 0x41615252
    jne  .ok
    cmp  dword [rcx + 484], 0x61417272
    jne  .ok
    mov  eax, [rcx + 488]
    cmp  eax, 0xFFFFFFFF
    je   .ok
    mov  edx, [r12 + FD_CLUSTER_COUNT]
    cmp  rax, rdx
    ja   .unknown
    add  rax, r13                          ; below zero wraps above the bound
    cmp  rax, rdx
    jbe  .store
.unknown:
    mov  eax, 0xFFFFFFFF
.store:
    mov  [rcx + 488], eax
    mov  rdi, r12
    mov  rsi, rbx
    mov  edx, 1
    lea  rcx, [rel fd_fat_scan1 + 3584]
    call fd_write_sectors
    test rax, rax
    jnz  .fail
.ok:
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=ctx, RSI=journal sector, EDX=journal offset. One bounded pass:
; committed -> retire the journal; abandoned -> free up to FD_CP_RECLAIM_STEP
; clusters forward. Each free first advances the journal {cursor:=next,
; prev:=C} in one sector write, so a cut anywhere is idempotent and O(1).
; RAX 0 = journal retired (fd_cp_committed says how), 1 = more work,
; -1 = malformed/I/O (fails closed, frees nothing it cannot prove).
fd_cp_recover:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  ebp, edx
    mov  r15d, FD_CP_RECLAIM_STEP
.again:
    mov  rdi, r12
    mov  rsi, r13
    mov  edx, ebp
    lea  rcx, [rel fd_cp_rec]
    call fd_tx_read_entry
    test rax, rax
    jnz  .fail
    cmp  word [rel fd_cp_rec + 12], FD_CP_MAGIC
    jne  .fail
    cmp  byte [rel fd_cp_rec + 11], 0x20
    jne  .fail
    mov  byte [rel fd_cp_rec_repl], 0
    lea  rdi, [rel fd_cp_rec]
    lea  rsi, [rel fd_tx_plan]
    mov  edx, 11
    call memcmp
    test rax, rax
    jnz  .repl
    mov  byte [rel fd_cp_committed], 0
    cmp  dword [rel fd_cp_rec + FD_CP_PREV], 0
    jne  .abandoned                      ; reclaim began: never committed
    ; E2r: a live ~TMPREPL is resolved first, against this plan's head and size (it is retired
    ; before the plan, so a plan reclaiming already has none)
    mov  eax, [rel fd_cp_rec + 28]
    mov  [rel fd_cp_plan_size], eax
    lea  rsi, [rel fd_cp_rec]
    call fd_tx_head
    mov  [rel fd_cp_plan_head], eax
    mov  rdi, r12
    lea  rsi, [rel fd_tx_repl]
    call fd_find_root_slot
    cmp  rax, 1
    jne  .plan_alone
    mov  byte [rel fd_cp_plan_known], 1
    mov  rdi, r12
    mov  rsi, [rel fd_found_dir_lba]
    mov  edx, [rel fd_found_dir_off]
    call fd_cp_recover                   ; retired, or its old chain reclaimed a batch at a time
    mov  byte [rel fd_cp_plan_known], 0
    test rax, rax
    jnz  .out                            ; 1: more, the caller revisits / -1: failed closed, the plan kept
    jmp  .again                          ; the plan again (that call used fd_cp_rec)
.plan_alone:
    cmp  rax, -1
    jne  .plan_slot                      ; 0: a free slot, no ~TMPREPL
    cmp  dword [rel fat32_disk_last_error], FD_ERR_NO_SPACE
    jne  .fail                           ; a full root holds none either
.plan_slot:
    mov  esi, [rel fd_cp_rec + FD_CP_DST_SEC]
    test esi, esi
    jz   .abandoned                      ; no destination slot was reserved
    cmp  rsi, [r12 + FD_PART_SECTORS]
    jae  .fail
    add  rsi, [r12 + FD_PART_LBA]
    movzx edx, byte [rel fd_cp_rec + FD_CP_DST_IDX]
    cmp  edx, 15
    ja   .fail
    shl  edx, 5
    mov  rdi, r12
    lea  rcx, [rel fd_cp_dent]
    call fd_tx_read_entry                ; read-only: recovery never writes through this pointer
    test rax, rax
    jnz  .fail
    movzx eax, byte [rel fd_cp_dent]
    test eax, eax
    jz   .abandoned
    cmp  eax, 0xE5
    je   .abandoned
    cmp  byte [rel fd_cp_dent + 11], 0x20
    jne  .abandoned
    mov  eax, [rel fd_cp_dent + 28]
    cmp  eax, [rel fd_cp_rec + 28]
    jne  .abandoned
    lea  rsi, [rel fd_cp_dent]
    call fd_tx_head
    mov  ebx, eax
    lea  rsi, [rel fd_cp_rec]
    call fd_tx_head
    cmp  eax, ebx
    jne  .abandoned
    mov  byte [rel fd_cp_committed], 1   ; the destination owns the chain; only the journal remains
    jmp  .retire
.abandoned:
    mov  ebx, [rel fd_cp_rec + FD_CP_PREV]
    lea  rsi, [rel fd_cp_rec]
    call fd_tx_head
    mov  r14d, eax                       ; cursor
    test ebx, ebx
    jz   .cursor
    cmp  ebx, [r12 + FD_ROOT_CLUSTER]
    je   .fail
    mov  rdi, r12
    mov  esi, ebx
    call fd_cp_fat_entry
    cmp  eax, 0xFFFFFFFF
    je   .fail
    test eax, eax
    jz   .cursor                         ; the pending free already landed
    test r14d, r14d
    jnz  .prev_link
    cmp  eax, FD_EOC_MIN                 ; the freed tail must have been the EOC
    jb   .fail
    jmp  .free_prev
.prev_link:
    cmp  eax, r14d                       ; ...or still point at the cursor
    jne  .fail
.free_prev:
    mov  rdi, r12
    mov  esi, ebx
    mov  edx, r14d                       ; the chain continues at the cursor
    call fd_cp_free_entry
    test rax, rax
    jnz  .fail
.cursor:
    test r14d, r14d
    jz   .retire_orphan
    cmp  r14d, [r12 + FD_ROOT_CLUSTER]
    je   .fail
    mov  rdi, r12
    mov  esi, r14d
    call fd_cp_fat_entry
    cmp  eax, 0xFFFFFFFF
    je   .fail
    test eax, eax
    jz   .retire_orphan                  ; referenced, never allocated: the chain ends here
    xor  ebx, ebx
    cmp  eax, FD_EOC_MIN
    jae  .advance
    cmp  eax, 2
    jb   .fail
    cmp  eax, [r12 + FD_MAX_CLUSTER]
    jae  .fail
    cmp  eax, r14d
    je   .fail
    cmp  eax, [r12 + FD_ROOT_CLUSTER]
    je   .fail
    mov  ebx, eax
.advance:
    mov  [rel fd_cp_rec + 26], bx
    mov  eax, ebx
    shr  eax, 16
    mov  [rel fd_cp_rec + 20], ax
    mov  [rel fd_cp_rec + FD_CP_PREV], r14d
    mov  rdi, r12
    mov  rsi, r13
    lea  edx, [rbp + 20]
    lea  rcx, [rel fd_cp_rec + 20]
    mov  r8d, 8
    call fd_dir_patch                    ; journal first: {cursor:=next, prev:=C}
    test rax, rax
    jnz  .fail
    mov  rdi, r12
    mov  esi, r14d
    mov  edx, ebx                        ; the chain continues at next
    call fd_cp_free_entry                ; then free C
    test rax, rax
    jnz  .fail
    dec  r15d
    jnz  .again
    mov  eax, 1                          ; more to reclaim: the caller revisits
    jmp  .out
.retire_orphan:
    cmp  byte [rel fd_cp_rec_repl], 1
    je   .retire                         ; E2r: a replaced file's chain, not an orphan
    inc  qword [r12 + FD_ORPHANS]
.retire:
    mov  rdi, r12
    mov  rsi, r13
    mov  edx, ebp
    xor  ecx, ecx
    call fd_name_commit                  ; tombstone the journal
    test rax, rax
    jnz  .fail
    mov  dword [r12 + FD_FREE_VALID], 0
    xor  eax, eax
    jmp  .out
.repl:
    ; E2r ~TMPREPL {14/18 the replaced slot, 20/26 the old chain (cursor), 22 pending free, 28 old size}
    lea  rdi, [rel fd_cp_rec]
    lea  rsi, [rel fd_tx_repl]
    mov  edx, 11
    call memcmp
    test rax, rax
    jnz  .fail
    mov  byte [rel fd_cp_rec_repl], 1
    cmp  dword [rel fd_cp_rec + FD_CP_PREV], 0
    jne  .abandoned                      ; its reclaim began: only ever after the swap landed
    mov  rdi, r12
    call fd_cp_slot_entry                ; fd_cp_dent = the slot it names
    test rax, rax
    jnz  .fail
    movzx eax, byte [rel fd_cp_dent]
    test eax, eax
    jz   .fail
    cmp  eax, 0xE5
    je   .fail                           ; the slot is neither file: nothing is freed (failed closed)
    lea  rsi, [rel fd_cp_dent]
    call fd_tx_head
    mov  ebx, eax
    mov  eax, [rel fd_cp_dent + 28]
    cmp  eax, [rel fd_cp_rec + 28]
    jne  .repl_new
    lea  rsi, [rel fd_cp_rec]
    call fd_tx_head
    cmp  eax, ebx
    je   .retire                         ; the old file still there: the swap never landed, free nothing
.repl_new:
    cmp  byte [rel fd_cp_plan_known], 1
    jne  .fail                           ; without its plan nothing proves the swap: both kept
    cmp  ebx, [rel fd_cp_plan_head]
    jne  .fail
    mov  eax, [rel fd_cp_dent + 28]
    cmp  eax, [rel fd_cp_plan_size]
    jne  .fail
    jmp  .abandoned                      ; the new file there: the old chain goes, from the cursor
.fail:
    mov  dword [rel fat32_disk_last_error], FD_ERR_IO
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; fd_cp_slot_entry(RDI = real ctx; fd_cp_rec = a copy record): fd_cp_dent = the root-relative slot its
;   14/18 name (read-only). -> RAX 0 / -1 (no slot, or out of range). E2r.
fd_cp_slot_entry:
    push r12
    mov  r12, rdi
    mov  esi, [rel fd_cp_rec + FD_CP_DST_SEC]
    test esi, esi
    jz   .fail
    cmp  rsi, [r12 + FD_PART_SECTORS]
    jae  .fail
    add  rsi, [r12 + FD_PART_LBA]
    movzx edx, byte [rel fd_cp_rec + FD_CP_DST_IDX]
    cmp  edx, 15
    ja   .fail
    shl  edx, 5
    mov  rdi, r12
    lea  rcx, [rel fd_cp_dent]
    call fd_tx_read_entry
    test rax, rax
    jnz  .fail
    pop  r12
    ret
.fail:
    mov  rax, -1
    pop  r12
    ret

; fd_cp_repl_arm(R12 = real ctx): E2r step 3, the ~TMPREPL root record {14/18 the reserved (old) slot, 20/26
;   the old chain's head (its reclaim cursor), 22 pending free 0, 28 the old size}, written with a barrier
;   before THE commit patches that slot. -> RAX 0 / -1 (fat32_disk_last_error). Clobbers what fd_dir_patch does.
fd_cp_repl_arm:
    mov  rdi, r12
    call fd_cp_views_invalidate
    mov  rdi, r12
    lea  rsi, [rel fd_tx_repl]
    call fd_find_root_slot
    test rax, rax
    jnz  .io                             ; 1: a live one (every writer's sweep retires them first) / -1
    mov  rax, [rel fd_mut_dir_lba]
    mov  [rel fd_cp_repl_lba], rax
    mov  eax, [rel fd_mut_dir_off]
    mov  [rel fd_cp_repl_off], eax
    lea  rdi, [rel fd_cp_dent]
    xor  esi, esi
    mov  edx, 32
    call memset
    lea  rdi, [rel fd_cp_dent]
    lea  rsi, [rel fd_tx_repl]
    mov  edx, 11
    call memcpy
    mov  byte [rel fd_cp_dent + 11], 0x20
    mov  word [rel fd_cp_dent + 12], FD_CP_MAGIC
    mov  rax, [rel fd_cp_dst_lba]
    sub  rax, [r12 + FD_PART_LBA]
    mov  [rel fd_cp_dent + FD_CP_DST_SEC], eax
    mov  eax, [rel fd_cp_dst_off]
    shr  eax, 5
    mov  [rel fd_cp_dent + FD_CP_DST_IDX], al
    mov  eax, [rel fd_cp_old_head]
    mov  [rel fd_cp_dent + 26], ax
    shr  eax, 16
    mov  [rel fd_cp_dent + 20], ax
    mov  eax, [rel fd_cp_old_size]
    mov  [rel fd_cp_dent + 28], eax
    mov  dword [r12 + FD_SWEEP_DONE], 0  ; a stranded record is swept before the next writer
    mov  rdi, r12
    mov  rsi, [rel fd_cp_repl_lba]
    mov  edx, [rel fd_cp_repl_off]
    lea  rcx, [rel fd_cp_dent]
    mov  r8d, 32
    jmp  fd_dir_patch                    ; barrier: the old chain is recorded before its slot changes
.io:
    mov  dword [rel fat32_disk_last_error], FD_ERR_IO
    mov  rax, -1
    ret

; fd_cp_older(RDI = real ctx; fd_sector + fd_found_dir_off = the existing destination entry that
;   fd_find_root_slot matched at fd_found_dir_lba) -> RAX 1 older: fd_cp_repl set, its slot, head, size
;   and lower-case bits kept / 0 newer or within 2 s / 2 undecided: a time unknown on either side (no
;   stamp, no PaOS clock zone), any attribute but archive (read-only, hidden, system, a directory), a
;   tagged entry, the source itself / -1 its chain fails validation (fat32_disk_last_error). E2r (root
;   2026-10-17 21:04:41: compare in UTC, FAT local time is the PaOS clock zone). E2r-b: under
;   FS_CMODE_FORCE an entry it may replace is 1 whatever the times (its chain still validated).
fd_cp_older:
    push rbx
    push r12
    mov  r12, rdi
    mov  eax, [rel fd_found_dir_off]
    lea  rbx, [rel fd_sector]
    add  rbx, rax
    test byte [rbx + 11], 0xDF
    jnz  .undecided
    movzx eax, word [rbx + 12]
    cmp  eax, FD_TX_MAGIC
    je   .undecided
    cmp  eax, FD_CP_MAGIC
    je   .undecided
    mov  rsi, rbx
    call fd_tx_head
    mov  [rel fd_cp_old_head], eax
    test eax, eax
    jz   .other
    cmp  eax, [rel fd_cp_src_head]
    je   .undecided                      ; the source itself
.other:
    mov  eax, [rbx + 28]
    mov  [rel fd_cp_old_size], eax
    mov  al, [rbx + 12]
    and  al, 0x18
    mov  [rel fd_cp_old_case], al
    mov  eax, [rbx + 22]
    mov  [rel fd_cp_old_wrt], eax
    mov  rax, [rel fd_found_dir_lba]
    mov  [rel fd_cp_old_lba], rax
    mov  eax, [rel fd_found_dir_off]
    mov  [rel fd_cp_old_off], eax
    test dword [rel fd_cp_mode], FS_CMODE_FORCE
    jnz  .replace                        ; E2r-b: FSANSWER EACH= replace: the user's choice, no time compare
    mov  eax, [rel fd_cp_wrt]
    call fd_wrt_utc
    mov  [rel fd_cp_src_utc], rax
    mov  eax, [rel fd_cp_old_wrt]
    call fd_wrt_utc
    mov  rcx, rax
    mov  rax, [rel fd_cp_src_utc]
    xor  edx, edx
    xor  r8d, r8d
    call vfs_mtime_older
    cmp  eax, 1
    jne  .not_older
.replace:
    mov  rdi, r12
    mov  esi, [rel fd_cp_old_head]
    mov  edx, [rel fd_cp_old_size]
    call fd_validate_file_chain          ; a damaged old chain is never replaced (nor freed)
    test rax, rax
    jnz  .bad
    mov  byte [rel fd_cp_repl], 1
    mov  eax, 1
    jmp  .out
.not_older:
    mov  byte [rel fd_cp_old_case], 0
    jmp  .out
.bad:
    mov  byte [rel fd_cp_old_case], 0
    mov  rax, -1
    jmp  .out
.undecided:
    mov  eax, 2
.out:
    pop  r12
    pop  rbx
    ret

; fd_wrt_utc(EAX = DIR_WrtTime | WrtDate<<16) -> RAX = Unix UTC seconds, 0 unknown (no stamp, a field out of
;   range, no PaOS clock zone). E2r. Clobbers RCX, RDX, RSI, R8-R11.
fd_wrt_utc:
    call vfs_dos_to_unix
    test rax, rax
    jz   .none
    call time_local_to_utc
    jc   .none
    test rax, rax
    jg   .out
.none:
    xor  eax, eax
.out:
    ret

; RDI=ctx, ESI=cluster -> EAX = FAT entry (0x0FFFFFFF-masked), 0xFFFFFFFF on failure.
; Journal recovery only, and ESI is always the journal's own cursor, pending prev,
; or a cluster on the chain they reach. FAT1 and FAT2 are two sector writes with
; no barrier between them, so a cut can land one mirror without the other. While
; a copy journal is live the copy job is the only FAT writer and each barrier
; interval changes exactly one entry between free and in use (link 0->next, EOC
; 0->EOC, reclaim C->0). So when the sector pair differs in exactly ONE entry and
; that entry IS the queried cluster with one side free, it is that last unflushed
; write: heal it to free in both copies (journal-consistent: an unflushed link or
; EOC never committed; a reclaim free was already journaled) and flush. A
; difference at any OTHER entry is never touched (it may be a live file's): the
; queried entry's copies agree, so its value is returned and the sector stays as
; found. Anything else fails closed.
fd_cp_fat_entry:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  ebx, esi
    call fd_fat_get_pair
    cmp  eax, 0xFFFFFFFF
    jne  .out
    cmp  ebx, 2
    jb   .fail
    cmp  ebx, [r12 + FD_MAX_CLUSTER]
    jae  .fail
    mov  r13d, ebx
    shr  r13d, 7                         ; FAT sector of the entry
    mov  rdi, r12
    mov  rsi, [r12 + FD_FAT_LBA]
    add  rsi, r13
    mov  edx, 1
    lea  rcx, [rel fd_fat_scan1]
    call fd_read_sectors
    test rax, rax
    jnz  .fail
    mov  rdi, r12
    mov  rsi, [r12 + FD_FAT_LBA]
    add  rsi, [r12 + FD_FAT_SECTORS]
    add  rsi, r13
    mov  edx, 1
    lea  rcx, [rel fd_fat_scan2]
    call fd_read_sectors
    test rax, rax
    jnz  .fail
    lea  rsi, [rel fd_fat_scan1]
    lea  rdi, [rel fd_fat_scan2]
    xor  ecx, ecx
    mov  ebp, -1                         ; the one differing entry
.scan:
    mov  eax, [rsi + rcx*4]
    cmp  eax, [rdi + rcx*4]
    je   .same
    cmp  ebp, -1
    jne  .fail                           ; a second difference: not a torn journal write
    mov  ebp, ecx
.same:
    inc  ecx
    cmp  ecx, 128
    jb   .scan
    cmp  ebp, -1
    je   .fail                           ; mirrors agree: the read failure was real I/O
    mov  eax, ebx
    and  eax, 127
    cmp  ebp, eax
    je   .torn_here
    mov  eax, [rsi + rax*4]              ; another entry is torn: report ours, touch nothing
    and  eax, 0x0FFFFFFF
    jmp  .out
.torn_here:
    mov  eax, [rsi + rbp*4]
    mov  edx, [rdi + rbp*4]
    test eax, 0x0FFFFFFF
    jz   .heal
    test edx, 0x0FFFFFFF
    jnz  .fail                           ; neither side free: not a journal transition
.heal:
    and  dword [rsi + rbp*4], 0xF0000000 ; free, keeping the reserved high nibble
    mov  r14, rsi
    mov  rdi, r12
    mov  rsi, [r12 + FD_FAT_LBA]
    add  rsi, r13
    mov  edx, 1
    mov  rcx, r14
    call fd_write_sectors                ; FAT1
    test rax, rax
    jnz  .fail
    mov  rdi, r12
    mov  rsi, [r12 + FD_FAT_LBA]
    add  rsi, [r12 + FD_FAT_SECTORS]
    add  rsi, r13
    mov  edx, 1
    mov  rcx, r14
    call fd_write_sectors                ; FAT2
    test rax, rax
    jnz  .fail
    mov  rdi, r12
    call fd_flush
    test rax, rax
    jnz  .fail
    inc  dword [rel fd_cp_mirror_heals]
    mov  rdi, r12
    mov  esi, ebx
    call fd_fat_get_pair                 ; must now read back identical
    jmp  .out
.fail:
    mov  dword [rel fat32_disk_last_error], FD_ERR_IO
    mov  eax, 0xFFFFFFFF
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; RDI=ctx, ESI=journal chain start: walk it read-only through fd_cp_fat_entry so
; a torn entry ON THE CHAIN is healed when it is the queried cluster. Stops at a
; free entry or EOC; bounded by the cluster count. RAX 0 / -1.
fd_cp_heal_chain:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  ebx, esi
    mov  r13d, [r12 + FD_CLUSTER_COUNT]
.walk:
    test ebx, ebx
    jz   .ok
    dec  r13d
    js   .fail
    mov  rdi, r12
    mov  esi, ebx
    call fd_cp_fat_entry
    cmp  eax, 0xFFFFFFFF
    je   .fail
    test eax, eax
    jz   .ok
    cmp  eax, FD_EOC_MIN
    jae  .ok
    cmp  eax, 2
    jb   .fail
    cmp  eax, [r12 + FD_MAX_CLUSTER]
    jae  .fail
    cmp  eax, ebx
    je   .fail
    mov  ebx, eax
    jmp  .walk
.ok:
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=ctx, ESI=cluster to free, EDX=journal chain start. fd_fat_set_pair refuses
; a sector whose mirrors differ; when that difference is a torn entry further
; down our own chain (same FAT sector), heal the chain once and retry. A torn
; entry that is not ours is never healed, so the retry fails closed. RAX 0 / -1.
fd_cp_free_entry:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  ebx, esi
    mov  r13d, edx
    xor  edx, edx
    call fd_fat_set_pair
    test rax, rax
    jz   .flush
    mov  rdi, r12
    mov  esi, r13d
    call fd_cp_heal_chain
    test rax, rax
    jnz  .fail
    mov  rdi, r12
    mov  esi, ebx
    xor  edx, edx
    call fd_fat_set_pair
    test rax, rax
    jnz  .fail
.flush:
    mov  rdi, r12
    call fd_flush
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_fs_fat32_disk_5 0
align 8
fd_cp_job:       dq 0                    ; the VFS fs_copy_job being driven
fd_cp_ctx:       dq 0                    ; the real context owning the writer
fd_cp_dev:       dq 0                    ; BEGIN's registered medium custody
fd_cp_info:      dq 0
fd_cp_generation: dq 0
fd_cp_total:     dq 0
fd_cp_done:      dq 0
fd_cp_vdone:     dq 0
fd_cp_rec_lba:   dq 0                    ; ROOT journal sector
fd_cp_dst_lba:   dq 0                    ; reserved destination slot sector
fd_cp_rec_off:   dd 0
fd_cp_dst_off:   dd 0
fd_cp_src_head:  dd 0
fd_cp_src:       dd 0                    ; source cursor (copy, then verify)
fd_cp_head:      dd 0
fd_cp_tail:      dd 0                    ; referenced, still FAT-free until linked or EOC
fd_cp_alloc_hint: dd 2                   ; E5 private search cursor, reset at each top-level BEGIN
fd_cp_vdst:      dd 0
fd_cp_phase:     dd FD_CP_IDLE
; fd_cp_target..fd_cp_vbuf moved to WDATA_fs_fat32_disk_5_bss1 (zero-fill tail)
%endmacro
WDATA_DEFER WDATA_fs_fat32_disk_5
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER), in block order.
%macro WDATA_fs_fat32_disk_5_bss1 0
resb 24                 ; keeps fd_cp_target at its WDATA offset mod 64
fd_cp_target:    resd 1                  ; FS_JOB_CANCELLED / FS_JOB_FAILED after reclaim
fd_cp_error:     resd 1
fd_cp_committed: resb 1
fd_cp_runner_armed: resb 1               ; fs.orphan cadence registered (fat32_disk_idle_arm)
alignb 4
fd_cp_mirror_heals: resd 1               ; torn FAT1/FAT2 journal writes healed by recovery
alignb 8
fat32_disk_idle_observer: resq 1         ; set at runtime by a higher layer; never imported upward
fd_cp_name:      resb 11
fd_cp_rec:       resb 32
fd_cp_dent:      resb 32
fd_cp_wrt:       resd 1                  ; E2t: the source's DIR_WrtTime | WrtDate<<16 for the commit
fd_cp_repl:      resb 1                  ; E2r: this file replaces the older one in its reserved slot
fd_cp_swapped:   resb 1                  ;   THE commit landed with its barrier: RECLAIM frees the old chain, DONE
fd_cp_old_case:  resb 1                  ;   the replaced entry's lower-case bits (byte 12 & 0x18)
fd_cp_rec_repl:  resb 1                  ;   recovery: fd_cp_rec is a ~TMPREPL
fd_cp_plan_known: resb 1                 ;   recovery: a plan's head and size, for its ~TMPREPL
alignb 8
fd_cp_old_lba:   resq 1                  ;   the old entry's sector and offset (fd_find_root_slot's)
fd_cp_repl_lba:  resq 1                  ;   the ~TMPREPL record's sector and offset
fd_cp_src_utc:   resq 1
fd_cp_old_off:   resd 1
fd_cp_repl_off:  resd 1
fd_cp_old_head:  resd 1
fd_cp_old_size:  resd 1
fd_cp_old_wrt:   resd 1
fd_cp_plan_head: resd 1
fd_cp_plan_size: resd 1
alignb 64
fd_cp_buf:       resb 4096               ; source sectors
fd_cp_vbuf:      resb 4096               ; destination sectors (verify)
%endmacro
WDATA_BSS_DEFER WDATA_fs_fat32_disk_5_bss1
; E3b: private snapshot and bounded retry; no public context/job ABI change.
%macro WDATA_BSS_fs_fat32_source_retry 0
alignb 8
fd_cp_src_lba: resq 1
fd_cp_src_off: resd 1
fd_cp_src_entry: resb 32
fd_cp_src_retried: resb 1
fd_cp_src_retry_pending: resb 1
%endmacro
WDATA_BSS_DEFER WDATA_BSS_fs_fat32_source_retry

; RCQ-20 S4: its own block (WDATA_fs_fat32_disk_5_bss1's layout is pinned by the zero-storage move)
%macro WDATA_BSS_fs_fat32_copy_s4 0
fd_cp_mode:      resd 1                  ; FS_CMODE_* of the BEGIN
fd_cp_kept:      resd 1                  ; 0 refuse; keep-both: the k of fd_cp_name
fd_cp_req:       resb 11                 ; the requested 8.3 leaf while fd_cp_pick tries aliases
fd_scan_complete: resb 1                ; fd_find_in_dir read its whole chain (fd_cp_pick's miss test)
%endmacro
WDATA_BSS_DEFER WDATA_BSS_fs_fat32_copy_s4
; RCQ-32 settled storage absence: its own block.
%macro WDATA_BSS_fs_fat32_descriptor_absence 0
fat32_disk_descriptor_absent: resb 1    ; 1 = set by a higher layer: exact DATA disk proven absent; never imported upward
%endmacro
WDATA_BSS_DEFER WDATA_BSS_fs_fat32_descriptor_absence
; RCQ-38 G1b: its own block (the read-only boot-ESP handle).
%macro WDATA_BSS_fs_fat32_boot_esp_g1b 0
fd_ro_ctx:       resb FD_CTX_SIZE        ; the boot ESP's ctx: never DATA, never written
fd_ro_ops:       resb fs_ops_size        ; read slots only (fd_ro_build_ops)
fd_want_guid:    resq 1                  ; mount_ctx's GPT filter while fd_ro_mount/open run, else 0
fd_fat_owner:    resq 1                  ; the ctx whose FAT sector fd_fat_sector holds, 0 = none
fd_ro_guid:      resb 16                 ; the boot ESP's unique partition GUID (on-media bytes)
fd_ro_handle:    resd 1                  ; its vfs handle + 1, 0 = not open
fd_want_seen:    resd 1                  ; GPT entries naming fd_want_guid, every medium of this scan (rc-sec b1)
fd_want_fault:   resb 1                  ; 1 = a medium of this scan could not be read or parsed (rc-sec b1)
%endmacro
WDATA_BSS_DEFER WDATA_BSS_fs_fat32_boot_esp_g1b

%macro WDATA_BSS_fs_fat32_guest_source 0
alignb 8
fd_guest_ctx: resb FD_CTX_SIZE
fd_guest_ops: resb fs_ops_size
fd_guest_guid: resb 16
fd_guest_handle: resd 1
fd_resolve_absent: resb 1 ; only set at this resolver call's completed directory miss
fd_resolve_strict: resb 1 ; selector only: complete component walk, no legacy winner shortcut
alignb 8
fd_guest_header: resb 512
fd_guest_entries: resb 16384
%endmacro
WDATA_BSS_DEFER WDATA_BSS_fs_fat32_guest_source
str_fd_guest_fault: db "[PAOS64] guest source unreadable/malformed",0
str_fd_guest_ambiguous: db "[PAOS64] guest source ambiguous",0
str_fd_guest_none: db "[PAOS64] guest source absent/unmountable",0
str_fd_guest_fault_dev: db "[PAOS64] guest source fault dev=",0
str_fd_guest_fault_noname: db "-",0
; Its own block: the diagnostic's device, meaningful only while fd_want_fault is set.
%macro WDATA_BSS_fs_fat32_guest_fault_dev 0
alignb 8
fd_want_fault_dev: resq 1 ; dev* of the first medium that latched fd_want_fault (diagnostic only)
%endmacro
WDATA_BSS_DEFER WDATA_BSS_fs_fat32_guest_fault_dev
; RCQ-20 S5b: its own block (the tree walk; every field is meaningful only while fd_tree_on).
%macro WDATA_BSS_fs_fat32_copy_s5b 0
alignb 8
fd_tree_base:    resq 1                  ; bytes of the files committed so far
fd_tree_on:      resd 1                  ; FS_COPY_TREE: the live job is a tree
fd_tree_depth:   resd 1                  ; levels on fd_tree_lvl (1..FS_TREE_DEPTH_MAX)
fd_tree_stop:    resd 1                  ; a cancel between files: the state the next step ends with
fd_tree_src:     resd 1                  ; the source directory a BEGIN or a push is about to read
fd_tree_dmax:    resd 1                  ; levels this tree may hold (FS_TREE_DEPTH_MAX, or fewer deep down)
alignb 8
fd_tree_lvl:     resb FS_TREE_DEPTH_MAX * FD_TL_SIZE
%endmacro
WDATA_BSS_DEFER WDATA_BSS_fs_fat32_copy_s5b
; Smart copy B: its own block, like S5b's
%macro WDATA_BSS_fs_fat32_copy_fail 0
alignb 4
fd_tree_root_len: resd 1                 ; BEGIN's source path (FS_FAIL_PATH + 1: too long)
fd_tree_root:    resb FS_FAIL_PATH + 1
fd_tree_names:   resb FS_TREE_DEPTH_MAX * 11   ; level k's source alias at k*11 (k >= 1)
fd_tree_leaf:    resb 11                 ; the live tree file's alias
fd_tree_alias:   resb 13
fd_tree_fpath:   resb FS_FAIL_PATH + 2
fd_cp_src_fault: resb 1                  ; the live tree file failed on its own source
%endmacro
WDATA_BSS_DEFER WDATA_BSS_fs_fat32_copy_fail
; Smart copy C: its own block, like B's
%macro WDATA_BSS_fs_fat32_copy_same 0
alignb 8
fd_cp_cmp_left:  resq 1                  ; COMPARE: file bytes of this batch still to compare
fd_cp_cmp_head:  resd 1                  ; the existing destination file's first cluster
fd_cp_dstdir:    resd 1                  ; the directory a compared file's copy is armed in
fd_tree_merge_cl: resd 1                 ; the existing destination directory a level merges into (0 made)
fd_tree_dlen:    resd FS_TREE_DEPTH_MAX  ; fd_tree_dpath's length at each level (FD_PATH_MAX + 1: too long)
fd_tree_dpath:   resb FD_PATH_MAX
fd_tree_ppath:   resb FD_PATH_MAX
fd_tree_wpath:   resb FS_WAIT_PATH + 2   ; E2: an ask item's destination path (fd_tree_wait)
fd_tree_cdir:    resb 1                  ; E2: the conflict being noted is a directory's
fd_cp_cmp_on:    resb 1                  ; the job's file compares an existing destination first
%endmacro
WDATA_BSS_DEFER WDATA_BSS_fs_fat32_copy_same

fat32_disk_writefile:
    lea  r9, [rel fd_create_locked]
    jmp  fd_mut_call
fat32_disk_delete:
    lea  r9, [rel fd_delete_locked]
fd_mut_call:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  rbx, r9
    mov  rbp, rdi
    mov  r12, [rdi + fsmount.priv]
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    mov  rdi, r12
    call fd_writer_enter
    test rax, rax
    jnz  .out
    mov  rdi, rbp
    mov  rsi, r13
    mov  rdx, r14
    mov  rcx, r15
    call rbx
    mov  dword [r12 + FD_TX_BUSY], 0
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

fd_create_locked:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r15, rdi                          ; fsmount
    mov  r12, [rdi + fsmount.priv]
    mov  r13, rsi                          ; name11
    mov  r14, rdx                          ; payload
    mov  rbx, rcx                          ; bytes
    mov  dword [rel fat32_disk_last_error], FD_ERR_NONE
    test r13, r13
    jz   .bad_arg
    test r14, r14
    jz   .bad_arg
    test rbx, rbx
    jz   .bad_arg
    cmp  rbx, 256
    ja   .bad_arg
    mov  rdi, r12
    call fd_mutation_authorized
    test rax, rax
    jnz  .fail
    mov  rdi, r13
    mov  rsi, r12
    call fd_scratch_name_allowed
    test rax, rax
    jnz  .fail
    mov  rdi, r12
    call fd_invalidate_caches
    mov  rdi, r12
    mov  rsi, r13
    call fd_write_slot
    test rax, rax
    jnz  .fail
    mov  rdi, r12
    call fd_find_free_cluster
    cmp  rax, -1
    je   .fail
    mov  [rel fd_mut_cluster], eax
    cmp  byte [rel fd_fault_point], FD_FAULT_ALLOC
    je   .injected
    mov  rdi, r12
    mov  esi, eax
    mov  rdx, r14
    mov  rcx, rbx
    call fd_write_payload
    test rax, rax
    jnz  .fail_mutated
    cmp  byte [rel fd_fault_point], FD_FAULT_DATA
    je   .injected_mutated
    mov  rdi, r12
    mov  esi, [rel fd_mut_cluster]
    mov  edx, 0x0FFFFFFF
    call fd_fat_set_pair
    test rax, rax
    jnz  .fail_mutated
    ; Barrier 1: payload + both FAT copies durable before the name exists.
    mov  rdi, r12
    call fd_flush
    test rax, rax
    jnz  .fail_mutated
    lea  rdi, [rel fd_dirent_buf]
    xor  esi, esi
    mov  edx, 32
    call memset
    lea  rdi, [rel fd_dirent_buf]
    mov  rsi, r13
    mov  edx, 11
    call memcpy
    mov  byte [rel fd_dirent_buf + 11], 0x20
    mov  eax, [rel fd_mut_cluster]
    mov  [rel fd_dirent_buf + 26], ax
    shr  eax, 16
    mov  [rel fd_dirent_buf + 20], ax
    mov  [rel fd_dirent_buf + 28], ebx
    mov  rdi, r12
    mov  rsi, [rel fd_mut_dir_lba]
    mov  edx, 1
    lea  rcx, [rel fd_sector]
    call fd_read_sectors
    test rax, rax
    jnz  .fail_mutated
    lea  rdi, [rel fd_sector]
    mov  eax, [rel fd_mut_dir_off]
    add  rdi, rax
    lea  rsi, [rel fd_dirent_buf]
    mov  edx, 32
    call memcpy                            ; exactly one complete directory slot
    mov  rdi, r12
    mov  rsi, [rel fd_mut_dir_lba]
    mov  edx, 1
    lea  rcx, [rel fd_sector]
    call fd_write_sectors                  ; entry LAST
    test rax, rax
    jnz  .fail_mutated
    ; Barrier 2: the entry-last commit itself is durable before success.
    mov  rdi, r12
    call fd_flush
    test rax, rax
    jnz  .fail_mutated
    mov  rdi, r12
    call fd_invalidate_caches
    mov  rdi, r15
    mov  rsi, r13
    xor  edx, edx
    lea  rcx, [rel fd_verify_buf]
    mov  r8, rbx
    call fat32_disk_read_at                 ; production read path
    cmp  rax, rbx
    jne  .fail_mutated
    lea  rdi, [rel fd_verify_buf]
    mov  rsi, r14
    mov  rdx, rbx
    call memcmp
    test rax, rax
    jnz  .fail_mutated
    cmp  dword [r12 + FD_FREE_VALID], 1
    jne  .success
    cmp  qword [r12 + FD_FREE_COUNT], 0
    je   .success
    dec  qword [r12 + FD_FREE_COUNT]
.success:
    mov  eax, [rel fd_mut_cluster]
    jmp  .out
.bad_arg:
    mov  dword [rel fat32_disk_last_error], FD_ERR_BAD_ARG
    jmp  .fail_raw
.injected:
    mov  dword [rel fat32_disk_last_error], FD_ERR_IO
    jmp  .fail_raw
.injected_mutated:
    mov  dword [rel fat32_disk_last_error], FD_ERR_IO
.fail_mutated:
    mov  dword [r12 + FD_FREE_VALID], 0
    mov  rdi, r12
    call fd_invalidate_caches
.fail:
.fail_raw:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

fd_delete_locked:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, [rdi + fsmount.priv]
    mov  r13, rsi
    mov  dword [rel fat32_disk_last_error], FD_ERR_NONE
    test r13, r13
    jz   .bad_arg
    mov  rdi, r12
    call fd_mutation_authorized
    test rax, rax
    jnz  .fail
    mov  rdi, r13
    mov  rsi, r12
    call fd_scratch_name_allowed
    test rax, rax
    jnz  .fail
    mov  rdi, r12
    call fd_invalidate_caches
    mov  rdi, r12
    mov  rsi, r13
    call fd_lookup
    test rax, rax
    jnz  .not_found
    mov  r14d, [rel fd_found_cluster]
    mov  rdi, r12
    mov  esi, r14d
    mov  rdx, [rel fd_found_size]
    call fd_validate_file_chain
    test rax, rax
    jnz  .io_fail
    mov  rdi, r12
    mov  rsi, [rel fd_found_dir_lba]
    mov  edx, [rel fd_found_dir_off]
    xor  ecx, ecx
    call fd_name_commit                    ; shared DELETE/RENAME name-field primitive + barriers
    test rax, rax
    jnz  .mut_fail
    mov  rdi, r12
    call fd_invalidate_caches
    xor  ebx, ebx                          ; clusters freed
    mov  r15d, [r12 + FD_CLUSTER_COUNT]    ; corruption/cycle budget
    cmp  qword [rel fd_found_size], 0
    jne  .free_loop
    test r14d, r14d
    jz   .free_done
.free_loop:
    test r15d, r15d
    jz   .mut_fail
    dec  r15d
    mov  rdi, r12
    mov  esi, r14d
    call fd_fat_get_pair
    mov  [rel fd_mut_next], eax
    cmp  eax, 0xFFFFFFFF
    je   .mut_fail
    mov  rdi, r12
    mov  esi, r14d
    xor  edx, edx
    call fd_fat_set_pair
    test rax, rax
    jnz  .mut_fail
    inc  ebx
    mov  esi, [rel fd_mut_next]
    mov  rdi, r12
    call fd_classify_next
    cmp  eax, 1
    je   .free_done
    test eax, eax
    jnz  .mut_fail
    mov  r14d, [rel fd_mut_next]
    jmp  .free_loop
.free_done:
    mov  rdi, r12
    call fd_flush
    test rax, rax
    jnz  .mut_fail
    cmp  dword [r12 + FD_FREE_VALID], 1
    jne  .verify_absent
    add  [r12 + FD_FREE_COUNT], rbx
.verify_absent:
    mov  rdi, r12
    call fd_invalidate_caches
    mov  rdi, r12
    mov  rsi, r13
    call fd_lookup
    test rax, rax
    jz   .mut_fail                         ; tombstoned name must be absent
    cmp  dword [rel fat32_disk_last_error], FD_ERR_NOT_FOUND
    jne  .mut_fail                         ; an I/O failure is not proof of absence
    mov  dword [rel fat32_disk_last_error], FD_ERR_NONE
    xor  eax, eax
    jmp  .out
.bad_arg:
    mov  dword [rel fat32_disk_last_error], FD_ERR_BAD_ARG
    jmp  .fail_raw
.not_found:
    jmp  .fail_raw
.io_fail:
    mov  dword [rel fat32_disk_last_error], FD_ERR_IO
.mut_fail:
    mov  dword [r12 + FD_FREE_VALID], 0
    mov  rdi, r12
    call fd_invalidate_caches
.fail:
.fail_raw:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Task2404: port Classic fat32_mkdir_path/rmdir_path ordering onto blk_ops.
; A transaction view retains the original geometry/dev and scopes the existing
; lookup, temp-slot and recovery-pointer checks to ONE validated parent chain.
; The real mount's root is never changed. Its lock covers this whole operation.
; Recovery in subdirectories is lazy: scan their records before the next write;
; pre-commit reads retain the old version, committed tagged entries win on read.
fat32_disk_mutate_path:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r12, [rdi + fsmount.priv]
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    mov  ebp, r8d
    cmp  ebp, FS_MUT_RMDIR
    ja   .bad
    mov  rdi, r13
    call fd_path_validate_ascii
    cmp  rax, -1
    je   .bad
    cmp  ebp, FS_MUT_RENAME
    jne  .ascii_paths
    mov  rdi, r14
    call fd_path_validate_ascii
    cmp  rax, -1
    je   .bad
.ascii_paths:
    mov  eax, 1
    xchg eax, [rel fd_dir_gate]
    test eax, eax
    jnz  .busy
    mov  qword [rel fd_dir_owner], 0
    mov  byte [rel fd_dir_view_valid], 0
    mov  rdi, r12
    call fd_writer_enter
    test rax, rax
    jnz  .release_gate
    mov  [rel fd_dir_owner], r12
    mov  rdi, r12
    mov  rsi, r13
    lea  rdx, [rel fd_dir_name]
    call fd_mut_parent
    cmp  rax, -1
    je   .unlock
    mov  ebx, eax
    mov  al, [rel fd_dir_inside]
    mov  [rel fd_dir_source_inside], al
    cmp  ebp, FS_MUT_RENAME
    jne  .view
    mov  rdi, r12
    mov  rsi, r14
    lea  rdx, [rel fd_dir_new_name]
    call fd_mut_parent
    cmp  rax, -1
    je   .unlock
    cmp  eax, ebx
    jne  .cross
    mov  al, [rel fd_dir_source_inside]
    mov  [rel fd_dir_inside], al
.view:
    lea  rdi, [rel fd_dir_ctx]
    mov  rsi, r12
    mov  edx, FD_CTX_SIZE
    call memcpy
    mov  [rel fd_dir_ctx + FD_ROOT_CLUSTER], ebx
    mov  dword [rel fd_dir_ctx + FD_TX_BUSY], 0
    mov  dword [rel fd_dir_ctx + FD_SWEEP_DONE], 0
    mov  dword [rel fd_dir_ctx + FD_SWEEP_CLUSTER], 0
    lea  rax, [rel fd_dir_ctx]
    mov  [rel fd_dir_mount + fsmount.priv], rax
    mov  byte [rel fd_dir_view_valid], 1
    mov  rdi, rax
    call fd_invalidate_caches
    ; Validate the entire parent chain before publishing a slot, including the
    ; tail after an early 0x00 entry. Recovery then only accepts pointers here.
    lea  rdi, [rel fd_dir_ctx]
    mov  esi, ebx
    call fd_validate_dir_chain
    test rax, rax
    jnz  .io
    mov  ebx, FD_DIR_MAX_CLUSTERS * 128 + 64
.recover:
    lea  rdi, [rel fd_dir_ctx]
    call fd_sweep_step
    test rax, rax
    jnz  .io
    cmp  dword [rel fd_dir_ctx + FD_SWEEP_DONE], 1
    je   .dispatch
    dec  ebx
    jnz  .recover
    jmp  .io
.dispatch:
    lea  rdi, [rel fd_dir_mount]
    lea  rsi, [rel fd_dir_name]
    mov  rdx, r14
    mov  rcx, r15
    cmp  ebp, FS_MUT_CREATE
    je   .create
    cmp  ebp, FS_MUT_DELETE
    je   .delete
    cmp  ebp, FS_MUT_UPDATE
    je   .update
    cmp  ebp, FS_MUT_RENAME
    je   .rename
    cmp  ebp, FS_MUT_MKDIR
    je   .mkdir
    call fd_rmdir_locked
    jmp  .unlock
.mkdir:
    call fd_mkdir_locked
    jmp  .unlock
.create:
    call fat32_disk_writefile
    jmp  .unlock
.delete:
    call fat32_disk_delete
    jmp  .unlock
.update:
    call fat32_disk_update
    jmp  .unlock
.rename:
    lea  rdx, [rel fd_dir_new_name]
    call fat32_disk_rename
    jmp  .unlock
.cross:
    mov  dword [rel fat32_disk_last_error], FD_ERR_CROSS_DIR
    mov  rax, -1
    jmp  .unlock
.io:
    mov  dword [rel fat32_disk_last_error], FD_ERR_IO
    mov  rax, -1
.unlock:
    push rax
    cmp  byte [rel fd_dir_view_valid], 1
    jne  .invalidate_owner
    mov  rax, [rel fd_dir_ctx + FD_ORPHANS]
    mov  [r12 + FD_ORPHANS], rax
    mov  eax, [rel fd_dir_ctx + FD_ROOT_CLUSTER]
    cmp  eax, [r12 + FD_ROOT_CLUSTER]
    jne  .invalidate_owner
    ; Preserve the existing idle recovery of interrupted ROOT transactions.
    mov  eax, [rel fd_dir_ctx + FD_SWEEP_DONE]
    mov  [r12 + FD_SWEEP_DONE], eax
    mov  dword [r12 + FD_SWEEP_CLUSTER], 0
.invalidate_owner:
    mov  rdi, r12
    call fd_invalidate_caches
    mov  dword [r12 + FD_FREE_VALID], 0
    mov  dword [r12 + FD_TX_BUSY], 0
    mov  qword [rel fd_dir_owner], 0
    pop  rax
.release_gate:
    mov  dword [rel fd_dir_gate], 0
    jmp  .out
.bad:
    mov  dword [rel fat32_disk_last_error], FD_ERR_BAD_ARG
    mov  rax, -1
    jmp  .out
.busy:
    mov  dword [rel fat32_disk_last_error], FD_ERR_BUSY
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; RDI=real ctx, RSI=absolute Z path, RDX=leaf name11 output; RAX=parent.
; Reject traversal/empty components before resolving. The leaf takes the one name
; floor (fd_scratch_name_allowed); depth stays bounded. No caller can supply an LBA.
fd_mut_parent:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  rdi, rsi
    call fd_path_validate_ascii
    cmp  rax, -1
    je   .bad
    mov  r15d, eax
    mov  ebx, 1
    mov  ecx, 1
    xor  edx, edx
    mov  r9d, 1
.scan:
    cmp  ecx, r15d
    jae  .leaf
    cmp  byte [r13 + rcx], '/'
    jne  .next
    inc  r9d
    cmp  r9d, FD_PATH_DEPTH_MAX
    ja   .bad
    test edx, edx
    jnz  .have_first
    mov  edx, ecx
.have_first:
    lea  ebx, [ecx + 1]
.next:
    inc  ecx
    jmp  .scan
.leaf:
    mov  byte [rel fd_dir_inside], 0
    cmp  ebx, 1
    je   .convert
    mov  byte [rel fd_dir_inside], 1
.convert:
    lea  rdi, [r13 + rbx]
    mov  esi, r15d
    sub  esi, ebx
    mov  rdx, r14
    call fd_component_to_short
    test rax, rax
    jnz  .bad
    ; Internal recovery names cannot be authored, deleted or renamed by users.
    mov  rax, [r14]
    cmp  rax, [rel fd_tx_temp]
    je   .bad
    cmp  rax, [rel fd_tx_plan]
    je   .bad
    cmp  rax, [rel fd_tx_repl]           ; E2r: the replace's record
    je   .bad
    cmp  rax, [rel fd_grow_name]
    je   .bad
    cmp  ebx, 1
    jne  .resolve
    mov  rdi, r14
    mov  rsi, r12
    call fd_scratch_name_allowed
    test rax, rax
    jnz  .allow
.root:
    mov  eax, [r12 + FD_ROOT_CLUSTER]
    jmp  .out
.resolve:
    lea  rdi, [rel fd_dir_parent_path]
    mov  rsi, r13
    lea  edx, [rbx - 1]
    call memcpy
    lea  rax, [rel fd_dir_parent_path]
    mov  byte [rax + rbx - 1], 0
    mov  rdi, r12
    mov  rsi, rax
    call fat32_disk_resolve_path_lfn
    test rax, rax
    jnz  .bad
    test byte [rel fd_found_attr], 0x10
    jz   .not_dir
    mov  eax, [rel fd_found_cluster]
    cmp  eax, [r12 + FD_ROOT_CLUSTER]
    je   .allow
    jmp  .out
.not_dir:
    mov  dword [rel fat32_disk_last_error], FD_ERR_NOT_DIR
    jmp  .fail
.allow:
    mov  dword [rel fat32_disk_last_error], FD_ERR_ALLOWLIST
    jmp  .fail
.bad:
    mov  dword [rel fat32_disk_last_error], FD_ERR_BAD_ARG
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

fd_mkdir_locked:
    push rbx
    push rbp
    push r12
    push r13
    mov  r12, [rdi + fsmount.priv]
    mov  r13, rsi
.slot:
    mov  rdi, r12
    mov  rsi, r13
    call fd_write_slot
    test rax, rax
    jnz  .fail
    mov  rdi, r12
    call fd_find_free_cluster
    cmp  rax, -1
    je   .fail
    mov  ebp, eax
    xor  ebx, ebx
.zero:
    lea  rdi, [rel fd_sector]
    xor  esi, esi
    mov  edx, 512
    call memset
    test ebx, ebx
    jnz  .write
    lea  rdi, [rel fd_sector]
    mov  rax, '        '
    mov  [rdi], rax
    mov  [rdi + 32], rax
    mov  word [rdi + 8], '  '
    mov  byte [rdi + 10], ' '
    mov  word [rdi + 40], '  '
    mov  byte [rdi + 42], ' '
    mov  byte [rdi], '.'
    mov  word [rdi + 32], '..'
    mov  byte [rdi + 11], 0x10
    mov  byte [rdi + 43], 0x10
    mov  eax, ebp
    mov  [rdi + 26], ax
    shr  eax, 16
    mov  [rdi + 20], ax
    mov  eax, [r12 + FD_ROOT_CLUSTER]
    mov  rdx, [rel fd_dir_owner]
    cmp  eax, [rdx + FD_ROOT_CLUSTER]
    jne  .parent
    xor  eax, eax                       ; FAT32 '..' of a root child is zero
.parent:
    mov  [rdi + 58], ax
    shr  eax, 16
    mov  [rdi + 52], ax
.write:
    mov  rdi, r12
    mov  esi, ebp
    call fd_cluster_lba
    cmp  rax, -1
    je   .fail
    lea  rsi, [rax + rbx]
    mov  rdi, r12
    mov  edx, 1
    lea  rcx, [rel fd_sector]
    call fd_write_sectors
    test rax, rax
    jnz  .fail
    inc  ebx
    cmp  ebx, [r12 + FD_SPC]
    jb   .zero
    ; Persist initialized bytes BEFORE linking in either FAT.
    mov  rdi, r12
    call fd_flush
    test rax, rax
    jnz  .fail
    mov  rdi, r12
    mov  esi, ebp
    mov  edx, 0x0FFFFFFF
    call fd_fat_set_pair
    test rax, rax
    jnz  .fail
    lea  rdi, [rel fd_dirent_buf]
    xor  esi, esi
    mov  edx, 32
    call memset
    lea  rdi, [rel fd_dirent_buf]
    mov  rsi, r13
    mov  edx, 11
    call memcpy
    mov  byte [rel fd_dirent_buf + 11], 0x10
    mov  eax, ebp
    mov  [rel fd_dirent_buf + 26], ax
    shr  eax, 16
    mov  [rel fd_dirent_buf + 20], ax
    mov  rdi, r12
    mov  rsi, [rel fd_mut_dir_lba]
    mov  edx, [rel fd_mut_dir_off]
    lea  rcx, [rel fd_dirent_buf]
    mov  r8d, 32
    call fd_dir_patch                   ; FAT barrier, parent entry LAST, flush
    jmp  .out
.allow:
    mov  dword [rel fat32_disk_last_error], FD_ERR_ALLOWLIST
.fail:
    mov  rax, -1
.out:
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

fd_rmdir_locked:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r12, [rdi + fsmount.priv]
    mov  r13, rsi
    ; Slot lookup includes directories and returns the exact parent slot.
    mov  rdi, r12
    call fd_find_root_slot
    cmp  eax, 1
    jne  .missing
    ; fd_find_root_slot publishes the duplicate's slot for directory removal.
    mov  rdi, r12
    mov  rsi, [rel fd_found_dir_lba]
    mov  edx, [rel fd_found_dir_off]
    lea  rcx, [rel fd_dirent_buf]
    call fd_tx_read_entry
    test rax, rax
    jnz  .fail
    cmp  byte [rel fd_dirent_buf + 11], 0x10
    jne  .not_dir
    lea  rsi, [rel fd_dirent_buf]
    call fd_tx_head
    mov  r14d, eax
    cmp  eax, [r12 + FD_ROOT_CLUSTER]
    je   .not_dir
    mov  rdx, [rel fd_dir_owner]
    cmp  eax, [rdx + FD_ROOT_CLUSTER]
    je   .not_dir
    mov  rdi, r12
    mov  esi, eax
    call fd_validate_dir_chain
    test rax, rax
    jnz  .fail
    ; Validate and scan every sector of every cluster. Even stale live rows
    ; after a premature zero entry refuse removal rather than being orphaned.
    mov  ebp, r14d
.cluster:
    mov  rdi, r12
    mov  esi, ebp
    call fd_cluster_lba
    cmp  rax, -1
    je   .fail
    mov  r15, rax
    xor  ebx, ebx
.sector:
    mov  rdi, r12
    lea  rsi, [r15 + rbx]
    mov  edx, 1
    lea  rcx, [rel fd_sector]
    call fd_read_sectors
    test rax, rax
    jnz  .fail
    xor  r10d, r10d
.entry:
    lea  rdi, [rel fd_sector]
    add  rdi, r10
    cmp  byte [rdi], 0
    je   .next_entry
    cmp  byte [rdi], 0xE5
    je   .next_entry
    ; Only the first two canonical dot entries may be live.
    cmp  ebp, r14d
    jne  .not_empty
    test ebx, ebx
    jnz  .not_empty
    cmp  r10d, 32
    ja   .not_empty
    cmp  byte [rdi + 11], 0x10
    jne  .not_empty
    cmp  dword [rdi + 28], 0
    jne  .not_empty
    test r10d, r10d
    jnz  .dotdot
    cmp  word [rdi], '. '
    jne  .not_empty
    mov  r11d, r14d
    jmp  .dot_tail
.dotdot:
    cmp  word [rdi], '..'
    jne  .not_empty
    mov  r11d, [r12 + FD_ROOT_CLUSTER]
    mov  rdx, [rel fd_dir_owner]
    cmp  r11d, [rdx + FD_ROOT_CLUSTER]
    jne  .dot_tail
    xor  r11d, r11d
.dot_tail:
    mov  ecx, 2
.padding:
    cmp  byte [rdi + rcx], ' '
    jne  .not_empty
    inc  ecx
    cmp  ecx, 11
    jb   .padding
    movzx eax, word [rdi + 20]
    shl  eax, 16
    mov  ax, [rdi + 26]
    cmp  eax, r11d
    jne  .not_empty
.next_entry:
    add  r10d, 32
    cmp  r10d, 512
    jb   .entry
    inc  ebx
    cmp  ebx, [r12 + FD_SPC]
    jb   .sector
    mov  rdi, r12
    mov  esi, ebp
    call fd_fat_get_pair
    cmp  eax, 0xFFFFFFFF
    je   .fail
    cmp  eax, FD_EOC_MIN
    jae  .empty
    mov  ebp, eax
    jmp  .cluster
.empty:
    mov  rdi, r12
    mov  rsi, [rel fd_found_dir_lba]
    mov  edx, [rel fd_found_dir_off]
    xor  ecx, ecx
    call fd_name_commit                 ; tombstone durable before freeing
    test rax, rax
    jnz  .fail
.free:
    mov  rdi, r12
    mov  esi, r14d
    call fd_fat_get_pair
    cmp  eax, 0xFFFFFFFF
    je   .fail
    mov  ebp, eax
    mov  rdi, r12
    mov  esi, r14d
    xor  edx, edx
    call fd_fat_set_pair
    test rax, rax
    jnz  .fail
    cmp  ebp, FD_EOC_MIN
    jae  .flush
    mov  r14d, ebp
    jmp  .free
.flush:
    mov  rdi, r12
    call fd_flush
    jmp  .out
.missing:
    cmp  eax, -1
    je   .fail
    mov  dword [rel fat32_disk_last_error], FD_ERR_NOT_FOUND
    jmp  .fail
.not_dir:
    mov  dword [rel fat32_disk_last_error], FD_ERR_NOT_DIR
    jmp  .fail
.not_empty:
    mov  dword [rel fat32_disk_last_error], FD_ERR_NOT_EMPTY
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_fs_fat32_disk_0 0
fd_dir_ctx: resb FD_CTX_SIZE
fd_dir_mount: resb fsmount_size
fd_dir_owner: resq 1
fd_dir_gate: resd 1
fd_dir_view_valid: resb 1
fd_scan_committed: resb 1
fd_dir_inside: resb 1
fd_dir_source_inside: resb 1
fd_dir_name: resb 11
fd_dir_new_name: resb 11
fd_dir_first: resb 11
%endmacro
WDATA_BSS_DEFER WDATA_fs_fat32_disk_0
fd_dir_parent_path equ fd_path_input     ; parent consumed before any read-at call

fat32_disk_mount:
    mov  rdi, [rdi + fsmount.priv]
    jmp  fat32_disk_mount_ctx

fat32_disk_mount_ctx:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    cmp  [rel fd_cp_ctx], r12
    jne  .no_live_copy
    cmp  dword [rel fd_cp_phase], FD_CP_IDLE
    je   .no_live_copy
    ; A remount abandons the in-memory job; this mount's root sweep recovers its journal.
    mov  dword [rel fd_cp_phase], FD_CP_IDLE
    mov  rax, [rel fd_cp_job]
    mov  dword [rax + fs_copy_job.state], FS_JOB_FAILED
.no_live_copy:
    mov  dword [r12 + FD_MOUNTED], 0
    mov  qword [r12 + FD_MOUNT_GEN], 0
    mov  dword [r12 + FD_TX_BUSY], 0
    mov  dword [r12 + FD_SWEEP_CLUSTER], 0
    mov  dword [r12 + FD_SWEEP_DONE], 0
    mov  qword [r12 + FD_ORPHANS], 0
    call fd_invalidate_caches
    mov  qword [r12 + FD_DISK_GUID], 0
    mov  qword [r12 + FD_DISK_GUID + 8], 0
    mov  qword [r12 + FD_PART_GUID], 0
    mov  qword [r12 + FD_PART_GUID + 8], 0
    mov  dword [r12 + FD_FREE_VALID], 0
    mov  byte [r12 + FD_EXACT_BOUND], 0
    mov  byte [r12 + FD_PART_ESP], 0
    mov  byte [r12 + FD_SCAN_ERR], 0
    mov  dword [r12 + FD_PART_INDEX], -1
    mov  rdi, [r12 + FD_DEV]
    test rdi, rdi
    FD_RO_STEP 501
    jz   .fail
    call blk_identify
    test rax, rax
    FD_RO_STEP 502
    jnz  .fail_fault
    mov  rax, [r12 + FD_DEV]
    mov  rax, [rax + dev.info]
    test rax, rax
    FD_RO_STEP 503
    jz   .fail_geometry
    mov  rdx, [rax + blk_info.media_generation]
    mov  [r12 + FD_MOUNT_GEN], rdx       ; before the first geometry read
    cmp  dword [rax + blk_info.sector_size], 512
    FD_RO_STEP 504
    jne  .fail_geometry
    mov  rdi, r12
    xor  esi, esi
    mov  edx, 1
    lea  rcx, [rel fd_mbr_sector]
    call fd_read_sectors
    test rax, rax
    FD_RO_STEP 505
    jnz  .fail_fault
    cmp  word [rel fd_mbr_sector + 510], 0xAA55
    jne  .probe_gpt                       ; G1b (rc-sec L1): under the filter only, LBA1 may still hold a GPT
    lea  rbx, [rel fd_mbr_sector]
    call fd_is_fat32_bpb
    test eax, eax
    jnz  .mbr
    cmp  qword [rel fd_want_guid], 0
    jne  .probe_gpt                       ; G1b: a superfloppy has no partition GUID; a GPT behind it counts
    mov  qword [r12 + FD_PART_LBA], 0
    mov  rax, [r12 + FD_DEV]
    mov  rax, [rax + dev.info]
    mov  rax, [rax + blk_info.lba_max]
    inc  rax
    FD_RO_STEP 506
    jz   .fail
    mov  [r12 + FD_PART_SECTORS], rax
    mov  rdi, r12
    lea  rsi, [rel fd_mbr_sector]
    call fd_validate_bpb
    jmp  .out

; Under the boot-ESP filter only (rc-sec L1, 02:19:39): no 0xAA55 at LBA0, or a BPB there, may still sit in
; front of a GPT naming the wanted GUID. Probe LBA1 so its sightings count. r13d = 5 marks the probe: a missing
; 'EFI PART' is a plain skip (>= 4), and a GPT found this way is counted but never selected.
.probe_gpt:
    cmp  qword [rel fd_want_guid], 0
    FD_RO_STEP 507
    je   .fail                            ; the DATA scan: unchanged
    mov  r13d, 5
    jmp  .gpt

.mbr:
    xor  r13d, r13d
.mbr_loop:
    cmp  r13d, 4
    jae  .gpt
    mov  eax, r13d
    shl  eax, 4
    lea  rbx, [rel fd_mbr_sector + 446]
    add  rbx, rax
    movzx eax, byte [rbx + 4]
    cmp  al, 0xEE
    je   .gpt
    cmp  al, 0x0B
    je   .mbr_candidate
    cmp  al, 0x0C
    je   .mbr_candidate
    cmp  al, 0x1B
    je   .mbr_candidate
    cmp  al, 0x1C
    jne  .mbr_next
.mbr_candidate:
    cmp  qword [rel fd_want_guid], 0
    jne  .mbr_next                        ; G1b: nor has an MBR partition
    mov  eax, [rbx + 8]
    test eax, eax
    jz   .mbr_next
    mov  [r12 + FD_PART_LBA], rax
    mov  eax, [rbx + 12]
    test eax, eax
    jz   .mbr_next
    mov  [r12 + FD_PART_SECTORS], rax
    mov  rdi, r12
    mov  rsi, [r12 + FD_PART_LBA]
    mov  edx, 1
    lea  rcx, [rel fd_sector]
    call fd_read_sectors
    test rax, rax
    jnz  .mbr_next
    lea  rbx, [rel fd_sector]
    call fd_is_fat32_bpb
    test eax, eax
    jnz  .mbr_next
    mov  rdi, r12
    lea  rsi, [rel fd_sector]
    call fd_validate_bpb
    test rax, rax
    jz   .out
.mbr_next:
    inc  r13d
    jmp  .mbr_loop

.gpt:
    mov  rdi, r12
    mov  esi, 1
    mov  edx, 1
    lea  rcx, [rel fd_sector]
    call fd_read_sectors
    test rax, rax
    FD_RO_STEP 508
    jnz  .fail_fault
    mov  rax, 0x5452415020494645
    cmp  [rel fd_sector], rax
    je   .gpt_signed
    cmp  r13d, 4
    FD_RO_STEP 509
    jae  .fail                            ; no protective entry (.mbr_loop ran out, or the L1 probe): no GPT
    FD_RO_STEP 510
    jmp  .fail_fault                      ; a protective MBR without a GPT: unparsable, not absent
.gpt_signed:
    lea  rax, [rel fd_guest_ctx]
    cmp  r12, rax
    jne  .guest_checked
    mov  rdi, r12
    call fd_guest_gpt_validate
    test rax, rax
    jnz  .fail_fault
.guest_checked:
    mov  rax, [rel fd_sector + 56]
    mov  [r12 + FD_DISK_GUID], rax
    mov  rax, [rel fd_sector + 64]
    mov  [r12 + FD_DISK_GUID + 8], rax
    mov  rax, [rel fd_sector + 72]
    test rax, rax
    FD_RO_STEP 511
    jz   .fail_fault
    mov  [rel fd_gpt_entries_lba], rax
    mov  eax, [rel fd_sector + 80]
    test eax, eax
    FD_RO_STEP 512
    jz   .fail_fault
    cmp  eax, 128
    jbe  .gpt_count_ok
    mov  eax, 128
.gpt_count_ok:
    mov  [rel fd_gpt_count], eax
    cmp  dword [rel fd_sector + 84], 128
    FD_RO_STEP 513
    jne  .fail_fault
    cmp  qword [rel fd_want_guid], 0
    je   .gpt_scan
    mov  rdi, r12
    call fd_gpt_want_count
    cmp  eax, -1
    FD_RO_STEP 514
    je   .fail_fault                      ; G1b (rc-sec b1): the entry array did not read
    add  [rel fd_want_seen], eax          ; G1b (rc-sec b1): every sighting, before type/BPB/mount
    cmp  r13d, 5
    FD_RO_STEP 515
    je   .fail                            ; G1b (rc-sec L1): a GPT reached by the probe counts, never selects
    cmp  eax, 1
    FD_RO_STEP 516
    jne  .fail                            ; G1b (rc-sec g3): absent, or the GUID twice in this table
.gpt_scan:
    xor  r13d, r13d
.gpt_loop:
    cmp  r13d, [rel fd_gpt_count]
    FD_RO_STEP 517
    jae  .fail
    mov  eax, r13d
    shl  rax, 7
    mov  r14, rax
    shr  rax, 9
    add  rax, [rel fd_gpt_entries_lba]
    mov  rdi, r12
    mov  rsi, rax
    mov  edx, 1
    lea  rcx, [rel fd_sector]
    call fd_read_sectors
    test rax, rax
    FD_RO_STEP 518
    jnz  .gpt_read_error
    and  r14d, 511
    lea  rbx, [rel fd_sector]
    add  rbx, r14
    cmp  qword [rbx], 0
    je   .gpt_next
    mov  byte [r12 + FD_PART_ESP], 0
    mov  [r12 + FD_PART_INDEX], r13d
    mov  rax, FD_ESP_GUID_LO
    cmp  [rbx], rax
    jne  .gpt_type_done
    mov  rax, FD_ESP_GUID_HI
    cmp  [rbx + 8], rax
    jne  .gpt_type_done
    mov  byte [r12 + FD_PART_ESP], 1
.gpt_type_done:
    mov  rcx, [rel fd_want_guid]
    test rcx, rcx
    jz   .gpt_any
    lea  rax, [rel fd_selected_ctx]
    cmp  r12, rax
    je   .gpt_guid_match                  ; explicit context already CRC/type/extent checked
    cmp  byte [r12 + FD_PART_ESP], 1      ; old boot-ESP API remains ESP-only
    je   .gpt_guid_match
    lea  rax, [rel fd_guest_ctx]
    cmp  r12, rax
    jne  .gpt_next
    mov  rax, 0x4433b9e5ebd0a0a2         ; BASICDATA only, never any other GPT type
    cmp  [rbx], rax
    jne  .gpt_next
    mov  rax, 0xc79926b7b668c087
    cmp  [rbx + 8], rax
    jne  .gpt_next
.gpt_guid_match:
    mov  rax, [rbx + 16]
    cmp  rax, [rcx]
    jne  .gpt_next
    mov  rax, [rbx + 24]
    cmp  rax, [rcx + 8]
    jne  .gpt_next
.gpt_any:
    mov  rax, [rbx + 32]
    mov  r15, [rbx + 40]
    cmp  r15, rax
    jb   .gpt_next
    mov  [r12 + FD_PART_LBA], rax
    sub  r15, rax
    inc  r15
    jz   .gpt_next
    mov  [r12 + FD_PART_SECTORS], r15
    mov  rax, [rbx + 16]
    mov  [r12 + FD_PART_GUID], rax
    mov  rax, [rbx + 24]
    mov  [r12 + FD_PART_GUID + 8], rax
    mov  rdi, r12
    mov  rsi, [r12 + FD_PART_LBA]
    mov  edx, 1
    lea  rcx, [rel fd_sector]
    call fd_read_sectors
    test rax, rax
    FD_RO_STEP 519
    jnz  .gpt_read_error
    lea  rbx, [rel fd_sector]
    call fd_is_fat32_bpb
    call fd_ro_diag_bpb_result
    test eax, eax
    jnz  .gpt_next
    mov  rdi, r12
    lea  rsi, [rel fd_sector]
    call fd_validate_bpb
    test rax, rax
    jz   .out
    jmp  .gpt_next
.gpt_read_error:
    mov  byte [r12 + FD_SCAN_ERR], 1
    cmp  qword [rel fd_want_guid], 0
    je   .gpt_next
    call fd_want_fault_latch              ; G1b (rc-sec b1): the wanted entry's volume did not read
.gpt_next:
    inc  r13d
    jmp  .gpt_loop
.fail_geometry:
    ; Only the new guest-source scan must refuse an enumerated peer whose
    ; geometry cannot be inspected. Original ESP/DATA behavior stays intact.
    lea  rax, [rel fd_guest_ctx]
    cmp  r12, rax
    jne  .fail
; Exact-GUID filters latch faults; the DATA scan's .fail is unchanged.
.fail_fault:
    cmp  qword [rel fd_want_guid], 0
    FD_RO_STEP 520
    je   .fail
    call fd_want_fault_latch              ; G1b (rc-sec b1): unreadable or unparsable GPT refuses the open
.fail:
    call fd_ro_diag_fail
    mov  dword [r12 + FD_MOUNTED], 0
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

fd_is_fat32_bpb:
    cmp  word [rbx + 510], 0xAA55
    FD_RO_STEP 601
    jne  .no
    cmp  dword [rbx + 82], 'FAT3'
    FD_RO_STEP 602
    jne  .no
    cmp  dword [rbx + 86], '2   '
    FD_RO_STEP 603
    jne  .no
    xor  eax, eax
    ret
.no:
    mov  eax, -1
    ret

fd_validate_bpb:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  rbx, rsi
    cmp  word [rbx + 11], 512
    FD_RO_STEP 701
    jne  .fail
    movzx r13d, byte [rbx + 13]
    test r13d, r13d
    FD_RO_STEP 702
    jz   .fail
    mov  eax, r13d
    dec  eax
    test eax, r13d
    FD_RO_STEP 703
    jnz  .fail
    cmp  r13d, 128
    FD_RO_STEP 704
    ja   .fail
    movzx r14d, word [rbx + 14]
    test r14d, r14d
    FD_RO_STEP 705
    jz   .fail
    movzx r15d, byte [rbx + 16]
    test r15d, r15d
    FD_RO_STEP 706
    jz   .fail
    cmp  r15d, 4
    FD_RO_STEP 707
    ja   .fail
    mov  [r12 + FD_NFATS], r15d
    cmp  word [rbx + 17], 0
    FD_RO_STEP 708
    jne  .fail
    cmp  word [rbx + 22], 0
    FD_RO_STEP 709
    jne  .fail
    mov  eax, [rbx + 36]
    test eax, eax
    FD_RO_STEP 710
    jz   .fail
    mov  [r12 + FD_FAT_SECTORS], rax
    mov  eax, [rbx + 44]
    cmp  eax, 2
    FD_RO_STEP 711
    jb   .fail
    mov  [r12 + FD_ROOT_CLUSTER], eax
    movzx eax, word [rbx + 19]
    test eax, eax
    jnz  .have_total
    mov  eax, [rbx + 32]
.have_total:
    test rax, rax
    FD_RO_STEP 712
    jz   .fail
    mov  [r12 + FD_TOTAL_SECTORS], rax
    cmp  rax, [r12 + FD_PART_SECTORS]
    FD_RO_STEP 713
    ja   .fail
    mov  r8, [r12 + FD_FAT_SECTORS]
    imul r8, r15
    FD_RO_STEP 714
    jo   .fail
    add  r8, r14
    FD_RO_STEP 715
    jc   .fail
    cmp  r8, rax
    FD_RO_STEP 716
    jae  .fail
    mov  r9, rax
    sub  r9, r8
    mov  rax, r9
    xor  edx, edx
    div  r13
    cmp  rax, 65525
    FD_RO_STEP 717
    jb   .fail
    cmp  rax, 0x0FFFFFEE
    FD_RO_STEP 718
    ja   .fail
    mov  [r12 + FD_CLUSTER_COUNT], eax
    add  eax, 2
    mov  [r12 + FD_MAX_CLUSTER], eax
    cmp  [r12 + FD_ROOT_CLUSTER], eax
    FD_RO_STEP 719
    jae  .fail
    mov  rax, [r12 + FD_FAT_SECTORS]
    shl  rax, 7
    mov  ecx, [r12 + FD_MAX_CLUSTER]
    cmp  rax, rcx
    FD_RO_STEP 720
    jb   .fail
    mov  [r12 + FD_SPC], r13d
    mov  eax, r13d
    shl  eax, 9
    mov  [r12 + FD_CLUSTER_BYTES], eax
    mov  eax, [rbx + 67]                    ; FAT32 BPB volume serial
    mov  [r12 + FD_VOLUME_ID], eax
    mov  rax, [r12 + FD_PART_LBA]
    add  rax, r14
    FD_RO_STEP 721
    jc   .fail
    mov  [r12 + FD_FAT_LBA], rax
    mov  rdx, [r12 + FD_FAT_SECTORS]
    imul rdx, r15
    FD_RO_STEP 722
    jo   .fail
    add  rax, rdx
    FD_RO_STEP 723
    jc   .fail
    mov  [r12 + FD_DATA_LBA], rax
    mov  rax, [r12 + FD_PART_LBA]
    add  rax, [r12 + FD_TOTAL_SECTORS]
    FD_RO_STEP 724
    jc   .fail
    dec  rax
    mov  rdx, [r12 + FD_DEV]
    mov  rdx, [rdx + dev.info]
    cmp  rax, [rdx + blk_info.lba_max]
    FD_RO_STEP 725
    ja   .fail
    mov  rax, [rdx + blk_info.media_generation]
    cmp  rax, [r12 + FD_MOUNT_GEN]
    FD_RO_STEP 726
    jne  .fail                            ; no geometry assembled across two media
    mov  dword [r12 + FD_MOUNTED], 1
    mov  dword [r12 + FD_FSINFO_DELTA], 0
    mov  dword [r12 + FD_CACHE_START], 0
    mov  dword [r12 + FD_VALID_START], 0
    mov  byte [r12 + FD_LOOKUP_VALID], 0
    mov  qword [r12 + FD_FAT_CACHE_LBA], -1
    mov  dword [r12 + FD_FREE_VALID], 0
    xor  eax, eax
    jmp  .out
.fail:
    call fd_ro_diag_fail
    mov  dword [r12 + FD_MOUNTED], 0
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

fd_read_sectors:
    call ue_context
    test eax,eax
    jz .legacy
    xor eax,eax
    jmp ue_sectors
.legacy:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    ; The sole non-512 use is the bounded primary-header absence probe.
    ; Never let its temporary custody geometry reach FAT reads or a chunk.
    lea  rax, [rel fd_selected_ctx]
    cmp  r12, rax
    jne  .geometry_ok
    cmp  dword [rel fd_selected_sector], 512
    je   .geometry_ok
    cmp  dword [rel fd_selected_sector], 4096
    jne  .fail
    cmp  r13, 1
    jne  .fail
    cmp  r14, 1
    jne  .fail
    lea  rax, [rel fd_selected_header]
    cmp  r15, rax
    jne  .fail
.geometry_ok:
    call fd_read_custody
    test rax, rax
    FD_RO_STEP 801
    jnz  .fail
    test r14, r14
    jz   .ok
    mov  rax, r13
    add  rax, r14
    FD_RO_STEP 802
    jc   .fail
    dec  rax                              ; inclusive last requested LBA
    mov  rdx, [r12 + FD_DEV]
    test rdx, rdx
    FD_RO_STEP 803
    jz   .fail
    mov  rdx, [rdx + dev.info]
    test rdx, rdx
    FD_RO_STEP 804
    jz   .fail
    cmp  rax, [rdx + blk_info.lba_max]
    FD_RO_STEP 805
    ja   .fail
.loop:
    test r14, r14
    jz   .ok
    mov  rbx, r14
    cmp  rbx, 8
    jbe  .chunk
    mov  ebx, 8
.chunk:
    call fd_read_custody
    test rax, rax
    FD_RO_STEP 806
    jnz  .fail
    mov  rdi, [r12 + FD_DEV]
    mov  rsi, r13
    mov  rdx, rbx
    mov  rcx, r15
    call fd_ro_diag_io_begin
    call blk_read
    call fd_ro_diag_io_end
    push rax
    call fd_read_custody
    test rax, rax
    pop  rax
    FD_RO_STEP 807
    jnz  .fail                            ; changed even when the original read failed
    test rax, rax
    jnz  .read_refused
    add  r13, rbx
    mov  rax, rbx
    shl  rax, 9
    add  r15, rax
    sub  r14, rbx
    jmp  .loop
.read_refused:
    cmp  rbx, 1
    FD_RO_STEP 808
    jbe  .fail
.one:
    call fd_read_custody
    test rax, rax
    FD_RO_STEP 809
    jnz  .fail
    mov  rdi, [r12 + FD_DEV]
    mov  rsi, r13
    mov  edx, 1
    mov  rcx, r15
    call fd_ro_diag_io_begin
    call blk_read
    call fd_ro_diag_io_end
    push rax
    call fd_read_custody
    test rax, rax
    pop  rax
    FD_RO_STEP 810
    jnz  .fail
    test rax, rax
    FD_RO_STEP 811
    jnz  .fail
    inc  r13
    add  r15, 512
    dec  r14
    dec  rbx
    jnz  .one
    jmp  .loop
.ok:
    xor  eax, eax
    jmp  .out
.fail:
    call fd_ro_diag_fail
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

fd_next_cluster:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13d, esi
    cmp  r13d, 2
    jb   .fail
    cmp  r13d, [r12 + FD_MAX_CLUSTER]
    jae  .fail
    mov  eax, r13d
    shl  rax, 2
    mov  rbx, rax
    shr  rax, 9
    add  rax, [r12 + FD_FAT_LBA]
    and  ebx, 511
    cmp  [r12 + FD_FAT_CACHE_LBA], rax
    jne  .load
    cmp  [rel fd_fat_owner], r12          ; G1b: fd_fat_sector is shared by every ctx; the tag
    je   .cached                          ; is this ctx's, so the bytes must be too
.load:
    mov  qword [rel fd_fat_owner], 0      ; a failed read leaves the buffer nobody's
    push rax
    mov  rdi, r12
    mov  rsi, rax
    mov  edx, 1
    lea  rcx, [rel fd_fat_sector]
    call fd_read_sectors
    pop  rdx
    test rax, rax
    jnz  .fail
    mov  [r12 + FD_FAT_CACHE_LBA], rdx
    mov  [rel fd_fat_owner], r12
.cached:
    lea  rax, [rel fd_fat_sector]
    mov  eax, [rax + rbx]
    and  eax, 0x0FFFFFFF
    jmp  .out
.fail:
    mov  eax, 0xFFFFFFFF
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

fd_classify_next:
    cmp  esi, 0x0FFFFFFF                    ; fd_next_cluster's I/O sentinel is not EOC
    ja   .bad
    cmp  esi, FD_EOC_MIN
    jae  .eoc
    cmp  esi, FD_RESERVED_MIN
    jae  .bad
    cmp  esi, 2
    jb   .bad
    cmp  esi, [rdi + FD_MAX_CLUSTER]
    jae  .bad
    xor  eax, eax
    ret
.eoc:
    mov  eax, 1
    ret
.bad:
    mov  eax, -1
    ret

; Validate the complete chain implied by the directory size. Requiring the
; exact final cluster to point at EOC rejects short, overlong, cyclic, bad and
; reserved chains before even a random partial read can return data. The result
; is cached until the next mutation so bounded streaming chunks stay O(n).
fd_validate_file_chain:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rsi                            ; cache the actual argument, not unrelated lookup globals
    mov  r12, rdi
    mov  r13d, esi
    mov  r14, rdx
    test r14, r14
    jnz  .nonempty
    test r13d, r13d
    jnz  .fail
    xor  eax, eax
    jmp  .out
.nonempty:
    cmp  [r12 + FD_VALID_START], r13d
    jne  .calculate
    cmp  [r12 + FD_VALID_SIZE], r14
    je   .ok
.calculate:
    cmp  r13d, 2
    jb   .fail
    cmp  r13d, [r12 + FD_MAX_CLUSTER]
    jae  .fail
    mov  ecx, [r12 + FD_CLUSTER_BYTES]
    test ecx, ecx
    jz   .fail
    mov  rax, r14
    dec  rax
    xor  edx, edx
    div  rcx
    inc  rax
    mov  ecx, [r12 + FD_CLUSTER_COUNT]
    cmp  rax, rcx
    ja   .fail
    mov  r15, rax                         ; exact number of data clusters
.walk:
    cmp  r13d, 2
    jb   .fail
    cmp  r13d, [r12 + FD_MAX_CLUSTER]
    jae  .fail
    mov  rdi, r12
    mov  esi, r13d
    call fd_next_cluster
    mov  ebx, eax
    dec  r15
    jz   .last
    mov  rdi, r12
    mov  esi, ebx
    call fd_classify_next
    test eax, eax
    jnz  .fail
    mov  r13d, ebx
    jmp  .walk
.last:
    mov  rdi, r12
    mov  esi, ebx
    call fd_classify_next
    cmp  eax, 1
    jne  .fail
    mov  eax, [rsp]
    mov  [r12 + FD_VALID_START], eax
    mov  [r12 + FD_VALID_SIZE], r14
.ok:
    mov  dword [rel fat32_disk_last_error], FD_ERR_NONE
    xor  eax, eax
    jmp  .out
.fail:
    mov  dword [rel fat32_disk_last_error], FD_ERR_CHAIN_OR_IO
    mov  rax, -1
.out:
    pop  rsi
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

fd_lookup:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  dword [rel fat32_disk_last_error], FD_ERR_IO
    ; A successful exact-name lookup remains valid until mutation invalidates
    ; all cache tags, and makes large sequential streams O(data)
    ; rather than O(chunks * root-directory scan).
    cmp  byte [r12 + FD_LOOKUP_VALID], 1
    jne  .scan
    xor  ecx, ecx
.cache_cmp:
    cmp  ecx, 11
    jae  .cache_hit
    mov  al, [r13 + rcx]
    cmp  al, [r12 + FD_LOOKUP_NAME + rcx]
    jne  .scan
    inc  ecx
    jmp  .cache_cmp
.cache_hit:
    mov  eax, [r12 + FD_LOOKUP_CLUSTER]
    mov  [rel fd_found_cluster], eax
    mov  rax, [r12 + FD_LOOKUP_SIZE]
    mov  [rel fd_found_size], rax
    mov  al, [r12 + FD_LOOKUP_ATTR]
    mov  [rel fd_found_attr], al
    mov  dword [rel fat32_disk_last_error], FD_ERR_NONE
    xor  eax, eax
    jmp  .out
.scan:
    mov  byte [rel fd_lookup_candidate], 0
    mov  r14d, [r12 + FD_ROOT_CLUSTER]
    xor  r15d, r15d
    mov  dword [rel fd_found_cluster], 0
    mov  qword [rel fd_found_size], 0
.cluster:
    cmp  r15d, FD_DIR_MAX_CLUSTERS
    jae  .fail
    lea  r9, [rel fd_dir_seen]
    xor  ecx, ecx
.seen_scan:
    cmp  ecx, r15d
    jae  .seen_new
    cmp  r14d, [r9 + rcx*4]
    je   .fail
    inc  ecx
    jmp  .seen_scan
.seen_new:
    mov  [r9 + r15*4], r14d
    inc  r15d
    cmp  r14d, 2
    jb   .fail
    cmp  r14d, [r12 + FD_MAX_CLUSTER]
    jae  .fail
    mov  eax, r14d
    sub  eax, 2
    mov  ecx, [r12 + FD_SPC]
    imul rax, rcx
    jo   .fail
    add  rax, [r12 + FD_DATA_LBA]
    jc   .fail
    mov  rbx, rax
    xor  r10d, r10d
.sector:
    cmp  r10d, [r12 + FD_SPC]
    jae  .next_cluster
    mov  rdi, r12
    mov  rsi, rbx
    mov  edx, 1
    lea  rcx, [rel fd_sector]
    push r10
    call fd_read_sectors
    pop  r10
    test rax, rax
    jnz  .fail
    xor  r11d, r11d
.entry:
    cmp  r11d, 16
    jae  .sector_next
    mov  eax, r11d
    shl  eax, 5
    lea  rdx, [rel fd_sector]
    add  rdx, rax
    cmp  byte [rdx], 0
    je   .absent
    cmp  byte [rdx], 0xE5
    je   .entry_next
    cmp  byte [rdx + 11], 0x0F
    je   .entry_next
    test byte [rdx + 11], 0x18
    jnz  .entry_next
    xor  ecx, ecx
.name_cmp:
    cmp  ecx, 11
    jae  .found
    mov  al, [rdx + rcx]
    cmp  al, [r13 + rcx]
    jne  .entry_next
    inc  ecx
    jmp  .name_cmp
.found:
    ; A transaction-tagged committed entry wins regardless of directory order.
    ; Cache only after finding that winner or reaching the end of the root.
    cmp  byte [rel fd_lookup_candidate], 0
    je   .save_candidate
    cmp  word [rdx + 12], FD_TX_MAGIC
    jne  .entry_next
.save_candidate:
    mov  rax, [rdx]
    mov  [rel fd_source_entry], rax
    mov  rax, [rdx + 8]
    mov  [rel fd_source_entry + 8], rax
    mov  rax, [rdx + 16]
    mov  [rel fd_source_entry + 16], rax
    mov  rax, [rdx + 24]
    mov  [rel fd_source_entry + 24], rax
    mov  byte [rel fd_lookup_candidate], 1
    mov  al, [rdx + 11]
    mov  [rel fd_found_attr], al
    mov  [rel fd_found_dir_lba], rbx
    mov  eax, r11d
    shl  eax, 5
    mov  [rel fd_found_dir_off], eax
    movzx eax, word [rdx + 20]
    shl  eax, 16
    mov  ax, [rdx + 26]
    mov  [rel fd_found_cluster], eax
    mov  eax, [rdx + 28]
    mov  [rel fd_found_size], rax
    cmp  word [rdx + 12], FD_TX_MAGIC
    jne  .entry_next
.cache_begin:
    mov  al, [rel fd_found_attr]
    mov  [r12 + FD_LOOKUP_ATTR], al
    mov  rax, [rel fd_found_size]
    mov  [r12 + FD_LOOKUP_SIZE], rax
    mov  eax, [rel fd_found_cluster]
    mov  [r12 + FD_LOOKUP_CLUSTER], eax
    xor  ecx, ecx
.cache_name:
    cmp  ecx, 11
    jae  .cache_done
    mov  al, [r13 + rcx]
    mov  [r12 + FD_LOOKUP_NAME + rcx], al
    inc  ecx
    jmp  .cache_name
.cache_done:
    mov  byte [r12 + FD_LOOKUP_VALID], 1
    mov  dword [rel fat32_disk_last_error], FD_ERR_NONE
    xor  eax, eax
    jmp  .out
.entry_next:
    inc  r11d
    jmp  .entry
.sector_next:
    inc  rbx
    inc  r10d
    jmp  .sector
.next_cluster:
    mov  rdi, r12
    mov  esi, r14d
    call fd_next_cluster
    mov  ebx, eax
    mov  rdi, r12
    mov  esi, ebx
    call fd_classify_next
    cmp  eax, 1
    je   .absent
    cmp  eax, 0
    jne  .fail
    mov  r14d, ebx
    jmp  .cluster
.absent:
    cmp  byte [rel fd_lookup_candidate], 1
    je   .cache_begin
    mov  dword [rel fat32_disk_last_error], FD_ERR_NOT_FOUND
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Exact UTF-8 comparison with ASCII-only casefold. Non-ASCII bytes (therefore
; canonical decoded scalars) match exactly; no locale folding or normalization.
fd_name_ci_equal:
    push rbx
    xor  ecx, ecx
.char:
    cmp  ecx, edx
    jae  .end
    mov  al, [rdi + rcx]
    test al, al
    jz   .no
    mov  bl, [rsi + rcx]
    cmp  al, 'a'
    jb   .fold_b
    cmp  al, 'z'
    ja   .fold_b
    sub  al, 0x20
.fold_b:
    cmp  bl, 'a'
    jb   .compare
    cmp  bl, 'z'
    ja   .compare
    sub  bl, 0x20
.compare:
    cmp  al, bl
    jne  .no
    inc  ecx
    jmp  .char
.end:
    cmp  byte [rdi + rdx], 0
    jne  .no
    mov  eax, 1
    pop  rbx
    ret
.no:
    xor  eax, eax
    pop  rbx
    ret

; Render an 11-byte alias as NAME.EXT.  RDI=short entry, RSI=13-byte output.
fd_short_to_name:
    xor  edx, edx
    xor  ecx, ecx
.base:
    cmp  ecx, 8
    jae  .extension
    mov  al, [rdi + rcx]
    cmp  al, ' '
    je   .extension
    cmp  ecx, 0
    jne  .base_store
    cmp  al, 0x05                         ; encoded leading 0xE5 is not ASCII
    jne  .base_store
    mov  al, 0xE5
.base_store:
    mov  [rsi + rdx], al
    inc  edx
    inc  ecx
    jmp  .base
.extension:
    cmp  byte [rdi + 8], ' '
    je   .done
    mov  byte [rsi + rdx], '.'
    inc  edx
    mov  ecx, 8
.ext:
    cmp  ecx, 11
    jae  .done
    mov  al, [rdi + rcx]
    cmp  al, ' '
    je   .done
    mov  [rsi + rdx], al
    inc  edx
    inc  ecx
    jmp  .ext
.done:
    mov  byte [rsi + rdx], 0
    ret

; Canonical VFAT checksum over the following 11-byte alias.
fd_lfn_checksum:
    xor  eax, eax
    xor  ecx, ecx
.byte:
    mov  dl, al
    and  dl, 1
    ror  al, 1
    and  al, 0x7F
    shl  dl, 7
    or   al, dl
    add  al, [rdi + rcx]
    inc  ecx
    cmp  ecx, 11
    jb   .byte
    movzx eax, al
    ret

fd_lfn_reset:
    mov  byte [rel fd_lfn_valid], 0
    mov  byte [rel fd_lfn_expected], 0
    mov  word [rel fd_lfn_term_pos], 0xFFFF
    mov  byte [rel fd_lfn_name], 0
    ret

; Collect one 0x0F row.  A malformed row poisons only this sequence; the short
; alias that follows remains eligible, preventing corrupt LFN wrong-file match.
fd_lfn_collect:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    movzx ebx, byte [r12]
    test bl, 0xA0                         ; reserved ordinal bits
    jnz  .bad
    mov  r13d, ebx
    and  r13d, 0x1F
    test r13d, r13d
    jz   .bad
    cmp  r13d, FD_LFN_ENTRIES_MAX
    ja   .bad
    cmp  byte [r12 + 12], 0
    jne  .bad
    cmp  word [r12 + 26], 0
    jne  .bad
    cmp  byte [rel fd_lfn_valid], 1
    je   .continuation
    test bl, 0x40
    jz   .bad
    lea  rdi, [rel fd_lfn_utf16]
    xor  eax, eax
    mov  ecx, FD_LFN_MAX + 1
    cld
    rep  stosw
    mov  byte [rel fd_lfn_valid], 1
    mov  [rel fd_lfn_total], r13b
    mov  [rel fd_lfn_expected], r13b
    mov  al, [r12 + 13]
    mov  [rel fd_lfn_checksum_byte], al
    mov  word [rel fd_lfn_term_pos], 0xFFFF
    jmp  .common
.continuation:
    test bl, 0x40
    jnz  .bad
    cmp  r13b, [rel fd_lfn_expected]
    jne  .bad
.common:
    mov  al, [r12 + 13]
    cmp  al, [rel fd_lfn_checksum_byte]
    jne  .bad
    mov  r14d, r13d
    dec  r14d
    imul r14d, r14d, 13                  ; logical character base
    xor  r15d, r15d
    xor  ebx, ebx                        ; padding follows terminator in row
.unit:
    cmp  r15d, 13
    jae  .row_ok
    lea  rdx, [rel fd_lfn_offsets]
    movzx eax, byte [rdx + r15]
    movzx ecx, word [r12 + rax]
    mov  eax, r14d
    add  eax, r15d
    test ebx, ebx
    jnz  .padding
    test ecx, ecx
    jz   .terminator
    cmp  ecx, 0xFFFF
    je   .bad
    cmp  ecx, 0x20
    jb   .bad
    cmp  ecx, 0x7F
    je   .bad
    cmp  ecx, '"'
    je   .bad
    cmp  ecx, '*'
    je   .bad
    cmp  ecx, '/'
    je   .bad
    cmp  ecx, ':'
    je   .bad
    cmp  ecx, '<'
    je   .bad
    cmp  ecx, '>'
    je   .bad
    cmp  ecx, '?'
    je   .bad
    cmp  ecx, 0x5C
    je   .bad
    cmp  ecx, '|'
    je   .bad
    cmp  eax, FD_LFN_MAX
    jae  .bad
    lea  rdx, [rel fd_lfn_utf16]
    mov  [rdx + rax * 2], cx
    jmp  .unit_next
.terminator:
    cmp  eax, r14d                       ; reject redundant empty highest row
    jbe  .bad
    cmp  r13b, [rel fd_lfn_total]       ; only the last logical row may terminate
    jne  .bad
    cmp  eax, FD_LFN_MAX
    ja   .bad
    cmp  word [rel fd_lfn_term_pos], 0xFFFF
    jne  .bad
    mov  [rel fd_lfn_term_pos], ax
    lea  rdx, [rel fd_lfn_utf16]
    mov  word [rdx + rax * 2], 0
    mov  ebx, 1
    jmp  .unit_next
.padding:
    cmp  ecx, 0xFFFF
    jne  .bad
.unit_next:
    inc  r15d
    jmp  .unit
.row_ok:
    dec  byte [rel fd_lfn_expected]
    xor  eax, eax
    jmp  .out
.bad:
    call fd_lfn_reset
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Bind the accumulated long name to its alias.  RDI=short entry -> EAX=1/0.
fd_lfn_for_short:
    cmp  byte [rel fd_lfn_valid], 1
    jne  .no
    cmp  byte [rel fd_lfn_expected], 0
    jne  .no
    push rdi
    call fd_lfn_checksum
    pop  rdi
    cmp  al, [rel fd_lfn_checksum_byte]
    jne  .no
    movzx ecx, word [rel fd_lfn_term_pos]
    cmp  ecx, 0xFFFF
    jne  .terminated
    movzx ecx, byte [rel fd_lfn_total]
    imul ecx, ecx, 13
    cmp  ecx, FD_LFN_MAX
    ja   .no
.terminated:
    ; Decode only a complete checksum-bound sequence. Rows arrive backwards;
    ; keeping bounded UTF-16 first permits a pair split across LFN rows.
    jmp  fd_lfn_decode
.no:
    xor  eax, eax
    ret

; ECX = validated unit count -> EAX=1 complete canonical UTF-8 / 0 alias.
; The output and every downstream component remain <=255 BYTES plus NUL.
; Never expose a partial prefix when a scalar or the total length is invalid.
fd_lfn_decode:
    push rdi
    push rsi
    push rbx
    push r12
    push r13
    push r14
    mov  r12d, ecx
    test r12d, r12d
    jz   .bad
    xor  r13d, r13d
    xor  ebx, ebx
    lea  r14, [rel fd_lfn_utf16]
.scalar:
    cmp  r13d, r12d
    jae  .done
    movzx edi, word [r14 + r13 * 2]
    inc  r13d
    cmp  edi, 0xD800
    jb   .encode
    cmp  edi, 0xDFFF
    ja   .encode
    cmp  edi, 0xDBFF
    ja   .bad                            ; unpaired low surrogate
    cmp  r13d, r12d
    jae  .bad                            ; high surrogate at end
    movzx eax, word [r14 + r13 * 2]
    inc  r13d
    cmp  eax, 0xDC00
    jb   .bad
    cmp  eax, 0xDFFF
    ja   .bad
    sub  edi, 0xD800
    shl  edi, 10
    sub  eax, 0xDC00
    lea  edi, [rdi + rax + 0x10000]
.encode:
    lea  rsi, [rel fd_lfn_name]
    add  rsi, rbx
    mov  edx, FD_LFN_MAX
    sub  edx, ebx
    call ue_utf8_encode                  ; strict scalar, all-or-nothing per scalar
    test eax, eax
    js   .bad
    add  ebx, eax
    jmp  .scalar
.done:
    lea  rax, [rel fd_lfn_name]
    mov  byte [rax + rbx], 0
    mov  eax, 1
    jmp  .out
.bad:
    call fd_lfn_reset                    ; partial UTF-8 is never an eligible name
    xor  eax, eax
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rsi
    pop  rdi
    ret

fd_short_is_dot:
    cmp  byte [rdi], '.'
    jne  .no
    cmp  byte [rdi + 1], ' '
    je   .yes
    cmp  byte [rdi + 1], '.'
    jne  .no
    cmp  byte [rdi + 2], ' '
    jne  .no
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; RDI=short entry, RSI=component, EDX=len -> EAX=1 on LFN or alias match.
fd_entry_match:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13d, edx
    call fd_lfn_for_short
    test eax, eax
    jz   .alias
    lea  rdi, [rel fd_lfn_name]
    mov  rsi, r12
    mov  edx, r13d
    call fd_name_ci_equal
    test eax, eax
    jnz  .out
.alias:
    mov  rdi, rbx
    lea  rsi, [rel fd_short_name]
    call fd_short_to_name
    lea  rdi, [rel fd_short_name]
    mov  rsi, r12
    mov  edx, r13d
    call fd_name_ci_equal
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Conservative exact-8.3 converter used only for the root cache fast path.
; A rejection falls through to the full alias/LFN scanner, so it cannot change
; namespace semantics.
fd_component_to_short:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13d, esi
    mov  r14, rdx
    test r13d, r13d
    jz   .fail
    cmp  r13d, 12
    ja   .fail
    mov  rax, 0x2020202020202020
    mov  [r14], rax
    mov  word [r14 + 8], 0x2020
    mov  byte [r14 + 10], 0x20
    xor  ecx, ecx                        ; base count
    xor  edx, edx                        ; extension count
    xor  ebx, ebx                        ; in extension
    xor  r8d, r8d
.char:
    cmp  r8d, r13d
    jae  .done
    mov  al, [r12 + r8]
    cmp  al, '.'
    jne  .fold
    test ebx, ebx
    jnz  .fail
    test ecx, ecx
    jz   .fail
    mov  ebx, 1
    inc  r8d
    jmp  .char
.fold:
    cmp  al, 'a'
    jb   .legal
    cmp  al, 'z'
    ja   .legal
    sub  al, 0x20
.legal:
    cmp  al, 'A'
    jb   .digit
    cmp  al, 'Z'
    jbe  .store
.digit:
    cmp  al, '0'
    jb   .special
    cmp  al, '9'
    jbe  .store
.special:
    cmp  al, '_'
    je   .store
    cmp  al, '-'
    je   .store
    cmp  al, '~'
    jne  .fail
.store:
    test ebx, ebx
    jnz  .store_ext
    cmp  ecx, 8
    jae  .fail
    mov  [r14 + rcx], al
    inc  ecx
    inc  r8d
    jmp  .char
.store_ext:
    cmp  edx, 3
    jae  .fail
    mov  [r14 + rdx + 8], al
    inc  edx
    inc  r8d
    jmp  .char
.done:
    test ecx, ecx
    jz   .fail
    test ebx, ebx
    jz   .ok
    test edx, edx
    jz   .fail
.ok:
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Absolute path validation and bounded length measurement.
fd_path_validate:
    test rdi, rdi
    jz   .bad
    cmp  byte [rdi], '/'
    jne  .bad
    xor  ecx, ecx
.scan:
    cmp  ecx, FD_PATH_MAX
    ja   .bad
    mov  al, [rdi + rcx]
    test al, al
    jz   .done
    cmp  al, 0x20
    jb   .bad
    cmp  al, 0x5C
    je   .bad
    inc  ecx
    jmp  .scan
.done:
    test ecx, ecx
    jz   .bad
    mov  eax, ecx
    ret
.bad:
    mov  rax, -1
    ret

; Mutation-only full-path preflight, before writer recovery or a gate/grant.
; ASCII aliases remain usable; newly readable Unicode spellings are read-only.
fd_path_validate_ascii:
    call fd_path_validate
    cmp  rax, -1
    je   .out
    xor  edx, edx
.byte:
    cmp  edx, eax
    jae  .out
    cmp  byte [rdi + rdx], 0x80
    jae  .bad
    inc  edx
    jmp  .byte
.bad:
    mov  rax, -1
.out:
    ret

fd_path_cache_lookup:
    cmp  rdi, [rel fd_path_cache_ctx]
    jne  .miss
    mov  rax, [rdi + FD_NAMESPACE_GEN]
    cmp  rax, [rel fd_path_cache_generation]
    jne  .miss
    mov  eax, [rel fd_path_len]
    cmp  eax, [rel fd_path_cache_len]
    jne  .miss
    push rdi
    mov  rdi, rsi
    lea  rsi, [rel fd_path_cache_path]
    mov  edx, eax
    call memcmp
    pop  rdi
    test rax, rax
    jnz  .miss
    mov  eax, [rel fd_path_cache_cluster]
    mov  [rel fd_found_cluster], eax
    mov  rax, [rel fd_path_cache_size]
    mov  [rel fd_found_size], rax
    mov  al, [rel fd_path_cache_attr]
    mov  [rel fd_found_attr], al
    xor  eax, eax
    ret
.miss:
    mov  rax, -1
    ret

; Validate a directory chain without trusting a size field.
fd_validate_dir_chain:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  ebx, esi
    xor  r13d, r13d
.cluster:
    cmp  r13d, FD_DIR_MAX_CLUSTERS
    jae  .fail
    cmp  ebx, 2
    jb   .fail
    cmp  ebx, [r12 + FD_MAX_CLUSTER]
    jae  .fail
    lea  rdx, [rel fd_dir_seen]
    xor  ecx, ecx
.seen:
    cmp  ecx, r13d
    jae  .remember
    cmp  ebx, [rdx + rcx*4]
    je   .fail
    inc  ecx
    jmp  .seen
.remember:
    mov  [rdx + r13*4], ebx
    inc  r13d
    mov  rdi, r12
    mov  esi, ebx
    call fd_next_cluster
    mov  ebx, eax
    mov  rdi, r12
    mov  esi, ebx
    call fd_classify_next
    cmp  eax, 1
    je   .ok
    test eax, eax
    jnz  .fail
    jmp  .cluster
.ok:
    mov  edx, r13d                    ; bounded complete cluster count for read-only cursors
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Scan one directory for one component while validating the ENTIRE chain.
; Finding a row early never hides a cyclic/reserved/overlong tail.
fd_find_in_dir:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  ebx, esi
    mov  [rel fd_scan_component], rdx
    mov  [rel fd_scan_component_len], ecx
    mov  byte [rel fd_scan_found], 0
    mov  byte [rel fd_scan_committed], 0
    mov  byte [rel fd_scan_complete], 0
    mov  byte [rel fd_dir_end_seen], 0
    mov  dword [rel fd_list_seen_count], 0
    call fd_lfn_reset
.cluster:
    mov  eax, [rel fd_list_seen_count]
    cmp  eax, FD_DIR_MAX_CLUSTERS
    jae  .fail
    cmp  ebx, 2
    jb   .fail
    cmp  ebx, [r12 + FD_MAX_CLUSTER]
    jae  .fail
    lea  rdx, [rel fd_dir_seen]
    xor  ecx, ecx
.seen:
    cmp  ecx, eax
    jae  .remember
    cmp  ebx, [rdx + rcx*4]
    je   .fail
    inc  ecx
    jmp  .seen
.remember:
    mov  [rdx + rax*4], ebx
    inc  eax
    mov  [rel fd_list_seen_count], eax
    mov  eax, ebx
    sub  eax, 2
    mov  ecx, [r12 + FD_SPC]
    imul rax, rcx
    jo   .fail
    add  rax, [r12 + FD_DATA_LBA]
    jc   .fail
    mov  rbp, rax
    xor  r13d, r13d
.sector:
    cmp  r13d, [r12 + FD_SPC]
    jae  .next_cluster
    mov  rdi, r12
    lea  rsi, [rbp + r13]
    mov  edx, 1
    lea  rcx, [rel fd_sector]
    call fd_read_sectors
    test rax, rax
    jnz  .fail
    xor  r15d, r15d
.entry:
    cmp  r15d, 16
    jae  .sector_next
    cmp  byte [rel fd_dir_end_seen], 1
    je   .entry_next
    mov  eax, r15d
    shl  eax, 5
    lea  r14, [rel fd_sector]
    add  r14, rax
    cmp  byte [r14], 0
    je   .end_entries
    cmp  byte [r14], 0xE5
    je   .reset_entry
    cmp  byte [r14 + 11], 0x0F
    je   .lfn
    test byte [r14 + 11], 0x08
    jnz  .reset_entry
    mov  rdi, r14
    call fd_short_is_dot
    test eax, eax
    jnz  .reset_entry
    mov  rdi, r14
    mov  rsi, [rel fd_scan_component]
    mov  edx, [rel fd_scan_component_len]
    call fd_entry_match
    test eax, eax
    jz   .reset_entry
    cmp  byte [rel fd_scan_found], 1
    jne  .save_match
    ; Match the root reader's durable-name winner during the post-commit cut.
    cmp  word [r14 + 12], FD_TX_MAGIC
    je   .new_winner
    cmp  byte [rel fd_scan_committed], 1
    je   .reset_entry
    jmp  .fail                         ; untagged duplicate remains corruption
.new_winner:
    cmp  byte [rel fd_scan_committed], 1
    je   .fail
.save_match:
    lea  rax, [rbp + r13]
    mov  [rel fd_found_dir_lba], rax
    mov  eax, r15d
    shl  eax, 5
    mov  [rel fd_found_dir_off], eax
    mov  rax, [r14]
    mov  [rel fd_source_entry], rax
    mov  rax, [r14 + 8]
    mov  [rel fd_source_entry + 8], rax
    mov  rax, [r14 + 16]
    mov  [rel fd_source_entry + 16], rax
    mov  rax, [r14 + 24]
    mov  [rel fd_source_entry + 24], rax
    cmp  word [r14 + 12], FD_TX_MAGIC
    sete byte [rel fd_scan_committed]
    mov  byte [rel fd_scan_found], 1
    movzx eax, word [r14 + 20]
    shl  eax, 16
    mov  ax, [r14 + 26]
    mov  [rel fd_found_cluster], eax
    mov  eax, [r14 + 28]
    mov  [rel fd_found_size], rax
    mov  al, [r14 + 11]
    mov  [rel fd_found_attr], al
.reset_entry:
    call fd_lfn_reset
    jmp  .entry_next
.lfn:
    mov  rdi, r14
    call fd_lfn_collect
    jmp  .entry_next
.end_entries:
    mov  byte [rel fd_dir_end_seen], 1
    call fd_lfn_reset
.entry_next:
    inc  r15d
    jmp  .entry
.sector_next:
    inc  r13d
    jmp  .sector
.next_cluster:
    mov  rdi, r12
    mov  esi, ebx
    call fd_next_cluster
    mov  ebx, eax
    mov  rdi, r12
    mov  esi, ebx
    call fd_classify_next
    cmp  eax, 1
    je   .chain_done
    test eax, eax
    jnz  .fail
    jmp  .cluster
.chain_done:
    mov  byte [rel fd_scan_complete], 1  ; RCQ-20 S4: the whole chain was read
    cmp  byte [rel fd_scan_found], 1
    jne  .fail
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Resolve an absolute path, bounded to 16 components.  '.'/'..', empty and
; trailing components are refused rather than normalized.
fat32_disk_resolve_path_lfn:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  byte [rel fd_resolve_absent], 0
    mov  rdi, r13
    call fd_path_validate
    cmp  rax, -1
    je   .fail
    mov  [rel fd_path_len], eax
    cmp  byte [rel fd_resolve_strict],1
    jne  .ordinary
    ; '/' has no component to walk. Strict consumers still need the actual
    ; mounted root and a freshly validated complete chain, never a cached name.
    cmp  eax,1
    jne  .walk_begin
    mov  rdi,r12
    mov  esi,[r12 + FD_ROOT_CLUSTER]
    call fd_validate_dir_chain
    test rax,rax
    jnz  .fail
    jmp  .root
.ordinary:
    mov  rdi, r12
    mov  rsi, r13
    call fd_path_cache_lookup
    test rax, rax
    jz   .ok
    cmp  dword [rel fd_path_len], 1
    jne  .fast_try
.root:
    mov  eax, [r12 + FD_ROOT_CLUSTER]
    mov  [rel fd_found_cluster], eax
    mov  qword [rel fd_found_size], 0
    mov  byte [rel fd_found_attr], 0x10
    jmp  .cache
.fast_try:
    lea  rdi, [r13 + 1]
    mov  esi, [rel fd_path_len]
    dec  esi
    lea  rdx, [rel fd_path_short]
    call fd_component_to_short
    test rax, rax
    jnz  .walk_begin
    mov  rdi, r12
    lea  rsi, [rel fd_path_short]
    call fd_lookup
    test rax, rax
    jnz  .walk_begin
    mov  rdi, r12
    mov  esi, [r12 + FD_ROOT_CLUSTER]
    call fd_validate_dir_chain
    test rax, rax
    jnz  .fail
    jmp  .cache
.walk_begin:
    mov  r14d, [r12 + FD_ROOT_CLUSTER]
    mov  r15d, 1
    xor  ebx, ebx
.component:
    mov  ecx, r15d
.find_end:
    cmp  ecx, [rel fd_path_len]
    jae  .component_end
    cmp  byte [r13 + rcx], '/'
    je   .component_end
    inc  ecx
    jmp  .find_end
.component_end:
    mov  edx, ecx
    sub  edx, r15d
    test edx, edx
    jz   .fail
    cmp  edx, FD_LFN_MAX
    ja   .fail
    cmp  edx, 1
    jne  .dotdot
    cmp  byte [r13 + r15], '.'
    je   .fail
.dotdot:
    cmp  edx, 2
    jne  .depth
    cmp  byte [r13 + r15], '.'
    jne  .depth
    cmp  byte [r13 + r15 + 1], '.'
    je   .fail
.depth:
    inc  ebx
    cmp  ebx, FD_PATH_DEPTH_MAX
    ja   .fail
    mov  [rel fd_path_next_index], ecx
    mov  rdi, r12
    mov  esi, r14d
    lea  rdx, [r13 + r15]
    mov  ecx, [rel fd_path_next_index]
    sub  ecx, r15d
    call fd_find_in_dir
    test rax, rax
    jz   .component_found
    cmp  byte [rel fd_scan_complete], 1
    jne  .fail
    cmp  byte [rel fd_scan_found], 0
    jne  .fail
    mov  byte [rel fd_resolve_absent], 1
    jmp  .fail
.component_found:
    mov  ecx, [rel fd_path_next_index]
    cmp  ecx, [rel fd_path_len]
    jae  .cache
    test byte [rel fd_found_attr], 0x10
    jz   .fail
    mov  r14d, [rel fd_found_cluster]
    inc  ecx
    cmp  ecx, [rel fd_path_len]
    jae  .fail
    mov  r15d, ecx
    jmp  .component
.cache:
    mov  [rel fd_path_cache_ctx], r12
    mov  rax, [r12 + FD_NAMESPACE_GEN]
    mov  [rel fd_path_cache_generation], rax
    mov  eax, [rel fd_path_len]
    mov  [rel fd_path_cache_len], eax
    mov  ecx, eax
    inc  ecx
    lea  rdi, [rel fd_path_cache_path]
    mov  rsi, r13
    mov  edx, ecx
    call memcpy
    mov  eax, [rel fd_found_cluster]
    mov  [rel fd_path_cache_cluster], eax
    mov  rax, [rel fd_found_size]
    mov  [rel fd_path_cache_size], rax
    mov  al, [rel fd_found_attr]
    mov  [rel fd_path_cache_attr], al
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

fat32_disk_stat:
    push rbx
    push r12
    mov  rbx, rdx
    mov  r12, [rdi + fsmount.priv]
    mov  rdi, r12
    mov  dword [rel fat32_disk_last_error], FD_ERR_UNMOUNTED
    cmp  dword [r12 + FD_MOUNTED], 1
    jne  .fail
    call fd_lookup
    test rax, rax
    jnz  .fail
    mov  rdi, r12
    mov  esi, [rel fd_found_cluster]
    mov  rdx, [rel fd_found_size]
    call fd_validate_file_chain
    test rax, rax
    jnz  .fail
    mov  rax, [rel fd_found_size]
    mov  [rbx + fs_stat.size], rax
    mov  dword [rbx + fs_stat.flags], FS_STAT_READONLY ; range writes absent; replacement uses fs_ops.update
    mov  dword [rbx + fs_stat.reserved], 0
    xor  eax, eax
    pop  r12
    pop  rbx
    ret
.fail:
    mov  rax, -1
    pop  r12
    pop  rbx
    ret

; Adapt the existing VFS path slice without changing any fs_ops offsets.
; RDI=mount, RSI=path, EDX=len. Preserve operation arguments RCX/R8/R9.
fd_path_slice:
    test edx, edx
    jz   .fail
    cmp  edx, FD_PATH_MAX
    ja   .fail
    xor  eax, eax
.copy:
    cmp  eax, edx
    jae  .done
    cmp  byte [rsi + rax], 0
    je   .fail
    push rcx
    mov  cl, [rsi + rax]
    lea  r10, [rel fd_path_input]
    mov  [r10 + rax], cl
    pop  rcx
    inc  eax
    jmp  .copy
.done:
    lea  rsi, [rel fd_path_input]
    mov  byte [rsi + rax], 0
    xor  eax, eax
    ret
.fail:
    mov  rax, -1
    ret

; replace_meta(self, RSI=path, EDX=len, RCX=fs_replace_meta*) -> 0/-1, read-only.
; Resolve afresh and use its saved entry. Never touches fd_cp_* / journal state.
fat32_disk_replace_meta:
    call fd_path_slice
    test rax, rax
    jnz  fat32_disk_fail
    push rbx
    push r12
    mov  rbx, rcx
    mov  r12, [rdi + fsmount.priv]
    cmp  dword [r12 + FD_MOUNTED], 1
    jne  .fail
    mov  qword [rbx + fs_replace_meta.seconds], 0
    mov  dword [rbx + fs_replace_meta.ns], 0
    mov  dword [rbx + fs_replace_meta.flags], 0
    mov  qword [rbx + fs_replace_meta.node], 0
    ; The size-only lookup caches do not retain the directory entry or its location.
    ; Read it afresh for metadata; this invalidates read caches only, never copy cursors.
    mov  qword [rel fd_path_cache_ctx], 0
    mov  byte [r12 + FD_LOOKUP_VALID], 0
    mov  rdi, r12
    call fat32_disk_resolve_path_lfn
    test rax, rax
    jnz  .fail
    test byte [rel fd_found_attr], 0x18   ; directory / volume label
    jnz  .ok
    mov  dword [rbx + fs_replace_meta.flags], FS_RMETA_REGULAR
    mov  eax, [rel fd_found_cluster]
    test eax, eax
    jnz  .node
    mov  rax, [rel fd_found_dir_lba]      ; empty files still have distinct identities
    shl  rax, 4
    mov  ecx, [rel fd_found_dir_off]
    shr  ecx, 5
    add  rax, rcx
    inc  rax
    bts  rax, 63                         ; disjoint from a FAT cluster number
.node:
    mov  [rbx + fs_replace_meta.node], rax
    lea  rsi, [rel fd_source_entry]       ; resolver snapshot; fd_sector may hold a later directory sector
    movzx eax, word [rsi + 12]
    cmp  eax, FD_TX_MAGIC
    je   .ok
    cmp  eax, FD_CP_MAGIC
    je   .ok
    test byte [rsi + 11], 0xDF           ; only an ordinary archive file is replacement eligible
    jnz  .time
    or   dword [rbx + fs_replace_meta.flags], FS_RMETA_ELIGIBLE
.time:
    mov  eax, [rsi + 22]
    call fd_wrt_utc
    mov  [rbx + fs_replace_meta.seconds], rax
.ok:
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r12
    pop  rbx
    ret

fat32_disk_stat_path:
    call fd_path_slice
    test rax, rax
    jnz  fat32_disk_fail
    mov  rdx, rcx
    jmp  fd_stat_path_z

fat32_disk_list_dir:
    call fd_path_slice
    test rax, rax
    jnz  fat32_disk_fail
    mov  rdx, rcx
    mov  ecx, r8d
    mov  r8, r9
    jmp  fat32_disk_list_path

fat32_disk_read_at_path:
    call fd_path_slice
    test rax, rax
    jnz  fat32_disk_fail
    mov  rdx, rcx
    mov  rcx, r8
    mov  r8, r9
    jmp  fat32_disk_read_at

fd_stat_path_z:
    mov  dword [rdx + fs_stat.reserved], 0
    push rbx
    push r12
    mov  rbx, rdx
    mov  r12, [rdi + fsmount.priv]
    cmp  dword [r12 + FD_MOUNTED], 1
    jne  .fail
    mov  rdi, r12
    call fat32_disk_resolve_path_lfn
    test rax, rax
    jnz  .fail
    test byte [rel fd_found_attr], 0x10
    jz   .file
    mov  rdi, r12
    mov  esi, [rel fd_found_cluster]
    call fd_validate_dir_chain
    test rax, rax
    jnz  .fail
    mov  qword [rbx + fs_stat.size], 0
    mov  dword [rbx + fs_stat.flags], FS_STAT_READONLY
    mov  dword [rbx + fs_stat.reserved], 1
    jmp  .ok
.file:
    mov  rdi, r12
    mov  esi, [rel fd_found_cluster]
    mov  rdx, [rel fd_found_size]
    call fd_validate_file_chain
    test rax, rax
    jnz  .fail
    mov  rax, [rel fd_found_size]
    mov  [rbx + fs_stat.size], rax
    mov  dword [rbx + fs_stat.flags], FS_STAT_READONLY
.ok:
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r12
    pop  rbx
    ret

fat32_disk_bounds_ok:
    cmp  rsi, rdi
    ja   .bad
    mov  rax, rsi
    add  rax, rdx
    jc   .bad
    cmp  rax, rdi
    ja   .bad
    xor  eax, eax
    ret
.bad:
    mov  rax, -1
    ret

; Export only facts already validated into this mount-private FAT context.
fat32_disk_info:
    push rbx
    push r12
    mov  rbx, [rdi + fsmount.priv]
    mov  r12, rsi
    cmp  dword [rbx + FD_MOUNTED], 1
    jne  .fail
    mov  rax, [r12 + fs_info.free_clusters] ; FS_INFO_FACTS: vfs_info_facts, no FAT walk
    mov  qword [r12 + fs_info.free_clusters], -1
    cmp  dword [rbx + FD_NFATS], 2
    jne  .free_ready                       ; retain read-only support for other layouts
    cmp  dword [rbx + FD_FREE_VALID], 1
    je   .free_ready
    cmp  rax, FS_INFO_FACTS
    je   .free_ready                       ; not counted: exported as -1 below
    mov  rdi, rbx
    call fd_count_free
    test rax, rax
    jnz  .fail
.free_ready:
    mov  rax, [rbx + FD_ORPHANS]
    mov  [r12 + fs_info.orphans], rax
    lea  rax, [rel str_fd_backend]
    mov  [r12 + fs_info.backend], rax
    mov  rax, [rbx + FD_DEV]
    test rax, rax
    jz   .fail
    mov  [r12 + fs_info.device], rax     ; the dev*, as on ext4 / NTFS / exFAT (it was the device's NAME pointer,
                                         ; which vol_owner_probe dereferenced as a dev*)
    lea  rax, [rel str_fd_part_type]
    mov  [r12 + fs_info.part_type], rax
    mov  eax, [rbx + FD_VOLUME_ID]
    mov  [r12 + fs_info.volume_id], eax
    mov  eax, [rbx + FD_CLUSTER_BYTES]
    mov  [r12 + fs_info.cluster_bytes], eax
    mov  rax, [rbx + FD_TOTAL_SECTORS]
    mov  [r12 + fs_info.total_sectors], rax
    mov  rax, [rbx + FD_PART_LBA]
    mov  [r12 + fs_info.part_start], rax
    mov  rax, [rbx + FD_PART_SECTORS]
    mov  [r12 + fs_info.part_sectors], rax
    mov  dword [r12 + fs_info.part_count], 1
    cmp  dword [rbx + FD_NFATS], 2
    jne  .free_exported
    cmp  dword [rbx + FD_FREE_VALID], 1    ; only an exact count; a facts call that skipped leaves -1
    jne  .free_exported
    mov  rax, [rbx + FD_FREE_COUNT]
    mov  [r12 + fs_info.free_clusters], rax
.free_exported:
    mov  eax, FS_SCHEME_SUPERFLOPPY
    mov  rdx, [rbx + FD_DISK_GUID]
    or   rdx, [rbx + FD_DISK_GUID + 8]
    jz   .not_gpt
    mov  eax, FS_SCHEME_GPT
    jmp  .scheme
.not_gpt:
    cmp  qword [rbx + FD_PART_LBA], 0
    je   .scheme
    mov  eax, FS_SCHEME_MBR
.scheme:
    mov  [r12 + fs_info.scheme], eax
    xor  eax, eax
    pop  r12
    pop  rbx
    ret
.fail:
    mov  rax, -1
    pop  r12
    pop  rbx
    ret

; Export the checksum-validated LFN when present, otherwise the exact alias.
; Names live in a single bounded backend arena for the duration of one listing.
; RAX 0 = exported, 1 = exported with its long name omitted (no pool room left:
; .name keeps the exact 8.3 alias and FS_DIRENT_LONG_OMITTED says so), -1 = fail.
fd_dirent_export:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12, rsi
    lea  rsi, [r12 + fs_dirent.name]
    call fd_short_to_name
    mov  rdi, rbx
    call fd_lfn_for_short
    lea  r13, [rel fd_lfn_name]
    test eax, eax
    jnz  .measure
    mov  rdi, rbx
    lea  rsi, [rel fd_short_name]
    call fd_short_to_name
    lea  r13, [rel fd_short_name]
.measure:
    xor  ecx, ecx
.len:
    cmp  ecx, FD_LFN_MAX
    ja   .fail
    cmp  byte [r13 + rcx], 0
    je   .room
    inc  ecx
    jmp  .len
.room:
    mov  eax, [rel fd_list_names_used]
    lea  edx, [rax + rcx + 1]
    cmp  edx, FD_LIST_NAMES_CAP
    ja   .no_room
    lea  rdi, [rel fd_list_names]
    add  rdi, rax
    push rdi
    push rdx
    mov  rsi, rdi
    mov  rdi, r12
    call vfs_dirent_set_long_name
    pop  rdx
    pop  rdi
    push rdx
    mov  rsi, r13
    mov  edx, ecx
    inc  edx
    call memcpy
    pop  rdx
    mov  [rel fd_list_names_used], edx
    mov  eax, [rbx + 28]
    mov  [r12 + fs_dirent.size], rax
    xor  eax, eax
    test byte [rbx + 11], 0x10
    jz   .flags
    mov  eax, FS_DIRENT_DIR
.flags:
    or   eax, FS_DIRENT_LONG_NAME
    mov  [r12 + fs_dirent.flags], eax
    xor  eax, eax
    jmp  .out
.no_room:                                ; the inline .name already holds the exact alias
    mov  eax, [rbx + 28]
    mov  [r12 + fs_dirent.size], rax
    mov  dword [r12 + fs_dirent.reserved], 0
    xor  eax, eax
    test byte [rbx + 11], 0x10
    jz   .short_kind
    mov  eax, FS_DIRENT_DIR
.short_kind:
    lea  rdx, [rel fd_lfn_name]
    cmp  r13, rdx
    jne  .alias_only                     ; no long name exists: nothing is omitted
    or   eax, FS_DIRENT_LONG_OMITTED
    mov  [r12 + fs_dirent.flags], eax
    mov  eax, 1
    jmp  .out
.alias_only:
    mov  [r12 + fs_dirent.flags], eax
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Legacy root ABI is preserved as a thin wrapper around the pathname tail.
fat32_disk_list_root:
    mov  r8, rcx
    mov  ecx, edx
    mov  rdx, rsi
    lea  rsi, [rel str_fd_root_path]
    jmp  fat32_disk_list_path

; fat32_disk_list_path(self,path,entries,cap,result) validates the complete
; target directory chain and continues validation after output truncation.
; Retained observation of the most recent synchronous directory enumeration.
; Read-only accessor never initiates I/O, invalidation, remount or selection.
; RDI=mount -> RAX=global enumeration serial, RDX=actual successful directory
; sector reads, RCX=result, R8=1 only for this FAT context, R9/R10=mount/namespace
; generations. Foreign/unsupported contexts expose no other context's result.
fat32_disk_list_observe:
    mov  rax, [rel fd_list_observe_seq]
    xor  edx, edx
    mov  rcx, -1
    xor  r8d, r8d
    xor  r9d, r9d
    xor  r10d, r10d
    test rdi, rdi
    jz   .out
    mov  r11, [rdi + fsmount.ops]
    lea  rsi, [rel fat32_disk_ops]
    cmp  r11, rsi
    je   .fat
    lea  rsi, [rel fd_ro_ops]
    cmp  r11, rsi
    je   .fat
    lea  rsi, [rel fd_scratch_ops]
    cmp  r11, rsi
    jne  .out
.fat:
    mov  r11, [rdi + fsmount.priv]
    test r11, r11
    jz   .out
    cmp  r11, [rel fd_list_observe_ctx]
    jne  .out
    mov  rdx, [rel fd_list_observe_reads]
    mov  rcx, [rel fd_list_observe_rc]
    mov  r8d, 1
    mov  r9, [r11 + FD_MOUNT_GEN]
    mov  r10, [r11 + FD_NAMESPACE_GEN]
.out:
    ret

fat32_disk_list_path:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r12, [rdi + fsmount.priv]
    inc  qword [rel fd_list_observe_seq]
    mov  [rel fd_list_observe_ctx], r12
    mov  qword [rel fd_list_observe_reads], 0
    mov  qword [rel fd_list_observe_rc], -1
    mov  r13, rdx
    mov  r14d, ecx
    mov  r15, r8
    test r15, r15
    jz   .fail
    mov  dword [r15 + fs_list_result.count], 0
    mov  dword [r15 + fs_list_result.truncated], 0
    mov  dword [r15 + fs_list_result.names_short], 0
    mov  dword [rel fd_list_names_used], 0
    mov  byte [rel fd_dir_end_seen], 0
    cmp  dword [r12 + FD_MOUNTED], 1
    jne  .fail
    mov  rdi, r12
    call fat32_disk_resolve_path_lfn
    test rax, rax
    jnz  .fail
    test byte [rel fd_found_attr], 0x10
    jz   .fail
    mov  ebx, [rel fd_found_cluster]
    mov  [rel fd_list_cluster], ebx
    mov  byte [rel fd_dir_end_seen], 0 ; resolver may have seen the parent terminator
    mov  dword [rel fd_list_seen_count], 0
    call fd_lfn_reset
.cluster:
    mov  eax, [rel fd_list_seen_count]
    cmp  eax, FD_DIR_MAX_CLUSTERS
    jae  .fail
    cmp  ebx, 2
    jb   .fail
    cmp  ebx, [r12 + FD_MAX_CLUSTER]
    jae  .fail
    lea  rdx, [rel fd_dir_seen]
    xor  ecx, ecx
.seen:
    cmp  ecx, eax
    jae  .remember
    cmp  ebx, [rdx + rcx*4]
    je   .fail
    inc  ecx
    jmp  .seen
.remember:
    mov  [rdx + rax*4], ebx
    inc  eax
    mov  [rel fd_list_seen_count], eax
    mov  eax, ebx
    sub  eax, 2
    mov  ecx, [r12 + FD_SPC]
    imul rax, rcx
    jo   .fail
    add  rax, [r12 + FD_DATA_LBA]
    jc   .fail
    mov  rbp, rax
    mov  dword [rel fd_list_sector_index], 0
.sector:
    mov  eax, [rel fd_list_sector_index]
    cmp  eax, [r12 + FD_SPC]
    jae  .next_cluster
    mov  rdi, r12
    mov  rsi, rbp
    add  rsi, rax
    mov  edx, 1
    lea  rcx, [rel fd_sector]
    call fd_read_sectors
    test rax, rax
    jnz  .fail
    ; Count only a completed real blk_read through fd_read_sectors and its
    ; unchanged exact-device/media guards, never cached GUI rows or attempts.
    inc  qword [rel fd_list_observe_reads]
    mov  dword [rel fd_list_entry_index], 0
.entry:
    mov  eax, [rel fd_list_entry_index]
    cmp  eax, 16
    jae  .sector_next
    cmp  byte [rel fd_dir_end_seen], 1
    je   .entry_next
    shl  eax, 5
    lea  rbx, [rel fd_sector]
    add  rbx, rax
    cmp  byte [rbx], 0
    je   .end_entries
    cmp  byte [rbx], 0xE5
    je   .reset_entry
    cmp  byte [rbx + 11], 0x0F
    je   .lfn
    test byte [rbx + 11], 0x08
    jnz  .reset_entry
    mov  rdi, rbx
    call fd_short_is_dot
    test eax, eax
    jnz  .reset_entry
    cmp  dword [rel vfs_list_skip], 0    ; smart copy D: FSCHECK pages a directory past its first entries
    je   .listed
    dec  dword [rel vfs_list_skip]
    jmp  .reset_entry
.listed:
    mov  eax, [r15 + fs_list_result.count]
    cmp  eax, r14d
    jae  .clamped
    imul rax, rax, fs_dirent_size
    lea  rsi, [r13 + rax]
    mov  rdi, rbx
    call fd_dirent_export
    test rax, rax
    js   .clamped
    jz   .exported
    mov  dword [r15 + fs_list_result.names_short], 1
.exported:
    inc  dword [r15 + fs_list_result.count]
    jmp  .reset_entry
.clamped:
    mov  dword [r15 + fs_list_result.truncated], 1
.reset_entry:
    call fd_lfn_reset
    jmp  .entry_next
.lfn:
    mov  rdi, rbx
    call fd_lfn_collect
    jmp  .entry_next
.end_entries:
    mov  byte [rel fd_dir_end_seen], 1
    call fd_lfn_reset
.entry_next:
    inc  dword [rel fd_list_entry_index]
    jmp  .entry
.sector_next:
    inc  dword [rel fd_list_sector_index]
    jmp  .sector
.next_cluster:
    ; RBX currently aliases an entry pointer after any parsed sector; recover
    ; the chain cluster from its dedicated state before reading FAT.
    mov  ebx, [rel fd_list_cluster]
    mov  rdi, r12
    mov  esi, ebx
    call fd_next_cluster
    mov  ebx, eax
    mov  rdi, r12
    mov  esi, ebx
    call fd_classify_next
    cmp  eax, 1
    je   .success
    test eax, eax
    jnz  .fail
    mov  [rel fd_list_cluster], ebx
    jmp  .cluster
.success:
    mov  qword [rel fd_list_observe_rc], 0
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

fd_copy_cluster_range:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13d, esi
    mov  r14, rdx
    mov  r15, rcx
    mov  rbx, r8
    mov  eax, r13d
    sub  eax, 2
    mov  ecx, [r12 + FD_SPC]
    imul rax, rcx
    jo   .fail
    add  rax, [r12 + FD_DATA_LBA]
    jc   .fail
    mov  r13, rax
    mov  rax, r14
    shr  rax, 9
    add  r13, rax
    and  r14d, 511
    test r14, r14
    jz   .full
    mov  rdi, r12
    mov  rsi, r13
    mov  edx, 1
    lea  rcx, [rel fd_sector]
    call fd_read_sectors
    test rax, rax
    jnz  .fail
    mov  rcx, 512
    sub  rcx, r14
    cmp  rcx, rbx
    jbe  .partial_n
    mov  rcx, rbx
.partial_n:
    push rcx
    mov  rdi, r15
    lea  rsi, [rel fd_sector]
    add  rsi, r14
    mov  rdx, rcx
    call memcpy
    pop  rcx
    add  r15, rcx
    sub  rbx, rcx
    inc  r13
.full:
    mov  rdx, rbx
    shr  rdx, 9
    test rdx, rdx
    jz   .tail
    push rdx
    mov  rdi, r12
    mov  rsi, r13
    mov  rcx, r15
    call fd_read_sectors
    pop  rdx
    test rax, rax
    jnz  .fail
    add  r13, rdx
    mov  rax, rdx
    shl  rax, 9
    add  r15, rax
    sub  rbx, rax
.tail:
    test rbx, rbx
    jz   .ok
    mov  rdi, r12
    mov  rsi, r13
    mov  edx, 1
    lea  rcx, [rel fd_sector]
    call fd_read_sectors
    test rax, rax
    jnz  .fail
    mov  rdi, r15
    lea  rsi, [rel fd_sector]
    mov  rdx, rbx
    call memcpy
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

fat32_disk_read_at:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  rbp, rsp
    sub  rsp, 48
    mov  r12, [rdi + fsmount.priv]
    mov  [rbp - 8], rsi
    mov  [rbp - 16], rdx
    mov  [rbp - 24], rcx
    mov  [rbp - 32], r8
    mov  [rbp - 40], r8
    mov  dword [rel fat32_disk_last_error], FD_ERR_UNMOUNTED
    cmp  dword [r12 + FD_MOUNTED], 1
    jne  .fail
    mov  rsi, [rbp - 8]
    cmp  byte [rsi], '/'
    jne  .legacy_lookup
    mov  rdi, r12
    call fat32_disk_resolve_path_lfn
    test rax, rax
    jnz  .fail
    test byte [rel fd_found_attr], 0x10
    jnz  .fail
    jmp  .resolved
.legacy_lookup:
    mov  rdi, r12
    call fd_lookup
    test rax, rax
    jnz  .fail
.resolved:
    mov  r13d, [rel fd_found_cluster]
    mov  r14, [rel fd_found_size]
    mov  rdi, r12
    mov  esi, r13d
    mov  rdx, r14
    call fd_validate_file_chain
    test rax, rax
    jnz  .fail
    mov  rdi, r14
    mov  rsi, [rbp - 16]
    mov  rdx, [rbp - 32]
    call fat32_disk_bounds_ok
    test rax, rax
    jnz  .fail
    cmp  qword [rbp - 32], 0
    je   .success
    cmp  r13d, 2
    jb   .fail
    cmp  r13d, [r12 + FD_MAX_CLUSTER]
    jae  .fail
    mov  eax, [r12 + FD_CLUSTER_BYTES]
    test eax, eax
    jz   .fail
    mov  rax, [rbp - 16]
    xor  edx, edx
    mov  ecx, [r12 + FD_CLUSTER_BYTES]
    div  rcx
    mov  r15, rax
    mov  [rbp - 48], rdx                 ; within-cluster offset
    cmp  [r12 + FD_CACHE_START], r13d
    jne  .from_start
    cmp  [r12 + FD_CACHE_SIZE], r14
    jne  .from_start
    mov  eax, [r12 + FD_CACHE_INDEX]
    cmp  rax, r15
    ja   .from_start
    mov  r13d, [r12 + FD_CACHE_CLUSTER]
    mov  r14d, eax
    jmp  .locate
.from_start:
    mov  r13d, [rel fd_found_cluster]
    xor  r14d, r14d
.locate:
    cmp  r14, r15
    jae  .read_loop
    mov  rdi, r12
    mov  esi, r13d
    call fd_next_cluster
    mov  ebx, eax
    mov  rdi, r12
    mov  esi, ebx
    call fd_classify_next
    test eax, eax
    jnz  .fail
    mov  r13d, ebx
    inc  r14d
    jmp  .locate
.read_loop:
    mov  rbx, [rbp - 48]
    mov  rax, [rbp - 32]
    test rax, rax
    jz   .done_data
    mov  ecx, [r12 + FD_CLUSTER_BYTES]
    sub  rcx, rbx
    cmp  rcx, rax
    jbe  .take
    mov  rcx, rax
.take:
    push rcx
    mov  rdi, r12
    mov  esi, r13d
    mov  rdx, rbx
    mov  r8, rcx
    mov  rcx, [rbp - 24]
    call fd_copy_cluster_range
    pop  rcx
    test rax, rax
    jnz  .fail
    add  [rbp - 24], rcx
    sub  [rbp - 32], rcx
    mov  eax, [rel fd_found_cluster]
    mov  [r12 + FD_CACHE_START], eax
    mov  [r12 + FD_CACHE_CLUSTER], r13d
    mov  [r12 + FD_CACHE_INDEX], r14d
    mov  rax, [rel fd_found_size]
    mov  [r12 + FD_CACHE_SIZE], rax
    cmp  qword [rbp - 32], 0
    je   .done_data
    mov  rdi, r12
    mov  esi, r13d
    call fd_next_cluster
    mov  ebx, eax
    mov  rdi, r12
    mov  esi, ebx
    call fd_classify_next
    test eax, eax
    jnz  .fail
    mov  r13d, ebx
    inc  r14d
    mov  qword [rbp - 48], 0
    jmp  .read_loop
.done_data:
    mov  rax, [rbp - 16]
    add  rax, [rbp - 40]
    jc   .fail
    cmp  rax, [rel fd_found_size]
    jne  .success
    mov  rdi, r12
    mov  esi, r13d
    call fd_next_cluster
    mov  esi, eax
    mov  rdi, r12
    call fd_classify_next
    cmp  eax, 1
    jne  .fail
.success:
    mov  rax, [rbp - 40]
    jmp  .out
.fail:
    cmp  dword [rel fat32_disk_last_error], FD_ERR_NONE
    jne  .have_error
    mov  dword [rel fat32_disk_last_error], FD_ERR_IO
.have_error:
    mov  rax, -1
.out:
    add  rsp, 48
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; fat32_disk_file_extents(RDI=fsmount,RSI=path,EDX=len,RCX=fs_extent_map*,R8D=cap) -> RAX the file's total
;   extent count / -1 (fat32_disk_last_error). RCQ-38 G3 (PLAN_G3 af6044e9; rc-boot 15:54:00 C1/C2). The path
;   resolves exactly as fat32_disk_read_at's; a directory or volume label refuses. The whole chain is validated
;   (exact length, EOC) before the walk. Physically contiguous clusters coalesce into one {lba, blocks} extent,
;   each cluster bounded by fd_cluster_lba; the blocks sum to ceil(size / 512), so no extent reaches past the
;   file's last block. More extents than cap: the first cap are written; RAX and .count hold the total (the
;   caller's slow path; frozen 15:55:23). Any failure after the argument check leaves .count 0 and .version 0,
;   so fat32_disk_extent_check never calls a failed map current: .version is stamped last (srcreview C1).
;   Read-only: no write, no grant, no fd_invalidate_caches. BSP only, like every fat32_disk entry.
fat32_disk_file_extents:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 24                         ; [0] the map, [8] cap
    mov  [rsp], rcx
    mov  [rsp + 8], r8d
    mov  rbx, rdi
    mov  r12, [rdi + fsmount.priv]
    mov  dword [rel fat32_disk_last_error], FD_ERR_UNMOUNTED
    cmp  dword [r12 + FD_MOUNTED], 1
    jne  .fail
    mov  dword [rel fat32_disk_last_error], FD_ERR_NONE
    test rcx, rcx
    jz   .bad_arg
    mov  dword [rcx + fs_extent_map.count], 0
    mov  dword [rcx + fs_extent_map.version], 0   ; stamped on success only
    call fd_path_slice                   ; RSI = the Z path in fd_path_input
    test rax, rax
    jnz  .bad_arg
    cmp  byte [rsi], '/'
    jne  .legacy
    mov  rdi, r12
    call fat32_disk_resolve_path_lfn
    test rax, rax
    jnz  .fail
    jmp  .found
.legacy:
    mov  rdi, r12
    call fd_lookup
    test rax, rax
    jnz  .fail
.found:
    test byte [rel fd_found_attr], 0x18  ; a directory or volume label has no file extents
    jnz  .bad_arg
    mov  r13d, [rel fd_found_cluster]
    mov  r14, [rel fd_found_size]
    mov  rdi, r12
    mov  esi, r13d
    mov  rdx, r14
    call fd_validate_file_chain          ; exact length and EOC before the walk (empty: no cluster)
    test rax, rax
    jnz  .fail
    mov  rax, [r12 + FD_DEV]
    test rax, rax
    jz   .io
    mov  rcx, [rax + dev.info]
    test rcx, rcx
    jz   .io
    cmp  qword [rcx + blk_info.media_generation], 0
    je   .io                             ; a medium nobody could check the map against later
    cmp  dword [rcx + blk_info.sector_size], 512
    jne  .io                             ; the walk counts 512 B blocks (fat32 mounts nothing else)
    mov  rdi, [rsp]
    mov  [rdi + fs_extent_map.dev], rax
    mov  rax, [rcx + blk_info.media_generation]
    mov  [rdi + fs_extent_map.media_gen], rax
    mov  dword [rdi + fs_extent_map.block_bytes], 512
    mov  [rdi + fs_extent_map.mount], rbx
    mov  rax, [rbx + fsmount.ops]
    mov  [rdi + fs_extent_map.ops], rax
    mov  [rdi + fs_extent_map.priv], r12
    mov  rax, [r12 + FD_NAMESPACE_GEN]
    mov  [rdi + fs_extent_map.ns_gen], rax
    mov  [rdi + fs_extent_map.size], r14
    mov  eax, [r12 + FD_VOLUME_ID]
    mov  [rdi + fs_extent_map.volume_id], eax
    mov  eax, [rsp + 8]
    mov  [rdi + fs_extent_map.cap], eax
    mov  dword [rdi + fs_extent_map.reserved], 0
    xor  r15d, r15d                      ; extents so far
    xor  ebp, ebp                        ; RBX/RBP: the open run's lba / blocks (0 = none open)
    add  r14, 511
    shr  r14, 9                          ; R14: the file's blocks still to place
    jz   .done
.walk:
    mov  rdi, r12
    mov  esi, r13d
    call fd_cluster_lba                  ; RAX = the cluster's first LBA, RDX = one past its last
    cmp  rax, -1
    je   .fail
    sub  rdx, rax
    jz   .io
    cmp  rdx, r14
    jbe  .take
    mov  rdx, r14                        ; the file ends inside this cluster
.take:
    sub  r14, rdx
    test rbp, rbp
    jz   .open
    lea  rcx, [rbx + rbp]
    cmp  rcx, rax
    jne  .emit
    add  rbp, rdx                        ; physically contiguous: the run grows
    jmp  .advance
.emit:                                   ; the run RBX/RBP ends: written while there is room, always counted
    cmp  r15d, [rsp + 8]
    jae  .counted
    mov  rcx, [rsp]
    mov  r8d, r15d
    shl  r8, 4
    mov  [rcx + r8 + fs_extent_map.ext], rbx
    mov  [rcx + r8 + fs_extent_map.ext + 8], rbp
.counted:
    inc  r15d
    test rdx, rdx
    jz   .done                           ; that was the final run
.open:
    mov  rbx, rax
    mov  rbp, rdx
.advance:
    test r14, r14
    jnz  .next
    xor  edx, edx
    jmp  .emit
.next:
    mov  rdi, r12
    mov  esi, r13d
    call fd_next_cluster
    mov  r13d, eax
    mov  rdi, r12
    mov  esi, eax
    call fd_classify_next
    test eax, eax
    jnz  .io                             ; the chain was validated: only a read fault lands here
    jmp  .walk
.done:
    mov  rdi, [rsp]
    mov  [rdi + fs_extent_map.count], r15d   ; the total, which may exceed .cap
    mov  dword [rdi + fs_extent_map.version], FS_EXTENT_MAP_VERSION   ; last: only a whole map is checkable
    mov  eax, r15d
    jmp  .out
.bad_arg:
    mov  dword [rel fat32_disk_last_error], FD_ERR_BAD_ARG
    jmp  .fail
.io:
    mov  dword [rel fat32_disk_last_error], FD_ERR_IO
.fail:
    cmp  dword [rel fat32_disk_last_error], FD_ERR_NONE
    jne  .have_error
    mov  dword [rel fat32_disk_last_error], FD_ERR_IO   ; the resolvers fail without naming why
.have_error:
    mov  rax, -1
.out:
    add  rsp, 24
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; fat32_disk_extent_check(RDI=fsmount,RSI=fs_extent_map*) -> EAX 0 the map still describes this mount at its
;   generation / 1 only FD_NAMESPACE_GEN moved (resolve again) / -1 another mount, device, volume or medium, a
;   medium generation that reads 0, or a map of another version. RCQ-38 G3: a pure state read, no I/O.
;   Clobbers RAX, RCX, R8.
fat32_disk_extent_check:
    cmp  dword [rsi + fs_extent_map.version], FS_EXTENT_MAP_VERSION
    jne  .other
    cmp  rdi, [rsi + fs_extent_map.mount]
    jne  .other
    mov  rax, [rdi + fsmount.ops]
    cmp  rax, [rsi + fs_extent_map.ops]
    jne  .other
    mov  r8, [rdi + fsmount.priv]
    cmp  r8, [rsi + fs_extent_map.priv]
    jne  .other
    cmp  dword [r8 + FD_MOUNTED], 1
    jne  .other
    mov  rax, [r8 + FD_DEV]
    test rax, rax
    jz   .other
    cmp  rax, [rsi + fs_extent_map.dev]
    jne  .other
    mov  rax, [rax + dev.info]
    test rax, rax
    jz   .other
    mov  rcx, [rax + blk_info.media_generation]
    test rcx, rcx
    jz   .other                          ; unreadable counts as changed
    cmp  rcx, [rsi + fs_extent_map.media_gen]
    jne  .other
    mov  eax, [r8 + FD_VOLUME_ID]
    cmp  eax, [rsi + fs_extent_map.volume_id]
    jne  .other
    mov  rax, [r8 + FD_NAMESPACE_GEN]
    cmp  rax, [rsi + fs_extent_map.ns_gen]
    jne  .moved
    xor  eax, eax
    ret
.moved:
    mov  eax, 1
    ret
.other:
    mov  eax, -1
    ret

%include "fs/fat32_source.inc"

; Read-only source adapter for the existing ext4 transaction copier. It never
; selects/arms a volume, recovers a journal, or acquires a source write grant.
; One BSP copy job owns these snapshots. Pure checks preserve all but RAX/RDX.
; Pure read identity for all FAT aliases, including the exact selected and
; scratch descriptors. The selected read alias is not copier admission.
fat32_disk_read_device:               ; RDI=mount -> dev / 0, preserves RDX
    push rdx
    mov  rax, [rdi + fsmount.ops]
    lea  rdx, [rel fd_selected_ops]
    cmp  rax, rdx
    je   .ctx
    lea  rdx, [rel fd_scratch_ops]
    cmp  rax, rdx
    je   .ctx
    pop  rdx
    jmp  fat32_disk_source_device
.ctx:
    mov  rax, [rdi + fsmount.priv]
    test rax, rax
    jz   .bad
    cmp  dword [rax + FD_MOUNTED], 1
    jne  .bad
    mov  rax, [rax + FD_DEV]
    pop  rdx
    ret
.bad:
    xor  eax, eax
    pop  rdx
    ret

fat32_disk_source_device:              ; RDI=registered fsmount -> dev / 0
    push rdx
    mov  rax, [rdi + fsmount.ops]
    lea  rdx, [rel fat32_disk_ops]
    cmp  rax, rdx
    je   .ctx
    lea  rdx, [rel fd_ro_ops]
    cmp  rax, rdx
    je   .ctx
    lea  rdx, [rel fd_scratch_ops]
    cmp  rax, rdx
    je   .scratch
    jmp  .bad
.ctx:
    mov  rax, [rdi + fsmount.priv]
    test rax, rax
    jz   .bad
    cmp  dword [rax + FD_MOUNTED], 1
    jne  .bad
    mov  rax, [rax + FD_DEV]
    pop  rdx
    ret
.bad:
    xor  eax, eax
    pop  rdx
    ret

.scratch:
    ; Only the actual registered FSFATARM mount may be a scratch copy source.
    ; This is pure read custody: no OWNER, source arm, write grant or refresh.
    push rdi
    push rcx
    mov  edi, [rel fd_scratch_handle]   ; retained one-based registration
    test edi, edi
    jz   .scratch_bad
    dec  edi
    call vfs_mount_ptr
    cmp  rax, [rsp + 8]
    jne  .scratch_bad
    mov  rdx, [rax + fsmount.priv]
    lea  rcx, [rel fd_scratch_ctx]
    cmp  rdx, rcx
    jne  .scratch_bad
    mov  rdi, rdx
    call fd_scratch_current             ; registry, exact info/ops/geometry/generation
    test rax, rax
    jnz  .scratch_bad
    cmp dword [rel fd_scratch_mbr_slot],0
    je .gpt_identity
    mov eax,[rel fd_scratch_mbr_slot]
    dec eax
    shl eax,4
    lea rcx,[rel fd_scratch_header+446]
    add rcx,rax
    mov eax,[rcx+8]
    cmp rax,[rel fd_scratch_ctx+FD_PART_LBA]
    jne .scratch_bad
    mov eax,[rcx+12]
    cmp rax,[rel fd_scratch_ctx+FD_PART_SECTORS]
    jne .scratch_bad
    call fd_scratch_metadata
    test rax,rax
    jnz .scratch_bad
    jmp .serial
.gpt_identity:
    ; Retain the exact accepted GPT extent and identities, not another context
    ; or a self-consistent replacement BPB at a different partition offset.
    mov  eax, [rel fd_scratch_ctx + FD_PART_INDEX]
    cmp  eax, 128
    jae  .scratch_bad
    cmp  eax, [rel fd_scratch_header + 80]
    jae  .scratch_bad
    shl  eax, 7
    lea  rcx, [rel fd_scratch_entries]
    add  rcx, rax
    mov  rax, [rcx + 32]
    cmp  rax, [rel fd_scratch_ctx + FD_PART_LBA]
    jne  .scratch_bad
    mov  rdx, [rcx + 40]
    sub  rdx, rax
    jc   .scratch_bad
    add  rdx, 1
    jc   .scratch_bad
    cmp  rdx, [rel fd_scratch_ctx + FD_PART_SECTORS]
    jne  .scratch_bad
    mov  rax, [rcx + 16]
    cmp  rax, [rel fd_scratch_ctx + FD_PART_GUID]
    jne  .scratch_bad
    mov  rax, [rcx + 24]
    cmp  rax, [rel fd_scratch_ctx + FD_PART_GUID + 8]
    jne  .scratch_bad
    mov  rax, [rel fd_scratch_header + 56]
    cmp  rax, [rel fd_scratch_ctx + FD_DISK_GUID]
    jne  .scratch_bad
    mov  rax, [rel fd_scratch_header + 64]
    cmp  rax, [rel fd_scratch_ctx + FD_DISK_GUID + 8]
    jne  .scratch_bad
.serial:
    mov  eax, [rel fd_scratch_boot + 67]
    cmp  eax, [rel fd_scratch_ctx + FD_VOLUME_ID]
    jne  .scratch_bad
    mov  rax, [rel fd_scratch_ctx + FD_DEV]
    pop  rcx
    pop  rdi
    pop  rdx
    ret
.scratch_bad:
    pop  rcx
    pop  rdi
    jmp  .bad

fat32_disk_source_bind:                ; RDI=mount -> 0 / -1, no file or write admission
    push rbx
    push r12
    mov  rbx, rdi
    call fat32_disk_source_device
    test rax, rax
    jz   .bad
    mov  [rel fd_src_mount], rbx
    mov  r12, [rbx + fsmount.priv]
    mov  [rel fd_src_ctx], r12
    mov  rdx, [rbx + fsmount.ops]
    mov  [rel fd_src_ops], rdx
    mov  rax, [rax + dev.info]
    test rax, rax
    jz   .bad
    mov  [rel fd_src_info], rax
    cmp  dword [rax + blk_info.sector_size], 512
    jne  .bad
    mov  rdx, [rax + blk_info.lba_max]
    mov  [rel fd_src_max], rdx
    mov  rax, [rax + blk_info.media_generation]
    test rax, rax
    jz   .bad
    cmp  rax, [r12 + FD_MOUNT_GEN]
    jne  .bad
    mov  [rel fd_src_gen], rax
    mov  rax, [r12 + FD_NAMESPACE_GEN]
    test rax, rax
    jz   .bad
    mov  [rel fd_src_ns], rax
    cmp  qword [r12 + FD_PART_SECTORS], 0
    je   .bad
    cmp  dword [r12 + FD_VOLUME_ID], 0
    je   .bad                         ; an unknown serial is not usable copy custody
    lea  rdi, [rel fd_src_geom]
    mov  rsi, r12
    mov  edx, 80                      ; immutable mounted geometry, through FD_MOUNTED
    call memcpy
    mov  eax, [r12 + FD_VOLUME_ID]
    mov  [rel fd_src_volume], eax
    lea  rdi, [rel fd_src_guids]
    lea  rsi, [r12 + FD_DISK_GUID]
    mov  edx, 32
    call memcpy
    call fd_src_read_bpb
    test rax, rax
    jnz  .bad
    ; The fresh BPB must describe the geometry being bound, not a stale cache.
    cmp  word [rel fd_src_bpb + 510], 0xAA55
    jne  .bad
    cmp  word [rel fd_src_bpb + 11], 512
    jne  .bad
    movzx eax, byte [rel fd_src_bpb + 13]
    cmp  eax, [r12 + FD_SPC]
    jne  .bad
    movzx eax, byte [rel fd_src_bpb + 16]
    cmp  eax, [r12 + FD_NFATS]
    jne  .bad
    mov  eax, [rel fd_src_bpb + 32]
    cmp  rax, [r12 + FD_TOTAL_SECTORS]
    jne  .bad
    mov  eax, [rel fd_src_bpb + 36]
    cmp  rax, [r12 + FD_FAT_SECTORS]
    jne  .bad
    mov  ecx, [r12 + FD_NFATS]
    imul rax, rcx
    movzx edx, word [rel fd_src_bpb + 14]
    add  rdx, [r12 + FD_PART_LBA]
    jc   .bad
    cmp  rdx, [r12 + FD_FAT_LBA]
    jne  .bad
    add  rax, rdx
    jc   .bad
    cmp  rax, [r12 + FD_DATA_LBA]
    jne  .bad
    mov  eax, [rel fd_src_bpb + 44]
    cmp  eax, [r12 + FD_ROOT_CLUSTER]
    jne  .bad
    mov  eax, [rel fd_src_bpb + 67]
    cmp  eax, [r12 + FD_VOLUME_ID]
    jne  .bad
    lea  rdi, [rel fd_src_bpb_saved]
    lea  rsi, [rel fd_src_bpb]
    mov  edx, 512
    call memcpy
    call fat32_disk_source_token
    jmp  .out
.bad:
    mov  rax, -1
.out:
    pop  r12
    pop  rbx
    ret

fat32_disk_source_token:
    push rcx
    push r8
    push r9
    mov  rax, [rel fd_src_mount]
    test rax, rax
    jz   .bad
    mov  rdx, [rel fd_src_ops]
    cmp  [rax + fsmount.ops], rdx
    jne  .bad
    lea  rcx, [rel fd_scratch_ops]
    cmp  rdx, rcx
    jne  .callbacks
    push rdi
    mov  rdi, rax
    call fat32_disk_source_device       ; exact registration/retained extent at every read boundary
    pop  rdi
    test rax, rax
    jz   .bad
    mov  rax, [rel fd_src_mount]
    ; FSFATARM copies the exact selected read wrappers, which repeat scratch
    ; custody before delegating. Do not substitute the legacy direct callbacks.
    lea  rcx, [rel fd_selected_read_at_path]
    cmp  [rdx + fs_ops.read_at_path], rcx
    jne  .bad
    lea  rcx, [rel fd_selected_stat_path]
    jmp  .stat_callback
.callbacks:
    lea  rcx, [rel fat32_disk_read_at_path]
    cmp  [rdx + fs_ops.read_at_path], rcx
    jne  .bad
    lea  rcx, [rel fat32_disk_stat_path]
.stat_callback:
    cmp  [rdx + fs_ops.stat_path], rcx
    jne  .bad
    mov  r9, [rel fd_src_ctx]
    cmp  [rax + fsmount.priv], r9
    jne  .bad
    lea  r8, [rel fd_src_geom]
    xor  ecx, ecx
.geometry:
    mov  rax, [r9 + rcx*8]
    cmp  rax, [r8 + rcx*8]
    jne  .bad
    inc  ecx
    cmp  ecx, 10
    jb   .geometry
    mov  eax, [r9 + FD_VOLUME_ID]
    cmp  eax, [rel fd_src_volume]
    jne  .bad
    mov  rax, [r9 + FD_NAMESPACE_GEN]
    cmp  rax, [rel fd_src_ns]
    jne  .bad
    mov  rax, [r9 + FD_MOUNT_GEN]
    cmp  rax, [rel fd_src_gen]
    jne  .bad
    lea  r8, [rel fd_src_guids]
    xor  ecx, ecx
.guids:
    mov  rax, [r9 + FD_DISK_GUID + rcx*8]
    cmp  rax, [r8 + rcx*8]
    jne  .bad
    inc  ecx
    cmp  ecx, 4
    jb   .guids
    mov  rax, [r9 + FD_DEV]
    mov  rax, [rax + dev.info]
    cmp  rax, [rel fd_src_info]
    jne  .bad
    mov  rdx, [rax + blk_info.media_generation]
    cmp  rdx, [rel fd_src_gen]
    jne  .bad
    cmp  dword [rax + blk_info.sector_size], 512
    jne  .bad
    mov  rdx, [rax + blk_info.lba_max]
    cmp  rdx, [rel fd_src_max]
    jne  .bad
    xor  eax, eax
    jmp  .out
.bad:
    mov  rax, -1
.out:
    pop  r9
    pop  r8
    pop  rcx
    ret

fd_src_read_bpb:
    call fat32_disk_source_token
    test rax, rax
    jnz  .out
    mov  rdi, [rel fd_src_ctx]
    mov  rsi, [rdi + FD_PART_LBA]
    mov  edx, 1
    lea  rcx, [rel fd_src_bpb]
    call fd_read_sectors
    push rax
    call fat32_disk_source_token
    test rax, rax
    pop  rax
    jz   .out
    mov  rax, -1
.out:
    ret

fat32_disk_source_current:
    call fd_src_read_bpb
    test rax, rax
    jnz  .out
    lea  rdi, [rel fd_src_bpb]
    lea  rsi, [rel fd_src_bpb_saved]
    mov  edx, 512
    call memcmp
    test rax, rax
    jnz  .bad
    mov  rdi, [rel fd_src_ctx]
    call fd_read_cache_drop              ; fresh facts without changing namespace custody
    jmp  fat32_disk_source_token
.bad:
    mov  rax, -1
.out:
    ret

; RSI=Z path, EDX=length, ECX=1 bind / 0 check -> RAX exact regular-file size / -1.
; Reuse the bounded Unicode resolver/full-chain validator via native file_extents.
; No extents are exported: cap=0, a fixed 80-byte identity map only.
fat32_disk_source_stat:
    push rbx
    push r12
    push r13
    push r14
    mov  ebx, ecx
    mov  r12, rsi
    mov  r13d, edx
    call fat32_disk_source_current
    test rax, rax
    jnz  .bad
    mov  rdi, [rel fd_src_mount]
    mov  rsi, r12
    mov  edx, r13d
    lea  rcx, [rel fd_src_map]
    xor  r8d, r8d
    call fat32_disk_file_extents
    cmp  rax, -1
    je   .bad
    call fat32_disk_source_token
    test rax, rax
    jnz  .bad
    test ebx, ebx
    jz   .check
    lea  rdi, [rel fd_src_file]
    lea  rsi, [rel fd_source_entry]
    mov  edx, 32
    call memcpy
    mov  rax, [rel fd_found_dir_lba]
    mov  [rel fd_src_file_lba], rax
    mov  eax, [rel fd_found_dir_off]
    mov  [rel fd_src_file_off], eax
    jmp  .size
.check:
    mov  rax, [rel fd_found_dir_lba]
    cmp  rax, [rel fd_src_file_lba]
    jne  .bad
    mov  eax, [rel fd_found_dir_off]
    cmp  eax, [rel fd_src_file_off]
    jne  .bad
    lea  rdi, [rel fd_src_file]
    lea  rsi, [rel fd_source_entry]
    mov  edx, 32
    call memcmp
    test rax, rax
    jnz  .bad
.size:
    mov  rax, [rel fd_src_map + fs_extent_map.size]
    jmp  .out
.bad:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; fat32_disk_source_mtime -> RAX = the bound source file's modification time as Unix UTC seconds, EDX = 0
;   (FAT keeps 2-second units); CF=1 unknown: no stamp (date 0, a field out of range), an entry
;   fat32_disk_update has tagged, or no PaOS clock zone for its local time. E2t (root 2026-10-17
;   21:04:41: FAT local time is the PaOS clock zone). After a binding fat32_disk_source_stat.
;   Clobbers RCX, RDX, RSI, R8-R11.
fat32_disk_source_mtime:
    cmp  word [rel fd_src_file + 12], FD_TX_MAGIC
    je   .unknown
    mov  eax, [rel fd_src_file + 22]
    call vfs_dos_to_unix
    test rax, rax
    jz   .unknown
    call time_local_to_utc
    jc   .unknown
    test rax, rax
    jle  .unknown                        ; a FAT date is never at or before 1970
    xor  edx, edx
    ret
.unknown:
    stc
    ret

%macro WDATA_BSS_fs_fat32_source 0
alignb 8
fd_src_mount: resq 1
fd_src_ops: resq 1
fd_src_ctx: resq 1
fd_src_info: resq 1
fd_src_gen: resq 1
fd_src_ns: resq 1
fd_src_max: resq 1
fd_src_geom: resb 80
fd_src_guids: resb 32
fd_src_volume: resd 1
fd_source_entry: resb 32
fd_src_file: resb 32
fd_src_file_lba: resq 1
fd_src_file_off: resd 1
fd_src_map: resb fs_extent_map_size
fd_src_bpb: resb 512
fd_src_bpb_saved: resb 512
%endmacro
WDATA_BSS_DEFER WDATA_BSS_fs_fat32_source

; RDI=FT_SIZE cursor, RSI=absolute Z directory, ECX=1 bind / 0 check.
; Caller retains paths; source binding remains the original tree's binding.
fat32_disk_source_dir:
    push rbx
    push r12
    push r13
    push r14
    mov  r13, rdi
    mov  r14, rsi
    mov  ebx, ecx
    call fat32_disk_source_current
    test rax, rax
    jnz  .changed
    mov  r12, [rel fd_src_ctx]
    mov  rdi, r12
    mov  rsi, r14
    call fat32_disk_resolve_path_lfn
    test rax, rax
    jnz  .changed
    test byte [rel fd_found_attr], 0x10
    jz   .unsupported
    test byte [rel fd_found_attr], 0xC8
    jnz  .unsupported
    mov  eax, [rel fd_found_cluster]
    test ebx, ebx
    jz   .check_head
    mov  [r13 + FT_HEAD], eax
    xor  eax, eax
    cmp  word [r14], 0x002F
    sete al
    mov  [r13 + FT_ROOT], eax
    test eax, eax
    jnz  .chain
    lea  rdi, [r13 + FT_ENTRY]
    lea  rsi, [rel fd_source_entry]
    mov  edx, 32
    call memcpy
    mov  rax, [rel fd_found_dir_lba]
    mov  [r13 + FT_ENTRY_LBA], rax
    mov  eax, [rel fd_found_dir_off]
    mov  [r13 + FT_ENTRY_OFF], eax
    jmp  .chain
.check_head:
    cmp  eax, [r13 + FT_HEAD]
    jne  .changed
    cmp  dword [r13 + FT_ROOT], 1
    je   .chain
    mov  rax, [rel fd_found_dir_lba]
    cmp  rax, [r13 + FT_ENTRY_LBA]
    jne  .changed
    mov  eax, [rel fd_found_dir_off]
    cmp  eax, [r13 + FT_ENTRY_OFF]
    jne  .changed
    lea  rdi, [r13 + FT_ENTRY]
    lea  rsi, [rel fd_source_entry]
    mov  edx, 32
    call memcmp
    test rax, rax
    jnz  .changed
.chain:
    mov  rdi, r12
    mov  esi, [r13 + FT_HEAD]
    call fd_validate_dir_chain
    test rax, rax
    jnz  .corrupt
    test ebx, ebx
    jz   .check_chain
    mov  [r13 + FT_COUNT], edx
    shl  edx, 2
    lea  rdi, [r13 + FT_CHAIN]
    lea  rsi, [rel fd_dir_seen]
    call memcpy
    mov  qword [r13 + FT_BLOCK], -1
    mov  qword [r13 + FT_CURSOR], 0
    mov  dword [r13 + FT_END], 0
    mov  dword [r13 + FT_HAD_LFN], 0
    mov  dword [r13 + FT_LFN_STATE], 0
    mov  word [r13 + FT_LFN_STATE + 4], 0xFFFF
    jmp  .token
.check_chain:
    cmp  edx, [r13 + FT_COUNT]
    jne  .changed
    shl  edx, 2
    lea  rdi, [r13 + FT_CHAIN]
    lea  rsi, [rel fd_dir_seen]
    call memcmp
    test rax, rax
    jnz  .changed
    cmp  qword [r13 + FT_BLOCK], -1
    je   .token
    mov  rdi, r12
    mov  rsi, [r13 + FT_BLOCK]
    mov  edx, 1
    lea  rcx, [rel fd_tree_sector]
    call fd_read_sectors
    test rax, rax
    jnz  .io
    call fd_tree_sector_hash
    cmp  rax, [r13 + FT_HASH]
    jne  .changed
.token:
    call fat32_disk_source_token
    test rax, rax
    jnz  .changed
    xor  eax, eax
    jmp  .out
.io:
    mov  dword [rel ext4_disk_last_error], FT_E_IO
    jmp  .bad
.corrupt:
    mov  dword [rel ext4_disk_last_error], FT_E_CORRUPT
    jmp  .bad
.unsupported:
    mov  dword [rel ext4_disk_last_error], FT_E_UNSUPPORTED
    jmp  .bad
.changed:
    mov  dword [rel ext4_disk_last_error], FT_E_SOURCE_CHANGED
.bad:
    call fat32_disk_source_token
    test rax, rax
    jz   .error_set
    mov  dword [rel ext4_disk_last_error], FT_E_SOURCE_CHANGED
.error_set:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; A previously consumed child must resolve to its complete original entry.
fat32_disk_source_node:               ; RDI=cursor, RSI=child Z -> 0 / -1
    push r12
    push r13
    push r14
    mov  r13, rdi
    mov  r14, rsi
    call fat32_disk_source_current
    test rax, rax
    jnz  .bad
    mov  r12, [rel fd_src_ctx]
    mov  rdi, r12
    mov  rsi, r14
    call fat32_disk_resolve_path_lfn
    test rax, rax
    jnz  .bad
    mov  rax, [rel fd_found_dir_lba]
    cmp  rax, [r13 + FT_NEXT_LBA]
    jne  .bad
    mov  eax, [rel fd_found_dir_off]
    cmp  eax, [r13 + FT_NEXT_OFF]
    jne  .bad
    lea  rdi, [r13 + FT_NEXT]
    lea  rsi, [rel fd_source_entry]
    mov  edx, 32
    call memcmp
    test rax, rax
    jnz  .bad
    call fat32_disk_source_token
    test rax, rax
    jz   .out
.bad:
    mov  dword [rel ext4_disk_last_error], FT_E_SOURCE_CHANGED
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    ret

; RDI=validated cursor -> 1 entry (RDX=complete Z name, ECX=len, R8D=head,
; R9D=attributes), 0 end, 2 yield, -1 typed refusal. At most one sector's
; sixteen entries per call; LFN units survive yields and child operations.
fat32_disk_source_next:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r13, rdi
    mov  r12, [rel fd_src_ctx]
    call fat32_disk_source_token
    test rax, rax
    jnz  .changed
    cmp  dword [r13 + FT_END], 0
    jne  .end
    mov  eax, [r13 + FT_COUNT]
    mov  ecx, [r12 + FD_CLUSTER_BYTES]
    imul rax, rcx
    shr  rax, 5
    cmp  [r13 + FT_CURSOR], rax
    jae  .end
    mov  rax, [r13 + FT_CURSOR]
    xor  edx, edx
    mov  ecx, [r12 + FD_CLUSTER_BYTES]
    shr  ecx, 5
    div  rcx
    cmp  eax, [r13 + FT_COUNT]
    jae  .corrupt
    mov  esi, [r13 + FT_CHAIN + rax*4]
    mov  r14, rdx
    mov  rdi, r12
    call fd_cluster_lba
    cmp  rax, -1
    je   .corrupt
    mov  rdx, r14
    shr  rdx, 4
    lea  rbp, [rax + rdx]
    mov  rdi, r12
    mov  rsi, rbp
    mov  edx, 1
    lea  rcx, [rel fd_tree_sector]
    call fd_read_sectors
    test rax, rax
    jnz  .io
    call fd_tree_sector_hash
    cmp  rbp, [r13 + FT_BLOCK]
    jne  .new_block
    cmp  rax, [r13 + FT_HASH]
    jne  .changed
.new_block:
    mov  [r13 + FT_BLOCK], rbp
    mov  [r13 + FT_HASH], rax
    mov  eax, [r13 + FT_LFN_STATE]
    mov  [rel fd_lfn_valid], eax
    mov  ax, [r13 + FT_LFN_STATE + 4]
    mov  [rel fd_lfn_term_pos], ax
    lea  rdi, [rel fd_lfn_utf16]
    lea  rsi, [r13 + FT_LFN_UNITS]
    mov  edx, 512
    call memcpy
    and  r14d, 15
.entry:
    mov  ebx, r14d
    shl  ebx, 5
    lea  r15, [rel fd_tree_sector]
    add  r15, rbx
    inc  qword [r13 + FT_CURSOR]
    cmp  byte [r15], 0
    je   .end_mark
    cmp  byte [r15], 0xE5
    je   .reset
    cmp  byte [r15 + 11], 0x0F
    je   .lfn
    test byte [r15 + 11], 0x08
    jnz  .reset                         ; volume label, not a filesystem child
    mov  rdi, r15
    call fd_short_is_dot
    test eax, eax
    jnz  .reset
    test byte [r15 + 11], 0xC0
    jnz  .unsupported
    cmp  word [r15 + 12], FD_TX_MAGIC
    je   .unsupported                   ; no source transaction/recovery interpretation
    cmp  dword [r13 + FT_HAD_LFN], 0
    je   .short
    mov  rdi, r15
    call fd_lfn_for_short
    cmp  eax, 1
    jne  .corrupt                       ; never substitute an alias for a failed LFN
    lea  rsi, [rel fd_lfn_name]
    jmp  .name
.short:
    mov  rdi, r15
    lea  rsi, [rel fd_lfn_name]
    call fd_short_to_name
    lea  rsi, [rel fd_lfn_name]
.name:
    xor  ecx, ecx
.name_byte:
    mov  al, [rsi + rcx]
    test al, al
    jz   .name_done
    cmp  al, 0x20
    jb   .unsupported
    cmp  al, 0x7F
    jae  .unsupported                   ; destination mutation grammar is ASCII
    cmp  al, '/'
    je   .corrupt
    inc  ecx
    cmp  ecx, FD_LFN_MAX
    jbe  .name_byte
    jmp  .unsupported
.name_done:
    test ecx, ecx
    jz   .corrupt
    mov  r14d, ecx
    lea  rdi, [rel fd_tree_name]
    mov  edx, ecx
    inc  edx
    call memcpy
    lea  rdi, [r13 + FT_NEXT]
    mov  rsi, r15
    mov  edx, 32
    call memcpy
    mov  [r13 + FT_NEXT_LBA], rbp
    mov  [r13 + FT_NEXT_OFF], ebx
    call fd_lfn_reset
    mov  dword [r13 + FT_HAD_LFN], 0
    movzx r8d, word [r15 + 20]
    shl  r8d, 16
    mov  r8w, [r15 + 26]
    movzx r9d, byte [r15 + 11]
    lea  rdx, [rel fd_tree_name]
    mov  ecx, r14d
    mov  ebx, 1
    jmp  .save
.lfn:
    mov  dword [r13 + FT_HAD_LFN], 1
    mov  rdi, r15
    call fd_lfn_collect
    test rax, rax
    jnz  .corrupt
    jmp  .advance
.reset:
    call fd_lfn_reset
    mov  dword [r13 + FT_HAD_LFN], 0
.advance:
    inc  r14d
    cmp  r14d, 16
    jb   .entry
    mov  ebx, 2
.save:
    push rcx
    push rdx
    mov  eax, [rel fd_lfn_valid]
    mov  [r13 + FT_LFN_STATE], eax
    mov  ax, [rel fd_lfn_term_pos]
    mov  [r13 + FT_LFN_STATE + 4], ax
    lea  rdi, [r13 + FT_LFN_UNITS]
    lea  rsi, [rel fd_lfn_utf16]
    mov  edx, 512
    call memcpy
    call fat32_disk_source_token
    test rax, rax
    pop  rdx
    pop  rcx
    jnz  .changed
    mov  eax, ebx
    jmp  .out
.end_mark:
    mov  dword [r13 + FT_END], 1
.end:
    cmp  dword [r13 + FT_HAD_LFN], 0
    jne  .corrupt
    xor  eax, eax
    jmp  .out
.io:
    mov  dword [rel ext4_disk_last_error], FT_E_IO
    jmp  .bad
.corrupt:
    mov  dword [rel ext4_disk_last_error], FT_E_CORRUPT
    jmp  .bad
.unsupported:
    mov  dword [rel ext4_disk_last_error], FT_E_UNSUPPORTED
    jmp  .bad
.changed:
    mov  dword [rel ext4_disk_last_error], FT_E_SOURCE_CHANGED
.bad:
    call fat32_disk_source_token
    test rax, rax
    jz   .error_set
    mov  dword [rel ext4_disk_last_error], FT_E_SOURCE_CHANGED
.error_set:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Hash all 512 bytes, including unused rows, for resumed-sector custody.
fd_tree_sector_hash:
    mov  rax, 0xCBF29CE484222325
    mov  rdx, 0x100000001B3
    xor  ecx, ecx
    push rsi
    lea  rsi, [rel fd_tree_sector]
.byte:
    xor  al, [rsi + rcx]
    imul rax, rdx
    inc  ecx
    cmp  ecx, 512
    jb   .byte
    pop  rsi
    ret

%macro WDATA_BSS_fs_fat32_tree_source 0
fd_tree_sector: resb 512
fd_tree_name: resb FD_LFN_MAX + 1
%endmacro
WDATA_BSS_DEFER WDATA_BSS_fs_fat32_tree_source

fd_kat_walk:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13d, esi
    mov  r14d, edx
    mov  r15d, ecx
    xor  ebx, ebx
    lea  rdx, [rel fd_kat_seen]
.loop:
    cmp  ebx, r14d
    jae  .fail
    cmp  r13d, 2
    jb   .fail
    cmp  r13d, r15d
    jae  .fail
    xor  ecx, ecx
.seen:
    cmp  ecx, ebx
    jae  .store
    cmp  r13d, [rdx + rcx*4]
    je   .fail
    inc  ecx
    jmp  .seen
.store:
    mov  [rdx + rbx*4], r13d
    inc  ebx
    mov  eax, [r12 + r13*4]
    and  eax, 0x0FFFFFFF
    cmp  ebx, r14d
    je   .need_eoc
    cmp  eax, 2
    jb   .fail
    cmp  eax, FD_RESERVED_MIN
    jae  .fail
    cmp  eax, r15d
    jae  .fail
    mov  r13d, eax
    jmp  .loop
.need_eoc:
    cmp  eax, FD_EOC_MIN
    jb   .fail
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

fat32_disk_kat:
    mov  byte [rel vfs_kat_fragmented], 0
    mov  byte [rel vfs_kat_cycle], 0
    mov  byte [rel vfs_kat_bounds], 0
    lea  rdi, [rel fd_kat_fragmented_fat]
    mov  esi, 3
    mov  edx, 3
    mov  ecx, 10
    call fd_kat_walk
    test rax, rax
    jnz  .fail
    mov  byte [rel vfs_kat_fragmented], 1
    lea  rdi, [rel fd_kat_cycle_fat]
    mov  esi, 3
    mov  edx, 3
    mov  ecx, 10
    call fd_kat_walk
    test rax, rax
    jz   .fail
    mov  byte [rel vfs_kat_cycle], 1
    lea  rdi, [rel fd_kat_reserved_fat]
    mov  esi, 3
    mov  edx, 2
    mov  ecx, 10
    call fd_kat_walk
    test rax, rax
    jz   .fail
    lea  rdi, [rel fd_kat_bad_fat]
    mov  esi, 3
    mov  edx, 2
    mov  ecx, 10
    call fd_kat_walk
    test rax, rax
    jz   .fail
    mov  edi, 100
    mov  esi, 95
    mov  edx, 6
    call fat32_disk_bounds_ok
    test rax, rax
    jz   .fail
    mov  edi, 100
    mov  esi, 95
    mov  edx, 5
    call fat32_disk_bounds_ok
    test rax, rax
    jnz  .fail
    mov  rdi, -1
    mov  rsi, -2
    mov  edx, 4
    call fat32_disk_bounds_ok             ; off+len overflow must reject
    test rax, rax
    jz   .fail
    mov  byte [rel vfs_kat_bounds], 1
    lea  rdi, [rel str_fd_kat]
    call serial_string
    xor  eax, eax
    ret
.fail:
    mov  rax, -1
    ret

; Sparse FAT32 fixture used only by the QEMU command KAT. Its bystander file
; chain is deliberately fragmented 3 -> 7 -> 4 and all reads still enter via
; blk_read and this backend's normal mount/stat/read/list paths.
FD_KAT_TOTAL_SECTORS equ 66552
FD_KAT_FAT_SECTORS   equ 513
FD_KAT_DATA_LBA      equ 1027
FD_KAT_FILE_SIZE     equ 1042
FD_KAT_DEEP_SIZE     equ 18
fd_kat_dirs_mode: db 0

fd_kat_identify:
    xor  eax, eax
    ret

fd_kat_fail_io:
    mov  rax, -1
    ret

fd_kat_flush:
    inc  dword [rel fd_kat_flush_count]
    xor  eax, eax
    ret

fd_kat_reset_media:
    mov  byte [rel fd_kat_dirs_mode], 0
    mov  qword [rel fd_path_cache_ctx], 0
    lea  rdi, [rel fd_kat_fat1]
    xor  esi, esi
    mov  edx, 512
    call memset
    lea  rdi, [rel fd_kat_root]
    xor  esi, esi
    mov  edx, 512
    call memset
    lea  rdi, [rel fd_kat_data5]
    xor  esi, esi
    mov  edx, 5*512
    call memset
    lea  rax, [rel fd_kat_fat1]
    mov  dword [rax + 0*4], 0x0FFFFFF8
    mov  dword [rax + 1*4], 0x0FFFFFFF
    mov  dword [rax + 2*4], 0x0FFFFFFF
    mov  dword [rax + 3*4], 7
    mov  dword [rax + 4*4], 0x0FFFFFFF
    mov  dword [rax + 7*4], 4
    lea  rdi, [rel fd_kat_fat2]
    lea  rsi, [rel fd_kat_fat1]
    mov  edx, 512
    call memcpy
    lea  rax, [rel fd_kat_root]
    mov  rdx, 'SCRATCH '
    mov  [rax], rdx
    mov  word [rax + 8], 'TX'
    mov  byte [rax + 10], 'T'
    mov  byte [rax + 11], 0x20
    mov  word [rax + 20], 0
    mov  word [rax + 26], 3
    mov  dword [rax + 28], FD_KAT_FILE_SIZE
    mov  byte [rax + 32], 0
    mov  dword [rel fd_kat_flush_count], 0
    mov  byte [rel fd_fault_point], FD_FAULT_NONE
    mov  byte [rel fd_fault_seen], FD_FAULT_NONE
    mov  byte [rel fd_kat_fail_fat2], 0
    ret

; Build one synthetic VFAT row for the sparse fixture/parser KAT.
; RDI=row, ESI=raw ordinal, EDX=logical base, RCX=name, R8D=len, R9D=checksum.
fd_kat_make_lfn_row:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push r8
    push r9
    mov  r12, rdi
    mov  r13d, esi
    mov  r14d, edx
    mov  r15, rcx
    mov  rdi, r12
    mov  esi, 0xFF
    mov  edx, 32
    call memset
    pop  r9
    pop  r8
    mov  [r12], r13b
    mov  byte [r12 + 11], 0x0F
    mov  byte [r12 + 12], 0
    mov  [r12 + 13], r9b
    mov  word [r12 + 26], 0
    xor  ebx, ebx
.unit:
    cmp  ebx, 13
    jae  .done
    lea  rdx, [rel fd_lfn_offsets]
    movzx eax, byte [rdx + rbx]
    mov  ecx, r14d
    add  ecx, ebx
    mov  edx, 0xFFFF
    cmp  ecx, r8d
    ja   .store
    je   .terminator
    movzx edx, byte [r15 + rcx]
    jmp  .store
.terminator:
    xor  edx, edx
.store:
    mov  [r12 + rax], dx
    inc  ebx
    jmp  .unit
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Parser-only vectors supplement the on-media sparse tree: max 255-byte LFN,
; mixed-case match, and checksum-corrupt fallback that can match only alias.
fat32_disk_dirs_lfn_kat:
    mov  byte [rel fd_kat_dirs_mode], 1
    lea  rdi, [rel fd_kat_ctx]
    call fd_invalidate_caches
    push rbx
    push r12
    push r13
    push r14
    push r15
    lea  rdi, [rel fd_kat_short_entry]
    xor  esi, esi
    mov  edx, 32
    call memset
    mov  rax, 'JULYSU~1'
    mov  [rel fd_kat_short_entry], rax
    mov  word [rel fd_kat_short_entry + 8], 'TX'
    mov  byte [rel fd_kat_short_entry + 10], 'T'
    mov  byte [rel fd_kat_short_entry + 11], 0x20
    lea  rdi, [rel fd_kat_short_entry]
    call fd_lfn_checksum
    mov  [rel fd_kat_checksum], al
    lea  rdi, [rel fd_kat_lfn_rows]
    mov  esi, 0x42
    mov  edx, 13
    lea  rcx, [rel fd_kat_lfn_name]
    mov  r8d, fd_kat_lfn_name.len
    movzx r9d, byte [rel fd_kat_checksum]
    call fd_kat_make_lfn_row
    lea  rdi, [rel fd_kat_lfn_rows + 32]
    mov  esi, 1
    xor  edx, edx
    lea  rcx, [rel fd_kat_lfn_name]
    mov  r8d, fd_kat_lfn_name.len
    movzx r9d, byte [rel fd_kat_checksum]
    call fd_kat_make_lfn_row
    call fd_lfn_reset
    lea  rdi, [rel fd_kat_lfn_rows]
    call fd_lfn_collect
    test rax, rax
    jnz  .fail
    lea  rdi, [rel fd_kat_lfn_rows + 32]
    call fd_lfn_collect
    test rax, rax
    jnz  .fail
    lea  rdi, [rel fd_kat_short_entry]
    lea  rsi, [rel fd_kat_lfn_mixed]
    mov  edx, fd_kat_lfn_mixed.len
    call fd_entry_match
    test eax, eax
    jz   .fail
    ; Corrupt only the LFN checksum. Long-name lookup must miss; alias survives.
    xor  byte [rel fd_kat_lfn_rows + 13], 0x5A
    call fd_lfn_reset
    lea  rdi, [rel fd_kat_lfn_rows]
    call fd_lfn_collect
    lea  rdi, [rel fd_kat_lfn_rows + 32]
    call fd_lfn_collect
    lea  rdi, [rel fd_kat_short_entry]
    lea  rsi, [rel fd_kat_lfn_name]
    mov  edx, fd_kat_lfn_name.len
    call fd_entry_match
    test eax, eax
    jnz  .fail
    lea  rdi, [rel fd_kat_short_entry]
    lea  rsi, [rel fd_kat_alias_name]
    mov  edx, fd_kat_alias_name.len
    call fd_entry_match
    test eax, eax
    jz   .fail
    ; Exact 255-character component: 20 rows, sequence 20..1.
    lea  rdi, [rel fd_kat_max_name]
    mov  al, 'M'
    mov  ecx, FD_LFN_MAX
    cld
    rep  stosb
    mov  byte [rdi], 0
    mov  rax, 'MAXNAM~1'
    mov  [rel fd_kat_short_entry], rax
    mov  word [rel fd_kat_short_entry + 8], 'BI'
    mov  byte [rel fd_kat_short_entry + 10], 'N'
    lea  rdi, [rel fd_kat_short_entry]
    call fd_lfn_checksum
    mov  [rel fd_kat_checksum], al
    call fd_lfn_reset
    mov  ebx, FD_LFN_ENTRIES_MAX
.max_row:
    lea  rdi, [rel fd_kat_lfn_rows]
    mov  esi, ebx
    cmp  ebx, FD_LFN_ENTRIES_MAX
    jne  .max_ord
    or   esi, 0x40
.max_ord:
    mov  edx, ebx
    dec  edx
    imul edx, edx, 13
    lea  rcx, [rel fd_kat_max_name]
    mov  r8d, FD_LFN_MAX
    movzx r9d, byte [rel fd_kat_checksum]
    call fd_kat_make_lfn_row
    lea  rdi, [rel fd_kat_lfn_rows]
    call fd_lfn_collect
    test rax, rax
    jnz  .fail
    dec  ebx
    jnz  .max_row
    lea  rdi, [rel fd_kat_short_entry]
    lea  rsi, [rel fd_kat_max_name]
    mov  edx, FD_LFN_MAX
    call fd_entry_match
    test eax, eax
    jz   .fail
    mov  dword [rel fd_list_names_used], 0
    lea  rdi, [rel fd_kat_short_entry]
    lea  rsi, [rel fd_kat_dirent]
    call fd_dirent_export
    test rax, rax
    jnz  .fail
    lea  rdi, [rel fd_kat_dirent]
    call vfs_dirent_name
    mov  rdi, rax
    lea  rsi, [rel fd_kat_max_name]
    mov  edx, FD_LFN_MAX
    call fd_name_ci_equal
    test eax, eax
    jz   .fail
    lea  rdi, [rel fd_kat_ctx]
    mov  esi, 20
    call fd_validate_dir_chain
    test rax, rax                        ; cyclic directory must refuse
    jz   .fail
    mov  ebx, 22
.bad_tail:
    lea  rdi, [rel fd_kat_ctx]
    mov  esi, ebx
    call fd_validate_dir_chain
    test rax, rax
    jz   .fail
    inc  ebx
    cmp  ebx, 25
    jb   .bad_tail
    lea  rdi, [rel fd_kat_ctx]
    mov  esi, 50
    call fd_validate_dir_chain           ; 65 clusters exceeds the bound
    test rax, rax
    jz   .fail
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

fd_dirs_kat_read:
    push r12
    push r13
    push r14
    mov  r12, rsi
    mov  r13, rdx
    mov  r14, rcx
    mov  rax, r12
    add  rax, r13
    jc   .fail
    cmp  rax, FD_KAT_TOTAL_SECTORS
    ja   .fail
.sector:
    test r13, r13
    jz   .ok
    mov  rdi, r14
    xor  esi, esi
    mov  edx, 512
    call memset
    cmp  r12, 0
    je   .bpb
    cmp  r12, 1 + FD_KAT_FAT_SECTORS
    je   .fat
    cmp  r12, 1
    je   .fat
    cmp  r12, FD_KAT_DATA_LBA
    je   .root
    cmp  r12, FD_KAT_DATA_LBA + 2
    je   .tail
    cmp  r12, FD_KAT_DATA_LBA + 3
    je   .documents_head
    cmp  r12, FD_KAT_DATA_LBA + 4
    je   .reports
    cmp  r12, FD_KAT_DATA_LBA + 7
    je   .documents_tail
    cmp  r12, FD_KAT_DATA_LBA + 8
    je   .deep_data
    cmp  r12, FD_KAT_DATA_LBA + 28
    jb   .not_max
    cmp  r12, FD_KAT_DATA_LBA + 35
    jbe  .max_directory
.not_max:
    cmp  r12, FD_KAT_DATA_LBA + 9
    jb   .next
    cmp  r12, FD_KAT_DATA_LBA + 12
    jbe  .many
    jmp  .next
.bpb:
    mov  word [r14 + 11], 512
    mov  byte [r14 + 13], 1
    mov  word [r14 + 14], 1
    mov  byte [r14 + 16], 2
    mov  word [r14 + 17], 0
    mov  word [r14 + 19], 0
    mov  word [r14 + 22], 0
    mov  dword [r14 + 32], FD_KAT_TOTAL_SECTORS
    mov  dword [r14 + 36], FD_KAT_FAT_SECTORS
    mov  dword [r14 + 44], 2
    mov  dword [r14 + 67], 0x24000001
    mov  dword [r14 + 82], 'FAT3'
    mov  dword [r14 + 86], '2   '
    mov  word [r14 + 510], 0xAA55
    jmp  .next
.fat:
    mov  dword [r14 + 0*4], 0x0FFFFFF8
    mov  dword [r14 + 1*4], 0x0FFFFFFF
    mov  dword [r14 + 2*4], 0x0FFFFFFF
    mov  dword [r14 + 3*4], 7
    mov  dword [r14 + 4*4], 0x0FFFFFFF
    mov  dword [r14 + 5*4], 9
    mov  dword [r14 + 6*4], 0x0FFFFFFF
    mov  dword [r14 + 7*4], 4
    mov  dword [r14 + 9*4], 0x0FFFFFFF
    mov  dword [r14 + 10*4], 0x0FFFFFFF
    mov  dword [r14 + 11*4], 12
    mov  dword [r14 + 12*4], 13
    mov  dword [r14 + 13*4], 14
    mov  dword [r14 + 14*4], 0x0FFFFFFF
    mov  dword [r14 + 20*4], 21
    mov  dword [r14 + 21*4], 20
    mov  dword [r14 + 22*4], 0x0FFFFFF0
    mov  dword [r14 + 23*4], 0x0FFFFFF7
    mov  dword [r14 + 24*4], 0
    mov  ecx, 30
.max_fat:
    lea  eax, [ecx + 1]
    mov  [r14 + rcx*4], eax
    inc  ecx
    cmp  ecx, 37
    jb   .max_fat
    mov  dword [r14 + 37*4], 0x0FFFFFFF
    mov  ecx, 50
.overlong_fat:
    lea  eax, [ecx + 1]
    mov  [r14 + rcx*4], eax
    inc  ecx
    cmp  ecx, 114
    jb   .overlong_fat
    mov  dword [r14 + 114*4], 0x0FFFFFFF
    jmp  .next
.root:
    mov  rax, 'SCRATCH '
    mov  [r14], rax
    mov  word [r14 + 8], 'TX'
    mov  byte [r14 + 10], 'T'
    mov  byte [r14 + 11], 0x20
    mov  word [r14 + 20], 0
    mov  word [r14 + 26], 3
    mov  dword [r14 + 28], FD_KAT_FILE_SIZE
    ; Valid one-row LFN Documents -> DOCUME~1 (directory cluster 5).
    mov  rax, 'DOCUME~1'
    mov  [r14 + 64], rax
    mov  word [r14 + 72], 0x2020
    mov  byte [r14 + 74], ' '
    mov  byte [r14 + 75], 0x10
    mov  word [r14 + 90], 5
    lea  rdi, [r14 + 64]
    call fd_lfn_checksum
    mov  r9d, eax
    lea  rdi, [r14 + 32]
    mov  esi, 0x41
    xor  edx, edx
    lea  rcx, [rel fd_kat_doc_name]
    mov  r8d, fd_kat_doc_name.len
    call fd_kat_make_lfn_row
    ; Two additional directory vectors: 63 visible rows and a cyclic chain.
    mov  rax, 'MANY    '
    mov  [r14 + 96], rax
    mov  word [r14 + 104], 0x2020
    mov  byte [r14 + 106], ' '
    mov  byte [r14 + 107], 0x10
    mov  word [r14 + 122], 11
    mov  rax, 'CYCLE   '
    mov  [r14 + 128], rax
    mov  word [r14 + 136], 0x2020
    mov  byte [r14 + 138], ' '
    mov  byte [r14 + 139], 0x10
    mov  word [r14 + 154], 20
    mov  rax, 'MAX     '
    mov  [r14 + 160], rax
    mov  word [r14 + 168], 0x2020
    mov  byte [r14 + 170], ' '
    mov  byte [r14 + 171], 0x10
    mov  word [r14 + 186], 30
    ; Complete but wrong-checksum LFN: only CORRUP~1.TXT may resolve.
    mov  rax, 'CORRUP~1'
    mov  [r14 + 256], rax
    mov  word [r14 + 264], 'TX'
    mov  byte [r14 + 266], 'T'
    mov  byte [r14 + 267], 0x20
    mov  word [r14 + 282], 10
    mov  dword [r14 + 284], FD_KAT_DEEP_SIZE
    lea  rdi, [r14 + 256]
    call fd_lfn_checksum
    xor  eax, 0x5A
    mov  r9d, eax
    lea  rdi, [r14 + 192]
    mov  esi, 0x42
    mov  edx, 13
    lea  rcx, [rel fd_kat_lfn_name]
    mov  r8d, fd_kat_lfn_name.len
    call fd_kat_make_lfn_row
    lea  rdi, [r14 + 224]
    mov  esi, 1
    xor  edx, edx
    lea  rcx, [rel fd_kat_lfn_name]
    mov  r8d, fd_kat_lfn_name.len
    call fd_kat_make_lfn_row
    mov  byte [r14 + 288], 0
    jmp  .next
.tail:
    lea  rsi, [rel fd_kat_file_tail]
    mov  rdi, r14
    mov  edx, fd_kat_file_tail.len
    call memcpy
    jmp  .next
.documents_head:
    ; '.' and '..' are present and must never escape into FSLS.
    mov  byte [r14], '.'
    mov  byte [r14 + 1], ' '
    mov  byte [r14 + 11], 0x10
    mov  word [r14 + 26], 5
    mov  byte [r14 + 32], '.'
    mov  byte [r14 + 33], '.'
    mov  byte [r14 + 34], ' '
    mov  byte [r14 + 43], 0x10
    mov  word [r14 + 58], 2
    mov  ecx, 2
.doc_fill:
    cmp  ecx, 16
    jae  .next
    mov  eax, ecx
    shl  eax, 5
    lea  rdi, [r14 + rax]
    mov  rax, 0x2020202020202020
    mov  [rdi], rax
    mov  word [rdi + 8], 0x2020
    mov  byte [rdi + 10], ' '
    mov  eax, ecx
    add  al, 'A'
    mov  [rdi], al
    mov  byte [rdi + 11], 0x20
    inc  ecx
    jmp  .doc_fill
.documents_tail:
    mov  rax, 'REPORTS '
    mov  [r14], rax
    mov  word [r14 + 8], 0x2020
    mov  byte [r14 + 10], ' '
    mov  byte [r14 + 11], 0x10
    mov  word [r14 + 26], 6
    mov  byte [r14 + 32], 0
    jmp  .next
.reports:
    mov  byte [r14], '.'
    mov  byte [r14 + 1], ' '
    mov  byte [r14 + 11], 0x10
    mov  word [r14 + 26], 6
    mov  byte [r14 + 32], '.'
    mov  byte [r14 + 33], '.'
    mov  byte [r14 + 34], ' '
    mov  byte [r14 + 43], 0x10
    mov  word [r14 + 58], 5
    mov  rax, 'JULYSU~1'
    mov  [r14 + 128], rax
    mov  word [r14 + 136], 'TX'
    mov  byte [r14 + 138], 'T'
    mov  byte [r14 + 139], 0x20
    mov  word [r14 + 154], 10
    mov  dword [r14 + 156], FD_KAT_DEEP_SIZE
    lea  rdi, [r14 + 128]
    call fd_lfn_checksum
    mov  r9d, eax
    lea  rdi, [r14 + 64]
    mov  esi, 0x42
    mov  edx, 13
    lea  rcx, [rel fd_kat_lfn_name]
    mov  r8d, fd_kat_lfn_name.len
    call fd_kat_make_lfn_row
    lea  rdi, [r14 + 96]
    mov  esi, 1
    xor  edx, edx
    lea  rcx, [rel fd_kat_lfn_name]
    mov  r8d, fd_kat_lfn_name.len
    ; R9D still holds the alias checksum (callee preserves it by stack).
    call fd_kat_make_lfn_row
    mov  byte [r14 + 160], 0
    jmp  .next
.deep_data:
    lea  rsi, [rel fd_kat_deep_data]
    mov  rdi, r14
    mov  edx, fd_kat_deep_data.len
    call memcpy
    jmp  .next
.max_directory:
    ; Six max-length names span eight directory clusters. Each 20-row LFN
    ; crosses sectors; the sixth name forces the bounded FSLS arena to clamp.
    push rbx
    push rbp
    push r15
    mov  rbx, r12
    sub  rbx, FD_KAT_DATA_LBA + 28
    shl  ebx, 4
    xor  ebp, ebp
.max_entry:
    cmp  ebp, 16
    jae  .max_done
    cmp  ebx, 126
    jae  .max_done
    mov  eax, ebx
    xor  edx, edx
    mov  ecx, 21
    div  ecx
    mov  r15d, edx                     ; row within this name's 21 entries
    add  al, 'M'
    mov  [rel fd_kat_max_name + 254], al
    sub  al, 'M' - '1'
    mov  [rel fd_kat_short_entry + 7], al
    mov  word [rel fd_kat_short_entry + 26], 0
    mov  dword [rel fd_kat_short_entry + 28], 0
    cmp  ebx, 21
    jae  .max_alias
    mov  word [rel fd_kat_short_entry + 26], 10
    mov  dword [rel fd_kat_short_entry + 28], FD_KAT_DEEP_SIZE
.max_alias:
    lea  rdi, [rel fd_kat_short_entry]
    call fd_lfn_checksum
    mov  r9d, eax
    mov  eax, ebp
    shl  eax, 5
    lea  rdi, [r14 + rax]
    cmp  r15d, 20
    je   .max_short
    mov  esi, 20
    sub  esi, r15d
    mov  edx, esi
    dec  edx
    imul edx, edx, 13
    test r15d, r15d
    jnz  .max_ordinal
    or   esi, 0x40
.max_ordinal:
    lea  rcx, [rel fd_kat_max_name]
    mov  r8d, FD_LFN_MAX
    call fd_kat_make_lfn_row
    jmp  .max_next
.max_short:
    lea  rsi, [rel fd_kat_short_entry]
    mov  edx, 32
    call memcpy
.max_next:
    inc  ebx
    inc  ebp
    jmp  .max_entry
.max_done:
    pop  r15
    pop  rbp
    pop  rbx
    jmp  .next
.many:
    mov  rax, r12
    sub  rax, FD_KAT_DATA_LBA + 9
    mov  edx, 16
    cmp  eax, 3
    jne  .many_count
    mov  edx, 15
.many_count:
    xor  ecx, ecx
.many_entry:
    cmp  ecx, edx
    jae  .many_done
    mov  eax, ecx
    shl  eax, 5
    lea  rdi, [r14 + rax]
    mov  rax, 'ENTRY000'
    mov  [rdi], rax
    mov  rax, r12
    sub  rax, FD_KAT_DATA_LBA + 9
    add  al, '0'
    mov  [rdi + 5], al
    mov  eax, ecx
    shr  eax, 3
    add  al, '0'
    mov  [rdi + 6], al
    mov  eax, ecx
    and  eax, 7
    add  al, '0'
    mov  [rdi + 7], al
    mov  word [rdi + 8], 'TX'
    mov  byte [rdi + 10], 'T'
    mov  byte [rdi + 11], 0x20
    inc  ecx
    jmp  .many_entry
.many_done:
    cmp  edx, 16
    je   .next
    mov  byte [r14 + 15*32], 0
.next:
    inc  r12
    add  r14, 512
    dec  r13
    jmp  .sector
.ok:
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    ret

fd_kat_read:
    cmp  byte [rel fd_kat_dirs_mode], 1
    je   fd_dirs_kat_read
    push r12
    push r13
    push r14
    mov  r12, rsi
    mov  r13, rdx
    mov  r14, rcx
    mov  rax, r12
    add  rax, r13
    jc   .fail
    cmp  rax, FD_KAT_TOTAL_SECTORS
    ja   .fail
.sector:
    test r13, r13
    jz   .ok
    mov  rdi, r14
    xor  esi, esi
    mov  edx, 512
    call memset
    cmp  r12, 0
    je   .bpb
    cmp  r12, 1
    je   .fat1
    cmp  r12, 1 + FD_KAT_FAT_SECTORS
    je   .fat2
    cmp  r12, FD_KAT_DATA_LBA
    je   .root
    cmp  r12, FD_KAT_DATA_LBA + 2
    je   .tail
    cmp  r12, FD_KAT_DATA_LBA + 3
    jb   .next
    cmp  r12, FD_KAT_DATA_LBA + 5
    je   .next                          ; cluster 7 remains the zero-filled bystander
    cmp  r12, FD_KAT_DATA_LBA + 8
    jbe  .data5
    jmp  .next
.bpb:
    mov  word [r14 + 11], 512
    mov  byte [r14 + 13], 1
    mov  word [r14 + 14], 1
    mov  byte [r14 + 16], 2
    mov  word [r14 + 17], 0
    mov  word [r14 + 19], 0
    mov  word [r14 + 22], 0
    mov  dword [r14 + 32], FD_KAT_TOTAL_SECTORS
    mov  dword [r14 + 36], FD_KAT_FAT_SECTORS
    mov  dword [r14 + 44], 2
    mov  dword [r14 + 67], 0x24000001
    mov  dword [r14 + 82], 'FAT3'
    mov  dword [r14 + 86], '2   '
    mov  word [r14 + 510], 0xAA55
    jmp  .next
.fat1:
    mov  rdi, r14
    lea  rsi, [rel fd_kat_fat1]
    mov  edx, 512
    call memcpy
    jmp  .next
.fat2:
    mov  rdi, r14
    lea  rsi, [rel fd_kat_fat2]
    mov  edx, 512
    call memcpy
    jmp  .next
.root:
    mov  rdi, r14
    lea  rsi, [rel fd_kat_root]
    mov  edx, 512
    call memcpy
    jmp  .next
.tail:
    lea  rsi, [rel fd_kat_file_tail]
    mov  rdi, r14
    mov  edx, fd_kat_file_tail.len
    call memcpy
    jmp  .next
.data5:
    mov  rdi, r14
    lea  rsi, [rel fd_kat_data5]
    mov  rax, r12
    sub  rax, FD_KAT_DATA_LBA + 3
    cmp  eax, 2
    jb   .data_index
    dec  eax                            ; pack 5,6,8,9 without a buffer for cluster 7
.data_index:
    shl  rax, 9
    add  rsi, rax
    mov  edx, 512
    call memcpy
.next:
    inc  r12
    add  r14, 512
    dec  r13
    jmp  .sector
.ok:
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    ret

fd_kat_write:
    push r12
    push r13
    push r14
    mov  r12, rsi
    mov  r13, rdx
    mov  r14, rcx
    cmp  r13, 1
    jne  .fail
    cmp  r12, 1
    je   .fat1
    cmp  r12, 1 + FD_KAT_FAT_SECTORS
    je   .fat2
    cmp  r12, FD_KAT_DATA_LBA
    je   .root
    cmp  r12, FD_KAT_DATA_LBA + 3
    jb   .fail
    cmp  r12, FD_KAT_DATA_LBA + 5         ; fragmented bystander's middle cluster
    je   .fail
    cmp  r12, FD_KAT_DATA_LBA + 8
    jbe  .data5
    jmp  .fail
.fat1:
    cmp  byte [rel fd_tx_kat_active], 1
    jne  .fat1_copy
    call fd_tx_kat_fat_watch
    test rax, rax
    jnz  .fail
.fat1_copy:
    lea  rdi, [rel fd_kat_fat1]
    jmp  .copy
.fat2:
    cmp  byte [rel fd_kat_fail_fat2], 0
    je   .fat2_ready
    dec  byte [rel fd_kat_fail_fat2]
    jmp  .fail
.fat2_ready:
    lea  rdi, [rel fd_kat_fat2]
    jmp  .copy
.root:
    cmp  byte [rel fd_tx_kat_active], 1
    jne  .root_order
    call fd_tx_kat_watch
    test rax, rax
    jnz  .fail
.root_order:
    ; Check ordering at the consuming block callback, not just total flushes.
    ; A fresh name cannot become visible until its data/FAT barrier completed.
    cmp  byte [r14 + 32], 'F'
    jne  .root_delete
    cmp  dword [rel fd_kat_flush_count], 1
    jb   .fail
    jmp  .root_ready
.root_delete:
    cmp  dword [rel fd_kat_flush_count], 2
    jb   .fail
.root_ready:
    lea  rdi, [rel fd_kat_root]
    jmp  .copy
.data5:
    cmp  byte [rel fd_dirs_write_active], 1
    jne  .data_ready
    cmp  byte [rel fd_tx_kat_active], 1
    jne  .data_ready
    cmp  r12, FD_KAT_DATA_LBA + 3
    jne  .data_ready
    call fd_tx_kat_watch
    test rax, rax
    jnz  .fail
.data_ready:
    lea  rdi, [rel fd_kat_data5]
    mov  rax, r12
    sub  rax, FD_KAT_DATA_LBA + 3
    cmp  eax, 2
    jb   .data_index
    dec  eax
.data_index:
    shl  rax, 9
    add  rdi, rax
.copy:
    mov  rsi, r14
    mov  edx, 512
    call memcpy
    cmp  r12, 1
    jne  .ok
    cmp  byte [rel fd_fault_point], FD_FAULT_FAT1
    jne  .ok
    mov  byte [rel fd_fault_seen], FD_FAULT_FAT1 ; injected at actual FAT1 completion
.ok:
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    ret

; Consuming block callback asserts the 11-byte commit did not rewrite the
; entry's attributes, transaction record, cluster, or size. Its old FAT head
; must still be allocated at the instant the new name reaches the device.
fd_tx_kat_watch:
    push rbx
    push r12
    push r13
    xor  ebx, ebx
.slot:
    lea  r12, [rel fd_kat_root]
    cmp  byte [rel fd_dirs_write_active], 1
    jne  .watch_root
    lea  r12, [rel fd_kat_data5]
.watch_root:
    add  r12, rbx
    lea  r13, [r14 + rbx]
    cmp  word [r12 + 12], FD_TX_MAGIC
    jne  .next
    mov  rdi, r12
    lea  rsi, [rel fd_tx_temp]
    mov  edx, 11
    call memcmp
    test rax, rax
    jnz  .next
    cmp  byte [r13], 'F'
    jne  .next
    lea  rdi, [r12 + 11]
    lea  rsi, [r13 + 11]
    mov  edx, 21
    call memcmp
    test rax, rax
    jnz  .fail
    lea  rdx, [rel fd_kat_fat1]
    mov  eax, [rel fd_tx_kat_old_head]
    cmp  dword [rdx + rax*4], 0
    je   .fail
    mov  byte [rel fd_tx_commit_seen], 1
    mov  eax, [rel fd_kat_flush_count]
    mov  [rel fd_tx_commit_flush], eax
.next:
    add  ebx, 32
    cmp  ebx, 512
    jb   .slot
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

fd_tx_kat_fat_watch:
    lea  rdx, [rel fd_kat_fat1]
    mov  eax, [rel fd_tx_kat_old_head]
    mov  ecx, [rdx + rax*4]
    cmp  ecx, [r14 + rax*4]
    jne  .changed
    mov  eax, [rel fd_tx_kat_old_tail]
    mov  ecx, [rdx + rax*4]
    cmp  ecx, [r14 + rax*4]
    je   .ok
.changed:
    cmp  byte [rel fd_tx_commit_seen], 1
    jne  .fail
    mov  eax, [rel fd_kat_flush_count]
    cmp  eax, [rel fd_tx_commit_flush]
    jbe  .fail                          ; no old FAT mutation before commit flush
.ok:
    xor  eax, eax
    ret
.fail:
    mov  rax, -1
    ret

; Four pre-commit cuts plus the durable duplicate-name window. Every case
; starts with a TWO-cluster old file, attempts a different two-cluster payload,
; remounts, checks every byte through VFS, and drives bounded recovery passes.
; This models software crash cuts at barriers, not a mid-sector power tear.
; Replay all four pre-commit cuts AND the committed duplicate window through
; the path seam. The consuming blk callback checks the 11-byte-only commit and
; old FAT lifetime, using the subdirectory sector rather than the root sector.
fat32_disk_dirs_write_kat:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, edi
    mov  r14d, 1
.cut:
    mov  byte [rel fd_tx_kat_active], 0
    mov  byte [rel fd_tx_fault], 0
    call fd_kat_reset_media
    mov  byte [rel fd_kat_write_mode], 1
    mov  byte [rel fd_dirs_write_active], 1
    lea  rdi, [rel fd_kat_ctx]
    call fat32_disk_mount_ctx
    test rax, rax
    jnz  .fail
    lea  rsi, [rel fd_dw_denied]
    mov  r8d, FS_MUT_MKDIR
    call .mutate
    cmp  rax, -1
    jne  .fail
    cmp  dword [rel fat32_disk_last_error], FD_ERR_ALLOWLIST
    jne  .fail
    cmp  dword [rel fd_kat_flush_count], 0
    jne  .fail
    lea  rsi, [rel fd_dw_dir]
    mov  r8d, FS_MUT_MKDIR
    call .mutate
    test rax, rax
    jnz  .fail
    ; Independently inspect the block fixture: correct parent pointer, mirror,
    ; and zero-filled unused directory bytes, not just mkdir's return code.
    cmp  word [rel fd_kat_data5], '. '
    jne  .fail
    cmp  word [rel fd_kat_data5 + 32], '..'
    jne  .fail
    cmp  byte [rel fd_kat_data5 + 11], 0x10
    jne  .fail
    cmp  byte [rel fd_kat_data5 + 43], 0x10
    jne  .fail
    cmp  word [rel fd_kat_data5 + 26], 5
    jne  .fail
    cmp  word [rel fd_kat_data5 + 58], 0
    jne  .fail
    lea  rdi, [rel fd_kat_data5 + 64]
    mov  ecx, 448
.zero:
    cmp  byte [rdi], 0
    jne  .fail
    inc  rdi
    loop .zero
    lea  rsi, [rel fd_dw_nested]
    mov  r8d, FS_MUT_MKDIR
    call .mutate
    test rax, rax
    jnz  .fail
    cmp  word [rel fd_kat_data5 + 512 + 26], 6
    jne  .fail
    cmp  word [rel fd_kat_data5 + 512 + 58], 5
    jne  .fail
    lea  rsi, [rel fd_dw_nested]
    mov  r8d, FS_MUT_RMDIR
    call .mutate
    test rax, rax
    jnz  .fail
    ; Coexist with a valid LFN bystander backed by the existing fragmented file.
    lea  rdi, [rel fd_dw_alias]
    call fd_lfn_checksum
    movzx r13d, al
    lea  rdi, [rel fd_kat_data5 + 64]
    mov  esi, 0x42
    mov  edx, 13
    lea  rcx, [rel fd_kat_lfn_name]
    mov  r8d, fd_kat_lfn_name.len
    mov  r9d, r13d
    call fd_kat_make_lfn_row
    lea  rdi, [rel fd_kat_data5 + 96]
    mov  esi, 1
    xor  edx, edx
    lea  rcx, [rel fd_kat_lfn_name]
    mov  r8d, fd_kat_lfn_name.len
    mov  r9d, r13d
    call fd_kat_make_lfn_row
    lea  rdi, [rel fd_kat_data5 + 128]
    lea  rsi, [rel fd_kat_root]
    mov  edx, 32
    call memcpy
    lea  rdi, [rel fd_kat_data5 + 128]
    lea  rsi, [rel fd_dw_alias]
    mov  edx, 11
    call memcpy
    lea  rsi, [rel fd_dw_file]
    lea  rdx, [rel fd_kat_create_payload]
    mov  ecx, fd_kat_create_payload.len
    mov  r8d, FS_MUT_CREATE
    call .mutate
    cmp  rax, -1
    je   .fail
    lea  rdi, [rel fd_kat_tx_payload]
    mov  esi, 0x31
    mov  edx, 513
    call memset
    lea  rsi, [rel fd_dw_file]
    mov  r8d, FS_MUT_UPDATE
    call .update
    test rax, rax
    jnz  .fail
    ; Capture the live old pair from the actual path lookup for the block watch.
    lea  rdi, [rel fd_kat_ctx]
    lea  rsi, [rel fd_dw_file]
    call fat32_disk_resolve_path_lfn
    test rax, rax
    jnz  .fail
    mov  eax, [rel fd_found_cluster]
    mov  [rel fd_tx_kat_old_head], eax
    lea  rdx, [rel fd_kat_fat1]
    mov  eax, [rdx + rax*4]
    mov  [rel fd_tx_kat_old_tail], eax
    lea  rdi, [rel fd_kat_tx_payload]
    mov  esi, 0x72
    mov  edx, 513
    call memset
    mov  byte [rel fd_tx_kat_active], 1
    mov  byte [rel fd_tx_commit_seen], 0
    mov  byte [rel fd_tx_fault_seen], 0
    mov  [rel fd_tx_fault], r14b
    lea  rsi, [rel fd_dw_file]
    mov  r8d, FS_MUT_UPDATE
    call .update
    cmp  rax, -1
    jne  .fail
    cmp  [rel fd_tx_fault_seen], r14b
    jne  .fail
    mov  byte [rel fd_tx_fault], 0
    mov  r15d, 0x31
    cmp  r14d, 5
    jne  .precommit
    cmp  byte [rel fd_tx_commit_seen], 1
    jne  .fail
    mov  r15d, 0x72
    jmp  .remount
.precommit:
    cmp  byte [rel fd_tx_commit_seen], 0
    jne  .fail
.remount:
    lea  rdi, [rel fd_kat_ctx]
    call fat32_disk_mount_ctx
    test rax, rax
    jnz  .fail
    call .read_winner
    test rax, rax
    jnz  .fail
    ; A same-name rename refuses, but first recovers this parent after remount.
    lea  rsi, [rel fd_dw_file]
    mov  rdx, rsi
    mov  r8d, FS_MUT_RENAME
    call .mutate
    cmp  rax, -1
    jne  .fail
    cmp  dword [rel fat32_disk_last_error], FD_ERR_EXISTS
    jne  .fail
    call .read_winner
    test rax, rax
    jnz  .fail
    mov  byte [rel fd_tx_kat_active], 0
    lea  rdi, [rel fd_kat_fat1]
    lea  rsi, [rel fd_kat_fat2]
    mov  edx, 512
    call memcmp
    test rax, rax
    jnz  .fail
    xor  ebx, ebx
    lea  rdx, [rel fd_kat_fat1]
    mov  ecx, 6
.allocated:
    cmp  ecx, 7
    je   .skip_bystander
    cmp  dword [rdx + rcx*4], 0
    je   .skip_bystander
    inc  ebx
.skip_bystander:
    inc  ecx
    cmp  ecx, 10
    jbe  .allocated
    cmp  ebx, 2
    jne  .fail
    ; Read the LFN sibling after all mutations through the production path.
    mov  edi, r12d
    lea  rsi, [rel fd_dw_lfn]
    mov  edx, fd_dw_lfn.len
    mov  ecx, 1024
    lea  r8, [rel fd_verify_buf]
    mov  r9d, fd_kat_file_tail.len
    call vfs_read_at_path
    cmp  rax, fd_kat_file_tail.len
    jne  .fail
    lea  rdi, [rel fd_verify_buf]
    lea  rsi, [rel fd_kat_file_tail]
    mov  edx, fd_kat_file_tail.len
    call memcmp
    test rax, rax
    jnz  .fail
    lea  rsi, [rel fd_dw_dir]
    mov  r8d, FS_MUT_RMDIR
    call .mutate
    cmp  rax, -1
    jne  .fail
    cmp  dword [rel fat32_disk_last_error], FD_ERR_NOT_EMPTY
    jne  .fail
    lea  rsi, [rel fd_dw_file]
    mov  r8d, FS_MUT_RMDIR
    call .mutate
    cmp  rax, -1
    jne  .fail
    cmp  dword [rel fat32_disk_last_error], FD_ERR_NOT_DIR
    jne  .fail
    lea  rsi, [rel fd_dw_file]
    lea  rdx, [rel fd_dw_cross]
    mov  r8d, FS_MUT_RENAME
    call .mutate
    cmp  rax, -1
    jne  .fail
    cmp  dword [rel fat32_disk_last_error], FD_ERR_CROSS_DIR
    jne  .fail
    lea  rsi, [rel fd_dw_file]
    lea  rdx, [rel fd_dw_renamed]
    mov  r8d, FS_MUT_RENAME
    call .mutate
    test rax, rax
    jnz  .fail
    lea  rsi, [rel fd_dw_renamed]
    mov  r8d, FS_MUT_DELETE
    call .mutate
    test rax, rax
    jnz  .fail
    ; Remove only synthetic LFN rows; the bystander's shared chain is untouched.
    mov  byte [rel fd_kat_data5 + 64], 0xE5
    mov  byte [rel fd_kat_data5 + 96], 0xE5
    mov  byte [rel fd_kat_data5 + 128], 0xE5
    ; A second-cluster live row must refuse even when cluster one has 0x00.
    mov  dword [rel fd_kat_fat1 + 5*4], 6
    mov  dword [rel fd_kat_fat2 + 5*4], 6
    mov  dword [rel fd_kat_fat1 + 6*4], 0x0FFFFFFF
    mov  dword [rel fd_kat_fat2 + 6*4], 0x0FFFFFFF
    lea  rdi, [rel fd_kat_data5 + 512]
    xor  esi, esi
    mov  edx, 512
    call memset
    mov  byte [rel fd_kat_data5 + 512 + 480], 'X'
    lea  rsi, [rel fd_dw_dir]
    mov  r8d, FS_MUT_RMDIR
    call .mutate
    cmp  rax, -1
    jne  .fail
    cmp  dword [rel fat32_disk_last_error], FD_ERR_NOT_EMPTY
    jne  .fail
    mov  byte [rel fd_kat_data5 + 512 + 480], 0xE5
    lea  rsi, [rel fd_dw_dir]
    mov  r8d, FS_MUT_RMDIR
    call .mutate
    test rax, rax
    jnz  .fail
    cmp  dword [rel fd_kat_fat1 + 5*4], 0
    jne  .fail
    cmp  dword [rel fd_kat_fat2 + 5*4], 0
    jne  .fail
    cmp  dword [rel fd_kat_fat1 + 6*4], 0
    jne  .fail
    cmp  dword [rel fd_kat_fat2 + 6*4], 0
    jne  .fail
    lea  rdi, [rel fd_kat_ctx]
    lea  rsi, [rel fd_dw_dir]
    call fat32_disk_resolve_path_lfn
    test rax, rax
    jz   .fail
    inc  r14d
    cmp  r14d, 5
    jbe  .cut
    lea  rdi, [rel str_fd_dirs_write_kat]
    call serial_string
    xor  eax, eax
    jmp  .out
.update:
    lea  rdx, [rel fd_kat_tx_payload]
    mov  ecx, 513
.mutate:
    mov  edi, r12d
    jmp  vfs_mutate_path
.read_winner:
    mov  edi, r12d
    lea  rsi, [rel fd_dw_file]
    mov  edx, fd_dw_file.len
    xor  ecx, ecx
    lea  r8, [rel fd_fat_scan1]
    mov  r9d, 513
    call vfs_read_at_path
    cmp  rax, 513
    jne  .read_fail
    lea  rdi, [rel fd_fat_scan1]
    mov  ecx, 513
.byte:
    cmp  [rdi], r15b
    jne  .read_fail
    inc  rdi
    loop .byte
    xor  eax, eax
    ret
.read_fail:
    mov  rax, -1
    ret
.fail:
    lea  rdi, [rel str_fd_dirs_write_fail]
    call serial_string
    mov  rdi, r14
    call serial_hex64
    call serial_newline
    mov  rax, -1
.out:
    mov  byte [rel fd_tx_fault], 0
    mov  byte [rel fd_tx_kat_active], 0
    mov  byte [rel fd_dirs_write_active], 0
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

fd_dirs_write_active: db 0
fd_dw_dir: db "/FSWDIR1",0
fd_dw_denied: db "/PAOS.CFG",0
fd_dw_nested: db "/FSWDIR1/SUBDIR",0
fd_dw_file: db "/FSWDIR1/FILE.BIN",0
.len equ $ - fd_dw_file - 1
fd_dw_lfn: db "/FSWDIR1/July summary.txt",0
.len equ $ - fd_dw_lfn - 1
fd_dw_alias: db "JULYSU~1TXT"
fd_dw_cross: db "/FSW2.TST",0
fd_dw_renamed: db "/FSWDIR1/RENAMED.TST",0
str_fd_dirs_write_kat: db "[PAOS64] P6 fs: directory-write KAT PASS (fault matrix inside subdir, rmdir refusals) [fs.dirs.write.kat]",13,10,0
str_fd_dirs_write_fail: db "[PAOS64] P6 fs: directory-write KAT FAIL cut=",0

fat32_disk_txn_kat:
    push rbx
    push r12
    push r13
    push r14
    push r15
    xor  r14d, r14d
    mov  r12d, edi
    call vfs_mount_ptr
    test rax, rax
    jz   .fail
    lea  rdx, [rel fd_kat_ctx]
    cmp  [rax + fsmount.priv], rdx
    jne  .fail
    mov  r14d, 1
.cut:
    mov  byte [rel fd_tx_kat_active], 0
    mov  byte [rel fd_tx_fault], 0
    call fd_kat_reset_media
    mov  byte [rel fd_kat_write_mode], 1
    lea  rdi, [rel fd_kat_ctx]
    call fat32_disk_mount_ctx
    test rax, rax
    jnz  .fail
    mov  edi, r12d
    lea  rsi, [rel fd_kat_create_name]
    lea  rdx, [rel fd_kat_create_payload]
    mov  ecx, fd_kat_create_payload.len
    call vfs_writefile
    cmp  rax, -1
    je   .fail
    lea  rdi, [rel fd_kat_tx_payload]
    mov  esi, 0x31
    mov  edx, 513
    call memset
    mov  edi, r12d
    lea  rsi, [rel fd_kat_create_name]
    lea  rdx, [rel fd_kat_tx_payload]
    mov  ecx, 513
    call vfs_update
    test rax, rax
    jnz  .fail
    ; Exercise both directory orders: odd cases place the old entry before
    ; the reusable slot, even cases retain the hole before the old entry.
    test r14d, 1
    jz   .order_ready
    lea  rdi, [rel fd_kat_root + 32]
    lea  rsi, [rel fd_kat_root + 64]
    mov  edx, 32
    call memcpy
    mov  byte [rel fd_kat_root + 64], 0
.order_ready:
    lea  rdi, [rel fd_kat_ctx]
    call fd_invalidate_caches
    lea  rdi, [rel fd_kat_ctx]
    lea  rsi, [rel fd_kat_create_name]
    call fd_lookup
    test rax, rax
    jnz  .fail
    mov  eax, [rel fd_found_cluster]
    mov  [rel fd_tx_kat_old_head], eax
    lea  rdx, [rel fd_kat_fat1]
    mov  eax, [rdx + rax*4]
    mov  [rel fd_tx_kat_old_tail], eax
    lea  rdi, [rel fd_kat_tx_payload]
    mov  esi, 0x72
    mov  edx, 513
    call memset
    mov  byte [rel fd_tx_kat_active], 1
    mov  byte [rel fd_tx_commit_seen], 0
    mov  byte [rel fd_tx_fault_seen], 0
    mov  [rel fd_tx_fault], r14b
    mov  edi, r12d
    lea  rsi, [rel fd_kat_create_name]
    lea  rdx, [rel fd_kat_tx_payload]
    mov  ecx, 513
    call vfs_update
    cmp  rax, -1
    jne  .fail
    cmp  [rel fd_tx_fault_seen], r14b
    jne  .fail                           ; no earlier refusal can masquerade as the cut
    mov  byte [rel fd_tx_fault], 0
    mov  r15d, 0x31
    cmp  r14d, 5
    jne  .precommit
    cmp  byte [rel fd_tx_commit_seen], 1
    jne  .fail
    mov  r15d, 0x72                      ; committed new name wins before cleanup
    jmp  .remount
.precommit:
    cmp  byte [rel fd_tx_commit_seen], 0
    jne  .fail
.remount:
    lea  rdi, [rel fd_kat_ctx]
    call fat32_disk_mount_ctx
    test rax, rax
    jnz  .fail
    call .read_winner
    test rax, rax
    jnz  .fail
    mov  ebx, 4                          ; one-sector fixture: record + end scan
.sweep:
    lea  rdi, [rel fd_kat_ctx]
    call fd_sweep_step
    test rax, rax
    jnz  .fail
    cmp  dword [rel fd_kat_ctx + FD_SWEEP_DONE], 1
    je   .swept
    dec  ebx
    jnz  .sweep
    jmp  .fail
.swept:
    cmp  qword [rel fd_kat_ctx + FD_ORPHANS], 1
    jne  .fail
    call .read_winner
    test rax, rax
    jnz  .fail
    lea  rdi, [rel fd_kat_fat1]
    lea  rsi, [rel fd_kat_fat2]
    mov  edx, 512
    call memcmp
    test rax, rax
    jnz  .fail
    ; Exactly the winning pair remains allocated; no reservation leaked.
    xor  ebx, ebx
    lea  rdx, [rel fd_kat_fat1]
    cmp  dword [rdx + 5*4], 0
    setne al
    movzx eax, al
    add  ebx, eax
    cmp  dword [rdx + 6*4], 0
    setne al
    movzx eax, al
    add  ebx, eax
    cmp  dword [rdx + 8*4], 0
    setne al
    movzx eax, al
    add  ebx, eax
    cmp  dword [rdx + 9*4], 0
    setne al
    movzx eax, al
    add  ebx, eax
    cmp  ebx, 2
    jne  .fail
    mov  edi, r12d
    lea  rsi, [rel fd_kat_bystander_name]
    mov  edx, 1024
    lea  rcx, [rel fd_verify_buf]
    mov  r8d, fd_kat_file_tail.len
    call vfs_read_at
    cmp  rax, fd_kat_file_tail.len
    jne  .fail
    lea  rdi, [rel fd_verify_buf]
    lea  rsi, [rel fd_kat_file_tail]
    mov  edx, fd_kat_file_tail.len
    call memcmp
    test rax, rax
    jnz  .fail
    inc  r14d
    cmp  r14d, 5
    jbe  .cut
    mov  byte [rel fd_tx_kat_active], 0
    ; An in-flight writer refuses without touching the existing version.
    mov  dword [rel fd_kat_ctx + FD_TX_BUSY], 1
    mov  edi, r12d
    lea  rsi, [rel fd_kat_create_name]
    lea  rdx, [rel fd_kat_tx_payload]
    mov  ecx, 513
    call vfs_update
    mov  dword [rel fd_kat_ctx + FD_TX_BUSY], 0
    cmp  rax, -1
    jne  .fail
    cmp  dword [rel fat32_disk_last_error], FD_ERR_BUSY
    jne  .fail
    mov  edi, r12d
    lea  rsi, [rel fd_kat_tx_name]
    lea  rdx, [rel fd_kat_create_payload]
    mov  ecx, fd_kat_create_payload.len
    call vfs_writefile
    cmp  rax, -1
    je   .fail
    mov  edi, r12d
    lea  rsi, [rel fd_kat_create_name]
    lea  rdx, [rel fd_kat_tx_name]
    call vfs_rename
    cmp  rax, -1
    jne  .fail
    cmp  dword [rel fat32_disk_last_error], FD_ERR_EXISTS
    jne  .fail
    call .read_winner
    test rax, rax
    jnz  .fail
    mov  edi, r12d
    lea  rsi, [rel fd_kat_tx_name]
    call vfs_delete
    test rax, rax
    jnz  .fail
    mov  edi, r12d
    lea  rsi, [rel fd_kat_create_name]
    lea  rdx, [rel fd_kat_tx_name]
    call vfs_rename
    test rax, rax
    jnz  .fail
    lea  rdi, [rel fd_kat_ctx]
    lea  rsi, [rel fd_kat_create_name]
    call fd_lookup
    test rax, rax
    jz   .fail
    cmp  dword [rel fat32_disk_last_error], FD_ERR_NOT_FOUND
    jne  .fail
    mov  edi, r12d
    lea  rsi, [rel fd_kat_tx_name]
    xor  edx, edx
    lea  rcx, [rel fd_fat_scan1]
    mov  r8d, 513
    call vfs_read_at
    cmp  rax, 513
    jne  .fail
    lea  rdi, [rel fd_fat_scan1]
    lea  rsi, [rel fd_kat_tx_payload]
    mov  edx, 513
    call memcmp
    test rax, rax
    jnz  .fail
    mov  edi, r12d
    lea  rsi, [rel fd_kat_tx_name]
    call vfs_delete
    test rax, rax
    jnz  .fail
    lea  rdi, [rel str_fd_tx_kat]
    call serial_string
    xor  eax, eax
    jmp  .out
.read_winner:
    mov  edi, r12d
    lea  rsi, [rel fd_kat_create_name]
    xor  edx, edx
    lea  rcx, [rel fd_fat_scan1]
    mov  r8d, 513
    call vfs_read_at
    cmp  rax, 513
    jne  .read_fail
    lea  rdi, [rel fd_fat_scan2]
    mov  esi, r15d
    mov  edx, 513
    call memset
    lea  rdi, [rel fd_fat_scan1]
    lea  rsi, [rel fd_fat_scan2]
    mov  edx, 513
    jmp  memcmp
.read_fail:
    mov  rax, -1
    ret
.fail:
    lea  rdi, [rel str_fd_tx_kat_fail]
    call serial_string
    mov  rdi, r14
    call serial_hex64
    call serial_newline
    mov  rax, -1
.out:
    mov  byte [rel fd_tx_fault], 0
    mov  byte [rel fd_tx_kat_active], 0
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Writable sparse-image KAT.  Each injected create is remounted and checked for
; an absent name plus byte-identical FAT mirrors; the final non-injected pass is
; content-read-back verified and deleted through the same VFS slots.
fat32_disk_create_kat:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, edi
    call vfs_mount_ptr
    test rax, rax
    jz   .fail
    mov  r13, rax
    lea  rdx, [rel fd_kat_ctx]
    cmp  [r13 + fsmount.priv], rdx
    jne  .fail
    ; The live probe uses numbered names. Exercise the path conversion seam
    ; too: a name11-only KAT would miss a digit rejected before its digit check.
    lea  rdi, [rel fd_kat_create_path]
    mov  esi, fd_kat_create_path.len
    call vfs_path_to_name11
    test rax, rax
    jnz  .fail
    lea  rdi, [rel vfs_path_name]
    lea  rsi, [rel fd_kat_create_name]
    mov  edx, 11
    call memcmp
    test rax, rax
    jnz  .fail
    mov  r14d, FD_FAULT_ALLOC
.fault:
    call fd_kat_reset_media
    mov  byte [rel fd_kat_write_mode], 1
    lea  rdi, [rel fd_kat_ctx]
    call fat32_disk_mount_ctx
    test rax, rax
    jnz  .fail
    mov  [rel fd_fault_point], r14b
    mov  edi, r12d
    lea  rsi, [rel fd_kat_create_name]
    lea  rdx, [rel fd_kat_create_payload]
    mov  ecx, fd_kat_create_payload.len
    call vfs_writefile
    cmp  rax, -1
    jne  .fail
    cmp  r14d, FD_FAULT_FAT1
    jne  .fault_observed
    cmp  byte [rel fd_fault_seen], FD_FAULT_FAT1
    jne  .fail
.fault_observed:
    mov  byte [rel fd_fault_point], FD_FAULT_NONE
    mov  byte [rel fd_fault_seen], FD_FAULT_NONE
    ; A remount is a cache boundary even if the context was previously live.
    mov  qword [rel fd_kat_ctx + FD_FAT_CACHE_LBA], 1
    mov  byte [rel fd_kat_ctx + FD_LOOKUP_VALID], 1
    mov  dword [rel fd_kat_ctx + FD_CACHE_START], 5
    mov  dword [rel fd_kat_ctx + FD_VALID_START], 5
    lea  rdi, [rel fd_kat_ctx]
    call fat32_disk_mount_ctx                 ; volume still validates
    test rax, rax
    jnz  .fail
    cmp  qword [rel fd_kat_ctx + FD_FAT_CACHE_LBA], -1
    jne  .fail
    cmp  byte [rel fd_kat_ctx + FD_LOOKUP_VALID], 0
    jne  .fail
    cmp  dword [rel fd_kat_ctx + FD_CACHE_START], 0
    jne  .fail
    cmp  dword [rel fd_kat_ctx + FD_VALID_START], 0
    jne  .fail
    lea  rdi, [rel fd_kat_fat1]
    lea  rsi, [rel fd_kat_fat2]
    mov  edx, 512
    call memcmp
    test rax, rax
    jnz  .fail
    lea  rdi, [rel fd_kat_ctx]
    lea  rsi, [rel fd_kat_create_name]
    call fd_lookup
    test rax, rax
    jz   .fail                               ; pre-commit name must be absent
    ; Prove the existing fragmented bystander still validates and delivers
    ; its known tail through production VFS reads after every fault cut.
    mov  edi, r12d
    lea  rsi, [rel fd_kat_bystander_name]
    mov  edx, 1024
    lea  rcx, [rel fd_verify_buf]
    mov  r8d, fd_kat_file_tail.len
    call vfs_read_at
    cmp  rax, fd_kat_file_tail.len
    jne  .fail
    lea  rdi, [rel fd_verify_buf]
    lea  rsi, [rel fd_kat_file_tail]
    mov  edx, fd_kat_file_tail.len
    call memcmp
    test rax, rax
    jnz  .fail
    inc  r14d
    cmp  r14d, FD_FAULT_FAT1
    jbe  .fault

    ; Exhaust FAT2's three write retries after FAT1 changes. The shared
    ; choke point must restore the original mirrors before reporting failure.
    call fd_kat_reset_media
    mov  byte [rel fd_kat_write_mode], 1
    lea  rdi, [rel fd_kat_ctx]
    call fat32_disk_mount_ctx
    test rax, rax
    jnz  .fail
    mov  byte [rel fd_kat_fail_fat2], 3
    mov  edi, r12d
    lea  rsi, [rel fd_kat_create_name]
    lea  rdx, [rel fd_kat_create_payload]
    mov  ecx, fd_kat_create_payload.len
    call vfs_writefile
    cmp  rax, -1
    jne  .fail
    cmp  byte [rel fd_kat_fail_fat2], 0
    jne  .fail
    lea  rdi, [rel fd_kat_ctx]
    call fat32_disk_mount_ctx
    test rax, rax
    jnz  .fail
    lea  rdi, [rel fd_kat_fat1]
    lea  rsi, [rel fd_kat_fat2]
    mov  edx, 512
    call memcmp
    test rax, rax
    jnz  .fail
    cmp  dword [rel fd_kat_fat1 + 5*4], 0
    jne  .fail
    cmp  byte [rel fd_kat_root + 32], 0
    jne  .fail

    call fd_kat_reset_media
    mov  byte [rel fd_kat_write_mode], 1
    lea  rdi, [rel fd_kat_ctx]
    call fat32_disk_mount_ctx
    test rax, rax
    jnz  .fail
    mov  edi, r12d
    lea  rsi, [rel fd_kat_create_name]
    lea  rdx, [rel fd_kat_create_payload]
    mov  ecx, fd_kat_create_payload.len
    call vfs_writefile
    cmp  rax, -1
    je   .fail
    ; Duplicate and protected-name refusals must leave the created bytes intact.
    mov  edi, r12d
    lea  rsi, [rel fd_kat_create_name]
    lea  rdx, [rel fd_kat_create_payload]
    mov  ecx, fd_kat_create_payload.len
    call vfs_writefile
    cmp  rax, -1
    jne  .fail
    cmp  dword [rel fat32_disk_last_error], FD_ERR_EXISTS
    jne  .fail
    mov  edi, r12d
    lea  rsi, [rel fd_marker_name]
    call vfs_delete
    cmp  rax, -1
    jne  .fail
    cmp  dword [rel fat32_disk_last_error], FD_ERR_ALLOWLIST
    jne  .fail
    mov  edi, r12d
    lea  rsi, [rel fd_kat_create_name]
    xor  edx, edx
    lea  rcx, [rel fd_kat_create_readback]
    mov  r8d, fd_kat_create_payload.len
    call vfs_read_at
    cmp  rax, fd_kat_create_payload.len
    jne  .fail
    lea  rdi, [rel fd_kat_create_readback]
    lea  rsi, [rel fd_kat_create_payload]
    mov  edx, fd_kat_create_payload.len
    call memcmp
    test rax, rax
    jnz  .fail
    mov  edi, r12d
    lea  rsi, [rel fd_kat_create_name]
    call vfs_delete
    test rax, rax
    jnz  .fail
    lea  rdi, [rel fd_kat_ctx]
    lea  rsi, [rel fd_kat_create_name]
    call fd_lookup
    test rax, rax
    jz   .fail
    lea  rdi, [rel fd_kat_fat1]
    lea  rsi, [rel fd_kat_fat2]
    mov  edx, 512
    call memcmp
    test rax, rax
    jnz  .fail
    cmp  dword [rel fd_kat_flush_count], 4
    jb   .fail                               ; both create + both delete barriers
    cmp  dword [rel fd_kat_fat1 + 5*4], 0
    jne  .fail                               ; deleted chain was actually freed
    lea  rdi, [rel str_fd_create_kat]
    call serial_string
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    mov  byte [rel fd_fault_point], FD_FAULT_NONE
    mov  byte [rel fd_fault_seen], FD_FAULT_NONE
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

fat32_disk_kat_mount:
    push rbx
    call fd_kat_reset_media
    call fat32_disk_build_ops
    lea  rbx, [rel fd_kat_blk_ops]
    lea  rax, [rel fd_kat_identify]
    mov  [rbx + blk_ops.identify], rax
    lea  rax, [rel fd_kat_read]
    mov  [rbx + blk_ops.read], rax
    lea  rax, [rel fd_kat_write]
    mov  [rbx + blk_ops.write], rax
    lea  rax, [rel fd_kat_flush]
    mov  [rbx + blk_ops.flush], rax
    lea  rbx, [rel fd_kat_blk_info]
    lea  rax, [rel str_fd_kat_dev]
    mov  [rbx + blk_info.name], rax
    mov  dword [rbx + blk_info.sector_size], 512
    mov  qword [rbx + blk_info.lba_max], FD_KAT_TOTAL_SECTORS - 1
    mov  byte [rbx + blk_info.dma_mask], 64
    mov  byte [rbx + blk_info.removable], 0
    mov  dword [rbx + blk_info.flags], 0
    ; Private, unregistered boot fixture: each reconstruction is a new local
    ; incarnation. It never enters the physical block registry or DATA binding.
    inc  qword [rbx + blk_info.media_generation]
    lea  rbx, [rel fd_kat_dev]
    lea  rax, [rel fd_kat_blk_ops]
    mov  [rbx + dev.ops], rax
    lea  rax, [rel fd_kat_blk_info]
    mov  [rbx + dev.info], rax
    mov  qword [rbx + dev.priv], 0
    mov  dword [rbx + dev.prio], PRIO_DOMAIN
    mov  dword [rbx + dev.health], HEALTH_OK
    mov  dword [rbx + dev.class], CLASS_BLOCK
    mov  dword [rbx + dev.flags], 0
    lea  rax, [rel str_fd_kat_dev]
    mov  [rbx + dev.name], rax
    lea  rdi, [rel fat32_disk_ops]
    lea  rsi, [rel fd_kat_ctx]
    lea  rdx, [rel str_fd_kat_mount]
    mov  [rsi + FD_DEV], rbx
    mov  byte [rel fd_kat_write_mode], 1
    call vfs_register_mount
    pop  rbx
    ret

; Fixture and production contexts share bounded scratch buffers; invalidate
; production cache tags before restoring the DATA mount handle.
fat32_disk_kat_finish:
    mov  byte [rel fd_kat_dirs_mode], 0
    mov  qword [rel fd_path_cache_ctx], 0
    mov  byte [rel fd_tx_fault], 0
    mov  byte [rel fd_tx_kat_active], 0
    mov  byte [rel fd_kat_write_mode], 0
    mov  byte [rel fd_fault_point], FD_FAULT_NONE
    mov  byte [rel fd_fault_seen], FD_FAULT_NONE
    mov  rax, -1
    mov  [rel fat32_disk_ctx + FD_FAT_CACHE_LBA], rax
    mov  dword [rel fat32_disk_ctx + FD_CACHE_START], 0
    mov  dword [rel fat32_disk_ctx + FD_VALID_START], 0
    mov  byte [rel fat32_disk_ctx + FD_LOOKUP_VALID], 0
    ret

; Host-generated media matrix, Task2401. The host supplies six disposable MBR
; disks to QEMU's AHCI controller and independently inspects their final bytes.
; Unlike the sparse KAT, these reads/writes traverse real emulated block I/O.
; No disk is eligible on bare metal: CPUID hypervisor, exact disk size, MBR
; signature, partition geometry and case-specific BPB identity all precede arm.
; The arm lasts only for this synchronous boot call and is never verb-visible.
; RDI is the caller's read-only observation callback: (EDI=mount handle) -> 0/-1.
FD_MEDIA_PART     equ 2048
FD_MEDIA_FATS     equ 513
FD_MEDIA_SECTORS  equ 32 + 2*FD_MEDIA_FATS + 65525
FD_MEDIA_DISK     equ FD_MEDIA_PART + FD_MEDIA_SECTORS + 32

fat32_disk_media_kat:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  rbp, rdi
    mov  eax, 1
    cpuid
    test ecx, 0x80000000
    jz   .out
    xor  r12d, r12d
.next:
    mov  rdi, r12
    xor  esi, esi
    mov  edx, BLKF_RO
    call blk_iter_after
    test rax, rax
    jz   .done
    mov  r12, rax
    mov  rdx, [rax + dev.info]
    cmp  dword [rdx + blk_info.sector_size], 512
    jne  .next
    cmp  qword [rdx + blk_info.lba_max], FD_MEDIA_DISK - 1
    jne  .next
    mov  rdi, r12
    xor  esi, esi
    mov  edx, 1
    lea  rcx, [rel fd_media_header]
    call blk_read
    test rax, rax
    jnz  .next
    lea  rdi, [rel fd_media_header + 256]
    lea  rsi, [rel fd_media_magic]
    mov  edx, 16
    call memcmp
    test rax, rax
    jnz  .next
    mov  r14d, [rel fd_media_header + 272]
    cmp  r14d, 5
    ja   .next
    lea  rdi, [rel str_fd_media_begin]
    call serial_string
    mov  edi, r14d
    call serial_hex64
    call serial_newline
    mov  [rel fd_media_dev], r12
    mov  [rel fd_media_ctx + FD_DEV], r12
    mov  r15d, [rel vfs_mount_count]
    lea  rdi, [rel fat32_disk_ops]
    lea  rsi, [rel fd_media_ctx]
    lea  rdx, [rel fd_media_magic]
    call vfs_register_mount
    test rax, rax
    js   .fail
    mov  r13d, eax
    cmp  qword [rel fd_media_ctx + FD_PART_LBA], FD_MEDIA_PART
    jne  .fail
    cmp  qword [rel fd_media_ctx + FD_PART_SECTORS], FD_MEDIA_SECTORS
    jne  .fail
    cmp  qword [rel fd_media_ctx + FD_TOTAL_SECTORS], FD_MEDIA_SECTORS
    jne  .fail
    cmp  qword [rel fd_media_ctx + FD_FAT_SECTORS], FD_MEDIA_FATS
    jne  .fail
    cmp  dword [rel fd_media_ctx + FD_SPC], 1
    jne  .fail
    cmp  dword [rel fd_media_ctx + FD_ROOT_CLUSTER], 2
    jne  .fail
    lea  eax, [r14 + 0x24010000]
    cmp  eax, [rel fd_media_ctx + FD_VOLUME_ID]
    jne  .fail
    mov  byte [rel fd_media_armed], 1
    mov  byte [rel fd_fault_point], FD_FAULT_NONE
    cmp  r14d, FD_FAULT_FAT1
    ja   .create
    mov  [rel fd_fault_point], r14b
.create:
    mov  edi, r13d
    lea  rsi, [rel fd_media_name]
    lea  rdx, [rel fd_media_header + 288]
    mov  ecx, 96
    call vfs_writefile
    test r14d, r14d
    jz   .created
    cmp  r14d, 4
    je   .created
    cmp  rax, -1
    jne  .fail
    cmp  r14d, 5
    jne  .fault_seen
    cmp  dword [rel fat32_disk_last_error], FD_ERR_NO_SPACE
    jne  .fail
    lea  rdi, [rel fd_media_ctx]
    call fd_count_free
    test rax, rax
    jnz  .fail
    cmp  qword [rel fd_media_ctx + FD_FREE_COUNT], 0
    jne  .fail
.fault_seen:
    cmp  r14d, FD_FAULT_FAT1
    jne  .remount
    cmp  byte [rel fd_fault_seen], FD_FAULT_FAT1
    jne  .fail
    jmp  .remount
.created:
    cmp  rax, -1
    je   .fail
    ; Duplicate and non-scratch negatives must not alter this file or INITRD.
    mov  edi, r13d
    lea  rsi, [rel fd_media_name]
    lea  rdx, [rel fd_media_header + 288]
    mov  ecx, 96
    call vfs_writefile
    cmp  rax, -1
    jne  .fail
    cmp  dword [rel fat32_disk_last_error], FD_ERR_EXISTS
    jne  .fail
    mov  edi, r13d
    lea  rsi, [rel fd_marker_name]
    call vfs_delete
    cmp  rax, -1
    jne  .fail
    cmp  dword [rel fat32_disk_last_error], FD_ERR_ALLOWLIST
    jne  .fail
    cmp  r14d, 4
    jne  .remount
    mov  edi, r13d
    lea  rsi, [rel fd_media_name]
    call vfs_delete
    test rax, rax
    jnz  .fail
.remount:
    mov  byte [rel fd_fault_point], FD_FAULT_NONE
    mov  byte [rel fd_fault_seen], FD_FAULT_NONE
    lea  rdi, [rel fd_media_ctx]
    call fd_flush
    test rax, rax
    jnz  .fail
    lea  rdi, [rel fd_media_ctx]
    call fat32_disk_mount_ctx
    test rax, rax
    jnz  .fail
    test r14d, r14d
    jz   .readback
    lea  rdi, [rel fd_media_ctx]
    lea  rsi, [rel fd_media_name]
    call fd_lookup
    test rax, rax
    jz   .fail
    cmp  dword [rel fat32_disk_last_error], FD_ERR_NOT_FOUND
    jne  .fail
    jmp  .pass
.readback:
    mov  edi, r13d
    lea  rsi, [rel fd_media_name]
    xor  edx, edx
    lea  rcx, [rel fd_verify_buf]
    mov  r8d, 96
    call vfs_read_at
    cmp  rax, 96
    jne  .fail
    lea  rdi, [rel fd_verify_buf]
    lea  rsi, [rel fd_media_header + 288]
    mov  edx, 96
    call memcmp
    test rax, rax
    jnz  .fail
.pass:
    ; The service owns command dispatch/serialization; keep that dependency
    ; above the FS layer by invoking its supplied observation callback.
    mov  edi, r13d
    call rbp
    test rax, rax
    jnz  .fail
    lea  rdi, [rel str_fd_media_pass]
    call serial_string
    call .disarm
    jmp  .next
.fail:
    lea  rdi, [rel str_fd_media_fail]
    call serial_string
    call .disarm
    jmp  .out
.disarm:
    mov  byte [rel fd_media_armed], 0
    mov  byte [rel fd_fault_point], FD_FAULT_NONE
    mov  byte [rel fd_fault_seen], FD_FAULT_NONE
    mov  [rel vfs_mount_count], r15d
    lea  rdi, [rel fat32_disk_ctx]
    call fd_invalidate_caches
    ret
.done:
    lea  rdi, [rel str_fd_media_done]
    call serial_string
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_fs_fat32_disk_1 0
fd_media_ctx: times FD_CTX_SIZE db 0
fd_media_dev: dq 0
fd_media_armed: db 0
fd_media_header: times 512 db 0
fd_media_magic: db "PAOS2401MEDIAKAT",0
fd_media_name: db "FSW2401 TST"
str_fd_media_begin: db "[fs.media] BEGIN ",0
str_fd_media_write: db "[fs.media] WRITE ",0
str_fd_media_flush: db "[fs.media] FLUSH",13,10,0
str_fd_media_pass: db "[fs.media] PASS",13,10,0
str_fd_media_fail: db "[fs.media] FAIL",13,10,0
str_fd_media_done: db "[fs.media] DONE",13,10,0

times 56 db 0                  ; fat32_disk_ops..fat32_disk_selected_dev moved to WDATA_fs_fat32_disk_1_bss1: keeps the labels below at their offset mod 64
fat32_disk_selected_port: dd 0xFFFFFFFF
fat32_disk_selected_volume_id: dd 0
fat32_disk_selection_reason: db FD_SELECT_NONE
fat32_disk_saved_reason: db FD_SELECT_NONE
fd_kat_write_mode: db 0
fd_fault_point: db FD_FAULT_NONE
fd_fault_seen: db FD_FAULT_NONE
fd_kat_fail_fat2: db 0
align 4
fat32_disk_last_error: dd FD_ERR_NONE
fat32_disk_saved_port: dd 0xFFFFFFFF
fat32_disk_saved_volume_id: dd 0
fat32_disk_saved_dev: dq 0
align 8
fd_gpt_entries_lba: dq 0
fd_gpt_count:       dd 0
fd_list_observe_seq: dq 0
fd_list_observe_ctx: dq 0
fd_list_observe_reads: dq 0
fd_list_observe_rc: dq -1
fd_list_seen_count: dd 0
fd_list_sector_index: dd 0
fd_list_entry_index: dd 0
fd_found_cluster:   dd 0
fd_found_size:      dq 0
fd_found_dir_lba:   dq 0
fd_found_dir_off:   dd 0
fd_mut_dir_lba:     dq 0
fd_mut_dir_off:     dd 0
fd_mut_cluster:     dd 0
fd_mut_next:        dd 0
fd_mut_slot_valid:  db 0
fd_lookup_candidate: db 0
fd_found_attr:      db 0
fd_tx_fault:        db 0                   ; boot-local KAT only; never exported as a verb
fd_tx_fault_seen:   db 0
fd_tx_kat_active:   db 0
fd_tx_commit_seen:  db 0
; T5-15.4 V-C3: everything PaOS itself keeps on a FAT volume. test_rc_volume_rule_host
; censuses native writers against this list; a new store reddens it until listed.
; VR-1 (ROOT109242): PAOS2 CFG (input settings v2) and UPDATE CFG (update consent) are
; DATA policy stores like PAOS CFG; only the DATA context may create or replace them.
FD_PROTECTED_COUNT equ 16
fd_protected_names:
    db 'PAOSDOCSBIN'
    db 'PAOSAPPSBIN'
    db 'PAOS    CFG'
    db 'PAOS2   CFG'
    db 'UPDATE  CFG'
    db 'DDLEARN0BIN'
    db 'DDLEARN1BIN'
    db '~TMPPLAN   '
    db '~TMPREPL   '
    db '~TMPSWAP   '
    db '~TMPGROW   '
    db 'INITRD  GZ '
    db 'BZIMAGE    '
    db 'BZIMAGE2   '
    db 'INITRD2 GZ '
    db 'MODEL   PXG'
fd_tx_plan:         db "~TMPPLAN   "
fd_tx_repl:         db "~TMPREPL   "       ; E2r: a replace's old-chain record, beside the plan
fd_tx_temp:         db "~TMPSWAP   "
fd_tx_cadence:      db "fs.orphan",0
align 8
fd_tx_lba:          dq 0
fd_tx_old_lba:      dq 0
fd_tx_off:          dd 0
fd_tx_reservation:  dd 0
fd_tx_old_head:     dd 0
fd_tx_old_tail:     dd 0
fd_tx_kat_old_head: dd 0
fd_tx_kat_old_tail: dd 0
fd_tx_commit_flush: dd 0
%endmacro
WDATA_DEFER WDATA_fs_fat32_disk_1
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER), in block order.
%macro WDATA_fs_fat32_disk_1_bss1 0
resb 18                 ; keeps fat32_disk_ops at its WDATA offset mod 64
fat32_disk_ops: resb fs_ops_size
fat32_disk_ctx: resb FD_CTX_SIZE
fat32_disk_fallback_ctx: resb FD_CTX_SIZE
fat32_disk_saved_ctx: resb FD_CTX_SIZE
fd_kat_ctx: resb FD_CTX_SIZE
fd_kat_dev: resb dev_size
fd_kat_blk_ops: resb blk_ops_size
fd_kat_blk_info: resb blk_info_size
fat32_disk_selected_dev: resq 1
%endmacro
WDATA_BSS_DEFER WDATA_fs_fat32_disk_1_bss1
; Existing create/verify scratch is idle while the writer lock owns recovery.
fd_tx_entry equ fd_dirent_buf
fd_tx_old equ fd_verify_buf
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_fs_fat32_disk_2 0
align 4
fd_kat_flush_count: dd 0
fd_scan_found:      db 0
fd_dir_end_seen:    db 0
fd_lfn_valid:       db 0
fd_lfn_expected:    db 0
fd_lfn_total:       db 0
fd_lfn_checksum_byte: db 0
align 2
fd_lfn_term_pos:    dw 0xFFFF
align 4
fd_path_len:        dd 0
fd_path_next_index: dd 0
fd_scan_component_len: dd 0
fd_list_names_used: dd 0
fd_list_cluster:    dd 0
align 8
fd_scan_component:  dq 0
fd_path_cache_ctx:  dq 0
fd_path_cache_size: dq 0
fd_path_cache_generation: dq 0
fd_path_cache_len:  dd 0
fd_path_cache_cluster: dd 0
fd_path_cache_attr: db 0
align 8
fd_lfn_utf16:       times (FD_LFN_MAX + 1) dw 0
fd_lfn_name:        times (FD_LFN_MAX + 1) db 0
fd_short_name:      times 13 db 0
fd_path_short:      times 11 db 0
fd_path_cache_path: times (FD_PATH_MAX + 1) db 0
fd_list_names:      times FD_LIST_NAMES_CAP db 0
fd_lfn_offsets:     db 1,3,5,7,9,14,16,18,20,22,24,28,30
fd_kat_lfn_rows:    times 64 db 0
fd_kat_short_entry: times 32 db 0
fd_kat_dirent:      times fs_dirent_size db 0
fd_kat_max_name:    times (FD_LFN_MAX + 1) db 0
fd_kat_checksum:    db 0
fd_kat_doc_name: db "Documents"
.len equ $ - fd_kat_doc_name
fd_kat_lfn_name: db "July summary.txt"
.len equ $ - fd_kat_lfn_name
fd_kat_lfn_mixed: db "jULY SUMMARY.TxT"
.len equ $ - fd_kat_lfn_mixed
fd_kat_alias_name: db "JULYSU~1.TXT"
.len equ $ - fd_kat_alias_name
fd_kat_deep_data: db "PAOS-LFN-DEEP-KAT",10
.len equ $ - fd_kat_deep_data
%endmacro
WDATA_DEFER WDATA_fs_fat32_disk_2
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_fs_fat32_disk_3 0
str_fd_root_path:  db "/",0
fd_path_input: times (FD_PATH_MAX + 1) db 0

fd_dir_seen:        times FD_DIR_MAX_CLUSTERS dd 0
fd_kat_seen:        times 64 dd 0
fd_mbr_sector:      times 512 db 0
fd_sector:          times 512 db 0
fd_fat_sector:      times 512 db 0
fd_fat2_sector:     times 512 db 0
fd_fat_scan1:       times 4096 db 0
fd_fat_scan2:       times 4096 db 0
fd_dirent_buf:      times 32 db 0
fd_verify_buf:      times 256 db 0
fd_kat_fat1:        times 512 db 0
fd_kat_fat2:        times 512 db 0
fd_kat_root:        times 512 db 0
fd_kat_data5:       times 5*512 db 0      ; writable clusters 5,6,8,9,10
%endmacro
WDATA_DEFER WDATA_fs_fat32_disk_3
; No free-count scan runs inside the synchronous transaction KAT. Reuse its
; second buffer for the chosen payload/expected bytes, never as media storage.
fd_kat_tx_payload equ fd_fat_scan2
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_fs_fat32_disk_4 0
fd_kat_tx_name:     db "FSW2    TST"
fd_kat_create_readback: times 96 db 0
fd_kat_fragmented_fat: dd 0,0,0,7,0x0FFFFFFF,0,0,4,0,0
fd_kat_cycle_fat:      dd 0,0,0,7,0,0,0,3,0,0
fd_kat_reserved_fat:   dd 0,0,0,0x0FFFFFF0,0,0,0,0,0,0
fd_kat_bad_fat:        dd 0,0,0,0x0FFFFFF7,0,0,0,0,0,0
fd_kat_file_tail: db "PAOS-AHCI-SCRATCH",10
.len equ $ - fd_kat_file_tail
fd_kat_create_payload: db "PaOS FAT32 create/delete crash-cut KAT: data first, dual FAT, entry last, durable barriers."
.len equ $ - fd_kat_create_payload
fd_kat_create_name: db "FSW1    TST"
fd_kat_bystander_name: db "SCRATCH TXT"
fd_kat_create_path: db "/FSW1.TST"
.len equ $ - fd_kat_create_path

str_fd_ahci_prefix: db "ahci",0
str_fd_nvme_prefix: db "nvme",0
align 8
%if COG_MODEL_ENABLED = 1
fd_expected_data_volume:
    db COG_DATA_DISK_GUID_BYTES
    db COG_DATA_PART_GUID_BYTES
    dq COG_DATA_PART_SECTORS
    dq COG_DATA_FS_SECTORS
    dd COG_DATA_VOLUME_ID
    dd 0
%endif
fd_marker_name:    db "INITRD  GZ "          ; protected INITRD.GZ, exact FAT 8.3
str_fd_backend:    db "fat32_disk",0
str_fd_ro_backend: db "fat32_boot_esp_ro",0
str_fd_esp_fault: db "fat32: boot ESP refused: a medium did not read or parse",0
str_fd_foreign_gpt: db "[PAOS64] fatro scan: GPT names another extent, searched not selectable backup_lba=",0
str_fd_foreign_gpt_max: db " lba_max=",0
str_fd_foreign_gpt_tag: db " [fs.fatro.scan.foreign_gpt]",0
str_fd_esp_ambiguous: db "fat32: boot ESP refused: its GUID is named more than once",0
str_fd_esp_none: db "fat32: boot ESP refused: no mountable ESP with its GUID",0
; Canonical read-only token identity for the bounded PARTLS type union.
fat32_disk_part_type:
str_fd_part_type:  db "fat32",0
str_fd_mount_name: db "sata-fat32",0
str_fd_kat_dev:    db "qemu-fat32-kat",0
str_fd_kat_mount:  db "qemu-fat32-kat",0
str_fd_mounted:    db "[PAOS64] C8 physical FAT32 mounted over supplied blk_ops handle [vfs.fat32_disk.mounted]",13,10,0
str_fd_fallback_skipped: db "[vfs.fat32_disk.fallback-skipped] dev=",0
str_fd_fallback_entry: db " entry_index=",0
str_fd_create_kat: db "[PAOS64] P6 fs: create/delete KAT PASS (fault-injected at alloc/data/FAT1, volume re-validates, FATs agree) [fs.write.create.kat]",13,10,0
str_fd_tx_ready: db "[PAOS64] P6 fs: FAT32 temp-then-swap update + atomic rename + orphan sweep ready [fs.write.txn.ready]",13,10,0
str_fd_tx_kat: db "[PAOS64] P6 fs: update transaction KAT PASS (4-point fault injection, old file intact at every pre-commit failure, orphan reclaimed) [fs.write.txn.kat]",13,10,0
str_fd_tx_kat_fail: db "[PAOS64] P6 fs: update transaction KAT FAIL cut=",0
str_fd_kat:        db "[PAOS64] C8 FAT32 stream KAT fragmented=1 cycle_rejected=1 bounds_rejected=1",13,10,0
%endmacro
WDATA_DEFER WDATA_fs_fat32_disk_4

%macro WDATA_BSS_fs_fat32_selected_ro 0
alignb 8
fat32_disk_ro_diag: resb FD_RO_BYTES
fd_ro_diag_candidate_name: resb 64
fd_ro_diag_step: resq 1
fd_ro_diag_active: resb 1
alignb 8
fd_owned_read: resb 96
fd_owned_check: resb 96
fd_owned_index: resd 1
fd_owned_token: resb 16
fd_owned_active: resb 1
fd_owned_dirty: resb 1
alignb 8
fd_selected_ctx: resb FD_CTX_SIZE
fd_selected_ops: resb fs_ops_size
fd_selected_guid: resb 16
fd_selected_start: resq 1
fd_selected_sectors: resq 1
fd_selected_generation: resq 1
fd_selected_max: resq 1
fd_selected_logical: resd 1
fd_selected_handle: resd 1
fd_selected_sector: resd 1
fd_selected_header: resb 4096
fd_selected_entries: resb 128 * 128
%endmacro
WDATA_BSS_DEFER WDATA_BSS_fs_fat32_selected_ro
str_fd_selected_name: db 'fat-ro0', 0
str_fd_selected_backend: db 'fat32_selected_ro', 0

; Explicit OWNER/SPECIAL scratch authority is a separate mount. Neither the
; descriptor DATA context nor either read-only context acquires new authority.
; Binding: disk GUID[16], volume serial u32, partition GUID[16], start/sectors.
; select_ro_exact supplies complete CRC/overlap/clone validation; this copy
; pins that exact GPT and BPB and never refreshes its media generation.
; Native local MBR path only. The remote GUID selector never accepts zero
; GUIDs. RDI=registered dev*, ESI=BPB serial, RCX=first, R8=count.
; The actual primary slot/signature/type come from fs_identify's live walk.
fd_scratch_arm_mbr:
    mov [rel fd_mbr_request_dev],rdi
    lea rdi,[rel fd_mbr_zero_guid]
    mov rdx,rdi
    call fat32_disk_scratch_arm
    mov qword [rel fd_mbr_request_dev],0
    ret

; Called only inside the arm after its OWNER/busy guards. No writes/mount
; publication. Generation/extent and BPB are actual current registered media.
fd_scratch_select_mbr:
    ; An MBR boot has no ESP GUID. Until firmware identifies the boot volume,
    ; a removable (or unknown-removability) boot could be this FAT32 primary.
    ; Never arm it speculatively; do this before any arm media probing.
    cmp byte [rel boot_esp_removable],0
    je .boot_named
    cmp byte [rel boot_esp_part_guid_ok],1
    jne .no
.boot_named:
    mov rdi,[rel fd_mbr_request_dev]
    call guest_volume_native_allowed
    test rax,rax
    jnz .no
    mov rdi,[rel fd_mbr_request_dev]
    mov rsi,r15
    mov rdx,[rsp+8]                     ; caller's saved count, after CALL
    lea rcx,[rel fd_mbr_tuple]
    call fs_identify_primary
    test rax,rax
    jnz .no
    cmp dword [rel fd_mbr_tuple+36],FS_SCHEME_MBR
    jne .no
    mov eax,[rel fd_mbr_tuple+40]
    cmp eax,0x0b
    je .type
    cmp eax,0x0c
    jne .no                            ; hidden/ESP/extended are never writers
.type:
    call fd_selected_invalidate
    mov dword [rel vfs_disk_handle],-1
    lea rdi,[rel fd_selected_ctx]
    xor eax,eax
    mov ecx,FD_CTX_SIZE/8
    rep stosq
    mov rdi,[rel fd_mbr_request_dev]
    mov [rel fd_selected_ctx+FD_DEV],rdi
    mov rsi,[rel fd_mbr_tuple+16]
    mov [rel fd_selected_ctx+FD_PART_LBA],rsi
    mov rax,[rel fd_mbr_tuple+24]
    mov [rel fd_selected_ctx+FD_PART_SECTORS],rax
    mov rax,[rel fd_mbr_tuple+8]
    mov [rel fd_selected_ctx+FD_MOUNT_GEN],rax
    mov [rel fd_selected_generation],rax
    mov dword [rel fd_selected_logical],512
    mov rax,[rdi+dev.info]
    cmp dword [rax+blk_info.logical_sector_bytes],512
    jne .no
    mov rax,[rax+blk_info.lba_max]
    mov [rel fd_selected_max],rax
    mov dword [rel fd_selected_ctx+FD_PART_INDEX],-1
    mov edx,1
    lea rcx,[rel fd_sector]
    call blk_read
    test rax,rax
    jnz .no
    lea rdi,[rel fd_selected_ctx]
    lea rsi,[rel fd_sector]
    call fd_validate_bpb
    test rax,rax
    jnz .no
    cmp r13d,[rel fd_selected_ctx+FD_VOLUME_ID]
    jne .no
    ; Save the table bytes BEFORE the final independent exact-walk comparison.
    mov rdi,[rel fd_mbr_request_dev]
    xor esi,esi
    mov edx,1
    lea rcx,[rel fd_selected_gpt_saved]
    call blk_read
    test rax,rax
    jnz .no
    mov rdi,[rel fd_mbr_request_dev]
    mov rsi,r15
    mov rdx,[rsp+8]
    lea rcx,[rel fd_mbr_recheck]
    call fs_identify_primary
    test rax,rax
    jnz .no
    lea rdi,[rel fd_mbr_tuple]
    lea rsi,[rel fd_mbr_recheck]
    mov ecx,6
    repe cmpsq
    jne .no
    mov eax,[rel fd_mbr_tuple+44]
    cmp eax,[rel fd_selected_gpt_saved+440]
    jne .no
    call fd_selected_build_ops
    xor eax,eax
    ret
.no:
    mov rax,-1
    ret

fat32_disk_scratch_arm:                 ; RDI=disk GUID, ESI=serial, RDX=part GUID,
                                      ; RCX=start, R8=sectors -> handle / -1/-2/-3
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 16
    mov r12, rdi
    mov r13d, esi
    mov r14, rdx
    mov r15, rcx
    mov [rsp], r8
    call fd_scratch_owner
    test rax, rax
    jnz .out
    call vfs_copy_busy
    test eax, eax
    jnz .busy
    call storage_access_binding_busy
    test eax, eax
    jnz .busy
    cmp dword [rel fd_scratch_ctx + FD_TX_BUSY], 0
    jne .busy
    mov byte [rel fd_scratch_armed], 0
    mov dword [rel fd_scratch_ctx + FD_MOUNTED], 0
    lea rax, [rel str_fd_scratch_select]
    mov [rel fd_scratch_stage], rax
    mov dword [rel fd_scratch_mbr_slot],0
    cmp qword [rel fd_mbr_request_dev],0
    je .gpt_select
    call fd_scratch_select_mbr
    test rax,rax
    jnz .fail
    mov eax,[rel fd_mbr_tuple+32]
    mov [rel fd_scratch_mbr_slot],eax
    jmp .selected
.gpt_select:
    mov rdi, r14
    mov rdx, r15
    mov rcx, [rsp]
    call fat32_disk_select_ro_exact
.selected:
    test rax, rax
    js .out
    lea rax, [rel str_fd_scratch_identity]
    mov [rel fd_scratch_stage], rax
    ; No ESP, superfloppy, zero serial or descriptor inference.
    cmp byte [rel fd_selected_ctx + FD_PART_ESP], 0
    jne .fail
    ; T5-15.4: the volume the INITRD.GZ boot marker selected is never scratch (as vol_owner).
    cmp byte [rel fat32_disk_selection_reason], FD_SELECT_MARKER
    jne .not_marker
    mov rax, [rel fd_selected_ctx + FD_DEV]
    cmp rax, [rel fat32_disk_selected_dev]
    jne .not_marker
    mov eax, [rel fd_selected_ctx + FD_VOLUME_ID]
    cmp eax, [rel fat32_disk_selected_volume_id]
    je .fail
.not_marker:
    cmp dword [rel fd_scratch_mbr_slot],0
    jne .serial
    mov eax, [rel fd_selected_ctx + FD_PART_INDEX]
    cmp eax, 128
    jae .fail
    shl eax, 7
    lea rbp, [rel fd_selected_entries]
    add rbp, rax
    mov rax, 0x4433b9e5ebd0a0a2
    cmp [rbp], rax
    jne .fail
    mov rax, 0xc79926b7b668c087
    cmp [rbp + 8], rax
    jne .fail
    cmp qword [rbp + 48], 0             ; no hidden/read-only/required GPT attributes
    jne .fail
.serial:
    test r13d, r13d
    jz .fail
    cmp r13d, [rel fd_selected_ctx + FD_VOLUME_ID]
    jne .fail
    lea rdi, [rel fd_selected_ctx + FD_DISK_GUID]
    mov rsi, r12
    mov edx, 16
    call memcmp
    test rax, rax
    jnz .fail
    lea rdi, [rel fd_scratch_ctx]
    lea rsi, [rel fd_selected_ctx]
    mov edx, FD_CTX_SIZE
    call memcpy
    ; This does not become the compiled DATA authority.
    mov byte [rel fd_scratch_ctx + FD_EXACT_BOUND], 0
    mov rax, [rel fd_selected_generation]
    mov [rel fd_scratch_generation], rax
    mov rax, [rel fd_selected_max]
    mov [rel fd_scratch_max], rax
    mov rax, [rel fd_scratch_ctx + FD_DEV]
    mov rdx, [rax + dev.info]
    mov [rel fd_scratch_info], rdx
    mov rdx, [rax + dev.ops]
    mov [rel fd_scratch_devops], rdx
    lea rdi, [rel fd_scratch_header]
    lea rsi, [rel fd_selected_gpt_saved]
    mov edx, 512
    call memcpy
    mov dword [rel fd_scratch_table_sectors],0
    cmp dword [rel fd_scratch_mbr_slot],0
    jne .boot
    ; The selected validator zeros this field while computing its CRC.
    mov eax, [rel fat32_disk_ro_diag + FD_RO_HEADER_CRC]
    mov [rel fd_scratch_header + 16], eax
    lea rdi, [rel fd_scratch_entries]
    lea rsi, [rel fd_selected_entries]
    mov eax, [rel fd_scratch_header + 80]
    add eax, 3
    shr eax, 2
    mov [rel fd_scratch_table_sectors], eax
    shl eax, 9
    mov edx, eax
    call memcpy
.boot:
    ; mount_ctx's final fd_sector is the exact accepted partition BPB.
    lea rdi, [rel fd_scratch_boot]
    lea rsi, [rel fd_sector]
    mov edx, 512
    call memcpy
    lea rax, [rel str_fd_scratch_metadata]
    mov [rel fd_scratch_stage], rax
    call fd_scratch_metadata
    test rax, rax
    jnz .fail
    lea rax, [rel str_fd_scratch_request]
    mov [rel fd_scratch_stage], rax
    call fd_scratch_request
    test rax, rax
    jnz .fail
    lea rax, [rel str_fd_scratch_mount_register]
    mov [rel fd_scratch_stage], rax
    mov edi, [rel fd_scratch_handle]
    test edi, edi
    jnz .existing
    ; Copy the read-only adapters, never the descriptor's legacy write slots.
    lea rdi, [rel fd_scratch_ops]
    lea rsi, [rel fd_selected_ops]
    mov edx, fs_ops_size
    call memcpy
    lea rax, [rel fd_scratch_mount]
    mov [rel fd_scratch_ops + fs_ops.mount], rax
    lea rax, [rel fat32_disk_mutate_path]
    mov [rel fd_scratch_ops + fs_ops.mutate_path], rax
    lea rax, [rel small_copy_fat_dispatch]
    mov [rel fd_scratch_ops + fs_ops.copy], rax
    lea rax, [rel small_copy_between]
    mov [rel fd_scratch_ops + fs_ops.copy_between], rax
    lea rax, [rel fd_scratch_hint]
    mov [rel fd_scratch_ops + fs_ops.mutate_armed], rax
    lea rdi, [rel fd_scratch_ops]
    lea rsi, [rel fd_scratch_ctx]
    lea rdx, [rel str_fd_scratch_name]
    call vfs_register_mount
    test rax, rax
    js .fail
    inc eax
    mov [rel fd_scratch_handle], eax
    jmp .publish
.existing:
    dec edi
    call vfs_mount_ptr
    test rax, rax
    jz .fail
    lea rdx, [rel fd_scratch_ops]
    cmp [rax + fsmount.ops], rdx
    jne .fail
    lea rdx, [rel fd_scratch_ctx]
    cmp [rax + fsmount.priv], rdx
    jne .fail
.publish:
    ; vfs_register_mount invokes mount: its disarm is intentional. Arm last.
    lea rax, [rel str_fd_scratch_revalidate]
    mov [rel fd_scratch_stage], rax
    call fd_scratch_metadata
    test rax, rax
    jnz .fail
    lea rax, [rel str_fd_scratch_publish_request]
    mov [rel fd_scratch_stage], rax
    call fd_scratch_request
    test rax, rax
    jnz .fail
    lock inc qword [rel fd_scratch_arm_epoch]   ; rc-sec 105819 C5: a new arm, never 0, never reused
    jnz .epoch
    lock inc qword [rel fd_scratch_arm_epoch]
.epoch:
    mov byte [rel fd_scratch_armed], 1
    mov eax, [rel fd_scratch_handle]
    dec eax
    mov [rel vfs_disk_handle], eax
    lock inc qword [rel vfs_write_generation]
    jmp .out
.fail:
    mov byte [rel fd_scratch_armed], 0
    mov dword [rel fd_scratch_ctx + FD_MOUNTED], 0
    mov dword [rel vfs_disk_handle], -1
    mov rax, -1
    jmp .out
.busy:
    mov rax, -2
.out:
    add rsp, 16
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Read-only observation; never selection or authority.
fat32_disk_scratch_diagnostic:
    mov rax, [rel fd_scratch_stage]
    ret

; T5-15.4 local arm (V-C7). RDI=the FAT context the mount holds -> RAX 0 / negative.
; No verb: dispatch calls it under the local bit. The identity is the context's own
; live GPT and BPB identity, revalidated by the arm; fat32_disk_scratch_arm keeps
; its ESP, attribute, type, boot-marker and generation refusals, and ends on swap.
fat32_disk_local_arm:
    lea rax, [rel fd_scratch_ctx]
    cmp rdi, rax
    jne .check
    cmp byte [rel fd_scratch_armed], 1
    je .done
.check:
    push rdi
    mov rdi,[rdi+FD_DEV]
    call guest_volume_native_allowed
    pop rdi
    test rax,rax
    jnz .no
    mov rax, [rdi + FD_DEV]
    test rax, rax
    jz .no
    mov rax, [rax + dev.info]
    test rax, rax
    jz .no
    cmp byte [rax + blk_info.removable], 0
    jne .copy
    test dword [rax + blk_info.flags], BLKF_REMOVABLE
    jnz .copy
    ; Own partition A1: a fixed FAT32 arms only as the selected mount's live adopted extent,
    ; checked before the arm touches any selection; fd_scratch_request decides again.
    cmp dword [rel vfs_disk_handle], -1
    je .no                              ; no selected mount
    push rdi
    mov rsi, rdi
    mov rdx, rdi
    mov edi, [rel vfs_disk_handle]
    call fd_adopted_extent
    pop rdi
    test rax, rax
    jnz .no
.copy:
    mov rax,[rdi+FD_DISK_GUID]
    or rax,[rdi+FD_DISK_GUID+8]
    jnz .gpt
    cmp qword [rdi+FD_PART_LBA],0
    je .no
    mov esi,[rdi+FD_VOLUME_ID]
    mov rcx,[rdi+FD_PART_LBA]
    mov r8,[rdi+FD_PART_SECTORS]
    mov rdi,[rdi+FD_DEV]
    call fd_scratch_arm_mbr
    jmp .armed
.gpt:
    mov rax, [rdi + FD_DISK_GUID]
    mov [rel fd_local_disk], rax
    mov rax, [rdi + FD_DISK_GUID + 8]
    mov [rel fd_local_disk + 8], rax
    mov rax, [rdi + FD_PART_GUID]
    mov [rel fd_local_part], rax
    mov rax, [rdi + FD_PART_GUID + 8]
    mov [rel fd_local_part + 8], rax
    mov esi, [rdi + FD_VOLUME_ID]
    mov rcx, [rdi + FD_PART_LBA]
    mov r8, [rdi + FD_PART_SECTORS]
    lea rdi, [rel fd_local_disk]
    lea rdx, [rel fd_local_part]
    call fat32_disk_scratch_arm
.armed:
    test rax, rax
    js .out
    mov byte [rel fat32_disk_local_moved], 1
.done:
    xor eax, eax
.out:
    ret
.no:
    mov rax, -1
    ret

; A2/D3 explicit native Explorer press: EDI=sealed slot, RSI=visible 16-byte
; token -> RAX mount handle / negative. The registry independently checks the
; unlocked owner, whole identity, uniqueness and session before giving a READ
; extent. Install only the existing selected context's read slots; no arm,
; recovery, bind or write call. The original strict vol_owner_probe is intact.
fat32_disk_select_owned_ro:
    push rbx
    push r12
    push r13
    mov  r12d, edi
    mov  r13, rsi
    mov  al, [rel hv_linux_running]
    or   al, [rel hv_linux_start_active]
    or   al, [rel hv_linux_run_req]
    or   al, [rel vtd_owner_guest]
    test al, al
    jnz  .busy
    call vfs_copy_busy
    test eax, eax
    jnz  .busy
    call storage_access_binding_busy
    test eax, eax
    jnz  .busy
    cmp  dword [rel fd_scratch_ctx + FD_MOUNTED], 0
    jne  .busy
    mov  edi, r12d
    mov  rsi, r13
    lea  rdx, [rel fd_owned_read]
    call vol_owner_read_resolve
    test eax, eax
    jz   .resolved
    cmp  eax, 9                         ; VO_E_DIRTY: readable observation only
    jne  .no
.resolved:
    ; Every pre-selection refusal above preserves the current view. Once a
    ; rebind begins, a failure invalidates it; never resurrect a stale context.
    lock inc qword [rel vfs_write_generation]
    mov  dword [rel vfs_disk_handle], -1
    call fd_selected_invalidate
    lea  rdi, [rel fd_selected_ctx]
    xor  esi, esi
    mov  edx, FD_CTX_SIZE
    call memset
    mov  rax, [rel fd_owned_read]
    test rax, rax
    jz   .fail
    mov  [rel fd_selected_ctx + FD_DEV], rax
    mov  rax, [rel fd_owned_read + 8]
    mov  [rel fd_selected_ctx + FD_PART_LBA], rax
    mov  rax, [rel fd_owned_read + 16]
    mov  [rel fd_selected_ctx + FD_PART_SECTORS], rax
    mov  rax, [rel fd_owned_read + 24]
    mov  [rel fd_selected_generation], rax
    mov  [rel fd_selected_ctx + FD_MOUNT_GEN], rax
    mov  rax, [rel fd_owned_read + 32]
    mov  [rel fd_selected_max], rax
    mov  eax, [rel fd_owned_read + 40]
    mov  [rel fd_selected_logical], eax
    mov  dword [rel fd_selected_sector], 512
    mov  rax, [rel fd_owned_read + 64]
    mov  [rel fd_selected_ctx + FD_DISK_GUID], rax
    mov  rax, [rel fd_owned_read + 72]
    mov  [rel fd_selected_ctx + FD_DISK_GUID + 8], rax
    mov  rax, [rel fd_owned_read + 80]
    mov  [rel fd_selected_ctx + FD_PART_GUID], rax
    mov  rax, [rel fd_owned_read + 88]
    mov  [rel fd_selected_ctx + FD_PART_GUID + 8], rax
    lea  rdi, [rel fd_selected_ctx]
    mov  rsi, [rel fd_selected_ctx + FD_PART_LBA]
    mov  edx, 1
    lea  rcx, [rel fd_sector]
    call fd_read_sectors
    test rax, rax
    jnz  .fail
    lea  rdi, [rel fd_selected_ctx]
    lea  rsi, [rel fd_sector]
    call fd_validate_bpb
    test rax, rax
    jnz  .fail
    ; A second full native resolution must still describe these very bytes,
    ; generation and geometry. Keep the first snapshot until this comparison.
    mov  edi, r12d
    mov  rsi, r13
    lea  rdx, [rel fd_owned_check]
    call vol_owner_read_resolve
    test eax, eax
    jz   .compare
    cmp  eax, 9
    jne  .fail
.compare:
    lea  rdi, [rel fd_owned_read]
    lea  rsi, [rel fd_owned_check]
    mov  edx, 96
    call memcmp
    test eax, eax
    jnz  .fail
    lea  rdi, [rel fd_selected_ctx]
    call fd_selected_current
    test rax, rax
    jnz  .fail
    mov  edi, [rel fd_selected_handle]
    test edi, edi
    jz   .register
    dec  edi
    call vfs_mount_ptr
    test rax, rax
    jz   .fail
    lea  rdx, [rel fd_selected_ops]
    cmp  [rax + fsmount.ops], rdx
    jne  .fail
    lea  rdx, [rel fd_selected_ctx]
    cmp  [rax + fsmount.priv], rdx
    jne  .fail
    jmp  .publish
.register:
    call fd_selected_build_ops
    lea  rdi, [rel fd_selected_ops]
    lea  rsi, [rel fd_selected_ctx]
    lea  rdx, [rel str_fd_selected_name]
    call vfs_register_mount
    test rax, rax
    js   .fail
    inc  eax
    mov  [rel fd_selected_handle], eax
.publish:
    mov  [rel fd_owned_index], r12d
    mov  byte [rel fd_owned_active], 1
    mov  eax, [rel fd_owned_read + 44]
    mov  [rel fd_owned_dirty], al
    lea  rdi, [rel fd_selected_ctx]
    call fd_read_cache_drop
    mov  eax, [rel fd_selected_handle]
    dec  eax
    mov  [rel vfs_disk_handle], eax
    jmp  .out
.fail:
    call fd_selected_invalidate
.no:
    mov  rax, -1
    jmp  .out
.busy:
    mov  rax, -2
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Cached status for the current adopted read view: EDI=mount -> EAX 0 clean
; read-only, 1 dirty read-only, -1 not this view. No media I/O, recovery or grant.
fat32_disk_owned_read_state:
    cmp  byte [rel fd_owned_active], 1
    jne  .no
    mov  eax, [rel fd_selected_handle]
    dec  eax
    cmp  edi, eax
    jne  .no
    cmp  dword [rel fd_selected_ctx + FD_MOUNTED], 1
    jne  .no
    movzx eax, byte [rel fd_owned_dirty]
    ret
.no:
    mov  eax, -1
    ret

; A2/D3 observation guard. No I/O or authority: does this exact fixed
; window hold the native FAT volume selected by the INITRD.GZ boot marker?
; RDI=dev, RSI=first, RDX=count -> EAX 1 yes / 0 no.
fat32_disk_is_boot_extent:
    xor  eax, eax
    cmp  byte [rel fat32_disk_selection_reason], FD_SELECT_MARKER
    jne  .out
    cmp  dword [rel fat32_disk_ctx + FD_MOUNTED], 0
    je   .out
    cmp  rdi, [rel fat32_disk_ctx + FD_DEV]
    jne  .out
    cmp  rsi, [rel fat32_disk_ctx + FD_PART_LBA]
    jne  .out
    cmp  rdx, [rel fat32_disk_ctx + FD_PART_SECTORS]
    jne  .out
    inc  eax
.out:
    ret

; T5-15.4 press route (SEC 90164). RDI=row's device -> RAX mount handle / negative.
; The caller, form_exp_drive_select, holds Explorer's owner, focus and frame gates.
; Read-only: the exact GPT selector or the unique MBR FAT32 reader, no recovery, arm or write. It
; refuses, and keeps the current selection, while any selected or scratch FAT is live.
; Removable is the driver's flag, never the media.
fat32_disk_select_removable_ro:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  al, [rel hv_linux_running]     ; cmd_verb_fsfatro's guard, which the selector lacks
    or   al, [rel hv_linux_start_active]
    or   al, [rel hv_linux_run_req]
    or   al, [rel vtd_owner_guest]
    test al, al
    jnz  .busy
    cmp  dword [rel fd_selected_ctx + FD_MOUNTED], 0
    jne  .busy
    cmp  dword [rel fd_scratch_ctx + FD_MOUNTED], 0
    jne  .busy
    xor  r12d, r12d
.live:
    mov  rdi, r12
    mov  esi, BLKCAP_READ
    xor  edx, edx
    call blk_iter_after
    test rax, rax
    jz   .no
    mov  r12, rax
    cmp  rax, rbx
    jne  .live
    mov  rax, [rbx + dev.info]
    test rax, rax
    jz   .no
    cmp  byte [rax + blk_info.removable], 0
    jne  .native
    test dword [rax + blk_info.flags], BLKF_REMOVABLE
    jz   .no
.native:
    cmp  dword [rax + blk_info.sector_size], 512
    jne  .no
    mov  r13d, [rel vfs_disk_handle]
    mov  rdi, rbx
    call fd_removable_pick
    cmp  rax, 1                         ; a readable non-GPT header, not a GPT parse failure
    je   .mbr
    test rax, rax
    jnz  .no
    mov  byte [rel fd_select_press], 1  ; spent by the selector's own authority check
    lea  rdi, [rel fd_local_part]
    mov  esi, -1                        ; no compiled maximum assertion
    mov  rdx, [rel fd_local_start]
    mov  rcx, [rel fd_local_sectors]
    call fat32_disk_select_ro_exact
    test rax, rax
    js   .restore
    cmp  rbx, [rel fd_selected_ctx + FD_DEV]
    je   .out
    call fd_selected_invalidate         ; the same GUID on another device
    mov  rax, -1
    jmp  .restore
.mbr:
    mov  rdi, rbx
    call fd_removable_mbr_ro
    test rax, rax
    jns  .out
.restore:
    mov  [rel vfs_disk_handle], r13d    ; only fat-ro0 was rebound, and it was not live
    jmp  .out
.busy:
    mov  rax, -2
    jmp  .out
.no:
    mov  rax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=dev -> RAX 0 with fd_local_part/start/sectors for the ONE Basic Data entry;
; 1 only for a readable non-GPT LBA1, -1 on read/malformed GPT failure.
; Hostile media: this only locates. The selector then validates CRCs, bounds,
; overlap and clones on its own reads.
fd_removable_pick:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  rsi, 1
    mov  edx, 1
    lea  rcx, [rel fd_local_sector]
    call blk_read
    test rax, rax
    jnz  .no
    mov  rax, 0x5452415020494645        ; "EFI PART"
    cmp  [rel fd_local_sector], rax
    jne  .mbr
    mov  r12, [rel fd_local_sector + 72]
    cmp  r12, 2
    jb   .no
    mov  rax, [rbx + dev.info]
    cmp  r12, [rax + blk_info.lba_max]
    ja   .no
    mov  r13d, [rel fd_local_sector + 80]
    test r13d, r13d
    jz   .no
    cmp  r13d, 128
    ja   .no
    cmp  dword [rel fd_local_sector + 84], 128
    jne  .no
    xor  r14d, r14d                     ; entry
    xor  r15d, r15d                     ; matches
.entry:
    cmp  r14d, r13d
    jae  .done
    test r14d, 3
    jnz  .have
    mov  rax, r12
    mov  ecx, r14d
    shr  ecx, 2
    add  rax, rcx
    jc   .no
    mov  rdi, rbx
    mov  rsi, rax
    mov  edx, 1
    lea  rcx, [rel fd_local_sector]
    call blk_read
    test rax, rax
    jnz  .no
.have:
    mov  eax, r14d
    and  eax, 3
    shl  eax, 7
    lea  rdx, [rel fd_local_sector]
    add  rdx, rax
    mov  rax, 0x4433b9e5ebd0a0a2
    cmp  [rdx], rax
    jne  .next
    mov  rax, 0xc79926b7b668c087
    cmp  [rdx + 8], rax
    jne  .next
    inc  r15d
    mov  rax, [rdx + 16]
    mov  [rel fd_local_part], rax
    mov  rax, [rdx + 24]
    mov  [rel fd_local_part + 8], rax
    mov  rax, [rdx + 32]
    mov  rcx, [rdx + 40]
    test rax, rax
    jz   .no
    cmp  rcx, rax
    jb   .no
    mov  [rel fd_local_start], rax
    sub  rcx, rax
    inc  rcx
    jz   .no
    mov  [rel fd_local_sectors], rcx
.next:
    inc  r14d
    jmp  .entry
.done:
    cmp  r15d, 1                        ; which of several is the owner's choice, not ours
    jne  .no
    xor  eax, eax
    jmp  .out
.mbr:
    mov  eax, 1
    jmp  .out
.no:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Original local press only: discover one ordinary MBR FAT32 primary on this
; registered removable device. Reuse the maintained identifier and FAT reader,
; then publish the same read-only fat-ro0 ops. This grants no scratch/Format
; authority and never calls mount recovery, an arm, write, or flush.
fd_removable_mbr_ro:
    push rbx
    mov  rbx, rdi
    call vfs_copy_busy
    test eax, eax
    jnz  .busy
    call storage_access_binding_busy
    test eax, eax
    jnz  .busy
    mov  rdi, rbx
    call guest_volume_native_allowed
    test rax, rax
    jnz  .no
    mov  rdi, rbx
    xor  esi, esi                       ; discover: never choose among multiple primaries
    xor  edx, edx
    lea  rcx, [rel fd_local_mbr_tuple]
    call fs_identify_primary
    test rax, rax
    jnz  .no
    cmp  dword [rel fd_local_mbr_tuple + 36], FS_SCHEME_MBR
    jne  .no
    mov  eax, [rel fd_local_mbr_tuple + 40]
    cmp  eax, 0x0b
    je   .fat
    cmp  eax, 0x0c
    jne  .no                           ; hidden/ESP/extended/non-FAT never become this view
.fat:
    mov  rax, [rbx + dev.info]
    test rax, rax
    jz   .no
    cmp  dword [rax + blk_info.sector_size], 512
    jne  .no
    cmp  dword [rax + blk_info.logical_sector_bytes], 512
    jne  .no
    cmp  qword [rel fd_local_mbr_tuple + 8], 0
    je   .no
    lock inc qword [rel vfs_write_generation]
    mov  dword [rel vfs_disk_handle], -1
    call fd_selected_invalidate
    lea  rdi, [rel fd_selected_ctx]
    xor  eax, eax
    mov  ecx, FD_CTX_SIZE / 8
    rep stosq
    mov  [rel fd_selected_ctx + FD_DEV], rbx
    mov  rsi, [rel fd_local_mbr_tuple + 16]
    mov  [rel fd_selected_ctx + FD_PART_LBA], rsi
    mov  rax, [rel fd_local_mbr_tuple + 24]
    mov  [rel fd_selected_ctx + FD_PART_SECTORS], rax
    mov  rax, [rel fd_local_mbr_tuple + 8]
    mov  [rel fd_selected_ctx + FD_MOUNT_GEN], rax
    mov  [rel fd_selected_generation], rax
    mov  dword [rel fd_selected_logical], 512
    mov  rax, [rbx + dev.info]
    mov  rax, [rax + blk_info.lba_max]
    mov  [rel fd_selected_max], rax
    mov  dword [rel fd_selected_ctx + FD_PART_INDEX], -1
    mov  rdi, rbx
    mov  edx, 1
    lea  rcx, [rel fd_local_sector]
    call blk_read
    test rax, rax
    jnz  .fail
    lea  rbx, [rel fd_local_sector]
    call fd_is_fat32_bpb
    mov  rbx, [rel fd_selected_ctx + FD_DEV]
    test eax, eax
    jnz  .fail
    lea  rdi, [rel fd_selected_ctx]
    lea  rsi, [rel fd_local_sector]
    call fd_validate_bpb
    test rax, rax
    jnz  .fail
    ; A second discovery must independently retain the complete incarnation,
    ; extent, primary slot, type and MBR signature, including uniqueness.
    mov  rdi, rbx
    xor  esi, esi
    xor  edx, edx
    lea  rcx, [rel fd_local_mbr_recheck]
    call fs_identify_primary
    test rax, rax
    jnz  .fail
    lea  rdi, [rel fd_local_mbr_tuple]
    lea  rsi, [rel fd_local_mbr_recheck]
    mov  ecx, 6
    repe cmpsq
    jne  .fail
    mov  rdi, rbx
    mov  rsi, [rel fd_selected_ctx + FD_PART_LBA]
    mov  edx, 1
    lea  rcx, [rel fd_sector]
    call blk_read
    test rax, rax
    jnz  .fail
    lea  rdi, [rel fd_local_sector]
    lea  rsi, [rel fd_sector]
    mov  ecx, 64
    repe cmpsq
    jne  .fail                          ; full BPB, not only the volume serial
    lea  rdi, [rel fd_selected_ctx]
    call fd_selected_current           ; final READ/health/member/generation/geometry check
    test rax, rax
    jnz  .fail
    mov  edi, [rel fd_selected_handle]
    test edi, edi
    jz   .register
    dec  edi
    call vfs_mount_ptr
    test rax, rax
    jz   .fail
    lea  rdx, [rel fd_selected_ops]
    cmp  [rax + fsmount.ops], rdx
    jne  .fail
    lea  rdx, [rel fd_selected_ctx]
    cmp  [rax + fsmount.priv], rdx
    jne  .fail
    jmp  .publish
.register:
    call fd_selected_build_ops
    lea  rdi, [rel fd_selected_ops]
    lea  rsi, [rel fd_selected_ctx]
    lea  rdx, [rel str_fd_selected_name]
    call vfs_register_mount
    test rax, rax
    js   .fail
    inc  eax
    mov  [rel fd_selected_handle], eax
.publish:
    lea  rdi, [rel fd_selected_ctx]
    call fd_read_cache_drop
    mov  eax, [rel fd_selected_handle]
    dec  eax
    mov  [rel vfs_disk_handle], eax
    jmp  .out
.fail:
    call fd_selected_invalidate
.no:
    mov  rax, -1
    jmp  .out
.busy:
    mov  rax, -2
.out:
    pop  rbx
    ret

; fat32_disk_next_unviewed(RDI=previous dev or 0) -> RAX the next native removable
; device no FAT or exFAT mount views, or 0; RDX its name. Reads no media.
fat32_disk_next_unviewed:
    push rbx
    mov  rbx, rdi
.next:
    mov  rdi, rbx
    mov  esi, BLKCAP_READ
    xor  edx, edx
    call blk_iter_after
    test rax, rax
    jz   .out
    mov  rbx, rax
    mov  rax, [rbx + dev.info]
    test rax, rax
    jz   .next
    cmp  byte [rax + blk_info.removable], 0
    jne  .native
    test dword [rax + blk_info.flags], BLKF_REMOVABLE
    jz   .next
.native:
    mov  rdi, rbx
    call fat32_disk_device_mounted
    test eax, eax
    jnz  .next
    mov  rdi, rbx
    call exfat_disk_device_mounted
    test eax, eax
    jnz  .next
    mov  rax, rbx
    mov  rdx, [rbx + dev.name]
.out:
    pop  rbx
    ret

; RDI=dev -> EAX 1 when a FAT mount this module holds already views it. No I/O.
fat32_disk_device_mounted:
    xor  eax, eax
    cmp  dword [rel fd_selected_ctx + FD_MOUNTED], 0
    je   .scratch
    cmp  rdi, [rel fd_selected_ctx + FD_DEV]
    je   .yes
.scratch:
    cmp  dword [rel fd_scratch_ctx + FD_MOUNTED], 0
    je   .data
    cmp  rdi, [rel fd_scratch_ctx + FD_DEV]
    je   .yes
.data:
    cmp  dword [rel fat32_disk_ctx + FD_MOUNTED], 0
    je   .out
    cmp  rdi, [rel fat32_disk_ctx + FD_DEV]
    jne  .out
.yes:
    mov  eax, 1
.out:
    ret

fat32_disk_scratch_off:
    call fd_scratch_owner
    test rax, rax
    jnz .out
    cmp dword [rel fd_scratch_ctx + FD_TX_BUSY], 0
    jne .busy
    mov byte [rel fd_scratch_armed], 0
    xor eax, eax
.out:
    ret
.busy:
    mov rax, -2
    ret

fd_scratch_owner:
    call storage_access_request_owner
    cmp eax, 1
    jne .no
    call storage_access_request_intent
    cmp eax, SA_INTENT_SPECIAL
    je .yes
    call storage_access_request_local   ; T5-15.4: fd_scratch_request binds the device
    cmp eax, 1
    jne .no
.yes:
    xor eax, eax
    ret
.no:
    mov rax, -3
    ret

; Non-choosing remount: never update geometry, identity or an arm.
fd_scratch_mount:
    mov byte [rel fd_scratch_armed], 0
    mov rdi, [rdi + fsmount.priv]
    jmp fd_scratch_current

; Same-volume, refuse-existing file copy on the exact OWNER-armed scratch
; mount. Reuse the FAT journal/step/cancel engine with its real context, never
; the compiled DATA context. Only BEGIN consumes current OWNER/SPECIAL; later
; bounded calls present the storage core's retained exact-partition job tag.
fd_scratch_copy:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, r8
    mov ebx, ecx
    lea rax, [rel fd_scratch_ops]
    cmp [rdi + fsmount.ops], rax
    jne .fail
    lea rax, [rel fd_scratch_ctx]
    cmp [rdi + fsmount.priv], rax
    jne .fail
    cmp ebx, FS_COPY_BEGIN_CARRIED
    je .carried
    cmp ebx, FS_COPY_BEGIN
    jne .existing
    test r9d, r9d                        ; selected simple file copy only: no TREE/replace/ask/queue
    jnz .fail
    cmp qword [rel fd_scratch_job_tag], 0
    jne .fail
    cmp dword [rel fd_cp_phase], FD_CP_IDLE
    jne .fail
    mov rdi, rax
    call fd_scratch_write_gate           ; current owner, GPT/BPB, medium and arm before grant
    test rax, rax
    jnz .fail
    mov rdi, [rel fd_scratch_ctx + FD_DEV]
    mov rsi, [rel fd_scratch_ctx + FD_PART_LBA]
    mov rdx, [rel fd_scratch_ctx + FD_PART_SECTORS]
    lea r8, [rel str_fd_scratch_gate]
    call storage_access_job_grant        ; under this request's intent, no carried intent/signer
    test rax, rax
    jle .fail
    mov [rel fd_scratch_job_tag], rax
    xor r9d, r9d
    jmp .invoke
.carried:
    ; A queued scratch BEGIN from vfs_copy_dequeue (rc-sec 105819 C9/C10, 105868 step 2). The carry,
    ; not the absent request, decides; the opener consumes it before any check and refuses
    ; mode, a retained job or a live phase exactly as the plain BEGIN above does. Its BEGIN
    ; writes then take fd_scratch_request's .carried_begin (step 2), never the live-request path.
    mov rdi, r15
    mov esi, r9d
    call fd_scratch_job_open_carried     ; -> tag > 0 / -1 (vfs_copy_refusal typed)
    test rax, rax
    jle .fail
    mov [rel fd_scratch_job_tag], rax
    mov byte [rel fd_scratch_job_step], 2 ; rc-sec 105868: the one writer of 2, after the tag is stored
    mov ebx, FS_COPY_BEGIN
    xor r9d, r9d
    jmp .invoke
.existing:
    cmp ebx, FS_COPY_STEP
    je .owned
    cmp ebx, FS_COPY_CANCEL
    jne .fail
.owned:
    cmp qword [rel fd_scratch_job_tag], 0
    je .fail
    cmp r15, [rel fd_cp_job]
    jne .fail
    lea rax, [rel fd_scratch_ctx]
    cmp rax, [rel fd_cp_ctx]
    jne .fail
    mov byte [rel fd_scratch_job_step], 1 ; only this callback may present the retained window
.invoke:
    mov rdi, r12
    mov rsi, r13
    mov rdx, r14
    mov ecx, ebx
    mov r8, r15
    call fat32_disk_copy
    mov rbx, rax
    mov byte [rel fd_scratch_job_step], 0
    mov rdi, [rel fd_scratch_job_tag]
    call storage_access_job_step_end     ; never leave the step's request grant ambient
    test rbx, rbx
    js .revoke                          ; refused BEGIN has no retained job
    cmp dword [rel fd_cp_phase], FD_CP_IDLE
    jne .result
.revoke:
    call fd_scratch_copy_close
.result:
    mov rax, rbx
    jmp .out
.fail:
    mov dword [rel fat32_disk_last_error], FD_ERR_NOT_EXACT
    mov rax, -1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ---------------------------------------------------------------------------
; FAT-scratch carried copy (ROOT105787 option A; rc-sec 105819 C1-C12, 105840).
; A queued FSCOPY on the exact armed fd_scratch mount carries its owner's console
; decision to the dequeue's BEGIN in its fs_copy_carry (kind FS_CARRY_FAT_SCRATCH;
; .owned_token holds the arm epoch). Recorded at FSCOPY (fd_scratch_carry_record),
; re-checked by the dequeue and the sweep (fd_scratch_carry_check), consumed once at
; BEGIN (fd_scratch_job_open_carried, called only from fd_scratch_copy). Compiled
; out of a public build exactly as EXT_W_OWNED (C2): nothing records, nothing opens.
%define FD_SCRATCH_CARRY 1
%ifdef PAOS_PUBLIC_BUILD
%if PAOS_PUBLIC_BUILD != 0
%define FD_SCRATCH_CARRY 0
%endif
%endif

; fd_scratch_carry_record(RDI=fsmount, RSI=fs_copy_carry, EDX=FS_CMODE_* of the FSCOPY)
;   -> RAX 0 recorded / -1 this enqueue carries nothing (job_active). C1: the
;   OWNER's own request, owned ops not latched, the full fd_scratch_owner. C3: the
;   live request passes fd_scratch_request's SPECIAL rule; the recorded intent is
;   exactly sa_intent_for(FD_DEV) (storage_access_intent_for_dev, D-a); UNKNOWN
;   class refused, SENSITIVE needs SPECIAL. C4: identity from fd_scratch_ctx,
;   snapshotted after fd_scratch_metadata and before the classify read, checked
;   again after it. C6: mode 0 only. Writes the carry only on success.
fd_scratch_carry_record:
%if FD_SCRATCH_CARRY
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, fs_copy_carry_size + 8
    mov  [rsp + fs_copy_carry_size], rsi
    mov  rbx, rdi
    mov  r13, rsp                        ; publish nothing until every check holds
    test edx, edx
    jnz  .no                             ; C6: a simple selected file copy (the BEGIN refuses any mode)
    lea  rax, [rel fd_scratch_ops]
    cmp  [rbx + fsmount.ops], rax
    jne  .no
    lea  r12, [rel fd_scratch_ctx]
    cmp  [rbx + fsmount.priv], r12
    jne  .no                             ; C7: the exact scratch mount
    cmp  byte [rel fd_scratch_armed], 1
    jne  .no
    call storage_access_request_owner
    cmp  eax, 1
    jne  .no                             ; C1: only the OWNER's own request carries
    call storage_access_owned_latched
    test eax, eax
    jnz  .no
    call fd_scratch_owner                ; C1: the full live predicate
    test rax, rax
    jnz  .no
    call storage_access_request_intent   ; C3 step 1: fd_scratch_request's own rule, on the live request
    cmp  eax, SA_INTENT_SPECIAL
    je   .special
    mov  rdi, [r12 + FD_DEV]
    call storage_access_intent_for_dev
    cmp  eax, SA_INTENT_SPECIAL
    jne  .no                             ; the live gate would refuse this request
.special:
    mov  rdi, [r12 + FD_DEV]
    call storage_access_intent_for_dev   ; C3: exactly sa_intent_for(FD_DEV)
    mov  r15d, eax
    call fd_scratch_metadata             ; C4: current medium + full GPT/table/BPB first
    test rax, rax
    jnz  .no
    mov  rax, [r12 + FD_DEV]             ; C4: snapshot before the classification read
    test rax, rax
    jz   .no
    mov  [r13 + fs_copy_carry.dev], rax
    mov  rdx, [r12 + FD_PART_LBA]
    mov  [r13 + fs_copy_carry.part_lba], rdx
    mov  rdx, [r12 + FD_PART_SECTORS]
    mov  [r13 + fs_copy_carry.part_sectors], rdx
    mov  rdx, [rax + dev.ops]
    mov  [r13 + fs_copy_carry.ops], rdx
    mov  rdx, [rax + dev.priv]
    mov  [r13 + fs_copy_carry.priv], rdx
    mov  rsi, [rax + dev.info]
    test rsi, rsi
    jz   .no
    mov  [r13 + fs_copy_carry.info], rsi
    mov  r14, [rel fd_scratch_generation]
    test r14, r14
    jz   .no
    cmp  r14, [rsi + blk_info.media_generation]
    jne  .no
    cmp  r14, [r12 + FD_MOUNT_GEN]
    jne  .no
    mov  [r13 + fs_copy_carry.gen], r14
    mov  rax, [rel fd_scratch_arm_epoch]
    test rax, rax
    jz   .no
    mov  [r13 + fs_copy_carry.owned_token], rax   ; C5/C6: the arm epoch (this kind has no owned token)
    mov  [r13 + fs_copy_carry.ctx], r12
    add  rsi, blk_info.sector_size
    lea  rdi, [r13 + fs_copy_carry.geometry]
    mov  edx, blk_info_size - blk_info.sector_size
    call memcpy
    call boot_ms_now
    mov  [r13 + fs_copy_carry.t_enqueue], rax
    mov  rdi, [r13 + fs_copy_carry.dev]
    mov  rsi, [r13 + fs_copy_carry.part_lba]
    mov  rdx, [r13 + fs_copy_carry.part_sectors]
    call storage_access_classify         ; a read of LBA 1: no grant, no window
    cmp  eax, SA_CLASS_UNKNOWN
    je   .no
    cmp  eax, SA_CLASS_SENSITIVE
    jne  .classed
    cmp  r15d, SA_INTENT_SPECIAL
    jne  .no                             ; as the gate would refuse this window under this intent
.classed:
    mov  [r13 + fs_copy_carry.class], eax
    mov  rdi, r13
    call fd_scratch_carry_check          ; the route, generation and arm still hold after that read
    test eax, eax
    jnz  .no
    mov  [r13 + fs_copy_carry.intent], r15d
    mov  dword [r13 + fs_copy_carry.owner], 1
    mov  rax, [rel fd_scratch_carry_seq]
    inc  rax
    jz   .no                             ; C6: 64-bit, never 0, never reissued
    mov  [rel fd_scratch_carry_seq], rax
    mov  [r13 + fs_copy_carry.id], rax
    mov  dword [r13 + fs_copy_carry.kind], FS_CARRY_FAT_SCRATCH
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
%else
    mov  rax, -1                         ; C2: a public build carries nothing
    ret
%endif

; fd_scratch_carry_check(RDI=fs_copy_carry) -> EAX 0 it still holds / the FS_CREF_*
;   it no longer holds by: mount_changed (not fd_scratch_ctx or unmounted, another
;   device, window, backend route, geometry or generation), arm_changed (disarmed,
;   or armed again: another epoch), carry_expired (older than FS_CARRY_MAX_AGE_MS).
;   No I/O, no grant. The dequeue (stamp op 3), the sweep (op 4), the record and
;   fd_scratch_job_open_carried ask it. Preserves RDI; clobbers RAX, RCX, RDX, R8.
fd_scratch_carry_check:
%if FD_SCRATCH_CARRY
    lea  r8, [rel fd_scratch_ctx]
    cmp  [rdi + fs_copy_carry.ctx], r8
    jne  .mount
    cmp  dword [r8 + FD_MOUNTED], 1
    jne  .mount
    mov  rax, [r8 + FD_DEV]
    test rax, rax
    jz   .mount
    cmp  rax, [rdi + fs_copy_carry.dev]
    jne  .mount
    mov  rcx, [r8 + FD_PART_LBA]
    cmp  rcx, [rdi + fs_copy_carry.part_lba]
    jne  .mount
    mov  rcx, [r8 + FD_PART_SECTORS]
    cmp  rcx, [rdi + fs_copy_carry.part_sectors]
    jne  .mount
    mov  rcx, [rax + dev.ops]
    cmp  rcx, [rdi + fs_copy_carry.ops]
    jne  .mount
    mov  rcx, [rax + dev.priv]
    cmp  rcx, [rdi + fs_copy_carry.priv]
    jne  .mount
    mov  rdx, [rax + dev.info]
    test rdx, rdx
    jz   .mount
    cmp  rdx, [rdi + fs_copy_carry.info]
    jne  .mount
    xor  ecx, ecx
.bytes:
    mov  al, [rdx + rcx + blk_info.sector_size]
    cmp  al, [rdi + rcx + fs_copy_carry.geometry]
    jne  .mount
    inc  ecx
    cmp  ecx, blk_info_size - blk_info.sector_size
    jb   .bytes
    mov  rax, [rel fd_scratch_generation]
    test rax, rax
    jz   .mount                          ; an unreadable generation counts as changed
    cmp  rax, [rdi + fs_copy_carry.gen]
    jne  .mount
    cmp  rax, [rdx + blk_info.media_generation]
    jne  .mount
    cmp  rax, [r8 + FD_MOUNT_GEN]
    jne  .mount
    cmp  byte [rel fd_scratch_armed], 1
    jne  .arm
    mov  rax, [rel fd_scratch_arm_epoch]
    test rax, rax
    jz   .arm
    cmp  rax, [rdi + fs_copy_carry.owned_token]
    jne  .arm                            ; C5: off then arm again is another epoch
    push rdi
    call boot_ms_now
    pop  rdi
    sub  rax, [rdi + fs_copy_carry.t_enqueue]
    cmp  rax, FS_CARRY_MAX_AGE_MS
    ja   .expired
    xor  eax, eax
    ret
.arm:
    mov  eax, FS_CREF_ARM_CHANGED
    ret
.expired:
    mov  eax, FS_CREF_CARRY_EXPIRED
    ret
%endif
.mount:
    mov  eax, FS_CREF_MOUNT_CHANGED
    ret

; fd_scratch_job_open_carried(RDI=the job: .carry -> its fs_copy_carry, ESI=FS_CMODE_*)
;   -> RAX the job tag > 0 / -1 (FD_ERR_NOT_EXACT; vfs_copy_refusal names
;   mount_changed, arm_changed, carry_expired or class_changed when that is why).
;   C9, failing on the first miss: the job's .carry is cleared and the carry itself
;   zeroed before any check; kind; an id at or below the last spent one never
;   begins (take-once); the plain BEGIN's own refusals (mode, a retained job, a live
;   engine); owner and ctx; the arm and its epoch; current medium + full GPT/BPB
;   and the carried route; age; owned ops not latched; the same class, SENSITIVE
;   only under a carried SPECIAL; the arm and medium again after that read;
;   fpw_gate and fd_data_write_gate; then the one carried grant. C10: this replaces
;   only fd_scratch_owner and fd_scratch_request's live-request pieces. Referenced
;   only from fd_scratch_copy (storage_grant_lint).
fd_scratch_job_open_carried:
%if FD_SCRATCH_CARRY
    push rbx
    push r13
    sub  rsp, fs_copy_carry_size + 8
    mov  r13d, esi
    mov  rbx, [rdi + fs_copy_job.carry]
    mov  qword [rdi + fs_copy_job.carry], 0   ; consumed before any check
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
    cmp  dword [rbx + fs_copy_carry.kind], FS_CARRY_FAT_SCRATCH
    jne  .denied
    mov  rax, [rbx + fs_copy_carry.id]
    cmp  rax, [rel fd_scratch_carry_spent]
    jbe  .denied                         ; take-once
    mov  [rel fd_scratch_carry_spent], rax
    test r13d, r13d
    jnz  .denied                         ; the plain BEGIN's refusals, unchanged
    cmp  qword [rel fd_scratch_job_tag], 0
    jne  .denied
    cmp  dword [rel fd_cp_phase], FD_CP_IDLE
    jne  .denied
    cmp  dword [rbx + fs_copy_carry.owner], 1
    jne  .denied
    lea  rax, [rel fd_scratch_ctx]
    cmp  [rbx + fs_copy_carry.ctx], rax
    jne  .mount
    call .medium                         ; arm + epoch, then medium, route and age
    test eax, eax
    jnz  .typed
    call storage_access_owned_latched
    test eax, eax
    jnz  .denied
    mov  rdi, [rbx + fs_copy_carry.dev]
    mov  rsi, [rbx + fs_copy_carry.part_lba]
    mov  rdx, [rbx + fs_copy_carry.part_sectors]
    call storage_access_classify
    cmp  eax, [rbx + fs_copy_carry.class]
    mov  eax, FS_CREF_CLASS_CHANGED
    jne  .typed                          ; a read fault classifies UNKNOWN, never the recorded class
    cmp  dword [rbx + fs_copy_carry.class], SA_CLASS_SENSITIVE
    jne  .class_ok
    cmp  dword [rbx + fs_copy_carry.intent], SA_INTENT_SPECIAL
    jne  .denied                         ; SENSITIVE only under a carried SPECIAL
.class_ok:
    call .medium                         ; the classification I/O changed nothing
    test eax, eax
    jnz  .typed
    lea  rdi, [rel fd_scratch_ctx]
    call fpw_gate
    test rax, rax
    jnz  .denied
    lea  rdi, [rel fd_scratch_ctx]
    call fd_data_write_gate
    test rax, rax
    jnz  .denied
    mov  rdi, [rel fd_scratch_ctx + FD_DEV]
    mov  rsi, [rel fd_scratch_ctx + FD_PART_LBA]
    mov  rdx, [rel fd_scratch_ctx + FD_PART_SECTORS]
    mov  ecx, [rbx + fs_copy_carry.intent]
    lea  r8, [rel str_fd_scratch_carried]
    ; rc-sec 105840 D-c: the shared job_grant body runs storage_access_require, which records a
    ; request grant for exactly this range (sa_grant_record). That grant admits no write alone:
    ; every BEGIN write still runs storage_access_job_require (this exact retained window) and
    ; then storage_access_write_admitted (with the live-Try refusal), and fd_scratch_copy's
    ; storage_access_job_step_end drops the grant right after the BEGIN step.
    call storage_access_job_grant_carried   ; tag > 0 / -1, under the CARRIED intent
    test rax, rax
    jle  .denied
    jmp  .out
.medium:                                 ; RBX = the spent copy -> EAX 0 / FS_CREF_*
    cmp  byte [rel fd_scratch_armed], 1
    jne  .m_arm
    mov  rax, [rel fd_scratch_arm_epoch]
    test rax, rax
    jz   .m_arm
    cmp  rax, [rbx + fs_copy_carry.owned_token]
    jne  .m_arm
    call fd_scratch_metadata             ; fd_scratch_current + GPT header, entries, BPB
    test rax, rax
    mov  eax, FS_CREF_MOUNT_CHANGED
    jnz  .m_out
    mov  rdi, rbx
    jmp  fd_scratch_carry_check          ; route, geometry, generation, arm, age
.m_arm:
    mov  eax, FS_CREF_ARM_CHANGED
.m_out:
    ret
.mount:
    mov  eax, FS_CREF_MOUNT_CHANGED
.typed:
    mov  [rel vfs_copy_refusal], eax
.denied:
    mov  dword [rel fat32_disk_last_error], FD_ERR_NOT_EXACT
    mov  rax, -1
.out:
    add  rsp, fs_copy_carry_size + 8
    pop  r13
    pop  rbx
    ret
%else
    mov  qword [rdi + fs_copy_job.carry], 0
    mov  dword [rel fat32_disk_last_error], FD_ERR_NOT_EXACT
    mov  rax, -1                         ; C2: a public build never begins a carried copy
    ret
%endif

fd_scratch_copy_close:
    mov rdi, [rel fd_scratch_job_tag]
    test rdi, rdi
    jz .out
    mov qword [rel fd_scratch_job_tag], 0
    mov byte [rel fd_scratch_job_step], 0
    jmp storage_access_job_revoke
.out:
    ret

; The VFS may fail a substituted mount without calling its former backend.
; Revoke that now-inert window and abandon memory only; old journal recovery
; requires a fresh admitted arm. Never reclaim via the substituted medium.
fd_scratch_copy_retire:
    cmp qword [rel fd_scratch_job_tag], 0
    je .out
    mov rax, [rel fd_cp_job]
    test rax, rax
    jz .out
    cmp dword [rax + fs_copy_job.state], FS_JOB_DONE
    jb .out
    cmp dword [rel fd_cp_phase], FD_CP_IDLE
    je fd_scratch_copy_close
    mov dword [rel fd_cp_phase], FD_CP_IDLE
    mov dword [rel fd_scratch_ctx + FD_TX_BUSY], 0
    mov dword [rel fd_scratch_ctx + FD_MOUNTED], 0
    mov byte [rel fd_scratch_armed], 0
    jmp fd_scratch_copy_close
.out:
    ret

; Pure admission hint. Real authority is repeated by every physical write.
fd_scratch_hint:
    xor eax, eax
    lea rdx, [rel fd_scratch_ops]
    cmp [rdi + fsmount.ops], rdx
    jne .out
    lea rdx, [rel fd_scratch_ctx]
    cmp [rdi + fsmount.priv], rdx
    jne .out
    cmp dword [rdx + FD_MOUNTED], 1
    jne .out
    cmp byte [rel fd_scratch_armed], 1
    jne .out
    mov eax, 1
.out:
    ret

; Preserve caller arguments. Internal directory views inherit ONLY their
; locked owner, never their address or the descriptor's exact-bound byte.
fd_scratch_current:
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
    lea rax, [rel fd_scratch_ctx]
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
    cmp rax, [rel fd_scratch_info]
    jne .fail
    test rax, rax
    jz .fail
    mov rdx, [rbx + dev.ops]
    cmp rdx, [rel fd_scratch_devops]
    jne .fail
    cmp dword [rax + blk_info.sector_size], 512
    jne .fail
    cmp dword [rax + blk_info.logical_sector_bytes], 512
    jne .fail
    test dword [rax + blk_info.flags], BLKF_RO
    jnz .fail
    mov rdx, [rel fd_scratch_max]
    cmp rdx, [rax + blk_info.lba_max]
    jne .fail
    mov rdx, [rel fd_scratch_generation]
    test rdx, rdx
    jz .fail
    cmp rdx, [rax + blk_info.media_generation]
    jne .fail
    cmp rdx, [rel fd_scratch_ctx + FD_MOUNT_GEN]
    jne .fail
.ok:
    xor eax, eax
    jmp .out
.fail:
    mov byte [rel fd_scratch_armed], 0
    mov dword [rel fd_scratch_ctx + FD_MOUNTED], 0
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

; Compare the complete admitted MBR or GPT/header/table and accepted BPB.
; Native reads go straight through blk_read; no recursion through read custody.
; No identity refresh is possible. 1..32 sectors, each at most one sector/IO.
fd_scratch_metadata:
    push rbx
    push r12
    lea rdi, [rel fd_scratch_ctx]
    call fd_scratch_current
    test rax, rax
    jnz .out
    mov rdi, [rel fd_scratch_ctx + FD_DEV]
    mov esi, 1
    cmp dword [rel fd_scratch_mbr_slot],0
    je .header
    xor esi,esi
.header:
    mov edx, 1
    lea rcx, [rel fd_scratch_check]
    call blk_read
    test rax, rax
    jnz .fail
    lea rdi, [rel fd_scratch_check]
    lea rsi, [rel fd_scratch_header]
    mov edx, 512
    call memcmp
    test rax, rax
    jnz .fail
    cmp dword [rel fd_scratch_mbr_slot],0
    jne .boot
    xor ebx, ebx
.table:
    mov rdi, [rel fd_scratch_ctx + FD_DEV]
    mov rsi, [rel fd_scratch_header + 72]
    add rsi, rbx
    mov edx, 1
    lea rcx, [rel fd_scratch_check]
    call blk_read
    test rax, rax
    jnz .fail
    mov eax, ebx
    shl eax, 9
    lea rsi, [rel fd_scratch_entries]
    add rsi, rax
    lea rdi, [rel fd_scratch_check]
    mov edx, 512
    call memcmp
    test rax, rax
    jnz .fail
    inc ebx
    cmp ebx, [rel fd_scratch_table_sectors]
    jb .table
.boot:
    mov rdi, [rel fd_scratch_ctx + FD_DEV]
    mov rsi, [rel fd_scratch_ctx + FD_PART_LBA]
    mov edx, 1
    lea rcx, [rel fd_scratch_check]
    call blk_read
    test rax, rax
    jnz .fail
    lea rdi, [rel fd_scratch_check]
    lea rsi, [rel fd_scratch_boot]
    mov edx, 512
    call memcmp
    test rax, rax
    jnz .fail
    lea rdi, [rel fd_scratch_ctx]
    call fd_scratch_current                ; identity again after every bounded read set
    jmp .out
.fail:
    mov byte [rel fd_scratch_armed], 0
    mov dword [rel fd_scratch_ctx + FD_MOUNTED], 0
    mov rax, -1
.out:
    pop r12
    pop rbx
    ret

; Ordinary scratch commands need current OWNER/SPECIAL admission. Only the
; bound copy callback may present its retained exact-partition job window; each
; physical effect still repeats admission and current-medium/metadata checks.
; Peter decision 10 (LEDGER 85949, 87106): an unowned FAT32 volume is writable in a public 0.1
; build only on removable media. Own partition A1 (Peter 107863, SEC 90335): a fixed FAT32 is
; writable only while fd_scratch_adopted_check binds and live-checks it, on every call, as an
; adopted volume that is not the DATA role; a local owner then gets SPECIAL for that exact
; partition only, never the device (sa_intent_for stays removable-only).
fd_scratch_request:
    mov byte [rel fd_scratch_adopted], 0
%ifdef PAOS_PUBLIC_BUILD
%if PAOS_PUBLIC_BUILD != 0
    mov rax,[rel fd_scratch_ctx + FD_DEV]
    test rax,rax
    jz .fail
    mov rax,[rax + dev.info]
    test rax,rax
    jz .fail
    cmp byte [rax + blk_info.removable],0
    jne .removable
    test dword [rax + blk_info.flags],BLKF_REMOVABLE
    jnz .removable
    cmp byte [rel fd_scratch_job_step], 0
    jne .fixed_check
    call fd_scratch_owner               ; own partition A4 (SEC-A1-3): ownership before the two probes
    test rax, rax
    jnz .out
.fixed_check:
    call fd_scratch_adopted_check
    test rax,rax
    jnz .fail
    mov byte [rel fd_scratch_adopted], 1
.removable:
%endif
%endif
    cmp byte [rel fd_scratch_job_step], 1
    je .job
    cmp byte [rel fd_scratch_job_step], 2
    je .carried_begin
    call fd_scratch_owner
    test rax, rax
    jnz .out
    call storage_access_request_intent
    cmp  eax, SA_INTENT_SPECIAL
    je   .signed
    mov  rdi, [rel fd_scratch_ctx + FD_DEV]
    call storage_access_intent_for_dev
    cmp  eax, SA_INTENT_SPECIAL
    je   .signed                        ; a local grant reaches removable alone
    call storage_access_request_local   ; A1: else only a local owner on an adopted fixed FAT32
    cmp  eax, 1
    jne  .fail
    cmp  byte [rel fd_scratch_adopted], 1
    je   .adopted
    call fd_scratch_adopted_check       ; a lab build has not checked yet
    test rax, rax
    jnz  .fail
.adopted:
    mov rdi, [rel fd_scratch_ctx + FD_DEV]
    mov rsi, [rel fd_scratch_ctx + FD_PART_LBA]
    mov rdx, [rel fd_scratch_ctx + FD_PART_SECTORS]
    mov ecx, SA_INTENT_SPECIAL          ; the exact partition: never the table or the device
    lea r8, [rel str_fd_scratch_gate]
    call storage_access_require
    test rax, rax
    jnz .out
    jmp .admitted
.signed:
    mov rdi, [rel fd_scratch_ctx + FD_DEV]
    mov rsi, [rel fd_scratch_ctx + FD_PART_LBA]
    mov rdx, [rel fd_scratch_ctx + FD_PART_SECTORS]
    lea r8, [rel str_fd_scratch_gate]
    call storage_access_require_request
    test rax, rax
    jnz .out
    jmp .admitted
.carried_begin:
    ; Step 2, the carried BEGIN only (rc-sec 105868): no live request and no running job yet,
    ; so neither fd_scratch_owner nor .job's fd_cp_ctx/FD_TX_BUSY binding (set later by this BEGIN)
    ; can hold. Its own window, an idle engine, the exact retained range and write_admitted can.
    mov rcx, [rel fd_scratch_job_tag]
    test rcx, rcx
    jz .fail
    cmp dword [rel fd_cp_phase], FD_CP_IDLE
    jne .fail                           ; fail closed: a moved phase is no BEGIN
    jmp .window
.job:
    lea rax, [rel fd_scratch_ctx]
    cmp [rel fd_cp_ctx], rax
    jne .fail
    cmp dword [rax + FD_TX_BUSY], 1
    jne .fail
    mov rcx, [rel fd_scratch_job_tag]
    test rcx, rcx
    jz .fail
.window:
    lea rax, [rel fd_scratch_ctx]
    mov rdi, [rax + FD_DEV]
    mov rsi, [rax + FD_PART_LBA]
    mov rdx, [rax + FD_PART_SECTORS]
    call storage_access_job_require      ; exact retained partition, never an ambient owner bit
    test rax, rax
    jnz .out
.admitted:
    mov rdi, [rel fd_scratch_ctx + FD_DEV]
    mov rsi, [rel fd_scratch_ctx + FD_PART_LBA]
    mov rdx, [rel fd_scratch_ctx + FD_PART_SECTORS]
    call storage_access_write_admitted
.out:
    ret
.fail:
    mov rax, -1
    ret

; fd_scratch_adopted_check -> RAX 0 / -1. Own partition A1 (SEC 90335): the scratch context's
; exact partition is, now, an adopted FAT32 that is not the DATA role, probed through the mount
; that holds the context: the scratch mount, or before its first registration the selected
; mount it was copied from.
fd_scratch_adopted_check:
    mov eax, [rel fd_scratch_handle]
    lea rsi, [rel fd_scratch_ctx]
    test eax, eax
    jnz .registered
    mov eax, [rel vfs_disk_handle]
    inc eax
    jz .no                              ; no selected mount
    lea rsi, [rel fd_selected_ctx]
.registered:
    dec eax
    mov edi, eax
    lea rdx, [rel fd_scratch_ctx]       ; the extent a grant would cover
    jmp fd_adopted_extent
.no:
    mov rax, -1
    ret

; fd_adopted_extent(EDI=mount handle, RSI=the FAT context that mount must hold, RDX=the context
; whose exact extent is checked) -> RAX 0 / -1. vol_owner_bind_mount runs a full live probe
; through the mount; vol_owner_live_check_files probes again and checks containment, epoch,
; sequence, media generation and that the entry is not the DATA role. Nothing is cached.
fd_adopted_extent:
    push rbx
    push r12
    push r13
    mov r12d, edi
    mov rbx, rsi
    mov r13, rdx
    mov rdi, [r13 + FD_DEV]
    call guest_volume_native_allowed    ; own partition A4 (SEC-A1-1): a guest volume job fences this device
    test rax, rax
    jnz .no
    mov edi, r12d
    call vfs_mount_ptr
    test rax, rax
    jz .no
    cmp [rax + fsmount.priv], rbx
    jne .no                             ; only a FAT context this module owns
    mov edi, r12d
    call vol_owner_bind_mount
    test rax, rax
    jz .no
    mov rcx, rax
    mov rdi, [r13 + FD_DEV]
    mov rsi, [r13 + FD_PART_LBA]
    mov rdx, [r13 + FD_PART_SECTORS]
    call vol_owner_live_check_files
    test eax, eax
    jnz .no
    xor eax, eax
    jmp .out
.no:
    mov rax, -1
.out:
    pop r13
    pop r12
    pop rbx
    ret

; This helper is inert for every existing context; callers retain their old
; authority. The scratch context and its locked directory view recheck all.
fd_scratch_write_gate:
    call fpw_gate
    test rax, rax
    jnz .data_return
    call fd_data_write_gate
    test rax, rax
    jnz .data_return
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
    jne .fail
    mov rdi, [rel fd_dir_owner]
    test rdi, rdi
    jz .fail
    cmp dword [rdi + FD_TX_BUSY], 1
    jne .fail
.context:
    lea rax, [rel fd_scratch_ctx]
    cmp rdi, rax
    jne .ordinary
    cmp byte [rel fd_scratch_armed], 1
    jne .fail
    cmp byte [rel fd_scratch_job_step], 1
    je .metadata
    cmp byte [rel fd_scratch_job_step], 2   ; the carried BEGIN (rc-sec 105868): its carry replaced the owner
    je .metadata
    call fd_scratch_owner
    test rax, rax
    jnz .out
.metadata:
    call fd_scratch_metadata
    test rax, rax
    jnz .out
    call fd_scratch_request
    jmp .out
.ordinary:
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

.data_return:
    ret

str_fd_scratch_name: db 'fat-scratch',0
fat32_disk_local_moved: db 0
fd_select_press: db 0
align 8, db 0
fd_local_start: dq 0
fd_local_sectors: dq 0
align 8, db 0
fd_local_disk: times 16 db 0
fd_local_part: times 16 db 0
fd_local_sector: times 512 db 0
align 8, db 0
fd_local_mbr_tuple: times 48 db 0
fd_local_mbr_recheck: times 48 db 0
str_fd_scratch_select: db 'select',0
str_fd_scratch_identity: db 'identity',0
str_fd_scratch_metadata: db 'metadata',0
str_fd_scratch_request: db 'request',0
str_fd_scratch_mount_register: db 'mount_register',0
str_fd_scratch_revalidate: db 'revalidate',0
str_fd_scratch_publish_request: db 'publish_request',0
str_fd_scratch_gate: db 'fs.fat32.owner_scratch',0
str_fd_scratch_carried: db 'fs.fat32.owner_scratch.carried',0
%macro WDATA_BSS_fs_fat32_owner_scratch 0
alignb 8
fd_scratch_ctx: resb FD_CTX_SIZE
fd_scratch_ops: resb fs_ops_size
fd_scratch_info: resq 1
fd_scratch_devops: resq 1
fd_scratch_generation: resq 1
fd_scratch_max: resq 1
fd_scratch_stage: resq 1
fd_scratch_job_tag: resq 1
fd_scratch_arm_epoch: resq 1         ; C5: the one writer is fat32_disk_scratch_arm's publish
fd_scratch_carry_seq: resq 1         ; C6: a carry id, never 0, never reissued
fd_scratch_carry_spent: resq 1       ; C9: take-once floor of the scratch kind
fd_scratch_job_step: resb 1
alignb 8
fd_scratch_handle: resd 1
fd_scratch_adopted: resb 1               ; A1: set by this call's public adopted check only
fd_scratch_table_sectors: resd 1
fd_scratch_mbr_slot: resd 1
alignb 8
fd_mbr_request_dev: resq 1
fd_mbr_zero_guid: resb 16
fd_mbr_tuple: resb 48
fd_mbr_recheck: resb 48
fd_scratch_armed: resb 1
alignb 8
fd_selected_gpt_saved: resb 512
fd_scratch_header: resb 512
fd_scratch_entries: resb 16384
fd_scratch_boot: resb 512
fd_scratch_check: resb 512
%endmacro
WDATA_BSS_DEFER WDATA_BSS_fs_fat32_owner_scratch

; The scratch copy uses the same read adapters, with independent custody.
fd_exact_read_current:
    call fd_selected_current
    test rax, rax
    jnz .out
    call fd_scratch_current
    test rax, rax
    jnz .out
    jmp fd_data_current
.out:
    ret

; Read-only image capability query. No mount, media IO or authority change.
fat32_disk_format_ops:
    lea  rax, [rel fat32_disk_ops]
    ret

%include "fs/fat32_copy_observation.asm"

%include "fs/data_config_provider.asm"

%include "fs/fat32_probe_window.asm"

%include "fs/update_esp.asm"
