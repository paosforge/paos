;; MODULE fs/exfat_disk
;; LAYER 4
;; EXPORTS exfat_disk_select_removable_gpt_ro, exfat_disk_mount_readonly
;; EXPORTS exfat_disk_select_removable_mbr_ro, exfat_refusal_reset, exfat_refusal_record, exfat_refusal_lookup, exfat_refusal_epoch, exfat_refusal_overflow, exfat_refusal_conflict, exfat_refusal_scan_limited, exfat_disk_copy_snapshot, exfat_disk_copy_read_begin, exfat_disk_copy_device, exfat_disk_copy_stat, exfat_disk_source_device, exfat_disk_source_bind, exfat_disk_source_token, exfat_disk_source_current, exfat_disk_source_stat, exfat_disk_source_read, exfat_disk_replace_state, exfat_disk_move_state, exfat_disk_move_destination_attempted, exfat_disk_move_destination_confirmed, exfat_disk_move_source_attempted, exfat_disk_move_source_confirmed, exfat_disk_arm, exfat_disk_disarm, exfat_disk_write_reclaimed, exfat_disk_write_reclaim_attempted, exfat_disk_write_reclaim_state, exfat_disk_write_allocation, exfat_disk_write_reserved, exfat_disk_write_reservation_attempted, exfat_disk_write_stage, exfat_disk_write_published, exfat_disk_write_dirty, exfat_disk_write_zeroed, exfat_disk_write_zero_attempted, exfat_disk_write_confirmed, exfat_disk_write_attempted, exfat_disk_register, exfat_disk_handle, exfat_disk_last_error, exfat_disk_mount_count, exfat_disk_part_type, exfat_disk_source_mtime, exfat_disk_format_ops
;; IMPORTS fs/small_copy, fs/fs_identify, fs/blockdev, fs/storage_access, fs/vfs, core/lib/mem, core/heap, core/time, boot/serial
;; CAPS CAP_BLOCK_READ, CAP_BLOCK_WRITE
;; OWNER saga:rcq20_filesystems
;; CONTEXT: bsp_only
; ============================================================================
; fs/exfat_disk.asm — native exFAT reader and bounded protected writer on VFS
; (RCQ-20-format-inventory-exfat-ro-S1, RC spec §7.5 additional formats).
; Media only through the blk device handle in each mount's private context:
; no controller symbol, no module-global "current mount".
; Registered namespace mutation: canonical 8.3 trees (<=4 components),
; one-cluster initialized NoFatChain ancestor directories, armed OWNER/SPECIAL.
; Whole-file replacement (FS_MUT_UPDATE/existing update slot) stages a new run,
; publishes a verified stream, then retires old allocation; names/attrs/times
; are preserved, interrupted metadata never authorizes reclaim.
; Same-media file/nonempty-directory moves publish destination before source
; retirement and retain all allocation. Every write rechecks both ancestor
; chains and exact namespace images; interrupted duplicates stay dirty.
; WRITE: root canonical name11 create (empty through64KiB, bounded contiguous
; allocation and single-device-sector entry publication), plus existing files,
; <=64 KiB/call (including any initialization gap),
; within DataLength, or extending an existing NoFatChain run into adjacent free
; clusters. Ordinary initialized overwrites preserve metadata.
; Preallocated initialization also zeroes gaps before durable VDL/checksum
; publication, bracketed by verified main VolumeDirty writes. Growth first
; reserves the bitmap durably; FAT and timestamps are unchanged. Whole-volume bounded
; ownership census rejects requested clusters shared with metadata/other files.
; Each 512-byte device sector is RMW, granted, flushed and read-back compared.
; On failure RAX=-1, last_error names the failure, write_confirmed is the
; verified prefix, write_attempted includes the uncertain current piece. No
; rollback or atomicity claim. All scratch is BSP nonyielding/non-reentrant.
;
; DISCOVERY: every healthy registered block device with 512-byte logical
;   sectors; a superfloppy volume, MBR primaries (extended containers skipped)
;   and GPT entries are probed for "EXFAT   " at byte 3 of the first sector.
;   Up to EXF_MAX_MOUNTS volumes mount as "exfat0", "exfat1".
;
; FAIL-CLOSED MOUNT (marker [fs.exfat.refused] reason=... and no mount):
;   * boot sector signature 0xAA55 and every extended boot sector's 0xAA550000;
;   * MustBeZero bytes 11..63 all zero; FileSystemRevision major 1;
;   * BytesPerSectorShift 9..12, SectorsPerClusterShift <= 25 - it;
;   * NumberOfFats 1 (2 = TexFAT, not supported) and ActiveFat 0;
;   * VolumeLength inside the partition; FatOffset >= 24; FatLength covers
;     ClusterCount + 2 entries; the FAT ends at or before ClusterHeapOffset;
;     ClusterCount in [1, 0xFFFFFFF5] and the heap ends inside VolumeLength;
;     the root cluster inside the heap;
;   * the boot-region checksum over sectors 0..10 (VolumeFlags and
;     PercentInUse excluded) equals every dword of sector 11;
;   * VolumeDirty or MediaFailure set: refused, never mounted silently;
;   * the root directory's chain, one Allocation Bitmap entry covering every
;     cluster (DataLength at most ceil(ClusterCount / 8) rounded up to one
;     cluster, so a crafted chain cannot stall the mount) and one Up-case Table
;     entry whose TableChecksum matches.
;
; READ SEMANTICS: directories are entry sets (File 0x85 + Stream 0xC0 +
;   FileName 0xC1); SecondaryCount in [1 + names, 18], every secondary in
;   bounds, SetChecksum and NameHash verified, names free of NUL, '/', '\\'
;   and the other characters exFAT forbids. Cluster chains follow the FAT
;   (every link inside the heap, loop-free by Brent's check, ending in EOC
;   exactly at the stream's last cluster) or a NoFatChain contiguous run
;   inside the heap. Bytes past ValidDataLength read as zero; nothing reads
;   past DataLength. Names list as UTF-8; lookups compare through the volume's
;   up-case table (case-insensitive) after strict UTF-8 decoding. "." and ".."
;   components are refused.
;
; ERRORS: every refused operation leaves a stable code in exfat_disk_last_error
;   (EXF_E_*): a bad SecondaryCount, SetChecksum, chain loop and out-of-heap
;   cluster each have their own code.
;
; CONCURRENCY: BSP only, non-reentrant, like fat32_disk. The entry-set, name,
;   path and listing scratch, the chain-check state and the file-read piece
;   length are module globals held across blk_read. No storage path yields
;   today; a yielding block backend needs per-call state here first.
; ============================================================================

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place

EXF_MAX_MOUNTS       equ 2
EXF_SEC_MAX          equ 4096                 ; largest supported filesystem sector (shift 12)
EXF_GPT_MAX          equ 128
EXF_PATH_MAX         equ 1024
EXF_NAME_MAX         equ 255                  ; UTF-16 code units
EXF_UTF8_MAX         equ 3 * EXF_NAME_MAX     ; a BMP name's worst UTF-8 length
EXF_DIR_MAX_BYTES    equ 0x10000000           ; 256 MiB: the format's directory bound
EXF_UPCASE_MAX       equ 0x20000              ; a full 65536-entry table, uncompressed
EXF_WRITE_MAX        equ 65536
EXF_WRITE_CLUSTERS   equ 4096                 ; max clusters in any census stream
EXF_WRITE_DIRS       equ 128
EXF_WRITE_ENTRIES    equ 8192
EXF_WRITE_BUDGET     equ 65536                ; aggregate census cluster visits
EXF_GROW_MAX        equ 128
EXF_GROW_BITMAPS    equ 2
EXF_WRITE_PLAN      equ 129                  ; max clusters touched by 64 KiB
EXF_XFER_MAX         equ 8                    ; sectors per blk_read (the proven AHCI op)
EXF_LIST_POOL_ENTRIES equ 66                  ; Explorer's 64 rows + 2 (as ext4_disk)
EXF_LIST_NAMES_CAP   equ EXF_LIST_POOL_ENTRIES * 256

; ---- boot sector (byte offsets) ----
EBS_NAME             equ 0x03
EBS_ZERO             equ 0x0B
EBS_ZERO_LEN         equ 53
EBS_PART_OFFSET      equ 0x40
EBS_VOL_LEN          equ 0x48
EBS_FAT_OFF          equ 0x50
EBS_FAT_LEN          equ 0x54
EBS_HEAP_OFF         equ 0x58
EBS_CLUS_COUNT       equ 0x5C
EBS_ROOT             equ 0x60
EBS_SERIAL           equ 0x64
EBS_REV              equ 0x68
EBS_FLAGS            equ 0x6A
EBS_BPS_SHIFT        equ 0x6C
EBS_SPC_SHIFT        equ 0x6D
EBS_NFATS            equ 0x6E
EBS_PCT_USE          equ 0x70
EBS_SIG              equ 0x1FE

EXF_VF_ACTIVE_FAT    equ 1
EXF_VF_DIRTY         equ 2
EXF_VF_MEDIA_FAIL    equ 4

; ---- FAT ----
EXF_FAT_BAD          equ 0xFFFFFFF7
EXF_FAT_EOC          equ 0xFFFFFFFF
EXF_CLUS_MAX         equ 0xFFFFFFF5

; ---- directory entries ----
EXF_DE_END           equ 0x00
EXF_DE_BITMAP        equ 0x81
EXF_DE_UPCASE        equ 0x82
EXF_DE_LABEL         equ 0x83
EXF_DE_FILE          equ 0x85
EXF_DE_STREAM        equ 0xC0
EXF_DE_NAME          equ 0xC1
EXF_DE_INUSE         equ 0x80
EXF_DE_SECONDARY     equ 0x40
EXF_DE_BENIGN        equ 0x20
EXF_ATTR_DIR         equ 0x10
EXF_SF_ALLOC         equ 1                    ; GeneralSecondaryFlags.AllocationPossible
EXF_SF_NOFATCHAIN    equ 2
EXF_SEC_COUNT_MAX    equ 18
EXF_NAME_PER_ENTRY   equ 15

; ---- mount refusal reasons (16-byte names in exf_reason_names) ----
EXF_R_BOOTSIG        equ 1
EXF_R_ZERO           equ 2
EXF_R_REV            equ 3
EXF_R_SECTOR         equ 4
EXF_R_CLUSTER        equ 5
EXF_R_FATS           equ 6
EXF_R_LAYOUT         equ 7
EXF_R_CSUM           equ 8
EXF_R_DIRTY          equ 9
EXF_R_MEDIA          equ 10
EXF_R_ROOT           equ 11
EXF_R_BITMAP         equ 12
EXF_R_UPCASE         equ 13
EXF_R_NOMEM          equ 14
EXF_R_IO             equ 15
EXF_R_NOMOUNT        equ 16

; ---- per-operation errors (exfat_disk_last_error) ----
EXF_E_NONE           equ 0
EXF_E_NOTFOUND       equ 1
EXF_E_CORRUPT        equ 2
EXF_E_IO             equ 3
EXF_E_UNSUPPORTED    equ 4
%define EXF_PUBLIC_MEDIA_GATE 0
%ifdef PAOS_PUBLIC_BUILD
%if PAOS_PUBLIC_BUILD != 0
%define EXF_PUBLIC_MEDIA_GATE 1
%endif
%endif
EXF_E_AUTH           equ 9
EXF_E_STALE          equ 10
EXF_E_READONLY       equ 11
EXF_E_VERIFY         equ 12
EXF_E_FLUSH          equ 13
EXF_E_NOSPACE        equ 14
EXF_E_EXISTS         equ 15
EXF_E_NAME_INVALID   equ 16                  ; actual forbidden mutation-name unit
EXF_E_PATH_LONG      equ 17                  ; existing63-byte mutation path bound
EXF_E_RANGE          equ 5
EXF_E_NOTDIR         equ 6
EXF_E_BADPATH        equ 7
EXF_E_ISDIR          equ 8
EXF_E_SECCOUNT       equ 20                   ; SecondaryCount out of range for the set
EXF_E_SETCSUM        equ 21                   ; SetChecksum mismatch
EXF_E_LOOP           equ 22                   ; a FAT chain revisits a cluster
EXF_E_CLUSTER        equ 23                   ; a cluster outside the heap, or a short chain
EXF_E_NAMEHASH       equ 24                   ; NameHash does not match the name

EXF_WALK_LOOKUP      equ 0
EXF_WALK_LIST        equ 1

; One located stream: a directory or file, as its Stream Extension describes it.
struc exf_strm
  .first:          resd 1                ; first cluster (0 = no allocation)
  .flags:          resd 1                ; GeneralSecondaryFlags
  .attr:           resd 1                ; FileAttributes of the owning File entry
  .pad:            resd 1
  .valid:          resq 1                ; ValidDataLength
  .length:         resq 1                ; DataLength
endstruc

; Complete bounded bitmap transaction plan, shared with growth's exact keys.
struc exf_r_plan
  .count:    resd 1
  .clusters: resd EXF_GROW_BITMAPS
  .bits:     resd EXF_GROW_BITMAPS
  .lbas:     resq EXF_GROW_BITMAPS
  .old:      resb 512 * EXF_GROW_BITMAPS
  .new:      resb 512 * EXF_GROW_BITMAPS
endstruc

; One mount's private context; the up-case table (EXF_UPCASE_MAX) and two
; EXF_SEC_MAX buffers follow it in the same allocation.
struc exf_ctx
  .dev:            resq 1
  .part_lba:       resq 1
  .part_sectors:   resq 1
  .vol_sectors:    resq 1                ; VolumeLength (filesystem sectors)
  .fat_off:        resq 1                ; filesystem sectors
  .heap_off:       resq 1
  .upcase:         resq 1                ; -> 65536 UTF-16 code units
  .sec_buf:        resq 1                ; directory/data sector cache
  .sec_tag:        resq 1                ; filesystem sector held in sec_buf (-1 none)
  .fat_buf:        resq 1                ; FAT sector cache
  .fat_tag:        resq 1
  .name:           resq 1                ; -> "exfat0"/"exfat1"
  .it_left:        resq 1                ; directory iterator: bytes left in the stream
  .map_idx:        resq 1                ; exf_map cache: cluster index ...
  .it_clus:        resd 1                ; directory iterator: current cluster
  .it_coff:        resd 1                ;   byte offset inside it
  .it_nofat:       resd 1                ;   EXF_SF_NOFATCHAIN of the stream
  .map_clus:       resd 1                ; ... and its cluster
  .clus_count:     resd 1
  .root_clus:      resd 1
  .fat_len:        resd 1
  .serial:         resd 1
  .sec_shift:      resd 1                ; BytesPerSectorShift
  .spc_shift:      resd 1                ; SectorsPerClusterShift
  .clus_shift:     resd 1                ; sec_shift + spc_shift
  .dev_shift:      resd 1                ; sec_shift - 9 (device sectors per filesystem sector)
  .scheme:         resd 1
  .xfer:           resd 1
  .mounted:        resd 1
  .handle:         resd 1
  .vflags:         resd 1
  .pad:            resd 1
  .media_gen:      resq 1
  .info_identity:  resq 1
  .ops_identity:   resq 1
  .boot_identity:  resb 120
  .bitmap:         resb exf_strm_size
  .upstream:       resb exf_strm_size
  .root:           resb exf_strm_size    ; the root directory as a stream
  .dir:            resb exf_strm_size    ; directory being walked
  .leaf:           resb exf_strm_size    ; resolved leaf / listed child
  .incarnation:    resq 1               ; assigned once per registered context, not refresh
  .armed:          resd 1
  .arm_serial:     resd 1
  .arm_self:       resq 1
  .arm_dev:        resq 1
  .arm_info:       resq 1
  .arm_ops:        resq 1
  .arm_gen:        resq 1
  .arm_part:       resq 1
  .arm_sectors:    resq 1
  .arm_incarnation: resq 1
  .arm_handle:     resq 1
  .arm_boot:       resb 120
endstruc

EXF_CTX_ALLOC equ exf_ctx_size + EXF_UPCASE_MAX + 2 * EXF_SEC_MAX

; ---------------------------------------------------------------------------
; exfat_disk_register() -> RAX = handle of the first exFAT mount / -1.
;   Probes every registered block device, mounts up to EXF_MAX_MOUNTS valid,
;   clean exFAT volumes read-only and registers each as a VFS mount. Emits
;   [fs.exfat.mounted] per mount, [fs.exfat.refused] per rejected volume and
;   [fs.exfat.skipped] when nothing mounted. Never writes.
; ---------------------------------------------------------------------------
exfat_disk_register:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  dword [rel exfat_disk_handle], -1
    mov  dword [rel exfat_disk_mount_count], 0
    mov  qword [rel exf_src_contexts], 0
    mov  qword [rel exf_src_contexts + 8], 0
    call exfat_refusal_reset
    call exf_build_ops
    xor  r13d, r13d                      ; previous dev*
.dev:
    cmp  dword [rel exfat_disk_mount_count], EXF_MAX_MOUNTS
    jae  .done
    mov  rdi, r13
    xor  esi, esi                        ; every healthy device
    xor  edx, edx
    call blk_iter_after
    test rax, rax
    jz   .done
    mov  r13, rax
    mov  rdi, rax
    call exf_scan_device
    jmp  .dev
.done:
    cmp  dword [rel exfat_disk_mount_count], 0
    jne  .some
    lea  rdi, [rel str_exf_skipped]
    call serial_string
    mov  rax, -1
    jmp  .out
.some:
    movsxd rax, dword [rel exfat_disk_handle]
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; exfat_disk_select_removable_mbr_ro(RDI=opaque row dev*) -> handle / -1,
; -2 busy. BSP only, non-reentrant, after boot registration. The Explorer caller
; owns its local owner/focus/frame gates. This helper only reads: no request
; authority, arm, recovery, write or flush. Append one uniquely identified 0x07
; MBR primary without resetting any existing exFAT context. GPT uses its own entry.
; Separate GPT entry: same original eligibility/validator/publication path,
; strict shared GPT BASIC DATA query, independent complete96-byte recheck.
exfat_disk_select_removable_gpt_ro:
    mov byte [rel exf_sel_gpt],1
    jmp exf_sel_begin
exfat_disk_select_removable_mbr_ro:
    mov byte [rel exf_sel_gpt],0
exf_sel_begin:
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
    cmp dword [rel exfat_disk_mount_count],EXF_MAX_MOUNTS
    jae .no
    ; Resolve the opaque row before dereferencing it, even on refusal.
    mov rdi,rbx
    call exf_sel_member
    test rax,rax
    jz .no
    mov rdi,rbx
    call exfat_disk_device_mounted
    test eax,eax
    jnz .no
    mov rdi,rbx
    call guest_volume_native_allowed
    test rax,rax
    jnz .no
    mov rax,[rbx+dev.info]
    mov [rel exf_sel_identity],rax
    mov rdx,[rbx+dev.ops]
    mov [rel exf_sel_identity+8],rdx
    mov rdx,[rbx+dev.priv]
    mov [rel exf_sel_identity+16],rdx
    mov rdx,[rax+blk_info.media_generation]
    test rdx,rdx
    jz .no
    mov [rel exf_sel_identity+24],rdx
    mov rdx,[rax+blk_info.lba_max]
    mov [rel exf_sel_identity+32],rdx
    mov [rel exf_sel_device],rbx
    mov byte [rel exf_sel_reading],1
    call exf_sel_current
    test rax,rax
    jnz .no
    mov rdi,rbx
    xor esi,esi
    xor edx,edx
    lea rcx,[rel exf_sel_primary]
    lea r8,[rel exf_sel_current]
    call exf_sel_query
    test rax,rax
    jnz .no
    call exf_sel_current
    test rax,rax
    jnz .no
    mov rdi,rbx
    mov rsi,[rel exf_sel_primary+16]
    mov edx,1
    lea rcx,[rel exf_sel_vbr]
    call exf_raw_read
    test rax,rax
    jnz .no
    mov rax,'EXFAT   '
    cmp [rel exf_sel_vbr+EBS_NAME],rax
    jne .no
    lea rdi,[rel exf_boot_buf]
    lea rsi,[rel exf_sel_vbr]
    mov edx,512
    call memcpy
    mov r13d,[rel exfat_disk_mount_count]
    test r13d,r13d
    jnz .ops_ready
    call exf_build_ops
.ops_ready:
    mov rdi,rbx
    mov rsi,[rel exf_sel_primary+16]
    mov rdx,[rel exf_sel_primary+24]
    mov ecx,[rel exf_sel_primary+36]
    lea r8,[rel exf_sel_recheck]
    mov byte [rel exf_sel_reading],1
    call exf_try_mount_checked
    mov byte [rel exf_sel_reading],0
    mov eax,[rel exfat_disk_mount_count]
    sub eax,r13d
    cmp eax,1
    jne .no
    lea rax,[rel exf_src_contexts]
    mov r12,[rax+r13*8]
    mov eax,[r12+exf_ctx.handle]
    mov [rel vfs_disk_handle],eax
    jmp .out
.busy:
    mov rax,-2
    jmp .out
.no:
    mov rax,-1
.out:
    mov byte [rel exf_sel_reading],0
    pop r13
    pop r12
    pop rbx
    ret

; RCX is caller-owned out96 (MBR uses original48 only). All original
; identity/eligibility checks remain in exf_sel_current. No fallback from GPT.
exf_sel_query:
    cmp byte [rel exf_sel_gpt],0
    je .mbr
    mov esi,1
    jmp fs_identify_single_gpt_checked
.mbr:
    push rcx
    call fs_identify_primary_checked
    pop rcx
    test rax,rax
    jnz .out
    cmp dword [rcx+36],FS_SCHEME_MBR
    jne .no
    cmp dword [rcx+40],0x07
    jne .no
.out:
    ret
.no:
    mov rax,-1
    ret

; Opaque dev -> current native readable removable dev / 0. No media I/O.
exf_sel_member:
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
exf_sel_current:
    mov rdi,[rel exf_sel_device]
    call exf_sel_member
    test rax,rax
    jz .no
    mov rdx,[rax+dev.info]
    cmp rdx,[rel exf_sel_identity]
    jne .no
    mov rcx,[rax+dev.ops]
    cmp rcx,[rel exf_sel_identity+8]
    jne .no
    mov rcx,[rax+dev.priv]
    cmp rcx,[rel exf_sel_identity+16]
    jne .no
    mov rcx,[rdx+blk_info.media_generation]
    cmp rcx,[rel exf_sel_identity+24]
    jne .no
    mov rcx,[rdx+blk_info.lba_max]
    cmp rcx,[rel exf_sel_identity+32]
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
; compare the original48 MBR or complete96 GPT tuple and original VBR. No partial mount
; is visible if any parser-time device/table/boot identity changed.
exf_sel_recheck:
    call exf_sel_current
    test rax,rax
    jnz .out
    mov rdi,[rel exf_sel_device]
    xor esi,esi
    xor edx,edx
    lea rcx,[rel exf_sel_again]
    lea r8,[rel exf_sel_current]
    call exf_sel_query
    test rax,rax
    jnz .out
    lea rdi,[rel exf_sel_primary]
    lea rsi,[rel exf_sel_again]
    mov ecx,6
    cmp byte [rel exf_sel_gpt],0
    je .compare
    mov ecx,12
.compare:
    repe cmpsq
    jne .no
    call exf_sel_current
    test rax,rax
    jnz .out
    mov rdi,[rel exf_sel_device]
    mov rsi,[rel exf_sel_primary+16]
    mov edx,1
    lea rcx,[rel exf_sel_vbr_again]
    call exf_raw_read
    test rax,rax
    jnz .out
    lea rdi,[rel exf_sel_vbr]
    lea rsi,[rel exf_sel_vbr_again]
    mov ecx,64
    repe cmpsq
    jne .no
    jmp exf_sel_current
.no:
    mov rax,-1
.out:
    ret

; exf_scan_device(RDI=dev*): superfloppy, MBR primaries, GPT entries.
exf_scan_device:
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
    cmp  dword [rax + blk_info.sector_size], 512
    jne  .out                            ; 512-byte device arithmetic only (as ext4_disk)
    mov  rdi, r12
    xor  esi, esi
    mov  edx, 1
    lea  rcx, [rel exf_scan_buf]
    call exf_raw_read
    test rax, rax
    jnz  .out
    ; an exFAT boot sector also carries 0xAA55 and a zero "partition table"
    ; (MustBeZero covers 11..63, the table lives at 446): probe it first
    mov  rax, 'EXFAT   '
    cmp  [rel exf_scan_buf + EBS_NAME], rax
    je   .superfloppy
    cmp  word [rel exf_scan_buf + 510], 0xAA55
    jne  .out
    mov  rax, [rel exf_scan_buf + 446]
    or   rax, [rel exf_scan_buf + 454]
    or   rax, [rel exf_scan_buf + 462]
    or   rax, [rel exf_scan_buf + 470]
    or   rax, [rel exf_scan_buf + 478]
    or   rax, [rel exf_scan_buf + 486]
    or   rax, [rel exf_scan_buf + 494]
    or   rax, [rel exf_scan_buf + 502]
    jnz  .table
    jmp  .out
.superfloppy:
    mov  rdi, r12
    xor  esi, esi
    mov  rdx, r15
    mov  ecx, FS_SCHEME_SUPERFLOPPY
    call exf_probe
    jmp  .out
.table:
    xor  r13d, r13d
.mbr:
    cmp  r13d, 4
    jae  .out
    mov  eax, r13d
    shl  eax, 4
    lea  rbx, [rel exf_scan_buf + 446]
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
    push rbx
    mov  rdi, r12
    mov  ecx, FS_SCHEME_MBR
    call exf_probe
    pop  rbx
    ; exf_probe reads into its own buffer; the MBR stays in exf_scan_buf
.mbr_next:
    inc  r13d
    jmp  .mbr
.gpt:
    mov  rdi, r12
    mov  esi, 1
    mov  edx, 1
    lea  rcx, [rel exf_scan_buf]
    call exf_raw_read
    test rax, rax
    jnz  .out
    mov  rax, 0x5452415020494645         ; "EFI PART"
    cmp  [rel exf_scan_buf], rax
    jne  .out
    cmp  dword [rel exf_scan_buf + 84], 128
    jne  .out
    mov  r14, [rel exf_scan_buf + 72]    ; entries LBA
    test r14, r14
    jz   .out
    mov  eax, [rel exf_scan_buf + 80]
    cmp  eax, EXF_GPT_MAX
    jbe  .count_ok
    mov  eax, EXF_GPT_MAX
.count_ok:
    mov  [rel exf_gpt_count], eax
    xor  r13d, r13d
.gpt_entry:
    cmp  r13d, [rel exf_gpt_count]
    jae  .out
    test r13d, 3
    jnz  .have_sector
    mov  esi, r13d
    shr  esi, 2
    add  rsi, r14
    jc   .out
    mov  rdi, r12
    mov  edx, 1
    lea  rcx, [rel exf_scan_buf]
    call exf_raw_read
    test rax, rax
    jnz  .out
.have_sector:
    mov  eax, r13d
    and  eax, 3
    shl  eax, 7
    lea  rbx, [rel exf_scan_buf]
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
    call exf_probe
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

; exf_probe(RDI=dev, RSI=part lba, RDX=sectors, ECX=scheme) -> RAX 1 = an exFAT
;   boot sector was found (mounted or refused), 0 = not exFAT. The boot sector
;   goes to exf_boot_buf; exf_scan_buf is preserved.
exf_probe:
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
    cmp  r14, 24                         ; the main boot region alone is 12 sectors of >= 512 B
    jb   .out
    mov  rdi, r12
    mov  rsi, r13
    mov  edx, 1
    lea  rcx, [rel exf_boot_buf]
    call exf_raw_read
    test rax, rax
    jnz  .out
    mov  rax, 'EXFAT   '
    cmp  [rel exf_boot_buf + EBS_NAME], rax
    jne  .out
    mov  ebx, 1
    cmp  dword [rel exfat_disk_mount_count], EXF_MAX_MOUNTS
    jae  .out
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, r14
    mov  ecx, r15d
    call exf_try_mount
.out:
    mov  eax, ebx
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; exf_try_mount(RDI=dev, RSI=lba, RDX=sectors, ECX=scheme): boot sector in
; exf_boot_buf. Mounts + registers, or emits the refusal. A refused context is
; kept as the spare for the next candidate (the heap is a bump allocator).
exf_try_mount:
    xor r8d,r8d                       ; ordinary boot scan has no late selector
; Internal R8=optional pre-publication read-only validator. R12=candidate.
exf_try_mount_checked:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 32                        ; original identity + optional validator
    mov [rsp+24],r8
    mov  rax, [rdi + dev.info]
    mov  [rsp], rax
    mov  rax, [rdi + dev.ops]
    mov  [rsp + 8], rax
    mov  rax, [rdi + dev.info]
    mov  rax, [rax + blk_info.media_generation]
    mov  [rsp + 16], rax
    mov  r13, rdi
    mov  r14, rsi
    mov  r15, rdx
    mov  ebx, ecx
    mov  r12, [rel exf_spare_ctx]
    test r12, r12
    jnz  .have_ctx
    mov  rdi, EXF_CTX_ALLOC
    call kmalloc
    test rax, rax
    jnz  .alloc_ok
    mov  rdi, r13
    mov  rsi, r14
    mov  edx, EXF_R_NOMEM
    mov  rcx, r15                       ; exact candidate extent, not reused spare ctx
    lea  r8, [rsp]                      ; [info identity, ops identity, original generation]
    call exfat_refusal_record
    call exf_emit_refused
    jmp  .out
.alloc_ok:
    mov  r12, rax
    mov  [rel exf_spare_ctx], rax
.have_ctx:
    mov  rdi, r12
    xor  esi, esi
    mov  edx, exf_ctx_size
    call memset
    lea  rax, [r12 + exf_ctx_size]
    mov  [r12 + exf_ctx.upcase], rax
    add  rax, EXF_UPCASE_MAX
    mov  [r12 + exf_ctx.sec_buf], rax
    add  rax, EXF_SEC_MAX
    mov  [r12 + exf_ctx.fat_buf], rax
    mov  qword [r12 + exf_ctx.sec_tag], -1
    mov  qword [r12 + exf_ctx.fat_tag], -1
    mov  dword [r12 + exf_ctx.handle], -1
    mov  [r12 + exf_ctx.dev], r13
    mov  [r12 + exf_ctx.part_lba], r14
    mov  [r12 + exf_ctx.part_sectors], r15
    mov  [r12 + exf_ctx.scheme], ebx
    mov  eax, [rel exfat_disk_mount_count]
    imul eax, eax, 7
    lea  rdx, [rel str_exf_mount_names]
    add  rax, rdx
    mov  [r12 + exf_ctx.name], rax
    mov  rax, [r13 + dev.info]
    mov  ecx, [rax + blk_info.max_transfer_sectors]
    cmp  qword [rax + blk_info.capabilities], 0
    je   .xfer_default                   ; pre-2912 backend: the field is not declared
    test ecx, ecx
    jz   .xfer_default
    cmp  ecx, EXF_XFER_MAX
    jbe  .xfer_set
.xfer_default:
    mov  ecx, EXF_XFER_MAX
.xfer_set:
    mov  [r12 + exf_ctx.xfer], ecx
    call exf_mount_ctx
    test eax, eax
    jz   .mounted
    mov  rdi, r13
    mov  rsi, r14
    mov  edx, eax
    mov  rcx, r15                       ; exact candidate extent, not reused spare ctx
    lea  r8, [rsp]                      ; [info identity, ops identity, original generation]
    call exfat_refusal_record
    call exf_emit_refused
    jmp  .out
.mounted:
    mov rax,[rsp+24]
    test rax,rax
    jz .identity
    call rax
    test rax,rax
    jnz .out                           ; private spare remains unpublished
.identity:
    mov  rax, [r13 + dev.info]
    mov  [r12 + exf_ctx.info_identity], rax
    mov  rax, [rax + blk_info.media_generation]
    mov  [r12 + exf_ctx.media_gen], rax
    mov  rax, [r13 + dev.ops]
    mov  [r12 + exf_ctx.ops_identity], rax
    lea  rdi, [r12 + exf_ctx.boot_identity]
    lea  rsi, [rel exf_boot_buf]
    mov  edx, 120
    call memcpy
    mov  dword [r12 + exf_ctx.mounted], 1
    lea  rdi, [rel exf_ops]
    mov  rsi, r12
    mov  rdx, [r12 + exf_ctx.name]
    call vfs_register_mount
    test rax, rax
    jns  .registered
    mov  dword [r12 + exf_ctx.mounted], 0
    mov  rdi, r13
    mov  rsi, r14
    mov  edx, EXF_R_NOMOUNT
    mov  rcx, r15                       ; exact candidate extent, not reused spare ctx
    lea  r8, [rsp]                      ; [info identity, ops identity, original generation]
    call exfat_refusal_record
    call exf_emit_refused
    jmp  .out
.registered:
    mov  [r12 + exf_ctx.handle], eax
    inc  qword [rel exf_a_incarnation_next]
    mov  rax, [rel exf_a_incarnation_next]
    mov  [r12 + exf_ctx.incarnation], rax
    call exf_src_register
    mov  eax, [r12 + exf_ctx.handle]
    cmp  dword [rel exfat_disk_mount_count], 0
    jne  .not_first
    mov  [rel exfat_disk_handle], eax
.not_first:
    inc  dword [rel exfat_disk_mount_count]
    mov  qword [rel exf_spare_ctx], 0
    call exf_emit_mounted
.out:
    add  rsp, 32
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; exf_mount_ctx(R12=ctx; boot sector in exf_boot_buf) -> EAX 0 mounted /
;   EXF_R_* reason. Validates the main boot region, then loads the root
;   directory's Allocation Bitmap and Up-case Table entries.
exf_mount_ctx:
    push rbx
    push r13
    push r14
    push r15
    lea  rbx, [rel exf_boot_buf]
    cmp  word [rbx + EBS_SIG], 0xAA55
    jne  .bootsig
    cmp  word [rbx], 0x76EB              ; JumpBoot EB 76 90
    jne  .bootsig
    cmp  byte [rbx + 2], 0x90
    jne  .bootsig
    xor  ecx, ecx
.zero:
    cmp  byte [rbx + EBS_ZERO + rcx], 0
    jne  .mustzero
    inc  ecx
    cmp  ecx, EBS_ZERO_LEN
    jb   .zero
    cmp  byte [rbx + EBS_REV + 1], 1     ; FileSystemRevision major
    jne  .revision
    movzx ecx, byte [rbx + EBS_BPS_SHIFT]
    cmp  ecx, 9
    jb   .sector
    cmp  ecx, 12
    ja   .sector
    mov  [r12 + exf_ctx.sec_shift], ecx
    lea  eax, [rcx - 9]
    mov  [r12 + exf_ctx.dev_shift], eax
    movzx eax, byte [rbx + EBS_SPC_SHIFT]
    mov  edx, 25
    sub  edx, ecx
    cmp  eax, edx
    ja   .cluster
    mov  [r12 + exf_ctx.spc_shift], eax
    add  eax, ecx
    mov  [r12 + exf_ctx.clus_shift], eax
    cmp  byte [rbx + EBS_NFATS], 1       ; 2 = TexFAT
    jne  .fats
    movzx eax, word [rbx + EBS_FLAGS]
    mov  [r12 + exf_ctx.vflags], eax
    test eax, EXF_VF_ACTIVE_FAT          ; the second FAT does not exist
    jnz  .fats
    ; ---- layout: every region inside the volume, the volume inside the partition
    mov  rax, [rbx + EBS_VOL_LEN]
    test rax, rax
    jz   .layout
    mov  rdx, [r12 + exf_ctx.part_sectors]
    mov  ecx, [r12 + exf_ctx.dev_shift]
    shr  rdx, cl
    cmp  rax, rdx
    ja   .layout
    mov  [r12 + exf_ctx.vol_sectors], rax
    mov  r13, rax                        ; VolumeLength
    mov  eax, [rbx + EBS_FAT_OFF]
    cmp  eax, 24
    jb   .layout
    mov  [r12 + exf_ctx.fat_off], rax
    mov  r14d, [rbx + EBS_FAT_LEN]
    test r14d, r14d
    jz   .layout
    mov  [r12 + exf_ctx.fat_len], r14d
    mov  r15d, [rbx + EBS_CLUS_COUNT]
    test r15d, r15d
    jz   .layout
    cmp  r15d, EXF_CLUS_MAX
    ja   .layout
    mov  [r12 + exf_ctx.clus_count], r15d
    lea  rax, [r15 + 2]                  ; FAT entries 0..ClusterCount+1
    shl  rax, 2
    mov  rdx, r14
    mov  ecx, [r12 + exf_ctx.sec_shift]
    shl  rdx, cl
    cmp  rax, rdx
    ja   .layout
    mov  rax, [r12 + exf_ctx.fat_off]
    add  rax, r14                        ; end of the (single) FAT
    mov  edx, [rbx + EBS_HEAP_OFF]
    cmp  rax, rdx
    ja   .layout
    mov  [r12 + exf_ctx.heap_off], rdx
    mov  rax, r15
    mov  ecx, [r12 + exf_ctx.spc_shift]
    shl  rax, cl                         ; < 2^48: no overflow
    add  rax, rdx
    cmp  rax, r13
    ja   .layout
    mov  eax, [rbx + EBS_ROOT]
    cmp  eax, 2
    jb   .root
    lea  rdx, [r15 + 1]
    cmp  rax, rdx
    ja   .root
    mov  [r12 + exf_ctx.root_clus], eax
    mov  eax, [rbx + EBS_SERIAL]
    mov  [r12 + exf_ctx.serial], eax
    ; ---- boot checksum over sectors 0..10 against every dword of sector 11
    xor  r13d, r13d                      ; checksum
    xor  r14d, r14d                      ; sector
.csum_sector:
    mov  rsi, r14
    call exf_sec_get
    test rax, rax
    jz   .io
    mov  rdi, rax
    mov  ecx, [r12 + exf_ctx.sec_shift]
    mov  edx, 1
    shl  edx, cl                         ; sector bytes
    cmp  r14d, 11
    je   .csum_compare
    cmp  r14d, 1
    jb   .sum
    cmp  r14d, 8
    ja   .sum
    cmp  dword [rdi + rdx - 4], 0xAA550000   ; extended boot signature
    jne  .bootsig
.sum:
    xor  ecx, ecx
.sum_byte:
    test r14d, r14d
    jnz  .take
    cmp  ecx, EBS_FLAGS                  ; VolumeFlags (2 bytes) and PercentInUse
    je   .skip
    cmp  ecx, EBS_FLAGS + 1
    je   .skip
    cmp  ecx, EBS_PCT_USE
    je   .skip
.take:
    ror  r13d, 1
    movzx eax, byte [rdi + rcx]
    add  r13d, eax
.skip:
    inc  ecx
    cmp  ecx, edx
    jb   .sum_byte
    inc  r14d
    jmp  .csum_sector
.csum_compare:
    xor  ecx, ecx
.csum_dword:
    cmp  [rdi + rcx], r13d
    jne  .checksum
    add  ecx, 4
    cmp  ecx, edx
    jb   .csum_dword
    ; ---- a volume the writer did not finish, or one on failing media
    mov  eax, [r12 + exf_ctx.vflags]
    test eax, EXF_VF_DIRTY
    jnz  .dirty
    test eax, EXF_VF_MEDIA_FAIL
    jnz  .media
    ; ---- the root directory: its whole chain, its size from the chain
    mov  esi, [r12 + exf_ctx.root_clus]
    xor  edx, edx                        ; measure
    call exf_chain_walk
    test rax, rax
    js   .root
    mov  ecx, [r12 + exf_ctx.clus_shift]
    shl  rax, cl
    lea  rdi, [r12 + exf_ctx.root]
    mov  edx, [r12 + exf_ctx.root_clus]
    mov  [rdi + exf_strm.first], edx
    mov  dword [rdi + exf_strm.flags], EXF_SF_ALLOC
    mov  dword [rdi + exf_strm.attr], EXF_ATTR_DIR
    mov  [rdi + exf_strm.valid], rax
    mov  [rdi + exf_strm.length], rax
    call exf_mount_root_scan
    jmp  .out
.bootsig:
    mov  eax, EXF_R_BOOTSIG
    jmp  .out
.mustzero:
    mov  eax, EXF_R_ZERO
    jmp  .out
.revision:
    mov  eax, EXF_R_REV
    jmp  .out
.sector:
    mov  eax, EXF_R_SECTOR
    jmp  .out
.cluster:
    mov  eax, EXF_R_CLUSTER
    jmp  .out
.fats:
    mov  eax, EXF_R_FATS
    jmp  .out
.layout:
    mov  eax, EXF_R_LAYOUT
    jmp  .out
.checksum:
    mov  eax, EXF_R_CSUM
    jmp  .out
.dirty:
    mov  eax, EXF_R_DIRTY
    jmp  .out
.media:
    mov  eax, EXF_R_MEDIA
    jmp  .out
.root:
    mov  eax, EXF_R_ROOT
    jmp  .out
.io:
    mov  eax, EXF_R_IO
.out:
    mov  qword [r12 + exf_ctx.sec_tag], -1
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

; exf_mount_root_scan(R12=ctx; ctx.root set) -> EAX 0 / EXF_R_*. Finds the
;   Allocation Bitmap (0x81) and Up-case Table (0x82) entries, checks both
;   streams and loads the up-case table. A second entry of either type anywhere
;   in the root refuses the volume.
exf_mount_root_scan:
    push rbx
    push r13
    push r14
    push r15
    xor  r13d, r13d                      ; bitmap found
    xor  r14d, r14d                      ; up-case first cluster (0 = not found)
    lea  rdi, [r12 + exf_ctx.root]
    call exf_dir_open
.entry:
    test r13d, r13d
    jz   .read
    test r14d, r14d
    jnz  .found_both
.read:
    call exf_next_set
    test rax, rax
    js   .root
    jz   .ended
    cmp  rax, 2
    jne  .entry                          ; file sets: structure checked, otherwise ignored here
    movzx eax, byte [rel exf_set_buf]
    cmp  eax, EXF_DE_BITMAP
    je   .bitmap
    cmp  eax, EXF_DE_UPCASE
    jne  .entry
    test r14d, r14d
    jnz  .upcase                         ; a second table
    mov  r14d, [rel exf_set_buf + 20]
    mov  eax, [rel exf_set_buf + 4]
    mov  [rel exf_up_csum], eax
    mov  rax, [rel exf_set_buf + 24]
    mov  [rel exf_up_len], rax
    test r14d, r14d
    jz   .upcase
    jmp  .entry
.bitmap:
    test r13d, r13d
    jnz  .bad_bitmap                     ; a second bitmap needs TexFAT
    test byte [rel exf_set_buf + 1], 1   ; BitmapFlags: the first (only) bitmap
    jnz  .bad_bitmap
    mov  rax, [rel exf_set_buf + 24]
    mov  edx, [r12 + exf_ctx.clus_count]
    add  rdx, 7
    shr  rdx, 3
    cmp  rax, rdx
    jb   .bad_bitmap
    mov  ecx, [r12 + exf_ctx.clus_shift]
    mov  r8d, 1
    shl  r8, cl
    dec  r8
    add  rdx, r8
    not  r8
    and  rdx, r8                         ; ceil(ClusterCount / 8) rounded up to one cluster
    cmp  rax, rdx
    ja   .bad_bitmap                     ; longer: its chain walk is unbounded work at mount
    lea  rdi, [r12 + exf_ctx.leaf]
    mov  edx, [rel exf_set_buf + 20]
    call exf_fixed_strm
    lea  rdi, [r12 + exf_ctx.leaf]
    call exf_chain_check
    test rax, rax
    jnz  .bad_bitmap
    lea  rdi, [r12 + exf_ctx.bitmap]
    lea  rsi, [r12 + exf_ctx.leaf]
    mov  edx, exf_strm_size
    call memcpy
    mov  r13d, 1
    jmp  .entry
.ended:
    test r13d, r13d
    jz   .bad_bitmap
    test r14d, r14d
    jz   .upcase
.found_both:
    ; the rest of the root must hold no second Allocation Bitmap (TexFAT) or
    ; Up-case Table: raw entries to the end marker (a valid File set never
    ; holds a primary type, so a 0x81/0x82 byte here is always a primary)
.dup_scan:
    call exf_dir_next
    test rax, rax
    js   .root
    jz   .dup_done
    movzx eax, byte [rax]
    test eax, eax
    jz   .dup_done
    cmp  eax, EXF_DE_BITMAP
    je   .bad_bitmap
    cmp  eax, EXF_DE_UPCASE
    je   .upcase
    jmp  .dup_scan
.dup_done:
    mov  rax, [rel exf_up_len]
    test rax, rax
    jz   .upcase
    test eax, 1
    jnz  .upcase
    cmp  rax, EXF_UPCASE_MAX
    ja   .upcase
    lea  rdi, [r12 + exf_ctx.leaf]
    mov  edx, r14d
    call exf_fixed_strm
    lea  rdi, [r12 + exf_ctx.leaf]
    call exf_chain_check
    test rax, rax
    jnz  .upcase
    lea  rdi, [r12 + exf_ctx.upstream]
    lea  rsi, [r12 + exf_ctx.leaf]
    mov  edx, exf_strm_size
    call memcpy
    call exf_upcase_load
    test rax, rax
    jnz  .upcase
    xor  eax, eax
    jmp  .out
.bad_bitmap:
    mov  eax, EXF_R_BITMAP
    jmp  .out
.upcase:
    mov  eax, EXF_R_UPCASE
    jmp  .out
.root:
    mov  eax, EXF_R_ROOT
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

; exf_fixed_strm(RDI=exf_strm*, EDX=first cluster, RAX=DataLength): a FAT-chained
;   system stream whose ValidDataLength is its DataLength.
exf_fixed_strm:
    mov  [rdi + exf_strm.first], edx
    mov  dword [rdi + exf_strm.flags], EXF_SF_ALLOC
    mov  dword [rdi + exf_strm.attr], 0
    mov  dword [rdi + exf_strm.pad], 0
    mov  [rdi + exf_strm.valid], rax
    mov  [rdi + exf_strm.length], rax
    ret

; exf_upcase_load(R12=ctx; ctx.leaf = the table's stream) -> RAX 0/-1.
;   TableChecksum over the stored bytes; decompresses into ctx.upcase (identity
;   first; 0xFFFF n = n identity entries; entries past U+FFFF ignored).
exf_upcase_load:
    push rbx
    push r13
    push r14
    push r15
    mov  rdi, [r12 + exf_ctx.upcase]
    xor  eax, eax
.ident:
    mov  [rdi + rax * 2], ax
    inc  eax
    cmp  eax, 0x10000
    jb   .ident
    xor  r13d, r13d                      ; checksum
    xor  r14d, r14d                      ; table index
    xor  r15d, r15d                      ; offset in the stream
    xor  ebx, ebx                        ; 1 = the previous unit was 0xFFFF
.chunk:
    mov  rcx, [r12 + exf_ctx.leaf + exf_strm.length]
    sub  rcx, r15
    jz   .done
    cmp  rcx, 512
    jbe  .sized
    mov  ecx, 512
.sized:
    mov  [rel exf_up_chunk_len], ecx
    mov  rsi, r15
    lea  rdx, [rel exf_chunk]
    call exf_file_read
    test rax, rax
    js   .fail
    xor  ecx, ecx
.byte:
    ror  r13d, 1
    lea  rdx, [rel exf_chunk]
    movzx eax, byte [rdx + rcx]
    add  r13d, eax
    inc  ecx
    cmp  ecx, [rel exf_up_chunk_len]
    jb   .byte
    xor  ecx, ecx
.unit:
    lea  rdx, [rel exf_chunk]
    movzx eax, word [rdx + rcx]
    test ebx, ebx
    jz   .not_skip
    add  r14, rax                        ; a run of identity entries
    xor  ebx, ebx
    jmp  .unit_next
.not_skip:
    cmp  rax, r14
    je   .identity
    cmp  eax, 0xFFFF
    jne  .map
    mov  ebx, 1
    jmp  .unit_next
.map:
    cmp  r14, 0x10000
    jae  .identity
    mov  rdx, [r12 + exf_ctx.upcase]
    mov  [rdx + r14 * 2], ax
.identity:
    inc  r14
.unit_next:
    add  ecx, 2
    cmp  ecx, [rel exf_up_chunk_len]
    jb   .unit
    mov  eax, [rel exf_up_chunk_len]
    add  r15, rax
    jmp  .chunk
.done:
    cmp  r13d, [rel exf_up_csum]
    jne  .fail
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
; Media access
; ---------------------------------------------------------------------------
; exf_raw_read(RDI=dev, RSI=lba, RDX=count, RCX=buf) -> RAX 0/-1.
;   512-byte device sectors, whole request inside the device, EXF_XFER_MAX (or
;   the device's declared limit) per blk_read, single-sector fallback.
exf_raw_read:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rdx
    mov  r14, rcx
    call exf_sel_guard
    test rax,rax
    jnz .fail
    call exf_src_guard
    test rax, rax
    jnz  .fail
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
    mov  rax, [rbx + dev.info]
    mov  ecx, EXF_XFER_MAX
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
    mov  rdi, rbx
    mov  rsi, r12
    mov  rdx, r15
    mov  rcx, r14
    call exf_sel_block_read
    test rax, rax
    jz   .advance
    mov  rdi, rbx
    call exf_src_guard
    test rax, rax
    jnz  .fail
    cmp  r15, 1
    jbe  .fail
.one:
    test r15, r15
    jz   .fell_back
    mov  rdi, rbx
    mov  rsi, r12
    mov  edx, 1
    mov  rcx, r14
    call exf_sel_block_read
    test rax, rax
    jnz  .fail
    inc  r12
    add  r14, 512
    dec  r13
    dec  r15
    jmp  .one
.fell_back:
    inc  qword [rel exf_rd_fallback]
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
exf_sel_guard:
    cmp byte [rel exf_sel_reading],0
    je .ordinary
    push rdi
    push rsi
    push rdx
    push rcx
    call exf_sel_current
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    ret
.ordinary:
    xor eax,eax
    ret
exf_sel_block_read:
    call exf_sel_guard
    test rax,rax
    jnz .out
    call exf_src_block_read
    push rax
    call exf_sel_guard
    test rax,rax
    pop rax
    jz .out
    mov rax,-1
.out:
    ret

; exf_read_fs(R12=ctx, RSI=filesystem sector, RDX=count, RCX=buf) -> RAX 0/-1.
;   Every sector inside VolumeLength (so inside the partition).
exf_read_fs:
    test rdx, rdx
    jz   .fail
    mov  rax, rsi
    add  rax, rdx
    jc   .fail
    cmp  rax, [r12 + exf_ctx.vol_sectors]
    ja   .fail
    mov  r8, rcx
    mov  ecx, [r12 + exf_ctx.dev_shift]
    shl  rsi, cl
    shl  rdx, cl
    add  rsi, [r12 + exf_ctx.part_lba]
    mov  rcx, r8
    mov  rdi, [r12 + exf_ctx.dev]
    jmp  exf_raw_read
.fail:
    mov  rax, -1
    ret

; exf_sec_get(R12=ctx, RSI=filesystem sector) -> RAX = ctx.sec_buf holding it / 0
;   (exfat_disk_last_error = EXF_E_IO).
exf_sec_get:
    cmp  rsi, [r12 + exf_ctx.sec_tag]
    je   .hit
    push rsi
    mov  edx, 1
    mov  rcx, [r12 + exf_ctx.sec_buf]
    call exf_read_fs
    pop  rsi
    test rax, rax
    jnz  .fail
    mov  [r12 + exf_ctx.sec_tag], rsi
.hit:
    mov  rax, [r12 + exf_ctx.sec_buf]
    ret
.fail:
    mov  qword [r12 + exf_ctx.sec_tag], -1
    mov  dword [rel exfat_disk_last_error], EXF_E_IO
    xor  eax, eax
    ret

; exf_fat_get(R12=ctx, ESI=cluster in [2, ClusterCount+1]) -> RAX = FAT entry
;   (zero-extended) / -1 (EXF_E_IO). The mount proved the FAT holds the entry.
exf_fat_get:
    push rbx
    mov  ebx, esi
    mov  rax, rbx
    shl  rax, 2
    mov  ecx, [r12 + exf_ctx.sec_shift]
    shr  rax, cl
    add  rax, [r12 + exf_ctx.fat_off]
    cmp  rax, [r12 + exf_ctx.fat_tag]
    je   .hit
    push rax
    mov  rsi, rax
    mov  edx, 1
    mov  rcx, [r12 + exf_ctx.fat_buf]
    call exf_read_fs
    pop  rdx
    test rax, rax
    jnz  .io
    mov  [r12 + exf_ctx.fat_tag], rdx
.hit:
    mov  ecx, [r12 + exf_ctx.sec_shift]
    mov  edx, 1
    shl  edx, cl
    dec  edx
    lea  eax, [rbx * 4]
    and  eax, edx
    mov  rdx, [r12 + exf_ctx.fat_buf]
    mov  eax, [rdx + rax]
    pop  rbx
    ret
.io:
    mov  qword [r12 + exf_ctx.fat_tag], -1
    mov  dword [rel exfat_disk_last_error], EXF_E_IO
    mov  rax, -1
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; Cluster chains
; ---------------------------------------------------------------------------
; exf_chain_walk(R12=ctx, ESI=first cluster (in range), RDX=n) -> RAX clusters / -1.
;   n > 0: the chain must hold exactly n clusters and end in EOC.
;   n = 0: measure a directory chain of at most min(ClusterCount, 256 MiB).
;   Every link must name a heap cluster (EXF_E_CLUSTER otherwise: bad-cluster
;   marks, free entries, links past ClusterCount + 1, short or long chains);
;   Brent's cycle check reports a revisit as EXF_E_LOOP. The walk stops after
;   4 * limit + 4 links whatever the FAT says.
exf_chain_walk:
    push rbx
    push r13
    push r14
    push r15
    mov  r13d, esi                       ; current
    mov  r14, rdx                        ; n
    mov  r15, rdx                        ; limit
    test r15, r15
    jnz  .limited
    mov  r15d, EXF_DIR_MAX_BYTES
    mov  ecx, [r12 + exf_ctx.clus_shift]
    shr  r15, cl
    mov  eax, [r12 + exf_ctx.clus_count]
    cmp  r15, rax
    jbe  .limited
    mov  r15, rax
.limited:
    mov  ebx, r13d                       ; Brent tortoise
    mov  qword [rel exf_bw_count], 1
    mov  qword [rel exf_bw_power], 1
    mov  qword [rel exf_bw_lam], 0
.step:
    cmp  dword [rel exf_w_active], 0
    je   .read_step
    cmp  qword [rel exf_bw_count], EXF_WRITE_CLUSTERS
    ja   .unsupported
.read_step:
    mov  esi, r13d
    call exf_fat_get
    test rax, rax
    js   .fail
    call exf_src_link
    test rax, rax
    js   .fail
    cmp  eax, EXF_FAT_EOC
    jne  .link
    mov  rax, [rel exf_bw_count]
    test r14, r14
    jz   .measured
    cmp  rax, r14
    je   .out
    jmp  .cluster
.measured:
    cmp  rax, r15
    ja   .cluster
    jmp  .out
.link:
    cmp  eax, 2
    jb   .cluster
    mov  edx, [r12 + exf_ctx.clus_count]
    inc  rdx
    cmp  rax, rdx
    ja   .cluster
    cmp  eax, ebx
    je   .loop
    inc  qword [rel exf_bw_lam]
    mov  rdx, [rel exf_bw_lam]
    cmp  rdx, [rel exf_bw_power]
    jne  .keep
    mov  ebx, eax
    shl  qword [rel exf_bw_power], 1
    mov  qword [rel exf_bw_lam], 0
.keep:
    mov  r13d, eax
    inc  qword [rel exf_bw_count]
    mov  rdx, [rel exf_bw_count]
    lea  rcx, [r15 * 4 + 4]
    cmp  rdx, rcx
    ja   .cluster
    jmp  .step
.unsupported:
    mov  dword [rel exfat_disk_last_error], EXF_E_UNSUPPORTED
    jmp  .fail
.loop:
    mov  dword [rel exfat_disk_last_error], EXF_E_LOOP
    jmp  .fail
.cluster:
    mov  dword [rel exfat_disk_last_error], EXF_E_CLUSTER
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

; exf_strm_range(R12=ctx, RDI=exf_strm*) -> RAX 0 / -1 (EXF_E_CLUSTER / CORRUPT).
;   No allocation: DataLength 0. Otherwise DataLength 0 has FirstCluster 0, and
;   a sized stream's clusters (FAT: its first; NoFatChain: all of them) lie
;   inside the heap.
exf_strm_range:
    mov  rax, [rdi + exf_strm.length]
    test dword [rdi + exf_strm.flags], EXF_SF_ALLOC
    jnz  .alloc
    test rax, rax
    jnz  .corrupt
    xor  eax, eax
    ret
.alloc:
    test rax, rax
    jnz  .sized
    cmp  dword [rdi + exf_strm.first], 0
    jne  .corrupt
    ret                                  ; RAX = 0
.sized:
    mov  ecx, [r12 + exf_ctx.clus_shift]
    mov  rdx, rax
    shr  rdx, cl                         ; whole clusters
    mov  r8d, 1
    shl  r8, cl
    dec  r8
    test rax, r8
    jz   .count
    inc  rdx
.count:
    mov  r8d, [r12 + exf_ctx.clus_count]
    cmp  rdx, r8
    ja   .cluster
    mov  eax, [rdi + exf_strm.first]
    cmp  eax, 2
    jb   .cluster
    inc  r8                              ; last heap cluster
    cmp  rax, r8
    ja   .cluster
    test dword [rdi + exf_strm.flags], EXF_SF_NOFATCHAIN
    jz   .ok
    lea  rax, [rax + rdx - 1]
    cmp  rax, r8
    ja   .cluster
.ok:
    xor  eax, eax
    ret
.cluster:
    mov  dword [rel exfat_disk_last_error], EXF_E_CLUSTER
    mov  rax, -1
    ret
.corrupt:
    mov  dword [rel exfat_disk_last_error], EXF_E_CORRUPT
    mov  rax, -1
    ret

; exf_chain_check(R12=ctx, RDI=exf_strm*) -> RAX 0/-1: the range checks, then
;   (FAT-chained) the walk of exactly ceil(DataLength / cluster) clusters.
exf_chain_check:
    push rbx
    mov  rbx, rdi
    ; The writer's finite admission bound applies during resolve/mount refresh,
    ; before the reader could walk a hostile huge chain. Ordinary reads retain
    ; their existing format limits. Census also bounds the aggregate visits.
    cmp  dword [rel exf_w_active], 0
    je   .reader_range
    mov  rax, [rbx + exf_strm.length]
    test dword [rbx + exf_strm.attr], EXF_ATTR_DIR
    jz   .write_count
    cmp  rax, 0x100000
    ja   .write_bound
.write_count:
    mov  ecx, [r12 + exf_ctx.clus_shift]
    mov  rdx, 1
    shl  rdx, cl
    dec  rdx
    add  rax, rdx
    jc   .write_bound
    shr  rax, cl
    cmp  rax, EXF_WRITE_CLUSTERS
    ja   .write_bound
.reader_range:
    call exf_strm_range
    test rax, rax
    jnz  .out
    mov  rdx, [rbx + exf_strm.length]
    test rdx, rdx
    jz   .out                            ; RAX = 0
    test dword [rbx + exf_strm.flags], EXF_SF_NOFATCHAIN
    jnz  .out
    mov  ecx, [r12 + exf_ctx.clus_shift]
    mov  rax, rdx
    shr  rdx, cl
    mov  r8d, 1
    shl  r8, cl
    dec  r8
    test rax, r8
    jz   .walk
    inc  rdx
.walk:
    mov  esi, [rbx + exf_strm.first]
    call exf_chain_walk
    test rax, rax
    js   .out
    xor  eax, eax
    jmp  .out
.write_bound:
    mov  dword [rel exfat_disk_last_error], EXF_E_UNSUPPORTED
    mov  rax, -1
.out:
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; Directories
; ---------------------------------------------------------------------------
; exf_dir_open(R12=ctx, RDI=exf_strm* of a checked directory chain)
exf_dir_open:
    mov  eax, [rdi + exf_strm.first]
    mov  [r12 + exf_ctx.it_clus], eax
    mov  dword [r12 + exf_ctx.it_coff], 0
    mov  rax, [rdi + exf_strm.length]
    mov  [r12 + exf_ctx.it_left], rax
    mov  eax, [rdi + exf_strm.flags]
    and  eax, EXF_SF_NOFATCHAIN
    mov  [r12 + exf_ctx.it_nofat], eax
    ret

; exf_dir_next(R12=ctx) -> RAX = the next 32-byte entry (inside ctx.sec_buf,
;   valid until the next read) / 0 at the end of the stream / -1.
exf_dir_next:
    cmp  qword [r12 + exf_ctx.it_left], 0
    je   .end
    mov  ecx, [r12 + exf_ctx.clus_shift]
    mov  eax, 1
    shl  rax, cl
    cmp  [r12 + exf_ctx.it_coff], eax
    jb   .in_cluster
    mov  esi, [r12 + exf_ctx.it_clus]
    cmp  dword [r12 + exf_ctx.it_nofat], 0
    je   .fat
    inc  esi
    jmp  .check
.fat:
    call exf_fat_get
    test rax, rax
    js   .fail
    mov  esi, eax
.check:
    cmp  esi, 2
    jb   .cluster
    mov  eax, [r12 + exf_ctx.clus_count]
    inc  rax
    cmp  rsi, rax
    ja   .cluster
    mov  [r12 + exf_ctx.it_clus], esi
    mov  dword [r12 + exf_ctx.it_coff], 0
.in_cluster:
    mov  eax, [r12 + exf_ctx.it_clus]
    sub  eax, 2
    mov  ecx, [r12 + exf_ctx.spc_shift]
    shl  rax, cl
    mov  edx, [r12 + exf_ctx.it_coff]
    mov  ecx, [r12 + exf_ctx.sec_shift]
    shr  edx, cl
    add  rax, rdx
    add  rax, [r12 + exf_ctx.heap_off]
    mov  rsi, rax
    call exf_sec_get
    test rax, rax
    jz   .fail
    mov  ecx, [r12 + exf_ctx.sec_shift]
    mov  edx, 1
    shl  edx, cl
    dec  edx
    and  edx, [r12 + exf_ctx.it_coff]
    add  rax, rdx
    add  dword [r12 + exf_ctx.it_coff], 32
    sub  qword [r12 + exf_ctx.it_left], 32
    ret
.end:
    xor  eax, eax
    ret
.cluster:
    mov  dword [rel exfat_disk_last_error], EXF_E_CLUSTER
.fail:
    mov  rax, -1
    ret

; exf_next_set(R12=ctx) -> RAX 1 = a File entry set in exf_set_buf (its
;   SecondaryCount in exf_set_count), 2 = a Bitmap/Up-case/Label entry in
;   exf_set_buf, 0 = end of directory, -1 = refused. Unused entries and benign
;   primaries (with their in-use secondaries) are skipped.
exf_next_set:
    push rbx
    push r13
.scan:
    call exf_dir_next
    test rax, rax
    js   .fail
    jz   .out
    movzx ecx, byte [rax]
    test ecx, ecx
    jz   .end                            ; end-of-directory marker
    test ecx, EXF_DE_INUSE
    jz   .scan
    mov  rsi, rax
    lea  rdi, [rel exf_set_buf]
    mov  edx, 32
    call memcpy
    movzx ecx, byte [rel exf_set_buf]
    cmp  ecx, EXF_DE_FILE
    je   .file
    test ecx, EXF_DE_SECONDARY
    jnz  .corrupt                        ; an in-use secondary with no primary
    cmp  ecx, EXF_DE_BITMAP
    je   .special
    cmp  ecx, EXF_DE_UPCASE
    je   .special
    cmp  ecx, EXF_DE_LABEL
    je   .special
    test ecx, EXF_DE_BENIGN
    jz   .corrupt                        ; an unknown critical primary
    movzx r13d, byte [rel exf_set_buf + 1]
.benign:
    test r13d, r13d
    jz   .scan
    call exf_dir_next
    test rax, rax
    js   .fail
    jz   .out
    movzx ecx, byte [rax]
    and  ecx, EXF_DE_INUSE | EXF_DE_SECONDARY
    cmp  ecx, EXF_DE_INUSE | EXF_DE_SECONDARY
    jne  .corrupt                        ; its count must not swallow a primary or free slot
    dec  r13d
    jmp  .benign
.special:
    mov  eax, 2
    jmp  .out
.file:
    ; Physical primary location survives sets spanning sectors/clusters.
    mov  eax, [r12 + exf_ctx.it_clus]
    sub  eax, 2
    mov  ecx, [r12 + exf_ctx.spc_shift]
    shl  rax, cl
    add  rax, [r12 + exf_ctx.heap_off]
    mov  ecx, [r12 + exf_ctx.sec_shift]
    shl  rax, cl
    mov  edx, [r12 + exf_ctx.it_coff]
    lea  rax, [rax + rdx - 32]
    mov  [rel exf_set_location], rax
    movzx r13d, byte [rel exf_set_buf + 1]
    cmp  r13d, 2
    jb   .seccount
    cmp  r13d, EXF_SEC_COUNT_MAX
    ja   .seccount
    mov  [rel exf_set_count], r13d
    lea  rbx, [rel exf_set_buf + 32]
.secondary:
    call exf_dir_next
    test rax, rax
    js   .fail
    jz   .seccount                       ; the set runs past the directory
    mov  rsi, rax
    mov  rdi, rbx
    mov  edx, 32
    call memcpy
    movzx eax, byte [rbx]
    and  eax, EXF_DE_INUSE | EXF_DE_SECONDARY
    cmp  eax, EXF_DE_INUSE | EXF_DE_SECONDARY
    jne  .seccount                       ; the next primary or a free slot
    add  rbx, 32
    dec  r13d
    jnz  .secondary
    ; SetChecksum: every byte of the set except entry 0's checksum field
    mov  ecx, [rel exf_set_count]
    inc  ecx
    shl  ecx, 5
    lea  rsi, [rel exf_set_buf]
    xor  eax, eax
    xor  edx, edx
.csum:
    cmp  edx, 2
    je   .csum_skip
    cmp  edx, 3
    je   .csum_skip
    ror  ax, 1
    movzx r8d, byte [rsi + rdx]
    add  ax, r8w
.csum_skip:
    inc  edx
    cmp  edx, ecx
    jb   .csum
    cmp  ax, [rsi + 2]
    jne  .setcsum
    ; Stream Extension first, then exactly ceil(NameLength / 15) FileName entries
    cmp  byte [rsi + 32], EXF_DE_STREAM
    jne  .corrupt
    movzx eax, byte [rsi + 32 + 3]       ; NameLength
    test eax, eax
    jz   .corrupt
    add  eax, EXF_NAME_PER_ENTRY - 1
    xor  edx, edx
    mov  ecx, EXF_NAME_PER_ENTRY
    div  ecx
    mov  r13d, eax                       ; FileName entries
    inc  eax
    cmp  eax, [rel exf_set_count]
    ja   .seccount
    lea  rbx, [rsi + 64]
.names:
    cmp  byte [rbx], EXF_DE_NAME
    jne  .corrupt
    add  rbx, 32
    dec  r13d
    jnz  .names
    ; anything after the names must be a benign secondary
    lea  rcx, [rel exf_set_buf]
    mov  eax, [rel exf_set_count]
    inc  eax
    shl  eax, 5
    add  rcx, rax                        ; end of the set
.rest:
    cmp  rbx, rcx
    jae  .file_ok
    test byte [rbx], EXF_DE_BENIGN
    jz   .corrupt
    add  rbx, 32
    jmp  .rest
.file_ok:
    mov  eax, 1
    jmp  .out
.end:
    mov  qword [r12 + exf_ctx.it_left], 0
    xor  eax, eax
    jmp  .out
.seccount:
    mov  dword [rel exfat_disk_last_error], EXF_E_SECCOUNT
    jmp  .fail
.setcsum:
    mov  dword [rel exfat_disk_last_error], EXF_E_SETCSUM
    jmp  .fail
.corrupt:
    mov  dword [rel exfat_disk_last_error], EXF_E_CORRUPT
.fail:
    mov  rax, -1
.out:
    pop  r13
    pop  rbx
    ret

; exf_unit_forbidden(EAX=UTF-16 unit) -> CF set for a character exFAT names
;   never hold: controls, " * / : < > ? \ |
exf_unit_forbidden:
    cmp  eax, 0x20
    jb   .bad
    cmp  eax, 0x22
    je   .bad
    cmp  eax, 0x2A
    je   .bad
    cmp  eax, 0x2F
    je   .bad
    cmp  eax, 0x3A
    je   .bad
    cmp  eax, 0x3C
    je   .bad
    cmp  eax, 0x3E
    je   .bad
    cmp  eax, 0x3F
    je   .bad
    cmp  eax, 0x5C
    je   .bad
    cmp  eax, 0x7C
    je   .bad
    clc
    ret
.bad:
    stc
    ret

; exf_name_hash(R12=ctx, RSI=UTF-16 units, ECX=count) -> AX = NameHash over the
;   up-cased name (each unit's low byte, then its high byte).
exf_name_hash:
    push rbx
    mov  rbx, [r12 + exf_ctx.upcase]
    xor  eax, eax
    xor  edx, edx
.unit:
    cmp  edx, ecx
    jae  .out
    movzx r8d, word [rsi + rdx * 2]
    movzx r8d, word [rbx + r8 * 2]
    ror  ax, 1
    movzx r9d, r8b
    add  ax, r9w
    ror  ax, 1
    shr  r8d, 8
    add  ax, r8w
    inc  edx
    jmp  .unit
.out:
    pop  rbx
    ret

; exf_set_decode(R12=ctx; a File set in exf_set_buf) -> RAX 0/-1. Fills ctx.leaf
;   and the name (exf_name16 / exf_name_len) after the stream and name checks.
exf_set_decode:
    push rbx
    lea  rbx, [rel exf_set_buf]
    lea  rdi, [r12 + exf_ctx.leaf]
    mov  eax, [rbx + 12]                 ; E2t: LastModifiedTimestamp, its 10 ms increment and UtcOffset
    mov  [rel exf_leaf_mt_ts], eax
    mov  al, [rbx + 21]
    mov  [rel exf_leaf_mt_ms], al
    mov  al, [rbx + 23]
    mov  [rel exf_leaf_mt_utc], al
    movzx eax, word [rbx + 4]            ; FileAttributes
    mov  [rdi + exf_strm.attr], eax
    movzx eax, byte [rbx + 32 + 1]       ; GeneralSecondaryFlags
    mov  [rdi + exf_strm.flags], eax
    mov  dword [rdi + exf_strm.pad], 0
    mov  eax, [rbx + 32 + 20]
    mov  [rdi + exf_strm.first], eax
    mov  rax, [rbx + 32 + 8]
    mov  [rdi + exf_strm.valid], rax
    mov  rdx, [rbx + 32 + 24]
    mov  [rdi + exf_strm.length], rdx
    cmp  rax, rdx
    ja   .corrupt                        ; ValidDataLength past DataLength
    call exf_strm_range
    test rax, rax
    jnz  .fail
    lea  rdi, [r12 + exf_ctx.leaf]
    test dword [rdi + exf_strm.attr], EXF_ATTR_DIR
    jz   .name
    mov  rax, [rdi + exf_strm.length]
    cmp  rax, [rdi + exf_strm.valid]
    jne  .corrupt
    cmp  rax, EXF_DIR_MAX_BYTES
    ja   .corrupt
    mov  ecx, [r12 + exf_ctx.clus_shift]
    mov  edx, 1
    shl  rdx, cl
    dec  rdx
    test rax, rdx
    jnz  .corrupt
.name:
    movzx ecx, byte [rbx + 32 + 3]       ; NameLength (1..255, checked by exf_next_set)
    mov  [rel exf_name_len], ecx
    lea  rdi, [rel exf_name16]
    lea  rsi, [rbx + 64 + 2]
.copy:
    mov  rax, [rsi]                      ; 15 units = 30 bytes per FileName entry
    mov  [rdi], rax
    mov  rax, [rsi + 8]
    mov  [rdi + 8], rax
    mov  rax, [rsi + 16]
    mov  [rdi + 16], rax
    mov  eax, [rsi + 24]
    mov  [rdi + 24], eax
    mov  ax, [rsi + 28]
    mov  [rdi + 28], ax
    add  rsi, 32
    add  rdi, 30
    sub  ecx, EXF_NAME_PER_ENTRY
    jg   .copy
    mov  ecx, [rel exf_name_len]
    lea  rsi, [rel exf_name16]
    xor  edx, edx
.check:
    movzx eax, word [rsi + rdx * 2]
    call exf_unit_forbidden
    jc   .corrupt
    inc  edx
    cmp  edx, ecx
    jb   .check
    call exf_name_hash
    cmp  ax, [rbx + 32 + 4]
    jne  .namehash
    xor  eax, eax
    jmp  .out
.namehash:
    mov  dword [rel exfat_disk_last_error], EXF_E_NAMEHASH
    jmp  .fail
.corrupt:
    mov  dword [rel exfat_disk_last_error], EXF_E_CORRUPT
.fail:
    mov  rax, -1
.out:
    pop  rbx
    ret

; exf_utf8_to_16(RSI=bytes, ECX=len) -> RAX 0 / -1. Strict UTF-8 (no overlong
;   forms, no encoded surrogates, nothing past U+10FFFF, no forbidden
;   character) to at most EXF_NAME_MAX units in exf_comp16 / exf_comp_len.
exf_utf8_to_16:
    push rbx
    push r13
    lea  r13, [rsi + rcx]                ; end
    lea  rdi, [rel exf_comp16]
    xor  ebx, ebx                        ; units
.next:
    cmp  rsi, r13
    jae  .done
    movzx eax, byte [rsi]
    inc  rsi
    cmp  eax, 0x80
    jb   .emit
    cmp  eax, 0xC2
    jb   .bad
    mov  ecx, 1
    mov  r8d, 0x80
    and  eax, 0x1F
    cmp  byte [rsi - 1], 0xE0
    jb   .cont
    mov  ecx, 2
    mov  r8d, 0x800
    movzx eax, byte [rsi - 1]
    and  eax, 0x0F
    cmp  byte [rsi - 1], 0xF0
    jb   .cont
    cmp  byte [rsi - 1], 0xF4
    ja   .bad
    mov  ecx, 3
    mov  r8d, 0x10000
    movzx eax, byte [rsi - 1]
    and  eax, 0x07
.cont:
    cmp  rsi, r13
    jae  .bad
    movzx edx, byte [rsi]
    inc  rsi
    mov  r9d, edx
    and  r9d, 0xC0
    cmp  r9d, 0x80
    jne  .bad
    shl  eax, 6
    and  edx, 0x3F
    or   eax, edx
    dec  ecx
    jnz  .cont
    cmp  eax, r8d
    jb   .bad                            ; overlong
    cmp  eax, 0x10FFFF
    ja   .bad
    cmp  eax, 0xD800
    jb   .emit
    cmp  eax, 0xDFFF
    jbe  .bad                            ; an encoded surrogate
    cmp  eax, 0x10000
    jb   .emit
    cmp  ebx, EXF_NAME_MAX - 1
    jae  .bad
    sub  eax, 0x10000
    mov  edx, eax
    shr  edx, 10
    add  edx, 0xD800
    mov  [rdi + rbx * 2], dx
    inc  ebx
    and  eax, 0x3FF
    add  eax, 0xDC00
    mov  [rdi + rbx * 2], ax
    inc  ebx
    jmp  .next
.emit:
    call exf_unit_forbidden
    jc   .bad
    cmp  ebx, EXF_NAME_MAX
    jae  .bad
    mov  [rdi + rbx * 2], ax
    inc  ebx
    jmp  .next
.done:
    test ebx, ebx
    jz   .bad
    mov  [rel exf_comp_len], ebx
    xor  eax, eax
    jmp  .out
.bad:
    mov  rax, -1
.out:
    pop  r13
    pop  rbx
    ret

; exf_name_utf8(-; exf_name16 / exf_name_len) -> EAX = UTF-8 bytes in exf_utf8
;   (NUL-terminated). An unpaired surrogate becomes U+FFFD.
exf_name_utf8:
    lea  rsi, [rel exf_name16]
    mov  ecx, [rel exf_name_len]
    lea  rdi, [rel exf_utf8]
    xor  edx, edx
.unit:
    cmp  edx, ecx
    jae  .done
    movzx eax, word [rsi + rdx * 2]
    inc  edx
    cmp  eax, 0x80
    jb   .one
    cmp  eax, 0x800
    jb   .two
    cmp  eax, 0xD800
    jb   .three
    cmp  eax, 0xDFFF
    ja   .three
    cmp  eax, 0xDC00
    jae  .replace                        ; a low surrogate first
    cmp  edx, ecx
    jae  .replace
    movzx r8d, word [rsi + rdx * 2]
    cmp  r8d, 0xDC00
    jb   .replace
    cmp  r8d, 0xDFFF
    ja   .replace
    inc  edx
    sub  eax, 0xD800
    shl  eax, 10
    sub  r8d, 0xDC00
    add  eax, r8d
    add  eax, 0x10000
    mov  r8d, eax
    shr  r8d, 18
    or   r8d, 0xF0
    mov  [rdi], r8b
    mov  r8d, eax
    shr  r8d, 12
    and  r8d, 0x3F
    or   r8d, 0x80
    mov  [rdi + 1], r8b
    mov  r8d, eax
    shr  r8d, 6
    and  r8d, 0x3F
    or   r8d, 0x80
    mov  [rdi + 2], r8b
    and  eax, 0x3F
    or   eax, 0x80
    mov  [rdi + 3], al
    add  rdi, 4
    jmp  .unit
.replace:
    mov  eax, 0xFFFD
.three:
    mov  r8d, eax
    shr  r8d, 12
    or   r8d, 0xE0
    mov  [rdi], r8b
    mov  r8d, eax
    shr  r8d, 6
    and  r8d, 0x3F
    or   r8d, 0x80
    mov  [rdi + 1], r8b
    and  eax, 0x3F
    or   eax, 0x80
    mov  [rdi + 2], al
    add  rdi, 3
    jmp  .unit
.two:
    mov  r8d, eax
    shr  r8d, 6
    or   r8d, 0xC0
    mov  [rdi], r8b
    and  eax, 0x3F
    or   eax, 0x80
    mov  [rdi + 1], al
    add  rdi, 2
    jmp  .unit
.one:
    mov  [rdi], al
    inc  rdi
    jmp  .unit
.done:
    mov  byte [rdi], 0
    lea  rax, [rel exf_utf8]
    sub  rdi, rax
    mov  eax, edi
    ret

; exf_dir_find(R12=ctx; iterator open on ctx.dir, component in exf_comp16)
;   -> RAX 1 = found (ctx.leaf) / 0 = absent / -1. Every set on the way is
;   decoded and checked; names compare through the up-case table.
exf_dir_find:
    cmp  dword [rel exf_t_active], 0
    jne  exf_t_find
    push rbx
.next:
    call exf_next_set
    test rax, rax
    js   .out
    jz   .out
    cmp  rax, 1
    jne  .next
    call exf_set_decode
    test rax, rax
    jnz  .fail
    mov  ecx, [rel exf_name_len]
    cmp  ecx, [rel exf_comp_len]
    jne  .next
    mov  rbx, [r12 + exf_ctx.upcase]
    lea  rsi, [rel exf_name16]
    lea  rdi, [rel exf_comp16]
    xor  edx, edx
.unit:
    movzx eax, word [rsi + rdx * 2]
    movzx eax, word [rbx + rax * 2]
    movzx r8d, word [rdi + rdx * 2]
    movzx r8d, word [rbx + r8 * 2]
    cmp  eax, r8d
    jne  .next
    inc  edx
    cmp  edx, ecx
    jb   .unit
    mov  eax, 1
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  rbx
    ret

; exf_resolve(R12=ctx, RSI=path bytes, EDX=len) -> RAX 0/-1; the leaf in
;   ctx.leaf with its whole chain checked. "" and "/" are the root; "." and ".."
;   are refused; nothing is followed through a file.
exf_resolve:
    push rbx
    push r13
    push r14
    cmp  edx, EXF_PATH_MAX
    ja   .badpath
    mov  rbx, rsi                        ; cursor
    lea  r13, [rsi + rdx]                ; end
    lea  rdi, [r12 + exf_ctx.leaf]
    lea  rsi, [r12 + exf_ctx.root]
    mov  edx, exf_strm_size
    call memcpy
.comp:
    cmp  rbx, r13
    jae  .final
    cmp  byte [rbx], '/'
    jne  .comp_start
    inc  rbx
    jmp  .comp
.comp_start:
    test dword [r12 + exf_ctx.leaf + exf_strm.attr], EXF_ATTR_DIR
    jz   .notdir
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
    jmp  .clen
.cdone:
    mov  r14d, ecx
    cmp  byte [rbx], '.'
    jne  .named
    cmp  ecx, 1
    je   .badpath
    cmp  ecx, 2
    jne  .named
    cmp  byte [rbx + 1], '.'
    je   .badpath
.named:
    mov  rsi, rbx
    call exf_utf8_to_16
    test rax, rax
    jnz  .badpath
    lea  rdi, [r12 + exf_ctx.dir]
    lea  rsi, [r12 + exf_ctx.leaf]
    mov  edx, exf_strm_size
    call memcpy
    lea  rdi, [r12 + exf_ctx.dir]
    call exf_chain_check
    test rax, rax
    jnz  .fail
    lea  rdi, [r12 + exf_ctx.dir]
    call exf_dir_open
    call exf_dir_find
    test rax, rax
    js   .fail
    jz   .notfound
    call exf_src_component
    test rax, rax
    jnz  .fail
    add  rbx, r14
    jmp  .comp
.final:
    lea  rdi, [r12 + exf_ctx.leaf]
    call exf_chain_check
    test rax, rax
    jnz  .fail
    xor  eax, eax
    jmp  .out
.notdir:
    mov  dword [rel exfat_disk_last_error], EXF_E_NOTDIR
    jmp  .fail
.notfound:
    mov  dword [rel exfat_disk_last_error], EXF_E_NOTFOUND
    jmp  .fail
.badpath:
    mov  dword [rel exfat_disk_last_error], EXF_E_BADPATH
.fail:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  rbx
    ret

; exf_list_emit(R12=ctx; a decoded set) -> RAX 0 = continue, 1 = the caller's
;   array is full (truncated), -1.
exf_list_emit:
    push rbx
    push r13
    push r14
    push r15
    mov  r15, [rel exf_list_result]
    mov  eax, [r15 + fs_list_result.count]
    cmp  eax, [rel exf_list_cap]
    jb   .room
    mov  dword [r15 + fs_list_result.truncated], 1
    mov  eax, 1
    jmp  .out
.room:
    imul rax, rax, fs_dirent_size
    mov  r14, [rel exf_list_ptr]
    add  r14, rax                        ; -> fs_dirent
    mov  rdi, r14
    xor  esi, esi
    mov  edx, fs_dirent_size
    call memset
    test dword [r12 + exf_ctx.leaf + exf_strm.attr], EXF_ATTR_DIR
    jz   .file
    mov  dword [r14 + fs_dirent.flags], FS_DIRENT_DIR
    jmp  .name
.file:
    mov  rax, [r12 + exf_ctx.leaf + exf_strm.length]
    mov  [r14 + fs_dirent.size], rax
.name:
    call exf_name_utf8
    mov  r13d, eax                       ; UTF-8 bytes
    ; inline copy: at most 12 bytes, cut on a character boundary
    mov  ebx, r13d
    cmp  ebx, 12
    jbe  .inline
    mov  ebx, 12
    lea  rsi, [rel exf_utf8]
.boundary:
    movzx eax, byte [rsi + rbx]
    and  eax, 0xC0
    cmp  eax, 0x80
    jne  .inline
    dec  ebx
    jmp  .boundary
.inline:
    lea  rdi, [r14 + fs_dirent.name]
    lea  rsi, [rel exf_utf8]
    mov  edx, ebx
    call memcpy
    cmp  r13d, 12
    jbe  .counted
    mov  eax, [rel exf_list_names_used]
    lea  edx, [rax + r13 + 1]
    cmp  edx, EXF_LIST_NAMES_CAP
    ja   .omitted
    mov  [rel exf_list_names_used], edx
    lea  rdi, [rel exf_list_names]
    add  rdi, rax
    push rdi
    lea  rsi, [rel exf_utf8]
    lea  edx, [r13 + 1]                  ; with the NUL
    call memcpy
    pop  rsi
    mov  rdi, r14
    call vfs_dirent_set_long_name
    jmp  .counted
.omitted:
    or   dword [r14 + fs_dirent.flags], FS_DIRENT_LONG_OMITTED
    mov  dword [r15 + fs_list_result.names_short], 1
.counted:
    inc  dword [r15 + fs_list_result.count]
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

; exf_dir_list(R12=ctx; iterator open) -> RAX 0/-1: every set decoded, checked
;   and listed until the end or the caller's array is full.
exf_dir_list:
.next:
    call exf_next_set
    test rax, rax
    js   .fail
    jz   .done
    cmp  rax, 1
    jne  .next
    call exf_set_decode
    test rax, rax
    jnz  .fail
    call exf_list_emit
    test rax, rax
    js   .fail
    jz   .next
.done:
    xor  eax, eax
    ret
.fail:
    mov  rax, -1
    ret

; exf_map(R12=ctx, RSI=cluster index inside ctx.leaf) -> RAX = cluster / -1.
;   NoFatChain: first + index. FAT: forward from the cached position (the chain
;   was checked whole by exf_resolve; every link is still range-checked).
exf_map:
    mov  eax, [r12 + exf_ctx.leaf + exf_strm.first]
    test dword [r12 + exf_ctx.leaf + exf_strm.flags], EXF_SF_NOFATCHAIN
    jz   .fat
    add  rax, rsi
    ret
.fat:
    push rbx
    push r13
    mov  rbx, rsi
    cmp  rbx, [r12 + exf_ctx.map_idx]
    jb   .restart
    mov  r13d, [r12 + exf_ctx.map_clus]
    jmp  .walk
.restart:
    mov  qword [r12 + exf_ctx.map_idx], 0
    mov  r13d, eax
.walk:
    cmp  rbx, [r12 + exf_ctx.map_idx]
    je   .found
    mov  esi, r13d
    call exf_fat_get
    test rax, rax
    js   .out
    cmp  eax, 2
    jb   .cluster
    mov  edx, [r12 + exf_ctx.clus_count]
    inc  rdx
    cmp  rax, rdx
    ja   .cluster
    mov  r13d, eax
    inc  qword [r12 + exf_ctx.map_idx]
    mov  [r12 + exf_ctx.map_clus], r13d
    jmp  .walk
.found:
    mov  [r12 + exf_ctx.map_clus], r13d
    mov  eax, r13d
    jmp  .out
.cluster:
    mov  dword [rel exfat_disk_last_error], EXF_E_CLUSTER
    mov  rax, -1
.out:
    pop  r13
    pop  rbx
    ret

; exf_file_read(R12=ctx, RSI=off, RDX=buf, RCX=len) over ctx.leaf -> RAX len/-1.
;   off + len must not pass DataLength; bytes at or past ValidDataLength are
;   zeros and never read from the medium.
exf_file_read:
    push rbx
    push r13
    push r14
    push r15
    mov  r13, rsi                        ; offset
    mov  r14, rdx                        ; destination
    mov  r15, rcx                        ; remaining
    xor  ebx, ebx                        ; done
    mov  rax, r13
    add  rax, r15
    jc   .range
    cmp  rax, [r12 + exf_ctx.leaf + exf_strm.length]
    ja   .range
    mov  qword [r12 + exf_ctx.map_idx], 0
    mov  eax, [r12 + exf_ctx.leaf + exf_strm.first]
    mov  [r12 + exf_ctx.map_clus], eax
.piece:
    test r15, r15
    jz   .done
    mov  rdx, [r12 + exf_ctx.leaf + exf_strm.valid]
    cmp  r13, rdx
    jb   .data
    mov  rdi, r14                        ; past ValidDataLength: zeros
    xor  esi, esi
    mov  rdx, r15
    call memset
    mov  rdx, r15
    jmp  .advance
.data:
    sub  rdx, r13                        ; valid bytes left
    cmp  rdx, r15
    jbe  .valid_cut
    mov  rdx, r15
.valid_cut:
    mov  [rel exf_rd_piece], rdx
    mov  rsi, r13
    mov  ecx, [r12 + exf_ctx.clus_shift]
    shr  rsi, cl
    call exf_map
    test rax, rax
    js   .fail
    ; filesystem sector of this byte and its offset inside the sector
    mov  ecx, [r12 + exf_ctx.clus_shift]
    mov  r9d, 1
    shl  r9, cl                          ; cluster bytes
    lea  r8, [r9 - 1]
    and  r8, r13                         ; offset in the cluster
    sub  r9, r8                          ; bytes left in the cluster
    cmp  r9, [rel exf_rd_piece]
    jae  .in_cluster
    mov  [rel exf_rd_piece], r9
.in_cluster:
    sub  eax, 2
    mov  ecx, [r12 + exf_ctx.spc_shift]
    shl  rax, cl
    mov  rsi, r8
    mov  ecx, [r12 + exf_ctx.sec_shift]
    shr  rsi, cl
    add  rsi, rax
    add  rsi, [r12 + exf_ctx.heap_off]   ; filesystem sector
    mov  r9d, 1
    shl  r9, cl
    dec  r9
    and  r8, r9                          ; offset in the sector
    jnz  .bounce
    mov  rax, [rel exf_rd_piece]
    shr  rax, cl                         ; whole sectors
    jz   .bounce
    mov  rdx, rax
    shl  rax, cl
    mov  [rel exf_rd_piece], rax
    mov  rcx, r14
    call exf_read_fs
    test rax, rax
    jnz  .io
    mov  rdx, [rel exf_rd_piece]
    jmp  .advance
.bounce:
    push r8
    call exf_sec_get
    pop  r8
    test rax, rax
    jz   .fail
    lea  rsi, [rax + r8]
    mov  ecx, [r12 + exf_ctx.sec_shift]
    mov  edx, 1
    shl  rdx, cl
    sub  rdx, r8
    cmp  rdx, [rel exf_rd_piece]
    jbe  .copy
    mov  rdx, [rel exf_rd_piece]
.copy:
    mov  [rel exf_rd_piece], rdx
    mov  rdi, r14
    call memcpy
    mov  rdx, [rel exf_rd_piece]
.advance:
    add  r13, rdx
    add  r14, rdx
    add  rbx, rdx
    sub  r15, rdx
    jmp  .piece
.done:
    mov  rax, rbx
    jmp  .out
.io:
    mov  dword [rel exfat_disk_last_error], EXF_E_IO
    jmp  .fail
.range:
    mov  dword [rel exfat_disk_last_error], EXF_E_RANGE
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; fs_ops: protected root name11 creation plus existing bounded path writes.
; ---------------------------------------------------------------------------
exf_build_ops:
    lea  rdi, [rel exf_ops]
    lea  rax, [rel small_copy]
    mov  [rdi + fs_ops.copy], rax
    lea  rax, [rel small_copy_between]
    mov  [rdi + fs_ops.copy_between], rax
    lea  rax, [rel exf_a_mutate_path]
    mov  [rdi + fs_ops.mutate_path], rax
    lea  rax, [rel exf_a_mutate_armed]
    mov  [rdi + fs_ops.mutate_armed], rax
    lea  rax, [rel exf_op_rename]
    mov  [rdi + fs_ops.rename], rax
    lea  rax, [rel exf_op_delete]
    mov  [rdi + fs_ops.delete], rax
    lea  rax, [rel exf_a_update]
    mov  [rdi + fs_ops.update], rax
    lea  rax, [rel exf_op_create]
    mov  [rdi + fs_ops.writefile], rax
    lea  rax, [rel exf_op_write_at]
    mov  [rdi + fs_ops.write_at], rax
    lea  rax, [rel exf_op_write_at_path]
    mov  [rdi + fs_ops.write_at_path], rax
    lea  rax, [rel str_exf_backend]
    mov  [rdi + fs_ops.name], rax
    lea  rax, [rel exf_op_mount]
    mov  [rdi + fs_ops.mount], rax
    lea  rax, [rel exf_op_readfile]
    mov  [rdi + fs_ops.readfile], rax
    lea  rax, [rel exf_op_stat]
    mov  [rdi + fs_ops.stat], rax
    lea  rax, [rel exf_op_read_at]
    mov  [rdi + fs_ops.read_at], rax
    lea  rax, [rel exf_op_info]
    mov  [rdi + fs_ops.info], rax
    lea  rax, [rel exf_op_list_root]
    mov  [rdi + fs_ops.list_root], rax
    lea  rax, [rel exf_op_stat_path]
    mov  [rdi + fs_ops.stat_path], rax
    lea  rax, [rel exf_op_read_at_path]
    mov  [rdi + fs_ops.read_at_path], rax
    lea  rax, [rel exf_op_list_dir]
    mov  [rdi + fs_ops.list_dir], rax
    ret

; mount(RDI=fsmount) -> 0 when the private context finished mounting
exf_op_mount:
    mov  rax, [rdi + fsmount.priv]
    test rax, rax
    jz   .fail
    cmp  dword [rax + exf_ctx.mounted], 1
    jne  .fail
    xor  eax, eax
    ret
.fail:
    mov  rax, -1
    ret

; RDI=fsmount -> R12=ctx (caller saved r12); jumps to .unmounted when unmounted.
%macro EXF_ENTER 0
    mov  dword [rel exfat_disk_last_error], EXF_E_NONE
    mov  r12, [rdi + fsmount.priv]
    test r12, r12
    jz   .unmounted
    cmp  dword [r12 + exf_ctx.mounted], 1
    jne  .unmounted
%endmacro

; stat_path(self, RSI=path, EDX=len, RCX=fs_stat*) -> 0/-1
exf_op_stat_path:
    push rbx
    push r12
    mov  rbx, rcx
    EXF_ENTER
    test rbx, rbx
    jz   .unmounted
    call exf_resolve
    test rax, rax
    jnz  .fail
    mov  dword [rbx + fs_stat.flags], FS_STAT_READONLY
    mov  qword [rbx + fs_stat.size], 0
    mov  ecx, 1
    test dword [r12 + exf_ctx.leaf + exf_strm.attr], EXF_ATTR_DIR
    jnz  .kind
    mov  rax, [r12 + exf_ctx.leaf + exf_strm.length]
    mov  [rbx + fs_stat.size], rax
    xor  ecx, ecx
    ; Overwrite capability is conditional on the request gate and initialized
    ; range; directories and on-disk read-only files remain read-only.
    test dword [r12 + exf_ctx.leaf + exf_strm.attr], 1
    jnz  .kind
    mov  dword [rbx + fs_stat.flags], 0
.kind:
    mov  [rbx + fs_stat.reserved], ecx   ; bit 0 = directory
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
exf_op_read_at_path:
    push rbx
    push r12
    push r13
    push r14
    mov  rbx, rcx
    mov  r13, r8
    mov  r14, r9
    EXF_ENTER
    call exf_resolve
    test rax, rax
    jnz  .fail
    test dword [r12 + exf_ctx.leaf + exf_strm.attr], EXF_ATTR_DIR
    jz   .regular
    mov  dword [rel exfat_disk_last_error], EXF_E_ISDIR
    jmp  .fail
.regular:
    mov  rsi, rbx
    mov  rdx, r13
    mov  rcx, r14
    call exf_file_read
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
exf_op_list_dir:
    push rbx
    push r12
    push r13
    push r14
    mov  rbx, r9
    mov  r13, rcx
    mov  r14d, r8d
    EXF_ENTER
    test rbx, rbx
    jz   .unmounted
    mov  dword [rbx + fs_list_result.count], 0
    mov  dword [rbx + fs_list_result.truncated], 0
    mov  dword [rbx + fs_list_result.names_short], 0
    call exf_resolve
    test rax, rax
    jnz  .fail
    test dword [r12 + exf_ctx.leaf + exf_strm.attr], EXF_ATTR_DIR
    jnz  .dir
    mov  dword [rel exfat_disk_last_error], EXF_E_NOTDIR
    jmp  .fail
.dir:
    mov  [rel exf_list_ptr], r13
    mov  [rel exf_list_cap], r14d
    mov  [rel exf_list_result], rbx
    mov  dword [rel exf_list_names_used], 0
    lea  rdi, [r12 + exf_ctx.dir]
    lea  rsi, [r12 + exf_ctx.leaf]
    mov  edx, exf_strm_size
    call memcpy
    lea  rdi, [r12 + exf_ctx.dir]
    call exf_dir_open
    call exf_dir_list
    test rax, rax
    jnz  .fail
    xor  eax, eax
    jmp  .out
.unmounted:
.fail:
    test rbx, rbx
    jz   .no_result
    mov  dword [rbx + fs_list_result.count], 0
.no_result:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; list_root(self, RSI=fs_dirent[], EDX=cap, RCX=fs_list_result*) -> 0/-1
exf_op_list_root:
    mov  r9, rcx
    mov  r8d, edx
    mov  rcx, rsi
    lea  rsi, [rel str_exf_root]
    mov  edx, 1
    jmp  exf_op_list_dir

; exf_name11_path(RSI=name11) -> RSI = "/BASE.EXT" in exf_n11_path, EDX = len.
;   Trailing spaces trimmed; the lookup itself is case-insensitive.
;   Clobbers RAX, RCX, RDX, RDI, R10 only (callers keep R8/R9 live).
exf_name11_path:
    lea  rdi, [rel exf_n11_path]
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
exf_op_stat:
    test rsi, rsi
    jz   .fail
    push rdi
    push rdx                             ; fs_stat*
    call exf_name11_path
    pop  rcx
    pop  rdi
    jmp  exf_op_stat_path
.fail:
    mov  rax, -1
    ret

; read_at(self, RSI=name11, RDX=off, RCX=buf, R8=len) -> len/-1
exf_op_read_at:
    test rsi, rsi
    jz   .fail
    mov  r9, r8                          ; len
    mov  r8, rcx                         ; buf
    push rdi
    push rdx                             ; offset
    call exf_name11_path                 ; keeps r8/r9
    pop  rcx
    pop  rdi
    jmp  exf_op_read_at_path
.fail:
    mov  rax, -1
    ret

; ---------------------------------------------------------------------------
; Bounded initialized overwrite. Synchronous request scope: no job/owned-op is
; minted or borrowed. require_request decides every RMW sector before the first
; mutation, then again immediately before blk_write. Its ordinary request grant
; is still structurally checked by blockdev and expires at the request boundary.
; ---------------------------------------------------------------------------
; exf_w_live(R12=ctx) -> 0/-1. Registered identity and geometry are immutable;
; bind this mount to that exact registration, not a device name or VFS handle.
exf_w_live:
    mov  rdi, [r12 + exf_ctx.dev]
    mov  rax, [rdi + dev.info]
    cmp  rax, [r12 + exf_ctx.info_identity]
    jne  .stale
    test rax, rax
    jz   .stale
    mov  rdx, [rax + blk_info.media_generation]
    test rdx, rdx
    jz   .stale
    cmp  rdx, [r12 + exf_ctx.media_gen]
    jne  .stale
    mov  rdx, [rdi + dev.ops]
    cmp  rdx, [r12 + exf_ctx.ops_identity]
    jne  .stale
    cmp  dword [rax + blk_info.sector_size], 512
    jne  .stale
    mov  ecx, [rax + blk_info.logical_sector_bytes]
    test ecx, ecx
    jz   .geometry
    cmp  ecx, 512
    jne  .stale
.geometry:
    cmp  dword [rdi + dev.health], HEALTH_OK
    jne  .io
    test dword [rdi + dev.flags], BLKF_RO
    jnz  .ro
    test dword [rax + blk_info.flags], BLKF_RO
    jnz  .ro
    mov  rdx, [rax + blk_info.capabilities]
    test rdx, rdx
    jz   .legacy
    and  edx, BLKCAP_READ | BLKCAP_WRITE | BLKCAP_FLUSH
    cmp  edx, BLKCAP_READ | BLKCAP_WRITE | BLKCAP_FLUSH
    jne  .unsupported
.legacy:
    mov  rdx, [r12 + exf_ctx.part_lba]
    add  rdx, [r12 + exf_ctx.part_sectors]
    jc   .stale
    dec  rdx
    cmp  rdx, [rax + blk_info.lba_max]
    ja   .stale
    xor  eax, eax
    ret
.ro:
    mov  dword [rel exfat_disk_last_error], EXF_E_READONLY
    jmp  .fail
.unsupported:
    mov  dword [rel exfat_disk_last_error], EXF_E_UNSUPPORTED
    jmp  .fail
.io:
    mov  dword [rel exfat_disk_last_error], EXF_E_IO
    jmp  .fail
.stale:
    mov  dword [rel exfat_disk_last_error], EXF_E_STALE
.fail:
    mov  rax, -1
    ret

; Allocation is defined by the bitmap, not by nonzero FAT entries. The bitmap
; stream has already passed the bounded full-chain check. Never repurpose leaf.
; exf_w_allocated(R12=ctx, ESI=heap cluster) -> 0/-1.
exf_w_allocated:
    push rbx
    push r13
    push r14
    mov  ebx, esi
    sub  ebx, 2
    mov  r13d, ebx
    shr  r13, 3                          ; bitmap byte offset
    mov  r14, r13
    mov  ecx, [r12 + exf_ctx.clus_shift]
    shr  r14, cl                         ; bitmap cluster index
    mov  esi, [r12 + exf_ctx.bitmap + exf_strm.first]
.walk:
    test r14, r14
    jz   .mapped
    call exf_fat_get
    test rax, rax
    js   .out
    cmp  eax, 2
    jb   .corrupt
    mov  edx, [r12 + exf_ctx.clus_count]
    inc  rdx
    cmp  rax, rdx
    ja   .corrupt
    mov  esi, eax
    dec  r14
    jmp  .walk
.mapped:
    mov  eax, esi
    sub  eax, 2
    mov  ecx, [r12 + exf_ctx.spc_shift]
    shl  rax, cl
    add  rax, [r12 + exf_ctx.heap_off]
    mov  ecx, [r12 + exf_ctx.clus_shift]
    mov  rdx, 1
    shl  rdx, cl
    dec  rdx
    and  r13, rdx
    mov  rsi, r13
    mov  ecx, [r12 + exf_ctx.sec_shift]
    shr  rsi, cl
    add  rsi, rax
    call exf_sec_get
    test rax, rax
    jz   .fail
    mov  ecx, [r12 + exf_ctx.sec_shift]
    mov  edx, 1
    shl  edx, cl
    dec  edx
    and  r13d, edx
    movzx eax, byte [rax + r13]
    mov  ecx, ebx
    and  ecx, 7
    bt   eax, ecx
    jnc  .corrupt
    xor  eax, eax
    jmp  .out
.corrupt:
    mov  dword [rel exfat_disk_last_error], EXF_E_CLUSTER
.fail:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  rbx
    ret

; Check a complete stream before touching data. EDX=1 also refuses any cluster
; present in the request's target plan (metadata/other stream alias).
exf_w_stream:
    push rbx
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  r15d, edx
    mov  rax, [rbx + exf_strm.length]
    mov  rdx, [rbx + exf_strm.valid]
    cmp  rdx, rax
    ja   .corrupt
    mov  ecx, [r12 + exf_ctx.clus_shift]
    mov  r14, rax
    shr  r14, cl
    mov  rdx, 1
    shl  rdx, cl
    dec  rdx
    test rax, rdx
    jz   .count
    inc  r14
.count:
    cmp  r14, EXF_WRITE_CLUSTERS
    ja   .unsupported
    cmp  r14d, [rel exf_w_budget]
    ja   .unsupported
    sub  [rel exf_w_budget], r14d
    call exf_chain_check
    test rax, rax
    jnz  .out
    mov  r13d, [rbx + exf_strm.first]
.cluster:
    test r14, r14
    jz   .ok
    cmp  dword [rel exf_m_account], 0
    je   .owned
    mov  eax, r13d
    sub  eax, 2
    cmp  eax, 65536
    jae  .unsupported
    lea  rdi, [rel exf_m_seen]
    bts  dword [rdi], eax
    jc   .corrupt                        ; every reachable allocation has ONE owner
.owned:
    mov  esi, r13d
    call exf_w_allocated
    test rax, rax
    jnz  .out
    test r15d, r15d
    jz   .metadata_alias                 ; target allocation must not alias its own metadata
    lea  rdi, [rel exf_w_plan]
    xor  ecx, ecx
.alias:
    cmp  ecx, [rel exf_w_plan_count]
    jae  .metadata_alias
    cmp  r13d, [rdi + rcx * 4]
    je   .corrupt
    inc  ecx
    jmp  .alias
.metadata_alias:
    cmp  dword [rel exf_i_mode], 0
    je   .next
    cmp  r13d, [rel exf_i_meta_cluster]
    jne  .bitmap_alias
    cmp  r15d, 2                         ; exact parent directory only
    jne  .corrupt
    inc  dword [rel exf_i_parent_hits]
.bitmap_alias:
    cmp  dword [rel exf_n_mode], 0
    je   .bitmap_keys
    cmp  r13d, [rel exf_n_meta_cluster2]
    jne  .bitmap_keys
    cmp  r15d, 2                         ; second namespace sector's exact root only
    jne  .corrupt
.bitmap_keys:
    cmp  dword [rel exf_m_cross], 0
    je   .destination_checked
    cmp  r13d, [rel exf_m_dst_cluster]
    jne  .destination_checked
    cmp  r15d, 4                         ; exact destination parent only
    jne  .corrupt
    inc  dword [rel exf_m_dst_hits]
.destination_checked:
    cmp  dword [rel exf_g_mode], 0
    je   .next
    lea  rdi, [rel exf_g_bitmap_clusters]
    xor  ecx, ecx
.bitmap_check:
    cmp  ecx, [rel exf_g_bitmap_count]
    jae  .reservation_keys_done
    cmp  r13d, [rdi + rcx * 4]
    jne  .bitmap_next
    cmp  r15d, 3                         ; only the real bitmap stream may own it
    jne  .corrupt
.bitmap_next:
    inc  ecx
    jmp  .bitmap_check
.reservation_keys_done:
    cmp  dword [rel exf_r_active], 0
    je   .next
    lea  rdi, [rel exf_r_retirement + exf_r_plan.clusters]
    xor  ecx, ecx
.retirement_key:
    cmp  ecx, [rel exf_r_retirement]
    jae  .next
    cmp  r13d, [rdi + rcx * 4]
    jne  .retirement_next
    cmp  r15d, 3
    jne  .corrupt
.retirement_next:
    inc  ecx
    jmp  .retirement_key
.next:
    dec  r14
    jz   .ok
    test dword [rbx + exf_strm.flags], EXF_SF_NOFATCHAIN
    jnz  .contiguous
    mov  esi, r13d
    call exf_fat_get
    test rax, rax
    js   .out
    mov  r13d, eax
    jmp  .cluster
.contiguous:
    inc  r13d
    jmp  .cluster
.ok:
    xor  eax, eax
    jmp  .out
.corrupt:
    mov  dword [rel exfat_disk_last_error], EXF_E_CORRUPT
    jmp  .fail
.unsupported:
    mov  dword [rel exfat_disk_last_error], EXF_E_UNSUPPORTED
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

; Complete reachable allocation census. A bounded queue visits directories once,
; with no recursion or UI listing cap. Unknown/benign allocation extensions are
; refused here: this initial writer cannot prove their ownership. Read unchanged.
exf_w_census:
    push rbx
    push r13
    cmp  dword [rel exf_m_cross], 0
    jne  .move_init
    cmp  dword [rel exf_r_active], 0
    je   .move_init_done
.move_init:
    lea  rdi, [rel exf_m_seen]
    xor  esi, esi
    mov  edx, 8192
    call memset
    lea  rdi, [rel exf_m_depths]
    xor  esi, esi
    mov  edx, EXF_WRITE_DIRS * 16
    call memset
    mov  dword [rel exf_m_census], 1
    mov  dword [rel exf_m_account], 1
.move_init_done:
    lea  rdi, [r12 + exf_ctx.bitmap]
    mov  edx, 3                          ; bitmap metadata exception, never file data
    call exf_w_stream
    test rax, rax
    jnz  .out
    lea  rdi, [r12 + exf_ctx.upstream]
    mov  edx, 1
    call exf_w_stream
    test rax, rax
    jnz  .out
    lea  rdi, [rel exf_w_dirs]
    lea  rsi, [r12 + exf_ctx.root]
    mov  edx, exf_strm_size
    call memcpy
    mov  dword [rel exf_w_dir_count], 1
    mov  dword [rel exf_w_dir_index], 0
    mov  dword [rel exf_w_entries], EXF_WRITE_ENTRIES
    mov  dword [rel exf_w_found], 0
    mov  dword [rel exf_i_parent_hits], 0
.directory:
    mov  eax, [rel exf_w_dir_index]
    cmp  eax, [rel exf_w_dir_count]
    jae  .done
    shl  eax, 5
    lea  rbx, [rel exf_w_dirs]
    add  rbx, rax
    cmp  qword [rbx + exf_strm.length], 0x100000 ; directory admission bound
    ja   .unsupported
    mov  r13d, 1
    cmp  dword [rel exf_i_mode], 0
    je   .parent_checked
    mov  rdi, rbx
    lea  rsi, [rel exf_i_parent]
    mov  edx, exf_strm_size
    call memcmp
    test rax, rax
    jnz  .parent_checked
    mov  r13d, 2
.parent_checked:
    cmp  dword [rel exf_m_cross], 0
    je   .move_parent_checked
    mov  rdi, rbx
    lea  rsi, [rel exf_m_dst_parent]
    mov  edx, exf_strm_size
    call memcmp
    test rax, rax
    jnz  .move_parent_checked
    mov  r13d, 4
.move_parent_checked:
    cmp  dword [rel exf_t_active], 0
    je   .target_checked
    cmp  dword [rel exf_n_mode], 1
    jne  .target_checked
    cmp  dword [rel exf_t_kind], 1
    jne  .target_checked
    mov  rdi, rbx
    lea  rsi, [rel exf_n_stream]
    mov  edx, exf_strm_size
    call memcmp
    test rax, rax
    jnz  .target_checked
    xor  r13d, r13d                     ; exact renamed directory owns its allocation
.target_checked:
    cmp  dword [rel exf_m_census], 0
    je   .account_ready
    xor  eax, eax
    cmp  dword [rel exf_w_dir_index], 0
    sete al
    mov  [rel exf_m_account], eax
.account_ready:
    mov  rdi, rbx
    mov  edx, r13d
    call exf_w_stream
    test rax, rax
    jnz  .out
    mov  rdi, rbx
    call exf_dir_open
.entry:
    ; Raw primary lookahead: benign extensions may own clusters we do not
    ; understand. Refuse them rather than claiming the census is complete.
    call exf_dir_next
    test rax, rax
    js   .out
    jz   .nextdir
    movzx ecx, byte [rax]
    test ecx, ecx
    jz   .nextdir
    test ecx, EXF_DE_INUSE
    jz   .entry
    cmp  ecx, EXF_DE_FILE
    je   .file
    cmp  dword [rel exf_w_dir_index], 0
    jne  .unsupported
    cmp  ecx, EXF_DE_BITMAP
    je   .entry
    cmp  ecx, EXF_DE_UPCASE
    je   .entry
    cmp  ecx, EXF_DE_LABEL
    je   .entry
    jmp  .unsupported
.file:
    ; Put the iterator back by one entry; next_set retains the reader's
    ; set checksum/name/secondary structure validation, including spanning sets.
    sub  dword [r12 + exf_ctx.it_coff], 32
    add  qword [r12 + exf_ctx.it_left], 32
    call exf_next_set
    cmp  rax, 1
    jne  .fail
    dec  dword [rel exf_w_entries]
    js   .unsupported
    call exf_set_decode
    test rax, rax
    jnz  .out
    ; Accept exactly Stream + Name secondary entries. Extra benign secondaries
    ; may describe allocation and are outside this finite write subset.
    mov  eax, [rel exf_name_len]
    add  eax, 14
    xor  edx, edx
    mov  ecx, 15
    div  ecx
    inc  eax
    cmp  eax, [rel exf_set_count]
    jne  .unsupported
    cmp  byte [rel exf_set_buf + 33], EXF_SF_ALLOC
    je   .flagsok
    cmp  byte [rel exf_set_buf + 33], EXF_SF_ALLOC | EXF_SF_NOFATCHAIN
    jne  .unsupported
.flagsok:
    cmp  dword [rel exf_m_census], 0
    je   .move_depth_checked
    cmp  dword [rel exf_r_active], 0
    jne  .replacement_depth_checked
    call exf_m_depth_check
    test rax, rax
    jnz  .out
.replacement_depth_checked:
    mov  dword [rel exf_m_account], 1
.move_depth_checked:
    mov  rax, [rel exf_set_location]
    cmp  rax, [rel exf_w_location]
    je   .target
    mov  r13d, 1
    cmp  dword [rel exf_i_mode], 0
    je   .leaf_parent_checked
    lea  rdi, [r12 + exf_ctx.leaf]
    lea  rsi, [rel exf_i_parent]
    mov  edx, exf_strm_size
    call memcmp
    test rax, rax
    jnz  .leaf_parent_checked
    mov  r13d, 2
.leaf_parent_checked:
    cmp  dword [rel exf_m_cross], 0
    je   .move_leaf_parent_checked
    lea  rdi, [r12 + exf_ctx.leaf]
    lea  rsi, [rel exf_m_dst_parent]
    mov  edx, exf_strm_size
    call memcmp
    test rax, rax
    jnz  .move_leaf_parent_checked
    mov  r13d, 4
.move_leaf_parent_checked:
    lea  rdi, [r12 + exf_ctx.leaf]
    mov  edx, r13d
    call exf_w_stream
    test rax, rax
    jnz  .out
    ; parent may also have been checked as a leaf before queueing; that is
    ; expected, while every other stream still refuses the metadata cluster.
    test dword [r12 + exf_ctx.leaf + exf_strm.attr], EXF_ATTR_DIR
    jz   .entry
    ; A repeated directory's first cluster means an alias/cycle, not a new path.
.queue_directory:
    lea  rdi, [rel exf_w_dirs]
    xor  ecx, ecx
    mov  eax, [r12 + exf_ctx.leaf + exf_strm.first]
.unique:
    cmp  ecx, [rel exf_w_dir_count]
    jae  .enqueue
    mov  edx, ecx
    shl  edx, 5
    cmp  eax, [rdi + rdx + exf_strm.first]
    je   .corrupt
    inc  ecx
    jmp  .unique
.enqueue:
    cmp  ecx, EXF_WRITE_DIRS
    jae  .unsupported
    cmp  dword [rel exf_m_census], 0
    je   .move_enqueue_done
    lea  rdx, [rel exf_m_depths]
    mov  eax, [rel exf_w_dir_index]
    mov  eax, [rdx + rax * 8]
    inc  eax
    mov  [rdx + rcx * 8], eax
    lea  rdx, [rel exf_m_tags]
    mov  eax, [rel exf_w_dir_index]
    mov  eax, [rdx + rax * 8]
    mov  rsi, [rel exf_set_location]
    cmp  rsi, [rel exf_w_location]
    jne  .move_tag_ready
    mov  eax, 1
.move_tag_ready:
    mov  [rdx + rcx * 8], eax
.move_enqueue_done:
    shl  ecx, 5
    add  rdi, rcx
    lea  rsi, [r12 + exf_ctx.leaf]
    mov  edx, exf_strm_size
    call memcpy
    inc  dword [rel exf_w_dir_count]
    jmp  .entry
.target:
    mov  eax, [rel exf_set_count]
    inc  eax
    shl  eax, 5
    cmp  eax, [rel exf_w_set_len]
    jne  .corrupt
    lea  rdi, [rel exf_set_buf]
    lea  rsi, [rel exf_w_set]
    mov  edx, eax
    call memcmp
    test rax, rax
    jnz  .corrupt
    inc  dword [rel exf_w_found]
    cmp  dword [rel exf_m_census], 0
    je   .move_target_accounted
    lea  rdi, [r12 + exf_ctx.leaf]
    xor  edx, edx
    cmp  dword [rel exf_r_active], 0
    setne dl                            ; old replacement stream cannot own the NEW plan
    call exf_w_stream
    test rax, rax
    jnz  .out
.move_target_accounted:
    cmp  dword [rel exf_t_active], 0
    je   .entry
    cmp  dword [rel exf_n_mode], 1
    jne  .entry
    cmp  dword [rel exf_t_kind], 1
    jne  .entry
    jmp  .queue_directory               ; rename must census every live descendant too

.nextdir:
    inc  dword [rel exf_w_dir_index]
    jmp  .directory
.done:
    cmp  dword [rel exf_c_mode], 0
    jne  .create_done
    cmp  dword [rel exf_w_found], 1
    jne  .corrupt
    jmp  .parent_done
.create_done:
    cmp  dword [rel exf_r_active], 0
    je   .absent_create
    cmp  dword [rel exf_w_found], 1
    jne  .corrupt
    jmp  .parent_done
.absent_create:
    cmp  dword [rel exf_w_found], 0
    jne  .corrupt
.parent_done:
    cmp  dword [rel exf_i_mode], 0
    je   .census_ok
    cmp  dword [rel exf_i_parent_hits], 0
    je   .corrupt
.census_ok:
    xor  eax, eax
    jmp  .out
.unsupported:
    mov  dword [rel exfat_disk_last_error], EXF_E_UNSUPPORTED
    jmp  .fail
.corrupt:
    mov  dword [rel exfat_disk_last_error], EXF_E_CORRUPT
.fail:
    mov  rax, -1
.out:
    pop  r13
    pop  rbx
    ret

; Map a request byte offset to one DEVICE sector. EAX=piece bytes, RSI=LBA.
; Uses the re-resolved, identity-checked stream after the census. All file/heap bounds have
; already been checked; blockdev independently validates range and admission.
exf_w_piece_map:
    push rbx
    mov  rbx, [rel exf_w_offset]
    mov  rsi, rbx
    mov  ecx, [r12 + exf_ctx.clus_shift]
    shr  rsi, cl
    call exf_map
    test rax, rax
    js   .out
    sub  eax, 2
    mov  ecx, [r12 + exf_ctx.spc_shift]
    shl  rax, cl
    add  rax, [r12 + exf_ctx.heap_off]
    mov  ecx, [r12 + exf_ctx.dev_shift]
    shl  rax, cl
    add  rax, [r12 + exf_ctx.part_lba]
    mov  ecx, [r12 + exf_ctx.clus_shift]
    mov  rdx, 1
    shl  rdx, cl
    dec  rdx
    and  rdx, rbx
    shr  rdx, 9
    lea  rsi, [rax + rdx]
    mov  [rel exf_w_sector], rsi
    and  ebx, 511
    mov  [rel exf_w_within], rbx
    mov  eax, 512
    sub  rax, rbx
    cmp  rax, [rel exf_w_length]
    jbe  .sized
    mov  rax, [rel exf_w_length]
.sized:
    mov  [rel exf_w_piece], rax
.out:
    pop  rbx
    ret

; The owner's current request is the authority. No owner or intent is set by
; this backend. Check both again before each grant; do not carry them to a tick.
exf_w_gate:
%if EXF_PUBLIC_MEDIA_GATE
    call exf_public_media_gate
    test rax, rax
    jnz  .ret
%endif
    call exf_w_live
    test rax, rax
    jnz  .ret
    call exf_volume_pin                  ; after live: reads the device the context still owns
    test rax, rax
    jnz  .ret
    cmp  dword [rel exf_m_gate_active], 0
    je   .move_bound
    call exf_m_binding                  ; fresh reads BEFORE current arm/owner/grant
    test rax, rax
    jnz  .ret
    call exf_w_live                     ; changes during those reads cannot carry authority
    test rax, rax
    jnz  .ret
.move_bound:
    cmp  dword [rel exf_r_gate_active], 0
    je   .replacement_bound
    call exf_r_binding
    test rax, rax
    jnz  .ret
    call exf_w_live
    test rax, rax
    jnz  .ret
.replacement_bound:
    cmp  dword [rel exf_a_inflight], 0
    je   .request
    call exf_a_ctx_check                 ; arm is identity/readiness only, never a grant
    cmp  rax, 1
    jne  .no
    cmp  dword [rel exf_w_owner], 1
    jne  .no
    cmp  dword [rel exf_w_intent], SA_INTENT_SPECIAL
    jne  .no
.request:
    call storage_access_request_owner
    cmp  eax, [rel exf_w_owner]
    jne  .no
    mov  rdi, [r12 + exf_ctx.dev]
    call storage_access_intent_for_dev
    cmp  eax, [rel exf_w_intent]
    jne  .no
    mov  rdi, [r12 + exf_ctx.dev]
    mov  rsi, [rel exf_w_sector]
    mov  edx, 1
    lea  r8, [rel str_exf_write_gate]
    call storage_access_require_request
    test rax, rax
    jnz  .no
    mov  rdi, [r12 + exf_ctx.dev]
    mov  rsi, [rel exf_w_sector]
    mov  edx, 1
    call storage_access_write_admitted      ; includes live Try refusal before first write
    test rax, rax
    jz   .ret
.no:
    mov  dword [rel exfat_disk_last_error], EXF_E_AUTH
    mov  rax, -1
.ret:
    ret

; Bounded existing NoFatChain growth. Allocation is authoritative bitmap state,
; additionally checked against every reachable stream before any mutation.
; All newly allocated bytes are initialized, including post-EOF cluster padding.
; Allocation diagnostics: 0 none,1 partial/uncertain reservation,2 all verified;
; reserved/reservation_attempted count new clusters, never an atomicity claim.
; Stages9/10 mean bitmap reservation attempted/verified between dirty and data.

; RAX=request end -> 0/-1. The native resolver already checked the OLD stream.
exf_g_bounds:
    mov  r8, rax
    cmp  dword [r12 + exf_ctx.leaf + exf_strm.flags], EXF_SF_ALLOC | EXF_SF_NOFATCHAIN
    jne  .unsupported
    mov  rax, [r12 + exf_ctx.leaf + exf_strm.length]
    test rax, rax
    jz   .unsupported                    ; no existing run: creation is outside this allocator
    mov  ecx, [r12 + exf_ctx.clus_shift]
    mov  rdx, 1
    shl  rdx, cl
    dec  rdx
    add  rax, rdx
    jc   .range
    shr  rax, cl                         ; old allocated clusters
    mov  r9, r8
    add  r9, rdx
    jc   .range
    shr  r9, cl                         ; new allocation size
    cmp  r9, EXF_WRITE_CLUSTERS
    ja   .unsupported
    mov  r10, r9
    sub  r10, rax
    jc   .range
    cmp  r10, EXF_GROW_MAX
    ja   .unsupported
    mov  edx, [r12 + exf_ctx.leaf + exf_strm.first]
    lea  r11, [rdx + r9 - 1]
    mov  esi, [r12 + exf_ctx.clus_count]
    inc  rsi
    cmp  r11, rsi
    ja   .range
    add  rax, rdx
    mov  [rel exf_g_first], eax
    mov  [rel exf_g_count], r10d
    mov  [rel exf_g_new_length], r8
    test r10, r10
    jz   .no_new_allocation
    shl  r9, cl
    mov  r8, r9                          ; zero through entire new allocation end
.no_new_allocation:
    mov  [rel exf_g_work_end], r8
    mov  rax, [rel exf_w_length]
    mov  [rel exf_g_data_left], rax
    mov  dword [rel exf_g_mode], 1
    xor  eax, eax
    ret
.unsupported:
    mov  dword [rel exfat_disk_last_error], EXF_E_UNSUPPORTED
    jmp  .fail
.range:
    mov  dword [rel exfat_disk_last_error], EXF_E_RANGE
.fail:
    mov  rax, -1
    ret

; ESI=heap cluster -> RSI=bitmap DEVICE LBA, EDX=bit within512B, R9D=bitmap
; heap cluster, RAX=0/-1. Native FAT access follows the checked bitmap stream;
; leaf, file map and iterator state are not repurposed.
exf_g_bitmap_location:
    push rbx
    push r13
    push r14
    mov  ebx, esi
    sub  ebx, 2
    mov  r13d, ebx
    shr  r13, 3
    mov  r14, r13
    mov  ecx, [r12 + exf_ctx.clus_shift]
    shr  r14, cl
    mov  esi, [r12 + exf_ctx.bitmap + exf_strm.first]
.walk:
    test r14, r14
    jz   .mapped
    call exf_fat_get
    test rax, rax
    js   .out
    cmp  eax, 2
    jb   .corrupt
    mov  edx, [r12 + exf_ctx.clus_count]
    inc  rdx
    cmp  rax, rdx
    ja   .corrupt
    mov  esi, eax
    dec  r14
    jmp  .walk
.mapped:
    mov  r9d, esi
    mov  eax, esi
    sub  eax, 2
    mov  ecx, [r12 + exf_ctx.spc_shift]
    shl  rax, cl
    add  rax, [r12 + exf_ctx.heap_off]
    mov  ecx, [r12 + exf_ctx.dev_shift]
    shl  rax, cl
    add  rax, [r12 + exf_ctx.part_lba]
    mov  ecx, [r12 + exf_ctx.clus_shift]
    mov  rdx, 1
    shl  rdx, cl
    dec  rdx
    and  r13, rdx
    shr  r13, 9
    lea  rsi, [rax + r13]
    mov  edx, ebx
    and  edx, 4095
    xor  eax, eax
    jmp  .out
.corrupt:
    mov  dword [rel exfat_disk_last_error], EXF_E_CORRUPT
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  rbx
    ret

; Prepare <=2 bitmap-sector snapshots and bit-only postimages. Old cache/disk
; bytes stay unchanged. Every new cluster must be free, including the last one.
exf_g_prepare:
    push rbx
    push r13
    push r14
    push r15
    mov  r13d, [rel exf_g_first]
    mov  r14d, [rel exf_g_count]
    mov  dword [rel exf_g_bitmap_count], 0
.cluster:
    test r14, r14
    jz   .ok
    mov  esi, r13d
    call exf_g_bitmap_location
    test rax, rax
    jnz  .out
    mov  r15d, edx
    xor  ebx, ebx
.find:
    cmp  ebx, [rel exf_g_bitmap_count]
    jae  .new_sector
    lea  rdi, [rel exf_g_bitmap_lbas]
    cmp  rsi, [rdi + rbx * 8]
    je   .found
    inc  ebx
    jmp  .find
.new_sector:
    cmp  ebx, EXF_GROW_BITMAPS
    jae  .unsupported
    lea  rdi, [rel exf_g_bitmap_lbas]
    mov  [rdi + rbx * 8], rsi
    lea  rdi, [rel exf_g_bitmap_clusters]
    mov  [rdi + rbx * 4], r9d
    lea  rdi, [rel exf_g_bitmap_bits]
    mov  dword [rdi + rbx * 4], 0
    inc  dword [rel exf_g_bitmap_count]
    mov  rax, rbx
    shl  rax, 9
    lea  rcx, [rel exf_g_bitmap_old]
    add  rcx, rax
    mov  rdi, [r12 + exf_ctx.dev]
    mov  edx, 1
    call blk_read
    test rax, rax
    jnz  .io
    mov  rax, rbx
    shl  rax, 9
    lea  rdi, [rel exf_g_bitmap_new]
    add  rdi, rax
    lea  rsi, [rel exf_g_bitmap_old]
    add  rsi, rax
    mov  edx, 512
    call memcpy
.found:
    mov  eax, ebx
    shl  eax, 9
    lea  rdi, [rel exf_g_bitmap_new]
    add  rdi, rax
    mov  eax, r15d
    shr  eax, 3
    mov  ecx, r15d
    and  ecx, 7
    mov  edx, 1
    shl  edx, cl
    cmp  dword [rel exf_n_mode], 2
    jae  .reclaim_bit
    test byte [rdi + rax], dl
    jnz  .full
    or   byte [rdi + rax], dl
    jmp  .bit_ready
.reclaim_bit:
    test byte [rdi + rax], dl
    jz   .corrupt
    not  edx
    and  byte [rdi + rax], dl
.bit_ready:
    lea  rdi, [rel exf_g_bitmap_bits]
    inc  dword [rdi + rbx * 4]
    inc  r13d
    dec  r14d
    jmp  .cluster
.ok:
    xor  eax, eax
    jmp  .out
.full:
    mov  dword [rel exfat_disk_last_error], EXF_E_NOSPACE
    jmp  .fail
.corrupt:
    mov  dword [rel exfat_disk_last_error], EXF_E_CORRUPT
    jmp  .fail
.unsupported:
    mov  dword [rel exfat_disk_last_error], EXF_E_UNSUPPORTED
    jmp  .fail
.io:
    mov  dword [rel exfat_disk_last_error], EXF_E_IO
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

; Called by initialization's complete preflight. No mutation, including when a
; late metadata gate refuses. Every real reservation still repeats admission.
exf_g_preflight:
    push rbx
    xor  ebx, ebx
.sector:
    cmp  ebx, [rel exf_g_bitmap_count]
    jae  .ok
    lea  rdi, [rel exf_g_bitmap_lbas]
    mov  rax, [rdi + rbx * 8]
    mov  [rel exf_w_sector], rax
    call exf_w_gate
    test rax, rax
    jnz  .out
    inc  ebx
    jmp  .sector
.ok:
    xor  eax, eax
.out:
    pop  rbx
    ret

; Durable dirty already verified. Compare the entire original bitmap sector
; immediately before setting only its reserved bits. An interrupted reservation
; can leave orphans or uncertain bits; NEVER clear them as an invented rollback.
exf_g_reserve:
    push rbx
    xor  ebx, ebx
.sector:
    cmp  ebx, [rel exf_g_bitmap_count]
    jae  .done
    lea  rdi, [rel exf_g_bitmap_lbas]
    mov  rsi, [rdi + rbx * 8]
    mov  [rel exf_w_sector], rsi
    mov  rdi, [r12 + exf_ctx.dev]
    mov  edx, 1
    lea  rcx, [rel exf_w_verify]
    call blk_read
    test rax, rax
    jnz  .io
    mov  eax, ebx
    shl  eax, 9
    lea  rdi, [rel exf_g_bitmap_old]
    add  rdi, rax
    lea  rsi, [rel exf_w_verify]
    mov  edx, 512
    call memcmp
    test rax, rax
    jnz  .stale
    lea  rdi, [rel exf_w_bounce]
    mov  eax, ebx
    shl  eax, 9
    lea  rsi, [rel exf_g_bitmap_new]
    add  rsi, rax
    mov  edx, 512
    call memcpy
    call exf_w_gate                       ; known refusal cannot claim a new reservation attempt
    test rax, rax
    jnz  .out
    mov  qword [rel exfat_disk_write_stage], 9
    mov  qword [rel exfat_disk_write_allocation], 1
    lea  rdi, [rel exf_g_bitmap_bits]
    mov  eax, [rdi + rbx * 4]
    add  rax, [rel exfat_disk_write_reserved]
    mov  [rel exfat_disk_write_reservation_attempted], rax
    call exf_i_commit
    test rax, rax
    jnz  .out
    lea  rdi, [rel exf_g_bitmap_bits]
    mov  eax, [rdi + rbx * 4]
    add  [rel exfat_disk_write_reserved], rax
    cmp  dword [rel exf_r_active], 0
    je   .replacement_reserved
    inc  dword [rel exf_r_reserved_sectors]
.replacement_reserved:
    mov  qword [r12 + exf_ctx.sec_tag], -1
    inc  ebx
    jmp  .sector
.done:
    cmp  dword [rel exf_g_bitmap_count], 0
    je   .ok
    mov  qword [rel exfat_disk_write_allocation], 2
    mov  qword [rel exfat_disk_write_stage], 10
.ok:
    xor  eax, eax
    jmp  .out
.io:
    mov  dword [rel exfat_disk_last_error], EXF_E_IO
    jmp  .fail
.stale:
    mov  dword [rel exfat_disk_last_error], EXF_E_STALE
.fail:
    mov  rax, -1
.out:
    pop  rbx
    ret

; Initialization publication states (exported diagnostics, not write authority):
; stage: 0 no mutation,1 dirty attempted,2 dirty verified,3 zero/data phase,
; 4 data durable,5 VDL attempted,6 VDL verified,7 clean attempted,8 complete.
; published: 0 unattempted,1 uncertain,2 verified. dirty: 0 clean/no attempt,
; 1 verified dirty,2 uncertain. Failure after stage1 poisons the mount regardless
; of whether a best-effort dirty/error mark succeeds. No rollback or auto repair.

; Commit one prepared 512-byte device sector, with the same exact request gate,
; structural block admission, flush, whole-sector verification and live identity
; checks as the initialized overwrite engine. R12=ctx, w_sector and bounce set.
exf_i_commit:
    call exf_w_gate
    test rax, rax
    jnz  .out
    mov  rdi, [r12 + exf_ctx.dev]
    mov  rsi, [rel exf_w_sector]
    mov  edx, 1
    lea  rcx, [rel exf_w_bounce]
    call blk_write
    test rax, rax
    jnz  .io
    mov  rdi, [r12 + exf_ctx.dev]
    call blk_flush
    test rax, rax
    jnz  .flush
    call exf_w_live
    test rax, rax
    jnz  .out
    mov  rdi, [r12 + exf_ctx.dev]
    mov  rsi, [rel exf_w_sector]
    mov  edx, 1
    lea  rcx, [rel exf_w_verify]
    call blk_read
    test rax, rax
    jnz  .io
    lea  rdi, [rel exf_w_bounce]
    lea  rsi, [rel exf_w_verify]
    mov  edx, 512
    call memcmp
    test rax, rax
    jnz  .verify
    jmp  exf_w_live
.flush:
    mov  dword [rel exfat_disk_last_error], EXF_E_FLUSH
    jmp  .fail
.verify:
    mov  dword [rel exfat_disk_last_error], EXF_E_VERIFY
    jmp  .fail
.io:
    mov  dword [rel exfat_disk_last_error], EXF_E_IO
.fail:
    mov  rax, -1
.out:
    ret

; Read the exact boot and directory sectors and preflight their grants BEFORE
; setting dirty. The primary+stream fields must share one device sector; other
; entry-set bytes may span sectors but remain immutable and checksum-covered.
exf_i_prepare:
    mov  rdi, [r12 + exf_ctx.dev]
    mov  rsi, [r12 + exf_ctx.part_lba]
    mov  edx, 1
    lea  rcx, [rel exf_i_boot]
    call blk_read
    test rax, rax
    jnz  .io
    lea  rdi, [rel exf_i_boot]
    lea  rsi, [r12 + exf_ctx.boot_identity]
    mov  edx, 120
    call memcmp
    test rax, rax
    jnz  .stale
    mov  rdi, [r12 + exf_ctx.dev]
    mov  rsi, [rel exf_i_meta_lba]
    mov  edx, 1
    lea  rcx, [rel exf_i_meta]
    call blk_read
    test rax, rax
    jnz  .io
    lea  rdi, [rel exf_i_meta]
    add  rdi, [rel exf_i_meta_within]
    lea  rsi, [rel exf_w_set]
    mov  edx, 64
    cmp  dword [rel exf_c_mode], 0
    je   .compare_preimage
    mov  edx, [rel exf_c_span]
.compare_preimage:
    call memcmp
    test rax, rax
    jnz  .stale
    mov  rax, [rel exf_i_meta_lba]
    mov  [rel exf_w_sector], rax
    call exf_w_gate
    test rax, rax
    jnz  .out
    mov  rax, [r12 + exf_ctx.part_lba]
    mov  [rel exf_w_sector], rax
    call exf_w_gate
    test rax, rax
    jnz  .out
    jmp  exf_g_preflight                  ; every bitmap sector admitted before dirty
.io:
    mov  dword [rel exfat_disk_last_error], EXF_E_IO
    jmp  .fail
.stale:
    mov  dword [rel exfat_disk_last_error], EXF_E_STALE
.fail:
    mov  rax, -1
.out:
    ret

exf_i_dirty_begin:
    lea  rdi, [rel exf_w_bounce]
    lea  rsi, [rel exf_i_boot]
    mov  edx, 512
    call memcpy
    or   word [rel exf_w_bounce + EBS_FLAGS], EXF_VF_DIRTY
    cmp  dword [rel exf_g_bitmap_count], 0
    je   .dirty_percent_ready
    mov  byte [rel exf_w_bounce + EBS_PCT_USE], 0xff ; unknown BEFORE any allocation change
.dirty_percent_ready:
    mov  rax, [r12 + exf_ctx.part_lba]
    mov  [rel exf_w_sector], rax
    mov  qword [rel exfat_disk_write_stage], 1
    mov  qword [rel exfat_disk_write_dirty], 2
    call exf_i_commit
    test rax, rax
    jnz  .out
    mov  qword [rel exfat_disk_write_dirty], 1
    mov  qword [rel exfat_disk_write_stage], 2
.out:
    ret

; Publish only after ALL zero/data sectors have individually passed flush and
; full readback. VDL and SetChecksum are issued together in one sector write;
; this is NOT an assertion of power-fail sector atomicity. Dirty remains set
; during any torn/uncertain entry-set mutation and the mount is poisoned on error.
exf_i_publish:
    mov  qword [rel exfat_disk_write_stage], 4
    mov  rdi, [r12 + exf_ctx.dev]
    mov  rsi, [rel exf_i_meta_lba]
    mov  edx, 1
    lea  rcx, [rel exf_w_verify]
    call blk_read
    test rax, rax
    jnz  .io
    lea  rdi, [rel exf_w_verify]
    lea  rsi, [rel exf_i_meta]
    mov  edx, 512
    call memcmp
    test rax, rax
    jnz  .stale
    lea  rdi, [rel exf_i_new_set]
    lea  rsi, [rel exf_w_set]
    mov  edx, [rel exf_w_set_len]
    cmp  dword [rel exf_c_mode], 0
    je   .copy_set
    lea  rsi, [rel exf_c_set]
    mov  edx, [rel exf_c_span]
.copy_set:
    call memcpy
    mov  rax, [rel exf_i_new_valid]
    mov  [rel exf_i_new_set + 40], rax
    cmp  dword [rel exf_g_mode], 0
    je   .length_ready
    mov  rax, [rel exf_g_new_length]
    mov  [rel exf_i_new_set + 56], rax
.length_ready:
    ; Same native SetChecksum algorithm, over the entire saved entry set.
    lea  rdi, [rel exf_i_new_set]
    xor  eax, eax
    xor  ecx, ecx
.checksum:
    cmp  ecx, 2
    je   .skip
    cmp  ecx, 3
    je   .skip
    ror  ax, 1
    movzx edx, byte [rdi + rcx]
    add  ax, dx
.skip:
    inc  ecx
    cmp  ecx, [rel exf_w_set_len]
    jb   .checksum
    mov  [rel exf_i_new_set + 2], ax
    lea  rdi, [rel exf_w_bounce]
    lea  rsi, [rel exf_i_meta]
    mov  edx, 512
    call memcpy
    lea  rdi, [rel exf_w_bounce]
    add  rdi, [rel exf_i_meta_within]
    lea  rsi, [rel exf_i_new_set]
    mov  edx, 64                         ; VDL + checksum; other bytes are identical
    cmp  dword [rel exf_c_mode], 0
    je   .copy_publication
    mov  edx, [rel exf_c_span]            ; complete new set, plus end marker when consumed
.copy_publication:
    call memcpy
    mov  rax, [rel exf_i_meta_lba]
    mov  [rel exf_w_sector], rax
    call exf_w_gate                       ; known pre-publication refusal stays unpublished
    test rax, rax
    jnz  .out
    mov  qword [rel exfat_disk_write_stage], 5
    mov  qword [rel exfat_disk_write_published], 1
    call exf_i_commit
    test rax, rax
    jnz  .out
    mov  qword [rel exfat_disk_write_published], 2
    mov  qword [rel exfat_disk_write_stage], 6
    mov  rax, [rel exf_i_new_valid]
    mov  [r12 + exf_ctx.leaf + exf_strm.valid], rax
    cmp  dword [rel exf_g_mode], 0
    je   .stream_published
    mov  rax, [rel exf_g_new_length]
    mov  [r12 + exf_ctx.leaf + exf_strm.length], rax
.stream_published:
    cmp  dword [rel exf_r_active], 0
    jne  exf_r_after_publication          ; verified stream before OLD allocation retirement
.clean_tail:
    ; Only clear OUR verified dirty mark, after checking the entire boot sector.
    ; Backup VolumeFlags are stale by specification and are never used/rewritten.
    mov  rax, [r12 + exf_ctx.part_lba]
    mov  [rel exf_w_sector], rax
    mov  rdi, [r12 + exf_ctx.dev]
    mov  rsi, rax
    mov  edx, 1
    lea  rcx, [rel exf_w_verify]
    call blk_read
    test rax, rax
    jnz  .io
    lea  rdi, [rel exf_w_bounce]
    lea  rsi, [rel exf_i_boot]
    mov  edx, 512
    call memcpy
    or   word [rel exf_w_bounce + EBS_FLAGS], EXF_VF_DIRTY
    cmp  dword [rel exf_g_bitmap_count], 0
    je   .dirty_image_ready
    mov  byte [rel exf_w_bounce + EBS_PCT_USE], 0xff
.dirty_image_ready:
    lea  rdi, [rel exf_w_bounce]
    lea  rsi, [rel exf_w_verify]
    mov  edx, 512
    call memcmp
    test rax, rax
    jnz  .stale
    and  word [rel exf_w_bounce + EBS_FLAGS], ~EXF_VF_DIRTY
    cmp  dword [rel exf_g_bitmap_count], 0
    je   .percent_ready
    mov  byte [rel exf_w_bounce + EBS_PCT_USE], 0xff ; allocation percentage now unknown
.percent_ready:
    mov  qword [rel exfat_disk_write_stage], 7
    mov  qword [rel exfat_disk_write_dirty], 2
    call exf_i_commit
    test rax, rax
    jnz  .out
    mov  qword [rel exfat_disk_write_dirty], 0
    cmp  dword [rel exf_g_bitmap_count], 0
    je   .identity_ready
    mov  byte [r12 + exf_ctx.boot_identity + EBS_PCT_USE], 0xff
    ; The verified clean commit changed precisely PercentInUse. Keep the
    ; original registration identity for copy readers, updating only that byte;
    ; re-registering here would bless unrelated context/route/upcase churn.
    lea  rdx, [rel exf_src_metadata]
    cmp  r12, [rel exf_src_contexts]
    je   .source_percent
    cmp  r12, [rel exf_src_contexts + 8]
    jne  .identity_ready
    add  rdx, EXF_SRC_META_BYTES
.source_percent:
    mov  byte [rdx + 80 + exf_ctx.boot_identity - exf_ctx.clus_count + EBS_PCT_USE], 0xff
.identity_ready:
    cmp  dword [rel exf_a_inflight], 0
    je   .arm_identity_ready
    mov  al, [r12 + exf_ctx.boot_identity + EBS_PCT_USE]
    mov  [r12 + exf_ctx.arm_boot + EBS_PCT_USE], al ; only our verified percentage change
.arm_identity_ready:
    mov  qword [rel exfat_disk_write_stage], 8
    xor  eax, eax
    ret
.io:
    mov  dword [rel exfat_disk_last_error], EXF_E_IO
    jmp  .fail
.stale:
    mov  dword [rel exfat_disk_last_error], EXF_E_STALE
.fail:
    mov  rax, -1
.out:
    ret

; Best effort failure signaling, never rollback. Preserve the original error and
; publication diagnostics. If authority/media identity is gone, or I/O keeps
; failing, dirty=unknown and the poisoned mount still cannot claim clean success.
; Only current request authority may mark this exact main boot sector.
exf_i_failed:
    push rbx
    mov  ebx, [rel exfat_disk_last_error]
    mov  qword [rel exfat_disk_write_dirty], 2
    mov  rax, [r12 + exf_ctx.part_lba]
    mov  [rel exf_w_sector], rax
    call exf_w_gate
    test rax, rax
    jnz  .out
    mov  rdi, [r12 + exf_ctx.dev]
    mov  rsi, [rel exf_w_sector]
    mov  edx, 1
    lea  rcx, [rel exf_w_bounce]
    call blk_read
    test rax, rax
    jnz  .out
    or   word [rel exf_w_bounce + EBS_FLAGS], EXF_VF_DIRTY
    cmp  ebx, EXF_E_IO
    je   .media
    cmp  ebx, EXF_E_FLUSH
    je   .media
    cmp  ebx, EXF_E_VERIFY
    jne  .mark
.media:
    or   word [rel exf_w_bounce + EBS_FLAGS], EXF_VF_MEDIA_FAIL
.mark:
    call exf_i_commit
    test rax, rax
    jnz  .out
    mov  qword [rel exfat_disk_write_dirty], 1
.out:
    mov  [rel exfat_disk_last_error], ebx
    pop  rbx
    ret

; Registered FSARM exFAT identity is its actual32-bit serial, not an invented
; UUID. The private arm records this exact incarnation/device/window/boot. It
; carries NO storage grant; every registered mutation still enters w_gate.
exfat_disk_arm:
    push rbx
    push r12
    push r13
    push r14
    mov  r14d, esi
    call exf_a_ctx_of
    test rax, rax
    jz   .stale
    mov  r12, rax
    mov  r13, rdx                       ; exact fsmount
    call exf_a_authority
    test rax, rax
    jnz  .out
    mov  dword [r12 + exf_ctx.armed], 0
    cmp  r14d, [r12 + exf_ctx.serial]
    jne  .stale
    cmp  qword [r12 + exf_ctx.incarnation], 0
    je   .stale
    mov  rdi, [r12 + exf_ctx.dev]
    mov  rsi, [r12 + exf_ctx.part_lba]
    mov  edx, 1
    lea  rcx, [rel exf_boot_buf]
    call blk_read
    test rax, rax
    jnz  .io
    lea  rdi, [rel exf_boot_buf]
    lea  rsi, [r12 + exf_ctx.boot_identity]
    mov  edx, 120
    call memcmp
    test rax, rax
    jnz  .stale
    cmp  word [rel exf_boot_buf + EBS_FLAGS], 0
    jne  .stale
    call exf_a_authority                 ; repeat after I/O before publishing ready state
    test rax, rax
    jnz  .out
    mov  [r12 + exf_ctx.arm_serial], r14d
    mov  [r12 + exf_ctx.arm_self], r13
    mov  rax, [r12 + exf_ctx.dev]
    mov  [r12 + exf_ctx.arm_dev], rax
    mov  rax, [r12 + exf_ctx.info_identity]
    mov  [r12 + exf_ctx.arm_info], rax
    mov  rax, [r12 + exf_ctx.ops_identity]
    mov  [r12 + exf_ctx.arm_ops], rax
    mov  rax, [r12 + exf_ctx.media_gen]
    mov  [r12 + exf_ctx.arm_gen], rax
    mov  rax, [r12 + exf_ctx.part_lba]
    mov  [r12 + exf_ctx.arm_part], rax
    mov  rax, [r12 + exf_ctx.part_sectors]
    mov  [r12 + exf_ctx.arm_sectors], rax
    mov  rax, [r12 + exf_ctx.incarnation]
    mov  [r12 + exf_ctx.arm_incarnation], rax
    mov  eax, [r12 + exf_ctx.handle]
    mov  [r12 + exf_ctx.arm_handle], rax
    lea  rdi, [r12 + exf_ctx.arm_boot]
    lea  rsi, [r12 + exf_ctx.boot_identity]
    mov  edx, 120
    call memcpy
    mov  dword [r12 + exf_ctx.armed], 1
    mov  dword [rel exfat_disk_last_error], EXF_E_NONE
    xor  eax, eax
    jmp  .out
.stale:
    mov  dword [rel exfat_disk_last_error], EXF_E_STALE
    jmp  .fail
.io:
    mov  dword [rel exfat_disk_last_error], EXF_E_IO
.fail:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=dev -> EAX 1 when an exFAT mount views it. No I/O.
exfat_disk_device_mounted:
    push rbx
    push r12
    mov  r12, rdi
    xor  ebx, ebx
.next:
    cmp  ebx, VFS_MAX_MOUNTS
    jae  .no
    mov  edi, ebx
    inc  ebx
    call exf_a_ctx_of
    test rax, rax
    jz   .next
    cmp  r12, [rax + exf_ctx.dev]
    jne  .next
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

; T5-15.4 local arm (V-C7). EDI=handle -> RAX 0 / -1. No verb: dispatch calls it under
; the local bit. Same exact arm, on the context's own serial; ends on swap as ever.
exfat_disk_local_arm:
    push rdi
    call exf_a_ctx_of
    pop  rdi
    test rax, rax
    jz   .no
    cmp  dword [rax + exf_ctx.armed], 1
    je   .done
    mov  esi, [rax + exf_ctx.serial]
    jmp  exfat_disk_arm
.done:
    xor  eax, eax
    ret
.no:
    mov  rax, -1
    ret

exfat_disk_disarm:
    push r12
    call exf_a_ctx_of
    test rax, rax
    jz   .stale
    mov  r12, rax
    call exf_a_authority
    test rax, rax
    jnz  .out
    mov  dword [r12 + exf_ctx.armed], 0
    mov  dword [rel exfat_disk_last_error], EXF_E_NONE
    xor  eax, eax
    jmp  .out
.stale:
    mov  dword [rel exfat_disk_last_error], EXF_E_STALE
    mov  rax, -1
.out:
    pop  r12
    ret

; RDI=handle -> RAX=exact mounted exFAT context,RDX=fsmount, or0. No I/O.
exf_a_ctx_of:
    call vfs_mount_ptr
    test rax, rax
    jz   .out
    lea  rcx, [rel exf_ops]
    cmp  [rax + fsmount.ops], rcx
    jne  .no
    mov  rdx, rax
    mov  rax, [rdx + fsmount.priv]
    test rax, rax
    jz   .out
    cmp  dword [rax + exf_ctx.mounted], 1
    jne  .no
    ret
.no:
    xor  eax, eax
.out:
    ret

; Arm/disarm both need this request's verified owner and SPECIAL intent plus
; the unchanged whole-partition request gate. No setter/owned token is used.
; Peter decision 10 (LEDGER 85949, 87106): a public 0.1 build writes exFAT only on removable
; media. R12=ctx -> RAX 0 / -1 EXF_E_AUTH.
%if EXF_PUBLIC_MEDIA_GATE
exf_public_media_gate:
    mov  rax, [r12 + exf_ctx.dev]
    test rax, rax
    jz   .fixed
    mov  rax, [rax + dev.info]
    test rax, rax
    jz   .fixed
    cmp  byte [rax + blk_info.removable], 0
    jne  .pass
    test dword [rax + blk_info.flags], BLKF_REMOVABLE
    jnz  .pass
.fixed:
    mov  dword [rel exfat_disk_last_error], EXF_E_AUTH
    mov  rax, -1
    ret
.pass:
    xor  eax, eax
    ret
%endif

; T5-15.4: exFAT is never the MSI's reserved partition.
exf_volume_pin:
    push rdi
    push rsi
    push rdx
    push rcx
    push r8
    mov  rdi, [r12 + exf_ctx.dev]
    xor  esi, esi
    xor  edx, edx
    xor  ecx, ecx
    xor  r8d, r8d
    call volume_pin_admits
    pop  r8
    pop  rcx
    pop  rdx
    pop  rsi
    pop  rdi
    ret

exf_a_authority:
%if EXF_PUBLIC_MEDIA_GATE
    call exf_public_media_gate
    test rax, rax
    jnz  .out
%endif
    call storage_access_request_owner
    cmp  eax, 1
    jne  .no
    mov  rdi, [r12 + exf_ctx.dev]
    call storage_access_intent_for_dev
    cmp  eax, SA_INTENT_SPECIAL
    jne  .no
    call exf_w_live
    test rax, rax
    jnz  .out
    call exf_volume_pin
    test rax, rax
    jnz  .no
    mov  rdi, [r12 + exf_ctx.dev]
    mov  rsi, [r12 + exf_ctx.part_lba]
    mov  rdx, [r12 + exf_ctx.part_sectors]
    lea  r8, [rel str_exf_a_gate]
    call storage_access_require_request
    test rax, rax
    jnz  .no
    mov  rdi, [r12 + exf_ctx.dev]
    mov  rsi, [r12 + exf_ctx.part_lba]
    mov  rdx, [r12 + exf_ctx.part_sectors]
    call storage_access_write_admitted
    test rax, rax
    jz   .out
.no:
    mov  dword [rel exfat_disk_last_error], EXF_E_AUTH
    mov  rax, -1
.out:
    ret

; Pure admission hint: no IO, gate, counter/state write or request capture.
exf_a_mutate_armed:
    push r12
    mov  r12, [rdi + fsmount.priv]
    test r12, r12
    jz   .no
    cmp  rdi, [r12 + exf_ctx.arm_self]
    jne  .no
    call exf_a_ctx_check
    pop  r12
    ret
.no:
    xor  eax, eax
    pop  r12
    ret

; R12=ctx ->1/0, pure. Repeated by every adapter write gate. Mutable live boot
; contents are still re-read by the actual backend before mutation.
exf_a_ctx_check:
    cmp  dword [r12 + exf_ctx.armed], 1
    jne  .no
    cmp  dword [r12 + exf_ctx.mounted], 1
    jne  .no
    cmp  dword [r12 + exf_ctx.vflags], 0
    jne  .no
    mov  rax, [r12 + exf_ctx.incarnation]
    cmp  rax, [r12 + exf_ctx.arm_incarnation]
    jne  .no
    mov  eax, [r12 + exf_ctx.serial]
    cmp  eax, [r12 + exf_ctx.arm_serial]
    jne  .no
    mov  eax, [r12 + exf_ctx.handle]
    cmp  rax, [r12 + exf_ctx.arm_handle]
    jne  .no
    mov  rdi, rax
    call vfs_mount_ptr
    test rax, rax
    jz   .no
    cmp  rax, [r12 + exf_ctx.arm_self]
    jne  .no
    cmp  [rax + fsmount.priv], r12
    jne  .no
    lea  rcx, [rel exf_ops]
    cmp  [rax + fsmount.ops], rcx
    jne  .no
    mov  rax, [r12 + exf_ctx.part_lba]
    cmp  rax, [r12 + exf_ctx.arm_part]
    jne  .no
    mov  rax, [r12 + exf_ctx.part_sectors]
    cmp  rax, [r12 + exf_ctx.arm_sectors]
    jne  .no
    mov  rdi, [r12 + exf_ctx.dev]
    cmp  rdi, [r12 + exf_ctx.arm_dev]
    jne  .no
    cmp  dword [rdi + dev.health], HEALTH_OK
    jne  .no
    test dword [rdi + dev.flags], BLKF_RO
    jnz  .no
    mov  rax, [rdi + dev.info]
    cmp  rax, [r12 + exf_ctx.arm_info]
    jne  .no
    cmp  rax, [r12 + exf_ctx.info_identity]
    jne  .no
    mov  rcx, [rdi + dev.ops]
    cmp  rcx, [r12 + exf_ctx.arm_ops]
    jne  .no
    cmp  rcx, [r12 + exf_ctx.ops_identity]
    jne  .no
    mov  rcx, [rax + blk_info.media_generation]
    cmp  rcx, [r12 + exf_ctx.arm_gen]
    jne  .no
    cmp  rcx, [r12 + exf_ctx.media_gen]
    jne  .no
    test dword [rax + blk_info.flags], BLKF_RO
    jnz  .no
    cmp  dword [rax + blk_info.sector_size], 512
    jne  .no
    mov  ecx, [rax + blk_info.logical_sector_bytes]
    test ecx, ecx
    jz   .geometry
    cmp  ecx, 512
    jne  .no
.geometry:
    mov  rcx, [rax + blk_info.capabilities]
    test rcx, rcx
    jz   .boot_identity
    and  ecx, BLKCAP_READ | BLKCAP_WRITE | BLKCAP_FLUSH
    cmp  ecx, BLKCAP_READ | BLKCAP_WRITE | BLKCAP_FLUSH
    jne  .no
.boot_identity:
    lea  rdi, [r12 + exf_ctx.boot_identity]
    lea  rsi, [r12 + exf_ctx.arm_boot]
    mov  edx, 120
    call memcmp
    test rax, rax
    jnz  .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; Existing VFS path mutation ABI. Canonical 8.3 trees under the volume rule,
; including same-media cross-parent rename. CREATE additionally admits a bounded
; package leaf using the SAME single-name entry set; no alias or authority change.
; FSWRITE retains its write_at route.
exf_a_mutate_path:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  ebx, r8d
    mov  r13, rdi
    mov  r14, rdx
    mov  r15, rcx
    cmp  dword [rel exf_a_inflight], 0
    jne  .unsupported
    cmp  dword [rel exf_w_active], 0
    jne  .unsupported
    cmp  ebx, FS_MUT_UPDATE
    je   .op
    cmp  ebx, FS_MUT_CREATE
    je   .op
    cmp  ebx, FS_MUT_DELETE
    je   .op
    cmp  ebx, FS_MUT_RENAME
    je   .op
    cmp  ebx, FS_MUT_MKDIR
    je   .op
    cmp  ebx, FS_MUT_RMDIR
    jne  .unsupported
.op:
    mov  dword [rel exf_m_cross], 0
    mov  dword [rel exf_m_gate_active], 0
    mov  [rel exf_a_path_input], rsi
    mov  r12, [r13 + fsmount.priv]
    mov  rdi, r13
    call exf_a_mutate_armed
    cmp  rax, 1
    jne  .auth
    call exf_a_authority                 ; THIS request's owner/intent, even on TEST_SCRATCH
    test rax, rax
    jnz  .out
    ; The hint clobbers caller-saved RSI; recover the request's synchronous scratch.
    mov  rsi, [rel exf_a_path_input]
    jmp  .convert
.convert:
    mov  rsi, [rel exf_a_path_input]
    lea  rdi, [rel exf_n_old_path]
    lea  rdx, [rel exf_a_old11]
    xor  r8d, r8d                       ; file leaf
    cmp  ebx, FS_MUT_CREATE
    jne  .not_create_kind
    mov  r8d, 3                         ; 8.3 or bounded .PAOSAPP create-only leaf
.not_create_kind:
    cmp  ebx, FS_MUT_RENAME
    jne  .not_rename_kind
    mov  r8d, 2                         ; typed file or directory leaf
.not_rename_kind:
    cmp  ebx, FS_MUT_MKDIR
    je   .directory_kind
    cmp  ebx, FS_MUT_RMDIR
    jne  .parse_old
.directory_kind:
    mov  r8d, 1
.parse_old:
    call exf_t_path
    test rax, rax
    jnz  .path_refused
    mov  [rel exf_n_old_len], edx
    mov  [rel exf_t_old_leaf], r9d
    mov  [rel exf_t_kind], ecx
    cmp  ebx, FS_MUT_RENAME
    jne  .dispatch
    mov  rsi, r14
    lea  rdi, [rel exf_n_new_path]
    lea  rdx, [rel exf_a_new11]
    mov  r8d, [rel exf_t_kind]
    call exf_t_path
    test rax, rax
    jnz  .path_refused
    mov  [rel exf_n_new_len], edx
    mov  [rel exf_t_new_leaf], r9d
    cmp  r9d, [rel exf_t_old_leaf]
    jne  .cross_parent
    lea  rdi, [rel exf_n_old_path]
    lea  rsi, [rel exf_n_new_path]
    mov  edx, r9d
    call memcmp
    test rax, rax
    jz   .dispatch
.cross_parent:
    mov  dword [rel exf_m_cross], 1
.dispatch:
    mov  dword [rel exf_t_active], 1
    mov  dword [rel exf_a_inflight], 1
    mov  rdi, r13
    lea  rsi, [rel exf_a_old11]
    cmp  ebx, FS_MUT_MKDIR
    je   .mkdir
    cmp  ebx, FS_MUT_RMDIR
    je   .rmdir
    cmp  ebx, FS_MUT_DELETE
    je   .delete
    cmp  ebx, FS_MUT_RENAME
    je   .rename
    cmp  ebx, FS_MUT_UPDATE
    je   .update
    mov  rdx, r14
    mov  rcx, r15
    call exf_op_create
    jmp  .result
.update:
    mov  rdx, r14
    mov  rcx, r15
    call exf_r_update
    jmp  .result
.mkdir:
    call exf_d_mkdir
    jmp  .result
.rmdir:
    call exf_d_rmdir
    jmp  .result
.delete:
    call exf_op_delete
    jmp  .result
.rename:
    lea  rdx, [rel exf_a_new11]
    call exf_op_rename
.result:
    mov  dword [rel exf_m_gate_active], 0
    mov  dword [rel exf_m_cross], 0
    mov  dword [rel exf_t_active], 0
    mov  dword [rel exf_a_inflight], 0
    cmp  rax, -1
    jne  .ok
    cmp  dword [rel exfat_disk_last_error], EXF_E_EXISTS
    je   .out
    cmp  dword [rel exfat_disk_last_error], EXF_E_NOTFOUND
    je   .out
    mov  dword [r12 + exf_ctx.armed], 0   ; dirty/poison/stale/unsupported actual backend never stays ready
    jmp  .out
.ok:
    xor  eax, eax
    jmp  .out
.path_refused:
    ; Only this synchronous parser's explicit causes earn typed observations.
    ; Other unsupported grammar remains distinct from invalid exFAT names.
    cmp  rax, EXF_E_NAME_INVALID
    je   .path_cause
    cmp  rax, EXF_E_PATH_LONG
    jne  .unsupported
.path_cause:
    mov  [rel exfat_disk_last_error], eax
    jmp  .fail
.auth:
    mov  dword [rel exfat_disk_last_error], EXF_E_AUTH
    jmp  .fail
.unsupported:
    mov  dword [rel exfat_disk_last_error], EXF_E_UNSUPPORTED
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; RSI=root absolute Z path -> RDI=name11. Bounded and canonical ASCII 8.3. T5-15.4:
; the volume rule decides where; this decides only what a name may be.
exf_a_path11:
    push rbx
    mov  rbx, rdi
    test rsi, rsi
    jz   .no
    cmp  byte [rsi], '/'
    jne  .no
    xor  ecx, ecx
.length:
    cmp  ecx, 13
    ja   .no
    cmp  byte [rsi + rcx], 0
    je   .sized
    inc  ecx
    jmp  .length
.sized:
    cmp  ecx, 2
    jb   .no
    mov  dword [rbx], 0x20202020
    mov  dword [rbx + 4], 0x20202020
    mov  word [rbx + 8], 0x2020
    mov  byte [rbx + 10], ' '
    mov  edx, 1
    xor  r8d, r8d
    xor  r9d, r9d
.char:
    movzx eax, byte [rsi + rdx]
    test eax, eax
    jz   .done
    cmp  al, '.'
    je   .dot
    cmp  al, 'a'
    jb   .upper
    cmp  al, 'z'
    ja   .upper
    sub  al, 32
.upper:
    cmp  al, '_'
    je   .valid
    cmp  al, '-'
    je   .valid
    cmp  al, '~'
    je   .valid
    cmp  al, '0'
    jb   .no
    cmp  al, '9'
    jbe  .valid
    cmp  al, 'A'
    jb   .no
    cmp  al, 'Z'
    ja   .no
.valid:
    cmp  r9d, 0
    jne  .ext
    cmp  r8d, 8
    jae  .no
    jmp  .store
.ext:
    cmp  r8d, 11
    jae  .no
.store:
    mov  [rbx + r8], al
    inc  r8d
    inc  edx
    jmp  .char
.dot:
    test r9d, r9d
    jnz  .no
    test r8d, r8d
    jz   .no
    mov  r9d, 1
    mov  r8d, 8
    inc  edx
    jmp  .char
.done:
    test r8d, r8d
    jz   .no
    test r9d, r9d
    jz   .named                          ; no extension
    cmp  r8d, 8
    je   .no                             ; "NAME." is not canonical
.named:
    xor  eax, eax
    pop  rbx
    ret
.no:
    mov  rax, -1
    pop  rbx
    ret

; Bounded scratch tree parser. RSI=Z path,RDI=64B canonical output,RDX=name11,
; R8D=0 file/1 dir/2 either/3 create -> RAX0/-1 or explicit EXF_E_NAME_INVALID/
; EXF_E_PATH_LONG; EDX=len,ECX=kind,R9D=leaf offset on success.
; Explicit causes observe existing refusals only; they grant no new grammar.
; At most4 components, each ancestor a canonical directory name, last an 8.3 file
; or directory. No command classifier result, dot/escape or native alias is trusted.
exf_t_path:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8
    mov  [rsp], r8d
    mov  dword [rsp + 4], 0
    mov  r12, rdx
    mov  r13, rdi
    test rsi, rsi
    jz   .no
    cmp  byte [rsi], '/'
    jne  .no
    xor  r14d, r14d
.copy:
    movzx eax, byte [rsi + r14]
    test eax, eax
    jz   .copied
    cmp  r14d, 63
    jae  .path_long
    cmp  al, '/'                         ; path delimiter, never a name unit
    je   .copy_unit
    call exf_unit_forbidden              ; same native name rule as the reader
    jc   .name_invalid
.copy_unit:
    cmp  al, 'a'
    jb   .upper
    cmp  al, 'z'
    ja   .upper
    sub  al, 32
.upper:
    mov  [r13 + r14], al
    inc  r14d
    jmp  .copy
.copied:
    mov  byte [r13 + r14], 0
    mov  r15d, 1
    mov  ebx, 1
.scan:
    cmp  ebx, r14d
    je   .component
    cmp  byte [r13 + rbx], '/'
    je   .component
    inc  ebx
    jmp  .scan
.component:
    mov  edx, ebx
    sub  edx, r15d
    jz   .no
    cmp  dword [rsp], 3
    jne  .short_component
    cmp  ebx, r14d
    jne  .short_component              ; ancestors retain the exact old grammar
    cmp  edx, 15                        ; one UTF16 name entry, no set growth
    ja   .no
    jmp  .component_size_ok
.short_component:
    cmp  edx, 12
    ja   .no
.component_size_ok:
    inc  dword [rsp + 4]
    cmp  dword [rsp + 4], 4
    ja   .no
    mov  byte [rel exf_t_component], '/'
    lea  rdi, [rel exf_t_component + 1]
    lea  rsi, [r13 + r15]
    call memcpy
    mov  edx, ebx
    sub  edx, r15d
    lea  rdi, [rel exf_t_component + 1]
    mov  byte [rdi + rdx], 0
    lea  rsi, [rel exf_t_component]
    cmp  ebx, r14d
    je   .leaf
    lea  rdi, [rel exf_t_component11]
    call exf_d_path11
    test rax, rax
    jnz  .no
    inc  ebx
    mov  r15d, ebx
    jmp  .scan
.leaf:
    mov  rdi, r12
    cmp  dword [rsp], 1
    je   .directory
    cmp  dword [rsp], 2                 ; rename: a leaf with no dot is a directory
    jne  .file_leaf
    push rsi
    mov  rax, rsi
.dot_scan:
    cmp  byte [rax], 0
    je   .dotless
    cmp  byte [rax], '.'
    je   .dotted
    inc  rax
    jmp  .dot_scan
.dotless:
    pop  rsi
    jmp  .directory
.dotted:
    pop  rsi
.file_leaf:
    call exf_a_path11
    test rax, rax
    jz   .file
    cmp  dword [rsp], 3
    jne  .not_package
    lea  rsi, [rel exf_t_component]
    call exf_p_leaf
    test rax, rax
    jnz  .no
    mov  ecx, 3                         ; private parsed kind, not caller authority
    jmp  .ok
.not_package:
    cmp  dword [rsp], 2
    jne  .no
    lea  rsi, [rel exf_t_component]
    mov  rdi, r12
.directory:
    call exf_d_path11
    test rax, rax
    jnz  .no
    mov  ecx, 1
    jmp  .ok
.file:
    xor  ecx, ecx
.ok:
    mov  edx, r14d
    mov  r9d, r15d
    xor  eax, eax
    jmp  .out
.name_invalid:
    mov  eax, EXF_E_NAME_INVALID
    jmp  .out
.path_long:
    mov  eax, EXF_E_PATH_LONG
    jmp  .out
.no:
    mov  rax, -1
.out:
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Canonical leaf /<1..7 [A-Z0-9_]>.PAOSAPP, already folded by exf_t_path.
; One name entry holds exactly15 UTF16 units. This is only a CREATE parser:
; UPDATE/DELETE/RENAME and root name11 APIs retain their old admitted operands.
; No name11 alias is emitted or later used as the destination.
exf_p_leaf:
    xor  ecx, ecx
.base:
    movzx eax, byte [rsi + rcx + 1]
    cmp  al, '.'
    je   .suffix
    cmp  ecx, 7
    jae  .no
    cmp  al, '_'
    je   .char
    cmp  al, '0'
    jb   .no
    cmp  al, '9'
    jbe  .char
    cmp  al, 'A'
    jb   .no
    cmp  al, 'Z'
    ja   .no
.char:
    inc  ecx
    jmp  .base
.suffix:
    test ecx, ecx
    jz   .no
    lea  rdx, [rsi + rcx + 2]
    ; Bytewise, stopping at the first mismatch (including a short NUL).
    lea  rdi, [rel exf_p_suffix]
    xor  ecx, ecx
.match:
    mov  al, [rdi + rcx]
    cmp  al, [rdx + rcx]
    jne  .no
    test al, al
    jz   .ok
    inc  ecx
    jmp  .match
.ok:
    xor  eax, eax
    ret
.no:
    mov  rax, -1
    ret

; Strict lookup while a registered tree transaction is active. Scan the complete
; directory for a unique actual upcase match, then restore that exact set/leaf.
; Reject an ASCII/upcase alias rather than creating into another named estate.
; Native reader lookups outside this synchronous adapter retain their old path.
exf_t_find:
    push rbx
    mov  dword [rel exf_t_find_count], 0
.next:
    call exf_next_set
    test rax, rax
    js   .out
    jz   .end
    cmp  rax, 1
    jne  .next
    call exf_set_decode
    test rax, rax
    jnz  .out
    mov  ecx, [rel exf_name_len]
    cmp  ecx, [rel exf_comp_len]
    jne  .next
    mov  rbx, [r12 + exf_ctx.upcase]
    lea  rsi, [rel exf_name16]
    lea  rdi, [rel exf_comp16]
    xor  edx, edx
.unit:
    movzx eax, word [rsi + rdx * 2]
    movzx eax, word [rbx + rax * 2]
    movzx r8d, word [rdi + rdx * 2]
    movzx r8d, word [rbx + r8 * 2]
    cmp  eax, r8d
    jne  .next
    inc  edx
    cmp  edx, ecx
    jb   .unit
    cmp  dword [rel exf_set_count], 2
    jne  .no
    xor  edx, edx
.ascii:
    movzx eax, word [rsi + rdx * 2]
    cmp  eax, 128
    jae  .no
    cmp  al, 'a'
    jb   .canonical
    cmp  al, 'z'
    ja   .canonical
    sub  al, 32
.canonical:
    cmp  ax, [rdi + rdx * 2]
    jne  .no
    inc  edx
    cmp  edx, ecx
    jb   .ascii
    inc  dword [rel exf_t_find_count]
    cmp  dword [rel exf_t_find_count], 1
    ja   .no
    mov  rax, [rel exf_set_location]
    mov  [rel exf_t_find_location], rax
    lea  rdi, [rel exf_t_find_set]
    lea  rsi, [rel exf_set_buf]
    mov  edx, 96
    call memcpy
    jmp  .next
.end:
    cmp  dword [rel exf_t_find_count], 0
    je   .out                           ; RAX=0, absent
    lea  rdi, [rel exf_set_buf]
    lea  rsi, [rel exf_t_find_set]
    mov  edx, 96
    call memcpy
    mov  dword [rel exf_set_count], 2
    mov  rax, [rel exf_t_find_location]
    mov  [rel exf_set_location], rax
    call exf_set_decode
    test rax, rax
    jnz  .out
    mov  eax, 1
    jmp  .out
.no:
    mov  dword [rel exfat_disk_last_error], EXF_E_UNSUPPORTED
    mov  rax, -1
.out:
    pop  rbx
    ret

; Snapshot (ECX0) or revalidate (ECX1) every actual ancestor set/location, plus
; its writable one-cluster NoFatChain directory shape. Three bounded ancestors
; maximum. R12=ctx, private canonical old path. Direct name11 APIs keep root.
exf_t_parent:
    push rbx
    push r13
    push r14
    push r15
    mov  r13d, ecx
    cmp  dword [rel exf_t_active], 0
    je   .root
    mov  qword [r12 + exf_ctx.sec_tag], -1
    mov  qword [r12 + exf_ctx.fat_tag], -1
    mov  r14d, 1
    xor  r15d, r15d
.scan:
    cmp  r14d, [rel exf_t_old_leaf]
    jae  .selected
    lea  rax, [rel exf_n_old_path]
    cmp  byte [rax + r14], '/'
    jne  .next
    lea  rsi, [rel exf_n_old_path]
    mov  edx, r14d
    call exf_resolve
    test rax, rax
    jnz  .out
    mov  eax, [r12 + exf_ctx.leaf + exf_strm.attr]
    test eax, EXF_ATTR_DIR
    jz   .no
    test eax, 1
    jnz  .no
    cmp  dword [r12 + exf_ctx.leaf + exf_strm.flags], EXF_SF_ALLOC | EXF_SF_NOFATCHAIN
    jne  .no
    mov  ecx, [r12 + exf_ctx.clus_shift]
    mov  rax, 1
    shl  rax, cl
    cmp  rax, EXF_WRITE_MAX
    ja   .no
    cmp  rax, [r12 + exf_ctx.leaf + exf_strm.length]
    jne  .no
    cmp  rax, [r12 + exf_ctx.leaf + exf_strm.valid]
    jne  .no
    cmp  dword [rel exf_set_count], 2
    jne  .no
    cmp  r15d, 3
    jae  .no
    imul ebx, r15d, 104
    lea  rax, [rel exf_t_ancestors]
    add  rbx, rax
    mov  rax, [rel exf_set_location]
    test r13d, r13d
    jnz  .compare
    mov  [rbx], rax
    lea  rdi, [rbx + 8]
    lea  rsi, [rel exf_set_buf]
    mov  edx, 96
    call memcpy
    jmp  .stored
.compare:
    cmp  rax, [rbx]
    jne  .stale
    lea  rdi, [rbx + 8]
    lea  rsi, [rel exf_set_buf]
    mov  edx, 96
    call memcmp
    test rax, rax
    jnz  .stale
.stored:
    inc  r15d
.next:
    inc  r14d
    jmp  .scan
.selected:
    test r15d, r15d
    jz   .root
    lea  rsi, [r12 + exf_ctx.leaf]
    jmp  .parent
.root:
    lea  rsi, [r12 + exf_ctx.root]
.parent:
    lea  rdi, [rel exf_i_parent]
    mov  edx, exf_strm_size
    test r13d, r13d
    jnz  .parent_compare
    call memcpy
    xor  eax, eax
    jmp  .out
.parent_compare:
    call memcmp
    test rax, rax
    jz   .out
.stale:
    mov  dword [rel exfat_disk_last_error], EXF_E_STALE
    jmp  .fail
.no:
    mov  dword [rel exfat_disk_last_error], EXF_E_UNSUPPORTED
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

; Directory names are 1..8 canonical ASCII characters, no extension or subpath.
; Independent of the command layer.
exf_d_path11:
    push rbx
    mov  rbx, rdi
    test rsi, rsi
    jz   .no
    cmp  byte [rsi], '/'
    jne  .no
    mov  dword [rbx], 0x20202020
    mov  dword [rbx + 4], 0x20202020
    mov  word [rbx + 8], 0x2020
    mov  byte [rbx + 10], ' '
    xor  ecx, ecx
.char:
    movzx eax, byte [rsi + rcx + 1]
    test eax, eax
    jz   .end
    cmp  ecx, 8
    jae  .no
    cmp  al, 'a'
    jb   .upper
    cmp  al, 'z'
    ja   .upper
    sub  al, 32
.upper:
    cmp  al, '_'
    je   .valid
    cmp  al, '-'
    je   .valid
    cmp  al, '~'
    je   .valid
    cmp  al, '0'
    jb   .no
    cmp  al, '9'
    jbe  .valid
    cmp  al, 'A'
    jb   .no
    cmp  al, 'Z'
    ja   .no
.valid:
    mov  [rbx + rcx], al
    inc  ecx
    jmp  .char
.end:
    test ecx, ecx
    jz   .no
    xor  eax, eax
    pop  rbx
    ret
.no:
    mov  rax, -1
    pop  rbx
    ret

; Every entry of the complete single-cluster directory is checked, even after
; an end marker. No FAT32 dots. Only unused or known inactive ordinary entry
; types are accepted; any live, system or unknown entry refuses before effects.
exf_d_empty:
    lea  rdi, [rel exf_n_stream]
    call exf_dir_open
.entry:
    call exf_dir_next
    test rax, rax
    js   .out
    jz   .ok
    movzx ecx, byte [rax]
    test ecx, ecx
    jz   .entry
    cmp  ecx, EXF_DE_FILE & 0x7f
    je   .entry
    cmp  ecx, EXF_DE_STREAM & 0x7f
    je   .entry
    cmp  ecx, EXF_DE_NAME & 0x7f
    je   .entry
    mov  dword [rel exfat_disk_last_error], EXF_E_UNSUPPORTED
    mov  rax, -1
    ret
.ok:
    xor  eax, eax
.out:
    ret

; Namespace transactions share the existing request gates/commit/failure/clean
; machinery. Mode1 rename,mode2 file delete,mode3 bounded empty directory remove.
exf_d_rmdir:
    mov  ecx, 3
    jmp  exf_n_operation
exf_op_rename:
    mov  ecx, 1
    jmp  exf_n_operation
exf_op_delete:
    xor  edx, edx
    mov  ecx, 2
exf_n_operation:
    push rbx
    push r12
    push r13
    push r14
    push r15
    cmp  dword [rel exf_w_active], 0
    jne  .busy
    EXF_ENTER
    mov  r14, rdx
    mov  [rel exf_n_mode], ecx
    mov  dword [rel exf_w_active], 1
    mov  dword [rel exf_c_mode], 0
    mov  dword [rel exf_g_mode], 0
    mov  dword [rel exf_i_mode], 1
    xor  eax, eax
    mov  [rel exf_n_meta_cluster2], eax
    mov  [rel exf_m_gate_active], eax
    mov  [rel exf_m_failure], eax
    mov  [rel exf_m_dirty_started], eax
    mov  [rel exf_m_account], eax
    mov  [rel exf_m_census], eax
    mov  [rel exf_m_dst_hits], eax
    mov  [rel exfat_disk_replace_state], rax
    mov  [rel exfat_disk_move_state], rax
    mov  [rel exfat_disk_move_destination_attempted], rax
    mov  [rel exfat_disk_move_destination_confirmed], rax
    mov  [rel exfat_disk_move_source_attempted], rax
    mov  [rel exfat_disk_move_source_confirmed], rax
    mov  [rel exf_g_bitmap_count], eax
    mov  [rel exf_g_count], eax
    mov  [rel exf_w_plan_count], eax
    mov  [rel exfat_disk_write_stage], rax
    mov  [rel exfat_disk_write_published], rax
    mov  [rel exfat_disk_write_dirty], rax
    mov  [rel exfat_disk_write_confirmed], rax
    mov  [rel exfat_disk_write_attempted], rax
    mov  [rel exfat_disk_write_zeroed], rax
    mov  [rel exfat_disk_write_zero_attempted], rax
    mov  [rel exfat_disk_write_allocation], rax
    mov  [rel exfat_disk_write_reserved], rax
    mov  [rel exfat_disk_write_reservation_attempted], rax
    mov  [rel exfat_disk_write_reclaimed], rax
    mov  [rel exfat_disk_write_reclaim_attempted], rax
    mov  [rel exfat_disk_write_reclaim_state], rax
    cmp  dword [rel exf_t_active], 0
    jne  .names_ready
    call exf_n_name
    test rax, rax
    jnz  .range
    mov  [rel exf_n_old_len], edx
    lea  rdi, [rel exf_n_old_path]
    call memcpy
    cmp  dword [rel exf_n_mode], 1
    jne  .names_ready
    mov  rsi, r14
    call exf_n_name
    test rax, rax
    jnz  .range
    mov  [rel exf_n_new_len], edx
    lea  rdi, [rel exf_n_new_path]
    call memcpy
.names_ready:
    call storage_access_request_owner
    mov  [rel exf_w_owner], eax
    mov  rdi, [r12 + exf_ctx.dev]
    call storage_access_intent_for_dev
    mov  [rel exf_w_intent], eax
    call exf_w_live
    test rax, rax
    jnz  .fail
    mov  qword [r12 + exf_ctx.sec_tag], -1
    mov  qword [r12 + exf_ctx.fat_tag], -1
    mov  rdi, [r12 + exf_ctx.dev]
    mov  rsi, [r12 + exf_ctx.part_lba]
    mov  edx, 1
    lea  rcx, [rel exf_boot_buf]
    call exf_raw_read
    test rax, rax
    jnz  .io
    lea  rdi, [rel exf_boot_buf]
    lea  rsi, [r12 + exf_ctx.boot_identity]
    mov  edx, 120
    call memcmp
    test rax, rax
    jnz  .stale
    call exf_mount_ctx
    test eax, eax
    jnz  .fail
    cmp  dword [r12 + exf_ctx.vflags], 0
    jne  .unsupported
    xor  ecx, ecx
    call exf_t_parent                   ; snapshot each actual canonical ancestor
    test rax, rax
    jnz  .fail
    lea  rsi, [rel exf_n_old_path]
    mov  edx, [rel exf_n_old_len]
    call exf_resolve
    test rax, rax
    jnz  .fail
    test dword [r12 + exf_ctx.leaf + exf_strm.attr], 1
    jnz  .unsupported
    cmp  dword [rel exf_n_mode], 3
    je   .directory
    cmp  dword [rel exf_t_active], 0
    je   .regular_file
    cmp  dword [rel exf_t_kind], 1
    je   .directory
.regular_file:
    test dword [r12 + exf_ctx.leaf + exf_strm.attr], EXF_ATTR_DIR
    jnz  .unsupported
    jmp  .kind_checked
.directory:
    test dword [r12 + exf_ctx.leaf + exf_strm.attr], EXF_ATTR_DIR
    jz   .unsupported
    ; This operation never changes or frees a chained/multicluster directory.
    mov  ecx, [r12 + exf_ctx.clus_shift]
    mov  rax, 1
    shl  rax, cl
    cmp  rax, EXF_WRITE_MAX
    ja   .unsupported
    cmp  rax, [r12 + exf_ctx.leaf + exf_strm.length]
    jne  .unsupported
.kind_checked:
    cmp  dword [rel exf_set_count], 2
    jne  .unsupported
    mov  ecx, [rel exf_name_len]
    cmp  ecx, 12
    ja   .unsupported
    lea  rdi, [rel exf_name16]
.ascii_source:
    cmp  word [rdi], 128
    jae  .unsupported
    add  rdi, 2
    dec  ecx
    jnz  .ascii_source
    mov  rax, [r12 + exf_ctx.leaf + exf_strm.length]
    cmp  rax, EXF_WRITE_MAX
    ja   .unsupported
    cmp  rax, [r12 + exf_ctx.leaf + exf_strm.valid]
    jne  .unsupported                    ; initialized files or complete initialized directory
    mov  edx, EXF_SF_ALLOC
    test rax, rax
    jz   .flags
    or   edx, EXF_SF_NOFATCHAIN
.flags:
    cmp  edx, [r12 + exf_ctx.leaf + exf_strm.flags]
    jne  .unsupported
    mov  ecx, [r12 + exf_ctx.clus_shift]
    mov  rdx, 1
    shl  rdx, cl
    dec  rdx
    add  rax, rdx
    shr  rax, cl
    cmp  rax, EXF_GROW_MAX
    ja   .unsupported
    mov  [rel exf_w_plan_count], eax
    mov  r13d, eax
    shl  rax, cl
    cmp  rax, EXF_WRITE_MAX
    ja   .unsupported
    mov  edx, [r12 + exf_ctx.leaf + exf_strm.first]
    mov  [rel exf_g_first], edx
    lea  rdi, [rel exf_w_plan]
    xor  ecx, ecx
.plan:
    cmp  ecx, r13d
    jae  .save
    mov  [rdi + rcx * 4], edx
    inc  edx
    inc  ecx
    jmp  .plan
.save:
    lea  rdi, [rel exf_n_stream]
    lea  rsi, [r12 + exf_ctx.leaf]
    mov  edx, exf_strm_size
    call memcpy
    mov  rax, [rel exf_set_location]
    mov  [rel exf_w_location], rax
    mov  dword [rel exf_w_set_len], 96
    lea  rdi, [rel exf_w_set]
    lea  rsi, [rel exf_set_buf]
    mov  edx, 96
    call memcpy
    call exf_n_locate                     ; map all3 slots through the exact selected parent
    test rax, rax
    jnz  .fail
    cmp  dword [rel exf_n_mode], 2
    jb   .census
    mov  dword [rel exf_g_mode], 1
    mov  [rel exf_g_count], r13d
    call exf_g_prepare                    ; checked bit-only CLEAR postimages, no writes
    test rax, rax
    jnz  .fail
.census:
    cmp  dword [rel exf_m_cross], 0
    je   .move_plan_ready
    call exf_m_plan
    test rax, rax
    jnz  .fail
.move_plan_ready:
    mov  dword [rel exf_w_budget], EXF_WRITE_BUDGET
    lea  rdi, [rel exf_n_stream]
    xor  edx, edx
    call exf_w_stream
    test rax, rax
    jnz  .fail
    call exf_w_census
    mov  dword [rel exf_m_account], 0
    mov  dword [rel exf_m_census], 0
    test rax, rax
    jnz  .fail
    cmp  dword [rel exf_m_cross], 0
    je   .move_census_done
    cmp  dword [rel exf_m_dst_hits], 0
    je   .unsupported
.move_census_done:
    cmp  dword [rel exf_n_mode], 3
    jne  .empty_checked
    call exf_d_empty                     ; complete allocation, never just a UI listing/end marker
    test rax, rax
    jnz  .fail
.empty_checked:
    call exf_n_identity                  ; source exact set/location and authoritative destination
    test rax, rax
    jnz  .fail
    mov  ecx, 1
    call exf_t_parent                   ; final exact ancestor set/location before dirty
    test rax, rax
    jnz  .fail
    cmp  dword [rel exf_m_cross], 0
    je   .move_parents_checked
    call exf_m_check_destination
    test rax, rax
    jnz  .fail
.move_parents_checked:
    call exf_n_prepare                   ; ALL metadata/bitmap snapshots/grants before dirty
    test rax, rax
    jnz  .fail
    cmp  dword [rel exf_n_noop], 0
    jne  .success                        ; exact same canonical name: validated authorized no-op
    cmp  dword [rel exf_m_cross], 0
    je   .same_parent
    call exf_m_prepare
    test rax, rax
    jnz  .fail
    call exf_m_publish
    test rax, rax
    jnz  .fail
    jmp  .success
.same_parent:
    call exf_n_postimages
    call exf_i_dirty_begin
    test rax, rax
    jnz  .fail
    call exf_n_publish
    test rax, rax
    jnz  .fail
.success:
    mov  dword [rel exfat_disk_last_error], EXF_E_NONE
    xor  eax, eax
    jmp  .finish
.range:
    mov  dword [rel exfat_disk_last_error], EXF_E_RANGE
    jmp  .fail
.io:
    mov  dword [rel exfat_disk_last_error], EXF_E_IO
    jmp  .fail
.stale:
    mov  dword [rel exfat_disk_last_error], EXF_E_STALE
    jmp  .fail
.unsupported:
    mov  dword [rel exfat_disk_last_error], EXF_E_UNSUPPORTED
.fail:
    cmp  qword [rel exfat_disk_write_stage], 0
    je   .failed
    mov  dword [rel exf_m_failure], 1
    call exf_i_failed                    ; dirty signaling only, never speculative free/clean
    mov  dword [r12 + exf_ctx.mounted], 0
.failed:
    mov  rax, -1
.finish:
    mov  dword [rel exf_m_gate_active], 0
    mov  dword [rel exf_m_account], 0
    mov  dword [rel exf_m_census], 0
    mov  dword [rel exf_n_mode], 0
    mov  dword [rel exf_w_active], 0
    mov  qword [r12 + exf_ctx.sec_tag], -1
    mov  qword [r12 + exf_ctx.fat_tag], -1
    jmp  .out
.busy:
    mov  dword [rel exfat_disk_last_error], EXF_E_UNSUPPORTED
    mov  rax, -1
    jmp  .out
.unmounted:
    mov  dword [rel exfat_disk_last_error], EXF_E_STALE
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Canonical name11 validation; output RSI path, EDX byte length, RAX0/-1.
exf_n_name:
    test rsi, rsi
    jz   .bad
    mov  rax, rsi
    add  rax, 11
    jc   .bad
    xor  ecx, ecx
    xor  r8d, r8d
    xor  r9d, r9d
.char:
    cmp  ecx, 8
    jne  .field
    test r9d, r9d
    jz   .bad
    xor  r8d, r8d
.field:
    movzx eax, byte [rsi + rcx]
    cmp  al, ' '
    je   .space
    test r8d, r8d
    jnz  .bad
    cmp  al, '_'
    je   .valid
    cmp  al, '0'
    jb   .bad
    cmp  al, '9'
    jbe  .valid
    cmp  al, 'A'
    jb   .bad
    cmp  al, 'Z'
    ja   .bad
.valid:
    inc  r9d
    jmp  .next
.space:
    mov  r8d, 1
.next:
    inc  ecx
    cmp  ecx, 11
    jb   .char
    call exf_name11_path
    xor  eax, eax
    ret
.bad:
    mov  rax, -1
    ret

; Physical location of the just-returned parent entry, including fragmented FAT.
; RSI=device LBA, EDX=within512; RAX=relative byte address (set_location units).
exf_n_entry_location:
    mov  eax, [r12 + exf_ctx.it_clus]
    sub  eax, 2
    mov  ecx, [r12 + exf_ctx.clus_shift]
    shl  rax, cl
    mov  rsi, [r12 + exf_ctx.heap_off]
    mov  ecx, [r12 + exf_ctx.sec_shift]
    shl  rsi, cl
    add  rax, rsi
    mov  edx, [r12 + exf_ctx.it_coff]
    sub  edx, 32
    add  rax, rdx
    mov  rsi, rax
    shr  rsi, 9
    add  rsi, [r12 + exf_ctx.part_lba]
    mov  edx, eax
    and  edx, 511
    ret

exf_n_locate:
    push rbx
    push r13
    lea  rdi, [rel exf_i_parent]
    call exf_dir_open
    mov  dword [rel exf_n_meta_count], 0
    xor  ebx, ebx
.scan:
    call exf_dir_next
    cmp  rax, -1
    je   .stale
    test rax, rax
    jz   .stale
    mov  r13, rax
    call exf_n_entry_location
    cmp  rax, [rel exf_w_location]
    jne  .scan
.entry:
    lea  rdi, [rel exf_n_entry_lbas]
    mov  [rdi + rbx * 8], rsi
    lea  rdi, [rel exf_n_entry_within]
    mov  [rdi + rbx * 4], edx
    cmp  ebx, 0
    jne  .second
    mov  [rel exf_n_meta_lbas], rsi
    mov  dword [rel exf_n_meta_count], 1
    mov  eax, [r12 + exf_ctx.it_clus]
    mov  [rel exf_i_meta_cluster], eax
    jmp  .compare
.second:
    cmp  rsi, [rel exf_n_meta_lbas]
    je   .compare
    mov  [rel exf_n_meta_lbas + 8], rsi
    mov  dword [rel exf_n_meta_count], 2
    mov  eax, [r12 + exf_ctx.it_clus]
    mov  [rel exf_n_meta_cluster2], eax
.compare:
    lea  rsi, [rel exf_w_set]
    mov  eax, ebx
    shl  eax, 5
    add  rsi, rax
    mov  rdi, r13
    mov  edx, 32
    call memcmp
    test rax, rax
    jnz  .stale
    inc  ebx
    cmp  ebx, 3
    jae  .ok
    call exf_dir_next
    cmp  rax, -1
    je   .stale
    test rax, rax
    jz   .stale
    mov  r13, rax
    call exf_n_entry_location
    jmp  .entry
.ok:
    xor  eax, eax
    jmp  .out
.stale:
    mov  dword [rel exfat_disk_last_error], EXF_E_STALE
    mov  rax, -1
.out:
    pop  r13
    pop  rbx
    ret

exf_n_identity:
    mov  dword [rel exf_n_noop], 0
    mov  qword [r12 + exf_ctx.sec_tag], -1
    mov  qword [r12 + exf_ctx.fat_tag], -1
    lea  rsi, [rel exf_n_old_path]
    mov  edx, [rel exf_n_old_len]
    call exf_resolve
    test rax, rax
    jnz  .out
    mov  rax, [rel exf_set_location]
    cmp  rax, [rel exf_w_location]
    jne  .stale
    cmp  dword [rel exf_set_count], 2
    jne  .stale
    lea  rdi, [rel exf_set_buf]
    lea  rsi, [rel exf_w_set]
    mov  edx, 96
    call memcmp
    test rax, rax
    jnz  .stale
    cmp  dword [rel exf_n_mode], 1
    jne  .ok
    lea  rsi, [rel exf_n_new_path]
    mov  edx, [rel exf_n_new_len]
    call exf_resolve
    test rax, rax
    jnz  .absent
    mov  rax, [rel exf_set_location]
    cmp  rax, [rel exf_w_location]
    jne  .exists
    mov  eax, [rel exf_n_old_len]
    cmp  eax, [rel exf_n_new_len]
    jne  .exists
    lea  rdi, [rel exf_n_old_path]
    lea  rsi, [rel exf_n_new_path]
    mov  edx, eax
    call memcmp
    test rax, rax
    jnz  .exists
    mov  dword [rel exf_n_noop], 1
    jmp  .ok
.absent:
    cmp  dword [rel exfat_disk_last_error], EXF_E_NOTFOUND
    jne  .out
.ok:
    xor  eax, eax
    ret
.exists:
    mov  dword [rel exfat_disk_last_error], EXF_E_EXISTS
    jmp  .fail
.stale:
    mov  dword [rel exfat_disk_last_error], EXF_E_STALE
.fail:
    mov  rax, -1
.out:
    ret

exf_n_prepare:
    push rbx
    mov  rdi, [r12 + exf_ctx.dev]
    mov  rsi, [r12 + exf_ctx.part_lba]
    mov  edx, 1
    lea  rcx, [rel exf_i_boot]
    call blk_read
    test rax, rax
    jnz  .io
    lea  rdi, [rel exf_i_boot]
    lea  rsi, [r12 + exf_ctx.boot_identity]
    mov  edx, 120
    call memcmp
    test rax, rax
    jnz  .stale
    xor  ebx, ebx
.sector:
    mov  eax, ebx
    shl  eax, 9
    lea  rcx, [rel exf_n_old]
    add  rcx, rax
    lea  rdi, [rel exf_n_meta_lbas]
    mov  rsi, [rdi + rbx * 8]
    mov  [rel exf_w_sector], rsi
    mov  rdi, [r12 + exf_ctx.dev]
    mov  edx, 1
    call blk_read
    test rax, rax
    jnz  .io
    call exf_w_gate
    test rax, rax
    jnz  .out
    inc  ebx
    cmp  ebx, [rel exf_n_meta_count]
    jb   .sector
    ; Every entry slot in the fresh sector snapshots must still match identity.
    xor  ebx, ebx
.entry:
    lea  rdi, [rel exf_n_entry_lbas]
    mov  rax, [rdi + rbx * 8]
    xor  edx, edx
    cmp  rax, [rel exf_n_meta_lbas]
    je   .index
    mov  edx, 512
.index:
    lea  rdi, [rel exf_n_old]
    add  rdi, rdx
    lea  rax, [rel exf_n_entry_within]
    mov  eax, [rax + rbx * 4]
    add  rdi, rax
    mov  eax, ebx
    shl  eax, 5
    lea  rsi, [rel exf_w_set]
    add  rsi, rax
    mov  edx, 32
    call memcmp
    test rax, rax
    jnz  .stale
    inc  ebx
    cmp  ebx, 3
    jb   .entry
    mov  rax, [r12 + exf_ctx.part_lba]
    mov  [rel exf_w_sector], rax
    call exf_w_gate
    test rax, rax
    jnz  .out
    call exf_g_preflight
    jmp  .out
.io:
    mov  dword [rel exfat_disk_last_error], EXF_E_IO
    jmp  .fail
.stale:
    mov  dword [rel exfat_disk_last_error], EXF_E_STALE
.fail:
    mov  rax, -1
.out:
    pop  rbx
    ret

exf_n_postimages:
    push rbx
    lea  rdi, [rel exf_n_new]
    lea  rsi, [rel exf_n_old]
    mov  edx, 1024
    call memcpy
    lea  rdi, [rel exf_c_set]
    lea  rsi, [rel exf_w_set]
    mov  edx, 96
    call memcpy
    cmp  dword [rel exf_n_mode], 2
    jae  .delete
    lea  rdi, [rel exf_c_set + 66]
    xor  esi, esi
    mov  edx, 30
    call memset
    lea  rsi, [rel exf_n_new_path + 1]
    mov  ecx, [rel exf_n_new_len]
    dec  ecx
    cmp  dword [rel exf_t_active], 0
    je   .leaf_name
    mov  eax, [rel exf_t_new_leaf]
    lea  rsi, [rel exf_n_new_path]
    add  rsi, rax
    mov  ecx, [rel exf_n_new_len]
    sub  ecx, eax
.leaf_name:
    mov  [rel exf_c_set + 35], cl
    lea  rdi, [rel exf_c_set + 66]
    xor  edx, edx
.name:
    movzx eax, byte [rsi + rdx]
    mov  [rdi + rdx * 2], ax
    inc  edx
    cmp  edx, ecx
    jb   .name
    mov  rsi, rdi
    call exf_name_hash
    mov  [rel exf_c_set + 36], ax
    lea  rdi, [rel exf_c_set]
    xor  eax, eax
    xor  ecx, ecx
.checksum:
    cmp  ecx, 2
    je   .skip
    cmp  ecx, 3
    je   .skip
    ror  ax, 1
    movzx edx, byte [rdi + rcx]
    add  ax, dx
.skip:
    inc  ecx
    cmp  ecx, 96
    jb   .checksum
    mov  [rel exf_c_set + 2], ax
    jmp  .scatter
.delete:
    and  byte [rel exf_c_set], 0x7f
    and  byte [rel exf_c_set + 32], 0x7f
    and  byte [rel exf_c_set + 64], 0x7f
.scatter:
    xor  ebx, ebx
.entry:
    lea  rdi, [rel exf_n_entry_lbas]
    mov  rax, [rdi + rbx * 8]
    xor  edx, edx
    cmp  rax, [rel exf_n_meta_lbas]
    je   .index
    mov  edx, 512
.index:
    lea  rdi, [rel exf_n_new]
    add  rdi, rdx
    lea  rax, [rel exf_n_entry_within]
    mov  eax, [rax + rbx * 4]
    add  rdi, rax
    mov  eax, ebx
    shl  eax, 5
    lea  rsi, [rel exf_c_set]
    add  rsi, rax
    mov  edx, 32
    call memcpy
    inc  ebx
    cmp  ebx, 3
    jb   .entry
    pop  rbx
    ret

exf_n_publish:
    push rbx
    xor  ebx, ebx
.sector:
    lea  rdi, [rel exf_n_meta_lbas]
    mov  rsi, [rdi + rbx * 8]
    mov  [rel exf_w_sector], rsi
    mov  rdi, [r12 + exf_ctx.dev]
    mov  edx, 1
    lea  rcx, [rel exf_w_verify]
    call blk_read
    test rax, rax
    jnz  .io
    mov  eax, ebx
    shl  eax, 9
    lea  rdi, [rel exf_n_old]
    add  rdi, rax
    lea  rsi, [rel exf_w_verify]
    mov  edx, 512
    call memcmp
    test rax, rax
    jnz  .stale
    mov  eax, ebx
    shl  eax, 9
    lea  rsi, [rel exf_n_new]
    add  rsi, rax
    lea  rdi, [rel exf_w_bounce]
    mov  edx, 512
    call memcpy
    call exf_w_gate
    test rax, rax
    jnz  .out
    mov  qword [rel exfat_disk_write_stage], 5
    mov  qword [rel exfat_disk_write_published], 1
    call exf_i_commit
    test rax, rax
    jnz  .out
    inc  ebx
    cmp  ebx, [rel exf_n_meta_count]
    jb   .sector
    ; Re-read the complete postimage after ALL directory sectors committed.
    ; Reclamation cannot rely on a first-sector check from before the last one.
    mov  qword [rel exfat_disk_write_stage], 6
    call exf_n_verify_namespace
    test rax, rax
    jnz  .out
    mov  qword [rel exfat_disk_write_published], 2
    mov  qword [rel exfat_disk_write_stage], 6
    cmp  dword [rel exf_n_mode], 2
    jb   .clean
    call exf_n_reclaim                    ; complete inactive entry DURABLE before any bit cleared
    test rax, rax
    jnz  .out
.clean:
    pop  rbx
    jmp  exf_i_publish.stream_published    ; existing verified dirty->clean tail, no length stores
.io:
    mov  dword [rel exfat_disk_last_error], EXF_E_IO
    jmp  .fail
.stale:
    mov  dword [rel exfat_disk_last_error], EXF_E_STALE
.fail:
    mov  rax, -1
.out:
    pop  rbx
    ret

; Registered cross-parent move: destination-first, allocation retained forever
; by this transaction. Both parent chains/root links and complete sector images
; remain bound at EVERY write gate. An interrupted duplicate is dirty/uncertain,
; not rollback, reclamation, or a clean namespace. Direct name11/same-parent
; operations do not enter this pipeline.
exf_m_swap_paths:
    lea  rdi, [rel exf_n_old_path]
    lea  rsi, [rel exf_n_new_path]
    xor  ecx, ecx
.loop:
    mov  rax, [rdi + rcx]
    mov  rdx, [rsi + rcx]
    mov  [rdi + rcx], rdx
    mov  [rsi + rcx], rax
    add  ecx, 8
    cmp  ecx, 64
    jb   .loop
    mov  eax, [rel exf_n_old_len]
    xchg eax, [rel exf_n_new_len]
    mov  [rel exf_n_old_len], eax
    mov  eax, [rel exf_t_old_leaf]
    xchg eax, [rel exf_t_new_leaf]
    mov  [rel exf_t_old_leaf], eax
    ret

; Canonical ancestor count, including each complete prefix, excluding leaf.
exf_m_ancestor_count:
    xor  eax, eax
    mov  edx, 1
.loop:
    cmp  edx, ecx
    jae  .out
    cmp  byte [rdi + rdx], '/'
    jne  .next
    inc  eax
.next:
    inc  edx
    jmp  .loop
.out:
    ret

exf_m_restore_source:
    lea  rdi, [rel exf_i_parent]
    lea  rsi, [rel exf_m_src_parent]
    mov  edx, 32
    call memcpy
    lea  rdi, [rel exf_t_ancestors]
    lea  rsi, [rel exf_m_src_ancestors]
    mov  edx, 312
    call memcpy
    lea  rdi, [rel exf_w_set]
    lea  rsi, [rel exf_m_src_set]
    mov  edx, 96
    call memcpy
    mov  eax, [rel exf_m_src_cluster]
    mov  [rel exf_i_meta_cluster], eax
    ret

exf_m_plan:
    push rbx
    lea  rdi, [rel exf_m_src_parent]
    lea  rsi, [rel exf_i_parent]
    mov  edx, 32
    call memcpy
    lea  rdi, [rel exf_m_src_ancestors]
    lea  rsi, [rel exf_t_ancestors]
    mov  edx, 312
    call memcpy
    lea  rdi, [rel exf_m_src_set]
    lea  rsi, [rel exf_w_set]
    mov  edx, 96
    call memcpy
    mov  eax, [rel exf_i_meta_cluster]
    mov  [rel exf_m_src_cluster], eax
    lea  rdi, [rel exf_n_old_path]
    mov  ecx, [rel exf_t_old_leaf]
    call exf_m_ancestor_count
    mov  [rel exf_m_src_count], eax
    lea  rdi, [rel exf_n_new_path]
    mov  ecx, [rel exf_t_new_leaf]
    call exf_m_ancestor_count
    mov  [rel exf_m_dst_count], eax
    sub  eax, [rel exf_m_src_count]
    mov  [rel exf_m_depth_delta], eax
    call exf_m_swap_paths
    xor  ecx, ecx
    call exf_t_parent
    mov  rbx, rax
    test rax, rax
    jnz  .restore
    lea  rdi, [rel exf_m_dst_parent]
    lea  rsi, [rel exf_i_parent]
    mov  edx, 32
    call memcpy
    lea  rdi, [rel exf_m_dst_ancestors]
    lea  rsi, [rel exf_t_ancestors]
    mov  edx, 312
    call memcpy
    mov  eax, [rel exf_m_src_parent + exf_strm.first]
    cmp  eax, [rel exf_m_dst_parent + exf_strm.first]
    je   .alias
    cmp  dword [rel exf_t_kind], 1
    jne  .cycle_checked
    ; Actual FirstCluster ancestry, not merely a textual prefix test.
    lea  rdi, [rel exf_m_dst_ancestors]
    xor  ecx, ecx
.ancestor:
    cmp  ecx, [rel exf_m_dst_count]
    jae  .cycle_checked
    imul edx, ecx, 104
    mov  eax, [rdi + rdx + 8 + 52]
    cmp  eax, [rel exf_n_stream + exf_strm.first]
    je   .alias
    inc  ecx
    jmp  .ancestor
.cycle_checked:
    call exf_c_slot
    mov  rbx, rax
    test rax, rax
    jnz  .restore
    mov  eax, [rel exf_i_meta_cluster]
    mov  [rel exf_m_dst_cluster], eax
    mov  rax, [rel exf_i_meta_lba]
    mov  [rel exf_m_dst_lba], rax
    cmp  rax, [rel exf_n_meta_lbas]
    je   .alias
    cmp  dword [rel exf_n_meta_count], 2
    jne  .sectors_distinct
    cmp  rax, [rel exf_n_meta_lbas + 8]
    je   .alias
.sectors_distinct:
    mov  eax, [rel exf_c_span]
    mov  [rel exf_m_dst_span], eax
    mov  rax, [rel exf_i_meta_within]
    mov  [rel exf_m_dst_within], rax
    lea  rdi, [rel exf_m_dst_slot]
    lea  rsi, [rel exf_w_set]
    mov  edx, [rel exf_m_dst_span]
    call memcpy
    mov  rdi, [r12 + exf_ctx.dev]
    mov  rsi, [rel exf_m_dst_lba]
    mov  edx, 1
    lea  rcx, [rel exf_m_dst_old]
    call blk_read
    test rax, rax
    jnz  .io
    lea  rdi, [rel exf_m_dst_old]
    add  rdi, [rel exf_m_dst_within]
    lea  rsi, [rel exf_m_dst_slot]
    mov  edx, [rel exf_m_dst_span]
    call memcmp
    test rax, rax
    jnz  .alias
    xor  ebx, ebx
    jmp  .restore
.io:
    call exf_m_io
    mov  rbx, rax
    jmp  .restore
.alias:
    mov  dword [rel exfat_disk_last_error], EXF_E_CORRUPT
    mov  rbx, -1
.restore:
    call exf_m_swap_paths
    call exf_m_restore_source
    mov  rax, rbx
    test rax, rax
    jnz  .out
    call exf_m_root_snapshot
.out:
    pop  rbx
    ret

exf_m_check_destination:
    push rbx
    call exf_m_swap_paths
    lea  rdi, [rel exf_i_parent]
    lea  rsi, [rel exf_m_dst_parent]
    mov  edx, 32
    call memcpy
    lea  rdi, [rel exf_t_ancestors]
    lea  rsi, [rel exf_m_dst_ancestors]
    mov  edx, 312
    call memcpy
    mov  ecx, 1
    call exf_t_parent
    mov  rbx, rax
    call exf_m_swap_paths
    call exf_m_restore_source
    mov  rax, rbx
    pop  rbx
    ret

; Root may be FAT fragmented. Bind every link, including the exact EOC value,
; with a finite 128-cluster admission for this new operation only.
exf_m_root_snapshot:
    push rbx
    lea  rdi, [rel exf_m_root_stream]
    lea  rsi, [r12 + exf_ctx.root]
    mov  edx, 32
    call memcpy
    mov  rax, [r12 + exf_ctx.root + exf_strm.length]
    mov  ecx, [r12 + exf_ctx.clus_shift]
    shr  rax, cl
    test rax, rax
    jz   .no
    cmp  rax, 128
    ja   .no
    mov  [rel exf_m_root_count], eax
    mov  eax, [r12 + exf_ctx.root + exf_strm.first]
    mov  [rel exf_m_root_links], eax
    xor  ebx, ebx
.loop:
    lea  rdi, [rel exf_m_root_links]
    mov  esi, [rdi + rbx * 4]
    call exf_m_fat_raw
    test rax, rax
    js   .out
    lea  rdi, [rel exf_m_root_links]
    mov  [rdi + rbx * 4 + 4], eax
    inc  ebx
    cmp  ebx, [rel exf_m_root_count]
    jae  .last
    cmp  eax, 2
    jb   .no
    mov  edx, [r12 + exf_ctx.clus_count]
    inc  edx
    cmp  eax, edx
    ja   .no
    jmp  .loop
.last:
    cmp  eax, 0xfffffff8
    jb   .no
    xor  eax, eax
    jmp  .out
.no:
    mov  dword [rel exfat_disk_last_error], EXF_E_UNSUPPORTED
    mov  rax, -1
.out:
    pop  rbx
    ret

; ESI cluster, fresh exact FAT32 entry through a private 512-byte read buffer.
exf_m_fat_raw:
    push rbx
    mov  ebx, esi
    shl  rbx, 2
    mov  rsi, [r12 + exf_ctx.fat_off]
    mov  ecx, [r12 + exf_ctx.dev_shift]
    shl  rsi, cl
    mov  rax, rbx
    shr  rax, 9
    add  rsi, rax
    add  rsi, [r12 + exf_ctx.part_lba]
    call exf_m_read
    test rax, rax
    jnz  .out
    and  ebx, 511
    lea  rdi, [rel exf_m_verify]
    mov  eax, [rdi + rbx]
.out:
    pop  rbx
    ret
exf_m_read:
    mov  rdi, [r12 + exf_ctx.dev]
    mov  edx, 1
    lea  rcx, [rel exf_m_verify]
    call blk_read
    test rax, rax
    jnz  exf_m_io
    ret
exf_m_io:
    mov  dword [rel exfat_disk_last_error], EXF_E_IO
    mov  rax, -1
    ret
exf_m_stale:
    mov  dword [rel exfat_disk_last_error], EXF_E_STALE
    mov  rax, -1
    ret

; A moved directory and all descendants must remain within the supported
; four-component namespace; unrelated directory depths do not constrain it.
exf_m_depth_check:
    mov  ecx, [rel exf_w_dir_index]
    lea  rdi, [rel exf_m_tags]
    cmp  dword [rdi + rcx * 8], 0
    jne  .check
    mov  rax, [rel exf_set_location]
    cmp  rax, [rel exf_w_location]
    jne  .ok
.check:
    lea  rdi, [rel exf_m_depths]
    mov  eax, [rdi + rcx * 8]
    inc  eax
    add  eax, [rel exf_m_depth_delta]
    cmp  eax, 4
    ja   .no
.ok:
    xor  eax, eax
    ret
.no:
    mov  dword [rel exfat_disk_last_error], EXF_E_UNSUPPORTED
    mov  rax, -1
    ret

exf_m_prepare:
    mov  rsi, [rel exf_m_dst_lba]
    call exf_m_read
    test rax, rax
    jnz  .out
    lea  rdi, [rel exf_m_verify]
    lea  rsi, [rel exf_m_dst_old]
    mov  edx, 512
    call memcmp
    test rax, rax
    jnz  exf_m_stale
    mov  rax, [rel exf_m_dst_lba]
    mov  [rel exf_w_sector], rax
    call exf_w_gate
    test rax, rax
    jnz  .out
    call exf_n_postimages               ; renamed set, preserving stream and timestamps
    lea  rdi, [rel exf_m_dst_new]
    lea  rsi, [rel exf_m_dst_old]
    mov  edx, 512
    call memcpy
    lea  rdi, [rel exf_m_dst_new]
    add  rdi, [rel exf_m_dst_within]
    lea  rsi, [rel exf_c_set]
    mov  edx, 96
    call memcpy
    cmp  dword [rel exf_m_dst_span], 128
    jne  .eod_ready
    lea  rdi, [rel exf_m_dst_new + 96]
    add  rdi, [rel exf_m_dst_within]
    xor  esi, esi
    mov  edx, 32
    call memset
.eod_ready:
    mov  dword [rel exf_n_mode], 2
    call exf_n_postimages               ; complete inactive source; NO g_prepare/reclaim
    mov  dword [rel exf_n_mode], 1
    mov  dword [rel exf_m_gate_active], 1
    ; The first gate rechecks all prepared inputs before a dirty write exists.
    call exf_w_gate
.out:
    ret

; Recheck both ancestor chains directly even during a partially retired source
; set (a normal directory parser must reject such an intermediate orphan).
; Cross moves admit ancestor sets wholly within one device sector. Full root
; FAT links plus exact complete ancestor sets bind path reachability/geometry.
exf_m_ancestors_check:
    push rbx
    push r13
    push r14
    mov  rbx, rdi
    mov  r13d, ecx
.loop:
    test r13d, r13d
    jz   .ok
    mov  r14, [rbx]
    mov  eax, r14d
    and  eax, 511
    cmp  eax, 416
    ja   .no
    mov  rsi, r14
    shr  rsi, 9
    add  rsi, [r12 + exf_ctx.part_lba]
    call exf_m_read
    test rax, rax
    jnz  .out
    ; A later read of a shared sector must recheck earlier source AND
    ; destination records too, not just the ancestor prompting this read.
    mov  rsi, r14
    and  rsi, -512
    lea  rdi, [rel exf_m_src_ancestors]
    mov  ecx, [rel exf_m_src_count]
    call exf_m_shared_ancestors
    test rax, rax
    jnz  .out
    mov  rsi, r14
    and  rsi, -512
    lea  rdi, [rel exf_m_dst_ancestors]
    mov  ecx, [rel exf_m_dst_count]
    call exf_m_shared_ancestors
    test rax, rax
    jnz  .out
    and  r14d, 511
    lea  rdi, [rel exf_m_verify]
    add  rdi, r14
    lea  rsi, [rbx + 8]
    mov  edx, 96
    call memcmp
    test rax, rax
    jnz  .no
    add  rbx, 104
    dec  r13d
    jmp  .loop
.no:
    call exf_m_stale
    jmp  .out
.ok:
    xor  eax, eax
.out:
    pop  r14
    pop  r13
    pop  rbx
    ret

; RDI saved array, ECX count, RSI relative byte start of the fresh sector.
; No I/O and no scratch sharing with the caller's expected publication image.
exf_m_shared_ancestors:
    push rbx
    push r13
    push r14
    mov  rbx, rdi
    mov  r13d, ecx
    mov  r14, rsi
.loop:
    test r13d, r13d
    jz   .ok
    mov  rax, [rbx]
    and  rax, -512
    cmp  rax, r14
    jne  .next
    mov  eax, [rbx]
    and  eax, 511
    cmp  eax, 416
    ja   .stale
    lea  rdi, [rel exf_m_verify]
    add  rdi, rax
    lea  rsi, [rbx + 8]
    mov  edx, 96
    call memcmp
    test rax, rax
    jnz  .stale
.next:
    add  rbx, 104
    dec  r13d
    jmp  .loop
.stale:
    call exf_m_stale
    jmp  .out
.ok:
    xor  eax, eax
.out:
    pop  r14
    pop  r13
    pop  rbx
    ret

exf_m_binding:
    push rbx
    ; Full boot identity; only our dirty transition (and failure media flag)
    ; may differ. Normal forward progress requires the exact dirty state.
    mov  rsi, [r12 + exf_ctx.part_lba]
    call exf_m_read
    test rax, rax
    jnz  .out
    movzx eax, word [rel exf_m_verify + EBS_FLAGS]
    cmp  dword [rel exf_m_failure], 0
    jne  .failure_flags
    mov  edx, [rel exf_m_dirty_started]
    shl  edx, 1
    cmp  eax, edx
    jne  .stale
    and  word [rel exf_m_verify + EBS_FLAGS], ~EXF_VF_DIRTY
    jmp  .boot_compare
.failure_flags:
    test eax, ~(EXF_VF_DIRTY | EXF_VF_MEDIA_FAIL)
    jnz  .stale
    and  word [rel exf_m_verify + EBS_FLAGS], ~(EXF_VF_DIRTY | EXF_VF_MEDIA_FAIL)
.boot_compare:
    lea  rdi, [rel exf_m_verify]
    lea  rsi, [rel exf_i_boot]
    mov  edx, 512
    call memcmp
    test rax, rax
    jnz  .stale
    lea  rdi, [rel exf_m_root_stream]
    lea  rsi, [r12 + exf_ctx.root]
    mov  edx, 32
    call memcmp
    test rax, rax
    jnz  .stale
    xor  ebx, ebx
.root:
    lea  rdi, [rel exf_m_root_links]
    mov  esi, [rdi + rbx * 4]
    call exf_m_fat_raw
    test rax, rax
    js   .out
    lea  rdi, [rel exf_m_root_links]
    cmp  eax, [rdi + rbx * 4 + 4]
    jne  .stale
    inc  ebx
    cmp  ebx, [rel exf_m_root_count]
    jb   .root
    lea  rdi, [rel exf_m_src_ancestors]
    mov  ecx, [rel exf_m_src_count]
    call exf_m_ancestors_check
    test rax, rax
    jnz  .out
    lea  rdi, [rel exf_m_dst_ancestors]
    mov  ecx, [rel exf_m_dst_count]
    call exf_m_ancestors_check
    test rax, rax
    jnz  .out
    cmp  dword [rel exf_m_failure], 0
    jne  .ok                            ; failure signaling cannot invent name certainty
    call exf_m_names_check
    jmp  .out
.stale:
    call exf_m_stale
    jmp  .out
.ok:
    xor  eax, eax
.out:
    pop  rbx
    ret

exf_m_names_check:
    push rbx
    mov  rsi, [rel exf_m_dst_lba]
    call exf_m_read
    test rax, rax
    jnz  .out
    lea  rsi, [rel exf_m_dst_old]
    cmp  qword [rel exfat_disk_move_destination_confirmed], 0
    je   .destination
    lea  rsi, [rel exf_m_dst_new]
.destination:
    lea  rdi, [rel exf_m_verify]
    mov  edx, 512
    call memcmp
    test rax, rax
    jnz  .stale
    xor  ebx, ebx
.source:
    lea  rdi, [rel exf_n_meta_lbas]
    mov  rsi, [rdi + rbx * 8]
    call exf_m_read
    test rax, rax
    jnz  .out
    lea  rsi, [rel exf_n_old]
    cmp  rbx, [rel exfat_disk_move_source_confirmed]
    jae  .image
    lea  rsi, [rel exf_n_new]
.image:
    mov  eax, ebx
    shl  eax, 9
    add  rsi, rax
    lea  rdi, [rel exf_m_verify]
    mov  edx, 512
    call memcmp
    test rax, rax
    jnz  .stale
    inc  ebx
    cmp  ebx, [rel exf_n_meta_count]
    jb   .source
    xor  eax, eax
    jmp  .out
.stale:
    call exf_m_stale
.out:
    pop  rbx
    ret

; Move states:0 none/preflight,1 destination uncertain,2 destination verified,
; 3 source retirement uncertain/partial,4 fully retired,5 clean uncertain,
; 6 complete. Counts are device sectors, NOT reclaimed clusters or atomicity.
exf_m_publish:
    push rbx
    call exf_i_dirty_begin
    test rax, rax
    jnz  .out
    mov  dword [rel exf_m_dirty_started], 1
    lea  rdi, [rel exf_w_bounce]
    lea  rsi, [rel exf_m_dst_new]
    mov  edx, 512
    call memcpy
    mov  rax, [rel exf_m_dst_lba]
    mov  [rel exf_w_sector], rax
    call exf_w_gate
    test rax, rax
    jnz  .out
    mov  qword [rel exfat_disk_write_stage], 14
    mov  qword [rel exfat_disk_write_published], 1
    mov  qword [rel exfat_disk_move_state], 1
    mov  qword [rel exfat_disk_move_destination_attempted], 1
    call exf_i_commit
    test rax, rax
    jnz  .out
    mov  qword [rel exfat_disk_move_destination_confirmed], 1
    mov  qword [rel exfat_disk_move_state], 2
    mov  qword [rel exfat_disk_write_published], 2
    mov  qword [rel exfat_disk_write_stage], 15
    xor  ebx, ebx
.retire:
    mov  eax, ebx
    shl  eax, 9
    lea  rsi, [rel exf_n_new]
    add  rsi, rax
    lea  rdi, [rel exf_w_bounce]
    mov  edx, 512
    call memcpy
    lea  rdi, [rel exf_n_meta_lbas]
    mov  rax, [rdi + rbx * 8]
    mov  [rel exf_w_sector], rax
    call exf_w_gate
    test rax, rax
    jnz  .out
    mov  qword [rel exfat_disk_write_stage], 16
    mov  qword [rel exfat_disk_move_state], 3
    lea  rax, [rbx + 1]
    mov  [rel exfat_disk_move_source_attempted], rax
    call exf_i_commit
    test rax, rax
    jnz  .out
    inc  ebx
    mov  [rel exfat_disk_move_source_confirmed], rbx
    cmp  ebx, [rel exf_n_meta_count]
    jb   .retire
    mov  qword [rel exfat_disk_move_state], 4
    mov  qword [rel exfat_disk_write_stage], 17
    call exf_w_gate                     ; both complete namespace images before clean
    test rax, rax
    jnz  .out
    mov  qword [rel exfat_disk_move_state], 5
    call exf_i_publish.stream_published
    test rax, rax
    jnz  .out
    mov  dword [rel exf_m_dirty_started], 0
    call exf_w_gate                     ; verify both images and identity after clean
    test rax, rax
    jnz  .out
    mov  qword [rel exfat_disk_move_state], 6
    xor  eax, eax
.out:
    pop  rbx
    ret

exf_n_reclaim:
    push rbx
    cmp  qword [rel exfat_disk_write_published], 2
    jne  .unpublished
    xor  ebx, ebx
.sector:
    cmp  ebx, [rel exf_g_bitmap_count]
    jae  .done
    lea  rdi, [rel exf_g_bitmap_lbas]
    mov  rsi, [rdi + rbx * 8]
    mov  [rel exf_w_sector], rsi
    mov  rdi, [r12 + exf_ctx.dev]
    mov  edx, 1
    lea  rcx, [rel exf_w_verify]
    call blk_read
    test rax, rax
    jnz  .io
    mov  eax, ebx
    shl  eax, 9
    lea  rdi, [rel exf_g_bitmap_old]
    add  rdi, rax
    lea  rsi, [rel exf_w_verify]
    mov  edx, 512
    call memcmp
    test rax, rax
    jnz  .stale
    mov  eax, ebx
    shl  eax, 9
    lea  rsi, [rel exf_g_bitmap_new]
    add  rsi, rax
    lea  rdi, [rel exf_w_bounce]
    mov  edx, 512
    call memcpy
    call exf_w_gate
    test rax, rax
    jnz  .out
    mov  qword [rel exfat_disk_write_stage], 12
    mov  qword [rel exfat_disk_write_reclaim_state], 1
    lea  rdi, [rel exf_g_bitmap_bits]
    mov  eax, [rdi + rbx * 4]
    add  rax, [rel exfat_disk_write_reclaimed]
    mov  [rel exfat_disk_write_reclaim_attempted], rax
    call exf_i_commit
    test rax, rax
    jnz  .out
    lea  rdi, [rel exf_g_bitmap_bits]
    mov  eax, [rdi + rbx * 4]
    add  [rel exfat_disk_write_reclaimed], rax
    cmp  dword [rel exf_r_active], 0
    je   .replacement_retired
    inc  dword [rel exf_r_retired_sectors]
.replacement_retired:
    inc  ebx
    jmp  .sector
.done:
    cmp  dword [rel exf_g_bitmap_count], 0
    je   .ok
    mov  qword [rel exfat_disk_write_reclaim_state], 2
    mov  qword [rel exfat_disk_write_stage], 13
.ok:
    xor  eax, eax
    jmp  .out
.io:
    mov  dword [rel exfat_disk_last_error], EXF_E_IO
    jmp  .fail
.stale:
    mov  dword [rel exfat_disk_last_error], EXF_E_STALE
    jmp  .fail
.unpublished:
    mov  dword [rel exfat_disk_last_error], EXF_E_CORRUPT
.fail:
    mov  rax, -1
.out:
    pop  rbx
    ret

exf_n_verify_namespace:
    push rbx
    xor  ebx, ebx
.sector:
    lea  rdi, [rel exf_n_meta_lbas]
    mov  rsi, [rdi + rbx * 8]
    mov  rdi, [r12 + exf_ctx.dev]
    mov  edx, 1
    lea  rcx, [rel exf_w_verify]
    call blk_read
    test rax, rax
    jnz  .io
    call exf_w_live
    test rax, rax
    jnz  .out
    mov  eax, ebx
    shl  eax, 9
    lea  rdi, [rel exf_n_new]
    add  rdi, rax
    lea  rsi, [rel exf_w_verify]
    mov  edx, 512
    call memcmp
    test rax, rax
    jnz  .stale
    inc  ebx
    cmp  ebx, [rel exf_n_meta_count]
    jb   .sector
    xor  eax, eax
    jmp  .out
.io:
    mov  dword [rel exfat_disk_last_error], EXF_E_IO
    jmp  .fail
.stale:
    mov  dword [rel exfat_disk_last_error], EXF_E_STALE
.fail:
    mov  rax, -1
.out:
    pop  rbx
    ret

; Root-only create through the existing writefile(name11,buf,len) slot. This
; slot refuses replacement. Canonical uppercase ASCII A-Z/0-9/_ with trailing
; space padding (1..8 base,0..3 extension); no path or directory operation.
; Complete set (96B) and, when consuming end-of-directory, a new end marker
; share ONE 512B device sector. No directory extension. First-fit examines at
; most8192 heap clusters; <=128 clusters and <=64KiB whole allocation. Empty
; files use first=0,flags=AllocationPossible only. Directory mode2 initializes
; one <=64KiB cluster, VDL=DL=cluster bytes, Directory attr, no dot entries.
; Both modes use NoFatChain for their nonempty contiguous allocation, so FAT
; entries are not interpreted or overwritten. No extra directory scratch state.
exf_d_mkdir:
    mov  r8d, 2
    xor  ecx, ecx
    xor  edx, edx
    jmp  exf_c_operation
exf_op_create:
    mov  r8d, 1
exf_c_operation:
    push rbx
    push r12
    push r13
    push r14
    push r15
    cmp  dword [rel exf_w_active], 0
    jne  .busy
    EXF_ENTER
    mov  dword [rel exf_w_active], 1
    mov  [rel exf_c_mode], r8d
    xor  eax, eax
    cmp  r8d, 3
    sete al
    mov  [rel exf_r_active], eax
    xor  eax, eax
    mov  [rel exf_r_gate_active], eax
    mov  [rel exf_r_failure], eax
    mov  [rel exf_r_boot_state], eax
    mov  [rel exf_r_published], eax
    mov  [rel exf_r_reserved_sectors], eax
    mov  [rel exf_r_retired_sectors], eax
    mov  [rel exfat_disk_replace_state], rax
    mov  dword [rel exf_n_mode], 0
    mov  [rel exf_c_length], rcx
    mov  [rel exf_w_buffer], rdx
    xor  eax, eax
    mov  [rel exfat_disk_write_confirmed], rax
    mov  [rel exfat_disk_write_attempted], rax
    mov  [rel exfat_disk_write_zeroed], rax
    mov  [rel exfat_disk_write_zero_attempted], rax
    mov  [rel exfat_disk_write_allocation], rax
    mov  [rel exfat_disk_write_reserved], rax
    mov  [rel exfat_disk_write_reservation_attempted], rax
    mov  [rel exfat_disk_write_published], rax
    mov  [rel exfat_disk_write_reclaimed], rax
    mov  [rel exfat_disk_write_reclaim_attempted], rax
    mov  [rel exfat_disk_write_reclaim_state], rax
    mov  [rel exfat_disk_move_state], rax
    mov  [rel exfat_disk_move_destination_attempted], rax
    mov  [rel exfat_disk_move_destination_confirmed], rax
    mov  [rel exfat_disk_move_source_attempted], rax
    mov  [rel exfat_disk_move_source_confirmed], rax
    mov  [rel exfat_disk_write_dirty], rax
    mov  [rel exfat_disk_write_stage], rax
    mov  [rel exf_c_allocation], rax
    mov  [rel exf_c_first], eax
    mov  [rel exf_g_count], eax
    mov  [rel exf_g_bitmap_count], eax
    mov  [rel exf_w_plan_count], eax
    mov  dword [rel exf_i_mode], 1
    mov  dword [rel exf_g_mode], 1
    mov  qword [rel exf_w_location], -1
    cmp  rcx, EXF_WRITE_MAX
    ja   .unsupported
    test rsi, rsi
    jz   .range
    mov  rax, rsi
    add  rax, 11
    jc   .range
    test rcx, rcx
    jnz  .nonempty
    cmp  dword [rel exf_r_active], 0
    jne  .range                         ; no new zero-length/truncate grammar
    jmp  .buffer_ok
.nonempty:
    test rdx, rdx
    jz   .range
    mov  rax, rdx
    add  rax, rcx
    jc   .range
.buffer_ok:
    ; A package leaf exists only after this synchronous CREATE adapter parsed
    ; the original absolute path. It has no name11 representation. Bypass only
    ; that legacy encoding check, never the live volume/OWNER/storage gates.
    cmp  dword [rel exf_t_active], 1
    jne  .short_name
    cmp  dword [rel exf_t_kind], 3
    jne  .short_name
    cmp  dword [rel exf_a_inflight], 1
    jne  .range
    cmp  dword [rel exf_c_mode], 1
    jne  .range
    cmp  dword [rel exf_r_active], 0
    jne  .range
    jmp  .tree_path
.short_name:
    ; Reject embedded spaces and lowercase/ambiguous name11 encodings.
    xor  ebx, ebx
    xor  r13d, r13d
    xor  r14d, r14d
.name:
    movzx eax, byte [rsi + rbx]
    cmp  ebx, 8
    jne  .field
    test r14d, r14d
    jz   .range
    xor  r13d, r13d
.field:
    cmp  al, ' '
    je   .space
    test r13d, r13d
    jnz  .range
    cmp  al, '_'
    je   .char
    cmp  al, '0'
    jb   .range
    cmp  al, '9'
    jbe  .char
    cmp  al, 'A'
    jb   .range
    cmp  al, 'Z'
    ja   .range
.char:
    inc  r14d
    jmp  .nextchar
.space:
    mov  r13d, 1
.nextchar:
    inc  ebx
    cmp  ebx, 11
    jb   .name
    call exf_name11_path
    mov  [rel exf_w_path], rsi
    mov  [rel exf_w_path_len], edx
    cmp  dword [rel exf_t_active], 0
    je   .path_ready
.tree_path:
    lea  rax, [rel exf_n_old_path]
    mov  [rel exf_w_path], rax
    mov  eax, [rel exf_n_old_len]
    mov  [rel exf_w_path_len], eax
.path_ready:
    call storage_access_request_owner
    mov  [rel exf_w_owner], eax
    mov  rdi, [r12 + exf_ctx.dev]
    call storage_access_intent_for_dev
    mov  [rel exf_w_intent], eax
    call exf_w_live
    test rax, rax
    jnz  .fail
    mov  qword [r12 + exf_ctx.sec_tag], -1
    mov  qword [r12 + exf_ctx.fat_tag], -1
    mov  rdi, [r12 + exf_ctx.dev]
    mov  rsi, [r12 + exf_ctx.part_lba]
    mov  edx, 1
    lea  rcx, [rel exf_boot_buf]
    call exf_raw_read
    test rax, rax
    jnz  .io
    lea  rdi, [rel exf_boot_buf]
    lea  rsi, [r12 + exf_ctx.boot_identity]
    mov  edx, 120
    call memcmp
    test rax, rax
    jnz  .stale
    call exf_mount_ctx
    test eax, eax
    jnz  .fail
    cmp  dword [r12 + exf_ctx.vflags], 0
    jne  .unsupported
    cmp  dword [rel exf_c_mode], 2
    jne  .length_ready
    mov  ecx, [r12 + exf_ctx.clus_shift]
    mov  rax, 1
    shl  rax, cl
    cmp  rax, EXF_WRITE_MAX
    ja   .unsupported
    mov  [rel exf_c_length], rax         ; directory VDL=DL=one whole initialized cluster
.length_ready:
    xor  ecx, ecx
    call exf_t_parent
    test rax, rax
    jnz  .fail
    mov  rsi, [rel exf_w_path]
    mov  edx, [rel exf_w_path_len]
    call exf_resolve                     ; actual volume upcase, including collisions with long names
    cmp  dword [rel exf_r_active], 0
    je   .create_identity
    test rax, rax
    jnz  .fail                          ; replacement NEVER silently creates
    call exf_r_source
    test rax, rax
    jnz  .fail
    jmp  .slot_ready
.create_identity:
    test rax, rax
    jz   .exists
    cmp  dword [rel exfat_disk_last_error], EXF_E_NOTFOUND
    jne  .fail
    call exf_c_slot
    test rax, rax
    jnz  .fail
.slot_ready:
    call exf_c_allocate                  ; only read free bits; census precedes mutation
    test rax, rax
    jnz  .fail
    mov  dword [rel exf_w_budget], EXF_WRITE_BUDGET
    call exf_g_prepare
    test rax, rax
    jnz  .fail
    cmp  dword [rel exf_r_active], 0
    je   .retirement_planned
    call exf_r_retirement_plan           ; old-bit clear images, including reservation overlap
    test rax, rax
    jnz  .fail
.retirement_planned:
    call exf_w_census                    ; complete root/data/metadata ownership
    mov  dword [rel exf_m_account], 0
    mov  dword [rel exf_m_census], 0
    test rax, rax
    jnz  .fail
    ; Recheck target identity/absence and exact ancestors after census.
    cmp  dword [rel exf_r_active], 0
    je   .check_absence
    call exf_r_identity
    test rax, rax
    jnz  .fail
    jmp  .identity_ready
.check_absence:
    mov  qword [r12 + exf_ctx.sec_tag], -1
    mov  qword [r12 + exf_ctx.fat_tag], -1
    mov  rsi, [rel exf_w_path]
    mov  edx, [rel exf_w_path_len]
    call exf_resolve
    test rax, rax
    jz   .exists
    cmp  dword [rel exfat_disk_last_error], EXF_E_NOTFOUND
    jne  .fail
.identity_ready:
    mov  ecx, 1
    call exf_t_parent                   ; final exact ancestors, after all collision reads
    test rax, rax
    jnz  .fail
    cmp  dword [rel exf_r_active], 0
    je   .create_set
    call exf_r_set_build
    jmp  .set_ready
.create_set:
    call exf_c_set_build
.set_ready:
    xor  r13d, r13d
.preflight:
    cmp  r13, [rel exf_c_allocation]
    jae  .metadata
    mov  rax, r13
    call exf_c_sector
    call exf_w_gate
    test rax, rax
    jnz  .fail
    add  r13, 512
    jmp  .preflight
.metadata:
    call exf_i_prepare
    test rax, rax
    jnz  .fail
    cmp  dword [rel exf_r_active], 0
    je   .replacement_prepared
    call exf_r_prepare
    test rax, rax
    jnz  .fail
.replacement_prepared:
    call exf_i_dirty_begin
    test rax, rax
    jnz  .fail
    cmp  dword [rel exf_r_active], 0
    je   .replacement_dirty
    mov  dword [rel exf_r_boot_state], 1
    mov  qword [rel exfat_disk_replace_state], 1
.replacement_dirty:
    call exf_g_reserve
    test rax, rax
    jnz  .fail
    xor  r13d, r13d
.zero:
    cmp  r13, [rel exf_c_allocation]
    jae  .content_begin
    mov  rax, r13
    call exf_c_sector
    lea  rdi, [rel exf_w_bounce]
    xor  esi, esi
    mov  edx, 512
    call memset
    mov  qword [rel exfat_disk_write_stage], 3
    lea  rax, [r13 + 512]
    mov  [rel exfat_disk_write_zero_attempted], rax
    call exf_i_commit
    test rax, rax
    jnz  .fail
    add  r13, 512
    mov  [rel exfat_disk_write_zeroed], r13
    jmp  .zero
.content_begin:
    cmp  dword [rel exf_c_mode], 2
    je   .publish                       ; directory bytes already durable zero, no caller data/dots
    xor  r13d, r13d
.content:
    cmp  r13, [rel exf_c_length]
    jae  .publish
    mov  rax, r13
    call exf_c_sector
    mov  rdi, [r12 + exf_ctx.dev]
    mov  rsi, [rel exf_w_sector]
    mov  edx, 1
    lea  rcx, [rel exf_w_bounce]
    call blk_read
    test rax, rax
    jnz  .io
    mov  r14, [rel exf_c_length]
    sub  r14, r13
    cmp  r14, 512
    jbe  .content_piece
    mov  r14d, 512
.content_piece:
    lea  rdi, [rel exf_w_bounce]
    mov  rsi, [rel exf_w_buffer]
    add  rsi, r13
    mov  rdx, r14
    call memcpy
    mov  qword [rel exfat_disk_write_stage], 11 ; create content after full durable zero
    lea  rax, [r13 + r14]
    mov  [rel exfat_disk_write_attempted], rax
    call exf_i_commit
    test rax, rax
    jnz  .fail
    add  r13, r14
    mov  [rel exfat_disk_write_confirmed], r13
    jmp  .content
.publish:
    cmp  dword [rel exf_r_active], 0
    je   .replacement_data_ready
    call exf_r_verify_data               ; entire new allocation, including zero padding
    test rax, rax
    jnz  .fail
.replacement_data_ready:
    call exf_i_publish                   ; full new set and clean after verified zero/content
    test rax, rax
    jnz  .fail
    mov  dword [rel exfat_disk_last_error], EXF_E_NONE
    xor  eax, eax                       ; existing update ABI returns0/-1
    cmp  dword [rel exf_r_active], 0
    jne  .finish
    mov  eax, [rel exf_c_first]           ; writefile result is first cluster;0 empty success
    jmp  .finish
.exists:
    mov  dword [rel exfat_disk_last_error], EXF_E_EXISTS
    jmp  .fail
.range:
    mov  dword [rel exfat_disk_last_error], EXF_E_RANGE
    jmp  .fail
.unsupported:
    mov  dword [rel exfat_disk_last_error], EXF_E_UNSUPPORTED
    jmp  .fail
.stale:
    mov  dword [rel exfat_disk_last_error], EXF_E_STALE
    jmp  .fail
.io:
    mov  dword [rel exfat_disk_last_error], EXF_E_IO
.fail:
    cmp  qword [rel exfat_disk_write_stage], 0
    je   .failed_result
    mov  dword [rel exf_r_failure], 1
    call exf_i_failed
    mov  dword [r12 + exf_ctx.mounted], 0
.failed_result:
    mov  rax, -1
.finish:
    mov  dword [rel exf_r_gate_active], 0
    mov  dword [rel exf_r_active], 0
    mov  dword [rel exf_m_account], 0
    mov  dword [rel exf_m_census], 0
    mov  dword [rel exf_c_mode], 0
    mov  dword [rel exf_w_active], 0
    mov  qword [r12 + exf_ctx.sec_tag], -1
    mov  qword [r12 + exf_ctx.fat_tag], -1
    jmp  .out
.busy:
    mov  dword [rel exfat_disk_last_error], EXF_E_UNSUPPORTED
    mov  rax, -1
    jmp  .out
.unmounted:
    mov  dword [rel exfat_disk_last_error], EXF_E_STALE
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Scan selected parent entries for96 inactive bytes. Consuming EOD needs128bytes
; in the same device sector/parent allocation so the new terminator is durable with the
; set. Deleted-slot reuse retains later entries and existing end marker.
; Existing root update(name11,buf,len) slot uses the SAME armed canonical path
; adapter. No legacy arbitrary-name update or unarmed direct writer is exposed.
exf_a_update:
    push rbx
    push r13
    push r14
    mov  rbx, rdi
    mov  r13, rdx
    mov  r14, rcx
    cmp  dword [rel exf_w_active], 0
    jne  .no
    cmp  dword [rel exf_a_inflight], 0
    jne  .no
    call exf_n_name
    test rax, rax
    jnz  .no
    mov  rdi, rbx
    mov  rdx, r13
    mov  rcx, r14
    mov  r8d, FS_MUT_UPDATE
    pop  r14
    pop  r13
    pop  rbx
    jmp  exf_a_mutate_path
.no:
    mov  dword [rel exfat_disk_last_error], EXF_E_UNSUPPORTED
    mov  rax, -1
    pop  r14
    pop  r13
    pop  rbx
    ret
exf_r_update:
    mov  r8d, 3
    jmp  exf_c_operation

; Native resolution has succeeded. Capture exact old set/stream and selected
; parent map; replacement never consumes a free directory slot or renames data.
exf_r_source:
    mov  eax, [r12 + exf_ctx.leaf + exf_strm.attr]
    test eax, EXF_ATTR_DIR | 1
    jnz  .unsupported
    cmp  dword [rel exf_set_count], 2
    jne  .unsupported
    mov  rax, [r12 + exf_ctx.leaf + exf_strm.length]
    cmp  rax, EXF_WRITE_MAX
    ja   .unsupported
    cmp  rax, [r12 + exf_ctx.leaf + exf_strm.valid]
    jne  .unsupported
    mov  edx, EXF_SF_ALLOC
    test rax, rax
    jz   .flags
    or   edx, EXF_SF_NOFATCHAIN
.flags:
    cmp  edx, [r12 + exf_ctx.leaf + exf_strm.flags]
    jne  .unsupported
    mov  ecx, [r12 + exf_ctx.clus_shift]
    mov  rdx, 1
    shl  rdx, cl
    dec  rdx
    add  rax, rdx
    jc   .unsupported
    shr  rax, cl
    cmp  rax, EXF_GROW_MAX
    ja   .unsupported
    mov  [rel exf_r_old_count], eax
    shl  rax, cl
    cmp  rax, EXF_WRITE_MAX
    ja   .unsupported
    mov  eax, [r12 + exf_ctx.leaf + exf_strm.first]
    mov  [rel exf_r_old_first], eax
    lea  rdi, [rel exf_r_old_stream]
    lea  rsi, [r12 + exf_ctx.leaf]
    mov  edx, 32
    call memcpy
    mov  rax, [rel exf_set_location]
    mov  [rel exf_w_location], rax
    mov  dword [rel exf_w_set_len], 96
    lea  rdi, [rel exf_w_set]
    lea  rsi, [rel exf_set_buf]
    mov  edx, 96
    call memcpy
    mov  dword [rel exf_n_meta_cluster2], 0
    call exf_n_locate
    test rax, rax
    jnz  .out
    cmp  dword [rel exf_n_meta_count], 1
    jne  .unsupported
    mov  rax, [rel exf_n_meta_lbas]
    mov  [rel exf_i_meta_lba], rax
    mov  eax, [rel exf_n_entry_within]
    cmp  eax, 416
    ja   .unsupported
    mov  [rel exf_i_meta_within], rax
    mov  dword [rel exf_c_span], 96
    xor  eax, eax
.out:
    ret
.unsupported:
    mov  dword [rel exfat_disk_last_error], EXF_E_UNSUPPORTED
    mov  rax, -1
    ret

exf_r_identity:
    mov  qword [r12 + exf_ctx.sec_tag], -1
    mov  qword [r12 + exf_ctx.fat_tag], -1
    mov  rsi, [rel exf_w_path]
    mov  edx, [rel exf_w_path_len]
    call exf_resolve
    test rax, rax
    jnz  .out
    mov  rax, [rel exf_set_location]
    cmp  rax, [rel exf_w_location]
    jne  exf_m_stale
    cmp  dword [rel exf_set_count], 2
    jne  exf_m_stale
    lea  rdi, [rel exf_set_buf]
    lea  rsi, [rel exf_w_set]
    mov  edx, 96
    call memcmp
    test rax, rax
    jnz  exf_m_stale
    lea  rdi, [r12 + exf_ctx.leaf]
    lea  rsi, [rel exf_r_old_stream]
    mov  edx, 32
    call memcmp
    test rax, rax
    jnz  exf_m_stale
.out:
    ret

; A bitmap plan is36 bytes of count/keys plus2048 bytes of pre/postimages.
; The reservation plan stays available through publication AND reclamation.
exf_r_plan_save:
    push rbx
    mov  rbx, rdi
    lea  rsi, [rel exf_g_bitmap_count]
    mov  edx, exf_r_plan.old
    call memcpy
    lea  rdi, [rbx + exf_r_plan.old]
    lea  rsi, [rel exf_g_bitmap_old]
    mov  edx, 1024 * EXF_GROW_BITMAPS
    call memcpy
    pop  rbx
    ret
exf_r_plan_load:
    push rbx
    mov  rbx, rdi
    mov  rsi, rdi
    lea  rdi, [rel exf_g_bitmap_count]
    mov  edx, exf_r_plan.old
    call memcpy
    lea  rsi, [rbx + exf_r_plan.old]
    lea  rdi, [rel exf_g_bitmap_old]
    mov  edx, 1024 * EXF_GROW_BITMAPS
    call memcpy
    pop  rbx
    ret

exf_r_retirement_plan:
    push rbx
    push r13
    push r14
    lea  rdi, [rel exf_r_reservation]
    call exf_r_plan_save
    mov  eax, [rel exf_r_old_first]
    mov  [rel exf_g_first], eax
    mov  eax, [rel exf_r_old_count]
    mov  [rel exf_g_count], eax
    mov  dword [rel exf_n_mode], 2
    call exf_g_prepare                  ; accepted exact bit-clear planner, no mutation
    mov  r14, rax
    mov  dword [rel exf_n_mode], 0
    test rax, rax
    jnz  .restore
    lea  rdi, [rel exf_r_retirement]
    call exf_r_plan_save
    xor  ebx, ebx
.old_sector:
    cmp  ebx, [rel exf_r_retirement]
    jae  .restore
    xor  r13d, r13d
.new_sector:
    cmp  r13d, [rel exf_r_reservation]
    jae  .next_old
    lea  rdi, [rel exf_r_reservation + exf_r_plan.lbas]
    mov  rax, [rdi + r13 * 8]
    lea  rdi, [rel exf_r_retirement + exf_r_plan.lbas]
    cmp  rax, [rdi + rbx * 8]
    jne  .next_new
    ; Shared bitmap sector: expected reclaim input includes all new reserved
    ; bits. Its output retains those bits while clearing ONLY old allocation.
    mov  eax, ebx
    shl  eax, 9
    lea  rdi, [rel exf_r_retirement + exf_r_plan.old]
    add  rdi, rax
    mov  eax, r13d
    shl  eax, 9
    lea  rsi, [rel exf_r_reservation + exf_r_plan.new]
    add  rsi, rax
    mov  edx, 512
    call memcpy
    mov  eax, ebx
    shl  eax, 9
    lea  rdi, [rel exf_r_retirement + exf_r_plan.new]
    add  rdi, rax
    mov  eax, r13d
    shl  eax, 9
    lea  rsi, [rel exf_r_reservation + exf_r_plan.old]
    add  rsi, rax
    xor  ecx, ecx
.merge:
    mov  rax, [rsi + rcx]
    xor  rax, [rsi + rcx + 1024]         ; exactly the new reservation bits
    or   [rdi + rcx], rax
    add  ecx, 8
    cmp  ecx, 512
    jb   .merge
.next_new:
    inc  r13d
    jmp  .new_sector
.next_old:
    inc  ebx
    jmp  .old_sector
.restore:
    lea  rdi, [rel exf_r_reservation]
    call exf_r_plan_load
    mov  eax, [rel exf_c_first]
    mov  [rel exf_g_first], eax
    mov  eax, [rel exf_w_plan_count]
    mov  [rel exf_g_count], eax
    mov  rax, r14
    pop  r14
    pop  r13
    pop  rbx
    ret

exf_r_set_build:
    lea  rdi, [rel exf_c_set]
    lea  rsi, [rel exf_w_set]
    mov  edx, 96
    call memcpy
    mov  byte [rel exf_c_set + 33], EXF_SF_ALLOC | EXF_SF_NOFATCHAIN
    mov  eax, [rel exf_c_first]
    mov  [rel exf_c_set + 52], eax
    mov  rax, [rel exf_c_length]
    mov  [rel exf_c_set + 40], rax
    mov  [rel exf_c_set + 56], rax
    mov  [rel exf_i_new_valid], rax
    mov  [rel exf_g_new_length], rax
    lea  rdi, [rel exf_c_set]
    xor  eax, eax
    xor  ecx, ecx
.sum:
    cmp  ecx, 2
    je   .skip
    cmp  ecx, 3
    je   .skip
    ror  ax, 1
    movzx edx, byte [rdi + rcx]
    add  ax, dx
.skip:
    inc  ecx
    cmp  ecx, 96
    jb   .sum
    mov  [rel exf_c_set + 2], ax
    ret

exf_r_prepare:
    push rbx
    lea  rdi, [rel exf_r_meta_new]
    lea  rsi, [rel exf_i_meta]
    mov  edx, 512
    call memcpy
    lea  rdi, [rel exf_r_meta_new]
    add  rdi, [rel exf_i_meta_within]
    lea  rsi, [rel exf_c_set]
    mov  edx, 96
    call memcpy
    lea  rdi, [rel exf_m_src_parent]
    lea  rsi, [rel exf_i_parent]
    mov  edx, 32
    call memcpy
    lea  rdi, [rel exf_m_src_ancestors]
    lea  rsi, [rel exf_t_ancestors]
    mov  edx, 312
    call memcpy
    mov  dword [rel exf_m_dst_count], 0
    lea  rdi, [rel exf_n_old_path]
    mov  ecx, [rel exf_t_old_leaf]
    call exf_m_ancestor_count
    mov  [rel exf_m_src_count], eax
    call exf_m_root_snapshot
    test rax, rax
    jnz  .out
    xor  ebx, ebx
.preflight:
    cmp  ebx, [rel exf_r_retirement]
    jae  .enable
    lea  rdi, [rel exf_r_retirement + exf_r_plan.lbas]
    mov  rax, [rdi + rbx * 8]
    mov  [rel exf_w_sector], rax
    call exf_w_gate
    test rax, rax
    jnz  .out
    inc  ebx
    jmp  .preflight
.enable:
    mov  dword [rel exf_r_gate_active], 1
    call exf_w_gate                     ; complete snapshot binding before first dirty write
.out:
    pop  rbx
    ret

exf_r_binding:
    push rbx
    mov  rsi, [r12 + exf_ctx.part_lba]
    call exf_m_read
    test rax, rax
    jnz  .out
    lea  rdi, [rel exf_r_boot_expected]
    lea  rsi, [rel exf_i_boot]
    mov  edx, 512
    call memcpy
    cmp  dword [rel exf_r_failure], 0
    jne  .failure_boot
    cmp  dword [rel exf_r_boot_state], 0
    je   .boot_ready
    mov  byte [rel exf_r_boot_expected + EBS_PCT_USE], 0xff
    cmp  dword [rel exf_r_boot_state], 1
    jne  .boot_ready
    or   word [rel exf_r_boot_expected + EBS_FLAGS], EXF_VF_DIRTY
    jmp  .boot_ready
.failure_boot:
    movzx eax, word [rel exf_m_verify + EBS_FLAGS]
    test eax, ~(EXF_VF_DIRTY | EXF_VF_MEDIA_FAIL)
    jnz  .stale
    and  word [rel exf_m_verify + EBS_FLAGS], ~(EXF_VF_DIRTY | EXF_VF_MEDIA_FAIL)
    mov  al, [rel exf_m_verify + EBS_PCT_USE]
    cmp  al, [rel exf_i_boot + EBS_PCT_USE]
    je   .failure_pct
    cmp  al, 0xff
    jne  .stale
.failure_pct:
    mov  [rel exf_r_boot_expected + EBS_PCT_USE], al
.boot_ready:
    lea  rdi, [rel exf_m_verify]
    lea  rsi, [rel exf_r_boot_expected]
    mov  edx, 512
    call memcmp
    test rax, rax
    jnz  .stale
    lea  rdi, [rel exf_m_src_parent]
    lea  rsi, [rel exf_i_parent]
    mov  edx, 32
    call memcmp
    test rax, rax
    jnz  .stale
    lea  rdi, [rel exf_m_root_stream]
    lea  rsi, [r12 + exf_ctx.root]
    mov  edx, 32
    call memcmp
    test rax, rax
    jnz  .stale
    xor  ebx, ebx
.root:
    lea  rdi, [rel exf_m_root_links]
    mov  esi, [rdi + rbx * 4]
    call exf_m_fat_raw
    test rax, rax
    js   .out
    lea  rdi, [rel exf_m_root_links]
    cmp  eax, [rdi + rbx * 4 + 4]
    jne  .stale
    inc  ebx
    cmp  ebx, [rel exf_m_root_count]
    jb   .root
    lea  rdi, [rel exf_m_src_ancestors]
    mov  ecx, [rel exf_m_src_count]
    call exf_m_ancestors_check
    test rax, rax
    jnz  .out
    cmp  dword [rel exf_r_failure], 0
    jne  .ok                            ; signal failure, never invent allocation certainty
    mov  rsi, [rel exf_i_meta_lba]
    call exf_m_read
    test rax, rax
    jnz  .out
    lea  rsi, [rel exf_i_meta]
    cmp  dword [rel exf_r_published], 0
    je   .metadata
    lea  rsi, [rel exf_r_meta_new]
.metadata:
    lea  rdi, [rel exf_m_verify]
    mov  edx, 512
    call memcmp
    test rax, rax
    jnz  .stale
    call exf_r_bitmap_binding
    jmp  .out
.stale:
    call exf_m_stale
    jmp  .out
.ok:
    xor  eax, eax
.out:
    pop  rbx
    ret

; Bind BOTH plans throughout reservation, data, publication and retirement.
; Overlapping bitmap sectors advance once, preserving the new reservation bits.
exf_r_bitmap_binding:
    push rbx
    push r13
    push r14
    xor  ebx, ebx
.reservation:
    cmp  ebx, [rel exf_r_reservation]
    jae  .retirement_begin
    lea  rdi, [rel exf_r_reservation + exf_r_plan.lbas]
    mov  rsi, [rdi + rbx * 8]
    mov  r14, rsi
    call exf_m_read
    test rax, rax
    jnz  .out
    lea  rsi, [rel exf_r_reservation + exf_r_plan.old]
    cmp  ebx, [rel exf_r_reserved_sectors]
    jae  .reservation_image
    add  rsi, 1024
.reservation_image:
    mov  eax, ebx
    shl  eax, 9
    add  rsi, rax
    xor  r13d, r13d
.overlap:
    cmp  r13d, [rel exf_r_retired_sectors]
    jae  .compare_reservation
    lea  rdi, [rel exf_r_retirement + exf_r_plan.lbas]
    cmp  r14, [rdi + r13 * 8]
    jne  .overlap_next
    mov  eax, r13d
    shl  eax, 9
    lea  rsi, [rel exf_r_retirement + exf_r_plan.new]
    add  rsi, rax
    jmp  .compare_reservation
.overlap_next:
    inc  r13d
    jmp  .overlap
.compare_reservation:
    lea  rdi, [rel exf_m_verify]
    mov  edx, 512
    call memcmp
    test rax, rax
    jnz  .stale
    inc  ebx
    jmp  .reservation
.retirement_begin:
    xor  ebx, ebx
.retirement:
    cmp  ebx, [rel exf_r_retirement]
    jae  .ok
    lea  rdi, [rel exf_r_retirement + exf_r_plan.lbas]
    mov  r14, [rdi + rbx * 8]
    xor  r13d, r13d
.skip_shared:
    cmp  r13d, [rel exf_r_reservation]
    jae  .read_retirement
    lea  rdi, [rel exf_r_reservation + exf_r_plan.lbas]
    cmp  r14, [rdi + r13 * 8]
    je   .next_retirement
    inc  r13d
    jmp  .skip_shared
.read_retirement:
    mov  rsi, r14
    call exf_m_read
    test rax, rax
    jnz  .out
    lea  rsi, [rel exf_r_retirement + exf_r_plan.old]
    cmp  ebx, [rel exf_r_retired_sectors]
    jae  .retirement_image
    add  rsi, 1024
.retirement_image:
    mov  eax, ebx
    shl  eax, 9
    add  rsi, rax
    lea  rdi, [rel exf_m_verify]
    mov  edx, 512
    call memcmp
    test rax, rax
    jnz  .stale
.next_retirement:
    inc  ebx
    jmp  .retirement
.stale:
    call exf_m_stale
    jmp  .out
.ok:
    xor  eax, eax
.out:
    pop  r14
    pop  r13
    pop  rbx
    ret

exf_r_verify_data:
    push rbx
    push r13
    xor  ebx, ebx
.sector:
    cmp  rbx, [rel exf_c_allocation]
    jae  .ok
    mov  rax, rbx
    call exf_c_sector
    mov  rsi, [rel exf_w_sector]
    call exf_m_read
    test rax, rax
    jnz  .out
    lea  rdi, [rel exf_w_bounce]
    xor  esi, esi
    mov  edx, 512
    call memset
    cmp  rbx, [rel exf_c_length]
    jae  .padding
    mov  r13, [rel exf_c_length]
    sub  r13, rbx
    cmp  r13, 512
    jbe  .piece
    mov  r13d, 512
.piece:
    lea  rdi, [rel exf_w_bounce]
    mov  rsi, [rel exf_w_buffer]
    add  rsi, rbx
    mov  rdx, r13
    call memcpy
.padding:
    lea  rdi, [rel exf_w_bounce]
    lea  rsi, [rel exf_m_verify]
    mov  edx, 512
    call memcmp
    test rax, rax
    jnz  .verify
    call exf_w_live
    test rax, rax
    jnz  .out
    add  rbx, 512
    jmp  .sector
.verify:
    mov  dword [rel exfat_disk_last_error], EXF_E_VERIFY
    mov  rax, -1
    jmp  .out
.ok:
    xor  eax, eax
.out:
    pop  r13
    pop  rbx
    ret

; Reclaim requires the complete replacement stream to be confirmed durable.
; Uncertain metadata never enters this path. Restore reservation bookkeeping
; even on failure; failure signaling must retain the right dirty/PctUse image.
exf_r_after_publication:
    push rbx
    cmp  qword [rel exfat_disk_write_published], 2
    jne  .stale
    mov  dword [rel exf_r_published], 1
    mov  qword [rel exfat_disk_replace_state], 2
    mov  eax, [rel exf_c_first]
    mov  [r12 + exf_ctx.leaf + exf_strm.first], eax
    mov  dword [r12 + exf_ctx.leaf + exf_strm.flags], EXF_SF_ALLOC | EXF_SF_NOFATCHAIN
    lea  rdi, [rel exf_r_retirement]
    call exf_r_plan_load
    mov  qword [rel exfat_disk_replace_state], 3
    call exf_n_reclaim
    mov  rbx, rax
    lea  rdi, [rel exf_r_reservation]
    call exf_r_plan_load
    mov  rax, rbx
    test rax, rax
    jnz  .out
    call exf_w_gate                     ; namespace and BOTH bitmaps before clean
    test rax, rax
    jnz  .out
    call exf_i_publish.clean_tail
    test rax, rax
    jnz  .out
    mov  dword [rel exf_r_boot_state], 2
    call exf_w_gate                     ; final identity/images after verified clean
    test rax, rax
    jnz  .out
    mov  qword [rel exfat_disk_replace_state], 4
    xor  eax, eax
    jmp  .out
.stale:
    call exf_m_stale
.out:
    pop  rbx
    ret

exf_c_slot:
    push rbx
    push r13
    lea  rdi, [rel exf_i_parent]
    call exf_dir_open
    xor  ebx, ebx
.next:
    call exf_dir_next
    test rax, rax
    js   .out
    jz   .full
    mov  r13, rax
    mov  edx, [r12 + exf_ctx.it_coff]
    sub  edx, 32
    and  edx, 511
    test edx, edx
    jnz  .same_sector
    xor  ebx, ebx
.same_sector:
    cmp  byte [r13], 0
    je   .end_marker
    test byte [r13], EXF_DE_INUSE
    jnz  .reset
    inc  ebx
    cmp  ebx, 3
    jb   .next
    sub  r13, 64
    sub  edx, 64
    mov  dword [rel exf_c_span], 96
    jmp  .found
.reset:
    xor  ebx, ebx
    jmp  .next
.end_marker:
    ; Do not skip an existing EOD to create invisible entries in the next sector.
    cmp  edx, 384
    ja   .full
    cmp  qword [r12 + exf_ctx.it_left], 96
    jb   .full
    mov  dword [rel exf_c_span], 128
.found:
    mov  [rel exf_i_meta_within], rdx
    mov  eax, [r12 + exf_ctx.it_clus]
    mov  [rel exf_i_meta_cluster], eax
    sub  eax, 2
    mov  ecx, [r12 + exf_ctx.spc_shift]
    shl  rax, cl
    add  rax, [r12 + exf_ctx.heap_off]
    mov  ecx, [r12 + exf_ctx.dev_shift]
    shl  rax, cl
    mov  edx, [r12 + exf_ctx.it_coff]
    sub  edx, 32
    ; For a deleted run the iterator is after the THIRD slot.
    cmp  dword [rel exf_c_span], 96
    jne  .slot_offset
    sub  edx, 64
.slot_offset:
    shr  edx, 9
    add  rax, rdx
    add  rax, [r12 + exf_ctx.part_lba]
    mov  [rel exf_i_meta_lba], rax
    lea  rdi, [rel exf_w_set]
    mov  rsi, r13
    mov  edx, [rel exf_c_span]
    call memcpy
    mov  dword [rel exf_w_set_len], 96
    xor  eax, eax
    jmp  .out
.full:
    mov  dword [rel exfat_disk_last_error], EXF_E_NOSPACE
    mov  rax, -1
.out:
    pop  r13
    pop  rbx
    ret

; Bounded bitmap first-fit. Candidate bits are still proven unowned by census;
; bitmap free alone never authorizes a crosslink. No in-memory bitmap mutation.
exf_c_allocate:
    push rbx
    push r13
    push r14
    push r15
    mov  rax, [rel exf_c_length]
    test rax, rax
    jz   .ok
    mov  ecx, [r12 + exf_ctx.clus_shift]
    mov  rdx, 1
    shl  rdx, cl
    dec  rdx
    add  rax, rdx
    shr  rax, cl
    cmp  rax, EXF_GROW_MAX
    ja   .unsupported
    mov  [rel exf_g_count], eax
    shl  rax, cl
    cmp  rax, EXF_WRITE_MAX
    ja   .unsupported
    mov  [rel exf_c_allocation], rax
    mov  qword [rel exf_c_bitmap_tag], -1
    mov  r14d, [r12 + exf_ctx.clus_count]
    cmp  r14d, 8192
    jbe  .limit
    mov  r14d, 8192
.limit:
    add  r14d, 2
    mov  r13d, 2
    xor  ebx, ebx
.scan:
    cmp  r13d, r14d
    jae  .full
    mov  esi, r13d
    call exf_g_bitmap_location
    test rax, rax
    jnz  .out
    mov  r15d, edx
    cmp  rsi, [rel exf_c_bitmap_tag]
    je   .cached_bitmap
    mov  [rel exf_c_bitmap_tag], rsi
    mov  rdi, [r12 + exf_ctx.dev]
    mov  edx, 1
    lea  rcx, [rel exf_w_verify]
    call blk_read
    test rax, rax
    jnz  .io
.cached_bitmap:
    mov  eax, r15d
    shr  eax, 3
    lea  rdi, [rel exf_w_verify]
    movzx eax, byte [rdi + rax]
    mov  ecx, r15d
    and  ecx, 7
    bt   eax, ecx
    jc   .occupied
    inc  ebx
    cmp  ebx, [rel exf_g_count]
    jae  .run
    jmp  .next
.occupied:
    xor  ebx, ebx
.next:
    inc  r13d
    jmp  .scan
.run:
    inc  r13d
    sub  r13d, ebx
    mov  [rel exf_c_first], r13d
    mov  [rel exf_g_first], r13d
    mov  [rel exf_w_plan_count], ebx
    lea  rdi, [rel exf_w_plan]
    xor  ecx, ecx
.plan:
    mov  [rdi + rcx * 4], r13d
    inc  r13d
    inc  ecx
    cmp  ecx, ebx
    jb   .plan
.ok:
    xor  eax, eax
    jmp  .out
.full:
    mov  dword [rel exfat_disk_last_error], EXF_E_NOSPACE
    jmp  .fail
.unsupported:
    mov  dword [rel exfat_disk_last_error], EXF_E_UNSUPPORTED
    jmp  .fail
.io:
    mov  dword [rel exfat_disk_last_error], EXF_E_IO
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

; RAX=offset in new contiguous allocation -> w_sector. Bounds prevalidated.
exf_c_sector:
    shr  rax, 9
    mov  edx, [rel exf_c_first]
    sub  edx, 2
    mov  ecx, [r12 + exf_ctx.clus_shift]
    sub  ecx, 9
    shl  rdx, cl
    add  rax, rdx
    mov  rdx, [r12 + exf_ctx.heap_off]
    mov  ecx, [r12 + exf_ctx.dev_shift]
    shl  rdx, cl
    add  rax, rdx
    add  rax, [r12 + exf_ctx.part_lba]
    mov  [rel exf_w_sector], rax
    ret

exf_c_set_build:
    lea  rdi, [rel exf_c_set]
    xor  esi, esi
    mov  edx, 128
    call memset
    mov  byte [rel exf_c_set], EXF_DE_FILE
    mov  byte [rel exf_c_set + 1], 2
    mov  word [rel exf_c_set + 4], 0x20   ; Archive
    cmp  dword [rel exf_c_mode], 2
    jne  .attr_ready
    mov  word [rel exf_c_set + 4], EXF_ATTR_DIR
.attr_ready:
    call exf_c_timestamp
    mov  [rel exf_c_set + 8], eax
    mov  [rel exf_c_set + 12], eax
    mov  [rel exf_c_set + 16], eax
    mov  byte [rel exf_c_set + 32], EXF_DE_STREAM
    mov  byte [rel exf_c_set + 33], EXF_SF_ALLOC
    cmp  qword [rel exf_c_length], 0
    je   .empty
    or   byte [rel exf_c_set + 33], EXF_SF_NOFATCHAIN
.empty:
    mov  eax, [rel exf_c_first]
    mov  [rel exf_c_set + 52], eax
    mov  rax, [rel exf_c_length]
    mov  [rel exf_c_set + 40], rax
    mov  [rel exf_c_set + 56], rax
    mov  [rel exf_i_new_valid], rax
    mov  [rel exf_g_new_length], rax
    mov  byte [rel exf_c_set + 64], EXF_DE_NAME
    mov  rsi, [rel exf_w_path]
    inc  rsi
    mov  ecx, [rel exf_w_path_len]
    dec  ecx
    cmp  dword [rel exf_t_active], 0
    je   .leaf_name
    mov  eax, [rel exf_t_old_leaf]
    lea  rsi, [rel exf_n_old_path]
    add  rsi, rax
    mov  ecx, [rel exf_n_old_len]
    sub  ecx, eax
.leaf_name:
    mov  [rel exf_c_set + 35], cl
    xor  edx, edx
    lea  rdi, [rel exf_c_set + 66]
.name:
    movzx eax, byte [rsi + rdx]
    mov  [rdi + rdx * 2], ax
    inc  edx
    cmp  edx, ecx
    jb   .name
    mov  rsi, rdi
    call exf_name_hash                   ; checked/decompressed on-volume upcase, never ASCII guess
    mov  [rel exf_c_set + 36], ax
    ret

; Canonical wall read only; no RTC access/clock setter. DOS1980..2107 range.
; Unseeded/out-of-range clocks use DOS epoch, UTC-offset-valid stays clear;
; this finite backend does not invent a current date or UTC provenance. Native
; wall seed may itself be approximate/local. 10ms increments remain0.
exf_c_timestamp:
    push rbx
    push r13
    push r14
    push r15
    call time_wall_now_s
    cmp  rax, 315532800                  ; 1980-01-01
    jb   .unknown
    mov  rdx, 4354819199                 ; 2107-12-31T23:59:59
    cmp  rax, rdx
    ja   .unknown
    sub  rax, 315532800
    xor  edx, edx
    mov  ecx, 86400
    div  rcx
    mov  r13d, eax                       ; days since1980
    mov  rax, rdx
    xor  edx, edx
    mov  ecx, 3600
    div  ecx
    shl  eax, 11
    mov  ebx, eax
    mov  rax, rdx
    xor  edx, edx
    mov  ecx, 60
    div  ecx
    shl  eax, 5
    or   ebx, eax
    shr  edx, 1
    or   ebx, edx
    mov  r14d, 1980
.year:
    mov  r15d, 365
    test r14d, 3
    jnz  .year_days
    cmp  r14d, 2100                      ; sole nonleap century in supported range
    je   .year_days
    inc  r15d
.year_days:
    cmp  r13d, r15d
    jb   .months
    sub  r13d, r15d
    inc  r14d
    jmp  .year
.months:
    sub  r14d, 1980
    shl  r14d, 9
    xor  ecx, ecx
    lea  rdi, [rel exf_c_month_days]
.month:
    movzx edx, byte [rdi + rcx]
    cmp  ecx, 1
    jne  .month_days
    cmp  r15d, 366
    jne  .month_days
    inc  edx
.month_days:
    cmp  r13d, edx
    jb   .date
    sub  r13d, edx
    inc  ecx
    jmp  .month
.date:
    inc  ecx
    shl  ecx, 5
    or   r14d, ecx
    inc  r13d
    or   r14d, r13d
    shl  r14d, 16
    mov  eax, ebx
    or   eax, r14d
    jmp  .out
.unknown:
    mov  eax, 0x00210000
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

; write_at_path(self, RSI=path, EDX=len, RCX=off, R8=buf, R9=len) -> len/-1.
; Failure counters are separate from RAX: a failed backend write/flush can have
; changed the medium. Never return a successful short count for such an error.
exf_op_write_at_path:
    push rbx
    push r12
    push r13
    push r14
    push r15
    cmp  dword [rel exf_w_active], 0
    jne  .busy
    mov  qword [rel exfat_disk_write_confirmed], 0
    mov  qword [rel exfat_disk_write_attempted], 0
    mov  qword [rel exfat_disk_write_reclaimed], 0
    mov  qword [rel exfat_disk_write_reclaim_attempted], 0
    mov  qword [rel exfat_disk_write_reclaim_state], 0
    mov  qword [rel exfat_disk_replace_state], 0
    mov  qword [rel exfat_disk_move_state], 0
    mov  qword [rel exfat_disk_move_destination_attempted], 0
    mov  qword [rel exfat_disk_move_destination_confirmed], 0
    mov  qword [rel exfat_disk_move_source_attempted], 0
    mov  qword [rel exfat_disk_move_source_confirmed], 0
    mov  dword [rel exf_i_mode], 0
    mov  dword [rel exf_g_mode], 0
    mov  dword [rel exf_g_bitmap_count], 0
    mov  qword [rel exfat_disk_write_allocation], 0
    mov  qword [rel exfat_disk_write_reserved], 0
    mov  qword [rel exfat_disk_write_reservation_attempted], 0
    mov  qword [rel exfat_disk_write_stage], 0
    mov  qword [rel exfat_disk_write_published], 0
    mov  qword [rel exfat_disk_write_dirty], 0
    mov  qword [rel exfat_disk_write_zeroed], 0
    mov  qword [rel exfat_disk_write_zero_attempted], 0
    EXF_ENTER
    mov  dword [rel exf_w_active], 1
    mov  dword [rel exf_c_mode], 0
    mov  dword [rel exf_n_mode], 0
    mov  [rel exf_w_offset], rcx
    mov  [rel exf_w_buffer], r8
    mov  [rel exf_w_length], r9
    mov  [rel exf_w_path], rsi
    mov  [rel exf_w_path_len], edx
    cmp  edx, EXF_PATH_MAX
    ja   .range
    test rsi, rsi
    jz   .range
    mov  rax, rsi
    add  rax, rdx
    jc   .range
    cmp  r9, EXF_WRITE_MAX
    ja   .unsupported
    mov  rax, rcx
    add  rax, r9
    jc   .range
    mov  rax, r8
    add  rax, r9
    jc   .range
    test r9, r9
    jz   .bufferok
    test r8, r8
    jz   .range
.bufferok:
    call storage_access_request_owner
    mov  [rel exf_w_owner], eax
    mov  rdi, [r12 + exf_ctx.dev]
    call storage_access_intent_for_dev
    mov  [rel exf_w_intent], eax
    call exf_w_live
    test rax, rax
    jnz  .fail
    ; Invalidate both caches and revalidate live boot/root/upcase before lookup.
    mov  qword [r12 + exf_ctx.sec_tag], -1
    mov  qword [r12 + exf_ctx.fat_tag], -1
    mov  rdi, [r12 + exf_ctx.dev]
    mov  rsi, [r12 + exf_ctx.part_lba]
    mov  edx, 1
    lea  rcx, [rel exf_boot_buf]
    call exf_raw_read
    test rax, rax
    jnz  .io
    lea  rdi, [r12 + exf_ctx.boot_identity]
    lea  rsi, [rel exf_boot_buf]
    mov  edx, 120
    call memcmp
    test rax, rax
    jnz  .stale
    call exf_mount_ctx
    test eax, eax
    jz   .mount_refreshed
    cmp  eax, EXF_R_IO
    je   .io
    cmp  dword [rel exfat_disk_last_error], EXF_E_IO
    je   .io
    cmp  dword [rel exfat_disk_last_error], EXF_E_UNSUPPORTED
    je   .unsupported
    jmp  .corrupt
.mount_refreshed:
    mov  rsi, [rel exf_w_path]
    mov  edx, [rel exf_w_path_len]
    call exf_resolve
    test rax, rax
    jnz  .fail
    test dword [r12 + exf_ctx.leaf + exf_strm.attr], EXF_ATTR_DIR | 1
    jnz  .readonly
    mov  rax, [rel exf_w_offset]
    add  rax, [rel exf_w_length]
    cmp  rax, [r12 + exf_ctx.leaf + exf_strm.length]
    jbe  .within_length
    cmp  qword [rel exf_w_length], 0
    je   .range
    call exf_g_bounds                     ; existing nonempty NoFatChain run only
    test rax, rax
    jnz  .fail
    mov  rax, [rel exf_g_new_length]
.within_length:
    cmp  rax, [r12 + exf_ctx.leaf + exf_strm.valid]
    jbe  .initialized
    cmp  qword [rel exf_w_length], 0
    je   .range                          ; retain zero-length initialized-range contract
    mov  [rel exf_i_new_valid], rax
    mov  rdx, [r12 + exf_ctx.leaf + exf_strm.valid]
    mov  [rel exf_i_old_valid], rdx
    mov  rcx, [rel exf_w_offset]
    xor  ebx, ebx
    cmp  rcx, rdx
    jbe  .no_gap
    mov  rbx, rcx
    sub  rbx, rdx
    mov  rcx, rdx
.no_gap:
    mov  [rel exf_i_gap_left], rbx
    cmp  dword [rel exf_g_mode], 0
    je   .work_end
    mov  rax, [rel exf_g_work_end]          ; include newly allocated tail padding
.work_end:
    sub  rax, rcx
    cmp  rax, EXF_WRITE_MAX
    ja   .unsupported
    mov  [rel exf_w_offset], rcx          ; plan includes every gap cluster
    mov  [rel exf_w_length], rax
    mov  dword [rel exf_i_mode], 1
    cmp  dword [r12 + exf_ctx.vflags], 0   ; finite subset: no ClearToZero/reserved flags
    jne  .unsupported
    mov  rax, [rel exf_set_location]
    mov  rdx, rax
    and  edx, 511
    cmp  edx, 448                        ; primary+stream (64B) in ONE device sector
    ja   .unsupported
    mov  [rel exf_i_meta_within], rdx
    shr  rax, 9
    add  rax, [r12 + exf_ctx.part_lba]
    mov  [rel exf_i_meta_lba], rax
    mov  rax, [rel exf_set_location]
    mov  ecx, [r12 + exf_ctx.sec_shift]
    shr  rax, cl
    sub  rax, [r12 + exf_ctx.heap_off]
    mov  ecx, [r12 + exf_ctx.spc_shift]
    shr  rax, cl
    add  eax, 2
    mov  [rel exf_i_meta_cluster], eax
    lea  rdi, [rel exf_i_parent]
    lea  rsi, [r12 + exf_ctx.dir]
    mov  edx, exf_strm_size
    call memcpy
.initialized:
    cmp  qword [rel exf_w_length], 0
    je   .success                         ; explicit read-only no-op; no grant/write/flush
    mov  rax, [rel exf_set_location]
    mov  [rel exf_w_location], rax
    mov  eax, [rel exf_set_count]
    inc  eax
    shl  eax, 5
    mov  [rel exf_w_set_len], eax
    mov  edx, eax
    lea  rdi, [rel exf_w_set]
    lea  rsi, [rel exf_set_buf]
    call memcpy
    mov  dword [rel exf_w_plan_count], 0
    mov  dword [rel exf_w_budget], EXF_WRITE_BUDGET
    cmp  dword [rel exf_g_mode], 0
    je   .growth_prepared
    call exf_g_prepare                    ; free bits and bitmap sector ownership keys
    test rax, rax
    jnz  .fail
.growth_prepared:
    lea  rdi, [r12 + exf_ctx.leaf]
    xor  edx, edx
    call exf_w_stream
    test rax, rax
    jnz  .fail
    mov  r13, [rel exf_w_offset]
    mov  r14, r13
    add  r14, [rel exf_w_length]
    dec  r14
    mov  ecx, [r12 + exf_ctx.clus_shift]
    shr  r13, cl
    shr  r14, cl
    mov  qword [r12 + exf_ctx.map_idx], 0
    mov  eax, [r12 + exf_ctx.leaf + exf_strm.first]
    mov  [r12 + exf_ctx.map_clus], eax
.plan:
    mov  rsi, r13
    call exf_map
    test rax, rax
    js   .fail
    mov  ecx, [rel exf_w_plan_count]
    cmp  ecx, EXF_WRITE_PLAN
    jae  .unsupported
    lea  rdi, [rel exf_w_plan]
    mov  [rdi + rcx * 4], eax
    inc  dword [rel exf_w_plan_count]
    inc  r13
    cmp  r13, r14
    jbe  .plan
    call exf_w_census
    test rax, rax
    jnz  .fail
    ; Re-resolve without a cache hit, comparing every byte of the entry set and
    ; its physical location. This closes identity changes during prevalidation.
    mov  qword [r12 + exf_ctx.sec_tag], -1
    mov  qword [r12 + exf_ctx.fat_tag], -1
    mov  rsi, [rel exf_w_path]
    mov  edx, [rel exf_w_path_len]
    call exf_resolve
    test rax, rax
    jnz  .fail
    mov  rax, [rel exf_set_location]
    cmp  rax, [rel exf_w_location]
    jne  .stale
    mov  eax, [rel exf_set_count]
    inc  eax
    shl  eax, 5
    cmp  eax, [rel exf_w_set_len]
    jne  .stale
    lea  rdi, [rel exf_set_buf]
    lea  rsi, [rel exf_w_set]
    mov  edx, eax
    call memcmp
    test rax, rax
    jnz  .stale
    ; Preflight ALL device sectors under the current request before first write.
    ; Subsequent calls repeat the gate; no request context is captured for reuse.
    mov  r13, [rel exf_w_offset]
    mov  r14, [rel exf_w_length]
.preflight:
    call exf_w_piece_map
    test rax, rax
    js   .fail
    call exf_w_gate
    test rax, rax
    jnz  .fail
    mov  rax, [rel exf_w_piece]
    add  [rel exf_w_offset], rax
    sub  [rel exf_w_length], rax
    jnz  .preflight
    mov  [rel exf_w_offset], r13
    mov  [rel exf_w_length], r14
    cmp  dword [rel exf_i_mode], 0
    je   .write
    call exf_i_prepare                    ; boot+metadata snapshot and ALL metadata grants
    test rax, rax
    jnz  .fail
    call exf_i_dirty_begin                ; flush+verify dirty before any data or VDL write
    test rax, rax
    jnz  .fail
    call exf_g_reserve                    ; durable allocation before new-cluster data
    test rax, rax
    jnz  .fail
.write:
    call exf_w_piece_map
    test rax, rax
    js   .fail
    mov  dword [rel exf_i_zero_mode], 0
    cmp  dword [rel exf_i_mode], 0
    je   .piece_ready
    mov  qword [rel exfat_disk_write_stage], 3
    mov  rdx, [rel exf_i_gap_left]
    test rdx, rdx
    jnz  .gap_piece
    cmp  dword [rel exf_g_mode], 0
    je   .piece_ready
    mov  rdx, [rel exf_g_data_left]
    test rdx, rdx
    jnz  .data_piece
    mov  dword [rel exf_i_zero_mode], 2    ; new allocation's tail padding
    jmp  .piece_ready
.gap_piece:
    mov  dword [rel exf_i_zero_mode], 1
.data_piece:
    cmp  rax, rdx
    jbe  .piece_ready
    mov  [rel exf_w_piece], rdx
.piece_ready:
    mov  rdi, [r12 + exf_ctx.dev]
    mov  rsi, [rel exf_w_sector]
    mov  edx, 1
    lea  rcx, [rel exf_w_bounce]
    call blk_read
    test rax, rax
    jnz  .io
    lea  rdi, [rel exf_w_bounce]
    add  rdi, [rel exf_w_within]
    mov  rdx, [rel exf_w_piece]
    cmp  dword [rel exf_i_zero_mode], 0
    je   .copy_data
    xor  esi, esi
    call memset
    jmp  .piece_filled
.copy_data:
    mov  rsi, [rel exf_w_buffer]
    call memcpy
.piece_filled:
    call exf_w_gate
    test rax, rax
    jnz  .fail
    cmp  dword [rel exf_i_zero_mode], 0
    jne  .zero_attempt
    mov  rax, [rel exfat_disk_write_confirmed]
    add  rax, [rel exf_w_piece]
    mov  [rel exfat_disk_write_attempted], rax ; write may fail after partial media change
    jmp  .piece_attempted
.zero_attempt:
    mov  rax, [rel exfat_disk_write_zeroed]
    add  rax, [rel exf_w_piece]
    mov  [rel exfat_disk_write_zero_attempted], rax
.piece_attempted:
    mov  rdi, [r12 + exf_ctx.dev]
    mov  rsi, [rel exf_w_sector]
    mov  edx, 1
    lea  rcx, [rel exf_w_bounce]
    call blk_write
    test rax, rax
    jnz  .io
    mov  rdi, [r12 + exf_ctx.dev]
    call blk_flush
    test rax, rax
    jnz  .flush
    call exf_w_live
    test rax, rax
    jnz  .fail
    mov  rdi, [r12 + exf_ctx.dev]
    mov  rsi, [rel exf_w_sector]
    mov  edx, 1
    lea  rcx, [rel exf_w_verify]
    call blk_read
    test rax, rax
    jnz  .io
    lea  rdi, [rel exf_w_bounce]
    lea  rsi, [rel exf_w_verify]
    mov  edx, 512
    call memcmp
    test rax, rax
    jnz  .verify
    call exf_w_live
    test rax, rax
    jnz  .fail
    mov  rax, [rel exf_w_piece]
    cmp  dword [rel exf_i_zero_mode], 0
    jne  .zero_confirmed
    add  [rel exfat_disk_write_confirmed], rax
    add  [rel exf_w_buffer], rax
    cmp  dword [rel exf_g_mode], 0
    je   .piece_confirmed
    sub  [rel exf_g_data_left], rax
    jmp  .piece_confirmed
.zero_confirmed:
    add  [rel exfat_disk_write_zeroed], rax
    cmp  dword [rel exf_i_zero_mode], 1
    jne  .piece_confirmed
    sub  [rel exf_i_gap_left], rax
.piece_confirmed:
    add  [rel exf_w_offset], rax
    sub  [rel exf_w_length], rax
    jnz  .write
    cmp  dword [rel exf_i_mode], 0
    je   .success
    call exf_i_publish                    ; data+zeros durable BEFORE VDL/checksum
    test rax, rax
    jnz  .fail
.success:
    mov  dword [rel exfat_disk_last_error], EXF_E_NONE
    mov  rax, [rel exfat_disk_write_confirmed]
    jmp  .finish
.verify:
    mov  dword [rel exfat_disk_last_error], EXF_E_VERIFY
    jmp  .fail
.flush:
    mov  dword [rel exfat_disk_last_error], EXF_E_FLUSH
    jmp  .fail
.io:
    mov  dword [rel exfat_disk_last_error], EXF_E_IO
    jmp  .fail
.readonly:
    mov  dword [rel exfat_disk_last_error], EXF_E_READONLY
    jmp  .fail
.range:
    mov  dword [rel exfat_disk_last_error], EXF_E_RANGE
    jmp  .fail
.unsupported:
    mov  dword [rel exfat_disk_last_error], EXF_E_UNSUPPORTED
    jmp  .fail
.corrupt:
    mov  dword [rel exfat_disk_last_error], EXF_E_CORRUPT
    jmp  .fail
.stale:
    mov  dword [rel exfat_disk_last_error], EXF_E_STALE
.fail:
    cmp  qword [rel exfat_disk_write_stage], 0
    je   .ordinary_failure
    call exf_i_failed                     ; mark dirty/error if authority survives; no rollback
    mov  dword [r12 + exf_ctx.mounted], 0  ; uncertainty can never become an automatic clean retry
    lea  rdi, [rel str_exf_i_failed]
    call serial_string
    mov  rdi, [rel exfat_disk_write_stage]
    call serial_hex64
    lea  rdi, [rel str_exf_i_published]
    call serial_string
    mov  rdi, [rel exfat_disk_write_published]
    call serial_hex64
    lea  rdi, [rel str_exf_i_dirty]
    call serial_string
    mov  rdi, [rel exfat_disk_write_dirty]
    call serial_hex64
    lea  rdi, [rel str_exf_g_allocation]
    call serial_string
    mov  rdi, [rel exfat_disk_write_allocation]
    call serial_hex64
    lea  rdi, [rel str_exf_g_reserved]
    call serial_string
    mov  rdi, [rel exfat_disk_write_reserved]
    call serial_hex64
    call serial_newline
.ordinary_failure:
    cmp  qword [rel exfat_disk_write_attempted], 0
    je   .failed_result
    lea  rdi, [rel str_exf_write_failed]
    call serial_string
    mov  rdi, [rel exfat_disk_write_confirmed]
    call serial_hex64
    lea  rdi, [rel str_exf_write_attempted]
    call serial_string
    mov  rdi, [rel exfat_disk_write_attempted]
    call serial_hex64
    lea  rdi, [rel str_exf_write_error]
    call serial_string
    mov  edi, [rel exfat_disk_last_error]
    call serial_hex64
    call serial_newline
.failed_result:
    mov  rax, -1
.finish:
    mov  dword [rel exf_w_active], 0
    mov  qword [r12 + exf_ctx.sec_tag], -1
    mov  qword [r12 + exf_ctx.fat_tag], -1
    jmp  .out
.busy:
    mov  dword [rel exfat_disk_last_error], EXF_E_UNSUPPORTED
    mov  rax, -1
    jmp  .out
.unmounted:
    mov  dword [rel exfat_disk_last_error], EXF_E_STALE
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; write_at(self, RSI=name11, RDX=off, RCX=buf, R8=len) -> same semantics.
exf_op_write_at:
    test rsi, rsi
    jz   .fail
    mov  r9, r8
    mov  r8, rcx
    push rdi
    push rdx
    call exf_name11_path
    pop  rcx
    pop  rdi
    jmp  exf_op_write_at_path
.fail:
    mov  rax, -1
    ret

; readfile(self, RSI=name11, RDX=buf, RCX=cap) -> len/-1 (the whole file must fit)
exf_op_readfile:
    push rbx
    push r12
    push r13
    push r14
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rdx
    mov  r14, rcx
    lea  rdx, [rel exf_stat_tmp]
    call exf_op_stat
    test rax, rax
    jnz  .fail
    test dword [rel exf_stat_tmp + fs_stat.reserved], 1
    jnz  .fail
    mov  r8, [rel exf_stat_tmp + fs_stat.size]
    cmp  r8, r14
    ja   .fail
    mov  rdi, rbx
    mov  rsi, r12
    xor  edx, edx
    mov  rcx, r13
    call exf_op_read_at
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
exf_op_info:
    push r12
    mov  rdx, rsi
    EXF_ENTER
    test rdx, rdx
    jz   .unmounted
    lea  rax, [rel str_exf_backend]
    mov  [rdx + fs_info.backend], rax
    mov  [rdx + fs_info.part_type], rax  ; a string, as PARTLS prints it (fat32_disk does the same)
    mov  rax, [r12 + exf_ctx.dev]
    mov  [rdx + fs_info.device], rax
    mov  eax, [r12 + exf_ctx.serial]
    mov  [rdx + fs_info.volume_id], eax
    mov  ecx, [r12 + exf_ctx.clus_shift]
    mov  eax, 1
    shl  eax, cl
    mov  [rdx + fs_info.cluster_bytes], eax
    mov  rax, [r12 + exf_ctx.vol_sectors]
    mov  ecx, [r12 + exf_ctx.dev_shift]
    shl  rax, cl
    mov  [rdx + fs_info.total_sectors], rax
    mov  rax, [r12 + exf_ctx.part_lba]
    mov  [rdx + fs_info.part_start], rax
    mov  rax, [r12 + exf_ctx.part_sectors]
    mov  [rdx + fs_info.part_sectors], rax
    mov  eax, [r12 + exf_ctx.scheme]
    mov  [rdx + fs_info.scheme], eax
    mov  dword [rdx + fs_info.part_count], 1
    xor  eax, eax                        ; free_clusters / orphans keep vfs_info's -1 (unknown)
    pop  r12
    ret
.unmounted:
    mov  rax, -1
    pop  r12
    ret

; ---------------------------------------------------------------------------
; Markers
; ---------------------------------------------------------------------------
; exf_emit_mounted(R12=ctx)
exf_emit_mounted:
    lea  rdi, [rel str_exf_mounted]
    call serial_string
    mov  rdi, [r12 + exf_ctx.name]
    call serial_string
    lea  rdi, [rel str_exf_m_dev]
    call serial_string
    mov  rdi, [r12 + exf_ctx.dev]
    call exf_emit_dev_name
    lea  rdi, [rel str_exf_m_lba]
    call serial_string
    mov  rdi, [r12 + exf_ctx.part_lba]
    call serial_hex64
    lea  rdi, [rel str_exf_m_sectors]
    call serial_string
    mov  rdi, [r12 + exf_ctx.vol_sectors]
    call serial_hex64
    lea  rdi, [rel str_exf_m_bps]
    call serial_string
    mov  ecx, [r12 + exf_ctx.sec_shift]
    mov  edi, 1
    shl  edi, cl
    call serial_hex64
    lea  rdi, [rel str_exf_m_cluster]
    call serial_string
    mov  ecx, [r12 + exf_ctx.clus_shift]
    mov  edi, 1
    shl  edi, cl
    call serial_hex64
    lea  rdi, [rel str_exf_m_clusters]
    call serial_string
    mov  edi, [r12 + exf_ctx.clus_count]
    call serial_hex64
    lea  rdi, [rel str_exf_m_ro]
    call serial_string
    lea  rdi, [rel str_exf_crlf]
    call serial_string
    ret

; exf_emit_refused(RDI=dev, RSI=part lba, EDX=reason)
exf_emit_refused:
    push rbx
    push r13
    push r14
    mov  rbx, rdi
    mov  r13, rsi
    mov  r14d, edx
    lea  rdi, [rel str_exf_refused]
    call serial_string
    mov  eax, r14d
    cmp  eax, EXF_R_NOMOUNT
    jbe  .named
    xor  eax, eax
.named:
    shl  eax, 4
    lea  rdi, [rel exf_reason_names]
    add  rdi, rax
    call serial_string
    lea  rdi, [rel str_exf_m_dev]
    call serial_string
    mov  rdi, rbx
    call exf_emit_dev_name
    lea  rdi, [rel str_exf_m_lba]
    call serial_string
    mov  rdi, r13
    call serial_hex64
    lea  rdi, [rel str_exf_crlf]
    call serial_string
    pop  r14
    pop  r13
    pop  rbx
    ret

; exf_emit_dev_name(RDI=dev*)
exf_emit_dev_name:
    test rdi, rdi
    jz   .anon
    mov  rdi, [rdi + dev.name]
    test rdi, rdi
    jnz  .print
.anon:
    lea  rdi, [rel str_exf_anon]
.print:
    jmp  serial_string

; ---- read-only data ----
exf_c_month_days:    db 31,28,31,30,31,30,31,31,30,31,30,31
exf_p_suffix:        db 'PAOSAPP', 0
; Canonical read-only token identity for the bounded PARTLS type union.
exfat_disk_part_type:
str_exf_backend:     db "exfat", 0
str_exf_root:        db "/", 0
str_exf_anon:        db "?", 0
str_exf_mount_names: db "exfat0", 0, "exfat1", 0
%macro EXF_REASON 1
%%row: db %1
    times 16 - ($ - %%row) db 0
%endmacro
exf_reason_names:
    EXF_REASON "unknown"
    EXF_REASON "bootsig"
    EXF_REASON "mustbezero"
    EXF_REASON "revision"
    EXF_REASON "sectorshift"
    EXF_REASON "clustershift"
    EXF_REASON "fats"
    EXF_REASON "layout"
    EXF_REASON "checksum"
    EXF_REASON "dirty"
    EXF_REASON "mediafailure"
    EXF_REASON "root"
    EXF_REASON "bitmap"
    EXF_REASON "upcase"
    EXF_REASON "nomem"
    EXF_REASON "io"
    EXF_REASON "nomount"
%if ($ - exf_reason_names) != 16 * (EXF_R_NOMOUNT + 1)
    %error "exf_reason_names: one 16-byte row per EXF_R_* reason"
%endif
str_exf_mounted:     db "[PAOS64] [fs.exfat.mounted] ", 0
str_exf_m_dev:       db " dev=", 0
str_exf_m_lba:       db " lba=", 0
str_exf_m_sectors:   db " sectors=", 0
str_exf_m_bps:       db " bps=", 0
str_exf_m_cluster:   db " cluster=", 0
str_exf_m_clusters:  db " clusters=", 0
str_exf_m_ro:        db " write=bounded-contiguous-growth gated=1 max=65536", 0
str_exf_g_allocation: db " allocation=", 0
str_exf_g_reserved: db " reserved=", 0
str_exf_i_failed: db "[PAOS64] [fs.exfat.initialize.failed] stage=", 0
str_exf_i_published: db " published=", 0
str_exf_i_dirty: db " dirty=", 0
str_exf_write_failed: db "[PAOS64] [fs.exfat.write.failed] confirmed=", 0
str_exf_write_attempted: db " attempted=", 0
str_exf_write_error: db " error=", 0
str_exf_write_gate:  db "exfat-initialized-overwrite", 0
str_exf_a_gate:      db "exfat-namespace-arm", 0
str_exf_crlf:        db 13, 10, 0
str_exf_refused:     db "[PAOS64] [fs.exfat.refused] reason=", 0
str_exf_skipped:     db "[PAOS64] [fs.exfat.skipped] no mountable exFAT volume", 13, 10, 0

%macro WDATA_fs_exfat_disk 0
exfat_disk_handle:      dd -1
%endmacro
WDATA_DEFER WDATA_fs_exfat_disk
; Zero-initialised state (core/abi/wdata.inc WDATA_BSS_DEFER).
%macro WDATA_fs_exfat_disk_bss1 0
exfat_disk_replace_state: resq 1
exf_r_active: resd 1
exf_r_gate_active: resd 1
exf_r_failure: resd 1
exf_r_boot_state: resd 1
exf_r_published: resd 1
exf_r_reserved_sectors: resd 1
exf_r_retired_sectors: resd 1
exf_r_old_first: resd 1
exf_r_old_count: resd 1
exf_r_old_stream: resb 32
exf_r_reservation: resb exf_r_plan_size
exf_r_retirement: resb exf_r_plan_size
exf_r_meta_new: resb 512
exf_r_boot_expected: resb 512
exfat_disk_move_state: resq 1
exfat_disk_move_destination_attempted: resq 1
exfat_disk_move_destination_confirmed: resq 1
exfat_disk_move_source_attempted: resq 1
exfat_disk_move_source_confirmed: resq 1
exf_m_cross: resd 1
exf_m_gate_active: resd 1
exf_m_failure: resd 1
exf_m_dirty_started: resd 1
exf_m_account: resd 1
exf_m_census: resd 1
exf_m_dst_hits: resd 1
exf_m_src_count: resd 1
exf_m_dst_count: resd 1
exf_m_depth_delta: resd 1
exf_m_src_cluster: resd 1
exf_m_dst_cluster: resd 1
exf_m_dst_lba: resq 1
exf_m_dst_within: resq 1
exf_m_dst_span: resd 1
exf_m_src_parent: resb 32
exf_m_dst_parent: resb 32
exf_m_src_ancestors: resb 312
exf_m_dst_ancestors: resb 312
exf_m_src_set: resb 96
exf_m_dst_slot: resb 128
exf_m_dst_old: resb 512
exf_m_dst_new: resb 512
exf_m_verify: resb 512
exf_m_root_stream: resb 32
exf_m_root_count: resd 1
exf_m_root_links: resd 129
exf_m_seen: resb 8192
exf_m_depths: resb EXF_WRITE_DIRS * 8
exf_m_tags: resb EXF_WRITE_DIRS * 8
exfat_disk_write_allocation: resq 1
exf_a_incarnation_next: resq 1
exf_a_inflight: resd 1
exf_a_path_input: resq 1
exf_a_old11: resb 11
exf_a_new11: resb 11
exfat_disk_write_reserved: resq 1
exfat_disk_write_reservation_attempted: resq 1
exfat_disk_write_reclaimed: resq 1
exfat_disk_write_reclaim_attempted: resq 1
exfat_disk_write_reclaim_state: resq 1
exf_n_mode: resd 1
exf_n_noop: resd 1
exf_n_meta_count: resd 1
exf_n_meta_cluster2: resd 1
exf_n_old_len: resd 1
exf_n_new_len: resd 1
exf_n_old_path: resb 64
exf_n_new_path: resb 64
exf_t_active: resd 1
exf_t_kind: resd 1
exf_t_old_leaf: resd 1
exf_t_new_leaf: resd 1
exf_t_component: resb 17                ; '/' +15units +NUL
exf_t_component11: resb 11
exf_t_ancestors: resb 3 * 104          ; exact physical location +96-byte set per ancestor
exf_t_find_count: resd 1
exf_t_find_location: resq 1
exf_t_find_set: resb 96
exf_n_stream: resb exf_strm_size
exf_n_entry_lbas: resq 3
exf_n_entry_within: resd 3
exf_n_meta_lbas: resq 2
exf_n_old: resb 1024
exf_n_new: resb 1024
exf_g_mode: resd 1
exf_c_mode: resd 1
exf_c_first: resd 1
exf_c_span: resd 1
exf_c_length: resq 1
exf_c_allocation: resq 1
exf_c_bitmap_tag: resq 1
exf_c_set: resb 128
exf_g_first: resd 1
exf_g_count: resd 1
exf_g_bitmap_count: resd 1
exf_g_bitmap_clusters: resd EXF_GROW_BITMAPS
exf_g_bitmap_bits: resd EXF_GROW_BITMAPS
exf_g_bitmap_lbas: resq EXF_GROW_BITMAPS
exf_g_new_length: resq 1
exf_g_work_end: resq 1
exf_g_data_left: resq 1
exf_g_bitmap_old: resb 512 * EXF_GROW_BITMAPS
exf_g_bitmap_new: resb 512 * EXF_GROW_BITMAPS
exfat_disk_write_stage: resq 1
exfat_disk_write_published: resq 1
exfat_disk_write_dirty: resq 1
exfat_disk_write_zeroed: resq 1
exfat_disk_write_zero_attempted: resq 1
exf_i_mode: resd 1
exf_i_zero_mode: resd 1
exf_i_parent_hits: resd 1
exf_i_meta_cluster: resd 1
exf_i_new_valid: resq 1
exf_i_old_valid: resq 1
exf_i_gap_left: resq 1
exf_i_meta_within: resq 1
exf_i_meta_lba: resq 1
exf_i_parent: resb exf_strm_size
exf_i_boot: resb 512
exf_i_meta: resb 512
exf_i_new_set: resb 32 * (EXF_SEC_COUNT_MAX + 1)
exfat_disk_write_confirmed: resq 1
exfat_disk_write_attempted: resq 1
exf_set_location:       resq 1
exf_w_active:           resd 1
exf_w_plan_count:       resd 1
exf_w_dir_count:        resd 1
exf_w_dir_index:        resd 1
exf_w_entries:          resd 1
exf_w_budget:           resd 1
exf_w_found:            resd 1
exf_w_set_len:          resd 1
exf_w_location:         resq 1
exf_w_path:             resq 1
exf_w_path_len:         resd 1
exf_w_owner:            resd 1
exf_w_intent:           resd 1
exf_w_offset:           resq 1
exf_w_buffer:           resq 1
exf_w_length:           resq 1
exf_w_sector:           resq 1
exf_w_piece:            resq 1
exf_w_within:           resq 1
exf_w_set:              resb 32 * (EXF_SEC_COUNT_MAX + 1)
exf_w_plan:             resd EXF_WRITE_PLAN
exf_w_dirs:             resb exf_strm_size * EXF_WRITE_DIRS
exf_w_bounce:           resb 512
exf_w_verify:           resb 512
exfat_disk_mount_count: resd 1
exfat_disk_last_error:  resd 1
exf_gpt_count:          resd 1
exf_set_count:          resd 1
exf_name_len:           resd 1
exf_comp_len:           resd 1
exf_up_csum:            resd 1
exf_up_chunk_len:       resd 1
exf_list_cap:           resd 1
exf_list_names_used:    resd 1
exf_up_len:             resq 1
exf_list_ptr:           resq 1
exf_list_result:        resq 1
exf_sel_gpt:            resb 1
exf_sel_reading:        resb 1
alignb 8
exf_sel_device:         resq 1
exf_sel_identity:       resq 5
exf_sel_primary:        resb 96
exf_sel_again:          resb 96
exf_sel_vbr:            resb 512
exf_sel_vbr_again:      resb 512
exf_spare_ctx:          resq 1
exf_rd_fallback:        resq 1
exf_rd_piece:           resq 1
exf_bw_count:           resq 1
exf_bw_power:           resq 1
exf_bw_lam:             resq 1
exf_stat_tmp:           resb fs_stat_size
exf_ops:                resb fs_ops_size
exf_n11_path:           resb 16
exf_scan_buf:           resb 512
exf_boot_buf:           resb 512
exf_chunk:              resb 512
exf_set_buf:            resb 32 * (EXF_SEC_COUNT_MAX + 1)
exf_name16:             resb 2 * 256
exf_comp16:             resb 2 * 256
exf_utf8:               resb 4 * 256
exf_list_names:         resb EXF_LIST_NAMES_CAP
%endmacro
WDATA_BSS_DEFER WDATA_fs_exfat_disk_bss1

; ---------------------------------------------------------------------------
; Read-only copy-source adapter. A single BSP copy job owns these snapshots.
; Admission uses the actual registered context and canonical block route. The
; immutable mount metadata is recorded at registration, never from a replacement
; display mount. Mutable iterator/cache fields and write authority are excluded.
; Copy-only limits: 64 KiB identity transcript, 32 path components, 4096 FAT
; links and 8192 physical transfers per adapter call. Existing reader/writer
; capacities and authority are unchanged. No source storage window is opened.
; ---------------------------------------------------------------------------
EXF_SRC_TRACE_MAX equ 65536
EXF_SRC_META_BYTES equ 64 + 8 + 8 + (exf_ctx.dir - exf_ctx.clus_count) + 8 + 24 + 16 + (blk_info_size - blk_info.logical_sector_bytes) + EXF_UPCASE_MAX

; R12=context, before publishing the registration count.
exf_src_register:
    push rdi
    push rsi
    push rdx
    push rcx
    mov  eax, [rel exfat_disk_mount_count]
    lea  rdi, [rel exf_src_contexts]
    mov  [rdi + rax * 8], r12
    imul rax, EXF_SRC_META_BYTES
    lea  rdi, [rel exf_src_metadata]
    add  rdi, rax
    mov  ecx, 1
    call exf_src_metadata_check
    pop  rcx
    pop  rdx
    pop  rsi
    pop  rdi
    ret

; RDI=fsmount -> exact dev* / 0. Pure, preserving all except RAX.
exfat_disk_source_device:
    push rdi
    push rdx
    lea  rax, [rel exf_ops]
    cmp  [rdi + fsmount.ops], rax
    jne  .bad
    mov  rdx, [rdi + fsmount.priv]
    test rdx, rdx
    jz   .bad
    cmp  rdx, [rel exf_src_contexts]
    je   .ctx
    cmp  rdx, [rel exf_src_contexts + 8]
    jne  .bad
.ctx:
    cmp  dword [rdx + exf_ctx.mounted], 1
    jne  .bad
    push rdi
    mov  edi, [rdx + exf_ctx.handle]
    call vfs_mount_ptr
    pop  rdi
    cmp  rax, rdi
    jne  .bad
    mov  rax, [rdx + exf_ctx.dev]
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  rdx
    pop  rdi
    ret

; Copy admission must compare the original immutable context BEFORE following
; its device/info/cache pointers. Pure, preserving every register except RAX.
exfat_disk_copy_device:
    push r12
    push rdi
    push rsi
    push rdx
    push rcx
    push r8
    push r9
    push r10
    push r11
    call exfat_disk_source_device
    test rax, rax
    jz   .out
    mov  r12, [rdi + fsmount.priv]
    lea  rdi, [rel exf_src_metadata]
    cmp  r12, [rel exf_src_contexts]
    je   .check
    add  rdi, EXF_SRC_META_BYTES
.check:
    xor  ecx, ecx
    call exf_src_metadata_check
    test rax, rax
    jnz  .bad
    mov  rax, [r12 + exf_ctx.dev]
    jmp  .out
.bad:
    xor  eax, eax
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
    ret

; RDI=fsmount -> RAX=1 only for an exact, current, healthy registered mount
; whose actual block descriptor says RO. Pure: no I/O, arm, grant or setters;
; preserves every register except RAX. An absent arm is never an RO fact.
exfat_disk_mount_readonly:
    push rdx
    test rdi, rdi
    jz .no
    call exfat_disk_copy_device          ; immutable mount/context/device/info + generation
    test rax, rax
    jz .out
    cmp dword [rax + dev.health], HEALTH_OK
    jne .no
    mov rdx, [rax + dev.info]            ; verified non-null by the currentness check
    mov edx, [rdx + blk_info.flags]
    or edx, [rax + dev.flags]
    test edx, BLKF_RO
    setnz al
    movzx eax, al
    jmp .out
.no:
    xor eax, eax
.out:
    pop rdx
    ret

; RDI=mount, RSI=2048B zeroed native token -> RAX=dev*/0, RDX=epoch.
; Keep the exFAT layout private: other filesystem-only HOST compositions need
; only these callbacks, rather than duplicating this context's field offsets.
%if 64 + exf_ctx.dir - exf_ctx.clus_count > 1024
 %error "exFAT copy token geometry overlaps incarnation"
%endif
exfat_disk_copy_snapshot:
    push rbx
    push r12
    mov  rbx, rsi
    call exfat_disk_copy_device
    test rax, rax
    jz   .out
    mov  r12, [rdi + fsmount.priv]
    push rax
    mov  rdi, rbx
    mov  rsi, r12
    mov  edx, 64
    call memcpy
    lea  rdi, [rbx + 64]
    lea  rsi, [r12 + exf_ctx.clus_count]
    mov  edx, exf_ctx.dir - exf_ctx.clus_count
    call memcpy
    ; Original registry + fresh boot authenticate the verified percentage.
    mov  byte [rbx + 64 + exf_ctx.boot_identity - exf_ctx.clus_count + EBS_PCT_USE], 0
    mov  rax, [r12 + exf_ctx.incarnation]
    mov  [rbx + 1024], rax
    mov  rdx, [r12 + exf_ctx.media_gen]
    pop  rax
.out:
    pop  r12
    pop  rbx
    ret

; Enter the original per-transfer read guard for this bound copy mount.
; sc_io_end always clears the flag before any mutation or other device read.
exfat_disk_copy_read_begin:
    call exfat_disk_source_current
    test rax, rax
    jnz  .out
    push r12
    mov  r12, [rel exf_src_mount]
    mov  r12, [r12 + fsmount.priv]
    mov  qword [r12 + exf_ctx.sec_tag], -1
    mov  qword [r12 + exf_ctx.fat_tag], -1
    mov  qword [rel exf_src_reading], 1
    pop  r12
.out:
    ret

; R12=ctx, RDI=registered snapshot, ECX=save(1)/compare(0).
; Immutable context ranges are compared BEFORE their pointers are dereferenced.
exf_src_metadata_check:
    push rbx
    push r13
    push r14
    push r15
    mov  r13, rdi
    mov  r14d, ecx
    lea  r15, [rel exf_src_ranges]
    mov  ebx, EXF_SRC_RANGES
.range:
    mov  esi, [r15]
    add  rsi, r12
    mov  edx, [r15 + 4]
    call exf_src_meta_span
    test rax, rax
    jnz  .out
    add  r15, 8
    dec  ebx
    jnz  .range
    mov  rbx, [r12 + exf_ctx.dev]
    lea  rsi, [rbx + dev.ops]
    mov  edx, 8
    call exf_src_meta_span
    test rax, rax
    jnz  .out
    lea  rsi, [rbx + dev.priv]
    mov  edx, 8
    call exf_src_meta_span
    test rax, rax
    jnz  .out
    lea  rsi, [rbx + dev.info]
    mov  edx, 8
    call exf_src_meta_span
    test rax, rax
    jnz  .out
    mov  rbx, [rbx + dev.info]
    test rbx, rbx
    jz   .bad
    cmp  dword [rbx + blk_info.sector_size], 512
    jne  .bad
    mov  rax, [rbx + blk_info.media_generation]
    test rax, rax
    jz   .bad
    cmp  rax, [r12 + exf_ctx.media_gen]
    jne  .bad
    lea  rsi, [rbx + blk_info.sector_size]
    mov  edx, 4
    call exf_src_meta_span
    test rax, rax
    jnz  .out
    lea  rsi, [rbx + blk_info.unit]
    mov  edx, 4
    call exf_src_meta_span
    test rax, rax
    jnz  .out
    lea  rsi, [rbx + blk_info.lba_max]
    mov  edx, 8
    call exf_src_meta_span
    test rax, rax
    jnz  .out
    lea  rsi, [rbx + blk_info.logical_sector_bytes]
    mov  edx, blk_info_size - blk_info.logical_sector_bytes
    call exf_src_meta_span
    test rax, rax
    jnz  .out
    mov  rsi, [r12 + exf_ctx.upcase]
    mov  edx, EXF_UPCASE_MAX
    call exf_src_meta_span
    jmp  .out
.bad:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret
exf_src_meta_span:
    push rdx
    mov  rdi, r13
    test r14d, r14d
    jz   .compare
    call memcpy
    xor  eax, eax
    jmp  .done
.compare:
    call memcmp
.done:
    pop  rdx
    add  r13, rdx
    ret

exfat_disk_source_bind:
    mov  [rel exf_src_mount], rdi
    call exfat_disk_source_token
    test rax, rax
    jnz  .out
    call exfat_disk_source_current
.out:
    ret

; Pure token, preserving every register except RAX, including argument registers
; used by native multi-transfer and fallback loops.
exfat_disk_source_token:
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
    mov  rdi, [rel exf_src_mount]
    test rdi, rdi
    jz   .bad
    call exfat_disk_source_device
    test rax, rax
    jz   .bad
    cmp  dword [rel exf_w_active], 0
    jne  .bad
    cmp  dword [rel exf_t_active], 0
    jne  .bad
    mov  r12, [rdi + fsmount.priv]
    lea  rdi, [rel exf_src_metadata]
    cmp  r12, [rel exf_src_contexts]
    je   .check
    add  rdi, EXF_SRC_META_BYTES
.check:
    xor  ecx, ecx
    call exf_src_metadata_check
    jmp  .out
.bad:
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
exf_src_guard:
    cmp  qword [rel exf_src_reading], 0
    je   .ok
    call exfat_disk_source_token
    test rax, rax
    jnz  .out
    push rax
    mov  rax, [rel exf_src_mount]
    mov  rax, [rax + fsmount.priv]
    cmp  rdi, [rax + exf_ctx.dev]
    pop  rax
    jne  .bad
.ok:
    xor  eax, eax
.out:
    ret
.bad:
    mov  rax, -1
    ret
exf_src_block_read:
    call exf_src_guard
    test rax, rax
    jnz  .out
    cmp  qword [rel exf_src_reading], 0
    je   .read
    cmp  qword [rel exf_src_budget], 0
    je   .bad
    dec  qword [rel exf_src_budget]
.read:
    push rdi
    call blk_read
    pop  rdi
    push rax
    call exf_src_guard
    test rax, rax
    pop  rax
    jz   .out
.bad:
    mov  rax, -1
.out:
    ret
exf_src_enter:
    cmp  qword [rel exf_src_reading], 0
    jne  .nested
    mov  qword [rel exf_src_budget], 8192
.nested:
    mov  qword [rel exf_src_reading], 1
    ret

; Fresh mounted boot identity, not a display volume identifier. Every physical
; transfer, including a failed multi-read and its fallback, has pure guards.
exfat_disk_source_current:
    push r12
    push qword [rel exf_src_reading]
    call exf_src_enter
    call exfat_disk_source_token
    test rax, rax
    jnz  .bad
    mov  rax, [rel exf_src_mount]
    mov  r12, [rax + fsmount.priv]
    mov  rdi, [r12 + exf_ctx.dev]
    mov  rsi, [r12 + exf_ctx.part_lba]
    mov  edx, 1
    lea  rcx, [rel exf_src_vbr]
    call exf_raw_read
    test rax, rax
    jnz  .bad
    lea  rdi, [r12 + exf_ctx.boot_identity]
    lea  rsi, [rel exf_src_vbr]
    mov  edx, 120
    call memcmp
    test rax, rax
    jnz  .bad
    call exfat_disk_source_token
    jmp  .out
.bad:
    mov  rax, -1
.out:
    pop  qword [rel exf_src_reading]
    pop  r12
    ret

; Ordered full parent stream, physical entry location/count, all entry-set
; bytes, and every FAT link traversed by resolution. Exact bytes, no hashes or
; truncated identities. Hook is inert for all ordinary reader/writer calls.
; RSI=bytes, EDX=len -> RAX=0/-1, only argument registers may change.
exf_src_trace:
    mov  rax, [rel exf_src_cursor]
    add  rax, rdx
    jc   .bad
    mov  rdi, [rel exf_src_trace_target]
    test rdi, rdi
    jz   .ordinary
    cmp  rax, EXF_COPY_TRACE_MAX
    ja   .bad
    jmp  .bounded
.ordinary:
    cmp  rax, EXF_SRC_TRACE_MAX
    ja   .bad
.bounded:
    cmp  dword [rel exf_src_binding], 0
    jne  .save
    cmp  rax, [rel exf_src_length]
    ja   .bad
.save:
    push rax
    mov  rdi, [rel exf_src_trace_target]
    test rdi, rdi
    jnz  .target
    lea  rdi, [rel exf_src_trace_buf]
.target:
    add  rdi, [rel exf_src_cursor]
    cmp  dword [rel exf_src_binding], 0
    je   .compare
    call memcpy
    xor  eax, eax
    jmp  .done
.compare:
    call memcmp
.done:
    pop  rdx
    mov  [rel exf_src_cursor], rdx
    ret
.bad:
    mov  rax, -1
    ret
exf_src_link:
    cmp  dword [rel exf_src_resolving], 0
    je   .out
    push rax
    push rdi
    push rsi
    push rdx
    push rcx
    inc  dword [rel exf_src_links]
    cmp  dword [rel exf_src_links], 4096
    ja   .bad
    mov  [rel exf_src_link_pair], r13d
    mov  [rel exf_src_link_pair + 4], eax
    lea  rsi, [rel exf_src_link_pair]
    mov  edx, 8
    call exf_src_trace
    test rax, rax
    jnz  .bad
    pop  rcx
    pop  rdx
    pop  rsi
    pop  rdi
    pop  rax
.out:
    ret
.bad:
    pop  rcx
    pop  rdx
    pop  rsi
    pop  rdi
    add  rsp, 8
    mov  rax, -1
    ret
exf_src_component:
    cmp  dword [rel exf_src_resolving], 0
    je   .ok
    inc  dword [rel exf_src_components]
    cmp  dword [rel exf_src_components], 32
    ja   .bad
    test dword [r12 + exf_ctx.leaf + exf_strm.attr], ~0x37
    jnz  .bad
    test dword [r12 + exf_ctx.leaf + exf_strm.flags], ~3
    jnz  .bad
    lea  rsi, [r12 + exf_ctx.dir]
    mov  edx, exf_strm_size
    call exf_src_trace
    test rax, rax
    jnz  .bad
    lea  rsi, [rel exf_set_location]
    mov  edx, 8
    call exf_src_trace
    test rax, rax
    jnz  .bad
    lea  rsi, [rel exf_set_count]
    mov  edx, 4
    call exf_src_trace
    test rax, rax
    jnz  .bad
    mov  edx, [rel exf_set_count]
    inc  edx
    shl  edx, 5
    lea  rsi, [rel exf_set_buf]
    call exf_src_trace
    ret
.ok:
    xor  eax, eax
    ret
.bad:
    mov  rax, -1
    ret

; RSI/EDX=path, ECX=bind(1)/compare(0) -> logical size / -1.
exfat_disk_source_stat:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push qword [rel exf_src_reading]
    call exf_src_enter
    mov  r13, rsi
    mov  r14d, edx
    mov  r15d, ecx
    call exfat_disk_source_current
    test rax, rax
    jnz  .bad
    mov  rax, [rel exf_src_mount]
    mov  r12, [rax + fsmount.priv]
    mov  qword [r12 + exf_ctx.sec_tag], -1
    mov  qword [r12 + exf_ctx.fat_tag], -1
    mov  qword [rel exf_src_cursor], 0
    mov  dword [rel exf_src_links], 0
    mov  dword [rel exf_src_components], 0
    mov  [rel exf_src_binding], r15d
    mov  dword [rel exf_src_resolving], 1
    mov  rsi, r13
    mov  edx, r14d
    call exf_resolve
    mov  dword [rel exf_src_resolving], 0
    test rax, rax
    jnz  .bad
    test dword [r12 + exf_ctx.leaf + exf_strm.attr], EXF_ATTR_DIR
    jnz  .bad
    cmp  dword [rel exf_src_components], 0
    je   .bad
    mov  rax, [rel exf_src_cursor]
    test r15d, r15d
    jz   .compare
    mov  [rel exf_src_length], rax
    mov  ecx, [rel exf_leaf_mt_ts]       ; E2t: the bound file's modification time (the leaf just decoded)
    mov  [rel exf_src_mt_ts], ecx
    mov  cl, [rel exf_leaf_mt_ms]
    mov  [rel exf_src_mt_ms], cl
    mov  cl, [rel exf_leaf_mt_utc]
    mov  [rel exf_src_mt_utc], cl
    jmp  .token
.compare:
    cmp  rax, [rel exf_src_length]
    jne  .bad
.token:
    call exfat_disk_source_token
    test rax, rax
    jnz  .bad
    mov  rax, [r12 + exf_ctx.leaf + exf_strm.length]
    jmp  .out
.bad:
    mov  rax, -1
.out:
    pop  qword [rel exf_src_reading]
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Bounded copy stat: RSI/EDX=path, R8=1024B identity -> size/-1.
; Reuse the ORIGINAL complete ordered resolver transcript, with a separate
; caller-owned slot for each file. Overflow refuses, never truncates. Restore
; the ordinary source adapter's retained length/target on every outcome.
EXF_COPY_TRACE_MAX equ 1016
exfat_disk_copy_stat:
    push rbx
    push qword [rel exf_src_trace_target]
    push qword [rel exf_src_length]
    mov  rbx, r8
    lea  rax, [r8 + 8]
    mov  [rel exf_src_trace_target], rax
    mov  ecx, 1
    call exfat_disk_source_stat
    test rax, rax
    js   .out
    mov  rdx, [rel exf_src_length]
    mov  [rbx], rdx
.out:
    pop  qword [rel exf_src_length]
    pop  qword [rel exf_src_trace_target]
    pop  rbx
    ret

; exfat_disk_source_mtime -> RAX = the bound source file's modification time as Unix UTC seconds, EDX =
;   nanoseconds; CF=1 unknown (no stamp, a field out of range, a 10 ms increment past 199, or local time
;   with no PaOS clock zone). E2t (root 2026-10-17 21:04:41). The File entry's LastModified timestamp
;   (DOS packing) + 10 ms increment; its UtcOffset when OffsetValid (bit 7; bits 0-6 signed 15-minute
;   units), else local time in the PaOS clock zone. Clobbers RCX, RDX, RSI, R8-R11.
exfat_disk_source_mtime:
    mov  eax, [rel exf_src_mt_ts]
    call vfs_dos_to_unix
    test rax, rax
    jz   .unknown
    movzx ecx, byte [rel exf_src_mt_ms]
    cmp  ecx, 199
    ja   .unknown
    push rax
    mov  eax, ecx
    xor  edx, edx
    mov  ecx, 100
    div  ecx                             ; EAX = a whole second more, EDX = 10 ms units
    imul edx, edx, 10000000
    mov  ecx, eax
    pop  rax
    add  rax, rcx
    push rdx                             ; nanoseconds
    movzx ecx, byte [rel exf_src_mt_utc]
    test cl, 0x80
    jz   .zone
    shl  ecx, 25
    sar  ecx, 25                         ; bits 0-6, signed
    imul ecx, ecx, 900                   ; 15-minute units -> seconds east of UTC
    movsxd rcx, ecx
    sub  rax, rcx
    pop  rdx
    clc
    ret
.zone:
    call time_local_to_utc
    pop  rdx
    jc   .unknown
    test rax, rax
    jle  .unknown                        ; an exFAT date is never at or before 1970
    ret
.unknown:
    stc
    ret

; Native read_at_path ABI; resolve identity immediately before and after the
; actual native logical read, including its VDL zero tail and verification.
exfat_disk_source_read:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push qword [rel exf_src_reading]
    call exf_src_enter
    mov  rbx, rsi
    mov  r13d, edx
    mov  r14, rcx
    mov  r15, r8
    push r9
    xor  ecx, ecx
    call exfat_disk_source_stat
    cmp  rax, -1
    je   .pre_bad
    mov  rax, [rel exf_src_mount]
    mov  r12, [rax + fsmount.priv]
    mov  rsi, r14
    mov  rdx, r15
    mov  rcx, [rsp]
    call exf_file_read
    push rax
    mov  rsi, rbx
    mov  edx, r13d
    xor  ecx, ecx
    call exfat_disk_source_stat
    cmp  rax, -1
    pop  rax
    jne  .out
.pre_bad:
    mov  rax, -2
.out:
    add  rsp, 8
    pop  qword [rel exf_src_reading]
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

exf_src_ranges:
    dd exf_ctx.dev, 64
    dd exf_ctx.fat_buf, 8
    dd exf_ctx.name, 8
    dd exf_ctx.clus_count, exf_ctx.dir - exf_ctx.clus_count
    dd exf_ctx.incarnation, 8
EXF_SRC_RANGES equ ($ - exf_src_ranges) / 8
%macro WDATA_fs_exfat_copy_source_bss 0
exf_src_contexts: resq EXF_MAX_MOUNTS
exf_src_metadata: resb EXF_MAX_MOUNTS * EXF_SRC_META_BYTES
exf_src_mount: resq 1
exf_src_reading: resq 1
exf_src_budget: resq 1
exf_src_cursor: resq 1
exf_src_length: resq 1
exf_src_binding: resd 1
exf_leaf_mt_ts: resd 1                   ; E2t: the last decoded File entry's LastModified timestamp,
exf_src_mt_ts: resd 1                    ;   and the bound source's
exf_leaf_mt_ms: resb 1
exf_leaf_mt_utc: resb 1
exf_src_mt_ms: resb 1
exf_src_mt_utc: resb 1
exf_src_resolving: resd 1
exf_src_links: resd 1
exf_src_components: resd 1
exf_src_link_pair: resb 8
exf_src_vbr: resb 512
exf_src_trace_target: resq 1
exf_src_trace_buf: resb EXF_SRC_TRACE_MAX
%endmacro
WDATA_BSS_DEFER WDATA_fs_exfat_copy_source_bss

; Read-only image capability query. No mount, media IO or authority change.
exfat_disk_format_ops:
    lea  rax, [rel exf_ops]
    ret

; Bounded observations of actual discovery refusals, not authority or a rescan.
; Each 56-byte record: dev*, LBA, extent, original generation, info*, ops*, reason.
EXF_REFUSAL_MAX equ 16
exfat_refusal_reset:
    mov dword [rel exfat_refusal_count],0
    mov byte [rel exfat_refusal_overflow],0
    ; Discovery skips extended containers and stops at bounded mount/GPT limits.
    ; No value from this cache, including a miss, certifies filesystem absence.
    mov byte [rel exfat_refusal_scan_limited],1
    inc qword [rel exfat_refusal_epoch]
    jnz .epoch
    mov byte [rel exfat_refusal_epoch_wrapped],1
.epoch:
    mov al,[rel exfat_refusal_epoch_wrapped]
    mov [rel exfat_refusal_conflict],al    ; wrap remains poisoned until reboot
    ret

; RDI actual dev, RSI LBA, EDX reason, RCX extent, R8 -> original info/ops/gen.
; Caller-volatile scratch only; preserves RDI/RSI/RDX for the existing serial rail.
; No IO, allocation, context pointer retention, mount or writer state change.
exfat_refusal_record:
    test rdi,rdi
    jz .invalid
    test r8,r8
    jz .invalid
    test rcx,rcx
    jz .invalid
    test edx,edx
    jz .invalid
    cmp edx,EXF_R_NOMOUNT
    ja .invalid
    cmp qword [r8],0
    je .invalid
    cmp qword [r8+8],0
    je .invalid
    cmp qword [r8+16],0
    je .invalid
    lea r9,[rel exfat_refusal_records]
    xor r10d,r10d
.find:
    cmp r10d,[rel exfat_refusal_count]
    jae .append
    cmp r10d,EXF_REFUSAL_MAX
    jae .full
    cmp [r9],rdi
    jne .next
    cmp [r9+8],rsi
    jne .next
    cmp [r9+16],rcx
    jne .invalid
    mov r11,[r8+16]
    cmp [r9+24],r11
    jne .invalid
    mov r11,[r8]
    cmp [r9+32],r11
    jne .invalid
    mov r11,[r8+8]
    cmp [r9+40],r11
    jne .invalid
    cmp [r9+48],edx
    jne .invalid
    ret
.next:
    add r9,56
    inc r10d
    jmp .find
.append:
    cmp r10d,EXF_REFUSAL_MAX
    jae .full
    mov [r9],rdi
    mov [r9+8],rsi
    mov [r9+16],rcx
    mov r11,[r8+16]
    mov [r9+24],r11
    mov r11,[r8]
    mov [r9+32],r11
    mov r11,[r8+8]
    mov [r9+40],r11
    mov [r9+48],edx
    mov dword [r9+52],0
    inc dword [rel exfat_refusal_count]
    ret
.full:
    mov byte [rel exfat_refusal_overflow],1
    ret
.invalid:
    mov byte [rel exfat_refusal_conflict],1
    ret

; RDI actual dev, RSI exact LBA -> RAX original record or zero. Never refreshes.
exfat_refusal_lookup:
    lea rax,[rel exfat_refusal_records]
    xor ecx,ecx
.next:
    cmp ecx,[rel exfat_refusal_count]
    jae .missing
    cmp ecx,EXF_REFUSAL_MAX
    jae .missing
    cmp [rax],rdi
    jne .advance
    cmp [rax+8],rsi
    je .done
.advance:
    add rax,56
    inc ecx
    jmp .next
.missing:
    xor eax,eax
.done:
    ret

%macro WDATA_BSS_exfat_refusal 0
alignb 8
exfat_refusal_epoch: resq 1
exfat_refusal_count: resd 1
exfat_refusal_overflow: resb 1
exfat_refusal_conflict: resb 1
exfat_refusal_epoch_wrapped: resb 1
exfat_refusal_scan_limited: resb 1
exfat_refusal_records: resb EXF_REFUSAL_MAX*56
%endmacro
WDATA_BSS_DEFER WDATA_BSS_exfat_refusal
