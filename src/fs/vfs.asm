;; MODULE fs/vfs
;; LAYER 4
;; EXPORTS vfs_info_facts, vfs_register_guest_source, vfs_register_guest_esp, vfs_open_guest_source, vfs_open_guest_esp, vfs_guest_pair_state, vfs_guest_source_hint, vfs_copy_partial_snapshot, vfs_copy_partial_ready, vfs_builtin_census, vfs_mount_usage, vfs_select_fat_ro_exact, vfs_select_ntfs_exact, vfs_write_generation, vfs_copy_busy, vfs_dirent_name, vfs_dirent_set_long_name, vfs_selftest, vfs_init, vfs_register_mount, vfs_mount_ptr, vfs_writefile, vfs_update, vfs_rename, vfs_readfile, vfs_delete, vfs_stat, vfs_read_at, vfs_info, vfs_list_root, vfs_path_to_name11, vfs_path_stat, vfs_readfile_path, vfs_write_at, vfs_select_disk_by_name, vfs_stat_path, vfs_read_at_path, vfs_write_at_path, vfs_list_dir, vfs_mutate_path, vfs_copy_start, vfs_copy_start_mode, vfs_copy_enqueue, vfs_copy_tick, vfs_copy_cancel, vfs_copy_status, vfs_copy_note_recovery, vfs_copy_recovery, vfs_copy_refusal, vfs_copy_stamp_hook, vfs_copy_session_sweep, vfs_copy_dropped_status, vfs_file_extents, vfs_file_extents_current, vfs_open_boot_esp, vfs_copy_start_between, vfs_ntfs_selection_state, vfs_copy_snapshot, vfs_copy_current, vfs_copy_item_note, vfs_copy_paths, vfs_copy_progress, vfs_copy_fail_note, vfs_copy_begin_failure, vfs_copy_source_note, vfs_copy_fail_entry, vfs_copy_check, vfs_copy_check_issue, vfs_check, vfs_list_skip, vfs_copy_scan, vfs_copy_scan_issue, vfs_copy_wait_note, vfs_copy_wait_entry, vfs_copy_answer, vfs_copy_policy_ptr, vfs_copy_differs, vfs_ask_job, vfs_ask_phase, vfs_ask_answer, vfs_ask_n, vfs_dos_to_unix, vfs_mtime_older
;; IMPORTS boot/serial, boot/header, boot/nvram_access, core/lib/mem, core/lib/fmt, core/lib/sha256, core/heap, fs/blockdev, fs/fat32_disk, fs/ntfs_disk, fs/ext4_disk, fs/data_crypto_store, fs/guest_volume, fs/vfs_copy_service, fs/fs_format
;; CAPS
;; OWNER saga:vfs_fat_seam
; ============================================================================
; fs/vfs.asm — C8 VFS BACKEND-CLASS SEAM (the filesystem driver-class vtable) +
; a real, RAM-backed FAT32 backend proving SAFE-WRITE (temp-then-swap atomic
; flush), + a degenerate 2nd backend (a read-only mock, mount "c8-ro-mock"; it
; reads no filesystem and credits none) to exercise the backend selector. CONTRACT_LADDER C8 (vfs_fat_seam).
;
; THE SEAM (driver-class, like blk_ops/netdev_ops in driver_classes.inc): a
; filesystem backend is a `fs_ops` vtable. stat/read_at are additive tail slots:
; every legacy slot keeps its original offset and every streaming consumer uses
; the same mount handle rather than importing a filesystem implementation.
; The VFS keeps a mount table of `fsmount` {ops,priv,name} and dispatches EVERY
; op through mount[idx].ops — the SAME table + selector for both backends, no
; duplicate per-backend logic (trap #3). mount[0]=fat32 (rw), mount[1]=c8-ro-mock
; (the mock; the real read-only exFAT backend is fs/exfat_disk, "exfat0"). Adding a 3rd filesystem is one fs_ops table + one mount row.
;
; SAFE-WRITE (temp-then-swap, the proven defense vs mid-write corruption — ESP
; incidents v0.3.538/v0.7.749, ESSENCE §2/§6): fat32_writefile
;   (1) allocates a FRESH cluster and writes the payload there (old data untouched)
;   (2) adds a TEMP dir entry (~TMPSWAP) pointing at the fresh cluster
;   (3) VERIFIES the temp reads back byte-equal (abort => old file still intact)
;   (4) frees the OLD file's clusters + tombstones its dir entry
;   (5) ATOMIC RENAME: writes ONLY the 11-byte 8.3 name field of the temp entry
;       (a single 11-byte write, NOT a read-modify-write of the 32-byte slot —
;       trap #1, ESSENCE §6). A crash before (5) leaves the old file winning and
;       an orphan ~TMPSWAP (cross-reboot orphan sweep = post-NIC follow-up, §2).
; Both FATs are mirrored on every FAT mutation (fat_set writes FAT1 AND FAT2 —
; trap #7; a FAT1-only write is the whole-volume-corruption signature).
;
; CONTENT-GRADE (trap #4, "the instrument you control is lying"): the readback
; marker fires ONLY after a runtime memcmp of the 256-byte read vs the written
; pattern returns 0. A "write succeeded" marker is never emitted on its own.
;
; SCOPE (honest): RAM-backed volume (kmalloc), single-cluster files (payload
; <= 512 B; the 256-byte selftest fits). Structurally FAT32 (32-bit FAT entries,
; BPB_FATSz32, RootClus, 8.3 dir entries) but SMALL — 256 data clusters, below
; the >=65525-cluster threshold a strict host driver uses to distinguish FAT32
; from FAT16. Our own reader/writer is authoritative here; host-mountability +
; multi-cluster/fragmented temp-files + bare-metal USB round-trip are the
; declared post-NIC follow-ups (contract done_when + decompose_note 1008b).
;
; QEMU is a STRUCTURAL smoke test: it proves the seam dispatch, the FAT layout
; math, the temp-then-swap ordering, and byte-equal content grading. Real media
; timing/coherency is bare-metal-pending (contract target: qemu_only).
; ============================================================================

; ---- FAT32 geometry (RAM volume) -------------------------------------------
VFS_BPS        equ 512                              ; bytes/sector
VFS_SPC        equ 1                                ; sectors/cluster (1 => 512-B cluster)
VFS_RSVD       equ 32                               ; reserved sectors (BPB region)
VFS_NFATS      equ 2                                ; FAT1 + FAT2 (mirrored)
VFS_DCLUS      equ 256                              ; data clusters
VFS_FATSZ      equ 3                                ; sectors/FAT ((256+2)*4=1032 -> 3 sec)
VFS_FAT1       equ VFS_RSVD                         ; FAT1 start sector (32)
VFS_FAT2       equ VFS_RSVD + VFS_FATSZ             ; FAT2 start sector (35)
VFS_DATA       equ VFS_RSVD + VFS_NFATS*VFS_FATSZ   ; data region start sector (38)
VFS_TOTSEC     equ VFS_DATA + VFS_DCLUS             ; total sectors (294)
VFS_VOLBYTES   equ VFS_TOTSEC * VFS_BPS             ; volume size (150528 B, kmalloc)
VFS_ROOTCLUS   equ 2                                ; root dir cluster (FAT32 canon)
VFS_MAXCLUS    equ VFS_ROOTCLUS + VFS_DCLUS         ; one past last valid cluster (258)
FAT_EOC        equ 0x0FFFFFFF                       ; end-of-chain
FAT_EOC_MIN    equ 0x0FFFFFF8                       ; >= this => end-of-chain

; ---- 8.3 directory entry (32 bytes) ----------------------------------------
DE_NAME        equ 0                                ; 11-byte 8.3 name
DE_ATTR        equ 11
DE_CLUSHI      equ 20
DE_CLUSLO      equ 26
DE_SIZE        equ 28                               ; dword file size
DE_STRIDE      equ 32
DE_PER_CLUS    equ (VFS_BPS / DE_STRIDE)            ; 16 entries in the 512-B root cluster
ATTR_ARCHIVE   equ 0x20
DE_FREE        equ 0x00                             ; slot never used (end of dir)
DE_DELETED     equ 0xE5                             ; tombstone

; ---- the backend-class vtable seam -----------------------------------------
struc fs_ops
  .name:      resq 1   ; -> ASCII backend name
  .mount:     resq 1   ; (self)                         -> RAX 0/-1
  .readfile:  resq 1   ; (self,RSI=name11,RDX=buf,RCX=cap) -> RAX len / -1 ENOENT
  .writefile: resq 1   ; (self,RSI=name11,RDX=buf,RCX=len) -> RAX clus / -1 (temp-then-swap)
  .delete:    resq 1   ; (self,RSI=name11)              -> RAX 0/-1
  .stat:      resq 1   ; (self,RSI=name11,RDX=fs_stat*) -> RAX 0/-1
  .read_at:   resq 1   ; (self,RSI=name11,RDX=off,RCX=buf,R8=len) -> RAX len/-1
  .info:      resq 1   ; (self,RSI=fs_info*) -> RAX 0/-1
  .list_root: resq 1   ; (self,RSI=entries,EDX=cap,RCX=result) -> RAX 0/-1
  .write_at:  resq 1   ; (self,RSI=name11,RDX=off,RCX=buf,R8=len) -> RAX len/-1 — additive tail slot
                       ;   (2026-09-07 NTFS): IN-PLACE overwrite inside an existing file's allocated,
                       ;   initialized extents; 0 = backend has no such op (vfs_write_at returns -1)
  .stat_path:     resq 1 ; (self,RSI=path,EDX=len,RCX=fs_stat*) -> RAX 0/-1              — v1.1 PATHS (additive tail,
  .read_at_path:  resq 1 ; (self,RSI=path,EDX=len,RCX=off,R8=buf,R9=len) -> RAX len/-1    2026-09-07): "/DIR/SUB/FILE"
  .write_at_path: resq 1 ; (self,RSI=path,EDX=len,RCX=off,R8=buf,R9=len) -> RAX len/-1    resolved by the backend;
  .list_dir:      resq 1 ; (self,RSI=path,EDX=len,RCX=entries,R8D=cap,R9=result) -> 0/-1  0 = not provided (-1)
  .update:        resq 1 ; (self,RSI=name11,RDX=buf,RCX=len) -> 0/-1; durable replacement
  .rename:        resq 1 ; (self,RSI=old11,RDX=new11) -> 0/-1; refuses existing destination
  .mutate_path:   resq 1 ; (self,RSI=absolute Z path,RDX=data/new Z path,RCX=len,R8D=op)
  .copy:          resq 1 ; (self,RSI=src Z path,RDX=dst Z path,ECX=FS_COPY_*,R8=fs_copy_job*) -> 0/-1;
                         ;   RCQ-20 additive tail: one bounded streaming job, stepped by vfs_copy_tick
  .mutate_armed:  resq 1 ; (self) -> RAX 1 = this mount accepts .mutate_path NOW (an owner-armed write
                         ;   authority, e.g. ext4 via FSARM); anything else = no. RCQ-20 additive tail, a pure
                         ;   state read (no IO). 0 = never: FAT keeps its exact DATA gate; NTFS/RAM leave it 0.
  .file_extents:  resq 1 ; (self,RSI=path,EDX=len,RCX=fs_extent_map*,R8D=cap) -> RAX extents / -1. RCQ-38 G3
                         ;   additive tail, read-only; 0 = not provided (vfs_file_extents -1: the slow path)
  .extent_check:  resq 1 ; (self,RSI=fs_extent_map*) -> EAX 0 same mount and generation / 1 only the
                         ;   generation moved / -1 another mount, device, volume or medium. A pure state read.
  .copy_between:  resq 1 ; additive tail: BEGIN destination self, R10=explicit source fsmount; STEP/CANCEL via .copy
  .replace_meta:  resq 1 ; (self,RSI=path,EDX=len,RCX=fs_replace_meta*) -> 0/-1; readonly facts, no arm/BEGIN
endstruc

FS_MUT_CREATE equ 0
FS_MUT_DELETE equ 1
FS_MUT_UPDATE equ 2
FS_MUT_RENAME equ 3
FS_MUT_MKDIR  equ 4
FS_MUT_RMDIR  equ 5

FS_COPY_BEGIN  equ 0
FS_COPY_STEP   equ 1
FS_COPY_CANCEL equ 2
FS_COPY_BEGIN_CARRIED equ 3   ; RCQ-20 S5c: the dequeue's BEGIN of a queued ext4 job, under its carry (.carry)

; The single copy job. The backend fills done/total/state/error; the VFS owns id
; and mount, so a refused FSCOPY never disturbs the previous job's report.
; RCQ-20 S1 (additive tail): a successful BEGIN also fills .dev (the block device
; the job writes) and .preserved (what this format keeps, FS_PRES_*). The VFS
; stamps .t_start/.t_end (boot ms) and judges .durable when the job ends DONE
; (a job reaches DONE only after its flushes returned 0): 1 only when the device
; declares BLKCAP_FLUSH, unverified when it declares no mask. A backend whose
; commit landed behind a failed barrier reports uncertain itself, before DONE.
struc fs_copy_job
  .id:    resq 1
  .done:  resq 1
  .total: resq 1          ; FS_TOTAL_UNKNOWN until a backend knows it
  .state: resd 1
  .error: resd 1          ; backend error recorded when the job fails
  .mount: resd 1
  .flush_fails: resd 1   ; blk_flush_failures (low dword) at BEGIN
  .t_start:   resq 1
  .t_end:     resq 1
  .dev:       resq 1
  .durable:   resd 1      ; FS_DUR_*
  .preserved: resd 1      ; FS_PRES_*
  .kept:      resd 1      ; RCQ-20 S4: 0 a refuse job; keep-both: 1 the requested name, 2..9 the k-th
  .pos:       resd 1      ; RCQ-20 S5a: a queued job's place, 1 = next to run (0 otherwise)
  .queued:    resd 1      ; S5a, vfs_copy_job only: how many jobs wait behind it (vfs_copy_busy reads it)
  .reason:    resq 1      ; S5a: set when a queued job ended at its deferred BEGIN: the stamp hook's reason
  .carry:     resq 1      ; S5c, vfs_copy_job only: -> the carry of the queued ext4 job being begun (one writer,
                          ;   vfs_copy_dequeue; ext_w_job_open_carried clears it before any check)
  .tree:      resd 1      ; RCQ-20 S5b: 1 a tree job (FS_COPY_TREE); .done/.total then count the whole tree
  .files:     resd 1      ; S5b: files committed so far (only after each file's commit)
  .skipped:   resd 1      ; S5b: entries the walk did not copy, each counted (never silently)
  .paused:    resd 1      ; smart copy A (spec 7.5.1 #6): 1 while FSPAUSE holds the live job (vfs_copy_pause)
  .paused_at: resq 1      ; boot ms of that FSPAUSE; ELAPSED_MS/RATE_BPS count copying time only
  .failed:    resd 1      ; smart copy B (spec 7.5.1 #3): tree entries not copied, each recorded (vfs_copy_fail_note)
  .fail_run:  resd 1      ; B: operational failures since the tree's last commit; FS_FAIL_RUN of them end the job
  .same:      resd 1      ; smart copy C (FS_CMODE_SKIPSAME): destination files found equal and left alone
  .replaced:  resd 1      ; E2r-b (FS_CMODE_REPLACE): destination files replaced (each counted at its swap)
endstruc

; Read-only scalar projection. No paths, device/context/reason/carry pointers or
; mutable aliases leave retention through vfs_copy_snapshot. Existing ABI stays fixed.
struc fs_copy_view
  .id:        resq 1
  .done:      resq 1
  .total:     resq 1
  .state:     resd 1
  .error:     resd 1
  .durable:   resd 1
  .pos:       resd 1
  .tree:      resd 1
  .files:     resd 1
  .skipped:   resd 1
  .origin:    resd 1   ; 0 current/latest, 1 queued, 2 cancelled queue, 3 dropped
  .preserved: resd 1
  .kept:      resd 1
  .reserved:  resq 2   ; always zero, snapshot size 80 bytes
endstruc
; E4: a separate scalar accessor; fs_copy_job/fs_copy_view retain their layouts.
; Totals are observations of the original source scan, not a promise against later
; source mutation. Unknown = -1. Files exclude directories; .files_done commits only.
struc fs_copy_progress
  .id:          resq 1
  .bytes_done:  resq 1
  .bytes_total: resq 1
  .files_done:  resq 1
  .files_total: resq 1
  .elapsed_ms:  resq 1
  .rate_bps:    resq 1
  .eta_ms:      resq 1
  .problems:    resd 1
  .scan:        resd 1
  .state:       resd 1
  .reserved:    resd 1
endstruc
FS_COPY_RETAIN_MAX equ 2 + 2 * FS_QUEUE_MAX ; descriptive only; bounded RAM, not history

; E4: requested endpoints, not current-file or final keep-both names. No aliases.
; Per-field flags distinguish unavailable/overlong paths from a known empty path.
FS_COPY_PATH_CAP equ 256
FS_COPY_PATH_SRC equ 1
FS_COPY_PATH_DST equ 2
struc fs_copy_paths
  .id:        resq 1
  .src_mount: resd 1
  .dst_mount: resd 1
  .known:     resd 1
  .src_len:   resd 1
  .dst_len:   resd 1
  .reserved:  resd 1
  .src:       resb FS_COPY_PATH_CAP
  .dst:       resb FS_COPY_PATH_CAP
endstruc

; E4 current source basename, independently versioned from endpoints/progress.
; known=1 only while a real backend is processing this file; unknown has len0.
struc fs_copy_item
  .id:       resq 1
  .known:    resd 1
  .len:      resd 1
  .reserved: resq 2
  .name:     resb FS_COPY_PATH_CAP
endstruc

FS_TOTAL_UNKNOWN  equ -1
FS_RATE_UNKNOWN   equ -1      ; RCQ-21: vfs_copy_rate without elapsed time
FS_PACE_SAMPLES   equ 8       ; E4: fixed recent active-time observations, no heap
FS_PACE_STEP_MS   equ 250
FS_PACE_MIN_MS    equ 1000
struc fs_copy_pace_sample
  .elapsed: resq 1
  .bytes:   resq 1
  .files:   resq 1
endstruc
FS_DUR_NO         equ 0    ; not completed
FS_DUR_YES        equ 1
FS_DUR_UNVERIFIED equ 2    ; flushed, but the device declares no FLUSH capability
FS_DUR_UNCERTAIN  equ 3    ; the commit landed but its flush failed
FS_PRES_NONE      equ 0
FS_PRES_FAT       equ 1    ; data, size, mtime (E2t; 8.3 name; attributes, other times not kept)
FS_PRES_EXT4      equ 2    ; data, size, mode, holes, mtime (E2t; owner, other times not kept)
; RCQ-20 S4 conflict policy, R9D of a BEGIN. An existing destination: refuse = EXISTS;
; keepboth = the first free k-th name (k 2..FS_KEPT_MAX), picked before any write.
FS_CMODE_REFUSE   equ 0
FS_CMODE_KEEPBOTH equ 1
; Smart copy C (spec 7.5.1 #4, "copying again acts as a fast sync"): a flag beside the bit above. An existing
; destination FILE of the source's size is compared first (read-only) and, when equal, skipped (SKIPPED_SAME);
; a tree merges into an existing destination DIRECTORY. Any other conflict follows the bit above, decided up front.
FS_CMODE_SKIPSAME equ 2
FS_KEPT_MAX       equ 9
; RCQ-20 S5b: R9D's tree flag beside FS_CMODE_*: copy a source DIRECTORY into a new directory, as one job.
; The conflict policy then names the top directory only; nothing inside a new directory can conflict.
FS_COPY_TREE      equ 0x100
; Exact FSCOPY PAUSE=1: startup state only, never a backend conflict-policy bit.
FS_COPY_START_PAUSED equ 0x200
; Explicit single-file hold after durable private work, before publication.
FS_COPY_HOLD_PARTIAL equ 0x400
struc fs_copy_partial
 .id: resq 1
 .stage: resq 1 ; 1 armed, 2 ext append held, 3 NT private CREATE held, 4 consumed
 .bytes: resq 1
 .path: resb 256
endstruc
FS_CMODE_MASK     equ 0xFF
; Smart copy E2 (spec 7.5.1 #2, MODE=ask; root 17:23:38): a flag beside the bits above. A tree merges into an
; existing destination directory as SKIPSAME's does, and a name conflict is not decided: the backend hands it to
; the job's WAITING list (vfs_copy_wait_note) and the walk goes on. An answer (vfs_copy_answer) ORs its bits into
; the live policy: SKIPSAME and/or KEEPBOTH as above, or FS_CMODE_SKIP (the conflict is skipped, counted SKIPPED).
; Same-volume BEGINs only (vfs_copy_start_between refuses it). No replace: that is E2r.
FS_CMODE_ASK      equ 4
FS_CMODE_SKIP     equ 8
; Smart copy E2r (replace-older; root 17:23:38, 21:04:41): a flag beside the bits above. A FILE destination whose
; mtime is older than the source's by more than 2 s (vfs_mtime_older, in UTC) is replaced: the copy is built
; beside it and swapped in one journaled step (ext4: rename over in one jbd2 transaction; FAT32: the old entry's
; slot patched, the old chain freed after), so the name reads the old file or the new one at every cut. Newer or
; within 2 s: skipped (counted SKIPPED). A time unknown on either side, or a destination this copy may not
; replace (not a regular file, read-only/system/hidden, a refused flag): never replaced, it waits as an ask item.
; Same-volume BEGINs only, as ASK (vfs_copy_start_between refuses it).
FS_CMODE_REPLACE  equ 16
; E2r-b: beside REPLACE only, from FSANSWER EACH=<item> replace (the user's choice for that one file): the time is
; not compared; the destination is still replaced only when this copy may replace it (else it waits again).
FS_CMODE_FORCE    equ 32
FS_WAIT_MAX       equ 256  ; conflicts one job keeps waiting (RAM); past it the walk holds (too_many_conflicts)
FS_WAIT_SPARE     equ 2    ;   the item that met a full list: once with no answer, once under a skipsame answer
FS_WAIT_PATH      equ 255  ; a longer path cannot wait: listed as a failure, as refuse mode lists it
FS_WK_FILE        equ 1    ; fs_copy_wait.kind: a file whose destination name is taken
FS_WK_DIR         equ 2    ;   a directory whose destination name is not a directory (skip / keepboth)
FS_WK_DIFFERS     equ 3    ;   a file a skipsame answer found different (skip / keepboth)
FS_ASK_WALK       equ 1    ; vfs_ask_phase (0: not an ask job): the backend walks, or copies the one file
FS_ASK_HELD       equ 2    ;   the walk met a full list: no step until an answer releases it
FS_ASK_WAITING    equ 3    ;   the walk is done; unanswered items wait (nothing written)
FS_ASK_CHILD      equ 4    ;   an answered item copies: a child BEGIN under the job's own id
FS_TREE_DEPTH_MAX equ 8    ; directory levels, the source directory included; a deeper one is recorded, not made
; Smart copy B (spec 7.5.1 #3, "one bad file never stops the job"): a tree entry that fails on its own
; (a source it cannot read or accept, its partial already reclaimed) is recorded and the walk goes on.
; A destination, authority, medium or walk failure still ends the job. The job then ends DONE with
; FAILED=<n> (RESULT=partial); FSJOBFAIL lists the recorded source paths for a retry.
FS_FAIL_VFS       equ -1   ; fs_copy_fail.pres only: error is FS_CREF_*, not a backend error
FS_FAIL_MAX       equ 16   ; source paths kept for FSJOBFAIL (FAILED counts on past them)
FS_FAIL_PATH      equ 255  ; a longer path is counted, not listed
FS_FAIL_RUN       equ 16   ; that many failures with no commit between them end the job: not one bad file
struc fs_copy_fail
  .error:  resd 1          ; backend error, or FS_CREF_* when .pres = FS_FAIL_VFS
  .pres:   resd 1          ; FS_PRES_* of this failure, or FS_FAIL_VFS for a VFS refusal
  .len:    resd 1
  .path:   resb FS_FAIL_PATH + 1
endstruc
struc fs_copy_wait         ; E2: one conflict of an ask job (vfs_ask_items)
  .kind:   resd 1          ; FS_WK_*
  .answer: resd 1          ; 0, or this item's own answer (FS_CMODE_SKIP / SKIPSAME / KEEPBOTH bits)
  .slen:   resd 1
  .dlen:   resd 1
  .id:     resd 1          ; this job's number for it (1, 2, ...): FSANSWER EACH= names it, as items leave
  .src:    resb FS_WAIT_PATH + 1
  .dst:    resb FS_WAIT_PATH + 1
endstruc
; Smart copy D (FSCHECK, root 13:43): one read-only check of a copy, before any job (vfs_copy_check)
FS_CHECK_ENTRIES   equ 4096  ; nodes one check visits at most, the top one counted
FS_CHECK_BUDGET_MS equ 2000  ; and milliseconds; past either, the totals are lower bounds
FS_CHECK_PAGE      equ 64    ; directory entries one listing reads (vfs_list_skip passes those before)
FS_CHECK_ISSUES    equ 16    ; issues listed (ISSUES counts on past them)
FS_CHECK_PATH      equ 1024  ; a destination path this long is an issue (no backend makes it)
FS_CHECK_FAT_COMPONENTS equ 16  ; fat32_disk FD_PATH_DEPTH_MAX: a FAT32 tree's dmax (fd_tree_outside)
FS_CHECK_EXT_PART  equ 19    ; ext4_copy: a file is built as <dir>/.paoscopy-<8 hex>, which must fit as well
FS_SCAN_FIRST_ENTRIES equ 256 ; E1 (spec 7.5.1 #1): a tree job's scan, at its BEGIN (nodes, the top counted)
FS_SCAN_FIRST_MS   equ 50    ;   and milliseconds, so a job starts at once on any tree
FS_SCAN_STEP_ENTRIES equ 512 ;   then nodes per copy tick, ahead of the data
FS_SCAN_STEP_MS    equ 20    ;   and milliseconds per tick
FS_SCAN_NONE       equ 0     ; vfs_scan_status: no scan (a file job, or a refused BEGIN)
FS_SCAN_RUNNING    equ 1
FS_SCAN_DONE       equ 2     ;   every node visited: the totals are exact
FS_SCAN_STOPPED    equ 3     ;   it ended early (a listing it could not page, the job ended): lower bounds
FS_CHK_ENTRIES     equ 1     ; fs_check.reason
FS_CHK_BUDGET      equ 2
FS_CHK_EXISTS      equ 1     ; fs_check_issue.kind: refused, the destination exists
FS_CHK_RENAME      equ 2     ;   keep-both: made under the first free "stem (k)" name
FS_CHK_SAME        equ 3     ;   skip-same candidate: equal size, the copy's compare decides
FS_CHK_TOO_BIG     equ 4     ;   past a FAT32 file's 4 GiB - 1
FS_CHK_NAME        equ 5     ;   a name past 255 bytes
FS_CHK_DEEP        equ 6     ;   a directory below the tree's depth limit: nothing below it is made
FS_CHK_PATH        equ 7     ;   a destination path of FS_CHECK_PATH bytes or more
FS_CHK_NODE        equ 8     ;   neither a file nor a directory: never copied
FS_CHK_UNREAD      equ 9     ;   a directory the check could not list
struc fs_check
  .id:       resq 1          ; 1, 2, ... per check (FSCHECK ITEM= names the latest)
  .files:    resq 1
  .dirs:     resq 1          ; the top directory included
  .bytes:    resq 1
  .need:     resq 1          ; destination bytes, see vfs_copy_check
  .free:     resq 1          ; destination free bytes, -1 unknown
  .ms:       resq 1          ; the check's own milliseconds
  .entries:  resd 1          ; nodes visited
  .reason:   resd 1          ; 0 / FS_CHK_ENTRIES / FS_CHK_BUDGET (then .complete = 0)
  .complete: resd 1
  .issues:   resd 1
  .listed:   resd 1
  .same:     resd 1
  .replace:  resd 1          ; eligible taken files with a known older destination
  .skipped:  resd 1          ; taken files known not older
  .conflicts: resd 1         ; undecided files / incompatible kinds (EXISTS issues)
  .replace_policy: resd 1    ; replacement fields are present only for this policy
endstruc
struc fs_check_issue
  .kind:     resd 1
  .len:      resd 1
  .path:     resb FS_FAIL_PATH + 1   ; the source path
endstruc
struc fs_check_frame
  .slen:     resd 1          ; this directory's source path length
  .dlen:     resd 1          ; and destination path length
  .index:    resd 1          ; its next entry
  .merge:    resd 1          ; 1 the destination directory exists (skip-same): each name conflicts
  .ebytes:   resq 1          ; directory entry bytes the copy adds to the destination directory
endstruc
; vfs_copy_refusal: a typed keep-both refusal the backend reports (0 = none)
FS_CREF_UNREPRESENTABLE equ 1  ; no k-th name the backend can represent
FS_CREF_EXHAUSTED       equ 2  ; every k-th name 2..FS_KEPT_MAX is taken
FS_CREF_MOUNT_CHANGED   equ 3   ; RCQ-20 S5a: a queued job's mount is not the one its command admitted
FS_CREF_SESSION_ENDED   equ 4   ; RCQ-20 S5a: a pending job dropped at a session change (rc-sec/root 13:13:36)
FS_CREF_CLASS_CHANGED   equ 5   ; RCQ-20 S5c: a queued ext4 job's volume no longer classifies as at its FSCOPY
FS_CREF_ARM_CHANGED     equ 6   ; S5c: its mount was disarmed or armed again (another owned token)
FS_CREF_CARRY_EXPIRED   equ 7   ; S5c: it waited longer than FS_CARRY_MAX_AGE_MS
FS_CREF_INSIDE_SRC      equ 8   ; RCQ-20 S5b: a tree's destination lies inside its own source directory
FS_CREF_NO_SPACE        equ 9   ; E1: a tree's scan saw more needed than the destination has free, before any write

; RCQ-20 S3: what the backend's restart recovery did with an interrupted copy (RAM, this boot)
struc fs_copy_rec
  .outcome:   resd 1      ; FS_REC_* (0 = nothing recovered this boot)
  .backend:   resd 1      ; FS_PRES_FAT / FS_PRES_EXT4
  .name:      resb 11     ; the committed destination's 8.3 leaf, when .named
  .named:     resb 1
endstruc
FS_REC_COMMITTED  equ 1    ; the destination was complete: only the journal was retired
FS_REC_RECLAIMED  equ 2    ; it never committed: the partial was freed
FS_REC_FAILED     equ 3    ; malformed or unreadable: failed closed, nothing freed that is not proven

; RCQ-38 G3: one regular file's physical extents, for a consumer that reads the medium by block (PREL1). The
; header is FROZEN (rc-boot 15:54:00 C1): its offsets are pinned by test_rc_fat32_extents_host. The extents
; are in device blocks of .block_bytes (C2); their blocks sum to ceil(size / block_bytes). The map is the
; caller's memory and untrusted once returned: vfs_file_extents_current compares its identity again.
FS_EXTENT_MAP_VERSION equ 1
struc fs_extent_map
  .mount:       resq 1    ;  0 the fsmount resolved
  .ops:         resq 1    ;  8 its ops
  .priv:        resq 1    ; 16 its backend context
  .dev:         resq 1    ; 24 the block device
  .media_gen:   resq 1    ; 32 blk_info.media_generation then (never 0)
  .ns_gen:      resq 1    ; 40 the backend's namespace generation then
  .size:        resq 1    ; 48 the file's bytes
  .volume_id:   resd 1    ; 56
  .block_bytes: resd 1    ; 60
  .count:       resd 1    ; 64 the total extent count (may exceed .cap: only cap are written)
  .cap:         resd 1    ; 68
  .version:     resd 1    ; 72 FS_EXTENT_MAP_VERSION
  .reserved:    resd 1    ; 76 0
  .ext:                   ; 80 cap x {lba qword, blocks qword}
endstruc

FS_JOB_IDLE       equ 0
FS_JOB_RUNNING    equ 1
FS_JOB_VERIFYING  equ 2
FS_JOB_CANCELLING equ 3    ; cancel or failure: reclaiming the partial chain
FS_JOB_DONE       equ 4
FS_JOB_CANCELLED  equ 5
FS_JOB_FAILED     equ 6
FS_JOB_QUEUED     equ 7    ; RCQ-20 S5a: accepted, waiting for the active job; never a backend state

; RCQ-20 S5a pending queue (root S0 Q1; FAT only, root 13:06:28): up to FS_QUEUE_MAX jobs wait,
; FIFO, behind the one active job. A record holds what the command admitted (paths, mode, the
; mount); its BEGIN runs later, from the tick, one per tick, and only on that same mount.
FS_QUEUE_MAX      equ 4
FS_QPATH_CAP      equ 256  ; a queued path with its NUL
; RCQ-20 S5c (rc-sec rev 3 6454fc74, root 14:09:28): a queued ext4 job carries its owner's console decision to
; the dequeue's BEGIN as an argument, never as request state. Recorded at FSCOPY (ext_w_carry_record), re-checked
; at the dequeue and by the sweep (ext_w_carry_check), consumed once (ext_w_job_open_carried). A FAT DATA record's
; carry is all zero (kind 0): it is never begun with FS_COPY_BEGIN_CARRIED.
; FAT scratch (ROOT105787, rc-sec 105819/105840 C1-C12): the exact armed fd_scratch mount carries the same way
; (fd_scratch_carry_record / fd_scratch_carry_check / fd_scratch_job_open_carried); .owned_token holds its arm epoch.
FS_CARRY_EXT4       equ 1
FS_CARRY_FAT_SCRATCH equ 2
FS_CARRY_MAX_AGE_MS equ 900000   ; 15 min on the boot clock (rev 3 C3 (g), root Q5)
struc fs_copy_carry
  .kind:         resd 1   ; 0 none (FAT DATA) / FS_CARRY_EXT4 / FS_CARRY_FAT_SCRATCH
  .intent:       resd 1   ; SA_INTENT_* of the FSCOPY's request
  .owner:        resd 1   ; its OWNER bit (1: an ext4 enqueue needs it)
  .class:        resd 1   ; SA_CLASS_* of the mount's partition window then
  .ctx:          resq 1   ; the mount's ext_ctx
  .dev:          resq 1
  .part_lba:     resq 1
  .part_sectors: resq 1
  .gen:          resq 1   ; the device's media generation then (never 0)
  .owned_token:  resq 1   ; the arm's owned token / 0 not owned
  .t_enqueue:    resq 1   ; boot ms
  .id:           resq 1   ; never reissued; an id at or below the last one spent never begins
  ; Internal queued decision: exact backend route and all scalar block facts.
  ; Existing prefix offsets stay fixed; queue/staging copies use its full size.
  .ops:          resq 1
  .priv:         resq 1
  .info:         resq 1
  .geometry:     resb blk_info_size - blk_info.sector_size
  ; SEC106668 R2: who asked, recorded at enqueue for receipts; no BEGIN, check or sweep reads it.
  .frame:        resq 1   ; FS_CARRY_FRAME_CONSOLE / FS_CARRY_FRAME_REMOTE_OWNER
  .spare:        resq 1   ; zero; keeps the size a multiple of 16
endstruc
FS_CARRY_FRAME_CONSOLE      equ 0
FS_CARRY_FRAME_REMOTE_OWNER equ 1   ; a consumed signed OWNER frame (command_auth_owner_consumed_for)
struc fs_copy_qrec
  .job:    resb fs_copy_job_size   ; what FSJOB reads while it waits (state FS_JOB_QUEUED)
  .mode:   resd 1
  .handle: resd 1
  .ops:    resq 1                  ; the admitted mount: handle, ops and priv must all still match
  .priv:   resq 1
  .ident:  resq 3                  ; and its medium, as the stamp hook recorded it at enqueue
  .session: resq 2                 ; the local session then (bound principal, key handle): a change drops it
  .carry:  resb fs_copy_carry_size ; RCQ-20 S5c: an ext4 record's carried decision (zero for FAT)
  .src:    resb FS_QPATH_CAP
  .dst:    resb FS_QPATH_CAP
endstruc

struc fs_stat
  .size:      resq 1
  .flags:     resd 1
  .reserved:  resd 1
endstruc

FS_STAT_READONLY equ 1

; Read-only replacement facts. No fs_stat ABI change; unsupported ops leave a conflict undecided.
; node is backend-private, nonzero, comparable only on the same mount. flags describe the node, not authority.
struc fs_replace_meta
  .seconds:   resq 1
  .ns:        resd 1
  .flags:     resd 1
  .node:      resq 1
endstruc
FS_RMETA_REGULAR  equ 1
FS_RMETA_ELIGIBLE equ 2

; Additive, mount-private read metadata.  Controller details never cross this
; seam: each backend fills these facts through its fs_ops instance.
struc fs_info
  .backend:       resq 1
  .device:        resq 1
  .part_type:     resq 1
  .volume_id:     resd 1
  .cluster_bytes: resd 1
  .total_sectors: resq 1
  .part_start:    resq 1
  .part_sectors:  resq 1
  .scheme:        resd 1
  .part_count:    resd 1
  .free_clusters: resq 1   ; exact validated allocation count, -1 if unsupported
  .orphans:       resq 1   ; reclaimed since mount, -1 if unsupported
endstruc
; vfs_info_facts sets free_clusters to this before the backend runs: facts only, so a backend whose free count
; walks the volume (FAT32's dual-FAT scan) skips the walk.  Callers never see it: it leaves as -1 or a cached count.
FS_INFO_FACTS equ -2

FS_SCHEME_SUPERFLOPPY equ 0
FS_SCHEME_MBR         equ 1
FS_SCHEME_GPT         equ 2

struc fs_dirent
  .name:     resb 13
  .pad:      resb 3
  .size:     resq 1
  .flags:    resd 1
  .reserved: resd 1
endstruc

FS_DIRENT_DIR equ 1
FS_DIRENT_LONG_NAME equ 2 ; reserved holds signed displacement from vfs_dirent_name
FS_DIRENT_LONG_OMITTED equ 4 ; the backend had no room for this entry's long name: .name is its 8.3 alias
%if fs_dirent_size != 32 || fs_dirent.size != 16 || fs_dirent.flags != 24
    %error "Task2403 must preserve the legacy directory-entry ABI"
%endif

struc fs_list_result
  .count:       resd 1
  .truncated:   resd 1
  .names_short: resd 1   ; 1 = at least one entry carries FS_DIRENT_LONG_OMITTED
endstruc
%if fs_list_result_size != 12 || fs_list_result.truncated != 4 || fs_list_result.names_short != 8
    %error "RCQ-20: fs_list_result is the 12-byte listing ABI every caller buffer is sized to"
%endif

struc fsmount
  .ops:   resq 1       ; -> fs_ops
  .priv:  resq 1       ; -> backend private (opaque)
  .name:  resq 1       ; mount label
endstruc

; Boot fixtures, descriptor/ESP, NTFS, two ext4, two exFAT, and the
; selected FAT read-only/scratch aliases can coexist beyond eight slots.
; Keep a fixed bound; eight additional 24-byte rows cost 192 bytes.
VFS_MAX_MOUNTS equ 16

; Keep the established 32-byte dirent ABI, including the inline short alias.
; The flagged optional name is in a backend's bounded static image arena.
; Store a signed displacement from this runtime anchor, never a baked RVA.
; A backend without the flag keeps its original inline-name semantics.
vfs_dirent_name:
    lea  rax, [rdi + fs_dirent.name]
    test dword [rdi + fs_dirent.flags], FS_DIRENT_LONG_NAME
    jz   .out
    movsxd rax, dword [rdi + fs_dirent.reserved]
    lea  rdx, [rel vfs_dirent_name]
    add  rax, rdx
.out:
    ret

; RDI=dirent, RSI=static NUL name. Valid until the backend's next listing.
vfs_dirent_set_long_name:
    lea  rax, [rel vfs_dirent_name]
    mov  rdx, rsi
    sub  rdx, rax
    mov  [rdi + fs_dirent.reserved], edx
    or   dword [rdi + fs_dirent.flags], FS_DIRENT_LONG_NAME
    ret


; Convert an exact, root-only path to a FAT 8.3 name.  Directories, truncation,
; empty components and unsupported characters are rejected; no caller can turn
; "MODEL.PXG" into an approximate lookup through silent normalization.
vfs_path_to_name11:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13d, esi
    test r12, r12
    jz   .fail
    test r13d, r13d
    jz   .fail
    cmp  r13d, 13                         ; slash + 8 + dot + 3 at most
    ja   .fail
    lea  r8, [rel vfs_path_name]
    mov  rax, 0x2020202020202020
    mov  [r8], rax
    mov  word [r8 + 8], 0x2020
    mov  byte [r8 + 10], 0x20
    xor  r14d, r14d                       ; source index
    xor  ebx, ebx                         ; 0=base, 1=extension
    xor  ecx, ecx                         ; base length
    xor  edx, edx                         ; extension length
    mov  al, [r12]
    cmp  al, '/'
    je   .skip_root
    cmp  al, '\'
    jne  .scan
.skip_root:
    inc  r14d
    cmp  r14d, r13d
    jae  .fail
.scan:
    cmp  r14d, r13d
    jae  .done
    mov  al, [r12 + r14]
    test al, al
    jz   .fail
    cmp  al, '/'
    je   .fail
    cmp  al, '\'
    je   .fail
    cmp  al, '.'
    jne  .character
    test ebx, ebx
    jnz  .fail
    test ecx, ecx
    jz   .fail
    mov  ebx, 1
    inc  r14d
    jmp  .scan
.character:
    cmp  al, 'a'
    jb   .validate
    cmp  al, 'z'
    ja   .validate
    sub  al, 0x20
.validate:
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
    jne  .fail
.store:
    test ebx, ebx
    jnz  .store_ext
    cmp  ecx, 8
    jae  .fail
    mov  [r8 + rcx], al
    inc  ecx
    inc  r14d
    jmp  .scan
.store_ext:
    cmp  edx, 3
    jae  .fail
    mov  [r8 + rdx + 8], al
    inc  edx
    inc  r14d
    jmp  .scan
.done:
    test ecx, ecx
    jz   .fail
    test ebx, ebx
    jz   .ok
    test edx, edx                         ; a trailing dot is not a name
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

; vfs_path_stat(RDI=path, ESI=len, R8D=mount handle) -> regular-file size/-1.
; Preserve the exact root 8.3 route (including a leading backslash). Other
; paths use native path admission; a refusal never becomes an alias lookup.
vfs_path_stat:
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13d, esi
    mov  r14d, r8d
    call vfs_path_to_name11
    test rax, rax
    jz   .legacy
    mov  edi, r14d
    call vfs_mount_ptr
    test rax, rax
    jz   .fail
    mov  rax, [rax + fsmount.ops]
    cmp  qword [rax + fs_ops.stat_path], 0
    je   .fail
    mov  edi, r14d
    mov  rsi, r12
    mov  edx, r13d
    lea  rcx, [rel vfs_stat_buf]
    call vfs_stat_path
    test rax, rax
    jnz  .fail
    jmp  .checked
.legacy:
    mov  edi, r14d
    lea  rsi, [rel vfs_path_name]
    lea  rdx, [rel vfs_stat_buf]
    call vfs_stat
    test rax, rax
    jnz  .fail
.checked:
    test dword [rel vfs_stat_buf + fs_stat.reserved], 3
    jnz  .fail
    mov  rax, [rel vfs_stat_buf + fs_stat.size]
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    ret

; Whole-file path seam (same classic-compatible ABI):
; (RDI=path,ESI=len,RDX=buf,ECX=cap,R8D=mount handle) -> bytes/-1.
; Preserve exact root 8.3 inputs through their existing legacy slots. Other
; paths require paired native path slots, retaining exact nested/long names and
; the backend's admission. A native refusal never falls back to an alias lookup.
; Only a regular file that fits in full is read, and a short read is failure.
vfs_readfile_path:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 16
    mov  r12, rdi                         ; exact path
    mov  ebx, esi                         ; path byte length
    mov  r13, rdx                         ; destination
    mov  r14d, ecx                        ; capacity
    mov  r15d, r8d                        ; mount handle
    mov  qword [rsp + 8], 0               ; legacy path selection
    call vfs_path_to_name11
    test rax, rax
    jz   .legacy_stat
    mov  edi, r15d
    call vfs_mount_ptr
    test rax, rax
    jz   .fail
    mov  rax, [rax + fsmount.ops]
    cmp  qword [rax + fs_ops.stat_path], 0
    je   .fail
    cmp  qword [rax + fs_ops.read_at_path], 0
    je   .fail
    mov  qword [rsp + 8], 1
    mov  edi, r15d
    mov  rsi, r12
    mov  edx, ebx
    lea  rcx, [rel vfs_stat_buf]
    call vfs_stat_path
    test rax, rax
    jnz  .fail
    jmp  .checked
.legacy_stat:
    mov  edi, r15d
    lea  rsi, [rel vfs_path_name]
    lea  rdx, [rel vfs_stat_buf]
    call vfs_stat
    test rax, rax
    jnz  .fail
.checked:
    test dword [rel vfs_stat_buf + fs_stat.reserved], 3
    jnz  .fail
    mov  rax, [rel vfs_stat_buf + fs_stat.size]
    cmp  rax, r14
    ja   .fail
    mov  [rsp], rax                       ; expected whole-file byte count
    cmp  qword [rsp + 8], 0
    je   .legacy_read
    mov  edi, r15d
    mov  rsi, r12
    mov  edx, ebx
    xor  ecx, ecx                        ; offset 0
    mov  r8, r13
    mov  r9, rax
    call vfs_read_at_path
    jmp  .read_done
.legacy_read:
    mov  edi, r15d
    lea  rsi, [rel vfs_path_name]
    xor  edx, edx                         ; offset 0
    mov  rcx, r13
    mov  r8, rax
    call vfs_read_at
.read_done:
    cmp  rax, [rsp]
    jne  .fail
    jmp  .out
.fail:
    mov  rax, -1
.out:
    add  rsp, 16
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Read-only registry occupancy; no reservation or backend call.
; vfs_mount_usage -> EAX used slots, EDX capacity.
vfs_mount_usage:
    mov eax, [rel vfs_mount_count]
    mov edx, VFS_MAX_MOUNTS
    ret

; Private registration for the fixed, unnamed, read-only guest-source backend.
; No caller-selected ops/context/name, and no write-generation change: this does
; not select the command root or grant any mutation authority. Ordinary mount
; registration (including the existing boot ESP) retains its original barrier.
vfs_register_guest_source:
    lea  rdi, [rel fd_guest_ops]
    lea  rsi, [rel fd_guest_ctx]
    xor  edx, edx
    jmp  vfs_register_mount.read_only

; The guest-pair scoped boot-ESP handle: the same fixed unnamed RO registration.
vfs_register_guest_esp:
    lea  rdi, [rel fd_gesp_ops]
    lea  rsi, [rel fd_gesp_ctx]
    xor  edx, edx
    jmp  vfs_register_mount.read_only

; vfs_register_mount(RDI=ops,RSI=priv,RDX=name) -> RAX=handle / -1
vfs_register_mount:
    lock inc qword [rel vfs_write_generation]   ; RCQ-39 F-a: before the backend, whatever its result
.read_only:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    call guest_volume_mount_allowed
    test rax,rax
    jnz .fail
    mov  rdi, r12
    mov  rsi, r13
    call fs_format_mount_allowed          ; Format F1 custody (SEC 108221 C1/C7): no native remount
    test rax,rax
    jnz .fail
    test r12, r12
    jz   .fail
    cmp  qword [r12 + fs_ops.name], 0
    je   .fail
    cmp  qword [r12 + fs_ops.mount], 0
    je   .fail
    cmp  qword [r12 + fs_ops.stat], 0
    je   .fail
    cmp  qword [r12 + fs_ops.read_at], 0
    je   .fail
    mov  ebx, [rel vfs_mount_count]
    cmp  ebx, VFS_MAX_MOUNTS
    jae  .fail
    lea  rdi, [rel vfs_mounts]
    mov  eax, ebx
    imul rax, rax, fsmount_size
    add  rdi, rax
    mov  [rdi + fsmount.ops], r12
    mov  [rdi + fsmount.priv], r13
    mov  [rdi + fsmount.name], r14
    push rdi
    call [r12 + fs_ops.mount]
    pop  rdi
    test rax, rax
    jnz  .clear
    inc  dword [rel vfs_mount_count]
    mov  eax, ebx
    jmp  .out
.clear:
    mov  qword [rdi + fsmount.ops], 0
    mov  qword [rdi + fsmount.priv], 0
    mov  qword [rdi + fsmount.name], 0
.fail:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ============================================================================
; low-level RAM-volume helpers
; ============================================================================

; vfs_sec(RDI=lba) -> RAX = ptr to sector    clobbers RAX,RDX
vfs_sec:
    mov  rax, [rel vfs_vol]
    mov  rdx, rdi
    shl  rdx, 9                          ; * 512
    add  rax, rdx
    ret

; fat_entry_ptr(RDI=clus, RSI=fat_base_sector) -> RAX = &FAT[clus]  clobbers RAX,RDX
fat_entry_ptr:
    mov  rax, [rel vfs_vol]
    mov  rdx, rsi
    shl  rdx, 9                          ; fat_base * 512
    add  rax, rdx
    mov  rdx, rdi
    shl  rdx, 2                          ; clus * 4 (32-bit entries)
    add  rax, rdx
    ret

; fat_get(RDI=clus) -> EAX = 28-bit entry value (from FAT1)   clobbers RAX,RDX,RSI
fat_get:
    mov  rsi, VFS_FAT1
    call fat_entry_ptr
    mov  eax, [rax]
    and  eax, 0x0FFFFFFF
    ret

; fat_set(RDI=clus, RSI=val) — write BOTH FATs (mirror, trap #7)   clobbers RAX,RDX
fat_set:
    push rbx
    push r12
    mov  r12, rdi                        ; clus
    mov  ebx, esi
    and  ebx, 0x0FFFFFFF                  ; val (28-bit)
    mov  rdi, r12
    mov  rsi, VFS_FAT1
    call fat_entry_ptr
    mov  [rax], ebx
    mov  rdi, r12
    mov  rsi, VFS_FAT2
    call fat_entry_ptr
    mov  [rax], ebx
    pop  r12
    pop  rbx
    ret

; fat_alloc() -> RAX = fresh cluster (marked EOC) or 0 (full)
fat_alloc:
    push rbx
    mov  rbx, 3                          ; cluster 2 is root; data allocs start at 3
.loop:
    cmp  rbx, VFS_MAXCLUS
    jae  .full
    mov  rdi, rbx
    call fat_get
    test eax, eax                        ; 0 => free
    jz   .found
    inc  rbx
    jmp  .loop
.found:
    mov  rdi, rbx
    mov  rsi, FAT_EOC
    call fat_set
    mov  rax, rbx
    pop  rbx
    ret
.full:
    xor  eax, eax
    pop  rbx
    ret

; fat_free_chain(RDI=clus) — free a cluster chain (single-cluster in scope)
fat_free_chain:
    push rbx
    mov  rbx, rdi
.loop:
    cmp  ebx, 3
    jb   .done                           ; 0/1/reserved, or root(2) — never freed here
    cmp  ebx, VFS_MAXCLUS
    jae  .done
    mov  rdi, rbx
    call fat_get                         ; EAX = next in chain
    mov  r8d, eax
    mov  rdi, rbx
    xor  rsi, rsi
    call fat_set                         ; free this cluster
    cmp  r8d, FAT_EOC_MIN
    jae  .done
    mov  ebx, r8d
    jmp  .loop
.done:
    pop  rbx
    ret

; clus_ptr(RDI=clus) -> RAX = ptr to the cluster's data   clobbers RAX,RDX,RDI
clus_ptr:
    lea  rax, [rdi - VFS_ROOTCLUS]
    add  rax, VFS_DATA                   ; data sector = DATA + (clus-2)*SPC (SPC=1)
    mov  rdi, rax
    jmp  vfs_sec

; de_clus(RDI=entry) -> RAX = first cluster   clobbers RAX,RDX
de_clus:
    movzx eax, word [rdi + DE_CLUSHI]
    shl  eax, 16
    movzx edx, word [rdi + DE_CLUSLO]
    or   eax, edx
    ret

; dir_find(RDI=name11) -> RAX = entry ptr or 0
dir_find:
    push rbx
    push r12
    push r13
    mov  r13, rdi                        ; name
    mov  rdi, VFS_ROOTCLUS
    call clus_ptr                        ; RAX = root dir
    mov  rbx, rax
    mov  r12, DE_PER_CLUS
.loop:
    movzx eax, byte [rbx]
    test al, al
    jz   .notfound                       ; 0x00 => end of directory
    cmp  al, DE_DELETED
    je   .next
    mov  rdi, rbx
    mov  rsi, r13
    mov  rdx, 11
    call memcmp
    test rax, rax
    jz   .found
.next:
    add  rbx, DE_STRIDE
    dec  r12
    jnz  .loop
.notfound:
    xor  eax, eax
    jmp  .out
.found:
    mov  rax, rbx
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; dir_alloc_slot() -> RAX = free/tombstoned entry ptr or 0
dir_alloc_slot:
    push rbx
    push r12
    mov  rdi, VFS_ROOTCLUS
    call clus_ptr
    mov  rbx, rax
    mov  r12, DE_PER_CLUS
.loop:
    movzx eax, byte [rbx]
    test al, al
    jz   .got                            ; 0x00 free
    cmp  al, DE_DELETED
    je   .got                            ; tombstone reusable
    add  rbx, DE_STRIDE
    dec  r12
    jnz  .loop
    xor  eax, eax
    jmp  .out
.got:
    mov  rax, rbx
.out:
    pop  r12
    pop  rbx
    ret

; dir_write_entry(RDI=slot, RSI=name11, RDX=clus, RCX=size) — fill a 32-byte entry
dir_write_entry:
    push rbx
    push r12
    push r13
    push r14
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rdx
    mov  r14, rcx
    mov  rdi, rbx
    xor  rsi, rsi
    mov  rdx, DE_STRIDE
    call memset                          ; zero the slot
    mov  rdi, rbx
    mov  rsi, r12
    mov  rdx, 11
    call memcpy                          ; 8.3 name
    mov  byte [rbx + DE_ATTR], ATTR_ARCHIVE
    mov  eax, r13d
    mov  word [rbx + DE_CLUSLO], ax
    shr  eax, 16
    mov  word [rbx + DE_CLUSHI], ax
    mov  eax, r14d
    mov  dword [rbx + DE_SIZE], eax
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ============================================================================
; fat32_format — lay down BPB + FAT[0]/FAT[1] + empty root dir on the RAM volume
; ============================================================================
fat32_format:
    mov  rdi, [rel vfs_vol]
    xor  rsi, rsi
    mov  rdx, VFS_VOLBYTES
    call memset                          ; blank volume
    ; --- BPB (sector 0), the FAT32 fields our reader consults ---
    mov  rdi, [rel vfs_vol]
    mov  word  [rdi + 11], VFS_BPS       ; BytsPerSec
    mov  byte  [rdi + 13], VFS_SPC       ; SecPerClus
    mov  word  [rdi + 14], VFS_RSVD      ; RsvdSecCnt
    mov  byte  [rdi + 16], VFS_NFATS     ; NumFATs
    mov  word  [rdi + 17], 0             ; RootEntCnt = 0 (FAT32)
    mov  word  [rdi + 19], 0             ; TotSec16 = 0
    mov  dword [rdi + 32], VFS_TOTSEC    ; TotSec32
    mov  dword [rdi + 36], VFS_FATSZ     ; FATSz32
    mov  dword [rdi + 44], VFS_ROOTCLUS  ; RootClus
    mov  word  [rdi + 510], 0xAA55       ; boot signature
    ; --- FAT[0]=media, FAT[1]=EOC, in BOTH FATs ---
    xor  rdi, rdi
    mov  rsi, VFS_FAT1
    call fat_entry_ptr
    mov  dword [rax], FAT_EOC_MIN
    mov  rdi, 1
    mov  rsi, VFS_FAT1
    call fat_entry_ptr
    mov  dword [rax], FAT_EOC
    xor  rdi, rdi
    mov  rsi, VFS_FAT2
    call fat_entry_ptr
    mov  dword [rax], FAT_EOC_MIN
    mov  rdi, 1
    mov  rsi, VFS_FAT2
    call fat_entry_ptr
    mov  dword [rax], FAT_EOC
    ; --- root dir cluster (2) => EOC (one-cluster root) ---
    mov  rdi, VFS_ROOTCLUS
    mov  rsi, FAT_EOC
    call fat_set
    ret

; ============================================================================
; fat32 backend ops (rw) — self ignored; single global volume
; ============================================================================
fat32_mount:
    xor  eax, eax
    ret

; fat32_readfile(self,RSI=name11,RDX=buf,RCX=cap) -> RAX = file size / -1
fat32_readfile:
    push rbx
    push r13
    push r14
    push r15
    mov  r13, rdx                        ; buf
    mov  r14, rcx                        ; cap
    mov  rdi, rsi
    call dir_find
    test rax, rax
    jz   .enoent
    mov  rbx, rax                        ; entry
    mov  r15d, dword [rbx + DE_SIZE]     ; file size
    mov  rcx, r15
    cmp  rcx, r14                        ; N = min(size, cap)
    jbe  .haveN
    mov  rcx, r14
.haveN:
    mov  rdi, rbx
    call de_clus
    mov  rdi, rax
    call clus_ptr                        ; RAX = data ptr
    push rcx
    mov  rdi, r13
    mov  rsi, rax
    pop  rdx                             ; len = N
    call memcpy
    mov  rax, r15                        ; return true file size
    jmp  .out
.enoent:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

; fat32_writefile(self,RSI=name11,RDX=buf,RCX=len) -> RAX = file cluster / -1
;   THE temp-then-swap safe write. len <= 512 (single-cluster scope).
fat32_writefile:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rsi                        ; target name
    mov  r12, rdx                        ; payload
    mov  r13, rcx                        ; len
    ; (1) fresh cluster + write payload there (old data untouched)
    call fat_alloc
    test rax, rax
    jz   .fail
    mov  r14, rax                        ; new cluster
    mov  rdi, r14
    call clus_ptr
    mov  r8, rax                         ; data ptr
    mov  rdi, rax
    xor  rsi, rsi
    mov  rdx, VFS_BPS
    call memset                          ; zero the fresh cluster
    mov  rdi, r8
    mov  rsi, r12
    mov  rdx, r13
    call memcpy                          ; payload -> fresh cluster
    ; (2) TEMP dir entry (~TMPSWAP) -> fresh cluster
    call dir_alloc_slot
    test rax, rax
    jz   .fail_free
    mov  r15, rax                        ; temp slot
    mov  rdi, r15
    lea  rsi, [rel vfs_tmpname]
    mov  rdx, r14
    mov  rcx, r13
    call dir_write_entry
    ; (3) VERIFY temp reads back byte-equal (else abort; old file intact)
    mov  rdi, r14
    call clus_ptr
    mov  rdi, rax
    mov  rsi, r12
    mov  rdx, r13
    call memcmp
    test rax, rax
    jnz  .fail_free_slot
    ; (4) delete OLD target (free clusters + tombstone) if present
    mov  rdi, rbx
    call dir_find
    test rax, rax
    jz   .noold
    mov  r9, rax                         ; old entry
    mov  rdi, r9
    call de_clus
    mov  rdi, rax
    call fat_free_chain
    mov  byte [r9], DE_DELETED
.noold:
    ; (5) ATOMIC RENAME — write ONLY the 11-byte name field (single write, trap #1)
    mov  rdi, r15
    mov  rsi, rbx
    mov  rdx, 11
    call memcpy
    mov  rax, r14                        ; success -> file cluster
    jmp  .out
.fail_free_slot:
    mov  byte [r15], DE_DELETED          ; drop the temp entry
.fail_free:
    mov  rdi, r14
    call fat_free_chain                  ; reclaim the fresh cluster
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; fat32_delete(self,RSI=name11) -> RAX 0 / -1
fat32_delete:
    push rbx
    mov  rdi, rsi
    call dir_find
    test rax, rax
    jz   .none
    mov  rbx, rax
    mov  rdi, rbx
    call de_clus
    mov  rdi, rax
    call fat_free_chain
    mov  byte [rbx], DE_DELETED
    xor  eax, eax
    pop  rbx
    ret
.none:
    mov  rax, -1
    pop  rbx
    ret

; fat32_stat(self,RSI=name11,RDX=fs_stat*) -> RAX 0/-1
fat32_stat:
    push rbx
    mov  rbx, rdx
    mov  rdi, rsi
    call dir_find
    test rax, rax
    jz   .fail
    mov  edx, [rax + DE_SIZE]
    mov  [rbx + fs_stat.size], rdx
    mov  dword [rbx + fs_stat.flags], 0
    mov  dword [rbx + fs_stat.reserved], 0
    xor  eax, eax
    pop  rbx
    ret
.fail:
    mov  rax, -1
    pop  rbx
    ret

; fat32_read_at(self,RSI=name11,RDX=off,RCX=buf,R8=len) -> RAX len/-1
; RAM backend remains single-cluster, but now exercises the exact stream ABI.
fat32_read_at:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdx
    mov  r13, rcx
    mov  r14, r8
    mov  rdi, rsi
    call dir_find
    test rax, rax
    jz   .fail
    mov  ebx, [rax + DE_SIZE]
    mov  rcx, r12
    add  rcx, r14
    jc   .fail
    cmp  rcx, rbx
    ja   .fail
    test r14, r14
    jz   .ok
    mov  rdi, rax
    call de_clus
    mov  rdi, rax
    call clus_ptr
    add  rax, r12
    mov  rdi, r13
    mov  rsi, rax
    mov  rdx, r14
    call memcpy
.ok:
    mov  rax, r14
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ============================================================================
; degenerate 2nd backend (read-only mock) — exercises backend selection only.
; Its labels keep the historical exfat_ prefix; it parses no exFAT and its
; mount name, content and markers say "c8-ro-mock" (RCQ-20 exFAT S1).
; ============================================================================
exfat_mount:
    lea  rdi, [rel str_exfat_init]
    call serial_string                   ; mock.init marker (2nd-backend proof)
    xor  eax, eax
    ret

; exfat_readfile(self,RSI=name11,RDX=buf,RCX=cap) -> RAX = len (pre-baked)
exfat_readfile:
    push r12
    mov  r12, rdx
    mov  rdi, r12
    lea  rsi, [rel exfat_content]
    mov  rdx, exfat_content.len
    call memcpy
    mov  rax, exfat_content.len
    pop  r12
    ret

exfat_writefile:                         ; read-only
    mov  rax, -1
    ret
exfat_delete:
    mov  rax, -1
    ret

exfat_stat:
    mov  qword [rdx + fs_stat.size], exfat_content.len
    mov  dword [rdx + fs_stat.flags], FS_STAT_READONLY
    mov  dword [rdx + fs_stat.reserved], 0
    xor  eax, eax
    ret

exfat_read_at:
    mov  rax, rdx
    add  rax, r8
    jc   .fail
    cmp  rax, exfat_content.len
    ja   .fail
    test r8, r8
    jz   .ok
    push r8
    mov  rdi, rcx
    lea  rsi, [rel exfat_content]
    add  rsi, rdx
    mov  rdx, r8
    call memcpy
    pop  r8
.ok:
    mov  rax, r8
    ret
.fail:
    mov  rax, -1
    ret

; Throwaway read-only backend used only by the degenerate-second seam KAT.
vfs_kat_mount:
    xor  eax, eax
    ret
vfs_kat_fail:
    mov  rax, -1
    ret
vfs_kat_stat:
    mov  qword [rdx + fs_stat.size], vfs_kat_content.len
    mov  dword [rdx + fs_stat.flags], FS_STAT_READONLY
    mov  dword [rdx + fs_stat.reserved], 0
    xor  eax, eax
    ret
vfs_kat_read_at:
    mov  rax, rdx
    add  rax, r8
    jc   .fail
    cmp  rax, vfs_kat_content.len
    ja   .fail
    test r8, r8
    jz   .ok
    push r8
    mov  rdi, rcx
    lea  rsi, [rel vfs_kat_content]
    add  rsi, rdx
    mov  rdx, r8
    call memcpy
    pop  r8
.ok:
    mov  rax, r8
    ret
.fail:
    mov  rax, -1
    ret

; ============================================================================
; VFS dispatch — SAME mount table + selector for every backend (trap #3)
; ============================================================================
; vfs_mount_ptr(RDI=idx) -> RAX = fsmount*
vfs_mount_ptr:
    cmp  edi, [rel vfs_mount_count]
    jae  .none
    cmp  edi, VFS_MAX_MOUNTS
    jae  .none
    bt   dword [rel vfs_retired_mounts], edi
    jc   .none
    lea  rax, [rel vfs_mounts]
    imul rdi, rdi, fsmount_size
    add  rax, rdi
    ; Keep lookup's historical argument ABI: only RAX/RDI may change.
    push rdi
    push rsi
    push rax
    mov rdi,[rax+fsmount.ops]
    mov rsi,[rax+fsmount.priv]
    call guest_volume_mount_allowed
    test rax,rax
    jnz .deny
    call fs_format_mount_allowed          ; Format F1 custody: same RDI/RSI, only RAX changes
    test rax,rax
.deny:
    pop rax
    pop rsi
    pop rdi
    jnz .none
    ret
.none:
    xor  eax, eax
    ret

; vfs_writefile(RDI=idx,RSI=name11,RDX=buf,RCX=len) -> RAX (backend result)
vfs_update:
    mov  r9d, fs_ops.update
    jmp  vfs_write_dispatch
; Additive path transaction seam; preserve the operation across mount lookup.
vfs_mutate_path:
    mov  r9d, fs_ops.mutate_path
    jmp  vfs_write_dispatch
vfs_rename:
    mov  r9d, fs_ops.rename
    jmp  vfs_write_dispatch
vfs_writefile:
    mov  r9d, fs_ops.writefile
vfs_write_dispatch:                      ; writefile, update, mutate_path, rename
    lock inc qword [rel vfs_write_generation]   ; RCQ-39 F-a: before the backend, whatever its result
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rsi
    mov  r13, rdx
    mov  r14, rcx
    mov  ebx, r9d
    call vfs_mount_ptr
    test rax, rax
    jz   .fail
    mov  r11, rax
    mov  r10, [r11 + fsmount.ops]
    cmp  qword [r10 + rbx], 0
    je   .fail
    mov  rdi, r11
    mov  rsi, r12
    mov  rdx, r13
    mov  rcx, r14
    call [r10 + rbx]
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
.fail:
    mov  rax, -1
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; vfs_readfile(RDI=idx,RSI=name11,RDX=buf,RCX=cap) -> RAX (backend result)
vfs_readfile:
    push r12
    push r13
    push r14
    mov  r12, rsi
    mov  r13, rdx
    mov  r14, rcx
    call vfs_mount_ptr
    test rax, rax
    jz   .fail
    mov  r11, rax
    mov  r10, [r11 + fsmount.ops]
    cmp  qword [r10 + fs_ops.readfile], 0
    je   .fail
    mov  rdi, r11
    mov  rsi, r12
    mov  rdx, r13
    mov  rcx, r14
    call [r10 + fs_ops.readfile]
    pop  r14
    pop  r13
    pop  r12
    ret
.fail:
    mov  rax, -1
    pop  r14
    pop  r13
    pop  r12
    ret

; vfs_delete(RDI=idx,RSI=name11) -> RAX (backend result)
vfs_delete:
    lock inc qword [rel vfs_write_generation]   ; RCQ-39 F-a: before the backend, whatever its result
    push r12
    mov  r12, rsi
    call vfs_mount_ptr
    test rax, rax
    jz   .fail
    mov  r11, rax
    mov  r10, [r11 + fsmount.ops]
    cmp  qword [r10 + fs_ops.delete], 0
    je   .fail
    mov  rdi, r11
    mov  rsi, r12
    call [r10 + fs_ops.delete]
    pop  r12
    ret
.fail:
    mov  rax, -1
    pop  r12
    ret

; vfs_stat(RDI=handle,RSI=name11,RDX=fs_stat*) -> RAX 0/-1
vfs_stat:
    push r12
    push r13
    mov  r12, rsi
    mov  r13, rdx
    call vfs_mount_ptr
    test rax, rax
    jz   .fail
    mov  r11, rax
    mov  r10, [r11 + fsmount.ops]
    mov  rdi, r11
    mov  rsi, r12
    mov  rdx, r13
    call [r10 + fs_ops.stat]
    pop  r13
    pop  r12
    ret
.fail:
    mov  rax, -1
    pop  r13
    pop  r12
    ret

; vfs_read_at(RDI=handle,RSI=name11,RDX=off,RCX=buf,R8=len) -> RAX len/-1
vfs_read_at:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rsi
    mov  r13, rdx
    mov  r14, rcx
    mov  r15, r8
    call vfs_mount_ptr
    test rax, rax
    jz   .fail
    mov  r11, rax
    mov  r10, [r11 + fsmount.ops]
    mov  rdi, r11
    mov  rsi, r12
    mov  rdx, r13
    mov  rcx, r14
    mov  r8, r15
    call [r10 + fs_ops.read_at]
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

; vfs_write_at(RDI=handle,RSI=name11,RDX=off,RCX=buf,R8=len) -> RAX len/-1
;   Dispatches to fs_ops.write_at when the backend provides it (NULL slot -> -1).
vfs_write_at:
    lock inc qword [rel vfs_write_generation]   ; RCQ-39 F-a: before the backend, whatever its result
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rsi
    mov  r13, rdx
    mov  r14, rcx
    mov  r15, r8
    call vfs_mount_ptr
    test rax, rax
    jz   .fail
    mov  r11, rax
    mov  r10, [r11 + fsmount.ops]
    cmp  qword [r10 + fs_ops.write_at], 0
    je   .fail
    mov  rdi, r11
    mov  rsi, r12
    mov  rdx, r13
    mov  rcx, r14
    mov  r8, r15
    call [r10 + fs_ops.write_at]
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

; ---- RCQ-20 copy job: one at a time, stepped from the backend's idle cadence ----
; vfs_copy_start(EDI=handle,RSI=src Z path,RDX=dst Z path) -> RAX job id / -1 backend refusal / -2 job active
; vfs_copy_start_mode(..., ECX=FS_CMODE_*): the same with a conflict policy (RCQ-20 S4);
;   on -1, vfs_copy_refusal names a typed keep-both refusal (0 = the backend's own error)
;   RCQ-20 S5a: -2 also while jobs are queued, so a new request never overtakes them (its
;   caller may queue it with vfs_copy_enqueue)
vfs_copy_start:
    xor  ecx, ecx                        ; FS_CMODE_REFUSE
vfs_copy_start_mode:
    lock inc qword [rel vfs_write_generation]   ; RCQ-39 F-a: before the backend, whatever its result
    mov  dword [rel vfs_copy_refusal], 0
    mov  r9d, ecx
    call vfs_copy_busy
    test eax, eax
    jnz  .active
    mov  r10d, FS_COPY_BEGIN
    xor  eax, eax                        ; a fresh id
    xor  r11d, r11d                    ; ordinary same-mount BEGIN
    jmp  vfs_copy_begin
.active:
    mov  rax, -2
    ret

; vfs_copy_start_between(EDI=source handle, ESI=destination handle, RDX=source Z,
; RCX=destination Z, R8D=mode) -> job id / -1 unsupported/refused / -2 busy.
; Explicit two-mount BEGIN only; backend judges source-kind/tree support, no queue/carry.
vfs_copy_start_between:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  ebx, esi
    mov  r12, rdx
    mov  r13, rcx
    mov  r14d, r8d
    mov  [rel vfs_copy_between_sh], edi  ; E1: the tree scan lists the source through it
    test r14d, FS_CMODE_ASK | FS_CMODE_SKIP | FS_CMODE_REPLACE
    jnz  .bad                            ; E2: MODE=ask is same-volume only (E2r: replace-older too)
    cmp  edi, ebx
    je   .bad
    call vfs_mount_ptr
    test rax, rax
    jz   .bad
    mov  r15, rax
    call vfs_copy_busy
    test eax, eax
    jnz  .busy
    lock inc qword [rel vfs_write_generation]
    mov  dword [rel vfs_copy_refusal], 0
    mov  edi, ebx
    mov  rsi, r12
    mov  rdx, r13
    mov  r9d, r14d
    mov  r11, r15
    mov  r10d, FS_COPY_BEGIN
    xor  eax, eax
    call vfs_copy_begin
    jmp  .out
.busy:
    mov  rax, -2
    jmp  .out
.bad:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; vfs_copy_begin(EDI=handle,RSI=src,RDX=dst,R9D=FS_CMODE_*,RAX=the queued job's id, 0 = a fresh one,
;   R10D=FS_COPY_BEGIN, or FS_COPY_BEGIN_CARRIED from vfs_copy_dequeue only (RCQ-20 S5c))
;   -> RAX job id / -1 backend refusal. The BEGIN both vfs_copy_start_mode and the queue run.
;   E2r-b: a same-volume single-file FS_CMODE_REPLACE BEGIN the backend refused with vfs_copy_replace_verdict 0
;   (not older) or 2 (undecided) is no refusal: the job is an ask job of that one file, settled SKIPPED at once
;   (0) or waiting for FSANSWER (2), nothing written either way.
vfs_copy_begin:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 40
    mov  dword [rel vfs_copy_begin_error], 0
    mov  dword [rel vfs_copy_begin_pres], FS_PRES_NONE
    mov  [rsp], r11                     ; source mount, or zero for same-volume
    mov  dword [rsp + 32], 0            ; 1 = run the stored item's automatic answer immediately
    mov  ebp, r10d
    mov  ebx, edi
    mov  r12, rsi
    mov  r13, rdx
    mov  r14d, r9d
    mov  r15, rax
    test r14d, FS_COPY_HOLD_PARTIAL
    jz .partial_flags_valid
    cmp r14d, FS_COPY_HOLD_PARTIAL
    jne .fail
    cmp qword [rsp], 0
    jne .fail
    test r15, r15
    jnz .fail
    cmp ebp, FS_COPY_BEGIN
    jne .fail
.partial_flags_valid:
    mov  eax, r14d
    and  eax, FS_COPY_START_PAUSED
    mov  [rsp + 36], eax                 ; private spare dword beside auto-answer
    and  r14d, ~FS_COPY_START_PAUSED      ; backend sees its unchanged old policy
    test r14d, FS_CMODE_ASK              ; E2: an ask job whose destination name is taken
    jnz  .ask_top
    test r14d, FS_COPY_TREE
    jnz  .scan_first
    mov  eax, r14d
    and  eax, FS_CMODE_SKIPSAME | FS_CMODE_REPLACE
    cmp  eax, FS_CMODE_SKIPSAME | FS_CMODE_REPLACE
    jne  .scan_first
.ask_top:                               ; combined file: compare as a child, so a late undecided result can wait
    cmp  dword [rel vfs_ask_child_begin], 0
    jne  .scan_first
    cmp  qword [rsp], 0
    jne  .fail
    mov  edi, ebx
    mov  rsi, r12
    mov  rdx, r13
    mov  ecx, r14d
    call vfs_ask_top
    test rax, rax
    js   .fail
    jz   .scan_first
    test r14d, FS_CMODE_ASK
    jnz  .ask_waiting
    mov  dword [rel vfs_ask_items + fs_copy_wait.answer], FS_CMODE_SKIPSAME | FS_CMODE_REPLACE
    mov  dword [rsp + 32], 1
    jmp  .ask_waiting
.scan_first:
    test r14d, FS_COPY_TREE
    jz   .mount
    mov  edi, ebx                        ; E1: the scan's first step, before the backend writes anything
    cmp  qword [rsp], 0
    je   .scan
    mov  edi, [rel vfs_copy_between_sh]
.scan:
    mov  rsi, r12
    mov  edx, ebx
    mov  rcx, r13
    mov  r8d, r14d
    call vfs_scan_open
    test eax, eax
    jz   .mount
    mov  dword [rel vfs_copy_refusal], FS_CREF_NO_SPACE
    jmp  .fail
.mount:
    mov  edi, ebx
    call vfs_mount_ptr
    test rax, rax
    jz   .fail
    mov  r10, [rax + fsmount.ops]
    cmp  qword [r10 + fs_ops.copy], 0
    je   .fail
    ; This finite option is same-volume mode0, never queued/carried/tree/ask.
    ; Only these exact native producers implement its prepublication boundary.
    test r14d, FS_COPY_HOLD_PARTIAL
    jz .partial_checked
    cmp r14d, FS_COPY_HOLD_PARTIAL
    jne .fail
    cmp qword [rsp], 0
    jne .fail
    test r15, r15
    jnz .fail
    cmp ebp, FS_COPY_BEGIN
    jne .fail
    lea rdx, [rel ext_ops]
    cmp r10, rdx
    je .partial_checked
    lea rdx, [rel nt_ops]
    cmp r10, rdx
    je .partial_checked
    lea rdx, [rel exf_ops]
    cmp r10, rdx
    jne .fail
.partial_checked:
    mov qword [rel vfs_partial_job], 0
    push rax
    push rdi
    push rcx
    lea rdi, [rel vfs_partial_record]
    xor eax, eax
    mov ecx, fs_copy_partial_size / 8
    rep stosq
    pop rcx
    pop rdi
    pop rax
    test r14d, FS_COPY_HOLD_PARTIAL
    jz .partial_prepared
    lea rdx, [rel vfs_copy_job]
    mov [rel vfs_partial_job], rdx
    mov rdx, [rel vfs_copy_seq]
    inc rdx
    jz .fail                           ; no wrapping identity for private names
    js .fail                           ; negative return values are API refusals
    mov [rel vfs_partial_record + fs_copy_partial.id], rdx
    mov qword [rel vfs_partial_record + fs_copy_partial.stage], 1
.partial_prepared:
    ; Snapshot before BEGIN: a later mount-slot reuse cannot redirect STEP/CANCEL.
    ; Publish only on success; a refused BEGIN preserves the prior job binding.
    mov  [rsp + 8], r10
    mov  rdx, [rax + fsmount.priv]
    mov  [rsp + 16], rdx
    mov  rdx, [r10 + fs_ops.copy]
    mov  [rsp + 24], rdx
    mov  rdi, rax
    mov  rsi, r12
    mov  rdx, r13
    mov  ecx, ebp
    lea  r8, [rel vfs_copy_job]
    mov  r9d, r14d                           ; the conflict policy; BEGIN sets .kept on success
    mov  r11, [rel blk_flush_failures]     ; before BEGIN: its own flushes count too
    mov  [rel vfs_copy_job + fs_copy_job.flush_fails], r11d
    mov  qword [rel vfs_copy_policy_ptr], 0  ; E2: the backend's BEGIN publishes its live policy dword
    mov  dword [rel vfs_copy_replace_verdict], -1   ; E2r-b: only this BEGIN's own decision is read below
    mov  qword [rel vfs_copy_item_phase], 0 ; this BEGIN must publish its own file observation
    cmp  qword [rsp], 0
    jne  .between
    call [r10 + fs_ops.copy]                 ; fills total/done/state only on success
    jmp  .begun
.between:
    mov  rax, [r10 + fs_ops.copy_between]
    test rax, rax
    jz   .fail
    mov  r10, [rsp]
    call rax
.begun:
    test rax, rax
    jnz  .refused
    ; The isolated service acquires its private lease during the original BEGIN
    ; (never at configuration). Retain that newly published mount binding before
    ; any STEP/CANCEL. Other backends keep their pre-BEGIN custody snapshot.
    mov rax,[rsp+8]
    lea rdx,[rel vfs_copy_service_ops]
    cmp rax,rdx
    jne .begin_binding_ready
    mov edi,ebx
    call vfs_mount_ptr
    test rax,rax
    jz .refused
    mov rdx,[rsp+8]
    cmp [rax+fsmount.ops],rdx
    jne .refused
    mov rdx,[rax+fsmount.priv]
    test rdx,rdx
    jz .refused
    mov [rsp+16],rdx
.begin_binding_ready:
    mov  rax, [rsp + 8]
    mov  [rel vfs_copy_live_ops], rax
    mov  rax, [rsp + 16]
    mov  [rel vfs_copy_live_priv], rax
    mov  rax, [rsp + 24]
    mov  [rel vfs_copy_live_entry], rax
    mov  [rel vfs_copy_job + fs_copy_job.mount], ebx
    mov  dword [rel vfs_copy_job + fs_copy_job.durable], FS_DUR_NO
    mov  dword [rel vfs_copy_job + fs_copy_job.pos], 0
    mov  qword [rel vfs_copy_job + fs_copy_job.reason], 0
    mov  dword [rel vfs_copy_job + fs_copy_job.paused], 0   ; smart copy A: every BEGIN starts unheld
    mov  qword [rel vfs_copy_job + fs_copy_job.paused_at], 0
    mov  dword [rel vfs_copy_job + fs_copy_job.failed], 0   ; smart copy B: the list names this job only
    mov  dword [rel vfs_copy_job + fs_copy_job.fail_run], 0
    mov  dword [rel vfs_copy_job + fs_copy_job.same], 0       ; smart copy C
    mov  dword [rel vfs_copy_job + fs_copy_job.replaced], 0   ; E2r-b
    mov  dword [rel vfs_copy_fail_n], 0
    test r14d, FS_COPY_TREE
    jnz  .tree                           ; RCQ-20 S5b: a tree's BEGIN filled its own tail
    mov  dword [rel vfs_copy_job + fs_copy_job.tree], 0
    mov  dword [rel vfs_copy_job + fs_copy_job.files], 0
    mov  dword [rel vfs_copy_job + fs_copy_job.skipped], 0
.tree:
    call boot_ms_now
    mov  [rel vfs_copy_job + fs_copy_job.t_start], rax
    cmp  dword [rsp + 36], 0
    je   .start_unheld
    mov  [rel vfs_copy_job + fs_copy_job.paused_at], rax
    mov  dword [rel vfs_copy_job + fs_copy_job.paused], 1
.start_unheld:
    test r15, r15
    jnz  .id                             ; a queued job keeps the id its FSCOPY was given
    inc  qword [rel vfs_copy_seq]
    mov  r15, [rel vfs_copy_seq]
.id:
    mov  [rel vfs_copy_job + fs_copy_job.id], r15
    mov  [rel vfs_copy_fail_job], r15
    mov rax,[rsp+8]
    lea rdx,[rel vfs_copy_service_ops]
    cmp rax,rdx
    jne .service_id_ready
    lea rdi,[rel vfs_copy_job]
    mov rsi,r15
    call vfs_copy_service_bind_job
    test eax,eax
    jnz .refused
.service_id_ready:
    test r14d, FS_COPY_HOLD_PARTIAL
    jz .partial_bound
    ; NT/exFAT BEGIN may have produced its private file already. BEGIN's ordinary
    ; bookkeeping above clears pause; install the actual hold only now, with ID.
    cmp qword [rel vfs_partial_record + fs_copy_partial.stage], 3
    jne .partial_bound
    call boot_ms_now
    mov [rel vfs_copy_job + fs_copy_job.paused_at], rax
    mov dword [rel vfs_copy_job + fs_copy_job.paused], 1
.partial_bound:
    cmp  dword [rel vfs_ask_child_begin], 0
    jne  .asked                          ; E2: a child BEGIN belongs to the ask job running it
    mov  qword [rel vfs_ask_job], 0
    mov  dword [rel vfs_ask_phase], 0
    test r14d, FS_CMODE_ASK
    jnz  .ask_job
    test r14d, FS_CMODE_REPLACE
    jz   .asked
    test r14d, FS_COPY_TREE
    jz   .asked                          ; E2r-b2: a replace-older TREE asks for the files it cannot decide
.ask_job:
    mov  [rel vfs_ask_job], r15
    mov  dword [rel vfs_ask_phase], FS_ASK_WALK
.asked:
    mov  rax, r15
    cmp  dword [rel vfs_ask_child_begin], 0
    jne  .out                           ; an ASK child keeps the original job's scan binding
    mov  rdi, r15
    mov  esi, ebx
    cmp  qword [rsp], 0
    je   .paths_same
    mov  esi, [rel vfs_copy_between_sh]
.paths_same:
    mov  edx, ebx
    mov  rcx, r12
    mov  r8, r13
    call vfs_copy_paths_note
    mov  rax, r15
    test r14d, FS_COPY_TREE
    jz   .no_scan
    mov  [rel vfs_scan_job], r15         ; E1: the scan now belongs to this job
    jmp  .out
.ask_waiting:                            ; E2: nothing to walk; its one item waits (vfs_ask_top stored it)
    mov  qword [rel vfs_copy_item_phase], 0 ; no backend file while the conflict waits
    mov  dword [rel vfs_copy_job + fs_copy_job.state], FS_JOB_RUNNING
    mov  dword [rel vfs_copy_job + fs_copy_job.error], 0
    mov  [rel vfs_copy_job + fs_copy_job.mount], ebx
    mov  qword [rel vfs_copy_job + fs_copy_job.done], 0
    mov  qword [rel vfs_copy_job + fs_copy_job.total], 0
    mov  qword [rel vfs_copy_job + fs_copy_job.t_end], 0
    mov  qword [rel vfs_copy_job + fs_copy_job.dev], 0
    mov  dword [rel vfs_copy_job + fs_copy_job.durable], FS_DUR_NO
    mov  dword [rel vfs_copy_job + fs_copy_job.preserved], FS_PRES_NONE
    mov  dword [rel vfs_copy_job + fs_copy_job.kept], 0
    mov  dword [rel vfs_copy_job + fs_copy_job.pos], 0
    mov  qword [rel vfs_copy_job + fs_copy_job.reason], 0
    mov  dword [rel vfs_copy_job + fs_copy_job.paused], 0
    mov  qword [rel vfs_copy_job + fs_copy_job.paused_at], 0
    mov  dword [rel vfs_copy_job + fs_copy_job.failed], 0
    mov  dword [rel vfs_copy_job + fs_copy_job.fail_run], 0
    mov  dword [rel vfs_copy_job + fs_copy_job.same], 0
    mov  dword [rel vfs_copy_job + fs_copy_job.replaced], 0
    mov  dword [rel vfs_copy_job + fs_copy_job.files], 0
    mov  dword [rel vfs_copy_job + fs_copy_job.skipped], 0
    mov  eax, r14d
    shr  eax, 8                          ; FS_COPY_TREE
    and  eax, 1
    mov  [rel vfs_copy_job + fs_copy_job.tree], eax
    mov  dword [rel vfs_copy_fail_n], 0
    mov  qword [rel vfs_copy_live_ops], 0   ; no backend binding: nothing steps until a child BEGIN
    mov  qword [rel vfs_copy_live_priv], 0
    mov  qword [rel vfs_copy_live_entry], 0
    mov  r11, [rel blk_flush_failures]
    mov  [rel vfs_copy_job + fs_copy_job.flush_fails], r11d
    mov  dword [rel vfs_ask_durable], FS_DUR_NO
    call boot_ms_now
    mov  [rel vfs_copy_job + fs_copy_job.t_start], rax
    test r15, r15
    jnz  .ask_id
    inc  qword [rel vfs_copy_seq]
    mov  r15, [rel vfs_copy_seq]
.ask_id:
    mov  [rel vfs_copy_job + fs_copy_job.id], r15
    mov  [rel vfs_copy_fail_job], r15
    mov  [rel vfs_ask_job], r15
    mov  dword [rel vfs_ask_phase], FS_ASK_WAITING
    cmp  dword [rsp + 32], 0
    je   .ask_wait
    call vfs_ask_next                    ; E2r-b: its one item answered skip: DONE, SKIPPED=1, nothing written
.ask_wait:
    mov  rdi, r15
    mov  esi, ebx                       ; top-level ASK is same-volume only
    mov  edx, ebx
    mov  rcx, r12
    mov  r8, r13
    call vfs_copy_paths_note
    mov  rax, r15
    jmp  .no_scan
.refused:                                ; E2r-b: a single-file REPLACE BEGIN that did not replace (verdict 0 not
    test r14d, FS_CMODE_REPLACE          ;   older, 2 undecided) becomes an ask job of that one item: skipped
    jz   .fail                           ;   as answered, or waiting for an answer (never replaced silently).
    test r14d, FS_COPY_TREE              ;   A child BEGIN's refusal is vfs_ask_next's to decide.
    jnz  .fail
    cmp  dword [rel vfs_ask_child_begin], 0
    jne  .fail
    cmp  qword [rsp], 0
    jne  .fail
    mov  eax, [rel vfs_copy_replace_verdict]
    test eax, eax
    jz   .verdict
    cmp  eax, 2
    jne  .fail
.verdict:
    mov  [rsp + 32], eax
    mov  edi, ebx
    mov  rsi, r12
    mov  rdx, r13
    mov  ecx, r14d
    call vfs_ask_top
    test rax, rax
    jle  .fail                           ; (the name free again, or no room: the refusal stands)
    cmp  dword [rsp + 32], 0
    jne  .undecided
    mov  dword [rel vfs_ask_items + fs_copy_wait.answer], FS_CMODE_SKIP
    mov  dword [rsp + 32], 1
    jmp  .ask_waiting
.undecided:
    mov  dword [rsp + 32], 0
    jmp  .ask_waiting
.fail:
    mov  rax, -1
.no_scan:
    cmp  dword [rel vfs_ask_child_begin], 0
    jne  .out                           ; file/refused children must not clear the job's scan
    mov  dword [rel vfs_scan_status], FS_SCAN_NONE   ; E1: a file job, or no job: no scan (the last one's is gone)
    mov  qword [rel vfs_scan_job], 0
.out:
    add  rsp, 40
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; vfs_copy_enqueue(EDI=handle,RSI=src Z path,RDX=dst Z path,ECX=FS_CMODE_*) -> RAX the queued job's id /
;   -1 no such mount / -3 the queue is full / -4 a path does not fit a queued record (FS_QPATH_CAP).
;   RCQ-20 S5a: only after vfs_copy_start_mode answered -2, for a request its command admitted. Nothing
;   is read or written on the volume until its BEGIN (vfs_copy_dequeue).
vfs_copy_enqueue:
    test ecx, FS_COPY_HOLD_PARTIAL
    jz .ordinary
    mov rax, -1                       ; this boundary requires a fresh active BEGIN
    ret
.ordinary:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  ebx, edi
    mov  r12, rsi
    mov  r13, rdx
    mov  r14d, ecx
    mov  eax, [rel vfs_copy_job + fs_copy_job.queued]
    cmp  eax, FS_QUEUE_MAX
    jae  .full
    imul eax, eax, fs_copy_qrec_size
    lea  r15, [rel vfs_copy_queue]
    add  r15, rax
    lea  rdi, [r15 + fs_copy_qrec.src]
    mov  rsi, r12
    call vfs_copy_qpath
    test eax, eax
    jnz  .long
    lea  rdi, [r15 + fs_copy_qrec.dst]
    mov  rsi, r13
    call vfs_copy_qpath
    test eax, eax
    jnz  .long
    mov  edi, ebx
    call vfs_mount_ptr
    test rax, rax
    jz   .fail
    mov  rcx, [rax + fsmount.ops]
    mov  [r15 + fs_copy_qrec.ops], rcx
    mov  rcx, [rax + fsmount.priv]
    mov  [r15 + fs_copy_qrec.priv], rcx
    mov  [r15 + fs_copy_qrec.handle], ebx
    mov  [r15 + fs_copy_qrec.mode], r14d
    mov  edi, 2
    mov  rsi, r15
    call vfs_copy_stamp                  ; records the medium's identity in .ident
    mov  rdi, r15
    xor  esi, esi
    mov  edx, fs_copy_job_size
    call memset                          ; its report starts clean
    mov  dword [r15 + fs_copy_job.state], FS_JOB_QUEUED
    mov  qword [r15 + fs_copy_job.total], FS_TOTAL_UNKNOWN
    test r14d, FS_COPY_TREE
    setnz al
    movzx eax, al
    mov  [r15 + fs_copy_job.tree], eax   ; RCQ-20 S5b: FSJOB names a queued tree as one
    mov  [r15 + fs_copy_job.mount], ebx
    mov  eax, [rel vfs_copy_job + fs_copy_job.queued]
    inc  eax
    mov  [r15 + fs_copy_job.pos], eax
    mov  [rel vfs_copy_job + fs_copy_job.queued], eax
    call boot_ms_now
    mov  [r15 + fs_copy_job.t_start], rax
    inc  qword [rel vfs_copy_seq]
    mov  rax, [rel vfs_copy_seq]
    mov  [r15 + fs_copy_job.id], rax
    jmp  .out
.full:
    mov  rax, -3
    jmp  .out
.long:
    mov  rax, -4
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

; vfs_copy_qpath(RDI = a record's path field, RSI = a Z path) -> EAX 0 / -1: it does not fit
;   FS_QPATH_CAP with its NUL (a bounded scan; the caller's path is never read past the cap).
vfs_copy_qpath:
    xor  ecx, ecx
.byte:
    mov  al, [rsi + rcx]
    mov  [rdi + rcx], al
    test al, al
    jz   .fits
    inc  ecx
    cmp  ecx, FS_QPATH_CAP
    jb   .byte
    mov  eax, -1
    ret
.fits:
    xor  eax, eax
    ret

; vfs_copy_dequeue() -> EAX the job state. RCQ-20 S5a: the active job has ended; BEGIN the head of
;   the queue, only on the mount its command admitted (the same handle, ops and private context, and
;   the medium the stamp hook recorded), else it ends FAILED mount_changed with no BEGIN. A refused BEGIN ends that
;   job FAILED with its reason, as the latest job report; the next one waits for the next tick.
vfs_copy_dequeue:
    push rbx
    push r12
    sub  rsp, 8
    lea  rbx, [rel vfs_copy_queue]
    lock inc qword [rel vfs_write_generation]   ; RCQ-39 F-a: a BEGIN, whatever its result
    mov  dword [rel vfs_copy_refusal], FS_CREF_MOUNT_CHANGED
    mov  edi, [rbx + fs_copy_qrec.handle]
    call vfs_mount_ptr
    test rax, rax
    jz   .refused
    mov  rcx, [rax + fsmount.ops]
    cmp  rcx, [rbx + fs_copy_qrec.ops]
    jne  .refused
    mov  rcx, [rax + fsmount.priv]
    cmp  rcx, [rbx + fs_copy_qrec.priv]
    jne  .refused
    mov  edi, 3
    mov  rsi, rbx
    call vfs_copy_stamp                  ; 0: the same medium (no hook: changed)
    test eax, eax
    jnz  .refused
    mov  dword [rel vfs_copy_refusal], 0
    xor  edi, edi
    mov  rsi, rbx
    call vfs_copy_stamp                  ; before the BEGIN: the reason channel starts clear
    mov  r10d, FS_COPY_BEGIN
    cmp  dword [rbx + fs_copy_qrec.carry + fs_copy_carry.kind], FS_CARRY_EXT4
    je   .carried
    cmp  dword [rbx + fs_copy_qrec.carry + fs_copy_carry.kind], FS_CARRY_FAT_SCRATCH
    jne  .begin                          ; (stamp op 3 above refused a scratch kind on any other mount)
.carried:
    lea  rax, [rbx + fs_copy_qrec.carry]
    mov  [rel vfs_copy_job + fs_copy_job.carry], rax   ; RCQ-20 S5c: the one writer; its consumer clears it
    mov  r10d, FS_COPY_BEGIN_CARRIED     ; only here: an ext4 or FAT scratch record (FAT DATA refuses it: BAD_ARG)
.begin:
    mov  edi, [rbx + fs_copy_qrec.handle]
    lea  rsi, [rbx + fs_copy_qrec.src]
    lea  rdx, [rbx + fs_copy_qrec.dst]
    mov  r9d, [rbx + fs_copy_qrec.mode]
    mov  rax, [rbx + fs_copy_qrec.job + fs_copy_job.id]
    xor  r11d, r11d
    call vfs_copy_begin
    mov  qword [rel vfs_copy_job + fs_copy_job.carry], 0   ; (a BEGIN refused before its consumer)
    test rax, rax
    jns  .pop
.refused:
    mov  r12d, [rel vfs_copy_job + fs_copy_job.queued]
    lea  rdi, [rel vfs_copy_job]         ; the record becomes the latest job report
    mov  rsi, rbx
    mov  edx, fs_copy_job_size
    call memcpy
    mov  [rel vfs_copy_job + fs_copy_job.queued], r12d   ; (a record's own count is 0)
    mov  dword [rel vfs_copy_job + fs_copy_job.state], FS_JOB_FAILED
    mov  dword [rel vfs_copy_job + fs_copy_job.pos], 0
    call boot_ms_now
    mov  [rel vfs_copy_job + fs_copy_job.t_end], rax
    mov  edi, 1
    lea  rsi, [rel vfs_copy_job]
    call vfs_copy_stamp                  ; names its reason in vfs_copy_job.reason
.pop:
    lea  rdi, [rbx + fs_copy_qrec.carry] ; S5c: a carry never outlives its one dequeue
    xor  esi, esi
    mov  edx, fs_copy_carry_size
    call memset
    xor  ecx, ecx
    call vfs_copy_qremove
    mov  eax, [rel vfs_copy_job + fs_copy_job.state]
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; vfs_copy_stamp(EDI, RSI = a queue record) -> EAX: the command layer's hook (vfs_copy_stamp_hook,
;   set before it queues a job). The VFS never reads a backend's own state or error codes.
;   0: RSI = a queued record whose BEGIN is next; 1: RSI = a job that ended before it ran: name its reason (.reason);
;   2: record the record's medium identity (.ident), session (.session) and an ext4 carry (.carry, S5c);
;   3: EAX 0 = the same medium, else changed (an ext4 record's hook may name a narrower vfs_copy_refusal);
;   4: EAX 0 = the record still holds (its session, or locked; S5c ext4: and its carry), else the FS_CREF_*
;   reason it is dropped with.
vfs_copy_stamp:
    mov  rax, [rel vfs_copy_stamp_hook]
    test rax, rax
    jz   .none
    jmp  rax
.none:
    mov  eax, 1                          ; no hook: never "the same medium"
    ret

; vfs_copy_session_sweep() - RCQ-20 S5a (rc-sec 13:10:12, root 13:13:36): every pending job whose
;   session ended (stamp op 4) is dropped with no backend call: FAILED session_ended, readable only
;   through vfs_copy_dropped_status (its own request key), never by job id. Clobbers caller-saved.
;   RCQ-20 S5c: an ext4 job whose carry no longer holds is dropped the same way, with the hook's reason.
vfs_copy_session_sweep:
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 8
    xor  ebx, ebx
.scan:
    cmp  ebx, [rel vfs_copy_job + fs_copy_job.queued]
    jae  .out
    imul r12d, ebx, fs_copy_qrec_size
    lea  rax, [rel vfs_copy_queue]
    add  r12, rax
    mov  edi, 4
    mov  rsi, r12
    call vfs_copy_stamp
    test eax, eax
    jnz  .drop
    inc  ebx
    jmp  .scan
.drop:
    mov  r14d, eax                       ; the reason (FS_CREF_*)
    mov  eax, [rel vfs_copy_dropped_next]
    inc  dword [rel vfs_copy_dropped_next]
    and  eax, FS_QUEUE_MAX - 1
    imul r13d, eax, fs_copy_job_size
    lea  rax, [rel vfs_copy_dropped]
    add  r13, rax
    mov  rdi, r13
    mov  rsi, r12
    mov  edx, fs_copy_job_size
    call memcpy
    mov  dword [r13 + fs_copy_job.state], FS_JOB_FAILED
    mov  dword [r13 + fs_copy_job.pos], 0
    call boot_ms_now
    mov  [r13 + fs_copy_job.t_end], rax
    mov  r12d, [rel vfs_copy_refusal]    ; (the reason channel of a request in flight)
    mov  [rel vfs_copy_refusal], r14d
    mov  edi, 1
    mov  rsi, r13
    call vfs_copy_stamp
    mov  [rel vfs_copy_refusal], r12d
    mov  ecx, ebx
    call vfs_copy_qremove                ; the next one moves into this index
    jmp  .scan
.out:
    add  rsp, 8
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; vfs_copy_dropped_status(RDI = job id) -> RAX the record of a pending job a session change dropped / 0
vfs_copy_dropped_status:
    test rdi, rdi
    jz   .none
    lea  rax, [rel vfs_copy_dropped]
    mov  ecx, FS_QUEUE_MAX
.scan:
    cmp  rdi, [rax + fs_copy_job.id]
    je   .out
    add  rax, fs_copy_job_size
    dec  ecx
    jnz  .scan
.none:
    xor  eax, eax
.out:
    ret

; vfs_copy_qremove(ECX = a queue index) - drops that record; the ones behind it move up.
vfs_copy_qremove:
    push rbx
    push r12
    sub  rsp, 8
    mov  ebx, ecx
    mov  r12d, [rel vfs_copy_job + fs_copy_job.queued]
    dec  r12d
    mov  [rel vfs_copy_job + fs_copy_job.queued], r12d
.shift:
    cmp  ebx, r12d
    jae  .last
    imul edi, ebx, fs_copy_qrec_size
    lea  rax, [rel vfs_copy_queue]
    add  rdi, rax
    lea  rsi, [rdi + fs_copy_qrec_size]
    mov  edx, fs_copy_qrec_size
    call memcpy
    imul eax, ebx, fs_copy_qrec_size
    lea  rcx, [rel vfs_copy_queue]
    inc  ebx
    mov  [rcx + rax + fs_copy_qrec.job + fs_copy_job.pos], ebx
    jmp  .shift
.last:
    imul eax, r12d, fs_copy_qrec_size
    lea  rcx, [rel vfs_copy_queue]
    mov  qword [rcx + rax + fs_copy_qrec.job + fs_copy_job.id], 0   ; never found again
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; vfs_copy_busy() -> EAX 1 while a copy job is running or reclaiming after a
;   cancel/failure (the states vfs_copy_start refuses as active), else 0.
;   RCQ-27 POWER-05: a busy job defers the lid-close Shut down. Clobbers ECX.
;   RCQ-20 S5a: also 1 while jobs are queued (root Q-D): they still owe a run.
vfs_copy_busy:
    xor  eax, eax
    mov  ecx, [rel vfs_copy_job + fs_copy_job.state]
    cmp  ecx, FS_JOB_RUNNING
    jb   .queue
    cmp  ecx, FS_JOB_CANCELLING
    jbe  .busy
.queue:
    cmp  dword [rel vfs_copy_job + fs_copy_job.queued], 0
    je   .out
.busy:
    mov  eax, 1
.out:
    ret

; vfs_copy_tick() -> RAX job state. One bounded backend step while a job is live;
;   RCQ-20 S5a: else, with jobs queued, the next one's BEGIN (one per tick).
;   Smart copy A: a held (FSPAUSE) job takes no copying step and the queue behind it waits;
;   finishing writes (VERIFYING) and a cancel's reclaim still run, so a hold never strands a commit.
vfs_copy_tick:
    sub  rsp, 8
    call vfs_copy_tick_job
    mov  [rsp], rax
    call vfs_copy_pace_note              ; observe once after the bounded production step
    mov  rax, [rsp]
    add  rsp, 8
    ret
vfs_copy_tick_job:
    cmp  dword [rel vfs_copy_job + fs_copy_job.paused], 0
    je   .live
    cmp  dword [rel vfs_copy_job + fs_copy_job.state], FS_JOB_RUNNING
    jne  .live
    mov  eax, FS_JOB_RUNNING
    ret
.live:
    cmp  dword [rel vfs_ask_phase], FS_ASK_HELD
    jb   .unasked
    cmp  dword [rel vfs_copy_job + fs_copy_job.state], FS_JOB_RUNNING
    jne  .unasked                        ; a cancel's reclaim still runs
    cmp  dword [rel vfs_ask_phase], FS_ASK_WAITING
    je   vfs_ask_next                    ; E2: the next answered item, or still waiting
    cmp  dword [rel vfs_ask_phase], FS_ASK_HELD
    jne  .unasked
    mov  eax, FS_JOB_RUNNING             ; E2: held at a full list: no step until an answer
    ret
.unasked:
    mov  eax, [rel vfs_copy_job + fs_copy_job.state]
    cmp  eax, FS_JOB_RUNNING
    jb   .next
    cmp  eax, FS_JOB_CANCELLING
    jbe  .step
.next:
    cmp  dword [rel vfs_copy_job + fs_copy_job.queued], 0
    je   .step
    sub  rsp, 8
    call vfs_copy_session_sweep          ; never BEGIN a job its session's end dropped
    add  rsp, 8
    cmp  dword [rel vfs_copy_job + fs_copy_job.queued], 0
    jne  vfs_copy_dequeue
.step:
    sub  rsp, 8
    call vfs_scan_step                   ; E1: the scan runs ahead of the data (it checks the job itself)
    add  rsp, 8
    mov  ecx, FS_COPY_STEP
    jmp  vfs_copy_op

; vfs_copy_cancel(RDI=job id) -> 0 accepted / -1 no such live job
;   RCQ-20 S5a: a queued job is dropped without a backend call; its report (CANCELLED)
;   stays readable in vfs_copy_qended until another queued job is cancelled.
vfs_copy_cancel:
    test rdi, rdi
    jz   .none
    cmp  rdi, [rel vfs_copy_job + fs_copy_job.id]
    jne  .queued
    cmp  dword [rel vfs_ask_phase], FS_ASK_WAITING
    je   .ask_waiting
    mov  ecx, FS_COPY_CANCEL
    call vfs_copy_op
    cmp  eax, FS_JOB_CANCELLING
    jne  .none
    call vfs_copy_unhold                 ; smart copy A: an accepted cancel ends any hold (time counts again)
    xor  eax, eax
    ret
.ask_waiting:                            ; E2: no backend runs: the job ends here, its list dropped
    cmp  dword [rel vfs_copy_job + fs_copy_job.state], FS_JOB_RUNNING
    jne  .none
    call vfs_copy_unhold
    mov  dword [rel vfs_copy_job + fs_copy_job.state], FS_JOB_CANCELLED
    mov  eax, [rel vfs_ask_durable]
    mov  [rel vfs_copy_job + fs_copy_job.durable], eax
    call boot_ms_now
    mov  [rel vfs_copy_job + fs_copy_job.t_end], rax
    mov  dword [rel vfs_ask_phase], 0
    mov  dword [rel vfs_ask_n], 0
    xor  eax, eax
    ret
.queued:
    lea  rsi, [rel vfs_copy_queue]
    xor  ecx, ecx
.scan:
    cmp  ecx, [rel vfs_copy_job + fs_copy_job.queued]
    jae  .none
    cmp  rdi, [rsi + fs_copy_qrec.job + fs_copy_job.id]
    je   .drop
    add  rsi, fs_copy_qrec_size
    inc  ecx
    jmp  .scan
.drop:
    push rcx
    lea  rdi, [rel vfs_copy_qended]
    mov  edx, fs_copy_job_size
    call memcpy
    mov  dword [rel vfs_copy_qended + fs_copy_job.state], FS_JOB_CANCELLED
    mov  dword [rel vfs_copy_qended + fs_copy_job.pos], 0
    call boot_ms_now
    mov  [rel vfs_copy_qended + fs_copy_job.t_end], rax
    mov  ecx, [rsp]
    call vfs_copy_qremove
    pop  rcx
    xor  eax, eax
    ret
.none:
    mov  rax, -1
    ret

; vfs_copy_pause(RDI=job id, ESI=1 hold / 0 release) -> RAX 0 accepted (also when already so) /
;   -1 no live job by that id (unknown, finished or cancelling) / -2 that job is still queued.
;   Smart copy A (spec 7.5.1 #6, within a session): only the live job, while copying or finishing.
;   A hold stops the clock; its release adds the held time to .t_start, so ELAPSED_MS and RATE_BPS
;   count copying time only. Nothing is read or written on any volume here. Clobbers RCX, RDX.
vfs_copy_pause:
    test rdi, rdi
    jz   .none
    cmp  rdi, [rel vfs_copy_job + fs_copy_job.id]
    jne  .queued
    mov  eax, [rel vfs_copy_job + fs_copy_job.state]
    cmp  eax, FS_JOB_RUNNING
    jb   .none
    cmp  eax, FS_JOB_VERIFYING
    ja   .none
    test esi, esi
    jz   .release
    cmp  dword [rel vfs_copy_job + fs_copy_job.paused], 0
    jne  .ok                             ; already held: a retried FSPAUSE changes nothing
    sub  rsp, 8
    call boot_ms_now
    add  rsp, 8
    mov  [rel vfs_copy_job + fs_copy_job.paused_at], rax
    mov  dword [rel vfs_copy_job + fs_copy_job.paused], 1
    jmp  .ok
.release:
    call vfs_copy_unhold                 ; not held: a retried FSRESUME changes nothing
.ok:
    xor  eax, eax
    ret
.queued:
    lea  rdx, [rel vfs_copy_queue]
    xor  ecx, ecx
.scan:
    cmp  ecx, [rel vfs_copy_job + fs_copy_job.queued]
    jae  .none
    cmp  rdi, [rdx + fs_copy_qrec.job + fs_copy_job.id]
    je   .waits
    add  rdx, fs_copy_qrec_size
    inc  ecx
    jmp  .scan
.waits:
    mov  rax, -2
    ret
.none:
    mov  rax, -1
    ret

; Producer-only observation, no authority or I/O. RDI=exact active job,
; RSI=private Z path, RDX=durable bytes, ECX=2 ext append /3 NT or exFAT CREATE.
; A hold can be emitted once. All native writer/current guards run before it.
vfs_copy_partial_ready:
    cmp rdi, [rel vfs_partial_job]
    jne .no
    lea rax, [rel vfs_copy_job]
    cmp rdi, rax
    jne .no
    cmp qword [rel vfs_partial_record + fs_copy_partial.stage], 1
    jne .no
    cmp dword [rdi + fs_copy_job.state], FS_JOB_RUNNING
    jne .no
    cmp ecx, 2
    je .ext
    cmp ecx, 3
    jne .no
    jmp .path
.ext:
    mov rax, [rdi + fs_copy_job.id]
    cmp rax, [rel vfs_partial_record + fs_copy_partial.id]
    jne .no
    test rdx, rdx
    jz .no
    cmp rdx, [rdi + fs_copy_job.done]
    ja .no
.path:
    xor eax, eax
.length:
    cmp byte [rsi + rax], 0
    je .copy
    inc eax
    cmp eax, 256
    jb .length
.no:
    mov rax, -1
    ret
.copy:
    push rbx
    mov rbx, rdi
    mov [rel vfs_partial_record + fs_copy_partial.bytes], rdx
    mov [rel vfs_partial_record + fs_copy_partial.stage], rcx
    lea rdi, [rel vfs_partial_record + fs_copy_partial.path]
    inc eax
    mov edx, eax
    call memcpy
    call boot_ms_now
    mov [rbx + fs_copy_job.paused_at], rax
    mov dword [rbx + fs_copy_job.paused], 1
    xor eax, eax
    pop rbx
    ret

; RDI=exact job ID, RSI=output, RDX=capacity >= fs_copy_partial_size.
; Output unchanged on refusal. Retained facts only: no pointers/read/refresh.
; A consumed, terminal, re-held or unrelated job cannot masquerade as this hold.
vfs_copy_partial_snapshot:
    cmp rdx, fs_copy_partial_size
    jb .no
    test rsi, rsi
    jz .no
    test rdi, rdi
    jz .no
    cmp rdi, [rel vfs_copy_job + fs_copy_job.id]
    jne .no
    cmp rdi, [rel vfs_partial_record + fs_copy_partial.id]
    jne .no
    cmp dword [rel vfs_copy_job + fs_copy_job.state], FS_JOB_RUNNING
    jne .no
    cmp dword [rel vfs_copy_job + fs_copy_job.paused], 1
    jne .no
    mov rax, [rel vfs_partial_record + fs_copy_partial.stage]
    sub eax, 2
    cmp eax, 1
    ja .no
    mov rdi, rsi
    lea rsi, [rel vfs_partial_record]
    mov edx, fs_copy_partial_size
    sub rsp, 8
    call memcpy
    add rsp, 8
    xor eax, eax
    ret
.no:
    mov rax, -1
    ret

; vfs_copy_unhold() -> releases the live job's hold, whatever its state (FSRESUME, an accepted cancel):
;   the held time joins .t_start, including an ask child's saved aggregate start (compose/restore use it).
;   No hold: nothing changes. Clobbers RAX (boot_ms_now's clobbers).
vfs_copy_unhold:
    cmp qword [rel vfs_partial_record + fs_copy_partial.stage], 2
    jb .partial_released
    mov qword [rel vfs_partial_record + fs_copy_partial.stage], 4
.partial_released:
    cmp  dword [rel vfs_copy_job + fs_copy_job.paused], 0
    je   .out
    call boot_ms_now
    sub  rax, [rel vfs_copy_job + fs_copy_job.paused_at]
    cmp  dword [rel vfs_ask_phase], FS_ASK_CHILD
    jne  .parent_clock_ready
    add  [rel vfs_ask_parent + fs_copy_job.t_start], rax
.parent_clock_ready:
    add  [rel vfs_copy_job + fs_copy_job.t_start], rax
    mov  qword [rel vfs_copy_job + fs_copy_job.paused_at], 0
    mov  dword [rel vfs_copy_job + fs_copy_job.paused], 0
.out:
    ret

vfs_copy_op:
    mov  eax, [rel vfs_copy_job + fs_copy_job.state]
    cmp  eax, FS_JOB_RUNNING
    jb   .out
    cmp  eax, FS_JOB_CANCELLING
    ja   .out
    lock inc qword [rel vfs_write_generation]   ; RCQ-39 F-a: a live job writes the destination, whatever its result
    push rcx
    mov  edi, [rel vfs_copy_job + fs_copy_job.mount]
    call vfs_mount_ptr
    pop  rcx
    test rax, rax
    jz   .lost
    mov  r10, [rax + fsmount.ops]
    cmp  r10, [rel vfs_copy_live_ops]
    jne  .lost
    mov  rdx, [rax + fsmount.priv]
    cmp  rdx, [rel vfs_copy_live_priv]
    jne  .lost
    mov  rdx, [r10 + fs_ops.copy]
    cmp  rdx, [rel vfs_copy_live_entry]
    jne  .lost
    mov  rdi, rax
    xor  esi, esi
    xor  edx, edx
    lea  r8, [rel vfs_copy_job]
    call [r10 + fs_ops.copy]
    mov  eax, [rel vfs_copy_job + fs_copy_job.state]
    cmp  eax, FS_JOB_DONE
    jb   .out
.ended:                                  ; this step ended the job
    push rax
    call boot_ms_now
    mov  [rel vfs_copy_job + fs_copy_job.t_end], rax
    pop  rax
    cmp  eax, FS_JOB_DONE
    jne  .asked
    cmp  dword [rel vfs_copy_job + fs_copy_job.durable], FS_DUR_NO
    jne  .asked                          ; the backend reported uncertain
    mov  ecx, FS_DUR_UNCERTAIN
    mov  edx, [rel blk_flush_failures]
    cmp  edx, [rel vfs_copy_job + fs_copy_job.flush_fails]
    jne  .judged                         ; a flush failed during the job, even if a retry then succeeded
    mov  ecx, FS_DUR_UNVERIFIED
    mov  rdx, [rel vfs_copy_job + fs_copy_job.dev]
    test rdx, rdx
    jz   .judged
    mov  rdx, [rdx + dev.info]
    test rdx, rdx
    jz   .judged
    test qword [rdx + blk_info.capabilities], BLKCAP_FLUSH
    jz   .judged                         ; 0 = a legacy mask: blk_flush dispatched, nothing declared
    mov  ecx, FS_DUR_YES
.judged:
    mov  [rel vfs_copy_job + fs_copy_job.durable], ecx
.asked:
    cmp  dword [rel vfs_ask_phase], 0
    je   .out
    mov  eax, [rel vfs_copy_job + fs_copy_job.state]
    jmp  vfs_ask_end                     ; E2: an ask walk or child ended: resolve, wait, or end
.out:
    ret
.lost:
    mov  dword [rel vfs_copy_job + fs_copy_job.state], FS_JOB_FAILED
    ; No call/reclaim on a substituted destination. Retain any old partial for
    ; the backend's ordinary recovery; the next admitted job gets a fresh binding.
    mov  eax, [rel vfs_copy_refusal]
    push rax
    mov  dword [rel vfs_copy_refusal], FS_CREF_MOUNT_CHANGED
    mov  edi, 1
    lea  rsi, [rel vfs_copy_job]
    call vfs_copy_stamp
    pop  rax
    mov  [rel vfs_copy_refusal], eax
    mov  eax, FS_JOB_FAILED
    jmp  .ended

; vfs_copy_note_recovery(EDI=FS_REC_*, ESI=backend, RDX=11-byte 8.3 leaf or 0). RCQ-20 S3: the
; backends call it from their restart recovery (never from a live job's own reclaim); the last one wins.
vfs_copy_note_recovery:
    mov  [rel vfs_copy_recovery + fs_copy_rec.outcome], edi
    mov  [rel vfs_copy_recovery + fs_copy_rec.backend], esi
    mov  byte [rel vfs_copy_recovery + fs_copy_rec.named], 0
    test rdx, rdx
    jz   .out
    mov  rax, [rdx]
    mov  [rel vfs_copy_recovery + fs_copy_rec.name], rax
    mov  eax, [rdx + 7]
    mov  [rel vfs_copy_recovery + fs_copy_rec.name + 7], eax
    mov  byte [rel vfs_copy_recovery + fs_copy_rec.named], 1
.out:
    ret

; vfs_copy_fail_note(RDI=fs_copy_job*, RSI=source path, EDX=its length (-1: nothing to list), ECX=backend
;   error) -> RAX 1 the walk goes on / 0 FS_FAIL_RUN operational failures since the last commit.
;   Backends use vfs_copy_source_note for typed source churn that does not spend this budget.
;   Smart copy B: a tree backend calls it for an entry it did not copy (its own partial already
;   reclaimed) or a node it refused. FAILED counts every one; the first FS_FAIL_MAX whose path fits
;   FS_FAIL_PATH are listed for FSJOBFAIL. Reads and writes nothing on any volume.
vfs_copy_fail_note:
    push rbx
    mov  rbx, rdi
    inc  dword [rbx + fs_copy_job.failed]
    inc  dword [rbx + fs_copy_job.fail_run]
    lea  rax, [rel vfs_copy_job]
    cmp  rbx, rax
    jne  .run                            ; (only the live job is ever listed)
    mov  rax, [rbx + fs_copy_job.id]
    cmp  rax, [rel vfs_copy_fail_job]
    jne  .run
    mov  edx, edx
    cmp  edx, FS_FAIL_PATH
    ja   .run                            ; -1 or too long: counted, not listed
    mov  r8d, [rel vfs_copy_fail_n]
    cmp  r8d, FS_FAIL_MAX
    jae  .run
    imul r8d, r8d, fs_copy_fail_size
    lea  rdi, [rel vfs_copy_fails]
    add  rdi, r8
    mov  [rdi + fs_copy_fail.error], ecx
    mov  eax, [rbx + fs_copy_job.preserved]
    mov  [rdi + fs_copy_fail.pres], eax
    mov  [rdi + fs_copy_fail.len], edx
    mov  byte [rdi + fs_copy_fail.path + rdx], 0
    add  rdi, fs_copy_fail.path
    call memcpy
    inc  dword [rel vfs_copy_fail_n]
.run:
    xor  eax, eax
    cmp  dword [rbx + fs_copy_job.fail_run], FS_FAIL_RUN
    setb al
    pop  rbx
    ret

; vfs_copy_begin_failure(EDI=backend error, ESI=FS_PRES_*): a refusing BEGIN
; publishes only its scalar reason. No job, paths, authority or disk state changes.
; Every VFS BEGIN clears this channel, including ones refused before a backend.
; Preserves all registers. Never used for STEP/CANCEL or a successful BEGIN.
vfs_copy_begin_failure:
    mov  [rel vfs_copy_begin_error], edi
    mov  [rel vfs_copy_begin_pres], esi
    ret

; Same list/count operation for an ASK child that refused BEGIN. The parent may
; still have PRESERVED=none, or a different child's value: use this refusal's
; own format. A typed VFS preflight/name/identity refusal takes precedence.
vfs_copy_refusal_note:
    push rbx
    push r12
    sub  rsp, 8
    mov  ebx, [rel vfs_copy_fail_n]
    mov  ecx, [rel vfs_copy_begin_error]
    mov  r12d, [rel vfs_copy_begin_pres]
    mov  eax, [rel vfs_copy_refusal]
    test eax, eax
    jz   .note
    mov  ecx, eax
    mov  r12d, FS_FAIL_VFS
.note:
    call vfs_copy_fail_note
    cmp  ebx, [rel vfs_copy_fail_n]
    jae  .out                           ; full list or overlong path: count only
    imul ebx, fs_copy_fail_size
    lea  rdx, [rel vfs_copy_fails]
    mov  [rdx + rbx + fs_copy_fail.pres], r12d
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; vfs_copy_source_note: same arguments/list/count as vfs_copy_fail_note,
; but a backend has classified a per-item source outcome (vanished or changed
; twice), after safe reclaim. It neither spends nor resets the I/O failure run.
vfs_copy_source_note:
    push rbx
    mov  rbx, rdi
    call vfs_copy_fail_note
    dec  dword [rbx + fs_copy_job.fail_run] ; undo only this item, preserve earlier faults
    mov  eax, 1
    pop  rbx
    ret

; vfs_copy_fail_entry(RDI=job id, ESI=index) -> RAX fs_copy_fail* / 0, RDX = entries listed for that job.
;   Smart copy B: read-only; the list belongs to the latest job's record only (0 listed for any other).
vfs_copy_fail_entry:
    xor  eax, eax
    xor  edx, edx
    test rdi, rdi
    jz   .out
    cmp  rdi, [rel vfs_copy_fail_job]
    jne  .out
    cmp  rdi, [rel vfs_copy_job + fs_copy_job.id]
    jne  .out
    mov  edx, [rel vfs_copy_fail_n]
    cmp  esi, edx
    jae  .out
    imul eax, esi, fs_copy_fail_size
    lea  rcx, [rel vfs_copy_fails]
    add  rax, rcx
.out:
    ret

; ---- Smart copy E2 (spec 7.5.1 #2, MODE=ask; root 17:23:38): one conflict question ----
; vfs_ask_store(ESI=FS_WK_*, RDX=source path, ECX=its length, R8=destination path, R9D=its length) -> RAX 0
;   stored as item vfs_ask_n (counted) / -1 a path past FS_WAIT_PATH, or no slot left. RAM only.
vfs_ask_store:
    cmp  ecx, FS_WAIT_PATH
    ja   .no
    cmp  r9d, FS_WAIT_PATH
    ja   .no
    mov  eax, [rel vfs_ask_n]
    cmp  eax, FS_WAIT_MAX + FS_WAIT_SPARE
    jae  .no
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdx
    mov  r13d, ecx
    mov  r14, r8
    mov  r15d, r9d
    imul eax, eax, fs_copy_wait_size
    lea  rbx, [rel vfs_ask_items]
    add  rbx, rax
    mov  [rbx + fs_copy_wait.kind], esi
    mov  dword [rbx + fs_copy_wait.answer], 0
    inc  dword [rel vfs_ask_seq]
    mov  eax, [rel vfs_ask_seq]
    mov  [rbx + fs_copy_wait.id], eax
    mov  [rbx + fs_copy_wait.slen], r13d
    mov  [rbx + fs_copy_wait.dlen], r15d
    lea  rdi, [rbx + fs_copy_wait.src]
    mov  rsi, r12
    mov  edx, r13d
    call memcpy
    mov  byte [rbx + fs_copy_wait.src + r13], 0
    lea  rdi, [rbx + fs_copy_wait.dst]
    mov  rsi, r14
    mov  edx, r15d
    call memcpy
    mov  byte [rbx + fs_copy_wait.dst + r15], 0
    inc  dword [rel vfs_ask_n]
    xor  eax, eax
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
.no:
    mov  rax, -1
    ret

; vfs_zlen(RDI = a NUL-terminated path) -> RAX its length; nothing else changes. E2 (vfs_ask_top).
vfs_zlen:
    xor  eax, eax
.scan:
    cmp  byte [rdi + rax], 0
    je   .out
    inc  rax
    jmp  .scan
.out:
    ret

; vfs_mtime_older(RAX = source Unix seconds, EDX = its nanoseconds, RCX = destination Unix seconds, R8D = its
;   nanoseconds; seconds <= 0 = unknown) -> EAX 1: the destination is older by more than 2 s (replace it), 0: not
;   (newer, equal, or within 2 s: FAT keeps 2-second units), 2: unknown on either side (never replaced). E2r, root
;   2026-10-17 21:04:41. Both times are UTC (the readers convert). Clobbers RCX.
vfs_mtime_older:
    test rax, rax
    jle  .unknown
    test rcx, rcx
    jle  .unknown
    sub  rax, rcx                        ; source - destination, whole seconds (both positive)
    cmp  rax, 2
    jg   .older
    jl   .not_older
    cmp  edx, r8d
    ja   .older                          ; exactly 2 s apart and the source later still: more than 2 s
.not_older:
    xor  eax, eax
    ret
.older:
    mov  eax, 1
    ret
.unknown:
    mov  eax, 2
    ret

; vfs_dos_to_unix(EAX = date<<16 | time, the DOS packing of FAT32 DIR_WrtTime/WrtDate and of exFAT
;   timestamps) -> RAX = seconds from 1970-01-01 00:00 to that civil date and time, no zone applied;
;   0 = not a time (date 0, or a field out of range, Feb 29 outside a leap year). E2t (root
;   2026-10-17 21:04:41: every copy carries the source mtime). Clobbers RCX, RDX, R8, R9, R10, R11.
vfs_dos_to_unix:
    mov  r11d, eax                       ; the packed stamp
    mov  r8d, eax
    shr  r8d, 16                         ; date
    jz   .none
    mov  r9d, r8d
    shr  r9d, 5
    and  r9d, 15                         ; month
    jz   .none
    cmp  r9d, 12
    ja   .none
    mov  r10d, r8d
    and  r10d, 31                        ; day
    jz   .none
    shr  r8d, 9
    add  r8d, 1980                       ; year, 1980..2107
    lea  rcx, [rel vfs_month_days]
    movzx edx, byte [rcx + r9 - 1]
    cmp  r10d, edx
    jbe  .clock
    cmp  r9d, 2
    jne  .none
    cmp  r10d, 29
    jne  .none
    test r8d, 3
    jnz  .none                           ; Feb 29: a leap year only
    cmp  r8d, 2100
    je   .none                           ; the one century in range, not a leap year
.clock:
    mov  ecx, r11d
    and  ecx, 31
    cmp  ecx, 29
    ja   .none                           ; 2-second units 0..29
    mov  ecx, r11d
    shr  ecx, 5
    and  ecx, 63
    cmp  ecx, 59
    ja   .none
    movzx ecx, r11w
    shr  ecx, 11
    cmp  ecx, 23
    ja   .none
    ; days from 1970-01-01: years counted from March, from 1600 (a 400-year boundary)
    mov  eax, r8d
    cmp  r9d, 2
    ja   .march
    dec  eax                             ; January and February count with the year before
    add  r9d, 9
    jmp  .years
.march:
    sub  r9d, 3
.years:
    sub  eax, 1600                       ; a = years since 1600-03-01
    mov  r8d, eax
    imul r8d, r8d, 365
    mov  ecx, eax
    shr  ecx, 2
    add  r8d, ecx                        ; + a/4
    xor  edx, edx
    mov  ecx, 100
    div  ecx
    sub  r8d, eax                        ; - a/100
    shr  eax, 2
    add  r8d, eax                        ; + a/400
    imul eax, r9d, 153
    add  eax, 2
    xor  edx, edx
    mov  ecx, 5
    div  ecx
    add  eax, r10d
    dec  eax                             ; day of the March-based year
    add  eax, r8d
    sub  eax, 135080                     ; 1600-03-01 .. 1970-01-01
    imul rax, rax, 86400
    mov  ecx, r11d
    and  ecx, 31
    lea  rax, [rax + rcx * 2]
    mov  ecx, r11d
    shr  ecx, 5
    and  ecx, 63
    imul ecx, ecx, 60
    add  rax, rcx
    movzx ecx, r11w
    shr  ecx, 11
    imul ecx, ecx, 3600
    add  rax, rcx
    ret
.none:
    xor  eax, eax
    ret

vfs_month_days: db 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31

; vfs_ask_top(EDI=handle, RSI=source Z, RDX=destination Z, ECX=mode) -> RAX 0 BEGIN as usual / 1 the job begins
;   waiting whole, its one item stored / -1 that item cannot wait (a path past FS_WAIT_PATH): refused, nothing
;   kept. A new ask job's list starts empty here. The destination is only stat'd: a taken name (for a tree, one
;   that is not a directory to merge into) is the item, FS_WK_FILE for a file, FS_WK_DIR for a tree. A free or
;   unreadable name: the backend's BEGIN decides, as for any job.
vfs_ask_top:
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 8
    mov  ebx, edi
    mov  r12, rsi
    mov  r13, rdx
    mov  r14d, ecx
    xor  eax, eax
    mov  [rel vfs_ask_n], eax
    mov  [rel vfs_ask_seq], eax
    mov  [rel vfs_ask_answer], eax
    mov  [rel vfs_ask_phase], eax
    mov  qword [rel vfs_ask_job], 0
    mov  dword [rel vfs_ask_durable], FS_DUR_NO
    mov  [rel vfs_ask_mount], ebx
    mov  rdi, r13
    call vfs_zlen
    mov  edx, eax
    mov  edi, ebx
    mov  rsi, r13
    lea  rcx, [rel vfs_ask_stat]
    call vfs_stat_path
    test rax, rax
    jnz  .begin
    mov  esi, FS_WK_FILE
    test r14d, FS_COPY_TREE
    jz   .wait
    test dword [rel vfs_ask_stat + fs_stat.reserved], 1
    jnz  .begin                          ; an existing directory: the walk merges into it
    mov  esi, FS_WK_DIR
.wait:
    mov  [rsp], esi
    mov  rdi, r13
    call vfs_zlen
    mov  r9d, eax
    mov  rdi, r12
    call vfs_zlen
    mov  ecx, eax
    mov  esi, [rsp]
    mov  rdx, r12
    mov  r8, r13
    call vfs_ask_store
    test rax, rax
    js   .out
    mov  eax, 1
    jmp  .out
.begin:
    xor  eax, eax
.out:
    add  rsp, 8
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; vfs_copy_wait_note(RDI=fs_copy_job*, ESI=FS_WK_FILE|FS_WK_DIR, RDX=source path, ECX=its length,
;   R8=destination path, R9D=its length) -> RAX 1 taken (it waits, or a skip answer counted it SKIPPED) /
;   2 it cannot wait (a path past FS_WAIT_PATH, a keep-both answer the backend still refused, no spare slot): the
;   caller lists it as refuse mode does. A tree backend calls it for a name conflict under FS_CMODE_ASK. Under a
;   skipsame answer a file arrives compared (or not comparable): it waits as FS_WK_DIFFERS. The item past
;   FS_WAIT_MAX is kept in a spare slot and holds the walk (vfs_copy_tick takes no step) until an answer for
;   every item releases it: nothing is dropped. Reads and writes nothing on any volume.
vfs_copy_wait_note:
    lea  rax, [rel vfs_copy_job]
    cmp  rdi, rax
    jne  .cannot
    mov  eax, [rel vfs_ask_phase]
    cmp  eax, FS_ASK_WALK
    jb   .cannot
    cmp  eax, FS_ASK_HELD
    ja   .cannot
    mov  eax, [rel vfs_ask_answer]
    test eax, FS_CMODE_SKIP
    jnz  .skip
    test eax, FS_CMODE_KEEPBOTH
    jnz  .cannot
    test eax, FS_CMODE_SKIPSAME
    jz   .store
    cmp  esi, FS_WK_FILE
    jne  .store
    mov  esi, FS_WK_DIFFERS
.store:
    push rdi
    call vfs_ask_store
    pop  rdi
    test rax, rax
    js   .cannot
    cmp  dword [rel vfs_ask_n], FS_WAIT_MAX
    jbe  .taken
    mov  dword [rel vfs_ask_phase], FS_ASK_HELD   ; too many conflicts: kept, the walk holds for an answer
.taken:
    mov  eax, 1
    ret
.skip:
    inc  dword [rdi + fs_copy_job.skipped]
    mov  eax, 1
    ret
.cannot:
    mov  eax, 2
    ret

; vfs_copy_answer(RDI=job id, ESI=item id (fs_copy_wait.id), -1 = every item without its own answer and every
;   conflict still to come, EDX=FS_CMODE_SKIP, FS_CMODE_SKIPSAME, FS_CMODE_KEEPBOTH or SKIPSAME|KEEPBOTH) -> RAX 0
;   E2r-b2b: FS_CMODE_REPLACE (replace-older) or REPLACE|FORCE (replace) answers one file, or all currently
;   waiting file items without their own answer. A directory still waits. These snapshot answers, like EACH,
;   neither set the future conflict policy nor release a capacity-held walk (broad skip/keep-both can do that).
;   (the same answer again too: a retry) / -1 no live ask job by that id / -2 no such item waiting / -3 refused:
;   another answer for every item after a final one (only a skipsame one may be followed), another answer for an
;   item already answered, or skipsame for an item a compare cannot settle (a directory, a known difference). While the walk runs, an answer for every item reaches the live backend policy
;   (vfs_copy_policy_ptr) from its next decision and releases a held walk; waiting items resolve after the walk.
vfs_copy_answer:
    test rdi, rdi
    jz   .none
    cmp  rdi, [rel vfs_ask_job]
    jne  .none
    cmp  rdi, [rel vfs_copy_job + fs_copy_job.id]
    jne  .none
    cmp  dword [rel vfs_ask_phase], 0
    je   .none
    cmp  dword [rel vfs_copy_job + fs_copy_job.state], FS_JOB_RUNNING
    jne  .none
    cmp  edx, FS_CMODE_SKIP
    je   .valid
    cmp  edx, FS_CMODE_REPLACE
    je   .replace
    cmp  edx, FS_CMODE_REPLACE | FS_CMODE_FORCE
    je   .replace
    test edx, edx
    jz   .refused
    test edx, ~(FS_CMODE_SKIPSAME | FS_CMODE_KEEPBOTH)
    jnz  .refused
    jmp  .valid
.replace:
    cmp  esi, -1
    jne  .valid
    mov  eax, [rel vfs_ask_answer]
    test eax, eax
    jz   .replace_all
    cmp  eax, FS_CMODE_SKIPSAME
    jne  .refused                        ; a final broad answer keeps its original meaning
.replace_all:                            ; E2r-b2b: stamp the current list; no volume IO or backend policy change
    xor  eax, eax
    lea  rcx, [rel vfs_ask_items]
.replace_item:
    cmp  eax, [rel vfs_ask_n]
    jae  .ok
    cmp  dword [rcx + fs_copy_wait.kind], FS_WK_DIR
    je   .replace_next                   ; a directory can never inherit a replace answer
    cmp  dword [rcx + fs_copy_wait.answer], 0
    jne  .replace_next                   ; preserve individual choices and the active child's answer
    mov  [rcx + fs_copy_wait.answer], edx
.replace_next:
    add  rcx, fs_copy_wait_size
    inc  eax
    jmp  .replace_item
.valid:
    cmp  esi, -1
    jne  .each
    mov  eax, [rel vfs_ask_answer]
    test eax, eax
    jz   .all
    cmp  edx, eax
    je   .ok                             ; a retry
    cmp  eax, FS_CMODE_SKIPSAME
    jne  .refused
.all:
    mov  [rel vfs_ask_answer], edx
    cmp  dword [rel vfs_ask_phase], FS_ASK_HELD
    ja   .ok                             ; the walk is done: resolution reads it
    mov  rax, [rel vfs_copy_policy_ptr]
    test rax, rax
    jz   .release
    and  dword [rax], ~(FS_CMODE_SKIP | FS_CMODE_SKIPSAME | FS_CMODE_KEEPBOTH)
    or   [rax], edx
.release:
    mov  dword [rel vfs_ask_phase], FS_ASK_WALK
    jmp  .ok
.each:
    lea  rcx, [rel vfs_ask_items]
    xor  eax, eax
.find:
    cmp  eax, [rel vfs_ask_n]
    jae  .item_none
    cmp  [rcx + fs_copy_wait.id], esi
    je   .found
    add  rcx, fs_copy_wait_size
    inc  eax
    jmp  .find
.found:
    mov  eax, [rcx + fs_copy_wait.answer]
    test eax, eax
    jz   .unanswered
    cmp  eax, edx
    je   .ok                             ; a retry
    jmp  .refused                        ; (its child may be running under the first answer)
.unanswered:
    cmp  edx, FS_CMODE_SKIPSAME
    jne  .set
    cmp  dword [rcx + fs_copy_wait.kind], FS_WK_FILE
    jne  .refused
.set:
    test edx, FS_CMODE_REPLACE
    jz   .store
    cmp  dword [rcx + fs_copy_wait.kind], FS_WK_DIR
    je   .refused                        ; E2r-b: a file only (a directory item is never replaced)
.store:
    mov  [rcx + fs_copy_wait.answer], edx
.ok:
    xor  eax, eax
    ret
.none:
    mov  rax, -1
    ret
.item_none:
    mov  rax, -2
    ret
.refused:
    mov  rax, -3
    ret

; vfs_copy_wait_entry(RDI=job id, ESI=index) -> RAX fs_copy_wait* / 0, RDX = items waiting (answered or not) for
;   that job. E2: read-only; the list belongs to the live ask job only (0 waiting for any other).
vfs_copy_wait_entry:
    xor  eax, eax
    xor  edx, edx
    test rdi, rdi
    jz   .out
    cmp  rdi, [rel vfs_ask_job]
    jne  .out
    cmp  rdi, [rel vfs_copy_job + fs_copy_job.id]
    jne  .out
    cmp  dword [rel vfs_ask_phase], 0
    je   .out
    mov  edx, [rel vfs_ask_n]
    cmp  esi, edx
    jae  .out
    imul eax, esi, fs_copy_wait_size
    lea  rcx, [rel vfs_ask_items]
    add  rax, rcx
.out:
    ret

; vfs_ask_remove(EDI=index): the items after it move down one; vfs_ask_n counts one less.
vfs_ask_remove:
    push rbx
    push r12
    sub  rsp, 8
    mov  ebx, edi
    lea  r12, [rel vfs_ask_items]
.shift:
    lea  eax, [rbx + 1]
    cmp  eax, [rel vfs_ask_n]
    jae  .last
    imul edi, ebx, fs_copy_wait_size
    add  rdi, r12
    lea  rsi, [rdi + fs_copy_wait_size]
    mov  edx, fs_copy_wait_size
    call memcpy
    inc  ebx
    jmp  .shift
.last:
    dec  dword [rel vfs_ask_n]
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; vfs_ask_restore(): the job's own record back from vfs_ask_parent, RUNNING and not yet durable; the live
;   slot's queue count and carry and any FSPAUSE hold stay as they are now.
vfs_ask_restore:
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 8
    mov  ebx, [rel vfs_copy_job + fs_copy_job.queued]
    mov  r12, [rel vfs_copy_job + fs_copy_job.carry]
    mov  r13d, [rel vfs_copy_job + fs_copy_job.paused]
    mov  r14, [rel vfs_copy_job + fs_copy_job.paused_at]
    lea  rdi, [rel vfs_copy_job]
    lea  rsi, [rel vfs_ask_parent]
    mov  edx, fs_copy_job_size
    call memcpy
    mov  [rel vfs_copy_job + fs_copy_job.queued], ebx
    mov  [rel vfs_copy_job + fs_copy_job.carry], r12
    mov  [rel vfs_copy_job + fs_copy_job.paused], r13d
    mov  [rel vfs_copy_job + fs_copy_job.paused_at], r14
    mov  dword [rel vfs_copy_job + fs_copy_job.state], FS_JOB_RUNNING
    mov  qword [rel vfs_copy_job + fs_copy_job.t_end], 0
    mov  dword [rel vfs_copy_job + fs_copy_job.durable], FS_DUR_NO
    add  rsp, 8
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; vfs_ask_end(EAX = the state the step left) -> EAX the job's state now (vfs_copy_op's tail). A walk that ended
;   DONE with items waiting turns to their resolution (the job stays RUNNING); a child's counts fold into the
;   job, and its item is resolved, waits again (a skipsame compare found a difference), or is listed as a
;   failure (its source path). A walk that failed or was cancelled ends as ever, its list dropped; a cancelled
;   child ends the job CANCELLED.
vfs_ask_end:
    cmp  dword [rel vfs_ask_phase], FS_ASK_CHILD
    je   .child
    cmp  eax, FS_JOB_DONE
    jne  .drop
    cmp  dword [rel vfs_ask_n], 0
    je   .drop
    mov  ecx, [rel vfs_copy_job + fs_copy_job.durable]
    mov  [rel vfs_ask_durable], ecx
    mov  dword [rel vfs_copy_job + fs_copy_job.state], FS_JOB_RUNNING
    mov  qword [rel vfs_copy_job + fs_copy_job.t_end], 0
    mov  dword [rel vfs_copy_job + fs_copy_job.durable], FS_DUR_NO
    mov  dword [rel vfs_ask_phase], FS_ASK_WAITING
    jmp  vfs_ask_next
.drop:
    mov  dword [rel vfs_ask_phase], 0
    mov  dword [rel vfs_ask_n], 0
    ret
.child:
    push rbx
    push r12
    sub  rsp, 8
    mov  ebx, eax
    mov  ecx, [rel vfs_ask_cur]
    imul ecx, ecx, fs_copy_wait_size
    lea  r12, [rel vfs_ask_items]
    add  r12, rcx
    lea  r8, [rel vfs_ask_parent]
    lea  r9, [rel vfs_copy_job]
    mov  rax, [r9 + fs_copy_job.done]
    add  [r8 + fs_copy_job.done], rax
    mov  rax, [r9 + fs_copy_job.total]
    cmp  rax, FS_TOTAL_UNKNOWN
    je   .total_unknown
    cmp  qword [r8 + fs_copy_job.total], FS_TOTAL_UNKNOWN
    je   .totalled
    add  [r8 + fs_copy_job.total], rax
    jmp  .totalled
.total_unknown:
    mov  [r8 + fs_copy_job.total], rax
.totalled:
    mov  eax, [r9 + fs_copy_job.skipped]
    add  [r8 + fs_copy_job.skipped], eax
    mov  eax, [r9 + fs_copy_job.same]
    add  [r8 + fs_copy_job.same], eax
    mov  eax, [r9 + fs_copy_job.replaced]
    add  [r8 + fs_copy_job.replaced], eax
    mov  eax, [r9 + fs_copy_job.failed]
    add  [r8 + fs_copy_job.failed], eax
    cmp  dword [r8 + fs_copy_job.preserved], FS_PRES_NONE
    jne  .pres_kept                      ; a job that began waiting whole takes its first child's
    mov  eax, [r9 + fs_copy_job.preserved]
    mov  [r8 + fs_copy_job.preserved], eax
    mov  rax, [r9 + fs_copy_job.dev]
    mov  [r8 + fs_copy_job.dev], rax
.pres_kept:
    cmp  dword [r8 + fs_copy_job.tree], 0
    jne  .kept_tree                      ; a tree's KEPT is its top's (BEGIN's)
    mov  eax, [r9 + fs_copy_job.kept]
    mov  [r8 + fs_copy_job.kept], eax    ; a file job waiting whole: its one child's name
.kept_tree:
    mov  eax, [r9 + fs_copy_job.durable]
    cmp  eax, [rel vfs_ask_durable]
    jbe  .durable_kept
    mov  [rel vfs_ask_durable], eax      ; the worst of the walk's and every child's
.durable_kept:
    cmp  ebx, FS_JOB_CANCELLED
    je   .cancelled
    cmp  ebx, FS_JOB_DONE
    jne  .failed
    mov  eax, [r9 + fs_copy_job.files]
    cmp  dword [r9 + fs_copy_job.tree], 0
    jne  .files
    xor  eax, eax
    cmp  dword [r9 + fs_copy_job.same], 0
    jne  .files                          ; skip-same found it equal: nothing copied
    cmp  dword [r9 + fs_copy_job.skipped], 0
    jne  .files                          ; combined compare found it not older: nothing copied
    inc  eax
.files:
    add  [r8 + fs_copy_job.files], eax
    call vfs_ask_restore
    mov  edi, [rel vfs_ask_cur]
    call vfs_ask_remove
    jmp  .next
.failed:
    cmp  dword [rel vfs_copy_differs], 0
    je   .listed
    cmp  dword [r12 + fs_copy_wait.kind], FS_WK_DIR
    je   .listed                         ; (a tree child's files never wait again as one item)
    test dword [r12 + fs_copy_wait.answer], FS_CMODE_REPLACE
    jz   .differs_kind
    cmp  dword [rel vfs_copy_replace_verdict], 2
    je   .wait_again                     ; combined compare: undecided replacement remains a FILE item
.differs_kind:
    mov  dword [r12 + fs_copy_wait.kind], FS_WK_DIFFERS   ; skipsame's compare found a difference:
.wait_again:
    mov  dword [r12 + fs_copy_wait.answer], 0             ;   it waits again, for skip or keep-both
    call vfs_ask_restore
    jmp  .next
.listed:
    mov  ebx, [r9 + fs_copy_job.error]
    call vfs_ask_restore
    lea  rdi, [rel vfs_copy_job]
    lea  rsi, [r12 + fs_copy_wait.src]
    mov  edx, [r12 + fs_copy_wait.slen]
    mov  ecx, ebx
    call vfs_copy_fail_note              ; its source path, as a tree lists an entry it could not copy
    mov  dword [rel vfs_copy_job + fs_copy_job.fail_run], 0
    mov  edi, [rel vfs_ask_cur]
    call vfs_ask_remove
.next:
    mov  dword [rel vfs_ask_phase], FS_ASK_WAITING
    add  rsp, 8
    pop  r12
    pop  rbx
    jmp  vfs_ask_next
.cancelled:
    call vfs_ask_restore
    mov  dword [rel vfs_copy_job + fs_copy_job.state], FS_JOB_CANCELLED
    mov  eax, [rel vfs_ask_durable]
    mov  [rel vfs_copy_job + fs_copy_job.durable], eax
    call boot_ms_now
    mov  [rel vfs_copy_job + fs_copy_job.t_end], rax
    mov  dword [rel vfs_ask_phase], 0
    mov  dword [rel vfs_ask_n], 0
    mov  eax, FS_JOB_CANCELLED
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; vfs_ask_next() -> EAX the job's state (phase FS_ASK_WAITING, from vfs_copy_tick or a child's end). Counts what a
;   skip answer names as SKIPPED, begins the first other answered item as a child BEGIN under the job's id (phase
;   FS_ASK_CHILD: a file as FSCOPY's one file, a directory as TREE=1, under the answer's policy), or waits; with
;   nothing left the job ends DONE. A child its BEGIN refuses is listed as a failure, nothing written.
vfs_ask_next:
    push rbx
    push r12
    push r13
    xor  ebx, ebx
.item:
    cmp  ebx, [rel vfs_ask_n]
    jae  .none_ready
    imul eax, ebx, fs_copy_wait_size
    lea  r12, [rel vfs_ask_items]
    add  r12, rax
    mov  eax, [r12 + fs_copy_wait.answer]
    test eax, eax
    jnz  .answered
    mov  eax, [rel vfs_ask_answer]
    cmp  eax, FS_CMODE_SKIPSAME
    jne  .answered
    cmp  dword [r12 + fs_copy_wait.kind], FS_WK_FILE
    jne  .next                           ; a compare cannot settle it: it waits for skip or keep-both
.answered:
    test eax, eax
    jz   .next
    test eax, FS_CMODE_SKIP
    jz   .child
    inc  dword [rel vfs_copy_job + fs_copy_job.skipped]
    mov  edi, ebx
    call vfs_ask_remove
    jmp  .item
.next:
    inc  ebx
    jmp  .item
.none_ready:
    mov  eax, FS_JOB_RUNNING
    cmp  dword [rel vfs_ask_n], 0
    jne  .out                            ; unanswered items: the job waits
    mov  eax, [rel vfs_ask_durable]
    mov  [rel vfs_copy_job + fs_copy_job.durable], eax
    call boot_ms_now
    mov  [rel vfs_copy_job + fs_copy_job.t_end], rax
    mov  dword [rel vfs_copy_job + fs_copy_job.state], FS_JOB_DONE
    mov  dword [rel vfs_ask_phase], 0
    mov  eax, FS_JOB_DONE
    jmp  .out
.child:
    mov  r13d, eax
    and  r13d, FS_CMODE_SKIPSAME | FS_CMODE_KEEPBOTH | FS_CMODE_REPLACE | FS_CMODE_FORCE
    cmp  dword [r12 + fs_copy_wait.kind], FS_WK_DIR
    jne  .begin
    or   r13d, FS_COPY_TREE
.begin:
    mov  [rel vfs_ask_cur], ebx
    lea  rdi, [rel vfs_ask_parent]
    lea  rsi, [rel vfs_copy_job]
    mov  edx, fs_copy_job_size
    call memcpy
    mov  eax, [rel vfs_copy_fail_n]
    mov  [rel vfs_ask_fail_n], eax
    mov  dword [rel vfs_copy_differs], 0
    mov  dword [rel vfs_ask_child_begin], 1
    mov  dword [rel vfs_ask_phase], FS_ASK_CHILD
    lock inc qword [rel vfs_write_generation]
    mov  dword [rel vfs_copy_refusal], 0
    mov  edi, [rel vfs_ask_mount]
    lea  rsi, [r12 + fs_copy_wait.src]
    lea  rdx, [r12 + fs_copy_wait.dst]
    mov  r9d, r13d
    mov  rax, [rel vfs_ask_job]
    mov  r10d, FS_COPY_BEGIN
    xor  r11d, r11d
    call vfs_copy_begin
    mov  dword [rel vfs_ask_child_begin], 0
    mov  ecx, [rel vfs_ask_fail_n]
    mov  [rel vfs_copy_fail_n], ecx      ; the job's failure list goes on
    test rax, rax
    js   .refused
    mov  eax, FS_JOB_RUNNING
    jmp  .out
.refused:
    mov  dword [rel vfs_ask_phase], FS_ASK_WAITING
    call vfs_ask_restore
    test r13d, FS_CMODE_REPLACE
    jz   .refused_same
    mov  eax, [rel vfs_copy_replace_verdict]   ; E2r-b: a replace answer's child that did not replace
    test eax, eax
    jz   .refused_newer
    cmp  eax, 2
    jne  .refused_listed
    mov  dword [r12 + fs_copy_wait.answer], 0  ; undecided, or not a file it may replace: it waits again
    jmp  .next
.refused_newer:
    inc  dword [rel vfs_copy_job + fs_copy_job.skipped]   ; not older: skipped, counted (nothing written)
    mov  edi, ebx
    call vfs_ask_remove
    jmp  .item
.refused_same:
    test r13d, FS_CMODE_SKIPSAME
    jz   .refused_listed
    cmp  dword [rel vfs_copy_differs], 0
    je   .refused_listed
    mov  dword [r12 + fs_copy_wait.kind], FS_WK_DIFFERS   ; skipsame's BEGIN found the name taken by another
    mov  dword [r12 + fs_copy_wait.answer], 0             ;   size or kind: it waits again, for skip or keep-both
    jmp  .next
.refused_listed:
    lea  rdi, [rel vfs_copy_job]
    lea  rsi, [r12 + fs_copy_wait.src]
    mov  edx, [r12 + fs_copy_wait.slen]
    call vfs_copy_refusal_note
    mov  dword [rel vfs_copy_job + fs_copy_job.fail_run], 0
    mov  edi, ebx
    call vfs_ask_remove
    jmp  .item
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; vfs_ask_compose() -> RAX vfs_ask_view: while a child copies, the child's record with the job's own start, kind
;   and totals added (FSJOB, Explorer and vfs_copy_snapshot read it). Preserves every register but RAX.
vfs_ask_compose:
    push rdi
    push rsi
    push rdx
    push rcx
    push r8
    lea  rdi, [rel vfs_ask_view]
    lea  rsi, [rel vfs_copy_job]
    mov  edx, fs_copy_job_size
    call memcpy
    lea  r8, [rel vfs_ask_parent]
    lea  rdi, [rel vfs_ask_view]
    mov  rax, [r8 + fs_copy_job.t_start]
    mov  [rdi + fs_copy_job.t_start], rax
    mov  eax, [r8 + fs_copy_job.tree]
    mov  [rdi + fs_copy_job.tree], eax
    test eax, eax
    jz   .kept                           ; a file job waiting whole: its one child's KEPT
    mov  eax, [r8 + fs_copy_job.kept]
    mov  [rdi + fs_copy_job.kept], eax
.kept:
    mov  rax, [r8 + fs_copy_job.done]
    add  [rdi + fs_copy_job.done], rax
    mov  rax, [r8 + fs_copy_job.total]
    cmp  rax, FS_TOTAL_UNKNOWN
    je   .total
    cmp  qword [rdi + fs_copy_job.total], FS_TOTAL_UNKNOWN
    je   .totalled
    add  rax, [rdi + fs_copy_job.total]
.total:
    mov  [rdi + fs_copy_job.total], rax
.totalled:
    cmp  dword [rel vfs_copy_job + fs_copy_job.tree], 0
    jne  .files
    mov  dword [rdi + fs_copy_job.files], 0   ; a file child counts once it ends
.files:
    mov  eax, [r8 + fs_copy_job.files]
    add  [rdi + fs_copy_job.files], eax
    mov  eax, [r8 + fs_copy_job.skipped]
    add  [rdi + fs_copy_job.skipped], eax
    mov  eax, [r8 + fs_copy_job.same]
    add  [rdi + fs_copy_job.same], eax
    mov  eax, [r8 + fs_copy_job.replaced]
    add  [rdi + fs_copy_job.replaced], eax   ; E2r-b: what earlier children replaced (review F1, 2026-10-18)
    mov  eax, [r8 + fs_copy_job.failed]
    add  [rdi + fs_copy_job.failed], eax
    mov  rax, rdi
    pop  r8
    pop  rcx
    pop  rdx
    pop  rsi
    pop  rdi
    ret

; vfs_copy_check(EDI=source handle, RSI=source Z path, EDX=destination handle, RCX=destination Z path,
;   R8D=FS_CMODE_* | FS_COPY_TREE) -> RAX 0 (vfs_check holds the result) / -1 the source or the destination
;   volume is unreadable / -2 a directory without TREE=1. Smart copy D (FSCHECK, root 13:43): reads only, and
;   only through stat_path / list_dir / info. It visits at most FS_CHECK_ENTRIES nodes (the top one counted)
;   within FS_CHECK_BUDGET_MS; past either, REASON says which and every total is a lower bound. A
;   directory is read FS_CHECK_PAGE entries per listing (vfs_list_skip passes the ones before); a backend
;   that does not page ends the check REASON=ENTRIES past its first page. Each issue is counted; the first
;   FS_CHECK_ISSUES whose source path fits FS_FAIL_PATH are listed (vfs_copy_check_issue).
;   Conflicts follow the copy's policy: refuse/keep-both decide the top (a tree is made whole or not at
;   all); skip-same merges into an existing directory, where each name is a conflict of its own.
;   NEED: the files' bytes in destination clusters, and the directory entries the copy adds, in clusters
;   per directory (a new one at least one); inodes, extent blocks and the journal are not counted.
vfs_copy_check:
    mov  dword [rel vfs_chk_e0], -1
    mov  dword [rel vfs_chk_cap], FS_CHECK_ENTRIES
    mov  qword [rel vfs_chk_ms], FS_CHECK_BUDGET_MS
    mov  dword [rel vfs_chk_resumable], 0
; vfs_copy_check_bounded: the same walk within vfs_chk_cap nodes / vfs_chk_ms; with vfs_chk_resumable,
;   a bound reached is a pause (RAX 1, the walk resumes at vfs_copy_check_resume) instead of a result.
vfs_copy_check_bounded:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8
    mov  [rel vfs_chk_sh], edi
    mov  [rel vfs_chk_dh], edx
    mov  [rel vfs_chk_mode], r8d
    test r8d, FS_CMODE_ASK
    jz   .chk_mode
    and  dword [rel vfs_chk_mode], ~(FS_CMODE_ASK | FS_CMODE_SKIP)
    or   dword [rel vfs_chk_mode], FS_CMODE_SKIPSAME   ; E2: an ask copy merges as skip-same's, its conflicts issues
.chk_mode:
    mov  r12, rsi
    mov  r13, rcx
    mov  rbx, [rel vfs_check + fs_check.id]
    lea  rdi, [rel vfs_check]
    xor  esi, esi
    mov  edx, fs_check_size
    call memset
    inc  rbx
    mov  [rel vfs_check + fs_check.id], rbx
    mov  qword [rel vfs_check + fs_check.free], -1
    mov  eax, [rel vfs_chk_mode]
    and  eax, FS_CMODE_REPLACE
    mov  [rel vfs_check + fs_check.replace_policy], eax
    mov  dword [rel vfs_list_skip], 0
    mov  dword [rel vfs_chk_depth], 0
    mov  dword [rel vfs_chk_topref], 0
    call boot_ms_now
    mov  [rel vfs_chk_t0], rax
    mov  rdi, r12
    lea  rbx, [rel vfs_chk_src]
    call .take_path
    js   .unreadable
    mov  r14d, eax                       ; R14D = the source path's length
    mov  rdi, r13
    lea  rbx, [rel vfs_chk_dst]
    call .take_path
    js   .unreadable
    mov  r15d, eax                       ; R15D = the destination path's length
    mov  edi, [rel vfs_chk_dh]
    lea  rsi, [rel vfs_chk_info]
    call vfs_info
    test rax, rax
    jnz  .unreadable
    mov  eax, [rel vfs_chk_info + fs_info.cluster_bytes]
    test eax, eax
    jnz  .cluster
    mov  eax, 512
.cluster:
    mov  [rel vfs_chk_cb], eax
    mov  rax, [rel vfs_chk_info + fs_info.free_clusters]
    cmp  rax, -1
    je   .free
    mov  ecx, [rel vfs_chk_cb]
    imul rax, rcx
    mov  [rel vfs_check + fs_check.free], rax
.free:
    xor  ecx, ecx                        ; destination format: 1 FAT32, 2 ext, 0 neither
    mov  rsi, [rel vfs_chk_info + fs_info.backend]
    test rsi, rsi
    jz   .kind
    mov  eax, [rsi]
    and  eax, 0xFFFFFF
    cmp  eax, 'fat'
    jne  .not_fat
    mov  ecx, 1
.not_fat:
    cmp  eax, 'ext'
    jne  .kind
    mov  ecx, 2
.kind:
    mov  [rel vfs_chk_kind], ecx
    mov  dword [rel vfs_chk_dmax], FS_TREE_DEPTH_MAX
    cmp  ecx, 1
    jne  .depth_set
    xor  ecx, ecx                        ; FAT32: every path the tree makes stays FD_PATH_DEPTH_MAX components
    xor  edx, edx
.slashes:
    cmp  edx, r15d
    jae  .counted_slashes
    cmp  byte [rbx + rdx], '/'
    jne  .slash_next
    inc  ecx
.slash_next:
    inc  edx
    jmp  .slashes
.counted_slashes:
    mov  eax, FS_CHECK_FAT_COMPONENTS    ; less the destination parent's components (slashes - 1), less 1
    sub  eax, ecx
    jns  .depth_floor                    ; 16 or more slashes leave no level: never a negative limit, which
    xor  eax, eax                        ; the unsigned descent test would read as no limit at all
.depth_floor:
    cmp  eax, FS_TREE_DEPTH_MAX
    jle  .depth_fat
    mov  eax, FS_TREE_DEPTH_MAX
.depth_fat:
    mov  [rel vfs_chk_dmax], eax
.depth_set:
    mov  dword [rel vfs_check + fs_check.entries], 1
    mov  edi, [rel vfs_chk_sh]
    lea  rsi, [rel vfs_chk_src]
    mov  edx, r14d
    lea  rcx, [rel vfs_chk_stat]
    call vfs_stat_path
    test rax, rax
    jnz  .unreadable
    test dword [rel vfs_chk_stat + fs_stat.reserved], 1
    jnz  .top_dir
    ; ---- one file ----
    test dword [rel vfs_chk_mode], FS_COPY_TREE
    jnz  .not_tree                       ; TREE=1 names a directory
    mov  dword [rel vfs_check + fs_check.files], 1
    mov  rax, [rel vfs_chk_stat + fs_stat.size]
    mov  [rel vfs_check + fs_check.bytes], rax
    mov  [rel vfs_chk_fsize], rax
    cmp  dword [rel vfs_chk_kind], 1
    jne  .file_room
    mov  ecx, 0xFFFFFFFF
    cmp  rax, rcx
    ja   .top_too_big
.file_room:
    call .dst_stat
    test eax, eax
    jz   .file_need
    test dword [rel vfs_chk_dstat + fs_stat.reserved], 1
    jnz  .top_policy
    test dword [rel vfs_chk_mode], FS_CMODE_REPLACE
    jz   .top_same
    call .replace_verdict
    cmp  eax, 1
    je   .top_replace
    test eax, eax
    jnz  .top_policy
    inc  dword [rel vfs_check + fs_check.skipped]
    jmp  .complete
.top_replace:
    inc  dword [rel vfs_check + fs_check.replace]
    jmp  .file_need                      ; full fresh allocation: the old file stays until the swap
.top_same:
    test dword [rel vfs_chk_mode], FS_CMODE_SKIPSAME
    jz   .top_policy
    mov  rax, [rel vfs_chk_dstat + fs_stat.size]
    cmp  rax, [rel vfs_chk_fsize]
    jne  .top_policy
    mov  ecx, FS_CHK_SAME
    call .issue
    inc  dword [rel vfs_check + fs_check.same]
    jmp  .complete
.top_policy:
    mov  ecx, FS_CHK_EXISTS
    test dword [rel vfs_chk_mode], FS_CMODE_KEEPBOTH
    jz   .top_refused
    mov  ecx, FS_CHK_RENAME
    call .issue
.file_need:
    mov  rax, [rel vfs_chk_fsize]
    call .clusters
    add  [rel vfs_check + fs_check.need], rax
    jmp  .complete
.top_refused:
    call .issue
    jmp  .complete
.top_too_big:
    mov  ecx, FS_CHK_TOO_BIG
    call .issue
    jmp  .complete
    ; ---- a tree ----
.top_dir:
    test dword [rel vfs_chk_mode], FS_COPY_TREE
    jz   .not_tree
    mov  dword [rel vfs_check + fs_check.dirs], 1
    mov  dword [rel vfs_chk_cmerge], 0
    call .dst_stat
    test eax, eax
    jz   .top_frame
    test dword [rel vfs_chk_mode], FS_CMODE_SKIPSAME | FS_CMODE_REPLACE
    jz   .tree_policy
    test dword [rel vfs_chk_dstat + fs_stat.reserved], 1
    jz   .tree_policy
    mov  dword [rel vfs_chk_cmerge], 1   ; skip-same: the copy merges into the existing directory
    jmp  .top_frame
.tree_policy:
    mov  ecx, FS_CHK_EXISTS              ; refused whole: the walk still totals what it names
    mov  dword [rel vfs_chk_topref], 1
    test dword [rel vfs_chk_mode], FS_CMODE_KEEPBOTH
    jz   .tree_policy_note
    mov  dword [rel vfs_chk_topref], 0
    mov  ecx, FS_CHK_RENAME
.tree_policy_note:
    call .issue
.top_frame:
    lea  rbx, [rel vfs_chk_frames]
    mov  [rbx + fs_check_frame.slen], r14d
    mov  [rbx + fs_check_frame.dlen], r15d
    mov  dword [rbx + fs_check_frame.index], 0
    mov  eax, [rel vfs_chk_cmerge]
    mov  [rbx + fs_check_frame.merge], eax
    mov  qword [rbx + fs_check_frame.ebytes], 0
    mov  dword [rel vfs_chk_depth], 1
.page:
    call .budget
    jnz  .stop
    mov  eax, [rel vfs_chk_depth]
    dec  eax
    imul eax, eax, fs_check_frame_size
    lea  rbx, [rel vfs_chk_frames]
    add  rbx, rax                        ; RBX = the directory being read
    mov  r14d, [rbx + fs_check_frame.slen]
    mov  r15d, [rbx + fs_check_frame.dlen]
    lea  rax, [rel vfs_chk_src]
    mov  byte [rax + r14], 0
    lea  rax, [rel vfs_chk_dst]
    mov  byte [rax + r15], 0
    mov  eax, [rbx + fs_check_frame.index]
    mov  [rel vfs_list_skip], eax
    mov  edi, [rel vfs_chk_sh]
    lea  rsi, [rel vfs_chk_src]
    mov  edx, r14d
    lea  rcx, [rel vfs_chk_page]
    mov  r8d, FS_CHECK_PAGE
    lea  r9, [rel vfs_chk_lres]
    call vfs_list_dir
    mov  ecx, [rel vfs_list_skip]
    mov  dword [rel vfs_list_skip], 0
    test rax, rax
    jnz  .unlisted
    xor  r12d, r12d                      ; R12D = entry of this page
    test ecx, ecx
    jz   .paged
    cmp  ecx, [rbx + fs_check_frame.index]
    jne  .stop_entries                   ; the directory shrank under the check
    cmp  ecx, FS_CHECK_PAGE
    jae  .stop_entries                   ; a backend that does not page: its first page only
    mov  r12d, ecx                       ; it listed from the first entry: go on at .index
.paged:
    cmp  dword [rel vfs_chk_lres + fs_list_result.names_short], 0
    jne  .stop_entries
.entry:
    cmp  r12d, [rel vfs_chk_lres + fs_list_result.count]
    jae  .page_end
    call .budget
    jnz  .stop
    mov  eax, [rel vfs_check + fs_check.entries]
    cmp  eax, [rel vfs_chk_cap]
    jae  .cap                            ; before .index moves: a resumed walk reads this entry next
    inc  dword [rbx + fs_check_frame.index]
    inc  dword [rel vfs_check + fs_check.entries]
    mov  eax, r12d
    inc  r12d
    shl  eax, 5                          ; fs_dirent_size
    lea  r13, [rel vfs_chk_page]
    add  r13, rax                        ; R13 = the entry
    mov  rdi, r13
    call vfs_dirent_name
    mov  [rel vfs_chk_nptr], rax
    mov  rdi, rax
    call .length
    mov  [rel vfs_chk_nlen], eax
    ; the child's paths: <dir>/<name> on both sides (the source's within the check's buffer)
    lea  ecx, [r14 + rax + 1]
    cmp  ecx, FS_CHECK_PATH
    jae  .child_path_long
    lea  ecx, [r15 + rax + 1]
    cmp  ecx, FS_CHECK_PATH
    jae  .child_path_long
    lea  rdi, [rel vfs_chk_src]
    mov  ecx, r14d
    call .append
    mov  [rel vfs_chk_cslen], eax
    lea  rdi, [rel vfs_chk_dst]
    mov  ecx, r15d
    call .append
    mov  [rel vfs_chk_cdlen], eax
    mov  eax, [r13 + fs_dirent.flags]
    test eax, FS_DIRENT_DIR
    jnz  .child_dir
    test eax, ~(FS_DIRENT_LONG_NAME | FS_DIRENT_LONG_OMITTED)
    jnz  .child_node
    ; a file
    cmp  dword [rel vfs_chk_kind], 2
    jne  .file_path_ok
    lea  eax, [r15 + FS_CHECK_EXT_PART]
    cmp  eax, FS_CHECK_PATH
    jae  .child_path_long                ; its partial's path is too long
.file_path_ok:
    inc  qword [rel vfs_check + fs_check.files]
    mov  rax, [r13 + fs_dirent.size]
    mov  [rel vfs_chk_fsize], rax
    add  [rel vfs_check + fs_check.bytes], rax
    cmp  dword [rel vfs_chk_nlen], 255
    ja   .child_name
    cmp  dword [rel vfs_chk_kind], 1
    jne  .file_fits
    mov  ecx, 0xFFFFFFFF
    cmp  rax, rcx
    ja   .child_too_big
.file_fits:
    cmp  dword [rbx + fs_check_frame.merge], 0
    je   .file_made
    call .child_dst_stat
    test eax, eax
    jz   .file_made
    test dword [rel vfs_chk_dstat + fs_stat.reserved], 1
    jnz  .file_policy                    ; a directory there: never the same file
    test dword [rel vfs_chk_mode], FS_CMODE_REPLACE
    jz   .child_same
    call .replace_verdict
    cmp  eax, 1
    je   .child_replace
    test eax, eax
    jnz  .file_policy
    inc  dword [rel vfs_check + fs_check.skipped]
    jmp  .entry
.child_replace:
    inc  dword [rel vfs_check + fs_check.replace]
    mov  rax, [rel vfs_chk_fsize]
    call .clusters
    add  [rel vfs_check + fs_check.need], rax
    jmp  .entry                          ; an existing slot: no new directory entry
.child_same:
    mov  rax, [rel vfs_chk_dstat + fs_stat.size]
    cmp  rax, [rel vfs_chk_fsize]
    jne  .file_policy
    mov  ecx, FS_CHK_SAME
    call .child_issue
    inc  dword [rel vfs_check + fs_check.same]
    jmp  .entry
.file_policy:
    mov  ecx, FS_CHK_EXISTS
    test dword [rel vfs_chk_mode], FS_CMODE_KEEPBOTH
    jz   .child_listed
    mov  ecx, FS_CHK_RENAME
    call .child_issue
.file_made:
    mov  rax, [rel vfs_chk_fsize]
    call .clusters
    add  [rel vfs_check + fs_check.need], rax
    call .entry_bytes
    add  [rbx + fs_check_frame.ebytes], rax
    jmp  .entry
.child_dir:
    inc  qword [rel vfs_check + fs_check.dirs]
    cmp  dword [rel vfs_chk_nlen], 255
    ja   .child_name
    mov  eax, [rel vfs_chk_depth]
    cmp  eax, [rel vfs_chk_dmax]
    jae  .child_deep                     ; neither it nor anything below is made
    mov  dword [rel vfs_chk_cmerge], 0
    cmp  dword [rbx + fs_check_frame.merge], 0
    je   .dir_made
    call .child_dst_stat
    test eax, eax
    jz   .dir_made
    test dword [rel vfs_chk_dstat + fs_stat.reserved], 1
    jz   .dir_policy
    mov  dword [rel vfs_chk_cmerge], 1   ; merges into the directory already there
    jmp  .push
.dir_policy:
    mov  ecx, FS_CHK_EXISTS
    test dword [rel vfs_chk_mode], FS_CMODE_KEEPBOTH
    jz   .child_listed                   ; refused: nothing below is made
    mov  ecx, FS_CHK_RENAME
    call .child_issue
.dir_made:
    call .entry_bytes
    add  [rbx + fs_check_frame.ebytes], rax
.push:
    mov  eax, [rel vfs_chk_cslen]
    mov  ecx, [rel vfs_chk_cdlen]
    add  rbx, fs_check_frame_size
    mov  [rbx + fs_check_frame.slen], eax
    mov  [rbx + fs_check_frame.dlen], ecx
    mov  dword [rbx + fs_check_frame.index], 0
    mov  eax, [rel vfs_chk_cmerge]
    mov  [rbx + fs_check_frame.merge], eax
    mov  qword [rbx + fs_check_frame.ebytes], 0
    inc  dword [rel vfs_chk_depth]
    jmp  .page
.child_node:
    mov  ecx, FS_CHK_NODE
    jmp  .child_listed
.child_name:
    mov  ecx, FS_CHK_NAME
    jmp  .child_listed
.child_too_big:
    mov  ecx, FS_CHK_TOO_BIG
    jmp  .child_listed
.child_deep:
    mov  ecx, FS_CHK_DEEP
.child_listed:
    call .child_issue
    jmp  .entry
.child_path_long:
    test dword [r13 + fs_dirent.flags], FS_DIRENT_DIR
    jnz  .long_dir
    inc  qword [rel vfs_check + fs_check.files]
    mov  rax, [r13 + fs_dirent.size]
    add  [rel vfs_check + fs_check.bytes], rax
    jmp  .long_note
.long_dir:
    inc  qword [rel vfs_check + fs_check.dirs]
.long_note:
    mov  ecx, FS_CHK_PATH                ; counted; its path is past the list's FS_FAIL_PATH
    mov  edx, -1
    call .issue_at
    jmp  .entry
.unlisted:
    mov  ecx, FS_CHK_UNREAD
    lea  rsi, [rel vfs_chk_src]
    mov  edx, r14d
    call .issue_at
    jmp  .pop
.page_end:
    cmp  dword [rel vfs_chk_lres + fs_list_result.truncated], 0
    jne  .page                           ; the next page from .index
.pop:
    mov  rax, [rbx + fs_check_frame.ebytes]
    cmp  dword [rbx + fs_check_frame.merge], 0
    jne  .merged_dir
    mov  ecx, 64                         ; a new FAT32 directory: "." and ".."
    cmp  dword [rel vfs_chk_kind], 2
    jne  .dot
    mov  ecx, 24                         ; ext: "." and ".."
.dot:
    add  rax, rcx
.merged_dir:
    call .clusters
    cmp  dword [rel vfs_chk_kind], 2
    jne  .dir_need
    mov  ecx, [rel vfs_chk_cb]
    cmp  rax, rcx
    jbe  .dir_need
    add  rax, rcx                        ; ext: past one block a directory is indexed (one more)
.dir_need:
    add  [rel vfs_check + fs_check.need], rax
    dec  dword [rel vfs_chk_depth]
    jnz  .page
.complete:
    mov  dword [rel vfs_check + fs_check.complete], 1
    jmp  .result
.cap:
    cmp  dword [rel vfs_chk_resumable], 0
    jne  .yield
.stop_entries:
    mov  dword [rel vfs_check + fs_check.reason], FS_CHK_ENTRIES
    jmp  .result
.stop:
    cmp  dword [rel vfs_chk_resumable], 0
    jne  .yield
    mov  dword [rel vfs_check + fs_check.reason], FS_CHK_BUDGET
    jmp  .result
.yield:
    mov  eax, 1                          ; E1: paused at a node boundary (.page, or the frame's .index)
    jmp  .out
.result:
    call boot_ms_now
    sub  rax, [rel vfs_chk_t0]
    mov  [rel vfs_check + fs_check.ms], rax
    xor  eax, eax
    jmp  .out
.not_tree:
    mov  rax, -2
    jmp  .out
.unreadable:
    mov  rax, -1
.out:
    mov  dword [rel vfs_list_skip], 0
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret
; RDI = Z path -> copied to RBX, EAX its length / SF set: FS_CHECK_PATH or longer
.take_path:
    call .length
    mov  rsi, rdi
    cmp  rax, FS_CHECK_PATH
    jae  .take_long
    push rax
    lea  rdx, [rax + 1]
    mov  rdi, rbx
    call memcpy
    pop  rax
    test eax, eax
    ret
.take_long:
    mov  eax, -1
    test eax, eax
    ret
; RDI = Z string -> RAX its length (RDI kept)
.length:
    xor  eax, eax
.length_next:
    cmp  byte [rdi + rax], 0
    je   .length_end
    inc  rax
    jmp  .length_next
.length_end:
    ret
; RDI = path buffer, ECX = its length -> EAX the length of <path>/<name> (vfs_chk_nptr / vfs_chk_nlen)
.append:
    mov  rdx, rdi
    add  rdi, rcx
    cmp  ecx, 1
    jne  .sep
    cmp  byte [rdx], '/'
    je   .no_sep                         ; the root: "/<name>"
.sep:
    mov  byte [rdi], '/'
    inc  rdi
.no_sep:
    push rdx
    mov  rsi, [rel vfs_chk_nptr]
    mov  edx, [rel vfs_chk_nlen]
    call memcpy
    mov  edx, [rel vfs_chk_nlen]
    add  rax, rdx
    mov  byte [rax], 0
    pop  rdx
    sub  rax, rdx
    ret
; Read-only verdict for the Z-terminated paths currently held by the walker. The callbacks do not bind
; sources or share writer state; an FSCHECK between two copy ticks must leave that copy unchanged.
.replace_verdict:
    lea  rsi, [rel vfs_chk_src]
    mov  rdi, rsi
    call .length
    mov  edx, eax
    mov  edi, [rel vfs_chk_sh]
    lea  rcx, [rel vfs_chk_smeta]
    call vfs_replace_meta
    test rax, rax
    jnz  .replace_unknown
    mov  eax, [rel vfs_chk_smeta + fs_replace_meta.flags]
    test eax, FS_RMETA_REGULAR
    jz   .replace_unknown
    lea  rsi, [rel vfs_chk_dst]
    mov  rdi, rsi
    call .length
    mov  edx, eax
    mov  edi, [rel vfs_chk_dh]
    lea  rcx, [rel vfs_chk_dmeta]
    call vfs_replace_meta
    test rax, rax
    jnz  .replace_unknown
    mov  eax, [rel vfs_chk_dmeta + fs_replace_meta.flags]
    and  eax, FS_RMETA_REGULAR | FS_RMETA_ELIGIBLE
    cmp  eax, FS_RMETA_REGULAR | FS_RMETA_ELIGIBLE
    jne  .replace_unknown
    mov  eax, [rel vfs_chk_sh]
    cmp  eax, [rel vfs_chk_dh]
    jne  .replace_times
    mov  rax, [rel vfs_chk_smeta + fs_replace_meta.node]
    test rax, rax
    jz   .replace_unknown
    cmp  rax, [rel vfs_chk_dmeta + fs_replace_meta.node]
    je   .replace_unknown                ; another name of the same backend node
.replace_times:
    mov  rax, [rel vfs_chk_smeta + fs_replace_meta.seconds]
    mov  edx, [rel vfs_chk_smeta + fs_replace_meta.ns]
    mov  rcx, [rel vfs_chk_dmeta + fs_replace_meta.seconds]
    mov  r8d, [rel vfs_chk_dmeta + fs_replace_meta.ns]
    jmp  vfs_mtime_older
.replace_unknown:
    mov  eax, 2
    ret

; the top destination's stat -> EAX 1 exists (vfs_chk_dstat) / 0
.dst_stat:
    mov  edi, [rel vfs_chk_dh]
    lea  rsi, [rel vfs_chk_dst]
    mov  edx, r15d
    jmp  .stat_dst
.child_dst_stat:
    mov  edi, [rel vfs_chk_dh]
    lea  rsi, [rel vfs_chk_dst]
    mov  edx, [rel vfs_chk_cdlen]
.stat_dst:
    lea  rcx, [rel vfs_chk_dstat]
    call vfs_stat_path
    xor  ecx, ecx
    test rax, rax
    sete cl
    mov  eax, ecx
    ret
; RAX = bytes -> RAX in destination clusters
.clusters:
    mov  ecx, [rel vfs_chk_cb]
    lea  rax, [rax + rcx - 1]
    xor  edx, edx
    div  rcx
    imul rax, rcx
    ret
; the directory entry the child takes in its destination directory -> RAX bytes
.entry_bytes:
    mov  eax, [rel vfs_chk_nlen]
    cmp  dword [rel vfs_chk_kind], 2
    je   .ext_entry
    mov  rsi, [rel vfs_chk_nptr]         ; FAT32: an upper-case 8.3 name is one entry
    xor  ecx, ecx                        ; ECX = characters of this part, EDX = 1 past the dot
    xor  edx, edx
    cmp  eax, 12
    ja   .lfn
.short:
    test eax, eax
    jz   .short_end
    movzx r8d, byte [rsi]
    inc  rsi
    dec  eax
    cmp  r8b, '.'
    je   .short_dot
    inc  ecx
    cmp  r8b, '0'
    jb   .short_sym
    cmp  r8b, '9'
    jbe  .short_ok
    cmp  r8b, 'A'
    jb   .lfn
    cmp  r8b, 'Z'
    jbe  .short_ok
.short_sym:
    cmp  r8b, '_'
    je   .short_ok
    cmp  r8b, '-'
    je   .short_ok
    cmp  r8b, '~'
    jne  .lfn                            ; anything else: a long name (counted generously)
.short_ok:
    mov  r9d, 8                          ; 8 before the dot, 3 after
    test edx, edx
    jz   .short_room
    mov  r9d, 3
.short_room:
    cmp  ecx, r9d
    ja   .lfn
    jmp  .short
.short_dot:
    test edx, edx
    jnz  .lfn
    test ecx, ecx
    jz   .lfn
    mov  edx, 1
    xor  ecx, ecx
    jmp  .short
.short_end:
    test edx, edx
    jz   .one_entry
    test ecx, ecx
    jz   .lfn                            ; a trailing dot
.one_entry:
    mov  eax, 32
    ret
.lfn:
    mov  eax, [rel vfs_chk_nlen]         ; one 8.3 entry and ceil(len / 13) long-name entries
    add  eax, 12
    xor  edx, edx
    mov  ecx, 13
    div  ecx
    inc  eax
    shl  eax, 5
    ret
.ext_entry:
    add  eax, 8 + 3                      ; ext: 8 bytes and the name, 4-aligned
    and  eax, ~3
    ret
; 1 = the budget is spent (ZF clear)
.budget:
    mov  eax, [rel vfs_check + fs_check.entries]
    cmp  eax, [rel vfs_chk_e0]
    je   .budget_left                    ; E1: a resumable call visits one node at least (a slow medium)
    call boot_ms_now
    sub  rax, [rel vfs_chk_t0]
    cmp  rax, [rel vfs_chk_ms]
    seta al
    movzx eax, al
    test eax, eax
    ret
.budget_left:
    xor  eax, eax
    ret
; ECX = kind: of the top (its source path, R14D), the child (its source path), or RSI/EDX (-1: counted only)
.issue:
    lea  rsi, [rel vfs_chk_src]
    mov  edx, r14d
    jmp  .issue_at
.child_issue:
    lea  rsi, [rel vfs_chk_src]
    mov  edx, [rel vfs_chk_cslen]
.issue_at:
    cmp  ecx, FS_CHK_EXISTS
    jne  .issue_count
    cmp  dword [rel vfs_check + fs_check.replace_policy], 0
    je   .issue_count
    inc  dword [rel vfs_check + fs_check.conflicts]
.issue_count:
    inc  dword [rel vfs_check + fs_check.issues]
    cmp  edx, FS_FAIL_PATH
    ja   .issue_out
    mov  eax, [rel vfs_check + fs_check.listed]
    cmp  eax, FS_CHECK_ISSUES
    jae  .issue_out
    inc  dword [rel vfs_check + fs_check.listed]
    imul eax, eax, fs_check_issue_size
    lea  rdi, [rel vfs_check_issues]
    add  rdi, rax
    mov  [rdi + fs_check_issue.kind], ecx
    mov  [rdi + fs_check_issue.len], edx
    mov  byte [rdi + fs_check_issue.path + rdx], 0
    add  rdi, fs_check_issue.path
    call memcpy
.issue_out:
    ret

; vfs_copy_check_issue(ESI=index) -> RAX fs_check_issue* / 0 past LISTED. Reads the latest check only.
vfs_copy_check_issue:
    xor  eax, eax
    cmp  esi, [rel vfs_check + fs_check.listed]
    jae  .out
    imul eax, esi, fs_check_issue_size
    lea  rcx, [rel vfs_check_issues]
    add  rax, rcx
.out:
    ret

; ---- E1 (spec 7.5.1 #1, root 15:06): a tree job's scan runs ahead of its data ----
; The FSCHECK walk, resumable: its whole state (vfs_chk_block) is swapped with vfs_scan_state around each
; bounded scan step, so a check (FSCHECK) between ticks keeps its own result. Reads only, as FSCHECK. The
; scan pages like FSCHECK, so a backend that does not page stops it (FS_SCAN_STOPPED, lower bounds).

; vfs_copy_check_resume() -> as vfs_copy_check_bounded: the walk the last bounded call paused, from where
;   it paused (the frames hold each directory's next entry). Only while the walk is paused (depth > 0).
vfs_copy_check_resume:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8
    call boot_ms_now
    mov  [rel vfs_chk_t0], rax
    jmp  vfs_copy_check_bounded.page

; vfs_scan_swap(): exchanges the walk's state with the job scan's. Clobbers RAX, RCX, RDX, RSI, RDI.
vfs_scan_swap:
    lea  rsi, [rel vfs_chk_block]
    lea  rdi, [rel vfs_scan_state]
    mov  ecx, (vfs_chk_block_end - vfs_chk_block) / 8
.next:
    mov  rax, [rsi]
    mov  rdx, [rdi]
    mov  [rsi], rdx
    mov  [rdi], rax
    add  rsi, 8
    add  rdi, 8
    dec  ecx
    jnz  .next
    ret

; vfs_scan_open(EDI=source handle, RSI=source Z, EDX=destination handle, RCX=destination Z, R8D=mode)
;   -> EAX 1 the job cannot fit (BEGIN refuses it before any write) / 0 it may begin. A tree's BEGIN, before
;   its backend's: the scan's first FS_SCAN_FIRST_ENTRIES nodes / FS_SCAN_FIRST_MS. Cannot fit = the
;   destination's known free bytes are fewer than the NEED seen so far (a lower bound) and the top is not
;   refused (the backend names that refusal itself). The scan binds to a job only when its BEGIN succeeds.
vfs_scan_open:
    cmp  dword [rel vfs_ask_child_begin], 0
    je   vfs_scan_open_job
    ; A directory answer still needs its own bounded no-space preflight. Its walk is temporary:
    ; keep the original job's complete result or paused cursor, and FSCHECK's independent result.
    push rbx
    push r12
    push r13
    mov  rbx, [rel vfs_scan_job]
    mov  r12d, [rel vfs_scan_status]
    call vfs_scan_child_swap
    call vfs_scan_open_job
    mov  r13d, eax
    call vfs_scan_child_swap
    mov  [rel vfs_scan_job], rbx
    mov  [rel vfs_scan_status], r12d
    mov  eax, r13d
    pop  r13
    pop  r12
    pop  rbx
    ret

; Exchanges only the private job walk with the child preflight scratch. Preserves all scan arguments.
vfs_scan_child_swap:
    push rdx
    lea  r9, [rel vfs_scan_state]
    lea  r10, [rel vfs_scan_child_state]
    mov  r11d, (vfs_chk_block_end - vfs_chk_block) / 8
.next:
    mov  rax, [r9]
    mov  rdx, [r10]
    mov  [r9], rdx
    mov  [r10], rax
    add  r9, 8
    add  r10, 8
    dec  r11d
    jnz  .next
    pop  rdx
    ret

vfs_scan_open_job:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  ebx, edi
    mov  r12, rsi
    mov  r13d, edx
    mov  r14, rcx
    mov  r15d, r8d
    mov  dword [rel vfs_scan_status], FS_SCAN_NONE
    mov  qword [rel vfs_scan_job], 0
    call vfs_scan_swap
    mov  dword [rel vfs_chk_e0], 1       ; the top: the walk's first node
    mov  dword [rel vfs_chk_cap], FS_SCAN_FIRST_ENTRIES
    mov  qword [rel vfs_chk_ms], FS_SCAN_FIRST_MS
    mov  dword [rel vfs_chk_resumable], 1
    mov  edi, ebx
    mov  rsi, r12
    mov  edx, r13d
    mov  rcx, r14
    mov  r8d, r15d
    call vfs_copy_check_bounded
    xor  ebx, ebx                        ; EBX = the answer
    test rax, rax
    js   .back                           ; unreadable or not a tree: the backend's BEGIN decides
    mov  ecx, FS_SCAN_RUNNING
    test rax, rax
    jnz  .status
    mov  ecx, FS_SCAN_DONE
    cmp  dword [rel vfs_check + fs_check.complete], 0
    jne  .status
    mov  ecx, FS_SCAN_STOPPED
.status:
    mov  [rel vfs_scan_status], ecx
    cmp  dword [rel vfs_chk_topref], 0
    jne  .back
    mov  rax, [rel vfs_check + fs_check.free]
    cmp  rax, -1
    je   .back
    cmp  [rel vfs_check + fs_check.need], rax
    seta bl
.back:
    call vfs_scan_swap
    mov  eax, ebx
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; vfs_scan_step() -> one bounded scan step (FS_SCAN_STEP_ENTRIES / FS_SCAN_STEP_MS) of the live job's scan,
;   while it runs and its job copies or finishes, unheld. vfs_copy_tick, before the job's own step. A running
;   scan belongs to the whole job: an ASK child preserves it; a new job opens or clears it.
vfs_scan_step:
    cmp  dword [rel vfs_scan_status], FS_SCAN_RUNNING
    jne  .out
    cmp  dword [rel vfs_copy_job + fs_copy_job.paused], 0
    jne  .out                            ; a held job reads nothing either
    mov  eax, [rel vfs_copy_job + fs_copy_job.state]
    cmp  eax, FS_JOB_RUNNING
    jb   .out
    cmp  eax, FS_JOB_VERIFYING
    ja   .out
    sub  rsp, 8
    call vfs_scan_swap
    mov  eax, [rel vfs_check + fs_check.entries]
    mov  [rel vfs_chk_e0], eax
    add  eax, FS_SCAN_STEP_ENTRIES
    mov  [rel vfs_chk_cap], eax
    mov  qword [rel vfs_chk_ms], FS_SCAN_STEP_MS
    mov  dword [rel vfs_chk_resumable], 1
    call vfs_copy_check_resume
    test rax, rax
    jnz  .back                           ; paused again
    mov  ecx, FS_SCAN_DONE
    cmp  dword [rel vfs_check + fs_check.complete], 0
    jne  .ended
    mov  ecx, FS_SCAN_STOPPED
.ended:
    mov  [rel vfs_scan_status], ecx
.back:
    call vfs_scan_swap
    add  rsp, 8
.out:
    ret

; vfs_copy_scan(RDI=job id) -> RAX the scan's fs_check* (totals, ISSUES, LISTED) / 0 no scan of that job,
;   EDX FS_SCAN_*: a running scan whose job is no longer live reads FS_SCAN_STOPPED. Reads only.
vfs_copy_scan:
    xor  eax, eax
    xor  edx, edx
    test rdi, rdi
    jz   .out
    cmp  dword [rel vfs_scan_status], FS_SCAN_NONE
    je   .out
    cmp  rdi, [rel vfs_scan_job]
    jne  .out
    mov  edx, [rel vfs_scan_status]
    cmp  edx, FS_SCAN_RUNNING
    jne  .found
    cmp  rdi, [rel vfs_copy_job + fs_copy_job.id]
    jne  .gone
    mov  ecx, [rel vfs_copy_job + fs_copy_job.state]
    cmp  ecx, FS_JOB_RUNNING
    jb   .gone
    cmp  ecx, FS_JOB_VERIFYING
    jbe  .found
.gone:
    mov  edx, FS_SCAN_STOPPED
.found:
    lea  rax, [rel vfs_scan_state + (vfs_check - vfs_chk_block)]
.out:
    ret

; vfs_copy_scan_issue(RDI=job id, ESI=index) -> RAX fs_check_issue* / 0 (no scan of that job, or past LISTED)
vfs_copy_scan_issue:
    push rsi
    call vfs_copy_scan
    pop  rsi
    test rax, rax
    jz   .out
    cmp  esi, [rax + fs_check.listed]
    jae  .none
    imul eax, esi, fs_check_issue_size
    lea  rcx, [rel vfs_scan_state + (vfs_check_issues - vfs_chk_block)]
    add  rax, rcx
    ret
.none:
    xor  eax, eax
.out:
    ret

; vfs_copy_status(RDI=job id, 0 = latest) -> RAX fs_copy_job* / 0 unknown
;   RCQ-20 S5a: also a queued job's record (STATE queued, POS) or the last queued job cancelled
vfs_copy_status:
    mov  rax, [rel vfs_copy_job + fs_copy_job.id]
    test rax, rax
    jz   .none
    test rdi, rdi
    jz   .hit
    cmp  rdi, rax
    je   .hit
    lea  rax, [rel vfs_copy_qended]      ; RCQ-20 S5a: a queued job cancelled before it ran
    cmp  rdi, [rax + fs_copy_job.id]
    je   .found
    lea  rax, [rel vfs_copy_queue]       ; or one still queued (clobbers RCX)
    mov  ecx, [rel vfs_copy_job + fs_copy_job.queued]
.scan:
    test ecx, ecx
    jz   .none
    cmp  rdi, [rax + fs_copy_qrec.job + fs_copy_job.id]
    je   .found
    add  rax, fs_copy_qrec_size
    dec  ecx
    jmp  .scan
.hit:
    lea  rax, [rel vfs_copy_job]
    cmp  dword [rel vfs_ask_phase], FS_ASK_CHILD
    je   vfs_ask_compose                 ; E2: the job's own totals plus the child copying now
.found:
    ret
.none:
    xor  eax, eax
    ret

; vfs_copy_rate(RDI=fs_copy_job*) -> RAX elapsed ms, RDX bytes/s or FS_RATE_UNKNOWN.
; RCQ-21: the one clock rule FSJOB and Explorer both show. A queued job waits since
; its FSCOPY, an ended job stops at its own end, any other job runs to now. No elapsed
; time (or an uncalibrated clock): no rate. Reads the record only. Clobbers RCX.
vfs_copy_rate:
    push rdi
    cmp  dword [rdi + fs_copy_job.state], FS_JOB_QUEUED
    je   .waiting                        ; RCQ-20 S5a: waiting since its FSCOPY
    mov  rax, [rdi + fs_copy_job.t_end]
    cmp  dword [rdi + fs_copy_job.state], FS_JOB_DONE
    jae  .elapsed                        ; ended: its own end time
    mov  rax, [rdi + fs_copy_job.paused_at]
    cmp  dword [rdi + fs_copy_job.paused], 0
    jne  .elapsed                        ; smart copy A: held: its clock stopped at the FSPAUSE
.waiting:
    call boot_ms_now
.elapsed:
    pop  rdi
    sub  rax, [rdi + fs_copy_job.t_start]
    jnc  .elapsed_ok
    xor  eax, eax                        ; regressed/unavailable clock: no elapsed pace
.elapsed_ok:
    mov  rcx, rax
    mov  rax, [rdi + fs_copy_job.done]
    jmp  vfs_copy_bps

; Shared checked bytes/s, RAX bytes / RCX ms -> RDX rate, RAX elapsed.
vfs_copy_bps:
    mov  rdx, FS_RATE_UNKNOWN
    test rcx, rcx
    jz   .out
    mov  edx, 1000
    mul  rdx                             ; full 128-bit product: large jobs never wrap or #DE
    cmp  rdx, rcx
    jae  .rate_overflow
    div  rcx
    mov  rdx, rax
    jmp  .out
.rate_overflow:
    mov  rdx, FS_RATE_UNKNOWN
.out:
    mov  rax, rcx
    ret

; vfs_copy_progress(RDI=exact nonzero id, RSI=caller fs_copy_progress*, RDX=capacity)
; -> EAX 1 copied, 0 unknown/evicted, -1 invalid (output untouched on 0/-1).
; BSP read-only query: no scan advancement, backend, sweep or job mutation. Clock
; follows vfs_copy_rate, including pause. Service callers enforce authority first.
; ETA is a conservative pace estimate, not a bound: max(byte pace, committed-file
; pace). Zero-byte trees use file pace. Ambiguous or insufficient observations stay
; unknown; in particular skipped may include directories, so never subtract it from
; scanned files. No path, device, reason pointer or caller-owned alias is exposed.
; E4 recent pace: newest retained observation >=1s old, sampled every >=250 active
; ms by the tick. Before that, lifetime pace. Queries never sample; FSJOB's legacy
; lifetime rate is unchanged. A stalled tick stream lengthens the interval honestly.
vfs_copy_progress:
    test rdi, rdi
    jz   .bad
    test rsi, rsi
    jz   .bad
    cmp  rdx, fs_copy_progress_size
    jb   .bad
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 32                        ; interval, byte delta, file delta
    mov  rbx, rdi
    mov  r12, rsi
    call vfs_copy_status
    test rax, rax
    jz   .missing
    mov  r13, rax
    mov  rdi, r12
    xor  eax, eax
    mov  ecx, fs_copy_progress_size / 8
    rep stosq
    mov  [r12 + fs_copy_progress.id], rbx
    mov  rax, [r13 + fs_copy_job.done]
    mov  [r12 + fs_copy_progress.bytes_done], rax
    mov  qword [r12 + fs_copy_progress.bytes_total], FS_TOTAL_UNKNOWN
    mov  qword [r12 + fs_copy_progress.files_total], FS_TOTAL_UNKNOWN
    mov  qword [r12 + fs_copy_progress.eta_ms], FS_RATE_UNKNOWN
    mov  eax, [r13 + fs_copy_job.state]
    mov  [r12 + fs_copy_progress.state], eax
    mov  eax, [r13 + fs_copy_job.failed]
    mov  [r12 + fs_copy_progress.problems], eax
    cmp  dword [r13 + fs_copy_job.tree], 0
    jne  .tree
    cmp  dword [r13 + fs_copy_job.state], FS_JOB_QUEUED
    je   .clock
    mov  rax, [r13 + fs_copy_job.total]
    mov  [r12 + fs_copy_progress.bytes_total], rax
    mov  qword [r12 + fs_copy_progress.files_total], 1
    cmp  dword [r13 + fs_copy_job.state], FS_JOB_DONE
    jne  .clock
    cmp  dword [r13 + fs_copy_job.skipped], 0
    jne  .clock                          ; a skipped top file was not committed
    mov  qword [r12 + fs_copy_progress.files_done], 1
    jmp  .clock
.tree:
    mov  eax, [r13 + fs_copy_job.files]
    mov  [r12 + fs_copy_progress.files_done], rax
    mov  rdi, rbx
    call vfs_copy_scan
    mov  [r12 + fs_copy_progress.scan], edx
    test rax, rax
    jz   .clock
    cmp  edx, FS_SCAN_DONE
    jne  .clock                          ; running/stopped: lower bounds, never totals
    cmp  dword [rax + fs_check.complete], 1
    jne  .clock
    cmp  dword [rax + fs_check.issues], 0
    jne  .clock                          ; inaccessible/omitted subtree or conflicting kinds
    mov  rcx, [rax + fs_check.files]
    mov  [r12 + fs_copy_progress.files_total], rcx
    mov  rcx, [rax + fs_check.bytes]
    mov  [r12 + fs_copy_progress.bytes_total], rcx
.clock:
    mov  rdi, r13
    call vfs_copy_rate
    mov  [r12 + fs_copy_progress.elapsed_ms], rax
    mov  [r12 + fs_copy_progress.rate_bps], rdx
    mov  [rsp], rax
    mov  rcx, [r13 + fs_copy_job.done]
    mov  [rsp + 8], rcx
    mov  ecx, [r13 + fs_copy_job.files]
    mov  [rsp + 16], rcx
    cmp  dword [r13 + fs_copy_job.state], FS_JOB_VERIFYING
    ja   .pace_ready
    cmp  rbx, [rel vfs_copy_job + fs_copy_job.id]
    jne  .pace_ready
    cmp  dword [rel vfs_ask_phase], 0
    jne  .pace_ready
    mov  rdi, r13
    mov  rsi, rax
    call vfs_copy_pace_read
    mov  [rsp], rax
    mov  [rsp + 8], rdx
    mov  [rsp + 16], rcx
    mov  rcx, rax
    mov  rax, rdx
    call vfs_copy_bps                    ; same overflow rule as legacy lifetime rate
    mov  [r12 + fs_copy_progress.rate_bps], rdx
.pace_ready:
    cmp  dword [r13 + fs_copy_job.state], FS_JOB_DONE
    je   .done                           ; no operation remains, even when its result is partial
    cmp  dword [r13 + fs_copy_job.state], FS_JOB_VERIFYING
    ja   .copied                         ; queue/cancel/reclaim/failure has no copying ETA
    cmp  dword [r13 + fs_copy_job.skipped], 0
    jne  .copied
    cmp  dword [r13 + fs_copy_job.failed], 0
    jne  .copied
    cmp  rbx, [rel vfs_copy_job + fs_copy_job.id]
    jne  .copied
    cmp  dword [rel vfs_ask_phase], 0
    jne  .copied                         ; answered children and unresolved conflicts share parent totals
    mov  r14, [rsp]
    test r14, r14
    jz   .copied
    mov  rax, [r12 + fs_copy_progress.bytes_total]
    cmp  rax, FS_TOTAL_UNKNOWN
    je   .copied
    mov  rsi, [r12 + fs_copy_progress.bytes_done]
    sub  rax, rsi
    jb   .copied                         ; source changed after scan; don't underflow
    mov  rsi, [rsp + 8]                  ; recent bytes, not lifetime bytes
    xor  r15d, r15d
    test rax, rax
    jnz  .byte_pace
    cmp  dword [r13 + fs_copy_job.state], FS_JOB_VERIFYING
    je   .copied                         ; E4-F1: payload counted, final writes unmeasured
    jmp  .file_pace
.byte_pace:
    mov  rcx, r14
    call vfs_progress_remaining
    cmp  rax, FS_RATE_UNKNOWN
    je   .copied
    mov  r15, rax
.file_pace:
    cmp  dword [r13 + fs_copy_job.tree], 0
    je   .estimate                       ; one large file: byte pace alone is useful
    mov  rax, [r12 + fs_copy_progress.files_total]
    cmp  rax, FS_TOTAL_UNKNOWN
    je   .copied
    mov  rsi, [r12 + fs_copy_progress.files_done]
    sub  rax, rsi
    jb   .copied
    mov  rsi, [rsp + 16]                 ; recent committed files, not lifetime files
    test rax, rax
    jz   .estimate
    mov  rcx, r14
    call vfs_progress_remaining
    cmp  rax, FS_RATE_UNKNOWN
    je   .copied
    cmp  r15, rax
    cmovb r15, rax
.estimate:
    test r15, r15
    jz   .copied                         ; all payload counted: finishing writes have no measured ETA
    mov  [r12 + fs_copy_progress.eta_ms], r15
    jmp  .copied
.done:
    mov  qword [r12 + fs_copy_progress.eta_ms], 0
.copied:
    mov  eax, 1
    jmp  .out
.missing:
    xor  eax, eax
.out:
    add  rsp, 32
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
.bad:
    mov  eax, -1
    ret

; ceil(remaining RAX * elapsed RCX / completed RSI), checked 128-bit arithmetic.
; No useful pace or unrepresentable milliseconds -> unknown, never wrap or #DE.
vfs_progress_remaining:
    test rsi, rsi
    jz   .unknown
    mul  rcx
    cmp  rdx, rsi
    jae  .unknown
    div  rsi
    test rdx, rdx
    jz   .out
    add  rax, 1
    jc   .unknown
.out:
    ret
.unknown:
    mov  rax, FS_RATE_UNKNOWN
    ret

; E4 private recent observations. Only the production tick writes this ring; no
; backend call, allocation or path. ASK children have different counters/clocks:
; discard their history rather than mixing it into their parent's pace.
vfs_copy_pace_note:
    cmp  dword [rel vfs_ask_phase], 0
    jne  .discard
    push rbx
    push r12
    push r13
    lea  rbx, [rel vfs_copy_job]
    mov  rax, [rbx + fs_copy_job.id]
    test rax, rax
    jz   .out
    mov  ecx, [rbx + fs_copy_job.state]
    cmp  ecx, FS_JOB_RUNNING
    jb   .out
    cmp  ecx, FS_JOB_VERIFYING
    jbe  .clock
    cmp  ecx, FS_JOB_DONE
    jne  .out                           ; reclaim/cancel/failure never contributes
.clock:
    mov  rdi, rbx
    call vfs_copy_rate
    mov  r12, rax
    mov  rax, [rbx + fs_copy_job.id]
    cmp  rax, [rel vfs_pace_job]
    je   .latest
    mov  [rel vfs_pace_job], rax
    mov  dword [rel vfs_pace_n], 1
    mov  dword [rel vfs_pace_next], 1
    lea  r13, [rel vfs_pace_samples]
    mov  qword [r13 + fs_copy_pace_sample.elapsed], 0
    mov  qword [r13 + fs_copy_pace_sample.bytes], 0
    mov  qword [r13 + fs_copy_pace_sample.files], 0
.latest:
    mov  eax, [rel vfs_pace_next]
    dec  eax
    and  eax, FS_PACE_SAMPLES - 1
    imul eax, fs_copy_pace_sample_size
    lea  r13, [rel vfs_pace_samples]
    add  r13, rax
    cmp  r12, [r13 + fs_copy_pace_sample.elapsed]
    jb   .reset
    mov  rax, [rbx + fs_copy_job.done]
    cmp  rax, [r13 + fs_copy_pace_sample.bytes]
    jb   .reset
    mov  eax, [rbx + fs_copy_job.files]
    cmp  rax, [r13 + fs_copy_pace_sample.files]
    jb   .reset
    mov  rax, r12
    sub  rax, [r13 + fs_copy_pace_sample.elapsed]
    cmp  rax, FS_PACE_STEP_MS
    jb   .out
    mov  eax, [rel vfs_pace_next]
    imul eax, fs_copy_pace_sample_size
    lea  r13, [rel vfs_pace_samples]
    add  r13, rax
    inc  dword [rel vfs_pace_next]
    and  dword [rel vfs_pace_next], FS_PACE_SAMPLES - 1
    cmp  dword [rel vfs_pace_n], FS_PACE_SAMPLES
    jae  .store
    inc  dword [rel vfs_pace_n]
    jmp  .store
.reset:                                 ; retry/reclaim or clock regression: fresh anchor
    mov  dword [rel vfs_pace_n], 1
    mov  dword [rel vfs_pace_next], 1
    lea  r13, [rel vfs_pace_samples]
.store:
    mov  [r13 + fs_copy_pace_sample.elapsed], r12
    mov  rax, [rbx + fs_copy_job.done]
    mov  [r13 + fs_copy_pace_sample.bytes], rax
    mov  eax, [rbx + fs_copy_job.files]
    mov  [r13 + fs_copy_pace_sample.files], rax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret
.discard:
    mov  qword [rel vfs_pace_job], 0
    ret

; RDI job, RSI active elapsed -> RAX interval, RDX byte delta, RCX file delta.
; Read-only bounded8 scan. Until enough history exists use lifetime counters.
; A counter/time regression before the next tick yields no pace, never underflow.
vfs_copy_pace_read:
    mov  rax, [rdi + fs_copy_job.id]
    cmp  rax, [rel vfs_pace_job]
    jne  .average
    mov  r10d, [rel vfs_pace_n]
    test r10d, r10d
    jz   .average
    mov  eax, [rel vfs_pace_next]
    dec  eax
    and  eax, FS_PACE_SAMPLES - 1
    imul eax, fs_copy_pace_sample_size
    lea  r11, [rel vfs_pace_samples]
    add  rax, r11
    cmp  rsi, [rax + fs_copy_pace_sample.elapsed]
    jb   .unknown
    mov  rdx, [rdi + fs_copy_job.done]
    cmp  rdx, [rax + fs_copy_pace_sample.bytes]
    jb   .unknown
    mov  ecx, [rdi + fs_copy_job.files]
    cmp  rcx, [rax + fs_copy_pace_sample.files]
    jb   .unknown
    mov  r9, rsi
    sub  r9, FS_PACE_MIN_MS
    jb   .average
    xor  r8d, r8d
.scan:
    cmp  [r11 + fs_copy_pace_sample.elapsed], r9
    ja   .next
    test r8, r8
    jz   .choose
    mov  rax, [r11 + fs_copy_pace_sample.elapsed]
    cmp  rax, [r8 + fs_copy_pace_sample.elapsed]
    jbe  .next
.choose:
    mov  r8, r11
.next:
    add  r11, fs_copy_pace_sample_size
    dec  r10d
    jnz  .scan
    test r8, r8
    jz   .average
    mov  rax, rsi
    sub  rax, [r8 + fs_copy_pace_sample.elapsed]
    sub  rdx, [r8 + fs_copy_pace_sample.bytes]
    jb   .unknown
    sub  rcx, [r8 + fs_copy_pace_sample.files]
    jb   .unknown
    ret
.average:
    mov  rax, rsi
    mov  rdx, [rdi + fs_copy_job.done]
    mov  ecx, [rdi + fs_copy_job.files]
    ret
.unknown:
    xor  eax, eax
    xor  edx, edx
    xor  ecx, ecx
    ret

; vfs_copy_item_note(RDI=source Z path, RSI=private backend phase dword*,
; EDX=bit mask of active file phases). Internal backend publication only, no IO.
; Own the basename now; backend paths and walker scratch may change after return.
; At most1024 bytes searched, at most255 bytes kept; never a partial filename.
vfs_copy_item_note:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13d, edx
    lea  rdi, [rel vfs_copy_item_live]
    xor  eax, eax
    mov  ecx, fs_copy_item_size / 8
    rep stosq
    mov  [rel vfs_copy_item_phase], r12
    mov  [rel vfs_copy_item_mask], r13d
    test rbx, rbx
    jz   .out
    mov  rsi, rbx
    xor  ecx, ecx
.find:
    mov  al, [rbx + rcx]
    test al, al
    jz   .leaf
    cmp  al, '/'
    jne  .next
    lea  rsi, [rbx + rcx + 1]
.next:
    inc  ecx
    cmp  ecx, 1024
    jb   .find
    jmp  .out
.leaf:
    cmp  byte [rsi], 0
    je   .out
    lea  rdi, [rel vfs_copy_item_live + fs_copy_item.name]
    call vfs_copy_paths_put
    test eax, eax
    js   .out
    mov  [rel vfs_copy_item_live + fs_copy_item.len], eax
    mov  dword [rel vfs_copy_item_live + fs_copy_item.known], 1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; vfs_copy_current(RDI=exact nonzero id, RSI=caller view, RDX=capacity)
; -> 1 snapshot, 0 unknown/evicted id, -1 bad args; output untouched for0/-1.
; A retained job without an actively processed file returns known0, fully zeroed
; name/reserved. No callback, clock, backend/scan step, allocation or IO.
vfs_copy_current:
    test rdi, rdi
    jz   .bad
    test rsi, rsi
    jz   .bad
    cmp  rdx, fs_copy_item_size
    jb   .bad
    push rbx
    push r12
    push r13
    mov  r12, rsi
    mov  r13, rdi
    call vfs_copy_status
    test rax, rax
    jz   .out
    mov  rbx, rax
    mov  rdi, r12
    xor  eax, eax
    mov  ecx, fs_copy_item_size / 8
    rep stosq
    mov  [r12 + fs_copy_item.id], r13
    cmp  r13, [rel vfs_copy_job + fs_copy_job.id]
    jne  .copied                         ; queued/cancelled records never borrow the live file
    mov  eax, [rbx + fs_copy_job.state]
    cmp  eax, FS_JOB_RUNNING
    je   .live
    cmp  eax, FS_JOB_VERIFYING
    jne  .copied                         ; terminal and reclaim jobs have no current file
.live:
    mov  rax, [rel vfs_copy_item_phase]
    test rax, rax
    jz   .copied
    mov  ecx, [rax]
    cmp  ecx, 32
    jae  .copied
    mov  eax, [rel vfs_copy_item_mask]
    bt   eax, ecx
    jnc  .copied                         ; backend between files, reclaiming or idle
    lea  rsi, [rel vfs_copy_item_live]
    mov  rdi, r12
    mov  ecx, fs_copy_item_size / 8
    rep movsq
    mov  [r12 + fs_copy_item.id], r13
.copied:
    mov  eax, 1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret
.bad:
    mov  eax, -1
    ret

; vfs_copy_paths_note(RDI=id, ESI=source mount, EDX=destination mount,
; RCX=source Z path, R8=destination Z path). Successful top-level BEGIN only.
; Overlong endpoints are independently unknown; no path truncation or disk IO.
vfs_copy_paths_note:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  r12d, esi
    mov  r13d, edx
    mov  r14, rcx
    mov  r15, r8
    lea  rdi, [rel vfs_copy_paths_live]
    xor  eax, eax
    mov  ecx, fs_copy_paths_size / 8
    rep stosq
    mov  rax, rbx
    lea  rbx, [rel vfs_copy_paths_live]
    mov  [rbx + fs_copy_paths.id], rax
    mov  [rbx + fs_copy_paths.src_mount], r12d
    mov  [rbx + fs_copy_paths.dst_mount], r13d
    mov  r12, rbx
    mov  rsi, r14
    mov  rdx, r15
    call vfs_copy_paths_fill
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; R12=zeroed view, RSI=source, RDX=destination. Caller-owned buffers only.
vfs_copy_paths_fill:
    push rbx
    mov  rbx, rdx
    lea  rdi, [r12 + fs_copy_paths.src]
    call vfs_copy_paths_put
    test eax, eax
    js   .dst
    mov  [r12 + fs_copy_paths.src_len], eax
    or   dword [r12 + fs_copy_paths.known], FS_COPY_PATH_SRC
.dst:
    mov  rsi, rbx
    lea  rdi, [r12 + fs_copy_paths.dst]
    call vfs_copy_paths_put
    test eax, eax
    js   .out
    mov  [r12 + fs_copy_paths.dst_len], eax
    or   dword [r12 + fs_copy_paths.known], FS_COPY_PATH_DST
.out:
    pop  rbx
    ret

; Bounded NUL search before copying; refusal leaves the zeroed field untouched.
vfs_copy_paths_put:
    xor  ecx, ecx
.find:
    cmp  byte [rsi + rcx], 0
    je   .copy
    inc  ecx
    cmp  ecx, FS_COPY_PATH_CAP
    jb   .find
    mov  eax, -1
    ret
.copy:
    mov  eax, ecx
    inc  ecx
    rep movsb
    ret

; vfs_copy_paths(RDI=exact nonzero id, RSI=caller view, RDX=capacity)
; -> 1 copied, 0 unknown/evicted, -1 bad args; output untouched for0/-1.
; Internal BSP accessor: service callers enforce principal/session authority.
; Known retained jobs can have no retained endpoints (known=0, empty fields).
vfs_copy_paths:
    test rdi, rdi
    jz   .bad
    test rsi, rsi
    jz   .bad
    cmp  rdx, fs_copy_paths_size
    jb   .bad
    push rbx
    push r12
    push r13
    mov  r12, rsi
    mov  r13, rdi
    call vfs_copy_status
    test rax, rax
    jz   .out
    mov  rbx, rax
    mov  rdi, r12
    xor  eax, eax
    mov  ecx, fs_copy_paths_size / 8
    rep stosq
    mov  [r12 + fs_copy_paths.id], r13
    mov  eax, [rbx + fs_copy_job.mount]
    mov  [r12 + fs_copy_paths.src_mount], eax
    mov  [r12 + fs_copy_paths.dst_mount], eax
    cmp  r13, [rel vfs_copy_paths_live + fs_copy_paths.id]
    jne  .queued
    mov  rdi, r12
    lea  rsi, [rel vfs_copy_paths_live]
    mov  ecx, fs_copy_paths_size / 8
    rep movsq
    jmp  .copied
.queued:
    cmp  dword [rbx + fs_copy_job.state], FS_JOB_QUEUED
    jne  .copied                       ; ended/dropped queue never aliases reused slots
    lea  rsi, [rbx + fs_copy_qrec.src]
    lea  rdx, [rbx + fs_copy_qrec.dst]
    call vfs_copy_paths_fill
.copied:
    mov  eax, 1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret
.bad:
    mov  eax, -1
    ret

; vfs_copy_snapshot(RDI=exact nonzero id, RSI=caller fs_copy_view*, RDX=capacity)
; -> EAX 1 copied, 0 evicted/unknown, -1 bad arguments (output untouched then).
; Internal BSP retention accessor: service callers filter principal/session first.
; No hook, sweep, clock, backend or job operation. Never interprets id 0 as latest.
vfs_copy_snapshot:
    test rdi, rdi
    jz   .bad
    test rsi, rsi
    jz   .bad
    cmp  rdx, fs_copy_view_size
    jb   .bad
    push rbx
    push r12
    push r13
    mov  r12, rsi
    mov  r13, rdi
    xor  ebx, ebx
    call vfs_copy_status
    test rax, rax
    jz   .dropped
    lea  rcx, [rel vfs_copy_qended]
    cmp  rax, rcx
    je   .ended
    lea  rcx, [rel vfs_copy_job]
    cmp  rax, rcx
    je   .copy
    lea  rcx, [rel vfs_ask_view]         ; E2: the live ask job while a child copies
    cmp  rax, rcx
    je   .copy
    mov  ebx, 1
    jmp  .copy
.ended:
    mov  ebx, 2
    jmp  .copy
.dropped:
    mov  rdi, r13
    call vfs_copy_dropped_status
    test rax, rax
    jz   .out
    mov  ebx, 3
.copy:
    mov  r13, rax
    mov  rdi, r12
    xor  eax, eax
    mov  ecx, fs_copy_view_size / 8
    rep stosq
%macro COPY_VIEW 2
    mov  %2, [r13 + fs_copy_job.%1]
    mov  [r12 + fs_copy_view.%1], %2
%endmacro
    COPY_VIEW id, rax
    COPY_VIEW done, rax
    COPY_VIEW total, rax
    COPY_VIEW state, eax
    COPY_VIEW error, eax
    COPY_VIEW durable, eax
    COPY_VIEW pos, eax
    COPY_VIEW tree, eax
    COPY_VIEW files, eax
    COPY_VIEW skipped, eax
    COPY_VIEW preserved, eax
    COPY_VIEW kept, eax
%unmacro COPY_VIEW 2
    mov  [r12 + fs_copy_view.origin], ebx
    mov  eax, 1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret
.bad:
    mov  eax, -1
    ret

; ---- v1.1 paths: thin dispatchers onto the additive path slots (NULL slot -> -1) ----
; vfs_stat_path(RDI=handle,RSI=path,EDX=len,RCX=fs_stat*) -> 0/-1
vfs_stat_path:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rsi
    mov  r13d, edx
    mov  r14, rcx
    call vfs_mount_ptr
    test rax, rax
    jz   .fail
    mov  r11, rax
    mov  r10, [r11 + fsmount.ops]
    cmp  qword [r10 + fs_ops.stat_path], 0
    je   .fail
    mov  rdi, r11
    mov  rsi, r12
    mov  edx, r13d
    mov  rcx, r14
    call [r10 + fs_ops.stat_path]
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
; vfs_replace_meta: same path ABI as stat_path, an independent readonly tail callback. No writer fallback.
vfs_replace_meta:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rsi
    mov  r13d, edx
    mov  r14, rcx
    call vfs_mount_ptr
    test rax, rax
    jz   .fail
    mov  rdi, rax
    mov  r10, [rax + fsmount.ops]
    cmp  qword [r10 + fs_ops.replace_meta], 0
    je   .fail
    mov  rsi, r12
    mov  edx, r13d
    mov  rcx, r14
    call [r10 + fs_ops.replace_meta]
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

; vfs_read_at_path(RDI=handle,RSI=path,EDX=len,RCX=off,R8=buf,R9=len) -> len/-1
vfs_read_at_path:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rsi
    mov  r13d, edx
    mov  r14, rcx
    mov  r15, r8
    mov  rbx, r9
    call vfs_mount_ptr
    test rax, rax
    jz   .fail
    mov  r11, rax
    mov  r10, [r11 + fsmount.ops]
    cmp  qword [r10 + fs_ops.read_at_path], 0
    je   .fail
    mov  rdi, r11
    mov  rsi, r12
    mov  edx, r13d
    mov  rcx, r14
    mov  r8, r15
    mov  r9, rbx
    call [r10 + fs_ops.read_at_path]
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
; vfs_write_at_path(RDI=handle,RSI=path,EDX=len,RCX=off,R8=buf,R9=len) -> len/-1
vfs_write_at_path:
    lock inc qword [rel vfs_write_generation]   ; RCQ-39 F-a: before the backend, whatever its result
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rsi
    mov  r13d, edx
    mov  r14, rcx
    mov  r15, r8
    mov  rbx, r9
    call vfs_mount_ptr
    test rax, rax
    jz   .fail
    mov  r11, rax
    mov  r10, [r11 + fsmount.ops]
    cmp  qword [r10 + fs_ops.write_at_path], 0
    je   .fail
    mov  rdi, r11
    mov  rsi, r12
    mov  edx, r13d
    mov  rcx, r14
    mov  r8, r15
    mov  r9, rbx
    call [r10 + fs_ops.write_at_path]
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
; vfs_file_extents(EDI=handle,RSI=path,EDX=len,RCX=fs_extent_map*,R8D=cap) -> RAX the file's total extent count
;   (more than cap: only cap are written) / -1. RCQ-38 G3. -1 also when the backend has no extent op (ext4,
;   NTFS, RAM): the caller takes its slow path. vfs_mount_ptr touches only RAX/RDI, so the arguments pass through.
vfs_file_extents:
    call vfs_mount_ptr
    test rax, rax
    jz   .fail
    mov  r10, [rax + fsmount.ops]
    mov  r10, [r10 + fs_ops.file_extents]
    test r10, r10
    jz   .fail
    mov  rdi, rax
    jmp  r10
.fail:
    mov  rax, -1
    ret

; vfs_file_extents_current(EDI=handle,RSI=fs_extent_map*) -> EAX 0 the map still holds / 1 only the generation
;   moved (resolve again) / -1 another mount, device, volume or medium (or no such op). RCQ-38 G3.
vfs_file_extents_current:
    call vfs_mount_ptr
    test rax, rax
    jz   .other
    mov  r10, [rax + fsmount.ops]
    mov  r10, [r10 + fs_ops.extent_check]
    test r10, r10
    jz   .other
    mov  rdi, rax
    jmp  r10
.other:
    mov  eax, -1
    ret

; vfs_open_boot_esp(RDI = the boot ESP's unique partition GUID, 16 on-media bytes) -> RAX handle / -1.
;   RCQ-38 G1b: the READ-ONLY boot-ESP handle (fat32_disk_boot_esp_open). Reads, lists and G3
;   extents only: every mutating entry here refuses it (its fs_ops slots are 0) and it has no
;   name, so FSSEL never re-points the verbs at it. -1 = no volume: no GPT ESP with that GUID
;   on any readable medium, the GUID on two media, or a zero GUID. BSP only.
vfs_open_boot_esp:
    jmp  fat32_disk_boot_esp_open

; BSP/non-reentrant. Exact ESP/BASICDATA GUID -> separate unnamed read-only
; FAT32 source handle; never FSSEL or write authority. Signed VM profile owns
; artifact identity, this API supplies location only. Same GUID cached once.
vfs_open_guest_source:
    jmp fat32_disk_guest_source_open

; BSP/non-reentrant. The guest-pair consumer's boot-ESP open (hv_guest_files_begin only):
; the boot-ESP GUID scan with the scoped fault rule on its own unnamed RO handle; never the
; shared vfs_open_boot_esp handle. Location only: the signed VM profile pins every byte.
vfs_open_guest_esp:
    jmp fat32_disk_guest_esp_open

; vfs_guest_pair_state(EDI = 0 boot-ESP pair scan / 1 SOURCE.BIN scan) -> EAX = its last FD_PAIR_*,
;   RDX = its faulting medium's kept name ("-" = none). Values only, for GUESTVM STAT (root 119659).
vfs_guest_pair_state:
    jmp fat32_disk_pair_report_state

; EDI=existing bootESP RO handle, RSI=path, EDX=len, RCX=64B output.
; 0 exact64, 1 proven complete absence, -1 every other failure.
vfs_guest_source_hint:
    call vfs_mount_ptr
    test rax,rax
    jz .fail
    mov rdi,rax
    jmp fat32_disk_guest_source_hint
.fail:
    mov rax,-1
    ret

; vfs_list_dir(RDI=handle,RSI=path,EDX=len,RCX=entries,R8D=cap,R9=result) -> 0/-1
vfs_list_dir:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rsi
    mov  r13d, edx
    mov  r14, rcx
    mov  r15, r8
    mov  rbx, r9
    test rbx, rbx
    jz   .no_result
    mov  dword [rbx + fs_list_result.names_short], 0   ; for backends that never set it
.no_result:
    call vfs_mount_ptr
    test rax, rax
    jz   .fail
    mov  r11, rax
    mov  r10, [r11 + fsmount.ops]
    cmp  qword [r10 + fs_ops.list_dir], 0
    je   .fail
    mov  rdi, r11
    mov  rsi, r12
    mov  edx, r13d
    mov  rcx, r14
    mov  r8, r15
    mov  r9, rbx
    call [r10 + fs_ops.list_dir]
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

; Pure retained NTFS selection snapshot, BSP command context. No block I/O.
; Noncurrent snapshots contain version/status only; all facts are cleared.
FS_NTFS_STATE_VERSION equ 1
FS_NTFS_CLOSED equ 0
FS_NTFS_UNAVAILABLE equ 1
FS_NTFS_STALE equ 2
FS_NTFS_CURRENT equ 3
struc fs_ntfs_selection
  .version: resd 1
  .status: resd 1
  .start: resq 1
  .sectors: resq 1
  .lba_max: resq 1                   ; inclusive last LBA, not a sector count
  .media_gen: resq 1
  .binding_gen: resq 1               ; epoch captured at successful NTFS binding
  .sector_bytes: resd 1
  .logical_bytes: resd 1             ; raw observed logical bytes (0 = unspecified)
  .device: resb 64                   ; complete ASCII token, 1..63 bytes + NUL
  .mount: resq 1
endstruc
; RDI=128-byte fs_ntfs_selection* -> EAX=FS_NTFS_* / -1 null destination.
; This is an observation, never authority, auto-selection or a mount attempt.
vfs_ntfs_selection_state:
    jmp ntfs_disk_selection_state

; vfs_select_ntfs_exact(RDI=registered device name, ESI=len, RDX=start,
; RCX=sectors) -> handle/-1 invalid/-2 busy/-3 authority. Explicit read binding;
; backend owns the singleton lifecycle, fresh metadata checks and invalidation.
vfs_select_ntfs_exact:
    jmp  ntfs_disk_select_exact

; vfs_select_disk_by_name(RDI=name bytes, ESI=len) -> RAX handle / -1.
;   Re-points vfs_disk_handle (the mount the FS verbs address) at the mount
;   whose label matches exactly (e.g. "fat32", "ntfs0"). No I/O.
vfs_select_disk_by_name:
    lock inc qword [rel vfs_write_generation]   ; RCQ-39 F-a: a re-point changes what a name resolves to
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13d, esi
    xor  r14d, r14d
.next:
    cmp  r14d, VFS_MAX_MOUNTS
    jae  .fail
    mov  edi, r14d
    call vfs_mount_ptr
    test rax, rax
    jz   .skip
    mov  rbx, [rax + fsmount.name]
    test rbx, rbx
    jz   .skip
    xor  ecx, ecx
.cmp:
    cmp  ecx, r13d
    jae  .end_tok
    mov  al, [rbx + rcx]
    test al, al
    jz   .skip
    cmp  al, [r12 + rcx]
    jne  .skip
    inc  ecx
    jmp  .cmp
.end_tok:
    cmp  byte [rbx + rcx], 0
    jne  .skip
    mov  [rel vfs_disk_handle], r14d
    mov  eax, r14d
    jmp  .out
.skip:
    inc  r14d
    jmp  .next
.fail:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; vfs_info(RDI=handle,RSI=fs_info*) -> RAX 0/-1
vfs_info:
    mov  qword [rsi + fs_info.orphans], -1
    push rbx
    mov  rbx, rsi
    mov  qword [rbx + fs_info.free_clusters], -1 ; older backends: unknown, never stale
    call vfs_mount_ptr
    test rax, rax
    jz   .fail
    mov  r10, [rax + fsmount.ops]
    cmp  qword [r10 + fs_ops.info], 0
    je   .fail
    mov  rdi, rax
    mov  rsi, rbx
    call [r10 + fs_ops.info]
    pop  rbx
    ret
.fail:
    mov  rax, -1
    pop  rbx
    ret

; vfs_info_facts(RDI=handle,RSI=fs_info*) -> 0/-1.  vfs_info's facts with no whole-volume walk (ROOT108324): the
; census prints identity and geometry only, so its cost must not grow with the volume.  free_clusters is a count
; the backend already holds, else -1.  The mount's own free-count state is not changed.
vfs_info_facts:
    mov  qword [rsi + fs_info.orphans], -1
    push rbx
    mov  rbx, rsi
    mov  qword [rbx + fs_info.free_clusters], FS_INFO_FACTS
    call vfs_mount_ptr
    test rax, rax
    jz   .fail
    mov  r10, [rax + fsmount.ops]
    cmp  qword [r10 + fs_ops.info], 0
    je   .fail
    mov  rdi, rax
    mov  rsi, rbx
    call [r10 + fs_ops.info]
    cmp  qword [rbx + fs_info.free_clusters], FS_INFO_FACTS
    jne  .out
    mov  qword [rbx + fs_info.free_clusters], -1 ; a backend that ignored the request: unknown, never the marker
.out:
    pop  rbx
    ret
.fail:
    mov  qword [rbx + fs_info.free_clusters], -1
    mov  rax, -1
    pop  rbx
    ret

; vfs_list_root(RDI=handle,RSI=fs_dirent[],EDX=cap,RCX=result) -> 0/-1
vfs_list_root:
    push rbx
    push r12
    push r13
    mov  rbx, rsi
    mov  r12d, edx
    mov  r13, rcx
    test r13, r13
    jz   .no_result
    mov  dword [r13 + fs_list_result.names_short], 0   ; for backends that never set it
.no_result:
    call vfs_mount_ptr
    test rax, rax
    jz   .fail
    mov  r10, [rax + fsmount.ops]
    cmp  qword [r10 + fs_ops.list_root], 0
    je   .fail
    mov  rdi, rax
    mov  rsi, rbx
    mov  edx, r12d
    mov  rcx, r13
    call [r10 + fs_ops.list_root]
    pop  r13
    pop  r12
    pop  rbx
    ret
.fail:
    mov  rax, -1
    pop  r13
    pop  r12
    pop  rbx
    ret

; ============================================================================
; vfs_init — allocate the volume, format FAT32, wire + mount both backends
; ============================================================================
; vfs_build_vtables — fill the fs_ops slots with RUNTIME VAs (lea, not baked dq).
vfs_build_vtables:
    lea  rax, [rel str_fat32_name]
    mov  [rel fat32_ops + fs_ops.name], rax
    lea  rax, [rel fat32_mount]
    mov  [rel fat32_ops + fs_ops.mount], rax
    lea  rax, [rel fat32_readfile]
    mov  [rel fat32_ops + fs_ops.readfile], rax
    lea  rax, [rel fat32_writefile]
    mov  [rel fat32_ops + fs_ops.writefile], rax
    lea  rax, [rel fat32_delete]
    mov  [rel fat32_ops + fs_ops.delete], rax
    lea  rax, [rel fat32_stat]
    mov  [rel fat32_ops + fs_ops.stat], rax
    lea  rax, [rel fat32_read_at]
    mov  [rel fat32_ops + fs_ops.read_at], rax
    lea  rax, [rel str_exfat_name]
    mov  [rel exfat_ops + fs_ops.name], rax
    lea  rax, [rel exfat_mount]
    mov  [rel exfat_ops + fs_ops.mount], rax
    lea  rax, [rel exfat_readfile]
    mov  [rel exfat_ops + fs_ops.readfile], rax
    lea  rax, [rel exfat_writefile]
    mov  [rel exfat_ops + fs_ops.writefile], rax
    lea  rax, [rel exfat_delete]
    mov  [rel exfat_ops + fs_ops.delete], rax
    lea  rax, [rel exfat_stat]
    mov  [rel exfat_ops + fs_ops.stat], rax
    lea  rax, [rel exfat_read_at]
    mov  [rel exfat_ops + fs_ops.read_at], rax
    lea  rax, [rel str_vfs_kat_name]
    mov  [rel vfs_kat_ops + fs_ops.name], rax
    lea  rax, [rel vfs_kat_mount]
    mov  [rel vfs_kat_ops + fs_ops.mount], rax
    lea  rax, [rel vfs_kat_fail]
    mov  [rel vfs_kat_ops + fs_ops.readfile], rax
    mov  [rel vfs_kat_ops + fs_ops.writefile], rax
    mov  [rel vfs_kat_ops + fs_ops.delete], rax
    lea  rax, [rel vfs_kat_stat]
    mov  [rel vfs_kat_ops + fs_ops.stat], rax
    lea  rax, [rel vfs_kat_read_at]
    mov  [rel vfs_kat_ops + fs_ops.read_at], rax
    ret

vfs_init:
    call vfs_build_vtables               ; runtime-VA function pointers (not baked dq)
    mov  dword [rel vfs_mount_count], 0
    lea  rdi, [rel vfs_mounts]
    xor  eax, eax
    mov  ecx, (VFS_MAX_MOUNTS * fsmount_size) / 8
    rep  stosq
    ; volume + scratch buffers (heap; keeps the image small + within budget)
    mov  rdi, VFS_VOLBYTES
    call kmalloc
    test rax, rax
    jz   .oom
    mov  [rel vfs_vol], rax
    mov  rdi, 64
    call kmalloc
    test rax, rax
    jz   .oom
    mov  [rel vfs_scratch], rax
    mov  rdi, 256
    call kmalloc
    test rax, rax
    jz   .oom
    mov  [rel vfs_pattern], rax
    mov  rdi, 256
    call kmalloc
    test rax, rax
    jz   .oom
    mov  [rel vfs_pattern2], rax
    mov  rdi, 512
    call kmalloc
    test rax, rax
    jz   .oom
    mov  [rel vfs_readbuf], rax
    call fat32_format
    ; Register both built-ins through the same N-ary API. No dispatch edit is
    ; needed when fat32_disk or the throwaway KAT backend is added later.
    lea  rdi, [rel fat32_ops]
    xor  esi, esi
    lea  rdx, [rel str_fat32_name]
    call vfs_register_mount
    test rax, rax
    js   .oom
    mov  [rel vfs_ram_handle], eax
    lea  rdi, [rel exfat_ops]
    xor  esi, esi
    lea  rdx, [rel str_exfat_name]
    call vfs_register_mount
    test rax, rax
    js   .oom
    mov  [rel vfs_exfat_handle], eax
    xor  eax, eax
    ret
.oom:
    mov  rax, -1
    ret

; build_pattern — deterministic known 256-byte pattern (byte[i] = i & 0xFF)
build_pattern:
    mov  rdx, [rel vfs_pattern]
    xor  rcx, rcx
.l:
    mov  al, cl
    mov  [rdx + rcx], al
    inc  rcx
    cmp  rcx, 256
    jb   .l
    ret

; build_pattern2 — a DIFFERENT known 256-byte pattern (byte[i] = (i*7+0x5A)&0xFF)
build_pattern2:
    mov  rdx, [rel vfs_pattern2]
    xor  rcx, rcx
.l:
    lea  eax, [rcx + rcx*8]               ; i*9 -> just needs to differ from i
    add  eax, 0x5A
    mov  [rdx + rcx], al
    inc  rcx
    cmp  rcx, 256
    jb   .l
    ret

; emit_hex(RDI=value) — print the value as minimal lowercase hex
emit_hex:
    mov  rsi, [rel vfs_scratch]
    xor  rdx, rdx
    call fmt_hex
    mov  rdi, [rel vfs_scratch]
    call serial_string
    ret

; ============================================================================
; vfs_selftest — the QEMU-gradeable acceptance (all 4 markers + content grade)
; ============================================================================
vfs_selftest:
    push r15
    call vfs_init
    test rax, rax
    jnz  .fail
    call sha256_selftest
    test rax, rax
    jnz  .fail
    lea  rdi, [rel str_init_ready]
    call serial_string
    ; --- basic: mount table wired to BOTH backend vtables (dispatch sanity) ---
    mov  edi, [rel vfs_ram_handle]
    call vfs_mount_ptr
    test rax, rax
    jz   .fail
    mov  rdx, [rax + fsmount.ops]
    lea  rcx, [rel fat32_ops]
    cmp  rdx, rcx
    jne  .fail
    mov  edi, [rel vfs_exfat_handle]
    call vfs_mount_ptr
    test rax, rax
    jz   .fail
    mov  rax, [rax + fsmount.ops]
    lea  rcx, [rel exfat_ops]
    cmp  rax, rcx
    jne  .fail
    lea  rdi, [rel str_selftest_basic]
    call serial_string
    ; --- temp-then-swap write of a known 256-byte pattern (via vfs dispatch) ---
    call build_pattern
    mov  edi, [rel vfs_ram_handle]
    lea  rsi, [rel name_data_bin]
    mov  rdx, [rel vfs_pattern]
    mov  rcx, 256
    call vfs_writefile                   ; RAX = file cluster / -1
    cmp  rax, 0
    jl   .fail
    mov  r15, rax                        ; cluster (for the marker)
    lea  rdi, [rel str_wr_a]
    call serial_string
    mov  rdi, r15
    call emit_hex
    lea  rdi, [rel str_wr_b]
    call serial_string
    ; --- read back + BYTE-EQUAL content grade (marker gated on memcmp==0) ---
    mov  edi, [rel vfs_ram_handle]
    lea  rsi, [rel name_data_bin]
    mov  rdx, [rel vfs_readbuf]
    mov  rcx, 512
    call vfs_readfile
    cmp  rax, 256                        ; must report the true 256-byte size
    jne  .fail
    mov  rdi, [rel vfs_readbuf]
    mov  rsi, [rel vfs_pattern]
    mov  rdx, 256
    call memcmp
    test rax, rax
    jnz  .fail                           ; content mismatch => real failure
    lea  rdi, [rel str_rb_match]
    call serial_string
    ; --- additive stat/read_at tail slots, content-graded at a nonzero offset ---
    mov  edi, [rel vfs_ram_handle]
    lea  rsi, [rel name_data_bin]
    lea  rdx, [rel vfs_stat_buf]
    call vfs_stat
    test rax, rax
    jnz  .fail
    cmp  qword [rel vfs_stat_buf + fs_stat.size], 256
    jne  .fail
    mov  edi, [rel vfs_ram_handle]
    lea  rsi, [rel name_data_bin]
    mov  edx, 37
    mov  rcx, [rel vfs_readbuf]
    mov  r8d, 64
    call vfs_read_at
    cmp  rax, 64
    jne  .fail
    mov  rdi, [rel vfs_readbuf]
    mov  rsi, [rel vfs_pattern]
    add  rsi, 37
    mov  edx, 64
    call memcmp
    test rax, rax
    jnz  .fail
    mov  byte [rel vfs_m_stream], 1
    lea  rdi, [rel str_vfs_stream_ops]
    call serial_string
    ; --- OVERWRITE an EXISTING file: proves temp-then-swap step 4 (old data
    ;     stays intact on its original cluster until the atomic name-swap, old
    ;     clusters freed after). Write a DIFFERENT pattern to the SAME name, read
    ;     back, and require the NEW content (byte-equal to pattern2, != pattern1). ---
    call build_pattern2
    mov  edi, [rel vfs_ram_handle]
    lea  rsi, [rel name_data_bin]
    mov  rdx, [rel vfs_pattern2]
    mov  rcx, 256
    call vfs_writefile                   ; RAX = new cluster (fresh; old was freed)
    cmp  rax, 0
    jl   .fail
    mov  edi, [rel vfs_ram_handle]
    lea  rsi, [rel name_data_bin]
    mov  rdx, [rel vfs_readbuf]
    mov  rcx, 512
    call vfs_readfile
    cmp  rax, 256
    jne  .fail
    mov  rdi, [rel vfs_readbuf]
    mov  rsi, [rel vfs_pattern2]
    mov  rdx, 256
    call memcmp
    test rax, rax
    jnz  .fail                           ; must equal the NEW content
    mov  rdi, [rel vfs_readbuf]
    mov  rsi, [rel vfs_pattern]
    mov  rdx, 256
    call memcmp
    test rax, rax
    jz   .fail                           ; must DIFFER from the OLD content (real swap)
    lea  rdi, [rel str_ovw_ok]
    call serial_string
    ; --- delete + verify absence (reread must ENOENT) ---
    mov  edi, [rel vfs_ram_handle]
    lea  rsi, [rel name_data_bin]
    call vfs_delete
    test rax, rax
    jnz  .fail
    mov  edi, [rel vfs_ram_handle]
    lea  rsi, [rel name_data_bin]
    mov  rdx, [rel vfs_readbuf]
    mov  rcx, 512
    call vfs_readfile
    cmp  rax, -1                         ; reread of a deleted file must fail
    jne  .fail
    lea  rdi, [rel str_del_ok]
    call serial_string
    ; --- 2nd backend dispatch: read through the exfat mock (mount 1) ---
    mov  edi, [rel vfs_exfat_handle]
    lea  rsi, [rel name_data_bin]
    mov  rdx, [rel vfs_readbuf]
    mov  rcx, 512
    call vfs_readfile                    ; routes to exfat_readfile (selector proof)
    cmp  rax, exfat_content.len
    jne  .fail
    ; --- register a throwaway read-only backend without editing dispatch ---
    lea  rdi, [rel vfs_kat_ops]
    xor  esi, esi
    lea  rdx, [rel str_vfs_kat_name]
    call vfs_register_mount
    test rax, rax
    js   .fail
    mov  [rel vfs_kat_handle], eax
    mov  edi, eax
    lea  rsi, [rel name_data_bin]
    mov  edx, 5
    mov  rcx, [rel vfs_readbuf]
    mov  r8d, 9
    call vfs_read_at
    cmp  rax, 9
    jne  .fail
    mov  rdi, [rel vfs_readbuf]
    lea  rsi, [rel vfs_kat_content + 5]
    mov  edx, 9
    call memcmp
    test rax, rax
    jnz  .fail
    mov  byte [rel vfs_m_second], 1
    lea  rdi, [rel str_vfs_registry_second]
    call serial_string
    ; The physical backend is optional on QEMU and mandatory on Lenovo. Its
    ; mount marker is earned only after live BPB geometry validation succeeds.
    call fat32_disk_register
    test rax, rax
    js   .no_physical
    mov  [rel vfs_disk_handle], eax
    ; Read-only observation only: ordinary two-device regression deliberately
    ; withholds this line, while the dedicated single-device GPT fixture earns
    ; it from the same fallback proof real data-crypto writes must pass.
    call data_crypto_fallback_boot_probe
    cmp  eax, 1
    je   .fallback_proved
    cmp  eax, -1
    jne  .no_physical
    lea  rdi, [rel str_vfs_fallback_refused]
    call serial_string
    jmp  .no_physical
.fallback_proved:
    lea  rdi, [rel str_vfs_fallback_proved]
    call serial_string
.no_physical:
    ; PETER 2026-09-30 06:22 storage: prove the NVRAM class table, then resolve
    ; the DATA-record backend once (read-and-copy migration of a gap record into
    ; the PaOS-owned PaOSDataRecord variable; the gap itself is only read).
    call storage_access_nvram_kat
    call data_crypto_boot_migrate
    ; 2026-09-07 desktop bring-up: the NTFS volume (largest across AHCI/NVMe) mounts as
    ; "ntfs0". The FS verbs keep addressing the FAT mount when one was selected; with NO
    ; FAT volume (a Windows-only box) they fall back to ntfs0. `FSSEL <label>` re-routes.
    call ntfs_disk_register
    test rax, rax
    js   .ntfs_done
    cmp  dword [rel vfs_disk_handle], -1
    jne  .ntfs_done
    mov  [rel vfs_disk_handle], eax
.ntfs_done:
    ; RCQ-20 E1: clean ext2/ext3/ext4 volumes mount read-only as "ext0"/"ext1". Like ntfs0,
    ; an ext mount becomes the FS-verb/Explorer mount only when nothing else holds it;
    ; `FSSEL ext0` re-routes.
    call ext4_disk_register
    test rax, rax
    js   .ext_done
    cmp  dword [rel vfs_disk_handle], -1
    jne  .ext_done
    mov  [rel vfs_disk_handle], eax
.ext_done:
    ; RCQ-20 exFAT S1: clean exFAT volumes mount read-only as "exfat0"/"exfat1" (the C8
    ; selector mock above is "c8-ro-mock" and is not an exFAT reader).
    ; Root L26367: untrusted removable exFAT never becomes vfs_disk_handle by fallback; FSSEL only.
    call exfat_disk_register
    test rax, rax
    js   .exfat_done
.exfat_done:
    ; RCQ-20 S2: name encrypted (BitLocker/LUKS) volumes as refused; read-only, never a mount, RAX ignored.
    call fs_identify_scan
    call fat32_disk_kat
    test rax, rax
    jnz  .fail
    ; Task2400's command KAT depends on both this fragmented-chain verdict and
    ; the registry initialized earlier.  Running it here (not command_udp_init)
    ; prevents the prior boot-order skip where vfs_kat_fragmented was still 0.
    call fs_command_kat
    call fs_command_media_kat
    xor  eax, eax
    pop  r15
    ret
.fail:
    lea  rdi, [rel str_vfs_fail]
    call serial_string
    mov  rax, -1
    pop  r15
    ret

; ============================================================================
; fs/vfs data — vtables (R/O), mount table + volume pointers (in-image, RW+X
; image page today, like core/heap's heap_next), markers, fixtures.
; ============================================================================
; vtables are POPULATED AT RUNTIME by vfs_build_vtables (below): `dq <symbol>`
; in -f bin static data bakes the compile-time org-0 OFFSET, but UEFI loads the
; keep at a nonzero base, so a baked function pointer would call a bogus low
; address (#UD). We fill each slot with `lea rax,[rel fn]` at boot instead —
; the documented PaOS fix for runtime-VA function tables. Reserved as zeros here.
fat32_ops:  times fs_ops_size db 0
exfat_ops:  times fs_ops_size db 0
vfs_kat_ops: times fs_ops_size db 0

vfs_vol:       dq 0                      ; -> kmalloc'd RAM volume
vfs_scratch:   dq 0                      ; -> hex scratch
vfs_pattern:   dq 0                      ; -> 256-byte known pattern
vfs_pattern2:  dq 0                      ; -> 2nd distinct pattern (overwrite proof)
vfs_readbuf:   dq 0                      ; -> 512-byte readback buffer
vfs_mount_count: dd 0
vfs_ram_handle:   dd -1
vfs_exfat_handle: dd -1
vfs_kat_handle:   dd -1
vfs_disk_handle:  dd -1                  ; exported by flat namespace to GUESTFILE
vfs_m_stream:     db 0
vfs_m_second:     db 0
vfs_m_disk:       db 0
vfs_kat_fragmented: db 0
vfs_kat_cycle:      db 0
vfs_kat_bounds:     db 0
align 8
vfs_stat_buf:    times fs_stat_size db 0
vfs_path_name:   times 11 db 0
vfs_mounts:      times (VFS_MAX_MOUNTS * fsmount_size) db 0
; Naturally aligned (rc-vm 18:43:28): readers use plain aligned 64-bit movs, no lock.
align 8
vfs_copy_seq:    dq 0
; The active job alone owns this binding. Queue slots retain their own admission
; snapshots; dequeue publishes this only after its BEGIN succeeds.
vfs_copy_live_ops:   dq 0
vfs_copy_live_priv:  dq 0
vfs_copy_live_entry: dq 0
; RCQ-39 F-a: bumped (64-bit, no wrap) on every VFS-mediated write, delete, copy step, mount
; registration and disk re-point. Consumers compare snapshots. NOT counted: raw block writes
; below VFS, media swapped under a mount, the fat32 idle recovery sweep (below VFS, no file
; content change), and fat32_disk_select_exact / boot self-test re-points (boot-only today).
vfs_write_generation: dq 0
vfs_partial_job: dq 0
vfs_partial_record: times fs_copy_partial_size db 0
vfs_copy_job:    times fs_copy_job_size db 0
vfs_copy_recovery: times fs_copy_rec_size db 0   ; RCQ-20 S3, see vfs_copy_note_recovery
vfs_copy_refusal: dd 0                             ; RCQ-20 S4: FS_CREF_* of the last refused BEGIN
; RCQ-20 S5a: its own zero-storage block (no file bytes)
%macro WDATA_BSS_fs_vfs_copy_s5a 0
alignb 8
vfs_copy_queue:      resb FS_QUEUE_MAX * fs_copy_qrec_size   ; FIFO; [0] runs next
vfs_copy_qended:     resb fs_copy_job_size                   ; the last queued job cancelled before it ran
alignb 8
vfs_copy_item_live: resb fs_copy_item_size ; owned basename; no backend pointer escapes query
vfs_copy_item_phase: resq 1              ; private phase dword of the selected backend
vfs_copy_item_mask: resd 1
alignb 8
vfs_copy_paths_live: resb fs_copy_paths_size ; requested roots of the most recent successful top-level BEGIN
vfs_copy_stamp_hook: resq 1                                  ; the command layer's reason hook (vfs_copy_stamp)
vfs_copy_dropped:    resb FS_QUEUE_MAX * fs_copy_job_size    ; pending jobs a session change dropped (a ring)
vfs_copy_dropped_next: resd 1
alignb 8
vfs_pace_job:        resq 1
vfs_pace_n:          resd 1
vfs_pace_next:       resd 1
vfs_pace_samples:    resb FS_PACE_SAMPLES * fs_copy_pace_sample_size
%endmacro
WDATA_BSS_DEFER WDATA_BSS_fs_vfs_copy_s5a
; Smart copy B: the latest job's recorded failures (vfs_copy_fail_note), no file bytes
%macro WDATA_BSS_fs_vfs_copy_fail 0
alignb 8
vfs_copy_begin_error: resd 1                                ; this BEGIN only, no job mutation on refusal
vfs_copy_begin_pres:  resd 1                                ; error namespace, independent of parent PRESERVED
vfs_copy_fail_job:   resq 1                                  ; the job id the list belongs to
vfs_copy_fail_n:     resd 1                                  ; entries listed (<= FS_FAIL_MAX)
alignb 8
vfs_copy_fails:      resb FS_FAIL_MAX * fs_copy_fail_size
%endmacro
WDATA_BSS_DEFER WDATA_BSS_fs_vfs_copy_fail
; Smart copy E2: the ask job's WAITING list and its resolution, RAM only (no file bytes)
%macro WDATA_BSS_fs_vfs_copy_ask 0
alignb 8
vfs_ask_job:         resq 1                                  ; the ask job's id (0: none)
vfs_copy_policy_ptr: resq 1                                  ; the live backend's policy dword, set by its BEGIN
vfs_ask_phase:       resd 1                                  ; FS_ASK_* (0: not an ask job)
vfs_ask_answer:      resd 1                                  ; the answer for every item without its own (0: none)
vfs_ask_seq:         resd 1                                  ; the last item id this ask job gave (fs_copy_wait.id)
vfs_ask_n:           resd 1                                  ; items waiting, answered or not (vfs_ask_items)
vfs_ask_mount:       resd 1                                  ; the job's mount, for each child BEGIN
vfs_ask_cur:         resd 1                                  ; the item the live child copies
vfs_ask_child_begin: resd 1                                  ; 1 while vfs_ask_next runs a child BEGIN
vfs_ask_fail_n:      resd 1
vfs_ask_durable:     resd 1                                  ; the worst FS_DUR_* of the walk and its children
vfs_copy_differs:    resd 1                                  ; a backend's one-file skip-same compare differed
vfs_copy_replace_verdict: resd 1                            ; E2r: a REPLACE BEGIN's EXISTS: 0 newer (skip), 2 it asks, -1 none
alignb 8
vfs_ask_parent:      resb fs_copy_job_size                   ; the job's own record while a child runs
vfs_ask_view:        resb fs_copy_job_size                   ; what readers see then (vfs_ask_compose)
vfs_ask_stat:        resb fs_stat_size
vfs_ask_items:       resb (FS_WAIT_MAX + FS_WAIT_SPARE) * fs_copy_wait_size
%endmacro
WDATA_BSS_DEFER WDATA_BSS_fs_vfs_copy_ask
; Smart copy D: the latest check (vfs_copy_check), no file bytes
%macro WDATA_BSS_fs_vfs_copy_check 0
alignb 8
vfs_chk_block:                                               ; E1: the walk's whole state (vfs_scan_swap)
vfs_check:           resb fs_check_size
vfs_check_issues:    resb FS_CHECK_ISSUES * fs_check_issue_size
vfs_chk_frames:      resb FS_TREE_DEPTH_MAX * fs_check_frame_size
vfs_chk_page:        resb FS_CHECK_PAGE * fs_dirent_size
vfs_chk_info:        resb fs_info_size
alignb 8
vfs_chk_stat:        resb fs_stat_size
vfs_chk_dstat:       resb fs_stat_size
vfs_chk_smeta:       resb fs_replace_meta_size
vfs_chk_dmeta:       resb fs_replace_meta_size
vfs_chk_lres:        resb fs_list_result_size
alignb 8
vfs_chk_t0:          resq 1
vfs_chk_fsize:       resq 1
vfs_chk_nptr:        resq 1
vfs_chk_sh:          resd 1
vfs_chk_dh:          resd 1
vfs_chk_mode:        resd 1
vfs_chk_cb:          resd 1
vfs_chk_kind:        resd 1                                  ; 1 FAT32, 2 ext, 0 neither
vfs_chk_dmax:        resd 1
vfs_chk_depth:       resd 1
vfs_chk_nlen:        resd 1
vfs_chk_cslen:       resd 1
vfs_chk_cdlen:       resd 1
vfs_chk_cmerge:      resd 1
vfs_chk_topref:      resd 1                                  ; E1: the top is refused (EXISTS): no space verdict
vfs_list_skip:       resd 1                                  ; entries a paging list_dir passes first (FSCHECK only; else 0)
vfs_chk_src:         resb FS_CHECK_PATH + 1
vfs_chk_dst:         resb FS_CHECK_PATH + 1
alignb 8
vfs_chk_block_end:
vfs_scan_state:      resb vfs_chk_block_end - vfs_chk_block  ; E1: the job scan's walk while it is not stepping
vfs_scan_child_state: resb vfs_chk_block_end - vfs_chk_block ; temporary ASK directory preflight, never published
vfs_scan_job:        resq 1                                  ; the job the scan belongs to (0 none)
vfs_chk_ms:          resq 1                                  ; this call's milliseconds (FSCHECK: FS_CHECK_BUDGET_MS)
vfs_chk_cap:         resd 1                                  ; nodes the walk stops at (FSCHECK: FS_CHECK_ENTRIES)
vfs_chk_resumable:   resd 1                                  ; 1 a bound pauses the walk (the job scan)
vfs_chk_e0:          resd 1                                  ; nodes at this call's start: no budget before one more
vfs_scan_status:     resd 1                                  ; FS_SCAN_*
vfs_copy_between_sh: resd 1                                  ; vfs_copy_start_between's source handle, for the scan
%endmacro
WDATA_BSS_DEFER WDATA_BSS_fs_vfs_copy_check

str_fat32_name:  db "fat32", 0
str_exfat_name:  db "c8-ro-mock", 0
str_vfs_kat_name: db "throwaway-ro", 0
name_data_bin:   db "DATA    BIN"        ; 11-byte 8.3 ("DATA"+4sp+"BIN")
vfs_tmpname:     db "~TMPSWAP   "        ; 11-byte 8.3 temp name ("~TMPSWAP"+3sp)
exfat_content:   db "C8-RO-MOCK-BACKEND", 10
.len equ $ - exfat_content
vfs_kat_content: db "throwaway-backend-selected-by-handle"
.len equ $ - vfs_kat_content

str_init_ready:      db "[PAOS64] C8 vfs.init.ready: 2 backends mounted (fat32 rw + c8 ro-mock)", 13, 10, 0
str_selftest_basic:  db "[PAOS64] C8 vfs.selftest.basic: mount-table class dispatch + fat round-trip PASS", 13, 10, 0
str_wr_a:            db "[PAOS64] C8 vfs.writefile.tempswap: temp clus=0x", 0
str_wr_b:            db " wrote 256 bytes -> atomic name-swap DATA.BIN", 13, 10, 0
str_rb_match:        db "[PAOS64] C8 vfs.readback.match: read 256 bytes cmp=OK byte-equal match", 13, 10, 0
str_ovw_ok:          db "[PAOS64] C8 vfs.overwrite.swap: DATA.BIN re-written; readback=new content, old content gone OK", 13, 10, 0
str_del_ok:          db "[PAOS64] C8 vfs.delete.verify: unlinked DATA.BIN reread=ENOENT OK", 13, 10, 0
str_exfat_init:      db "[PAOS64] C8 mock.init: degenerate 2nd backend mounted (read-only mock, not exFAT)", 13, 10, 0
str_vfs_stream_ops:  db "[PAOS64] C8 VFS stat/read_at tail slots content-grade PASS [vfs.stream.ops]",13,10,0
str_vfs_registry_second: db "[PAOS64] C8 VFS N-ary registry selected throwaway read-only backend by handle [vfs.mount.registry.second]",13,10,0
str_vfs_fallback_proved: db "[PAOS64] C8 VFS single-device GPT-gap fallback proof PASS [data.store.fallback.proved]",13,10,0
str_vfs_fallback_refused: db "[PAOS64] C8 VFS system-disk fallback write proof REFUSED [data.store.fallback.refused]",13,10,0
str_vfs_fail:        db "[PAOS64] C8 vfs.selftest: FAIL (content/dispatch check failed)", 13, 10, 0

; Exact read-only FAT selection uses a separate context and no write authority.
vfs_select_fat_ro_exact:
    jmp fat32_disk_select_ro_exact

; Read-only exact built-in backing facts for census only. These two legacy
; vtables have no info slot. Never infer a private backend from its name/absence.
; RDI=actual fsmount, RSI=cleared fs_info. EAX=1 RAM FAT,2 no-filesystem mock,
; 0 unknown/unavailable. No selector, registry, volume or write-generation change.
vfs_builtin_census:
    xor eax,eax
    mov rdx,[rdi+fsmount.ops]
    lea rcx,[rel fat32_ops]
    cmp rdx,rcx
    jne .mock
    mov rdx,[rel vfs_vol]
    test rdx,rdx
    jz .out
    cmp word [rdx+510],0xaa55
    jne .out
    cmp word [rdx+11],VFS_BPS
    jne .out
    cmp byte [rdx+13],VFS_SPC
    jne .out
    mov ecx,[rdx+32]
    cmp ecx,VFS_TOTSEC
    jne .out
    mov [rsi+fs_info.total_sectors],rcx
    movzx ecx,word [rdx+11]
    movzx edi,byte [rdx+13]
    imul ecx,edi
    mov [rsi+fs_info.cluster_bytes],ecx
    mov ecx,[rdx+67]
    mov [rsi+fs_info.volume_id],ecx
    lea rcx,[rel str_vfs_census_ram]
    mov [rsi+fs_info.backend],rcx
    mov eax,1
    jmp .binding
.mock:
    lea rcx,[rel exfat_ops] ; historical variable; this is c8-ro-mock, not exFAT
    cmp rdx,rcx
    jne .out
    lea rcx,[rel str_vfs_census_mock]
    mov [rsi+fs_info.backend],rcx
    mov dword [rsi+fs_info.volume_id],0
    mov dword [rsi+fs_info.cluster_bytes],0 ; no filesystem or sector geometry
    mov qword [rsi+fs_info.total_sectors],0
    mov eax,2
.binding:
    mov qword [rsi+fs_info.device],0
    mov qword [rsi+fs_info.part_start],-1
    mov qword [rsi+fs_info.part_sectors],0
    mov dword [rsi+fs_info.scheme],-1
    mov dword [rsi+fs_info.part_count],0
.out:
    ret
str_vfs_census_ram: db 'fat32_ram_test',0
str_vfs_census_mock: db 'c8-ro-mock',0

%include "fs/owned_media.asm"
%include "fs/guest_volume.asm"
