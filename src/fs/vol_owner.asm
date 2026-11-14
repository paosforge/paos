;; MODULE fs/vol_owner
;; LAYER 4
;; EXPORTS vol_owner_read_prepare, vol_owner_read_catalog, vol_owner_read_resolve, vol_owner_mount_bound, vol_owner_load, vol_owner_probe, vol_owner_adopt, vol_owner_release, vol_owner_reset, vol_owner_bind_mount, vol_owner_live_check, vol_owner_live_check_files, vol_owner_local_snapshot, vol_owner_local_adopt, vol_owner_local_cancel, vol_owner_device_dirty, vol_owner_status_text, vol_owner_state, vol_owner_last_error
;; IMPORTS fs/vfs, fs/blockdev, fs/storage_access, fs/fat32_disk, fs/guest_volume, sec/principal, sec/session, sec/adopt_decision, core/lib/aes256_gcm, core/lib/hkdf_sha256, core/lib/crc32, core/lib/mem, core/csprng, core/time, boot/nvram_access, boot/serial
;; CAPS CAP_BLOCK_READ
;; OWNER saga:rcq20_filesystems
;; CONTEXT: bsp_only  (serialized command/poll consumer, like data/config_store; module-static scratch)
; ============================================================================
; fs/vol_owner.asm — durable volume ownership registry (RCQ-21 SA1; design
; proposals/rc-fs-claude-20261007/DESIGN_RCQ-21-SA-durable-volume-ownership.md,
; admin GO 2026-10-09 07:15:18 with conditions).
;
; The owner adopts a volume ONCE (an authenticated owner request carrying
; SA_INTENT_SPECIAL). The adoption is recorded in one sealed UEFI variable,
; PaOSVolOwn1 under the PaOS vendor GUID, with the data/config_store pattern:
; key = HKDF(machine credential, "PaOS volume ownership v1"), AES-256-GCM,
; the record magic as AAD, exact-size write, readback, reopen and compare.
; A factory reset wipes the machine credential, so every adoption is revoked.
;
; SA2 authorizes only explicit owned-filesystem operations using bind_mount /
; live_check and blk_write_owned; generic blk_write gains no authority. The
; optional DATA role delegates only the separately bounded native DATA service
; to a single adopted GPT FAT32 volume (fs/vol_owner_data.asm).
;
; Identity bound per entry (all of it must match the live media, re-read from
; the disk, never taken from a backend's cached context):
;   GPT: disk GUID, partition GUID, type GUID, first LBA, sector count
;        (header CRC and entry-array CRC verified; exactly one entry matches)
;   MBR: disk signature (nonzero), primary partition index, type, first LBA, count
;   FS : FAT32 volume id + label, or the ext superblock UUID; filesystem kind
; Exact clones that preserve every one of these fields are indistinguishable;
; when two live volumes match one entry at the same time, NEITHER is bound
; (VO_E_DUP) until the owner releases or one is removed.
;
; Eligibility (conservative; admin D3): FAT32 on GPT basic-data or MBR 0x0B/0x0C,
; ext2/3/4 on GPT Linux-filesystem or MBR 0x83; 512-byte logical sectors;
; clean (FAT[1] clean-shutdown + no-error bits; ext VALID, no ERRORS, no
; RECOVER). Refused: the ESP and every other type, GPT attribute bit 0
; (platform-required), NTFS, superfloppy, extended/logical MBR, the FAT
; volume selected by the INITRD.GZ boot marker, and any volume on a removable
; device (blk_info.removable or BLKF_REMOVABLE: removable and foreign media
; writes stay Peter-reserved; checked in vol_owner_probe, so at ADOPT, at bind
; and by every live_check's full re-probe).
;
; Persistence is fail-closed. Any failure after SetVariable was attempted
; leaves the registry UNCERTAIN: nothing is owned, the cache is cleared, and
; only a reload decides what the firmware actually holds (old, new or corrupt).
; A record that does not open, or a malformed plaintext, is CORRUPT: nothing is
; owned and ADOPT is refused until the owner RESETs (which only removes
; authority). An absent variable is an empty registry.
; ============================================================================

VO_ST_UNLOADED  equ 0
VO_ST_OK        equ 1
VO_ST_CORRUPT   equ 2
VO_ST_UNCERTAIN equ 3
VO_ST_NOKEY     equ 4

VO_E_NONE      equ 0
VO_E_NOMOUNT   equ 1
VO_E_IO        equ 2
VO_E_GEOMETRY  equ 3
VO_E_SCHEME    equ 4
VO_E_NOENTRY   equ 5
VO_E_TYPE      equ 6
VO_E_ATTR      equ 7
VO_E_FSKIND    equ 8
VO_E_DIRTY     equ 9
VO_E_MARKER    equ 10
VO_E_DENIED    equ 11
VO_E_FULL      equ 12
VO_E_EXISTS    equ 13
VO_E_REGISTRY  equ 14
VO_E_PERSIST   equ 15
VO_E_NOKEY     equ 16
VO_E_NOTFOUND  equ 17
VO_E_DUP       equ 18
VO_E_NOTOWNED  equ 19
VO_E_EXHAUSTED equ 20             ; the bind sequence reached its limit: refused, never reused
VO_E_REMOVABLE equ 21             ; the volume's device is removable (Peter-reserved media)
VO_E_NOTEMPTY  equ 22             ; own partition A4 (SEC E5): the root holds more than a label and SVI
VO_E_SNAPSHOT  equ 23             ; own partition A3: no live snapshot slot for this mount and id, or it expired
VO_E_CHANGED   equ 24             ; own partition A3: the live identity differs from the snapshot's
VO_E_DECISION  equ 25             ; own partition A3: no valid one-use owner decision for this snapshot
VO_E_BUSY      equ 26             ; own partition A3 (SEC108128 P4): a guest volume job fences the device
VO_E_SESSION   equ 27             ; own partition A3 (SEC108128 P2): not the same unlocked owner session
VO_PRIN_OWNER  equ 1              ; == sec/principal PRIN_OWNER (pinned by test)
VO_SNAP_LIFE_US equ 120000000     ; a snapshot older than 120 s is never adopted
VO_DG_MAGIC    equ 0xD524         ; = fat32_disk FD_DG_MAGIC (directory-growth journal); pinned by test
VO_CP_MAGIC    equ 0xC524         ; = fat32_disk FD_CP_MAGIC (copy journal); pinned by test
VO_SNAP_OUT    equ 96             ; vol_owner_local_snapshot's display record
VO_ROOT_MAX    equ 64             ; root chain clusters read by the empty check: fat32_disk FD_DIR_MAX_CLUSTERS

VO_KIND_FAT32  equ 1
VO_KIND_EXT    equ 2
VO_SCHEME_MBR  equ 1
VO_SCHEME_GPT  equ 2

VO_ENT_MAX     equ 8
VO_ENT_SIZE    equ 128
VO_HDR_SIZE    equ 32
VO_PLAIN_SIZE  equ VO_HDR_SIZE + VO_ENT_MAX * VO_ENT_SIZE
VO_RECORD_SIZE equ 16 + VO_PLAIN_SIZE + 16
; header
VOH_MAGIC      equ 0          ; 'VOR1'
VOH_COUNT      equ 4          ; in-use entries
VOH_GEN        equ 8          ; bumped by every saved change
VOH_SEQ        equ 16         ; last adoption sequence
; entry (identity = bytes VO_ID_OFF .. VO_ID_OFF+VO_ID_LEN-1)
VOE_MAGIC      equ 0          ; 'VOE1' in use, 0 free (whole entry zero)
VOE_KIND       equ 4
VOE_SCHEME     equ 5
VOE_MBR_INDEX  equ 6
VOE_MBR_TYPE   equ 7
VOE_FIRST      equ 8
VOE_COUNT      equ 16
VOE_DISK       equ 24         ; GPT disk GUID / MBR signature dword
VOE_PART       equ 40         ; GPT partition GUID
VOE_TYPE       equ 56         ; GPT type GUID
VOE_FSID       equ 72         ; ext UUID / FAT volume id dword + 11-byte label
VOE_ATTRS      equ 88         ; GPT attributes (eligibility only; not identity)
VOE_SEQ        equ 96
VOE_TIME       equ 104
VO_ID_OFF      equ 4
VO_ID_LEN      equ 84         ; kind .. fsid

VO_BIND_MAX    equ 8
VOB_DEV        equ 0
VOB_FIRST      equ 8
VOB_COUNT      equ 16
VOB_MGEN       equ 24
VOB_EPOCH      equ 32
VOB_SEQ        equ 40
VOB_ENTRY      equ 48
VOB_FLAGS      equ 52
VOB_KIND       equ 56
VOB_MOUNT      equ 60             ; the vfs mount handle the binding was made through
VOB_SIZE       equ 64
VOB_F_LIVE     equ 1
VOB_F_DUP      equ 2
VO_BIND_SEQ_LIMIT equ 0x00FFFFFFFFFFFFFF  ; 56-bit token sequence

VO_GPT_ARR_MAX equ 16384      ; 128 entries of 128 bytes
VO_FW_READ     equ 0
VO_FW_WRITE    equ 1
VO_EFI_NOT_FOUND equ 0x800000000000000E
VO_FD_SELECT_MARKER equ 1     ; = fat32_disk FD_SELECT_MARKER (pinned by the host test)
VO_SECTOR      equ 512

; ---------------------------------------------------------------------------
; vol_owner_state() -> EAX = VO_ST_*;  vol_owner_last_error() -> EAX = VO_E_*
vol_owner_state:
    movzx eax, byte [rel vo_state]
    ret
vol_owner_last_error:
    mov  eax, [rel vo_last_error]
    ret

; vo_fail(EAX = VO_E_*) -> records it, EAX unchanged.
vo_fail:
    mov  [rel vo_last_error], eax
    ret

; ---------------------------------------------------------------------------
; vo_read(RDI=dev, RSI=lba, RDX=buf) -> EAX 0 / -1: ONE 512-byte sector.
vo_read:
    mov  rcx, rdx
    mov  edx, 1
    call blk_read
    test rax, rax
    jnz  .bad
    xor  eax, eax
    ret
.bad:
    mov  eax, -1
    ret

; vo_guid_eq(RDI=a16, RSI=b16) -> ZF set when equal. Clobbers RAX.
vo_guid_eq:
    mov  rax, [rdi]
    cmp  rax, [rsi]
    jne  .out
    mov  rax, [rdi + 8]
    cmp  rax, [rsi + 8]
.out:
    ret

; ---------------------------------------------------------------------------
; vol_owner_probe(EDI = mount handle, RSI = 128-byte identity out)
;   -> EAX 0 eligible (identity filled, vo_probe_dev set) / VO_E_* refused.
; Read-only: blk_read only. Every fact comes from the live media.
vol_owner_probe:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8
    mov  ebp, edi                        ; handle
    mov  r15, rsi                        ; identity out
    mov  qword [rel vo_probe_dev], 0
    mov  byte [rel vo_probe_part], 0
    mov  rdi, r15
    xor  esi, esi
    mov  edx, VO_ENT_SIZE
    call memset
    mov  edi, ebp
    call vfs_mount_ptr
    test rax, rax
    jz   .nomount
    mov  [rel vo_probe_mount], rax
    mov  edi, ebp
    lea  rsi, [rel vo_fsinfo]
    call vfs_info
    test rax, rax
    jnz  .nomount
.window:
    mov  rbx, [rel vo_fsinfo + fs_info.device]
    test rbx, rbx
    jz   .nomount
    mov  rax, [rbx + dev.info]
    test rax, rax
    jz   .nomount
    cmp  dword [rbx + dev.health], HEALTH_OK
    jne  .io
    cmp  byte [rax + blk_info.removable], 0
    jne  .removable
    test dword [rax + blk_info.flags], BLKF_REMOVABLE
    jnz  .removable
    cmp  dword [rax + blk_info.sector_size], VO_SECTOR
    jne  .geometry
    mov  r12, [rel vo_fsinfo + fs_info.part_start]
    mov  r13, [rel vo_fsinfo + fs_info.part_sectors]
    test r13, r13
    jz   .geometry
    mov  rcx, r12
    add  rcx, r13                        ; end (exclusive)
    jc   .geometry
    dec  rcx                             ; last
    cmp  rcx, [rax + blk_info.lba_max]
    ja   .geometry
    mov  dword [r15 + VOE_MAGIC], 'VOE1'
    mov  [r15 + VOE_FIRST], r12
    mov  [r15 + VOE_COUNT], r13
    ; ---- the partition table, read back from LBA 0/1 ----
    mov  rdi, rbx
    xor  esi, esi
    lea  rdx, [rel vo_sector]
    call vo_read
    test eax, eax
    jnz  .io
    cmp  word [rel vo_sector + 510], 0xAA55
    jne  .scheme
    mov  eax, [rel vo_fsinfo + fs_info.scheme]
    cmp  eax, FS_SCHEME_GPT
    je   .gpt
    cmp  eax, FS_SCHEME_MBR
    jne  .scheme
    ; ---- MBR: a primary entry, a nonzero disk signature, no protective 0xEE ----
    mov  byte [r15 + VOE_SCHEME], VO_SCHEME_MBR
    mov  eax, [rel vo_sector + 440]
    test eax, eax
    jz   .scheme
    mov  [r15 + VOE_DISK], eax
    xor  ecx, ecx                        ; entry index
    mov  r14d, -1                        ; matched index
.mbr_scan:
    cmp  ecx, 4
    jae  .mbr_done
    mov  edx, ecx
    shl  edx, 4
    lea  rsi, [rel vo_sector + 446]
    add  rsi, rdx
    movzx eax, byte [rsi + 4]
    cmp  eax, 0xEE
    je   .scheme                         ; a GPT disk presented as MBR: refuse
    test eax, eax
    jz   .mbr_next
    mov  eax, [rsi + 8]
    cmp  rax, r12
    jne  .mbr_next
    mov  eax, [rsi + 12]
    cmp  rax, r13
    jne  .mbr_next
    cmp  r14d, -1
    jne  .noentry                        ; two entries with one window
    mov  r14d, ecx
.mbr_next:
    inc  ecx
    jmp  .mbr_scan
.mbr_done:
    cmp  r14d, -1
    je   .noentry                        ; extended/logical or no entry: not eligible
    mov  [r15 + VOE_MBR_INDEX], r14b
    lea  eax, [r14d + 1]
    mov  [rel vo_probe_part], al          ; display only, never identity
    mov  edx, r14d
    shl  edx, 4
    lea  rsi, [rel vo_sector + 446]
    movzx eax, byte [rsi + rdx + 4]
    mov  [r15 + VOE_MBR_TYPE], al
    cmp  eax, 0x0B
    je   .fs
    cmp  eax, 0x0C
    je   .fs
    cmp  eax, 0x83
    je   .fs
    jmp  .type
    ; ---- GPT: header CRC, array CRC, exactly one entry with this window ----
.gpt:
    mov  byte [r15 + VOE_SCHEME], VO_SCHEME_GPT
    mov  rdi, rbx
    mov  esi, 1
    lea  rdx, [rel vo_gpt_hdr]
    call vo_read
    test eax, eax
    jnz  .io
    mov  rax, 'EFI PART'
    cmp  [rel vo_gpt_hdr], rax
    jne  .scheme
    mov  esi, [rel vo_gpt_hdr + 12]      ; header size
    cmp  esi, 92
    jb   .scheme
    cmp  esi, VO_SECTOR
    ja   .scheme
    mov  eax, [rel vo_gpt_hdr + 16]
    mov  [rsp], eax
    mov  dword [rel vo_gpt_hdr + 16], 0
    lea  rdi, [rel vo_gpt_hdr]
    call hotpatch_crc32
    mov  ecx, [rsp]
    mov  [rel vo_gpt_hdr + 16], ecx
    cmp  eax, ecx
    jne  .scheme
    cmp  dword [rel vo_gpt_hdr + 84], 128 ; entry size
    jne  .scheme
    mov  eax, [rel vo_gpt_hdr + 80]      ; entry count
    test eax, eax
    jz   .scheme
    cmp  eax, VO_GPT_ARR_MAX / 128
    ja   .scheme
    mov  r14d, eax                       ; entries
    lea  rdi, [r15 + VOE_DISK]
    lea  rsi, [rel vo_gpt_hdr + 56]
    mov  edx, 16
    call memcpy
    ; read ceil(entries*128/512) sectors of the array
    mov  eax, r14d
    shl  eax, 7
    add  eax, VO_SECTOR - 1
    shr  eax, 9
    mov  [rsp + 4], eax                  ; sectors to read
    mov  rax, [rel vo_gpt_hdr + 72]      ; array LBA
    mov  ecx, [rsp + 4]
    add  rcx, rax
    jc   .scheme
    mov  rdx, [rbx + dev.info]
    dec  rcx
    cmp  rcx, [rdx + blk_info.lba_max]
    ja   .scheme
    xor  ecx, ecx
.arr_read:
    cmp  ecx, [rsp + 4]
    jae  .arr_crc
    push rcx
    push rcx
    mov  rsi, [rel vo_gpt_hdr + 72]
    add  rsi, rcx
    lea  rdx, [rel vo_gpt_arr]
    shl  ecx, 9
    add  rdx, rcx
    mov  rdi, rbx
    call vo_read
    pop  rcx
    pop  rcx
    test eax, eax
    jnz  .io
    inc  ecx
    jmp  .arr_read
.arr_crc:
    lea  rdi, [rel vo_gpt_arr]
    mov  esi, r14d
    shl  esi, 7
    call hotpatch_crc32
    cmp  eax, [rel vo_gpt_hdr + 88]
    jne  .scheme
    xor  ecx, ecx
    xor  edx, edx                        ; matched entry pointer
.gpt_scan:
    cmp  ecx, r14d
    jae  .gpt_done
    mov  esi, ecx
    shl  esi, 7
    lea  rdi, [rel vo_gpt_arr]
    add  rdi, rsi
    mov  rax, [rdi]
    or   rax, [rdi + 8]
    jz   .gpt_next                       ; unused entry
    cmp  [rdi + 32], r12
    jne  .gpt_next
    mov  rax, r12
    add  rax, r13
    dec  rax
    cmp  [rdi + 40], rax
    jne  .gpt_next
    test rdx, rdx
    jnz  .noentry                        ; two entries with one window
    mov  rdx, rdi
.gpt_next:
    inc  ecx
    jmp  .gpt_scan
.gpt_done:
    test rdx, rdx
    jz   .noentry
    mov  r14, rdx
    lea  rax, [rel vo_gpt_arr]
    mov  rcx, rdx
    sub  rcx, rax
    shr  rcx, 7
    inc  ecx
    mov  [rel vo_probe_part], cl          ; display only, never identity
    mov  rax, [r14 + 48]
    mov  [r15 + VOE_ATTRS], rax
    lea  rdi, [r15 + VOE_PART]
    lea  rsi, [r14 + 16]
    mov  edx, 16
    call memcpy
    lea  rdi, [r15 + VOE_TYPE]
    mov  rsi, r14
    mov  edx, 16
    call memcpy
    lea  rdi, [r15 + VOE_TYPE]
    lea  rsi, [rel vo_guid_esp]
    call vo_guid_eq
    je   .type
    lea  rdi, [r15 + VOE_TYPE]
    lea  rsi, [rel vo_guid_basic]
    call vo_guid_eq
    je   .gpt_attr
    lea  rdi, [r15 + VOE_TYPE]
    lea  rsi, [rel vo_guid_linux]
    call vo_guid_eq
    jne  .type
.gpt_attr:
    test byte [r15 + VOE_ATTRS], 1       ; platform-required
    jnz  .attr
    ; ---- the filesystem, read from its own first sectors ----
.fs:
    mov  rdi, rbx
    mov  rsi, r12
    lea  rdx, [rel vo_sector]
    call vo_read
    test eax, eax
    jnz  .io
    mov  rax, 'NTFS    '
    cmp  [rel vo_sector + 3], rax
    je   .fskind
    call vo_bpb_is_fat32
    test eax, eax
    jz   .try_ext
    mov  byte [r15 + VOE_KIND], VO_KIND_FAT32
    mov  eax, [rel vo_sector + 67]       ; volume id
    mov  [r15 + VOE_FSID], eax
    lea  rdi, [r15 + VOE_FSID + 4]
    lea  rsi, [rel vo_sector + 71]       ; label
    mov  edx, 11
    call memcpy
    ; type consistency: GPT basic-data or MBR 0x0B/0x0C
    cmp  byte [r15 + VOE_SCHEME], VO_SCHEME_GPT
    jne  .fat_mbr
    lea  rdi, [r15 + VOE_TYPE]
    lea  rsi, [rel vo_guid_basic]
    call vo_guid_eq
    jne  .type
    jmp  .fat_marker
.fat_mbr:
    cmp  byte [r15 + VOE_MBR_TYPE], 0x83
    je   .type
.fat_marker:
    ; The raw read-only resolver has no mount yet. Check the boot extent as
    ; well as the original mount guard; neither route may view the boot marker
    ; volume as adopted files.
    mov  rdi, rbx
    mov  rsi, r12
    mov  rdx, r13
    call fat32_disk_is_boot_extent
    test eax, eax
    jnz  .marker
    ; the FAT volume the INITRD.GZ boot marker selected is never adoptable
    mov  rax, [rel vo_probe_mount]
    test rax, rax
    jz   .fat_clean
    lea  rcx, [rel fat32_disk_ops]
    cmp  [rax + fsmount.ops], rcx
    jne  .fat_clean
    cmp  byte [rel fat32_disk_selection_reason], VO_FD_SELECT_MARKER
    je   .marker
.fat_clean:
    ; own partition A4 (SEC D1): boot-sector byte 0x41 bit 0 is the volume-dirty flag Linux vfat and
    ; Windows set (dosfstools fsck.fat 4.2 reports it as "Dirty bit is set"). vo_sector is still LBA first.
    test byte [rel vo_sector + 0x41], 1
    jnz  .dirty
    movzx esi, word [rel vo_sector + 14] ; reserved sectors: FAT #1 starts here
    add  rsi, r12
    mov  rdi, rbx
    lea  rdx, [rel vo_sector]
    call vo_read
    test eax, eax
    jnz  .io
    mov  eax, [rel vo_sector + 4]        ; FAT[1]
    and  eax, 0x0C000000                 ; clean-shutdown | no-hard-error
    cmp  eax, 0x0C000000
    jne  .dirty
    jmp  .ok
.try_ext:
    mov  rdi, rbx
    lea  rsi, [r12 + 2]                  ; superblock at byte 1024
    lea  rdx, [rel vo_sector]
    call vo_read
    test eax, eax
    jnz  .io
    cmp  word [rel vo_sector + 56], 0xEF53
    jne  .fskind
    movzx eax, word [rel vo_sector + 58] ; s_state
    and  eax, 3
    cmp  eax, 1                          ; VALID, no ERRORS
    jne  .dirty
    ; INCOMPAT_RECOVER (journal needs replay) refuses adoption. A live re-check
    ; tolerates it: ext4_write sets it on disk between the steps of its own
    ; journaled transaction (ext4_write.asm:37-43). VALID/no-ERRORS still holds.
    cmp  byte [rel vo_probe_live], 0
    jne  .ext_id
    test dword [rel vo_sector + 96], 4
    jnz  .dirty
.ext_id:
    mov  byte [r15 + VOE_KIND], VO_KIND_EXT
    lea  rdi, [r15 + VOE_FSID]
    lea  rsi, [rel vo_sector + 104]
    mov  edx, 16
    call memcpy
    cmp  byte [r15 + VOE_SCHEME], VO_SCHEME_GPT
    jne  .ext_mbr
    lea  rdi, [r15 + VOE_TYPE]
    lea  rsi, [rel vo_guid_linux]
    call vo_guid_eq
    jne  .type
    jmp  .ok
.ext_mbr:
    cmp  byte [r15 + VOE_MBR_TYPE], 0x83
    jne  .type
.ok:
    mov  [rel vo_probe_dev], rbx
    xor  eax, eax
    jmp  .out
.nomount:  mov eax, VO_E_NOMOUNT
    jmp  .out
.io:       mov eax, VO_E_IO
    jmp  .out
.removable: mov eax, VO_E_REMOVABLE
    jmp  .out
.geometry: mov eax, VO_E_GEOMETRY
    jmp  .out
.scheme:   mov eax, VO_E_SCHEME
    jmp  .out
.noentry:  mov eax, VO_E_NOENTRY
    jmp  .out
.type:     mov eax, VO_E_TYPE
    jmp  .out
.attr:     mov eax, VO_E_ATTR
    jmp  .out
.fskind:   mov eax, VO_E_FSKIND
    jmp  .out
.dirty:    mov eax, VO_E_DIRTY
    jmp  .out
.marker:   mov eax, VO_E_MARKER
.out:
    call vo_fail
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Internal raw-window observation: same parser and strict dirty result as
; vol_owner_probe, without inventing a VFS mount. vo_fsinfo was filled by the
; resolver from a sealed identity and a live registered device. No binding or
; write authority is issued. The full FAT identity is filled before DIRTY.
; RSI=identity out; same saved-register frame as vol_owner_probe.window.
vo_probe_extent:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8
    mov  r15, rsi
    mov  qword [rel vo_probe_mount], 0
    mov  qword [rel vo_probe_dev], 0
    mov  byte [rel vo_probe_part], 0
    mov  rdi, r15
    xor  esi, esi
    mov  edx, VO_ENT_SIZE
    call memset
    jmp  vol_owner_probe.window

; vo_bpb_is_fat32 (vo_sector = boot sector) -> EAX 1 a FAT32 BPB, 0 not.
vo_bpb_is_fat32:
    cmp  word [rel vo_sector + 510], 0xAA55
    jne  .no
    cmp  word [rel vo_sector + 11], VO_SECTOR
    jne  .no
    movzx eax, byte [rel vo_sector + 13]  ; sectors per cluster: a power of two
    test eax, eax
    jz   .no
    lea  ecx, [eax - 1]
    test eax, ecx
    jnz  .no
    cmp  word [rel vo_sector + 14], 0     ; reserved sectors
    je   .no
    movzx eax, byte [rel vo_sector + 16]  ; FAT count
    cmp  eax, 1
    jb   .no
    cmp  eax, 2
    ja   .no
    cmp  word [rel vo_sector + 17], 0     ; root entries
    jne  .no
    cmp  word [rel vo_sector + 19], 0     ; total sectors 16
    jne  .no
    cmp  word [rel vo_sector + 22], 0     ; FAT size 16
    jne  .no
    cmp  dword [rel vo_sector + 36], 0    ; FAT size 32
    je   .no
    mov  rax, 'FAT32   '
    cmp  [rel vo_sector + 82], rax
    jne  .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; Own partition A4 (SEC 107877 E1-E4): the empty-volume check, read from live media.
; vo_root_empty(RDI = dev, RSI = partition first LBA) -> EAX 0 empty / VO_E_NOTEMPTY / VO_E_IO.
; blk_read only. Every 32-byte slot of the whole root cluster chain (at most VO_ROOT_MAX clusters,
; the journal sweep's own bound) is read; the scan does not stop at 0x00. Allowed: free (0x00),
; deleted (0xE5), at most one volume label (attr 0x08, no cluster, size 0) and at most one System
; Volume Information directory (SFN 'SYSTEM~1   ', directory plus hidden or system) preceded by
; exactly its two LFN slots, whose checksum matches it. After the first 0x00 slot only 0x00 or 0xE5
; may follow. A slot carrying FD_DG_MAGIC or FD_CP_MAGIC at +12 is refused. A chain over the bound,
; a loop, a free, bad or out-of-range link, or an unreadable sector refuses.
vo_root_empty:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8
    mov  rbx, rdi
    mov  r12, rsi
    mov  rdi, rbx
    mov  rsi, r12
    lea  rdx, [rel vo_sector]
    call vo_read
    test eax, eax
    jnz  .io
    call vo_bpb_is_fat32
    test eax, eax
    jz   .notempty
    movzx eax, byte [rel vo_sector + 13]
    mov  [rel vo_e_spc], eax
    movzx ecx, word [rel vo_sector + 14]  ; reserved
    lea  rax, [r12 + rcx]
    mov  [rel vo_e_fat_lba], rax
    movzx eax, byte [rel vo_sector + 16]  ; FAT count
    mov  edx, [rel vo_sector + 36]        ; FAT size 32
    imul rax, rdx
    add  rax, rcx                         ; sectors before the data region
    mov  r13, rax
    mov  eax, [rel vo_sector + 32]        ; total sectors 32
    cmp  rax, r13
    jbe  .notempty
    sub  rax, r13
    xor  edx, edx
    mov  ecx, [rel vo_e_spc]
    div  rcx
    add  rax, 2                           ; exclusive cluster bound
    mov  ecx, 0x0FFFFFF7
    cmp  rax, rcx
    cmova rax, rcx                        ; a BAD mark or above is never a link
    mov  ecx, [rel vo_sector + 36]
    shl  rcx, 7                           ; entries one FAT holds
    cmp  rax, rcx
    ja   .notempty
    mov  [rel vo_e_max], eax
    lea  rax, [r12 + r13]
    mov  [rel vo_e_data_lba], rax
    mov  r14d, [rel vo_sector + 44]       ; root cluster
    xor  eax, eax
    mov  [rel vo_e_term], al
    mov  [rel vo_e_label], al
    mov  [rel vo_e_svi], al
    mov  [rel vo_e_lfn], al
    mov  [rel vo_e_chk], al
    xor  r15d, r15d
.cluster:
    cmp  r14d, 2
    jb   .notempty
    cmp  r14d, [rel vo_e_max]
    jae  .notempty
    cmp  r15d, VO_ROOT_MAX
    jae  .notempty
    lea  rdx, [rel vo_e_seen]
    xor  ecx, ecx
.seen:
    cmp  ecx, r15d
    jae  .remember
    cmp  r14d, [rdx + rcx*4]
    je   .notempty                        ; a loop
    inc  ecx
    jmp  .seen
.remember:
    mov  [rdx + r15*4], r14d
    inc  r15d
    mov  eax, r14d
    sub  eax, 2
    mov  ecx, [rel vo_e_spc]
    imul rax, rcx
    add  rax, [rel vo_e_data_lba]
    mov  rbp, rax
    mov  dword [rsp], 0
.sector:
    mov  eax, [rsp]
    cmp  eax, [rel vo_e_spc]
    jae  .next_cluster
    mov  rdi, rbx
    lea  rsi, [rbp + rax]
    lea  rdx, [rel vo_sector]
    call vo_read
    test eax, eax
    jnz  .io
    lea  rdi, [rel vo_sector]
    call vo_empty_slots
    test eax, eax
    jnz  .notempty
    inc  dword [rsp]
    jmp  .sector
.next_cluster:
    mov  esi, r14d
    shr  esi, 7                           ; 128 FAT entries per sector
    add  rsi, [rel vo_e_fat_lba]
    mov  rdi, rbx
    lea  rdx, [rel vo_fat_sector]
    call vo_read
    test eax, eax
    jnz  .io
    mov  eax, r14d
    and  eax, 127
    lea  rcx, [rel vo_fat_sector]
    mov  eax, [rcx + rax*4]
    and  eax, 0x0FFFFFFF
    cmp  eax, 0x0FFFFFF8
    jae  .end
    mov  r14d, eax                        ; 0, 1, BAD and out of range refuse at .cluster
    jmp  .cluster
.end:
    cmp  byte [rel vo_e_lfn], 0
    jne  .notempty                        ; an LFN run without its short entry
    xor  eax, eax
    jmp  .out
.notempty:
    mov  eax, VO_E_NOTEMPTY
    jmp  .out
.io:
    mov  eax, VO_E_IO
.out:
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; vo_empty_slots(RDI = one 512-byte root sector) -> EAX 0 allowed / 1 refused. The run state
; (terminator, label, SVI, LFN run, checksum) carries across sectors and clusters.
vo_empty_slots:
    mov  r8, rdi
    lea  r9, [rdi + VO_SECTOR]
.slot:
    cmp  r8, r9
    jae  .ok
    movzx eax, byte [r8]
    cmp  byte [rel vo_e_term], 0
    je   .live
    test eax, eax                         ; past the terminator: free or deleted only
    jz   .next
    cmp  eax, 0xE5
    je   .next
    jmp  .bad
.live:
    test eax, eax
    jnz  .present
    cmp  byte [rel vo_e_lfn], 0
    jne  .bad
    mov  byte [rel vo_e_term], 1
    jmp  .next
.present:
    cmp  eax, 0xE5
    jne  .used
    cmp  byte [rel vo_e_lfn], 0
    jne  .bad
    jmp  .next
.used:
    movzx ecx, byte [r8 + 11]
    cmp  ecx, 0x0F
    je   .lfn
    movzx edx, word [r8 + 12]
    cmp  edx, VO_DG_MAGIC
    je   .bad
    cmp  edx, VO_CP_MAGIC
    je   .bad
    cmp  ecx, 0x08
    je   .label
    cmp  byte [rel vo_e_lfn], 2           ; System Volume Information, after exactly its LFN pair
    jne  .bad
    test ecx, 0x10
    jz   .bad
    test ecx, 0x06
    jz   .bad
    test ecx, 0xC8
    jnz  .bad
    mov  rax, [r8]
    cmp  rax, [rel vo_svi_sfn]
    jne  .bad
    mov  eax, [r8 + 7]
    cmp  eax, [rel vo_svi_sfn + 7]
    jne  .bad
    xor  eax, eax                         ; the LFN checksum of the 11-byte short name
    xor  ecx, ecx
.sum:
    mov  edx, eax
    shr  edx, 1
    and  eax, 1
    shl  eax, 7
    or   eax, edx
    movzx edx, byte [r8 + rcx]
    add  eax, edx
    and  eax, 0xFF
    inc  ecx
    cmp  ecx, 11
    jb   .sum
    cmp  al, [rel vo_e_chk]
    jne  .bad
    cmp  byte [rel vo_e_svi], 0
    jne  .bad
    mov  byte [rel vo_e_svi], 1
    mov  byte [rel vo_e_lfn], 0
    jmp  .next
.label:
    cmp  byte [rel vo_e_lfn], 0
    jne  .bad
    cmp  word [r8 + 20], 0
    jne  .bad
    cmp  word [r8 + 26], 0
    jne  .bad
    cmp  dword [r8 + 28], 0
    jne  .bad
    cmp  byte [rel vo_e_label], 0
    jne  .bad
    mov  byte [rel vo_e_label], 1
    jmp  .next
.lfn:
    movzx eax, byte [rel vo_e_lfn]
    lea  rsi, [rel vo_lfn_svi2]           ; ordinal 0x42 first, then 0x01
    test eax, eax
    jz   .lfn_match
    lea  rsi, [rel vo_lfn_svi1]
    cmp  eax, 1
    jne  .bad
    mov  dl, [r8 + 13]
    cmp  dl, [rel vo_e_chk]
    jne  .bad
.lfn_match:
    xor  ecx, ecx
.lfn_byte:
    cmp  ecx, 13                          ; the checksum byte is the SFN's, compared above/below
    je   .lfn_skip
    mov  dl, [r8 + rcx]
    cmp  dl, [rsi + rcx]
    jne  .bad
.lfn_skip:
    inc  ecx
    cmp  ecx, 32
    jb   .lfn_byte
    mov  dl, [r8 + 13]
    mov  [rel vo_e_chk], dl
    inc  byte [rel vo_e_lfn]
.next:
    add  r8, 32
    jmp  .slot
.ok:
    xor  eax, eax
    ret
.bad:
    mov  eax, 1
    ret

; ---------------------------------------------------------------------------
; vol_owner_local_snapshot(EDI = mount handle, RSI = 96-byte out) -> EAX 0 / VO_E_*.
; Own partition A3/A4 (FS108103 A3_ABI.md, AV108110). Read-only: vol_owner_probe, then the empty
; check on live media. Refuses anything but an eligible, clean, empty fixed FAT32. On success it
; keeps one native slot {snapshot id, the full probed identity, mount handle, monotonic time} for
; the local adoption, and fills the out buffer for display only. The out buffer is never read back.
; Out: +0 id[16] (CSPRNG) | +16 device name[32] NUL-padded | +48 disk bytes | +56 partition bytes |
; +64 table (VO_SCHEME_MBR 1 / VO_SCHEME_GPT 2) | +65 partition number (1-based) | +66 0[2] |
; +68 FAT label[11] + NUL | +80 0[16]. A refusal leaves the out buffer zero and no slot.
vol_owner_local_snapshot:
    push rbx
    push r12
    push r13
    mov  r12d, edi
    mov  r13, rsi
    call vo_snap_clear
    mov  rdi, r13
    xor  esi, esi
    mov  edx, VO_SNAP_OUT
    call memset
    call vo_owner_session                ; P2: an unlocked local owner session, kept for the adopt
    test eax, eax
    jnz  .err
    mov  [rel vo_snap_auth], rdx
    mov  edi, r12d
    lea  rsi, [rel vo_snap_ident]
    call vol_owner_probe
    test eax, eax
    jnz  .err
    mov  eax, VO_E_FSKIND
    cmp  byte [rel vo_snap_ident + VOE_KIND], VO_KIND_FAT32
    jne  .err
    mov  rbx, [rel vo_probe_dev]
    mov  rdi, rbx
    call guest_volume_native_allowed     ; P4: a guest volume job holds this device
    test rax, rax
    mov  eax, VO_E_BUSY
    jnz  .err
    mov  rdi, rbx
    mov  rsi, [rel vo_snap_ident + VOE_FIRST]
    call vo_root_empty
    test eax, eax
    jnz  .err
    lea  rdi, [rel vo_snap_id]
    mov  esi, 16
    call csprng_generate
    test rax, rax
    mov  eax, VO_E_IO
    jnz  .err
    mov  rax, [rel vo_snap_id]
    mov  [r13], rax
    mov  rax, [rel vo_snap_id + 8]
    mov  [r13 + 8], rax
    mov  rsi, [rbx + dev.name]
    test rsi, rsi
    jz   .sizes
    xor  ecx, ecx
.name:
    mov  al, [rsi + rcx]
    test al, al
    jz   .sizes
    mov  [r13 + 16 + rcx], al
    inc  ecx
    cmp  ecx, 31
    jb   .name
.sizes:
    mov  rax, [rbx + dev.info]
    mov  rax, [rax + blk_info.lba_max]
    inc  rax
    shl  rax, 9
    mov  [r13 + 48], rax
    mov  rax, [rel vo_snap_ident + VOE_COUNT]
    shl  rax, 9
    mov  [r13 + 56], rax
    mov  al, [rel vo_snap_ident + VOE_SCHEME]
    mov  [r13 + 64], al
    mov  al, [rel vo_probe_part]
    mov  [r13 + 65], al
    lea  rdi, [r13 + 68]
    lea  rsi, [rel vo_snap_ident + VOE_FSID + 4]
    mov  edx, 11
    call memcpy
    mov  [rel vo_snap_mount], r12d
    call time_monotonic_now_us
    mov  [rel vo_snap_time], rax
    mov  byte [rel vo_snap_valid], 1
    xor  eax, eax
    jmp  .out
.err:
    push rax
    push rax
    call vo_snap_clear
    mov  rdi, r13
    xor  esi, esi
    mov  edx, VO_SNAP_OUT
    call memset
    pop  rax
    pop  rax
    call vo_fail
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; vo_snap_clear: no slot; the id, the kept identity and the session are wiped.
vo_snap_clear:
    mov  byte [rel vo_snap_valid], 0
    mov  qword [rel vo_snap_auth], 0
    lea  rdi, [rel vo_snap_ident]
    xor  esi, esi
    mov  edx, VO_ENT_SIZE + 16
    jmp  memset

; ---------------------------------------------------------------------------
; Registry persistence.

; vo_key_request(RSI = record, i.e. vo_record or vo_verify) -> EAX 0 / -1.
; Builds vo_req over that record with the derived key in vo_key.
vo_key_request:
    push rbx
    mov  rbx, rsi
    call principal_system_auth_credential
    test rax, rax
    jz   .bad
    mov  rdi, rax
    mov  esi, 32
    lea  rdx, [rel vo_domain]
    mov  ecx, vo_domain.len
    lea  r8, [rel vo_domain]
    mov  r9d, vo_domain.len
    sub  rsp, 8
    lea  rax, [rel vo_key]
    mov  [rsp], rax
    call principal_hkdf32
    add  rsp, 8
    test eax, eax
    jnz  .bad
    lea  rax, [rel vo_req]
    lea  rdx, [rel vo_key]
    mov  [rax + AEAD_KEY], rdx
    lea  rdx, [rbx + 4]
    mov  [rax + AEAD_NONCE], rdx
    mov  [rax + AEAD_AAD], rbx
    mov  qword [rax + AEAD_AAD_LEN], 4
    mov  qword [rax + AEAD_INPUT_LEN], VO_PLAIN_SIZE
    lea  rdx, [rbx + 16 + VO_PLAIN_SIZE]
    mov  [rax + AEAD_TAG], rdx
    xor  eax, eax
    pop  rbx
    ret
.bad:
    call vo_key_wipe
    mov  eax, -1
    pop  rbx
    ret

vo_key_wipe:
    lea  rdi, [rel vo_key]
    xor  esi, esi
    mov  edx, 32
    jmp  memset

; vo_cache_clear: the plaintext cache and every binding are dropped.
vo_cache_clear:
    lea  rdi, [rel vo_plain]
    xor  esi, esi
    mov  edx, VO_PLAIN_SIZE
    call memset
    lea  rdi, [rel vo_binds]
    xor  esi, esi
    mov  edx, VO_BIND_MAX * VOB_SIZE
    call memset
    inc  qword [rel vo_epoch]
    ret

; vo_plain_valid(RDI = plaintext) -> EAX 1 well-formed, 0 not.
vo_plain_valid:
    cmp  dword [rdi + VOH_MAGIC], 'VOR1'
    jne  .no
    xor  ecx, ecx                        ; index
    xor  r8d, r8d                        ; in-use count
    xor  r9d, r9d                        ; at most one DATA role
.scan:
    cmp  ecx, VO_ENT_MAX
    jae  .count
    mov  edx, ecx
    shl  edx, 7
    lea  rsi, [rdi + VO_HDR_SIZE + rdx]
    cmp  dword [rsi + VOE_MAGIC], 0
    je   .free
    cmp  dword [rsi + VOE_MAGIC], 'VOE1'
    jne  .no
    movzx eax, byte [rsi + VOE_KIND]
    cmp  eax, VO_KIND_FAT32
    jb   .no
    cmp  eax, VO_KIND_EXT
    ja   .no
    movzx eax, byte [rsi + VOE_SCHEME]
    cmp  eax, VO_SCHEME_MBR
    jb   .no
    cmp  eax, VO_SCHEME_GPT
    ja   .no
    mov  rax, [rsi + VOE_COUNT]
    test rax, rax
    jz   .no
    add  rax, [rsi + VOE_FIRST]
    jc   .no
    cmp dword [rsi + VOE_DATA_ROLE + 4], 0
    jne .no
    cmp qword [rsi + VOE_DATA_ROLE + 8], 0
    jne .no
    cmp dword [rsi + VOE_DATA_ROLE], 0
    je .role_ok
    cmp dword [rsi + VOE_DATA_ROLE], VO_DATA_ROLE
    jne .no
    inc r9d
    cmp r9d, 1
    ja .no
    cmp byte [rsi + VOE_KIND], VO_KIND_FAT32
    jne .no
    cmp byte [rsi + VOE_SCHEME], VO_SCHEME_GPT
    jne .no
    cmp qword [rsi + VOE_ATTRS], 0
    jne .no
.role_ok:
    inc  r8d
    jmp  .next
.free:
    xor  edx, edx                        ; a free entry is all zero
.zero:
    cmp  edx, VO_ENT_SIZE
    jae  .next
    cmp  qword [rsi + rdx], 0
    jne  .no
    add  edx, 8
    jmp  .zero
.next:
    inc  ecx
    jmp  .scan
.count:
    cmp  r8d, [rdi + VOH_COUNT]
    jne  .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; vol_owner_load() -> EAX 0 (state OK) / -1 (state NOKEY or CORRUPT).
vol_owner_load:
    push rbx
    call vo_cache_clear
    lea  rsi, [rel vo_verify]
    call vo_key_request
    test eax, eax
    jnz  .nokey
    mov  edi, VO_FW_READ
    call vo_firmware
    mov  rdx, VO_EFI_NOT_FOUND
    cmp  rax, rdx
    je   .empty
    cmp  rax, -1                         ; no runtime mapped yet: retryable, not CORRUPT
    je   .nokey
    test rax, rax
    jnz  .corrupt
    cmp  dword [rel vo_verify], 'PVO1'
    jne  .corrupt
    lea  rax, [rel vo_req]
    lea  rdx, [rel vo_verify + 16]
    mov  [rax + AEAD_INPUT], rdx
    lea  rdx, [rel vo_check]
    mov  [rax + AEAD_OUTPUT], rdx
    mov  rdi, rax
    call aes256_gcm_open
    test eax, eax
    jnz  .corrupt
    lea  rdi, [rel vo_check]
    call vo_plain_valid
    test eax, eax
    jz   .corrupt
    lea  rdi, [rel vo_plain]
    lea  rsi, [rel vo_check]
    mov  edx, VO_PLAIN_SIZE
    call memcpy
    jmp  .ok
.empty:
    mov  dword [rel vo_plain + VOH_MAGIC], 'VOR1'
.ok:
    mov  byte [rel vo_state], VO_ST_OK
    xor  ebx, ebx
    jmp  .out
.nokey:
    mov  byte [rel vo_state], VO_ST_NOKEY
    mov  eax, VO_E_NOKEY
    call vo_fail
    mov  ebx, -1
    jmp  .out
.corrupt:
    mov  byte [rel vo_state], VO_ST_CORRUPT
    mov  eax, VO_E_REGISTRY
    call vo_fail
    mov  ebx, -1
.out:
    call vo_key_wipe
    lea  rdi, [rel vo_check]
    xor  esi, esi
    mov  edx, VO_PLAIN_SIZE
    call memset
    inc  qword [rel vo_epoch]
    mov  eax, ebx
    pop  rbx
    ret

; vo_ready() -> EAX 0 when the registry is loaded and OK (loads it once when
; it was never loaded or the credential was not yet available).
vo_ready:
    movzx eax, byte [rel vo_state]
    cmp  eax, VO_ST_OK
    je   .yes
    cmp  eax, VO_ST_UNLOADED
    je   .load
    cmp  eax, VO_ST_NOKEY
    jne  .no
.load:
    call vol_owner_load
    test eax, eax
    jnz  .no
.yes:
    xor  eax, eax
    ret
.no:
    mov  eax, -1
    ret

; vo_save (vo_new = complete new plaintext) -> EAX 0 / VO_E_*.
; Failure before SetVariable leaves the state as it was. Any failure from the
; write on is UNCERTAIN: cache dropped, nothing owned until a reload decides.
vo_save:
    push rbx
    lea  rdi, [rel vo_backup]
    lea  rsi, [rel vo_record]
    mov  edx, VO_RECORD_SIZE
    call memcpy
    mov  dword [rel vo_record], 'PVO1'
    lea  rdi, [rel vo_record + 4]
    mov  esi, 12
    call csprng_generate
    test eax, eax
    jnz  .before
    lea  rsi, [rel vo_record]
    call vo_key_request
    test eax, eax
    jnz  .nokey
    lea  rax, [rel vo_req]
    lea  rdx, [rel vo_new]
    mov  [rax + AEAD_INPUT], rdx
    lea  rdx, [rel vo_record + 16]
    mov  [rax + AEAD_OUTPUT], rdx
    mov  rdi, rax
    call aes256_gcm_seal
    test eax, eax
    jnz  .before
    ; from here on the firmware may hold either record
    mov  byte [rel vo_state], VO_ST_UNCERTAIN
    call vo_cache_clear
    mov  edi, VO_FW_WRITE
    call vo_firmware
    test rax, rax
    jnz  .uncertain
    mov  edi, VO_FW_READ
    call vo_firmware
    test rax, rax
    jnz  .uncertain
    lea  rdi, [rel vo_record]
    lea  rsi, [rel vo_verify]
    mov  edx, VO_RECORD_SIZE
    call memcmp
    test eax, eax
    jnz  .uncertain
    lea  rsi, [rel vo_verify]
    call vo_key_request
    test eax, eax
    jnz  .uncertain
    lea  rax, [rel vo_req]
    lea  rdx, [rel vo_verify + 16]
    mov  [rax + AEAD_INPUT], rdx
    lea  rdx, [rel vo_check]
    mov  [rax + AEAD_OUTPUT], rdx
    mov  rdi, rax
    call aes256_gcm_open
    test eax, eax
    jnz  .uncertain
    lea  rdi, [rel vo_check]
    lea  rsi, [rel vo_new]
    mov  edx, VO_PLAIN_SIZE
    call memcmp
    test eax, eax
    jnz  .uncertain
    lea  rdi, [rel vo_plain]
    lea  rsi, [rel vo_new]
    mov  edx, VO_PLAIN_SIZE
    call memcpy
    mov  byte [rel vo_state], VO_ST_OK
    xor  ebx, ebx
    jmp  .out
.nokey:
    mov  ebx, VO_E_NOKEY
    jmp  .restore
.before:
    mov  ebx, VO_E_PERSIST
.restore:
    lea  rdi, [rel vo_record]
    lea  rsi, [rel vo_backup]
    mov  edx, VO_RECORD_SIZE
    call memcpy
    jmp  .out
.uncertain:
    mov  byte [rel vo_state], VO_ST_UNCERTAIN
    call vo_cache_clear
    mov  ebx, VO_E_PERSIST
.out:
    call vo_key_wipe
    lea  rdi, [rel vo_check]
    xor  esi, esi
    mov  edx, VO_PLAIN_SIZE
    call memset
    mov  eax, ebx
    test eax, eax
    jz   .ret
    call vo_fail
.ret:
    pop  rbx
    ret

; vo_firmware(EDI = VO_FW_READ into vo_verify | VO_FW_WRITE vo_record) on
; PaOSVolOwn1 -> RAX 0, the EFI status, -1 when no runtime is mapped (or the
; write was refused / failed), -2 a read of the wrong size or attributes.
; The data/config_store pc_firmware contract: Win64 alignment, shadow space,
; exact size and NV|BS|RT attributes on read, the NVRAM gate before a write.
vo_firmware:
    push rbp
    mov  rbp, rsp
    push r12
    sub  rsp, 8
    and  rsp, -16
    sub  rsp, 48
    cmp  byte [rel pbm_runtime_code_mapped], 1
    jne  .bad
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .bad
    test edi, edi
    jnz  .write
    mov  qword [rel vo_size], VO_RECORD_SIZE
    mov  dword [rel vo_attrs], 0
    lea  rcx, [rel vo_name]
    lea  rdx, [rel vo_guid]
    lea  r8, [rel vo_attrs]
    lea  r9, [rel vo_size]
    lea  rax, [rel vo_verify]
    mov  [rsp + 32], rax
    call [r12 + 0x48]
    test rax, rax
    jnz  .out
    cmp  qword [rel vo_size], VO_RECORD_SIZE
    jne  .malformed
    cmp  dword [rel vo_attrs], 7
    jne  .malformed
    xor  eax, eax
    jmp  .out
.malformed:
    mov  rax, -2                         ; present but not our record shape: CORRUPT
    jmp  .out
.write:
    call storage_access_request_intent
    mov  edx, eax
    lea  rdi, [rel vo_guid]
    lea  rsi, [rel vo_name]
    lea  rcx, [rel str_vo_nvg_tag]
    call storage_access_nvram_require
    test rax, rax
    jnz  .bad
    lea  rcx, [rel vo_name]
    lea  rdx, [rel vo_guid]
    mov  r8d, 7
    mov  r9d, VO_RECORD_SIZE
    lea  rax, [rel vo_record]
    mov  [rsp + 32], rax
    call [r12 + 0x58]
    test rax, rax
    jnz  .bad
    xor  eax, eax
    jmp  .out
.bad:
    mov  rax, -1
.out:
    mov  r12, [rbp - 8]
    mov  rsp, rbp
    pop  rbp
    ret

; ---------------------------------------------------------------------------
; A2/D3: adopted FAT32 discovery is observation, never an ownership binding.
; prepare is an explicit Explorer-open/refresh operation (may load the sealed
; firmware record). catalog is a pure cached, owner-private paint getter:
; EDI=slot 0..7, RSI=16-byte output -> EAX 1 present / 0 absent; {epoch,seq}.
; Labels are generated by the GUI, not copied from hostile media. The token
; names this exact record version; release, reload, reset or re-adoption makes
; an old visible row unusable. No API below calls bind/adopt/arm or writes.
vol_owner_read_prepare:
    sub  rsp, 8
    call vo_read_owner
    test eax, eax
    jnz  .out
    call vo_ready
    test eax, eax
    jz   .out
    mov  eax, VO_E_REGISTRY
.out:
    add  rsp, 8
    ret

; EAX 0 / DENIED; RDX is the nonzero unlocked local owner session token.
vo_read_owner:
    sub  rsp, 8
    call session_shell_local_authority
    cmp  rax, VO_PRIN_OWNER
    jne  .no
    test rdx, rdx
    jz   .no
    xor  eax, eax
    jmp  .out
.no:
    mov  eax, VO_E_DENIED
.out:
    add  rsp, 8
    ret

; Pure slot lookup; caller has checked the owner. RAX=entry / 0.
vo_read_entry:
    cmp  edi, VO_ENT_MAX
    jae  .no
    cmp  byte [rel vo_state], VO_ST_OK
    jne  .no
    imul edi, VO_ENT_SIZE
    lea  rax, [rel vo_plain + VO_HDR_SIZE]
    add  rax, rdi
    cmp  dword [rax + VOE_MAGIC], 'VOE1'
    jne  .no
    cmp  byte [rax + VOE_KIND], VO_KIND_FAT32
    jne  .no
    ret
.no:
    xor  eax, eax
    ret

vol_owner_read_catalog:
    push rbx
    push r12
    sub  rsp, 8
    mov  ebx, edi
    mov  r12, rsi
    mov  qword [r12], 0
    mov  qword [r12 + 8], 0
    call vo_read_owner
    test eax, eax
    jnz  .no
    mov  edi, ebx
    call vo_read_entry
    test rax, rax
    jz   .no
    mov  rdx, [rel vo_epoch]
    mov  [r12], rdx
    mov  rdx, [rax + VOE_SEQ]
    mov  [r12 + 8], rdx
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; EDI=slot, RSI=16-byte visible token, RDX=96-byte read-only extent out.
; EAX 0 clean / DIRTY readable (9) / other VO_E_* refused with ZERO output.
; Output: dev, first, sectors, media_generation, lba_max (qwords), logical
; sector bytes (dword), dirty (dword), epoch, adoption sequence (qwords),
; GPT disk/partition GUIDs (16 bytes each; both ZERO for MBR).
; The consumer must install read-only ops, retain generation/geometry custody
; and revalidate this same row before publication. The output is NOT accepted
; by any write chokepoint. Resolve fixed media on the explicit owner press,
; not in paint. Compare the entire sealed identity, including MBR signature,
; primary index and FAT ID/label; duplicate live identities refuse. A dirty
; FAT probe has its full identity but still refuses ordinary bind/live_check.
vol_owner_read_resolve:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 72
    mov  r14d, edi
    mov  r13, rdx
    mov  rax, [rsi]
    mov  [rsp], rax
    mov  rax, [rsi + 8]
    mov  [rsp + 8], rax
    mov  rdi, r13
    xor  esi, esi
    mov  edx, 96
    call memset
    call vo_read_owner
    test eax, eax
    jnz  .out
    mov  [rsp + 56], rdx
    mov  edi, r14d
    call vo_read_entry
    test rax, rax
    jz   .stale
    mov  r12, rax
    call .row_current
    test eax, eax
    jnz  .stale
    xor  ebx, ebx
    xor  ebp, ebp
.next:
    mov  rdi, rbx
    mov  esi, BLKCAP_READ
    xor  edx, edx
    call blk_iter_after
    test rax, rax
    jz   .found
    mov  rbx, rax
    mov  rdi, rbx
    call blk_identify
    test rax, rax
    jnz  .io
    mov  rax, [rbx + dev.info]
    test rax, rax
    jz   .io
    ; Only fixed 512-byte devices can be adopted under this registry schema.
    cmp  byte [rax + blk_info.removable], 0
    jne  .next
    test dword [rax + blk_info.flags], BLKF_REMOVABLE
    jnz  .next
    cmp  dword [rax + blk_info.sector_size], VO_SECTOR
    jne  .next
    cmp  dword [rax + blk_info.logical_sector_bytes], VO_SECTOR
    jne  .io
    cmp  dword [rbx + dev.health], HEALTH_OK
    jne  .io
    cmp  qword [rax + blk_info.media_generation], 0
    je   .io
    mov  rdx, [r12 + VOE_FIRST]
    add  rdx, [r12 + VOE_COUNT]
    jc   .io
    dec  rdx
    cmp  rdx, [rax + blk_info.lba_max]
    ja   .next                        ; the sealed window does not fit this peer
    mov  r15, [rax + blk_info.media_generation]
    mov  rdi, rbx
    call guest_volume_native_allowed
    test rax, rax
    jnz  .busy
    call .probe
    cmp  eax, VO_E_IO
    je   .io
    cmp  eax, VO_E_GEOMETRY
    je   .io
    test eax, eax
    jz   .identity
    cmp  eax, VO_E_DIRTY
    jne  .next
.identity:
    mov  [rsp + 64], eax
    lea  rdi, [rel vo_live_ident + VO_ID_OFF]
    lea  rsi, [r12 + VO_ID_OFF]
    mov  edx, VO_ID_LEN
    call memcmp
    test eax, eax
    jnz  .next
    mov  rax, [rbx + dev.info]
    cmp  r15, [rax + blk_info.media_generation]
    jne  .io
    inc  ebp
    cmp  ebp, 1
    jne  .dup
    mov  [rsp + 16], rbx
    mov  [rsp + 24], r15
    mov  rdx, [rax + blk_info.lba_max]
    mov  [rsp + 32], rdx
    mov  edx, [rax + blk_info.logical_sector_bytes]
    mov  [rsp + 40], edx
    mov  edx, [rsp + 64]
    mov  [rsp + 44], edx
    jmp  .next
.found:
    test ebp, ebp
    jz   .missing
    mov  rbx, [rsp + 16]
    call .probe                         ; re-read the candidate after the scan
    mov  [rsp + 64], eax
    test eax, eax
    jz   .final_id
    cmp  eax, VO_E_DIRTY
    jne  .io
.final_id:
    lea  rdi, [rel vo_live_ident + VO_ID_OFF]
    lea  rsi, [r12 + VO_ID_OFF]
    mov  edx, VO_ID_LEN
    call memcmp
    test eax, eax
    jnz  .stale
    mov  rax, [rbx + dev.info]
    test rax, rax
    jz   .io
    cmp  dword [rbx + dev.health], HEALTH_OK
    jne  .io
    mov  rdx, [rsp + 24]
    cmp  rdx, [rax + blk_info.media_generation]
    jne  .io
    mov  rdx, [rsp + 32]
    cmp  rdx, [rax + blk_info.lba_max]
    jne  .io
    cmp  dword [rax + blk_info.sector_size], VO_SECTOR
    jne  .io
    cmp  dword [rax + blk_info.logical_sector_bytes], VO_SECTOR
    jne  .io
    call vo_read_owner
    test eax, eax
    jnz  .out
    cmp  rdx, [rsp + 56]
    jne  .stale
    call .row_current
    test eax, eax
    jnz  .stale
    mov  [r13], rbx
    mov  rax, [r12 + VOE_FIRST]
    mov  [r13 + 8], rax
    mov  rax, [r12 + VOE_COUNT]
    mov  [r13 + 16], rax
    mov  rax, [rsp + 24]
    mov  [r13 + 24], rax
    mov  rax, [rsp + 32]
    mov  [r13 + 32], rax
    mov  dword [r13 + 40], VO_SECTOR
    xor  eax, eax
    cmp  dword [rsp + 64], VO_E_DIRTY
    sete al
    mov  [r13 + 44], eax
    mov  rax, [rsp]
    mov  [r13 + 48], rax
    mov  rax, [rsp + 8]
    mov  [r13 + 56], rax
    cmp  byte [r12 + VOE_SCHEME], VO_SCHEME_GPT
    jne  .published
    lea  rdi, [r13 + 64]
    lea  rsi, [r12 + VOE_DISK]
    mov  edx, 32
    call memcpy
.published:
    mov  eax, [rsp + 64]
    jmp  .out
.row_current:                         ; called with a return address on stack
    cmp  byte [rel vo_state], VO_ST_OK
    jne  .row_no
    mov  rax, [rsp + 8]
    cmp  rax, [rel vo_epoch]
    jne  .row_no
    mov  rax, [rsp + 16]
    cmp  rax, [r12 + VOE_SEQ]
    jne  .row_no
    xor  eax, eax
    ret
.row_no:
    mov  eax, 1
    ret
.probe:
    mov  [rel vo_fsinfo + fs_info.device], rbx
    mov  rax, [r12 + VOE_FIRST]
    mov  [rel vo_fsinfo + fs_info.part_start], rax
    mov  rax, [r12 + VOE_COUNT]
    mov  [rel vo_fsinfo + fs_info.part_sectors], rax
    movzx eax, byte [r12 + VOE_SCHEME]
    mov  [rel vo_fsinfo + fs_info.scheme], eax
    lea  rsi, [rel vo_live_ident]
    jmp  vo_probe_extent
.stale:
    mov  eax, VO_E_CHANGED
    jmp  .out
.missing:
    mov  eax, VO_E_NOTFOUND
    jmp  .out
.dup:
    mov  eax, VO_E_DUP
    jmp  .out
.busy:
    mov  eax, VO_E_BUSY
    jmp  .out
.io:
    mov  eax, VO_E_IO
.out:
    call vo_fail
    add  rsp, 72
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret


; ---------------------------------------------------------------------------
; Owner operations (registry changes). The caller is the FSOWN verb.

; vo_new_from_plain: vo_new = vo_plain.
vo_new_from_plain:
    lea  rdi, [rel vo_new]
    lea  rsi, [rel vo_plain]
    mov  edx, VO_PLAIN_SIZE
    jmp  memcpy

; vol_owner_adopt(EDI = mount handle) -> EAX 0 / VO_E_*.
; Needs SA_INTENT_SPECIAL in flight: a verified owner ticket (admin D2).
vol_owner_adopt:
    mov  byte [rel vo_adopt_local], 0
    push rdi
    call storage_access_request_intent
    pop  rdi
    cmp  eax, SA_INTENT_SPECIAL
    je   vo_adopt_core
    mov  eax, VO_E_DENIED
    jmp  vo_fail

; vol_owner_local_adopt(EDI = mount handle, RSI = 16-byte snapshot id) -> EAX 0 / VO_E_*.
; Own partition A3 (A3_ABI.md, AV108110; SEC 107877 E1/E5, SEC108128 P2-P5, SEC108140). The owner's
; local route: no SA_INTENT_SPECIAL is set anywhere. In order, on every call:
; 1. sec/adopt_decision's av_adopt_decision_consume with RDI = the id FS stored at the snapshot, never
;    the caller's (SEC108140). AV's one-use decision is spent on every call; storage_grant_lint pins
;    this routine as its only caller. No card registered, or any refusal: VO_E_DECISION.
; 2. The snapshot slot: the caller's id, the same mount, younger than VO_SNAP_LIFE_US (VO_E_SNAPSHOT),
;    and the same unlocked local owner session as at the snapshot (VO_E_SESSION). Cleared.
; 3. vo_adopt_core, in this same synchronous call: the guest fence (VO_E_BUSY), a live probe whose
;    whole identity must equal the snapshot's (VO_E_CHANGED), the empty check again on live media
;    (VO_E_NOTEMPTY), then the signed route's own uniqueness and save. A refusal writes nothing.
vol_owner_local_adopt:
    push rbx
    push r12
    push r13
    mov  r12d, edi
    mov  r13, rsi
    lea  rdi, [rel vo_snap_id]           ; first, before any other check: FS's own stored id
    call av_adopt_decision_consume
    mov  ebx, eax
    mov  byte [rel vo_adopt_local], 0
    test ebx, ebx
    jnz  .decision
    cmp  byte [rel vo_snap_valid], 1
    jne  .snapshot
    cmp  [rel vo_snap_mount], r12d
    jne  .snapshot
    mov  rdi, r13
    lea  rsi, [rel vo_snap_id]
    mov  edx, 16
    call memcmp
    test eax, eax
    jnz  .snapshot
    call time_monotonic_now_us
    sub  rax, [rel vo_snap_time]
    cmp  rax, VO_SNAP_LIFE_US
    jae  .snapshot                       ; also a clock that ran backwards
    call vo_owner_session
    test eax, eax
    jnz  .session
    cmp  rdx, [rel vo_snap_auth]
    jne  .session
    mov  byte [rel vo_snap_valid], 0
    mov  byte [rel vo_adopt_local], 1
    mov  edi, r12d
    call vo_adopt_core
    mov  byte [rel vo_adopt_local], 0
    mov  ebx, eax
    call vo_snap_clear
    mov  eax, ebx
    jmp  .out
.decision:
    mov  ebx, VO_E_DECISION
    jmp  .fail
.session:
    mov  ebx, VO_E_SESSION
    jmp  .fail
.snapshot:
    mov  ebx, VO_E_SNAPSHOT
.fail:
    call vo_snap_clear
    mov  eax, ebx
    call vo_fail
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; vo_owner_session() -> EAX 0 with RDX = the session authority token / VO_E_SESSION (RDX 0).
; sec/session's local-authority snapshot: no remote frame, no injected input, unlocked, a bound
; session key and the current epoch; the principal must be the owner (not a Try or other account).
vo_owner_session:
    call session_shell_local_authority
    cmp  rax, VO_PRIN_OWNER
    jne  .bad
    test rdx, rdx
    jz   .bad
    cmp  rdx, -1
    je   .bad
    xor  eax, eax
    ret
.bad:
    xor  edx, edx
    mov  eax, VO_E_SESSION
    ret

; vol_owner_local_cancel(): memory only, no IO, safe at any time and before any snapshot. AV calls it
; from its session, window and Deny erasers (AV108129, SEC108128 P6).
vol_owner_local_cancel:
    jmp  vo_snap_clear

; vo_adopt_core(EDI = mount handle) -> EAX 0 / VO_E_*. Callers: vol_owner_adopt after its
; SPECIAL check, vol_owner_local_adopt after its decision and slot checks (vo_adopt_local = 1).
vo_adopt_core:
    push rbx
    push r12
    push r13
    mov  r12d, edi
    call vo_ready
    test eax, eax
    jnz  .registry
    mov  edi, r12d
    lea  rsi, [rel vo_ident]
    call vol_owner_probe
    test eax, eax
    jnz  .out
    mov  rdi, [rel vo_probe_dev]
    call guest_volume_native_allowed     ; P4: never adopt a device a guest volume job holds
    test rax, rax
    mov  eax, VO_E_BUSY
    jnz  .err
    cmp  byte [rel vo_adopt_local], 1
    jne  .unique
    ; A3 local route (SEC E1): the volume the owner confirmed, still empty, read in this call
    lea  rdi, [rel vo_ident]
    lea  rsi, [rel vo_snap_ident]
    mov  edx, VO_ENT_SIZE
    call memcmp
    test eax, eax
    mov  eax, VO_E_CHANGED
    jnz  .err
    mov  rdi, [rel vo_probe_dev]
    mov  rsi, [rel vo_ident + VOE_FIRST]
    call vo_root_empty
    test eax, eax
    jnz  .err
.unique:
    ; already registered (same identity) or overlapping a registered extent of
    ; the same disk: refused, never a duplicate entry
    xor  ebx, ebx
    mov  r13d, -1                        ; first free
.scan:
    cmp  ebx, VO_ENT_MAX
    jae  .scanned
    mov  eax, ebx
    shl  eax, 7
    lea  rsi, [rel vo_plain + VO_HDR_SIZE]
    add  rsi, rax
    cmp  dword [rsi + VOE_MAGIC], 'VOE1'
    je   .used
    cmp  r13d, -1
    jne  .next
    mov  r13d, ebx
    jmp  .next
.used:
    push rsi
    lea  rdi, [rsi + VO_ID_OFF]
    lea  rsi, [rel vo_ident + VO_ID_OFF]
    mov  edx, VO_ID_LEN
    call memcmp
    pop  rsi
    test eax, eax
    jz   .exists
    mov  al, [rsi + VOE_SCHEME]
    cmp  al, [rel vo_ident + VOE_SCHEME]
    jne  .next
    push rsi
    lea  rdi, [rsi + VOE_DISK]
    lea  rsi, [rel vo_ident + VOE_DISK]
    call vo_guid_eq
    pop  rsi
    jne  .next
    ; same disk: [a, a+n) and [b, b+m) overlap when a < b+m and b < a+n
    mov  rax, [rsi + VOE_FIRST]
    mov  rcx, [rel vo_ident + VOE_FIRST]
    mov  rdx, rcx
    add  rdx, [rel vo_ident + VOE_COUNT]
    cmp  rax, rdx
    jae  .next
    mov  rdx, rax
    add  rdx, [rsi + VOE_COUNT]
    cmp  rcx, rdx
    jb   .exists
.next:
    inc  ebx
    jmp  .scan
.scanned:
    cmp  r13d, -1
    je   .full
    call vo_new_from_plain
    mov  eax, r13d
    shl  eax, 7
    lea  rbx, [rel vo_new + VO_HDR_SIZE]
    add  rbx, rax
    mov  rdi, rbx
    lea  rsi, [rel vo_ident]
    mov  edx, VO_ENT_SIZE
    call memcpy
    mov  rax, [rel vo_new + VOH_SEQ]
    inc  rax
    mov  [rel vo_new + VOH_SEQ], rax
    mov  [rbx + VOE_SEQ], rax
    call time_wall_now_s
    mov  [rbx + VOE_TIME], rax
    inc  dword [rel vo_new + VOH_COUNT]
    inc  qword [rel vo_new + VOH_GEN]
    call vo_save
    test eax, eax
    jnz  .out
    lea  rdi, [rel str_vo_adopted]
    cmp  byte [rel vo_adopt_local], 1    ; P5: the record names the route
    jne  .audit
    lea  rdi, [rel str_vo_adopted_local]
.audit:
    mov  esi, r13d
    call vo_audit
    xor  eax, eax
    jmp  .out
.registry: mov eax, VO_E_REGISTRY
    jmp  .err
.exists:   mov eax, VO_E_EXISTS
    jmp  .err
.full:     mov eax, VO_E_FULL
.err:
    call vo_fail
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; vol_owner_release(EDI = entry index) -> EAX 0 / VO_E_*. Only removes authority.
vol_owner_release:
    push rbx
    mov  ebx, edi
    call vo_ready
    test eax, eax
    jnz  .registry
    cmp  ebx, VO_ENT_MAX
    jae  .notfound
    mov  eax, ebx
    shl  eax, 7
    lea  rsi, [rel vo_plain + VO_HDR_SIZE]
    cmp  dword [rsi + rax + VOE_MAGIC], 'VOE1'
    jne  .notfound
    call vo_new_from_plain
    mov  eax, ebx
    shl  eax, 7
    lea  rdi, [rel vo_new + VO_HDR_SIZE]
    add  rdi, rax
    xor  esi, esi
    mov  edx, VO_ENT_SIZE
    call memset
    dec  dword [rel vo_new + VOH_COUNT]
    inc  qword [rel vo_new + VOH_GEN]
    call vo_save
    test eax, eax
    jnz  .out
    lea  rdi, [rel str_vo_released]
    mov  esi, ebx
    call vo_audit
    xor  eax, eax
    jmp  .out
.registry: mov eax, VO_E_REGISTRY
    jmp  .err
.notfound: mov eax, VO_E_NOTFOUND
.err:
    call vo_fail
.out:
    pop  rbx
    ret

; vol_owner_reset() -> EAX 0 / VO_E_*: an empty registry (the CORRUPT/UNCERTAIN
; exit). Only removes authority.
vol_owner_reset:
    mov  rax, [rel vo_plain + VOH_GEN]   ; zero unless the cache was valid
    push rax
    lea  rdi, [rel vo_new]
    xor  esi, esi
    mov  edx, VO_PLAIN_SIZE
    call memset
    pop  rax
    inc  rax
    mov  [rel vo_new + VOH_GEN], rax
    mov  dword [rel vo_new + VOH_MAGIC], 'VOR1'
    call vo_save
    test eax, eax
    jnz  .out
    lea  rdi, [rel str_vo_reset]
    mov  esi, -1
    call vo_audit
    xor  eax, eax
.out:
    ret

; vo_audit(RDI = event cstr, ESI = entry index or -1): one serial line.
vo_audit:
    push rbx
    mov  ebx, esi
    push rdi
    lea  rdi, [rel str_vo_prefix]
    call serial_string
    pop  rdi
    call serial_string
    lea  rdi, [rel str_vo_entry]
    call serial_string
    movsxd rdi, ebx
    call serial_hex64
    lea  rdi, [rel str_vo_gen]
    call serial_string
    mov  rdi, [rel vo_plain + VOH_GEN]
    call serial_hex64
    lea  rdi, [rel str_vo_crlf]
    call serial_string
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; The SA2 interface (rc-sec rules on its use). No caller in SA1.

; vol_owner_bind_mount(EDI = mount handle) -> RAX token (nonzero) / 0 with
; vol_owner_last_error = the reason (VO_E_NOTOWNED, VO_E_DUP, a probe refusal).
vol_owner_bind_mount:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, edi
    call vo_ready
    test eax, eax
    jnz  .registry
    mov  edi, r12d
    lea  rsi, [rel vo_ident]
    call vol_owner_probe
    test eax, eax
    jnz  .none
    xor  ebx, ebx                        ; matching entry
.find:
    cmp  ebx, VO_ENT_MAX
    jae  .notowned
    mov  eax, ebx
    shl  eax, 7
    lea  rdi, [rel vo_plain + VO_HDR_SIZE]
    add  rdi, rax
    cmp  dword [rdi + VOE_MAGIC], 'VOE1'
    jne  .find_next
    add  rdi, VO_ID_OFF
    lea  rsi, [rel vo_ident + VO_ID_OFF]
    mov  edx, VO_ID_LEN
    call memcmp
    test eax, eax
    jz   .found
.find_next:
    inc  ebx
    jmp  .find
.found:
    mov  r13, [rel vo_probe_dev]
    ; existing live bindings of this epoch: the same volume is re-bound in
    ; place; another volume matching the same entry makes both DUP
    xor  r14d, r14d                      ; dup seen
    mov  r15d, -1                        ; slot to use
    xor  ecx, ecx
.slots:
    cmp  ecx, VO_BIND_MAX
    jae  .slots_done
    mov  eax, ecx
    shl  eax, 6
    lea  rsi, [rel vo_binds]
    add  rsi, rax
    test dword [rsi + VOB_FLAGS], VOB_F_LIVE
    jz   .slot_free
    mov  rax, [rsi + VOB_EPOCH]
    cmp  rax, [rel vo_epoch]
    jne  .slot_free                      ; stale: reusable
    cmp  [rsi + VOB_ENTRY], ebx
    jne  .slot_next
    cmp  [rsi + VOB_DEV], r13
    jne  .slot_dup
    mov  rax, [rel vo_ident + VOE_FIRST]
    cmp  [rsi + VOB_FIRST], rax
    jne  .slot_dup
    test dword [rsi + VOB_FLAGS], VOB_F_DUP
    jz   .slot_same
    mov  r14d, 1                         ; it stays DUP
.slot_same:
    mov  r15d, ecx
    jmp  .slot_next
.slot_dup:
    or   dword [rsi + VOB_FLAGS], VOB_F_DUP
    mov  r14d, 1
    jmp  .slot_next
.slot_free:
    cmp  r15d, -1
    jne  .slot_next
    mov  dword [rsi + VOB_FLAGS], 0
    mov  r15d, ecx
.slot_next:
    inc  ecx
    jmp  .slots
.slots_done:
    mov  rax, [rel vo_bind_seq]
    mov  rcx, VO_BIND_SEQ_LIMIT          ; a token carries 56 bits of sequence: refuse,
    cmp  rax, rcx                        ; before touching any slot, rather than reuse one
    jae  .exhausted
    cmp  r15d, -1
    je   .full
    mov  eax, r15d
    shl  eax, 6
    lea  rsi, [rel vo_binds]
    add  rsi, rax
    mov  [rsi + VOB_DEV], r13
    mov  rax, [rel vo_ident + VOE_FIRST]
    mov  [rsi + VOB_FIRST], rax
    mov  rax, [rel vo_ident + VOE_COUNT]
    mov  [rsi + VOB_COUNT], rax
    mov  rax, [r13 + dev.info]
    mov  rax, [rax + blk_info.media_generation]
    mov  [rsi + VOB_MGEN], rax
    mov  rax, [rel vo_epoch]
    mov  [rsi + VOB_EPOCH], rax
    mov  [rsi + VOB_ENTRY], ebx
    movzx eax, byte [rel vo_ident + VOE_KIND]
    mov  [rsi + VOB_KIND], eax
    mov  [rsi + VOB_MOUNT], r12d
    mov  rax, [rel vo_bind_seq]
    inc  rax
    mov  [rel vo_bind_seq], rax
    mov  [rsi + VOB_SEQ], rax
    mov  edx, VOB_F_LIVE
    test r14d, r14d
    jz   .flags
    or   edx, VOB_F_DUP
.flags:
    mov  [rsi + VOB_FLAGS], edx
    test r14d, r14d
    jnz  .dup
    shl  rax, 8
    lea  ecx, [r15d + 1]
    or   rax, rcx
    jmp  .out
.registry: mov eax, VO_E_REGISTRY
    jmp  .err
.notowned: mov eax, VO_E_NOTOWNED
    jmp  .err
.full:     mov eax, VO_E_FULL
    jmp  .err
.dup:      mov eax, VO_E_DUP
    jmp  .err
.exhausted:
    mov  eax, VO_E_EXHAUSTED
.err:
    call vo_fail
.none:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; vol_owner_live_check(RDI=dev, RSI=lba, RDX=count, RCX=token) -> EAX 0 the
; whole range lies inside a live, unique, still-identical owned binding / -1.
; Re-verified on every call: registry OK and unchanged since the bind (epoch),
; the token's slot and sequence, the same device and media generation, a
; healthy device, overflow-safe containment, and a full re-probe of the
; volume through its mount: current partition-table and filesystem identity
; and eligibility, compared whole with the adopted entry. media_generation is
; fixed at registration, so it is a cheap pre-check only, never the proof.
; EDI=vfs handle, RSI=dev -> RAX 1 if this mount holds a live, unique binding of the
; current epoch on this exact medium, else 0. Read-only: no probe, no slot change.
; A verb's volume rule asks here. Every physical effect still takes vol_owner_live_check.
vol_owner_mount_bound:
    xor  eax, eax
    cmp  byte [rel vo_state], VO_ST_OK
    jne  .ret
    test rsi, rsi
    jz   .ret
    cmp  dword [rsi + dev.health], HEALTH_OK
    jne  .ret
    push rbx
    push rcx
    push rdx
    lea  rbx, [rel vo_binds]
    mov  ecx, VO_BIND_MAX
.slot:
    mov  edx, [rbx + VOB_FLAGS]
    and  edx, VOB_F_LIVE | VOB_F_DUP
    cmp  edx, VOB_F_LIVE
    jne  .next
    cmp  edi, [rbx + VOB_MOUNT]
    jne  .next
    cmp  rsi, [rbx + VOB_DEV]
    jne  .next
    mov  rdx, [rbx + VOB_EPOCH]
    cmp  rdx, [rel vo_epoch]
    jne  .next
    mov  rdx, [rsi + dev.info]
    test rdx, rdx
    jz   .next
    mov  rdx, [rdx + blk_info.media_generation]
    cmp  rdx, [rbx + VOB_MGEN]
    jne  .next
    mov  eax, 1
    jmp  .done
.next:
    add  rbx, VOB_SIZE
    dec  ecx
    jnz  .slot
.done:
    pop  rdx
    pop  rcx
    pop  rbx
.ret:
    ret

vol_owner_live_check:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    cmp  byte [rel vo_state], VO_ST_OK
    jne  .no
    test r12, r12
    jz   .no
    test r14, r14
    jz   .no
    movzx eax, cl
    test eax, eax
    jz   .no
    dec  eax
    cmp  eax, VO_BIND_MAX
    jae  .no
    shl  eax, 6
    lea  rbx, [rel vo_binds]
    add  rbx, rax
    mov  eax, [rbx + VOB_FLAGS]
    and  eax, VOB_F_LIVE | VOB_F_DUP
    cmp  eax, VOB_F_LIVE
    jne  .no
    shr  rcx, 8
    cmp  rcx, [rbx + VOB_SEQ]
    jne  .no
    mov  rax, [rbx + VOB_EPOCH]
    cmp  rax, [rel vo_epoch]
    jne  .no
    cmp  r12, [rbx + VOB_DEV]
    jne  .no
    cmp  dword [r12 + dev.health], HEALTH_OK
    jne  .no
    mov  rax, [r12 + dev.info]
    test rax, rax
    jz   .no
    mov  rax, [rax + blk_info.media_generation]
    cmp  rax, [rbx + VOB_MGEN]
    jne  .no
    ; lba >= first, rel = lba - first < count_b, n <= count_b - rel
    mov  rax, r13
    sub  rax, [rbx + VOB_FIRST]
    jb   .no
    mov  rcx, [rbx + VOB_COUNT]
    cmp  rax, rcx
    jae  .no
    sub  rcx, rax
    cmp  r14, rcx
    ja   .no
    ; the registry entry this slot was bound to (unchanged within the epoch)
    mov  eax, [rbx + VOB_ENTRY]
    cmp  eax, VO_ENT_MAX
    jae  .no
    shl  eax, 7
    lea  r15, [rel vo_plain + VO_HDR_SIZE]
    add  r15, rax
    cmp  dword [r15 + VOE_MAGIC], 'VOE1'
    jne  .no
    ; the whole volume, re-probed now through its mount (SEC ae3d2900): the
    ; partition table (header/array CRC, unique entry, type, attributes,
    ; extent), the filesystem kind, id and state, the marker rule; then the
    ; complete identity must equal the adopted entry, on the same device. A
    ; changed disk/partition GUID, type, extent or filesystem, or an
    ; unreadable/malformed table, is not owned.
    mov  byte [rel vo_probe_live], 1
    mov  edi, [rbx + VOB_MOUNT]
    lea  rsi, [rel vo_live_ident]
    call vol_owner_probe
    mov  byte [rel vo_probe_live], 0
    test eax, eax
    jnz  .no
    cmp  r12, [rel vo_probe_dev]
    jne  .no
    lea  rdi, [r15 + VO_ID_OFF]
    lea  rsi, [rel vo_live_ident + VO_ID_OFF]
    mov  edx, VO_ID_LEN
    call memcmp
    test eax, eax
    jnz  .no
.yes:
    xor  eax, eax
    jmp  .out
.no:
    mov  eax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; vol_owner_live_check_files(RDI=dev, RSI=lba, RDX=count, RCX=token) -> EAX 0 / -1.
; Own partition A1 (Peter 107863, SEC 90335): vol_owner_live_check, unchanged, then the
; bound entry must hold no DATA role, so Explorer files never land on the sealed DATA
; volume. The DATA callers keep vol_owner_live_check itself.
vol_owner_live_check_files:
    push rcx
    call vol_owner_live_check
    pop  rcx
    test eax, eax
    jnz  .no
    movzx eax, cl                        ; live_check admitted the slot: 1..VO_BIND_MAX
    dec  eax
    shl  eax, 6
    lea  rdx, [rel vo_binds]
    mov  eax, [rdx + rax + VOB_ENTRY]
    shl  eax, 7
    lea  rdx, [rel vo_plain + VO_HDR_SIZE]
    cmp  dword [rdx + rax + VOE_DATA_ROLE], 0
    jne  .no
    xor  eax, eax
    ret
.no:
    mov  eax, -1
    ret

; vol_owner_device_dirty(RDI = dev): every binding on that device is dropped
; (offered for an admitted SPECIAL write to a partition table or raw range).
vol_owner_device_dirty:
    xor  ecx, ecx
.loop:
    cmp  ecx, VO_BIND_MAX
    jae  .out
    mov  eax, ecx
    shl  eax, 6
    lea  rsi, [rel vo_binds]
    add  rsi, rax
    cmp  [rsi + VOB_DEV], rdi
    jne  .next
    mov  dword [rsi + VOB_FLAGS], 0
.next:
    inc  ecx
    jmp  .loop
.out:
    ret

; ---------------------------------------------------------------------------
; vol_owner_status_text(RDI = buf, ESI = cap >= 64) -> EAX = length (NUL-terminated).
; Discloses state, generation and per-entry kind/scheme/extent/binding only:
; no disk/partition GUIDs, MBR signatures, volume ids, labels or UUIDs.
vol_owner_status_text:
    push rbx
    push r12
    push r13
    mov  [rel vo_out_ptr], rdi
    mov  [rel vo_out_base], rdi
    lea  eax, [esi - 1]
    add  rax, rdi
    mov  [rel vo_out_end], rax
    call vo_ready                        ; a never-loaded registry is loaded once
    lea  rdi, [rel str_vo_st_state]
    call vo_out_str
    movzx eax, byte [rel vo_state]
    cmp  eax, VO_ST_NOKEY
    ja   .unk
    lea  rcx, [rel vo_state_names]
    lea  rdi, [rcx + rax * 8]
    jmp  .state
.unk:
    lea  rdi, [rel str_vo_unknown]
.state:
    call vo_out_str
    cmp  byte [rel vo_state], VO_ST_OK
    jne  .done
    lea  rdi, [rel str_vo_st_entries]
    call vo_out_str
    mov  eax, [rel vo_plain + VOH_COUNT]
    call vo_out_dec
    lea  rdi, [rel str_vo_st_gen]
    call vo_out_str
    mov  rax, [rel vo_plain + VOH_GEN]
    call vo_out_dec
    xor  ebx, ebx
.ent:
    cmp  ebx, VO_ENT_MAX
    jae  .done
    mov  eax, ebx
    shl  eax, 7
    lea  r12, [rel vo_plain + VO_HDR_SIZE]
    add  r12, rax
    cmp  dword [r12 + VOE_MAGIC], 'VOE1'
    jne  .ent_next
    lea  rdi, [rel str_vo_st_idx]
    call vo_out_str
    mov  eax, ebx
    call vo_out_dec
    lea  rdi, [rel str_vo_st_fat]
    cmp  byte [r12 + VOE_KIND], VO_KIND_FAT32
    je   .kind
    lea  rdi, [rel str_vo_st_ext]
.kind:
    call vo_out_str
    lea  rdi, [rel str_vo_st_gpt]
    cmp  byte [r12 + VOE_SCHEME], VO_SCHEME_GPT
    je   .sch
    lea  rdi, [rel str_vo_st_mbr]
.sch:
    call vo_out_str
    lea  rdi, [rel str_vo_st_first]
    call vo_out_str
    mov  rax, [r12 + VOE_FIRST]
    call vo_out_dec
    lea  rdi, [rel str_vo_st_sectors]
    call vo_out_str
    mov  rax, [r12 + VOE_COUNT]
    call vo_out_dec
    cmp dword [r12 + VOE_DATA_ROLE], VO_DATA_ROLE
    jne .role_text_done
    lea rdi, [rel str_vo_st_data]
    call vo_out_str
.role_text_done:
    ; bound = a live binding of this epoch on this entry (dup wins)
    xor  r13d, r13d
    xor  ecx, ecx
.b:
    cmp  ecx, VO_BIND_MAX
    jae  .b_done
    mov  eax, ecx
    shl  eax, 6
    lea  rsi, [rel vo_binds]
    add  rsi, rax
    test dword [rsi + VOB_FLAGS], VOB_F_LIVE
    jz   .b_next
    mov  rax, [rsi + VOB_EPOCH]
    cmp  rax, [rel vo_epoch]
    jne  .b_next
    cmp  [rsi + VOB_ENTRY], ebx
    jne  .b_next
    cmp  r13d, 2
    je   .b_next
    mov  r13d, 1
    test dword [rsi + VOB_FLAGS], VOB_F_DUP
    jz   .b_next
    mov  r13d, 2
.b_next:
    inc  ecx
    jmp  .b
.b_done:
    lea  rdi, [rel str_vo_st_unbound]
    test r13d, r13d
    jz   .bnd
    lea  rdi, [rel str_vo_st_bound]
    cmp  r13d, 1
    je   .bnd
    lea  rdi, [rel str_vo_st_dup]
.bnd:
    call vo_out_str
.ent_next:
    inc  ebx
    jmp  .ent
.done:
    mov  rdi, [rel vo_out_ptr]
    mov  byte [rdi], 0
    mov  rax, rdi
    sub  rax, [rel vo_out_base]
    pop  r13
    pop  r12
    pop  rbx
    ret

; vo_out_str(RDI = cstr): appended, bounded by vo_out_end.
vo_out_str:
    mov  rsi, [rel vo_out_ptr]
.loop:
    mov  al, [rdi]
    test al, al
    jz   .out
    cmp  rsi, [rel vo_out_end]
    jae  .out
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .loop
.out:
    mov  [rel vo_out_ptr], rsi
    ret

; vo_out_dec(RAX = unsigned): decimal appended.
vo_out_dec:
    lea  rdi, [rel vo_dec_buf + 23]
    mov  byte [rdi], 0
    mov  rcx, 10
.digit:
    xor  edx, edx
    div  rcx
    add  dl, '0'
    dec  rdi
    mov  [rdi], dl
    test rax, rax
    jnz  .digit
    jmp  vo_out_str

; ---------------------------------------------------------------------------
vo_domain: db 'PaOS volume ownership v1'
.len equ $ - vo_domain
; on-disk (mixed-endian) GPT type GUIDs
vo_guid_esp:   db 0x28,0x73,0x2A,0xC1,0x1F,0xF8,0xD2,0x11,0xBA,0x4B,0x00,0xA0,0xC9,0x3E,0xC9,0x3B
vo_guid_basic: db 0xA2,0xA0,0xD0,0xEB,0xE5,0xB9,0x33,0x44,0x87,0xC0,0x68,0xB6,0xB7,0x26,0x99,0xC7
vo_guid_linux: db 0xAF,0x3D,0xC6,0x0F,0x83,0x84,0x72,0x47,0x8E,0x79,0x3D,0x69,0xD8,0x47,0x7D,0xE4
vo_state_names: db "unload",0,0, "ok",0,0,0,0,0,0, "corrupt",0, "uncertn",0, "nokey",0,0,0
str_vo_unknown:     db "unknown",0
str_vo_st_state:    db "state=",0
str_vo_st_entries:  db " entries=",0
str_vo_st_gen:      db " gen=",0
str_vo_st_idx:      db " [",0
str_vo_st_fat:      db " fat32",0
str_vo_st_ext:      db " ext",0
str_vo_st_gpt:      db " gpt",0
str_vo_st_mbr:      db " mbr",0
str_vo_st_first:    db " first=",0
str_vo_st_sectors:  db " sectors=",0
str_vo_st_data:     db " data",0
str_vo_st_unbound:  db " unbound]",0
str_vo_st_bound:    db " bound]",0
str_vo_st_dup:      db " dup]",0
str_vo_prefix:      db "[PAOS64] [fs.volowner] ",0
str_vo_adopted:     db "adopted",0
str_vo_adopted_local: db "adopted local-card",0
str_vo_released:    db "released",0
str_vo_reset:       db "reset",0
str_vo_entry:       db " entry=",0
str_vo_gen:         db " gen=",0
str_vo_crlf:        db 13,10,0
str_vo_nvg_tag:     db "vol_owner_registry",0
; own partition A4: the System Volume Information entries Windows writes, byte for byte. Byte 13
; (the checksum of the short name) is compared against the short entry, not this template.
vo_svi_sfn:         db "SYSTEM~1   "
vo_lfn_svi2: db 0x42, 0x20, 0x00, 0x49, 0x00, 0x6e, 0x00, 0x66, 0x00, 0x6f, 0x00, 0x0f, 0x00, 0x00, 0x72, 0x00, 0x6d, 0x00, 0x61, 0x00, 0x74, 0x00, 0x69, 0x00, 0x6f, 0x00, 0x00, 0x00, 0x6e, 0x00, 0x00, 0x00
vo_lfn_svi1: db 0x01, 0x53, 0x00, 0x79, 0x00, 0x73, 0x00, 0x74, 0x00, 0x65, 0x00, 0x0f, 0x00, 0x00, 0x6d, 0x00, 0x20, 0x00, 0x56, 0x00, 0x6f, 0x00, 0x6c, 0x00, 0x75, 0x00, 0x00, 0x00, 0x6d, 0x00, 0x65, 0x00

%include "fs/vol_owner_data.asm"

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
%macro WDATA_fs_vol_owner_0 0
vo_name: dw 'P','a','O','S','V','o','l','O','w','n','1',0
; the PaOS vendor GUID data/config_store uses (NV_CLASS_PAOS with a "PaOS" name)
vo_guid: db 0x29,0xc1,0x6e,0x5a,0x54,0x25,0x4c,0x49,0x99,0xbd,0xb0,0x39,0x60,0xdf,0x47,0x04
align 8
vo_size:        dq VO_RECORD_SIZE
%endmacro
WDATA_DEFER WDATA_fs_vol_owner_0
; Zero-initialised state with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER). Same labels, same order and
; the same zero initial value; only paos.efi shrinks.
%if VO_ST_UNLOADED != 0
%error "vo_state lives in the zero-fill tail: VO_ST_UNLOADED must be 0"
%endif
%macro WDATA_BSS_fs_vol_owner 0
alignb 8
vo_epoch:       resq 1
vo_bind_seq:    resq 1
vo_probe_dev:   resq 1
vo_probe_mount: resq 1
vo_out_ptr:     resq 1
vo_out_base:    resq 1
vo_out_end:     resq 1
vo_attrs:       resd 1
vo_last_error:  resd 1
vo_state:       resb 1                  ; VO_ST_UNLOADED
alignb 8
vo_fsinfo:      resb fs_info_size
vo_dec_buf:     resb 24
vo_probe_live:  resb 1
alignb 8
; the reset-wipe range: vo_ident .. vo_sector (identity, bindings, plaintext,
; records, key); keep these contiguous (pinned by test)
vo_ident:       resb VO_ENT_SIZE
vo_live_ident:  resb VO_ENT_SIZE
vo_binds:       resb VO_BIND_MAX * VOB_SIZE
vo_plain:       resb VO_PLAIN_SIZE
vo_new:         resb VO_PLAIN_SIZE
vo_check:       resb VO_PLAIN_SIZE
vo_record:      resb VO_RECORD_SIZE
vo_verify:      resb VO_RECORD_SIZE
vo_backup:      resb VO_RECORD_SIZE
vo_key:         resb 32
vo_req:         resb AEAD_REQ_SZ
vo_sector:      resb VO_SECTOR
vo_gpt_hdr:     resb VO_SECTOR
vo_gpt_arr:     resb VO_GPT_ARR_MAX
; own partition A3/A4: the local snapshot slot (vo_snap_ident and vo_snap_id contiguous: vo_snap_clear)
alignb 8
vo_snap_ident:  resb VO_ENT_SIZE
vo_snap_id:     resb 16
vo_snap_time:   resq 1
vo_e_fat_lba:   resq 1
vo_e_data_lba:  resq 1
vo_snap_mount:  resd 1
vo_e_spc:       resd 1
vo_e_max:       resd 1
vo_e_seen:      resd VO_ROOT_MAX
vo_snap_valid:  resb 1
vo_adopt_local: resb 1                  ; 1 only inside vol_owner_local_adopt's vo_adopt_core call
alignb 8
vo_snap_auth:   resq 1                  ; the session authority token at the snapshot (P2)
vo_probe_part:  resb 1
vo_e_term:      resb 1
vo_e_label:     resb 1
vo_e_svi:       resb 1
vo_e_lfn:       resb 1
vo_e_chk:       resb 1
alignb 8
vo_fat_sector:  resb VO_SECTOR
%endmacro
WDATA_BSS_DEFER WDATA_BSS_fs_vol_owner
