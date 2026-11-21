;; MODULE fs/fs_format
;; LAYER 4
;; EXPORTS fs_format_classify, fs_format_snapshot, fs_format_register_decision, fs_format_begin, fs_format_cancel, fs_format_label_valid, fs_format_custody, fs_format_bind_start, fs_format_end, fs_format_state, fs_format_mount_allowed
;; IMPORTS fs/blockdev, fs/fs_identify, fs/guest_volume, fs/vfs, fs/owned_media, fs/storage_access, fs/fat32_disk, fs/ntfs_disk, fs/ext4_disk, fs/exfat_disk, fs/vfs_copy_service, fs/data_config_provider, sec/session, core/lib/mem, core/lib/crc32, core/csprng, core/time, core/smp, boot/boot_esp_guid, boot/serial
;; CAPS CAP_BLOCK_READ
;; OWNER saga:storage
;; CONTEXT: bsp_only  (one native supervisor: module-static slot, custody and scratch; no yield inside a call)
; ============================================================================
; fs/fs_format.asm — Format F1 (Peter 107813, ROOT 108207, FORMAT_SIZE.md; authored by rc-amd, owner FS):
; the native side of the Explorer Format of a removable drive. The guest does the format (F2 transport, F3
; tools); this module classifies the live device, holds custody for exactly one format, binds the owner's
; confirmation token, and re-probes the result. It never writes a sector (blk_read only).
;
; 1. fs_format_classify: removable driver flag, 512-byte sectors, not held by a guest/copy/binding, not PaOS
;    boot media, exactly one table entry admitted by fs_identify_primary (rc-ai F2s: superfloppy, extended,
;    encrypted and overlap refused there), GPT CRCs, a type allowlist, never LBA 0 or past the device.
; 2. fs_format_snapshot / fs_format_begin: the A3 pattern (vol_owner_local_snapshot/_adopt). A CSPRNG
;    16-byte request id is the card's confirmation token (FS obligation 3). Begin calls the registered
;    decision consumer FIRST with the stored id, then the slot, the session, the filesystem and label, a
;    live reclassification equal to the snapshot, and vfs_retire_device; only then is custody HELD.
;    The consumer slot is this module's own (fs_format_register_decision), never sec/adopt_decision.
; 3. F2 joins (VM 108218) through fs_format_custody (verifies F2's descriptor144 against custody; its
;    scheme through rc-ai's guest_volume_format_scheme, the one translation site of SEC 108221 C8) and
;    fs_format_bind_start (the token, once).
; 4. fs_format_mount_allowed (SEC C1/C7): while custody is HELD, and while a QUARANTINE names the same
;    incarnation, vfs refuses every native mount, selection and mount lookup of that device.
; 5. fs_format_end: unplug or fault quarantines; otherwise a live re-probe of tuple, kind and label.
;    DONE only for a clean transport with every field equal; else UNCERTAIN. Nothing is mounted here:
;    native views were retired at begin, and the existing selectors remount once custody is released.
; begin and end each write one serial audit line (SEC C5): device name, scheme, slot, filesystem and
; the outcome; never the label or the request id. sec/session's local wipe calls fs_format_cancel (C6).
; ============================================================================

FF_E_NONE      equ 0
FF_E_NODEV     equ 1
FF_E_FIXED     equ 2
FF_E_SECTOR    equ 3
FF_E_BUSY      equ 4
FF_E_BOOTMEDIA equ 5
FF_E_TABLE     equ 6
FF_E_TYPE      equ 7
FF_E_EXTENT    equ 8
FF_E_IO        equ 9
FF_E_SESSION   equ 10
FF_E_DECISION  equ 11
FF_E_SNAPSHOT  equ 12
FF_E_FS        equ 13
FF_E_LABEL     equ 14
FF_E_CHANGED   equ 15
FF_E_CUSTODY   equ 16

FF_R_DONE        equ 0
FF_R_UNCERTAIN   equ 1
FF_R_QUARANTINE  equ 2
FF_R_NOT_STARTED equ 3

FF_T_CLEAN       equ 0
FF_T_UNCERTAIN   equ 1
FF_T_FAULT       equ 2
FF_T_NOT_STARTED equ 3

FF_KIND_FAT32  equ 1
FF_KIND_EXFAT  equ 2
FF_KIND_NTFS   equ 3
FF_KIND_EXT4   equ 4

FF_CS_NONE     equ 0
FF_CS_HELD     equ 1
FF_CS_QUAR     equ 2

FF_SCHEME_MBR  equ 1              ; == vfs FS_SCHEME_MBR == vol_owner VO_SCHEME_MBR (pinned by test)
FF_SCHEME_GPT  equ 2
FF_PRIN_OWNER  equ 1              ; == sec/principal PRIN_OWNER (pinned by test)
FF_SNAP_LIFE_US equ 120000000     ; a snapshot older than 120 s never begins a format
FF_GPT_MAX     equ 128
FF_LABEL_MAX   equ 11

; classification record (64 bytes)
FFC_FIRST      equ 0
FFC_COUNT      equ 8
FFC_DEVBYTES   equ 16
FFC_GEN        equ 24
FFC_SCHEME     equ 32
FFC_SLOT       equ 33
FFC_MBRTYPE    equ 34
FFC_KIND       equ 35
FFC_MBRSIG     equ 36
FFC_GPTTYPE    equ 40             ; GPT: 1 Basic Data, 2 Linux filesystem; MBR 0
FFC_GPTDISK    equ 48
FFC_PARTGUID   equ 64             ; GPT: the entry's unique partition GUID (never zero); MBR 0
FFC_SIZE       equ 80

; custody record handed to F2 (128 bytes)
FFK_DEV        equ 0
FFK_GEN        equ 8
FFK_FIRST      equ 16
FFK_COUNT      equ 24
FFK_SCHEME     equ 32
FFK_SLOT       equ 33
FFK_FS         equ 34
FFK_LABELLEN   equ 35
FFK_TOKEN      equ 40
FFK_LABEL      equ 56
FFK_SIZE       equ 128

; ---------------------------------------------------------------------------
; fs_format_classify(RDI=dev, RSI=first, RDX=count, RCX=out64) -> EAX 0 / FF_E_*.
; first = count = 0 asks for the device's single table entry; otherwise the exact extent the
; caller names (the card's drive). Read-only: blk_read only. A refusal zeroes out64.
fs_format_classify:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    mov  rdi, rcx
    xor  esi, esi
    mov  edx, FFC_SIZE
    call memset
    ; 1. a currently registered READ device
    xor  ebx, ebx
.member:
    mov  rdi, rbx
    mov  esi, BLKCAP_READ
    xor  edx, edx
    call blk_iter_after
    test rax, rax
    jz   .nodev
    mov  rbx, rax
    cmp  rax, r12
    jne  .member
    mov  rbp, [r12 + dev.info]
    test rbp, rbp
    jz   .nodev
    ; 2. removable is the driver's flag, never the media
    cmp  byte [rbp + blk_info.removable], 0
    jne  .removable
    test dword [rbp + blk_info.flags], BLKF_REMOVABLE
    jz   .fixed
.removable:
    ; 3. 512-byte logical sectors
    cmp  dword [rbp + blk_info.sector_size], 512
    jne  .sector
    cmp  qword [rbp + blk_info.lba_max], 2
    jb   .sector
    ; 4. nobody else holds it
    mov  rdi, r12
    call guest_volume_native_allowed
    test rax, rax
    jnz  .busy
    call vfs_copy_busy
    test eax, eax
    jnz  .busy
    call storage_access_binding_busy
    test eax, eax
    jnz  .busy
    ; 5. PaOS booted from removable media it cannot name: no removable format at all (fail-closed)
    cmp  byte [rel boot_esp_part_guid_ok], 1
    je   .read0
    cmp  byte [rel boot_esp_removable], 0
    jne  .bootmedia
.read0:
    mov  rdi, r12
    xor  esi, esi
    lea  rdx, [rel ff_sec]
    call ff_read
    test eax, eax
    jnz  .io
    ; a filesystem boot sector at LBA 0 is a superfloppy: never a table (F2s also refuses it)
    lea  rdi, [rel ff_sec]
    call ff_kind_of_sector
    test eax, eax
    jnz  .table
    cmp  word [rel ff_sec + 510], 0xAA55
    jne  .table
    mov  eax, [rel ff_sec + 440]
    mov  [r15 + FFC_MBRSIG], eax
    xor  ecx, ecx
.prescan:
    mov  eax, ecx
    shl  eax, 4
    lea  rdx, [rel ff_sec + 446]
    cmp  byte [rdx + rax + 4], 0xEE
    je   .gpt
    inc  ecx
    cmp  ecx, 4
    jb   .prescan
    ; ---- MBR: the entry with this window, or the single nonempty entry ----
    cmp  dword [r15 + FFC_MBRSIG], 0     ; FS 108217: the disk signature is the stick's identity
    je   .table
    mov  byte [r15 + FFC_SCHEME], FF_SCHEME_MBR
    xor  ecx, ecx                        ; slot index
    xor  r8d, r8d                        ; matched slot + 1
    xor  r9d, r9d                        ; nonempty slots
.mbr:
    mov  eax, ecx
    shl  eax, 4
    lea  rdx, [rel ff_sec + 446]
    add  rdx, rax
    cmp  byte [rdx + 4], 0
    je   .mbr_next
    inc  r9d
    mov  eax, [rdx + 8]
    mov  r10d, [rdx + 12]
    mov  r11, r13
    or   r11, r14
    jz   .mbr_any
    cmp  rax, r13
    jne  .mbr_next
    cmp  r10, r14
    jne  .mbr_next
.mbr_any:
    test r8d, r8d
    jnz  .table                          ; two entries with this window
    lea  r8d, [ecx + 1]
    mov  [r15 + FFC_FIRST], rax
    mov  [r15 + FFC_COUNT], r10
    movzx eax, byte [rdx + 4]
    mov  [r15 + FFC_MBRTYPE], al
.mbr_next:
    inc  ecx
    cmp  ecx, 4
    jb   .mbr
    test r8d, r8d
    jz   .table
    mov  rax, r13
    or   rax, r14
    jnz  .mbr_one
    cmp  r9d, 1
    jne  .table                          ; which of several is the owner's choice, not ours
.mbr_one:
    mov  [r15 + FFC_SLOT], r8b
    movzx eax, byte [r15 + FFC_MBRTYPE]
    lea  rdi, [rel ff_mbr_types]
.mbr_type:
    movzx ecx, byte [rdi]
    test ecx, ecx
    jz   .type
    cmp  eax, ecx
    je   .extent
    inc  rdi
    jmp  .mbr_type
    ; ---- GPT: header CRC, array CRC, boot ESP anywhere, the entry, its type and attributes ----
.gpt:
    mov  dword [r15 + FFC_MBRSIG], 0
    mov  byte [r15 + FFC_SCHEME], FF_SCHEME_GPT
    mov  rdi, r12
    mov  esi, 1
    lea  rdx, [rel ff_hdr]
    call ff_read
    test eax, eax
    jnz  .io
    mov  rax, 'EFI PART'
    cmp  [rel ff_hdr], rax
    jne  .table
    mov  esi, [rel ff_hdr + 12]
    cmp  esi, 92
    jb   .table
    cmp  esi, 512
    ja   .table
    mov  eax, [rel ff_hdr + 16]
    mov  [rsp], eax
    mov  dword [rel ff_hdr + 16], 0
    lea  rdi, [rel ff_hdr]
    call hotpatch_crc32
    mov  ecx, [rsp]
    mov  [rel ff_hdr + 16], ecx
    cmp  eax, ecx
    jne  .table
    cmp  dword [rel ff_hdr + 84], 128
    jne  .table
    mov  eax, [rel ff_hdr + 80]
    test eax, eax
    jz   .table
    cmp  eax, FF_GPT_MAX
    ja   .table
    mov  [rel ff_gpt_n], eax
    mov  rax, [rel ff_hdr + 72]          ; array LBA: at least 2, the whole array inside the device
    cmp  rax, 2
    jb   .table
    mov  ecx, [rel ff_gpt_n]
    add  ecx, 3
    shr  ecx, 2                          ; sectors
    mov  [rsp + 4], ecx
    add  rax, rcx
    jc   .table
    dec  rax
    cmp  rax, [rbp + blk_info.lba_max]
    ja   .table
    xor  ecx, ecx
.arr:
    cmp  ecx, [rsp + 4]
    jae  .arr_crc
    mov  [rsp], ecx
    mov  rsi, [rel ff_hdr + 72]
    add  rsi, rcx
    lea  rdx, [rel ff_arr]
    shl  ecx, 9
    add  rdx, rcx
    mov  rdi, r12
    call ff_read
    test eax, eax
    jnz  .io
    mov  ecx, [rsp]
    inc  ecx
    jmp  .arr
.arr_crc:
    lea  rdi, [rel ff_arr]
    mov  esi, [rel ff_gpt_n]
    shl  esi, 7
    call hotpatch_crc32
    cmp  eax, [rel ff_hdr + 88]
    jne  .table
    lea  rdi, [r15 + FFC_GPTDISK]
    lea  rsi, [rel ff_hdr + 56]
    mov  edx, 16
    call memcpy
    xor  ecx, ecx
    xor  r8d, r8d                        ; matched entry + 1
    xor  r9d, r9d                        ; used entries
.gent:
    cmp  ecx, [rel ff_gpt_n]
    jae  .gdone
    mov  eax, ecx
    shl  eax, 7
    lea  rdx, [rel ff_arr]
    add  rdx, rax
    mov  rax, [rdx]
    or   rax, [rdx + 8]
    jz   .gnext                          ; unused entry
    inc  r9d
    cmp  byte [rel boot_esp_part_guid_ok], 1
    jne  .gwin
    mov  rax, [rdx + 16]                 ; this stick holds the ESP PaOS was loaded from
    cmp  rax, [rel boot_esp_part_guid]
    jne  .gwin
    mov  rax, [rdx + 24]
    cmp  rax, [rel boot_esp_part_guid + 8]
    je   .bootmedia
.gwin:
    mov  rax, [rdx + 32]
    mov  r10, [rdx + 40]
    cmp  r10, rax
    jb   .gnext
    sub  r10, rax
    inc  r10                             ; count
    mov  r11, r13
    or   r11, r14
    jz   .gany
    cmp  rax, r13
    jne  .gnext
    cmp  r10, r14
    jne  .gnext
.gany:
    test r8d, r8d
    jnz  .table
    lea  r8d, [ecx + 1]
    mov  [r15 + FFC_FIRST], rax
    mov  [r15 + FFC_COUNT], r10
    mov  [rel ff_gpt_entry], rdx
.gnext:
    inc  ecx
    jmp  .gent
.gdone:
    test r8d, r8d
    jz   .table
    mov  rax, r13
    or   rax, r14
    jnz  .gone
    cmp  r9d, 1
    jne  .table
.gone:
    mov  [r15 + FFC_SLOT], r8b
    mov  rdx, [rel ff_gpt_entry]
    mov  rax, [rdx + 16]
    or   rax, [rdx + 24]
    jz   .table                          ; a zero unique GUID names no partition
    mov  rax, [rdx + 16]
    mov  [r15 + FFC_PARTGUID], rax
    mov  rax, [rdx + 24]
    mov  [r15 + FFC_PARTGUID + 8], rax
    test byte [rdx + 48], 1              ; platform-required
    jnz  .type
    mov  rax, [rdx]
    mov  rcx, [rdx + 8]
    mov  byte [r15 + FFC_GPTTYPE], 1
    cmp  rax, [rel ff_guid_basic]
    jne  .glinux
    cmp  rcx, [rel ff_guid_basic + 8]
    je   .extent
.glinux:
    mov  byte [r15 + FFC_GPTTYPE], 2
    cmp  rax, [rel ff_guid_linux]
    jne  .type
    cmp  rcx, [rel ff_guid_linux + 8]
    jne  .type
    ; ---- the extent: never LBA 0, never the whole device, inside the device ----
.extent:
    mov  rax, [r15 + FFC_FIRST]
    mov  rcx, [r15 + FFC_COUNT]
    test rax, rax
    jz   .bad_extent
    test rcx, rcx
    jz   .bad_extent
    add  rcx, rax
    jc   .bad_extent
    dec  rcx
    cmp  rcx, [rbp + blk_info.lba_max]
    ja   .bad_extent
    ; ---- F2s: fs_identify's own walk admits exactly this primary ----
    mov  rdi, r12
    mov  rsi, [r15 + FFC_FIRST]
    mov  rdx, [r15 + FFC_COUNT]
    lea  rcx, [rel ff_prim]
    call fs_identify_primary
    test rax, rax
    jnz  .table
    cmp  [rel ff_prim], r12
    jne  .table
    mov  rax, [rbp + blk_info.media_generation]
    test rax, rax
    jz   .table
    cmp  [rel ff_prim + 8], rax
    jne  .table
    mov  [r15 + FFC_GEN], rax
    mov  rax, [r15 + FFC_FIRST]
    cmp  [rel ff_prim + 16], rax
    jne  .table
    mov  rax, [r15 + FFC_COUNT]
    cmp  [rel ff_prim + 24], rax
    jne  .table
    movzx eax, byte [r15 + FFC_SLOT]
    cmp  [rel ff_prim + 32], eax
    jne  .table
    movzx eax, byte [r15 + FFC_SCHEME]
    cmp  [rel ff_prim + 36], eax
    jne  .table
    movzx eax, byte [r15 + FFC_MBRTYPE]  ; rc-ai 108220: MBR type u32 @40, signature u32 @44 (GPT: 0)
    cmp  [rel ff_prim + 40], eax
    jne  .table
    mov  eax, [r15 + FFC_MBRSIG]
    cmp  [rel ff_prim + 44], eax
    jne  .table
    mov  rax, [rbp + blk_info.lba_max]
    inc  rax
    shl  rax, 9
    mov  [r15 + FFC_DEVBYTES], rax
    ; the current filesystem, for display and the end's comparison (not a refusal)
    mov  rdi, r12
    mov  rsi, [r15 + FFC_FIRST]
    call ff_probe_kind
    mov  [r15 + FFC_KIND], al
    xor  eax, eax
    jmp  .out
.nodev:     mov  eax, FF_E_NODEV
            jmp  .fail
.fixed:     mov  eax, FF_E_FIXED
            jmp  .fail
.sector:    mov  eax, FF_E_SECTOR
            jmp  .fail
.busy:      mov  eax, FF_E_BUSY
            jmp  .fail
.bootmedia: mov  eax, FF_E_BOOTMEDIA
            jmp  .fail
.table:     mov  eax, FF_E_TABLE
            jmp  .fail
.type:      mov  eax, FF_E_TYPE
            jmp  .fail
.bad_extent: mov eax, FF_E_EXTENT
            jmp  .fail
.io:        mov  eax, FF_E_IO
.fail:
    mov  [rsp], eax
    mov  rdi, r15
    xor  esi, esi
    mov  edx, FFC_SIZE
    call memset
    mov  eax, [rsp]
.out:
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; ff_read(RDI=dev, RSI=lba, RDX=buf) -> EAX 0 / -1. One sector, blk_read only.
ff_read:
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

; ff_kind_of_sector(RDI=sector) -> EAX FF_KIND_FAT32/EXFAT/NTFS, or 0. The boot sector alone.
ff_kind_of_sector:
    mov  rax, 'EXFAT   '
    cmp  [rdi + 3], rax
    je   .exfat
    mov  rax, 'NTFS    '
    cmp  [rdi + 3], rax
    je   .ntfs
    cmp  word [rdi + 510], 0xAA55
    jne  .none
    cmp  word [rdi + 11], 512
    jne  .none
    cmp  word [rdi + 22], 0              ; FAT size 16
    jne  .none
    mov  rax, 'FAT32   '
    cmp  [rdi + 82], rax
    jne  .none
    mov  eax, FF_KIND_FAT32
    ret
.exfat:
    cmp  word [rdi + 510], 0xAA55
    jne  .none
    mov  eax, FF_KIND_EXFAT
    ret
.ntfs:
    cmp  word [rdi + 510], 0xAA55
    jne  .none
    mov  eax, FF_KIND_NTFS
    ret
.none:
    xor  eax, eax
    ret

; ff_probe_kind(RDI=dev, RSI=first) -> EAX kind / 0 (unknown or unreadable). Leaves the first
; sector in ff_vbr and, for ext4, the superblock sector (first + 2) in ff_sb. Read-only.
ff_probe_kind:
    push rbx
    push r12
    sub  rsp, 8
    mov  rbx, rdi
    mov  r12, rsi
    lea  rdi, [rel ff_vbr]
    xor  esi, esi
    mov  edx, 512
    call memset
    lea  rdi, [rel ff_sb]
    xor  esi, esi
    mov  edx, 512
    call memset
    mov  rdi, rbx
    mov  rsi, r12
    lea  rdx, [rel ff_vbr]
    call ff_read
    test eax, eax
    jnz  .none
    lea  rdi, [rel ff_vbr]
    call ff_kind_of_sector
    test eax, eax
    jnz  .out
    mov  rdi, rbx
    lea  rsi, [r12 + 2]                  ; the ext superblock is at byte 1024 of the volume
    lea  rdx, [rel ff_sb]
    call ff_read
    test eax, eax
    jnz  .none
    cmp  word [rel ff_sb + 56], 0xEF53
    jne  .none
    test dword [rel ff_sb + 96], 0x40    ; INCOMPAT_EXTENTS: ext4, not ext2/3
    jz   .none
    mov  eax, FF_KIND_EXT4
    jmp  .out
.none:
    xor  eax, eax
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; fs_format_label_valid(EDI=filesystem, RSI=label, EDX=length) -> EAX 0 / -1.
; The guest's one portable rule for all four (guest_drive_rename.valid_label, pinned by test):
; [A-Z][A-Z0-9 _-]{0,10}, no trailing space. The filesystem must be 1..4.
fs_format_label_valid:
    lea  eax, [edi - 1]
    cmp  eax, 3
    ja   .bad
    test edx, edx
    jz   .bad
    cmp  edx, FF_LABEL_MAX
    ja   .bad
    test rsi, rsi
    jz   .bad
    movzx eax, byte [rsi]
    sub  eax, 'A'
    cmp  eax, 25
    ja   .bad
    mov  ecx, 1
.ch:
    cmp  ecx, edx
    jae  .end
    movzx eax, byte [rsi + rcx]
    cmp  eax, ' '
    je   .ok
    cmp  eax, '_'
    je   .ok
    cmp  eax, '-'
    je   .ok
    lea  r8d, [eax - 'A']
    cmp  r8d, 25
    jbe  .ok
    lea  r8d, [eax - '0']
    cmp  r8d, 9
    ja   .bad
.ok:
    inc  ecx
    jmp  .ch
.end:
    cmp  byte [rsi + rdx - 1], ' '
    je   .bad
    xor  eax, eax
    ret
.bad:
    mov  eax, -1
    ret

; ---------------------------------------------------------------------------
; ff_owner_session() -> EAX 0 with RDX = the session authority token / FF_E_SESSION (RDX 0).
; As vol_owner's vo_owner_session: an unlocked local owner session, no remote frame or injected input.
ff_owner_session:
    call session_shell_local_authority
    cmp  rax, FF_PRIN_OWNER
    jne  .bad
    test rdx, rdx
    jz   .bad
    cmp  rdx, -1
    je   .bad
    xor  eax, eax
    ret
.bad:
    xor  edx, edx
    mov  eax, FF_E_SESSION
    ret

; ff_custody_settle: a QUARANTINED custody clears only once its device left the registry or its
; medium changed (a replug); a HELD custody never clears here. No IO.
ff_custody_settle:
    cmp  byte [rel ff_cust_state], FF_CS_QUAR
    jne  .out
    mov  rdi, [rel ff_cust + FFK_DEV]
    mov  rsi, [rel ff_cust + FFK_GEN]
    call ff_member_gen
    test eax, eax
    jz   .out
    call ff_custody_clear
.out:
    ret

; ff_member_gen(RDI=dev, RSI=generation) -> EAX 0 while that exact incarnation is registered / 1 gone.
ff_member_gen:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    xor  ebx, ebx
.next:
    mov  rdi, rbx
    xor  esi, esi
    xor  edx, edx
    call blk_iter_after
    test rax, rax
    jz   .gone
    mov  rbx, rax
    cmp  rax, r12
    jne  .next
    mov  rax, [r12 + dev.info]
    test rax, rax
    jz   .gone
    cmp  [rax + blk_info.media_generation], r13
    jne  .gone
    xor  eax, eax
    jmp  .out
.gone:
    mov  eax, 1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

ff_custody_clear:
    mov  byte [rel ff_cust_state], FF_CS_NONE
    mov  byte [rel ff_cust_bound], 0
    lea  rdi, [rel ff_cust]
    xor  esi, esi
    mov  edx, FFK_SIZE
    jmp  memset

; ff_snap_clear: no slot; the id, the kept classification and the session are wiped. No IO.
ff_snap_clear:
    mov  byte [rel ff_snap_valid], 0
    mov  qword [rel ff_snap_auth], 0
    mov  qword [rel ff_snap_dev], 0
    lea  rdi, [rel ff_snap_class]
    xor  esi, esi
    mov  edx, FFC_SIZE + 16              ; ff_snap_class then ff_snap_id
    jmp  memset

; ---------------------------------------------------------------------------
; fs_format_snapshot(RDI=dev, RSI=first, RDX=count, RCX=out96) -> EAX 0 / FF_E_*.
; The card draws from this. Read-only. Out (display only, never read back): +0 request id[16] (CSPRNG,
; the confirmation token) | +16 device name[32] NUL-padded | +48 disk bytes | +56 partition bytes |
; +64 scheme (1 MBR, 2 GPT) | +65 slot (1-based) | +66 current kind (0 unknown) | +67 the kept MBR type |
; +68 the kept GPT type (1 Basic Data, 2 Linux) | +69..+95 0. The type is the card's to name (SEC C 3).
; Keeps one slot {id, dev, classification, session token, monotonic time}; a refusal leaves none.
fs_format_snapshot:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    call ff_snap_clear
    mov  rdi, r15
    xor  esi, esi
    mov  edx, 96
    call memset
    call ff_custody_settle
    mov  eax, FF_E_BUSY
    cmp  byte [rel ff_cust_state], FF_CS_NONE
    jne  .err                            ; one format at a time, quarantine included
    call ff_owner_session
    test eax, eax
    jnz  .err
    mov  [rel ff_snap_auth], rdx
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, r14
    lea  rcx, [rel ff_snap_class]
    call fs_format_classify
    test eax, eax
    jnz  .err
    lea  rdi, [rel ff_snap_id]
    mov  esi, 16
    call csprng_generate
    test rax, rax
    mov  eax, FF_E_IO
    jnz  .err
    mov  rax, [rel ff_snap_id]
    or   rax, [rel ff_snap_id + 8]
    mov  eax, FF_E_IO
    jz   .err                            ; an all-zero id is never a token
    mov  rax, [rel ff_snap_id]
    mov  [r15], rax
    mov  rax, [rel ff_snap_id + 8]
    mov  [r15 + 8], rax
    mov  rsi, [r12 + dev.name]
    test rsi, rsi
    jz   .sizes
    xor  ecx, ecx
.name:
    mov  al, [rsi + rcx]
    test al, al
    jz   .sizes
    mov  [r15 + 16 + rcx], al
    inc  ecx
    cmp  ecx, 31
    jb   .name
.sizes:
    mov  rax, [rel ff_snap_class + FFC_DEVBYTES]
    mov  [r15 + 48], rax
    mov  rax, [rel ff_snap_class + FFC_COUNT]
    shl  rax, 9
    mov  [r15 + 56], rax
    mov  al, [rel ff_snap_class + FFC_SCHEME]
    mov  [r15 + 64], al
    mov  al, [rel ff_snap_class + FFC_SLOT]
    mov  [r15 + 65], al
    mov  al, [rel ff_snap_class + FFC_KIND]
    mov  [r15 + 66], al
    mov  al, [rel ff_snap_class + FFC_MBRTYPE]
    mov  [r15 + 67], al
    mov  al, [rel ff_snap_class + FFC_GPTTYPE]
    mov  [r15 + 68], al
    mov  [rel ff_snap_dev], r12
    call time_monotonic_now_us
    mov  [rel ff_snap_time], rax
    mov  byte [rel ff_snap_valid], 1
    xor  eax, eax
    jmp  .out
.err:
    mov  ebx, eax
    call ff_snap_clear
    mov  rdi, r15
    xor  esi, esi
    mov  edx, 96
    call memset
    mov  eax, ebx
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; fs_format_cancel(): memory only, no IO, safe at any time. Wipes the snapshot slot; never custody.
fs_format_cancel:
    jmp  ff_snap_clear

; fs_format_register_decision(RDI=consumer) -> EAX 1 registered / 0 refused. BSP only, nonzero and
; immutable: the same pointer again is accepted, any other refused. The consumer's ABI:
; RDI = 16-byte request id -> EAX 0 valid; it spends its one-use decision on every call.
; F1 registers nothing; F4's card does, after SEC's read. Never sec/adopt_decision's slot.
fs_format_register_decision:
    push rbx
    mov  rbx, rdi
    call smp_current_logical
    test eax, eax
    jnz  .bad
    test rbx, rbx
    jz   .bad
    mov  rax, [rel ff_consumer]
    test rax, rax
    jz   .store
    cmp  rax, rbx
    jne  .bad
.store:
    mov  [rel ff_consumer], rbx
    mov  eax, 1
    pop  rbx
    ret
.bad:
    xor  eax, eax
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; fs_format_begin(RDI=16-byte request id, ESI=filesystem, RDX=label, ECX=label length) -> EAX 0 / FF_E_*.
; In order, on every call:
; 1. the registered consumer with F1's STORED id, never the caller's; spent on every call (DECISION);
; 2. the slot: the caller's id, younger than FF_SNAP_LIFE_US (a clock that ran backwards refuses)
;    (SNAPSHOT); the same owner session token (SESSION); the slot is cleared;
; 3. filesystem 1..4 (FS) and fs_format_label_valid (LABEL);
; 4. a live fs_format_classify of the same extent whose 64 bytes equal the snapshot's (CHANGED, or
;    the classification's own refusal);
; 5. vfs_retire_device(dev, generation): native views end before custody (BUSY);
; 6. custody HELD {dev, generation, tuple, filesystem, label, the request id as token}.
; A refusal at any step writes nothing and leaves no custody.
fs_format_begin:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8
    mov  r12, rdi
    mov  r13d, esi
    mov  r14, rdx
    mov  r15d, ecx
    mov  rax, [rel ff_consumer]          ; first, before any other check: the stored id
    test rax, rax
    jz   .decision
    lea  rdi, [rel ff_snap_id]
    call rax
    test eax, eax
    jnz  .decision
    cmp  byte [rel ff_snap_valid], 1
    jne  .snapshot
    test r12, r12
    jz   .snapshot
    mov  rdi, r12
    lea  rsi, [rel ff_snap_id]
    mov  edx, 16
    call memcmp
    test eax, eax
    jnz  .snapshot
    call time_monotonic_now_us
    sub  rax, [rel ff_snap_time]
    cmp  rax, FF_SNAP_LIFE_US
    jae  .snapshot                       ; also a clock that ran backwards
    call ff_owner_session
    test eax, eax
    jnz  .session
    cmp  rdx, [rel ff_snap_auth]
    jne  .session
    mov  byte [rel ff_snap_valid], 0     ; one use, whatever follows
    call ff_custody_settle
    cmp  byte [rel ff_cust_state], FF_CS_NONE
    jne  .busy
    lea  eax, [r13d - 1]
    cmp  eax, 3
    ja   .fs
    mov  edi, r13d
    mov  rsi, r14
    mov  edx, r15d
    call fs_format_label_valid
    test eax, eax
    jnz  .label
    mov  rbx, [rel ff_snap_dev]
    mov  rdi, rbx
    mov  rsi, [rel ff_snap_class + FFC_FIRST]
    mov  rdx, [rel ff_snap_class + FFC_COUNT]
    lea  rcx, [rel ff_live]
    call fs_format_classify
    test eax, eax
    jnz  .fail
    lea  rdi, [rel ff_live]
    lea  rsi, [rel ff_snap_class]
    mov  edx, FFC_SIZE
    call memcmp
    test eax, eax
    jnz  .changed
    mov  rdi, rbx
    mov  rsi, [rel ff_live + FFC_GEN]
    call vfs_retire_device
    test rax, rax
    js   .busy
    ; custody: copy the tuple, the filesystem, the label and the token
    call ff_custody_clear
    mov  [rel ff_cust + FFK_DEV], rbx
    mov  rax, [rel ff_live + FFC_GEN]
    mov  [rel ff_cust + FFK_GEN], rax
    mov  rax, [rel ff_live + FFC_FIRST]
    mov  [rel ff_cust + FFK_FIRST], rax
    mov  rax, [rel ff_live + FFC_COUNT]
    mov  [rel ff_cust + FFK_COUNT], rax
    mov  al, [rel ff_live + FFC_SCHEME]
    mov  [rel ff_cust + FFK_SCHEME], al
    mov  al, [rel ff_live + FFC_SLOT]
    mov  [rel ff_cust + FFK_SLOT], al
    mov  [rel ff_cust + FFK_FS], r13b
    mov  [rel ff_cust + FFK_LABELLEN], r15b
    mov  rax, [rel ff_snap_id]
    mov  [rel ff_cust + FFK_TOKEN], rax
    mov  rax, [rel ff_snap_id + 8]
    mov  [rel ff_cust + FFK_TOKEN + 8], rax
    lea  rdi, [rel ff_cust + FFK_LABEL]
    mov  rsi, r14
    mov  edx, r15d
    call memcpy
    lea  rdi, [rel ff_cust_class]
    lea  rsi, [rel ff_live]
    mov  edx, FFC_SIZE
    call memcpy
    mov  byte [rel ff_cust_state], FF_CS_HELD
    call ff_snap_clear
    lea  rdi, [rel str_ff_begin]
    mov  esi, -1
    call ff_audit
    xor  eax, eax
    jmp  .out
.decision:  mov  eax, FF_E_DECISION
            jmp  .fail
.snapshot:  mov  eax, FF_E_SNAPSHOT
            jmp  .fail
.session:   mov  eax, FF_E_SESSION
            jmp  .fail
.busy:      mov  eax, FF_E_BUSY
            jmp  .fail
.fs:        mov  eax, FF_E_FS
            jmp  .fail
.label:     mov  eax, FF_E_LABEL
            jmp  .fail
.changed:   mov  eax, FF_E_CHANGED
.fail:
    mov  [rsp], eax
    call ff_snap_clear
    mov  eax, [rsp]
.out:
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; fs_format_custody(RDI=descriptor144) -> EAX 0 / -1. VM 108218 (2): F2 calls it right after the format
; lease's 144-byte snapshot; 0 only while custody is HELD for exactly that incarnation and extent: dev +0,
; media generation +8, first +16, count +24, scheme u32 +136 (F2's grant enum: custody's native scheme
; through guest_volume_format_scheme, SEC C8's one translation site; never a second table here), one-based
; slot u32 +140, and the identity fields rc-ai fills: MBR: +32 the disk-signature dword, +36..+63 zero;
; GPT: +32 the disk GUID, +48 the unique partition GUID. Read-only.
fs_format_custody:
    cmp  byte [rel ff_cust_state], FF_CS_HELD
    jne  .bad
    test rdi, rdi
    jz   .bad
    push rdi
    movzx edi, byte [rel ff_cust + FFK_SCHEME]
    call guest_volume_format_scheme      ; RAX only
    pop  rdi
    cmp  rax, -1
    je   .bad
    cmp  [rdi + 136], eax
    jne  .bad
    mov  rax, [rdi]
    cmp  rax, [rel ff_cust + FFK_DEV]
    jne  .bad
    mov  rax, [rdi + 8]
    cmp  rax, [rel ff_cust + FFK_GEN]
    jne  .bad
    mov  rax, [rdi + 16]
    cmp  rax, [rel ff_cust + FFK_FIRST]
    jne  .bad
    mov  rax, [rdi + 24]
    cmp  rax, [rel ff_cust + FFK_COUNT]
    jne  .bad
    movzx eax, byte [rel ff_cust + FFK_SLOT]
    cmp  [rdi + 140], eax
    jne  .bad
    cmp  byte [rel ff_cust + FFK_SCHEME], FF_SCHEME_GPT
    je   .gpt
    mov  eax, [rel ff_cust_class + FFC_MBRSIG]
    cmp  [rdi + 32], eax
    jne  .bad
    mov  eax, [rdi + 36]
    or   rax, [rdi + 40]
    or   rax, [rdi + 48]
    or   rax, [rdi + 56]
    jnz  .bad
    xor  eax, eax
    ret
.gpt:
    mov  rax, [rdi + 32]
    cmp  rax, [rel ff_cust_class + FFC_GPTDISK]
    jne  .bad
    mov  rax, [rdi + 40]
    cmp  rax, [rel ff_cust_class + FFC_GPTDISK + 8]
    jne  .bad
    mov  rax, [rdi + 48]
    cmp  rax, [rel ff_cust_class + FFC_PARTGUID]
    jne  .bad
    mov  rax, [rdi + 56]
    cmp  rax, [rel ff_cust_class + FFC_PARTGUID + 8]
    jne  .bad
    xor  eax, eax
    ret
.bad:
    mov  eax, -1
    ret

; fs_format_bind_start(RDI=16-byte token) -> EAX 0 / -1. F2's kind-2 fsg_begin calls it once: the token
; must equal custody's, and the first success is the only one. A refusal changes nothing.
fs_format_bind_start:
    cmp  byte [rel ff_cust_state], FF_CS_HELD
    jne  .bad
    cmp  byte [rel ff_cust_bound], 0
    jne  .bad
    test rdi, rdi
    jz   .bad
    mov  rax, [rdi]
    cmp  rax, [rel ff_cust + FFK_TOKEN]
    jne  .bad
    mov  rax, [rdi + 8]
    cmp  rax, [rel ff_cust + FFK_TOKEN + 8]
    jne  .bad
    mov  byte [rel ff_cust_bound], 1
    xor  eax, eax
    ret
.bad:
    mov  eax, -1
    ret

; ---------------------------------------------------------------------------
; fs_format_end(EDI=transport, RSI=out64) -> EAX FF_R_* / -1 (no custody; out zeroed).
; transport: FF_T_CLEAN (fsg_retire 0 and FINISH done), FF_T_UNCERTAIN, FF_T_FAULT (fault, unplug,
; deadline), FF_T_NOT_STARTED (cancel before dispatch / no transport).
; - the incarnation is gone (deregistered or a new generation), or FF_T_FAULT: QUARANTINE; custody
;   stays QUARANTINED until the device leaves (ff_custody_settle). No remount, no credit.
; - FF_T_NOT_STARTED: NOT_STARTED if no START was bound, else UNCERTAIN; custody released.
; - otherwise a live re-probe: the same classification tuple (scheme, slot, first, count, MBR type
;   and signature, GPT disk), then the kind at the extent and, where native-cheap (FAT32 BPB, ext4
;   superblock), the label. DONE only for FF_T_CLEAN with every field equal; else UNCERTAIN.
; Out: +0 outcome, +1 detected kind, +2 label verified (1) / unverified (0), +3 0, +4 label[16],
; +24 first, +32 count, +40 scheme, +41 slot.
fs_format_end:
    push rbx
    push r12
    push r13
    mov  ebx, edi
    mov  r12, rsi
    mov  rdi, rsi
    xor  esi, esi
    mov  edx, 64
    call memset
    cmp  byte [rel ff_cust_state], FF_CS_HELD
    jne  .none
    mov  rax, [rel ff_cust + FFK_FIRST]
    mov  [r12 + 24], rax
    mov  rax, [rel ff_cust + FFK_COUNT]
    mov  [r12 + 32], rax
    mov  al, [rel ff_cust + FFK_SCHEME]
    mov  [r12 + 40], al
    mov  al, [rel ff_cust + FFK_SLOT]
    mov  [r12 + 41], al
    cmp  ebx, FF_T_FAULT
    je   .quarantine
    mov  rdi, [rel ff_cust + FFK_DEV]
    mov  rsi, [rel ff_cust + FFK_GEN]
    call ff_member_gen
    test eax, eax
    jnz  .quarantine
    cmp  ebx, FF_T_NOT_STARTED
    jne  .probe
    mov  r13d, FF_R_NOT_STARTED
    cmp  byte [rel ff_cust_bound], 0
    je   .release
    mov  r13d, FF_R_UNCERTAIN            ; a START was bound: the guest may have written
    jmp  .release
.probe:
    mov  r13d, FF_R_UNCERTAIN
    cmp  ebx, FF_T_CLEAN
    jne  .reprobe
    cmp  byte [rel ff_cust_bound], 1
    jne  .reprobe                        ; no START was ever bound: nothing to credit
    mov  r13d, FF_R_DONE
.reprobe:
    mov  rdi, [rel ff_cust + FFK_DEV]
    mov  rsi, [rel ff_cust + FFK_FIRST]
    mov  rdx, [rel ff_cust + FFK_COUNT]
    lea  rcx, [rel ff_live]
    call fs_format_classify
    test eax, eax
    jnz  .uncertain
    ; the table is the guest's to keep, never to change
    mov  rax, [rel ff_live + FFC_FIRST]
    cmp  rax, [rel ff_cust_class + FFC_FIRST]
    jne  .uncertain
    mov  rax, [rel ff_live + FFC_COUNT]
    cmp  rax, [rel ff_cust_class + FFC_COUNT]
    jne  .uncertain
    mov  rax, [rel ff_live + FFC_GEN]
    cmp  rax, [rel ff_cust_class + FFC_GEN]
    jne  .uncertain
    mov  eax, [rel ff_live + FFC_SCHEME]     ; scheme, slot, MBR type (kind byte masked below)
    xor  eax, [rel ff_cust_class + FFC_SCHEME]
    and  eax, 0x00FFFFFF
    jnz  .uncertain
    mov  eax, [rel ff_live + FFC_MBRSIG]
    cmp  eax, [rel ff_cust_class + FFC_MBRSIG]
    jne  .uncertain
    mov  rax, [rel ff_live + FFC_GPTDISK]
    cmp  rax, [rel ff_cust_class + FFC_GPTDISK]
    jne  .uncertain
    mov  rax, [rel ff_live + FFC_GPTDISK + 8]
    cmp  rax, [rel ff_cust_class + FFC_GPTDISK + 8]
    jne  .uncertain
    mov  al, [rel ff_live + FFC_GPTTYPE]
    cmp  al, [rel ff_cust_class + FFC_GPTTYPE]
    jne  .uncertain
    mov  rax, [rel ff_live + FFC_PARTGUID]
    cmp  rax, [rel ff_cust_class + FFC_PARTGUID]
    jne  .uncertain
    mov  rax, [rel ff_live + FFC_PARTGUID + 8]
    cmp  rax, [rel ff_cust_class + FFC_PARTGUID + 8]
    jne  .uncertain
    ; the kind at the extent (ff_vbr / ff_sb hold its sectors from the classification's probe)
    movzx eax, byte [rel ff_live + FFC_KIND]
    mov  [r12 + 1], al
    cmp  al, [rel ff_cust + FFK_FS]
    jne  .uncertain
    cmp  eax, FF_KIND_FAT32
    je   .fat_label
    cmp  eax, FF_KIND_EXT4
    je   .ext_label
    jmp  .settled                        ; exFAT / NTFS: the label stays unverified, never a match
.fat_label:
    lea  rdi, [r12 + 4]
    lea  rsi, [rel ff_vbr + 71]
    mov  edx, 11
    call memcpy
    mov  ecx, 11                         ; the BPB label: the requested one, space-padded to 11
    jmp  .label_cmp
.ext_label:
    lea  rdi, [r12 + 4]
    lea  rsi, [rel ff_sb + 120]
    mov  edx, 16
    call memcpy
    mov  ecx, 16                         ; s_volume_name: the requested one, NUL-padded to 16
.label_cmp:
    movzx edx, byte [rel ff_cust + FFK_LABELLEN]
    lea  r9, [rel ff_cust + FFK_LABEL]   ; no RIP-relative index form
    xor  r8d, r8d
.lc:
    cmp  r8d, ecx
    jae  .label_ok
    movzx eax, byte [r12 + 4 + r8]
    cmp  r8d, edx
    jae  .pad
    cmp  al, [r9 + r8]
    jne  .uncertain
    jmp  .lnext
.pad:
    cmp  ecx, 11
    jne  .pad_nul
    cmp  eax, ' '
    jne  .uncertain
    jmp  .lnext
.pad_nul:
    test eax, eax
    jnz  .uncertain
.lnext:
    inc  r8d
    jmp  .lc
.label_ok:
    mov  byte [r12 + 2], 1
    jmp  .settled
.uncertain:
    mov  r13d, FF_R_UNCERTAIN
.settled:
.release:
    mov  [r12], r13b
    lea  rdi, [rel str_ff_end]
    mov  esi, r13d
    call ff_audit
    call ff_custody_clear
    mov  eax, r13d
    jmp  .out
.quarantine:
    mov  byte [r12], FF_R_QUARANTINE
    mov  byte [rel ff_cust_state], FF_CS_QUAR
    lea  rdi, [rel str_ff_end]
    mov  esi, FF_R_QUARANTINE
    call ff_audit
    mov  eax, FF_R_QUARANTINE
    jmp  .out
.none:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; fs_format_mount_allowed(RDI=fs_ops, RSI=mount context) -> RAX 0 allowed / -1. vfs_register_mount and
; vfs_mount_ptr ask it after guest_volume_mount_allowed (SEC 108221 C1, C7). No custody: allowed. Else the
; backend's device is named exactly as owned_media and guest_volume name it: RAM volumes and the guest
; lease's own copy service carry none; NTFS is nt_dev; every FAT/ext/exFAT context (fat32_disk, ro,
; selected, scratch, DATA, guest source, ext, exFAT) begins with its dev*. An unknown backend refuses
; while any custody exists. That device refuses, HELD or QUARANTINED, for custody's own media generation
; only: a new medium in the same slot is a different incarnation (SEC-F1-1), and custody verification
; still refuses it by generation. No IO; only RAX changes.
fs_format_mount_allowed:
    cmp  byte [rel ff_cust_state], FF_CS_NONE
    jne  .custody
    xor  eax, eax
    ret
.custody:
    push rdx
    lea  rax, [rel vfs_copy_service_ops]
    cmp  rdi, rax
    je   .yes
    lea  rax, [rel fat32_ops]
    cmp  rdi, rax
    je   .yes
    lea  rax, [rel exfat_ops]
    cmp  rdi, rax
    je   .yes
    lea  rax, [rel vfs_kat_ops]
    cmp  rdi, rax
    je   .yes
    lea  rax, [rel nt_ops]
    cmp  rdi, rax
    jne  .ctx_ops
    mov  rdx, [rel nt_dev]
    jmp  .dev
.ctx_ops:
    lea  rax, [rel fat32_disk_ops]
    cmp  rdi, rax
    je   .ctx
    lea  rax, [rel fd_ro_ops]
    cmp  rdi, rax
    je   .ctx
    lea  rax, [rel fd_selected_ops]
    cmp  rdi, rax
    je   .ctx
    lea  rax, [rel fd_scratch_ops]
    cmp  rdi, rax
    je   .ctx
    lea  rax, [rel fd_data_ops]
    cmp  rdi, rax
    je   .ctx
    lea  rax, [rel fd_guest_ops]
    cmp  rdi, rax
    je   .ctx
    lea  rax, [rel fd_gesp_ops]
    cmp  rdi, rax
    je   .ctx
    lea  rax, [rel ext_ops]
    cmp  rdi, rax
    je   .ctx
    lea  rax, [rel exf_ops]
    cmp  rdi, rax
    jne  .no
.ctx:
    test rsi, rsi
    jz   .no
    mov  rdx, [rsi]
.dev:
    test rdx, rdx
    jz   .yes                            ; no device: nothing of custody's
    cmp  rdx, [rel ff_cust + FFK_DEV]
    jne  .yes
    mov  rax, [rdx + dev.info]
    test rax, rax
    jz   .no
    mov  rax, [rax + blk_info.media_generation]
    cmp  rax, [rel ff_cust + FFK_GEN]
    jne  .yes
.no:
    pop  rdx
    mov  rax, -1
    ret
.yes:
    pop  rdx
    xor  eax, eax
    ret

; ff_audit(RDI=event cstr, ESI=outcome or -1): one serial line from custody (SEC C5): device name, scheme,
; slot, filesystem and the outcome. Never the label, the request id or a disk identity.
ff_audit:
    push rbx
    push r12
    sub  rsp, 8
    mov  ebx, esi
    mov  r12, rdi
    lea  rdi, [rel str_ff_prefix]
    call serial_string
    mov  rdi, r12
    call serial_string
    lea  rdi, [rel str_ff_dev]
    call serial_string
    lea  rdi, [rel str_ff_unknown]
    mov  rax, [rel ff_cust + FFK_DEV]
    test rax, rax
    jz   .name
    mov  rax, [rax + dev.name]
    test rax, rax
    jz   .name
    mov  rdi, rax
.name:
    call serial_string
    lea  rdi, [rel str_ff_scheme]
    call serial_string
    lea  rdi, [rel str_ff_mbr]
    cmp  byte [rel ff_cust + FFK_SCHEME], FF_SCHEME_GPT
    jne  .scheme
    lea  rdi, [rel str_ff_gpt]
.scheme:
    call serial_string
    lea  rdi, [rel str_ff_slot]
    call serial_string
    movzx edi, byte [rel ff_cust + FFK_SLOT]
    call serial_hex64
    lea  rdi, [rel str_ff_fs]
    call serial_string
    movzx eax, byte [rel ff_cust + FFK_FS]
    lea  rdi, [rel ff_kind_names]
    shl  eax, 3
    add  rdi, rax
    call serial_string
    test ebx, ebx
    js   .eol
    lea  rdi, [rel str_ff_outcome]
    call serial_string
    lea  rdi, [rel ff_outcome_names]
    shl  ebx, 4
    add  rdi, rbx
    call serial_string
.eol:
    call serial_newline
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; fs_format_state() -> EAX custody state (0 none, 1 held, 2 quarantined) | bound << 8. No IO.
fs_format_state:
    movzx eax, byte [rel ff_cust_bound]
    shl  eax, 8
    or   al, [rel ff_cust_state]
    ret

%include "core/abi/wdata.inc"
%macro WDATA_fs_format_0 0
ff_mbr_types:  db 0x01, 0x04, 0x06, 0x07, 0x0B, 0x0C, 0x0E, 0x83, 0
align 8
ff_guid_basic: db 0xA2,0xA0,0xD0,0xEB,0xE5,0xB9,0x33,0x44,0x87,0xC0,0x68,0xB6,0xB7,0x26,0x99,0xC7
ff_guid_linux: db 0xAF,0x3D,0xC6,0x0F,0x83,0x84,0x72,0x47,0x8E,0x79,0x3D,0x69,0xD8,0x47,0x7D,0xE4
ff_consumer:   dq 0
str_ff_prefix: db "[fs.format] ",0
str_ff_begin:  db "begin",0
str_ff_end:    db "end",0
str_ff_dev:    db " dev=",0
str_ff_unknown: db "unknown",0
str_ff_scheme: db " scheme=",0
str_ff_mbr:    db "mbr",0
str_ff_gpt:    db "gpt",0
str_ff_slot:   db " slot=",0
str_ff_fs:     db " fs=",0
str_ff_outcome: db " outcome=",0
ff_kind_names: db "unknown",0, "fat32",0,0,0, "exfat",0,0,0, "ntfs",0,0,0,0, "ext4",0,0,0,0
ff_outcome_names: db "DONE",0,0,0,0,0,0,0,0,0,0,0,0, "UNCERTAIN",0,0,0,0,0,0,0
                  db "QUARANTINE",0,0,0,0,0,0, "NOT_STARTED",0,0,0,0,0
%endmacro
WDATA_DEFER WDATA_fs_format_0
%macro WDATA_BSS_fs_format 0
alignb 8
ff_snap_class: resb FFC_SIZE             ; ff_snap_class then ff_snap_id: ff_snap_clear
ff_snap_id:    resb 16
ff_snap_dev:   resq 1
ff_snap_time:  resq 1
ff_snap_auth:  resq 1
ff_live:       resb FFC_SIZE
ff_cust:       resb FFK_SIZE
ff_cust_class: resb FFC_SIZE
ff_prim:       resb 48
ff_gpt_entry:  resq 1
ff_gpt_n:      resd 1
ff_snap_valid: resb 1
ff_cust_state: resb 1
ff_cust_bound: resb 1
alignb 16
ff_sec:        resb 512
ff_hdr:        resb 512
ff_vbr:        resb 512
ff_sb:         resb 512
ff_arr:        resb FF_GPT_MAX * 128
%endmacro
WDATA_BSS_DEFER WDATA_BSS_fs_format
