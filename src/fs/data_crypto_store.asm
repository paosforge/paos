;; MODULE fs/data_crypto_store
;; LAYER 4
;; EXPORTS data_crypto_block_read, data_crypto_block_write, data_crypto_write_permitted, data_crypto_block_name, data_crypto_fallback_boot_probe, data_crypto_boot_migrate, data_crypto_backend, data_crypto_backend_is_nvram
;; IMPORTS fs/blockdev, fs/storage_access, fs/fat32_disk, data/crypto_envelope, core/lib/crc32, core/lib/sha256, core/lib/mem, boot/nvram_access, boot/boot_v2_health, boot/boot_v2_handoff, boot/header, boot/serial
;; CAPS
;; OWNER saga:sec
; ============================================================================
; Contract-1054's bounded block-layer seam.  The L5 command projection can only
; submit complete authenticated-envelope records for the two slots (PRIMARY /
; TMP, historically GPT-gap LBAs 0x700/0x708); plaintext is never an argument
; to either function.  Legacy device selection is inherited from fs/fat32_disk's
; content-selected physical DATA volume (the Lenovo DATA disk is AHCI).  The
; desktop-session owner uses bytes 0..343 of those raw sectors; the record owns
; bytes 344..511.  Callers serialize through fs/blockdev's persist_gap_lock.
;
; PaOS-OWNED STORAGE (PETER RULING 2026-09-30 06:22 "Storage"): the owner DATA
; record no longer lives in another OS's raw GPT gap.  Its home is the PaOS-
; namespace UEFI variable PaOSDataRecord (NORMAL NVRAM class, boot/nvram_access).
; The two slots keep their identity (PRIMARY = "LBA 0x700", TMP = "LBA 0x708")
; so fs/safe_write's TMP->PRIMARY transaction, the envelope bytes and every
; authentication/integrity rule are unchanged; only the medium moved.
;
;   PaOSDataRecord (vendor 7268a9b4-3f8a-45a0-9f8d-1b73e9ac1054, NV|BS|RT, 380 B)
;     +0   PRIMARY record (168 B; bit-exact copy of gap LBA 0x700 bytes 344..511)
;     +168 TMP record     (168 B; bit-exact copy of gap LBA 0x708 bytes 344..511)
;     +336 gap baseline SHA-256 over the two gap tails at the last sync (32 B)
;     +368 magic 'PDR1'   +372 flags (bit0 = baseline observed)   +376 CRC32 [0..376)
;
; Backend resolution (once per boot, under persist_gap_lock):
;   runtime NVRAM available (mutable Boot-v2 Manager launch):
;     variable absent + gap tails hold data  -> READ-AND-COPY migration: one
;         SetVariable + exact GetVariable readback; the gap is only READ, never
;         written or erased ([storage.data.migrated]).
;     variable present, baseline observed, gap tails changed since that sync
;         -> only an older payload (rollback, e.g. 0.0.43) can have written the
;         gap after the copy; it is the newest writer, so re-copy it
;         ([storage.data.resynced]) - last-writer-wins survives A/B flips.
;     otherwise the variable is authoritative; an absent variable is created by
;         the first explicit DATA write.
;   no runtime NVRAM this boot: a QEMU test-scratch DATA device (no GPT) keeps
;     the legacy raw slots behind the storage gate with IMPLICIT intent (never a
;     real GPT gap); anything else is fail-closed unavailable.
; ============================================================================

DCB_LBA_PRIMARY equ PERSIST_GAP_LBA_PRIMARY  ; fs/blockdev reservation
DCB_LBA_TMP     equ PERSIST_GAP_LBA_TMP
DCB_SECTOR_SIZE equ 512
DCB_RECORD_OFF  equ 344
DCB_RECORD_SIZE equ 168
DCB_GPT_SIGNATURE equ 0x5452415020494645    ; "EFI PART"
DCB_GPT_HEADER_MIN equ 92
DCB_GPT_ENTRY_SIZE equ 128
DCB_GPT_ENTRY_CAP equ 128
DCB_BACKEND_NONE        equ 0
DCB_BACKEND_NVRAM       equ 1
DCB_BACKEND_SCRATCH     equ 2
DCB_BACKEND_UNAVAILABLE equ 3
DCB_NV_SLOT_P    equ 0
DCB_NV_SLOT_T    equ DCB_RECORD_SIZE
DCB_NV_TAILS     equ 2 * DCB_RECORD_SIZE          ; 336
DCB_NV_DIGEST    equ DCB_NV_TAILS
DCB_NV_MAGIC_OFF equ DCB_NV_DIGEST + 32           ; 368
DCB_NV_FLAGS     equ DCB_NV_MAGIC_OFF + 4         ; 372
DCB_NV_CRC       equ DCB_NV_FLAGS + 4             ; 376
DCB_NV_SIZE      equ DCB_NV_CRC + 4               ; 380
DCB_NV_MAGIC     equ 0x31524450                   ; 'PDR1'
DCB_NV_F_BASELINE equ 1
DCB_NV_ATTRS     equ 7                            ; NV | BOOTSERVICE | RUNTIME
DCB_EFI_NOT_FOUND equ 0x800000000000000E
DCB_GAP_OK       equ 0
DCB_GAP_NODEV    equ 1
DCB_GAP_IOERR    equ -1

%if DCB_RECORD_OFF + DCB_RECORD_SIZE != DCB_SECTOR_SIZE
    %error "data-crypto record must exactly fill the reserved sector tail"
%endif

; dcb_selected_dev() -> RAX=the physical device whose FAT32 DATA volume was
; selected by live on-media discovery, or 0.  The historical marker-selected
; DATA path remains unchanged.  A no-marker system-disk fallback is writable
; only after dcb_fallback_prove establishes the deliberately narrow Dell-safe
; case: exactly one AHCI/NVMe device, 512-byte logical sectors, CRC-valid GPT,
; a unique selected ESP-type entry, no earlier discovery IO error,
; both reserved LBAs outside every partition, and tails that are zero or a
; structurally valid PaOS DSE2 record.  Any ambiguity is denied for the boot.
dcb_selected_dev:
    mov  rax, [rel fat32_disk_selected_dev]
    test rax, rax
    jz   .none
    cmp  dword [rax + dev.health], HEALTH_OK
    jne  .none
    cmp  byte [rel fat32_disk_selection_reason], FD_SELECT_MARKER
    je   .found
    cmp  byte [rel fat32_disk_selection_reason], FD_SELECT_FALLBACK
    jne  .none
    cmp  byte [rel dcb_fallback_state], 1
    jne  .prove
    cmp  [rel dcb_fallback_dev], rax
    jne  .none
.found:
    ret
.prove:
    ; State 2 is both a permanent refusal and the in-progress value.  A racing
    ; caller therefore fails closed; the boot-local proof is never duplicated.
    cmp  byte [rel dcb_fallback_state], 0
    jne  .none
    mov  byte [rel dcb_fallback_state], 2
    push rbx
    mov  rbx, rax
    mov  rdi, rax
    call dcb_fallback_prove
    test eax, eax
    jz   .prove_fail
    mov  [rel dcb_fallback_dev], rbx
    mov  byte [rel dcb_fallback_state], 1
    mov  rax, rbx
    pop  rbx
    ret
.prove_fail:
    pop  rbx
.none:
    xor  eax, eax
    ret

; data_crypto_fallback_boot_probe() -> EAX=1 when fallback proof succeeds, -1
; when a live fallback is refused, and 0 when selection is not a fallback. This
; is an observation seam for QEMU fixtures; it grants no write by itself.
data_crypto_fallback_boot_probe:
    cmp  byte [rel fat32_disk_selection_reason], FD_SELECT_FALLBACK
    jne  .not_fallback
    call dcb_selected_dev
    test rax, rax
    jz   .refused
    mov  eax, 1
    ret
.refused:
    mov  eax, -1
    ret
.not_fallback:
    xor  eax, eax
    ret

; dcb_physical_unique(RDI=selected dev*) -> EAX=1 iff the selected handle is
; the one and only healthy physical AHCI/NVMe registry member.  A second device,
; a foreign fallback, or an empty registry refuses the system-disk exception.
dcb_physical_unique:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    xor  r13d, r13d                       ; unique handle found
    xor  ebx, ebx                         ; phase 0=ahci, 1=nvme
    xor  r14d, r14d                       ; previous handle
.next:
    lea  rdi, [rel dcb_ahci_prefix]
    test ebx, ebx
    jz   .prefix
    lea  rdi, [rel dcb_nvme_prefix]
.prefix:
    mov  esi, 4
    mov  rdx, r14
    call blk_find_prefix_after
    test rax, rax
    jz   .prefix_done
    test r13, r13
    jnz  .no                              ; multiple physical devices
    mov  r13, rax
    mov  r14, rax
    jmp  .next
.prefix_done:
    test ebx, ebx
    jnz  .compare
    mov  ebx, 1
    xor  r14d, r14d
    jmp  .next
.compare:
    xor  eax, eax
    test r13, r13
    jz   .out
    cmp  r13, r12
    jne  .out
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; dcb_crc32_update(EAX=raw crc, RDI=bytes, ECX=len) -> EAX=raw crc.
; This incremental IEEE primitive lets the bounded GPT-entry scan validate the
; array CRC one sector at a time without adding a layout-sensitive 16KiB buffer.
dcb_crc32_update:
    test ecx, ecx
    jz   .done
.byte:
    movzx edx, byte [rdi]
    xor  eax, edx
    mov  edx, 8
.bit:
    mov  esi, eax
    and  esi, 1
    neg  esi
    and  esi, 0xEDB88320
    shr  eax, 1
    xor  eax, esi
    dec  edx
    jnz  .bit
    inc  rdi
    dec  ecx
    jnz  .byte
.done:
    ret

; dcb_tail_owned(RDI=sector512) -> EAX=1 iff the 168-byte owned tail is all
; zero or has the structural DSE2 header. Authentication remains mandatory in
; safe_write before any existing record is trusted or replaced.
dcb_tail_owned:
    lea  rdx, [rdi + DCB_RECORD_OFF]
    mov  rdi, rdx
    mov  ecx, DCB_RECORD_SIZE
.zero_scan:
    cmp  byte [rdi], 0
    jne  .record
    inc  rdi
    dec  ecx
    jnz  .zero_scan
    mov  eax, 1
    ret
.record:
    mov  rdi, rdx
    jmp  data_crypto_record_valid

; dcb_fallback_prove(RDI=selected dev*) -> EAX=1/0.
; The proof is read-only.  Stack locals retain media facts across blk_read calls:
;   +0 entries LBA, +8 selected start, +16 selected end,
;   +24 first usable, +32 last usable,
;   +40 entry count, +44 entry bytes, +48 entry CRC, +52 running raw CRC,
;   +56 entry sectors.
dcb_fallback_prove:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 64
    mov  rbx, rdi
    call dcb_physical_unique
    test eax, eax
    jz   .fail
    mov  rax, [rbx + dev.info]
    test rax, rax
    jz   .fail
    cmp  dword [rax + blk_info.sector_size], DCB_SECTOR_SIZE
    jne  .fail
    mov  rcx, [rax + blk_info.capabilities]
    test rcx, rcx
    jz   .legacy_geometry
    cmp  dword [rax + blk_info.logical_sector_bytes], DCB_SECTOR_SIZE
    jne  .fail
.legacy_geometry:
    mov  r15, [rax + blk_info.lba_max]
    cmp  qword [rel fat32_disk_ctx + FD_DEV], rbx
    jne  .fail
    cmp  byte [rel fat32_disk_ctx + FD_SCAN_ERR], 0
    jne  .fail
    mov  rax, [rel fat32_disk_ctx + FD_PART_LBA]
    cmp  rax, DCB_LBA_TMP
    jbe  .fail
    mov  [rsp + 8], rax
    mov  rcx, [rel fat32_disk_ctx + FD_PART_SECTORS]
    test rcx, rcx
    jz   .fail
    dec  rcx
    add  rcx, rax
    jc   .fail
    cmp  rcx, r15
    ja   .fail
    mov  [rsp + 16], rcx

    ; Require a protective MBR before interpreting LBA1 as GPT.
    mov  rdi, rbx
    xor  esi, esi
    mov  edx, 1
    lea  rcx, [rel dcb_sector]
    call blk_read
    test eax, eax
    jnz  .fail
    cmp  word [rel dcb_sector + 510], 0xAA55
    jne  .fail
    lea  rdx, [rel dcb_sector + 446]
    xor  ebp, ebp
.mbr_scan:
    cmp  byte [rdx + rbp + 4], 0xEE
    je   .mbr_ok
    add  ebp, 16
    cmp  ebp, 64
    jb   .mbr_scan
    jmp  .fail
.mbr_ok:
    mov  rdi, rbx
    mov  esi, 1
    mov  edx, 1
    lea  rcx, [rel dcb_gpt_header]
    call blk_read
    test eax, eax
    jnz  .fail
    mov  rax, DCB_GPT_SIGNATURE
    cmp  [rel dcb_gpt_header], rax
    jne  .fail
    cmp  dword [rel dcb_gpt_header + 8], 0x00010000
    jne  .fail
    mov  r13d, [rel dcb_gpt_header + 12]
    cmp  r13d, DCB_GPT_HEADER_MIN
    jb   .fail
    cmp  r13d, DCB_SECTOR_SIZE
    ja   .fail
    mov  r14d, [rel dcb_gpt_header + 16]
    mov  dword [rel dcb_gpt_header + 16], 0
    lea  rdi, [rel dcb_gpt_header]
    mov  esi, r13d
    call hotpatch_crc32
    mov  [rel dcb_gpt_header + 16], r14d
    cmp  eax, r14d
    jne  .fail
    cmp  qword [rel dcb_gpt_header + 24], 1
    jne  .fail
    mov  rax, [rel dcb_gpt_header + 32]
    cmp  rax, 1
    jbe  .fail
    cmp  rax, r15
    ja   .fail
    mov  rax, [rel dcb_gpt_header + 40]
    mov  rcx, [rel dcb_gpt_header + 48]
    cmp  rcx, rax
    jb   .fail
    cmp  rax, DCB_LBA_PRIMARY
    ja   .fail
    cmp  rcx, DCB_LBA_TMP
    jb   .fail
    cmp  rcx, r15
    ja   .fail
    mov  [rsp + 24], rax
    mov  [rsp + 32], rcx
    mov  rax, [rel dcb_gpt_header + 56]
    or   rax, [rel dcb_gpt_header + 64]
    jz   .fail
    mov  rax, [rel dcb_gpt_header + 72]
    cmp  rax, 2
    jb   .fail
    cmp  rax, r15
    ja   .fail
    mov  [rsp], rax
    mov  eax, [rel dcb_gpt_header + 80]
    test eax, eax
    jz   .fail
    cmp  eax, DCB_GPT_ENTRY_CAP
    ja   .fail
    mov  [rsp + 40], eax
    cmp  dword [rel dcb_gpt_header + 84], DCB_GPT_ENTRY_SIZE
    jne  .fail
    shl  eax, 7
    mov  [rsp + 44], eax
    mov  eax, [rel dcb_gpt_header + 88]
    mov  [rsp + 48], eax
    mov  eax, [rsp + 44]
    add  eax, DCB_SECTOR_SIZE - 1
    jc   .fail
    shr  eax, 9
    mov  [rsp + 56], eax
    mov  ecx, eax
    dec  rcx
    add  rcx, [rsp]
    jc   .fail
    cmp  rcx, r15
    ja   .fail

    mov  dword [rsp + 52], 0xFFFFFFFF
    xor  r12d, r12d                       ; sector index
    xor  r13d, r13d                       ; global entry index
    xor  r14d, r14d                       ; selected partition entry found
.entry_sector:
    cmp  r12d, [rsp + 56]
    jae  .entries_done
    mov  rsi, [rsp]
    add  rsi, r12
    mov  rdi, rbx
    mov  edx, 1
    lea  rcx, [rel dcb_sector]
    call blk_read
    test eax, eax
    jnz  .fail
    mov  eax, [rsp + 44]
    mov  ecx, r12d
    shl  ecx, 9
    sub  eax, ecx
    cmp  eax, DCB_SECTOR_SIZE
    jbe  .crc_len
    mov  eax, DCB_SECTOR_SIZE
.crc_len:
    mov  ecx, eax
    mov  eax, [rsp + 52]
    lea  rdi, [rel dcb_sector]
    call dcb_crc32_update
    mov  [rsp + 52], eax
    xor  r15d, r15d                       ; entry slot within sector
.entry_in_sector:
    cmp  r15d, 4
    jae  .next_entry_sector
    cmp  r13d, [rsp + 40]
    jae  .next_entry_sector
    mov  eax, r15d
    shl  eax, 7
    lea  rdx, [rel dcb_sector]
    add  rdx, rax
    mov  rax, [rdx]
    or   rax, [rdx + 8]
    jz   .entry_next
    mov  rax, [rdx + 32]
    mov  rcx, [rdx + 40]
    cmp  rcx, rax
    jb   .fail
    cmp  rax, [rsp + 24]
    jb   .fail
    cmp  rcx, [rsp + 32]
    ja   .fail
    cmp  rax, DCB_LBA_PRIMARY
    ja   .check_tmp
    cmp  rcx, DCB_LBA_PRIMARY
    jae  .fail
.check_tmp:
    cmp  rax, DCB_LBA_TMP
    ja   .check_selected
    cmp  rcx, DCB_LBA_TMP
    jae  .fail
.check_selected:
    cmp  rax, [rsp + 8]
    jne  .entry_next
    cmp  rcx, [rsp + 16]
    jne  .fail
    test r14d, r14d
    jnz  .fail                            ; duplicate selected start is ambiguous
    mov  rax, FD_ESP_GUID_LO
    cmp  [rdx], rax
    jne  .fail
    mov  rax, FD_ESP_GUID_HI
    cmp  [rdx + 8], rax
    jne  .fail
    mov  r14d, 1
.entry_next:
    inc  r13d
    inc  r15d
    jmp  .entry_in_sector
.next_entry_sector:
    inc  r12d
    jmp  .entry_sector
.entries_done:
    test r14d, r14d
    jz   .fail
    mov  eax, [rsp + 52]
    not  eax
    cmp  eax, [rsp + 48]
    jne  .fail

    mov  rdi, rbx
    mov  esi, DCB_LBA_PRIMARY
    mov  edx, 1
    lea  rcx, [rel dcb_sector]
    call blk_read
    test eax, eax
    jnz  .fail
    lea  rdi, [rel dcb_sector]
    call dcb_tail_owned
    test eax, eax
    jz   .fail
    mov  rdi, rbx
    mov  esi, DCB_LBA_TMP
    mov  edx, 1
    lea  rcx, [rel dcb_sector]
    call blk_read
    test eax, eax
    jnz  .fail
    lea  rdi, [rel dcb_sector]
    call dcb_tail_owned
    test eax, eax
    jz   .fail
    mov  eax, 1
    jmp  .out
.fail:
    xor  eax, eax
.out:
    add  rsp, 64
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; data_crypto_block_name() -> RAX=exact backend identity / 0.  DSECPUT emits this
; measured identity: the registry name of the legacy scratch device, or the
; PaOS-owned NVRAM variable once the record lives there.
data_crypto_block_name:
    call dcb_resolve
    cmp  eax, DCB_BACKEND_NVRAM
    je   .nvram
    cmp  eax, DCB_BACKEND_SCRATCH
    jne  .none
    call dcb_selected_dev
    test rax, rax
    jz   .none
    mov  rax, [rax + dev.name]
    ret
.nvram:
    lea  rax, [rel str_dcb_nv_backend]
    ret
.none:
    xor  eax, eax
    ret

; data_crypto_backend() -> EAX=DCB_BACKEND_* (resolving it once if needed).
data_crypto_backend:
    jmp  dcb_resolve

; data_crypto_backend_is_nvram() -> EAX=1 when the record lives in PaOSDataRecord.
data_crypto_backend_is_nvram:
    call dcb_resolve
    cmp  eax, DCB_BACKEND_NVRAM
    sete al
    movzx eax, al
    ret

; dcb_lba_allowed(RDI=lba) -> EAX=1/0.
dcb_lba_allowed:
    cmp  rdi, DCB_LBA_PRIMARY
    je   .yes
    cmp  rdi, DCB_LBA_TMP
    je   .yes
    xor  eax, eax
    ret
.yes:
    mov  eax, 1
    ret

; dcb_slot_ptr(RDI=lba, RSI=image) -> RAX=&image[slot] (lba already validated).
dcb_slot_ptr:
    lea  rax, [rsi + DCB_NV_SLOT_P]
    cmp  rdi, DCB_LBA_PRIMARY
    je   .out
    lea  rax, [rsi + DCB_NV_SLOT_T]
.out:
    ret

; data_crypto_block_read(RDI=lba,RSI=sector512) -> 0/-1.
; Caller holds persist_gap_lock (every fs/safe_write path does).  In the NVRAM
; backend the "sector" is a virtual slot view: bytes 0..343 are zero (the raw
; session-manifest prefix is not part of the DATA record) and bytes 344..511
; are the slot's exact record bytes.
data_crypto_block_read:
    push rbx
    push r12
    mov  r12, rdi
    mov  rbx, rsi
    test rbx, rbx
    jz   .fail
    call dcb_lba_allowed
    test eax, eax
    jz   .fail
    call dcb_resolve_locked
    cmp  eax, DCB_BACKEND_NVRAM
    je   .nvram
    cmp  eax, DCB_BACKEND_SCRATCH
    jne  .fail
    call dcb_selected_dev
    test rax, rax
    jz   .fail
    mov  rdi, rax
    mov  rsi, r12
    mov  edx, 1
    mov  rcx, rbx
    call blk_read
    test eax, eax
    jnz  .fail
    xor  eax, eax
    jmp  .out
.nvram:
    mov  rdi, rbx
    xor  esi, esi
    mov  edx, DCB_RECORD_OFF
    call memset
    mov  rdi, r12
    lea  rsi, [rel dcb_nv_image]
    call dcb_slot_ptr
    lea  rdi, [rbx + DCB_RECORD_OFF]
    mov  rsi, rax
    mov  edx, DCB_RECORD_SIZE
    call memcpy
    xor  eax, eax
    jmp  .out
.fail:
    mov  eax, -1
.out:
    pop  r12
    pop  rbx
    ret

; data_crypto_block_write(RDI=lba,RSI=sector512) -> 0/-1, durable on success.
; Caller holds persist_gap_lock.  NVRAM backend: only bytes 344..511 (the
; record) are stored; one SetVariable of the whole 2-slot image + exact
; GetVariable readback, and the RAM image advances only after that proof.
; The raw GPT gap is NEVER a target of this function.
data_crypto_block_write:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    test r13, r13
    jz   .fail
    call dcb_lba_allowed
    test eax, eax
    jz   .fail
    call dcb_resolve_locked
    cmp  eax, DCB_BACKEND_NVRAM
    je   .nvram
    cmp  eax, DCB_BACKEND_SCRATCH
    jne  .fail
    call dcb_selected_dev
    test rax, rax
    jz   .fail
    mov  rdi, rax
    mov  rsi, r12
    mov  rdx, r13
    call dcb_scratch_write
    jmp  .out
.nvram:
    lea  rdi, [rel dcb_nv_stage]
    lea  rsi, [rel dcb_nv_image]
    mov  edx, DCB_NV_SIZE
    call memcpy
    mov  rdi, r12
    lea  rsi, [rel dcb_nv_stage]
    call dcb_slot_ptr
    mov  rdi, rax
    lea  rsi, [r13 + DCB_RECORD_OFF]
    mov  edx, DCB_RECORD_SIZE
    call memcpy
    lea  rdi, [rel dcb_nv_stage]
    lea  rsi, [rel str_dcb_nv_caller]
    call dcb_nv_commit
    jmp  .out
.fail:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; dcb_scratch_gate(RDI=dev, RSI=lba) -> RAX 0/-1 (refusal marker from the gate).
; The DATA record's only raw-sector path always asks with the IMPLICIT intent:
; OWNED/TEST_SCRATCH only, whatever authority the request carries.
dcb_scratch_gate:
    mov  edx, 1
    mov  ecx, SA_INTENT_IMPLICIT
    lea  r8, [rel str_dcb_sa_caller]
    jmp  storage_access_require

; dcb_scratch_write(RDI=dev, RSI=lba, RDX=sector512) -> 0/-1.
; Legacy raw slot write, reachable ONLY when no runtime NVRAM exists this boot
; and the DATA device classified TEST_SCRATCH at resolve time (QEMU disk without
; a GPT, or a RAM/null backend).  It asks the storage gate with the IMPLICIT
; intent, which admits only PaOS-owned or test-scratch storage: a real GPT gap is
; refused even for an owner-signed request.
dcb_scratch_write:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rdx
    mov  rdi, rbx
    mov  rsi, r12
    call dcb_scratch_gate
    test rax, rax
    jnz  .fail
    mov  rdi, rbx
    mov  rsi, r12
    mov  edx, 1
    mov  rcx, r13
    call blk_write
    test eax, eax
    jnz  .fail
    mov  rdi, rbx
    call blk_flush
    test eax, eax
    jnz  .fail
    xor  eax, eax
    jmp  .out
.fail:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

align 8
dcb_fallback_dev: dq 0
dcb_fallback_state: db 0                 ; 0=unproved, 1=allowed, 2=denied/busy
dcb_ahci_prefix: db "ahci",0
dcb_nvme_prefix: db "nvme",0
align 8
dcb_gpt_header: times DCB_SECTOR_SIZE db 0
dcb_sector: times DCB_SECTOR_SIZE db 0

; data_crypto_write_permitted() -> RAX 0 if the in-flight context may write the data record now, -1 otherwise
; (no marker; lets idempotent background persisters decide once instead of retrying a refusal every tick).
; The PaOS-owned record is ONE owner slot (last writer wins): a background writer
; (the NTP receipt) must never overwrite owner data implicitly, so the NVRAM
; backend admits only an explicit owner request here.  Scratch keeps its rule.
data_crypto_write_permitted:
    call dcb_resolve
    cmp  eax, DCB_BACKEND_NVRAM
    je   .nvram
    cmp  eax, DCB_BACKEND_SCRATCH
    jne  .no
    call dcb_selected_dev
    test rax, rax
    jz   .no
    mov  rdi, rax
    mov  rsi, DCB_LBA_PRIMARY
    mov  edx, DCB_LBA_TMP - DCB_LBA_PRIMARY + 1
    jmp  storage_access_permitted_request
.nvram:
    call storage_access_request_intent
    cmp  eax, SA_INTENT_SPECIAL
    jne  .no
    xor  eax, eax
    ret
.no:
    mov  rax, -1
    ret
str_dcb_sa_caller: db "data_crypto_record", 0

; ===========================================================================
; PaOS-owned NVRAM backend.
; ===========================================================================

; dcb_resolve() -> EAX=backend.  Acquires persist_gap_lock (callers that do
; not already hold it: boot migration, block_name, write_permitted).
dcb_resolve:
    movzx eax, byte [rel dcb_backend]
    test eax, eax
    jnz  .out
    call persist_gap_lock_acquire
    call dcb_resolve_locked
    push rax
    call persist_gap_lock_release
    pop  rax
.out:
    ret

; data_crypto_boot_migrate() — the boot-time resolution: runs the (read-only
; for the gap) migration/resync once, so the move happens on the first boot of
; this payload rather than on the owner's first DATA verb.  Idempotent.
data_crypto_boot_migrate:
    jmp  dcb_resolve

; dcb_gap_read_tails() -> EAX=DCB_GAP_*.  READ-ONLY: two blk_read calls, the
; tails land in dcb_gap_tails (PRIMARY then TMP) and their SHA-256 in
; dcb_gap_digest.  No write path exists here.
dcb_gap_read_tails:
    push rbx
    call dcb_selected_dev
    test rax, rax
    jz   .nodev
    mov  rbx, rax
    mov  rdi, rbx
    mov  esi, DCB_LBA_PRIMARY
    mov  edx, 1
    lea  rcx, [rel dcb_sector]
    call blk_read
    test eax, eax
    jnz  .io
    lea  rdi, [rel dcb_gap_tails + DCB_NV_SLOT_P]
    lea  rsi, [rel dcb_sector + DCB_RECORD_OFF]
    mov  edx, DCB_RECORD_SIZE
    call memcpy
    mov  rdi, rbx
    mov  esi, DCB_LBA_TMP
    mov  edx, 1
    lea  rcx, [rel dcb_sector]
    call blk_read
    test eax, eax
    jnz  .io
    lea  rdi, [rel dcb_gap_tails + DCB_NV_SLOT_T]
    lea  rsi, [rel dcb_sector + DCB_RECORD_OFF]
    mov  edx, DCB_RECORD_SIZE
    call memcpy
    lea  rdi, [rel dcb_gap_digest]
    lea  rsi, [rel dcb_gap_tails]
    mov  edx, DCB_NV_TAILS
    call dcb_sha256
    test eax, eax
    jnz  .io
    mov  eax, DCB_GAP_OK
    jmp  .out
.nodev:
    mov  eax, DCB_GAP_NODEV
    jmp  .out
.io:
    mov  eax, DCB_GAP_IOERR
.out:
    pop  rbx
    ret

; dcb_sha256(RDI=out32, RSI=data, EDX=len) -> EAX 0/-1 (private context).
dcb_sha256:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13d, edx
    lea  rdi, [rel dcb_sha_ctx]
    call sha256_stream_init
    lea  rdi, [rel dcb_sha_ctx]
    mov  rsi, r12
    mov  edx, r13d
    call sha256_stream_update
    test rax, rax
    jnz  .fail
    lea  rdi, [rel dcb_sha_ctx]
    mov  rsi, rbx
    call sha256_stream_final
    xor  eax, eax
    jmp  .out
.fail:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; dcb_tails_zero(RDI=336-byte tails) -> EAX=1 all zero.
dcb_tails_zero:
    mov  ecx, DCB_NV_TAILS
    xor  eax, eax
.scan:
    or   al, [rdi]
    inc  rdi
    dec  ecx
    jnz  .scan
    test al, al
    setz al
    movzx eax, al
    ret

; dcb_nv_seal(RDI=image) — stamp magic and CRC32 over [0..DCB_NV_CRC).
dcb_nv_seal:
    push rbx
    mov  rbx, rdi
    mov  dword [rbx + DCB_NV_MAGIC_OFF], DCB_NV_MAGIC
    mov  rdi, rbx
    mov  esi, DCB_NV_CRC
    call pbm_crc32
    mov  [rbx + DCB_NV_CRC], eax
    pop  rbx
    ret

; dcb_nv_well_formed(RDI=image) -> EAX=1 magic + CRC valid.
dcb_nv_well_formed:
    push rbx
    mov  rbx, rdi
    cmp  dword [rbx + DCB_NV_MAGIC_OFF], DCB_NV_MAGIC
    jne  .no
    mov  rdi, rbx
    mov  esi, DCB_NV_CRC
    call pbm_crc32
    cmp  eax, [rbx + DCB_NV_CRC]
    jne  .no
    mov  eax, 1
    pop  rbx
    ret
.no:
    xor  eax, eax
    pop  rbx
    ret

; dcb_nv_get() -> EAX 0 read into dcb_nv_verify (exact size/attrs), 1 absent, -1 other.
dcb_nv_get:
    push rbx
    push r12
    push r13
    mov  r13, rsp
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .bad
    mov  qword [rel dcb_nv_io_size], DCB_NV_SIZE
    mov  dword [rel dcb_nv_io_attrs], 0
    lea  rcx, [rel dcb_nv_name]
    lea  rdx, [rel storage_access_nvram_paos_data_guid]
    lea  r8, [rel dcb_nv_io_attrs]
    lea  r9, [rel dcb_nv_io_size]
    and  rsp, -16
    sub  rsp, 48
    lea  rbx, [rel dcb_nv_verify]
    mov  [rsp + 32], rbx
    call [r12 + 0x48]                   ; EFI_RUNTIME_SERVICES.GetVariable
    mov  rsp, r13
    test rax, rax
    jz   .check
    mov  rdx, DCB_EFI_NOT_FOUND
    cmp  rax, rdx
    jne  .bad
    mov  eax, 1
    jmp  .out
.check:
    cmp  dword [rel dcb_nv_io_attrs], DCB_NV_ATTRS
    jne  .bad
    cmp  qword [rel dcb_nv_io_size], DCB_NV_SIZE
    jne  .bad
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; dcb_nv_commit(RDI=stage image, RSI=caller tag) -> EAX 0/-1.
; Seal, ask the storage gate (PaOS-namespace NVRAM: NORMAL), ONE SetVariable,
; exact GetVariable readback; only then does the RAM image become the stage.
dcb_nv_commit:
    push rbx
    push r12
    push r13
    push r14
    mov  r14, rdi
    mov  rbx, rsi
    mov  rdi, r14
    call dcb_nv_seal
    call storage_access_request_intent
    mov  edx, eax
    lea  rdi, [rel storage_access_nvram_paos_data_guid]
    lea  rsi, [rel dcb_nv_name]
    mov  rcx, rbx
    call storage_access_nvram_require
    test rax, rax
    jnz  .fail
    cmp  byte [rel pbm_runtime_code_mapped], 1
    jne  .fail
    mov  r12, [rel runtime_services]
    test r12, r12
    jz   .fail
    mov  r13, rsp
    lea  rcx, [rel dcb_nv_name]
    lea  rdx, [rel storage_access_nvram_paos_data_guid]
    mov  r8d, DCB_NV_ATTRS
    mov  r9d, DCB_NV_SIZE
    and  rsp, -16
    sub  rsp, 48
    mov  [rsp + 32], r14
    call [r12 + 0x58]                   ; EFI_RUNTIME_SERVICES.SetVariable (PaOSDataRecord)
    mov  rsp, r13
    test rax, rax
    jnz  .fail
    call dcb_nv_get
    test eax, eax
    jnz  .fail
    lea  rdi, [rel dcb_nv_verify]
    mov  rsi, r14
    mov  edx, DCB_NV_SIZE
    call memcmp
    test eax, eax
    jnz  .fail
    lea  rdi, [rel dcb_nv_image]
    mov  rsi, r14
    mov  edx, DCB_NV_SIZE
    call memcpy
    mov  byte [rel dcb_nv_present], 1
    xor  eax, eax
    jmp  .out
.fail:
    lea  rdi, [rel str_dcb_nv_commit_failed]
    call serial_string
    mov  eax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; dcb_stage_from_gap() — dcb_nv_stage := gap tails || gap digest, baseline flag.
dcb_stage_from_gap:
    lea  rdi, [rel dcb_nv_stage]
    xor  esi, esi
    mov  edx, DCB_NV_SIZE
    call memset
    lea  rdi, [rel dcb_nv_stage]
    lea  rsi, [rel dcb_gap_tails]
    mov  edx, DCB_NV_TAILS
    call memcpy
    lea  rdi, [rel dcb_nv_stage + DCB_NV_DIGEST]
    lea  rsi, [rel dcb_gap_digest]
    mov  edx, 32
    call memcpy
    mov  dword [rel dcb_nv_stage + DCB_NV_FLAGS], DCB_NV_F_BASELINE
    ret

; dcb_resolve_locked() -> EAX=DCB_BACKEND_*.  Caller holds persist_gap_lock.
; Decided once per boot; every branch emits exactly one backend marker.
dcb_resolve_locked:
    movzx eax, byte [rel dcb_backend]
    test eax, eax
    jnz  .ret
    push rbx
    push r12
    cmp  byte [rel pbm_runtime_code_mapped], 1
    jne  .no_nvram
    cmp  qword [rel runtime_services], 0
    je   .no_nvram
    call dcb_nv_get
    mov  ebx, eax                         ; 0 present, 1 absent, -1 bad
    cmp  ebx, -1
    je   .nv_invalid
    test ebx, ebx
    jnz  .gap
    lea  rdi, [rel dcb_nv_verify]
    call dcb_nv_well_formed
    test eax, eax
    jz   .nv_invalid
    lea  rdi, [rel dcb_nv_image]
    lea  rsi, [rel dcb_nv_verify]
    mov  edx, DCB_NV_SIZE
    call memcpy
    mov  byte [rel dcb_nv_present], 1
.gap:
    call dcb_gap_read_tails
    mov  r12d, eax                        ; DCB_GAP_*
    test ebx, ebx
    jz   .present
    ; ---- variable absent ----
    cmp  r12d, DCB_GAP_IOERR
    je   .gap_unreadable
    cmp  r12d, DCB_GAP_OK
    jne  .fresh_nobaseline
    lea  rdi, [rel dcb_gap_tails]
    call dcb_tails_zero
    test eax, eax
    jnz  .fresh_baseline
    ; READ-AND-COPY migration: the gap was only read above.
    call dcb_stage_from_gap
    lea  rdi, [rel dcb_nv_stage]
    lea  rsi, [rel str_dcb_nv_migrate_caller]
    call dcb_nv_commit
    test eax, eax
    jnz  .migrate_failed
    lea  rdi, [rel str_dcb_migrated]
    call serial_string
    call dcb_emit_digest
    lea  rdi, [rel str_dcb_migrated_marker]
    call serial_string
    jmp  .nvram
.fresh_baseline:
    ; empty gap observed: nothing to migrate; remember the baseline so a later
    ; rollback-era gap write is recognized.  Created by the first DATA write.
    call dcb_stage_from_gap
    lea  rdi, [rel dcb_nv_image]
    lea  rsi, [rel dcb_nv_stage]
    mov  edx, DCB_NV_SIZE
    call memcpy
    jmp  .nvram_empty
.fresh_nobaseline:
    ; no DATA device selected this boot: the variable starts empty, baseline unknown.
    lea  rdi, [rel dcb_nv_image]
    xor  esi, esi
    mov  edx, DCB_NV_SIZE
    call memset
    jmp  .nvram_empty
    ; ---- variable present ----
.present:
    cmp  r12d, DCB_GAP_OK
    jne  .nvram
    test dword [rel dcb_nv_image + DCB_NV_FLAGS], DCB_NV_F_BASELINE
    jz   .no_baseline
    lea  rdi, [rel dcb_gap_digest]
    lea  rsi, [rel dcb_nv_image + DCB_NV_DIGEST]
    mov  edx, 32
    call memcmp
    test eax, eax
    jz   .nvram
    ; The gap changed after the last sync.  This payload never writes it, so
    ; an older payload (rollback) did: it is the newest writer.  Re-copy.
    call dcb_stage_from_gap
    lea  rdi, [rel dcb_nv_stage]
    lea  rsi, [rel str_dcb_nv_migrate_caller]
    call dcb_nv_commit
    test eax, eax
    jnz  .migrate_failed
    lea  rdi, [rel str_dcb_resynced]
    call serial_string
    call dcb_emit_digest
    lea  rdi, [rel str_dcb_resynced_marker]
    call serial_string
    jmp  .nvram
.no_baseline:
    lea  rdi, [rel dcb_gap_tails]
    call dcb_tails_zero
    test eax, eax
    jnz  .nvram
    lea  rdi, [rel str_dcb_shadowed]
    call serial_string
    jmp  .nvram
.nvram_empty:
    mov  byte [rel dcb_nv_present], 0
.nvram:
    mov  byte [rel dcb_backend], DCB_BACKEND_NVRAM
    lea  rdi, [rel str_dcb_backend_nvram]
    call serial_string
    movzx edi, byte [rel dcb_nv_present]
    call serial_hex64
    lea  rdi, [rel str_dcb_backend_nvram_marker]
    call serial_string
    jmp  .done
.nv_invalid:
    lea  rdi, [rel str_dcb_nv_invalid]
    jmp  .unavailable
.gap_unreadable:
    lea  rdi, [rel str_dcb_gap_unreadable]
    jmp  .unavailable
.migrate_failed:
    lea  rdi, [rel str_dcb_migrate_failed]
    jmp  .unavailable
.no_nvram:
    call dcb_selected_dev
    test rax, rax
    jz   .no_nvram_nodev
    mov  rdi, rax
    mov  esi, DCB_LBA_PRIMARY
    mov  edx, DCB_LBA_TMP - DCB_LBA_PRIMARY + 1
    call storage_access_classify
    cmp  eax, SA_CLASS_TEST_SCRATCH
    jne  .no_nvram_real
    mov  byte [rel dcb_backend], DCB_BACKEND_SCRATCH
    lea  rdi, [rel str_dcb_backend_scratch]
    call serial_string
    jmp  .done
.no_nvram_real:
    lea  rdi, [rel str_dcb_no_nvram_real]
    jmp  .unavailable
.no_nvram_nodev:
    lea  rdi, [rel str_dcb_no_nvram_nodev]
.unavailable:
    call serial_string
    mov  byte [rel dcb_backend], DCB_BACKEND_UNAVAILABLE
.done:
    movzx eax, byte [rel dcb_backend]
    pop  r12
    pop  rbx
.ret:
    ret

; " gap_sha256=<first 8 bytes>" of the synced gap tails (audit breadcrumb).
dcb_emit_digest:
    lea  rdi, [rel str_dcb_digest]
    call serial_string
    mov  rdi, [rel dcb_gap_digest]
    bswap rdi
    jmp  serial_hex64

align 2                                 ; a CHAR16 string handed to firmware must be 2-aligned (UEFI; edk2 ASSERTs)
dcb_nv_name: dw 'P','a','O','S','D','a','t','a','R','e','c','o','r','d',0
str_dcb_nv_backend: db "nvram:PaOSDataRecord", 0
str_dcb_nv_caller: db "data_crypto_record", 0
str_dcb_nv_migrate_caller: db "data_record_migrate", 0
str_dcb_digest: db " gap_sha256_prefix=", 0
str_dcb_migrated: db "[PAOS64] storage: DATA record MIGRATED by read-and-copy: gap LBA 0x700/0x708 tails -> NVRAM PaOSDataRecord (exact readback; gap read-only, untouched)", 0
str_dcb_migrated_marker: db " [storage.data.migrated]", 13, 10, 0
str_dcb_resynced: db "[PAOS64] storage: DATA record RESYNCED from gap tails changed since last sync (older-payload write is newest) -> NVRAM PaOSDataRecord", 0
str_dcb_resynced_marker: db " [storage.data.resynced]", 13, 10, 0
str_dcb_shadowed: db "[PAOS64] storage: gap tails hold data but PaOSDataRecord has no gap baseline; NVRAM stays authoritative, gap untouched [storage.data.gap_shadowed]", 13, 10, 0
str_dcb_backend_nvram: db "[PAOS64] storage: DATA record backend=nvram var=PaOSDataRecord present=", 0
str_dcb_backend_nvram_marker: db " [storage.data.backend.nvram]", 13, 10, 0
str_dcb_backend_scratch: db "[PAOS64] storage: DATA record backend=scratch (no runtime NVRAM; QEMU test-scratch slots) [storage.data.backend.scratch]", 13, 10, 0
str_dcb_nv_invalid: db "[PAOS64] storage: PaOSDataRecord unreadable/malformed; DATA record unavailable (fail-closed, never overwritten) [storage.data.backend.unavailable]", 13, 10, 0
str_dcb_gap_unreadable: db "[PAOS64] storage: DATA gap unreadable before migration; DATA record unavailable this boot [storage.data.backend.unavailable]", 13, 10, 0
str_dcb_migrate_failed: db "[PAOS64] storage: DATA record migration/resync write failed; gap untouched; DATA record unavailable this boot [storage.data.migrate.failed]", 13, 10, 0
str_dcb_no_nvram_real: db "[PAOS64] storage: no runtime NVRAM and DATA device is not test scratch; DATA record unavailable (raw gap never written) [storage.data.backend.unavailable]", 13, 10, 0
str_dcb_no_nvram_nodev: db "[PAOS64] storage: no runtime NVRAM and no DATA device; DATA record unavailable [storage.data.backend.unavailable]", 13, 10, 0
str_dcb_nv_commit_failed: db "[PAOS64] storage: PaOSDataRecord SetVariable/readback failed [storage.data.nvram.commit-failed]", 13, 10, 0
dcb_backend: db 0
dcb_nv_present: db 0
align 8
dcb_nv_io_size: dq 0
dcb_nv_io_attrs: dd 0
align 16
dcb_nv_image: times DCB_NV_SIZE db 0
align 16
dcb_nv_stage: times DCB_NV_SIZE db 0
align 16
dcb_nv_verify: times DCB_NV_SIZE db 0
align 16
dcb_gap_tails: times DCB_NV_TAILS db 0
dcb_gap_digest: times 32 db 0
align 16
dcb_sha_ctx: times S256_CTX_SZ db 0
