;; MODULE fs/ntfs_disk
;; LAYER 4
;; EXPORTS ntfs_disk_select_removable_gpt_ro, ntfs_disk_select_removable_mbr_ro, ntfs_disk_refusal_stage, ntfs_disk_selection_state, ntfs_disk_select_exact, ntfs_disk_register, ntfs_disk_handle, ntfs_disk_write_state, nt_path_refusal, ntfs_disk_source_device, ntfs_disk_source_bind, ntfs_disk_source_token, ntfs_disk_source_current, ntfs_disk_source_stat, ntfs_disk_source_read, ntfs_disk_source_dir, ntfs_disk_source_next, ntfs_disk_source_node, ntfs_disk_source_tree_forget, ntfs_disk_source_mtime, ntfs_disk_format_ops
;; IMPORTS fs/fs_identify, fs/ext4_disk, fs/blockdev, fs/storage_access, fs/vfs, core/lib/crc32, core/lib/mem, core/unicode_edit, boot/serial
;; CAPS CAP_BLOCK_READ, CAP_BLOCK_WRITE
;; OWNER saga:desktop_bringup
; ============================================================================
; fs/ntfs_disk.asm — physical NTFS backend on the VFS fs_ops seam (2026-09-07,
; desktop bring-up). Distilled from the monolith's 9779 read-only NTFS (mount +
; MFT fixups + mapping-pair runlists + $I30 INDX walk + $DATA runs) onto the
; rework's driver-class seams: media ONLY through the blk device handle held in
; the private context (ESSENCE E1), never a controller symbol.
;
; READ (v1): superfloppy / MBR(0x07) / GPT volumes whose $Boot carries the NTFS
;   OEM id; root-directory files by 8.3 name (VFS name11) matched case-
;   insensitively against ANY namespace ($FILE_NAME in $INDEX_ROOT + every
;   in-use $INDEX_ALLOCATION block per $BITMAP); resident and non-resident
;   unnamed $DATA; sparse runs read as zeros; bytes past initialized_size read
;   as zeros (NTFS semantics). Honest refusals (marker + -1): compressed or
;   encrypted streams, attribute lists, > NT_MAX_RUNS extents, index blocks
;   > 4 KiB. Listings publish complete UTF-8 names or omit an entry with truncated=1.
;
; WRITE (v1, the SAFE SUBSET — the installer contract): write_at() overwrites
;   bytes INSIDE an existing file's already-allocated, already-initialized
;   $DATA extents. Nonresident writes leave metadata byte-identical. Resident
;   writes stage an ordinary base FILE in $MFT, updating only DATA bytes and
;   required USA storage; mirrored/reserved records are refused. Neither path
;   allocates, changes size, or updates $Bitmap/$LogFile/$UsnJrnl. Gates (any -> refused, marker with reason):
;     1. $Volume dirty flag set (chkdsk owed)            2. \hiberfil.sys 'hibr'/'HIBR'
;        (Windows hibernated / Fast Startup — cached metadata would clobber us)
;     3. unsupported resident layout / compressed / sparse / encrypted / attr list
;     4. off+len beyond data_size OR beyond initialized_size (pre-create the
;        file WITH real bytes from Windows; a zero-VDL file would read as zeros)
;     5. a sparse (unallocated) run inside the range
;   Then: sector-granular RMW through a bounce, successful blk_flush, and a
;   READ-BACK memcmp. Both durability and matching bytes are required for
;   [fs.ntfs.write.verified]. Failed/unsupported flush retains its block error
;   and disarms writes: cached bytes may already differ, persistence is unknown.
;   Existing whole-file saves use .update / FS_MUT_UPDATE at the SAME live
;   DATA size. They also require the current verified OWNER + SPECIAL intent,
;   the mounted media generation and an ordinary nonprotected scratch file.
;   Authority is checked at each sector/retry, before flush and before success.
;   I/O/readback uncertainty disarms this writer. .writefile stays unsupported:
;   its allocating cluster/temp-swap ABI cannot promise an in-place update.
;   FS_MUT_RENAME additionally admits an equal-length FSW*.TST Win32 leaf
;   rename for one resident file/link/name in a one-entry resident parent.
;   Both FILE_NAME copies are staged; live VBR/geometry and raw partial
;   postimages are checked through flush/readback. Uncertainty disarms; this
;   is bounded metadata support, without journal/crash atomicity or allocation.
;   Creating/deleting files = explicit follow-on (full metadata write).
; ============================================================================

; A public 0.1 build reads NTFS only (Peter decision 10 (LEDGER 85949, 87106)): no save authority, and the sole
; block-write sink refuses before touching the disk. Lab builds keep the writer for its 0.2 work.
%define NT_PUBLIC_READ_ONLY 0
%ifdef PAOS_PUBLIC_BUILD
%if PAOS_PUBLIC_BUILD != 0
%define NT_PUBLIC_READ_ONLY 1
%endif
%endif
; NT_PUBLIC_READ_ONLY end

NT_MAX_RUNS      equ 64
NT_RECBUF        equ 4096
NT_MAX_SPC_LOG2  equ 12              ; SEC-NTFS-geometry: <= 4096 sectors (2 MiB) per cluster
NT_IDXBUF        equ 4096
NT_SECBUF        equ 4096                      ; 8-sector bounce
NT_DIRBM         equ 512                       ; $BITMAP copy -> 4096 index blocks
NT_NAME_MAX      equ 765                       ; 255 UTF16 units, worst case UTF8
NT_LIST_NAMES_CAP equ 65536                    ; complete names only; next listing invalidates
; Per mutate_path refusal observation. Reset at entry; no authority or retry.
NT_PATH_NONE    equ 0
NT_PATH_LONG    equ 1
NT_PATH_NAME    equ 2
NT_PATH_MISSING equ 3
NT_MUT_PATH_MAX  equ 200                       ; mutation bytes excluding NUL; ASCII components <=63
NT_READ_PATH_CAP equ 1024                      ; read scratch INCLUDING its internal trailing NUL
                                               ; explicit span excludes NUL: 0..1023 bytes

NT_A_STDINFO     equ 0x10
NT_A_ATTRLIST    equ 0x20
NT_A_FILENAME    equ 0x30
NT_A_VOLINFO     equ 0x70
NT_A_DATA        equ 0x80
NT_A_INDEXROOT   equ 0x90
NT_A_INDEXALLOC  equ 0xA0
NT_A_BITMAP      equ 0xB0

NT_REC_MFT       equ 0
NT_REC_VOLUME    equ 3
NT_REC_ROOT      equ 5

NT_VISIT_LIST    equ 0
NT_VISIT_LOOKUP  equ 1
NT_VISIT_TREE    equ 2
%include "fs/ntfs_tree_source.inc"

NT_WREF_NOTARMED equ 1
NT_WREF_NOFILE   equ 2
NT_WREF_RESIDENT equ 3
NT_WREF_FLAGS    equ 4                         ; compressed/sparse/encrypted
NT_WREF_ATTRLIST equ 5
NT_WREF_RANGE    equ 6                         ; beyond data_size / initialized_size
NT_WREF_SPARSE   equ 7
NT_WREF_RUNS     equ 8
NT_WREF_IO       equ 9
NT_WREF_VERIFY   equ 10
NT_WREF_FLUSH    equ 11                        ; persistence unconfirmed; writer disarmed

; ---------------------------------------------------------------------------
; ntfs_disk_register — discover the NTFS volume (largest across every AHCI/NVMe
; block device; superfloppy, MBR 0x07 or GPT), mount it, register the fs_ops
; mount "ntfs0". -> RAX = mount handle / -1 (no volume: [fs.ntfs.skipped]).
; ---------------------------------------------------------------------------
ntfs_disk_register:
    mov byte [rel nt_sel_active],0
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  dword [rel ntfs_disk_handle], -1
    mov  qword [rel nt_binding_generation], 0
    mov  byte [rel nt_mounted], 0
    mov  qword [rel nt_best_sectors], 0
    mov  qword [rel nt_best_dev], 0
    mov  dword [rel nt_best_prio], 0
    mov  byte [rel nt_scan_prio], 0
    call nt_build_ops
    ; --- scan AHCI then NVMe registrations.  Default choice = the LARGEST NTFS
    ;     volume anywhere.  -DPAOS_NTFS_PREFER_NVME=1 ranks NVMe-resident volumes
    ;     above AHCI ones (Peter's desktop: Windows C: lives on the NVMe, the
    ;     bigger BACKUP volume on the 8 TB SATA would otherwise win). ---
    lea  rdi, [rel str_nt_pfx_ahci]
    mov  esi, 4
    call nt_scan_prefix
%ifdef PAOS_NTFS_PREFER_NVME
    mov  byte [rel nt_scan_prio], 1
%endif
    lea  rdi, [rel str_nt_pfx_nvme]
    mov  esi, 4
    call nt_scan_prefix
    cmp  qword [rel nt_best_dev], 0
    je   .none
    ; --- mount the chosen candidate ---
    mov  rax, [rel nt_best_dev]
    mov  [rel nt_dev], rax
    mov  rax, [rel nt_best_lba]
    mov  [rel nt_part_lba], rax
    mov  rax, [rel nt_best_sectors]
    mov  [rel nt_part_sectors], rax
    mov  eax, [rel nt_best_scheme]
    mov  [rel nt_scheme], eax
    call nt_mount_volume
    test rax, rax
    jz   .mounted
    ; --- honest failure line, then ONE fallback to the alternate candidate ---
    call nt_emit_mount_failed
    cmp  qword [rel nt_alt_dev], 0
    je   .none
    mov  rax, [rel nt_alt_dev]
    mov  [rel nt_dev], rax
    mov  qword [rel nt_alt_dev], 0
    mov  rax, [rel nt_alt_lba]
    mov  [rel nt_part_lba], rax
    mov  rax, [rel nt_alt_sectors]
    mov  [rel nt_part_sectors], rax
    mov  eax, [rel nt_alt_scheme]
    mov  [rel nt_scheme], eax
    call nt_mount_volume
    test rax, rax
    jz   .mounted
    call nt_emit_mount_failed
    jmp  .none
.mounted:
    lea  rdi, [rel nt_ops]
    lea  rsi, [rel nt_ctx]
    lea  rdx, [rel str_nt_mount_name]
    call vfs_register_mount
    test rax, rax
    js   .none
    mov  [rel ntfs_disk_handle], eax
    mov  rax, [rel vfs_write_generation]
    mov  [rel nt_binding_generation], rax
    call nt_emit_mounted
    mov  eax, [rel ntfs_disk_handle]
    jmp  .out
.none:
    lea  rdi, [rel str_nt_skipped]
    call serial_string
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; First-context late read-only NTFS. BSP/non-reentrant after boot registration.
; RDI is an opaque registered removable dev, never a controller or row number.
; Existing singleton context/handle is busy and remains byte-identical. No
; second context, scan ranking, request authority, writer arm, write or flush.
; Return >=0 handle, -1 unsupported/invalid, -2 busy (never fall through).
ntfs_disk_select_removable_gpt_ro:
    mov esi,1
    jmp nt_sel_begin
ntfs_disk_select_removable_mbr_ro:
    xor esi,esi
nt_sel_begin:
    push rbx
    push r12
    mov r12d,esi
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
    cmp dword [rel ntfs_disk_handle],-1
    jne .busy
    cmp byte [rel nt_mounted],0
    jne .busy
    cmp byte [rel nt_sel_active],0
    jne .busy
    mov [rel nt_sel_gpt],r12b
    mov rdi,rbx
    call nt_sel_member
    test rax,rax
    jz .no
    mov rdi,rbx
    call guest_volume_native_allowed
    test rax,rax
    jnz .no
    mov rax,[rbx+dev.info]
    mov [rel nt_sel_identity],rax
    mov rdx,[rbx+dev.ops]
    mov [rel nt_sel_identity+8],rdx
    mov rdx,[rbx+dev.priv]
    mov [rel nt_sel_identity+16],rdx
    mov rdx,[rax+blk_info.media_generation]
    test rdx,rdx
    jz .no
    mov [rel nt_sel_identity+24],rdx
    mov rdx,[rax+blk_info.lba_max]
    mov [rel nt_sel_identity+32],rdx
    mov [rel nt_sel_device],rbx
    mov byte [rel nt_sel_active],1
    call nt_sel_current
    test rax,rax
    jnz .fail
    mov rdi,rbx
    lea rcx,[rel nt_sel_primary]
    call nt_sel_query
    test rax,rax
    jnz .fail
    mov [rel nt_dev],rbx
    mov rax,[rel nt_sel_primary+16]
    mov [rel nt_part_lba],rax
    mov rax,[rel nt_sel_primary+24]
    mov [rel nt_part_sectors],rax
    mov eax,[rel nt_sel_primary+36]
    mov [rel nt_scheme],eax
    mov r12,[rel nt_read_failures]
    call nt_mount_volume
    ; Original clean-boot eligibility is never authority for this selector.
    mov byte [rel nt_write_armed],0
    test rax,rax
    jnz .fail
    cmp r12,[rel nt_read_failures]
    jne .fail
    mov rax,0x202020205346544e
    cmp [rel nt_boot_buf+3],rax
    jne .fail
    cmp word [rel nt_boot_buf+510],0xaa55
    jne .fail
    call nt_sel_recheck
    test rax,rax
    jnz .fail
    call nt_build_ops
    lea rdi,[rel nt_ops]
    lea rsi,[rel nt_ctx]
    lea rdx,[rel str_nt_mount_name]
    call vfs_register_mount
    test rax,rax
    js .fail
    mov [rel ntfs_disk_handle],eax
    mov [rel vfs_disk_handle],eax
    lock inc qword [rel vfs_write_generation]
    mov rdx,[rel vfs_write_generation]
    mov [rel nt_binding_generation],rdx
    mov byte [rel nt_lookup_pre],0
    mov byte [rel nt_found],0
    mov dword [rel nt_nruns],0
    jmp .out
.fail:
    call nt_exact_invalidate
.no:
    mov rax,-1
    jmp .out
.busy:
    mov rax,-2
.out:
    pop r12
    pop rbx
    ret

; RCX=out96; MBR retains original48. GPT has no loose-parser fallback.
nt_sel_query:
    xor esi,esi
    xor edx,edx
    lea r8,[rel nt_sel_current]
    cmp byte [rel nt_sel_gpt],0
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
nt_sel_member:
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
nt_sel_current:
    mov rdi,[rel nt_sel_device]
    call nt_sel_member
    test rax,rax
    jz .no
    mov rdx,[rax+dev.info]
    cmp rdx,[rel nt_sel_identity]
    jne .no
    mov rcx,[rax+dev.ops]
    cmp rcx,[rel nt_sel_identity+8]
    jne .no
    mov rcx,[rax+dev.priv]
    cmp rcx,[rel nt_sel_identity+16]
    jne .no
    mov rcx,[rdx+blk_info.media_generation]
    cmp rcx,[rel nt_sel_identity+24]
    jne .no
    mov rcx,[rdx+blk_info.lba_max]
    cmp rcx,[rel nt_sel_identity+32]
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

nt_sel_recheck:
    mov rdi,[rel nt_sel_device]
    lea rcx,[rel nt_sel_again]
    call nt_sel_query
    test rax,rax
    jnz .out
    lea rdi,[rel nt_sel_primary]
    lea rsi,[rel nt_sel_again]
    mov ecx,6
    cmp byte [rel nt_sel_gpt],0
    je .compare
    mov ecx,12
.compare:
    repe cmpsq
    jne .no
    mov rdi,[rel nt_sel_device]
    mov rsi,[rel nt_sel_primary+16]
    mov edx,1
    lea rcx,[rel nt_sel_vbr]
    call nt_dev_read
    test rax,rax
    jnz .out
    lea rdi,[rel nt_boot_buf]
    lea rsi,[rel nt_sel_vbr]
    mov ecx,64
    repe cmpsq
    jne .no
    jmp nt_sel_current
.no:
    mov rax,-1
.out:
    ret

; Preserve all block-read operands; registry lookup precedes captured pointers.
; Active persists for the lifetime of this read-only singleton, including VFS
; reads outside a copy/space query. Explicit authorized rebind invalidates it.
nt_sel_guard:
    cmp byte [rel nt_sel_active],0
    je .ok
    cmp rdi,[rel nt_sel_device]
    jne .no
    push rdi
    push rsi
    push rdx
    push rcx
    push r8
    push r9
    push r10
    push r11
    call nt_sel_current
    pop r11
    pop r10
    pop r9
    pop r8
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    ret
.no:
    mov rax,-1
    ret
.ok:
    xor eax,eax
    ret

; Explicit runtime binding. BSP-only like the command/storage transaction rails.
; RDI=name bytes, ESI=len, RDX=exact partition start, RCX=exact sector count.
; -> RAX mount / -1 invalid or failed (NTFS closed), -2 busy / -3 unauthorized
; (no state change). No scan ranking, fallback, formatting or media writes.
; OWNER+SPECIAL authorizes binding only: no storage grant/owned token is made.
; Fresh clean/hibernation eligibility is recomputed by the existing mount; each
; later write still needs its own current OWNER/SPECIAL and full estate guards.
ntfs_disk_refusal_stage:
    movzx eax, byte [rel nt_mount_stage]
    ret

ntfs_disk_select_exact:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 40
    mov  byte [rel nt_mount_stage], 0     ; no stale parser stage on auth/busy refusal
    mov  r12, rdi
    mov  r13d, esi
    mov  r14, rdx
    mov  r15, rcx
    call storage_access_request_owner
    cmp  eax, 1
    jne  .auth
    call storage_access_request_intent
    cmp  eax, SA_INTENT_SPECIAL
    jne  .auth
    call vfs_copy_busy
    test eax, eax
    jnz  .busy
    call storage_access_binding_busy
    test eax, eax
    jnz  .busy
    ; No operation can observe a partly rebound singleton. Old handles remain
    ; registered but all their NTFS ops refuse while nt_mounted=0. Never restore
    ; an old context after a failure: it would silently select another volume.
    lock inc qword [rel vfs_write_generation]
    mov  dword [rel vfs_disk_handle], -1
    call nt_exact_invalidate
    mov  rax, [rel nt_read_failures]
    mov  [rsp + 8], rax
    test r12, r12
    jz   .fail
    test r13d, r13d
    jz   .fail
    cmp  r13d, 63
    ja   .fail
    test r15, r15
    jz   .fail
    xor  ebx, ebx                         ; previous registered device
    xor  ebp, ebp                         ; exact match (duplicates refused)
.find:
    mov  rdi, rbx
    mov  esi, BLKCAP_READ
    xor  edx, edx
    call blk_iter_after
    test rax, rax
    jz   .found
    mov  rbx, rax
    mov  rdx, [rbx + dev.name]
    test rdx, rdx
    jz   .find
    xor  ecx, ecx
.name:
    cmp  ecx, r13d
    jae  .term
    mov  al, [rdx + rcx]
    test al, al
    jz   .find
    cmp  al, [r12 + rcx]
    jne  .find
    inc  ecx
    jmp  .name
.term:
    cmp  byte [rdx + rcx], 0
    jne  .find
    test rbp, rbp
    jnz  .fail
    mov  rbp, rbx
    jmp  .find
.found:
    test rbp, rbp
    jz   .fail
    mov  rdi, rbp
    call blk_identify
    test rax, rax
    jnz  .fail
    mov  rbx, [rbp + dev.info]
    cmp  dword [rbx + blk_info.sector_size], 512
    jne  .fail
    mov  rax, r15
    dec  rax
    add  rax, r14
    jc   .fail
    cmp  rax, [rbx + blk_info.lba_max]
    ja   .fail
    mov  rax, [rbx + blk_info.media_generation]
    test rax, rax
    jz   .fail
    mov  [rsp], rax                        ; initial medium/geometry across ALL I/O
    mov  rax, [rbx + blk_info.lba_max]
    mov  [rsp + 16], rax
    mov  eax, [rbx + blk_info.logical_sector_bytes]
    mov  [rsp + 24], eax
    mov  [rel nt_dev], rbp
    mov  [rel nt_part_lba], r14
    mov  [rel nt_part_sectors], r15
    call nt_exact_partition
    test eax, eax
    jnz  .fail
    ; Full OEM/signature validation before the maintained geometry/MFT loader.
    mov  rdi, rbp
    mov  rsi, r14
    mov  edx, 1
    lea  rcx, [rel nt_vbr_buf]
    call nt_dev_read
    test rax, rax
    jnz  .fail
    mov  rax, 0x202020205346544e            ; "NTFS    "
    cmp  [rel nt_vbr_buf + 3], rax
    jne  .fail
    cmp  word [rel nt_vbr_buf + 510], 0xAA55
    jne  .fail
    call nt_mount_volume
    test rax, rax
    jnz  .fail
    ; The boot reader allows unknown dirty/hiber state for read-only mounts.
    ; Explicit binding must not publish after any failed qualification read.
    mov  rax, [rel nt_read_failures]
    cmp  rax, [rsp + 8]
    jne  .fail
    ; Registry identity/geometry must still be the same after I/O. Iteration
    ; never dereferences an unregistered saved pointer to find its successor.
    xor  ebx, ebx
.recheck:
    mov  rdi, rbx
    mov  esi, BLKCAP_READ
    xor  edx, edx
    call blk_iter_after
    test rax, rax
    jz   .fail
    mov  rbx, rax
    cmp  rbx, rbp
    jne  .recheck
    mov  rax, [rbx + dev.info]
    mov  rcx, [rsp]
    cmp  rcx, [rax + blk_info.media_generation]
    jne  .fail
    cmp  rcx, [rel nt_mount_generation]
    jne  .fail
    mov  rcx, [rsp + 16]
    cmp  rcx, [rax + blk_info.lba_max]
    jne  .fail
    cmp  rcx, [rel nt_rename_mount_max]
    jne  .fail
    cmp  dword [rax + blk_info.sector_size], 512
    jne  .fail
    mov  ecx, [rsp + 24]
    cmp  ecx, [rax + blk_info.logical_sector_bytes]
    jne  .fail
    cmp  ecx, [rel nt_rename_mount_logical]
    jne  .fail
    mov  edi, [rel ntfs_disk_handle]
    cmp  edi, -1
    je   .register
    call vfs_mount_ptr
    test rax, rax
    jz   .fail
    lea  rdx, [rel nt_ops]
    cmp  [rax + fsmount.ops], rdx
    jne  .fail
    lea  rdx, [rel nt_ctx]
    cmp  [rax + fsmount.priv], rdx
    jne  .fail
    jmp  .publish
.register:
    call nt_build_ops
    lea  rdi, [rel nt_ops]
    lea  rsi, [rel nt_ctx]
    lea  rdx, [rel str_nt_mount_name]
    call vfs_register_mount
    test rax, rax
    js   .fail
    mov  [rel ntfs_disk_handle], eax
.publish:
    ; Mount lookup populated scratch during hibernation qualification. It is
    ; not a cached path or DATA stream for the next caller.
    mov  byte [rel nt_lookup_pre], 0
    mov  byte [rel nt_found], 0
    mov  dword [rel nt_nruns], 0
    mov  eax, [rel ntfs_disk_handle]
    mov  [rel vfs_disk_handle], eax
    mov  rdx, [rel vfs_write_generation]
    mov  [rel nt_binding_generation], rdx
    jmp  .out
.fail:
    call nt_exact_invalidate
    mov  rax, -1
    jmp  .out
.busy:
    mov  rax, -2
    jmp  .out
.auth:
    mov  rax, -3
.out:
    add  rsp, 40
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

nt_exact_invalidate:
    mov byte [rel nt_sel_active],0
    mov  byte [rel nt_mounted], 0
    mov  byte [rel nt_write_armed], 0
    mov  byte [rel nt_dirty], 2
    mov  byte [rel nt_hiber], 2
    mov  byte [rel nt_lookup_pre], 0
    mov  byte [rel nt_found], 0
    mov  byte [rel nt_lookup_complete], 0
    mov  dword [rel nt_nruns], 0
    mov  dword [rel nt_mft_nruns], 0
    mov  qword [rel nt_dev], 0
    mov  qword [rel nt_part_lba], 0
    mov  qword [rel nt_part_sectors], 0
    mov  qword [rel nt_mount_generation], 0
    mov  qword [rel nt_binding_generation], 0
    ret

; Exact supported partition metadata, read-only. Superfloppy=whole device;
; MBR=unique primary07; GPT=unique Basic Data in a CRC-checked primary header
; and complete bounded array (1..128 entries,128-byte entries). No extended
; MBR/hybrid/GPT backup fallback. Reject any occupied partition overlapping the
; requested window, even if its type is unsupported. Calls nt_dev_read only on
; this device. All failures leave caller's mounted flag false.
nt_exact_partition:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 32                           ; GPT CRC/first/last/entries LBA
    mov  r12, [rel nt_part_lba]
    mov  r13, [rel nt_part_sectors]
    lea  r14, [r12 + r13 - 1]               ; overflow checked by caller
    xor  ebp, ebp                          ; number of exact supported matches
    mov  rdi, [rel nt_dev]
    xor  esi, esi
    mov  edx, 1
    lea  rcx, [rel nt_sec_buf]
    call nt_dev_read
    test rax, rax
    jnz  .fail
    cmp  word [rel nt_sec_buf + 510], 0xAA55
    jne  .fail
    test r12, r12
    jnz  .mbr
    mov  rax, [rel nt_dev]
    mov  rax, [rax + dev.info]
    mov  rax, [rax + blk_info.lba_max]
    cmp  rax, r14
    jne  .fail
    mov  dword [rel nt_scheme], FS_SCHEME_SUPERFLOPPY
    jmp  .ok
.mbr:
    lea  rbx, [rel nt_sec_buf + 446]
    mov  r15d, 4
    ; Protective MBR must be unambiguous, never a hybrid interpretation.
    cmp  byte [rbx + 4], 0xEE
    je   .protective
.mbr_entry:
    movzx eax, byte [rbx + 4]
    test eax, eax
    jz   .mbr_next
    cmp  al, 0xEE
    je   .fail
    mov  esi, [rbx + 8]
    mov  edx, [rbx + 12]
    test rsi, rsi
    jz   .fail
    test rdx, rdx
    jz   .fail
    lea  rcx, [rsi + rdx - 1]
    mov  rdi, [rel nt_dev]
    mov  rdi, [rdi + dev.info]
    cmp  rcx, [rdi + blk_info.lba_max]
    ja   .fail
    cmp  rcx, r12
    jb   .mbr_next
    cmp  rsi, r14
    ja   .mbr_next
    cmp  rsi, r12
    jne  .fail
    cmp  rdx, r13
    jne  .fail
    cmp  al, 0x07
    jne  .fail
    inc  ebp
.mbr_next:
    add  rbx, 16
    dec  r15d
    jnz  .mbr_entry
    cmp  ebp, 1
    jne  .fail
    mov  dword [rel nt_scheme], FS_SCHEME_MBR
    jmp  .ok
.protective:
    cmp  dword [rbx + 8], 1
    jne  .fail
    ; Windows may retain the full-u32 protective sentinel on a smaller disk.
    ; It is not partition authority: all GPT CRC/geometry/exact-entry checks
    ; below remain mandatory, including rejection of hybrid MBR entries.
    cmp  dword [rbx + 12], 0xFFFFFFFF
    je   .protective_span_ok
    mov  rax, [rel nt_dev]
    mov  rax, [rax + dev.info]
    mov  rax, [rax + blk_info.lba_max]
    mov  edx, 0xFFFFFFFF
    cmp  rax, rdx
    cmova rax, rdx
    cmp  eax, [rbx + 12]                  ; otherwise require exact capped span
    jne  .fail
.protective_span_ok:
    mov  ecx, 3
.pmbr:
    add  rbx, 16
    cmp  byte [rbx + 4], 0
    jne  .fail
    loop .pmbr
    mov  rdi, [rel nt_dev]
    mov  esi, 1
    mov  edx, 1
    lea  rcx, [rel nt_sec_buf]
    call nt_dev_read
    test rax, rax
    jnz  .fail
    lea  rbx, [rel nt_sec_buf]
    mov  rax, 0x5452415020494645
    cmp  [rbx], rax
    jne  .fail
    cmp  dword [rbx + 8], 0x10000
    jne  .fail
    cmp  dword [rbx + 20], 0
    jne  .fail
    cmp  qword [rbx + 24], 1
    jne  .fail
    mov  rax, [rel nt_dev]
    mov  rax, [rax + dev.info]
    mov  rax, [rax + blk_info.lba_max]
    cmp  [rbx + 32], rax
    jne  .fail
    mov  esi, [rbx + 12]
    cmp  esi, 92
    jb   .fail
    cmp  esi, 512
    ja   .fail
    mov  r15d, [rbx + 16]
    mov  dword [rbx + 16], 0
    mov  rdi, rbx
    call hotpatch_crc32
    cmp  eax, r15d
    jne  .fail
    mov  rax, [rbx + 40]                    ; first usable
    cmp  rax, 2
    jb   .fail
    cmp  r12, rax
    jb   .fail
    mov  [rsp + 8], rax
    mov  rax, [rbx + 48]                    ; last usable
    cmp  rax, [rbx + 32]
    jae  .fail
    cmp  r14, rax
    ja   .fail
    mov  [rsp + 16], rax
    mov  rax, [rbx + 56]
    or   rax, [rbx + 64]
    jz   .fail
    cmp  dword [rbx + 84], 128
    jne  .fail
    mov  r15d, [rbx + 80]
    test r15d, r15d
    jz   .fail
    cmp  r15d, 128
    ja   .fail
    mov  eax, [rbx + 88]
    mov  [rsp], eax                        ; array CRC
    mov  rax, [rbx + 72]
    cmp  rax, 2
    jb   .fail
    mov  [rsp + 24], rax
    mov  edx, r15d
    add  edx, 3
    shr  edx, 2                            ; ceil(entries*128/512)
    add  rax, rdx
    jc   .fail
    cmp  rax, [rsp + 8]                    ; complete array before usable area
    ja   .fail
    mov  rdi, [rel nt_dev]
    mov  rsi, [rsp + 24]
    lea  rcx, [rel nt_exact_entries]
    call nt_dev_read
    test rax, rax
    jnz  .fail
    lea  rdi, [rel nt_exact_entries]
    mov  esi, r15d
    shl  esi, 7
    call hotpatch_crc32
    cmp  eax, [rsp]
    jne  .fail
    lea  rbx, [rel nt_exact_entries]
.gpt_entry:
    mov  rax, [rbx]
    or   rax, [rbx + 8]
    jz   .gpt_next
    mov  rsi, [rbx + 32]
    mov  rdx, [rbx + 40]
    cmp  rdx, rsi
    jb   .fail
    cmp  rsi, [rsp + 8]
    jb   .fail
    cmp  rdx, [rsp + 16]
    ja   .fail
    cmp  rdx, r12
    jb   .gpt_next
    cmp  rsi, r14
    ja   .gpt_next
    cmp  rsi, r12
    jne  .fail
    cmp  rdx, r14
    jne  .fail
    mov  rax, 0x4433b9e5ebd0a0a2            ; Microsoft Basic Data GUID, on disk
    cmp  [rbx], rax
    jne  .fail
    mov  rax, 0xc79926b7b668c087
    cmp  [rbx + 8], rax
    jne  .fail
    mov  rax, [rbx + 16]
    or   rax, [rbx + 24]
    jz   .fail
    inc  ebp
.gpt_next:
    add  rbx, 128
    dec  r15d
    jnz  .gpt_entry
    cmp  ebp, 1
    jne  .fail
    mov  dword [rel nt_scheme], FS_SCHEME_GPT
.ok:
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    add  rsp, 32
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; nt_scan_prefix(RDI=name prefix, ESI=len): every registered block device with
; that prefix -> nt_scan_device. clobbers caller-saved + rbx/r12-r14 (saved).
nt_scan_prefix:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13d, esi
    xor  r14d, r14d                        ; previous dev*
.next:
    mov  rdi, r12
    mov  esi, r13d
    mov  rdx, r14
    call blk_find_prefix_after
    test rax, rax
    jz   .done
    mov  r14, rax
    mov  rdi, rax
    call nt_scan_device
    jmp  .next
.done:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; nt_scan_device(RDI=dev*): superfloppy NTFS / MBR type 0x07 / GPT entries whose
; first sector carries the NTFS OEM id -> keep the largest as the candidate.
nt_scan_device:
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
    cmp  dword [rax + blk_info.sector_size], 512
    jne  .out
    mov  r15, [rax + blk_info.lba_max]
    inc  r15                               ; total sectors (lba_max inclusive)
    jz   .out
    mov  rdi, r12
    xor  esi, esi
    mov  edx, 1
    lea  rcx, [rel nt_sec_buf]
    call nt_dev_read
    test rax, rax
    jnz  .out
    ; superfloppy: NTFS OEM at LBA 0
    cmp  dword [rel nt_sec_buf + 3], 'NTFS'
    jne  .not_super
    mov  rdi, r12
    xor  esi, esi                          ; part lba 0
    mov  rdx, r15                          ; sectors
    mov  ecx, FS_SCHEME_SUPERFLOPPY
    call nt_consider
    jmp  .out
.not_super:
    cmp  word [rel nt_sec_buf + 510], 0xAA55
    jne  .out
    xor  r13d, r13d
.mbr_loop:
    cmp  r13d, 4
    jae  .out
    mov  eax, r13d
    shl  eax, 4
    lea  rbx, [rel nt_sec_buf + 446]
    add  rbx, rax
    movzx eax, byte [rbx + 4]
    cmp  al, 0xEE
    je   .gpt
    cmp  al, 0x07
    jne  .mbr_next
    mov  esi, [rbx + 8]                    ; start LBA
    test esi, esi
    jz   .mbr_next
    mov  edx, [rbx + 12]                   ; sectors
    test edx, edx
    jz   .mbr_next
    mov  rdi, r12
    mov  ecx, FS_SCHEME_MBR
    call nt_probe_candidate                ; reads the VBR, keeps it if NTFS
.mbr_next:
    inc  r13d
    jmp  .mbr_loop
.gpt:
    mov  rdi, r12
    mov  esi, 1
    mov  edx, 1
    lea  rcx, [rel nt_sec_buf]
    call nt_dev_read
    test rax, rax
    jnz  .out
    mov  rax, 0x5452415020494645           ; "EFI PART"
    cmp  [rel nt_sec_buf], rax
    jne  .out
    mov  rax, [rel nt_sec_buf + 72]        ; entries LBA
    test rax, rax
    jz   .out
    mov  [rel nt_gpt_entries_lba], rax
    mov  eax, [rel nt_sec_buf + 80]        ; entry count
    test eax, eax
    jz   .out
    cmp  eax, 128
    jbe  .cnt_ok
    mov  eax, 128
.cnt_ok:
    mov  [rel nt_gpt_count], eax
    cmp  dword [rel nt_sec_buf + 84], 128  ; entry size
    jne  .out
    xor  r13d, r13d
.gpt_loop:
    cmp  r13d, [rel nt_gpt_count]
    jae  .out
    mov  eax, r13d
    shl  rax, 7
    mov  r14, rax
    shr  rax, 9
    add  rax, [rel nt_gpt_entries_lba]
    mov  rdi, r12
    mov  rsi, rax
    mov  edx, 1
    lea  rcx, [rel nt_sec_buf]
    call nt_dev_read
    test rax, rax
    jnz  .gpt_next
    and  r14d, 511
    lea  rbx, [rel nt_sec_buf]
    add  rbx, r14
    mov  rax, [rbx]
    or   rax, [rbx + 8]
    jz   .gpt_next                         ; empty type GUID
    mov  rsi, [rbx + 32]                   ; first LBA
    mov  rdx, [rbx + 40]                   ; last LBA (inclusive)
    cmp  rdx, rsi
    jb   .gpt_next
    sub  rdx, rsi
    inc  rdx                               ; sectors
    mov  rdi, r12
    mov  ecx, FS_SCHEME_GPT
    call nt_probe_candidate
.gpt_next:
    inc  r13d
    jmp  .gpt_loop
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; nt_probe_candidate(RDI=dev, RSI=part lba, RDX=sectors, ECX=scheme): read the
; VBR into nt_vbr_buf (NOT nt_sec_buf: the caller's MBR/GPT sector stays live)
; and keep it if it is NTFS. Preserves rbx/r12-r15.
nt_probe_candidate:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15d, ecx
    mov  rdi, r12
    mov  rsi, r13
    mov  edx, 1
    lea  rcx, [rel nt_vbr_buf]
    call nt_dev_read
    test rax, rax
    jnz  .out
    cmp  dword [rel nt_vbr_buf + 3], 'NTFS'
    jne  .out
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, r14
    mov  ecx, r15d
    call nt_consider
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; nt_consider(RDI=dev, RSI=lba, RDX=sectors, ECX=scheme): keep the candidate of the
; highest scan priority (PAOS_NTFS_PREFER_NVME), and among equals the largest.
nt_consider:
    movzx eax, byte [rel nt_scan_prio]
    cmp  eax, [rel nt_best_prio]
    ja   .promote
    jb   .keep
    cmp  rdx, [rel nt_best_sectors]
    jbe  .keep
    jmp  .take
.promote:
    ; a higher-priority pass displaces the current best: keep that one as the
    ; ALTERNATE so a preferred volume that fails to mount falls back to it.
    cmp  qword [rel nt_best_dev], 0
    je   .take
    push rax
    mov  rax, [rel nt_best_dev]
    mov  [rel nt_alt_dev], rax
    mov  rax, [rel nt_best_lba]
    mov  [rel nt_alt_lba], rax
    mov  rax, [rel nt_best_sectors]
    mov  [rel nt_alt_sectors], rax
    mov  eax, [rel nt_best_scheme]
    mov  [rel nt_alt_scheme], eax
    pop  rax
.take:
    mov  [rel nt_best_prio], eax
    mov  [rel nt_best_dev], rdi
    mov  [rel nt_best_lba], rsi
    mov  [rel nt_best_sectors], rdx
    mov  [rel nt_best_scheme], ecx
.keep:
    ret

; nt_dev_read(RDI=dev, RSI=lba, RDX=count, RCX=buf) -> RAX 0/-1 (range-checked).
;   Multi-sector first; when the backend refuses that (the NVMe read op accepts
;   exactly ONE block per call — found by the QEMU NVMe A/B, and Windows C: lives
;   on NVMe on Peter's desktop) fall back to one blk_read per sector.  Counted in
;   nt_rd_fallback (mounted line "rd1=") so the slow path is never invisible.
nt_dev_read:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  r14, rsi
    mov  r12, rdx
    mov  r15, rcx
    call nt_sel_guard
    test rax,rax
    jnz .fail
    mov  rax, rsi
    add  rax, rdx
    jc   .fail
    dec  rax
    mov  r13, [rdi + dev.info]
    test r13, r13
    jz   .fail
    cmp  rax, [r13 + blk_info.lba_max]
    ja   .fail
    call nt_src_block_read
    test rax, rax
    jz   .ok
    cmp byte [rel nt_sel_active],0
    jne .fail
    call nt_src_guard
    test rax, rax
    jnz  .fail
    cmp  r12, 1
    jbe  .fail
    ; --- per-sector fallback ---
    mov  eax, [r13 + blk_info.sector_size]
    test eax, eax
    jnz  .stride_ok
    mov  eax, 512
.stride_ok:
    mov  r13d, eax                         ; stride
.one:
    test r12, r12
    jz   .fell_back
    mov  rdi, rbx
    mov  rsi, r14
    mov  edx, 1
    mov  rcx, r15
    call nt_src_block_read
    test rax, rax
    jnz  .fail
    inc  r14
    add  r15, r13
    dec  r12
    jmp  .one
.fell_back:
    inc  qword [rel nt_rd_fallback]
.ok:
    xor  eax, eax
    jmp  .out
.fail:
    inc  qword [rel nt_read_failures]
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; nt_read(RSI=absolute lba, RDX=count, RCX=buf) -> RAX 0/-1 on the mounted dev.
nt_read:
    call nt_lba_in_volume                  ; SEC-NTFS: never outside this partition
    jc   .out_of_volume
    mov  rdi, [rel nt_dev]
    jmp  nt_dev_read
.out_of_volume:
    inc  qword [rel nt_read_failures]
    mov  rax, -1
    ret

; nt_lba_in_volume(RSI=absolute lba, RDX=count) -> CF clear when the whole run
; [RSI, RSI+RDX) lies inside the mounted partition [nt_part_lba, +nt_part_sectors),
; CF set otherwise (empty run, unknown size, overflow or outside). SEC-NTFS:
; runlist LCNs come from on-disk metadata, so a corrupt or hostile $MFT must not
; steer a read or an owner-authorized overwrite into another partition or the
; backup GPT. Clobbers RAX, R8.
nt_lba_in_volume:
    test rdx, rdx
    jz   .bad
    mov  r8, [rel nt_part_sectors]
    test r8, r8
    jz   .bad
    mov  rax, [rel nt_part_lba]
    add  r8, rax                            ; partition end (exclusive)
    jc   .bad
    cmp  rsi, rax
    jb   .bad
    mov  rax, rsi
    add  rax, rdx
    jc   .bad
    cmp  rax, r8
    ja   .bad
    clc
    ret
.bad:
    stc
    ret

; nt_write(RSI=absolute lba, RDX=count, RCX=buf) -> RAX 0/-1. Range-checked,
; and NEVER below the volume's data area (the caller confines it to file runs).
nt_write:
    cmp byte [rel nt_sel_active],0
    je .not_late
    mov rax,-1
    ret
.not_late:
%if NT_PUBLIC_READ_ONLY
    mov  rax, -1
    ret
%else
    call nt_volume_pin                  ; T5-15.4: NTFS is never the MSI's reserved partition
    test rax, rax
    jz   .pin_ok
    ret
.pin_ok:
%endif
    push r12
    push r13
    push r9                              ; save-mode bit from the sole writer
    mov  r12, rdx
    mov  rdi, [rel nt_dev]
    test rdi, rdi
    jz   .fail
    mov  rax, rsi
    add  rax, rdx
    jc   .fail
    dec  rax
    mov  r13, [rdi + dev.info]
    test r13, r13
    jz   .fail
    cmp  rax, [r13 + blk_info.lba_max]
    ja   .fail
    call nt_lba_in_volume                  ; SEC-NTFS: never outside this partition (was: only its start)
    jc   .fail
    ; storage-access gate: an NTFS volume is another OS's partition (sensitive) — owner-signed only, audited.
    push rsi
    push rcx
    mov  rdx, r12
    lea  r8, [rel str_nt_sa_caller]
    call storage_access_require_request
    pop  rcx
    pop  rsi
    test rax, rax
    jnz  .fail
    ; ONE SECTOR PER OP: the AHCI backend's write op accepts exactly one sector
    ; (ahci_op_write: count must be 1). Each sector gets a bounded retry — a cold
    ; AHCI port can error its first op and warm on retry (the session-persist
    ; seam guards the same way). Every attempt is the SAME sector + SAME bytes,
    ; so a retry can never write anything different.
    push rbx
    push r14
    push r15
    mov  r14, rsi                          ; current lba
    mov  r15, rcx                          ; current buf
.sector:
    test r12, r12
    jz   .wok
    mov  ebx, 4
.again:
    cmp  qword [rsp + 24], 0
    je   .current
    call nt_save_current                 ; each individual sector and retry
    test rax, rax
    jnz  .write_fail
.current:
    mov  rdi, [rel nt_dev]
    mov  rsi, r14
    mov  edx, 1
    mov  rcx, r15
    call blk_write
    mov  [rel nt_last_blk_rc], rax
    test rax, rax
    jz   .next_sector
    dec  ebx
    jnz  .again
.write_fail:
    pop  r15
    pop  r14
    pop  rbx
    jmp  .fail
.next_sector:
    inc  r14
    add  r15, 512
    dec  r12
    jmp  .sector
.wok:
    pop  r15
    pop  r14
    pop  rbx
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    add  rsp, 8
    pop  r13
    pop  r12
    ret

; ---------------------------------------------------------------------------
; nt_mount_volume — parse $Boot geometry, load the $MFT runlist, read $Volume
; flags and the hiberfil gate. -> RAX 0/-1.
; ---------------------------------------------------------------------------
nt_mount_volume:
    push rbx
    push r12
    mov  byte [rel nt_mounted], 0
    mov  byte [rel nt_dirty], 2            ; unknown until bounded $Volume qualification
    mov  byte [rel nt_hiber], 2            ; unknown until lookup/header qualification
    mov  byte [rel nt_write_armed], 0
    mov  byte [rel nt_mount_stage], 1      ; 1 = boot sector read
    ; Bind the geometry and every qualification read to the same incarnation.
    ; Zero is an unknown token: keep coherent reads available, never arm writes.
    mov  rax, [rel nt_dev]
    test rax, rax
    jz   .fail
    mov  rax, [rax + dev.info]
    test rax, rax
    jz   .fail
    mov  rax, [rax + blk_info.media_generation]
    mov  [rel nt_mount_generation], rax
    mov  rsi, [rel nt_part_lba]
    mov  edx, 1
    lea  rcx, [rel nt_boot_buf]
    call nt_read
    test rax, rax
    jnz  .fail
    lea  rbx, [rel nt_boot_buf]
    mov  byte [rel nt_mount_stage], 2      ; 2 = OEM id
    cmp  dword [rbx + 3], 'NTFS'
    jne  .fail
    mov  byte [rel nt_mount_stage], 3      ; 3 = bytes/sector != 512 (4Kn volumes: v1 limit)
    cmp  word [rbx + 0x0B], 512            ; bytes/sector
    jne  .fail
    mov  rax, [rel nt_dev]
    mov  rax, [rax + dev.info]
    mov  rcx, [rax + blk_info.lba_max]
    mov  [rel nt_rename_mount_max], rcx
    mov  ecx, [rax + blk_info.logical_sector_bytes]
    mov  [rel nt_rename_mount_logical], ecx
    call nt_parse_geometry                 ; stages 4/5/7 (SEC-NTFS-geometry)
    test eax, eax
    jnz  .fail
    mov  rdi, [rel nt_mft_lcn]
    call nt_clus_to_lba
    mov  [rel nt_mft_lba], rax
    ; --- $MFT record 0 -> its own $DATA runlist (any record then resolves) ---
    mov  byte [rel nt_mount_stage], 6      ; 6 = $MFT record 0 / its $DATA runlist
    call nt_load_mft_runlist
    test rax, rax
    jnz  .fail
    mov  byte [rel nt_mount_stage], 0      ; mounted
    mov  byte [rel nt_mounted], 1
    ; --- $Volume (record 3) $VOLUME_INFORMATION flags: bit0 = dirty ---
    mov  edi, NT_REC_VOLUME
    call nt_read_record
    test rax, rax
    jnz  .vol_done
    call nt_volume_state
    test eax, eax
    js   .vol_done                        ; unknown stays readable, never write-armed
    mov  [rel nt_dirty], al               ; qualified 0 = clean, 1 = dirty
.vol_done:
    ; --- hiberfil.sys: failed discovery/read is UNKNOWN, never absence ---
    lea  rdi, [rel str_nt_hiberfil]
    call nt_lookup_root_ascii
    test rax, rax
    jz   .hib_found
    cmp  byte [rel nt_lookup_complete], 1
    je   .hib_clear                       ; complete traversal, name absent
    jmp  .hib_done
.hib_found:
    cmp  byte [rel nt_found_isdir], 0
    jne  .hib_done
    mov  rax, [rel nt_found_ref]
    mov  edi, eax
    cmp  rax, rdi                        ; no truncated high record reference
    jne  .hib_done
    call nt_read_record
    test rax, rax
    jnz  .hib_done
    lea  rbx, [rel nt_rec_buf]
    cmp  dword [rbx], 'FILE'
    jne  .hib_done
    cmp  word [rbx + 22], 1
    jne  .hib_done
    cmp  qword [rbx + 32], 0
    jne  .hib_done
    mov  eax, [rel nt_found_ref]
    cmp  [rbx + 44], eax
    jne  .hib_done
    mov  ax, [rel nt_found_sequence]
    test ax, ax
    jz   .hib_done
    cmp  [rbx + 16], ax
    jne  .hib_done
    xor  edx, edx
    lea  rcx, [rel nt_verify_buf]
    mov  r8d, 4
    call nt_data_read_at
    cmp  rax, 4
    jne  .hib_done                       ; short/failed header stays unknown
    mov  eax, [rel nt_verify_buf]
    cmp  eax, 'hibr'
    je   .hib
    cmp  eax, 'HIBR'
    je   .hib
.hib_clear:
    mov  byte [rel nt_hiber], 0
    jmp  .hib_done
.hib:
    mov  byte [rel nt_hiber], 1
.hib_done:
    ; $Volume and hiberfil traversal may have crossed a replacement too. A
    ; mixed mount is unusable, even when both media have identical geometry.
    mov  rdi, [rel nt_dev]
    call nt_sel_guard
    test rax,rax
    jnz .fail
    mov  rax, [rel nt_dev]
    mov  rax, [rax + dev.info]
    mov  rax, [rax + blk_info.media_generation]
    cmp  rax, [rel nt_mount_generation]
    jne  .fail
    test rax, rax
    jz   .armed_done
    cmp  byte [rel nt_dirty], 0
    jne  .armed_done
    cmp  byte [rel nt_hiber], 0
    jne  .armed_done
    mov  byte [rel nt_write_armed], 1
.armed_done:
    xor  eax, eax
    jmp  .out
.fail:
    mov  byte [rel nt_mounted], 0
    mov  rax, -1
.out:
    pop  r12
    pop  rbx
    ret

; nt_volume_state -> EAX 0 clean / 1 dirty / -1 unknown, from fixed-up record3.
; A missing/malformed value must not authorize a write. Walk only actual FILE
; bytes-in-use, require one plain resident unnamed value, and finish the bounded
; attribute chain (duplicate values/attribute lists are unsupported). No I/O or
; metadata writes; clobbers only caller-saved registers.
nt_volume_state:
    lea  rdi, [rel nt_rec_buf]
    cmp  dword [rdi], 'FILE'
    jne  .unknown
    cmp  word [rdi + 0x16], 1             ; ordinary in-use FILE, not a directory
    jne  .unknown
    cmp  qword [rdi + 0x20], 0            ; no extension record
    jne  .unknown
    mov  r8d, [rdi + 0x18]                ; actual bytes-in-use, not 4KiB scratch tail
    cmp  r8d, [rel nt_rec_bytes]
    ja   .unknown
    cmp  r8d, 0x30
    jb   .unknown
    movzx ecx, word [rdi + 0x14]
    cmp  ecx, 0x30
    jb   .unknown
    test cl, 7
    jnz  .unknown
    add  r8, rdi                         ; end of FILE bytes-in-use
    add  rdi, rcx                        ; first attribute
    mov  r9d, 2                          ; not yet qualified
.next:
    lea  r10, [rdi + 4]
    cmp  r10, r8
    ja   .unknown
    mov  eax, [rdi]
    cmp  eax, 0xFFFFFFFF
    je   .end
    cmp  eax, NT_A_ATTRLIST
    je   .unknown
    lea  r10, [rdi + 16]
    cmp  r10, r8
    ja   .unknown
    mov  edx, [rdi + 4]
    cmp  edx, 16
    jb   .unknown
    test dl, 7
    jnz  .unknown
    lea  r10, [rdi + rdx]                 ; next attribute, bounded before value use
    cmp  r10, r8
    ja   .unknown
    cmp  eax, NT_A_VOLINFO
    jne  .advance
    cmp  r9d, 2                          ; duplicate state is ambiguous
    jne  .unknown
    cmp  edx, 24
    jb   .unknown
    cmp  byte [rdi + 8], 0
    jne  .unknown
    cmp  byte [rdi + 9], 0
    jne  .unknown
    cmp  word [rdi + 12], 0
    jne  .unknown
    mov  ecx, [rdi + 16]                  ; resident value length
    cmp  ecx, 12
    jb   .unknown
    movzx r11d, word [rdi + 20]
    cmp  r11d, 24
    jb   .unknown
    add  rcx, r11                        ; full64 sum, cannot wrap the DWORD length
    cmp  rcx, rdx
    ja   .unknown
    movzx r9d, word [rdi + r11 + 10]      ; VOLUME_INFORMATION flags bit0 = dirty
    and  r9d, 1
.advance:
    mov  rdi, r10
    jmp  .next
.end:
    cmp  r9d, 2
    je   .unknown
    mov  eax, r9d
    ret
.unknown:
    mov  eax, -1
    ret

; nt_parse_geometry(RBX = verified 512-byte-sector NTFS boot sector) -> EAX 0, or
; -1 with nt_mount_stage naming the field. SEC-NTFS-geometry: a crafted boot
; sector on any attached disk is parsed at boot, so every field that later
; divides, shifts or sizes a buffer is validated first:
;   sectors/cluster: a power of two <= 2^NT_MAX_SPC_LOG2 (2 MiB clusters at
;     512 B), including the 2^(256-x) form, so nt_clus_bytes is never 0 (the
;     #DE in nt_vcn_to_lba) and never wraps;
;   total sectors: nonzero and inside the partition;
;   MFT record: [1024, NT_RECBUF] (nt_size_field refuses exponents > 31);
;   index block: a power of two in [512, NT_IDXBUF], else stored as 0, which
;     every use refuses.
; Fields are staged in registers and committed only after every check passed,
; so a refused sector leaves no partial geometry behind (nt_mounted stays 0).
; clobbers: RAX,RCX,R8-R11.
nt_parse_geometry:
    mov  byte [rel nt_mount_stage], 4      ; 4 = sectors/cluster
    movzx eax, byte [rbx + 0x0D]           ; sectors/cluster (or 2^(256-x) when > 0x80)
    cmp  eax, 0x80
    jbe  .spc_plain
    mov  ecx, 256
    sub  ecx, eax
    cmp  ecx, NT_MAX_SPC_LOG2
    ja   .bad
    mov  eax, 1
    shl  eax, cl
    jmp  .spc_ok
.spc_plain:
    test eax, eax
    jz   .bad
    lea  ecx, [rax - 1]
    test eax, ecx
    jnz  .bad                              ; not a power of two
.spc_ok:
    mov  r8d, eax                          ; sectors/cluster (staged)
    shl  eax, 9
    mov  r9d, eax                          ; cluster bytes (staged)
    mov  byte [rel nt_mount_stage], 7      ; 7 = total sectors 0 or larger than the partition
    mov  rax, [rbx + 0x28]                 ; total sectors
    test rax, rax
    jz   .bad
    cmp  rax, [rel nt_part_sectors]
    ja   .bad
    mov  r10, rax                          ; total sectors (staged)
    mov  byte [rel nt_mount_stage], 5      ; 5 = MFT record size out of [1024, NT_RECBUF]
    movsx eax, byte [rbx + 0x40]           ; clusters per MFT record (signed)
    mov  ecx, r9d
    call nt_size_field
    cmp  eax, 1024
    jb   .bad
    cmp  eax, NT_RECBUF
    ja   .bad
    mov  r11d, eax                         ; record bytes (staged)
    movsx eax, byte [rbx + 0x44]           ; clusters per index block (signed)
    mov  ecx, r9d
    call nt_size_field
    cmp  eax, 512
    jb   .idx_unusable
    cmp  eax, NT_IDXBUF
    ja   .idx_unusable
    lea  ecx, [rax - 1]
    test eax, ecx
    jz   .commit
.idx_unusable:
    xor  eax, eax                          ; refused at every use (0)
.commit:
    mov  [rel nt_idx_bytes], eax
    mov  [rel nt_spc], r8d
    mov  [rel nt_clus_bytes], r9d
    mov  [rel nt_total_sectors], r10
    mov  [rel nt_rec_bytes], r11d
    shr  r11d, 9
    mov  [rel nt_rec_sectors], r11d
    mov  rax, [rbx + 0x30]                 ; MFT LCN
    mov  [rel nt_mft_lcn], rax
    mov  rax, [rbx + 0x48]
    mov  [rel nt_serial], rax
    xor  eax, eax
    ret
.bad:
    mov  eax, -1
    ret

; nt_size_field(EAX = signed "clusters per X", ECX = cluster bytes) -> EAX bytes
; (2^-x when negative); 0 for an exponent above 31 or a product that would not
; fit 32 bits. The positive product cannot overflow today (<= 127 clusters of at
; most 2 MiB); the jo is a defensive bound, not dead weight. clobbers: RAX,RCX.
nt_size_field:
    test eax, eax
    js   .neg
    imul eax, ecx
    jo   .zero
    ret
.neg:
    neg  eax
    cmp  eax, 31
    ja   .zero
    mov  ecx, eax
    mov  eax, 1
    shl  eax, cl
    ret
.zero:
    xor  eax, eax
    ret

; nt_clus_to_lba(RDI=lcn) -> RAX absolute LBA. Clobbers RAX, RDX.
nt_clus_to_lba:
    ; SEC-NTFS: LCN comes from an on-disk runlist. An overflowing product or sum
    ; yields -1 (no device has that LBA; nt_lba_in_volume refuses it) instead of
    ; wrapping back into the volume.
    mov  eax, [rel nt_spc]
    mul  rdi
    jo   .bad
    add  rax, [rel nt_part_lba]
    jc   .bad
    ret
.bad:
    mov  rax, -1
    ret

; nt_fixup(RDI=record) -> RAX 0/-1: apply the Update Sequence Array in place
; (512-byte stride) for a FILE / INDX record; verifies every USN slot.
nt_fixup:
    push rbx
    push r12
    mov  rbx, rdi
    mov  eax, [rbx]
    cmp  eax, 'FILE'
    je   .ok
    cmp  eax, 'INDX'
    jne  .fail
.ok:
    movzx eax, word [rbx + 4]              ; USA offset
    movzx ecx, word [rbx + 6]              ; USA count (incl. USN)
    cmp  ecx, 2
    jb   .fail
    cmp  ecx, (NT_RECBUF / 512) + 1
    ja   .fail
    ; Bound the USA before dereferencing it, including generic INDX readers.
    cmp  eax, 8
    jb   .fail
    test eax, 1
    jnz  .fail
    lea  edx, [rax + rcx*2]
    cmp  edx, 510                         ; USA must precede the first sector tail
    ja   .fail
    lea  r12, [rbx + rax]
    movzx r8d, word [r12]                  ; USN
    mov  edx, 1
.loop:
    cmp  edx, ecx
    jae  .done
    mov  eax, edx
    shl  eax, 9
    sub  eax, 2
    cmp  word [rbx + rax], r8w             ; sector tail must carry the USN
    jne  .fail
    movzx r9d, word [r12 + rdx*2]
    mov  [rbx + rax], r9w
    inc  edx
    jmp  .loop
.done:
    xor  eax, eax
    pop  r12
    pop  rbx
    ret
.fail:
    mov  rax, -1
    pop  r12
    pop  rbx
    ret

; nt_find_attr(RDI=record, ESI=type) -> RAX attr ptr / 0. First attribute of
; that type with an EMPTY name (unnamed $DATA / the sole $I30 index attrs).
nt_find_attr:
    push rbx
    mov  rbx, rdi
    movzx eax, word [rbx + 0x14]
    add  rbx, rax
    lea  r8, [rdi + NT_RECBUF - 16]        ; hard bound inside the buffer
.loop:
    cmp  rbx, r8
    jae  .none
    mov  eax, [rbx]
    cmp  eax, 0xFFFFFFFF
    je   .none
    cmp  eax, esi
    jne  .next
    cmp  byte [rbx + 9], 0                 ; name length 0 -> unnamed
    je   .found
.next:
    mov  eax, [rbx + 4]
    cmp  eax, 16
    jb   .none
    add  rbx, rax
    jmp  .loop
.found:
    mov  rax, rbx
    pop  rbx
    ret
.none:
    xor  eax, eax
    pop  rbx
    ret

; nt_find_attr_any(RDI=record, ESI=type) -> RAX attr ptr / 0. First attribute of
; that type REGARDLESS of name: the directory index trio ($INDEX_ROOT,
; $INDEX_ALLOCATION, $BITMAP) is always NAMED "$I30".
nt_find_attr_any:
    push rbx
    mov  rbx, rdi
    movzx eax, word [rbx + 0x14]
    add  rbx, rax
    lea  r8, [rdi + NT_RECBUF - 16]
.loop:
    cmp  rbx, r8
    jae  .none
    mov  eax, [rbx]
    cmp  eax, 0xFFFFFFFF
    je   .none
    cmp  eax, esi
    je   .found
    mov  eax, [rbx + 4]
    cmp  eax, 16
    jb   .none
    add  rbx, rax
    jmp  .loop
.found:
    mov  rax, rbx
    pop  rbx
    ret
.none:
    xor  eax, eax
    pop  rbx
    ret

; nt_has_attr(RDI=record, ESI=type) -> EAX 1/0 (any name).
nt_has_attr:
    push rbx
    mov  rbx, rdi
    movzx eax, word [rbx + 0x14]
    add  rbx, rax
    lea  r8, [rdi + NT_RECBUF - 16]
.loop:
    cmp  rbx, r8
    jae  .no
    mov  eax, [rbx]
    cmp  eax, 0xFFFFFFFF
    je   .no
    cmp  eax, esi
    je   .yes
    mov  eax, [rbx + 4]
    cmp  eax, 16
    jb   .no
    add  rbx, rax
    jmp  .loop
.yes:
    mov  eax, 1
    pop  rbx
    ret
.no:
    xor  eax, eax
    pop  rbx
    ret

; nt_decode_runlist(RDI=mapping pairs, RSI=out[16: lcn,len], EDX=max, RCX=end
; bound) -> EAX run count, or -1 on malformed, unterminated or >max runs.
; Sparse runs store lcn = -1.
nt_decode_runlist:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  r14d, edx
    mov  r15, rcx                          ; end bound (exclusive)
    xor  ebx, ebx                          ; count
    mov  qword [rel nt_prev_lcn], 0
.loop:
    cmp  r12, r15
    jae  .bad                              ; an explicit zero terminator is required
    movzx eax, byte [r12]
    test al, al
    jz   .done
    cmp  ebx, r14d
    jae  .overflow
    inc  r12
    mov  r10d, eax
    and  r10d, 0x0F                        ; len bytes
    shr  eax, 4                            ; off bytes
    mov  r11d, eax
    cmp  r10d, 8
    ja   .bad
    cmp  r11d, 8
    ja   .bad
    ; Check the entire pair before consuming fields or publishing this run.
    mov  ecx, r10d
    add  ecx, r11d
    mov  rax, r15
    sub  rax, r12
    cmp  rax, rcx
    jb   .bad
    xor  r8, r8
    xor  ecx, ecx
.rl:
    test r10d, r10d
    jz   .rl_done
    movzx rax, byte [r12]
    shl  rax, cl
    or   r8, rax
    inc  r12
    add  cl, 8
    dec  r10d
    jmp  .rl
.rl_done:
    test r8, r8
    jz   .bad                              ; zero-length run
    test r11d, r11d
    jz   .sparse
    xor  r9, r9
    xor  ecx, ecx
    mov  edx, r11d
.ro:
    test edx, edx
    jz   .ro_sx
    movzx rax, byte [r12]
    shl  rax, cl
    or   r9, rax
    inc  r12
    add  cl, 8
    dec  edx
    jmp  .ro
.ro_sx:
    mov  eax, r11d
    shl  eax, 3
    mov  ecx, 64
    sub  ecx, eax
    shl  r9, cl
    sar  r9, cl                            ; sign-extend the delta
    mov  rax, [rel nt_prev_lcn]
    add  rax, r9
    jo   .bad                              ; signed LCN arithmetic must not wrap
    test rax, rax
    js   .bad                              ; only offset-width zero denotes sparse
    mov  [rel nt_prev_lcn], rax
    jmp  .store
.sparse:
    mov  rax, -1
.store:
    mov  rcx, rbx
    shl  rcx, 4
    mov  [r13 + rcx], rax
    mov  [r13 + rcx + 8], r8
    inc  ebx
    jmp  .loop
.done:
    mov  rdi, r13
    mov  esi, ebx
    call nt_validate_runlist
    test eax, eax
    jnz  .bad
    mov  eax, ebx
    jmp  .out
.overflow:
.bad:
    mov  eax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; nt_validate_runlist(RDI=runs, ESI=count) -> EAX 0/-1.
; All published runs and every mapping use this geometry contract. Signed
; positive lengths, total stream bytes <= INT64_MAX, and complete physical
; extents inside the BPB volume keep subsequent sums/products representable.
; The sole negative LCN allowed here is the decoder's explicit sparse marker.
; Preserves RDI/RSI and callee-saved registers; clobbers RAX,RCX,RDX,R8-R11.
nt_validate_runlist:
    cmp  esi, NT_MAX_RUNS
    ja   .bad
    test esi, esi
    jz   .ok
    mov  ecx, [rel nt_clus_bytes]
    test ecx, ecx
    jz   .bad
    mov  rax, 0x7FFFFFFFFFFFFFFF
    xor  edx, edx
    div  rcx
    mov  r9, rax                           ; maximum total virtual clusters
    mov  ecx, [rel nt_spc]
    test ecx, ecx
    jz   .bad
    mov  rax, [rel nt_total_sectors]
    xor  edx, edx
    div  rcx
    mov  r10, rax                          ; complete clusters in this volume
    mov  r11, rdi
    mov  ecx, esi
    xor  r8d, r8d                          ; cumulative virtual clusters
.loop:
    mov  rdx, [r11 + 8]
    test rdx, rdx
    jle  .bad                              ; zero/negative lengths are malformed
    add  r8, rdx
    jc   .bad
    cmp  r8, r9
    ja   .bad                              ; virtual span/byte products cannot wrap
    mov  rax, [r11]
    cmp  rax, -1
    je   .next
    test rax, rax
    js   .bad
    add  rax, rdx                          ; physical end cluster, exclusive
    jo   .bad
    cmp  rax, r10
    ja   .bad                              ; validate the whole extent, not just its start
.next:
    add  r11, 16
    dec  ecx
    jnz  .loop
.ok:
    xor  eax, eax
    ret
.bad:
    mov  eax, -1
    ret

; nt_load_mft_runlist -> RAX 0/-1: record 0 (contiguous at nt_mft_lba by
; definition for its first extent) -> unnamed $DATA mapping pairs.
nt_load_mft_runlist:
    push rbx
    mov  dword [rel nt_mft_nruns], 0
    mov  rsi, [rel nt_mft_lba]
    mov  edx, [rel nt_rec_sectors]
    lea  rcx, [rel nt_rec_buf]
    call nt_read
    test rax, rax
    jnz  .fail
    lea  rdi, [rel nt_rec_buf]
    mov  esi, [rel nt_rec_bytes]
    call nt_fixup_file
    test rax, rax
    jnz  .fail
    ; Record fixup establishes the actual FILE extent. Reuse the maintained
    ; whole-chain bounds before the legacy finder or mapping-pair decoder.
    ; Like nt_sx_record_valid, enter the shared bounds with a checked file kind.
    lea  rdi, [rel nt_rec_buf]
    cmp  word [rdi + 22], 1               ; ordinary in-use FILE, not directory/extension
    jne  .fail
    mov  r8d, [rel nt_rec_bytes]
    lea  rsi, [rdi + r8]                  ; actual bytes read, never on-disk attr length
    call nt_dir_record_valid.flags_ok
    test rax, rax
    jnz  .fail
    lea  rdi, [rel nt_rec_buf]
    mov  esi, NT_A_DATA
    call nt_find_attr
    test rax, rax
    jz   .fail
    cmp  byte [rax + 8], 0
    je   .fail                             ; $MFT data must be non-resident
    mov  rbx, rax
    movzx ecx, word [rbx + 0x20]
    lea  rdi, [rbx + rcx]
    mov  ecx, [rbx + 4]
    lea  rcx, [rbx + rcx]                  ; end of attribute
    lea  rsi, [rel nt_mft_runs]
    mov  edx, NT_MAX_RUNS
    call nt_decode_runlist
    test eax, eax
    jle  .fail
    mov  [rel nt_mft_nruns], eax
    lea  rdi, [rel nt_mft_runs]
    mov  esi, eax
    xor  edx, edx
    call nt_vcn_to_lba
    cmp  rax, [rel nt_mft_lba]
    jne  .fail
    test rcx, rcx
    jnz  .fail
    mov  ecx, [rel nt_rec_bytes]
    cmp  rdx, rcx
    jb   .fail                            ; bootstrap FILE must fit first extent
    xor  eax, eax
    pop  rbx
    ret
.fail:
    mov  dword [rel nt_mft_nruns], 0
    mov  dword [rel nt_rec_buf], 0
    mov  rax, -1
    pop  rbx
    ret

; nt_vcn_to_lba(RDI=runs, ESI=nruns, RDX=byte offset into the stream)
;   -> RAX = absolute LBA of the sector holding that byte, RDX = bytes left in
;   the run from that sector's start (>= 512), RCX = byte offset within the
;   sector; RAX = -1 sparse/unmapped (RDX = bytes of sparse left), -2 beyond.
nt_vcn_to_lba:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13d, esi
    test esi, esi
    jz   .beyond
    push rdx
    call nt_validate_runlist
    pop  rdx
    test eax, eax
    jnz  .beyond
    mov  rax, rdx
    xor  edx, edx
    mov  ecx, [rel nt_clus_bytes]
    div  rcx                               ; rax = vcn, rdx = byte in cluster
    mov  r8, rdx                           ; byte within cluster
    xor  r9, r9                            ; run start vcn
.walk:
    test r13d, r13d
    jz   .beyond
    mov  r10, [r12 + 8]                    ; run length (clusters)
    lea  r11, [r9 + r10]
    cmp  rax, r11
    jb   .found
    mov  r9, r11
    add  r12, 16
    dec  r13d
    jmp  .walk
.found:
    mov  rbx, rax
    sub  rbx, r9                           ; cluster index within run
    ; bytes left in run from this byte: (len - idx) * clus - byte_in_cluster
    mov  rcx, r10
    sub  rcx, rbx
    mov  eax, [rel nt_clus_bytes]
    imul rcx, rax
    sub  rcx, r8
    mov  r11, rcx                          ; bytes left in run from the byte
    mov  rax, [r12]                        ; lcn (or -1)
    cmp  rax, -1
    je   .sparse
    add  rax, rbx
    jc   .beyond                           ; SEC-NTFS: an overflowing run is an error, never sparse
    mov  rdi, rax
    call nt_clus_to_lba
    cmp  rax, -1
    je   .beyond                           ; LCN beyond any addressable sector
    mov  rcx, r8
    shr  rcx, 9
    add  rax, rcx                          ; sector holding the byte
    jc   .beyond
    mov  rcx, r8
    and  rcx, 511                          ; byte within sector
    mov  rdx, r11
    add  rdx, rcx                          ; bytes left counted from the sector start
    jmp  .out
.sparse:
    mov  rdx, r11
    mov  rax, -1
    jmp  .out
.beyond:
    mov  rax, -2
    xor  edx, edx
    xor  ecx, ecx
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; nt_read_stream_record(RDI=runs, ESI=count, RDX=stream byte offset,
; RCX=destination, R8D=record bytes) -> RAX 0/-1. No allocation. Records are
; sector aligned, 512..4096 bytes. Preflight the ENTIRE logical span before
; I/O, then remap every sector: physical adjacency is never inferred. Sparse,
; short, unmapped and overflowing spans fail without publishing a record.
nt_read_stream_record:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 24
    mov  r12, rdi
    mov  r13d, esi
    mov  r14, rdx
    mov  r15, rcx
    mov  ebx, r8d
    cmp  ebx, 512
    jb   .fail
    cmp  ebx, NT_RECBUF
    ja   .fail
    test ebx, 511
    jnz  .fail
    test r14, 511
    jnz  .fail
    mov  rax, r14
    add  rax, rbx
    jc   .fail
    mov  rax, r15
    add  rax, rbx
    jc   .fail
    mov  [rsp], r14
    mov  [rsp + 8], r15
    mov  [rsp + 16], ebx
    mov  dword [rsp + 20], 0             ; preflight, then read
.sector:
    mov  rdi, r12
    mov  esi, r13d
    mov  rdx, r14
    call nt_vcn_to_lba
    cmp  rax, -1
    je   .fail
    cmp  rax, -2
    je   .fail
    test rcx, rcx
    jnz  .fail
    cmp  rdx, 512
    jb   .fail                           ; never read past mapper's extent
    cmp  dword [rsp + 20], 0
    je   .advance
    mov  rsi, rax
    mov  edx, 1
    mov  rcx, r15
    call nt_read
    test rax, rax
    jnz  .fail
.advance:
    add  r14, 512
    add  r15, 512
    sub  ebx, 512
    jnz  .sector
    cmp  dword [rsp + 20], 0
    jne  .ok
    inc  dword [rsp + 20]
    mov  r14, [rsp]
    mov  r15, [rsp + 8]
    mov  ebx, [rsp + 16]
    jmp  .sector
.ok:
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    add  rsp, 24
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; nt_fixup_file(RDI=FILE, ESI=actual bytes read) -> RAX 0/-1.
; The generic fixup's 4 KiB ceiling does not establish coverage of a smaller
; FILE. Require every sector of THIS record exactly once before any fixup.
nt_fixup_file:
    cmp  esi, 1024
    jb   .fail
    cmp  esi, NT_RECBUF
    ja   .fail
    test esi, 511
    jnz  .fail
    cmp  dword [rdi], 'FILE'
    jne  .fail
    mov  eax, esi
    shr  eax, 9
    inc  eax
    cmp  [rdi + 6], ax
    jne  .fail
    jmp  nt_fixup
.fail:
    mov  rax, -1
    ret

; nt_read_record(EDI=record number) -> RAX 0/-1; nt_rec_buf holds a complete
; fixed-up FILE on success. Supports records crossing discontiguous MFT runs.
nt_read_record:
    push rbx
    push r12
    mov  eax, edi                        ; the public record ABI is unsigned32
    mov  ecx, [rel nt_rec_bytes]
    cmp  ecx, 1024
    jb   .fail
    cmp  ecx, NT_RECBUF
    ja   .fail
    test ecx, 511
    jnz  .fail
    mov  edx, ecx
    shr  edx, 9
    cmp  edx, [rel nt_rec_sectors]
    jne  .fail
    imul rax, rcx
    jo   .fail
    mov  rdx, rax
    lea  rdi, [rel nt_mft_runs]
    mov  esi, [rel nt_mft_nruns]
    lea  rcx, [rel nt_rec_buf]
    mov  r8d, [rel nt_rec_bytes]
    call nt_read_stream_record
    test rax, rax
    jnz  .fail
    lea  rdi, [rel nt_rec_buf]
    mov  esi, [rel nt_rec_bytes]
    call nt_fixup_file
    test rax, rax
    jnz  .fail
    test word [rel nt_rec_buf + 0x16], 1
    jz   .fail
    xor  eax, eax
    pop  r12
    pop  rbx
    ret
.fail:
    mov  dword [rel nt_rec_buf], 0        ; partial/stale bytes are not a FILE
    mov  byte [rel nt_found], 0
    mov  byte [rel nt_lookup_complete], 0
    mov  byte [rel nt_write_armed], 0
    mov  rax, -1
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; Root directory walk: $INDEX_ROOT entries, then every $INDEX_ALLOCATION block
; that $BITMAP marks in use. Modes: LIST (fill fs_dirent[]) / LOOKUP (match
; nt_match_name, ASCII uppercase, any namespace).
; ---------------------------------------------------------------------------
; A directory record must be wholly bounded before the legacy attribute lookup
; helpers see it. Missing/unsupported attributes never establish absence.
; RDI=FILE, RSI=actual record end -> 0/-1; no reads outside that span.
nt_dir_record_valid:
    mov  r8, rsi
    sub  r8, rdi
    cmp  r8, 48
    jb   .bad
    cmp  dword [rdi], 'FILE'
    jne  .bad
    cmp  word [rdi + 22], 3
    jne  .bad
.flags_ok:                               ; nt_sx_record_valid shares these bounds
    cmp  qword [rdi + 32], 0
    jne  .bad
    mov  eax, [rdi + 28]
    cmp  rax, r8
    jne  .bad
    mov  eax, [rdi + 24]
    cmp  rax, r8
    ja   .bad
    lea  r8, [rdi + rax]                  ; actual bytes in use
    movzx eax, word [rdi + 20]
    cmp  eax, 48
    jb   .bad
    test al, 7
    jnz  .bad
    mov  r9, r8
    sub  r9, rdi                         ; bytes in use
    mov  r10, rsi
    sub  r10, rdi                        ; actual FILE extent
    shr  r10, 9
    inc  r10d
    cmp  [rdi + 6], r10w
    jne  .bad
    movzx ecx, word [rdi + 4]
    cmp  ecx, 48
    jb   .bad
    lea  ecx, [rcx + r10*2]
    cmp  ecx, eax                        ; USA cannot overlap attributes
    ja   .bad
    cmp  rcx, r9
    ja   .bad
    add  rdi, rax
.loop:
    lea  rax, [rdi + 4]
    cmp  rax, r8
    ja   .bad
    cmp  dword [rdi], -1
    je   .ok
    lea  rax, [rdi + 16]
    cmp  rax, r8
    ja   .bad
    cmp  dword [rdi], NT_A_ATTRLIST
    je   .bad                            ; extension records unsupported
    mov  eax, [rdi + 4]
    test al, 7
    jnz  .bad
    lea  r9, [rdi + rax]
    cmp  r9, r8
    ja   .bad
    cmp  byte [rdi + 8], 1
    ja   .bad
    mov  ecx, 24
    cmp  byte [rdi + 8], 0
    je   .header
    mov  ecx, 64
.header:
    cmp  eax, ecx
    jb   .bad
    mov  r10d, ecx
    movzx edx, byte [rdi + 9]
    test edx, edx
    jz   .value
    movzx r11d, word [rdi + 10]
    cmp  r11d, ecx
    jb   .bad
    lea  r10d, [r11 + rdx*2]
    cmp  r10d, eax
    ja   .bad
.value:
    cmp  byte [rdi + 8], 0
    jne  .runs
    movzx edx, word [rdi + 20]
    cmp  edx, r10d
    jb   .bad
    mov  ecx, [rdi + 16]
    add  rcx, rdx
    cmp  rcx, rax
    ja   .bad
    jmp  .next
.runs:
    movzx edx, word [rdi + 32]
    cmp  edx, r10d
    jb   .bad
    cmp  edx, eax
    jae  .bad
.next:
    mov  rdi, r9
    jmp  .loop
.ok:
    xor  eax, eax
    ret
.bad:
    mov  rax, -1
    ret

; On the validated directory record, require the actual $I30 name, plain flags
; and a unique instance. RAX=attribute/0, RDX=0/-1 (malformed/unsupported).
nt_dir_attr:
    call nt_find_attr_any
    xor  edx, edx
    test rax, rax
    jz   .out
    cmp  word [rax + 12], 0
    jne  .bad
    cmp  byte [rax + 9], 4
    jne  .bad
    movzx ecx, word [rax + 10]
    mov  r9, 0x0030003300490024          ; UTF16 "$I30"
    cmp  [rax + rcx], r9
    jne  .bad
    mov  r9, rax
.next:
    mov  ecx, [r9 + 4]
    add  r9, rcx
    cmp  dword [r9], -1
    je   .out
    cmp  [r9], esi
    je   .bad
    jmp  .next
.bad:
    mov  rdx, -1
.out:
    ret

; nt_walk_root -> RAX 0/-1, including every node even after a match/list cap.
nt_walk_root:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  edi, [rel nt_walk_rec]
    call nt_read_record
    test rax, rax
    jnz  .fail
    lea  rdi, [rel nt_rec_buf]
    mov  esi, [rel nt_rec_bytes]
    add  rsi, rdi
    call nt_dir_record_valid
    test rax, rax
    jnz  .fail
    cmp  qword [rel nt_tree_frame], 0
    je   .tree_record_ok
    lea  rdi, [rel nt_rec_buf]
    mov  esi, [rel nt_rec_bytes]
    mov  edx, NTT_FILE
    call nt_tree_snapshot
    test rax, rax
    jnz  .fail
.tree_record_ok:
    cmp  qword [rel nt_src_reading], 0
    je   .source_node_ok
    call nt_src_node_safe
    test rax, rax
    jnz  .fail
.source_node_ok:
    lea  rdi, [rel nt_rec_buf]
    mov  esi, NT_A_INDEXROOT
    call nt_dir_attr
    test rdx, rdx
    jnz  .fail
    test rax, rax
    jz   .fail
    cmp  byte [rax + 8], 0
    jne  .fail
    mov  ecx, [rax + 16]
    cmp  ecx, 32
    jb   .fail
    movzx edx, word [rax + 20]
    lea  r12, [rax + rdx]                 ; root value
    lea  r15, [r12 + rcx]                 ; actual root value end
    cmp  dword [r12], NT_A_FILENAME
    jne  .fail
    cmp  dword [r12 + 4], 1               ; filename collation
    jne  .fail
    mov  eax, [rel nt_idx_bytes]
    test eax, eax
    jz   .fail
    cmp  [r12 + 8], eax
    jne  .fail
    mov  dword [rel nt_dir_blocks], 0
    mov  dword [rel nt_dirbm_bits], 0
    lea  rdi, [rel nt_rec_buf]
    mov  esi, NT_A_BITMAP
    call nt_dir_attr
    test rdx, rdx
    jnz  .fail
    test rax, rax
    jz   .allocation
    cmp  byte [rax + 8], 0
    jne  .fail                            ; nonresident bitmap unsupported
    mov  ecx, [rax + 16]
    test ecx, ecx
    jz   .fail
    cmp  ecx, NT_DIRBM
    ja   .fail                            ; never truncate coverage
    movzx edx, word [rax + 20]
    lea  rsi, [rax + rdx]
    lea  rdi, [rel nt_dirbm]
    mov  eax, ecx
    shl  eax, 3
    mov  [rel nt_dirbm_bits], eax
    rep  movsb
.allocation:
    lea  rdi, [rel nt_rec_buf]
    mov  esi, NT_A_INDEXALLOC
    call nt_dir_attr
    test rdx, rdx
    jnz  .fail
    test rax, rax
    jnz  .large
    cmp  dword [rel nt_dirbm_bits], 0
    jne  .fail
    cmp  dword [r12 + 28], 0              ; root must be a leaf
    jne  .fail
    xor  r13d, r13d
    jmp  .root
.large:
    mov  rbx, rax
    cmp  byte [rbx + 8], 1
    jne  .fail
    cmp  dword [r12 + 28], 1
    jne  .fail
    cmp  qword [rbx + 16], 0              ; no extension VCN
    jne  .fail
    cmp  word [rbx + 34], 0
    jne  .fail
    mov  r13, [rbx + 48]
    test r13, r13
    jz   .fail
    cmp  r13, [rbx + 40]
    ja   .fail
    cmp  r13, [rbx + 56]
    jne  .fail                            ; uninitialized index is unknown
    mov  rax, r13
    xor  edx, edx
    mov  ecx, [rel nt_idx_bytes]
    div  rcx
    test rdx, rdx
    jnz  .fail                            ; partial last index block
    cmp  rax, 4096
    ja   .fail
    cmp  byte [rel nt_tree_scope], 0
    je   .tree_bound_ok
    cmp  rax, NTT_BLOCKS
    ja   .tree_bound
.tree_bound_ok:
    cmp  eax, [rel nt_dirbm_bits]
    ja   .fail                            ; coverage cannot prove absence
    mov  [rel nt_dir_blocks], eax
    ; Bits beyond the allocation must be clear too.
    mov  ecx, eax
.bm_tail:
    cmp  ecx, [rel nt_dirbm_bits]
    jae  .decode
    lea  rdx, [rel nt_dirbm]
    bt   [rdx], ecx
    jc   .fail
    inc  ecx
    jmp  .bm_tail
.decode:
    movzx ecx, word [rbx + 32]
    lea  rdi, [rbx + rcx]
    mov  ecx, [rbx + 4]
    lea  rcx, [rbx + rcx]
    lea  rsi, [rel nt_runs]
    mov  edx, NT_MAX_RUNS
    call nt_decode_runlist
    test eax, eax
    jle  .fail
    mov  [rel nt_nruns], eax
    ; The complete plain allocation must be represented, including inactive
    ; blocks. A bitmap does not authorize silently missing/sparse extents.
    mov  rax, [rbx + 40]
    xor  edx, edx
    mov  ecx, [rel nt_clus_bytes]
    div  rcx
    test rdx, rdx
    jnz  .fail
    mov  r8, rax                         ; clusters left in declared allocation
    mov  rdx, [rbx + 24]
    inc  rdx
    jz   .fail
    cmp  rax, rdx
    jne  .fail
    lea  rdi, [rel nt_runs]
    mov  ecx, [rel nt_nruns]
.run_coverage:
    cmp  qword [rdi], 0
    jl   .fail                           ; no sparse/negative physical index run
    mov  rax, [rdi + 8]
    cmp  rax, r8
    ja   .fail
    sub  r8, rax
    add  rdi, 16
    dec  ecx
    jnz  .run_coverage
    test r8, r8
    jnz  .fail
.root:
    lea  rdi, [r12 + 16]
    mov  rsi, r15
    call nt_visit_node
    test rax, rax
    jnz  .fail
    xor  r14d, r14d
.blk_loop:
    cmp  r14d, [rel nt_dir_blocks]
    jae  .ok
    lea  rdx, [rel nt_dirbm]
    bt   [rdx], r14d
    jnc  .blk_next
    mov  eax, [rel nt_idx_bytes]
    imul rax, r14
    jo   .fail
    mov  rdx, rax
    lea  rdi, [rel nt_runs]
    mov  esi, [rel nt_nruns]
    lea  rcx, [rel nt_idx_buf]
    mov  r8d, [rel nt_idx_bytes]
    call nt_read_stream_record
    test rax, rax
    jnz  .fail
    cmp  dword [rel nt_idx_buf], 'INDX'
    jne  .fail
    ; USA itself must fit in this actual block, not stale 4 KiB buffer tail.
    mov  eax, [rel nt_idx_bytes]
    shr  eax, 9
    inc  eax
    cmp  [rel nt_idx_buf + 6], ax
    jne  .fail
    movzx ecx, word [rel nt_idx_buf + 4]
    cmp  ecx, 40
    jb   .fail
    lea  ecx, [rcx + rax*2]
    mov  eax, [rel nt_idx_buf + 24]
    add  eax, 24
    cmp  ecx, eax
    ja   .fail
    cmp  ecx, [rel nt_idx_bytes]
    ja   .fail
    ; Stored VCN is in clusters, or sectors for sub-cluster index blocks.
    mov  eax, [rel nt_idx_bytes]
    imul rax, r14
    mov  ecx, [rel nt_clus_bytes]
    cmp  ecx, [rel nt_idx_bytes]
    jbe  .vcn_unit
    mov  ecx, 512
.vcn_unit:
    xor  edx, edx
    div  rcx
    cmp  rax, [rel nt_idx_buf + 16]
    jne  .fail
    cmp  qword [rel nt_tree_frame], 0
    je   .tree_index_ok
    lea  rdi, [rel nt_idx_buf]
    mov  esi, [rel nt_idx_bytes]
    imul edx, r14d, 4096
    add  edx, NTT_INDEX
    call nt_tree_snapshot
    test rax, rax
    jnz  .fail
.tree_index_ok:
    lea  rdi, [rel nt_idx_buf]
    call nt_fixup
    test rax, rax
    jnz  .fail
    lea  rdi, [rel nt_idx_buf + 24]
    lea  rsi, [rel nt_idx_buf]
    mov  eax, [rel nt_idx_bytes]
    add  rsi, rax
    call nt_visit_node
    test rax, rax
    jnz  .fail
.blk_next:
    inc  r14d
    jmp  .blk_loop
.ok:
    xor  eax, eax
    jmp  .out
.tree_bound:
    mov  dword [rel ext4_disk_last_error], 7 ; explicit bounded traversal refusal
.fail:
    mov  byte [rel nt_write_armed], 0      ; failure revokes provisional admission
    cmp  dword [rel nt_walk_rec], NT_REC_ROOT
    jne  .error
    mov  byte [rel nt_hiber], 2
.error:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; nt_visit_node(RDI=node header, RSI=actual value/block end) -> 0/-1.
; A name match/list truncation is provisional until a valid terminal entry.
nt_visit_node:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  rax, rsi
    sub  rax, rdi
    cmp  rax, 16
    jb   .bad
    mov  ecx, [r12 + 8]                   ; allocated node extent
    cmp  rcx, rax
    ja   .bad
    mov  edx, [r12 + 4]
    cmp  edx, ecx
    ja   .bad
    mov  eax, [r12]
    cmp  eax, 16
    jb   .bad
    test al, 7
    jnz  .bad
    cmp  eax, edx
    jae  .bad
    cmp  dword [r12 + 12], 1
    ja   .bad
    lea  r13, [r12 + rax]
    lea  r14, [r12 + rdx]
.loop:
    lea  rax, [r13 + 16]
    cmp  rax, r14
    ja   .bad
    movzx eax, word [r13 + 8]
    cmp  eax, 16
    jb   .bad
    test al, 7
    jnz  .bad
    lea  r15, [r13 + rax]                 ; entry end
    cmp  r15, r14
    ja   .bad
    movzx edx, word [r13 + 12]
    test edx, ~3
    jnz  .bad
    cmp  word [r13 + 14], 0
    jne  .bad
    mov  ecx, edx
    and  ecx, 1
    cmp  ecx, [r12 + 12]
    jne  .bad                            ; child required for internal nodes
    test ecx, ecx
    jz   .key
    cmp  eax, 24
    jb   .bad
    mov  rax, [r15 - 8]                  ; child VCN
    mov  ecx, [rel nt_clus_bytes]
    cmp  ecx, [rel nt_idx_bytes]
    jbe  .child_unit
    mov  ecx, 512
.child_unit:
    mul  rcx
    test rdx, rdx
    jnz  .bad
    xor  edx, edx
    mov  ecx, [rel nt_idx_bytes]
    test ecx, ecx
    jz   .bad
    div  rcx
    test rdx, rdx
    jnz  .bad
    cmp  rax, 4096
    jae  .bad
    cmp  eax, [rel nt_dir_blocks]
    jae  .bad
    lea  rcx, [rel nt_dirbm]
    bt   [rcx], eax
    jnc  .bad
.key:
    movzx eax, word [r13 + 10]
    test word [r13 + 12], 2
    jnz  .terminal
    cmp  eax, 68                         ; FILE_NAME + nonempty UTF16 name
    jb   .bad
    lea  rcx, [r13 + rax + 16]
    mov  rdx, r15
    test word [r13 + 12], 1
    jz   .key_end
    sub  rdx, 8
.key_end:
    cmp  rcx, rdx
    ja   .bad
    movzx ecx, byte [r13 + 80]
    test ecx, ecx
    jz   .bad
    lea  edx, [rcx*2 + 66]
    cmp  eax, edx
    jne  .bad
    cmp  byte [r13 + 81], 3
    ja   .bad
    lea  rsi, [r13 + 82]
    call nt_key_utf8                       ; validate every key, including hidden/DOS
    test eax, eax
    js   .bad
    mov  [rel nt_utf8_bytes], eax
    cmp  byte [rel nt_visit_mode], NT_VISIT_LOOKUP
    je   .lookup
    cmp  byte [rel nt_visit_mode], NT_VISIT_TREE
    je   .tree
    ; ---------- LIST ----------
    movzx eax, byte [r13 + 0x10 + 0x41]    ; namespace
    cmp  al, 2
    je   .advance                          ; DOS-only duplicate of a long name
    cmp  word [r13 + 0x10 + 0x42], '$'     ; system files stay hidden
    je   .advance
    mov  rbx, [rel nt_list_ptr]
    test rbx, rbx
    jz   .advance
    mov  eax, [rel nt_list_count]
    cmp  eax, [rel nt_list_cap]
    jb   .list_room
    mov  dword [rel nt_list_trunc], 1
    jmp  .advance
.list_room:
    imul rax, rax, fs_dirent_size
    add  rbx, rax                          ; dirent slot
    mov  eax, [rel nt_list_names_used]
    mov  ecx, [rel nt_utf8_bytes]
    lea  edx, [rax + rcx + 1]
    cmp  edx, NT_LIST_NAMES_CAP
    ja   .omit                            ; never publish a partial identity/alias
    lea  rdi, [rel nt_list_names]
    add  rdi, rax
    mov  [rel nt_list_names_used], edx
    lea  rsi, [rel nt_utf8_name]
    inc  ecx                              ; complete NUL-terminated UTF8
    rep  movsb
    mov  byte [rbx + fs_dirent.name], 0
    cmp  dword [rel nt_utf8_bytes], 12
    ja   .inline_done
    lea  rdi, [rbx + fs_dirent.name]
    lea  rsi, [rel nt_utf8_name]
    mov  ecx, [rel nt_utf8_bytes]
    inc  ecx
    rep  movsb
.inline_done:
    mov  rax, [r13 + 0x10 + 0x30]          ; real size
    mov  [rbx + fs_dirent.size], rax
    mov  dword [rbx + fs_dirent.flags], 0
    mov  dword [rbx + fs_dirent.reserved], 0
    mov  eax, [r13 + 0x10 + 0x38]
    test eax, 0x10000000
    jz   .not_dir
    mov  dword [rbx + fs_dirent.flags], FS_DIRENT_DIR
.not_dir:
    mov  eax, [rel nt_list_names_used]
    sub  eax, [rel nt_utf8_bytes]
    dec  eax
    lea  rsi, [rel nt_list_names]
    add  rsi, rax
    mov  rdi, rbx
    call vfs_dirent_set_long_name
    inc  dword [rel nt_list_count]
    jmp  .advance
.omit:
    mov  dword [rel nt_list_trunc], 1
    jmp  .advance
    ; ---------- complete TREE cursor (no system-name hiding/list capacity) ----------
.tree:
    call nt_tree_visit
    test rax, rax
    jnz  .bad
    jmp  .advance
    ; ---------- LOOKUP ----------
.lookup:
    mov  ecx, [rel nt_utf8_bytes]
    cmp  ecx, [rel nt_match_len]
    jne  .advance
    lea  rsi, [rel nt_utf8_name]
    lea  rdi, [rel nt_match_name]
    xor  edx, edx
.cmp:
    cmp  edx, ecx
    jae  .match
    mov  al, [rsi + rdx]
    ; Canonical UTF8 compares exactly. The path resolver folds ASCII input;
    ; legacy name11/internal cstrings retain their uppercase input contract.
    cmp  al, 'a'
    jb   .compare
    cmp  al, 'z'
    ja   .compare
    sub  al, 0x20
.compare:
    cmp  al, [rdi + rdx]
    jne  .advance
    inc  edx
    jmp  .cmp
.match:
    cmp  byte [rel nt_found], 1
    jne  .new_match
    ; Namespace duplicates may name the same full reference, never another file.
    movzx eax, word [rel nt_found_sequence]
    shl  rax, 48
    or   rax, [rel nt_found_ref]
    cmp  rax, [r13]
    jne  .bad
    jmp  .advance
.new_match:
    mov  rax, [r13]
    shr  rax, 48
    mov  [rel nt_found_sequence], ax
    mov  rax, [r13]
    mov  rdx, 0x0000FFFFFFFFFFFF
    and  rax, rdx
    mov  [rel nt_found_ref], rax
    mov  rax, [r13 + 0x10 + 0x30]
    mov  [rel nt_found_size], rax
    mov  byte [rel nt_found_isdir], 0
    mov  eax, [r13 + 0x10 + 0x38]
    test eax, 0x10000000
    jz   .set_found
    mov  byte [rel nt_found_isdir], 1
.set_found:
    mov  byte [rel nt_found], 1
    jmp  .advance
.advance:
    mov  r13, r15
    jmp  .loop                            ; exhaustion without terminal is failure
.terminal:
    test eax, eax
    jnz  .bad
    mov  eax, 16
    test word [r13 + 12], 1
    jz   .terminal_len
    add  eax, 8
.terminal_len:
    cmp  ax, [r13 + 8]
    jne  .bad
    cmp  r15, r14
    jne  .bad
    xor  eax, eax
    jmp  .done
.bad:
    mov  rax, -1
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Complete bounded UTF16 FILE_NAME -> canonical UTF8 in nt_utf8_name.
; RSI points to ECX already span-checked units (1..255). EAX bytes / -1.
; A high surrogate MUST have its low pair, never a replacement/low-byte alias.
nt_key_utf8:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r14, rsi
    mov  r12d, ecx
    xor  r13d, r13d
    xor  ebx, ebx
.scalar:
    cmp  r13d, r12d
    jae  .ok
    movzx edi, word [r14 + r13*2]
    inc  r13d
    test edi, edi
    jz   .bad
    cmp  edi, 0xD800
    jb   .encode
    cmp  edi, 0xDFFF
    ja   .encode
    cmp  edi, 0xDBFF
    ja   .bad
    cmp  r13d, r12d
    jae  .bad
    movzx eax, word [r14 + r13*2]
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
    lea  rsi, [rel nt_utf8_name]
    add  rsi, rbx
    mov  edx, NT_NAME_MAX
    sub  edx, ebx
    call ue_utf8_encode
    test eax, eax
    js   .bad
    add  ebx, eax
    jmp  .scalar
.ok:
    lea  rax, [rel nt_utf8_name]
    mov  byte [rax + rbx], 0
    mov  eax, ebx
    jmp  .out
.bad:
    mov  byte [rel nt_utf8_name], 0
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; nt_lookup_root_ascii(RDI=uppercase ASCII cstr) -> RAX 0 found / -1 (in the root).
nt_lookup_root_ascii:
    mov  esi, NT_REC_ROOT
; nt_lookup_dir_ascii(RDI=uppercase ASCII cstr, ESI=directory FILE record) -> 0/-1.
nt_lookup_dir_ascii:
    push rbx
    mov  byte [rel nt_lookup_complete], 0
    mov  [rel nt_walk_rec], esi
    mov  rbx, rdi
    xor  ecx, ecx
.len:
    cmp  byte [rbx + rcx], 0
    je   .len_done
    inc  ecx
    cmp  ecx, NT_NAME_MAX + 1
    jb   .len
    jmp  .fail
.len_done:
    test ecx, ecx
    jz   .fail
    push rcx
    mov  rdi, rbx
    mov  esi, ecx
    call ue_utf8_validate
    pop  rcx
    cmp  eax, 1
    jne  .fail
    mov  [rel nt_match_len], ecx
    lea  rdi, [rel nt_match_name]
    mov  rsi, rbx
    rep  movsb
    mov  byte [rdi], 0
    mov  byte [rel nt_found], 0
    mov  byte [rel nt_visit_mode], NT_VISIT_LOOKUP
    call nt_walk_root
    test rax, rax
    jnz  .fail
    mov  byte [rel nt_lookup_complete], 1
    cmp  byte [rel nt_found], 1
    jne  .fail
    ; An index key is a reference, not authority for the current FILE identity.
    ; Validate before stat, read or a later component can use/narrow it.
    call nt_lookup_ref
    test rax, rax
    jnz  .fail
    xor  eax, eax
    pop  rbx
    ret
.fail:
    mov  rax, -1
    pop  rbx
    ret

; nt_lookup_name11(RSI=FAT name11) -> RAX 0 found / -1. "NAME    EXT" -> "NAME.EXT".
;   When a path op already resolved the leaf (nt_lookup_pre = 1) the found_* state
;   is reused as-is, so every name11 op body doubles as the path op body.
nt_lookup_name11:
    push rbx
    cmp  byte [rel nt_lookup_pre], 1
    jne  .by_name
    xor  eax, eax
    pop  rbx
    ret
.by_name:
    lea  rdi, [rel nt_name_scratch]
    xor  ecx, ecx
    xor  edx, edx
.base:
    cmp  ecx, 8
    jae  .base_done
    mov  al, [rsi + rcx]
    cmp  al, ' '
    je   .base_done
    mov  [rdi + rdx], al
    inc  edx
    inc  ecx
    jmp  .base
.base_done:
    cmp  byte [rsi + 8], ' '
    je   .no_ext
    mov  byte [rdi + rdx], '.'
    inc  edx
    mov  ecx, 8
.ext:
    cmp  ecx, 11
    jae  .no_ext
    mov  al, [rsi + rcx]
    cmp  al, ' '
    je   .no_ext
    mov  [rdi + rdx], al
    inc  edx
    inc  ecx
    jmp  .ext
.no_ext:
    mov  byte [rdi + rdx], 0
    lea  rdi, [rel nt_name_scratch]
    call nt_lookup_root_ascii
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; nt_data_read_at(RDX=off, RCX=buf, R8=len) on the FILE record in nt_rec_buf
;   -> RAX bytes delivered / -1. Resident + non-resident unnamed $DATA; sparse
;   runs and bytes past initialized_size read as zeros; refuses compressed /
;   encrypted streams and attribute lists.
; ---------------------------------------------------------------------------
; nt_data_attr_admit(RDI=FILE, RSI=actual end) -> RAX=unique unnamed DATA/0.
; Full metadata admission precedes even EOF/zero-cap reads. No caller bytes or
; device I/O here. Failed admission invalidates the decoded DATA run count.
; FILE bytes have already passed the loader's exact USA restoration.
nt_data_attr_admit:
    push rbx
    push r12
    xor  ebx, ebx
    mov  dword [rel nt_nruns], 0
    mov  r8, rsi
    sub  r8, rdi
    cmp  r8, 1024
    jb   .bad
    cmp  r8, NT_RECBUF
    ja   .bad
    test r8d, 511
    jnz  .bad
    cmp  dword [rdi], 'FILE'
    jne  .bad
    cmp  qword [rel nt_data_stream], 0
    je   .file_flags
    cmp  word [rdi + 22], 9               ; explicit stream of a view-index FILE
    je   .in_use
.file_flags:
    cmp  word [rdi + 22], 1
    jne  .bad
.in_use:
    cmp  qword [rdi + 32], 0
    jne  .bad
    mov  eax, [rdi + 28]
    cmp  rax, r8
    jne  .bad
    mov  eax, [rdi + 24]
    cmp  rax, r8
    ja   .bad
    lea  r8, [rdi + rax]                  ; actual bytes in use
    movzx eax, word [rdi + 20]
    cmp  eax, 48
    jb   .bad
    test al, 7
    jnz  .bad
    mov  r9, r8
    sub  r9, rdi                         ; bytes in use
    mov  r10, rsi
    sub  r10, rdi                        ; actual FILE extent
    shr  r10, 9
    inc  r10d
    cmp  [rdi + 6], r10w
    jne  .bad
    movzx ecx, word [rdi + 4]
    cmp  ecx, 48
    jb   .bad
    lea  ecx, [rcx + r10*2]
    cmp  ecx, eax                        ; USA cannot overlap attributes
    ja   .bad
    cmp  rcx, r9
    ja   .bad
    add  rdi, rax
.loop:
    lea  rax, [rdi + 4]
    cmp  rax, r8
    ja   .bad
    cmp  dword [rdi], -1
    je   .ok
    lea  rax, [rdi + 16]
    cmp  rax, r8
    ja   .bad
    cmp  dword [rdi], NT_A_ATTRLIST
    je   .bad                            ; extension records unsupported
    mov  eax, [rdi + 4]
    test al, 7
    jnz  .bad
    lea  r9, [rdi + rax]
    cmp  r9, r8
    ja   .bad
    cmp  byte [rdi + 8], 1
    ja   .bad
    mov  ecx, 24
    cmp  byte [rdi + 8], 0
    je   .header
    mov  ecx, 64
    test word [rdi + 12], 0x8001
    jz   .header
    mov  ecx, 72                          ; sparse/compressed extended header
.header:
    cmp  eax, ecx
    jb   .bad
    mov  r10d, ecx
    movzx edx, byte [rdi + 9]
    test edx, edx
    jz   .value
    movzx r11d, word [rdi + 10]
    cmp  r11d, ecx
    jb   .bad
    lea  r10d, [r11 + rdx*2]
    cmp  r10d, eax
    ja   .bad
.value:
    cmp  byte [rdi + 8], 0
    jne  .runs
    movzx edx, word [rdi + 20]
    cmp  edx, r10d
    jb   .bad
    mov  ecx, [rdi + 16]
    add  rcx, rdx
    cmp  rcx, rax
    ja   .bad
    jmp  .next
.runs:
    movzx edx, word [rdi + 32]
    cmp  edx, r10d
    jb   .bad
    cmp  edx, eax
    jae  .bad
.next:
    cmp  dword [rdi], NT_A_DATA
    jne  .advance
    cmp  qword [rel nt_data_stream], 0
    je   .unnamed
    cmp  byte [rdi + 9], 4                ; explicit 4-character stream name
    jne  .advance
    movzx eax, word [rdi + 10]            ; name span bounded above
    mov  rax, [rdi + rax]
    cmp  rax, [rel nt_data_stream]
    jne  .advance
    jmp  .selected
.unnamed:
    cmp  byte [rdi + 9], 0
    jne  .advance                         ; named streams do not replace DATA
.selected:
    test rbx, rbx
    jnz  .bad                             ; ambiguous duplicate unnamed DATA
    mov  rbx, rdi
.advance:
    mov  rdi, r9
    jmp  .loop
.ok:
    test rbx, rbx
    jz   .bad
    test word [rbx + 12], 0x7FFF           ; only ordinary/sparse DATA supported
    jnz  .bad
    cmp  byte [rbx + 8], 0
    jne  .nonresident
    cmp  word [rbx + 12], 0
    jne  .bad                             ; resident DATA has no sparse mapping
    jmp  .good
.nonresident:
    cmp  qword [rbx + 16], 0               ; extension stream not implemented
    jne  .bad
    cmp  byte [rbx + 34], 0                ; no compression-unit interpretation
    jne  .bad
    mov  rax, [rbx + 40]                   ; virtual allocation includes holes
    test rax, rax
    js   .bad
    mov  ecx, [rel nt_clus_bytes]
    test ecx, ecx
    jz   .bad
    xor  edx, edx
    div  rcx
    test rdx, rdx
    jnz  .bad
    mov  rax, [rbx + 48]
    cmp  rax, [rbx + 40]
    ja   .bad
    mov  rdx, [rbx + 56]
    cmp  rdx, rax
    ja   .bad
    movzx ecx, word [rbx + 32]
    lea  rdi, [rbx + rcx]
    mov  ecx, [rbx + 4]
    lea  rcx, [rbx + rcx]
    lea  rsi, [rel nt_runs]
    mov  edx, NT_MAX_RUNS
    call nt_decode_runlist
    test eax, eax
    js   .bad
    mov  r12d, eax
    lea  rdi, [rel nt_runs]
    mov  ecx, eax
    xor  r8d, r8d                         ; total virtual clusters
    xor  r9d, r9d                         ; allocated physical clusters
    test ecx, ecx
    jz   .coverage
.sum:
    mov  rax, [rdi + 8]
    add  r8, rax                          ; decoder has validated all arithmetic
    cmp  qword [rdi], -1
    je   .hole
    add  r9, rax
.hole:
    add  rdi, 16
    dec  ecx
    jnz  .sum
.coverage:
    mov  rax, [rbx + 24]
    inc  rax                              ; empty stream uses HighestVcn=-1
    jz   .empty
    test rax, rax
    js   .bad
    cmp  rax, r8
    jne  .bad
    jmp  .allocation
.empty:
    test r8, r8
    jnz  .bad
.allocation:
    mov  ecx, [rel nt_clus_bytes]
    imul r8, rcx
    cmp  r8, [rbx + 40]
    jne  .bad                             ; complete single-segment coverage
    test word [rbx + 12], 0x8000
    jz   .publish
    imul r9, rcx
    cmp  r9, [rbx + 64]                    ; sparse physical allocation
    jne  .bad
.publish:
    mov  [rel nt_nruns], r12d
.good:
    mov  rax, rbx
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

nt_data_read_at:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdx                          ; off
    mov  r13, rcx                          ; buf
    mov  r14, r8                           ; len
    lea  rdi, [rel nt_rec_buf]
    mov  esi, [rel nt_rec_bytes]
    add  rsi, rdi
    call nt_data_attr_admit
    test rax, rax
    jz   .fail
    mov  rbx, rax
    cmp  byte [rbx + 8], 0
    jne  .nonres
    ; ---- resident ----
    mov  eax, [rbx + 0x10]                 ; value length
    cmp  r12, rax
    jae  .zero_len
    sub  rax, r12
    cmp  r14, rax
    jbe  .res_len_ok
    mov  r14, rax
.res_len_ok:
    movzx ecx, word [rbx + 0x14]
    lea  rsi, [rbx + rcx]
    add  rsi, r12
    mov  rdi, r13
    mov  rcx, r14
    rep  movsb
    mov  rax, r14
    jmp  .out
.nonres:
    mov  rax, [rbx + 0x30]                 ; data size
    cmp  r12, rax
    jae  .zero_len
    sub  rax, r12
    cmp  r14, rax
    jbe  .nr_len_ok
    mov  r14, rax                          ; clamp to EOF
.nr_len_ok:
    mov  r15, [rbx + 0x38]                 ; initialized size
    xor  ebx, ebx                          ; delivered
.chunk:
    cmp  rbx, r14
    jae  .done_nr
    lea  rdx, [r12 + rbx]                  ; absolute byte offset
    cmp  rdx, r15
    jae  .zeros_tail                       ; past initialized size -> zeros
    lea  rdi, [rel nt_runs]
    mov  esi, [rel nt_nruns]
    call nt_vcn_to_lba
    cmp  rax, -2
    je   .fail
    cmp  rax, -1
    je   .sparse_chunk
    ; rax = sector lba, rdx = bytes left in run from the sector start, rcx = byte in sector
    mov  r8, rdx
    mov  r9, rcx
    mov  r10, r14
    sub  r10, rbx                          ; remaining wanted
    ; how many bytes can this bounce deliver: min(remaining, run-left - inSector, 4096 - inSector)
    mov  r11, NT_SECBUF
    sub  r11, r9
    cmp  r10, r11
    jbe  .c1
    mov  r10, r11
.c1:
    mov  r11, r8
    sub  r11, r9
    cmp  r10, r11
    jbe  .c2
    mov  r10, r11
.c2:
    ; Never copy physical bytes beyond initialized_size. The next iteration
    ; zeroes that logical tail, even when the boundary is inside a sector.
    mov  r11, r15
    sub  r11, r12
    sub  r11, rbx                          ; initialized bytes from this offset
    cmp  r10, r11
    jbe  .init_len
    mov  r10, r11
.init_len:
    ; sectors to read = ceil((inSector + take) / 512)
    lea  rdx, [r9 + r10 + 511]
    shr  rdx, 9
    mov  rsi, rax
    lea  rcx, [rel nt_sec_buf]
    push r9
    push r10
    call nt_read
    pop  r10
    pop  r9
    test rax, rax
    jnz  .fail
    lea  rsi, [rel nt_sec_buf]
    add  rsi, r9
    lea  rdi, [r13 + rbx]
    mov  rcx, r10
    rep  movsb
    add  rbx, r10
    jmp  .chunk
.sparse_chunk:
    ; rdx = sparse bytes left from this byte
    mov  r10, r14
    sub  r10, rbx
    cmp  r10, rdx
    jbe  .sp_len
    mov  r10, rdx
.sp_len:
    lea  rdi, [r13 + rbx]
    mov  rcx, r10
    xor  eax, eax
    rep  stosb
    add  rbx, r10
    jmp  .chunk
.zeros_tail:
    lea  rdi, [r13 + rbx]
    mov  rcx, r14
    sub  rcx, rbx
    xor  eax, eax
    rep  stosb
    mov  rbx, r14
.done_nr:
    mov  rax, rbx
    jmp  .out
.zero_len:
    xor  eax, eax
    jmp  .out
.refuse_attrlist:
    lea  rdi, [rel str_nt_refuse_attrlist]
    call nt_once_refusal
    jmp  .fail
.refuse_flags:
    lea  rdi, [rel str_nt_refuse_flags]
    call nt_once_refusal
    jmp  .fail
.refuse_runs:
    lea  rdi, [rel str_nt_refuse_runs]
    call nt_once_refusal
.fail:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; nt_once_refusal(RDI=cstr): bounded (8 per boot) honest refusal lines.
nt_once_refusal:
    cmp  byte [rel nt_refusal_count], 8
    jae  .skip
    inc  byte [rel nt_refusal_count]
    call serial_string
.skip:
    ret

; ---------------------------------------------------------------------------
; fs_ops implementation
; ---------------------------------------------------------------------------
nt_build_ops:
    lea  rdi, [rel nt_ops]
    lea  rax, [rel str_nt_backend]
    mov  [rdi + fs_ops.name], rax
    lea  rax, [rel nt_op_mount]
    mov  [rdi + fs_ops.mount], rax
    lea  rax, [rel nt_op_readfile]
    mov  [rdi + fs_ops.readfile], rax
    lea  rax, [rel nt_op_unsupported]
    mov  [rdi + fs_ops.writefile], rax
    lea  rax, [rel nt_op_unsupported]
    mov  [rdi + fs_ops.delete], rax
    lea  rax, [rel nt_op_stat]
    mov  [rdi + fs_ops.stat], rax
    lea  rax, [rel nt_op_read_at]
    mov  [rdi + fs_ops.read_at], rax
    lea  rax, [rel nt_op_info]
    mov  [rdi + fs_ops.info], rax
    lea  rax, [rel nt_op_list_root]
    mov  [rdi + fs_ops.list_root], rax
    lea  rax, [rel nt_op_write_at]
    mov  [rdi + fs_ops.write_at], rax
    lea  rax, [rel nt_op_stat_path]        ; v1.1 path slots (additive tail)
    mov  [rdi + fs_ops.stat_path], rax
    lea  rax, [rel nt_op_read_at_path]
    mov  [rdi + fs_ops.read_at_path], rax
    lea  rax, [rel nt_op_write_at_path]
    mov  [rdi + fs_ops.write_at_path], rax
    lea  rax, [rel nt_op_list_dir]
    mov  [rdi + fs_ops.list_dir], rax
    lea  rax, [rel nt_op_update]
    mov  [rdi + fs_ops.update], rax
    lea  rax, [rel nt_op_mutate_path]
    mov  [rdi + fs_ops.mutate_path], rax
    lea  rax, [rel nt_op_save_armed]
    mov  [rdi + fs_ops.mutate_armed], rax
    lea  rax, [rel small_copy]
    mov  [rdi + fs_ops.copy], rax
    lea  rax, [rel small_copy_between]
    mov  [rdi + fs_ops.copy_between], rax
    ret

nt_op_mount:
    xor  eax, eax
    cmp  byte [rel nt_mounted], 1
    je   .ok
    mov  rax, -1
.ok:
    ret

nt_op_unsupported:
    mov  rax, -1
    ret

; stat(self, RSI=name11, RDX=fs_stat*) -> 0/-1
nt_op_stat:
    push rbx
    mov  rbx, rdx
    cmp  byte [rel nt_mounted], 1
    jne  .fail
    call nt_lookup_name11
    test rax, rax
    jnz  .fail
    mov  rax, [rel nt_found_size]
    mov  [rbx + fs_stat.size], rax
    mov  dword [rbx + fs_stat.flags], 0
    cmp  byte [rel nt_write_armed], 1
    je   .rw
    mov  dword [rbx + fs_stat.flags], FS_STAT_READONLY
.rw:
    movzx eax, byte [rel nt_found_isdir]
    mov  [rbx + fs_stat.reserved], eax     ; 1 = directory (paths can stat directories)
    xor  eax, eax
    pop  rbx
    ret
.fail:
    mov  rax, -1
    pop  rbx
    ret

; readfile(self, RSI=name11, RDX=buf, RCX=cap) -> len / -1
nt_op_readfile:
    mov  r8, rcx
    mov  rcx, rdx
    xor  edx, edx
    ; fallthrough into read_at with off=0

; read_at(self, RSI=name11, RDX=off, RCX=buf, R8=len) -> len / -1
nt_op_read_at:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdx
    mov  r13, rcx
    mov  r14, r8
    cmp  byte [rel nt_mounted], 1
    jne  .fail
    call nt_lookup_name11
    test rax, rax
    jnz  .fail
    cmp  byte [rel nt_found_isdir], 1
    je   .fail
    call nt_lookup_ref                    ; recheck the FILE loaded for DATA
    test rax, rax
    jnz  .fail
    mov  rdx, r12
    mov  rcx, r13
    mov  r8, r14
    call nt_data_read_at
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
nt_op_info:
    ; Publish a count only after the complete selected-volume read succeeds.
    mov  qword [rsi + fs_info.free_clusters], -1
    push rsi
    call nt_space_count
    pop  rsi
    test rax, rax
    js   .fail
    mov  [rsi + fs_info.free_clusters], rax
    lea  rax, [rel str_nt_backend]
    mov  [rsi + fs_info.backend], rax
    mov  rax, [rel nt_dev]
    mov  [rsi + fs_info.device], rax
    mov  qword [rsi + fs_info.part_type], 0x07
    mov  rax, [rel nt_serial]
    mov  [rsi + fs_info.volume_id], eax
    mov  eax, [rel nt_clus_bytes]
    mov  [rsi + fs_info.cluster_bytes], eax
    mov  rax, [rel nt_total_sectors]
    mov  [rsi + fs_info.total_sectors], rax
    mov  rax, [rel nt_part_lba]
    mov  [rsi + fs_info.part_start], rax
    mov  rax, [rel nt_part_sectors]
    mov  [rsi + fs_info.part_sectors], rax
    mov  eax, [rel nt_scheme]
    mov  [rsi + fs_info.scheme], eax
    mov  dword [rsi + fs_info.part_count], 1
    xor  eax, eax
    ret
.fail:
    mov  rax, -1
    ret

; list_root(self, RSI=fs_dirent[], EDX=cap, RCX=fs_list_result*) -> 0/-1
nt_op_list_root:
    push rbx
    mov  rbx, rcx
    cmp  byte [rel nt_mounted], 1
    jne  .fail
    mov  dword [rel nt_walk_rec], NT_REC_ROOT
    mov  [rel nt_list_ptr], rsi
    mov  [rel nt_list_cap], edx
    mov  dword [rel nt_list_count], 0
    mov  dword [rel nt_list_trunc], 0
    mov  dword [rel nt_list_names_used], 0
    mov  byte [rel nt_visit_mode], NT_VISIT_LIST
    call nt_walk_root
    mov  qword [rel nt_list_ptr], 0
    test rax, rax
    jnz  .fail
    mov  eax, [rel nt_list_count]
    mov  [rbx + fs_list_result.count], eax
    mov  eax, [rel nt_list_trunc]
    mov  [rbx + fs_list_result.truncated], eax
    mov  dword [rbx + fs_list_result.names_short], 0
    xor  eax, eax
    pop  rbx
    ret
.fail:
    mov  rax, -1
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; Paths (v1.1, 2026-09-07 evening): "/DIR/SUB/FILE.EXT" resolved one $I30 lookup
; per component from the root. Strict UTF-8, ASCII case-insensitive, every namespace
; (so long names resolve too); '\' accepted as a separator. Read paths contain
; <=NT_READ_PATH_CAP-1 UTF-8 bytes EXCLUDING NUL; input need not be terminated.
; The scratch CAP includes one appended NUL. Components contain <=NT_NAME_MAX
; UTF-8 bytes (255 UTF-16 units on disk). Mutation callers use their own bounded
; adapter below, retaining NT_MUT_PATH_MAX and ASCII <=63-byte components.
; The path ops resolve the leaf, then reuse the name11 op
; bodies with the lookup pre-done (nt_lookup_pre), so there is ONE read path
; and ONE write path in this module, whichever way a file is named.
; ---------------------------------------------------------------------------
; nt_resolve_path(RSI=path bytes, EDX=len) -> RAX 0/-1; leaves nt_found_ref /
;   nt_found_size / nt_found_isdir on the leaf ("/" or "" = the root itself).
nt_resolve_path:
    push rbx
    push r12
    push r13
    cmp  edx, NT_READ_PATH_CAP - 1
    ja   .fail
    push rsi
    push rdx
    mov  rdi, rsi
    mov  esi, edx
    call ue_utf8_validate
    pop  rdx
    pop  rsi
    cmp  eax, 1
    jne  .fail
    lea  rdi, [rel nt_path_buf]
    xor  ecx, ecx
.cp:
    cmp  ecx, edx
    jae  .cp_done
    movzx eax, byte [rsi + rcx]
    test al, al
    jz   .fail                            ; explicit span must not hide a suffix
    cmp  al, 'a'
    jb   .cp_case
    cmp  al, 'z'
    ja   .cp_case
    sub  al, 0x20
.cp_case:
    cmp  al, '\'
    jne  .cp_store
    mov  al, '/'
.cp_store:
    mov  [rdi + rcx], al
    inc  ecx
    jmp  .cp
.cp_done:
    mov  byte [rdi + rcx], 0
    mov  r12, rdi                          ; cursor
    mov  qword [rel nt_found_ref], NT_REC_ROOT
    mov  qword [rel nt_found_size], 0
    mov  byte [rel nt_found_isdir], 1
    mov  byte [rel nt_found], 1
.comp:
    cmp  byte [r12], '/'
    jne  .comp_start
    inc  r12
    jmp  .comp
.comp_start:
    cmp  byte [r12], 0
    je   .ok                               ; nothing left: the current leaf is the answer
    cmp  byte [rel nt_found_isdir], 1
    jne  .fail                             ; can only descend into a directory
    mov  r13d, [rel nt_found_ref]
    lea  rdi, [rel nt_comp_buf]
    xor  ecx, ecx
.cc:
    mov  al, [r12 + rcx]
    test al, al
    jz   .cc_done
    cmp  al, '/'
    je   .cc_done
    cmp  ecx, NT_NAME_MAX
    jae  .fail
    mov  [rdi + rcx], al
    inc  ecx
    jmp  .cc
.cc_done:
    mov  byte [rdi + rcx], 0
    add  r12, rcx
    mov  [rel nt_path_parent], r13d
    lea  rdi, [rel nt_comp_buf]
    mov  esi, r13d
    call nt_lookup_dir_ascii
    test rax, rax
    jnz  .fail
    jmp  .comp
.ok:
    xor  eax, eax
    jmp  .out
.fail:
    mov  byte [rel nt_found], 0
    mov  rax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Mutation-only resolver admission. Keep this bound separate from the read
; capacity: direct backend writes and all staged UPDATE/rename/namespace paths
; must never inherit longer or non-ASCII read paths. No I/O or grants here.
nt_resolve_mutation_path:
    cmp  edx, NT_MUT_PATH_MAX
    ja   .fail
    call nt_mutation_ascii
    test rax, rax
    jnz  .fail
    jmp  nt_resolve_path
.fail:
    mov  byte [rel nt_found], 0
    mov  rax, -1
    ret

; stat_path(self, RSI=path, EDX=len, RCX=fs_stat*) -> 0/-1
nt_op_stat_path:
    push rbx
    mov  rbx, rcx
    cmp  byte [rel nt_mounted], 1
    jne  .fail
    call nt_resolve_path
    test rax, rax
    jnz  .fail
    mov  byte [rel nt_lookup_pre], 1
    mov  rdx, rbx
    call nt_op_stat
    mov  byte [rel nt_lookup_pre], 0
    pop  rbx
    ret
.fail:
    mov  rax, -1
    pop  rbx
    ret

; read_at_path(self, RSI=path, EDX=len, RCX=off, R8=buf, R9=len) -> len/-1
nt_op_read_at_path:
    push rbx
    push r12
    push r13
    mov  rbx, rcx
    mov  r12, r8
    mov  r13, r9
    cmp  byte [rel nt_mounted], 1
    jne  .fail
    call nt_resolve_path
    test rax, rax
    jnz  .fail
    mov  byte [rel nt_lookup_pre], 1
    mov  rdx, rbx
    mov  rcx, r12
    mov  r8, r13
    call nt_op_read_at
    mov  byte [rel nt_lookup_pre], 0
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; RSI/EDX explicit bytes -> 0/-1, arguments unchanged; no I/O or grants.
; Mutations deliberately keep their pre-Unicode ASCII boundary.
nt_mutation_ascii:
    test edx, edx
    jz   .empty
    test rsi, rsi
    jz   .null
    push rcx
    push rbx
    xor  ecx, ecx
    xor  ebx, ebx
.loop:
    cmp  ecx, edx
    jae  .yes
    movzx eax, byte [rsi + rcx]
    cmp  eax, 0x7F                        ; old key matcher also refused DEL
    jae  .no
    cmp  al, '/'
    je   .separator
    cmp  al, '\'
    je   .separator
    inc  ebx
    cmp  ebx, 63                          ; retain original write resolver bound
    ja   .no
    jmp  .next
.separator:
    xor  ebx, ebx
.next:
    inc  ecx
    jmp  .loop
.yes:
    xor  eax, eax
    jmp  .out
.no:
    mov  rax, -1
.out:
    pop  rbx
    pop  rcx
    ret
.empty:
    xor  eax, eax
    ret
.null:
    mov  rax, -1
    ret

; write_at_path(self, RSI=path, EDX=len, RCX=off, R8=buf, R9=len) -> len/-1
;   (same gates and read-back verification as write_at; NT_WREF_NOFILE when the
;   path does not resolve)
nt_op_write_at_path:
    push rbx
    push r12
    push r13
    mov  rbx, rcx
    mov  r12, r8
    mov  r13, r9
    mov  dword [rel nt_wref], NT_WREF_NOFILE
    cmp  byte [rel nt_mounted], 1
    jne  .fail
    cmp  edx, NT_MUT_PATH_MAX
    ja   .fail
    call nt_mutation_ascii
    test rax, rax
    jnz  .fail
    call nt_resolve_mutation_path
    test rax, rax
    jnz  .fail
    mov  byte [rel nt_lookup_pre], 1
    mov  rdx, rbx
    mov  rcx, r12
    mov  r8, r13
    call nt_op_write_at
    mov  byte [rel nt_lookup_pre], 0
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; list_dir(self, RSI=path, EDX=len, RCX=fs_dirent[], R8D=cap, R9=fs_list_result*) -> 0/-1
nt_op_list_dir:
    push rbx
    push r12
    push r13
    mov  rbx, r9
    mov  r12, rcx
    mov  r13d, r8d
    cmp  byte [rel nt_mounted], 1
    jne  .fail
    call nt_resolve_path
    test rax, rax
    jnz  .fail
    cmp  byte [rel nt_found_isdir], 1
    jne  .fail                             ; a file is not listable
    mov  eax, [rel nt_found_ref]
    mov  [rel nt_walk_rec], eax
    mov  [rel nt_list_ptr], r12
    mov  [rel nt_list_cap], r13d
    mov  dword [rel nt_list_count], 0
    mov  dword [rel nt_list_trunc], 0
    mov  dword [rel nt_list_names_used], 0
    mov  byte [rel nt_visit_mode], NT_VISIT_LIST
    call nt_walk_root
    mov  qword [rel nt_list_ptr], 0
    mov  dword [rel nt_walk_rec], NT_REC_ROOT
    test rax, rax
    jnz  .fail
    mov  eax, [rel nt_list_count]
    mov  [rbx + fs_list_result.count], eax
    mov  eax, [rel nt_list_trunc]
    mov  [rbx + fs_list_result.truncated], eax
    mov  dword [rbx + fs_list_result.names_short], 0
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; write_at(self, RSI=name11, RDX=off, RCX=buf, R8=len) -> RAX len / -1.
; THE SAFE SUBSET: in-place overwrite inside existing, initialized, plainly
; allocated nonresident $DATA extents, or validated resident FILE staging;
; whole-file resident resize also stages the bounded parent size cache.
; ---------------------------------------------------------------------------
nt_op_write_at:
    xor  r9d, r9d                         ; range-write ABI unchanged
.whole:                                    ; R9=1: whole-file update
    push rbx
    push r12
    push r13
    push r14
    push r15
    push r9                              ; whole-file mode, private to this frame
    mov  r12, rdx                          ; off
    mov  r13, rcx                          ; buf
    mov  r14, r8                           ; len
    mov  dword [rel nt_wref], 0
    cmp  byte [rel nt_mounted], 1
    jne  .fail
    cmp  byte [rel nt_lookup_pre], 1
    je   .ascii_ready
    push rdx
    mov  edx, 11
    call nt_mutation_ascii
    pop  rdx
    test rax, rax
    jnz  .fail
.ascii_ready:
    cmp  byte [rel nt_write_armed], 1
    je   .armed
    mov  dword [rel nt_wref], NT_WREF_NOTARMED
    jmp  .refused
.armed:
    test r14, r14
    jnz  .lookup
    cmp  qword [rsp], 0
    je   .zero
.lookup:
    call nt_lookup_name11
    test rax, rax
    jnz  .nofile
    cmp  byte [rel nt_found_isdir], 1
    je   .nofile
    mov  edi, [rel nt_found_ref]
    call nt_read_record
    test rax, rax
    jnz  .nofile
    lea  rdi, [rel nt_rec_buf]
    mov  esi, NT_A_ATTRLIST
    call nt_has_attr
    test eax, eax
    jz   .no_attrlist
    mov  dword [rel nt_wref], NT_WREF_ATTRLIST
    jmp  .refused
.no_attrlist:
    lea  rdi, [rel nt_rec_buf]
    mov  esi, NT_A_DATA
    call nt_find_attr
    test rax, rax
    jz   .nofile
    mov  rbx, rax
    cmp  byte [rbx + 8], 0
    jne  .nonres
    mov  r9, [rsp]
    call nt_resident_write
    test rax, rax
    js   .refused
    jmp  .out
.nonres:
    cmp  qword [rsp], 0
    je   .nonres_same
    test r14, r14
    jz   .nonres_resize
    cmp  r14, [rbx + 48]
    jne  .nonres_resize
    cmp  r14, [rbx + 56]
    je   .nonres_same
.nonres_resize:
    mov  r9, [rsp]
    call nt_nonresident_resize
    test rax, rax
    js   .refused
    jmp  .out
.nonres_same:
    test r14, r14
    jz   .range                           ; zero-length growth/truncate is resident only
    movzx eax, word [rbx + 0x0C]
    test ax, 0xC001                        ; compressed | encrypted | sparse-flag
    jz   .flags_ok
    mov  dword [rel nt_wref], NT_WREF_FLAGS
    jmp  .refused
.flags_ok:
    cmp  qword [rsp], 0
    je   .range_check
    call nt_save_plain                    ; exact live DATA size + ordinary record
    test rax, rax
    jnz  .range
.range_check:
    mov  rax, r12
    add  rax, r14
    jc   .range
    cmp  rax, [rbx + 0x30]                 ; data size
    ja   .range
    cmp  rax, [rbx + 0x38]                 ; initialized size
    ja   .range
    movzx ecx, word [rbx + 0x20]
    lea  rdi, [rbx + rcx]
    mov  ecx, [rbx + 4]
    lea  rcx, [rbx + rcx]
    lea  rsi, [rel nt_runs]
    mov  edx, NT_MAX_RUNS
    call nt_decode_runlist
    test eax, eax
    jg   .runs_ok
    mov  dword [rel nt_wref], NT_WREF_RUNS
    jmp  .refused
.runs_ok:
    mov  [rel nt_nruns], eax
    ; ---- pass 1: every byte of the range must land on a mapped run ----
    xor  ebx, ebx
.check:
    cmp  rbx, r14
    jae  .write
    lea  rdx, [r12 + rbx]
    lea  rdi, [rel nt_runs]
    mov  esi, [rel nt_nruns]
    call nt_vcn_to_lba
    cmp  rax, -2
    je   .range
    cmp  rax, -1
    jne  .mapped
    mov  dword [rel nt_wref], NT_WREF_SPARSE
    jmp  .refused
.mapped:
    ; advance to the end of this run (rdx = bytes left counted from sector start, rcx = in-sector)
    sub  rdx, rcx
    add  rbx, rdx
    jmp  .check
    ; ---- pass 2: sector-granular read-modify-write through the bounce ----
.write:
    xor  ebx, ebx
.wchunk:
    cmp  qword [rsp], 0
    je   .current_wchunk
    call nt_save_current
    test rax, rax
    jnz  .uncertain
.current_wchunk:
    cmp  rbx, r14
    jae  .flush
    lea  rdx, [r12 + rbx]
    lea  rdi, [rel nt_runs]
    mov  esi, [rel nt_nruns]
    call nt_vcn_to_lba
    cmp  rax, -1
    je   .io
    cmp  rax, -2
    je   .io
    mov  r15, rax                          ; sector lba
    mov  r8, rdx                           ; bytes left in run from sector start
    mov  r9, rcx                           ; byte within sector
    mov  r10, r14
    sub  r10, rbx                          ; remaining
    mov  r11, NT_SECBUF
    sub  r11, r9
    cmp  r10, r11
    jbe  .w1
    mov  r10, r11
.w1:
    mov  r11, r8
    sub  r11, r9
    cmp  r10, r11
    jbe  .w2
    mov  r10, r11
.w2:
    lea  rdx, [r9 + r10 + 511]
    shr  rdx, 9                            ; sectors touched
    ; read the touched sectors (partial head/tail must keep their other bytes)
    push r9
    push r10
    push rdx
    mov  rsi, r15
    lea  rcx, [rel nt_sec_buf]
    call nt_read
    pop  rdx
    pop  r10
    pop  r9
    test rax, rax
    jnz  .io
    ; patch
    lea  rdi, [rel nt_sec_buf]
    add  rdi, r9
    lea  rsi, [r13 + rbx]
    mov  rcx, r10
    push rdx
    push r10
    rep  movsb
    pop  r10
    pop  rdx
    ; write them back
    push r10
    mov  rsi, r15
    lea  rcx, [rel nt_sec_buf]
    mov  r9, [rsp + 8]                   ; saved mode under pushed chunk length
    call nt_write
    pop  r10
    test rax, rax
    jnz  .io
    add  rbx, r10
    jmp  .wchunk
.flush:
    cmp  qword [rsp], 0
    je   .current_flush
    call nt_save_current
    test rax, rax
    jnz  .uncertain
.current_flush:
    mov  rdi, [rel nt_dev]
    call blk_flush                         ; cached read-back cannot establish persistence
    test rax, rax
    jnz  .flush_fail
    ; ---- read-back verify (content-grade): re-read through the read path ----
    mov  edi, [rel nt_found_ref]
    call nt_read_record
    test rax, rax
    jnz  .verify_fail
    xor  ebx, ebx
.vchunk:
    cmp  rbx, r14
    jae  .verified
    mov  r10, r14
    sub  r10, rbx
    cmp  r10, NT_SECBUF
    jbe  .v1
    mov  r10, NT_SECBUF
.v1:
    lea  rdx, [r12 + rbx]
    lea  rcx, [rel nt_verify_buf]
    mov  r8, r10
    push r10
    call nt_data_read_at
    pop  r10
    cmp  rax, r10
    jne  .verify_fail
    lea  rdi, [rel nt_verify_buf]
    lea  rsi, [r13 + rbx]
    mov  rdx, r10
    push r10
    call memcmp
    pop  r10
    test rax, rax
    jnz  .verify_fail
    add  rbx, r10
    jmp  .vchunk
.verified:
    cmp  qword [rsp], 0
    je   .current_verified
    call nt_save_current
    test rax, rax
    jnz  .uncertain
.current_verified:
    lea  rdi, [rel str_nt_write_verified]
    call serial_string
    mov  rdi, r14
    call serial_hex64
    call serial_newline
    mov  rax, r14
    jmp  .out
.zero:
    xor  eax, eax
    jmp  .out
.nofile:
    mov  dword [rel nt_wref], NT_WREF_NOFILE
    jmp  .refused
.range:
    mov  dword [rel nt_wref], NT_WREF_RANGE
    jmp  .refused
.uncertain:
    mov  byte [rel nt_write_armed], 0
.io:
    mov  dword [rel nt_wref], NT_WREF_IO
    jmp  .refused
.verify_fail:
    mov  dword [rel nt_wref], NT_WREF_VERIFY
    jmp  .refused
.flush_fail:
    mov  [rel nt_last_blk_rc], rax
    mov  byte [rel nt_write_armed], 0       ; keep uncertain bytes; no retry/rollback
    mov  dword [rel nt_wref], NT_WREF_FLUSH
.refused:
    cmp  qword [rsp], 0
    je   .report
    cmp  dword [rel nt_wref], NT_WREF_IO
    jb   .report
    mov  byte [rel nt_write_armed], 0
.report:
    lea  rdi, [rel str_nt_write_refused]
    call serial_string
    mov  edi, [rel nt_wref]
    call serial_hex64
    lea  rdi, [rel str_nt_write_blkrc]
    call serial_string
    mov  rdi, [rel nt_last_blk_rc]
    call serial_hex64
    call serial_newline
.fail:
    mov  rax, -1
.out:
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret


; Whole-file save uses UPDATE (0/-1), never writefile's cluster/allocation ABI.
; Registered FSWRITE checks its scratch allowlist and verified OWNER before
; reaching mutate_path. Direct callers get the same scratch boundary here.
nt_op_update:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12, rdx
    mov  r13, rcx
    mov  edx, 11
    call nt_mutation_ascii
    test rax, rax
    jnz  .ascii_no
    ; Canonical name11 -> bounded absolute path, then the same path adapter.
    lea  rdi, [rel nt_save_name]
    mov  byte [rdi], '/'
    mov  edx, 1
    xor  ecx, ecx
.base:
    cmp  ecx, 8
    jae  .ext_start
    mov  al, [rsi + rcx]
    cmp  al, ' '
    je   .ext_start
    mov  [rdi + rdx], al
    inc  edx
    inc  ecx
    jmp  .base
.ext_start:
    mov  byte [rdi + rdx], '.'
    inc  edx
    mov  ecx, 8
.ext:
    mov  al, [rsi + rcx]
    mov  [rdi + rdx], al
    inc  edx
    inc  ecx
    cmp  ecx, 11
    jb   .ext
    mov  byte [rdi + rdx], 0
    mov  rdi, rbx
    lea  rsi, [rel nt_save_name]
    mov  rdx, r12
    mov  rcx, r13
    mov  r8d, FS_MUT_UPDATE
    call nt_op_mutate_path
    jmp  .ascii_out
.ascii_no:
    mov  rax, -1
.ascii_out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Pure hint: this NTFS subset needs CURRENT verified OWNER, not a persistent
; arm token. The mounted clean/nonhibernated state is necessary, not authority.
nt_op_save_armed:
    lea  rax, [rel nt_ops]
    cmp  [rdi + fsmount.ops], rax
    jne  .no
    lea  rax, [rel nt_ctx]
    cmp  [rdi + fsmount.priv], rax
    jne  .no
    call nt_save_current
    test rax, rax
    setz al
    movzx eax, al
    ret
.no:
    xor  eax, eax
    ret

nt_save_current:
    call nt_save_authority
    test rax, rax
    jnz  .out
    cmp  byte [rel nt_nr_ready], 0
    jne  nt_nr_current
    cmp  byte [rel nt_ns_ready], 0
    jne  nt_ns_current
    cmp  byte [rel nt_rename_mode], 0
    jne  nt_rename_current
    cmp  byte [rel nt_res_resize], 0
    jne  nt_rename_current               ; live geometry for resident metadata
.out:
    ret

%if NT_PUBLIC_READ_ONLY == 0
nt_volume_pin:
    push rdi
    push rsi
    push rdx
    push rcx
    push r8
    mov  rdi, [rel nt_dev]
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
%endif

nt_save_authority:
%if NT_PUBLIC_READ_ONLY
    mov  rax, -1
    ret
%else
    call nt_volume_pin
    test rax, rax
    jnz  .no
%endif
    cmp  byte [rel nt_mounted], 1
    jne  .no
    cmp  byte [rel nt_write_armed], 1
    jne  .no
    cmp  byte [rel nt_dirty], 0
    jne  .no
    cmp  byte [rel nt_hiber], 0
    jne  .no
    mov  rax, [rel nt_dev]
    test rax, rax
    jz   .no
    mov  rax, [rax + dev.info]
    test rax, rax
    jz   .no
    mov  rax, [rax + blk_info.media_generation]
    test rax, rax
    jz   .no
    cmp  rax, [rel nt_mount_generation]
    jne  .no
    call storage_access_request_intent
    cmp  eax, SA_INTENT_SPECIAL
    jne  .no
    call storage_access_request_owner
    cmp  rax, 1
    jne  .no
    xor  eax, eax
    ret
.no:
    mov  rax, -1
    ret

; Metadata live geometry and full mount VBR fingerprint, checked by
; every existing current-authority boundary (including individual retries).
; Preserve registers expected by the shared save-current predicate.
nt_rename_current:
    push rdi
    push rsi
    push rdx
    push rcx
    push r8
    push r9
    push r10
    push r11
    call nt_rename_geometry
    test rax, rax
    jnz  .no
.read:
    mov  rsi, [rel nt_part_lba]
    mov  edx, 1
    lea  rcx, [rel nt_rename_boot]
    call nt_read
    test rax, rax
    jnz  .no
    call nt_save_authority               ; after the live fingerprint read too
    test rax, rax
    jnz  .no
    call nt_rename_geometry
    test rax, rax
    jnz  .no
    lea  rdi, [rel nt_rename_boot]
    lea  rsi, [rel nt_boot_buf]
    mov  edx, 512
    call memcmp
    test rax, rax
    jnz  .out
    call nt_dir_current                 ; immutable ancestry on EVERY retry too
    jmp  .out
.no:
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
    ret

nt_rename_geometry:
    mov  rax, [rel nt_dev]
    mov  rax, [rax + dev.info]
    cmp  dword [rax + blk_info.sector_size], 512
    jne  .no
    mov  rcx, [rax + blk_info.lba_max]
    cmp  rcx, [rel nt_rename_mount_max]
    jne  .no
    mov  ecx, [rax + blk_info.logical_sector_bytes]
    cmp  ecx, [rel nt_rename_mount_logical]
    jne  .no
    test ecx, ecx
    jz   .yes
    cmp  ecx, 512
    jne  .no
.yes:
    xor  eax, eax
    ret
.no:
    mov  rax, -1
    ret

; RSI=Z path. Reject aliases/escape/special streams; retain the shared scratch
; namespace: /FSW*.TST or a /FSWDIR[0..2 chars]/... tree. All components bounded.
nt_save_path:
    cmp  byte [rsi], '/'
    jne  .no
    mov  edx, 1
    mov  r9d, 1                           ; component start
    xor  r10d, r10d                       ; first component length
.scan:
    cmp  edx, NT_MUT_PATH_MAX
    ja   .long
    movzx eax, byte [rsi + rdx]
    cmp  al, 0x80                       ; explicit guard for every path mutation
    jae  .no
    test al, al
    jz   .component
    cmp  al, '/'
    je   .component
    cmp  al, '.'
    je   .next
    cmp  al, '-'
    je   .next
    cmp  al, '_'
    je   .next
    or   al, 0x20
    cmp  al, 'a'
    jb   .digit
    cmp  al, 'z'
    jbe  .next
.digit:
    mov  al, [rsi + rdx]
    sub  al, '0'
    cmp  al, 9
    ja   .no
.next:
    inc  edx
    jmp  .scan
.component:
    mov  ecx, edx
    sub  ecx, r9d
    jz   .no
    cmp  ecx, 63
    ja   .no
    cmp  byte [rsi + r9], '.'
    jne  .ordinary
    cmp  ecx, 1
    je   .no
    cmp  ecx, 2
    jne  .ordinary
    cmp  byte [rsi + r9 + 1], '.'
    je   .no
.ordinary:
    test r10d, r10d
    jnz  .later
    mov  r10d, ecx
    cmp  al, 0                            ; AL still NUL or slash at component boundary
    je   .root
    cmp  ecx, 6
    jb   .no
    cmp  ecx, 8
    ja   .no
    mov  eax, [rsi + 1]
    or   eax, 0x20202020
    cmp  eax, 'fswd'
    jne  .no
    mov  ax, [rsi + 5]
    or   ax, 0x2020
    cmp  ax, 'ir'
    jne  .no
    ; Match the command's FSWDIR suffix rule (no dots), including internal
    ; suffix dots that Windows would treat differently from scratch names.
    cmp  ecx, 6
    je   .continue
    cmp  byte [rsi + 7], '.'
    je   .no
    cmp  ecx, 7
    je   .continue
    cmp  byte [rsi + 8], '.'
    je   .no
    jmp  .continue
.root:
    cmp  ecx, 7
    jb   .no
    cmp  ecx, 12
    ja   .no
    mov  eax, [rsi]
    or   eax, 0x20202000
    cmp  eax, '/fsw'
    jne  .no
    mov  eax, [rsi + rdx - 4]
    or   eax, 0x20202000
    cmp  eax, '.tst'
    jne  .no
.later:
    cmp  byte [rsi + rdx - 1], '.'
    je   .no
    cmp  byte [rsi + rdx], 0
    je   .yes
.continue:
    lea  r9d, [rdx + 1]
    inc  edx
    jmp  .scan
.yes:
    xor  eax, eax
    ret
.long:
    mov  dword [rel nt_path_refusal], NT_PATH_LONG
    mov  rax, -1
    ret
.no:
    mov  dword [rel nt_path_refusal], NT_PATH_NAME
    mov  rax, -1
    ret

nt_op_mutate_path:
    mov  dword [rel nt_path_refusal], NT_PATH_NONE
    cmp  r8, FS_MUT_CREATE
    je   nt_op_file_path
    cmp  r8, FS_MUT_DELETE
    je   nt_op_file_path
    cmp  r8, FS_MUT_MKDIR
    je   nt_op_directory_path
    cmp  r8, FS_MUT_RMDIR
    je   nt_op_directory_path
    cmp  r8, FS_MUT_RENAME                ; full-width operation admission
    je   nt_op_rename_path
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rsi
    mov  r13, rdx
    mov  r14, rcx
    cmp  r8, FS_MUT_UPDATE                ; full64 opcode, existing-file update only
    jne  .no
    test rcx, rcx
    jz   .buffer_ok
    test rdx, rdx
    jz   .no
.buffer_ok:
    mov  rax, rdx
    add  rax, rcx
    jc   .no
    call nt_op_save_armed
    cmp  rax, 1
    jne  .no
    mov  rsi, r12
    call nt_save_path
    test rax, rax
    jnz  .no
    mov  rsi, r12
    call nt_resolve_mutation_path         ; EDX=bounded path length
    test rax, rax
    jnz  .no
    mov  byte [rel nt_lookup_pre], 1
    xor  edx, edx
    mov  rcx, r13
    mov  r8, r14
    mov  r9d, 1
    call nt_op_write_at.whole
    mov  byte [rel nt_lookup_pre], 0
    cmp  rax, r14
    jne  .no
    xor  eax, eax
    jmp  .out
.no:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; File rename: bounded ASCII Win32 name, plain resident/nonresident DATA,
; one link/FILE_NAME and complete sorted resident $I30 leaves in ordinary parents.
; No allocation or journal/crash atomicity promise. Reuse the
; existing transaction with two or three records: stage all before writes, compare each
; partial postimage, flush, read back; disarm on any uncertain observation.
; FS_MUT_RENAME uses RDX=new NUL path, RCX=0 (never the UPDATE data ABI).
nt_op_rename_path:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  byte [rel nt_cross], 0
    mov  byte [rel nt_cross_phase], 0
    mov  byte [rel nt_dir_ready], 0
    mov  dword [rel nt_dir_count], 0
    mov  r12, rsi
    mov  r13, rdx
    test rcx, rcx
    jnz  .no
    test rsi, rsi
    jz   .no
    test rdx, rdx
    jz   .no
    call nt_op_save_armed
    cmp  rax, 1
    jne  .no
    mov  rsi, r12
    call nt_save_path
    test rax, rax
    jnz  .no
    mov  r14d, edx
    mov  rsi, r13
    call nt_save_path
    test rax, rax
    jnz  .no
    mov  [rel nt_rename_len], edx         ; new total length, then leaf length
    mov  ecx, r14d
.last_slash:
    dec  ecx
    cmp  byte [r12 + rcx], '/'
    jne  .last_slash
    inc  ecx
    mov  r15d, ecx                       ; leaf offset, including root slash
    lea  rax, [r12 + r15]
    mov  [rel nt_rename_old], rax
    sub  r14d, r15d
    mov  [rel nt_rename_old_len], r14d
    ; Resolve BOTH actual parents, binding the complete record+sequence refs.
    mov  rsi, r12
    lea  edx, [r15 - 1]
    call nt_rename_resolve_parent
    test rax, rax
    jnz  .no
    mov  [rel nt_rename_parent_full], rdx
    mov  ecx, [rel nt_rename_len]
.new_slash:
    dec  ecx
    cmp  byte [r13 + rcx], '/'
    jne  .new_slash
    lea  rax, [r13 + rcx + 1]
    mov  [rel nt_rename_new], rax
    mov  edx, ecx
    inc  ecx
    sub  [rel nt_rename_len], ecx
    mov  rsi, r13
    call nt_rename_resolve_parent
    test rax, rax
    jnz  .no
    mov  [rel nt_cross_dest_ref], rdx
    cmp  rdx, [rel nt_rename_parent_full]
    je   .parents_ready
    cmp  edx, [rel nt_rename_parent_full]
    je   .no                            ; conflicting sequence for same record
    mov  byte [rel nt_cross], 1
.parents_ready:
    mov  r14d, [rel nt_rename_len]
    ; Scratch FSW*.TST leaves only: no DOS device names or trailing-dot alias.
    cmp  r14d, 7
    jb   .no
    mov  rsi, [rel nt_rename_new]
    cmp  byte [rsi], 'F'
    jne  .no
    cmp  word [rsi + 1], 'SW'
    jne  .no
    cmp  dword [rsi + r14 - 4], '.TST'
    jne  .no
    xor  ecx, ecx
    xor  ebx, ebx
    cmp  r14d, [rel nt_rename_old_len]
    setne bl
.name:
    mov  al, [rsi + rcx]
    ; Restrict the body to uppercase ASCII, digits, dash, underscore; one dot.
    mov  edx, r14d
    sub  edx, 4
    cmp  ecx, edx
    jae  .different
    cmp  al, '-'
    je   .different
    cmp  al, '_'
    je   .different
    cmp  al, '0'
    jb   .no
    cmp  al, '9'
    jbe  .different
    cmp  al, 'A'
    jb   .no
    cmp  al, 'Z'
    ja   .no
.different:
    cmp  ecx, [rel nt_rename_old_len]
    jae  .next                           ; never read past the old NUL
    mov  rdx, [rel nt_rename_old]
    mov  dl, [rdx + rcx]
    or   dl, 0x20
    or   al, 0x20
    cmp  al, dl
    je   .next
    inc  ebx
.next:
    inc  ecx
    cmp  ecx, r14d
    jb   .name
    or   bl, [rel nt_cross]
    test ebx, ebx
    jz   .no                             ; no self/case-only rename
    mov  rsi, r12
    call nt_save_path
    mov  rsi, r12
    call nt_resolve_mutation_path
    test rax, rax
    jnz  .no
    mov  eax, [rel nt_path_parent]
    cmp  eax, [rel nt_rename_parent_full]
    jne  .no
    mov  [rel nt_rename_parent], eax
    mov  edi, [rel nt_found_ref]
    call nt_read_record
    test rax, rax
    jnz  .uncertain
    cmp  byte [rel nt_found_isdir], 1
    je   .directory
    lea  rdi, [rel nt_rec_buf]
    mov  esi, [rel nt_rec_bytes]
    add  rsi, rdi
    call nt_data_attr_admit              ; complete bounded stream and run geometry
    test rax, rax
    jz   .no
    cmp  word [rax + 12], 0              ; no compressed/encrypted/sparse DATA
    jne  .no
    mov  r13, rax                       ; never dereferenced for metadata-only rename
    mov  r14d, [rax + 16]
    mov  r9d, 1                         ; resident rename
    cmp  byte [rax + 8], 0
    je   .stream_ready
    cmp  word [rax + 34], 0              ; full compression-unit field
    jne  .no
    cmp  dword [rax + 36], 0             ; reserved nonresident header bytes
    jne  .no
    mov  r14, [rax + 48]
    call nt_rename_runs_plain
    test eax, eax
    jnz  .no
    mov  r9d, 2                         ; nonresident metadata-only rename
    jmp  .stream_ready
.directory:
    ; Bind each actual path edge to the directory's unique FILE_NAME parent,
    ; not a lexical prefix or a guessed record number. Keep immutable ancestors
    ; for live whole-record comparisons at every authority/retry boundary.
    mov  rax, [rel nt_found_ref]
    mov  [rel nt_dir_child], eax
    mov  ax, [rel nt_found_sequence]
    mov  [rel nt_dir_sequence], ax
    mov  rsi, r12
    mov  rdx, [rel nt_rename_parent_full]
    call nt_dir_chain
    test rax, rax
    jnz  .uncertain
    mov  rsi, r13
    mov  rdx, [rel nt_cross_dest_ref]
    call nt_dir_chain
    test rax, rax
    jnz  .uncertain
    mov  eax, [rel nt_dir_child]
    mov  [rel nt_found_ref], rax
    mov  ax, [rel nt_dir_sequence]
    mov  [rel nt_found_sequence], ax
    mov  edi, [rel nt_dir_child]
    call nt_read_record
    test rax, rax
    jnz  .uncertain
    movzx edx, word [rel nt_dir_sequence]
    shl  rdx, 48
    or   rdx, [rel nt_found_ref]
    call nt_dir_admit                    ; own complete resident index stays byte-exact
    test rax, rax
    jnz  .no
    xor  r14d, r14d
    mov  r9d, 3                         ; directory, metadata only, no DATA
.stream_ready:
    mov  [rel nt_rename_mode], r9b
    xor  r12d, r12d
    mov  r9d, 1
    call nt_resident_write
    mov  byte [rel nt_rename_mode], 0
    cmp  rax, r14
    jne  .no
    xor  eax, eax
    jmp  .out
.uncertain:
    mov  byte [rel nt_write_armed], 0
.no:
    mov  rax, -1
.out:
    mov  byte [rel nt_cross], 0
    mov  byte [rel nt_cross_phase], 0
    mov  byte [rel nt_dir_ready], 0
    mov  dword [rel nt_dir_count], 0
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Resolve a bounded parent prefix without changing caller path bytes.
; EDX=prefix bytes excluding slash before leaf; RDX=full reference on success.
nt_rename_resolve_parent:
    push rbx
    lea  rdi, [rel nt_cross_path]
    mov  ebx, edx
    mov  ecx, edx
    rep  movsb
    mov  byte [rdi], 0
    lea  rsi, [rel nt_cross_path]
    mov  edx, ebx
    call nt_resolve_mutation_path
    test rax, rax
    jnz  .out
    cmp  byte [rel nt_found_isdir], 1
    jne  .no
    cmp  qword [rel nt_found_ref], NT_REC_ROOT
    jne  .sequence
    ; The generic empty-path resolver has no index key to supply a sequence.
    ; Read the real root FILE; never reuse the last component's cached token.
    mov  edi, NT_REC_ROOT
    call nt_read_record
    test rax, rax
    jnz  .no
    cmp  dword [rel nt_rec_buf + 44], NT_REC_ROOT
    jne  .no
    mov  ax, [rel nt_rec_buf + 16]
    mov  [rel nt_found_sequence], ax
.sequence:
    mov  rdx, [rel nt_found_ref]
    mov  ecx, edx
    cmp  rdx, rcx
    jne  .no
    movzx ecx, word [rel nt_found_sequence]
    shl  rcx, 48
    or   rdx, rcx
    xor  eax, eax
    jmp  .out
.no:
    mov  rax, -1
.out:
    pop  rbx
    ret

; RDX=full reference, nt_rec_buf=logical FILE. Root is read-only terminal;
; ordinary directories require one Win32 FN, no DATA/aliases/allocation, and
; a complete sorted resident $I30. Reuse the same whole-leaf key validator.
nt_dir_admit:
    push rbx
    push r12
    push r15
    mov  dword [rel nt_dir_fn_spaces], 0
    mov  r12, rdx
    lea  rdi, [rel nt_rec_buf]
    mov  esi, [rel nt_rec_bytes]
    add  rsi, rdi
    call nt_dir_record_valid
    test rax, rax
    jnz  .no
    lea  rbx, [rel nt_rec_buf]
    cmp  [rbx + 44], r12d
    jne  .no
    mov  rax, r12
    shr  rax, 32
    test ax, ax
    jnz  .no
    shr  rax, 16
    test ax, ax
    jz   .no
    cmp  [rbx + 16], ax
    jne  .no                            ; actual directory sequence, never guessed
    cmp  word [rbx + 18], 1
    je   .links
    cmp  byte [rel nt_dir_parent_only], 0
    je   .no
    cmp  r12d, NT_REC_ROOT
    je   .no                            ; the root keeps its single link
    cmp  word [rbx + 18], 2
    jne  .no                            ; Win32/DOS pair, counted at .end
.links:
    cmp  r12d, NT_REC_ROOT
    je   .ordinary
    cmp  r12d, 16
    jb   .no
    mov  eax, [rel nt_clus_bytes]
    xor  edx, edx
    div  dword [rel nt_rec_bytes]
    cmp  r12d, eax
    jb   .no
.ordinary:
    movzx r8d, word [rbx + 20]
    mov  r10d, [rbx + 24]
    sub  r10d, 8
    jc   .no
    xor  r9d, r9d
    xor  r11d, r11d
.attrs:
    cmp  r8d, r10d
    ja   .no
    mov  eax, [rbx + r8]
    cmp  eax, -1
    je   .end
    cmp  eax, NT_A_FILENAME
    jne  .unique
    cmp  r9d, eax
    jne  .unique
    cmp  byte [rel nt_dir_parent_only], 0
    jne  .plain                         ; second parent name: pair checked at .end
.unique:
    cmp  eax, r9d
    jbe  .no                            ; unique attributes, no hardlink aliases
    mov  r9d, eax
    cmp  eax, NT_A_STDINFO
    je   .plain
    cmp  eax, NT_A_FILENAME
    je   .plain
    cmp  eax, 0x40
    je   .plain
    cmp  eax, 0x50
    jne  .after_security
    cmp  r12d, NT_REC_ROOT
    je   .root_extra                    ; immutable root security may be nonresident
    jmp  .plain
.after_security:
    cmp  eax, NT_A_INDEXROOT
    je   .plain
    cmp  r12d, NT_REC_ROOT
    jne  .no                            ; no directory INDEX_ALLOCATION mutation
    cmp  eax, NT_A_INDEXALLOC
    je   .root_extra
    cmp  eax, NT_A_BITMAP
    je   .root_extra
    cmp  eax, 0x100
    jne  .no
    ; Windows adds this bounded resident $TXF_DATA to the immutable root.
    ; It is opaque ancestor metadata, never inherited or staged for mutation.
    ; nt_ns_root_admit still refuses it as a writable CREATE parent.
    cmp  dword [rbx + r8 + 4], 104
    jne  .no
    cmp  byte [rbx + r8 + 8], 0
    jne  .no
    cmp  byte [rbx + r8 + 9], 9
    jne  .no
    cmp  word [rbx + r8 + 10], 24
    jne  .no
    cmp  word [rbx + r8 + 12], 0
    jne  .no
    cmp  dword [rbx + r8 + 16], 56
    jne  .no
    cmp  word [rbx + r8 + 20], 48
    jne  .no
    cmp  word [rbx + r8 + 22], 0
    jne  .no
    mov  rax, 0x0046005800540024        ; UTF16 "$TXF"
    cmp  [rbx + r8 + 24], rax
    jne  .no
    mov  rax, 0x005400410044005F        ; UTF16 "_DAT"
    cmp  [rbx + r8 + 32], rax
    jne  .no
    cmp  word [rbx + r8 + 40], 'A'
    jne  .no
.root_extra:
    ; Already bounded by nt_dir_record_valid. Root remains immutable and its
    ; real allocation tree was traversed by the actual resolver.
    mov  ecx, [rbx + r8 + 4]
    add  ecx, r8d
    jmp  .next
.plain:
    cmp  byte [rbx + r8 + 8], 0
    jne  .no
    cmp  word [rbx + r8 + 12], 0
    jne  .no
    mov  ecx, [rbx + r8 + 4]
    add  ecx, r8d
    movzx edx, word [rbx + r8 + 20]
    add  edx, r8d
    cmp  r9d, NT_A_INDEXROOT
    je   .index
    cmp  byte [rbx + r8 + 9], 0
    jne  .no
    cmp  r9d, NT_A_STDINFO
    jne  .filename
    or   r11d, 1
    cmp  dword [rbx + r8 + 16], 36
    jb   .no
    cmp  r12d, NT_REC_ROOT
    je   .next
    test dword [rbx + rdx + 32], 0x4E07
    jnz  .no
    jmp  .next
.filename:
    cmp  r9d, NT_A_FILENAME
    jne  .next
    or   r11d, 2
    mov  eax, [rbx + r8 + 16]
    cmp  eax, 68
    jb   .no
    mov  [rel nt_res_fn], edx
    mov  [rel nt_res_fn_len], eax
    mov  [rel nt_rename_fn_attr], r8d
    mov  rax, [rbx + rdx]
    mov  [rel nt_dir_next], rax
    cmp  r12d, NT_REC_ROOT
    jne  .ordinary_name
    cmp  rax, r12
    jne  .no
    cmp  dword [rbx + r8 + 16], 68
    jne  .no
    cmp  dword [rbx + rdx + 64], 0x002E0301 ; one char, Win32+DOS '.'
    jne  .no
    jmp  .next
.ordinary_name:
    test dword [rbx + rdx + 56], 0x4E07
    jnz  .no
    cmp  byte [rel nt_dir_parent_only], 0
    jne  .parent_name
    mov  eax, [rbx + rdx + 56]
    and  eax, 0x10000010
    cmp  eax, 0x10000010
    jne  .no                            ; unique FN actually describes a directory
    cmp  byte [rbx + rdx + 65], 1
    jne  .no
    movzx eax, byte [rbx + rdx + 64]
.name_length:
    test eax, eax
    jz   .no
    cmp  eax, 63
    ja   .no
    lea  eax, [rax*2 + 66]
    cmp  eax, [rel nt_res_fn_len]
    jne  .no
    jmp  .next
.parent_name:
    ; Namespace-path parent/ancestor only: this record is never renamed or
    ; retired by the operation, so its own POSIX, Win32, Win32+DOS name or
    ; Win32/DOS pair is opaque. The view-index bit still marks a directory.
    test dword [rbx + rdx + 56], 0x10000000
    jz   .no
    movzx eax, byte [rbx + rdx + 65]
    cmp  eax, 3
    ja   .no
    bts  dword [rel nt_dir_fn_spaces], eax
    jc   .no                            ; one name per namespace
    cmp  eax, 2
    je   .dos_name
    mov  [rel nt_dir_fn_attr], r8d
    mov  eax, [rel nt_res_fn]
    mov  [rel nt_dir_fn_off], eax
    mov  eax, [rel nt_res_fn_len]
    mov  [rel nt_dir_fn_len], eax
    mov  rax, [rel nt_dir_next]
    mov  [rel nt_dir_fn_next], rax
    jmp  .parent_length
.dos_name:
    mov  rax, [rel nt_dir_next]
    mov  [rel nt_dir_fn_dos_next], rax
.parent_length:
    movzx eax, byte [rdx + rbx + 64]
    jmp  .name_length
.index:
    or   r11d, 4
    cmp  byte [rbx + r8 + 9], 4
    jne  .no
    cmp  word [rbx + r8 + 10], 24
    jne  .no
    lea  eax, [r8 + 32]
    cmp  eax, edx
    ja   .no
    test edx, 7
    jnz  .no
    mov  rax, 0x0030003300490024
    cmp  [rbx + r8 + 24], rax
    jne  .no
    cmp  dword [rbx + r8 + 16], 32
    jb   .no
    cmp  dword [rbx + rdx], NT_A_FILENAME
    jne  .no
    cmp  dword [rbx + rdx + 4], 1
    jne  .no
    cmp  r12d, NT_REC_ROOT
    je   .next                          ; immutable root can use allocation
    add  edx, 16
    cmp  dword [rbx + rdx + 12], 0
    jne  .no
    mov  r15d, [rbx + rdx]
    cmp  r15d, 16
    jb   .no
    test r15d, 7
    jnz  .no
    mov  eax, [rbx + rdx + 4]
    cmp  r15d, eax
    ja   .no
    cmp  eax, [rbx + rdx + 8]
    jne  .no
    push rcx
    mov  ecx, [rbx + r8 + 16]
    sub  ecx, 16
    cmp  eax, ecx
    pop  rcx
    ja   .no
    add  eax, edx
    mov  [rel nt_res_index_end], eax
    add  r15d, edx
    mov  [rel nt_res_parent_ref], r12
    mov  byte [rel nt_dir_leaf], 1
    call nt_rename_leaf
    mov  byte [rel nt_dir_leaf], 0
    test rax, rax
    jnz  .no                            ; whole own index, even after found keys
.next:
    mov  r8d, ecx
    jmp  .attrs
.end:
    cmp  r8d, r10d
    jne  .no
    cmp  r11d, 7
    jne  .no
    cmp  byte [rel nt_dir_parent_only], 0
    je   .admitted
    cmp  r12d, NT_REC_ROOT
    je   .admitted
    call nt_dir_parent_names
    test eax, eax
    jnz  .no
.admitted:
    mov  [rel nt_res_end], r8d
    mov  dword [rel nt_res_fn_count], 1
    xor  eax, eax
    jmp  .out
.no:
    mov  rax, -1
.out:
    pop  r15
    pop  r12
    pop  rbx
    ret

; RBX=admitted parent FILE. Exactly one POSIX, Win32 or Win32+DOS name, or a
; Win32 and DOS pair naming the same parent; the link count counts them. The
; primary (non-DOS) name is restored for the path-edge and own-key checks.
nt_dir_parent_names:
    mov  eax, [rel nt_dir_fn_spaces]
    mov  ecx, 1
    cmp  eax, 1                         ; POSIX
    je   .count
    cmp  eax, 2                         ; Win32
    je   .count
    cmp  eax, 8                         ; Win32+DOS
    je   .count
    cmp  eax, 6                         ; Win32 and DOS pair
    jne  .no
    mov  rax, [rel nt_dir_fn_dos_next]
    cmp  rax, [rel nt_dir_fn_next]
    jne  .no
    mov  ecx, 2
.count:
    cmp  [rbx + 18], cx
    jne  .no
    mov  eax, [rel nt_dir_fn_off]
    mov  [rel nt_res_fn], eax
    mov  eax, [rel nt_dir_fn_len]
    mov  [rel nt_res_fn_len], eax
    mov  eax, [rel nt_dir_fn_attr]
    mov  [rel nt_rename_fn_attr], eax
    mov  rax, [rel nt_dir_fn_next]
    mov  [rel nt_dir_next], rax
    xor  eax, eax
    ret
.no:
    mov  eax, -1
    ret

; File CREATE parent admission: the parent and its ancestors are never renamed
; or retired by an insert, so Windows/libntfs-3g name forms and POSIX/Win32+DOS
; sibling keys are admitted. DELETE/MKDIR/RMDIR/RENAME and every child record
; keep the exact single-Win32 policy. Registers are preserved for the callee.
nt_dir_parent_chain:
    call nt_dir_parent_scope
    call nt_dir_chain
    mov  byte [rel nt_dir_parent_only], 0
    ret

nt_dir_parent_admit:
    call nt_dir_parent_scope
    call nt_dir_admit
    mov  byte [rel nt_dir_parent_only], 0
    ret

nt_dir_parent_scope:
    mov  byte [rel nt_dir_parent_only], 0
    cmp  byte [rel nt_ns_file], 1
    jne  .out
    cmp  dword [rel nt_ns_op], FS_MUT_MKDIR
    jne  .out                           ; file insert only
    mov  byte [rel nt_dir_parent_only], 1
.out:
    ret

; RSI=original full path, RDX=actual resolved parent full reference. Walk
; unique FILE_NAME parent links and verify EVERY edge with the actual path
; resolver (including sequence and component name). Acyclic root reachability
; is required for both paths; any ancestor equal to the moved child is refused.
nt_dir_chain:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rsi
    mov  r14, rdx
    xor  r13d, r13d
.length:
    cmp  byte [r12 + r13], 0
    je   .trim
    inc  r13d
    jmp  .length
.trim:
    dec  r13d
    cmp  byte [r12 + r13], '/'
    jne  .trim
.node:
    cmp  r14d, [rel nt_dir_child]
    je   .no                            ; self/descendant or source cycle
    mov  edi, r14d
    call nt_read_record
    test rax, rax
    jnz  .no
    mov  rdx, r14
    call nt_dir_admit
    test rax, rax
    jnz  .no
    ; Derive a complete contiguous record mapping, no mid-record run boundary.
    mov  eax, r14d
    mov  ecx, [rel nt_rec_bytes]
    imul rax, rcx
    mov  rdx, rax
    lea  rdi, [rel nt_mft_runs]
    mov  esi, [rel nt_mft_nruns]
    call nt_vcn_to_lba
    cmp  rax, -2
    jae  .no
    test rcx, rcx
    jnz  .no
    mov  ecx, [rel nt_rec_bytes]
    cmp  rdx, rcx
    jb   .no
    mov  [rel nt_dir_lba], rax
    mov  r15d, [rel nt_dir_count]
    cmp  r15d, NT_MUT_PATH_MAX + 2
    jae  .no
    ; Distinct record identities must never alias physical storage, including
    ; immutable ancestors. Duplicated ancestors from the two chains are fine.
    xor  ebx, ebx
.overlap:
    cmp  ebx, r15d
    jae  .snapshot
    lea  rdi, [rel nt_dir_refs]
    cmp  [rdi + rbx*8], r14
    je   .same
    lea  rdi, [rel nt_dir_lbas]
    mov  rdx, [rdi + rbx*8]
    call nt_cross_record_pair
    test eax, eax
    jnz  .no
    jmp  .prior_next
.same:
    lea  rdi, [rel nt_dir_lbas]
    cmp  rax, [rdi + rbx*8]
    jne  .no
.prior_next:
    mov  rax, [rel nt_dir_lba]
    inc  ebx
    jmp  .overlap
.snapshot:
    lea  rdi, [rel nt_dir_refs]
    mov  [rdi + r15*8], r14
    lea  rdi, [rel nt_dir_lbas]
    mov  [rdi + r15*8], rax
    imul edi, r15d, NT_RECBUF
    lea  rsi, [rel nt_dir_images]
    add  rdi, rsi
    push rdi
    lea  rsi, [rel nt_rec_buf]
    mov  edx, [rel nt_rec_bytes]
    call memcpy
    pop  rdi
    movzx ecx, word [rdi + 4]
    mov  ax, [rdi + rcx]
    mov  ecx, 1
.raw:
    mov  edx, ecx
    shl  edx, 9
    mov  [rdi + rdx - 2], ax
    inc  ecx
    cmp  ecx, [rel nt_rec_sectors]
    jbe  .raw
    inc  dword [rel nt_dir_count]
    cmp  r14d, NT_REC_ROOT
    jne  .edge
    test r13d, r13d
    jnz  .no                            ; actual root reached at actual path root
    xor  eax, eax
    jmp  .out
.edge:
    test r13d, r13d
    jz   .no
    mov  ebx, r13d
.slash:
    dec  ebx
    cmp  byte [r12 + rbx], '/'
    jne  .slash
    mov  ecx, r13d
    sub  ecx, ebx
    dec  ecx
    lea  rdi, [rel nt_rec_buf]
    mov  edx, [rel nt_res_fn]
    add  rdi, rdx
    cmp  cl, [rdi + 64]
    jne  .no
    xor  edx, edx
.name:
    lea  eax, [rbx + rdx + 1]
    movzx eax, byte [r12 + rax]
    cmp  al, 'a'
    jb   .upper
    cmp  al, 'z'
    ja   .upper
    sub  al, 32
.upper:
    cmp  byte [rel nt_dir_parent_only], 0
    je   .exact
    cmp  dword [rel nt_dir_fn_spaces], 1
    jne  .fold
    lea  eax, [rdx + rbx + 1]
    movzx eax, byte [r12 + rax]          ; POSIX name: case-sensitive, exact input byte
    jmp  .exact
.fold:
    movzx r8d, word [rdi + rdx*2 + 66]
    sub  r8d, 'a'
    cmp  r8d, 25
    ja   .exact
    or   al, 0x20                       ; stored lowercase ASCII, either input case
.exact:
    cmp  ax, [rdi + rdx*2 + 66]
    jne  .no                            ; reject path alias of a different name
    inc  edx
    cmp  edx, ecx
    jb   .name
    mov  r14, [rel nt_dir_next]
    mov  rsi, r12
    mov  edx, ebx
    call nt_rename_resolve_parent
    test rax, rax
    jnz  .no
    cmp  rdx, r14
    jne  .no                            ; actual parent reference AND sequence
    mov  r13d, ebx
    jmp  .node
.no:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Before any mutation, disallow a child's mapping overlapping any ancestor.
nt_dir_child_mapping:
    push rbx
    xor  ebx, ebx
.loop:
    cmp  ebx, [rel nt_dir_count]
    jae  .ok
    mov  rax, [rel nt_res_lba]
    lea  rdi, [rel nt_dir_lbas]
    mov  rdx, [rdi + rbx*8]
    call nt_cross_record_pair
    test eax, eax
    jnz  .out
    inc  ebx
    jmp  .loop
.ok:
    xor  eax, eax
.out:
    pop  rbx
    ret

nt_dir_staged_parents:
    push rbx
    xor  ebx, ebx
.loop:
    cmp  ebx, [rel nt_dir_count]
    jae  .ok
    lea  rdi, [rel nt_dir_refs]
    mov  eax, [rdi + rbx*8]
    lea  rdi, [rel nt_res_parent_expected]
    cmp  eax, [rel nt_cross_dest_ref]
    je   .compare
    cmp  eax, [rel nt_rename_parent_full]
    jne  .next
    cmp  byte [rel nt_cross], 0
    je   .compare
    lea  rdi, [rel nt_cross_source_expected]
.compare:
    imul esi, ebx, NT_RECBUF
    lea  rdx, [rel nt_dir_images]
    add  rsi, rdx
    mov  edx, [rel nt_rec_bytes]
    call memcmp
    test rax, rax
    jnz  .out                           ; parent ancestry changed during preflight
.next:
    inc  ebx
    jmp  .loop
.ok:
    xor  eax, eax
.out:
    pop  rbx
    ret

; Called inside nt_rename_current, hence inside each individual write retry.
; Own separate raw buffer; never recursively call nt_save_current here. The two
; mutable parents use the existing complete expected-partial-image comparison.
nt_dir_current:
    cmp  byte [rel nt_dir_ready], 0
    je   .inactive
    push rbx
    push r12
    push r13
    push r14
    push r15
    xor  ebx, ebx
.loop:
    cmp  ebx, [rel nt_dir_count]
    jae  .ok
    lea  rdi, [rel nt_dir_refs]
    mov  eax, [rdi + rbx*8]
    cmp  eax, [rel nt_rename_parent_full]
    je   .next
    cmp  eax, [rel nt_cross_dest_ref]
    je   .next
    lea  rdi, [rel nt_dir_lbas]
    mov  rsi, [rdi + rbx*8]
    mov  edx, [rel nt_rec_sectors]
    lea  rcx, [rel nt_dir_readback]
    call nt_read
    test rax, rax
    jnz  .no
    call nt_save_authority
    test rax, rax
    jnz  .no
    call nt_rename_geometry
    test rax, rax
    jnz  .no
    imul esi, ebx, NT_RECBUF
    lea  rdi, [rel nt_dir_images]
    add  rsi, rdi
    lea  rdi, [rel nt_dir_readback]
    mov  edx, [rel nt_rec_bytes]
    call memcmp
    test rax, rax
    jnz  .no                            ; late immutable ancestor change
.next:
    inc  ebx
    jmp  .loop
.ok:
    xor  eax, eax
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
.inactive:
    xor  eax, eax
    ret

; Decoded DATA from nt_data_attr_admit: no holes, duplicate physical extents,
; or overlap with the MFT, MFTMirr or boot cluster. Preserve caller stream size.
nt_rename_runs_plain:
    push rbx
    push r12
    lea  rbx, [rel nt_runs]
    mov  r12d, [rel nt_nruns]
.loop:
    test r12d, r12d
    jz   .ok
    mov  r8, [rbx]
    test r8, r8
    jle  .no                            ; no sparse pairs or boot cluster
    mov  r9, [rbx + 8]
    add  r9, r8                         ; bounded by shared geometry admission
    lea  rdi, [rel nt_runs]
.prior:
    cmp  rdi, rbx
    jae  .mft
    mov  rax, [rdi]
    mov  rdx, [rdi + 8]
    add  rdx, rax
    cmp  r8, rdx
    jae  .next_prior
    cmp  rax, r9
    jb   .no                            ; overlapping DATA physical runs
.next_prior:
    add  rdi, 16
    jmp  .prior
.mft:
    lea  rdi, [rel nt_mft_runs]
    mov  ecx, [rel nt_mft_nruns]
.mft_loop:
    test ecx, ecx
    jz   .mirror
    mov  rax, [rdi]
    mov  rdx, [rdi + 8]
    add  rdx, rax
    cmp  r8, rdx
    jae  .next_mft
    cmp  rax, r9
    jb   .no                            ; metadata writes cannot change DATA extents
.next_mft:
    add  rdi, 16
    dec  ecx
    jmp  .mft_loop
.mirror:
    lea  rdi, [rel nt_boot_buf]
    mov  rax, [rdi + 56]                 ; MFTMirr LCN, max(4 records, one cluster)
    mov  edx, [rel nt_rec_bytes]
    shl  rdx, 2
    mov  ecx, [rel nt_clus_bytes]
    cmp  rdx, rcx
    jae  .mirror_size
    mov  rdx, rcx
.mirror_size:
    lea  rdx, [rdx + rcx - 1]
    push rax
    mov  rax, rdx
    xor  edx, edx
    div  rcx
    mov  rdx, rax
    pop  rax
    add  rdx, rax
    jc   .no
    test rax, rax
    jz   .no
    mov  r10, rdx
    mov  rax, [rel nt_total_sectors]
    mov  ecx, [rel nt_spc]
    xor  edx, edx
    div  rcx
    cmp  r10, rax
    ja   .no                            ; mirror extent must fit the volume
    mov  rax, [rdi + 56]
    cmp  r8, r10
    jae  .advance
    cmp  rax, r9
    jb   .no
.advance:
    add  rbx, 16
    dec  r12d
    jmp  .loop
.ok:
    xor  eax, eax
    jmp  .out
.no:
    mov  eax, -1
.out:
    pop  r12
    pop  rbx
    ret

; Resident in-place save / metadata rename. R12=offset, R13=source, R14=len, R9=whole mode.
; Saves remain resident-only here; rename also admits plain nonresident DATA.
; Bounded whole-file resize
; updates DATA and both FILE_NAME size caches; no allocation, timestamp or
; sequence update, journal or atomicity promise. Reserved AND all MFTMirr
; coverage refused. A record must fit a single mapped MFT run. Private raw
; expected/staged/readback images keep USA storage separate from logical data.
nt_resident_write:
    push rbx
    push r15
    push r9
    mov  dword [rel nt_wref], NT_WREF_RESIDENT
    mov  dword [rel nt_res_attempted], 0
    mov  dword [rel nt_res_confirmed], 0
    mov  byte [rel nt_res_resize], 0
    mov  dword [rel nt_res_fn_count], 0
    call nt_save_current
    test rax, rax
    jnz  .uncertain
    cmp  byte [rel nt_rename_mode], 0
    jne  .record                       ; metadata-only: no DATA source buffer
    test r14, r14
    jz   .source_ok
    test r13, r13
    jz   .no
.source_ok:
    mov  rax, r13
    add  rax, r14
    jc   .no
.record:
    cmp  byte [rel nt_rename_mode], 3
    je   .directory_record
    lea  rbx, [rel nt_rec_buf]
    cmp  dword [rbx], 'FILE'
    jne  .no
    cmp  word [rbx + 22], 1               ; in use, ordinary, no unknown flags
    jne  .no
    cmp  qword [rbx + 32], 0              ; no extension record
    jne  .no
    mov  rax, [rel nt_found_ref]
    mov  ecx, eax
    cmp  rax, rcx                        ; reader ABI supports only 32-bit refs
    jne  .no
    cmp  [rbx + 44], eax                 ; FILE belongs to the resolved index ref
    jne  .no
    mov  cx, [rel nt_found_sequence]
    test cx, cx
    jz   .no
    cmp  [rbx + 16], cx                  ; refuse a stale/reused directory ref
    jne  .no
    cmp  eax, 16
    jb   .no
    mov  ecx, [rel nt_clus_bytes]
    xor  edx, edx
    mov  eax, ecx
    div  dword [rel nt_rec_bytes]         ; MFTMirr=max(4 records, one cluster)
    cmp  [rel nt_found_ref], eax
    jb   .no
    mov  ecx, [rel nt_rec_sectors]
    inc  ecx
    cmp  cx, [rbx + 6]                   ; EXACT USA coverage of this record
    jne  .no
    movzx eax, word [rbx + 4]
    cmp  eax, 48
    jb   .no
    lea  eax, [rax + rcx*2]
    movzx r8d, word [rbx + 20]
    cmp  eax, r8d
    ja   .no
    test r8d, 7
    jnz  .no
    mov  r10d, [rbx + 24]                ; used <= allocated == record size
    mov  eax, [rel nt_rec_bytes]
    cmp  [rbx + 28], eax
    jne  .no
    cmp  r10d, eax
    ja   .no
    sub  r10d, 4
    jc   .no
    xor  r9d, r9d                        ; prior attribute type (ordered)
    xor  r11d, r11d                      ; STDINFO/DATA seen bits
.attrs:
    cmp  r8d, r10d
    ja   .no
    mov  eax, [rbx + r8]
    cmp  eax, -1
    je   .end_attrs
    cmp  eax, r9d
    jb   .no
    jne  .type_ok
    cmp  eax, NT_A_FILENAME              ; only FILE_NAME may repeat
    jne  .no
.type_ok:
    mov  r9d, eax
    cmp  eax, NT_A_STDINFO
    je   .allowed_type
    cmp  eax, NT_A_FILENAME
    je   .allowed_type
    cmp  eax, 0x40                       ; OBJECT_ID
    je   .allowed_type
    cmp  eax, 0x50                       ; SECURITY_DESCRIPTOR
    je   .allowed_type
    cmp  eax, NT_A_DATA
    jne  .no                            ; no reparse/index/unknown attributes
.allowed_type:
    lea  eax, [r8 + 24]
    cmp  eax, r10d
    ja   .no
    mov  ecx, [rbx + r8 + 4]
    cmp  ecx, 24
    jb   .no
    test ecx, 7
    jnz  .no
    add  ecx, r8d
    jc   .no
    lea  eax, [r10 + 4]
    cmp  ecx, eax
    ja   .no
    cmp  byte [rbx + r8 + 9], 0          ; no named streams/attributes
    jne  .no
    cmp  word [rbx + r8 + 12], 0
    jne  .no
    cmp  byte [rbx + r8 + 8], 0
    je   .resident_attr
    cmp  byte [rel nt_nr_mode], 0
    jne  .nonresident_attr
    cmp  byte [rel nt_rename_mode], 2
    jne  .no
.nonresident_attr:
    cmp  r9d, NT_A_DATA
    jne  .no                            ; only fully admitted DATA may be nonresident
    cmp  byte [rbx + r8 + 8], 1
    jne  .no
    mov  rax, r14
    cmp  byte [rel nt_nr_mode], 0
    je   .nonresident_size
    mov  rax, [rel nt_nr_old_size]
.nonresident_size:
    cmp  rax, [rbx + r8 + 48]
    jne  .no
    or   r11d, 2
    mov  [rel nt_res_data], r8d
    jmp  .next_attr                     ; preserve every DATA header/mapping byte
.resident_attr:
    movzx eax, word [rbx + r8 + 20]
    cmp  eax, 24
    jb   .no
    add  eax, r8d
    mov  edx, eax                        ; logical value start
    add  eax, [rbx + r8 + 16]
    jc   .no
    cmp  eax, ecx
    ja   .no
    cmp  r9d, NT_A_FILENAME
    jne  .stdinfo
    cmp  dword [rbx + r8 + 16], 66
    jb   .no
    test dword [rbx + rdx + 56], 0x4E17
    jnz  .no
    inc  dword [rel nt_res_fn_count]
    mov  [rel nt_res_fn], edx
    mov  [rel nt_rename_fn_attr], r8d
    mov  eax, [rbx + r8 + 16]
    mov  [rel nt_res_fn_len], eax
.stdinfo:
    cmp  r9d, NT_A_STDINFO
    jne  .data
    or   r11d, 1
    cmp  dword [rbx + r8 + 16], 36
    jb   .no
    test dword [rbx + rdx + 32], 0x4E17
    jnz  .no
.data:
    cmp  r9d, NT_A_DATA
    jne  .next_attr
    or   r11d, 2
    cmp  byte [rbx + r8 + 22], 0         ; reserved resident DATA indexed flag
    jne  .no
    mov  [rel nt_res_value], edx
    mov  [rel nt_res_data], r8d
    mov  eax, [rbx + r8 + 16]
    cmp  qword [rsp], 0
    je   .range
    test r12, r12
    jnz  .no
    cmp  r14, rax                        ; same-length save keeps its old subset
    je   .range
    mov  byte [rel nt_res_resize], 1
    jmp  .next_attr
.range:
    mov  rdx, r12
    add  rdx, r14
    jc   .no
    cmp  rdx, rax
    ja   .no
.next_attr:
    mov  r8d, ecx
    jmp  .attrs
.end_attrs:
    cmp  r11d, 3
    jne  .no
    mov  [rel nt_res_end], r8d
    cmp  byte [rel nt_nr_mode], 0
    jne  .resize_metadata
    cmp  byte [rel nt_rename_mode], 0
    je   .mapped_record
.resize_metadata:
    mov  byte [rel nt_res_resize], 1
    jmp  .mapped_record
.directory_record:
    ; nt_dir_admit consumed the complete child and set the unique FN/END.
    ; Do not reinterpret a directory's index as DATA or rewrite its children.
    mov  byte [rel nt_res_resize], 1
    mov  dword [rel nt_res_fn_count], 1
.mapped_record:
    ; Independently preflight full record mapping before any write. Refuse a
    ; run boundary inside a record instead of assuming contiguous MFT sectors.
    mov  eax, [rel nt_found_ref]
    mov  ecx, [rel nt_rec_bytes]
    imul rax, rcx
    mov  rdx, rax
    lea  rdi, [rel nt_mft_runs]
    mov  esi, [rel nt_mft_nruns]
    call nt_vcn_to_lba
    cmp  rax, -2
    jae  .no
    test rcx, rcx
    jnz  .no
    mov  ecx, [rel nt_rec_bytes]
    cmp  rdx, rcx
    jb   .no
    mov  [rel nt_res_lba], rax
    cmp  byte [rel nt_rename_mode], 3
    jne  .child_mapping_ok
    call nt_dir_child_mapping
    test eax, eax
    jnz  .no
    mov  rax, [rel nt_res_lba]
.child_mapping_ok:
    mov  rsi, rax
    mov  edx, [rel nt_rec_sectors]
    call nt_lba_in_volume
    jc   .no
    ; Recreate original raw storage from fixed-up logical bytes.
    lea  rdi, [rel nt_res_expected]
    lea  rsi, [rel nt_rec_buf]
    mov  edx, [rel nt_rec_bytes]
    call memcpy
    lea  rbx, [rel nt_res_expected]
    movzx ecx, word [rbx + 4]
    movzx eax, word [rbx + rcx]
    mov  ecx, 1
.original_tails:
    mov  edx, ecx
    shl  edx, 9
    mov  [rbx + rdx - 2], ax
    inc  ecx
    cmp  ecx, [rel nt_rec_sectors]
    jbe  .original_tails
    lea  rdi, [rel nt_res_stage]
    lea  rsi, [rel nt_rec_buf]
    mov  edx, [rel nt_rec_bytes]
    call memcpy
    cmp  byte [rel nt_res_resize], 0
    je   .patch
    call nt_resident_resize_prepare
    cmp  rax, -2
    je   .uncertain
    test rax, rax
    jnz  .no
.patch:
    cmp  byte [rel nt_rename_mode], 3
    jne  .patch_mode
    call nt_dir_staged_parents
    test rax, rax
    jnz  .uncertain
    mov  byte [rel nt_dir_ready], 1      ; all affected preimages now derived
.patch_mode:
    cmp  byte [rel nt_nr_mode], 0
    jne  .encode
    cmp  byte [rel nt_rename_mode], 0
    jne  .encode
    lea  rdi, [rel nt_res_stage]
    mov  eax, [rel nt_res_value]
    add  rdi, rax
    add  rdi, r12
    mov  rsi, r13
    mov  rdx, r14
    call memcpy
.encode:
    lea  rdi, [rel nt_res_stage]
    call nt_resident_encode
    cmp  byte [rel nt_nr_mode], 0
    je   .metadata_ready
    call nt_nr_prepare
    cmp  rax, -2
    je   .uncertain
    test rax, rax
    jnz  .no
    call nt_nr_write_data               ; durable initialized bytes BEFORE sizes
    test rax, rax
    jnz  .uncertain
.metadata_ready:
    xor  r15d, r15d
.sector:
    ; Compare whole current raw record with expected partial postimage before
    ; each sector, so observed stale/foreign changes are never overwritten.
    call nt_resident_compare
    test rax, rax
    jnz  .uncertain
    mov  rax, r15
    mov  rsi, [rel nt_res_lba]
    lea  rcx, [rel nt_res_stage]
    lea  rdi, [rel nt_res_expected]
    cmp  eax, [rel nt_rec_sectors]
    jb   .selected
    sub  eax, [rel nt_rec_sectors]
    mov  rsi, [rel nt_res_parent_lba]
    lea  rcx, [rel nt_res_parent_stage]
    lea  rdi, [rel nt_res_parent_expected]
    cmp  byte [rel nt_cross], 0
    je   .selected
    cmp  eax, [rel nt_rec_sectors]
    jae  .destination
    mov  rsi, [rel nt_cross_source_lba]
    lea  rcx, [rel nt_cross_source_stage]
    lea  rdi, [rel nt_cross_source_expected]
    jmp  .selected
.destination:
    sub  eax, [rel nt_rec_sectors]
.selected:
    add  rsi, rax
    shl  rax, 9
    add  rcx, rax
    add  rdi, rax
    push rdi
    push rcx
    mov  edx, 1
    mov  r9d, 1                          ; current OWNER/intent on EVERY retry
    inc  dword [rel nt_res_attempted]     ; sector may have changed on failure
    call nt_write
    pop  rsi
    pop  rdi
    test rax, rax
    jnz  .uncertain
    inc  dword [rel nt_res_confirmed]
    mov  edx, 512
    call memcpy
    inc  r15d
    mov  eax, [rel nt_rec_sectors]
    cmp  byte [rel nt_res_resize], 0
    je   .counted
    add  eax, eax
    cmp  byte [rel nt_cross], 0
    je   .counted
    add  eax, [rel nt_rec_sectors]
.counted:
    cmp  r15d, eax
    jb   .sector
    call nt_save_current
    test rax, rax
    jnz  .uncertain
    mov  rdi, [rel nt_dev]
    call blk_flush
    mov  [rel nt_last_blk_rc], rax
    test rax, rax
    jnz  .flush_fail
    call nt_resident_compare             ; independent raw buffer after flush
    test rax, rax
    jnz  .verify_fail
    mov  dword [rel nt_wref], 0
    lea  rdi, [rel str_nt_write_verified]
    call serial_string
    mov  rdi, r14
    call serial_hex64
    call serial_newline
    mov  rax, r14
    jmp  .out
.flush_fail:
    mov  dword [rel nt_wref], NT_WREF_FLUSH
    jmp  .disarm
.verify_fail:
    mov  dword [rel nt_wref], NT_WREF_VERIFY
    jmp  .disarm
.uncertain:
    mov  dword [rel nt_wref], NT_WREF_IO
.disarm:
    mov  byte [rel nt_write_armed], 0
.no:
    mov  rax, -1
.out:
    mov  byte [rel nt_res_resize], 0     ; transaction-local geometry/parent scope
    add  rsp, 8
    pop  r15
    pop  rbx
    ret

; Private complete raw-record identity/readback comparison; current authority
; both sides of reads, including fallback reads. No write/rollback on failure.
nt_resident_compare:
    mov  rsi, [rel nt_res_lba]
    lea  rdi, [rel nt_res_expected]
    call nt_resident_compare_one
    test rax, rax
    jnz  .out
    cmp  byte [rel nt_res_resize], 0
    je   .out
    mov  rsi, [rel nt_res_parent_lba]
    lea  rdi, [rel nt_res_parent_expected]
    call nt_resident_compare_one
    test rax, rax
    jnz  .out
    cmp  byte [rel nt_cross], 0
    je   .out
    mov  rsi, [rel nt_cross_source_lba]
    lea  rdi, [rel nt_cross_source_expected]
    jmp  nt_resident_compare_one
.out:
    ret

; RSI=LBA, RDI=expected raw record. Never fix up a possibly partial image.
nt_resident_compare_one:
    push rbx
    push rsi
    mov  rbx, rdi
    call nt_save_current
    pop  rsi
    test rax, rax
    jnz  .no
    mov  edx, [rel nt_rec_sectors]
    lea  rcx, [rel nt_res_readback]
    call nt_read
    test rax, rax
    jnz  .no
    call nt_save_current
    test rax, rax
    jnz  .no
    lea  rdi, [rel nt_res_readback]
    mov  rsi, rbx
    mov  edx, [rel nt_rec_bytes]
    call memcmp
    pop  rbx
    ret
.no:
    mov  rax, -1
    pop  rbx
    ret

; Encode a previously validated logical FILE at RDI into raw USA storage.
nt_resident_encode:
    movzx r8d, word [rdi + 4]
    inc  word [rdi + r8]                 ; new USN, never zero
    jnz  .token_ok
    inc  word [rdi + r8]
.token_ok:
    mov  ax, [rdi + r8]
    mov  ecx, 1
.tails:
    mov  edx, ecx
    shl  edx, 9
    mov  r9w, [rdi + rdx - 2]
    lea  r10, [r8 + rcx*2]
    mov  [rdi + r10], r9w                ; logical tails saved in USA
    mov  [rdi + rdx - 2], ax
    inc  ecx
    cmp  ecx, [rel nt_rec_sectors]
    jbe  .tails
    ret

; Prepare BOTH records before the first write. Supported resize layout:
; one link/name, final DATA, ordinary resident parent leaf. Multi-entry resize
; and rename admit uppercase ASCII Win32 ordinary keys in strict name order.
; The original single-entry resize subset remains supported.
; No index allocation, aliases, extension records or metadata allocation.
; Returns -1 for unsupported, -2 for uncertain read/authority, 0 when staged.
nt_resident_resize_prepare:
    push rbx
    push r15
    lea  rbx, [rel nt_res_stage]
    cmp  word [rbx + 18], 1
    jne  .no
    cmp  dword [rel nt_res_fn_count], 1
    jne  .no
    mov  eax, [rel nt_res_end]
    add  eax, 8
    cmp  eax, [rbx + 24]                 ; final end marker incl reserved word
    jne  .no
    cmp  byte [rel nt_rename_mode], 3
    je   .name_capacity                 ; directory preserves the whole index
    mov  edx, [rel nt_res_data]
    mov  eax, [rbx + rdx + 4]
    add  eax, edx
    cmp  eax, [rel nt_res_end]           ; DATA must be last
    jne  .no
    cmp  byte [rel nt_nr_mode], 0
    jne  .name_capacity                 ; preallocated DATA span stays exact
    cmp  byte [rel nt_rename_mode], 2
    je   .name_capacity                 ; unchanged nonresident attribute span
    movzx eax, word [rbx + rdx + 20]
    add  rax, r14                       ; full64 capacity before narrowing
    jc   .no
    add  rax, 7
    jc   .no
    and  rax, -8
    mov  ecx, [rel nt_rec_bytes]
    sub  ecx, edx
    sub  ecx, 8
    cmp  rax, rcx
    ja   .no
    mov  [rel nt_res_new_attr], eax
    add  eax, edx
    add  eax, 8
    mov  [rel nt_res_new_used], eax
.name_capacity:
    mov  edx, [rel nt_res_fn]
    cmp  byte [rel nt_nr_mode], 0
    jne  .nonresident_cache
    cmp  byte [rel nt_rename_mode], 2
    jne  .child_filename
.nonresident_cache:
    mov  ecx, [rel nt_res_data]
    mov  rax, [rbx + rcx + 40]
    cmp  [rbx + rdx + 40], rax
    jne  .no                            ; child allocation cache agrees with DATA
    mov  rax, [rbx + rcx + 48]
    cmp  [rbx + rdx + 48], rax
    jne  .no                            ; child real size cache agrees with DATA
.child_filename:
    movzx eax, byte [rbx + rdx + 64]
    test eax, eax
    jz   .no
    cmp  eax, 63
    ja   .no
    lea  eax, [rax*2 + 66]
    cmp  eax, [rel nt_res_fn_len]
    jne  .no
    cmp  byte [rbx + rdx + 65], 3
    ja   .no
    cmp  byte [rbx + rdx + 65], 2        ; no DOS alias
    je   .no
    mov  rax, [rbx + rdx]               ; full parent reference incl sequence
    mov  [rel nt_res_parent_ref], rax
    cmp  byte [rel nt_rename_mode], 0
    je   .parent_identity
    cmp  rax, [rel nt_rename_parent_full]
    jne  .no                            ; resolved parent including sequence
    cmp  byte [rbx + rdx + 65], 1         ; Win32 only; no POSIX/DOS aliases
    jne  .no
    movzx ecx, byte [rbx + rdx + 64]
    cmp  ecx, [rel nt_rename_old_len]
    jne  .no
    push rax
    mov  rsi, [rel nt_rename_old]
    xor  ecx, ecx
.old_name:
    movzx eax, byte [rsi + rcx]
    cmp  [rbx + rdx + 66], ax
    jne  .bad_old
    add  edx, 2
    inc  ecx
    cmp  ecx, [rel nt_rename_old_len]
    jb   .old_name
    pop  rax
    jmp  .parent_identity
.bad_old:
    pop  rax
    jmp  .no
.parent_identity:
    shr  rax, 32
    test ax, ax                         ; no >32-bit parent record
    jnz  .no
    shr  rax, 16
    test ax, ax
    jz   .no
    mov  edi, [rel nt_res_parent_ref]
    cmp  edi, [rel nt_found_ref]
    je   .no
    cmp  edi, NT_REC_ROOT
    je   .ordinary_parent
    cmp  edi, 16
    jb   .no
.ordinary_parent:
    mov  eax, [rel nt_clus_bytes]
    xor  edx, edx
    div  dword [rel nt_rec_bytes]
    cmp  edi, eax
    jb   .no
    mov  eax, edi
    mov  ecx, [rel nt_rec_bytes]
    imul rax, rcx
    mov  rdx, rax
    lea  rdi, [rel nt_mft_runs]
    mov  esi, [rel nt_mft_nruns]
    call nt_vcn_to_lba
    cmp  rax, -2
    jae  .no
    test rcx, rcx
    jnz  .no
    mov  ecx, [rel nt_rec_bytes]
    cmp  rdx, rcx
    jb   .no
    mov  [rel nt_res_parent_lba], rax
    mov  rsi, rax
    mov  edx, [rel nt_rec_sectors]
    call nt_lba_in_volume
    jc   .no
    call nt_save_current
    test rax, rax
    jnz  .uncertain
    mov  edi, [rel nt_res_parent_ref]
    call nt_read_record
    test rax, rax
    jnz  .uncertain
    call nt_save_current
    test rax, rax
    jnz  .uncertain
    lea  rbx, [rel nt_rec_buf]
    cmp  dword [rbx], 'FILE'
    jne  .no
    cmp  word [rbx + 22], 3
    jne  .no
    cmp  word [rbx + 18], 1
    jne  .no
    cmp  qword [rbx + 32], 0
    jne  .no
    mov  eax, [rel nt_res_parent_ref]
    cmp  [rbx + 44], eax
    jne  .no
    mov  rax, [rel nt_res_parent_ref]
    shr  rax, 48
    cmp  [rbx + 16], ax
    jne  .no
    mov  ecx, [rel nt_rec_sectors]
    inc  ecx
    cmp  [rbx + 6], cx
    jne  .no
    movzx eax, word [rbx + 4]
    cmp  eax, 48
    jb   .no
    lea  eax, [rax + rcx*2]
    movzx r8d, word [rbx + 20]
    cmp  eax, r8d
    ja   .no
    test r8d, 7
    jnz  .no
    mov  r10d, [rbx + 24]
    mov  eax, [rel nt_rec_bytes]
    cmp  [rbx + 28], eax
    jne  .no
    cmp  r10d, eax
    ja   .no
    sub  r10d, 8
    jc   .no
    xor  r9d, r9d
    xor  r11d, r11d                     ; STDINFO/FILENAME/INDEXROOT bits
.attrs:
    cmp  r8d, r10d
    ja   .no
    mov  eax, [rbx + r8]
    cmp  eax, -1
    je   .end_attrs
    cmp  eax, r9d                       ; no repeated attrs / aliases
    jbe  .no
    mov  r9d, eax
    cmp  eax, NT_A_STDINFO
    je   .allowed
    cmp  eax, NT_A_FILENAME
    je   .allowed
    cmp  eax, 0x40
    je   .allowed
    cmp  eax, 0x50
    je   .allowed
    cmp  eax, NT_A_INDEXROOT
    jne  .no
.allowed:
    lea  eax, [r8 + 24]
    cmp  eax, r10d
    ja   .no
    mov  ecx, [rbx + r8 + 4]
    cmp  ecx, 24
    jb   .no
    test ecx, 7
    jnz  .no
    add  ecx, r8d
    jc   .no
    cmp  ecx, r10d
    ja   .no
    cmp  byte [rbx + r8 + 8], 0
    jne  .no
    cmp  word [rbx + r8 + 12], 0
    jne  .no
    movzx edx, word [rbx + r8 + 20]
    cmp  edx, 24
    jb   .no
    add  edx, r8d
    mov  eax, [rbx + r8 + 16]
    add  eax, edx
    jc   .no
    cmp  eax, ecx
    ja   .no
    cmp  r9d, NT_A_INDEXROOT
    je   .index
    cmp  byte [rbx + r8 + 9], 0
    jne  .no
    cmp  r9d, NT_A_STDINFO
    jne  .filename
    or   r11d, 1
    cmp  dword [rbx + r8 + 16], 36
    jb   .no
    test dword [rbx + rdx + 32], 0x4E07 ; ordinary directory, no protected flags
    jnz  .no
.filename:
    cmp  r9d, NT_A_FILENAME
    jne  .next
    or   r11d, 2
    cmp  dword [rbx + r8 + 16], 66
    jb   .no
    test dword [rbx + rdx + 56], 0x4E07
    jnz  .no
    jmp  .next
.index:
    mov  [rel nt_rename_index_attr], r8d
    cmp  byte [rel nt_rename_mode], 0
    je   .index_aligned
    test edx, 7                        ; named resident value is 8-byte aligned
    jnz  .no
.index_aligned:
    or   r11d, 4
    cmp  byte [rbx + r8 + 9], 4
    jne  .no
    cmp  word [rbx + r8 + 10], 24
    jne  .no
    lea  eax, [r8 + 32]
    cmp  eax, edx                       ; name cannot overlap the value
    ja   .no
    mov  rax, 0x0030003300490024        ; UTF16 $I30
    cmp  [rbx + r8 + 24], rax
    jne  .no
    mov  eax, [rbx + r8 + 16]
    cmp  eax, 32
    jb   .no
    cmp  dword [rbx + rdx], NT_A_FILENAME
    jne  .no
    cmp  dword [rbx + rdx + 4], 1        ; filename collation
    jne  .no
    add  edx, 16                        ; INDEX_HEADER
    mov  [rel nt_rename_index_header], edx
    cmp  dword [rbx + rdx + 12], 0      ; leaf, reserved bytes zero
    jne  .no
    mov  r15d, [rbx + rdx]
    cmp  r15d, 16
    jb   .no
    test r15d, 7
    jnz  .no
    mov  eax, [rbx + rdx + 4]           ; used <= allocated <= value extent
    cmp  r15d, eax                      ; bound relative offset before addition
    ja   .no
    cmp  eax, [rbx + rdx + 8]
    ja   .no
    cmp  byte [rel nt_rename_mode], 0
    je   .index_size_ok
    cmp  eax, [rbx + rdx + 8]            ; resident root used == allocated
    jne  .no
.index_size_ok:
    push rcx
    mov  ecx, [rbx + r8 + 16]
    sub  ecx, 16
    cmp  [rbx + rdx + 8], ecx
    pop  rcx
    ja   .no
    add  eax, edx
    mov  [rel nt_res_index_end], eax
    add  r15d, edx
    cmp  byte [rel nt_nr_mode], 0
    jne  .complete_leaf
    cmp  byte [rel nt_rename_mode], 0
    jne  .complete_leaf
    ; Preserve the original one-entry resize domain. A sibling layout must
    ; pass the shared complete leaf validator, never stop at the found key.
    lea  eax, [r15 + 16]
    cmp  eax, [rel nt_res_index_end]
    ja   .no
    movzx eax, word [rbx + r15 + 8]
    lea  eax, [r15 + rax + 16]
    cmp  eax, [rel nt_res_index_end]
    je   .single_entry
.complete_leaf:
    call nt_rename_leaf                  ; complete leaf, including later keys
    test rax, rax
    jnz  .no
    jmp  .next
.single_entry:
    lea  eax, [r15 + 16]
    cmp  eax, [rel nt_res_index_end]
    ja   .no
    cmp  dword [rbx + r15 + 12], 0      ; no child VCN/unknown flags
    jne  .no
    movzx eax, word [rbx + r15 + 8]
    test eax, 7
    jnz  .no
    cmp  eax, 16
    jb   .no
    add  eax, r15d
    jc   .no
    mov  [rel nt_res_index_next], eax
    cmp  eax, [rel nt_res_index_end]
    ja   .no
    movzx eax, word [rbx + r15 + 10]
    cmp  eax, [rel nt_res_fn_len]
    jne  .no
    add  eax, 16
    movzx edx, word [rbx + r15 + 8]
    cmp  eax, edx
    ja   .no
    movzx eax, word [rel nt_found_sequence]
    shl  rax, 48
    or   rax, [rel nt_found_ref]
    cmp  [rbx + r15], rax
    jne  .no
    add  r15d, 16                       ; FILE_NAME key
    ; Exact parent identity, name/namespace and ordinary attributes. Cached
    ; timestamps and old sizes can differ; both affected size caches replaced.
    mov  rax, [rel nt_res_parent_ref]
    cmp  [rbx + r15], rax
    jne  .no
    test dword [rbx + r15 + 56], 0x4E17
    jnz  .no
    push rcx
    push r8
    push r9
    push r10
    push r11
    lea  rdi, [rbx + r15 + 64]
    lea  rsi, [rel nt_res_stage]
    mov  eax, [rel nt_res_fn]
    lea  rsi, [rsi + rax + 64]
    mov  edx, [rel nt_res_fn_len]
    sub  edx, 64
    call memcmp
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rcx
    test rax, rax
    jnz  .no
    mov  [rel nt_res_parent_key], r15d
    mov  edx, [rel nt_res_index_next]
    lea  eax, [rdx + 16]
    cmp  eax, [rel nt_res_index_end]     ; one entry only; no alias/other layout
    jne  .no
    cmp  word [rbx + rdx + 8], 16
    jne  .no
    cmp  word [rbx + rdx + 10], 0
    jne  .no
    cmp  dword [rbx + rdx + 12], 2
    jne  .no
.next:
    mov  r8d, ecx
    jmp  .attrs
.end_attrs:
    cmp  r8d, r10d
    jne  .no
    cmp  r11d, 7
    jne  .no
    lea  rdi, [rel nt_res_parent_expected]
    mov  rsi, rbx
    mov  edx, [rel nt_rec_bytes]
    call memcpy
    lea  rdi, [rel nt_res_parent_stage]
    mov  rsi, rbx
    mov  edx, [rel nt_rec_bytes]
    call memcpy
    lea  rbx, [rel nt_res_parent_expected]
    movzx ecx, word [rbx + 4]
    mov  ax, [rbx + rcx]
    mov  ecx, 1
.raw_tails:
    mov  edx, ecx
    shl  edx, 9
    mov  [rbx + rdx - 2], ax
    inc  ecx
    cmp  ecx, [rel nt_rec_sectors]
    jbe  .raw_tails
    cmp  byte [rel nt_cross], 0
    je   .ordinary_stage
    cmp  byte [rel nt_cross_phase], 0
    jne  .cross_stage
    mov  rax, [rel nt_res_parent_lba]
    mov  [rel nt_cross_source_lba], rax
    mov  eax, [rel nt_rename_index_attr]
    mov  [rel nt_cross_source_attr], eax
    mov  eax, [rel nt_rename_index_header]
    mov  [rel nt_cross_source_header], eax
    mov  eax, [rel nt_res_parent_key]
    mov  [rel nt_cross_source_key], eax
    lea  rdi, [rel nt_cross_source_expected]
    lea  rsi, [rel nt_res_parent_expected]
    mov  edx, [rel nt_rec_bytes]
    call memcpy
    lea  rdi, [rel nt_cross_source_stage]
    lea  rsi, [rel nt_res_parent_stage]
    mov  edx, [rel nt_rec_bytes]
    call memcpy
    mov  byte [rel nt_cross_phase], 1
    mov  rax, [rel nt_cross_dest_ref]
    mov  [rel nt_res_parent_ref], rax
    jmp  .parent_identity
.cross_stage:
    call nt_cross_stage
    jmp  .out
.ordinary_stage:
    cmp  byte [rel nt_rename_mode], 0
    jne  .rename_names
    lea  rbx, [rel nt_res_parent_stage]
    mov  edx, [rel nt_res_parent_key]
    call nt_resize_allocation
    mov  [rbx + rdx + 40], rax
    mov  [rbx + rdx + 48], r14
    mov  rdi, rbx
    call nt_resident_encode
    lea  rbx, [rel nt_res_stage]
    mov  edx, [rel nt_res_fn]
    call nt_resize_allocation
    mov  [rbx + rdx + 40], rax
    mov  [rbx + rdx + 48], r14
    cmp  byte [rel nt_nr_mode], 0
    je   .resident_stage
    mov  edx, [rel nt_res_data]
    mov  [rbx + rdx + 48], r14           ; retain allocated_size and mapping pairs
    mov  [rbx + rdx + 56], r14           ; every published byte is staged + flushed
    xor  eax, eax
    jmp  .out
.resident_stage:
    mov  ecx, [rbx + 24]
    mov  eax, [rel nt_res_new_used]
    cmp  ecx, eax
    jae  .clear
    mov  ecx, eax
.clear:
    mov  eax, [rel nt_res_value]
    lea  rdi, [rbx + rax]
    sub  ecx, eax
    xor  eax, eax
    rep  stosb                          ; DATA/padding/end marker only
    mov  edx, [rel nt_res_data]
    mov  eax, [rel nt_res_new_attr]
    mov  [rbx + rdx + 4], eax
    mov  [rbx + rdx + 16], r14d
    add  eax, edx
    mov  dword [rbx + rax], -1
    mov  eax, [rel nt_res_new_used]
    mov  [rbx + 24], eax
    xor  eax, eax
    jmp  .out
.rename_names:
    ; Resize aligned spans; reuse extra slot allocation before record space.
    ; Both complete logical records have passed all admission before this.
    ; Check BOTH capacities before changing either staged image.
    mov  eax, [rel nt_rename_len]
    lea  eax, [rax*2 + 66]
    mov  [rel nt_rename_key_len], eax
    lea  rdi, [rel nt_res_stage]
    mov  r8d, [rel nt_rename_fn_attr]
    movzx esi, word [rdi + r8 + 20]
    add  esi, [rel nt_res_fn_len]
    add  esi, 7
    and  esi, -8                        ; old minimal aligned attribute span
    movzx edx, word [rdi + r8 + 20]
    add  edx, eax
    add  edx, 7
    and  edx, -8
    sub  edx, esi                       ; signed child span delta
    test edx, edx
    jle  .child_cut
    mov  eax, [rdi + r8 + 4]
    sub  eax, esi                       ; reuse extra FILE_NAME allocation
    cmp  eax, edx
    jbe  .child_slack
    mov  eax, edx
.child_slack:
    add  esi, eax
    sub  edx, eax
.child_cut:
    add  esi, r8d
    mov  [rel nt_rename_child_cut], esi
    mov  [rel nt_rename_child_delta], edx
    movsxd rax, edx
    mov  ecx, [rdi + 24]
    add  rax, rcx
    mov  r9d, [rel nt_rec_bytes]
    cmp  rax, r9
    ja   .no                            ; no child record space
    lea  rbx, [rel nt_res_parent_stage]
    mov  r8d, [rel nt_res_parent_key]
    movzx esi, word [rbx + r8 - 6]       ; old key length
    add  esi, 16 + 7
    and  esi, -8
    mov  edx, [rel nt_rename_key_len]
    add  edx, 16 + 7
    and  edx, -8
    sub  edx, esi                       ; signed entry/index/parent delta
    test edx, edx
    jle  .parent_cut
    movzx eax, word [rbx + r8 - 8]
    sub  eax, esi                       ; reuse extra index entry allocation
    cmp  eax, edx
    jbe  .parent_slack
    mov  eax, edx
.parent_slack:
    add  esi, eax
    sub  edx, eax
.parent_cut:
    lea  esi, [rsi + r8 - 16]
    mov  [rel nt_rename_parent_cut], esi
    mov  [rel nt_rename_parent_delta], edx
    movsxd rax, edx
    mov  ecx, [rbx + 24]
    add  rax, rcx
    cmp  rax, r9
    ja   .no                            ; no parent record space
    ; Child: move extra attribute slack, every following attribute and END.
    mov  esi, [rel nt_rename_child_cut]
    mov  ecx, [rdi + 24]
    mov  edx, [rel nt_rename_child_delta]
    call nt_rename_shift
    mov  r8d, [rel nt_rename_fn_attr]
    mov  edx, [rel nt_rename_child_delta]
    add  [rdi + r8 + 4], edx
    add  [rdi + 24], edx
    mov  eax, [rel nt_rename_key_len]
    mov  [rdi + r8 + 16], eax
    ; Parent: move extra entry slack, END entry, index/attribute slack, END.
    mov  rdi, rbx
    mov  esi, [rel nt_rename_parent_cut]
    mov  ecx, [rdi + 24]
    mov  edx, [rel nt_rename_parent_delta]
    call nt_rename_shift
    mov  r8d, [rel nt_res_parent_key]
    mov  edx, [rel nt_rename_parent_delta]
    add  [rdi + r8 - 8], dx              ; entry allocated length
    mov  eax, [rel nt_rename_key_len]
    mov  [rdi + r8 - 6], ax              ; key logical length
    mov  r8d, [rel nt_rename_index_header]
    add  [rdi + r8 + 4], edx             ; index used and allocated
    add  [rdi + r8 + 8], edx
    mov  r8d, [rel nt_rename_index_attr]
    add  [rdi + r8 + 4], edx             ; attribute allocated and value length
    add  [rdi + r8 + 16], edx
    add  [rdi + 24], edx
    ; Rewrite names and zero only their new minimal alignment padding.
    lea  rdi, [rel nt_res_stage]
    mov  eax, [rel nt_res_fn]
    lea  rdx, [rel nt_res_stage]
    mov  ecx, [rel nt_rename_fn_attr]
    add  rdx, rcx                       ; child attribute alignment base
    lea  rdi, [rdi + rax]
    call nt_rename_name
    lea  rdi, [rel nt_res_parent_stage]
    mov  eax, [rel nt_res_parent_key]
    lea  rdi, [rdi + rax]
    lea  rdx, [rdi - 16]                 ; parent entry alignment base
    call nt_rename_name
    call nt_rename_reorder               ; move the whole entry; siblings exact
    lea  rdi, [rel nt_res_parent_stage]
    call nt_resident_encode
    xor  eax, eax
    jmp  .out
.uncertain:
    mov  rax, -2
    jmp  .out
.no:
    mov  rax, -1
.out:
    pop  r15
    pop  rbx
    ret

; All three complete records and both full leaves admitted, no media changes.
; Preserve the source index's cached FILE_NAME metadata in the moved key.
nt_cross_stage:
    push rbx
    mov  rax, [rel nt_res_lba]
    mov  rdx, [rel nt_cross_source_lba]
    call nt_cross_record_pair
    test eax, eax
    jnz  .no
    mov  rax, [rel nt_res_lba]
    mov  rdx, [rel nt_res_parent_lba]
    call nt_cross_record_pair
    test eax, eax
    jnz  .no
    mov  rax, [rel nt_cross_source_lba]
    mov  rdx, [rel nt_res_parent_lba]
    call nt_cross_record_pair
    test eax, eax
    jnz  .no
    mov  eax, [rel nt_rename_len]
    lea  eax, [rax*2 + 66]
    mov  [rel nt_rename_key_len], eax
    lea  rdi, [rel nt_res_stage]
    mov  r8d, [rel nt_rename_fn_attr]
    movzx esi, word [rdi + r8 + 20]
    add  esi, [rel nt_res_fn_len]
    add  esi, 7
    and  esi, -8                        ; old minimal aligned attribute span
    movzx edx, word [rdi + r8 + 20]
    add  edx, eax
    add  edx, 7
    and  edx, -8
    sub  edx, esi                       ; signed child span delta
    test edx, edx
    jle  .child_cut
    mov  eax, [rdi + r8 + 4]
    sub  eax, esi                       ; reuse extra FILE_NAME allocation
    cmp  eax, edx
    jbe  .child_slack
    mov  eax, edx
.child_slack:
    add  esi, eax
    sub  edx, eax
.child_cut:
    add  esi, r8d
    mov  [rel nt_rename_child_cut], esi
    mov  [rel nt_rename_child_delta], edx
    movsxd rax, edx
    mov  ecx, [rdi + 24]
    add  rax, rcx
    mov  r9d, [rel nt_rec_bytes]
    cmp  rax, r9
    ja   .no                            ; cross-parent child record space
    ; New destination entry uses a minimal aligned span, no allocation.
    mov  eax, [rel nt_rename_key_len]
    add  eax, 16 + 7
    and  eax, -8
    mov  [rel nt_cross_entry_size], eax
    lea  rbx, [rel nt_res_parent_stage]
    add  eax, [rbx + 24]
    cmp  eax, [rel nt_rec_bytes]
    ja   .no                            ; destination capacity before staging
    ; Child: move extra attribute slack, every following attribute and END.
    mov  esi, [rel nt_rename_child_cut]
    mov  ecx, [rdi + 24]
    mov  edx, [rel nt_rename_child_delta]
    call nt_rename_shift
    mov  r8d, [rel nt_rename_fn_attr]
    mov  edx, [rel nt_rename_child_delta]
    add  [rdi + r8 + 4], edx
    add  [rdi + 24], edx
    mov  eax, [rel nt_rename_key_len]
    mov  [rdi + r8 + 16], eax
    lea  rdi, [rel nt_res_stage]
    mov  eax, [rel nt_res_fn]
    mov  rdx, [rel nt_cross_dest_ref]
    mov  [rdi + rax], rdx              ; child's complete new parent reference
    mov  ecx, [rel nt_rename_fn_attr]
    lea  rdx, [rdi + rcx]
    add  rdi, rax
    call nt_rename_name
    ; Save target header and cached metadata before removing its whole span.
    lea  rsi, [rel nt_cross_source_stage]
    mov  eax, [rel nt_cross_source_key]
    lea  rsi, [rsi + rax - 16]
    lea  rdi, [rel nt_rename_entry]
    mov  edx, 82
    call memcpy
    lea  rdi, [rel nt_rename_entry]
    mov  eax, [rel nt_cross_entry_size]
    mov  [rdi + 8], ax
    mov  eax, [rel nt_rename_key_len]
    mov  [rdi + 10], ax
    mov  rax, [rel nt_cross_dest_ref]
    mov  [rdi + 16], rax
    mov  rdx, rdi
    add  rdi, 16
    call nt_rename_name
    ; Source removal moves every later entry/attribute/END and clears vacated
    ; bytes; lengths change by the entire original entry allocation.
    lea  rdi, [rel nt_cross_source_stage]
    mov  eax, [rel nt_cross_source_key]
    movzx edx, word [rdi + rax - 8]
    lea  esi, [rax + rdx - 16]
    neg  edx
    mov  ecx, [rdi + 24]
    call nt_rename_shift
    mov  r8d, [rel nt_cross_source_header]
    mov  r9d, [rel nt_cross_source_attr]
    call nt_cross_lengths
    call nt_resident_encode
    ; Destination insertion at the independently validated lexical position.
    lea  rdi, [rel nt_res_parent_stage]
    mov  esi, [rel nt_rename_insert]
    mov  ecx, [rdi + 24]
    mov  edx, [rel nt_cross_entry_size]
    call nt_rename_shift
    mov  r8d, [rel nt_rename_index_header]
    mov  r9d, [rel nt_rename_index_attr]
    call nt_cross_lengths
    lea  rdi, [rel nt_res_parent_stage]
    mov  eax, [rel nt_rename_insert]
    add  rdi, rax
    lea  rsi, [rel nt_rename_entry]
    mov  edx, [rel nt_cross_entry_size]
    call memcpy
    lea  rdi, [rel nt_res_parent_stage]
    call nt_resident_encode
    xor  eax, eax
    pop  rbx
    ret
.no:
    mov  rax, -1
    pop  rbx
    ret

; Complete record mappings must be physically disjoint, even if corrupt MFT
; run pairs alias distinct record identities. Both ends were volume-bounded.
nt_cross_record_pair:
    cmp  rax, rdx
    jbe  .ordered
    xchg rax, rdx
.ordered:
    mov  ecx, [rel nt_rec_sectors]
    add  rax, rcx
    cmp  rax, rdx
    ja   .no
    xor  eax, eax
    ret
.no:
    mov  eax, -1
    ret

; RDI=staged parent, EDX=signed entry delta, R8D=header, R9D=attribute.
nt_cross_lengths:
    add  [rdi + r8 + 4], edx
    add  [rdi + r8 + 8], edx
    add  [rdi + r9 + 4], edx
    add  [rdi + r9 + 16], edx
    add  [rdi + 24], edx
    ret

; RBX=validated parent FILE, R15D=first entry, index_end already bounded.
; No staging/media changes: reject the entire leaf before admitting either FILE.
; Conservative collation domain: uppercase ASCII A-Z/0-9/._-, no leading dot.
; Thus byte/UTF16 lexical order agrees with filename collation without assuming
; an arbitrary Unicode upcase table. Refuse lowercase and all other codepoints.
nt_rename_leaf:
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov  ebp, r15d
    mov  r12d, [rel nt_res_index_end]
    xor  r13d, r13d                    ; previous entry
    mov  dword [rel nt_res_parent_key], 0
    mov  dword [rel nt_rename_insert], 0
    cmp  byte [rel nt_dir_leaf], 0
    jne  .loop
    cmp  byte [rel nt_rename_mode], 0
    je   .loop                          ; resize has no destination name
    lea  rdi, [rel nt_rename_new_key]
    mov  rdx, rdi
    call nt_rename_name
.loop:
    lea  eax, [r15 + 16]
    cmp  eax, r12d
    ja   .no
    movzx r14d, word [rbx + r15 + 8]
    cmp  r14d, 16
    jb   .no
    test r14d, 7
    jnz  .no
    add  r14d, r15d
    cmp  r14d, r12d
    ja   .no
    cmp  dword [rbx + r15 + 12], 2
    je   .end
    cmp  dword [rbx + r15 + 12], 0
    jne  .no
    movzx eax, word [rbx + r15 + 10]
    cmp  eax, 68                       ; at least one UTF16 code unit
    jb   .no
    lea  edx, [r15 + rax + 16]
    cmp  edx, r14d
    ja   .no
    movzx ecx, byte [rbx + r15 + 80]
    test ecx, ecx
    jz   .no
    cmp  ecx, 63
    ja   .no
    lea  edx, [rcx*2 + 66]
    cmp  eax, edx
    jne  .no
    cmp  byte [rbx + r15 + 81], 1
    je   .namespace
    cmp  byte [rel nt_dir_parent_only], 0
    je   .system_key
    cmp  byte [rbx + r15 + 81], 0
    je   .namespace                     ; POSIX key (libntfs-3g)
    cmp  byte [rbx + r15 + 81], 3
    je   .namespace                     ; Win32+DOS key (Windows 8.3 name)
.system_key:
    cmp  dword [rel nt_res_parent_ref], NT_REC_ROOT
    jne  .no
    cmp  dword [rbx + r15], 16
    jae  .no
.namespace:
    mov  rax, [rel nt_res_parent_ref]
    cmp  [rbx + r15 + 16], rax
    jne  .no
    cmp  dword [rel nt_res_parent_ref], NT_REC_ROOT
    jne  .ordinary_flags
    cmp  dword [rbx + r15], 16
    jae  .ordinary_flags
    call nt_root_system_key
    test eax, eax
    jnz  .no
    jmp  .system_ref
.ordinary_flags:
    test dword [rbx + r15 + 72], 0x4E07
    jnz  .no
    mov  eax, [rbx + r15 + 72]
    and  eax, 0x10000010
    jz   .ordinary_key
    cmp  eax, 0x10000000
    jne  .key_type
    cmp  byte [rel nt_dir_parent_only], 0
    jne  .ordinary_key                  ; Windows/libntfs-3g directory key
.key_type:
    cmp  eax, 0x10000010
    jne  .no                            ; no ambiguous file/directory key type
.ordinary_key:
    cmp  dword [rbx + r15], 16
    jb   .no
.system_ref:
    mov  rax, [rbx + r15]
    cmp  eax, [rel nt_res_parent_ref]
    je   .no
    mov  rdx, rax
    shr  rdx, 32
    test dx, dx                        ; supported 32-bit FILE identity
    jnz  .no
    shr  rdx, 16
    test dx, dx                        ; nonzero sequence
    jz   .no
    mov  edx, ebp
.refs:
    cmp  edx, r15d
    jae  .chars_start
    cmp  eax, [rbx + rdx]              ; no aliases, even stale-sequence aliases
    je   .no
    movzx ecx, word [rbx + rdx + 8]
    add  edx, ecx
    jmp  .refs
.chars_start:
    cmp  dword [rbx + r15], 16
    jb   .ordered                       ; exact immutable $Secure/$Extend keys
    cmp  word [rbx + r15 + 82], '.'
    je   .no
    xor  ecx, ecx
.chars:
    lea  edx, [r15 + rcx*2]
    movzx eax, word [rbx + rdx + 82]
    cmp  eax, 'A'
    jb   .digit
    cmp  eax, 'Z'
    jbe  .char_ok
.digit:
    cmp  eax, '0'
    jb   .punct
    cmp  eax, '9'
    jbe  .char_ok
.punct:
    cmp  eax, '.'
    je   .char_ok
    cmp  eax, '_'
    je   .char_ok
    cmp  eax, '-'
    jne  .no
.char_ok:
    inc  ecx
    movzx eax, byte [rbx + r15 + 80]
    cmp  ecx, eax
    jb   .chars
.ordered:
    test r13d, r13d
    jz   .identity
    lea  rsi, [rbx + r13 + 16]
    lea  rdi, [rbx + r15 + 16]
    call nt_rename_compare
    test eax, eax
    jns  .no                           ; strict order, rejects duplicate names
.identity:
    cmp  byte [rel nt_dir_leaf], 0
    jne  .advance                       ; validation of an entire own/ancestor leaf
    cmp  byte [rel nt_cross_phase], 0
    je   .source_identity
    mov  eax, [rel nt_found_ref]
    cmp  [rbx + r15], eax
    je   .no                            ; destination cannot alias the moved FILE
    jmp  .destination
.source_identity:
    movzx eax, word [rel nt_found_sequence]
    shl  rax, 48
    or   rax, [rel nt_found_ref]
    cmp  [rbx + r15], rax
    jne  .destination
    cmp  dword [rel nt_res_parent_key], 0
    jne  .no
    movzx edx, word [rbx + r15 + 10]
    cmp  edx, [rel nt_res_fn_len]
    jne  .no
    cmp  byte [rel nt_nr_mode], 0
    jne  .nonresident_cache
    cmp  byte [rel nt_rename_mode], 2
    jne  .target_name
.nonresident_cache:
    lea  rsi, [rel nt_res_stage]
    mov  eax, [rel nt_res_fn]
    mov  rcx, [rsi + rax + 40]
    cmp  [rbx + r15 + 56], rcx
    jne  .no                            ; parent allocation cache agrees with child
    mov  rcx, [rsi + rax + 48]
    cmp  [rbx + r15 + 64], rcx
    jne  .no                            ; parent real size cache agrees with child
.target_name:
    mov  eax, [rbx + r15 + 72]
    and  eax, 0x10000010
    cmp  byte [rel nt_rename_mode], 3
    jne  .file_key
    cmp  eax, 0x10000010
    jne  .no                            ; directory target identity/type agrees
    jmp  .key_type_ok
.file_key:
    test eax, eax
    jnz  .no
.key_type_ok:
    sub  edx, 64
    lea  rdi, [rbx + r15 + 80]
    lea  rsi, [rel nt_res_stage]
    mov  eax, [rel nt_res_fn]
    lea  rsi, [rsi + rax + 64]
    call memcmp
    test rax, rax
    jnz  .no
    lea  eax, [r15 + 16]
    mov  [rel nt_res_parent_key], eax
    jmp  .advance
.destination:
    cmp  byte [rel nt_cross], 0
    je   .same_parent
    cmp  byte [rel nt_cross_phase], 0
    je   .advance
.same_parent:
    cmp  byte [rel nt_rename_mode], 0
    je   .advance                       ; resize keeps every entry in place
    lea  rsi, [rel nt_rename_new_key]
    lea  rdi, [rbx + r15 + 16]
    call nt_rename_compare
    test eax, eax
    jz   .no                           ; destination collision anywhere in leaf
    jns  .advance
    cmp  dword [rel nt_rename_insert], 0
    jne  .advance
    mov  [rel nt_rename_insert], r15d
.advance:
    mov  r13d, r15d
    mov  r15d, r14d
    jmp  .loop                         ; never early-success at target
.end:
    lea  eax, [r15 + 16]
    cmp  eax, r12d
    jne  .no
    cmp  word [rbx + r15 + 8], 16
    jne  .no
    cmp  word [rbx + r15 + 10], 0
    jne  .no
    cmp  qword [rbx + r15], 0
    jne  .no
    cmp  byte [rel nt_dir_leaf], 0
    jne  .destination_end
    cmp  byte [rel nt_cross_phase], 0
    jne  .destination_end
    cmp  dword [rel nt_res_parent_key], 0
    je   .no
.destination_end:
    cmp  dword [rel nt_rename_insert], 0
    jne  .ok
    mov  [rel nt_rename_insert], r15d   ; append before terminator
.ok:
    xor  eax, eax
    jmp  .out
.no:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rbp
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    ret

; RSI/RDI=admitted uppercase ASCII FILE_NAME keys; signed lexical comparison.
; Only EAX/ECX/EDX/R8D clobbered, never consult locale or a guessed Unicode table.
nt_rename_compare:
    xor  ecx, ecx
.loop:
    movzx eax, byte [rsi + 64]
    movzx edx, byte [rdi + 64]
    cmp  ecx, eax
    jae  .length
    cmp  ecx, edx
    jae  .length
    movzx eax, word [rsi + rcx*2 + 66]
    movzx edx, word [rdi + rcx*2 + 66]
    cmp  eax, edx
    jne  .difference
    inc  ecx
    jmp  .loop
.length:
    sub  eax, edx
    ret
.difference:
    sub  eax, edx
    ret

; Staging is already fully admitted, resized and named. Rotate the entire entry
; within the admitted leaf interval, preserving every sibling byte and padding.
nt_rename_reorder:
    lea  rdi, [rel nt_res_parent_stage]
    mov  r8d, [rel nt_res_parent_key]
    sub  r8d, 16                       ; target start
    mov  r9d, [rel nt_rename_insert]   ; insertion in original coordinates
    cmp  r9d, r8d
    jbe  .coordinate_ok
    add  r9d, [rel nt_rename_parent_delta]
.coordinate_ok:
    movzx r10d, word [rdi + r8 + 8]     ; entire resized target entry
    lea  rsi, [rel nt_rename_entry]
    xor  ecx, ecx
.save:
    mov  al, [rdi + r8]
    mov  [rsi + rcx], al
    inc  r8d
    inc  ecx
    cmp  ecx, r10d
    jb   .save
    sub  r8d, r10d
    cmp  r9d, r8d
    jb   .earlier
    sub  r9d, r10d
    cmp  r9d, r8d
    jbe  .copy
    mov  ecx, r8d
.later:
    lea  edx, [rcx + r10]
    mov  al, [rdi + rdx]
    mov  [rdi + rcx], al
    inc  ecx
    cmp  ecx, r9d
    jb   .later
    jmp  .copy
.earlier:
    mov  ecx, r8d
.right:
    dec  ecx
    mov  al, [rdi + rcx]
    lea  edx, [rcx + r10]
    mov  [rdi + rdx], al
    cmp  ecx, r9d
    ja   .right
.copy:
    xor  ecx, ecx
.restore:
    mov  al, [rsi + rcx]
    lea  edx, [r9 + rcx]
    mov  [rdi + rdx], al
    inc  ecx
    cmp  ecx, r10d
    jb   .restore
    lea  eax, [r9 + 16]
    mov  [rel nt_res_parent_key], eax
    ret

; Relocate a bounded suffix inside a validated staged FILE, no I/O.
; RDI=record, ESI=minimal span end, ECX=old used, EDX=signed aligned delta.
; Preserve prefix and extra allocation slack; clear vacated record bytes.
; Manual backward copy keeps DF clear across all callers and exits.
nt_rename_shift:
    movsxd rdx, edx
    test edx, edx
    jz   .out
    mov  r8d, esi
    test edx, edx
    js   .left
.right:
    cmp  ecx, r8d
    jbe  .out
    dec  ecx
    mov  al, [rdi + rcx]
    lea  r9, [rcx + rdx]
    mov  [rdi + r9], al
    jmp  .right
.left:
    cmp  esi, ecx
    jae  .vacated
    mov  al, [rdi + rsi]
    lea  r9, [rsi + rdx]
    mov  [rdi + r9], al
    inc  esi
    jmp  .left
.vacated:
    lea  r8, [rcx + rdx]
.zero:
    cmp  r8d, ecx
    jae  .out
    mov  byte [rdi + r8], 0
    inc  r8d
    jmp  .zero
.out:
    ret

; RDI=FILE_NAME value/key, RDX=attribute/entry alignment base.
nt_rename_name:
    mov  eax, [rel nt_rename_len]
    mov  [rdi + 64], al
    mov  rsi, [rel nt_rename_new]
    xor  ecx, ecx
.chars:
    movzx eax, byte [rsi + rcx]
    mov  [rdi + rcx*2 + 66], ax
    inc  ecx
    cmp  ecx, [rel nt_rename_len]
    jb   .chars
    lea  r9, [rdi + rcx*2 + 66]
    mov  r8, r9
    sub  r8, rdx
    add  r8, 7
    and  r8, -8
    add  r8, rdx
.padding:
    cmp  r9, r8
    jae  .out
    mov  byte [r9], 0
    inc  r9
    jmp  .padding
.out:
    ret

; RBX=current unnamed DATA header, R14=requested whole-file length.
; Do this against the SAME live record used by the range writer, before I/O.
nt_save_plain:
    cmp  dword [rbx + 4], 64
    jb   .no
    mov  edx, [rel nt_rec_buf + 24]        ; FILE bytes-in-use, not stale buffer tail
    cmp  edx, [rel nt_rec_bytes]
    ja   .no
    lea  rdi, [rel nt_rec_buf]
    add  rdx, rdi
    mov  eax, [rbx + 4]
    lea  rdi, [rbx + rax]
    cmp  rdi, rdx
    ja   .no
    cmp  qword [rbx + 0x10], 0            ; stream starts at VCN zero
    jne  .no
    cmp  word [rbx + 0x22], 0            ; not a compressed allocation
    jne  .no
    movzx eax, word [rbx + 0x20]
    cmp  eax, 64
    jb   .no
    cmp  eax, [rbx + 4]
    jae  .no
    cmp  r14, [rbx + 0x28]               ; physical allocation covers the file
    ja   .no
    cmp  r14, [rbx + 0x30]
    jne  .no
    cmp  r14, [rbx + 0x38]
    jne  .no
    cmp  dword [rel nt_found_ref], 16       ; all NTFS reserved metafiles
    jb   .no
    test word [rel nt_rec_buf + 0x16], 2   ; record itself must be an ordinary file
    jnz  .no
    cmp  qword [rel nt_rec_buf + 0x20], 0  ; not an extension record
    jne  .no
    lea  rdi, [rel nt_rec_buf]
    mov  esi, NT_A_STDINFO
    call nt_find_attr
    test rax, rax
    jz   .no
    cmp  byte [rax + 8], 0
    jne  .no
    cmp  dword [rax + 0x10], 36
    jb   .no
    movzx ecx, word [rax + 0x14]
    cmp  ecx, 24
    jb   .no
    lea  edx, [rcx + 36]
    cmp  edx, [rax + 4]
    ja   .no
    lea  rdi, [rax + rdx]
    mov  edx, [rel nt_rec_buf + 24]
    lea  r8, [rel nt_rec_buf]
    add  rdx, r8
    cmp  rdi, rdx
    ja   .no
    test dword [rax + rcx + 32], 0x4E17    ; RO/hidden/system/dir/sparse/reparse/compressed/encrypted
    jnz  .no
    xor  eax, eax
    ret
.no:
    mov  rax, -1
    ret

; nt_emit_mounted — the earned mount line (content-graded fields).
nt_emit_mounted:
    lea  rdi, [rel str_nt_mounted]
    call serial_string
    mov  rdi, [rel nt_part_lba]
    call serial_hex64
    lea  rdi, [rel str_nt_m_sectors]
    call serial_string
    mov  rdi, [rel nt_part_sectors]
    call serial_hex64
    lea  rdi, [rel str_nt_m_clus]
    call serial_string
    mov  edi, [rel nt_clus_bytes]
    call serial_hex64
    lea  rdi, [rel str_nt_m_rec]
    call serial_string
    mov  edi, [rel nt_rec_bytes]
    call serial_hex64
    lea  rdi, [rel str_nt_m_mftruns]
    call serial_string
    mov  edi, [rel nt_mft_nruns]
    call serial_hex64
    lea  rdi, [rel str_nt_m_serial]
    call serial_string
    mov  rdi, [rel nt_serial]
    call serial_hex64
    lea  rdi, [rel str_nt_m_dirty]
    call serial_string
    movzx edi, byte [rel nt_dirty]
    call serial_hex64
    lea  rdi, [rel str_nt_m_hiber]
    call serial_string
    movzx edi, byte [rel nt_hiber]
    call serial_hex64
    lea  rdi, [rel str_nt_m_write]
    call serial_string
    movzx edi, byte [rel nt_write_armed]
    call serial_hex64
    lea  rdi, [rel str_nt_m_dev]
    call serial_string
    mov  rax, [rel nt_dev]
    mov  rdi, [rax + dev.name]
    test rdi, rdi
    jz   .no_name
    call serial_string
.no_name:
    lea  rdi, [rel str_nt_m_pref]
    call serial_string
%ifdef PAOS_NTFS_PREFER_NVME
    mov  edi, 1
%else
    xor  edi, edi
%endif
    call serial_hex64
    lea  rdi, [rel str_nt_m_rd1]
    call serial_string
    mov  rdi, [rel nt_rd_fallback]         ; multi-sector reads that had to go sector-by-sector
    call serial_hex64
    lea  rdi, [rel str_nt_m_tail]
    call serial_string
    ret

; nt_emit_mount_failed — one honest line per candidate that did not mount:
; device name + the stage that refused (see nt_mount_volume's stage numbers).
nt_emit_mount_failed:
    lea  rdi, [rel str_nt_mfail]
    call serial_string
    mov  rax, [rel nt_dev]
    test rax, rax
    jz   .no_name
    mov  rdi, [rax + dev.name]
    test rdi, rdi
    jz   .no_name
    call serial_string
.no_name:
    lea  rdi, [rel str_nt_mfail_stage]
    call serial_string
    movzx edi, byte [rel nt_mount_stage]
    call serial_hex64
    lea  rdi, [rel str_nt_mfail_tail]
    call serial_string
    ret

; Read-only retained state. Registry geometry is immutable after registration;
; BSP owns NTFS/VFS context changes. Resolve the saved pointer through bounded
; healthy READ enumeration BEFORE dereferencing it. No identify, FS ops, block
; I/O, grant, mutation, re-arm or restoration of a failed/previous binding.
; RDI=fs_ntfs_selection* -> EAX=FS_NTFS_*; noncurrent facts are always zero.
ntfs_disk_selection_state:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    test r12, r12
    jz   .null
    xor  r15d, r15d                        ; closed until a mounted selection exists
    call .clear
    cmp  byte [rel nt_mounted], 1
    jne  .status
    cmp  dword [rel ntfs_disk_handle], -1
    je   .status
    mov  edi, [rel vfs_disk_handle]
    cmp  edi, -1
    je   .status
    mov  r15d, FS_NTFS_UNAVAILABLE
    cmp  edi, [rel ntfs_disk_handle]
    jne  .status
    mov  r15d, FS_NTFS_STALE
    call vfs_mount_ptr
    test rax, rax
    jz   .status
    lea  rdx, [rel nt_ops]
    cmp  [rax + fsmount.ops], rdx
    jne  .status
    lea  rdx, [rel nt_ctx]
    cmp  [rax + fsmount.priv], rdx
    jne  .status
    xor  ebx, ebx
    mov  r13d, 64                         ; registry hard limit, cycles stay bounded
.next:
    dec  r13d
    js   .status
    mov  rdi, rbx
    mov  esi, BLKCAP_READ
    xor  edx, edx
    call blk_iter_after
    test rax, rax
    jz   .status
    mov  rbx, rax
    cmp  rax, [rel nt_dev]
    jne  .next
    mov  r14, [rbx + dev.info]             ; now a live healthy READ registration
    mov  rax, [r14 + blk_info.media_generation]
    test rax, rax
    jz   .status
    cmp  rax, [rel nt_mount_generation]
    jne  .status
    mov  rax, [r14 + blk_info.lba_max]
    cmp  rax, [rel nt_rename_mount_max]
    jne  .status
    cmp  dword [r14 + blk_info.sector_size], 512
    jne  .status
    mov  ecx, [r14 + blk_info.logical_sector_bytes]
    cmp  ecx, [rel nt_rename_mount_logical]
    jne  .status
    test ecx, ecx
    jz   .geometry_ok
    cmp  ecx, 512
    jne  .status
.geometry_ok:
    cmp  qword [rel nt_binding_generation], 0
    je   .status
    mov  rcx, [rel nt_part_sectors]
    test rcx, rcx
    jz   .status
    dec  rcx
    add  rcx, [rel nt_part_lba]
    jc   .status
    cmp  rcx, rax
    ja   .status
    ; Device labels are diagnostics, not authority. Copy a complete safe token;
    ; no raw pointer, partial name, whitespace or control byte reaches the wire.
    mov  r15d, FS_NTFS_UNAVAILABLE
    mov  rdx, [rbx + dev.name]
    test rdx, rdx
    jz   .status
    xor  ecx, ecx
.name:
    cmp  ecx, 64
    jae  .status
    mov  al, [rdx + rcx]
    test al, al
    jz   .terminated
    cmp  al, '0'
    jb   .punctuation
    cmp  al, '9'
    jbe  .store
    cmp  al, 'A'
    jb   .punctuation
    cmp  al, 'Z'
    jbe  .store
    cmp  al, 'a'
    jb   .punctuation
    cmp  al, 'z'
    jbe  .store
.punctuation:
    cmp  al, '_'
    je   .store
    cmp  al, '-'
    je   .store
    cmp  al, '.'
    je   .store
    cmp  al, ':'
    jne  .status
.store:
    mov  [r12 + fs_ntfs_selection.device + rcx], al
    inc  ecx
    jmp  .name
.terminated:
    test ecx, ecx
    jz   .status
    mov  rax, [rel nt_part_lba]
    mov  [r12 + fs_ntfs_selection.start], rax
    mov  rax, [rel nt_part_sectors]
    mov  [r12 + fs_ntfs_selection.sectors], rax
    mov  rax, [r14 + blk_info.lba_max]
    mov  [r12 + fs_ntfs_selection.lba_max], rax
    mov  rax, [r14 + blk_info.media_generation]
    mov  [r12 + fs_ntfs_selection.media_gen], rax
    mov  rax, [rel nt_binding_generation]
    mov  [r12 + fs_ntfs_selection.binding_gen], rax
    mov  eax, [r14 + blk_info.sector_size]
    mov  [r12 + fs_ntfs_selection.sector_bytes], eax
    mov  eax, [r14 + blk_info.logical_sector_bytes]
    mov  [r12 + fs_ntfs_selection.logical_bytes], eax
    mov  eax, [rel ntfs_disk_handle]
    mov  [r12 + fs_ntfs_selection.mount], rax
    mov  r15d, FS_NTFS_CURRENT
    jmp  .finish
.status:
    call .clear                           ; erase even a partly copied invalid name
.finish:
    mov  [r12 + fs_ntfs_selection.status], r15d
    mov  eax, r15d
    jmp  .out
.null:
    mov  eax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
.clear:
    mov  rdi, r12
    xor  eax, eax
    mov  ecx, fs_ntfs_selection_size / 8
    rep stosq
    mov  dword [r12 + fs_ntfs_selection.version], FS_NTFS_STATE_VERSION
    ret

; ntfs_disk_write_state() -> EAX 1 = the FS-verb mount is this NTFS volume and
; writes are armed, 0 = it is this volume but read-only (dirty/hiberfil gate
; or a failed flush left persistence uncertain),
; -1 = the FS-verb mount is not an NTFS volume (or none mounted).  Read-only
; observer for the Explorer status row; it never changes the arming itself.
ntfs_disk_write_state:
    mov  eax, [rel ntfs_disk_handle]
    cmp  eax, -1
    je   .na
    cmp  eax, [rel vfs_disk_handle]
    jne  .na
    movzx eax, byte [rel nt_write_armed]
    ret
.na:
    mov  eax, -1
    ret

; ---------------------------------------------------------------------------
; data (in-image writable; no absolute addresses in data — lea [rel] only)
; ---------------------------------------------------------------------------
; Read-only regular-file source adapter for the ext4 copy job. No writer,
; storage grant, resolver growth or staging capacity is added here. A bound
; native table/context, device/info, partition, full geometry/MFT map and
; nonzero current media generation are checked at every real block boundary.
; The complete fixed-up FILE and its full reference/sequence are re-resolved
; before and after each logical read (including destination verification).
ntfs_disk_source_device:
    lea  rax, [rel nt_ops]
    cmp  [rdi + fsmount.ops], rax
    jne  .bad
    lea  rax, [rel nt_ctx]
    cmp  [rdi + fsmount.priv], rax
    jne  .bad
    cmp  byte [rel nt_mounted], 1
    jne  .bad
    mov  rax, [rel nt_dev]
    ret
.bad:
    xor  eax, eax
    ret

ntfs_disk_source_bind:
    push rbx
    push r12
    mov  r12, rdi
    call ntfs_disk_source_device
    test rax, rax
    jz   .bad
    mov  [rel nt_src_mount], r12
    mov  rbx, [rax + dev.info]
    test rbx, rbx
    jz   .bad
    mov  [rel nt_src_info], rbx
    mov  rdx, [rax + dev.ops]
    mov  [rel nt_src_ops], rdx
    mov  rdx, [rax + dev.priv]
    mov  [rel nt_src_priv], rdx
    mov  edx, [rbx + blk_info.unit]
    mov  [rel nt_src_unit], edx
    cmp  dword [rbx + blk_info.sector_size], 512
    jne  .bad
    mov  rax, [rbx + blk_info.media_generation]
    test rax, rax
    jz   .bad
    cmp  rax, [rel nt_mount_generation]
    jne  .bad
    cmp  qword [rel nt_serial], 0
    je   .bad
    mov  rax, [rbx + blk_info.lba_max]
    mov  [rel nt_src_max], rax
    mov  eax, [rbx + blk_info.logical_sector_bytes]
    mov  [rel nt_src_logical], eax
    lea  r8, [rel nt_dev]
    lea  r9, [rel nt_src_fields]
    lea  r10, [rel nt_src_geo]
    mov  ecx, NT_SRC_FIELDS
.fields:
    movsxd rdx, dword [r9]
    mov  eax, [r8 + rdx]
    cmp  dword [r9 + 4], 4
    je   .save
    mov  rax, [r8 + rdx]
.save:
    mov  [r10], rax
    add  r9, 8
    add  r10, 8
    loop .fields
    lea  rdi, [rel nt_src_blkgeo]
    lea  rsi, [rbx + blk_info.logical_sector_bytes]
    mov  edx, blk_info_size - blk_info.logical_sector_bytes
    call memcpy
    lea  rdi, [rel nt_src_mft]
    lea  rsi, [rel nt_mft_runs]
    mov  edx, NT_MAX_RUNS * 16
    call memcpy
    lea  rdi, [rel nt_src_boot]
    lea  rsi, [rel nt_boot_buf]
    mov  edx, 512
    call memcpy
    call ntfs_disk_source_current
    jmp  .out
.bad:
    mov  rax, -1
.out:
    pop  r12
    pop  rbx
    ret

; Pure check, preserving every register except RAX. No token/geometry change
; can cause I/O to a replacement device, even inside the fallback loop.
ntfs_disk_source_token:
    push rdi
    push rsi
    push rdx
    push rcx
    push r8
    push r9
    push r10
    mov  rdi, [rel nt_src_mount]
    test rdi, rdi
    jz   .bad
    call ntfs_disk_source_device
    test rax, rax
    jz   .bad
    mov  rdx, [rax + dev.ops]
    cmp  rdx, [rel nt_src_ops]
    jne  .bad
    mov  rdx, [rax + dev.priv]
    cmp  rdx, [rel nt_src_priv]
    jne  .bad
    mov  rdx, [rax + dev.info]
    cmp  rdx, [rel nt_src_info]
    jne  .bad
    test rdx, rdx
    jz   .bad
    mov  eax, [rdx + blk_info.unit]
    cmp  eax, [rel nt_src_unit]
    jne  .bad
    cmp  dword [rdx + blk_info.sector_size], 512
    jne  .bad
    mov  rax, [rdx + blk_info.media_generation]
    test rax, rax
    jz   .bad
    cmp  rax, [rel nt_mount_generation]
    jne  .bad
    mov  rax, [rdx + blk_info.lba_max]
    cmp  rax, [rel nt_src_max]
    jne  .bad
    mov  eax, [rdx + blk_info.logical_sector_bytes]
    cmp  eax, [rel nt_src_logical]
    jne  .bad
    lea  rsi, [rdx + blk_info.logical_sector_bytes]
    lea  rdi, [rel nt_src_blkgeo]
    mov  edx, blk_info_size - blk_info.logical_sector_bytes
    call memcmp
    test rax, rax
    jnz  .bad
    lea  r8, [rel nt_dev]
    lea  r9, [rel nt_src_fields]
    lea  r10, [rel nt_src_geo]
    mov  ecx, NT_SRC_FIELDS
.fields:
    movsxd rdx, dword [r9]
    mov  eax, [r8 + rdx]
    cmp  dword [r9 + 4], 4
    je   .compare
    mov  rax, [r8 + rdx]
.compare:
    cmp  rax, [r10]
    jne  .bad
    add  r9, 8
    add  r10, 8
    loop .fields
    lea  rdi, [rel nt_src_mft]
    lea  rsi, [rel nt_mft_runs]
    mov  edx, NT_MAX_RUNS * 16
    call memcmp
    test rax, rax
    jnz  .bad
    xor  eax, eax
    jmp  .out
.bad:
    mov  rax, -1
.out:
    pop  r10
    pop  r9
    pop  r8
    pop  rcx
    pop  rdx
    pop  rsi
    pop  rdi
    ret

nt_src_guard:
    call nt_sel_guard
    test rax,rax
    jnz .out
    cmp  qword [rel nt_src_reading], 0
    je   .ok
    call ntfs_disk_source_token
    test rax, rax
    jnz  .out
    cmp  rdi, [rel nt_src_geo]             ; first snapshotted field is exact device
    jne  .bad
.ok:
    call nt_space_guard
    test rax, rax
    jnz  .out
    cmp  byte [rel nt_space_active], 0
    je   .out
    cmp  rdi, [rel nt_space_geo]           ; never read a replacement device
    jne  .bad
.out:
    ret
.bad:
    mov  rax, -1
    ret
nt_src_block_read:
    call nt_src_guard
    test rax, rax
    jnz  .out
    ; The callback need not preserve argument registers. Reconstruct the
    ; actual device for the post-read guard, preserving its original result.
    push rdi
    call blk_read
    pop  rdi
    push rax
    call nt_src_guard
    test rax, rax
    pop  rax
    jz   .out
    mov  rax, -1
.out:
    ret

; Read a fresh VBR; pure checks happen before and after the physical read.
; Scoped counter is nestable, and zero again on EVERY outer adapter exit.
ntfs_disk_source_current:
    push qword [rel nt_src_reading]
    mov  qword [rel nt_src_reading], 1
    call ntfs_disk_source_token
    test rax, rax
    jnz  .bad
    mov  rsi, [rel nt_part_lba]
    mov  edx, 1
    lea  rcx, [rel nt_src_vbr]
    call nt_read
    test rax, rax
    jnz  .bad
    lea  rdi, [rel nt_src_boot]
    lea  rsi, [rel nt_src_vbr]
    mov  edx, 512
    call memcmp
    test rax, rax
    jnz  .bad
    call ntfs_disk_source_token
    jmp  .out
.bad:
    mov  rax, -1
.out:
    pop  qword [rel nt_src_reading]
    ret

; Validated FILE attribute spans are required first (directory validator or
; DATA admission). Reparse attributes/flags, compression and encryption are
; refused for every traversed node; this adapter never follows them.
nt_src_node_safe:
    lea  rdi, [rel nt_rec_buf]
    mov  esi, 0xC0                       ; $REPARSE_POINT
    call nt_find_attr_any
    test rax, rax
    jnz  .bad
    lea  rdi, [rel nt_rec_buf]
    mov  esi, NT_A_STDINFO
    call nt_find_attr_any
    test rax, rax
    jz   .bad
    cmp  byte [rax + 8], 0
    jne  .bad
    cmp  byte [rax + 9], 0
    jne  .bad
    cmp  word [rax + 12], 0
    jne  .bad
    cmp  dword [rax + 16], 36
    jb   .bad
    movzx edx, word [rax + 20]
    test dword [rax + rdx + 32], 0x4C00  ; reparse/compressed/encrypted
    jnz  .bad
.next:
    mov  edx, [rax + 4]
    add  rax, rdx
    cmp  dword [rax], -1
    je   .ok
    cmp  dword [rax], NT_A_STDINFO
    je   .bad                            ; ambiguous node metadata is unsupported
    jmp  .next
.ok:
    xor  eax, eax
    ret
.bad:
    mov  rax, -1
    ret

; The maintained resolver has a 32-bit directory-record ABI. Every lookup
; rejects unsupported references before a consumer can narrow them. Check the
; actual FILE sequence, identity and kind, including intermediate directories.
; Keep the source-copy entry point for its existing explicit custody checks.
nt_src_lookup_ref:
nt_lookup_ref:
    push rbx
    mov  rax, [rel nt_found_ref]
    mov  rdi, rax
    shr  rax, 32
    jnz  .bad
    movzx ebx, word [rel nt_found_sequence]
    test ebx, ebx
    jz   .bad
    call nt_read_record
    test rax, rax
    jnz  .bad
    cmp  bx, [rel nt_rec_buf + 16]
    jne  .bad
    mov  eax, [rel nt_found_ref]
    cmp  eax, [rel nt_rec_buf + 44]
    jne  .bad
    movzx eax, byte [rel nt_found_isdir]
    shl  eax, 1
    or   eax, 1
    cmp  ax, [rel nt_rec_buf + 22]
    jne  .bad
    cmp  qword [rel nt_rec_buf + 32], 0
    jne  .bad
    xor  eax, eax
    jmp  .out
.bad:
    mov  dword [rel nt_rec_buf], 0
    mov  byte [rel nt_found], 0
    mov  byte [rel nt_lookup_complete], 0
    mov  byte [rel nt_write_armed], 0
    mov  rax, -1
.out:
    pop  rbx
    ret

; RSI/EDX=path, ECX=bind(1)/compare(0) -> logical size / -1.
; Full fixed-up FILE bytes include all run mapping and initialized lengths;
; no CRC collision or truncated reference is accepted as file identity.
ntfs_disk_source_stat:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push qword [rel nt_src_reading]
    mov  qword [rel nt_src_reading], 1
    mov  r12, rsi
    mov  r13d, edx
    mov  r14d, ecx
    call ntfs_disk_source_current
    test rax, rax
    jnz  .bad
    mov  rsi, r12
    mov  edx, r13d
    call nt_resolve_path
    test rax, rax
    jnz  .bad
    cmp  byte [rel nt_found_isdir], 0
    jne  .bad
    mov  rbx, [rel nt_found_ref]
    mov  rax, rbx
    shr  rax, 32                        ; reader has a 32-bit record number ABI
    jnz  .bad                           ; refuse rather than alias upper bits
    movzx r15d, word [rel nt_found_sequence]
    mov  edi, ebx
    call nt_read_record
    test rax, rax
    jnz  .bad
    cmp  r15w, [rel nt_rec_buf + 16]
    jne  .bad
    lea  rdi, [rel nt_rec_buf]
    mov  esi, [rel nt_rec_bytes]
    add  rsi, rdi
    call nt_data_attr_admit
    test rax, rax
    jz   .bad
    mov  r15d, [rax + 16]               ; resident length
    cmp  byte [rax + 8], 0
    je   .size
    mov  r15, [rax + 48]                ; nonresident logical length
.size:
    call nt_src_node_safe
    test rax, rax
    jnz  .bad
    test r14d, r14d
    jz   .compare
    call nt_tree_expected
    test rax, rax
    jnz  .bad
    mov  [rel nt_src_ref], rbx
    lea  rdi, [rel nt_src_file]
    lea  rsi, [rel nt_rec_buf]
    mov  edx, [rel nt_rec_bytes]
    call memcpy
    jmp  .token
.compare:
    cmp  rbx, [rel nt_src_ref]
    jne  .bad
    lea  rdi, [rel nt_src_file]
    lea  rsi, [rel nt_rec_buf]
    mov  edx, [rel nt_rec_bytes]
    call memcmp
    test rax, rax
    jnz  .bad
.token:
    call ntfs_disk_source_token
    test rax, rax
    jnz  .bad
    mov  rax, r15
    jmp  .out
.bad:
    mov  rax, -1
.out:
    pop  qword [rel nt_src_reading]
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ntfs_disk_source_mtime -> RAX = the bound source file's modification time as Unix UTC seconds (before 1970:
;   negative), EDX = nanoseconds; CF=1 unknown (no resident $STANDARD_INFORMATION holding it, FILETIME 0).
;   E2t (root 2026-10-17 21:04:41: every copy carries the source mtime): $STANDARD_INFORMATION +8, the
;   file's "altered" FILETIME (UTC, 100 ns since 1601), from the FILE ntfs_disk_source_stat admitted and
;   bound (nt_src_file). Clobbers RCX, RDX, RSI, RDI, R8, R9.
ntfs_disk_source_mtime:
    lea  rdi, [rel nt_src_file]
    mov  esi, 0x10                       ; $STANDARD_INFORMATION (unnamed)
    call nt_find_attr
    test rax, rax
    jz   .unknown
    cmp  byte [rax + 8], 0
    jne  .unknown                        ; always resident
    mov  ecx, [rax + 16]                 ; value length
    cmp  ecx, 16
    jb   .unknown
    movzx edx, word [rax + 20]           ; value offset
    add  rcx, rdx
    cmp  ecx, [rax + 4]
    ja   .unknown                        ; the value inside its attribute
    lea  r8, [rax + rdx + 16]
    lea  r9, [rel nt_src_file + NT_RECBUF]
    cmp  r8, r9
    ja   .unknown                        ; and inside the record buffer
    mov  rax, [rax + rdx + 8]
    test rax, rax
    jle  .unknown                        ; 0 (never set) or past the signed range
    xor  edx, edx
    mov  rcx, 10000000
    div  rcx                             ; seconds since 1601, RDX = 100 ns units
    imul edx, edx, 100
    mov  rcx, 11644473600
    sub  rax, rcx                        ; 1601-01-01 .. 1970-01-01
    clc
    ret
.unknown:
    stc
    ret

; Same ABI as read_at_path. Stat and read share the admitted FILE instead of
; resolving a second, unchecked record. All bytes are native logical DATA,
; including zeroes for holes and uninitialized tails. No source write path.
ntfs_disk_source_read:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push qword [rel nt_src_reading]
    mov  qword [rel nt_src_reading], 1
    mov  rbx, rsi
    mov  r12d, edx
    mov  r13, rcx
    mov  r14, r8
    mov  r15, r9
    xor  ecx, ecx
    call ntfs_disk_source_stat
    cmp  rax, -1
    je   .bad
    ; ntfs_disk_source_stat left nt_rec_buf and admitted native nt_runs current.
    mov  rdx, r13
    mov  rcx, r14
    mov  r8, r15
    call nt_data_read_at
    push rax
    mov  rsi, rbx
    mov  edx, r12d
    xor  ecx, ecx
    call ntfs_disk_source_stat
    cmp  rax, -1
    pop  rax
    jne  .out
.bad:
    mov  rax, -2                       ; source identity/admission failed
.out:
    pop  qword [rel nt_src_reading]
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Complete read-only NTFS tree source. A cursor is an ordinal in the validated
; native directory walk, never an fs_dirent snapshot. Rewalks are bounded by
; NTT_BLOCKS/NTT_KEYS and compare exact FILE/active INDX bytes on every resume.
; No disk selection, writer, grant, source recovery or source mutation occurs.
ntfs_disk_source_tree_forget:
    mov  qword [rel nt_tree_frame], 0
    mov  byte [rel nt_tree_scope], 0
    mov  byte [rel nt_tree_pending], 0
    ret

; RDI=bytes, ESI=length, EDX=frame offset. Preserve native walk callee registers.
nt_tree_snapshot:
    cmp  edx, NTT_FILE
    jne  .snapshot
    cmp  byte [rel nt_tree_binding], 0
    je   .snapshot
    push rdi
    push rsi
    push rdx
    call nt_tree_expected               ; compare the actual last physical FILE read
    pop  rdx
    pop  rsi
    pop  rdi
    test rax, rax
    jnz  .out
.snapshot:
    mov  rax, [rel nt_tree_frame]
    add  rax, rdx
    mov  rdx, rsi
    mov  rsi, rdi
    mov  rdi, rax
    cmp  byte [rel nt_tree_binding], 0
    je   .compare
    call memcpy
    xor  eax, eax
    ret
.compare:
    call memcmp
    test rax, rax
    jz   .out
    mov  dword [rel ext4_disk_last_error], 17
    mov  rax, -1
.out:
    ret

; R13=current validated index entry. Every key is validated by nt_visit_node.
; DOS-only aliases are refused: omitting one without proving its partner would
; be silent data loss. Dollar-prefixed user names are ordinary exact names.
nt_tree_visit:
    cmp  byte [r13 + 81], 2
    je   .unsupported
    mov  ecx, [rel nt_utf8_bytes]
    cmp  ecx, 1
    jne  .entry
    cmp  byte [rel nt_utf8_name], '.'
    jne  .entry
    mov  rax, [rel nt_tree_frame]
    mov  rax, [rax + NTT_REF]
    cmp  rax, [r13]
    jne  .unsupported
    xor  eax, eax                       ; the actual self entry, not an omitted child
    ret
.entry:
    mov  rax, [rel nt_tree_seen]
    cmp  rax, NTT_KEYS
    jae  .bound
    inc  qword [rel nt_tree_seen]
    mov  rdx, [rel nt_tree_frame]
    cmp  eax, [rdx + NTT_CURSOR]
    jne  .ok
    mov  rax, [r13]
    mov  [rdx + NTT_NEXTREF], rax
    mov  eax, [r13 + 72]                 ; full FILE_NAME flags (node checked separately)
    mov  [rdx + NTT_ATTR], eax
    mov  [rdx + NTT_LEN], ecx
    lea  rdi, [rdx + NTT_NAME]
    lea  rsi, [rel nt_utf8_name]
    lea  edx, [rcx + 1]
    call memcpy
.ok:
    xor  eax, eax
    ret
.bound:
    mov  dword [rel ext4_disk_last_error], 7
    mov  rax, -1
    ret
.unsupported:
    mov  dword [rel ext4_disk_last_error], 4
    mov  rax, -1
    ret

; Consume a directory-key's exact FILE admission when a child binds. This
; closes the gap between node validation and the per-file/directory BEGIN.
nt_tree_expected:
    cmp  byte [rel nt_tree_pending], 0
    je   .ok
    lea  rdi, [rel nt_tree_node_file]
    lea  rsi, [rel nt_rec_buf]
    mov  edx, [rel nt_rec_bytes]
    call memcmp
    test rax, rax
    jnz  .bad
    mov  byte [rel nt_tree_pending], 0
.ok:
    xor  eax, eax
    ret
.bad:
    mov  dword [rel ext4_disk_last_error], 17
    mov  rax, -1
    ret

; RDI=cursor, RSI=NUL full directory path, ECX=bind(1)/compare(0) -> 0/-1.
; The full reference/sequence, full fixed-up FILE, active bitmap and every
; physical index block remain bound across children and all bounded steps.
ntfs_disk_source_dir:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push qword [rel nt_src_reading]
    mov  qword [rel nt_src_reading], 1
    mov  byte [rel nt_tree_scope], 1
    mov  qword [rel nt_tree_frame], 0
    mov  r15, rdi
    mov  r12, rsi
    mov  r14d, ecx
    mov  dword [rel ext4_disk_last_error], 17
    xor  r13d, r13d
.length:
    cmp  r13d, NT_READ_PATH_CAP - 1
    ja   .bad
    cmp  byte [r12 + r13], 0
    je   .path
    inc  r13d
    jmp  .length
.path:
    call ntfs_disk_source_current
    test rax, rax
    jnz  .bad
    mov  rsi, r12
    mov  edx, r13d
    call nt_resolve_path
    test rax, rax
    jnz  .bad
    cmp  byte [rel nt_found_isdir], 1
    jne  .unsupported
    mov  rbx, [rel nt_found_ref]
    mov  rax, rbx
    shr  rax, 32
    jnz  .unsupported
    mov  edi, ebx
    call nt_read_record
    test rax, rax
    jnz  .bad
    ; A literal root has no parent key. Every other path has a native sequence.
    cmp  r13d, 1
    jne  .sequence
    cmp  byte [r12], '/'
    je   .reference
.sequence:
    mov  ax, [rel nt_found_sequence]
    cmp  ax, [rel nt_rec_buf + 16]
    jne  .bad
.reference:
    movzx eax, word [rel nt_rec_buf + 16]
    shl  rax, 48
    or   rbx, rax
    test r14d, r14d
    jz   .compare_ref
    mov  [r15 + NTT_REF], rbx
    mov  dword [r15 + NTT_CURSOR], 0
    jmp  .walk
.compare_ref:
    cmp  rbx, [r15 + NTT_REF]
    jne  .bad
.walk:
    mov  [rel nt_tree_frame], r15
    mov  [rel nt_tree_binding], r14b
    mov  qword [rel nt_tree_seen], 0
    mov  dword [r15 + NTT_LEN], 0
    mov  [rel nt_walk_rec], ebx
    mov  byte [rel nt_visit_mode], NT_VISIT_TREE
    call nt_walk_root
    mov  qword [rel nt_tree_frame], 0
    test rax, rax
    jnz  .bad
    mov  eax, [rel nt_tree_seen]
    mov  [r15 + NTT_COUNT], eax
    call ntfs_disk_source_current
    test rax, rax
    jnz  .bad
    xor  eax, eax
    jmp  .out
.unsupported:
    mov  dword [rel ext4_disk_last_error], 4
.bad:
    mov  rax, -1
.out:
    mov  qword [rel nt_tree_frame], 0
    mov  byte [rel nt_tree_scope], 0
    pop  qword [rel nt_src_reading]
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=cursor, RSI=directory path -> 1 entry,0 end,-1 typed refusal.
; Returns owned complete UTF8 RDX/ECX, low record R8D, normalized directory R9D.
ntfs_disk_source_next:
    push rbx
    mov  rbx, rdi
    xor  ecx, ecx
    call ntfs_disk_source_dir
    test rax, rax
    jnz  .out
    mov  ecx, [rbx + NTT_LEN]
    test ecx, ecx
    jz   .out
    cmp  ecx, 255                        ; destination's byte name bound
    ja   .unsupported
    lea  rdx, [rbx + NTT_NAME]
    xor  eax, eax
.name:
    cmp  eax, ecx
    jae  .identity
    cmp  byte [rdx + rax], '/'
    je   .unsupported
    cmp  byte [rdx + rax], '\'
    je   .unsupported                   ; source resolver treats this as a separator
    inc  eax
    jmp  .name
.identity:
    cmp  ecx, 2
    jne  .ref
    cmp  word [rdx], '..'
    je   .unsupported
.ref:
    mov  r8, [rbx + NTT_NEXTREF]
    mov  rax, r8
    shr  rax, 32
    and  eax, 0xFFFF                     ; no 48->32 record alias
    jnz  .unsupported
    xor  r9d, r9d
    test dword [rbx + NTT_ATTR], 0x10000000
    jz   .file
    mov  r9d, 0x10
.file:
    inc  dword [rbx + NTT_CURSOR]
    mov  eax, 1
    jmp  .out
.unsupported:
    mov  dword [rel ext4_disk_last_error], 4
    mov  rax, -1
.out:
    pop  rbx
    ret

; RDI=cursor with last complete key, RSI=full child path ->0/-1.
; Reject index/FILE disagreement, reparse, recycled or unsupported nodes before
; destination mutation. Hold full FILE through the next child bind.
ntfs_disk_source_node:
    push rbx
    push r12
    push r13
    push qword [rel nt_src_reading]
    mov  qword [rel nt_src_reading], 1
    mov  rbx, rdi
    mov  r12, rsi
    mov  dword [rel ext4_disk_last_error], 17
    xor  r13d, r13d
.length:
    cmp  r13d, NT_READ_PATH_CAP - 1
    ja   .bad
    cmp  byte [r12 + r13], 0
    je   .path
    inc  r13d
    jmp  .length
.path:
    call ntfs_disk_source_current
    test rax, rax
    jnz  .bad
    mov  rsi, r12
    mov  edx, r13d
    call nt_resolve_path
    test rax, rax
    jnz  .bad
    movzx eax, word [rel nt_found_sequence]
    shl  rax, 48
    or   rax, [rel nt_found_ref]
    cmp  rax, [rbx + NTT_NEXTREF]
    jne  .bad
    mov  edi, [rel nt_found_ref]
    call nt_read_record
    test rax, rax
    jnz  .bad
    movzx eax, word [rel nt_rec_buf + 16]
    shl  rax, 48
    mov  edx, [rel nt_found_ref]
    or   rax, rdx
    cmp  rax, [rbx + NTT_NEXTREF]
    jne  .bad
    movzx eax, word [rel nt_rec_buf + 22]
    and  eax, 3
    cmp  eax, 1
    je   .regular
    cmp  eax, 3
    jne  .unsupported
    test dword [rbx + NTT_ATTR], 0x10000000
    jz   .bad
    lea  rdi, [rel nt_rec_buf]
    mov  esi, [rel nt_rec_bytes]
    add  rsi, rdi
    call nt_dir_record_valid
    test rax, rax
    jnz  .unsupported
    jmp  .safe
.regular:
    test dword [rbx + NTT_ATTR], 0x10000000
    jnz  .bad
    lea  rdi, [rel nt_rec_buf]
    mov  esi, [rel nt_rec_bytes]
    add  rsi, rdi
    call nt_data_attr_admit
    test rax, rax
    jz   .unsupported
.safe:
    call nt_src_node_safe
    test rax, rax
    jnz  .unsupported
    lea  rdi, [rel nt_tree_node_file]
    lea  rsi, [rel nt_rec_buf]
    mov  edx, [rel nt_rec_bytes]
    call memcpy
    mov  byte [rel nt_tree_pending], 1
    call ntfs_disk_source_token
    test rax, rax
    jnz  .bad
    xor  eax, eax
    jmp  .out
.unsupported:
    mov  dword [rel ext4_disk_last_error], 4
.bad:
    mov  rax, -1
.out:
    pop  qword [rel nt_src_reading]
    pop  r13
    pop  r12
    pop  rbx
    ret

nt_tree_frame: dq 0
nt_tree_scope: db 0
nt_tree_binding: db 0
nt_tree_pending: db 0
align 8
nt_tree_seen: dq 0
nt_tree_node_file: times NT_RECBUF db 0

; Geometry descriptor: offset from nt_dev, width. Excludes mutable read
; counters and per-read scratch. Includes the namespace binding epoch and
; original mount token, rather than the destination's global write epoch.
nt_src_fields:
    dd nt_dev - nt_dev, 8
    dd nt_part_lba - nt_dev, 8
    dd nt_part_sectors - nt_dev, 8
    dd nt_total_sectors - nt_dev, 8
    dd nt_mft_lcn - nt_dev, 8
    dd nt_mft_lba - nt_dev, 8
    dd nt_serial - nt_dev, 8
    dd nt_binding_generation - nt_dev, 8
    dd nt_mount_generation - nt_dev, 8
    dd nt_spc - nt_dev, 4
    dd nt_clus_bytes - nt_dev, 4
    dd nt_rec_bytes - nt_dev, 4
    dd nt_rec_sectors - nt_dev, 4
    dd nt_idx_bytes - nt_dev, 4
    dd nt_mft_nruns - nt_dev, 4
    dd nt_scheme - nt_dev, 4
NT_SRC_FIELDS equ ($ - nt_src_fields) / 8
; Native $Bitmap free-space query. BSP-owned synchronous scratch, independent
; of the copy-source token. No allocation, write grant, write or flush path.
; At most 16 MiB of bitmap (134217728 clusters), streamed through 4 KiB.
NT_SPACE_MAX_BITMAP equ 16 * 1024 * 1024

; RDI=fsmount* -> RAX exact free clusters / -1. Only the current selected
; native NTFS binding is queryable; every physical read checks its token.
nt_space_count:
    push rbx
    push r12
    push r13
    push r14
    push r15
    cmp  byte [rel nt_space_active], 0
    jne  .busy
    mov  r12, rdi
    lea  rdi, [rel nt_space_selection]
    call ntfs_disk_selection_state
    cmp  eax, FS_NTFS_CURRENT
    jne  .busy
    mov  edi, [rel ntfs_disk_handle]
    call vfs_mount_ptr
    cmp  rax, r12
    jne  .busy
    mov  [rel nt_space_mount], r12
    mov  rbx, [rel nt_dev]               ; selection resolved this registration
    mov  rax, [rbx + dev.info]
    mov  [rel nt_space_info], rax
    mov  rax, [rbx + dev.ops]
    mov  [rel nt_space_ops], rax
    mov  rax, [rbx + dev.priv]
    mov  [rel nt_space_priv], rax
    lea  rdi, [rel nt_space_blkgeo]
    mov  rsi, [rel nt_space_info]
    mov  edx, blk_info_size
    call memcpy
    lea  r8, [rel nt_dev]
    lea  r9, [rel nt_src_fields]
    lea  r10, [rel nt_space_geo]
    mov  ecx, NT_SRC_FIELDS
.snapshot:
    movsxd rdx, dword [r9]
    mov  eax, [r8 + rdx]
    cmp  dword [r9 + 4], 4
    je   .save
    mov  rax, [r8 + rdx]
.save:
    mov  [r10], rax
    add  r9, 8
    add  r10, 8
    loop .snapshot
    lea  rdi, [rel nt_space_mft]
    lea  rsi, [rel nt_mft_runs]
    mov  edx, NT_MAX_RUNS * 16
    call memcpy
    lea  rdi, [rel nt_space_boot]
    lea  rsi, [rel nt_boot_buf]
    mov  edx, 512
    call memcpy
    mov  byte [rel nt_space_active], 1
    call nt_space_vbr
    test rax, rax
    jnz  .bad
    mov  rax, [rel nt_total_sectors]
    mov  ecx, [rel nt_spc]
    test ecx, ecx
    jz   .bad
    xor  edx, edx
    div  rcx
    test rax, rax
    jz   .bad
    mov  r15, rax                       ; only complete addressable clusters
    add  rax, 7
    jc   .bad
    shr  rax, 3
    cmp  rax, NT_SPACE_MAX_BITMAP
    ja   .bad
    mov  r14, rax                       ; required bytes, not padded DATA size
    mov  edi, 6                         ; volume $Bitmap, not a directory bitmap
    call nt_read_record
    test rax, rax
    jnz  .bad
    cmp  dword [rel nt_rec_buf + 44], 6
    jne  .bad
    cmp  word [rel nt_rec_buf + 16], 0
    je   .bad
    lea  rdi, [rel nt_rec_buf]
    mov  esi, [rel nt_rec_bytes]
    add  rsi, rdi
    call nt_data_attr_admit             ; bounded FILE/attributes/full run map
    test rax, rax
    jz   .bad
    cmp  word [rax + 12], 0             ; no sparse/compressed/encrypted bitmap
    jne  .bad
    cmp  byte [rax + 8], 0
    je   .resident
    mov  rdx, [rax + 48]
    cmp  rdx, [rax + 56]                ; zero-filled tails are not free space
    jne  .bad
    ; Even an unflagged hole is not an allocated bitmap stream.
    lea  rcx, [rel nt_runs]
    mov  esi, [rel nt_nruns]
.runs:
    test esi, esi
    jz   .length
    mov  r8, [rcx]
    cmp  r8, -1
    je   .bad
    mov  r9, [rcx + 8]
    add  r9, r8                         ; decoder already bounded the sum
    lea  r10, [rcx + 16]
    mov  edi, esi
    dec  edi
.overlap:
    test edi, edi
    jz   .next_run
    mov  rax, [r10]
    cmp  rax, -1
    je   .bad
    cmp  rax, r9
    jae  .disjoint
    add  rax, [r10 + 8]
    cmp  r8, rax
    jb   .bad                          ; no aliased physical bitmap extents
.disjoint:
    add  r10, 16
    dec  edi
    jmp  .overlap
.next_run:
    add  rcx, 16
    dec  esi
    jmp  .runs
.resident:
    cmp  byte [rax + 22], 0
    jne  .bad
    mov  edx, [rax + 16]
.length:
    cmp  rdx, r14
    jb   .bad
    cmp  rdx, NT_SPACE_MAX_BITMAP
    ja   .bad
    xor  r12d, r12d                     ; stream offset
    xor  r13d, r13d                     ; allocated valid bits
.chunk:
    mov  rbx, r14
    sub  rbx, r12
    jz   .complete
    cmp  rbx, 4096
    jbe  .read
    mov  ebx, 4096
.read:
    mov  rdx, r12
    lea  rcx, [rel nt_space_buf]
    mov  r8, rbx
    call nt_data_read_at
    cmp  rax, rbx
    jne  .bad
    xor  edx, edx
    lea  rsi, [rel nt_space_buf]
.byte:
    movzx eax, byte [rsi + rdx]
    lea  rcx, [r12 + rdx + 1]
    cmp  rcx, r14
    jne  .popcount
    mov  ecx, r15d
    and  ecx, 7
    jz   .popcount
    mov  edi, 1
    shl  edi, cl
    dec  edi
    and  eax, edi                      ; last byte: ignore non-cluster padding
.popcount:
    test eax, eax
    jz   .next
    lea  ecx, [eax - 1]
    and  eax, ecx                      ; portable, at most eight iterations
    inc  r13
    jmp  .popcount
.next:
    inc  rdx
    cmp  rdx, rbx
    jb   .byte
    add  r12, rbx
    jmp  .chunk
.complete:
    call nt_space_vbr                   ; fresh on-disk volume identity again
    test rax, rax
    jnz  .bad
    mov  rax, r15
    sub  rax, r13
    mov  byte [rel nt_space_active], 0
    jmp  .out
.bad:
    mov  byte [rel nt_space_active], 0
.busy:
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Pure check, all registers except RAX preserved. No replacement pointer is
; dereferenced before healthy bounded registry enumeration resolves it.
nt_space_guard:
    cmp  byte [rel nt_space_active], 0
    jne  .check
    xor  eax, eax
    ret
.check:
    push rdi
    push rsi
    push rdx
    push rcx
    push r8
    push r9
    push r10
    lea  rdi, [rel nt_space_now]
    call ntfs_disk_selection_state
    cmp  eax, FS_NTFS_CURRENT
    jne  .bad
    lea  rdi, [rel nt_space_selection]
    lea  rsi, [rel nt_space_now]
    mov  edx, fs_ntfs_selection_size
    call memcmp
    test rax, rax
    jnz  .bad
    mov  edi, [rel ntfs_disk_handle]
    call vfs_mount_ptr
    cmp  rax, [rel nt_space_mount]
    jne  .bad
    mov  rax, [rel nt_dev]
    cmp  rax, [rel nt_space_geo]
    jne  .bad
    mov  rdx, [rax + dev.ops]
    cmp  rdx, [rel nt_space_ops]
    jne  .bad
    mov  rdx, [rax + dev.priv]
    cmp  rdx, [rel nt_space_priv]
    jne  .bad
    mov  rsi, [rax + dev.info]
    cmp  rsi, [rel nt_space_info]
    jne  .bad
    lea  rdi, [rel nt_space_blkgeo]
    mov  edx, blk_info_size
    call memcmp
    test rax, rax
    jnz  .bad
    lea  r8, [rel nt_dev]
    lea  r9, [rel nt_src_fields]
    lea  r10, [rel nt_space_geo]
    mov  ecx, NT_SRC_FIELDS
.fields:
    movsxd rdx, dword [r9]
    mov  eax, [r8 + rdx]
    cmp  dword [r9 + 4], 4
    je   .compare
    mov  rax, [r8 + rdx]
.compare:
    cmp  rax, [r10]
    jne  .bad
    add  r9, 8
    add  r10, 8
    loop .fields
    lea  rdi, [rel nt_space_mft]
    lea  rsi, [rel nt_mft_runs]
    mov  edx, NT_MAX_RUNS * 16
    call memcmp
    test rax, rax
    jnz  .bad
    xor  eax, eax
    jmp  .out
.bad:
    mov  rax, -1
.out:
    pop  r10
    pop  r9
    pop  r8
    pop  rcx
    pop  rdx
    pop  rsi
    pop  rdi
    ret

nt_space_vbr:
    mov  rsi, [rel nt_part_lba]
    mov  edx, 1
    lea  rcx, [rel nt_space_vbr_buf]
    call nt_read
    test rax, rax
    jnz  .out
    lea  rdi, [rel nt_space_boot]
    lea  rsi, [rel nt_space_vbr_buf]
    mov  edx, 512
    call memcmp
.out:
    ret

align 8
nt_space_active: db 0
align 8
nt_space_mount: dq 0
nt_space_info: dq 0
nt_space_ops: dq 0
nt_space_priv: dq 0
nt_space_geo: times NT_SRC_FIELDS dq 0
nt_space_blkgeo: times blk_info_size db 0
nt_space_selection: times fs_ntfs_selection_size db 0
nt_space_now: times fs_ntfs_selection_size db 0
nt_space_mft: times NT_MAX_RUNS * 16 db 0
nt_space_boot: times 512 db 0
nt_space_vbr_buf: times 512 db 0
nt_space_buf: times 4096 db 0
nt_src_geo:     times NT_SRC_FIELDS dq 0
nt_src_mount:   dq 0
nt_src_info:    dq 0
nt_src_ops:     dq 0
nt_src_priv:    dq 0
nt_src_unit:    dd 0
nt_src_blkgeo:  times (blk_info_size - blk_info.logical_sector_bytes) db 0
nt_src_max:     dq 0
nt_src_logical: dd 0
nt_src_reading: dq 0
nt_src_ref:     dq 0
nt_src_mft:     times NT_MAX_RUNS * 16 db 0
nt_src_boot:    times 512 db 0
nt_src_vbr:     times 512 db 0
nt_src_file:    times NT_RECBUF db 0

ntfs_disk_handle:    dd -1
nt_exact_entries:    times 16384 db 0      ; bounded full GPT array, no heap/media writes
nt_ctx:              dq 0                  ; opaque priv (the module IS the context)
nt_ops:              times fs_ops_size db 0

nt_dev:              dq 0
nt_read_failures:    dq 0                    ; final read failures, monotonic BSP counter
nt_part_lba:         dq 0
nt_part_sectors:     dq 0
nt_total_sectors:    dq 0
nt_mft_lcn:          dq 0
nt_mft_lba:          dq 0
nt_serial:           dq 0
nt_binding_generation: dq 0                 ; captured binding epoch, not write authority
nt_mount_generation: dq 0
nt_save_name:        times 14 db 0
nt_prev_lcn:         dq 0
nt_best_dev:         dq 0
nt_best_lba:         dq 0
nt_best_sectors:     dq 0
nt_gpt_entries_lba:  dq 0
nt_last_blk_rc:      dq 0
nt_found_sequence:   dw 0
nt_found_ref:        dq 0
nt_found_size:       dq 0
nt_list_ptr:         dq 0
nt_spc:              dd 0
nt_clus_bytes:       dd 0
nt_rec_bytes:        dd 0
nt_rec_sectors:      dd 0
nt_idx_bytes:        dd 0
nt_mft_nruns:        dd 0
nt_nruns:            dd 0
nt_scheme:           dd 0
nt_best_scheme:      dd 0
nt_best_prio:        dd 0                  ; scan priority of the kept candidate (PREFER_NVME)
nt_scan_prio:        db 0                  ; priority of the pass currently scanning
nt_mount_stage:      db 0                  ; nt_mount_volume: last stage entered (0 = mounted)
nt_alt_dev:          dq 0                  ; alternate candidate (displaced by a preferred one)
nt_alt_lba:          dq 0
nt_alt_sectors:      dq 0
nt_alt_scheme:       dd 0
nt_rd_fallback:      dq 0                  ; multi-sector reads that fell back to per-sector ops
nt_gpt_count:        dd 0
nt_match_len:        dd 0
nt_list_cap:         dd 0
nt_list_names_used:  dd 0
nt_utf8_bytes:        dd 0
nt_utf8_name:         times (NT_NAME_MAX + 1) db 0
nt_list_names:       times NT_LIST_NAMES_CAP db 0
nt_list_count:       dd 0
nt_list_trunc:       dd 0
nt_dirbm_bits:       dd 0
nt_wref:             dd 0
nt_path_refusal:     dd NT_PATH_NONE       ; current mutate_path observation only
nt_mounted:          db 0
nt_dirty:            db 2                  ; 0 clean, 1 dirty, 2 unknown (not write-qualified)
nt_hiber:            db 2                  ; 0 qualified clear,1 hibernated,2 unknown
nt_lookup_complete:  db 0                  ; traversal returned success (not I/O failure)
nt_write_armed:      db 0
nt_visit_mode:       db 0
nt_found:            db 0
nt_found_isdir:      db 0
nt_refusal_count:    db 0
nt_match_name:       times (NT_NAME_MAX + 1) db 0
nt_name_scratch:     times 16 db 0
nt_walk_rec:         dd NT_REC_ROOT        ; directory record nt_walk_root walks
nt_lookup_pre:       db 0                  ; 1 = a path op already resolved the leaf
nt_path_buf:         times NT_READ_PATH_CAP db 0
nt_comp_buf:         times (NT_NAME_MAX + 1) db 0
nt_dir_blocks:       dd 0                  ; bounded allocation coverage for child VCNs
nt_dirbm:            times NT_DIRBM db 0
nt_mft_runs:         times NT_MAX_RUNS*16 db 0
nt_runs:             times NT_MAX_RUNS*16 db 0
nt_boot_buf:         times 512 db 0
nt_vbr_buf:          times 512 db 0
nt_rec_buf:          times NT_RECBUF db 0
nt_idx_buf:          times NT_IDXBUF db 0
nt_sec_buf:          times NT_SECBUF db 0
nt_verify_buf:       times NT_SECBUF db 0
nt_res_resize:       db 0
align 8
nt_res_parent_ref:   dq 0
nt_res_parent_lba:   dq 0
nt_res_fn_count:     dd 0
nt_res_fn:           dd 0
nt_res_fn_len:       dd 0
nt_res_data:         dd 0
nt_res_end:          dd 0
nt_res_new_attr:     dd 0
nt_res_new_used:     dd 0
nt_res_parent_key:   dd 0
nt_res_index_end:    dd 0
nt_res_index_next:   dd 0
nt_res_parent_expected: times NT_RECBUF db 0
nt_res_parent_stage: times NT_RECBUF db 0
nt_rename_insert:   dd 0
nt_rename_new_key:  times 200 db 0
nt_rename_entry:    times NT_RECBUF db 0
nt_res_lba:          dq 0
nt_res_value:        dd 0
nt_res_attempted:    dd 0                  ; possibly touched record sectors
nt_res_confirmed:    dd 0                  ; sectors with successful block status
nt_res_expected:     times NT_RECBUF db 0
nt_res_stage:        times NT_RECBUF db 0
nt_res_readback:     times NT_RECBUF db 0

str_nt_backend:      db "ntfs_disk", 0
str_nt_no_utc:       db "[PAOS64] ntfs create refused: the wall clock has no UTC provenance (not set by SNTP; NTPSYNC first) [fs.ntfs.create.no_utc]", 13, 10, 0
str_nt_mount_name:   db "ntfs0", 0
str_nt_pfx_ahci:     db "ahci", 0
str_nt_pfx_nvme:     db "nvme", 0
str_nt_hiberfil:     db "HIBERFIL.SYS", 0
str_nt_skipped:      db "[PAOS64] L4 fs: ntfs skipped (no NTFS volume on any AHCI/NVMe device) [fs.ntfs.skipped]", 13, 10, 0
str_nt_mounted:      db "[PAOS64] L4 fs: NTFS mounted ntfs0 part_lba=", 0
str_nt_m_sectors:    db " sectors=", 0
str_nt_m_clus:       db " clus=", 0
str_nt_m_rec:        db " rec=", 0
str_nt_m_mftruns:    db " mft_runs=", 0
str_nt_m_serial:     db " serial=", 0
str_nt_m_dirty:      db " dirty=", 0
str_nt_m_hiber:      db " hiber=", 0
str_nt_m_write:      db " write_armed=", 0
str_nt_m_dev:        db " dev=", 0
str_nt_m_pref:       db " prefer_nvme=", 0
str_nt_m_rd1:        db " rd1=", 0
str_nt_m_tail:       db " [fs.ntfs.mounted]", 13, 10, 0
str_nt_mfail:        db "[PAOS64] L4 fs: ntfs mount FAILED dev=", 0
str_nt_mfail_stage:  db " stage=", 0
str_nt_mfail_tail:   db " (1 boot read, 2 OEM id, 3 bps!=512, 4 spc, 5 rec size, 6 $MFT runlist) [fs.ntfs.mount_failed]", 13, 10, 0
str_nt_write_verified: db "[PAOS64] L4 fs: ntfs write_at READ-BACK VERIFIED bytes=", 0
str_nt_write_refused:  db "[PAOS64] L4 fs: ntfs write_at REFUSED reason=", 0
str_nt_write_blkrc:    db " last_blk_rc=", 0
str_nt_refuse_attrlist: db "[PAOS64] L4 fs: ntfs refused: attribute list (not supported yet) [fs.ntfs.refused.attrlist]", 13, 10, 0
str_nt_refuse_flags:    db "[PAOS64] L4 fs: ntfs refused: compressed/encrypted stream [fs.ntfs.refused.flags]", 13, 10, 0
str_nt_refuse_runs:     db "[PAOS64] L4 fs: ntfs refused: > 64 extents or bad runlist [fs.ntfs.refused.runs]", 13, 10, 0
str_nt_sa_caller: db "NTFS_WRITE", 0

; Private synchronous rename admission state; never authority or a persistent arm.
nt_rename_mode: db 0
align 8
nt_rename_old: dq 0
nt_rename_new: dq 0
nt_rename_len: dd 0
nt_rename_old_len: dd 0
nt_rename_fn_attr: dd 0
nt_rename_index_attr: dd 0
nt_rename_index_header: dd 0
nt_rename_key_len: dd 0
nt_rename_child_cut: dd 0
nt_rename_parent_cut: dd 0
nt_rename_child_delta: dd 0
nt_rename_parent_delta: dd 0
nt_rename_parent: dd 0
nt_path_parent: dd 0
nt_rename_mount_max: dq 0
nt_rename_mount_logical: dd 0
nt_rename_boot: times 512 db 0

; Transaction-local cross-parent staging; buffers are never authority.
nt_cross: db 0
nt_cross_phase: db 0
align 8
nt_rename_parent_full: dq 0
nt_cross_dest_ref: dq 0
nt_cross_source_lba: dq 0
nt_cross_source_attr: dd 0
nt_cross_source_header: dd 0
nt_cross_source_key: dd 0
nt_cross_entry_size: dd 0
nt_cross_path: times (NT_MUT_PATH_MAX + 1) db 0
nt_cross_source_expected: times NT_RECBUF db 0
nt_cross_source_stage: times NT_RECBUF db 0

; Both paths are <=NT_MUT_PATH_MAX bytes, each component >=1 byte plus separator.
; Their combined ancestry has at most NT_MUT_PATH_MAX+2 records including roots.
nt_dir_ready: db 0
nt_dir_leaf: db 0
nt_dir_sequence: dw 0
nt_dir_child: dd 0
nt_dir_count: dd 0
nt_dir_ref: dq 0
nt_dir_next: dq 0
nt_dir_lba: dq 0
nt_dir_refs: times (NT_MUT_PATH_MAX + 2) dq 0
nt_dir_lbas: times (NT_MUT_PATH_MAX + 2) dq 0
nt_dir_images: times (NT_MUT_PATH_MAX + 2)*NT_RECBUF db 0
nt_dir_readback: times NT_RECBUF db 0

; Resident directory namespace transaction. Finite allocation profile: 1024-byte
; FILEs, 4096-byte clusters, initialized MFT (<=4096 records), a one-cluster MFT
; bitmap (<=512 bytes), one-cluster volume bitmap (<=4096 bytes). No new clusters,
; MFT growth, journal or undo. Slots 0/1/2 are parent/child/MFT bitmap; slots
; 3/4/5 hold immutable MFT FILE/$Bitmap FILE/volume bitmap authority.
; CREATE snapshots at most one FILE record of DATA; nt_ns_create_record admits
; only the bytes fitting after the actual name/security headers and END.
; DELETE consumes no buffer.
; File DELETE additionally releases up to four plain allocated DATA clusters,
; after complete <=128-record ownership census and a durable retirement barrier.
; Normalize the admitted full-width opcode only after dispatch, sharing exactly
; the same allocation/publish and unpublish/retire/free write custody as dirs.
nt_op_file_path:
    mov  byte [rel nt_ns_file], 1
    jmp  nt_op_namespace_path
nt_op_directory_path:
    mov  byte [rel nt_ns_file], 0
nt_op_namespace_path:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  byte [rel nt_ns_ready], 0
    mov  byte [rel nt_sx_ready], 0
    mov  byte [rel nt_nd_mode], 0
    mov  byte [rel nt_nd_ready], 0
    mov  byte [rel nt_dir_ready], 0
    mov  dword [rel nt_dir_count], 0
    mov  byte [rel nt_cross], 0
    mov  [rel nt_ns_op], r8d
    mov  r12, rsi
    cmp  byte [rel nt_ns_file], 0
    je   .no_data
    cmp  r8, FS_MUT_DELETE
    jne  .create_data
    mov  dword [rel nt_ns_op], FS_MUT_RMDIR
    jmp  .no_data
.create_data:
    cmp  rcx, 1024                     ; full64 snapshot bound; exact FILE fit below
    ja   .no
    mov  [rel nt_ns_length], ecx
    test rcx, rcx
    jz   .data_ok
    test rdx, rdx
    jz   .no
    mov  rax, rdx
    add  rax, rcx
    jc   .no
    mov  [rel nt_ns_source], rdx
.data_ok:
    mov  dword [rel nt_ns_op], FS_MUT_MKDIR
    jmp  .path
.no_data:
    test rcx, rcx
    jnz  .no
.path:
    mov  rsi, r12
    test rsi, rsi
    jz   .no
    call nt_op_save_armed
    cmp  eax, 1
    jne  .no
    cmp  dword [rel nt_rec_bytes], 1024
    jne  .no
    cmp  dword [rel nt_clus_bytes], 4096
    jne  .no
    cmp  byte [rel nt_ns_file], 0
    je   .payload_ready
    cmp  dword [rel nt_ns_op], FS_MUT_MKDIR
    jne  .payload_ready
    mov  edx, [rel nt_ns_length]
    test edx, edx
    jz   .payload_ready
    mov  rsi, [rel nt_ns_source]
    lea  rdi, [rel nt_ns_payload]
    call memcpy                         ; private immutable DATA snapshot
.payload_ready:
    mov  rsi, r12
    call nt_save_path
    test rax, rax
    jnz  .no
    mov  ecx, edx
.slash:
    dec  ecx
    cmp  byte [r12 + rcx], '/'
    jne  .slash
    mov  ebp, ecx
    lea  rsi, [r12 + rcx + 1]
    sub  edx, ecx
    dec  edx
    mov  [rel nt_rename_new], rsi
    mov  [rel nt_rename_len], edx
    call nt_ns_name
    test eax, eax
    jnz  .no
    mov  rsi, r12
    mov  edx, ebp
    call nt_rename_resolve_parent
    test rax, rax
    jnz  .no
    cmp  edx, 24
    jae  .parent_ok
    cmp  byte [rel nt_ns_file], 1
    jne  .no
    cmp  edx, NT_REC_ROOT
    jne  .no                            ; only bounded resident scratch root
.parent_ok:
    mov  [rel nt_rename_parent_full], rdx
    mov  [rel nt_cross_dest_ref], rdx
    ; CREATE has a finite canonical STDINFO/resident-security profile. Refuse
    ; a known unsupported parent BEFORE entering ancestry/custody staging:
    ; that read-only admission failure must not poison an unrelated range
    ; WRITE on the clean mount. No parent bytes become write authority here.
    cmp  byte [rel nt_ns_file], 1
    jne  .profile_ready                ; directory CREATE scope unchanged
    cmp  dword [rel nt_ns_op], FS_MUT_MKDIR
    jne  .profile_ready
    mov  edi, edx
    call nt_read_record
    test rax, rax
    jnz  .uncertain                    ; actual read/fixup uncertainty still fences
    call nt_ns_create_profile
    cmp  eax, -2
    je   .uncertain                    ; malformed FILE is not an admission hint
    test eax, eax
    jnz  .no                           ; unsupported layout, zero writes/flushes
    call nt_sx_prepare                 ; NTFS 3.x parent: read-only $Secure
    test eax, eax
    jnz  .no                           ; unresolved/uninheritable, zero writes
.profile_ready:
    mov  dword [rel nt_dir_child], -1
    mov  rsi, r12
    mov  rdx, [rel nt_rename_parent_full]
    call nt_dir_parent_chain            ; actual name/sequence edges to real root
    test rax, rax
    jnz  .uncertain
    mov  byte [rel nt_rename_mode], 4    ; live geometry throughout this operation
    mov  edi, [rel nt_rename_parent_full]
    call nt_read_record
    test rax, rax
    jnz  .uncertain
    mov  rdx, [rel nt_rename_parent_full]
    call nt_dir_parent_admit
    test rax, rax
    jnz  .no
    cmp  byte [rel nt_ns_file], 0
    je   .parent_profile
    cmp  dword [rel nt_rename_parent_full], NT_REC_ROOT
    jne  .parent_profile
    call nt_ns_root_admit
    test eax, eax
    jnz  .no
.parent_profile:
    xor  ebx, ebx                      ; slot0 parent
    mov  edi, [rel nt_rename_parent_full]
    call nt_ns_record_slot
    test eax, eax
    jnz  .uncertain
    ; The independently reread parent must equal its earlier ancestry image.
    xor  r13d, r13d
.parent_snapshot:
    lea  rsi, [rel nt_dir_refs]
    mov  rax, [rel nt_rename_parent_full]
    cmp  rax, [rsi + r13*8]
    jne  .parent_next
    imul esi, r13d, NT_RECBUF
    lea  rdi, [rel nt_dir_images]
    add  rsi, rdi
    lea  rdi, [rel nt_ns_expected]
    mov  edx, 1024
    call memcmp
    test rax, rax
    jnz  .uncertain
.parent_next:
    inc  r13d
    cmp  r13d, [rel nt_dir_count]
    jb   .parent_snapshot
    ; Actual MFT metadata, bounded DATA and actual bitmap; never guess a slot.
    xor  edi, edi
    call nt_read_record
    test rax, rax
    jnz  .uncertain
    cmp  dword [rel nt_rec_buf + 44], 0
    jne  .no
    call nt_ns_data
    test rax, rax
    jz   .no
    mov  rdx, [rax + 48]
    cmp  rdx, [rax + 56]
    jne  .no
    test edx, 1023
    jnz  .no
    shr  rdx, 10
    cmp  rdx, 27
    jb   .no
    cmp  rdx, 4096
    ja   .no
    mov  [rel nt_ns_records], edx
    mov  edx, [rel nt_nruns]
    cmp  edx, [rel nt_mft_nruns]
    jne  .no
    shl  edx, 4
    lea  rdi, [rel nt_mft_runs]
    lea  rsi, [rel nt_runs]
    call memcmp
    test rax, rax
    jnz  .no                            ; mounted and current MFT mapping agree
    mov  ebx, 3
    xor  edi, edi
    call nt_ns_record_slot
    test eax, eax
    jnz  .uncertain
    lea  rdi, [rel nt_rec_buf]
    mov  esi, NT_A_BITMAP
    call nt_find_attr_any
    test rax, rax
    jz   .no
    mov  ebx, 2
    call nt_ns_mft_bitmap
    cmp  eax, -2
    je   .uncertain
    test eax, eax
    jnz  .no
    cmp  dword [rel nt_ns_bitmap_bytes], 512
    ja   .no
    mov  eax, [rel nt_ns_bitmap_bytes]
    mov  [rel nt_ns_mft_bytes], eax
    shl  eax, 3
    cmp  eax, [rel nt_ns_records]
    jb   .no
    cmp  word [rel nt_ns_expected + 2*NT_RECBUF], 0xFFFF
    jne  .no                            ; never allocate reserved system identities
    ; Full bitmap/header consistency in the supported initialized region.
    mov  dword [rel nt_ns_child], -1
    mov  r13d, 24
.scan:
    mov  edi, r13d
    call nt_ns_read_candidate
    cmp  eax, 1
    je   .blank
    test eax, eax
    jnz  .uncertain
    cmp  dword [rel nt_rec_buf + 44], r13d
    jne  .no
    mov  eax, r13d
    lea  rsi, [rel nt_ns_expected + 2*NT_RECBUF]
    bt   [rsi], eax
    jc   .allocated
    mov  edi, r13d
    call nt_ns_free
    test eax, eax
    jnz  .no
    cmp  word [rel nt_rec_buf + 16], -1
    je   .scan_next                     ; exhausted sequence: never wrap/reuse
    cmp  dword [rel nt_ns_child], -1
    jne  .scan_next
    mov  [rel nt_ns_child], r13d
    mov  ax, [rel nt_rec_buf + 16]
    mov  [rel nt_ns_sequence], ax
    jmp  .scan_next
.blank:
    ; Windows leaves initialized MFT slots never formatted (all zero). Free
    ; only with a clear bitmap bit; first use gets sequence 1 like Windows.
    mov  eax, r13d
    lea  rsi, [rel nt_ns_expected + 2*NT_RECBUF]
    bt   [rsi], eax
    jc   .no                            ; allocated identity is never blank
    cmp  dword [rel nt_ns_child], -1
    jne  .scan_next
    mov  [rel nt_ns_child], r13d
    mov  word [rel nt_ns_sequence], 0
    jmp  .scan_next
.allocated:
    test word [rel nt_rec_buf + 22], 1
    jz   .no                            ; metadata FILEs may also have view flags
.scan_next:
    inc  r13d
    cmp  r13d, [rel nt_ns_records]
    jb   .scan
    mov  ecx, [rel nt_ns_mft_bytes]
    shl  ecx, 3
.extra_bits:
    cmp  r13d, ecx
    jae  .volume
    lea  rsi, [rel nt_ns_expected + 2*NT_RECBUF]
    bt   [rsi], r13d
    jc   .no                            ; allocation beyond initialized MFT refused
    inc  r13d
    jmp  .extra_bits
.volume:
    mov  edi, 6
    call nt_read_record
    test rax, rax
    jnz  .uncertain
    cmp  dword [rel nt_rec_buf + 44], 6
    jne  .no
    call nt_ns_data
    test rax, rax
    jz   .no
    mov  r14, rax
    mov  ebx, 4
    mov  edi, 6
    call nt_ns_record_slot
    test eax, eax
    jnz  .uncertain
    mov  rax, r14
    mov  ebx, 5
    call nt_ns_vol_bitmap
    cmp  eax, -2
    je   .uncertain
    test eax, eax
    jnz  .no
    mov  rax, [rel nt_total_sectors]
    xor  edx, edx
    mov  ecx, [rel nt_spc]
    div  rcx
    add  rax, 7
    shr  rax, 3
    mov  edx, [rel nt_ns_bitmap_bytes]
    cmp  rax, rdx
    jne  .no                            ; full 64-bit volume map size, no prefix
    cmp  qword [rel nt_ns_lbas + 2*8], 0
    je   .no
    cmp  dword [rel nt_ns_op], FS_MUT_RMDIR
    je   .remove
    cmp  dword [rel nt_ns_child], -1
    je   .no                            ; honest initialized-record exhaustion
    mov  edi, [rel nt_ns_child]
    call nt_ns_read_candidate
    cmp  eax, 1
    je   .blank_child
    test eax, eax
    jnz  .uncertain
    mov  ax, [rel nt_ns_sequence]
    cmp  ax, [rel nt_rec_buf + 16]
    jne  .uncertain
    mov  edi, [rel nt_ns_child]
    call nt_ns_free
    test eax, eax
    jnz  .uncertain
    jmp  .child_slot
.blank_child:
    cmp  word [rel nt_ns_sequence], 0
    jne  .uncertain                     ; scanned formatted, now blank
.child_slot:
    mov  ebx, 1
    mov  edi, [rel nt_ns_child]
    call nt_ns_record_slot
    test eax, eax
    jnz  .uncertain
    call nt_ns_create_record
    test eax, eax
    jnz  .no
    lea  rdi, [rel nt_ns_stage + 2*NT_RECBUF]
    mov  eax, [rel nt_ns_child]
    bts  [rdi], eax                     ; actual MFT allocation, no private slots
    jmp  .parent
.remove:
    mov  rsi, r12
    call nt_save_path
    mov  rsi, r12
    mov  byte [rel nt_lookup_complete], 0
    call nt_resolve_mutation_path
    test rax, rax
    jnz  .resolve_failed
    mov  al, [rel nt_ns_file]
    xor  al, 1
    cmp  [rel nt_found_isdir], al
    jne  .no
    mov  rax, [rel nt_found_ref]
    cmp  rax, 24
    jb   .no
    cmp  rax, 4096
    jae  .no
    cmp  eax, [rel nt_ns_records]
    jae  .no
    mov  [rel nt_ns_child], eax
    lea  rdi, [rel nt_ns_expected + 2*NT_RECBUF]
    bt   [rdi], eax
    jnc  .no
    mov  edi, eax
    call nt_read_record
    test rax, rax
    jnz  .uncertain
    movzx edx, word [rel nt_found_sequence]
    shl  rdx, 48
    mov  eax, [rel nt_ns_child]
    or   rdx, rax
    cmp  byte [rel nt_ns_file], 0
    jne  .file_remove
    call nt_dir_admit
    jmp  .remove_admitted
.file_remove:
    call nt_ns_file_admit
.remove_admitted:
    test rax, rax
    jnz  .no
    mov  eax, [rel nt_res_fn]
    lea  rsi, [rel nt_rec_buf]
    add  rsi, rax
    mov  rax, [rel nt_rename_parent_full]
    cmp  [rsi], rax
    jne  .no
    lea  rdi, [rel nt_ns_key]
    mov  edx, [rel nt_res_fn_len]
    mov  [rel nt_ns_key_bytes], edx
    call memcpy
    cmp  byte [rel nt_ns_file], 1
    je   .retire
    ; Complete admitted own index must consist ONLY of its terminal entry.
    call nt_ns_index
    add  eax, 16
    cmp  eax, [rel nt_res_index_end]
    jne  .no                            ; nonempty, even if a caller listed cap0
.retire:
    cmp  word [rel nt_rec_buf + 4], 48
    jne  .no
    cmp  word [rel nt_rec_buf + 20], 56
    jne  .no
    mov  ebx, 1
    mov  edi, [rel nt_ns_child]
    call nt_ns_record_slot
    test eax, eax
    jnz  .uncertain
    lea  rdi, [rel nt_ns_stage + NT_RECBUF]
    mov  ax, [rdi + 16]
    mov  [rel nt_ns_sequence], ax
    mov  word [rdi + 18], 0
    mov  word [rdi + 22], 0
    mov  dword [rdi + 24], 64
    mov  qword [rdi + 8], 0
    add  rdi, 56
    mov  ecx, 1024 - 56
    xor  eax, eax
    rep  stosb
    lea  rdi, [rel nt_ns_stage + NT_RECBUF]
    mov  dword [rdi + 56], -1
    call nt_resident_encode
    lea  rdi, [rel nt_ns_stage + 2*NT_RECBUF]
    mov  eax, [rel nt_ns_child]
    btr  [rdi], eax
.parent:
    call nt_ns_parent_stage
    cmp  eax, -2
    je   .uncertain
    test eax, eax
    jnz  .no
    xor  edi, edi
    call nt_ns_windows
    cmp  eax, -2
    je   .uncertain
    test eax, eax
    jnz  .no
    call nt_ns_mapping
    test eax, eax
    jnz  .no
    cmp  byte [rel nt_nd_mode], 0
    je   .allocation_ready
    call nt_nd_prepare
    cmp  eax, -2
    je   .uncertain
    test eax, eax
    jnz  .no
    mov  byte [rel nt_nd_ready], 1
.allocation_ready:
    mov  byte [rel nt_dir_ready], 1
    mov  byte [rel nt_ns_ready], 1       ; all affected and allocation images ready
    call nt_save_current
    test rax, rax
    jnz  .uncertain
    ; Creation: allocate bitmap, materialize FILE, publish parent. Removal:
    ; unpublish parent, clear FILE, release bitmap. Partial states are reported.
    xor  r13d, r13d
.write_slot:
    mov  ebx, r13d
    cmp  r13d, 3
    jne  .metadata_slot
    mov  ebx, 5                        ; release volume allocation LAST
    jmp  .chosen
.metadata_slot:
    cmp  dword [rel nt_ns_op], FS_MUT_RMDIR
    je   .chosen
    mov  ebx, 2
    sub  ebx, r13d
.chosen:
    xor  r14d, r14d
.sector:
    call nt_ns_slot_lba
    imul ecx, ebx, NT_RECBUF
    lea  r15, [rel nt_ns_stage]
    add  r15, rcx
    mov  eax, r14d
    shl  eax, 9
    add  r15, rax
    mov  rcx, r15
    mov  edx, 1
    mov  r9d, 1
    call nt_write                       ; current predicate runs at EVERY retry
    test rax, rax
    jnz  .uncertain
    imul edi, ebx, NT_RECBUF
    lea  rsi, [rel nt_ns_expected]
    add  rdi, rsi
    mov  eax, r14d
    shl  eax, 9
    add  rdi, rax
    mov  rsi, r15
    mov  edx, 512
    call memcpy                         ; exact intended partial image, not live bytes
    call nt_save_current
    test rax, rax
    jnz  .uncertain
    inc  r14d
    lea  rdi, [rel nt_ns_sectors]
    cmp  r14d, [rdi + rbx*4]
    jb   .sector
    inc  r13d
    cmp  r13d, 3
    jb   .write_slot
    cmp  byte [rel nt_nd_mode], 0
    je   .writes_done
    cmp  r13d, 3
    jne  .writes_done
    ; Unlink + retirement + MFT release must be durable BEFORE physical
    ; clusters become reusable. Failure here leaves allocation intact.
    call nt_save_current
    test rax, rax
    jnz  .uncertain
    mov  rdi, [rel nt_dev]
    call blk_flush
    test rax, rax
    jnz  .uncertain
    call nt_save_current
    test rax, rax
    jnz  .uncertain
    jmp  .write_slot
.writes_done:
    call nt_save_current
    test rax, rax
    jnz  .uncertain
    mov  rdi, [rel nt_dev]
    call blk_flush
    test rax, rax
    jnz  .uncertain
    call nt_save_current                ; complete postimage after flush too
    test rax, rax
    jnz  .uncertain
    xor  eax, eax
    jmp  .out
.resolve_failed:
    ; Only a completed index walk with no matching name proves absence.
    ; Reset at this exact resolver boundary: an earlier parent lookup cannot
    ; turn an I/O/capability failure into not_found.
    cmp  byte [rel nt_lookup_complete], 1
    jne .no
    cmp  byte [rel nt_found], 0
    jne .no
    mov  dword [rel nt_path_refusal], NT_PATH_MISSING
    jmp .no
.uncertain:
    mov  byte [rel nt_write_armed], 0
.no:
    mov  rax, -1
.out:
    mov  byte [rel nt_ns_ready], 0
    mov  byte [rel nt_ns_wmode], 0
    mov  byte [rel nt_nd_ready], 0
    mov  byte [rel nt_nd_mode], 0
    mov  byte [rel nt_ns_file], 0
    mov  byte [rel nt_dir_ready], 0
    mov  dword [rel nt_dir_count], 0
    mov  byte [rel nt_rename_mode], 0
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; Scratch uppercase ASCII leaf, shared namespace policy without broadening it.
nt_ns_name:
    cmp  edx, 7
    jb   .no
    cmp  byte [rsi], 'F'
    jne  .no
    cmp  word [rsi + 1], 'SW'
    jne  .no
    cmp  dword [rsi + rdx - 4], '.TST'
    jne  .no
    sub  edx, 4
    xor  ecx, ecx
.loop:
    mov  al, [rsi + rcx]
    cmp  al, '-'
    je   .next
    cmp  al, '_'
    je   .next
    cmp  al, '0'
    jb   .no
    cmp  al, '9'
    jbe  .next
    cmp  al, 'A'
    jb   .no
    cmp  al, 'Z'
    ja   .no
.next:
    inc  ecx
    cmp  ecx, edx
    jb   .loop
    xor  eax, eax
    ret
.no:
    mov  eax, -1
    ret

; Generic existing metadata DATA admission plus a deliberately plain segment.
nt_ns_data:
    lea  rdi, [rel nt_rec_buf]
    lea  rsi, [rdi + 1024]
    call nt_data_attr_admit
    test rax, rax
    jz   .out
    cmp  byte [rax + 8], 1
    jne  .no
    cmp  word [rax + 12], 0
    jne  .no
    cmp  word [rax + 34], 0
    jne  .no
    cmp  dword [rax + 36], 0
    jne  .no
    push rax
    lea  rdi, [rel nt_rec_buf]
    cmp  word [rdi + 18], 1
    jne  .bad_pop
    movzx ecx, word [rdi + 20]
    xor  r8d, r8d
    xor  r9d, r9d
.attrs:
    mov  edx, [rdi + rcx]
    cmp  edx, -1
    je   .end
    cmp  edx, r8d
    jbe  .bad_pop
    mov  r8d, edx
    cmp  byte [rdi + rcx + 9], 0
    jne  .bad_pop
    cmp  word [rdi + rcx + 12], 0
    jne  .bad_pop
    cmp  edx, NT_A_STDINFO
    je   .resident
    cmp  edx, NT_A_FILENAME
    je   .resident
    cmp  edx, NT_A_DATA
    je   .next
    cmp  dword [rdi + 44], 0
    jne  .bad_pop
    cmp  edx, NT_A_BITMAP
    jne  .bad_pop
    inc  r9d
    jmp  .next
.resident:
    cmp  byte [rdi + rcx + 8], 0
    jne  .bad_pop
.next:
    add  ecx, [rdi + rcx + 4]
    jmp  .attrs
.end:
    add  ecx, 8
    cmp  ecx, [rdi + 24]
    jne  .bad_pop
    cmp  dword [rdi + 44], 0
    jne  .good_pop
    cmp  r9d, 1
    jne  .bad_pop
.good_pop:
    pop  rax
    ret
.bad_pop:
    pop  rax
.no:
    xor  eax, eax
.out:
    ret

; EDI=identity, exact inactive FILE format. Sequence is incremented on reuse;
; exhausted sequence values remain unavailable instead of wrapping.
nt_ns_free:
    cmp  [rel nt_rec_buf + 44], edi
    jne  .no
    cmp  word [rel nt_rec_buf + 22], 0
    jne  .no
    cmp  word [rel nt_rec_buf + 18], 0
    jne  .no
    cmp  qword [rel nt_rec_buf + 32], 0
    jne  .no
    cmp  dword [rel nt_rec_buf + 24], 64
    jne  .no
    cmp  dword [rel nt_rec_buf + 28], 1024
    jne  .no
    cmp  dword [rel nt_rec_buf + 56], -1
    jne  .no
    cmp  word [rel nt_rec_buf + 20], 56
    jne  .no
    cmp  word [rel nt_rec_buf + 4], 48
    jne  .no
    cmp  word [rel nt_rec_buf + 16], 0
    je   .no
    xor  eax, eax
    ret
.no:
    mov  eax, -1
    ret

; EDI=record -> complete logical FILE, including currently inactive records.
nt_ns_read_inactive:
    mov  eax, edi
    shl  rax, 10
    mov  rdx, rax
    lea  rdi, [rel nt_mft_runs]
    mov  esi, [rel nt_mft_nruns]
    lea  rcx, [rel nt_rec_buf]
    mov  r8d, 1024
    call nt_read_stream_record
    test rax, rax
    jnz  .out
    lea  rdi, [rel nt_rec_buf]
    mov  esi, 1024
    call nt_fixup_file
.out:
    ret

; EDI=record -> 0 formatted logical FILE, 1 never formatted (1024 zero bytes,
; raw in nt_rec_buf), else read/format failure.
nt_ns_read_candidate:
    mov  eax, edi
    shl  rax, 10
    mov  rdx, rax
    lea  rdi, [rel nt_mft_runs]
    mov  esi, [rel nt_mft_nruns]
    lea  rcx, [rel nt_rec_buf]
    mov  r8d, 1024
    call nt_read_stream_record
    test rax, rax
    jnz  .out
    lea  rdi, [rel nt_rec_buf]
    mov  ecx, 1024
    xor  eax, eax
    repe scasb
    je   .blank
    lea  rdi, [rel nt_rec_buf]
    mov  esi, 1024
    call nt_fixup_file
.out:
    ret
.blank:
    mov  eax, 1
    ret

; EBX=slot, EDI=record; derive whole contiguous checked mapping and raw preimage
; from the SAME logical FILE just admitted. Do not reread into the stage.
nt_ns_record_slot:
    mov  eax, edi
    shl  rax, 10
    mov  rdx, rax
    lea  rdi, [rel nt_mft_runs]
    mov  esi, [rel nt_mft_nruns]
    call nt_vcn_to_lba
    cmp  rax, -2
    jae  .no
    test rcx, rcx
    jnz  .no
    cmp  rdx, 1024
    jb   .no
    lea  rdi, [rel nt_ns_lbas]
    mov  [rdi + rbx*8], rax
    lea  rdi, [rel nt_ns_sectors]
    mov  dword [rdi + rbx*4], 2
    imul edi, ebx, NT_RECBUF
    lea  rsi, [rel nt_ns_expected]
    add  rdi, rsi
    lea  rsi, [rel nt_rec_buf]
    mov  edx, 1024
    call memcpy
    ; Restore raw USA tails WITHOUT changing the token or its saved tails.
    imul edi, ebx, NT_RECBUF
    lea  rsi, [rel nt_ns_expected]
    add  rdi, rsi
    movzx eax, word [rdi + 4]
    mov  ax, [rdi + rax]
    mov  [rdi + 510], ax
    mov  [rdi + 1022], ax
    imul edi, ebx, NT_RECBUF
    lea  rsi, [rel nt_ns_stage]
    add  rdi, rsi
    lea  rsi, [rel nt_rec_buf]
    mov  edx, 1024
    call memcpy
    xor  eax, eax
    ret
.no:
    mov  eax, -1
    ret

; RAX=bounded bitmap attribute, EBX=slot. Real complete plain single run.
nt_ns_bitmap:
    push r12
    mov  r12, rax
    test rax, rax
    jz   .no
    cmp  byte [rax + 8], 1
    jne  .no
    cmp  byte [rax + 9], 0
    jne  .no
    cmp  word [rax + 12], 0
    jne  .no
    cmp  qword [rax + 16], 0
    jne  .no
    cmp  word [rax + 34], 0
    jne  .no
    cmp  dword [rax + 36], 0
    jne  .no
    mov  rdx, [rax + 48]
    test rdx, rdx
    jz   .no
    cmp  rdx, NT_RECBUF
    ja   .no
    cmp  rdx, [rax + 56]
    jne  .no
    mov  [rel nt_ns_bitmap_bytes], edx
    add  edx, 511
    shr  edx, 9
    lea  rdi, [rel nt_ns_sectors]
    mov  [rdi + rbx*4], edx
    movzx ecx, word [rax + 32]
    lea  rdi, [rax + rcx]
    mov  ecx, [rax + 4]
    add  rcx, rax
    lea  rsi, [rel nt_runs]
    mov  edx, NT_MAX_RUNS
    call nt_decode_runlist
    cmp  eax, 1
    jne  .no
    mov  rdi, [rel nt_runs]
    test rdi, rdi
    jle  .no
    cmp  qword [rel nt_runs + 8], 1
    jne  .no                            ; both bounded maps fit one actual cluster
    mov  rax, [rel nt_runs + 8]
    mov  ecx, [rel nt_clus_bytes]
    imul rax, rcx
    cmp  rax, [r12 + 40]
    jne  .no
    mov  eax, [rel nt_ns_bitmap_bytes]
    add  eax, 511
    and  eax, -512
    cmp  rax, [r12 + 40]
    ja   .no
    mov  rax, [rel nt_runs + 8]
    dec  rax
    cmp  rax, [r12 + 24]
    jne  .no
    call nt_clus_to_lba
    lea  rdi, [rel nt_ns_lbas]
    mov  [rdi + rbx*8], rax
    mov  rsi, rax
    lea  rdi, [rel nt_ns_sectors]
    mov  edx, [rdi + rbx*4]
    imul ecx, ebx, NT_RECBUF
    lea  rdi, [rel nt_ns_expected]
    add  rcx, rdi
    call nt_read
    test rax, rax
    jnz  .io
    imul esi, ebx, NT_RECBUF
    lea  rdi, [rel nt_ns_expected]
    add  rsi, rdi
    imul edi, ebx, NT_RECBUF
    lea  rdx, [rel nt_ns_stage]
    add  rdi, rdx
    lea  rdx, [rel nt_ns_sectors]
    mov  edx, [rdx + rbx*4]
    shl  edx, 9
    call memcpy
    xor  eax, eax
    pop  r12
    ret
.io:
    mov  eax, -2
    pop  r12
    ret
.no:
    mov  eax, -1
    pop  r12
    ret

; nt_rec_buf=admitted directory; return first own index entry offset EAX.
nt_ns_index:
    lea  rdi, [rel nt_rec_buf]
    mov  esi, NT_A_INDEXROOT
    call nt_find_attr_any
    sub  rax, rdi
    mov  [rel nt_ns_index_attr], eax
    movzx edx, word [rdi + rax + 20]
    add  eax, edx
    add  eax, 16
    mov  [rel nt_ns_index_header], eax
    mov  edx, [rdi + rax + 4]
    add  edx, eax
    mov  [rel nt_res_index_end], edx
    add  eax, [rdi + rax]
    ret

; Non-authorizing preflight, also repeated on the staged parent immediately
; before constructing a new FILE. Modern shared-security IDs require separate
; inheritance support: never copy one as though it were an explicit descriptor.
; Generic full-record validation bounds every attribute before the searches.
; EAX 0 supported shape, -1 unsupported profile, -2 malformed FILE.
nt_ns_create_profile:
    mov  byte [rel nt_ns_profile], 0
    lea  rdi, [rel nt_rec_buf]
    mov  esi, [rel nt_rec_bytes]
    add  rsi, rdi
    call nt_dir_record_valid
    test rax, rax
    jnz  .malformed
    lea  rdi, [rel nt_rec_buf]
    mov  esi, NT_A_STDINFO
    call nt_find_attr_any
    test rax, rax
    jz   .no
    cmp  byte [rax + 8], 0
    jne  .no
    cmp  byte [rax + 9], 0
    jne  .no
    cmp  word [rax + 12], 0
    jne  .no
    cmp  dword [rax + 16], 48
    jne  .shared
    cmp  dword [rax + 4], 72
    jne  .no
    cmp  word [rax + 20], 24
    jne  .no
    lea  rdi, [rel nt_rec_buf]
    mov  esi, 0x50
    call nt_find_attr_any
    test rax, rax
    jz   .no
    cmp  byte [rax + 8], 0
    jne  .no
    cmp  byte [rax + 9], 0
    jne  .no
    cmp  word [rax + 12], 0
    jne  .no
    mov  byte [rel nt_ns_profile], 1    ; explicit resident descriptor
    xor  eax, eax
    ret
.shared:
    ; NTFS 3.x: 72-byte STDINFO whose nonzero security_id is the only
    ; descriptor source. Its inheritance is computed (nt_sx_prepare).
    cmp  dword [rax + 16], 72
    jne  .no
    cmp  dword [rax + 4], 96
    jne  .no
    cmp  word [rax + 20], 24
    jne  .no
    cmp  dword [rax + 24 + 52], 0
    je   .no                            ; no explicit-id0 v3 profile
    lea  rdi, [rel nt_rec_buf]
    mov  esi, 0x50
    call nt_find_attr_any
    test rax, rax
    jnz  .no                            ; never two descriptor sources
    mov  byte [rel nt_ns_profile], 3
    xor  eax, eax
    ret
.no:
    mov  eax, -1
    ret
.malformed:
    mov  eax, -2
    ret

; Build a new ordinary FILE from checked free identity and admitted parent
; STDINFO/security metadata. Resident I30 allocates no physical clusters.
nt_ns_create_record:
    lea  rdi, [rel nt_rec_buf]
    lea  rsi, [rel nt_ns_stage]
    mov  edx, 1024
    call memcpy
    call nt_ns_create_profile
    test eax, eax
    jnz  .no
    cmp  byte [rel nt_ns_profile], 3
    je   .inherited
    cmp  byte [rel nt_sx_ready], 0
    jne  .no                            ; admitted v3 parent changed profile
    lea  rdi, [rel nt_rec_buf]
    mov  esi, NT_A_STDINFO
    call nt_find_attr_any
    cmp  dword [rax + 16], 48
    jne  .no                            ; no quota/object-id inheritance profile
    cmp  dword [rax + 4], 72
    jne  .no
    cmp  word [rax + 20], 24
    jne  .no                            ; the copied canonical 48-byte STDINFO
    mov  [rel nt_ns_std], rax
    lea  rdi, [rel nt_rec_buf]
    mov  esi, 0x50
    call nt_find_attr_any
    test rax, rax
    jz   .no                            ; explicit resident security required
    mov  edx, [rax + 16]
    cmp  edx, 20
    jb   .no
    cmp  edx, 512
    ja   .no
    movzx ecx, word [rax + 20]
    lea  rsi, [rax + rcx]
    cmp  byte [rsi], 1
    jne  .no
    test word [rsi + 2], 0x8000
    jz   .no                            ; only self-relative existing descriptor
    mov  [rel nt_ns_security], rax
    call nt_ns_security_admit
    test eax, eax
    jnz  .no
    mov  dword [rel nt_ns_std_bytes], 72
    jmp  .profile_built
.inherited:
    cmp  byte [rel nt_ns_file], 1
    jne  .no                            ; directory inheritance not implemented
    cmp  byte [rel nt_sx_ready], 1
    jne  .no                            ; admission computed this descriptor
    lea  rdi, [rel nt_rec_buf]
    mov  esi, NT_A_STDINFO
    call nt_find_attr_any
    mov  [rel nt_ns_std], rax
    mov  edx, [rax + 24 + 52]
    cmp  edx, [rel nt_sx_parent_id]
    jne  .no                            ; staged parent names the admitted id
    lea  rax, [rel nt_sx_attr_buf]
    mov  [rel nt_ns_security], rax
    mov  dword [rel nt_ns_std_bytes], 96
.profile_built:
    lea  rdi, [rel nt_ns_stage + NT_RECBUF]
    mov  ecx, 1024
    xor  eax, eax
    rep  stosb
    lea  rbx, [rel nt_ns_stage + NT_RECBUF]
    mov  dword [rbx], 'FILE'
    mov  word [rbx + 4], 48
    mov  word [rbx + 6], 3
    mov  ax, [rel nt_ns_sequence]
    inc  ax
    mov  [rbx + 16], ax
    mov  [rel nt_ns_sequence], ax
    mov  word [rbx + 18], 1
    mov  word [rbx + 20], 56
    mov  word [rbx + 22], 3
    cmp  byte [rel nt_ns_file], 0
    je   .header_kind
    mov  word [rbx + 22], 1
.header_kind:
    mov  dword [rbx + 28], 1024
    mov  word [rbx + 40], 4
    mov  eax, [rel nt_ns_child]
    mov  [rbx + 44], eax
    mov  word [rbx + 48], 1
    mov  rsi, [rel nt_ns_std]
    lea  rdi, [rbx + 56]
    mov  edx, [rel nt_ns_std_bytes]
    call memcpy
    cmp  dword [rel nt_ns_std_bytes], 96
    jne  .std_copied
    lea  rdi, [rbx + 56 + 24 + 36]      ; class/owner/security id/quota/USN
    mov  ecx, 36
    xor  eax, eax
    rep  stosb                          ; security_id 0: explicit descriptor
.std_copied:
    mov  word [rbx + 56 + 14], 0
    call time_wall_utc_now_s            ; RCQ-20: UTC (an applied SNTP sample) or 0
    test rax, rax
    jz   .no_utc                        ; RTC-seeded (may be local) or unseeded: no stamp, no write
    mov  rcx, 0x0000000FFFFFFFFF
    cmp  rax, rcx
    ja   .no
    mov  rcx, 11644473600
    add  rax, rcx
    mov  ecx, 10000000
    imul rax, rcx
    mov  [rel nt_ns_time], rax
    mov  [rbx + 80], rax
    mov  [rbx + 88], rax
    mov  [rbx + 96], rax
    mov  [rbx + 104], rax
    mov  dword [rbx + 112], 0x10
    cmp  byte [rel nt_ns_file], 0
    je   .std_kind
    mov  dword [rbx + 112], 0x20
.std_kind:
    ; FILE_NAME, canonical resident header, exactly one Win32 name.
    mov  edi, [rel nt_ns_std_bytes]
    lea  rdi, [rbx + rdi + 56]
    mov  dword [rdi], NT_A_FILENAME
    mov  eax, [rel nt_rename_len]
    lea  eax, [rax*2 + 66]
    mov  [rel nt_ns_key_bytes], eax
    mov  [rdi + 16], eax
    add  eax, 24 + 7
    and  eax, -8
    mov  [rdi + 4], eax
    add  eax, [rel nt_ns_std_bytes]
    lea  r13d, [rax + 56]
    mov  word [rdi + 14], 1
    mov  word [rdi + 20], 24
    add  rdi, 24
    mov  rax, [rel nt_rename_parent_full]
    mov  [rdi], rax
    mov  rax, [rel nt_ns_time]
    mov  [rdi + 8], rax
    mov  [rdi + 16], rax
    mov  [rdi + 24], rax
    mov  [rdi + 32], rax
    mov  dword [rdi + 56], 0x10000010
    cmp  byte [rel nt_ns_file], 0
    je   .fn_kind
    mov  dword [rdi + 56], 0x20
    mov  eax, [rel nt_ns_length]
    mov  [rdi + 48], rax
    add  eax, 7
    and  eax, -8
    mov  [rdi + 40], rax
.fn_kind:
    mov  byte [rdi + 65], 1
    lea  rdx, [rdi - 24]
    call nt_rename_name
    mov  esi, [rel nt_ns_std_bytes]
    lea  rsi, [rbx + rsi + 80]
    lea  rdi, [rel nt_ns_key]
    mov  edx, [rel nt_ns_key_bytes]
    call memcpy
    ; v1: parent's resident descriptor byte-for-byte; v3: the admitted
    ; inherited descriptor. Either way an independent attribute ID.
    mov  rsi, [rel nt_ns_security]
    mov  edx, [rsi + 4]
    mov  eax, 88
    cmp  byte [rel nt_ns_file], 0
    je   .capacity
    mov  eax, [rel nt_ns_length]
    add  eax, 7
    and  eax, -8
    add  eax, 32                       ; DATA header + END
.capacity:
    add  eax, r13d
    add  eax, edx
    cmp  eax, 1024
    ja   .no
    lea  rdi, [rbx + r13]
    call memcpy
    mov  word [rbx + r13 + 14], 2
    mov  rsi, [rel nt_ns_security]
    add  r13d, [rsi + 4]
    lea  rdi, [rbx + r13]
    cmp  byte [rel nt_ns_file], 0
    jne  .file_data
    mov  dword [rdi], NT_A_INDEXROOT
    mov  dword [rdi + 4], 80
    mov  byte [rdi + 9], 4
    mov  word [rdi + 10], 24
    mov  word [rdi + 14], 3
    mov  dword [rdi + 16], 48
    mov  word [rdi + 20], 32
    mov  rax, 0x0030003300490024
    mov  [rdi + 24], rax
    mov  dword [rdi + 32], NT_A_FILENAME
    mov  dword [rdi + 36], 1
    mov  dword [rdi + 40], 4096
    mov  byte [rdi + 44], 1
    mov  dword [rdi + 48], 16
    mov  dword [rdi + 52], 32
    mov  dword [rdi + 56], 32
    mov  word [rdi + 72], 16
    mov  dword [rdi + 76], 2
    mov  dword [rdi + 80], -1
    lea  eax, [r13 + 88]
    jmp  .used
.file_data:
    mov  dword [rdi], NT_A_DATA
    mov  eax, [rel nt_ns_length]
    mov  [rdi + 16], eax
    add  eax, 7
    and  eax, -8
    add  eax, 24
    mov  [rdi + 4], eax
    mov  word [rdi + 14], 3
    mov  word [rdi + 20], 24
    add  r13d, eax
    mov  dword [rbx + r13], -1
    add  rdi, 24
    lea  rsi, [rel nt_ns_payload]
    mov  edx, [rel nt_ns_length]
    call memcpy
    lea  eax, [r13 + 8]
.used:
    mov  [rbx + 24], eax
    mov  rdi, rbx
    call nt_resident_encode
    xor  eax, eax
    ret
.no_utc:
    lea  rdi, [rel str_nt_no_utc]
    call serial_string
.no:
    mov  eax, -1
    ret

; Only these actual NTFS metadata names may appear as immutable siblings in
; a mutable resident root. Exact type, namespace, name and identity are checked;
; scratch mutation paths can never select either. All ordinary keys retain the
; uppercase collation domain. $Extend precedes $Secure precedes ordinary keys.
nt_root_system_key:
    cmp  word [rbx + r15 + 10], 80
    jne  .no
    cmp  word [rbx + r15 + 80], 0x0307
    jne  .no
    cmp  dword [rbx + r15], 9
    je   .secure
    cmp  dword [rbx + r15], 11
    jne  .no
    cmp  dword [rbx + r15 + 72], 0x10000006
    jne  .no
    mov  rax, 0x0074007800450024
    cmp  [rbx + r15 + 82], rax
    jne  .no
    cmp  dword [rbx + r15 + 90], 0x006E0065
    jne  .no
    cmp  word [rbx + r15 + 94], 'd'
    jne  .no
    xor  eax, eax
    ret
.secure:
    cmp  dword [rbx + r15 + 72], 0x20000006
    jne  .no
    mov  rax, 0x0063006500530024
    cmp  [rbx + r15 + 82], rax
    jne  .no
    cmp  dword [rbx + r15 + 90], 0x00720075
    jne  .no
    cmp  word [rbx + r15 + 94], 'e'
    jne  .no
    xor  eax, eax
    ret
.no:
    mov  eax, -1
    ret

; Root is mutable only in the same complete resident leaf profile. Root's
; immutable-ancestor allowance for INDEX_ALLOCATION/nonresident security must
; never become authority to mutate that layout. Generic bounds came from
; nt_dir_admit; this second pass narrows the mutable root before slot staging.
nt_ns_root_admit:
    push rbx
    push r15
    lea  rbx, [rel nt_rec_buf]
    movzx r8d, word [rbx + 20]
.attrs:
    mov  eax, [rbx + r8]
    cmp  eax, -1
    je   .leaf
    cmp  byte [rbx + r8 + 8], 0
    jne  .no
    cmp  word [rbx + r8 + 12], 0
    jne  .no
    cmp  eax, NT_A_INDEXROOT
    je   .named_index
    cmp  byte [rbx + r8 + 9], 0
    jne  .no
.named_index:
    cmp  eax, NT_A_STDINFO
    je   .std
    cmp  eax, NT_A_FILENAME
    je   .fn
    cmp  eax, 0x50
    je   .next
    cmp  eax, NT_A_INDEXROOT
    jne  .no
    jmp  .next
.std:
    movzx edx, word [rbx + r8 + 20]
    add  edx, r8d
    test dword [rbx + rdx + 32], 0x4E07
    jnz  .no
    jmp  .next
.fn:
    movzx edx, word [rbx + r8 + 20]
    add  edx, r8d
    test dword [rbx + rdx + 56], 0x4E07
    jnz  .no
.next:
    add  r8d, [rbx + r8 + 4]
    jmp  .attrs
.leaf:
    call nt_ns_index
    mov  r15d, eax
    mov  edx, [rel nt_ns_index_header]
    cmp  dword [rbx + rdx + 12], 0
    jne  .no
    cmp  dword [rbx + rdx], 16
    jne  .no
    mov  ecx, [rbx + rdx + 4]
    cmp  ecx, [rbx + rdx + 8]
    jne  .no
    mov  eax, [rel nt_ns_index_attr]
    mov  eax, [rbx + rax + 16]
    sub  eax, 16
    cmp  ecx, eax
    jne  .no
    mov  rax, [rel nt_rename_parent_full]
    mov  [rel nt_res_parent_ref], rax
    mov  byte [rel nt_dir_leaf], 1
    call nt_rename_leaf
    mov  byte [rel nt_dir_leaf], 0
    test rax, rax
    jnz  .no
    xor  eax, eax
    jmp  .out
.no:
    mov  rax, -1
.out:
    pop  r15
    pop  rbx
    ret

; RDX=actual full file ref; nt_rec_buf=logical FILE. Generic complete attribute
; bounds first, then unique plain STDINFO/FN/[security]/DATA. Resident delete
; uses its complete in-record attribute span. Nonresident admits four plain
; allocated clusters; nt_nd_prepare independently proves exclusive ownership.
; Refuse all hardlink, alias, named-stream, protected and unsupported profiles.
nt_ns_file_admit:
    push rbx
    push r12
    mov  r12, rdx
    lea  rdi, [rel nt_rec_buf]
    lea  rsi, [rdi + 1024]
    call nt_data_attr_admit
    test rax, rax
    jz   .no
    cmp  byte [rax + 8], 0
    jne  .nonresident
    ; The complete resident value is already bounded by its attribute
    ; inside this FILE. DELETE consumes no CREATE payload buffer.
    mov  edx, [rax + 16]
    mov  [rel nt_ns_length], edx
    add  edx, 7
    and  edx, -8
    mov  [rel nt_nd_allocated], edx
    jmp  .identity
.nonresident:
    cmp  word [rax + 12], 0
    jne  .no
    cmp  word [rax + 34], 0
    jne  .no
    cmp  dword [rax + 36], 0
    jne  .no
    mov  rdx, [rax + 40]
    test rdx, rdx
    jz   .no
    cmp  rdx, NT_NR_CAP
    ja   .no
    mov  [rel nt_nd_allocated], edx
    shr  edx, 9
    mov  [rel nt_nr_sectors], edx
    mov  rdx, [rax + 48]
    mov  [rel nt_ns_length], edx
    call nt_rename_runs_plain           ; no holes, duplicate extents or system DATA
    test eax, eax
    jnz  .no
    xor  ebx, ebx
.map:
    lea  rdi, [rel nt_runs]
    mov  esi, [rel nt_nruns]
    mov  edx, ebx
    shl  edx, 9
    call nt_vcn_to_lba
    cmp  rax, -2
    jae  .no
    test rcx, rcx
    jnz  .no
    cmp  rdx, 512
    jb   .no
    lea  rdi, [rel nt_nr_lbas]
    mov  [rdi + rbx*8], rax
    inc  ebx
    cmp  ebx, [rel nt_nr_sectors]
    jb   .map
    mov  byte [rel nt_nd_mode], 1
.identity:
    lea  rbx, [rel nt_rec_buf]
    cmp  [rbx + 44], r12d
    jne  .no
    shr  r12, 48
    test r12w, r12w
    jz   .no
    cmp  [rbx + 16], r12w
    jne  .no
    cmp  word [rbx + 18], 1
    jne  .no
    movzx r8d, word [rbx + 20]
    xor  r9d, r9d
    xor  r11d, r11d
.attrs:
    mov  eax, [rbx + r8]
    cmp  eax, -1
    je   .end
    cmp  eax, r9d
    jbe  .no                            ; no repeated FILE_NAME/streams
    mov  r9d, eax
    cmp  eax, NT_A_DATA
    je   .data
    cmp  byte [rbx + r8 + 8], 0
    jne  .no
    cmp  byte [rbx + r8 + 9], 0
    jne  .no
    cmp  word [rbx + r8 + 12], 0
    jne  .no
    movzx edx, word [rbx + r8 + 20]
    add  edx, r8d
    cmp  eax, NT_A_STDINFO
    je   .std
    cmp  eax, NT_A_FILENAME
    je   .fn
    cmp  eax, 0x50
    je   .next
    jmp  .no
.data:
    ; The complete unnamed DATA was already admitted above. Do not read a
    ; nonresident header as a resident value (offset22 is part of LowestVcn).
    cmp  byte [rel nt_nd_mode], 0
    jne  .data_ok
    cmp  byte [rbx + r8 + 22], 0
    jne  .no
.data_ok:
    or   r11d, 4
    jmp  .next
.std:
    cmp  dword [rbx + r8 + 16], 36
    jb   .no
    test dword [rbx + rdx + 32], 0x4E17
    jnz  .no
    or   r11d, 1
    jmp  .next
.fn:
    cmp  dword [rbx + r8 + 16], 68
    jb   .no
    test dword [rbx + rdx + 56], 0x4E17
    jnz  .no
    cmp  byte [rbx + rdx + 65], 1
    jne  .no
    movzx eax, byte [rbx + rdx + 64]
    cmp  eax, [rel nt_rename_len]
    jne  .no
    lea  eax, [rax*2 + 66]
    cmp  [rbx + r8 + 16], eax
    jne  .no
    mov  [rel nt_res_fn_len], eax
    mov  [rel nt_res_fn], edx
    mov  ecx, [rel nt_ns_length]
    cmp  [rbx + rdx + 48], rcx
    jne  .no
    mov  ecx, [rel nt_nd_allocated]
    cmp  [rbx + rdx + 40], rcx
    jne  .no
    or   r11d, 2
.next:
    add  r8d, [rbx + r8 + 4]
    jmp  .attrs
.end:
    cmp  r11d, 7
    jne  .no
    add  r8d, 8
    cmp  r8d, [rbx + 24]
    jne  .no
    xor  eax, eax
    jmp  .out
.no:
    mov  rax, -1
.out:
    pop  r12
    pop  rbx
    ret

; RSI=self-relative descriptor, EDX=value length. Finite explicit descriptor
; copy: bounded owner/group SIDs and a plain allow/deny DACL, no SACL. No ACL
; inheritance engine or security-id/quota allocation is claimed by this profile.
nt_ns_security_admit:
    mov  r8, rsi
    mov  r9d, edx
    cmp  dword [r8 + 12], 0
    jne  .no                            ; no audit ACL custody in this profile
    test word [r8 + 2], 0x0010
    jnz  .no
    mov  r10d, 4
.sid:
    mov  eax, [r8 + r10]
    test eax, eax
    jz   .sid_next
    cmp  eax, 20
    jb   .no
    cmp  eax, r9d
    jae  .no                            ; bound BEFORE the 32-bit offset addition
    test eax, 3
    jnz  .no
    lea  ecx, [rax + 8]
    cmp  ecx, r9d
    ja   .no
    cmp  byte [r8 + rax], 1
    jne  .no
    movzx edx, byte [r8 + rax + 1]
    cmp  edx, 15
    ja   .no
    lea  ecx, [rcx + rdx*4]
    cmp  ecx, r9d
    ja   .no
.sid_next:
    add  r10d, 4
    cmp  r10d, 8
    jbe  .sid
    mov  eax, [r8 + 16]
    test eax, eax
    jz   .yes                           ; existing null/absent DACL copied exactly
    test word [r8 + 2], 4
    jz   .no
    cmp  eax, 20
    jb   .no
    cmp  eax, r9d
    jae  .no                            ; bound BEFORE the 32-bit offset addition
    test eax, 3
    jnz  .no
    lea  ecx, [rax + 8]
    cmp  ecx, r9d
    ja   .no
    lea  rsi, [r8 + rax]
    cmp  byte [rsi], 2
    jne  .no
    cmp  byte [rsi + 1], 0
    jne  .no
    cmp  word [rsi + 6], 0
    jne  .no
    movzx edx, word [rsi + 2]
    cmp  edx, 8
    jb   .no
    add  eax, edx
    cmp  eax, r9d
    ja   .no
    lea  r11, [r8 + rax]
    movzx r10d, word [rsi + 4]
    add  rsi, 8
.ace:
    test r10d, r10d
    jz   .ace_end
    lea  rax, [rsi + 16]
    cmp  rax, r11
    ja   .no
    cmp  byte [rsi], 1
    ja   .no                            ; ordinary ACCESS_ALLOWED/DENIED only
    test byte [rsi + 1], 0xE0
    jnz  .no
    cmp  byte [rsi + 8], 1
    jne  .no
    movzx ecx, byte [rsi + 9]
    cmp  ecx, 15
    ja   .no
    lea  ecx, [rcx*4 + 16]
    cmp  [rsi + 2], cx
    jne  .no
    add  rsi, rcx
    cmp  rsi, r11
    ja   .no
    dec  r10d
    jmp  .ace
.ace_end:
    cmp  rsi, r11
    jne  .no
.yes:
    xor  eax, eax
    ret
.no:
    mov  eax, -1
    ret

; ---------------------------------------------------------------------------
; NTFS 3.x inherited security for file CREATE. Read-only $Secure: a parent
; with a 72-byte STANDARD_INFORMATION names its descriptor by a nonzero
; security_id. Resolve it through the complete $SII view index (every in-use
; node, unique key, data id equal to key) and the $SDS entry header and hash.
; Compute the MS-DTYP file inheritance of its DACL into an explicit resident
; descriptor for the new FILE, whose v3 STDINFO keeps security_id 0 (the
; long-standing ntfs-3g form). $Secure/$SDH/$SII/$SDS are never written.
; ---------------------------------------------------------------------------
NT_SX_PARENT_MAX equ 4096
NT_SX_SD_MAX     equ 512
NT_SX_SII        equ 0x0049004900530024     ; UTF16 "$SII"
NT_SX_SDS        equ 0x0053004400530024     ; UTF16 "$SDS"
NT_SX_CREATOR    equ 0x0300000000000101     ; S-1-3-x prefix (one subauthority)
NT_SX_ADMIN0     equ 0x0500000000000201     ; S-1-5-32-544 (BUILTIN\Administrators)
NT_SX_ADMIN1     equ 0x0000022000000020

; RDI=FILE, RSI=actual end -> RAX 0/-1. In-use view-index FILE (not a
; directory); the remaining complete attribute bounds are the directory
; validator's own.
nt_sx_record_valid:
    mov  r8, rsi
    sub  r8, rdi
    cmp  r8, 48
    jb   .bad
    cmp  dword [rdi], 'FILE'
    jne  .bad
    cmp  word [rdi + 22], 9
    jne  .bad
    jmp  nt_dir_record_valid.flags_ok
.bad:
    mov  rax, -1
    ret

; RDI=validated FILE, ESI=type, RDX=UTF16 4-character name -> RAX unique
; plain attribute/0, RDX 0/-1 (duplicate or flagged).
nt_sx_attr:
    mov  r9, rdx
    xor  r10d, r10d
    movzx eax, word [rdi + 20]
    lea  rcx, [rdi + rax]
.loop:
    cmp  dword [rcx], -1
    je   .done
    cmp  [rcx], esi
    jne  .next
    cmp  byte [rcx + 9], 4
    jne  .next
    movzx eax, word [rcx + 10]
    cmp  [rcx + rax], r9
    jne  .next
    test r10, r10
    jnz  .bad
    cmp  word [rcx + 12], 0
    jne  .bad
    mov  r10, rcx
.next:
    mov  eax, [rcx + 4]
    add  rcx, rax
    jmp  .loop
.done:
    mov  rax, r10
    xor  edx, edx
    ret
.bad:
    xor  eax, eax
    mov  rdx, -1
    ret

; RDI=$SII node header, RSI=actual node end -> RAX 0/-1. Every entry has the
; exact ULONG key/20-byte data shape and a terminal END; nt_sx_id may match
; at most once across the whole index.
nt_sx_visit:
    mov  rax, rsi
    sub  rax, rdi
    cmp  rax, 16
    jb   .bad
    mov  ecx, [rdi + 8]                   ; allocated node extent
    cmp  rcx, rax
    ja   .bad
    mov  edx, [rdi + 4]                   ; used node extent
    cmp  edx, ecx
    ja   .bad
    mov  eax, [rdi]
    cmp  eax, 16
    jb   .bad
    test al, 7
    jnz  .bad
    cmp  eax, edx
    jae  .bad
    lea  r10, [rdi + rdx]
    add  rdi, rax
.entry:
    lea  rax, [rdi + 16]
    cmp  r10, rax                         ; header within the used node
    jb   .bad
    movzx ecx, word [rdi + 8]
    movzx edx, word [rdi + 12]
    test edx, ~3
    jnz  .bad
    lea  rax, [rdi + rcx]
    cmp  r10, rax                         ; whole entry within the used node
    jb   .bad
    mov  r11d, 16
    test edx, 1
    jz   .shape
    mov  r11d, 24                         ; trailing child VCN
.shape:
    test edx, 2
    jnz  .last
    add  r11d, 24                         ; ULONG key + {hash,id,offset,length}
    cmp  ecx, r11d
    jne  .bad
    cmp  word [rdi + 10], 4
    jne  .bad
    cmp  word [rdi], 20
    jne  .bad
    cmp  word [rdi + 2], 20
    jne  .bad
    mov  eax, [rdi + 16]
    cmp  eax, [rdi + 24]
    jne  .bad                             ; data security_id is its key
    cmp  eax, [rel nt_sx_id]
    jne  .next
    cmp  byte [rel nt_sx_found], 0
    jne  .bad                             ; duplicate key is ambiguous
    mov  byte [rel nt_sx_found], 1
    mov  eax, [rdi + 20]
    mov  [rel nt_sx_hash], eax
    mov  rax, [rdi + 28]
    mov  [rel nt_sx_offset], rax
    mov  eax, [rdi + 36]
    mov  [rel nt_sx_length], eax
.next:
    add  rdi, rcx
    jmp  .entry
.last:
    cmp  ecx, r11d
    jne  .bad
    cmp  word [rdi + 10], 0
    jne  .bad
    cmp  word [rdi + 2], 0
    jne  .bad
    xor  eax, eax
    ret
.bad:
    mov  rax, -1
    ret

; EDI=security_id -> RAX 0 with the parent descriptor at nt_sx_entry+20
; (nt_sx_parent_len bytes), else -1. Reads only; no write grant is touched.
nt_sx_lookup:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  [rel nt_sx_id], edi
    mov  byte [rel nt_sx_found], 0
    mov  edi, 9                           ; $Secure is FILE 9 on NTFS 3.x
    call nt_read_record
    test rax, rax
    jnz  .bad
    cmp  dword [rel nt_rec_buf + 44], 9
    jne  .bad
    lea  rdi, [rel nt_rec_buf]
    mov  esi, [rel nt_rec_bytes]
    add  rsi, rdi
    call nt_sx_record_valid
    test rax, rax
    jnz  .bad
    lea  rdi, [rel nt_rec_buf]
    mov  esi, NT_A_INDEXROOT
    mov  rdx, NT_SX_SII
    call nt_sx_attr
    test rdx, rdx
    jnz  .bad
    test rax, rax
    jz   .bad
    cmp  byte [rax + 8], 0
    jne  .bad
    mov  ecx, [rax + 16]
    cmp  ecx, 32
    jb   .bad
    movzx edx, word [rax + 20]
    lea  r12, [rax + rdx]                 ; root value, validator-bounded
    lea  r15, [r12 + rcx]
    cmp  dword [r12], 0                   ; view index: no indexed attribute
    jne  .bad
    cmp  dword [r12 + 4], 0x10            ; COLLATION_NTOFS_ULONG
    jne  .bad
    mov  eax, [rel nt_idx_bytes]
    test eax, eax
    jz   .bad
    cmp  [r12 + 8], eax
    jne  .bad
    mov  dword [rel nt_dir_blocks], 0
    mov  dword [rel nt_dirbm_bits], 0
    lea  rdi, [rel nt_rec_buf]
    mov  esi, NT_A_BITMAP
    mov  rdx, NT_SX_SII
    call nt_sx_attr
    test rdx, rdx
    jnz  .bad
    test rax, rax
    jz   .allocation
    cmp  byte [rax + 8], 0
    jne  .bad                             ; nonresident index bitmap unsupported
    mov  ecx, [rax + 16]
    test ecx, ecx
    jz   .bad
    cmp  ecx, NT_DIRBM
    ja   .bad
    movzx edx, word [rax + 20]
    lea  rsi, [rax + rdx]
    lea  rdi, [rel nt_dirbm]
    mov  eax, ecx
    shl  eax, 3
    mov  [rel nt_dirbm_bits], eax
    rep  movsb
.allocation:
    lea  rdi, [rel nt_rec_buf]
    mov  esi, NT_A_INDEXALLOC
    mov  rdx, NT_SX_SII
    call nt_sx_attr
    test rdx, rdx
    jnz  .bad
    test rax, rax
    jnz  .large
    cmp  dword [rel nt_dirbm_bits], 0
    jne  .bad
    cmp  dword [r12 + 28], 0              ; root must be a leaf
    jne  .bad
    jmp  .root
.large:
    mov  rbx, rax
    cmp  byte [rbx + 8], 1
    jne  .bad
    cmp  dword [r12 + 28], 1
    jne  .bad
    cmp  qword [rbx + 16], 0              ; no extension VCN
    jne  .bad
    cmp  word [rbx + 34], 0
    jne  .bad
    mov  r13, [rbx + 48]
    test r13, r13
    jz   .bad
    cmp  r13, [rbx + 40]
    ja   .bad
    cmp  r13, [rbx + 56]
    jne  .bad                             ; uninitialized index is unknown
    mov  rax, r13
    xor  edx, edx
    mov  ecx, [rel nt_idx_bytes]
    div  rcx
    test rdx, rdx
    jnz  .bad
    cmp  rax, 4096
    ja   .bad
    cmp  eax, [rel nt_dirbm_bits]
    ja   .bad                             ; coverage cannot prove absence
    mov  [rel nt_dir_blocks], eax
    mov  ecx, eax
.bm_tail:
    cmp  ecx, [rel nt_dirbm_bits]
    jae  .decode
    lea  rdx, [rel nt_dirbm]
    bt   [rdx], ecx
    jc   .bad
    inc  ecx
    jmp  .bm_tail
.decode:
    movzx ecx, word [rbx + 32]
    lea  rdi, [rbx + rcx]
    mov  ecx, [rbx + 4]
    lea  rcx, [rbx + rcx]
    lea  rsi, [rel nt_runs]
    mov  edx, NT_MAX_RUNS
    call nt_decode_runlist
    test eax, eax
    jle  .bad
    mov  [rel nt_nruns], eax
    mov  rax, [rbx + 40]
    xor  edx, edx
    mov  ecx, [rel nt_clus_bytes]
    div  rcx
    test rdx, rdx
    jnz  .bad
    mov  r8, rax
    mov  rdx, [rbx + 24]
    inc  rdx
    jz   .bad
    cmp  rax, rdx
    jne  .bad
    lea  rdi, [rel nt_runs]
    mov  ecx, [rel nt_nruns]
.run_coverage:
    cmp  qword [rdi], 0
    jl   .bad                             ; no sparse/negative physical run
    mov  rax, [rdi + 8]
    cmp  rax, r8
    ja   .bad
    sub  r8, rax
    add  rdi, 16
    dec  ecx
    jnz  .run_coverage
    test r8, r8
    jnz  .bad
.root:
    lea  rdi, [r12 + 16]
    mov  rsi, r15
    call nt_sx_visit
    test rax, rax
    jnz  .bad
    xor  r14d, r14d
.block:
    cmp  r14d, [rel nt_dir_blocks]
    jae  .indexed
    lea  rdx, [rel nt_dirbm]
    bt   [rdx], r14d
    jnc  .block_next
    mov  eax, [rel nt_idx_bytes]
    imul rax, r14
    mov  rdx, rax
    lea  rdi, [rel nt_runs]
    mov  esi, [rel nt_nruns]
    lea  rcx, [rel nt_idx_buf]
    mov  r8d, [rel nt_idx_bytes]
    call nt_read_stream_record
    test rax, rax
    jnz  .bad
    cmp  dword [rel nt_idx_buf], 'INDX'
    jne  .bad
    mov  eax, [rel nt_idx_bytes]
    shr  eax, 9
    inc  eax
    cmp  [rel nt_idx_buf + 6], ax
    jne  .bad
    movzx ecx, word [rel nt_idx_buf + 4]
    cmp  ecx, 40
    jb   .bad
    lea  ecx, [rcx + rax*2]
    mov  eax, [rel nt_idx_buf + 24]
    add  eax, 24
    cmp  ecx, eax
    ja   .bad
    cmp  ecx, [rel nt_idx_bytes]
    ja   .bad
    mov  eax, [rel nt_idx_bytes]
    imul rax, r14
    mov  ecx, [rel nt_clus_bytes]
    cmp  ecx, [rel nt_idx_bytes]
    jbe  .vcn_unit
    mov  ecx, 512
.vcn_unit:
    xor  edx, edx
    div  rcx
    cmp  rax, [rel nt_idx_buf + 16]
    jne  .bad
    lea  rdi, [rel nt_idx_buf]
    call nt_fixup
    test rax, rax
    jnz  .bad
    lea  rdi, [rel nt_idx_buf + 24]
    lea  rsi, [rel nt_idx_buf]
    mov  eax, [rel nt_idx_bytes]
    add  rsi, rax
    call nt_sx_visit
    test rax, rax
    jnz  .bad
.block_next:
    inc  r14d
    jmp  .block
.indexed:
    cmp  byte [rel nt_sx_found], 1
    jne  .bad                             ; absent id: no descriptor to inherit
    mov  r13d, [rel nt_sx_length]
    cmp  r13d, 40
    jb   .bad
    cmp  r13d, 20 + NT_SX_PARENT_MAX
    ja   .bad
    test r13d, 3
    jnz  .bad
    mov  rax, NT_SX_SDS
    mov  [rel nt_data_stream], rax
    mov  rdx, [rel nt_sx_offset]
    lea  rcx, [rel nt_sx_entry]
    mov  r8, r13
    call nt_data_read_at
    mov  qword [rel nt_data_stream], 0
    cmp  rax, r13
    jne  .bad
    lea  rsi, [rel nt_sx_entry]
    mov  eax, [rel nt_sx_hash]
    cmp  [rsi], eax
    jne  .bad
    mov  eax, [rel nt_sx_id]
    cmp  [rsi + 4], eax
    jne  .bad
    mov  rax, [rel nt_sx_offset]
    cmp  [rsi + 8], rax
    jne  .bad
    cmp  [rsi + 16], r13d
    jne  .bad
    ; NTFS descriptor hash: h = dword + rol(h, 3) over every descriptor dword.
    lea  ecx, [r13 - 20]
    shr  ecx, 2
    add  rsi, 20
    xor  eax, eax
.hash:
    rol  eax, 3
    add  eax, [rsi]
    add  rsi, 4
    dec  ecx
    jnz  .hash
    cmp  eax, [rel nt_sx_hash]
    jne  .bad
    lea  eax, [r13 - 20]
    mov  [rel nt_sx_parent_len], eax
    xor  eax, eax
    jmp  .out
.bad:
    mov  qword [rel nt_data_stream], 0
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; RSI=parent descriptor, EDX=bytes -> EAX 0/-1. MS-DTYP file inheritance:
; each ACCESS_ALLOWED/DENIED ACE with OBJECT_INHERIT is copied with file
; generic rights mapped and propagation flags cleared; CREATOR OWNER/GROUP
; become the new owner/group (BUILTIN\Administrators). As Windows does, only a
; parent with SE_DACL_AUTO_INHERITED gives INHERITED_ACE and the child the same
; control bit (a pre-Windows-2000 parent DACL is copied plainly). No SACL. No OI ACE
; (the creator's default DACL), SACLs and other ACE types are unsupported.
; Output: nt_sx_attr_buf, a complete resident $SECURITY_DESCRIPTOR attribute.
nt_sx_inherit:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r8, rsi
    mov  r9d, edx
    lea  rdi, [rel nt_sx_attr_buf]
    mov  ecx, 24 + NT_SX_SD_MAX
    xor  eax, eax
    rep  stosb
    cmp  r9d, 20
    jb   .no
    cmp  word [r8], 1                     ; revision 1, Sbz1 0
    jne  .no
    movzx eax, word [r8 + 2]
    test eax, 0x8000
    jz   .no                              ; self-relative
    test eax, 0x4010
    jnz  .no                              ; no SACL or resource-manager control
    test eax, 4
    jz   .no
    cmp  dword [r8 + 12], 0
    jne  .no
    mov  eax, [r8 + 16]
    test eax, eax
    jz   .no                              ; NULL DACL
    cmp  eax, 20
    jb   .no
    cmp  eax, r9d
    jae  .no
    test eax, 3
    jnz  .no
    lea  ecx, [rax + 8]
    cmp  ecx, r9d
    ja   .no
    lea  r12, [r8 + rax]
    cmp  byte [r12], 2
    jne  .no
    cmp  byte [r12 + 1], 0
    jne  .no
    cmp  word [r12 + 6], 0
    jne  .no
    movzx edx, word [r12 + 2]
    cmp  edx, 8
    jb   .no
    add  eax, edx
    cmp  eax, r9d
    ja   .no
    lea  r13, [r12 + rdx]                 ; DACL end
    movzx r14d, word [r12 + 4]
    add  r12, 8
    lea  rdi, [rel nt_sx_attr_buf + 24 + 28]
    lea  rbx, [rel nt_sx_attr_buf + 24 + NT_SX_SD_MAX - 32]
    xor  r15d, r15d
.ace:
    test r14d, r14d
    jz   .aces_done
    lea  rax, [r12 + 16]
    cmp  rax, r13
    ja   .no
    cmp  byte [r12], 1
    ja   .no                              ; ordinary ACCESS_ALLOWED/DENIED only
    test byte [r12 + 1], 0xE0
    jnz  .no
    cmp  byte [r12 + 8], 1
    jne  .no
    movzx ecx, byte [r12 + 9]
    cmp  ecx, 15
    ja   .no
    lea  ecx, [rcx*4 + 16]
    cmp  [r12 + 2], cx
    jne  .no
    lea  rax, [r12 + rcx]
    cmp  rax, r13
    ja   .no
    test byte [r12 + 1], 1                ; OBJECT_INHERIT reaches files
    jz   .ace_next
    lea  rax, [rdi + rcx + 8]             ; creator substitution grows by 4
    cmp  rax, rbx
    ja   .no
    mov  al, [r12]
    mov  [rdi], al
    movzx eax, word [r8 + 2]
    shr  eax, 6
    and  eax, 0x10                        ; SE_DACL_AUTO_INHERITED -> INHERITED_ACE
    mov  [rdi + 1], al                    ; propagation cleared
    mov  eax, [r12 + 4]
    mov  edx, eax
    and  edx, 0x0FFFFFFF
    test eax, 0x80000000
    jz   .no_read
    or   edx, 0x120089                    ; FILE_GENERIC_READ
.no_read:
    test eax, 0x40000000
    jz   .no_write
    or   edx, 0x120116                    ; FILE_GENERIC_WRITE
.no_write:
    test eax, 0x20000000
    jz   .no_execute
    or   edx, 0x1200A0                    ; FILE_GENERIC_EXECUTE
.no_execute:
    test eax, 0x10000000
    jz   .mapped
    or   edx, 0x1F01FF                    ; FILE_ALL_ACCESS
.mapped:
    mov  [rdi + 4], edx
    cmp  ecx, 20
    jne  .copy_sid
    mov  rax, NT_SX_CREATOR
    cmp  [r12 + 8], rax
    jne  .copy_sid
    cmp  dword [r12 + 16], 1
    ja   .copy_sid                        ; S-1-3-0 owner, S-1-3-1 group
    mov  rax, NT_SX_ADMIN0
    mov  [rdi + 8], rax
    mov  rax, NT_SX_ADMIN1
    mov  [rdi + 16], rax
    mov  word [rdi + 2], 24
    add  rdi, 24
    jmp  .ace_out
.copy_sid:
    mov  [rdi + 2], cx
    push rcx
    push rdi
    lea  rsi, [r12 + 8]
    add  rdi, 8
    sub  ecx, 8
    rep  movsb
    pop  rdi
    pop  rcx
    add  rdi, rcx
.ace_out:
    inc  r15d
.ace_next:
    add  r12, rcx
    dec  r14d
    jmp  .ace
.aces_done:
    cmp  r12, r13
    jne  .no                              ; exact ACL extent
    test r15d, r15d
    jz   .no                              ; Windows would use the creator default DACL
    lea  rbx, [rel nt_sx_attr_buf + 24]
    mov  rax, rdi
    sub  rax, rbx                         ; descriptor bytes before owner
    lea  ecx, [rax - 20]
    mov  byte [rbx + 20], 2
    mov  [rbx + 22], cx
    mov  [rbx + 24], r15w
    mov  rdx, NT_SX_ADMIN0
    mov  [rdi], rdx
    mov  [rdi + 16], rdx
    mov  rdx, NT_SX_ADMIN1
    mov  [rdi + 8], rdx
    mov  [rdi + 24], rdx
    mov  byte [rbx], 1
    movzx edx, word [r8 + 2]
    and  edx, 0x0400
    or   edx, 0x8004
    mov  [rbx + 2], dx                    ; self-relative, parent's DACL auto-inherit
    mov  [rbx + 4], eax                   ; owner
    lea  edx, [rax + 16]
    mov  [rbx + 8], edx                   ; group
    mov  dword [rbx + 16], 20             ; DACL
    add  eax, 32
    lea  rbx, [rel nt_sx_attr_buf]
    mov  dword [rbx], 0x50
    mov  [rbx + 16], eax
    add  eax, 24 + 7
    and  eax, -8
    mov  [rbx + 4], eax
    mov  word [rbx + 20], 24
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

; Parent FILE in nt_rec_buf after nt_ns_create_profile -> EAX 0/-1. v1 has
; nothing to resolve. v3 resolves the descriptor, validates it with the
; existing descriptor admission, and admits the inherited result likewise.
nt_sx_prepare:
    mov  byte [rel nt_sx_ready], 0
    cmp  byte [rel nt_ns_profile], 3
    jne  .ok
    lea  rdi, [rel nt_rec_buf]
    mov  esi, NT_A_STDINFO
    call nt_find_attr_any
    test rax, rax
    jz   .no
    mov  edi, [rax + 24 + 52]
    test edi, edi
    jz   .no
    mov  [rel nt_sx_parent_id], edi
    call nt_sx_lookup
    test rax, rax
    jnz  .no
    lea  rsi, [rel nt_sx_entry + 20]
    mov  edx, [rel nt_sx_parent_len]
    call nt_ns_security_admit             ; complete parent descriptor bounds
    test eax, eax
    jnz  .no
    lea  rsi, [rel nt_sx_entry + 20]
    mov  edx, [rel nt_sx_parent_len]
    call nt_sx_inherit
    test eax, eax
    jnz  .no
    lea  rsi, [rel nt_sx_attr_buf + 24]
    mov  edx, [rel nt_sx_attr_buf + 16]
    call nt_ns_security_admit             ; and the constructed descriptor
    test eax, eax
    jnz  .no
    mov  byte [rel nt_sx_ready], 1
.ok:
    xor  eax, eax
    ret
.no:
    mov  eax, -1
    ret

; Parent already wholly admitted. Independently find insertion/removal point;
; preserve all sibling, attribute slack, END and cache bytes.
nt_ns_parent_stage:
    push rbx
    lea  rdi, [rel nt_rec_buf]
    lea  rsi, [rel nt_ns_stage]
    mov  edx, 1024
    call memcpy
    call nt_ns_index
    mov  r14d, eax
    lea  rbx, [rel nt_ns_stage]
    mov  dword [rel nt_ns_position], 0
.loop:
    cmp  dword [rbx + r14 + 12], 2
    je   .end
    mov  rax, [rbx + r14]
    shl  rax, 16
    shr  rax, 16
    cmp  eax, [rel nt_ns_records]
    jae  .no
    lea  rdi, [rel nt_ns_expected + 2*NT_RECBUF]
    bt   [rdi], eax
    jnc  .no                            ; all original sibling keys are allocated
    mov  edi, eax
    call nt_read_record                 ; allocated sibling's real current identity
    test rax, rax
    jnz  .io
    mov  eax, [rbx + r14]
    cmp  [rel nt_rec_buf + 44], eax
    jne  .no
    mov  rax, [rbx + r14]
    shr  rax, 48
    cmp  [rel nt_rec_buf + 16], ax
    jne  .no                            ; stale siblings never survive publication
    lea  rsi, [rbx + r14 + 16]
    lea  rdi, [rel nt_ns_key]
    call nt_rename_compare
    test eax, eax
    jz   .equal
    jl   .next
    cmp  dword [rel nt_ns_position], 0
    jne  .next
    mov  [rel nt_ns_position], r14d
    jmp  .next
.equal:
    cmp  dword [rel nt_ns_op], FS_MUT_MKDIR
    je   .no                            ; actual complete index collision
    movzx eax, word [rel nt_ns_sequence]
    shl  rax, 48
    mov  edx, [rel nt_ns_child]
    or   rax, rdx
    cmp  [rbx + r14], rax
    jne  .no                            ; stale key never removes a new identity
    movzx edx, word [rbx + r14 + 10]
    cmp  edx, [rel nt_ns_key_bytes]
    jne  .no
    lea  rdi, [rbx + r14 + 80]
    lea  rsi, [rel nt_ns_key + 64]
    sub  edx, 64
    call memcmp
    test rax, rax
    jnz  .no
    mov  [rel nt_ns_position], r14d
    jmp  .next
.next:
    movzx eax, word [rbx + r14 + 8]
    add  r14d, eax
    jmp  .loop
.end:
    cmp  dword [rel nt_ns_op], FS_MUT_RMDIR
    je   .remove
    cmp  dword [rel nt_ns_position], 0
    jne  .insert
    mov  [rel nt_ns_position], r14d
.insert:
    mov  eax, [rel nt_ns_key_bytes]
    add  eax, 16 + 7
    and  eax, -8
    mov  [rel nt_ns_delta], eax
    add  eax, [rbx + 24]
    cmp  eax, 1024
    ja   .no
    mov  rdi, rbx
    mov  esi, [rel nt_ns_position]
    mov  ecx, [rbx + 24]
    mov  edx, [rel nt_ns_delta]
    call nt_rename_shift
    mov  eax, [rel nt_ns_position]
    lea  rdi, [rbx + rax]
    mov  ecx, [rel nt_ns_delta]
    xor  eax, eax
    rep  stosb
    mov  eax, [rel nt_ns_position]
    lea  rdi, [rbx + rax]
    movzx eax, word [rel nt_ns_sequence]
    shl  rax, 48
    mov  edx, [rel nt_ns_child]
    or   rax, rdx
    mov  [rdi], rax
    mov  eax, [rel nt_ns_delta]
    mov  [rdi + 8], ax
    mov  eax, [rel nt_ns_key_bytes]
    mov  [rdi + 10], ax
    add  rdi, 16
    lea  rsi, [rel nt_ns_key]
    mov  edx, eax
    call memcpy
    jmp  .lengths
.remove:
    mov  esi, [rel nt_ns_position]
    test esi, esi
    jz   .no
    movzx edx, word [rbx + rsi + 8]
    add  esi, edx
    neg  edx
    mov  [rel nt_ns_delta], edx
    mov  rdi, rbx
    mov  ecx, [rbx + 24]
    call nt_rename_shift
.lengths:
    mov  rdi, rbx
    mov  edx, [rel nt_ns_delta]
    mov  r8d, [rel nt_ns_index_header]
    mov  r9d, [rel nt_ns_index_attr]
    call nt_cross_lengths
    call nt_resident_encode
    xor  eax, eax
    pop  rbx
    ret
.io:
    mov  eax, -2
    pop  rbx
    ret
.no:
    mov  eax, -1
    pop  rbx
    ret

; Disjoint mutable/immutable storage, actual volume allocation for every slot,
; the COMPLETE MFT allocation, and every ancestor. No DATA clusters allocated.
nt_ns_mapping:
    push rbp
    push rbx
    push r12
    push r13
    mov  rax, [rel nt_total_sectors]
    xor  edx, edx
    mov  ecx, [rel nt_spc]
    div  rcx
    cmp  [rel nt_boot_buf + 56], rax
    jae  .no                            ; validate mirror LCN before multiplication
    xor  ebx, ebx
.outer:
    call nt_ns_wskip
    je   .next                          ; windows audited in nt_ns_windows
    lea  rdi, [rel nt_ns_lbas]
    mov  rsi, [rdi + rbx*8]
    lea  rdi, [rel nt_ns_sectors]
    mov  edx, [rdi + rbx*4]
    call nt_lba_in_volume
    jc   .no
    call nt_ns_volume_range
    test eax, eax
    jnz  .no
    lea  rdi, [rel nt_ns_lbas]
    mov  r12, [rdi + rbx*8]
    lea  rdi, [rel nt_ns_sectors]
    mov  r13d, [rdi + rbx*4]
    add  r13, r12
    lea  ebp, [rbx + 1]
.inner:
    cmp  ebp, 6
    jae  .next
    cmp  ebp, 5
    jne  .inner_slot
    cmp  byte [rel nt_ns_wmode], 0
    jne  .inner_next
.inner_slot:
    lea  rdi, [rel nt_ns_lbas]
    mov  rax, [rdi + rbp*8]
    cmp  rax, r13
    jae  .inner_next
    lea  rdi, [rel nt_ns_sectors]
    mov  edx, [rdi + rbp*4]
    add  rax, rdx
    cmp  rax, r12
    ja   .no                            ; neither bitmap may alias any FILE
.inner_next:
    inc  ebp
    jmp  .inner
.next:
    inc  ebx
    cmp  ebx, 6
    jb   .outer
    ; Parent index identities must be allocated, never dangling free slots.
    lea  rdi, [rel nt_rec_buf]
    lea  rsi, [rel nt_ns_stage]
    mov  edx, 1024
    call memcpy
    lea  rdi, [rel nt_rec_buf]
    mov  esi, 1024
    call nt_fixup_file
    test eax, eax
    jnz  .no
    call nt_ns_index
    mov  ebx, eax
.parent_keys:
    lea  rdi, [rel nt_rec_buf]
    cmp  dword [rdi + rbx + 12], 2
    je   .parent_done
    mov  rax, [rdi + rbx]
    shl  rax, 16
    shr  rax, 16
    cmp  eax, [rel nt_ns_records]
    jae  .no
    ; The staged create key is allocated by the staged bitmap. The removed
    ; key is already absent. All preserved sibling identities remain allocated.
    lea  rsi, [rel nt_ns_stage + 2*NT_RECBUF]
    bt   [rsi], eax
    jnc  .no
    movzx eax, word [rdi + rbx + 8]
    add  ebx, eax
    jmp  .parent_keys
.parent_done:
    xor  ebx, ebx
.ancestors:
    lea  rdi, [rel nt_dir_refs]
    mov  eax, [rdi + rbx*8]
    cmp  eax, [rel nt_ns_records]
    jae  .no
    lea  rdi, [rel nt_ns_expected + 2*NT_RECBUF]
    bt   [rdi], eax
    jnc  .no                            ; every actual ancestor is allocated
    lea  rdi, [rel nt_dir_lbas]
    mov  rsi, [rdi + rbx*8]
    mov  edx, 2
    call nt_ns_volume_range
    test eax, eax
    jnz  .no
    ; Child cannot alias an ancestor (parent aliases checked among slots).
    lea  rdi, [rel nt_dir_lbas]
    mov  rdx, [rdi + rbx*8]
    mov  rax, [rel nt_ns_lbas + 8]
    call nt_cross_record_pair
    test eax, eax
    jnz  .no
    inc  ebx
    cmp  ebx, [rel nt_dir_count]
    jb   .ancestors
    xor  ebx, ebx
.mft:
    mov  eax, ebx
    shl  eax, 4
    lea  r12, [rel nt_mft_runs]
    add  r12, rax
    mov  rdi, [r12]
    test rdi, rdi
    jle  .no
    call nt_clus_to_lba
    mov  rsi, rax
    mov  rdx, [r12 + 8]
    mov  ecx, [rel nt_spc]
    imul rdx, rcx
    call nt_ns_volume_range
    test eax, eax
    jnz  .no
    ; Complete MFT physical runs cannot overlap one another or either bitmap.
    mov  r13, rsi
    add  r13, rdx
    mov  rdi, [rel nt_boot_buf + 56]
    test rdi, rdi
    jz   .no
    call nt_clus_to_lba
    cmp  rax, r13
    jae  .mirror_clear
    add  rax, 8
    cmp  rax, rsi
    ja   .no
.mirror_clear:
    xor  ebp, ebp
.mft_prior:
    cmp  ebp, ebx
    jae  .mft_bitmaps
    lea  rdi, [rel nt_mft_runs]
    mov  eax, ebp
    shl  eax, 4
    add  rdi, rax
    mov  rax, [rdi]
    mov  ecx, [rel nt_spc]
    imul rax, rcx
    add  rax, [rel nt_part_lba]
    cmp  rax, r13
    jae  .mft_prior_next
    imul rcx, [rdi + 8]
    add  rax, rcx
    cmp  rax, rsi
    ja   .no
.mft_prior_next:
    inc  ebp
    jmp  .mft_prior
.mft_bitmaps:
    mov  ebp, 2
.bitmap_overlap:
    cmp  ebp, 5
    jne  .bitmap_slot
    cmp  byte [rel nt_ns_wmode], 0
    jne  .bitmap_next
.bitmap_slot:
    lea  rdi, [rel nt_ns_lbas]
    mov  rax, [rdi + rbp*8]
    cmp  rax, r13
    jae  .bitmap_next
    lea  rdi, [rel nt_ns_sectors]
    mov  ecx, [rdi + rbp*4]
    add  rax, rcx
    cmp  rax, rsi
    ja   .no
.bitmap_next:
    add  ebp, 3
    cmp  ebp, 5
    jbe  .bitmap_overlap
    inc  ebx
    cmp  ebx, [rel nt_mft_nruns]
    jb   .mft
    mov  rdi, [rel nt_boot_buf + 56]
    test rdi, rdi
    jz   .no
    call nt_clus_to_lba
    mov  rsi, rax
    mov  edx, 8
    call nt_ns_volume_range
    test eax, eax
    jnz  .no
    mov  ebx, 2
.mirror_bitmaps:
    call nt_ns_wskip
    je   .mirror_bitmap_next
    lea  rdi, [rel nt_ns_lbas]
    mov  rax, [rdi + rbx*8]
    mov  rcx, rax
    sub  rcx, [rel nt_part_lba]
    cmp  rcx, 8
    jb   .no                            ; no bitmap in the boot cluster
    lea  rdi, [rel nt_ns_sectors]
    mov  edx, [rdi + rbx*4]
    add  rax, rdx
    cmp  rax, rsi
    jbe  .mirror_bitmap_next
    lea  rdx, [rsi + 8]
    lea  rdi, [rel nt_ns_lbas]
    cmp  [rdi + rbx*8], rdx
    jb   .no
.mirror_bitmap_next:
    add  ebx, 3
    cmp  ebx, 5
    jbe  .mirror_bitmaps
    xor  eax, eax
    jmp  .out
.no:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

NT_NS_WINDOWS     equ 8                 ; volume-map sectors (32768 clusters) per operation
NT_NS_MFTBM_MAX   equ 65536             ; $MFT bitmap read once at admission

; RAX=$MFT $BITMAP. A one-cluster map of <=512 bytes keeps the whole-map slot.
; Windows reserves larger, fragmented maps (4104 B in two runs on a fresh
; 64 GiB volume): slot 2 is then the map's first 512-byte sector through the
; actual runlist; it holds every native identity (records <= 4096). Every
; later sector is read once here and must be clear, so no identity beyond the
; window is allocated. EAX 0, -1 refused, -2 read failure.
nt_ns_mft_bitmap:
    mov  ebx, 2
    test rax, rax
    jz   nt_ns_bitmap
    cmp  byte [rax + 8], 1
    jne  nt_ns_bitmap
    mov  ecx, [rel nt_clus_bytes]
    cmp  [rax + 40], rcx
    jne  .window
    cmp  qword [rax + 48], 512
    jbe  nt_ns_bitmap
.window:
    push r12
    push r13
    push r14
    mov  r12, [rax + 48]                ; map bytes (admitted below)
    lea  rsi, [rel nt_runs]
    mov  edx, NT_NS_MFTBM_MAX
    call nt_ns_stream_admit
    cmp  eax, -1
    je   .no
    mov  r13d, eax
    xor  r14d, r14d
.sector:
    lea  rdi, [rel nt_runs]
    mov  esi, r13d
    mov  rdx, r14
    shl  rdx, 9
    call nt_vcn_to_lba
    cmp  rax, -2
    jae  .no
    cmp  rdx, 512
    jb   .no
    mov  rsi, rax
    mov  edx, 1
    lea  rcx, [rel nt_ns_readback]
    test r14, r14
    jnz  .read
    mov  [rel nt_ns_lbas + 2*8], rsi
    mov  dword [rel nt_ns_sectors + 2*4], 1
    lea  rcx, [rel nt_ns_expected + 2*NT_RECBUF]
.read:
    call nt_read
    test rax, rax
    jnz  .io
    test r14, r14
    jz   .next
    mov  rcx, r12
    mov  rax, r14
    shl  rax, 9
    sub  rcx, rax                       ; map bytes from this sector
    cmp  rcx, 512
    jbe  .tail
    mov  ecx, 512
.tail:
    lea  rdi, [rel nt_ns_readback]
    xor  eax, eax
    repe scasb
    jne  .no                            ; identity beyond the window allocated
.next:
    inc  r14
    mov  rax, r14
    shl  rax, 9
    cmp  rax, r12
    jb   .sector
    lea  rdi, [rel nt_ns_stage + 2*NT_RECBUF]
    lea  rsi, [rel nt_ns_expected + 2*NT_RECBUF]
    mov  edx, 512
    call memcpy
    mov  eax, 512
    cmp  r12, rax
    cmovb eax, r12d                     ; a shorter map covers fewer identities
    mov  [rel nt_ns_bitmap_bytes], eax
    xor  eax, eax
    jmp  .out
.io:
    mov  eax, -2
    jmp  .out
.no:
    mov  eax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    ret

; RAX=$Bitmap DATA, EBX=5. A map within one cluster keeps the whole-map slot.
; A larger map (2 MiB on a 64 GiB volume) is admitted with its actual runlist;
; slot 5 then holds at most NT_NS_WINDOWS 512-byte sectors, loaded only for
; ranges whose allocation the operation proves (nt_ns_windows).
nt_ns_vol_bitmap:
    mov  byte [rel nt_ns_wmode], 0
    mov  dword [rel nt_ns_wcount], 0
    test rax, rax
    jz   nt_ns_bitmap
    cmp  byte [rax + 8], 1
    jne  nt_ns_bitmap
    mov  ecx, [rel nt_clus_bytes]
    cmp  [rax + 40], rcx
    jbe  nt_ns_bitmap
    push r12
    mov  r12, rax
    lea  rsi, [rel nt_ns_vruns]
    mov  edx, NT_SPACE_MAX_BITMAP
    call nt_ns_stream_admit
    cmp  eax, -1
    je   .no
    mov  [rel nt_ns_vnruns], eax
    mov  rax, [r12 + 48]
    mov  [rel nt_ns_bitmap_bytes], eax  ; full-size check follows in the caller
    mov  qword [rel nt_ns_lbas + 5*8], 0
    mov  dword [rel nt_ns_sectors + 5*4], 0
    mov  byte [rel nt_ns_wmode], 1
    xor  eax, eax
    pop  r12
    ret
.no:
    mov  eax, -1
    pop  r12
    ret

; RAX=nonresident map attribute, RSI=private runs out, RDX=max bytes. Plain
; unnamed stream from VCN 0, initialized == data <= allocated, highest VCN
; covering the allocation, real (non-sparse) runs summing to it exactly.
; EAX run count, or -1.
nt_ns_stream_admit:
    push r12
    push r13
    push r14
    mov  r12, rax
    mov  r13, rsi
    mov  r14, rdx
    cmp  byte [rax + 8], 1
    jne  .no
    cmp  byte [rax + 9], 0
    jne  .no
    cmp  word [rax + 12], 0
    jne  .no
    cmp  qword [rax + 16], 0
    jne  .no
    cmp  word [rax + 34], 0
    jne  .no
    cmp  dword [rax + 36], 0
    jne  .no
    mov  rdx, [rax + 48]
    test rdx, rdx
    jz   .no
    cmp  rdx, r14
    ja   .no
    cmp  rdx, [rax + 56]
    jne  .no                            ; no uninitialized map tail
    cmp  rdx, [rax + 40]
    ja   .no
    mov  rax, [r12 + 40]
    xor  edx, edx
    mov  ecx, [rel nt_clus_bytes]
    div  rcx
    test rdx, rdx
    jnz  .no
    test rax, rax
    jz   .no
    dec  rax
    cmp  rax, [r12 + 24]
    jne  .no
    movzx ecx, word [r12 + 32]
    lea  rdi, [r12 + rcx]
    mov  ecx, [r12 + 4]
    add  rcx, r12
    mov  rsi, r13
    mov  edx, NT_MAX_RUNS
    call nt_decode_runlist
    test eax, eax
    jle  .no
    mov  r14d, eax
    xor  ecx, ecx
    xor  r8d, r8d
.runs:
    mov  edx, ecx
    shl  edx, 4
    cmp  qword [r13 + rdx], 0
    jle  .no                            ; no sparse or boot-cluster map runs
    add  r8, [r13 + rdx + 8]
    jc   .no
    inc  ecx
    cmp  ecx, r14d
    jb   .runs
    mov  rax, [r12 + 24]
    inc  rax
    cmp  r8, rax
    jne  .no
    mov  eax, r14d
    jmp  .out
.no:
    mov  eax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    ret

; ZF=1 when slot EBX is the windowed volume map. Preserves registers.
nt_ns_wskip:
    cmp  ebx, 5
    jne  .out
    cmp  byte [rel nt_ns_wmode], 1
.out:
    ret

; RAX=volume-map sector -> EAX loaded window index, or -1. Clobbers RDX.
nt_ns_wfind:
    push rcx
    xor  ecx, ecx
.loop:
    cmp  ecx, [rel nt_ns_wcount]
    jae  .miss
    lea  rdx, [rel nt_ns_wsec]
    cmp  [rdx + rcx*8], rax
    je   .hit
    inc  ecx
    jmp  .loop
.hit:
    mov  eax, ecx
    pop  rcx
    ret
.miss:
    mov  eax, -1
    pop  rcx
    ret

; EBX=slot, R14=sector index -> RSI absolute LBA (window table for slot 5).
nt_ns_slot_lba:
    call nt_ns_wskip
    jne  .range
    lea  rsi, [rel nt_ns_wlba]
    mov  rsi, [rsi + r14*8]
    ret
.range:
    lea  rsi, [rel nt_ns_lbas]
    mov  rsi, [rsi + rbx*8]
    add  rsi, r14
    ret

; R12=sector, RAX=start, RCX=count -> EAX 1 when start <= R12 < start+count.
nt_ns_hits:
    cmp  r12, rax
    jb   .miss
    add  rax, rcx
    jc   .hit
    cmp  r12, rax
    jb   .hit
.miss:
    xor  eax, eax
    ret
.hit:
    mov  eax, 1
    ret

; RAX=cluster the staged volume map releases (allocation already proven).
; EAX 0, or -1 when its window is not loaded.
nt_ns_release:
    cmp  byte [rel nt_ns_wmode], 0
    jne  .window
    lea  rdi, [rel nt_ns_stage + 5*NT_RECBUF]
    btr  [rdi], eax
    xor  eax, eax
    ret
.window:
    push rcx
    mov  rcx, rax
    shr  rax, 12
    call nt_ns_wfind
    cmp  eax, -1
    je   .out
    shl  eax, 9
    lea  rdi, [rel nt_ns_stage + 5*NT_RECBUF]
    add  rdi, rax
    and  ecx, 4095
    btr  [rdi], ecx
    xor  eax, eax
.out:
    pop  rcx
    ret

; RSI=LBA, RDX=sectors of a range whose allocation the operation proves. Load
; the volume-map sector of every cluster it covers. EAX 0, -1 refused (beyond
; the map, unmapped or sparse map VCN, more than NT_NS_WINDOWS sectors), -2
; read failure. Preserves RBX, R12-R14, RSI, RDX.
nt_ns_wneed:
    push rbx
    push r12
    push r13
    push rsi
    push rdx
    test rdx, rdx
    jz   .no
    mov  rax, rsi
    sub  rax, [rel nt_part_lba]
    jc   .no
    lea  r12, [rax + rdx - 1]
    cmp  r12, rax
    jb   .no
    mov  ecx, [rel nt_spc]
    xor  edx, edx
    div  rcx
    mov  rbx, rax                       ; first cluster
    mov  rax, r12
    xor  edx, edx
    div  rcx
    mov  r12, rax                       ; last cluster
    mov  rax, [rel nt_total_sectors]
    xor  edx, edx
    div  rcx
    cmp  r12, rax
    jae  .no
.cluster:
    mov  rax, rbx
    shr  rax, 12
    mov  r13, rax
    call nt_ns_wfind
    cmp  eax, -1
    jne  .loaded
    cmp  dword [rel nt_ns_wcount], NT_NS_WINDOWS
    jae  .no                            ; bounded: refuse, never scan the map
    lea  rdi, [rel nt_ns_vruns]
    mov  esi, [rel nt_ns_vnruns]
    mov  rdx, r13
    shl  rdx, 9
    call nt_vcn_to_lba
    cmp  rax, -2
    jae  .no
    cmp  rdx, 512
    jb   .no
    mov  rsi, rax
    mov  edx, 1
    call nt_lba_in_volume
    jc   .no
    mov  eax, [rel nt_ns_wcount]
    lea  rdi, [rel nt_ns_wlba]
    mov  [rdi + rax*8], rsi
    lea  rdi, [rel nt_ns_wsec]
    mov  [rdi + rax*8], r13
    shl  eax, 9
    lea  rcx, [rel nt_ns_expected + 5*NT_RECBUF]
    add  rcx, rax
    mov  edx, 1
    call nt_read
    test rax, rax
    jnz  .io
    mov  eax, [rel nt_ns_wcount]
    shl  eax, 9
    lea  rsi, [rel nt_ns_expected + 5*NT_RECBUF]
    add  rsi, rax
    lea  rdi, [rel nt_ns_stage + 5*NT_RECBUF]
    add  rdi, rax
    mov  edx, 512
    call memcpy
    inc  dword [rel nt_ns_wcount]
.loaded:
    lea  rbx, [r13 + 1]
    shl  rbx, 12                        ; first cluster of the next map sector
    cmp  rbx, r12
    jbe  .cluster
    xor  eax, eax
    jmp  .out
.io:
    mov  eax, -2
    jmp  .out
.no:
    mov  eax, -1
.out:
    pop  rdx
    pop  rsi
    pop  r13
    pop  r12
    pop  rbx
    ret

; Window mode only. EDI=1 adds the private DATA sectors (nt_nr_lbas). Load the
; volume-map sector of every range whose allocation the operation proves: FILE
; and map slots, actual ancestors, every $MFT run, $MFTMirr, DATA, and every
; run of the map itself. Every map cluster must be allocated; each window is
; disjoint from every slot, other window, ancestor, $MFT run, mirror and DATA
; sector. EAX 0, -1 refused, -2 read failure.
nt_ns_windows:
    cmp  byte [rel nt_ns_wmode], 0
    jne  .start
    xor  eax, eax
    ret
.start:
    push rbx
    push r12
    push r13
    push r14
    mov  r14d, edi
    xor  ebx, ebx
.slots:
    lea  rdi, [rel nt_ns_lbas]
    mov  rsi, [rdi + rbx*8]
    lea  rdi, [rel nt_ns_sectors]
    mov  edx, [rdi + rbx*4]
    test edx, edx
    jz   .slot_next
    call nt_ns_wneed
    test eax, eax
    jnz  .out
.slot_next:
    inc  ebx
    cmp  ebx, 5
    jb   .slots
    xor  ebx, ebx
.ancestors:
    cmp  ebx, [rel nt_dir_count]
    jae  .mft
    lea  rdi, [rel nt_dir_lbas]
    mov  rsi, [rdi + rbx*8]
    mov  edx, 2
    call nt_ns_wneed
    test eax, eax
    jnz  .out
    inc  ebx
    jmp  .ancestors
.mft:
    xor  ebx, ebx
.mft_run:
    cmp  ebx, [rel nt_mft_nruns]
    jae  .mirror
    mov  eax, ebx
    shl  eax, 4
    lea  r12, [rel nt_mft_runs]
    add  r12, rax
    mov  rdi, [r12]
    call nt_clus_to_lba
    mov  rsi, rax
    mov  rdx, [r12 + 8]
    mov  ecx, [rel nt_spc]
    imul rdx, rcx
    call nt_ns_wneed
    test eax, eax
    jnz  .out
    inc  ebx
    jmp  .mft_run
.mirror:
    mov  rdi, [rel nt_boot_buf + 56]
    call nt_clus_to_lba
    mov  rsi, rax
    mov  edx, 8
    call nt_ns_wneed
    test eax, eax
    jnz  .out
    xor  ebx, ebx
.data:
    test r14d, r14d
    jz   .own
    cmp  ebx, [rel nt_nr_sectors]
    jae  .own
    lea  rdi, [rel nt_nr_lbas]
    mov  rsi, [rdi + rbx*8]
    mov  edx, 1
    call nt_ns_wneed
    test eax, eax
    jnz  .out
    inc  ebx
    jmp  .data
.own:
    xor  ebx, ebx                       ; the whole map stream, windows included
.own_run:
    cmp  ebx, [rel nt_ns_vnruns]
    jae  .audit
    call nt_ns_vrun
    call nt_ns_wneed
    test eax, eax
    jnz  .out
    inc  ebx
    jmp  .own_run
.audit:
    mov  eax, [rel nt_ns_wcount]
    mov  [rel nt_ns_sectors + 5*4], eax
    xor  ebx, ebx
.map_run:
    cmp  ebx, [rel nt_ns_vnruns]
    jae  .windows
    call nt_ns_vrun
    call nt_ns_volume_range
    test eax, eax
    jnz  .no                            ; every map cluster is itself allocated
    inc  ebx
    jmp  .map_run
.windows:
    xor  ebx, ebx
.window:
    cmp  ebx, [rel nt_ns_wcount]
    jae  .ok
    lea  rdi, [rel nt_ns_wlba]
    mov  r12, [rdi + rbx*8]
    xor  r13d, r13d
.slot_pairs:
    lea  rdi, [rel nt_ns_lbas]
    mov  rax, [rdi + r13*8]
    lea  rdi, [rel nt_ns_sectors]
    mov  ecx, [rdi + r13*4]
    call nt_ns_hits
    test eax, eax
    jnz  .no
    inc  r13d
    cmp  r13d, 5
    jb   .slot_pairs
    xor  r13d, r13d
.window_pairs:
    cmp  r13d, ebx
    je   .window_pair_next
    lea  rdi, [rel nt_ns_wlba]
    mov  rax, [rdi + r13*8]
    mov  ecx, 1
    call nt_ns_hits
    test eax, eax
    jnz  .no
.window_pair_next:
    inc  r13d
    cmp  r13d, [rel nt_ns_wcount]
    jb   .window_pairs
    xor  r13d, r13d
.ancestor_pairs:
    cmp  r13d, [rel nt_dir_count]
    jae  .mft_pairs
    lea  rdi, [rel nt_dir_lbas]
    mov  rax, [rdi + r13*8]
    mov  ecx, 2
    call nt_ns_hits
    test eax, eax
    jnz  .no
    inc  r13d
    jmp  .ancestor_pairs
.mft_pairs:
    xor  r13d, r13d
.mft_pair:
    cmp  r13d, [rel nt_mft_nruns]
    jae  .mirror_pair
    mov  eax, r13d
    shl  eax, 4
    lea  rsi, [rel nt_mft_runs]
    add  rsi, rax
    mov  rdi, [rsi]
    call nt_clus_to_lba
    mov  rcx, [rsi + 8]
    mov  edx, [rel nt_spc]
    imul rcx, rdx
    call nt_ns_hits
    test eax, eax
    jnz  .no
    inc  r13d
    jmp  .mft_pair
.mirror_pair:
    mov  rdi, [rel nt_boot_buf + 56]
    call nt_clus_to_lba
    mov  ecx, 8
    call nt_ns_hits
    test eax, eax
    jnz  .no
    test r14d, r14d
    jz   .window_next
    mov  rax, r12
    mov  edx, 1
    call nt_nr_overlaps
    test eax, eax
    jnz  .no                            ; never release or alias a map sector
.window_next:
    inc  ebx
    jmp  .window
.ok:
    xor  eax, eax
    jmp  .out
.no:
    mov  eax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; EBX=volume-map run -> RSI first LBA, RDX sectors (runs admitted: LCN > 0).
nt_ns_vrun:
    mov  eax, ebx
    shl  eax, 4
    lea  rsi, [rel nt_ns_vruns]
    add  rsi, rax
    mov  rdi, [rsi]
    mov  rdx, [rsi + 8]
    push rdx
    call nt_clus_to_lba
    pop  rdx
    mov  rsi, rax
    mov  ecx, [rel nt_spc]
    imul rdx, rcx
    ret

; Retry-predicate custody of every loaded window: exact expected bytes.
nt_ns_windows_current:
    push rbx
    xor  ebx, ebx
.loop:
    cmp  ebx, [rel nt_ns_wcount]
    jae  .ok
    lea  rdi, [rel nt_ns_wlba]
    mov  rsi, [rdi + rbx*8]
    mov  edx, 1
    lea  rcx, [rel nt_ns_readback]
    call nt_read
    test rax, rax
    jnz  .no
    call nt_save_authority
    test rax, rax
    jnz  .no
    call nt_rename_current
    test rax, rax
    jnz  .no
    mov  esi, ebx
    shl  esi, 9
    lea  rdi, [rel nt_ns_expected + 5*NT_RECBUF]
    add  rsi, rdi
    lea  rdi, [rel nt_ns_readback]
    mov  edx, 512
    call memcmp
    test rax, rax
    jnz  .no
    inc  ebx
    jmp  .loop
.ok:
    xor  eax, eax
    pop  rbx
    ret
.no:
    mov  rax, -1
    pop  rbx
    ret

; RSI=LBA, RDX=sectors. Preserve range for caller's disjointness checks.
nt_ns_volume_range:
    push rsi
    push rdx
    mov  rax, rsi
    sub  rax, [rel nt_part_lba]
    jc   .no
    mov  r8, rdx
    add  r8, rax
    jc   .no
    dec  r8
    mov  ecx, [rel nt_spc]
    xor  edx, edx
    div  rcx
    mov  r9, rax
    mov  rax, r8
    xor  edx, edx
    div  rcx
    mov  r8, rax
    lea  rdi, [rel nt_ns_expected + 5*NT_RECBUF]
.bits:
    mov  rax, [rel nt_total_sectors]
    xor  edx, edx
    div  rcx
    cmp  r8, rax
    jae  .no
    cmp  byte [rel nt_ns_wmode], 0
    jne  .window
    bt   [rdi], r9
    jnc  .no
.bit_next:
    inc  r9
    cmp  r9, r8
    jbe  .bits
    xor  eax, eax
    jmp  .out
.window:
    mov  rax, r9
    shr  rax, 12                        ; 4096 clusters per map sector
    call nt_ns_wfind
    cmp  eax, -1
    je   .no                            ; never inferred: the sector is loaded
    shl  eax, 9
    lea  rdi, [rel nt_ns_expected + 5*NT_RECBUF]
    add  rdi, rax
    mov  eax, r9d
    and  eax, 4095
    bt   [rdi], eax
    jnc  .no
    jmp  .bit_next
.no:
    mov  eax, -1
.out:
    pop  rdx
    pop  rsi
    ret

; Full raw expected-partial-image comparison INSIDE the sector retry predicate.
; Separate buffer from ancestry checks; never recursively invoke save_current.
nt_ns_current:
    push rbx
    push rdi
    push rsi
    push rdx
    push rcx
    push r8
    push r9
    push r10
    push r11
    call nt_rename_current
    test rax, rax
    jnz  .no
    xor  ebx, ebx
.loop:
    call nt_ns_wskip
    jne  .range
    call nt_ns_windows_current
    test rax, rax
    jnz  .no
    jmp  .slot_next
.range:
    lea  rdi, [rel nt_ns_lbas]
    mov  rsi, [rdi + rbx*8]
    lea  rdi, [rel nt_ns_sectors]
    mov  edx, [rdi + rbx*4]
    lea  rcx, [rel nt_ns_readback]
    call nt_read
    test rax, rax
    jnz  .no
    call nt_save_authority
    test rax, rax
    jnz  .no
    call nt_rename_current
    test rax, rax
    jnz  .no
    imul esi, ebx, NT_RECBUF
    lea  rdi, [rel nt_ns_expected]
    add  rsi, rdi
    cmp  byte [rel nt_nr_mode], 0
    je   .expected
    test ebx, ebx
    jnz  .child_expected
    lea  rsi, [rel nt_res_parent_expected]
    jmp  .expected
.child_expected:
    cmp  ebx, 1
    jne  .expected
    lea  rsi, [rel nt_res_expected]
.expected:
    lea  rdi, [rel nt_ns_readback]
    lea  rdx, [rel nt_ns_sectors]
    mov  edx, [rdx + rbx*4]
    shl  edx, 9
    call memcmp
    test rax, rax
    jnz  .no                            ; metadata/bitmap custody, including retry
.slot_next:
    inc  ebx
    cmp  ebx, 6
    jb   .loop
    cmp  byte [rel nt_nd_ready], 0
    je   .complete
    call nt_nr_census_current           ; all other owners stay fixed during release
    test rax, rax
    jnz  .no
    call nt_rename_current              ; authority/ancestry after final census read
    test rax, rax
    jnz  .no
.complete:
    xor  eax, eax
    jmp  .out
.no:
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
    pop  rbx
    ret

nt_ns_ready: db 0
nt_ns_file: db 0
nt_ns_length: dd 0
nt_ns_source: dq 0
nt_ns_payload: times 1024 db 0
nt_ns_sequence: dw 0
nt_ns_op: dd 0
nt_ns_records: dd 0
nt_ns_child: dd 0
nt_ns_bitmap_bytes: dd 0
nt_ns_mft_bytes: dd 0
nt_ns_key_bytes: dd 0
nt_ns_index_attr: dd 0
nt_ns_index_header: dd 0
nt_ns_position: dd 0
nt_ns_delta: dd 0
nt_ns_std: dq 0
nt_ns_security: dq 0
nt_ns_time: dq 0
nt_ns_key: times 192 db 0
nt_ns_lbas: times 6 dq 0
nt_ns_sectors: times 6 dd 0
nt_ns_expected: times 6*NT_RECBUF db 0
nt_ns_stage: times 6*NT_RECBUF db 0
nt_ns_readback: times NT_RECBUF db 0
nt_ns_profile: db 0
nt_ns_std_bytes: dd 0
nt_data_stream: dq 0
nt_sx_ready: db 0
nt_sx_found: db 0
nt_sx_id: dd 0
nt_sx_parent_id: dd 0
nt_sx_hash: dd 0
nt_sx_length: dd 0
nt_sx_parent_len: dd 0
nt_sx_offset: dq 0
nt_sx_entry: times 20 + NT_SX_PARENT_MAX db 0
nt_sx_attr_buf: times 24 + NT_SX_SD_MAX db 0
nt_dir_parent_only: db 0
nt_dir_fn_spaces: dd 0
nt_dir_fn_off: dd 0
nt_dir_fn_len: dd 0
nt_dir_fn_attr: dd 0
nt_dir_fn_next: dq 0
nt_dir_fn_dos_next: dq 0
nt_ns_wmode: db 0
nt_ns_wcount: dd 0
nt_ns_vnruns: dd 0
nt_ns_wlba: times NT_NS_WINDOWS dq 0
nt_ns_wsec: times NT_NS_WINDOWS dq 0
nt_ns_vruns: times NT_MAX_RUNS*16 db 0
    times -((NT_NS_WINDOWS * 512) > NT_RECBUF) db 0  ; windows share slot 5's NT_RECBUF buffers


; Existing allocation only: at most four plain 4096-byte clusters (16 KiB).
; A finite 32-sector map is private before shared run scratch is reused. Three
; four-bounce-buffer DATA images cost 48 KiB (below the 128 KiB FILE census).
; Native FSWRITE remains capped by its existing FS_IO_CAP; no UI budget change.
NT_NR_CAP equ 4 * NT_SECBUF
NT_NR_SECTORS equ NT_NR_CAP / 512
; No allocation/free or journal/crash-atomicity promise. Complete private bytes
; and zero tail are durable before publishing DATA/init and both name caches.
nt_nonresident_resize:
    push rbx
    push r9
    cmp  dword [rel nt_rec_bytes], 1024
    jne  .no
    cmp  dword [rel nt_clus_bytes], 4096
    jne  .no
    cmp  r14, NT_NR_CAP
    ja   .no
    test r12, r12
    jnz  .no
    test r14, r14
    jz   .source
    test r13, r13
    jz   .no
.source:
    mov  rax, r13
    add  rax, r14
    jc   .no
    lea  rdi, [rel nt_rec_buf]
    lea  rsi, [rdi + 1024]
    call nt_data_attr_admit
    test rax, rax
    jz   .no
    cmp  byte [rax + 8], 1
    jne  .no
    cmp  word [rax + 12], 0
    jne  .no
    cmp  word [rax + 34], 0
    jne  .no
    cmp  dword [rax + 36], 0
    jne  .no
    mov  rdx, [rax + 40]
    test rdx, rdx
    jz   .no
    cmp  rdx, NT_NR_CAP
    ja   .no
    cmp  r14, rdx
    ja   .no                            ; no capacity growth or cluster allocation
    mov  [rel nt_nr_capacity], rdx
    shr  edx, 9
    mov  [rel nt_nr_sectors], edx
    mov  rdx, [rax + 48]
    mov  [rel nt_nr_old_size], rdx
    call nt_rename_runs_plain           ; boot/MFT/MFTMirr and aliases excluded
    test eax, eax
    jnz  .no
    xor  ebx, ebx
.map:
    lea  rdi, [rel nt_runs]
    mov  esi, [rel nt_nruns]
    mov  edx, ebx
    shl  edx, 9
    call nt_vcn_to_lba                  ; actual reader mapper, every sector
    cmp  rax, -2
    jae  .no
    test rcx, rcx
    jnz  .no
    cmp  rdx, 512
    jb   .no
    lea  rdi, [rel nt_nr_lbas]
    mov  [rdi + rbx*8], rax
    inc  ebx
    cmp  ebx, [rel nt_nr_sectors]
    jb   .map
    mov  rax, [rel nt_nr_lbas]
    mov  [rel nt_nr_lba], rax            ; first sector, diagnostic only
    mov  eax, [rel nt_found_ref]
    mov  [rel nt_nr_child], eax
    ; Snapshot caller bytes once; never consult them during sector publication.
    lea  rdi, [rel nt_nr_stage]
    xor  eax, eax
    mov  ecx, NT_NR_CAP
    rep  stosb
    lea  rdi, [rel nt_nr_stage]
    mov  rsi, r13
    mov  rdx, r14
    call memcpy
    lea  rdi, [rel nt_nr_path]
    lea  rsi, [rel nt_path_buf]
    mov  edx, NT_MUT_PATH_MAX + 1
    call memcpy
    mov  byte [rel nt_nr_mode], 1
    mov  r9, [rsp]
    call nt_resident_write
    mov  byte [rel nt_nr_mode], 0
    mov  byte [rel nt_ns_wmode], 0
    mov  byte [rel nt_nr_ready], 0
    mov  byte [rel nt_dir_ready], 0
    mov  dword [rel nt_dir_count], 0
    jmp  .out
.no:
    mov  rax, -1
.out:
    add  rsp, 8
    pop  rbx
    ret

nt_resize_allocation:
    lea  rax, [r14 + 7]
    and  rax, -8
    cmp  byte [rel nt_nr_mode], 0
    je   .out
    mov  rax, [rel nt_nr_capacity]       ; unchanged physical capacity, never round len
.out:
    ret

; Both resize metadata images are already fully admitted and encoded. Collect
; the actual immutable allocation authority, complete parent and path snapshots.
nt_nr_prepare:
    push rbx
    push r13
    push r14
    push r15
    mov  byte [rel nt_dir_ready], 0
    mov  dword [rel nt_dir_count], 0
    mov  byte [rel nt_cross], 0
    mov  rdx, [rel nt_res_parent_ref]
    mov  [rel nt_rename_parent_full], rdx
    mov  [rel nt_cross_dest_ref], rdx
    mov  dword [rel nt_dir_child], -1
    lea  rsi, [rel nt_nr_path]
    call nt_dir_chain
    test rax, rax
    jnz  .uncertain
    call nt_dir_staged_parents
    test rax, rax
    jnz  .uncertain
    mov  rax, [rel nt_res_parent_lba]
    mov  [rel nt_ns_lbas], rax
    mov  rax, [rel nt_res_lba]
    mov  [rel nt_ns_lbas + 8], rax
    mov  dword [rel nt_ns_sectors], 2
    mov  dword [rel nt_ns_sectors + 4], 2
    lea  rdi, [rel nt_ns_stage]
    lea  rsi, [rel nt_res_parent_stage]
    mov  edx, 1024
    call memcpy
    ; Actual MFT metadata, bounded DATA and actual bitmap; never guess a slot.
    xor  edi, edi
    call nt_read_record
    test rax, rax
    jnz  .uncertain
    cmp  dword [rel nt_rec_buf + 44], 0
    jne  .no
    call nt_ns_data
    test rax, rax
    jz   .no
    mov  rdx, [rax + 48]
    cmp  rdx, [rax + 56]
    jne  .no
    test edx, 1023
    jnz  .no
    shr  rdx, 10
    cmp  rdx, 27
    jb   .no
    cmp  rdx, 4096
    ja   .no
    mov  [rel nt_ns_records], edx
    mov  edx, [rel nt_nruns]
    cmp  edx, [rel nt_mft_nruns]
    jne  .no
    shl  edx, 4
    lea  rdi, [rel nt_mft_runs]
    lea  rsi, [rel nt_runs]
    call memcmp
    test rax, rax
    jnz  .no                            ; mounted and current MFT mapping agree
    mov  ebx, 3
    xor  edi, edi
    call nt_ns_record_slot
    test eax, eax
    jnz  .uncertain
    lea  rdi, [rel nt_rec_buf]
    mov  esi, NT_A_BITMAP
    call nt_find_attr_any
    test rax, rax
    jz   .no
    mov  ebx, 2
    call nt_ns_mft_bitmap
    cmp  eax, -2
    je   .uncertain
    test eax, eax
    jnz  .no
    cmp  dword [rel nt_ns_bitmap_bytes], 512
    ja   .no
    mov  eax, [rel nt_ns_bitmap_bytes]
    mov  [rel nt_ns_mft_bytes], eax
    shl  eax, 3
    cmp  eax, [rel nt_ns_records]
    jb   .no
    cmp  word [rel nt_ns_expected + 2*NT_RECBUF], 0xFFFF
    jne  .no                            ; never allocate reserved system identities
    mov  edi, 6
    call nt_read_record
    test rax, rax
    jnz  .uncertain
    cmp  dword [rel nt_rec_buf + 44], 6
    jne  .no
    call nt_ns_data
    test rax, rax
    jz   .no
    mov  r15, rax
    mov  ebx, 4
    mov  edi, 6
    call nt_ns_record_slot
    test eax, eax
    jnz  .uncertain
    mov  rax, r15
    mov  ebx, 5
    call nt_ns_vol_bitmap
    cmp  eax, -2
    je   .uncertain
    test eax, eax
    jnz  .no
    mov  rax, [rel nt_total_sectors]
    xor  edx, edx
    mov  ecx, [rel nt_spc]
    div  rcx
    add  rax, 7
    shr  rax, 3
    mov  edx, [rel nt_ns_bitmap_bytes]
    cmp  rax, rdx
    jne  .no                            ; full 64-bit volume map size, no prefix

    mov  eax, [rel nt_nr_child]
    cmp  eax, [rel nt_ns_records]
    jae  .no
    lea  rdi, [rel nt_ns_expected + 2*NT_RECBUF]
    bt   [rdi], eax
    jnc  .no                            ; resized FILE itself must be allocated
    mov  edi, 1                         ; private DATA sectors join the audit
    call nt_ns_windows
    cmp  eax, -2
    je   .uncertain
    test eax, eax
    jnz  .no
    call nt_ns_mapping
    test eax, eax
    jnz  .no
    call nt_nr_census
    cmp  eax, -2
    je   .uncertain
    test eax, eax
    jnz  .no
    ; DATA cannot alias either bitmap, any metadata slot, or actual ancestor.
    xor  r14d, r14d
.data_sectors:
    lea  rdi, [rel nt_nr_lbas]
    mov  rsi, [rdi + r14*8]
    mov  edx, 1
    call nt_ns_volume_range
    test eax, eax
    jnz  .no                            ; every DATA cluster is actually allocated
    xor  ebx, ebx
.slots:
    call nt_ns_wskip
    je   .slot_next
    lea  rdi, [rel nt_ns_lbas]
    mov  rax, [rdi + rbx*8]
    lea  rdx, [rsi + 1]
    cmp  rax, rdx
    jae  .slot_next
    lea  rdi, [rel nt_ns_sectors]
    mov  edx, [rdi + rbx*4]
    add  rax, rdx
    cmp  rax, rsi
    ja   .no                            ; allocation metadata is never DATA
.slot_next:
    inc  ebx
    cmp  ebx, 6
    jb   .slots
    xor  ebx, ebx
.ancestors:
    lea  rdi, [rel nt_dir_lbas]
    mov  rax, [rdi + rbx*8]
    lea  rdx, [rsi + 1]
    cmp  rax, rdx
    jae  .ancestor_next
    add  rax, 2
    cmp  rax, rsi
    ja   .no
.ancestor_next:
    inc  ebx
    cmp  ebx, [rel nt_dir_count]
    jb   .ancestors
    inc  r14d
    cmp  r14d, [rel nt_nr_sectors]
    jb   .data_sectors
    ; Every preserved leaf key must still name the real current allocated FILE.
    lea  rdi, [rel nt_rec_buf]
    lea  rsi, [rel nt_res_parent_expected]
    mov  edx, 1024
    call memcpy
    lea  rdi, [rel nt_rec_buf]
    mov  esi, 1024
    call nt_fixup_file
    test eax, eax
    jnz  .no
    call nt_ns_index
    mov  r13d, eax
    lea  rdi, [rel nt_ns_stage]
    lea  rsi, [rel nt_rec_buf]
    mov  edx, 1024
    call memcpy                         ; iterate logical keys, never raw USA tails
    lea  rbx, [rel nt_ns_stage]
.keys:
    cmp  dword [rbx + r13 + 12], 2
    je   .snapshot
    mov  edi, [rbx + r13]
    call nt_read_record
    test rax, rax
    jnz  .uncertain
    mov  eax, [rbx + r13]
    cmp  [rel nt_rec_buf + 44], eax
    jne  .no
    test word [rel nt_rec_buf + 22], 1
    jz   .no
    mov  rax, [rbx + r13]
    shr  rax, 48
    cmp  [rel nt_rec_buf + 16], ax
    jne  .no                            ; actual sibling sequence, no stale keys
    movzx eax, word [rbx + r13 + 8]
    add  r13d, eax
    jmp  .keys
.snapshot:
    lea  rcx, [rel nt_nr_expected]
    call nt_nr_read_data
    test rax, rax
    jnz  .uncertain
    mov  byte [rel nt_dir_ready], 1
    mov  byte [rel nt_nr_ready], 1       ; all metadata, bitmap and DATA preimages
    call nt_nr_current
    test rax, rax
    jnz  .uncertain
    xor  eax, eax
    jmp  .out
.no:
    mov  rax, -1
    jmp  .out
.uncertain:
    mov  rax, -2
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  rbx
    ret

; Complete expected partial DATA plus six metadata/bitmap images and ancestry.
; Called within EACH individual sector retry, without recursive save_current.
nt_nr_current:
    push rdi
    push rsi
    push rdx
    push rcx
    push r8
    push r9
    push r10
    push r11
    call nt_ns_current
    test rax, rax
    jnz  .no
    call nt_nr_census_current
    test rax, rax
    jnz  .no
    lea  rcx, [rel nt_nr_readback]
    call nt_nr_read_data
    test rax, rax
    jnz  .no
    call nt_save_authority
    test rax, rax
    jnz  .no
    call nt_rename_current
    test rax, rax
    jnz  .no
    lea  rdi, [rel nt_nr_readback]
    lea  rsi, [rel nt_nr_expected]
    mov  edx, [rel nt_nr_capacity]
    call memcmp
    test rax, rax
    jnz  .no
    ; Metadata custody must also survive the complete mapped DATA read itself,
    ; including the pre-flush and final post-flush checks.
    call nt_ns_current
    test rax, rax
    jnz  .no
    call nt_nr_census_current           ; post-DATA-read allocated FILE custody
    test rax, rax
    jnz  .no
    call nt_rename_current
    jmp  .out
.no:
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
    ret

nt_nr_write_data:
    push r15
    xor  r15d, r15d
.loop:
    call nt_save_current
    test rax, rax
    jnz  .no
    lea  rsi, [rel nt_nr_lbas]
    mov  rsi, [rsi + r15*8]              ; never assume adjacent physical sectors
    mov  edx, 1
    mov  rax, r15
    shl  eax, 9
    lea  rcx, [rel nt_nr_stage]
    add  rcx, rax
    mov  r9d, 1
    call nt_write
    test rax, rax
    jnz  .no
    mov  rax, r15
    shl  eax, 9
    lea  rdi, [rel nt_nr_expected]
    add  rdi, rax
    lea  rsi, [rel nt_nr_stage]
    add  rsi, rax
    mov  edx, 512
    call memcpy
    inc  r15d
    cmp  r15d, [rel nt_nr_sectors]
    jb   .loop
    call nt_save_current
    test rax, rax
    jnz  .no
    mov  rdi, [rel nt_dev]
    call blk_flush
    mov  [rel nt_last_blk_rc], rax
    test rax, rax
    jnz  .no
    call nt_save_current                 ; independent full readback after flush
    jmp  .out
.no:
    mov  rax, -1
.out:
    pop  r15
    ret

; RCX=private destination. Full logical allocation in mapped sector order;
; shared nt_runs is deliberately NOT consulted after metadata/census reads.
nt_nr_read_data:
    push rbx
    push r12
    mov  r12, rcx
    xor  ebx, ebx
.loop:
    lea  rsi, [rel nt_nr_lbas]
    mov  rsi, [rsi + rbx*8]
    mov  edx, 1
    mov  rcx, r12
    call nt_read
    test rax, rax
    jnz  .out
    add  r12, 512
    inc  ebx
    cmp  ebx, [rel nt_nr_sectors]
    jb   .loop
.out:
    pop  r12
    pop  rbx
    ret

; RAX=start sector, RDX=sector count of a validated other stream run.
; Return EAX=1 if any private target sector overlaps. Preserve census iterator.
nt_nr_overlaps:
    push rcx
    push rdi
    mov  r8, rax
    add  rdx, rax
    xor  ecx, ecx
    lea  rdi, [rel nt_nr_lbas]
.loop:
    mov  rax, [rdi + rcx*8]
    cmp  rax, r8
    jb   .next
    cmp  rax, rdx
    jb   .yes
.next:
    inc  ecx
    cmp  ecx, [rel nt_nr_sectors]
    jb   .loop
    xor  eax, eax
    jmp  .out
.yes:
    mov  eax, 1
.out:
    pop  rdi
    pop  rcx
    ret

nt_nr_mode: db 0
nt_nr_ready: db 0
nt_nr_child: dd 0
nt_nr_old_size: dq 0
nt_nr_lba: dq 0
nt_nr_capacity: dq 0
nt_nr_sectors: dd 0
nt_nr_lbas: times NT_NR_SECTORS dq 0
nt_nr_path: times (NT_MUT_PATH_MAX + 1) db 0
nt_nr_stage: times NT_NR_CAP db 0
nt_nr_expected: times NT_NR_CAP db 0
nt_nr_readback: times NT_NR_CAP db 0

; Complete bounded allocated FILE census: no stream other than this unnamed
; DATA may claim its allocation (including named metadata/index/security streams).
; Keep immutable raw snapshots under the same retry predicate. This subset caps
; initialized MFT at 128 records; it never treats a bitmap bit as ownership.
nt_nr_census:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    cmp  dword [rel nt_ns_records], 128
    ja   .no
    lea  rdi, [rel nt_nr_other_lbas]
    mov  ecx, 128*8
    xor  eax, eax
    rep  stosb
    xor  ebp, ebp
.records:
    cmp  ebp, [rel nt_ns_records]
    jae  .ok
    lea  rdi, [rel nt_ns_expected + 2*NT_RECBUF]
    bt   [rdi], ebp
    jnc  .next_record
    mov  edi, ebp
    call nt_ns_read_inactive
    test eax, eax
    jnz  .io
    lea  rbx, [rel nt_rec_buf]
    cmp  [rbx + 44], ebp
    jne  .no
    cmp  qword [rbx + 32], 0
    jne  .no                            ; no unseen extension segment ownership
    test word [rbx + 22], 1
    jnz  .active
    cmp  ebp, 12
    jb   .no
    cmp  ebp, 16
    jae  .no                            ; only reserved unused system identities
.active:
    mov  eax, [rbx + 24]
    cmp  eax, 1024
    ja   .no
    cmp  dword [rbx + 28], 1024
    jne  .no
    mov  r13d, eax
    sub  r13d, 8
    jc   .no
    movzx r12d, word [rbx + 20]
    cmp  r12d, 48
    jb   .no
    test r12d, 7
    jnz  .no
.attrs:
    cmp  r12d, r13d
    ja   .no
    cmp  dword [rbx + r12], -1
    je   .end
    cmp  dword [rbx + r12], NT_A_ATTRLIST
    je   .no                            ; never ignore out-of-record extents
    lea  eax, [r12 + 24]
    cmp  eax, r13d
    ja   .no
    mov  r14d, [rbx + r12 + 4]
    cmp  r14d, 24
    jb   .no
    test r14d, 7
    jnz  .no
    add  r14d, r12d
    jc   .no
    cmp  r14d, r13d
    ja   .no
    cmp  byte [rbx + r12 + 8], 0
    je   .resident
    cmp  byte [rbx + r12 + 8], 1
    jne  .no
    lea  eax, [r12 + 64]
    cmp  eax, r14d
    ja   .no
    cmp  qword [rbx + r12 + 16], 0
    jne  .no
    movzx eax, word [rbx + r12 + 32]
    cmp  eax, 64
    jb   .no
    add  eax, r12d
    cmp  eax, r14d
    jae  .no
    lea  rdi, [rbx + rax]
    lea  rcx, [rbx + r14]
    lea  rsi, [rel nt_runs]
    mov  edx, NT_MAX_RUNS
    call nt_decode_runlist
    test eax, eax
    jle  .no
    cmp  ebp, [rel nt_nr_child]
    jne  .other_stream
    cmp  dword [rbx + r12], NT_A_DATA
    jne  .other_stream
    cmp  byte [rbx + r12 + 9], 0
    je   .next_attr                     ; only the already-admitted target stream
.other_stream:
    mov  ecx, eax
    lea  rdi, [rel nt_runs]
.runs:
    mov  rsi, [rdi]
    test rsi, rsi
    js   .next_run                     ; sparse ranges own no physical clusters
    mov  rax, rsi
    imul rax, 8
    add  rax, [rel nt_part_lba]
    mov  rdx, [rdi + 8]
    imul rdx, 8
    call nt_nr_overlaps
    test eax, eax
    jnz  .no                            ; another allocated stream owns DATA
.next_run:
    add  rdi, 16
    dec  ecx
    jnz  .runs
    jmp  .next_attr
.resident:
    movzx eax, word [rbx + r12 + 20]
    cmp  eax, 24
    jb   .no
    add  eax, r12d
    add  eax, [rbx + r12 + 16]
    jc   .no
    cmp  eax, r14d
    ja   .no
.next_attr:
    mov  r12d, r14d
    jmp  .attrs
.end:
    cmp  r12d, r13d
    jne  .no
    ; Mutable child/parent and MFT/$Bitmap FILEs already have full expected
    ; images in nt_ns_current; snapshot every other allocated record here.
    cmp  ebp, [rel nt_nr_child]
    je   .next_record
    cmp  ebp, [rel nt_res_parent_ref]
    je   .next_record
    test ebp, ebp
    jz   .next_record
    cmp  ebp, 6
    je   .next_record
    mov  eax, ebp
    shl  eax, 10
    mov  rdx, rax
    lea  rdi, [rel nt_mft_runs]
    mov  esi, [rel nt_mft_nruns]
    call nt_vcn_to_lba
    cmp  rax, -2
    jae  .no
    test rcx, rcx
    jnz  .no
    cmp  rdx, 1024
    jb   .no
    lea  rdi, [rel nt_nr_other_lbas]
    mov  [rdi + rbp*8], rax
    mov  edi, ebp
    shl  edi, 10
    lea  rsi, [rel nt_nr_other_images]
    add  rdi, rsi
    lea  rsi, [rel nt_rec_buf]
    mov  edx, 1024
    call memcpy
    mov  edi, ebp
    shl  edi, 10
    lea  rsi, [rel nt_nr_other_images]
    add  rdi, rsi
    movzx eax, word [rdi + 4]
    mov  ax, [rdi + rax]
    mov  [rdi + 510], ax
    mov  [rdi + 1022], ax
.next_record:
    inc  ebp
    jmp  .records
.ok:
    xor  eax, eax
    jmp  .out
.io:
    mov  eax, -2
    jmp  .out
.no:
    mov  eax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

nt_nr_census_current:
    push rbx
    xor  ebx, ebx
.loop:
    cmp  ebx, [rel nt_ns_records]
    jae  .ok
    lea  rdi, [rel nt_nr_other_lbas]
    mov  rsi, [rdi + rbx*8]
    test rsi, rsi
    jz   .next
    mov  edx, 2
    lea  rcx, [rel nt_nr_other_readback]
    call nt_read
    test rax, rax
    jnz  .no
    call nt_save_authority
    test rax, rax
    jnz  .no
    call nt_rename_geometry
    test rax, rax
    jnz  .no
    mov  esi, ebx
    shl  esi, 10
    lea  rdi, [rel nt_nr_other_images]
    add  rsi, rdi
    lea  rdi, [rel nt_nr_other_readback]
    mov  edx, 1024
    call memcmp
    test rax, rax
    jnz  .no                            ; complete allocated-record custody
.next:
    inc  ebx
    jmp  .loop
.ok:
    xor  eax, eax
    jmp  .out
.no:
    mov  rax, -1
.out:
    pop  rbx
    ret

nt_nr_other_lbas: times 128 dq 0
nt_nr_other_images: times 128*1024 db 0
nt_nr_other_readback: times 1024 db 0

; Plain nonresident DELETE reuses namespace publish/retire and the existing
; bounded complete FILE census, without touching DATA bytes. Every actual
; allocated cluster must be disjoint from all metadata/ancestors and every
; other allocated stream. The staged volume map changes only target bits.
nt_nd_prepare:
    push rbx
    push r12
    mov  eax, [rel nt_ns_child]
    mov  [rel nt_nr_child], eax
    mov  rax, [rel nt_rename_parent_full]
    mov  [rel nt_res_parent_ref], rax
    call nt_nr_census
    test eax, eax
    jnz  .out                           ; -2 preserves uncertain I/O distinction
    mov  edi, 1                         ; released DATA sectors join the audit
    call nt_ns_windows
    test eax, eax
    jnz  .out
    xor  ebx, ebx
.slots:
    call nt_ns_wskip
    je   .slot_next                     ; windows audited in nt_ns_windows
    lea  rdi, [rel nt_ns_lbas]
    mov  rax, [rdi + rbx*8]
    lea  rdi, [rel nt_ns_sectors]
    mov  edx, [rdi + rbx*4]
    call nt_nr_overlaps
    test eax, eax
    jnz  .no                            ; never free allocation metadata
.slot_next:
    inc  ebx
    cmp  ebx, 6
    jb   .slots
    xor  ebx, ebx
.ancestors:
    lea  rdi, [rel nt_dir_lbas]
    mov  rax, [rdi + rbx*8]
    mov  edx, 2
    call nt_nr_overlaps
    test eax, eax
    jnz  .no
    inc  ebx
    cmp  ebx, [rel nt_dir_count]
    jb   .ancestors
    xor  ebx, ebx
.clusters:
    lea  rdi, [rel nt_nr_lbas]
    mov  rsi, [rdi + rbx*8]
    mov  edx, 8                        ; one full 4096-byte cluster at a time
    call nt_ns_volume_range
    test eax, eax
    jnz  .no                            ; allocation is required, never inferred
    mov  rax, rsi
    sub  rax, [rel nt_part_lba]
    shr  rax, 3
    call nt_ns_release                  ; release actual target cluster, no DATA write
    test eax, eax
    jnz  .no
    add  ebx, 8
    cmp  ebx, [rel nt_nr_sectors]
    jb   .clusters
    xor  eax, eax
    jmp  .out
.no:
    mov  eax, -1
.out:
    pop  r12
    pop  rbx
    ret

nt_nd_mode: db 0
nt_nd_ready: db 0
nt_nd_allocated: dd 0

; Read-only image capability query. No mount, media IO or authority change.
ntfs_disk_format_ops:
    lea  rax, [rel nt_ops]
    ret

; Lifetime identity only; never storage authority.
%macro WDATA_BSS_nt_late_selector 0
nt_sel_gpt: resb 1
nt_sel_active: resb 1
alignb 8
nt_sel_device: resq 1
nt_sel_identity: resq 5
nt_sel_primary: resb 96
nt_sel_again: resb 96
nt_sel_vbr: resb 512
%endmacro
WDATA_BSS_DEFER WDATA_BSS_nt_late_selector
