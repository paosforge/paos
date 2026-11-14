;; MODULE fs/fs_identify
;; LAYER 4
;; EXPORTS fs_identify_scan, fs_identify_refused_count, fs_identify_table, fs_identify_table_count, fs_identify_primary, fs_identify_primary_checked, fs_identify_single_gpt_checked
;; IMPORTS fs/blockdev, fs/vfs, boot/serial, core/lib/crc32
;; CAPS CAP_BLOCK_READ
;; OWNER saga:rcq20_filesystems
;; CONTEXT: bsp_only
; ============================================================================
; fs/fs_identify.asm — READ-ONLY identification of encrypted volumes
; (RCQ-20-format-refusal-S2, contract r2 0993be21; SPEC:461 "refused safely,
; with a useful explanation"). It never mounts, never writes, allocates
; nothing and does not touch the default disk: it only names BitLocker and
; LUKS volumes that no backend will mount.
;
; DISCOVERY (as exfat_disk's exf_scan_device): every healthy registered block
;   device with 512-byte logical sectors. LBA 0 is read into the scan buffer
;   and classified FIRST (SEC C1): a match is the superfloppy volume part=0
;   and ends that device. Otherwise, with 0xAA55 and a non-empty table, all
;   four MBR slots are prescanned: any type 0xEE makes the GPT authoritative
;   and no MBR slot is classified (a hybrid MBR never reports a volume twice).
;   Else MBR primaries 1..4 (types 0x00/0x05/0x0F/0x85 are not volumes).
;   GPT: 'EFI PART', entry size 128, count clamped to 128, entries LBA >= 2
;   and the whole array inside the device (overflow-safe), entries part=1..N.
;
; CLASSIFICATION: one sector per candidate, its first LBA, read into the
;   candidate buffer only (SEC C2). BitLocker: '-FVE-FS-' at bytes 3..10 and
;   0xAA55 at 510. LUKS: 'LUKS' BA BE at bytes 0..5 and a big-endian version
;   1 or 2 at byte 6. Anything else is not reported.
;
; SKIP VS END (D1d): a candidate whose range fails the walk's pre-check (zero
;   start or length, end beyond the device, GPT first 0, last < first, last
;   past the device) is SKIPPED, counted in fs_identify_skipped, and the walk
;   goes on. A read error, or an LBA the read helper's own in-device check
;   refuses (counted in fs_identify_read_refused; the walk validates first,
;   so it stays 0), ENDS that device's walk; nothing is printed for it.
;   Per device at most 1 + 1 + 32 + 1 per candidate (<= 4 MBR, <= 128 GPT)
;   single-sector reads.
;
; OUTPUT, one line per identified volume:
;   [PAOS64] [fs.refused] dev=<dev.name or ?> part=<k> format=<bitlocker|luks>
;   reason=encrypted (not mounted: PaOS does not unlock encrypted volumes)
;   No summary line. fs_identify_table keeps the first FSID_TABLE_MAX rows;
;   fs_identify_refused_count counts every identified volume. A row's dev* is
;   an identity hint captured at scan time with blk_info.media_generation: a
;   consumer resolves the device through the registry and the generation and
;   never dereferences a stale dev*.
;
; CONCURRENCY: BSP only, boot time (vfs_selftest), non-reentrant; the two
;   sector buffers and the counters are module globals held across blk_read.
; ============================================================================

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place

FSID_TABLE_MAX     equ 8
FSID_GPT_MAX       equ 128
FSID_FMT_BITLOCKER equ 1
FSID_FMT_LUKS      equ 2

; One fs_identify_table row (SR-S2-2: pinned by the size guard below).
struc fsid_row
  .dev:         resq 1   ; dev* at scan time: identity hint only, never dereferenced later
  .generation:  resq 1   ; blk_info.media_generation at scan time
  .first_lba:   resq 1   ; the volume's first LBA (0 for a superfloppy)
  .part:        resd 1   ; 0 superfloppy, 1..4 MBR slot, 1..N GPT entry index
  .scheme:      resd 1   ; FS_SCHEME_*
  .format:      resd 1   ; FSID_FMT_*
  .reserved:    resd 1
endstruc
%if fsid_row_size != 40 || fsid_row.first_lba != 16 || fsid_row.part != 24 || fsid_row.format != 32
    %error "fsid_row: the fs_identify_table row layout moved"
%endif

; fs_identify_single_gpt_checked(RDI=registered dev*, ESI=1 BASIC/2 LINUX,
; RCX=out96, R8=mandatory no-argument original-identity guard) -> 0/-1.
; Additive BSP, synchronous, non-reentrant read-only query. The guard must
; re-resolve registry membership before dereferencing the original DEV and
; validate its full incarnation/eligibility before/after each transfer.
; Standard 512-byte GPT only: exact 92-byte headers, 128x128 array, one used
; entry, zero attributes, exact requested type, primary and backup agreement.
; out96: original out48 (kind replaces MBR type), disk GUID16, part GUID16,
; primary/array/backup CRC32 and reserved0. No mount or storage authority.
fs_identify_single_gpt_checked:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov r12,rdi
    mov r13,rcx
    mov r14d,esi
    mov [rel fsid_sg_guard],r8
    test rcx,rcx
    jz .no
    mov rdi,rcx
    xor eax,eax
    mov ecx,12
    cld
    rep stosq
    test r8,r8
    jz .fail
    cmp r14d,1
    jb .fail
    cmp r14d,2
    ja .fail
    lea rdi,[rel fsid_sg_result]
    xor eax,eax
    mov ecx,12
    rep stosq
    mov rdi,r12
    xor esi,esi
    xor edx,edx
    lea rcx,[rel fsid_sg_result]
    call fs_identify_primary_checked
    test rax,rax
    jnz .fail
    cmp dword [rel fsid_sg_result+36],FS_SCHEME_GPT
    jne .fail
    call fsid_sg_call_guard
    test rax,rax
    jnz .fail
    mov rax,[r12+dev.info]
    mov r15,[rax+blk_info.lba_max]
    inc r15
    cmp r15,68
    jb .fail
    ; Original checked discovery precedes this strict independent table walk.
    xor esi,esi
    lea rdi,[rel fsid_sg_sector]
    call fsid_sg_read
    test rax,rax
    jnz .fail
    cmp word [rel fsid_sg_sector+510],0xaa55
    jne .fail
    cmp byte [rel fsid_sg_sector+446],0
    jne .fail
    cmp byte [rel fsid_sg_sector+450],0xee
    jne .fail
    cmp dword [rel fsid_sg_sector+454],1
    jne .fail
    lea rax,[r15-1]
    mov edx,0xffffffff
    cmp rax,rdx
    cmova rax,rdx
    cmp [rel fsid_sg_sector+458],eax
    jne .fail
    lea rdi,[rel fsid_sg_sector+462]
    xor eax,eax
    mov ecx,48
    repe scasb
    jne .fail
    mov eax,[rel fsid_sg_sector+440]
    mov [rel fsid_sg_result+44],eax
    mov esi,1
    lea rdi,[rel fsid_sg_header]
    call fsid_sg_read
    test rax,rax
    jnz .fail
    lea rdi,[rel fsid_sg_header]
    mov esi,1
    lea rdx,[r15-1]
    mov ecx,2
    call fsid_sg_header_check
    test rax,rax
    jnz .fail
    xor ebx,ebx
.array:
    mov rdi,rbx
    shl rdi,9
    lea rax,[rel fsid_sg_entries]
    add rdi,rax
    lea rsi,[rbx+2]
    call fsid_sg_read
    test rax,rax
    jnz .fail
    inc ebx
    cmp ebx,32
    jb .array
    lea rdi,[rel fsid_sg_entries]
    mov esi,16384
    call hotpatch_crc32
    cmp eax,[rel fsid_sg_header+88]
    jne .fail
    mov [rel fsid_sg_result+84],eax
    mov eax,[rel fsid_sg_header+16]
    mov [rel fsid_sg_result+80],eax
    mov rax,[rel fsid_sg_header+56]
    mov [rel fsid_sg_result+48],rax
    mov rax,[rel fsid_sg_header+64]
    mov [rel fsid_sg_result+56],rax
    lea rbx,[rel fsid_sg_entries]
    xor ebp,ebp
    xor r10d,r10d
.entry:
    mov rax,[rbx]
    or rax,[rbx+8]
    jnz .used
    ; An unused type with residual entry bytes is malformed, not absent.
    mov rdi,rbx
    xor eax,eax
    mov ecx,128
    repe scasb
    jne .fail
    jmp .next
.used:
    inc ebp
    cmp ebp,1
    jne .fail
    lea rdi,[rel fsid_sg_basic]
    cmp r14d,1
    je .type
    lea rdi,[rel fsid_sg_linux]
.type:
    mov rax,[rdi]
    cmp [rbx],rax
    jne .fail
    mov rax,[rdi+8]
    cmp [rbx+8],rax
    jne .fail
    mov rax,[rbx+16]
    or rax,[rbx+24]
    jz .fail
    cmp qword [rbx+48],0
    jne .fail
    mov rax,[rbx+32]
    cmp rax,[rel fsid_sg_header+40]
    jb .fail
    mov rdx,[rbx+40]
    cmp rdx,rax
    jb .fail
    cmp rdx,[rel fsid_sg_header+48]
    ja .fail
    sub rdx,rax
    inc rdx
    cmp rax,[rel fsid_sg_result+16]
    jne .fail
    cmp rdx,[rel fsid_sg_result+24]
    jne .fail
    lea eax,[r10d+1]
    cmp eax,[rel fsid_sg_result+32]
    jne .fail
    mov rax,[rbx+16]
    mov [rel fsid_sg_result+64],rax
    mov rax,[rbx+24]
    mov [rel fsid_sg_result+72],rax
.next:
    add rbx,128
    inc r10d
    cmp r10d,128
    jb .entry
    cmp ebp,1
    jne .fail
    lea rsi,[r15-1]
    lea rdi,[rel fsid_sg_sector]
    call fsid_sg_read
    test rax,rax
    jnz .fail
    lea rdi,[rel fsid_sg_sector]
    lea rsi,[r15-1]
    mov edx,1
    lea rcx,[r15-33]
    call fsid_sg_header_check
    test rax,rax
    jnz .fail
    ; Header roles differ; all shared identity/geometry/array fields agree.
    lea rdi,[rel fsid_sg_sector+40]
    lea rsi,[rel fsid_sg_header+40]
    mov ecx,4
    repe cmpsq
    jne .fail
    mov eax,[rel fsid_sg_sector+88]
    cmp eax,[rel fsid_sg_result+84]
    jne .fail
    mov eax,[rel fsid_sg_sector+16]
    mov [rel fsid_sg_result+88],eax
    xor ebx,ebx
.backup:
    lea rsi,[r15-33]
    add rsi,rbx
    lea rdi,[rel fsid_sg_sector]
    call fsid_sg_read
    test rax,rax
    jnz .fail
    mov rsi,rbx
    shl rsi,9
    lea rax,[rel fsid_sg_entries]
    add rsi,rax
    lea rdi,[rel fsid_sg_sector]
    mov ecx,64
    repe cmpsq
    jne .fail
    inc ebx
    cmp ebx,32
    jb .backup
    call fsid_sg_call_guard
    test rax,rax
    jnz .fail
    mov [rel fsid_sg_result+40],r14d
    mov rdi,r13
    lea rsi,[rel fsid_sg_result]
    mov ecx,12
    rep movsq
    xor eax,eax
    jmp .out
.fail:
    mov rdi,r13
    xor eax,eax
    mov ecx,12
    rep stosq
.no:
    mov rax,-1
.out:
    mov qword [rel fsid_sg_guard],0
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Validate a complete standard header including its own CRC and zero padding.
; RDI=header, RSI=current, RDX=alternate, RCX=array LBA; R15=sectors.
fsid_sg_header_check:
    push rbx
    push rbp
    mov rbx,rdi
    mov rax,'EFI PART'
    cmp [rbx],rax
    jne .no
    cmp dword [rbx+8],0x10000
    jne .no
    cmp dword [rbx+12],92
    jne .no
    cmp dword [rbx+20],0
    jne .no
    cmp [rbx+24],rsi
    jne .no
    cmp [rbx+32],rdx
    jne .no
    cmp [rbx+72],rcx
    jne .no
    cmp qword [rbx+40],34
    jb .no
    mov rax,[rbx+48]
    cmp rax,[rbx+40]
    jb .no
    lea rdx,[r15-34]
    cmp rax,rdx
    ja .no
    mov rax,[rbx+56]
    or rax,[rbx+64]
    jz .no
    cmp dword [rbx+80],128
    jne .no
    cmp dword [rbx+84],128
    jne .no
    lea rdi,[rbx+92]
    xor eax,eax
    mov ecx,420
    repe scasb
    jne .no
    mov ebp,[rbx+16]
    mov dword [rbx+16],0
    mov rdi,rbx
    mov esi,92
    call hotpatch_crc32
    mov [rbx+16],ebp
    cmp eax,ebp
    jne .no
    xor eax,eax
    jmp .out
.no:
    mov rax,-1
.out:
    pop rbp
    pop rbx
    ret

; One sector only, preserving original-identity callback around native IO.
fsid_sg_read:
    call fsid_sg_call_guard
    test rax,rax
    jnz .no
    cmp rsi,r15
    jae .no
    mov rcx,rdi
    mov rdi,r12
    mov edx,1
    call blk_read
    test rax,rax
    jnz .no
    call fsid_sg_call_guard
    test rax,rax
    jnz .no
    ret
.no:
    mov rax,-1
    ret
fsid_sg_call_guard:
    push rdi
    push rsi
    push rdx
    push rcx
    push r8
    push r9
    push r10
    push r11
    call [rel fsid_sg_guard]
    pop r11
    pop r10
    pop r9
    pop r8
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    ret

fsid_sg_basic: dq 0x4433b9e5ebd0a0a2,0xc79926b7b668c087
fsid_sg_linux: dq 0x477284830fc63daf,0xe47d47d8693d798e
fsid_sg_code_end:
; Separate private bounded workspace, preceding the unchanged inventory budget.
%macro WDATA_fs_fs_identify_sg_bss 0
alignb 8
fsid_sg_bss_begin:
fsid_sg_guard: resq 1
fsid_sg_result: resb 96
fsid_sg_header: resb 512
fsid_sg_sector: resb 512
fsid_sg_entries: resb 16384
fsid_sg_bss_end:
%endmacro
WDATA_BSS_DEFER WDATA_fs_fs_identify_sg_bss

; fs_identify_primary(RDI=registered dev*, RSI=first, RDX=count, RCX=out48)
; -> 0/-1. Synchronous BSP read-only exact primary query, never authority.
; out48 = dev, generation, first, count (u64), slot, scheme, MBR type, MBR signature (u32).
; Refusal clears output; encrypted/superfloppy/extended/overlap are not admitted.
; GPT consumers must additionally use their CRC/type/attribute validators.
fs_identify_primary:
    xor r8d,r8d
; Same query with R8 = optional no-argument 0/-1 registry identity guard.
; BSP non-reentrant; checked reads validate before/after transfer. This only
; refuses stale reads; it grants no storage authority. Existing API uses 0.
fs_identify_primary_checked:
    mov [rel fsid_primary_guard],r8
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12,rdi
    mov r13,rcx
    test rcx,rcx
    jz .no
    mov [rel fsid_primary_first],rsi
    mov [rel fsid_primary_count],rdx
    mov rdi,rcx
    xor eax,eax
    mov ecx,6
    cld
    rep stosq
    mov [rel fsid_primary_out],r13
    mov dword [rel fsid_primary_matches],0
    mov dword [rel fsid_primary_bad],0
    mov rax,rdx
    or rax,rsi
    jz .discover
    test rdx,rdx
    jz .clear
    test rsi,rsi
    jz .clear
.discover:
    xor ebx,ebx
.member:
    mov rdi,rbx
    xor esi,esi
    xor edx,edx
    call blk_iter_after
    test rax,rax
    jz .clear
    mov rbx,rax
    cmp rax,r12
    jne .member
    mov rdi,r12
    call fsid_scan_device
    cmp dword [rel fsid_primary_matches],1
    jne .clear
    cmp dword [rel fsid_primary_bad],0
    jne .clear
    call fsid_query_guard
    test rax,rax
    jnz .clear
    mov rax,[r12+dev.info]
    mov rax,[rax+blk_info.media_generation]
    cmp [r13+8],rax
    jne .clear
    mov qword [rel fsid_primary_out],0
    xor eax,eax
    jmp .out
.clear:
    mov rdi,r13
    xor eax,eax
    mov ecx,6
    rep stosq
    mov qword [rel fsid_primary_out],0
.no:
    mov rax,-1
.out:
    mov qword [rel fsid_primary_guard],0
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Recognise filesystem VBRs BEFORE interpreting bytes 446-509 as MBR slots.
; Encrypted signatures use fsid_classify first. Conservative FAT BPB detection
; also covers boot code without an advisory FAT32 label. False refusal writes
; nothing; a plausible boot-code partition must never become a writer lease.
fsid_boot_sector:
    mov rax,'EXFAT   '
    cmp [rdi+3],rax
    je .yes
    mov rax,'NTFS    '
    cmp [rdi+3],rax
    je .yes
    cmp byte [rdi],0xeb
    je .fat
    cmp byte [rdi],0xe9
    jne .no
.fat:
    cmp word [rdi+11],512
    je .bpb
    cmp word [rdi+11],1024
    je .bpb
    cmp word [rdi+11],2048
    je .bpb
    cmp word [rdi+11],4096
    jne .no
.bpb:
    movzx eax,byte [rdi+13]
    test eax,eax
    jz .no
    lea edx,[eax-1]
    test eax,edx
    jnz .no
    cmp word [rdi+14],0
    je .no
    cmp byte [rdi+16],0
    je .no
.yes:
    mov eax,1
    ret
.no:
    xor eax,eax
    ret

; Exact-query MBR preflight over all four slots. No extended/hybrid/active
; container, malformed neighbour or intersecting primary can hide in a lease.
fsid_primary_mbr_check:
    cmp dword [rel fsid_scan_buf+440],0
    je .no
    lea rdi,[rel fsid_scan_buf+446]
    mov ecx,4
.next:
    movzx eax,byte [rdi+4]
    test eax,eax
    jz .empty
    cmp byte [rdi],0
    jne .no
    cmp al,5
    je .no
    cmp al,0x0f
    je .no
    cmp al,0x85
    je .no
    cmp al,0xee
    je .no
    mov eax,[rdi+8]
    mov edx,[rdi+12]
    test eax,eax
    jz .no
    test edx,edx
    jz .no
    add rdx,rax
    cmp rdx,r15
    ja .no
    ; Reject overlap with any earlier nonempty slot, even if neither is wanted.
    lea rsi,[rel fsid_scan_buf+446]
.overlap:
    cmp rsi,rdi
    je .advance
    cmp byte [rsi+4],0
    je .prior
    mov r8d,[rsi+8]
    mov r9d,[rsi+12]
    add r9,r8
    cmp rax,r9
    jae .prior
    cmp r8,rdx
    jb .no
.prior:
    add rsi,16
    jmp .overlap
.empty:
    mov rax,[rdi]
    or rax,[rdi+8]
    jnz .no
.advance:
    add rdi,16
    dec rcx
    jnz .next
    xor eax,eax
    ret
.no:
    mov dword [rel fsid_primary_bad],1
    mov eax,-1
    ret

; ---------------------------------------------------------------------------
; fs_identify_scan() -> RAX = number of identified (refused) volumes.
;   Called once from vfs_selftest after exfat_disk_register; the caller
;   ignores RAX and has no failure path to take.
; ---------------------------------------------------------------------------
fs_identify_scan:
    push rbx
    push r12
    push r13
    push r14
    push r15
    xor  eax, eax
    mov  [rel fs_identify_refused_count], eax
    mov  [rel fs_identify_table_count], eax
    mov  [rel fs_identify_skipped], eax
    mov  [rel fs_identify_read_refused], eax
    lea  rdi, [rel fs_identify_table]
    mov  ecx, FSID_TABLE_MAX * fsid_row_size / 8
    rep  stosq
    xor  ebx, ebx                        ; previous dev*
.dev:
    mov  rdi, rbx
    xor  esi, esi                        ; every healthy device
    xor  edx, edx
    call blk_iter_after
    test rax, rax
    jz   .done
    mov  rbx, rax
    mov  rdi, rax
    call fsid_scan_device
    jmp  .dev
.done:
    mov  eax, [rel fs_identify_refused_count]
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; fsid_scan_device(RDI=dev*). Holds R12 = dev and R15 = device sectors for
;   fsid_read / fsid_candidate / fsid_report.
fsid_scan_device:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    call fsid_query_guard
    test rax,rax
    jnz .out
    call blk_identify
    test rax, rax
    jnz  .out
    call fsid_query_guard
    test rax,rax
    jnz .out
    mov  rax, [r12 + dev.info]
    test rax, rax
    jz   .out
    cmp  dword [rax + blk_info.sector_size], 512
    jne  .out                            ; 512-byte device arithmetic only (as exfat/ext4)
    mov  r15, [rax + blk_info.lba_max]
    inc  r15                             ; device sectors
    jz   .out
    xor  esi, esi
    lea  rdi, [rel fsid_scan_buf]
    call fsid_read
    test rax, rax
    jnz  .out
    ; SEC C1: LBA 0 is a candidate volume before any byte of it is read as a table
    lea  rdi, [rel fsid_scan_buf]
    call fsid_classify
    test eax, eax
    jz   .table
    cmp qword [rel fsid_primary_out],0
    jne .out
    mov  ecx, eax
    xor  esi, esi                        ; part 0
    xor  edx, edx                        ; first LBA 0
    mov  r8d, FS_SCHEME_SUPERFLOPPY
    call fsid_report
    jmp  .out                            ; an identified superfloppy has no table
.table:
    lea rdi,[rel fsid_scan_buf]
    call fsid_boot_sector
    test eax,eax
    jnz .out
    cmp  word [rel fsid_scan_buf + 510], 0xAA55
    jne  .out
    mov  rax, [rel fsid_scan_buf + 446]
    or   rax, [rel fsid_scan_buf + 454]
    or   rax, [rel fsid_scan_buf + 462]
    or   rax, [rel fsid_scan_buf + 470]
    or   rax, [rel fsid_scan_buf + 478]
    or   rax, [rel fsid_scan_buf + 486]
    or   rax, [rel fsid_scan_buf + 494]
    or   rax, [rel fsid_scan_buf + 502]
    jz   .out
    ; SEC C3: prescan all four slots; any 0xEE means the GPT alone is walked
    xor  r13d, r13d
.prescan:
    mov  eax, r13d
    shl  eax, 4
    lea  rbx, [rel fsid_scan_buf + 446]
    cmp  byte [rbx + rax + 4], 0xEE
    je   .gpt
    inc  r13d
    cmp  r13d, 4
    jb   .prescan
    cmp qword [rel fsid_primary_out],0
    je .mbr_start
    ; Refuse a GPT header hidden behind a non-protective/hybrid MBR.
    mov esi,1
    lea rdi,[rel fsid_cand_buf]
    call fsid_read
    test rax,rax
    jnz .out
    mov rax,'EFI PART'
    cmp [rel fsid_cand_buf],rax
    jne .plain_mbr
    mov dword [rel fsid_primary_bad],1
    jmp .out
.plain_mbr:
    call fsid_primary_mbr_check
    test eax,eax
    jnz .out
.mbr_start:
    xor  r13d, r13d
.mbr:
    cmp  r13d, 4
    jae  .mbr_done
    mov  eax, r13d
    shl  eax, 4
    lea  rbx, [rel fsid_scan_buf + 446]
    add  rbx, rax
    movzx eax, byte [rbx + 4]
    test al, al
    jz   .mbr_next
    cmp  al, 0x05                        ; extended containers hold no volume
    je   .mbr_next
    cmp  al, 0x0F
    je   .mbr_next
    cmp  al, 0x85
    je   .mbr_next
    mov  esi, [rbx + 8]                  ; start (zero-extended)
    mov  edx, [rbx + 12]                 ; length (zero-extended)
    test esi, esi
    jz   .mbr_skip
    test edx, edx
    jz   .mbr_skip
    lea  rax, [rsi + rdx]                ; 64-bit end: u32 start + u32 length never wraps
    cmp  rax, r15
    ja   .mbr_skip
    lea  edi, [r13d + 1]                 ; part = slot 1..4
    mov  r8d, FS_SCHEME_MBR
    call fsid_candidate
    test rax, rax
    jnz  .out                            ; MBR: a read error ends the device
    jmp  .mbr_next
.mbr_skip:
    inc  dword [rel fs_identify_skipped]
.mbr_next:
    inc  r13d
    jmp  .mbr
.mbr_done:
    jmp  .out                            ; MBR and GPT are never both walked
.gpt:
    mov  esi, 1
    lea  rdi, [rel fsid_scan_buf]
    call fsid_read
    test rax, rax
    jnz  .out
    mov  rax, 0x5452415020494645         ; "EFI PART"
    cmp  [rel fsid_scan_buf], rax
    jne  .out
    cmp  dword [rel fsid_scan_buf + 84], 128
    jne  .out                            ; entry size exactly 128
    mov  eax, [rel fsid_scan_buf + 80]
    cmp  eax, FSID_GPT_MAX
    jbe  .count_ok
    mov  eax, FSID_GPT_MAX
.count_ok:
    mov  [rel fsid_gpt_count], eax
    mov  r14, [rel fsid_scan_buf + 72]   ; entries LBA
    cmp  r14, 2
    jb   .out                            ; never LBA 0 or the header itself
    add  eax, 3
    shr  eax, 2                          ; ceil(count / 4) array sectors, <= 32
    mov  rdx, r14
    add  rdx, rax
    jc   .out                            ; SR-S2-3: an entries LBA near 2^64 cannot wrap past the check
    cmp  rdx, r15
    ja   .out                            ; the whole array lies inside the device
    xor  r13d, r13d
.gpt_entry:
    cmp  r13d, [rel fsid_gpt_count]
    jae  .out
    test r13d, 3
    jnz  .have_sector
    mov  esi, r13d
    shr  esi, 2
    add  rsi, r14
    lea  rdi, [rel fsid_scan_buf]
    call fsid_read
    test rax, rax
    jnz  .out
.have_sector:
    mov  eax, r13d
    and  eax, 3
    shl  eax, 7
    lea  rbx, [rel fsid_scan_buf]
    add  rbx, rax
    mov  rax, [rbx]
    or   rax, [rbx + 8]
    jz   .gpt_next                       ; unused entry: not a candidate
    mov  rsi, [rbx + 32]                 ; first LBA
    mov  rdx, [rbx + 40]                 ; last LBA (inclusive)
    test rsi, rsi
    jz   .gpt_skip
    cmp  rdx, rsi
    jb   .gpt_skip
    cmp  rdx, r15
    jae  .gpt_skip
    lea  edi, [r13d + 1]                 ; part = entry index 1..N
    mov  r8d, FS_SCHEME_GPT
    sub rdx,rsi
    inc rdx
    call fsid_candidate
    test rax, rax
    jnz  .out                            ; GPT: a read error ends the device
    jmp  .gpt_next
.gpt_skip:
    inc  dword [rel fs_identify_skipped]
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

; fsid_candidate(RSI=first LBA, EDI=part, R8D=scheme; R12=dev, R15=sectors)
;   -> RAX 0, or -1 on a read error. The candidate's first sector goes to
;   fsid_cand_buf only (SEC C2): the scan buffer being walked is never touched.
fsid_candidate:
    push rbp
    push rbx
    mov rbp,rdx
    push r13
    push r14
    mov  rbx, rsi
    mov  r13d, edi
    mov  r14d, r8d
    lea  rdi, [rel fsid_cand_buf]        ; SEC C2: never the scan buffer being walked
    call fsid_read
    test rax, rax
    jnz  .out
    lea  rdi, [rel fsid_cand_buf]        ; classified from the candidate buffer only
    call fsid_classify
    cmp qword [rel fsid_primary_out],0
    je .report
    test eax,eax
    jnz .query_skip
    mov rax,[rel fsid_primary_first]
    or rax,[rel fsid_primary_count]
    jz .match
    cmp rbx,[rel fsid_primary_first]
    jne .out
    cmp rbp,[rel fsid_primary_count]
    jne .out
.match:
    inc dword [rel fsid_primary_matches]
    mov rdi,[rel fsid_primary_out]
    mov [rdi],r12
    mov rax,[r12+dev.info]
    mov rax,[rax+blk_info.media_generation]
    test rax,rax
    jz .invalid
    mov [rdi+8],rax
    mov [rdi+16],rbx
    mov [rdi+24],rbp
    mov [rdi+32],r13d
    mov [rdi+36],r14d
    cmp r14d,FS_SCHEME_MBR
    jne .query_skip
    mov eax,r13d
    dec eax
    shl eax,4
    lea rdx,[rel fsid_scan_buf+446]
    movzx eax,byte [rdx+rax+4]
    mov [rdi+40],eax
    mov eax,[rel fsid_scan_buf+440]
    mov [rdi+44],eax
.query_skip:
    xor eax,eax
    jmp .out
.invalid:
    mov dword [rel fsid_primary_bad],1
    jmp .out
.report:
    test eax,eax
    jz .out
    mov  ecx, eax
    mov  esi, r13d
    mov  rdx, rbx
    mov  r8d, r14d
    call fsid_report
    xor  eax, eax
.out:
    pop  r14
    pop  r13
    pop  rbx
    pop rbp
    ret

; fsid_read(RDI=buf, RSI=lba; R12=dev, R15=sectors) -> RAX 0 / -1.
;   Exactly one sector through blk_read, after an in-device check.
fsid_read:
    push rbx
    call fsid_query_guard
    test rax,rax
    jnz .fail
    cmp  rsi, r15
    jae  .refused
    mov  rcx, rdi
    mov  rdi, r12
    mov  edx, 1                          ; one sector per read (D1b/D1d)
    call blk_read
    test rax, rax
    jnz  .fail
    call fsid_query_guard
    test rax,rax
    jnz .fail
    pop  rbx
    ret
.refused:
    inc  dword [rel fs_identify_read_refused]
.fail:
    mov dword [rel fsid_primary_bad],1
    mov  rax, -1
    pop  rbx
    ret

; Preserve IO arguments and the scan's volatile values around caller guard.
fsid_query_guard:
    cmp qword [rel fsid_primary_guard],0
    je .ordinary
    push rdi
    push rsi
    push rdx
    push rcx
    push r8
    push r9
    push r10
    push r11
    call [rel fsid_primary_guard]
    pop r11
    pop r10
    pop r9
    pop r8
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    ret
.ordinary:
    xor eax,eax
    ret

; fsid_classify(RDI=sector) -> EAX = FSID_FMT_* / 0. Reads bytes 0..511 only.
fsid_classify:
    mov  rax, '-FVE-FS-'
    cmp  [rdi + 3], rax
    jne  .luks
    cmp  word [rdi + 510], 0xAA55
    jne  .none
    mov  eax, FSID_FMT_BITLOCKER
    ret
.luks:
    cmp  dword [rdi], 0x534B554C         ; "LUKS"
    jne  .none
    cmp  word [rdi + 4], 0xBEBA          ; BA BE
    jne  .none
    movzx eax, word [rdi + 6]
    rol  ax, 8                           ; big-endian version
    cmp  eax, 1
    je   .luks_ok
    cmp  eax, 2
    jne  .none
.luks_ok:
    mov  eax, FSID_FMT_LUKS
    ret
.none:
    xor  eax, eax
    ret

; fsid_report(ESI=part, RDX=first LBA, ECX=format, R8D=scheme; R12=dev)
;   Counts the volume, fills a table row while one is free, prints one line.
fsid_report:
    push rbx
    push r13
    push r14
    mov  r13d, esi
    mov  r14d, ecx
    inc  dword [rel fs_identify_refused_count]
    mov  eax, [rel fs_identify_table_count]
    cmp  eax, FSID_TABLE_MAX
    jae  .print                          ; the table saturates; the count does not
    imul eax, eax, fsid_row_size
    lea  rbx, [rel fs_identify_table]
    add  rbx, rax
    mov  [rbx + fsid_row.dev], r12
    mov  rax, [r12 + dev.info]
    mov  rax, [rax + blk_info.media_generation]
    mov  [rbx + fsid_row.generation], rax
    mov  [rbx + fsid_row.first_lba], rdx
    mov  [rbx + fsid_row.part], r13d
    mov  [rbx + fsid_row.scheme], r8d
    mov  [rbx + fsid_row.format], r14d
    inc  dword [rel fs_identify_table_count]
.print:
    call fsid_emit
    pop  r14
    pop  r13
    pop  rbx
    ret

; fsid_emit(R12=dev, R13D=part, R14D=format): the one [fs.refused] line.
fsid_emit:
    sub  rsp, 8
    lea  rdi, [rel str_fsid_refused]
    call serial_string
    mov  rdi, [r12 + dev.name]
    test rdi, rdi
    jnz  .name
    lea  rdi, [rel str_fsid_anon]
.name:
    call serial_string
    lea  rdi, [rel str_fsid_part]
    call serial_string
    mov  edi, r13d
    call fsid_emit_dec
    lea  rdi, [rel str_fsid_format]
    call serial_string
    lea  rdi, [rel str_fsid_bitlocker]
    cmp  r14d, FSID_FMT_BITLOCKER
    je   .fmt
    lea  rdi, [rel str_fsid_luks]
.fmt:
    call serial_string
    lea  rdi, [rel str_fsid_reason]
    call serial_string
    add  rsp, 8
    ret

; fsid_emit_dec(EDI=value): unsigned decimal (boot/serial has no decimal printer).
fsid_emit_dec:
    sub  rsp, 24
    lea  rsi, [rsp + 15]
    mov  byte [rsi], 0
    mov  eax, edi
    mov  ecx, 10
.digit:
    xor  edx, edx
    div  ecx
    add  dl, '0'
    dec  rsi
    mov  [rsi], dl
    test eax, eax
    jnz  .digit
    mov  rdi, rsi
    call serial_string
    add  rsp, 24
    ret

; ---- read-only data ----
str_fsid_refused:    db "[PAOS64] [fs.refused] dev=", 0
str_fsid_anon:       db "?", 0
str_fsid_part:       db " part=", 0
str_fsid_format:     db " format=", 0
str_fsid_bitlocker:  db "bitlocker", 0
str_fsid_luks:       db "luks", 0
str_fsid_reason:     db " reason=encrypted (not mounted: PaOS does not unlock encrypted volumes)", 13, 10, 0

; Zero-initialised state (core/abi/wdata.inc WDATA_BSS_DEFER). The table is last.
%macro WDATA_fs_fs_identify_bss1 0
fs_identify_refused_count: resd 1
fs_identify_table_count:   resd 1
fs_identify_skipped:       resd 1    ; candidates skipped by the walk's range pre-check
fs_identify_read_refused:  resd 1    ; LBAs the read helper refused (0 unless the walk is wrong)
fsid_gpt_count:            resd 1
alignb 8
fsid_primary_guard: resq 1
fsid_primary_out: resq 1
fsid_primary_first: resq 1
fsid_primary_count: resq 1
fsid_primary_matches: resd 1
fsid_primary_bad: resd 1
fsid_scan_buf:             resb 512  ; LBA 0, the GPT header, the current GPT entry sector
fsid_cand_buf:             resb 512  ; each candidate's first sector, nothing else (SEC C2)
fs_identify_table:         resb FSID_TABLE_MAX * fsid_row_size
%endmacro
WDATA_BSS_DEFER WDATA_fs_fs_identify_bss1
