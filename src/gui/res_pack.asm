;; MODULE gui/res_pack
;; LAYER 6
;; EXPORTS res_prel1_admit, res_pack_open, res_pack_info, res_pack_page, res_pack_read_whole, res_pack_close, res_pack_prel1_gen, res_pack_artifact_source
;; IMPORTS fs/vfs, core/lib/sha256, core/lib/mem, bootmgr/rsa2048_verify, boot/boot_v2_handoff, svc/command_auth, boot/serial, gui/res_pack_image
;; CAPS
;; OWNER rc-boot-claude
;; CONTEXT: bsp_only
; gui/res_pack.asm — RCQ-38 PREL1 native page admission (boot-evidence/
; 20261010-rcq38-prel1-page-admission: DESIGN fcef9597 + AMENDMENT_R1 ed4a2a18
; + AMENDMENT_R2 2b7a2c76 + AMENDMENT_R3 0604c527; rc-sec 40f28460).
;
; ONE owner-signed record, PREL1, lists every resource artifact: name, kind,
; exact bytes, whole-artifact SHA-256, and for paged kinds the length and
; SHA-256 of the artifact's flat PPGH1 page table. Storage is untrusted:
; authenticity comes only from the signature over PREL1 and the hashes it
; carries. Nothing here trusts a byte it has not first compared:
;   - PREL1: shape -> RSA (compiled owner modulus) -> key id -> generation floor
;     and directory equality -> image_text_digest (v1: the compiled EMPTY
;     constant) -> every row byte. Any failure refuses that generation.
;   - a page table is read whole (length from PREL1, never its own header),
;     hashed, compared, and only then its header is checked against the row.
;   - a page is read ONCE straight into the caller's 4 KiB slot, hashed in
;     place over its exact length and compared with the verified table. A
;     mismatch or read error wipes the slot and latches the artifact for the
;     boot (E_UNAVAILABLE with no I/O after that).
;
; Source: EFI/PaOS/res/<gen>/ on the ESP PaOS booted from (rc-sec 15:53:40 (3)).
; <gen> is 1..8 decimal digits with no leading zero; the newest generation that
; admits wins, else the next lower, at most 2 attempts, decided once per boot
; (rc-sec (2)). The boot ESP is the read-only second FAT context selected by
; its partition GUID (rc-fs G1b, vfs_open_boot_esp). rp_locate opens it once,
; inside the decided-once admission, only when BOOT found exactly one GPT
; HardDrive node on the loaded image's device (boot_esp_part_guid_ok == 1;
; rc-boot 2026-10-17 15:24:05). Any other value, or vfs -1, is no volume:
; E_NO_VOLUME, reason absent, image fallback. rp_vol_ok is set only by
; rp_locate (and by the host harness). Every byte read through the handle is
; untrusted and authenticated by the PREL1 signature and hashes below (rc-sec
; g1: 'authenticates').
;
; RCQ-38 I1 join (root 2026-10-16 20:21:06; rc-boot 20:21:31, 23:33:31): a
; second source, the starter set compiled INTO the signed image
; (gui/res_pack_image, generated; Secure Boot covers its bytes). The source is
; decided ONCE, in res_prel1_admit, before any artifact is opened:
;   - an admitted ESP generation is the source for the whole boot (unchanged);
;   - otherwise (no volume, or a complete listing with no generation: "absent";
;     a res/ listing or a record stat that failed, "list-failed" / "record-failed"
;     (missing or unreadable: vfs does not say which); a listing past
;     RP_DIR_CAP, "truncated" / "over-cap"; any refusal: "refused:<code>")
;     rp_rec and every latch are wiped and only then the compiled rows are
;     copied in, so no byte of a refused record survives.
; One [res.pack.source] line names the outcome; a tampered record never reads
; as a missing one. The two sources are never mixed, never retried, and the ESP
; is not read again after the decision. A refusal is a resource outcome only:
; nothing here touches the boot journal, health, Ready or Safe. Every check
; after the fetch is the same for both sources (table hash before any table
; field, each page hashed in place, latches); only the fetch differs (rp_fetch:
; vfs on the ESP path, or a bounded copy out of the image span). An image with
; no compiled rows (rp_img_count 0) keeps the PREL1-only behaviour.
;
; Every entry is BSP-only (sha256/rsa module statics) and non-reentrant. Status
; in EAX; RBX RBP R12-R15 preserved.

RP_OK               equ 0
RP_E_NO_SOURCE      equ 1
RP_E_NO_VOLUME      equ 2
RP_E_NO_PREL1       equ 3
RP_E_PREL1_SHAPE    equ 4
RP_E_PREL1_SIG      equ 5
RP_E_PREL1_KEYID    equ 6
RP_E_PREL1_GEN      equ 7
RP_E_PREL1_IMAGE    equ 8
RP_E_PREL1_ROWS     equ 9
RP_E_NOT_LISTED     equ 10
RP_E_FILE           equ 11
RP_E_PGH_CAPACITY   equ 12
RP_E_PGH_HASH       equ 13
RP_E_PGH_SHAPE      equ 14
RP_E_READ           equ 15
RP_E_PAGE_HASH      equ 16
RP_E_UNAVAILABLE    equ 17
RP_E_ARG            equ 18
RP_E_HANDLES        equ 19

RES_MIN_GENERATION  equ 1               ; rc-sec 40f28460 B3: raised by a release that supersedes a set

; PREL1 header (little-endian; signature 256 B big-endian at signed_bytes)
P1_MAGIC            equ 0
P1_VERSION          equ 8
P1_HEADER_BYTES     equ 10
P1_ROW_BYTES        equ 12
P1_ROW_COUNT        equ 14
P1_SIGNED           equ 16
P1_TOTAL            equ 20
P1_GEN              equ 24
P1_FLAGS            equ 28
P1_KEY_ID           equ 32
P1_IMAGE_TEXT       equ 64
P1_RESERVED         equ 160
P1_HDR              equ 256
P1_ROW              equ 192
P1_ROWS_MAX         equ 64
P1_SIG              equ 256
PREL1_MAX           equ P1_HDR + P1_ROWS_MAX * P1_ROW + P1_SIG   ; 12,800

; PREL1 row
PR_NAME             equ 0
PR_NAME_MAX         equ 96
PR_PACK_NAME_MAX    equ 92              ; + ".pgh" fits the 96-byte basename cap
PR_KIND             equ 96
PR_FLAGS            equ 97
PR_RSVD             equ 98
PR_BYTES            equ 100
PR_SHA              equ 104
PR_PGH_BYTES        equ 136
PR_PAGES            equ 140
PR_PGH_SHA          equ 144
PR_IDENT            equ 176

RP_KIND_FONT        equ 1
RP_KIND_DICT        equ 2
RP_KIND_NOTICE      equ 5               ; 3 catalog / 4 map: reserved in v1 (R2 translation slice)

RP_FONT_MAX         equ 16 << 20
RP_DICT_MAX         equ 8 << 20
RP_NOTICE_MAX       equ 64 << 10

; PPGH1 page table header (FORMAT.md <8sHHIII32s8s>)
PG_VERSION          equ 8
PG_HEADER           equ 10
PG_PAGE             equ 12
PG_PACK_BYTES       equ 16
PG_PAGES            equ 20
PG_PACK_SHA         equ 24
PG_RESERVED         equ 56
PG_HDR              equ 64

; handle (RPH_SIZE bytes)
RPH_STATE           equ 0               ; 0 free, 1 open
RPH_KIND            equ 1
RPH_ROW             equ 2
RPH_BYTES           equ 4
RPH_PAGES           equ 8
RPH_PGH             equ 16              ; borrowed caller table, open..close
RPH_SIZE            equ 32
RP_HANDLES          equ 32

RP_ST_UNTRIED       equ 0
RP_ST_ADMITTED      equ 1
RP_ST_REFUSED       equ 2

RP_SRC_NONE         equ 0               ; res_pack_artifact_source(): not decided, or no source
RP_SRC_ESP          equ 1
RP_SRC_IMAGE        equ 2

; Why an RP_E_NO_PREL1 boot fell back to the image (rp_why; the [res.pack.source] reason token).
; vfs -1 on the boot ESP never says whether the name is missing or unreadable (the FAT walk sets
; no error), so only a COMPLETE listing with no <gen> directory is "absent" (rc-boot 06:33:29, A).
RP_WHY_ABSENT        equ 0             ; a complete listing named no <gen> (and: no volume)
RP_WHY_LIST_FAILED   equ 1             ; vfs_list_dir(res/) -1: missing or unreadable
RP_WHY_TRUNCATED     equ 2             ; the listing did not fit RP_DIR_CAP
RP_WHY_OVER_CAP      equ 3             ; a count past RP_DIR_CAP with no truncation flag
RP_WHY_RECORD_FAILED equ 4             ; a <gen> was named; vfs_stat_path(its record) -1

RP_GEN_DIGITS       equ 8
RP_DIR_CAP          equ 32
RP_PATH_MAX         equ 128

RP_STAGE_ADMIT      equ 1
RP_STAGE_OPEN       equ 2
RP_STAGE_PAGE       equ 3
RP_STAGE_WHOLE      equ 4
RP_STAGE_INFO       equ 5

; res_prel1_admit() -> EAX status. The first call decides the generation for
; the boot; every later call returns the same status with no I/O.
res_prel1_admit:
    cmp  byte [rel rp_state], RP_ST_UNTRIED
    je   .first
    mov  eax, [rel rp_status]
    ret
.first:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  byte [rel rp_state], RP_ST_REFUSED   ; decided once, whatever happens below
    call rp_locate
    mov  r12d, RP_E_NO_VOLUME
    cmp  byte [rel rp_vol_ok], 0
    je   .done
    mov  r12d, RP_E_NO_PREL1
    xor  r13d, r13d                     ; no <gen> named yet (RP_WHY_RECORD_FAILED below)
    mov  byte [rel rp_why], RP_WHY_LIST_FAILED
    mov  edi, [rel rp_vol]
    lea  rsi, [rel str_rp_res_dir]
    mov  edx, str_rp_res_dir_len
    lea  rcx, [rel rp_dirents]
    mov  r8d, RP_DIR_CAP
    lea  r9, [rel rp_list]
    call vfs_list_dir
    test rax, rax
    jnz  .done
    mov  byte [rel rp_why], RP_WHY_TRUNCATED
    cmp  dword [rel rp_list + fs_list_result.truncated], 0
    jne  .done                          ; an unbounded listing is not a decision we can make
    mov  byte [rel rp_why], RP_WHY_OVER_CAP
    mov  ecx, [rel rp_list + fs_list_result.count]
    cmp  ecx, RP_DIR_CAP
    ja   .done
    mov  byte [rel rp_why], RP_WHY_ABSENT
    xor  r13d, r13d                     ; newest
    xor  r14d, r14d                     ; next lower
    lea  rbx, [rel rp_dirents]
    mov  r15d, ecx
.scan:
    test r15d, r15d
    jz   .scanned
    test dword [rbx + fs_dirent.flags], FS_DIRENT_DIR
    jz   .next
    lea  rdi, [rbx + fs_dirent.name]
    call rp_parse_gen
    test eax, eax
    jz   .next
    cmp  eax, r13d
    jbe  .lower
    mov  r14d, r13d
    mov  r13d, eax
    jmp  .next
.lower:
    je   .next
    cmp  eax, r14d
    jbe  .next
    mov  r14d, eax
.next:
    add  rbx, fs_dirent_size
    dec  r15d
    jmp  .scan
.scanned:
    test r13d, r13d
    jz   .done
    mov  edi, r13d
    call rp_admit_gen
    mov  r12d, eax
    test eax, eax
    jz   .admitted
    test r14d, r14d
    jz   .done
    mov  edi, r14d
    call rp_admit_gen
    test eax, eax
    jnz  .done                          ; report the newest generation's refusal
    lea  rdi, [rel str_rp_fb_newest]
    call serial_string
    mov  edi, r13d
    call serial_hex64
    lea  rdi, [rel str_rp_fb_refused]
    call serial_string
    mov  edi, r12d
    call serial_hex64
    lea  rdi, [rel str_rp_fb_admitted]
    call serial_string
    mov  edi, r14d
    call serial_hex64
    lea  rdi, [rel str_rp_eol]
    call serial_string
    mov  r13d, r14d
    xor  r12d, r12d
.admitted:
    mov  byte [rel rp_state], RP_ST_ADMITTED
    mov  [rel rp_gen], r13d
.done:
    mov  [rel rp_status], r12d
    lea  rdi, [rel str_rp_state]
    call serial_string
    mov  edi, r12d
    call serial_hex64
    lea  rdi, [rel str_rp_state_gen]
    call serial_string
    mov  edi, [rel rp_gen]
    call serial_hex64
    lea  rdi, [rel str_rp_eol]
    call serial_string
    ; RCQ-38 I1 join: the source, decided here and nowhere else
    test r12d, r12d
    jnz  .not_esp
    mov  byte [rel rp_source], RP_SRC_ESP
    lea  rdi, [rel str_rp_src_esp]
    call serial_string
    jmp  .decided
.not_esp:
    cmp  dword [rel rp_img_count], 0
    je   .decided                       ; no compiled set: refused, as before
    cmp  r12d, RP_E_NO_PREL1
    jne  .why
    test r13d, r13d
    jz   .why
    mov  byte [rel rp_why], RP_WHY_RECORD_FAILED ; the newest <gen>'s record did not stat
.why:
    mov  edi, r12d
    call rp_image_admit
    mov  r12d, eax
.decided:
    mov  eax, r12d
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; res_pack_prel1_gen() -> EAX the admitted generation (0 = none).
res_pack_prel1_gen:
    mov  eax, [rel rp_gen]
    ret

; res_pack_artifact_source() -> EAX RP_SRC_NONE / RP_SRC_ESP / RP_SRC_IMAGE (valid once
; res_prel1_admit has run).
res_pack_artifact_source:
    movzx eax, byte [rel rp_source]
    ret

; rp_locate: once per boot, from res_prel1_admit only. Opens the read-only boot
; ESP when BOOT captured exactly one GPT partition GUID; otherwise, or on -1,
; leaves rp_vol_ok 0 (no volume). No I/O beyond vfs_open_boot_esp's own scan.
rp_locate:
    cmp  byte [rel rp_vol_ok], 0
    jne  .out                           ; already located (host harness)
    cmp  byte [rel boot_esp_part_guid_ok], 1
    jne  .out                           ; 0: none, MBR, two nodes or no DevicePath
    sub  rsp, 8                         ; vfs entered with the alignment res_prel1_admit's own calls give it
    lea  rdi, [rel boot_esp_part_guid]
    call vfs_open_boot_esp
    add  rsp, 8
    cmp  rax, -1
    je   .out
    mov  [rel rp_vol], eax
    mov  byte [rel rp_vol_ok], 1
.out:
    ret

; rp_image_admit(EDI the ESP status, non-zero) -> EAX RP_OK, or the ESP status
; when the compiled set cannot be held (the boot stays refused). The compiled set
; becomes the boot's source: rp_rec and the latches are wiped FIRST, so nothing
; of a refused record remains, then the rows are copied in (the emitter verified
; them; every table and page is still hashed against them before use).
rp_image_admit:
    push rbx
    mov  ebx, edi
    lea  rdi, [rel rp_rec]
    xor  esi, esi
    mov  edx, PREL1_MAX
    call memset
    lea  rdi, [rel rp_row_latch]
    xor  esi, esi
    mov  edx, P1_ROWS_MAX
    call memset
    mov  eax, ebx
    mov  edx, [rel rp_img_count]
    cmp  edx, P1_ROWS_MAX
    ja   .out                           ; never more rows than the record holds
    mov  [rel rp_rec + P1_ROW_COUNT], dx
    imul edx, edx, P1_ROW
    lea  rdi, [rel rp_rec + P1_HDR]
    lea  rsi, [rel rp_img_rows]
    call memcpy
    mov  byte [rel rp_source], RP_SRC_IMAGE
    mov  byte [rel rp_state], RP_ST_ADMITTED
    mov  dword [rel rp_status], RP_OK
    lea  rdi, [rel str_rp_src_image]
    call serial_string
    lea  rdi, [rel str_rp_src_absent]
    cmp  ebx, RP_E_NO_VOLUME
    je   .reason
    cmp  ebx, RP_E_NO_PREL1
    je   .why
    lea  rdi, [rel str_rp_src_refused]
    call serial_string
    mov  edi, ebx
    call serial_hex64
    jmp  .eol
.why:                                   ; RP_E_NO_PREL1: rp_why names which (absent only when proven)
    movzx eax, byte [rel rp_why]
    lea  rdi, [rel str_rp_why_list]
    cmp  eax, RP_WHY_LIST_FAILED
    je   .reason
    lea  rdi, [rel str_rp_why_trunc]
    cmp  eax, RP_WHY_TRUNCATED
    je   .reason
    lea  rdi, [rel str_rp_why_cap]
    cmp  eax, RP_WHY_OVER_CAP
    je   .reason
    lea  rdi, [rel str_rp_why_record]
    cmp  eax, RP_WHY_RECORD_FAILED
    je   .reason
    lea  rdi, [rel str_rp_src_absent]
.reason:
    call serial_string
.eol:
    lea  rdi, [rel str_rp_eol]
    call serial_string
    xor  eax, eax
.out:
    pop  rbx
    ret

; rp_fetch(EBX row, ESI 0 artifact / 1 table, RCX offset, R8 dst, R9 length)
; -> RAX bytes, the length only when all of it was copied.
; The ONE fetch both sources share; every check stays with the caller.
rp_fetch:
    cmp  byte [rel rp_source], RP_SRC_IMAGE
    je   .image
    push rcx
    push r8
    push r9
    mov  ecx, esi
    call rp_row_path
    pop  r9
    pop  r8
    pop  rcx
    mov  edi, [rel rp_vol]
    lea  rsi, [rel rp_path]
    mov  edx, eax
    jmp  vfs_read_at_path
.image:
    call rp_image_span                  ; RAX span start, RDX span bytes (0: none, so any length > 0 is short)
    cmp  rcx, rdx
    ja   .short
    sub  rdx, rcx
    cmp  r9, rdx
    ja   .short                         ; offset + length past the span: nothing copied
    lea  rsi, [rax + rcx]
    mov  rdi, r8
    mov  rdx, r9
    push r9
    call memcpy
    pop  rax
    ret
.short:
    xor  eax, eax
    ret

; rp_size(EBX row, ESI 0 artifact / 1 table) -> RAX the stored size, -1 when
; there is none.
rp_size:
    cmp  byte [rel rp_source], RP_SRC_IMAGE
    je   .image
    sub  rsp, 8
    mov  ecx, esi
    call rp_row_path
    mov  edi, [rel rp_vol]
    lea  rsi, [rel rp_path]
    mov  edx, eax
    lea  rcx, [rel rp_stat]
    call vfs_stat_path
    add  rsp, 8
    test rax, rax
    mov  rax, -1
    jnz  .out
    mov  rax, [rel rp_stat + fs_stat.size]
.out:
    ret
.image:
    call rp_image_span
    mov  rax, -1
    test rdx, rdx
    cmovnz rax, rdx
    ret

; rp_image_span(EBX row, ESI 0 artifact / 1 table) -> RAX the span's address,
; RDX the bytes the image really holds there (RAX 0, RDX 0 = no such span). Only
; RAX, RDX and R10 change (rp_fetch keeps the offset in RCX).
rp_image_span:
    xor  edx, edx
    xor  eax, eax
    cmp  ebx, [rel rp_img_count]
    jae  .out
    lea  rax, [rel rp_img_span]
    lea  rax, [rax + rbx*8]
    lea  rax, [rax + rbx*8]             ; 16 B per row
    mov  edx, [rax + rsi*8 + 4]
    mov  eax, [rax + rsi*8]
    lea  r10, [rel rp_img_base]
    add  rax, r10
.out:
    ret

; rp_parse_gen(RDI NUL-terminated dirent name) -> EAX generation, 0 = not a
; generation name (1..8 decimal digits, no leading zero, nothing else).
rp_parse_gen:
    xor  eax, eax
    xor  ecx, ecx
    cmp  byte [rdi], '0'
    je   .bad                           ; leading zero, or "0"
.digit:
    movzx edx, byte [rdi + rcx]
    test edx, edx
    jz   .end
    sub  edx, '0'
    cmp  edx, 9
    ja   .bad
    cmp  ecx, RP_GEN_DIGITS
    jae  .bad
    imul eax, eax, 10
    add  eax, edx
    inc  ecx
    jmp  .digit
.end:
    test ecx, ecx
    jnz  .out
.bad:
    xor  eax, eax
.out:
    ret

; rp_admit_gen(EDI generation) -> EAX status. Admits from scratch: nothing a
; previous candidate read or decided is reused (rc-sec 15:53:40 (2a)).
rp_admit_gen:
    push rbx
    push r12
    push r13
    sub  rsp, 16
    mov  r12d, edi
    lea  rdi, [rel rp_rec]
    xor  esi, esi
    mov  edx, PREL1_MAX
    call memset
    lea  rdi, [rel rp_row_latch]
    xor  esi, esi
    mov  edx, P1_ROWS_MAX
    call memset
    mov  edi, r12d
    call rp_fmt_gen
    lea  rsi, [rel str_rp_prel1_name]
    mov  edx, str_rp_prel1_name_len
    xor  ecx, ecx
    call rp_build_path
    mov  r13d, eax                      ; path length
    mov  ebx, RP_E_NO_PREL1
    mov  edi, [rel rp_vol]
    lea  rsi, [rel rp_path]
    mov  edx, r13d
    lea  rcx, [rel rp_stat]
    call vfs_stat_path
    test rax, rax
    jnz  .out
    mov  ebx, RP_E_PREL1_SHAPE
    mov  rax, [rel rp_stat + fs_stat.size]
    cmp  rax, PREL1_MAX
    ja   .out                           ; never read more than the record buffer
    cmp  rax, P1_HDR + P1_ROW + P1_SIG
    jb   .out
    mov  [rsp], rax
    mov  ebx, RP_E_READ
    mov  edi, [rel rp_vol]
    lea  rsi, [rel rp_path]
    mov  edx, r13d
    xor  ecx, ecx
    lea  r8, [rel rp_rec]
    mov  r9, [rsp]
    call vfs_read_at_path
    cmp  rax, [rsp]
    jne  .out
    ; 1. shape, before any field is trusted
    mov  ebx, RP_E_PREL1_SHAPE
    lea  rdi, [rel rp_rec + P1_MAGIC]
    lea  rsi, [rel rp_prel1_magic]
    mov  edx, 8
    call memcmp
    test eax, eax
    jnz  .out
    cmp  word [rel rp_rec + P1_VERSION], 1
    jne  .out
    cmp  word [rel rp_rec + P1_HEADER_BYTES], P1_HDR
    jne  .out
    cmp  word [rel rp_rec + P1_ROW_BYTES], P1_ROW
    jne  .out
    movzx eax, word [rel rp_rec + P1_ROW_COUNT]
    test eax, eax
    jz   .out
    cmp  eax, P1_ROWS_MAX
    ja   .out
    imul eax, eax, P1_ROW
    add  eax, P1_HDR
    cmp  [rel rp_rec + P1_SIGNED], eax
    jne  .out
    add  eax, P1_SIG
    cmp  [rel rp_rec + P1_TOTAL], eax
    jne  .out
    cmp  [rsp], rax
    jne  .out                           ; file length == total_bytes, exactly
    ; 2. signature over [0, signed_bytes) with the compiled owner modulus
    mov  ebx, RP_E_PREL1_SIG
    mov  edx, [rel rp_rec + P1_SIGNED]
    lea  rsi, [rel rp_rec]
    lea  rdi, [rsi + rdx]
    lea  rcx, [rel boot_v2_owner_modulus]
    call rsa2048_verify_sha256
    test eax, eax
    jnz  .out
    ; 3. key id
    mov  ebx, RP_E_PREL1_KEYID
    lea  rdi, [rel rp_rec + P1_KEY_ID]
    lea  rsi, [rel command_auth_owner_key_id]
    mov  edx, 32
    call memcmp
    test eax, eax
    jnz  .out
    ; 4. generation: the floor, and the directory may not relabel the record
    mov  ebx, RP_E_PREL1_GEN
    mov  eax, [rel rp_rec + P1_GEN]
    cmp  eax, RES_MIN_GENERATION
    jb   .out
    cmp  eax, r12d
    jne  .out
    ; 5. image binding: v1 is IME-only, so the digest is the compiled empty inventory
    mov  ebx, RP_E_PREL1_IMAGE
    lea  rdi, [rel rp_rec + P1_IMAGE_TEXT]
    lea  rsi, [rel rp_empty_image_text]
    mov  edx, 32
    call memcmp
    test eax, eax
    jnz  .out
    ; 6. every row byte, after the signature: signed is not the same as well-formed
    call rp_check_rows
    mov  ebx, eax
.out:
    test ebx, ebx
    jz   .ret
    mov  edi, ebx
    mov  esi, RP_STAGE_ADMIT
    mov  edx, r12d                      ; the candidate generation
    call rp_marker
.ret:
    mov  eax, ebx
    add  rsp, 16
    pop  r13
    pop  r12
    pop  rbx
    ret

; rp_check_rows() -> EAX 0 / RP_E_PREL1_ROWS. Header flags and reserved bytes
; zero; rows strictly ascending by the whole 96-byte name field; per-kind caps,
; equations, identity bytes and zero padding.
rp_check_rows:
    push rbx
    push r12
    push r13
    push r14
    push r15
    cmp  dword [rel rp_rec + P1_FLAGS], 0
    jne  .bad
    lea  rsi, [rel rp_rec + P1_RESERVED]
    mov  ecx, P1_HDR - P1_RESERVED
    call rp_all_zero
    test eax, eax
    jnz  .bad
    movzx r15d, word [rel rp_rec + P1_ROW_COUNT]
    lea  r12, [rel rp_rec + P1_HDR]
    xor  r13d, r13d                     ; previous row
.row:
    mov  rsi, r12
    call rp_name_len
    mov  r14d, eax
    mov  rsi, r12
    mov  edx, r14d
    call rp_name_ok
    test eax, eax
    jnz  .bad
    cmp  r14d, str_rp_prel1_name_len     ; the record's own name is reserved: attaching the
    jne  .not_record                    ; owner's prel1.bin would overwrite that artifact
    mov  rdi, r12
    lea  rsi, [rel str_rp_prel1_name]
    mov  edx, str_rp_prel1_name_len
    call memcmp
    test eax, eax
    jz   .bad
.not_record:
    test r13, r13
    jz   .ordered
    mov  rdi, r13
    mov  rsi, r12
    mov  edx, PR_NAME_MAX
    call memcmp
    test eax, eax
    jns  .bad                           ; equal or descending
.ordered:
    cmp  byte [r12 + PR_FLAGS], 0
    jne  .bad
    cmp  word [r12 + PR_RSVD], 0
    jne  .bad
    mov  ebx, [r12 + PR_BYTES]
    test ebx, ebx
    jz   .bad
    movzx eax, byte [r12 + PR_KIND]
    cmp  eax, RP_KIND_FONT
    je   .font
    cmp  eax, RP_KIND_DICT
    je   .dict
    cmp  eax, RP_KIND_NOTICE
    jne  .bad                           ; 3/4 (catalog/map) are not v1 kinds
    cmp  ebx, RP_NOTICE_MAX
    ja   .bad
    cmp  dword [r12 + PR_PGH_BYTES], 0
    jne  .bad
    cmp  dword [r12 + PR_PAGES], 0
    jne  .bad
    lea  rsi, [r12 + PR_PGH_SHA]
    mov  ecx, 32 + 16                   ; pgh_sha256 and identity16 are both zero
    call rp_all_zero
    test eax, eax
    jnz  .bad
    jmp  .next
.font:
    cmp  ebx, RP_FONT_MAX
    ja   .bad
    cmp  dword [r12 + PR_IDENT], 0      ; glyph count
    je   .bad
    cmp  word [r12 + PR_IDENT + 4], 0   ; width
    je   .bad
    cmp  word [r12 + PR_IDENT + 6], 0   ; height
    je   .bad
    movzx eax, byte [r12 + PR_IDENT + 8]
    cmp  eax, 1
    je   .bpp
    cmp  eax, 8
    jne  .bad
.bpp:
    movzx eax, word [r12 + PR_IDENT + 9] ; face | subset << 8
    lea  rdi, [rel rp_font_pairs]
    mov  ecx, rp_font_pairs_count
.pair:
    cmp  ax, [rdi]
    je   .pair_ok
    add  rdi, 2
    dec  ecx
    jnz  .pair
    jmp  .bad
.pair_ok:
    lea  rsi, [r12 + PR_IDENT + 11]
    mov  ecx, 5
    call rp_all_zero
    test eax, eax
    jnz  .bad
    jmp  .paged
.dict:
    cmp  ebx, RP_DICT_MAX
    ja   .bad
    cmp  dword [r12 + PR_IDENT], 0      ; entry count
    je   .bad
    movzx eax, word [r12 + PR_IDENT + 4]
    cmp  eax, 1                         ; ja
    je   .locale
    cmp  eax, 2                         ; zh-Hans
    jne  .bad
.locale:
    lea  rsi, [r12 + PR_IDENT + 6]
    mov  ecx, 10
    call rp_all_zero
    test eax, eax
    jnz  .bad
.paged:
    cmp  r14d, PR_PACK_NAME_MAX
    ja   .bad
    lea  eax, [rbx + 4095]
    shr  eax, 12
    cmp  [r12 + PR_PAGES], eax
    jne  .bad
    shl  eax, 5
    add  eax, PG_HDR
    cmp  [r12 + PR_PGH_BYTES], eax
    jne  .bad
.next:
    mov  r13, r12
    add  r12, P1_ROW
    dec  r15d
    jnz  .row
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, RP_E_PREL1_ROWS
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; rp_name_len(RSI 96-byte name field) -> EAX length without the trailing NUL run.
rp_name_len:
    mov  eax, PR_NAME_MAX
.strip:
    test eax, eax
    jz   .out
    cmp  byte [rsi + rax - 1], 0
    jne  .out
    dec  eax
    jmp  .strip
.out:
    ret

; rp_name_ok(RSI name, EDX length) -> EAX 0 when 1..96 bytes of
; [a-z][a-z0-9_.-]* with no "..", else 1.
rp_name_ok:
    test edx, edx
    jz   .bad
    cmp  edx, PR_NAME_MAX
    ja   .bad
    movzx eax, byte [rsi]
    sub  eax, 'a'
    cmp  eax, 25
    ja   .bad
    mov  ecx, 1
.char:
    cmp  ecx, edx
    jae  .ok
    movzx eax, byte [rsi + rcx]
    cmp  eax, '.'
    jne  .not_dot
    cmp  byte [rsi + rcx - 1], '.'
    je   .bad
    jmp  .good
.not_dot:
    cmp  eax, '-'
    je   .good
    cmp  eax, '_'
    je   .good
    lea  r8d, [rax - 'a']
    cmp  r8d, 25
    jbe  .good
    sub  eax, '0'
    cmp  eax, 9
    ja   .bad
.good:
    inc  ecx
    jmp  .char
.ok:
    mov  eax, edx                       ; no trailing dot: FAT drops it, so "abc."
    cmp  byte [rsi + rax - 1], '.'      ; would alias "abc" on the ESP
    je   .bad
    xor  eax, eax
    ret
.bad:
    mov  eax, 1
    ret

; rp_all_zero(RSI, ECX length) -> EAX 0 when every byte is zero, else 1.
rp_all_zero:
    xor  eax, eax
.loop:
    test ecx, ecx
    jz   .out
    dec  ecx
    or   al, [rsi + rcx]
    jmp  .loop
.out:
    test eax, eax
    setnz al
    ret

; rp_fmt_gen(EDI generation 1..99,999,999) -> rp_gen_str / rp_gen_len.
rp_fmt_gen:
    mov  eax, edi
    lea  r8, [rel rp_gen_str + RP_GEN_DIGITS]
    mov  r9, r8
    mov  ecx, 10
.div:
    xor  edx, edx
    div  ecx
    add  edx, '0'
    dec  r8
    mov  [r8], dl
    test eax, eax
    jnz  .div
    mov  rax, r9
    sub  rax, r8                        ; digit count
    mov  [rel rp_gen_len], eax
    lea  rdi, [rel rp_gen_str]
    mov  rsi, r8
    mov  rcx, rax
    cld
    rep  movsb
    ret

; rp_build_path(RSI name, EDX length, ECX 1 = append ".pgh") -> rp_path
; "/EFI/PaOS/res/<gen>/<name>[.pgh]" NUL-terminated, EAX length. The name is
; one PREL1 row name (verified charset, <= 96) or a compiled constant.
rp_build_path:
    push rbx
    mov  ebx, ecx
    mov  r8, rsi
    mov  r9d, edx
    cld
    lea  rdi, [rel rp_path]
    lea  rsi, [rel str_rp_res_dir]
    mov  ecx, str_rp_res_dir_len
    rep  movsb
    mov  al, '/'
    stosb
    lea  rsi, [rel rp_gen_str]
    mov  ecx, [rel rp_gen_len]
    rep  movsb
    mov  al, '/'
    stosb
    mov  rsi, r8
    mov  ecx, r9d
    rep  movsb
    test ebx, ebx
    jz   .term
    mov  eax, '.pgh'
    stosd
.term:
    mov  byte [rdi], 0
    lea  rax, [rel rp_path]
    sub  rdi, rax
    mov  eax, edi
    pop  rbx
    ret

; rp_row_path(EBX row index, ECX 1 = ".pgh") -> rp_path, EAX length.
rp_row_path:
    push r12
    imul eax, ebx, P1_ROW
    lea  r12, [rel rp_rec + P1_HDR]
    add  r12, rax
    push rcx
    mov  rsi, r12
    call rp_name_len
    pop  rcx
    mov  edx, eax
    mov  rsi, r12
    call rp_build_path
    pop  r12
    ret

; rp_marker(EDI code, ESI stage, EDX detail): one serial line per refusal.
rp_marker:
    push rbx
    push r12
    push r13
    mov  ebx, edi
    mov  r12d, esi
    mov  r13d, edx
    lea  rdi, [rel str_rp_refused]
    call serial_string
    mov  edi, ebx
    call serial_hex64
    lea  rdi, [rel str_rp_stage]
    call serial_string
    mov  edi, r12d
    call serial_hex64
    lea  rdi, [rel str_rp_detail]
    call serial_string
    mov  edi, r13d
    call serial_hex64
    lea  rdi, [rel str_rp_eol]
    call serial_string
    pop  r13
    pop  r12
    pop  rbx
    ret

; rp_handle(EDI handle) -> RAX handle pointer, 0 = not an open handle.
rp_handle:
    lea  eax, [rdi - 1]
    cmp  eax, RP_HANDLES
    jae  .bad
    imul eax, eax, RPH_SIZE
    lea  rdx, [rel rp_handles]
    add  rax, rdx
    cmp  byte [rax + RPH_STATE], 1
    je   .out
.bad:
    xor  eax, eax
.out:
    ret

; rp_latch(EBX row index): this artifact is unavailable for the rest of the boot.
%macro RP_LATCH 0
    lea  rax, [rel rp_row_latch]
    mov  byte [rax + rbx], 1
%endmacro

; res_pack_open(RDI name, ESI name_len, EDX kind, RCX identity16 request,
;               R8 pgh_dst, R9 pgh_capacity) -> EAX status, EDX handle 1..32.
; The request identity is the consumer's compiled descriptor; count 0 means
; "not requested" and every other identity byte is compared exactly.
res_pack_open:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 24
    mov  r12, rdi
    mov  r13d, esi
    mov  r14d, edx
    mov  r15, rcx
    mov  rbp, r8
    mov  [rsp], r9
    mov  ebx, -1                        ; no row yet (marker detail)
    cmp  byte [rel rp_state], RP_ST_ADMITTED
    je   .admitted
    mov  eax, RP_E_UNAVAILABLE
    cmp  byte [rel rp_state], RP_ST_REFUSED
    je   .ret                           ; already reported by the admission
    call res_prel1_admit
    test eax, eax
    jnz  .ret
.admitted:
    mov  eax, RP_E_ARG
    test r15, r15
    jz   .fail
    test r12, r12
    jz   .fail
    mov  eax, RP_E_NOT_LISTED
    mov  rsi, r12
    mov  edx, r13d
    call rp_name_ok
    test eax, eax
    mov  eax, RP_E_NOT_LISTED
    jnz  .fail
    ; exact name match over the verified rows
    movzx ecx, word [rel rp_rec + P1_ROW_COUNT]
    mov  [rsp + 8], ecx
    xor  ebx, ebx
.find:
    cmp  ebx, [rsp + 8]
    jae  .unlisted
    imul eax, ebx, P1_ROW
    lea  rsi, [rel rp_rec + P1_HDR]
    add  rsi, rax
    mov  [rsp + 16], rsi
    call rp_name_len
    cmp  eax, r13d
    jne  .find_next
    mov  rdi, [rsp + 16]
    mov  rsi, r12
    mov  edx, r13d
    call memcmp
    test eax, eax
    jz   .found
.find_next:
    inc  ebx
    jmp  .find
.unlisted:
    mov  ebx, -1
    mov  eax, RP_E_NOT_LISTED
    jmp  .fail
.found:
    mov  r12, [rsp + 16]                ; r12 = the verified row from here on
    mov  eax, RP_E_NOT_LISTED
    movzx ecx, byte [r12 + PR_KIND]
    cmp  ecx, r14d
    jne  .fail
    lea  rdi, [r12 + PR_IDENT + 4]
    lea  rsi, [r15 + 4]
    mov  edx, 12
    cmp  dword [r15], 0
    je   .ident
    lea  rdi, [r12 + PR_IDENT]
    mov  rsi, r15
    mov  edx, 16
.ident:
    call memcmp
    test eax, eax
    mov  eax, RP_E_NOT_LISTED
    jnz  .fail
    lea  rax, [rel rp_row_latch]
    cmp  byte [rax + rbx], 0
    mov  eax, RP_E_UNAVAILABLE
    jne  .ret
    ; a free handle
    lea  r15, [rel rp_handles]
    xor  ecx, ecx
.slot:
    cmp  byte [r15 + RPH_STATE], 0
    je   .slot_ok
    add  r15, RPH_SIZE
    inc  ecx
    cmp  ecx, RP_HANDLES
    jb   .slot
    mov  eax, RP_E_HANDLES
    jmp  .fail
.slot_ok:
    mov  [rsp + 8], ecx
    ; the artifact exists at exactly the listed size
    xor  esi, esi
    call rp_size
    mov  ecx, [r12 + PR_BYTES]
    cmp  rax, rcx
    mov  eax, RP_E_FILE
    jne  .fail
    cmp  r14d, RP_KIND_NOTICE
    je   .opened
    ; paged: the table length comes from PREL1, never from the table
    mov  eax, RP_E_PGH_CAPACITY
    mov  ecx, [r12 + PR_PGH_BYTES]
    cmp  rcx, [rsp]
    ja   .fail                          ; nothing written
    mov  eax, RP_E_ARG
    test rbp, rbp
    jz   .fail
    mov  esi, 1
    call rp_size
    mov  ecx, [r12 + PR_PGH_BYTES]
    cmp  rax, rcx
    mov  eax, RP_E_FILE
    jne  .fail
    mov  esi, 1
    xor  ecx, ecx
    mov  r8, rbp
    mov  r9d, [r12 + PR_PGH_BYTES]
    call rp_fetch
    mov  ecx, [r12 + PR_PGH_BYTES]
    cmp  rax, rcx
    mov  eax, RP_E_READ
    jne  .table_bad
    lea  rdi, [rel rp_digest]
    mov  rsi, rbp
    mov  edx, [r12 + PR_PGH_BYTES]
    call sha256_hash
    lea  rdi, [rel rp_digest]
    lea  rsi, [r12 + PR_PGH_SHA]
    mov  edx, 32
    call memcmp
    test eax, eax
    mov  eax, RP_E_PGH_HASH
    jnz  .table_bad
    ; authenticated: only now is any table header field looked at
    mov  rdi, rbp
    lea  rsi, [rel rp_ppgh_magic]
    mov  edx, 8
    call memcmp
    test eax, eax
    jnz  .shape_bad
    cmp  word [rbp + PG_VERSION], 1
    jne  .shape_bad
    cmp  word [rbp + PG_HEADER], PG_HDR
    jne  .shape_bad
    cmp  dword [rbp + PG_PAGE], 4096
    jne  .shape_bad
    mov  eax, [r12 + PR_BYTES]
    cmp  [rbp + PG_PACK_BYTES], eax
    jne  .shape_bad
    mov  eax, [r12 + PR_PAGES]
    cmp  [rbp + PG_PAGES], eax
    jne  .shape_bad
    cmp  qword [rbp + PG_RESERVED], 0
    jne  .shape_bad
    lea  rdi, [rbp + PG_PACK_SHA]
    lea  rsi, [r12 + PR_SHA]
    mov  edx, 32
    call memcmp
    test eax, eax
    jnz  .shape_bad
.opened:
    mov  ecx, [rsp + 8]
    imul eax, ecx, RPH_SIZE
    lea  r15, [rel rp_handles]
    add  r15, rax
    mov  byte [r15 + RPH_STATE], 1
    mov  al, [r12 + PR_KIND]
    mov  [r15 + RPH_KIND], al
    mov  [r15 + RPH_ROW], bl
    mov  eax, [r12 + PR_BYTES]
    mov  [r15 + RPH_BYTES], eax
    mov  eax, [r12 + PR_PAGES]
    mov  [r15 + RPH_PAGES], eax
    mov  [r15 + RPH_PGH], rbp
    lea  edx, [rcx + 1]
    xor  eax, eax
    jmp  .out
.shape_bad:
    mov  eax, RP_E_PGH_SHAPE
.table_bad:
    ; an unauthenticated or mis-bound table never stays in the caller's area
    mov  [rsp + 16], rax
    mov  rdi, rbp
    xor  esi, esi
    mov  edx, [r12 + PR_PGH_BYTES]
    call memset
    RP_LATCH
    mov  rax, [rsp + 16]
.fail:
    mov  [rsp + 16], rax
    mov  edi, eax
    mov  esi, RP_STAGE_OPEN
    mov  edx, ebx
    call rp_marker
    mov  rax, [rsp + 16]
.ret:
    xor  edx, edx
.out:
    add  rsp, 24
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; res_pack_info(EDI handle, RSI out16 or 0) -> EAX status, RDX bytes,
; ECX page_count; on OK the ADMITTED identity16 is copied to out16.
res_pack_info:
    push rbx
    push r12
    sub  rsp, 8
    mov  r12, rsi
    call rp_handle
    test rax, rax
    jz   .arg
    mov  rbx, rax
    movzx ecx, byte [rbx + RPH_ROW]
    lea  rax, [rel rp_row_latch]
    cmp  byte [rax + rcx], 0
    jne  .unavail
    test r12, r12
    jz   .no_copy
    imul eax, ecx, P1_ROW
    lea  rsi, [rel rp_rec + P1_HDR + PR_IDENT]
    add  rsi, rax
    mov  rdi, r12
    mov  edx, 16
    call memcpy
.no_copy:
    mov  edx, [rbx + RPH_BYTES]
    mov  ecx, [rbx + RPH_PAGES]
    xor  eax, eax
    jmp  .out
.unavail:
    mov  eax, RP_E_UNAVAILABLE
    jmp  .zero
.arg:
    mov  edi, RP_E_ARG
    mov  esi, RP_STAGE_INFO
    mov  edx, -1
    call rp_marker
    mov  eax, RP_E_ARG
.zero:
    xor  edx, edx
    xor  ecx, ecx
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; res_pack_page(EDI handle, ESI n, RDX dst 4 KiB-aligned) -> EAX status,
; EDX valid length 1..4096 on OK (dst tail zeroed). Any other status leaves
; dst all zero.
res_pack_page:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8
    mov  r12d, esi
    mov  r13, rdx
    mov  ebx, -1
    call rp_handle
    test rax, rax
    jz   .arg
    mov  r14, rax
    movzx ebx, byte [r14 + RPH_ROW]
    movzx eax, byte [r14 + RPH_KIND]
    cmp  eax, RP_KIND_NOTICE
    je   .arg                           ; whole-file kind
    cmp  r12d, [r14 + RPH_PAGES]
    jae  .arg
    test r13, r13
    jz   .arg
    test r13d, 4095
    jnz  .arg
    lea  rax, [rel rp_row_latch]
    cmp  byte [rax + rbx], 0
    jne  .latched
    mov  r15d, [r14 + RPH_BYTES]
    mov  eax, r12d
    shl  eax, 12
    sub  r15d, eax                      ; > 0 because n < page_count
    cmp  r15d, 4096
    jbe  .len
    mov  r15d, 4096
.len:
    xor  esi, esi
    mov  ecx, r12d
    shl  rcx, 12
    mov  r8, r13
    mov  r9d, r15d
    call rp_fetch                       ; ONE fetch, straight into the caller's slot
    cmp  rax, r15
    mov  ebp, RP_E_READ
    jne  .bad
    lea  rdi, [rel rp_digest]
    mov  rsi, r13
    mov  edx, r15d                      ; the exact length: nothing past it is hashed
    call sha256_hash
    mov  eax, r12d
    shl  rax, 5
    mov  rsi, [r14 + RPH_PGH]
    lea  rsi, [rsi + rax + PG_HDR]
    lea  rdi, [rel rp_digest]
    mov  edx, 32
    call memcmp
    test eax, eax
    mov  ebp, RP_E_PAGE_HASH
    jnz  .bad
    lea  rdi, [r13 + r15]
    xor  esi, esi
    mov  edx, 4096
    sub  edx, r15d
    call memset
    xor  eax, eax
    mov  edx, r15d
    jmp  .out
.bad:
    mov  rdi, r13
    xor  esi, esi
    mov  edx, 4096
    call memset
    RP_LATCH
    mov  eax, ebp
    jmp  .fail
.latched:
    mov  rdi, r13                       ; latched: no I/O and no marker repeat, but dst
    xor  esi, esi                       ; never keeps bytes across a non-OK status
    mov  edx, 4096
    call memset
    mov  eax, RP_E_UNAVAILABLE
    jmp  .ret
.arg:
    test r13, r13                       ; a usable dst never keeps bytes across E_ARG
    jz   .arg_status                    ; (srcreview C1): null or misaligned is not
    test r13d, 4095                     ; written at all
    jnz  .arg_status
    mov  rdi, r13
    xor  esi, esi
    mov  edx, 4096
    call memset
.arg_status:
    mov  eax, RP_E_ARG
.fail:
    mov  ebp, eax
    mov  edi, eax
    mov  esi, RP_STAGE_PAGE
    mov  edx, ebx
    call rp_marker
    mov  eax, ebp
.ret:
    xor  edx, edx
.out:
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; res_pack_read_whole(EDI handle, RSI dst, EDX capacity) -> EAX status, EDX
; bytes. Whole-file kinds only (v1: notice). The artifact is read once into
; dst and compared with the row's SHA-256 before return; any failure leaves
; dst[0, bytes) zero.
res_pack_read_whole:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8
    mov  r13, rsi
    mov  r12d, edx
    mov  ebx, -1
    call rp_handle
    test rax, rax
    jz   .arg
    mov  r14, rax
    movzx ebx, byte [r14 + RPH_ROW]
    cmp  byte [r14 + RPH_KIND], RP_KIND_NOTICE
    jne  .arg
    test r13, r13
    jz   .arg
    lea  rax, [rel rp_row_latch]
    cmp  byte [rax + rbx], 0
    mov  eax, RP_E_UNAVAILABLE
    jne  .ret
    mov  r15d, [r14 + RPH_BYTES]
    mov  eax, RP_E_PGH_CAPACITY
    cmp  r15d, r12d
    ja   .fail                          ; nothing written
    xor  esi, esi
    xor  ecx, ecx
    mov  r8, r13
    mov  r9d, r15d
    call rp_fetch
    cmp  rax, r15
    mov  ebp, RP_E_READ
    jne  .bad
    lea  rdi, [rel rp_digest]
    mov  rsi, r13
    mov  edx, r15d
    call sha256_hash
    imul eax, ebx, P1_ROW
    lea  rsi, [rel rp_rec + P1_HDR + PR_SHA]
    add  rsi, rax
    lea  rdi, [rel rp_digest]
    mov  edx, 32
    call memcmp
    test eax, eax
    mov  ebp, RP_E_PAGE_HASH
    jnz  .bad
    xor  eax, eax
    mov  edx, r15d
    jmp  .out
.bad:
    mov  rdi, r13
    xor  esi, esi
    mov  edx, r15d
    call memset
    RP_LATCH
    mov  eax, ebp
    jmp  .fail
.arg:
    mov  eax, RP_E_ARG
.fail:
    mov  ebp, eax
    mov  edi, eax
    mov  esi, RP_STAGE_WHOLE
    mov  edx, ebx
    call rp_marker
    mov  eax, ebp
.ret:
    xor  edx, edx
.out:
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; res_pack_close(EDI handle) -> EAX 0, or E_ARG for a handle that is not open.
; The caller's table is no longer borrowed after this.
res_pack_close:
    call rp_handle
    test rax, rax
    jz   .arg
    mov  qword [rax], 0
    mov  qword [rax + 8], 0
    mov  qword [rax + 16], 0
    mov  qword [rax + 24], 0
    xor  eax, eax
    ret
.arg:
    mov  eax, RP_E_ARG
    ret

rp_prel1_magic:      db "PREL1", 0, 0, 0
rp_ppgh_magic:       db "PPGH1", 0, 0, 0
; SHA-256("PaOS/res/image-text/v1" || u32 0): the v1 IME-only inventory
; (rc-sec 15:53:40 (1b): compiled, never computed from the record).
rp_empty_image_text: db 0x57,0x94,0x82,0xd2,0x61,0xdc,0x5e,0xc0,0x99,0x2a,0x81,0xee,0x78,0x0a,0xc9,0x8b
                     db 0x36,0xdc,0x6f,0x65,0x52,0xd8,0xa2,0xe5,0x25,0x0e,0xe0,0x8e,0x17,0x6c,0x20,0xf8
; admissible font (face, subset) pairs (AMENDMENT_R2 S1): (1,1) legacy latin,
; (1,4) latin text entry, (2,5) ja, (3,6) zh-Hans. A cross pair is refused.
rp_font_pairs:       db 1, 1, 1, 4, 2, 5, 3, 6
rp_font_pairs_count  equ ($ - rp_font_pairs) / 2
str_rp_res_dir:      db "/EFI/PaOS/res"
str_rp_res_dir_len   equ $ - str_rp_res_dir
                     db 0
str_rp_prel1_name:   db "prel1.bin"
str_rp_prel1_name_len equ $ - str_rp_prel1_name
                     db 0
str_rp_state:        db "[res.pack.prel1] status=", 0
str_rp_state_gen:    db " gen=", 0
str_rp_refused:      db "[res.pack.refused] code=", 0
str_rp_stage:        db " stage=", 0
str_rp_detail:       db " detail=", 0
str_rp_fb_newest:    db "[res.pack.fallback] newest=", 0
str_rp_fb_refused:   db " refused=", 0
str_rp_fb_admitted:  db " admitted=", 0
str_rp_src_esp:      db "[res.pack.source] source=esp", 13, 10, 0
str_rp_src_image:    db "[res.pack.source] source=image reason=", 0
str_rp_src_absent:   db "absent", 0
str_rp_why_list:     db "list-failed", 0
str_rp_why_trunc:    db "truncated", 0
str_rp_why_cap:      db "over-cap", 0
str_rp_why_record:   db "record-failed", 0
str_rp_src_refused:  db "refused:", 0
str_rp_eol:          db 13, 10, 0

%macro WDATA_gui_res_pack 0
alignb 64
rp_rec:              resb PREL1_MAX     ; the verified PREL1, from scratch per candidate
alignb 64
rp_handles:          resb RP_HANDLES * RPH_SIZE
rp_dirents:          resb RP_DIR_CAP * fs_dirent_size
rp_row_latch:        resb P1_ROWS_MAX
rp_digest:           resb 32
rp_path:             resb RP_PATH_MAX
rp_stat:             resb fs_stat_size
rp_list:             resb fs_list_result_size
rp_gen_str:          resb RP_GEN_DIGITS + 4
rp_gen_len:          resd 1
rp_status:           resd 1
rp_gen:              resd 1
rp_vol:              resd 1             ; the source volume's vfs handle
rp_vol_ok:           resb 1             ; set by the boot-ESP locator only (G1b)
rp_state:            resb 1
%endmacro
WDATA_BSS_DEFER WDATA_gui_res_pack

%macro WDATA_gui_res_pack_source 0
rp_source:           resb 1             ; RP_SRC_*: decided once by res_prel1_admit
rp_why:              resb 1             ; RP_WHY_*: set with the RP_E_NO_PREL1 decision
%endmacro
WDATA_BSS_DEFER WDATA_gui_res_pack_source
