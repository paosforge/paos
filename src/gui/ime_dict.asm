;; MODULE gui/ime_dict
;; LAYER 6
;; EXPORTS ime_arena_region, ime_dict_bind, ime_dict_unbind, ime_dict_read, ime_dict_lookup, ime_dict_candidate, ime_dict_bound
;; IMPORTS gui/res_pack, core/heap, core/lib/mem, boot/serial
;; CAPS
;; OWNER rc-input-claude
;; CONTEXT: bsp_only
; gui/ime_dict.asm — RCQ-38 I1: the PDCT1 dictionary consumer (CONTRACT_I1_PDCT.md
; 4c1e51e6; relops PRODUCT_DICTIONARY.md; rc-boot's res_pack API, AMENDMENT_R3).
;
; The IME reservation is ONE kmalloc_model block (root's 6.5 MiB reservation;
; rc-input map 11:23:01), taken at the first bind, zeroed here, never freed:
;   R0 descriptor / bind scratch @0 4 KiB    R3 zh index @3,149,824 256 KiB
;   R1 ja index @4,096 1 MiB                 R4 zh page cache @3,411,968 768 KiB
;   R2 ja page cache @1,052,672 2 MiB        R5 glyph cache (I4) @4,198,400 1 MiB
; R6, the rest, is root's. kmalloc_model is only 16-aligned and a page slot must
; be 4 KiB-aligned, so the base is rounded up inside the block; the slack
; (< 4 KiB) comes off the end of R6.
;
; Storage is reached ONLY through res_pack: every byte read here is a page that
; res_pack verified against the owner-signed PREL1's page table. Even so, every
; offset and length taken from a pack is bounded before use (a signed but
; malformed pack must not steer a read or a write).
;
; The index region (R1 / R3) is DERIVED at bind from verified pages and is byte
; for byte relops' reference snapshot (rcq38_product_dictionary.index_bytes):
;   header 128 B "PIDX1", shard table 48 B / shard, anchors 12 B (each shard's
;   first row, then every stride-th), key pool, the shards' PPGH1 tables
;   (exact, as res_pack read and verified them), slot metadata 16 B / slot,
;   candidate scratch 4 KiB, control scratch 4 KiB; each part 4 KiB-aligned,
;   every other byte zero.
; Bind takes two passes because res_pack borrows a shard's table buffer from
; open to close and the PPGH area's offset depends on the key pool's size:
; pass 1 opens every shard with its table in the page-cache region and builds
; the anchors and key pool; pass 2 reopens each shard with its table at its
; final place (res_pack reads and verifies it again), then the cache region and
; R0 are wiped, so a bound locale starts with a cold cache and the index region
; equals the reference.
;
; RCQ-38 I1 join (root 2026-10-16 20:21:06): linked in the image (paos.asm), in
; place of gui/ime_dict_absent. The shards come from whichever source res_pack
; decided for the boot: an admitted ESP PREL1 generation holds the full product
; (IME_JA_SHARDS / IME_ZH_SHARDS); the image's compiled starter set holds one
; shard per locale (IME_*_IMAGE_SHARDS), single-character conversion only. The
; "shard N is not listed" probe applies to either count. Nothing else here
; depends on the source: every byte still arrives as a res_pack-verified page.
;
; Every entry is BSP-only and non-reentrant (res_pack's rule). Status in EAX;
; RBX RBP R12-R15 preserved.

%ifdef IME_DICT_LINKED
%fatal "two IME dictionaries linked: gui/ime_dict and another"
%endif
%define IME_DICT_LINKED 1               ; root 16:01:48 (2)(b): exactly one dictionary (gui/ime_route requires it)

IME_OK              equ 0
IME_E_LOCALE        equ 1
IME_E_ARENA         equ 2
IME_E_PREL1         equ 3               ; detail = res_pack status
IME_E_OPEN          equ 4               ; detail = res_pack status
IME_E_SHARDS        equ 5               ; a shard 000..N-1 not listed, or shard N listed
IME_E_IDENT         equ 6
IME_E_HEADER        equ 7
IME_E_ORDER         equ 8
IME_E_ROW           equ 9
IME_E_BUDGET        equ 10
IME_E_READ          equ 11              ; detail = res_pack status (the artifact is latched)
IME_E_UNBOUND       equ 12
IME_E_KEY           equ 13              ; a query of 0 or more than 128 bytes
IME_E_MATCHES       equ 14              ; more than 512 raw rows: refused, never truncated
IME_MATCH_MAX       equ 512

IME_JA_SHARDS       equ 11              ; the measured product (PRODUCT_DICTIONARY.md)
IME_ZH_SHARDS       equ 1
IME_JA_IMAGE_SHARDS equ 1               ; the image's starter set (gui/res_pack_image)
IME_ZH_IMAGE_SHARDS equ 1
IME_SHARDS_MAX      equ 31              ; shard N is probed, and handles are 32 bytes per locale
%if IME_JA_SHARDS > IME_SHARDS_MAX || IME_ZH_SHARDS > IME_SHARDS_MAX
%error "ime_dict: shard count above IME_SHARDS_MAX"
%endif

IME_ARENA_BYTES     equ 6815744
IME_MAP_END         equ 5246976         ; R5's end; the round-up slack stays below R6's size
IME_REGIONS         equ 6
IME_BIND_SLOTS      equ 64              ; page slots used during bind (metadata in R0)
IME_BIND_MIN_SLOTS  equ 4

; R0 bind scratch
R0_ROW_A            equ 0               ; 448 B: row 36 @0, key @64, surface @192
R0_ROW_B            equ 512
R0_HEADER           equ 1024            ; the shard's first 192 bytes
R0_IDENT            equ 1280            ; admitted identity16
R0_META             equ 2048            ; IME_BIND_SLOTS x 16 B
ROWBUF_KEY          equ 64
ROWBUF_SURF         equ 192

; per-locale descriptor (ime_desc, 32 B each)
D_IDX_N             equ 0
D_CACHE_N           equ 4
D_SLOTS             equ 8
D_STRIDE            equ 12
D_SHARDS            equ 16
D_SRC_KIND          equ 20
D_BUDGET            equ 24
D_CACHE_BYTES       equ 28

; PDCT1 (resource_packs/FORMAT.md)
PD_VERSION          equ 8
PD_KIND             equ 10
PD_HEADER_SIZE      equ 12
PD_TOTAL            equ 16
PD_FLAGS            equ 20
PD_META_OFF         equ 24
PD_META_BYTES       equ 28
PD_INDEX_OFF        equ 32
PD_COUNT            equ 36
PD_ENTRY            equ 40
PD_BLOB_OFF         equ 44
PD_BLOB_BYTES       equ 48
PD_RESERVED         equ 52
PD_META_LOCALE      equ 128
PD_META_SRC_KIND    equ 136
PD_META_CODEC       equ 138
PD_META_MAX_KEY     equ 140
PD_META_RESERVED    equ 176
PD_ROWS             equ 192
PD_ROW              equ 36
PD_COUNT_MAX        equ 250000
PD_KEY_MAX          equ 128
PD_SURF_MAX         equ 256
; row <IIIIiIIII>
PR_KEY_OFF          equ 0
PR_KEY_LEN          equ 4
PR_SURF_OFF         equ 8
PR_SURF_LEN         equ 12
PR_COST             equ 16
PR_LEFT             equ 20
PR_RIGHT            equ 24
PR_WEIGHT           equ 28
PR_ATTR             equ 32

; PIDX1 header <8sHH10I76s> and parts
PX_VERSION          equ 8
PX_LOCALE           equ 10
PX_STRIDE           equ 12
PX_SHARDS           equ 16
PX_ANCHORS          equ 20
PX_POOL_BYTES       equ 24
PX_SHARD_OFF        equ 28
PX_ANCHOR_OFF       equ 32
PX_POOL_OFF         equ 36
PX_PPGH_OFF         equ 40
PX_SLOT_OFF         equ 44
PX_CAND_OFF         equ 48
PX_SHARD_TABLE      equ 4096            ; the header is 128 B, so the table is always here
SH_FIRST_ROW        equ 0
SH_ROWS             equ 4
SH_BYTES            equ 8
SH_PAGES            equ 12
SH_PPGH             equ 16
SH_FIRST_ANCHOR     equ 20
SH_SIZE             equ 48
AN_ROW              equ 0
AN_KEY_OFF          equ 4
AN_KEY_LEN          equ 8
AN_SIZE             equ 12
SLOT_SHARD          equ 0
SLOT_FLAGS          equ 2
SLOT_PAGE           equ 4
SLOT_LRU            equ 8
SLOT_SIZE           equ 16
SLOT_VALID          equ 1
CAND_AND_CONTROL    equ 8192            ; 512 x 8 B candidate scratch + 4 KiB control
CTL_ROW             equ 0               ; control scratch: the row being read (448 B)
CTL_PREV            equ 512             ; the previous match's row (its surface)

; ime_arena_region(EDI n) -> RAX base, RDX size: the IME reservation's region n
; (0..5). 0 / 0 before the arena is taken, after a refusal, and for n >= 6
; (R6 is root's).
ime_arena_region:
    xor  eax, eax
    xor  edx, edx
    cmp  edi, IME_REGIONS
    jae  .out
    cmp  byte [rel ime_arena_st], 1
    jne  .out
    lea  rcx, [rel ime_map]
    mov  eax, edi
    mov  edx, [rcx + rax*8 + 4]
    mov  eax, [rcx + rax*8]
    add  rax, [rel ime_arena]
.out:
    ret

; id_arena() -> EAX IME_OK / IME_E_ARENA. The first call takes the block;
; a refusal latches for the boot (a bump heap does not get bigger).
id_arena:
    cmp  byte [rel ime_arena_st], 1
    je   .ok
    cmp  byte [rel ime_arena_st], 0
    jne  .refused
    sub  rsp, 8
    mov  edi, IME_ARENA_BYTES
    call kmalloc_model
    add  rsp, 8
    test rax, rax
    jz   .take_refusal
    mov  [rel ime_arena_raw], rax
    lea  rdi, [rax + 4095]
    and  rdi, -4096
    mov  [rel ime_arena], rdi
    add  rax, IME_ARENA_BYTES
    sub  rax, rdi                       ; the usable bytes from the rounded base
    sub  rsp, 8
    mov  rdx, rax
    xor  esi, esi
    call memset
    add  rsp, 8
    mov  byte [rel ime_arena_st], 1
.ok:
    xor  eax, eax
    ret
.take_refusal:
    mov  byte [rel ime_arena_st], 2
.refused:
    mov  eax, IME_E_ARENA
    ret

; id_setup(EDI locale 1 ja / 2 zh-Hans) -> CF set for any other value. Loads the
; locale's context (ic_*) and its region addresses; the arena must be taken.
id_setup:
    lea  eax, [rdi - 1]
    cmp  eax, 1
    ja   .bad
    mov  [rel ic_li], eax
    shl  eax, 5
    lea  rsi, [rel ime_desc]
    add  rsi, rax
    lea  rdx, [rel ime_map]
    mov  eax, [rsi + D_IDX_N]
    mov  ecx, [rdx + rax*8]
    add  rcx, [rel ime_arena]
    mov  [rel ic_idx], rcx
    mov  eax, [rsi + D_CACHE_N]
    mov  ecx, [rdx + rax*8]
    add  rcx, [rel ime_arena]
    mov  [rel ic_cache], rcx
    mov  eax, [rsi + D_SLOTS]
    mov  [rel ic_slots], eax
    mov  eax, [rsi + D_STRIDE]
    mov  [rel ic_stride], eax
    mov  eax, [rsi + D_SHARDS]
    mov  [rel ic_shards], eax
    mov  eax, [rsi + D_SRC_KIND]
    mov  [rel ic_src_kind], eax
    mov  eax, [rsi + D_BUDGET]
    mov  [rel ic_budget], eax
    mov  eax, [rsi + D_CACHE_BYTES]
    mov  [rel ic_cache_bytes], eax
    sub  rsp, 8
    call res_pack_artifact_source                ; the boot's source (NONE before the admission)
    add  rsp, 8
    cmp  eax, RP_SRC_IMAGE
    jne  .counted
    mov  eax, [rel ic_li]
    lea  rcx, [rel ime_image_shards]
    movzx eax, byte [rcx + rax]
    mov  [rel ic_shards], eax
.counted:
    clc
    ret
.bad:
    stc
    ret

; id_handles() -> RAX the current locale's 32 handle bytes.
id_handles:
    mov  eax, [rel ic_li]
    shl  eax, 5
    lea  rcx, [rel ime_hnd]
    add  rax, rcx
    ret

; id_shard(EDI k) -> RAX the current locale's shard-table entry k.
id_shard:
    imul eax, edi, SH_SIZE
    add  rax, [rel ic_idx]
    add  rax, PX_SHARD_TABLE
    ret

; id_page(EDI shard, ESI page) -> RAX the 4 KiB slot holding that verified page,
; or 0 (the read failed: ime_err_detail = res_pack's status, the slot is free).
; A hit refreshes the slot's LRU stamp; a miss takes a free slot, else the
; least recently used one, and reads the page straight into it.
id_page:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 16
    mov  r12d, edi
    mov  r13d, esi
    mov  eax, [rel ic_li]
    lea  rcx, [rel ime_meta_p]
    mov  rbx, [rcx + rax*8]
    lea  rcx, [rel ime_nslots]
    mov  r14d, [rcx + rax*4]
    xor  ecx, ecx
    xor  r15d, r15d                     ; victim
    mov  r8d, -1                        ; its stamp
    mov  r9d, -1                        ; the first free slot
.scan:
    cmp  ecx, r14d
    jae  .miss
    mov  edx, ecx
    shl  rdx, 4
    add  rdx, rbx
    test word [rdx + SLOT_FLAGS], SLOT_VALID
    jz   .free
    cmp  [rdx + SLOT_SHARD], r12w
    jne  .stamp
    cmp  [rdx + SLOT_PAGE], r13d
    je   .hit
.stamp:
    cmp  [rdx + SLOT_LRU], r8d
    jae  .next
    mov  r8d, [rdx + SLOT_LRU]
    mov  r15d, ecx
    jmp  .next
.free:
    cmp  r9d, -1
    jne  .next
    mov  r9d, ecx
.next:
    inc  ecx
    jmp  .scan
.hit:
    call id_tick
    mov  [rdx + SLOT_LRU], eax
    mov  eax, ecx
    jmp  .slot
.miss:
    cmp  r9d, -1
    je   .evict
    mov  r15d, r9d
.evict:
    mov  edx, r15d
    shl  rdx, 4
    add  rdx, rbx
    mov  qword [rdx], 0                 ; not valid while the read runs
    mov  qword [rdx + 8], 0
    call id_handles
    movzx edi, byte [rax + r12]
    mov  eax, [rel ic_li]
    lea  rcx, [rel ime_cache_p]
    mov  rdx, [rcx + rax*8]
    mov  eax, r15d
    shl  rax, 12
    add  rdx, rax
    mov  [rsp], rdx
    mov  esi, r13d
    call res_pack_page
    test eax, eax
    jnz  .fail
    mov  edx, r15d
    shl  rdx, 4
    add  rdx, rbx
    mov  [rdx + SLOT_SHARD], r12w
    mov  word [rdx + SLOT_FLAGS], SLOT_VALID
    mov  [rdx + SLOT_PAGE], r13d
    call id_tick
    mov  [rdx + SLOT_LRU], eax
    mov  rax, [rsp]
    jmp  .out
.slot:
    mov  ecx, [rel ic_li]
    lea  rdx, [rel ime_cache_p]
    shl  rax, 12
    add  rax, [rdx + rcx*8]
    jmp  .out
.fail:
    mov  [rel ime_err_detail], eax
    mov  ecx, [rel ic_li]               ; a bound locale is latched whole (rc-input 15:39:03):
    lea  rdx, [rel ime_bound]           ; res_pack latched the shard, and a dictionary with a
    cmp  byte [rdx + rcx], 1            ; hole would give wrong candidates, not fewer
    jne  .failed
    mov  byte [rdx + rcx], 2
.failed:
    xor  eax, eax
.out:
    add  rsp, 16
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; id_tick() -> EAX the current locale's next LRU stamp. Clobbers RAX, R10, R11
; only (id_page keeps RCX/RDX live across it).
id_tick:
    mov  r11d, [rel ic_li]
    lea  r10, [rel ime_clock]
    inc  dword [r10 + r11*4]
    mov  eax, [r10 + r11*4]
    ret

; id_read(EDI shard, ESI off, EDX len, RCX dst) -> EAX IME_OK, IME_E_ROW (the
; span leaves the shard) or IME_E_READ. Copies verified bytes across pages.
id_read:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8
    mov  r12d, edi
    mov  r13d, esi
    mov  r14d, edx
    mov  r15, rcx
    call id_shard
    mov  ecx, [rax + SH_BYTES]
    mov  eax, r13d
    add  rax, r14
    cmp  rax, rcx
    ja   .row
.loop:
    test r14d, r14d
    jz   .ok
    mov  edi, r12d
    mov  esi, r13d
    shr  esi, 12
    call id_page
    test rax, rax
    jz   .read
    mov  ebx, r13d
    and  ebx, 4095
    mov  ebp, 4096
    sub  ebp, ebx
    cmp  ebp, r14d
    cmova ebp, r14d
    lea  rsi, [rax + rbx]
    mov  rdi, r15
    mov  edx, ebp
    call memcpy
    add  r15, rbp
    add  r13d, ebp
    sub  r14d, ebp
    jmp  .loop
.ok:
    xor  eax, eax
    jmp  .out
.row:
    mov  eax, IME_E_ROW
    jmp  .out
.read:
    mov  eax, IME_E_READ
.out:
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; ime_dict_read(EDI locale, ESI shard, EDX off, ECX len, R8 dst) -> EAX status:
; verified bytes of a bound locale's shard (I2 / I3 read surfaces through it).
ime_dict_read:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, esi
    mov  r13d, edx
    mov  r14d, ecx
    mov  r15, r8
    lea  eax, [rdi - 1]
    cmp  eax, 1
    ja   .locale
    lea  rcx, [rel ime_bound]
    cmp  byte [rcx + rax], 2
    je   .latched
    cmp  byte [rcx + rax], 1
    jne  .unbound
    call id_setup
    cmp  r12d, [rel ic_shards]
    jae  .row
    mov  edi, r12d
    mov  esi, r13d
    mov  edx, r14d
    mov  rcx, r15
    call id_read
    jmp  .out
.locale:
    mov  eax, IME_E_LOCALE
    jmp  .out
.unbound:
    mov  eax, IME_E_UNBOUND
    jmp  .out
.latched:
    mov  eax, IME_E_READ
    jmp  .out
.row:
    mov  eax, IME_E_ROW
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; id_row(EDI shard, ESI row, RDX buf, ECX 1 = also read the surface) -> EAX
; status. Reads the 36 B row to buf, its key to buf+64, its surface to
; buf+192, after bounding: row < count, key 1..128 B, surface 1..256 B, both
; spans inside [blob, total).
id_row:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8
    mov  r12d, edi
    mov  r13d, esi
    mov  r14, rdx
    mov  r15d, ecx
    call id_shard
    mov  rbx, rax
    cmp  r13d, [rbx + SH_ROWS]
    jae  .row
    imul esi, r13d, PD_ROW
    add  esi, PD_ROWS
    mov  edi, r12d
    mov  edx, PD_ROW
    mov  rcx, r14
    call id_read
    test eax, eax
    jnz  .out
    imul ebp, [rbx + SH_ROWS], PD_ROW
    add  ebp, PD_ROWS                   ; blob offset
    mov  eax, [r14 + PR_KEY_LEN]
    dec  eax
    cmp  eax, PD_KEY_MAX - 1
    ja   .row
    mov  eax, [r14 + PR_SURF_LEN]
    dec  eax
    cmp  eax, PD_SURF_MAX - 1
    ja   .row
    mov  eax, [r14 + PR_KEY_OFF]
    cmp  eax, ebp
    jb   .row
    mov  eax, [r14 + PR_SURF_OFF]
    cmp  eax, ebp
    jb   .row
    mov  ecx, [rbx + SH_BYTES]
    mov  eax, [r14 + PR_KEY_OFF]
    mov  edx, [r14 + PR_KEY_LEN]
    add  rax, rdx
    cmp  rax, rcx
    ja   .row
    mov  eax, [r14 + PR_SURF_OFF]
    mov  edx, [r14 + PR_SURF_LEN]
    add  rax, rdx
    cmp  rax, rcx
    ja   .row
    mov  edi, r12d
    mov  esi, [r14 + PR_KEY_OFF]
    mov  edx, [r14 + PR_KEY_LEN]
    lea  rcx, [r14 + ROWBUF_KEY]
    call id_read
    test eax, eax
    jnz  .out
    test r15d, r15d
    jz   .out
    mov  edi, r12d
    mov  esi, [r14 + PR_SURF_OFF]
    mov  edx, [r14 + PR_SURF_LEN]
    lea  rcx, [r14 + ROWBUF_SURF]
    call id_read
    jmp  .out
.row:
    mov  eax, IME_E_ROW
.out:
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; id_cmp_bytes(RDI a, ESI a_len, RDX b, ECX b_len) -> EAX -1 / 0 / 1: unsigned
; bytewise, a shorter prefix first (FORMAT's key and surface order).
id_cmp_bytes:
    mov  r8d, esi
    cmp  r8d, ecx
    cmova r8d, ecx
    xor  r9d, r9d
.loop:
    cmp  r9d, r8d
    jae  .lengths
    movzx eax, byte [rdi + r9]
    movzx r10d, byte [rdx + r9]
    cmp  eax, r10d
    jb   .less
    ja   .more
    inc  r9d
    jmp  .loop
.lengths:
    cmp  esi, ecx
    jb   .less
    ja   .more
    xor  eax, eax
    ret
.less:
    mov  eax, -1
    ret
.more:
    mov  eax, 1
    ret

; id_cmp_rows(RDI row buf a, RSI row buf b) -> EAX -1 / 0 / 1 under FORMAT's
; full sort tuple (key, surface, left, right, cost i32, weight, attributes).
id_cmp_rows:
    push rbx
    push r12
    sub  rsp, 8
    mov  rbx, rdi
    mov  r12, rsi
    lea  rdi, [rbx + ROWBUF_KEY]
    mov  esi, [rbx + PR_KEY_LEN]
    lea  rdx, [r12 + ROWBUF_KEY]
    mov  ecx, [r12 + PR_KEY_LEN]
    call id_cmp_bytes
    test eax, eax
    jnz  .out
    lea  rdi, [rbx + ROWBUF_SURF]
    mov  esi, [rbx + PR_SURF_LEN]
    lea  rdx, [r12 + ROWBUF_SURF]
    mov  ecx, [r12 + PR_SURF_LEN]
    call id_cmp_bytes
    test eax, eax
    jnz  .out
    mov  ecx, [rbx + PR_LEFT]
    cmp  ecx, [r12 + PR_LEFT]
    jb   .less
    ja   .more
    mov  ecx, [rbx + PR_RIGHT]
    cmp  ecx, [r12 + PR_RIGHT]
    jb   .less
    ja   .more
    mov  ecx, [rbx + PR_COST]
    cmp  ecx, [r12 + PR_COST]
    jl   .less
    jg   .more
    mov  ecx, [rbx + PR_WEIGHT]
    cmp  ecx, [r12 + PR_WEIGHT]
    jb   .less
    ja   .more
    mov  ecx, [rbx + PR_ATTR]
    cmp  ecx, [r12 + PR_ATTR]
    jb   .less
    ja   .more
    xor  eax, eax
    jmp  .out
.less:
    mov  eax, -1
    jmp  .out
.more:
    mov  eax, 1
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; id_name(EDI k) -> RDI ime_name, ESI its length: "<prefix>-full-%03u.pdct".
id_name:
    mov  r8d, edi
    lea  rdi, [rel ime_name]
    cmp  dword [rel ic_li], 0
    jne  .zh
    lea  rsi, [rel str_ime_ja_prefix]
    mov  ecx, str_ime_ja_prefix_len
    jmp  .copy
.zh:
    lea  rsi, [rel str_ime_zh_prefix]
    mov  ecx, str_ime_zh_prefix_len
.copy:
    mov  r9d, ecx
    cld
    rep  movsb
    mov  eax, r8d
    xor  edx, edx
    mov  ecx, 100
    div  ecx
    add  al, '0'
    stosb
    mov  eax, edx
    xor  edx, edx
    mov  ecx, 10
    div  ecx
    add  al, '0'
    stosb
    lea  eax, [rdx + '0']
    stosb
    mov  dword [rdi], '.pdc'
    mov  word [rdi + 4], 't'
    lea  esi, [r9 + 8]
    lea  rdi, [rel ime_name]
    ret

; id_open(EDI k, RSI pgh_dst, EDX capacity) -> EAX res_pack status, EDX handle.
; The request identity is { count 0 (not requested), locale u16, zero[10] }.
id_open:
    push rbx
    push r12
    push r13
    mov  r12, rsi
    mov  r13d, edx
    call id_name
    lea  rcx, [rel ime_ident]
    mov  qword [rcx], 0
    mov  qword [rcx + 8], 0
    mov  eax, [rel ic_li]
    inc  eax
    mov  [rcx + 4], ax
    mov  edx, RP_KIND_DICT
    mov  r8, r12
    mov  r9d, r13d
    call res_pack_open
    pop  r13
    pop  r12
    pop  rbx
    ret

; id_close_all(): close every handle the current locale holds.
id_close_all:
    push rbx
    push r12
    sub  rsp, 8
    call id_handles
    mov  rbx, rax
    xor  r12d, r12d
.loop:
    cmp  r12d, 32
    jae  .out
    movzx edi, byte [rbx + r12]
    test edi, edi
    jz   .next
    mov  byte [rbx + r12], 0
    call res_pack_close
.next:
    inc  r12d
    jmp  .loop
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; id_wipe(): the current locale's index and cache regions and R0 go to zero,
; its cache is empty (no slot metadata) and it is not bound.
id_wipe:
    sub  rsp, 8
    mov  rdi, [rel ic_idx]
    xor  esi, esi
    mov  edx, [rel ic_budget]
    call memset
    mov  rdi, [rel ic_cache]
    xor  esi, esi
    mov  edx, [rel ic_cache_bytes]
    call memset
    mov  rdi, [rel ime_arena]
    xor  esi, esi
    mov  edx, 4096
    call memset
    mov  ecx, [rel ic_li]
    lea  rax, [rel ime_nslots]
    mov  dword [rax + rcx*4], 0
    lea  rax, [rel ime_clock]
    mov  dword [rax + rcx*4], 0
    lea  rax, [rel ime_bound]
    mov  byte [rax + rcx], 0
    lea  rax, [rel ime_cand_n]
    mov  dword [rax + rcx*4], 0
    add  rsp, 8
    ret

; ime_dict_bind(EDI locale 1 ja / 2 zh-Hans) -> EAX status, EDX detail. Derives
; the locale's index from verified pages (see the header). Bound already: OK
; with no I/O; latched (a page read failed after bind): IME_E_READ with no I/O.
; Any failure closes every handle of the locale and wipes its regions; a later
; call tries again from scratch.
ime_dict_bind:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8
    mov  r12d, edi
    lea  eax, [rdi - 1]
    cmp  eax, 1
    ja   .bad_locale
    lea  rcx, [rel ime_bound]
    cmp  byte [rcx + rax], 1
    je   .already
    cmp  byte [rcx + rax], 2
    je   .latched
    mov  [rel ic_li], eax               ; the marker names the locale even before id_setup
    mov  dword [rel ime_err_detail], 0
    call id_arena
    test eax, eax
    jnz  .early
    mov  edi, r12d
    call id_setup
    call res_prel1_admit
    test eax, eax
    jz   .admitted
    mov  [rel ime_err_detail], eax
    mov  eax, IME_E_PREL1
    jmp  .early
.admitted:
    mov  edi, r12d
    call id_setup                       ; again: the shard count follows the decided source
    call id_wipe
    call id_handles
    mov  rbx, rax
    ; pass 1a: open shards 0..N-1 with their tables at the cache region's start
    xor  r12d, r12d                     ; k
    xor  r14d, r14d                     ; table bytes so far
    xor  r15d, r15d                     ; global rows so far
    xor  ebp, ebp                       ; anchors so far
.open_next:
    cmp  r12d, [rel ic_shards]
    jae  .probe
    mov  edi, r12d
    mov  rsi, [rel ic_cache]
    add  rsi, r14
    mov  edx, [rel ic_cache_bytes]
    sub  edx, r14d
    call id_open
    test eax, eax
    jnz  .open_failed
    mov  [rbx + r12], dl
    movzx edi, dl
    mov  rsi, [rel ime_arena]
    add  rsi, R0_IDENT
    call res_pack_info
    test eax, eax
    jnz  .open_failed_status
    mov  r13, rdx                       ; bytes
    mov  r8d, ecx                       ; pages
    mov  rsi, [rel ime_arena]
    mov  r9d, [rsi + R0_IDENT]          ; the admitted row count
    test r9d, r9d
    jz   .ident
    cmp  r9d, PD_COUNT_MAX
    ja   .ident
    mov  edi, r12d
    call id_shard
    mov  [rax + SH_FIRST_ROW], r15d
    mov  [rax + SH_ROWS], r9d
    mov  [rax + SH_BYTES], r13d
    mov  [rax + SH_PAGES], r8d
    mov  [rax + SH_PPGH], r14d
    mov  [rax + SH_FIRST_ANCHOR], ebp
    shl  r8d, 5
    add  r8d, 64
    add  r14d, r8d                      ; this table's exact bytes
    mov  eax, [rel ic_cache_bytes]
    sub  eax, IME_BIND_MIN_SLOTS * 4096 + 4096
    cmp  r14d, eax
    ja   .budget
    add  r15d, r9d
    mov  eax, r9d
    add  eax, [rel ic_stride]
    dec  eax
    xor  edx, edx
    div  dword [rel ic_stride]
    add  ebp, eax
    inc  r12d
    jmp  .open_next
.probe:
    ; shard N must not be listed: the compiled count is the whole set
    mov  edi, r12d
    mov  rsi, [rel ic_cache]
    add  rsi, r14
    mov  edx, [rel ic_cache_bytes]
    sub  edx, r14d
    call id_open
    cmp  eax, RP_E_NOT_LISTED
    je   .pass1b
    test eax, eax
    jnz  .extra
    mov  [rbx + r12], dl                ; closed by the failure path
.extra:
    mov  [rel ime_err_detail], r12d
    mov  eax, IME_E_SHARDS
    jmp  .fail
.pass1b:
    mov  [rel ib_tables], r14d
    mov  [rel ib_anchors], ebp
    ; bind page slots: after the tables, metadata in R0
    mov  rax, [rel ic_cache]
    lea  rax, [rax + r14 + 4095]
    and  rax, -4096
    mov  ecx, [rel ic_li]
    lea  rdx, [rel ime_cache_p]
    mov  [rdx + rcx*8], rax
    mov  rdx, [rel ic_cache]
    mov  esi, [rel ic_cache_bytes]
    add  rdx, rsi
    sub  rdx, rax
    shr  rdx, 12
    mov  eax, IME_BIND_SLOTS
    cmp  edx, eax
    cmova edx, eax
    lea  rax, [rel ime_nslots]
    mov  [rax + rcx*4], edx
    mov  rax, [rel ime_arena]
    add  rax, R0_META
    lea  rdx, [rel ime_meta_p]
    mov  [rdx + rcx*8], rax
    ; layout up to the key pool
    mov  eax, [rel ic_shards]
    imul eax, eax, SH_SIZE
    add  eax, PX_SHARD_TABLE + 4095
    and  eax, -4096
    mov  [rel ib_anchor_off], eax
    imul ecx, ebp, AN_SIZE
    add  eax, ecx
    add  eax, 4095
    and  eax, -4096
    mov  [rel ib_pool_off], eax
    cmp  eax, [rel ic_budget]
    ja   .budget
    mov  dword [rel ib_pool], 0
    ; pass 1b: per shard, the header, the anchors and their keys, the order
    xor  r12d, r12d
    xor  ebp, ebp                       ; anchor index
.shard_next:
    cmp  r12d, [rel ic_shards]
    jae  .layout
    call id_check_header                ; R12D = k
    test eax, eax
    jnz  .fail
    mov  edi, r12d
    call id_shard
    mov  r13, rax
    xor  r14d, r14d                     ; row in the shard
.anchor_next:
    cmp  r14d, [r13 + SH_ROWS]
    jae  .order
    mov  edi, r12d
    mov  esi, r14d
    mov  rdx, [rel ime_arena]
    add  rdx, R0_ROW_A
    xor  ecx, ecx
    call id_row
    test eax, eax
    jnz  .fail_row
    mov  rsi, [rel ime_arena]
    mov  r15d, [rsi + R0_ROW_A + PR_KEY_LEN]
    mov  eax, [rel ib_pool_off]
    add  eax, [rel ib_pool]
    add  eax, r15d
    cmp  eax, [rel ic_budget]
    ja   .budget
    mov  rdi, [rel ic_idx]
    mov  eax, [rel ib_anchor_off]
    add  rdi, rax
    imul eax, ebp, AN_SIZE
    add  rdi, rax
    mov  eax, [r13 + SH_FIRST_ROW]
    add  eax, r14d
    mov  [rdi + AN_ROW], eax
    mov  eax, [rel ib_pool]
    mov  [rdi + AN_KEY_OFF], eax
    mov  [rdi + AN_KEY_LEN], r15w
    mov  rdi, [rel ic_idx]
    mov  eax, [rel ib_pool_off]
    add  rdi, rax
    mov  eax, [rel ib_pool]
    add  rdi, rax
    lea  rsi, [rsi + R0_ROW_A + ROWBUF_KEY]
    mov  edx, r15d
    call memcpy
    add  [rel ib_pool], r15d
    inc  ebp
    add  r14d, [rel ic_stride]
    jmp  .anchor_next
.order:
    ; the last row of shard k-1 sorts strictly below the first row of shard k
    test r12d, r12d
    jz   .shard_done
    lea  edi, [r12 - 1]
    call id_shard
    mov  esi, [rax + SH_ROWS]
    dec  esi
    lea  edi, [r12 - 1]
    mov  rdx, [rel ime_arena]
    add  rdx, R0_ROW_B
    mov  ecx, 1
    call id_row
    test eax, eax
    jnz  .fail_row
    mov  edi, r12d
    xor  esi, esi
    mov  rdx, [rel ime_arena]
    add  rdx, R0_ROW_A
    mov  ecx, 1
    call id_row
    test eax, eax
    jnz  .fail_row
    mov  rdi, [rel ime_arena]
    lea  rsi, [rdi + R0_ROW_A]
    add  rdi, R0_ROW_B
    call id_cmp_rows
    cmp  eax, 0
    jl   .shard_done
    mov  [rel ime_err_detail], r12d
    mov  eax, IME_E_ORDER
    jmp  .fail
.shard_done:
    inc  r12d
    jmp  .shard_next
.layout:
    mov  eax, [rel ib_pool_off]
    add  eax, [rel ib_pool]
    add  eax, 4095
    and  eax, -4096
    mov  [rel ib_ppgh_off], eax
    add  eax, [rel ib_tables]
    add  eax, 4095
    and  eax, -4096
    mov  [rel ib_slot_off], eax
    mov  ecx, [rel ic_slots]
    shl  ecx, 4
    add  eax, ecx
    add  eax, 4095
    and  eax, -4096
    mov  [rel ib_cand_off], eax
    add  eax, CAND_AND_CONTROL
    cmp  eax, [rel ic_budget]
    ja   .budget
    ; pass 2: every table moves to its final place in the PPGH area
    call id_close_all
    xor  r12d, r12d
.reopen_next:
    cmp  r12d, [rel ic_shards]
    jae  .header
    mov  edi, r12d
    call id_shard
    mov  edx, [rax + SH_PAGES]
    shl  edx, 5
    add  edx, 64
    mov  rsi, [rel ic_idx]
    mov  ecx, [rel ib_ppgh_off]
    add  rsi, rcx
    mov  ecx, [rax + SH_PPGH]
    add  rsi, rcx
    mov  edi, r12d
    call id_open
    test eax, eax
    jnz  .open_failed
    mov  [rbx + r12], dl
    inc  r12d
    jmp  .reopen_next
.header:
    mov  rdi, [rel ic_idx]
    mov  rax, [rel ime_pidx_magic]
    mov  [rdi], rax
    mov  word [rdi + PX_VERSION], 1
    mov  eax, [rel ic_li]
    inc  eax
    mov  [rdi + PX_LOCALE], ax
    mov  eax, [rel ic_stride]
    mov  [rdi + PX_STRIDE], eax
    mov  eax, [rel ic_shards]
    mov  [rdi + PX_SHARDS], eax
    mov  eax, [rel ib_anchors]
    mov  [rdi + PX_ANCHORS], eax
    mov  eax, [rel ib_pool]
    mov  [rdi + PX_POOL_BYTES], eax
    mov  dword [rdi + PX_SHARD_OFF], PX_SHARD_TABLE
    mov  eax, [rel ib_anchor_off]
    mov  [rdi + PX_ANCHOR_OFF], eax
    mov  eax, [rel ib_pool_off]
    mov  [rdi + PX_POOL_OFF], eax
    mov  eax, [rel ib_ppgh_off]
    mov  [rdi + PX_PPGH_OFF], eax
    mov  eax, [rel ib_slot_off]
    mov  [rdi + PX_SLOT_OFF], eax
    mov  eax, [rel ib_cand_off]
    mov  [rdi + PX_CAND_OFF], eax
    ; cold cache: wipe the cache region and R0; metadata now lives in the index
    mov  rdi, [rel ic_cache]
    xor  esi, esi
    mov  edx, [rel ic_cache_bytes]
    call memset
    mov  rdi, [rel ime_arena]
    xor  esi, esi
    mov  edx, 4096
    call memset
    mov  ecx, [rel ic_li]
    mov  rax, [rel ic_cache]
    lea  rdx, [rel ime_cache_p]
    mov  [rdx + rcx*8], rax
    mov  rax, [rel ic_idx]
    mov  edx, [rel ib_slot_off]
    add  rax, rdx
    lea  rdx, [rel ime_meta_p]
    mov  [rdx + rcx*8], rax
    mov  eax, [rel ic_slots]
    lea  rdx, [rel ime_nslots]
    mov  [rdx + rcx*4], eax
    lea  rdx, [rel ime_clock]
    mov  dword [rdx + rcx*4], 0
    lea  rdx, [rel ime_bound]
    mov  byte [rdx + rcx], 1
    xor  eax, eax
    mov  edx, [rel ib_anchors]
    jmp  .marker
.already:
    xor  eax, eax
    xor  edx, edx
    jmp  .out
.bad_locale:
    mov  eax, IME_E_LOCALE
    xor  edx, edx
    jmp  .out
.latched:
    mov  eax, IME_E_READ                ; latched: unbind first (its handles are still open)
    xor  edx, edx
    jmp  .out
.open_failed:
    mov  [rel ime_err_detail], eax
    cmp  eax, RP_E_NOT_LISTED
    mov  eax, IME_E_OPEN
    jne  .fail
    mov  [rel ime_err_detail], r12d
    mov  eax, IME_E_SHARDS
    jmp  .fail
.open_failed_status:
    mov  [rel ime_err_detail], eax
    mov  eax, IME_E_OPEN
    jmp  .fail
.ident:
    mov  [rel ime_err_detail], r12d
    mov  eax, IME_E_IDENT
    jmp  .fail
.budget:
    mov  eax, IME_E_BUDGET
    jmp  .fail
.fail_row:
    cmp  eax, IME_E_READ
    je   .fail
    mov  [rel ime_err_detail], r12d
.fail:
    mov  [rsp], eax
    call id_close_all
    call id_wipe
    mov  eax, [rsp]
.early:
    mov  edx, [rel ime_err_detail]
.marker:
    mov  [rsp], eax
    mov  r13d, edx
    lea  rdi, [rel str_ime_bind]
    call serial_string
    mov  edi, [rel ic_li]
    inc  edi
    call serial_hex64
    lea  rdi, [rel str_ime_status]
    call serial_string
    mov  edi, [rsp]
    call serial_hex64
    lea  rdi, [rel str_ime_detail]
    call serial_string
    mov  edi, r13d
    call serial_hex64
    lea  rdi, [rel str_ime_eol]
    call serial_string
    mov  eax, [rsp]
    mov  edx, r13d
.out:
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; id_check_header(R12D shard k, called from bind) -> EAX IME_OK / IME_E_HEADER
; (ime_err_detail = k) / IME_E_READ. The PDCT1 header and metadata of a shard:
; every field native relies on, plus the reserved bytes, and its row count
; equal to the admitted identity's.
id_check_header:
    push rbx
    push r13
    sub  rsp, 8
    mov  edi, r12d
    xor  esi, esi
    mov  edx, PD_ROWS
    mov  rcx, [rel ime_arena]
    add  rcx, R0_HEADER
    call id_read
    test eax, eax
    jnz  .out
    mov  edi, r12d
    call id_shard
    mov  r13, rax
    mov  rbx, [rel ime_arena]
    add  rbx, R0_HEADER
    mov  rax, [rel ime_pdct_magic]
    cmp  [rbx], rax
    jne  .bad
    cmp  word [rbx + PD_VERSION], 1
    jne  .bad
    cmp  word [rbx + PD_KIND], 2
    jne  .bad
    cmp  dword [rbx + PD_HEADER_SIZE], 128
    jne  .bad
    mov  eax, [r13 + SH_BYTES]
    cmp  [rbx + PD_TOTAL], eax
    jne  .bad
    cmp  dword [rbx + PD_FLAGS], 0
    jne  .bad
    cmp  dword [rbx + PD_META_OFF], 128
    jne  .bad
    cmp  dword [rbx + PD_META_BYTES], 64
    jne  .bad
    cmp  dword [rbx + PD_INDEX_OFF], PD_ROWS
    jne  .bad
    mov  eax, [r13 + SH_ROWS]
    cmp  [rbx + PD_COUNT], eax
    jne  .bad
    cmp  dword [rbx + PD_ENTRY], PD_ROW
    jne  .bad
    imul eax, eax, PD_ROW
    add  eax, PD_ROWS
    cmp  [rbx + PD_BLOB_OFF], eax
    jne  .bad
    add  eax, [rbx + PD_BLOB_BYTES]
    jc   .bad
    cmp  eax, [r13 + SH_BYTES]
    jne  .bad
    lea  rdi, [rbx + PD_RESERVED]       ; 52..87: reserved u32 + reserved32
    mov  ecx, 36
    call id_zero
    jnz  .bad
    lea  rdi, [rbx + 120]
    mov  ecx, 8
    call id_zero
    jnz  .bad
    mov  eax, [rel ic_li]
    lea  rcx, [rel ime_locale8]
    mov  rax, [rcx + rax*8]
    cmp  [rbx + PD_META_LOCALE], rax
    jne  .bad
    movzx eax, word [rbx + PD_META_SRC_KIND]
    cmp  eax, [rel ic_src_kind]
    jne  .bad
    cmp  word [rbx + PD_META_CODEC], 1
    jne  .bad
    cmp  dword [rbx + PD_META_MAX_KEY], PD_KEY_MAX
    jne  .bad
    lea  rdi, [rbx + PD_META_RESERVED]
    mov  ecx, 16
    call id_zero
    jnz  .bad
    xor  eax, eax
    jmp  .out
.bad:
    mov  [rel ime_err_detail], r12d
    mov  eax, IME_E_HEADER
.out:
    add  rsp, 8
    pop  r13
    pop  rbx
    ret

; id_zero(RDI p, ECX n) -> ZF set when all n bytes are zero. Clobbers RAX RCX RDI.
id_zero:
    xor  eax, eax
    cld
    repe scasb
    ret

; ime_dict_unbind(EDI locale) -> EAX IME_OK / IME_E_LOCALE: closes every handle
; of the locale and wipes its regions (IME disable or a locale switch).
ime_dict_unbind:
    sub  rsp, 8
    lea  eax, [rdi - 1]
    cmp  eax, 1
    ja   .locale
    cmp  byte [rel ime_arena_st], 1
    jne  .ok
    call id_setup
    call id_close_all
    call id_wipe
.ok:
    xor  eax, eax
    add  rsp, 8
    ret
.locale:
    mov  eax, IME_E_LOCALE
    add  rsp, 8
    ret

; id_locate(EDI global row) -> EAX shard, EDX row in it; CF set when no shard of
; the current locale holds it.
id_locate:
    mov  r8, [rel ic_idx]
    add  r8, PX_SHARD_TABLE
    xor  eax, eax
.next:
    cmp  eax, [rel ic_shards]
    jae  .miss
    mov  edx, edi
    sub  edx, [r8 + SH_FIRST_ROW]
    jb   .skip
    cmp  edx, [r8 + SH_ROWS]
    jb   .hit
.skip:
    add  r8, SH_SIZE
    inc  eax
    jmp  .next
.hit:
    clc
    ret
.miss:
    stc
    ret

; id_rank(RAX candidate entry <score_bits u32, global_row u32>) -> RAX its
; order, smaller first: ja cost ascending (i32), zh-Hans weight descending
; (u32), then the global row ascending (CONTRACT_I1_PDCT D5). Clobbers RCX.
id_rank:
    mov  ecx, eax
    shr  rax, 32
    cmp  dword [rel ic_li], 0
    jne  .zh
    xor  ecx, 0x80000000
    jmp  .pack
.zh:
    not  ecx
.pack:
    shl  rcx, 32
    or   rax, rcx
    ret

; id_cand(ECX i) -> RAX the address of candidate scratch entry i.
id_cand:
    mov  rax, [rel ic_idx]
    mov  edx, [rax + PX_CAND_OFF]
    add  rax, rdx
    lea  rax, [rax + rcx*8]
    ret

; id_ctl() -> RAX the control scratch page (after the candidate scratch).
id_ctl:
    mov  rax, [rel ic_idx]
    mov  edx, [rax + PX_CAND_OFF]
    add  rax, rdx
    add  rax, IME_MATCH_MAX * 8
    ret

; ime_dict_lookup(EDI locale, RSI key, EDX len) -> EAX status, ECX unique
; candidates, EDX raw rows. CONTRACT_I1_PDCT D4/D5: lower_bound over the anchors
; (the first anchor key >= the query), start at the PRECEDING anchor, read at
; most a stride of smaller keys, then every row whose key equals the query,
; across pages and shards. Rows with one key sort by surface, so equal surfaces
; are adjacent: each run keeps its best-ranked row (the others merge). The
; candidate scratch then holds the unique rows <score_bits, global_row> in rank
; order; ime_dict_candidate reads their surfaces. More than 512 raw rows: a
; refusal and a marker, never a truncated list. Any failure leaves 0 candidates.
ime_dict_lookup:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 24
    mov  rbx, rsi
    mov  r12d, edx
    lea  eax, [rdi - 1]
    cmp  eax, 1
    ja   .locale
    lea  rcx, [rel ime_bound]
    cmp  byte [rcx + rax], 2
    je   .latched
    cmp  byte [rcx + rax], 1
    jne  .unbound
    call id_setup
    mov  ecx, [rel ic_li]
    lea  rax, [rel ime_cand_n]
    mov  dword [rax + rcx*4], 0
    lea  eax, [r12 - 1]
    cmp  eax, PD_KEY_MAX - 1
    ja   .key
    ; lower_bound over the anchors
    mov  r8, [rel ic_idx]
    xor  r13d, r13d                     ; lo
    mov  r14d, [r8 + PX_ANCHORS]        ; hi
.bisect:
    cmp  r13d, r14d
    jae  .found
    lea  ebp, [r13 + r14]
    shr  ebp, 1
    call id_anchor_cmp                  ; EBP anchor -> EAX sign of anchor key vs query
    cmp  eax, 0
    jge  .upper
    lea  r13d, [rbp + 1]
    jmp  .bisect
.upper:
    mov  r14d, ebp
    jmp  .bisect
.found:
    test r13d, r13d
    jz   .start
    dec  r13d
.start:
    mov  r8, [rel ic_idx]
    mov  eax, [r8 + PX_ANCHOR_OFF]
    add  r8, rax
    imul eax, r13d, AN_SIZE
    mov  edi, [r8 + rax + AN_ROW]
    call id_locate
    jc   .row
    mov  r13d, eax                      ; shard
    mov  r14d, edx                      ; row in it
    xor  r15d, r15d                     ; raw matches
    mov  dword [rsp], 0                 ; unique so far
    mov  dword [rsp + 4], 0             ; smaller keys read
.scan:
    mov  edi, r13d
    call id_shard
    cmp  r14d, [rax + SH_ROWS]
    jb   .read_row
    inc  r13d
    xor  r14d, r14d
    cmp  r13d, [rel ic_shards]
    jb   .scan
    jmp  .done
.read_row:
    call id_ctl
    mov  rdx, rax
    mov  edi, r13d
    mov  esi, r14d
    xor  ecx, ecx
    call id_row
    test eax, eax
    jnz  .fail
    call id_ctl
    lea  rdi, [rax + CTL_ROW + ROWBUF_KEY]
    mov  esi, [rax + CTL_ROW + PR_KEY_LEN]
    mov  rdx, rbx
    mov  ecx, r12d
    call id_cmp_bytes
    cmp  eax, 0
    jg   .done
    je   .match
    test r15d, r15d
    jnz  .done                          ; smaller after a match: not sorted, stop
    inc  dword [rsp + 4]
    mov  eax, [rel ic_stride]
    cmp  [rsp + 4], eax
    ja   .done                          ; past the next anchor: the key is absent
    jmp  .next_row
.match:
    inc  r15d
    cmp  r15d, IME_MATCH_MAX
    ja   .matches
    call id_ctl
    mov  rdx, rax
    mov  edi, r13d
    mov  esi, r14d
    mov  ecx, 1
    call id_row
    test eax, eax
    jnz  .fail
    call id_ctl
    mov  rbp, rax
    mov  ecx, [rbp + CTL_ROW + PR_COST]
    cmp  dword [rel ic_li], 0
    je   .score
    mov  ecx, [rbp + CTL_ROW + PR_WEIGHT]
.score:
    mov  edi, r13d
    call id_shard
    mov  edx, [rax + SH_FIRST_ROW]
    add  edx, r14d                      ; global row
    shl  rdx, 32
    or   rdx, rcx
    mov  [rsp + 8], rdx                 ; this row's entry
    mov  ecx, [rsp]
    test ecx, ecx
    jz   .new
    lea  rdi, [rbp + CTL_ROW + ROWBUF_SURF]
    mov  esi, [rbp + CTL_ROW + PR_SURF_LEN]
    lea  rdx, [rbp + CTL_PREV + ROWBUF_SURF]
    mov  ecx, [rbp + CTL_PREV + PR_SURF_LEN]
    call id_cmp_bytes
    test eax, eax
    jnz  .new
    ; same surface as the run so far: keep the better-ranked row
    mov  ecx, [rsp]
    dec  ecx
    call id_cand
    mov  rbp, rax
    mov  rax, [rsp + 8]
    call id_rank
    mov  [rsp + 16], rax
    mov  rax, [rbp]
    call id_rank
    cmp  [rsp + 16], rax
    jae  .next_row
    mov  rax, [rsp + 8]
    mov  [rbp], rax
    jmp  .next_row
.new:
    mov  ecx, [rsp]
    call id_cand
    mov  rdx, [rsp + 8]
    mov  [rax], rdx
    inc  dword [rsp]
    call id_ctl
    lea  rdi, [rax + CTL_PREV]
    lea  rsi, [rax + CTL_ROW]
    mov  edx, CTL_PREV
    call memcpy
.next_row:
    inc  r14d
    jmp  .scan
.done:
    mov  ebp, [rsp]
    call id_sort                        ; EBP entries
    mov  ecx, [rel ic_li]
    lea  rax, [rel ime_cand_n]
    mov  [rax + rcx*4], ebp
    xor  eax, eax
    mov  ecx, ebp
    mov  edx, r15d
    jmp  .out
.matches:
    lea  rdi, [rel str_ime_lookup]
    call serial_string
    mov  edi, [rel ic_li]
    inc  edi
    call serial_hex64
    lea  rdi, [rel str_ime_rows]
    call serial_string
    mov  edi, IME_MATCH_MAX
    call serial_hex64
    lea  rdi, [rel str_ime_eol]
    call serial_string
    mov  eax, IME_E_MATCHES
    jmp  .fail
.locale:
    mov  eax, IME_E_LOCALE
    jmp  .zero
.latched:
    mov  eax, IME_E_READ
    jmp  .zero
.unbound:
    mov  eax, IME_E_UNBOUND
    jmp  .zero
.key:
    mov  eax, IME_E_KEY
    jmp  .zero
.row:
    mov  eax, IME_E_ROW
.fail:
    mov  ecx, [rel ic_li]
    lea  rdx, [rel ime_cand_n]
    mov  dword [rdx + rcx*4], 0
.zero:
    xor  ecx, ecx
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

; id_anchor_cmp(EBP anchor index; RBX query, R12D its length) -> EAX the sign
; of the anchor's key against the query. The key is in the derived index.
id_anchor_cmp:
    sub  rsp, 8
    mov  r8, [rel ic_idx]
    mov  eax, [r8 + PX_ANCHOR_OFF]
    imul ecx, ebp, AN_SIZE
    add  eax, ecx
    lea  r9, [r8 + rax]
    mov  edi, [r8 + PX_POOL_OFF]
    add  edi, [r9 + AN_KEY_OFF]
    add  rdi, r8
    movzx esi, word [r9 + AN_KEY_LEN]
    mov  rdx, rbx
    mov  ecx, r12d
    call id_cmp_bytes
    add  rsp, 8
    ret

; id_sort(EBP n): insertion sort of candidate entries 0..n-1 by id_rank
; (n <= 512). Preserves RBX RBP R12-R15.
id_sort:
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8
    xor  ecx, ecx
    call id_cand
    mov  r12, rax                       ; entry 0
    mov  r13d, 1
.outer:
    cmp  r13d, ebp
    jae  .out
    mov  r14, [r12 + r13*8]             ; the entry being placed
    mov  rax, r14
    call id_rank
    mov  r15, rax
    mov  edx, r13d
.inner:
    test edx, edx
    jz   .place
    mov  rax, [r12 + rdx*8 - 8]
    call id_rank
    cmp  rax, r15
    jbe  .place
    mov  rax, [r12 + rdx*8 - 8]
    mov  [r12 + rdx*8], rax
    dec  edx
    jmp  .inner
.place:
    mov  [r12 + rdx*8], r14
    inc  r13d
    jmp  .outer
.out:
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    ret

; ime_dict_candidate(EDI locale, ESI i, RDX out 256 B) -> EAX status, EDX the
; surface's bytes, ECX its global row: candidate i of the locale's last lookup.
ime_dict_candidate:
    push rbx
    push r12
    push r13
    mov  r12d, esi
    mov  r13, rdx
    lea  eax, [rdi - 1]
    cmp  eax, 1
    ja   .locale
    lea  rcx, [rel ime_bound]
    cmp  byte [rcx + rax], 2
    je   .latched
    cmp  byte [rcx + rax], 1
    jne  .unbound
    call id_setup
    mov  ecx, [rel ic_li]
    lea  rax, [rel ime_cand_n]
    cmp  r12d, [rax + rcx*4]
    jae  .row
    mov  ecx, r12d
    call id_cand
    mov  ebx, [rax + 4]                 ; global row
    mov  edi, ebx
    call id_locate
    jc   .row
    mov  edi, eax
    mov  esi, edx
    call id_ctl
    mov  rdx, rax
    mov  ecx, 1
    call id_row
    test eax, eax
    jnz  .zero
    call id_ctl
    lea  rsi, [rax + CTL_ROW + ROWBUF_SURF]
    mov  edx, [rax + CTL_ROW + PR_SURF_LEN]
    mov  r12d, edx
    mov  rdi, r13
    call memcpy
    xor  eax, eax
    mov  edx, r12d
    mov  ecx, ebx
    jmp  .out
.locale:
    mov  eax, IME_E_LOCALE
    jmp  .zero
.latched:
    mov  eax, IME_E_READ
    jmp  .zero
.unbound:
    mov  eax, IME_E_UNBOUND
    jmp  .zero
.row:
    mov  eax, IME_E_ROW
.zero:
    xor  ecx, ecx
    xor  edx, edx
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; the reservation map: (offset, size) of R0..R5 inside the arena
ime_map:             dd 0, 4096
                     dd 4096, 1048576
                     dd 1052672, 2097152
                     dd 3149824, 262144
                     dd 3411968, 786432
                     dd 4198400, 1048576
; per locale: index region, cache region, slots, stride, shards, source kind,
; index budget, cache bytes (32 B each; ja, then zh-Hans)
ime_desc:            dd 1, 2, 512, 128, IME_JA_SHARDS, 2, 1048576, 2097152
                     dd 3, 4, 192, 64, IME_ZH_SHARDS, 1, 262144, 786432
ime_image_shards:    db IME_JA_IMAGE_SHARDS, IME_ZH_IMAGE_SHARDS
ime_dict_bound:      db 1                ; a dictionary is linked (per-locale state: ime_bound)
ime_locale8:         db "ja", 0, 0, 0, 0, 0, 0
                     db "zh-Hans", 0
ime_pdct_magic:      db "PDCT1", 0, 0, 0
ime_pidx_magic:      db "PIDX1", 0, 0, 0
str_ime_ja_prefix:   db "ja-full-"
str_ime_ja_prefix_len equ $ - str_ime_ja_prefix
str_ime_zh_prefix:   db "pinyin-full-"
str_ime_zh_prefix_len equ $ - str_ime_zh_prefix
str_ime_bind:        db "[ime.dict] bind locale=", 0
str_ime_status:      db " status=", 0
str_ime_detail:      db " detail=", 0
str_ime_eol:         db 13, 10, 0
str_ime_lookup:      db "[ime.dict] lookup refused locale=", 0
str_ime_rows:        db " rows>", 0

%macro WDATA_gui_ime_dict 0
alignb 8
ime_arena:           resq 1             ; the 4 KiB-rounded base (0 = not taken)
ime_arena_raw:       resq 1             ; kmalloc_model's pointer
ime_cache_p:         resq 2             ; per locale: page slot 0
ime_meta_p:          resq 2             ; per locale: slot metadata
ime_nslots:          resd 2             ; per locale: slots in use (0 = no cache)
ime_clock:           resd 2             ; per locale: LRU stamp
ime_err_detail:      resd 1
ic_li:               resd 1             ; the current locale: 0 ja, 1 zh-Hans
ic_slots:            resd 1
ic_stride:           resd 1
ic_shards:           resd 1
ic_src_kind:         resd 1
ic_budget:           resd 1
ic_cache_bytes:      resd 1
ic_idx:              resq 1
ic_cache:            resq 1
ib_tables:           resd 1             ; bind: PPGH bytes of every shard
ib_anchors:          resd 1
ib_pool:             resd 1
ib_anchor_off:       resd 1
ib_pool_off:         resd 1
ib_ppgh_off:         resd 1
ib_slot_off:         resd 1
ib_cand_off:         resd 1
ime_ident:           resb 16            ; the open request's identity16
ime_name:            resb 32
ime_hnd:             resb 64            ; per locale: 32 res_pack handles
ime_cand_n:          resd 2             ; per locale: unique candidates of the last lookup
ime_bound:           resb 2             ; per locale: 0 no, 1 bound, 2 latched (until unbind)
ime_arena_st:        resb 1             ; 0 untried, 1 taken, 2 refused
%endmacro
WDATA_BSS_DEFER WDATA_gui_ime_dict
