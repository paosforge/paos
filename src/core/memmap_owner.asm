;; MODULE core/memmap_owner
%include "core/abi/build_profile.inc"
;; LAYER 1
;; EXPORTS memmap_owner_census, memmap_owner_selftest
;; IMPORTS boot/serial, boot/paging, sec/ucode_preload, sec/cpu_microcode_boot, boot/pmod_loader
;; CAPS
;; OWNER saga:core
; ============================================================================
; core/memmap_owner.asm — firmware memory-ownership census (RC s21.1).
;
; Every PaOS-owned pre-EBS region is allocated as EfiLoaderData (AllocatePages
; type 2 / AllocatePool type 2) before boot/paging.asm reads the final UEFI map
; that becomes current at ExitBootServices (mmap_final_publish): the paging
; regions, plus three pools other boot modules keep and read after EBS
; (sec/ucode_preload's microcode pack pool, only while the pack was admitted
; to mcb_pack_buf, every other path frees it; boot/pmod_loader's two 4 KiB
; preload buffers, HELLO and netmon, never freed), the retained fatal identity
; page and HP high-page mapping probe. Each page allocation has a zero owner
; on absence and remains LoaderData in the final map. This
; census walks that PUBLISHED map (mmap_buffer / mmap_size / mmap_desc_size,
; stride = mmap_desc_size, never a hardcoded width) and proves, for every
; PaOS region that is present (base != 0 and length != 0; absent ones are
; skipped and counted):
;   1. its page span is fully covered by type 1 (LoaderCode) / 2 (LoaderData)
;      descriptors (sum of overlap == span; descriptors are nonoverlapping),
;   2. it overlaps NO descriptor of any other type (reserved, boot services,
;      runtime, conventional, unusable, ACPI, MMIO, PAL, persistent, unknown),
;   3. no two present PaOS regions overlap each other (exact bytes).
; Pool allocations are byte ranges that need not be page aligned: coverage
; and foreign-type checks use the span rounded OUTWARD to 4 KiB pages (a
; pool page carries its pool's type); region-vs-region overlap uses the exact
; bytes, so two pool blocks sharing one pool page are not a self overlap.
;
; Not included on purpose: the PE image itself (firmware/Manager-owned
; LoadImage allocation, type not PaOS's choice), post-EBS memory_budget spans
; (type 7 by design), leaked pre-EBS retries that keep no pointer, and
; boot/chainload's device-path pool (freed before every return to PaOS, or
; handed to a foreign OS by StartImage, which never returns).
;
; Read-only: no firmware call, allocation, map or region-variable write. A
; failure prints one line and returns; it never halts the boot.
; ============================================================================

MMO_REGION_MAX     equ 18                  ; slots below, in this order
MMO_SPAN_BYTES     equ 16                  ; {base:u64, length:u64}
MMO_NO_INDEX       equ 0xFFFFFFFF          ; region/type field not applicable
MMO_DESC_MIN       equ 40                  ; EFI_MEMORY_DESCRIPTOR v1 size
MMO_DESC_MAX       equ 256
MMO_MAP_MAX        equ 65536               ; paging's MMAP_BUFFER_BYTES capacity
MMO_PMOD_REGION    equ 16 * 4096           ; paging: AllocatePages 16 (LoaderData)
MMO_PMOD_PT        equ 8192                ; paging: AllocatePool 8192 (LoaderData)
MMO_PMOD_SANDBOX   equ 16384               ; paging: AllocatePool 16384 (LoaderData)
MMO_WX_PAGE        equ 4096                ; paging: AllocatePool 4096 (LoaderData)
MMO_INV_MAP        equ 65536               ; paging: INV_MAP_BYTES AllocatePool (LoaderData)
MMO_UCP_POOL       equ 0x100000 + 16       ; ucode_preload: UCP_MAX + UCP_ALIGN AllocatePool (LoaderData)
MMO_PERCPU_STACK   equ 0x400000           ; percpu_stack: PERCPU_STACK_ALLOC_SIZE retained allocation
MMO_CRASH_IDENTITY equ 4096               ; crash_identity.inc: CRID_PAGES = 1
MMO_HP_MAPPING     equ 4096               ; hp_usb_mapping: one retained LoaderData page
MMO_PMOD_FILE      equ 4096                ; pmod_loader: PMOD_FILE_MAX AllocatePool (LoaderData)

MMO_R_UNCOVERED    equ 1
MMO_R_FOREIGN      equ 2
MMO_R_OVERLAP      equ 3
MMO_R_MAP          equ 4

; census output record (32 bytes, caller-owned)
MMO_OUT_REASON     equ 0                   ; u32: 0 pass, else MMO_R_*
MMO_OUT_REGION     equ 4                   ; u32: failing slot, MMO_NO_INDEX if none
MMO_OUT_TYPE       equ 8                   ; u32: foreign descriptor type, else MMO_NO_INDEX
MMO_OUT_REGIONS    equ 12                  ; u32: present regions
MMO_OUT_ABSENT     equ 16                  ; u32: absent regions
MMO_OUT_LOADER     equ 24                  ; u64: sum of page-rounded loader-covered bytes
MMO_OUT_BYTES      equ 32

; Slot r12 (byte offset) <- {rax = base, rdx = byte length}.
%macro MMO_PUT 0
    mov  [rbx + r12], rax
    mov  [rbx + r12 + 8], rdx
    add  r12, MMO_SPAN_BYTES
%endmacro

; memmap_owner_census(RDI=out[MMO_OUT_BYTES]) -> EAX = 0 pass / MMO_R_* reason.
; Preserves RBX, RBP, R12-R15. Clobbers RAX, RCX, RDX, RSI, RDI, R8-R11.
memmap_owner_census:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, MMO_REGION_MAX * MMO_SPAN_BYTES
    mov  r15, rdi
    xor  eax, eax
    mov  [r15 + MMO_OUT_REGIONS], eax
    mov  [r15 + MMO_OUT_ABSENT], rax
    mov  [r15 + MMO_OUT_LOADER], rax
    mov  dword [r15 + MMO_OUT_REASON], MMO_R_MAP
    mov  dword [r15 + MMO_OUT_REGION], MMO_NO_INDEX
    mov  dword [r15 + MMO_OUT_TYPE], MMO_NO_INDEX

    ; --- the published map: shape + every descriptor (defensive repeat of
    ;     mmap_final_validate's admission; nothing is trusted unchecked) ---
    mov  rsi, [rel mmap_buffer]
    test rsi, rsi
    jz   .out
    mov  r8, [rel mmap_desc_size]
    cmp  r8, MMO_DESC_MIN
    jb   .out
    cmp  r8, MMO_DESC_MAX
    ja   .out
    test r8, 7
    jnz  .out
    mov  r9, [rel mmap_size]
    test r9, r9
    jz   .out
    cmp  r9, MMO_MAP_MAX
    ja   .out
    mov  rax, rsi
    add  rax, r9
    jc   .out
    mov  rax, r9
    xor  edx, edx
    div  r8
    test rdx, rdx
    jnz  .out
    mov  rcx, r9
.shape:
    mov  rax, [rsi + 8]
    test eax, 4095
    jnz  .out
    mov  rdx, [rsi + 24]
    test rdx, rdx
    jz   .out
    mov  rdi, rdx
    shr  rdi, 52
    jnz  .out
    shl  rdx, 12
    add  rax, rdx
    jc   .out
    add  rsi, r8
    sub  rcx, r8
    jnz  .shape

    ; --- the PaOS-owned pre-EBS regions (paging, ucode_preload, pmod_loader data) ---
    mov  rbx, rsp
    xor  r12d, r12d
    mov  rax, [rel heap_base]               ; 0 heap (bytes)
    mov  rdx, [rel heap_size]
    MMO_PUT
    mov  rax, [rel model_heap_alloc_base]   ; 1 entire arena, including verified model prefix
    mov  rdx, [rel model_heap_alloc_size]
    MMO_PUT
    mov  rdx, [rel pt_alloc_pages]          ; page count -> bytes
    mov  rax, rdx
    shr  rax, 52
    jz   .pt_pages_ok
    mov  rdx, -1                            ; unrepresentable -> wraps -> uncovered
    jmp  .pt_len_ready
.pt_pages_ok:
    shl  rdx, 12
.pt_len_ready:
    mov  rax, [rel pt_alloc_buf]            ; 2 page tables (pages)
    MMO_PUT
    mov  rax, [rel fb_shadow_region_base]   ; 3 GUI back buffer (bytes)
    mov  rdx, [rel fb_shadow_region_size]
    MMO_PUT
    mov  rax, [rel diag_ring_base]          ; 4 diag ring (fixed pages or pooled fallback)
    mov  edx, DIAG_RING_SIZE
    MMO_PUT
    mov  rax, [rel filmstrip_ring_base]     ; 5 filmstrip (fixed pages)
    mov  edx, FILMSTRIP_RING_PAGES * 4096
    MMO_PUT
    mov  rax, [rel pmod_region_phys]        ; 6 PMOD backing pages
    mov  edx, MMO_PMOD_REGION
    MMO_PUT
    mov  rax, [rel pmod_pt_alloc]           ; 7 PMOD PT pool block
    mov  edx, MMO_PMOD_PT
    MMO_PUT
    mov  rax, [rel pmod_sandbox_alloc]      ; 8 PMOD sandbox CR3 pool block
    mov  edx, MMO_PMOD_SANDBOX
    MMO_PUT
    mov  rax, [rel mmap_owned_buffer]       ; 9 the final-map buffer itself (pool)
    mov  rdx, [rel mmap_capacity]
    MMO_PUT
    mov  rax, [rel wx_test_page]            ; 10 W^X test page (pool)
    mov  edx, MMO_WX_PAGE
    MMO_PUT
    mov  rax, [rel inv_map_buffer]          ; 11 inventory map buffer (pool)
    mov  edx, MMO_INV_MAP
    MMO_PUT
    mov  rax, [rel ucp_pool]                ; 12 microcode pack pool, kept only when admitted
    cmp  qword [rel mcb_pack_buf], 0
    jne  .ucp_kept
    xor  eax, eax                           ; not admitted = FreePool'd, stale pointer -> absent
.ucp_kept:
    mov  edx, MMO_UCP_POOL
    MMO_PUT
%if !PAOS_PUBLIC_BUILD
    mov  rax, [rel pmod_external_buf]       ; 13 PMOD HELLO preload buffer (pool, kept)
    mov  edx, MMO_PMOD_FILE
    MMO_PUT
    xor  eax, eax                           ; 14 retired PMOD netmon preload (SEC 119690): always absent
    mov  edx, MMO_PMOD_FILE
    MMO_PUT
%else
    ; Public builds omit both lab PMOD owners but retain their stable slots.
    xor  eax, eax
    xor  edx, edx
    MMO_PUT
    MMO_PUT
%endif

    mov  rax, [rel percpu_stack_alloc]      ; 15 permanent guarded CPU arena (whole allocation)
    mov  edx, MMO_PERCPU_STACK
    MMO_PUT

    mov  rax, [rel crash_identity_base]     ; 16 retained fatal identity page
    mov  edx, MMO_CRASH_IDENTITY
    MMO_PUT
    mov  rax, [rel hp_mapping_page]         ; 17 retained high-page mapping probe
    mov  edx, MMO_HP_MAPPING
    MMO_PUT

    ; --- per region: loader coverage and no foreign type ---
    xor  ebp, ebp                           ; loader-covered bytes
    xor  r12d, r12d
.region:
    cmp  r12, MMO_REGION_MAX * MMO_SPAN_BYTES
    jae  .pairs
    mov  r13, [rbx + r12]
    mov  r14, [rbx + r12 + 8]
    test r13, r13
    jz   .absent
    test r14, r14
    jz   .absent
    inc  dword [r15 + MMO_OUT_REGIONS]
    mov  dword [r15 + MMO_OUT_REASON], MMO_R_UNCOVERED
    mov  eax, r12d
    shr  eax, 4
    mov  [r15 + MMO_OUT_REGION], eax
    add  r14, r13                           ; exact end
    jc   .out
    add  r14, 4095
    jc   .out
    and  r14, -4096                         ; span end, rounded out
    and  r13, -4096                         ; span start, rounded out
    xor  r10d, r10d                         ; covered bytes of this span
    mov  rsi, [rel mmap_buffer]
    mov  rcx, [rel mmap_size]
.desc:
    mov  rax, [rsi + 8]                     ; descriptor start
    mov  rdx, [rsi + 24]
    shl  rdx, 12
    add  rdx, rax                           ; descriptor end (shape-checked)
    cmp  rdx, r13
    jbe  .desc_next
    cmp  rax, r14
    jae  .desc_next
    mov  edi, [rsi]
    cmp  edi, 1                             ; EfiLoaderCode
    je   .owned
    cmp  edi, 2                             ; EfiLoaderData
    je   .owned
    mov  dword [r15 + MMO_OUT_REASON], MMO_R_FOREIGN
    mov  [r15 + MMO_OUT_TYPE], edi
    jmp  .out
.owned:
    cmp  rax, r13
    jae  .lo_ready
    mov  rax, r13
.lo_ready:
    cmp  rdx, r14
    jbe  .hi_ready
    mov  rdx, r14
.hi_ready:
    sub  rdx, rax
    add  r10, rdx
.desc_next:
    add  rsi, r8
    sub  rcx, r8
    jnz  .desc
    mov  rax, r14
    sub  rax, r13
    cmp  r10, rax
    jne  .out                               ; hole: reason stays uncovered
    add  rbp, r10
    jmp  .region_next
.absent:
    inc  dword [r15 + MMO_OUT_ABSENT]
.region_next:
    add  r12, MMO_SPAN_BYTES
    jmp  .region

    ; --- present regions never overlap each other (exact bytes) ---
.pairs:
    mov  dword [r15 + MMO_OUT_REASON], MMO_R_OVERLAP
    mov  dword [r15 + MMO_OUT_REGION], MMO_NO_INDEX
    xor  r12d, r12d
.pair_i:
    cmp  r12, MMO_REGION_MAX * MMO_SPAN_BYTES
    jae  .pass
    mov  r13, [rbx + r12]
    mov  r14, [rbx + r12 + 8]
    test r13, r13
    jz   .pair_i_next
    test r14, r14
    jz   .pair_i_next
    add  r14, r13                           ; end i (no wrap: checked above)
    lea  r11, [r12 + MMO_SPAN_BYTES]
.pair_j:
    cmp  r11, MMO_REGION_MAX * MMO_SPAN_BYTES
    jae  .pair_i_next
    mov  rsi, [rbx + r11]
    mov  rdi, [rbx + r11 + 8]
    test rsi, rsi
    jz   .pair_j_next
    test rdi, rdi
    jz   .pair_j_next
    add  rdi, rsi                           ; end j
    cmp  r13, rdi
    jae  .pair_j_next                       ; i starts at/after j ends
    cmp  rsi, r14
    jae  .pair_j_next                       ; j starts at/after i ends
    mov  eax, r11d
    shr  eax, 4
    mov  [r15 + MMO_OUT_REGION], eax
    jmp  .out
.pair_j_next:
    add  r11, MMO_SPAN_BYTES
    jmp  .pair_j
.pair_i_next:
    add  r12, MMO_SPAN_BYTES
    jmp  .pair_i
.pass:
    mov  dword [r15 + MMO_OUT_REASON], 0
    mov  [r15 + MMO_OUT_LOADER], rbp
.out:
    mov  eax, [r15 + MMO_OUT_REASON]
    add  rsp, MMO_REGION_MAX * MMO_SPAN_BYTES
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; memmap_owner_selftest — run the census, emit one PASS or FAILED line (the
; verdict suffix strings are core/log catalogue rows). Never halts.
; Returns EAX = census reason. Preserves RBX, RBP, R12-R15.
memmap_owner_selftest:
    push rbx
    sub  rsp, MMO_OUT_BYTES
    mov  rdi, rsp
    call memmap_owner_census
    mov  ebx, eax
    test eax, eax
    jnz  .fail
    lea  rdi, [rel str_mmo_pass_pfx]
    call serial_string
    mov  edi, [rsp + MMO_OUT_REGIONS]
    call serial_hex64
    lea  rdi, [rel str_mmo_absent]
    call serial_string
    mov  edi, [rsp + MMO_OUT_ABSENT]
    call serial_hex64
    lea  rdi, [rel str_mmo_loader]
    call serial_string
    mov  rdi, [rsp + MMO_OUT_LOADER]
    call serial_hex64
    lea  rdi, [rel str_mmo_pass]
    call serial_string
    jmp  .done
.fail:
    lea  rdi, [rel str_mmo_fail_pfx]
    call serial_string
    mov  edi, [rsp + MMO_OUT_REGION]
    call serial_hex64
    lea  rdi, [rel str_mmo_r1]
    cmp  ebx, MMO_R_UNCOVERED
    je   .reason
    lea  rdi, [rel str_mmo_r2]
    cmp  ebx, MMO_R_FOREIGN
    je   .reason
    lea  rdi, [rel str_mmo_r3]
    cmp  ebx, MMO_R_OVERLAP
    je   .reason
    lea  rdi, [rel str_mmo_r4]
.reason:
    call serial_string
    lea  rdi, [rel str_mmo_type]
    call serial_string
    mov  edi, [rsp + MMO_OUT_TYPE]
    call serial_hex64
    lea  rdi, [rel str_mmo_fail]
    call serial_string
.done:
    mov  eax, ebx
    add  rsp, MMO_OUT_BYTES
    pop  rbx
    ret

; --- core/memmap_owner data (read-only strings) ---
str_mmo_pass_pfx: db "[PAOS64] M1 memmap: owner census regions=", 0
str_mmo_absent:   db " absent=", 0
str_mmo_loader:   db " loader_bytes=", 0
str_mmo_pass:     db " PASS [memmap.owner.census.ok]", 13, 10, 0
str_mmo_fail_pfx: db "[PAOS64] M1 memmap: owner census FAILED region=", 0
str_mmo_r1:       db " reason=1 uncovered", 0
str_mmo_r2:       db " reason=2 foreign type", 0
str_mmo_r3:       db " reason=3 self overlap", 0
str_mmo_r4:       db " reason=4 map invalid", 0
str_mmo_type:     db " type=", 0
str_mmo_fail:     db " [memmap.owner.census.fail]", 13, 10, 0
