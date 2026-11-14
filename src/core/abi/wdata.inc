; ============================================================================
; core/abi/wdata.inc — WRITABLE-DATA SEGREGATION (the TCG self-modifying-code
; hazard fix, w044 TCG_REPORT.md). A header: emits no bytes where it is included.
;
; WHY: PaOS is one flat PE section; every module historically ends with its own
; writable state (counters, locks, scratch buffers) right after its code. Under
; QEMU TCG (the AMD `hp`/`hp-e1000e`/`amd-tcg` matrix profiles) any store into a
; 4 KiB page that also holds translated code takes QEMU's self-modifying-code
; slow path (notdirty_write -> tb_invalidate_phys_range_fast) on EVERY store.
; Measured on 81b2aeb2c: 266,671,972 such stores in one `hp` run, 81% of them to
; core/lib/ed25519 `ed_mul_t` (the field-multiply scratch sharing a page with
; the multiply loop). Whether a hot variable shares a page with hot code was
; decided by incidental layout, so a 160-byte shift anywhere upstream swung TCG
; wall time ~2x. KVM and metal are unaffected (no such write tracking).
;
; HOW: a module wraps its writable block in a macro and DEFERS it:
;
;     %macro WDATA_mymodule 0
;     my_counter: dq 0
;     my_scratch: times 256 db 0
;     %endmacro
;     WDATA_DEFER WDATA_mymodule
;
; The source stays next to the code that owns it; the BYTES are emitted once, at
; the image tail, by WDATA_EMIT_REGION inside a region that starts and ends on
; an in-memory 4 KiB page boundary and contains no instructions. Labels are
; ordinary global labels (rip-relative [rel x] works unchanged, intra-block
; label differences are unchanged). Every block starts 64-byte aligned.
;
; RULES for a deferred block: data only (never code, never the hotpatch arena or
; anything executed); no macro/%define-alias tokens whose meaning depends on the
; include site; nothing whose POSITION relative to code matters (e.g. the SMP
; real-mode trampoline). tools/wdata_check.py (run by `make build`) verifies the
; region is page-isolated and that every symbol in WDATA_HOT_SYMBOLS lives in it.
;
; In-memory page math: code_start is file offset 0x200 at RVA 0x1000 (see
; boot/header.asm), so an RVA page boundary is a file offset == 0x200 mod 0x1000.
; The loader page-aligns the image base (SectionAlignment 0x1000), so this holds
; for the direct 1 MiB load and for a Manager-relocated StartImage alike.
;
; Builds that include a converted module WITHOUT paos.asm (none today) get the
; historical behaviour: WDATA_DEFER expands the block in place.
;
; ZERO-FILL TAIL (WDATA_BSS_DEFER): a block that holds only zero-initialised
; storage may be declared with resb/resw/resd/resq/alignb only and deferred with
; WDATA_BSS_DEFER instead. Its labels are placed after the last file byte (paos.asm
; code_end, normally wdata_region_pad_end) in NASM `absolute` space: no file bytes,
; but inside VirtualSize/SizeOfImage, which the PE loader (firmware LoadImage, shim)
; zero-fills beyond SizeOfRawData. Same RW memory, same page isolation from code
; (the tail starts on the next in-memory page boundary), same initial value (zero).
; It only shrinks paos.efi.
; Any db/dw/dd/dq in such a block is an assembly error ("attempt to assemble code
; in [ABSOLUTE] space"), so a non-zero initialiser cannot be dropped silently.
; Standalone assemblies expand the block in place, where res* emits zeros.
; ============================================================================
%ifndef PAOS_WDATA_INC
%define PAOS_WDATA_INC 1

%assign WDATA_N 0
%assign WDATA_BSS_N 0

%macro WDATA_DEFER 1
%ifdef PAOS_WDATA_REGION
    %xdefine WDATA_ITEM_%[WDATA_N] %1
    %assign WDATA_N WDATA_N + 1
%else
    %1
%endif
%endmacro

%macro WDATA_BSS_DEFER 1
%ifdef PAOS_WDATA_REGION
    %xdefine WDATA_BSS_ITEM_%[WDATA_BSS_N] %1
    %assign WDATA_BSS_N WDATA_BSS_N + 1
%else
    [warning push]
    [warning -zeroing]
    %1
    [warning pop]
%endif
%endmacro

; Pad with zero bytes to the next in-memory 4 KiB page boundary (RVA-relative).
%macro WDATA_PAGE_PAD 0
    times ((0x1000 - (($ - code_start) & 0xFFF)) & 0xFFF) db 0
%endmacro

; Emitted exactly once, by src/paos.asm, after the last code module.
%macro WDATA_EMIT_REGION 0
    WDATA_PAGE_PAD
wdata_region:
%assign %%i 0
%rep WDATA_N
    align 64, db 0
    WDATA_ITEM_%[%%i]
%assign %%i %%i + 1
%endrep
wdata_region_end:
    WDATA_PAGE_PAD
wdata_region_pad_end:
%endmacro

; Emitted exactly once, by src/paos.asm, with the label that ends the file-backed
; image (%1). Reserves every WDATA_BSS_DEFER block in `absolute` space after it
; (no file bytes), starting on an in-memory 4 KiB page boundary, and defines
; wdata_bss_end, the end of the zero-filled tail. In the normal image %1 is the
; page-aligned wdata_region_pad_end, so with no such block wdata_bss_end == %1.
%macro WDATA_EMIT_BSS 1
absolute %1
    resb ((0x1000 - (($ - code_start) & 0xFFF)) & 0xFFF)
wdata_bss:
%assign %%i 0
%rep WDATA_BSS_N
    alignb 64
    WDATA_BSS_ITEM_%[%%i]
%assign %%i %%i + 1
%endrep
; Cover the complete final data page: a PE loader clears only through VirtualSize.
    resb ((0x1000 - (($ - code_start) & 0xFFF)) & 0xFFF)
wdata_bss_end:
section .text
%endmacro

%endif
