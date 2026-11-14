%include "core/abi/crash_identity.inc"
; ============================================================================
; core/abi/diag.inc — DEBUG-INFO foundation constants + the phase-breadcrumb
; macro. A header (.inc emits no bytes), included FIRST in the link map so both
; boot/paging.asm (which RESERVES the ring) and core/diag.asm (which OWNS it)
; share one definition of the ring geometry — G1 single-definition applied to a
; memory-layout constant (MEMORY_MAP §1 "Diag ring: fixed 64 KiB, survives warm
; reboot"). No struc/db here — pure equ + one %macro, like driver_classes.inc.
; ============================================================================

; ---- the persistent diag ring: a FIXED physical region (MEMORY_MAP §1) --------
; A known address, reserved from firmware once (AllocatePages/AllocateAddress) so
; it (a) never overlaps the heap/DMA pool and (b) is the SAME address every boot —
; the substrate a warm-reboot survivor's records are read back from. 0x0200_0000
; (32 MiB) sits clear of the keep+headroom (<8 MiB), the DMA design pool (8-14 MiB)
; and the module region (14-32 MiB) — MEMORY_MAP §1's physical layout.
DIAG_RING_BASE   equ 0x02000000            ; fixed base (MEMORY_MAP constant)
DIAG_RING_SIZE   equ 0x10000               ; 64 KiB
DIAG_RING_PAGES  equ (DIAG_RING_SIZE / 4096)   ; 16 pages of 4 KiB
DIAG_MAGIC       equ 0x50414F5344494147    ; "PAOSDIAG" sentinel (init writes it)
DIAG_MAGIC_INV   equ 0xAFBEB0ACBBB6BEB8    ; bitwise inverse: detects one-sided magic damage
DIAG_VERSION     equ 3                     ; v3 survives firmware reuse of the first cache line

; ---- boot filmstrip: fixed, same-boot framebuffer evidence (Task2302) ------
; 0x0210_0000 begins one MiB beyond the 64 KiB persistent diag reservation at
; 0x0200_0000. The gap keeps the two independently allocated Address ranges
; unmistakable in firmware maps. Filmstrip data is deliberately NOT persistent
; and never touches the ESP: every boot rewrites its 256-byte header and four
; 320x180 BGRX slots in this EfiLoaderData reservation.
FILMSTRIP_RING_BASE   equ 0x02100000
FILMSTRIP_HEADER_SIZE equ 256
FILMSTRIP_SLOTS       equ 4
FILMSTRIP_W           equ 320
FILMSTRIP_H           equ 180
FILMSTRIP_FRAME_BYTES equ (FILMSTRIP_W * FILMSTRIP_H * 4) ; 230,400
FILMSTRIP_CROP_W      equ 128
FILMSTRIP_CROP_H      equ 64
FILMSTRIP_CROP_BYTES  equ (FILMSTRIP_CROP_W * FILMSTRIP_CROP_H * 4) ; 32,768
FILMSTRIP_RING_SIZE   equ (FILMSTRIP_HEADER_SIZE + FILMSTRIP_SLOTS * FILMSTRIP_FRAME_BYTES + FILMSTRIP_CROP_BYTES) ; 954,624
FILMSTRIP_RING_PAGES  equ ((FILMSTRIP_RING_SIZE + 4095) / 4096) ; 234 pages
; diag_prev_valid is also the bounded malformed-reason code.  NONE/VALID are
; states; every value in [BAD_MIN,BAD_MAX] names the first rejected invariant.
DIAG_PREV_NONE             equ 0
DIAG_PREV_VALID            equ 1
DIAG_PREV_BAD_MAGIC        equ 2
DIAG_PREV_BAD_INVERSE      equ 3
DIAG_PREV_BAD_VERSION      equ 4
DIAG_PREV_BAD_HEADER_BYTES equ 5
DIAG_PREV_BAD_RECORD_BYTES equ 6
DIAG_PREV_BAD_RECORD_COUNT equ 7
DIAG_PREV_BAD_RING_BYTES   equ 8
DIAG_PREV_BAD_BOOT         equ 9
DIAG_PREV_BAD_HEAD_RANGE   equ 10
DIAG_PREV_BAD_HEAD_ALIGN   equ 11
DIAG_PREV_BAD_FAULT_COUNT  equ 12
DIAG_PREV_BAD_HEAD_SEQ     equ 13
DIAG_PREV_BAD_RECORD_SEQ   equ 14
DIAG_PREV_BAD_RECORD_KIND  equ 15
DIAG_PREV_BAD_PHASE_ARG    equ 16
DIAG_PREV_BAD_MIN          equ DIAG_PREV_BAD_MAGIC
DIAG_PREV_BAD_MAX          equ DIAG_PREV_BAD_PHASE_ARG

; ---- ring header (first DIAG_HDR_SIZE bytes of the region) ----
; UEFI's page allocator may reuse the first free-page cache line for list
; metadata before AllocateAddress gives this fixed range back to PaOS.  Metal
; evidence preserved the v2 inverse at +88 while destroying magic/summary at
; +0..+63.  V3 therefore treats that line as sacrificial and keeps every trusted
; header field above it.  The whole region remains the existing fixed 64 KiB.
DIAG_FW_SCRATCH_BYTES equ 64
DIAG_HDR_SIZE    equ 192
DIAG_H_MAGIC     equ 64                     ; dq — present => a prior boot's ring
DIAG_H_BOOT      equ 72                     ; dq — boot counter (persistence proof)
DIAG_H_HEAD      equ 80                     ; dq — byte offset of next record (wraps)
DIAG_H_SEQ       equ 88                     ; dq — monotonic record sequence
DIAG_H_FAULTS    equ 96                     ; dq — total fault records ever written
DIAG_H_LVEC      equ 104                    ; dq — last fault: vector
DIAG_H_LRIP      equ 112                    ; dq — last fault: RIP
DIAG_H_LCR2      equ 120                    ; dq — last fault: CR2
DIAG_H_VERSION   equ 128                    ; dd — DIAG_VERSION
DIAG_H_HDR_BYTES equ 132                    ; dd — DIAG_HDR_SIZE
DIAG_H_REC_BYTES equ 136                    ; dd — DIAG_REC_SIZE
DIAG_H_REC_COUNT equ 140                    ; dd — DIAG_NREC
DIAG_H_RING_BYTES equ 144                   ; dd — DIAG_RING_SIZE
DIAG_H_MAGIC_INV equ 152                    ; dq — DIAG_MAGIC_INV

; ---- fixed-stride records (ring buffer after the header) ----
DIAG_REC_SIZE    equ 64
DIAG_NREC        equ (DIAG_RING_SIZE - DIAG_HDR_SIZE) / DIAG_REC_SIZE  ; 1021 in v3
DIAG_REC_AREA    equ DIAG_NREC * DIAG_REC_SIZE   ; usable record bytes (wrap modulus)
DIAG_R_KIND      equ 0                      ; dd — DIAG_K_* taxonomy below
DIAG_R_ARG       equ 4                      ; dd — phase id, or fault vector
DIAG_R_SEQ       equ 8                      ; dq — sequence at write time
DIAG_R_A         equ 16                     ; dq — fault RIP (else 0)
DIAG_R_B         equ 24                     ; dq — fault CR2 (else 0)
DIAG_R_C         equ 32                     ; dq — fault error code (else 0)
DIAG_R_TAG       equ 40                     ; 24-byte NUL-padded name

DIAG_K_ENTER     equ 1
DIAG_K_EXIT      equ 2
DIAG_K_FAULT     equ 3
; Existing boot-time producers use the same retained ring.  Keep this taxonomy
; aligned with THERM_DIAG_KIND (svc/thermal) and DIAG_KIND_* (svc/resilience),
; otherwise a healthy prior boot is rejected as BAD_RECORD_KIND on readback.
DIAG_K_THERMAL   equ 4
DIAG_K_AER       equ 5
DIAG_K_IOMMU     equ 6
; Fatal MCA snapshot. ARG=0xffffffff: global/unqualified, else Intel bank index.
; global A=MCG_CAP B=MCG_STATUS C=bounded scan count; bank A=MCi_STATUS
; B=MCG_STATUS C=MCG_CAP. mca-amd-global uses C=0: no AMD bank scan.
; Tags distinguish unqualified/Intel global/AMD global/Intel bank records.
; Corrected polling tag mca-corrected: ARG=Intel bank, A=raw MCi_STATUS,
; B=dense logical CPU index, C=saturating boot-local software observation count
; for that CPU. Counts changed VAL=1/UC=0 samples, not hardware error totals;
; unchanged raw status deduplicates. Shared banks may count on multiple CPUs.
; smca-corrected uses the same ARG/A/B/C fields for qualified AMD SMCA STATUS
; (C0002001h+bank*10h). Also requires Deferred/PCC/TCC/Poison clear. QUAL=4
; in the existing CPU-local polling row identifies this layout; QUAL=3 means
; absent required capability, not a healthy zero. Raw CAP exposes bank clipping.
; Sampling can miss transitions, ring contention can drop records; no new
; durability or containment guarantee. Fatal snapshot tag semantics above stay.
DIAG_K_MCA       equ 7
; Opt-in lab first-contact recovery only. ARG=1 no timely owner contact,
; 2 storage quiesce refused, 3 warm reset attempted (not completed).
; A=absolute monotonic deadline us, B=last timer sample us, C=Manager state
; generation (0 unavailable); fixed tag lab-return:no-contact. Header boot and
; record sequence bind the retained observation; no key, nonce or raw address.
; No channel-failure inference, health authority or cold/power-loss guarantee.
DIAG_K_LAB_RETURN equ 8
DIAG_K_MAX       equ DIAG_K_LAB_RETURN     ; reject every genuinely unregistered kind
; core/log's boot-wait flush writes each wait row as DIAG_K_EXIT whose arg is
; the owning P-stage, or this explicit "unattributed" sentinel for the raw
; remainder (BOOT_WAIT_PHASE_UNKNOWN). The retained-ring validator accepts it on
; EXIT rows only; every other EXIT/ENTER arg must still be a phase id.
DIAG_ARG_UNATTRIBUTED equ 255

; ---- phase ids (index into core/diag's diag_phase_names, same order) ----
DIAG_PH_STRIDE   equ 16                     ; bytes per phase-name slot
PH_IDT_ST        equ 0
PH_WX_ST         equ 1
PH_LIB           equ 2
PH_LOGFMT        equ 3
PH_KAT           equ 4
PH_HEAP_INIT     equ 5
PH_HEAP_ST       equ 6
PH_MEMMAP        equ 7
PH_TIME          equ 8
PH_TIMER_INIT    equ 9
PH_TIMER_ST      equ 10
PH_SCHED         equ 11
PH_PREEMPT       equ 12
PH_DMA           equ 13
PH_DIAG          equ 14
PH_HOTPATCH      equ 15
DIAG_NPHASES     equ 16

; PHASE id, fn — breadcrumb a boot phase into the ring, run it, breadcrumb exit.
; Expands INLINE in the orchestrator (boot/header) so "every phase logs entry/exit"
; costs one macro, not hand-written enter/exit pairs at each call site.
%macro PHASE 2
    mov  edi, %1
    call diag_phase_enter
    call %2
    mov  edi, %1
    call diag_phase_exit
%endmacro
