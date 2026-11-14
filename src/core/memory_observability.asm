;; MODULE core/memory_observability
;; LAYER 1
;; EXPORTS memory_observability_kat, mo_summary_build, mo_mode_result, mo_reconciles
;; IMPORTS boot/serial, core/memmap
;; CAPS
;; OWNER saga:foundation_resilience
; ============================================================================
; Task1481 — Foundation MEMORY_V1 / MEMORY_TEST_V1 observability protocol
; (frozen in gauntlet_v2/docs/PAOS_FOUNDATION_RESILIENCE.md §3).
;
; This slice reports HONEST current values and returns status=unsupported for
; every future MEMORY_TEST_V1 mode (owned by tasks 1482-1492); it does NOT
; pretend map scaling, zones, reclaim, guards, scrubbing, or quarantine exist.
; SUMMARY totals reconcile without unsigned wrap. Hostile grammar (unknown
; token / unsupported mode) fails closed and never returns success-shaped zeros.
;
; The acceptance is the qemu-graded content selftest marker
; [memory.observe.schema.ok]; this module owns the protocol LOGIC + the KAT.
; Position-independent ([rel]; no dq <symbol>). Self-contained so the metal
; candidate builds small from a pre-crasher base (Task3250/3456 pattern).
; ============================================================================

MO_SCHEMA           equ 1
MO_PAGE_SIZE_BASE   equ 4096
MO_MAP_TOP_EXCL     equ 0x0000000400000000   ; 16 GiB identity map ceiling (boot/paging)
MO_ZONE_COUNT       equ 1                     ; one honest general zone this slice

; result status codes for mo_mode_result
MO_ST_OK          equ 0
MO_ST_UNSUPPORTED equ 1
MO_ST_ERR         equ 2                       ; hostile grammar / unknown token

; MEMORY_TEST_V1 modes reserved by 1481 — all unsupported until their task ships
MO_MODE_SUMMARY    equ 0                      ; MEMORY_V1 SUMMARY (supported)
MO_MODE_SYNTHMAP   equ 1                      ; 1482
MO_MODE_ZONE_OWN   equ 2                      ; 1483
MO_MODE_META_CRC   equ 3                      ; 1485
MO_MODE_WX         equ 4                      ; 1487
MO_MODE_UNKNOWN    equ 0xFFFFFFFF             ; hostile / unknown token

; mo_summary_build -> fills mo_summary_* with honest current values.
;   usable = memmap-accounted RAM; physical_total = usable (inventory floor this
;   slice); reserved = 0 (not yet separately inventoried — honest, not faked);
;   mapped_top = 16 GiB ceiling; mapped_usable = min(usable, mapped_top).
;   Clobbers RAX, RCX.
mo_summary_build:
    push rbx
    call memmap_total                     ; RAX = usable bytes
    mov  [rel mo_usable], rax
    mov  [rel mo_physical_total], rax     ; inventory floor = accounted RAM
    mov  qword [rel mo_reserved], 0
    mov  rcx, MO_MAP_TOP_EXCL
    mov  [rel mo_mapped_top], rcx
    ; mapped_usable = min(usable, mapped_top)
    cmp  rax, rcx
    jbe  .use_usable
    mov  rax, rcx
.use_usable:
    mov  [rel mo_mapped_usable], rax
    mov  dword [rel mo_zone_count], MO_ZONE_COUNT
    pop  rbx
    ret

; mo_reconciles -> EAX=1 if SUMMARY totals reconcile with no unsigned wrap; else 0.
;   Requires: usable <= physical_total; reserved <= physical_total;
;   usable + reserved does not overflow and stays <= physical_total;
;   mapped_usable <= mapped_top; mapped_usable <= usable.
mo_reconciles:
    mov  rax, [rel mo_usable]
    cmp  rax, [rel mo_physical_total]
    ja   .no
    mov  rcx, [rel mo_reserved]
    cmp  rcx, [rel mo_physical_total]
    ja   .no
    add  rax, rcx                          ; usable + reserved
    jc   .no                               ; unsigned wrap
    cmp  rax, [rel mo_physical_total]
    ja   .no
    mov  rax, [rel mo_mapped_usable]
    cmp  rax, [rel mo_mapped_top]
    ja   .no
    cmp  rax, [rel mo_usable]
    ja   .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; mo_mode_result(EDI=mode) -> EAX = MO_ST_{OK,UNSUPPORTED,ERR}
;   SUMMARY is supported; every reserved MEMORY_TEST_V1 mode is unsupported;
;   an unknown token is a hostile ERR (fails closed). Unsupported never returns
;   OK-shaped zeros — the caller distinguishes on EAX, not on a zeroed payload.
mo_mode_result:
    cmp  edi, MO_MODE_SUMMARY
    je   .ok
    cmp  edi, MO_MODE_UNKNOWN
    je   .err
    cmp  edi, MO_MODE_WX                    ; SYNTHMAP..WX are the reserved future modes
    jbe  .unsupported
    ; any other numeric token is not a known mode -> hostile
.err:
    mov  eax, MO_ST_ERR
    ret
.unsupported:
    mov  eax, MO_ST_UNSUPPORTED
    ret
.ok:
    mov  eax, MO_ST_OK
    ret

; ----------------------------------------------------------------------------
; memory_observability_kat — boot content selftest. Proves:
;   (1) SUMMARY builds honest values that RECONCILE without wrap;
;   (2) schema/page-size/zone invariants hold;
;   (3) a reserved future mode (SYNTHMAP) returns status=unsupported, NOT ok;
;   (4) an unknown token FAILS CLOSED (ERR), not unsupported and not ok.
; Emits [memory.observe.schema.ok] only on a full pass.
; ----------------------------------------------------------------------------
memory_observability_kat:
    call mo_summary_build
    call mo_reconciles
    test eax, eax
    jz   .fail
    ; schema invariants
    cmp  dword [rel mo_zone_count], MO_ZONE_COUNT
    jne  .fail
    ; physical_total must be non-zero (real inventory, not a faked zero)
    cmp  qword [rel mo_physical_total], 0
    je   .fail
    ; (1) SUMMARY supported
    mov  edi, MO_MODE_SUMMARY
    call mo_mode_result
    cmp  eax, MO_ST_OK
    jne  .fail
    ; (3) reserved future mode unsupported (never ok)
    mov  edi, MO_MODE_SYNTHMAP
    call mo_mode_result
    cmp  eax, MO_ST_UNSUPPORTED
    jne  .fail
    mov  edi, MO_MODE_WX
    call mo_mode_result
    cmp  eax, MO_ST_UNSUPPORTED
    jne  .fail
    ; (4) unknown token fails closed (ERR)
    mov  edi, MO_MODE_UNKNOWN
    call mo_mode_result
    cmp  eax, MO_ST_ERR
    jne  .fail
    lea  rdi, [rel str_mo_kat_ok]
    call serial_string
    ret
.fail:
    lea  rdi, [rel str_mo_kat_fail]
    call serial_string
    ret

; --- memory_observability data (in-image; RW+NX) ---
mo_physical_total: dq 0
mo_usable:         dq 0
mo_reserved:       dq 0
mo_mapped_top:     dq 0
mo_mapped_usable:  dq 0
mo_zone_count:     dd 0
str_mo_kat_ok:   db "[PAOS64] Foundation memory_observability: content selftest PASS [memory.observe.schema.ok]", 13, 10, 0
str_mo_kat_fail: db "[PAOS64] Foundation memory_observability: content selftest FAIL [memory.observe.schema.fail]", 13, 10, 0
