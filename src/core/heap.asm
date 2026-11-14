;; MODULE core/heap
;; LAYER 1
;; EXPORTS heap_init, kmalloc, kmalloc_model, kfree, heap_selftest
;; IMPORTS boot/serial, boot/paging
;; CAPS
;; OWNER saga:core
; ============================================================================
; core/heap.asm — kernel heap (bump allocator).
;
; The M1 dynamic-memory floor: a bump allocator over the 16 MiB region grabbed
; by boot/paging.asm (heap_base/heap_size). Drivers/structs that need RAM call
; kmalloc; the BSS migration, dma_alloc, and task stacks build on this.
;
; M1 = bump only (kfree is a no-op) — fine since boot-time allocations are never
; freed (same rationale as the old tree's dma_pool). A free-list / size-class
; allocator is a later refinement (MEMORY_MAP §4: "bump-with-free-list"). 16-byte
; aligned; returns 0 on OOM (caller degrades — never silently overruns).
;
; 1303 tournament (durability variant): kmalloc REFUSES rather than corrupts on
; every bad input AND on corrupted allocator state — a size that wraps when
; rounded, a bump that wraps past the top of the address space, an allocator
; that was never initialized, or a heap_next that has been stomped (out of
; range / misaligned) all return 0; the live region is never bumped from a bad
; base. The bump itself is an atomic compare-exchange, so two cores (fan-in 37
; includes core/smp) can never be handed the same block. Every refusal is
; counted by CAUSE (oom / wrap / guard) and kfree counts foreign pointers —
; observable diagnostics, never fatal. kmalloc(0) yields a unique minimal
; block instead of an aliasing pointer. Clobbers stay RAX/RDX/RDI + flags,
; identical to the M1 contract, so no existing caller's register assumptions
; change. heap_selftest KATs the exact arithmetic and PROVES the containment
; by injecting each fault class ([tourn.kmalloc.kat], [tourn.kmalloc.guard]).
; ============================================================================

heap_init:
    ; The model heap is an independent high-memory arena.  Initialize it before
    ; the ordinary heap so either arena can degrade without corrupting the
    ; other's bounds.
    mov  rax, [rel model_heap_base]
    mov  rdx, [rel model_heap_size]
    test rax, rax
    jz   .model_degrade
    test rdx, rdx
    jz   .model_degrade
    add  rdx, rax
    jc   .model_degrade
    add  rax, 15
    jc   .model_degrade
    and  rax, -16
    cmp  rax, rdx
    ja   .model_degrade
    mov  [rel model_heap_next], rax
    mov  [rel model_heap_end], rdx
    jmp  .model_done
.model_degrade:
    xor  eax, eax
    mov  [rel model_heap_next], rax
    mov  [rel model_heap_end], rax
.model_done:
    mov  rax, [rel heap_base]
    mov  rdx, [rel heap_size]
    test rax, rax                       ; no region from paging -> refuse-all
    jz   .degrade
    test rdx, rdx                       ; zero-size region -> refuse-all
    jz   .degrade
    add  rdx, rax                       ; end = base + size
    jc   .degrade                       ; region wraps the address space
    add  rax, 15                        ; UEFI pool base is only 8-aligned;
    jc   .degrade                       ; round up ONCE so kmalloc's 16-align
    and  rax, -16                       ; invariant holds for the whole run
    cmp  rax, rdx                       ; alignment ate the entire region?
    ja   .degrade
    mov  [rel heap_next], rax
    mov  [rel heap_end], rdx
    ret
.degrade:
    xor  eax, eax                       ; next=end=0: every kmalloc refuses
    mov  [rel heap_next], rax           ; cleanly via the guard path instead
    mov  [rel heap_end], rax            ; of bumping from a garbage base
    lea  rdi, [rel str_heap_degrade]
    call serial_string
    ret

; kmalloc(RDI=size) -> RAX = ptr (16-aligned) or 0 on OOM/refusal.
; Clobbers RAX, RDX, RDI, flags (same set as the original M1 allocator).
; Refusal causes are counted separately: heap_stat_oom (region exhausted),
; heap_stat_wrap (size or bump arithmetic would wrap), heap_stat_guard
; (allocator state failed validation — uninit, out of range, misaligned).
; The bump is an atomic compare-exchange retry, so concurrent callers each
; get a distinct block; state is re-validated on every retry.
kmalloc:
    lock inc qword [rel heap_stat_calls]
    add  rdi, 15
    jc   .wrap                          ; size wraps on round-up (e.g. -1)
    and  rdi, -16
    jnz  .have_size
    mov  edi, 16                        ; size 0 -> unique minimal block,
.have_size:                             ; never an aliasing pointer
    mov  rax, [rel heap_next]
.retry:
    test rax, rax                       ; never initialized / init refused
    jz   .guard
    cmp  rax, [rel heap_base]           ; stomped below the region
    jb   .guard
    cmp  rax, [rel heap_end]            ; stomped past the region
    ja   .guard
    test al, 15                         ; 16-align invariant broken
    jnz  .guard
    mov  rdx, rax
    add  rdx, rdi                       ; new next; CF = bump wraps
    jc   .wrap
    cmp  rdx, [rel heap_end]
    ja   .oom
    lock cmpxchg [rel heap_next], rdx   ; publish iff nobody bumped meanwhile
    jne  .retry                         ; lost the race: RAX = fresh next,
    ret                                 ; re-validate + retry. Won: RAX = ptr
.guard:
    lock inc qword [rel heap_stat_guard]
    xor  eax, eax
    ret
.wrap:
    lock inc qword [rel heap_stat_wrap]
    xor  eax, eax
    ret
.oom:
    lock inc qword [rel heap_stat_oom]
    xor  eax, eax
    ret

; kmalloc_model(RDI=size) -> RAX = ptr (16-aligned) or 0.
; Dedicated bump allocator for immutable, very large model blobs.  It mirrors
; kmalloc's wrap/bounds/atomicity rules but deliberately has no free operation:
; MODEL.PXG is loaded once and remains resident for the life of the boot.
kmalloc_model:
    add  rdi, 15
    jc   .refuse
    and  rdi, -16
    test rdi, rdi
    jz   .refuse
    mov  rax, [rel model_heap_next]
.retry:
    test rax, rax
    jz   .refuse
    cmp  rax, [rel model_heap_base]
    jb   .refuse
    cmp  rax, [rel model_heap_end]
    ja   .refuse
    test al, 15
    jnz  .refuse
    mov  rdx, rax
    add  rdx, rdi
    jc   .refuse
    cmp  rdx, [rel model_heap_end]
    ja   .refuse
    lock cmpxchg [rel model_heap_next], rdx
    jne  .retry
    ret
.refuse:
    xor  eax, eax
    ret

; kfree(RDI=ptr) -> (bump allocator: no-op; free-list is a later refinement)
; Hardened: NULL is a legal silent no-op (free(NULL) idiom); a pointer that
; was never handed out (outside [heap_base, heap_next)) is COUNTED as a
; foreign free — observable evidence of a caller bug, never fatal.
kfree:
    test rdi, rdi
    jz   .done
    cmp  rdi, [rel heap_base]
    jb   .foreign
    cmp  rdi, [rel heap_next]
    jae  .foreign
.done:
    ret
.foreign:
    lock inc qword [rel heap_stat_foreign]
    ret

; heap_selftest — exact-arithmetic KAT vectors on the live allocator
; ([tourn.kmalloc.kat]), then fault-INJECTION vectors proving every bad-state
; class is refused-not-corrupted ([tourn.kmalloc.guard]), then the original
; distinct/writable/non-overlap checks. Bump state is saved and restored
; (bump = LIFO), so every KAT allocation is released and nothing leaks.
; A kmalloc whose arithmetic is off by one bit fails a vector; a refusal
; that lands in the wrong cause counter fails the exact delta checks.
heap_selftest:
    push rbx
    push r12
    push r13
    push r14

    mov  r12, [rel heap_next]           ; save live bump state
    mov  r13, [rel heap_end]

    ; V0: init invariants hold — next is 16-aligned and inside the region
    test r12b, 15
    jnz  .kat_fail
    cmp  r12, r13
    ja   .kat_fail

    ; V1 exact bump: kmalloc(1) returns old next exactly; next advances 16
    mov  edi, 1
    call kmalloc
    cmp  rax, r12
    jne  .kat_fail
    lea  rbx, [r12 + 16]
    cmp  [rel heap_next], rbx
    jne  .kat_fail

    ; V2 round-up: kmalloc(17) returns r12+16; next advances to r12+48
    mov  edi, 17
    call kmalloc
    cmp  rax, rbx
    jne  .kat_fail
    lea  rbx, [r12 + 48]
    cmp  [rel heap_next], rbx
    jne  .kat_fail

    ; V3 kfree containment: NULL and an in-heap pointer are silent no-ops;
    ; a pointer the heap never handed out is counted foreign — exactly once
    mov  r14, [rel heap_stat_foreign]
    xor  edi, edi
    call kfree
    mov  rdi, r12
    call kfree
    mov  rax, [rel heap_stat_foreign]
    sub  rax, r14
    jnz  .kat_fail
    mov  edi, 4096                      ; below heap_base, never handed out
    call kfree
    mov  rax, [rel heap_stat_foreign]
    sub  rax, r14
    cmp  rax, 1
    jne  .kat_fail

    ; V4 zero-size: unique minimal block (r12+48), NOT an aliasing pointer;
    ; next advances 16
    xor  edi, edi
    call kmalloc
    cmp  rax, rbx
    jne  .kat_fail
    lea  rbx, [r12 + 64]
    cmp  [rel heap_next], rbx
    jne  .kat_fail

    ; V5 boundary: with exactly 16 bytes left, 17 refuses as OOM leaving
    ; next untouched; then 16 exact-fits to the boundary (ja not jae)
    mov  r14, [rel heap_stat_oom]
    lea  rdx, [rbx + 16]
    mov  [rel heap_end], rdx
    mov  edi, 17
    call kmalloc
    test rax, rax
    jnz  .kat_fail
    cmp  [rel heap_next], rbx           ; refusal must not move next
    jne  .kat_fail
    mov  edi, 16
    call kmalloc
    cmp  rax, rbx
    jne  .kat_fail
    mov  rax, [rel heap_stat_oom]       ; exactly one refusal, cause = oom
    sub  rax, r14
    cmp  rax, 1
    jne  .kat_fail
    mov  [rel heap_end], r13

    ; V6 wrap refusals: a size that wraps on rounding (-1) and a rounded
    ; size that wraps the bump (-16) both refuse, cause = wrap, next parked
    mov  r14, [rel heap_stat_wrap]
    mov  rbx, [rel heap_next]
    mov  rdi, -1
    call kmalloc
    test rax, rax
    jnz  .kat_fail
    mov  rdi, -16
    call kmalloc
    test rax, rax
    jnz  .kat_fail
    cmp  [rel heap_next], rbx
    jne  .kat_fail
    mov  rax, [rel heap_stat_wrap]
    sub  rax, r14
    cmp  rax, 2
    jne  .kat_fail

    ; V7 fault injection: each corrupted-state class must REFUSE, never bump
    ; from a bad base — (a) uninitialized, (b) stomped below the region,
    ; (c) stomped past the region, (d) misaligned. All four land in the
    ; guard counter (not oom/wrap), proving the refusal is CLASSIFIED right.
    mov  r14, [rel heap_stat_guard]
    xor  eax, eax
    mov  [rel heap_next], rax           ; (a) uninit
    mov  edi, 16
    call kmalloc
    test rax, rax
    jnz  .kat_fail
    mov  qword [rel heap_next], 16      ; (b) aligned but below heap_base
    mov  edi, 16
    call kmalloc
    test rax, rax
    jnz  .kat_fail
    lea  rax, [r13 + 64]                ; (c) aligned, strictly past end
    and  rax, -16
    mov  [rel heap_next], rax
    mov  edi, 16
    call kmalloc
    test rax, rax
    jnz  .kat_fail
    lea  rax, [r12 + 8]                 ; (d) in-range but misaligned
    mov  [rel heap_next], rax
    mov  edi, 16
    call kmalloc
    test rax, rax
    jnz  .kat_fail
    mov  rax, [rel heap_stat_guard]     ; all four contained, all four guard
    sub  rax, r14
    cmp  rax, 4
    jne  .kat_fail

    ; V8 align/monotonic SWEEP ([tourn.kmalloc.align]) — durability depth beyond
    ; the point KATs: across a whole SIZE RANGE every block stays 16-aligned and
    ; never overlaps a live block (ptr never below the previous bump top). A
    ; rounding/align regression that the fixed vectors happen to miss dies here.
    mov  [rel heap_next], r12           ; clean, known 16-aligned base
    mov  rbx, r12                       ; rbx = high-water (last bump top)
    lea  r14, [rel km_sweep_sizes]      ; NUL(0)-terminated dword size table
.sweep_loop:
    mov  edi, [r14]
    test edi, edi
    jz   .sweep_done                    ; 0 terminator -> sweep complete
    call kmalloc                        ; clobbers RAX/RDX/RDI; rbx/r14 survive
    test rax, rax
    jz   .kat_fail                      ; a mid-sweep OOM is a coverage failure
    test al, 15                         ; 16-align invariant for THIS size
    jnz  .kat_fail
    cmp  rax, rbx                       ; must not alias an already-live block
    jb   .kat_fail
    mov  rbx, [rel heap_next]           ; advance high-water
    add  r14, 4
    jmp  .sweep_loop
.sweep_done:

    ; V9 exhaustion + recovery ([tourn.kmalloc.stress]) — graceful degradation
    ; under memory pressure: squeeze the region to exactly two blocks; the third
    ; and fourth allocation REFUSE (return 0) without bumping past heap_end, the
    ; oom cause is counted exactly, and restoring the region lets allocation
    ; RESUME. Proves refuse-not-overrun when full, then clean recovery.
    mov  [rel heap_next], r12           ; known base
    mov  rbx, r12                       ; remember base for recovery
    lea  rdx, [r12 + 32]                ; room for exactly two 16B blocks
    mov  [rel heap_end], rdx
    mov  r14, [rel heap_stat_oom]       ; snapshot oom cause
    mov  edi, 16
    call kmalloc                        ; block 1 — fits
    test rax, rax
    jz   .kat_fail
    mov  edi, 16
    call kmalloc                        ; block 2 — exact fit to the limit
    test rax, rax
    jz   .kat_fail
    mov  edi, 16
    call kmalloc                        ; over the limit — must refuse
    test rax, rax
    jnz  .kat_fail
    mov  edi, 16
    call kmalloc                        ; still refuses, still contained
    test rax, rax
    jnz  .kat_fail
    mov  rax, [rel heap_next]           ; next never bumped past heap_end
    cmp  rax, [rel heap_end]
    ja   .kat_fail
    mov  rax, [rel heap_stat_oom]       ; exactly two refusals, cause = oom
    sub  rax, r14
    cmp  rax, 2
    jne  .kat_fail
    mov  [rel heap_end], r13            ; restore the region ...
    mov  [rel heap_next], rbx
    mov  edi, 16
    call kmalloc                        ; ... allocation RESUMES cleanly
    test rax, rax
    jz   .kat_fail

    mov  [rel heap_next], r12           ; restore live state (LIFO: releases
    mov  [rel heap_end], r13            ; every KAT allocation, nothing leaks)

    lea  rdi, [rel str_heap_kat]
    call serial_string
    lea  rdi, [rel str_heap_guard1]     ; containment marker + live counters:
    call serial_string                  ; refusal causes stay countable after
    mov  rdi, [rel heap_stat_guard]     ; boot, so a stomped heap in the field
    call serial_hex64                   ; shows up in these diagnostics
    lea  rdi, [rel str_heap_guard2]
    call serial_string
    mov  rdi, [rel heap_stat_foreign]
    call serial_hex64
    call serial_newline

    lea  rdi, [rel str_heap_align]      ; V8 sweep passed
    call serial_string
    lea  rdi, [rel str_heap_stress]     ; V9 exhaustion+recovery passed
    call serial_string

    ; field observability ([tourn.kmalloc.stat]): the five live cause counters
    ; survive boot, so a heap stomped/exhausted in the FIELD is diagnosable
    ; post-mortem over serial without a debugger — calls/oom/wrap/guard/foreign.
    lea  rdi, [rel str_heap_stat]
    call serial_string
    mov  rdi, [rel heap_stat_calls]
    call serial_hex64
    lea  rdi, [rel str_heap_stat_oom]
    call serial_string
    mov  rdi, [rel heap_stat_oom]
    call serial_hex64
    lea  rdi, [rel str_heap_stat_wrap]
    call serial_string
    mov  rdi, [rel heap_stat_wrap]
    call serial_hex64
    lea  rdi, [rel str_heap_stat_guard]
    call serial_string
    mov  rdi, [rel heap_stat_guard]
    call serial_hex64
    lea  rdi, [rel str_heap_stat_foreign]
    call serial_string
    mov  rdi, [rel heap_stat_foreign]
    call serial_hex64
    call serial_newline
    jmp  .kat_done
.kat_fail:
    mov  [rel heap_next], r12           ; restore; no marker fires and the
    mov  [rel heap_end], r13            ; whole selftest reports FAILED
    jmp  .fail
.kat_done:

    mov  edi, 64
    call kmalloc
    test rax, rax
    jz   .fail
    mov  rbx, rax
    mov  dword [rbx], 0xCAFEBABE        ; writable (dword sentinel — 0xCAFEBABE fits 32b, no sign-ext warn)
    mov  edi, 64
    call kmalloc
    test rax, rax
    jz   .fail
    cmp  rax, rbx                       ; second block must differ
    je   .fail
    cmp  dword [rbx], 0xCAFEBABE        ; first block intact (no overlap)
    jne  .fail
    lea  rdi, [rel str_heap_ok]
    call serial_string
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
.fail:
    lea  rdi, [rel str_heap_fail]
    call serial_string
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

%ifidn RCQ37_VIDEO_BUILT,1
; Additive sibling, H1-H9. Legacy allocation/counters/line pins above unchanged.
; RDI=size, RSI=post-allocation floor -> RAX=ptr/0, RSI=typed cause.
; Clobbers RAX/RDX/RDI/RSI/flags only; zero additional statistics or state.
;; EXPORTS kmalloc_floor
kmalloc_floor:
    push rcx
    add rdi,15
    jc .wrap
    and rdi,-16
    jnz .size
    mov edi,16
.size:
    mov rax,[rel heap_next]
.retry:
    test rax,rax
    jz .guard
    cmp rax,[rel heap_base]
    jb .guard
    cmp rax,[rel heap_end]
    ja .guard
    test al,15
    jnz .guard
    mov rdx,rax
    add rdx,rdi
    jc .wrap
    cmp rdx,[rel heap_end]
    ja .oom
    mov rcx,rdx
    add rcx,rsi
    jc .wrap
    cmp rcx,[rel heap_end]
    ja .floor
    lock cmpxchg [rel heap_next],rdx
    jne .retry
    xor esi,esi
    pop rcx
    ret
.oom:
    mov esi,1
    jmp .refuse
.wrap:
    mov esi,2
    jmp .refuse
.guard:
    mov esi,3
    jmp .refuse
.floor:
    mov esi,4
.refuse:
    xor eax,eax
    pop rcx
    ret
%endif

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_core_heap_0 0
heap_next:         dq 0
heap_end:          dq 0
model_heap_next:   dq 0
model_heap_end:    dq 0
heap_stat_calls:   dq 0                 ; total kmalloc calls
heap_stat_oom:     dq 0                 ; refusals: region exhausted
heap_stat_wrap:    dq 0                 ; refusals: size/bump would wrap
heap_stat_guard:   dq 0                 ; refusals: state failed validation
heap_stat_foreign: dq 0                 ; kfree pointers never handed out
str_heap_ok:      db "[PAOS64] M1 core/heap: kmalloc bump allocator OK", 13, 10, 0
str_heap_kat:     db "[PAOS64] M1 core/heap: kmalloc KAT PASS (align/bump/round/zero/edge/OOM/wrap vectors) [tourn.kmalloc.kat]", 13, 10, 0
str_heap_guard1:  db "[PAOS64] M1 core/heap: fault-injection contained 4/4 + wrap 2/2 + foreign-free 1/1, refuse-not-corrupt [tourn.kmalloc.guard] guard=", 0
str_heap_guard2:  db " foreign=", 0
str_heap_align:   db "[PAOS64] M1 core/heap: kmalloc align/monotonic sweep PASS (16-aligned + no-overlap across size range) [tourn.kmalloc.align]", 13, 10, 0
str_heap_stress:  db "[PAOS64] M1 core/heap: kmalloc exhaustion contained + recovery OK (refuse-not-overrun under pressure, resumes after) [tourn.kmalloc.stress]", 13, 10, 0
str_heap_stat:    db "[PAOS64] M1 core/heap: live cause counters [tourn.kmalloc.stat] calls=", 0
str_heap_stat_oom:     db " oom=", 0
str_heap_stat_wrap:    db " wrap=", 0
str_heap_stat_guard:   db " guard=", 0
str_heap_stat_foreign: db " foreign=", 0
str_heap_degrade: db "[PAOS64] M1 core/heap: DEGRADED refuse-all (bad heap region from paging)", 13, 10, 0
str_heap_fail:    db "[PAOS64] M1 core/heap: FAILED", 13, 10, 0

; V8 sweep size table — small / exact-16 / round-up / mid / page-1, NUL-terminated.
km_sweep_sizes:   dd 1, 15, 16, 17, 33, 64, 255, 4095, 0
%endmacro
WDATA_DEFER WDATA_core_heap_0
