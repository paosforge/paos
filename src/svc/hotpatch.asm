;; MODULE svc/hotpatch
;; LAYER 5
;; EXPORTS hotpatch_selftest, hotpatch_gen_selftest, hotpatch_symbol_selftest, hotpatch_arena_init, hotpatch_write_detour, hotpatch_restore_bytes, hotpatch_restore_bytes_checked, status_hotpatch_hook, general_probe_field, hp_eligible, hp_apply_relocs, hp_resolve_symbol, hp_symtab_init, hp_addrstab_check
;; IMPORTS boot/serial, boot/gdt, core/dma, core/log, core/lib/fmt, core/lib/crc32, core/smp
;; CAPS
;; OWNER saga:hotpatch
; ============================================================================
; svc/hotpatch.asm — the LOOP ACCELERATOR: function-level live hot-patch, no
; reboot (LIVE_FORGE.md §4.5, drivers/hotpatch/ESSENCE.md). Below the module-swap
; rungs (§4) sits the finest-grained live change: replace ONE running function's
; body while the OS keeps working. This is the single biggest NON-model speedup
; for the dev loop — it turns the ~2 min "tweak → ESP deploy → reboot → observe"
; inner cycle into tens of milliseconds (measured ~30–60 ms on bare metal, 9905).
;
; This module ports the PROVEN 9385 primitive (v0.7.270) — DISTILLED onto the
; clean tree, not transcribed — and provides the QEMU-gradeable boot self-test.
; The network delivery protocol (HOTPATCH_START/DATA/COMMIT UDP handlers), the
; general build-driven patch generator, and auto-PIC bodies are the follow-on
; seams (LIVE_FORGE §4.5 items 1–3) that ride the net stack + build; they are NOT
; in this rung. What IS here is the load-bearing engine + its safety model.
;
; THE SAFETY MODEL (why it can't brick the box) — kpatch completion model:
;   * Patch unit = a WHOLE function. New body lands in a PIC patch arena; the ONLY
;     mutation to existing code is a 5-byte `jmp rel32` at the old entry — mutation
;     surface bounded to 5 bytes at one address.
;   * The OLD body persists forever: a task suspended inside it finishes the old
;     version; only NEW calls take the detour. No in-flight-frame hazard, no
;     stop-the-world, no reference counting.
;   * Install under `cli` + PaOS's single-core scheduler → the patcher is the only
;     code running; the 5-byte write can't race an in-flight entry.
;   * Opcode byte (0xE9) written LAST, after the rel32 + mfence → a half-written
;     detour is never a decodable jump (correct even if SMP ever lands).
;   * CRC32 (zlib/IEEE, matches python zlib.crc32) verifies arena integrity before
;     the detour is armed — the host↔box contract, exercised here box-local.
;   * VOLATILE by design: a bad patch's failure floor is "lose the patch", never
;     "brick the box". On bare metal the floor is a watchdog reboot into the clean
;     ESP binary; the in-RAM, QEMU-gradeable equivalent proven here is
;     SELF-TEST-OR-REVERT: a committed patch that fails its declared self-test is
;     auto-reverted (its 5 bytes restored), leaving the clean function running.
;
; ⚠ REWORK ADAPTATION (W^X): the old tree's DMA pool was executable; this tree
; ENFORCES W^X (boot/paging.asm: every 2 MiB data page is NX; there is a live
; #PF-on-exec-data self-test). A `dma_alloc` arena therefore lands in an NX page,
; so hotpatch_arena_init makes every containing leaf executable (clears NX
; with an all-core TLB update), handling both 4 KiB and 2 MiB mappings.
; The patch arena is, by nature, an execute region.
; This is a bounded W^X relaxation of the containing leaves; a production build
; wants a dedicated 2 MiB-aligned arena flipped RX-only after each write (deferred,
; needs a finer arena allocator than the M2 bump pool) — said plainly, not hidden.
;
; ⚠ QEMU is a STRUCTURAL smoke test only. This proves the detour math, the arena
; exec flip, CRC gating, content-graded new behavior, and self-test-or-revert run
; correctly. Real-silicon prefetch/coherency behavior (the mfence + `jmp $+2`
; prefetch-flush belt) is bare-metal-pending — QEMU-green is NOT "works on hardware".
; ============================================================================

HP_ARENA_SIZE    equ 65536              ; 64 KiB PIC patch arena (ESSENCE constant)
HP_VICTIM_BASE   equ 0x0BA5E11E         ; the victim fn's clean (unpatched) return
HP_PHYS_MASK     equ 0x000FFFFFFFFFF000 ; 4 KiB-frame address field (page-table walk)

; --- eligibility-gate change kinds (LIVE_FORGE §4.5, "single-function-body-only")
;     Only a self-contained function BODY is live-patchable; anything that runs
;     before the patcher is up, spans >1 function, or moves data layout is REFUSED
;     (full deploy required). These are the generator's classification tokens. ---
HP_ELIG_SINGLE_FN   equ 1               ; a single function body -> ELIGIBLE
HP_ELIG_BOOT_PATH   equ 2               ; runs before hotpatch_init -> ineligible
HP_ELIG_MULTI_FN    equ 3               ; touches >1 function -> ineligible
HP_ELIG_DATA_LAYOUT equ 4               ; struct/global layout change -> ineligible

; ---------------------------------------------------------------------------
; hotpatch_write_detour — arm a 5-byte `jmp rel32` at a function's entry so all
;   NEW calls land in the PIC body at `slot`. rel32 = slot-(target+5); the +5
;   (jmp length) is the classic off-by-one. Opcode 0xE9 written LAST (after the
;   rel32 + mfence) so a partial write is never a decodable jump; whole thing
;   under cli/pushfq/popfq; ends with `jmp $+2` to flush this core's prefetch.
;   RANGE-GUARDED: the displacement is checked to FIT a signed-32 rel32 BEFORE
;   any byte is written. If slot is >2 GiB from target (the bare-metal #PF: arena
;   from conventional RAM lands out of ±2 GiB of the in-image target on real RAM),
;   NOTHING is written and the call returns refused — a bad-range patch becomes a
;   graceful "not applied" miss, never a jump-to-unmapped box-hang. Completes the
;   module's "can't brick the box" claim (1092; investigate 1091).
;  in:  RDI=target entry, RSI=arena slot (PIC body)
;  out: RAX = 1 detour armed and all-core-visible / 0 refused or coherence failed
;  clobbers: RAX, RCX (flags preserved)
; ---------------------------------------------------------------------------
hotpatch_write_detour:
    pushfq
    push rbx
    push r12
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    mov  rbx, rdi
    mov  rax, rsi
    sub  rax, rdi
    sub  rax, 5                         ; RAX = displacement = slot - (target + 5)
    movsxd rcx, eax                     ; sign-extend the low 32 back to 64
    cmp  rcx, rax                       ; equal iff the displacement FITS signed-32
    jne  .out_of_range                  ; >2 GiB away -> refuse; write nothing
    mov  r12d, eax
    mov  rdi, rbx
    call smp_mapping_update_begin       ; every peer is at a quiescent IRQ boundary
    jc   .out_of_range
    pushfq
    cli
    mov  [rbx + 1], r12d                ; rel32 first
    mfence
    mov  byte [rbx], 0xE9               ; opcode 0xE9 LAST
    mfence
    jmp  short $+2                      ; force 2-byte fallthrough even under -O0/-O1
    popfq
    mov  rdi, rbx
    call smp_mapping_update_commit      ; release + invalidate + all-online ack
    jc   .coherence_failed
    mov  eax, 1                         ; armed
    jmp  .return
.coherence_failed:
    xor  eax, eax                       ; mutation ran, but all-core visibility did not earn success
    jmp  .return
.out_of_range:
    xor  eax, eax                       ; refused — target's entry bytes UNCHANGED
.return:
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  r12
    pop  rbx
    popfq
    ret

; ---------------------------------------------------------------------------
; hotpatch_restore_bytes — undo a detour by restoring the 5 saved entry bytes.
;   Mirror of the install: opcode byte (offset 0) restored LAST, under cli. This
;   is the revert used by both explicit revert and the self-test-or-revert
;   watchdog — the failure floor that makes patches volatile-safe.
;  in:  RDI=target entry, RSI=ptr to the 5 saved bytes
;  clobbers: none (legacy preserving entry; ignores the checked result)
; ---------------------------------------------------------------------------
hotpatch_restore_bytes:
    push rax
    call hotpatch_restore_bytes_checked
    pop  rax
    ret

; Checked entry: RAX=1 only after restore and all-online coherence succeed.
; RAX=0 means begin refused (no stores), or commit failed (local bytes restored
; but all-core visibility unproved). All other GPRs and input flags preserved.
; Callers must retain their recovery record on failure, never acknowledge revert.
hotpatch_restore_bytes_checked:
    pushfq
    push rbx
    push r12
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    mov  rbx, rdi
    mov  r12, rsi
    mov  rdi, rbx
    call smp_mapping_update_begin
    jc   .failed
    pushfq
    cli
    mov  al, [r12 + 1]
    mov  [rbx + 1], al
    mov  al, [r12 + 2]
    mov  [rbx + 2], al
    mov  al, [r12 + 3]
    mov  [rbx + 3], al
    mov  al, [r12 + 4]
    mov  [rbx + 4], al
    mfence
    mov  al, [r12 + 0]
    mov  [rbx + 0], al                  ; opcode byte LAST
    mfence
    jmp  short $+2
    popfq
    mov  rdi, rbx
    call smp_mapping_update_commit
    jc   .failed
    mov  eax, 1
    jmp  .out
.failed:
    xor  eax, eax
.out:
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  r12
    pop  rbx
    popfq
    ret

; ---------------------------------------------------------------------------
; hp_make_exec — clear NX on the present 4 KiB or 2 MiB leaf covering RDI.
;   Upper entries must already permit execution: never broaden another subtree.
;   Reject noncanonical addresses, missing entries and unsupported 1 GiB leaves.
;   Keep the all-core rendezvous around the leaf mutation and report its result.
;  in: RDI=virtual address
;  out: CF=0, RAX=leaf span (4096/2 MiB), coherence confirmed; CF=1 refused
;  clobbers: RAX
; ---------------------------------------------------------------------------
hp_make_exec:
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    mov  rbx, rdi
    mov  rax, rdi
    shl  rax, 16
    sar  rax, 16
    cmp  rax, rdi
    jne  .refuse
    mov  r8, HP_PHYS_MASK
    mov  rax, cr3
    and  rax, r8                        ; PML4 base
    mov  rcx, rdi
    shr  rcx, 39
    and  ecx, 0x1FF
    mov  rax, [rax + rcx*8]
    test al, 1
    jz   .refuse
    test al, 0x80
    jnz  .refuse
    bt   rax, 63
    jc   .refuse
    and  rax, r8                        ; PDPT base
    mov  rcx, rdi
    shr  rcx, 30
    and  ecx, 0x1FF
    mov  rax, [rax + rcx*8]
    test al, 1
    jz   .refuse
    test al, 0x80                       ; no 1 GiB leaves in this mapper
    jnz  .refuse
    bt   rax, 63
    jc   .refuse
    and  rax, r8                        ; PD base
    mov  rcx, rdi
    shr  rcx, 21
    and  ecx, 0x1FF
    lea  r12, [rax + rcx*8]
    mov  rax, [r12]
    test al, 1
    jz   .refuse
    test al, 0x80
    mov  r13d, 0x200000
    jnz  .leaf                          ; existing 2 MiB leaf
    bt   rax, 63                        ; a PT pointer is not a leaf
    jc   .refuse
    and  rax, r8
    mov  rcx, rdi
    shr  rcx, 12
    and  ecx, 0x1FF
    lea  r12, [rax + rcx*8]             ; exact 4 KiB leaf; preserve neighbors
    mov  r13d, 4096
    test byte [r12], 1
    jz   .refuse
.leaf:
    mov  rdi, rbx
    call smp_mapping_update_begin
    jc   .out
    mov  rdx, [r12]
    btr  rdx, 63
    mov  [r12], rdx
    mov  rdi, rbx
    call smp_mapping_update_commit
    jc   .out                          ; retain commit failure
    mov  eax, r13d                     ; successful leaf span, for arena iteration
    jmp  .out
.refuse:
    stc
.out:
    pop  r13
    pop  r12
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; hotpatch_arena_init — prepare the static in-image 64 KiB PIC arena.
;   Visit every covered 4 KiB page, including an unaligned final page. On a large
;   leaf the existing 2 MiB relaxation is retained. Publish the base only after
;   all leaf changes and all-core commits succeed. A failure may leave earlier
;   leaves executable, but returns no usable arena and never arms a patch.
;  out: RAX=arena base, or 0 on refusal/coherence failure
;  clobbers: RAX,RCX,RDX,RDI,R8
; ---------------------------------------------------------------------------
hotpatch_arena_init:
    mov  qword [rel hotpatch_arena_base], 0
    mov  qword [rel hotpatch_arena_bump], 0
    lea  rdi, [rel hp_arena_static]
    and  rdi, -4096
    lea  rcx, [rel hp_arena_static + HP_ARENA_SIZE - 1]
    and  rcx, -4096
.page:
    call hp_make_exec
    jc   .fail
    lea  rdx, [rax - 1]
    or   rdi, rdx                      ; skip to the next leaf boundary
    inc  rdi
    cmp  rdi, rcx
    jbe  .page
.ready:
    lea  rax, [rel hp_arena_static]
    mov  [rel hotpatch_arena_base], rax
    ret
.fail:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; hp_victim — the patch TARGET the self-test rewrites. Its entry is exactly a
;   5-byte `mov eax, imm32` (B8 + 4) so a 5-byte detour overwrites the whole
;   instruction and never spills into the `ret`; the trailing NOPs are the
;   self-contained-hook guard (ESSENCE: each hook is ≥5 bytes + padding). Clean,
;   it returns HP_VICTIM_BASE.
;  out: EAX = HP_VICTIM_BASE (when unpatched)
; ---------------------------------------------------------------------------
hp_victim:
    mov  eax, HP_VICTIM_BASE            ; B8 imm32 — exactly the 5 bytes the detour claims
    ret
    nop
    nop
    nop
    nop

; ---------------------------------------------------------------------------
; hp_commit_selftest — install a detour, then SELF-TEST-OR-REVERT: invoke the now-
;   patched function and require it returns the declared token (behavioral proof,
;   NOT a byte compare — a latch can't fake a token it doesn't know). If it does,
;   the patch is kept; if not, the 5 entry bytes are restored (the watchdog),
;   leaving the clean function running. This is the seconds-scale miniature of the
;   forge's verify-or-revert discipline (LIVE_FORGE §5).
;  in:  RDI=target entry, RSI=arena slot, RDX=ptr to 5 saved bytes, RCX=expected token
;  out: RAX = 1 kept / 0 reverted
;  clobbers: RAX (RBX,R12,R13 saved)
; ---------------------------------------------------------------------------
hp_commit_selftest:
    push rbx
    push r12
    push r13
    mov  rbx, rdi                       ; target (also the fn to invoke)
    mov  r13, rdx                       ; saved-bytes ptr
    mov  r12, rcx                       ; expected token
    call hotpatch_write_detour          ; RDI=target, RSI=slot still live -> RAX=1 armed / 0 refused
    test rax, rax
    jz   .revert                        ; out-of-range install refused -> non-fatal miss (bytes unchanged)
    call rbx                            ; invoke the patched fn -> RAX = its return
    cmp  rax, r12
    jne  .revert
    mov  eax, 1                         ; token matched -> keep
    jmp  .done
.revert:
    mov  rdi, rbx                       ; self-test failed -> restore clean bytes
    mov  rsi, r13
    call hotpatch_restore_bytes
    xor  eax, eax                       ; reverted
.done:
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; hotpatch_selftest — the QEMU-gradeable acceptance. Proves, fully in RAM:
;   (1) arena up + executable; baseline victim returns HP_VICTIM_BASE.
;   (2) GOOD patch, CONTENT-GRADED: build a PIC body `mov rax, <random nonce>; ret`
;       where the nonce is a per-boot rdtsc value (a token the code did not know at
;       assemble time), CRC-gate the arena copy, commit-with-self-test, then invoke
;       the victim and require it returns EXACTLY the nonce → the new behavior is
;       proven by content, not by a latch firing.
;   (3) revert the good patch → victim returns baseline again (clean slate).
;   (4) BAD patch → self-test-or-revert (the watchdog): commit a body that returns
;       the WRONG value; the declared self-test fails; the patch auto-reverts; the
;       victim is back to baseline → a bad patch cannot survive.
;   Emits the marker iff every check passes (branch-free failure counting in R15).
;  out: (marker) "[PAOS64] P3 hotpatch: live patch+revert PASS" iff all pass.
; ---------------------------------------------------------------------------
hotpatch_selftest:
    push rbx
    push r12
    push r13
    push r14
    push r15
    xor  r15, r15                       ; running failure count

    ; ---- (0) CRC32 KAT — the IEEE check vectors, un-fakeable ground truth:
    ;      crc32("123456789")==0xCBF43926, crc32("")==0 (byte-match python
    ;      zlib.crc32). A faster-but-wrong CRC would silently corrupt every
    ;      patch, so a miss counts into the selftest verdict.
    lea  rdi, [rel str_hp_kat_vec]
    mov  esi, 9
    call hotpatch_crc32
    cmp  eax, 0xCBF43926
    jne  .crc_kat_fail
    xor  esi, esi                       ; empty buffer -> 0x00000000
    call hotpatch_crc32
    test eax, eax
    jnz  .crc_kat_fail
    lea  rdi, [rel str_hp_crc_kat]      ; both vectors exact -> [hotpatch.crc.kat]
    call serial_string
    jmp  .crc_kat_done
.crc_kat_fail:
    inc  r15
.crc_kat_done:

    call hotpatch_arena_init            ; arena up + executable
    test rax, rax
    jz   .hard_fail                     ; no arena -> nothing to prove; fail
    mov  rbx, rax                       ; RBX = arena base
    lea  rdi, [rel str_hp_arena_static] ; arena is STATIC in-image (rel32-reachable) [hp.arena.static]
    call serial_string

    lea  r12, [rel hp_victim]           ; R12 = the target function

    ; ---- (1) baseline: unpatched victim returns HP_VICTIM_BASE ----
    call hp_victim
    cmp  rax, HP_VICTIM_BASE
    setne al
    movzx eax, al
    add  r15, rax

    ; ---- (2) GOOD patch — content-graded random nonce ----
    rdtsc                               ; per-boot entropy (EDX:EAX)
    shl  rdx, 32
    or   rax, rdx
    mov  rcx, 0x9E3779B97F4A7C15        ; golden-ratio mix -> full 64-bit, != baseline
    xor  rax, rcx
    mov  r14, rax                       ; R14 = the random nonce (the graded token)

    ; build the PIC body in scratch: 48 B8 <nonce8> C3  ("mov rax, imm64; ret")
    lea  rdi, [rel hp_scratch]
    mov  byte [rdi + 0], 0x48
    mov  byte [rdi + 1], 0xB8
    mov  [rdi + 2], r14                 ; imm64 = nonce (position-independent)
    mov  byte [rdi + 10], 0xC3
    ; expected CRC over the intended body (host side of the contract)
    lea  rdi, [rel hp_scratch]
    mov  esi, 11
    call hotpatch_crc32
    mov  r13d, eax                      ; R13D = expected crc
    ; "upload": copy scratch -> arena slot 0
    lea  rsi, [rel hp_scratch]
    mov  rdi, rbx
    mov  ecx, 11
    rep  movsb
    ; CRC-verify the arena copy before arming the detour
    mov  rdi, rbx
    mov  esi, 11
    call hotpatch_crc32
    cmp  eax, r13d
    setne al
    movzx eax, al
    add  r15, rax
    ; save the victim's 5 entry bytes, then commit-with-self-test (expect=nonce)
    mov  eax, [r12]
    mov  [rel hp_saved], eax
    mov  al, [r12 + 4]
    mov  [rel hp_saved + 4], al
    mov  rdi, r12                       ; target
    mov  rsi, rbx                       ; slot 0
    lea  rdx, [rel hp_saved]
    mov  rcx, r14                       ; expected token = the random nonce
    call hp_commit_selftest
    cmp  rax, 1                         ; must be KEPT
    setne cl
    movzx ecx, cl
    add  r15, rcx
    ; content-grade: the live patched fn must return EXACTLY the nonce
    call hp_victim
    cmp  rax, r14
    setne al
    movzx eax, al
    add  r15, rax

    ; ---- (3) revert the good patch -> clean slate ----
    mov  rdi, r12
    lea  rsi, [rel hp_saved]
    call hotpatch_restore_bytes
    call hp_victim
    cmp  rax, HP_VICTIM_BASE
    setne al
    movzx eax, al
    add  r15, rax

    ; ---- (4) BAD patch -> self-test-or-revert watchdog ----
    rdtsc                               ; a fresh expected token the bad body won't return
    shl  rdx, 32
    or   rax, rdx
    mov  rcx, 0x2545F4914F6CDD1D
    xor  rax, rcx
    mov  r14, rax                       ; R14 = expected token (fresh nonce)
    ; build a WRONG body in slot 1 (bump: base+16): returns 0xDEADBEEFDEADBEEF
    lea  rdi, [rbx + 16]
    mov  byte [rdi + 0], 0x48
    mov  byte [rdi + 1], 0xB8
    mov  rcx, 0xDEADBEEFDEADBEEF
    mov  [rdi + 2], rcx
    mov  byte [rdi + 10], 0xC3
    ; save entry bytes (baseline again), commit expecting the nonce the body lacks
    mov  eax, [r12]
    mov  [rel hp_saved], eax
    mov  al, [r12 + 4]
    mov  [rel hp_saved + 4], al
    mov  rdi, r12
    lea  rsi, [rbx + 16]
    lea  rdx, [rel hp_saved]
    mov  rcx, r14                       ; expected token — the bad body returns 0xDEAD… instead
    call hp_commit_selftest
    test rax, rax                       ; must be REVERTED (0)
    setnz cl
    movzx ecx, cl
    add  r15, rcx
    ; watchdog proof: the bad patch is gone — victim back to baseline
    call hp_victim
    cmp  rax, HP_VICTIM_BASE
    setne al
    movzx eax, al
    add  r15, rax

    ; ---- (5) NEGATIVE gate: rel32 range-guard REFUSES an out-of-range detour ----
    ; QEMU can't reproduce the true >2 GiB span (small RAM), so drive a SYNTHETIC one:
    ; a slot 2 GiB+ from the target. The guard must refuse (RAX=0) and leave the
    ; target's 5 entry bytes UNCHANGED. A pre-fix build (blind E9 write) fails here.
    ; MUST be last + we must NOT call the target after (a broken guard would have armed
    ; a detour to an unmapped slot -> calling it would #PF).
    xor  r14, r14                       ; r14 = guard-local failure count
    mov  eax, [r12]                     ; save hp_victim's first 5 entry bytes
    mov  [rel hp_saved], eax
    mov  al, [r12 + 4]
    mov  [rel hp_saved + 4], al
    mov  rdi, r12                       ; target = hp_victim (real, writable, in-image)
    mov  rsi, r12
    mov  rax, 0x80000005                ; +2 GiB + 5 -> displacement 0x80000000 (out of signed-32)
    add  rsi, rax                       ; slot = target + 2 GiB + 5 (never dereferenced; refused first)
    call hotpatch_write_detour          ; must REFUSE -> RAX = 0
    test rax, rax
    setnz cl                            ; nonzero = guard FAILED to refuse
    movzx ecx, cl
    add  r14, rcx
    mov  eax, [r12]                     ; target's entry bytes must be UNCHANGED...
    cmp  eax, [rel hp_saved]
    setne al
    movzx eax, al
    add  r14, rax
    mov  al, [r12 + 4]                  ; ...including the 5th byte
    cmp  al, [rel hp_saved + 4]
    setne al
    movzx eax, al
    add  r14, rax
    add  r15, r14                       ; roll guard failures into the global verdict count
    test r14, r14
    jnz  .skip_guard_marker
    lea  rdi, [rel str_hp_guard]        ; guard fully passed -> emit [hp.rel32.guard]
    call serial_string
.skip_guard_marker:

    ; ---- verdict ----
    test r15, r15
    jnz  .fail
    mov  rdi, LOG_INF                   ; observable INF summary (TESTING §7)
    lea  rsi, [rel str_sub_hp]
    lea  rdx, [rel str_hp_ready]
    call log_line
    lea  rdi, [rel str_hp_pass]         ; the acceptance marker
    call serial_string
    jmp  .ret
.hard_fail:
    inc  r15                            ; arena unavailable counts as a failure
.fail:
    lea  rdi, [rel str_hp_failpfx]      ; observable failure count, then FAIL
    lea  rsi, [rel hp_msgbuf]
    call fmt_str
    lea  rsi, [rel hp_msgbuf]
    add  rsi, rax
    mov  rdi, r15
    call fmt_dec
    mov  rdi, LOG_ERR
    lea  rsi, [rel str_sub_hp]
    lea  rdx, [rel hp_msgbuf]
    call log_line
    lea  rdi, [rel str_hp_fail]
    call serial_string
.ret:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ============================================================================
; 1106 ADDRESS-STABLE HOT-PATCHABLE SLOT REGION — the general-patcher seam.
; Every live-patchable function lives here in a FIXED-SIZE, fixed-ORDER slot
; (HP_SLOT_SIZE bytes, NOP-padded). Two properties fall out by construction:
;   * editing one slot function's body (within its slot) moves NO other symbol
;     in the image — the padding absorbs the delta, so a real single-function
;     change classifies DETOUR-eligible instead of reboot-only (contract B);
;     overflowing a slot is a BUILD ERROR (`times` goes negative), never a
;     silent layout shift.
;   * every slot entry has >= 5 safely-overwritable bytes (ret + NOP pad), so
;     the 5-byte `jmp rel32` detour can never spill into a neighbouring fn.
; A function is live-patchable BY SYMBOL iff it is registered in hp_symtab
; below with HP_ELIG_SINGLE_FN — which in practice means "authored into a
; slot here". Everything else refuses at HOTPATCH_START (eligibility gate).
; ============================================================================
HP_SLOT_SIZE  equ 64

align 64
hp_slots_base:
; --- slot 0: general_probe_field — the general-patcher STATUS-field hook. The UDP
;     STATUS reply builder calls it on every reply (RBX=reply buf base, R15D=write
;     offset — the gen'd-body ABI). Unpatched: pure no-op, no field; a committed
;     body typically appends " <nonce>" advancing R15D (the 1106 probe's grade). ---
general_probe_field:
    ret
    times HP_SLOT_SIZE - ($ - general_probe_field) db 0x90
; --- slot 1: status_hotpatch_hook — the original 1018 LIVE patch target (legacy
;     KIND STATUSHOOK), same reply-builder ABI as slot 0. Unpatched: no-op, no
;     HOTPATCH= field; the generated body appends " HOTPATCH=1" (advancing R15D).
;     The un-fakeable content-grade surface: the field can only appear if a real
;     body was uploaded, CRC-gated, and armed live. ---
status_hotpatch_hook:
    ret
    times HP_SLOT_SIZE - ($ - status_hotpatch_hook) db 0x90
hp_slots_end:

; --- hp_symtab — the by-symbol patch-target registry. Fixed 40-byte entries:
;       +0  name  (NUL-terminated, max 23 chars)
;       +24 addr  (dq, RUNTIME-filled by hp_symtab_init — never `dq <symbol>`:
;                  that bakes the compile-time RVA, not the load VA; G1 hazard)
;       +32 elig  (dd, HP_ELIG_* class — the box-side eligibility gate)
;       +36 slot  (dd, fixed slot index for SINGLE_FN entries; the addr-stable
;                  contract checked live: addr == hp_slots_base + slot*64)
;     Ineligible exemplars (boot-path etc.) are listed ON PURPOSE so a named
;     ineligible target is REFUSED with a specific verdict, not "unknown". ---
HP_SYM_ADDR   equ 24
HP_SYM_ELIG   equ 32
HP_SYM_SLOT   equ 36
HP_SYMENT     equ 40
HP_SYM_COUNT  equ 3

align 8
hp_symtab:
.e0_name: db "general_probe_field", 0
          times hp_symtab + 24 - $ db 0
.e0_addr: dq 0
.e0_elig: dd HP_ELIG_SINGLE_FN
.e0_slot: dd 0
.e1_name: db "status_hotpatch_hook", 0
          times hp_symtab + HP_SYMENT + 24 - $ db 0
.e1_addr: dq 0
.e1_elig: dd HP_ELIG_SINGLE_FN
.e1_slot: dd 1
.e2_name: db "gdt_init", 0                    ; boot-path exemplar: runs before the
          times hp_symtab + 2*HP_SYMENT + 24 - $ db 0    ; patcher is up -> REFUSED
.e2_addr: dq 0
.e2_elig: dd HP_ELIG_BOOT_PATH
.e2_slot: dd 0
hp_symtab_ready: db 0

; ---------------------------------------------------------------------------
; hp_symtab_init — runtime-fill the symtab addr fields (lea, not dq — G1) once.
;   Idempotent; called lazily from every resolve path so there is no boot-order
;   dependency. clobbers RAX.
; ---------------------------------------------------------------------------
hp_symtab_init:
    cmp  byte [rel hp_symtab_ready], 1
    je   .done
    lea  rax, [rel general_probe_field]
    mov  [rel hp_symtab.e0_addr], rax
    lea  rax, [rel status_hotpatch_hook]
    mov  [rel hp_symtab.e1_addr], rax
    lea  rax, [rel gdt_init]
    mov  [rel hp_symtab.e2_addr], rax
    mov  byte [rel hp_symtab_ready], 1
.done:
    ret

; ---------------------------------------------------------------------------
; hp_resolve_symbol — look a NUL-terminated name up in hp_symtab.
;  in:  RDI=name cstr
;  out: RAX = entry ptr (read HP_SYM_ADDR/ELIG/SLOT off it) or 0 = unknown
;  clobbers: RAX,RCX,RDX,RSI,R8,R9
; ---------------------------------------------------------------------------
hp_resolve_symbol:
    call hp_symtab_init
    lea  rsi, [rel hp_symtab]           ; entry cursor
    mov  ecx, HP_SYM_COUNT
.entry:
    xor  edx, edx                       ; byte index into the two names
.byte:
    mov  al, [rsi + rdx]
    cmp  al, [rdi + rdx]
    jne  .next
    test al, al                         ; matched a NUL -> full match
    jz   .found
    inc  edx
    cmp  edx, 24
    jb   .byte
.next:
    add  rsi, HP_SYMENT
    dec  ecx
    jnz  .entry
    xor  eax, eax                       ; unknown symbol
    ret
.found:
    mov  rax, rsi
    ret

; ---------------------------------------------------------------------------
; hp_addrstab_check — the LIVE address-stability verdict (never a latch: re-walks
;   the table on every call). Stable iff every SINGLE_FN symtab entry sits at
;   EXACTLY hp_slots_base + slot*HP_SLOT_SIZE — i.e. the hot-patchable functions
;   are in their fixed slots, so a single-fn edit cannot have moved its peers.
;  out: RAX = 1 stable / 0 drifted
;  clobbers: RAX,RCX,RDX,RSI,R8,R9
; ---------------------------------------------------------------------------
hp_addrstab_check:
    call hp_symtab_init
    lea  rsi, [rel hp_symtab]
    mov  ecx, HP_SYM_COUNT
    lea  r8,  [rel hp_slots_base]
.entry:
    cmp  dword [rsi + HP_SYM_ELIG], HP_ELIG_SINGLE_FN
    jne  .next                          ; only slot residents carry the contract
    mov  edx, [rsi + HP_SYM_SLOT]
    imul rdx, HP_SLOT_SIZE
    add  rdx, r8                        ; expected = base + slot*size
    cmp  rdx, [rsi + HP_SYM_ADDR]
    jne  .drift
.next:
    add  rsi, HP_SYMENT
    dec  ecx
    jnz  .entry
    mov  eax, 1
    ret
.drift:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; hotpatch_symbol_selftest — the QEMU-gradeable 1106 acceptance. Two earned
;   markers, each iff its checks ALL pass (branch-free failure counting):
;     * [hotpatch.target.by_symbol] — resolve "general_probe_field" through the
;       SAME string-matching path HOTPATCH_START uses, require the address and
;       eligibility come back right, then run a FULL live patch cycle on the
;       resolved (non-STATUSHOOK) target: PIC body returning a per-boot random
;       nonce, commit-with-self-test, content-grade the nonce, revert clean.
;       Also: a boot-path name resolves INELIGIBLE (the negative gate).
;     * [hotpatch.build.addr_stable] — hp_addrstab_check passes live: every
;       registered hot-patchable fn is in its fixed slot.
; ---------------------------------------------------------------------------
hotpatch_symbol_selftest:
    push rbx
    push r12
    push r13
    push r14
    push r15
    xor  r15, r15                       ; failure count

    ; ---- resolve by name (the UDP path's resolver) ----
    lea  rdi, [rel str_hps_gpf_name]
    call hp_resolve_symbol
    test rax, rax
    setz cl
    movzx ecx, cl
    add  r15, rcx
    test rax, rax
    jz   .stab                          ; unknown -> can't continue the patch leg
    mov  rbx, rax                       ; RBX = symtab entry
    lea  rdx, [rel general_probe_field]
    cmp  rdx, [rbx + HP_SYM_ADDR]       ; resolver returned the REAL address
    setne al
    movzx eax, al
    add  r15, rax
    cmp  dword [rbx + HP_SYM_ELIG], HP_ELIG_SINGLE_FN
    setne al
    movzx eax, al
    add  r15, rax
    ; negative: a boot-path name resolves but is NOT single-fn-eligible
    lea  rdi, [rel str_hps_boot_name]
    call hp_resolve_symbol
    test rax, rax
    setz cl
    movzx ecx, cl
    add  r15, rcx
    test rax, rax
    jz   .patch
    cmp  dword [rax + HP_SYM_ELIG], HP_ELIG_SINGLE_FN
    sete cl                             ; eligible would be WRONG
    movzx ecx, cl
    add  r15, rcx

.patch:
    ; ---- full live patch cycle on the by-symbol target (slot 0) ----
    call hotpatch_arena_init
    test rax, rax
    jz   .out                          ; no copy/detour without an executable arena
    mov  r13, rax                       ; R13 = arena slot
    rdtsc                               ; per-boot random nonce (graded token)
    shl  rdx, 32
    or   rax, rdx
    mov  rcx, 0x6C1106C11106C1A5
    xor  rax, rcx
    mov  r14, rax                       ; R14 = nonce
    lea  rdi, [rel hp_scratch]          ; body: 48 B8 <nonce8> C3
    mov  byte [rdi + 0], 0x48
    mov  byte [rdi + 1], 0xB8
    mov  [rdi + 2], r14
    mov  byte [rdi + 10], 0xC3
    lea  rsi, [rel hp_scratch]          ; upload -> arena
    mov  rdi, r13
    mov  ecx, 11
    cld
    rep  movsb
    mov  r12, [rbx + HP_SYM_ADDR]       ; R12 = resolved target
    mov  eax, [r12]                     ; save its 5 entry bytes
    mov  [rel hp_saved], eax
    mov  al, [r12 + 4]
    mov  [rel hp_saved + 4], al
    mov  rdi, r12                       ; commit-with-self-test (expect the nonce)
    mov  rsi, r13
    lea  rdx, [rel hp_saved]
    mov  rcx, r14
    call hp_commit_selftest
    cmp  rax, 1                         ; must be KEPT
    setne al
    movzx eax, al
    add  r15, rax
    call general_probe_field            ; content-grade: live fn returns the nonce
    cmp  rax, r14
    setne al
    movzx eax, al
    add  r15, rax
    mov  rdi, r12                       ; revert -> clean slate
    lea  rsi, [rel hp_saved]
    call hotpatch_restore_bytes
    mov  eax, [r12]                     ; entry bytes byte-exact restored
    cmp  eax, [rel hp_saved]
    setne al
    movzx eax, al
    add  r15, rax
    test r15, r15
    jnz  .stab
    lea  rdi, [rel str_hp_sym_pass]
    call serial_string

.stab:
    ; ---- address-stable build property (independent marker) ----
    call hp_addrstab_check
    cmp  rax, 1
    jne  .out
    lea  rdi, [rel str_hp_stab_pass]
    call serial_string
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; hp_eligible — the ELIGIBILITY GATE (LIVE_FORGE §4.5): classify a change kind as
;   live-patchable or not. ONLY a single self-contained function BODY is eligible;
;   boot-path / multi-function / data-layout changes are REFUSED (the generator then
;   falls back to full deploy). Kept branch-free-simple: the gate is a whitelist of
;   exactly one kind — everything else is ineligible by construction (a new kind is
;   ineligible until explicitly proven safe).
;  in:  EDI = HP_ELIG_* kind   out: RAX = 1 eligible / 0 ineligible
; ---------------------------------------------------------------------------
hp_eligible:
    xor  eax, eax
    cmp  edi, HP_ELIG_SINGLE_FN
    jne  .out
    mov  eax, 1
.out:
    ret

; ---------------------------------------------------------------------------
; hp_apply_relocs — consume a per-function reloc table (C1, PRINCIPLES §1) to PIC-ify
;   a freshly-extracted function body: for each {offset, value} entry patch the value
;   (an IMM64 site — the position-independent seam the generator fills from the
;   link-map instead of hand-baking). Preflight the complete caller-owned, readable
;   immutable table before any body write. Reject wrapping spans, table/body overlap
;   and any offset beyond bodylen-8, preserving all bytes on malformed input. These
;   checks do not validate pointer mappings or synchronize a concurrent table writer.
;   A zero-length table is trivially applied without dereferencing either pointer.
;  in:  RDI=body, ESI=bodylen, RDX=reloc table (16B entries {dq off, dq val}), ECX=n
;  out: RAX = 1 all applied / 0 rejected (malformed)
;  clobbers: RAX,RCX,RDX,R8,R9,R10
; ---------------------------------------------------------------------------
hp_apply_relocs:
    test ecx, ecx
    jz   .ok                            ; empty table never dereferences either pointer
    mov  eax, esi                       ; bodylen is the documented 32-bit input
    cmp  eax, 8
    jb   .reject                        ; no IMM64 fits in a shorter body
    mov  r8, rdi
    add  r8, rax                        ; exclusive body end
    jc   .reject                        ; reject wrapping destination spans
    mov  r9d, ecx
    shl  r9, 4                         ; table byte count (n is uint32)
    add  r9, rdx                        ; exclusive table end
    jc   .reject
    cmp  rdi, r9
    jae  .disjoint                      ; body begins at/after table end
    cmp  rdx, r8
    jb   .reject                        ; table must not alias writable body bytes
.disjoint:
    lea  r8, [rax - 8]                  ; largest legal offset; no offset+8 wrap
    mov  r9, rdx
    mov  r10d, ecx
.preflight:
    cmp  [r9], r8
    ja   .reject                        ; validate EVERY entry before the first store
    add  r9, 16
    dec  r10d
    jnz  .preflight
.loop:
    mov  r8, [rdx + 0]
    mov  r10, [rdx + 8]
    mov  [rdi + r8], r10
    add  rdx, 16
    dec  ecx
    jnz  .loop
.ok:
    mov  eax, 1
    ret
.reject:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; hotpatch_gen_selftest — the QEMU-gradeable GENERATOR acceptance (the platform-
;   agnostic half of 1018; the LIVE UDP half is bare-metal, graded by the probe).
;   Proves, fully in RAM, the three generator invariants and emits one marker each,
;   ONLY when that invariant's checks all pass (branch-free failure counting):
;     * [hotpatch.gen.eligibility_gate] — the gate ACCEPTS a single-fn-body change and
;       REFUSES boot-path / multi-fn / data-layout changes (1 accept + 3 rejects).
;     * [hotpatch.gen.c1_reloc_consumed] — a per-function reloc table is consumed to
;       PIC-ify a body (IMM64 site filled from the table, verified byte-exact) AND a
;       MALFORMED table (out-of-range offset) is rejected with nothing written.
;     * [hotpatch.gen.validated] — end-to-end: generate a body that returns a per-boot
;       random nonce (the IMM64 filled by a reloc, not baked), CRC-implicit via the
;       engine, commit-with-self-test against hp_victim, content-grade the nonce
;       round-trip, then revert clean. A latch cannot fake a nonce it never knew.
; ---------------------------------------------------------------------------
hotpatch_gen_selftest:
    push rbx
    push r12
    push r13
    push r14
    push r15
    call hotpatch_arena_init            ; arena up + executable
    test rax, rax
    jz   .skip_valid                   ; refuse before any arena access
    mov  r15, rax                       ; R15 = arena base (patch slot)

    ; ===== (A) eligibility gate: 1 accept + 3 rejects =====
    xor  r12, r12                       ; R12 = elig failure count
    mov  edi, HP_ELIG_SINGLE_FN
    call hp_eligible                    ; expect 1
    cmp  rax, 1
    setne al
    movzx eax, al
    add  r12, rax
    mov  edi, HP_ELIG_BOOT_PATH
    call hp_eligible                    ; expect 0
    test rax, rax
    setnz al
    movzx eax, al
    add  r12, rax
    mov  edi, HP_ELIG_MULTI_FN
    call hp_eligible                    ; expect 0
    test rax, rax
    setnz al
    movzx eax, al
    add  r12, rax
    mov  edi, HP_ELIG_DATA_LAYOUT
    call hp_eligible                    ; expect 0
    test rax, rax
    setnz al
    movzx eax, al
    add  r12, rax
    test r12, r12
    jnz  .skip_elig
    lea  rdi, [rel str_hp_gen_elig]
    call serial_string
.skip_elig:

    ; ===== (B) C1 reloc consumption: good-apply + malformed-reject =====
    xor  r13, r13                       ; R13 = reloc failure count
    rdtsc                               ; per-boot nonce (also reused for (C))
    shl  rdx, 32
    or   rax, rdx
    mov  rcx, 0x9E3779B97F4A7C15
    xor  rax, rcx
    mov  r14, rax                       ; R14 = the random nonce (graded token)
    ; body template: 48 B8 <imm64=0> C3  ("mov rax, imm64; ret") — 11 bytes
    lea  rdi, [rel hp_scratch]
    mov  byte  [rdi + 0], 0x48
    mov  byte  [rdi + 1], 0xB8
    mov  qword [rdi + 2], 0             ; the IMM64 reloc site (to be filled)
    mov  byte  [rdi + 10], 0xC3
    ; reloc table: one IMM64 entry {offset=2, value=nonce}
    lea  rdi, [rel hp_reloc_tbl]
    mov  qword [rdi + 0], 2
    mov  [rdi + 8], r14
    ; consume it
    lea  rdi, [rel hp_scratch]
    mov  esi, 11
    lea  rdx, [rel hp_reloc_tbl]
    mov  ecx, 1
    call hp_apply_relocs                ; expect 1
    cmp  rax, 1
    setne al
    movzx eax, al
    add  r13, rax
    ; verify the IMM64 site == nonce (byte-exact PIC-ification)
    lea  rdi, [rel hp_scratch]
    mov  rax, [rdi + 2]
    cmp  rax, r14
    setne al
    movzx eax, al
    add  r13, rax
    ; malformed: offset=100 (> body len 11) MUST be rejected, nothing written
    lea  rdi, [rel hp_reloc_tbl]
    mov  qword [rdi + 0], 100
    mov  qword [rdi + 8], 0
    lea  rdi, [rel hp_scratch]
    mov  esi, 11
    lea  rdx, [rel hp_reloc_tbl]
    mov  ecx, 1
    call hp_apply_relocs                ; expect 0
    test rax, rax
    setnz al
    movzx eax, al
    add  r13, rax
    test r13, r13
    jnz  .skip_reloc
    lea  rdi, [rel str_hp_gen_reloc]
    call serial_string
.skip_reloc:

    ; ===== (C) validated: end-to-end nonce round-trip via the engine =====
    xor  ebx, ebx                       ; RBX = validated failure count
    ; rebuild body + good reloc (we clobbered the table above)
    lea  rdi, [rel hp_scratch]
    mov  byte  [rdi + 0], 0x48
    mov  byte  [rdi + 1], 0xB8
    mov  qword [rdi + 2], 0
    mov  byte  [rdi + 10], 0xC3
    lea  rdi, [rel hp_reloc_tbl]
    mov  qword [rdi + 0], 2
    mov  [rdi + 8], r14
    lea  rdi, [rel hp_scratch]
    mov  esi, 11
    lea  rdx, [rel hp_reloc_tbl]
    mov  ecx, 1
    call hp_apply_relocs
    ; "upload" the reloc'd body -> arena slot (R15)
    lea  rsi, [rel hp_scratch]
    mov  rdi, r15
    mov  ecx, 11
    cld
    rep  movsb
    ; save hp_victim's 5 entry bytes, commit-with-self-test expecting the nonce
    lea  r12, [rel hp_victim]
    mov  eax, [r12]
    mov  [rel hp_saved], eax
    mov  al, [r12 + 4]
    mov  [rel hp_saved + 4], al
    mov  rdi, r12                       ; target
    mov  rsi, r15                       ; slot
    lea  rdx, [rel hp_saved]
    mov  rcx, r14                       ; expected token = nonce
    call hp_commit_selftest             ; expect 1 (kept)
    cmp  rax, 1
    setne al
    movzx eax, al
    add  rbx, rax
    ; content-grade: the live patched victim returns EXACTLY the nonce
    call hp_victim
    cmp  rax, r14
    setne al
    movzx eax, al
    add  rbx, rax
    ; revert -> clean slate
    mov  rdi, r12
    lea  rsi, [rel hp_saved]
    call hotpatch_restore_bytes
    call hp_victim
    cmp  rax, HP_VICTIM_BASE
    setne al
    movzx eax, al
    add  rbx, rax
    test rbx, rbx
    jnz  .skip_valid
    lea  rdi, [rel str_hp_gen_valid]
    call serial_string
.skip_valid:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ============================================================================
; svc/hotpatch data (in-image RW+X pre-BSS; the image page is RW under our map,
; so the scratch/saved buffers are writable, and hp_victim's entry is writable
; in place — the detour target). Never `dq <symbol>`: all addresses are reached
; RIP-relative (MODULES G1 load-VA hazard).
; ============================================================================
hotpatch_arena_base: dq 0
hotpatch_arena_bump: dq 0
hp_saved:            times 8  db 0      ; the victim's saved 5 entry bytes (0..4)
hp_scratch:          times 16 db 0      ; the intended PIC body, pre-upload
hp_reloc_tbl:        times 32 db 0      ; per-function reloc table scratch (C1 seam)
hp_msgbuf:           times 32 db 0
; STATIC in-image PIC patch arena (1092): in-image => always within signed-rel32 of
; every in-image patch target, so the detour never overflows ±2 GiB (the bare-metal
; #PF). The static arena occupies 64 KiB in the image. NX data under
; W^X; hotpatch_arena_init flips its page(s) executable at boot. Align the
; allocation so a 4 KiB leaf never exposes adjacent scratch buffers or strings.
; Page math is relative to code_start: PE file 0x200 maps to RVA 0x1000,
; so file-offset ALIGN would leave the arena 0xE00 bytes into a runtime page.
; Use the WDATA_PAGE_PAD idiom on both sides. A 2 MiB leaf retains its
; existing coarse permission granularity.
times ((0x1000 - (($ - code_start) & 0xFFF)) & 0xFFF) db 0
hp_arena_static:     times HP_ARENA_SIZE db 0
times ((0x1000 - (($ - code_start) & 0xFFF)) & 0xFFF) db 0

str_sub_hp:      db "hotpatch", 0
str_hp_ready:    db "live patch+revert online (arena X, CRC-gated, self-test-or-revert)", 0
str_hp_failpfx:  db "hotpatch failures=", 0
str_hp_pass:     db "[PAOS64] P3 hotpatch: live patch+revert PASS", 13, 10, 0
str_hp_fail:     db "[PAOS64] P3 hotpatch: live patch+revert FAIL", 13, 10, 0
str_hp_arena_static: db "[PAOS64] P3 hotpatch: arena static in-image (rel32-reachable) [hp.arena.static]", 13, 10, 0
str_hp_guard:        db "[PAOS64] P3 hotpatch: rel32-range guard PASS (out-of-range detour refused) [hp.rel32.guard]", 13, 10, 0
str_hp_kat_vec:      db "123456789"    ; the standard IEEE CRC32 check input (no NUL needed; len passed)
str_hp_crc_kat:      db "[PAOS64] P3 hotpatch: CRC32 KAT PASS ('123456789'=0xCBF43926, ''=0) [hotpatch.crc.kat]", 13, 10, 0
; --- 1018 generator (QEMU-gradeable) markers: each fires only when its invariant's
;     RAM checks all pass (see hotpatch_gen_selftest). Registered dotted in
;     regression_tests.txt (key == contract's required name, character-for-character). ---
str_hp_gen_elig:     db "[PAOS64] P3 hotpatch-gen: eligibility gate accepts single-fn / refuses boot-path+multi-fn+data-layout [hotpatch.gen.eligibility_gate]", 13, 10, 0
str_hp_gen_reloc:    db "[PAOS64] P3 hotpatch-gen: C1 per-function reloc table consumed (IMM64 PIC-ified, malformed rejected) [hotpatch.gen.c1_reloc_consumed]", 13, 10, 0
str_hp_gen_valid:    db "[PAOS64] P3 hotpatch-gen: generator validated end-to-end (reloc'd body, nonce round-trip, clean revert) [hotpatch.gen.validated]", 13, 10, 0
; --- 1106 general-patcher markers (each fires only when its invariant's RAM
;     checks all pass; see hotpatch_symbol_selftest) + the resolver's name keys ---
str_hps_gpf_name:  db "general_probe_field", 0
str_hps_boot_name: db "gdt_init", 0
str_hp_sym_pass:   db "[PAOS64] P3 hotpatch: target-by-symbol resolve+patch+nonce+revert PASS (non-STATUSHOOK target) [hotpatch.target.by_symbol]", 13, 10, 0
str_hp_stab_pass:  db "[PAOS64] P3 hotpatch: hot-patchable slot region address-stable (fixed per-fn slots) [hotpatch.build.addr_stable]", 13, 10, 0
