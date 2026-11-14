;; MODULE core/lib/strmem_kat
;; LAYER 1
;; EXPORTS strmem_kat_selftest, lib_clobber_selftest
;; IMPORTS core/lib/str, core/lib/mem, core/lib/fmt, core/log, boot/serial
;; CAPS
;; OWNER saga:core
; ============================================================================
; core/lib/strmem_kat.asm — the KNOWN-ANSWER-TEST harness for the str + mem
; primitives (TESTING §8: "common functions get the most test rigor — reference
; vectors, and the single-definition assertion; tournament them hardest").
;
; These primitives are called from every layer, so a wrong one (or a duplicate
; variant) poisons the whole tree — the ~111-str-variant lesson. This module is
; the frozen scorecard the str/mem tournament shoots at (TESTING §2): it grades
; the BEHAVIOUR against literal expected answers, so a lazy/broken implementation
; cannot pass by merely running (TESTING §1).
;
; COVERAGE
;   TABLES (data-driven, additive — a new case is one more row, no code change):
;     strlen_vectors   (string  -> length)
;     strcmp_vectors   (a,b     -> sign of a[i]-b[i])
;     memcmp_vectors   (a,b,len -> sign, incl a NUL-edge and a zero-length row)
;   EXPLICIT KA BLOCKS (buffer-producing ops graded byte-for-byte):
;     strcpy_s  (normal, truncation cap, dstsize=0 no-write)
;     str_find  (found pointer, absent->0, empty needle, match-at-start)
;     memcpy    (copies past embedded NUL; returns dst), memset (fill + bounds)
;   NEGATIVE / EDGE (TESTING §4 — the failure modes, not just the happy path):
;     overlapping memcpy  -> documents forward-copy hazard (dst>src duplicates;
;                            "ABCDEF" -> "AAAAAA" is the deterministic known answer)
;     zero-length         -> memcpy/memset are no-ops, memcmp returns 0
;     NUL edge            -> memcpy/memcmp span the NUL; strcpy_s stops at it
;
; SINGLE-DEFINITION PROOF (G1): not asserted at runtime but at BUILD time — modlint
; (make's first step) fails on any *str(len|cmp|cpy|cat|chr|nlen)* / *mem(cpy|set|
; cmp|move)* label outside core/lib/. A green build IS the "exactly one of each"
; proof; this KAT proves that one is CORRECT.
;
; Assertions are branch-free: each check does cmp/test -> setne -> add into r15
; (the running failure count). 0 failures => the PASS marker; any failure logs the
; count (observable, TESTING §7) and emits FAIL. All buffers/vectors are in-image
; (RW+X pre-BSS, MEMORY_MAP §3.1), same placement as fmt.asm's fmt_scratch.
; ============================================================================

; kat_signcheck(RDI=result(signed), RSI=expected sign in {-1,0,+1}) -> RAX 0=match
;   Grades a strcmp/memcmp result by SIGN (the primitives return a[i]-b[i], whose
;   magnitude is unspecified — only the sign is contractual).
kat_signcheck:
    test rsi, rsi
    js   .exp_neg
    jnz  .exp_pos
    test rdi, rdi                   ; expect zero
    jnz  .no
    jmp  .yes
.exp_pos:
    test rdi, rdi                   ; expect > 0
    jle  .no
    jmp  .yes
.exp_neg:
    test rdi, rdi                   ; expect < 0
    jge  .no
.yes:
    xor  eax, eax
    ret
.no:
    mov  eax, 1
    ret

; kat_group_marker(RDI=group failure count, RSI=PASS marker string)
;   Emits the per-primitive PASS marker (via serial_string) IFF the group had
;   zero failures. A wrong reference-vector result makes that group's count > 0,
;   so ITS marker never appears (un-fakeable per-function proof, TESTING §2.5 —
;   the core_lib tournament ranks correctness on exactly these markers). Preserves
;   r12-r15/rbx (serial_string saves rdi/rax only, its callee serial_char saves the
;   rest), so callers can snapshot the running fail count in r12-r15 across the call.
kat_group_marker:
    test rdi, rdi
    jnz  .skip                      ; group had >=1 failure -> marker ABSENT
    mov  rdi, rsi
    call serial_string
.skip:
    ret

; strmem_kat_selftest — run every vector/block, emit the acceptance marker.
;   out: (marker) "[PAOS64] P2 lib: str+mem KAT PASS" iff all pass.
strmem_kat_selftest:
    push rbx
    push r12
    push r13
    push r14
    push r15
    xor  r15, r15                   ; running failure count (combined marker)
    mov  qword [rel kat_mem_fails], 0  ; lib.mem.kat accumulator (its blocks are
                                        ; interleaved by the str group, so a memory
                                        ; counter, not an r15 snapshot delta)

    ; ---- TABLE: strlen (string -> length) ----  [lib.strlen.kat group] ----
    mov  r12, r15                   ; per-group snapshot: failures = r15 - r12
    lea  r14, [rel strlen_vectors]
    lea  r13, [rel strlen_vectors_end]
.sl_loop:
    cmp  r14, r13
    jae  .sl_done
    lea  rdi, [r14 + 4]             ; inline string
    call strlen
    movzx ecx, word [r14]           ; expected length
    cmp  rax, rcx
    setne al
    movzx eax, al
    add  r15, rax
    add  r14, 24
    jmp  .sl_loop
.sl_done:
    mov  rdi, r15                    ; strlen group failures
    sub  rdi, r12
    lea  rsi, [rel str_km_strlen_pass]
    call kat_group_marker

    ; ---- TABLE: strcmp (a,b -> sign of a[i]-b[i]) ----  [lib.strcmp.kat group] ----
    mov  r12, r15
    lea  r14, [rel strcmp_vectors]
    lea  r13, [rel strcmp_vectors_end]
.sc_loop:
    cmp  r14, r13
    jae  .sc_done
    lea  rdi, [r14 + 4]             ; a
    lea  rsi, [r14 + 18]            ; b (4 + 14)
    call strcmp
    movsxd rdi, eax                 ; result (32-bit signed a[i]-b[i]) -> 64-bit
    movsx rsi, byte [r14]           ; expected sign
    call kat_signcheck
    add  r15, rax
    add  r14, 32
    jmp  .sc_loop
.sc_done:
    mov  rdi, r15                    ; strcmp group failures
    sub  rdi, r12
    lea  rsi, [rel str_km_strcmp_pass]
    call kat_group_marker
    mov  rdi, r15                    ; tourn.strcmp.kat: SAME strcmp fail count
    sub  rdi, r12                    ; (kat_group_marker preserves r12-r15) — reuse
    lea  rsi, [rel str_km_tourn_strcmp_kat]  ; the one G1 table, no 2nd KAT authored
    call kat_group_marker

    ; ---- TABLE: memcmp (a,b,len -> sign; incl NUL-edge + zero-length rows) ----  [lib.memcmp.kat group] ----
    mov  r12, r15
    lea  r14, [rel memcmp_vectors]
    lea  r13, [rel memcmp_vectors_end]
.mm_loop:
    cmp  r14, r13
    jae  .mm_done
    lea  rdi, [r14 + 4]             ; a
    lea  rsi, [r14 + 16]            ; b (4 + 12)
    movzx edx, byte [r14 + 1]       ; len
    call memcmp
    movsxd rdi, eax                 ; result (32-bit signed a[i]-b[i]) -> 64-bit
    movsx rsi, byte [r14]           ; expected sign
    call kat_signcheck
    add  r15, rax
    add  r14, 28
    jmp  .mm_loop
.mm_done:
    mov  rdi, r15                    ; memcmp group failures
    sub  rdi, r12
    lea  rsi, [rel str_km_memcmp_pass]
    call kat_group_marker

    ; ==== lib.mem.kat region A: memset + memcpy (region B = overlap + zero-len below) ====
    mov  r12, r15                   ; region-A snapshot
    ; ---- BLOCK: memset (fill + tight bounds) ----
    lea  rdi, [rel kat_scratch]
    mov  esi, 0xAB
    mov  edx, 16
    call memset
    cmp  byte [rel kat_scratch], 0xAB       ; first filled
    setne al
    movzx eax, al
    add  r15, rax
    cmp  byte [rel kat_scratch + 15], 0xAB  ; last filled
    setne al
    movzx eax, al
    add  r15, rax
    cmp  byte [rel kat_scratch + 16], 0     ; one past NOT touched
    setne al
    movzx eax, al
    add  r15, rax

    ; ---- BLOCK: memcpy (copies past an embedded NUL; returns dst) ----
    lea  rdi, [rel kat_dst]
    lea  rsi, [rel kat_embed]               ; a,b,0,c,d,0 (6 bytes)
    mov  edx, 6
    call memcpy
    lea  rbx, [rel kat_dst]
    cmp  rax, rbx                           ; memcpy returns dst
    setne al
    movzx eax, al
    add  r15, rax
    cmp  byte [rel kat_dst + 3], 'c'        ; byte AFTER the embedded NUL copied
    setne al
    movzx eax, al
    add  r15, rax
    lea  rdi, [rel kat_dst]                 ; full 6 bytes equal (memcmp, NUL-agnostic)
    lea  rsi, [rel kat_embed]
    mov  edx, 6
    call memcmp
    test rax, rax
    setnz al
    movzx eax, al
    add  r15, rax

    mov  rax, r15                   ; fold region A into the lib.mem.kat accumulator
    sub  rax, r12
    add  [rel kat_mem_fails], rax

    ; ==== lib.str.kat group: strcpy_s + str_find ====
    mov  r12, r15                   ; str-group snapshot
    ; ---- BLOCK: strcpy_s (normal / truncation cap / dstsize=0 no-write) ----
    lea  rdi, [rel kat_dst]                 ; normal: ample buffer
    lea  rsi, [rel kat_hello]
    mov  edx, 32
    call strcpy_s
    cmp  rax, 5                             ; copied strlen("hello")
    setne al
    movzx eax, al
    add  r15, rax
    lea  rdi, [rel kat_dst]
    lea  rsi, [rel kat_hello]
    call strcmp                             ; equal
    test rax, rax
    setnz al
    movzx eax, al
    add  r15, rax
    lea  rdi, [rel kat_dst]                 ; cap: dstsize=4 -> "hel" + NUL
    lea  rsi, [rel kat_hello]
    mov  edx, 4
    call strcpy_s
    cmp  rax, 3                             ; copied only 3
    setne al
    movzx eax, al
    add  r15, rax
    lea  rdi, [rel kat_dst]
    lea  rsi, [rel kat_hel]                 ; "hel"
    call strcmp
    test rax, rax
    setnz al
    movzx eax, al
    add  r15, rax
    mov  byte [rel kat_scratch], 0x77       ; guard: dstsize=0 must not write
    lea  rdi, [rel kat_scratch]
    lea  rsi, [rel kat_hello]
    xor  edx, edx
    call strcpy_s
    test rax, rax                           ; returns 0
    setnz al
    movzx eax, al
    add  r15, rax
    cmp  byte [rel kat_scratch], 0x77       ; guard untouched
    setne al
    movzx eax, al
    add  r15, rax

    ; ---- BLOCK: str_find (found ptr / absent / empty needle / match-at-start) ----
    lea  rdi, [rel kat_haystack]            ; "hello world"
    lea  rsi, [rel kat_needle]              ; "world" @ offset 6
    call str_find
    lea  rbx, [rel kat_haystack]
    add  rbx, 6
    cmp  rax, rbx
    setne al
    movzx eax, al
    add  r15, rax
    lea  rdi, [rel kat_haystack]            ; absent -> 0
    lea  rsi, [rel kat_missing]             ; "xyz"
    call str_find
    test rax, rax
    setnz al
    movzx eax, al
    add  r15, rax
    lea  rdi, [rel kat_haystack]            ; empty needle -> haystack
    lea  rsi, [rel kat_empty]
    call str_find
    lea  rbx, [rel kat_haystack]
    cmp  rax, rbx
    setne al
    movzx eax, al
    add  r15, rax
    lea  rdi, [rel kat_haystack]            ; match at offset 0
    lea  rsi, [rel kat_hello]               ; "hello"
    call str_find
    lea  rbx, [rel kat_haystack]
    cmp  rax, rbx
    setne al
    movzx eax, al
    add  r15, rax

    mov  rdi, r15                    ; str group failures
    sub  rdi, r12
    lea  rsi, [rel str_km_str_pass]
    call kat_group_marker

    ; ==== lib.mem.kat region B: overlap + zero-length (folded into accumulator) ====
    mov  r12, r15                   ; region-B snapshot
    ; ---- NEGATIVE: overlapping memcpy is forward-only (NOT memmove) ----
    ; Reset kat_ov = "ABCDEF\0", then memcpy(kat_ov+1, kat_ov, 5). Forward rep movsb
    ; propagates 'A' through the overlap -> "AAAAAA". Deterministic known answer
    ; that DOCUMENTS the hazard (overlap needs a memmove; that is future work).
    lea  rdi, [rel kat_ov]
    lea  rsi, [rel kat_ov_src]              ; "ABCDEF\0"
    mov  edx, 7
    call memcpy
    lea  rdi, [rel kat_ov]
    inc  rdi                                ; dst = kat_ov + 1 (overlaps src)
    lea  rsi, [rel kat_ov]                  ; src = kat_ov
    mov  edx, 5
    call memcpy
    lea  rdi, [rel kat_ov]
    lea  rsi, [rel kat_ov_expect]           ; "AAAAAA"
    mov  edx, 6
    call memcmp
    test rax, rax
    setnz al
    movzx eax, al
    add  r15, rax

    ; ---- NEGATIVE/EDGE: zero-length memcpy/memset are no-ops; memcmp -> 0 ----
    lea  rdi, [rel kat_guard]               ; prime guard with 0x5A x8
    mov  esi, 0x5A
    mov  edx, 8
    call memset
    lea  rdi, [rel kat_guard]               ; zero-length copy must not touch it
    lea  rsi, [rel kat_hello]
    xor  edx, edx
    call memcpy
    cmp  byte [rel kat_guard], 0x5A
    setne al
    movzx eax, al
    add  r15, rax
    lea  rdi, [rel kat_guard]               ; zero-length memset must not touch it
    xor  esi, esi
    xor  edx, edx
    call memset
    cmp  byte [rel kat_guard], 0x5A
    setne al
    movzx eax, al
    add  r15, rax
    lea  rdi, [rel kat_guard]               ; zero-length memcmp -> equal (0)
    lea  rsi, [rel kat_hello]
    xor  edx, edx
    call memcmp
    test rax, rax
    setnz al
    movzx eax, al
    add  r15, rax

    mov  rax, r15                   ; fold region B, then emit the lib.mem.kat marker
    sub  rax, r12
    add  [rel kat_mem_fails], rax
    mov  rdi, [rel kat_mem_fails]
    lea  rsi, [rel str_km_mem_pass]
    call kat_group_marker

    ; ---- verdict (combined marker: additive, fires iff ALL groups clean) ----
    test r15, r15
    jz   .pass
    ; observable: log the failure count (TESTING §7) then emit FAIL.
    lea  rdi, [rel str_km_failpfx]          ; "failures="
    lea  rsi, [rel km_msgbuf]
    call fmt_str
    lea  rsi, [rel km_msgbuf]
    add  rsi, rax
    mov  rdi, r15
    call fmt_dec
    mov  rdi, LOG_ERR
    lea  rsi, [rel str_sub_km]
    lea  rdx, [rel km_msgbuf]
    call log_line
    lea  rdi, [rel str_km_fail]
    call serial_string
    jmp  .ret
.pass:
    mov  rdi, LOG_INF                        ; observable INF summary line
    lea  rsi, [rel str_sub_km]
    lea  rdx, [rel str_km_ready]
    call log_line
    lea  rdi, [rel str_km_pass]              ; the acceptance marker
    call serial_string
.ret:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ============================================================================
; lib_clobber_selftest (9703) — PROVE the register-clobber contract of the core/lib
; primitives. BOTH str+mem tournaments independently found the same latent bug: callers
; (fs/vfs) stash a LIVE value in r8 across `call memset`/`call strcpy_s`, so a primitive
; must touch ONLY the legacy scratch footprint (rax/rcx/rdx/rsi/rdi) — NEVER r8-r15 or
; the callee-saved rbx/rbp. A tournament 'fastest' variant broadcast through r8 (#GP);
; a 'durable' one clobbered r8 (fs/vfs cluster-ptr corruption); strcpy_s ITSELF used r8b
; until this task fixed it. This test makes the guarantee UNFAKEABLE: poison r8-r15/rbx/
; rbp with distinct sentinels, call each primitive with valid args, assert EVERY sentinel
; UNCHANGED after. A primitive that writes a forbidden reg makes the marker ABSENT (the
; negative gate: inject `mov r8,0` into memset and this test catches it -> marker gone).
; Behaviour is not exercised here (that's the KAT above) — only the clobber footprint.
; ============================================================================
%define LCS_R8  0x1181818181818118
%define LCS_R9  0x1291929192919129
%define LCS_R10 0x13A313A3A313A313
%define LCS_R11 0x14B414B4B414B414
%define LCS_R12 0x15C515C5C515C515
%define LCS_R13 0x16D616D6D616D616
%define LCS_R14 0x17E717E7E717E717
%define LCS_R15 0x18F818F8F818F818
%define LCS_RBX 0x19A919A9A919A919
%define LCS_RBP 0x1ABA1ABABA1ABA1A

; POISON — load every non-scratch reg with its sentinel. Uses only mov-imm64, so it
; never disturbs the arg regs (rdi/rsi/rdx/rcx) set up just before it.
%macro LCS_POISON 0
    mov  r8,  LCS_R8
    mov  r9,  LCS_R9
    mov  r10, LCS_R10
    mov  r11, LCS_R11
    mov  r12, LCS_R12
    mov  r13, LCS_R13
    mov  r14, LCS_R14
    mov  r15, LCS_R15
    mov  rbx, LCS_RBX
    mov  rbp, LCS_RBP
%endmacro

; lcs_check — assume r8-r15/rbx/rbp hold the sentinels; RAX = count of any that changed.
;   Scratch: RAX (holds each expected imm64, since cmp r64,imm64 doesn't exist), RCX
;   (setne), RDX (accumulator). Reads the tested regs only — never writes them.
lcs_check:
    xor  edx, edx
    mov  rax, LCS_R8
    cmp  r8, rax
    setne cl
    movzx ecx, cl
    add  rdx, rcx
    mov  rax, LCS_R9
    cmp  r9, rax
    setne cl
    movzx ecx, cl
    add  rdx, rcx
    mov  rax, LCS_R10
    cmp  r10, rax
    setne cl
    movzx ecx, cl
    add  rdx, rcx
    mov  rax, LCS_R11
    cmp  r11, rax
    setne cl
    movzx ecx, cl
    add  rdx, rcx
    mov  rax, LCS_R12
    cmp  r12, rax
    setne cl
    movzx ecx, cl
    add  rdx, rcx
    mov  rax, LCS_R13
    cmp  r13, rax
    setne cl
    movzx ecx, cl
    add  rdx, rcx
    mov  rax, LCS_R14
    cmp  r14, rax
    setne cl
    movzx ecx, cl
    add  rdx, rcx
    mov  rax, LCS_R15
    cmp  r15, rax
    setne cl
    movzx ecx, cl
    add  rdx, rcx
    mov  rax, LCS_RBX
    cmp  rbx, rax
    setne cl
    movzx ecx, cl
    add  rdx, rcx
    mov  rax, LCS_RBP
    cmp  rbp, rax
    setne cl
    movzx ecx, cl
    add  rdx, rcx
    mov  rax, rdx
    ret

; lib_clobber_selftest — out: "[PAOS64] ... [lib.clobber.contract.ok]" iff every primitive
;   preserved every sentinel. Running mismatch count lives in memory (lcs_fails) so no
;   register is stolen from the poison set. Callee-saved regs (rbx/rbp/r12-r15) are the
;   very ones under test, so save/restore them around the whole body.
lib_clobber_selftest:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  qword [rel lcs_fails], 0

    ; memcpy(dst, src, 6)
    lea  rdi, [rel lcs_buf]
    lea  rsi, [rel lcs_hello]
    mov  edx, 6
    LCS_POISON
    call memcpy
    call lcs_check
    add  [rel lcs_fails], rax

    ; memset(dst, 0xAB, 16)
    lea  rdi, [rel lcs_buf]
    mov  esi, 0xAB
    mov  edx, 16
    LCS_POISON
    call memset
    call lcs_check
    add  [rel lcs_fails], rax

    ; memcmp(buf, buf, 8) -> equal
    lea  rdi, [rel lcs_buf]
    lea  rsi, [rel lcs_buf]
    mov  edx, 8
    LCS_POISON
    call memcmp
    call lcs_check
    add  [rel lcs_fails], rax

    ; strlen(hello)
    lea  rdi, [rel lcs_hello]
    LCS_POISON
    call strlen
    call lcs_check
    add  [rel lcs_fails], rax

    ; strcmp(hello, hello) -> equal
    lea  rdi, [rel lcs_hello]
    lea  rsi, [rel lcs_hello]
    LCS_POISON
    call strcmp
    call lcs_check
    add  [rel lcs_fails], rax

    ; strcpy_s(buf2, hello, 32)  — the one that used to clobber r8
    lea  rdi, [rel lcs_buf2]
    lea  rsi, [rel lcs_hello]
    mov  edx, 32
    LCS_POISON
    call strcpy_s
    call lcs_check
    add  [rel lcs_fails], rax

    ; str_find("hello world", "world")
    lea  rdi, [rel lcs_world]
    lea  rsi, [rel lcs_needle]
    LCS_POISON
    call str_find
    call lcs_check
    add  [rel lcs_fails], rax

    ; ---- verdict ----
    mov  rax, [rel lcs_fails]
    test rax, rax
    jnz  .fail
    lea  rdi, [rel str_lcs_ok]
    call serial_string
    jmp  .ret
.fail:
    lea  rdi, [rel str_lcs_fail]
    call serial_string
.ret:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; lib_clobber_selftest data
lcs_buf:      times 32 db 0
lcs_buf2:     times 32 db 0
lcs_fails:    dq 0
lcs_hello:    db "hello", 0
lcs_world:    db "hello world", 0
lcs_needle:   db "world", 0
str_lcs_ok:   db "[PAOS64] core/lib clobber self-test: all primitives preserved r8-r15/rbx/rbp sentinels [lib.clobber.contract.ok]", 13, 10, 0
str_lcs_fail: db "[PAOS64] core/lib clobber self-test: FAIL a primitive clobbered a non-scratch reg [lib.clobber.contract.FAIL]", 13, 10, 0

; ============================================================================
; KAT data (in-image RW+X pre-BSS, MEMORY_MAP §3.1). Vectors store their strings
; INLINE, never `dq <label>`: a table is data, and a symbol address would bake in
; the assemble-time (org-0) VA — the load-VA hazard the whole tree avoids (MODULES
; G1: runtime lea, never dq <symbol>). Reached RIP-relative through r14.
; ============================================================================

; scratch/working buffers (a fresh copy per op; no test depends on another's state)
kat_scratch:  times 32 db 0
kat_dst:      times 32 db 0
kat_guard:    times 16 db 0
kat_ov:       times 8  db 0
km_msgbuf:    times 32 db 0
kat_mem_fails: dq 0                        ; lib.mem.kat accumulator (interleaved blocks)

; literals
kat_hello:      db "hello", 0
kat_hel:        db "hel", 0
kat_embed:      db "ab", 0, "cd", 0        ; a,b,0,c,d,0 — embedded NUL for memcpy
kat_haystack:   db "hello world", 0
kat_needle:     db "world", 0
kat_missing:    db "xyz", 0
kat_empty:      db 0
kat_ov_src:     db "ABCDEF", 0
kat_ov_expect:  db "AAAAAA", 0

str_sub_km:     db "lib", 0
str_km_ready:   db "str+mem KAT online", 0
str_km_failpfx: db "str+mem KAT failures=", 0
str_km_pass:    db "[PAOS64] P2 lib: str+mem KAT PASS", 13, 10, 0
str_km_fail:    db "[PAOS64] P2 lib: str+mem KAT FAIL", 13, 10, 0

; per-function known-answer markers (1098) — each fires ONLY if its group's
; reference-vector comparisons all passed (a wrong result -> group count > 0 ->
; marker absent). These are the per-primitive scorecard the core_lib tournament
; ranks correctness on (design §2.5); additive to the combined marker above.
str_km_strlen_pass: db "[PAOS64] P2 lib: strlen KAT PASS [lib.strlen.kat]", 13, 10, 0
str_km_strcmp_pass: db "[PAOS64] P2 lib: strcmp KAT PASS [lib.strcmp.kat]", 13, 10, 0
str_km_tourn_strcmp_kat: db "[PAOS64] P2 lib: strcmp tournament KAT PASS [tourn.strcmp.kat]", 13, 10, 0
str_km_memcmp_pass: db "[PAOS64] P2 lib: memcmp KAT PASS [lib.memcmp.kat]", 13, 10, 0
str_km_mem_pass:    db "[PAOS64] P2 lib: mem KAT PASS [lib.mem.kat]", 13, 10, 0
str_km_str_pass:    db "[PAOS64] P2 lib: str KAT PASS [lib.str.kat]", 13, 10, 0

; ---- strlen vectors. stride 24: +0 dw len, +2 dw rsvd, +4 inline str (<=19 ch) ----
%macro SLV 2
    dw %1
    dw 0
    %%s: db %2, 0
    times 20 - ($ - %%s) db 0
%endmacro
strlen_vectors:
    SLV 0,  ""
    SLV 1,  "x"
    SLV 3,  "abc"
    SLV 5,  "hello"
    SLV 11, "hello world"
strlen_vectors_end:

; ---- strcmp vectors. stride 32: +0 db sign, +1 pad(3), +4 a[14], +18 b[14] ----
%macro SCV 3
    db %1
    db 0, 0, 0
    %%a: db %2, 0
    times 14 - ($ - %%a) db 0
    %%b: db %3, 0
    times 14 - ($ - %%b) db 0
%endmacro
strcmp_vectors:
    SCV  0, "abc", "abc"            ; equal
    SCV -1, "abc", "abd"           ; a < b at last char
    SCV  1, "abd", "abc"           ; a > b at last char
    SCV -1, "ab",  "abc"           ; a is a proper prefix (a[2]=NUL < 'c')
    SCV  1, "abc", "ab"            ; b is a proper prefix
    SCV  0, "",    ""              ; both empty
    SCV -1, "",    "a"             ; empty < non-empty
strcmp_vectors_end:

; ---- memcmp vectors. stride 28: +0 db sign, +1 db len, +2 dw0, +4 a[12], +16 b[12] ----
%macro MCV 4
    db %1
    db %2
    dw 0
    %%a: db %3, 0
    times 12 - ($ - %%a) db 0
    %%b: db %4, 0
    times 12 - ($ - %%b) db 0
%endmacro
memcmp_vectors:
    MCV  0, 3, "abc", "abc"        ; equal
    MCV -1, 3, "abc", "abd"        ; a < b
    MCV  1, 3, "abd", "abc"        ; a > b
    MCV  1, 2, "az",  "ay"         ; a > b at idx 1
    MCV  0, 5, "ab",  "ab"         ; NUL edge: compares a,b,0,0,0 across the NUL
    MCV  0, 0, "xy",  "zw"         ; zero-length -> equal regardless of content
memcmp_vectors_end:
