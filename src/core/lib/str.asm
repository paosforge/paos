;; MODULE core/lib/str
;; LAYER 1
;; EXPORTS strlen, strcmp, strcpy_s, str_find, lib_selftest
;; IMPORTS core/lib/mem, boot/serial
;; CAPS
;; OWNER saga:core
; ============================================================================
; core/lib/str.asm — the ONE canonical string primitives (G1, MODULES §3):
; strlen / strcmp / strcpy_s (bounded copy) / str_find (substring), plus the
; core/lib self-test. The monolith scattered ~111 str variants (dns_strcmp,
; sheet_strcpy_max, capi_strstr, ui_strlen, ...); here there is exactly one of
; each, and modlint's primitive denylist (*str(len|cmp|cpy|cat|chr|nlen)*) FAILS
; the build on any second variant defined outside core/lib/. Never again.
;
; CLOBBER CONTRACT (9703 — stricter than SysV, this is what callers depend on):
; every primitive here touches ONLY the legacy scratch footprint RAX/RCX/RDX/RSI/RDI
; and NEVER r8-r15 or the callee-saved rbx/rbp. fs/vfs keeps a live cluster ptr in r8
; across `call memset`/`call strcpy_s`; a primitive that writes any of r8-r15/rbx/rbp
; silently corrupts the caller. lib_clobber_selftest (strmem_kat.asm) proves it every
; boot by poisoning those regs and asserting they survive each call.
;
; TOURNAMENT (TESTING §7, correct>simple>fast>small>observable). The hot ones,
; graded against the strmem KAT table (core/lib/strmem_kat.asm):
;  * strlen: (A) byte scan to NUL  (B) 8-byte SWAR zero-detect  (C) rep scasb.
;    WINNER A — correct + simplest + zero setup; the callers here format short
;    strings, so (B)'s word-at-a-time win never pays for its tail-mask/alignment
;    complexity. Revisit only if a profile shows strlen hot on long buffers.
;  * strcmp: (A) byte compare, branch on diff/NUL  (B) SWAR word compare.
;    WINNER A — correct + simplest; returns the signed a[i]-b[i] at the first
;    difference (sign is the contract the KAT grades, not just equal/not-equal).
;  * strcpy_s: (A) bounded byte copy, always NUL-terminate  (B) strlen-then-memcpy
;    (double scan; over-copies on a size cap)  (C) rep movsb + fixups. WINNER A —
;    single pass, honours the destination-size cap, ALWAYS terminates (the safety
;    the monolith's fed_strcpy/https_strcpy lacked). No new copy loop leaks out.
;  * str_find: (A) naive O(n*m) scan  (B) two-way / KMP  (C) SIMD first-byte.
;    WINNER A — correct + simplest; needles here are short literals so KMP's
;    preprocess never pays off. Distilled from the monolith's capi_strstr, but
;    returns a POINTER (or 0), not a bool — more useful, still KAT-graded.
; ============================================================================

; strlen(RDI=str) -> RAX=len          ; clobbers: RAX only (rdi push/pop-preserved)
strlen:
    push rdi
    xor  eax, eax
.scan:
    cmp  byte [rdi], 0
    je   .done
    inc  rdi
    jmp  .scan
.done:
    mov  rax, rdi
    pop  rdi
    sub  rax, rdi
    ret

; strcmp(RDI=a, RSI=b) -> RAX = 0 if equal, else a[i]-b[i] at first diff
;   clobbers: RAX,RCX,RDI,RSI — no r8-r15/rbx/rbp. The 2nd byte rides CL/RCX (a
;   legacy caller-saved scratch strcpy_s already clobbers), so there is NO stack
;   traffic. The equal-terminator exit is folded into .diff: at the shared NUL both
;   bytes are 0, so movzx/movzx/sub yields 0 — one exit, fewer instrs, smaller body.
;   lib.clobber.contract asserts r8-r15/rbx/rbp only, so rcx use stays green.
strcmp:
.cmp:
    mov  al, [rdi]
    mov  cl, [rsi]
    cmp  al, cl
    jne  .diff
    test al, al
    je   .diff                 ; equal at NUL: al=cl=0 -> sub below = 0
    inc  rdi
    inc  rsi
    jmp  .cmp
.diff:
    movzx eax, al
    movzx ecx, cl
    sub  eax, ecx
    ret

; strcpy_s(RDI=dst, RSI=src, RDX=dstsize) -> RAX = bytes copied (excl NUL)
;   Bounded, always-terminating copy: writes at most dstsize-1 chars of src then a
;   NUL. dstsize is the FULL destination buffer size (incl the NUL slot); dstsize=0
;   writes nothing and returns 0. RAX = min(strlen(src), dstsize-1). The safe
;   replacement for the monolith's unbounded fed_strcpy/https_strcpy.
;   CLOBBER CONTRACT (9703): touches only RAX,RCX,RDX (rdx=dstsize is consumed into
;   the rcx budget first, then reused as the copy scratch). NEVER r8-r15/rbx/rbp —
;   fs/vfs stashes a live cluster ptr in r8 across this call; using r8b here (the
;   pre-9703 code did) silently corrupted it. Enforced by lib_clobber_selftest.
strcpy_s:
    test rdx, rdx
    jz   .zero                      ; no room even for a NUL -> nothing to do
    xor  rax, rax                   ; bytes copied
    lea  rcx, [rdx - 1]             ; budget = dstsize - 1 (reserve the NUL slot)
.copy:
    test rcx, rcx
    jz   .term                      ; cap reached -> truncate + terminate
    mov  dl, [rsi + rax]            ; scratch in RDX (legacy footprint) — NOT r8
    test dl, dl
    jz   .term                      ; source NUL -> done
    mov  [rdi + rax], dl
    inc  rax
    dec  rcx
    jmp  .copy
.term:
    mov  byte [rdi + rax], 0        ; ALWAYS terminate within the buffer
    ret
.zero:
    xor  eax, eax
    ret

; str_find(RDI=haystack, RSI=needle) -> RAX = ptr to first match, or 0 if absent
;   C strstr semantics: an empty needle matches at the start (returns haystack).
;   Naive O(n*m) scan (needles are short literals here — TOURNAMENT B above).
;   clobbers: RAX,RCX,RDI (rbx push/pop-preserved) — no r8-r15/rbp
str_find:
    push rbx
    cmp  byte [rsi], 0              ; empty needle -> match at haystack
    je   .match
.outer:
    xor  rcx, rcx                   ; needle index
.inner:
    mov  bl, [rsi + rcx]            ; needle char
    test bl, bl
    jz   .match                     ; walked the whole needle -> full match at rdi
    mov  al, [rdi + rcx]            ; haystack char
    test al, al
    jz   .notfound                  ; haystack ended mid-needle
    cmp  al, bl
    jne  .advance
    inc  rcx
    jmp  .inner
.advance:
    inc  rdi                        ; slide the window one char right
    cmp  byte [rdi], 0
    jne  .outer                     ; more haystack to try
.notfound:
    xor  eax, eax
    pop  rbx
    ret
.match:
    mov  rax, rdi
    pop  rbx
    ret

; lib_selftest — exercise mem + str, emit a marker (verify-everything-every-boot)
lib_selftest:
    lea  rdi, [rel lib_buf]         ; memset 16 bytes to 0xAB
    mov  esi, 0xAB
    mov  edx, 16
    call memset
    cmp  byte [rel lib_buf], 0xAB
    jne  .fail
    lea  rdi, [rel lib_buf]         ; memcpy "hello\0"
    lea  rsi, [rel lib_hello]
    mov  edx, 6
    call memcpy
    lea  rdi, [rel lib_buf]         ; strlen == 5
    call strlen
    cmp  rax, 5
    jne  .fail
    lea  rdi, [rel lib_buf]         ; strcmp equal
    lea  rsi, [rel lib_hello]
    call strcmp
    test rax, rax
    jnz  .fail
    lea  rdi, [rel lib_buf]         ; memcmp equal
    lea  rsi, [rel lib_hello]
    mov  edx, 6
    call memcmp
    test rax, rax
    jnz  .fail
    lea  rdi, [rel str_lib_ok]
    call serial_string
    ret
.fail:
    lea  rdi, [rel str_lib_fail]
    call serial_string
    ret

lib_buf:      times 32 db 0
lib_hello:    db "hello", 0
str_lib_ok:   db "[PAOS64] M1 core/lib: mem+str primitives OK", 13, 10, 0
str_lib_fail: db "[PAOS64] M1 core/lib: FAILED", 13, 10, 0
