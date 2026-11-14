;; MODULE core/lib/mem
;; LAYER 1
;; EXPORTS memcpy, memset, memcmp
;; IMPORTS
;; CAPS
;; OWNER saga:core
; ============================================================================
; core/lib/mem.asm — the ONE canonical memcpy/memset/memcmp (G1, MODULES §3).
; The current tree has ~111 scattered copies of these; here there is exactly one,
; and modlint's primitive denylist FAILS the build on any `*memcpy*`/`*memset*`
; defined outside core/lib/. SysV internal ABI; DF assumed 0 but cld'd to be safe.
;
; CLOBBER CONTRACT (9703 — stricter than SysV): memcpy/memset/memcmp touch ONLY the
; legacy scratch footprint RAX/RCX/RDX/RSI/RDI, NEVER r8-r15 or callee-saved rbx/rbp.
; fs/vfs keeps a live cluster ptr in r8 across `call memset`; a rewrite that broadcasts
; through r8 (a tournament variant did) silently corrupts it. lib_clobber_selftest
; (strmem_kat.asm) poisons r8-r15/rbx/rbp and asserts they survive every primitive.
;
; TOURNAMENT (TESTING §7, correct>simple>fast>small>observable). Graded against
; the strmem KAT table (core/lib/strmem_kat.asm):
;  * memcpy: (A) rep movsb  (B) 8-byte movsq + byte tail  (C) SSE/AVX streaming.
;    WINNER A — correct + smallest; on every CPU PaOS targets `rep movsb` is
;    ERMSB-accelerated, so (B)/(C)'s bulk win is marginal and their tail/alignment
;    handling is pure risk. HAZARD (KAT negative): forward-only — NOT overlap-safe.
;    Overlapping dst>src duplicates; callers that overlap need a memmove (future).
;  * memset: (A) rep stosb  (B) rax-broadcast rep stosq + tail. WINNER A — same
;    ERMSB reasoning; correct + smallest, no broadcast/tail bookkeeping.
;  * memcmp: (A) repe cmpsb + recover a[i]-b[i] from the pointers  (B) SWAR word
;    compare then narrow. WINNER A — correct + simplest, and it yields the SIGNED
;    first-difference (the sign is the contract the KAT grades). Reads exactly RDX
;    bytes: NUL-agnostic (unlike strcmp), which the KAT's NUL-edge row proves.
; ============================================================================

; memcpy(RDI=dst, RSI=src, RDX=len) -> RAX=dst
;   clobbers: RAX,RCX,RSI,RDI (rdi push/pop-restored to dst into RAX) — no r8-r15/rbx/rbp
memcpy:
    cld
    push rdi
    mov  rcx, rdx
    rep  movsb
    pop  rax
    ret

; memset(RDI=dst, RSI=byte, RDX=len) -> RAX=dst
;   clobbers: RAX,RCX,RSI,RDI — no r8-r15/rbx/rbp
memset:
    cld
    push rdi
    mov  rcx, rdx
    mov  rax, rsi                   ; AL = fill byte
    rep  stosb
    pop  rax
    ret

; memcmp(RDI=a, RSI=b, RDX=len) -> RAX = 0 if equal, else (a[i]-b[i]) at first diff
;   clobbers: RAX,RCX,RDX,RSI,RDI — no r8-r15/rbx/rbp
memcmp:
    cld
    mov  rcx, rdx
    repe cmpsb
    je   .equal
    movzx eax, byte [rdi - 1]
    movzx edx, byte [rsi - 1]
    sub  eax, edx
    ret
.equal:
    xor  eax, eax
    ret
