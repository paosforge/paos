;; MODULE cognition/tokenize_ascii
;; LAYER 6
;; EXPORTS cog_tokenize_ascii_advisory
;; IMPORTS
;; CAPS
;; OWNER saga:cognition
; RCQ-25 native text-to-ID seam, not a semantic classifier or calibrated model.
; Caller supplies an authenticated immutable PVT1 vocabulary, readable mapped
; text/table, and writable output held alive throughout the synchronous call.
; Structural checks do NOT authenticate a table or establish page permissions.
; No I/O, allocation, SIMD/XSAVE requirement, policy action or authority grant.
;
; SysV: RDI text, RSI text bytes (0..4096), RDX PVT1, RCX table bytes
;       (20..8MiB), R8 output u32 IDs, R9 capacity in IDs (2..512).
; Return EAX: 2..512 IDs including CLS/SEP; -1 invalid/unsupported input/table;
; -2 insufficient output capacity; -3 context longer than 4096 bytes/510 body IDs.
; All negative results leave output untouched. Output must be 4-aligned,
; non-null, non-wrapping and disjoint from text and table over its full capacity.
; Empty text still requires a non-null pointer but does not read text bytes.
; ASCII only: space/TAB/LF/CR, printable bytes, fixed BGE special-token IDs.
; Other controls/DEL/non-ASCII refuse; unknown words map to authenticated UNK.
; Config-free scalar kernels from paos_classifier4850e3f1 are included verbatim
; from their entry labels; .inc headers record upstream file and body hashes.
; The upstream request kernel stages all IDs on stack before copying to output.
; Preserves SysV callee-saved registers. Bounded call-stack use <3KiB.

cog_tokenize_ascii_advisory:
    push rbx
    mov  rbx, r8
    test rdi, rdi
    jz   .invalid
    test rdx, rdx
    jz   .invalid
    test rbx, rbx
    jz   .invalid
    test bl, 3
    jnz  .invalid
    cmp  rsi, 4096
    ja   .too_long
    cmp  rcx, 20
    jb   .invalid
    cmp  rcx, 8388608
    ja   .invalid
    cmp  r9, 2
    jb   .invalid
    cmp  r9, 512
    ja   .invalid
    lea  r10, [r9*4]
    add  r10, rbx                 ; output end; capacity multiplication bounded
    jc   .invalid
    mov  rax, rdi
    add  rax, rsi
    jc   .invalid
    test rsi, rsi                 ; empty range cannot overlap
    jz   .table_range
    cmp  rax, rbx
    jbe  .table_range
    cmp  rdi, r10
    jb   .invalid
.table_range:
    mov  rax, rdx
    add  rax, rcx
    jc   .invalid
    cmp  rax, rbx
    jbe  .ready
    cmp  rdx, r10
    jb   .invalid
.ready:
    call paos_tokenize_ascii      ; original six arguments preserved
    pop  rbx
    ret
.too_long:
    mov  eax, -3
    pop  rbx
    ret
.invalid:
    mov  eax, -1
    pop  rbx
    ret

%include "cognition/vocab_lookup_kernel.inc"
%include "cognition/wordpiece_ascii_kernel.inc"
%include "cognition/tokenize_ascii_kernel.inc"
