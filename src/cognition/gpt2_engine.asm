;; MODULE cognition/gpt2_engine
;; LAYER 6
;; EXPORTS cog_declare, cmd_verb_modelrun, cmd_verb_modelout, cmd_verb_modelkat, cog_out_buf, cog_out_cur, cog_out_ready, str_cog_sha_value
;; IMPORTS boot/model_preload, core/smp, cognition/inference_scaling, boot/serial, core/heap, core/lib/fmt, core/lib/sha256, core/lib/str, dev/blk/ahci, fs/fat32_disk, fs/vfs, svc/command, svc/command_ai_file, cognition/ai_intent_controller
;; CAPS
;; OWNER saga:cognition
; ===========================================================================
; cognition/gpt2_engine.asm — C12 cognition: the local LLM inference tile (1061,
; COGNITION.md §2/§3 subconscious tier). PORTED (M16 port-don't-reinvent) from the
; proven recipe ../../paos/recipes/cpu_llm_distilgpt2 (M1-M5 QEMU-green, token-
; identical to HuggingFace):
;   - fp32 math + SIMD matmul + causal softmax + LayerNorm   (monolith fp32 cluster)
;   - PXG2 GPT-2 forward engine + KV-cache generate           (recipe engine module)
; The numeric kernel is UNCHANGED proven code (gelu_accurate, scale 0.125, eps 1e-5,
; Conv1D [in,out], tied head); only the SEAM is adapted (rework kmalloc/serial + the
; registry-verb tile surface).
;
; v1 deliverable: load the real distilgpt2 (PXG2) + run ONE forward pass -> next-token
; argmax, content-graded vs the HuggingFace oracle. Reference prompt "The capital of
; France is" (oracle BPE ids 464 3139 286 4881 318) -> argmax 262 (" the"). Surfaced
; as MODELRUN / MODELOUT / MODELKAT registry verbs (COMMANDS.md §1 single vocabulary).
;
; Native boot adopts the fixed-pin, owner-bound read-only data-volume preload.
; Failure of that pre-EBS attempt refuses inference without disk or fixed-address
; fallback. The raw QEMU injection and historical AHCI descriptor loader below
; remain isolated HOST fixtures only when no native boot attempt ran.
; ===========================================================================

%include "cognition-model-identity.inc"
%include "cognition/model_artifact.inc"
; Old descriptor includes retain the enabled behavior byte-for-byte. Public
; disabled includes define only this mode and contain no identity placeholders.
%ifndef COG_MODEL_ENABLED
%ifdef PAOS_PUBLIC_BUILD
%if PAOS_PUBLIC_BUILD != 0
%error "public build requires explicit COG_MODEL_ENABLED"
%endif
%endif
%define COG_MODEL_ENABLED 1
%endif
%ifdef PAOS_PUBLIC_BUILD
%if PAOS_PUBLIC_BUILD != 0 && COG_MODEL_ENABLED != 0
%error "public build requires COG_MODEL_ENABLED=0"
%endif
%endif
%if COG_MODEL_ENABLED != 0 && COG_MODEL_ENABLED != 1
%error "COG_MODEL_ENABLED must be 0 or 1"
%endif

; ---- serial number/hex shims (rework boot/serial has only char/string/newline;
;      these are the monolith's, DIL/EDI-compatible with rework serial_char) --------
; serial_decimal — print RDI as unsigned decimal (no newline).
; Tournament 1306 v2 (FAST): division-free — q = n/10 via reciprocal multiply
; ((n * 0xCCCCCCCCCCCCCCCD) >> 67, the exact u64/10 codegen GCC/Clang emit,
; correct for ALL 2^64 inputs; the boot KAT locks the pow10 boundaries where
; a wrong reciprocal would first show). ~4 cycles/digit vs 30-90 for the DIV
; it replaces; digits leave via ONE serial_string call, not per-digit I/O.
; sd_format: RDI=value, RSI=buffer end (exclusive); writes digits backwards
; (max 20), returns RAX = first digit. Clobbers RCX, RDX, RDI, RSI.
sd_format:
    mov  rax, rdi
    mov  rdi, 0xCCCCCCCCCCCCCCCD
.sf_digit:
    mov  rcx, rax                ; rcx = n
    mul  rdi                     ; rdx = hi64(n * reciprocal)
    shr  rdx, 3                  ; rdx = q = n/10
    lea  rax, [rdx + rdx*4]
    add  rax, rax                ; rax = q*10
    sub  rcx, rax                ; rcx = n - q*10 = digit 0..9
    add  cl, '0'
    dec  rsi
    mov  [rsi], cl
    mov  rax, rdx                ; n = q
    test rax, rax
    jnz  .sf_digit
    mov  rax, rsi
    ret

serial_decimal:
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    sub  rsp, 24                 ; digits land in [rsp..rsp+20)
    lea  rsi, [rsp + 20]
    mov  byte [rsi], 0
    call sd_format
    mov  rdi, rax
    call serial_string
    add  rsp, 24
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rax
    ret

; serial_hex_nibble — print DIL's low nibble as one hex digit.
serial_hex_nibble:
    push rdi
    and  dil, 0x0F
    cmp  dil, 10
    jb   .shn_digit
    add  dil, 'A' - 10
    jmp  .shn_print
.shn_digit:
    add  dil, '0'
.shn_print:
    call serial_char
    pop  rdi
    ret

; serial_hex32 — print EDI as "0x" + 8 hex nibbles.
serial_hex32:
    push rdi
    push rbx
    push rcx
    mov  ebx, edi
    mov  dil, '0'
    call serial_char
    mov  dil, 'x'
    call serial_char
    mov  ecx, 8
.sh_loop:
    rol  ebx, 4
    mov  dil, bl
    call serial_hex_nibble
    dec  ecx
    jnz  .sh_loop
    pop  rcx
    pop  rbx
    pop  rdi
    ret

; --- tournament 1306 KAT + guard + perf: vectors that break a WRONG reciprocal
;     (pow10 boundary, interior zeros, 2^32 seam, all-9s 10^19-1, u64-max = full
;     20 digits) + an underrun canary under the widest write. Any miss withholds
;     ALL markers and emits .fail; perf is measured only after correctness holds.
serial_decimal_kat:
    push rbx
    push r12
    lea  rbx, [rel sd_kat_vals]
    lea  r12, [rel sd_kat_expect]
    mov  r8d, 6                  ; vector count
.sk_vec:
    mov  rdi, [rbx]
    lea  rsi, [rel sd_kat_buf + 20]
    mov  byte [rsi], 0
    call sd_format               ; RAX = digits (NUL-terminated above)
.sk_cmp:
    mov  cl, [rax]
    cmp  cl, [r12]
    jne  .sk_fail
    inc  rax
    inc  r12
    test cl, cl
    jnz  .sk_cmp                 ; NUL matched -> r12 at next expected
    add  rbx, 8
    dec  r8d
    jnz  .sk_vec
    cmp  byte [rel sd_kat_canary], 0x5A  ; u64-max wrote EXACTLY 20B
    jne  .sk_fail
    ; fast-claim evidence: rdtsc over 1000 20-digit formats (engine only, no
    ; UART in the timed window); one line = PASS + all 3 tokens + cycles.
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  rbx, rax
    mov  r8d, 1000
.sk_perf:
    mov  rdi, -1                 ; 2^64-1: 20 digits, worst case
    lea  rsi, [rel sd_kat_buf + 20]
    call sd_format
    dec  r8d
    jnz  .sk_perf
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    sub  rax, rbx
    mov  rbx, rax
    lea  rdi, [rel str_sd_kat_ok]
    call serial_string
    mov  rdi, rbx
    call serial_decimal          ; proven by the vectors that just passed
    lea  rdi, [rel str_sd_kat_tail]
    call serial_string
    jmp  .sk_out
.sk_fail:
    lea  rdi, [rel str_sd_kat_fail]
    call serial_string
.sk_out:
    pop  r12
    pop  rbx
    ret

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_cognition_gpt2_engine_0 0
sd_kat_canary: db 0x5A
sd_kat_buf:    times 21 db 0
sd_kat_vals:   dq 0, 10, 1002003, 4294967296, 0x8AC7230489E7FFFF, -1
sd_kat_expect: db "0",0,"10",0,"1002003",0,"4294967296",0,"9999999999999999999",0,"18446744073709551615",0
str_sd_kat_ok:   db "[PAOS64] M16 cognition: serial_decimal KAT+GUARD PASS (pow10/2^32 seam/all-9s/u64-max, canary intact, div-free) [tourn.serial_decimal.kat] [tourn.serial_decimal.guard] PERF 1000x 20-digit formats cycles=", 0
str_sd_kat_tail: db " [tourn.serial_decimal.perf]", 13, 10, 0
str_sd_kat_fail: db "[PAOS64] M16 cognition: serial_decimal KAT/GUARD FAIL [tourn.serial_decimal.kat.fail]", 13, 10, 0
%endmacro
WDATA_DEFER WDATA_cognition_gpt2_engine_0

; Classic-compatible name retained at the port seam; all reads route through the
; rework VFS mount handle and its read-only physical FAT32 backend.
fat32_readfile_path:
    jmp  vfs_readfile_path
fp32_add:
    addss xmm0, xmm1
    ret

; fp32_sub: XMM0 = XMM0 - XMM1 (scalar float)
fp32_sub:
    subss xmm0, xmm1
    ret

; fp32_mul: XMM0 = XMM0 * XMM1 (scalar float)
fp32_mul:
    mulss xmm0, xmm1
    ret

; fp32_div: XMM0 = XMM0 / XMM1 (scalar float)
fp32_div:
    divss xmm0, xmm1
    ret

; fp32_abs: XMM0 = |XMM0| (scalar float)
;   Clears sign bit using AND mask
fp32_abs:
    andps xmm0, [rel fp32_abs_mask]
    ret

; fp32_neg: XMM0 = -XMM0 (scalar float)
;   Flips sign bit using XOR mask
fp32_neg:
    xorps xmm0, [rel fp32_sign_mask]
    ret

; fp32_exp_approx: XMM0 = exp(XMM0) (scalar float, polynomial approximation)
;   Uses range reduction: exp(x) = 2^(x * log2(e))
;   Then 2^f for f in [-0.5, 0.5] via degree-4 minimax polynomial
;   Accurate to ~1e-4 for |x| < 10
fp32_exp_approx:
    push rbx
    sub rsp, 16                         ; Local storage

    ; t = x * log2(e)
    mulss xmm0, [rel fp32_log2e]

    ; n = round(t) — use cvtss2si (rounds to nearest by default) then back
    cvtss2si eax, xmm0                 ; Round to nearest integer
    cvtsi2ss xmm1, eax                 ; Convert back to float = n

    ; f = t - n — fractional part in [-0.5, 0.5]
    movss xmm2, xmm0
    subss xmm2, xmm1                   ; xmm2 = f
    add eax, 127                        ; IEEE754 bias
    cmp eax, 255
    jge .exp_overflow
    cmp eax, 0
    jle .exp_underflow

    shl eax, 23                         ; Place in exponent field
    movd xmm3, eax                      ; xmm3 = 2^n as float

    ; Polynomial: p(f) = c0 + f*(c1 + f*(c2 + f*(c3 + f*c4)))
    ; Horner's method
    movss xmm0, [rel fp32_exp_c4]
    mulss xmm0, xmm2
    addss xmm0, [rel fp32_exp_c3]
    mulss xmm0, xmm2
    addss xmm0, [rel fp32_exp_c2]
    mulss xmm0, xmm2
    addss xmm0, [rel fp32_exp_c1]
    mulss xmm0, xmm2
    addss xmm0, [rel fp32_exp_c0]

    ; Result = p(f) * 2^n
    mulss xmm0, xmm3

    add rsp, 16
    pop rbx
    ret

.exp_overflow:
    movss xmm0, [rel fp32_inf]
    add rsp, 16
    pop rbx
    ret

.exp_underflow:
    xorps xmm0, xmm0                   ; Return 0.0
    add rsp, 16
    pop rbx
    ret

; fp32_sigmoid: XMM0 = 1 / (1 + exp(-x))
;   Uses fp32_exp_approx internally
fp32_sigmoid:
    push rbx

    ; Negate x
    xorps xmm0, [rel fp32_sign_mask]   ; xmm0 = -x

    ; exp(-x)
    call fp32_exp_approx

    ; 1 + exp(-x)
    addss xmm0, [rel fp32_one]

    ; 1 / (1 + exp(-x))
    movss xmm1, [rel fp32_one]
    divss xmm1, xmm0
    movss xmm0, xmm1

    pop rbx
    ret

; fp32_tanh: XMM0 = tanh(x) = 2*sigmoid(2x) - 1
;   Uses fp32_sigmoid internally
fp32_tanh:
    push rbx

    ; 2x
    addss xmm0, xmm0

    ; sigmoid(2x)
    call fp32_sigmoid

    ; 2 * sigmoid(2x)
    addss xmm0, xmm0

    ; 2 * sigmoid(2x) - 1
    subss xmm0, [rel fp32_one]

    pop rbx
    ret

; fp32_dot4: XMM0 = dot product of two 4-element float vectors
;   RDI = pointer to vector A (4 floats, 16 bytes, should be 16-byte aligned)
;   RSI = pointer to vector B (4 floats, 16 bytes, should be 16-byte aligned)
;   Returns: XMM0 = A[0]*B[0] + A[1]*B[1] + A[2]*B[2] + A[3]*B[3]
fp32_dot4:
    movups xmm0, [rdi]                 ; Load A (use unaligned for safety)
    movups xmm1, [rsi]                 ; Load B
    mulps xmm0, xmm1                   ; Element-wise multiply
    ; Horizontal sum: xmm0 = [a0*b0, a1*b1, a2*b2, a3*b3]
    movaps xmm1, xmm0
    shufps xmm1, xmm1, 0x4E           ; [a2*b2, a3*b3, a0*b0, a1*b1]
    addps xmm0, xmm1                   ; [a0b0+a2b2, a1b1+a3b3, ...]
    movaps xmm1, xmm0
    shufps xmm1, xmm1, 0xB1           ; Swap pairs
    addss xmm0, xmm1                   ; Final sum in xmm0[0]
    ret

; fp32_vec4_add: Element-wise add of 4-float vectors
;   RDI = pointer to dst/A, RSI = pointer to B
;   Result stored in [RDI]
fp32_vec4_add:
    movups xmm0, [rdi]
    movups xmm1, [rsi]
    addps xmm0, xmm1
    movups [rdi], xmm0
    ret

; fp32_vec4_mul: Element-wise multiply of 4-float vectors
;   RDI = pointer to dst/A, RSI = pointer to B
;   Result stored in [RDI]
fp32_vec4_mul:
    movups xmm0, [rdi]
    movups xmm1, [rsi]
    mulps xmm0, xmm1
    movups [rdi], xmm0
    ret

; fp32_serial_print: Print a float value to serial as "integer.fraction"
;   XMM0 = float value to print
;   Prints sign, integer part, decimal point, 4 fractional digits
;   TOURNAMENT 1309 most-durable variant: the proven normal-value path below
;   is byte-for-byte UNCHANGED; durability is added by containment. NaN, +/-Inf
;   and |x| >= 2^31 all used to fall into cvttss2si's indefinite (0x80000000)
;   and print 10+ garbage digits into every log line; they are now classified
;   from the raw bits BEFORE any conversion and degrade to short fixed tokens
;   (nan / [-]inf / [-]ovf — sign-honest for inf/ovf, sign-agnostic for NaN).
fp32_serial_print:
    push rbx
    push r12
    sub rsp, 8                          ; Align stack

    ; Contain non-finite / non-representable inputs (see header comment)
    movd eax, xmm0
    mov  ecx, eax
    and  ecx, 0x7FFFFFFF                ; drop sign for the class compare
    cmp  ecx, 0x7F800000
    ja   .fsp_nan                       ; NaN, any payload, either sign
    je   .fsp_inf                       ; +/- infinity
    cmp  ecx, 0x4F000000                ; 2^31 as fp32
    jae  .fsp_ovf                       ; int part outside int32 (incl -2^31,
                                        ; contained too: symmetric bound)

    ; Check sign
    movd eax, xmm0
    test eax, 0x80000000
    jz .fsp_positive
    mov dil, '-'
    call serial_char
    andps xmm0, [rel fp32_abs_mask]    ; Make positive
.fsp_positive:

    ; Integer part
    cvttss2si r12d, xmm0               ; Truncate to int
    movsx rdi, r12d
    call serial_decimal

    ; Decimal point
    mov dil, '.'
    call serial_char

    ; Fractional part: multiply by 10000, get integer
    cvtsi2ss xmm1, r12d                ; Convert int back to float
    subss xmm0, xmm1                   ; Get fractional part
    mulss xmm0, [rel fp32_10000]       ; Scale up
    cvttss2si eax, xmm0                ; Get as integer

    ; Ensure positive
    test eax, eax
    jns .fsp_frac_pos
    neg eax
.fsp_frac_pos:
    ; Clamp: frac is provably 0..9999 for finite inputs, but a 5th digit from
    ; any future rounding drift would corrupt every log line — contain it
    cmp eax, 9999
    jbe .fsp_frac_ok
    mov eax, 9999
.fsp_frac_ok:

    ; Print with leading zeros (4 digits)
    mov ebx, eax
    mov ecx, 1000
.fsp_digit_loop:
    xor edx, edx
    mov eax, ebx
    div ecx                             ; eax = digit, edx = remainder
    mov ebx, edx
    add al, '0'
    movzx edi, al
    push rcx
    call serial_char
    pop rcx
    ; Divide divisor by 10
    mov eax, ecx
    xor edx, edx
    mov ecx, 10
    div ecx
    mov ecx, eax
    test ecx, ecx
    jnz .fsp_digit_loop

.fsp_done:
    add rsp, 8
    pop r12
    pop rbx
    ret

; Contained edge exits: bounded fixed tokens, degrade never garbage. RBX is
; saved by the prologue; serial_char/serial_string preserve it.
.fsp_nan:
    lea  rbx, [rel str_fsp_nan]
    jmp  .fsp_tok
.fsp_inf:
    lea  rbx, [rel str_fsp_inf]
    jmp  .fsp_sgn
.fsp_ovf:
    lea  rbx, [rel str_fsp_ovf]
.fsp_sgn:
    test eax, eax                       ; sign bit of the original value
    jns  .fsp_tok
    mov  dil, '-'
    call serial_char
.fsp_tok:
    mov  rdi, rbx
    call serial_string
    jmp  .fsp_done

; --- tournament 1309 (most-durable): KAT + edge-containment GUARD + PERF ---
; The regression harness is the byte-for-byte comparator (an instrument the
; kernel doesn't control): the KAT and GUARD marker lines registered in
; regression_tests.txt embed the full EXPECTED bytes. One wrong output byte
; on the normal path (7 exact-fp32 vectors) OR on the contained edge path
; (nan inf -inf ovf -ovf) and the marker never matches -> variant scores 0.
fp32_print_kat:
    push rbx
    push r12
    ; KAT: 7 exact vectors (sign, zero, leading-zero fraction, sixteenths)
    lea  rdi, [rel str_fsp_kat_pre]
    call serial_string
    xor  ebx, ebx
.fpk_vec:
    lea  rax, [rel fsp_kat_vals]
    movss xmm0, [rax + rbx*4]
    call fp32_serial_print
    mov  dil, ' '
    call serial_char
    inc  ebx
    cmp  ebx, 7
    jb   .fpk_vec
    lea  rdi, [rel str_fsp_kat_tail]
    call serial_string
    ; GUARD: feed every contained class LIVE through the real function
    ; (QNaN, +Inf, -Inf, 3e9 and -3e9 >= 2^31) — graded like the KAT
    lea  rdi, [rel str_fsp_guard_pre]
    call serial_string
    xor  ebx, ebx
.fpk_edge:
    lea  rax, [rel fsp_edge_vals]
    movss xmm0, [rax + rbx*4]
    call fp32_serial_print
    mov  dil, ' '
    call serial_char
    inc  ebx
    cmp  ebx, 5
    jb   .fpk_edge
    lea  rdi, [rel str_fsp_guard_tail]
    call serial_string
    ; PERF: rdtsc over 64 REAL prints (engine + UART = the felt cost) of the
    ; widest KAT value; 64 iterations bounds bare-metal boot cost (<100ms)
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  rbx, rax
    mov  r12d, 64
.fpk_perf:
    movss xmm0, [rel fsp_kat_vals + 24] ; 32000.5
    call fp32_serial_print
    dec  r12d
    jnz  .fpk_perf
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    sub  rax, rbx
    mov  rbx, rax                       ; cycles delta survives serial_string
    lea  rdi, [rel str_fsp_perf_pre]
    call serial_string
    mov  rdi, rbx
    call serial_decimal
    lea  rdi, [rel str_fsp_perf_tail]
    call serial_string
    pop  r12
    pop  rbx
    ret

fsp_kat_vals:                           ; 5.5 -2.25 0.0 0.0625 -0.0625 123.9375 32000.5
    dd 0x40B00000, 0xC0100000, 0x00000000, 0x3D800000, 0xBD800000, 0x42F7E000, 0x46FA0100
fsp_edge_vals:                          ; QNaN, +Inf, -Inf, 3e9, -3e9
    dd 0x7FC00000, 0x7F800000, 0xFF800000, 0x4F32D05E, 0xCF32D05E
str_fsp_nan:        db "nan", 0
str_fsp_inf:        db "inf", 0
str_fsp_ovf:        db "ovf", 0
str_fsp_kat_pre:    db "[PAOS64] M16 cognition: fp32_serial_print KAT ", 0
str_fsp_kat_tail:   db "[tourn.fp32_serial_print.kat]", 13, 10, 0
str_fsp_guard_pre:  db "[PAOS64] M16 cognition: fp32_serial_print GUARD ", 0
str_fsp_guard_tail: db "[tourn.fp32_serial_print.guard]", 13, 10, 0
str_fsp_perf_pre:   db 13, 10, "[PAOS64] M16 cognition: fp32_serial_print PERF 64 full prints cycles=", 0
str_fsp_perf_tail:  db " [tourn.fp32_serial_print.perf]", 13, 10, 0

; =============================================================================
; FP32 Math Self-Test
; =============================================================================
fp32_selftest:
    push rbx
    push r12

    lea rdi, [rel str_fp32_testing]
    call serial_string

    ; --- Test 1: Addition (3.0 + 2.5 = 5.5) ---
    lea rdi, [rel str_fp32_add_test]
    call serial_string
    movss xmm0, [rel fp32_test_3_0]
    movss xmm1, [rel fp32_test_2_5]
    call fp32_add
    call fp32_serial_print              ; Should print 5.5000
    lea rdi, [rel str_crlf]
    call serial_string

    ; --- Test 2: Subtraction (10.0 - 3.5 = 6.5) ---
    lea rdi, [rel str_fp32_sub_test]
    call serial_string
    movss xmm0, [rel fp32_test_10_0]
    movss xmm1, [rel fp32_test_3_5]
    call fp32_sub
    call fp32_serial_print              ; Should print 6.5000
    lea rdi, [rel str_crlf]
    call serial_string

    ; --- Test 3: Multiplication (4.0 * 2.5 = 10.0) ---
    lea rdi, [rel str_fp32_mul_test]
    call serial_string
    movss xmm0, [rel fp32_test_4_0]
    movss xmm1, [rel fp32_test_2_5]
    call fp32_mul
    call fp32_serial_print              ; Should print 10.0000
    lea rdi, [rel str_crlf]
    call serial_string

    ; --- Test 4: Division (10.0 / 4.0 = 2.5) ---
    lea rdi, [rel str_fp32_div_test]
    call serial_string
    movss xmm0, [rel fp32_test_10_0]
    movss xmm1, [rel fp32_test_4_0]
    call fp32_div
    call fp32_serial_print              ; Should print 2.5000
    lea rdi, [rel str_crlf]
    call serial_string

    ; --- Test 5: exp(1.0) ≈ 2.7183 ---
    lea rdi, [rel str_fp32_exp_test]
    call serial_string
    movss xmm0, [rel fp32_one]
    call fp32_exp_approx
    call fp32_serial_print              ; Should print ~2.7182
    lea rdi, [rel str_crlf]
    call serial_string

    ; --- Test 6: exp(0.0) = 1.0 ---
    lea rdi, [rel str_fp32_exp0_test]
    call serial_string
    xorps xmm0, xmm0                   ; 0.0
    call fp32_exp_approx
    call fp32_serial_print              ; Should print 1.0000
    lea rdi, [rel str_crlf]
    call serial_string

    ; --- Test 7: sigmoid(0.0) = 0.5 ---
    lea rdi, [rel str_fp32_sig_test]
    call serial_string
    xorps xmm0, xmm0                   ; 0.0
    call fp32_sigmoid
    call fp32_serial_print              ; Should print 0.5000
    lea rdi, [rel str_crlf]
    call serial_string

    ; --- Test 8: tanh(0.0) = 0.0 ---
    lea rdi, [rel str_fp32_tanh_test]
    call serial_string
    xorps xmm0, xmm0                   ; 0.0
    call fp32_tanh
    call fp32_serial_print              ; Should print 0.0000
    lea rdi, [rel str_crlf]
    call serial_string

    ; --- Test 9: Dot product [1,2,3,4]·[2,3,4,5] = 2+6+12+20 = 40.0 ---
    lea rdi, [rel str_fp32_dot_test]
    call serial_string
    lea rdi, [rel fp32_test_vec_a]
    lea rsi, [rel fp32_test_vec_b]
    call fp32_dot4
    call fp32_serial_print              ; Should print 40.0000
    lea rdi, [rel str_crlf]
    call serial_string

    ; --- Test 10: sigmoid(large positive) ≈ 1.0 ---
    lea rdi, [rel str_fp32_sig10_test]
    call serial_string
    movss xmm0, [rel fp32_test_10_0]
    call fp32_sigmoid
    call fp32_serial_print              ; Should print ~1.0000
    lea rdi, [rel str_crlf]
    call serial_string

    ; All tests complete
    lea rdi, [rel str_fp32_marker]
    call serial_string

    pop r12
    pop rbx
    ret

; =============================================================================
; FP32 Constants (16-byte aligned for SSE loads)
; =============================================================================
align 16
fp32_abs_mask:      dd 0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF, 0x7FFFFFFF
fp32_sign_mask:     dd 0x80000000, 0x80000000, 0x80000000, 0x80000000

align 4
fp32_one:           dd 0x3F800000      ; 1.0f
fp32_log2e:         dd 0x3FB8AA3B      ; log2(e) = 1.44269504
fp32_inf:           dd 0x7F800000      ; +infinity
fp32_10000:         dd 0x461C4000      ; 10000.0f

; Minimax polynomial coefficients for 2^f, f in [-0.5, 0.5]
; p(f) ≈ c0 + c1*f + c2*f^2 + c3*f^3 + c4*f^4
fp32_exp_c0:        dd 0x3F800000      ; 1.0
fp32_exp_c1:        dd 0x3F317218      ; 0.6931472 (ln2)
fp32_exp_c2:        dd 0x3E75FDF0      ; 0.2402265
fp32_exp_c3:        dd 0x3D6354E2      ; 0.0554959
fp32_exp_c4:        dd 0x3C1D9538      ; 0.0096138

; Test values
fp32_test_2_5:      dd 0x40200000      ; 2.5f
fp32_test_3_0:      dd 0x40400000      ; 3.0f
fp32_test_3_5:      dd 0x40600000      ; 3.5f
fp32_test_4_0:      dd 0x40800000      ; 4.0f
fp32_test_10_0:     dd 0x41200000      ; 10.0f

; Test vectors (4 floats each)
align 16
fp32_test_vec_a:    dd 0x3F800000, 0x40000000, 0x40400000, 0x40800000  ; [1, 2, 3, 4]
fp32_test_vec_b:    dd 0x40000000, 0x40400000, 0x40800000, 0x40A00000  ; [2, 3, 4, 5]

; =============================================================================
; SIMD Matrix Multiplication with Auto-Selection
; =============================================================================
; Three paths selected at runtime via CPUID:
;   Level 1 - SSE:      MULPS + ADDPS   (128-bit, 4 floats per op)
;   Level 2 - AVX:      VMULPS + VADDPS (256-bit, 8 floats per op)
;   Level 3 - AVX2+FMA: VFMADD231PS    (fused multiply-add, 256-bit)
; All matrices are row-major float32 arrays.

; simd_matmul_detect: Detect best SIMD path and enable AVX if available
; Sets simd_matmul_level: 1=SSE, 2=AVX, 3=AVX2+FMA
simd_matmul_detect:
    push rbx
    push rcx
    push rdx

    ; Default to SSE (always available on x86-64)
    mov byte [rel simd_matmul_level], 1

    ; Check CPUID leaf 1 for XSAVE (bit 26), AVX (bit 28), FMA (bit 12)
    mov eax, 1
    cpuid
    mov r8d, ecx                        ; Save feature flags

    ; Need both XSAVE and AVX to enable AVX
    test ecx, (1 << 26)                 ; XSAVE?
    jz .detect_done
    test ecx, (1 << 28)                 ; AVX?
    jz .detect_done

    ; Enable OSXSAVE in CR4 (required for AVX/YMM registers)
    mov rax, cr4
    or rax, (1 << 18)                   ; CR4.OSXSAVE
    mov cr4, rax

    ; Set XCR0: enable x87 (bit 0) + SSE (bit 1) + AVX (bit 2)
    xor ecx, ecx                        ; Select XCR0
    xgetbv                              ; Read current XCR0 into EDX:EAX
    or eax, 0x07                        ; Enable x87 + SSE + AVX state
    xsetbv                              ; Write XCR0

    ; AVX now enabled
    mov byte [rel simd_matmul_level], 2

    ; Check for FMA3 (CPUID.1:ECX bit 12)
    test r8d, (1 << 12)
    jz .detect_done

    ; Check for AVX2 (CPUID.7:EBX bit 5)
    cmp dword [rel cpuid_max_leaf], 7
    jb .detect_done
    mov eax, 7
    xor ecx, ecx
    cpuid
    test ebx, (1 << 5)
    jz .detect_done

    ; AVX2 + FMA3 available
    mov byte [rel simd_matmul_level], 3

.detect_done:
    ; Print detected SIMD level
    lea rdi, [rel str_simd_detect]
    call serial_string
    movzx eax, byte [rel simd_matmul_level]
    cmp al, 3
    je .print_fma
    cmp al, 2
    je .print_avx
    lea rdi, [rel str_simd_sse]
    jmp .print_name
.print_avx:
    lea rdi, [rel str_simd_avx]
    jmp .print_name
.print_fma:
    lea rdi, [rel str_simd_fma]
.print_name:
    call serial_string
    call serial_newline

    pop rdx
    pop rcx
    pop rbx
    ret

; simd_matmul: General NxN matrix multiply C = A * B (float32, row-major)
; Input: RDI = A (M x K floats), RSI = B (K x N floats), RDX = C (M x N floats)
;        ECX = M (rows of A/C), R8D = N (cols of B/C), R9D = K (cols of A / rows of B)
; Dispatches to best available SIMD path
simd_matmul:
    movzx eax, byte [rel simd_matmul_level]
    cmp al, 3
    je simd_matmul_fma
    cmp al, 2
    je simd_matmul_avx
    jmp simd_matmul_sse

; simd_matmul_sse: SSE path — MULPS + ADDPS (4 floats per op)
; Same calling convention as simd_matmul
simd_matmul_sse:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15

    ; Save arguments to callee-saved registers
    mov r12, rdi                        ; R12 = A base
    mov r13, rsi                        ; R13 = B base
    mov r14, rdx                        ; R14 = C base
    mov r15d, ecx                       ; R15D = M (rows)
    mov ebx, r8d                        ; EBX = N (cols)
    mov ebp, r9d                        ; EBP = K (inner dim)

    xor ecx, ecx                        ; ECX = i (row counter)
.sse_row_loop:
    cmp ecx, r15d
    jge .sse_done

    ; RAX = pointer to A[i][0] = A + i*K*4
    mov eax, ecx
    imul eax, ebp
    shl eax, 2                          ; * sizeof(float)
    lea rdi, [r12 + rax]               ; RDI = &A[i][0]

    ; R8 = pointer to C[i][0] = C + i*N*4
    mov eax, ecx
    imul eax, ebx
    shl eax, 2
    lea r8, [r14 + rax]                ; R8 = &C[i][0]

    push rcx                            ; Save row counter

    ; Process columns in groups of 4
    xor edx, edx                        ; EDX = j (col counter)
.sse_col_loop:
    lea eax, [edx + 3]
    cmp eax, ebx
    jg .sse_col_remainder               ; Less than 4 cols remaining

    ; Accumulate C[i][j..j+3] = sum_k A[i][k] * B[k][j..j+3]
    xorps xmm0, xmm0                   ; XMM0 = accumulator [0,0,0,0]

    xor ecx, ecx                        ; ECX = k
.sse_k_loop:
    cmp ecx, ebp
    jge .sse_k_done

    ; Broadcast A[i][k] to all 4 lanes
    movss xmm1, [rdi + rcx*4]          ; Load A[i][k]
    shufps xmm1, xmm1, 0x00            ; Broadcast to [a,a,a,a]

    ; Load B[k][j..j+3]
    mov eax, ecx
    imul eax, ebx                       ; k * N
    add eax, edx                        ; k * N + j
    movups xmm2, [r13 + rax*4]         ; Load 4 floats from B

    ; Multiply and accumulate
    mulps xmm2, xmm1
    addps xmm0, xmm2

    inc ecx
    jmp .sse_k_loop

.sse_k_done:
    ; Store result C[i][j..j+3]
    movups [r8 + rdx*4], xmm0

    add edx, 4
    jmp .sse_col_loop

.sse_col_remainder:
    ; Handle remaining columns (N % 4) with scalar ops
    cmp edx, ebx
    jge .sse_col_done

    xorps xmm0, xmm0                   ; Scalar accumulator

    xor ecx, ecx                        ; k = 0
.sse_scalar_k:
    cmp ecx, ebp
    jge .sse_scalar_store

    movss xmm1, [rdi + rcx*4]          ; A[i][k]
    mov eax, ecx
    imul eax, ebx
    add eax, edx
    movss xmm2, [r13 + rax*4]          ; B[k][j]
    mulss xmm2, xmm1
    addss xmm0, xmm2

    inc ecx
    jmp .sse_scalar_k

.sse_scalar_store:
    movss [r8 + rdx*4], xmm0
    inc edx
    jmp .sse_col_remainder

.sse_col_done:
    pop rcx                             ; Restore row counter
    inc ecx
    jmp .sse_row_loop

.sse_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; simd_matmul_avx: AVX path — VMULPS + VADDPS (8 floats per op)
; Same calling convention as simd_matmul
simd_matmul_avx:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi                        ; A base
    mov r13, rsi                        ; B base
    mov r14, rdx                        ; C base
    mov r15d, ecx                       ; M
    mov ebx, r8d                        ; N
    mov ebp, r9d                        ; K

    xor ecx, ecx                        ; i = 0
.avx_row_loop:
    cmp ecx, r15d
    jge .avx_done

    mov eax, ecx
    imul eax, ebp
    shl eax, 2
    lea rdi, [r12 + rax]               ; &A[i][0]

    mov eax, ecx
    imul eax, ebx
    shl eax, 2
    lea r8, [r14 + rax]                ; &C[i][0]

    push rcx

    xor edx, edx                        ; j = 0
.avx_col_loop:
    lea eax, [edx + 7]
    cmp eax, ebx
    jg .avx_col_narrow                  ; < 8 cols left, try SSE-width

    ; 8-wide accumulator
    vxorps ymm0, ymm0, ymm0

    xor ecx, ecx                        ; k = 0
.avx_k_loop:
    cmp ecx, ebp
    jge .avx_k_done

    vbroadcastss ymm1, [rdi + rcx*4]   ; Broadcast A[i][k] to 8 lanes

    mov eax, ecx
    imul eax, ebx
    add eax, edx
    vmulps ymm2, ymm1, [r13 + rax*4]   ; B[k][j..j+7] * A[i][k]
    vaddps ymm0, ymm0, ymm2            ; Accumulate

    inc ecx
    jmp .avx_k_loop

.avx_k_done:
    vmovups [r8 + rdx*4], ymm0          ; Store 8 results
    add edx, 8
    jmp .avx_col_loop

.avx_col_narrow:
    ; Fall back to 4-wide SSE for remaining columns
    lea eax, [edx + 3]
    cmp eax, ebx
    jg .avx_col_scalar

    vxorps xmm0, xmm0, xmm0

    xor ecx, ecx
.avx_sse_k:
    cmp ecx, ebp
    jge .avx_sse_k_done

    vbroadcastss xmm1, [rdi + rcx*4]
    mov eax, ecx
    imul eax, ebx
    add eax, edx
    vmulps xmm2, xmm1, [r13 + rax*4]
    vaddps xmm0, xmm0, xmm2

    inc ecx
    jmp .avx_sse_k

.avx_sse_k_done:
    vmovups [r8 + rdx*4], xmm0
    add edx, 4
    jmp .avx_col_narrow

.avx_col_scalar:
    ; Remaining < 4 columns: scalar
    cmp edx, ebx
    jge .avx_col_done

    vxorps xmm0, xmm0, xmm0

    xor ecx, ecx
.avx_scalar_k:
    cmp ecx, ebp
    jge .avx_scalar_store

    vmovss xmm1, [rdi + rcx*4]
    mov eax, ecx
    imul eax, ebx
    add eax, edx
    vmovss xmm2, [r13 + rax*4]
    vmulss xmm2, xmm2, xmm1
    vaddss xmm0, xmm0, xmm2

    inc ecx
    jmp .avx_scalar_k

.avx_scalar_store:
    vmovss [r8 + rdx*4], xmm0
    inc edx
    jmp .avx_col_scalar

.avx_col_done:
    pop rcx
    inc ecx
    jmp .avx_row_loop

.avx_done:
    vzeroupper                           ; Clear upper YMM state for SSE compat
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; simd_matmul_fma: AVX2+FMA path — VFMADD231PS (fused multiply-add, 256-bit)
; Same calling convention as simd_matmul
simd_matmul_fma:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi                        ; A base
    mov r13, rsi                        ; B base
    mov r14, rdx                        ; C base
    mov r15d, ecx                       ; M
    mov ebx, r8d                        ; N
    mov ebp, r9d                        ; K

    xor ecx, ecx                        ; i = 0
.fma_row_loop:
    cmp ecx, r15d
    jge .fma_done

    mov eax, ecx
    imul eax, ebp
    shl eax, 2
    lea rdi, [r12 + rax]               ; &A[i][0]

    mov eax, ecx
    imul eax, ebx
    shl eax, 2
    lea r8, [r14 + rax]                ; &C[i][0]

    push rcx

    xor edx, edx                        ; j = 0
.fma_col_loop:
    lea eax, [edx + 7]
    cmp eax, ebx
    jg .fma_col_narrow

    ; 8-wide FMA accumulator
    vxorps ymm0, ymm0, ymm0

    xor ecx, ecx                        ; k = 0
.fma_k_loop:
    cmp ecx, ebp
    jge .fma_k_done

    vbroadcastss ymm1, [rdi + rcx*4]   ; Broadcast A[i][k]

    mov eax, ecx
    imul eax, ebx
    add eax, edx
    ; FMA: ymm0 = ymm0 + ymm1 * mem  (fused multiply-add)
    vfmadd231ps ymm0, ymm1, [r13 + rax*4]

    inc ecx
    jmp .fma_k_loop

.fma_k_done:
    vmovups [r8 + rdx*4], ymm0
    add edx, 8
    jmp .fma_col_loop

.fma_col_narrow:
    ; 4-wide FMA for remaining columns
    lea eax, [edx + 3]
    cmp eax, ebx
    jg .fma_col_scalar

    vxorps xmm0, xmm0, xmm0

    xor ecx, ecx
.fma_sse_k:
    cmp ecx, ebp
    jge .fma_sse_k_done

    vbroadcastss xmm1, [rdi + rcx*4]
    mov eax, ecx
    imul eax, ebx
    add eax, edx
    vfmadd231ps xmm0, xmm1, [r13 + rax*4]

    inc ecx
    jmp .fma_sse_k

.fma_sse_k_done:
    vmovups [r8 + rdx*4], xmm0
    add edx, 4
    jmp .fma_col_narrow

.fma_col_scalar:
    ; Scalar remainder
    cmp edx, ebx
    jge .fma_col_done

    vxorps xmm0, xmm0, xmm0

    xor ecx, ecx
.fma_scalar_k:
    cmp ecx, ebp
    jge .fma_scalar_store

    vmovss xmm1, [rdi + rcx*4]
    mov eax, ecx
    imul eax, ebx
    add eax, edx
    vfmadd231ss xmm0, xmm1, [r13 + rax*4]

    inc ecx
    jmp .fma_scalar_k

.fma_scalar_store:
    vmovss [r8 + rdx*4], xmm0
    inc edx
    jmp .fma_col_scalar

.fma_col_done:
    pop rcx
    inc ecx
    jmp .fma_row_loop

.fma_done:
    vzeroupper
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; =============================================================================
; SIMD Matrix Multiply Self-Test
; =============================================================================
; Multiplies two 4x4 matrices and verifies result against expected values

simd_matmul_selftest:
    push rbx
    push r12
    sub rsp, 64                         ; 64 bytes for result matrix C (4x4 floats)

    lea rdi, [rel str_simd_testing]
    call serial_string

    ; Print detected SIMD level
    lea rdi, [rel str_simd_using]
    call serial_string
    movzx eax, byte [rel simd_matmul_level]
    cmp al, 3
    je .st_print_fma
    cmp al, 2
    je .st_print_avx
    lea rdi, [rel str_simd_sse]
    jmp .st_print
.st_print_avx:
    lea rdi, [rel str_simd_avx]
    jmp .st_print
.st_print_fma:
    lea rdi, [rel str_simd_fma]
.st_print:
    call serial_string
    call serial_newline

    ; Clear result buffer on stack
    mov r12, rsp                        ; R12 = C result buffer
    xor eax, eax
    mov ecx, 16
    mov rdi, r12
    rep stosd

    ; Multiply: C = A * B  (4x4)
    ; A = [[1,2,3,4],[5,6,7,8],[9,10,11,12],[13,14,15,16]]
    ; B = [[2,0,0,0],[0,2,0,0],[0,0,2,0],[0,0,0,2]]  (2 * Identity)
    ; Expected C = [[2,4,6,8],[10,12,14,16],[18,20,22,24],[26,28,30,32]]
    lea rdi, [rel simd_test_mat_a]      ; A
    lea rsi, [rel simd_test_mat_b]      ; B
    mov rdx, r12                        ; C (stack buffer)
    mov ecx, 4                          ; M = 4
    mov r8d, 4                          ; N = 4
    mov r9d, 4                          ; K = 4
    call simd_matmul

    ; Verify C[0][0] = 2.0
    lea rdi, [rel str_simd_c00]
    call serial_string
    movss xmm0, [r12]                  ; C[0][0]
    call fp32_serial_print
    call serial_newline

    ; Verify C[1][1] = 12.0  (offset = (1*4+1)*4 = 20)
    lea rdi, [rel str_simd_c11]
    call serial_string
    movss xmm0, [r12 + 20]             ; C[1][1]
    call fp32_serial_print
    call serial_newline

    ; Verify C[3][3] = 32.0  (offset = (3*4+3)*4 = 60)
    lea rdi, [rel str_simd_c33]
    call serial_string
    movss xmm0, [r12 + 60]             ; C[3][3]
    call fp32_serial_print
    call serial_newline

    ; Print success marker
    lea rdi, [rel str_simd_marker]
    call serial_string

    add rsp, 64
    pop r12
    pop rbx
    ret

; =============================================================================
; SIMD Matrix Multiply Constants
; =============================================================================
align 16
; Test matrix A: [[1,2,3,4],[5,6,7,8],[9,10,11,12],[13,14,15,16]]
simd_test_mat_a:
    dd 0x3F800000, 0x40000000, 0x40400000, 0x40800000   ; Row 0: 1, 2, 3, 4
    dd 0x40A00000, 0x40C00000, 0x40E00000, 0x41000000   ; Row 1: 5, 6, 7, 8
    dd 0x41100000, 0x41200000, 0x41300000, 0x41400000   ; Row 2: 9, 10, 11, 12
    dd 0x41500000, 0x41600000, 0x41700000, 0x41800000   ; Row 3: 13, 14, 15, 16

; Test matrix B: 2 * Identity
simd_test_mat_b:
    dd 0x40000000, 0x00000000, 0x00000000, 0x00000000   ; Row 0: 2, 0, 0, 0
    dd 0x00000000, 0x40000000, 0x00000000, 0x00000000   ; Row 1: 0, 2, 0, 0
    dd 0x00000000, 0x00000000, 0x40000000, 0x00000000   ; Row 2: 0, 0, 2, 0
    dd 0x00000000, 0x00000000, 0x00000000, 0x40000000   ; Row 3: 0, 0, 0, 2

; SIMD level variable
simd_matmul_level:  db 1                ; 1=SSE, 2=AVX, 3=AVX2+FMA

; =============================================================================
; CPU Optimization — Task 133
; =============================================================================
; Checks AVX/AVX2/AVX-512/AES-NI support via CPUID, sets feature flags,
; selects optimized function pointers, and runs a 2x2 identity matmul selftest.
; Called after cpuid_detect and simd_matmul_detect.

; cpu_optimize: Select best CPU optimization path and verify with selftest
; Input: None (reads cpuid results and simd_matmul_level)
; Output: Sets cpuopt_has_avx, cpuopt_has_avx2, cpuopt_has_avx512, cpuopt_has_aesni
; Notes: Emits serial markers for detected features and selftest result
cpu_optimize:
    push rbx
    push r12

    ; --- Detect features from CPUID ---
    ; Leaf 1: ECX has AVX (28), AES-NI (25)
    mov eax, 1
    cpuid
    mov r12d, ecx                       ; Save leaf 1 ECX

    ; AES-NI (ECX bit 25)
    xor eax, eax
    test r12d, (1 << 25)
    setnz al
    mov byte [rel cpuopt_has_aesni], al

    ; AVX (ECX bit 28) — also needs XSAVE (bit 26)
    xor eax, eax
    test r12d, (1 << 28)
    jz .no_avx
    test r12d, (1 << 26)               ; XSAVE required
    jz .no_avx
    mov al, 1
.no_avx:
    mov byte [rel cpuopt_has_avx], al

    ; AVX2 (Leaf 7, EBX bit 5)
    xor eax, eax
    mov byte [rel cpuopt_has_avx2], 0
    mov byte [rel cpuopt_has_avx512], 0
    cmp dword [rel cpuid_max_leaf], 7
    jb .skip_leaf7
    mov eax, 7
    xor ecx, ecx
    cpuid
    ; AVX2
    xor eax, eax
    test ebx, (1 << 5)
    setnz al
    mov byte [rel cpuopt_has_avx2], al
    ; AVX-512F (EBX bit 16)
    xor eax, eax
    test ebx, (1 << 16)
    setnz al
    mov byte [rel cpuopt_has_avx512], al
.skip_leaf7:

    ; --- Print selected optimization path ---
    lea rdi, [rel str_cpuopt_selected]
    call serial_string

    ; Determine path name based on simd_matmul_level (already set by simd_matmul_detect)
    movzx eax, byte [rel simd_matmul_level]
    cmp al, 3
    je .sel_avx2
    cmp al, 2
    je .sel_avx
    lea rdi, [rel str_cpuopt_sse]
    jmp .sel_print
.sel_avx:
    lea rdi, [rel str_cpuopt_avx]
    jmp .sel_print
.sel_avx2:
    lea rdi, [rel str_cpuopt_avx2]
.sel_print:
    call serial_string
    call serial_newline

    ; --- Print AES-NI status ---
    lea rdi, [rel str_cpuopt_aesni]
    call serial_string
    movzx edi, byte [rel cpuopt_has_aesni]
    call serial_decimal
    call serial_newline

    ; --- 2x2 identity matmul selftest ---
    ; A = Identity 2x2, B = Identity 2x2 => C should be Identity 2x2
    ; Using stack for result matrix C (2x2 = 4 floats = 16 bytes, align to 16)
    sub rsp, 32                         ; 16 bytes for C + padding for alignment

    ; Clear result buffer
    xor eax, eax
    mov [rsp], rax
    mov [rsp+8], rax

    ; Call simd_matmul: C = A * B (2x2)
    lea rdi, [rel cpuopt_ident2x2]      ; A = 2x2 identity
    lea rsi, [rel cpuopt_ident2x2]      ; B = 2x2 identity
    lea rdx, [rsp]                      ; C = result on stack
    mov ecx, 2                          ; M = 2
    mov r8d, 2                          ; N = 2
    mov r9d, 2                          ; K = 2
    call simd_matmul

    ; Verify C[0][0] == 1.0 (0x3F800000)
    mov eax, [rsp]
    cmp eax, 0x3F800000
    jne .selftest_fail

    ; Verify C[0][1] == 0.0
    mov eax, [rsp+4]
    test eax, eax
    jnz .selftest_fail

    ; Verify C[1][0] == 0.0
    mov eax, [rsp+8]
    test eax, eax
    jnz .selftest_fail

    ; Verify C[1][1] == 1.0 (0x3F800000)
    mov eax, [rsp+12]
    cmp eax, 0x3F800000
    jne .selftest_fail

    ; Selftest passed
    lea rdi, [rel str_cpuopt_pass]
    call serial_string
    jmp .selftest_done

.selftest_fail:
    lea rdi, [rel str_cpuopt_fail]
    call serial_string

.selftest_done:
    add rsp, 32

    ; Emit regression marker
    lea rdi, [rel str_cpuopt_marker]
    call serial_string

    pop r12
    pop rbx
    ret

; --- CPU optimization data ---
align 16
; 2x2 identity matrix (float32)
cpuopt_ident2x2:
    dd 0x3F800000, 0x00000000           ; Row 0: 1.0, 0.0
    dd 0x00000000, 0x3F800000           ; Row 1: 0.0, 1.0

; Feature flags
cpuopt_has_avx:     db 0                ; 1 if AVX supported
cpuopt_has_avx2:    db 0                ; 1 if AVX2 supported
cpuopt_has_avx512:  db 0                ; 1 if AVX-512 supported
cpuopt_has_aesni:   db 0                ; 1 if AES-NI supported

; =============================================================================
; Softmax — Numerically Stable, SIMD-Optimized
; =============================================================================
; softmax(x, n): Computes softmax in-place over an array of n float32 values
;   1. Find max (numerical stability)
;   2. Subtract max from each element
;   3. Compute exp(x_i - max) for each element
;   4. Sum all exp values
;   5. Divide each element by sum
;
; Input:
;   RDI = pointer to float32 array (input/output, overwritten with softmax result)
;   ESI = number of elements (n >= 1)
; Output:
;   Array at [RDI] contains softmax probabilities
; Clobbers: XMM0-XMM5, RAX, RCX, RDX

softmax:
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 8                          ; Align stack to 16

    mov r12, rdi                        ; R12 = array pointer
    mov r13d, esi                       ; R13 = n (element count)

    ; === Step 1: Find max element (for numerical stability) ===
    ; Process 4 floats at a time with SSE, then reduce
    movss xmm0, [r12]                  ; xmm0 = max = arr[0]
    shufps xmm0, xmm0, 0              ; Broadcast to all lanes

    mov ecx, 1                          ; Index = 1
    mov eax, r13d
    sub eax, 3                          ; eax = n - 3 (threshold for SIMD loop)
    cmp ecx, eax
    jge .max_scalar_loop

    ; SIMD max loop: process 4 elements at a time
.max_simd_loop:
    movups xmm1, [r12 + rcx*4]
    maxps xmm0, xmm1
    add ecx, 4
    cmp ecx, eax
    jl .max_simd_loop

    ; Reduce xmm0 to single max across 4 lanes
    movaps xmm1, xmm0
    shufps xmm1, xmm1, 0x4E           ; Swap high/low pairs
    maxps xmm0, xmm1
    movaps xmm1, xmm0
    shufps xmm1, xmm1, 0xB1           ; Swap within pairs
    maxss xmm0, xmm1                   ; xmm0[0] = max of 4 lanes

.max_scalar_loop:
    cmp ecx, r13d
    jge .max_done
    movss xmm1, [r12 + rcx*4]
    maxss xmm0, xmm1
    inc ecx
    jmp .max_scalar_loop

.max_done:
    ; xmm0[0] = max value — save it
    movss [rel softmax_max_val], xmm0

    ; === Step 2 & 3: Subtract max, compute exp, accumulate sum ===
    xorps xmm4, xmm4                   ; xmm4 = sum accumulator = 0.0
    xor ecx, ecx                        ; Index = 0

.exp_loop:
    cmp ecx, r13d
    jge .exp_done

    ; Load element, subtract max
    movss xmm0, [r12 + rcx*4]
    subss xmm0, [rel softmax_max_val]

    ; Save index (exp_approx clobbers registers)
    mov r14d, ecx
    call fp32_exp_approx                ; xmm0 = exp(x_i - max)

    ; Store exp result back and accumulate sum
    mov ecx, r14d
    movss [r12 + rcx*4], xmm0
    addss xmm4, xmm0

    inc ecx
    jmp .exp_loop

.exp_done:
    ; === Step 4: Divide each element by sum ===
    ; xmm4 = sum of all exp values
    ; Broadcast sum for SIMD division
    shufps xmm4, xmm4, 0              ; Broadcast sum to all 4 lanes

    xor ecx, ecx
    mov eax, r13d
    sub eax, 3                          ; Threshold for SIMD loop

    cmp ecx, eax
    jge .div_scalar_loop

    ; SIMD division loop: 4 elements at a time
.div_simd_loop:
    movups xmm0, [r12 + rcx*4]
    divps xmm0, xmm4
    movups [r12 + rcx*4], xmm0
    add ecx, 4
    cmp ecx, eax
    jl .div_simd_loop

.div_scalar_loop:
    cmp ecx, r13d
    jge .div_done
    movss xmm0, [r12 + rcx*4]
    divss xmm0, xmm4                   ; xmm4[0] still has sum
    movss [r12 + rcx*4], xmm0
    inc ecx
    jmp .div_scalar_loop

.div_done:
    add rsp, 8
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; =============================================================================
; Softmax Self-Test
; =============================================================================
; Tests softmax on a known 4-element vector: [1.0, 2.0, 3.0, 4.0]
; Expected: [0.0321, 0.0871, 0.2369, 0.6439] (sum ≈ 1.0)

softmax_selftest:
    push rbx
    push r12
    sub rsp, 32                         ; 16 bytes for test array + alignment

    lea rdi, [rel str_softmax_testing]
    call serial_string

    ; Copy test vector to stack (so we don't clobber the constant)
    mov r12, rsp
    movups xmm0, [rel softmax_test_input]
    movups [r12], xmm0

    ; Run softmax on [1.0, 2.0, 3.0, 4.0]
    mov rdi, r12
    mov esi, 4
    call softmax

    ; Print results
    lea rdi, [rel str_softmax_r0]
    call serial_string
    movss xmm0, [r12]                  ; softmax[0] ≈ 0.0321
    call fp32_serial_print
    call serial_newline

    lea rdi, [rel str_softmax_r1]
    call serial_string
    movss xmm0, [r12 + 4]             ; softmax[1] ≈ 0.0871
    call fp32_serial_print
    call serial_newline

    lea rdi, [rel str_softmax_r2]
    call serial_string
    movss xmm0, [r12 + 8]             ; softmax[2] ≈ 0.2369
    call fp32_serial_print
    call serial_newline

    lea rdi, [rel str_softmax_r3]
    call serial_string
    movss xmm0, [r12 + 12]            ; softmax[3] ≈ 0.6439
    call fp32_serial_print
    call serial_newline

    ; Verify sum ≈ 1.0
    lea rdi, [rel str_softmax_sum]
    call serial_string
    movss xmm0, [r12]
    addss xmm0, [r12 + 4]
    addss xmm0, [r12 + 8]
    addss xmm0, [r12 + 12]
    call fp32_serial_print              ; Should print ~1.0000
    call serial_newline

    ; Print success marker
    lea rdi, [rel str_softmax_marker]
    call serial_string

    add rsp, 32
    pop r12
    pop rbx
    ret

; Softmax constants and test data
align 16
softmax_test_input: dd 0x3F800000, 0x40000000, 0x40400000, 0x40800000  ; [1.0, 2.0, 3.0, 4.0]

align 4
softmax_max_val:    dd 0               ; Temporary: max value during computation

; =============================================================================
; Layer Normalization
; =============================================================================
; Computes LayerNorm: output[i] = gamma[i] * (x[i] - mean) / sqrt(var + eps) + beta[i]
; SIMD-optimized with SSE for 4-element-at-a-time processing.
;
; layernorm:
;   Input:
;     RDI = pointer to float32 array (input/output, overwritten with normalized result)
;     RSI = pointer to gamma (scale) array, or 0 for no scaling
;     RDX = pointer to beta (shift) array, or 0 for no shifting
;     ECX = number of elements (n >= 1)
;   Output:
;     Array at [RDI] contains layer-normalized values
;   Clobbers: XMM0-XMM7, RAX, RCX, RDX

layernorm:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 8                          ; Align stack to 16

    mov r12, rdi                        ; R12 = array pointer
    mov r13, rsi                        ; R13 = gamma pointer (or 0)
    mov r14, rdx                        ; R14 = beta pointer (or 0)
    mov r15d, ecx                       ; R15 = n (element count)

    ; === Step 1: Compute mean = sum(x) / n ===
    xorps xmm4, xmm4                   ; xmm4 = sum accumulator = 0.0
    xor ecx, ecx                        ; Index = 0
    mov eax, r15d
    sub eax, 3                          ; Threshold for SIMD loop

    cmp ecx, eax
    jge .ln_mean_scalar

    ; SIMD sum: 4 elements at a time
.ln_mean_simd:
    movups xmm0, [r12 + rcx*4]
    addps xmm4, xmm0
    add ecx, 4
    cmp ecx, eax
    jl .ln_mean_simd

    ; Horizontal sum of xmm4
    movaps xmm0, xmm4
    shufps xmm0, xmm0, 0x4E            ; Swap high/low pairs
    addps xmm4, xmm0
    movaps xmm0, xmm4
    shufps xmm0, xmm0, 0xB1            ; Swap within pairs
    addss xmm4, xmm0                   ; xmm4[0] = sum of 4 lanes

.ln_mean_scalar:
    cmp ecx, r15d
    jge .ln_mean_done
    movss xmm0, [r12 + rcx*4]
    addss xmm4, xmm0
    inc ecx
    jmp .ln_mean_scalar

.ln_mean_done:
    ; xmm4[0] = sum of all elements
    ; Divide by n to get mean
    cvtsi2ss xmm5, r15d                ; xmm5 = (float)n
    divss xmm4, xmm5                   ; xmm4[0] = mean
    movss [rel layernorm_mean], xmm4   ; Save mean

    ; === Step 2: Compute variance = sum((x - mean)^2) / n ===
    xorps xmm6, xmm6                   ; xmm6 = variance accumulator = 0.0
    shufps xmm4, xmm4, 0              ; Broadcast mean to all 4 lanes
    xor ecx, ecx

    cmp ecx, eax
    jge .ln_var_scalar

    ; SIMD variance: 4 elements at a time
.ln_var_simd:
    movups xmm0, [r12 + rcx*4]
    subps xmm0, xmm4                   ; xmm0 = x - mean
    mulps xmm0, xmm0                   ; xmm0 = (x - mean)^2
    addps xmm6, xmm0                   ; Accumulate
    add ecx, 4
    cmp ecx, eax
    jl .ln_var_simd

    ; Horizontal sum of xmm6
    movaps xmm0, xmm6
    shufps xmm0, xmm0, 0x4E
    addps xmm6, xmm0
    movaps xmm0, xmm6
    shufps xmm0, xmm0, 0xB1
    addss xmm6, xmm0                   ; xmm6[0] = partial sum

.ln_var_scalar:
    cmp ecx, r15d
    jge .ln_var_done
    movss xmm0, [r12 + rcx*4]
    subss xmm0, xmm4                   ; xmm4[0] still has mean
    mulss xmm0, xmm0
    addss xmm6, xmm0
    inc ecx
    jmp .ln_var_scalar

.ln_var_done:
    ; xmm6[0] = sum of squared deviations
    divss xmm6, xmm5                   ; xmm6[0] = variance (xmm5 still = n)
    movss [rel layernorm_var], xmm6    ; Save variance

    ; === Step 3: Compute 1/sqrt(variance + epsilon) ===
    addss xmm6, [rel layernorm_epsilon] ; xmm6 = var + eps
    sqrtss xmm6, xmm6                  ; xmm6 = sqrt(var + eps)
    movss xmm7, [rel fp32_one]
    divss xmm7, xmm6                   ; xmm7 = 1.0 / sqrt(var + eps) = inv_std
    shufps xmm7, xmm7, 0              ; Broadcast inv_std to all lanes

    ; === Step 4: Normalize — (x - mean) * inv_std, then scale/shift ===
    ; xmm4 still has mean broadcast, xmm7 has inv_std broadcast
    xor ecx, ecx

    cmp ecx, eax
    jge .ln_norm_scalar

    ; SIMD normalize: 4 elements at a time
.ln_norm_simd:
    movups xmm0, [r12 + rcx*4]
    subps xmm0, xmm4                   ; x - mean
    mulps xmm0, xmm7                   ; (x - mean) * inv_std

    ; Apply gamma (scale) if provided
    test r13, r13
    jz .ln_no_gamma_simd
    movups xmm1, [r13 + rcx*4]
    mulps xmm0, xmm1
.ln_no_gamma_simd:

    ; Apply beta (shift) if provided
    test r14, r14
    jz .ln_no_beta_simd
    movups xmm1, [r14 + rcx*4]
    addps xmm0, xmm1
.ln_no_beta_simd:

    movups [r12 + rcx*4], xmm0
    add ecx, 4
    cmp ecx, eax
    jl .ln_norm_simd

.ln_norm_scalar:
    cmp ecx, r15d
    jge .ln_norm_done
    movss xmm0, [r12 + rcx*4]
    subss xmm0, xmm4                   ; x - mean
    mulss xmm0, xmm7                   ; (x - mean) * inv_std

    ; Apply gamma (scale) if provided
    test r13, r13
    jz .ln_no_gamma_scalar
    movss xmm1, [r13 + rcx*4]
    mulss xmm0, xmm1
.ln_no_gamma_scalar:

    ; Apply beta (shift) if provided
    test r14, r14
    jz .ln_no_beta_scalar
    movss xmm1, [r14 + rcx*4]
    addss xmm0, xmm1
.ln_no_beta_scalar:

    movss [r12 + rcx*4], xmm0
    inc ecx
    jmp .ln_norm_scalar

.ln_norm_done:
    add rsp, 8
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; =============================================================================
; Layer Normalization Self-Test
; =============================================================================
; Tests LayerNorm on a known 4-element vector: [1.0, 2.0, 3.0, 4.0]
; Mean = 2.5, Var = 1.25, std = sqrt(1.25 + 1e-5) ≈ 1.11803
; Expected normalized: [-1.3416, -0.4472, 0.4472, 1.3416]

; =============================================================================
; CPU-LLM demo engine (recipe: recipes/cpu_llm_distilgpt2)
; Runs a REAL distilgpt2 (GPT-2 arch) through the pure-NASM CPU engine.
; The model file (model.pxg2, PXG2 format) is injected by QEMU:
;   -m 3G -device loader,file=model.pxg2,addr=0x80000000,force-raw=on
; so it lands at guest-physical 0x80000000 (identity-mapped; PaOS heap top
; ~0x80000000 but the bitmap won't hand it out before this runs, and we never
; copy the weights — we read them in place).
;
; PXG2 header @ 0x80000000 (little-endian):
;   +0  char[4] magic "PXG2"   +4  u32 version(2)
;   +8  u32 n_layer  +12 u32 n_head  +16 u32 d_model  +20 u32 d_hidden
;   +24 u32 n_vocab  +28 u32 n_ctx   +32 u32 tensor_count  +36 u32 reserved
;   +40 descriptors[tensor_count] { u32 name_id, u32 dtype, u64 off, u64 nelem }
;   then 16-byte-aligned fp32 tensor data.
; Trigger: serial command 'm'.
; =============================================================================
; Model is placed by QEMU `-device loader,addr=0x100000000` in HIGH RAM (4 GiB),
; ABOVE both OVMF's <4 GiB working range and PaOS's heap (which picks the largest
; low conventional region, ~2.9 GiB). 0x80000000 (2 GiB) was clobbered by firmware
; in [16,24 MiB). PaOS's 16 GiB identity map makes 4 GiB directly addressable.
MODEL_PHYS          equ 0x100000000
PXG2_MAGIC          equ 0x32475850          ; "PXG2" little-endian
; Token->bytes table (build_tokvocab.py) + BPE merges (build_bpe.py) injected by extra
; QEMU loaders at 5 GiB+ (above the largest model, gpt2-124M ~497MB). Needs -m 6G.
TOKVOCAB_PHYS       equ 0x140000000
TVOC_MAGIC          equ 0x434F5654          ; "TVOC" little-endian
BPEM_PHYS           equ 0x148000000         ; BPE merges table (on-device encoder)
BPEM_MAGIC          equ 0x4D455042          ; "BPEM" little-endian

; llm_cksum32: 32-bit rolling dword sum of a memory window.
;   RDI = base pointer, ESI = number of dwords. Returns sum in EAX.
llm_cksum32:
    xor eax, eax
    xor ecx, ecx
.lc_loop:
    cmp ecx, esi
    jge .lc_done
    add eax, [rdi + rcx*4]
    inc ecx
    jmp .lc_loop
.lc_done:
    ret

; m3_dbg_cksum_window: edi=offset in MiB. Checksum a 16 MiB window and print.
m3_dbg_cksum_window:
    push rbx
    mov ebx, edi                       ; save MB
    lea rdi, [rel str_dbg_ck]
    call serial_string
    mov edi, ebx
    call serial_decimal
    lea rdi, [rel str_dbg_ck2]
    call serial_string
    ; ptr = MODEL_PHYS + mb*1MiB
    mov rdi, [rel model_base]
    mov eax, ebx
    shl eax, 20                         ; mb * 1MiB
    add rdi, rax
    mov esi, 0x400000                  ; 16 MiB / 4 = 4Mi dwords
    call llm_cksum32
    mov edi, eax
    call serial_hex32
    lea rdi, [rel str_ld_nl]
    call serial_string
    pop rbx
    ret

; llm_demo_run: Milestone 1 — verify the real model is present + correctly
; loaded into PaOS memory, then (later milestones) run the forward pass.
llm_demo_run:
%if COG_MODEL_ENABLED = 0
    xor eax, eax
    ret
%else
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp

    mov rsi, [rel model_base]                 ; RSI = model base (header)

    ; --- Validate magic ---
    mov eax, [rsi]
    cmp eax, PXG2_MAGIC
    je .ld_magic_ok
    lea rdi, [rel str_ld_nomodel]
    call serial_string
    mov edi, eax
    call serial_hex32
    lea rdi, [rel str_ld_nl]
    call serial_string
    jmp .ld_done
.ld_magic_ok:

    ; --- Print header dims ---
    lea rdi, [rel str_ld_hdr]
    call serial_string
    lea rdi, [rel str_ld_layers]
    call serial_string
    mov edi, [rsi+8]
    call serial_decimal
    lea rdi, [rel str_ld_heads]
    call serial_string
    mov edi, [rsi+12]
    call serial_decimal
    lea rdi, [rel str_ld_dmodel]
    call serial_string
    mov edi, [rsi+16]
    call serial_decimal
    lea rdi, [rel str_ld_dhidden]
    call serial_string
    mov edi, [rsi+20]
    call serial_decimal
    lea rdi, [rel str_ld_vocab]
    call serial_string
    mov edi, [rsi+24]
    call serial_decimal
    lea rdi, [rel str_ld_nctx]
    call serial_string
    mov edi, [rsi+28]
    call serial_decimal
    lea rdi, [rel str_ld_tensors]
    call serial_string
    mov edi, [rsi+32]
    call serial_decimal
    lea rdi, [rel str_ld_nl]
    call serial_string

    ; --- Checksum window 0: first 16 MiB (4Mi dwords) ---
    lea rdi, [rel str_ld_cksum0]
    call serial_string
    mov rdi, [rel model_base]
    mov esi, 0x400000                   ; 4,194,304 dwords = 16 MiB
    call llm_cksum32
    mov edi, eax
    call serial_hex32
    lea rdi, [rel str_ld_nl]
    call serial_string

    ; --- Checksum window T: 16 MiB starting at +310 MiB (tail) ---
    lea rdi, [rel str_ld_cksumt]
    call serial_string
    mov rdi, [rel model_base]
    add rdi, 310*1024*1024              ; +310 MiB (within the 327,652,176-byte file)
    mov esi, 0x400000                   ; 16 MiB window
    call llm_cksum32
    mov edi, eax
    call serial_hex32
    lea rdi, [rel str_ld_nl]
    call serial_string

    ; --- load integrity: checksum a few windows across the model ---
    mov edi, 64
    call m3_dbg_cksum_window
    mov edi, 150
    call m3_dbg_cksum_window
    mov edi, 300
    call m3_dbg_cksum_window

    lea rdi, [rel str_ld_m1ok]
    call serial_string

    ; --- M2: token+position embedding (verify tensor addressing on real weights) ---
    call llm_m2_embed

    ; --- M3: full 6-layer GPT-2 forward pass -> logits -> argmax ---
    call llm_m3_forward

    ; --- M4: autoregressive generation + tok/s (naive full recompute) ---
    call llm_m4_generate
    ; --- M5: KV-cached generation (same tokens, much less work -> faster tok/s) ---
    call llm_m5_generate

.ld_done:
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

%endif

; llm_find_tensor: resolve a PXG2 tensor by name_id to its data pointer.
;   EDI = name_id. Returns RAX = pointer to fp32 data (MODEL_PHYS+off), or 0.
;   Descriptors at MODEL_PHYS+40, 24 bytes each: {u32 name_id, u32 dtype, u64 off, u64 nelem}.
;   RAX holds model_base for the whole scan, so the matched off is added via a
;   register (an imm32 add would sign-extend a bit-31 offset — KAT-locked below).
llm_find_tensor:
    mov rax, [rel model_base]
    mov ecx, [rax + 32]                ; tensor_count (down-counter)
    lea r11, [rax + 40]                ; first descriptor
.lft_next:
    sub ecx, 1
    jc  .lft_none                      ; all scanned -> not found
    cmp [r11], edi                     ; name_id match?
    lea r11, [r11 + 24]                ; advance (lea preserves the cmp flags)
    jne .lft_next
    add rax, [r11 - 16]                ; rax = model_base + off (u64)
    ret
.lft_none:
    xor eax, eax
    ret

; --- tournament 1304 KAT: exercise llm_find_tensor against a tiny synthetic
;     descriptor table (model-independent — runs every boot, QEMU and metal).
;     model_base is repointed at the table and restored before any print (serial
;     helpers here don't preserve callee-saved regs, so the save lives in data).
;     Vectors: duplicate id -> FIRST match; last entry reached; bit-31 offset not
;     sign-extended; absent id -> 0; empty table -> 0. Any mismatch withholds the
;     marker and emits .fail instead.
llm_find_tensor_kat:
    mov  rax, [rel model_base]
    mov  [rel lft_kat_saved], rax
    lea  rax, [rel lft_kat_tbl]
    mov  [rel model_base], rax
    ; v1: id 7 appears twice -> first descriptor's off (0x100) must win
    mov  edi, 7
    call llm_find_tensor
    lea  rcx, [rel lft_kat_tbl]
    add  rcx, 0x100
    cmp  rax, rcx
    jne  .fail
    ; v2: id 42 = last entry, off 0x80000000 (locks the no-sign-extend behavior)
    mov  edi, 42
    call llm_find_tensor
    lea  rcx, [rel lft_kat_tbl]
    mov  r11, 0x80000000
    add  rcx, r11
    cmp  rax, rcx
    jne  .fail
    ; v3: absent id -> 0
    mov  edi, 99
    call llm_find_tensor
    test rax, rax
    jnz  .fail
    ; v4: empty table (tensor_count=0) -> 0
    mov  dword [rel lft_kat_tbl + 32], 0
    mov  edi, 7
    call llm_find_tensor
    mov  dword [rel lft_kat_tbl + 32], 3
    test rax, rax
    jnz  .fail
    mov  rax, [rel lft_kat_saved]      ; restore before printing
    mov  [rel model_base], rax
    lea  rdi, [rel str_lft_kat_ok]
    call serial_string
    ret
.fail:
    mov  rax, [rel lft_kat_saved]
    mov  [rel model_base], rax
    lea  rdi, [rel str_lft_kat_fail]
    call serial_string
    ret

align 8
lft_kat_tbl:                            ; synthetic PXG2 tail: only +32 count and
    times 32 db 0                       ; +40 descriptors are read by the scanner
    dd 3, 0                             ; +32 tensor_count, +36 pad
    dd 7,  0
    dq 0x100, 1                         ; {name_id, dtype, off, nelem}
    dd 7,  0
    dq 0x200, 1                         ; duplicate id — first must win
    dd 42, 0
    dq 0x80000000, 1                    ; bit-31 off — no sign-extend
lft_kat_saved:    dq 0
str_lft_kat_ok:   db "[PAOS64] M16 cognition: llm_find_tensor KAT PASS (dup-first/last/bit31-off/absent/empty) [tourn.llm_find_tensor.kat]", 13, 10, 0
str_lft_kat_fail: db "[PAOS64] M16 cognition: llm_find_tensor KAT FAIL [tourn.llm_find_tensor.kat.fail]", 13, 10, 0

; llm_m2_embed: compute hidden = wte[token] + wpe[pos] for the hardcoded test
; prompt "The quick brown fox" (4 tokens), into a heap buffer, and print
; diagnostics (raw fp32 bit patterns + a float sum) for host comparison.
LLM_M2_NTOK         equ 4
; NOTE: serial_string / serial_hex32 / kmalloc in this codebase do NOT preserve
; callee-saved registers, so wte/wpe/hidden pointers are kept in BSS globals
; (m2_wte_p / m2_wpe_p / m2_hidden_p), reloaded around every call. The embed
; loop itself contains no calls, so registers are stable within it.
llm_m2_embed:
    push rbx
    push r12
    push rbp

    lea rdi, [rel str_m2_dbg_a]
    call serial_string

    ; Allocate hidden buffer: NTOK * 768 floats
    mov edi, LLM_M2_NTOK * 768 * 4
    call kmalloc
    test rax, rax
    jz .m2_fail
    mov [rel m2_hidden_p], rax

    ; Resolve wte (name_id 0) and wpe (name_id 1)
    xor edi, edi
    call llm_find_tensor               ; rax = wte
    test rax, rax
    jz .m2_fail
    mov [rel m2_wte_p], rax
    mov edi, 1
    call llm_find_tensor               ; rax = wpe
    test rax, rax
    jz .m2_fail
    mov [rel m2_wpe_p], rax

    lea rdi, [rel str_m2_dbg_b]
    call serial_string

    ; For each position p in 0..NTOK-1: hidden[p] = wte[token_p] + wpe[p]
    xor ebp, ebp                       ; ebp = p
.m2_pos:
    cmp ebp, LLM_M2_NTOK
    jge .m2_pos_done
    ; token id = llm_m2_tokens[p]
    lea rbx, [rel llm_m2_tokens]
    mov r12d, [rbx + rbp*4]            ; r12d = token id
    ; rsi = wte + token*768*4
    mov eax, r12d
    imul eax, 768*4
    mov rsi, [rel m2_wte_p]
    add rsi, rax
    ; rdx = wpe + p*768*4
    mov eax, ebp
    imul eax, 768*4
    mov rdx, [rel m2_wpe_p]
    add rdx, rax
    ; rdi = hidden + p*768*4
    mov eax, ebp
    imul eax, 768*4
    mov rdi, [rel m2_hidden_p]
    add rdi, rax
    ; add 768 floats (no calls inside loop — registers stable)
    xor ecx, ecx
.m2_add:
    cmp ecx, 768
    jge .m2_add_done
    movss xmm0, [rsi + rcx*4]
    addss xmm0, [rdx + rcx*4]
    movss [rdi + rcx*4], xmm0
    inc ecx
    jmp .m2_add
.m2_add_done:
    inc ebp
    jmp .m2_pos
.m2_pos_done:

    lea rdi, [rel str_m2_dbg_c]
    call serial_string

    ; Diagnostics: hidden[0][0..3] and hidden[3][0..3] raw fp32 hex
    lea rdi, [rel str_m2_h00]
    call serial_string
    mov rsi, [rel m2_hidden_p]
    call llm_print4_hex
    lea rdi, [rel str_m2_h30]
    call serial_string
    mov rsi, [rel m2_hidden_p]
    add rsi, 3*768*4
    call llm_print4_hex

    ; Float sum over all NTOK*768 elements -> raw hex of the fp32 sum
    lea rdi, [rel str_m2_sum]
    call serial_string
    xorps xmm0, xmm0
    mov rsi, [rel m2_hidden_p]
    mov ecx, LLM_M2_NTOK * 768
.m2_sum_loop:
    test ecx, ecx
    jz .m2_sum_done
    addss xmm0, [rsi]
    add rsi, 4
    dec ecx
    jmp .m2_sum_loop
.m2_sum_done:
    movd eax, xmm0
    mov edi, eax
    call serial_hex32
    lea rdi, [rel str_ld_nl]
    call serial_string
    lea rdi, [rel str_m2_ok]
    call serial_string
    jmp .m2_ret

.m2_fail:
    lea rdi, [rel str_m2_fail]
    call serial_string
.m2_ret:
    pop rbp
    pop r12
    pop rbx
    ret

; llm_print4_hex: print 4 consecutive fp32 raw bit patterns at [RSI], space-sep + CRLF.
llm_print4_hex:
    push rbx
    push r12
    mov r12, rsi
    xor ebx, ebx
.p4_loop:
    cmp ebx, 4
    jge .p4_done
    mov edi, [r12 + rbx*4]
    call serial_hex32
    mov dil, ' '
    call serial_char
    inc ebx
    jmp .p4_loop
.p4_done:
    lea rdi, [rel str_ld_nl]
    call serial_string
    pop r12
    pop rbx
    ret

; =============================================================================
; M3: full GPT-2 forward pass for distilgpt2 (6 layers, seq=4, d=768, 12 heads)
; on the real weights. Pre-norm blocks; output head tied to wte. Uses the
; existing primitives (simd_matmul, layernorm, softmax, gelu) + bias/residual.
; All persistent pointers live in BSS globals (kmalloc/serial/etc. clobber
; callee-saved regs). Prints a per-layer fingerprint for layer-by-layer
; comparison against the oracle, then the argmax next-token id.
; =============================================================================

; m3_copy_dwords: rdi=dst, rsi=src, ecx=dword count. No calls.
m3_copy_dwords:
    cld
    rep movsd
    ret

; m3_resadd: dst[i] += src[i] for ecx floats. rdi=dst, rsi=src, ecx=count. No calls.
m3_resadd:
.ra_loop:
    test ecx, ecx
    jz .ra_done
    movss xmm0, [rdi]
    addss xmm0, [rsi]
    movss [rdi], xmm0
    add rdi, 4
    add rsi, 4
    dec ecx
    jmp .ra_loop
.ra_done:
    ret

; m3_bias_add: buf[row][col] += bias[col]. globals m3_ba_buf/m3_ba_bias; edi=M, esi=N. No calls.
m3_bias_add:
    mov r8, [rel m3_ba_buf]
    mov r9, [rel m3_ba_bias]
    xor eax, eax                       ; row
.ba_row:
    cmp eax, edi
    jge .ba_done
    mov r10d, eax
    imul r10d, esi
    shl r10d, 2
    lea r11, [r8 + r10]                ; row base
    xor ecx, ecx                       ; col
.ba_col:
    cmp ecx, esi
    jge .ba_colend
    movss xmm0, [r11 + rcx*4]
    addss xmm0, [r9 + rcx*4]
    movss [r11 + rcx*4], xmm0
    inc ecx
    jmp .ba_col
.ba_colend:
    inc eax
    jmp .ba_row
.ba_done:
    ret

; m3_layernorm4: layernorm 4 rows of [.,768] in place. globals m3_ln_src/m3_ln_g/m3_ln_b.
m3_layernorm4:
    push rbx
    xor ebx, ebx                       ; row (ebx survives layernorm)
.l4_loop:
    cmp ebx, [rel m3_seq]
    jge .l4_done
    mov rdi, [rel m3_ln_src]
    mov eax, ebx
    imul eax, 768*4
    add rdi, rax                       ; row ptr (reg add, no sign-ext trap)
    mov rsi, [rel m3_ln_g]
    mov rdx, [rel m3_ln_b]
    mov ecx, 768
    call layernorm
    inc ebx
    jmp .l4_loop
.l4_done:
    pop rbx
    ret

; m3_attention: multi-head causal self-attention. qkv[4,2304] (globals m3_qkv) ->
; attn[4,768] (m3_attn). 12 heads x head_dim 64, scale 1/sqrt(64)=0.125, causal.
m3_attention:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov r15, [rel m3_qkv]              ; qkv base (survives softmax)
    mov r14, [rel m3_attn]             ; attn base (survives softmax)
    xor r12d, r12d                     ; h
.at_h:
    cmp r12d, 12
    jge .at_done
    xor r13d, r13d                     ; i (query position)
.at_i:
    cmp r13d, [rel m3_seq]
    jge .at_hnext
    ; --- scores[j] = (q_i . k_j) * 0.125 for j=0..i ---
    xor ebp, ebp                       ; j
.at_j:
    cmp ebp, r13d
    jg .at_jdone
    ; q_i = r15 + i*9216 + h*256
    mov eax, r13d
    imul eax, 9216
    lea rsi, [r15 + rax]
    mov edx, r12d
    shl edx, 8                         ; h*256
    add rsi, rdx
    ; k_j = r15 + j*9216 + 3072 + h*256
    mov eax, ebp
    imul eax, 9216
    lea rdi, [r15 + rax]
    add rdi, 3072                      ; + 768*4 (k block)
    add rdi, rdx                       ; + h*256
    ; dot over 64
    xorps xmm0, xmm0
    xor ecx, ecx
.at_dot:
    cmp ecx, 64
    jge .at_dotd
    movss xmm1, [rsi + rcx*4]
    mulss xmm1, [rdi + rcx*4]
    addss xmm0, xmm1
    inc ecx
    jmp .at_dot
.at_dotd:
    mov eax, 0x3E000000                ; 0.125
    movd xmm2, eax
    mulss xmm0, xmm2
    lea r11, [rel m3_scores]
    movss [r11 + rbp*4], xmm0
    inc ebp
    jmp .at_j
.at_jdone:
    ; softmax(scores, i+1)  (preserves r12-r15, rbx, rbp)
    lea rdi, [rel m3_scores]
    lea esi, [r13d + 1]
    call softmax
    ; --- out[i][h*64+d] = sum_{j<=i} scores[j] * v_j[d] ---
    mov eax, r13d
    imul eax, 3072                     ; attn row i stride = 768*4
    lea r10, [r14 + rax]
    mov edx, r12d
    shl edx, 8
    add r10, rdx                       ; r10 = attn out row+head base
    xor ecx, ecx                       ; d
.at_outd:
    cmp ecx, 64
    jge .at_outdd
    xorps xmm0, xmm0                   ; acc
    xor ebp, ebp                       ; j
.at_outj:
    cmp ebp, r13d
    jg .at_outjd
    lea r11, [rel m3_scores]
    movss xmm1, [r11 + rbp*4]          ; scores[j]
    mov eax, ebp
    imul eax, 9216
    lea r11, [r15 + rax]
    add r11, 6144                      ; v block = 1536*4
    mov edx, r12d
    shl edx, 8
    add r11, rdx                       ; v_j + head
    movss xmm2, [r11 + rcx*4]          ; v_j[d]
    mulss xmm1, xmm2
    addss xmm0, xmm1
    inc ebp
    jmp .at_outj
.at_outjd:
    movss [r10 + rcx*4], xmm0
    inc ecx
    jmp .at_outd
.at_outdd:
    inc r13d
    jmp .at_i
.at_hnext:
    inc r12d
    jmp .at_h
.at_done:
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; m3_fingerprint: print "[LLMDEMO] M3 L<n> row0= h h h h sum=h" for hidden x.
m3_fingerprint:
    lea rdi, [rel str_m3_l]
    call serial_string
    mov edi, [rel m3_L]
    call serial_decimal
    lea rdi, [rel str_m3_row0]
    call serial_string
    mov rsi, [rel m2_hidden_p]
    call llm_print4_hex                ; row0[0:4] + CRLF
    lea rdi, [rel str_m3_row3]
    call serial_string
    mov rsi, [rel m2_hidden_p]
    add rsi, 3*768*4
    call llm_print4_hex                ; row3[0:4] + CRLF
    ret

; llm_dot768: SSE 4-wide dot product of two 768-float vectors (768 % 4 == 0).
;   RDI = ptr A, RSI = ptr B. Returns the dot in xmm0 (low lane).
;   Clobbers xmm0,xmm1,xmm2,RCX. Preserves all GP regs and xmm3-7 (so the argmax
;   running-max in xmm7 survives across calls). ~4x fewer iterations than scalar.
llm_dot768:
    xorps xmm0, xmm0
    xor ecx, ecx
.d768_loop:
    cmp ecx, 768
    jge .d768_done
    movups xmm1, [rdi + rcx*4]
    movups xmm2, [rsi + rcx*4]
    mulps xmm1, xmm2
    addps xmm0, xmm1
    add ecx, 4
    jmp .d768_loop
.d768_done:
    movhlps xmm1, xmm0                 ; xmm1.low = high pair (c,d)
    addps xmm0, xmm1                   ; [a+c, b+d, *, *]
    movaps xmm1, xmm0
    shufps xmm1, xmm1, 0x55            ; xmm1.low = lane1 (b+d)
    addss xmm0, xmm1                   ; xmm0.low = a+c+b+d
    ret

; gelu_accurate: exact gelu_new in place, using the identity
;   gelu_new(x) = x * sigmoid(2*arg),  arg = sqrt(2/pi)*(x + 0.044715*x^3)
; via fp32_exp_approx (~1e-4) instead of the Padé-tanh (~2e-2, clamped) the
; default `gelu` uses. The Padé error accumulates into ~0.1-0.5 logit error that
; flips argmax on near-ties (e.g. prompt "The capital of France is", margin 0.36).
; Scalar (one exp call/element) — fine for the small per-step MLP. RDI=array, ESI=n.
gelu_accurate:
    push rbx
    push r12
    push r13
    sub rsp, 8
    mov r12, rdi
    mov r13d, esi
    xor ebx, ebx
.gacc_loop:
    cmp ebx, r13d
    jge .gacc_done
    movss xmm6, [r12 + rbx*4]          ; xmm6 = x (survives fp32_exp_approx: it uses xmm0-3)
    ; arg2 = 2*sqrt(2/pi) * (x + 0.044715*x^3)
    movss xmm0, xmm6
    mulss xmm0, xmm6
    mulss xmm0, xmm6                   ; x^3
    mulss xmm0, [rel gelu_coeff_044715]
    addss xmm0, xmm6                   ; x + 0.044715*x^3
    mulss xmm0, [rel gelu_2sqrt2pi]    ; * 2*sqrt(2/pi)
    ; e = exp(-arg2)
    xorps xmm1, xmm1
    subss xmm1, xmm0
    movss xmm0, xmm1
    call fp32_exp_approx               ; xmm0 = exp(-arg2)  (preserves r12/r13/rbx/xmm6)
    addss xmm0, [rel fp32_one]         ; 1 + e
    movss xmm1, [rel fp32_one]
    divss xmm1, xmm0                   ; sigmoid(arg2) = 1/(1+e)
    mulss xmm1, xmm6                   ; x * sigmoid(2*arg)
    movss [r12 + rbx*4], xmm1
    inc ebx
    jmp .gacc_loop
.gacc_done:
    add rsp, 8
    pop r13
    pop r12
    pop rbx
    ret
gelu_2sqrt2pi:  dd 1.5957691216         ; 2*sqrt(2/pi)

; m3_logits_argmax: logits for last position (tied head), print argmax id + logit.
m3_logits_argmax:
    mov r8, [rel m2_hidden_p]
    add r8, 3*768*4                    ; last row (token index 3)
    mov r9, [rel m2_wte_p]             ; wte base
    mov eax, 0xFF800000               ; -inf
    movd xmm7, eax
    xor r10d, r10d                     ; argmax id
    xor r11d, r11d                     ; v
.lv:
    cmp r11d, 50257
    jge .lvd
    mov eax, r11d
    imul eax, 3072                     ; v*768*4
    lea rsi, [r9 + rax]                ; wte[v]
    mov rdi, r8                        ; last-position hidden
    call llm_dot768                    ; xmm0 = dot(hidden, wte[v])
    comiss xmm0, xmm7
    jbe .lskip
    movaps xmm7, xmm0
    mov r10d, r11d
.lskip:
    inc r11d
    jmp .lv
.lvd:
    ; diagnostic: logit for the expected token 274
    mov r8, [rel m2_hidden_p]
    add r8, 3*768*4
    mov r9, [rel m2_wte_p]
    mov eax, 274
    imul eax, 3072
    lea rsi, [r9 + rax]
    xorps xmm0, xmm0
    xor ecx, ecx
.l274:
    cmp ecx, 768
    jge .l274d
    movss xmm1, [r8 + rcx*4]
    mulss xmm1, [rsi + rcx*4]
    addss xmm0, xmm1
    inc ecx
    jmp .l274
.l274d:
    lea rdi, [rel str_m3_l274]
    call serial_string
    movd edi, xmm0
    call serial_hex32
    lea rdi, [rel str_ld_nl]
    call serial_string

    lea rdi, [rel str_m3_argmax]
    call serial_string
    mov edi, r10d
    call serial_decimal
    lea rdi, [rel str_m3_logit]
    call serial_string
    movd edi, xmm7
    call serial_hex32
    lea rdi, [rel str_ld_nl]
    call serial_string
    ret

; llm_m3_forward: orchestrate the full forward pass. x starts in m2_hidden_p.
llm_m3_forward:
    push rbx

    mov rax, [rel model_base]                 ; n_layer from PXG2 header (dynamic: 6 or 12)
    mov eax, [rax + 8]
    mov [rel m_nlayer], eax
    mov dword [rel m3_seq], 4          ; M3 demo runs the 4-token prompt
    lea rdi, [rel str_m3_start]
    call serial_string

    ; --- allocate work buffers (kmalloc clobbers regs -> store to globals) ---
    mov edi, 4*768*4
    call kmalloc
    test rax, rax
    jz .m3_fail
    mov [rel m3_normed], rax
    mov edi, 4*2304*4
    call kmalloc
    test rax, rax
    jz .m3_fail
    mov [rel m3_qkv], rax
    mov edi, 4*768*4
    call kmalloc
    test rax, rax
    jz .m3_fail
    mov [rel m3_attn], rax
    mov edi, 4*768*4
    call kmalloc
    test rax, rax
    jz .m3_fail
    mov [rel m3_proj], rax
    mov edi, 4*3072*4
    call kmalloc
    test rax, rax
    jz .m3_fail
    mov [rel m3_ff1], rax
    mov edi, 4*768*4
    call kmalloc
    test rax, rax
    jz .m3_fail
    mov [rel m3_ff2], rax

    ; --- layer loop (L in m3_L global; everything else via globals) ---
    mov dword [rel m3_L], 0
.m3_layer:
    mov eax, [rel m_nlayer]
    cmp dword [rel m3_L], eax
    jge .m3_layers_done

    ; resolve this layer's 12 tensors: name_id = 100 + L*20 + k
    mov ebx, [rel m3_L]
    imul ebx, 20
    add ebx, 100                       ; ebx = base_id (survives find_tensor)
    mov edi, ebx
    call llm_find_tensor
    mov [rel m3_ln1g], rax
    lea edi, [ebx+1]
    call llm_find_tensor
    mov [rel m3_ln1b], rax
    lea edi, [ebx+2]
    call llm_find_tensor
    mov [rel m3_aw], rax
    lea edi, [ebx+3]
    call llm_find_tensor
    mov [rel m3_ab], rax
    lea edi, [ebx+4]
    call llm_find_tensor
    mov [rel m3_pw], rax
    lea edi, [ebx+5]
    call llm_find_tensor
    mov [rel m3_pb], rax
    lea edi, [ebx+6]
    call llm_find_tensor
    mov [rel m3_ln2g], rax
    lea edi, [ebx+7]
    call llm_find_tensor
    mov [rel m3_ln2b], rax
    lea edi, [ebx+8]
    call llm_find_tensor
    mov [rel m3_fcw], rax
    lea edi, [ebx+9]
    call llm_find_tensor
    mov [rel m3_fcb], rax
    lea edi, [ebx+10]
    call llm_find_tensor
    mov [rel m3_fpw], rax
    lea edi, [ebx+11]
    call llm_find_tensor
    mov [rel m3_fpb], rax

    ; === attention sub-block ===
    ; normed = copy(x); layernorm(normed, ln1)
    mov rdi, [rel m3_normed]
    mov rsi, [rel m2_hidden_p]
    mov ecx, 4*768
    call m3_copy_dwords
    mov rax, [rel m3_normed]
    mov [rel m3_ln_src], rax
    mov rax, [rel m3_ln1g]
    mov [rel m3_ln_g], rax
    mov rax, [rel m3_ln1b]
    mov [rel m3_ln_b], rax
    call m3_layernorm4
    ; qkv = normed @ attn_w (M=4,N=2304,K=768); qkv += attn_b
    mov rdi, [rel m3_normed]
    mov rsi, [rel m3_aw]
    mov rdx, [rel m3_qkv]
    mov ecx, 4
    mov r8d, 2304
    mov r9d, 768
    call simd_matmul
    mov rax, [rel m3_qkv]
    mov [rel m3_ba_buf], rax
    mov rax, [rel m3_ab]
    mov [rel m3_ba_bias], rax
    mov edi, 4
    mov esi, 2304
    call m3_bias_add
    ; attention -> attn
    call m3_attention
    ; proj = attn @ proj_w (M=4,N=768,K=768); proj += proj_b
    mov rdi, [rel m3_attn]
    mov rsi, [rel m3_pw]
    mov rdx, [rel m3_proj]
    mov ecx, 4
    mov r8d, 768
    mov r9d, 768
    call simd_matmul
    mov rax, [rel m3_proj]
    mov [rel m3_ba_buf], rax
    mov rax, [rel m3_pb]
    mov [rel m3_ba_bias], rax
    mov edi, 4
    mov esi, 768
    call m3_bias_add
    ; x += proj
    mov rdi, [rel m2_hidden_p]
    mov rsi, [rel m3_proj]
    mov ecx, 4*768
    call m3_resadd

    ; === MLP sub-block ===
    ; normed = copy(x); layernorm(normed, ln2)
    mov rdi, [rel m3_normed]
    mov rsi, [rel m2_hidden_p]
    mov ecx, 4*768
    call m3_copy_dwords
    mov rax, [rel m3_normed]
    mov [rel m3_ln_src], rax
    mov rax, [rel m3_ln2g]
    mov [rel m3_ln_g], rax
    mov rax, [rel m3_ln2b]
    mov [rel m3_ln_b], rax
    call m3_layernorm4
    ; ff1 = normed @ fc_w (M=4,N=3072,K=768); ff1 += fc_b; gelu
    mov rdi, [rel m3_normed]
    mov rsi, [rel m3_fcw]
    mov rdx, [rel m3_ff1]
    mov ecx, 4
    mov r8d, 3072
    mov r9d, 768
    call simd_matmul
    mov rax, [rel m3_ff1]
    mov [rel m3_ba_buf], rax
    mov rax, [rel m3_fcb]
    mov [rel m3_ba_bias], rax
    mov edi, 4
    mov esi, 3072
    call m3_bias_add
    mov rdi, [rel m3_ff1]
    mov esi, 4*3072
    call gelu_accurate
    ; ff2 = ff1 @ fcp_w (M=4,N=768,K=3072); ff2 += fcp_b
    mov rdi, [rel m3_ff1]
    mov rsi, [rel m3_fpw]
    mov rdx, [rel m3_ff2]
    mov ecx, 4
    mov r8d, 768
    mov r9d, 3072
    call simd_matmul
    mov rax, [rel m3_ff2]
    mov [rel m3_ba_buf], rax
    mov rax, [rel m3_fpb]
    mov [rel m3_ba_bias], rax
    mov edi, 4
    mov esi, 768
    call m3_bias_add
    ; x += ff2
    mov rdi, [rel m2_hidden_p]
    mov rsi, [rel m3_ff2]
    mov ecx, 4*768
    call m3_resadd

    ; per-layer fingerprint
    call m3_fingerprint

    inc dword [rel m3_L]
    jmp .m3_layer
.m3_layers_done:

    ; --- final layernorm (ln_f, name_id 9000/9001) in place on x ---
    mov edi, 9000
    call llm_find_tensor
    mov [rel m3_ln_g], rax
    mov edi, 9001
    call llm_find_tensor
    mov [rel m3_ln_b], rax
    mov rax, [rel m2_hidden_p]
    mov [rel m3_ln_src], rax
    call m3_layernorm4
    mov dword [rel m3_L], 99           ; mark post_lnf
    call m3_fingerprint

    ; --- logits + argmax ---
    call m3_logits_argmax
    jmp .m3_ret
.m3_fail:
    lea rdi, [rel str_m3_fail]
    call serial_string
.m3_ret:
    pop rbx
    ret

; =============================================================================
; M4: autoregressive generation + tokens/sec. Reuses the M3 helpers but with a
; runtime sequence length (m3_seq) and the mutable m4_tokens buffer. Full
; recompute each step (no KV cache yet) — fine for a demo; TCG is the limiter.
; =============================================================================

; m4_embed: embed m4_tokens[0..m3_seq-1] into m2_hidden_p (wte[tok]+wpe[pos]).
; Quiet. Reuses m2_wte_p / m2_wpe_p resolved earlier.
m4_embed:
    push rbx
    push rbp
    xor ebp, ebp                       ; p
.m4e_pos:
    cmp ebp, [rel m3_seq]
    jge .m4e_done
    lea rbx, [rel m4_tokens]
    mov r9d, [rbx + rbp*4]             ; token id
    ; rsi = wte + token*768*4
    mov eax, r9d
    imul eax, 768*4
    mov rsi, [rel m2_wte_p]
    add rsi, rax
    ; rdx = wpe + p*768*4
    mov eax, ebp
    imul eax, 768*4
    mov rdx, [rel m2_wpe_p]
    add rdx, rax
    ; rdi = hidden + p*768*4
    mov eax, ebp
    imul eax, 768*4
    mov rdi, [rel m2_hidden_p]
    add rdi, rax
    xor ecx, ecx
.m4e_add:
    cmp ecx, 768
    jge .m4e_addend
    movss xmm0, [rsi + rcx*4]
    addss xmm0, [rdx + rcx*4]
    movss [rdi + rcx*4], xmm0
    inc ecx
    jmp .m4e_add
.m4e_addend:
    inc ebp
    jmp .m4e_pos
.m4e_done:
    pop rbp
    pop rbx
    ret

; m4_run_blocks: 6 GPT-2 blocks + ln_f over m3_seq positions (quiet). Hidden in
; m2_hidden_p, work buffers in the m3_* globals (sized for MAX_SEQ by caller).
m4_run_blocks:
    mov dword [rel m3_L], 0
.m4b_layer:
    mov eax, [rel m_nlayer]
    cmp dword [rel m3_L], eax
    jge .m4b_done
    ; resolve 12 tensors: name_id = 100 + L*20 + k
    mov edi, [rel m3_L]
    imul edi, 20
    add edi, 100
    push rdi                            ; save base_id on stack (find_tensor clobbers)
    call llm_find_tensor
    mov [rel m3_ln1g], rax
    mov edi, [rsp]
    add edi, 1
    call llm_find_tensor
    mov [rel m3_ln1b], rax
    mov edi, [rsp]
    add edi, 2
    call llm_find_tensor
    mov [rel m3_aw], rax
    mov edi, [rsp]
    add edi, 3
    call llm_find_tensor
    mov [rel m3_ab], rax
    mov edi, [rsp]
    add edi, 4
    call llm_find_tensor
    mov [rel m3_pw], rax
    mov edi, [rsp]
    add edi, 5
    call llm_find_tensor
    mov [rel m3_pb], rax
    mov edi, [rsp]
    add edi, 6
    call llm_find_tensor
    mov [rel m3_ln2g], rax
    mov edi, [rsp]
    add edi, 7
    call llm_find_tensor
    mov [rel m3_ln2b], rax
    mov edi, [rsp]
    add edi, 8
    call llm_find_tensor
    mov [rel m3_fcw], rax
    mov edi, [rsp]
    add edi, 9
    call llm_find_tensor
    mov [rel m3_fcb], rax
    mov edi, [rsp]
    add edi, 10
    call llm_find_tensor
    mov [rel m3_fpw], rax
    mov edi, [rsp]
    add edi, 11
    call llm_find_tensor
    mov [rel m3_fpb], rax
    pop rdi                             ; discard base_id

    ; --- attention sub-block ---
    mov rdi, [rel m3_normed]
    mov rsi, [rel m2_hidden_p]
    mov ecx, [rel m3_seq]
    imul ecx, 768
    call m3_copy_dwords
    mov rax, [rel m3_normed]
    mov [rel m3_ln_src], rax
    mov rax, [rel m3_ln1g]
    mov [rel m3_ln_g], rax
    mov rax, [rel m3_ln1b]
    mov [rel m3_ln_b], rax
    call m3_layernorm4
    mov rdi, [rel m3_normed]
    mov rsi, [rel m3_aw]
    mov rdx, [rel m3_qkv]
    mov ecx, [rel m3_seq]
    mov r8d, 2304
    mov r9d, 768
    call simd_matmul
    mov rax, [rel m3_qkv]
    mov [rel m3_ba_buf], rax
    mov rax, [rel m3_ab]
    mov [rel m3_ba_bias], rax
    mov edi, [rel m3_seq]
    mov esi, 2304
    call m3_bias_add
    call m3_attention
    mov rdi, [rel m3_attn]
    mov rsi, [rel m3_pw]
    mov rdx, [rel m3_proj]
    mov ecx, [rel m3_seq]
    mov r8d, 768
    mov r9d, 768
    call simd_matmul
    mov rax, [rel m3_proj]
    mov [rel m3_ba_buf], rax
    mov rax, [rel m3_pb]
    mov [rel m3_ba_bias], rax
    mov edi, [rel m3_seq]
    mov esi, 768
    call m3_bias_add
    mov rdi, [rel m2_hidden_p]
    mov rsi, [rel m3_proj]
    mov ecx, [rel m3_seq]
    imul ecx, 768
    call m3_resadd

    ; --- MLP sub-block ---
    mov rdi, [rel m3_normed]
    mov rsi, [rel m2_hidden_p]
    mov ecx, [rel m3_seq]
    imul ecx, 768
    call m3_copy_dwords
    mov rax, [rel m3_normed]
    mov [rel m3_ln_src], rax
    mov rax, [rel m3_ln2g]
    mov [rel m3_ln_g], rax
    mov rax, [rel m3_ln2b]
    mov [rel m3_ln_b], rax
    call m3_layernorm4
    mov rdi, [rel m3_normed]
    mov rsi, [rel m3_fcw]
    mov rdx, [rel m3_ff1]
    mov ecx, [rel m3_seq]
    mov r8d, 3072
    mov r9d, 768
    call simd_matmul
    mov rax, [rel m3_ff1]
    mov [rel m3_ba_buf], rax
    mov rax, [rel m3_fcb]
    mov [rel m3_ba_bias], rax
    mov edi, [rel m3_seq]
    mov esi, 3072
    call m3_bias_add
    mov rdi, [rel m3_ff1]
    mov eax, [rel m3_seq]
    imul eax, 3072
    mov esi, eax
    call gelu_accurate
    mov rdi, [rel m3_ff1]
    mov rsi, [rel m3_fpw]
    mov rdx, [rel m3_ff2]
    mov ecx, [rel m3_seq]
    mov r8d, 768
    mov r9d, 3072
    call simd_matmul
    mov rax, [rel m3_ff2]
    mov [rel m3_ba_buf], rax
    mov rax, [rel m3_fpb]
    mov [rel m3_ba_bias], rax
    mov edi, [rel m3_seq]
    mov esi, 768
    call m3_bias_add
    mov rdi, [rel m2_hidden_p]
    mov rsi, [rel m3_ff2]
    mov ecx, [rel m3_seq]
    imul ecx, 768
    call m3_resadd

    inc dword [rel m3_L]
    jmp .m4b_layer
.m4b_done:
    ; final ln_f
    mov edi, 9000
    call llm_find_tensor
    mov [rel m3_ln_g], rax
    mov edi, 9001
    call llm_find_tensor
    mov [rel m3_ln_b], rax
    mov rax, [rel m2_hidden_p]
    mov [rel m3_ln_src], rax
    call m3_layernorm4
    ret

; m4_argmax_last: argmax over vocab of the LAST position's logits (tied head).
; Stores the token id in m3_argmax_tok.
m4_argmax_last:
    ; last row = m2_hidden_p + (seq-1)*768*4
    mov eax, [rel m3_seq]
    dec eax
    imul eax, 768*4
    mov r8, [rel m2_hidden_p]
    add r8, rax
    mov r9, [rel m2_wte_p]
    mov eax, 0xFF800000
    movd xmm7, eax
    xor r10d, r10d
    xor r11d, r11d
.m4a_v:
    cmp r11d, 50257
    jge .m4a_done
    mov eax, r11d
    imul eax, 3072
    lea rsi, [r9 + rax]
    mov rdi, r8                        ; last-position hidden (ln_f output)
    call llm_dot768                    ; xmm0 = dot(hidden, wte[v])
    comiss xmm0, xmm7
    jbe .m4a_skip
    movaps xmm7, xmm0
    mov r10d, r11d
.m4a_skip:
    inc r11d
    jmp .m4a_v
.m4a_done:
    mov [rel m3_argmax_tok], r10d
    ret

; llm_m4_generate: greedy autoregressive generation of M4_NGEN tokens + tok/s.
llm_m4_generate:
    push rbx
    push r12
    push r13
    push r14
    push r15

    lea rdi, [rel str_m4_start]
    call serial_string

    ; seed m4_tokens with the prompt (464, 2068, 7586, 21831), seq=4
    lea rdi, [rel m4_tokens]
    lea rsi, [rel llm_m2_tokens]
    mov ecx, 4
    cld
    rep movsd
    mov dword [rel m3_seq], 4

    ; (re)allocate MAX_SEQ-sized buffers into the m3_* globals + m2_hidden_p
    mov edi, MAX_SEQ*768*4
    call kmalloc
    mov [rel m2_hidden_p], rax
    mov edi, MAX_SEQ*768*4
    call kmalloc
    mov [rel m3_normed], rax
    mov edi, MAX_SEQ*2304*4
    call kmalloc
    mov [rel m3_qkv], rax
    mov edi, MAX_SEQ*768*4
    call kmalloc
    mov [rel m3_attn], rax
    mov edi, MAX_SEQ*768*4
    call kmalloc
    mov [rel m3_proj], rax
    mov edi, MAX_SEQ*3072*4
    call kmalloc
    mov [rel m3_ff1], rax
    mov edi, MAX_SEQ*768*4
    call kmalloc
    mov [rel m3_ff2], rax

    ; timer start
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r15, rax                        ; r15 = start TSC

    ; print the prompt continuation tokens as we go
    lea rdi, [rel str_m4_gen]
    call serial_string

    xor r12d, r12d                      ; n = generated count
.m4_loop:
    cmp r12d, M4_NGEN
    jge .m4_loopdone
    ; m3_seq = 4 + n
    mov eax, r12d
    add eax, 4
    mov [rel m3_seq], eax
    call m4_embed
    call m4_run_blocks
    call m4_argmax_last
    ; append token: m4_tokens[seq] = argmax  (seq = current m3_seq)
    mov eax, [rel m3_seq]
    lea rbx, [rel m4_tokens]
    mov ecx, [rel m3_argmax_tok]
    mov [rbx + rax*4], ecx
    ; print "[LLMDEMO] M4 tok[n]=<id>" on its own line (robust vs serial chatter)
    lea rdi, [rel str_m4_tok]
    call serial_string
    mov edi, r12d
    call serial_decimal
    lea rdi, [rel str_m4_tok2]
    call serial_string
    mov edi, [rel m3_argmax_tok]
    call serial_decimal
    lea rdi, [rel str_ld_nl]
    call serial_string
    inc r12d
    jmp .m4_loop
.m4_loopdone:
    lea rdi, [rel str_ld_nl]
    call serial_string

    ; timer end + elapsed microseconds
    rdtsc
    shl rdx, 32
    or rax, rdx
    sub rax, r15                        ; delta TSC
    xor edx, edx
    mov rcx, [rel tsc_ticks_per_us]
    test rcx, rcx
    jz .m4_notime
    div rcx                             ; rax = elapsed microseconds
    mov r14, rax                        ; r14 = us
    lea rdi, [rel str_m4_us]
    call serial_string
    mov rdi, r14
    call serial_decimal
    lea rdi, [rel str_m4_us2]
    call serial_string
    mov edi, M4_NGEN
    call serial_decimal
    ; milli-tok/s = NGEN * 1e9 / us  (so 0.057 tok/s prints as 57)
    mov rax, M4_NGEN
    imul rax, 1000000000
    xor edx, edx
    mov rcx, r14
    test rcx, rcx
    jz .m4_notime
    div rcx
    mov r14, rax
    lea rdi, [rel str_m4_tps]
    call serial_string
    mov rdi, r14
    call serial_decimal
    lea rdi, [rel str_m4_tps2]
    call serial_string
.m4_notime:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

str_m4_start: db "[LLMDEMO] M4 autoregressive generation (greedy)...", 13, 10, 0
str_m4_gen:   db "[LLMDEMO] M4 greedy decode:", 13, 10, 0
str_m4_tok:   db "[LLMDEMO] M4 tok[", 0
str_m4_tok2:  db "]=", 0
str_m4_us:    db "[LLMDEMO] M4 elapsed_us=", 0
str_m4_us2:   db " ngen=", 0
str_m4_tps:   db " milli_tok_per_s(=tok/s*1000)=", 0
str_m4_tps2:  db 13, 10, 0

; =============================================================================
; M5: KV-cached autoregressive generation. Processes ONE position at a time;
; caches K,V per layer per position so each step's matmuls are M=1 (one row)
; and attention runs the new query against the cached K/V. Per-step forward cost
; is ~constant in the number of generated tokens (vs M4's O(seq) full recompute).
; Produces the SAME tokens as M4 — a speed optimization, not a behavior change.
; Cache layout: kv_k/kv_v are [6 layers][MAX_SEQ pos][768], element offset
; (L*MAX_SEQ + pos)*768.
; =============================================================================

; m5_attention: single-query (m5_qkv q-block, [0:768]) attends to cached K/V for
; layer m5_L over positions 0..m5_pos. Writes m5_attn[768]. 12 heads, hd=64.
m5_attention:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    ; cache element base for this layer = L*MAX_SEQ*768
    mov eax, [rel m5_L]
    imul eax, MAX_SEQ*768
    mov r13d, eax                      ; r13 = layer element base
    mov r12, [rel m5_qkv]              ; q base (q is [0:768])
    xor ebx, ebx                       ; h
.m5a_h:
    cmp ebx, 12
    jge .m5a_done
    ; scores[j] = (q_h . k_j_h) * 0.125, j = 0..pos
    xor ebp, ebp                       ; j
.m5a_j:
    cmp ebp, [rel m5_pos]
    jg .m5a_jdone
    mov eax, ebx
    shl eax, 8                         ; h*256
    lea rsi, [r12 + rax]               ; q_h
    ; k_j_h = kv_k + (base + j*768 + h*64)*4
    mov rdi, [rel kv_k]
    mov eax, ebp
    imul eax, 768
    add eax, r13d                      ; base + j*768
    lea rdi, [rdi + rax*4]
    mov eax, ebx
    shl eax, 8
    add rdi, rax                       ; + h*64*4
    xorps xmm0, xmm0
    xor ecx, ecx
.m5a_dot:
    cmp ecx, 64
    jge .m5a_dotd
    movss xmm1, [rsi + rcx*4]
    mulss xmm1, [rdi + rcx*4]
    addss xmm0, xmm1
    inc ecx
    jmp .m5a_dot
.m5a_dotd:
    mov eax, 0x3E000000
    movd xmm2, eax
    mulss xmm0, xmm2
    lea r8, [rel m3_scores]
    movss [r8 + rbp*4], xmm0
    inc ebp
    jmp .m5a_j
.m5a_jdone:
    lea rdi, [rel m3_scores]
    mov esi, [rel m5_pos]
    inc esi
    call softmax                       ; clobbers r15 (not preserved) — recompute below
    ; out[h*64+d] = sum_j scores[j] * V_j_h[d]
    mov r9, [rel m5_attn]
    mov eax, ebx
    shl eax, 8
    add r9, rax                        ; out_h
    xor ecx, ecx                       ; d
.m5a_outd:
    cmp ecx, 64
    jge .m5a_outdd
    xorps xmm0, xmm0
    xor ebp, ebp                       ; j
.m5a_outj:
    cmp ebp, [rel m5_pos]
    jg .m5a_outjd
    lea r8, [rel m3_scores]
    movss xmm1, [r8 + rbp*4]
    ; v_j_h = kv_v + (base + j*768 + h*64)*4
    mov r10, [rel kv_v]
    mov eax, ebp
    imul eax, 768
    add eax, r13d
    lea r10, [r10 + rax*4]
    mov eax, ebx
    shl eax, 8
    add r10, rax
    movss xmm2, [r10 + rcx*4]
    mulss xmm1, xmm2
    addss xmm0, xmm1
    inc ebp
    jmp .m5a_outj
.m5a_outjd:
    movss [r9 + rcx*4], xmm0
    inc ecx
    jmp .m5a_outd
.m5a_outdd:
    inc ebx
    jmp .m5a_h
.m5a_done:
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; m5_store_kv: copy K (m5_qkv[768:1536]) and V (m5_qkv[1536:2304]) into the cache
; at layer m5_L, position m5_pos.
m5_store_kv:
    mov eax, [rel m5_L]
    imul eax, MAX_SEQ
    add eax, [rel m5_pos]
    imul eax, 768                      ; element offset = (L*MAX_SEQ+pos)*768
    mov r8d, eax                       ; r8 = element offset (survives rep movsd)
    mov rdi, [rel kv_k]
    lea rdi, [rdi + r8*4]
    mov rsi, [rel m5_qkv]
    add rsi, 768*4                     ; K block
    mov ecx, 768
    cld
    rep movsd
    mov rdi, [rel kv_v]
    lea rdi, [rdi + r8*4]
    mov rsi, [rel m5_qkv]
    add rsi, 1536*4                    ; V block
    mov ecx, 768
    rep movsd
    ret

; m5_step: process one position (token=m5_token, pos=m5_pos) through all 6 layers
; using the KV cache. Result hidden left in m5_hidden.
m5_step:
    ; --- embed: m5_hidden = wte[token] + wpe[pos] ---
    mov r9d, [rel m5_token]
    mov eax, r9d
    imul eax, 768*4
    mov rsi, [rel m2_wte_p]
    add rsi, rax
    mov eax, [rel m5_pos]
    imul eax, 768*4
    mov rdx, [rel m2_wpe_p]
    add rdx, rax
    mov rdi, [rel m5_hidden]
    xor ecx, ecx
.m5s_emb:
    cmp ecx, 768
    jge .m5s_embd
    movss xmm0, [rsi + rcx*4]
    addss xmm0, [rdx + rcx*4]
    movss [rdi + rcx*4], xmm0
    inc ecx
    jmp .m5s_emb
.m5s_embd:
    mov dword [rel m5_L], 0
.m5s_layer:
    mov eax, [rel m_nlayer]
    cmp dword [rel m5_L], eax
    jge .m5s_done
    ; resolve 12 tensors: name_id = 100 + L*20 + k
    mov edi, [rel m5_L]
    imul edi, 20
    add edi, 100
    push rdi
    call llm_find_tensor
    mov [rel m3_ln1g], rax
    mov edi, [rsp]
    add edi, 1
    call llm_find_tensor
    mov [rel m3_ln1b], rax
    mov edi, [rsp]
    add edi, 2
    call llm_find_tensor
    mov [rel m3_aw], rax
    mov edi, [rsp]
    add edi, 3
    call llm_find_tensor
    mov [rel m3_ab], rax
    mov edi, [rsp]
    add edi, 4
    call llm_find_tensor
    mov [rel m3_pw], rax
    mov edi, [rsp]
    add edi, 5
    call llm_find_tensor
    mov [rel m3_pb], rax
    mov edi, [rsp]
    add edi, 6
    call llm_find_tensor
    mov [rel m3_ln2g], rax
    mov edi, [rsp]
    add edi, 7
    call llm_find_tensor
    mov [rel m3_ln2b], rax
    mov edi, [rsp]
    add edi, 8
    call llm_find_tensor
    mov [rel m3_fcw], rax
    mov edi, [rsp]
    add edi, 9
    call llm_find_tensor
    mov [rel m3_fcb], rax
    mov edi, [rsp]
    add edi, 10
    call llm_find_tensor
    mov [rel m3_fpw], rax
    mov edi, [rsp]
    add edi, 11
    call llm_find_tensor
    mov [rel m3_fpb], rax
    pop rdi

    ; --- attention sub-block (single row) ---
    mov rdi, [rel m5_normed]
    mov rsi, [rel m5_hidden]
    mov ecx, 768
    call m3_copy_dwords
    mov rdi, [rel m5_normed]
    mov rsi, [rel m3_ln1g]
    mov rdx, [rel m3_ln1b]
    mov ecx, 768
    call layernorm
    ; qkv = normed @ c_attn + b   (M=1,N=2304,K=768)
    mov rdi, [rel m5_normed]
    mov rsi, [rel m3_aw]
    mov rdx, [rel m5_qkv]
    mov ecx, 1
    mov r8d, 2304
    mov r9d, 768
    call cog_matmul
    jc .m5s_failed
    mov rax, [rel m5_qkv]
    mov [rel m3_ba_buf], rax
    mov rax, [rel m3_ab]
    mov [rel m3_ba_bias], rax
    mov edi, 1
    mov esi, 2304
    call m3_bias_add
    call m5_store_kv
    call m5_attention
    ; proj = attn @ c_proj + b  (M=1,N=768,K=768)
    mov rdi, [rel m5_attn]
    mov rsi, [rel m3_pw]
    mov rdx, [rel m5_proj]
    mov ecx, 1
    mov r8d, 768
    mov r9d, 768
    call cog_matmul
    jc .m5s_failed
    mov rax, [rel m5_proj]
    mov [rel m3_ba_buf], rax
    mov rax, [rel m3_pb]
    mov [rel m3_ba_bias], rax
    mov edi, 1
    mov esi, 768
    call m3_bias_add
    ; hidden += proj
    mov rdi, [rel m5_hidden]
    mov rsi, [rel m5_proj]
    mov ecx, 768
    call m3_resadd

    ; --- MLP sub-block (single row) ---
    mov rdi, [rel m5_normed]
    mov rsi, [rel m5_hidden]
    mov ecx, 768
    call m3_copy_dwords
    mov rdi, [rel m5_normed]
    mov rsi, [rel m3_ln2g]
    mov rdx, [rel m3_ln2b]
    mov ecx, 768
    call layernorm
    mov rdi, [rel m5_normed]
    mov rsi, [rel m3_fcw]
    mov rdx, [rel m5_ff1]
    mov ecx, 1
    mov r8d, 3072
    mov r9d, 768
    call cog_matmul
    jc .m5s_failed
    mov rax, [rel m5_ff1]
    mov [rel m3_ba_buf], rax
    mov rax, [rel m3_fcb]
    mov [rel m3_ba_bias], rax
    mov edi, 1
    mov esi, 3072
    call m3_bias_add
    mov rdi, [rel m5_ff1]
    mov esi, 3072
    call gelu_accurate
    mov rdi, [rel m5_ff1]
    mov rsi, [rel m3_fpw]
    mov rdx, [rel m5_ff2]
    mov ecx, 1
    mov r8d, 768
    mov r9d, 3072
    call cog_matmul
    jc .m5s_failed
    mov rax, [rel m5_ff2]
    mov [rel m3_ba_buf], rax
    mov rax, [rel m3_fpb]
    mov [rel m3_ba_bias], rax
    mov edi, 1
    mov esi, 768
    call m3_bias_add
    mov rdi, [rel m5_hidden]
    mov rsi, [rel m5_ff2]
    mov ecx, 768
    call m3_resadd

    inc dword [rel m5_L]
    jmp .m5s_layer
.m5s_done:
    clc
    ret
.m5s_failed:
    stc
    ret

; m5_predict: ln_f(m5_hidden) then argmax over vocab -> m3_argmax_tok.
; Preserves r12 (the caller's generation-loop position counter).
m5_predict:
    push r12
    mov rdi, [rel m5_normed]
    mov rsi, [rel m5_hidden]
    mov ecx, 768
    call m3_copy_dwords
    mov edi, 9000
    call llm_find_tensor
    mov r12, rax                       ; lnf_g (find_tensor + layernorm preserve r12)
    mov edi, 9001
    call llm_find_tensor
    mov rdi, [rel m5_normed]
    mov rsi, r12                       ; lnf_g
    mov rdx, rax                       ; lnf_b
    mov ecx, 768
    call layernorm
    ; argmax: logit[v] = dot(normed, wte[v])
    mov r8, [rel m5_normed]
    mov r9, [rel m2_wte_p]
    mov eax, 0xFF800000
    movd xmm7, eax
    xor r10d, r10d
    xor r11d, r11d
.m5p_v:
    cmp r11d, 50257
    jge .m5p_done
    mov eax, r11d
    imul eax, 3072
    lea rsi, [r9 + rax]
    mov rdi, r8                        ; hidden (ln_f output)
    call llm_dot768                    ; xmm0 = dot(hidden, wte[v])
    mov rax, [rel m5_logits]           ; store logit for the top-5 accuracy dump
    movss [rax + r11*4], xmm0
    comiss xmm0, xmm7
    jbe .m5p_skip
    movaps xmm7, xmm0
    mov r10d, r11d
.m5p_skip:
    inc r11d
    jmp .m5p_v
.m5p_done:
    mov [rel m3_argmax_tok], r10d
    pop r12
    ret

; m5_dump_top5: emit the top-5 (id=rawfp32-logit) of the buffered logits, for the
; host benchmark.py to compare to the oracle (top-k overlap + per-token logit error).
; Destructive (sets each emitted entry to -inf) — only called once (first prediction).
m5_dump_top5:
    push rbx
    push r12
    push r13
    lea rdi, [rel str_m5_top5]
    call serial_string
    mov r12, [rel m5_logits]
    xor r13d, r13d                     ; k = 0..4
.t5_outer:
    cmp r13d, 5
    jge .t5_done
    mov eax, 0xFF800000
    movd xmm7, eax
    xor ebx, ebx                       ; argmax index
    xor ecx, ecx                       ; v
.t5_scan:
    cmp ecx, 50257
    jge .t5_emit
    movss xmm0, [r12 + rcx*4]
    comiss xmm0, xmm7
    jbe .t5_next
    movaps xmm7, xmm0
    mov ebx, ecx
.t5_next:
    inc ecx
    jmp .t5_scan
.t5_emit:
    mov dil, ' '
    call serial_char
    mov edi, ebx
    call serial_decimal
    mov dil, '='
    call serial_char
    mov rax, [rel m5_logits]
    mov edi, [rax + rbx*4]             ; raw fp32 bits of the logit
    call serial_hex32
    mov rax, [rel m5_logits]           ; mark emitted = -inf
    mov dword [rax + rbx*4], 0xFF800000
    inc r13d
    jmp .t5_outer
.t5_done:
    lea rdi, [rel str_ld_nl]
    call serial_string
    pop r13
    pop r12
    pop rbx
    ret

; serial_write_n: write ESI raw bytes from [RDI] to serial (not null-terminated).
serial_write_n:
    push rbx
    push r12
    push r13
    mov r12, rdi
    mov r13d, esi
    xor ebx, ebx
.swn_loop:
    cmp ebx, r13d
    jge .swn_done
    movzx edi, byte [r12 + rbx]
    call serial_char
    inc ebx
    jmp .swn_loop
.swn_done:
    pop r13
    pop r12
    pop rbx
    ret

; m5_detokenize: print the M4_NGEN generated tokens as real text, using the TVOC
; token->bytes table at TOKVOCAB_PHYS. Graceful skip if the table isn't present.
m5_detokenize:
    mov rsi, [rel tokvocab_base]
    mov eax, [rsi]
    cmp eax, TVOC_MAGIC
    jne .dt_skip
    lea rdi, [rel str_m5_text]
    call serial_string
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r14, [rel tokvocab_base]
    mov r15d, [r14 + 8]                ; data_offset
    xor r13d, r13d                     ; k = 0..M4_NGEN-1
.dt_loop:
    cmp r13d, M4_NGEN
    jge .dt_done
    ; tok = m4_tokens[gen_prompt_len + k]
    mov eax, [rel gen_prompt_len]
    add eax, r13d
    lea rbx, [rel m4_tokens]
    mov r12d, [rbx + rax*4]            ; token id
    ; start = offsets[tok], end = offsets[tok+1]  (offset table at base+12)
    lea rsi, [r14 + 12]
    mov eax, r12d
    mov ecx, [rsi + rax*4]             ; start
    mov edx, [rsi + rax*4 + 4]         ; end
    ; strptr = base + data_offset + start ; len = end - start
    mov rdi, r14
    mov eax, r15d
    add rdi, rax                       ; + data_offset
    mov eax, ecx
    add rdi, rax                       ; + start
    mov esi, edx
    sub esi, ecx                       ; len
    call serial_write_n
    inc r13d
    jmp .dt_loop
.dt_done:
    lea rdi, [rel str_ld_nl]
    call serial_string
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
.dt_skip:
    ret

; llm_m5_generate: KV-cached greedy generation of M4_NGEN tokens + tok/s.
; llm_m5_generate: full-demo entry — seed the default prompt, then run the core.
llm_m5_generate:
%if COG_MODEL_ENABLED = 0
    xor eax, eax
    ret
%else
    lea rdi, [rel m4_tokens]
    lea rsi, [rel llm_m2_tokens]
    mov ecx, 4
    cld
    rep movsd
    mov dword [rel gen_prompt_len], 4
    jmp m5_generate_core               ; tail-call (core returns to our caller)

%endif

; Allocate the activation/KV/logit working set once.  MODELRUN reuses these
; buffers and recomputes the forward pass on every call; the general bump heap
; therefore does not leak one activation set per UDP request.
m5_prepare_buffers:
    cmp byte [rel m5_buffers_state], 1
    je .ready
    cmp byte [rel m5_buffers_state], 2
    je .fail
    mov edi, 768*4
    call kmalloc
    test rax, rax
    jz .mark_fail
    mov [rel m5_hidden], rax
    mov edi, 768*4
    call kmalloc
    test rax, rax
    jz .mark_fail
    mov [rel m5_normed], rax
    mov edi, 2304*4
    call kmalloc
    test rax, rax
    jz .mark_fail
    mov [rel m5_qkv], rax
    mov edi, 768*4
    call kmalloc
    test rax, rax
    jz .mark_fail
    mov [rel m5_attn], rax
    mov edi, 768*4
    call kmalloc
    test rax, rax
    jz .mark_fail
    mov [rel m5_proj], rax
    mov edi, 3072*4
    call kmalloc
    test rax, rax
    jz .mark_fail
    mov [rel m5_ff1], rax
    mov edi, 768*4
    call kmalloc
    test rax, rax
    jz .mark_fail
    mov [rel m5_ff2], rax
    mov edi, MAX_LAYER*MAX_SEQ*768*4
    call kmalloc
    test rax, rax
    jz .mark_fail
    mov [rel kv_k], rax
    mov edi, MAX_LAYER*MAX_SEQ*768*4
    call kmalloc
    test rax, rax
    jz .mark_fail
    mov [rel kv_v], rax
    mov edi, 50257*4
    call kmalloc
    test rax, rax
    jz .mark_fail
    mov [rel m5_logits], rax
    mov byte [rel m5_buffers_state], 1
.ready:
    xor eax, eax
    ret
.mark_fail:
    mov byte [rel m5_buffers_state], 2
.fail:
    mov eax, -1
    ret

; m5_generate_core: KV-cached greedy generation of M4_NGEN tokens. Assumes
; m4_tokens[0..gen_prompt_len-1] hold the prompt and gen_prompt_len is set
; (so LLMGEN can drive it with an arbitrary host-tokenized prompt).
m5_generate_core:
%if COG_MODEL_ENABLED = 0
    xor eax, eax
    ret
%else
    push rbx
    push r12
    push r13
    push r14
    push r15

    call m5_prepare_buffers
    test eax, eax
    jnz .m5g_alloc_fail

    lea rdi, [rel str_m5_start]
    call serial_string

    ; n_layer from PXG2 header (dynamic: 6=distilgpt2, 12=gpt2-124M)
    mov rax, [rel model_base]
    mov eax, [rax + 8]
    mov [rel m_nlayer], eax
    ; resolve wte/wpe so this runs standalone (not only after M2)
    xor edi, edi
    call llm_find_tensor
    mov [rel m2_wte_p], rax
    test rax, rax
    jz .m5g_alloc_fail
    mov edi, 1
    call llm_find_tensor
    mov [rel m2_wpe_p], rax
    test rax, rax
    jz .m5g_alloc_fail

    rdtsc
    shl rdx, 32
    or rax, rdx
    mov r15, rax                       ; start TSC

    lea rdi, [rel str_m5_gen]
    call serial_string

    xor r12d, r12d                     ; pos
    xor r13d, r13d                     ; generated count
.m5g_loop:
    ; process positions 0 .. (gen_prompt_len + M4_NGEN - 2)
    mov eax, [rel gen_prompt_len]
    add eax, M4_NGEN - 1
    cmp r12d, eax
    jge .m5g_done
    ; token = m4_tokens[pos]
    lea rbx, [rel m4_tokens]
    mov eax, [rbx + r12*4]
    mov [rel m5_token], eax
    mov [rel m5_pos], r12d
    call m5_step
    jc .m5g_alloc_fail
    ; predict once we're at/after the last prompt token (pos >= prompt_len-1)
    mov eax, [rel gen_prompt_len]
    dec eax
    cmp r12d, eax
    jl .m5g_next
    call m5_predict
    ; on the FIRST prediction (== oracle logits.bin position) dump top-5 for accuracy
    test r13d, r13d
    jnz .m5g_t5done
    cmp byte [rel cog_scale_measuring], 0
    jne .m5g_t5done                      ; keep the entire logits output intact for hashing
    call m5_dump_top5
.m5g_t5done:
    ; append: m4_tokens[pos+1] = argmax
    lea rbx, [rel m4_tokens]
    mov eax, r12d
    inc eax
    mov ecx, [rel m3_argmax_tok]
    mov [rbx + rax*4], ecx
    ; print "[LLMDEMO] M5 tok[n]=<id>"
    lea rdi, [rel str_m5_tok]
    call serial_string
    mov edi, r13d
    call serial_decimal
    lea rdi, [rel str_m4_tok2]
    call serial_string
    mov edi, [rel m3_argmax_tok]
    call serial_decimal
    lea rdi, [rel str_ld_nl]
    call serial_string
    inc r13d
.m5g_next:
    inc r12d
    jmp .m5g_loop
.m5g_done:
    rdtsc
    shl rdx, 32
    or rax, rdx
    sub rax, r15
    xor edx, edx
    mov rcx, [rel tsc_ticks_per_us]
    test rcx, rcx
    jz .m5g_notime
    div rcx
    mov r14, rax                       ; us
    lea rdi, [rel str_m5_us]
    call serial_string
    mov rdi, r14
    call serial_decimal
    lea rdi, [rel str_m4_us2]
    call serial_string
    mov edi, M4_NGEN
    call serial_decimal
    mov rax, M4_NGEN
    imul rax, 1000000000
    xor edx, edx
    mov rcx, r14
    test rcx, rcx
    jz .m5g_notime
    div rcx
    mov r14, rax
    lea rdi, [rel str_m4_tps]
    call serial_string
    mov rdi, r14
    call serial_decimal
    lea rdi, [rel str_m4_tps2]
    call serial_string
.m5g_notime:
    call m5_detokenize                 ; print the generated tokens as real text
    xor eax, eax
    jmp .m5g_return
.m5g_alloc_fail:
    mov eax, -1
.m5g_return:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

%endif

; llm_gen_cmd: parse space-separated decimal token ids from the "LLMGEN ..." cmd
; into m4_tokens, set gen_prompt_len, then run KV-cached generation on them.
;   RDI = ptr to args (after "LLMGEN"), ESI = remaining length.
llm_gen_cmd:
%if COG_MODEL_ENABLED = 0
    xor eax, eax
    ret
%else
    push rbx
    push r12
    push r13
    push r14
    mov r12, rdi                       ; cursor
    mov r13d, esi                      ; remaining length
    lea r14, [rel m4_tokens]
    xor ebx, ebx                       ; token count
.gc_scan:
    test r13d, r13d
    jz .gc_end
    movzx eax, byte [r12]
    cmp al, '0'
    jb .gc_skip
    cmp al, '9'
    ja .gc_skip
    ; accumulate a decimal number
    xor ecx, ecx
.gc_digit:
    test r13d, r13d
    jz .gc_store
    movzx eax, byte [r12]
    cmp al, '0'
    jb .gc_store
    cmp al, '9'
    ja .gc_store
    sub eax, '0'
    imul ecx, ecx, 10
    add ecx, eax
    inc r12
    dec r13d
    jmp .gc_digit
.gc_store:
    cmp ebx, MAX_SEQ - M4_NGEN          ; bound the prompt so prompt+gen <= MAX_SEQ
    jae .gc_scan
    mov [r14 + rbx*4], ecx
    inc ebx
    jmp .gc_scan
.gc_skip:
    inc r12
    dec r13d
    jmp .gc_scan
.gc_end:
    test ebx, ebx
    jz .gc_none                        ; no tokens parsed
    mov [rel gen_prompt_len], ebx
    pop r14
    pop r13
    pop r12
    pop rbx
    jmp m5_generate_core               ; tail-call (returns to net_boot_handler)
.gc_none:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

%endif

; =============================================================================
; On-device GPT-2 BPE encoder (recipe build_bpe.py). Works in RAW BYTE space
; (byte_encoder is a bijection, so BPE is equivalent on raw bytes — proven in
; build_bpe.py). Uses the BPEM merges table @BPEM_PHYS + the TVOC token->bytes
; table @TOKVOCAB_PHYS (reverse-scanned for bytes->id). "LLMTXT <text>" command.
; Subset pre-tokenizer (optional leading space + a run of one char class) — exact
; for the demo's English prompts. Each final BPE token -> id into m4_tokens.
; =============================================================================

; bpe_memeq: ECX bytes at [RDI] == [RSI]? -> EAX=1/0. Clobbers EAX,EDX only.
bpe_memeq:
    xor edx, edx
.me_loop:
    cmp edx, ecx
    jge .me_eq
    mov al, [rdi + rdx]
    cmp al, [rsi + rdx]
    jne .me_ne
    inc edx
    jmp .me_loop
.me_eq:
    mov eax, 1
    ret
.me_ne:
    xor eax, eax
    ret

; bpe_class: AL=char -> EAX (0=space,1=letter,2=digit,3=punct). Preserves all but EAX.
bpe_class:
    cmp al, ' '
    je .cl_sp
    cmp al, '0'
    jb .cl_pu
    cmp al, '9'
    jbe .cl_di
    cmp al, 'A'
    jb .cl_pu
    cmp al, 'Z'
    jbe .cl_le
    cmp al, 'a'
    jb .cl_pu
    cmp al, 'z'
    jbe .cl_le
.cl_pu:
    mov eax, 3
    ret
.cl_sp:
    xor eax, eax
    ret
.cl_le:
    mov eax, 1
    ret
.cl_di:
    mov eax, 2
    ret

; bpe_merge_rank: rank of merge (Lptr[Llen], Rptr[Rlen]) or 0x7FFFFFFF if none.
;   RDI=Lptr ESI=Llen RDX=Rptr ECX=Rlen -> EAX=rank. (bpe_memeq preserves r8-r11.)
bpe_merge_rank:
    mov [rel bpe_Lptr], rdi
    mov [rel bpe_Llen], esi
    mov [rel bpe_Rptr], rdx
    mov [rel bpe_Rlen], ecx
    mov rax, [rel bpem_base]
    mov edx, [rax]
    cmp edx, BPEM_MAGIC
    jne .mr_none
    xor r9d, r9d                       ; r (loop counter, survives bpe_memeq)
.mr_loop:
    mov rax, [rel bpem_base]
    cmp r9d, [rax + 4]                 ; count
    jge .mr_none
    lea r8, [rax + 12]                 ; entries base
    mov r10d, r9d
    shl r10d, 3
    add r8, r10                        ; r8 = entry r
    movzx edx, word [r8 + 4]           ; left_len
    cmp edx, [rel bpe_Llen]
    jne .mr_next
    movzx edx, word [r8 + 6]           ; right_len
    cmp edx, [rel bpe_Rlen]
    jne .mr_next
    ; p = BPEM_PHYS + pool_off + pair_off
    mov rax, [rel bpem_base]
    mov edx, [rax + 8]                 ; pool_off
    add rax, rdx
    mov edx, [r8]                      ; pair_off
    add rax, rdx
    mov [rel bpe_p], rax
    mov rdi, rax
    mov rsi, [rel bpe_Lptr]
    mov ecx, [rel bpe_Llen]
    call bpe_memeq
    test eax, eax
    jz .mr_next
    mov rdi, [rel bpe_p]
    mov edx, [rel bpe_Llen]
    add rdi, rdx                       ; p + Llen
    mov rsi, [rel bpe_Rptr]
    mov ecx, [rel bpe_Rlen]
    call bpe_memeq
    test eax, eax
    jz .mr_next
    mov eax, r9d                       ; match -> rank
    ret
.mr_next:
    inc r9d
    jmp .mr_loop
.mr_none:
    mov eax, 0x7FFFFFFF
    ret

; bpe_vocab_lookup: id of the token whose raw bytes == [RDI][ESI], or 0xFFFFFFFF.
bpe_vocab_lookup:
    mov [rel bpe_Lptr], rdi
    mov [rel bpe_Llen], esi
    mov rax, [rel tokvocab_base]
    mov r8d, [rax + 8]                 ; data_off
    xor r9d, r9d                       ; v
.vl_loop:
    cmp r9d, 50257
    jge .vl_none
    mov rax, [rel tokvocab_base]
    lea r10, [rax + 12]                ; offset table
    mov edx, [r10 + r9*4]              ; start
    mov ecx, [r10 + r9*4 + 4]          ; end
    mov r11d, ecx
    sub r11d, edx                      ; token byte length
    cmp r11d, [rel bpe_Llen]
    jne .vl_next
    mov rdi, [rel tokvocab_base]
    mov eax, r8d
    add rdi, rax                       ; + data_off
    mov eax, edx
    add rdi, rax                       ; + start
    mov rsi, [rel bpe_Lptr]
    mov ecx, [rel bpe_Llen]
    call bpe_memeq
    test eax, eax
    jnz .vl_found
.vl_next:
    inc r9d
    jmp .vl_loop
.vl_found:
    mov eax, r9d
    ret
.vl_none:
    mov eax, 0xFFFFFFFF
    ret

; bpe_encode_chunk: BPE one chunk (RDI=cbuf, ESI=clen), append token ids to
; m4_tokens (index bpe_ntok). Segments are contiguous spans; bpe_seg_len[] holds
; their byte lengths.
bpe_encode_chunk:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi                       ; cbuf
    mov r13d, esi                      ; clen
    lea r14, [rel bpe_seg_len]
    ; init: one segment per byte
    xor ecx, ecx
.ec_init:
    cmp ecx, r13d
    jge .ec_initd
    mov dword [r14 + rcx*4], 1
    inc ecx
    jmp .ec_init
.ec_initd:
    mov [rel bpe_seg_count], r13d
.ec_mergeloop:
    mov eax, [rel bpe_seg_count]
    cmp eax, 1
    jle .ec_emit
    mov dword [rel bpe_best_rank], 0x7FFFFFFF
    mov dword [rel bpe_best_i], -1
    xor ebx, ebx                       ; i
    xor r15d, r15d                     ; pos
.ec_find:
    mov eax, [rel bpe_seg_count]
    dec eax
    cmp ebx, eax                       ; i < seg_count-1 ?
    jge .ec_finddone
    mov esi, [r14 + rbx*4]             ; Llen
    lea rdi, [r12 + r15]               ; Lptr
    mov eax, ebx
    inc eax
    mov ecx, [r14 + rax*4]             ; Rlen
    lea rdx, [r12 + r15]
    movsxd rax, esi
    add rdx, rax                       ; Rptr = cbuf + pos + Llen
    call bpe_merge_rank                ; EAX = rank (preserves rbx,r12-r15)
    cmp eax, [rel bpe_best_rank]
    jge .ec_findnext
    mov [rel bpe_best_rank], eax
    mov [rel bpe_best_i], ebx
.ec_findnext:
    mov eax, [r14 + rbx*4]
    add r15d, eax                      ; pos += seg_len[i]
    inc ebx
    jmp .ec_find
.ec_finddone:
    mov eax, [rel bpe_best_i]
    cmp eax, 0
    jl .ec_emit                        ; no mergeable pair -> done
    mov ebx, eax                       ; bi
    ; seg_len[bi] += seg_len[bi+1]
    mov eax, ebx
    inc eax
    mov ecx, [r14 + rax*4]
    add [r14 + rbx*4], ecx
    ; shift seg_len[bi+1 .. count-2] <- [bi+2 .. count-1]
    mov eax, ebx
    inc eax                            ; j = bi+1
.ec_shift:
    mov ecx, [rel bpe_seg_count]
    dec ecx
    cmp eax, ecx                       ; j < count-1 ?
    jge .ec_shiftd
    mov ecx, [r14 + rax*4 + 4]
    mov [r14 + rax*4], ecx
    inc eax
    jmp .ec_shift
.ec_shiftd:
    dec dword [rel bpe_seg_count]
    jmp .ec_mergeloop
.ec_emit:
    xor ebx, ebx                       ; i
    xor r15d, r15d                     ; pos
.ec_emitl:
    cmp ebx, [rel bpe_seg_count]
    jge .ec_emitd
    mov esi, [r14 + rbx*4]
    lea rdi, [r12 + r15]
    call bpe_vocab_lookup              ; EAX = id
    mov ecx, [rel bpe_ntok]
    lea rdx, [rel m4_tokens]
    mov [rdx + rcx*4], eax
    inc dword [rel bpe_ntok]
    mov eax, [r14 + rbx*4]
    add r15d, eax
    inc ebx
    jmp .ec_emitl
.ec_emitd:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; llm_txt_cmd: RDI=text, ESI=len. Pre-tokenize + BPE-encode into m4_tokens, set
; gen_prompt_len, then run KV-cached generation.
llm_txt_cmd:
%if COG_MODEL_ENABLED = 0
    ret
%else
    push rbx
    push r12
    push r13
    push r14
    mov r12, rdi                       ; text
    mov r13d, esi                      ; len
    mov dword [rel bpe_ntok], 0
    xor ebx, ebx                       ; i
.tx_loop:
    cmp ebx, r13d
    jge .tx_done
    mov r14d, ebx                      ; chunk start
    movzx eax, byte [r12 + rbx]
    cmp al, ' '                        ; optional one leading space
    jne .tx_nospace
    inc ebx
.tx_nospace:
    cmp ebx, r13d
    jge .tx_emit
    movzx eax, byte [r12 + rbx]
    call bpe_class
    mov ecx, eax                       ; cls
.tx_run:
    cmp ebx, r13d
    jge .tx_emit
    movzx eax, byte [r12 + rbx]
    cmp al, ' '
    je .tx_emit
    push rcx
    call bpe_class
    pop rcx
    cmp eax, ecx
    jne .tx_emit
    inc ebx
    jmp .tx_run
.tx_emit:
    lea rdi, [r12 + r14]               ; chunk ptr
    mov esi, ebx
    sub esi, r14d                      ; chunk len
    test esi, esi
    jz .tx_loop
    call bpe_encode_chunk
    jmp .tx_loop
.tx_done:
    ; debug: print the on-device-encoded token ids
    lea rdi, [rel str_enc]
    call serial_string
    xor r14d, r14d
.tx_dbg:
    cmp r14d, [rel bpe_ntok]
    jge .tx_dbgd
    mov dil, ' '
    call serial_char
    lea rax, [rel m4_tokens]
    mov edi, [rax + r14*4]
    call serial_decimal
    inc r14d
    jmp .tx_dbg
.tx_dbgd:
    lea rdi, [rel str_ld_nl]
    call serial_string
    mov eax, [rel bpe_ntok]
    test eax, eax
    jz .tx_ret                         ; nothing parsed
    mov [rel gen_prompt_len], eax
    pop r14
    pop r13
    pop r12
    pop rbx
    jmp m5_generate_core               ; tail-call
.tx_ret:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
%endif

; BPE encoder state
bpe_seg_len:   times 256 dd 0
bpe_seg_count: dd 0
bpe_best_rank: dd 0
bpe_best_i:    dd 0
bpe_ntok:      dd 0
bpe_Lptr:      dq 0
bpe_Llen:      dd 0
bpe_Rptr:      dq 0
bpe_Rlen:      dd 0
bpe_p:         dq 0

; =============================================================================
; Bare-metal model load.  The source is the descriptor-selected Samsung FAT32
; partition, never an ESP chosen by mount order.  MODEL.PXG uses the dedicated
; high model heap; small optional tokenizer blobs use the ordinary heap.
; =============================================================================
; cpu_llm_load_blob: stat, allocate the EXACT file size, stream via VFS, and
; validate the 4-byte magic. RDI=path, ESI=path_len, EDX=magic, ECX=maxsize.
; Returns RAX=buffer ptr on success, 0 on any failure.
cpu_llm_load_blob:
%if COG_MODEL_ENABLED = 0
    xor eax, eax
    ret
%else
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi                       ; path
    mov r13d, esi                      ; path_len
    mov r14d, edx                      ; expected magic
    mov ebx, ecx                       ; maximum accepted size
    mov qword [rel cpu_llm_last_blob_size], 0
    mov eax, [rel vfs_disk_handle]
    test eax, eax
    js .lb_fail
    mov r8d, eax
    mov rdi, r12
    mov esi, r13d
    call vfs_path_stat
    cmp rax, 4
    jb .lb_fail
    mov r15, rax
    mov eax, ebx
    cmp r15, rax
    ja .lb_fail
    mov rdi, r15
    cmp r14d, PXG2_MAGIC
    jne .lb_small
    call kmalloc_model
    jmp .lb_allocated
.lb_small:
    call kmalloc
.lb_allocated:
    test rax, rax
    jz .lb_fail
    mov rbx, rax                       ; exact-size destination
    mov rdi, r12
    mov esi, r13d
    mov rdx, rbx
    mov ecx, r15d
    mov r8d, [rel vfs_disk_handle]
    call fat32_readfile_path
    cmp rax, r15
    jne .lb_fail
    mov eax, [rbx]
    cmp eax, r14d
    jne .lb_fail
.lb_ok:
    mov [rel cpu_llm_last_blob_size], r15
    mov rax, rbx
    jmp .lb_ret
.lb_fail:
    xor eax, eax
.lb_ret:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
%endif

; Only the pre-EBS fixed-file verifier can publish this immutable resident
; input. It has already removed the bytes from the post-EBS model allocator.
cog_adopt_boot_model:
%if COG_MODEL_ENABLED = 0
    xor eax, eax
    ret
%else
    cmp byte [rel boot_model_ready], 1
    jne .absent
    mov rax, [rel boot_model_base]
    test rax, rax
    jz .absent
    cmp qword [rel boot_model_size], COG_MODEL_BYTES
    jne .absent
    mov [rel model_base], rax
    mov qword [rel cog_model_size], COG_MODEL_BYTES
    mov byte [rel cog_model_hash_ok], 1
    mov byte [rel cog_disk_loaded], 1
    mov byte [rel cog_boot_loaded], 1
    lea rax, [rel cog_optional_absent]
    mov [rel tokvocab_base], rax
    mov [rel bpem_base], rax
    mov eax, 1
    ret
.absent:
    xor eax, eax
    ret
%endif

; Historical function name retained. A real pre-EBS attempt can only adopt the
; owner-configured, verified data volume or refuse. The descriptor code below
; remains for isolated historical HOST fixtures that never run pre-EBS.
cpu_llm_load_model_nvme:
%if COG_MODEL_ENABLED = 0
    xor eax, eax
    ret
%else
    push rbx
    cmp byte [rel cog_disk_loaded], 1
    je .lmn_ok
    call cog_adopt_boot_model
    test eax, eax
    jnz .lmn_ok
    ; A pre-EBS configuration/load refusal is final for this boot: never try
    ; another disk or the fixed-address QEMU injection after that attempt.
    cmp byte [rel boot_model_attempted], 1
    je .lmn_refused
    mov byte [rel cog_disk_loaded], 0
    mov byte [rel cog_model_hash_ok], 0
    mov qword [rel cog_model_size], 0
    ; Public units are identity-stable even when firmware/HBA port order moves:
    ; primary system disk remains ahci0, descriptor data disk remains ahci1.
    lea rdi, [rel cog_expected_system_model]
    lea rsi, [rel cog_expected_system_serial]
    xor edx, edx
    call ahci_bind_name_identity
    test rax, rax
    jz .lmn_fail
    lea rdi, [rel cog_expected_disk_model]
    lea rsi, [rel cog_expected_disk_serial]
    mov edx, 1
    call ahci_bind_name_identity
    test rax, rax
    jz .lmn_fail
    mov rbx, rax
    lea rdi, [rel cog_expected_volume]
    mov rsi, rbx
    call fat32_disk_select_exact
    test rax, rax
    jnz .lmn_fail
    lea rdi, [rel str_model_pxg_path]
    mov esi, str_model_pxg_path_len
    mov edx, PXG2_MAGIC
    mov ecx, COG_MODEL_BYTES
    call cpu_llm_load_blob
    test rax, rax
    jz .lmn_fail
    mov rbx, rax
    cmp qword [rel cpu_llm_last_blob_size], COG_MODEL_BYTES
    jne .lmn_fail
    lea rdi, [rel cog_model_digest]
    mov rsi, rbx
    mov edx, COG_MODEL_BYTES
    call sha256_hash
    test rax, rax
    jnz .lmn_fail
    lea rsi, [rel cog_model_digest]
    lea rdi, [rel cog_expected_sha256]
    xor ecx, ecx
.lmn_hash_cmp:
    cmp ecx, 32
    jae .lmn_hash_ok
    mov al, [rsi + rcx]
    cmp al, [rdi + rcx]
    jne .lmn_fail
    inc ecx
    jmp .lmn_hash_cmp
.lmn_hash_ok:
    mov [rel model_base], rbx
    mov qword [rel cog_model_size], COG_MODEL_BYTES
    mov byte [rel cog_model_hash_ok], 1
    mov byte [rel cog_disk_loaded], 1
    ; The QEMU defaults point at optional loader addresses.  On metal, replace
    ; them with a known zero word before attempting the best-effort disk blobs,
    ; so an absent TOKVOCAB/BPE file cannot inspect unrelated high RAM.
    lea rax, [rel cog_optional_absent]
    mov [rel tokvocab_base], rax
    mov [rel bpem_base], rax
    lea rdi, [rel str_tvoc_path]       ; tokvocab (for detokenize) — best-effort
    mov esi, str_tvoc_path_len
    mov edx, TVOC_MAGIC
    mov ecx, 4194304
    call cpu_llm_load_blob
    test rax, rax
    jz .lmn_notv
    mov [rel tokvocab_base], rax
.lmn_notv:
    lea rdi, [rel str_bpem_path]       ; merges (for on-device encode) — best-effort
    mov esi, str_bpem_path_len
    mov edx, BPEM_MAGIC
    mov ecx, 4194304
    call cpu_llm_load_blob
    test rax, rax
    jz .lmn_nobp
    mov [rel bpem_base], rax
.lmn_nobp:
.lmn_ok:
    mov eax, 1
    pop rbx
    ret
.lmn_fail:
    ; A completed, failed attempt: the exact data disk is absent only if the
    ; AHCI scan proves it (complete, no uncertainty, no slot with its identity).
    lea rdi, [rel cog_expected_disk_model]
    lea rsi, [rel cog_expected_disk_serial]
    call ahci_identity_absent
    mov [rel fat32_disk_descriptor_absent], al
.lmn_refused:
    xor eax, eax
    pop rbx
    ret
%endif

; llm_load_cmd: "LLMLOAD" handler — load model (+blobs) from NVMe, report result.
llm_load_cmd:
%if COG_MODEL_ENABLED = 0
    xor eax, eax
    ret
%else
    call cpu_llm_load_model_nvme
    test eax, eax
    jz .llc_fail
    lea rdi, [rel str_lm_ok]
    call serial_string
    ret
.llc_fail:
    lea rdi, [rel str_lm_fail]
    call serial_string
    ret

%endif

str_model_pxg_path:  db "\MODEL.PXG"
str_model_pxg_path_len equ $ - str_model_pxg_path
str_tvoc_path:  db "\TOKVOCAB.BIN"
str_tvoc_path_len equ $ - str_tvoc_path
str_bpem_path:  db "\BPEMERGE.BIN"
str_bpem_path_len equ $ - str_bpem_path
str_lm_ok:    db "[LLMDEMO] verified model loaded", 13, 10, 0
str_lm_fail:  db "[LLMDEMO] model unavailable; no alternate-disk fallback after boot attempt", 13, 10, 0

COG_MODEL_BYTES equ COG_FIXED_MODEL_BYTES
align 8
%if COG_MODEL_ENABLED = 1
cog_expected_volume:
    db COG_DATA_DISK_GUID_BYTES
    db COG_DATA_PART_GUID_BYTES
    dq COG_DATA_PART_SECTORS
    dq COG_DATA_FS_SECTORS
    dd COG_DATA_VOLUME_ID
    dd 0
cog_expected_disk_model:  db COG_DATA_MODEL_BYTES, 0
cog_expected_disk_serial: db COG_DATA_SERIAL_BYTES, 0
cog_expected_system_model:  db COG_SYSTEM_MODEL_BYTES, 0
cog_expected_system_serial: db COG_SYSTEM_SERIAL_BYTES, 0
%endif
cog_expected_sha256: db COG_FIXED_MODEL_SHA256_BYTES
cog_model_digest: times 32 db 0
cpu_llm_last_blob_size: dq 0
cog_optional_absent: dd 0

str_enc:      db "[LLMDEMO] encoded:", 0
str_m5_start: db "[LLMDEMO] M5 KV-cached generation...", 13, 10, 0
str_m5_gen:   db "[LLMDEMO] M5 greedy decode (KV cache):", 13, 10, 0
str_m5_tok:   db "[LLMDEMO] M5 tok[", 0
str_m5_us:    db "[LLMDEMO] M5 elapsed_us=", 0
str_m5_top5:  db "[LLMDEMO] M5 top5(first-pred id=rawfp32logit):", 0
str_m5_text:  db "[LLMDEMO] M5 text: ", 0

; M5 globals
m5_hidden:  dq 0
m5_normed:  dq 0
m5_qkv:     dq 0
m5_attn:    dq 0
m5_proj:    dq 0
m5_ff1:     dq 0
m5_ff2:     dq 0
kv_k:       dq 0
kv_v:       dq 0
m5_L:       dd 0
m5_pos:     dd 0
m5_token:   dd 0
gen_prompt_len: dd 4                    ; prompt length for M5 gen (LLMGEN sets it)
m_nlayer:   dd 6                        ; layer count, read from PXG2 header (6=distilgpt2, 12=gpt2)
; Runtime base of the loaded model. Defaults to the QEMU `-device loader` address;
; on bare metal cpu_llm_load_model_nvme reads MODEL.PXG into a buffer and sets this.
%if COG_MODEL_ENABLED = 1
model_base:    dq MODEL_PHYS
tokvocab_base: dq TOKVOCAB_PHYS         ; runtime base of the TVOC token->bytes table
bpem_base:     dq BPEM_PHYS             ; runtime base of the BPEM merges table
%else
model_base:    dq 0
tokvocab_base: dq 0
bpem_base:     dq 0
%endif
m5_logits:  dq 0                        ; 50257-float buffer for the top-5 accuracy dump
m5_buffers_state: db 0                  ; 0=untried, 1=persistent set ready, 2=failed
align 8

; M3 globals + strings
m3_normed:  dq 0
m3_qkv:     dq 0
m3_attn:    dq 0
m3_proj:    dq 0
m3_ff1:     dq 0
m3_ff2:     dq 0
m3_ln_src:  dq 0
m3_ln_g:    dq 0
m3_ln_b:    dq 0
m3_ba_buf:  dq 0
m3_ba_bias: dq 0
m3_ln1g:    dq 0
m3_ln1b:    dq 0
m3_aw:      dq 0
m3_ab:      dq 0
m3_pw:      dq 0
m3_pb:      dq 0
m3_ln2g:    dq 0
m3_ln2b:    dq 0
m3_fcw:     dq 0
m3_fcb:     dq 0
m3_fpw:     dq 0
m3_fpb:     dq 0
m3_L:       dd 0
m3_seq:     dd 4                        ; current sequence length (M3=4; M4 grows it)
m3_argmax_tok: dd 0                     ; M4: argmax token of the last position
MAX_SEQ     equ 32
MAX_LAYER   equ 12                       ; KV cache sizing: 6=distilgpt2, 12=gpt2-124M
M4_NGEN     equ 1                        ; tokens to generate (TCG is slow; full recompute)
align 16
m3_scores:  times MAX_SEQ dd 0
m4_tokens:  times 64 dd 0               ; mutable token buffer (prompt + generated)
str_m3_start:  db "[LLMDEMO] M3 forward (6 layers)...", 13, 10, 0
str_m3_l:      db "[LLMDEMO] M3 L", 0
str_m3_row0:   db " row0[0:4]= ", 0
str_m3_row3:   db "[LLMDEMO] M3     row3[0:4]= ", 0
str_m3_l274:   db "[LLMDEMO] M3 logit[274](rawfp32)=", 0
str_m3_l8053:  db "[LLMDEMO] M3 logit[8053](rawfp32)=", 0
str_m3_w8053:  db "[LLMDEMO] M3 wte[8053][0:4](PaOS)= ", 0
str_m3_argmax: db "[LLMDEMO] M3 argmax token=", 0
str_m3_logit:  db " logit(rawfp32)=", 0
str_m3_fail:   db "[LLMDEMO] M3 alloc FAILED", 13, 10, 0

; "The quick brown fox" GPT-2 BPE token ids (from the oracle).
llm_m2_tokens:   dd 464, 2068, 7586, 21831
m2_wte_p:        dq 0
m2_wpe_p:        dq 0
m2_hidden_p:     dq 0
str_m2_h00:      db "[LLMDEMO] M2 hidden[0][0..3]= ", 0
str_m2_h30:      db "[LLMDEMO] M2 hidden[3][0..3]= ", 0
str_m2_sum:      db "[LLMDEMO] M2 embsum(rawfp32)=", 0
str_m2_ok:       db "[LLMDEMO] M2 embed done", 13, 10, 0
str_m2_dbg_a:    db "[LLMDEMO] M2.a enter", 13, 10, 0
str_m2_dbg_b:    db "[LLMDEMO] M2.b allocs+resolve ok", 13, 10, 0
str_m2_dbg_c:    db "[LLMDEMO] M2.c embed loop done", 13, 10, 0
str_m2_fail:     db "[LLMDEMO] M2 embed FAILED (tensor/alloc)", 13, 10, 0

str_ld_nomodel:  db "[LLMDEMO] no model at 0x80000000 (magic=", 0
str_ld_hdr:      db "[LLMDEMO] PXG2 model present.", 13, 10, 0
str_ld_layers:   db "[LLMDEMO]  n_layer=", 0
str_ld_heads:    db "  n_head=", 0
str_ld_dmodel:   db "  d_model=", 0
str_ld_dhidden:  db "  d_hidden=", 0
str_ld_vocab:    db "  n_vocab=", 0
str_ld_nctx:     db "  n_ctx=", 0
str_ld_tensors:  db "  tensors=", 0
str_ld_cksum0:   db "[LLMDEMO] cksum0(first16M)=", 0
str_ld_cksumt:   db "[LLMDEMO] cksumT(+310M,16M)=", 0
str_ld_m1ok:     db "[LLMDEMO] M1 load-verify done", 13, 10, 0
str_ld_nl:       db 13, 10, 0
str_dbg_ck:      db "[LLMDEMO] cksum[", 0
str_dbg_ck2:     db "MB,+16MB]=", 0

; ===========================================================================
; cognition model tile (1061) — boot KAT + MODELRUN/MODELOUT/MODELKAT registry verbs.
; ===========================================================================
COG_REF_ARGMAX  equ 262        ; HuggingFace oracle argmax for the reference prompt
COG_REF_NTOK    equ 5

; --- cog_run_forward: run ONE forward pass on the reference prompt -> RAX = argmax.
;   Copies the oracle BPE ids into the engine's mutable token buffer, sets the prompt
;   length, and runs the KV-cached forward (M4_NGEN=1 => the single next-token argmax
;   lands in m3_argmax_tok). clobbers: caller-saved.
cog_run_forward:
%if COG_MODEL_ENABLED = 0
    mov eax, -1
    ret
%else
    push rbx
    call smp_par_for_retired
    test eax, eax
    jz .fail                            ; timed-out AP may still own activation buffers
    lea  rsi, [rel cog_ref_tokens]
    lea  rdi, [rel m4_tokens]
    mov  ecx, COG_REF_NTOK
    rep  movsd                          ; m4_tokens[0..4] = reference ids
    mov  dword [rel gen_prompt_len], COG_REF_NTOK
    call m5_generate_core               ; forward + 1-token generate -> m3_argmax_tok
    test eax, eax
    jnz  .fail
    mov  eax, [rel m3_argmax_tok]
    pop  rbx
    ret
.fail:
    mov  eax, -1
    pop  rbx
    ret
%endif

; --- cog_declare: register the 3 verbs, emit model.tile.ready (always), then run the
;   boot KAT IFF a real PXG2 model is present at model_base (magic + n_layer match).
;   No model -> clean degrade (no compute, no markers beyond tile.ready). Called from
;   boot/header.asm after the registry is up. clobbers: caller-saved.
cog_declare:
    push rbx
    ; the tile code is present this boot
    lea  rdi, [rel str_cog_ready]
    call serial_string
    mov  byte [rel cog_m_ready], 1
    ; register MODELRUN / MODELOUT / MODELKAT (ARGT_TEXT; cap 0 = v1 allow-all)
    lea  rdi, [rel str_verb_modelrun]
    lea  rsi, [rel cmd_verb_modelrun]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_verb_modelout]
    lea  rsi, [rel cmd_verb_modelout]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_verb_modelkat]
    lea  rsi, [rel cmd_verb_modelkat]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    ; --- tournament 1304: llm_find_tensor KAT (synthetic table, model-independent) ---
    call llm_find_tensor_kat
    ; --- tournament 1306: serial_decimal KAT + guard + measured perf ---
    call serial_decimal_kat
    ; --- tournament 1309: fp32_serial_print KAT + containment guard + perf ---
    call fp32_print_kat
%if COG_MODEL_ENABLED = 1
    ; Adopt the signed-selector preload. A failed real boot attempt skips the
    ; KAT without touching the legacy fixed-address injection fixture.
    call cpu_llm_load_model_nvme
    cmp byte [rel boot_model_attempted], 1
    jne .model_load_legacy_fixture
    test eax, eax
    jz .no_model
.model_load_legacy_fixture:
    ; --- boot KAT: only if a real distilgpt2 (PXG2, 6-layer) is loaded ---
    mov  rax, [rel model_base]
    mov  eax, [rax]                     ; magic
    cmp  eax, PXG2_MAGIC
    jne  .no_model
    mov  rax, [rel model_base]
    mov  eax, [rax + 8]                 ; n_layer
    cmp  eax, 6                         ; distilgpt2
    jne  .no_model
    mov  byte [rel cog_model_present], 1
    lea  rdi, [rel str_cog_load]
    call serial_string
    mov  byte [rel cog_m_load], 1
    ; run the forward and grade against the oracle argmax
    call cog_run_forward
    mov  [rel cog_kat_argmax], eax
    cmp  eax, COG_REF_ARGMAX
    jne  .infer_fail
    lea  rdi, [rel str_cog_infer_ok]
    call serial_string
    mov  byte [rel cog_m_infer], 1
    jmp  .done
.infer_fail:
    lea  rdi, [rel str_cog_infer_fail]
    call serial_string
    mov  edi, [rel cog_kat_argmax]
    call serial_decimal
    call serial_newline
    jmp  .done
.no_model:
    lea  rdi, [rel str_cog_nomodel]
    call serial_string
.done:
%else
    lea rdi, [rel str_cog_disabled]
    call serial_string
%endif
    pop  rbx
    ret

%if COG_MODEL_ENABLED = 0
str_cog_disabled: db "model.disabled profile=explicit", 13, 10, 0
str_cog_via_disabled: db " via=disabled", 0
%endif

; ---- staged-reply helpers (cog_out_buf, framed verbatim by command_udp.asm, exactly
;      like rt_out_buf). clobbers: RAX,RSI (put_str/put_dec). ----
cog_out_reset:
    lea  rax, [rel cog_out_buf]
    mov  [rel cog_out_cur], rax
    mov  byte [rel cog_out_buf], 0
    ret

cog_put_str:                            ; RDI = cstr
    mov  rsi, [rel cog_out_cur]
.cp:
    mov  al, [rdi]
    test al, al
    jz   .done
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .cp
.done:
    mov  byte [rsi], 0
    mov  [rel cog_out_cur], rsi
    ret

cog_put_dec:                            ; RDI = value
    mov  rsi, [rel cog_out_cur]
    push rsi
    call fmt_dec                        ; RAX = digit count, NUL-terminates
    pop  rsi
    add  rsi, rax
    mov  [rel cog_out_cur], rsi
    ret

; --- VERB: MODELRUN (RDI=req, RSI=resp) — ARGT_TEXT arg = "<prompt_id> <nonce>".
;   Runs one inference for the reference prompt and records ran/token + the caller's
;   exact nonce so MODELOUT can reflect it (un-fakeable: a stub can't echo a fresh
;   random nonce it was never given). "nomodel" id or an absent model -> ran=0 (clean
;   degrade). The persistent activation set makes this a real forward on every
;   accepted call rather than a nonce reflected over the boot-latched result.
cmd_verb_modelrun:
    mov rax, [rdi + REQ_ARG]
    test rax, rax
    jz .legacy
    lea rdx, [rel str_cog_scale_route]
    xor ecx, ecx
.scale_prefix:
    mov r8b, [rax + rcx]
    cmp r8b, [rdx + rcx]
    jne .legacy
    inc ecx
    cmp ecx, 5
    jb .scale_prefix
    cmp byte [rax + 5], 0
    je .scale_empty
    cmp byte [rax + 5], ' '
    jne .legacy
    lea rdx, [rax + 6]
    jmp cog_scale_command
.scale_empty:
    lea rdx, [rax + 5]
    jmp cog_scale_command
.legacy:
    ; Read-only intent observation retains this native verb's registry gate.
    mov rax,[rdi+REQ_ARG]
    test rax,rax
    jz .file_route
    lea rdx,[rel str_cog_intent]
    xor ecx,ecx
.intent:
    mov r8b,[rax+rcx]
    cmp r8b,[rdx+rcx]
    jne .file_route
    inc ecx
    cmp ecx,6
    jb .intent
    ; Reserve the INTENT token even with malformed trailing whitespace/args.
    ; Only the exact native handler may decide whether this request is valid.
    cmp byte [rax+6],' '
    ja .file_route
    jmp cog_ai_intent_command
.file_route:
    ; Installed file ingestion uses this same registry/auth/secret route.
    mov rax,[rdi+REQ_ARG]
    test rax,rax
    jz .ordinary
    lea rdx,[rel str_cog_advisefile_prefix]
    xor ecx,ecx
.file_prefix:
    mov r8b,[rax+rcx]
    cmp r8b,[rdx+rcx]
    jne .ordinary
    inc ecx
    cmp ecx,11
    jb .file_prefix
    ; Retire a previous model reply on every file-ingress outcome.
    mov byte [rel cog_out_ready],0
    mov byte [rel cog_out_buf],0
    lea rcx,[rel cog_out_buf]
    mov [rel cog_out_cur],rcx
    lea rdx,[rax+11]
    jmp command_ai_file_command
.ordinary:
    ; Existing registry/auth route; classifier advice has no new authority.
    mov rax,[rdi+REQ_ARG]
    test rax,rax
    jz .gpt2
    lea rdx,[rel str_cog_classifier_prefix]
    xor ecx,ecx
.classifier_prefix:
    mov r8b,[rax+rcx]
    cmp r8b,[rdx+rcx]
    jne .gpt2
    inc ecx
    cmp ecx,8
    jb .classifier_prefix
    lea rdx,[rax+8]
    cmp byte [rdx],0
    je .classifier
    cmp byte [rdx],' '
    jne .gpt2
    inc rdx
.classifier:
    jmp cog_classifier_command
.gpt2:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov  r13, rsi                       ; resp
    mov  r12, [rdi + REQ_ARG]           ; "<prompt_id> <nonce>"
    ; copy the prompt-id token
    mov  rsi, r12
    lea  rdi, [rel cog_argid]
    mov  ecx, 31
.id:
    test ecx, ecx
    jz   .id_done
    mov  al, [rsi]
    test al, al
    jz   .id_done
    cmp  al, ' '
    je   .id_done
    mov  [rdi], al
    inc  rdi
    inc  rsi
    dec  ecx
    jmp  .id
.id_done:
    mov  byte [rdi], 0
.skip:
    cmp  byte [rsi], ' '
    jne  .nonce_ready
    inc  rsi
    jmp  .skip
.nonce_ready:
    ; copy the nonce token into cog_nonce (bounded 47)
    lea  rdi, [rel cog_nonce]
    mov  ecx, 47
.nc:
    test ecx, ecx
    jz   .nc_done
    mov  al, [rsi]
    test al, al
    jz   .nc_done
    cmp  al, ' '
    je   .nc_done
    mov  [rdi], al
    inc  rdi
    inc  rsi
    dec  ecx
    jmp  .nc
.nc_done:
    mov  byte [rdi], 0
    ; decide ran: model must be present AND id must not be "nomodel"
    mov  dword [rel cog_ran], 0
    mov  dword [rel cog_out_tok], -1
    cmp  byte [rel cog_model_present], 1
    jne  .staged
    lea  rdi, [rel cog_argid]
    lea  rsi, [rel str_cog_nomodel_id]
    call strcmp
    test rax, rax
    jz   .staged                        ; id == "nomodel" -> ran stays 0
    call cog_run_forward
    cmp  eax, COG_REF_ARGMAX
    jne  .staged
    mov  [rel cog_out_tok], eax
    mov  dword [rel cog_ran], 1
.staged:
    call cog_out_reset
    lea  rdi, [rel str_cog_run_ack]     ; " modelrun accepted"
    call cog_put_str
    mov  byte [rel cog_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  eax, [rel cog_ran]
    mov  [r13 + RSP_VAL], rax
    pop  r13
    pop  r12
    pop  rbx
    ret

; --- VERB: MODELOUT (RDI=req, RSI=resp) — report the last MODELRUN result:
;   "ran=<0|1> token=<argmax> nonce=<the caller's nonce>". The oracle argmax + the
;   reflected random nonce are what the probe content-grades.
cmd_verb_modelout:
    call cmd_handler_prologue
    push r13
    mov  r13, rsi
    call cog_out_reset
    lea  rdi, [rel str_cog_ran]         ; " ran="
    call cog_put_str
    mov  edi, [rel cog_ran]
    call cog_put_dec
    lea  rdi, [rel str_cog_token]       ; " token="
    call cog_put_str
    mov  edi, [rel cog_out_tok]
    call cog_put_dec
    lea  rdi, [rel str_cog_nonce_f]     ; " nonce="
    call cog_put_str
    lea  rdi, [rel cog_nonce]
    call cog_put_str
    mov  byte [rel cog_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  eax, [rel cog_out_tok]
    mov  [r13 + RSP_VAL], rax
    pop  r13
    ret

; --- VERB: MODELKAT (RDI=req, RSI=resp) — the latched boot-KAT next-token argmax for
;   the fixed reference prompt: "argmax=<n> ref=capital_france expect=262 present=<0|1>".
;   Graded vs the pre-computed oracle (anti-chicken-and-egg): argmax must equal 262.
cmd_verb_modelkat:
    call cmd_handler_prologue
    push r13
    mov  r13, rsi
    call cog_out_reset
    lea  rdi, [rel str_cog_kat]         ; " argmax="
    call cog_put_str
    mov  edi, [rel cog_kat_argmax]
    call cog_put_dec
    lea  rdi, [rel str_cog_kat_ref]     ; " ref=capital_france expect=262 present="
    call cog_put_str
    mov  edi, [rel cog_model_present]
    call cog_put_dec
    lea  rdi, [rel str_cog_kat_disk]
    call cog_put_str
    movzx edi, byte [rel cog_disk_loaded]
    call cog_put_dec
    lea  rdi, [rel str_cog_kat_size]
    call cog_put_str
    mov  rdi, [rel cog_model_size]
    call cog_put_dec
    lea  rdi, [rel str_cog_kat_sha]
    call cog_put_str
    cmp  byte [rel cog_model_hash_ok], 1
    jne  .no_hash
    lea  rdi, [rel str_cog_sha_value]
    call cog_put_str
    jmp  .via
.no_hash:
    lea  rdi, [rel str_cog_none]
    call cog_put_str
.via:
    cmp  byte [rel cog_boot_loaded], 1
    jne  .disk_via
    lea  rdi, [rel str_cog_via_boot]
    call cog_put_str
    jmp  .kat_ready
.disk_via:
    cmp  byte [rel cog_disk_loaded], 1
    jne  .loader_via
    lea  rdi, [rel str_cog_via_disk]
    call cog_put_str
    jmp  .kat_ready
.loader_via:
%if COG_MODEL_ENABLED = 0
    lea  rdi, [rel str_cog_via_disabled]
%else
    lea  rdi, [rel str_cog_via_loader]
%endif
    call cog_put_str
.kat_ready:
    mov  byte [rel cog_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  eax, [rel cog_kat_argmax]
    mov  [r13 + RSP_VAL], rax
    pop  r13
    ret

; ---- module data ----------------------------------------------------------
align 4
cog_ref_tokens:    dd 464, 3139, 286, 4881, 318   ; "The capital of France is" (oracle BPE ids)
cog_model_present: dd 0
cog_kat_argmax:    dd -1
cog_ran:           dd 0
cog_out_tok:       dd -1
cog_model_size:    dq 0
cog_disk_loaded:   db 0
cog_boot_loaded:   db 0
cog_model_hash_ok: db 0
cog_m_ready:       db 0
cog_m_load:        db 0
cog_m_infer:       db 0
cog_out_ready:     db 0
align 8
cog_out_cur:       dq 0
cog_out_buf:       times 384 db 0
cog_nonce:         times 48  db 0
cog_argid:         times 32  db 0

; verb names
str_cog_advisefile_prefix: db "ADVISEFILE ",0
str_cog_classifier_prefix: db "CLASSIFY",0
str_cog_intent: db "INTENT",0
str_verb_modelrun: db "MODELRUN", 0
str_verb_modelout: db "MODELOUT", 0
str_verb_modelkat: db "MODELKAT", 0
str_cog_nomodel_id: db "nomodel", 0

; serial markers (registered in regression_tests.txt)
str_cog_ready:     db "[PAOS64] P8 model: local inference tile ready [model.tile.ready]", 13, 10, 0
str_cog_load:      db "[PAOS64] P8 model: PXG2 loader parsed header+tensors selftest PASS [model.load.ok]", 13, 10, 0
str_cog_infer_ok:  db "[PAOS64] P8 model: forward-pass argmax matches oracle selftest PASS [model.infer.selftest]", 13, 10, 0
str_cog_infer_fail: db "[PAOS64] P8 model: forward-pass argmax MISMATCH vs oracle (got argmax=", 0
str_cog_nomodel:   db "[PAOS64] P8 model: no model injected (magic mismatch) - tile degraded, ran=0", 13, 10, 0

; UDP earned-marker tokens (BOOTLOG grep targets; leading space keeps replies tokenized)
str_udp_cog_ready: db " model.tile.ready", 0
str_udp_cog_load:  db " model.load.ok", 0
str_udp_cog_infer: db " model.infer.selftest", 0

; UDP reply fragments
str_cog_run_ack:   db " modelrun accepted", 0
str_cog_ran:       db " ran=", 0
str_cog_token:     db " token=", 0
str_cog_nonce_f:   db " nonce=", 0
str_cog_kat:       db " argmax=", 0
str_cog_kat_ref:   db " ref=capital_france expect=262 present=", 0
str_cog_kat_disk:  db " disk=", 0
str_cog_kat_size:  db " size=", 0
str_cog_kat_sha:   db " sha256=", 0
str_cog_sha_value: db "a10f8753605f4db4fd2ff0f3950c6f1a4364a5e8832fd074ff2787ef5d38a36c", 0
str_cog_none:      db "none", 0
str_cog_via_disk:  db " via=fat32_disk/blk_ops", 0
str_cog_via_boot: db " via=boot_data", 0
str_cog_via_loader: db " via=qemu_loader", 0

; ---- symbols the ported fp32/simd/softmax/layernorm block references but that lived
;      elsewhere in the monolith's data section. Load-bearing constants get their real
;      values (gelu_new 0.044715; LayerNorm eps 1e-5 per the MANIFEST); the *_selftest
;      debug strings are dead code here (the selftests are never called) so they are
;      empty; scratch cells are zero; the SIMD level stays SSE (simd_matmul_level db 1). ----
align 4
gelu_coeff_044715: dd 0.044715
layernorm_epsilon: dd 1.0e-5
layernorm_mean:    dd 0
layernorm_var:     dd 0
cpuid_max_leaf:    dd 0
align 8
tsc_ticks_per_us:  dq 3700           ; nominal i9 ~3.7GHz; tok/s print only, avoids div-by-zero
str_crlf:            db 13,10,0
str_fp32_sig10_test: db 0
str_fp32_marker:     db 0
str_simd_detect:     db 0
str_simd_sse:        db 0
str_simd_avx:        db 0
str_simd_fma:        db 0
str_simd_testing:    db 0
str_simd_using:      db 0
str_simd_c00:        db 0
str_simd_c11:        db 0
str_simd_c33:        db 0
str_simd_marker:     db 0
str_cpuopt_selected: db 0
str_cpuopt_sse:      db 0
str_cpuopt_avx:      db 0
str_cpuopt_avx2:     db 0
str_cpuopt_aesni:    db 0
str_cpuopt_pass:     db 0
str_cpuopt_fail:     db 0
str_cpuopt_marker:   db 0
str_softmax_testing: db 0
str_softmax_r0:      db 0
str_softmax_r1:      db 0
str_softmax_r2:      db 0
str_softmax_r3:      db 0
str_softmax_sum:     db 0
str_softmax_marker:  db 0
str_fp32_testing:   db 0
str_fp32_add_test:  db 0
str_fp32_sub_test:  db 0
str_fp32_mul_test:  db 0
str_fp32_div_test:  db 0
str_fp32_exp_test:  db 0
str_fp32_exp0_test: db 0
str_fp32_sig_test:  db 0
str_fp32_tanh_test: db 0
str_fp32_dot_test:  db 0

str_cog_scale_route: db "SCALE", 0
