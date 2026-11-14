;; MODULE cognition/rank_int8
;; LAYER 6
;; EXPORTS cog_rank_int8_advisory
;; IMPORTS
;; CAPS
;; OWNER saga:cognition
; ===========================================================================
; cognition/rank_int8.asm — RCQ-25 slice 1: a bounded ADVISORY numeric ranking
; primitive (signed-int8 query . prototype dot products -> choose / abstain).
;
; ADVICE GRANTS NO AUTHORITY. This is a numerical primitive only: no model, no
; tokenizer, no calibration, no I/O, no verb. Its choice is a suggestion; no
; caller may gate a security, ownership, trust or authorization decision on it,
; and a deterministic native policy stays authoritative (RC spec 21.5; root
; ruling RCQ-25-native-classifier-slice1 2026-10-09 08:04). The thresholds it
; takes are caller policy and are NOT calibrated here.
;
; PROVENANCE (consumed read-only; never edited there):
;   ~/projects/paos_classifier commit 4850e3f1e091c0c8438cc38ac1b0825fc7ac248f
;   native/paos_rank_int8.asm sha256 6509bbd8c854ad2ca67e9768d0642407b43955c244df665e294bef7bf447f3e7
;   The block between "BEGIN UPSTREAM KERNEL" and "END UPSTREAM KERNEL" is that
;   file's paos_rank_int8 body, byte-identical (region sha256
;   75092b4f7d13bfa79e4ac11fd5fe3e561da08942ebd8a89085837e26b42614c5). Only the
;   standalone prologue (bits/section/global) is dropped for the monolith.
;   gauntlet_v2/tests/test_rc_cognition_rank_int8_host.py pins both hashes.
;
; Scalar only (movsx/imul, no SSE/AVX state): the SSE2/scalar baseline needs
; no CPU/XSAVE admission. A future AVX2 path stays opt-in behind an
; XSAVE-admitted check (root RCQ-24 ruling 07:10).
;
; Bounds: count 2..256, dimension 1..2048, so |dot| <= 2048*128*128 =
; 33,554,432 < 2^31. Every size product (count*dimension) is a u32*u32 in 64
; bits and cannot overflow; every pointer+length end is carry-checked.
; ===========================================================================

COG_RANK_IO_BYTES   equ 16          ; config {u32 count, u32 dim, i32 min_dot, i32 min_margin}
                                    ; output {u32 status, u32 best, i32 best_dot, i32 second_dot}
COG_RANK_CHOOSE     equ 0
COG_RANK_ABSTAIN    equ 1
COG_RANK_INVALID    equ 2

; ---------------------------------------------------------------------------
; cog_rank_int8_advisory — validated entry to the upstream kernel (SysV).
;   in:  RDI = query (int8[dimension])     RSI = query length in bytes
;        RDX = rows (int8[count][dimension], row-major)  RCX = rows length
;        R8  = config (16 bytes, 4-aligned)  R9 = output (16 bytes, 4-aligned)
;   out: EAX = status (0 choose, 1 abstain, 2 invalid); output filled when
;        R9 is usable (on 2: best_index = 0xFFFFFFFF, dots = INT32_MIN).
;        An unusable output (null, misaligned, wrapping, overlapping an input,
;        or with an input range whose end wraps) is never written.
;   Refuses (2) unless: config non-null, 4-aligned, end does not wrap;
;   count 2..256, dimension 1..2048, min_margin >= 0; query non-null and
;   query length == dimension; rows non-null and rows length ==
;   count*dimension; no pointer+length end wraps; the output range is
;   disjoint from config, query and rows (the kernel writes output first).
;   The config is snapshotted on the stack and the kernel reads only the
;   snapshot, so a concurrent writer cannot change the validated bounds.
;   clobbers: RAX RCX RDX RSI RDI R8-R11 (SysV); preserves RBX RBP R12-R15.
; ---------------------------------------------------------------------------
cog_rank_int8_advisory:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 16                    ; config snapshot (rsp stays 16-aligned at the call)
    mov  r12, rdi                   ; query
    mov  r13, rsi                   ; query length
    mov  r14, rdx                   ; rows
    mov  r15, rcx                   ; rows length
    mov  rbx, r9                    ; output
    ; -- output: usable or never written
    test rbx, rbx
    jz   .refuse_silent
    test bl, 3
    jnz  .refuse_silent
    mov  rax, rbx
    add  rax, COG_RANK_IO_BYTES
    jc   .refuse_silent
    ; Prove output disjoint without touching any declared input, even on an
    ; invalid call. Initializing it first can corrupt aliased config/query/rows
    ; or fault when that input is read-only. These checks never read input data.
    test r8, r8
    jz   .precheck_query
    mov  rdi, r8
    mov  rsi, COG_RANK_IO_BYTES
    call .range_ok
    jnz  .refuse_silent
.precheck_query:
    test r12, r12
    jz   .precheck_rows
    test r13, r13
    jz   .precheck_rows
    mov  rdi, r12
    mov  rsi, r13
    call .range_ok
    jnz  .refuse_silent
.precheck_rows:
    test r14, r14
    jz   .precheck_done
    test r15, r15
    jz   .precheck_done
    mov  rdi, r14
    mov  rsi, r15
    call .range_ok
    jnz  .refuse_silent
.precheck_done:
    mov  dword [rbx], COG_RANK_INVALID
    mov  dword [rbx + 4], -1
    mov  dword [rbx + 8], 0x80000000
    mov  dword [rbx + 12], 0x80000000
    ; -- config: usable, disjoint from output, then snapshot
    test r8, r8
    jz   .refuse
    test r8b, 3
    jnz  .refuse
    mov  rax, [r8]
    mov  [rsp], rax
    mov  rax, [r8 + 8]
    mov  [rsp + 8], rax
    mov  ecx, [rsp]                 ; count
    cmp  ecx, 2
    jb   .refuse
    cmp  ecx, 256
    ja   .refuse
    mov  edx, [rsp + 4]             ; dimension
    test edx, edx
    jz   .refuse
    cmp  edx, 2048
    ja   .refuse
    cmp  dword [rsp + 12], 0
    jl   .refuse
    ; -- query: exactly dimension bytes, no wrap, disjoint from output
    test r12, r12
    jz   .refuse
    cmp  r13, rdx
    jne  .refuse
    ; -- rows: exactly count*dimension bytes (u32*u32 in 64 bits), no wrap, disjoint
    test r14, r14
    jz   .refuse
    mov  eax, ecx
    mov  edx, edx
    imul rax, rdx
    cmp  r15, rax
    jne  .refuse
    ; -- the upstream kernel on the validated snapshot
    mov  rdi, r12
    mov  rsi, r14
    mov  rdx, rsp
    mov  rcx, rbx
    call paos_rank_int8
    jmp  .out
.refuse:
    mov  eax, COG_RANK_INVALID      ; output already holds the invalid pattern
    jmp  .out
.refuse_silent:
    mov  eax, COG_RANK_INVALID
.out:
    add  rsp, 16
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; .range_ok: RDI = base, RSI = length (> 0). ZF=1 when [base, base+len) does not
; wrap and is disjoint from the output range [RBX, RBX+16). Clobbers RAX.
.range_ok:
    mov  rax, rdi
    add  rax, rsi
    jc   .range_bad                 ; end wraps
    cmp  rax, rbx                   ; end <= output start: disjoint
    jbe  .range_good
    mov  rax, rbx
    add  rax, COG_RANK_IO_BYTES
    cmp  rdi, rax                   ; start >= output end: disjoint
    jae  .range_good
.range_bad:
    or   eax, 1                     ; ZF=0 (rax is non-zero here or forced so)
    ret
.range_good:
    xor  eax, eax                   ; ZF=1
    ret

; BEGIN UPSTREAM KERNEL (paos_classifier 4850e3f1 native/paos_rank_int8.asm; byte-identical)
paos_rank_int8:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi                    ; query
    mov r13, rsi                    ; current prototype row
    mov r14, rdx                    ; config
    mov r15, rcx                    ; output
    test r15, r15
    jz .invalid_return
    mov dword [r15], 2
    mov dword [r15+4], -1
    mov dword [r15+8], 0x80000000
    mov dword [r15+12], 0x80000000
    test r12, r12
    jz .invalid_return
    test r13, r13
    jz .invalid_return
    test r14, r14
    jz .invalid_return
    mov ebx, [r14]                 ; count
    cmp ebx, 2
    jb .invalid_return
    cmp ebx, 256
    ja .invalid_return
    mov r8d, [r14+4]               ; dimension
    test r8d, r8d
    jz .invalid_return
    cmp r8d, 2048
    ja .invalid_return
    cmp dword [r14+12], 0          ; negative margin is invalid
    jl .invalid_return
    xor r9d, r9d                   ; row index
.row:
    xor eax, eax                   ; signed dot accumulator
    xor ecx, ecx                   ; column index
.column:
    movsx edx, byte [r12+rcx]
    movsx edi, byte [r13+rcx]
    imul edx, edi
    add eax, edx
    inc ecx
    cmp ecx, r8d
    jb .column
    cmp eax, [r15+8]
    jle .second
    mov edx, [r15+8]
    mov [r15+12], edx
    mov [r15+8], eax
    mov [r15+4], r9d
    jmp .advance
.second:
    cmp eax, [r15+12]
    jle .advance
    mov [r15+12], eax
.advance:
    add r13, r8
    inc r9d
    cmp r9d, ebx
    jb .row
    mov eax, [r15+8]
    cmp eax, [r14+8]
    jl .abstain
    sub eax, [r15+12]
    test eax, eax                   ; never choose an exact tie
    jz .abstain
    cmp eax, [r14+12]
    jl .abstain
    mov dword [r15], 0
    xor eax, eax
    jmp .done
.abstain:
    mov dword [r15], 1
    mov eax, 1
    jmp .done
.invalid_return:
    mov eax, 2
.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
; END UPSTREAM KERNEL
