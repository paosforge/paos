;; MODULE cognition/matmul_dispatch
;; LAYER 6
;; EXPORTS cog_matmul_u8s8_auto_advisory, cog_matmul_avx2_ready
;; IMPORTS sched_xstate_avx_ready
;; CAPS
;; OWNER saga:cognition
; Explicit CPU/OS/scheduler-gated native unsigned/signed integer matmul.
; Original scalar and encoderprojection APIs remain unchanged. Auto entry has
; identical config40/full64 exact spans/workcap/ownership/refusal contract to
; original bounded scalar adapter. Caller authenticates immutable mapped data.
; AVX2 admitted only with negotiated scheduler XSAVE x87/SSE/YMM capacity and
; live CPUID/XCR0 support. No FMA requirement, CR4/XCR0 writes, cache/allocation,
; I/O, model/authority/quality/performance/runtime claim. FullFP/DF/GPR preserved.
; Both kernels reuse exact pinned matmul_u8s8_kernel.inc under private labels.
COG_AUTO_MATMUL_MAX_WORK equ 16777216

; Boolean capability probe; never enables or caches extended CPU state.
; A scheduler that saves only FXSAVE state must never admit YMM instructions.
; XGETBV is reached only with XSAVE+OSXSAVE+AVX; leaf7 only when present.
; FMA is unnecessary for this exact integer kernel. FullFP/DF/GPRABI preserved.
cog_matmul_avx2_ready:
    push rbx
    call sched_xstate_avx_ready
    cmp  eax, 1
    jne  .no
    xor  eax, eax
    cpuid
    cmp  eax, 7
    jb   .no
    mov  eax, 1
    cpuid
    and  ecx, 0x1c000000         ;XSAVE26,OSXSAVE27,AVX28
    cmp  ecx, 0x1c000000
    jne  .no
    xor  ecx, ecx
    xgetbv
    and  eax, 7                  ;x87/SSE/YMM enabled locally
    cmp  eax, 7
    jne  .no
    mov  eax, 7
    xor  ecx, ecx
    cpuid
    test ebx, 0x20               ;AVX2, subleaf0
    jz   .no
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  rbx
    ret

; Same ABI, snapshot, finite work cap and invalid atomicity as original scalar.
; Explicit live CPU+OS+negotiated scheduler admission; falls back if any missing.
; No mutable global dispatch cache. Integer AVX2 changes neither MXCSR nor x87.
; Existing VZEROUPPER/scalar tail preserved verbatim in the included kernel.
; Stack including capability probe/kernel remains<224bytes.
cog_matmul_u8s8_auto_advisory:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 56                  ; 40-byte config snapshot; aligned kernel call
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    test r12, r12
    jz   .invalid
    test r13, r13
    jz   .invalid
    test r14, r14
    jz   .invalid
    test r14b, 3
    jnz  .invalid
    test r15, r15
    jz   .invalid
    test r15b, 7
    jnz  .invalid
    mov  rax, r15
    add  rax, 40
    jc   .invalid
    mov  rax, [r15]
    mov  [rsp], rax
    mov  rax, [r15+8]
    mov  [rsp+8], rax
    mov  rax, [r15+16]
    mov  [rsp+16], rax
    mov  rax, [r15+24]
    mov  [rsp+24], rax
    mov  rax, [r15+32]
    mov  [rsp+32], rax
    mov  eax, [rsp]
    test eax, eax
    jz   .invalid
    cmp  eax, 512
    ja   .invalid
    mov  ecx, [rsp+4]
    test ecx, ecx
    jz   .invalid
    cmp  ecx, 1536
    ja   .invalid
    mov  edx, [rsp+8]
    test edx, edx
    jz   .invalid
    cmp  edx, 1536
    ja   .invalid
    cmp  word [rsp+14], 0
    jne  .invalid
    mov  r8, rax
    imul r8, rcx                  ; A bytes (rows*inner)
    mov  r9, rdx
    imul r9, rcx                  ; B bytes (cols*inner)
    mov  r10, rax
    imul r10, rdx
    shl  r10, 2                   ; C bytes (rows*cols*4)
    imul rax, r9                  ; work = rows*cols*inner (bounded u32 inputs)
    cmp  rax, COG_AUTO_MATMUL_MAX_WORK
    ja   .invalid
    cmp  [rsp+16], r8
    jne  .invalid
    cmp  [rsp+24], r9
    jne  .invalid
    cmp  [rsp+32], r10
    jne  .invalid
    mov  rbx, r14
    add  rbx, r10                 ; output end
    jc   .invalid
    mov  rdi, r15
    mov  esi, 40
    call .range_ok
    jnz  .invalid
    mov  rdi, r12
    mov  rsi, r8
    call .range_ok
    jnz  .invalid
    mov  rdi, r13
    mov  rsi, r9
    call .range_ok
    jnz  .invalid
    call cog_matmul_avx2_ready   ;after all metadata/ownership, no input consumed
    mov  [rsp+40], eax
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, r14
    mov  rcx, rsp
    cmp  dword [rsp+40], 1
    jne  .scalar
    call cog_auto_matmul_avx2   ;exact pinned integer kernel, admitted state only
    jmp  .out
.scalar:
    call cog_auto_matmul_scalar
    jmp  .out
.invalid:
    mov  eax, 1
.out:
    add  rsp, 56
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; RDI=input base, RSI=nonzero bytes; R14=output start, RBX=output end.
; ZF=1 iff range does not wrap and is disjoint. Only RAX/flags clobbered.
.range_ok:
    mov  rax, rdi
    add  rax, rsi
    jc   .range_bad
    cmp  rax, r14
    jbe  .range_good
    cmp  rdi, rbx
    jae  .range_good
.range_bad:
    or   eax, 1
    ret
.range_good:
    xor  eax, eax
    ret


; Preserve source-exact upstream arithmetic without exposing ungated rawAVX2.
%define paos_matmul_u8s8 cog_auto_matmul_scalar
%define paos_matmul_u8s8_avx2 cog_auto_matmul_avx2
%define paos_matmul_u8s8_common cog_auto_matmul_common
%include "cognition/matmul_u8s8_kernel.inc"
%undef paos_matmul_u8s8
%undef paos_matmul_u8s8_avx2
%undef paos_matmul_u8s8_common
