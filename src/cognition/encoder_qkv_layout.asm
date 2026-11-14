;; MODULE cognition/encoder_qkv_layout
;; LAYER 6
;; EXPORTS cog_encoder_qkv_layout_f32_advisory
;; IMPORTS
;; CAPS
;; OWNER saga:cognition
; Native BGE batch-one QKV layout + pinned Q/K scaling. SysV RDI Q[L,384],
; RSI K[L,384], RDX V[L,384], RCX output bundle, R8 config40(8-aligned):
; u32 L,reserved0; u64 q_bytes,k_bytes,v_bytes,out_bytes (exact L*1536 each
; source, L*4608 output). L1..512. Output sections Q[12,L,32], K[12,32,L],
; V[12,L,32]. Q/K multiply by exact f32 scale0x3ed744fd; V copies unchanged.
; Arrays nonnull4-aligned, checked range ends, output disjoint from all inputs
; and original config; read-only sources may alias. Config snapshot; all Q/K/V
; finite abs<=65536 preflighted before first store. EAX0 success/1 invalid;
; invalid leaves caller buffers unchanged. Caller owns stable mapped data and
; admission/authentication; no I/O/allocation/global scratch or authority grant.
; Scalar SSE2 under standard temporary MXCSR, full caller environment restored.
; SysV nonvolatile GPR/RSP/DF/x87 preserved; nested stack<192 bytes.
; Partial attention layout only; no model/full encoder/runtime acceptance.

cog_encoder_qkv_layout_f32_advisory:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 56
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    mov  rbx, r8
    test r12, r12
    jz   .invalid
    test r12b, 3
    jnz  .invalid
    test r13, r13
    jz   .invalid
    test r13b, 3
    jnz  .invalid
    test r14, r14
    jz   .invalid
    test r14b, 3
    jnz  .invalid
    test r15, r15
    jz   .invalid
    test r15b, 3
    jnz  .invalid
    test rbx, rbx
    jz   .invalid
    test bl, 7
    jnz  .invalid
    mov  rax, rbx
    add  rax, 40
    jc   .invalid
    xor  ecx, ecx
.snapshot:
    mov  rax, [rbx+rcx*8]
    mov  [rsp+rcx*8], rax
    inc  ecx
    cmp  ecx, 5
    jb   .snapshot
    mov  eax, [rsp]
    test eax, eax
    jz   .invalid
    cmp  eax, 512
    ja   .invalid
    cmp  dword [rsp+4], 0
    jne  .invalid
    imul rax, 1536
    mov  r9, rax
    cmp  [rsp+8], r9
    jne  .invalid
    cmp  [rsp+16], r9
    jne  .invalid
    cmp  [rsp+24], r9
    jne  .invalid
    imul rax, 3
    cmp  [rsp+32], rax
    jne  .invalid
    mov  rbp, r15
    add  rbp, rax                 ; bundle end
    jc   .invalid
    mov  rdi, rbx
    mov  esi, 40
    call .range_ok
    jnz  .invalid
    mov  rdi, r12
    mov  rsi, r9
    call .range_ok
    jnz  .invalid
    mov  rdi, r13
    mov  rsi, r9
    call .range_ok
    jnz  .invalid
    mov  rdi, r14
    mov  rsi, r9
    call .range_ok
    jnz  .invalid
    stmxcsr [rsp+40]
    mov  dword [rsp+44], 0x1f80
    ldmxcsr [rsp+44]
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, r14
    mov  rcx, r15
    mov  r8, rsp
    call paos_qkv_layout_f32
    ldmxcsr [rsp+40]
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

; ZF=1 iff immutable[RDI,RDI+RSI) nonwrapping/disjoint from output[R15,RBP).
; Only RAX/flags clobbered; R9 retains expected source size.
.range_ok:
    mov  rax, rdi
    add  rax, rsi
    jc   .range_bad
    cmp  rax, r15
    jbe  .range_good
    cmp  rdi, rbp
    jae  .range_good
.range_bad:
    or   eax, 1
    ret
.range_good:
    xor  eax, eax
    ret

%include "cognition/encoder_qkv_layout_kernel.inc"
