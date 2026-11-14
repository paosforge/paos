;; MODULE cognition/encoder_attention_unlayout
;; LAYER 6
;; EXPORTS cog_encoder_attention_unlayout_f32_advisory
;; IMPORTS
;; CAPS
;; OWNER saga:cognition
; Native inverse context head layout: RDI context f32[12,L,32], RSI output
; f32[L,384], RDX config24(8-aligned): u32 L,reserved0; u64 input_bytes,
; output_bytes, exact L*1536. L1..512, input finite abs<=65536. Bitwise copy.
; Nonnull4-aligned arrays/nonwrapping ends; output disjoint from input and
; original config. Snapshot metadata, entire input scanned before first store.
; EAX0 success/1 invalid; refusal leaves caller buffers unchanged. Caller owns
; stable mapped buffers and admission; range checks do not prove permissions.
; No allocation/I/O/global scratch/authority. Complete MXCSR restored, SysV
; nonvolatile GPR/RSP/DF/x87 preserved. Scalar SSE2; nested stack<144 bytes.
; Partial attention only; no model/whole encoder/runtime acceptance.

cog_encoder_attention_unlayout_f32_advisory:
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 40                  ; config24 + saved/temporary MXCSR8, aligned
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
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
    test r14b, 7
    jnz  .invalid
    mov  rax, r14
    add  rax, 24
    jc   .invalid
    mov  rax, [r14]
    mov  [rsp], rax
    mov  rax, [r14+8]
    mov  [rsp+8], rax
    mov  rax, [r14+16]
    mov  [rsp+16], rax
    mov  eax, [rsp]
    test eax, eax
    jz   .invalid
    cmp  eax, 512
    ja   .invalid
    cmp  dword [rsp+4], 0
    jne  .invalid
    imul rax, 1536
    cmp  [rsp+8], rax
    jne  .invalid
    cmp  [rsp+16], rax
    jne  .invalid
    mov  rbx, rax
    mov  r11, r13
    add  r11, rax                 ; output end
    jc   .invalid
    mov  rdi, r14
    mov  esi, 24
    call .range_ok
    jnz  .invalid
    mov  rdi, r12
    mov  rsi, rbx
    call .range_ok
    jnz  .invalid
    stmxcsr [rsp+24]
    mov  dword [rsp+28], 0x1f80
    ldmxcsr [rsp+28]
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, rsp
    call paos_attention_unlayout_f32        ; scalar entry, config snapshot
    ldmxcsr [rsp+24]
    jmp  .out
.invalid:
    mov  eax, 1
.out:
    add  rsp, 40
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ZF=1 iff [RDI,RDI+RSI) is non-wrapping/disjoint from output [R13,R11).
; Only RAX/flags clobbered.
.range_ok:
    mov  rax, rdi
    add  rax, rsi
    jc   .range_bad
    cmp  rax, r13
    jbe  .range_good
    cmp  rdi, r11
    jae  .range_good
.range_bad:
    or   eax, 1
    ret
.range_good:
    xor  eax, eax
    ret

%include "cognition/encoder_attention_unlayout_kernel.inc"
