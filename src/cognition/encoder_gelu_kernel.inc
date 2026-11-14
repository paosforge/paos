; Adapted native/paos_gelu_erf_f32.asm from paos_classifier4850e3f1.
; Original file SHA256 f85d940cfcbc9d32f3c51d085cda9ad110e83717f89387ffc91ec1222c042b2f
; Original body SHA256 bbc5d5347441a0d852468ac4097e4c33fa341835904a425f9a0706109a084281
; Adapted body SHA256 1c9659959fd1f587e52857e380cd704305f0128b2952f575470ee1809772dc2c
; Scalar roundss/cvttss2si pair becomes SSE2 cvtss2si under standard MXCSR.
; Finite-input preflight widened: all large finite values use existing safe tails.
; Internal symbols: use cog_encoder_gelu_f32_advisory; AVX2 entry unused.
paos_gelu_erf_f32:
    xor eax, eax
    jmp paos_gelu_erf_f32_common
paos_gelu_erf_f32_avx2:
    mov eax, 1
paos_gelu_erf_f32_common:
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 16
    mov [rsp], eax              ; explicit AVX2 path; caller checks CPU/OS
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    test r12, r12
    jz .invalid
    test r13, r13
    jz .invalid
    test r14, r14
    jz .invalid
    mov ebx, [r14]
    test ebx, ebx
    jz .invalid
    cmp ebx, 786432
    ja .invalid
    cmp dword [r14+4], 0
    jne .invalid
    mov eax, ebx
    shl rax, 2
    cmp [r14+8], rax
    jb .invalid
    cmp [r14+16], rax
    jb .invalid
    mov r8, r12
    add r8, rax
    jc .invalid
    mov r9, r13
    add r9, rax
    jc .invalid
    cmp r12, r9
    jae .xy_disjoint
    cmp r13, r8
    jb .invalid
.xy_disjoint:
    mov r10, r14
    add r10, 24
    jc .invalid
    cmp r14, r9
    jae .config_disjoint
    cmp r13, r10
    jb .invalid
.config_disjoint:
    xor ecx, ecx
.scan:
    mov eax, [r12+rcx*4]
    and eax, 0x7fffffff
    cmp eax, 0x7f800000       ; all finite f32; large values take safe tail
    jae .invalid
    inc ecx
    cmp ecx, ebx
    jb .scan
    xor ecx, ecx
    cmp dword [rsp], 0
    jne .vector_write
.write:
    movss xmm0, [r12+rcx*4]   ; x
    movd eax, xmm0
    mov edx, eax
    and edx, 0x7fffffff
    cmp edx, 0x41400000        ; |x| >= 12: saturated tail
    jae .tail
    movd xmm1, edx
    mulss xmm1, [rel .invsqrt2] ; z=|x|/sqrt(2)
    movss xmm2, xmm1
    mulss xmm2, xmm2
    xorps xmm3, xmm3
    subss xmm3, xmm2           ; -z^2
    ; exp(-z^2) = 2^n * poly(r), n=round(log2(e)*(-z^2)).
    movss xmm4, xmm3
    mulss xmm4, [rel .log2e]
    cvtss2si edx, xmm4       ; SSE2 nearest-even under wrapper MXCSR
    cvtsi2ss xmm5, edx
    mulss xmm5, [rel .ln2]
    subss xmm3, xmm5           ; reduced r
    movss xmm6, [rel .c6]
    mulss xmm6, xmm3
    addss xmm6, [rel .c5]
    mulss xmm6, xmm3
    addss xmm6, [rel .c4]
    mulss xmm6, xmm3
    addss xmm6, [rel .c3]
    mulss xmm6, xmm3
    addss xmm6, [rel .c2]
    mulss xmm6, xmm3
    addss xmm6, [rel .one]
    mulss xmm6, xmm3
    addss xmm6, [rel .one]
    add edx, 127
    shl edx, 23
    movd xmm7, edx
    mulss xmm6, xmm7           ; exp(-z^2)
    ; t = 1 / (1+p*z).
    mulss xmm1, [rel .p]
    addss xmm1, [rel .one]
    movss xmm2, [rel .one]
    divss xmm2, xmm1           ; t
    movss xmm3, [rel .a5]
    mulss xmm3, xmm2
    addss xmm3, [rel .a4]
    mulss xmm3, xmm2
    addss xmm3, [rel .a3]
    mulss xmm3, xmm2
    addss xmm3, [rel .a2]
    mulss xmm3, xmm2
    addss xmm3, [rel .a1]
    mulss xmm3, xmm2
    mulss xmm3, xmm6           ; erfc(z) approximation
    test eax, 0x80000000
    jnz .negative
    movss xmm4, [rel .two]
    subss xmm4, xmm3           ; 1+erf(z)=2-erfc(z)
    jmp .finish
.negative:
    movaps xmm4, xmm3          ; 1+erf(-z)=erfc(z)
.finish:
    mulss xmm4, [rel .half]
    mulss xmm0, xmm4
    movss [r13+rcx*4], xmm0
    jmp .next
.tail:
    test eax, 0x80000000
    jz .positive_tail
    xorps xmm0, xmm0
.positive_tail:
    movss [r13+rcx*4], xmm0
.next:
    inc ecx
    cmp ecx, ebx
    jb .write
    jmp .success
.vector_write:
    lea eax, [rcx+8]
    cmp eax, ebx
    ja .vector_done
    vmovups ymm0, [r12+rcx*4]   ; x
    vbroadcastss ymm8, [rel .abs_bits]
    vandps ymm1, ymm0, ymm8     ; |x|
    vbroadcastss ymm8, [rel .twelve]
    vcmpps ymm10, ymm1, ymm8, 13 ; saturated-tail lanes |x| >= 12
    vminps ymm1, ymm1, ymm8     ; avoid exponent overflow in tail lanes
    vbroadcastss ymm8, [rel .invsqrt2]
    vmulps ymm2, ymm1, ymm8     ; z
    vmulps ymm3, ymm2, ymm2
    vxorps ymm8, ymm8, ymm8
    vsubps ymm3, ymm8, ymm3     ; -z^2
    vbroadcastss ymm8, [rel .log2e]
    vmulps ymm4, ymm3, ymm8
    vroundps ymm4, ymm4, 0
    vcvttps2dq ymm11, ymm4
    vbroadcastss ymm8, [rel .ln2]
    vmulps ymm4, ymm4, ymm8
    vsubps ymm3, ymm3, ymm4     ; reduced r
    vbroadcastss ymm5, [rel .c6]
    vmulps ymm5, ymm5, ymm3
    vbroadcastss ymm8, [rel .c5]
    vaddps ymm5, ymm5, ymm8
    vmulps ymm5, ymm5, ymm3
    vbroadcastss ymm8, [rel .c4]
    vaddps ymm5, ymm5, ymm8
    vmulps ymm5, ymm5, ymm3
    vbroadcastss ymm8, [rel .c3]
    vaddps ymm5, ymm5, ymm8
    vmulps ymm5, ymm5, ymm3
    vbroadcastss ymm8, [rel .c2]
    vaddps ymm5, ymm5, ymm8
    vmulps ymm5, ymm5, ymm3
    vbroadcastss ymm8, [rel .one]
    vaddps ymm5, ymm5, ymm8
    vmulps ymm5, ymm5, ymm3
    vaddps ymm5, ymm5, ymm8
    vpbroadcastd ymm8, [rel .exp_bias]
    vpaddd ymm11, ymm11, ymm8
    vpslld ymm11, ymm11, 23
    vmulps ymm5, ymm5, ymm11   ; exp(-z^2)
    vbroadcastss ymm8, [rel .p]
    vmulps ymm7, ymm2, ymm8
    vbroadcastss ymm8, [rel .one]
    vaddps ymm7, ymm7, ymm8
    vdivps ymm7, ymm8, ymm7    ; t
    vbroadcastss ymm6, [rel .a5]
    vmulps ymm6, ymm6, ymm7
    vbroadcastss ymm8, [rel .a4]
    vaddps ymm6, ymm6, ymm8
    vmulps ymm6, ymm6, ymm7
    vbroadcastss ymm8, [rel .a3]
    vaddps ymm6, ymm6, ymm8
    vmulps ymm6, ymm6, ymm7
    vbroadcastss ymm8, [rel .a2]
    vaddps ymm6, ymm6, ymm8
    vmulps ymm6, ymm6, ymm7
    vbroadcastss ymm8, [rel .a1]
    vaddps ymm6, ymm6, ymm8
    vmulps ymm6, ymm6, ymm7
    vmulps ymm6, ymm6, ymm5   ; erfc(z)
    vxorps ymm9, ymm9, ymm9
    vcmpps ymm9, ymm0, ymm9, 1 ; negative x
    vbroadcastss ymm8, [rel .two]
    vsubps ymm8, ymm8, ymm6   ; positive 1+erf
    vblendvps ymm8, ymm8, ymm6, ymm9
    vbroadcastss ymm11, [rel .half]
    vmulps ymm8, ymm8, ymm11
    vmulps ymm8, ymm8, ymm0
    vandnps ymm11, ymm9, ymm0 ; positive tail x, negative tail 0
    vblendvps ymm8, ymm8, ymm11, ymm10
    vmovups [r13+rcx*4], ymm8
    add ecx, 8
    jmp .vector_write
.vector_done:
    vzeroupper
    cmp ecx, ebx
    jb .write                   ; scalar remainder
.success:
    xor eax, eax
    jmp .done
.invalid:
    mov eax, 1
.done:
    add rsp, 16
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
align 4
.invsqrt2: dd 0.7071067811865476
.abs_bits: dd 0x7fffffff
.twelve: dd 12.0
.exp_bias: dd 127
.log2e: dd 1.4426950408889634
.ln2: dd 0.6931471805599453
.one: dd 1.0
.two: dd 2.0
.half: dd 0.5
.c2: dd 0.5
.c3: dd 0.16666666666666666
.c4: dd 0.041666666666666664
.c5: dd 0.008333333333333333
.c6: dd 0.001388888888888889
.p: dd 0.3275911
.a1: dd 0.254829592
.a2: dd -0.284496736
.a3: dd 1.421413741
.a4: dd -1.453152027
.a5: dd 1.061405429
