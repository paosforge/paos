; Pinned paos_classifier4850e3f1 native/paos_softmax_f32.asm body.
; Scalar ROUNDSS/CVTTSS2SI adapted to SSE2 CVTSS2SI under standard MXCSR.
; Explicit AVX2 entry retained internally but never called by PaOS seam.
paos_softmax_f32:
    xor eax, eax
    jmp paos_softmax_f32_common
paos_softmax_f32_avx2:
    mov eax, 1
paos_softmax_f32_common:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 16
    mov [rsp+8], eax            ; 0 scalar, 1 AVX2
    mov r12, rdi                 ; X
    mov r13, rsi                 ; Y
    mov r14, rdx                 ; config
    test r12, r12
    jz .invalid
    test r13, r13
    jz .invalid
    test r14, r14
    jz .invalid
    mov eax, [r14]
    test eax, eax
    jz .invalid
    cmp eax, 6144
    ja .invalid
    mov ebx, [r14+4]
    test ebx, ebx
    jz .invalid
    cmp ebx, 512
    ja .invalid
    imul eax, ebx
    mov r15d, eax                ; total float values, <= 3,145,728
    shl rax, 2
    cmp [r14+8], rax
    jb .invalid
    cmp [r14+16], rax
    jb .invalid
    mov r8, r12
    add r8, rax                 ; X end
    jc .invalid
    mov r9, r13
    add r9, rax                 ; Y end
    jc .invalid
    cmp r12, r9
    jae .xy_disjoint
    cmp r13, r8
    jb .invalid
.xy_disjoint:
    mov r10, r14
    add r10, 24                 ; config end
    jc .invalid
    cmp r14, r9
    jae .yc_disjoint
    cmp r13, r10
    jb .invalid
.yc_disjoint:
    xor ecx, ecx
.scan:
    mov eax, [r12+rcx*4]
    cmp eax, 0xff7fffff         ; exact finite attention-mask sentinel
    je .scan_next
    and eax, 0x7fffffff
    cmp eax, 0x49742400         ; 1,000,000.0
    ja .invalid                ; includes Inf and NaN
.scan_next:
    inc ecx
    cmp ecx, r15d
    jb .scan
    xor ebp, ebp                ; row index
.row:
    mov eax, ebp
    imul eax, ebx
    lea r8, [r12+rax*4]        ; X row
    lea r9, [r13+rax*4]        ; Y row
    movss xmm6, [r8]           ; row maximum
    cmp dword [rsp+8], 0
    jne .vector_max_start
    mov ecx, 1
.max_loop:
    cmp ecx, ebx
    jae .max_done
    movss xmm0, [r8+rcx*4]
    maxss xmm6, xmm0
    inc ecx
    jmp .max_loop
.vector_max_start:
    vbroadcastss ymm6, [r8]
    xor ecx, ecx
.vector_max_loop:
    mov eax, ecx
    add eax, 8
    cmp eax, ebx
    ja .vector_max_reduce
    vmaxps ymm6, ymm6, [r8+rcx*4]
    add ecx, 8
    jmp .vector_max_loop
.vector_max_reduce:
    vextractf128 xmm0, ymm6, 1
    vmaxps xmm6, xmm6, xmm0
    vmovaps xmm0, xmm6
    vshufps xmm0, xmm0, xmm0, 0x4e
    vmaxps xmm6, xmm6, xmm0
    vmovaps xmm0, xmm6
    vshufps xmm0, xmm0, xmm0, 0xb1
    vmaxps xmm6, xmm6, xmm0
    vzeroupper
.vector_max_tail:
    cmp ecx, ebx
    jae .max_done
    movss xmm0, [r8+rcx*4]
    maxss xmm6, xmm0
    inc ecx
    jmp .vector_max_tail
.max_done:
    cmp dword [rsp+8], 0
    jne .vector_start
    xorps xmm5, xmm5           ; exponent sum
    xor ecx, ecx
.exp_loop:
    movss xmm2, [r8+rcx*4]
    subss xmm2, xmm6           ; <=0, stable after max subtraction
    ucomiss xmm2, [rel .cutoff]
    jb .exp_zero
    movaps xmm0, xmm2
    mulss xmm0, [rel .log2e]
    cvtss2si eax, xmm0         ; SSE2 nearest-even under wrapper MXCSR
    cvtsi2ss xmm1, eax
    mulss xmm1, [rel .ln2]
    subss xmm2, xmm1           ; reduced remainder in [-ln2/2,ln2/2]
    movss xmm3, [rel .c6]
    mulss xmm3, xmm2
    addss xmm3, [rel .c5]
    mulss xmm3, xmm2
    addss xmm3, [rel .c4]
    mulss xmm3, xmm2
    addss xmm3, [rel .c3]
    mulss xmm3, xmm2
    addss xmm3, [rel .c2]
    mulss xmm3, xmm2
    addss xmm3, [rel .one]
    mulss xmm3, xmm2
    addss xmm3, [rel .one]
    add eax, 127
    shl eax, 23
    movd xmm4, eax             ; 2^n as f32 exponent bits
    mulss xmm3, xmm4
    jmp .exp_store
.exp_zero:
    xorps xmm3, xmm3
.exp_store:
    movss [r9+rcx*4], xmm3
    addss xmm5, xmm3
    inc ecx
    cmp ecx, ebx
    jb .exp_loop
    cmp dword [rsp+8], 0
    jne .recompute_sum
    jmp .normalize_start
.vector_start:
    movss [rsp], xmm6           ; preserve scalar maximum for each vector block
    vbroadcastss ymm7, [rel .cutoff]
    vbroadcastss ymm8, [rel .log2e]
    vbroadcastss ymm9, [rel .ln2]
    vbroadcastss ymm10, [rel .c6]
    vbroadcastss ymm11, [rel .c5]
    vbroadcastss ymm12, [rel .c4]
    vbroadcastss ymm13, [rel .c3]
    vbroadcastss ymm14, [rel .c2]
    vbroadcastss ymm15, [rel .one]
    xor ecx, ecx
.vector_loop:
    mov eax, ecx
    add eax, 8
    cmp eax, ebx
    ja .vector_done
    vbroadcastss ymm6, [rsp]
    vmovups ymm0, [r8+rcx*4]
    vsubps ymm0, ymm0, ymm6
    vcmpps ymm6, ymm0, ymm7, 13  ; original x >= cutoff
    vmaxps ymm0, ymm0, ymm7     ; keep sentinel in finite exp domain
    vmulps ymm1, ymm0, ymm8
    vroundps ymm2, ymm1, 0
    vcvttps2dq ymm5, ymm2
    vmulps ymm2, ymm2, ymm9
    vsubps ymm3, ymm0, ymm2
    vmovaps ymm4, ymm10
    vmulps ymm4, ymm4, ymm3
    vaddps ymm4, ymm4, ymm11
    vmulps ymm4, ymm4, ymm3
    vaddps ymm4, ymm4, ymm12
    vmulps ymm4, ymm4, ymm3
    vaddps ymm4, ymm4, ymm13
    vmulps ymm4, ymm4, ymm3
    vaddps ymm4, ymm4, ymm14
    vmulps ymm4, ymm4, ymm3
    vaddps ymm4, ymm4, ymm15
    vmulps ymm4, ymm4, ymm3
    vaddps ymm4, ymm4, ymm15
    vpaddd ymm5, ymm5, [rel .bias127]
    vpslld ymm5, ymm5, 23
    vmulps ymm4, ymm4, ymm5
    vandps ymm4, ymm4, ymm6
    vmovups [r9+rcx*4], ymm4
    add ecx, 8
    jmp .vector_loop
.vector_done:
    vzeroupper
    movss xmm6, [rsp]
    cmp ecx, ebx
    jae .recompute_sum
    xorps xmm5, xmm5
    jmp .exp_loop              ; at most seven scalar-tail elements
.recompute_sum:
    vxorps ymm5, ymm5, ymm5
    xor ecx, ecx
.vector_sum_loop:
    mov eax, ecx
    add eax, 8
    cmp eax, ebx
    ja .vector_sum_reduce
    vaddps ymm5, ymm5, [r9+rcx*4]
    add ecx, 8
    jmp .vector_sum_loop
.vector_sum_reduce:
    vextractf128 xmm0, ymm5, 1
    vaddps xmm5, xmm5, xmm0
    vhaddps xmm5, xmm5, xmm5
    vhaddps xmm5, xmm5, xmm5
    vzeroupper
.sum_tail:
    cmp ecx, ebx
    jae .vector_normalize_start
    addss xmm5, [r9+rcx*4]
    inc ecx
    jmp .sum_tail
.vector_normalize_start:
    movss [rsp], xmm5
    vbroadcastss ymm5, [rsp]
    xor ecx, ecx
.vector_normalize_loop:
    mov eax, ecx
    add eax, 8
    cmp eax, ebx
    ja .vector_normalize_done
    vmovups ymm0, [r9+rcx*4]
    vdivps ymm0, ymm0, ymm5
    vmovups [r9+rcx*4], ymm0
    add ecx, 8
    jmp .vector_normalize_loop
.vector_normalize_done:
    vzeroupper
    movss xmm5, [rsp]
    cmp ecx, ebx
    jae .row_done
    jmp .normalize
.normalize_start:
    xor ecx, ecx
.normalize:
    movss xmm0, [r9+rcx*4]
    divss xmm0, xmm5
    movss [r9+rcx*4], xmm0
    inc ecx
    cmp ecx, ebx
    jb .normalize
.row_done:
    inc ebp
    cmp ebp, [r14]
    jb .row
    xor eax, eax
    jmp .done
.invalid:
    mov eax, 1
.done:
    add rsp, 16
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.cutoff: dd -80.0
.log2e: dd 1.4426950408889634
.ln2: dd 0.6931471805599453
.one: dd 1.0
.c2: dd 0.5
.c3: dd 0.16666666666666666
.c4: dd 0.041666666666666664
.c5: dd 0.008333333333333333
.c6: dd 0.001388888888888889
.bias127: times 8 dd 127
