; Exact native/paos_dequant_bias_f32.asm entry-label body from paos_classifier
; commit4850e3f1e091c0c8438cc38ac1b0825fc7ac248f.
; File SHA256 d7894c5ef36f6f7e31357d0136606a0d0d8df83aacb402fb247cdba16acd3531
; Body SHA256 1ae720d4c8d1dad2afd74ada66333182c134975cb219acb6770c1e336e834356
; Internal symbols: use cog_dequant_bias_f32_advisory (scalar only).
paos_dequant_bias_f32:
    xor eax, eax
    jmp paos_dequant_bias_f32_common
paos_dequant_bias_f32_avx2:
    mov eax, 1
paos_dequant_bias_f32_common:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 16
    mov [rsp+8], eax            ; scalar=0, AVX2=1
    mov r12, rdi                 ; int32 accumulator
    mov r13, rsi                 ; bias
    mov r14, rdx                 ; output
    mov rbx, rcx                 ; config
    test r12, r12
    jz .invalid
    test r13, r13
    jz .invalid
    test r14, r14
    jz .invalid
    test rbx, rbx
    jz .invalid
    mov eax, [rbx]
    test eax, eax
    jz .invalid
    cmp eax, 512
    ja .invalid
    mov r15d, [rbx+4]
    cmp r15d, 384
    je .cols_ok
    cmp r15d, 1536
    jne .invalid
.cols_ok:
    mov eax, [rbx+8]
    cmp eax, 0x1e3ce508         ; 1e-20 normal minimum
    jb .invalid
    cmp eax, 0x447a0000         ; 1000.0 maximum
    ja .invalid
    mov eax, [rbx+12]
    cmp eax, 0x1e3ce508
    jb .invalid
    cmp eax, 0x447a0000
    ja .invalid
    movss xmm0, [rbx+8]
    mulss xmm0, [rbx+12]
    movd eax, xmm0
    cmp eax, 0x1e3ce508
    jb .invalid                 ; reject underflowed product
    cmp eax, 0x49742400         ; product <= 1,000,000
    ja .invalid
    movss [rsp], xmm0
    mov eax, [rbx]
    imul eax, r15d
    shl rax, 2
    cmp [rbx+16], rax
    jb .invalid
    cmp [rbx+32], rax
    jb .invalid
    mov r8, r12
    add r8, rax                 ; accumulator end
    jc .invalid
    mov r9, r14
    add r9, rax                 ; output end
    jc .invalid
    mov eax, r15d
    shl rax, 2
    cmp [rbx+24], rax
    jb .invalid
    mov r10, r13
    add r10, rax                ; bias end
    jc .invalid
    cmp r12, r9
    jae .input_disjoint
    cmp r14, r8
    jb .invalid
.input_disjoint:
    cmp r13, r9
    jae .bias_disjoint
    cmp r14, r10
    jb .invalid
.bias_disjoint:
    mov r11, rbx
    add r11, 40                ; config end
    jc .invalid
    cmp rbx, r9
    jae .config_disjoint
    cmp r14, r11
    jb .invalid
.config_disjoint:
    xor ecx, ecx
.scan_bias:
    mov eax, [r13+rcx*4]
    and eax, 0x7fffffff
    cmp eax, 0x47800000         ; |bias| <= 65536
    ja .invalid
    inc ecx
    cmp ecx, r15d
    jb .scan_bias
    xor ebp, ebp
.row:
    mov eax, ebp
    imul eax, r15d
    lea r8, [r12+rax*4]
    lea r9, [r14+rax*4]
    xor ecx, ecx
    cmp dword [rsp+8], 0
    jne .vector_start
.col:
    cvtsi2ss xmm0, dword [r8+rcx*4]
    mulss xmm0, [rsp]
    addss xmm0, [r13+rcx*4]
    movss [r9+rcx*4], xmm0
    inc ecx
    cmp ecx, r15d
    jb .col
    jmp .row_done
.vector_start:
    vbroadcastss ymm2, [rsp]
.vector_col:
    mov eax, ecx
    add eax, 8
    cmp eax, r15d
    ja .vector_done
    vmovdqu ymm0, [r8+rcx*4]
    vcvtdq2ps ymm0, ymm0
    vmulps ymm0, ymm0, ymm2
    vaddps ymm0, ymm0, [r13+rcx*4]
    vmovups [r9+rcx*4], ymm0
    add ecx, 8
    jmp .vector_col
.vector_done:
    vzeroupper
    cmp ecx, r15d
    jb .col
.row_done:
    inc ebp
    cmp ebp, [rbx]
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
