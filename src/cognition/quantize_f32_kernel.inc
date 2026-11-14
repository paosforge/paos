; Adapted native/paos_dynamic_quantize_f32.asm from paos_classifier
; commit4850e3f1e091c0c8438cc38ac1b0825fc7ac248f.
; Original file SHA256 2d0e3cc6f176349f9293d0249b07375aaa04aaea19aa066c0495140cafcb6c24
; Original body SHA256 a7b4e04f105f4ce0b506890a72e9da355e949d1affd1a1256e70b227a0dceda6
; Adapted body SHA256 06ebfc60ab5668cec4894108bc9ab6b75d98da03bc910d871f90327595b1cdab
; Only two roundss/cvttss2si pairs become SSE2 cvtss2si with nearest-even MXCSR.
; Internal symbol: use cog_quantize_f32_advisory.
paos_dynamic_quantize_f32:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 32
    mov r12, rdi                  ; x
    mov r13, rsi                  ; y
    mov r14, rdx                  ; scale
    mov r15, rcx                  ; zero point
    mov rbx, r8                   ; config
    test r12, r12
    jz .invalid
    test r13, r13
    jz .invalid
    test r14, r14
    jz .invalid
    test r15, r15
    jz .invalid
    test rbx, rbx
    jz .invalid
    mov r8d, [rbx]
    test r8d, r8d
    jz .invalid
    cmp r8d, 786432              ; 512 x 1536 maximum admitted tensor
    ja .invalid
    cmp dword [rbx+4], 0
    jne .invalid
    mov eax, r8d
    shl rax, 2
    cmp [rbx+8], rax
    jb .invalid
    mov eax, r8d
    cmp [rbx+16], rax
    jb .invalid
    mov r9, r12
    mov eax, r8d
    shl rax, 2
    add r9, rax                   ; x end
    jc .invalid
    mov r10, r13
    add r10, r8                   ; y end
    jc .invalid
    cmp r12, r10
    jae .disjoint
    cmp r13, r9
    jb .invalid
.disjoint:
    mov r11, r14
    add r11, 4                   ; scale end
    jc .invalid
    mov rax, r15
    add rax, 1                   ; zero-point end
    jc .invalid
    cmp r12, r11
    jae .x_scale_disjoint
    cmp r14, r9
    jb .invalid
.x_scale_disjoint:
    cmp r12, rax
    jae .x_zero_disjoint
    cmp r15, r9
    jb .invalid
.x_zero_disjoint:
    cmp r13, r11
    jae .y_scale_disjoint
    cmp r14, r10
    jb .invalid
.y_scale_disjoint:
    cmp r13, rax
    jae .y_zero_disjoint
    cmp r15, r10
    jb .invalid
.y_zero_disjoint:
    cmp r14, rax
    jae .outputs_disjoint
    cmp r15, r11
    jb .invalid
.outputs_disjoint:
    xorps xmm0, xmm0             ; minimum adjusted to include zero
    xorps xmm1, xmm1             ; maximum adjusted to include zero
    xor ecx, ecx
.range:
    mov eax, [r12+rcx*4]
    mov edx, eax
    and edx, 0x7f800000
    cmp edx, 0x7f800000
    je .invalid                  ; reject NaN/Inf before any output
    movd xmm2, eax
    minss xmm0, xmm2
    maxss xmm1, xmm2
    inc ecx
    cmp rcx, r8
    jb .range
    subss xmm1, xmm0             ; max - min
    xorps xmm2, xmm2
    ucomiss xmm1, xmm2
    je .all_zero
    divss xmm1, [rel .qmax]
    movd eax, xmm1
    mov edx, eax
    and edx, 0x7f800000
    cmp edx, 0x7f800000
    je .invalid                  ; overflowed range/scale
    test eax, 0x7fffffff
    jz .invalid                  ; nonzero range rounded to zero scale
    movss [rsp], xmm1            ; scale
    xorps xmm3, xmm3
    subss xmm3, xmm0             ; -min
    divss xmm3, xmm1
    cvtss2si eax, xmm3          ; SSE2 nearest-even under wrapper MXCSR
    cmp eax, 0
    jge .zp_high
    xor eax, eax
.zp_high:
    cmp eax, 255
    jle .store_zp
    mov eax, 255
.store_zp:
    mov [rsp+4], eax
    jmp .quantize
.all_zero:
    mov dword [rsp], 0x3f800000  ; ONNX Runtime's scale=1 zero case
    mov dword [rsp+4], 0
.quantize:
    xor ecx, ecx
.quant_loop:
    movss xmm2, [r12+rcx*4]
    divss xmm2, [rsp]
    cvtss2si eax, xmm2          ; SSE2 nearest-even under wrapper MXCSR
    add eax, [rsp+4]
    cmp eax, 0
    jge .upper
    xor eax, eax
.upper:
    cmp eax, 255
    jle .store
    mov eax, 255
.store:
    mov [r13+rcx], al
    inc ecx
    cmp rcx, r8
    jb .quant_loop
    movss xmm0, [rsp]
    movss [r14], xmm0
    mov eax, [rsp+4]
    mov [r15], al
    xor eax, eax
    jmp .done
.invalid:
    mov eax, 1
.done:
    add rsp, 32
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.qmax: dd 255.0
