; Exact pinned4850e3f1 native/paos_qkv_layout_f32.asm body; no adaptations.
paos_qkv_layout_f32:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 16
    mov r12, rdi                 ; Q input
    mov r13, rsi                 ; K input
    mov r14, rdx                 ; V input
    mov r15, rcx                 ; output bundle
    mov rbx, r8                  ; config
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
    cmp r8d, 512
    ja .invalid
    cmp dword [rbx+4], 0
    jne .invalid
    mov eax, r8d
    imul eax, 1536              ; input bytes per projection
    mov r9d, eax
    cmp [rbx+8], r9
    jb .invalid
    cmp [rbx+16], r9
    jb .invalid
    cmp [rbx+24], r9
    jb .invalid
    mov eax, r9d
    imul eax, 3
    cmp [rbx+32], rax
    jb .invalid
    mov r10, r15
    add r10, rax                ; output end
    jc .invalid
    mov r11, rbx
    add r11, 40                ; config end
    jc .invalid
    cmp rbx, r10
    jae .config_disjoint
    cmp r15, r11
    jb .invalid
.config_disjoint:
    mov r11, r12
    add r11, r9                 ; Q end
    jc .invalid
    cmp r12, r10
    jae .q_disjoint
    cmp r15, r11
    jb .invalid
.q_disjoint:
    mov r11, r13
    add r11, r9                 ; K end
    jc .invalid
    cmp r13, r10
    jae .k_disjoint
    cmp r15, r11
    jb .invalid
.k_disjoint:
    mov r11, r14
    add r11, r9                 ; V end
    jc .invalid
    cmp r14, r10
    jae .v_disjoint
    cmp r15, r11
    jb .invalid
.v_disjoint:
    mov eax, r8d
    imul eax, 384
    mov [rsp], eax              ; floats per input
    xor ecx, ecx
.scan:
    mov eax, [r12+rcx*4]
    and eax, 0x7fffffff
    cmp eax, 0x47800000
    ja .invalid
    mov eax, [r13+rcx*4]
    and eax, 0x7fffffff
    cmp eax, 0x47800000
    ja .invalid
    mov eax, [r14+rcx*4]
    and eax, 0x7fffffff
    cmp eax, 0x47800000
    ja .invalid
    inc ecx
    cmp ecx, [rsp]
    jb .scan
    lea r11, [r15+r9]          ; K output base
    lea r10, [r11+r9]          ; V output base
    xor ebp, ebp                ; sequence token
.token:
    xor edx, edx                ; head
.head:
    xor ecx, ecx                ; head dimension
.dimension:
    mov eax, ebp
    imul eax, 384
    mov esi, edx
    shl esi, 5
    add eax, esi
    add eax, ecx               ; source [token, head, dimension]
    movss xmm0, [r12+rax*4]
    mulss xmm0, [rel .qk_scale]
    movss xmm1, [r13+rax*4]
    mulss xmm1, [rel .qk_scale]
    movss xmm2, [r14+rax*4]
    mov esi, edx
    imul esi, r8d
    shl esi, 5
    mov edi, ebp
    shl edi, 5
    add esi, edi
    add esi, ecx               ; Q/V [head, token, dimension]
    movss [r15+rsi*4], xmm0
    movss [r10+rsi*4], xmm2
    mov esi, edx
    shl esi, 5
    add esi, ecx
    imul esi, r8d
    add esi, ebp               ; K [head, dimension, token]
    movss [r11+rsi*4], xmm1
    inc ecx
    cmp ecx, 32
    jb .dimension
    inc edx
    cmp edx, 12
    jb .head
    inc ebp
    cmp ebp, r8d
    jb .token
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
.qk_scale: dd 0x3ed744fd
