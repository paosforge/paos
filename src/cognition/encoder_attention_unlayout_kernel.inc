; Exact pinned4850e3f1 native/paos_attention_unlayout_f32.asm body; no adaptations.
paos_attention_unlayout_f32:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    sub rsp, 8
    mov r12, rdi                 ; heads
    mov r13, rsi                 ; output
    mov r14, rdx                 ; config
    test r12, r12
    jz .invalid
    test r13, r13
    jz .invalid
    test r14, r14
    jz .invalid
    mov ebx, [r14]
    test ebx, ebx
    jz .invalid
    cmp ebx, 512
    ja .invalid
    cmp dword [r14+4], 0
    jne .invalid
    mov eax, ebx
    imul eax, 1536              ; bytes per sequence
    cmp [r14+8], rax
    jb .invalid
    cmp [r14+16], rax
    jb .invalid
    mov r8, r12
    add r8, rax                 ; input end
    jc .invalid
    mov r9, r13
    add r9, rax                 ; output end
    jc .invalid
    cmp r12, r9
    jae .input_disjoint
    cmp r13, r8
    jb .invalid
.input_disjoint:
    mov r10, r14
    add r10, 24                ; config end
    jc .invalid
    cmp r14, r9
    jae .config_disjoint
    cmp r13, r10
    jb .invalid
.config_disjoint:
    mov eax, ebx
    imul eax, 384
    xor ecx, ecx
.scan:
    mov edx, [r12+rcx*4]
    and edx, 0x7fffffff
    cmp edx, 0x47800000         ; |head value| <= 65536
    ja .invalid
    inc ecx
    cmp ecx, eax
    jb .scan
    xor ebp, ebp                ; token
.token:
    xor edx, edx                ; head
.head:
    xor ecx, ecx                ; dimension
.dimension:
    mov eax, edx
    imul eax, ebx
    add eax, ebp
    shl eax, 5
    add eax, ecx               ; source [head,token,dimension]
    movss xmm0, [r12+rax*4]
    mov eax, ebp
    imul eax, 384
    mov esi, edx
    shl esi, 5
    add eax, esi
    add eax, ecx               ; output [token,head,dimension]
    movss [r13+rax*4], xmm0
    inc ecx
    cmp ecx, 32
    jb .dimension
    inc edx
    cmp edx, 12
    jb .head
    inc ebp
    cmp ebp, ebx
    jb .token
    xor eax, eax
    jmp .done
.invalid:
    mov eax, 1
.done:
    add rsp, 8
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
