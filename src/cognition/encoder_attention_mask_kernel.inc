; Exact pinned4850e3f1 native/paos_attention_mask_f32.asm body, no adaptation.
paos_attention_mask_f32:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 16
    mov r12, rdi                 ; scores
    mov r13, rsi                 ; mask
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
    mov r15d, [rbx]
    test r15d, r15d
    jz .invalid
    cmp r15d, 512
    ja .invalid
    cmp dword [rbx+4], 0
    jne .invalid
    mov eax, r15d
    imul eax, r15d
    imul eax, 12
    mov [rsp], eax              ; number of score values
    shl rax, 2
    cmp [rbx+8], rax
    jb .invalid
    cmp [rbx+24], rax
    jb .invalid
    mov r8, r12
    add r8, rax                 ; scores end
    jc .invalid
    mov r9, r14
    add r9, rax                 ; output end
    jc .invalid
    mov eax, r15d
    cmp [rbx+16], rax
    jb .invalid
    mov r10, r13
    add r10, rax                ; mask end
    jc .invalid
    cmp r12, r9
    jae .scores_disjoint
    cmp r14, r8
    jb .invalid
.scores_disjoint:
    cmp r13, r9
    jae .mask_disjoint
    cmp r14, r10
    jb .invalid
.mask_disjoint:
    mov r11, rbx
    add r11, 32                ; config end
    jc .invalid
    cmp rbx, r9
    jae .config_disjoint
    cmp r14, r11
    jb .invalid
.config_disjoint:
    xor ecx, ecx
.scan_mask:
    cmp byte [r13+rcx], 1
    ja .invalid
    inc ecx
    cmp ecx, r15d
    jb .scan_mask
    xor ecx, ecx
.scan_scores:
    mov eax, [r12+rcx*4]
    and eax, 0x7fffffff
    cmp eax, 0x49742400         ; |score| <= 1,000,000
    ja .invalid
    inc ecx
    cmp ecx, [rsp]
    jb .scan_scores
    xor ecx, ecx                ; flat score index
    xor edx, edx                ; key index within row
.write:
    cmp byte [r13+rdx], 0
    je .masked
    mov eax, [r12+rcx*4]
    jmp .store
.masked:
    mov eax, 0xff7fffff         ; finite -FLT_MAX
.store:
    mov [r14+rcx*4], eax
    inc edx
    cmp edx, r15d
    jb .next
    xor edx, edx
.next:
    inc ecx
    cmp ecx, [rsp]
    jb .write
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
    pop rbx
    ret
