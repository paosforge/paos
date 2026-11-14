mp3_imdct_long:
    push rbx
    push r12
    push r13
    push r14
    mov r12, rdi                     ; X
    mov r13, rsi                     ; OUT
    lea r14, [rel mp3_imdct_cos36]
    xor ebx, ebx                     ; i
.iml_i:
    cmp ebx, 36
    jae .iml_done
    xorpd xmm0, xmm0                 ; acc
    mov eax, ebx
    imul eax, 144                    ; 18 doubles * 8 bytes per row
    lea rcx, [r14 + rax]             ; row ptr = cos36 + i*18
    xor edx, edx                     ; k
.iml_k:
    cmp edx, 18
    jae .iml_kdone
    movsd xmm1, [r12 + rdx*8]
    mulsd xmm1, [rcx + rdx*8]
    addsd xmm0, xmm1
    inc edx
    jmp .iml_k
.iml_kdone:
    lea rax, [rel mp3_imdct_win_long]
    mulsd xmm0, [rax + rbx*8]
    movsd [r13 + rbx*8], xmm0
    inc ebx
    jmp .iml_i
.iml_done:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

