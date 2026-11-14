mp3_alias_reduce:
    mov r8d, 1                       ; sb
.ar_sb:
    cmp r8d, 32
    jge .ar_done
    mov eax, r8d
    imul eax, 18                     ; b = boundary line
    xor ecx, ecx                     ; k
.ar_k:
    cmp ecx, 8
    jge .ar_next
    mov edx, eax
    sub edx, ecx
    dec edx                          ; lo idx = b-1-k
    mov r9d, eax
    add r9d, ecx                     ; up idx = b+k
    movsd xmm0, [rdi + rdx*8]        ; lo
    movsd xmm1, [rdi + r9*8]         ; up
    lea r10, [rel mp3dq_cs]
    movsd xmm2, [r10 + rcx*8]        ; cs[k]
    lea r10, [rel mp3dq_ca]
    movsd xmm3, [r10 + rcx*8]        ; ca[k]
    movapd xmm4, xmm0
    mulsd xmm4, xmm2                 ; lo*cs
    movapd xmm5, xmm1
    mulsd xmm5, xmm3                 ; up*ca
    subsd xmm4, xmm5                 ; new lo = lo*cs - up*ca
    movapd xmm6, xmm1
    mulsd xmm6, xmm2                 ; up*cs
    movapd xmm7, xmm0
    mulsd xmm7, xmm3                 ; lo*ca
    addsd xmm6, xmm7                 ; new up = up*cs + lo*ca
    movsd [rdi + rdx*8], xmm4
    movsd [rdi + r9*8], xmm6
    inc ecx
    jmp .ar_k
.ar_next:
    inc r8d
    jmp .ar_sb
.ar_done:
    ret

