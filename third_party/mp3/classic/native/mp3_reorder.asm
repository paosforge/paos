mp3_reorder:
    lea r8, [rel mp3dq_perm]
    xor ecx, ecx
.ro_loop:
    cmp ecx, 576
    jge .ro_done
    movzx eax, word [r8 + rcx*2]     ; perm[i]
    movsd xmm0, [rdi + rax*8]
    movsd [rsi + rcx*8], xmm0
    inc ecx
    jmp .ro_loop
.ro_done:
    ret

