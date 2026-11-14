mp3_intensity_band:
    cmp ecx, 7
    jge .ib_done
    lea r8, [rel mp3dq_is_kl]
    movsd xmm2, [r8 + rcx*8]         ; k_l
    lea r8, [rel mp3dq_is_kr]
    movsd xmm3, [r8 + rcx*8]         ; k_r
    xor r9d, r9d
.ib_loop:
    cmp r9d, edx
    jge .ib_done
    movsd xmm0, [rdi + r9*8]         ; left
    movapd xmm1, xmm0
    mulsd xmm0, xmm2                 ; left*k_l
    mulsd xmm1, xmm3                 ; left*k_r
    movsd [rdi + r9*8], xmm0
    movsd [rsi + r9*8], xmm1
    inc r9d
    jmp .ib_loop
.ib_done:
    ret

