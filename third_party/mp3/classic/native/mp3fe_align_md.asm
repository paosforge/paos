mp3fe_align_md:
    push rbx
    mov rsi, [rel mp3fe_bptr]
    movzx ebx, byte [rel mp3fe_bbit]
    lea rdi, [rel mp3fe_md]
    mov edx, 560
.am_loop:
    movzx eax, byte [rsi]
    movzx r9d, byte [rsi+1]
    mov ecx, ebx
    shl eax, cl
    mov ecx, 8
    sub ecx, ebx
    shr r9d, cl
    or eax, r9d
    mov [rdi], al
    inc rsi
    inc rdi
    dec edx
    jnz .am_loop
    pop rbx
    ret

; mp3fe_read_scalefactors(edi=gr) -> eax = part2_length (bits consumed).
;   Long-block only. scfsi sharing honored for gr1. Fills mp3fe_sf[0..20].
