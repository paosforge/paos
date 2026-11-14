mp3fe_getbits:
    push rbx
    push rsi
    push rcx
    push rdx
    xor eax, eax
    mov rsi, [rel mp3fe_bptr]
    mov ebx, [rel mp3fe_bbit]
    mov r10d, edi
.gb_loop:
    test r10d, r10d
    jz .gb_done
    movzx edx, byte [rsi]
    mov ecx, 7
    sub ecx, ebx
    shr edx, cl
    and edx, 1
    add eax, eax
    or eax, edx
    inc ebx
    cmp ebx, 8
    jb .gb_nob
    xor ebx, ebx
    inc rsi
.gb_nob:
    dec r10d
    jmp .gb_loop
.gb_done:
    mov [rel mp3fe_bptr], rsi
    mov [rel mp3fe_bbit], ebx
    pop rdx
    pop rcx
    pop rsi
    pop rbx
    ret

; mp3fe_skipbits(edi=n) — advance global bitpos by n bits.
