mp3fe_skipbits:
    mov eax, [rel mp3fe_bbit]
    add eax, edi
    mov ecx, eax
    shr ecx, 3
    and eax, 7
    mov [rel mp3fe_bbit], eax
    mov rdx, [rel mp3fe_bptr]
    add rdx, rcx
    mov [rel mp3fe_bptr], rdx
    ret

; mp3fe_align_md — byte-align 560 huffman bytes from current bitpos into mp3fe_md.
;   md[i] = (src[i]<<off) | (src[i+1]>>(8-off)); off==0 reduces to a plain copy.
