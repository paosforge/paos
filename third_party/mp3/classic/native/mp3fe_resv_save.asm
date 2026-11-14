mp3fe_resv_save:
    cld
    ; pos = (mp3fe_bptr - mdbuf) + (mp3fe_bbit ? 1 : 0)
    mov rax, [rel mp3fe_bptr]
    lea rcx, [rel mp3fe_mdbuf]
    sub rax, rcx                        ; whole bytes consumed
    mov edx, [rel mp3fe_bbit]
    test edx, edx
    jz .rs_nopad
    inc eax
.rs_nopad:
    ; remains = total - pos
    mov ecx, [rel mp3fe_mdbuf_total]
    sub ecx, eax
    jns .rs_rem_ok
    xor ecx, ecx                        ; clamp remains >= 0
.rs_rem_ok:
    cmp ecx, MP3FE_RESV_MAX
    jbe .rs_clamped
    ; keep only the last MP3FE_RESV_MAX bytes: advance pos, cap remains
    mov edx, ecx
    sub edx, MP3FE_RESV_MAX
    add eax, edx
    mov ecx, MP3FE_RESV_MAX
.rs_clamped:
    mov [rel mp3fe_resv_len], ecx
    test ecx, ecx
    jz .rs_done
    lea rsi, [rel mp3fe_mdbuf]
    add rsi, rax                        ; mdbuf + pos
    lea rdi, [rel mp3fe_resv_buf]
    rep movsb
.rs_done:
    ret

align 8
