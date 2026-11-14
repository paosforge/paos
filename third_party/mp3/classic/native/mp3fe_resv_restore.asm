mp3fe_resv_restore:
    push rbx
    push r12
    push r13
    push r14
    cld
    mov r12, rsi                        ; md_ptr
    mov r13d, edx                       ; md_len
    mov r14d, ecx                       ; mdb
    mov ebx, [rel mp3fe_resv_len]       ; resv_len
    ; bytes_have = min(resv_len, mdb)
    mov r10d, ebx
    cmp r10d, r14d
    jbe .rr_have_ok
    mov r10d, r14d
.rr_have_ok:
    ; copy reservoir tail: resv_buf + (resv_len - bytes_have), r10d bytes
    lea rdi, [rel mp3fe_mdbuf]
    lea rsi, [rel mp3fe_resv_buf]
    mov ecx, ebx
    sub ecx, r10d
    add rsi, rcx                        ; src = resv_buf + (resv_len - bytes_have)
    mov ecx, r10d                       ; count = bytes_have
    rep movsb                           ; rdi advances to mdbuf + bytes_have
    ; copy this frame's main data: r12, r13d bytes
    mov rsi, r12
    mov ecx, r13d
    rep movsb                           ; rdi advances to mdbuf + total
    ; total = bytes_have + md_len
    mov eax, r10d
    add eax, r13d
    mov [rel mp3fe_mdbuf_total], eax
    ; zero-pad 560 bytes so align_md's fixed 560-byte read never sees stale data/OOB
    mov ecx, 560
    xor al, al
    rep stosb
    ; point the bit reader at mdbuf byte 0
    lea rax, [rel mp3fe_mdbuf]
    mov [rel mp3fe_bptr], rax
    mov dword [rel mp3fe_bbit], 0
    ; decodable iff resv_len >= mdb
    xor eax, eax
    cmp ebx, r14d
    setae al
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; mp3fe_resv_save — after the granules consumed bits from mp3fe_mdbuf, save the
;   unconsumed tail (clamped to MP3FE_RESV_MAX) as the new reservoir. On an
;   underrun frame (no decode) the bit reader is still at byte 0, so the whole
;   mdbuf becomes the reservoir — that is the recover-after-resync path.
;   Clobbers only caller-scratch regs (rax/rcx/rdx/rsi/rdi).
