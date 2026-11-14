mp3fe_read_scalefactors:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12d, edi                    ; gr
    lea r13, [rel mp3fe_si]
    mov eax, r12d
    imul eax, MP3FE_GRSZ
    add r13, rax                     ; r13 = &mp3fe_si[gr]
    mov eax, [r13 + GRO_SC]          ; scalefac_compress[gr]
    lea rcx, [rel mp3fe_slen1]
    movzx r14d, byte [rcx + rax]     ; slen1
    lea rcx, [rel mp3fe_slen2]
    movzx r15d, byte [rcx + rax]     ; slen2
    mov dword [rel mp3fe_part2], 0
    xor ebx, ebx                      ; sfb
.sf_loop:
    cmp ebx, 21
    jae .sf_done
    ; slen = sfb<11 ? slen1 : slen2
    mov ecx, r14d
    cmp ebx, 11
    jl .sf_haveslen
    mov ecx, r15d
.sf_haveslen:
    ; group = sfb<6?0 : sfb<11?1 : sfb<16?2 : 3   (only matters for gr1 sharing)
    cmp r12d, 1
    jne .sf_read                      ; gr0 always reads
    ; compute group + check scfsi
    xor edx, edx                      ; group
    cmp ebx, 6
    jl .sf_grp
    inc edx
    cmp ebx, 11
    jl .sf_grp
    inc edx
    cmp ebx, 16
    jl .sf_grp
    inc edx
.sf_grp:
    mov eax, 3
    sub eax, edx                      ; bit index = 3-group
    mov edx, [rel mp3fe_scfsi]
    bt edx, eax
    jnc .sf_read
    ; shared: copy from gr0 saved
    lea rdx, [rel mp3fe_sf_g0]
    mov eax, [rdx + rbx*4]
    lea rdx, [rel mp3fe_sf]
    mov [rdx + rbx*4], eax
    jmp .sf_next
.sf_read:
    test ecx, ecx
    jz .sf_zero
    mov edi, ecx                      ; slen bits
    add [rel mp3fe_part2], ecx
    push rcx
    call mp3fe_getbits
    pop rcx
    jmp .sf_store
.sf_zero:
    xor eax, eax
.sf_store:
    lea rdx, [rel mp3fe_sf]
    mov [rdx + rbx*4], eax
    cmp r12d, 0
    jne .sf_next
    lea rdx, [rel mp3fe_sf_g0]
    mov [rdx + rbx*4], eax            ; save gr0 for sharing
.sf_next:
    inc ebx
    jmp .sf_loop
.sf_done:
    mov eax, [rel mp3fe_part2]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; mp3fe_build_regions(edi=gr) — fill mp3fe_regions from r0/r1/big_values/ts.
