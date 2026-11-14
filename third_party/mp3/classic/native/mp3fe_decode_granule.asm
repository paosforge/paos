mp3fe_decode_granule:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12d, edi                     ; gr
    lea r15, [rel mp3fe_si]
    mov eax, r12d
    imul eax, MP3FE_GRSZ
    add r15, rax                      ; r15 = &mp3fe_si[gr] (preserved by all callees)
    ; block type 0 (long) only; else emit silence + skip p23 bits
    mov eax, [r15 + GRO_BT]
    test eax, eax
    jz .dg_long
    mov edi, [r15 + GRO_P23]
    call mp3fe_skipbits
    jmp .dg_silence
.dg_long:
    ; scalefactors
    mov edi, r12d
    call mp3fe_read_scalefactors
    mov r13d, eax                     ; part2
    ; huffman portion: byte-align main data into mp3fe_md
    call mp3fe_align_md
    ; zero is[576]
    lea rdi, [rel mp3fe_is]
    xor eax, eax
    mov ecx, 576
    cld
    rep stosd
    ; build regions
    mov edi, r12d
    call mp3fe_build_regions
    ; limit_bits = p23 - part2
    mov r14d, [r15 + GRO_P23]
    sub r14d, r13d
    ; huffman_decode(md, 560, regions, limit, c1t, is)
    lea rdi, [rel mp3fe_md]
    mov esi, 560
    lea rdx, [rel mp3fe_regions]
    mov ecx, r14d
    mov r8d, [r15 + GRO_C1T]
    lea r9, [rel mp3fe_is]
    call mp3_huffman_decode
    ; advance bitpos past the whole huffman portion (we consumed it from a copy)
    mov edi, r14d
    call mp3fe_skipbits
    ; requant(is, xr, gg, scalefac, sfscale, 576)
    lea rdi, [rel mp3fe_is]
    lea rsi, [rel mp3dq_xr_l]
    mov edx, [r15 + GRO_GG]
    lea rcx, [rel mp3fe_sf]
    mov r8d, [r15 + GRO_SFS]
    mov r9d, 576
    call mp3_requant_granule
    ; alias -> hybrid -> synthesis
    lea rdi, [rel mp3dq_xr_l]
    call mp3_alias_reduce
    lea rdi, [rel mp3dq_xr_l]
    lea rsi, [rel mp3fe_hyb]
    call mp3_hybrid_granule
    lea rdi, [rel mp3fe_hyb]
    lea rsi, [rel mp3sy_out]
    call mp3_synth_granule
    ; convert mp3sy_out[576] doubles -> int16 (x32768, clamp) -> mp3fe_pcm
    lea rsi, [rel mp3sy_out]
    movsd xmm2, [rel mp3fe_scale]
    xor ecx, ecx
.dg_cv:
    cmp ecx, 576
    jae .dg_done
    mov eax, [rel mp3fe_samples]
    cmp eax, MP3FE_MAX_SAMPLES
    jae .dg_done
    movsd xmm0, [rsi + rcx*8]
    mulsd xmm0, xmm2
    cvttsd2si edx, xmm0
    cmp edx, 32767
    jle .dg_hi
    mov edx, 32767
.dg_hi:
    cmp edx, -32768
    jge .dg_lo
    mov edx, -32768
.dg_lo:
    lea rdi, [rel mp3fe_pcm]
    mov [rdi + rax*2], dx
    inc eax
    mov [rel mp3fe_samples], eax
    inc ecx
    jmp .dg_cv
.dg_silence:
    ; emit 576 zero samples
    xor ecx, ecx
.dg_sil:
    cmp ecx, 576
    jae .dg_done
    mov eax, [rel mp3fe_samples]
    cmp eax, MP3FE_MAX_SAMPLES
    jae .dg_done
    lea rdi, [rel mp3fe_pcm]
    mov word [rdi + rax*2], 0
    inc eax
    mov [rel mp3fe_samples], eax
    inc ecx
    jmp .dg_sil
.dg_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; mp3fe_decode_buf(rdi=buf, esi=len) -> eax = total int16 mono samples (0 = fail).
;   Sets audio_wav_data_ptr/src_frames + audio_cur_rate/channels/format. Resets
;   the synthesis FIFO + hybrid overlap so the first granule starts clean.
