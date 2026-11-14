mp3fe_decode_buf:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov r12, rdi                      ; buf
    mov r13d, esi
    add r13, r12                      ; end ptr (zero-extend len)
    mov dword [rel mp3fe_samples], 0
    mov byte [rel mp3fe_decoded], 0
    mov dword [rel mp3fe_resv_len], 0      ; bit reservoir empty at stream start
    ; reset synthesis FIFO + hybrid overlap (stream start)
    call mp3_synth_reset
    lea rdi, [rel mp3hy_overlap]
    xorpd xmm0, xmm0
    xor ecx, ecx
.db_ovz:
    movsd [rdi + rcx*8], xmm0
    inc ecx
    cmp ecx, 576
    jb .db_ovz
    ; skip ID3v2 if present
    mov eax, [r12]
    and eax, 0x00FFFFFF
    cmp eax, 0x334449                 ; 'I''D''3' little-endian (49 44 33)
    jne .db_loop
    movzx eax, byte [r12+6]
    shl eax, 21
    movzx ecx, byte [r12+7]
    shl ecx, 14
    or eax, ecx
    movzx ecx, byte [r12+8]
    shl ecx, 7
    or eax, ecx
    movzx ecx, byte [r12+9]
    or eax, ecx
    add eax, 10
    add r12, rax
.db_loop:
    ; need at least a header + side info
    lea rax, [r12+25]
    cmp rax, r13
    jae .db_end
    mov eax, [rel mp3fe_samples]
    cmp eax, MP3FE_MAX_SAMPLES
    jae .db_end
    ; sync?
    cmp byte [r12], 0xFF
    jne .db_resync
    movzx eax, byte [r12+1]
    and eax, 0xE0
    cmp eax, 0xE0
    jne .db_resync
    ; parse + validate MPEG-1 Layer III
    mov rsi, r12
    call mp3_parse_frame_header
    test eax, eax
    jz .db_resync
    ; mono only (chan mode == 3)
    movzx eax, byte [r12+3]
    shr eax, 6
    cmp eax, 3
    jne .db_skipframe_calc
    ; frame length = 144*bitrate*1000/rate + pad
    mov eax, [rel audio_cur_bitrate]
    imul eax, 1000
    imul eax, 144
    xor edx, edx
    mov ecx, [rel audio_cur_rate]
    test ecx, ecx
    jz .db_end
    div ecx
    movzx ecx, byte [r12+2]
    shr ecx, 1
    and ecx, 1
    add eax, ecx                      ; eax = framelen
    mov r14d, eax                     ; save framelen
    ; side info ptr = r12 + 4 + (crc?2:0)
    mov ebp, 4
    test byte [r12+1], 1
    jnz .db_nocrc
    add ebp, 2
.db_nocrc:
    lea rsi, [r12 + rbp]              ; side info ptr
    mov [rel mp3fe_bptr], rsi
    mov dword [rel mp3fe_bbit], 0
    ; --- side info (mono): mdb(9) priv(5) scfsi(4) ---
    mov edi, 9
    call mp3fe_getbits
    mov r15d, eax                     ; mdb
    mov edi, 5
    call mp3fe_getbits
    mov edi, 4
    call mp3fe_getbits
    mov [rel mp3fe_scfsi], eax
    ; --- two granules side info (r11 = lea'd base of mp3fe_si[gr]) ---
    xor ebx, ebx                      ; gr
.db_gr_si:
    cmp ebx, 2
    jae .db_si_done
    lea r11, [rel mp3fe_si]
    mov eax, ebx
    imul eax, MP3FE_GRSZ
    add r11, rax                      ; r11 = &mp3fe_si[gr] (preserved across getbits)
    mov edi, 12
    call mp3fe_getbits
    mov [r11 + GRO_P23], eax
    mov edi, 9
    call mp3fe_getbits
    mov [r11 + GRO_BV], eax
    mov edi, 8
    call mp3fe_getbits
    mov [r11 + GRO_GG], eax
    mov edi, 4
    call mp3fe_getbits
    mov [r11 + GRO_SC], eax
    mov edi, 1
    call mp3fe_getbits
    test eax, eax
    jnz .db_si_short
    ; long block: ts0 ts1 ts2 r0 r1 pre sfs c1t
    mov dword [r11 + GRO_BT], 0
    mov edi, 5
    call mp3fe_getbits
    mov [r11 + GRO_TS0], eax
    mov edi, 5
    call mp3fe_getbits
    mov [r11 + GRO_TS1], eax
    mov edi, 5
    call mp3fe_getbits
    mov [r11 + GRO_TS2], eax
    mov edi, 4
    call mp3fe_getbits
    mov [r11 + GRO_R0], eax
    mov edi, 3
    call mp3fe_getbits
    mov [r11 + GRO_R1], eax
    mov edi, 1
    call mp3fe_getbits
    mov [r11 + GRO_PRE], eax
    mov edi, 1
    call mp3fe_getbits
    mov [r11 + GRO_SFS], eax
    mov edi, 1
    call mp3fe_getbits
    mov [r11 + GRO_C1T], eax
    jmp .db_gr_next
.db_si_short:
    ; window-switched: block_type(2) mixed(1) ts0(5) ts1(5) sbg0/1/2(3)
    mov edi, 2
    call mp3fe_getbits
    mov [r11 + GRO_BT], eax           ; nonzero -> handled as silence in granule
    mov edi, 1
    call mp3fe_getbits                ; mixed
    mov edi, 5
    call mp3fe_getbits
    mov edi, 5
    call mp3fe_getbits
    mov edi, 9
    call mp3fe_getbits                ; 3x subblock_gain (3 bits each)
    ; 9320e fix: short branch must ALSO read the trailing preflag + scalefac_scale
    ; + count1table_select (3 bits) that the long branch reads. Omitting them
    ; under-read 3 bits and desynced the NEXT granule's window_switching_flag,
    ; routing it to the long path on garbage -> loud ~6 kHz.
    mov edi, 1
    call mp3fe_getbits
    mov [r11 + GRO_PRE], eax          ; preflag
    mov edi, 1
    call mp3fe_getbits
    mov [r11 + GRO_SFS], eax          ; scalefac_scale
    mov edi, 1
    call mp3fe_getbits
    mov [r11 + GRO_C1T], eax          ; count1table_select
.db_gr_next:
    inc ebx
    jmp .db_gr_si
.db_si_done:
    ; --- bit reservoir (minimp3 model) ---
    ; This frame's own main data lives at [side info ptr + 17 .. end of frame].
    ; The granule data actually begins main_data_begin (r15d) bytes BEFORE that,
    ; i.e. in bytes carried over from prior frames. mp3fe_resv_restore concatenates
    ; the reservoir tail + this frame's main data into mp3fe_mdbuf and points the
    ; bit reader at byte 0 (which == main_data_begin bytes before this frame's md).
    lea rsi, [r12 + rbp + 17]            ; this frame's main data ptr
    mov edx, r14d                        ; framelen
    sub edx, ebp                         ; - (header+crc)
    sub edx, 17                          ; - mono side-info size => md_len
    jle .db_advance                      ; malformed/short frame: skip, leave reservoir
    mov ecx, r15d                        ; main_data_begin
    call mp3fe_resv_restore
    test eax, eax
    jz .db_resv_save                     ; reservoir underrun: cannot decode this frame
    ; decodable: granule bits are present in mp3fe_mdbuf
    xor edi, edi
    call mp3fe_decode_granule
    mov edi, 1
    call mp3fe_decode_granule
.db_resv_save:
    ; persist the unconsumed tail of mp3fe_mdbuf as the new reservoir (recover path:
    ; even an underrun frame contributes its main data so later frames can decode).
    call mp3fe_resv_save
.db_advance:
    add r12, r14                      ; cur += framelen
    jmp .db_loop
.db_skipframe_calc:
    ; non-mono frame: cannot decode; bail (stop) — caller handles 0 if no samples
    jmp .db_end
.db_resync:
    inc r12
    jmp .db_loop
.db_end:
    mov eax, [rel mp3fe_samples]
    test eax, eax
    jz .db_fail
    mov byte [rel mp3fe_decoded], 1
    lea rcx, [rel mp3fe_pcm]
    mov [rel audio_wav_data_ptr], rcx
    mov [rel audio_wav_src_frames], eax    ; mono: frames == samples
    mov dword [rel audio_cur_channels], 1
    mov dword [rel audio_cur_rate], 44100
    mov byte [rel audio_cur_format], 2
    jmp .db_ret
.db_fail:
    xor eax, eax
.db_ret:
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

align 8
