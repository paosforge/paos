mp3fe_build_regions:
    push rbx
    push r11
    lea r11, [rel mp3fe_si]
    mov eax, edi
    imul eax, MP3FE_GRSZ
    add r11, rax                      ; r11 = &mp3fe_si[gr]
    mov eax, [r11 + GRO_BV]
    add eax, eax                      ; bigv = 2*big_values
    mov r8d, eax                      ; r8 = bigv
    lea rbx, [rel mp3fe_sfband_l]
    ; r0b = sfband[r0+1]
    mov ecx, [r11 + GRO_R0]
    inc ecx
    mov r9d, [rbx + rcx*4]            ; r0b
    ; r1b = sfband[r0+1 + r1+1]
    add ecx, [r11 + GRO_R1]
    inc ecx
    cmp ecx, 22
    jbe .br_r1ok
    mov ecx, 22
.br_r1ok:
    mov r10d, [rbx + rcx*4]           ; r1b
    ; reg0n = min(r0b,bigv); reg1n = min(r1b,bigv)
    cmp r9d, r8d
    jbe .br_r0min
    mov r9d, r8d
.br_r0min:
    cmp r10d, r8d
    jbe .br_r1min
    mov r10d, r8d
.br_r1min:
    cmp r10d, r9d
    jae .br_seq
    mov r10d, r9d                     ; clamp reg1n >= reg0n
.br_seq:
    ; pairs0=reg0n/2 (ts0); pairs1=(reg1n-reg0n)/2 (ts1); pairs2=(bigv-reg1n)/2 (ts2)
    mov eax, r9d
    shr eax, 1
    mov edx, [r11 + GRO_TS0]
    mov [rel mp3fe_regions + 0], edx
    mov [rel mp3fe_regions + 4], eax
    mov eax, r10d
    sub eax, r9d
    shr eax, 1
    mov edx, [r11 + GRO_TS1]
    mov [rel mp3fe_regions + 8], edx
    mov [rel mp3fe_regions + 12], eax
    mov eax, r8d
    sub eax, r10d
    shr eax, 1
    mov edx, [r11 + GRO_TS2]
    mov [rel mp3fe_regions + 16], edx
    mov [rel mp3fe_regions + 20], eax
    mov dword [rel mp3fe_regions + 24], -1
    mov dword [rel mp3fe_regions + 28], 0
    pop r11
    pop rbx
    ret

; mp3fe_decode_granule(edi=gr) — full pipeline for one long-block granule;
;   appends 576 int16 PCM samples to mp3fe_pcm. Reads global bitpos (positioned
;   at this granule's main-data start). Advances bitpos past part2_3_length.
