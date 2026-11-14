
mp3_parse_frame_header:
    movzx eax, byte [rsi]
    cmp al, 0xFF
    jne .mp3_fail
    movzx ecx, byte [rsi+1]
    mov edx, ecx
    and edx, 0xE0
    cmp edx, 0xE0
    jne .mp3_fail
    mov edx, ecx
    shr edx, 3
    and edx, 3
    cmp edx, 3                       ; MPEG version 1
    jne .mp3_fail
    mov edx, ecx
    shr edx, 1
    and edx, 3
    cmp edx, 1                       ; Layer III
    jne .mp3_fail
    movzx ecx, byte [rsi+2]
    mov edx, ecx
    shr edx, 4
    and edx, 0xF                     ; bitrate index
    cmp edx, 1
    jl .mp3_fail
    cmp edx, 14
    jg .mp3_fail
    lea r8, [rel mp3_br_table_l3]
    movzx eax, word [r8 + rdx*2]
    mov [rel audio_cur_bitrate], eax
    mov edx, ecx
    shr edx, 2
    and edx, 3                       ; samplerate index
    cmp edx, 3
    je .mp3_fail
    lea r8, [rel mp3_sr_table_mpeg1]
    mov eax, [r8 + rdx*4]
    mov [rel audio_cur_rate], eax
    mov eax, 1
    ret
.mp3_fail:
    xor eax, eax
    ret

