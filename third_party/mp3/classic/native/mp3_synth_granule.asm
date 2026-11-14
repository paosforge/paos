mp3_synth_granule:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi                     ; in base
    mov r13, rsi                     ; out base
    xor ebx, ebx                     ; slot
.sg_slot:
    cmp ebx, 18
    jae .sg_done
    ; --- shift FIFO down by 64: V[i]=V[i-64] for i=1023..64 ---
    lea rdi, [rel mp3sy_V]
    mov ecx, 1023
.sg_shift:
    cmp ecx, 64
    jb .sg_shift_done
    mov eax, ecx
    sub eax, 64
    movsd xmm0, [rdi + rax*8]
    movsd [rdi + rcx*8], xmm0
    dec ecx
    jmp .sg_shift
.sg_shift_done:
    ; --- V[i] = sum_k cosN[i*32+k]*S[k], S[k]=in[k*18+slot], i=0..63 ---
    xor r14d, r14d                   ; i
.sg_mm:
    cmp r14d, 64
    jae .sg_mm_done
    xorpd xmm0, xmm0                 ; acc
    mov rax, r14
    shl rax, 8                       ; i*32*8 = i*256 (byte offset of cosN row)
    lea r15, [rel mp3sy_cosN]
    add r15, rax                     ; &cosN[i*32]
    xor ecx, ecx                     ; k
.sg_dot:
    cmp ecx, 32
    jae .sg_dot_done
    movsd xmm1, [r15 + rcx*8]        ; cosN[i*32+k]
    mov eax, ecx
    imul eax, 18
    add eax, ebx                     ; k*18 + slot
    mulsd xmm1, [r12 + rax*8]        ; * S[k]
    addsd xmm0, xmm1
    inc ecx
    jmp .sg_dot
.sg_dot_done:
    lea rdi, [rel mp3sy_V]
    movsd [rdi + r14*8], xmm0
    inc r14d
    jmp .sg_mm
.sg_mm_done:
    ; --- build U[512]: U[i*64+j]=V[i*128+j]; U[i*64+32+j]=V[i*128+96+j] ---
    xor r14d, r14d                   ; i (0..7)
.sg_u_i:
    cmp r14d, 8
    jae .sg_u_done
    xor ecx, ecx                     ; j (0..31)
.sg_u_j:
    cmp ecx, 32
    jae .sg_u_j_done
    lea rdi, [rel mp3sy_V]
    lea rsi, [rel mp3sy_U]
    mov eax, r14d
    shl eax, 7                       ; i*128
    add eax, ecx                     ; V idx = i*128+j
    movsd xmm0, [rdi + rax*8]
    mov edx, r14d
    shl edx, 6                       ; i*64
    add edx, ecx                     ; U idx = i*64+j
    movsd [rsi + rdx*8], xmm0
    mov eax, r14d
    shl eax, 7
    add eax, 96
    add eax, ecx                     ; V idx = i*128+96+j
    movsd xmm0, [rdi + rax*8]
    mov edx, r14d
    shl edx, 6
    add edx, 32
    add edx, ecx                     ; U idx = i*64+32+j
    movsd [rsi + rdx*8], xmm0
    inc ecx
    jmp .sg_u_j
.sg_u_j_done:
    inc r14d
    jmp .sg_u_i
.sg_u_done:
    ; --- PCM[j] = sum_{m=0..15} U[j+32m]*D[j+32m]; out[slot*32+j] ---
    xor r14d, r14d                   ; j (0..31)
.sg_pcm:
    cmp r14d, 32
    jae .sg_pcm_done
    xorpd xmm0, xmm0                 ; acc
    xor ecx, ecx                     ; m
.sg_tap:
    cmp ecx, 16
    jae .sg_tap_done
    mov eax, ecx
    shl eax, 5                       ; m*32
    add eax, r14d                    ; j + 32m
    lea rdi, [rel mp3sy_U]
    lea rsi, [rel mp3sy_D]
    movsd xmm1, [rdi + rax*8]
    mulsd xmm1, [rsi + rax*8]
    addsd xmm0, xmm1
    inc ecx
    jmp .sg_tap
.sg_tap_done:
    mov eax, ebx
    shl eax, 5                       ; slot*32
    add eax, r14d
    movsd [r13 + rax*8], xmm0
    inc r14d
    jmp .sg_pcm
.sg_pcm_done:
    inc ebx
    jmp .sg_slot
.sg_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

