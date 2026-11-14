mp3_hybrid_granule:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi                     ; xr base
    mov r13, rsi                     ; out base
    xor ebx, ebx                     ; sb
.hg_sb:
    cmp ebx, 32
    jae .hg_done
    mov eax, ebx
    imul eax, 144                    ; sb*18*8 bytes
    lea rdi, [r12 + rax]
    lea rsi, [rel mp3hy_imdct_tmp]
    call mp3_imdct_long              ; preserves rbx/r12/r13; r15 free (set below)
    mov r14d, ebx
    imul r14d, 18                    ; line base = sb*18
    xor r15d, r15d                   ; s
.hg_s:
    cmp r15d, 18
    jae .hg_save
    lea rdx, [rel mp3hy_imdct_tmp]
    movsd xmm0, [rdx + r15*8]
    lea rcx, [rel mp3hy_overlap]
    lea rax, [r14 + r15]             ; line = base + s
    addsd xmm0, [rcx + rax*8]
    test ebx, 1                      ; odd subband?
    jz .hg_store
    test r15d, 1                     ; odd sample?
    jz .hg_store
    movsd xmm1, [rel mp3hy_signbit]
    xorpd xmm0, xmm1                 ; frequency inversion: negate
.hg_store:
    movsd [r13 + rax*8], xmm0
    inc r15d
    jmp .hg_s
.hg_save:
    xor r15d, r15d
.hg_sv:
    cmp r15d, 18
    jae .hg_next
    lea rdx, [rel mp3hy_imdct_tmp]
    mov eax, r15d
    add eax, 18
    movsd xmm0, [rdx + rax*8]
    lea rcx, [rel mp3hy_overlap]
    lea rax, [r14 + r15]
    movsd [rcx + rax*8], xmm0
    inc r15d
    jmp .hg_sv
.hg_next:
    inc ebx
    jmp .hg_sb
.hg_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

