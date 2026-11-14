mp3_sfb_of_line:
    push rcx
    push rdx
    push r8
    lea rdx, [rel mp3dq_sfb_long]
    xor ecx, ecx
.sol_loop:
    cmp ecx, mp3dq_sfb_long_count-1
    jge .sol_done
    mov r8d, [rdx + rcx*4 + 4]       ; SFB_LONG[sfb+1] upper boundary
    cmp eax, r8d
    jl .sol_done
    inc ecx
    jmp .sol_loop
.sol_done:
    mov eax, ecx
    pop r8
    pop rdx
    pop rcx
    ret

; mp3_requant_granule(rdi=is(int32*), rsi=xr(double*), edx=global_gain,
;   rcx=scalefac(int32*), r8d=scalefac_scale, r9d=nz). Zeros xr[576] then
;   requantizes the first nz lines: eff_gain = global_gain -
;   2*(1+scale)*scalefac[sfb]; xr[i] = mp3_requantize(is[i], eff_gain).
mp3_requant_granule:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    sub rsp, 16
    mov [rsp+0], edx                 ; global_gain
    mov [rsp+8], r9d                 ; nz
    mov r12, rdi                     ; is_ptr
    mov r13, rsi                     ; xr_ptr
    mov r14, rcx                     ; scalefac_ptr
    mov ebx, r8d
    lea ebx, [rbx*2 + 2]             ; mult = 2*(1+scale)
    ; zero xr[576] (= 1152 dwords)
    mov rdi, r13
    xor eax, eax
    mov ecx, 1152
    cld
    rep stosd
    xor r15d, r15d                   ; i
.rg_loop:
    cmp r15d, [rsp+8]
    jge .rg_done
    mov eax, r15d
    call mp3_sfb_of_line             ; eax = sfb
    mov eax, [r14 + rax*4]           ; scalefac[sfb]
    imul eax, ebx                    ; mult*scalefac
    mov edx, [rsp+0]                 ; global_gain
    sub edx, eax                     ; eff_gain
    mov edi, [r12 + r15*4]           ; is[i]
    mov esi, edx                     ; eff_gain
    call mp3_requantize              ; xmm0 = xr[i]
    movsd [r13 + r15*8], xmm0
    inc r15d
    jmp .rg_loop
.rg_done:
    add rsp, 16
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; mp3_ms_stereo(rdi=xr_l, rsi=xr_r): in-place MS (mid/side) decode, 576 lines.
mp3_ms_stereo:
    movsd xmm3, [rel mp3dq_inv_sqrt2]
    xor ecx, ecx
.ms_loop:
    cmp ecx, 576
    jge .ms_done
    movsd xmm0, [rdi + rcx*8]        ; m
    movsd xmm1, [rsi + rcx*8]        ; s
    movapd xmm2, xmm0
    addsd xmm2, xmm1                 ; m+s
    mulsd xmm2, xmm3
    subsd xmm0, xmm1                 ; m-s
    mulsd xmm0, xmm3
    movsd [rdi + rcx*8], xmm2
    movsd [rsi + rcx*8], xmm0
    inc ecx
    jmp .ms_loop
.ms_done:
    ret

