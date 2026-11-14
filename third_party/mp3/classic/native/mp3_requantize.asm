mp3_requantize:
    push rbp
    mov rbp, rsp
    sub rsp, 16
    mov eax, edi
    test eax, eax
    jnz .mrq_nz
    xorpd xmm0, xmm0                 ; is==0 -> 0.0
    jmp .mrq_done
.mrq_nz:
    xor r8d, r8d                     ; r8d = negative-sign flag
    test eax, eax
    jns .mrq_pos
    neg eax
    mov r8d, 1
.mrq_pos:
    mov [rbp-8], eax                 ; |is| (int32)
    ; st0 = |is|^(4/3) = 2^( (4/3) * log2(|is|) )
    fild dword [rbp-8]               ; st0=|is|
    fld qword [rel mp3_c_four_thirds]; st0=4/3, st1=|is|
    fxch                             ; st0=|is|, st1=4/3
    fyl2x                            ; st0=(4/3)*log2(|is|)  (pops)
    fld st0                          ; st0=y, st1=y
    frndint                          ; st0=round(y)=n, st1=y
    fsub st1, st0                    ; st1 = y - n  (frac in [-0.5,0.5])
    fxch                             ; st0=frac, st1=n
    f2xm1                            ; st0 = 2^frac - 1
    fld1
    faddp st1, st0                   ; st0 = 2^frac
    fscale                           ; st0 = 2^frac * 2^n = |is|^(4/3)  (st1=n)
    fstp st1                         ; drop n -> st0 = |is|^(4/3)
    ; multiply by 2^(0.25*(gain-210))
    mov eax, esi
    sub eax, 210
    mov [rbp-8], eax
    fild dword [rbp-8]               ; st0=(gain-210), st1=xr
    fld qword [rel mp3_c_quarter]    ; st0=0.25, st1=(gain-210), st2=xr
    fmulp st1, st0                   ; st0=0.25*(gain-210), st1=xr
    fld st0                          ; st0=e, st1=e, st2=xr
    frndint                          ; st0=n
    fsub st1, st0                    ; st1=frac
    fxch                             ; st0=frac, st1=n
    f2xm1
    fld1
    faddp st1, st0                   ; st0=2^frac
    fscale                           ; st0=2^e  (st1=n)
    fstp st1                         ; st0=2^e, st1=xr
    fmulp st1, st0                   ; st0 = xr * 2^e
    fstp qword [rbp-16]
    movsd xmm0, [rbp-16]
    test r8d, r8d
    jz .mrq_done
    xorpd xmm1, xmm1
    subsd xmm1, xmm0                 ; negate
    movapd xmm0, xmm1
.mrq_done:
    mov rsp, rbp
    pop rbp
    ret

