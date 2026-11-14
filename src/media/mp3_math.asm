;; MODULE media/mp3p_math
;; LAYER 4
;; EXPORTS mp3p_alias_reduce_bands, mp3p_hybrid_typed, mp3p_requant_short, mp3p_reorder_short, mp3p_huffman_decode, mp3p_requant_granule, mp3p_ms_stereo, mp3p_alias_reduce, mp3p_hybrid_granule, mp3p_synth_granule
;; IMPORTS
;; CAPS
;; OWNER rc-codex-av
; Private pure math helpers. Port Classic0cab native routines; see provenance.
; ONLY producer-validated caller-owned scratch/limits; not an untrusted API.
; Math runs inside producer's saved/normalized/restored full FP environment.
; Requant R10=immutable23-dword rate-specific long band positions.
; Hybrid RDX=overlap576 doubles,RCX=tmp36 doubles. Typed addsR8=block_type,
; R9=mixed long subbands0/2; old entry remains normal-long. Synth RDX=V1024,RCX=U512.
; No mutable globals, allocation, external codec runtime or data reads beyond
; padded private entropy buffer. Immutable tables are included separately.
mp3p_requantize:
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
    fld qword [rel mp3p_c_four_thirds]; st0=4/3, st1=|is|
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
    fld qword [rel mp3p_c_quarter]    ; st0=0.25, st1=(gain-210), st2=xr
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

mp3p_imdct_long:
    lea rdx,[rel mp3p_imdct_win_long]
mp3p_imdct_window:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r15,rdx                     ; explicit36-sample window
    mov r12, rdi                     ; X
    mov r13, rsi                     ; OUT
    lea r14, [rel mp3p_imdct_cos36]
    xor ebx, ebx                     ; i
.iml_i:
    cmp ebx, 36
    jae .iml_done
    xorpd xmm0, xmm0                 ; acc
    mov eax, ebx
    imul eax, 144                    ; 18 doubles * 8 bytes per row
    lea rcx, [r14 + rax]             ; row ptr = cos36 + i*18
    xor edx, edx                     ; k
.iml_k:
    cmp edx, 18
    jae .iml_kdone
    movsd xmm1, [r12 + rdx*8]
    mulsd xmm1, [rcx + rdx*8]
    addsd xmm0, xmm1
    inc edx
    jmp .iml_k
.iml_kdone:
    mov rax,r15
    mulsd xmm0, [rax + rbx*8]
    movsd [r13 + rbx*8], xmm0
    inc ebx
    jmp .iml_i
.iml_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

mp3p_huffman_decode:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 48
    ; --- save config to locals ---
    mov [rsp+0], dword 0          ; idx (count of values stored)
    mov [rsp+8], ecx              ; limit_bits
    mov [rsp+16], rdi             ; buf_base
    mov [rsp+24], r8d             ; count1_table
    mov rbx, r9                   ; dst = is_out
    ; --- init bit reader (pos=0) ---
    mov r14, rdi                  ; next_ptr = buf
    movzx eax, byte [r14]
    shl eax, 8
    movzx r10d, byte [r14+1]
    or eax, r10d
    shl eax, 8
    movzx r10d, byte [r14+2]
    or eax, r10d
    shl eax, 8
    movzx r10d, byte [r14+3]
    or eax, r10d                  ; eax = b0<<24|b1<<16|b2<<8|b3
    mov r12d, eax                 ; cache
    mov r13d, -8                  ; sh
    add r14, 4                    ; next_ptr += 4
    mov r15, [rsp+16]
    mov eax, esi
    add r15, rax                  ; buf_end = buf_base + buflen
    ; --- big_values regions ---
    mov rbp, rdx                  ; region ptr
.mhd_region:
    mov r8d, [rbp]                ; table_num
    cmp r8d, -1
    je .mhd_regions_done
    mov ecx, [rbp+4]             ; pair_count
.mhd_pair:
    test ecx, ecx
    jz .mhd_region_next
    push rcx
    mov r8d, [rbp]               ; table_num (reload; constant per region)
    call .mhd_decode_pair
    pop rcx
    mov rax,r14
    sub rax,[rsp+16]
    shl rax,3
    sub eax,24
    add eax,r13d
    cmp eax,[rsp+8]
    jg .mhd_error
    add dword [rsp+0], 2
    dec ecx
    jmp .mhd_pair
.mhd_region_next:
    add rbp, 8
    jmp .mhd_region
.mhd_regions_done:
    ; --- count1 region ---
.mhd_c1_loop:
    cmp dword [rsp+0], 572
    jg .mhd_done
    ; leaf = cb[peek(4)]
    mov eax, r12d
    shr eax, 28                  ; peek(4)
    lea r9, [rel mp3p_huff_tab32]
    cmp dword [rsp+24], 0
    je .mhd_c1_cb0
    lea r9, [rel mp3p_huff_tab33]
.mhd_c1_cb0:
    movzx edi, byte [r9 + rax]   ; leaf
    test edi, 8
    jnz .mhd_c1_have
    ; second level: leaf = cb[(leaf>>3) + ((cache<<4) >> (32-(leaf&3)))]
    mov ecx, edi
    and ecx, 3
    mov eax, 32
    sub eax, ecx
    mov ecx, eax                 ; cl = 32-(leaf&3)
    mov eax, r12d
    shl eax, 4
    shr eax, cl
    mov esi, edi
    sar esi, 3                   ; leaf>>3
    add eax, esi
    movzx edi, byte [r9 + rax]
.mhd_c1_have:
    ; flush(leaf & 7)
    mov ecx, edi
    and ecx, 7
    mov eax, ecx
    shl r12d, cl
    add r13d, eax
    ; BSPOS = (next_ptr - buf_base)*8 - 24 + sh
    mov rax, r14
    sub rax, [rsp+16]
    shl rax, 3
    sub eax, 24
    add eax, r13d
    cmp eax, [rsp+8]
    jg .mhd_done                 ; overshoot: discard this quad, stop
    ; emit 4 values (present bits 128>>s); absent stay 0 (buffer pre-zeroed)
    test edi, 128
    jz .mhd_c1_s0
    mov r9d, 1
    test r12d, r12d
    jns .mhd_c1_s0p
    neg r9d
.mhd_c1_s0p:
    mov [rbx], r9d
    shl r12d, 1
    add r13d, 1
.mhd_c1_s0:
    test edi, 64
    jz .mhd_c1_s1
    mov r9d, 1
    test r12d, r12d
    jns .mhd_c1_s1p
    neg r9d
.mhd_c1_s1p:
    mov [rbx+4], r9d
    shl r12d, 1
    add r13d, 1
.mhd_c1_s1:
    test edi, 32
    jz .mhd_c1_s2
    mov r9d, 1
    test r12d, r12d
    jns .mhd_c1_s2p
    neg r9d
.mhd_c1_s2p:
    mov [rbx+8], r9d
    shl r12d, 1
    add r13d, 1
.mhd_c1_s2:
    test edi, 16
    jz .mhd_c1_s3
    mov r9d, 1
    test r12d, r12d
    jns .mhd_c1_s3p
    neg r9d
.mhd_c1_s3p:
    mov [rbx+12], r9d
    shl r12d, 1
    add r13d, 1
.mhd_c1_s3:
    mov rax,r14
    sub rax,[rsp+16]
    shl rax,3
    sub eax,24
    add eax,r13d
    cmp eax,[rsp+8]
    jle .mhd_quad_commit
    mov qword [rbx],0
    mov qword [rbx+8],0
    jmp .mhd_done
.mhd_quad_commit:
    add rbx, 16
    add dword [rsp+0], 4
    call .mhd_check_bits
    jmp .mhd_c1_loop
.mhd_error:
    mov dword [rsp+0],-1
.mhd_done:
    mov eax, [rsp+0]
    add rsp, 48
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; --- internal: decode one big_values pair. r8d=table_num. Writes 2 int32 at
;     [rbx], advances rbx by 8. Uses reader regs r12-r15; scratch eax/ecx/edx/
;     esi/edi/r9/r10/r11. Preserves rbx(adv)/rbp/r8. ---
.mhd_decode_pair:
    lea r9, [rel mp3p_huff_tabindex]
    movzx r10d, word [r9 + r8*2]  ; base element index into tabs
    lea r9, [rel mp3p_huff_linbits]
    movzx r11d, byte [r9 + r8]    ; linbits
    mov esi, 5                    ; w
    xor edx, edx                  ; adj
.mhd_dp_loop:
    mov ecx, 32
    sub ecx, esi
    mov eax, r12d
    shr eax, cl                   ; peek(w)
    add eax, edx                  ; + adj
    add eax, r10d                 ; + base
    lea r9, [rel mp3p_huff_tabs]
    movsx edi, word [r9 + rax*2]  ; leaf (signed)
    test edi, edi
    jns .mhd_dp_term
    ; non-terminal: flush(w); w = leaf&7; adj = -(leaf>>3)
    mov ecx, esi
    shl r12d, cl
    add r13d, esi
    mov esi, edi
    and esi, 7
    mov edx, edi
    sar edx, 3
    neg edx
    jmp .mhd_dp_loop
.mhd_dp_term:
    ; flush(leaf>>8)
    mov ecx, edi
    sar ecx, 8                    ; codelen
    mov eax, ecx
    shl r12d, cl
    add r13d, eax
    ; ---- value j=0 ----
    mov eax, edi
    and eax, 0x0F                 ; lsb
    test r11d, r11d
    jz .mhd_dp0_sign
    cmp eax, 15
    jne .mhd_dp0_sign
    mov ecx, 32
    sub ecx, r11d
    mov r9d, r12d
    shr r9d, cl
    add eax, r9d                  ; lsb += peek(linbits)
    mov ecx, r11d
    shl r12d, cl
    add r13d, r11d
    push rax                      ; preserve magnitude — .mhd_check_bits clobbers eax (xor eax,eax)
    call .mhd_check_bits
    pop rax
.mhd_dp0_sign:
    mov r9d, eax                  ; magnitude
    test r12d, r12d
    jns .mhd_dp0_pos
    neg r9d
.mhd_dp0_pos:
    mov [rbx], r9d
    test eax, eax
    jz .mhd_dp0_nf
    shl r12d, 1
    add r13d, 1
.mhd_dp0_nf:
    shr edi, 4                    ; lf >>= 4
    ; ---- value j=1 ----
    mov eax, edi
    and eax, 0x0F
    test r11d, r11d
    jz .mhd_dp1_sign
    cmp eax, 15
    jne .mhd_dp1_sign
    mov ecx, 32
    sub ecx, r11d
    mov r9d, r12d
    shr r9d, cl
    add eax, r9d
    mov ecx, r11d
    shl r12d, cl
    add r13d, r11d
    push rax                      ; preserve magnitude — .mhd_check_bits clobbers eax (xor eax,eax)
    call .mhd_check_bits
    pop rax
.mhd_dp1_sign:
    mov r9d, eax
    test r12d, r12d
    jns .mhd_dp1_pos
    neg r9d
.mhd_dp1_pos:
    mov [rbx+4], r9d
    test eax, eax
    jz .mhd_dp1_nf
    shl r12d, 1
    add r13d, 1
.mhd_dp1_nf:
    add rbx, 8
    call .mhd_check_bits
    ret

; --- internal: refill bit cache. Mirrors minimp3 CHECK_BITS. Uses eax/ecx,
;     reads r14(next)/r15(end), updates r12(cache)/r13(sh)/r14. ---
.mhd_check_bits:
    cmp r13d, 0
    jl .mhd_cb_done
    xor eax, eax
    cmp r14, r15
    jae .mhd_cb_zero
    movzx eax, byte [r14]
.mhd_cb_zero:
    inc r14
    mov ecx, r13d
    shl eax, cl
    or r12d, eax
    sub r13d, 8
    jmp .mhd_check_bits
.mhd_cb_done:
    ret

mp3p_sfb_of_line:
    push rcx
    push rdx
    push r8
    mov rdx, r10                    ; immutable rate-specific band positions
    xor ecx, ecx
.sol_loop:
    cmp ecx, 21
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

; mp3p_requant_granule(rdi=is(int32*), rsi=xr(double*), edx=global_gain,
;   rcx=scalefac(int32*), r8d=scalefac_scale, r9d=nz). Zeros xr[576] then
;   requantizes the first nz lines: eff_gain = global_gain -
;   2*(1+scale)*scalefac[sfb]; xr[i] = mp3p_requantize(is[i], eff_gain).
mp3p_requant_granule:
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
    call mp3p_sfb_of_line             ; eax = sfb
    mov eax, [r14 + rax*4]           ; scalefac[sfb]
    imul eax, ebx                    ; mult*scalefac
    mov edx, [rsp+0]                 ; global_gain
    sub edx, eax                     ; eff_gain
    mov edi, [r12 + r15*4]           ; is[i]
    mov esi, edx                     ; eff_gain
    call mp3p_requantize              ; xmm0 = xr[i]
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

; mp3p_ms_stereo(rdi=xr_l, rsi=xr_r): in-place MS (mid/side) decode, 576 lines.
mp3p_ms_stereo:
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

mp3p_alias_reduce:
    mov esi,31
mp3p_alias_reduce_bands:
    inc esi                         ; boundary index1..count inclusive
    mov r8d, 1                       ; sb
.ar_sb:
    cmp r8d,esi
    jge .ar_done
    mov eax, r8d
    imul eax, 18                     ; b = boundary line
    xor ecx, ecx                     ; k
.ar_k:
    cmp ecx, 8
    jge .ar_next
    mov edx, eax
    sub edx, ecx
    dec edx                          ; lo idx = b-1-k
    mov r9d, eax
    add r9d, ecx                     ; up idx = b+k
    movsd xmm0, [rdi + rdx*8]        ; lo
    movsd xmm1, [rdi + r9*8]         ; up
    lea r10, [rel mp3dq_cs]
    movsd xmm2, [r10 + rcx*8]        ; cs[k]
    lea r10, [rel mp3dq_ca]
    movsd xmm3, [r10 + rcx*8]        ; ca[k]
    movapd xmm4, xmm0
    mulsd xmm4, xmm2                 ; lo*cs
    movapd xmm5, xmm1
    mulsd xmm5, xmm3                 ; up*ca
    subsd xmm4, xmm5                 ; new lo = lo*cs - up*ca
    movapd xmm6, xmm1
    mulsd xmm6, xmm2                 ; up*cs
    movapd xmm7, xmm0
    mulsd xmm7, xmm3                 ; lo*ca
    addsd xmm6, xmm7                 ; new up = up*cs + lo*ca
    movsd [rdi + rdx*8], xmm4
    movsd [rdi + r9*8], xmm6
    inc ecx
    jmp .ar_k
.ar_next:
    inc r8d
    jmp .ar_sb
.ar_done:
    ret

mp3p_hybrid_granule:
    xor r8d,r8d
    xor r9d,r9d
mp3p_hybrid_typed:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,32
    mov [rsp],rdx                   ; caller-owned overlap
    mov [rsp+16],r8d                ; block type0/1/2/3
    mov [rsp+20],r9d                ; mixed long prefix2 subbands
    mov [rsp+8],rcx                 ; caller-owned IMDCT temporary
    mov r12, rdi                     ; xr base
    mov r13, rsi                     ; out base
    xor ebx, ebx                     ; sb
.hg_sb:
    cmp ebx, 32
    jae .hg_done
    mov eax, ebx
    imul eax, 144                    ; sb*18*8 bytes
    lea rdi, [r12 + rax]
    mov rsi,[rsp+8]
    lea rdx,[rel mp3p_imdct_win_long]
    cmp ebx,[rsp+20]
    jb .hg_transform_long
    mov eax,[rsp+16]
    cmp eax,2
    je .hg_transform_short
    cmp eax,1
    jne .hg_check_stop
    lea rdx,[rel mp3p_window_start]
    jmp .hg_transform_long
.hg_check_stop:
    cmp eax,3
    jne .hg_transform_long
    lea rdx,[rel mp3p_window_stop]
.hg_transform_long:
    call mp3p_imdct_window
    jmp .hg_transform_done
.hg_transform_short:
    call mp3p_imdct_short
.hg_transform_done:
    mov r14d, ebx
    imul r14d, 18                    ; line base = sb*18
    xor r15d, r15d                   ; s
.hg_s:
    cmp r15d, 18
    jae .hg_save
    mov rdx,[rsp+8]
    movsd xmm0, [rdx + r15*8]
    mov rcx,[rsp]
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
    mov rdx,[rsp+8]
    mov eax, r15d
    add eax, 18
    movsd xmm0, [rdx + rax*8]
    mov rcx,[rsp]
    lea rax, [r14 + r15]
    movsd [rcx + rax*8], xmm0
    inc r15d
    jmp .hg_sv
.hg_next:
    inc ebx
    jmp .hg_sb
.hg_done:
    add rsp,32
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

mp3p_synth_granule:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,16
    mov [rsp],rdx                   ; caller-owned V FIFO
    mov [rsp+8],rcx                 ; caller-owned U scratch
    mov r12, rdi                     ; in base
    mov r13, rsi                     ; out base
    xor ebx, ebx                     ; slot
.sg_slot:
    cmp ebx, 18
    jae .sg_done
    ; --- shift FIFO down by 64: V[i]=V[i-64] for i=1023..64 ---
    mov rdi,[rsp]
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
    mov rdi,[rsp]
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
    mov rdi,[rsp]
    mov rsi,[rsp+8]
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
    mov rdi,[rsp+8]
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
    add rsp,16
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret


mp3p_c_four_thirds: dq 1.3333333333333333
mp3p_c_quarter: dq 0.25
mp3hy_signbit: dq 0x8000000000000000

; Short IMDCT adaptation of Classic's matrix/window long kernel: three6->12
; transforms gathered from the reordered interleaved spectrum, placed at6+6w.
; CC0 reference L3_imdct12/short supplies ordering/overlap authority. Finite
;36zero +3*12*6 dots; caller-owned tmp36, no state/publication in this helper.
mp3p_imdct_short:
 push rbx
 push r12
 push r13
 push r14
 push r15
 mov r12,rdi
 mov r13,rsi
 mov rdi,r13
 xor eax,eax
 mov ecx,36
 rep stosq
 xor ebx,ebx
.window:
 xor r14d,r14d
.sample:
 lea r15,[rel mp3p_cos12]
 imul eax,r14d,48
 add r15,rax
 xor ecx,ecx
 xorpd xmm0,xmm0
.dot:
 lea eax,[rcx+rcx*2]
 add eax,ebx
 movsd xmm1,[r12+rax*8]
 mulsd xmm1,[r15+rcx*8]
 addsd xmm0,xmm1
 inc ecx
 cmp ecx,6
 jb .dot
 lea rax,[rel mp3p_window_short]
 mulsd xmm0,[rax+r14*8]
 imul eax,ebx,6
 lea eax,[rax+r14+6]
 addsd xmm0,[r13+rax*8]
 movsd [r13+rax*8],xmm0
 inc r14d
 cmp r14d,12
 jb .sample
 inc ebx
 cmp ebx,3
 jb .window
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbx
 ret

; Native Classic reorder gather generalized from its44.1k permutation to
; actual immutable rate-specific width triplets. RDI=xr,RSI=scratch576,
; RDX=short/mixed widths,R8d=long-sf prefix0/8,R9d=long-lines0/36.
; Long prefix remains in place. Return finite reordered suffix in XR.
mp3p_reorder_short:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 mov r12,rdi
 mov r13,rsi
 lea r14,[rdx+r8]
 mov eax,r9d
 lea r12,[r12+rax*8]
 mov r15,r12
 mov rbp,r13
.band:
 movzx ebx,byte [r14]
 test ebx,ebx
 jz .copy
 xor ecx,ecx
.line:
 movsd xmm0,[r12+rcx*8]
 movsd [r13],xmm0
 lea eax,[rbx+rcx]
 movsd xmm0,[r12+rax*8]
 movsd [r13+8],xmm0
 add eax,ebx
 movsd xmm0,[r12+rax*8]
 movsd [r13+16],xmm0
 add r13,24
 inc ecx
 cmp ecx,ebx
 jb .line
 imul eax,ebx,24
 add r12,rax
 add r14,3
 jmp .band
.copy:
 mov rcx,r13
 sub rcx,rbp
 shr rcx,3
 mov rdi,r15
 mov rsi,rbp
 rep movsq
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret

; Requant short/mixed coded-order spectrum; finite width-table sum576.
; RDI=is,RSI=xr,EDX=global_gain,RCX=sf[40],R8d=scale,R9d=long_sf0/8,
; R10=widths40,R11=subblock_gains3. Preflag does not apply to short layout.
mp3p_requant_short:
 push rbx
 push rbp
 push r12
 push r13
 push r14
 push r15
 sub rsp,48
 mov r12,rdi
 mov r13,rsi
 mov r14,rcx
 mov r15,r10
 mov [rsp],edx
 lea eax,[r8*2+2]
 mov [rsp+4],eax
 mov [rsp+8],r9d
 mov [rsp+16],r11
 mov dword [rsp+24],0             ; sf index
 mov dword [rsp+28],0             ; running spectral line
.sf:
 mov eax,[rsp+24]
 movzx ebp,byte [r15+rax]
 test ebp,ebp
 jz .done
 mov ecx,[r14+rax*4]
 imul ecx,[rsp+4]
 mov ebx,[rsp]
 sub ebx,ecx
 sub eax,[rsp+8]
 jc .gain
 xor edx,edx
 mov ecx,3
 div ecx
 mov rax,[rsp+16]
 mov eax,[rax+rdx*4]
 shl eax,3
 sub ebx,eax
.gain:
 mov eax,[rsp+28]
 mov edi,[r12+rax*4]
 mov esi,ebx
 call mp3p_requantize
 mov eax,[rsp+28]
 movsd [r13+rax*8],xmm0
 inc dword [rsp+28]
 dec ebp
 jnz .gain
 inc dword [rsp+24]
 jmp .sf
.done:
 add rsp,48
 pop r15
 pop r14
 pop r13
 pop r12
 pop rbp
 pop rbx
 ret
