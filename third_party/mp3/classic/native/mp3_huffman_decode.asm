mp3_huffman_decode:
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
    lea r9, [rel mp3_huff_tab32]
    cmp dword [rsp+24], 0
    je .mhd_c1_cb0
    lea r9, [rel mp3_huff_tab33]
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
    add rbx, 16
    add dword [rsp+0], 4
    call .mhd_check_bits
    jmp .mhd_c1_loop
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
    lea r9, [rel mp3_huff_tabindex]
    movzx r10d, word [r9 + r8*2]  ; base element index into tabs
    lea r9, [rel mp3_huff_linbits]
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
    lea r9, [rel mp3_huff_tabs]
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

