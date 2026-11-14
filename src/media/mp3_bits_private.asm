;; MODULE media/mp3_bits_private
;; LAYER 4
;; EXPORTS media_mp3_bits_read
;; IMPORTS
;; CAPS
;; OWNER saga:audio
; Private UNWIRED port of Classic mp3fe_getbits. No global decoder state.
; RDI=trusted mapped writable ctx32, RSI=0..24 count64 -> RAX=0/-1/-2,
; RDX=zero-extended bits,0 on refusal. Only bit_offset commits on success.
; ctx qwords: source,source_bytes,bit_offset,reserved0. Full spans disjoint,
; lower canonical, context aligned8. Arithmetic does not prove mappings.
; -1 span/count/bit boundary/reserved; -2 input view exceeds16MiB.
media_mp3_bits_read:
    test rdi,rdi
    jz .bad
    test dil,7
    jnz .bad
    mov rax,rdi
    add rax,32
    jc .bad
    dec rax
    shr rax,47
    jnz .bad
    cmp rsi,24
    ja .bad
    mov r8,rdi
    cmp qword [r8+24],0
    jne .bad
    mov r9,[r8]
    mov r10,[r8+8]
    mov r11,[r8+16]
    test r9,r9
    jz .bad
    cmp r10,16777216
    ja .quota
    mov rcx,r9
    shr rcx,47                  ; validate start even for empty source view
    jnz .bad
    mov rax,r9
    add rax,r10
    jc .bad
    mov rcx,rax
    dec rcx
    shr rcx,47
    jnz .bad
    test r10,r10
    jz .span_ok                  ; empty interval cannot overlap ctx
    lea rcx,[r8+32]
    cmp r8,rax
    jae .span_ok
    cmp r9,rcx
    jb .bad
.span_ok:
    shl r10,3                   ; byte quota makes this exact in64bits
    cmp r11,r10
    ja .bad
    mov rdi,r11
    add rdi,rsi
    jc .bad
    cmp rdi,r10
    ja .bad
    xor edx,edx
    test esi,esi
    jz .ok                      ; zero bits: no input read or context store
.read:
    mov rax,r11
    shr rax,3
    movzx eax,byte [r9+rax]
    mov ecx,r11d
    and ecx,7
    xor ecx,7                   ; Classic MSB first: 7-intra_byte_bit
    shr eax,cl
    and eax,1
    add edx,edx
    or edx,eax
    inc r11
    dec esi
    jnz .read                   ; <=24 iterations, at most4 distinct bytes
    mov [r8+16],rdi              ; commit only after complete successful read
.ok:
    xor eax,eax
    ret
.bad:
    mov rax,-1
    xor edx,edx
    ret
.quota:
    mov rax,-2
    xor edx,edx
    ret
