;; MODULE media/mp3_header_private
;; LAYER 4
;; EXPORTS media_mp3_frame_header
;; IMPORTS
;; CAPS
;; OWNER saga:audio
; Private bounded MPEG1/2/2.5 LayerIII header/table port; see owned README.
; RDI=trusted stable mapped input, RSI=full available span, RDX=result32.
; RAX=0 success, -1 span/overlap/truncation, -2 unsupported header subset.
; Refusals preserve all memory. Arithmetic is not mapping/ownership proof.
; Only four input bytes read. Full spans lower canonical, result aligned8.
; Result uint32: rate,kbps,frame_bytes,channels,side_bytes,main_offset,
; main_bytes,header_be. No scan/CRC/body/entropy validation or PCM decoding.
media_mp3_frame_header:
    test rdi,rdi
    jz .bad
    cmp rsi,4
    jb .bad
    mov rax,rdi
    add rax,rsi
    jc .bad
    mov rcx,rax
    dec rcx
    shr rcx,47
    jnz .bad
    test rdx,rdx
    jz .bad
    test dl,7
    jnz .bad
    mov rcx,rdx
    add rcx,32
    jc .bad
    mov r8,rcx
    dec r8
    shr r8,47
    jnz .bad
    cmp rdi,rcx
    jae .disjoint
    cmp rdx,rax
    jb .bad
.disjoint:
    mov r8d,[rdi]
    bswap r8d
    mov ecx,r8d
    shr ecx,21
    cmp ecx,0x7ff
    jne .unsupported
    mov ecx,r8d
    shr ecx,19
    and ecx,3
    cmp ecx,1                    ; reserved version;0=2.5,2=2,3=1
    je .unsupported
    mov ecx,r8d
    shr ecx,17
    and ecx,3
    cmp ecx,1                    ; Classic LayerIII
    jne .unsupported
    mov eax,r8d
    shr eax,12
    and eax,15
    test eax,eax                 ; no free-format
    jz .unsupported
    cmp eax,14
    ja .unsupported
    lea rcx,[rel mp3h_bitrate]
    test r8d,0x80000             ; version1 bit: MPEG1 vs LSF
    jnz .bitrate
    lea rcx,[rel mp3h_bitrate_lsf]
.bitrate:
    movzx r10d,word [rcx+rax*2]
    mov eax,r8d
    shr eax,10
    and eax,3
    cmp eax,3
    je .unsupported
    lea rcx,[rel mp3h_rate]
    mov r9d,[rcx+rax*4]
    test r8d,0x80000
    jnz .rate
    shr r9d,1
    test r8d,0x100000
    jnz .rate
    shr r9d,1
.rate:
    mov rdi,rdx                  ; division clobbers RDX, preserve result
    mov eax,r10d
    imul eax,144000              ;1152samples MPEG1,576 LSF
    test r8d,0x80000
    jnz .length
    shr eax,1
.length:
    xor edx,edx
    div r9d
    mov ecx,r8d
    shr ecx,9
    and ecx,1
    add eax,ecx                  ; header padding
    mov r11d,eax
    cmp rsi,r11                  ; complete frame required, unsigned full64
    jb .bad
    mov esi,2
    mov ecx,32
    mov eax,r8d
    shr eax,6
    and eax,3
    cmp eax,3
    jne .channels
    mov esi,1
    mov ecx,17
.channels:
    test r8d,0x80000
    jnz .side
    mov ecx,17
    cmp esi,1
    jne .side
    mov ecx,9
.side:
    mov edx,4
    test r8d,0x10000             ; protection bit1 means no CRC word
    jnz .no_crc
    add edx,2
.no_crc:
    add edx,ecx
    cmp r11d,edx
    jb .bad
    mov eax,r11d
    sub eax,edx
    ; No fallible operation remains. Commit complete caller-owned result.
    mov [rdi],r9d
    mov [rdi+4],r10d
    mov [rdi+8],r11d
    mov [rdi+12],esi
    mov [rdi+16],ecx
    mov [rdi+20],edx
    mov [rdi+24],eax
    mov [rdi+28],r8d
    xor eax,eax
    ret
.bad:
    mov rax,-1
    ret
.unsupported:
    mov rax,-2
    ret
; Immutable Classic tables only, no global mutable decoder state.
mp3h_bitrate: dw 0,32,40,48,56,64,80,96,112,128,160,192,224,256,320,0
mp3h_rate: dd 44100,48000,32000,0

mp3h_bitrate_lsf: dw 0,8,16,24,32,40,48,56,64,80,96,112,128,144,160,0
