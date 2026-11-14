;; MODULE gui/img/img_exif_locate
;; LAYER 6
;; EXPORTS img_exif_locate
;; IMPORTS core/lib/crc32
;; CAPS
;; OWNER saga:gui_image_pipeline
;
; Native JPEG/PNG EXIF span discovery, NOT a pixel decoder or TIFF validator.
; img_exif_locate(RDI=immutable LE request40): src:u64@0,len:u64@8,
; dst:u64@16,cap:u64@24,reserved:u64@32=0. Mapped/stable borrowed source;
; len8..33554432, cap>=32. Full nonwrapping src/dst disjoint, full dst/request40
; disjoint; read-only src/request alias allowed. All nonvolatile64 and flags/DF
; preserved. EAX0/RDX32 found; EAX1/RDX0 absent; EAX2/RDX0 invalid/unsupported.
; Success writes exactly32 LE bytes: version:u32@0=1,format:u32@4(3JPEG/2PNG),
; TIFF_offset:u64@8,TIFF_len:u64@16,reserved:u64@24=0. No output on1/2.
; Offset/length describe original borrowed source, not a retained allocation or
; pointer. Caller keeps source stable for downstream TIFF parsing. No authority
; to display/share metadata or accept/decode image pixels follows from success.
;
; JPEG: walks SOI to exact terminal EOI, segments/fill bytes and all scan bytes,
; FF00 stuffing, RST/TEM and DNL resumption. >=1SOS required. One Exif\0\0 APP1
; before first SOS; duplicate/late Exif refuses. Other APP1/XMP ignored. Segment
; lengths checked before reads; no marker search inside segment payload. SOS
; content/DNL values/frame/Huffman/entropy semantics are decoder's job.
; PNG: signature, first unique13-byte IHDR, all chunk spans/names/CRC, contiguous
; >=1IDAT and zero-length exact terminal IEND. Known critical PLTE admitted only
; before IDAT; unknown critical refuses. One eXIf outside IDAT sequence, before
; or after IDAT. Other ancillary chunks ignored after CRC. IHDR dimensions,
; color/palette/animation/compression/filter data semantics remain decoder's job.
; Both: TIFF span8..65535 with classic II42/MM42 signature; no IFD traversal.
; This is a resource subset for metadata, not full PNG/Exif format coverage.
;
; O(source length), bounded32MiB, no allocation/global writes/IO/FP/SIMD.
; 80B private frame wiped on every exit;56B saved state+CRC8B return+16B saves
; =>160B deepest stack below caller return. CRC is existing pure table primitive.
; Creator: rc-ai-claude running on OpenAI Codex.
; https://www.w3.org/TR/2025/REC-png-3-20250624/#eXIf
; https://www.cipa.jp/std/documents/e/DC-X008-Translation-2019-E.pdf

img_exif_locate:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,80
    mov rbp,rsp
    cld
    mov r11,rdi
    mov rdi,rbp
    xor eax,eax
    mov ecx,10
    rep stosq
    test r11,r11
    jz .bad
    mov rax,r11
    add rax,40
    jc .bad
    mov r12,[r11]
    mov r13,[r11+8]
    mov rbx,[r11+16]
    mov rcx,[r11+24]
    test r12,r12
    jz .bad
    test rbx,rbx
    jz .bad
    cmp r13,8
    jb .bad
    cmp r13,33554432
    ja .bad
    cmp rcx,32
    jb .bad
    cmp qword [r11+32],0
    jne .bad
    mov rax,r12
    add rax,r13
    jc .bad
    mov rdx,rbx
    add rdx,rcx
    jc .bad
    cmp rbx,rax
    jae .source_disjoint
    cmp r12,rdx
    jb .bad
.source_disjoint:
    cmp r11,rdx
    jae .request_disjoint
    lea rax,[r11+40]
    cmp rbx,rax
    jb .bad
.request_disjoint:
    mov [rbp],rbx
    cmp word [r12],0xd8ff
    je .jpeg
    cmp dword [r12],0x474e5089
    jne .bad
    cmp dword [r12+4],0x0a1a0a0d
    jne .bad
    jmp .png

.jpeg:
    mov dword [rbp+32],3
    mov r14d,2
.marker_start:
    cmp r14,r13
    jae .bad
    cmp byte [r12+r14],0xff
    jne .bad
    xor r10d,r10d             ; marker came from header, not entropy
.marker_ff:
    inc r14
    cmp r14,r13
    jae .bad
    cmp byte [r12+r14],0xff
    je .marker_ff
    movzx ebx,byte [r12+r14]
    inc r14
    test bl,bl
    jz .bad                   ; FF00 valid only in scan, handled there
    cmp bl,0xd9
    je .jpeg_end
    cmp bl,0xd8
    je .bad
    cmp bl,1
    je .standalone
    cmp bl,0xc0
    jb .bad
    cmp bl,0xd0
    jb .segment
    cmp bl,0xd7
    ja .segment
    test r10d,r10d
    jz .bad                   ; RST only in scan
.standalone:
    test r10d,r10d
    jnz .entropy
    jmp .marker_start
.segment:
    mov [rbp+44],r10d
    lea rax,[r14+2]
    cmp rax,r13
    ja .bad
    movzx r15d,word [r12+r14]
    rol r15w,8
    cmp r15d,2
    jb .bad
    lea rax,[r14+r15]
    cmp rax,r13
    ja .bad
    mov [rbp+64],rax
    cmp bl,0xe1
    jne .after_app1
    cmp r15d,8
    jb .after_app1
    cmp dword [r12+r14+2],'Exif'
    jne .after_app1
    cmp word [r12+r14+6],0
    jne .after_app1
    cmp dword [rbp+36],0
    jne .bad
    cmp qword [rbp+24],0
    jne .bad
    lea rax,[r14+8]
    lea rcx,[r15-8]
    call .tiff_span
    jc .bad
.after_app1:
    mov r14,[rbp+64]
    cmp bl,0xda
    je .start_scan
    cmp bl,0xdc
    jne .marker_start
    cmp r15d,4
    jne .bad                   ; DNL has two-byte line count
    cmp dword [rbp+44],0
    jne .entropy
    jmp .marker_start
.start_scan:
    mov dword [rbp+36],1
.entropy:
    cmp r14,r13
    jae .bad
    cmp byte [r12+r14],0xff
    je .entropy_ff
    inc r14
    jmp .entropy
.entropy_ff:
    lea rax,[r14+1]
    cmp rax,r13
    jae .bad
    cmp byte [r12+rax],0
    jne .entropy_marker
    add r14,2
    jmp .entropy
.entropy_marker:
    mov r10d,1
    jmp .marker_ff
.jpeg_end:
    cmp dword [rbp+36],0
    je .bad
    cmp r14,r13
    jne .bad
    jmp .complete

.png:
    mov dword [rbp+32],2
    mov r14d,8
.chunk:
    lea rax,[r14+12]
    cmp rax,r13
    ja .bad
    mov r15d,[r12+r14]
    bswap r15d
    test r15d,r15d
    js .bad
    add rax,r15
    cmp rax,r13
    ja .bad
    mov [rbp+64],rax
    lea r10,[r12+r14]
    xor ecx,ecx
.chunk_name:
    movzx eax,byte [r10+rcx+4]
    or al,32
    sub al,'a'
    cmp al,25
    ja .bad
    inc ecx
    cmp ecx,4
    jb .chunk_name
    test byte [r12+r14+6],32
    jnz .bad
    lea rdi,[r12+r14+4]
    lea esi,[r15+4]
    call hotpatch_crc32
    lea rdx,[r12+r14]
    mov edx,[rdx+r15+8]
    bswap edx
    cmp eax,edx
    jne .bad
    mov ebx,[r12+r14+4]
    cmp r14,8
    jne .not_first
    cmp ebx,'IHDR'
    jne .bad
    cmp r15d,13
    jne .bad
    jmp .next_chunk
.not_first:
    cmp ebx,'IHDR'
    je .bad
    cmp ebx,'IDAT'
    je .idat
    cmp dword [rbp+48],1
    jne .not_idat
    mov dword [rbp+48],2
.not_idat:
    cmp ebx,'IEND'
    je .png_end
    cmp ebx,'eXIf'
    je .png_exif
    cmp ebx,'PLTE'
    je .plte
    test bl,32
    jz .bad                   ; unknown critical chunk
    jmp .next_chunk
.plte:
    cmp dword [rbp+48],0
    jne .bad
    jmp .next_chunk
.idat:
    cmp dword [rbp+48],2
    je .bad
    mov dword [rbp+48],1
    jmp .next_chunk
.png_exif:
    cmp qword [rbp+24],0
    jne .bad
    lea rax,[r14+8]
    mov rcx,r15
    call .tiff_span
    jc .bad
.next_chunk:
    mov r14,[rbp+64]
    jmp .chunk
.png_end:
    test r15d,r15d
    jnz .bad
    cmp dword [rbp+48],0
    je .bad
    mov rax,[rbp+64]
    cmp rax,r13
    jne .bad
.complete:
    cmp qword [rbp+24],0
    je .absent
    mov rdi,[rbp]
    mov dword [rdi],1
    mov eax,[rbp+32]
    mov [rdi+4],eax
    mov rax,[rbp+16]
    mov [rdi+8],rax
    mov rax,[rbp+24]
    mov [rdi+16],rax
    mov qword [rdi+24],0
    xor eax,eax
    mov edx,32
    jmp .done
.absent:
    mov eax,1
    xor edx,edx
    jmp .done
.bad:
    mov eax,2
    xor edx,edx
.done:
    mov r8d,eax
    mov r9,rdx
    mov rdi,rbp
    xor eax,eax
    mov ecx,10
    rep stosq
    mov eax,r8d
    mov rdx,r9
    add rsp,80
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    popfq
    ret

.tiff_span:                   ; RAX offset/RCX len already inside source
    cmp rcx,8
    jb .tiff_bad
    cmp rcx,65535
    ja .tiff_bad
    mov edx,[r12+rax]
    cmp edx,0x002a4949
    je .tiff_ok
    cmp edx,0x2a004d4d
    jne .tiff_bad
.tiff_ok:
    mov [rbp+16],rax
    mov [rbp+24],rcx
    clc
    ret
.tiff_bad:
    stc
    ret
