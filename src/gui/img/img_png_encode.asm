;; MODULE gui/img/img_png_encode
;; LAYER 6
;; EXPORTS img_png_encode, img_png_encode_surface
;; IMPORTS core/lib/crc32
;; CAPS
;; OWNER saga:gui_image_pipeline
;
; Actual creator: rc-ai-claude running on OpenAI Codex.
; img_png_encode(RDI=request48) -> EAX=IMG_OK(0)/IMG_E_BOUNDS(2), RDX=bytes/0.
; Immutable little-endian request: src:u64@0, src_len:u64@8, dst:u64@16,
; dst_cap:u64@24, width:u32@32, height:u32@36, src_stride:u64@40.
; Top-down straight-alpha RGBA8888, dimensions1..4096, area<=4194304.
; Required source=(height-1)*stride+width*4, stride>=width*4. Padding is unread.
; Output: deterministic PNG signature, IHDR(8bit RGBA/noninterlaced), one IDAT
; with zlib78/01, filter0 rows and stored DEFLATE blocks<=65535, then IEND.
; Raw N=(width*4+1)*height, blocks=ceil(N/65535); exact bytes=63+N+5*blocks.
; Maximum16782660 bytes. Pixels/alpha/hidden RGB preserved; no metadata copied.
; No compression-level/quality option: this is bounded lossless memory export.
; img_png_encode_surface uses the same request48, result/ownership/PNG contract,
; with axes1..16384 and area<=16777216. Maximum67130436 bytes at1024x16384.
; This entry admits full4K screenshot pixels without expanding the old entry's
; limits or any decoder/share/editor limit. Native large-image decoding remains
; separately bounded. Caller allocates exact PNG capacity using the formula above;
; maximum surface output includes overhead beyond64MiB packed input pixels.
;
; Full declared source/destination spans must not wrap or overlap. Destination
; must be disjoint from request48. All validation precedes writes; refused calls
; modify neither buffers nor request. On success output beyond RDX is untouched.
; Caller supplies mapped spans for the synchronous call. No allocation, scratch,
; retained pointer, filesystem/IO, FP/SIMD or mutation of source/request.
; RBX/RBP/R12-R15 and flags including DF are preserved. O(input/output bytes).

img_png_encode_surface:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 48
    mov  qword [rsp + 32], 16384      ; per-entry axis bound
    mov  qword [rsp + 40], 16777216   ; per-entry pixel bound
    jmp  img_png_encode.preflight

img_png_encode:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 48
    mov  qword [rsp + 32], 4096
    mov  qword [rsp + 40], 4194304
.preflight:
    test rdi, rdi
    jz   .bounds
    mov  rax, rdi
    add  rax, 48
    jc   .bounds
    mov  r11, rdi
    mov  rbx, [rdi]
    mov  r8, [rdi + 8]
    mov  rbp, [rdi + 16]
    mov  r9, [rdi + 24]
    mov  r12d, [rdi + 32]
    mov  r13d, [rdi + 36]
    mov  r14, [rdi + 40]
    test rbx, rbx
    jz   .bounds
    test rbp, rbp
    jz   .bounds
    test r12d, r12d
    jz   .bounds
    test r13d, r13d
    jz   .bounds
    cmp  r12, [rsp + 32]
    ja   .bounds
    cmp  r13, [rsp + 32]
    ja   .bounds
    mov  rax, r12
    imul rax, r13
    cmp  rax, [rsp + 40]
    ja   .bounds
    shl  r12, 2
    lea  rax, [r12 + 1]
    imul rax, r13
    mov  [rsp], rax                  ; unfiltered stream bytes remaining
    add  rax, 65534
    xor  edx, edx
    mov  ecx, 65535
    div  rcx
    lea  rax, [rax + rax * 4]        ; stored headers:5 bytes/block
    add  rax, [rsp]
    add  rax, 6                      ; zlib header + Adler32
    mov  [rsp + 16], rax             ; IDAT payload size (bounded u32)
    lea  r15, [rax + 57]             ; PNG signature + three chunk envelopes/IHDR
    cmp  r9, r15
    jb   .bounds
    mov  rax, rbx
    add  rax, r8
    jc   .bounds
    mov  rax, rbp
    add  rax, r9
    jc   .bounds
    cmp  r14, r12
    jb   .bounds
    mov  rax, r13
    dec  rax
    mul  r14
    test rdx, rdx
    jnz  .bounds
    add  rax, r12
    jc   .bounds
    cmp  r8, rax
    jb   .bounds
    lea  rax, [rbx + r8]
    cmp  rbp, rax
    jae  .source_disjoint
    lea  rax, [rbp + r9]
    cmp  rbx, rax
    jb   .bounds
.source_disjoint:
    lea  rax, [r11 + 48]
    cmp  rbp, rax
    jae  .descriptor_disjoint
    lea  rax, [rbp + r9]
    cmp  r11, rax
    jb   .bounds
.descriptor_disjoint:
    cld                              ; ordinary CRC caller state, restored below
    mov  rax, 0x0a1a0a0d474e5089
    mov  [rbp], rax
    mov  dword [rbp + 8], 0x0d000000
    mov  dword [rbp + 12], 'IHDR'
    mov  eax, r12d
    shr  eax, 2
    bswap eax
    mov  [rbp + 16], eax
    mov  eax, r13d
    bswap eax
    mov  [rbp + 20], eax
    mov  dword [rbp + 24], 0x00000608
    mov  byte [rbp + 28], 0
    lea  rdi, [rbp + 12]
    mov  esi, 17
    call hotpatch_crc32
    bswap eax
    mov  [rbp + 29], eax
    mov  eax, [rsp + 16]
    bswap eax
    mov  [rbp + 33], eax
    mov  dword [rbp + 37], 'IDAT'
    mov  word [rbp + 41], 0x0178
    lea  rdi, [rbp + 43]
    mov  qword [rsp + 8], 0          ; current block bytes remaining
    mov  r8d, 1                      ; Adler A
    xor  r9d, r9d                    ; Adler B
.row:
    xor  eax, eax                    ; filter0 prefix is part of zlib/Adler stream
    call .emit
    mov  rcx, r12
.pixel_byte:
    mov  al, [rbx]
    inc  rbx
    call .emit
    dec  rcx
    jnz  .pixel_byte
    dec  r13
    jz   .stream_done
    add  rbx, r14
    sub  rbx, r12
    jmp  .row
.stream_done:
    mov  eax, r9d
    shl  eax, 16
    or   eax, r8d
    bswap eax
    mov  [rdi], eax
    lea  rdi, [rbp + 37]
    mov  esi, [rsp + 16]
    add  esi, 4
    call hotpatch_crc32
    bswap eax
    mov  [rbp + r15 - 16], eax
    mov  dword [rbp + r15 - 12], 0
    mov  dword [rbp + r15 - 8], 'IEND'
    lea  rdi, [rbp + r15 - 8]
    mov  esi, 4
    call hotpatch_crc32
    bswap eax
    mov  [rbp + r15 - 4], eax
    xor  eax, eax
    mov  rdx, r15
    jmp  .out
.bounds:
    mov  eax, 2
    xor  edx, edx
.out:
    add  rsp, 48
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    popfq
    ret

; AL input byte, RDI output cursor, R8D/R9D Adler state. RCX/row state intact.
; Return address shifts caller's remaining-stream/block locals to+8/+16.
.emit:
    cmp  qword [rsp + 16], 0
    jne  .write
    mov  r10, [rsp + 8]
    cmp  r10, 65535
    jbe  .last_block
    mov  r10d, 65535
.last_block:
    xor  r11d, r11d
    cmp  r10, [rsp + 8]
    sete r11b
    mov  [rdi], r11b                 ; BFINAL, BTYPE00, byte-aligned stored block
    mov  [rdi + 1], r10w
    mov  r11d, r10d
    not  r11w
    mov  [rdi + 3], r11w
    add  rdi, 5
    mov  [rsp + 16], r10
.write:
    mov  [rdi], al
    inc  rdi
    movzx eax, al
    add  r8d, eax
    cmp  r8d, 65521
    jb   .a_reduced
    sub  r8d, 65521
.a_reduced:
    add  r9d, r8d
    cmp  r9d, 65521
    jb   .b_reduced
    sub  r9d, 65521
.b_reduced:
    dec  qword [rsp + 8]
    dec  qword [rsp + 16]
    ret
