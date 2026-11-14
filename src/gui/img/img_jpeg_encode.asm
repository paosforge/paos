;; MODULE gui/img/img_jpeg_encode
;; LAYER 6
;; EXPORTS img_jpeg_encode
;; IMPORTS
;; CAPS
;; OWNER saga:gui_image_pipeline
;
; Native memory-only baseline JPEG, 8-bit YCbCr 4:4:4, one sequential scan.
; img_jpeg_encode(RDI=request64) -> EAX=0/RDX=actual bytes, or EAX=2/RDX=0.
; Little-endian request: src:u64@0, len:u64@8, dst:u64@16, cap:u64@24,
; width:u32@32, height:u32@36, stride:u64@40, quality:u32@48 (1..100),
; matte:u32@52 (packed R,G,B,255), reserved:u64@56=0. Borrowed top-down
; RGBA8888: dimensions 1..4096, area <=4194304; required source span is
; (height-1)*stride+width*4, stride>=width*4. Caller maps and retains spans.
; Destination capacity must be at least 338+876*ceil(width/8)*ceil(height/8),
; a conservative worst-case bound, even if the resulting file is smaller.
; Full nonwrapping declared source/destination spans are disjoint; full
; destination/request64 spans are disjoint. Read-only source/request alias is
; permitted. Validation precedes all destination writes. Refusal is immutable.
;
; Explicit alpha flattening: (C*A+matteC*(255-A)+127)/255, per channel.
; Fixed integer RGB->YCbCr; edge pixels replicate to complete 8x8 blocks.
; Orthonormal Q14 cosine basis; quantization rounds signed magnitudes once
; to nearest (ties away from zero) after both DCT stages. One luminance table
; serves all components: standard example values scaled by 5000/Q if Q<50,
; otherwise 200-2*Q; (base*scale+50)/100 clamped to 1..255. Quality100 is
; still lossy. Small fixed canonical DC(4-bit)/AC(8-bit) Huffman tables trade
; compression for simple bounded work. No EXIF/location/ICC/comments copied;
; fixed JFIF1.01 declares YCbCr. No file I/O, allocator, retained pointer,
; global mutable state, SIMD/FP, metadata parser or source mutation.
; Reentrant with disjoint destinations and stable caller-owned source/request.
; Full64 RBX/RBP/R12-R15, flags incl DF, FP state preserved. 896B private
; frame is zeroed on exit; deepest stack 976B incl saves and return addresses
; below the caller's return address. No quality/speed/UI/metal acceptance.

img_jpeg_encode:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 896
    mov  rbp, rsp
    test rdi, rdi
    jz   .bounds
    mov  rax, rdi
    add  rax, 64
    jc   .bounds
    cmp  qword [rdi + 56], 0
    jne  .bounds
    mov  eax, [rdi + 48]
    dec  eax
    cmp  eax, 99
    ja   .bounds
    cmp  byte [rdi + 55], 255
    jne  .bounds
    mov  rbx, [rdi]
    mov  r8, [rdi + 8]
    mov  r13, [rdi + 16]
    mov  r9, [rdi + 24]
    mov  r14d, [rdi + 32]
    mov  r15d, [rdi + 36]
    test rbx, rbx
    jz   .bounds
    test r13, r13
    jz   .bounds
    test r14d, r14d
    jz   .bounds
    test r15d, r15d
    jz   .bounds
    cmp  r14d, 4096
    ja   .bounds
    cmp  r15d, 4096
    ja   .bounds
    mov  eax, r14d
    imul rax, r15
    cmp  rax, 4194304
    ja   .bounds
    lea  eax, [r14 + 7]
    shr  eax, 3
    lea  ecx, [r15 + 7]
    shr  ecx, 3
    imul eax, ecx
    imul eax, 876
    add  eax, 338                   ; bounded below 59MiB by geometry caps
    cmp  r9, rax
    jb   .bounds
    mov  rax, rbx
    add  rax, r8
    jc   .bounds
    mov  rax, r13
    add  rax, r9
    jc   .bounds
    mov  r12, [rdi + 40]
    lea  rcx, [r14 * 4]
    cmp  r12, rcx
    jb   .bounds
    mov  eax, r15d
    dec  eax
    mul  r12
    test rdx, rdx
    jnz  .bounds
    add  rax, rcx
    jc   .bounds
    cmp  r8, rax
    jb   .bounds
    lea  rax, [rbx + r8]
    cmp  r13, rax
    jae  .source_disjoint
    lea  rax, [r13 + r9]
    cmp  rbx, rax
    jb   .bounds
.source_disjoint:
    lea  rax, [rdi + 64]
    cmp  r13, rax
    jae  .request_disjoint
    lea  rax, [r13 + r9]
    cmp  rdi, rax
    jb   .bounds
.request_disjoint:
    mov  [rbp], rbx                 ; source
    mov  [rbp + 8], r12             ; stride
    mov  [rbp + 16], r14d
    mov  [rbp + 20], r15d
    mov  eax, [rdi + 52]
    mov  [rbp + 24], eax            ; matte
    mov  [rbp + 32], r13            ; initial output pointer
    mov  ecx, [rdi + 48]
    mov  eax, 5000
    xor  edx, edx
    cmp  ecx, 50
    jb   .low_quality
    mov  eax, 100
    sub  eax, ecx
    shl  eax, 1
    jmp  .scale
.low_quality:
    div  ecx
.scale:
    mov  r8d, eax
    lea  rsi, [rel img_jpe_quant_base]
    xor  edi, edi
.quant:
    movzx eax, byte [rsi + rdi]
    imul eax, r8d
    add  eax, 50
    xor  edx, edx
    mov  ecx, 100
    div  ecx
    mov  ecx, 1
    cmp  eax, ecx
    cmovb eax, ecx
    mov  ecx, 255
    cmp  eax, ecx
    cmova eax, ecx
    mov  [rbp + rdi * 2 + 640], ax
    inc  edi
    cmp  edi, 64
    jb   .quant
    cld
    lea  rsi, [rel img_jpe_prefix]
    mov  rdi, r13
    mov  ecx, img_jpe_prefix_end - img_jpe_prefix
    rep  movsb
    mov  r13, rdi
    lea  rsi, [rel img_jpe_zigzag]
    xor  ecx, ecx
.dqt:
    movzx eax, byte [rsi + rcx]
    mov  al, [rbp + rax * 2 + 640]
    mov  [r13], al
    inc  r13
    inc  ecx
    cmp  ecx, 64
    jb   .dqt
    lea  rsi, [rel img_jpe_sof]
    mov  rdi, r13
    mov  ecx, img_jpe_sof_end - img_jpe_sof
    rep  movsb
    mov  eax, [rbp + 20]
    xchg al, ah
    mov  [r13 + 5], ax
    mov  eax, [rbp + 16]
    xchg al, ah
    mov  [r13 + 7], ax
    mov  r13, rdi
    lea  rsi, [rel img_jpe_huff_scan]
    mov  ecx, img_jpe_huff_scan_end - img_jpe_huff_scan
    rep  movsb
    mov  r13, rdi
    mov  qword [rbp + 40], 0         ; MCU x,y
    mov  qword [rbp + 52], 0         ; bit count + buffer low
    mov  qword [rbp + 56], 0
    mov  qword [rbp + 64], 0         ; three DC predictors
    mov  dword [rbp + 72], 0
.mcu:
    mov  dword [rbp + 48], 0         ; component Y,Cb,Cr
.component:
    call .fill
    call .dct
    call .entropy
    inc  dword [rbp + 48]
    cmp  dword [rbp + 48], 3
    jb   .component
    inc  dword [rbp + 40]
    mov  eax, [rbp + 40]
    shl  eax, 3
    cmp  eax, [rbp + 16]
    jb   .mcu
    mov  dword [rbp + 40], 0
    inc  dword [rbp + 44]
    mov  eax, [rbp + 44]
    shl  eax, 3
    cmp  eax, [rbp + 20]
    jb   .mcu
    mov  ecx, 8
    sub  ecx, [rbp + 52]
    cmp  ecx, 8
    je   .finished
    mov  eax, 1
    shl  eax, cl
    dec  eax                        ; final byte padded with ones, then stuffed
    call .bits
.finished:
    mov  word [r13], 0xd9ff
    add  r13, 2
    mov  rdx, r13
    sub  rdx, [rbp + 32]
    xor  r8d, r8d
    jmp  .out
.bounds:
    mov  r8d, 2
    xor  edx, edx
.out:
    mov  rdi, rbp
    mov  ecx, 112
    xor  eax, eax
    cld
    rep  stosq                      ; retire all private pixels/coefficients
    mov  eax, r8d
    add  rsp, 896
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    popfq
    ret

.fill:
    xor  r15d, r15d
.row:
    xor  r14d, r14d
.pixel:
    mov  eax, [rbp + 40]
    lea  eax, [r14 + rax * 8]
    mov  ecx, [rbp + 16]
    dec  ecx
    cmp  eax, ecx
    cmova eax, ecx
    mov  ebx, eax
    mov  eax, [rbp + 44]
    lea  eax, [r15 + rax * 8]
    mov  ecx, [rbp + 20]
    dec  ecx
    cmp  eax, ecx
    cmova eax, ecx
    imul rax, [rbp + 8]
    add  rax, [rbp]
    mov  eax, [rax + rbx * 4]
    call .colour
    lea  ecx, [r14 + r15 * 8]
    mov  [rbp + rcx * 2 + 128], ax
    inc  r14d
    cmp  r14d, 8
    jb   .pixel
    inc  r15d
    cmp  r15d, 8
    jb   .row
    ret

.colour:
    mov  r11d, eax
    shr  eax, 24
    mov  r10d, eax                  ; alpha
    xor  r9d, r9d
    xor  r8d, r8d
.channel:
    mov  eax, r11d
    mov  ecx, r8d
    shr  eax, cl
    and  eax, 255
    imul eax, r10d
    mov  esi, [rbp + 24]
    shr  esi, cl
    and  esi, 255
    mov  ecx, 255
    sub  ecx, r10d
    imul esi, ecx
    lea  eax, [rax + rsi + 127]
    xor  edx, edx
    mov  ecx, 255
    div  ecx
    mov  [rbp + r9 * 4 + 80], eax
    add  r8d, 8
    inc  r9d
    cmp  r9d, 3
    jb   .channel
    cmp  dword [rbp + 48], 0
    jne  .chroma
    imul eax, [rbp + 80], 19595
    imul ecx, [rbp + 84], 38470
    imul edx, [rbp + 88], 7471
    add  eax, ecx
    lea  eax, [rax + rdx + 32768]
    shr  eax, 16
    sub  eax, 128
    ret
.chroma:
    cmp  dword [rbp + 48], 1
    jne  .cr
    imul eax, [rbp + 80], -11059
    imul ecx, [rbp + 84], -21709
    imul edx, [rbp + 88], 32768
    jmp  .chroma_sum
.cr:
    imul eax, [rbp + 80], 32768
    imul ecx, [rbp + 84], -27439
    imul edx, [rbp + 88], -5329
.chroma_sum:
    add  eax, ecx
    lea  eax, [rax + rdx + 32768]
    sar  eax, 16
    mov  ecx, 127
    cmp  eax, ecx
    cmovg eax, ecx
    ret

.dct:
    lea  r12, [rel img_jpe_basis]
    xor  r14d, r14d                 ; y
.hrow:
    xor  r15d, r15d                 ; u
.hcol:
    xor  ecx, ecx
    xor  r10d, r10d
    lea  r8d, [r14 * 8]
    lea  r9d, [r15 * 8]
.hdot:
    lea  eax, [r8 + rcx]
    movsx ebx, word [rbp + rax * 2 + 128]
    lea  eax, [r9 + rcx]
    movsx edx, word [r12 + rax * 2]
    imul ebx, edx
    add  r10d, ebx
    inc  ecx
    cmp  ecx, 8
    jb   .hdot
    lea  eax, [r8 + r15]
    mov  [rbp + rax * 4 + 256], r10d
    inc  r15d
    cmp  r15d, 8
    jb   .hcol
    inc  r14d
    cmp  r14d, 8
    jb   .hrow
    xor  r14d, r14d                 ; v
.vrow:
    xor  r15d, r15d                 ; u
.vcol:
    xor  ecx, ecx
    xor  r10d, r10d
    lea  r9d, [r14 * 8]
.vdot:
    lea  eax, [r15 + rcx * 8]
    movsxd rbx, dword [rbp + rax * 4 + 256]
    lea  eax, [r9 + rcx]
    movsx rdx, word [r12 + rax * 2]
    imul rbx, rdx
    add  r10, rbx
    inc  ecx
    cmp  ecx, 8
    jb   .vdot
    lea  esi, [r15 + r14 * 8]
    movzx r9d, word [rbp + rsi * 2 + 640]
    shl  r9, 28                     ; one combined DCT/quantization rounding
    mov  rax, r10
    sar  r10, 63
    xor  rax, r10
    sub  rax, r10
    mov  rdx, r9
    shr  rdx, 1
    add  rax, rdx
    xor  edx, edx
    div  r9
    xor  rax, r10
    sub  rax, r10
    mov  [rbp + rsi * 2 + 512], ax
    inc  r15d
    cmp  r15d, 8
    jb   .vcol
    inc  r14d
    cmp  r14d, 8
    jb   .vrow
    ret

.entropy:
    mov  ecx, [rbp + 48]
    movsx eax, word [rbp + 512]
    mov  edx, [rbp + rcx * 4 + 64]
    mov  [rbp + rcx * 4 + 64], eax
    sub  eax, edx
    mov  edi, -1
    call .number
    mov  r14d, 1                    ; zigzag index
    xor  r15d, r15d                 ; zero run
.ac:
    lea  rsi, [rel img_jpe_zigzag]
    movzx ecx, byte [rsi + r14]
    movsx ebx, word [rbp + rcx * 2 + 512]
    test ebx, ebx
    jnz  .nonzero
    inc  r15d
    jmp  .next
.nonzero:
    cmp  r15d, 16
    jb   .value
    mov  eax, 1                     ; ZRL has 8-bit code 1
    mov  ecx, 8
    call .bits
    sub  r15d, 16
    jmp  .nonzero
.value:
    mov  eax, ebx
    mov  edi, r15d
    call .number
    xor  r15d, r15d
.next:
    inc  r14d
    cmp  r14d, 64
    jb   .ac
    test r15d, r15d
    jz   .entropy_done
    xor  eax, eax                   ; EOB has 8-bit code 0
    mov  ecx, 8
    call .bits
.entropy_done:
    ret

.number:
    mov  [rbp + 808], eax
    cdq
    xor  eax, edx
    sub  eax, edx
    xor  ecx, ecx
    test eax, eax
    jz   .category
    bsr  ecx, eax
    inc  ecx
.category:
    mov  [rbp + 812], ecx
    test edi, edi
    js   .dc_code
    imul eax, edi, 10
    lea  eax, [rax + rcx + 1]        ; EOB,ZRL, then run*10+(size-1)
    mov  ecx, 8
    jmp  .code
.dc_code:
    mov  eax, ecx
    mov  ecx, 4
.code:
    call .bits
    mov  ecx, [rbp + 812]
    test ecx, ecx
    jz   .number_done
    mov  eax, [rbp + 808]
    test eax, eax
    jns  .positive
    dec  eax                        ; JPEG negative amplitude is one's complement
.positive:
    mov  edx, 1
    shl  edx, cl
    dec  edx
    and  eax, edx
    call .bits
.number_done:
    ret

.bits:
    mov  r8, [rbp + 56]
    shl  r8, cl
    or   r8, rax
    mov  edx, [rbp + 52]
    add  edx, ecx
.byte:
    cmp  edx, 8
    jb   .remaining
    sub  edx, 8
    mov  rax, r8
    mov  ecx, edx
    shr  rax, cl
    mov  [r13], al
    inc  r13
    cmp  al, 255
    jne  .byte
    mov  byte [r13], 0              ; byte stuffing only in entropy data
    inc  r13
    jmp  .byte
.remaining:
    mov  ecx, edx
    mov  eax, 1
    shl  eax, cl
    dec  eax
    and  r8, rax
    mov  [rbp + 56], r8
    mov  [rbp + 52], edx
    ret

section .rodata
img_jpe_prefix:
    db 0xff,0xd8, 0xff,0xe0,0,16, 'JFIF',0, 1,1,0, 0,1,0,1,0,0
    db 0xff,0xdb,0,67,0
img_jpe_prefix_end:
img_jpe_sof:
    db 0xff,0xc0,0,17,8, 0,0,0,0, 3, 1,0x11,0, 2,0x11,0, 3,0x11,0
img_jpe_sof_end:
img_jpe_huff_scan:
    db 0xff,0xc4,0,210
    db 0, 0,0,0,12,0,0,0,0,0,0,0,0,0,0,0,0
    db 0,1,2,3,4,5,6,7,8,9,10,11
    db 0x10, 0,0,0,0,0,0,0,162,0,0,0,0,0,0,0,0
    db 0,0xf0
%assign jpe_run 0
%rep 16
%assign jpe_cat 1
%rep 10
    db (jpe_run << 4) | jpe_cat
%assign jpe_cat jpe_cat + 1
%endrep
%assign jpe_run jpe_run + 1
%endrep
%undef jpe_run
%undef jpe_cat
    db 0xff,0xda,0,12,3,1,0,2,0,3,0,0,63,0
img_jpe_huff_scan_end:
img_jpe_quant_base:
    db 16,11,10,16,24,40,51,61
    db 12,12,14,19,26,58,60,55
    db 14,13,16,24,40,57,69,56
    db 14,17,22,29,51,87,80,62
    db 18,22,37,56,68,109,103,77
    db 24,35,55,64,81,104,113,92
    db 49,64,78,87,103,121,120,101
    db 72,92,95,98,112,100,103,99
img_jpe_zigzag:
    db 0,1,8,16,9,2,3,10,17,24,32,25,18,11,4,5
    db 12,19,26,33,40,48,41,34,27,20,13,6,7,14,21,28
    db 35,42,49,56,57,50,43,36,29,22,15,23,30,37,44,51
    db 58,59,52,45,38,31,39,46,53,60,61,54,47,55,62,63
img_jpe_basis:
    dw 5793,5793,5793,5793,5793,5793,5793,5793
    dw 8035,6811,4551,1598,-1598,-4551,-6811,-8035
    dw 7568,3135,-3135,-7568,-7568,-3135,3135,7568
    dw 6811,-1598,-8035,-4551,4551,8035,1598,-6811
    dw 5793,-5793,-5793,5793,5793,-5793,-5793,5793
    dw 4551,-8035,1598,6811,-6811,-1598,8035,-4551
    dw 3135,-7568,7568,-3135,-3135,7568,-7568,3135
    dw 1598,-4551,6811,-8035,8035,-6811,4551,-1598
section .text
