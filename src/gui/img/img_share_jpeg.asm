;; MODULE gui/img/img_share_jpeg
;; LAYER 6
;; EXPORTS img_share_jpeg
;; IMPORTS gui/img/img_core, gui/img/img_jpeg_encode
;; CAPS
;; OWNER saga:gui_image_pipeline
;; CONTEXT: bsp_only  (serialized image pipeline, heap and shared SHA256 workspace)
;
; Caller serializes ALL shared SHA users on BSP (no AP/IRQ/reentry), as required
; by native GIF source-copy qualification. This wrapper does not acquire a lock.
;
; Actual creator: rc-ai-claude running on OpenAI Codex.
; img_share_jpeg(RDI=immutable LE request48) -> EAX=status,RDX=bytes/0.
; src:u64@0,len:u64@8,dst:u64@16,cap:u64@24,quality:u32@32(1..100),
; matte:u32@36(packed R,G,B,255),reserved:u64@40=0. Stable mapped caller
; spans: source2..32MiB,capacity1..64MiB. Entire declared src/dst and
; dst/request48 spans must be nonwrapping/disjoint. Readonly source/request
; alias allowed. Original/request/destination slack remain unchanged.
;
; Actual core decoding supplies oriented RGBA for its supported BMP family,
; PNG, JPEG and native still-GIF profiles, with unchanged4096axis/4Mpixel
; bounds/color/grammar policy. Actual JPEG encoder then writes baseline
; YCbCr444, quality1..100, with explicit alpha matte (C*A+M*(255-A)+127)/255.
; It requires capacity >=338+876*ceil(w/8)*ceil(h/8), even for smaller output.
; Quality100 is lossy. New JPEG contains only fixed JFIF, tables, frame/scan
; and entropy: no EXIF/GPS/XMP/profile/comments/source metadata copied.
; This cannot remove location visibly drawn in pixels or authorize sharing.
;
; Status0 success,1 bad magic,2 request/encoder bounds,3..7 core errors,
; 8 busy. All refusals leave destination untouched. Every
; successful decode pairs with actual img_output_release, including encoder
; capacity refusal. No error is invented after publication. Singleton core
; ownership is private as in img_cache/share_png: caller must serialize the
; pipeline and prevent intervening heap allocation until return. No forced
; owner reset; unsupported heap contention leaves the existing live-release
; diagnostic intact for the core owner. Busy preserves earlier live output.
;
; Existing decoder allocations/snapshots retain their own bounds/lifetimes;
; no encoder allocation, wrapper globals, IO, retained pointers, FP/SIMD.
; 96B initialized/wiped frame
; +56B saves; codec stacks additional. Full64 nonvolatiles/all flags/DF saved.

img_share_jpeg:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 96
    cld
    mov  r11, rdi
    mov  rdi, rsp
    xor  eax, eax
    mov  ecx, 12
    rep  stosq
    test r11, r11
    jz   .bounds
    mov  r10, r11
    add  r10, 48
    jc   .bounds
    cmp  qword [r11 + 40], 0
    jne  .bounds
    mov  eax, [r11 + 32]
    dec  eax
    cmp  eax, 99
    ja   .bounds
    cmp  byte [r11 + 39], 255
    jne  .bounds
    mov  rax, [r11 + 32]
    mov  [rsp + 48], rax              ; quality + matte for actual request64
    mov  rbx, [r11]
    mov  r12, [r11 + 8]
    mov  r13, [r11 + 16]
    mov  r14, [r11 + 24]
    test rbx, rbx
    jz   .bounds
    test r13, r13
    jz   .bounds
    cmp  r12, 2
    jb   .bounds
    cmp  r12, 33554432
    ja   .bounds
    test r14, r14
    jz   .bounds
    cmp  r14, 67108864
    ja   .bounds
    mov  r8, rbx
    add  r8, r12
    jc   .bounds
    mov  r9, r13
    add  r9, r14
    jc   .bounds
    cmp  rbx, r9
    jae  .input_clear
    cmp  r13, r8
    jb   .bounds
.input_clear:
    cmp  r11, r9
    jae  .request_clear
    cmp  r13, r10
    jb   .bounds
.request_clear:
    cmp  qword [rel img_active_out], 0
    jne  .busy                         ; never call decode over a live owner
    cmp  word [rbx], 'GI'
    je   .decode                       ; native bounded still-GIF policy
.decode:
    mov  [rsp + 16], r13
    mov  [rsp + 24], r14
    mov  rdi, rbx
    mov  rsi, r12
    call img_decode
    test eax, eax
    jnz  .failed
    mov  [rsp], rbx                    ; oriented packed RGBA from decoder
    mov  [rsp + 32], ecx
    mov  [rsp + 36], edx
    mov  eax, ecx
    shl  rax, 2
    mov  [rsp + 40], rax               ; width*4 stride
    imul rax, rdx
    mov  [rsp + 8], rax                ; width*height*4 declared span
    mov  rdi, rsp
    call img_jpeg_encode
    mov  [rsp + 64], eax
    mov  [rsp + 72], rdx
    call img_output_release           ; also on encoder capacity refusal
    mov  eax, [rsp + 64]
    mov  rdx, [rsp + 72]
    jmp  .return
.bounds:
    mov  eax, 2
    jmp  .failed
.busy:
    mov  eax, 8
.failed:
    xor  edx, edx
.return:
    mov  r8d, eax
    mov  r9, rdx
    mov  rdi, rsp
    xor  eax, eax
    mov  ecx, 12
    rep  stosq
    mov  eax, r8d
    mov  rdx, r9
    add  rsp, 96
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    popfq
    ret
