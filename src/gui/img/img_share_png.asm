;; MODULE gui/img/img_share_png
;; LAYER 6
;; EXPORTS img_share_png
;; IMPORTS gui/img/img_core, gui/img/img_png_encode
;; CAPS
;; OWNER saga:gui_image_pipeline
;; CONTEXT: bsp_only  (serialized image pipeline, heap and shared SHA256 workspace)
;
; Caller serializes ALL shared SHA users on BSP (no AP/IRQ/reentry), as required
; by native GIF source-copy qualification. This wrapper does not acquire a lock.
;
; Actual creator: rc-ai-claude running on OpenAI Codex.
; img_share_png(RDI=immutable request40) -> EAX=status, RDX=PNG bytes/0.
; Little endian: src:u64@0,len:u64@8,dst:u64@16,cap:u64@24,reserved:u64@32=0.
; Stable mapped caller-owned spans; src2..32MiB, cap1..32MiB. Full src/dst
; and dst/request40 spans must be disjoint and nonwrapping. Readonly source
; may contain the request. Destination slack and original bytes are untouched.
;
; BMP, PNG, JPEG and accepted native still-GIF use the actual core decoder,
; including its unchanged bounds, format/color policy and EXIF orientation.
; Re-encode canonical top-down RGBA as a new PNG containing ONLY IHDR, IDAT,
; IEND. No source EXIF/GPS/XMP/text/profile/thumbnail/comment bytes are copied.
; Alpha and hidden RGB are preserved from decoded pixels; JPEG remains subject
; to the existing decoder's color/rounding, not an additional JPEG encode.
; This does not remove location visibly drawn in pixels or authorize sharing.
;
; EAX0 success, 1 bad magic, 2 request/encoder bounds, 3..7 decoder errors,
; 8 busy (an existing decode output is left untouched).
; Refusals publish no destination bytes. Actual PNG encoder preflights before
; writing. Every successful decode is paired with actual img_output_release,
; including encoder refusal. No error is manufactured after output publication.
;
; Core-private decode/release seam in this translation unit, same as img_cache.
; Caller MUST serialize the singleton image pipeline and prevent intervening
; heap allocations until return, as for ordinary decode/release. No new lock or
; allocator reset: existing release's non-LIFO contention oracle remains intact.
; Unsupported concurrent heap activity can therefore leave img_active_out live;
; the core owner must retire it through the existing release path. The wrapper
; never clears or steals that ownership to hide failed reclamation.
; One bounded decoder allocation (format-specific scratch included), no encoder
; allocation, I/O, globals of its own, FP/SIMD or retained wrapper pointers.
; 96B initialized/wiped frame +56B saves; decoder/encoder stack is additional.
; RBX/RBP/R12-R15 and all caller flags including DF are preserved.

img_share_png:
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
    add  r10, 40
    jc   .bounds
    cmp  qword [r11 + 32], 0
    jne  .bounds
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
    cmp  r14, 33554432
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
    cmp  word [rbx], 'BM'
    je   .decode
    cmp  word [rbx], 0xD8FF
    je   .decode
    cmp  r12, 8
    jb   .magic
    cmp  dword [rbx], 0x474E5089
    jne  .magic
    cmp  dword [rbx + 4], 0x0A1A0A0D
    jne  .magic
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
    call img_png_encode
    mov  [rsp + 48], eax
    mov  [rsp + 56], rdx
    call img_output_release           ; also on encoder capacity refusal
    mov  eax, [rsp + 48]
    mov  rdx, [rsp + 56]
    jmp  .return
.magic:
    mov  eax, 1
    jmp  .failed
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
