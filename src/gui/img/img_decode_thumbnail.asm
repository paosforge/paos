;; MODULE gui/img/img_decode_thumbnail
;; LAYER 6
;; EXPORTS img_decode_thumbnail
;; IMPORTS gui/img/img_core, gui/img/img_rgba_thumbnail
;; CAPS
;; OWNER saga:gui_image_pipeline
;; CONTEXT: bsp_only  (serialized image pipeline, heap and shared SHA256 workspace)
;
; Caller serializes ALL shared SHA users on BSP (no AP/IRQ/reentry), as required
; by native GIF source-copy qualification. This wrapper does not acquire a lock.
;
; Actual creator: rc-ai-claude running on OpenAI Codex.
; img_decode_thumbnail(RDI=immutable LE request48) -> EAX=status,RDX=bytes/0.
; src:u64@0,len:u64@8,dst:u64@16,cap:u64@24,
; max_w:u32@32,max_h:u32@36,reserved:u64@40=0.
; Caller-owned stable mapped spans. Compressed source2..32MiB, cap20..32MiB,
; box1..4096. Full declared src/dst and dst/request48 spans disjoint and
; nonwrapping; readonly source/request alias allowed. Original/slack unchanged.
;
; BMP/PNG/JPEG and accepted native still-GIF pass through the actual core
; decoder and its existing dimensions/4Mpixel bounds, color policy and EXIF
; orientation BEFORE fitting. Native GIF grammar/ownership checks are unchanged.
; Actual img_rgba_thumbnail area-averages into the existing16B version1 header
; and packed RGBA record. No upscaling; its exact alpha-weighted encoded-color
; and rounding rules apply. No metadata, file names or retained pointers in
; the output; no library/cache/scheduling/file/permission policy is installed.
;
; Status0 success;1 magic;2 request/thumbnail bounds;3..7 decoder errors;
; 8 busy. All refusals leave destination untouched. Every
; successful decode pairs with actual img_output_release, even short capacity.
; No error is invented after publication. Core-private ownership seam is the
; same as img_cache/share_png; caller serializes singleton image pipeline AND
; prevents intervening heap allocations until return. No forced owner reset:
; unsupported heap contention leaves the existing release diagnostic live and
; the core owner must retire it. Earlier live decode is preserved on busy8.
;
; One decoder allocation including format-specific scratch; thumbnail does
; not allocate. No wrapper globals, IO, FP/SIMD.96B initialized/wiped frame
; +56B saves; decoder/thumbnail stacks additional. Full64 nonvolatiles and
; all caller flags including DF preserved.

img_decode_thumbnail:
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
    cmp  r14, 20
    jb   .bounds
    cmp  r14, 33554432
    ja   .bounds
    mov  eax, [r11 + 32]
    test eax, eax
    jz   .bounds
    cmp  eax, 4096
    ja   .bounds
    mov  [rsp + 48], eax
    mov  eax, [r11 + 36]
    test eax, eax
    jz   .bounds
    cmp  eax, 4096
    ja   .bounds
    mov  [rsp + 52], eax
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
    jne  .busy
    cmp  word [rbx], 'GI'
    je   .decode
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
    mov  [rsp + 32], r13
    mov  [rsp + 40], r14
    mov  rdi, rbx
    mov  rsi, r12
    call img_decode
    test eax, eax
    jnz  .failed
    mov  [rsp], rbx                     ; oriented, packed top-down RGBA
    mov  [rsp + 24], ecx
    mov  [rsp + 28], edx
    mov  eax, ecx
    shl  rax, 2
    mov  [rsp + 16], rax                ; packed stride
    imul rax, rdx
    mov  [rsp + 8], rax
    mov  rdi, rsp                       ; complete initialized request64
    call img_rgba_thumbnail
    mov  [rsp + 64], eax
    mov  [rsp + 72], rdx
    call img_output_release
    mov  eax, [rsp + 64]
    mov  rdx, [rsp + 72]
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
