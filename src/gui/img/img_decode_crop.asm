;; MODULE gui/img/img_decode_crop
;; LAYER 6
;; EXPORTS img_decode_crop
;; IMPORTS gui/img/img_core, gui/img/img_rgba_crop
;; CAPS
;; OWNER saga:gui_image_pipeline
;; CONTEXT: bsp_only  (serialized image pipeline, heap and shared SHA256 workspace)
;
; Actual creator: rc-ai-claude running on OpenAI Codex.
; img_decode_crop(RDI=immutable LE request64) -> EAX=status,RDX=span/0.
; src:u64@0,len:u64@8,dst:u64@16,cap:u64@24,dst_stride:u64@32,
; crop_x:u32@40,crop_y:u32@44,crop_w:u32@48,crop_h:u32@52,
; clockwise_quarter_turns:u32@56 (0..3),reserved:u32@60=0.
; Stable mapped caller spans. Source2..32MiB, capacity4..64MiB, crop axes
; 1..4096, area<=4M. Full declared src/dst and dst/request64 disjoint and
; nonwrapping; read-only source/request alias allowed. Destination dimensions
; swap on odd turns; stride and last-row pixel span must fit before decode.
;
; Decode accepted BMP family/PNG/JPEG/native still-GIF through actual core,
; applying EXIF orientation BEFORE crop coordinates. Crop must fit oriented
; decoded source; then rotate clockwise in exact quarter turns. Straight RGBA
; including hidden RGB is copied exactly; padding/slack and compressed source
; remain unchanged. No metadata copy, file IO, UI or authority grant.
;
; Status0 success;1 magic;2 bounds;3..7 decoder errors;8 busy. Refusals never
; write destination. Every successful decode pairs with img_output_release,
; including a source-rectangle refusal. Earlier live output is preserved on
; busy8. Release contention retains honest core ownership, never force-reset.
; Caller serializes ALL shared SHA users on BSP (no AP/IRQ/reentry), singleton
; pipeline and heap, preventing intervening allocations until return.
;
; No wrapper allocations/globals/FP/SIMD. Decoder may allocate nested BMP
; scratch; renderer allocates nothing. Initialized/wiped96B frame +56B saves,
; callees additional. Full64 nonvolatiles/flags/DF preserved.

img_decode_crop:
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
    add  r10, 64
    jc   .bounds
    cmp  dword [r11 + 60], 0
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
    cmp  r14, 4
    jb   .bounds
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
    ; Stage the raw renderer's immutable80B request before calling core.
    mov  [rsp + 16], r13
    mov  [rsp + 24], r14
    mov  rax, [r11 + 32]
    mov  [rsp + 64], rax
    mov  rax, [r11 + 40]
    mov  [rsp + 48], rax
    mov  rax, [r11 + 48]
    mov  [rsp + 56], rax
    mov  eax, [r11 + 56]
    cmp  eax, 3
    ja   .bounds
    mov  [rsp + 72], eax
    ; Destination-only and absolute crop bounds precede allocation.
    mov  eax, [rsp + 56]
    mov  ecx, [rsp + 60]
    test eax, eax
    jz   .bounds
    test ecx, ecx
    jz   .bounds
    cmp  eax, 4096
    ja   .bounds
    cmp  ecx, 4096
    ja   .bounds
    cmp  dword [rsp + 48], 4096
    jae  .bounds
    cmp  dword [rsp + 52], 4096
    jae  .bounds
    mov  edx, eax
    imul edx, ecx
    cmp  edx, 4194304
    ja   .bounds
    test dword [rsp + 72], 1
    jz   .dimensions
    xchg eax, ecx
.dimensions:
    shl  rax, 2
    cmp  [rsp + 64], rax
    jb   .bounds
    mov  r8, rax
    mov  eax, ecx
    dec  rax
    mul  qword [rsp + 64]
    test rdx, rdx
    jnz  .bounds
    add  rax, r8
    jc   .bounds
    cmp  rax, r14
    ja   .bounds
    cmp  qword [rel img_active_out], 0
    jne  .busy
    cmp  word [rbx], 'GI'
    je   .decode
    cmp  word [rbx], 'BM'
    je   .decode
    cmp  word [rbx], 'BA'
    je   .decode
    cmp  word [rbx], 'IC'
    je   .decode
    cmp  word [rbx], 'PT'
    je   .decode
    cmp  word [rbx], 'CI'
    je   .decode
    cmp  word [rbx], 'CP'
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
    mov  rdi, rbx
    mov  rsi, r12
    call img_decode
    test eax, eax
    jnz  .failed
    mov  [rsp], rbx
    mov  [rsp + 32], ecx
    mov  [rsp + 36], edx
    mov  eax, ecx
    shl  rax, 2
    mov  [rsp + 40], rax
    imul rax, rdx
    mov  [rsp + 8], rax
    mov  rdi, rsp
    call img_rgba_crop
    mov  [rsp + 80], eax
    mov  [rsp + 88], rdx
    call img_output_release
    mov  eax, [rsp + 80]
    mov  rdx, [rsp + 88]
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
