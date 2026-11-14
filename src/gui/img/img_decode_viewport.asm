;; MODULE gui/img/img_decode_viewport
;; LAYER 6
;; EXPORTS img_decode_viewport
;; IMPORTS gui/img/img_core, gui/img/img_rgba_viewport
;; CAPS
;; OWNER saga:gui_image_pipeline
;; CONTEXT: bsp_only  (serialized image pipeline, heap and shared SHA256 workspace)
;
; Caller serializes ALL shared SHA users on BSP (no AP/IRQ/reentry), as required
; by native GIF source-copy qualification. This wrapper does not acquire a lock.
;
; Actual creator: rc-ai-claude running on OpenAI Codex.
; img_decode_viewport(RDI=immutable LE request80) -> EAX=status,RDX=span/0.
; src:u64@0,len:u64@8,dst:u64@16,cap:u64@24,dst_stride:u64@32,
; dst_w:u32@40,dst_h:u32@44,origin_x:i32@48,origin_y:i32@52,
; step_x:u32@56,step_y:u32@60,background:RGBA8888-u32@64,
; reserved:u32@68=0,reserved:u64@72=0. Stable mapped caller spans.
; Source2..32MiB, destination capacity4..64MiB, axes1..4096,area<=4M.
; Full declared src/dst spans and dst/request80 must be disjoint/nonwrapping;
; read-only source/request alias allowed. Destination rows/stride must fit.
;
; Decode accepted BMP family/PNG/JPEG/native still-GIF through actual core,
; applying EXIF orientation before viewport coordinates. Native GIF grammar
; and ownership checks are unchanged. Existing viewport signed16.16 origin,
; unsigned step1..4096*65536 and exact point-sampling/background rules apply.
; Copies straight RGBA including hidden RGB. Writes pixels only; destination
; row padding/slack and compressed original remain unchanged. No metadata copy.
;
; Status0 success;1 magic;2 bounds;3..7 decoder errors;8 busy. All refusals
; leave destination unchanged. Every successful decode pairs with actual
; img_output_release. Caller serializes singleton pipeline AND prevents heap
; allocation until return; release contention retains honest core ownership,
; never force-reset here. Earlier live decode is preserved on busy8.
;
; No wrapper allocation, globals, IO, FP/SIMD or UI policy. Decoder may allocate
; nested BMP container scratch; renderer allocates nothing. Initialized/wiped
; 128B frame +56B saves, callees additional. Full64 nonvolatiles/flags/DF kept.

img_decode_viewport:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 128
    cld
    mov  r11, rdi
    mov  rdi, rsp
    xor  eax, eax
    mov  ecx, 16
    rep  stosq
    test r11, r11
    jz   .bounds
    mov  r10, r11
    add  r10, 80
    jc   .bounds
    cmp  dword [r11 + 68], 0
    jne  .bounds
    cmp  qword [r11 + 72], 0
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
    mov  [rsp + 16], r13
    mov  [rsp + 24], r14
    mov  rax, [r11 + 32]
    mov  [rsp + 48], rax
    mov  rax, [r11 + 40]
    mov  [rsp + 56], rax
    mov  rax, [r11 + 48]
    mov  [rsp + 64], rax
    mov  rax, [r11 + 56]
    mov  [rsp + 72], rax
    mov  eax, [r11 + 64]
    mov  [rsp + 80], eax
    ; Destination-only validation precedes decode and its allocation.
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
    mov  edx, eax
    imul edx, ecx
    cmp  edx, 4194304
    ja   .bounds
    shl  rax, 2
    cmp  [rsp + 48], rax
    jb   .bounds
    mov  r8, rax
    mov  eax, ecx
    dec  rax
    mul  qword [rsp + 48]
    test rdx, rdx
    jnz  .bounds
    add  rax, r8
    jc   .bounds
    cmp  rax, r14
    ja   .bounds
    mov  eax, [rsp + 72]
    test eax, eax
    jz   .bounds
    cmp  eax, 268435456
    ja   .bounds
    mov  eax, [rsp + 76]
    test eax, eax
    jz   .bounds
    cmp  eax, 268435456
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
    call img_rgba_viewport
    mov  [rsp + 96], eax
    mov  [rsp + 104], rdx
    call img_output_release
    mov  eax, [rsp + 96]
    mov  rdx, [rsp + 104]
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
    mov  ecx, 16
    rep  stosq
    mov  eax, r8d
    mov  rdx, r9
    add  rsp, 128
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    popfq
    ret
