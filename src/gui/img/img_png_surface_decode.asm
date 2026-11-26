;; MODULE gui/img/img_png_surface_decode
;; LAYER 6
;; EXPORTS img_png_decode_surface_into
;; IMPORTS gui/img/img_core, gui/img/img_png
;; CAPS
;; OWNER saga:gui_image_pipeline
;; CONTEXT: bsp_only (serialized image pipeline, heap and shared SHA256 workspace)
;
; Actual creator: rc-ai-claude on OpenAI Codex.
; RDI=immutable LE request48: src:u64@0,len:u64@8,dst:u64@16,cap:u64@24,
; expected oriented width:u32@32,height:u32@36,dst stride:u64@40.
; EAX=status,RDX=last-row pixel span on success,zero on failure.
; Source33..64MiB+32KiB;axes1..16384,area<=16M;capacity4..128MiB.
; Mapped stable caller spans, unsigned nonwrap. Full source/destination cap
; disjoint; full destination cap excludes request48. Read-only request/source
; alias allowed. Row stride>=width*4; returned span excludes final padding.
;
; Decode full supported PNG grammar, samples, Adam7 and EXIF orientation through
; the existing SHA-owned snapshot decoder under a separate bounded policy.
; Expected dimensions must match final oriented output. Decode/refusal/OOM never
; writes destination. Success copies straight RGBA including hidden RGB, leaves
; padding/slack intact and retires the temporary allocation. No retained source,
; caller IO, globals or wrapper allocation. Core release contention is retained
; honestly, never force-reset. Existing core/probe/decoder caps are unchanged.
; Status0 success;1..7 existing image errors;8 busy preserves an earlier output.
; Caller serializes BSP pipeline/heap/SHA users through return (no AP/IRQ/reentry).
; Private wiped32B frame+56B saves;callees additional. Full64 nonvolatiles,
; flags/DF and FP controls preserved. No FP/SIMD.

%include "gui/img/img_cold_hooks.inc"

img_png_decode_surface_into:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 32
    cld
    mov  r11, rdi
    xor  eax, eax
    mov  rdi, rsp
    mov  ecx, 4
    rep  stosq
    test r11, r11
    jz   .bounds
    mov  r10, r11
    add  r10, 48
    jc   .bounds
    mov  rbx, [r11]
    mov  r12, [r11 + 8]
    mov  r13, [r11 + 16]
    mov  r14, [r11 + 24]
    mov  r15, [r11 + 40]
    test rbx, rbx
    jz   .bounds
    test r13, r13
    jz   .bounds
    cmp  r12, 33
    jb   .bounds
    cmp  r12, PNG_SURFACE_SOURCE_MAX
    ja   .bounds
    cmp  r14, 4
    jb   .bounds
    cmp  r14, 134217728
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
    mov  eax, [r11 + 32]
    mov  ecx, [r11 + 36]
    test eax, eax
    jz   .bounds
    test ecx, ecx
    jz   .bounds
    cmp  eax, 16384
    ja   .bounds
    cmp  ecx, 16384
    ja   .bounds
    mov  [rsp], eax
    mov  [rsp + 4], ecx
    mov  edx, eax
    imul edx, ecx
    cmp  edx, 16777216
    ja   .bounds
    shl  rax, 2
    mov  rbp, rax
    cmp  r15, rax
    jb   .bounds
    mov  eax, ecx
    dec  rax
    mul  r15
    test rdx, rdx
    jnz  .bounds
    add  rax, rbp
    jc   .bounds
    cmp  rax, r14
    ja   .bounds
    mov  [rsp + 8], rax
    IMG_COLD_BUSY_JUMP .busy
    cmp  qword [rel img_active_out], 0
    jne  .busy
    mov  rdi, rbx
    mov  rsi, r12
    call img_png_decode_surface
    test eax, eax
    jnz  .failed
    cmp  ecx, [rsp]
    jne  .geometry
    cmp  edx, [rsp + 4]
    jne  .geometry
    mov  rsi, rbx
    mov  rdi, r13
    mov  r12d, edx
.row:
    mov  rcx, rbp
    rep  movsb
    add  rdi, r15
    sub  rdi, rbp
    dec  r12d
    jnz  .row
    mov  dword [rsp + 16], 0
    jmp  .release
.geometry:
    mov  dword [rsp + 16], IMG_E_BOUNDS
.release:
    call img_output_release
    mov  eax, [rsp + 16]
    mov  rdx, [rsp + 8]
    test eax, eax
    jz   .return
    jmp  .failed
.bounds:
    mov  eax, IMG_E_BOUNDS
    jmp  .failed
.busy:
    mov  eax, 8
.failed:
    xor  edx, edx
.return:
    mov  r8d, eax
    mov  r9, rdx
    xor  eax, eax
    mov  rdi, rsp
    mov  ecx, 4
    rep  stosq
    mov  eax, r8d
    mov  rdx, r9
    add  rsp, 32
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    popfq
    ret
