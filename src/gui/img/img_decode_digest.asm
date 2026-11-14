;; MODULE gui/img/img_decode_digest
;; LAYER 6
;; EXPORTS img_decode_digest
;; IMPORTS gui/img/img_core, gui/img/img_rgba_digest
;; CAPS
;; OWNER saga:gui_image_pipeline
;; CONTEXT: bsp_only  (serialized image pipeline, heap and shared SHA256 workspace)
;
; Actual creator: rc-ai-claude running on OpenAI Codex.
; img_decode_digest(RDI=immutable LE request32) -> EAX=status,RDX=64/0.
; src:u64@0,len:u64@8,dst:u64@16,cap:u64@24. Caller supplies stable
; mapped spans; source2..32MiB,cap64..32MiB. Full declared src/dst spans
; nonwrapping/disjoint; dst/request32 disjoint; readonly src/request alias
; allowed. Refusals write no destination bytes; success writes exactly64B.
;
; Actual BMP/PNG/baseline+progressive JPEG decode bakes camera orientation
; before actual img_rgba_digest hashes the packed straight RGBA. Existing
; decoder bounds (4096 axes,4M pixels) and color policy apply. Output is the
; unchanged version1/algorithm1 RGBA digest record: dimensions, pixel count
; in bytes and domain-separated SHA256. Metadata/container/stride are not
; identity; dimensions/alpha/hidden RGB are. JPEG lossy differences remain.
; Exact decoded-pixel identity is a candidate match only, never authority to
; delete/skip an import; no index, cache, file IO or perceptual matching here.
; Accepted native still-GIF uses the same core path and bounded grammar;
; unsupported GIF features still refuse through the native parser.
;
; Status0 success;1 magic;2 request/digest bounds or SHA error;3..7 decoder
; errors;8 busy. Actual img_output_release pairs with every
; successful decode, including digest failure. No forced owner reset and no
; error invented after publication. A prior live output returns busy8 intact.
; Caller serializes singleton image pipeline, prevents intervening heap
; allocation and serializes ALL shared SHA users on BSP (no AP/IRQ/reentry).
; Unsupported heap contention retains the core release diagnostic/live owner.
;
; No wrapper globals, IO or allocation beyond actual decoder;64B initialized
; and wiped frame +56B saves, called modules' stacks additional. Full64
; nonvolatiles, all caller flags including DF and FP controls preserved.

img_decode_digest:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 64
    cld
    mov  r11, rdi
    mov  rdi, rsp
    xor  eax, eax
    mov  ecx, 8
    rep  stosq
    test r11, r11
    jz   .bounds
    mov  r10, r11
    add  r10, 32
    jc   .bounds
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
    cmp  r14, 64
    jb   .bounds
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
    mov  [rsp + 16], r13
    mov  [rsp + 24], r14
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
    mov  rdi, rsp                       ; complete initialized RGBA request48
    call img_rgba_digest
    mov  [rsp + 48], eax
    mov  [rsp + 56], rdx
    call img_output_release
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
    mov  ecx, 8
    rep  stosq
    mov  eax, r8d
    mov  rdx, r9
    add  rsp, 64
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    popfq
    ret
