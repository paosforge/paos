;; MODULE gui/img/img_capture_rgba
;; LAYER 6
;; EXPORTS img_capture_rgba
;; IMPORTS
;; CAPS
;; OWNER saga:gui_image_pipeline
;
; Synchronous screenshot rectangle from a caller-admitted memory surface.
; img_capture_rgba(RDI=request80) -> EAX=IMG_OK(0)/IMG_E_BOUNDS(2), RDX=bytes/0.
; Immutable little-endian request: src:u64@0, length:u64@8, dst:u64@16,
; capacity:u64@24, frame_width:u32@32, frame_height:u32@36, stride:u64@40,
; x:u32@48, y:u32@52, width:u32@56, height:u32@60, format:u32@64,
; reserved:u32@68=0, reserved:u64@72=0. Coordinates are in source pixels.
; Formats: 1=straight RGBA8888, 2=straight BGRA8888, 3=BGRX8888 (X ignored,
; output alpha=255). All are top-down; no premultiplied-alpha interpretation.
; Output is packed top-down straight RGBA, exactly width*height*4 bytes.
; Full frame/window/region use the same explicit nonempty rectangle contract.
; Frame axes 1..16384, area <=67108864 pixels, length 1..1073741824 bytes.
; Stride >=frame_width*4; last-row extent fits length without unsigned wrap.
; Selected rectangle lies entirely in frame, area <=16777216 pixels (includes
; 3840x2160). Capacity >=output bytes and <=67108864 bytes. All declared spans
; are nonwrapping; entire source and destination capacity spans are disjoint;
; entire destination capacity also excludes request80. Readonly source/request
; alias is allowed. All validation precedes source reads and destination writes.
; Refusal changes no caller bytes. Success preserves source, descriptor and all
; output slack. Caller maps and stabilizes the descriptor and admitted surfaces
; throughout the call; device ownership and capture authorization stay upstream.
; No I/O, device read, clipboard, file save, UI/hotkey, allocation, global state,
; retained pointer, callee or FP/SIMD. RBX/RBP/R12-R15, flags/DF and FP preserved.
; This adds raw capture only. Existing img_png_encode retains its independent
; 4194304-pixel limit: full 4K PNG export still needs a separate encoder change.

img_capture_rgba:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8
    test rdi, rdi
    jz   .bounds
    mov  rax, rdi
    add  rax, 80
    jc   .bounds
    mov  r11, rdi                     ; immutable request until preflight ends
    mov  rbx, [rdi]                   ; source base, later selected row
    mov  r8, [rdi + 8]                ; full declared source length
    mov  r15, [rdi + 16]              ; destination
    mov  r9, [rdi + 24]               ; entire destination capacity
    mov  r10d, [rdi + 32]             ; frame width
    mov  ebp, [rdi + 36]              ; frame height
    mov  r14, [rdi + 40]              ; source stride
    mov  r12d, [rdi + 56]             ; selected width, later row bytes
    mov  r13d, [rdi + 60]             ; selected height
    cmp  dword [rdi + 68], 0
    jne  .bounds
    cmp  qword [rdi + 72], 0
    jne  .bounds
    mov  eax, [rdi + 64]
    dec  eax
    cmp  eax, 2
    ja   .bounds
    test rbx, rbx
    jz   .bounds
    test r15, r15
    jz   .bounds
    test r8, r8
    jz   .bounds
    cmp  r8, 1073741824
    ja   .bounds
    cmp  r9, 67108864
    ja   .bounds
    mov  rax, rbx
    add  rax, r8
    jc   .bounds
    mov  rax, r15
    add  rax, r9
    jc   .bounds
    test r10d, r10d
    jz   .bounds
    test ebp, ebp
    jz   .bounds
    cmp  r10d, 16384
    ja   .bounds
    cmp  ebp, 16384
    ja   .bounds
    mov  rax, r10
    imul rax, rbp                     ; axes already bounded; cannot overflow
    cmp  rax, 67108864
    ja   .bounds
    test r12d, r12d
    jz   .bounds
    test r13d, r13d
    jz   .bounds
    mov  eax, [r11 + 48]
    cmp  eax, r10d
    jae  .bounds
    mov  edx, r10d
    sub  edx, eax
    cmp  r12d, edx                    ; subtraction excludes endpoint wrap
    ja   .bounds
    mov  eax, [r11 + 52]
    cmp  eax, ebp
    jae  .bounds
    mov  edx, ebp
    sub  edx, eax
    cmp  r13d, edx
    ja   .bounds
    mov  rax, r12
    imul rax, r13
    cmp  rax, 16777216
    ja   .bounds
    shl  rax, 2
    cmp  r9, rax
    jb   .bounds
    mov  [rsp], rax                   ; successful packed output bytes
    shl  r10, 2                       ; full frame row bytes
    cmp  r14, r10
    jb   .bounds
    mov  eax, ebp
    dec  rax
    mul  r14                         ; unsigned extent, high half checked
    test rdx, rdx
    jnz  .bounds
    add  rax, r10
    jc   .bounds
    cmp  r8, rax
    jb   .bounds
    lea  rax, [rbx + r8]
    cmp  r15, rax
    jae  .source_disjoint
    lea  rax, [r15 + r9]
    cmp  rbx, rax
    jb   .bounds
.source_disjoint:
    lea  rax, [r11 + 80]
    cmp  r15, rax
    jae  .request_disjoint
    lea  rax, [r15 + r9]
    cmp  r11, rax
    jb   .bounds
.request_disjoint:
    ; Rectangle is inside the fully checked frame extent. Its offset and all
    ; subsequent row/pixel additions fit that extent and the source address span.
    mov  eax, [r11 + 52]
    imul rax, r14
    add  rbx, rax
    mov  eax, [r11 + 48]
    lea  rbx, [rbx + rax * 4]
    shl  r12, 2
    mov  ebp, [r11 + 64]              ; last descriptor read before publication
    cld
.row:
    mov  rsi, rbx
    mov  rdi, r15
    mov  rcx, r12
    shr  rcx, 2
    cmp  ebp, 1
    jne  .blue_first
    rep  movsd
    jmp  .row_done
.blue_first:
    mov  eax, [rsi]
    mov  r8d, eax
    and  eax, 0xff00ff00              ; keep G and original alpha
    mov  r9d, r8d
    shl  r9d, 16
    and  r9d, 0x00ff0000              ; source B -> output B byte
    shr  r8d, 16
    and  r8d, 255                     ; source R -> output R byte
    or   eax, r8d
    or   eax, r9d
    cmp  ebp, 3
    jne  .alpha_ready
    or   eax, 0xff000000              ; opaque BGRX, ignore X
.alpha_ready:
    mov  [rdi], eax
    add  rsi, 4
    add  rdi, 4
    dec  ecx
    jnz  .blue_first
.row_done:
    mov  r15, rdi
    dec  r13d
    jz   .ok
    add  rbx, r14
    jmp  .row
.ok:
    xor  eax, eax
    mov  rdx, [rsp]
    jmp  .out
.bounds:
    mov  eax, 2
    xor  edx, edx
.out:
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    popfq
    ret
