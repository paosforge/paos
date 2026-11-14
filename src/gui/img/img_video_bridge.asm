;; MODULE gui/img/img_video_bridge
;; LAYER 6
;; EXPORTS img_video_rgba_to_bgrx
;; IMPORTS gui/img/img_core, gui/shared_surface_portal
;; CAPS
;; OWNER saga:gui_image_pipeline

; RCQ-37 V02 private, UNWIRED format bridge. No allocation, surface ownership,
; handle validation, publication or clock. Canonical image decode stays RGBA.
; Requires IMG_MAX_DIM/IMG_MAX_PIXELS and the real SSP_FMT_BGRX at include time.
; The caller owns a stable, readable context and stable mapped buffers whose
; capacities are truthful; guest pointers/descriptors may not call this helper.
; All admission checks precede writes. Disjoint intervals only; padding is not
; copied. At most IMG_MAX_PIXELS pixels, one foreground frame per invocation.
; This bound is not a scheduler budget: wiring needs cooperative presentation.

struc img_video_frame
    .src:         resq 1          ; top-down RGBA, alpha ignored
    .src_bytes:   resq 1          ; readable bytes starting at src
    .dst:         resq 1          ; host-owned BGRX storage, opaque X=0xFF
    .dst_bytes:   resq 1          ; writable bytes starting at dst
    .width:       resd 1
    .height:      resd 1
    .src_stride:  resd 1
    .dst_stride:  resd 1
    .format:      resd 1          ; canonical SSP_FMT_BGRX, no new format ABI
    .reserved:    resd 1          ; zero
endstruc

; img_video_rgba_to_bgrx(RDI=trusted img_video_frame*) -> RAX=0 or -1.
; Refusal leaves both buffers and context unchanged; success changes only the
; destination's width*4 bytes on each row. No image/surface state is mutated.
; Preserves RBX/RBP/R12..R15, RDI and RSP. Clobbers RAX/RCX/RDX/RSI/R8..R11
; and arithmetic flags; no SIMD register is touched. R12/R13 are saved on all
; success/refusal paths; RBX/RBP/R14/R15 are unused.
img_video_rgba_to_bgrx:
    push r12
    push r13
    test rdi, rdi
    jz .bad
    cmp dword [rdi + img_video_frame.format], SSP_FMT_BGRX
    jne .bad
    cmp dword [rdi + img_video_frame.reserved], 0
    jne .bad
    mov r8d, [rdi + img_video_frame.width]
    mov r9d, [rdi + img_video_frame.height]
    test r8d, r8d
    jz .bad
    test r9d, r9d
    jz .bad
    cmp r8d, IMG_MAX_DIM
    ja .bad
    cmp r9d, IMG_MAX_DIM
    ja .bad
    mov eax, r8d
    imul rax, r9
    cmp rax, IMG_MAX_PIXELS
    ja .bad
    mov r12d, r8d
    shl r12d, 2                    ; row bytes, dimensions already bounded
    mov r10d, [rdi + img_video_frame.src_stride]
    mov r11d, [rdi + img_video_frame.dst_stride]
    cmp r10, r12
    jb .bad
    cmp r11, r12
    jb .bad
    mov rsi, [rdi + img_video_frame.src]
    mov rdx, [rdi + img_video_frame.dst]
    test rsi, rsi
    jz .bad
    test rdx, rdx
    jz .bad
    ; Last touched extent = (height-1)*stride + row bytes. A stride is u32
    ; and height <=4096, so the 64-bit product/add cannot overflow.
    mov eax, r9d
    dec eax
    imul rax, r10
    add rax, r12
    cmp rax, [rdi + img_video_frame.src_bytes]
    ja .bad
    mov ecx, r9d
    dec ecx
    imul rcx, r11
    add rcx, r12
    cmp rcx, [rdi + img_video_frame.dst_bytes]
    ja .bad
    add rax, rsi                   ; source interval end, exclusive
    jc .bad
    add rcx, rdx                   ; destination interval end, exclusive
    jc .bad
    cmp rdx, rax
    jae .disjoint
    cmp rsi, rcx
    jb .bad
.disjoint:
    ; Destination may not overwrite the context, including row padding.
    cmp rdi, rcx
    jae .copy
    mov rcx, rdi
    add rcx, img_video_frame_size
    jc .bad
    cmp rdx, rcx
    jb .bad
.copy:
    ; Advance by padding after the pixel loop has consumed width*4 bytes.
    sub r10, r12
    sub r11, r12
.row:
    mov r13d, r8d
.pixel:
    mov al, [rsi + 2]
    mov [rdx], al
    mov al, [rsi + 1]
    mov [rdx + 1], al
    mov al, [rsi]
    mov [rdx + 2], al
    mov byte [rdx + 3], 0xFF
    add rsi, 4
    add rdx, 4
    dec r13d
    jnz .pixel
    add rsi, r10
    add rdx, r11
    dec r9d
    jnz .row
    xor eax, eax
    jmp .out
.bad:
    mov rax, -1
.out:
    pop r13
    pop r12
    ret
