;; MODULE gui/img/img_cover
;; LAYER 6
;; PURPOSE Center-cover lock images with a soft black scrim and bounded paint storage.
;; EXPORTS img_cover_blit
;; IMPORTS gui/window, gui/compose_idle
;; OWNER saga:gui_image_pipeline

; RDI -> immutable 48-byte request: src:u64, len:u64, sw:u32, sh:u32,
; x:i32, y:i32, dw:u32, dh:u32, reserved:u64=0. Caller owns decoded RGBA.
; EAX=0 painted, 1 refused before any paint. Native limits: 4096/dimension,
; 4M source pixels, 65535/output dimension. No decode, allocation or globals.
; Center-cover uses ceil virtual dimensions, then floor nearest sampling.
; Alpha composites over black; RGB then retains102/255 (60% black scrim), matching v0.52 drawLock.
; Output is opaque, so a transparent image never exposes the previous screen.
; Tiles of 256 columns bound map+row to 2048 B regardless of display size.
; Repeated source rows are emitted in one stride-zero blit. fb_blit_rgba clips
; signed screen coordinates. BSP GUI context, like the other image painters.
img_cover_blit:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 2176
    mov qword [rsp+64],0                ; scoped prepaid ownership
    cld
    test rdi, rdi
    jz   .refuse
    mov  rax, rdi
    add  rax, 48
    jc   .refuse
    cmp  qword [rdi + 40], 0
    jne  .refuse
    mov  rbx, [rdi]
    test rbx, rbx
    jz   .refuse
    mov  eax, [rdi + 16]
    mov  ecx, [rdi + 20]
    test eax, eax
    jz   .refuse
    test ecx, ecx
    jz   .refuse
    cmp  eax, 4096
    ja   .refuse
    cmp  ecx, 4096
    ja   .refuse
    mov  [rsp], eax                     ; sw
    mov  [rsp + 4], ecx                 ; sh
    imul rax, rcx
    cmp  rax, 4194304
    ja   .refuse
    shl  rax, 2
    cmp  rax, [rdi + 8]
    ja   .refuse
    mov  rdx, rbx
    add  rdx, [rdi + 8]
    jc   .refuse
    mov  eax, [rdi + 32]
    mov  ecx, [rdi + 36]
    test eax, eax
    jz   .refuse
    test ecx, ecx
    jz   .refuse
    cmp  eax, 65535
    ja   .refuse
    cmp  ecx, 65535
    ja   .refuse
    mov  [rsp + 8], eax                 ; dw
    mov  [rsp + 12], ecx                ; dh
    mov  edx, [rdi + 24]
    mov  [rsp + 16], edx                ; x
    mov  edx, [rdi + 28]
    mov  [rsp + 20], edx                ; y
    ; Avoid signed coordinate wrap when adding tile offsets.
    movsxd rdx, dword [rsp + 16]
    add  rdx, rax
    cmp  rdx, 0x7fffffff
    jg   .refuse
    movsxd rdx, dword [rsp + 20]
    add  rdx, rcx
    cmp  rdx, 0x7fffffff
    jg   .refuse
    mov  r8d, [rsp]                     ; sw*dh versus sh*dw
    imul r8, rcx
    mov  r9d, [rsp + 4]
    imul r9, rax
    mov  [rsp + 24], eax                ; virtual width = dw
    mov  [rsp + 28], ecx                ; virtual height = dh
    cmp  r8, r9
    ja   .wide_source
    mov  rax, r9                        ; ceil(sh*dw/sw)
    mov  ecx, [rsp]
    lea  rax, [rax + rcx - 1]
    xor  edx, edx
    div  rcx
    mov  [rsp + 28], eax
    jmp  .crop
.wide_source:
    mov  rax, r8                        ; ceil(sw*dh/sh)
    mov  ecx, [rsp + 4]
    lea  rax, [rax + rcx - 1]
    xor  edx, edx
    div  rcx
    mov  [rsp + 24], eax
.crop:
    mov  eax, [rsp + 24]
    sub  eax, [rsp + 8]
    shr  eax, 1
    mov  [rsp + 32], eax                ; crop x
    mov  eax, [rsp + 28]
    sub  eax, [rsp + 12]
    shr  eax, 1
    mov  [rsp + 36], eax                ; crop y
    ; Bound mapping, source sampling and row-run traversal, not merely the
    ; final blit. Sampling still uses the original virtual cover geometry.
    mov r8d,[rsp+16]
    mov r9d,[rsp+20]
    mov r10d,[rsp+8]
    mov r11d,[rsp+12]
    call fb_compose_intersect
    jc .empty
    call fb_compose_take
    jc .empty
    sub r8d,[rsp+16]
    sub r9d,[rsp+20]
    mov [rsp+40],r8d                   ; clipped first column
    mov [rsp+44],r9d                   ; clipped first row
    add r10d,r8d
    add r11d,r9d
    mov [rsp+48],r10d                  ; clipped exclusive column
    mov [rsp+52],r11d                  ; clipped exclusive row
    cmp byte [rel fb_compose_clip_active],0
    je .not_prepaid
    inc byte [rel fb_compose_prepaid]
    mov byte [rsp+64],1
.not_prepaid:
    mov r12d,[rsp+40]                  ; tile x, original output phase
.tile:
    mov  r13d, [rsp + 48]
    sub  r13d, r12d
    cmp  r13d, 256
    jbe  .tile_size
    mov  r13d, 256
.tile_size:
    xor  ebp, ebp
.map:
    mov  eax, [rsp + 32]
    add  eax, r12d
    add  eax, ebp
    mov  ecx, [rsp]
    imul rax, rcx
    xor  edx, edx
    mov  ecx, [rsp + 24]
    div  rcx
    mov  [rsp + rbp*4 + 128], eax
    inc  ebp
    cmp  ebp, r13d
    jb   .map
    mov  r14d, [rsp+44]                ; output row, original sampling phase
.row:
    mov  eax, [rsp + 36]
    add  eax, r14d
    mov  ecx, [rsp + 4]
    imul rax, rcx
    xor  edx, edx
    mov  ecx, [rsp + 28]
    div  rcx                            ; source row
    mov  r15d, eax
    mov  ecx, [rsp]
    imul rax, rcx
    lea  rsi, [rbx + rax*4]
    xor  ebp, ebp
.pixel:
    mov  eax, [rsp + rbp*4 + 128]
    mov  r8d, [rsi + rax*4]
    mov  r9d, r8d
    shr  r9d, 24                       ; alpha
    xor  r10d, r10d
%assign IC_SHIFT 0
%rep 3
    mov  eax, r8d
    and  eax, 255
    imul eax, r9d
    add  eax, 128                       ; round(c*a/255) exactly
    mov  edx, eax
    shr  edx, 8
    add  eax, edx
    shr  eax, 8
    imul eax, eax, 102                  ; #00000099: retain102/255 color
    add  eax, 128                       ; round(c*102/255) exactly
    mov  edx, eax
    shr  edx, 8
    add  eax, edx
    shr  eax, 8
    shl  eax, IC_SHIFT
    or   r10d, eax
    shr  r8d, 8
%assign IC_SHIFT IC_SHIFT+8
%endrep
%undef IC_SHIFT
    or   r10d, 0xff000000
    mov  [rsp + rbp*4 + 1152], r10d
    inc  ebp
    cmp  ebp, r13d
    jb   .pixel
    ; Last output row for this source row: ceil((sy+1)*vh/sh)-crop_y.
    lea  eax, [r15 + 1]
    mov  ecx, [rsp + 28]
    imul rax, rcx
    mov  ecx, [rsp + 4]
    lea  rax, [rax + rcx - 1]
    xor  edx, edx
    div  rcx
    sub  eax, [rsp + 36]
    cmp  eax, [rsp + 52]
    cmova eax, [rsp + 52]
    mov  r15d, eax                      ; next row
    sub  eax, r14d
    mov  r11d, eax
    lea  rdi, [rsp + 1152]
    xor  esi, esi                       ; stride 0: repeat expanded row
    mov  r8d, [rsp + 16]
    add  r8d, r12d
    mov  r9d, [rsp + 20]
    add  r9d, r14d
    mov  r10d, r13d
    call fb_blit_rgba
    mov  r14d, r15d
    cmp  r14d, [rsp + 52]
    jb   .row
    add  r12d, r13d
    cmp  r12d, [rsp + 48]
    jb   .tile
.empty:
    xor  eax, eax
    jmp  .out
.refuse:
    mov  eax, 1
.out:
    cmp byte [rsp+64],0
    je .unpaid
    dec byte [rel fb_compose_prepaid]
.unpaid:
    add  rsp, 2176
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    popfq
    ret
