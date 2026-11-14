;; MODULE boot/firmware_logo_draw
;; LAYER 0
;; EXPORTS firmware_logo_draw, firmware_logo_drawn, firmware_logo_line_y
;; IMPORTS boot/firmware_logo, boot/gop
;; CAPS
;; OWNER saga:boot
; BSP boot-only consumer of the pre-EBS owned BMP. Never consult firmware
; tables/pointers/services after capture. Keep the original BGRT position,
; without scaling or rotation; unsupported orientation or no isolated loading
; indicator space returns0 BEFORE any store, leaving the caller's fallback.
; EAX=1 complete logo restored,0 unavailable. SysV callee-saved preserved;
; no calls, allocations, waits, mode changes or health/trust authority.
FLD_IMAGE_CAPACITY equ 16777216
FLD_MAX_PIXELS equ 16777216
%ifndef PAOS_PUBLICITY_LAB_PROFILE
%define PAOS_PUBLICITY_LAB_PROFILE 0
%endif
; The normal face owns only the timed dots; the diagnostic lab face retains
; its full text line. Both consumers use firmware_logo_line_y unchanged.
%if PAOS_PUBLICITY_LAB_PROFILE
FLD_LINE_WIDTH equ 840
FLD_LINE_HEIGHT equ 48
%else
FLD_LINE_WIDTH equ 56
FLD_LINE_HEIGHT equ 8
%endif
FLD_LINE_GAP equ 24
firmware_logo_draw:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  dword [rel firmware_logo_drawn], 0
    mov  dword [rel firmware_logo_line_y], 0
    cmp  dword [rel firmware_logo_state], 1
    jne  .bad
    cmp  dword [rel firmware_logo_status], 1 ; displayed, orientation0 only
    jne  .bad
    mov  ebp, [rel firmware_logo_bytes]
    cmp  ebp, 54
    jb   .bad
    cmp  ebp, FLD_IMAGE_CAPACITY
    ja   .bad
    mov  r12d, [rel firmware_logo_width]
    test r12d, r12d
    jz   .bad
    mov  r13d, [rel firmware_logo_height]
    test r13d, r13d
    jz   .bad
    mov  r14d, [rel firmware_logo_bpp]
    cmp  r14d, 24
    je   .bpp_ok
    cmp  r14d, 32
    jne  .bad
.bpp_ok:
    shr  r14d, 3                    ; source bytes/pixel,3or4
    cmp  dword [rel firmware_logo_top_down], 1
    ja   .bad
    mov  rax, r12
    imul rax, r14
    add  rax, 3
    and  rax, -4
    cmp  rax, FLD_IMAGE_CAPACITY
    ja   .bad
    cmp  eax, [rel firmware_logo_stride]
    jne  .bad
    mov  r15, rax
    imul rax, r13                   ; whole padded image rows
    mov  ecx, [rel firmware_logo_pixel_offset]
    cmp  ecx, 54
    jb   .bad
    add  rax, rcx
    jc   .bad
    cmp  rax, rbp
    ja   .bad
    mov  rbx, [rel fb_base]
    test rbx, rbx
    jz   .bad
    test bl, 3
    jnz  .bad
    cmp  dword [rel fb_bpp], 32
    jne  .bad
    cmp  dword [rel fb_pixel_format], 1
    ja   .bad
    mov  ecx, [rel fb_width]
    cmp  ecx, FLD_LINE_WIDTH
    jb   .bad
    cmp  [rel fb_stride], ecx
    jb   .bad
    mov  eax, [rel fb_height]
    cmp  eax, FLD_LINE_HEIGHT
    jb   .bad
    mov  edx, [rel fb_stride]
    imul rax, rdx
    cmp  rax, FLD_MAX_PIXELS
    ja   .bad
    shl  rax, 2
    cmp  rax, [rel fb_size]
    ja   .bad
    mov  rdx, rbx
    add  rdx, [rel fb_size]
    jc   .bad
    mov  rax, 0x0000800000000000
    cmp  rdx, rax                   ; current low identity-mapped GOP surface
    ja   .bad
    lea  rax, [rel firmware_logo_image]
    lea  rsi, [rax + FLD_IMAGE_CAPACITY]
    cmp  rbx, rsi
    jae  .disjoint
    cmp  rax, rdx
    jb   .bad                       ; no framebuffer writes into owned BMP
.disjoint:
    mov  eax, [rel firmware_logo_x]
    add  rax, r12
    mov  edx, [rel fb_width]
    cmp  rax, rdx
    ja   .bad
    mov  eax, [rel firmware_logo_y]
    add  rax, r13
    mov  edx, [rel fb_height]
    cmp  rax, rdx
    ja   .bad
    add  rax, FLD_LINE_GAP + FLD_LINE_HEIGHT
    cmp  rax, rdx
    ja   .above
    sub  eax, FLD_LINE_HEIGHT
    jmp  .line
.above:
    mov  eax, [rel firmware_logo_y]
    cmp  eax, FLD_LINE_GAP + FLD_LINE_HEIGHT
    jb   .bad
    sub  eax, FLD_LINE_GAP + FLD_LINE_HEIGHT
.line:
    mov  [rel firmware_logo_line_y], eax
    ; All record, source and destination extents admitted before first write.
    ; Remove stale Manager/firmware menu pixels without blanking the logo
    ; rectangle. Padding is inside the admitted surface and is cleared too.
    mov  rdi, rbx
    mov  r8d, [rel fb_stride]
    mov  r9d, [rel firmware_logo_x]
    mov  r10d, [rel firmware_logo_y]
    lea  r11, [r10 + r13]
    xor  edx, edx
    xor  eax, eax
    cld
.clear_row:
    cmp  edx, r10d
    jb   .whole_row
    cmp  edx, r11d
    jae  .whole_row
    mov  ecx, r9d
    rep  stosd
    lea  rdi, [rdi + r12*4]
    mov  ecx, r8d
    sub  ecx, r9d
    sub  ecx, r12d
    rep  stosd
    jmp  .cleared_row
.whole_row:
    mov  ecx, r8d
    rep  stosd
.cleared_row:
    inc  edx
    cmp  edx, [rel fb_height]
    jb   .clear_row
    mov  eax, [rel firmware_logo_y]
    mov  edx, [rel fb_stride]
    imul rax, rdx
    mov  edx, [rel firmware_logo_x]
    add  rax, rdx
    lea  rdi, [rbx + rax*4]
    lea  rsi, [rel firmware_logo_image]
    mov  eax, [rel firmware_logo_pixel_offset]
    add  rsi, rax
    cmp  dword [rel firmware_logo_top_down], 1
    je   .rows
    lea  rax, [r13 - 1]
    imul rax, r15
    add  rsi, rax
    neg  r15                       ; bottom-up source row advance
.rows:
    mov  rbp, rsi
    mov  rbx, rdi
    mov  ecx, r12d
.pixel:
    movzx eax, byte [rsi]
    movzx edx, byte [rsi + 1]
    shl  edx, 8
    or   eax, edx
    movzx edx, byte [rsi + 2]
    shl  edx, 16
    or   eax, edx                  ; BMP B,G,R ; reserved byte deliberately0
    cmp  dword [rel fb_pixel_format], 1
    je   .store
    bswap eax
    shr  eax, 8                    ; GOP RGB byte order R,G,B,0
.store:
    mov  [rdi], eax
    add  rsi, r14
    add  rdi, 4
    dec  ecx
    jnz  .pixel
    mov  rsi, rbp
    add  rsi, r15
    mov  eax, [rel fb_stride]
    lea  rdi, [rbx + rax*4]
    dec  r13d
    jnz  .rows
    mov  dword [rel firmware_logo_drawn], 1
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret
%include "core/abi/wdata.inc"
%macro WDATA_boot_firmware_logo_draw 0
align 4
firmware_logo_drawn: dd 0
firmware_logo_line_y: dd 0
%endmacro
WDATA_DEFER WDATA_boot_firmware_logo_draw
