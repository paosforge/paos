;; MODULE gui/compose_glyph
;; LAYER 6
;; EXPORTS fb_compose_glyph
;; IMPORTS gui/compose_idle, gui/window, gui/font_aa, boot/gop
;; CAPS
;; OWNER saga:gui
; A clipped glyph consumer for idle composition. RSI is immutable glyph data;
; r8/r9 original cell origin, r10/r11 its dimensions; EBX/ECX fg/bg.
; DL=8 or16 selects MSB-first packed bits; DL=0 selects byte coverage.
; The original cell has already passed its whole-cell screen-edge admission.
; All registers are preserved and no pointer survives this call.
fb_compose_glyph:
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    sub rsp,48
    mov [rsp],r8d                    ; original x/y/width
    mov [rsp+4],r9d
    mov [rsp+8],r10d
    mov [rsp+12],ebx                  ; fg/bg/format
    mov [rsp+16],ecx
    mov [rsp+20],edx
    mov [rsp+24],rsi                  ; used only inside this returned call
    call fb_compose_intersect
    jc .out
    call fb_compose_take
    jc .out
    mov r12d,r8d
    mov r13d,r9d
    lea r14d,[r8d+r10d]
    lea r15d,[r9d+r11d]
    mov [rsp+32],r8d
.row:
    mov r12d,[rsp+32]
.pixel:
    mov eax,r13d
    sub eax,[rsp+4]
    mov ecx,r12d
    sub ecx,[rsp]
    mov rsi,[rsp+24]
    cmp byte [rsp+20],0
    je .coverage
    cmp byte [rsp+20],16
    je .wide
    movzx eax,byte [rsi+rax]
    shl al,cl
    test al,0x80
    jmp .bit_color
.wide:
    movzx eax,word [rsi+rax*2]
    xchg al,ah
    shl ax,cl
    test ax,0x8000
.bit_color:
    mov edx,[rsp+16]
    cmovnz edx,[rsp+12]
    jmp .store
.coverage:
    imul eax,[rsp+8]
    add eax,ecx
    movzx eax,byte [rsi+rax]
    mov ebx,[rsp+12]
    mov ecx,[rsp+16]
    call font_aa_blend
.store:
    mov eax,r13d
    mov ecx,[rel fb_stride]
    imul rax,rcx
    add rax,r12
    mov rdi,[rel fb_base]
    mov [rdi+rax*4],edx
    inc r12d
    cmp r12d,r14d
    jb .pixel
    inc r13d
    cmp r13d,r15d
    jb .row
    mov r10d,r14d
    sub r10d,r8d
    mov r11d,r15d
    sub r11d,r9d
    call fb_damage_rect
.out:
    add rsp,48
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    ret
