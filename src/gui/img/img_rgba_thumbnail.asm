;; MODULE gui/img/img_rgba_thumbnail
;; LAYER 6
;; EXPORTS img_rgba_thumbnail
;; IMPORTS
;; CAPS
;; OWNER saga:gui_image_pipeline
;
; img_rgba_thumbnail(RDI=immutable LE request64) -> EAX0/RDXbytes or EAX2/RDX0.
; src:u64@0,len:u64@8,stride:u64@16,w:u32@24,h:u32@28,
; dst:u64@32,cap:u64@40,max_w:u32@48,max_h:u32@52,reserved:u64@56=0.
; Borrowed stable mapped straight RGBA8888. Source and box dimensions1..4096,
; source area<=4194304. Fit inside box without upscaling: limiting side exact,
; other side floor(source_other*limiting/source_side), minimum1 pixel. If source
; fits, keep both dimensions. Required source span excludes final row padding.
; Full declared src/dst and dst/request64 spans nonwrapping and disjoint;
; readonly source/request aliases allowed. All validation precedes output.
;
; Success:16B LE header version:u32@0=1,w:u32@4,h:u32@8,stride:u32@12=w*4,
; followed by tightly packed RGBA. RDX=16+w*h*4; capacity slack untouched.
; Each output pixel averages its complete source rectangle with exact rational
; area weights. Encoded sRGB channel math (no linear-light/color-management claim).
; Alpha=round_half_up(sum(weight*A)/sum(weight)); RGB=round_half_up(
; sum(weight*A*C)/sum(weight*A)). Zero alpha sum writes zero RGBA. This avoids
; hidden RGB bleeding from fully transparent pixels; identity clears those RGBs.
; Rounding a nonzero alpha sum to alpha0 can retain invisible RGB.
;
; Integer coordinates scale source cells by output dimensions, making weights
; integral. Each output's total weight=source_w*source_h<=4194304. A sum<=
; 1069547520; each weighted RGB sum<=272734617600, all fit unsigned64. Downscale
; only: each source cell intersects <=4 output cells, <=4*source_area terms.
; No allocation, retained pointers, globals, IO, FP/SIMD, cache or scheduling.
; Full64 nonvolatiles and flags/DF preserved.224B private frame wiped every
; return +56B saves =280B deepest stack below caller return; no nested calls.
; Creator: rc-ai-claude running on OpenAI Codex.

img_rgba_thumbnail:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,224
    mov rbp,rsp
    cld
    mov r11,rdi
    mov rdi,rbp
    xor eax,eax
    mov ecx,28
    rep stosq
    test r11,r11
    jz .bad
    mov rax,r11
    add rax,64
    jc .bad
    mov r12,[r11]
    mov r13,[r11+32]
    test r12,r12
    jz .bad
    test r13,r13
    jz .bad
    cmp qword [r11+56],0
    jne .bad
    mov eax,[r11+24]
    mov edx,[r11+28]
    mov r8d,[r11+48]
    mov r9d,[r11+52]
    test eax,eax
    jz .bad
    test edx,edx
    jz .bad
    test r8d,r8d
    jz .bad
    test r9d,r9d
    jz .bad
    cmp eax,4096
    ja .bad
    cmp edx,4096
    ja .bad
    cmp r8d,4096
    ja .bad
    cmp r9d,4096
    ja .bad
    mov [rbp+32],eax
    mov [rbp+36],edx
    mov r14d,eax
    mov r15d,edx
    imul rax,rdx
    cmp rax,4194304
    ja .bad
    mov [rbp+168],rax
    mov rbx,[r11+16]
    lea eax,[r14*4]
    cmp rbx,rax
    jb .bad
    mov eax,r15d
    dec eax
    mul rbx
    test rdx,rdx
    jnz .bad
    lea ecx,[r14*4]
    add rax,rcx
    jc .bad
    cmp [r11+8],rax
    jb .bad
    mov rax,r12
    add rax,[r11+8]
    jc .bad
    mov [rbp+8],rax             ; declared source end
    cmp r14d,r8d
    ja .fit
    cmp r15d,r9d
    jbe .fitted
.fit:
    mov eax,r14d
    imul rax,r9
    mov edx,r15d
    imul rdx,r8
    cmp rax,rdx
    jbe .height_limit
    mov eax,r15d
    imul rax,r8
    xor edx,edx
    div r14
    test eax,eax
    jnz .height_nonzero
    inc eax
.height_nonzero:
    mov r15d,eax
    mov r14d,r8d
    jmp .fitted
.height_limit:
    mov eax,r14d
    imul rax,r9
    xor edx,edx
    div r15
    test eax,eax
    jnz .width_nonzero
    inc eax
.width_nonzero:
    mov r14d,eax
    mov r15d,r9d
.fitted:
    mov rax,r14
    imul rax,r15
    lea rax,[rax*4+16]
    mov [rbp+56],rax
    cmp [r11+40],rax
    jb .bad
    mov rdx,r13
    add rdx,[r11+40]
    jc .bad
    cmp r13,[rbp+8]
    jae .source_disjoint
    cmp r12,rdx
    jb .bad
.source_disjoint:
    cmp r11,rdx
    jae .request_disjoint
    lea rax,[r11+64]
    cmp r13,rax
    jb .bad
.request_disjoint:
    lea rax,[r13+16]
    mov [rbp+176],rax
.row:
    mov rax,[rbp+64]            ; output y
    mov ecx,[rbp+36]
    imul rax,rcx
    mov [rbp+200],rax          ; y low, in source*output units
    add rcx,rax
    mov [rbp+208],rcx          ; y high
    xor edx,edx
    div r15
    mov [rbp+80],rax
    mov rax,rcx
    lea rax,[rax+r15-1]
    xor edx,edx
    div r15
    mov [rbp+88],rax
    mov qword [rbp+72],0
.column:
    mov rax,[rbp+72]
    mov ecx,[rbp+32]
    imul rax,rcx
    mov [rbp+184],rax          ; x low
    add rcx,rax
    mov [rbp+192],rcx          ; x high
    xor edx,edx
    div r14
    mov [rbp+96],rax
    mov rax,rcx
    lea rax,[rax+r14-1]
    xor edx,edx
    div r14
    mov [rbp+104],rax
    mov qword [rbp+136],0
    mov qword [rbp+144],0
    mov qword [rbp+152],0
    mov qword [rbp+160],0
    mov rax,[rbp+80]
    mov [rbp+112],rax
.source_row:
    mov rax,[rbp+112]
    imul rax,r15
    lea rcx,[rax+r15]
    cmp rax,[rbp+200]
    cmovb rax,[rbp+200]
    cmp rcx,[rbp+208]
    cmova rcx,[rbp+208]
    sub rcx,rax
    mov [rbp+128],rcx
    mov rax,[rbp+112]
    imul rax,rbx
    add rax,r12
    mov [rbp+216],rax
    mov rax,[rbp+96]
    mov [rbp+120],rax
.source_pixel:
    mov rax,[rbp+120]
    imul rax,r14
    lea rcx,[rax+r14]
    cmp rax,[rbp+184]
    cmovb rax,[rbp+184]
    cmp rcx,[rbp+192]
    cmova rcx,[rbp+192]
    sub rcx,rax
    imul rcx,[rbp+128]
    mov r10,[rbp+120]
    mov rax,[rbp+216]
    lea r10,[rax+r10*4]
    movzx r9d,byte [r10+3]
    imul r9,rcx
    add [rbp+136],r9
    movzx eax,byte [r10]
    imul rax,r9
    add [rbp+144],rax
    movzx eax,byte [r10+1]
    imul rax,r9
    add [rbp+152],rax
    movzx eax,byte [r10+2]
    imul rax,r9
    add [rbp+160],rax
    inc qword [rbp+120]
    mov rax,[rbp+120]
    cmp rax,[rbp+104]
    jb .source_pixel
    inc qword [rbp+112]
    mov rax,[rbp+112]
    cmp rax,[rbp+88]
    jb .source_row
    mov rdi,[rbp+176]
    mov r8,[rbp+136]
    test r8,r8
    jz .transparent
    mov rcx,[rbp+168]
    mov rax,rcx
    shr rax,1
    add rax,r8
    xor edx,edx
    div rcx
    mov [rdi+3],al
    mov r9,r8
    shr r9,1
    mov rax,[rbp+144]
    add rax,r9
    xor edx,edx
    div r8
    mov [rdi],al
    mov rax,[rbp+152]
    add rax,r9
    xor edx,edx
    div r8
    mov [rdi+1],al
    mov rax,[rbp+160]
    add rax,r9
    xor edx,edx
    div r8
    mov [rdi+2],al
    jmp .pixel_done
.transparent:
    mov dword [rdi],0
.pixel_done:
    add qword [rbp+176],4
    inc qword [rbp+72]
    cmp [rbp+72],r14
    jb .column
    inc qword [rbp+64]
    cmp [rbp+64],r15
    jb .row
    mov dword [r13],1
    mov [r13+4],r14d
    mov [r13+8],r15d
    lea eax,[r14*4]
    mov [r13+12],eax
    mov rdx,[rbp+56]
    xor eax,eax
    jmp .done
.bad:
    mov eax,2
    xor edx,edx
.done:
    mov r8d,eax
    mov r9,rdx
    mov rdi,rbp
    xor eax,eax
    mov ecx,28
    rep stosq
    mov eax,r8d
    mov rdx,r9
    add rsp,224
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    popfq
    ret
