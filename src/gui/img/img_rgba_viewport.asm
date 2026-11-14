;; MODULE gui/img/img_rgba_viewport
;; LAYER 6
;; EXPORTS img_rgba_viewport
;; IMPORTS
;; CAPS
;; OWNER saga:gui_image_pipeline
;
; Image Viewer zoom/pan point-sampling memory backend; no UI/gesture/fit policy.
; img_rgba_viewport(RDI=immutable request96) -> EAX0/RDXspan, or EAX2/RDX0.
; LE request: src:u64@0,len:u64@8,dst:u64@16,cap:u64@24,
; src_w:u32@32,src_h:u32@36,src_stride:u64@40,dst_stride:u64@48,
; dst_w:u32@56,dst_h:u32@60,origin_x:i32@64,origin_y:i32@68,
; step_x:u32@72,step_y:u32@76,background:RGBA8888-u32@80,
; reserved:u32@84=0,reserved:u64@88=0. Mapped borrowed straight RGBA8888.
; Each source/destination independently dimensions1..4096,area<=4194304;
; strides>=width*4,checked(h-1)*stride+width*4 spans. Complete declared
; source/destination spans nonwrapping and disjoint; full destination capacity
; disjoint from request96. Read-only source/request alias allowed.
;
; For destination(x,y), sample source at floor((origin_x+x*step_x)/65536),
; floor((origin_y+y*step_y)/65536). Signed origins are16.16; unsigned positive
; steps1..268435456 (4096*65536). Grid/centre choices belong to caller.
; Out-of-image samples get exact supplied background, including hidden RGB.
; In-image samples copy all four original bytes without blending/conversion.
; Min coordinate -2^31; max(2^31-1)+4095*2^28 <2^41, fits signed64.
; SAR16 implements floor also below zero. No fixedpoint addition wraps.
;
; All validation before writes; refusal changes no caller bytes. Writes pixel
; rows only, preserving padding/slack and original/request. O(dstarea), no
; allocation/global state/scratch/IO/FP/SIMD; full64 RBX/RBP/R12-R15 and
; incoming flags/DF preserved. 120-byte stack use including56-byte save frame.

img_rgba_viewport:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,64
    test rdi,rdi
    jz .bounds
    mov rax,rdi
    add rax,96
    jc .bounds
    mov r11,rdi
    mov r12,[r11]
    mov r10,[r11+8]
    mov r13,[r11+16]
    mov rdi,[r11+24]
    mov r14d,[r11+32]
    mov r15d,[r11+36]
    mov rbx,[r11+40]
    mov rbp,[r11+48]
    mov r8d,[r11+56]
    mov r9d,[r11+60]
    test r12,r12
    jz .bounds
    test r13,r13
    jz .bounds
    test r14d,r14d
    jz .bounds
    test r15d,r15d
    jz .bounds
    cmp r14d,4096
    ja .bounds
    cmp r15d,4096
    ja .bounds
    mov eax,r14d
    imul eax,r15d
    cmp eax,4194304
    ja .bounds
    test r8d,r8d
    jz .bounds
    test r9d,r9d
    jz .bounds
    cmp r8d,4096
    ja .bounds
    cmp r9d,4096
    ja .bounds
    mov eax,r8d
    imul eax,r9d
    cmp eax,4194304
    ja .bounds
    mov rax,r12
    add rax,r10
    jc .bounds
    mov rdx,r13
    add rdx,rdi
    jc .bounds
    cmp r13,rax
    jae .buffers_disjoint
    cmp r12,rdx
    jb .bounds
.buffers_disjoint:
    cmp r11,rdx
    jae .request_disjoint
    lea rax,[r11+96]
    cmp r13,rax
    jb .bounds
.request_disjoint:
    lea rcx,[r14*4]
    cmp rbx,rcx
    jb .bounds
    mov eax,r15d
    dec rax
    mul rbx
    test rdx,rdx
    jnz .bounds
    add rax,rcx
    jc .bounds
    cmp r10,rax
    jb .bounds
    lea rcx,[r8*4]
    cmp rbp,rcx
    jb .bounds
    mov eax,r9d
    dec rax
    mul rbp
    test rdx,rdx
    jnz .bounds
    add rax,rcx
    jc .bounds
    cmp rdi,rax
    jb .bounds
    mov [rsp+48],rax             ; returned span including inter-row padding
    mov [rsp],r8d               ; destination width
    mov [rsp+4],r9d             ; destination rows left
    movsxd rax,dword [r11+64]
    mov [rsp+8],rax             ; signed first x coordinate
    movsxd rax,dword [r11+68]
    mov [rsp+16],rax            ; signed current y coordinate
    mov eax,[r11+72]
    test eax,eax
    jz .bounds
    cmp eax,268435456
    ja .bounds
    mov [rsp+24],rax
    mov eax,[r11+76]
    test eax,eax
    jz .bounds
    cmp eax,268435456
    ja .bounds
    mov [rsp+32],rax
    mov eax,[r11+80]
    mov [rsp+40],eax
    cmp dword [r11+84],0
    jne .bounds
    cmp qword [r11+88],0
    jne .bounds
.row:
    xor edi,edi                 ; zero sentinel means whole background row
    mov rax,[rsp+16]
    sar rax,16
    cmp rax,r15                 ; negative coordinates compare above height
    jae .row_ready
    imul rax,rbx                ; checked used source span bounds this product
    lea rdi,[r12+rax]
.row_ready:
    mov rsi,[rsp+8]
    mov rdx,r13
    mov ecx,[rsp]
.pixel:
    mov eax,[rsp+40]
    test rdi,rdi
    jz .store
    mov r8,rsi
    sar r8,16
    cmp r8,r14
    jae .store
    mov eax,[rdi+r8*4]
.store:
    mov [rdx],eax
    add rdx,4
    add rsi,[rsp+24]
    dec ecx
    jnz .pixel
    dec dword [rsp+4]
    jz .success
    add r13,rbp
    mov rax,[rsp+32]
    add [rsp+16],rax
    jmp .row
.success:
    mov rdx,[rsp+48]
    xor eax,eax
    jmp .done
.bounds:
    mov eax,2
    xor edx,edx
.done:
    add rsp,64
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    popfq
    ret
