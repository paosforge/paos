;; MODULE gui/img/img_rgba_canvas
;; LAYER 6
;; EXPORTS img_rgba_canvas
;; IMPORTS
;; CAPS
;; OWNER saga:gui_image_pipeline
;
; Actual creator: rc-ai-claude running on OpenAI Codex.
; img_rgba_canvas(RDI=request48) -> EAX=IMG_OK(0)/IMG_E_BOUNDS(2),RDX=span/0.
; Immutable LE request:dst:u64@0,capacity:u64@8,width:u32@16,height:u32@20,
; stride:u64@24,color:RGBA8888-u32@32,reserved:u32@36=0,reserved:u64@40=0.
; Initialize a new caller-owned top-down straight-alpha RGBA image. Explicit
; color is copied exactly, including invisible RGB; no implicit color choice.
; Dimensions1..4096,area<=4194304,stride>=width*4; required span is checked
; (height-1)*stride+width*4. Full declared destination capacity must not wrap
; or overlap request48, including unused capacity. Caller maps/owns and keeps
; complete request/destination stable throughout. All validation before writes.
; Success fills pixel rows only; row padding and capacity slack unchanged.
; Refusal2/0 changes no caller memory. No allocator/scratch/global state/I/O,
; FP/SIMD,retained pointer,UI/history/file authority or default-color policy.
; O(area),no local stack; full64 RBX/RBP/R12-R15 and incoming flags/DF restored.

img_rgba_canvas:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    test rdi,rdi
    jz   .bounds
    mov  rax,rdi
    add  rax,48
    jc   .bounds
    mov  r11,rdi
    mov  rbx,[rdi]
    mov  r8,[rdi+8]
    mov  r12d,[rdi+16]
    mov  r13d,[rdi+20]
    mov  r14,[rdi+24]
    test rbx,rbx
    jz   .bounds
    mov  rax,rbx
    add  rax,r8
    jc   .bounds
    test r12d,r12d
    jz   .bounds
    test r13d,r13d
    jz   .bounds
    cmp  r12d,4096
    ja   .bounds
    cmp  r13d,4096
    ja   .bounds
    mov  rax,r12
    imul rax,r13
    cmp  rax,4194304
    ja   .bounds
    lea  r10,[r12*4]
    cmp  r14,r10
    jb   .bounds
    mov  rax,r13
    dec  rax
    mul  r14
    test rdx,rdx
    jnz  .bounds
    add  rax,r10
    jc   .bounds
    cmp  r8,rax
    jb   .bounds
    mov  rbp,rax
    lea  rax,[r11+48]
    cmp  rbx,rax
    jae  .descriptor_disjoint
    lea  rax,[rbx+r8]
    cmp  r11,rax
    jb   .bounds
.descriptor_disjoint:
    cmp  dword [r11+36],0
    jne  .bounds
    cmp  qword [r11+40],0
    jne  .bounds
    mov  r15d,[r11+32]
    mov  r9d,r13d
    cld
.row:
    mov  rdi,rbx
    mov  ecx,r12d
    mov  eax,r15d
    rep  stosd
    dec  r9d
    jz   .ok
    add  rbx,r14
    jmp  .row
.ok:
    xor  eax,eax
    mov  rdx,rbp
    jmp  .out
.bounds:
    mov  eax,2
    xor  edx,edx
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    popfq
    ret
