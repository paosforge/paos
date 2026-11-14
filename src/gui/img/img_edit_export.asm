;; MODULE gui/img/img_edit_export
;; LAYER 6
;; EXPORTS img_edit_export
;; IMPORTS gui/img/img_edit, gui/img/img_bmp_encode, gui/img/img_png_encode, gui/img/img_jpeg_encode
;; CAPS
;; OWNER saga:gui_image_pipeline
;
; Actual creator: rc-ai-claude on OpenAI Codex.
; img_edit_export(RDI=immutable request64) -> EAX0/RDXencoded bytes or EAX2/RDX0.
; LE request64: state:u64@0,binding:u64@8,expected_revision:u64@16,
; dst:u64@24,capacity:u64@32,format:u32@40,quality:u32@44,matte:u32@48,
; reserved32:u32@52=0,reserved64:u64@56=0.
; Format1=BMP,2=PNG,3=JPEG. BMP/PNG require quality=matte=0, preserve exact
; straight-alpha RGBA/hidden RGB. JPEG requires quality1..100 and matte RGBA
; with alpha255; uses existing encoder's exact flattening/quantization semantics.
; No source metadata is copied. Capacity and bytes follow the existing encoders:
; BMP122+4*w*h; PNG63+(4*w+1)*h+5*ceil(((4*w+1)*h)/65535);
; JPEG requires338+876*ceil(w/8)*ceil(h/8), returns actual bytes <=that bound.
;
; Validates actual state88 through img_edit_check, including both borrowed views,
; binding and revision. Export never writes state or consumes a revision, so
; UINT64_MAX is readable. Entire output capacity must exclude original/current,
; state88 and request64; full pointer+capacity must not wrap. Request may alias
; readonly source spans. Every check precedes writes; refused calls change no
; caller bytes. Success touches encoded output only; unused capacity unchanged.
; No allocator/free, filesystem, IO, retained pointer, authority or ownership
; transfer. Caller serializes calls, keeps state/request/source and mapped
; destination stable until return, and owns any subsequent save operation.
; Full64 RBX/RBP/R12-R15, flags/DF and FP preserved.64B initialized/wiped frame
; plus56B saves; nested JPEG encoder has its own documented976B deepest use.

img_edit_export:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,64
%assign img_edit_export_off 0
%rep 8
    mov qword [rsp+img_edit_export_off],0
%assign img_edit_export_off img_edit_export_off+8
%endrep
%undef img_edit_export_off
    test rdi,rdi
    jz .bounds
    mov rbp,rdi
    mov rax,rdi
    add rax,64
    jc .bounds
    mov rbx,[rbp]
    test rbx,rbx
    jz .bounds
    mov rdx,rbx
    add rdx,88
    jc .bounds
    cmp rbx,rax
    jae .request_state_disjoint
    cmp rbp,rdx
    jb .bounds
.request_state_disjoint:
    cmp dword [rbp+52],0
    jne .bounds
    cmp qword [rbp+56],0
    jne .bounds
    mov r12d,[rbp+40]
    cmp r12d,1
    jb .bounds
    cmp r12d,3
    ja .bounds
    je .format_ready
    cmp qword [rbp+44],0         ; no ignored lossless quality/matte knobs
    jne .bounds
.format_ready:
    mov [rsp],rbx
    mov rax,[rbp+8]
    mov [rsp+8],rax
    mov rax,[rbp+16]
    mov [rsp+16],rax             ; local request32 reserved at24 is zero
    mov rdi,rsp
    call img_edit_check
    test eax,eax
    jnz .bounds
    mov r13,rdx                 ; validated current view32 in stable state
    mov r14,[rbp+24]
    mov r15,[rbp+32]
    test r14,r14
    jz .bounds
    mov rdx,r14
    add rdx,r15
    jc .bounds
    lea rax,[rbp+64]
    cmp r14,rax
    jae .request_dst_disjoint
    cmp rbp,rdx
    jb .bounds
.request_dst_disjoint:
    lea rax,[rbx+88]
    cmp r14,rax
    jae .state_dst_disjoint
    cmp rbx,rdx
    jb .bounds
.state_dst_disjoint:
    mov rax,[rbx+24]
    cmp rax,rdx
    jae .original_disjoint
    add rax,[rbx+32]             ; original endpoint validated by check
    cmp r14,rax
    jb .bounds
.original_disjoint:
    ; Build actual encoder request64 over the local checker request. The
    ; encoders validate current/output overlap and all remaining bounds/options.
    mov rax,[r13]
    mov [rsp],rax
    mov rax,[r13+8]
    mov [rsp+8],rax
    mov [rsp+16],r14
    mov [rsp+24],r15
    mov rax,[r13+16]
    mov [rsp+32],rax
    mov rax,[r13+24]
    mov [rsp+40],rax
    mov rax,[rbp+44]
    mov [rsp+48],rax             ; quality,matte (reserved64 stays zero)
    mov rdi,rsp
    cmp r12d,1
    je .bmp
    cmp r12d,2
    je .png
    call img_jpeg_encode
    jmp .done
.bmp:
    call img_bmp_encode
    jmp .done
.png:
    call img_png_encode
    jmp .done
.bounds:
    mov eax,2
    xor edx,edx
.done:
%assign img_edit_export_off 0
%rep 8
    mov qword [rsp+img_edit_export_off],0
%assign img_edit_export_off img_edit_export_off+8
%endrep
%undef img_edit_export_off
    add rsp,64
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    popfq
    ret
