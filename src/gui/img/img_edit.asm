;; MODULE gui/img/img_edit
;; LAYER 6
;; EXPORTS img_edit_open, img_edit_apply, img_edit_revert, img_edit_adjust, img_edit_geometry, img_edit_check, img_edit_photo, img_edit_paint, img_edit_fill, img_edit_canvas, img_edit_resample
;; IMPORTS gui/img/img_rgba_adjust, gui/img/img_rgba_crop, gui/img/img_rgba_resize, gui/img/img_rgba_auto_levels, gui/img/img_rgba_straighten, gui/img/img_rgba_blur, gui/img/img_rgba_paint, gui/img/img_rgba_brush, gui/img/img_rgba_shape, gui/img/img_rgba_arrow, gui/img/img_rgba_text, gui/img/img_rgba_fill, gui/img/img_rgba_canvas, gui/img/img_rgba_resize_bilinear
;; CAPS
;; OWNER saga:gui_image_pipeline
;
; Borrowed original/current image views, caller-serialized, little endian.
; Views describe top-down RGBA8888; open/apply/revert treat pixels as opaque.
; view32: ptr:u64@0,len:u64@8,w:u32@16,h:u32@20,stride:u64@24.
; state88: magic:u64@0 (PAOSED01),binding:u64@8,revision:u64@16,
; original:view32@24,current:view32@56. Dimensions1..4096,area<=4194304;
; stride>=w*4,checked (h-1)*stride+w*4<=len,whole ptr+len nonwrapping.
; Entire image spans and request must be disjoint from writable state88.
; Current equals original in all four words, or full spans must be disjoint.
;
; RDI immutable request64 for open/apply: state:u64@0,view32@8,binding:u64@40,
; expected_revision:u64@48,reserved:u64@56=0. Open requires expected0 and
; nonzero binding; initializes all88bytes, revision1, both views=original.
; Apply requires matching binding/revision and fully valid existing state;
; candidate must be disjoint from original, may alias previous current/request.
; It replaces current32 only and increments revision. Revert request32:
; state:u64@0,binding:u64@8,expected_revision:u64@16,reserved:u64@24=0.
; It restores original32 to current and increments revision, even if unchanged.
; Apply/revert refuse revision UINT64_MAX. All checks precede all state writes.
; EAX0/RDXnewrevision on success; EAX2/RDX0 refusal, no caller memory writes.
;
; Caller supplies mapped request/state and stable mapped borrowed image spans;
; original is alive and immutable for whole binding, current until replaced.
; Open/apply/revert do not read/write pixels. No allocation/free, I/O,
; ownership transfer or undo stack in any entry.
; Reopen may replace a binding; caller chooses a different nonzero ID for each
; lifetime and serializes calls. Revision detects stale results, not authority;
; no atomic/CAS/thread-safety promise. Revert selects borrowed original bytes,
; and cannot repair caller changes to those bytes. No retained global pointers.
; Full64 RBX/RBP/R12-R15, flags/DF and FP preserved. Open/apply/revert:
; 56-byte save frame, 72-byte deepest stack use.
;
; img_edit_adjust(RDI=immutable request72) -> EAX0/RDXnewrevision or EAX2/RDX0.
; request72: state:u64@0,binding:u64@8,expected_revision:u64@16,
; dst:u64@24,capacity:u64@32,stride:u64@40,brightness:i32@48,
; contrast:i32@52,saturation:i32@56,warmth:i32@60,reserved:u64@64=0.
; Uses current dimensions/pixels and exact img_rgba_adjust integer semantics.
; Checks existing state/binding/revision and all spans/parameters before writes.
; Entire destination capacity must exclude original, current, state88 and
; request72; readonly request may alias either image. On success, writes only
; destination pixels (padding/slack untouched), publishes its borrowed view as
; current, increments revision once. Original descriptor/pixels are unchanged;
; revert remains available. Refusal changes neither state nor destination.
; Caller keeps original and current alive/immutable and supplies a distinct
; mapped destination, stable request/state, serialized through completion.
; A binding/revision is a stale-result check, not authorization or concurrency.
; 112-byte initialized/wiped local frame +56-byte saves; deepest stack 280 bytes.

img_edit_adjust:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,112
%assign img_edit_frame_off 0
%rep 14
    mov qword [rsp+img_edit_frame_off],0
%assign img_edit_frame_off img_edit_frame_off+8
%endrep
%undef img_edit_frame_off
    test rdi,rdi
    jz .bounds
    mov rbp,rdi
    mov rax,rdi
    add rax,72
    jc .bounds
    mov rbx,[rbp]
    test rbx,rbx
    jz .bounds
    mov rdx,rbx
    add rdx,88
    jc .bounds
    cmp rbx,rax
    jae .request_disjoint
    cmp rbp,rdx
    jb .bounds
.request_disjoint:
    cmp qword [rbp+64],0
    jne .bounds
    mov r12,[rbp+8]
    mov r13,[rbp+16]
    call img_edit_validate_state
    test eax,eax
    jnz .bounds
    cmp r12,[rbx+8]
    jne .bounds
    cmp r13,[rbx+16]
    jne .bounds
    cmp r13,-1
    je .bounds
    mov r14,[rbp+24]
    mov r15,[rbp+32]
    ; Local view32 at72; reuse the editor's exact dimension/span validator.
    mov [rsp+72],r14
    mov [rsp+80],r15
    mov rax,[rbx+72]
    mov [rsp+88],rax
    mov rax,[rbp+40]
    mov [rsp+96],rax
    lea rdi,[rsp+72]
    mov rsi,rbx
    call img_edit_validate_view
    test eax,eax
    jnz .bounds
    ; Validated endpoints: exclude destination from request and original.
    lea rdx,[r14+r15]
    lea rax,[rbp+72]
    cmp r14,rax
    jae .request_dst_disjoint
    cmp rbp,rdx
    jb .bounds
.request_dst_disjoint:
    mov rax,[rbx+24]
    cmp rax,rdx
    jae .original_disjoint
    add rax,[rbx+32]
    cmp r14,rax
    jb .bounds
.original_disjoint:
    ; Exact raw adjustment request72 in the first72 bytes of our local frame.
    ; Its validator also excludes destination from current, validates numeric
    ; parameters, and returns before every write on refusal.
    mov rax,[rbx+56]
    mov [rsp],rax
    mov rax,[rbx+64]
    mov [rsp+8],rax
    mov [rsp+16],r14
    mov [rsp+24],r15
    mov rax,[rbx+72]
    mov [rsp+32],rax
    mov rax,[rbx+80]
    mov [rsp+40],rax
    mov rax,[rsp+96]
    mov [rsp+48],rax
    mov rax,[rbp+48]
    mov [rsp+56],rax
    mov rax,[rbp+56]
    mov [rsp+64],rax
    mov rdi,rsp
    call img_rgba_adjust
    test eax,eax
    jnz .bounds
    ; No remaining refusal or fallible operation after successful pixel write.
    mov [rbx+56],r14
    mov [rbx+64],r15
    mov rax,[rsp+88]
    mov [rbx+72],rax
    mov rax,[rsp+96]
    mov [rbx+80],rax
    inc r13
    mov [rbx+16],r13
    mov rdx,r13
    xor eax,eax
    jmp .done
.bounds:
    mov eax,2
    xor edx,edx
.done:
%assign img_edit_frame_off 0
%rep 14
    mov qword [rsp+img_edit_frame_off],0
%assign img_edit_frame_off img_edit_frame_off+8
%endrep
%undef img_edit_frame_off
    add rsp,112
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    popfq
    ret

img_edit_open:
    pushfq
    mov eax,0
    jmp img_edit_dispatch
img_edit_apply:
    pushfq
    mov eax,1
    jmp img_edit_dispatch
img_edit_revert:
    pushfq
    mov eax,2
img_edit_dispatch:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov r14d,eax
    mov r15d,64
    cmp eax,2
    jne .request_size
    mov r15d,32
.request_size:
    test rdi,rdi
    jz .bounds
    mov rbp,rdi
    mov rax,rdi
    add rax,r15
    jc .bounds
    mov rbx,[rbp]
    test rbx,rbx
    jz .bounds
    mov rdx,rbx
    add rdx,88
    jc .bounds
    cmp rbx,rax
    jae .request_disjoint
    cmp rbp,rdx
    jb .bounds
.request_disjoint:
    cmp r14d,2
    je .revert_request
    cmp qword [rbp+56],0
    jne .bounds
    mov r12,[rbp+40]
    mov r13,[rbp+48]
    jmp .request_ready
.revert_request:
    cmp qword [rbp+24],0
    jne .bounds
    mov r12,[rbp+8]
    mov r13,[rbp+16]
.request_ready:
    test r12,r12
    jz .bounds
    test r14d,r14d
    jz .open
    mov rdi,rbx
    call img_edit_validate_state
    test eax,eax
    jnz .bounds
    cmp [rbx+8],r12
    jne .bounds
    cmp [rbx+16],r13
    jne .bounds
    cmp r13,-1
    je .bounds
    cmp r14d,2
    je .revert
    lea rdi,[rbp+8]
    mov rsi,rbx
    call img_edit_validate_view
    test eax,eax
    jnz .bounds
    ; Candidate and original full declared spans, not just used pixel spans.
    mov rax,[rbp+8]
    mov rdx,rax
    add rdx,[rbp+16]              ; endpoints already validated
    mov rcx,[rbx+24]
    cmp rcx,rdx
    jae .apply
    add rcx,[rbx+32]
    cmp rax,rcx
    jb .bounds
.apply:
    lea rdi,[rbp+8]
    jmp .replace_current
.revert:
    lea rdi,[rbx+24]
.replace_current:
    mov rax,[rdi]
    mov rcx,[rdi+8]
    mov rdx,[rdi+16]
    mov r8,[rdi+24]
    mov [rbx+56],rax
    mov [rbx+64],rcx
    mov [rbx+72],rdx
    mov [rbx+80],r8
    inc r13
    mov [rbx+16],r13
    mov rdx,r13
    xor eax,eax
    jmp .done
.open:
    test r13,r13
    jnz .bounds
    lea rdi,[rbp+8]
    mov rsi,rbx
    call img_edit_validate_view
    test eax,eax
    jnz .bounds
    mov rax,0x31304445534f4150
    mov [rbx],rax
    mov [rbx+8],r12
    mov qword [rbx+16],1
    mov rax,[rbp+8]
    mov rcx,[rbp+16]
    mov rdx,[rbp+24]
    mov r8,[rbp+32]
    mov [rbx+24],rax
    mov [rbx+32],rcx
    mov [rbx+40],rdx
    mov [rbx+48],r8
    mov [rbx+56],rax
    mov [rbx+64],rcx
    mov [rbx+72],rdx
    mov [rbx+80],r8
    mov edx,1
    xor eax,eax
    jmp .done
.bounds:
    mov eax,2
    xor edx,edx
.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    popfq
    ret

; img_edit_geometry(RDI=immutable request80) -> EAX0/RDXnewrevision or EAX2/RDX0.
; request80: state:u64@0,binding:u64@8,expected_revision:u64@16,
; dst:u64@24,capacity:u64@32,stride:u64@40,mode:u32@48,
; a:u32@52,b:u32@56,c:u32@60,d:u32@64,turns:u32@68,reserved:u64@72=0.
; mode0: crop current at (a,b), size(c,d), then clockwise quarter-turns0..3.
; mode1: exact point resize to(a,b), c=d=turns=0; floor(dst*src/out).
; Output axes1..4096,area<=4194304, preserving the editor view bound (the raw
; point kernel has a larger destination bound). Odd turns swap crop dimensions.
; Original/current state, binding/revision and all spans/parameters are validated
; before pixel writes. Entire destination capacity excludes original, current,
; state88 and request80. Readonly request may alias either source image.
; Successful raw kernel writes exact RGBA pixels only, then current32 and
; revision are published with no further fallible operation. Original descriptor
; and bytes remain unchanged; Revert remains available after dimension changes.
; Refusal changes neither state nor destination. Padding/slack remain untouched.
; Same serialized stable mapped-memory/lifetime contract as the other entries;
; caller owns destination, retains original, and keeps current alive until next
; replacement. No ownership transfer, authorization, CAS or undo promise.
; 112-byte initialized/wiped local frame plus56-byte saves; deepest stack272B.
img_edit_geometry:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,112
%assign img_edit_geom_off 0
%rep 14
    mov qword [rsp+img_edit_geom_off],0
%assign img_edit_geom_off img_edit_geom_off+8
%endrep
%undef img_edit_geom_off
    test rdi,rdi
    jz .bounds
    mov rbp,rdi
    mov rax,rdi
    add rax,80
    jc .bounds
    mov rbx,[rbp]
    test rbx,rbx
    jz .bounds
    mov rdx,rbx
    add rdx,88
    jc .bounds
    cmp rbx,rax
    jae .request_disjoint
    cmp rbp,rdx
    jb .bounds
.request_disjoint:
    cmp qword [rbp+72],0
    jne .bounds
    call img_edit_validate_state
    test eax,eax
    jnz .bounds
    mov rax,[rbp+8]
    cmp rax,[rbx+8]
    jne .bounds
    mov r13,[rbp+16]
    cmp r13,[rbx+16]
    jne .bounds
    cmp r13,-1
    je .bounds
    mov r12d,[rbp+48]
    cmp r12d,1
    ja .bounds
    mov r14,[rbp+24]
    mov r15,[rbp+32]
    ; Raw request at0..79; candidate view32 at80..111, both fully initialized.
    mov rax,[rbx+56]
    mov [rsp],rax
    mov rax,[rbx+64]
    mov [rsp+8],rax
    mov [rsp+16],r14
    mov [rsp+24],r15
    mov rax,[rbx+72]
    mov [rsp+32],rax
    mov [rsp+80],r14
    mov [rsp+88],r15
    mov rax,[rbp+40]
    mov [rsp+104],rax
    test r12d,r12d
    jnz .resize_request
    mov [rsp+64],rax              ; crop destination stride
    mov rax,[rbx+80]
    mov [rsp+40],rax              ; current source stride
    mov rax,[rbp+52]
    mov [rsp+48],rax              ; crop x,y
    mov eax,[rbp+60]
    mov edx,[rbp+64]
    mov [rsp+56],eax              ; crop width,height
    mov [rsp+60],edx
    mov ecx,[rbp+68]
    mov [rsp+72],ecx              ; reserved32 at76 is already zero
    test cl,1
    jz .crop_dims
    xchg eax,edx
.crop_dims:
    mov [rsp+96],eax
    mov [rsp+100],edx
    jmp .validate_destination
.resize_request:
    cmp qword [rbp+60],0          ; c,d must be zero
    jne .bounds
    cmp dword [rbp+68],0
    jne .bounds
    mov [rsp+56],rax              ; resize destination stride
    mov rax,[rbp+52]
    mov [rsp+40],rax              ; resize width,height
    mov [rsp+96],rax
    mov rax,[rbx+80]
    mov [rsp+48],rax              ; current source stride
.validate_destination:
    lea rdi,[rsp+80]
    mov rsi,rbx
    call img_edit_validate_view
    test eax,eax
    jnz .bounds
    lea rdx,[r14+r15]             ; candidate endpoint already checked
    lea rax,[rbp+80]
    cmp r14,rax
    jae .request_dst_disjoint
    cmp rbp,rdx
    jb .bounds
.request_dst_disjoint:
    mov rax,[rbx+24]
    cmp rax,rdx
    jae .original_disjoint
    add rax,[rbx+32]
    cmp r14,rax
    jb .bounds
.original_disjoint:
    ; The actual kernel additionally checks current/destination overlap and
    ; every operation parameter before any write. No metadata-only stand-in.
    mov rdi,rsp
    test r12d,r12d
    jnz .resize
    call img_rgba_crop
    jmp .kernel_done
.resize:
    call img_rgba_resize
.kernel_done:
    test eax,eax
    jnz .bounds
    ; No fallible work remains after the first pixel write.
    mov [rbx+56],r14
    mov [rbx+64],r15
    mov rax,[rsp+96]
    mov [rbx+72],rax
    mov rax,[rsp+104]
    mov [rbx+80],rax
    inc r13
    mov [rbx+16],r13
    mov rdx,r13
    xor eax,eax
    jmp .done
.bounds:
    mov eax,2
    xor edx,edx
.done:
%assign img_edit_geom_off 0
%rep 14
    mov qword [rsp+img_edit_geom_off],0
%assign img_edit_geom_off img_edit_geom_off+8
%endrep
%undef img_edit_geom_off
    add rsp,112
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    popfq
    ret

; Private: RDI=view32, RSI=validated state start; volatile registers only.
; Metadata only: never dereference view.ptr, never write caller memory.
img_edit_validate_view:
    mov r8,[rdi]
    test r8,r8
    jz .bad
    mov r9,[rdi+8]
    mov r11,r8
    add r11,r9
    jc .bad
    mov eax,[rdi+16]
    mov ecx,[rdi+20]
    test eax,eax
    jz .bad
    test ecx,ecx
    jz .bad
    cmp eax,4096
    ja .bad
    cmp ecx,4096
    ja .bad
    mov edx,eax
    imul edx,ecx                 ; <=4096 squared fits32
    cmp edx,4194304
    ja .bad
    lea r10,[rax*4]
    cmp [rdi+24],r10
    jb .bad
    mov eax,ecx
    dec rax
    mul qword [rdi+24]
    test rdx,rdx
    jnz .bad
    add rax,r10
    jc .bad
    cmp r9,rax
    jb .bad
    cmp rsi,r11
    jae .good
    lea rax,[rsi+88]              ; state endpoint checked by dispatcher
    cmp r8,rax
    jb .bad
.good:
    xor eax,eax
    ret
.bad:
    mov eax,2
    ret

; Readonly freshness check, same immutable request32 layout as Revert:
; state:u64@0,binding:u64@8,expected_revision:u64@16,reserved:u64@24=0.
; img_edit_check -> EAX0/RDXaddress of current view32, or EAX2/RDX0.
; Validates the complete existing state and both original/current borrowed
; views with unchanged validators, and requires exact binding/revision.
; No writes or pixel reads; UINT64_MAX revision is valid for readonly use.
; Returned descriptor remains borrowed inside state88, not a snapshot or an
; ownership/authority grant. Caller serializes and keeps the binding alive.
; Full64 nonvolatiles, flags/DF, FP preserved; deepest stack72B.
img_edit_check:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    test rdi,rdi
    jz .bounds
    mov rbp,rdi
    mov rax,rdi
    add rax,32
    jc .bounds
    mov rbx,[rbp]
    test rbx,rbx
    jz .bounds
    mov rdx,rbx
    add rdx,88
    jc .bounds
    cmp rbx,rax
    jae .request_disjoint
    cmp rbp,rdx
    jb .bounds
.request_disjoint:
    cmp qword [rbp+24],0
    jne .bounds
    call img_edit_validate_state
    test eax,eax
    jnz .bounds
    mov rax,[rbp+8]
    cmp rax,[rbx+8]
    jne .bounds
    mov rax,[rbp+16]
    cmp rax,[rbx+16]
    jne .bounds
    lea rdx,[rbx+56]
    xor eax,eax
    jmp .done
.bounds:
    mov eax,2
    xor edx,edx
.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    popfq
    ret

; Private: RBX=validated state pointer. Callee-saved registers untouched.
img_edit_validate_state:
    mov rax,0x31304445534f4150
    cmp [rbx],rax
    jne .bad
    cmp qword [rbx+8],0
    je .bad
    cmp qword [rbx+16],0
    je .bad
    lea rdi,[rbx+24]
    mov rsi,rbx
    call img_edit_validate_view
    test eax,eax
    jnz .bad
    lea rdi,[rbx+56]
    mov rsi,rbx
    call img_edit_validate_view
    test eax,eax
    jnz .bad
    mov rax,[rbx+24]
    cmp rax,[rbx+56]
    jne .disjoint
    mov rax,[rbx+32]
    cmp rax,[rbx+64]
    jne .disjoint
    mov rax,[rbx+40]
    cmp rax,[rbx+72]
    jne .disjoint
    mov rax,[rbx+48]
    cmp rax,[rbx+80]
    jne .disjoint
    xor eax,eax
    ret
.disjoint:
    mov rax,[rbx+24]
    mov rcx,rax
    add rcx,[rbx+32]
    cmp [rbx+56],rcx
    jae .good
    mov rcx,[rbx+56]
    add rcx,[rbx+64]
    cmp rax,rcx
    jb .bad
.good:
    xor eax,eax
    ret
.bad:
    mov eax,2
    ret

; Actual creator: rc-ai-claude on OpenAI Codex.
; img_edit_photo(RDI=immutable request96)->EAX0/RDXnewrevision or EAX2/RDX0.
; LE fields: state:u64@0,binding:u64@8,expected_revision:u64@16,dst:u64@24,
; capacity:u64@32,dst_stride:u64@40,mode:u32@48,amount:i32/u32@52,
; x:u32@56,y:u32@60,rect_w:u32@64,rect_h:u32@68,scratch:u64@72,
; scratch_capacity:u64@80,reserved:u64@88=0. Current dimensions retained.
; Mode1 auto-enhance uses exact opacity-weighted img_rgba_auto_levels:
; amount/rectangle must be zero; scratch requires1024B.
; Mode2 straighten uses exact img_rgba_straighten fixed-canvas transform:
; amount=clockwise angle in tenths degree (-150..150), rectangle/scratch/cap0.
; Mode3 annotation blur uses exact img_rgba_blur alpha-weighted ROI box:
; amount=radius0..32,nonempty rectangle within current,scratch>=rect_w*16B.
; No new filter math, ICC/model, default UI policy or JPEG-lossless promise.
;
; Complete state/binding/revision check precedes pixel/scratch access. Writable
; complete destination/scratch spans must exclude state88,request96,original,
; current and each other, even unused slack. Raw kernels validate remaining
; parameters/spans before writes. Request may alias readonly source memory.
; Successful raw call is followed only by current-view publication and one
; revision increment. Original/current old pixels unchanged; Revert survives.
; Refusal changes no caller bytes; UINT64_MAX revision refuses before pixels.
; Destination padding/slack and scratch excess stay unchanged; raw auto/blur
; clear exactly their used scratch. Caller supplies stable mapped spans and
; serializes calls, preserving borrowed original/current lifetimes. No alloc,
; free, IO, retained globals, ownership or authority; no undo-history stack.
; Full64 nonvolatiles,flags/DF,FP preserved.128B initialized/wiped local frame
; plus56B saves; unchanged raw callee stack use is additional.
img_edit_photo:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,128
%assign img_edit_photo_off 0
%rep 16
    mov qword [rsp+img_edit_photo_off],0
%assign img_edit_photo_off img_edit_photo_off+8
%endrep
%undef img_edit_photo_off
    test rdi,rdi
    jz .bounds
    mov rbp,rdi
    mov rax,rdi
    add rax,96
    jc .bounds
    mov rbx,[rbp]
    test rbx,rbx
    jz .bounds
    mov rdx,rbx
    add rdx,88
    jc .bounds
    cmp rbx,rax
    jae .request_disjoint
    cmp rbp,rdx
    jb .bounds
.request_disjoint:
    cmp qword [rbp+88],0
    jne .bounds
    mov r12,[rbp+8]
    mov r13,[rbp+16]
    call img_edit_validate_state
    test eax,eax
    jnz .bounds
    cmp r12,[rbx+8]
    jne .bounds
    cmp r13,[rbx+16]
    jne .bounds
    cmp r13,-1
    je .bounds
    mov eax,[rbp+48]
    cmp eax,1
    jb .bounds
    cmp eax,3
    ja .bounds
    je .mode_ready
    cmp qword [rbp+56],0
    jne .bounds
    cmp qword [rbp+64],0
    jne .bounds
    cmp eax,2
    je .straighten_options
    cmp dword [rbp+52],0
    jne .bounds
    jmp .mode_ready
.straighten_options:
    cmp qword [rbp+72],0
    jne .bounds
    cmp qword [rbp+80],0
    jne .bounds
.mode_ready:
    mov r14,[rbp+24]
    mov r15,[rbp+32]
    ; Local candidate view32 at96; exact existing editor view validator.
    mov [rsp+96],r14
    mov [rsp+104],r15
    mov rax,[rbx+72]
    mov [rsp+112],rax
    mov rax,[rbp+40]
    mov [rsp+120],rax
    lea rdi,[rsp+96]
    mov rsi,rbx
    call img_edit_validate_view
    test eax,eax
    jnz .bounds
    lea rdx,[r14+r15]
    lea rax,[rbp+96]
    cmp r14,rax
    jae .request_dst_disjoint
    cmp rbp,rdx
    jb .bounds
.request_dst_disjoint:
    mov rax,[rbx+24]
    cmp rax,rdx
    jae .original_dst_disjoint
    add rax,[rbx+32]
    cmp r14,rax
    jb .bounds
.original_dst_disjoint:
    cmp dword [rbp+48],2
    je .scratch_ready
    mov r8,[rbp+72]
    test r8,r8
    jz .bounds
    mov r10,r8
    add r10,[rbp+80]
    jc .bounds
    lea rax,[rbx+88]
    cmp r8,rax
    jae .state_scratch_disjoint
    cmp rbx,r10
    jb .bounds
.state_scratch_disjoint:
    lea rax,[rbp+96]
    cmp r8,rax
    jae .request_scratch_disjoint
    cmp rbp,r10
    jb .bounds
.request_scratch_disjoint:
    mov rax,[rbx+24]
    cmp rax,r10
    jae .scratch_ready
    add rax,[rbx+32]
    cmp r8,rax
    jb .bounds
.scratch_ready:
    ; Actual raw request begins at0; all reserved words initially zero.
    mov rax,[rbx+56]
    mov [rsp],rax
    mov rax,[rbx+64]
    mov [rsp+8],rax
    mov [rsp+16],r14
    mov [rsp+24],r15
    mov rax,[rbx+72]
    mov [rsp+32],rax
    mov rax,[rbx+80]
    mov [rsp+40],rax
    mov rax,[rsp+120]
    mov [rsp+48],rax
    mov rdi,rsp
    cmp dword [rbp+48],1
    je .auto
    cmp dword [rbp+48],2
    je .straighten
    mov rax,[rbp+56]
    mov [rsp+56],rax
    mov rax,[rbp+64]
    mov [rsp+64],rax
    mov eax,[rbp+52]
    mov [rsp+72],eax
    mov rax,[rbp+72]
    mov [rsp+80],rax
    mov rax,[rbp+80]
    mov [rsp+88],rax
    call img_rgba_blur
    jmp .raw_done
.auto:
    mov rax,[rbp+72]
    mov [rsp+56],rax
    mov rax,[rbp+80]
    mov [rsp+64],rax
    call img_rgba_auto_levels
    jmp .raw_done
.straighten:
    mov eax,[rbp+52]
    mov [rsp+56],eax
    call img_rgba_straighten
.raw_done:
    test eax,eax
    jnz .bounds
    ; No remaining validation/fallible operation after successful raw write.
    mov [rbx+56],r14
    mov [rbx+64],r15
    mov rax,[rsp+112]
    mov [rbx+72],rax
    mov rax,[rsp+120]
    mov [rbx+80],rax
    inc r13
    mov [rbx+16],r13
    mov rdx,r13
    xor eax,eax
    jmp .done
.bounds:
    mov eax,2
    xor edx,edx
.done:
%assign img_edit_photo_off 0
%rep 16
    mov qword [rsp+img_edit_photo_off],0
%assign img_edit_photo_off img_edit_photo_off+8
%endrep
%undef img_edit_photo_off
    add rsp,128
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    popfq
    ret

; Actual creator: rc-ai-claude on OpenAI Codex.
; img_edit_paint(RDI=immutable request96)->EAX0/RDXnewrevision or EAX2/RDX0.
; LE fields: state:u64@0,binding:u64@8,expected_revision:u64@16,
; dst:u64@24,capacity:u64@32,dst_stride:u64@40,kind:u32@48,
; reserved:u32@52=0,payload40@56. Current dimensions retained.
; Kind1 rectangle paint/highlight/erase: exact img_rgba_paint request tail
; @56..79; unused @80..95 zero. Kind2 round brush/eraser: exact
; img_rgba_brush tail @56..87; unused @88..95 zero. Kind3 filled/outlined
; rectangle/ellipse: exact img_rgba_shape tail @56..87; unused @88..95 zero.
; Kind4 arrow: exact img_rgba_arrow tail @56..95. Kind5 text: exact
; img_rgba_text tail @56..95, existing partial-Latin Spleen coverage only.
; Raw tail includes all raw reserved fields, which retain their zero rules.
;
; Complete state/binding/revision validation precedes pixel or text access.
; Full destination capacity excludes original,current,state88,request96 and
; required text bytes (kind5). Text must exclude writable state88.
; Raw kernels check remaining parameters/spans
; before writes. Readonly request/source/text may alias. Refusal changes no
; caller bytes; UINT64_MAX revision refuses. Existing raster/color math stays
; unchanged. Success publishes current32 then increments revision exactly once;
; no fallible step after raw success. Original/old current pixels untouched,
; Revert retained; destination padding/slack unchanged. No alloc/free,scratch,
; retained globals,IO,UI,file authority or undo-history stack. Caller supplies
; stable mapped borrowed spans,serializes calls and retains original/current
; lifetimes. Binding/revision detects stale jobs; it grants no authority/CAS.
; Full64 nonvolatiles,flags/DF and FP preserved.128B initialized/wiped local
; frame +56B saves; unchanged raw callee stack use is additional.
img_edit_paint:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,128
%assign img_edit_paint_off 0
%rep 16
    mov qword [rsp+img_edit_paint_off],0
%assign img_edit_paint_off img_edit_paint_off+8
%endrep
%undef img_edit_paint_off
    test rdi,rdi
    jz .bounds
    mov rbp,rdi
    mov rax,rdi
    add rax,96
    jc .bounds
    mov rbx,[rbp]
    test rbx,rbx
    jz .bounds
    mov rdx,rbx
    add rdx,88
    jc .bounds
    cmp rbx,rax
    jae .request_disjoint
    cmp rbp,rdx
    jb .bounds
.request_disjoint:
    cmp dword [rbp+52],0
    jne .bounds
    mov r12,[rbp+8]
    mov r13,[rbp+16]
    call img_edit_validate_state
    test eax,eax
    jnz .bounds
    cmp r12,[rbx+8]
    jne .bounds
    cmp r13,[rbx+16]
    jne .bounds
    cmp r13,-1
    je .bounds
    cmp dword [rbp+48],1
    jb .bounds
    cmp dword [rbp+48],5
    ja .bounds
    cmp dword [rbp+48],3
    ja .tail_ready
    cmp qword [rbp+88],0
    jne .bounds
    cmp dword [rbp+48],1
    jne .tail_ready
    cmp qword [rbp+80],0
    jne .bounds
.tail_ready:
    mov r14,[rbp+24]
    mov r15,[rbp+32]
    ; Candidate view32 is outside every possible raw request.
    mov [rsp+96],r14
    mov [rsp+104],r15
    mov rax,[rbx+72]
    mov [rsp+112],rax
    mov rax,[rbp+40]
    mov [rsp+120],rax
    lea rdi,[rsp+96]
    mov rsi,rbx
    call img_edit_validate_view
    test eax,eax
    jnz .bounds
    lea rdx,[r14+r15]
    lea rax,[rbp+96]
    cmp r14,rax
    jae .request_dst_disjoint
    cmp rbp,rdx
    jb .bounds
.request_dst_disjoint:
    mov rax,[rbx+24]
    cmp rax,rdx
    jae .original_dst_disjoint
    add rax,[rbx+32]
    cmp r14,rax
    jb .bounds
.original_dst_disjoint:
    cmp dword [rbp+48],5
    jne .text_ready
    ; Text is readonly input; publishing state must not alter its bytes.
    mov rax,[rbp+56]
    test rax,rax
    jz .bounds
    mov ecx,[rbp+64]
    test ecx,ecx
    jz .bounds
    cmp ecx,512
    ja .bounds
    lea rdx,[rcx*4]
    add rdx,rax
    jc .bounds
    lea rcx,[rbx+88]
    cmp rax,rcx
    jae .text_ready
    cmp rbx,rdx
    jb .bounds
.text_ready:
    ; Common raw prefix56: actual current source and candidate destination.
    mov rax,[rbx+56]
    mov [rsp],rax
    mov rax,[rbx+64]
    mov [rsp+8],rax
    mov [rsp+16],r14
    mov [rsp+24],r15
    mov rax,[rbx+72]
    mov [rsp+32],rax
    mov rax,[rbx+80]
    mov [rsp+40],rax
    mov rax,[rsp+120]
    mov [rsp+48],rax
%assign img_edit_paint_off 56
%rep 5
    mov rax,[rbp+img_edit_paint_off]
    mov [rsp+img_edit_paint_off],rax
%assign img_edit_paint_off img_edit_paint_off+8
%endrep
%undef img_edit_paint_off
    mov rdi,rsp
    cmp dword [rbp+48],1
    je .rectangle
    cmp dword [rbp+48],2
    je .brush
    cmp dword [rbp+48],3
    je .shape
    cmp dword [rbp+48],4
    je .arrow
    call img_rgba_text
    jmp .raw_done
.rectangle:
    call img_rgba_paint
    jmp .raw_done
.brush:
    call img_rgba_brush
    jmp .raw_done
.shape:
    call img_rgba_shape
    jmp .raw_done
.arrow:
    call img_rgba_arrow
.raw_done:
    test eax,eax
    jnz .bounds
    ; Success has no remaining validation/fallible step.
    mov [rbx+56],r14
    mov [rbx+64],r15
    mov rax,[rsp+112]
    mov [rbx+72],rax
    mov rax,[rsp+120]
    mov [rbx+80],rax
    inc r13
    mov [rbx+16],r13
    mov rdx,r13
    xor eax,eax
    jmp .done
.bounds:
    mov eax,2
    xor edx,edx
.done:
%assign img_edit_paint_off 0
%rep 16
    mov qword [rsp+img_edit_paint_off],0
%assign img_edit_paint_off img_edit_paint_off+8
%endrep
%undef img_edit_paint_off
    add rsp,128
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    popfq
    ret

; Actual creator: rc-ai-claude on OpenAI Codex.
; img_edit_fill(RDI=immutable request80) -> EAX0/RDXrevision or EAX2/RDX0.
; state:u64@0,binding:u64@8,expected_revision:u64@16,dst:u64@24,
; capacity:u64@32,dst_stride:u64@40,seed_x:u32@48,seed_y:u32@52,
; replacement:RGBA8888-u32@56,reserved:u32@60=0,scratch:u64@64,
; scratch_capacity:u64@72. Current dimensions retained. Actual img_rgba_fill
; semantics: exact four-connected identical-RGBA component, no tolerance/blend.
; State/binding/revision validation precedes pixel/scratch access; maxrevision
; refuses. Entire destination and scratch capacities exclude original,current,
; state88,request80 and each other, with overflow checked. Readonly request may
; alias either image. All validation precedes writes; refusal changes no caller
; memory. Raw success clears exactly area*4 scratch bytes, preserves excess
; scratch/padding/slack, then current32 and revision publish exactly once with
; no remaining fallible step. Original/old current pixels and Revert retained.
; Caller maps stable borrowed spans and serializes all calls. Binding/revision
; detect stale results; they grant no authority/CAS/concurrency/lifetime owner.
; No alloc/free/IO/global retained pointers/undo stack/UI. Full64 nonvolatiles,
; flags/DF and FP preserved.128B initialized/wiped locals +56B saves; unchanged
; raw callee stack additional.
img_edit_fill:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,128
%assign img_edit_fill_off 0
%rep 16
    mov qword [rsp+img_edit_fill_off],0
%assign img_edit_fill_off img_edit_fill_off+8
%endrep
%undef img_edit_fill_off
    test rdi,rdi
    jz .bounds
    mov rbp,rdi
    mov rax,rdi
    add rax,80
    jc .bounds
    mov rbx,[rbp]
    test rbx,rbx
    jz .bounds
    mov rdx,rbx
    add rdx,88
    jc .bounds
    cmp rbx,rax
    jae .request_disjoint
    cmp rbp,rdx
    jb .bounds
.request_disjoint:
    cmp dword [rbp+60],0
    jne .bounds
    mov r12,[rbp+8]
    mov r13,[rbp+16]
    call img_edit_validate_state
    test eax,eax
    jnz .bounds
    cmp r12,[rbx+8]
    jne .bounds
    cmp r13,[rbx+16]
    jne .bounds
    cmp r13,-1
    je .bounds
    mov r14,[rbp+24]
    mov r15,[rbp+32]
    ; Candidate view32 at88 excludes the complete raw request88.
    mov [rsp+88],r14
    mov [rsp+96],r15
    mov rax,[rbx+72]
    mov [rsp+104],rax
    mov rax,[rbp+40]
    mov [rsp+112],rax
    lea rdi,[rsp+88]
    mov rsi,rbx
    call img_edit_validate_view
    test eax,eax
    jnz .bounds
    lea rdx,[r14+r15]
    lea rax,[rbp+80]
    cmp r14,rax
    jae .request_dst_disjoint
    cmp rbp,rdx
    jb .bounds
.request_dst_disjoint:
    mov rax,[rbx+24]
    cmp rax,rdx
    jae .original_dst_disjoint
    add rax,[rbx+32]
    cmp r14,rax
    jb .bounds
.original_dst_disjoint:
    ; Raw checks scratch vs current,destination,local raw request. External
    ; request/state/original need these explicit full-capacity exclusions.
    mov r8,[rbp+64]
    test r8,r8
    jz .bounds
    mov r9,r8
    add r9,[rbp+72]
    jc .bounds
    lea rax,[rbx+88]
    cmp r8,rax
    jae .scratch_state_disjoint
    cmp rbx,r9
    jb .bounds
.scratch_state_disjoint:
    lea rax,[rbp+80]
    cmp r8,rax
    jae .scratch_request_disjoint
    cmp rbp,r9
    jb .bounds
.scratch_request_disjoint:
    mov rax,[rbx+24]
    cmp rax,r9
    jae .scratch_original_disjoint
    add rax,[rbx+32]
    cmp r8,rax
    jb .bounds
.scratch_original_disjoint:
    mov rax,[rbx+56]
    mov [rsp],rax
    mov rax,[rbx+64]
    mov [rsp+8],rax
    mov [rsp+16],r14
    mov [rsp+24],r15
    mov rax,[rbx+72]
    mov [rsp+32],rax
    mov rax,[rbx+80]
    mov [rsp+40],rax
    mov rax,[rsp+112]
    mov [rsp+48],rax
    mov rax,[rbp+48]
    mov [rsp+56],rax
    mov rax,[rbp+56]
    mov [rsp+64],rax
    mov [rsp+72],r8
    mov rax,[rbp+72]
    mov [rsp+80],rax
    mov rdi,rsp
    call img_rgba_fill
    test eax,eax
    jnz .bounds
    ; Raw success completed all validation and scratch clearing.
    mov [rbx+56],r14
    mov [rbx+64],r15
    mov rax,[rsp+104]
    mov [rbx+72],rax
    mov rax,[rsp+112]
    mov [rbx+80],rax
    inc r13
    mov [rbx+16],r13
    mov rdx,r13
    xor eax,eax
    jmp .done
.bounds:
    mov eax,2
    xor edx,edx
.done:
%assign img_edit_fill_off 0
%rep 16
    mov qword [rsp+img_edit_fill_off],0
%assign img_edit_fill_off img_edit_fill_off+8
%endrep
%undef img_edit_fill_off
    add rsp,128
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    popfq
    ret

; img_edit_canvas(RDI=immutable request64) -> EAX0/RDX1 or EAX2/RDX0.
; state:u64@0,binding:u64@8,dst:u64@16,capacity:u64@24,width:u32@32,
; height:u32@36,stride:u64@40,color:RGBA8888-u32@48,reserved:u32@52=0,
; reserved:u64@56=0. Fresh document: all88 state bytes must be zero, binding
; nonzero. A live/nonzero state refuses before any pixel write; use a separate
; state for a new document. Exact explicit color; no implicit background.
; State/request/full destination spans exclude one another with checked ends.
; Existing view limits and raw img_rgba_canvas semantics retained. All checks
; precede writes. On success pixels initialized, then all state88 published:
; magic,binding,revision1,original=current=the caller-owned canvas. Thereafter
; original must remain immutable for the binding, as with img_edit_open.
; Refusal changes no caller bytes. Destination padding/slack unchanged.
; No alloc/free/IO/default color/UI/history/authority. Caller maps stable spans,
; serializes calls and retains image lifetime. Full64 nonvolatiles,flags/DF and
; FP preserved.48B initialized/wiped locals +56B saves; raw stack additional.
img_edit_canvas:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,48
%assign img_edit_canvas_off 0
%rep 6
    mov qword [rsp+img_edit_canvas_off],0
%assign img_edit_canvas_off img_edit_canvas_off+8
%endrep
%undef img_edit_canvas_off
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
    jae .request_disjoint
    cmp rbp,rdx
    jb .bounds
.request_disjoint:
    mov r12,[rbp+8]
    test r12,r12
    jz .bounds
    cmp dword [rbp+52],0
    jne .bounds
    cmp qword [rbp+56],0
    jne .bounds
    ; A new canvas never replaces a still-borrowed document.
%assign img_edit_canvas_off 0
%rep 11
    cmp qword [rbx+img_edit_canvas_off],0
    jne .bounds
%assign img_edit_canvas_off img_edit_canvas_off+8
%endrep
%undef img_edit_canvas_off
    lea rdi,[rbp+16]
    mov rsi,rbx
    call img_edit_validate_view
    test eax,eax
    jnz .bounds
    mov rax,[rbp+16]
    mov rdx,rax
    add rdx,[rbp+24]
    lea rcx,[rbp+64]
    cmp rax,rcx
    jae .destination_ready
    cmp rbp,rdx
    jb .bounds
.destination_ready:
    ; Request's tail48 is exactly the actual raw canvas request.
%assign img_edit_canvas_off 0
%rep 6
    mov rax,[rbp+16+img_edit_canvas_off]
    mov [rsp+img_edit_canvas_off],rax
%assign img_edit_canvas_off img_edit_canvas_off+8
%endrep
%undef img_edit_canvas_off
    mov rdi,rsp
    call img_rgba_canvas
    test eax,eax
    jnz .bounds
    ; No further validation or fallible calls after pixels initialized.
    mov rax,0x31304445534f4150
    mov [rbx],rax
    mov [rbx+8],r12
    mov qword [rbx+16],1
%assign img_edit_canvas_off 0
%rep 4
    mov rax,[rbp+16+img_edit_canvas_off]
    mov [rbx+24+img_edit_canvas_off],rax
    mov [rbx+56+img_edit_canvas_off],rax
%assign img_edit_canvas_off img_edit_canvas_off+8
%endrep
%undef img_edit_canvas_off
    xor eax,eax
    mov edx,1
    jmp .done
.bounds:
    mov eax,2
    xor edx,edx
.done:
%assign img_edit_canvas_off 0
%rep 6
    mov qword [rsp+img_edit_canvas_off],0
%assign img_edit_canvas_off img_edit_canvas_off+8
%endrep
%undef img_edit_canvas_off
    add rsp,48
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    popfq
    ret

; Actual creator: rc-ai-claude on OpenAI Codex.
; img_edit_resample(RDI=immutable LE request64)->EAX0/RDXnewrevision,
; or EAX2/RDX0 refusal without caller writes.
; state:u64@0,binding:u64@8,expected_revision:u64@16,dst:u64@24,
; capacity:u64@32,dst_stride:u64@40,width:u32@48,height:u32@52,
; reserved:u64@56=0. Caller-serialized borrowed RGBA8888 views.
; Explicit alpha-weighted bilinear resize of current through the existing
; img_rgba_resize_bilinear kernel, including its fixed-point pixel centres,
; encoded-sRGB integer interpolation and hidden-RGB canonicalization at A=0.
; No default/cache/point-resize change, ICC or area anti-aliasing claim.
; Existing state and fresh binding/revision checked before any pixel access;
; revision UINT64_MAX refuses. Destination axes1..4096,area<=4194304,
; checked final-row required span and whole nonwrapping capacity; complete
; destination excludes original,current,state88 and external request64.
; Readonly request/source alias allowed. All validation precedes pixels.
; Success writes only destination pixels, leaves padding/capacity slack and
; original/previous-current bytes unchanged, publishes current32 and increments
; revision once. No fallible operation follows successful raw pixel writes.
; Original remains immutable/alive for binding; current alive until replaced;
; caller supplies mapped stable request/state/spans and chooses binding IDs.
; Freshness is not authority, CAS or concurrency. No allocation/free/I/O,
; history, ownership transfer, retained pointer, UI or save/file authority.
; Full64 nonvolatiles, flags/DF and FP preserved. Initialized/wiped96B locals
; +56B saves; raw kernel's200B frame/saves and private calls are additional.
img_edit_resample:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,96
%assign img_edit_resample_off 0
%rep 12
    mov qword [rsp+img_edit_resample_off],0
%assign img_edit_resample_off img_edit_resample_off+8
%endrep
%undef img_edit_resample_off
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
    jae .request_disjoint
    cmp rbp,rdx
    jb .bounds
.request_disjoint:
    cmp qword [rbp+56],0
    jne .bounds
    mov r12,[rbp+8]
    mov r13,[rbp+16]
    call img_edit_validate_state
    test eax,eax
    jnz .bounds
    cmp r12,[rbx+8]
    jne .bounds
    cmp r13,[rbx+16]
    jne .bounds
    cmp r13,-1
    je .bounds
    mov r14,[rbp+24]
    mov r15,[rbp+32]
    ; Candidate view32 at64; raw request64 at0.
    mov [rsp+64],r14
    mov [rsp+72],r15
    mov rax,[rbp+48]
    mov [rsp+80],rax
    mov rax,[rbp+40]
    mov [rsp+88],rax
    lea rdi,[rsp+64]
    mov rsi,rbx
    call img_edit_validate_view
    test eax,eax
    jnz .bounds
    lea rdx,[r14+r15]
    lea rax,[rbp+64]
    cmp r14,rax
    jae .request_dst_disjoint
    cmp rbp,rdx
    jb .bounds
.request_dst_disjoint:
    mov rax,[rbx+24]
    cmp rax,rdx
    jae .original_disjoint
    add rax,[rbx+32]
    cmp r14,rax
    jb .bounds
.original_disjoint:
    ; The unchanged raw validator excludes current and local raw request,
    ; and checks every parameter before its first pixel read/write.
    mov rax,[rbx+56]
    mov [rsp],rax
    mov rax,[rbx+64]
    mov [rsp+8],rax
    mov [rsp+16],r14
    mov [rsp+24],r15
    mov rax,[rbx+72]
    mov [rsp+32],rax
    mov rax,[rsp+80]
    mov [rsp+40],rax
    mov rax,[rbx+80]
    mov [rsp+48],rax
    mov rax,[rsp+88]
    mov [rsp+56],rax
    mov rdi,rsp
    call img_rgba_resize_bilinear
    test eax,eax
    jnz .bounds
    ; Publish once. No remaining validation or fallible operation.
    mov [rbx+56],r14
    mov [rbx+64],r15
    mov rax,[rsp+80]
    mov [rbx+72],rax
    mov rax,[rsp+88]
    mov [rbx+80],rax
    inc r13
    mov [rbx+16],r13
    mov rdx,r13
    xor eax,eax
    jmp .done
.bounds:
    mov eax,2
    xor edx,edx
.done:
%assign img_edit_resample_off 0
%rep 12
    mov qword [rsp+img_edit_resample_off],0
%assign img_edit_resample_off img_edit_resample_off+8
%endrep
%undef img_edit_resample_off
    add rsp,96
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    popfq
    ret
