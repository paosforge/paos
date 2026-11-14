;; MODULE gui/img/video_frame_queue_private
;; LAYER 6
;; EXPORTS video_frame_queue_init, video_frame_queue_begin, video_frame_queue_step, video_frame_queue_present, video_frame_queue_control, video_frame_queue_put
;; IMPORTS media/av_clock_private, gui/img/img_video_bridge, gui/shared_surface_portal
;; CAPS
;; OWNER rc-codex-av
; PRIVATE UNWIRED. Contract b11eb7e0c. Sole foreground owner; mapped truthful
; native spans/leases. No runtime surface/clock/DMA/allocation authority.
; RDI=context640 RSI=input RDX=result96 RCX=present scratch256. RAX=0/-1.
; Refusal preserves context/input/result/pixels; scratch expendable.

%define VQ_MAGIC 0x31514656
%define VQ_SLOT 160
%define VQ_N 3

video_frame_queue_init:
    xor r11d,r11d
    jmp vq_enter
video_frame_queue_begin:
    mov r11d,1
    jmp vq_enter
video_frame_queue_step:
    mov r11d,2
    jmp vq_enter
video_frame_queue_present:
    mov r11d,3
    jmp vq_enter
video_frame_queue_control:
    mov r11d,4
    jmp vq_enter
video_frame_queue_put:
    mov r11d,5
vq_enter:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,32
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    xor r15d,r15d
    mov ebp,r11d
    mov ebx,64
    test ebp,ebp
    jnz .not_init
    mov ebx,96
.not_init:
    cmp ebp,1
    jne .not_begin
    mov ebx,128
.not_begin:
    cmp ebp,2
    jne .not_step
    xor ebx,ebx
    test r13,r13
    jnz vq_bad
.not_step:
    cmp ebp,3
    jne .not_present
    mov ebx,192
    mov r15,rcx
    test r15,r15
    jz vq_bad
.not_present:
    mov [rsp+24],rbx
    test r12,r12
    jz .bad_meta
    test r14,r14
    jz .bad_meta
    mov rax,r12
    add rax,640
    jc .bad_meta
    mov rax,r14
    add rax,96
    jc .bad_meta
    mov rdx,rax
    mov rax,r14
    mov rdi,r12
    mov esi,640
    call vq_disjoint
    jc .bad_meta
    test ebx,ebx
    jz .metadata_ok
    test r13,r13
    jz .bad_meta
    mov rax,r13
    mov rdx,r13
    add rdx,rbx
    jc .bad_meta
    mov rdi,r12
    mov esi,640
    call vq_disjoint
    jc .bad_meta
    mov rdi,r14
    mov esi,96
    call vq_disjoint
    jc .bad_meta
.metadata_ok:
    jmp .metadata_continue
.bad_meta:
    jmp vq_bad
.metadata_continue:
    test r15,r15
    jz .scratch_ok
    mov rax,r15
    mov rdx,r15
    add rdx,256
    jc .bad_meta
    call vq_meta
    jc .bad_meta
.scratch_ok:
    test ebp,ebp
    jz vq_init
    cmp dword [r12],VQ_MAGIC
    jne .bad_header
    mov eax,[r12+4]
    dec eax
    cmp eax,6
    ja .bad_header
    cmp qword [r12+8],0
    je .bad_header
    cmp qword [r12+16],0
    je .bad_header
    cmp qword [r12+24],0
    je .bad_header
    jmp .bad_header_ok
.bad_header:
    jmp vq_bad
.bad_header_ok:
    mov eax,[r12+36]
    dec eax
    cmp eax,639
    ja .bad_header
    inc eax
    shl eax,2
    cmp eax,[r12+44]
    jne .bad_header
    mov ecx,[r12+40]
    dec ecx
    cmp ecx,359
    ja .bad_header
    inc ecx
    imul rax,rcx
    cmp rax,[r12+48]
    jne .bad_header
    mov rax,[r12+144]
    or rax,[r12+152]
    jnz .bad_header
    lea rbx,[r12+160]
.slots:
    mov eax,[rbx]
    cmp eax,4
    ja .bad_slot
    cmp dword [rbx+4],1
    ja .bad_slot
    test eax,eax
    jz .free
    cmp qword [rbx+8],0
    je .bad_slot
    jmp .reserved
.free:
    cmp qword [rbx+88],0
    jne .bad_slot
    jmp .bad_slot_ok
.bad_slot:
    jmp vq_bad
.bad_slot_ok:
.reserved:
    mov rax,[rbx+144]
    or rax,[rbx+152]
    jnz .bad_slot
    mov rax,[rbx+96]
    mov rdx,[rbx+104]
    call vq_pixel_span
    jc .bad_slot
    ; Whole fixed destination capacities, including unused tails, disjoint.
    lea r10,[r12+160]
.pairs:
    cmp r10,rbx
    je .next_pair
    mov rdi,[r10+96]
    mov rsi,[r10+104]
    call vq_disjoint
    jc .bad_slot
.next_pair:
    add r10,160
    lea rcx,[r12+640]
    cmp r10,rcx
    jb .pairs
    add rbx,160
    lea rcx,[r12+640]
    cmp rbx,rcx
    jb .slots
    xor r8d,r8d
    xor r9d,r9d
    xor r10d,r10d
    xor r11d,r11d
    lea rbx,[r12+160]
.counts:
    mov eax,[rbx]
    cmp eax,1
    sete cl
    movzx ecx,cl
    add r8d,ecx
    cmp eax,2
    sete cl
    movzx ecx,cl
    add r9d,ecx
    cmp eax,3
    sete cl
    movzx ecx,cl
    add r10d,ecx
    add r11d,[rbx+4]
    cmp dword [rbx+4],0
    je .next_count
    cmp eax,3
    jb .bad_counts
    cmp qword [rbx+112],0
    je .bad_counts
    jmp .next_count
.bad_counts:
    jmp vq_bad
.next_count:
    add rbx,160
    lea rcx,[r12+640]
    cmp rbx,rcx
    jb .counts
    cmp r8d,1
    ja .bad_counts
    cmp r9d,2
    ja .bad_counts
    cmp r10d,1
    ja .bad_counts
    cmp r11d,1
    ja .bad_counts
    cmp ebp,1
    je vq_begin
    cmp ebp,2
    je vq_step
    cmp ebp,3
    je vq_present
    cmp ebp,4
    je vq_control
    jmp vq_put

; [RAX,RDX) disjoint from [RDI,RDI+RSI). RAX/RDX preserved.
vq_disjoint:
    test rsi,rsi
    jz .ok
    mov rcx,rdi
    add rcx,rsi
    jc .bad
    cmp rax,rcx
    jae .ok
    cmp rdi,rdx
    jb .bad
.ok:
    clc
    ret
.bad:
    stc
    ret
; Existing nonempty span vs metadata. Scratch is checked separately by callers.
vq_meta:
    mov rdi,r12
    mov esi,640
    call vq_disjoint
    jc .bad
    mov rdi,r14
    mov esi,96
    call vq_disjoint
    jc .bad
    mov rdi,r13
    ; Derive input length from the operation, independent of nested call depth.
    mov esi,64
    test ebp,ebp
    jnz .not_init
    mov esi,96
.not_init:
    cmp ebp,1
    jne .not_begin
    mov esi,128
.not_begin:
    cmp ebp,2
    jne .not_step
    xor esi,esi
.not_step:
    cmp ebp,3
    jne .input_ok
    mov esi,192
.input_ok:
    call vq_disjoint
    ret
.bad:
    stc
    ret
; RAX=pixel pointer,RDX=capacity; returned end in RDX, pointer preserved.
vq_pixel_span:
    test rax,rax
    jz .bad
    cmp rdx,[r12+48]
    jb .bad
    cmp rdx,921600
    ja .bad
    add rdx,rax
    jc .bad
    call vq_meta
    jc .bad
    mov rdi,r15
    xor esi,esi
    test rdi,rdi
    jz .skip
    mov esi,256
.skip:
    call vq_disjoint
    ret
.bad:
    stc
    ret

vq_init:
    cmp dword [r13],1
    jne .bad_shape
    cmp dword [r13+4],96
    jne .bad_shape
    mov rax,[r13+8]
    test rax,rax
    jz .bad_shape
    cmp qword [r13+16],0
    je .bad_shape
    cmp qword [r13+24],0
    je .bad_shape
    cmp dword [r13+32],0
    je .bad_shape
    cmp dword [r13+44],SSP_FMT_BGRX
    jne .bad_shape
    jmp .bad_shape_ok
.bad_shape:
    jmp vq_bad
.bad_shape_ok:
    mov eax,[r13+36]
    dec eax
    cmp eax,639
    ja .bad_shape
    inc eax
    shl eax,2
    mov r8d,eax
    mov ecx,[r13+40]
    dec ecx
    cmp ecx,359
    ja .bad_shape
    inc ecx
    imul r8,rcx
    ; Context wholly zero, prior to any initialization write.
    xor ecx,ecx
.zero:
    cmp qword [r12+rcx],0
    jne .bad_shape
    add ecx,8
    cmp ecx,640
    jb .zero
    mov ebx,48
.span:
    mov rax,[r13+rbx]
    mov rdx,[r13+rbx+8]
    test rax,rax
    jz vq_bad
    cmp rdx,r8
    jb vq_bad
    cmp rdx,921600
    ja vq_bad
    add rdx,rax
    jc vq_bad
    call vq_meta
    jc vq_bad
    mov r10d,48
.pair:
    cmp r10d,ebx
    je .skip
    mov rdi,[r13+r10]
    mov rsi,[r13+r10+8]
    call vq_disjoint
    jc vq_bad
.skip:
    add r10d,16
    cmp r10d,96
    jb .pair
    add ebx,16
    cmp ebx,96
    jb .span
    mov dword [r12],VQ_MAGIC
    mov dword [r12+4],1
    mov ecx,8
.header:
    mov rax,[r13+rcx]
    mov [r12+rcx],rax
    add ecx,8
    cmp ecx,40
    jb .header
    mov eax,[r13+40]
    mov [r12+40],eax
    mov eax,[r13+36]
    shl eax,2
    mov [r12+44],eax
    mov [r12+48],r8
    lea rbx,[r12+160]
    mov ecx,48
.bind:
    mov rax,[r13+rcx]
    mov [rbx+96],rax
    mov rax,[r13+rcx+8]
    mov [rbx+104],rax
    add rbx,160
    add ecx,16
    cmp ecx,96
    jb .bind
    mov eax,12
    jmp vq_emit_none

vq_begin:
    cmp dword [r13],1
    jne .bad_frame
    cmp dword [r13+4],128
    jne .bad_frame
    lea rdi,[r13+16]
    call vq_identity
    jc .bad_frame
    cmp dword [r13+12],SSP_FMT_BGRX
    jne .bad_frame
    mov eax,[r13+8]
    dec eax
    cmp eax,1
    ja .bad_frame
    mov eax,[r13+64]
    cmp eax,[r12+36]
    jne .bad_frame
    mov eax,[r13+68]
    cmp eax,[r12+40]
    jne .bad_frame
    mov rax,[r13+120]
    mov ecx,[r13+76]
    or rax,rcx
    jnz .bad_frame
    cmp qword [r13+112],0
    je .bad_frame
    jmp .bad_frame_ok
.bad_frame:
    jmp vq_bad
.bad_frame_ok:
    mov rax,[r13+40]
    test rax,rax
    jz .bad_frame
    cmp rax,[r12+56]
    jbe .bad_frame
    cmp rax,[r13+104]
    jne .bad_frame
    mov rax,[r13+88]
    test rax,rax
    jle .bad_frame
    add rax,[r13+80]
    jo .bad_frame
    mov rax,[r13+96]
    test eax,eax
    jz .bad_frame
    shr rax,32
    test eax,eax
    jz .bad_frame
    cmp qword [r12+56],0
    je .first
    mov rax,[r13+80]
    cmp rax,[r12+64]
    jl vq_bad
    mov rax,[r13+96]
    cmp rax,[r12+72]
    jne vq_bad
.first:
    mov ecx,[r13+72]
    cmp ecx,[r12+44]
    jb .bad_source
    mov eax,[r12+40]
    dec eax
    imul rax,rcx
    mov ecx,[r12+44]
    add rax,rcx
    cmp rax,[r13+56]
    ja .bad_source
    jmp .bad_source_ok
.bad_source:
    jmp vq_bad
.bad_source_ok:
    mov rax,[r13+48]
    mov rdx,[r13+56]
    test rax,rax
    jz .bad_source
    cmp rdx,921600
    ja .bad_source
    add rdx,rax
    jc .bad_source
    call vq_meta
    jc .bad_source
    lea rbx,[r12+160]
.source_disjoint:
    mov rdi,[rbx+96]
    mov rsi,[rbx+104]
    call vq_disjoint
    jc .bad_source
    add rbx,160
    lea rcx,[r12+640]
    cmp rbx,rcx
    jb .source_disjoint
    cmp dword [r12+4],2
    ja vq_bad
    cmp qword [r12+88],0
    jne vq_backpressure
    lea rbx,[r12+160]
    xor r10d,r10d
.find:
    cmp dword [rbx],1
    je vq_backpressure
    cmp dword [rbx],0
    jne .next
    test r10,r10
    jnz .next
    mov r10,rbx
.next:
    add rbx,160
    lea rcx,[r12+640]
    cmp rbx,rcx
    jb .find
    mov rbx,r10
    test rbx,rbx
    jz vq_backpressure
    cmp qword [rbx+8],-1
    je vq_bad
    inc qword [rbx+8]
    mov dword [rbx],1
    mov rax,[r13+24]
    mov [rbx+16],rax
    mov rax,[r13+40]
    mov [rbx+24],rax
    mov [r12+56],rax
    mov [rbx+136],rax
    mov rax,[r13+80]
    mov [rbx+32],rax
    mov [r12+64],rax
    mov rax,[r13+88]
    mov [rbx+40],rax
    mov rax,[r13+96]
    mov [rbx+48],rax
    mov [r12+72],rax
    mov rax,[r13+48]
    mov [rbx+56],rax
    mov rax,[r13+56]
    mov [rbx+64],rax
    mov eax,[r13+8]
    mov [rbx+72],eax
    mov eax,[r13+72]
    mov [rbx+76],eax
    mov qword [rbx+80],0
    mov rax,[r13+112]
    mov [rbx+88],rax
    mov rax,[r12+24]
    mov [rbx+120],rax
    mov rax,[r12+8]
    mov [rbx+128],rax
    mov eax,1
    jmp vq_emit

vq_identity:
    mov rax,[rdi]
    cmp rax,[r12+8]
    jne .bad
    mov rax,[rdi+8]
    cmp rax,[r12+16]
    jne .bad
    mov rax,[rdi+16]
    cmp rax,[r12+24]
    jne .bad
    clc
    ret
.bad:
    stc
    ret

vq_step:
    mov eax,[r12+4]
    cmp eax,2
    jbe .find_start
    cmp eax,6
    jne vq_bad
.find_start:
    lea rbx,[r12+160]
.find:
    cmp dword [rbx],1
    je .found
    add rbx,160
    lea rcx,[r12+640]
    cmp rbx,rcx
    jb .find
    mov eax,3
    jmp vq_emit_none
.found:
    ; The third slot may be WRITING while two READY await presentation.
    ; Keep that capacity invariant before touching its next pixel row.
    cmp r9d,2
    jae vq_backpressure
    mov rax,[rbx+80]
    cmp rax,[r12+48]
    jae vq_bad
    xor edx,edx
    div dword [r12+44]
    test edx,edx
    jnz vq_bad
    mov ecx,[rbx+76]
    imul rax,rcx
    add rax,[rbx+56]
    jc vq_bad
    mov rsi,rax
    mov rdi,[rbx+96]
    add rdi,[rbx+80]
    jc vq_bad
    cmp dword [rbx+72],1
    jne .raw
    sub rsp,64
    mov [rsp],rsi
    mov eax,[r12+44]
    mov [rsp+8],rax
    mov [rsp+16],rdi
    mov [rsp+24],rax
    mov eax,[r12+36]
    mov [rsp+32],eax
    mov dword [rsp+36],1
    mov eax,[r12+44]
    mov [rsp+40],eax
    mov [rsp+44],eax
    mov dword [rsp+48],SSP_FMT_BGRX
    mov dword [rsp+52],0
    mov rdi,rsp
    call img_video_rgba_to_bgrx
    add rsp,64
    test rax,rax
    jnz vq_bad
    jmp .copied
.raw:
    mov ecx,[r12+36]
.pixel:
    mov eax,[rsi]
    or eax,0xFF000000
    mov [rdi],eax
    add rsi,4
    add rdi,4
    dec ecx
    jnz .pixel
.copied:
    mov eax,[r12+44]
    add [rbx+80],rax
    mov eax,1
    mov rcx,[rbx+80]
    cmp rcx,[r12+48]
    jb vq_emit
    sfence                         ; complete pixel writes precede READY
    mov dword [rbx],2
    mov rax,[rbx+88]
    mov [r12+88],rax
    mov eax,2
    jmp vq_emit

vq_present:
    mov eax,[r12+4]
    cmp eax,2
    jbe .active
    cmp eax,6
    jne .freeze
.active:
    mov rax,[r13+16]
    cmp rax,[r12+8]
    jne vq_bad
    mov rax,[r13+24]
    cmp rax,[r12+16]
    jne vq_bad
    xor r8d,r8d
    xor r9d,r9d
    lea rbx,[r12+160]
.ready:
    cmp dword [rbx],2
    jne .next
    test r8,r8
    jz .first
    mov r9,rbx
    jmp .next
.first:
    mov r8,rbx
.next:
    add rbx,160
    lea rax,[r12+640]
    cmp rbx,rax
    jb .ready
    test r8,r8
    jz .empty
    test r9,r9
    jz .ordered
    mov rax,[r8+24]
    cmp rax,[r9+24]
    jb .ordered
    xchg r8,r9
.ordered:
    mov [rsp],r8
    mov [rsp+8],r9
    mov dword [rsp+16],0
    mov dword [rsp+20],0
    mov rbx,r8
    call vq_decision
    cmp rax,-1
    je vq_bad
    mov [rsp+16],eax
    cmp eax,1
    je .hold
    cmp eax,4
    je .freeze
    mov rbx,[rsp+8]
    test rbx,rbx
    jz .decided
    call vq_decision
    cmp rax,-1
    je vq_bad
    mov [rsp+20],eax
.decided:
    xor ebx,ebx
    xor r8d,r8d                  ; late drops
    xor r9d,r9d                  ; superseded
    cmp dword [rsp+16],3
    sete r8b
    cmp dword [rsp+16],2
    jne .second
    mov rbx,[rsp]
.second:
    cmp dword [rsp+20],3
    jne .second_show
    inc r8d
.second_show:
    cmp dword [rsp+20],2
    jne .preflight
    test rbx,rbx
    setnz r9b
    mov rbx,[rsp+8]
.preflight:
    mov rax,[r12+120]
    add rax,r8
    jc vq_bad
    mov rax,[r12+128]
    add rax,r9
    jc vq_bad
    test rbx,rbx
    jz .commit
    cmp qword [r12+112],-1
    je vq_bad
    cmp qword [r12+80],-1
    je vq_bad
    lea r10,[r12+160]
.borrow:
    cmp dword [r10+4],0
    jne vq_backpressure
    add r10,160
    lea rax,[r12+640]
    cmp r10,rax
    jb .borrow
.commit:
    add [r12+120],r8
    add [r12+128],r9
    mov r10,[rsp]
    cmp dword [rsp+16],3
    je .drop_first
    cmp r9d,0
    je .drop_second
.drop_first:
    call vq_retire_slot
.drop_second:
    mov r10,[rsp+8]
    cmp dword [rsp+20],3
    jne .swap
    call vq_retire_slot
.swap:
    test rbx,rbx
    jz .dropped
    lea r10,[r12+160]
.old_front:
    cmp dword [r10],3
    jne .next_front
    call vq_retire_slot
.next_front:
    add r10,160
    lea rax,[r12+640]
    cmp r10,rax
    jb .old_front
    inc qword [r12+112]
    inc qword [r12+80]
    mov rax,[r12+80]
    mov [rbx+112],rax
    mov dword [rbx+4],1
    mov dword [rbx],3
    cmp dword [r12+4],6
    je .shown
    mov dword [r12+4],2
.shown:
    mov eax,6
    jmp vq_emit
.dropped:
    mov eax,7
    jmp vq_emit_none
.hold:
    mov eax,5
    jmp vq_emit_none
.freeze:
    mov eax,8
    jmp vq_emit_none
.empty:
    mov eax,3
    jmp vq_emit_none

; Actual S2a, caller snapshot unchanged. Native stack includes this CALL chain.
vq_decision:
    xor ecx,ecx
.copy:
    mov rax,[r13+rcx]
    mov [r15+rcx],rax
    add ecx,8
    cmp ecx,192
    jb .copy
    mov rax,[rbx+32]
    mov [r15+128],rax
    mov rax,[rbx+40]
    mov [r15+136],rax
    mov eax,[rbx+48]
    mov [r15+144],rax
    mov eax,[rbx+52]
    mov [r15+152],rax
    mov rax,[rbx+24]
    mov [r15+160],rax
    mov rax,[rbx+136]
    mov [r15+168],rax
    mov rdi,r15
    lea rsi,[r15+192]
    call media_av_clock_decide
    test rax,rax
    jnz .out
    mov rax,[r15+192]
.out:
    ret

vq_put:
    cmp dword [r13],1
    jne .bad_token
    cmp dword [r13+4],64
    jne .bad_token
    cmp dword [r13+60],0
    jne .bad_token
    mov eax,[r13+56]
    cmp eax,3
    jae .bad_token
    imul eax,160
    lea rbx,[r12+rax+160]
    cmp dword [rbx+4],1
    jne .bad_token
    mov rax,[r13+8]
    cmp rax,[rbx+128]
    jne .bad_token
    jmp .bad_token_ok
.bad_token:
    jmp vq_bad
.bad_token_ok:
    mov rax,[r13+16]
    cmp rax,[rbx+16]
    jne .bad_token
    mov rax,[r13+24]
    cmp rax,[rbx+120]
    jne .bad_token
    mov rax,[r13+32]
    cmp rax,[rbx+24]
    jne .bad_token
    mov rax,[r13+40]
    cmp rax,[rbx+8]
    jne .bad_token
    mov rax,[r13+48]
    cmp rax,[rbx+112]
    jne .bad_token
    mov dword [rbx+4],0
    mov qword [rbx+112],0
    cmp dword [rbx],4
    jne .drain
    mov r10,rbx
    call vq_retire_slot
.drain:
    call vq_drain
    jmp vq_emit_none

vq_control:
    cmp dword [r13],1
    jne .bad_control
    cmp dword [r13+4],64
    jne .bad_control
    lea rdi,[r13+16]
    call vq_identity
    jc .bad_control
    mov eax,[r13+12]
    or rax,[r13+56]
    jnz .bad_control
    jmp .bad_control_ok
.bad_control:
    jmp vq_bad
.bad_control_ok:
    mov rax,[r13+40]
    test rax,rax
    jz .bad_control
    cmp rax,[r12+104]
    jbe .bad_control
    mov r8d,[r13+8]
    mov eax,r8d
    dec eax
    cmp eax,7
    ja .bad_control
    cmp r8d,6
    je .source_ack
    cmp dword [r12+4],7
    je vq_bad
    cmp r8d,8
    je .pause_keep
    cmp r8d,3
    je .seek
    cmp qword [r13+48],0
    jne vq_bad
    cmp r8d,4
    je .preflight
    mov eax,[r12+4]
    cmp r8d,2
    jne .not_resume
    cmp eax,3
    jne vq_bad
    jmp .simple
.not_resume:
    cmp eax,4
    je vq_bad
    cmp eax,5
    je vq_bad
    cmp r8d,1
    jne .phase_not_pause
    cmp eax,3
    je vq_bad
.phase_not_pause:
    cmp r8d,5
    jne .preflight
    cmp eax,2
    ja vq_bad
    jmp .simple
 ; Opt-in lossless pause. Existing PAUSE1 still retires queued work.
.pause_keep:
    cmp qword [r13+48],0
    jne vq_bad
    mov eax,[r12+4]
    cmp eax,1
    je .keep_check
    cmp eax,2
    je .keep_check
    cmp eax,6
    jne vq_bad
.keep_check:
    lea r10,[r12+160]
.keep_slot:
    cmp dword [r10],1
    je vq_bad                       ; no partial source copy may be paused
    add r10,160
    lea rax,[r12+640]
    cmp r10,rax
    jb .keep_slot
    mov rax,[r13+40]
    mov [r12+104],rax
    mov dword [r12+4],3
    mov eax,9
    jmp vq_emit_none
.seek:
    mov eax,[r12+4]
    cmp eax,4
    je vq_bad
    cmp eax,5
    je vq_bad
    mov rax,[r12+16]
    inc rax
    jz vq_bad
    cmp rax,[r13+48]
    jne vq_bad
.preflight:
    xor r9d,r9d
    lea r10,[r12+160]
.count:
    mov eax,[r10]
    cmp eax,1
    je .count_it
    cmp r8d,7
    je .count_next
    cmp eax,2
    jne .count_next
.count_it:
    inc r9d
.count_next:
    add r10,160
    lea rax,[r12+640]
    cmp r10,rax
    jb .count
    mov rax,[r12+136]
    add rax,r9
    jc vq_bad
    add [r12+136],r9
    mov rax,[r13+40]
    mov [r12+104],rax
    lea r10,[r12+160]
.retire:
    mov eax,[r10]
    cmp eax,1
    jne .not_writing
    mov rax,[r10+88]
    mov [r12+88],rax
    jmp .retire_it
.not_writing:
    cmp r8d,7
    je .retire_next
    cmp eax,2
    je .retire_it
    cmp r8d,1
    je .retire_next
    cmp eax,3
    je .retire_it
    jmp .retire_next
.retire_it:
    call vq_retire_slot
.retire_next:
    add r10,160
    lea rax,[r12+640]
    cmp r10,rax
    jb .retire
    cmp r8d,1
    jne .not_pause
    mov dword [r12+4],3
    mov eax,9
    jmp vq_emit_none
.not_pause:
    cmp r8d,7
    je .canceled
    cmp r8d,3
    jne .close
    mov rax,[r13+48]
    mov [r12+96],rax
    mov dword [r12+4],4
    jmp .drain
.close:
    mov dword [r12+4],5
.drain:
    call vq_drain
    jmp vq_emit_none
.canceled:
    mov eax,3
    jmp vq_emit_none
.simple:
    mov rax,[r13+40]
    mov [r12+104],rax
    mov dword [r12+4],1
    mov eax,12
    cmp r8d,2
    je vq_emit_none
    mov dword [r12+4],6
    mov eax,14
    jmp vq_emit_none
.source_ack:
    mov rax,[r13+48]
    test rax,rax
    jz vq_bad
    cmp rax,[r12+88]
    jne vq_bad
    mov qword [r12+88],0
    lea r10,[r12+160]
.ack_slots:
    cmp [r10+88],rax
    jne .ack_next
    mov qword [r10+88],0
    cmp dword [r10],4
    jne .ack_next
    call vq_retire_slot
    mov rax,[r13+48]
.ack_next:
    add r10,160
    lea rcx,[r12+640]
    cmp r10,rcx
    jb .ack_slots
    mov rax,[r13+40]
    mov [r12+104],rax
    call vq_drain
    cmp eax,3
    jne vq_emit_none
    mov eax,13
    jmp vq_emit_none

; Cannot fail. Ref/source lease retain storage; generations never reset.
vq_retire_slot:
    mov dword [r10],4
    cmp dword [r10+4],0
    jne .out
    cmp qword [r10+88],0
    jne .out
    mov dword [r10],0
.out:
    ret
vq_drain:
    mov eax,3
    mov ecx,[r12+4]
    cmp ecx,4
    je .pending
    cmp ecx,5
    jne .out
.pending:
    mov eax,10
    cmp qword [r12+88],0
    jne .out
    lea r10,[r12+160]
.refs:
    cmp dword [r10+4],0
    jne .out
    add r10,160
    lea rdx,[r12+640]
    cmp r10,rdx
    jb .refs
    lea r10,[r12+160]
.free:
    mov dword [r10],0
    add r10,160
    cmp r10,rdx
    jb .free
    mov dword [r12+4],7
    mov eax,11
    cmp ecx,5
    je .out
    mov rdx,[r12+96]
    mov [r12+16],rdx
    mov qword [r12+96],0
    mov qword [r12+56],0
    mov qword [r12+64],0
    mov qword [r12+72],0
    mov dword [r12+4],1
    mov eax,12
.out:
    ret

vq_backpressure:
    mov eax,4
vq_emit_none:
    xor ebx,ebx
vq_emit:
    mov r11d,eax
    xor eax,eax
    mov ecx,0
.zero:
    mov [r14+rcx],rax
    add ecx,8
    cmp ecx,96
    jb .zero
    mov dword [r14],1
    mov [r14+4],r11d
    mov rax,[r12+8]
    mov [r14+16],rax
    mov rax,[r12+16]
    mov [r14+24],rax
    mov rax,[r12+24]
    mov [r14+32],rax
    mov rax,[r12+88]
    mov [r14+88],rax
    mov dword [r14+84],-1
    test rbx,rbx
    jz .done
    mov rax,[rbx+24]
    mov [r14+40],rax
    mov rax,[rbx+8]
    mov [r14+48],rax
    mov rax,[rbx+112]
    mov [r14+56],rax
    mov rax,[rbx+96]
    mov [r14+64],rax
    mov rax,[r12+48]
    mov [r14+72],rax
    mov eax,[rbx+80]
    mov [r14+80],eax
    mov rax,rbx
    sub rax,r12
    sub rax,160
    xor edx,edx
    mov ecx,160
    div ecx
    mov [r14+84],eax
.done:
    xor eax,eax
    jmp vq_out
vq_bad:
    mov rax,-1
vq_out:
    add rsp,32
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
