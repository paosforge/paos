;; MODULE gui/img/img_mjpeg_frame
;; LAYER 6
;; EXPORTS img_mjpeg_to_bgrx
;; IMPORTS gui/img/img_core, gui/img/img_video_bridge
;; CAPS
;; OWNER saga:gui_image_pipeline

; Native, synchronous MJPEG frame adapter. RDI -> immutable 48-byte request:
; +0 encoded pointer, +8 exact encoded length, +16 destination pointer,
; +24 destination capacity (u64); +32 width, +36 height, +40 destination
; stride, +44 reserved=0 (u32). RAX=0 success, -1 refusal. Success writes
; only width*4 bytes per row as BGRX (opaque X); refusal never writes dst.
; Preserves RBX/RBP/R12..R15, RSP and DF. No guest pointers or publication.
;
; Caller owns mapped, truthful, disjoint storage and an immutable encoded
; lease for this entire call. The foreground image codec must be serialized;
; an outstanding image allocation is refused without disturbing it. Reuses
; the real JPEG parser/decoder and image heap release; no new codec. The
; independently owned destination can then enter video_player_frame(kind2)
; and must remain leased until that owner's SOURCE_RELEASE_ACK.
; AVI bounds: <=640x360, packet <=512KiB. Full decode is synchronous, not a
; per-poll scheduler guarantee. Heap-tip contention retains img_core's honest
; leak behavior; this adapter does not claim a new allocator or heap margin.
img_mjpeg_to_bgrx:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 64                    ; img_video_frame, plus alignment
    cld
    mov r12, rdi
    test rdi, rdi
    jz .bad
    mov rax, rdi
    add rax, 48
    jc .bad
    cmp dword [rdi+44], 0
    jne .bad
    cmp qword [rel img_active_out], 0
    jne .bad
    cmp qword [rel img_active_src], 0
    jne .bad
    cmp qword [rel img_alloc_size], 0
    jne .bad
    mov r13, [rdi]
    mov r14, [rdi+8]
    test r13, r13
    jz .bad
    test r14, r14
    jz .bad
    cmp r14, 524288
    ja .bad
    mov r8, r13
    add r8, r14                     ; encoded exclusive end
    jc .bad
    mov ecx, [rdi+32]
    mov edx, [rdi+36]
    test ecx, ecx
    jz .bad
    test edx, edx
    jz .bad
    cmp ecx, 640
    ja .bad
    cmp edx, 360
    ja .bad
    mov [rsp+32], ecx
    mov [rsp+36], edx
    shl ecx, 2
    mov [rsp+40], ecx               ; decoded RGBA is packed
    cmp [rdi+40], ecx
    jb .bad
    mov r9d, [rdi+40]
    mov [rsp+44], r9d
    dec edx
    imul rdx, r9
    add rdx, rcx                    ; touched destination extent
    cmp rdx, [rdi+24]
    ja .bad
    mov r15, [rdi+16]
    test r15, r15
    jz .bad
    mov r10, r15
    add r10, [rdi+24]               ; full claimed span cannot wrap
    jc .bad
    ; Neither the encoded lease nor request can be overwritten by dst.
    cmp r15, r8
    jae .request_alias
    cmp r13, r10
    jb .bad
.request_alias:
    cmp r15, rax
    jae .admitted
    cmp r12, r10
    jb .bad
.admitted:
    mov [rsp+16], r15
    mov rax, [rdi+24]
    mov [rsp+24], rax
    mov dword [rsp+48], SSP_FMT_BGRX
    mov dword [rsp+52], 0
    mov rdi, r13
    mov rsi, r14
    call img_jpeg_probe_exact        ; includes actual EOI; AVI pad is external
    test eax, eax
    jnz .clear_bad
    cmp ecx, [rsp+32]
    jne .clear_bad
    cmp edx, [rsp+36]
    jne .clear_bad
    mov rdi, r13
    mov rsi, r14
    call img_jpeg_decode
    test eax, eax
    jnz .bad                        ; decoder retired its own failure
    ; Bind returned (Exif-oriented) dimensions before any destination write.
    cmp ecx, [rsp+32]
    jne .release_bad
    cmp edx, [rsp+36]
    jne .release_bad
    mov [rsp], rbx
    mov eax, ecx
    imul rax, rdx
    shl rax, 2
    mov [rsp+8], rax
    mov rdi, rsp
    call img_video_rgba_to_bgrx
    mov rbp, rax
    call img_output_release
    mov rax, rbp
    jmp .out
.release_bad:
    call img_output_release
    jmp .bad
.clear_bad:
    call img_refusal_clear
.bad:
    mov rax, -1
.out:
    add rsp, 64
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    popfq
    ret
