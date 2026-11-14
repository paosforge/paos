;; MODULE gui/img/img_jpeg_rotate
;; LAYER 6
;; EXPORTS img_jpeg_rotate
;; IMPORTS gui/img/img_exif_locate, gui/img/img_exif_info
;; CAPS
;; OWNER saga:gui_image_pipeline
;
; Lossless JPEG display rotation, immutable caller-memory service. No DCT,
; entropy, frame or pixel change: compose EXIF orientation with clockwise
; quarter_turns0..3, including mirrored camera orientations. The caller/viewer
; must honour EXIF. Stored frame dimensions stay unchanged; displayed dimensions
; swap on odd rotations. This is not JPEG coefficient rotation or pixel decode.
; LE request48: src:u64@0,len:u64@8,dst:u64@16,cap:u64@24,turns:u32@32,
; reserved:u32@36=0,reserved:u64@40=0. Source8..33554432. Exact output must
; fit cap and32MiB. Full nonwrapping src/dst and dst/request48 disjoint;
; read-only src/request alias allowed. Caller maps/stabilizes all spans.
; EAX0/RDXoutput_len; EAX2/RDX0 refusal with NO output writes.
;
; First validate complete framing with img_exif_locate and known TIFF fields
; with img_exif_info (their subsets apply, including <=256 IFD entries). Patch
; an existing orientation in a full copy. If absent, append a replacement IFD0
; (<=256 entries) after the old TIFF, preserving original entry bytes, external
; offsets and next-IFD word; update header offset and APP1 length. New orientation
; is inserted before the first greater tag, maintaining already-sorted order.
; Old IFD0 remains unreferenced. TIFF growth must fit JPEG APP1 (<=65527B TIFF).
; If EXIF absent, add a26B little-endian TIFF in36B APP1 after leading APP0s.
; Even turns0 publishes an explicit orientation. Other metadata, including GPS,
; remains: this is NOT the default share/location stripping operation.
; Unknown TIFF values/links remain opaque; no new validity/authority follows.
; No allocation/free, globals, IO, FP/SIMD, ownership transfer/retained pointers.
; Caller owns file/display/share authority, lifetime, serialization and saving.
; Full64 nonvolatiles and flags/DF preserved.448B initialized/wiped private
; frame+56B saves+8B call+488B deepest TIFF=>1000B below caller return.
; Creator: rc-ai-claude running on OpenAI Codex.
; Orientation: CIPA DC-X008-2019-E (same as existing native image pipeline).

img_jpeg_rotate:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,448
    mov rbp,rsp
    cld
    mov r11,rdi
    mov rdi,rbp
    xor eax,eax
    mov ecx,56
    rep stosq
    test r11,r11
    jz .bad
    mov rax,r11
    add rax,48
    jc .bad
    mov r12,[r11]
    mov r13,[r11+8]
    mov rbx,[r11+16]
    mov rcx,[r11+24]
    test r12,r12
    jz .bad
    test rbx,rbx
    jz .bad
    cmp r13,8
    jb .bad
    cmp r13,33554432
    ja .bad
    cmp dword [r11+32],3
    ja .bad
    cmp dword [r11+36],0
    jne .bad
    cmp qword [r11+40],0
    jne .bad
    mov rax,r12
    add rax,r13
    jc .bad
    mov rdx,rbx
    add rdx,rcx
    jc .bad
    cmp rbx,rax
    jae .source_disjoint
    cmp r12,rdx
    jb .bad
.source_disjoint:
    cmp r11,rdx
    jae .request_disjoint
    lea rax,[r11+48]
    cmp rbx,rax
    jb .bad
.request_disjoint:
    cmp word [r12],0xd8ff
    jne .bad
    mov [rbp+320],rcx
    mov eax,[r11+32]
    mov [rbp+328],rax
    mov [rbp],r12
    mov [rbp+8],r13
    lea rax,[rbp+48]
    mov [rbp+16],rax
    mov qword [rbp+24],32
    mov rdi,rbp
    call img_exif_locate
    cmp eax,2
    je .bad
    test eax,eax
    jnz .no_exif
    mov rax,[rbp+56]
    mov [rbp+336],rax
    lea r14,[r12+rax]
    mov rax,[rbp+64]
    mov [rbp+344],rax
    mov [rbp],r14
    mov [rbp+8],rax
    lea rax,[rbp+80]
    mov [rbp+16],rax
    mov qword [rbp+24],240
    mov rdi,rbp
    call img_exif_info
    test eax,eax
    jnz .bad
    mov eax,[rbp+88]
    mov [rbp+384],eax
    cmp word [r14],0x4949
    je .read_ifd
    mov dword [rbp+352],1
.read_ifd:
    lea rsi,[r14+4]
    call .u32
    mov [rbp+360],rax
    lea rsi,[r14+rax]
    call .u16
    mov [rbp+368],rax
    mov r15d,eax
    add rsi,2
.find_orientation:
    test r15d,r15d
    jz .append_ifd
    call .u16
    cmp eax,274
    je .patch_orientation
    add rsi,12
    dec r15d
    jmp .find_orientation
.patch_orientation:
    sub rsi,r14
    add rsi,8
    mov [rbp+376],rsi
    mov [rbp+408],r13
    jmp .compose
.append_ifd:
    cmp qword [rbp+368],256
    jae .bad
    mov rax,[rbp+344]
    inc rax
    and rax,-2
    mov [rbp+392],rax
    mov rcx,[rbp+368]
    inc rcx
    imul rcx,12
    lea rax,[rax+rcx+6]
    cmp rax,65527
    ja .bad
    mov [rbp+400],rax
    sub rax,[rbp+344]
    add rax,r13
    mov [rbp+408],rax
    mov dword [rbp+424],1
    jmp .compose
.no_exif:
    mov dword [rbp+384],1
    mov dword [rbp+424],2
    lea rax,[r13+36]
    mov [rbp+408],rax
    ; Full JPEG framing already validated. Keep leading APP0/JFIF first,
    ; retaining fill bytes before any subsequent marker with that marker.
    mov r15d,2
.leading_app0:
    mov r8,r15
.skip_fill:
    inc r8
    cmp byte [r12+r8],0xff
    je .skip_fill
    cmp byte [r12+r8],0xe0
    jne .insertion
    movzx eax,word [r12+r8+1]
    rol ax,8
    lea r15,[r8+rax+1]
    jmp .leading_app0
.insertion:
    mov [rbp+416],r15
.compose:
    mov rax,[rbp+408]
    cmp rax,33554432
    ja .bad
    cmp rax,[rbp+320]
    ja .bad
    mov eax,[rbp+384]
    mov ecx,[rbp+328]
.turn:
    test ecx,ecx
    jz .orientation_ready
    ; C4 acting on EXIF's eight D4 orientations. No writable lookup table.
    dec eax
    mov edx,eax
    shl edx,3
    push rcx
    mov ecx,edx
    mov rdx,0x0104030205080706
    shr rdx,cl
    movzx eax,dl
    pop rcx
    dec ecx
    jmp .turn
.orientation_ready:
    mov [rbp+384],eax
    ; All refusals above. Only now publish output to caller-owned destination.
    cmp dword [rbp+424],2
    je .write_new
    cmp dword [rbp+424],1
    je .write_append
    mov rdi,rbx
    mov rsi,r12
    mov rcx,r13
    rep movsb
    mov rdi,[rbp+336]
    add rdi,[rbp+376]
    add rdi,rbx
    mov eax,[rbp+384]
    call .put16
    jmp .good
.write_append:
    mov rdi,rbx
    mov rsi,r12
    mov rcx,[rbp+336]
    add rcx,[rbp+344]
    rep movsb
    test qword [rbp+344],1
    jz .aligned
    mov byte [rdi],0
    inc rdi
.aligned:
    mov eax,[rbp+368]
    inc eax
    call .put16
    mov rsi,[rbp+360]
    lea rsi,[r14+rsi+2]
    mov r9,[rbp+368]
    xor r10d,r10d
.copy_entries:
    test r9,r9
    jz .entries_done
    test r10d,r10d
    jnz .copy_entry
    call .u16
    cmp eax,274
    jb .copy_entry
    call .orientation_entry
    mov r10d,1
.copy_entry:
    mov ecx,12
    rep movsb
    dec r9
    jmp .copy_entries
.entries_done:
    test r10d,r10d
    jnz .copy_next
    call .orientation_entry
.copy_next:
    movsd                         ; preserve opaque next-IFD offset
    mov rsi,[rbp+336]
    add rsi,[rbp+344]
    mov rcx,r13
    sub rcx,rsi
    add rsi,r12
    rep movsb                     ; all remaining segments/scans identical
    mov rax,[rbp+336]
    lea rdi,[rbx+rax+4]
    mov eax,[rbp+392]
    call .put32
    mov rax,[rbp+336]
    lea rdi,[rbx+rax-8]
    mov eax,[rbp+400]
    add eax,8                      ; length includes length word + Exif\0\0
    rol ax,8                       ; JPEG length is always big endian
    mov [rdi],ax
    jmp .good
.write_new:
    mov rdi,rbx
    mov rsi,r12
    mov rcx,[rbp+416]
    rep movsb
    mov dword [rdi],0x2200e1ff
    mov dword [rdi+4],0x66697845
    mov word [rdi+8],0
    mov dword [rdi+10],0x002a4949
    mov dword [rdi+14],8
    mov word [rdi+18],1
    add rdi,20
    call .orientation_entry
    mov dword [rdi],0
    add rdi,4
    mov rcx,r13
    sub rcx,[rbp+416]
    rep movsb
.good:
    mov rdx,[rbp+408]
    xor eax,eax
    jmp .done
.bad:
    mov eax,2
    xor edx,edx
.done:
    mov r8d,eax
    mov rdi,rbp
    xor eax,eax
    mov ecx,56
    rep stosq
    mov eax,r8d
    add rsp,448
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    popfq
    ret

; Private endian helpers. RSI remains unchanged for peeks; RDI advances on put.
.u16:
    movzx eax,word [rsi]
    cmp dword [rbp+352],0
    je .u16_done
    rol ax,8
.u16_done:
    ret
.u32:
    mov eax,[rsi]
    cmp dword [rbp+352],0
    je .u32_done
    bswap eax
.u32_done:
    ret
.put16:
    cmp dword [rbp+352],0
    je .put16_le
    rol ax,8
.put16_le:
    stosw
    ret
.put32:
    cmp dword [rbp+352],0
    je .put32_le
    bswap eax
.put32_le:
    stosd
    ret
.orientation_entry:
    mov eax,274
    call .put16
    mov eax,3
    call .put16
    mov eax,1
    call .put32
    mov eax,[rbp+384]
    call .put16
    xor eax,eax
    call .put16
    ret
