;; MODULE gui/img/img_metadata_info
;; LAYER 6
;; EXPORTS img_metadata_info
;; IMPORTS gui/img/img_exif_locate, gui/img/img_exif_info
;; CAPS
;; OWNER saga:gui_image_pipeline
;
; Native caller-memory JPEG/PNG metadata service, composing the actual locator
; and TIFF reader. Immutable LE request48: src:u64@0,len:u64@8,dst:u64@16,
; cap:u64@24,flags:u64@32(bit0=include typed GPS),reserved:u64@40=0.
; Mapped/stable borrowed source8..33554432; cap>=256. Full nonwrapping source
; and destination spans disjoint; full destination/request48 disjoint.
; Read-only source/request alias allowed. Caller retains original bytes.
; EAX0/RDX256: complete record; EAX2/RDX0: unsupported/invalid, no writes.
; Record256: version:u32@0=1,format:u32@4(3JPEG/2PNG),state:u32@8
; (0=no EXIF,1=parsed EXIF),reserved:u32@12=0, then existing240B
; img_exif_info record@16. No EXIF returns its version1/orientation1 defaults.
; By default clear typed GPS presence bit4 and all56B GPS fields, AFTER full
; TIFF known-tag validation. Flag1 retains valid typed GPS only; it grants no
; permission to disclose it. This does not strip/rewrite metadata in the image.
; Caller owns file/display/share authority, lifetime and serialization.
; Locator validates full framing/all PNG CRC; pixel validity and unsupported
; TIFF semantics remain outside this API. Both dependencies' subsets apply.
; No allocation/global writes/IO/FP/SIMD/retained pointers. Full64 nonvolatiles
; and flags incl DF preserved.448B frame initialized/wiped both paths;
; 56B saves +8B call +488B TIFF deepest =>1000B below caller return.
; Creator: rc-ai-claude running on OpenAI Codex.

img_metadata_info:
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
    cmp rcx,256
    jb .bad
    test qword [r11+32],-2
    jnz .bad
    cmp qword [r11+40],0
    jne .bad
    mov rax,r12
    add rax,r13
    jc .bad
    mov rdx,rbx
    add rdx,rcx
    jc .bad
    cmp rbx,rax
    jae .src_disjoint
    cmp r12,rdx
    jb .bad
.src_disjoint:
    cmp r11,rdx
    jae .req_disjoint
    lea rax,[r11+48]
    cmp rbx,rax
    jb .bad
.req_disjoint:
    mov [rbp+360],rbx
    mov rax,[r11+32]
    mov [rbp+416],rax
    mov dword [rbp+392],2
    cmp word [r12],0xd8ff
    jne .locate
    mov dword [rbp+392],3
.locate:
    mov [rbp],r12
    mov [rbp+8],r13
    lea rax,[rbp+48]
    mov [rbp+16],rax
    mov qword [rbp+24],32
    mov rdi,rbp
    call img_exif_locate
    test eax,eax
    jz .found
    cmp eax,1
    jne .bad
    mov dword [rbp+120],1       ; absent EXIF: typed version and orientation
    mov dword [rbp+128],1
    jmp .publish
.found:
    mov rax,[rbp+56]           ; borrowed TIFF offset, already span-validated
    add rax,[rbp]
    mov [rbp+80],rax
    mov rax,[rbp+64]
    mov [rbp+88],rax
    lea rax,[rbp+120]
    mov [rbp+96],rax
    mov qword [rbp+104],240
    lea rdi,[rbp+80]
    call img_exif_info
    test eax,eax
    jnz .bad
    mov dword [rbp+400],1
    test qword [rbp+416],1
    jnz .publish
    and dword [rbp+124],~16
    lea rdi,[rbp+304]          ; typed GPS offset184,56B total
    xor eax,eax
    mov ecx,7
    rep stosq
.publish:
    mov rdi,[rbp+360]
    mov dword [rdi],1
    mov eax,[rbp+392]
    mov [rdi+4],eax
    mov eax,[rbp+400]
    mov [rdi+8],eax
    mov dword [rdi+12],0
    add rdi,16
    lea rsi,[rbp+120]
    mov ecx,30
    rep movsq
    xor eax,eax
    mov edx,256
    jmp .done
.bad:
    mov eax,2
    xor edx,edx
.done:
    mov r8d,eax
    mov r9,rdx
    mov rdi,rbp
    xor eax,eax
    mov ecx,56
    rep stosq
    mov eax,r8d
    mov rdx,r9
    add rsp,448
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    popfq
    ret
