;; MODULE gui/img/img_exif_info
;; LAYER 6
;; EXPORTS img_exif_info
;; IMPORTS
;; CAPS
;; OWNER saga:gui_image_pipeline
;
; Bounded classic TIFF/EXIF metadata payload reader, not a container decoder.
; RDI=immutable LE request40: src:u64,len:u64,dst:u64,cap:u64,reserved:u64=0.
; src starts II/MM (not Exif\0\0); len8..65535. Caller maps/stabilizes all
; declared spans. Full nonwrapping src/dst disjoint, dst/request40 disjoint;
; read-only src/request alias allowed. cap>=240. EAX0/RDX240 or EAX2/RDX0.
; Success writes fixed zero-initialized LE record240; any refusal writes none:
; version:u32@0=1, flags:u32@4 (Make0,Model1,Original2,Modified3,GPS4,Orient5),
; orientation:u32@8(default1), reserved:u32@12=0; Make:ASCII64@16,
; Model:ASCII64@80, Original:ASCII20@144, Modified:ASCII20@164;
; latRef:u32@184(N1/S2),lonRef:u32@188(E1/W2),latDMS:6*u32@192,
; lonDMS:6*u32@216. Each DMS is exact (numerator,denominator)*3, no rounding.
;
; Visits IFD0 and its direct Exif/GPS IFDs, <=256 entries each, word aligned
; offsets>=8 and complete tables incl ignored next-IFD word. Reject overlapping
; visited tables, duplicate known fields/pointers, invalid known types/counts/
; values. Unknown tags, their external data and next/thumbnail/interop links
; are ignored. This is NOT validation of every TIFF tag or image raster.
; Make/Model ASCII1..64 incl terminating NUL, printable ASCII before NUL and
; zero tail only. Longer/UTF8 strings unsupported. Dates exactly20 bytes,
; Gregorian YYYY:MM:DD HH:MM:SS (year1..9999,second0..60), local camera time,
; no inferred UTC/zone. Fully blank dates (with or without colons) are absent;
; partial unknown dates unsupported. All four valid GPS fields required for
; presence; partial GPS is validated then omitted/zeroed. D<=90/180,M/S<60,
; denominators nonzero and exact D+M/60+S/3600<=limit (128-bit integer check).
; Location is returned only to caller; no publication or metadata-copy policy.
;
; No allocation/global writes/IO/FP/SIMD. O(768 entries+bounded strings).
; 416-byte zeroed private frame +56-byte save +max16-byte calls=488B stack.
; Full64 nonvolatiles and flags/DF preserved. Creator: rc-ai-claude on Codex.
; Tag reference: https://www.cipa.jp/std/documents/e/DC-X008-Translation-2019-E.pdf

img_exif_info:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,416
    mov rbp,rsp
    cld
    mov r11,rdi
    mov rdi,rbp
    xor eax,eax
    mov ecx,52
    rep stosq
    test r11,r11
    jz .bad
    mov rax,r11
    add rax,40
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
    cmp r13,65535
    ja .bad
    cmp rcx,240
    jb .bad
    cmp qword [r11+32],0
    jne .bad
    mov rax,r12
    add rax,r13
    jc .bad
    mov rdx,rbx
    add rdx,rcx
    jc .bad
    cmp rbx,rax
    jae .src_ok
    cmp r12,rdx
    jb .bad
.src_ok:
    cmp r11,rdx
    jae .req_ok
    lea rax,[r11+40]
    cmp rbx,rax
    jb .bad
.req_ok:
    mov [rbp+240],rbx
    mov dword [rbp],1
    mov dword [rbp+8],1
    cmp word [r12],0x4949
    je .order_ok
    cmp word [r12],0x4d4d
    jne .bad
    mov dword [rbp+264],1
.order_ok:
    lea rsi,[r12+2]
    call .u16
    cmp eax,42
    jne .bad
    lea rsi,[r12+4]
    call .u32
    mov [rbp+272],eax
.ifd:
    ; EAX is payload-relative IFD offset, kind@260=0/1/2.
    cmp eax,8
    jb .bad
    test al,1
    jnz .bad
    mov r14,rax
    add rax,2
    cmp rax,r13
    ja .bad
    lea rsi,[r12+r14]
    call .u16
    cmp eax,256
    ja .bad
    mov r15d,eax
    imul eax,12
    lea rax,[r14+rax+6]
    cmp rax,r13
    ja .bad
    cmp dword [rbp+260],0
    je .save_ifd0
    cmp r14,[rbp+304]
    jae .no_ifd0_overlap
    mov ecx,[rbp+272]
    cmp rcx,rax
    jb .bad
.no_ifd0_overlap:
    cmp dword [rbp+260],1
    je .save_exif
    cmp dword [rbp+276],0
    je .table_ok
    cmp r14,[rbp+312]
    jae .table_ok
    mov ecx,[rbp+276]
    cmp rcx,rax
    jb .bad
    jmp .table_ok
.save_ifd0:
    mov [rbp+304],rax
    jmp .table_ok
.save_exif:
    mov [rbp+312],rax
.table_ok:
    lea r14,[r12+r14+2]
.entry:
    test r15d,r15d
    jz .next_ifd
    mov rsi,r14
    call .u16
    mov ecx,[rbp+260]
    cmp ecx,2
    je .gps_tag
    test ecx,ecx
    jnz .exif_tag
    cmp eax,0x010f
    je .make
    cmp eax,0x0110
    je .model
    cmp eax,0x0112
    je .orient
    cmp eax,0x0132
    je .modified
    cmp eax,0x8769
    je .exif_pointer
    cmp eax,0x8825
    je .gps_pointer
    jmp .next_entry
.exif_tag:
    cmp eax,0x9003
    je .original
    jmp .next_entry
.gps_tag:
    cmp eax,1
    je .latref
    cmp eax,2
    je .lat
    cmp eax,3
    je .lonref
    cmp eax,4
    je .lon
    jmp .next_entry
.make:
    mov ebx,0
    mov edi,16
    jmp .camera
.model:
    mov ebx,1
    mov edi,80
.camera:
    call .once
    jc .bad
    mov [rbp+328],edi
    call .ascii_span
    jc .bad
    cmp ecx,64
    ja .bad
    lea rdi,[rbp+rdi]
    xor edx,edx
.ascii_copy:
    lodsb
    test al,al
    jz .ascii_zero
    test edx,edx
    jnz .bad
    cmp al,32
    jb .bad
    cmp al,126
    ja .bad
    jmp .ascii_store
.ascii_zero:
    mov edx,1
.ascii_store:
    stosb
    dec ecx
    jnz .ascii_copy
    test edx,edx
    jz .bad
    bts dword [rbp+4],ebx
    jmp .next_entry
.modified:
    mov ebx,3
    mov edi,164
    jmp .date
.original:
    mov ebx,2
    mov edi,144
.date:
    call .once
    jc .bad
    mov [rbp+328],edi
    call .ascii_span
    jc .bad
    cmp ecx,20
    jne .bad
    call .date_check
    jc .bad
    test eax,eax
    jz .next_entry
    mov edi,[rbp+328]
    add rdi,rbp
    mov ecx,20
    rep movsb
    bts dword [rbp+4],ebx
    jmp .next_entry
.orient:
    mov ebx,5
    call .once
    jc .bad
    mov ecx,3
    mov edx,1
    call .type_count
    jc .bad
    lea rsi,[r14+8]
    call .u16
    cmp eax,1
    jb .bad
    cmp eax,8
    ja .bad
    mov [rbp+8],eax
    or dword [rbp+4],32
    jmp .next_entry
.exif_pointer:
    mov ebx,6
    mov edi,276
    jmp .pointer
.gps_pointer:
    mov ebx,7
    mov edi,280
.pointer:
    call .once
    jc .bad
    mov ecx,4
    mov edx,1
    call .type_count
    jc .bad
    lea rsi,[r14+8]
    call .u32
    cmp eax,8
    jb .bad
    mov [rbp+rdi],eax
    jmp .next_entry
.latref:
    mov ebx,8
    mov edi,184
    mov r8d,'N'
    mov r9d,'S'
    jmp .ref
.lonref:
    mov ebx,10
    mov edi,188
    mov r8d,'E'
    mov r9d,'W'
.ref:
    call .once
    jc .bad
    mov ecx,2
    mov edx,2
    call .type_count
    jc .bad
    cmp byte [r14+9],0
    jne .bad
    movzx eax,byte [r14+8]
    mov edx,1
    cmp eax,r8d
    je .ref_ok
    inc edx
    cmp eax,r9d
    jne .bad
.ref_ok:
    mov [rbp+rdi],edx
    jmp .next_entry
.lat:
    mov ebx,9
    mov edi,192
    mov dword [rbp+348],90
    jmp .rational
.lon:
    mov ebx,11
    mov edi,216
    mov dword [rbp+348],180
.rational:
    call .once
    jc .bad
    mov ecx,5
    mov edx,3
    call .type_count
    jc .bad
    lea rsi,[r14+8]
    call .u32
    lea rdx,[rax+24]
    cmp rdx,r13
    ja .bad
    lea rsi,[r12+rax]
    lea rdi,[rbp+rdi]
    mov [rbp+328],rdi
    mov ecx,6
.rational_copy:
    call .u32
    stosd
    add rsi,4
    loop .rational_copy
    mov rdi,[rbp+328]
    call .gps_check
    jc .bad
.next_entry:
    add r14,12
    dec r15d
    jmp .entry
.next_ifd:
    inc dword [rbp+260]
    cmp dword [rbp+260],1
    jne .try_gps
    mov eax,[rbp+276]
    test eax,eax
    jnz .ifd
    inc dword [rbp+260]
.try_gps:
    cmp dword [rbp+260],2
    jne .complete
    mov eax,[rbp+280]
    test eax,eax
    jnz .ifd
.complete:
    mov eax,[rbp+268]
    and eax,0xf00
    cmp eax,0xf00
    jne .omit_gps
    or dword [rbp+4],16
    jmp .publish
.omit_gps:
    lea rdi,[rbp+184]
    mov ecx,7
    xor eax,eax
    rep stosq
.publish:
    mov rdi,[rbp+240]
    mov rsi,rbp
    mov ecx,30
    rep movsq
    xor eax,eax
    mov edx,240
    jmp .done
.bad:
    mov eax,2
    xor edx,edx
.done:
    mov r8d,eax
    mov r9,rdx
    mov rdi,rbp
    xor eax,eax
    mov ecx,52
    rep stosq
    mov eax,r8d
    mov rdx,r9
    add rsp,416
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    popfq
    ret

.u16:                         ; RSI mapped, EAX host integer
    movzx eax,word [rsi]
    cmp dword [rbp+264],0
    je .u16_done
    rol ax,8
.u16_done:
    ret
.u32:
    mov eax,[rsi]
    cmp dword [rbp+264],0
    je .u32_done
    bswap eax
.u32_done:
    ret
.once:                        ; EBX bit; CF=duplicate
    bts dword [rbp+268],ebx
    ret
.type_count:                  ; ECX expected type, EDX expected count
    lea rsi,[r14+2]
    call .u16
    cmp eax,ecx
    jne .helper_bad
    lea rsi,[r14+4]
    call .u32
    cmp eax,edx
    jne .helper_bad
    clc
    ret
.ascii_span:                  ; ECX actual count, RSI complete ASCII span
    lea rsi,[r14+2]
    call .u16
    cmp eax,2
    jne .helper_bad
    lea rsi,[r14+4]
    call .u32
    test eax,eax
    jz .helper_bad
    mov ecx,eax
    lea rsi,[r14+8]
    cmp eax,4
    jbe .helper_ok
    call .u32
    lea rdx,[rax+rcx]
    cmp rdx,r13
    ja .helper_bad
    lea rsi,[r12+rax]
.helper_ok:
    clc
    ret
.helper_bad:
    stc
    ret

.date_check:                  ; RSI original20; EAX=0 unknown,1 valid; CF invalid
    cmp byte [rsi+19],0
    jne .helper_bad
    xor ecx,ecx
    xor r8d,r8d               ; nonblank digit count
    xor r9d,r9d               ; decimal value of date/time without separators
.date_char:
    movzx eax,byte [rsi+rcx]
    cmp ecx,4
    je .date_colon
    cmp ecx,7
    je .date_colon
    cmp ecx,13
    je .date_colon
    cmp ecx,16
    je .date_colon
    cmp ecx,10
    je .date_space
    cmp al,' '
    je .date_advance
    sub eax,'0'
    cmp eax,9
    ja .helper_bad
    inc r8d
    jmp .date_advance
.date_colon:
    cmp al,':'
    je .date_advance
.date_space:
    cmp al,' '
    jne .helper_bad
.date_advance:
    inc ecx
    cmp ecx,19
    jb .date_char
    xor eax,eax
    test r8d,r8d
    jz .helper_ok
    cmp r8d,14
    jne .helper_bad
    ; Separators must be exact for known dates (blank colon not accepted).
    cmp byte [rsi+4],':'
    jne .helper_bad
    cmp byte [rsi+7],':'
    jne .helper_bad
    cmp byte [rsi+13],':'
    jne .helper_bad
    cmp byte [rsi+16],':'
    jne .helper_bad
    mov r10,rsi
    call .two_digits
    imul eax,100
    mov r11d,eax
    add rsi,2
    call .two_digits
    add eax,r11d
    test eax,eax
    jz .helper_bad
    mov [rbp+336],eax
    lea rsi,[r10+5]
    call .two_digits
    cmp eax,1
    jb .helper_bad
    cmp eax,12
    ja .helper_bad
    mov r9d,eax
    lea rsi,[r10+8]
    call .two_digits
    test eax,eax
    jz .helper_bad
    mov r8d,eax
    mov ecx,31
    cmp r9d,2
    je .feb
    cmp r9d,4
    je .thirty
    cmp r9d,6
    je .thirty
    cmp r9d,9
    je .thirty
    cmp r9d,11
    jne .day_limit
.thirty:
    mov ecx,30
    jmp .day_limit
.feb:
    mov ecx,28
    mov eax,[rbp+336]
    test eax,3
    jnz .day_limit
    xor edx,edx
    mov edi,100
    div edi
    test edx,edx
    jnz .leap
    test eax,3
    jnz .day_limit
.leap:
    inc ecx
.day_limit:
    cmp r8d,ecx
    ja .helper_bad
    lea rsi,[r10+11]
    call .two_digits
    cmp eax,23
    ja .helper_bad
    lea rsi,[r10+14]
    call .two_digits
    cmp eax,59
    ja .helper_bad
    lea rsi,[r10+17]
    call .two_digits
    cmp eax,60
    ja .helper_bad
    mov rsi,r10
    mov eax,1
    clc
    ret
.two_digits:
    movzx eax,byte [rsi]
    sub eax,'0'
    imul eax,10
    movzx edx,byte [rsi+1]
    lea eax,[rax+rdx-'0']
    ret

.gps_check:                   ; RDI points to six host u32; limit@348
    xor ecx,ecx
.gps_component:
    mov eax,[rdi+rcx*8+4]
    test eax,eax
    jz .helper_bad
    mov edx,60
    test ecx,ecx
    jnz .component_limit
    mov edx,[rbp+348]
.component_limit:
    imul rax,rdx              ; <=180*(2^32-1), fits64
    mov edx,[rdi+rcx*8]
    cmp rdx,rax
    ja .helper_bad
    test ecx,ecx
    jz .component_next
    cmp rdx,rax
    je .helper_bad            ; equality of minute/second with60
.component_next:
    inc ecx
    cmp ecx,3
    jb .gps_component
    ; N = Dn*Md*Sd*3600 + Mn*Dd*Sd*60 + Sn*Dd*Md.
    mov eax,[rdi]
    mov ecx,[rdi+12]
    mul rcx
    mov ecx,[rdi+20]
    mul rcx
    mov ecx,3600
    call .mul128
    mov [rbp+352],rax
    mov [rbp+360],rdx
    mov eax,[rdi+8]
    mov ecx,[rdi+4]
    mul rcx
    mov ecx,[rdi+20]
    mul rcx
    mov ecx,60
    call .mul128
    add [rbp+352],rax
    adc [rbp+360],rdx
    mov eax,[rdi+16]
    mov ecx,[rdi+4]
    mul rcx
    mov ecx,[rdi+12]
    mul rcx
    add [rbp+352],rax
    adc [rbp+360],rdx
    ; RHS = limit*Dd*Md*Sd*3600. Each side <2^116, no overflow.
    mov eax,[rdi+4]
    mov ecx,[rdi+12]
    mul rcx
    mov ecx,[rdi+20]
    mul rcx
    mov ecx,3600
    call .mul128
    mov ecx,[rbp+348]
    call .mul128
    cmp [rbp+360],rdx
    ja .helper_bad
    jb .helper_ok
    cmp [rbp+352],rax
    ja .helper_bad
    jmp .helper_ok
.mul128:                      ; RDX:RAX * u32 RCX, bounded to128 bits
    mov r8,rdx
    mul rcx
    imul r8,rcx
    add rdx,r8
    ret
