;; MODULE gui/img/img_photo_timeline
;; LAYER 6
;; EXPORTS img_photo_timeline
;; IMPORTS
;; CAPS
;; OWNER saga:gui_image_pipeline
;
; Actual creator: rc-ai-claude on OpenAI Codex.
; img_photo_timeline(RDI=immutable LE request64)->EAX0/RDXcount or EAX2/RDX0.
; entries:u64@0,count:u64@8,dst:u64@16,capacity:u64@24,scratch:u64@32,
; scratch_capacity:u64@40,reserved:u64@48=0,reserved:u64@56=0.
; count0..4096; count0 ignores all span fields and writes nothing. Otherwise
; entry16 = opaque nonzero unique ID:u64 + metadata pointer:u64 (0=undated).
; Nonzero metadata points at a stable admitted img_metadata_info record256.
; This entry checks typed headers/DateTimeOriginal only, not the photo raster,
; TIFF/container grammar or other metadata. Caller admits/owns all inputs.
;
; Output row24 = ID:u64@0,local date key:u64@8,hasDate:u32@16,
; inputOrdinal:u32@20. Date key is decimal YYYYMMDDHHMMSS (0=undated),
; NOT a UTC timestamp: no inferred timezone, filesystem/modified-time fallback.
; Valid original date is strict Gregorian year1..9999,HH0..23,MM0..59,SS0..60;
; retains the metadata reader's leap-second semantics. Newest first, stable
; input order for identical dates and undated entries. No camera/GPS fields
; are copied to rows; this does not authorize disclosure or strip image files.
;
; Both full destination/scratch capacities >=count*24, nonwrapping/disjoint,
; excluding request64, used entries count*16, and each full metadata256 span.
; Readonly inputs may alias each other. Validate ALL spans, IDs and dates before
; any caller write; refusal changes no caller memory, including scratch.
; Success writes exactly count*24 destination bytes, clears exactly count*24
; scratch bytes; padding/capacity slack preserved. Caller maps/stabilizes all
; declared spans and serializes through completion. No allocation, retained
; pointers/state, filesystem/network I/O, import/UI policy or authority.
; O(count^2) bounded unique-ID checking + stable insertion sort, O(count)
; caller workspace. Full64 nonvolatiles, flags/DF and FP preserved;56B saves,
; private span/key helpers add at most16B return addresses below that frame.

img_photo_timeline:
    pushfq
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    test rdi,rdi
    jz .bad
    mov rbp,rdi
    mov rax,rdi
    add rax,64
    jc .bad
    cmp qword [rbp+48],0
    jne .bad
    cmp qword [rbp+56],0
    jne .bad
    mov r12,[rbp+8]
    cmp r12,4096
    ja .bad
    test r12,r12
    jz .success
    mov rbx,[rbp]
    mov r13,[rbp+16]
    mov r14,[rbp+32]
    test rbx,rbx
    jz .bad
    test r13,r13
    jz .bad
    test r14,r14
    jz .bad
    lea r15,[r12+r12*2]
    shl r15,3
    cmp [rbp+24],r15
    jb .bad
    cmp [rbp+40],r15
    jb .bad
    mov rax,r13
    add rax,[rbp+24]
    jc .bad
    mov rdx,r14
    add rdx,[rbp+40]
    jc .bad
    cmp r13,rdx
    jae .writable_disjoint
    cmp r14,rax
    jb .bad
.writable_disjoint:
    mov rdi,rbp
    mov esi,64
    call .readonly_span
    test eax,eax
    jnz .bad
    mov rdi,rbx
    mov rsi,r12
    shl rsi,4
    call .readonly_span
    test eax,eax
    jnz .bad
    ; Complete pointer/span preflight before dereferencing any metadata.
    xor r10d,r10d
.pointer_loop:
    mov rax,r10
    shl rax,4
    mov r8,[rbx+rax]
    test r8,r8
    jz .bad
    xor ecx,ecx
.unique:
    cmp rcx,r10
    jae .unique_ok
    mov rdx,rcx
    shl rdx,4
    cmp r8,[rbx+rdx]
    je .bad
    inc rcx
    jmp .unique
.unique_ok:
    mov rdi,[rbx+rax+8]
    test rdi,rdi
    jz .next_pointer
    mov esi,256
    call .readonly_span
    test eax,eax
    jnz .bad
.next_pointer:
    inc r10
    cmp r10,r12
    jb .pointer_loop
    ; Validate every typed header/date, still without caller writes.
    xor r10d,r10d
.validate_loop:
    mov rax,r10
    shl rax,4
    mov rdi,[rbx+rax+8]
    call .date_key
    test eax,eax
    jnz .bad
    inc r10
    cmp r10,r12
    jb .validate_loop
    ; Stable mapped inputs were validated. No fallible operation remains.
    xor r10d,r10d
.stage_loop:
    mov rax,r10
    shl rax,4
    mov rdi,[rbx+rax+8]
    call .date_key
    lea rcx,[r10+r10*2]
    shl rcx,3
    mov rax,r10
    shl rax,4
    mov rax,[rbx+rax]
    mov [r14+rcx],rax
    mov [r14+rcx+8],rdx
    xor eax,eax
    test rdx,rdx
    setnz al
    mov [r14+rcx+16],eax
    mov [r14+rcx+20],r10d
    inc r10
    cmp r10,r12
    jb .stage_loop
    ; Descending insertion sort, moving a row only for a strictly newer key.
    mov r10d,1
.sort_outer:
    cmp r10,r12
    jae .publish
    lea rax,[r10+r10*2]
    shl rax,3
    mov r8,[r14+rax]
    mov r9,[r14+rax+8]
    mov r11,[r14+rax+16]
    mov rcx,rax
.sort_inner:
    test rcx,rcx
    jz .insert
    cmp r9,[r14+rcx-16]
    jbe .insert
    mov rax,[r14+rcx-24]
    mov [r14+rcx],rax
    mov rax,[r14+rcx-16]
    mov [r14+rcx+8],rax
    mov rax,[r14+rcx-8]
    mov [r14+rcx+16],rax
    sub rcx,24
    jmp .sort_inner
.insert:
    mov [r14+rcx],r8
    mov [r14+rcx+8],r9
    mov [r14+rcx+16],r11
    inc r10
    jmp .sort_outer
.publish:
    cld
    mov rdi,r13
    mov rsi,r14
    mov rcx,r15
    shr rcx,3
    rep movsq
    mov rdi,r14
    mov rcx,r15
    shr rcx,3
    xor eax,eax
    rep stosq
.success:
    mov rdx,r12
    xor eax,eax
    jmp .done
.bad:
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

; RDI/RSI readonly span -> EAX0/2. Preserves R10 loop counter and nonvolatiles.
.readonly_span:
    mov rdx,rdi
    add rdx,rsi
    jc .span_bad
    mov rax,r13
    add rax,[rbp+24]
    cmp rdi,rax
    jae .span_dst_ok
    cmp r13,rdx
    jb .span_bad
.span_dst_ok:
    mov rax,r14
    add rax,[rbp+40]
    cmp rdi,rax
    jae .span_ok
    cmp r14,rdx
    jb .span_bad
.span_ok:
    xor eax,eax
    ret
.span_bad:
    mov eax,2
    ret

; RDI optional metadata256 -> EAX0/RDXkey or EAX2/RDX0. No writes.
; Volatile registers only, preserving R10 (row index).
.date_key:
    test rdi,rdi
    jz .no_date
    cmp dword [rdi],1
    jne .date_bad
    mov eax,[rdi+4]
    sub eax,2
    cmp eax,1
    ja .date_bad
    cmp dword [rdi+8],1
    ja .date_bad
    cmp dword [rdi+12],0
    jne .date_bad
    cmp dword [rdi+16],1
    jne .date_bad
    mov eax,[rdi+20]
    test eax,~63
    jnz .date_bad
    cmp dword [rdi+28],0
    jne .date_bad
    mov ecx,[rdi+24]
    dec ecx
    cmp ecx,7
    ja .date_bad
    cmp dword [rdi+8],0
    jne .parsed
    test eax,eax
    jnz .date_bad
    test ecx,ecx
    jnz .date_bad
.parsed:
    test eax,4
    jz .no_date
    add rdi,160
    cmp byte [rdi+4],':'
    jne .date_bad
    cmp byte [rdi+7],':'
    jne .date_bad
    cmp byte [rdi+10],' '
    jne .date_bad
    cmp byte [rdi+13],':'
    jne .date_bad
    cmp byte [rdi+16],':'
    jne .date_bad
    cmp byte [rdi+19],0
    jne .date_bad
    xor edx,edx
    xor ecx,ecx
.digit:
    cmp ecx,4
    je .skip
    cmp ecx,7
    je .skip
    cmp ecx,10
    je .skip
    cmp ecx,13
    je .skip
    cmp ecx,16
    je .skip
    movzx eax,byte [rdi+rcx]
    sub eax,'0'
    cmp eax,9
    ja .date_bad
    imul rdx,10
    add rdx,rax
.skip:
    inc ecx
    cmp ecx,19
    jb .digit
    mov rsi,rdi
    call .two
    imul r8d,eax,100
    lea rsi,[rdi+2]
    call .two
    add r8d,eax
    test r8d,r8d
    jz .date_bad
    lea rsi,[rdi+5]
    call .two
    mov r9d,eax
    dec eax
    cmp eax,11
    ja .date_bad
    lea rsi,[rdi+8]
    call .two
    mov r11d,eax
    test eax,eax
    jz .date_bad
    lea rsi,[rel img_photo_timeline_month_days]
    movzx ecx,byte [rsi+r9-1]
    cmp r9d,2
    jne .day_limit
    test r8d,3
    jnz .day_limit
    ; Preserve date key across the Gregorian century division.
    mov r9,rdx
    mov eax,r8d
    xor edx,edx
    mov esi,100
    div esi
    test edx,edx
    jnz .leap
    test eax,3
    jnz .not_leap
.leap:
    inc ecx
.not_leap:
    mov rdx,r9
.day_limit:
    cmp r11d,ecx
    ja .date_bad
    lea rsi,[rdi+11]
    call .two
    cmp eax,23
    ja .date_bad
    lea rsi,[rdi+14]
    call .two
    cmp eax,59
    ja .date_bad
    lea rsi,[rdi+17]
    call .two
    cmp eax,60
    ja .date_bad
    xor eax,eax
    ret
.no_date:
    xor eax,eax
    xor edx,edx
    ret
.date_bad:
    mov eax,2
    xor edx,edx
    ret
.two:
    movzx eax,byte [rsi]
    imul eax,10
    movzx ecx,byte [rsi+1]
    lea eax,[rax+rcx-528]           ; digits already checked, '0'*11=528
    ret

img_photo_timeline_month_days: db 31,28,31,30,31,30,31,31,30,31,30,31
