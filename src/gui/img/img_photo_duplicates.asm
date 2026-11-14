;; MODULE gui/img/img_photo_duplicates
;; LAYER 6
;; EXPORTS img_photo_duplicates
;; IMPORTS
;; CAPS
;; OWNER saga:gui_image_pipeline
;
; Actual creator: rc-ai-claude on OpenAI Codex.
; img_photo_duplicates(RDI=immutable LE request48)->EAX0/RDXcount or EAX2/RDX0.
; entries:u64@0,count:u64@8,dst:u64@16,capacity:u64@24,
; reserved:u64@32=0,reserved:u64@40=0. count0..4096; empty ignores all spans.
; Entry16: unique nonzero opaque ID:u64 + mandatory admitted digest64 pointer.
; Caller supplies stable mapped readonly request/entries/records and owns
; admission, access and lifetimes. Record64 is img_rgba_digest v1/algorithm1:
; version:u32=1,algorithm:u32=1,w:u32,h:u32,pixelBytes:u64,reserved:u64=0,
; SHA256:32bytes. Geometry is 1..4096 axes, <=4194304 pixels, byte count w*h*4.
; This entry checks typed headers/geometry, not the raster or hash authenticity.
;
; Output row24 in unchanged input order: ID:u64@0,representativeID:u64@8,
; groupSize:u32@16,inputOrdinal:u32@20. All64 record bytes must match for a
; candidate group. Representative is its FIRST input ID (not numeric minimum).
; Singletons remain with representative=self and size1. All SHA bytes and
; dimensions participate, including the digest's alpha/hidden-RGB semantics.
; Hash equality is only a duplicate CANDIDATE: never authority to delete,
; skip imports or disclose files; caller must apply product confirmation and
; access rules. No perceptual equivalence or original-file identity claim.
;
; Full destination capacity >=count*24, nonwrapping, disjoint from request48,
; used entries count*16 and EVERY full record64. Readonly inputs may alias.
; Validate all spans and unique IDs before ANY record read, then validate all
; headers before ANY caller write. Refusal changes no caller bytes. Success
; writes exactly count*24 bytes, preserving capacity slack. Caller serializes
; calls and keeps input stable throughout; no fallible operation after checks.
; O(count^2), O(1) private space, no allocation/retained pointers/IO/globals.
; This grouping performs NO SHA calls and has no shared SHA-workspace coupling.
; Full64 nonvolatiles, incoming flags/DF and FP preserved.56B saves +8B helper
; return below that frame. No UI/import policy, lifecycle or authority added.

img_photo_duplicates:
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
    add rax,48
    jc .bad
    cmp qword [rbp+32],0
    jne .bad
    cmp qword [rbp+40],0
    jne .bad
    mov r12,[rbp+8]
    cmp r12,4096
    ja .bad
    test r12,r12
    jz .success
    mov rbx,[rbp]
    mov r13,[rbp+16]
    test rbx,rbx
    jz .bad
    test r13,r13
    jz .bad
    lea rax,[r12+r12*2]
    shl rax,3
    cmp [rbp+24],rax
    jb .bad
    mov r14,r13
    add r14,[rbp+24]
    jc .bad
    mov rdi,rbp
    mov esi,48
    call .readonly_span
    test eax,eax
    jnz .bad
    mov rdi,rbx
    mov rsi,r12
    shl rsi,4
    call .readonly_span
    test eax,eax
    jnz .bad
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
    jz .bad
    mov esi,64
    call .readonly_span
    test eax,eax
    jnz .bad
    inc r10
    cmp r10,r12
    jb .pointer_loop
    ; Complete all header/geometry checks before publication.
    xor r10d,r10d
.header_loop:
    mov rax,r10
    shl rax,4
    mov rdi,[rbx+rax+8]
    cmp dword [rdi],1
    jne .bad
    cmp dword [rdi+4],1
    jne .bad
    mov eax,[rdi+8]
    dec eax
    cmp eax,4095
    ja .bad
    mov edx,[rdi+12]
    dec edx
    cmp edx,4095
    ja .bad
    inc eax
    inc edx
    imul rax,rdx
    cmp rax,4194304
    ja .bad
    shl rax,2
    cmp rax,[rdi+16]
    jne .bad
    cmp qword [rdi+24],0
    jne .bad
    inc r10
    cmp r10,r12
    jb .header_loop
    ; Inputs are stable and validated. No remaining fallible operation.
    xor r10d,r10d
.row_loop:
    mov rax,r10
    shl rax,4
    mov r8,[rbx+rax+8]
    xor r11d,r11d
    xor r15d,r15d
    xor ecx,ecx
.scan:
    mov rax,rcx
    shl rax,4
    mov r9,[rbx+rax+8]
    xor esi,esi
.equal:
    mov rdx,[r8+rsi]
    cmp rdx,[r9+rsi]
    jne .next
    add esi,8
    cmp esi,64
    jb .equal
    inc r11d
    test r15,r15
    jnz .next
    mov r15,[rbx+rax]
.next:
    inc rcx
    cmp rcx,r12
    jb .scan
    mov rax,r10
    shl rax,4
    mov rdx,[rbx+rax]
    lea rax,[r10+r10*2]
    shl rax,3
    mov [r13+rax],rdx
    mov [r13+rax+8],r15
    mov [r13+rax+16],r11d
    mov [r13+rax+20],r10d
    inc r10
    cmp r10,r12
    jb .row_loop
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

; RDI/RSI readonly span -> EAX0/2. R14 is validated full destination endpoint.
; Preserves R10 loop index and all nonvolatile registers.
.readonly_span:
    mov rdx,rdi
    add rdx,rsi
    jc .span_bad
    cmp rdi,r14
    jae .span_ok
    cmp r13,rdx
    jb .span_bad
.span_ok:
    xor eax,eax
    ret
.span_bad:
    mov eax,2
    ret
