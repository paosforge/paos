;; MODULE gui/img/img_photo_import_plan
;; LAYER 6
;; EXPORTS img_photo_import_plan
;; IMPORTS
;; CAPS
;; OWNER saga:gui_image_pipeline
;
; Actual creator: rc-ai-claude on OpenAI Codex.
; img_photo_import_plan(RDI=immutable mapped LE request64)->EAX0/RDXcount,
; or EAX2/RDX0 refusal. Request:u64 candidates@0,count@8,library@16,
; library_count@24,dst@32,capacity@40,reserved@48=0,reserved@56=0.
; Each count0..4096. Empty candidates validate both counts/reserved, then ignore
; every pointer/capacity and return0 rows. Empty library ignores library pointer.
; Entry16: nonzero full64 opaque ID@0,admitted file-identity64 pointer@8.
; IDs unique WITHIN each set; cross-set IDs and readonly spans may alias.
; File record64: magic8="PAOSFILE",LEu32version1@8,LEu32algorithm1@12,
; LEu64sourceLength1..33554432@16,standard SHA256raw32@24,reserved8zero@56.
; Header checks do not authenticate hash bytes or establish actual file content.
; Caller maps/stabilizes every used span and owns access,admission,lifetimes.
;
; Row32, unchanged candidate order: candidateID:u64@0,firstExistingID:u64@8
; (0 when absent),firstBatchID:u64@16,disposition:u32@24,ordinal:u32@28.
; Disposition1=new candidate,2=matches library,3=earlier batch repeat. The first
; matching library entry wins regardless of ID value. firstBatchID is earliest
; matching candidate ID, including self. Library match takes precedence over
; batch repeat. Match ALL64 record bytes (including every SHA byte and length).
; These are proposals, never import/skip/delete/access authority. No IO, file
; verification, persistent index, confirmation policy or perceptual comparison.
;
; Nonempty destination capacity>=count*32 and<=67108864, full span nonwrapping
; and disjoint from request64,both used descriptor arrays and EVERY record64.
; All descriptor/record spans and IDs validate before ANY record header read;
; all headers validate before ANY caller write. Refusal writes no caller bytes;
; success writes exactlycount*32 and preserves slack and all readonly inputs.
; No allocation/free,retained pointers,globals,SHA calls or decoder mutation.
; Stable disjoint caller inputs permit reentry; no shared SHA workspace usage.
; O(c*c+l*l+c*l),constant private space. Full64 nonvolatiles,flags/DF,FP kept.

img_photo_import_plan:
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
    cmp qword [rbp+24],4096
    ja .bad
    test r12,r12
    jz .success
    mov rbx,[rbp]
    mov r15,[rbp+16]
    mov r13,[rbp+32]
    test rbx,rbx
    jz .bad
    test r13,r13
    jz .bad
    mov rax,r12
    shl rax,5
    cmp [rbp+40],rax
    jb .bad
    cmp qword [rbp+40],67108864
    ja .bad
    mov r14,r13
    add r14,[rbp+40]
    jc .bad
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
    cmp qword [rbp+24],0
    je .arrays_clear
    test r15,r15
    jz .bad
    mov rdi,r15
    mov rsi,[rbp+24]
    shl rsi,4
    call .readonly_span
    test eax,eax
    jnz .bad
.arrays_clear:
    mov r8,rbx
    mov r9,r12
    call .set_spans
    test eax,eax
    jnz .bad
    mov r8,r15
    mov r9,[rbp+24]
    call .set_spans
    test eax,eax
    jnz .bad
    ; Both sets' complete span/ID checks precede either set's record reads.
    mov r8,rbx
    mov r9,r12
    call .set_headers
    test eax,eax
    jnz .bad
    mov r8,r15
    mov r9,[rbp+24]
    call .set_headers
    test eax,eax
    jnz .bad
    xor r10d,r10d
.row:
    mov rax,r10
    shl rax,4
    mov r8,[rbx+rax+8]
    xor ecx,ecx
.batch_scan:
    mov rax,rcx
    shl rax,4
    mov r9,[rbx+rax+8]
    call .records_equal
    test eax,eax
    jz .batch_found
    inc rcx
    ; Self is guaranteed equal after stable-input validation.
    jmp .batch_scan
.batch_found:
    mov rax,rcx
    shl rax,4
    mov r11,[rbx+rax]
    xor ecx,ecx
.library_scan:
    cmp rcx,[rbp+24]
    jae .no_existing
    mov rax,rcx
    shl rax,4
    mov r9,[r15+rax+8]
    call .records_equal
    test eax,eax
    jz .existing_found
    inc rcx
    jmp .library_scan
.existing_found:
    mov rax,rcx
    shl rax,4
    mov r9,[r15+rax]
    jmp .publish
.no_existing:
    xor r9d,r9d
.publish:
    mov rax,r10
    shl rax,4
    mov rdx,[rbx+rax]
    mov esi,1
    cmp r11,rdx
    je .batch_status
    mov esi,3
.batch_status:
    test r9,r9
    jz .status_ready
    mov esi,2
.status_ready:
    mov rax,r10
    shl rax,5
    mov [r13+rax],rdx
    mov [r13+rax+8],r9
    mov [r13+rax+16],r11
    mov [r13+rax+24],esi
    mov [r13+rax+28],r10d
    inc r10
    cmp r10,r12
    jb .row
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

; RDI/RSI readonly full span; R13/R14 destination endpoints. EAX0/2;
; clobbers RAX/RDX only, preserving span/unique-loop indices.
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

; R8 entries,R9 count (array already admitted); validates unique/nonzero IDs
; and EVERY record span, reading no record byte. EAX0/2.
.set_spans:
    xor r10d,r10d
.pointer_loop:
    cmp r10,r9
    jae .set_ok
    mov rax,r10
    shl rax,4
    mov r11,[r8+rax]
    test r11,r11
    jz .set_bad
    xor ecx,ecx
.unique:
    cmp rcx,r10
    jae .unique_ok
    mov rdx,rcx
    shl rdx,4
    cmp r11,[r8+rdx]
    je .set_bad
    inc rcx
    jmp .unique
.unique_ok:
    mov rdi,[r8+rax+8]
    test rdi,rdi
    jz .set_bad
    mov esi,64
    call .readonly_span
    test eax,eax
    jnz .set_bad
    inc r10
    jmp .pointer_loop

; Both sets' spans/IDs have passed before this is called. R8 entries,R9count.
.set_headers:
    xor r10d,r10d
.header_loop:
    cmp r10,r9
    jae .set_ok
    mov rax,r10
    shl rax,4
    mov rdi,[r8+rax+8]
    mov rax,'PAOSFILE'
    cmp [rdi],rax
    jne .set_bad
    cmp dword [rdi+8],1
    jne .set_bad
    cmp dword [rdi+12],1
    jne .set_bad
    mov rax,[rdi+16]
    test rax,rax
    jz .set_bad
    cmp rax,33554432
    ja .set_bad
    cmp qword [rdi+56],0
    jne .set_bad
    inc r10
    jmp .header_loop
.set_ok:
    xor eax,eax
    ret
.set_bad:
    mov eax,2
    ret

; R8/R9 validated record64 pointers. EAX0 equal/1 different; clobber RSI/RDX,
; preserve candidate index R10,scan RCX,first-batch ID R11 and all nonvolatiles.
.records_equal:
    xor esi,esi
.equal_qword:
    mov rdx,[r8+rsi]
    cmp rdx,[r9+rsi]
    jne .different
    add esi,8
    cmp esi,64
    jb .equal_qword
    xor eax,eax
    ret
.different:
    mov eax,1
    ret
