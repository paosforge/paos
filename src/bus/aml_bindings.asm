;; MODULE bus/aml_bindings
;; LAYER 2
;; EXPORTS aml_bindings_init, aml_bindings_insert, aml_bindings_find
;; IMPORTS aml_name_decode
;; CAPS
;; OWNER saga:bus
; Private, bounded native namespace storage/lookup groundwork for HP _PTS.
; Caller owns a mapped writable context and arena, and complete mapped input
; records/scopes. No concurrent access, external mutation or live firmware AML.
; Numeric bounds are NOT table/region address admission. Payload references are
; opaque and NEVER dereferenced here. The future ordered table loader must admit
; definition scopes, lifetime, object payloads and External/reopened-Scope policy.
; Strict duplicate refusal deliberately does not guess that loader policy.
; All failures leave context/arena unchanged and zero RDX/RCX/R8. Callee-saved
; registers are preserved. No globals, allocations, I/O or evaluator callsites.
%include "bus/aml_bindings.inc"

; RDI=context, RSI=arena start, RDX=end. Context and arena must be disjoint.
; Success: EAX=0, R8D=capacity, RDX=RCX=0. No arena byte is touched.
aml_bindings_init:
    test rdi, rdi
    jz .bounds
    mov rax, rdi
    add rax, aml_bindings_size
    jc .bounds
    test rsi, rsi
    jz .bounds
    cmp rsi, rdx
    jae .bounds
    cmp rax, rsi
    jbe .disjoint
    cmp rdi, rdx
    jb .bounds
.disjoint:
    mov r8, rdx
    mov rax, rdx
    sub rax, rsi
    cmp rax, AML_READ_MAX_BYTES
    ja .budget
    xor edx, edx
    mov ecx, aml_binding_size
    div rcx
    test eax, eax
    jz .bounds
    cmp rax, AML_BIND_MAX
    ja .budget
    mov [rdi+aml_bindings.start], rsi
    mov [rdi+aml_bindings.end], r8
    mov dword [rdi+aml_bindings.count], 0
    mov [rdi+aml_bindings.capacity], eax
    mov r8d, eax
    xor eax, eax
    xor edx, edx
    xor ecx, ecx
    ret
.bounds:
    mov eax, AML_READ_BOUNDS
    jmp aml_bindings_failure
.budget:
    mov eax, AML_READ_BUDGET
    jmp aml_bindings_failure

aml_bindings_failure:
    xor edx, edx
    xor ecx, ecx
    xor r8d, r8d
    ret

; Validate private context before any arena access. Preserves argument registers
; RDI/RSI/RDX/RCX; returns R9=arena, R11D=count. Entries remain trusted owner data.
aml_bindings_context:
    test rdi, rdi
    jz .bad
    mov rax, rdi
    add rax, aml_bindings_size
    jc .bad
    mov r9, [rdi+aml_bindings.start]
    mov r8, [rdi+aml_bindings.end]
    test r9, r9
    jz .bad
    cmp r9, r8
    jae .bad
    cmp rax, r9
    jbe .disjoint
    cmp rdi, r8
    jb .bad
.disjoint:
    mov rax, r8
    sub rax, r9
    cmp rax, AML_READ_MAX_BYTES
    ja .bad
    mov r10d, [rdi+aml_bindings.capacity]
    test r10d, r10d
    jz .bad
    cmp r10d, AML_BIND_MAX
    ja .bad
    mov r11d, [rdi+aml_bindings.count]
    cmp r11d, r10d
    ja .bad
    imul r10, aml_binding_size
    sub rax, r10
    jc .bad
    cmp rax, aml_binding_size         ; capacity must equal floor(span/record)
    jae .bad
    xor eax, eax
    ret
.bad:
    mov eax, AML_BIND_STATE
    ret

; RDI=canonical aml_name (full mapped record); no empty/root-only definitions.
; Metadata flags are forbidden on stored definitions. Unused tail is ignored.
aml_binding_name_valid:
    cmp dword [rdi+aml_name.flags], 0
    jne .bad
    mov r10d, [rdi+aml_name.count]
    test r10d, r10d
    jz .bad
    cmp r10d, AML_NAME_MAX_SEGS
    ja .bad
    xor r11d, r11d
.segment:
    xor ecx, ecx
.char:
    movzx eax, byte [rdi+aml_name.segments+r11]
    cmp al, '_'
    je .next
    cmp al, 'A'
    jb .digit
    cmp al, 'Z'
    jbe .next
.digit:
    test ecx, ecx
    jz .bad
    cmp al, '0'
    jb .bad
    cmp al, '9'
    ja .bad
.next:
    inc r11d
    inc ecx
    cmp ecx, 4
    jb .char
    dec r10d
    jnz .segment
    xor eax, eax
    ret
.bad:
    mov eax, AML_READ_SCOPE
    ret

; RDI=context, RSI=full mapped binding. Input may alias the arena: stage first.
; EAX=0, R8=published binding; RDX=RCX=0. Exact duplicate of ANY kind refuses.
; Publication is single-owner only: full record copied before count advances.
aml_bindings_insert:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, aml_binding_size
    mov r12, rdi
    mov r13, rsi
    call aml_bindings_context
    test eax, eax
    jnz .failed
    test r13, r13
    jz .bounds
    mov r14, r9
    mov ebp, r11d
    xor ecx, ecx
.stage:
    mov rax, [r13+rcx*8]
    mov [rsp+rcx*8], rax
    inc ecx
    cmp ecx, aml_binding_size/8
    jb .stage
    mov rdi, rsp
    call aml_binding_name_valid
    test eax, eax
    jnz .failed
    mov eax, [rsp+aml_binding.kind]
    dec eax
    cmp eax, AML_BIND_EXTERNAL-1
    ja .encoding
    mov eax, [rsp+aml_binding.source_id]
    dec eax
    cmp eax, AML_BIND_TABLES-1
    ja .encoding
    cmp dword [rsp+aml_binding.reserved], 0
    jne .encoding
    mov ebx, [rsp+aml_name.count]
    xor r15d, r15d
.scan:
    cmp r15d, ebp
    jae .capacity
    cmp [r14+aml_name.count], ebx
    jne .advance
    xor ecx, ecx
.compare:
    mov eax, [rsp+aml_name.segments+rcx*4]
    cmp [r14+aml_name.segments+rcx*4], eax
    jne .advance
    inc ecx
    cmp ecx, ebx
    jb .compare
    mov eax, AML_BIND_DUPLICATE
    jmp .failed
.advance:
    add r14, aml_binding_size
    inc r15d
    jmp .scan
.capacity:
    cmp ebp, [r12+aml_bindings.capacity]
    jae .budget
    mov ecx, ebx
    xor eax, eax
.tail:
    cmp ecx, AML_NAME_MAX_SEGS
    jae .publish
    mov [rsp+aml_name.segments+rcx*4], eax
    inc ecx
    jmp .tail
.publish:
    xor ecx, ecx
.copy:
    mov rax, [rsp+rcx*8]
    mov [r14+rcx*8], rax
    inc ecx
    cmp ecx, aml_binding_size/8
    jb .copy
    inc ebp
    mov [r12+aml_bindings.count], ebp
    mov r8, r14
    xor edx, edx
    xor ecx, ecx
    xor eax, eax
    jmp .out
.bounds:
    mov eax, AML_READ_BOUNDS
    jmp .failed
.encoding:
    mov eax, AML_READ_ENCODING
    jmp .failed
.budget:
    mov eax, AML_READ_BUDGET
.failed:
    call aml_bindings_failure
.out:
    add rsp, aml_binding_size
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; RDI=context, RSI=NameString, RDX=end, RCX=current canonical scope.
; Success EAX=0, R8=binding, RDX=next NameString byte, ECX=kind.
; Nearest binding wins across ALL kinds. Callers must check expected type/arity;
; a nearer non-method MUST NOT be skipped to reach an ancestor method.
; Root/parent/multi-segment references are exact; only SEARCH metadata from the
; native name reader permits ancestor search. NullName is not a reference.
aml_bindings_find:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 152
    mov r12, rdi
    call aml_bindings_context
    test eax, eax
    jnz .failed
    mov rdi, rsi
    mov rsi, rdx
    mov rdx, rcx
    mov rcx, rsp
    call aml_name_decode
    test eax, eax
    jnz .failed
    test r8d, AML_NAME_NULL
    jnz .encoding
    mov r14, rdx
    mov r15d, r8d
    mov ebx, [rsp+aml_name.count]
    test ebx, ebx
    jz .encoding
    mov r13d, [rsp+aml_name.segments+rbx*4-4] ; leaf kept while dropping parents
.retry:
    mov rbp, [r12+aml_bindings.start]
    mov r11d, [r12+aml_bindings.count]
.scan:
    test r11d, r11d
    jz .ancestor
    cmp [rbp+aml_name.count], ebx
    jne .advance
    xor ecx, ecx
.compare:
    mov eax, [rsp+aml_name.segments+rcx*4]
    cmp [rbp+aml_name.segments+rcx*4], eax
    jne .advance
    inc ecx
    cmp ecx, ebx
    jb .compare
    mov r8, rbp
    mov rdx, r14
    mov ecx, [rbp+aml_binding.kind]
    xor eax, eax
    jmp .out
.advance:
    add rbp, aml_binding_size
    dec r11d
    jmp .scan
.ancestor:
    test r15d, AML_NAME_SEARCH
    jz .missing
    cmp ebx, 1
    jbe .missing
    dec ebx
    mov [rsp+aml_name.count], ebx
    mov [rsp+aml_name.segments+rbx*4-4], r13d
    jmp .retry
.missing:
    mov eax, AML_BIND_NOT_FOUND
    jmp .failed
.encoding:
    mov eax, AML_READ_ENCODING
.failed:
    call aml_bindings_failure
.out:
    add rsp, 152
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
