;; MODULE bus/aml_namespace
;; LAYER 2
;; EXPORTS aml_length_decode, aml_package_decode, aml_integer_decode, aml_name_decode, aml_method_decode
;; IMPORTS
;; CAPS
;; OWNER saga:bus
; Native AML reader foundation for the HP _PTS preparation dependency. These
; functions decode bytes, not firmware behavior. No namespace is published, no
; method body is evaluated, and no region, mutex, port or MMIO is accessed.
; ACPI 6.5A 20.2.2/20.2.3/20.2.4 and 5.3 namespace search rules.
;
; Caller contract: [RDI,RSI) is an admitted, mapped, immutable byte span. A
; checked numeric extent does not admit a firmware address: the future table
; loader must use acpi_validate_sdt/range and ordered DSDT/SSDT admission first.
; All readers cap input at 1MiB and preserve SysV callee-saved registers. Failure
; returns a typed EAX error with RDX/RCX/R8 zero and leaves output records intact.
; Successful name/method records have zeroed unused segments/padding. They may
; alias the input/context, provided the caller owns the full writable record.
%include "bus/aml_namespace.inc"

; RDI=start, RSI=end -> EAX=0 or bounds/budget; no input byte is touched here.
aml_reader_span:
    test rdi, rdi
    jz .bounds
    cmp rdi, rsi
    jae .bounds
    mov rax, rsi
    sub rax, rdi
    cmp rax, AML_READ_MAX_BYTES
    ja .budget
    xor eax, eax
    ret
.bounds:
    mov eax, AML_READ_BOUNDS
    ret
.budget:
    mov eax, AML_READ_BUDGET
    ret

aml_reader_failure:
    xor edx, edx
    xor ecx, ecx
    xor r8d, r8d
    ret

; Decode the PkgLength encoding only, including Field bit lengths. EAX=status,
; R8D=value (all 28 bits), RDX=first byte after encoding, ECX=encoding width.
; A Field length is NOT a byte package extent. Only aml_package_decode makes
; that second interpretation and enforces value >= its own encoded width.
aml_length_decode:
    sub rsp, 8
    call aml_reader_span
    add rsp, 8
    test eax, eax
    jnz aml_reader_failure
    movzx eax, byte [rdi]
    lea rdx, [rdi+1]
    mov r9d, eax
    shr r9d, 6
    test r9d, r9d
    jz .short
    test al, 0x30                    ; reserved in multi-byte encoding
    jnz .encoding
    mov r8d, eax
    and r8d, 15
    mov rax, rsi
    sub rax, rdx
    cmp rax, r9
    jb .bounds
    mov ecx, 4
.byte:
    movzx eax, byte [rdx]
    shl eax, cl
    or r8d, eax
    inc rdx
    add ecx, 8
    dec r9d
    jnz .byte
    mov rcx, rdx
    sub rcx, rdi
    xor eax, eax
    ret
.short:
    mov r8d, eax
    and r8d, 63
    mov ecx, 1
    xor eax, eax
    ret
.bounds:
    mov eax, AML_READ_BOUNDS
    jmp aml_reader_failure
.encoding:
    mov eax, AML_READ_ENCODING
    jmp aml_reader_failure

; RDI points at a byte package's PkgLength (after its opcode), RSI=end.
; EAX=status, RDX=payload, RCX=package end, R8D=inclusive package byte length.
; Bytes after the package are permitted and never become part of this extent.
aml_package_decode:
    push rbx
    mov rbx, rdi
    call aml_length_decode
    test eax, eax
    jnz .out
    cmp r8d, ecx
    jb .encoding
    cmp r8d, AML_READ_MAX_BYTES
    ja .budget
    mov rax, rsi
    sub rax, rbx
    cmp r8, rax
    ja .bounds
    lea rcx, [rbx+r8]                ; <= admitted end, therefore cannot wrap
    xor eax, eax
    jmp .out
.encoding:
    mov eax, AML_READ_ENCODING
    jmp .bad
.budget:
    mov eax, AML_READ_BUDGET
    jmp .bad
.bounds:
    mov eax, AML_READ_BOUNDS
.bad:
    call aml_reader_failure
.out:
    pop rbx
    ret

; Integer objects only: Zero, One, Ones, Byte/Word/DWord/QWord prefixes. These
; are raw 64-bit encodings; a future evaluator owns revision-dependent integer
; width. Arguments, references, expressions and strings return UNSUPPORTED.
; EAX=status, R8=value, RDX=next byte, ECX=total encoded bytes.
aml_integer_decode:
    sub rsp, 8
    call aml_reader_span
    add rsp, 8
    test eax, eax
    jnz aml_reader_failure
    movzx eax, byte [rdi]
    lea rdx, [rdi+1]
    mov ecx, 1
    cmp eax, 1
    jbe .small
    cmp eax, 255
    je .ones
    mov r9d, 1
    cmp eax, 0x0a
    je .extent
    mov r9d, 2
    cmp eax, 0x0b
    je .extent
    mov r9d, 4
    cmp eax, 0x0c
    je .extent
    mov r9d, 8
    cmp eax, 0x0e
    jne .unsupported
.extent:
    mov rax, rsi
    sub rax, rdx
    cmp rax, r9
    jb .bounds
    cmp r9d, 8
    je .qword
    cmp r9d, 4
    je .dword
    cmp r9d, 2
    je .word
    movzx r8d, byte [rdx]
    jmp .read
.word:
    movzx r8d, word [rdx]
    jmp .read
.dword:
    mov r8d, [rdx]
    jmp .read
.qword:
    mov r8, [rdx]
.read:
    add rdx, r9
    lea ecx, [r9+1]
    xor eax, eax
    ret
.small:
    mov r8d, eax
    xor eax, eax
    ret
.ones:
    mov r8, -1
    xor eax, eax
    ret
.unsupported:
    mov eax, AML_READ_UNSUPPORTED
    jmp aml_reader_failure
.bounds:
    mov eax, AML_READ_BOUNDS
    jmp aml_reader_failure

; RDI=four admitted bytes -> EAX=0 or ENCODING. No names are normalized:
; NameSeg is uppercase A-Z/_ then exactly three A-Z/_/0-9 bytes.
aml_name_segment:
    xor ecx, ecx
.char:
    movzx eax, byte [rdi+rcx]
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
    inc ecx
    cmp ecx, 4
    jb .char
    xor eax, eax
    ret
.bad:
    mov eax, AML_READ_ENCODING
    ret

; RDI=NameString, RSI=end, RDX=canonical current aml_name scope,
; RCX=writable aml_name output. EAX=status, RDX=next, R8D=path metadata.
; This constructs a declaration path; it does not resolve a namespace object.
; ROOT/PARENT are exact, NULL is distinct from an empty root, and SEARCH only
; marks an unprefixed single-segment *reference* as eligible for ancestor lookup.
; Neither a definition nor a multi-segment/parent/root reference searches up.
aml_name_decode:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 152
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    call aml_reader_span
    test eax, eax
    jnz .failed
    test r14, r14
    jz .scope
    test r15, r15
    jz .bounds
    mov ebx, [r14+aml_name.count]
    cmp ebx, AML_NAME_MAX_SEGS
    ja .scope
    xor eax, eax
    xor ecx, ecx
.zero:
    mov [rsp+rcx*8], rax
    inc ecx
    cmp ecx, aml_name_size/8
    jb .zero
    xor ebp, ebp
.scope_segment:
    cmp ebp, ebx
    jae .prefix
    lea rdi, [r14+aml_name.segments+rbp*4]
    call aml_name_segment
    test eax, eax
    jnz .scope
    mov eax, [r14+aml_name.segments+rbp*4]
    mov [rsp+aml_name.segments+rbp*4], eax
    inc ebp
    jmp .scope_segment
.prefix:
    xor ebp, ebp
    cmp byte [r12], 0x5c
    jne .parents
    xor ebx, ebx
    mov ebp, AML_NAME_ROOT
    inc r12
    jmp .path
.parents:
    cmp r12, r13
    jae .bounds
    cmp byte [r12], 0x5e
    jne .path
    test ebx, ebx
    jz .scope
    dec ebx
    inc r12
    or ebp, AML_NAME_PARENT
    jmp .parents
.path:
    cmp r12, r13
    jae .bounds
    movzx eax, byte [r12]
    test eax, eax
    jz .null
    mov r9d, 1
    cmp eax, 0x2e
    je .dual
    cmp eax, 0x2f
    je .multi
    jmp .segments
.dual:
    inc r12
    mov r9d, 2
    jmp .segments
.multi:
    inc r12
    cmp r12, r13
    jae .bounds
    movzx r9d, byte [r12]
    inc r12
    test r9d, r9d
    jz .encoding
.segments:
    cmp r9d, AML_NAME_MAX_SEGS
    ja .budget
    lea eax, [rbx+r9]
    cmp eax, AML_NAME_MAX_SEGS
    ja .budget
    mov rax, r13
    sub rax, r12
    lea ecx, [r9*4]
    cmp rax, rcx
    jb .bounds
    test ebp, ebp
    jnz .copy_segments
    cmp r9d, 1
    jne .copy_segments
    or ebp, AML_NAME_SEARCH
.copy_segments:
    xor r10d, r10d
.segment:
    lea rdi, [r12+r10*4]
    call aml_name_segment
    test eax, eax
    jnz .failed
    mov eax, [r12+r10*4]
    mov [rsp+aml_name.segments+rbx*4], eax
    inc ebx
    inc r10d
    cmp r10d, r9d
    jb .segment
    lea r12, [r12+r9*4]
    jmp .publish
.null:
    inc r12
    or ebp, AML_NAME_NULL
.publish:
    mov [rsp+aml_name.count], ebx
    mov [rsp+aml_name.flags], ebp
    mov ecx, ebx
    xor eax, eax
.clear_tail:
    cmp ecx, AML_NAME_MAX_SEGS
    jae .copy
    mov [rsp+aml_name.segments+rcx*4], eax
    inc ecx
    jmp .clear_tail
.copy:
    xor ecx, ecx
.record:
    mov rax, [rsp+rcx*8]
    mov [r15+rcx*8], rax
    inc ecx
    cmp ecx, aml_name_size/8
    jb .record
    mov rdx, r12
    mov r8d, ebp
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
    jmp .failed
.scope:
    mov eax, AML_READ_SCOPE
.failed:
    call aml_reader_failure
.out:
    add rsp, 152
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; RDI=MethodOp, RSI=end, RDX=canonical current scope, RCX=aml_method output.
; On success RDX skips the whole declaration, R8D=MethodFlags. The returned body
; range is opaque, NOT validated/evaluated AML. A namespace loader must still
; admit table order, duplicates, actual definition scopes and method references.
aml_method_decode:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 168
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15, rcx
    call aml_reader_span
    test eax, eax
    jnz .failed
    test r15, r15
    jz .bounds
    cmp byte [r12], 0x14
    jne .unsupported
    lea rdi, [r12+1]
    mov rsi, r13
    call aml_package_decode
    test eax, eax
    jnz .failed
    mov r12, rcx
    mov rdi, rdx
    mov rsi, rcx
    mov rdx, r14
    lea rcx, [rsp]
    call aml_name_decode
    test eax, eax
    jnz .failed
    test r8d, AML_NAME_NULL
    jnz .encoding
    cmp rdx, r12                     ; one MethodFlags byte is mandatory
    jae .bounds
    movzx r8d, byte [rdx]
    mov [rsp+aml_method.flags], r8d
    mov dword [rsp+aml_method.reserved], 0
    inc rdx
    mov [rsp+aml_method.body], rdx
    mov [rsp+aml_method.end], r12
    xor ecx, ecx
.record:
    mov rax, [rsp+rcx*8]
    mov [r15+rcx*8], rax
    inc ecx
    cmp ecx, aml_method_size/8
    jb .record
    mov rdx, r12
    xor ecx, ecx
    xor eax, eax
    jmp .out
.bounds:
    mov eax, AML_READ_BOUNDS
    jmp .failed
.encoding:
    mov eax, AML_READ_ENCODING
    jmp .failed
.unsupported:
    mov eax, AML_READ_UNSUPPORTED
.failed:
    call aml_reader_failure
.out:
    add rsp, 168
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
