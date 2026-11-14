;; MODULE bus/aml_tables
;; LAYER 2
;; EXPORTS aml_tables_decode
;; IMPORTS
;; CAPS
;; OWNER saga:bus
; Pure ordered definition-block byte-set decoder. ACPI6.6 5.2.11.1/.2.
; Caller owns mapped immutable descriptors and complete mapped immutable table
; spans, and a complete writable output. It must retain these bytes while any
; output reference is used; no concurrent mutation. Numerical checks below do
; NOT map/admit firmware memory, prove FADT/root provenance or authorize I/O.
; The future live enumeration adapter must use existing acpi_validate_sdt/range
; admission and the actual root order. This function never follows raw firmware
; pointers. Repeated OEM IDs are preserved, not guessed to be namespace merges.
; No namespace, method execution, region access, allocations or global state.
; Failure leaves output byte-for-byte intact; all return payloads are zero.
%include "bus/aml_tables.inc"

; RDI=descriptor start, RSI=end, RDX=aml_tables output. Exactly1..16 descriptors.
; First is DSDT, all remaining SSDT, in caller order. Header+body checksums and
; aggregate bytes are checked before publication. Overlapping logical tables or
; any output/input alias refuse. Empty AML bodies and mapping padding are legal.
; Success: EAX=0, R8D=count, ECX=total bytes, RDX=0. Callee-saved preserved.
aml_tables_decode:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, aml_tables_size + 8       ; private staging; aligned future calls
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    test rdi, rdi
    jz .bounds
    cmp rdi, rsi
    jae .bounds
    mov rax, rsi
    sub rax, rdi
    test eax, aml_table_span_size-1
    jnz .bounds
    cmp rax, AML_TABLE_MAX * aml_table_span_size
    ja .budget
    shr eax, 4
    mov ebp, eax
    test r14, r14
    jz .bounds
    mov rdx, r14
    add rdx, aml_tables_size
    jc .bounds
    cmp rdx, r12
    jbe .disjoint
    cmp r14, r13
    jb .overlap
.disjoint:
    xor ecx, ecx
    xor eax, eax
.zero:
    mov [rsp+rcx*8], rax
    inc ecx
    cmp ecx, aml_tables_size/8
    jb .zero
    mov [rsp+aml_tables.count], ebp
    xor r15d, r15d
.table:
    mov rax, r15
    shl rax, 4
    mov rbx, [r12+rax+aml_table_span.start]
    mov r9, [r12+rax+aml_table_span.end]
    test rbx, rbx
    jz .bounds
    cmp rbx, r9
    jae .bounds
    mov rax, r9
    sub rax, rbx
    cmp rax, AML_TABLE_HEADER
    jb .bounds                       ; never read even a signature before header
    mov r10d, [rbx+4]
    cmp r10d, AML_TABLE_HEADER
    jb .bounds
    cmp r10, rax
    ja .bounds
    mov eax, [rsp+aml_tables.total_bytes]
    add rax, r10
    cmp rax, AML_READ_MAX_BYTES
    ja .budget
    mov [rsp+aml_tables.total_bytes], eax
    lea r9, [rbx+r10]                 ; <= caller span end; cannot wrap
    mov rdx, r14
    add rdx, aml_tables_size          ; checked above
    cmp rdx, rbx
    jbe .table_disjoint
    cmp r14, r9
    jb .overlap
.table_disjoint:
    mov eax, 'DSDT'
    test r15d, r15d
    jz .signature
    mov eax, 'SSDT'
.signature:
    cmp [rbx], eax
    jne .order
    xor ecx, ecx
.prior:
    cmp ecx, r15d
    jae .checksum_start
    mov eax, ecx
    shl rax, 6
    cmp r9, [rsp+rax+aml_tables.entries+aml_table.start]
    jbe .next_prior
    cmp rbx, [rsp+rax+aml_tables.entries+aml_table.end]
    jb .overlap
.next_prior:
    inc ecx
    jmp .prior
.checksum_start:
    mov rdi, rbx
    xor eax, eax
.checksum:
    add al, [rdi]
    inc rdi
    cmp rdi, r9
    jb .checksum
    test al, al
    jnz .checksum_bad
    mov rax, r15
    shl rax, 6
    lea rdi, [rsp+rax+aml_tables.entries]
    xor ecx, ecx
.header:
    mov al, [rbx+rcx]
    mov [rdi+aml_table.header+rcx], al
    inc ecx
    cmp ecx, AML_TABLE_HEADER
    jb .header
    lea eax, [r15+1]
    mov [rdi+aml_table.source_id], eax
    mov [rdi+aml_table.start], rbx
    lea rax, [rbx+AML_TABLE_HEADER]
    mov [rdi+aml_table.body], rax
    mov [rdi+aml_table.end], r9
    test r15d, r15d
    jnz .next
    mov eax, 32
    cmp byte [rbx+8], 2
    jb .width
    mov eax, 64
.width:
    mov [rsp+aml_tables.integer_bits], eax
.next:
    inc r15d
    cmp r15d, ebp
    jb .table
    xor ecx, ecx
.publish:
    mov rax, [rsp+rcx*8]
    mov [r14+rcx*8], rax
    inc ecx
    cmp ecx, aml_tables_size/8
    jb .publish
    mov r8d, ebp
    mov ecx, [rsp+aml_tables.total_bytes]
    xor edx, edx
    xor eax, eax
    jmp .out
.bounds:
    mov eax, AML_READ_BOUNDS
    jmp .failure
.budget:
    mov eax, AML_READ_BUDGET
    jmp .failure
.checksum_bad:
    mov eax, AML_TABLE_CHECKSUM
    jmp .failure
.order:
    mov eax, AML_TABLE_ORDER
    jmp .failure
.overlap:
    mov eax, AML_TABLE_OVERLAP
.failure:
    xor edx, edx
    xor ecx, ecx
    xor r8d, r8d
.out:
    add rsp, aml_tables_size + 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
