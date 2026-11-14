;; MODULE bus/acpi_table_spans
;; LAYER 2
;; EXPORTS acpi_table_spans_collect
;; IMPORTS bus/acpi
;; CAPS
;; OWNER saga:bus
; Qualified native firmware-to-AML source boundary, ACPI6.6 5.2.9/5.2.11.
; Revalidate the cached ACPI2 XSDT, unique FADT, selected DSDT and every SSDT.
; Existing acpi_range and acpi_validate_sdt own address/type/checksum admission.
; DSDT first, SSDTs in current root order, including repeated OEM identities.
; Identity preservation does not resolve namespace duplicate/External semantics.
;
; Caller serializes discovery and retains stable, unreclaimed mapped firmware
; bytes and the owned UEFI memory map for the lifetime of all returned spans.
; Output must be a complete private writable record, disjoint from the map,
; globals and firmware inputs. Checked aliases below are defense in depth, not
; proof of output allocation or a replacement for those ownership preconditions.
; This does NOT rediscover RSDP/root from UEFI or implement RSDT fallback; the
; existing native discovery supplies the cached XSDT. No I/O, namespace loader,
; evaluator, allocation or global publication, and no power-path callsite.
%include "bus/acpi_table_spans.inc"

; RDI=acpi_table_spans output. EAX=existing AF_* state (AF_VALID=1).
; Success ECX=count, RDX=FADT, R8=XSDT; failure zeroes all three payloads and
; leaves the entire output unchanged. Publication is a single-owner validated
; copy, not an atomic multicore store. Callee-saved registers are preserved.
; Limits:256 root entries,16 AML sources,1MiB AML aggregate. Existing 64KiB
; root/FADT/SSDT and1MiB DSDT caps remain; root/FADT are separately bounded.
; A nonzero present X_DSDT must qualify: invalid extended pointers do not fall
; back to an unrelated legacy DSDT. Missing pointers return AF_ABSENT. PSDT or
; a root-listed DSDT refuse AF_UNSUPPORTED rather than silently omit AML.
acpi_table_spans_collect:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, acpi_table_spans_size + 16 ; private staging; call-aligned stack
    mov r12, rdi
    test rdi, rdi
    jz .address
    mov rax, rdi
    add rax, acpi_table_spans_size
    jc .address
    xor eax, eax
    xor ecx, ecx
.zero:
    mov [rsp+rcx*8], rax
    inc ecx
    cmp ecx, acpi_table_spans_size/8
    jb .zero
    movzx eax, byte [rel acpi_root_state]
    cmp eax, AF_VALID
    jne .failure
    mov r13, [rel acpi_xsdt]
    test r13, r13
    jz .address
    mov rdi, r13
    mov esi, 'XSDT'
    call acpi_validate_sdt
    cmp eax, AF_VALID
    jne .failure
    mov r14d, ecx
    sub r14d, ACPI_HDR_LEN
    test r14d, 7
    jnz .length
    shr r14d, 3
    cmp r14d, AF_MAX_ENTRIES
    ja .budget
    mov rdi, r13
    lea rsi, [r13+rcx]
    mov rdx, rsp
    mov rcx, r12
    call acpi_table_spans_disjoint
    cmp eax, AF_VALID
    jne .failure
    mov [rsp+acpi_table_spans.root_start], rdi
    mov [rsp+acpi_table_spans.root_end], rsi
    mov dword [rsp+acpi_table_spans.count], 1 ; reserve index0 for FADT's DSDT
    xor r15d, r15d
.walk:
    cmp r15d, r14d
    jae .dsdt
    mov rbp, [r13+ACPI_HDR_LEN+r15*8]
    mov rdi, rbp
    mov esi, ACPI_HDR_LEN
    xor edx, edx
    call acpi_range
    jc .address
    ; Qualify ALL child headers. An unreadable/bad signature could conceal
    ; another FADT/SSDT. Unrequested bodies never consume checksum/budget.
    mov rax, rbp
    add rax, ACPI_HDR_LEN              ; range already proved no overflow
    cmp r12, rax
    jae .header_disjoint
    lea rax, [r12+acpi_table_spans_size]
    cmp rax, rbp
    ja .address
.header_disjoint:
    mov eax, [rbp]
    mov ecx, 4
.signature_byte:
    cmp al, 0x20
    jb .signature
    cmp al, 0x7e
    ja .signature
    shr eax, 8
    loop .signature_byte
    cmp dword [rbp], 'FACP'
    je .fadt
    cmp dword [rbp], 'SSDT'
    je .ssdt
    cmp dword [rbp], 'PSDT'
    je .unsupported
    cmp dword [rbp], 'DSDT'
    je .unsupported
.next:
    inc r15d
    jmp .walk
.fadt:
    cmp qword [rsp+acpi_table_spans.fadt_start], 0
    jne .duplicate
    mov rdi, rbp
    mov esi, 'FACP'
    call acpi_validate_sdt
    cmp eax, AF_VALID
    jne .failure
    cmp ecx, 44                       ; complete legacy DSDT pointer
    jb .length
    mov rdi, rbp
    lea rsi, [rbp+rcx]
    mov rdx, rsp
    mov rcx, r12
    call acpi_table_spans_disjoint
    cmp eax, AF_VALID
    jne .failure
    mov [rsp+acpi_table_spans.fadt_start], rdi
    mov [rsp+acpi_table_spans.fadt_end], rsi
    jmp .next
.ssdt:
    cmp dword [rsp+acpi_table_spans.count], ACPI_TABLE_SPANS_MAX_TABLES
    jae .budget
    mov ebx, [rbp+4]                  ; header already admitted
    cmp ebx, ACPI_TABLE_SPANS_MAX_BYTES
    ja .budget
    add ebx, [rsp+acpi_table_spans.total_bytes]
    cmp ebx, ACPI_TABLE_SPANS_MAX_BYTES
    ja .budget
    mov rdi, rbp
    mov esi, 'SSDT'
    call acpi_validate_sdt
    cmp eax, AF_VALID
    jne .failure
    mov rdi, rbp
    lea rsi, [rbp+rcx]
    mov rdx, rsp
    mov rcx, r12
    call acpi_table_spans_disjoint
    cmp eax, AF_VALID
    jne .failure
    mov ecx, [rsp+acpi_table_spans.count]
    shl ecx, 4
    mov [rsp+rcx+acpi_table_spans.spans+acpi_table_span.start], rdi
    mov [rsp+rcx+acpi_table_spans.spans+acpi_table_span.end], rsi
    mov [rsp+acpi_table_spans.total_bytes], ebx
    inc dword [rsp+acpi_table_spans.count]
    jmp .next
.dsdt:
    mov rbp, [rsp+acpi_table_spans.fadt_start]
    test rbp, rbp
    jz .absent
    mov rax, [rsp+acpi_table_spans.fadt_end]
    sub rax, rbp
    cmp eax, 148                      ; complete X_DSDT through byte147
    jb .legacy
    mov rbx, [rbp+140]
    test rbx, rbx
    jnz .dsdt_header
.legacy:
    mov ebx, [rbp+40]
    test ebx, ebx
    jz .absent
.dsdt_header:
    mov rdi, rbx
    mov esi, ACPI_HDR_LEN
    xor edx, edx
    call acpi_range
    jc .address
    mov ebp, [rbx+4]
    cmp ebp, ACPI_TABLE_SPANS_MAX_BYTES
    ja .budget
    add ebp, [rsp+acpi_table_spans.total_bytes]
    cmp ebp, ACPI_TABLE_SPANS_MAX_BYTES
    ja .budget
    mov rdi, rbx
    mov esi, 'DSDT'
    call acpi_validate_sdt
    cmp eax, AF_VALID
    jne .failure
    mov rdi, rbx
    lea rsi, [rbx+rcx]
    mov rdx, rsp
    mov rcx, r12
    call acpi_table_spans_disjoint
    cmp eax, AF_VALID
    jne .failure
    mov [rsp+acpi_table_spans.spans+acpi_table_span.start], rdi
    mov [rsp+acpi_table_spans.spans+acpi_table_span.end], rsi
    mov [rsp+acpi_table_spans.total_bytes], ebp
    xor ecx, ecx
.publish:
    mov rax, [rsp+rcx*8]
    mov [r12+rcx*8], rax
    inc ecx
    cmp ecx, acpi_table_spans_size/8
    jb .publish
    mov ecx, [rsp+acpi_table_spans.count]
    mov rdx, [rsp+acpi_table_spans.fadt_start]
    mov r8, r13
    mov eax, AF_VALID
    jmp .out
.address:
    mov eax, AF_ADDRESS
    jmp .failure
.length:
    mov eax, AF_LENGTH
    jmp .failure
.budget:
    mov eax, AF_BUDGET
    jmp .failure
.signature:
    mov eax, AF_SIGNATURE
    jmp .failure
.duplicate:
    mov eax, AF_DUPLICATE
    jmp .failure
.unsupported:
    mov eax, AF_UNSUPPORTED
    jmp .failure
.absent:
    mov eax, AF_ABSENT
.failure:
    xor ecx, ecx
    xor edx, edx
    xor r8d, r8d
.out:
    add rsp, acpi_table_spans_size + 16
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Internal pure helper. RDI/RSI=validated logical [start,end), RDX=private
; staging, RCX=complete output start. Preserves RDI/RSI and callee-saved regs.
; Output aliases =>ADDRESS; identical starts =>DUPLICATE; other intersections
; with root/FADT/previous AML logical spans =>ENTRY. Empty staging slots skip.
acpi_table_spans_disjoint:
    lea rax, [rcx+acpi_table_spans_size] ; caller checked output arithmetic
    cmp rax, rdi
    jbe .inputs
    cmp rcx, rsi
    jb .address
.inputs:
    xor r8d, r8d
    lea r9, [rdx+acpi_table_spans.root_start]
.control:
    mov r10, [r9]
    test r10, r10
    jz .next_control
    cmp rdi, r10
    je .duplicate
    cmp rsi, r10
    jbe .next_control
    cmp rdi, [r9+8]
    jb .overlap
.next_control:
    add r9, 16
    inc r8d
    cmp r8d, 2
    jb .control
    xor r8d, r8d
    mov r11d, [rdx+acpi_table_spans.count]
    lea r9, [rdx+acpi_table_spans.spans]
.aml:
    cmp r8d, r11d
    jae .ok
    mov r10, [r9]
    test r10, r10
    jz .next_aml
    cmp rdi, r10
    je .duplicate
    cmp rsi, r10
    jbe .next_aml
    cmp rdi, [r9+8]
    jb .overlap
.next_aml:
    add r9, acpi_table_span_size
    inc r8d
    jmp .aml
.ok:
    mov eax, AF_VALID
    ret
.address:
    mov eax, AF_ADDRESS
    ret
.duplicate:
    mov eax, AF_DUPLICATE
    ret
.overlap:
    mov eax, AF_ENTRY
    ret
