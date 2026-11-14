;; MODULE lib/safe_buffer
;; LAYER 1
;; EXPORTS safe_copy, safe_capped_len, safe_checked_add, safe_checked_mul, safe_span_validate, safe_tlv_u8_view, safe_tlv_u8_read, safe_buffer_selftest, safe_buffer_kat_ok, network_parser_bounds_kat_ok
;; IMPORTS boot/serial
;; CAPS
;; OWNER saga:security_hardening
; Contract 9523: one small failure-atomic primitive family for hostile fields.
; Every function preserves RBX/RBP/R8-R15. Results use only RAX/RDX/RCX/RDI;
; callers must still regard RAX/RCX/RDX/RSI/RDI as scratch.

SAFE_BUF_OK         equ 0
SAFE_BUF_TRUNCATED  equ 1
SAFE_BUF_BOUNDS     equ 2
SAFE_BUF_INVALID    equ 3

; safe_copy(dst, dst_cap, src, src_len)
;   in:  RDI=dst, RSI=full destination capacity including the NUL slot,
;        RDX=src, RCX=explicit source length
;   out: EAX=SAFE_BUF_OK/TRUNCATED/INVALID, RDX=bytes copied
; A positive destination capacity is always terminated. No source byte beyond
; src_len is inspected. Truncation is reported, never silently accepted.
safe_copy:
    push rbx
    test rsi, rsi
    jz   .no_capacity
    test rdi, rdi
    jz   .invalid
    mov  rax, rdi
    add  rax, rsi
    jc   .invalid                           ; destination capacity may not wrap
    mov  byte [rdi], 0
    test rcx, rcx
    jz   .empty
    test rdx, rdx
    jz   .invalid
    mov  rax, rdx
    add  rax, rcx
    jc   .invalid                           ; explicit source span may not wrap
    lea  rax, [rsi - 1]
    xor  esi, esi                         ; return status = OK
    cmp  rcx, rax
    jbe  .copy_ready
    mov  rcx, rax                         ; clamp by DESTINATION capacity
    mov  esi, SAFE_BUF_TRUNCATED
.copy_ready:
    xor  eax, eax                         ; copied count
.copy_loop:
    cmp  rax, rcx
    jae  .terminate
    mov  bl, [rdx + rax]
    mov  [rdi + rax], bl
    inc  rax
    jmp  .copy_loop
.terminate:
    mov  byte [rdi + rax], 0
    mov  rdx, rax
    mov  eax, esi
    pop  rbx
    ret
.empty:
    xor  eax, eax
    xor  edx, edx
    pop  rbx
    ret
.no_capacity:
    xor  edx, edx
    xor  eax, eax
    test rcx, rcx
    setnz al                               ; non-empty input was necessarily truncated
    pop  rbx
    ret
.invalid:
    mov  eax, SAFE_BUF_INVALID
    xor  edx, edx
    pop  rbx
    ret

; safe_capped_len(buf, cap) — the contract's capped strnlen operation.
;   in: RDI=buf, RSI=maximum readable bytes
;   out: RAX=length, EDX=SAFE_BUF_OK when NUL found, SAFE_BUF_TRUNCATED at cap,
;        SAFE_BUF_INVALID for NULL with a positive cap
safe_capped_len:
    xor  eax, eax
    test rsi, rsi
    jz   .at_cap
    test rdi, rdi
    jz   .bad_ptr
    mov  rdx, rdi
    add  rdx, rsi
    jc   .bad_ptr                           ; cap describes an invalid wrapped span
.scan:
    cmp  rax, rsi
    jae  .at_cap
    cmp  byte [rdi + rax], 0
    je   .found
    inc  rax
    jmp  .scan
.found:
    xor  edx, edx
    ret
.at_cap:
    mov  edx, SAFE_BUF_TRUNCATED
    ret
.bad_ptr:
    mov  edx, SAFE_BUF_INVALID
    ret

; safe_checked_add(RDI=a, RSI=b) -> RAX=sum or 0, EDX=OK/BOUNDS.
safe_checked_add:
    mov  rax, rdi
    add  rax, rsi
    jc   .overflow
    xor  edx, edx
    ret
.overflow:
    xor  eax, eax
    mov  edx, SAFE_BUF_BOUNDS
    ret

; safe_checked_mul(RDI=a, RSI=b) -> RAX=product or 0, EDX=OK/BOUNDS.
safe_checked_mul:
    mov  rax, rdi
    mul  rsi
    test rdx, rdx
    jnz  .overflow
    xor  edx, edx
    ret
.overflow:
    xor  eax, eax
    mov  edx, SAFE_BUF_BOUNDS
    ret

; safe_span_validate(base,total,offset,length)
;   in: RDI=base, RSI=total bytes, RDX=offset, RCX=length
;   out: EAX=OK/BOUNDS/INVALID, RDX=base+offset only on success
; Validate with subtraction before pointer formation, then separately reject
; both base+offset and end-pointer carry.
safe_span_validate:
    test rdi, rdi
    jz   .invalid
    cmp  rdx, rsi
    ja   .bounds
    mov  rax, rsi
    sub  rax, rdx                         ; remaining, cannot underflow
    cmp  rcx, rax
    ja   .bounds
    mov  rax, rdi
    add  rax, rdx
    jc   .bounds
    mov  rdx, rax
    add  rax, rcx
    jc   .bounds
    xor  eax, eax
    ret
.invalid:
    xor  edx, edx
    mov  eax, SAFE_BUF_INVALID
    ret
.bounds:
    xor  edx, edx
    mov  eax, SAFE_BUF_BOUNDS
    ret

; safe_tlv_u8_view(cursor,end)
;   format: one-byte tag, one-byte length, then value bytes
;   in:  RDI=cursor, RSI=end exclusive
;   out on success: EAX=OK, EDX=tag, ECX=value length,
;                   RDI=value pointer, RSI=next field
;   out on reject: EAX=TRUNCATED/INVALID, EDX=0, ECX=0
; The length byte is read exactly once. Remaining-input subtraction precedes
; both value/next pointer formation, so a hostile length cannot wrap a pointer.
safe_tlv_u8_view:
    test rdi, rdi
    jz   .view_invalid
    test rsi, rsi
    jz   .view_invalid
    cmp  rdi, rsi
    ja   .view_invalid
    mov  rax, rsi
    sub  rax, rdi
    cmp  rax, 2
    jb   .view_truncated
    movzx edx, byte [rdi]                 ; tag read once
    movzx ecx, byte [rdi + 1]             ; declared length read exactly once
    sub  rax, 2
    cmp  rcx, rax
    ja   .view_truncated
    add  rdi, 2                           ; safe only after remaining check
    lea  rsi, [rdi + rcx]
    xor  eax, eax
    ret
.view_truncated:
    mov  eax, SAFE_BUF_TRUNCATED
    jmp  .view_reject
.view_invalid:
    mov  eax, SAFE_BUF_INVALID
.view_reject:
    xor  edx, edx
    xor  ecx, ecx
    ret

; safe_tlv_u8_read(cursor,end,dst,dst_cap)
;   format: one-byte tag, one-byte length, then value bytes
;   in:  RDI=cursor, RSI=end exclusive, RDX=dst, RCX=dst capacity incl NUL
;   out on success: EAX=OK, RDI=next field, RDX=value bytes copied, ECX=tag
;   out on reject: EAX=TRUNCATED/BOUNDS/INVALID, RDX=0, ECX=0
; The declared length byte is loaded exactly once, checked against remaining
; input AND output capacity before the first value read/write, and a rejected
; field leaves no partial output (dst[0]=NUL when capacity permits).
safe_tlv_u8_read:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rdx
    mov  r14, rcx
    test r14, r14
    jz   .tlv_bounds
    test r13, r13
    jz   .tlv_invalid
    mov  byte [r13], 0
    test rbx, rbx
    jz   .tlv_invalid
    test r12, r12
    jz   .tlv_invalid
    cmp  rbx, r12
    ja   .tlv_invalid
    mov  rax, r12
    sub  rax, rbx                         ; remaining without pointer addition
    cmp  rax, 2
    jb   .tlv_truncated
    movzx r15d, byte [rbx]                ; tag read once
    movzx ecx, byte [rbx + 1]             ; declared length read exactly once
    sub  rax, 2
    cmp  rcx, rax
    ja   .tlv_truncated
    cmp  rcx, r14                         ; reserve one byte for required NUL
    jae  .tlv_bounds
    mov  rdi, r13
    mov  rsi, r14
    lea  rdx, [rbx + 2]
    call safe_copy
    test eax, eax                         ; prechecks make truncation impossible
    jnz  .tlv_invalid
    lea  rdi, [rbx + rdx + 2]
    mov  ecx, r15d
    xor  eax, eax
    jmp  .tlv_out
.tlv_truncated:
    mov  eax, SAFE_BUF_TRUNCATED
    jmp  .tlv_reject
.tlv_bounds:
    mov  eax, SAFE_BUF_BOUNDS
    jmp  .tlv_reject
.tlv_invalid:
    mov  eax, SAFE_BUF_INVALID
.tlv_reject:
    xor  edx, edx
    xor  ecx, ecx
.tlv_out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Deterministic boot KAT. Canary checks prove that success, truncation and
; rejection cannot write beyond the promised destination.
safe_buffer_selftest:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  byte [rel safe_buffer_kat_ok], 0

    lea  rdi, [rel safe_kat_dst]
    mov  esi, 4
    lea  rdx, [rel safe_kat_src]
    mov  ecx, 5
    call safe_copy
    cmp  eax, SAFE_BUF_TRUNCATED
    jne  .kat_fail
    cmp  edx, 3
    jne  .kat_fail
    cmp  dword [rel safe_kat_dst], 0x00434241 ; "ABC\0"
    jne  .kat_fail
    cmp  byte [rel safe_kat_dst + 4], 0xA5
    jne  .kat_fail

    mov  rax, 0xA5A5A5A5A5A5A5A5
    mov  [rel safe_kat_dst], rax
    lea  rdi, [rel safe_kat_dst]
    mov  esi, 1
    lea  rdx, [rel safe_kat_src]
    mov  ecx, 1
    call safe_copy
    cmp  eax, SAFE_BUF_TRUNCATED
    jne  .kat_fail
    cmp  byte [rel safe_kat_dst], 0
    jne  .kat_fail
    cmp  byte [rel safe_kat_dst + 1], 0xA5
    jne  .kat_fail

    lea  rdi, [rel safe_kat_src]
    mov  esi, 8
    call safe_capped_len
    cmp  rax, 5
    jne  .kat_fail
    test edx, edx
    jnz  .kat_fail
    lea  rdi, [rel safe_kat_unterminated]
    mov  esi, 4
    call safe_capped_len
    cmp  rax, 4
    jne  .kat_fail
    cmp  edx, SAFE_BUF_TRUNCATED
    jne  .kat_fail

    mov  rdi, -1
    mov  esi, 1
    call safe_checked_add
    test rax, rax
    jnz  .kat_fail
    cmp  edx, SAFE_BUF_BOUNDS
    jne  .kat_fail
    mov  edi, 6
    mov  esi, 7
    call safe_checked_mul
    cmp  rax, 42
    jne  .kat_fail
    test edx, edx
    jnz  .kat_fail
    mov  rdi, 1
    shl  rdi, 63
    mov  esi, 2
    call safe_checked_mul
    test rax, rax
    jnz  .kat_fail
    cmp  edx, SAFE_BUF_BOUNDS
    jne  .kat_fail

    lea  rdi, [rel safe_kat_span]
    mov  esi, 8
    mov  edx, 7
    mov  ecx, 1
    call safe_span_validate
    test eax, eax
    jnz  .kat_fail
    lea  rax, [rel safe_kat_span + 7]
    cmp  rdx, rax
    jne  .kat_fail
    lea  rdi, [rel safe_kat_span]
    mov  esi, 8
    mov  edx, 7
    mov  ecx, 2
    call safe_span_validate
    cmp  eax, SAFE_BUF_BOUNDS
    jne  .kat_fail

    lea  rdi, [rel safe_kat_tlv_good]
    lea  rsi, [rel safe_kat_tlv_good_end]
    lea  rdx, [rel safe_kat_tlv_out]
    mov  ecx, 2
    call safe_tlv_u8_read
    test eax, eax
    jnz  .kat_fail
    cmp  ecx, 53
    jne  .kat_fail
    cmp  edx, 1
    jne  .kat_fail
    cmp  word [rel safe_kat_tlv_out], 2
    jne  .kat_fail
    lea  rax, [rel safe_kat_tlv_good_end]
    cmp  rdi, rax
    jne  .kat_fail

    mov  rax, 0xA5A5A5A5A5A5A5A5
    mov  [rel safe_kat_tlv_out], rax
    lea  rdi, [rel safe_kat_tlv_bad]
    lea  rsi, [rel safe_kat_tlv_bad_end]
    lea  rdx, [rel safe_kat_tlv_out]
    mov  ecx, 4
    call safe_tlv_u8_read
    cmp  eax, SAFE_BUF_TRUNCATED
    jne  .kat_fail
    cmp  byte [rel safe_kat_tlv_out], 0
    jne  .kat_fail
    cmp  byte [rel safe_kat_tlv_out + 4], 0xA5
    jne  .kat_fail

    lea  rdi, [rel str_safe_buffer_kat_pass]
    call serial_string
    mov  byte [rel safe_buffer_kat_ok], 1
    xor  eax, eax
    jmp  .kat_out
.kat_fail:
    lea  rdi, [rel str_safe_buffer_kat_fail]
    call serial_string
    mov  rax, -1
.kat_out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

safe_kat_src:          db "ABCDE", 0
safe_kat_unterminated: db "WXYZ"
safe_kat_tlv_good:     db 53, 1, 2
safe_kat_tlv_good_end:
safe_kat_tlv_bad:      db 54, 4, 1, 2
safe_kat_tlv_bad_end:
safe_kat_span:         times 8 db 0
safe_kat_dst:          times 8 db 0xA5
safe_kat_tlv_out:      times 8 db 0xA5
safe_buffer_kat_ok:    db 0
network_parser_bounds_kat_ok: db 0
str_safe_buffer_kat_pass: db "[PAOS64] security: safe buffer copy/strnlen/arithmetic KAT PASS [security.safe_buffer.kat]",13,10,0
str_safe_buffer_kat_fail: db "[PAOS64] security: safe buffer KAT FAIL",13,10,0
