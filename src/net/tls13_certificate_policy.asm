;; MODULE net/tls13_certificate_policy
;; LAYER 4
;; PURPOSE Bounded ordinary TLS certificate policy after existing cryptographic anchoring.
;; EXPORTS tls13_cert_policy, tlscp_der
;; IMPORTS
;; CAPS
;; OWNER saga:net
;; CONTEXT: bsp_only
; Internal ABI, no IO: RDI={DER pointer:u64,length:u64} array, ESI=count1..8,
; RDX=original ASCII DNS reference, ECX=len1..200, R8=UTC seconds,
; R9D=cryptographically verified existing anchor path1(included)/2(omitted).
; RAX=0/-1, EDX=reason (1input/2DER/3date/4name/5constraints/6link).
; This leaf does NOT verify signatures or select trust. The caller must first
; authenticate every signature against the existing local ISRG Root X1 key.
; Exact Name DER equality is a conservative subset, not general X.501 matching.
TLSCP_MAX_CERT equ 8
TLSCP_MAX_DER equ 32768
TLSCP_MAX_EXT equ 32

tls13_cert_policy:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov dword [rel tlscp_reason], 1
    mov [rel tlscp_views], rdi
    mov [rel tlscp_count], esi
    mov [rel tlscp_host], rdx
    mov [rel tlscp_host_len], ecx
    mov [rel tlscp_now], r8
    mov dword [rel tlscp_index], 0
    mov qword [rel tlscp_prev_issuer_len], 0
    test rdi, rdi
    jz .fail
    test esi, esi
    jz .fail
    cmp esi, TLSCP_MAX_CERT
    ja .fail
    cmp r9d, 1
    je .included
    cmp r9d, 2
    jne .fail
    jmp .time
.included:
    cmp esi, 2
    jb .fail
    dec dword [rel tlscp_count] ; exact root bytes already verified by caller
.time:
    test r8, r8
    jz .fail
    mov rax, 253402300799         ; 9999-12-31T23:59:59Z
    cmp r8, rax
    ja .fail
    call tlscp_reference
    test eax, eax
    jnz .fail
.next:
    mov eax, [rel tlscp_index]
    shl eax, 4
    add rax, [rel tlscp_views]
    mov rdi, [rax]
    mov rsi, [rax+8]
    test rdi, rdi
    jz .fail
    cmp rsi, 1
    jb .fail
    cmp rsi, TLSCP_MAX_DER
    ja .fail
    add rsi, rdi
    jc .fail
    call tlscp_certificate
    test eax, eax
    jnz .fail
    inc dword [rel tlscp_index]
    mov eax, [rel tlscp_index]
    cmp eax, [rel tlscp_count]
    jb .next
    ; The final child issuer must be the exact subject of the fixed local root.
    lea rdi, [rel tlscp_anchor_name]
    mov ecx, tlscp_anchor_name_end-tlscp_anchor_name
    cmp rcx, [rel tlscp_prev_issuer_len]
    jne .link
    mov rsi, [rel tlscp_prev_issuer]
    repe cmpsb
    jne .link
    xor eax, eax
    xor edx, edx
    jmp .out
.link:
    mov dword [rel tlscp_reason], 6
.fail:
    mov rax, -1
    mov edx, [rel tlscp_reason]
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Strict supported DNS reference: ASCII LDH labels, max63, no trailing dot,
; wildcard, IP literal, CN fallback or IDNA transformation. At least one letter.
tlscp_reference:
    mov rdi, [rel tlscp_host]
    mov ecx, [rel tlscp_host_len]
tlscp_dns_name:
    test rdi, rdi
    jz .bad
    test ecx, ecx
    jz .bad
    cmp ecx, 200
    ja .bad
    xor edx, edx                    ; current label length
    xor r8d, r8d                    ; saw letter
    xor r9d, r9d                    ; previous character
.loop:
    movzx eax, byte [rdi]
    inc rdi
    cmp al, '.'
    je .dot
    cmp al, '-'
    je .hyphen
    cmp al, '0'
    jb .bad
    cmp al, '9'
    jbe .char
    or al, 32
    cmp al, 'a'
    jb .bad
    cmp al, 'z'
    ja .bad
    mov r8d, 1
    jmp .char
.hyphen:
    test edx, edx
    jz .bad
.char:
    inc edx
    cmp edx, 63
    ja .bad
    mov r9b, al
    jmp .advance
.dot:
    test edx, edx
    jz .bad
    cmp r9b, '-'
    je .bad
    xor edx, edx
.advance:
    dec ecx
    jnz .loop
    test edx, edx
    jz .bad
    cmp r9b, '-'
    je .bad
    test r8d, r8d
    jz .bad
    xor eax, eax
    ret
.bad:
    mov eax, -1
    ret

; DER cursor RDI..RSI. CF=0 EAX=single-byte tag,RDX=value,RCX=len,RDI=next.
; Definite shortest lengths <=32768 only; no indefinite/high-tag encodings.
tlscp_der:
    cmp rdi, rsi
    jae .bad
    movzx eax, byte [rdi]
    inc rdi
    mov r10d, eax
    and r10d, 31
    cmp r10d, 31
    je .bad
    test eax, eax
    jz .bad
    cmp rdi, rsi
    jae .bad
    movzx ecx, byte [rdi]
    inc rdi
    cmp ecx, 128
    jb .length
    cmp ecx, 0x81
    je .one
    cmp ecx, 0x82
    jne .bad
    lea r10, [rdi+2]
    cmp r10, rsi
    ja .bad
    movzx ecx, byte [rdi]
    test ecx, ecx
    jz .bad
    shl ecx, 8
    mov cl, [rdi+1]
    add rdi, 2
    cmp ecx, 256
    jb .bad
    jmp .length
.one:
    cmp rdi, rsi
    jae .bad
    movzx ecx, byte [rdi]
    inc rdi
    cmp ecx, 128
    jb .bad
.length:
    cmp ecx, TLSCP_MAX_DER
    ja .bad
    mov rdx, rdi
    add rdi, rcx
    jc .bad
    cmp rdi, rsi
    ja .bad
    clc
    ret
.bad:
    stc
    ret

; Canonical OID contents RDX/RCX, no nonminimal base128 or unterminated arc.
; Preserves cursor/length and policy registers.
tlscp_oid_valid:
    test rcx, rcx
    jz .bad
    cmp rcx, 64
    ja .bad
    xor r10d, r10d
.arc:
    cmp byte [rdx+r10], 0x80
    je .bad
.byte:
    mov al, [rdx+r10]
    inc r10
    test al, 128
    jz .end_arc
    cmp r10, rcx
    jae .bad
    jmp .byte
.end_arc:
    cmp r10, rcx
    jb .arc
    xor eax, eax
    ret
.bad:
    mov eax, -1
    ret

; Validate the conservative Name DER subset: <=32 nonempty single-attribute
; RDN SETs, exact OID and ASCII UTF8/Printable/IA5 values. Reject multi-valued
; RDNs rather than accepting a noncanonical SET ordering. Original next/end
; and callee-saved parser state preserved. Empty names deliberately unsupported.
tlscp_name:
    push rdi
    push rsi
    push rbx
    push rbp
    mov rsi, rdi
    mov rdi, rdx
    xor ebx, ebx
.rdn:
    cmp rdi, rsi
    jae .done
    inc ebx
    cmp ebx, 32
    ja .bad
    call tlscp_der
    jc .bad
    cmp eax, 49
    jne .bad
    mov rbp, rdi
    push rsi
    mov rsi, rdi
    mov rdi, rdx
    call tlscp_der
    jc .inner_bad
    cmp eax, 48
    jne .inner_bad
    cmp rdi, rsi                  ; exactly one AttributeTypeAndValue
    jne .inner_bad
    mov rdi, rdx
    call tlscp_der
    jc .inner_bad
    cmp eax, 6
    jne .inner_bad
    call tlscp_oid_valid
    test eax, eax
    jnz .inner_bad
    call tlscp_der
    jc .inner_bad
    cmp eax, 12
    je .string
    cmp eax, 19
    je .string
    cmp eax, 22
    jne .inner_bad
.string:
    mov r11d, eax                 ; PrintableString has a smaller alphabet
    cmp rdi, rsi
    jne .inner_bad
    test rcx, rcx
    jz .inner_bad
    cmp rcx, 200
    ja .inner_bad
.ascii:
    mov al, [rdx]
    cmp al, 32
    jb .inner_bad
    cmp al, 126
    ja .inner_bad
    cmp r11d, 19
    jne .char_ok
    cmp al, '0'
    jb .punctuation
    cmp al, '9'
    jbe .char_ok
    cmp al, 'A'
    jb .punctuation
    cmp al, 'Z'
    jbe .char_ok
    cmp al, 'a'
    jb .punctuation
    cmp al, 'z'
    jbe .char_ok
.punctuation:
    lea r10, [rel tlscp_printable_punctuation]
    push rcx
    mov ecx, 12
.punct:
    cmp al, [r10]
    je .punct_ok
    inc r10
    loop .punct
    pop rcx
    jmp .inner_bad
.punct_ok:
    pop rcx
.char_ok:
    inc rdx
    dec ecx
    jnz .ascii
    pop rsi
    mov rdi, rbp
    jmp .rdn
.done:
    test ebx, ebx
    jz .bad
    xor eax, eax
    jmp .out
.inner_bad:
    pop rsi
.bad:
    mov eax, -1
.out:
    pop rbp
    pop rbx
    pop rsi
    pop rdi
    ret

; Strict RSA SPKI nested consumption; original crypto parser uses the same
; rsaEncryption/NULL/exponent65537 and fixed2048/4096 widths. Preserve caller
; cursor/end. DER positive modulus needs one sign octet and exact full width.
tlscp_spki:
    push rdi
    push rsi
    mov rsi, rdi
    mov rdi, rdx
    call tlscp_der
    jc .bad
    cmp eax, 48
    jne .bad
    cmp rcx, 13
    jne .bad
    cmp word [rdx], 0x0906
    jne .bad
    mov r10, 0x01010df78648862a
    cmp [rdx+2], r10
    jne .bad
    cmp byte [rdx+10], 1
    jne .bad
    cmp word [rdx+11], 5
    jne .bad
    call tlscp_der
    jc .bad
    cmp eax, 3
    jne .bad
    cmp rdi, rsi
    jne .bad
    cmp rcx, 2
    jb .bad
    cmp byte [rdx], 0
    jne .bad
    lea rdi, [rdx+1]
    call tlscp_der
    jc .bad
    cmp eax, 48
    jne .bad
    cmp rdi, rsi
    jne .bad
    mov rdi, rdx
    call tlscp_der
    jc .bad
    cmp eax, 2
    jne .bad
    cmp rcx, 257
    je .modulus
    cmp rcx, 513
    jne .bad
.modulus:
    cmp byte [rdx], 0
    jne .bad
    test byte [rdx+1], 128
    jz .bad
    test byte [rdi-1], 1
    jz .bad
    call tlscp_der
    jc .bad
    cmp eax, 2
    jne .bad
    cmp rdi, rsi
    jne .bad
    cmp rcx, 3
    jne .bad
    cmp word [rdx], 1
    jne .bad
    cmp byte [rdx+2], 1
    jne .bad
    xor eax, eax
    jmp .out
.bad:
    mov eax, -1
.out:
    pop rsi
    pop rdi
    ret

; Positive canonical INTEGER <=65535. RDX=value,RCX=len -> EAX=value,CF.
tlscp_uint:
    test rcx, rcx
    jz .bad
    cmp rcx, 3
    ja .bad
    test byte [rdx], 128
    jnz .bad
    cmp rcx, 1
    je .parse
    cmp byte [rdx], 0
    jne .parse
    test byte [rdx+1], 128
    jz .bad
.parse:
    xor eax, eax
.loop:
    shl eax, 8
    movzx r10d, byte [rdx]
    or eax, r10d
    inc rdx
    dec ecx
    jnz .loop
    cmp eax, 65535
    ja .bad
    clc
    ret
.bad:
    stc
    ret

; Date value/tag -> signed Unix seconds. Strict RFC5280 time syntax/calendars.
tlscp_date:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    mov r12, rdx
    cmp eax, 23
    je .utc
    cmp eax, 24
    jne .bad
    cmp ecx, 15
    jne .bad
    call tlscp_decimal2
    jc .bad
    imul ebx, eax, 100
    call tlscp_decimal2
    jc .bad
    add ebx, eax
    cmp ebx, 2050
    jb .bad
    cmp ebx, 9999
    ja .bad
    jmp .month
.utc:
    cmp ecx, 13
    jne .bad
    call tlscp_decimal2
    jc .bad
    mov ebx, eax
    add ebx, 1900
    cmp eax, 50
    jae .month
    add ebx, 100
.month:
    call tlscp_decimal2
    jc .bad
    cmp eax, 1
    jb .bad
    cmp eax, 12
    ja .bad
    mov ebp, eax
    call tlscp_decimal2
    jc .bad
    mov r13d, eax                  ; day
    test eax, eax
    jz .bad
    lea rdx, [rel tlscp_month_days]
    movzx r14d, byte [rdx+rbp-1]
    ; Gregorian leap if divisible4 and (not100 or divisible400).
    xor r11d, r11d
    mov eax, ebx
    test eax, 3
    jnz .leap_done
    xor edx, edx
    mov ecx, 100
    div ecx
    test edx, edx
    jnz .leap
    mov eax, ebx
    xor edx, edx
    mov ecx, 400
    div ecx
    test edx, edx
    jnz .leap_done
.leap:
    mov r11d, 1
    cmp ebp, 2
    jne .leap_done
    inc r14d
.leap_done:
    cmp r13d, r14d
    ja .bad
    ; Days before current year: 365*(year-1970)+L(year-1)-L(1969).
    mov eax, ebx
    sub eax, 1970
    imul eax, 365
    movsxd r14, eax
    dec ebx
    mov eax, ebx
    shr eax, 2
    add r14, rax
    mov eax, ebx
    xor edx, edx
    mov ecx, 100
    div ecx
    sub r14, rax
    mov eax, ebx
    xor edx, edx
    mov ecx, 400
    div ecx
    add r14, rax
    sub r14, 477
    lea rdx, [rel tlscp_month_offsets]
    movzx eax, word [rdx+rbp*2-2]
    add r14, rax
    cmp ebp, 2
    jbe .day
    add r14, r11
.day:
    lea eax, [r13-1]
    add r14, rax
    imul r14, 86400
    call tlscp_decimal2
    jc .bad
    cmp eax, 23
    ja .bad
    imul eax, 3600
    add r14, rax
    call tlscp_decimal2
    jc .bad
    cmp eax, 59
    ja .bad
    imul eax, 60
    add r14, rax
    call tlscp_decimal2
    jc .bad
    cmp eax, 59
    ja .bad
    add r14, rax
    cmp byte [r12], 'Z'
    jne .bad
    mov rax, r14
    clc
    jmp .out
.bad:
    stc
.out:
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
; Date helper has a fixed proven input length, consumes two decimal characters.
tlscp_decimal2:
    movzx eax, byte [r12]
    sub eax, '0'
    cmp eax, 9
    ja .bad
    imul eax, 10
    movzx edx, byte [r12+1]
    sub edx, '0'
    cmp edx, 9
    ja .bad
    add eax, edx
    add r12, 2
    clc
    ret
.bad:
    stc
    ret

; Parse full cert structure. Only policy fields are used; original crypto parser
; verifies RSA SPKI, outer signature and TBS. Inner/outer algorithms must match.
tlscp_certificate:
    mov dword [rel tlscp_reason], 2
    call tlscp_der
    jc .bad
    cmp eax, 48
    jne .bad
    cmp rdi, rsi
    jne .bad
    mov rdi, rdx
    ; TBS full span, algorithm full span, signature BIT STRING.
    call tlscp_der
    jc .bad
    cmp eax, 48
    jne .bad
    mov r12, rdx
    mov r13, rdi                   ; TBS end
    mov r14, rdi                   ; outer algorithm start
    call tlscp_der
    jc .bad
    cmp eax, 48
    jne .bad
    mov r15, rdi
    sub r15, r14                   ; outer algorithm TLV length
    call tlscp_der
    jc .bad
    cmp eax, 3
    jne .bad
    cmp rcx, 2
    jb .bad
    cmp byte [rdx], 0
    jne .bad
    cmp rdi, rsi
    jne .bad
    mov rdi, r12
    mov rsi, r13
    call tlscp_der
    jc .bad
    cmp eax, 0xa0
    jne .bad
    cmp rcx, 3
    jne .bad
    cmp word [rdx], 0x0102
    jne .bad
    cmp byte [rdx+2], 2            ; X.509v3 only
    jne .bad
    call tlscp_der                ; positive nonzero serial <=20bytes
    jc .bad
    cmp eax, 2
    jne .bad
    test rcx, rcx
    jz .bad
    cmp rcx, 20
    ja .bad
    test byte [rdx], 128
    jnz .bad
    cmp rcx, 1
    je .serial_one
    cmp byte [rdx], 0
    jne .serial_ok
    test byte [rdx+1], 128
    jz .bad
    jmp .serial_ok
.serial_one:
    cmp byte [rdx], 0
    je .bad
.serial_ok:
    mov rbx, rdi
    call tlscp_der                ; signatureAlgorithm exact same DER
    jc .bad
    cmp eax, 48
    jne .bad
    mov rbp, rdi
    sub rbp, rbx
    cmp rbp, r15
    jne .bad
    push rdi
    push rsi
    mov rdi, rbx
    mov rsi, r14
    mov rcx, rbp
    repe cmpsb
    pop rsi
    pop rdi
    jne .bad
    mov rbx, rdi
    call tlscp_der                ; issuer Name full span
    jc .bad
    cmp eax, 48
    jne .bad
    test rcx, rcx
    jz .bad
    call tlscp_name
    test eax, eax
    jnz .bad
    mov [rel tlscp_issuer], rbx
    mov rax, rdi
    sub rax, rbx
    mov [rel tlscp_issuer_len], rax
    call tlscp_der                ; Validity, exactly two dates
    jc .bad
    cmp eax, 48
    jne .bad
    push rdi
    push rsi
    mov rdi, rdx
    mov rsi, [rsp+8]
    mov dword [rel tlscp_reason], 3
    call tlscp_der
    jc .validity_bad
    call tlscp_date
    jc .validity_bad
    mov rbx, rax
    cmp rax, [rel tlscp_now]
    jg .validity_bad
    call tlscp_der
    jc .validity_bad
    call tlscp_date
    jc .validity_bad
    cmp rax, rbx
    jl .validity_bad
    cmp rax, [rel tlscp_now]
    jl .validity_bad
    cmp rdi, rsi
    jne .validity_bad
    pop rsi
    pop rdi
    mov dword [rel tlscp_reason], 2
    mov rbx, rdi
    call tlscp_der                ; subject Name span
    jc .bad
    cmp eax, 48
    jne .bad
    test rcx, rcx
    jz .bad                      ; conservative subset requires nonempty DN
    call tlscp_name
    test eax, eax
    jnz .bad
    cmp dword [rel tlscp_index], 0
    je .subject_ok
    mov dword [rel tlscp_reason], 6
    mov rax, rdi
    sub rax, rbx
    cmp rax, [rel tlscp_prev_issuer_len]
    jne .bad
    push rdi
    push rsi
    mov rdi, rbx
    mov rsi, [rel tlscp_prev_issuer]
    mov rcx, rax
    repe cmpsb
    pop rsi
    pop rdi
    jne .bad
.subject_ok:
    mov dword [rel tlscp_reason], 2
    call tlscp_der                ; same RSA SPKI, exact nested DER consumption
    jc .bad
    cmp eax, 48
    jne .bad
    call tlscp_spki
    test eax, eax
    jnz .bad
    call tlscp_der                ; extensions [3], no issuer/subject uniqueID
    jc .bad
    cmp eax, 0xa3
    jne .bad
    cmp rdi, rsi
    jne .bad
    mov rsi, rdi
    mov rdi, rdx
    call tlscp_der
    jc .bad
    cmp eax, 48
    jne .bad
    cmp rdi, rsi
    jne .bad
    mov rdi, rdx
    call tlscp_extensions
    test eax, eax
    jnz .bad
    mov rax, [rel tlscp_issuer]
    mov [rel tlscp_prev_issuer], rax
    mov rax, [rel tlscp_issuer_len]
    mov [rel tlscp_prev_issuer_len], rax
    xor eax, eax
    ret
.validity_bad:
    pop rsi
    pop rdi
.bad:
    mov eax, -1
    ret

; Extension vector, bounded32 and duplicate OIDs rejected including noncritical.
tlscp_extensions:
    mov r12, rdi
    mov r13, rsi
    mov dword [rel tlscp_ext_count], 0
    mov byte [rel tlscp_ca], 0
    mov byte [rel tlscp_basic], 0
    mov byte [rel tlscp_matched], 0
.loop:
    cmp r12, r13
    jae .done
    mov dword [rel tlscp_reason], 2
    mov rdi, r12
    mov rsi, r13
    call tlscp_der
    jc .bad
    cmp eax, 48
    jne .bad
    mov r12, rdi
    mov r15, rdi                 ; extension end
    mov rdi, rdx
    mov rsi, r15
    call tlscp_der
    jc .bad
    cmp eax, 6
    jne .bad
    test rcx, rcx
    jz .bad
    cmp rcx, 64
    ja .bad
    call tlscp_oid_valid
    test eax, eax
    jnz .bad
    mov [rel tlscp_oid], rdx
    mov [rel tlscp_oid_len], rcx
    mov r14, rdi
    xor ebx, ebx
.duplicate:
    cmp ebx, [rel tlscp_ext_count]
    jae .new_oid
    lea rbp, [rel tlscp_ext_oids]
    mov eax, ebx
    shl eax, 4
    add rbp, rax
    cmp rcx, [rbp+8]
    jne .next_oid
    mov rsi, [rbp]
    mov rdi, rdx
    push rcx
    repe cmpsb
    pop rcx
    je .bad
.next_oid:
    inc ebx
    jmp .duplicate
.new_oid:
    cmp ebx, TLSCP_MAX_EXT
    jae .bad
    lea rbp, [rel tlscp_ext_oids]
    mov eax, ebx
    shl eax, 4
    add rbp, rax
    mov [rbp], rdx
    mov [rbp+8], rcx
    inc dword [rel tlscp_ext_count]
    mov rdi, r14
    mov rsi, r15
    mov byte [rel tlscp_critical], 0
    call tlscp_der
    jc .bad
    cmp eax, 1
    jne .value
    cmp rcx, 1
    jne .bad
    cmp byte [rdx], 255          ; DEFAULT FALSE must be omitted in DER
    jne .bad
    mov byte [rel tlscp_critical], 1
    call tlscp_der
    jc .bad
.value:
    cmp eax, 4
    jne .bad
    cmp rdi, r15
    jne .bad
    mov rdi, rdx
    mov rsi, r15                 ; outer OCTET STRING value fills extension
    mov rax, [rel tlscp_oid]
    cmp qword [rel tlscp_oid_len], 3
    jne .unknown
    cmp word [rax], 0x1d55
    jne .unknown
    movzx eax, byte [rax+2]
    cmp eax, 19
    je .basic
    cmp eax, 15
    je .usage
    cmp eax, 37
    je .purpose
    cmp eax, 17
    je .san
    ; Unsupported path constraints are refused even when noncritical.
    cmp eax, 30
    je .constraint
    cmp eax, 33
    je .constraint
    cmp eax, 36
    je .constraint
    cmp eax, 54
    je .constraint
.unknown:
    cmp byte [rel tlscp_critical], 0
    jne .constraint
    jmp .loop
.basic:
    mov byte [rel tlscp_basic], 1
    call tlscp_der
    jc .bad
    cmp eax, 48
    jne .bad
    cmp rdi, rsi
    jne .bad
    mov rdi, rdx
    cmp rdi, rsi
    je .basic_done
    call tlscp_der
    jc .bad
    cmp eax, 1
    jne .constraint
    cmp rcx, 1
    jne .bad
    cmp byte [rdx], 255
    jne .bad
    mov byte [rel tlscp_ca], 1
    cmp rdi, rsi
    je .basic_done
    call tlscp_der
    jc .bad
    cmp eax, 2
    jne .bad
    cmp rdi, rsi
    jne .bad
    call tlscp_uint
    jc .bad
    mov ecx, [rel tlscp_index]
    test ecx, ecx
    jz .constraint
    dec ecx                      ; number of CA certs below this issuer
    cmp ecx, eax
    ja .constraint
.basic_done:
    cmp dword [rel tlscp_index], 0
    je .basic_leaf
    cmp byte [rel tlscp_ca], 1
    jne .constraint
    cmp byte [rel tlscp_critical], 1
    jne .constraint
    jmp .loop
.basic_leaf:
    cmp byte [rel tlscp_ca], 0
    jne .constraint
    jmp .loop
.usage:
    call tlscp_der
    jc .bad
    cmp eax, 3
    jne .bad
    cmp rdi, rsi
    jne .bad
    cmp rcx, 2
    jb .bad
    cmp rcx, 3
    ja .bad
    cmp rcx, 3
    jne .ku_one_byte
    cmp byte [rdx+2], 128
    jne .constraint
    test byte [rdx+1], 8
    jz .constraint
.ku_one_byte:
    test byte [rdx+1], 1
    jz .ku_bits_ok
    test byte [rdx+1], 8
    jz .constraint
.ku_bits_ok:
    movzx ecx, byte [rdx]
    cmp ecx, 7
    ja .bad
    ; DER named bit list: last byte nonzero, unused bits zero, final bit set.
    movzx eax, byte [rdi-1]
    test eax, eax
    jz .bad
    mov r10d, 1
    shl r10d, cl
    test eax, r10d
    jz .bad
    dec r10d
    test eax, r10d
    jnz .bad
    cmp dword [rel tlscp_index], 0
    jne .ca_usage
    test byte [rdx+1], 128
    jz .constraint
    jmp .loop
.ca_usage:
    test byte [rdx+1], 4
    jz .constraint
    jmp .loop
.purpose:
    call tlscp_der
    jc .bad
    cmp eax, 48
    jne .bad
    cmp rdi, rsi
    jne .bad
    mov rdi, rdx
    xor ebp, ebp
.eku:
    cmp rdi, rsi
    jae .eku_done
    call tlscp_der
    jc .bad
    cmp eax, 6
    jne .bad
    test rcx, rcx
    jz .bad
    call tlscp_oid_valid
    test eax, eax
    jnz .bad
    cmp rcx, 8
    jne .eku
    ; Match full OID, not a prefix or peer-selected purpose.
    mov rax, 0x010307050501062b
    cmp qword [rdx], rax
    jne .eku
    mov ebp, 1
    jmp .eku
.eku_done:
    test ebp, ebp
    jz .constraint
    jmp .loop
.san:
    call tlscp_der
    jc .bad
    cmp eax, 48
    jne .bad
    cmp rdi, rsi
    jne .bad
    mov rdi, rdx
.san_next:
    cmp rdi, rsi
    jae .loop
    call tlscp_der
    jc .bad
    cmp eax, 0x82
    je .dns
    cmp eax, 0x87
    jne .constraint
    cmp rcx, 4
    je .san_next
    cmp rcx, 16
    je .san_next
    jmp .bad
.dns:
    ; Validate every presented DNS SAN, including nonmatching/issuer names.
    ; Reuse exact supported reference grammar; no hidden alternate identity.
    push rdi
    push rsi
    push rdx
    push rcx
    mov rdi, rdx
    call tlscp_dns_name
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    test eax, eax
    jnz .constraint
    cmp dword [rel tlscp_index], 0
    jne .san_next
    cmp ecx, [rel tlscp_host_len]
    jne .san_next
    mov rbp, [rel tlscp_host]
    xor ebx, ebx
.match:
    mov al, [rdx+rbx]
    mov r10b, [rbp+rbx]
    or al, 32
    or r10b, 32
    cmp al, r10b
    jne .san_next
    inc ebx
    cmp rbx, rcx
    jb .match
    mov byte [rel tlscp_matched], 1
    jmp .san_next
.done:
    mov dword [rel tlscp_reason], 5
    cmp byte [rel tlscp_basic], 1
    jne .bad
    cmp dword [rel tlscp_index], 0
    jne .good
    mov dword [rel tlscp_reason], 4
    cmp byte [rel tlscp_matched], 1
    jne .bad
.good:
    xor eax, eax
    ret
.constraint:
    mov dword [rel tlscp_reason], 5
.bad:
    mov eax, -1
    ret

tlscp_printable_punctuation: db " '()+,-./:=?"
tlscp_month_days: db 31,28,31,30,31,30,31,31,30,31,30,31
tlscp_month_offsets: dw 0,31,59,90,120,151,181,212,243,273,304,334
; Exact DER subject from the already-compiled ISRG Root X1 (SHA25696bcec06...).
tlscp_anchor_name:
    db 0x30,0x4f,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x06,0x13,0x02,0x55,0x53,0x31,0x29,0x30,0x27,0x06,0x03,0x55,0x04,0x0a,0x13,0x20,0x49,0x6e,0x74,0x65,0x72,0x6e,0x65,0x74,0x20,0x53,0x65,0x63,0x75,0x72,0x69,0x74,0x79,0x20,0x52,0x65,0x73,0x65,0x61,0x72,0x63,0x68,0x20,0x47,0x72,0x6f,0x75,0x70,0x31,0x15,0x30,0x13,0x06,0x03,0x55,0x04,0x03,0x13,0x0c,0x49,0x53,0x52,0x47,0x20,0x52,0x6f,0x6f,0x74,0x20,0x58,0x31
tlscp_anchor_name_end:
%macro WDATA_net_tls13_certificate_policy 0
align 8
tlscp_views: dq 0
tlscp_host: dq 0
tlscp_now: dq 0
tlscp_issuer: dq 0
tlscp_issuer_len: dq 0
tlscp_prev_issuer: dq 0
tlscp_prev_issuer_len: dq 0
tlscp_oid: dq 0
tlscp_oid_len: dq 0
tlscp_count: dd 0
tlscp_index: dd 0
tlscp_host_len: dd 0
tlscp_ext_count: dd 0
tlscp_reason: dd 0
tlscp_ca: db 0
tlscp_basic: db 0
tlscp_matched: db 0
tlscp_critical: db 0
align 8
tlscp_ext_oids: times TLSCP_MAX_EXT*2 dq 0
%endmacro
WDATA_DEFER WDATA_net_tls13_certificate_policy
