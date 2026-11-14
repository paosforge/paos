;; MODULE security/sensitive_classifier
;; LAYER 4
;; EXPORTS sensitive_classify, sensitive_classifier_selftest, sensitive_classifier_matrix
;; IMPORTS web/bounded_field_reader, lib/safe_buffer, boot/serial
;; CAPS
;; OWNER saga:agent_privacy
; Task3305: bounded local span classifier; no transport or raw-value logging.
;
; Detector version 1 / ABI 1. This is detection, not anonymization. Coverage:
; ASCII dot-atom email (multi-label DNS domain); formatted US SSN; 13..19
; digit Luhn cards (contiguous or four-digit hyphen groups); +E.164 (8..15
; digits) and NANP NXX-NXX-XXXX / NXX.NXX.XXXX; dotted IPv4; hex IPv6 with
; one optional :: (no zone IDs or embedded IPv4). No substring salvage from
; malformed maximal tokens. Space-grouped numbers, addresses, international
; IDs, Unicode email, and other ambiguous formats need preview/manual marks.
; Context: exact case-insensitive account/acct, secret/token/password/api_key,
; followed by ':' or '=' and at most 32 separator bytes. Account values are
; 6..20 digits; secrets are 8..128 ASCII letters/digits/_/- with both a letter
; and a digit. Context is cleared by any intervening token. No semantic PII
; inference, recursive grammar, allocation, retained input or value hashes.
;
; All bracket nesting is checked (cap 8); maximal token cap 256. UTF-8 must
; be shortest-form Unicode scalars, without NUL or non-whitespace controls.
; Caller spans must start/end at UTF-8 boundaries. Candidate cap 64 counts
; ALL detections including overlaps and manual marks. Excess is a refusal.
; Sort key: start ascending, length descending, class ascending. Greedy
; non-overlap selection follows that order (manual has no special override
; over an earlier or longer span). Confidence: 1=context, 2=syntax/checksum,
; 3=explicit owner mark. These are tiers, not probability estimates.

sc_image_begin:
SC_OK          equ 0
SC_BOUNDS      equ 1
SC_MALFORMED   equ 2
SC_TOO_MANY    equ 3
SC_VERSION     equ 1
SC_INPUT_CAP   equ 16384
SC_MATCH_CAP   equ 64
SC_TOKEN_CAP   equ 256
SC_DEPTH_CAP   equ 8
SC_CONTEXT_CAP equ 32
SC_MANUAL      equ 1
SC_SECRET      equ 2
SC_CARD        equ 3
SC_SSN         equ 4
SC_EMAIL       equ 5
SC_PHONE       equ 6
SC_IPV4        equ 7
SC_IPV6        equ 8
SC_SPAN_SIZE   equ 16
; record: +0 start:u32, +4 length:u32, +8 class:u16, +10 tier:u16,
;         +12 detector_version:u32. Manual input: {start:u32,length:u32}.

SC_L_CAND      equ 0                    ; 64 * 16 metadata bytes
SC_L_TOKEN     equ 1024                 ; 256 + NUL
SC_L_BRACKETS  equ 1288                 ; eight expected closing bytes
SC_L_COUNT     equ 1296
SC_L_DEPTH     equ 1300
SC_L_OUT       equ 1304
SC_L_CAP       equ 1312
SC_L_MARKS     equ 1320
SC_L_MARKCOUNT equ 1328
SC_L_CONTEXT   equ 1336                 ; 0 none, 1 secret, 2 account
SC_L_SEP       equ 1340                 ; ':'/'=' seen
SC_L_DISTANCE  equ 1344
SC_L_START     equ 1348
SC_L_LENGTH    equ 1352
SC_L_FRAME     equ 1360

; sensitive_classify(RDI=input, RSI=length, RDX=out, RCX=out capacity in
; records, R8=manual array or NULL, R9=manual count) -> EAX=status, ECX=count.
; Preserves RBX/RBP/R12..R15. Validates all extents before reads/writes.
; Output is untouched on refusal and count=0. Input/output may alias because
; commit occurs after all input reads. Caller supplies readable/writable mapped
; extents; arithmetic validation is not an MMU. Scratch is wiped on every exit.
sensitive_classify:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, SC_L_FRAME
    mov  rbx, rsp
    mov  [rbx + SC_L_OUT], rdx
    mov  [rbx + SC_L_CAP], rcx
    mov  [rbx + SC_L_MARKS], r8
    mov  [rbx + SC_L_MARKCOUNT], r9
    mov  dword [rbx + SC_L_COUNT], 0
    mov  dword [rbx + SC_L_DEPTH], 0
    mov  qword [rbx + SC_L_CONTEXT], 0
    mov  dword [rbx + SC_L_DISTANCE], 0
    cmp  rsi, SC_INPUT_CAP
    ja   .bounds
    cmp  rcx, SC_MATCH_CAP
    ja   .bounds
    cmp  r9, SC_MATCH_CAP
    ja   .many
    mov  r12, rdi
    mov  r13, rsi
    xor  edx, edx
    mov  rcx, rsi
    call safe_span_validate
    test eax, eax
    jnz  .bounds
    add  r13, r12                       ; checked by the primitive
    mov  rdi, [rbx + SC_L_OUT]
    mov  rsi, [rbx + SC_L_CAP]
    shl  rsi, 4                         ; <=64 was checked
    test rsi, rsi
    jz   .output_checked
    xor  edx, edx
    mov  rcx, rsi
    call safe_span_validate
    test eax, eax
    jnz  .bounds
.output_checked:
    mov  rdi, r12
    mov  rsi, r13
    call sc_utf8_validate
    test eax, eax
    jnz  .malformed
    mov  rsi, [rbx + SC_L_MARKCOUNT]
    test rsi, rsi
    jz   .scan_init
    shl  rsi, 3
    mov  rdi, [rbx + SC_L_MARKS]
    mov  rcx, rsi
    xor  edx, edx
    call safe_span_validate
    test eax, eax
    jnz  .bounds
    xor  r14d, r14d
.manual_loop:
    cmp  r14, [rbx + SC_L_MARKCOUNT]
    jae  .scan_init
    mov  rax, [rbx + SC_L_MARKS]
    mov  edx, [rax + r14*8]
    mov  ecx, [rax + r14*8 + 4]
    test ecx, ecx
    jz   .malformed
    mov  [rbx + SC_L_START], edx
    mov  [rbx + SC_L_LENGTH], ecx
    mov  rdi, r12
    mov  rsi, r13
    sub  rsi, r12
    call safe_span_validate
    test eax, eax
    jnz  .bounds
    mov  al, [rdx]
    and  al, 0xc0
    cmp  al, 0x80
    je   .malformed
    add  rdx, rcx
    cmp  rdx, r13
    je   .manual_add
    mov  al, [rdx]
    and  al, 0xc0
    cmp  al, 0x80
    je   .malformed
.manual_add:
    mov  eax, SC_MANUAL
    call sc_candidate_add
    test eax, eax
    jnz  .many
    inc  r14d
    jmp  .manual_loop
.scan_init:
    mov  r14, r12
.scan:
    cmp  r14, r13
    jae  .scanned
    movzx eax, byte [r14]
    call sc_delimiter
    test eax, eax
    jz   .token
    ; Delimiters cannot extend context arbitrarily, or through punctuation.
    inc  dword [rbx + SC_L_DISTANCE]
    cmp  dword [rbx + SC_L_DISTANCE], SC_CONTEXT_CAP
    jbe  .delimiter_kind
    mov  dword [rbx + SC_L_CONTEXT], 0
.delimiter_kind:
    movzx eax, byte [r14]
    cmp  al, '='
    je   .separator
    cmp  al, ' '
    je   .advance
    cmp  al, 9
    je   .advance
    cmp  al, '"'
    je   .advance
    cmp  al, 39
    je   .advance
    mov  dword [rbx + SC_L_CONTEXT], 0
    cmp  al, '('
    je   .open_paren
    cmp  al, '['
    je   .open_square
    cmp  al, '{'
    je   .open_brace
    cmp  al, ')'
    je   .close
    cmp  al, ']'
    je   .close
    cmp  al, '}'
    je   .close
    jmp  .advance
.separator:
    cmp  dword [rbx + SC_L_SEP], 0
    jne  .clear_context
    mov  dword [rbx + SC_L_SEP], 1
    jmp  .advance
.clear_context:
    mov  dword [rbx + SC_L_CONTEXT], 0
    jmp  .advance
.open_paren:
    mov  al, ')'
    jmp  .open
.open_square:
    mov  al, ']'
    jmp  .open
.open_brace:
    mov  al, '}'
.open:
    mov  ecx, [rbx + SC_L_DEPTH]
    cmp  ecx, SC_DEPTH_CAP
    jae  .bounds
    lea  rdx, [rbx + SC_L_BRACKETS]
    mov  [rdx + rcx], al
    inc  dword [rbx + SC_L_DEPTH]
    jmp  .advance
.close:
    mov  ecx, [rbx + SC_L_DEPTH]
    test ecx, ecx
    jz   .malformed
    dec  ecx
    lea  rdx, [rbx + SC_L_BRACKETS]
    cmp  [rdx + rcx], al
    jne  .malformed
    mov  [rbx + SC_L_DEPTH], ecx
.advance:
    inc  r14
    jmp  .scan
.token:
    mov  r15, r14
.token_end:
    cmp  r15, r13
    jae  .read_token
    movzx eax, byte [r15]
    call sc_delimiter
    test eax, eax
    jnz  .read_token
    mov  rax, r15
    sub  rax, r14
    cmp  eax, SC_TOKEN_CAP
    jae  .bounds
    inc  r15
    jmp  .token_end
.read_token:
    mov  rdi, r14
    mov  rsi, r15
    lea  rdx, [rbx + SC_L_TOKEN]
    mov  ecx, SC_TOKEN_CAP + 1
    xor  r8d, r8d
    call web_field_read_bounded
    test eax, eax
    jnz  .malformed
    mov  rax, r15
    sub  rax, r14
    cmp  rdx, rax
    jne  .malformed
    cmp  rcx, rax
    jne  .malformed
    mov  [rbx + SC_L_LENGTH], eax
    mov  rax, r14
    sub  rax, r12
    mov  [rbx + SC_L_START], eax
    ; Exact keyword before ':' splits just that token; IPv6 stays whole.
    lea  rdi, [rbx + SC_L_TOKEN]
    xor  ecx, ecx
.key_extent:
    cmp  ecx, [rbx + SC_L_LENGTH]
    jae  .key_check
    cmp  byte [rdi + rcx], ':'
    je   .key_check
    inc  ecx
    jmp  .key_extent
.key_check:
    call sc_context_key
    test eax, eax
    jz   .detect
    mov  [rbx + SC_L_CONTEXT], eax
    mov  dword [rbx + SC_L_SEP], 0
    mov  dword [rbx + SC_L_DISTANCE], 0
    cmp  ecx, [rbx + SC_L_LENGTH]
    je   .next_token
    mov  dword [rbx + SC_L_SEP], 1
    lea  r14, [r14 + rcx + 1]
    jmp  .scan
.detect:
    ; All validators receive only the complete bounded token. No prefix
    ; matches and no retry inside an invalid token can manufacture a span.
    lea  rdi, [rbx + SC_L_TOKEN]
    mov  ecx, [rbx + SC_L_LENGTH]
    call sc_card
    test eax, eax
    jz   .ssn
    mov  eax, SC_CARD
    call sc_candidate_add
    test eax, eax
    jnz  .many
.ssn:
    lea  rdi, [rbx + SC_L_TOKEN]
    mov  ecx, [rbx + SC_L_LENGTH]
    call sc_ssn
    test eax, eax
    jz   .email
    mov  eax, SC_SSN
    call sc_candidate_add
    test eax, eax
    jnz  .many
.email:
    lea  rdi, [rbx + SC_L_TOKEN]
    mov  ecx, [rbx + SC_L_LENGTH]
    call sc_email
    test eax, eax
    jz   .phone
    mov  eax, SC_EMAIL
    call sc_candidate_add
    test eax, eax
    jnz  .many
.phone:
    lea  rdi, [rbx + SC_L_TOKEN]
    mov  ecx, [rbx + SC_L_LENGTH]
    call sc_phone
    test eax, eax
    jz   .ipv4
    mov  eax, SC_PHONE
    call sc_candidate_add
    test eax, eax
    jnz  .many
.ipv4:
    lea  rdi, [rbx + SC_L_TOKEN]
    mov  ecx, [rbx + SC_L_LENGTH]
    call sc_ipv4
    test eax, eax
    jz   .ipv6
    mov  eax, SC_IPV4
    call sc_candidate_add
    test eax, eax
    jnz  .many
.ipv6:
    lea  rdi, [rbx + SC_L_TOKEN]
    mov  ecx, [rbx + SC_L_LENGTH]
    call sc_ipv6
    test eax, eax
    jz   .context
    mov  eax, SC_IPV6
    call sc_candidate_add
    test eax, eax
    jnz  .many
.context:
    cmp  dword [rbx + SC_L_SEP], 1
    jne  .clear_next
    mov  edx, [rbx + SC_L_CONTEXT]
    lea  rdi, [rbx + SC_L_TOKEN]
    mov  ecx, [rbx + SC_L_LENGTH]
    call sc_secret
    test eax, eax
    jz   .clear_next
    mov  eax, SC_SECRET
    call sc_candidate_add
    test eax, eax
    jnz  .many
.clear_next:
    mov  qword [rbx + SC_L_CONTEXT], 0
.next_token:
    mov  r14, r15
    jmp  .scan
.scanned:
    cmp  dword [rbx + SC_L_DEPTH], 0
    jne  .malformed
    ; Insertion sort, at most 64^2 metadata comparisons. No raw values.
    mov  r14d, 1
.sort_outer:
    cmp  r14d, [rbx + SC_L_COUNT]
    jae  .select_init
    mov  r15d, r14d
.sort_inner:
    test r15d, r15d
    jz   .sort_next
    mov  eax, r15d
    shl  eax, 4
    lea  rdi, [rbx + SC_L_CAND]
    add  rdi, rax
    lea  rsi, [rdi - SC_SPAN_SIZE]
    mov  eax, [rdi]
    cmp  eax, [rsi]
    jb   .swap
    ja   .sort_next
    mov  eax, [rdi + 4]
    cmp  eax, [rsi + 4]
    ja   .swap
    jb   .sort_next
    movzx eax, word [rdi + 8]
    cmp  ax, [rsi + 8]
    jae  .sort_next
.swap:
    mov  rax, [rdi]
    mov  rdx, [rdi + 8]
    mov  rcx, [rsi]
    mov  r8, [rsi + 8]
    mov  [rsi], rax
    mov  [rsi + 8], rdx
    mov  [rdi], rcx
    mov  [rdi + 8], r8
    dec  r15d
    jmp  .sort_inner
.sort_next:
    inc  r14d
    jmp  .sort_outer
.select_init:
    xor  r14d, r14d                     ; candidate index
    xor  r15d, r15d                     ; selected count
    xor  r8d, r8d                       ; exclusive end of previous span
.select:
    cmp  r14d, [rbx + SC_L_COUNT]
    jae  .commit
    mov  eax, r14d
    shl  eax, 4
    lea  rdi, [rbx + SC_L_CAND]
    add  rdi, rax
    inc  r14d
    cmp  [rdi], r8d
    jb   .select
    mov  r8d, [rdi]
    add  r8d, [rdi + 4]                 ; every extent already validated
    mov  eax, r15d
    shl  eax, 4
    lea  rsi, [rbx + SC_L_CAND]
    add  rsi, rax
    mov  rax, [rdi]
    mov  rdx, [rdi + 8]
    mov  [rsi], rax
    mov  [rsi + 8], rdx
    inc  r15d
    jmp  .select
.commit:
    cmp  r15, [rbx + SC_L_CAP]
    ja   .bounds
    mov  rdi, [rbx + SC_L_OUT]
    xor  edx, edx
    mov  ecx, r15d
    shl  ecx, 4
.copy:
    cmp  edx, ecx
    jae  .success
    mov  al, [rbx + rdx]
    mov  [rdi + rdx], al
    inc  edx
    jmp  .copy
.success:
    mov  ecx, r15d
    xor  eax, eax
    jmp  .out
.bounds:
    mov  eax, SC_BOUNDS
    jmp  .refused
.many:
    mov  eax, SC_TOO_MANY
    jmp  .refused
.malformed:
    mov  eax, SC_MALFORMED
.refused:
    xor  ecx, ecx
.out:
    ; Wipe copied tokens as well as metadata; never retain caller bytes.
    xor  edx, edx
.wipe:
    mov  byte [rbx + rdx], 0
    inc  edx
    cmp  edx, SC_L_FRAME
    jb   .wipe
    add  rsp, SC_L_FRAME
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; Internal: RBX=frame, EAX=class; validated current start/length. EAX=status.
sc_candidate_add:
    mov  ecx, [rbx + SC_L_COUNT]
    cmp  ecx, SC_MATCH_CAP
    jae  .full
    shl  ecx, 4
    lea  rdx, [rbx + SC_L_CAND]
    add  rdx, rcx
    mov  ecx, [rbx + SC_L_START]
    mov  [rdx], ecx
    mov  ecx, [rbx + SC_L_LENGTH]
    mov  [rdx + 4], ecx
    mov  [rdx + 8], ax
    mov  word [rdx + 10], 2
    cmp  eax, SC_MANUAL
    jne  .context
    mov  word [rdx + 10], 3
.context:
    cmp  eax, SC_SECRET
    jne  .version
    mov  word [rdx + 10], 1
.version:
    mov  dword [rdx + 12], SC_VERSION
    inc  dword [rbx + SC_L_COUNT]
    xor  eax, eax
    ret
.full:
    mov  eax, SC_TOO_MANY
    ret

; AL=byte -> EAX=1 delimiter, 0 token byte. All other registers preserved.
sc_delimiter:
    cmp  al, ' '
    jbe  .yes
    cmp  al, '"'
    je   .yes
    cmp  al, 39
    je   .yes
    cmp  al, ','
    je   .yes
    cmp  al, ';'
    je   .yes
    cmp  al, '<'
    je   .yes
    cmp  al, '>'
    je   .yes
    cmp  al, '='
    je   .yes
    cmp  al, '['
    je   .yes
    cmp  al, ']'
    je   .yes
    cmp  al, '{'
    je   .yes
    cmp  al, '}'
    je   .yes
    cmp  al, '('
    je   .yes
    cmp  al, ')'
    je   .yes
    xor  eax, eax
    ret
.yes:
    mov  eax, 1
    ret

; RDI=cursor, RSI=end -> EAX=0 valid, 1 invalid; no sentinel reads.
sc_utf8_validate:
.next:
    cmp  rdi, rsi
    jae  .ok
    movzx eax, byte [rdi]
    inc  rdi
    cmp  eax, 0x80
    jae  .multi
    cmp  eax, 0x20
    jae  .ascii
    cmp  eax, 9
    je   .next
    cmp  eax, 10
    je   .next
    cmp  eax, 13
    je   .next
    jmp  .bad
.ascii:
    cmp  eax, 0x7f
    je   .bad
    jmp  .next
.multi:
    cmp  eax, 0xc2
    jb   .bad
    cmp  eax, 0xdf
    jbe  .two
    cmp  eax, 0xef
    jbe  .three
    cmp  eax, 0xf4
    ja   .bad
    and  eax, 7
    mov  ecx, 3
    mov  r8d, 0x10000
    jmp  .continuations
.three:
    and  eax, 15
    mov  ecx, 2
    mov  r8d, 0x800
    jmp  .continuations
.two:
    and  eax, 31
    mov  ecx, 1
    mov  r8d, 0x80
.continuations:
    mov  rdx, rsi
    sub  rdx, rdi
    cmp  rdx, rcx
    jb   .bad
.continuation:
    movzx edx, byte [rdi]
    inc  rdi
    mov  r9d, edx
    and  r9d, 0xc0
    cmp  r9d, 0x80
    jne  .bad
    shl  eax, 6
    and  edx, 63
    or   eax, edx
    dec  ecx
    jnz  .continuation
    cmp  eax, r8d
    jb   .bad
    cmp  eax, 0x10ffff
    ja   .bad
    cmp  eax, 0xd800
    jb   .next
    cmp  eax, 0xdfff
    jbe  .bad
    jmp  .next
.ok:
    xor  eax, eax
    ret
.bad:
    mov  eax, 1
    ret

; Validators: RDI=bounded token, ECX=length -> EAX=1 match, 0 no match.
; Only volatile registers are clobbered. Never examine token[length].
sc_card:
    cmp  ecx, 13
    jb   .no
    cmp  ecx, 23                        ; 19 digits + four hyphens
    ja   .no
    cmp  byte [rdi], '0'
    je   .no
    xor  esi, esi
    xor  r8d, r8d                      ; total digits
    xor  r9d, r9d                      ; digits in group
    xor  r10d, r10d                    ; hyphens
.syntax:
    cmp  esi, ecx
    jae  .syntax_done
    movzx eax, byte [rdi + rsi]
    inc  esi
    cmp  al, '-'
    je   .hyphen
    sub  eax, '0'
    cmp  eax, 9
    ja   .no
    inc  r8d
    inc  r9d
    jmp  .syntax
.hyphen:
    cmp  r9d, 4
    jne  .no
    inc  r10d
    xor  r9d, r9d
    jmp  .syntax
.syntax_done:
    cmp  r8d, 13
    jb   .no
    cmp  r8d, 19
    ja   .no
    test r9d, r9d
    jz   .no
    test r10d, r10d
    jz   .luhn_init
    cmp  r9d, 4
    ja   .no
.luhn_init:
    xor  r8d, r8d                      ; rightmost digit has parity 0
    xor  r9d, r9d                      ; checksum, <= 19*9
    mov  esi, ecx
.luhn:
    test esi, esi
    jz   .checksum
    dec  esi
    movzx eax, byte [rdi + rsi]
    cmp  al, '-'
    je   .luhn
    sub  eax, '0'
    test r8b, 1
    jz   .sum
    add  eax, eax
    cmp  eax, 9
    jbe  .sum
    sub  eax, 9
.sum:
    add  r9d, eax
    inc  r8d
    jmp  .luhn
.checksum:
    mov  eax, r9d
    xor  edx, edx
    mov  esi, 10
    div  esi
    xor  eax, eax
    test edx, edx
    setz al
    ret
.no:
    xor  eax, eax
    ret

sc_ssn:
    cmp  ecx, 11
    jne  .no
    cmp  byte [rdi + 3], '-'
    jne  .no
    cmp  byte [rdi + 6], '-'
    jne  .no
    xor  esi, esi
.digits:
    cmp  esi, 11
    jae  .ranges
    cmp  esi, 3
    je   .next
    cmp  esi, 6
    je   .next
    movzx eax, byte [rdi + rsi]
    sub  eax, '0'
    cmp  eax, 9
    ja   .no
.next:
    inc  esi
    jmp  .digits
.ranges:
    mov  eax, [rdi]
    and  eax, 0x00ffffff
    cmp  eax, '000'
    je   .no
    cmp  eax, '666'
    je   .no
    cmp  byte [rdi], '9'
    je   .no
    cmp  word [rdi + 4], '00'
    je   .no
    cmp  dword [rdi + 7], '0000'
    je   .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; AL=ASCII -> EAX=1 alphanumeric, 0 otherwise; preserves ECX/RDI/RSI/R8..11.
sc_alnum:
    cmp  al, '0'
    jb   .alpha
    cmp  al, '9'
    jbe  .yes
.alpha:
    or   al, 0x20
    cmp  al, 'a'
    jb   .no
    cmp  al, 'z'
    ja   .no
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

sc_email:
    cmp  ecx, 6
    jb   .no
    cmp  ecx, 254
    ja   .no
    xor  esi, esi
    mov  r8d, 1                        ; previous byte dot (first dot refused)
.local:
    cmp  esi, ecx
    jae  .no
    cmp  esi, 64
    ja   .no
    movzx eax, byte [rdi + rsi]
    cmp  al, '@'
    je   .at
    cmp  al, '.'
    je   .dot
    cmp  al, '_'
    je   .local_char
    cmp  al, '%'
    je   .local_char
    cmp  al, '+'
    je   .local_char
    cmp  al, '-'
    je   .local_char
    call sc_alnum
    test eax, eax
    jz   .no
.local_char:
    xor  r8d, r8d
    inc  esi
    jmp  .local
.dot:
    test r8d, r8d
    jnz  .no
    mov  r8d, 1
    inc  esi
    jmp  .local
.at:
    test esi, esi
    jz   .no
    test r8d, r8d
    jnz  .no
    inc  esi
    xor  r8d, r8d                      ; label length
    xor  r9d, r9d                      ; dots
    xor  r10d, r10d                    ; last byte hyphen
    xor  r11d, r11d                    ; label has non-letter
.domain:
    cmp  esi, ecx
    jae  .domain_end
    movzx eax, byte [rdi + rsi]
    inc  esi
    cmp  al, '.'
    je   .domain_dot
    cmp  al, '-'
    je   .domain_hyphen
    mov  edx, eax
    call sc_alnum
    test eax, eax
    jz   .no
    cmp  dl, '9'
    ja   .domain_char
    mov  r11d, 1
.domain_char:
    xor  r10d, r10d
    inc  r8d
    cmp  r8d, 63
    ja   .no
    jmp  .domain
.domain_hyphen:
    test r8d, r8d
    jz   .no
    mov  r10d, 1
    mov  r11d, 1
    inc  r8d
    cmp  r8d, 63
    ja   .no
    jmp  .domain
.domain_dot:
    test r8d, r8d
    jz   .no
    test r10d, r10d
    jnz  .no
    inc  r9d
    xor  r8d, r8d
    xor  r11d, r11d
    jmp  .domain
.domain_end:
    test r9d, r9d
    jz   .no
    cmp  r8d, 2
    jb   .no
    or   r10d, r11d
    jnz  .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

sc_phone:
    test ecx, ecx
    jz   .no
    cmp  byte [rdi], '+'
    jne  .nanp
    cmp  ecx, 9                        ; bounded E.164 subset: 8..15 digits
    jb   .no
    cmp  ecx, 16
    ja   .no
    cmp  byte [rdi + 1], '0'
    je   .no
    mov  esi, 1
.international:
    cmp  esi, ecx
    jae  .yes
    movzx eax, byte [rdi + rsi]
    sub  eax, '0'
    cmp  eax, 9
    ja   .no
    inc  esi
    jmp  .international
.nanp:
    cmp  ecx, 12
    jne  .no
    mov  al, [rdi + 3]
    cmp  al, '-'
    je   .separator
    cmp  al, '.'
    jne  .no
.separator:
    cmp  [rdi + 7], al
    jne  .no
    cmp  byte [rdi], '2'
    jb   .no
    cmp  byte [rdi + 4], '2'
    jb   .no
    xor  esi, esi
.nanp_digit:
    cmp  esi, ecx
    jae  .yes
    cmp  esi, 3
    je   .next
    cmp  esi, 7
    je   .next
    movzx eax, byte [rdi + rsi]
    sub  eax, '0'
    cmp  eax, 9
    ja   .no
.next:
    inc  esi
    jmp  .nanp_digit
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; Port of the shipped ntp_parse_ipv4 octet accumulation/range sequence,
; with explicit end operands, no port/sentinel path, and no leading zeros.
sc_ipv4:
    cmp  ecx, 7
    jb   .no
    cmp  ecx, 15
    ja   .no
    xor  esi, esi
    xor  r8d, r8d
.component:
    xor  r9d, r9d                      ; digit count
    xor  r10d, r10d                    ; octet
    mov  r11d, esi                     ; component start
.digit:
    cmp  esi, ecx
    jae  .component_end
    movzx eax, byte [rdi + rsi]
    cmp  al, '.'
    je   .component_end
    sub  eax, '0'
    cmp  eax, 9
    ja   .no
    inc  r9d
    cmp  r9d, 3
    ja   .no
    imul r10d, r10d, 10
    add  r10d, eax
    cmp  r10d, 255
    ja   .no
    inc  esi
    jmp  .digit
.component_end:
    test r9d, r9d
    jz   .no
    cmp  r9d, 1
    je   .count
    cmp  byte [rdi + r11], '0'
    je   .no
.count:
    inc  r8d
    cmp  esi, ecx
    jae  .end
    cmp  r8d, 4
    jae  .no
    inc  esi                           ; checked '.'
    jmp  .component
.end:
    xor  eax, eax
    cmp  r8d, 4
    sete al
    ret
.no:
    xor  eax, eax
    ret

sc_ipv6:
    cmp  ecx, 2
    jb   .no
    cmp  ecx, 39
    ja   .no
    xor  esi, esi
    xor  r8d, r8d                      ; explicit hextets
    xor  r9d, r9d                      ; compression used
    cmp  byte [rdi], ':'
    jne  .group
    cmp  byte [rdi + 1], ':'
    jne  .no
    mov  r9d, 1
    mov  esi, 2
    cmp  esi, ecx
    je   .end
.group:
    xor  r10d, r10d
.hex:
    cmp  esi, ecx
    jae  .group_end
    movzx eax, byte [rdi + rsi]
    cmp  al, ':'
    je   .group_end
    cmp  al, '0'
    jb   .no
    cmp  al, '9'
    jbe  .hex_ok
    or   al, 0x20
    cmp  al, 'a'
    jb   .no
    cmp  al, 'f'
    ja   .no
.hex_ok:
    inc  r10d
    cmp  r10d, 4
    ja   .no
    inc  esi
    jmp  .hex
.group_end:
    test r10d, r10d
    jz   .no
    inc  r8d
    cmp  r8d, 8
    ja   .no
    cmp  esi, ecx
    je   .end
    inc  esi                           ; first colon
    cmp  esi, ecx
    je   .no                           ; lone trailing colon
    cmp  byte [rdi + rsi], ':'
    jne  .group
    test r9d, r9d
    jnz  .no
    mov  r9d, 1
    inc  esi
    cmp  esi, ecx
    jb   .group
.end:
    test r9d, r9d
    jz   .full
    cmp  r8d, 8                        ; :: must stand for >=1 hextet
    jae  .no
    mov  eax, 1
    ret
.full:
    xor  eax, eax
    cmp  r8d, 8
    sete al
    ret
.no:
    xor  eax, eax
    ret

; Exact case-insensitive context key; ECX is preserved for ':' splitting.
sc_context_key:
    cmp  ecx, 4
    je   .four
    cmp  ecx, 5
    je   .five
    cmp  ecx, 6
    je   .six
    cmp  ecx, 7
    je   .seven
    cmp  ecx, 8
    jne  .no
    mov  rax, [rdi]
    mov  rdx, 0x2020202020202020
    or   rax, rdx
    mov  rdx, 'password'
    cmp  rax, rdx
    je   .secret
    jmp  .no
.four:
    mov  eax, [rdi]
    or   eax, 0x20202020
    cmp  eax, 'acct'
    je   .account
    jmp  .no
.five:
    mov  eax, [rdi]
    or   eax, 0x20202020
    cmp  eax, 'toke'
    jne  .no
    mov  al, [rdi + 4]
    or   al, 0x20
    cmp  al, 'n'
    je   .secret
    jmp  .no
.six:
    mov  eax, [rdi]
    or   eax, 0x20202020
    cmp  eax, 'secr'
    jne  .no
    mov  ax, [rdi + 4]
    or   ax, 0x2020
    cmp  ax, 'et'
    je   .secret
    jmp  .no
.seven:
    mov  eax, [rdi]
    or   eax, 0x20202020
    cmp  eax, 'acco'
    je   .account_tail
    cmp  eax, 0x7f697061                ; case fold leaves '_' as 0x7f
    jne  .no
    mov  ax, [rdi + 4]
    or   ax, 0x2020
    cmp  ax, 'ke'
    jne  .no
    mov  al, [rdi + 6]
    or   al, 0x20
    cmp  al, 'y'
    je   .secret
    jmp  .no
.account_tail:
    mov  ax, [rdi + 4]
    or   ax, 0x2020
    cmp  ax, 'un'
    jne  .no
    mov  al, [rdi + 6]
    or   al, 0x20
    cmp  al, 't'
    jne  .no
.account:
    mov  eax, 2
    ret
.secret:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; EDX=context class (1 secret, 2 account). No context -> no match.
sc_secret:
    cmp  edx, 2
    je   .account
    cmp  edx, 1
    jne  .no
    cmp  ecx, 8
    jb   .no
    cmp  ecx, 128
    ja   .no
    xor  esi, esi
    xor  r8d, r8d                      ; bit0 digit, bit1 letter
.secret_loop:
    cmp  esi, ecx
    jae  .secret_end
    movzx eax, byte [rdi + rsi]
    inc  esi
    cmp  al, '-'
    je   .secret_loop
    cmp  al, '_'
    je   .secret_loop
    cmp  al, '0'
    jb   .no
    cmp  al, '9'
    ja   .letter
    or   r8d, 1
    jmp  .secret_loop
.letter:
    or   al, 0x20
    cmp  al, 'a'
    jb   .no
    cmp  al, 'z'
    ja   .no
    or   r8d, 2
    jmp  .secret_loop
.secret_end:
    xor  eax, eax
    cmp  r8d, 3
    sete al
    ret
.account:
    cmp  ecx, 6
    jb   .no
    cmp  ecx, 20
    ja   .no
    xor  esi, esi
.account_loop:
    cmp  esi, ecx
    jae  .yes
    movzx eax, byte [rdi + rsi]
    sub  eax, '0'
    cmp  eax, 9
    ja   .no
    inc  esi
    jmp  .account_loop
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; Immutable expected-span manifest. This is used ONLY by the test runner;
; sensitive_classify has no fixture, case ID, expected result or marker path.
; Table references are relative signed offsets, never baked runtime pointers.
%macro SC_KAT_ROW 8
    dd %1 - sc_kat_table, %1.len, %2 - sc_kat_table, %3, %4
    dd %5 - sc_kat_table, %6, %7, %8, 0
%endmacro
%macro SC_EXPECT 4
    dd %1, %2
    dw %3, %4
    dd SC_VERSION
%endmacro

; sensitive_classifier_matrix -> EAX=0 all pass / 1 failure, ECX=cases passed,
; EDX=observed class bitset, R8D=overlap cases passed, R9D=failing case (1-based).
; The output canaries and every metadata byte are checked on each invocation.
; No expected data is returned to the classifier. All work is stack-local.
sensitive_classifier_matrix:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 1040                     ; output64 records + two 8-byte guards
    mov  rbx, rsp
    lea  r12, [rel sc_kat_table]
    mov  r13, r12
    xor  r14d, r14d
    xor  r15d, r15d
    xor  ebp, ebp
.case:
    cmp  r14d, SC_KAT_CASES
    jae  .pass
    xor  ecx, ecx
.fill:
    mov  byte [rbx + rcx], 0xa5
    inc  ecx
    cmp  ecx, 1040
    jb   .fill
    movsxd rdi, dword [r13]
    add  rdi, r12
    mov  esi, [r13 + 4]
    lea  rdx, [rbx + 8]
    mov  ecx, [r13 + 28]
    movsxd r8, dword [r13 + 8]
    add  r8, r12
    mov  r9d, [r13 + 12]
    call sensitive_classify
    cmp  eax, [r13 + 16]
    jne  .fail
    cmp  ecx, [r13 + 24]
    jne  .fail
    mov  rax, 0xa5a5a5a5a5a5a5a5
    cmp  [rbx], rax
    jne  .fail
    cmp  [rbx + 1032], rax
    jne  .fail
    ; Successful spans must match the immutable oracle byte-for-byte.
    movsxd rdi, dword [r13 + 20]
    add  rdi, r12
    mov  r8d, ecx
    shl  ecx, 4
    xor  edx, edx
    lea  rsi, [rbx + 8]
.compare:
    cmp  edx, ecx
    jae  .tail
    mov  al, [rdi + rdx]
    cmp  [rsi + rdx], al
    jne  .fail
    inc  edx
    jmp  .compare
.tail:
    ; Failure has count=0: this checks the ENTIRE output remains untouched.
    cmp  edx, 1024
    jae  .classes
    cmp  byte [rsi + rdx], 0xa5
    jne  .fail
    inc  edx
    jmp  .tail
.classes:
    test r8d, r8d
    jz   .count_case
    movzx ecx, word [rsi + 8]
    bts  r15d, ecx
    add  rsi, SC_SPAN_SIZE
    dec  r8d
    jmp  .classes
.count_case:
    test dword [r13 + 32], 1
    jz   .next
    inc  ebp
.next:
    inc  r14d
    add  r13, 40
    jmp  .case
.pass:
    cmp  r15d, 0x1fe                   ; every declared class actually observed
    jne  .fail
    cmp  ebp, SC_KAT_OVERLAPS
    jne  .fail
    xor  eax, eax
    xor  r9d, r9d
    jmp  .out
.fail:
    mov  eax, 1
    lea  r9d, [r14 + 1]
.out:
    mov  ecx, r14d
    mov  edx, r15d
    mov  r8d, ebp
    add  rsp, 1040
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; sensitive_classifier_selftest: boot adapter over the same live matrix.
sensitive_classifier_selftest:
    call sensitive_classifier_matrix
    test eax, eax
    jnz  .fail
    lea  rdi, [rel sc_kat_pass]
    call serial_string
    lea  rdi, [rel sc_overlap_pass]
    call serial_string
    ret
.fail:
    lea  rdi, [rel sc_kat_fail]
    call serial_string
    ret

align 4
sc_kat_table:
    SC_KAT_ROW sc_k_card, sc_m_none, 0, SC_OK, sc_e_card, 1, 64, 0
    SC_KAT_ROW sc_k_card_hyphen, sc_m_none, 0, SC_OK, sc_e_card_hyphen, 1, 64, 0
    SC_KAT_ROW sc_k_ssn, sc_m_none, 0, SC_OK, sc_e_ssn, 1, 64, 0
    SC_KAT_ROW sc_k_email, sc_m_none, 0, SC_OK, sc_e_email, 1, 64, 0
    SC_KAT_ROW sc_k_phone, sc_m_none, 0, SC_OK, sc_e_phone, 1, 64, 0
    SC_KAT_ROW sc_k_e164, sc_m_none, 0, SC_OK, sc_e_e164, 1, 64, 0
    SC_KAT_ROW sc_k_ipv4, sc_m_none, 0, SC_OK, sc_e_ipv4, 1, 64, 0
    SC_KAT_ROW sc_k_ipv6, sc_m_none, 0, SC_OK, sc_e_ipv6, 1, 64, 0
    SC_KAT_ROW sc_k_ipv6_full, sc_m_none, 0, SC_OK, sc_e_ipv6_full, 1, 64, 0
    SC_KAT_ROW sc_k_ipv6_zero, sc_m_none, 0, SC_OK, sc_e_ipv6_zero, 1, 64, 0
    SC_KAT_ROW sc_k_secret, sc_m_none, 0, SC_OK, sc_e_secret, 1, 64, 0
    SC_KAT_ROW sc_k_account, sc_m_none, 0, SC_OK, sc_e_account, 1, 64, 0
    SC_KAT_ROW sc_k_inline, sc_m_none, 0, SC_OK, sc_e_inline, 1, 64, 0
    SC_KAT_ROW sc_k_apikey, sc_m_none, 0, SC_OK, sc_e_apikey, 1, 64, 0
    SC_KAT_ROW sc_k_repeat, sc_m_none, 0, SC_OK, sc_e_repeat, 2, 64, 0
    SC_KAT_ROW sc_k_manual, sc_m_manual, 1, SC_OK, sc_e_manual, 1, 64, 0
    SC_KAT_ROW sc_k_utf8, sc_m_utf8, 1, SC_OK, sc_e_utf8, 1, 64, 0
    ; Same start longer auto; earlier manual; same extent manual precedence;
    ; longer manual at same start; nested manual; class precedence account/card.
    SC_KAT_ROW sc_k_email, sc_m_short, 1, SC_OK, sc_e_email, 1, 64, 1
    SC_KAT_ROW sc_k_earlier, sc_m_earlier, 1, SC_OK, sc_e_earlier, 1, 64, 1
    SC_KAT_ROW sc_k_email, sc_m_equal, 1, SC_OK, sc_e_equal, 1, 64, 1
    SC_KAT_ROW sc_k_larger, sc_m_larger, 1, SC_OK, sc_e_larger, 1, 64, 1
    SC_KAT_ROW sc_k_manual, sc_m_nested, 3, SC_OK, sc_e_manual, 1, 64, 1
    SC_KAT_ROW sc_k_card_account, sc_m_none, 0, SC_OK, sc_e_card_account, 1, 64, 1
    ; All hostile cases invoke the real core, including late refusals.
    SC_KAT_ROW sc_k_bad_luhn, sc_m_none, 0, SC_OK, sc_e_none, 0, 64, 0
    SC_KAT_ROW sc_k_dates, sc_m_none, 0, SC_OK, sc_e_none, 0, 64, 0
    SC_KAT_ROW sc_k_bad_ssn, sc_m_none, 0, SC_OK, sc_e_none, 0, 64, 0
    SC_KAT_ROW sc_k_bad_email, sc_m_none, 0, SC_OK, sc_e_none, 0, 64, 0
    SC_KAT_ROW sc_k_bad_ip, sc_m_none, 0, SC_OK, sc_e_none, 0, 64, 0
    SC_KAT_ROW sc_k_bad_phone, sc_m_none, 0, SC_OK, sc_e_none, 0, 64, 0
    SC_KAT_ROW sc_k_bad_context, sc_m_none, 0, SC_OK, sc_e_none, 0, 64, 0
    SC_KAT_ROW sc_k_context_far, sc_m_none, 0, SC_OK, sc_e_none, 0, 64, 0
    SC_KAT_ROW sc_k_crossing, sc_m_none, 0, SC_OK, sc_e_none, 0, 64, 0
    SC_KAT_ROW sc_k_cut_email, sc_m_none, 0, SC_OK, sc_e_none, 0, 64, 0
    SC_KAT_ROW sc_k_cut_card, sc_m_none, 0, SC_OK, sc_e_none, 0, 64, 0
    SC_KAT_ROW sc_k_bad_utf8, sc_m_none, 0, SC_MALFORMED, sc_e_none, 0, 64, 0
    SC_KAT_ROW sc_k_surrogate, sc_m_none, 0, SC_MALFORMED, sc_e_none, 0, 64, 0
    SC_KAT_ROW sc_k_cut_utf8, sc_m_none, 0, SC_MALFORMED, sc_e_none, 0, 64, 0
    SC_KAT_ROW sc_k_high_utf8, sc_m_none, 0, SC_MALFORMED, sc_e_none, 0, 64, 0
    SC_KAT_ROW sc_k_nul, sc_m_none, 0, SC_MALFORMED, sc_e_none, 0, 64, 0
    SC_KAT_ROW sc_k_utf8, sc_m_split_utf8, 1, SC_MALFORMED, sc_e_none, 0, 64, 0
    SC_KAT_ROW sc_k_utf8, sc_m_split_end, 1, SC_MALFORMED, sc_e_none, 0, 64, 0
    SC_KAT_ROW sc_k_email, sc_m_beyond, 1, SC_BOUNDS, sc_e_none, 0, 64, 0
    SC_KAT_ROW sc_k_email, sc_m_wrap, 1, SC_BOUNDS, sc_e_none, 0, 64, 0
    SC_KAT_ROW sc_k_email, sc_m_empty, 1, SC_MALFORMED, sc_e_none, 0, 64, 0
    SC_KAT_ROW sc_k_email, sc_m_none, 65, SC_TOO_MANY, sc_e_none, 0, 64, 0
    SC_KAT_ROW sc_k_email, sc_m_none, 0, SC_OK, sc_e_email, 1, 1, 0
    SC_KAT_ROW sc_k_repeat, sc_m_none, 0, SC_BOUNDS, sc_e_none, 0, 1, 0
    SC_KAT_ROW sc_k_email, sc_m_none, 0, SC_BOUNDS, sc_e_none, 0, 0, 0
    SC_KAT_ROW sc_k_empty, sc_m_none, 0, SC_OK, sc_e_none, 0, 0, 0
    SC_KAT_ROW sc_k_over_input, sc_m_none, 0, SC_BOUNDS, sc_e_none, 0, 64, 0
    SC_KAT_ROW sc_k_token_cap, sc_m_none, 0, SC_OK, sc_e_none, 0, 64, 0
    SC_KAT_ROW sc_k_token_over, sc_m_none, 0, SC_BOUNDS, sc_e_none, 0, 64, 0
    SC_KAT_ROW sc_k_candidates_ok, sc_m_none, 0, SC_OK, sc_e_candidates, 64, 64, 0
    SC_KAT_ROW sc_k_candidates, sc_m_none, 0, SC_TOO_MANY, sc_e_none, 0, 64, 0
    SC_KAT_ROW sc_k_depth, sc_m_none, 0, SC_OK, sc_e_none, 0, 64, 0
    SC_KAT_ROW sc_k_depth_over, sc_m_none, 0, SC_BOUNDS, sc_e_none, 0, 64, 0
    SC_KAT_ROW sc_k_bracket_bad, sc_m_none, 0, SC_MALFORMED, sc_e_none, 0, 64, 0
    SC_KAT_ROW sc_k_late_bad, sc_m_none, 0, SC_MALFORMED, sc_e_none, 0, 64, 0
.end:
SC_KAT_CASES equ (sc_kat_table.end - sc_kat_table) / 40
SC_KAT_OVERLAPS equ 6
%unmacro SC_KAT_ROW 8

sc_m_none:
sc_e_none:
sc_m_manual: dd 0, 12
sc_m_utf8: dd 0, 2
sc_m_short: dd 0, 5
sc_m_earlier: dd 0, 3
sc_m_equal: dd 0, 18
sc_m_larger: dd 0, 23
sc_m_nested: dd 2, 3, 0, 12, 1, 8       ; deliberately unsorted
sc_m_split_utf8: dd 1, 1
sc_m_split_end: dd 0, 1
sc_m_beyond: dd 17, 2
sc_m_wrap: dd 0xffffffff, 2
sc_m_empty: dd 0, 0
sc_e_card: SC_EXPECT 0, 16, SC_CARD, 2
sc_e_card_hyphen: SC_EXPECT 0, 19, SC_CARD, 2
sc_e_ssn: SC_EXPECT 0, 11, SC_SSN, 2
sc_e_email: SC_EXPECT 0, 18, SC_EMAIL, 2
sc_e_phone: SC_EXPECT 0, 12, SC_PHONE, 2
sc_e_e164: SC_EXPECT 0, 12, SC_PHONE, 2
sc_e_ipv4: SC_EXPECT 0, 9, SC_IPV4, 2
sc_e_ipv6: SC_EXPECT 0, 11, SC_IPV6, 2
sc_e_ipv6_full: SC_EXPECT 0, 15, SC_IPV6, 2
sc_e_ipv6_zero: SC_EXPECT 0, 2, SC_IPV6, 2
sc_e_secret: SC_EXPECT 7, 8, SC_SECRET, 1
sc_e_account: SC_EXPECT 8, 10, SC_SECRET, 1
sc_e_inline: SC_EXPECT 6, 8, SC_SECRET, 1
sc_e_apikey: SC_EXPECT 10, 8, SC_SECRET, 1
sc_e_repeat:
    SC_EXPECT 0, 18, SC_EMAIL, 2
    SC_EXPECT 19, 18, SC_EMAIL, 2
sc_e_manual: SC_EXPECT 0, 12, SC_MANUAL, 3
sc_e_utf8: SC_EXPECT 0, 2, SC_MANUAL, 3
sc_e_earlier: SC_EXPECT 0, 3, SC_MANUAL, 3
sc_e_equal: SC_EXPECT 0, 18, SC_MANUAL, 3
sc_e_larger: SC_EXPECT 0, 23, SC_MANUAL, 3
sc_e_card_account: SC_EXPECT 8, 16, SC_SECRET, 1
sc_e_candidates:
%assign sc_kat_index 0
%rep 64
    SC_EXPECT sc_kat_index * 19, 18, SC_EMAIL, 2
%assign sc_kat_index sc_kat_index + 1
%endrep
%undef sc_kat_index
%unmacro SC_EXPECT 4

; Synthetic public test values only. Never serialize or hash these bytes.
sc_k_card: db '4111111111111111'
.len equ $ - sc_k_card
sc_k_card_hyphen: db '4111-1111-1111-1111'
.len equ $ - sc_k_card_hyphen
sc_k_ssn: db '123-45-6789'
.len equ $ - sc_k_ssn
sc_k_email: db 'owner@example.test'
.len equ $ - sc_k_email
sc_k_phone: db '202-555-0123'
.len equ $ - sc_k_phone
sc_k_e164: db '+12025550123'
.len equ $ - sc_k_e164
sc_k_ipv4: db '192.0.2.7'
.len equ $ - sc_k_ipv4
sc_k_ipv6: db '2001:db8::1'
.len equ $ - sc_k_ipv6
sc_k_ipv6_full: db '1:2:3:4:5:6:7:8'
.len equ $ - sc_k_ipv6_full
sc_k_ipv6_zero: db '::'
.len equ $ - sc_k_ipv6_zero
sc_k_secret: db 'secret=DemoKey9'
.len equ $ - sc_k_secret
sc_k_account: db 'account=3141592653'
.len equ $ - sc_k_account
sc_k_inline: db 'token:DemoKey9'
.len equ $ - sc_k_inline
sc_k_apikey: db 'API_KEY = DemoKey9'
.len equ $ - sc_k_apikey
sc_k_repeat: db 'owner@example.test owner@example.test'
.len equ $ - sc_k_repeat
sc_k_manual: db '123 Main Ave'
.len equ $ - sc_k_manual
sc_k_utf8: db 0xc3,0xa9
.len equ $ - sc_k_utf8
sc_k_earlier: db 'x owner@example.test'
.len equ $ - sc_k_earlier
sc_k_larger: db 'owner@example.test tail'
.len equ $ - sc_k_larger
sc_k_card_account: db 'account=4111111111111111'
.len equ $ - sc_k_card_account
sc_k_bad_luhn: db '4111111111111112 4111-1111-1111-1112 0000000000000000'
.len equ $ - sc_k_bad_luhn
sc_k_dates: db '2026-09-11 09/11/2026 42 123456 1234567890'
.len equ $ - sc_k_dates
sc_k_bad_ssn: db '000-45-6789 666-45-6789 900-45-6789 123-00-6789 123-45-0000'
.len equ $ - sc_k_bad_ssn
sc_k_bad_email: db '.owner@example.test a..b@example.test a@-example.test a@example-.test a@example..test a@example.t a@example.12'
.len equ $ - sc_k_bad_email
sc_k_bad_ip: db '256.0.2.7 192.00.2.7 192.0.2 192.0.2.7.1 1::2::3 1:2:3:4:5:6:7 1:2:3:4:5:6:7:8:: 12345::1 :::'
.len equ $ - sc_k_bad_ip
sc_k_bad_phone: db '+01234567890 +1234567 +1234567890123456 102-555-0123 202-055-0123 202-555.0123'
.len equ $ - sc_k_bad_phone
sc_k_bad_context: db 'counter=3141592653 secret=12345678 secret=abcdefgh secret=2026-09-11 secret DemoKey9 secret==DemoKey9 notsecret=DemoKey9 account=42'
.len equ $ - sc_k_bad_context
sc_k_context_far: db 'secret=', '                                 ', 'DemoKey9'
.len equ $ - sc_k_context_far
sc_k_crossing: db 'x4111111111111111 4111111111111111x x123-45-6789 192.0.2.7x x2001:db8::1'
.len equ $ - sc_k_crossing
sc_k_cut_email: db 'owner@example.test'
.len equ 13                            ; only owner@example, no suffix salvage
sc_k_cut_card: db '4111111111111111'
.len equ 12
sc_k_bad_utf8: db 0xc0,0xaf
.len equ $ - sc_k_bad_utf8
sc_k_surrogate: db 0xed,0xa0,0x80
.len equ $ - sc_k_surrogate
sc_k_cut_utf8: db 0xe2,0x82
.len equ $ - sc_k_cut_utf8
sc_k_high_utf8: db 0xf4,0x90,0x80,0x80
.len equ $ - sc_k_high_utf8
sc_k_nul: db 'x',0,'y'
.len equ $ - sc_k_nul
sc_k_empty:
.len equ 0
sc_k_over_input:
.len equ SC_INPUT_CAP + 1               ; must refuse BEFORE any input read
sc_k_token_cap: times SC_TOKEN_CAP db 'a'
.len equ $ - sc_k_token_cap
sc_k_token_over: times SC_TOKEN_CAP + 1 db 'a'
.len equ $ - sc_k_token_over
sc_k_candidates_ok:
.len equ 64 * 19
sc_k_candidates: times 65 db 'owner@example.test '
.len equ $ - sc_k_candidates
sc_k_depth: db '((((((((x))))))))'
.len equ $ - sc_k_depth
sc_k_depth_over: db '(((((((((x)))))))))'
.len equ $ - sc_k_depth_over
sc_k_bracket_bad: db '([)]'
.len equ $ - sc_k_bracket_bad
sc_k_late_bad: db 'owner@example.test ('
.len equ $ - sc_k_late_bad

sc_kat_pass: db '[PAOS64] M6 privacy: bounded sensitive classifier matrix PASS (classes negatives manual raw-zero) [privacy.sensitive.classifier.kat]',13,10,0
sc_overlap_pass: db '[PAOS64] M6 privacy: leftmost-longest overlap and class precedence PASS [privacy.sensitive.overlap.kat]',13,10,0
sc_kat_fail: db '[PAOS64] M6 privacy: sensitive classifier matrix FAIL',13,10,0
sc_image_end:
