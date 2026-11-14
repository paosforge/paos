;; MODULE web/bounded_field_reader
;; LAYER 4
;; EXPORTS web_field_read_bounded
;; IMPORTS
;; CAPS
;; OWNER saga:web_browser
; Task2701: bounded byte-field reader.  This module is deliberately independent
; of transport and allocation; structured_data.asm is its only product caller.

WEB_FIELD_OK         equ 0
WEB_FIELD_TRUNCATED  equ 1
WEB_FIELD_BOUNDS     equ 2
WEB_FIELD_MALFORMED  equ 3
WEB_FIELD_MODE_TOKEN equ 0
WEB_FIELD_MODE_TEXT  equ 1

; web_field_read_bounded
;   in:  rdi=cursor, rsi=end (exclusive), rdx=out, rcx=out_cap,
;        r8d=WEB_FIELD_MODE_TOKEN or WEB_FIELD_MODE_TEXT
;   out: eax=WEB_FIELD_*, rdx=consumed bytes, rcx=stored bytes
;
; A leading single/double quote selects quoted mode and is included in consumed;
; the matching quote is required and included too.  Otherwise the field ends at
; ASCII whitespace or one of the HTML/JSON grammar delimiters below.  The stop
; delimiter is not consumed.  Each input byte is loaded exactly once before all
; validation tests.  No sentinel read is performed: end is authoritative.
web_field_read_bounded:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  ebx, r8d                        ; explicit delimiter mode
    mov  r8, rdi                         ; immutable start
    mov  r9, rdi                         ; cursor
    mov  r10, rsi                        ; exclusive end
    mov  r11, rdx                        ; output
    mov  r12, rcx                        ; output capacity (includes NUL)
    xor  r13d, r13d                      ; stored bytes
    xor  r14d, r14d                      ; quote byte, 0 = unquoted
    test r12, r12
    jz   .bounds_no_store
    test r11, r11
    jz   .malformed_no_term
    test r8, r8
    jz   .malformed
    mov  byte [r11], 0                   ; always terminate when cap > 0
    cmp  r9, r10
    ja   .malformed
    je   .truncated
    movzx eax, byte [r9]                 ; read first byte once
    cmp  al, '"'
    je   .quoted_start
    cmp  al, 39                          ; single quote
    jne  .unquoted_classify
.quoted_start:
    mov  r14b, al
    inc  r9
    jmp  .quoted_loop

.unquoted_loop:
    cmp  r9, r10
    jae  .ok
    movzx eax, byte [r9]                 ; exactly one load for this byte
.unquoted_classify:
    test al, al
    jz   .malformed
    cmp  ebx, WEB_FIELD_MODE_TEXT
    jne  .token_classify
    cmp  al, '<'
    je   .ok
    cmp  al, ' '
    jae  .store_unquoted
    cmp  al, 9                           ; text retains ordinary whitespace
    je   .store_unquoted
    cmp  al, 10
    je   .store_unquoted
    cmp  al, 13
    je   .store_unquoted
    jmp  .malformed
.token_classify:
    cmp  al, ' '
    jbe  .unquoted_control
    cmp  al, '>'
    je   .ok
    cmp  al, '<'
    je   .ok
    cmp  al, '='
    je   .ok
    cmp  al, ','
    je   .ok
    cmp  al, '}'
    je   .ok
    cmp  al, ']'
    je   .ok
    jmp  .store_unquoted
.unquoted_control:
    cmp  al, 9                           ; tab/newline/CR/space terminate
    je   .ok
    cmp  al, 10
    je   .ok
    cmp  al, 13
    je   .ok
    cmp  al, ' '
    je   .ok
    jmp  .malformed                      ; other controls are never field bytes
.store_unquoted:
    mov  r15, r13
    inc  r15                             ; byte plus required trailing NUL
    cmp  r15, r12
    jae  .bounds
    mov  [r11 + r13], al
    inc  r13
    mov  byte [r11 + r13], 0
    inc  r9
    jmp  .unquoted_loop

.quoted_loop:
    cmp  r9, r10
    jae  .truncated
    movzx eax, byte [r9]                 ; exactly one load for this byte
    test al, al
    jz   .malformed
    cmp  al, r14b
    je   .quoted_done
    cmp  al, 10
    je   .malformed
    cmp  al, 13
    je   .malformed
    mov  r15, r13
    inc  r15
    cmp  r15, r12
    jae  .bounds
    mov  [r11 + r13], al
    inc  r13
    mov  byte [r11 + r13], 0
    inc  r9
    jmp  .quoted_loop
.quoted_done:
    inc  r9
.ok:
    mov  eax, WEB_FIELD_OK
    jmp  .out
.truncated:
    mov  eax, WEB_FIELD_TRUNCATED
    jmp  .out
.bounds:
    mov  eax, WEB_FIELD_BOUNDS
    jmp  .out
.bounds_no_store:
    mov  eax, WEB_FIELD_BOUNDS
    jmp  .out_no_term
.malformed:
    mov  eax, WEB_FIELD_MALFORMED
    jmp  .out
.malformed_no_term:
    mov  eax, WEB_FIELD_MALFORMED
    jmp  .out_no_term
.out:
    test r12, r12
    jz   .out_no_term
    mov  byte [r11 + r13], 0
.out_no_term:
    mov  rdx, r9
    sub  rdx, r8                         ; consumed bytes on every status
    mov  rcx, r13                        ; bytes retained before status
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
