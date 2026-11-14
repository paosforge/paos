;; MODULE svc/command_privacy
;; LAYER 5
;; EXPORTS command_privacy_register, cmd_verb_privacytest, privacy_out_ready, privacy_out_buf, privacy_audit_record
;; IMPORTS svc/command, security/sensitive_classifier, lib/safe_buffer, core/lib/sha256, core/lib/fmt
;; CAPS
;; OWNER saga:agent_privacy
; Task3305: fixed synthetic KAT adapter only. There is no arbitrary-input mode.
; Existing command projection serializes the request-scoped reply buffer, as
; for WEBSTRUCT. Classifier and matrix scratch remain entirely stack-local.
;
; Digest schema 1: SHA256(ASCII bytes from 'privacytest=ok' up to but excluding
; ' digest='). Includes nonce, version, exact earned counts and verdicts; never
; hashes input, synthetic values, span contents or other owner data. The common
; transport status tail is outside the digest. Max response is below 512 bytes.

PRIVACY_OUT_CAP equ 512
privacy_image_begin:

; command_privacy_register -> ordinary read-only registry row, cap=destr=0.
command_privacy_register:
    lea  rdi, [rel str_verb_privacytest]
    lea  rsi, [rel cmd_verb_privacytest]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8d, r8d
    xor  r9d, r9d
    call command_register_verb
    ret

; cmd_verb_privacytest(RDI=request, RSI=response). Exactly 32 lowercase hex
; nonce bytes required. Refusal never echoes arguments; suffixes/HEX payloads
; are refused before the matrix. The argument is never sent to the classifier.
cmd_verb_privacytest:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, S256_CTX_SZ + 32
    mov  rbx, rsp
    mov  r12, rsi
    mov  r13, [rdi + REQ_ARG]
    mov  byte [rel privacy_out_ready], 0
    lea  rax, [rel privacy_out_buf]
    mov  [rel privacy_out_cur], rax
    mov  byte [rax], 0
    mov  rdi, r13
    mov  esi, 33
    call safe_capped_len
    test edx, edx
    jnz  .nonce_bad
    cmp  eax, 32
    jne  .nonce_bad
    xor  ecx, ecx
.nonce_byte:
    movzx eax, byte [r13 + rcx]
    cmp  al, '0'
    jb   .nonce_bad
    cmp  al, '9'
    jbe  .nonce_next
    cmp  al, 'a'
    jb   .nonce_bad
    cmp  al, 'f'
    ja   .nonce_bad
.nonce_next:
    inc  ecx
    cmp  ecx, 32
    jb   .nonce_byte
    call sensitive_classifier_matrix
    test eax, eax
    jnz  .matrix_bad
    mov  r14d, ecx
    mov  r15d, r8d
    lea  rdi, [rel privacy_reply_head]
    call privacy_puts
    mov  rdi, r13
    call privacy_puts
    lea  rdi, [rel privacy_reply_cases]
    call privacy_puts
    mov  edi, r14d
    call privacy_putdec
    lea  rdi, [rel privacy_reply_classes]
    call privacy_puts
    mov  edi, r15d
    call privacy_putdec
    lea  rdi, [rel privacy_reply_tail]
    call privacy_puts
    mov  rdi, rbx
    call sha256_stream_init
    mov  rdi, rbx
    lea  rsi, [rel privacy_out_buf]
    mov  rdx, [rel privacy_out_cur]
    sub  rdx, rsi
    call sha256_stream_update
    test eax, eax
    jnz  .digest_bad
    mov  rdi, rbx
    lea  rsi, [rbx + S256_CTX_SZ]
    call sha256_stream_final
    lea  rdi, [rel privacy_reply_digest]
    call privacy_puts
    xor  r14d, r14d
.digest_byte:
    movzx r15d, byte [rbx + r14 + S256_CTX_SZ]
    mov  eax, r15d
    shr  eax, 4
    call privacy_hex_digit
    mov  eax, r15d
    and  eax, 15
    call privacy_hex_digit
    inc  r14d
    cmp  r14d, 32
    jb   .digest_byte
    jmp  .ready
.nonce_bad:
    lea  rdi, [rel privacy_reply_nonce_bad]
    call privacy_puts
    jmp  .ready
.matrix_bad:
    mov  r14d, r9d                     ; ordinal only, no test values
    lea  rdi, [rel privacy_reply_matrix_bad]
    call privacy_puts
    mov  edi, r14d
    call privacy_putdec
    jmp  .ready
.digest_bad:
    lea  rax, [rel privacy_out_buf]
    mov  [rel privacy_out_cur], rax
    mov  byte [rax], 0
    lea  rdi, [rel privacy_reply_digest_bad]
    call privacy_puts
.ready:
    mov  byte [rel privacy_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_OK
    ; Only public metadata occupied this frame; erase it for clean reuse.
    xor  ecx, ecx
.wipe:
    mov  byte [rbx + rcx], 0
    inc  ecx
    cmp  ecx, S256_CTX_SZ + 32
    jb   .wipe
    add  rsp, S256_CTX_SZ + 32
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=fixed literal or already validated 32-byte nonce; bounded by output cap.
privacy_puts:
    mov  rsi, [rel privacy_out_cur]
    lea  rdx, [rel privacy_out_buf + PRIVACY_OUT_CAP - 1]
.byte:
    cmp  rsi, rdx
    jae  .done
    mov  al, [rdi]
    test al, al
    jz   .done
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .byte
.done:
    mov  byte [rsi], 0
    mov  [rel privacy_out_cur], rsi
    ret

; EDI=bounded count (<= SC_KAT_CASES). fmt_dec writes at most 20 digits.
privacy_putdec:
    mov  rsi, [rel privacy_out_cur]
    lea  rax, [rel privacy_out_buf + PRIVACY_OUT_CAP - 21]
    cmp  rsi, rax
    ja   .out
    push rsi
    call fmt_dec
    pop  rsi
    add  rsi, rax
    mov  byte [rsi], 0
    mov  [rel privacy_out_cur], rsi
.out:
    ret

privacy_hex_digit:
    cmp  eax, 10
    jb   .decimal
    add  eax, 'a' - 10
    jmp  .store
.decimal:
    add  eax, '0'
.store:
    mov  rdx, [rel privacy_out_cur]
    lea  rcx, [rel privacy_out_buf + PRIVACY_OUT_CAP - 1]
    cmp  rdx, rcx
    jae  .out
    mov  [rdx], al
    inc  rdx
    mov  byte [rdx], 0
    mov  [rel privacy_out_cur], rdx
.out:
    ret

align 8
privacy_out_ready: db 0
align 8
privacy_out_cur: dq 0
privacy_out_buf: times PRIVACY_OUT_CAP db 0
str_verb_privacytest: db 'PRIVACYTEST',0
privacy_audit_record: db 'PRIVACYTEST synthetic_only=1 raw_values=0',0
privacy_reply_head: db 'privacytest=ok schema=1 nonce=',0
privacy_reply_cases: db ' cases=',0
privacy_reply_classes: db ' class_count=8 classes=card,ssn,email,phone,ipv4,ipv6,secret,manual detector_version=1 manual=pass luhn_invalid=pass overlap=leftmost_longest overlap_cases=',0
privacy_reply_tail: db ' negatives=pass raw_values=0 input_cap=16384 candidate_cap=64 token_cap=256 context_cap=32 depth_cap=8 coverage=bounded manual_for=addresses,non_us_ids,ambiguous',0
privacy_reply_digest: db ' digest=',0
privacy_reply_nonce_bad: db 'privacytest=refused reason=nonce raw_values=0',0
privacy_reply_matrix_bad: db 'privacytest=refused reason=matrix raw_values=0 case=',0
privacy_reply_digest_bad: db 'privacytest=refused reason=digest raw_values=0',0
privacy_image_end:

; Contract3305 binary delta, including a conservative allowance for registry,
; boot, auth and UDP wiring. Frame high-water is <3 KiB, with no heap use.
%if (sc_image_end - sc_image_begin) + (privacy_image_end - privacy_image_begin) + 512 > 16384
    %error "Task3305 classifier and adapter exceed their 16 KiB image budget"
%endif
