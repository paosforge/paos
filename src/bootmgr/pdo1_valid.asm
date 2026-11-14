;; MODULE bootmgr/pdo1_valid
;; LAYER 0
;; EXPORTS pdo1_record_valid
;; IMPORTS
;; CAPS
;; OWNER saga:boot
; Shared native/Manager pure PDO1 structure validator (U4b, SEC 106354 K6).
; No signature, I/O, clock, journal or state: each caller separately verifies
; the RSA signature with the key that verified its own PBMF and binds the
; manifest sequence and build to its own verified identity. Python mirror (REL-owned,
; REL 106363): gauntlet_v2/tools/pdo1_record.py decode(); both decide one case list.
%include "boot/dd_oracle_contract.inc"

; pdo1_record_valid(RDI = exact 1024-byte record) -> EAX = 1 valid, 0 refused.
; Preserves every register except RAX and flags.
pdo1_record_valid:
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    mov  rbx, rdi
    test rbx, rbx
    jz   .bad
    cmp  dword [rbx], PDO1_MAGIC
    jne  .bad
    cmp  word [rbx + 4], PDO1_VERSION
    jne  .bad
    cmp  word [rbx + 6], PDO1_SIZE
    jne  .bad
    ; Exact context, zero padded: every one of the 32 bytes.
    xor  ecx, ecx
.context:
    mov  al, [rbx + PDO1_CONTEXT_OFF + rcx]
    lea  rsi, [rel pdo1_context]
    cmp  al, [rsi + rcx]
    jne  .bad
    inc  ecx
    cmp  ecx, PDO1_CONTEXT_SIZE
    jb   .context
    mov  rax, [rbx + PDO1_MANIFEST_SEQ_OFF]
    test rax, rax
    jz   .bad
    cmp  rax, [rbx + PDO1_ORACLE_SEQ_OFF]   ; oracle_sequence == manifest_sequence (>= 1)
    jne  .bad
    mov  rax, [rbx + PDO1_BUILD_SHA_OFF]
    or   rax, [rbx + PDO1_BUILD_SHA_OFF + 8]
    or   rax, [rbx + PDO1_BUILD_SHA_OFF + 16]
    or   rax, [rbx + PDO1_BUILD_SHA_OFF + 24]
    jz   .bad                       ; build digest nonzero
    mov  rax, [rbx + PDO1_PIN_OFF]
    or   rax, [rbx + PDO1_PIN_OFF + 8]
    or   rax, [rbx + PDO1_PIN_OFF + 16]
    or   rax, [rbx + PDO1_PIN_OFF + 24]
    jz   .bad                       ; pin digest nonzero
    ; Nonce: 32 lowercase hex characters, not all '0'.
    xor  ecx, ecx
    xor  edx, edx                   ; any character other than '0'
.nonce:
    movzx eax, byte [rbx + PDO1_NONCE_OFF + rcx]
    cmp  al, '0'
    je   .nonce_next
    mov  edx, 1
    cmp  al, '1'
    jb   .bad
    cmp  al, '9'
    jbe  .nonce_next
    cmp  al, 'a'
    jb   .bad
    cmp  al, 'f'
    ja   .bad
.nonce_next:
    inc  ecx
    cmp  ecx, PDO1_NONCE_SIZE
    jb   .nonce
    test edx, edx
    jz   .bad
    movzx r8d, word [rbx + PDO1_URL_LEN_OFF]
    cmp  r8d, PDO1_URL_MIN
    jb   .bad
    cmp  r8d, PDO1_URL_MAX
    ja   .bad
    movzx eax, word [rbx + PDO1_NONCE_FORM_OFF]
    mov  r9d, PDO1_NONCE_HEX_LEN
    cmp  eax, PDO1_NONCE_FORM_HEX
    je   .form_ok
    mov  r9d, PDO1_NONCE_B64_LEN
    cmp  eax, PDO1_NONCE_FORM_B64
    jne  .bad
.form_ok:
    movzx r10d, word [rbx + PDO1_NONCE_URL_OFF]
    cmp  r10d, PDO1_URL_PREFIX_SIZE  ; never overlaps "https://"
    jb   .bad
    lea  eax, [r10d + r9d]
    cmp  eax, r8d                    ; wholly inside url_len
    ja   .bad
    cmp  word [rbx + PDO1_PAD_OFF], 0
    jne  .bad
    ; Exact "https://" prefix.
    xor  ecx, ecx
.prefix:
    mov  al, [rbx + PDO1_URL_OFF + rcx]
    lea  rsi, [rel pdo1_https]
    cmp  al, [rsi + rcx]
    jne  .bad
    inc  ecx
    cmp  ecx, PDO1_URL_PREFIX_SIZE
    jb   .prefix
    ; URL bytes: printable 0x21..0x7E, never '#'; zero after url_len.
    xor  ecx, ecx
.url:
    movzx eax, byte [rbx + PDO1_URL_OFF + rcx]
    cmp  ecx, r8d
    jae  .url_tail
    cmp  al, 0x21
    jb   .bad
    cmp  al, 0x7E
    ja   .bad
    cmp  al, '#'
    je   .bad
    jmp  .url_next
.url_tail:
    test al, al
    jnz  .bad
.url_next:
    inc  ecx
    cmp  ecx, PDO1_URL_FIELD
    jb   .url
    ; Reserved [416,768) is zero.
    mov  ecx, PDO1_RESERVED_OFF
.reserved:
    cmp  qword [rbx + rcx], 0
    jne  .bad
    add  ecx, 8
    cmp  ecx, PDO1_SIGNED_SIZE
    jb   .reserved
    ; The encoded nonce sits exactly at nonce_url_off (checked, never substituted).
    lea  rsi, [rbx + PDO1_URL_OFF + r10]
    cmp  r9d, PDO1_NONCE_B64_LEN
    je   .b64
    xor  ecx, ecx
.hex_equal:
    mov  al, [rbx + PDO1_NONCE_OFF + rcx]
    cmp  al, [rsi + rcx]
    jne  .bad
    inc  ecx
    cmp  ecx, PDO1_NONCE_HEX_LEN
    jb   .hex_equal
    jmp  .good
.b64:
    ; 32 input bytes = 10 full 3-byte groups + one 2-byte group with one '='.
    lea  rdi, [rbx + PDO1_NONCE_OFF]
    lea  r9, [rel pdo1_b64url]
    xor  ecx, ecx                    ; group index
.group:
    movzx eax, byte [rdi]
    shl  eax, 8
    movzx edx, byte [rdi + 1]
    or   eax, edx
    shl  eax, 8
    cmp  ecx, 10
    je   .last_group
    movzx edx, byte [rdi + 2]
    or   eax, edx
    mov  edx, eax
    shr  edx, 18
    and  edx, 63
    mov  dl, [r9 + rdx]
    cmp  dl, [rsi]
    jne  .bad
    mov  edx, eax
    shr  edx, 12
    and  edx, 63
    mov  dl, [r9 + rdx]
    cmp  dl, [rsi + 1]
    jne  .bad
    mov  edx, eax
    shr  edx, 6
    and  edx, 63
    mov  dl, [r9 + rdx]
    cmp  dl, [rsi + 2]
    jne  .bad
    mov  edx, eax
    and  edx, 63
    mov  dl, [r9 + rdx]
    cmp  dl, [rsi + 3]
    jne  .bad
    add  rdi, 3
    add  rsi, 4
    inc  ecx
    jmp  .group
.last_group:
    mov  edx, eax
    shr  edx, 18
    and  edx, 63
    mov  dl, [r9 + rdx]
    cmp  dl, [rsi]
    jne  .bad
    mov  edx, eax
    shr  edx, 12
    and  edx, 63
    mov  dl, [r9 + rdx]
    cmp  dl, [rsi + 1]
    jne  .bad
    mov  edx, eax
    shr  edx, 6
    and  edx, 63
    mov  dl, [r9 + rdx]
    cmp  dl, [rsi + 2]
    jne  .bad
    cmp  byte [rsi + 3], '='
    jne  .bad
.good:
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rbx
    ret

pdo1_context: db "PaOS/dd-boot-oracle/v1"
    times PDO1_CONTEXT_SIZE - ($ - pdo1_context) db 0
pdo1_https: db "https://"
pdo1_b64url: db "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
