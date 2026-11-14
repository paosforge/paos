;; MODULE web/light_kat
;; LAYER 4
;; EXPORTS web_light_selftest
;; IMPORTS boot/serial, web/light_extract, core/lib/mem
;; CAPS
;; OWNER saga:web_browser
; Boot-only inert fixtures; no network, owner, credentials, model or session.
web_light_selftest:
    push r12
    sub rsp, 80
    mov r12, rsp
    mov rax, 0x6b6b6b6b6b6b6b6b
    mov [r12+64], rax
    mov [r12+72], rax
    lea rdi, [rel wlk_text]
    mov esi, wlk_text.len
    xor r8d, r8d
    lea r9, [rel wlk_text_out]
    mov r10d, 11
    call web_light_kat_case
    test eax, eax
    jnz .bad
    lea rdi, [rel wlk_html]
    mov esi, wlk_html.len
    mov r8d, 1
    lea r9, [rel wlk_html_out]
    mov r10d, 5
    call web_light_kat_case
    test eax, eax
    jnz .bad
    lea rdi, [rel wlk_feed]
    mov esi, wlk_feed.len
    mov r8d, 2
    lea r9, [rel wlk_feed_out]
    mov r10d, 3
    call web_light_kat_case
    test eax, eax
    jnz .bad
    lea rdi, [rel wlk_json]
    mov esi, wlk_json.len
    mov r8d, 3
    lea r9, [rel wlk_json_out]
    mov r10d, 8
    call web_light_kat_case
    test eax, eax
    jnz .bad
    lea rdi, [rel wlk_bad]
    mov esi, wlk_bad.len
    mov rdx, r12
    mov ecx, 64
    mov r8d, 1
    call web_light_extract
    cmp eax, 2
    jne .bad
    test rdx, rdx
    jnz .bad
    cmp byte [r12], 0
    jne .bad
    lea rdi, [rel wlk_short]
    mov esi, 3
    mov rdx, r12
    mov ecx, 3
    xor r8d, r8d
    call web_light_extract
    cmp eax, 1
    jne .bad
    test rdx, rdx
    jnz .bad
    cmp byte [r12], 0
    jne .bad
    lea rdi, [rel wlk_utf8]
    mov esi, 2
    mov rdx, r12
    mov ecx, 64
    xor r8d, r8d
    call web_light_extract
    cmp eax, 3
    jne .bad
    test rdx, rdx
    jnz .bad
    cmp byte [r12], 0
    jne .bad
    mov rax, 0x6b6b6b6b6b6b6b6b
    cmp [r12+64], rax
    jne .bad
    cmp [r12+72], rax
    jne .bad
    lea rdi, [rel wlk_pass]
    call serial_string
    xor eax, eax
    jmp .out
.bad:
    lea rdi, [rel wlk_fail]
    call serial_string
    mov eax, 1
.out:
    ; Retire all parser/KAT scratch even after refusal.
    push rax
    mov rdi, r12
    mov edx, 80
    xor esi, esi
    call memset
    pop rax
    add rsp, 80
    pop r12
    ret
web_light_kat_case:
    push r9
    push r10
    mov rdx, r12
    mov ecx, 64
    call web_light_extract
    pop rcx
    pop rsi
    test eax, eax
    jnz .bad
    cmp rdx, rcx
    jne .bad
    mov rdi, r12
    mov rdx, rcx
    inc rdx
    call memcmp
    test eax, eax
    jnz .bad
    xor eax, eax
    ret
.bad:
    mov eax, 1
    ret
wlk_text: db '  Hello',9,'world  '
.len equ $-wlk_text
wlk_text_out: db 'Hello world',0
wlk_html: db '<p>A &amp; B</p>'
.len equ $-wlk_html
wlk_html_out: db 'A & B',0
wlk_feed: db '<feed><title>A</title><item>B</item></feed>'
.len equ $-wlk_feed
wlk_feed_out: db 'A B',0
wlk_json: db '{"x":[1,true]}'
.len equ $-wlk_json
wlk_json_out: db 'x 1 true',0
wlk_bad: db '<p>oops'
.len equ $-wlk_bad
wlk_short: db 'abc'
wlk_utf8: db 0xc3,0xa9
wlk_pass: db '[web.light.kat] PASS formats=4 negative=3 ascii_subset=1',13,10,0
wlk_fail: db '[web.light.kat] FAIL',13,10,0
