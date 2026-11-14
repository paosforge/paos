;; MODULE web/structured_kat
;; LAYER 4
;; EXPORTS web_structured_selftest
;; IMPORTS boot/serial, web/bounded_field_reader, web/structured_data, web/light_kat
;; CAPS
;; OWNER saga:web_browser
; Boot KATs for Task2701.  Markers are emitted only after content/status checks
; through the exact product reader and extractor entry points.

web_structured_selftest:
    push rbx
    push r12
    call web_light_selftest
    ; quoted success: exact consumed/stored and terminating NUL.
    lea  rdi, [rel web_kat_reader_ok]
    lea  rsi, [rel web_kat_reader_ok.end]
    lea  rdx, [rel web_kat_reader_buf]
    mov  ecx, 8
    xor  r8d, r8d
    call web_field_read_bounded
    test eax, eax
    jnz  .reader_fail
    cmp  edx, 5
    jne  .reader_fail
    cmp  ecx, 3
    jne  .reader_fail
    cmp  dword [rel web_kat_reader_buf], 0x00636261
    jne  .reader_fail
    ; capacity refusal still terminates at the last legal byte.
    lea  rdi, [rel web_kat_reader_ok]
    lea  rsi, [rel web_kat_reader_ok.end]
    lea  rdx, [rel web_kat_reader_buf]
    mov  ecx, 3
    xor  r8d, r8d
    call web_field_read_bounded
    cmp  eax, WEB_FIELD_BOUNDS
    jne  .reader_fail
    cmp  byte [rel web_kat_reader_buf + 2], 0
    jne  .reader_fail
    ; unterminated quote and cursor==end are explicit truncations.
    lea  rdi, [rel web_kat_reader_trunc]
    lea  rsi, [rel web_kat_reader_trunc.end]
    lea  rdx, [rel web_kat_reader_buf]
    mov  ecx, 8
    xor  r8d, r8d
    call web_field_read_bounded
    cmp  eax, WEB_FIELD_TRUNCATED
    jne  .reader_fail
    lea  rdi, [rel web_kat_reader_trunc.end]
    mov  rsi, rdi
    lea  rdx, [rel web_kat_reader_buf]
    mov  ecx, 8
    xor  r8d, r8d
    call web_field_read_bounded
    cmp  eax, WEB_FIELD_TRUNCATED
    jne  .reader_fail
    lea  rdi, [rel str_web_reader_kat_pass]
    call serial_string
    jmp  .extract
.reader_fail:
    lea  rdi, [rel str_web_reader_kat_fail]
    call serial_string
    jmp  .out

.extract:
    lea  rdi, [rel web_kat_mixed]
    mov  esi, web_kat_mixed.len
    lea  rdx, [rel web_kat_arena]
    mov  ecx, 1200
    call web_struct_extract
    test eax, eax
    jnz  .extract_fail
    cmp  ecx, 2
    jne  .extract_fail
    lea  rdi, [rel web_kat_arena]
    lea  rsi, [rel web_kat_need_og]
    call web_kat_contains
    test eax, eax
    jz   .extract_fail
    lea  rdi, [rel web_kat_arena]
    lea  rsi, [rel web_kat_need_img]
    call web_kat_contains
    test eax, eax
    jz   .extract_fail
    lea  rdi, [rel web_kat_bad_attr]
    mov  esi, web_kat_bad_attr.len
    lea  rdx, [rel web_kat_arena]
    mov  ecx, 1200
    call web_struct_extract
    cmp  eax, WEB_STRUCT_TRUNCATED
    jne  .extract_fail
    lea  rdi, [rel web_kat_bad_json]
    mov  esi, web_kat_bad_json.len
    lea  rdx, [rel web_kat_arena]
    mov  ecx, 1200
    call web_struct_extract
    cmp  eax, WEB_STRUCT_MALFORMED
    jne  .extract_fail
    lea  rdi, [rel web_kat_overlong]
    mov  esi, web_kat_overlong.len
    lea  rdx, [rel web_kat_arena]
    mov  ecx, 1200
    call web_struct_extract
    cmp  eax, WEB_STRUCT_BOUNDS
    jne  .extract_fail
    lea  rdi, [rel str_web_extract_kat_pass]
    call serial_string
    jmp  .out
.extract_fail:
    lea  rdi, [rel str_web_extract_kat_fail]
    call serial_string
.out:
    pop  r12
    pop  rbx
    ret

; RDI=haystack, RSI=needle. Both are bounded, terminated KAT/product outputs.
web_kat_contains:
    push rbx
    push r12
    mov  rbx, rdi
    mov  r12, rsi
.next:
    cmp  byte [rbx], 0
    je   .miss
    mov  rdi, rbx
    mov  rsi, r12
.cmp:
    movzx eax, byte [rsi]
    test al, al
    jz   .hit
    cmp  al, [rdi]
    jne  .advance
    inc  rdi
    inc  rsi
    jmp  .cmp
.advance:
    inc  rbx
    jmp  .next
.hit:
    mov  eax, 1
    jmp  .out
.miss:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

web_kat_reader_ok: db '"abc"'
.end:
web_kat_reader_trunc: db '"abc'
.end:
web_kat_mixed: db '<meta property="og:title" content="Kat"><img src="/k.png" alt="K" width="20" height="20">'
.len: equ $ - web_kat_mixed
web_kat_bad_attr: db '<meta property="og:title" content="unterminated>'
.len: equ $ - web_kat_bad_attr
web_kat_bad_json: db '<script type="application/ld+json">{"name":[1,2}</script>'
.len: equ $ - web_kat_bad_json
web_kat_overlong: db '<meta property="og:title" content="'
    times 257 db 'A'
    db '">'
.len: equ $ - web_kat_overlong
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_web_structured_kat_0 0
web_kat_need_og: db 'og:title=Kat',0
web_kat_need_img: db 'image:i0=%2Fk.png%7CK%7C20x20%7Ccontent',0
str_web_reader_kat_pass: db '[PAOS64] M6 web: bounded field reader KAT PASS (end cap terminate read-once) [web.structured.reader.kat]',13,10,0
str_web_reader_kat_fail: db '[PAOS64] M6 web: bounded field reader KAT FAIL',13,10,0
str_web_extract_kat_pass: db '[PAOS64] M6 web: structured extractor KAT PASS (mixed + hostile subset) [web.structured.extract.kat]',13,10,0
str_web_extract_kat_fail: db '[PAOS64] M6 web: structured extractor KAT FAIL',13,10,0
; web_kat_reader_buf..web_kat_arena moved to WDATA_web_structured_kat_0_bss1 (zero-fill tail)
%endmacro
WDATA_DEFER WDATA_web_structured_kat_0
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER), in block order.
%macro WDATA_web_structured_kat_0_bss1 0
resb 41                 ; keeps web_kat_reader_buf at its WDATA offset mod 64
web_kat_reader_buf: resb 16
web_kat_arena: resb 1200
%endmacro
WDATA_BSS_DEFER WDATA_web_structured_kat_0_bss1
