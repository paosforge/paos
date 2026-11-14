;; MODULE core/localization
;; LAYER 1
;; EXPORTS l10n_utf8_valid, l10n_catalog_validate, l10n_catalog_find, l10n_templates_equal, l10n_map_validate, l10n_resolve
;; IMPORTS
;; CAPS
;; OWNER rc-codex-relops
;; CONTEXT: bsp_only
; RCQ-38 S1 native bounded catalog core. No storage, allocation or EFI writes.
; SysV ABI; preserve RBX/RBP/R12..R15. All input buffers are owned immutable RAM.
; The trusted loader authenticates exact artifact hashes BEFORE making contexts.
; Contexts, views and callbacks MUST NOT be populated from resource bytes.
; See gauntlet_v2/docs/localization/NATIVE_CORE.md for the complete ABI and limits.

L10N_VIEW_SIZE equ 32
L10N_MAX_TEXT equ 8192
L10N_MAX_COUNT equ 16384
L10N_MAX_CATALOG equ 1048576

; RDI current, RSI end -> EAX scalar, advanced RDI, CF=0. CF=1 malformed.
; Clobbers RCX,RDX,R8,R9. Never reads at or past end.
l10n_utf8_next:
    cmp rdi, rsi
    jae .bad
    movzx eax, byte [rdi]
    inc rdi
    cmp eax, 0x80
    jb .ok
    cmp eax, 0xc2
    jb .bad
    cmp eax, 0xe0
    jb .two
    cmp eax, 0xf0
    jb .three
    cmp eax, 0xf5
    jae .bad
    and eax, 7
    mov ecx, 3
    mov r8d, 0x10000
    jmp .tail
.three:
    and eax, 15
    mov ecx, 2
    mov r8d, 0x800
    jmp .tail
.two:
    and eax, 31
    mov ecx, 1
    mov r8d, 0x80
.tail:
    cmp rdi, rsi
    jae .bad
    movzx edx, byte [rdi]
    inc rdi
    mov r9d, edx
    and r9d, 0xc0
    cmp r9d, 0x80
    jne .bad
    and edx, 63
    shl eax, 6
    or eax, edx
    dec ecx
    jnz .tail
    cmp eax, r8d
    jb .bad
    cmp eax, 0x10ffff
    ja .bad
    cmp eax, 0xd800
    jb .ok
    cmp eax, 0xdfff
    jbe .bad
.ok:
    clc
    ret
.bad:
    stc
    ret

; RDI bytes, ESI length, EDX allowLF (0/1) -> EAX 1/0.
; Pinned Unicode15.0.0 Cf: exactly170 scalars in21 ranges, plus U+034F.
l10n_utf8_valid:
    push rbx
    push r12
    test esi, esi
    jz .bad
    cmp esi, L10N_MAX_TEXT
    ja .bad
    mov ebx, edx
    mov esi, esi
    add rsi, rdi
    jc .bad
    mov r12, rsi
.next:
    mov rsi, r12
    call l10n_utf8_next
    jc .bad
    cmp eax, 32
    jae .high
    cmp eax, 10
    jne .bad
    cmp ebx, 1
    jne .bad
    jmp .advance
.high:
    cmp eax, 127
    jb .advance
    cmp eax, 160
    jb .bad
    cmp eax, 0x034f
    je .bad
    lea rdx, [rel l10n_cf_ranges]
    mov ecx, 21
.cf:
    cmp eax, [rdx]
    jb .advance
    cmp eax, [rdx+4]
    jbe .bad
    add rdx, 8
    dec ecx
    jnz .cf
.advance:
    cmp rdi, r12
    jb .next
    mov eax, 1
    jmp .out
.bad:
    xor eax, eax
.out:
    pop r12
    pop rbx
    ret

; RDI,RSI two32-byte hashes -> EAX1 equal,0 unequal (fixed32 iterations).
l10n_hash_equal:
    xor eax, eax
    xor ecx, ecx
.loop:
    mov dl, [rdi+rcx]
    xor dl, [rsi+rcx]
    or al, dl
    inc ecx
    cmp ecx, 32
    jb .loop
    test al, al
    setz al
    movzx eax, al
    ret

; RDI cursor, RSI end -> RAX name start /0 at end /-1 bad,
; EDX name length, RDI next cursor. Escaped braces produce no token.
; Internal grammar walker: UTF8 validation is separate.
l10n_token:
.scan:
    cmp rdi, rsi
    jae .end
    mov al, [rdi]
    inc rdi
    cmp al, '{'
    je .open
    cmp al, '}'
    jne .scan
    cmp rdi, rsi
    jae .bad
    cmp byte [rdi], '}'
    jne .bad
    inc rdi
    jmp .scan
.open:
    cmp rdi, rsi
    jae .bad
    cmp byte [rdi], '{'
    jne .name
    inc rdi
    jmp .scan
.name:
    mov rax, rdi
    xor edx, edx
.letter:
    cmp rdi, rsi
    jae .bad
    mov cl, [rdi]
    cmp cl, '}'
    je .close
    cmp edx, 64
    jae .bad
    cmp cl, '_'
    je .take
    cmp cl, 'A'
    jb .digit
    cmp cl, 'Z'
    jbe .take
    cmp cl, 'a'
    jb .bad
    cmp cl, 'z'
    jbe .take
    jmp .bad
.digit:
    test edx, edx
    jz .bad
    cmp cl, '0'
    jb .bad
    cmp cl, '9'
    ja .bad
.take:
    inc edx
    inc rdi
    jmp .letter
.close:
    test edx, edx
    jz .bad
    inc rdi
    ret
.end:
    xor eax, eax
    xor edx, edx
    ret
.bad:
    mov rax, -1
    ret

; RDI text, ESI bytes, RDX target name/0=count all, ECX name bytes
; -> EAX occurrence count, -1 malformed. Fully scans grammar each time.
l10n_token_count:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdx
    mov r13d, ecx
    lea r14, [rdi+rsi]
    xor ebx, ebx
.loop:
    mov rsi, r14
    call l10n_token
    cmp rax, -1
    je .bad
    test rax, rax
    jz .done
    test r12, r12
    jz .match
    cmp edx, r13d
    jne .loop
    xor r15d, r15d
.cmp:
    mov cl, [rax+r15]
    cmp cl, [r12+r15]
    jne .loop
    inc r15d
    cmp r15d, r13d
    jb .cmp
.match:
    inc ebx
    jmp .loop
.done:
    mov eax, ebx
    jmp .out
.bad:
    mov eax, -1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; RDI English, ESI bytes, RDX translation, ECX bytes -> EAX1/0.
; Exact named-placeholder multiset, including repeated names; no printf parser.
; No allocation; quadratic worst case bounded by two8192-byte inputs.
l10n_templates_equal:
    mov esi, esi                   ; public ESI length, discard dirty upper bits
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 40
    mov r12, rdi
    mov r13d, esi
    mov r14, rdx
    mov r15d, ecx
    test esi, esi
    jz .bad
    cmp esi, L10N_MAX_TEXT
    ja .bad
    test ecx, ecx
    jz .bad
    cmp ecx, L10N_MAX_TEXT
    ja .bad
    xor edx, edx
    xor ecx, ecx
    call l10n_token_count
    cmp eax, -1
    je .bad
    mov ebx, eax
    mov rdi, r14
    mov esi, r15d
    xor edx, edx
    call l10n_token_count
    cmp eax, ebx
    jne .bad
    mov rbp, r12
.loop:
    mov rdi, rbp
    lea rsi, [r12+r13]
    call l10n_token
    test rax, rax
    jz .yes
    cmp rax, -1
    je .bad
    mov rbp, rdi
    mov [rsp], rax
    mov [rsp+8], edx
    mov rdi, r12
    mov esi, r13d
    mov ecx, edx
    mov rdx, rax
    call l10n_token_count
    mov ebx, eax
    mov rdi, r14
    mov esi, r15d
    mov rdx, [rsp]
    mov ecx, [rsp+8]
    call l10n_token_count
    cmp eax, ebx
    jne .bad
    jmp .loop
.yes:
    mov eax, 1
    jmp .out
.bad:
    xor eax, eax
.out:
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; RDI valid view, ESI stable ID -> RAX entry pointer/0, EDX table index.
; The view/buffer are private immutable state, never a serialized DATA pointer.
l10n_catalog_find:
    xor eax, eax
    test rdi, rdi
    jz .out
    cmp dword [rdi+24], 1
    jne .out
    mov r8, [rdi]
    xor ecx, ecx
    mov r9d, [rdi+12]
.search:
    cmp ecx, r9d
    jae .none
    lea edx, [rcx+r9]
    shr edx, 1
    mov eax, edx
    shl rax, 4
    lea rax, [r8+rax+64]
    cmp esi, [rax]
    je .out
    jb .lower
    lea ecx, [rdx+1]
    jmp .search
.lower:
    mov r9d, edx
    jmp .search
.none:
    xor eax, eax
.out:
    ret

; RDI bytes, ESI exact bytes, RDX trusted context, RCX out view -> EAX1/0.
; Context: locale u32@0, revision u32@4, schemaSHA32@8, artifactSHA32@40,
; trusted SHA callback qword@72, English view qword@80, authenticated u32@88=1.
; SHA callback(out32 RDI, bytes RSI, length RDX) -> EAX0 success, nonzero fail.
; English context needs no English view: exact authenticated artifact pin is its
; reviewed full contract. Translations require that independently validated view.
l10n_catalog_validate:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 72
    mov r12, rdi
    mov r13d, esi
    mov r14, rdx
    mov r15, rcx
    mov qword [r15], 0
    mov qword [r15+8], 0
    mov qword [r15+16], 0
    mov qword [r15+24], 0
    cmp esi, 64
    jb .bad
    cmp esi, L10N_MAX_CATALOG
    ja .bad
    test r12, r12
    jz .bad
    test r14, r14
    jz .bad
    cmp dword [r14+88], 1
    jne .bad
    cmp qword [r14+72], 0
    je .bad
    mov eax, r13d
    add rax, r12
    jc .bad
    lea rdi, [rsp]
    mov rsi, r12
    mov edx, r13d
    call [r14+72]
    test eax, eax
    jnz .bad
    lea rdi, [rsp]
    lea rsi, [r14+40]
    call l10n_hash_equal
    test eax, eax
    jz .bad
    mov rax, 0x0000003154414350 ; PCAT1\0\0\0
    cmp [r12], rax
    jne .bad
    cmp word [r12+8], 1
    jne .bad
    movzx eax, word [r12+10]
    cmp eax, 5
    ja .bad
    cmp eax, [r14]
    jne .bad
    cmp dword [r12+12], 0
    jne .bad
    mov eax, [r12+16]
    test eax, eax
    jz .bad
    cmp eax, [r14+4]
    jne .bad
    lea rdi, [r12+28]
    lea rsi, [r14+8]
    call l10n_hash_equal
    test eax, eax
    jz .bad
    cmp r13d, [r12+60]
    jne .bad
    mov ebx, [r12+20]
    cmp ebx, L10N_MAX_COUNT
    ja .bad
    mov eax, ebx
    shl eax, 4
    add eax, 64
    cmp eax, [r12+24]
    jne .bad
    cmp eax, r13d
    ja .bad
    mov [rsp+32], eax               ; running blob offset
    mov dword [rsp+36], 0           ; previous ID
    mov rbp, [r14+80]
    cmp dword [r14], 0
    je .english
    test rbp, rbp
    jz .bad
    cmp dword [rbp+24], 1
    jne .bad
    cmp dword [rbp+16], 0
    jne .bad
    mov rdi, [rbp]
    add rdi, 28
    lea rsi, [r14+8]
    call l10n_hash_equal
    test eax, eax
    jz .bad
    mov eax, [rbp+20]
    cmp eax, [r14+4]
    jne .bad
.english:
    xor ebx, ebx
.row:
    cmp ebx, [r12+20]
    jae .done
    mov eax, ebx
    shl eax, 4
    lea rax, [r12+rax+64]
    mov [rsp+40], rax
    mov edx, [rax]
    cmp edx, [rsp+36]
    jbe .bad
    mov [rsp+36], edx
    cmp dword [rax+12], 1
    ja .bad
    mov ecx, [rax+4]
    cmp ecx, [rsp+32]
    jne .bad
    mov esi, [rax+8]
    test esi, esi
    jz .bad
    cmp esi, L10N_MAX_TEXT
    ja .bad
    mov edx, r13d
    sub edx, ecx                    ; offset<=total, checked each prior end
    jc .bad
    cmp esi, edx
    ja .bad
    lea edx, [rcx+rsi]
    mov [rsp+32], edx
    lea rdi, [r12+rcx]
    mov edx, 1
    call l10n_utf8_valid
    test eax, eax
    jz .bad
    mov rax, [rsp+40]
    mov ecx, [rax+4]
    mov esi, [rax+8]
    lea rdi, [r12+rcx]
    mov rdx, rdi
    mov ecx, esi
    cmp dword [r14], 0
    je .templates
    mov rdi, rbp
    mov esi, [rax]
    call l10n_catalog_find
    test rax, rax
    jz .bad
    mov rcx, [rsp+40]
    mov edx, [rax+12]
    cmp edx, [rcx+12]
    jne .bad
    mov rdi, [rbp]
    mov edx, [rax+4]
    add rdi, rdx
    mov esi, [rax+8]
    mov edx, [rcx+4]
    add rdx, r12
    mov ecx, [rcx+8]
.templates:
    call l10n_templates_equal
    test eax, eax
    jz .bad
    inc ebx
    jmp .row
.done:
    mov eax, [rsp+32]
    cmp eax, r13d
    jne .bad
    mov [r15], r12
    mov [r15+8], r13d
    mov eax, [r12+20]
    mov [r15+12], eax
    mov eax, [r14]
    mov [r15+16], eax
    mov eax, [r14+4]
    mov [r15+20], eax
    mov dword [r15+24], 1
    mov eax, 1
    jmp .out
.bad:
    xor eax, eax
.out:
    add rsp, 72
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

align 4
l10n_cf_ranges:
    dd 0xad,0xad, 0x600,0x605, 0x61c,0x61c, 0x6dd,0x6dd
    dd 0x70f,0x70f, 0x890,0x891, 0x8e2,0x8e2, 0x180e,0x180e
    dd 0x200b,0x200f, 0x202a,0x202e, 0x2060,0x2064, 0x2066,0x206f
    dd 0xfeff,0xfeff, 0xfff9,0xfffb, 0x110bd,0x110bd, 0x110cd,0x110cd
    dd 0x13430,0x1343f, 0x1bca0,0x1bca3, 0x1d173,0x1d17a
    dd 0xe0001,0xe0001, 0xe0020,0xe007f

; RDI UTF8 English, ESI bytes, RDX native bytes, ECX bytes, R8D encoding0/1
; -> EAX1/0. UTF8 English has already passed the catalog validator.
l10n_fallback_equal:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    lea r13, [rdi+rsi]
    mov r14, rdx
    lea r15, [rdx+rcx]
    cmp r8d, 1
    ja .bad
    je .wide
    cmp esi, ecx
    jne .bad
    xor ebx, ebx
.bytes:
    cmp ebx, esi
    jae .yes
    mov al, [r12+rbx]
    cmp al, [r14+rbx]
    jne .bad
    inc ebx
    jmp .bytes
.wide:
    test ecx, 1
    jnz .bad
.scalar:
    cmp r12, r13
    jae .end
    mov rdi, r12
    mov rsi, r13
    call l10n_utf8_next
    jc .bad
    mov r12, rdi
    mov edx, 2
    cmp eax, 0x10000
    jb .short
    mov edx, 4
.short:
    mov rcx, r15
    sub rcx, r14
    cmp rcx, rdx
    jb .bad
    cmp edx, 4
    jne .bmp
    sub eax, 0x10000
    mov edx, eax
    shr eax, 10
    add eax, 0xd800
    cmp ax, [r14]
    jne .bad
    and edx, 1023
    add edx, 0xdc00
    cmp dx, [r14+2]
    jne .bad
    add r14, 4
    jmp .scalar
.bmp:
    cmp ax, [r14]
    jne .bad
    add r14, 2
    jmp .scalar
.end:
    cmp r14, r15
    jne .bad
.yes:
    mov eax, 1
    jmp .out
.bad:
    xor eax, eax
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; RDI map bytes, ESI exact bytes, RDX trusted map context, RCX out view ->1/0.
; Context: image file bytes u32@0, sites revision@4, image SHA32@8,
; sites SHA32@40, map artifact SHA32@72, SHA callback@104, mapped image base@112,
; SizeOfImage u32@120, initialized range count u32@124, ranges pointer@128,
; validated English view@136, private2048-byte scratch@144, scratch bytes@152,
; authenticated u32@156=1. Range records: u32 RVA,u32 initialized byte length.
; File identity is from verified boot state, NOT a hash of relocated memory.
l10n_map_validate:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 72
    mov r12, rdi
    mov r13d, esi
    mov r14, rdx
    mov r15, rcx
    mov qword [r15], 0
    mov qword [r15+8], 0
    mov qword [r15+16], 0
    mov qword [r15+24], 0
    cmp esi, 96
    jb .bad
    cmp esi, 1048576
    ja .bad
    test r12, r12
    jz .bad
    test r14, r14
    jz .bad
    cmp dword [r14+156], 1
    jne .bad
    cmp qword [r14+104], 0
    je .bad
    mov eax, r13d
    add rax, r12
    jc .bad
    lea rdi, [rsp]
    mov rsi, r12
    mov edx, r13d
    call [r14+104]
    test eax, eax
    jnz .bad
    lea rdi, [rsp]
    lea rsi, [r14+72]
    call l10n_hash_equal
    test eax, eax
    jz .bad
    mov rax, 0x0000003141565250 ; PRVA1\0\0\0
    cmp [r12], rax
    jne .bad
    cmp dword [r12+8], 1             ; version1, flags0
    jne .bad
    cmp qword [r12+88], 0
    jne .bad
    mov ebx, [r12+12]
    test ebx, ebx
    jz .bad
    cmp ebx, L10N_MAX_COUNT
    ja .bad
    shl ebx, 4
    add ebx, 96
    cmp ebx, r13d
    jne .bad
    mov eax, [r14]
    cmp eax, 64
    jb .bad
    cmp eax, 67108864
    ja .bad
    cmp eax, [r12+16]
    jne .bad
    mov eax, [r14+4]
    test eax, eax
    jz .bad
    cmp eax, [r12+20]
    jne .bad
    lea rdi, [r12+24]
    lea rsi, [r14+8]
    call l10n_hash_equal
    test eax, eax
    jz .bad
    lea rdi, [r12+56]
    lea rsi, [r14+40]
    call l10n_hash_equal
    test eax, eax
    jz .bad
    mov rbp, [r14+136]
    test rbp, rbp
    jz .bad
    cmp dword [rbp+24], 1
    jne .bad
    cmp dword [rbp+16], 0
    jne .bad
    cmp qword [r14+144], 0
    je .bad
    cmp dword [r14+152], 2048
    jb .bad
    mov rdi, [r14+144]
    mov ecx, 256
    xor eax, eax
    cld
    rep stosq                       ; duplicate-ID bitmap indexed by English row
    mov eax, [r14+120]
    test eax, eax
    jz .bad
    cmp eax, 67108864
    ja .bad
    mov rdx, [r14+112]
    test rdx, rdx
    jz .bad
    add rdx, rax
    jc .bad
    mov ecx, [r14+124]
    test ecx, ecx
    jz .bad
    cmp ecx, 32
    ja .bad
    mov rdi, [r14+128]
    test rdi, rdi
    jz .bad
    xor edx, edx
.range:
    mov eax, [rdi]
    cmp eax, edx
    jb .bad
    mov edx, [rdi+4]
    test edx, edx
    jz .bad
    add rax, rdx                    ;64-bit sum cannot wrap a u32 span
    mov edx, [r14+120]
    cmp rax, rdx
    ja .bad
    mov edx, eax
    add rdi, 8
    dec ecx
    jnz .range
    mov dword [rsp+32], 0           ; previous span end
    xor ebx, ebx
.row:
    cmp ebx, [r12+12]
    jae .done
    mov eax, ebx
    shl eax, 4
    lea rax, [r12+rax+96]
    mov [rsp+40], rax
    mov edi, [rax]
    cmp edi, [rsp+32]
    jb .bad
    mov esi, [rax+8]
    test esi, esi
    jz .bad
    cmp esi, 16384
    ja .bad
    cmp dword [rax+12], 1
    ja .bad
    mov edx, edi
    add rdx, rsi
    mov ecx, [r14+120]
    cmp rdx, rcx
    ja .bad
    mov [rsp+32], edx
    mov rcx, [r14+128]
    mov r8d, [r14+124]
.find_range:
    mov edx, [rcx]
    cmp edi, edx
    jb .next_range
    mov r9d, edi
    sub r9d, edx
    mov edx, [rcx+4]
    cmp r9d, edx
    jae .next_range
    sub edx, r9d
    cmp esi, edx
    ja .next_range
    cmp dword [rax+12], 0
    jne .in_range                   ; UTF16 uses explicit-length core callers
    cmp esi, edx
    jae .bad                        ; UTF8 C string needs one initialized NUL
    mov r9, [r14+112]
    mov r10d, [rax]
    add r9, r10
    add r9, rsi
    cmp byte [r9], 0
    jne .bad                        ; a prefix cannot stand for a whole C string
    jmp .in_range
.next_range:
    add rcx, 8
    dec r8d
    jnz .find_range
    jmp .bad
.in_range:
    mov rdi, rbp
    mov esi, [rax+4]
    call l10n_catalog_find
    test rax, rax
    jz .bad
    mov rcx, [r14+144]
    bt dword [rcx], edx
    jc .bad
    bts dword [rcx], edx
    mov rdi, [rbp]
    mov edx, [rax+4]
    add rdi, rdx
    mov esi, [rax+8]
    mov rax, [rsp+40]
    mov edx, [rax]
    add rdx, [r14+112]
    mov ecx, [rax+8]
    mov r8d, [rax+12]
    call l10n_fallback_equal
    test eax, eax
    jz .bad
    inc ebx
    jmp .row
.done:
    mov [r15], r12
    mov [r15+8], r13d
    mov eax, [r12+12]
    mov [r15+12], eax
    mov eax, [r14+4]
    mov [r15+20], eax
    mov dword [r15+24], 1
    mov eax, 1
    jmp .out
.bad:
    xor eax, eax
.out:
    add rsp, 72
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; RDI catalog view/0, RSI map view/0, RDX original native text,
; ECX native byte length, R8D encoding0/1, R9 verified mapped-image base.
; -> RAX text, EDX byte length, ECX encoding, R8D1 translation/0 English.
; Never scans native text for NUL. Any missing resource/ID/exact-pointer/length
; mismatch returns the original resource-free English span unchanged.
; Parameterized/escaped templates remain on the existing typed native path;
; never return them to an untyped renderer or treat translation as a program.
l10n_resolve:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp, 24
    mov r12, rdi
    mov r13, rsi
    mov r14, rdx
    mov r15d, ecx
    mov ebp, r8d
    test rdi, rdi
    jz .fallback
    cmp dword [rdi+24], 1
    jne .fallback
    cmp dword [rdi+16], 0
    je .fallback
    test rsi, rsi
    jz .fallback
    cmp dword [rsi+24], 1
    jne .fallback
    mov rdx, r14
    sub rdx, r9
    jc .fallback
    mov eax, 0xffffffff
    cmp rdx, rax
    ja .fallback
    mov ebx, edx
    mov r9, [rsi]
    xor ecx, ecx
    mov r10d, [rsi+12]
.search:
    cmp ecx, r10d
    jae .fallback
    lea edx, [rcx+r10]
    shr edx, 1
    mov eax, edx
    shl rax, 4
    lea rax, [r9+rax+96]
    cmp ebx, [rax]
    je .found
    jb .lower
    lea ecx, [rdx+1]
    jmp .search
.lower:
    mov r10d, edx
    jmp .search
.found:
    cmp r15d, [rax+8]
    jne .fallback
    cmp ebp, [rax+12]
    jne .fallback
    mov esi, [rax+4]
    mov rdi, r12
    call l10n_catalog_find
    test rax, rax
    jz .fallback
    mov edx, [rax+8]
    mov ecx, [rax+4]
    mov rax, [r12]
    add rax, rcx
    xor ecx, ecx
.literal:
    cmp ecx, edx
    jae .translated
    cmp byte [rax+rcx], '{'
    je .fallback
    cmp byte [rax+rcx], '}'
    je .fallback
    inc ecx
    jmp .literal
.translated:
    xor ecx, ecx
    mov r8d, 1
    jmp .out
.fallback:
    mov rax, r14
    mov edx, r15d
    mov ecx, ebp
    xor r8d, r8d
.out:
    add rsp, 24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
