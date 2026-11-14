;; MODULE web/light_extract
;; LAYER 4
;; EXPORTS web_light_extract
;; IMPORTS
;; CAPS
;; OWNER saga:web_browser
; RCQ49 light reader: allocation-free ASCII text / markup subset / JSON.
; web_light_extract: SysV RDI=in, RSI=length (0..1024), RDX=out,
; RCX=capacity (1..4096 incl NUL), R8D=format (0 text,1 HTML,2 feed,3 JSON).
; Returns EAX=0 OK,1 bounds/alias,2 malformed,3 unsupported; RDX=used.
; On failure used=0 and valid disjoint output[0]=NUL. No I/O/global state.
; Callee-saved registers preserved. Input and output must be mapped for bounds.
web_light_extract:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 320
    mov rbp, rsp
    mov r12, rdi
    mov r13, rdi
    mov rbx, rdx
    mov r14, rdx
    mov r15, rdx
    mov dword [rbp], 0                 ; container/tag depth, max 8
    mov dword [rbp+4], r8d             ; format
    mov dword [rbp+8], 0               ; suppressed script/style depth
    mov dword [rbp+12], 0              ; output writable (after alias check)
    mov [rbp+16], rdi                  ; original start, declaration only at byte0
    test rcx, rcx
    jz .bounds_early
    cmp rcx, 4096
    ja .bounds_early
    test rbx, rbx
    jz .bounds_early
    add r15, rcx
    jc .bounds_early
    test rsi, rsi
    jz .range
    test r12, r12
    jz .bounds_early
    add r13, rsi
    jc .bounds_early
    cmp rbx, r13
    jae .range
    cmp r12, r15
    jb .bounds_early                  ; reject overlap without changing input
.range:
    mov dword [rbp+12], 1
    mov byte [rbx], 0
    cmp rsi, 1024
    ja .bounds_early
    cmp r8d, 3
    ja .unsupported
    mov rdi, r12
.validate:
    cmp rdi, r13
    jae .validated
    movzx eax, byte [rdi]
    inc rdi
    cmp al, 127
    jae .unsupported
    cmp al, 32
    jae .validate
    cmp al, 9
    je .validate
    cmp al, 10
    je .validate
    cmp al, 13
    je .validate
    jmp .malformed
.validated:
    test r8d, r8d
    jz .text
    cmp r8d, 3
    je .json
    call wl_markup
    jmp .parsed
.text:
    cmp r12, r13
    jae .success
    movzx eax, byte [r12]
    inc r12
    call wl_emit
    test eax, eax
    jnz .parsed
    jmp .text
.json:
    call wl_json_value
    test eax, eax
    jnz .parsed
    call wl_ws
    cmp r12, r13
    jne .malformed
.parsed:
    test eax, eax
    jnz .failure
.success:
    cmp r14, rbx
    je .done
    cmp byte [r14-1], ' '
    jne .done
    dec r14
.done:
    mov byte [r14], 0
    mov rdx, r14
    sub rdx, rbx
    xor eax, eax
    jmp .return
.bounds_early:
    mov eax, 1
    jmp .failure
.malformed:
    mov eax, 2
    jmp .failure
.unsupported:
    mov eax, 3
.failure:
    cmp dword [rbp+12], 0
    je .failed
    mov byte [rbx], 0
.failed:
    xor edx, edx
.return:
    add rsp, 320
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; Helpers preserve R8..R11 except where explicitly used by parser. End-exclusive.
wl_bad:
    mov eax, 2
    ret
wl_unsupported:
    mov eax, 3
    ret
wl_ok:
    xor eax, eax
    ret
wl_ws:
    cmp r12, r13
    jae wl_ok
    mov al, [r12]
    cmp al, ' '
    je .skip
    cmp al, 9
    je .skip
    cmp al, 10
    je .skip
    cmp al, 13
    jne wl_ok
.skip:
    inc r12
    jmp wl_ws
wl_space:
    mov eax, ' '
wl_emit:
    cmp al, 32
    ja .character
    mov al, ' '
    cmp r14, rbx
    je wl_ok
    cmp byte [r14-1], ' '
    je wl_ok
    ; A separator at the final NUL slot can only be trailing on success.
    ; Leave that slot as NUL. Any later character still fails the unchanged
    ; character bound, so words cannot merge or bypass capacity.
    lea rdx, [r14+1]
    cmp rdx, r15
    jae wl_ok
.character:
    lea rdx, [r14+1]
    cmp rdx, r15
    jae .full
    mov [r14], al
    inc r14
    mov byte [r14], 0
    xor eax, eax
    ret
.full:
    mov eax, 1
    ret

; Entity decoder consumes through ';', returns character AL, status in EDX.
wl_entity:
    inc r12
    mov rdi, r12
.find:
    cmp r12, r13
    jae .bad
    cmp byte [r12], ';'
    je .found
    inc r12
    mov rax, r12
    sub rax, rdi
    cmp rax, 8
    jbe .find
.bad:
    mov edx, 2
    ret
.found:
    mov rcx, r12
    sub rcx, rdi
    inc r12
    cmp rcx, 2
    jne .three
    cmp word [rdi], 'lt'
    je .lt
    cmp word [rdi], 'gt'
    je .gt
.three:
    cmp rcx, 3
    jne .four
    cmp word [rdi], 'am'
    jne .numeric
    cmp byte [rdi+2], 'p'
    je .amp
.four:
    cmp rcx, 4
    jne .numeric
    cmp dword [rdi], 'quot'
    je .quot
    cmp dword [rdi], 'apos'
    je .apos
.numeric:
    test rcx, rcx
    jz .bad
    cmp byte [rdi], '#'
    jne .bad
    inc rdi
    dec rcx
    jz .bad
    xor eax, eax
.digit:
    movzx edx, byte [rdi]
    sub edx, '0'
    cmp edx, 9
    ja .bad
    imul eax, 10
    add eax, edx
    cmp eax, 126
    ja .bad
    inc rdi
    loop .digit
    cmp eax, 32
    jb .bad
    xor edx, edx
    ret
.lt: mov eax, '<'
    jmp .ok
.gt: mov eax, '>'
    jmp .ok
.amp: mov eax, '&'
    jmp .ok
.quot: mov eax, '"'
    jmp .ok
.apos: mov eax, 39
.ok:
    xor edx, edx
    ret

; XML1.0 declaration subset, feed only and exactly at original byte0.
; Optional encoding is UTF-8 (ASCII subset still enforced by whole preflight).
; No other PI, standalone, DTD or external resource resolution is introduced.
wl_xml_declaration:
    cmp dword [rbp+4], 2
    jne wl_unsupported
    mov rax,[rbp+16]
    inc rax
    cmp r12,rax
    jne wl_bad
    xor r10d,r10d
    lea rsi,[rel wl_xml_start]
    call wl_xml_literal
    test eax,eax
    jnz .return
    mov r9,r12
    call wl_ws
    cmp r12,r9
    je wl_bad
    lea rsi,[rel wl_xml_version]
    call wl_xml_literal
    test eax,eax
    jnz .return
    lea rsi,[rel wl_xml_10]
    call wl_xml_quoted
    test eax,eax
    jnz .return
    mov r9,r12
    call wl_ws
    mov rax,r13
    sub rax,r12
    cmp rax,2
    jb wl_bad
    cmp word [r12],'?>'
    je .end
    cmp r12,r9                       ; encoding requires separating whitespace
    je wl_bad
    lea rsi,[rel wl_xml_encoding]
    call wl_xml_literal
    test eax,eax
    jnz .return
    lea rsi,[rel wl_xml_utf8]
    mov r10d,1                      ; XML encoding names are case-insensitive
    call wl_xml_quoted
    test eax,eax
    jnz .return
    call wl_ws
    mov rax,r13
    sub rax,r12
    cmp rax,2
    jb wl_bad
    cmp word [r12],'?>'
    jne wl_bad
.end:
    add r12,2
    xor eax,eax
.return:
    ret
; RSI points at a trusted fixed NUL token. Cursor advances within the input.
; R10D enables ASCII lowercase matching for encoding values only.
wl_xml_literal:
.loop:
    mov al,[rsi]
    test al,al
    jz wl_ok
    cmp r12,r13
    jae wl_bad
    mov dl,[r12]
    test r10d,r10d
    jz .compare
    or dl,32
.compare:
    cmp dl,al
    jne wl_bad
    inc r12
    inc rsi
    jmp .loop
; Match Eq and a quoted fixed value, with XML whitespace around '='.
wl_xml_quoted:
    call wl_ws
    cmp r12,r13
    jae wl_bad
    cmp byte [r12],'='
    jne wl_bad
    inc r12
    call wl_ws
    cmp r12,r13
    jae wl_bad
    movzx r8d,byte [r12]
    cmp r8b,'"'
    je .value
    cmp r8b,39
    jne wl_bad
.value:
    inc r12
    call wl_xml_literal
    test eax,eax
    jnz .return
    cmp r12,r13
    jae wl_bad
    cmp [r12],r8b
    jne wl_bad
    inc r12
    xor eax,eax
.return:
    ret
wl_xml_start: db '?xml',0
wl_xml_version: db 'version',0
wl_xml_10: db '1.0',0
wl_xml_encoding: db 'encoding',0
wl_xml_utf8: db 'utf-8',0

; Markup subset. Lowercase name stack (8*32B at rbp+64); attrs omitted.
; Balanced fragments; HTML void elements allowed only for format 1. Comments
; skipped. Feed-only initial XML1.0 declaration and literal CDATA are supported.
; Other PI/DTD/entities beyond the five named + decimal ASCII are refused.
wl_markup:
.loop:
    cmp r12, r13
    jae .end
    movzx eax, byte [r12]
    cmp al, '<'
    je .tag
    cmp dword [rbp+4],2
    jne .text_context
    cmp al,']'
    jne .text_context
    mov rdx,r13
    sub rdx,r12
    cmp rdx,3
    jb .text_context
    cmp word [r12],']]'
    jne .text_context
    cmp byte [r12+2],'>'
    je wl_bad                       ; CDATA terminator outside its section
.text_context:
    cmp dword [rbp+8], 0
    jne .skip_text
    cmp al, '&'
    jne .text
    call wl_entity
    test edx, edx
    jnz wl_bad
    jmp .emit
.text:
    inc r12
.emit:
    call wl_emit
    test eax, eax
    jnz .return
    jmp .loop
.skip_text:
    inc r12
    jmp .loop
.tag:
    inc r12
    cmp r12, r13
    jae wl_bad
    cmp byte [r12],'?'
    jne .not_pi
    call wl_xml_declaration
    test eax,eax
    jnz .return
    jmp .loop
.not_pi:
    cmp byte [r12], '!'
    jne .ordinary
    cmp dword [rbp+4],2
    jne .comment_start
    mov rax,r13
    sub rax,r12
    cmp rax,8
    jb .comment_start
    cmp dword [r12],'![CD'
    jne .comment_start
    cmp dword [r12+4],'ATA['
    jne .comment_start
    cmp dword [rbp],0
    je wl_bad                       ; CDATA only inside an open feed tag
    add r12,8
.cdata:
    cmp r12,r13
    jae wl_bad
    mov rax,r13
    sub rax,r12
    cmp rax,3
    jb .cdata_byte
    cmp word [r12],']]'
    jne .cdata_byte
    cmp byte [r12+2],'>'
    je .cdata_end
.cdata_byte:
    movzx eax,byte [r12]
    inc r12
    cmp dword [rbp+8],0
    jne .cdata
    call wl_emit                    ; literal characters, no tags/entities/PI
    test eax,eax
    jnz .return
    jmp .cdata
.cdata_end:
    add r12,3
    jmp .loop
.comment_start:
    ; No DTD or external entities. Only <!-- ... --> remains here.
    mov rax, r13
    sub rax, r12
    cmp rax, 3
    jb wl_bad
    cmp word [r12], '!-'
    jne wl_unsupported
    cmp byte [r12+2], '-'
    jne wl_unsupported
    add r12, 3
.comment:
    mov rax, r13
    sub rax, r12
    cmp rax, 3
    jb wl_bad
    cmp word [r12], '--'
    jne .next_comment
    cmp byte [r12+2], '>'
    je .comment_end
    jmp wl_bad                     ; internal -- not valid XML comment
.next_comment:
    inc r12
    jmp .comment
.comment_end:
    add r12, 3
    jmp .loop
.ordinary:
    xor r8d, r8d                   ; close flag
    cmp byte [r12], '/'
    jne .name_start
    inc r12
    mov r8d, 1
.name_start:
    mov qword [rbp+32], 0
    mov qword [rbp+40], 0
    mov qword [rbp+48], 0
    mov qword [rbp+56], 0
    xor r9d, r9d                   ; name length
.name:
    cmp r12, r13
    jae wl_bad
    movzx eax, byte [r12]
    cmp dword [rbp+4], 1
    jne .lower
    cmp al, 'A'
    jb .lower
    cmp al, 'Z'
    ja .lower
    or al, 32
.lower:
    cmp al, 'A'
    jb .lowercase
    cmp al, 'Z'
    jbe .name_char
.lowercase:
    cmp al, 'a'
    jb .other_name
    cmp al, 'z'
    jbe .name_char
.other_name:
    test r9d, r9d
    jz wl_bad
    cmp al, '0'
    jb .punct
    cmp al, '9'
    jbe .name_char
.punct:
    cmp al, '-'
    je .name_char
    cmp al, ':'
    je .name_char
    cmp al, '_'
    je .name_char
    jmp .name_done
.name_char:
    cmp r9d, 31
    jae wl_unsupported
    mov [rbp+32+r9], al
    inc r9d
    inc r12
    jmp .name
.name_done:
    mov byte [rbp+32+r9], 0
    ; Require whitespace, / or > between name and attributes.
    cmp al, '>'
    je .attrs
    cmp al, '/'
    je .attrs
    cmp al, ' '
    je .attrs
    cmp al, 9
    je .attrs
    cmp al, 10
    je .attrs
    cmp al, 13
    jne wl_bad
.attrs:
    call wl_ws
    cmp r12, r13
    jae wl_bad
    mov al, [r12]
    cmp al, '>'
    je .tag_end
    cmp al, '/'
    je .self_close
    test r8d, r8d
    jnz wl_bad
    ; Scan omitted attributes, respecting quote boundaries. This deliberately
    ; accepts opaque non-< attr bytes, not an HTML attribute semantic parser.
    cmp al, '<'
    je wl_bad
    cmp al, '"'
    je .quoted
    cmp al, 39
    je .quoted
    inc r12
    jmp .attrs
.quoted:
    mov dl, al
    inc r12
.quote_loop:
    cmp r12, r13
    jae wl_bad
    mov al, [r12]
    inc r12
    cmp al, dl
    je .attrs
    cmp al, '<'
    je wl_bad
    jmp .quote_loop
.self_close:
    test r8d, r8d
    jnz wl_bad
    inc r12
    cmp r12, r13
    jae wl_bad
    cmp byte [r12], '>'
    jne wl_bad
    mov r8d, 2
.tag_end:
    inc r12
    cmp r8d, 1
    je .close
    cmp r8d, 2
    je .boundary
    ; HTML void names; feeds require explicit close or />.
    cmp dword [rbp+4], 1
    jne .push
    lea rsi, [rel wl_void_names]
.void_next:
    cmp byte [rsi], 0
    je .push
    lea rdi, [rbp+32]
.void_compare:
    mov al, [rsi]
    cmp al, [rdi]
    jne .void_skip
    inc rsi
    inc rdi
    test al, al
    jnz .void_compare
    jmp .boundary
.void_skip:
    cmp byte [rsi], 0
    je .void_advance
    inc rsi
    jmp .void_skip
.void_advance:
    inc rsi
    jmp .void_next
.push:
    mov ecx, [rbp]
    cmp ecx, 8
    jae wl_unsupported
    shl ecx, 5
    lea rdi, [rbp+64+rcx]
    lea rsi, [rbp+32]
    mov ecx, 32
    rep movsb
    inc dword [rbp]
    ; Suppression begins only on script/style tags, in both markup formats.
    cmp dword [rbp+8], 0
    jne .boundary
    cmp dword [rbp+32], 'scri'
    jne .style
    cmp word [rbp+36], 'pt'
    jne .boundary
    cmp byte [rbp+38], 0
    jne .boundary
    jmp .suppress
.style:
    cmp dword [rbp+32], 'styl'
    jne .boundary
    cmp word [rbp+36], 'e'
    jne .boundary
.suppress:
    mov eax, [rbp]
    mov [rbp+8], eax
    jmp .boundary
.close:
    mov ecx, [rbp]
    test ecx, ecx
    jz wl_bad
    dec ecx
    shl ecx, 5
    lea rdi, [rbp+64+rcx]
    lea rsi, [rbp+32]
    mov ecx, 32
    repe cmpsb
    jne wl_bad
    mov eax, [rbp]
    cmp eax, [rbp+8]
    jne .pop
    mov dword [rbp+8], 0
.pop:
    dec dword [rbp]
.boundary:
    cmp dword [rbp+8], 0
    jne .loop
    call wl_space
    test eax, eax
    jnz .return
    jmp .loop
.end:
    cmp dword [rbp], 0
    jne wl_bad
    xor eax, eax
.return:
    ret
wl_void_names: db 'br',0,'hr',0,'meta',0,'link',0,'img',0,'input',0,'area',0,'base',0,'col',0,'embed',0,'param',0,'source',0,'track',0,'wbr',0,0

; JSON recursive descent: max container depth 8, complete document required.
wl_json_value:
    call wl_ws
    cmp r12, r13
    jae wl_bad
    mov al, [r12]
    cmp al, '"'
    je wl_json_string
    cmp al, '{'
    je wl_json_object
    cmp al, '['
    je wl_json_array
    cmp al, 't'
    je .true
    cmp al, 'f'
    je .false
    cmp al, 'n'
    je .null
    jmp wl_json_number
.true:
    mov rax, r13
    sub rax, r12
    cmp rax, 4
    jb wl_bad
    cmp dword [r12], 'true'
    jne wl_bad
    mov ecx, 4
    jmp wl_json_literal
.false:
    mov rax, r13
    sub rax, r12
    cmp rax, 5
    jb wl_bad
    cmp dword [r12], 'fals'
    jne wl_bad
    cmp byte [r12+4], 'e'
    jne wl_bad
    mov ecx, 5
    jmp wl_json_literal
.null:
    mov rax, r13
    sub rax, r12
    cmp rax, 4
    jb wl_bad
    cmp dword [r12], 'null'
    jne wl_bad
    mov ecx, 4
wl_json_literal:
    call wl_space
    test eax, eax
    jnz .return
.loop:
    movzx eax, byte [r12]
    inc r12
    call wl_emit
    test eax, eax
    jnz .return
    loop .loop
.return:
    ret
wl_json_open:
    cmp dword [rbp], 8
    jae wl_unsupported
    inc dword [rbp]
    inc r12
    call wl_ws
    xor eax, eax
    ret
wl_json_object:
    call wl_json_open
    test eax, eax
    jnz .return
    cmp r12, r13
    jae wl_bad
    cmp byte [r12], '}'
    je .close
.member:
    cmp r12, r13
    jae wl_bad
    cmp byte [r12], '"'
    jne wl_bad
    call wl_json_string
    test eax, eax
    jnz .return
    call wl_ws
    cmp r12, r13
    jae wl_bad
    cmp byte [r12], ':'
    jne wl_bad
    inc r12
    call wl_json_value
    test eax, eax
    jnz .return
    call wl_ws
    cmp r12, r13
    jae wl_bad
    cmp byte [r12], '}'
    je .close
    cmp byte [r12], ','
    jne wl_bad
    inc r12
    call wl_ws
    jmp .member
.close:
    inc r12
    dec dword [rbp]
    xor eax, eax
.return:
    ret
wl_json_array:
    call wl_json_open
    test eax, eax
    jnz .return
    cmp r12, r13
    jae wl_bad
    cmp byte [r12], ']'
    je .close
.member:
    call wl_json_value
    test eax, eax
    jnz .return
    call wl_ws
    cmp r12, r13
    jae wl_bad
    cmp byte [r12], ']'
    je .close
    cmp byte [r12], ','
    jne wl_bad
    inc r12
    jmp .member
.close:
    inc r12
    dec dword [rbp]
    xor eax, eax
.return:
    ret
wl_json_string:
    inc r12
    call wl_space
    test eax, eax
    jnz .return
.loop:
    cmp r12, r13
    jae wl_bad
    movzx eax, byte [r12]
    inc r12
    cmp al, '"'
    je wl_ok
    cmp al, 32
    jb wl_bad
    cmp al, 92
    jne .emit
    cmp r12, r13
    jae wl_bad
    movzx eax, byte [r12]
    inc r12
    cmp al, '"'
    je .emit
    cmp al, 92
    je .emit
    cmp al, '/'
    je .emit
    cmp al, 'u'
    je .unicode
    cmp al, 'b'
    je .space
    cmp al, 'f'
    je .space
    cmp al, 'n'
    je .space
    cmp al, 'r'
    je .space
    cmp al, 't'
    jne wl_bad
.space:
    mov eax, ' '
    jmp .emit
.unicode:
    mov rax, r13
    sub rax, r12
    cmp rax, 4
    jb wl_bad
    xor r10d, r10d
    mov r11d, 4
.hex:
    movzx eax, byte [r12]
    inc r12
    sub eax, '0'
    cmp eax, 9
    jbe .hex_value
    sub eax, ('a'-'0')
    cmp eax, 5
    jbe .hex_letter
    add eax, ('a'-'A')
    cmp eax, 5
    ja wl_bad
.hex_letter:
    add eax, 10
.hex_value:
    shl r10d, 4
    or r10d, eax
    dec r11d
    jnz .hex
    mov eax, r10d
    cmp eax, 126
    ja wl_unsupported
    cmp eax, 32
    jb wl_bad
.emit:
    call wl_emit
    test eax, eax
    jz .loop
.return:
    ret
wl_json_number:
    mov r10, r12
    cmp byte [r12], '-'
    jne .integer
    inc r12
.integer:
    cmp r12, r13
    jae wl_bad
    mov al, [r12]
    cmp al, '0'
    je .zero
    cmp al, '1'
    jb wl_bad
    cmp al, '9'
    ja wl_bad
.digits:
    inc r12
    cmp r12, r13
    jae .emit
    mov al, [r12]
    cmp al, '0'
    jb .fraction
    cmp al, '9'
    jbe .digits
    jmp .fraction
.zero:
    inc r12
.fraction:
    cmp r12, r13
    jae .emit
    cmp byte [r12], '.'
    jne .exponent
    inc r12
    call .required_digit
    test eax, eax
    jnz .return
.frac_digits:
    inc r12
    cmp r12, r13
    jae .emit
    mov al, [r12]
    cmp al, '0'
    jb .exponent
    cmp al, '9'
    jbe .frac_digits
.exponent:
    cmp r12, r13
    jae .emit
    mov al, [r12]
    or al, 32
    cmp al, 'e'
    jne .emit
    inc r12
    cmp r12, r13
    jae wl_bad
    mov al, [r12]
    cmp al, '+'
    je .sign
    cmp al, '-'
    jne .exp_digit
.sign:
    inc r12
.exp_digit:
    call .required_digit
    test eax, eax
    jnz .return
.exp_digits:
    inc r12
    cmp r12, r13
    jae .emit
    mov al, [r12]
    cmp al, '0'
    jb .emit
    cmp al, '9'
    jbe .exp_digits
.emit:
    call wl_space
    test eax, eax
    jnz .return
    mov r11, r10
.emit_next:
    cmp r11, r12
    jae wl_ok
    movzx eax, byte [r11]
    inc r11
    call wl_emit
    test eax, eax
    jz .emit_next
.return:
    ret
.required_digit:
    cmp r12, r13
    jae wl_bad
    cmp byte [r12], '0'
    jb wl_bad
    cmp byte [r12], '9'
    ja wl_bad
    xor eax, eax
    ret
