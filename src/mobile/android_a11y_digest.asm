;; MODULE mobile/android_a11y_digest
;; LAYER 4
;; EXPORTS android_a11y_digest, A11Y_INPUT_CAP, A11Y_OUTPUT_CAP
;; IMPORTS core/lib/fmt
;; CAPS
;; OWNER saga:android_guest
; Task3347. Pure byte parser: no allocation, device, transport or retained state.
; Uses Task2701's caller/end/capped-output seam and shared fmt_dec. Unlike the
; permissive HTML reader, XML requires matched tags, unique attributes and a
; complete document. See fixtures/android_a11y_digest/README.md for grammar.
; Meaningful-node selection follows the archived android_pilot.py prototype;
; the manifest records its source hash and this contract's stronger byte API.

android_a11y_image_start:

A11Y_INPUT_CAP   equ 16384
A11Y_OUTPUT_CAP  equ 8192             ; includes final NUL
A11Y_DEPTH_CAP   equ 16               ; includes hierarchy root
A11Y_NODE_CAP    equ 64               ; all nodes, including omitted layouts
A11Y_ATTR_CAP    equ 32               ; all attributes, including unknown ones
A11Y_NAME_CAP    equ 64
A11Y_VALUE_CAP   equ 256              ; BOTH raw and expanded bytes
A11Y_COORD_CAP   equ 65535
A11Y_OK          equ 0
A11Y_SYNTAX      equ 1
A11Y_LIMIT       equ 2
A11Y_ARGUMENT    equ 3

; All scratch belongs to this invocation. No recursive descent or input-sized
; stack allocation. Attribute names are checked spans into immutable input.
AD_OUT          equ 0
AD_CAP          equ 8
AD_COUNT        equ 16
AD_DEPTH        equ 20
AD_NODES        equ 24
AD_ROOT         equ 28
AD_ATTRS        equ 32
AD_TAG          equ 36               ; 1=hierarchy, 2=node
AD_CLOSE        equ 40
AD_SELF         equ 44
AD_FLAGS        equ 48               ; c/e/s/k bits0..3, other action bits4..8
AD_BOUNDS_SEEN  equ 52
AD_BOUNDS       equ 56
AD_LENGTHS      equ 72               ; id,text,description,class
AD_VLEN         equ 88
AD_NAME         equ 96
AD_NLEN         equ 104
AD_NAMES        equ 112              ; 32 pairs of pointer,length
AD_FIELDS       equ 624              ; 4 * 257 bytes
AD_VALUE        equ 1652             ; 257 bytes, decoded attribute
AD_RAW          equ 1912
AD_AID          equ 1920
AD_QUOTE        equ 1924
AD_DEC          equ 1928             ; 32-byte shared formatter destination
AD_FRAME        equ 2008

; android_a11y_digest(RDI=input, RSI=length, RDX=output, RCX=capacity)
; -> EAX=status (0/1/2/3), RDX=payload bytes, ECX=emitted nodes.
; SysV callee saves preserved, DF clear required. Input immutable, output must
; be disjoint and mapped for min(capacity,8192). NULL allowed only with size=0.
; Integer pointer wrap/overlap is an argument error: NO stores. Otherwise the
; entire effective output capacity is zeroed, and any error retains zero bytes
; and nodes (including after valid earlier nodes). Capacity includes NUL; zero
; capacity can successfully represent an empty digest. Caller pointers must be
; mapped ordinary RAM; this is a length-safe parser, not a memory capability.
android_a11y_digest:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, AD_FRAME
    mov rbx, rsp
    mov r12, rdi
    mov r13, rdi
    mov r14, rdx
    mov r15, rdx
    mov rbp, rsi
    cmp rcx, A11Y_OUTPUT_CAP
    jbe .cap
    mov ecx, A11Y_OUTPUT_CAP
.cap:
    add r15, rcx
    jc .argument
    test rcx, rcx
    jz .input
    test rdx, rdx
    jz .argument
.input:
    add r13, rsi
    jc .argument
    test rsi, rsi
    jz .disjoint
    test r12, r12
    jz .argument
    test rcx, rcx
    jz .disjoint
    cmp r12, r15
    jae .disjoint
    cmp r14, r13
    jb .argument
.disjoint:
    mov rdi, rbx
    mov ecx, AD_FRAME
    xor eax, eax
    rep stosb
    mov [rbx + AD_OUT], r14
    mov rax, r15
    sub rax, r14
    mov [rbx + AD_CAP], rax
    mov rcx, rax
    mov rdi, r14
    xor eax, eax
    rep stosb
    cmp rbp, A11Y_INPUT_CAP
    ja .limit
    call ad_space
    cmp r12, r13
    je .success
    cmp byte [r12], '<'
    je .scan
    ; Non-XML garbage is an empty snapshot. Embedded markup is NOT allowed to
    ; smuggle a prefix before a tree; it is malformed, as is trailing garbage.
.garbage:
    cmp byte [r12], '<'
    je .syntax
    inc r12
    cmp r12, r13
    jb .garbage
    jmp .success
.scan:
    call ad_space
    cmp r12, r13
    jae .end
    cmp byte [r12], '<'
    jne .syntax
    inc r12
    cmp r12, r13
    jae .syntax
    cmp byte [r12], '!'
    je .comment
    ; Processing instructions (including XML declarations), DTDs and CDATA
    ; are not in this byte grammar. No external or user-defined entities.
    mov dword [rbx + AD_CLOSE], 0
    mov dword [rbx + AD_SELF], 0
    cmp byte [r12], '/'
    jne .tag
    mov dword [rbx + AD_CLOSE], 1
    inc r12
.tag:
    call ad_name
    test eax, eax
    jnz .error
    mov [rbx + AD_NAME], rsi
    mov [rbx + AD_NLEN], rcx
    lea rdi, [rel ad_hierarchy]
    call ad_equal
    test eax, eax
    jnz .hierarchy
    lea rdi, [rel ad_node]
    call ad_equal
    test eax, eax
    jz .syntax
    mov dword [rbx + AD_TAG], 2
    jmp .kind
.hierarchy:
    mov dword [rbx + AD_TAG], 1
.kind:
    cmp dword [rbx + AD_CLOSE], 0
    jne .close
    cmp dword [rbx + AD_ROOT], 2
    je .syntax
    cmp dword [rbx + AD_TAG], 1
    jne .open_node
    cmp dword [rbx + AD_ROOT], 0
    jne .syntax
    mov dword [rbx + AD_ROOT], 1
    jmp .open_depth
.open_node:
    cmp dword [rbx + AD_DEPTH], 0
    je .syntax
    cmp dword [rbx + AD_NODES], A11Y_NODE_CAP
    jae .limit
    inc dword [rbx + AD_NODES]
.open_depth:
    cmp dword [rbx + AD_DEPTH], A11Y_DEPTH_CAP
    jae .limit
    inc dword [rbx + AD_DEPTH]
    mov dword [rbx + AD_ATTRS], 0
    mov dword [rbx + AD_FLAGS], 2       ; enabled defaults true
    mov dword [rbx + AD_BOUNDS_SEEN], 0
    mov qword [rbx + AD_LENGTHS], 0
    mov qword [rbx + AD_LENGTHS + 8], 0
.attrs:
    mov rbp, r12
    call ad_space
    cmp r12, r13
    jae .syntax
    cmp byte [r12], '>'
    je .opened
    cmp byte [r12], '/'
    je .self
    cmp r12, rbp                       ; attributes require whitespace
    je .syntax
    cmp dword [rbx + AD_ATTRS], A11Y_ATTR_CAP
    jae .limit
    call ad_name
    test eax, eax
    jnz .error
    mov [rbx + AD_NAME], rsi
    mov [rbx + AD_NLEN], rcx
    ; Check duplicates for ALL names, not just the projected attributes.
    xor r8d, r8d
.duplicate:
    cmp r8d, [rbx + AD_ATTRS]
    jae .unique
    mov r9d, r8d
    shl r9d, 4                        ; index <32, product <=496
    cmp rcx, [rbx + AD_NAMES + r9 + 8]
    jne .next_name
    mov rdi, [rbx + AD_NAMES + r9]
    xor r10d, r10d
.same_name:
    cmp r10, rcx
    je .syntax
    mov al, [rsi + r10]
    cmp al, [rdi + r10]
    jne .next_name
    inc r10
    jmp .same_name
.next_name:
    inc r8d
    jmp .duplicate
.unique:
    mov r9d, r8d
    shl r9d, 4
    mov [rbx + AD_NAMES + r9], rsi
    mov [rbx + AD_NAMES + r9 + 8], rcx
    inc dword [rbx + AD_ATTRS]
    call ad_space
    mov al, '='
    call ad_expect
    test eax, eax
    jnz .error
    call ad_space
    call ad_value
    test eax, eax
    jnz .error
    call ad_attribute
    test eax, eax
    jnz .error
    jmp .attrs
.self:
    inc r12
    mov dword [rbx + AD_SELF], 1
    cmp r12, r13
    jae .syntax
    cmp byte [r12], '>'
    jne .syntax
.opened:
    inc r12
    cmp dword [rbx + AD_TAG], 2
    jne .after_emit
    call ad_emit_node
    test eax, eax
    jnz .error
.after_emit:
    cmp dword [rbx + AD_SELF], 0
    je .scan
    jmp .pop
.close:
    mov eax, [rbx + AD_DEPTH]
    test eax, eax
    jz .syntax
    mov edx, 2
    cmp eax, 1
    jne .close_kind
    mov edx, 1
.close_kind:
    cmp edx, [rbx + AD_TAG]
    jne .syntax
    call ad_space
    mov al, '>'
    call ad_expect
    test eax, eax
    jnz .error
.pop:
    dec dword [rbx + AD_DEPTH]
    jnz .scan
    mov dword [rbx + AD_ROOT], 2
    jmp .scan
.comment:
    ; The only <! construct is <!-- ... -->. Interior '--' is forbidden.
    mov rax, r13
    sub rax, r12
    cmp rax, 3
    jb .syntax
    cmp word [r12], '!-'
    jne .syntax
    cmp byte [r12 + 2], '-'
    jne .syntax
    add r12, 3
.comment_byte:
    cmp r12, r13
    jae .syntax
    mov al, [r12]
    inc r12
    cmp al, '-'
    je .comment_dash
    call ad_xml_byte
    test eax, eax
    jnz .error
    jmp .comment_byte
.comment_dash:
    cmp r12, r13
    jae .syntax
    cmp byte [r12], '-'
    jne .comment_byte
    inc r12
    mov al, '>'
    call ad_expect
    test eax, eax
    jnz .error
    jmp .scan
.end:
    cmp dword [rbx + AD_DEPTH], 0
    jne .syntax
    cmp dword [rbx + AD_ROOT], 0
    je .syntax                        ; comments alone are not a tree
.success:
    xor eax, eax
    mov rdx, r14
    sub rdx, [rbx + AD_OUT]
    mov ecx, [rbx + AD_COUNT]
    jmp .return
.syntax:
    mov eax, A11Y_SYNTAX
    jmp .error
.limit:
    mov eax, A11Y_LIMIT
.error:
    mov ebp, eax
    mov rdi, [rbx + AD_OUT]
    mov rcx, [rbx + AD_CAP]
    xor eax, eax
    rep stosb                         ; erase ALL partially produced lines
    mov eax, ebp
    jmp .zero
.argument:
    mov eax, A11Y_ARGUMENT
.zero:
    xor edx, edx
    xor ecx, ecx
.return:
    add rsp, AD_FRAME
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; Internal helpers keep RBX/R12..R15 as explicit parser registers. Cursor
; increments occur only after cursor<end. They do not allocate or recurse.
ad_space:
    cmp r12, r13
    jae .done
    mov al, [r12]
    cmp al, ' '
    je .next
    cmp al, 9
    je .next
    cmp al, 10
    je .next
    cmp al, 13
    jne .done
.next:
    inc r12
    jmp ad_space
.done:
    ret

ad_expect:
    cmp r12, r13
    jae ad_bad
    cmp al, [r12]
    jne ad_bad
    inc r12
    xor eax, eax
    ret

; Read an ASCII XML name subset; opaque unknown attributes still have caps.
ad_name:
    mov rsi, r12
    xor ecx, ecx
.loop:
    cmp r12, r13
    jae .end
    mov al, [r12]
    cmp al, '_'
    je .take
    cmp al, ':'
    je .take
    cmp al, 'A'
    jb .other
    cmp al, 'Z'
    jbe .take
    cmp al, 'a'
    jb .other
    cmp al, 'z'
    jbe .take
.other:
    test ecx, ecx
    jz .end
    cmp al, '-'
    je .take
    cmp al, '.'
    je .take
    cmp al, '0'
    jb .end
    cmp al, '9'
    ja .end
.take:
    cmp ecx, A11Y_NAME_CAP
    jae ad_limit
    inc r12
    inc ecx
    jmp .loop
.end:
    test ecx, ecx
    jz ad_bad
    xor eax, eax
    ret

; Exact bounded name span == trusted NUL-terminated literal, returns 0/1.
; Preserve RSI/RCX so callers can compare several names.
ad_equal:
    xor edx, edx
.loop:
    cmp rdx, rcx
    jae .end
    mov al, [rdi + rdx]
    test al, al
    jz .no
    cmp al, [rsi + rdx]
    jne .no
    inc rdx
    jmp .loop
.end:
    cmp byte [rdi + rdx], 0
    jne .no
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

ad_xml_byte:
    cmp al, 32
    jae .ok
    cmp al, 9
    je .ok
    cmp al, 10
    je .ok
    cmp al, 13
    jne ad_bad
.ok:
    xor eax, eax
    ret

; Decode attributes exactly once. Raw AND expanded lengths <=256; '&#...;'
; uses checked multiply/add then UTF-8 expansion of an XML scalar. Literal
; bytes >=0x80 are opaque and unchanged; no normalization or case folding.
ad_value:
    cmp r12, r13
    jae ad_bad
    mov al, [r12]
    cmp al, '"'
    je .quote
    cmp al, 39
    jne ad_bad
.quote:
    mov [rbx + AD_QUOTE], al
    inc r12
    mov [rbx + AD_RAW], r12
    mov dword [rbx + AD_VLEN], 0
.loop:
    cmp r12, r13
    jae ad_bad
    mov al, [r12]
    cmp al, [rbx + AD_QUOTE]
    je .done
    mov rdx, r12
    sub rdx, [rbx + AD_RAW]
    cmp rdx, A11Y_VALUE_CAP
    jae ad_limit
    inc r12
    cmp al, '<'
    je ad_bad
    cmp al, '&'
    je .entity
    mov r11b, al
    call ad_xml_byte
    test eax, eax
    jnz .return
    mov al, r11b
    call ad_value_byte
    test eax, eax
    jnz .return
    jmp .loop
.entity:
    call ad_entity
    test eax, eax
    jnz .return
    jmp .loop
.done:
    mov rdx, r12
    sub rdx, [rbx + AD_RAW]
    cmp rdx, A11Y_VALUE_CAP
    ja ad_limit
    inc r12
    mov eax, [rbx + AD_VLEN]
    mov byte [rbx + AD_VALUE + rax], 0
    xor eax, eax
.return:
    ret

ad_value_byte:
    mov edx, [rbx + AD_VLEN]
    cmp edx, A11Y_VALUE_CAP
    jae ad_limit
    mov [rbx + AD_VALUE + rdx], al
    inc dword [rbx + AD_VLEN]
    xor eax, eax
    ret

ad_entity:
    mov rsi, r12
    xor ecx, ecx
.scan:
    cmp r12, r13
    jae ad_bad
    mov al, [r12]
    cmp al, ';'
    je .end
    cmp ecx, A11Y_VALUE_CAP            ; raw value cap also bounds leading zeros
    jae ad_bad
    inc r12
    inc ecx
    jmp .scan
.end:
    inc r12
    mov rax, r12
    sub rax, [rbx + AD_RAW]
    cmp rax, A11Y_VALUE_CAP
    ja ad_limit
    test ecx, ecx
    jz ad_bad
    cmp byte [rsi], '#'
    je .number
    lea rdi, [rel ad_amp]
    call ad_equal
    test eax, eax
    jnz .amp
    lea rdi, [rel ad_lt]
    call ad_equal
    test eax, eax
    jnz .lt
    lea rdi, [rel ad_gt]
    call ad_equal
    test eax, eax
    jnz .gt
    lea rdi, [rel ad_quot]
    call ad_equal
    test eax, eax
    jnz .quot
    lea rdi, [rel ad_apos]
    call ad_equal
    test eax, eax
    jz ad_bad
    mov al, 39
    jmp ad_value_byte
.amp:
    mov al, '&'
    jmp ad_value_byte
.lt:
    mov al, '<'
    jmp ad_value_byte
.gt:
    mov al, '>'
    jmp ad_value_byte
.quot:
    mov al, '"'
    jmp ad_value_byte
.number:
    inc rsi
    dec ecx
    jz ad_bad
    mov r8d, 10
    cmp byte [rsi], 'x'
    jne .digits
    mov r8d, 16
    inc rsi
    dec ecx
    jz ad_bad
.digits:
    xor r9d, r9d
.digit:
    movzx eax, byte [rsi]
    sub eax, '0'
    cmp eax, 9
    jbe .have_digit
    cmp r8d, 16
    jne ad_bad
    movzx eax, byte [rsi]
    or eax, 32
    sub eax, 'a'
    cmp eax, 5
    ja ad_bad
    add eax, 10
.have_digit:
    ; Before multiply: accumulator<=0x10FFFF, base<=16, product cannot
    ; overflow u32. Still validate the scalar cap BEFORE accepting each digit.
    imul r9d, r8d
    add r9d, eax
    jc ad_limit
    cmp r9d, 0x10ffff
    ja ad_limit
    inc rsi
    dec ecx
    jnz .digit
    cmp r9d, 0x20
    jae .scalar
    cmp r9d, 9
    je .scalar
    cmp r9d, 10
    je .scalar
    cmp r9d, 13
    jne ad_bad
.scalar:
    cmp r9d, 0xd800
    jb .encode
    cmp r9d, 0xdfff
    jbe ad_bad
    cmp r9d, 0xfffe
    je ad_bad
    cmp r9d, 0xffff
    je ad_bad
.encode:
    mov ecx, 1
    cmp r9d, 0x7f
    jbe .room
    inc ecx
    cmp r9d, 0x7ff
    jbe .room
    inc ecx
    cmp r9d, 0xffff
    jbe .room
    inc ecx
.room:
    mov edx, A11Y_VALUE_CAP
    sub edx, [rbx + AD_VLEN]
    cmp ecx, edx
    ja ad_limit
    mov edx, [rbx + AD_VLEN]
    lea rdi, [rbx + AD_VALUE + rdx]
    add [rbx + AD_VLEN], ecx            ; proven <=256
    mov eax, r9d
    cmp ecx, 1
    je .single
    cmp ecx, 2
    je .two
    cmp ecx, 3
    je .three
    shr eax, 18
    or al, 0xf0
    stosb
    mov eax, r9d
    shr eax, 12
    and al, 63
    or al, 0x80
    stosb
    jmp .tail_two
.three:
    shr eax, 12
    or al, 0xe0
    stosb
    jmp .tail_two
.two:
    shr eax, 6
    or al, 0xc0
    stosb
    jmp .last
.tail_two:
    mov eax, r9d
    shr eax, 6
    and al, 63
    or al, 0x80
    stosb
.last:
    mov eax, r9d
    and al, 63
    or al, 0x80
.single:
    stosb
    xor eax, eax
    ret

; Semantic table uses rel32 offsets, never compile-time dq runtime pointers.
; id/text/desc/class ids0..3, bool ids4..14, bounds15. All recognized
; boolean attributes are checked even on nodes which will not be emitted.
ad_attribute:
    lea r10, [rel ad_attr_table]
    xor r8d, r8d
.find:
    movsxd rdi, dword [r10 + r8*4]
    add rdi, r10
    mov rsi, [rbx + AD_NAME]
    mov rcx, [rbx + AD_NLEN]
    call ad_equal
    test eax, eax
    jnz .known
    inc r8d
    cmp r8d, 16
    jb .find
    xor eax, eax                       ; unknown attr was still bounded/decoded
    ret
.known:
    cmp r8d, 4
    jb .field
    cmp r8d, 15
    je ad_bounds
    mov [rbx + AD_AID], r8d
    lea rsi, [rbx + AD_VALUE]
    mov ecx, [rbx + AD_VLEN]
    lea rdi, [rel ad_true]
    call ad_equal
    test eax, eax
    jnz .true
    lea rdi, [rel ad_false]
    call ad_equal
    test eax, eax
    jz ad_bad
    mov eax, [rbx + AD_AID]
    sub eax, 4
    btr [rbx + AD_FLAGS], eax
    xor eax, eax
    ret
.true:
    mov eax, [rbx + AD_AID]
    sub eax, 4
    bts [rbx + AD_FLAGS], eax
    xor eax, eax
    ret
.field:
    mov ecx, [rbx + AD_VLEN]
    mov [rbx + AD_LENGTHS + r8*4], ecx
    imul eax, r8d, A11Y_VALUE_CAP + 1   ; id<4, offset<=771
    lea rdi, [rbx + AD_FIELDS + rax]
    lea rsi, [rbx + AD_VALUE]
    inc ecx                            ; <=257 including NUL
    rep movsb
    xor eax, eax
    ret

ad_bounds:
    lea rsi, [rbx + AD_VALUE]
    mov ecx, [rbx + AD_VLEN]
    lea rdi, [rsi + rcx]
    lea r10, [rel ad_bound_delims]
    xor r8d, r8d
.next:
    cmp rsi, rdi
    jae ad_bad
    mov al, [r10 + r8]
    cmp al, [rsi]
    jne ad_bad
    inc rsi
    xor r9d, r9d
    xor ecx, ecx
.digit:
    cmp rsi, rdi
    jae ad_bad
    movzx eax, byte [rsi]
    sub eax, '0'
    cmp eax, 9
    ja .after_number
    ; Guard decimal multiply/add before either can overflow or exceed cap.
    cmp r9d, A11Y_COORD_CAP / 10
    ja ad_limit
    jne .multiply
    cmp eax, A11Y_COORD_CAP % 10
    ja ad_limit
.multiply:
    imul r9d, 10
    add r9d, eax
    inc ecx
    inc rsi
    jmp .digit
.after_number:
    test ecx, ecx
    jz ad_bad
    mov [rbx + AD_BOUNDS + r8*4], r9d
    inc r8d
    cmp r8d, 2
    jne .check_four
    cmp byte [rsi], ']'
    jne ad_bad
    inc rsi
.check_four:
    cmp r8d, 4
    jb .next
    cmp byte [rsi], ']'
    jne ad_bad
    inc rsi
    cmp rsi, rdi
    jne ad_bad
    mov eax, [rbx + AD_BOUNDS]
    cmp eax, [rbx + AD_BOUNDS + 8]
    ja ad_bad
    mov eax, [rbx + AD_BOUNDS + 4]
    cmp eax, [rbx + AD_BOUNDS + 12]
    ja ad_bad
    mov dword [rbx + AD_BOUNDS_SEEN], 1
    xor eax, eax
    ret

; Output helpers reserve payload plus NUL by subtraction, never addition of
; attacker-controlled sizes. Each successful append leaves an exact terminator.
ad_put_byte:
    mov rdx, r15
    sub rdx, r14
    cmp rdx, 2
    jb ad_limit
    mov [r14], al
    inc r14
    mov byte [r14], 0
    xor eax, eax
    ret

ad_put_literal:
    mov al, [rsi]
    test al, al
    jz .done
    call ad_put_byte
    test eax, eax
    jnz .done
    inc rsi
    jmp ad_put_literal
.done:
    ret

ad_put_number:
    ; RDI is a previously bounded coordinate or emitted node index.
    lea rsi, [rbx + AD_DEC]
    push rbp
    mov rbp, rsp
    and rsp, -16
    call fmt_dec
    mov rsp, rbp
    pop rbp
    lea rsi, [rbx + AD_DEC]
    jmp ad_put_literal

; Percent-escape all grammar delimiters, '%' and ASCII control bytes. UTF-8
; octets pass through unchanged. Bounds/index punctuation is emitted only here.
ad_put_field:
    test ecx, ecx
    jz .done
    mov al, [rsi]
    cmp al, 32
    jb .escape
    cmp al, 127
    je .escape
    cmp al, '%'
    je .escape
    cmp al, '|'
    je .escape
    cmp al, '='
    je .escape
    cmp al, '['
    je .escape
    cmp al, ']'
    je .escape
    cmp al, 92
    je .escape
    cmp al, '"'
    je .escape
    call ad_put_byte
    test eax, eax
    jnz .return
    jmp .next
.escape:
    mov rdx, r15
    sub rdx, r14
    cmp rdx, 4
    jb ad_limit
    mov byte [r14], '%'
    movzx edx, al
    shr edx, 4
    lea rdi, [rel ad_hex]
    mov dl, [rdi + rdx]
    mov [r14 + 1], dl
    and eax, 15
    mov al, [rdi + rax]
    mov [r14 + 2], al
    add r14, 3
    mov byte [r14], 0
.next:
    inc rsi
    dec ecx
    jmp ad_put_field
.done:
    xor eax, eax
.return:
    ret

ad_emit_node:
    ; Prototype _is_meaningful: labelled or clickable/checkable/scrollable/
    ; long-clickable. A resource ID or focusable flag alone is layout metadata.
    ; Only XML ASCII whitespace is ignored for selection; output keeps every
    ; original decoded byte, including whitespace and opaque high bytes.
    test dword [rbx + AD_FLAGS], 0x71
    jnz .emit
    mov r8d, 1                        ; text then description, never ID/class
.label:
    imul eax, r8d, A11Y_VALUE_CAP + 1   ; index 1..2, offset <=514
    lea rsi, [rbx + AD_FIELDS + rax]
    mov ecx, [rbx + AD_LENGTHS + r8*4]
.label_byte:
    test ecx, ecx
    jz .next_label
    mov al, [rsi]
    inc rsi
    dec ecx
    cmp al, ' '
    je .label_byte
    cmp al, 9
    je .label_byte
    cmp al, 10
    je .label_byte
    cmp al, 13
    je .label_byte
    jmp .emit
.next_label:
    inc r8d
    cmp r8d, 3
    jb .label
    jmp .empty
.emit:
    cmp dword [rbx + AD_BOUNDS_SEEN], 1
    jne ad_bad
    mov al, '['
    call ad_put_byte
    test eax, eax
    jnz .return
    mov edi, [rbx + AD_COUNT]
    call ad_put_number
    test eax, eax
    jnz .return
    lea rsi, [rel ad_index_end]
    call ad_put_literal
    test eax, eax
    jnz .return
    ; Format each semantic field in a fixed order independent of XML order.
    xor ebp, ebp
.field:
    lea r10, [rel ad_field_prefixes]
    movsxd rsi, dword [r10 + rbp*4]
    add rsi, r10
    call ad_put_literal
    test eax, eax
    jnz .return
    imul eax, ebp, A11Y_VALUE_CAP + 1
    lea rsi, [rbx + AD_FIELDS + rax]
    mov ecx, [rbx + AD_LENGTHS + rbp*4]
    call ad_put_field
    test eax, eax
    jnz .return
    inc ebp
    cmp ebp, 4
    jb .field
    xor ebp, ebp
.flag:
    lea r10, [rel ad_flag_prefixes]
    movsxd rsi, dword [r10 + rbp*4]
    add rsi, r10
    call ad_put_literal
    test eax, eax
    jnz .return
    bt [rbx + AD_FLAGS], ebp
    setc al
    add al, '0'
    call ad_put_byte
    test eax, eax
    jnz .return
    inc ebp
    cmp ebp, 4
    jb .flag
    lea rsi, [rel ad_b_prefix]
    call ad_put_literal
    test eax, eax
    jnz .return
    xor ebp, ebp
.coord:
    mov edi, [rbx + AD_BOUNDS + rbp*4]
    call ad_put_number
    test eax, eax
    jnz .return
    inc ebp
    cmp ebp, 4
    je .finish
    cmp ebp, 2
    je .middle
    mov al, ','
    call ad_put_byte
    test eax, eax
    jnz .return
    jmp .coord
.middle:
    lea rsi, [rel ad_middle]
    call ad_put_literal
    test eax, eax
    jnz .return
    jmp .coord
.finish:
    lea rsi, [rel ad_line_end]
    call ad_put_literal
    test eax, eax
    jnz .return
    inc dword [rbx + AD_COUNT]          ; cannot exceed bounded all-node count
.empty:
    xor eax, eax
.return:
    ret

ad_bad:
    mov eax, A11Y_SYNTAX
    ret
ad_limit:
    mov eax, A11Y_LIMIT
    ret

ad_hierarchy: db 'hierarchy',0
ad_node: db 'node',0
ad_amp: db 'amp',0
ad_lt: db 'lt',0
ad_gt: db 'gt',0
ad_quot: db 'quot',0
ad_apos: db 'apos',0
ad_true: db 'true',0
ad_false: db 'false',0
ad_bound_delims: db '[,[,'
ad_hex: db '0123456789ABCDEF'
ad_attr_table:
    dd ad_id - ad_attr_table, ad_text - ad_attr_table
    dd ad_desc - ad_attr_table, ad_class - ad_attr_table
    dd ad_clickable - ad_attr_table, ad_enabled - ad_attr_table
    dd ad_selected - ad_attr_table, ad_checked - ad_attr_table
    dd ad_checkable - ad_attr_table, ad_scrollable - ad_attr_table
    dd ad_long - ad_attr_table, ad_focusable - ad_attr_table
    dd ad_focused - ad_attr_table, ad_password - ad_attr_table
    dd ad_visible - ad_attr_table, ad_bounds_name - ad_attr_table
ad_id: db 'resource-id',0
ad_text: db 'text',0
ad_desc: db 'content-desc',0
ad_class: db 'class',0
ad_clickable: db 'clickable',0
ad_enabled: db 'enabled',0
ad_selected: db 'selected',0
ad_checked: db 'checked',0
ad_checkable: db 'checkable',0
ad_scrollable: db 'scrollable',0
ad_long: db 'long-clickable',0
ad_focusable: db 'focusable',0
ad_focused: db 'focused',0
ad_password: db 'password',0
ad_visible: db 'visible-to-user',0
ad_bounds_name: db 'bounds',0
ad_field_prefixes:
    dd ad_id_prefix - ad_field_prefixes, ad_text_prefix - ad_field_prefixes
    dd ad_desc_prefix - ad_field_prefixes, ad_class_prefix - ad_field_prefixes
ad_flag_prefixes:
    dd ad_c_prefix - ad_flag_prefixes, ad_e_prefix - ad_flag_prefixes
    dd ad_s_prefix - ad_flag_prefixes, ad_k_prefix - ad_flag_prefixes
ad_index_end: db ']',0
ad_id_prefix: db '|id=',0
ad_text_prefix: db '|text=',0
ad_desc_prefix: db '|desc=',0
ad_class_prefix: db '|class=',0
ad_c_prefix: db '|c=',0
ad_e_prefix: db '|e=',0
ad_s_prefix: db '|s=',0
ad_k_prefix: db '|k=',0
ad_b_prefix: db '|b=[',0
ad_middle: db '][',0
ad_line_end: db ']',10,0
