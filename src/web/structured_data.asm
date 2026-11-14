;; MODULE web/structured_data
;; LAYER 4
;; EXPORTS web_struct_extract
;; IMPORTS web/bounded_field_reader, core/lib/str, core/lib/fmt
;; CAPS
;; OWNER saga:web_browser
; Task2701 offline structured-data core.  No transport, allocator, guest, DNS,
; TCP, TLS, HTTP, renderer, timer, or retained parser state exists here.

WEB_STRUCT_OK              equ 0
WEB_STRUCT_TRUNCATED       equ 1
WEB_STRUCT_BOUNDS          equ 2
WEB_STRUCT_MALFORMED       equ 3
WEB_STRUCT_TOO_MANY_FIELDS equ 4

WEB_CORE_INPUT_CAP   equ 65536
WEB_FIELD_COUNT_CAP equ 16
WEB_NAME_CAP         equ 65       ; 64 bytes plus NUL
WEB_VALUE_CAP        equ 257      ; 256 bytes plus NUL
WEB_TABLE_ROWS_CAP   equ 16
WEB_TABLE_COLS_CAP   equ 16
WEB_FORM_CTRLS_CAP   equ 16
WEB_IMAGES_CAP       equ 16
WEB_JSON_DEPTH_CAP   equ 8

; Stack-local scratch.  Every byte derived from input first arrives through
; web_field_read_bounded into one of these capped buffers.
WEB_L_TAG        equ 0
WEB_L_ANAME      equ 80
WEB_L_SKIPVAL    equ 160
WEB_L_TYPE       equ 432
WEB_L_PROPERTY   equ 704
WEB_L_CONTENT    equ 976
WEB_L_ITEMPROP   equ 1248
WEB_L_ITEMTYPE   equ 1520
WEB_L_NAME       equ 1792
WEB_L_METHOD     equ 2064
WEB_L_ACTION     equ 2336
WEB_L_SRC        equ 2608
WEB_L_ALT        equ 2880
WEB_L_WIDTH      equ 3152
WEB_L_HEIGHT     equ 3216
WEB_L_ROW        equ 3280
WEB_L_COMBO      equ 3552
WEB_L_ARENA      equ 3824
WEB_L_COUNT      equ 3832
WEB_L_REQUIRED   equ 3840
WEB_L_ITEMSCOPE  equ 3841
WEB_L_TABLE_IN   equ 3842
WEB_L_ROW_KIND   equ 3843       ; 0 none, 1 header, 2 data
WEB_L_ROW_CELLS  equ 3844
WEB_L_TABLE_ROWS equ 3848
WEB_L_TABLE_COLS equ 3852
WEB_L_ROW_LEN    equ 3856
WEB_L_FORM_INDEX equ 3860
WEB_L_IMAGE_INDEX equ 3864
WEB_L_CLOSING    equ 3868
WEB_L_ROW_OPEN   equ 3869
WEB_L_FRAME      equ 4096

; web_struct_extract(input,input_len,arena,arena_cap)
;   in:  RDI=input, RSI=input_len, RDX=caller arena, RCX=arena_cap
;   out: RAX=WEB_STRUCT_*, RDX=used bytes, RCX=record count
; On every refusal used=count=0 and arena[0]=NUL when cap>0.
web_struct_extract:
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, WEB_L_FRAME
    mov  rbx, rsp
    mov  [rbx + WEB_L_ARENA], rdx
    mov  dword [rbx + WEB_L_COUNT], 0
    mov  dword [rbx + WEB_L_FORM_INDEX], 0
    mov  dword [rbx + WEB_L_IMAGE_INDEX], 0
    mov  byte [rbx + WEB_L_TABLE_IN], 0
    mov  byte [rbx + WEB_L_ROW_OPEN], 0
    test rdx, rdx
    jz   .malformed_early
    test rcx, rcx
    jz   .bounds_early
    mov  byte [rdx], 0
    cmp  rsi, WEB_CORE_INPUT_CAP
    ja   .bounds
    test rdi, rdi
    jz   .malformed
    mov  r12, rdi
    mov  r13, rdi
    add  r13, rsi
    jc   .bounds
    mov  r14, rdx                         ; current output NUL
    mov  r15, rdx
    add  r15, rcx
    jc   .bounds
.scan:
    cmp  r12, r13
    jae  .success
    movzx eax, byte [r12]
    test al, al
    jz   .malformed
    cmp  al, '<'
    jne  .ordinary_byte
    inc  r12
    cmp  r12, r13
    jae  .truncated
    movzx eax, byte [r12]
    cmp  al, '!'
    je   .declaration
    cmp  al, '?'
    je   .declaration
    mov  byte [rbx + WEB_L_CLOSING], 0
    cmp  al, '/'
    jne  .read_tag
    mov  byte [rbx + WEB_L_CLOSING], 1
    inc  r12
    cmp  r12, r13
    jae  .truncated
.read_tag:
    mov  rdi, r12
    mov  rsi, r13
    lea  rdx, [rbx + WEB_L_TAG]
    mov  ecx, WEB_NAME_CAP
    xor  r8d, r8d
    call web_field_read_bounded
    test eax, eax
    jnz  .field_error
    test rcx, rcx
    jz   .malformed
    add  r12, rdx
    lea  rdi, [rbx + WEB_L_TAG]
    call web_ascii_lower
    cmp  byte [rbx + WEB_L_CLOSING], 1
    je   .closing_tag
    call web_clear_tag_state
    call web_parse_attributes
    test eax, eax
    jnz  .field_error
    call web_handle_open_tag
    test eax, eax
    jnz  .field_error
    jmp  .scan
.closing_tag:
    call web_skip_tag_tail
    test eax, eax
    jnz  .field_error
    call web_handle_close_tag
    test eax, eax
    jnz  .field_error
    jmp  .scan
.declaration:
    call web_skip_tag_tail
    test eax, eax
    jnz  .field_error
    jmp  .scan
.ordinary_byte:
    inc  r12
    jmp  .scan

.field_error:
    cmp  eax, WEB_FIELD_TRUNCATED
    je   .truncated
    cmp  eax, WEB_FIELD_BOUNDS
    je   .bounds
    cmp  eax, WEB_STRUCT_TOO_MANY_FIELDS
    je   .too_many
    cmp  eax, WEB_STRUCT_TRUNCATED
    je   .truncated
    cmp  eax, WEB_STRUCT_BOUNDS
    je   .bounds
    jmp  .malformed
.success:
    ; Tables are the one HTML subset whose structural well-formedness is part
    ; of the public contract.  An input ending inside a table/row is malformed,
    ; never partial success with retained records.
    cmp  byte [rbx + WEB_L_TABLE_IN], 0
    jne  .malformed
    cmp  byte [rbx + WEB_L_ROW_OPEN], 0
    jne  .malformed
    mov  rdx, r14
    sub  rdx, [rbx + WEB_L_ARENA]
    mov  ecx, [rbx + WEB_L_COUNT]
    xor  eax, eax
    jmp  .out
.truncated:
    mov  eax, WEB_STRUCT_TRUNCATED
    jmp  .refuse
.bounds_early:
    mov  eax, WEB_STRUCT_BOUNDS
    jmp  .out_zero
.bounds:
    mov  eax, WEB_STRUCT_BOUNDS
    jmp  .refuse
.too_many:
    mov  eax, WEB_STRUCT_TOO_MANY_FIELDS
    jmp  .refuse
.malformed_early:
    mov  eax, WEB_STRUCT_MALFORMED
    jmp  .out_zero
.malformed:
    mov  eax, WEB_STRUCT_MALFORMED
.refuse:
    mov  rdx, [rbx + WEB_L_ARENA]
    test rdx, rdx
    jz   .out_zero
    mov  byte [rdx], 0
.out_zero:
    xor  edx, edx
    xor  ecx, ecx
.out:
    add  rsp, WEB_L_FRAME
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; Lowercase one bounded-reader output.  Its NUL is trusted because only that
; helper creates these scratch strings.
web_ascii_lower:
.loop:
    movzx eax, byte [rdi]
    test al, al
    jz   .done
    cmp  al, 'A'
    jb   .next
    cmp  al, 'Z'
    ja   .next
    add  al, 32
    mov  [rdi], al
.next:
    inc  rdi
    jmp  .loop
.done:
    ret

; strcmp wrapper: RDI=cstr, RSI=cstr -> EAX 1/0.  Inputs are bounded outputs or
; static literals, never raw caller bytes.
web_streq:
    call strcmp
    test rax, rax
    setz al
    movzx eax, al
    ret

web_clear_tag_state:
    mov  byte [rbx + WEB_L_SKIPVAL], 0
    mov  byte [rbx + WEB_L_TYPE], 0
    mov  byte [rbx + WEB_L_PROPERTY], 0
    mov  byte [rbx + WEB_L_CONTENT], 0
    mov  byte [rbx + WEB_L_ITEMPROP], 0
    mov  byte [rbx + WEB_L_ITEMTYPE], 0
    mov  byte [rbx + WEB_L_NAME], 0
    mov  byte [rbx + WEB_L_METHOD], 0
    mov  byte [rbx + WEB_L_ACTION], 0
    mov  byte [rbx + WEB_L_SRC], 0
    mov  byte [rbx + WEB_L_ALT], 0
    mov  byte [rbx + WEB_L_WIDTH], 0
    mov  byte [rbx + WEB_L_HEIGHT], 0
    mov  byte [rbx + WEB_L_REQUIRED], 0
    mov  byte [rbx + WEB_L_ITEMSCOPE], 0
    ret

web_skip_ws:
.loop:
    cmp  r12, r13
    jae  .done
    movzx eax, byte [r12]
    cmp  al, ' '
    je   .one
    cmp  al, 9
    je   .one
    cmp  al, 10
    je   .one
    cmp  al, 13
    jne  .done
.one:
    inc  r12
    jmp  .loop
.done:
    ret

; Skip through the next '>' with explicit end.  Used only after a tag name or
; for declarations; attribute-bearing open tags take web_parse_attributes.
web_skip_tag_tail:
.loop:
    cmp  r12, r13
    jae  .trunc
    movzx eax, byte [r12]
    inc  r12
    cmp  al, '>'
    jne  .loop
    xor  eax, eax
    ret
.trunc:
    mov  eax, WEB_STRUCT_TRUNCATED
    ret

; Choose the capped destination for an attribute value by its already-lowercase
; name. Unknown attributes still pass through the same reader into SKIPVAL.
; web_streq/strcmp clobbers RCX, so every matched branch must return an explicit
; capacity; carrying the initial default through a comparison would become zero
; on an equal match and falsely refuse the field as bounds.
web_attribute_destination:
    lea  rdx, [rbx + WEB_L_SKIPVAL]
    mov  ecx, WEB_VALUE_CAP
    lea  rdi, [rbx + WEB_L_ANAME]
    lea  rsi, [rel str_web_attr_type]
    call web_streq
    test eax, eax
    jnz  .type
    lea  rdi, [rbx + WEB_L_ANAME]
    lea  rsi, [rel str_web_attr_property]
    call web_streq
    test eax, eax
    jnz  .property
    lea  rdi, [rbx + WEB_L_ANAME]
    lea  rsi, [rel str_web_attr_content]
    call web_streq
    test eax, eax
    jnz  .content
    lea  rdi, [rbx + WEB_L_ANAME]
    lea  rsi, [rel str_web_attr_itemprop]
    call web_streq
    test eax, eax
    jnz  .itemprop
    lea  rdi, [rbx + WEB_L_ANAME]
    lea  rsi, [rel str_web_attr_itemtype]
    call web_streq
    test eax, eax
    jnz  .itemtype
    lea  rdi, [rbx + WEB_L_ANAME]
    lea  rsi, [rel str_web_attr_name]
    call web_streq
    test eax, eax
    jnz  .name
    lea  rdi, [rbx + WEB_L_ANAME]
    lea  rsi, [rel str_web_attr_method]
    call web_streq
    test eax, eax
    jnz  .method
    lea  rdi, [rbx + WEB_L_ANAME]
    lea  rsi, [rel str_web_attr_action]
    call web_streq
    test eax, eax
    jnz  .action
    lea  rdi, [rbx + WEB_L_ANAME]
    lea  rsi, [rel str_web_attr_src]
    call web_streq
    test eax, eax
    jnz  .src
    lea  rdi, [rbx + WEB_L_ANAME]
    lea  rsi, [rel str_web_attr_alt]
    call web_streq
    test eax, eax
    jnz  .alt
    lea  rdi, [rbx + WEB_L_ANAME]
    lea  rsi, [rel str_web_attr_width]
    call web_streq
    test eax, eax
    jnz  .width
    lea  rdi, [rbx + WEB_L_ANAME]
    lea  rsi, [rel str_web_attr_height]
    call web_streq
    test eax, eax
    jnz  .height
    lea  rdx, [rbx + WEB_L_SKIPVAL]
    mov  ecx, WEB_VALUE_CAP
    ret
.type:     lea rdx, [rbx + WEB_L_TYPE]
    mov ecx, WEB_VALUE_CAP
    ret
.property: lea rdx, [rbx + WEB_L_PROPERTY]
    mov ecx, WEB_NAME_CAP
    ret
.content:  lea rdx, [rbx + WEB_L_CONTENT]
    mov ecx, WEB_VALUE_CAP
    ret
.itemprop: lea rdx, [rbx + WEB_L_ITEMPROP]
    mov ecx, WEB_NAME_CAP
    ret
.itemtype: lea rdx, [rbx + WEB_L_ITEMTYPE]
    mov ecx, WEB_VALUE_CAP
    ret
.name:     lea rdx, [rbx + WEB_L_NAME]
    mov ecx, WEB_NAME_CAP
    ret
.method:   lea rdx, [rbx + WEB_L_METHOD]
    mov ecx, WEB_VALUE_CAP
    ret
.action:   lea rdx, [rbx + WEB_L_ACTION]
    mov ecx, WEB_VALUE_CAP
    ret
.src:      lea rdx, [rbx + WEB_L_SRC]
    mov ecx, WEB_VALUE_CAP
    ret
.alt:      lea rdx, [rbx + WEB_L_ALT]
    mov ecx, WEB_VALUE_CAP
    ret
.width:    lea rdx, [rbx + WEB_L_WIDTH]
    mov ecx, 64
    ret
.height:   lea rdx, [rbx + WEB_L_HEIGHT]
    mov ecx, 64
    ret

; Parse attributes until '>', using explicit input end for every name/value.
web_parse_attributes:
.next:
    call web_skip_ws
    cmp  r12, r13
    jae  .truncated
    movzx eax, byte [r12]
    cmp  al, '>'
    je   .done
    cmp  al, '/'
    jne  .read_name
    inc  r12
    jmp  .next
.read_name:
    mov  rdi, r12
    mov  rsi, r13
    lea  rdx, [rbx + WEB_L_ANAME]
    mov  ecx, WEB_NAME_CAP
    xor  r8d, r8d
    call web_field_read_bounded
    test eax, eax
    jnz  .out
    test rcx, rcx
    jz   .malformed
    add  r12, rdx
    lea  rdi, [rbx + WEB_L_ANAME]
    call web_ascii_lower
    ; Boolean attributes are latched whether or not an explicit value follows.
    lea  rdi, [rbx + WEB_L_ANAME]
    lea  rsi, [rel str_web_attr_required]
    call web_streq
    test eax, eax
    jz   .check_itemscope
    mov  byte [rbx + WEB_L_REQUIRED], 1
.check_itemscope:
    lea  rdi, [rbx + WEB_L_ANAME]
    lea  rsi, [rel str_web_attr_itemscope]
    call web_streq
    test eax, eax
    jz   .maybe_value
    mov  byte [rbx + WEB_L_ITEMSCOPE], 1
.maybe_value:
    call web_skip_ws
    cmp  r12, r13
    jae  .truncated
    cmp  byte [r12], '='
    jne  .next
    inc  r12
    call web_skip_ws
    cmp  r12, r13
    jae  .truncated
    call web_attribute_destination       ; RDX=dest, RCX=cap
    mov  rdi, r12
    mov  rsi, r13
    xor  r8d, r8d
    call web_field_read_bounded
    test eax, eax
    jnz  .out
    add  r12, rdx
    jmp  .next
.done:
    inc  r12
    xor  eax, eax
.out:
    ret
.truncated:
    mov  eax, WEB_STRUCT_TRUNCATED
    ret
.malformed:
    mov  eax, WEB_STRUCT_MALFORMED
    ret

; Append one canonical record. Prefix/key are safe cstrs; value is a bounded
; field.  r14 always points at the current arena NUL and r15 is exclusive end.
web_emit_record:
    push r12
    push r13
    mov  r8, rdi                         ; prefix
    mov  r9, rsi                         ; key
    mov  r10, rdx                        ; value
    cmp  dword [rbx + WEB_L_COUNT], WEB_FIELD_COUNT_CAP
    jae  .too_many
    cmp  dword [rbx + WEB_L_COUNT], 0
    je   .prefix
    mov  al, ' '
    call web_emit_raw_byte
    test eax, eax
    jnz  .out
.prefix:
    mov  r12, r8
    call web_emit_safe_cstr
    test eax, eax
    jnz  .out
    mov  r12, r9
    call web_emit_safe_cstr
    test eax, eax
    jnz  .out
    mov  al, '='
    call web_emit_raw_byte
    test eax, eax
    jnz  .out
    mov  r12, r10
    xor  r13d, r13d
.value_loop:
    movzx eax, byte [r12]
    test al, al
    jz   .value_done
    inc  r13d
    cmp  r13d, 256
    ja   .bounds
    cmp  al, 'A'
    jb   .check_lower
    cmp  al, 'Z'
    jbe  .raw_value
.check_lower:
    cmp  al, 'a'
    jb   .check_digit
    cmp  al, 'z'
    jbe  .raw_value
.check_digit:
    cmp  al, '0'
    jb   .check_safe_punct
    cmp  al, '9'
    jbe  .raw_value
.check_safe_punct:
    cmp  al, '.'
    je   .raw_value
    cmp  al, '_'
    je   .raw_value
    cmp  al, '-'
    je   .raw_value
    push rax
    mov  al, '%'
    call web_emit_raw_byte
    test eax, eax
    jnz  .escape_fail
    pop  rax
    push rax
    shr  al, 4
    and  eax, 0x0F
    lea  r11, [rel str_web_hex]
    mov  al, [r11 + rax]
    call web_emit_raw_byte
    test eax, eax
    jnz  .escape_fail
    pop  rax
    and  eax, 0x0F
    lea  r11, [rel str_web_hex]
    mov  al, [r11 + rax]
    call web_emit_raw_byte
    test eax, eax
    jnz  .out
    jmp  .value_next
.escape_fail:
    pop  r11
    jmp  .out
.raw_value:
    call web_emit_raw_byte
    test eax, eax
    jnz  .out
.value_next:
    inc  r12
    jmp  .value_loop
.value_done:
    inc  dword [rbx + WEB_L_COUNT]
    xor  eax, eax
    jmp  .out
.too_many:
    mov  eax, WEB_STRUCT_TOO_MANY_FIELDS
    jmp  .out
.bounds:
    mov  eax, WEB_STRUCT_BOUNDS
.out:
    pop  r13
    pop  r12
    ret

; AL=byte.  Reserve byte+NUL before writing.
web_emit_raw_byte:
    lea  r11, [r14 + 1]
    cmp  r11, r15
    jae  .bounds
    mov  [r14], al
    inc  r14
    mov  byte [r14], 0
    xor  eax, eax
    ret
.bounds:
    mov  eax, WEB_STRUCT_BOUNDS
    ret

; R12=safe NUL-terminated cstr.
web_emit_safe_cstr:
.loop:
    movzx eax, byte [r12]
    test al, al
    jz   .done
    call web_emit_raw_byte
    test eax, eax
    jnz  .out
    inc  r12
    jmp  .loop
.done:
    xor  eax, eax
.out:
    ret

; Append a bounded field to WEB_L_ROW, inserting raw '|'.
web_row_append:
    push r12
    mov  r12, rdi
    mov  eax, [rbx + WEB_L_ROW_LEN]
    test eax, eax
    jz   .copy
    cmp  eax, 256
    jae  .bounds
    mov  byte [rbx + WEB_L_ROW + rax], '|'
    inc  eax
    mov  [rbx + WEB_L_ROW_LEN], eax
    mov  byte [rbx + WEB_L_ROW + rax], 0
.copy:
    movzx ecx, byte [r12]
    test cl, cl
    jz   .ok
    mov  eax, [rbx + WEB_L_ROW_LEN]
    cmp  eax, 256
    jae  .bounds
    mov  [rbx + WEB_L_ROW + rax], cl
    inc  eax
    mov  [rbx + WEB_L_ROW_LEN], eax
    mov  byte [rbx + WEB_L_ROW + rax], 0
    inc  r12
    jmp  .copy
.ok:
    xor  eax, eax
    pop  r12
    ret
.bounds:
    mov  eax, WEB_STRUCT_BOUNDS
    pop  r12
    ret

web_combo_reset:
    mov  dword [rbx + WEB_L_ROW_LEN], 0
    mov  byte [rbx + WEB_L_COMBO], 0
    ret

; RDI=safe bounded cstr, append to combo. AL separator decision is owned by caller.
web_combo_add:
    push r12
    mov  r12, rdi
.loop:
    movzx ecx, byte [r12]
    test cl, cl
    jz   .ok
    mov  eax, [rbx + WEB_L_ROW_LEN]
    cmp  eax, 256
    jae  .bounds
    mov  [rbx + WEB_L_COMBO + rax], cl
    inc  eax
    mov  [rbx + WEB_L_ROW_LEN], eax
    mov  byte [rbx + WEB_L_COMBO + rax], 0
    inc  r12
    jmp  .loop
.ok:
    xor  eax, eax
    pop  r12
    ret
.bounds:
    mov  eax, WEB_STRUCT_BOUNDS
    pop  r12
    ret

web_combo_bar:
    mov  eax, [rbx + WEB_L_ROW_LEN]
    cmp  eax, 256
    jae  .bounds
    mov  byte [rbx + WEB_L_COMBO + rax], '|'
    inc  eax
    mov  [rbx + WEB_L_ROW_LEN], eax
    mov  byte [rbx + WEB_L_COMBO + rax], 0
    xor  eax, eax
    ret
.bounds:
    mov  eax, WEB_STRUCT_BOUNDS
    ret

; Build decimal in COMBO; only values <=16 reach this helper.
web_small_dec:
    lea  rsi, [rbx + WEB_L_COMBO]
    call fmt_dec
    ret

; Dispatch one completely parsed opening tag.  Tag/attribute names have already
; been lowercased; values retain source case.
web_handle_open_tag:
    lea  rdi, [rbx + WEB_L_TAG]
    lea  rsi, [rel str_web_tag_script]
    call web_streq
    test eax, eax
    jnz  web_open_script
    lea  rdi, [rbx + WEB_L_TAG]
    lea  rsi, [rel str_web_tag_style]
    call web_streq
    test eax, eax
    jnz  web_open_style
    lea  rdi, [rbx + WEB_L_TAG]
    lea  rsi, [rel str_web_tag_meta]
    call web_streq
    test eax, eax
    jnz  web_open_meta
    lea  rdi, [rbx + WEB_L_TAG]
    lea  rsi, [rel str_web_tag_article]
    call web_streq
    test eax, eax
    jnz  web_open_article
    lea  rdi, [rbx + WEB_L_TAG]
    lea  rsi, [rel str_web_tag_table]
    call web_streq
    test eax, eax
    jnz  web_open_table
    lea  rdi, [rbx + WEB_L_TAG]
    lea  rsi, [rel str_web_tag_tr]
    call web_streq
    test eax, eax
    jnz  web_open_tr
    lea  rdi, [rbx + WEB_L_TAG]
    lea  rsi, [rel str_web_tag_th]
    call web_streq
    test eax, eax
    jnz  web_open_th
    lea  rdi, [rbx + WEB_L_TAG]
    lea  rsi, [rel str_web_tag_td]
    call web_streq
    test eax, eax
    jnz  web_open_td
    lea  rdi, [rbx + WEB_L_TAG]
    lea  rsi, [rel str_web_tag_form]
    call web_streq
    test eax, eax
    jnz  web_open_form
    lea  rdi, [rbx + WEB_L_TAG]
    lea  rsi, [rel str_web_tag_input]
    call web_streq
    test eax, eax
    jnz  web_open_control
    lea  rdi, [rbx + WEB_L_TAG]
    lea  rsi, [rel str_web_tag_button]
    call web_streq
    test eax, eax
    jnz  web_open_control
    lea  rdi, [rbx + WEB_L_TAG]
    lea  rsi, [rel str_web_tag_img]
    call web_streq
    test eax, eax
    jnz  web_open_image
    xor  eax, eax
    ret

web_open_meta:
    ; property/itemprop are record keys, not values.  Canonicalize them after
    ; bounded capture so dynamically supplied keys obey the lowercase stream
    ; contract while content/value case remains untouched.
    lea  rdi, [rbx + WEB_L_PROPERTY]
    call web_ascii_lower
    lea  rdi, [rbx + WEB_L_ITEMPROP]
    call web_ascii_lower
    ; OpenGraph: property must be exact lowercase "og:<key>".
    lea  r8, [rbx + WEB_L_PROPERTY]
    cmp  byte [r8 + 0], 'o'
    jne  .micro
    cmp  byte [r8 + 1], 'g'
    jne  .micro
    cmp  byte [r8 + 2], ':'
    jne  .micro
    cmp  byte [r8 + 3], 0
    je   .micro
    lea  rdi, [rel str_web_prefix_og]
    lea  rsi, [r8 + 3]
    lea  rdx, [rbx + WEB_L_CONTENT]
    call web_emit_record
    ret
.micro:
    cmp  byte [rbx + WEB_L_ITEMPROP], 0
    je   .ok
    lea  rdi, [rel str_web_prefix_micro]
    lea  rsi, [rbx + WEB_L_ITEMPROP]
    lea  rdx, [rbx + WEB_L_CONTENT]
    call web_emit_record
    ret
.ok:
    xor  eax, eax
    ret

web_open_article:
    cmp  byte [rbx + WEB_L_ITEMSCOPE], 1
    jne  .ok
    cmp  byte [rbx + WEB_L_ITEMTYPE], 0
    je   .ok
    lea  rdi, [rel str_web_prefix_micro]
    lea  rsi, [rel str_web_key_type]
    lea  rdx, [rbx + WEB_L_ITEMTYPE]
    call web_emit_record
    ret
.ok:
    xor  eax, eax
    ret

web_open_table:
    cmp  byte [rbx + WEB_L_TABLE_IN], 0
    jne  .malformed
    mov  byte [rbx + WEB_L_TABLE_IN], 1
    mov  dword [rbx + WEB_L_TABLE_ROWS], 0
    mov  dword [rbx + WEB_L_TABLE_COLS], 0
    mov  byte [rbx + WEB_L_ROW_KIND], 0
    mov  byte [rbx + WEB_L_ROW_OPEN], 0
    xor  eax, eax
    ret
.malformed:
    mov  eax, WEB_STRUCT_MALFORMED
    ret

web_open_tr:
    cmp  byte [rbx + WEB_L_TABLE_IN], 1
    jne  .ok
    cmp  byte [rbx + WEB_L_ROW_OPEN], 0
    jne  .malformed
    mov  byte [rbx + WEB_L_ROW_OPEN], 1
    mov  byte [rbx + WEB_L_ROW_KIND], 0
    mov  byte [rbx + WEB_L_ROW_CELLS], 0
    mov  dword [rbx + WEB_L_ROW_LEN], 0
    mov  byte [rbx + WEB_L_ROW], 0
.ok:
    xor  eax, eax
    ret
.malformed:
    mov  eax, WEB_STRUCT_MALFORMED
    ret

web_open_th:
    mov  al, 1
    jmp  web_open_cell
web_open_td:
    mov  al, 2
web_open_cell:
    cmp  byte [rbx + WEB_L_TABLE_IN], 1
    jne  .ok
    cmp  byte [rbx + WEB_L_ROW_OPEN], 1
    jne  .malformed
    cmp  byte [rbx + WEB_L_ROW_KIND], 0
    je   .set_kind
    cmp  byte [rbx + WEB_L_ROW_KIND], al
    jne  .malformed
    jmp  .kind_ok
.set_kind:
    mov  [rbx + WEB_L_ROW_KIND], al
.kind_ok:
    cmp  byte [rbx + WEB_L_ROW_CELLS], WEB_TABLE_COLS_CAP
    jae  .bounds
    mov  rdi, r12
    mov  rsi, r13
    lea  rdx, [rbx + WEB_L_SKIPVAL]
    mov  ecx, WEB_VALUE_CAP
    mov  r8d, WEB_FIELD_MODE_TEXT
    call web_field_read_bounded           ; text cell ends at '<'
    test eax, eax
    jnz  .out
    add  r12, rdx
    lea  rdi, [rbx + WEB_L_SKIPVAL]
    call web_row_append
    test eax, eax
    jnz  .out
    inc  byte [rbx + WEB_L_ROW_CELLS]
.ok:
    xor  eax, eax
.out:
    ret
.bounds:
    mov  eax, WEB_STRUCT_BOUNDS
    ret
.malformed:
    mov  eax, WEB_STRUCT_MALFORMED
    ret

web_open_form:
    mov  dword [rbx + WEB_L_FORM_INDEX], 0
    cmp  byte [rbx + WEB_L_METHOD], 0
    je   .action
    lea  rdi, [rel str_web_prefix_form]
    lea  rsi, [rel str_web_key_method]
    lea  rdx, [rbx + WEB_L_METHOD]
    call web_emit_record
    test eax, eax
    jnz  .out
.action:
    cmp  byte [rbx + WEB_L_ACTION], 0
    je   .ok
    lea  rdi, [rel str_web_prefix_form]
    lea  rsi, [rel str_web_key_action]
    lea  rdx, [rbx + WEB_L_ACTION]
    call web_emit_record
    ret
.ok:
    xor  eax, eax
.out:
    ret

web_open_control:
    cmp  byte [rbx + WEB_L_NAME], 0
    je   .ok
    cmp  dword [rbx + WEB_L_FORM_INDEX], WEB_FORM_CTRLS_CAP
    jae  .bounds
    call web_combo_reset
    lea  rdi, [rbx + WEB_L_NAME]
    call web_combo_add
    test eax, eax
    jnz  .out
    call web_combo_bar
    test eax, eax
    jnz  .out
    lea  rdi, [rbx + WEB_L_TYPE]
    cmp  byte [rdi], 0
    jne  .have_type
    lea  rdi, [rel str_web_default_text]
.have_type:
    call web_combo_add
    test eax, eax
    jnz  .out
    call web_combo_bar
    test eax, eax
    jnz  .out
    lea  rdi, [rel str_web_optional]
    cmp  byte [rbx + WEB_L_REQUIRED], 1
    jne  .required_ready
    lea  rdi, [rel str_web_required]
.required_ready:
    call web_combo_add
    test eax, eax
    jnz  .out
    lea  rdi, [rbx + WEB_L_TAG]
    mov  byte [rdi], 'f'
    mov  eax, [rbx + WEB_L_FORM_INDEX]
    mov  edi, eax
    lea  rsi, [rbx + WEB_L_TAG + 1]
    call fmt_dec
    lea  rdi, [rel str_web_prefix_form]
    lea  rsi, [rbx + WEB_L_TAG]
    lea  rdx, [rbx + WEB_L_COMBO]
    call web_emit_record
    test eax, eax
    jnz  .out
    inc  dword [rbx + WEB_L_FORM_INDEX]
.ok:
    xor  eax, eax
.out:
    ret
.bounds:
    mov  eax, WEB_STRUCT_BOUNDS
    ret

web_open_image:
    cmp  dword [rbx + WEB_L_IMAGE_INDEX], WEB_IMAGES_CAP
    jae  .bounds
    call web_combo_reset
    lea  rdi, [rbx + WEB_L_SRC]
    call web_combo_add
    test eax, eax
    jnz  .out
    call web_combo_bar
    test eax, eax
    jnz  .out
    lea  rdi, [rbx + WEB_L_ALT]
    call web_combo_add
    test eax, eax
    jnz  .out
    call web_combo_bar
    test eax, eax
    jnz  .out
    lea  rdi, [rbx + WEB_L_WIDTH]
    cmp  byte [rdi], 0
    jne  .width_ready
    lea  rdi, [rel str_web_zero]
.width_ready:
    call web_combo_add
    test eax, eax
    jnz  .out
    lea  rdi, [rel str_web_x]
    call web_combo_add
    test eax, eax
    jnz  .out
    lea  rdi, [rbx + WEB_L_HEIGHT]
    cmp  byte [rdi], 0
    jne  .height_ready
    lea  rdi, [rel str_web_zero]
.height_ready:
    call web_combo_add
    test eax, eax
    jnz  .out
    call web_combo_bar
    test eax, eax
    jnz  .out
    lea  r8, [rel str_web_content_class]
    cmp  byte [rbx + WEB_L_SRC], 0
    je   .junk
    lea  rdi, [rbx + WEB_L_WIDTH]
    lea  rsi, [rel str_web_one]
    call web_streq
    test eax, eax
    jz   .class_ready
    lea  rdi, [rbx + WEB_L_HEIGHT]
    lea  rsi, [rel str_web_one]
    call web_streq
    test eax, eax
    jz   .class_ready
.junk:
    lea  r8, [rel str_web_junk_class]
.class_ready:
    mov  rdi, r8
    call web_combo_add
    test eax, eax
    jnz  .out
    lea  rdi, [rbx + WEB_L_TAG]
    mov  byte [rdi], 'i'
    mov  edi, [rbx + WEB_L_IMAGE_INDEX]
    lea  rsi, [rbx + WEB_L_TAG + 1]
    call fmt_dec
    lea  rdi, [rel str_web_prefix_image]
    lea  rsi, [rbx + WEB_L_TAG]
    lea  rdx, [rbx + WEB_L_COMBO]
    call web_emit_record
    test eax, eax
    jnz  .out
    inc  dword [rbx + WEB_L_IMAGE_INDEX]
    xor  eax, eax
.out:
    ret
.bounds:
    mov  eax, WEB_STRUCT_BOUNDS
    ret

; Find literal closing sequence. RDI=needle, EDX=len; scans r12..r13.
; Success RAX=body end and RDX=cursor after close; failure RAX=0.
web_find_close:
    push rbx
    push r12
    push r13
    mov  r8, rdi
    mov  r9d, edx
    mov  r10, r12
.candidate:
    mov  rax, r13
    sub  rax, r10
    cmp  rax, r9
    jb   .miss
    xor  r11d, r11d
.compare:
    cmp  r11d, r9d
    jae  .hit
    movzx eax, byte [r10 + r11]
    cmp  al, [r8 + r11]
    jne  .next
    inc  r11d
    jmp  .compare
.next:
    inc  r10
    jmp  .candidate
.hit:
    mov  rax, r10
    lea  rdx, [r10 + r9]
    jmp  .out
.miss:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

web_open_script:
    lea  rdi, [rel str_web_close_script]
    mov  edx, 9
    call web_find_close
    test rax, rax
    jz   .truncated
    push rdx
    lea  rdi, [rbx + WEB_L_TYPE]
    lea  rsi, [rel str_web_jsonld_type]
    call web_streq
    test eax, eax
    jz   .opaque
    mov  rdi, r12
    pop  rdx
    push rdx
    sub  rdx, 9
    mov  rsi, rdx
    call web_json_parse
    test eax, eax
    jnz  .json_out
.opaque:
    pop  r12
    xor  eax, eax
    ret
.json_out:
    pop  r12
    ret
.truncated:
    mov  eax, WEB_STRUCT_TRUNCATED
    ret

web_open_style:
    lea  rdi, [rel str_web_close_style]
    mov  edx, 8
    call web_find_close
    test rax, rax
    jz   .truncated
    mov  r12, rdx
    xor  eax, eax
    ret
.truncated:
    mov  eax, WEB_STRUCT_TRUNCATED
    ret

; JSON-LD bounded object/scalar subset.  Arrays are outside this task's subset
; and therefore malformed.  Unknown scalar/object keys are consumed through the
; same bounded reader/recursive object skipper.  R12/R13 are restored for the
; surrounding HTML walk; r14/r15 and the caller arena remain the shared output.
web_json_parse:
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    call web_json_ws
    cmp  r12, r13
    jae  .truncated
    cmp  byte [r12], '{'
    jne  .malformed
    inc  r12
.pair:
    call web_json_ws
    cmp  r12, r13
    jae  .truncated
    cmp  byte [r12], '}'
    je   .done_object
    call web_json_read_key
    test eax, eax
    jnz  .out
    call web_json_colon
    test eax, eax
    jnz  .out
    ; "offers" owns one nested object; all other objects are bounded-skipped.
    lea  rdi, [rbx + WEB_L_TAG]
    lea  rsi, [rel str_web_json_offers]
    call web_streq
    test eax, eax
    jz   .ordinary_value
    cmp  r12, r13
    jae  .truncated
    cmp  byte [r12], '{'
    jne  .malformed
    mov  edi, 2
    call web_json_offers_object
    test eax, eax
    jnz  .out
    jmp  .separator
.ordinary_value:
    cmp  r12, r13
    jae  .truncated
    cmp  byte [r12], '{'
    jne  .scalar
    mov  edi, 2
    call web_json_skip_object
    test eax, eax
    jnz  .out
    jmp  .separator
.scalar:
    cmp  byte [r12], '['
    je   .malformed
    call web_json_read_scalar
    test eax, eax
    jnz  .out
    lea  rdi, [rbx + WEB_L_TAG]
    lea  rsi, [rel str_web_json_at_type]
    call web_streq
    test eax, eax
    jz   .name
    lea  rdi, [rel str_web_prefix_jsonld]
    lea  rsi, [rel str_web_key_type]
    lea  rdx, [rbx + WEB_L_SKIPVAL]
    call web_emit_record
    test eax, eax
    jnz  .out
    jmp  .separator
.name:
    lea  rdi, [rbx + WEB_L_TAG]
    lea  rsi, [rel str_web_json_name]
    call web_streq
    test eax, eax
    jz   .sku
    lea  rdi, [rel str_web_prefix_jsonld]
    lea  rsi, [rel str_web_json_name]
    lea  rdx, [rbx + WEB_L_SKIPVAL]
    call web_emit_record
    test eax, eax
    jnz  .out
    jmp  .separator
.sku:
    lea  rdi, [rbx + WEB_L_TAG]
    lea  rsi, [rel str_web_json_sku]
    call web_streq
    test eax, eax
    jz   .separator
    lea  rdi, [rel str_web_prefix_jsonld]
    lea  rsi, [rel str_web_json_sku]
    lea  rdx, [rbx + WEB_L_SKIPVAL]
    call web_emit_record
    test eax, eax
    jnz  .out
.separator:
    call web_json_ws
    cmp  r12, r13
    jae  .truncated
    cmp  byte [r12], ','
    je   .comma
    cmp  byte [r12], '}'
    je   .done_object
    jmp  .malformed
.comma:
    inc  r12
    jmp  .pair
.done_object:
    inc  r12
    call web_json_ws
    cmp  r12, r13
    jne  .malformed
    xor  eax, eax
    jmp  .out
.truncated:
    mov  eax, WEB_STRUCT_TRUNCATED
    jmp  .out
.malformed:
    mov  eax, WEB_STRUCT_MALFORMED
.out:
    pop  r13
    pop  r12
    ret

web_json_ws:
.loop:
    cmp  r12, r13
    jae  .done
    movzx eax, byte [r12]
    cmp  al, ' '
    je   .one
    cmp  al, 9
    je   .one
    cmp  al, 10
    je   .one
    cmp  al, 13
    jne  .done
.one:
    inc  r12
    jmp  .loop
.done:
    ret

web_json_read_key:
    cmp  r12, r13
    jae  .truncated
    movzx eax, byte [r12]
    cmp  al, '"'
    jne  .malformed
    mov  rdi, r12
    mov  rsi, r13
    lea  rdx, [rbx + WEB_L_TAG]
    mov  ecx, WEB_NAME_CAP
    xor  r8d, r8d
    call web_field_read_bounded
    test eax, eax
    jnz  .out
    test rcx, rcx
    jz   .malformed
    add  r12, rdx
    lea  rdi, [rbx + WEB_L_TAG]
    call web_ascii_lower
    xor  eax, eax
.out:
    ret
.truncated:
    mov  eax, WEB_STRUCT_TRUNCATED
    ret
.malformed:
    mov  eax, WEB_STRUCT_MALFORMED
    ret

web_json_colon:
    call web_json_ws
    cmp  r12, r13
    jae  .truncated
    cmp  byte [r12], ':'
    jne  .malformed
    inc  r12
    call web_json_ws
    cmp  r12, r13
    jae  .truncated
    xor  eax, eax
    ret
.truncated:
    mov  eax, WEB_STRUCT_TRUNCATED
    ret
.malformed:
    mov  eax, WEB_STRUCT_MALFORMED
    ret

web_json_read_scalar:
    cmp  r12, r13
    jae  .truncated
    cmp  byte [r12], '{'
    je   .malformed
    cmp  byte [r12], '['
    je   .malformed
    mov  rdi, r12
    mov  rsi, r13
    lea  rdx, [rbx + WEB_L_SKIPVAL]
    mov  ecx, WEB_VALUE_CAP
    xor  r8d, r8d
    call web_field_read_bounded
    test eax, eax
    jnz  .out
    test rcx, rcx
    jz   .malformed
    add  r12, rdx
    xor  eax, eax
.out:
    ret
.truncated:
    mov  eax, WEB_STRUCT_TRUNCATED
    ret
.malformed:
    mov  eax, WEB_STRUCT_MALFORMED
    ret

; EDI=depth (root is 1).  Parses offers and emits only price.
web_json_offers_object:
    cmp  edi, WEB_JSON_DEPTH_CAP
    ja   .bounds
    cmp  byte [r12], '{'
    jne  .malformed
    inc  r12
.pair:
    call web_json_ws
    cmp  r12, r13
    jae  .truncated
    cmp  byte [r12], '}'
    je   .done
    call web_json_read_key
    test eax, eax
    jnz  .out
    ; Preserve whether this key is price before scalar overwrites SKIPVAL only.
    lea  rdi, [rbx + WEB_L_TAG]
    lea  rsi, [rel str_web_json_price]
    call web_streq
    push rax
    call web_json_colon
    test eax, eax
    jnz  .colon_fail
    cmp  byte [r12], '{'
    je   .nested
    cmp  byte [r12], '['
    je   .array_fail
    call web_json_read_scalar
    test eax, eax
    jnz  .scalar_fail
    pop  rax
    test eax, eax
    jz   .separator
    lea  rdi, [rel str_web_prefix_jsonld]
    lea  rsi, [rel str_web_json_price]
    lea  rdx, [rbx + WEB_L_SKIPVAL]
    call web_emit_record
    test eax, eax
    jnz  .out
    jmp  .separator
.nested:
    pop  rax
    mov  edi, 3
    call web_json_skip_object
    test eax, eax
    jnz  .out
    jmp  .separator
.array_fail:
    pop  rax
    jmp  .malformed
.colon_fail:
.scalar_fail:
    add  rsp, 8
    jmp  .out
.separator:
    call web_json_ws
    cmp  r12, r13
    jae  .truncated
    cmp  byte [r12], ','
    je   .comma
    cmp  byte [r12], '}'
    je   .done
    jmp  .malformed
.comma:
    inc  r12
    jmp  .pair
.done:
    inc  r12
    xor  eax, eax
.out:
    ret
.bounds:
    mov  eax, WEB_STRUCT_BOUNDS
    ret
.truncated:
    mov  eax, WEB_STRUCT_TRUNCATED
    ret
.malformed:
    mov  eax, WEB_STRUCT_MALFORMED
    ret

; Recursively consume an unknown object. EDI=current depth.
web_json_skip_object:
    cmp  edi, WEB_JSON_DEPTH_CAP
    ja   .bounds
    push rdi
    cmp  byte [r12], '{'
    jne  .malformed_pop
    inc  r12
.pair:
    call web_json_ws
    cmp  r12, r13
    jae  .truncated_pop
    cmp  byte [r12], '}'
    je   .done
    call web_json_read_key
    test eax, eax
    jnz  .out_pop
    call web_json_colon
    test eax, eax
    jnz  .out_pop
    cmp  byte [r12], '['
    je   .malformed_pop
    cmp  byte [r12], '{'
    jne  .scalar
    mov  edi, [rsp]
    inc  edi
    call web_json_skip_object
    test eax, eax
    jnz  .out_pop
    jmp  .separator
.scalar:
    call web_json_read_scalar
    test eax, eax
    jnz  .out_pop
.separator:
    call web_json_ws
    cmp  r12, r13
    jae  .truncated_pop
    cmp  byte [r12], ','
    je   .comma
    cmp  byte [r12], '}'
    je   .done
    jmp  .malformed_pop
.comma:
    inc  r12
    jmp  .pair
.done:
    inc  r12
    xor  eax, eax
.out_pop:
    add  rsp, 8
    ret
.bounds:
    mov  eax, WEB_STRUCT_BOUNDS
    ret
.truncated_pop:
    mov  eax, WEB_STRUCT_TRUNCATED
    jmp  .out_pop
.malformed_pop:
    mov  eax, WEB_STRUCT_MALFORMED
    jmp  .out_pop

web_handle_close_tag:
    lea  rdi, [rbx + WEB_L_TAG]
    lea  rsi, [rel str_web_tag_tr]
    call web_streq
    test eax, eax
    jnz  web_close_tr
    lea  rdi, [rbx + WEB_L_TAG]
    lea  rsi, [rel str_web_tag_table]
    call web_streq
    test eax, eax
    jnz  web_close_table
    xor  eax, eax
    ret

web_close_tr:
    cmp  byte [rbx + WEB_L_TABLE_IN], 1
    jne  .ok
    cmp  byte [rbx + WEB_L_ROW_OPEN], 1
    jne  .malformed
    movzx eax, byte [rbx + WEB_L_ROW_KIND]
    cmp  eax, 1
    je   .header
    cmp  eax, 2
    je   .data
    jmp  .malformed
.header:
    movzx eax, byte [rbx + WEB_L_ROW_CELLS]
    test eax, eax
    jz   .malformed
    mov  [rbx + WEB_L_TABLE_COLS], eax
    mov  edi, eax
    call web_small_dec
    lea  rdi, [rel str_web_prefix_table]
    lea  rsi, [rel str_web_key_columns]
    lea  rdx, [rbx + WEB_L_COMBO]
    call web_emit_record
    test eax, eax
    jnz  .out
    lea  rdi, [rel str_web_prefix_table]
    lea  rsi, [rel str_web_key_head]
    lea  rdx, [rbx + WEB_L_ROW]
    call web_emit_record
    jmp  .finish
.data:
    mov  eax, [rbx + WEB_L_TABLE_ROWS]
    cmp  eax, WEB_TABLE_ROWS_CAP
    jae  .bounds
    mov  ecx, [rbx + WEB_L_TABLE_COLS]
    test ecx, ecx
    jz   .malformed
    movzx edx, byte [rbx + WEB_L_ROW_CELLS]
    cmp  edx, ecx
    jne  .malformed
    lea  rsi, [rbx + WEB_L_TAG]
    mov  byte [rsi], 'r'
    mov  edi, eax
    inc  rsi
    call fmt_dec
    lea  rdi, [rel str_web_prefix_table]
    lea  rsi, [rbx + WEB_L_TAG]
    lea  rdx, [rbx + WEB_L_ROW]
    call web_emit_record
    test eax, eax
    jnz  .out
    inc  dword [rbx + WEB_L_TABLE_ROWS]
.finish:
    mov  byte [rbx + WEB_L_ROW_KIND], 0
    mov  byte [rbx + WEB_L_ROW_OPEN], 0
.ok:
    xor  eax, eax
.out:
    ret
.bounds:
    mov  eax, WEB_STRUCT_BOUNDS
    ret
.malformed:
    mov  eax, WEB_STRUCT_MALFORMED
    ret

web_close_table:
    cmp  byte [rbx + WEB_L_TABLE_IN], 1
    jne  .ok
    cmp  byte [rbx + WEB_L_ROW_OPEN], 0
    jne  .malformed
    cmp  byte [rbx + WEB_L_ROW_KIND], 0
    jne  .malformed
    mov  edi, [rbx + WEB_L_TABLE_ROWS]
    call web_small_dec
    lea  rdi, [rel str_web_prefix_table]
    lea  rsi, [rel str_web_key_rows]
    lea  rdx, [rbx + WEB_L_COMBO]
    call web_emit_record
    test eax, eax
    jnz  .out
    mov  byte [rbx + WEB_L_TABLE_IN], 0
.ok:
    xor  eax, eax
.out:
    ret
.malformed:
    mov  eax, WEB_STRUCT_MALFORMED
    ret

; Data literals.
str_web_attr_type:      db "type",0
str_web_attr_property:  db "property",0
str_web_attr_content:   db "content",0
str_web_attr_itemprop:  db "itemprop",0
str_web_attr_itemtype:  db "itemtype",0
str_web_attr_itemscope: db "itemscope",0
str_web_attr_name:      db "name",0
str_web_attr_method:    db "method",0
str_web_attr_action:    db "action",0
str_web_attr_required:  db "required",0
str_web_attr_src:       db "src",0
str_web_attr_alt:       db "alt",0
str_web_attr_width:     db "width",0
str_web_attr_height:    db "height",0
str_web_hex:            db "0123456789ABCDEF"
str_web_tag_script: db "script",0
str_web_tag_style:  db "style",0
str_web_tag_meta:   db "meta",0
str_web_tag_article: db "article",0
str_web_tag_table:  db "table",0
str_web_tag_tr:     db "tr",0
str_web_tag_th:     db "th",0
str_web_tag_td:     db "td",0
str_web_tag_form:   db "form",0
str_web_tag_input:  db "input",0
str_web_tag_button: db "button",0
str_web_tag_img:    db "img",0
str_web_close_script: db "</script>"
str_web_close_style:  db "</style>"
str_web_jsonld_type: db "application/ld+json",0
str_web_prefix_og:    db "og:",0
str_web_prefix_micro: db "micro:",0
str_web_prefix_table: db "table:",0
str_web_prefix_form:  db "form:",0
str_web_prefix_image: db "image:",0
str_web_prefix_jsonld: db "jsonld:",0
str_web_key_type:    db "type",0
str_web_key_method:  db "method",0
str_web_key_action:  db "action",0
str_web_key_columns: db "columns",0
str_web_key_rows:    db "rows",0
str_web_key_head:    db "head",0
str_web_default_text: db "text",0
str_web_optional: db "optional",0
str_web_required: db "required",0
str_web_zero: db "0",0
str_web_one: db "1",0
str_web_x: db "x",0
str_web_content_class: db "content",0
str_web_junk_class: db "junk",0
str_web_json_offers: db "offers",0
str_web_json_at_type: db "@type",0
str_web_json_name: db "name",0
str_web_json_sku: db "sku",0
str_web_json_price: db "price",0
