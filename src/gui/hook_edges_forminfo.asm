;; MODULE gui/hook_edges_forminfo
;; LAYER 6
;; EXPORTS hook_forminfo_edge_declare, hook_forminfo_plan, hook_forminfo_post
;; IMPORTS svc/command, svc/command_hook, gui/form_loader
;; CAPS
;; OWNER saga:command
; Exact native FORMINFO page -> bounded hexadecimal chunk. No table access,
; input, load or independent renderer. Every query takes a fresh native page;
; page_hash covers that whole page, not a multi-query snapshot or authenticity.
HFI_NATIVE_MAX equ 1472
HFI_PAGE_MAX equ 1280
HFI_READ_MAX equ 384

hook_forminfo_edge_declare:
    push rbx
    lea  rbx, [rel hook_edge_forminfo]
    lea  rax, [rel str_hfi_name]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hfi_kind]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hfi_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_forminfo_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_forminfo_post]
    mov  [rbx + HE_POST], rax
    lea  rax, [rel form_out_buf]
    mov  [rbx + HE_OBUF], rax
    lea  rax, [rel form_out_ready]
    mov  [rbx + HE_OREADY], rax
    mov  qword [rbx + HE_WITNESS], 0
    mov  rdi, rbx
    call command_hook_edge_register
    pop  rbx
    ret

hook_forminfo_plan:
    push rbx
    push r12
    push rdi
    push rsi
    push rdx
    call hfi_retire
    pop  rdx
    pop  rsi
    pop  rdi
    cmp  edi, HOP_GET
    jne  .na
    mov  r12, rdx
    mov  rbx, rsi
    xor  ecx, ecx
.name:
    movzx eax, byte [rbx + rcx]
    test al, al
    jz   .name_end
    cmp  ecx, 31
    jae  .bad
    cmp  al, 'a'
    jb   .other
    cmp  al, 'z'
    jbe  .copy
.other:
    test ecx, ecx
    jz   .bad
    cmp  al, '_'
    je   .copy
    sub  eax, '0'
    cmp  eax, 9
    ja   .bad
    add  eax, '0'
.copy:
    lea  rdx, [rel hfi_identity]
    mov  [rdx + rcx], al
    inc  ecx
    jmp  .name
.name_end:
    test ecx, ecx
    jz   .bad
    mov  rdi, r12
    lea  rsi, [rel str_hfi_page_arg]
    call hfi_literal
    test eax, eax
    jz   .bad
    call hfi_u32
    test eax, eax
    jz   .bad
    test edx, edx
    jz   .bad
    mov  [rel hfi_page], edx
    lea  rsi, [rel str_hfi_read_arg]
    call hfi_literal
    test eax, eax
    jz   .bad
    call hfi_u32
    test eax, eax
    jz   .bad
    cmp  edx, HFI_PAGE_MAX
    ja   .bad
    mov  [rel hfi_offset], edx
    cmp  byte [rdi], ' '
    jne  .bad
    inc  rdi
    call hfi_u32
    test eax, eax
    jz   .bad
    test edx, edx
    jz   .bad
    cmp  edx, HFI_READ_MAX
    ja   .bad
    cmp  byte [rdi], 0
    jne  .bad
    mov  [rel hfi_length], edx
    call command_hook_arg_reset
    lea  rdi, [rel hfi_identity]
    call command_hook_arg_str
    lea  rdi, [rel str_hfi_space]
    call command_hook_arg_str
    mov  edi, [rel hfi_page]
    call command_hook_arg_dec
    mov  byte [rel hfi_pending], 1
    lea  rax, [rel str_hfi_verb]
    jmp  .out
.na:
    mov  ebx, HOOK_PLAN_NA
    jmp  .reject
.bad:
    mov  ebx, HOOK_PLAN_BADARG
.reject:
    call hfi_retire
    mov  edx, ebx
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

hook_forminfo_post:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rcx
    cmp  qword [rbx + RSP_CODE], CMDE_OK
    jne  .refused
    cmp  byte [rel hfi_pending], 1
    jne  .bad
    cmp  byte [rel form_out_ready], 1
    jne  .bad
    lea  rdi, [rel form_out_buf]
    xor  ecx, ecx
.scan:
    cmp  ecx, HFI_NATIVE_MAX - 1
    jae  .bad                         ; capacity-terminated/truncated is not complete
    cmp  byte [rdi + rcx], 0
    je   .end
    inc  ecx
    jmp  .scan
.end:
    lea  r15, [rdi + rcx]
    cmp  r15, [rel form_out_cur]
    jne  .bad
    lea  rsi, [rel str_hfi_prefix]
    call hfi_literal
    test eax, eax
    jz   .native_error
    lea  rsi, [rel hfi_identity]
    call hfi_literal
    test eax, eax
    jz   .bad
    lea  rsi, [rel str_hfi_page_field]
    call hfi_literal
    test eax, eax
    jz   .bad
    call hfi_u32
    test eax, eax
    jz   .bad
    cmp  edx, [rel hfi_page]
    jne  .bad
    cmp  byte [rdi], '/'
    jne  .bad
    inc  rdi
    call hfi_u32
    test eax, eax
    jz   .bad
    cmp  edx, [rel hfi_page]
    jb   .bad
    mov  [rel hfi_pages], edx
    cmp  byte [rdi], 10
    jne  .bad
    inc  rdi
    mov  r12, rdi                    ; actual native page payload
    sub  r15, r12
    cmp  r15, HFI_PAGE_MAX
    ja   .bad
    ; Every earlier native page is exactly1280 bytes; final may be empty
    ; (native zero-length declarations report1/0 and already refuse above).
    mov  eax, [rel hfi_page]
    cmp  eax, [rel hfi_pages]
    je   .length_ok
    cmp  r15, HFI_PAGE_MAX
    jne  .bad
.length_ok:
    mov  eax, [rel hfi_offset]
    cmp  rax, r15
    ja   .bad
    mov  r14, r15
    sub  r14, rax
    mov  ecx, [rel hfi_length]
    cmp  r14, rcx
    cmova r14, rcx
    ; FNV-1a over ALL current page bytes. This is a change witness, no MAC.
    mov  r13, 0xcbf29ce484222325
    mov  rsi, 0x100000001b3
    xor  ecx, ecx
.hash:
    cmp  rcx, r15
    jae  .emit
    movzx eax, byte [r12 + rcx]
    xor  r13, rax
    imul r13, rsi
    inc  rcx
    jmp  .hash
.emit:
    call command_hook_out_reset
    lea  rdi, [rel str_hfi_chunk]
    call command_hook_out_str
    lea  rdi, [rel hfi_identity]
    call command_hook_out_str
    lea  rdi, [rel str_hfi_page_field]
    call command_hook_out_str
    mov  edi, [rel hfi_page]
    call command_hook_out_dec
    lea  rdi, [rel str_hfi_pages]
    call command_hook_out_str
    mov  edi, [rel hfi_pages]
    call command_hook_out_dec
    lea  rdi, [rel str_hfi_page_bytes]
    call command_hook_out_str
    mov  rdi, r15
    call command_hook_out_dec
    lea  rdi, [rel str_hfi_offset]
    call command_hook_out_str
    mov  edi, [rel hfi_offset]
    call command_hook_out_dec
    lea  rdi, [rel str_hfi_n]
    call command_hook_out_str
    mov  rdi, r14
    call command_hook_out_dec
    lea  rdi, [rel str_hfi_more]
    call command_hook_out_str
    mov  eax, [rel hfi_offset]
    add  rax, r14
    xor  edi, edi
    cmp  rax, r15
    setb dil
    call command_hook_out_dec
    lea  rdi, [rel str_hfi_hash]
    call command_hook_out_str
    lea  rdi, [rel hfi_hex]
    mov  ecx, 16
.hex_hash:
    rol  r13, 4
    mov  eax, r13d
    and  eax, 15
    lea  rsi, [rel str_hfi_digits]
    mov  al, [rsi + rax]
    stosb
    loop .hex_hash
    lea  rdi, [rel hfi_hex]
    call command_hook_out_str
    lea  rdi, [rel str_hfi_hex]
    call command_hook_out_str
    mov  eax, [rel hfi_offset]
    add  r12, rax
    xor  r13d, r13d
.hex_bytes:
    cmp  r13, r14
    jae  .done
    movzx eax, byte [r12 + r13]
    mov  edx, eax
    shr  eax, 4
    and  edx, 15
    lea  rsi, [rel str_hfi_digits]
    mov  al, [rsi + rax]
    mov  [rel hfi_pair], al
    mov  al, [rsi + rdx]
    mov  [rel hfi_pair + 1], al
    lea  rdi, [rel hfi_pair]
    call command_hook_out_str
    inc  r13
    jmp  .hex_bytes
.done:
    mov  qword [rbx + RSP_HINT], 0
    mov  qword [rbx + RSP_VAL], 0
    call hfi_retire
    mov  eax, 1
    jmp  .out
.native_error:
    lea  rdi, [rel form_out_buf]
    lea  rsi, [rel str_hfi_native_missing]
    call hfi_literal
    test eax, eax
    jz   .try_page_error
    cmp  byte [rdi], 0
    jne  .bad
    lea  r12, [rel str_hfi_missing]
    jmp  .error
.try_page_error:
    lea  rdi, [rel form_out_buf]
    lea  rsi, [rel str_hfi_native_page]
    call hfi_literal
    test eax, eax
    jz   .bad
    cmp  byte [rdi], 0
    jne  .bad
    lea  r12, [rel str_hfi_bad_page]
    jmp  .error
.bad:
    lea  r12, [rel str_hfi_bad]
.error:
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_HINT], 0
    mov  qword [rbx + RSP_VAL], 0
    call command_hook_out_reset
    mov  rdi, r12
    call command_hook_out_str
    call hfi_retire
    mov  eax, 1
    jmp  .out
.refused:
    call hfi_retire
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

hfi_retire:
    mov  byte [rel form_out_ready], 0
    mov  qword [rel form_out_cur], 0
    lea  rdi, [rel form_out_buf]
    mov  ecx, HFI_NATIVE_MAX
    xor  eax, eax
    rep stosb
    lea  rdi, [rel hfi_state]
    mov  ecx, hfi_state_end - hfi_state
    rep stosb
    ret

hfi_literal:
.next:
    lodsb
    test al, al
    jz   .yes
    cmp  al, [rdi]
    jne  .no
    inc  rdi
    jmp  .next
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; Canonical u32, no sign/leading zero/wrap; caller owns delimiter.
hfi_u32:
    xor  edx, edx
    cmp  byte [rdi], '0'
    jne  .start
    inc  rdi
    mov  eax, 1
    ret
.start:
    movzx eax, byte [rdi]
    sub  eax, '1'
    cmp  eax, 8
    ja   .no
.digit:
    movzx eax, byte [rdi]
    sub  eax, '0'
    cmp  eax, 9
    ja   .yes
    cmp  edx, 429496729
    ja   .no
    jne  .acc
    cmp  eax, 5
    ja   .no
.acc:
    imul edx, edx, 10
    add  edx, eax
    inc  rdi
    jmp  .digit
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

str_hfi_name: db "form", 0
str_hfi_kind: db "service", 0
str_hfi_verb: db "FORMINFO", 0
str_hfi_schema: db "v=1 inst=identifier1..31 get=page{u32>=1} read{offset:0..1280,length:1..384} native=FORMINFO(name,page) result=FORMINFO_CHUNK{name,page,pages,page_bytes,offset,n,more,page_hash:FNV1a64,hex} observe=whole-current-page-and-range separate_reads=fresh-not-atomic byte_encoding=hex staging=1472-retired authority=native list=na set=na input=na cancel=na form_load=untyped", 0
str_hfi_page_arg: db "page ", 0
str_hfi_read_arg: db " read ", 0
str_hfi_space: db " ", 0
str_hfi_prefix: db " FORMINFO name=", 0
str_hfi_page_field: db " page=", 0
str_hfi_chunk: db " FORMINFO_CHUNK name=", 0
str_hfi_pages: db " pages=", 0
str_hfi_page_bytes: db " page_bytes=", 0
str_hfi_offset: db " offset=", 0
str_hfi_n: db " n=", 0
str_hfi_more: db " more=", 0
str_hfi_hash: db " page_hash=", 0
str_hfi_hex: db " hex=", 0
str_hfi_digits: db "0123456789abcdef", 0
str_hfi_native_missing: db " FORMINFO FORMINFO=ERR missing_form", 0
str_hfi_native_page: db " FORMINFO FORMINFO=ERR bad_page", 0
str_hfi_missing: db " hook err=forminfo_native_missing_form", 0
str_hfi_bad_page: db " hook err=forminfo_native_bad_page", 0
str_hfi_bad: db " hook err=forminfo_reply_incomplete", 0
align 8
hook_edge_forminfo: times (HE_SZ / 8) dq 0
hfi_state:
hfi_identity: times 32 db 0
hfi_page: dd 0
hfi_pages: dd 0
hfi_offset: dd 0
hfi_length: dd 0
hfi_pending: db 0
hfi_hex: times 17 db 0
hfi_pair: times 3 db 0
hfi_state_end:
