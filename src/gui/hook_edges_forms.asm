;; MODULE gui/hook_edges_forms
;; LAYER 6
;; EXPORTS hook_forms_edge_declare, hook_forms_plan, hook_forms_post
;; IMPORTS svc/command, svc/command_hook, gui/form_loader
;; CAPS
;; OWNER saga:command
; Read-only native FORMLIST inventory. No table scan, form load or input path.
; The registered native handler may change as the console binds: only this
; invocation's complete canonical receipt is copied and witnessed.
HFO_NATIVE_MAX equ 1472
HFO_REPLY_MAX equ 1024
HFO_NAME_MAX equ 31

hook_forms_edge_declare:
    push rbx
    lea  rbx, [rel hook_edge_forms]
    lea  rax, [rel str_hfo_name]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hfo_kind]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hfo_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_forms_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_forms_post]
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

hook_forms_plan:
    push rdi
    push rsi
    push rdx
    call hfo_retire
    pop  rdx
    pop  rsi
    pop  rdi
    cmp  edi, HOP_GET
    jne  .na
    cmp  byte [rsi], 0
    jne  .bad
    cmp  byte [rdx], 0
    jne  .bad
    mov  byte [rel hfo_pending], 1
    call command_hook_arg_reset
    lea  rax, [rel str_hfo_verb]
    ret
.na:
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    ret
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
    ret

hook_forms_post:
    push rbx
    push r12
    push r13
    mov  rbx, rcx
    cmp  qword [rbx + RSP_CODE], CMDE_OK
    jne  .refused
    cmp  byte [rel hfo_pending], 1
    jne  .bad
    cmp  byte [rel form_out_ready], 1
    jne  .bad
    lea  rdi, [rel form_out_buf]
    xor  ecx, ecx
.scan:
    cmp  ecx, HFO_REPLY_MAX
    jae  .bad
    cmp  byte [rdi + rcx], 0
    je   .end
    inc  ecx
    jmp  .scan
.end:
    lea  rax, [rdi + rcx]
    cmp  rax, [rel form_out_cur]
    jne  .bad
    lea  rsi, [rel str_hfo_prefix]
    call hfo_literal
    test eax, eax
    jz   .bad
    call hfo_count
    test eax, eax
    jz   .bad
    mov  r12d, edx
    lea  rsi, [rel str_hfo_names]
    call hfo_literal
    test eax, eax
    jz   .bad
    xor  r13d, r13d
    test r12d, r12d
    jz   .finish
.name:
    ; Current native names are lowercase identifiers, 1..31 bytes. A future
    ; larger/other grammar refuses rather than silently weakening this schema.
    movzx eax, byte [rdi]
    sub  eax, 'a'
    cmp  eax, 25
    ja   .bad
    mov  ecx, 1
    inc  rdi
.char:
    movzx eax, byte [rdi]
    test eax, eax
    jz   .name_end
    cmp  eax, ','
    je   .name_end
    cmp  ecx, HFO_NAME_MAX
    jae  .bad
    cmp  eax, '_'
    je   .take
    sub  eax, 'a'
    cmp  eax, 25
    jbe  .take
    movzx eax, byte [rdi]
    sub  eax, '0'
    cmp  eax, 9
    ja   .bad
.take:
    inc  ecx
    inc  rdi
    jmp  .char
.name_end:
    inc  r13d
    cmp  r13d, r12d
    ja   .bad
    je   .finish
    cmp  byte [rdi], ','
    jne  .bad
    inc  rdi
    jmp  .name
.finish:
    cmp  byte [rdi], 0
    jne  .bad
    call command_hook_out_reset
    lea  rdi, [rel form_out_buf]
    call command_hook_out_str
    call hfo_retire
    mov  eax, 1
    jmp  .out
.bad:
    call hfo_retire
    call command_hook_out_reset
    lea  rdi, [rel str_hfo_bad]
    call command_hook_out_str
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_VAL], 0
    mov  qword [rbx + RSP_HINT], 0
    mov  byte [rel command_hook_out_ready], 1
    xor  eax, eax
    jmp  .out
.refused:
    call hfo_retire                     ; native refusal code/hint survive
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

hfo_retire:
    mov  byte [rel hfo_pending], 0
    mov  byte [rel form_out_ready], 0
    mov  qword [rel form_out_cur], 0
    lea  rdi, [rel form_out_buf]
    mov  ecx, HFO_NATIVE_MAX
    xor  eax, eax
    rep stosb
    ret

hfo_literal:
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

; Canonical u32. No leading zero, sign or wrap; delimiter checked by caller.
hfo_count:
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

str_hfo_name: db "forms", 0
str_hfo_kind: db "service", 0
str_hfo_verb: db "FORMLIST", 0
str_hfo_schema: db "inst=none get=FORMLIST{n:u32,names:identifier[0..n]} name=[a-z][a-z0-9_]{0,30} observe=whole_validated_inventory receipt=complete,canonical,max1023,synchronous list=na set=na input=na cancel=na form_info=form:service form_load=untyped native_authority=unchanged", 0
str_hfo_prefix: db " FORMLIST n=", 0
str_hfo_names: db " names=", 0
str_hfo_bad: db " hook err=forms_reply_incomplete", 0
align 8
hook_edge_forms: times (HE_SZ / 8) dq 0
hfo_pending: db 0
