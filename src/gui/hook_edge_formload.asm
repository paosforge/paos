;; MODULE gui/hook_edge_formload
;; LAYER 6
;; EXPORTS hook_formload_edge_declare, hook_formload_plan, hook_formload_post
;; IMPORTS svc/command, svc/command_hook, gui/form_loader
;; CAPS
;; OWNER saga:command
; One additive typed suboperation: open a registered built-in native form.
; Only the current FORMLOAD registry handler runs, through command_dispatch.
; No title/focus override, ephemeral app blob, input or confirmation action.
HFL_NATIVE_MAX equ 1472

hook_formload_edge_declare:
    push rbx
    lea  rbx, [rel hook_edge_formload]
    lea  rax, [rel str_hfl_name]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hfl_kind]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hfl_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_formload_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_formload_post]
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

hook_formload_plan:
    push rbx
    push r12
    push rdi
    push rsi
    push rdx
    call hfl_retire
    pop  rdx
    pop  rsi
    pop  rdi
    cmp  edi, HOP_SET
    jne  .na
    mov  r12, rdx
    xor  ecx, ecx
.name:
    movzx eax, byte [rsi + rcx]
    test eax, eax
    jz   .name_end
    cmp  ecx, 31
    jae  .bad
    cmp  eax, 'a'
    jb   .other
    cmp  eax, 'z'
    jbe  .copy
.other:
    test ecx, ecx
    jz   .bad
    cmp  eax, '_'
    je   .copy
    sub  eax, '0'
    cmp  eax, 9
    ja   .bad
    add  eax, '0'
.copy:
    lea  rdx, [rel hfl_identity]
    mov  [rdx + rcx], al
    inc  ecx
    jmp  .name
.name_end:
    test ecx, ecx
    jz   .bad
    mov  rdi, r12
    lea  rsi, [rel str_hfl_open]
    call hfl_literal
    test eax, eax
    jz   .bad
    cmp  byte [rdi], 0
    jne  .bad
    call command_hook_arg_reset
    lea  rdi, [rel hfl_identity]
    call command_hook_arg_str
    mov  byte [rel hfl_pending], 1
    lea  rax, [rel str_hfl_verb]
    jmp  .out
.na:
    mov  ebx, HOOK_PLAN_NA
    jmp  .reject
.bad:
    mov  ebx, HOOK_PLAN_BADARG
.reject:
    call hfl_retire
    mov  edx, ebx
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

hook_formload_post:
    push rbx
    push r12
    mov  rbx, rcx
    cmp  qword [rbx + RSP_CODE], CMDE_OK
    jne  .refused
    cmp  byte [rel hfl_pending], 1
    jne  .bad
    cmp  byte [rel form_out_ready], 1
    jne  .bad
    lea  rdi, [rel form_out_buf]
    xor  ecx, ecx
.scan:
    cmp  ecx, HFL_NATIVE_MAX
    jae  .bad
    cmp  byte [rdi + rcx], 0
    je   .end
    inc  ecx
    jmp  .scan
.end:
    lea  rax, [rdi + rcx]
    cmp  rax, [rel form_out_cur]
    jne  .bad
    lea  rsi, [rel str_hfl_prefix]
    call hfl_literal
    test eax, eax
    jz   .native_error
    lea  rsi, [rel hfl_identity]
    call hfl_literal
    test eax, eax
    jz   .bad
    lea  rsi, [rel str_hfl_win]
    call hfl_literal
    test eax, eax
    jz   .bad
    call hfl_count
    test eax, eax
    jz   .bad
    lea  rsi, [rel str_hfl_widgets]
    call hfl_literal
    test eax, eax
    jz   .bad
    call hfl_count
    test eax, eax
    jz   .bad
    cmp  byte [rdi], 0
    jne  .bad
    mov  r12d, 1
    jmp  .copy
.native_error:
    ; Native FORMLOAD stages semantic errors with CMDE_OK. Preserve the exact
    ; bounded error text, but do not advertise that a window was opened.
    lea  rdi, [rel form_out_buf]
    lea  rsi, [rel str_hfl_error]
    call hfl_literal
    test eax, eax
    jz   .bad
    xor  ecx, ecx
.error_char:
    movzx eax, byte [rdi]
    test eax, eax
    jz   .error_end
    cmp  ecx, 31
    jae  .bad
    cmp  eax, '_'
    je   .error_take
    sub  eax, 'a'
    cmp  eax, 25
    ja   .bad
.error_take:
    inc  ecx
    inc  rdi
    jmp  .error_char
.error_end:
    test ecx, ecx
    jz   .bad
    xor  r12d, r12d
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_VAL], 0
    mov  qword [rbx + RSP_HINT], 0
.copy:
    call command_hook_out_reset
    lea  rdi, [rel form_out_buf]
    call command_hook_out_str
    call hfl_retire
    mov  byte [rel command_hook_out_ready], 1
    mov  eax, r12d
    jmp  .out
.bad:
    call hfl_retire
    call command_hook_out_reset
    lea  rdi, [rel str_hfl_bad]
    call command_hook_out_str
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_VAL], 0
    mov  qword [rbx + RSP_HINT], 0
    mov  byte [rel command_hook_out_ready], 1
    xor  eax, eax
    jmp  .out
.refused:
    call hfl_retire                     ; keep native code and hint
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

hfl_retire:
    lea  rdi, [rel hfl_state]
    mov  ecx, hfl_state_end - hfl_state
    xor  eax, eax
    rep stosb
    mov  byte [rel form_out_ready], 0
    mov  qword [rel form_out_cur], 0
    lea  rdi, [rel form_out_buf]
    mov  ecx, HFL_NATIVE_MAX
    rep stosb
    ret

hfl_literal:
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
hfl_count:
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

str_hfl_name: db "formload", 0
str_hfl_kind: db "service", 0
str_hfl_verb: db "FORMLOAD", 0
str_hfl_schema: db "inst=identifier name=[a-z][a-z0-9_]{0,30} set=open->FORMLOAD{name} receipt={name:identifier,win:u32,widgets:u32} synchronous,complete,canonical native_errors=non_success focus=native_default get=na observe=na list=na input=na cancel=na native_authority=unchanged", 0
str_hfl_open: db "open", 0
str_hfl_prefix: db " formload=ok name=", 0
str_hfl_win: db " win=", 0
str_hfl_widgets: db " widgets=", 0
str_hfl_error: db " FORMLOAD formload=ERR ", 0
str_hfl_bad: db " hook err=formload_reply_incomplete", 0
align 8
hook_edge_formload: times (HE_SZ / 8) dq 0
hfl_state:
hfl_pending: db 0
hfl_identity: times 32 db 0
hfl_state_end:
