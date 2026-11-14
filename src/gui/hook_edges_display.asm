;; MODULE gui/hook_edges_display
;; LAYER 6
;; EXPORTS hook_display_edge_declare, hook_display_plan, hook_display_post
;; IMPORTS svc/command, svc/command_hook, gui/command_res
;; CAPS
;; OWNER saga:command
; Native read-only dimensions and boot-time mode inventory. No table/provider
; access here: the ordinary nested registry dispatch retains native authority.
HDI_NATIVE_MAX equ 1024
HDI_MODE_MAX equ 64

hook_display_edge_declare:
    push rbx
    lea  rbx, [rel hook_edge_display]
    lea  rax, [rel str_hdi_name]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hdi_kind]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hdi_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_display_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_display_post]
    mov  [rbx + HE_POST], rax
    lea  rax, [rel gres_out_buf]
    mov  [rbx + HE_OBUF], rax
    lea  rax, [rel gres_out_ready]
    mov  [rbx + HE_OREADY], rax
    mov  qword [rbx + HE_WITNESS], 0
    mov  rdi, rbx
    call command_hook_edge_register
    pop  rbx
    ret

hook_display_plan:
    push rdi
    push rsi
    push rdx
    call hdi_retire
    pop  rdx
    pop  rsi
    pop  rdi
    cmp  edi, HOP_GET
    jne  .na
    cmp  byte [rsi], 0
    jne  .bad
    cmp  byte [rdx], 0
    je   .info
    mov  rdi, rdx
    lea  rsi, [rel str_hdi_modes_arg]
    call hdi_literal
    test eax, eax
    jz   .bad
    cmp  byte [rdi], 0
    jne  .bad
    mov  byte [rel hdi_pending], 2
    call command_hook_arg_reset
    lea  rax, [rel str_hdi_modes_verb]
    ret
.info:
    mov  byte [rel hdi_pending], 1
    call command_hook_arg_reset
    lea  rax, [rel str_hdi_info_verb]
    ret
.na:
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    ret
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
    ret

hook_display_post:
    push rbx
    push r12
    mov  rbx, rcx
    cmp  qword [rbx + RSP_CODE], CMDE_OK
    jne  .refused
    cmp  byte [rel gres_out_ready], 1
    jne  .bad
    lea  rdi, [rel gres_out_buf]
    xor  ecx, ecx
.scan:
    cmp  ecx, HDI_NATIVE_MAX
    jae  .bad
    cmp  byte [rdi + rcx], 0
    je   .end
    inc  ecx
    jmp  .scan
.end:
    lea  rax, [rdi + rcx]
    cmp  rax, [rel gres_out_cur]
    jne  .bad
    cmp  byte [rel hdi_pending], 1
    je   .info
    cmp  byte [rel hdi_pending], 2
    jne  .bad
    lea  rsi, [rel str_hdi_modes_head]
    call hdi_literal
    test eax, eax
    jz   .bad
    call hdi_count
    test eax, eax
    jz   .bad
    mov  r12d, edx
    lea  rsi, [rel str_hdi_current]
    call hdi_literal
    test eax, eax
    jz   .bad
    call hdi_wh
    test eax, eax
    jz   .bad
.row:
    test r12d, r12d
    jz   .finish
    cmp  byte [rdi], ' '
    jne  .bad
    inc  rdi
    call hdi_wh
    test eax, eax
    jz   .bad
    dec  r12d
    jmp  .row
.info:
    lea  rsi, [rel str_hdi_info_head]
    call hdi_literal
    test eax, eax
    jz   .bad
    call hdi_wh
    test eax, eax
    jz   .bad
    lea  rsi, [rel str_hdi_active]
    call hdi_literal
    test eax, eax
    jz   .bad
    call hdi_wh
    test eax, eax
    jz   .bad
    lea  rsi, [rel str_hdi_source]
    call hdi_literal
    test eax, eax
    jz   .bad
    cmp  dword [rdi], 'edid'
    je   .source4
    cmp  dword [rdi], 'none'
    je   .source4
    cmp  word [rdi], 'go'
    jne  .bad
    cmp  byte [rdi + 2], 'p'
    jne  .bad
    add  rdi, 3
    jmp  .dpi
.source4:
    add  rdi, 4
.dpi:
    lea  rsi, [rel str_hdi_dpi]
    call hdi_literal
    test eax, eax
    jz   .bad
    call hdi_decimal
    test eax, eax
    jz   .bad
    cmp  edx, 255
    ja   .bad
    lea  rsi, [rel str_hdi_count]
    call hdi_literal
    test eax, eax
    jz   .bad
    call hdi_count
    test eax, eax
    jz   .bad
.finish:
    cmp  byte [rdi], 0
    jne  .bad
    call command_hook_out_reset
    lea  rdi, [rel gres_out_buf]
    call command_hook_out_str
    call hdi_retire
    mov  eax, 1
    jmp  .out
.bad:
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  qword [rbx + RSP_VAL], 0
    call command_hook_out_reset
    lea  rdi, [rel str_hdi_bad]
    call command_hook_out_str
    call hdi_retire
    mov  eax, 1
    jmp  .out
.refused:
    call hdi_retire
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

hdi_count:
    call hdi_decimal
    test eax, eax
    jz   .out
    cmp  edx, HDI_MODE_MAX
    ja   .bad
.out:
    ret
.bad:
    xor  eax, eax
    ret

hdi_wh:
    call hdi_decimal
    test eax, eax
    jz   .out
    cmp  byte [rdi], 'x'
    jne  .bad
    inc  rdi
    jmp  hdi_decimal
.bad:
    xor  eax, eax
.out:
    ret

; Canonical full u32 decimal, including zero. Returns EAX=1, EDX=value;
; RDI advances only over the number. No sign, leading zero or wrapped prefix.
hdi_decimal:
    xor  edx, edx
    cmp  byte [rdi], '0'
    jne  .digits
    inc  rdi
    mov  eax, 1
    ret
.digits:
    xor  ecx, ecx
.loop:
    movzx eax, byte [rdi]
    sub  eax, '0'
    cmp  eax, 9
    ja   .end
    cmp  edx, 429496729
    ja   .bad
    jne  .take
    cmp  eax, 5
    ja   .bad
.take:
    imul edx, edx, 10
    add  edx, eax
    inc  rdi
    inc  ecx
    jmp  .loop
.end:
    test ecx, ecx
    jz   .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

hdi_literal:
    movzx eax, byte [rsi]
    test eax, eax
    jz   .yes
    cmp  al, [rdi]
    jne  .no
    inc  rsi
    inc  rdi
    jmp  hdi_literal
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

hdi_retire:
    mov  byte [rel hdi_pending], 0
    mov  byte [rel gres_out_ready], 0
    mov  qword [rel gres_out_cur], 0
    lea  rdi, [rel gres_out_buf]
    mov  ecx, HDI_NATIVE_MAX
    xor  eax, eax
    rep stosb
    ret

str_hdi_name: db "display", 0
str_hdi_kind: db "device", 0
str_hdi_schema: db "v=1 inst=none get=RESINFO{native:u32xu32,active:u32xu32,src:edid|gop|none,dpi:u8,modes:0..64}|modes:RESMODES{n:0..64,cur:u32xu32,rows:n*u32xu32} observe=whole-selected-native-receipt extent=complete,current,synchronous native=boot-detection active=live-render-surface modes=boot-captured not-atomic no-physical-paint-or-live-enumeration-proof authority=native scanout_change=untyped list=na set=na input=na cancel=na", 0
str_hdi_info_verb: db "RESINFO", 0
str_hdi_modes_verb: db "RESMODES", 0
str_hdi_modes_arg: db "modes", 0
str_hdi_info_head: db " RESINFO native=", 0
str_hdi_active: db " active=", 0
str_hdi_source: db " src=", 0
str_hdi_dpi: db " dpi=", 0
str_hdi_count: db " modes=", 0
str_hdi_modes_head: db " RESMODES n=", 0
str_hdi_current: db " cur=", 0
str_hdi_bad: db " hook err=display_reply_incomplete", 0
align 8
hook_edge_display: times HE_SZ db 0
hdi_pending: db 0
