;; MODULE svc/hook_edge_console
;; LAYER 5
;; EXPORTS hook_console_edge_declare, hook_console_plan, hook_console_post
;; IMPORTS svc/command_cons, svc/command, svc/command_hook
;; CAPS
;; OWNER saga:command
; Bounded native session inventory, without transcript/input/mutation operations.
; Common dispatch retains source/principal/capability/idempotency and native
; production owner-envelope/lab-only exemption. BSP-serialized shared stage.
; Copy a complete canonical inventory then erase all owned1450 producer bytes,
; cursor, ready and pending, including admission/native/structure refusal paths.
HCI_REPLY_MAX equ 1450
hook_console_edge_declare:
    push rbx
    lea rbx,[rel hook_edge_console]
    lea  rax, [rel str_hci_name]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hci_kind]
    mov  [rbx + HE_KIND], rax
    lea rax,[rel str_hci_schema]
    mov [rbx+HE_SCHEMA],rax
    lea rax,[rel hook_console_plan]
    mov [rbx+HE_PLAN],rax
    lea rax,[rel hook_console_post]
    mov [rbx+HE_POST],rax
    mov qword [rbx+HE_OBUF],0
    mov qword [rbx+HE_OREADY],0
    mov qword [rbx+HE_WITNESS],0 ; every row and field in the validated inventory
    mov rdi,rbx
    call command_hook_edge_register
    pop rbx
    ret
hook_console_plan:
    call hci_retire
    cmp edi,HOP_GET
    je .read
    cmp edi,HOP_LIST
    jne .na
.read:
    cmp byte [rsi],0
    jne .bad
    cmp byte [rdx],0
    jne .bad
    lea rdi,[rel str_hci_verb]
    call command_lookup
    cmp rax,-1
    je .unregistered
    mov byte [rel hci_pending],1
.unregistered:
    lea rax,[rel str_hci_verb]
    xor edx,edx
    ret
.na:
    xor eax,eax
    mov edx,HOOK_PLAN_NA
    ret
.bad:
    xor eax,eax
    mov edx,HOOK_PLAN_BADARG
    ret
hook_console_post:
    push rbx
    push r12
    mov rbx,rcx
    cmp qword [rbx+RSP_CODE],CMDE_OK
    jne .refused
    cmp byte [rel hci_pending],1
    jne .bad
    cmp byte [rel grid_out_ready],1
    jne .bad
    lea rdi,[rel grid_out_buf]
    xor ecx,ecx
.length:
    cmp ecx,HCI_REPLY_MAX
    jae .bad
    cmp byte [rdi+rcx],0
    je .bounded
    inc ecx
    jmp .length
.bounded:
    cmp ecx,HOOK_OUT_MAX
    jae .bad
    lea rax,[rdi+rcx]
    cmp rax,[rel grid_out_cur]
    jne .bad
    mov r12,rdi
    call hci_record
    test eax,eax
    jz .bad
    cmp rdx,[rbx+RSP_VAL] ; bind native count and complete row census
    jne .bad
    sub rdi,r12
    push rdi
    call command_hook_out_reset
    pop rsi
    mov rdi,r12
    call command_hook_out_strn
    call hci_retire
    mov eax,1
    jmp .out
.bad:
    call command_hook_out_reset
    lea rdi,[rel str_hci_bad]
    call command_hook_out_str
    mov qword [rbx+RSP_CODE],CMDE_BADARG
    mov qword [rbx+RSP_ACCEPTED],0
    mov qword [rbx+RSP_VAL],0
    lea rax,[rel str_hci_bad]
    mov [rbx+RSP_HINT],rax
    call hci_retire
    mov eax,1
    jmp .out
.refused:
    call hci_retire
    xor eax,eax
.out:
    pop r12
    pop rbx
    ret
hci_retire:
    push rax
    push rcx
    push rdi
    mov byte [rel hci_pending],0
    mov byte [rel grid_out_ready],0
    mov qword [rel grid_out_cur],0
    lea rdi,[rel grid_out_buf]
    xor eax,eax
    mov ecx,HCI_REPLY_MAX
    cld
    rep stosb
    pop rdi
    pop rcx
    pop rax
    ret

; A bounded NUL/cursor check precedes parsing. Count and all rows agree with
; native scalar; name grammar follows cons_name_len (printable !..~, 1..31).
; EAX=valid, RDX=count. Saved native u64 seq/floor are observations, not admission.
hci_record:
    push rbx
    push r12
    lea rsi,[rel str_hci_head]
    call hci_literal
    test eax,eax
    jz .no
    call hci_u64
    test eax,eax
    jz .no
    cmp rdx,4
    ja .no
    mov r12,rdx
    xor ebx,ebx
.row:
    cmp rbx,r12
    jae .end
    lea rsi,[rel str_hci_row]
    call hci_literal
    test eax,eax
    jz .no
    xor ecx,ecx
.name:
    movzx eax,byte [rdi]
    cmp eax,' '
    je .name_end
    cmp eax,0x21
    jb .no
    cmp eax,0x7e
    ja .no
    cmp ecx,31
    jae .no
    inc ecx
    inc rdi
    jmp .name
.name_end:
    test ecx,ecx
    jz .no
    lea rsi,[rel str_hci_seq]
    call hci_literal
    test eax,eax
    jz .no
    call hci_u64
    test eax,eax
    jz .no
    lea rsi,[rel str_hci_floor]
    call hci_literal
    test eax,eax
    jz .no
    call hci_u64
    test eax,eax
    jz .no
    lea rsi,[rel str_hci_bound]
    call hci_literal
    test eax,eax
    jz .no
    cmp byte [rdi],'n'
    jne .number
    lea rsi,[rel str_hci_none]
    call hci_literal
    test eax,eax
    jz .no
    jmp .records
.number:
    call hci_u64
    test eax,eax
    jz .no
    mov eax,0xfffffffe
    cmp rdx,rax
    ja .no
.records:
    lea rsi,[rel str_hci_records]
    call hci_literal
    test eax,eax
    jz .no
    call hci_u64
    test eax,eax
    jz .no
    cmp rdx,24
    ja .no
    lea rsi,[rel str_hci_bytes]
    call hci_literal
    test eax,eax
    jz .no
    call hci_u64
    test eax,eax
    jz .no
    cmp rdx,8192
    ja .no
    lea rsi,[rel str_hci_budget]
    call hci_literal
    test eax,eax
    jz .no
    inc ebx
    jmp .row
.end:
    cmp byte [rdi],0
    jne .no
    mov rdx,r12
    mov eax,1
    jmp .out
.no:
    xor eax,eax
.out:
    pop r12
    pop rbx
    ret
hci_literal:
    mov al,[rsi]
    test al,al
    jz .yes
    cmp al,[rdi]
    jne .no
    inc rsi
    inc rdi
    jmp hci_literal
.yes:
    mov eax,1
    ret
.no:
    xor eax,eax
    ret
; Canonical unsigned decimal, bounded to20 digits, overflow checked before use.
hci_u64:
    xor edx,edx
    xor ecx,ecx
.loop:
    movzx eax,byte [rdi]
    sub eax,'0'
    cmp eax,9
    ja .end
    cmp ecx,20
    jae .no
    test ecx,ecx
    jnz .acc
    cmp eax,0
    jne .acc
    movzx r8d,byte [rdi+1]
    sub r8d,'0'
    cmp r8d,9
    jbe .no
.acc:
    mov r8,1844674407370955161
    cmp rdx,r8
    ja .no
    jne .add
    cmp eax,5
    ja .no
.add:
    lea rdx,[rdx+rdx*4]
    lea rdx,[rax+rdx*2]
    inc ecx
    inc rdi
    jmp .loop
.end:
    test ecx,ecx
    jz .no
    mov eax,1
    ret
.no:
    xor eax,eax
    ret
str_hci_name: db "console",0
str_hci_kind: db "service",0
str_hci_verb: db "CONS_LIST",0
str_hci_schema: db "v=1 inst=none get=CONS_LIST list=CONS_LIST observe=whole-native-reply fields=n:0..4;rows{name:printable1..31,seq:u64,floor:u64,bound:u32|none,records:0..24,bytes:0..8192/8192} scope=inventory-only authority=native-production-owner;native-lab-exemption set=na input=na cancel=na",0
str_hci_bad: db " hook err=console_reply_incomplete",0
str_hci_head: db " CONS_LIST n=",0
str_hci_row: db " CONS name=",0
str_hci_seq: db " seq=",0
str_hci_floor: db " floor=",0
str_hci_bound: db " bound=",0
str_hci_none: db "none",0
str_hci_records: db " records=",0
str_hci_bytes: db " bytes=",0
str_hci_budget: db "/8192",0
align 8
hook_edge_console: times HE_SZ db 0
hci_pending: db 0
