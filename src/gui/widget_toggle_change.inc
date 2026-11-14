; Optional WIDGETSET value <0|1> if=<birth>,<window>,<before>. Original
; unlocked/principal gate runs first. All stores/redraw remain original WT_SET.
; A plain value preserves its original dispatch/result ABI. The guarded form
; accepts only the registered public disposable lab toggle, exact current birth.
wgt_toggle_condition:
    push rbx
    push r15
    mov rdi,r14
.scan:
    cmp byte [rdi],0
    je .ordinary
    cmp byte [rdi],' '
    je .suffix
    inc rdi
    jmp .scan
.suffix:
    ; Other types retain legacy values containing spaces.
    mov r15,rdi
    lea rdi,[rel str_wc_guard_value]
    mov rsi,r13
    call strcmp
    test eax,eax
    jnz .ordinary
    cmp byte [r15+1],'i'
    jne .ordinary
    cmp byte [r15+2],'f'
    jne .ordinary
    cmp byte [r15+3],'='
    jne .ordinary
%ifndef PAOS_PUBLICITY_LAB_PROFILE
%define PAOS_PUBLICITY_LAB_PROFILE 0
%endif
%if !PAOS_PUBLICITY_LAB_PROFILE
    jmp .bad
%endif
    cmp r15,r14
    jbe .bad
    mov rax,r15
    sub rax,r14
    cmp rax,1
    jne .bad
    movzx eax,byte [r14]
    sub eax,'0'
    cmp eax,1
    ja .bad
    mov [rel wgt_change_after],rax
    lea rdi,[r15+4]
    call wgt_change_dec
    jc .bad
    test rax,rax
    jz .bad
    cmp rax,-1
    je .bad
    mov [rel wgt_change_life],rax
    cmp byte [rdx],','
    jne .bad
    lea rdi,[rdx+1]
    call wgt_change_dec
    jc .bad
    cmp rax,64
    jae .bad
    mov [rel wgt_change_win],rax
    cmp byte [rdx],','
    jne .bad
    lea rdi,[rdx+1]
    call wgt_change_dec
    jc .bad
    cmp rax,1
    ja .bad
    cmp byte [rdx],0
    jne .bad
    mov [rel wgt_change_before],rax
    cmp rax,[rel wgt_change_after]
    je .bad
    mov edi,r12d
    call wgt_toggle_value_permission
    test eax,eax
    jnz .bad
    mov edi,r12d
    call wgt_birth_lifetime
    cmp rax,[rel wgt_change_life]
    jne .bad
    mov edi,r12d
    call wgt_slot_ptr
    mov ecx,[rax+WGI_WIN]
    cmp rcx,[rel wgt_change_win]
    jne .bad
    mov rax,[rax+WGI_NUM]
    cmp rax,[rel wgt_change_before]
    jne .bad
    mov byte [r15],0             ; original scalar strict parser sees just 0/1
    mov byte [rel wgt_change_active],1
.ordinary:
    xor eax,eax
    jmp .out
.bad:
    mov eax,1
.out:
    pop r15
    pop rbx
    ret

; Decimal with checked 64-bit multiply/add; reject empty/leading zero/overflow.
wgt_change_dec:
    mov r8,rdi
    xor eax,eax
    xor ecx,ecx
    mov r9d,10
.next:
    movzx r10d,byte [rdi]
    sub r10d,'0'
    cmp r10d,9
    ja .done
    mul r9
    test rdx,rdx
    jnz .bad
    add rax,r10
    jc .bad
    inc rdi
    inc ecx
    cmp ecx,20
    ja .bad
    jmp .next
.done:
    test ecx,ecx
    jz .bad
    cmp ecx,1
    je .ok
    cmp byte [r8],'0'
    je .bad
.ok:
    mov rdx,rdi
    clc
    ret
.bad:
    stc
    ret

wgt_toggle_change_result:
    lea rdi,[rel str_wc_guard_result]
    call wgt_out_str
    mov edi,r12d
    call wgt_out_dec
    lea rdi,[rel str_wc_guard_life]
    call wgt_out_str
    mov rdi,[rel wgt_change_life]
    call wgt_out_dec
    lea rdi,[rel str_wc_guard_win]
    call wgt_out_str
    mov rdi,[rel wgt_change_win]
    call wgt_out_dec
    lea rdi,[rel str_wc_guard_before]
    call wgt_out_str
    mov rdi,[rel wgt_change_before]
    call wgt_out_dec
    lea rdi,[rel str_wc_guard_after]
    call wgt_out_str
    mov edi,r12d
    call wgt_slot_ptr
    mov rdi,[rax+WGI_NUM]          ; actual value after original store and redraw
    call wgt_out_dec
    lea rdi,[rel str_wc_guard_end]
    call wgt_out_str
    ret

%macro WDATA_gui_widget_change 0
align 8
wgt_change_life: dq 0
wgt_change_win: dq 0
wgt_change_before: dq 0
wgt_change_after: dq 0
wgt_change_active: db 0
str_wc_guard_value: db "value",0
str_wc_guard_role: db "lab_toggle",0
str_wc_guard_type: db "toggle",0
str_wc_guard_result: db " widget change v=1 id=",0
str_wc_guard_life: db " life=",0
str_wc_guard_win: db " win=",0
str_wc_guard_before: db " before=",0
str_wc_guard_after: db " value=",0
str_wc_guard_end: db " result=ok end=1",0

%endmacro
WDATA_DEFER WDATA_gui_widget_change
