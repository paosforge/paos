%macro PP_TEXT 1
    lea rdi,[rel %1]
    mov rsi,rbp
    call fmt_str
    add rbp,rax
%endmacro
%macro PP_HEX 0
    mov rsi,rbp
    mov edx,16
    call fmt_hex
    add rbp,rax
%endmacro
; Passive exact original PCI-assignment predicate; not teardown authority.
; RDI=actual 32B driver observation, EAX/EDX=original guest decision/blocker.
; Caller is the existing IF-clear storage boundary, immediately after predicate.
; Private committed local BOOT LINUX executor only. No call/TTL/budget change.
command_power_return_pci:
    pushfq
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push rbx
    push r12
    push r13
    push r14
    push r15
    push rbp
    mov rbp,rsp
    sub rsp,1040
    and rsp,-16
    mov [rsp+1024],rbp
    cmp byte [rel pr_linux],1
    jne .out
    cmp byte [rel pr_kind],2
    jne .out
    cmp byte [rel pr_state],PR_COMMITTED
    jne .out
    cmp byte [rel sd_state],SD_EXECUTING
    jne .out
    ; EDX is the original first blocker: earlier checks never examined PCI.
    test edx,edx
    jz .reached
    cmp edx,15
    jb .out
.reached:
    cmp dword [rdi],1
    jne .out
    mov r12,rdi
    mov rbp,rsp
    PP_TEXT pp_trace
    PP_TEXT pr_nonce
    PP_TEXT pr_s_build
    PP_TEXT paos_build_hex
    PP_TEXT pr_s_boot_id
    PP_TEXT pr_s_hex
    mov rdi,[rel boot_tsc_start]
    PP_HEX
    PP_TEXT pr_s_boot_nonce
    PP_TEXT pr_s_hex
    mov edi,[rel boot_nonce]
    PP_HEX
    PP_TEXT pr_s_seq
    PP_TEXT pr_s_hex
    mov rdi,[rel pr_next_sequence]
    PP_HEX
    PP_TEXT pr_s_kind
    PP_TEXT pr_s_hex
    movzx edi,byte [rel pr_kind]
    PP_HEX
    PP_TEXT pp_owned
    PP_TEXT pr_s_hex
    mov edi,[r12+4]
    PP_HEX
    PP_TEXT pp_state
    PP_TEXT pr_s_hex
    mov edi,[r12+8]
    PP_HEX
    PP_TEXT pp_bdf
    PP_TEXT pr_s_hex
    mov edi,[r12+12]
    PP_HEX
    PP_TEXT pp_generation
    PP_TEXT pr_s_hex
    mov rdi,[r12+16]
    PP_HEX
    PP_TEXT pp_device_kind
    PP_TEXT pr_s_hex
    mov edi,[r12+24]
    PP_HEX
    PP_TEXT pp_claimed
    PP_TEXT pr_s_hex
    mov edi,[r12+28]
    PP_HEX
    PP_TEXT pr_s_ms
    PP_TEXT pr_s_hex
    call boot_ms_now
    mov rdi,rax
    PP_HEX
    PP_TEXT pr_s_until
    PP_TEXT pr_s_hex
    mov rdi,[rel pr_deadline]
    PP_HEX
    PP_TEXT sd_s_crlf
    mov rdi,rsp
    call serial_string
    call serial_drain_poll
.out:
    mov rsp,[rsp+1024]
    pop rbp
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    popfq
    ret

pp_trace: db '[PAOS64] POWERPCI1 nonce=',0
pp_owned: db ' owned=',0
pp_state: db ' state=',0
pp_bdf: db ' bdf=',0
pp_generation: db ' generation=',0
pp_device_kind: db ' device_kind=',0
pp_claimed: db ' claimed=',0

%unmacro PP_TEXT 1
%unmacro PP_HEX 0
