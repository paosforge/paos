; Sole registry projection. AUTH1 signs the entire original command. The
; nonce correlates evidence and identifies the one active case; no new TTL,
; sequence window, owner binding, firmware write, or public query authority.
%ifdef PAOS_PUBLICITY_LAB_PROFILE
%if PAOS_PUBLICITY_LAB_PROFILE
cmd_verb_sshprofilefault:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 48
    mov  r12, rdi
    mov  r13, rsi
    call ssh_keyverb_out_begin
    ; No argument dereference, native reload, or state change before ALL
    ; route, dispatch, ticket, and execution-principal checks have passed.
    cmp  byte [rel cmd_in_dispatch], 1
    jne  .owner
    cmp  dword [rel cmd_dispatch_depth], 1
    jne  .owner
    cmp  qword [r12 + REQ_SOURCE], CMD_SOURCE_UDP
    jne  .owner
    mov  rdi, r12
    call ssh_keyverb_owner_signed
    test eax, eax
    jz   .owner
    call ssh_cli_fault_owner
    test eax, eax
    jnz  .owner
    mov  r14, [r12 + REQ_ARG]
    test r14, r14
    jz   .grammar
    xor  ecx, ecx
.nonce:
    movzx eax, byte [r14 + rcx]
    cmp  al, '0'
    jb   .grammar
    cmp  al, '9'
    jbe  .digit
    cmp  al, 'a'
    jb   .grammar
    cmp  al, 'f'
    ja   .grammar
.digit:
    inc  ecx
    cmp  ecx, 16
    jb   .nonce
    cmp  byte [r14 + 16], ' '
    jne  .grammar
    lea  rdi, [r14 + 17]
    lea  rsi, [rel str_sshfault_status]
    call ssh_fault_word_is
    test eax, eax
    jnz  .status
    lea  rdi, [r14 + 17]
    lea  rsi, [rel str_sshfault_clear]
    call ssh_fault_word_is
    test eax, eax
    jnz  .clear
    ; Short-circuit every byte: a terminator fails before any later read.
    cmp  byte [r14 + 17], 'A'
    jne  .grammar
    cmp  byte [r14 + 18], 'R'
    jne  .grammar
    cmp  byte [r14 + 19], 'M'
    jne  .grammar
    cmp  byte [r14 + 20], ' '
    jne  .grammar
    movzx edi, byte [r14 + 21]
    sub  edi, '0'
    cmp  edi, 1
    jb   .grammar
    cmp  edi, 2
    ja   .grammar
    cmp  byte [r14 + 22], ' '
    jne  .grammar
    movzx esi, byte [r14 + 23]
    sub  esi, '0'
    cmp  esi, 1
    jb   .grammar
    cmp  esi, 4
    ja   .grammar
    cmp  byte [r14 + 24], 0
    jne  .grammar
    mov  ebx, 2                         ; ARM
    call ssh_cli_fault_arm
    test eax, eax
    jnz  .arm_refused
    lea  rdi, [rel ssh_fault_case_nonce]
    mov  rsi, r14
    mov  edx, 16
    call memcpy                        ; only a successful arm owns this nonce
    jmp  .snapshot
.status:
    mov  ebx, 1
    jmp  .snapshot
.clear:
    mov  rdi, rsp
    call ssh_cli_fault_status
    test eax, eax
    jnz  .owner
    cmp  byte [rsp], 1
    jne  .no_case
    mov  rdi, r14
    lea  rsi, [rel ssh_fault_case_nonce]
    mov  edx, 16
    call memcmp
    test eax, eax
    jnz  .wrong_case                    ; stale finally cannot retire a new case
    mov  ebx, 3                         ; CLEAR
    call ssh_cli_fault_retire           ; off + wipe BEFORE real authenticated read
    cmp  eax, -1
    je   .no_case
    ; A failed restoration still emits its final status, with an error code.
.snapshot:
    mov  rdi, rsp
    call ssh_cli_fault_status
    test eax, eax
    jnz  .owner
    xor  r15d, r15d
    cmp  byte [rsp + 3], 3
    jne  .format
    mov  r15d, 1                       ; persistent reboot-required latch
.format:
    call ssh_keyverb_out_begin          ; discard incidental store-warning text
    lea  rdi, [rel str_sshfault_head]
    call ssh_txt_put_str
    mov  rdi, r14
    mov  esi, 16
    call ssh_txt_put_bytes
    lea  rdi, [rel str_sshfault_op]
    call ssh_txt_put_str
    mov  edi, ebx
    call ssh_txt_put_dec
    lea  rdi, [rel str_sshfault_case]
    call ssh_txt_put_str
    lea  rdi, [rel ssh_fault_case_nonce]
    mov  esi, 16
    ; Zero at boot is represented by sixteen ASCII zeros, never embedded NUL.
    cmp  byte [rdi], 0
    jne  .case_ready
    lea  rdi, [rel str_sshfault_zero_nonce]
.case_ready:
    call ssh_txt_put_bytes
    lea  rdi, [rel str_sshfault_active]
    call ssh_txt_put_str
    movzx edi, byte [rsp]
    call ssh_txt_put_dec
    lea  rdi, [rel str_sshfault_store]
    call ssh_txt_put_str
    movzx edi, byte [rsp + 1]
    call ssh_txt_put_dec
    lea  rdi, [rel str_sshfault_mode]
    call ssh_txt_put_str
    movzx edi, byte [rsp + 2]
    call ssh_txt_put_dec
    lea  rdi, [rel str_sshfault_result]
    call ssh_txt_put_str
    movzx edi, byte [rsp + 3]
    call ssh_txt_put_dec
    lea  rdi, [rel str_sshfault_cid_reads]
    call ssh_txt_put_str
    mov  rdi, [rsp + 8]
    call ssh_txt_put_dec
    lea  rdi, [rel str_sshfault_kh_reads]
    call ssh_txt_put_str
    mov  rdi, [rsp + 16]
    call ssh_txt_put_dec
    lea  rdi, [rel str_sshfault_cid_writes]
    call ssh_txt_put_str
    mov  rdi, [rsp + 24]
    call ssh_txt_put_dec
    lea  rdi, [rel str_sshfault_kh_writes]
    call ssh_txt_put_str
    mov  rdi, [rsp + 32]
    call ssh_txt_put_dec
    lea  rdi, [rel str_sshfault_provenance]
    call ssh_txt_put_str
    test r15d, r15d
    jnz  .reboot
    lea  rdi, [rel str_sshfault_end]
    call ssh_txt_put_str
    mov  rdi, r13
    call ssh_keyverb_finish_ok
    jmp  .out
.reboot:
    lea  rdi, [rel str_sshfault_reboot]
    jmp  .error
.owner:
    lea  rdi, [rel str_sshfault_owner]
    jmp  .error
.grammar:
    lea  rdi, [rel str_sshfault_usage]
    jmp  .error
.arm_refused:
    lea  rdi, [rel str_sshfault_unavailable]
    jmp  .error
.no_case:
    lea  rdi, [rel str_sshfault_no_case]
    jmp  .error
.wrong_case:
    lea  rdi, [rel str_sshfault_wrong_case]
.error:
    call ssh_txt_put_str
    mov  rdi, r13
    call ssh_keyverb_finish_err
.out:
    add  rsp, 48
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Exact NUL-terminated operation, stops at the first mismatch/terminator.
ssh_fault_word_is:
    mov  al, [rdi]
    cmp  al, [rsi]
    jne  .no
    test al, al
    jz   .yes
    inc  rdi
    inc  rsi
    jmp  ssh_fault_word_is
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

str_sshfault_status: db "STATUS",0
str_sshfault_clear: db "CLEAR",0
str_sshfault_head: db " SSHPROFILEFAULT v=1 nonce=",0
str_sshfault_op: db " op=",0
str_sshfault_case: db " case_nonce=",0
str_sshfault_zero_nonce: db "0000000000000000"
str_sshfault_active: db " active=",0
str_sshfault_store: db " store=",0
str_sshfault_mode: db " mode=",0
str_sshfault_result: db " result=",0
str_sshfault_cid_reads: db " cid_reads=",0
str_sshfault_kh_reads: db " kh_reads=",0
str_sshfault_cid_writes: db " cid_writes=",0
str_sshfault_kh_writes: db " kh_writes=",0
str_sshfault_provenance: db " injected_at=paos_wrapper no_persistence_credit",0
str_sshfault_end: db " reboot_required=0 end=1",0
str_sshfault_reboot: db " REFUSED reboot_required=1 end=1",0
str_sshfault_owner: db " SSHPROFILEFAULT REFUSED top_level_udp_owner_auth1_required",0
str_sshfault_usage: db " SSHPROFILEFAULT REFUSED usage: <16lowerhex> STATUS|ARM <store1..2> <mode1..4>|CLEAR",0
str_sshfault_unavailable: db " SSHPROFILEFAULT REFUSED arm_unavailable use_STATUS no_persistence_credit",0
str_sshfault_no_case: db " SSHPROFILEFAULT REFUSED no_active_case no_persistence_credit",0
str_sshfault_wrong_case: db " SSHPROFILEFAULT REFUSED wrong_case_nonce no_persistence_credit",0
%macro WDATA_svc_ssh_profile_fault_command_0 0
ssh_fault_case_nonce: times 16 db 0
%endmacro
WDATA_DEFER WDATA_svc_ssh_profile_fault_command_0
%endif
%endif
