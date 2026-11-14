;; MODULE svc/command_fs_service
;; LAYER 5
;; OWNER saga:storage
; Included by command_fs; shares its original command/auth/output context.
; Configuring the service is OWNER+SPECIAL and destructive-class (no IO here).
; Observations are owner-only, frozen across five fixed pages under one nonce.
; Native addresses never appear in the wire records.
cmd_verb_fsservice:
    push rbx
    push r12
    push r13
    push r14
    push r15
    call cmd_handler_prologue
    mov r12,rdi
    mov r13,rsi
    call storage_access_request_owner
    cmp eax,1
    jne .auth
    call storage_access_request_intent
    cmp eax,SA_INTENT_SPECIAL
    jne .auth
    mov rax,[r12+REQ_PRINCIPAL]
    test rax,rax
    jz .auth
    mov rdx,[rel cmd_dispatch_proposer]
    test rdx,rdx
    jz .principal
    cmp rdx,rax
    jne .auth
.principal:
    mov rdi,[r12+REQ_ARG]
    test rdi,rdi
    jz .bad
    xor ecx,ecx
.bound:
    cmp ecx,594
    jae .bad
    cmp byte [rdi+rcx],0
    je .tokens
    inc ecx
    jmp .bound
.tokens:
    call fs_tokenize
    cmp dword [rel fs_tok_count],3
    jne .bad
    mov ecx,[rel fs_tok_len]
    test ecx,ecx
    jz .bad
    cmp ecx,62
    ja .bad
    mov rsi,[rel fs_tok_ptr]
    lea rdi,[rel fscmd_device]
    cld
    rep movsb
    mov byte [rdi],0
    cmp dword [rel fs_tok_len+4],512
    jne .bad
    mov rdi,[rel fs_tok_ptr+16]
    mov esi,[rel fs_tok_len+8]
    call fs_nonce_valid
    test eax,eax
    jz .bad
    mov rsi,[rel fs_tok_ptr+8]
    lea rdi,[rel fscmd_config]
    mov ecx,256
.hex:
    push rcx
    push rsi
    push rdi
    movzx eax,byte [rsi]
    call fs_hexval
    test eax,eax
    js .hex_bad
    shl eax,4
    mov r14d,eax
    mov rsi,[rsp+8]
    movzx eax,byte [rsi+1]
    call fs_hexval
    test eax,eax
    js .hex_bad
    or eax,r14d
    pop rdi
    pop rsi
    pop rcx
    stosb
    add rsi,2
    loop .hex
    lea rdi,[rel fscmd_device]
    lea rsi,[rel fscmd_config]
    mov rdx,[r12+REQ_PRINCIPAL]
    call copy_service_configure
    test rax,rax
    js .refused
    mov [r13+RSP_VAL],rax
    mov r15,rax
    mov rdx,[r12+REQ_PRINCIPAL]
    mov [rel fscmd_service_principal],rdx
    call fs_out_reset
    lea rdi,[rel fscmd_config_prefix]
    call fs_out_str
    mov rdi,[rel fs_tok_ptr+16]
    mov esi,16
    call fs_out_token
    lea rdi,[rel fscmd_mount_prefix]
    call fs_out_str
    mov rdi,r15
    call fs_out_dec
    lea rdi,[rel str_fs_copy_eol]
    call fs_out_str
    call fs_finish
    jmp .out
.hex_bad:
    add rsp,24
.bad:
    mov qword [r13+RSP_CODE],CMDE_BADARG
    jmp .out
.auth:
    mov qword [r13+RSP_CODE],CMDE_AUTHDENY
    jmp .out
.refused:
    mov qword [r13+RSP_CODE],CMDE_BADSEL
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

cmd_verb_fsservicestat:
    push rbx
    push r12
    push r13
    push r14
    push r15
    call cmd_handler_prologue
    mov r12,rdi
    mov r13,rsi
    call storage_access_request_owner
    cmp eax,1
    jne .auth
    mov rdi,[r12+REQ_ARG]
    test rdi,rdi
    jz .bad
    ; Exact page ASCII digit, one space, 16 lowerhex nonce, NUL.
    movzx ebx,byte [rdi]
    sub ebx,'0'
    cmp ebx,4
    ja .bad
    cmp byte [rdi+1],' '
    jne .bad
    cmp byte [rdi+18],0
    jne .bad
    lea rdi,[rdi+2]
    mov esi,16
    call fs_nonce_valid
    test eax,eax
    jz .bad
    mov r14,[r12+REQ_ARG]
    add r14,2
    mov r15,[r12+REQ_PRINCIPAL]
    test r15,r15
    jz .auth
    mov rax,[rel cmd_dispatch_proposer]
    test rax,rax
    jz .principal
    cmp rax,r15
    jne .auth
.principal:
    test ebx,ebx
    jnz .cached
    mov byte [rel fscmd_snapshot_valid],0
    lea rdi,[rel fscmd_snapshot]
    mov esi,1040
    call vfs_copy_service_state
    cmp eax,1040
    jne .refused
    mov rax,[r14]
    mov [rel fscmd_snapshot_nonce],rax
    mov rax,[r14+8]
    mov [rel fscmd_snapshot_nonce+8],rax
    mov [rel fscmd_snapshot_principal],r15
    mov byte [rel fscmd_snapshot_valid],1
.cached:
    cmp byte [rel fscmd_snapshot_valid],1
    jne .refused
    cmp r15,[rel fscmd_snapshot_principal]
    jne .auth
    mov rax,[r14]
    cmp rax,[rel fscmd_snapshot_nonce]
    jne .bad
    mov rax,[r14+8]
    cmp rax,[rel fscmd_snapshot_nonce+8]
    jne .bad
    call fs_out_reset
    lea rdi,[rel fscmd_stat_prefix]
    call fs_out_str
    mov rdi,r14
    mov esi,16
    call fs_out_token
    lea rdi,[rel fscmd_page_prefix]
    call fs_out_str
    mov edi,ebx
    call fs_out_dec
    lea rdi,[rel fscmd_hex_prefix]
    call fs_out_str
    mov eax,ebx
    shl eax,8
    lea rdi,[rel fscmd_snapshot]
    add rdi,rax
    mov esi,256
    cmp ebx,4
    jne .emit
    mov esi,16
.emit:
    call fs_out_data_hex
    lea rdi,[rel str_fs_copy_eol]
    call fs_out_str
    call fs_finish
    jmp .out
.bad:
    mov qword [r13+RSP_CODE],CMDE_BADARG
    jmp .out
.auth:
    mov qword [r13+RSP_CODE],CMDE_AUTHDENY
    jmp .out
.refused:
    mov qword [r13+RSP_CODE],CMDE_BADSEL
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
; Only FSCOPY's same-volume exact service mount may bypass the historical
; scratch filename classifier. The backend independently checks BOTH exact
; grant names, mode0 and OWNER+SPECIAL before acquiring/starting anything.
; RDI=token, ESI=len, RDX=private output; original R12=request/R14=verb.
fs_service_copy_path:
    push rbx
    push r15
    push rdi
    push rsi
    push rdx
    mov edi,[rel vfs_disk_handle]
    call vfs_mount_ptr
    test rax,rax
    jz .ordinary
    lea rdx,[rel vfs_copy_service_ops]
    cmp [rax+fsmount.ops],rdx
    jne .ordinary
    lea rax,[rel str_fscopy]
    cmp r14,rax
    jne .refused
    cmp byte [rel fs_cp_cross],0
    jne .refused
    cmp dword [rel fs_cp_mode],0
    jne .refused
    mov rax,[r12+REQ_PRINCIPAL]
    test rax,rax
    jz .refused
    cmp rax,[rel fscmd_service_principal]
    jne .refused
    mov rdx,[rel cmd_dispatch_proposer]
    test rdx,rdx
    jz .copy
    cmp rdx,rax
    jne .refused
.copy:
    mov rcx,[rsp+8]
    test ecx,ecx
    jz .refused
    cmp ecx,FS_PATH_CAP
    ja .refused
    mov rdi,[rsp]
    mov rsi,[rsp+16]
    cld
    rep movsb
    mov byte [rdi],0
    xor eax,eax
    jmp .out
.ordinary:
    mov rdx,[rsp]
    mov rsi,[rsp+8]
    mov rdi,[rsp+16]
    cmp byte [rel fs_cp_cross],0
    je .selected
    call fs_mut_path_copy.bound         ; the source is read-only; .cross rules on the destination
    jmp .out
.selected:
    call fs_mut_path_copy
    jmp .out
.refused:
    mov rax,-1
.out:
    add rsp,24
    pop r15
    pop rbx
    ret

str_fsservice: db 'FSSERVICE',0
str_fsservicestat: db 'FSSERVICESTAT',0
fscmd_config_prefix: db ' fservice_config=1 nonce=',0
fscmd_mount_prefix: db ' mount=',0
fscmd_stat_prefix: db ' fservice=1 nonce=',0
fscmd_page_prefix: db ' page=',0
fscmd_hex_prefix: db ' data=',0
%macro WDATA_svc_command_fs_service 0
align 8
fscmd_service_principal: dq 0
fscmd_snapshot_principal: dq 0
fscmd_snapshot_nonce: times 16 db 0
fscmd_snapshot_valid: db 0
fscmd_device: times 64 db 0
fscmd_config: times 256 db 0
fscmd_snapshot: times 1040 db 0
%endmacro
WDATA_DEFER WDATA_svc_command_fs_service
