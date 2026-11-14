;; MODULE svc/optional_fault
;; LAYER 5
;; EXPORTS optional_fault_declare, optional_fault_prepare, optional_fault_inject, optional_fault_status, optional_fault_reset, optional_fault_health, opt_epoch, opt_state
;; IMPORTS dev/blk/ramblk, fs/blockdev, core/lib/fmt, svc/command, svc/command_auth
;; CAPS
;; OWNER saga:rc_t2_1_optional_fault
; Runtime containment probe over a real registered, disposable RAM blk_ops
; medium. This is NOT a physical/silicon failure. Neither the ledger medium,
; physical devices, selection policy, nor write authorization is modified.
; The caller's nonce and monotonically increasing epoch bind each transition.
; Authority comes through ordinary command dispatch; no new public exception.
; PREP, FAULT and RESET are OWNER only: SYSTEM holds generic MUTATE, so the handler checks.

OPT_UNOBSERVED equ 0xfffffffe

optional_fault_declare:
    lea rdi,[rel str_opt_prep]
    lea rsi,[rel cmd_opt_prepare]
    call opt_register_mutating
    lea rdi,[rel str_opt_fault]
    lea rsi,[rel cmd_opt_fault]
    call opt_register_mutating
    lea rdi,[rel str_opt_reset]
    lea rsi,[rel cmd_opt_reset]
    call opt_register_mutating
    lea rdi,[rel str_opt_stat]
    lea rsi,[rel cmd_opt_stat]
    xor edx,edx
    mov ecx,ARGT_TEXT
    xor r8d,r8d
    xor r9d,r9d
    jmp command_register_verb
opt_register_mutating:
    xor edx,edx
    mov ecx,ARGT_TEXT
    xor r8d,r8d
    mov r9d,1
    jmp command_register_verb

; Fixed 24 lower-case hex digits followed by NUL. No prefix, whitespace,
; extra token, unbounded scan or caller-selected device handle is accepted.
opt_nonce_valid:
    test rdi,rdi
    jz .bad
    xor ecx,ecx
.loop:
    mov al,[rdi+rcx]
    cmp al,'0'
    jb .bad
    cmp al,'9'
    jbe .next
    cmp al,'a'
    jb .bad
    cmp al,'f'
    ja .bad
.next:
    inc ecx
    cmp ecx,24
    jb .loop
    cmp byte [rdi+24],0
    jne .bad
    xor eax,eax
    ret
.bad:
    mov eax,-1
    ret
opt_nonce_match:
    call opt_nonce_valid
    test eax,eax
    jnz .out
    xor ecx,ecx
    lea rdx,[rel opt_nonce]
.loop:
    mov al,[rdi+rcx]
    cmp al,[rdx+rcx]
    jne .bad
    inc ecx
    cmp ecx,24
    jb .loop
    xor eax,eax
.out:
    ret
.bad:
    mov eax,-1
    ret

; prepare: refusal changes no fault state. Creation is attempted only once;
; allocation/registry failure never repeatedly allocates memory on a retry.
optional_fault_prepare:
    push rbx
    mov rbx,rdi
    call opt_nonce_valid
    test eax,eax
    jnz .bad
    cmp dword [rel opt_state],0
    je .phase_ok
    cmp dword [rel opt_state],3
    jne .bad
.phase_ok:
    cmp qword [rel opt_epoch],-1
    je .bad
    call blk_select
    test rax,rax
    jz .bad                              ; preserve a known healthy storage path
    cmp byte [rel opt_created],0
    jne .existing
    mov byte [rel opt_created],2
    call ramblk_optional_create
    test eax,eax
    jnz .bad
    mov byte [rel opt_created],1
.existing:
    cmp byte [rel opt_created],1
    jne .bad
    lea rdi,[rel ramblk_optional_dev]
    call blk_identify                    ; reset only the private RAM medium
    test eax,eax
    jnz .bad
    mov dword [rel ramblk_optional_dev+dev.health],HEALTH_OK
    mov rsi,rbx
    lea rdi,[rel opt_nonce]
    mov ecx,25
    cld
    rep movsb
    inc qword [rel opt_epoch]
    mov dword [rel opt_state],1
    mov dword [rel opt_fault_rc],OPT_UNOBSERVED
    mov dword [rel opt_fallback_rc],OPT_UNOBSERVED
    mov dword [rel opt_reset_rc],OPT_UNOBSERVED
    mov qword [rel opt_fallback_generation],0
    mov dword [rel opt_fallback_bytes],0
    lea rdi,[rel str_opt_none]
    call opt_save_fallback_name
    lea rdi,[rel ramblk_optional_dev]
    call opt_read_sector
    mov [rel opt_pre_rc],eax
    test eax,eax
    jnz .observed_bad
    xor eax,eax
    pop rbx
    ret
.observed_bad:
    mov dword [rel ramblk_optional_dev+dev.health],HEALTH_DEGRADED
    mov dword [rel opt_state],4
.bad:
    mov eax,-1
    pop rbx
    ret

; Actual failure enters the same blk_read vtable dispatch as ordinary I/O.
; Once failure is observed the medium becomes degraded and class selection
; skips it. The fallback is the actual current selector, not a configured name.
optional_fault_inject:
    push rbx
    call opt_nonce_match
    test eax,eax
    jnz .bad
    cmp dword [rel opt_state],1
    jne .bad
    lea rdi,[rel ramblk_optional_dev]
    call ramblk_wedge
    lea rdi,[rel ramblk_optional_dev]
    call opt_read_sector
    mov [rel opt_fault_rc],eax
    cmp eax,-1
    jne .observed_bad
    mov dword [rel ramblk_optional_dev+dev.health],HEALTH_DEGRADED
    mov dword [rel opt_state],2
    call blk_select
    test rax,rax
    jz .ok                              ; truthful unavailable alternate
    lea rcx,[rel ramblk_optional_dev]
    cmp rax,rcx
    je .observed_bad
    mov rbx,rax
    mov rdi,[rbx+dev.name]
    call opt_save_fallback_name
    mov rdx,[rbx+dev.info]
    mov rax,[rdx+blk_info.media_generation]
    mov [rel opt_fallback_generation],rax
    mov eax,[rdx+blk_info.logical_sector_bytes]
    test eax,eax
    jnz .size
    mov eax,[rdx+blk_info.sector_size]
.size:
    cmp eax,4096
    ja .ok                              ; no oversize read into the private page
    mov [rel opt_fallback_bytes],eax
    mov rdi,rbx
    call opt_read_sector
    mov [rel opt_fallback_rc],eax
.ok:
    xor eax,eax
    pop rbx
    ret
.observed_bad:
    mov dword [rel opt_state],4
.bad:
    mov eax,-1
    pop rbx
    ret

optional_fault_status:
    cmp dword [rel opt_state],0
    je opt_nonce_valid.bad
    jmp opt_nonce_match

optional_fault_reset:
    push rbx
    call opt_nonce_match
    test eax,eax
    jnz .bad
    cmp dword [rel opt_state],2
    je .reset
    cmp dword [rel opt_state],4
    jne .bad
.reset:
    lea rdi,[rel ramblk_optional_dev]
    call blk_identify
    test eax,eax
    jnz .bad
    ; Successful identify reopens class dispatch for the verification read.
    ; A failed verification immediately restores degraded state.
    mov dword [rel ramblk_optional_dev+dev.health],HEALTH_OK
    lea rdi,[rel ramblk_optional_dev]
    call opt_read_sector
    mov [rel opt_reset_rc],eax
    test eax,eax
    jnz .degraded
    mov dword [rel ramblk_optional_dev+dev.health],HEALTH_OK
    mov dword [rel opt_state],3
    xor eax,eax
    pop rbx
    ret
.degraded:
    mov dword [rel ramblk_optional_dev+dev.health],HEALTH_DEGRADED
.bad:
    mov eax,-1
    pop rbx
    ret

; Live health projection, never a PBMH/Ready write or promotion authority.
optional_fault_health:
    mov eax,HEALTH_DEAD
    cmp byte [rel opt_created],1
    jne .out
    mov eax,[rel ramblk_optional_dev+dev.health]
.out:
    ret
opt_read_sector:
    xor esi,esi
    mov edx,1
    lea rcx,[rel opt_buffer]
    jmp blk_read
opt_save_fallback_name:
    lea rdx,[rel opt_fallback_name]
    xor ecx,ecx
    test rdi,rdi
    jz .done
.copy:
    mov al,[rdi+rcx]
    test al,al
    jz .done
    cmp ecx,31
    jae .done
    mov [rdx+rcx],al
    inc ecx
    jmp .copy
.done:
    mov byte [rdx+rcx],0
    ret

cmd_opt_prepare:
    call cmd_handler_prologue
    lea rax,[rel optional_fault_prepare]
    jmp cmd_opt_owner
cmd_opt_fault:
    call cmd_handler_prologue
    lea rax,[rel optional_fault_inject]
    jmp cmd_opt_owner
cmd_opt_stat:
    call cmd_handler_prologue
    lea rax,[rel optional_fault_status]
    jmp cmd_opt_common
cmd_opt_reset:
    call cmd_handler_prologue
    lea rax,[rel optional_fault_reset]
    jmp cmd_opt_owner
; RAX=operation. This request and its in-flight ticket, never ambient principal state.
cmd_opt_owner:
    push rax
    call command_auth_ticket_owner
    cmp eax,1
    pop rax
    je cmd_opt_common
    mov qword [rsi+RSP_CODE],CMDE_AUTHDENY
    ret
cmd_opt_common:
    push rbx
    push r12
    push r13
    mov rbx,rdi
    mov r12,rsi
    mov r13,rax
    mov rdi,[rbx+REQ_ARG]
    call r13
    mov qword [r12+RSP_CODE],CMDE_OK
    test eax,eax
    jz .format
    mov qword [r12+RSP_CODE],CMDE_BADARG
.format:
    call command_auth_out_reset
    lea rdi,[rel str_opt_wire]
    call opt_out_str
    lea rdi,[rel opt_nonce]
    call opt_out_str
    lea rdi,[rel str_opt_epoch]
    call opt_out_str
    mov rdi,[rel opt_epoch]
    call opt_out_dec
    lea rdi,[rel str_opt_generation]
    call opt_out_str
    mov rax,[rel ramblk_optional_dev+dev.info]
    xor edi,edi
    test rax,rax
    jz .generation
    mov rdi,[rax+blk_info.media_generation]
.generation:
    call opt_out_dec
    lea rdi,[rel str_opt_state]
    call opt_out_str
    mov edi,[rel opt_state]
    call opt_out_dec
    lea rdi,[rel str_opt_health]
    call opt_out_str
    call optional_fault_health
    mov edi,eax
    call opt_out_dec
    lea rdi,[rel str_opt_pre]
    call opt_out_str
    mov edi,[rel opt_pre_rc]
    call opt_out_dec
    lea rdi,[rel str_opt_failed]
    call opt_out_str
    mov edi,[rel opt_fault_rc]
    call opt_out_dec
    lea rdi,[rel str_opt_fallback]
    call opt_out_str
    lea rdi,[rel opt_fallback_name]
    call opt_out_str
    lea rdi,[rel str_opt_fallback_rc]
    call opt_out_str
    mov edi,[rel opt_fallback_rc]
    call opt_out_dec
    lea rdi,[rel str_opt_fallback_generation]
    call opt_out_str
    mov rdi,[rel opt_fallback_generation]
    call opt_out_dec
    lea rdi,[rel str_opt_fallback_bytes]
    call opt_out_str
    mov edi,[rel opt_fallback_bytes]
    call opt_out_dec
    lea rdi,[rel str_opt_reset_rc]
    call opt_out_str
    mov edi,[rel opt_reset_rc]
    call opt_out_dec
    mov rax,[rbx+REQ_ARG]
    mov [r12+RSP_VAL],rax
    mov byte [rel command_auth_out_ready],1
    pop r13
    pop r12
    pop rbx
    ret
opt_out_str:
    mov rsi,[rel command_auth_out_cur]
.copy:
    mov al,[rdi]
    mov [rsi],al
    test al,al
    jz .done
    inc rdi
    inc rsi
    jmp .copy
.done:
    mov [rel command_auth_out_cur],rsi
    ret
opt_out_dec:
    mov rsi,[rel command_auth_out_cur]
    call fmt_dec
    add [rel command_auth_out_cur],rax
    ret

str_opt_prep: db 'OPTPREP',0
str_opt_fault: db 'OPTFAULT',0
str_opt_stat: db 'OPTSTAT',0
str_opt_reset: db 'OPTRESET',0
str_opt_none: db 'none',0
str_opt_wire: db ' opt_schema=1 opt_device=optblk opt_kind=ram opt_nonce=',0
str_opt_epoch: db ' opt_epoch=',0
str_opt_generation: db ' opt_generation=',0
str_opt_state: db ' opt_state=',0
str_opt_health: db ' opt_health=',0
str_opt_pre: db ' pre_rc=',0
str_opt_failed: db ' fault_rc=',0
str_opt_fallback: db ' fallback=',0
str_opt_fallback_rc: db ' fallback_rc=',0
str_opt_fallback_generation: db ' fallback_generation=',0
str_opt_fallback_bytes: db ' fallback_bytes=',0
str_opt_reset_rc: db ' reset_rc=',0
opt_epoch: dq 0
opt_state: dd 0
opt_pre_rc: dd OPT_UNOBSERVED
opt_fault_rc: dd OPT_UNOBSERVED
opt_fallback_rc: dd OPT_UNOBSERVED
opt_reset_rc: dd OPT_UNOBSERVED
opt_fallback_generation: dq 0
opt_fallback_bytes: dd 0
opt_created: db 0
opt_nonce: times 25 db 0
opt_fallback_name: db 'none',0
    times 27 db 0
align 16
opt_buffer: times 4096 db 0
