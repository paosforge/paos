;; MODULE svc/command_tls13_probe
;; LAYER 5
;; EXPORTS command_tls13_probe_init
;; IMPORTS core/capability, core/lib/fmt, net/tls13, svc/command, svc/command_tls13
;; CAPS
;; OWNER saga:net
; Same ordinary TLS engine, no trust/root/owner exception. TLSOBS is a bounded
; public-data copy; TLSCLOSE can retire only the exact ordinary attempt epoch.
; Normal registry owner authorization and PMCAP_NET apply to both text verbs.
; Do not extend TLSSTAT: the retained HOOK parser has an exact status grammar.

command_tls13_probe_init:
    lea rdi, [rel tlsp_verb_obs]
    lea rsi, [rel tlsp_cmd_obs]
    mov edx, PMCAP_NET
    mov ecx, ARGT_TEXT
    xor r8d, r8d
    xor r9d, r9d
    call command_register_verb
    cmp eax, -1
    je .out
    lea rdi, [rel tlsp_verb_close]
    lea rsi, [rel tlsp_cmd_close]
    mov edx, PMCAP_NET
    mov ecx, ARGT_TEXT
    xor r8d, r8d
    xor r9d, r9d
    call command_register_verb
.out:
    ret

; RDI exact 16 lowercase hex nonce, first nibble a..f, then NUL. The request
; already supplies a bounded NUL text argument through command's normal parser.
tlsp_nonce:
    cmp byte [rdi], 'a'
    jb .bad
    cmp byte [rdi], 'f'
    ja .bad
    xor ecx, ecx
.loop:
    mov al, [rdi+rcx]
    cmp al, '0'
    jb .bad
    cmp al, '9'
    jbe .copy
    cmp al, 'a'
    jb .bad
    cmp al, 'f'
    ja .bad
.copy:
    lea rdx, [rel tlsp_nonce_buf]
    mov [rdx+rcx], al
    inc ecx
    cmp ecx, 16
    jb .loop
    cmp byte [rdi+16], 0
    jne .bad
    mov byte [rdx+16], 0
    xor eax, eax
    ret
.bad:
    mov rax, -1
    ret

tlsp_reset:
    lea rax, [rel tls13_cmd_out_buf]
    mov [rel tlsp_cur], rax
    mov byte [rax], 0
    mov byte [rel tls13_cmd_out_ready], 0
    mov byte [rel tlsp_overflow], 0
    ret

; All output appends reserve the final NUL. Integer conversion stays in core fmt.
tlsp_text:
    mov rsi, [rel tlsp_cur]
    lea rdx, [rel tls13_cmd_out_buf+1023]
.loop:
    mov al, [rdi]
    test al, al
    jz .done
    cmp rsi, rdx
    jae .full
    mov [rsi], al
    inc rsi
    inc rdi
    jmp .loop
.full:
    mov byte [rel tlsp_overflow], 1
.done:
    mov byte [rsi], 0
    mov [rel tlsp_cur], rsi
    ret

tlsp_u64:
    lea rsi, [rel tlsp_number]
    call fmt_dec
    lea rdi, [rel tlsp_number]
    jmp tlsp_text

; Table-anchored signed rel32 label, reserved dword, offset and width.
; No stored absolute pointers: the org-0 image is relocated by firmware.
; Entries remain 16 bytes; the scratch accessor is 288B.
tlsp_field:
    push rbx
    mov rbx, rdi
    lea rdi, [rel tlsp_fields]
    movsxd rax, dword [rbx]
    add rdi, rax
    call tlsp_text
    lea rax, [rel tlsp_snapshot]
    mov ecx, [rbx+8]
    add rax, rcx
    mov edx, [rbx+12]
    cmp edx, 8
    je .qword
    cmp edx, 4
    je .dword
    cmp edx, 2
    je .word
    movzx edi, byte [rax]
    jmp .emit
.word:
    movzx edi, word [rax]
    jmp .emit
.dword:
    mov edi, [rax]
    jmp .emit
.qword:
    mov rdi, [rax]
.emit:
    call tlsp_u64
    pop rbx
    ret

tlsp_publish:
    cmp byte [rel tlsp_overflow], 0
    jne .bad
    lea rdi, [rel tlsp_crlf]
    call tlsp_text
    cmp byte [rel tlsp_overflow], 0
    jne .bad
    mov byte [rel tls13_cmd_out_ready], 1
    xor eax, eax
    ret
.bad:
    mov byte [rel tls13_cmd_out_ready], 0
    mov byte [rel tls13_cmd_out_buf], 0
    mov rax, -1
    ret

tlsp_cmd_obs:
    call cmd_handler_prologue
    push rbx
    push r12
    mov rbx, rsi
    mov r12, [rdi+REQ_ARG]
    call tlsp_reset
    test r12, r12
    jz .bad
    mov rdi, r12
    call tlsp_nonce
    test rax, rax
    jnz .bad
    lea rdi, [rel tlsp_snapshot]
    mov esi, 288
    call tls13_observe
    test rax, rax
    jnz .unavailable
    cmp dword [rel tlsp_snapshot], 1
    jne .unavailable
    cmp dword [rel tlsp_snapshot+4], 288
    jne .unavailable
    movzx ecx, word [rel tlsp_snapshot+30]
    cmp ecx, 200
    ja .unavailable
    lea rdx, [rel tlsp_snapshot+80]
    cmp byte [rdx+rcx], 0
    jne .unavailable
    xor eax, eax
.name:
    cmp eax, ecx
    jae .valid
    mov sil, [rdx+rax]
    cmp sil, '.'
    je .next
    cmp sil, '-'
    je .next
    cmp sil, '0'
    jb .unavailable
    cmp sil, '9'
    jbe .next
    cmp sil, 'a'
    jb .unavailable
    cmp sil, 'z'
    ja .unavailable
.next:
    inc eax
    jmp .name
.valid:
    lea rdi, [rel tlsp_obs_prefix]
    call tlsp_text
    lea rdi, [rel tlsp_nonce_buf]
    call tlsp_text
    lea rdi, [rel tlsp_available]
    call tlsp_text
    lea r12, [rel tlsp_fields]
.fields:
    cmp qword [r12], 0
    je .ip
    mov rdi, r12
    call tlsp_field
    add r12, 16
    jmp .fields
.ip:
    lea rdi, [rel tlsp_ip]
    call tlsp_text
    xor r12d, r12d
.ip_byte:
    lea rax, [rel tlsp_snapshot+24]
    movzx edi, byte [rax+r12]
    call tlsp_u64
    inc r12d
    cmp r12d, 4
    je .sni
    lea rdi, [rel tlsp_dot]
    call tlsp_text
    jmp .ip_byte
.sni:
    lea rdi, [rel tlsp_sni]
    call tlsp_text
    lea rdi, [rel tlsp_snapshot+80]
    cmp byte [rdi], 0
    jne .name_emit
    lea rdi, [rel tlsp_dash]
.name_emit:
    call tlsp_text
    lea rdi, [rel tlsp_leaf]
    call tlsp_text
    xor r12d, r12d
.hash:
    lea rax, [rel tlsp_snapshot+48]
    movzx edi, byte [rax+r12]
    ; Canonical core formatter, exactly two hex digits per actual leaf byte.
    lea rsi, [rel tlsp_number]
    mov edx, 2
    call fmt_hex
    lea rdi, [rel tlsp_number]
    call tlsp_text
    inc r12d
    cmp r12d, 32
    jb .hash
    jmp .finish
.unavailable:
    lea rdi, [rel tlsp_obs_prefix]
    call tlsp_text
    lea rdi, [rel tlsp_nonce_buf]
    call tlsp_text
    lea rdi, [rel tlsp_unavailable]
    call tlsp_text
.finish:
    call tlsp_publish
    test rax, rax
    jnz .bad
    mov qword [rbx+RSP_CODE], CMDE_OK
    jmp .out
.bad:
    mov byte [rel tls13_cmd_out_ready], 0
    mov qword [rbx+RSP_CODE], CMDE_BADARG
.out:
    pop r12
    pop rbx
    ret

; Nonzero canonical decimal u64 then one space and nonce. Overflow is refused
; before calling the engine. This parser cannot retire an arbitrary old epoch.
tlsp_cmd_close:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov rbx, rsi
    mov r12, [rdi+REQ_ARG]
    call tlsp_reset
    test r12, r12
    jz .bad
    cmp byte [r12], '1'
    jb .bad
    cmp byte [r12], '9'
    ja .bad
    xor r13d, r13d
    mov r8d, 10
.digit:
    movzx ecx, byte [r12]
    cmp ecx, ' '
    je .nonce
    sub ecx, '0'
    cmp ecx, 9
    ja .bad
    mov rax, r13
    mul r8
    test rdx, rdx
    jnz .bad
    add rax, rcx
    jc .bad
    mov r13, rax
    inc r12
    jmp .digit
.nonce:
    lea rdi, [r12+1]
    call tlsp_nonce
    test rax, rax
    jnz .bad
    mov rdi, r13
    call tls13_close_attempt
    test rax, rax
    jz .closed
    cmp eax, -1
    je .refused
    cmp eax, -2
    jne .bad
    mov r12d, 2
    jmp .stage
.refused:
    mov r12d, 1
    jmp .stage
.closed:
    xor r12d, r12d
.stage:
    lea rdi, [rel tlsp_close_prefix]
    call tlsp_text
    lea rdi, [rel tlsp_nonce_buf]
    call tlsp_text
    lea rdi, [rel tlsp_attempt]
    call tlsp_text
    mov rdi, r13
    call tlsp_u64
    lea rdi, [rel tlsp_result]
    call tlsp_text
    mov edi, r12d
    call tlsp_u64
    call tlsp_publish
    test rax, rax
    jnz .bad
    test r12d, r12d
    jnz .refusal_code
    mov qword [rbx+RSP_ACCEPTED], 1
    mov qword [rbx+RSP_CODE], CMDE_OK
    jmp .out
.refusal_code:
    mov qword [rbx+RSP_CODE], CMDE_BADARG
    jmp .out
.bad:
    mov byte [rel tls13_cmd_out_ready], 0
    mov qword [rbx+RSP_CODE], CMDE_BADARG
.out:
    pop r13
    pop r12
    pop rbx
    ret

align 8
tlsp_snapshot: times 288 db 0
tlsp_cur: dq 0
tlsp_overflow: db 0
tlsp_nonce_buf: times 17 db 0
tlsp_number: times 32 db 0
tlsp_verb_obs: db "TLSOBS",0
tlsp_verb_close: db "TLSCLOSE",0
tlsp_obs_prefix: db " TLSOBS rev=1 nonce=",0
tlsp_close_prefix: db " TLSCLOSE rev=1 nonce=",0
tlsp_available: db " available=1",0
tlsp_unavailable: db " available=0",0
tlsp_ip: db " peer_ip=",0
tlsp_sni: db " sni=",0
tlsp_leaf: db " leaf_sha256=",0
tlsp_dot: db ".",0
tlsp_dash: db "-",0
tlsp_crlf: db 13,10,0
tlsp_attempt: db " attempt=",0
tlsp_result: db " result=",0
tlsp_policy_utc: db " policy_utc=",0
tlsp_peer_port: db " peer_port=",0
tlsp_policy_reason: db " policy_reason=",0
tlsp_state: db " state=",0
tlsp_error: db " error=",0
tlsp_established: db " established=",0
tlsp_cert_verified: db " cert_verified=",0
tlsp_chain_ok: db " chain_ok=",0
tlsp_certverify_ok: db " certverify_ok=",0
tlsp_finished_ok: db " finished_ok=",0
tlsp_trust_path: db " trust_path=",0
tlsp_policy_ok: db " policy_ok=",0
tlsp_app_owned: db " app_owned=",0
tlsp_tcb_present: db " tcb_present=",0
align 8
tlsp_fields:
    dd tlsp_attempt - tlsp_fields, 0
    dd 8, 8
    dd tlsp_policy_utc - tlsp_fields, 0
    dd 16, 8
    dd tlsp_peer_port - tlsp_fields, 0
    dd 28, 2
    dd tlsp_policy_reason - tlsp_fields, 0
    dd 32, 4
    dd tlsp_state - tlsp_fields, 0
    dd 36, 1
    dd tlsp_error - tlsp_fields, 0
    dd 37, 1
    dd tlsp_established - tlsp_fields, 0
    dd 38, 1
    dd tlsp_cert_verified - tlsp_fields, 0
    dd 39, 1
    dd tlsp_chain_ok - tlsp_fields, 0
    dd 40, 1
    dd tlsp_certverify_ok - tlsp_fields, 0
    dd 41, 1
    dd tlsp_finished_ok - tlsp_fields, 0
    dd 42, 1
    dd tlsp_trust_path - tlsp_fields, 0
    dd 43, 1
    dd tlsp_policy_ok - tlsp_fields, 0
    dd 44, 1
    dd tlsp_app_owned - tlsp_fields, 0
    dd 45, 1
    dd tlsp_tcb_present - tlsp_fields, 0
    dd 46, 1
    dq 0
