;; MODULE svc/command_fs_unsupported
;; LAYER 5
;; OWNER saga:fs_wave
; Included by command_fs. Pure bounded lookup of actual ext discovery refusals.
; No scan trigger, IO, mount, arm, writer or authority operation.
cmd_verb_extrefusal:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    call cmd_handler_prologue
    mov r12,rdi
    mov r13,rsi
    mov rdi,[r12+REQ_ARG]
    test rdi,rdi
    jz .bad
    xor ecx,ecx
.bound:
    cmp ecx,104
    jae .bad
    cmp byte [rdi+rcx],0
    je .tokens
    inc ecx
    jmp .bound
.tokens:
    call fs_tokenize
    cmp dword [rel fs_tok_count],3
    jne .bad
    mov eax,[rel fs_tok_len]
    test eax,eax
    jz .bad
    cmp eax,FS_INFO_DEV_NAME_MAX
    ja .bad
    mov rdi,[rel fs_tok_ptr+16]
    mov esi,[rel fs_tok_len+8]
    call fs_nonce_valid
    test eax,eax
    jz .bad
    mov rdi,[rel fs_tok_ptr+8]
    mov esi,[rel fs_tok_len+4]
    cmp esi,1
    jbe .decimal
    cmp byte [rdi],'0'
    je .bad
.decimal:
    call fsntfs_parse_u64
    test edx,edx
    jnz .bad
    mov r15,rax
    xor r14d,r14d
    xor ebp,ebp
.device:
    inc ebp
    cmp ebp,FS_INFO_DEV_SCAN_MAX
    ja .bad
    mov rdi,r14
    xor esi,esi
    xor edx,edx
    call blk_iter_after
    test rax,rax
    jz .bad
    mov r14,rax
    mov rdi,[rax+dev.name]
    test rdi,rdi
    jz .device
    mov rsi,[rel fs_tok_ptr]
    mov ecx,[rel fs_tok_len]
.name:
    mov al,[rsi]
    cmp al,[rdi]
    jne .device
    inc rdi
    inc rsi
    dec ecx
    jnz .name
    cmp byte [rdi],0
    jne .device
    mov rdi,r14
    mov rsi,r15
    call ext4_refusal_lookup
    mov rbx,rax
    call fs_out_reset
    lea rdi,[rel extr_head]
    call fs_out_str
    mov rdi,[rel fs_tok_ptr+16]
    mov esi,16
    call fs_out_token
    lea rdi,[rel extr_dev]
    call fs_out_str
    mov rdi,[rel fs_tok_ptr]
    mov esi,[rel fs_tok_len]
    call fs_out_token
    lea rdi,[rel extr_lba]
    call fs_out_str
    mov rdi,r15
    call fs_out_dec
    lea rdi,[rel extr_missing]
    test rbx,rbx
    jz .status
    lea rdi,[rel extr_refused]
.status:
    call fs_out_str
    lea rdi,[rel extr_reason]
    call fs_out_str
    xor edi,edi
    test rbx,rbx
    jz .reason
    mov edi,[rbx+24]
.reason:
    call fs_out_dec
    lea rdi,[rel extr_incompat]
    call fs_out_str
    xor edi,edi
    test rbx,rbx
    jz .incompat
    mov edi,[rbx+28]
.incompat:
    call fs_out_dec
    lea rdi,[rel extr_gen]
    call fs_out_str
    mov rax,[r14+dev.info]
    xor edi,edi
    test rax,rax
    jz .gen
    mov rdi,[rax+blk_info.media_generation]
.gen:
    call fs_out_dec
    lea rdi,[rel extr_saved_gen]
    call fs_out_str
    xor edi,edi
    test rbx,rbx
    jz .saved_gen
    mov rdi,[rbx+16]
.saved_gen:
    call fs_out_dec
    lea rdi,[rel extr_overflow]
    call fs_out_str
    movzx edi,byte [rel ext4_refusal_overflow]
    call fs_out_dec
    lea rdi,[rel extr_conflict]
    call fs_out_str
    movzx edi,byte [rel ext4_refusal_conflict]
    call fs_out_dec
    lea rdi,[rel extr_epoch]
    call fs_out_str
    mov rdi,[rel ext4_refusal_epoch]
    call fs_out_dec
    call fs_finish
    jmp .out
.bad:
    call fs_out_reset
    lea rdi,[rel extr_bad]
    call fs_out_str
    call fs_finish
    mov qword [r13+RSP_CODE],CMDE_BADARG
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
extr_name: db 'EXTREFUSAL',0
extr_head: db 'EXTREFUSAL V=1 NONCE=',0
extr_dev: db ' DEV=',0
extr_lba: db ' LBA=',0
extr_missing: db ' STATUS=UNOBSERVED',0
extr_refused: db ' STATUS=REFUSED',0
extr_reason: db ' REASON=',0
extr_incompat: db ' INCOMPAT=',0
extr_gen: db ' MEDIA_GENERATION=',0
extr_saved_gen: db ' RECORDED_MEDIA_GENERATION=',0
extr_overflow: db ' OVERFLOW=',0
extr_conflict: db ' CONFLICT=',0
extr_epoch: db ' EPOCH=',0
extr_bad: db 'EXTREFUSAL ERR bad_args',0

; RAX is the actual exact-selector return. Expose its parser stage only for
; a selection refusal; auth/busy never inherit a previous parser result.
fs_ntfs_refusal:
    push rbx
    mov rbx,rax
    call fs_out_reset
    lea rdi,[rel ntref_head]
    call fs_out_str
    mov rdi,[rel fs_tok_ptr+24]
    mov esi,16
    call fs_out_token
    lea rdi,[rel ntref_selection]
    cmp rbx,-2
    jne .auth
    lea rdi,[rel ntref_busy]
.auth:
    cmp rbx,-3
    jne .reason
    lea rdi,[rel ntref_auth]
.reason:
    call fs_out_str
    lea rdi,[rel ntref_stage]
    call fs_out_str
    xor edi,edi
    cmp rbx,-1
    jne .emit
    call ntfs_disk_refusal_stage
    mov edi,eax
.emit:
    call fs_out_dec
    call fs_finish
    mov [r13+RSP_VAL],rbx
    mov qword [r13+RSP_CODE],CMDE_BADSEL
    cmp rbx,-3
    jne .out
    mov qword [r13+RSP_CODE],CMDE_AUTHDENY
.out:
    pop rbx
    ret
ntref_head: db 'FSNTFS NONCE=',0
ntref_selection: db ' ERR=selection',0
ntref_busy: db ' ERR=busy',0
ntref_auth: db ' ERR=auth',0
ntref_stage: db ' STAGE=',0

; exFAT counterpart: original pre-parser identities remain observable when stale.
cmd_verb_exfrefusal:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    call cmd_handler_prologue
    mov r12,rdi
    mov r13,rsi
    mov rdi,[r12+REQ_ARG]
    test rdi,rdi
    jz .bad
    xor ecx,ecx
.bound:
    cmp ecx,104
    jae .bad
    cmp byte [rdi+rcx],0
    je .tokens
    inc ecx
    jmp .bound
.tokens:
    call fs_tokenize
    cmp dword [rel fs_tok_count],3
    jne .bad
    mov eax,[rel fs_tok_len]
    test eax,eax
    jz .bad
    cmp eax,FS_INFO_DEV_NAME_MAX
    ja .bad
    mov rdi,[rel fs_tok_ptr+16]
    mov esi,[rel fs_tok_len+8]
    call fs_nonce_valid
    test eax,eax
    jz .bad
    mov rdi,[rel fs_tok_ptr+8]
    mov esi,[rel fs_tok_len+4]
    cmp esi,1
    jbe .decimal
    cmp byte [rdi],'0'
    je .bad
.decimal:
    call fsntfs_parse_u64
    test edx,edx
    jnz .bad
    mov r15,rax
    xor r14d,r14d
    xor ebp,ebp
.device:
    inc ebp
    cmp ebp,FS_INFO_DEV_SCAN_MAX
    ja .bad
    mov rdi,r14
    xor esi,esi
    xor edx,edx
    call blk_iter_after
    test rax,rax
    jz .bad
    mov r14,rax
    mov rdi,[rax+dev.name]
    test rdi,rdi
    jz .device
    mov rsi,[rel fs_tok_ptr]
    mov ecx,[rel fs_tok_len]
.name:
    mov al,[rsi]
    cmp al,[rdi]
    jne .device
    inc rdi
    inc rsi
    dec ecx
    jnz .name
    cmp byte [rdi],0
    jne .device
    mov rdi,r14
    mov rsi,r15
    call exfat_refusal_lookup
    mov rbx,rax
    call fs_out_reset
    lea rdi,[rel exfr_head]
    call fs_out_str
    mov rdi,[rel fs_tok_ptr+16]
    mov esi,16
    call fs_out_token
    lea rdi,[rel exfr_dev]
    call fs_out_str
    mov rdi,[rel fs_tok_ptr]
    mov esi,[rel fs_tok_len]
    call fs_out_token
    lea rdi,[rel exfr_lba]
    call fs_out_str
    mov rdi,r15
    call fs_out_dec
    lea rdi,[rel exfr_missing]
    test rbx,rbx
    jz .status
    lea rdi,[rel exfr_refused]
.status:
    call fs_out_str
    lea rdi,[rel exfr_reason]
    call fs_out_str
    xor edi,edi
    test rbx,rbx
    jz .reason
    mov edi,[rbx+48]
.reason:
    call fs_out_dec
    lea rdi,[rel exfr_extent]
    call fs_out_str
    xor edi,edi
    test rbx,rbx
    jz .extent
    mov rdi,[rbx+16]
.extent:
    call fs_out_dec
    lea rdi,[rel exfr_gen]
    call fs_out_str
    mov rax,[r14+dev.info]
    xor edi,edi
    test rax,rax
    jz .gen
    mov rdi,[rax+blk_info.media_generation]
.gen:
    call fs_out_dec
    lea rdi,[rel exfr_saved_gen]
    call fs_out_str
    xor edi,edi
    test rbx,rbx
    jz .saved_gen
    mov rdi,[rbx+24]
.saved_gen:
    call fs_out_dec
    lea rdi,[rel exfr_current]
    call fs_out_str
    xor edi,edi
    test rbx,rbx
    jz .current
    mov rax,[r14+dev.info]
    test rax,rax
    jz .current
    cmp rax,[rbx+32]
    jne .current
    mov rax,[r14+dev.ops]
    cmp rax,[rbx+40]
    jne .current
    mov rax,[r14+dev.info]
    mov rax,[rax+blk_info.media_generation]
    test rax,rax
    jz .current
    cmp rax,[rbx+24]
    jne .current
    mov edi,1
.current:
    call fs_out_dec
    lea rdi,[rel exfr_limited]
    call fs_out_str
    movzx edi,byte [rel exfat_refusal_scan_limited]
    call fs_out_dec
    lea rdi,[rel exfr_overflow]
    call fs_out_str
    movzx edi,byte [rel exfat_refusal_overflow]
    call fs_out_dec
    lea rdi,[rel exfr_conflict]
    call fs_out_str
    movzx edi,byte [rel exfat_refusal_conflict]
    call fs_out_dec
    lea rdi,[rel exfr_epoch]
    call fs_out_str
    mov rdi,[rel exfat_refusal_epoch]
    call fs_out_dec
    call fs_finish
    jmp .out
.bad:
    call fs_out_reset
    lea rdi,[rel exfr_bad]
    call fs_out_str
    call fs_finish
    mov qword [r13+RSP_CODE],CMDE_BADARG
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
exfr_name: db 'EXFREFUSAL',0
exfr_head: db 'EXFREFUSAL V=1 NONCE=',0
exfr_dev: db ' DEV=',0
exfr_lba: db ' LBA=',0
exfr_missing: db ' STATUS=UNOBSERVED',0
exfr_refused: db ' STATUS=REFUSED',0
exfr_reason: db ' REASON=',0
exfr_extent: db ' EXTENT=',0
exfr_gen: db ' MEDIA_GENERATION=',0
exfr_saved_gen: db ' RECORDED_MEDIA_GENERATION=',0
exfr_overflow: db ' OVERFLOW=',0
exfr_conflict: db ' CONFLICT=',0
exfr_epoch: db ' EPOCH=',0
exfr_current: db ' IDENTITY_CURRENT=',0
exfr_limited: db ' SCAN_LIMITED=',0
exfr_bad: db 'EXFREFUSAL ERR bad_args',0
