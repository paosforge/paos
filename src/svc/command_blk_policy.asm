;; MODULE svc/command_blk_policy
;; LAYER 5
;; OWNER saga:storage
; Included by command_blk.asm. BLKPOLICY dev 0x<16hex> <16lowerhexnonce>.
; Explicit IMPLICIT decision only, using the actual production gate decision.
; Actual request authority is printed separately. No grant/write/intent change.
cmd_verb_blkpolicy:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    call blk_arg_common
    test rax,rax
    jz .out
    mov rbx,rax
    ; Reject ambiguous prefix names accepted by the historical blk_find helper.
    mov rdi,[rel blk_tok_ptr]
    mov rsi,[rbx+dev.name]
    mov ecx,[rel blk_tok_len]
.name:
    test ecx,ecx
    jz .name_end
    mov al,[rdi]
    cmp al,[rsi]
    jne .bad
    inc rdi
    inc rsi
    dec ecx
    jmp .name
.name_end:
    cmp byte [rsi],0
    jne .bad
    cmp dword [rel blk_tok_len+4],18
    jne .bad
    mov rdi,[rel blk_tok_ptr+8]
    cmp word [rdi],'0x'
    jne .bad
    add rdi,2
    mov ecx,16
.lba:
    mov al,[rdi]
    call blk_policy_hex
    test eax,eax
    jz .bad
    inc rdi
    loop .lba
    cmp dword [rel blk_tok_len+8],16
    jne .bad
    mov rdi,[rel blk_tok_ptr+16]
    mov ecx,16
.nonce:
    mov al,[rdi]
    call blk_policy_hex
    test eax,eax
    jz .bad
    inc rdi
    loop .nonce
    mov rdi,[rel blk_tok_ptr+8]
    mov esi,18
    call blk_parse_u64
    mov r12,rax
    lea rdi,[rel blk_policy_head]
    call blk_out_str
    mov rdi,[rel blk_tok_ptr+16]
    ; Last token is exactly sixteen bytes followed by NUL (tokenize contract).
    call blk_out_str
    lea rdi,[rel blk_policy_dev]
    call blk_out_str
    mov rdi,[rbx+dev.name]
    call blk_out_str
    lea rdi,[rel blk_policy_lba]
    call blk_out_str
    mov rdi,r12
    call blk_out_dec
    lea rdi,[rel blk_policy_eval]
    call blk_out_str
    call storage_access_request_intent
    mov edi,eax
    call blk_out_dec
    lea rdi,[rel blk_policy_owner]
    call blk_out_str
    call storage_access_request_owner
    mov edi,eax
    call blk_out_dec
    mov rdi,rbx
    mov rsi,r12
    mov edx,1
    xor ecx,ecx                      ; evaluated intent is explicitly IMPLICIT
    call storage_access_decision
    mov r13d,r9d
    mov r14d,r10d
    lea rdi,[rel blk_policy_allowed]
    test rax,rax
    jz .decision
    lea rdi,[rel blk_policy_refused]
.decision:
    call blk_out_str
    lea rdi,[rel blk_policy_class]
    call blk_out_str
    mov edi,r13d
    call blk_out_dec
    lea rdi,[rel blk_policy_reason]
    call blk_out_str
    mov edi,r14d
    call blk_out_dec
    lea rdi,[rel blk_policy_generation]
    call blk_out_str
    mov rax,[rbx+dev.info]
    mov rdi,[rax+blk_info.media_generation]
    call blk_out_dec
    jmp .ready
.bad:
    lea rdi,[rel blk_policy_bad]
    call blk_out_str
.ready:
    mov byte [rel blk_out_ready],1
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
; AL -> EAX 1 iff lower-case hexadecimal; preserves the parsing loop registers.
blk_policy_hex:
    cmp al,'0'
    jb .no
    cmp al,'9'
    jbe .yes
    cmp al,'a'
    jb .no
    cmp al,'f'
    ja .no
.yes:
    mov eax,1
    ret
.no:
    xor eax,eax
    ret
blk_policy_head: db " BLK POLICY V=1 NONCE=",0
blk_policy_dev: db " dev=",0
blk_policy_lba: db " lba=",0
blk_policy_eval: db " count=1 mode=DECISION_ONLY evaluated_intent=0 request_intent=",0
blk_policy_owner: db " request_owner=",0
blk_policy_allowed: db " decision=ALLOWED",0
blk_policy_refused: db " decision=REFUSED",0
blk_policy_class: db " class=",0
blk_policy_reason: db " reason=",0
blk_policy_generation: db " media_generation=",0
blk_policy_bad: db " BLK POLICY ERR badargs",0
