;; MODULE cognition/router_meter_text
;; LAYER 4
;; EXPORTS cog_router_meter_text
;; IMPORTS cognition/router_meter, core/lib/fmt
;; CAPS
;; OWNER saga:cognition
; RCQ51 callable text projection for a future meter UI. No production caller,
; dispatch, input, provider, model, I/O or authority. Reuse the actual reducer;
; never accept an unvalidated client-supplied aggregate as measurements.
; RDI=immutable native attempts[count*128], RSI=count1..8, RDX=out384.
; Trusted mapped/disjoint buffers, serialized native records, DF clear.
; EAX=0 success,1 invalid/range/identity/order,2 aggregate overflow; EDX=length
; excluding NUL (zero on refusal). Output unchanged on refusal; success writes
; exactly length+1 bytes and leaves the rest alone. All480 scratch bytes wiped.
; Selected tiers are selections, last_attempt_state is not logical task success;
; unknown token dimensions show partial amounts, never invented known totals.
cog_router_meter_text:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,480                     ; native snapshot96 + private text384
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    test r12,r12
    jz .invalid
    test r14,r14
    jz .invalid
    cmp r13,1
    jb .invalid
    cmp r13,8
    ja .invalid
    mov r8,r13
    shl r8,7
    add r8,r12
    jc .invalid
    mov r9,r14
    add r9,384
    jc .invalid
    cmp r12,r9
    jae .ranges
    cmp r14,r8
    jb .invalid
.ranges:
    mov rdx,rsp
    call cog_router_task_meter
    mov ebx,eax
    test eax,eax
    jnz .refused
    lea r15,[rsp+96]
    lea rdi,[rel cmt_task]
    call .literal
    mov rdi,[rsp+8]
    call .number
    lea rdi,[rel cmt_attempts]
    call .literal
    mov rdi,[rsp+16]
    call .number
    lea rdi,[rel cmt_epoch]
    call .literal
    mov rdi,[rsp+24]
    call .number
    lea rdi,[rel cmt_state]
    call .literal
    mov rax,[rsp+32]
    shl rax,4
    lea rdi,[rel cmt_states]
    add rdi,rax
    call .literal
    lea rdi,[rel cmt_selected]
    call .literal
    xor r12d,r12d
    xor ebx,ebx
.tier:
    mov rax,[rsp+80]
    bt rax,r12
    jnc .next_tier
    test ebx,ebx
    jz .tier_name
    lea rdi,[rel cmt_comma]
    call .literal
.tier_name:
    mov rax,r12
    shl rax,4
    lea rdi,[rel cmt_tiers]
    add rdi,rax
    call .literal
    mov ebx,1
.next_tier:
    inc r12d
    cmp r12d,5
    jb .tier
    test ebx,ebx
    jnz .input
    lea rdi,[rel cmt_none]
    call .literal
.input:
    lea rdi,[rel cmt_input]
    call .literal
    test qword [rsp+48],1
    jnz .input_number
    lea rdi,[rel cmt_unknown]
    call .literal
.input_number:
    mov rdi,[rsp+56]
    call .number
    test qword [rsp+48],1
    jnz .output
    lea rdi,[rel cmt_close]
    call .literal
.output:
    lea rdi,[rel cmt_output]
    call .literal
    test qword [rsp+48],2
    jnz .output_number
    lea rdi,[rel cmt_unknown]
    call .literal
.output_number:
    mov rdi,[rsp+64]
    call .number
    test qword [rsp+48],2
    jnz .egress
    lea rdi,[rel cmt_close]
    call .literal
.egress:
    lea rdi,[rel cmt_egress]
    call .literal
    mov rdi,[rsp+72]
    call .number
    lea rdi,[rel cmt_privacy]
    call .literal
    mov rax,[rsp+40]
    shl rax,4
    lea rdi,[rel cmt_privacies]
    add rdi,rax
    call .literal
    lea rsi,[rsp+96]
    mov r13,r15
    sub r13,rsi
    mov rcx,r13
    inc rcx
    mov rdi,r14
    rep movsb
    xor ebx,ebx
    jmp .wipe
.invalid:
    mov ebx,1
.refused:
    xor r13d,r13d
.wipe:
    mov rdi,rsp
    mov ecx,60
    xor eax,eax
    rep stosq
    mov eax,ebx
    mov edx,r13d
    add rsp,480
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.literal:
    sub rsp,8
    mov rsi,r15
    call fmt_str
    add r15,rax
    add rsp,8
    ret
.number:
    sub rsp,8
    mov rsi,r15
    call fmt_dec
    add r15,rax
    add rsp,8
    ret

; Constants only. Longest literal/state/tier/privacy and u64 widths give an
; intentionally conservative bound: 9 literal labels below, 6*20 numeric,
; 2*(16 unknown wrapper), 9 state, 38 tier names/commas, 8 privacy = <384.
cmt_task: db 'router task=',0
cmt_attempts: db ' attempts=',0
cmt_epoch: db ' last_epoch=',0
cmt_state: db ' last_attempt_state=',0
cmt_selected: db ' selected_tiers=',0
cmt_input: db ' input_tokens=',0
cmt_output: db ' output_tokens=',0
cmt_egress: db ' egress_bytes=',0
cmt_privacy: db ' privacy=',0
cmt_comma: db ',',0
cmt_none: db 'none',0
cmt_unknown: db 'unknown(partial=',0
cmt_close: db ')',0
cmt_states:
    db 'planned',0
    times 16-($-cmt_states) db 0
    db 'running',0
    times 32-($-cmt_states) db 0
    db 'complete',0
    times 48-($-cmt_states) db 0
    db 'cancelled',0
    times 64-($-cmt_states) db 0
    db 'failed',0
    times 80-($-cmt_states) db 0
    db 'refused',0
    times 96-($-cmt_states) db 0
cmt_tiers:
    db 'recipe',0
    times 16-($-cmt_tiers) db 0
    db 'rule',0
    times 32-($-cmt_tiers) db 0
    db 'classifier',0
    times 48-($-cmt_tiers) db 0
    db 'local',0
    times 64-($-cmt_tiers) db 0
    db 'cloud',0
    times 80-($-cmt_tiers) db 0
cmt_privacies:
    db 'public',0
    times 16-($-cmt_privacies) db 0
    db 'personal',0
    times 32-($-cmt_privacies) db 0
    db 'unknown',0
    times 48-($-cmt_privacies) db 0
