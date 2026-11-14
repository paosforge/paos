;; MODULE cognition/ai_intent_controller
;; LAYER 6
;; EXPORTS cog_ai_intent_tick, cog_ai_intent_cancel, cog_ai_intent_snapshot, cog_ai_intent_command, cog_ai_intent_take_tap
;; IMPORTS cognition/ai_key_consumer, cognition/gpt2_engine, gui/input_route, sec/session, sec/principal, svc/command, svc/command_auth
;; CAPS PMCAP_COMPUTE
;; OWNER saga:cognition
; RCQ51 BSP idle join, after native input routing. Sole queue consumer, one
; per-boot intent state. Calls are serialized on BSP with native routing.
; Trusted native callers only: intents are neither authority nor mic readiness.
; Native Esc retires via the input cancellation counter. No rendering, provider or voice I/O.
;
; tick(): actual consumer, at most one ordinary pop; retirement may additionally
; drain <=8. A changed native session epoch also drains before any new pop.
; Records carry no session epoch: discard the entire boundary queue, including
; any fresh gesture queued before this drain; the next fresh gesture may start.
; cancel(): explicit trusted retirement, drain <=8. Same EAX as the
; consumer (0 empty,1 accepted,2 retired,3 invalid); no caller-supplied state.
; Discard the native record16 immediately on return, keep only intent/sequence.
cog_ai_intent_tick:
    mov qword [rel cai_tap_source],0   ; a launch edge lives for this idle turn only
    xor r8d,r8d
    jmp cog_ai_intent_cancel.enter
cog_ai_intent_cancel:
    mov qword [rel cai_tap_source],0
    mov r8d,1
.enter:
    sub rsp,24
    mov rax,[rel session_authority_epoch]
    mov [rsp],rax
    lea rdi,[rel cai_state]
    lea rsi,[rel cai_out]
    test r8d,r8d
    jnz .cancel
    cmp rax,[rel cai_epoch]
    jne .epoch_changed
    call cog_ai_key_poll
    jmp .finish
.epoch_changed:
    mov r8d,2
.cancel:
    mov [rsp+8],r8
    call cog_ai_key_retire
    cmp eax,2
    jne .finish                       ; bad state cannot acknowledge a boundary
    mov rdx,[rsp]
    mov [rel cai_epoch],rdx
    cmp qword [rsp+8],2
    jne .finish
    mov qword [rel cai_out+24],1       ; lock/session boundary, not an owner request
.finish:
    ; Keep only a bounded one-shot projection for the native app launcher.
    ; The original consumer remains the sole native queue reader. No timestamp,
    ; record pointer, synthetic event, voice action or provider call escapes.
    cmp eax,1
    jne .wipe
    cmp byte [rel cai_out],INPUT_AI_TAP
    jne .wipe
    cmp word [rel cai_out+2],0          ; actual owner origin + reserved zero
    jne .wipe
    movzx edx,byte [rel cai_out+1]
    cmp edx,INPUT_AI_SRC_COPILOT
    jb .wipe
    cmp edx,INPUT_AI_SRC_FALLBACK
    ja .wipe
    mov [rel cai_tap_source],rdx
    mov edx,[rel cai_out+4]
    mov [rel cai_tap_seq],rdx
.wipe:
    mov qword [rel cai_out],0
    mov qword [rel cai_out+8],0
    mov qword [rsp],0
    mov qword [rsp+8],0
    add rsp,24
    ret

; snapshot(RDI=out40 mapped/writable, DF clear) -> EAX 0 success,3 bad range.
; Five qwords: version1,request_bits(typed1/PTT2/handsfree4),reason,have_seq0/1,
; last_u32_seq. Reasons match consumer:0 ordinary,1 lock/session change,2 loss/cancel,
; 3 record/sequence,4 hold transition,5 explicit retirement. Not event replay.
; Read-only: no pop/state writes. Check actual lock/counters now, so stale
; intent/sequence is suppressed even before the next tick performs retirement.
; The actual session epoch catches a lock+unlock or rebind between polls. It
; grants no authority; native BSP calls do not yield during this bounded read.
; Null, wrapping or own-private overlapping output leaves all bytes unchanged.
; Other pointer validity is the trusted mapped caller's responsibility.
cog_ai_intent_snapshot:
    mov eax,3
    test rdi,rdi
    jz .return
    mov rdx,rdi
    add rdx,40
    jc .return
    lea rcx,[rel cai_private_end]
    cmp rdi,rcx
    jae .range_ok
    lea rcx,[rel cai_state]
    cmp rdx,rcx
    ja .return
.range_ok:
    mov r8,[rel cai_state+8]
    mov r9,[rel cai_out+24]
    mov r10,[rel cai_state+24]
    mov r11,[rel cai_state+16]
    mov rax,[rel session_authority_epoch]
    cmp rax,[rel cai_epoch]
    jne .session_changed
    cmp byte [rel session_locked],0
    jne .locked
    mov rax,[rel input_ai_dropped]
    cmp rax,[rel cai_state+32]
    jne .lost
    mov rax,[rel input_ai_cancelled]
    cmp rax,[rel cai_state+40]
    jne .lost
    jmp .publish
.session_changed:
.locked:
    mov r9d,1
    jmp .clear
.lost:
    mov r9d,2
.clear:
    xor r8d,r8d
    xor r10d,r10d
    xor r11d,r11d
.publish:
    mov qword [rdi],1
    mov [rdi+8],r8
    mov [rdi+16],r9
    mov [rdi+24],r10
    mov [rdi+32],r11
    xor eax,eax
.return:
    ret

; Native BSP depth-zero launcher only. Return 1 Copilot / 2 Win+Space /
; 0 absent or no longer current. Spend before checking actual session, lock,
; loss/cancellation and sequence through the original masked snapshot. This is
; an input edge, never a grant, command, guest API or persistent typed request.
; No second queue pop. An unused edge expires at the next tick or cancellation.
cog_ai_intent_take_tap:
    xor eax,eax
    xchg rax,[rel cai_tap_source]
    test rax,rax
    jz .out
    sub rsp,56
    mov [rsp+40],rax
    mov rdx,[rel cai_tap_seq]
    mov [rsp+48],rdx
    mov rdi,rsp
    call cog_ai_intent_snapshot
    test eax,eax
    jnz .bad
    cmp qword [rsp+24],1
    jne .bad
    test qword [rsp+8],1
    jz .bad
    mov rdx,[rsp+48]
    cmp [rsp+32],rdx
    jne .bad
    mov rax,[rsp+40]
    jmp .wipe
.bad:
    xor eax,eax
.wipe:
    xor edx,edx
    mov [rsp],rdx
    mov [rsp+8],rdx
    mov [rsp+16],rdx
    mov [rsp+24],rdx
    mov [rsp+32],rdx
    mov [rsp+40],rdx
    mov [rsp+48],rdx
    add rsp,56
.out:
    ret

; Exact MODELRUN INTENT, no arguments. Same native owner-ticket/live-compute
; floor as CLASSIFY; a hook cannot supply a principal or bypass these checks.
; Read the actual masked snapshot once. No pop/tick/cancel, raw event or time.
cog_ai_intent_command:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    sub rsp,48
    mov r12,rdi
    mov r13,rsi
    call cai_command_wipe
    mov ebx,CMDE_AUTHDENY
    mov rdi,r12
    call command_auth_ticket_owner
    test eax,eax
    jz .denied
    mov rdi,[r12+REQ_PRINCIPAL]
    call principal_capabilities
    test rax,PMCAP_COMPUTE
    jz .denied
    mov ebx,CMDE_BADARG
    mov rax,[r12+REQ_ARG]
    test rax,rax
    jz .bad
    lea rdx,[rel str_cai_command]
    xor ecx,ecx
.arg:
    mov r8b,[rax+rcx]
    cmp r8b,[rdx+rcx]
    jne .bad
    inc ecx
    cmp ecx,7
    jb .arg
    mov rdi,rsp
    call cog_ai_intent_snapshot
    test eax,eax
    jnz .bad
    cmp qword [rsp],1
    jne .bad
    cmp qword [rsp+8],7
    ja .bad
    cmp qword [rsp+16],5
    ja .bad
    cmp qword [rsp+24],1
    ja .bad
    mov eax,0xffffffff
    cmp [rsp+32],rax
    ja .bad
    lea rdi,[rel str_cai_reply]
    call cog_put_str
    mov rdi,[rsp+8]
    call cog_put_dec
    lea rdi,[rel str_cai_reason]
    call cog_put_str
    mov rdi,[rsp+16]
    call cog_put_dec
    lea rdi,[rel str_cai_have]
    call cog_put_str
    mov rdi,[rsp+24]
    call cog_put_dec
    lea rdi,[rel str_cai_seq]
    call cog_put_str
    mov rdi,[rsp+32]
    call cog_put_dec
    lea rdi,[rel str_cai_none]
    call cog_put_str
    mov rax,[rsp+8]
    mov [r13+RSP_VAL],rax
    mov qword [r13+RSP_CODE],CMDE_OK
    mov qword [r13+RSP_ACCEPTED],1
    jmp .ready
.denied:
    lea rdi,[rel str_cai_denied]
    jmp .refuse
.bad:
    lea rdi,[rel str_cai_bad]
.refuse:
    call cog_put_str
    mov [r13+RSP_CODE],rbx
    mov qword [r13+RSP_ACCEPTED],0
    mov qword [r13+RSP_VAL],0
.ready:
    mov byte [rel cog_out_ready],1
    xor eax,eax
    mov [rsp],rax
    mov [rsp+8],rax
    mov [rsp+16],rax
    mov [rsp+24],rax
    mov [rsp+32],rax
    mov [rsp+40],rax
    add rsp,48
    pop r13
    pop r12
    pop rbx
    ret

cai_command_wipe:
    lea rdi,[rel cog_out_buf]
    xor eax,eax
    mov ecx,384/8
    cld
    rep stosq
    mov byte [rel cog_out_ready],0
    lea rax,[rel cog_out_buf]
    mov [rel cog_out_cur],rax
    ret

str_cai_command: db "INTENT",0
str_cai_reply: db " ai_intent v=1 bits=",0
str_cai_reason: db " reason=",0
str_cai_have: db " have_seq=",0
str_cai_seq: db " seq=",0
str_cai_none: db " action=none",0
str_cai_denied: db " ai_intent refused=owner_or_compute action=none",0
str_cai_bad: db " ai_intent refused=state_or_arguments action=none",0

%include "core/abi/wdata.inc"
%macro WDATA_cognition_ai_intent_controller 0
align 8,db 0
cai_state: dq 1,0,0,0,0,0,0,0
cai_out: times 32 db 0
cai_epoch: dq 1                     ; native session epoch starts at 1, never repeats
cai_tap_source: dq 0
cai_tap_seq: dq 0
cai_private_end:
%endmacro
WDATA_DEFER WDATA_cognition_ai_intent_controller
