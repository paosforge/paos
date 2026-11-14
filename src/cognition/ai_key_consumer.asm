;; MODULE cognition/ai_key_consumer
;; LAYER 6
;; EXPORTS cog_ai_key_poll, cog_ai_key_retire
;; IMPORTS gui/input_route, sec/session
;; CAPS
;; OWNER saga:cognition
; RCQ51 callable native gesture consumer; ai_intent_controller owns idle calls.
; Single trusted idle controller, exclusive pop consumer, serialized with input.
; RDI=state64 writable, RSI=out32 writable, mapped/disjoint, DF clear.
; State qwords: version1, request bits(typed1/PTT2/handsfree4), last_u32_seq,
; have_seq0/1, native_drop_snapshot, native_cancel_snapshot, hold_source0..2,
; reserved0. Initialize {1,0,...0}. State is not authority/device readiness.
; Out: actual native record16 (kind,source,origin,reserved,u32seq,u64time),
; request bits8, reason8. No-event/retired record is all zero, never stale.
; EAX:0 empty snapshot,1 accepted native record,2 retired,3 bad pointer/state.
; Reasons:0 ordinary,1 locked,2 lost/cancelled,3 malformed/discontinuous,
; 4 unmatched hold transition,5 explicit controller retirement (e.g. actual Esc).
; Bad args leave state/output/queue unchanged. Others wipe private record.
; Drain max8 on retirement, reset sequence; no queued restart after unlocking.
; Only requests: no mic state, recording, handsfree silence clock or routing proof.

cog_ai_key_retire:
    mov r8d,5
    jmp cog_ai_key_poll.enter
cog_ai_key_poll:
    xor r8d,r8d
.enter:
    push rbx
    push r12
    push r13
    sub rsp,16
    mov r12,rdi
    mov r13,rsi
    xor eax,eax
    mov [rsp],rax
    mov [rsp+8],rax
    call .validate
    test eax,eax
    jnz .badarg
    xor eax,eax
    mov [r13],rax
    mov [r13+8],rax
    mov [r13+16],rax
    mov [r13+24],rax
    test r8d,r8d
    jnz .retire_reason
    cmp byte [session_locked],0
    jne .locked
    mov rax,[input_ai_dropped]
    cmp rax,[r12+32]
    jne .lost
    mov rax,[input_ai_cancelled]
    cmp rax,[r12+40]
    jne .lost
    mov rdi,rsp
    call input_ai_key_pop
    test eax,eax
    jz .empty
    cmp byte [rsp],1
    jb .record_bad
    cmp byte [rsp],4
    ja .record_bad
    cmp byte [rsp+1],1
    jb .record_bad
    cmp byte [rsp+1],2
    ja .record_bad
    cmp word [rsp+2],0               ; actual human-origin0 and reserved0
    jne .record_bad
    cmp qword [r12+24],0
    je .sequence_ok
    mov eax,[r12+16]
    inc eax                          ; native u32 sequence wraps through zero
    cmp eax,[rsp+4]
    jne .record_bad
.sequence_ok:
    movzx eax,byte [rsp]
    cmp eax,1
    je .tap
    cmp eax,2
    je .double
    cmp eax,3
    je .hold_start
    test qword [r12+8],2
    jz .transition_bad
    movzx eax,byte [rsp+1]
    cmp rax,[r12+48]
    jne .transition_bad
    and qword [r12+8],~2
    mov qword [r12+48],0
    jmp .accepted
.tap:
    mov qword [r12+8],1             ; explicit typed request ends voice intent
    mov qword [r12+48],0
    jmp .accepted
.double:
    test qword [r12+8],2
    jnz .transition_bad
    or qword [r12+8],4
    jmp .accepted
.hold_start:
    test qword [r12+8],2
    jnz .transition_bad
    and qword [r12+8],~4
    or qword [r12+8],2
    movzx eax,byte [rsp+1]
    mov [r12+48],rax
.accepted:
    mov eax,[rsp+4]
    mov [r12+16],rax
    mov qword [r12+24],1
    mov rax,[rsp]
    mov [r13],rax
    mov rax,[rsp+8]
    mov [r13+8],rax
    mov eax,1
    jmp .publish
.empty:
    xor eax,eax
    jmp .publish
.locked:
    mov r8d,1
    jmp .retire_reason
.lost:
    mov r8d,2
    jmp .retire_reason
.record_bad:
    mov r8d,3
    jmp .retire_reason
.transition_bad:
    mov r8d,4
.retire_reason:
    mov [r13+24],r8
    mov qword [r12+8],0
    mov qword [r12+16],0
    mov qword [r12+24],0
    mov qword [r12+48],0
    mov rax,[input_ai_dropped]
    mov [r12+32],rax
    mov rax,[input_ai_cancelled]
    mov [r12+40],rax
    mov ebx,8                       ; actual ring capacity; never unbounded
.drain:
    mov rdi,rsp
    call input_ai_key_pop
    test eax,eax
    jz .retired
    dec ebx
    jnz .drain
.retired:
    mov eax,2
.publish:
    mov rdx,[r12+8]
    mov [r13+16],rdx
    jmp .out
.badarg:
    mov eax,3
.out:
    mov qword [rsp],0
    mov qword [rsp+8],0
    add rsp,16
    pop r13
    pop r12
    pop rbx
    ret

.validate:
    mov eax,1
    test r12,r12
    jz .invalid
    test r13,r13
    jz .invalid
    mov rdx,r12
    add rdx,64
    jc .invalid
    mov rcx,r13
    add rcx,32
    jc .invalid
    cmp r12,rcx
    jae .state
    cmp r13,rdx
    jb .invalid
.state:
    cmp qword [r12],1
    jne .invalid
    cmp qword [r12+8],7
    ja .invalid
    mov rdx,[r12+8]
    and edx,6
    cmp edx,6
    je .invalid
    mov edx,[r12+16]
    cmp rdx,[r12+16]
    jne .invalid
    cmp qword [r12+24],1
    ja .invalid
    cmp qword [r12+56],0
    jne .invalid
    test qword [r12+8],2
    jnz .held_state
    cmp qword [r12+48],0
    jne .invalid
    jmp .valid
.held_state:
    cmp qword [r12+48],1
    jb .invalid
    cmp qword [r12+48],2
    ja .invalid
.valid:
    xor eax,eax
.invalid:
    ret
