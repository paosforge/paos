;; MODULE cognition/router_meter
;; LAYER 4
;; EXPORTS cog_router_plan, cog_router_meter_event, cog_router_task_meter
;; IMPORTS
;; CAPS
;; OWNER saga:cognition
; RCQ51 pure design kernel. NO production caller, dispatch, model or I/O.
; All policy/eligibility/usage facts must come from the trusted native controller.
; Neither selection nor a meter record grants authority or authenticates facts.
; Buffers: mapped, immutable input, disjoint writable output/state; DF clear.
;
; plan(RDI=config[64],RSI=record[128]) -> EAX 0 selected,1 invalid,
; 2 no eligible route within ceiling,3 personal/unknown would need cloud.
; Config qwords: version1,task>0,epoch>0,eligible mask[0..31],ceiling[0..4],
; privacy[0 public,1 personal,2 unknown],attempted mask[0..31],reserved0.
; Priority:0 recipe,1 rule,2 classifier,3 local model,4 cloud. The middle two
; form one rules/classifier family. No personal/unknown cloud path exists here:
; actual consent provider/egress recheck are future joins, not guessed booleans.
; Record qwords: version1,task,epoch,tier(-1 on refusal),state,reason,
; input_tokens,output_tokens,egress_bytes,known mask,sequence,privacy,ceiling,
; attempted mask,eligible mask,reserved0. Known bits:1 input,2 output,4 egress.
; States:0 planned,1 running,2 complete,3 cancelled,4 failed,5 refused.
; Valid ranges + malformed config publish128 zero bytes. Pointer/range/alias
; refusal leaves output alone. Valid planned/refused counters are zero activity,
; never an assertion that a task has executed. No text/secret pointers retained.
cog_router_plan:
.native:
    push rbx
    push r12
    push r13
    sub rsp,128
    mov r12,rdi
    mov r13,rsi
    test r12,r12
    jz .pointer
    test r13,r13
    jz .pointer
    mov r8,r12
    add r8,64
    jc .pointer
    mov r9,r13
    add r9,128
    jc .pointer
    cmp r12,r9
    jae .ranges
    cmp r13,r8
    jb .pointer
.ranges:
    mov rdi,rsp
    mov ecx,16
    xor eax,eax
    rep stosq
    cmp qword [r12],1
    jne .invalid
    cmp qword [r12+8],0
    je .invalid
    cmp qword [r12+16],0
    je .invalid
    cmp qword [r12+24],31
    ja .invalid
    cmp qword [r12+32],4
    ja .invalid
    cmp qword [r12+40],2
    ja .invalid
    cmp qword [r12+48],31
    ja .invalid
    cmp qword [r12+56],0
    jne .invalid
    mov qword [rsp],1
    mov rax,[r12+8]
    mov [rsp+8],rax
    mov rax,[r12+16]
    mov [rsp+16],rax
    mov qword [rsp+72],7
    mov rax,[r12+40]
    mov [rsp+88],rax
    mov rax,[r12+32]
    mov [rsp+96],rax
    mov rax,[r12+48]
    mov [rsp+104],rax
    mov rax,[r12+24]
    mov [rsp+112],rax
    mov r8d,[r12+48]
    not r8d
    and r8d,[r12+24]                   ; eligible, not already attempted
    mov ecx,[r12+32]
    inc ecx
    mov r9d,1
    shl r9d,cl
    dec r9d
    and r9d,r8d                       ; explicit tier ceiling
    cmp qword [r12+40],0
    je .select
    and r9d,15                        ; no cloud for personal OR unknown
.select:
    test r9d,r9d
    jz .unavailable
    bsf eax,r9d
    mov [rsp+24],rax
    xor ebx,ebx
    jmp .publish
.unavailable:
    mov qword [rsp+24],-1
    mov qword [rsp+32],5
    mov ebx,2
    cmp qword [r12+40],0
    je .reason
    cmp qword [r12+32],4
    jne .reason
    test r8d,16
    jz .reason
    mov ebx,3
.reason:
    mov [rsp+40],rbx
    jmp .publish
.invalid:
    mov ebx,1
.publish:
    mov rsi,rsp
    mov rdi,r13
    mov ecx,16
    rep movsq
    mov eax,ebx
    jmp .return
.pointer:
    mov eax,1
.return:
    add rsp,128
    pop r13
    pop r12
    pop rbx
    ret

; task_meter(RDI=immutable records[count*128],RSI=count1..8,RDX=out[96])
; -> EAX 0 snapshot,1 invalid/range/identity/order,2 unsigned sum overflow.
; Output qwords:version1,task,count,last_epoch,last_attempt_state,privacy,
; known_mask,input_tokens,output_tokens,actual_egress,selected_tier_mask,reserved0.
; Pure recomputation, not an accumulator. All attempts retained, including costs
; before failure/cancellation. Unknown dimensions keep partial sums, not totals.
; Same task/privacy, strictly increasing epochs; only failed/cancelled/refused
; attempts may precede another attempt. Last state is NOT logical task success.
; Reuse the actual planner for immutable policy fields and planned/refused bytes.
; Trusted native-controller records only, not receipt authentication or history
; allocation. Mapped immutable inputs, disjoint mapped output, serialized caller.
; Refusals leave output untouched; all 288 scratch bytes wiped on every return.
cog_router_task_meter:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,288
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    test r12,r12
    jz .bad
    test r14,r14
    jz .bad
    cmp r13,1
    jb .bad
    cmp r13,8
    ja .bad
    mov r8,r13
    shl r8,7
    add r8,r12
    jc .bad
    mov r9,r14
    add r9,96
    jc .bad
    cmp r12,r9
    jae .ranges
    cmp r14,r8
    jb .bad
.ranges:
    mov rdi,rsp
    mov ecx,36
    xor eax,eax
    rep stosq
    mov qword [rsp],1
    mov rax,[r12+8]
    mov [rsp+8],rax
    mov [rsp+16],r13
    mov rax,[r12+88]
    mov [rsp+40],rax
    mov qword [rsp+48],7
    xor r15d,r15d
    xor ebx,ebx
.attempt:
    mov rax,[r12+8]
    cmp rax,[rsp+8]
    jne .bad
    mov rax,[r12+88]
    cmp rax,[rsp+40]
    jne .bad
    mov rax,[r12+16]
    cmp rax,r15
    jbe .bad
    mov r15,rax
    mov [rsp+24],rax
    mov rax,[r12+32]
    cmp rax,5
    ja .bad
    mov [rsp+32],rax
    lea rcx,[rbx+1]
    cmp rcx,r13
    je .plan
    cmp rax,3
    jb .bad
.plan:
    ; Reconstruct the actual fixed planner config, then compare its projection.
    mov rax,[r12]
    mov [rsp+96],rax
    mov rax,[r12+8]
    mov [rsp+104],rax
    mov rax,[r12+16]
    mov [rsp+112],rax
    mov rax,[r12+112]
    mov [rsp+120],rax
    mov rax,[r12+96]
    mov [rsp+128],rax
    mov rax,[r12+88]
    mov [rsp+136],rax
    mov rax,[r12+104]
    mov [rsp+144],rax
    mov rax,[r12+120]
    mov [rsp+152],rax
    lea rdi,[rsp+96]
    lea rsi,[rsp+160]
    call cog_router_plan.native
    cmp eax,1
    je .bad
    mov rsi,r12
    lea rdi,[rsp+160]
    mov ecx,4
    repe cmpsq
    jne .bad
    mov rax,[r12+40]
    cmp rax,[rsp+200]
    jne .bad
    lea rsi,[r12+88]
    lea rdi,[rsp+248]
    mov ecx,5
    repe cmpsq
    jne .bad
    mov rax,[r12+32]
    test rax,rax
    jz .static
    cmp rax,5
    je .static
    cmp qword [rsp+192],0          ; active/terminal needs selected plan
    jne .bad
    cmp qword [r12+80],1
    jb .bad
    cmp rax,1
    jne .terminal_sequence
    cmp qword [r12+80],1
    je .zero_usage
    jmp .sequence
.terminal_sequence:
    cmp qword [r12+80],2
    jb .bad
    jne .sequence
.zero_usage:
    mov rax,[r12+48]
    or rax,[r12+56]
    or rax,[r12+64]
    jnz .bad
    cmp qword [r12+72],7
    jne .bad
.sequence:
    cmp qword [r12+72],7
    ja .bad
    test qword [r12+72],4
    jz .bad
    cmp qword [r12+24],1
    ja .classifier
    cmp qword [r12+72],7
    jne .bad
    mov rax,[r12+48]
    or rax,[r12+56]
    jnz .bad
.classifier:
    cmp qword [r12+24],2
    jne .egress
    test qword [r12+72],2
    jz .bad
    cmp qword [r12+56],0
    jne .bad
.egress:
    cmp qword [r12+24],4
    je .sum
    cmp qword [r12+64],0
    jne .bad
    jmp .sum
.static:
    mov rsi,r12
    lea rdi,[rsp+160]
    mov ecx,16
    repe cmpsq
    jne .bad
.sum:
    mov rax,[r12+48]
    add [rsp+56],rax
    jc .overflow
    mov rax,[r12+56]
    add [rsp+64],rax
    jc .overflow
    mov rax,[r12+64]
    add [rsp+72],rax
    jc .overflow
    mov rax,[r12+72]
    and [rsp+48],rax
    mov rcx,[r12+24]
    cmp rcx,4
    ja .next
    mov eax,1
    shl rax,cl
    or [rsp+80],rax                ; selected tiers, not executed-tier proof
.next:
    add r12,128
    inc rbx
    cmp rbx,r13
    jb .attempt
    mov rsi,rsp
    mov rdi,r14
    mov ecx,12
    rep movsq
    xor ebx,ebx
    jmp .wipe
.bad:
    mov ebx,1
    jmp .wipe
.overflow:
    mov ebx,2
.wipe:
    mov rdi,rsp
    mov ecx,36
    xor eax,eax
    rep stosq
    mov eax,ebx
    add rsp,288
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; meter_event(RDI=mutable record[128],RSI=event[80]) -> EAX
; 0 accepted,1 invalid/state/replay,2 counter overflow,3 prohibited egress.
; Event qwords:version1,task,epoch,tier,next_sequence,kind,known_mask,
; input_token_delta,output_token_delta,egress_byte_delta.
; Kinds:1 start,2 usage delta,3 finish,4 cancel,5 fail. Terminal/start
; events require all-zero deltas and known=7. Usage requires known egress;
; unknown token deltas must be0 and permanently clear their record known bit.
; Recipe/rule require exact zero tokens; classifier has no generated tokens.
; Only cloud can report egress. Sequence is exactly previous+1, no wrap.
; Terminal records refuse further events. All refusals leave record unchanged.
; Existing record consistency uses the same planner/task reducer before each
; accepted transition. This validates/reduces trusted measurements, not evidence
; of actual execution or an authenticated history.
cog_router_meter_event:
    push rbx
    push r12
    push r13
    sub rsp,128
    mov r12,rdi
    mov r13,rsi
    test r12,r12
    jz .bad
    test r13,r13
    jz .bad
    mov r8,r12
    add r8,128
    jc .bad
    mov r9,r13
    add r9,80
    jc .bad
    cmp r12,r9
    jae .ranges
    cmp r13,r8
    jb .bad
.ranges:
    cmp qword [r12],1
    jne .bad
    cmp qword [r13],1
    jne .bad
    cmp qword [r12+8],0
    je .bad
    cmp qword [r12+16],0
    je .bad
    mov rax,[r12+8]
    cmp rax,[r13+8]
    jne .bad
    mov rax,[r12+16]
    cmp rax,[r13+16]
    jne .bad
    mov rax,[r12+24]
    cmp rax,4
    ja .bad
    cmp rax,[r13+24]
    jne .bad
    cmp qword [r12+32],1
    ja .bad                            ; already terminal/refused
    cmp qword [r12+40],0
    jne .bad
    cmp qword [r12+72],7
    ja .bad
    test qword [r12+72],4
    jz .bad
    cmp qword [r12+88],2
    ja .bad
    cmp qword [r12+96],4
    ja .bad
    cmp rax,[r12+96]
    ja .bad
    cmp qword [r12+104],31
    ja .bad
    cmp qword [r12+112],31
    ja .bad
    cmp qword [r12+120],0
    jne .bad
    cmp rax,4
    jne .sequence
    cmp qword [r12+88],0
    jne .egress                        ; personal/unknown cannot adopt cloud
.sequence:
    ; Validate the existing prefix with the actual planner/task reducer before
    ; accepting another event. Individual field ranges cannot establish that a
    ; selected tier was eligible or that usage followed start/usage events.
    ; The existing128-byte scratch holds its96-byte snapshot and is wiped on
    ; every exit below. This recomputes consistency, never authenticates facts.
    mov rdi,r12
    mov esi,1
    mov rdx,rsp
    call cog_router_task_meter
    test eax,eax
    jnz .bad
    mov rax,[r12+80]
    add rax,1
    jc .bad
    cmp rax,[r13+32]
    jne .bad
    mov rbx,[r13+40]
    cmp rbx,1
    jb .bad
    cmp rbx,5
    ja .bad
    cmp qword [r13+48],7
    ja .bad
    test qword [r13+48],4
    jz .bad                            ; actual egress count must be known
    cmp rbx,1
    je .start
    cmp qword [r12+32],1
    jne .bad
    cmp rbx,2
    je .usage
    jmp .zero_event
.start:
    cmp qword [r12+32],0
    jne .bad
    cmp qword [r12+80],0
    jne .bad
.zero_event:
    cmp qword [r13+48],7
    jne .bad
    mov rax,[r13+56]
    or rax,[r13+64]
    or rax,[r13+72]
    jnz .bad
    jmp .copy
.usage:
    test qword [r13+48],1
    jnz .input_known
    cmp qword [r13+56],0
    jne .bad
.input_known:
    test qword [r13+48],2
    jnz .output_known
    cmp qword [r13+64],0
    jne .bad
.output_known:
    cmp qword [r12+24],1
    ja .not_rule
    cmp qword [r13+48],7
    jne .bad
    cmp qword [r13+56],0
    jne .bad
    cmp qword [r13+64],0
    jne .bad
.not_rule:
    cmp qword [r12+24],2
    jne .not_classifier
    test qword [r13+48],2
    jz .bad
    cmp qword [r13+64],0
    jne .bad
.not_classifier:
    cmp qword [r12+24],4
    je .copy
    cmp qword [r13+72],0
    jne .egress
.copy:
    mov rsi,r12
    mov rdi,rsp
    mov ecx,16
    rep movsq
    mov rax,[r13+32]
    mov [rsp+80],rax
    cmp rbx,1
    je .running
    cmp rbx,2
    je .add
    dec rbx                            ; finish/cancel/fail -> states2/3/4
    mov [rsp+32],rbx
    jmp .publish
.running:
    mov qword [rsp+32],1
    jmp .publish
.add:
    mov rax,[r13+56]
    add [rsp+48],rax
    jc .overflow
    mov rax,[r13+64]
    add [rsp+56],rax
    jc .overflow
    mov rax,[r13+72]
    add [rsp+64],rax
    jc .overflow
    mov rax,[r13+48]
    and [rsp+72],rax                    ; unknown stays unknown
.publish:
    mov rsi,rsp
    mov rdi,r12
    mov ecx,16
    rep movsq
    xor ebx,ebx
    jmp .wipe
.bad:
    mov ebx,1
    jmp .wipe
.overflow:
    mov ebx,2
    jmp .wipe
.egress:
    mov ebx,3
.wipe:
    mov rdi,rsp
    mov ecx,16
    xor eax,eax
    rep stosq
    mov eax,ebx
    add rsp,128
    pop r13
    pop r12
    pop rbx
    ret
