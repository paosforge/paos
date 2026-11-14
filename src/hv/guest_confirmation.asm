;; MODULE hv/guest_confirmation
;; LAYER 5
;; PURPOSE One bounded native frozen-original WAIT confirmation continuation.
;; EXPORTS guest_request_configure_confirmation, guest_request_defer, guest_request_resume, guest_request_completion_state
;; IMPORTS hv/guest_request, sec/session, core/time
;; OWNER saga:guest_confirmation
; Included by guest_request. No guest approval-ID input, scheduler, executor,
; retained caller pointer or generic replay exception. All callbacks native.
GC_DESC_BYTES equ 160
GC_HUMAN_US equ 30000000
GC_RESULT_US equ 30000000
; state0 empty,1 pending,2 reserved (freeze/consume),3 executing,4 completed.

; Native init only: RDI=validate(desc)->EAX1 + RDX exact ASK policy generation;
; RSI=ask(frozen desc)->nativeID/0; RDX=consume(ID,exact desc)->1/0.
; Validator proves current enforced bundle/target/VM scope AND ASK policy.
; Read-only/non-yielding callbacks preserve SysV callee-saved registers.
; NULL means DENY, not a VM-wide-to-bundle identity conversion.
guest_request_configure_confirmation:
    cmp byte [rel gr_busy],0
    jne .bad
    cmp byte [rel command_auth_remote_active],0
    jne .bad
    cmp dword [rel cmd_dispatch_depth],0
    jne .bad
    call guest_request_retire
    mov [rel gr_confirm_validate],rdi
    mov [rel gr_confirm_ask],rsi
    mov [rel gr_confirm_consume],rdx
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Preserve all GPRs. This private leaf is called on every native retirement.
; Wipe the complete owned descriptor and original operands before releasing.
gr_confirmation_retire:
    push rax
    push rcx
    push rdi
    mov byte [rel gr_defer_state],0
    mov qword [rel gr_defer_id],0
    mov qword [rel gr_defer_policy],0
    mov qword [rel gr_defer_until],0
    mov qword [rel gr_defer_binding],0
    lea rdi,[rel gr_defer_desc]
    xor eax,eax
    mov ecx,(160+40+RSP_SZ)/8
    rep stosq
    lea rdi,[rel gr_result]
    mov ecx,GR_RESULT_BYTES/8
    rep stosq
    mov byte [rel gr_result_valid],0
    pop rdi
    pop rcx
    pop rax
    ret

; Private snapshot currentness, independent of an expired execution frame.
; EAX1/0. No effect. Validator must also check exact current ASK policy gen.
gr_confirmation_live:
    push rbx
    cmp byte [rel gr_defer_state],0
    je .bad
    mov rax,[rel gr_defer_binding]
    cmp rax,[rel gr_serial]
    jne .bad
    mov rax,[rel gr_defer_desc+8]
    cmp rax,[rel gr_pid]
    jne .bad
    mov rdi,[rel gr_defer_desc+16]
    mov esi,[rel gr_defer_desc+24]
    call gr_binding_current
    test eax,eax
    jz .bad
    call time_monotonic_now_us
    test rax,rax
    jz .bad
    cmp rax,[rel gr_defer_until]
    jae .bad
    mov rbx,[rel gr_confirm_validate]
    test rbx,rbx
    jz .bad
    lea rdi,[rel gr_defer_desc]
    call rbx
    cmp eax,1
    jne .bad
    mov rax,[rel gr_defer_policy]
    test rax,rax
    jz .bad
    cmp rdx,rax
    jne .bad
    ; Native callback cannot make retirement or deadline crossing invisible.
    mov rax,[rel gr_defer_binding]
    cmp rax,[rel gr_serial]
    jne .bad
    mov rdi,[rel gr_defer_desc+16]
    mov esi,[rel gr_defer_desc+24]
    call gr_binding_current
    test eax,eax
    jz .bad
    call time_monotonic_now_us
    test rax,rax
    jz .bad
    cmp rax,[rel gr_defer_until]
    jae .bad
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop rbx
    ret

; Grant callback only: RDI=exact current req, RSI=native160B descriptor,
; RDX=current ASK policy gen -> EAX0/-1. Freeze BEFORE invoking native ask.
; Descriptor ABI is INPUT app_grants160; exact original operands stay private.
; On already-consumed execution, only the same frozen descriptor is accepted;
; no second native prompt/approval is created by repeated effect checks.
guest_request_defer:
    push rbx
    push r12
    push r13
    mov rbx,rsi
    mov r12,rdx
    cmp byte [rel gr_busy],1
    jne .bad
    lea rax,[rel gr_req]
    cmp rdi,rax
    jne .bad
    cmp byte [rel command_auth_remote_active],1
    jne .bad
    lea rax,[rel gr_ticket]
    cmp rax,[rel command_auth_remote_ticket]
    jne .bad
    cmp qword [rel gr_ticket+AUTH_T_STATE],AUTH_TS_GUEST
    jne .bad
    test rbx,rbx
    jz .bad
    test r12,r12
    jz .bad
    cmp qword [rel gr_confirm_validate],0
    je .bad
    cmp qword [rel gr_confirm_ask],0
    je .bad
    cmp qword [rel gr_confirm_consume],0
    je .bad
    cmp byte [rel gr_defer_state],3
    je .same_execution
    cmp byte [rel gr_defer_state],0
    jne .bad
    cmp qword [rbx],1
    jne .bad
    cmp qword [rbx+152],0
    jne .bad
    mov rax,[rel gr_context+GR_PID]
    cmp rax,[rbx+8]
    jne .bad
    cmp rax,[rbx+48]
    jne .bad
    mov rax,[rel gr_context+GR_ENDPOINT]
    cmp rax,[rbx+16]
    jne .bad
    mov rax,[rel gr_context+GR_START]
    cmp rax,[rbx+24]
    jne .bad
    mov rax,[rel gr_context+GR_VM_EPOCH]
    cmp rax,[rbx+32]
    jne .bad
    mov rax,[rel gr_context+GR_SESSION]
    cmp rax,[rbx+40]
    jne .bad
    mov rax,[rel gr_context+GR_TARGET]
    cmp rax,[rbx+56]
    jne .bad
    mov rax,[rbx+64]
    test rax,rax
    jz .bad
    shr rax,32
    jnz .bad
    cmp qword [rbx+72],0
    je .bad
    cmp qword [rbx+80],0
    je .bad
    mov rax,[rbx+88]
    or rax,[rbx+96]
    or rax,[rbx+104]
    or rax,[rbx+112]
    jz .bad
    mov rax,[rel gr_context+GR_OP]
    cmp rax,[rbx+120]
    jne .bad
    mov rax,[rel gr_req+REQ_IDEM]
    cmp rax,[rbx+128]
    jne .bad
    mov rax,[rel gr_frame+24]
    cmp rax,[rbx+136]
    jne .bad
    mov rax,[rel gr_frame+32]
    cmp rax,[rbx+144]
    jne .bad
    call time_monotonic_now_us
    test rax,rax
    jz .bad
    cmp rax,[rel gr_context+GR_DEADLINE]
    jae .bad
    add rax,GC_HUMAN_US
    jc .bad
    mov [rel gr_defer_until],rax
    mov [rel gr_defer_policy],r12
    mov rax,[rel gr_serial]
    mov [rel gr_defer_binding],rax
    mov rsi,rbx
    lea rdi,[rel gr_defer_desc]
    mov ecx,GC_DESC_BYTES/8
    rep movsq
    lea rsi,[rel gr_frame]
    lea rdi,[rel gr_defer_frame]
    mov ecx,GR_FRAME_BYTES/8
    rep movsq
    mov byte [rel gr_defer_state],2
    call gr_confirmation_live
    test eax,eax
    jz .cancel
    lea rdi,[rel gr_defer_desc]
    call [rel gr_confirm_ask]
    test rax,rax
    jz .cancel
    mov r13,rax
    cmp byte [rel gr_defer_state],2
    jne .cancel
    call gr_confirmation_live
    test eax,eax
    jz .cancel
    mov [rel gr_defer_id],r13
    mov byte [rel gr_defer_state],1
    xor eax,eax
    jmp .out
.same_execution:
    cmp r12,[rel gr_defer_policy]
    jne .bad
    mov rsi,rbx
    lea rdi,[rel gr_defer_desc]
    mov ecx,GC_DESC_BYTES/8
    repe cmpsq
    jne .bad
    call gr_confirmation_live
    test eax,eax
    jz .bad
    xor eax,eax
    jmp .out
.cancel:
    call gr_confirmation_retire
.bad:
    mov eax,-1
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Private admission backpressure. Stale slots cancel; no new queue/eviction.
gr_confirmation_blocked:
    cmp byte [rel gr_defer_state],0
    je .free
    call gr_confirmation_live
    test eax,eax
    jnz .busy
    call gr_confirmation_retire
.free:
    xor eax,eax
    ret
.busy:
    mov eax,1
    ret

; INPUT trusted local HUMAN UI delivery only: RDI=nativeID, RSI=private frozen
; descriptor copy -> EAX=CMDE or-1 refusal. Approval consumer verifies provenance
; and spends once BEFORE the one maintained command_dispatch invocation.
guest_request_resume:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx,rdi
    mov r12,rsi
    cmp byte [rel gr_busy],0
    jne .bad
    cmp byte [rel command_auth_remote_active],0
    jne .bad
    cmp dword [rel cmd_dispatch_depth],0
    jne .bad
    cmp byte [rel gr_defer_state],1
    jne .bad
    cmp rbx,[rel gr_defer_id]
    jne .bad
    test r12,r12
    jz .bad
    lea rdi,[rel gr_defer_desc]
    mov rsi,r12
    mov ecx,GC_DESC_BYTES/8
    repe cmpsq
    jne .bad
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .cancel
    call gr_confirmation_live
    test eax,eax
    jz .cancel
    mov rax,[rel gr_defer_desc+128]
    cmp rax,[rel gr_last_seq]
    jne .cancel
    mov byte [rel gr_defer_state],2       ; reserve before native consume/reentry
    mov rdi,rbx
    lea rsi,[rel gr_defer_desc]
    call [rel gr_confirm_consume]
    cmp eax,1
    jne .cancel
    cmp byte [rel gr_defer_state],2
    jne .cancel
    call gr_confirmation_live
    test eax,eax
    jz .cancel
    lea rsi,[rel gr_defer_frame]
    lea rdi,[rel gr_frame]
    mov ecx,GR_FRAME_BYTES/8
    rep movsq
    mov byte [rel gr_defer_state],3       ; exact original approved continuation
    mov rdi,[rel gr_defer_desc+16]
    mov esi,[rel gr_defer_desc+24]
    lea rdx,[rel gr_resume_rsp]
    call gr_dispatch_frame
    mov r14d,eax
    cmp byte [rel gr_defer_state],3
    jne .cancel
    call gr_confirmation_live
    test eax,eax
    jz .cancel
    test r14d,r14d
    jz .completed
    ; Error does not imply no partial handler effect. Never retry/re-arm it.
    lea rdi,[rel gr_result]
    xor eax,eax
    mov ecx,GR_RESULT_BYTES/8
    rep stosq
    mov dword [rel gr_result],1
    mov [rel gr_result+4],r14d
    mov rax,[rel gr_defer_desc+128]
    mov [rel gr_result+8],rax
    mov rax,[rel gr_defer_desc+56]
    mov [rel gr_result+16],rax
.completed:
    call time_monotonic_now_us
    test rax,rax
    jz .cancel
    add rax,GC_RESULT_US
    jc .cancel
    mov [rel gr_defer_until],rax
    mov byte [rel gr_defer_state],4
    mov eax,r14d
    jmp .out
.cancel:
    call gr_confirmation_retire
.bad:
    mov eax,-1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Native producer polling only: endpoint/START/originalseq -> EAX1 pending,
; 2 completed,0 no slot,-1 refused. Never submits, approves, or executes work.
guest_request_completion_state:
    push rbx
    mov rbx,rdx
    cmp byte [rel gr_busy],0
    jne .bad
    cmp byte [rel command_auth_remote_active],0
    jne .bad
    cmp dword [rel cmd_dispatch_depth],0
    jne .bad
    call gr_binding_current
    test eax,eax
    jz .bad
    cmp byte [rel gr_defer_state],0
    je .empty
    cmp rbx,[rel gr_defer_desc+128]
    jne .bad
    call gr_confirmation_live
    test eax,eax
    jz .cancel
    cmp byte [rel gr_defer_state],1
    je .pending
    cmp byte [rel gr_defer_state],4
    jne .bad
    mov eax,2
    jmp .out
.pending:
    mov eax,1
    jmp .out
.cancel:
    call gr_confirmation_retire
.empty:
    xor eax,eax
    jmp .out
.bad:
    mov eax,-1
.out:
    pop rbx
    ret

; Private result-copy helper. Fresh frozen descriptor policy/lifetime check,
; NOT the expired execution request/ticket. No dispatch or second effect.
; RDI=endpoint,ESI=START,RDX=originalseq,RCX=destination128 -> EAX0/-1.
gr_confirmation_copy:
    push rbx
    push r12
    mov rbx,rcx
    mov r12,rdx
    cmp byte [rel command_auth_remote_active],0
    jne .bad
    cmp dword [rel cmd_dispatch_depth],0
    jne .bad
    call gr_binding_current
    test eax,eax
    jz .bad
    cmp byte [rel gr_defer_state],4
    jne .bad
    cmp r12,[rel gr_defer_desc+128]
    jne .bad
    cmp r12,[rel gr_result+8]
    jne .bad
    cmp r12,[rel gr_last_seq]
    jne .bad
    call gr_confirmation_live
    test eax,eax
    jz .cancel
    lea rsi,[rel gr_result]
    mov rdi,rbx
    mov ecx,GR_RESULT_BYTES/8
    rep movsq
    call gr_confirmation_retire
    mov byte [rel gr_result_valid],0
    xor eax,eax
    jmp .out
.cancel:
    call gr_confirmation_retire
.bad:
    mov eax,-1
.out:
    pop r12
    pop rbx
    ret

align 8
gr_confirm_validate: dq 0
gr_confirm_ask: dq 0
gr_confirm_consume: dq 0
gr_defer_id: dq 0
gr_defer_policy: dq 0
gr_defer_until: dq 0
gr_defer_binding: dq 0
gr_defer_state: db 0
align 8
gr_defer_desc: times GC_DESC_BYTES db 0
gr_defer_frame: times GR_FRAME_BYTES db 0
gr_resume_rsp: times RSP_SZ db 0
