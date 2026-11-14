;; MODULE hv/guest_command_policy
;; LAYER 5
;; PURPOSE Bound driver command ceiling, authenticated native settings and scalar copy.
;; EXPORTS guest_request_command_policy_set, guest_request_command_policy_copy, guest_request_command_policy_current, guest_request_command_policy_observe, guest_request_receipt_observe
;; IMPORTS hv/guest_request, sec/session, core/time, core/smp, svc/command_audit
;; OWNER saga:guest_request
; Included once by guest_request. Driver endpoint only; never app permission.
; BSP/stopped-vCPU/native memory only. No guest setter, parser or new dispatch.

; Preserve ALL registers/flags: invoked before every binding retirement.
gr_command_policy_retire:
    pushfq
    mov qword [rel gr_cp_mode],0
    mov qword [rel gr_cp_mask],0
    mov qword [rel gr_cp_owner],0
    mov qword [rel gr_cp_owner_session],0
    mov qword [rel gr_cp_changed],0
    mov qword [rel gr_cp_sequence],0
    mov qword [rel gr_cp_decision],2
    cmp qword [rel gr_cp_generation],-1
    je .out
    inc qword [rel gr_cp_generation]  ; saturation permanently refuses widening
.out:
    popfq
    ret

gr_command_policy_idle:
    cmp byte [rel gr_busy],0
    jne .bad
    cmp dword [rel cmd_dispatch_depth],0
    jne .bad
    cmp byte [rel cmd_in_dispatch],0
    jne .bad
    cmp byte [rel command_auth_remote_active],0
    jne .bad
    push rdi
    push rsi
    push rdx
    push rcx
    call smp_current_logical
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    test eax,eax
    jnz .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Native-only set(endpoint,START,input64,size64)->1/0; input eight u64:
; PID,binding,START,VMepoch,session,mode,WAITmask,reserved0.
; None=0/mask0; Custom=2/explicit nonempty mask1..15. Basic unsupported.
; All changes require the actual authenticated local OWNER and exact selection.
guest_request_command_policy_set:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx,rdx
    mov r12,rdi
    mov r13d,esi
    cmp ecx,64
    jne .bad
    test rbx,rbx
    jz .bad
    mov rax,rbx
    add rax,64
    jc .bad
    call gr_command_policy_idle
    test eax,eax
    jz .bad
    lea rax,[rel guest_request_endpoint]
    cmp r12,rax
    jne .bad
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .bad
    cmp rdx,[rbx+32]
    jne .bad
    mov rdi,r12
    mov esi,r13d
    call gr_binding_current
    test eax,eax
    jz .bad
    mov rax,[rel gr_pid]
    cmp [rbx],rax
    jne .bad
    mov rax,[rel gr_serial]
    cmp [rbx+8],rax
    jne .bad
    mov eax,r13d
    cmp [rbx+16],rax
    jne .bad
    mov rax,[rel gr_bound_vm_epoch]
    cmp [rbx+24],rax
    jne .bad
    cmp qword [rbx+56],0
    jne .bad
    mov r14,[rbx+40]
    mov r15,[rbx+48]
    test r14,r14
    jz .none
    cmp r14,2
    jne .bad
    test r15,r15
    jz .bad
    cmp r15,15
    ja .bad
    jmp .validated
.none:
    test r15,r15
    jnz .bad
.validated:
    cmp qword [rel gr_cp_generation],-2
    jae .bad
    call time_monotonic_now_us
    test rax,rax
    jz .bad
    cmp rax,-1
    je .bad
    cmp rax,[rel gr_cp_changed]
    jb .bad
    ; No callback/yield after authentication and before bounded mutation.
    mov [rel gr_cp_changed],rax
    inc qword [rel gr_cp_generation]
    mov [rel gr_cp_mode],r14
    mov [rel gr_cp_mask],r15
    mov qword [rel gr_cp_owner],PRIN_OWNER
    mov rax,[rel gr_session]
    mov [rel gr_cp_owner_session],rax
    mov qword [rel gr_cp_sequence],0
    mov qword [rel gr_cp_decision],2
    call gr_confirmation_retire
    call gr_receipt_retire
    ; Existing per-operation grants/WAIT tokens are NOT created or rewritten.
    ; Their own current policy and lifetime gates remain mandatory on every use.
    mov edi,0x0e000401              ; existing Guardian spine VERB/INFO
    mov esi,PRIN_OWNER             ; actually authenticated here, never guest
    mov edx,r14d
    shl edx,8
    or edx,r15d
    call audit_sec_event
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Original ceiling check, independently required before the original grant.
; No native callback, target inference, ALLOW ticket or confirmation approval.
gr_command_policy_admit:
    lea rax,[rel guest_request_endpoint]
    cmp [rel gr_context+GR_ENDPOINT],rax
    jne .app
    mov rax,[rel gr_req+REQ_IDEM]
    mov [rel gr_cp_sequence],rax
    mov qword [rel gr_cp_decision],0
    mov rax,[rel gr_cp_generation]
    test rax,rax
    jz .bad
    cmp rax,-1
    je .bad
    cmp rax,[rel gr_call_setting_generation]
    jne .bad
    cmp qword [rel gr_cp_mode],2
    jne .bad
    mov rcx,[rel gr_context+GR_OP]
    dec rcx
    cmp rcx,3
    ja .bad
    mov rax,[rel gr_cp_mask]
    bt rax,rcx
    jnc .bad
    mov qword [rel gr_cp_decision],1 ; ceiling passed, NOT a command grant
.app:
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Currentness for every public copy/dword. Native driver endpoint only.
guest_request_command_policy_current:
    lea rax,[rel guest_request_endpoint]
    cmp rdi,rax
    jne .bad
    mov rax,[rel gr_cp_generation]
    test rax,rax
    jz .bad
    cmp rax,-1
    je .bad
    call gr_binding_current
    test eax,eax
    jz .bad
    mov rdx,[rel gr_cp_generation] ; original generation, never an authority token
    ret
.bad:
    xor eax,eax
    ret

; copy(endpoint,START,native128out,size128)->1/0, no failed writes.
; GCS1 v1/128 header followed by15 u64, no native address or key.
guest_request_command_policy_copy:
    call gr_command_policy_idle
    test eax,eax
    jz .bad
    jmp gr_command_policy_copy_native
.bad:
    xor eax,eax
    ret

; Native GUI read only, with the caller's original admission/privacy intact.
; An admitted remote read may observe scalars; it never becomes a local OWNER
; or bypasses the independent strict setter, transport or per-operation gates.
guest_request_command_policy_observe:
    call gr_command_policy_observer_boundary
    test eax,eax
    jz .bad
    jmp gr_command_policy_copy_native
.bad:
    xor eax,eax
    ret

; One common codec, with no callback/yield or mutation of native policy.
gr_command_policy_copy_native:
    push rbx
    push r12
    mov rbx,rdx
    cmp ecx,128
    jne .bad
    test rbx,rbx
    jz .bad
    mov rax,rbx
    add rax,128
    jc .bad
    call guest_request_command_policy_current
    test eax,eax
    jz .bad
    call time_monotonic_now_us
    test rax,rax
    jz .bad
    cmp rax,-1
    je .bad
    cmp rax,[rel gr_cp_changed]
    jb .bad
    mov r12,rax
    mov rax,0x0080000131534347     ; GCS1 + u16 version1 + u16 size128
    mov [rbx],rax
    mov rax,[rel gr_pid]
    mov [rbx+8],rax
    mov rax,[rel gr_serial]
    mov [rbx+16],rax
    mov eax,[rel gr_start]
    mov [rbx+24],rax
    mov rax,[rel gr_bound_vm_epoch]
    mov [rbx+32],rax
    mov rax,[rel gr_session]
    mov [rbx+40],rax
    mov rax,[rel gr_cp_generation]
    mov [rbx+48],rax
    mov rax,[rel gr_cp_mode]
    mov [rbx+56],rax
    mov rax,[rel gr_cp_mask]
    mov [rbx+64],rax
    mov rax,[rel gr_cp_owner]
    mov [rbx+72],rax
    mov rax,[rel gr_cp_owner_session]
    mov [rbx+80],rax
    mov rax,[rel gr_cp_changed]
    mov [rbx+88],rax
    mov [rbx+96],r12
    mov rax,[rel gr_cp_sequence]
    mov [rbx+104],rax
    mov rax,[rel gr_cp_decision]
    mov [rbx+112],rax
    mov qword [rbx+120],0
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r12
    pop rbx
    ret

; Serialized BSP/stopped-vCPU native caller. Permit idle or exactly one
; admitted handler, never a nested dispatch or a partially entered/left frame.
; This gate confers no authority. GUI identity/privacy gates remain upstream.
; Preserve all input registers across the real LAPIC CPU query.
gr_command_policy_observer_boundary:
    cmp byte [rel gr_busy],0
    jne .bad
    cmp dword [rel cmd_dispatch_depth],0
    je .idle
    cmp dword [rel cmd_dispatch_depth],1
    jne .bad
    cmp byte [rel cmd_in_dispatch],1
    jne .bad
    jmp .cpu
.idle:
    cmp byte [rel cmd_in_dispatch],0
    jne .bad
.cpu:
    push rdi
    push rsi
    push rdx
    push rcx
    call smp_current_logical
    pop rcx
    pop rdx
    pop rsi
    pop rdi
    test eax,eax
    jnz .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Optional original still-current GCR1, same endpoint/START/out128/size128.
; Never manufacture a missing/expired receipt or rewrite its retained bytes.
guest_request_receipt_observe:
    push rbx
    push r12
    mov rbx,rdx
    cmp ecx,128
    jne .bad
    test rbx,rbx
    jz .bad
    mov rax,rbx
    add rax,128
    jc .bad
    call gr_command_policy_observer_boundary
    test eax,eax
    jz .bad
    call gr_receipt_current_native
    test eax,eax
    jz .bad
    call time_monotonic_now_us
    test rax,rax
    jz .bad
    cmp rax,[rel gr_receipt+104]
    jb .bad
    cmp rax,[rel gr_receipt+112]
    jae .bad
    mov r12,rax
    push rdi
    push rsi
    mov rdi,rbx
    lea rsi,[rel gr_receipt]
    mov ecx,16
    cld
    rep movsq
    mov [rbx+120],r12             ; copy time belongs to this copy only
    pop rsi
    pop rdi
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r12
    pop rbx
    ret

; One original driver completion, after exact typed-result validation. The
; existing Guardian spine folds GUES (never falsely verified OWNER); GCR1 keeps
; actual latest full guest identity. Separate GCA1 retains bounded checked
; identity/reason history; public counters are not identity-bearing receipts.
gr_command_policy_record:
    lea rax,[rel guest_request_endpoint]
    cmp [rel gr_context+GR_ENDPOINT],rax
    jne .out
    mov edi,0x0e000401
    cmp qword [rbx+RSP_CODE],CMDE_OK
    jne .refused
    mov edi,0x0e000101
    jmp .record
.refused:
    cmp qword [rbx+RSP_CODE],CMDE_AUTHDENY
    jne .record
    mov edi,0x0e000201
.record:
    mov rsi,[rel gr_context+GR_PID]
    mov edx,[rel gr_context+GR_OP]
    call audit_sec_event
    call audit_guest_command_record    ; separate bounded native identity history
.out:
    ret

align 8
gr_cp_generation: dq 0
gr_cp_mode: dq 0
gr_cp_mask: dq 0
gr_cp_owner: dq 0
gr_cp_owner_session: dq 0
gr_cp_changed: dq 0
gr_cp_sequence: dq 0
gr_cp_decision: dq 2
gr_call_setting_generation: dq 0
