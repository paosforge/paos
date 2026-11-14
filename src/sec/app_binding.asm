;; MODULE sec/app_binding
;; LAYER 6
;; PURPOSE Resolve actual isolated app VM, immutable bundle and owned window.
;; EXPORTS app_binding_form_open, app_binding_widget_member, app_binding_widget_window, app_binding_snapshot_source_allowed, app_binding_driver_snapshot_observe, app_binding_widget_finish, app_binding_policy_observe, app_binding_observe, app_binding_configure, app_binding_install, app_binding_retire, app_binding_policy, app_binding_validate, app_binding_resolve, app_binding_grant, app_binding_ask_validate, app_binding_snapshot_configure, app_binding_gui_policy, app_binding_snapshot_resolve
;; IMPORTS hv/app_vm, hv/guest_request, hv/guest_confirmation, svc/app_script, sec/app_grants, sec/session, gui/form_events, gui/form_loader, gui/app_launcher, gui/window_mgmt, gui/snapshot, svc/command, core/smp, core/time
;; OWNER saga:app_binding
;; CONTEXT: bsp_only
; Native-only, non-yielding. No caller-supplied digest/endpoint or proof callback.
; app_vm_snapshot MUST be the maintained actual READY/RUNNING instance accessor.
; This module neither boots a guest nor relabels the full driver VM.
AB_VM_BYTES equ 128
AB_SCRIPT_BYTES equ 384
AB_GRANT_BYTES equ 160
AB_CONTEXT_BYTES equ 104

; RDI=actual registered WAIT id. Explicit native initialization, depth0.
; Reconfiguration revokes old authority before replacing any callback.
app_binding_configure:
    push rbx
    mov rbx,rdi
    cmp byte [rel cmd_in_dispatch],0
    jne .bad
    mov byte [rel ab_configured],0
    call app_binding_retire
    lea rdi,[rel app_binding_validate]
    lea rsi,[rel guest_request_resume]
    call app_grants_configure
    lea rdi,[rel ab_policy_key]
    call app_grants_configure_scope
    cmp eax,1
    jne .clear
    lea rdi,[rel app_binding_ask_validate]
    lea rsi,[rel app_grants_ask]
    lea rdx,[rel app_grants_consume]
    call guest_request_configure_confirmation
    cmp eax,1
    jne .clear
    mov rdi,rbx
    lea rsi,[rel app_binding_grant]
    call guest_request_configure_wait
    cmp eax,1
    jne .clear
    lea rdi,[rel app_binding_resolve]
    call form_events_configure_guest
    cmp eax,1
    jne .clear
    mov byte [rel ab_configured],1
    mov eax,1
    pop rbx
    ret
.clear:
    xor edi,edi
    xor esi,esi
    call app_grants_configure
    xor edi,edi
    call form_events_configure_guest
    xor edi,edi
    xor esi,esi
    xor edx,edx
    call guest_request_configure_confirmation
.bad:
    xor eax,eax
    pop rbx
    ret

; RDI=actual app instance, RSI=current immutable handle, RDX=exact window id.
; Called by native launcher after READY identity and native form materialize,
; before activation. No requested grant is made effective by installing data.
app_binding_install:
    push rbx
    push r12
    push r13
    push r14
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    cmp byte [rel cmd_in_dispatch],0
    jne .bad
    cmp byte [rel ab_configured],1
    jne .bad
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .bad
    call app_binding_retire
    test r12,r12
    jz .bad
    test r13,r13
    jz .bad
    mov rax,r14
    shr rax,32
    jnz .bad
    mov rdi,r12
    lea rsi,[rel ab_vm]
    mov edx,AB_VM_BYTES
    call app_vm_snapshot
    cmp eax,1
    jne .bad
    cmp qword [rel ab_vm],1
    jne .bad
    cmp [rel ab_vm+56],r12
    jne .bad
    cmp [rel ab_vm+96],r13
    jne .bad
    cmp qword [rel ab_vm+112],0
    jne .bad
    cmp qword [rel ab_vm+120],0
    jne .bad
    mov rax,[rel ab_vm+8]
    cmp rax,PRIN_HOUSEHOLD
    jbe .bad
    cmp rax,WM_OWNER_CHROME
    je .bad
    lea rdx,[rel ab_vm]
    mov ecx,16
.ids:
    cmp qword [rdx+rcx],0
    je .bad
    add ecx,8
    cmp ecx,64
    jb .ids
    cmp qword [rel ab_vm+104],0
    je .bad
    lea rax,[rel guest_request_endpoint]
    cmp [rel ab_vm+16],rax
    je .bad                            ; driver identity is never an app proof
    mov rax,[rel session_authority_epoch]
    test rax,rax
    jz .bad
    cmp rax,-1
    je .bad
    cmp [rel ab_vm+40],rax
    jne .bad
    mov rdi,r13
    lea rsi,[rel ab_script]
    mov edx,AB_SCRIPT_BYTES
    call app_script_descriptor
    cmp eax,1
    jne .bad
    cmp qword [rel ab_script],1
    jne .bad
    cmp [rel ab_script+8],r13
    jne .bad
    lea rsi,[rel ab_vm+64]
    lea rdi,[rel ab_script+32]
    mov ecx,4
    repe cmpsq
    jne .bad
    mov rax,[rel ab_vm+64]
    or rax,[rel ab_vm+72]
    or rax,[rel ab_vm+80]
    or rax,[rel ab_vm+88]
    jz .bad
    mov [rel ab_instance],r12
    mov [rel ab_handle],r13
    mov [rel ab_window],r14
    movzx ebx,r14b
    cmp ebx,WM_MAX
    jae .bad
    mov edi,ebx
    call wmx_window_id
    cmp rax,r14
    jne .bad
    lea rax,[rel wm_gen]
    mov eax,[rax+rbx*4]
    test eax,eax
    jz .bad
    mov [rel ab_rawgen],rax
    mov edi,r14d
    call form_events_lifetime
    test rax,rax
    jz .bad
    mov [rel ab_reset],rax
    mov byte [rel ab_live],1
    call ab_current
    cmp eax,1
    jne .retire
    mov eax,1
    jmp .out
.retire:
    call app_binding_retire
.bad:
    xor eax,eax
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Invalidate first. Original lifecycle owns actual VM stop and form closure.
; Revocation is synchronous even when no request or WAIT is currently active.
app_binding_retire:
    push rbx
    push r12
    sub rsp,8
    mov byte [rel ab_live],0
    mov qword [rel ab_wait_receipt],0
    mov qword [rel ab_widget_receipt],0
    call ab_gui_revoke
    call app_grants_revoke
    mov edi,[rel ab_window]
    test edi,edi
    jz .no_window
    mov ebx,edi
    movzx edi,bl
    cmp edi,WM_MAX
    jae .no_window
    call wmx_window_id
    cmp eax,ebx
    jne .no_window
    movzx ebx,bl
    lea rax,[rel wm_gen]
    mov eax,[rax+rbx*4]
    cmp rax,[rel ab_rawgen]
    jne .no_window
    lea rax,[rel wm_owner]
    mov rax,[rax+rbx*8]
    cmp rax,[rel ab_vm+8]
    jne .no_window
    mov edi,ebx
    call form_events_reset
.no_window:
    mov r12d,1
.member:
    imul eax,r12d,24
    lea rbx,[rel ab_members]
    add rbx,rax
    mov rdi,[rbx]
    test rdi,rdi
    jz .next_member
    call ab_member_target
    test rax,rax
    jz .next_member
    movzx edi,al
    call form_events_reset
.next_member:
    inc r12d
    cmp r12d,4
    jb .member
    lea rdi,[rel ab_members]
    xor eax,eax
    mov ecx,4*24/8
    rep stosq
    mov qword [rel ab_instance],0
    mov qword [rel ab_handle],0
    mov qword [rel ab_window],0
    mov qword [rel ab_rawgen],0
    mov qword [rel ab_reset],0
    add rsp,8
    pop r12
    pop rbx
    ret

; Exact selected target after ab_current. Secondary records can be populated
; only through the verified native launcher below. Recheck the form core's own
; title/slot/owner/full generation identity AND nonwrapping event reset lifetime.
; RDI packed id -> RAX exact id, RDX raw32, RCX reset; zero on any mismatch.
ab_member_target:
    push rbx
    push r12
    push r13
    mov rbx,rdi
    test rbx,rbx
    jz .bad
    cmp rbx,[rel ab_window]
    jne .secondary
    mov rax,rbx
    mov rdx,[rel ab_rawgen]
    mov rcx,[rel ab_reset]
    jmp .out
.secondary:
    mov r12d,1
.next:
    imul eax,r12d,24
    lea r13,[rel ab_members]
    add r13,rax
    cmp rbx,[r13]
    jne .other
    mov edi,r12d
    call form_app_member_current
    cmp rax,rbx
    jne .bad
    cmp rdx,[rel ab_vm+8]
    jne .bad
    mov eax,ecx
    cmp rax,[r13+8]
    jne .bad
    mov rdi,rbx
    call form_events_lifetime
    test rax,rax
    jz .bad
    cmp rax,[r13+16]
    jne .bad
    mov rcx,rax
    mov rdx,[r13+8]
    mov rax,rbx
    jmp .out
.other:
    inc r12d
    cmp r12d,4
    jb .next
.bad:
    xor eax,eax
    xor edx,edx
    xor ecx,ecx
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Native grant-store key normalizer. Original target must pass full validation.
; Only policy lookup uses the primary key; original WAIT/ASK descriptors stay
; exact. Separate scratch avoids modifying ab_work during grant recursion.
ab_policy_key:
    push rbx
    mov rbx,rdi
    call app_binding_validate
    cmp eax,1
    jne .bad
    mov rsi,rbx
    lea rdi,[rel ab_key]
    mov ecx,AB_GRANT_BYTES/8
    cld
    rep movsq
    mov rax,[rel ab_window]
    mov [rel ab_key+56],rax
    mov rax,[rel ab_rawgen]
    mov [rel ab_key+64],rax
    mov rax,[rel ab_reset]
    mov [rel ab_key+72],rax
    lea rax,[rel ab_key]
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; RDI actual binding48, RSI bounded verified form name -> packed member id/0.
; Existing WAIT BEGIN ALLOW gate is rechecked before native materialization.
; New forms are staged; the widget adapter alone handles reveal/focus policy.
app_binding_form_open:
    push rbx
    push r12
    push r13
    push r14
    sub rsp,8
    xor ebx,ebx
    mov r12,rsi
    call app_binding_widget_window
    mov rbx,rdx
    test rax,rax
    jz .bad
    mov rdi,[rel ab_handle]
    mov rsi,r12
    call app_launcher_form_find
    cmp eax,4
    jae .bad
    test eax,eax
    jz .primary
    mov r13d,eax
    mov rdi,[rel ab_handle]
    mov rsi,[rel ab_vm+8]
    mov edx,r13d
    mov ecx,1
    call app_launcher_form_member
    test eax,eax
    jnz .bad
    mov edi,r13d
    call form_app_member_current
    test rax,rax
    jz .bad
    cmp rdx,[rel ab_vm+8]
    jne .bad
    mov r12,rax
    mov r14d,ecx
    mov rdi,rax
    call form_events_lifetime
    test rax,rax
    jz .bad
    mov [rsp],rax
    call ab_current
    mov rdx,[rsp]
    cmp eax,1
    jne .bad
    imul eax,r13d,24
    lea rdi,[rel ab_members]
    add rdi,rax
    mov [rdi],r12
    mov [rdi+8],r14
    mov [rdi+16],rdx
    mov rax,r12
    jmp .out
.primary:
    mov rax,[rel ab_window]
    jmp .out
.bad:
    xor eax,eax
.out:
    mov rdx,rbx                     ; original native policy receipt serial
    add rsp,8
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Native read-only actualness. Exact128 VM identity, exact384 verifier object,
; current owned packed id/full raw32 generation/nonwrapping reset lifetime.
; No grant API, request revalidation, dispatch, yield or guest entry occurs here.
ab_current:
    push rbx
    cmp byte [rel ab_live],1
    jne .bad
    cmp byte [rel session_locked],SESSION_UNLOCKED
    jne .bad
    cmp qword [rel session_key_handle],0
    je .bad
    mov rax,[rel session_bound_pid]
    test rax,rax
    jz .bad
    cmp rax,[rel ab_vm+48]
    jne .bad
    mov rax,[rel session_authority_epoch]
    test rax,rax
    jz .bad
    cmp rax,-1
    je .bad
    cmp rax,[rel session_authority]
    jne .bad
    mov rdi,[rel ab_instance]
    lea rsi,[rel ab_vm_check]
    mov edx,AB_VM_BYTES
    call app_vm_snapshot
    cmp eax,1
    jne .bad
    lea rsi,[rel ab_vm]
    lea rdi,[rel ab_vm_check]
    mov ecx,AB_VM_BYTES/8
    repe cmpsq
    jne .bad
    mov rdi,[rel ab_handle]
    lea rsi,[rel ab_script_check]
    mov edx,AB_SCRIPT_BYTES
    call app_script_native_descriptor
    cmp eax,1
    jne .bad
    lea rsi,[rel ab_script]
    lea rdi,[rel ab_script_check]
    mov ecx,AB_SCRIPT_BYTES/8
    repe cmpsq
    jne .bad
    mov ebx,[rel ab_window]
    movzx edi,bl
    call wmx_window_id
    cmp eax,ebx
    jne .bad
    movzx ebx,bl
    lea rax,[rel wm_owner]
    mov rax,[rax+rbx*8]
    cmp rax,[rel ab_vm+8]
    jne .bad
    lea rax,[rel wm_gen]
    mov eax,[rax+rbx*4]
    cmp rax,[rel ab_rawgen]
    jne .bad
    mov edi,[rel ab_window]
    call form_events_lifetime
    test rax,rax
    jz .bad
    cmp rax,[rel ab_reset]
    jne .bad
    mov rax,[rel session_authority_epoch]
    cmp rax,[rel ab_vm+40]
    jne .bad
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; Private160 template, identity only. Caller fills the typed operation and
; original operands from actual context_copy, or native OWNER policy choice.
ab_template:
    lea rdi,[rel ab_work]
    xor eax,eax
    mov ecx,AB_GRANT_BYTES/8
    rep stosq
    mov qword [rel ab_work],1
    mov rax,[rel ab_vm+8]
    mov [rel ab_work+8],rax
    mov [rel ab_work+48],rax
    mov rax,[rel ab_vm+16]
    mov [rel ab_work+16],rax
    mov rax,[rel ab_vm+24]
    mov [rel ab_work+24],rax
    mov rax,[rel ab_vm+32]
    mov [rel ab_work+32],rax
    mov rax,[rel ab_vm+40]
    mov [rel ab_work+40],rax
    mov rax,[rel ab_window]
    mov [rel ab_work+56],rax
    mov rax,[rel ab_rawgen]
    mov [rel ab_work+64],rax
    mov rax,[rel ab_reset]
    mov [rel ab_work+72],rax
    mov rax,[rel ab_instance]
    mov [rel ab_work+80],rax
    lea rsi,[rel ab_vm+64]
    lea rdi,[rel ab_work+88]
    mov ecx,4
    rep movsq
    ret

 ; Native-only public-field observation, not a policy or request API.
; RDI output120 ->1 current/0 unavailable. Never exports endpoint/host pointers.
; All fields come from the same live ab_current reconciliation.
app_binding_observe:
    push rbx
    mov rbx,rdi
    xor eax,eax
    mov ecx,15
    cld
    rep stosq
    call smp_current_logical
    test eax,eax
    jnz .bad
    cmp byte [rel cmd_in_dispatch],0
    jne .bad
    cmp dword [rel cmd_dispatch_depth],0
    jne .bad
    call ab_current
    cmp eax,1
    jne .bad
    mov qword [rbx],1
    mov rax,[rel ab_vm+8]
    mov [rbx+8],rax                 ; full enforced app principal
    mov rax,[rel ab_vm+24]
    mov [rbx+16],rax                ; START generation
    mov rax,[rel ab_vm+32]
    mov [rbx+24],rax                ; retirement generation
    mov rax,[rel ab_vm+40]
    mov [rbx+32],rax                ; owner epoch
    mov rax,[rel ab_window]
    mov [rbx+40],rax
    mov rax,[rel ab_rawgen]
    mov [rbx+48],rax
    mov rax,[rel ab_reset]
    mov [rbx+56],rax
    mov rax,[rel ab_instance]
    mov [rbx+64],rax                ; nonreused numeric instance, not address
    lea rsi,[rel ab_vm+64]
    lea rdi,[rbx+72]
    mov ecx,4
    rep movsq
    mov rax,[rel ag_generation]
    mov [rbx+104],rax
    call time_monotonic_now_us
    mov [rbx+112],rax
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; Proof-validator ABI only: RDI=private160 descriptor -> EAX1/0.
; May run outside an active request for pending ASK, policy and result-copy.
; Typed operand schema is separately checked by the maintained grant store.
app_binding_validate:
    push rbx
    mov rbx,rdi
    test rbx,rbx
    jz .bad
    call ab_current
    cmp eax,1
    jne .bad
    ; Compare with native facts without overwriting ab_work during recursion.
    cmp qword [rbx],1
    jne .bad
    mov rax,[rel ab_vm+8]
    cmp [rbx+8],rax
    jne .bad
    cmp [rbx+48],rax
    jne .bad
    mov rax,[rel ab_vm+16]
    cmp [rbx+16],rax
    jne .bad
    mov rax,[rel ab_vm+24]
    cmp [rbx+24],rax
    jne .bad
    mov rax,[rel ab_vm+32]
    cmp [rbx+32],rax
    jne .bad
    mov rax,[rel ab_vm+40]
    cmp [rbx+40],rax
    jne .bad
    mov rdi,[rbx+56]
    call ab_member_target
    test rax,rax
    jz .bad
    cmp [rbx+64],rdx
    jne .bad
    cmp [rbx+72],rcx
    jne .bad
    mov rax,[rel ab_instance]
    cmp [rbx+80],rax
    jne .bad
    lea rsi,[rel ab_vm+64]
    lea rdi,[rbx+88]
    mov ecx,4
    repe cmpsq
    jne .bad
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; RDI=exact maintained request. Copy native104 context, never trust callback
; context pointer or decode guest arguments/claims as native identity.
ab_request:
    push rbx
    mov rbx,rdi
    lea rsi,[rel ab_context]
    mov edx,AB_CONTEXT_BYTES
    call guest_request_context_copy
    test eax,eax
    jnz .bad
    call ab_current
    cmp eax,1
    jne .bad
    mov rax,[rel ab_vm+8]
    cmp [rel ab_context],rax
    jne .bad
    cmp qword [rel ab_context+8],0
    je .bad
    mov rax,[rel ab_vm+16]
    cmp [rel ab_context+16],rax
    jne .bad
    mov rax,[rel ab_vm+24]
    cmp [rel ab_context+24],rax
    jne .bad
    mov rax,[rel ab_vm+32]
    cmp [rel ab_context+32],rax
    jne .bad
    mov rax,[rel ab_vm+40]
    cmp [rel ab_context+40],rax
    jne .bad
    mov rdi,[rel ab_context+56]
    call ab_member_target
    test rax,rax
    jz .bad
    push rax
    push rdx
    push rcx
    call ab_template
    pop qword [rel ab_work+72]
    pop qword [rel ab_work+64]
    pop qword [rel ab_work+56]
    mov rax,[rel ab_context+48]
    mov [rel ab_work+120],rax
    mov rax,[rel ab_context+80]
    mov [rel ab_work+128],rax
    mov rax,[rel ab_context+88]
    mov [rel ab_work+136],rax
    mov rax,[rel ab_context+96]
    mov [rel ab_work+144],rax
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; Registered WAIT grant callback. EAX0 DENY/1 ALLOW/2 ASK, RDX generation.
; ASK freezes the original through the sole maintained continuation, never a
; resubmission. Input registers retained except documented RDX policy result.
app_binding_grant:
    push rbx
    push r12
    push rdi
    push rsi
    push rcx
    sub rsp,8
    mov qword [rsp],0
    mov rbx,rsi
    mov rdi,rsi
    call ab_request
    cmp eax,1
    jne .bad
    lea rdi,[rel ab_work]
    call app_grants_check
    call ab_policy_record_wait
    mov [rsp],rcx
    cmp eax,1
    je .out
    cmp eax,2
    jne .bad
    mov r12,rdx
    mov rdi,rbx
    lea rsi,[rel ab_work]
    call guest_request_defer
    test eax,eax
    jnz .bad
    mov rdx,r12
    mov eax,2
    jmp .out
.bad:
    xor eax,eax
    xor edx,edx
.out:
    mov rdi,[rsp]
    call ab_policy_finish_wait
    add rsp,8
    pop rcx
    pop rsi
    pop rdi
    pop r12
    pop rbx
    ret

; Handler resolver: exact request -> readonly160 and current policygen or0/0.
; The adapter still owns exact-request final revalidation immediately pre-effect.
app_binding_resolve:
    push rdi
    mov rsi,rdi
    call app_binding_grant
    test eax,eax
    jz .bad
    test rdx,rdx
    jz .bad
    lea rax,[rel ab_work]
    pop rdi
    ret
.bad:
    xor eax,eax
    xor edx,edx
    pop rdi
    ret

; Frozen ASK validation outside active request; no recursive request API.
app_binding_ask_validate:
    call app_grants_check
    cmp eax,2
    jne .bad
    test rdx,rdx
    jz .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    xor edx,edx
    ret

; Explicit native keyed OWNER policy action only: EDI op1..4, ESI policy0..2,
; RDX lifetime_us. This is never called from signed requested-grants metadata.
; Policy key excludes sequence/cursor/timeout; inert schema operands used solely
; for native policy configuration, not as an incoming invocation or approval.
app_binding_policy:
    push rbx
    push r12
    push r13
    mov ebx,edi
    mov r12d,esi
    mov r13,rdx
    cmp byte [rel cmd_in_dispatch],0
    jne .bad
    cmp ebx,1
    jb .bad
    cmp ebx,4
    ja .bad
    cmp r12d,2
    ja .bad
    call session_shell_local_authority
    test rax,rax
    jz .bad
    call ab_current
    cmp eax,1
    jne .bad
    call ab_template
    mov [rel ab_work+120],rbx
    mov qword [rel ab_work+128],1
    cmp ebx,3
    jb .no_token
    mov qword [rel ab_work+136],1
.no_token:
    lea rdi,[rel ab_work]
    mov esi,r12d
    mov rdx,r13
    call app_grants_set
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Guest widget text is tied to WAIT BEGIN ALLOW on this exact binding and window.
; RDI current binding48 -> RAX packed window, or0. ASK and DENY both refuse, no
; request is frozen, and policy and proof are rechecked on every call.
app_binding_widget_window:
    xor esi,esi
app_binding_widget_member:
    push rbx
    push r12
    push r13
    mov r13,rsi
    xor r12d,r12d
    mov rbx,rdi
    test rbx,rbx
    jz .bad
    call ab_current
    cmp eax,1
    jne .bad
    mov rax,[rel ab_vm+8]
    cmp [rbx],rax
    jne .bad
    mov rax,[rel ab_vm+16]
    cmp [rbx+16],rax
    jne .bad
    mov rax,[rel ab_vm+24]
    cmp [rbx+24],rax
    jne .bad
    mov rax,[rel ab_vm+32]
    cmp [rbx+32],rax
    jne .bad
    mov rax,[rel ab_vm+40]
    cmp [rbx+40],rax
    jne .bad
    call ab_template
    test r13,r13
    jz .target_ready
    mov rdi,r13
    call ab_member_target
    test rax,rax
    jz .bad
    mov [rel ab_work+56],rax
    mov [rel ab_work+64],rdx
    mov [rel ab_work+72],rcx
.target_ready:
    mov qword [rel ab_work+120],2
    mov qword [rel ab_work+128],1
    lea rdi,[rel ab_work]
    call app_grants_check
    call ab_policy_record_widget
    mov r12,rcx
    cmp eax,1
    jne .bad
    test rdx,rdx
    jz .bad
    mov qword [rel ab_widget_receipt+24*8],1
    mov rax,[rel ab_work+56]
    jmp .out
.bad:
    xor eax,eax
.out:
    mov rdx,r12                      ; passive same-invocation serial or0
    pop r13
    pop r12
    pop rbx
    ret

; Passive public effective-policy receipts, separate WAIT and widget slots.
; Common resolver capture preserves all documented policy return registers.
; Version stays0 until the actual admission/final handler path completes.
ab_policy_record_wait:
    lea rdi,[rel ab_wait_receipt]
    mov esi,1
    jmp ab_policy_record
ab_policy_record_widget:
    lea rdi,[rel ab_widget_receipt]
    mov esi,2
ab_policy_record:
    push rax
    push rdx
    push r8
    push r9
    push r10
    push rbx
    push r12
    mov rbx,rdi
    mov r12d,esi
    xor eax,eax
    mov ecx,28
    cld
    rep stosq
    cmp qword [rel ab_policy_serial],-1
    je .unavailable
    inc qword [rel ab_policy_serial]
    mov rax,[rel ab_policy_serial]
    mov [rbx+8],rax
    mov [rbx+16],r12
    mov rax,[rel ab_work+8]
    mov [rbx+3*8],rax
    mov rax,[rel ab_work+24]
    mov [rbx+4*8],rax
    mov rax,[rel ab_work+32]
    mov [rbx+5*8],rax
    mov rax,[rel ab_work+40]
    mov [rbx+6*8],rax
    mov rax,[rel ab_work+56]
    mov [rbx+7*8],rax
    mov rax,[rel ab_work+64]
    mov [rbx+8*8],rax
    mov rax,[rel ab_work+72]
    mov [rbx+9*8],rax
    mov rax,[rel ab_work+80]
    mov [rbx+10*8],rax
    mov rax,[rel ab_work+88]
    mov [rbx+11*8],rax
    mov rax,[rel ab_work+96]
    mov [rbx+12*8],rax
    mov rax,[rel ab_work+104]
    mov [rbx+13*8],rax
    mov rax,[rel ab_work+112]
    mov [rbx+14*8],rax
    mov rax,[rel ab_work+120]
    mov [rbx+15*8],rax
    cmp r12d,1
    jne .policy
    mov rax,[rel ab_work+128]
    mov [rbx+16*8],rax
.policy:
    mov rax,[rsp+48]                 ; original effective decision
    mov [rbx+18*8],rax
    mov rax,[rsp+32]                 ; exact resolver branch
    mov [rbx+19*8],rax
    mov rax,[rsp+40]                 ; actual resolver returned generation
    mov [rbx+20*8],rax
    mov rax,[rel ag_generation]
    mov [rbx+21*8],rax
    mov rax,[rsp+24]
    mov [rbx+22*8],rax
    mov rax,[rsp+16]
    mov [rbx+23*8],rax
    mov rcx,[rbx+8]
    jmp .out
.unavailable:
    xor ecx,ecx
.out:
    pop r12
    pop rbx
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rax
    ret

; RDI exact serial, EAX actual WAIT callback result; preserve EAX/RDX.
ab_policy_finish_wait:
    push rax
    push rdx
    test rdi,rdi
    jz .out
    cmp rdi,[rel ab_wait_receipt+8]
    jne .out
    mov [rel ab_wait_receipt+24*8],rax
    call time_monotonic_now_us
    mov [rel ab_wait_receipt+27*8],rax
    mov qword [rel ab_wait_receipt],1
.out:
    pop rdx
    pop rax
    ret

; RDI exact gate serial, ESI actual widget op, RDX original sequence,
; RCX original handler code. Metadata only; does not authorize any operation.
; Handler's EAX result is preserved. Zero/stale serial never reuses old policy.
app_binding_widget_finish:
    push rax
    test rdi,rdi
    jz .out
    cmp rdi,[rel ab_widget_receipt+8]
    jne .out
    cmp qword [rel ab_widget_receipt],0
    jne .out
    mov [rel ab_widget_receipt+16*8],rdx
    mov eax,esi
    mov [rel ab_widget_receipt+17*8],rax
    mov qword [rel ab_widget_receipt+25*8],1
    mov [rel ab_widget_receipt+26*8],rcx
    call time_monotonic_now_us
    mov [rel ab_widget_receipt+27*8],rax
    mov qword [rel ab_widget_receipt],1
.out:
    pop rax
    ret

; Native OWNER capture: RDI exact target digest32, RSI output448, always
; zero first. No resolver is called and no private endpoint/handle is copied.
; Retire clears both slots; serial is never reset across binding lifetimes.
app_binding_policy_observe:
    push rbx
    push r12
    push r13
    mov rbx,rdi
    mov r12,rsi
    mov rdi,rsi
    xor eax,eax
    mov ecx,56
    cld
    rep stosq
    call smp_current_logical
    test eax,eax
    jnz .out
    cmp byte [rel cmd_in_dispatch],0
    jne .out
    cmp dword [rel cmd_dispatch_depth],0
    jne .out
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .out
    mov r13,rdx
    lea r8,[rel ab_wait_receipt]
    call ab_policy_copy
    lea r8,[rel ab_widget_receipt]
    add r12,28*8
    call ab_policy_copy
.out:
    pop r13
    pop r12
    pop rbx
    ret
ab_policy_copy:
    cmp qword [r8],1
    jne .out
    cmp [r8+6*8],r13
    jne .out
    lea rdi,[r8+11*8]
    mov rsi,rbx
    mov ecx,4
    cld
    repe cmpsq
    jne .out
    mov rdi,r12
    mov rsi,r8
    mov ecx,28
    rep movsq
.out:
    ret

; Native gui.read is a distinct typed scope, never a WAIT operation/grant.
; One volatile original-window record, retired with this actual app binding.
; It grants no installation, egress, cloud or arbitrary desktop/active read.
app_binding_snapshot_configure:
    call smp_current_logical
    test eax,eax
    jnz ab_gui_bad
    cmp byte [rel cmd_in_dispatch],0
    jne ab_gui_bad
    lea rdi,[rel app_binding_snapshot_resolve]
    call snapshot_configure
    test eax,eax
    jz ab_gui_bad
    lea rdi,[rel app_binding_driver_snapshot_observe]
    jmp snapshot_configure_driver_observer

; Revoke first; generation saturates permanently. Producer owns its one buffer.
ab_gui_revoke:
    mov byte [rel ab_gui_policy],0
    mov qword [rel ab_gui_until],0
    cmp qword [rel ab_gui_generation],-1
    je .retire
    inc qword [rel ab_gui_generation]
.retire:
    jmp snapshot_retire
ab_gui_bad:
    xor eax,eax
    xor edx,edx
    ret

; Native keyed owner action at depth0: RDI original target32 from actual
; launcher getter (version,id,fullrawgen,fullowner), ESI0DENY/1ALLOW/2ASK,
; RDX bounded lifetime_us. ASK never queues/replays or reads a refused request.
app_binding_gui_policy:
    push rbx
    push r12
    push r13
    mov rbx,rdi
    mov r12d,esi
    mov r13,rdx
    call smp_current_logical
    test eax,eax
    jnz .bad
    cmp byte [rel cmd_in_dispatch],0
    jne .bad
    cmp r12d,2
    ja .bad
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .bad
    test r12d,r12d
    jz .deny                         ; saturation never prevents owner revocation
    cmp qword [rel ab_gui_generation],-2
    jae .bad
    test rbx,rbx
    jz .bad
    test r13,r13
    jz .bad
    cmp r13,AG_POLICY_MAX_US
    ja .bad
    call ab_current
    cmp eax,1
    jne .bad
    mov rdi,rbx
    call ab_gui_target_current
    cmp eax,1
    jne .bad
    mov rdi,[rel ab_vm+16]
    mov esi,[rel ab_vm+24]
    lea rdx,[rel ab_gui_probe]
    mov ecx,48
    call guest_request_binding_copy
    cmp eax,1
    jne .bad
    cmp qword [rel ab_gui_probe+8],0
    je .bad
    mov rax,[rel ab_vm+8]
    cmp [rel ab_gui_probe],rax
    jne .bad
    lea rdi,[rel ab_gui_probe+16]
    lea rsi,[rel ab_vm+16]
    mov ecx,4
    cld
    repe cmpsq
    jne .bad
    cmp qword [rel tsc_khz],0
    je .bad
    call time_monotonic_now_us
    test rax,rax
    jz .bad
    add r13,rax
    jc .bad
    call ab_gui_revoke
    mov rax,[rel session_key_handle]
    mov [rel ab_gui_key],rax
    mov [rel ab_gui_until],r13
    lea rdi,[rel ab_gui_target]
    mov rsi,rbx
    mov ecx,4
    rep movsq
    lea rdi,[rel ab_gui_binding]
    lea rsi,[rel ab_gui_probe]
    mov ecx,6
    rep movsq
    mov [rel ab_gui_policy],r12b
    mov eax,1
    jmp .out
.deny:
    call ab_gui_revoke
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

; RDI trusted target32. Full raw generation and owner, not packed-id alias.
ab_gui_target_current:
    push rbx
    mov rbx,rdi
    cmp qword [rbx],1
    jne .bad
    mov rax,[rbx+8]
    test rax,rax
    jz .bad
    shr rax,32
    jnz .bad
    mov rax,[rbx+16]
    test rax,rax
    jz .bad
    shr rax,32
    jnz .bad
    movzx edi,byte [rbx+8]
    cmp edi,WM_MAX
    jae .bad
    lea rax,[rel wm_state]
    cmp dword [rax+rdi*4],WM_VISIBLE
    je .visible
    cmp dword [rax+rdi*4],WM_MIN
    jne .bad
.visible:
    lea rax,[rel wm_no_history]
    cmp byte [rax+rdi],0
    jne .bad
    lea rax,[rel wm_owner]
    mov rax,[rax+rdi*8]
    cmp rax,WM_OWNER_CHROME
    je .bad
    cmp rax,[rbx+24]
    jne .bad
    lea rax,[rel wm_gen]
    mov eax,[rax+rdi*4]
    cmp rax,[rbx+16]
    jne .bad
    call wmx_window_id
    cmp rax,[rbx+8]
    jne .bad
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; The same actual enforced source route is exposed read-only. No request,
; guest assertion, app approval or SNAPSHOT context is accepted as identity.
app_binding_snapshot_source_allowed:
    xor eax,eax
    cmp rdi,2
    sete al
    ret
app_binding_driver_snapshot_observe:
    mov edi,1
    call app_binding_snapshot_source_allowed
    test eax,eax
    jnz .unavailable               ; future route needs its real policy observer
    mov rcx,[rel ab_gui_generation]
    test rcx,rcx
    jz .unavailable
    mov eax,1
    xor edx,edx                    ; DENY at the actual source guard
    mov r8d,1                      ; source unsupported, not permission proof
    ret
.unavailable:
    xor eax,eax
    ret
; Actual LIVE callback: caller's context pointer is not identity. Copy only
; through actual snapshot_context_copy(exactREQ), which validates its lifetime.
; Native owner is NOT projected inside the authenticated guest frame.
app_binding_snapshot_resolve:
    push rbx
    push r12
    mov rbx,rsi
    call smp_current_logical
    test eax,eax
    jnz .bad
    cmp byte [rel ab_gui_policy],0
    je .bad
    cmp qword [rel ab_gui_generation],-1
    je .bad
    mov rdi,rbx
    lea rsi,[rel ab_gui_context]
    mov edx,128
    call snapshot_context_copy
    test eax,eax
    jnz .bad
    mov rdi,[rel ab_gui_context+96]
    call app_binding_snapshot_source_allowed
    test eax,eax
    jz .bad                        ; driver VM never borrows an app approval
    cmp qword [rel ab_gui_context+48],3
    jne .bad                       ; no implicit desktop/active widening
    cmp qword [rel ab_gui_context+112],0
    jne .bad
    cmp qword [rel ab_gui_context+120],0
    jne .bad
    cmp qword [rel ab_gui_context+72],0
    je .bad
    mov rax,[rel ab_gui_context+80]
    test rax,rax
    jz .initial
    cmp rax,[rel ab_gui_generation]
    jne .bad
.initial:
    mov rax,[rel ab_gui_target+8]
    cmp [rel ab_gui_context+56],rax
    jne .bad
    mov rax,[rel ab_gui_target+16]
    cmp [rel ab_gui_context+64],rax
    jne .bad
    lea rdi,[rel ab_gui_context]
    lea rsi,[rel ab_gui_binding]
    mov ecx,6
    cld
    repe cmpsq
    jne .bad
    mov rax,[rel session_key_handle]
    cmp rax,[rel ab_gui_key]
    jne .retire
    call ab_current
    cmp eax,1
    jne .retire
    lea rdi,[rel ab_gui_target]
    call ab_gui_target_current
    cmp eax,1
    jne .retire
    cmp qword [rel tsc_khz],0
    je .retire
    call time_monotonic_now_us
    test rax,rax
    jz .retire
    cmp rax,[rel ab_gui_until]
    jae .retire
    ; LIVE also checks original binding at capture and every copy. Retain the
    ; same exact48 here so a coherent rebind never becomes a new authorization.
    mov rdi,[rel ab_vm+16]
    mov esi,[rel ab_vm+24]
    lea rdx,[rel ab_gui_probe]
    mov ecx,48
    call guest_request_binding_copy
    cmp eax,1
    jne .retire
    lea rdi,[rel ab_gui_probe]
    lea rsi,[rel ab_gui_binding]
    mov ecx,6
    repe cmpsq
    jne .retire
    movzx eax,byte [rel ab_gui_policy]
    mov rdx,[rel ab_gui_generation]
    jmp .out
.retire:
    ; No producer callback recursion from a policy callback; just retire the
    ; standing decision. LIVE's failing policy path retires its own read bytes.
    mov byte [rel ab_gui_policy],0
    mov qword [rel ab_gui_until],0
    cmp qword [rel ab_gui_generation],-1
    je .bad
    inc qword [rel ab_gui_generation]
.bad:
    xor eax,eax
    xor edx,edx
.out:
    pop r12
    pop rbx
    ret

%include "core/abi/wdata.inc"
%macro WDATA_sec_app_binding 0
ab_configured: db 0
ab_live: db 0
align 8
ab_instance: dq 0
ab_handle: dq 0
ab_window: dq 0
ab_rawgen: dq 0
ab_reset: dq 0
ab_policy_serial: dq 0
ab_gui_generation: dq 1
ab_gui_until: dq 0
ab_gui_key: dq 0
ab_gui_policy: db 0
%endmacro
WDATA_DEFER WDATA_sec_app_binding
%macro WDATA_BSS_sec_app_binding 0
ab_vm: resb AB_VM_BYTES
ab_vm_check: resb AB_VM_BYTES
ab_script: resb AB_SCRIPT_BYTES
ab_script_check: resb AB_SCRIPT_BYTES
ab_work: resb AB_GRANT_BYTES
ab_key: resb AB_GRANT_BYTES
ab_members: resb 4*24
ab_context: resb AB_CONTEXT_BYTES
ab_gui_target: resb 32
ab_gui_binding: resb 48
ab_gui_probe: resb 48
ab_gui_context: resb 128
alignb 8
ab_wait_receipt: resq 28
ab_widget_receipt: resq 28
%endmacro
WDATA_BSS_DEFER WDATA_BSS_sec_app_binding
