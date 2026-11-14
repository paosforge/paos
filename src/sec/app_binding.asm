;; MODULE sec/app_binding
;; LAYER 6
;; PURPOSE Resolve actual isolated app VM, immutable bundle and owned window.
;; EXPORTS app_binding_configure, app_binding_install, app_binding_retire, app_binding_policy, app_binding_validate, app_binding_resolve, app_binding_grant, app_binding_ask_validate, app_binding_snapshot_configure, app_binding_gui_policy, app_binding_snapshot_resolve
;; IMPORTS hv/app_vm, hv/guest_request, hv/guest_confirmation, svc/app_script, sec/app_grants, sec/session, gui/form_events, gui/window_mgmt, gui/snapshot, svc/command, core/smp, core/time
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
    mov byte [rel ab_live],0
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
    mov qword [rel ab_instance],0
    mov qword [rel ab_handle],0
    mov qword [rel ab_window],0
    mov qword [rel ab_rawgen],0
    mov qword [rel ab_reset],0
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
    mov rax,[rel ab_window]
    cmp [rbx+56],rax
    jne .bad
    mov rax,[rel ab_rawgen]
    cmp [rbx+64],rax
    jne .bad
    mov rax,[rel ab_reset]
    cmp [rbx+72],rax
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
    mov rax,[rel ab_window]
    cmp [rel ab_context+56],rax
    jne .bad
    call ab_template
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
    mov rbx,rsi
    mov rdi,rsi
    call ab_request
    cmp eax,1
    jne .bad
    lea rdi,[rel ab_work]
    call app_grants_check
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
    push rbx
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
    mov qword [rel ab_work+120],2
    mov qword [rel ab_work+128],1
    lea rdi,[rel ab_work]
    call app_grants_check
    cmp eax,1
    jne .bad
    test rdx,rdx
    jz .bad
    mov rax,[rel ab_window]
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
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
    jmp snapshot_configure

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
    cmp qword [rel ab_gui_context+96],2
    jne .bad                       ; driver VM never borrows an app approval
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
ab_context: resb AB_CONTEXT_BYTES
ab_gui_target: resb 32
ab_gui_binding: resb 48
ab_gui_probe: resb 48
ab_gui_context: resb 128
%endmacro
WDATA_BSS_DEFER WDATA_BSS_sec_app_binding
