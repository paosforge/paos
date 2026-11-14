;; MODULE sec/terminal_policy
;; LAYER 6
;; PURPOSE Terminal B final native four-tier policy, scoped consent and one action.
;; EXPORTS terminal_policy_configure, terminal_policy_init, terminal_policy_check, terminal_policy_effect, terminal_policy_copyout, terminal_policy_grant, terminal_policy_revoke, terminal_policy_pending, terminal_policy_approve, terminal_policy_audit_copy
;; IMPORTS core/time, core/smp, sec/session, sec/principal, svc/command
;; OWNER saga:terminal_policy
;; CONTEXT: bsp_only
%include "sec/terminal_policy.inc"
%include "core/abi/wdata.inc"
; This module is composed once. Native plan/validate/execute callbacks are
; mandatory proof boundaries, not guest-installable extensions. Missing denies.
%macro TP_SAVE_VOL 0
    pushfq
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
%endmacro
%macro TP_RESTORE_VOL 0
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    popfq
%endmacro

 ; Native configuration/inspection cannot run on an AP or within any registry
; authorization/handler frame. Preserve all API input registers across BSP proof.
tp_native_idle:
    cmp byte [rel tp_busy],0
    jne .bad
    cmp dword [rel cmd_dispatch_depth],0
    jne .bad
    cmp byte [rel command_auth_remote_active],0
    jne .bad
    push rdi
    push rsi
    push rdx
    push rcx
    push r8
    push r9
    push r10
    push r11
    call smp_current_logical
    pop r11
    pop r10
    pop r9
    pop r8
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

; configure(RDI native [plan,validate,execute,indicator])->1/0 at depth0.
; plan(RDI request1088,RSI desc256)->1, writes only operation/operand fields.
; validate(RDI frozen desc256)->1: actual final target/scope/secret predicate.
; execute(RDI desc,RSI private out65536,RDX original request1088,ECX65536)
;   ->EAX CMDE0..255,EDX length; shared registry, original TERM principal.
; indicator()->1 only if *current grant generation* is continuously presented.
terminal_policy_configure:
    push rbx
    mov rbx,rdi
    call tp_native_idle
    test eax,eax
    jz .bad
    cmp byte [rel tp_busy],0
    jne .bad
    cmp byte [rel cmd_in_dispatch],0
    jne .bad
    cmp byte [rel command_auth_remote_active],0
    jne .bad
    call terminal_policy_invalidate
    lea rdi,[rel tp_ops]
    xor eax,eax
    mov ecx,4
    rep stosq
    test rbx,rbx
    jz .bad
    mov ecx,4
    mov rsi,rbx
.scan:
    lodsq
    test rax,rax
    jz .bad
    loop .scan
    mov rsi,rbx
    lea rdi,[rel tp_ops]
    mov ecx,4
    rep movsq
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop rbx
    ret

; init(RDI actual native transport endpoint), depth0 native composition only.
; Caller installs four SEC callbacks in VM and configures native adapters.
; We do not overwrite session's existing Wi-Fi private-buffer eraser.
terminal_policy_init:
    push rbx
    mov rbx,rdi
    call tp_native_idle
    test eax,eax
    jz .bad
    cmp byte [rel tp_busy],0
    jne .bad
    cmp byte [rel cmd_in_dispatch],0
    jne .bad
    cmp byte [rel command_auth_remote_active],0
    jne .bad
    call terminal_policy_invalidate
    mov [rel tp_endpoint],rbx
    lea rdi,[rel terminal_policy_invalidate]
    call session_shell_register_terminal_retire
    test rbx,rbx
    jz .bad
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop rbx
    ret

; Closed op vocabulary. Registry metadata never grants authority.
tp_tier:
    mov rax,[rdi+TP_D_OP]
    cmp rax,TP_CATALOG
    jb .bad
    cmp rax,TP_PUBLIC_VALUE
    jbe .one
    cmp rax,TP_DESKTOP
    jb .bad
    cmp rax,TP_FOLDER_READ
    jbe .two
    cmp rax,TP_FILL
    jb .bad
    cmp rax,TP_INSTALL
    jbe .three
.bad:
    xor eax,eax
    ret
.one:
    mov eax,1
    ret
.two:
    mov eax,2
    ret
.three:
    mov eax,3
    ret

; Exact scopes, no textual path-prefix or generic whole-volume authority.
tp_scope_valid:
    cmp qword [rdi+TP_S_VERSION],1
    jne .bad
    cmp qword [rdi+TP_S_OP],TP_DESKTOP
    jb .bad
    cmp qword [rdi+TP_S_OP],TP_FOLDER_READ
    ja .bad
    cmp qword [rdi+TP_S_ID],0
    je .bad
    cmp qword [rdi+40],0
    jne .bad
    mov rax,[rdi+112]
    or rax,[rdi+120]
    jnz .bad
    ; Native full target generation required for exact-window grants.
    cmp qword [rdi+TP_S_OP],TP_WINDOW
    je .target
    cmp qword [rdi+TP_S_OP],TP_UI_READ
    jne .key
.target:
    cmp qword [rdi+TP_S_TARGET],0
    je .bad
    cmp qword [rdi+TP_S_GEN],0
    je .bad
.key:
    mov rax,[rdi+48]
    or rax,[rdi+56]
    or rax,[rdi+64]
    or rax,[rdi+72]
    or rax,[rdi+80]
    or rax,[rdi+88]
    or rax,[rdi+96]
    or rax,[rdi+104]
    jz .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Native human grant only. Durable save/restore belongs BOOT and GUI; this
; changes RAM immediately, does not claim a verified firmware write.
terminal_policy_grant:
    push rbx
    push r12
    push r13
    push r14
    mov rbx,rdi
    mov r12,rsi
    call tp_native_idle
    test eax,eax
    jz .bad
    cmp byte [rel tp_busy],0
    jne .bad
    cmp byte [rel cmd_in_dispatch],0
    jne .bad
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .bad
    cmp rdx,r12
    jne .bad
    call tp_binding_live
    test eax,eax
    jz .bad
    mov rdi,rbx
    call tp_scope_valid
    test eax,eax
    jz .bad
    cmp qword [rel tp_generation],-2
    jae .bad
    xor r13d,r13d                     ; first unused slot, if no replacement
    lea r14,[rel tp_scopes]
    mov r8d,TP_SCOPE_MAX
.scan:
    cmp qword [r14],0
    jne .occupied
    test r13,r13
    jnz .next
    mov r13,r14
    jmp .next
.occupied:
    mov rax,[rbx+TP_S_ID]
    cmp rax,[r14+TP_S_ID]
    je .replace
    cmp qword [rbx+TP_S_OP],TP_FOLDER_READ
    jne .next
    cmp qword [r14+TP_S_OP],TP_FOLDER_READ
    je .replace                      ; at most one owner-picked root
.next:
    add r14,TP_SCOPE_BYTES
    dec r8d
    jnz .scan
    test r13,r13
    jz .bad
    jmp .found
.replace:
    mov r13,r14
.found:
    ; Copy before deleting conflicts, including an input aliased to an old
    ; native row. An ID collision must not leave a second picked-folder grant.
    sub rsp,TP_SCOPE_BYTES
    mov rsi,rbx
    mov rdi,rsp
    mov ecx,TP_SCOPE_BYTES/8
    rep movsq
    mov rbx,rsp
    call terminal_policy_retire
    mov qword [rel tp_saved],0
    inc qword [rel tp_generation]
    lea r14,[rel tp_scopes]
    mov r8d,TP_SCOPE_MAX
.conflicts:
    cmp qword [r14],0
    je .keep
    mov rax,[rbx+TP_S_ID]
    cmp rax,[r14+TP_S_ID]
    je .erase
    cmp qword [rbx+TP_S_OP],TP_FOLDER_READ
    jne .keep
    cmp qword [r14+TP_S_OP],TP_FOLDER_READ
    jne .keep
.erase:
    mov rdi,r14
    xor eax,eax
    mov ecx,TP_SCOPE_BYTES/8
    rep stosq
.keep:
    add r14,TP_SCOPE_BYTES
    dec r8d
    jnz .conflicts
    mov rsi,rbx
    mov rdi,r13
    mov ecx,TP_SCOPE_BYTES/8
    rep movsq
    mov edi,TP_EV_GRANT
    mov rsi,[rbx+TP_S_OP]
    mov rcx,[rbx+TP_S_ID]
    mov rdi,rsp
    xor eax,eax
    mov r9d,esi
    mov ecx,TP_SCOPE_BYTES/8
    rep stosq
    add rsp,TP_SCOPE_BYTES
    mov esi,r9d
    mov edi,TP_EV_GRANT
    mov rcx,[r13+TP_S_ID]
    xor edx,edx
    call tp_audit
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Synchronous negative authority change. Keeps counters/nonreused binding.
; Register/flags preserving for lock/STOP/effect-boundary notification.
terminal_policy_revoke:
    TP_SAVE_VOL
    call terminal_policy_retire
    mov qword [rel tp_saved],0
    lea rdi,[rel tp_scopes]
    xor eax,eax
    mov ecx,TP_SCOPE_BYTES*TP_SCOPE_MAX/8
    rep stosq
    cmp qword [rel tp_generation],-1
    je .logged
    inc qword [rel tp_generation]
.logged:
    mov edi,TP_EV_REVOKE
    xor esi,esi
    xor edx,edx
    xor ecx,ecx
    call tp_audit
    TP_RESTORE_VOL
    ret

; Structural and actual native object validation. Never calls ambient OWNER.
tp_validate:
    push rbx
    mov rbx,rdi
    call tp_binding_live
    test eax,eax
    jz .bad
    cmp qword [rel tp_generation],-1
    je .bad
    cmp qword [rbx+TP_D_VERSION],1
    jne .bad
    mov rax,[rel tp_pid]
    cmp rax,[rbx+TP_D_PID]
    jne .bad
    mov rax,[rel tp_serial]
    cmp rax,[rbx+TP_D_BIND]
    jne .bad
    mov eax,[rel tp_start]
    cmp rax,[rbx+TP_D_START]
    jne .bad
    mov rax,[rel tp_epoch]
    cmp rax,[rbx+TP_D_VM]
    jne .bad
    mov rax,[rel tp_session]
    cmp rax,[rbx+TP_D_SESSION]
    jne .bad
    mov rax,[rel tp_generation]
    cmp rax,[rbx+TP_D_POLICY]
    jne .bad
    cmp qword [rbx+TP_D_PROTECTED],0
    jne .bad                         ; tier4 overrides EVERY grant/click
    cmp qword [rbx+TP_D_ARGLEN],1023
    ja .bad
    cmp qword [rbx+TP_D_SEQ],0
    je .bad
    lea rdi,[rbx+TP_D_RESERVED]
    mov ecx,5
    xor eax,eax
.reserved:
    or rax,[rdi]
    add rdi,8
    loop .reserved
    test rax,rax
    jnz .bad
    mov rdi,rbx
    call tp_tier
    test eax,eax
    jz .bad                         ; unknown is not a fourth-tier workaround
    cmp qword [rel tp_ops+8],0
    je .bad
    call time_monotonic_now_us
    test rax,rax
    jz .bad
    cmp rax,[rbx+TP_D_UNTIL]
    jae .bad
    mov rdi,rbx
    call [rel tp_ops+8]              ; actual resolved-object/operand proof
    cmp eax,1
    jne .bad
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop rbx
    ret

; Internal exact descriptor currently owned by SEC. A forged copy cannot
; replace the frozen final operation or arguments after an approval.
tp_owned:
    push rbx
    mov rbx,rdi
    lea rsi,[rel tp_desc]
    cmp byte [rel tp_busy],1
    je .compare
    cmp byte [rel tp_result_valid],1
    jne .bad
    lea rsi,[rel tp_result_desc]
.compare:
    mov ecx,TP_DESC_BYTES/8
    repe cmpsq
    jne .bad
    mov rdi,rbx
    call tp_validate
    jmp .out
.bad:
    xor eax,eax
.out:
    pop rbx
    ret

; check(desc)->1 authorized now; checking never spends a physical click.
terminal_policy_check:
    push rbx
    mov rbx,rdi
    call tp_owned
    test eax,eax
    jz .bad
    mov rdi,rbx
    call tp_tier
    cmp eax,1
    je .allow
    cmp eax,2
    je .read
    ; During original continuation only: approved exact descriptor or already
    ; consumed effect, never a blanket temporary OWNER capability.
    cmp byte [rel tp_busy],1
    jne .result
    cmp byte [rel tp_effect_spent],1
    je .allow
    cmp byte [rel tp_pending_state],2
    jne .bad
    mov rdi,rbx
    lea rsi,[rel tp_pending_desc]
    mov ecx,TP_DESC_BYTES/8
    repe cmpsq
    jne .bad
    jmp .allow
.result:
    ; Only frozen result bytes of an already-consumed action are readable.
    cmp byte [rel tp_result_spent],1
    jne .bad
    jmp .allow
.read:
    mov rdi,rbx
    call tp_scope_match
    test eax,eax
    jz .bad
    cmp qword [rel tp_ops+24],0
    je .bad
    call [rel tp_ops+24]
    cmp eax,1
    jne .bad
.allow:
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop rbx
    ret

; Descriptor grant match uses exact op/scope/target/generation/identity64.
tp_scope_match:
    push rbx
    push r12
    mov rbx,rdi
    lea r12,[rel tp_scopes]
    mov r8d,TP_SCOPE_MAX
.scan:
    cmp qword [r12],1
    jne .next
    mov rax,[rbx+TP_D_OP]
    cmp rax,[r12+TP_S_OP]
    jne .next
    mov rax,[rbx+TP_D_SCOPE]
    cmp rax,[r12+TP_S_ID]
    jne .next
    ; Window/UI grants name one exact lifetime. Desktop/active and FS grants
    ; name a capability/root identity; validator proves the current object is
    ; within that scope and secret exclusions independently at every check.
    cmp qword [rbx+TP_D_OP],TP_WINDOW
    je .exact_target
    cmp qword [rbx+TP_D_OP],TP_UI_READ
    jne .identity
.exact_target:
    mov rax,[rbx+TP_D_TARGET]
    cmp rax,[r12+TP_S_TARGET]
    jne .next
    mov rax,[rbx+TP_D_TARGETGEN]
    cmp rax,[r12+TP_S_GEN]
    jne .next
.identity:
    lea rdi,[rbx+TP_D_SCOPEKEY]
    lea rsi,[r12+TP_S_KEY]
    mov ecx,8
    repe cmpsq
    je .yes
.next:
    add r12,TP_SCOPE_BYTES
    dec r8d
    jnz .scan
    xor eax,eax
    jmp .out
.yes:
    mov eax,1
.out:
    pop r12
    pop rbx
    ret

; Handler must call this at the actual native effect site, without a yield
; before the effect. One mutation per frozen request; spend precedes callback.
terminal_policy_effect:
    push rbx
    mov rbx,rdi
    cmp byte [rel tp_busy],1
    jne .bad
    cmp byte [rel tp_effect_spent],0
    jne .bad
    call terminal_policy_check
    test eax,eax
    jz .bad
    mov rdi,rbx
    call tp_tier
    cmp eax,3
    jne .read
    mov byte [rel tp_effect_spent],1
    mov byte [rel tp_pending_state],0
    mov edi,TP_EV_CONSUME
    mov rsi,[rbx+TP_D_OP]
    mov rcx,[rbx+TP_D_SCOPE]
    xor edx,edx
    call tp_audit
.read:
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop rbx
    ret

; No secret release on any failure. Caller wipes its own private staging too.
terminal_policy_copyout:
    call terminal_policy_check
    test eax,eax
    jnz .out
    call terminal_policy_retire
    xor eax,eax
.out:
    ret

; pending(out256)->opaque id and frozen descriptor copy, no borrowed storage.
terminal_policy_pending:
    push rbx
    mov rbx,rdi
    cmp byte [rel tp_pending_state],0
    je .bad
    lea rdi,[rel tp_pending_desc]
    call tp_validate
    test eax,eax
    jz .cancel
    test rbx,rbx
    jz .bad
    mov rdi,rbx
    lea rsi,[rel tp_pending_desc]
    mov ecx,TP_DESC_BYTES/8
    rep movsq
    mov rax,[rel tp_pending_id]
    jmp .out
.cancel:
    call terminal_policy_retire
.bad:
    xor eax,eax
.out:
    pop rbx
    ret

; Native HUMAN chrome only. LIVE proves the physical click, current rendered
; prompt and input provenance. Local authority excludes injected/remote frame.
terminal_policy_approve:
    push rbx
    push r12
    mov rbx,rdi
    mov r12,rsi
    call tp_native_idle
    test eax,eax
    jz .bad
    cmp byte [rel cmd_in_dispatch],0
    jne .bad
    cmp byte [rel tp_busy],0
    jne .bad
    cmp byte [rel tp_pending_state],1
    jne .bad
    cmp rbx,[rel tp_pending_id]
    jne .bad
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .bad
    cmp rdx,r12
    jne .bad
    lea rdi,[rel tp_pending_desc]
    call tp_validate
    test eax,eax
    jz .bad
    mov byte [rel tp_pending_state],2
    mov eax,1
    jmp .out
.bad:
    call terminal_policy_retire
    xor eax,eax
.out:
    pop r12
    pop rbx
    ret

; Bounded RAM audit: no argument/text/digest/secret/target values. Coalesce
; adjacent identical event/PID/op/code and account overwritten records.
tp_audit:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    mov r15,rcx
    mov edi,0x0d000401             ; VERB / INFO / Terminal producer reason
    cmp r12d,TP_EV_ALLOW
    jne .audit_refuse
    mov edi,0x0d000101             ; ALLOWED only after synchronous result
.audit_refuse:
    cmp r12d,TP_EV_REFUSE
    jne .audit_shared
    mov edi,0x0d000201
.audit_shared:
    mov eax,r12d
    and eax,255
    shl eax,16
    or edi,eax
    mov rsi,[rel tp_pid]          ; TERM never stored as verified OWNER
    mov edx,r13d
    shl edx,8
    or dl,r14b
    call audit_sec_event          ; existing spine folds foreign principal
    mov rax,[rel tp_audit_count]
    test rax,rax
    jz .new
    dec rax
    and eax,TP_AUDIT_ROWS-1
    imul eax,TP_AUDIT_ROW
    lea rbx,[rel tp_audit_rows]
    add rbx,rax
    cmp r12,[rbx]
    jne .new
    mov rax,[rel tp_pid]
    cmp rax,[rbx+8]
    jne .new
    cmp r13,[rbx+16]
    jne .new
    cmp r14,[rbx+24]
    jne .new
    cmp r15,[rbx+56]
    jne .new
    mov rax,[rel tp_generation]
    cmp rax,[rbx+64]
    jne .new
    cmp qword [rbx+40],-1
    je .out
    inc qword [rbx+40]
    jmp .out
.new:
    cmp qword [rel tp_audit_count],-1
    je .dropped
    mov rax,[rel tp_audit_count]
    and eax,TP_AUDIT_ROWS-1
    imul eax,TP_AUDIT_ROW
    lea rbx,[rel tp_audit_rows]
    add rbx,rax
    cmp qword [rel tp_audit_count],TP_AUDIT_ROWS
    jb .record
.dropped:
    cmp qword [rel tp_audit_drops],-1
    je .record
    inc qword [rel tp_audit_drops]
.record:
    cmp qword [rel tp_audit_count],-1
    je .out
    mov [rbx],r12
    mov rax,[rel tp_pid]
    mov [rbx+8],rax
    mov [rbx+16],r13
    mov [rbx+24],r14
    mov rax,[rel tp_floor]
    mov [rbx+32],rax
    mov qword [rbx+40],1
    call time_monotonic_now_us
    mov [rbx+48],rax
    mov [rbx+56],r15
    mov rax,[rel tp_generation]
    mov [rbx+64],rax
    mov qword [rbx+72],0
    inc qword [rel tp_audit_count]
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

terminal_policy_audit_copy:
    push rbx
    mov rbx,rdi
    cmp esi,TP_AUDIT_BYTES
    jne .bad
    test rbx,rbx
    jz .bad
    call tp_native_idle
    test eax,eax
    jz .bad
    cmp byte [rel cmd_in_dispatch],0
    jne .bad
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .bad
    mov rdi,rbx
    xor eax,eax
    mov ecx,TP_AUDIT_BYTES/8
    rep stosq
    mov qword [rbx],1
    mov rax,[rel tp_audit_count]
    mov [rbx+8],rax
    mov rax,[rel tp_audit_drops]
    mov [rbx+16],rax
    lea rdi,[rbx+64]
    lea rsi,[rel tp_audit_rows]
    mov ecx,TP_AUDIT_ROWS*TP_AUDIT_ROW/8
    rep movsq
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop rbx
    ret

%include "sec/terminal_consent_adapter.asm"
%include "sec/terminal_command.asm"
%include "sec/terminal_native.asm"
%include "sec/terminal_binding.asm"
%include "sec/terminal_dispatch.asm"
%macro WDATA_terminal_policy 0
align 8
tp_ops: times 4 dq 0
tp_prepare_op: dq 0
tp_save_op: dq 0
tp_load_op: dq 0
tp_clear_op: dq 0
tp_restore_validate_op: dq 0
tp_provider_retire_op: dq 0
tp_restore_binding: dq 0
tp_saved: dq 0
tp_endpoint: dq 0
tp_epoch: dq 1
tp_serial: dq 0
tp_pid: dq 0
tp_session: dq 0
tp_floor: dq 0
tp_generation: dq 1
tp_pending_serial: dq 0
tp_pending_id: dq 0
tp_result_id: dq 0
tp_result_len: dq 0
tp_audit_count: dq 0
tp_audit_drops: dq 0
tp_start: dd 0
tp_busy: db 0
tp_pending_state: db 0
tp_effect_spent: db 0
tp_result_spent: db 0
tp_result_valid: db 0
%endmacro
WDATA_DEFER WDATA_terminal_policy
%macro WDATA_terminal_policy_bss 0
alignb 8
tp_scopes: resb TP_SCOPE_MAX*TP_SCOPE_BYTES
tp_save_rows: resb TP_SCOPE_MAX*TP_SCOPE_BYTES
tp_desc: resb TP_DESC_BYTES
tp_request: resb TP_WIRE_BYTES
tp_pending_desc: resb TP_DESC_BYTES
tp_pending_request: resb TP_WIRE_BYTES
tp_result_desc: resb TP_DESC_BYTES
tp_result: resb TP_RESULT_BYTES
tp_audit_rows: resb TP_AUDIT_ROWS*TP_AUDIT_ROW
%endmacro
WDATA_BSS_DEFER WDATA_terminal_policy_bss
