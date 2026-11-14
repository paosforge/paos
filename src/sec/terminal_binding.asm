;; MODULE sec/terminal_binding
;; LAYER 6
;; PURPOSE Native driver-only TERMINAL lifetime, independent of app WAIT binding.
;; EXPORTS terminal_policy_probe, terminal_policy_invalidate
;; IMPORTS sec/session, core/smp, hv/driver_domain
;; OWNER saga:terminal_policy
;; CONTEXT: bsp_only
; Included by terminal_policy.asm. Configured endpoint is a native runtime LEA,
; never a pointer received over TRM1. No standing capability or OWNER swap.
tp_driver_live:
    push rdi
    push rsi
    call smp_current_logical
    pop rsi
    pop rdi
    test eax,eax
    jnz .bad
    test rdi,rdi
    jz .bad
    cmp rdi,[rel tp_endpoint]
    jne .bad
    test esi,esi
    jz .bad
    cmp esi,[rel hv_linux_start_gen]
    jne .bad
    cmp esi,[rel hv_linux_start_consumed]
    jne .bad
    cmp byte [rel hv_linux_running],1
    jne .bad
    cmp byte [rel hv_linux_run_req],0
    jne .bad
    cmp byte [rel hv_linux_stop_req],0
    jne .bad
    cmp dword [rel vcb_handoff_active],0
    jne .bad
    cmp byte [rel session_locked],SESSION_UNLOCKED
    jne .bad
    cmp qword [rel session_key_handle],0
    je .bad
    cmp qword [rel session_bound_pid],PRIN_OWNER
    jne .bad
    mov rax,[rel session_authority_epoch]
    test rax,rax
    jz .bad
    cmp rax,-1
    je .bad
    cmp rax,[rel session_authority]
    jne .bad
    cmp qword [rel tp_epoch],-1
    je .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Current binding only; never creates one during effect/copyout.
tp_binding_live:
    lea rdi,[rel tp_endpoint]
    mov rdi,[rdi]
    mov esi,[rel tp_start]
    call tp_driver_live
    test eax,eax
    jz .bad
    cmp qword [rel tp_pid],0
    je .bad
    mov rax,[rel tp_session]
    cmp rax,[rel session_authority_epoch]
    jne .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Transport probe. Can bind only at a native, non-dispatch vCPU boundary.
; A different START/session first erases old authority; counter never wraps.
terminal_policy_probe:
    push rbx
    push r12
    mov rbx,rdi
    mov r12d,esi
    call tp_driver_live
    test eax,eax
    jz .retire
    cmp r12d,[rel tp_start]
    jne .bind
    mov rax,[rel session_authority_epoch]
    cmp rax,[rel tp_session]
    jne .bind
    mov rax,[rel tp_pid]
    test rax,rax
    jnz .out
.bind:
    cmp byte [rel tp_busy],0
    jne .retire
    cmp byte [rel cmd_in_dispatch],0
    jne .retire
    cmp byte [rel command_auth_remote_active],0
    jne .retire
    call terminal_policy_invalidate
    cmp qword [rel tp_serial],0x7fffffff
    jae .bad
    cmp qword [rel tp_epoch],-1
    je .bad
    inc qword [rel tp_serial]
    mov rax,[rel tp_serial]
    mov rdx,0x5445524d00000000         ; TERM class, not PRIN_OWNER/SYSTEM/app
    or rax,rdx
    mov [rel tp_pid],rax
    mov [rel tp_start],r12d
    mov rdx,[rel session_authority_epoch]
    mov [rel tp_session],rdx
    ; No remembered live authority is revived here. BOOT/LIVE restore exact
    ; authenticated selections explicitly after fresh binding and presentation.
    ; Authenticated reboot selections are native-only and independently proved
    ; against this fresh instance. Missing provider/store keeps grants empty.
    cmp byte [rel tpn_auto_restore],1
    jne .restored
    mov rdi,[rel session_authority]
    call terminal_policy_restore
.restored:
    mov rax,[rel tp_pid]
    ; Transport and policy floors survive every bind/retire/configuration.
    jmp .out
.retire:
    call terminal_policy_invalidate
.bad:
    xor eax,eax
.out:
    pop r12
    pop rbx
    ret

; Session lock, owner reset and native START/STOP call before publication/yield.
; Preserve registers/flags for original VM retirement seam.
terminal_policy_invalidate:
    pushfq
    push rax
    push rcx
    push rdi
    call terminal_policy_revoke
    mov qword [rel tp_pid],0
    mov qword [rel tp_session],0
    mov dword [rel tp_start],0
    cmp qword [rel tp_epoch],-1
    je .done
    inc qword [rel tp_epoch]
.done:
    pop rdi
    pop rcx
    pop rax
    popfq
    ret
