;; MODULE sec/data_config_local
;; LAYER 5
;; EXPORTS data_config_write_local, data_config_write_updates, data_config_write_daily, data_config_write_terminal_network
;; IMPORTS sec/session, fs/data_config_authority, boot/boot_v2_handoff, svc/command
;; CAPS
;; OWNER saga:fs_wave
;; CONTEXT: bsp_only
; Kernel-only Settings entry. Public tuple is captured at the local Apply;
; this fixed checker is repeated inside the provider before every effect.
data_config_write_local:
    lea r11, [rel data_config_local_check]
    jmp data_config_write_local_guarded

data_config_local_check:                 ; R8=captured PID, R9=authority
    push rdx
    push r8
    push r9
    cmp byte [rel pbm_try_media], 0
    jne .no
    cmp dword [rel cmd_dispatch_depth], 0
    jne .no
    call session_shell_local_authority
    cmp rax, 1                          ; PRIN_OWNER
    jne .no
    cmp rax, [rsp + 8]
    jne .no
    test rdx, rdx
    jz .no
    cmp rdx, [rsp]
    jne .no
    xor eax, eax
    jmp .out
.no:
    mov rax, -1
.out:
    pop r9
    pop r8
    pop rdx
    ret

; Native Settings update policy ONLY: preserve the fixed local owner checker
; and add exact original40 generation/deadline at EVERY provider effect.
; No caller-supplied callback, PIO grant or worker assertion enters here.
; settings_update_policy_current is the fixed native composition checker,
; like app_store_effect_check; no replacement callback is supplied by a caller.
data_config_write_updates:
    lea r11, [rel data_config_updates_check]
    jmp data_config_write_updates_guarded

data_config_updates_check:
    push rdx
    push r8
    push r9
    call data_config_local_check
    test eax, eax
    jnz .out
    call settings_update_policy_current
.out:
    pop r9
    pop r8
    pop rdx
    ret

; Native daily preference only. Neither scheduled CHECK nor UPDATE.CFG's
; original40 creates this authority. Repeated before EVERY provider effect.
data_config_write_daily:
    lea r11, [rel data_config_daily_check]
    jmp data_config_write_daily_guarded

data_config_daily_check:
    push rdx
    push r8
    push r9
    call data_config_local_check
    test eax, eax
    jnz .out
    call settings_update_daily_policy_current
.out:
    pop r9
    pop r8
    pop rdx
    ret

; Provider policy only. The Save backend owns original80 and candidate; this
; fixed check is repeated inside actual mode7 DATA effects, never a callback
; supplied by a request, command, app, guest or caller-selected identity.
data_config_write_terminal_network:
    lea r11,[rel data_config_terminal_network_check]
    jmp data_config_write_terminal_network_guarded

data_config_terminal_network_check:
    push rdx
    push r8
    push r9
    call data_config_local_check
    test eax,eax
    jnz .out
    call settings_terminal_network_policy_current
.out:
    pop r9
    pop r8
    pop rdx
    ret
