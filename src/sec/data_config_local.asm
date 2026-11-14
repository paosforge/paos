;; MODULE sec/data_config_local
;; LAYER 5
;; EXPORTS data_config_write_local
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
