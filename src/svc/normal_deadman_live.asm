;; MODULE svc/normal_deadman_live
;; LAYER 5
;; EXPORTS boot_d4_deadman_live, boot_d4_command_stall_control
;; IMPORTS core/normal_deadman, core/time, core/smp, core/idt, boot/boot_v2_handoff, boot/boot_v2_health
;; CAPS
;; OWNER saga:boot
; Standalone source harnesses retain the same disabled default as boot/header.
%ifndef PAOS_NORMAL_DEADMAN_MS
%define PAOS_NORMAL_DEADMAN_MS 0
%endif
%ifndef PAOS_LAB_D4_IFON_STALL
%define PAOS_LAB_D4_IFON_STALL 0
%endif
; No new wire ABI, grant, firmware write or reset policy. This source is opt-in;
; a chosen budget must cover every admitted legitimate command in that image.
boot_d4_deadman_live:
%if PAOS_NORMAL_DEADMAN_MS
    call boot_d4_deadman_eligible
    test eax,eax
    jz .out
    call tsc_now
    mov rdi,rax
    cmp byte [rel normal_deadman_state],0
    jne .heartbeat
    mov rax,[rel tsc_khz]               ; calibrated cycles per millisecond
    mov esi,PAOS_NORMAL_DEADMAN_MS
    mul rsi
    test rdx,rdx
    jnz .out
    test rax,rax
    jle .out                           ; zero / bit63 set cannot arm
    mov rsi,rax
    jmp normal_deadman_arm
.heartbeat:
    jmp normal_deadman_heartbeat
.out:
%endif
    xor eax,eax
    ret

%if PAOS_NORMAL_DEADMAN_MS
; First arm requires actual successful strong-health SetVariable publication,
; a full Manager-owned Normal identity and the existing metal-only reset gate.
; HOST stand-ins can exercise branches, not EFI durability or actual reset.
boot_d4_deadman_eligible:
    cmp byte [rel pbm_manager_launch],1
    jne .no
    test byte [rel pbm_flags],PBM_HF_MUTABLE_ATTEMPT
    jz .no
    cmp byte [rel pbm_profile],PBM_PROFILE_NORMAL
    jne .no
    movzx eax,byte [rel pbm_entry]
    cmp eax,PBM_ENTRY_PAOS_A
    je .slot
    cmp eax,PBM_ENTRY_PAOS_B
    jne .no
.slot:
    cmp byte [rel pbm_strong_health_published],1
    jne .no
    cmp qword [rel pbm_manager_sequence],0
    je .no
    cmp qword [rel pbm_attempt_nonce],0
    je .no
    mov rax,[rel pbm_payload_sha]
    or rax,[rel pbm_payload_sha+8]
    or rax,[rel pbm_payload_sha+16]
    or rax,[rel pbm_payload_sha+24]
    jz .no
    cmp byte [rel fault_warmreset_armed],1
    jne .no
    cmp qword [rel fault_demote_hook],0
    je .no
    cmp qword [rel tsc_khz],0
    je .no
    pushfq
    pop rax
    test eax,(1 << 9)
    jz .no
    call smp_current_logical
    test eax,eax
    jnz .no
    mov eax,1
    ret
.no:
    xor eax,eax
    ret
%endif

%if PAOS_LAB_D4_IFON_STALL
; Dispatcher selects only the exact remote OWNER-authenticated startup C7HEALTH
; AFTER registry authorization/admission, before its real handler. Preliminary
; public discovery/security/auth-floor reads never enter this fixture.
; The actual command stops making progress with IF still on. IRQ owns expiry;
; no synthetic health, recovery, fault record or tick/heartbeat is fabricated.
boot_d4_command_stall_control:
    call boot_d4_deadman_eligible
    test eax,eax
    jz .out
    cmp byte [rel normal_deadman_state],1
    jne .out
.stall:
    pause
    jmp .stall
.out:
    ret
%endif
