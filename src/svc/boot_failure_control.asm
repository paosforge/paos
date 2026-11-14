;; MODULE svc/boot_failure_control
;; LAYER 5
;; EXPORTS boot_b1_failure_control
;; IMPORTS boot/boot_v2_handoff, boot/boot_v2_health, svc/command_software_stop
;; CAPS
;; OWNER saga:boot
; Source-only diagnostic fixture. Existing Manager recovery policy owns what
; follows; no fabricated checkpoint, health, journal, policy or persistent token.
; A matching mutable Normal attempt faults once on this entry. A subsequent
; Normal entry can fault again; only the original finite lifecycle bounds it.
; Safe, Rescue and direct entries always return. An absent/failed durable edge
; is evidence missing, never permission to fabricate an incomplete checkpoint.

%if PAOS_LAB_B1_STARTING_FAILURE
; EAX is the actual C3WD_EDGE result, preserved by face_checkpoint_observe.
; No allocations, firmware calls, storage writes or waits. The existing early
; fatal handler handles this actual #UD, including its ordinary reset path.
boot_b1_failure_control:
    test eax,eax
    jnz .out
    cmp byte [rel pbm_manager_launch],1
    jne .out
    test byte [rel pbm_flags],PBM_HF_MUTABLE_ATTEMPT
    jz .out
    cmp byte [rel pbm_profile],PBM_PROFILE_NORMAL
    jne .out
    movzx eax,byte [rel pbm_entry]
    cmp eax,PBM_ENTRY_PAOS_A
    je .slot
    cmp eax,PBM_ENTRY_PAOS_B
    jne .out
.slot:
    cmp byte [rel c3wd_checkpoint_rc],PBM_INIT_RC_OK
    jne .out
    cmp byte [rel pbm_init_checkpoint_loaded],1
    jne .out
    cmp byte [rel pbm_init_checkpoint_durable],1
    jne .out
    cmp byte [rel pbm_strong_health_published],0
    jne .out
    lea r8,[rel pbm_init_checkpoint_record]
    cmp dword [r8+PBM_INIT_MAGIC_OFF],PBM_INIT_MAGIC
    jne .out
    cmp word [r8+PBM_INIT_SIZE_OFF],PBM_INIT_RECORD_SIZE
    jne .out
    cmp word [r8+PBM_INIT_VERSION_OFF],PBM_INIT_VERSION
    je .version
    cmp word [r8+PBM_INIT_VERSION_OFF],PBM_INIT_GRAPH_VERSION
    jne .out
.version:
    cmp byte [r8+PBM_INIT_STAGE_OFF],PBM_INIT_STAGE_P0
    jne .out
    cmp byte [r8+PBM_INIT_TRANSITION_OFF],PBM_INIT_TRANSITION_STARTING
    jne .out
    cmp byte [r8+PBM_INIT_RESULT_OFF],PBM_INIT_RESULT_NONE
    jne .out
    cmp word [r8+PBM_INIT_COMPLETED_MASK_OFF],0
    jne .out
    cmp byte [r8+PBM_INIT_PROFILE_OFF],PBM_PROFILE_NORMAL
    jne .out
    mov al,[rel pbm_entry]
    cmp al,[r8+PBM_INIT_ENTRY_OFF]
    jne .out
    mov rax,[rel pbm_manager_sequence]
    test rax,rax
    jz .out
    cmp rax,[r8+PBM_INIT_MANAGER_SEQ_OFF]
    jne .out
    mov rax,[rel pbm_attempt_nonce]
    test rax,rax
    jz .out
    cmp rax,[r8+PBM_INIT_ATTEMPT_NONCE_OFF]
    jne .out
    lea r9,[rel pbm_payload_sha]
    xor r10d,r10d
    xor ecx,ecx
.hash:
    mov rax,[r9+rcx]
    cmp rax,[r8+PBM_INIT_PAYLOAD_SHA_OFF+rcx]
    jne .out
    or r10,rax
    add ecx,8
    cmp ecx,32
    jb .hash
    test r10,r10
    jz .out
    ud2
.out:
    xor eax,eax
    ret
%endif
