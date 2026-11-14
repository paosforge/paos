; R5 maintained Manager consumer. Included in the Manager's code section.
; Optional owner grant file alone never selects Rescue. A runtime request must
; carry that grant AND match the exact durable source attempt. All effects use
; journal_commit (older copy, flush, full readback); no native journal writes.
%define R5_MANAGER_LINK 1
r5_owner_modulus equ pbm_owner_modulus
r5_crc32:
    mov ecx,esi
    jmp crc32
%include "bootmgr/recovery_grant.asm"
%include "bootmgr/recovery_route.asm"
%undef R5_MANAGER_LINK

; One nonrenewable 120s UEFI relative timer covers request verification,
; durable consumption and selection. Returned overrun/error refuses all further
; launch effects. Firmware calls cannot be preempted; no availability claim.
r5_manager_budget_begin:
    mov byte [rel r5_manager_active],1
    mov ecx,0x80000000              ; EVT_TIMER, no notification callback
    xor edx,edx
    xor r8d,r8d
    xor r9d,r9d
    mov rax,[rel boot_services]
    R5_FW_ENTER
    lea r10,[rel r5_manager_event]
    mov [rsp+32],r10
    call [rax+0x50]                 ; CreateEvent
    R5_FW_LEAVE
    test rax,rax
    jnz .no
    mov rcx,[rel r5_manager_event]
    mov edx,2                      ; TimerRelative
    mov r8d,1200000000              ; 120 seconds in 100ns units
    mov rax,[rel boot_services]
    R5_FW_ENTER
    call [rax+0x58]                 ; SetTimer
    R5_FW_LEAVE
    test rax,rax
    jnz .no
    jmp r5_manager_budget_check
.no:
    mov eax,1
    ret
r5_manager_budget_close:
    mov rcx,[rel r5_manager_event]
    test rcx,rcx
    jz .out
    mov qword [rel r5_manager_event],0
    mov rax,[rel boot_services]
    R5_FW_ENTER
    call [rax+0x70]                 ; CloseEvent, no callback or durable effect
    R5_FW_LEAVE
.out:
    ret
r5_manager_budget_check:
    cmp byte [rel r5_manager_active],0
    je .ok
    mov rcx,[rel r5_manager_event]
    test rcx,rcx
    jz .no
    mov rax,[rel boot_services]
    R5_FW_ENTER
    call [rax+0x78]                 ; CheckEvent
    R5_FW_LEAVE
    mov rdx,0x8000000000000006      ; only NOT_READY means before deadline
    cmp rax,rdx
    jne .no
.ok:
    xor eax,eax
    ret
.no:
    mov eax,1
    ret

; Every actual launch boundary checks the same timer; no menu or failed Rescue
; may turn a consumed recovery operation into an unrelated normal OS launch.
; EDI=entry, EAX=0 admitted. Ordinary boots have no active R5 operation.
r5_manager_launch_guard:
    cmp byte [rel r5_manager_active],0
    je .ok
    cmp byte [rel r5_manager_consumed],1
    jne .no
    cmp edi,PBM_ENTRY_RESCUE
    jne .no
    call r5_manager_budget_check
    ret
.ok:
    xor eax,eax
    ret
.no:
    mov eax,1
    ret

r5_manager_context:
    mov rax,[rel system_table]
    test rax,rax
    jz .no
    mov rdi,[rax+SMB_EST_CFG]
    mov rsi,[rax+SMB_EST_NUM]
    call smbios_identity_from_config
    test eax,eax
    jnz .no
    cmp qword [rel r5_root],0
    je .open
    mov eax,1
    ret
.open:
    call r5_route_open
    ret
.no:
    xor eax,eax
    ret

; Verify exact current manifest, node/medium/route and independently signed
; Rescue descriptor, in addition to the request's owner signature. All files
; are opened on this loaded Manager's own ESP. Existing signature/floor/image
; validation remains on the actual Rescue launch too (no direct transfer).
r5_manager_grant_context:
    cmp byte [rel manifest_verified],1
    jne .no
    mov rax,[rel r5_grant+R5_SEQUENCE]
    cmp rax,[rel manifest+PBM_MANIFEST_SEQUENCE_OFF]
    jne .no
    test word [rel manifest+PBM_MANIFEST_FLAGS_OFF],PBM_MANIFEST_FLAG_TRY_MEDIA
    jnz .no
    lea rdi,[rel r5_grant+R5_MANIFEST_SHA]
    lea rsi,[rel verified_manifest_sha]
    mov ecx,32
    call r5_equal
    test eax,eax
    jz .no
    movzx edi,byte [rel r5_grant+13]
    call integrity_vault_select_entry
    test rax,rax
    jz .no
    lea rdi,[rax+PBM_MANIFEST_ENTRY_SHA_OFF]
    lea rsi,[rel r5_grant+R5_PAYLOAD_SHA]
    mov ecx,32
    call r5_equal
    test eax,eax
    jz .no
    call load_verify_recovery_descriptor
    ; Independent verification is evidence for this grant only. Never leave
    ; both ordinary trust-source latches active (the Vault selector refuses it).
    mov byte [rel recovery_descriptor_verified],0
    mov rdx,[rel manifest+PBM_MANIFEST_SEQUENCE_OFF]
    mov [rel trust_sequence],rdx       ; descriptor verification must not replace floor authority
    test eax,eax
    jnz .no
    lea rdi,[rel recovery_descriptor+PBM_RECOVERY_ENTRY_OFF+PBM_MANIFEST_ENTRY_SHA_OFF]
    lea rsi,[rel r5_grant+R5_RESCUE_SHA]
    mov ecx,32
    call r5_equal
    test eax,eax
    jz .no
    mov eax,[rel recovery_descriptor+PBM_RECOVERY_ENTRY_OFF+4]
    cmp rax,[rel r5_grant+R5_RESCUE_SIZE]
    jne .no
    mov edi,PBM_ENTRY_RESCUE
    call integrity_vault_select_entry
    test rax,rax
    jz .no
    mov edx,[rax+4]
    cmp rdx,[rel r5_grant+R5_RESCUE_SIZE]
    jne .no
    lea rdi,[rax+PBM_MANIFEST_ENTRY_SHA_OFF]
    lea rsi,[rel r5_grant+R5_RESCUE_SHA]
    mov ecx,32
    call r5_equal
    test eax,eax
    jz .no
    call r5_manager_context
    test eax,eax
    jz .no
    call r5_route_validate
    ret
.no:
    xor eax,eax
    ret

; Called BEFORE compact health consumption, B1 application and final selection.
; EAX=0 absent/consumed,1 refusal -> visible Manager stop; no guessed fallback.
r5_manager_consume_request:
    push rbx
    push r12
    call r5_get_request
    mov rdx,R5_EFI_NOT_FOUND
    cmp rax,rdx
    je .quiet
    test rax,rax
    jnz .bad
    cmp qword [rel r5_var_size],R5_REQUEST_SIZE
    jne .bad
    cmp dword [rel r5_attrs],7
    jne .bad
    call r5_manager_budget_begin
    test eax,eax
    jnz .bad
    lea rsi,[rel r5_request+R5_REQUEST_GRANT]
    lea rdi,[rel r5_grant]
    mov ecx,R5_GRANT_SIZE/8
    rep movsq
    call r5_grant_valid
    test eax,eax
    jz .bad
    call r5_grant_digest
    test eax,eax
    jz .bad
    mov rax,[rel selected_state_ptr]
    mov [rel r5_source_state],rax
    call r5_request_valid
    test eax,eax
    jz .bad
    call r5_manager_budget_check
    test eax,eax
    jnz .bad
    call r5_manager_grant_context
    test eax,eax
    jz .bad
    call r5_manager_budget_check
    test eax,eax
    jnz .bad
    ; Preserve all trial/verified/quarantine/BIP/health/replay fields exactly.
    ; Consumed operation + Pending Rescue are ONE durable transaction.
    mov rsi,[rel selected_state_ptr]
    lea rdi,[rel state_work]
    mov ecx,PBM_STATE_SIZE/8
    rep movsq
    mov dword [rel state_work+R5_STATE_MAGIC_OFF],R5_STATE_MAGIC
    mov dword [rel state_work+R5_STATE_STATUS],R5_STATE_CONSUMED
    mov rax,[rel r5_grant+R5_OP]
    mov [rel state_work+R5_STATE_OP],rax
    lea rdi,[rel state_work+R5_STATE_DIGEST]
    lea rsi,[rel r5_digest]
    mov ecx,4
    rep movsq
    mov rax,[rel r5_request+8]
    mov [rel state_work+R5_STATE_NONCE],rax
    mov rax,[rel r5_request+16]
    mov [rel state_work+R5_STATE_GEN],rax
    mov byte [rel state_work+PBM_STATE_PENDING_ENTRY_OFF],PBM_ENTRY_RESCUE
    mov byte [rel state_work+PBM_STATE_PENDING_PROFILE_OFF],PBM_PROFILE_RESCUE
    call bind_work_manifest
    lea r12,[rel state_work]
    call journal_commit
    test eax,eax
    jnz .bad
    call r5_manager_budget_check
    test eax,eax
    jnz .bad
    call r5_delete_request
    test eax,eax
    jz .bad                         ; already consumed; failed delete never reauthorizes
    mov byte [rel r5_manager_consumed],1
    call r5_route_close
    lea rdi,[rel r5_consumed_text]
    call serial_string
.quiet:
    xor eax,eax
    jmp .out
.bad:
    call r5_route_close
    lea rdi,[rel r5_rejected_text]
    call serial_string
    mov eax,1
.out:
    pop r12
    pop rbx
    ret

; Called with state_work already describing the exact about-to-commit attempt,
; before journal_commit. Optional prelaunch grant is admitted only against precisely
; this source generation/manifest and selected normal A/B payload. Invalid or
; absent grants leave the operation unarmed; no owner timer is synthesized.
; The normal attempt commit durably binds digest/op to actual nonce+new gen.
r5_manager_bind_grant:
    push rbx
    push r12
    push r15
    mov rbx,[rel state_work+PBM_STATE_GENERATION_OFF]
    cmp r15d,PBM_ENTRY_PAOS_A
    jb .quiet
    cmp r15d,PBM_ENTRY_PAOS_B
    ja .quiet
    cmp byte [rel selected_profile],PBM_PROFILE_NORMAL
    jne .quiet
    call r5_manager_context
    test eax,eax
    jz .close
    lea rdi,[rel r5_grant_path]
    lea rsi,[rel r5_grant]
    mov edx,R5_GRANT_SIZE
    call r5_read_exact
    test eax,eax
    jz .close
    call r5_grant_valid
    test eax,eax
    jz .close
    cmp qword [rel r5_grant+R5_NONCE],0
    jne .close                       ; NEXT or prelaunch CURRENT/manual grant
    cmp rbx,[rel r5_grant+R5_EXPECTED_GEN]
    jne .close
    cmp r15b,[rel r5_grant+13]
    jne .close
    cmp dword [rel state_work+R5_STATE_MAGIC_OFF],R5_STATE_MAGIC
    jne .fresh
    mov rax,[rel r5_grant+R5_OP]
    cmp rax,[rel state_work+R5_STATE_OP]
    jbe .close
.fresh:
    call r5_grant_digest
    test eax,eax
    jz .close
    call r5_manager_grant_context
    test eax,eax
    jz .close
    mov dword [rel state_work+R5_STATE_MAGIC_OFF],R5_STATE_MAGIC
    mov dword [rel state_work+R5_STATE_STATUS],R5_STATE_BOUND
    mov rax,[rel r5_grant+R5_OP]
    mov [rel state_work+R5_STATE_OP],rax
    lea rdi,[rel state_work+R5_STATE_DIGEST]
    lea rsi,[rel r5_digest]
    mov ecx,4
    rep movsq
    mov rax,[rel current_attempt_nonce]
    mov [rel state_work+R5_STATE_NONCE],rax
    lea rax,[rbx+1]
    mov [rel state_work+R5_STATE_GEN],rax
.close:
    call r5_route_close
.quiet:
    pop r15
    pop r12
    pop rbx
    ret
r5_consumed_text: db '[PBM] Owner recovery operation consumed; signed Rescue pending. [recovery.controller.consumed]',13,10,0
r5_rejected_text: db '[PBM] Recovery request refused; authority, identity or durable consumption unavailable. [recovery.controller.rejected]',13,10,0
