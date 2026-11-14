;; MODULE svc/recovery_boot
;; LAYER 5
;; EXPORTS recovery_boot_preload, recovery_boot_init, recovery_boot_ready, recovery_boot_expiry, recovery_boot_command, recovery_boot_failure, recovery_boot_effect_begin, recovery_boot_quiesced, recovery_boot_effect_budget
;; IMPORTS bootmgr/rsa2048_verify, core/lib/sha256, fs/storage_access, bootmgr/recovery_route, bootmgr/recovery_grant, boot/boot_v2_handoff, boot/boot_v2_health, boot/header, boot/nvram_access, boot/serial, svc/recovery_controller, svc/command_auth, core/time
;; CAPS
;; OWNER saga:boot
; Shipping opt-in R5 controller admission. All file reads precede EBS; runtime
; has only the exact signed immutable route snapshot. No host channel required
; for NEXT grants. CURRENT grants also require a consumed owner BOOT request.
%include "boot/recovery_contract.inc"
r5_owner_modulus equ boot_v2_owner_modulus
r5_crc32 equ pbm_crc32

recovery_boot_preload:
    push rbx
    mov byte [rel recovery_boot_ready],0
    cmp byte [rel pbm_manager_launch],1
    jne .out
    cmp byte [rel pbm_try_media],0
    jne .out
    cmp byte [rel pbm_profile],PBM_PROFILE_NORMAL
    jne .out
    cmp byte [rel pbm_sb_secureboot],1
    jne .out
    call r5_route_open
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
    call r5_grant_digest
    test eax,eax
    jz .close
    lea rdi,[rel r5_manifest_path]
    lea rsi,[rel r5_native_manifest]
    mov edx,PBM_MANIFEST_SIZE
    call r5_read_exact
    test eax,eax
    jz .close
    call r5_native_manifest_valid
    test eax,eax
    jz .close
    lea rdi,[rel r5_state0_path]
    lea rsi,[rel r5_native_state0]
    mov edx,PBM_STATE_SIZE
    call r5_read_exact
    mov [rel r5_native_read0],al
    lea rdi,[rel r5_state1_path]
    lea rsi,[rel r5_native_state1]
    mov edx,PBM_STATE_SIZE
    call r5_read_exact
    mov [rel r5_native_read1],al
    call r5_native_select_state
    test eax,eax
    jz .close
    call r5_source_valid
    test eax,eax
    jz .close
    call r5_route_validate
    test eax,eax
    jz .close
    call r5_bootnext_absent
    test eax,eax
    jz .close
    call r5_get_request
    mov rdx,R5_EFI_NOT_FOUND
    cmp rax,rdx
    jne .close                         ; never overwrite a prior/unknown action
    mov byte [rel recovery_boot_ready],1
.close:
    call r5_route_close
.out:
    pop rbx
    ret

r5_native_manifest_valid:
    cmp dword [rel r5_native_manifest],PBM_MANIFEST_MAGIC
    jne .no
    cmp word [rel r5_native_manifest+4],PBM_MANIFEST_VERSION
    jne .no
    cmp word [rel r5_native_manifest+6],PBM_MANIFEST_SIZE
    jne .no
    test word [rel r5_native_manifest+PBM_MANIFEST_FLAGS_OFF],PBM_MANIFEST_FLAG_TRY_MEDIA
    jnz .no
    mov rax,[rel r5_grant+R5_SEQUENCE]
    cmp rax,[rel pbm_manager_sequence]
    jne .no
    cmp rax,[rel r5_native_manifest+PBM_MANIFEST_SEQUENCE_OFF]
    jne .no
    lea rdi,[rel r5_native_manifest+PBM_MANIFEST_SIGNATURE_OFF]
    lea rsi,[rel r5_native_manifest]
    mov edx,PBM_MANIFEST_SIGNED_SIZE
    lea rcx,[rel boot_v2_owner_modulus]
    call rsa2048_verify_sha256
    test eax,eax
    jnz .no
    lea rdi,[rel r5_native_digest]
    lea rsi,[rel r5_native_manifest]
    mov edx,PBM_MANIFEST_SIZE
    call sha256_hash
    test rax,rax
    jnz .no
    lea rdi,[rel r5_native_digest]
    lea rsi,[rel r5_grant+R5_MANIFEST_SHA]
    mov ecx,32
    call r5_equal
    test eax,eax
    jz .no
    mov al,[rel pbm_entry]
    cmp al,[rel r5_grant+13]
    jne .no
    movzx ecx,byte [rel r5_native_manifest+PBM_MANIFEST_COUNT_OFF]
    cmp ecx,PBM_MANIFEST_ENTRY_MAX
    ja .no
    lea rdx,[rel r5_native_manifest+PBM_MANIFEST_ENTRY_OFF]
.find:
    test ecx,ecx
    jz .no
    cmp [rdx],al
    je .found
    add rdx,PBM_MANIFEST_ENTRY_SIZE
    dec ecx
    jmp .find
.found:
    lea rdi,[rdx+PBM_MANIFEST_ENTRY_SHA_OFF]
    lea rsi,[rel r5_grant+R5_PAYLOAD_SHA]
    mov ecx,32
    call r5_equal
    test eax,eax
    jz .no
    lea rdi,[rel pbm_payload_sha]
    lea rsi,[rel r5_grant+R5_PAYLOAD_SHA]
    mov ecx,32
    jmp r5_equal
.no:
    xor eax,eax
    ret

; Read-only exact authoritative source. Corrupt copies are ignored only when
; the other is valid. A newer or equal-but-different valid copy refuses PBH1.
r5_native_state_valid:
    cmp dword [rdi],PBM_STATE_MAGIC
    jne .no
    cmp word [rdi+4],PBM_CONTRACT_VERSION
    jne .no
    cmp word [rdi+6],PBM_STATE_SIZE
    jne .no
    push rbx
    mov ebx,[rdi+PBM_STATE_CRC32]
    mov esi,PBM_STATE_CRC32
    call pbm_crc32
    cmp eax,ebx
    sete al
    movzx eax,al
    pop rbx
    ret
.no:
    xor eax,eax
    ret
r5_native_select_state:
    xor ebx,ebx
    cmp byte [rel r5_native_read0],1
    jne .one
    lea rdi,[rel r5_native_state0]
    call r5_native_state_valid
    test eax,eax
    jz .one
    lea rbx,[rel r5_native_state0]
.one:
    cmp byte [rel r5_native_read1],1
    jne .chosen
    lea rdi,[rel r5_native_state1]
    call r5_native_state_valid
    test eax,eax
    jz .chosen
    lea rdi,[rel r5_native_state1]
    test rbx,rbx
    jz .use1
    mov rax,[rdi+PBM_STATE_GENERATION_OFF]
    cmp rax,[rbx+PBM_STATE_GENERATION_OFF]
    jb .chosen
    ja .use1
    mov rsi,rbx
    mov ecx,PBM_STATE_SIZE
    call r5_equal
    test eax,eax
    jz .no
    jmp .chosen
.use1:
    lea rbx,[rel r5_native_state1]
.chosen:
    test rbx,rbx
    jz .no
    mov rax,[rbx+PBM_STATE_GENERATION_OFF]
    cmp rax,[rel pbm_state_generation]
    jne .no
    mov rax,[rbx+PBM_STATE_ATTEMPT_NONCE_OFF]
    cmp rax,[rel pbm_attempt_nonce]
    jne .no
    mov [rel r5_source_state],rbx
    mov eax,1
    ret
.no:
    xor eax,eax
    ret

recovery_boot_init:
    cmp byte [rel recovery_boot_ready],1
    jne .out
    cmp byte [rel r5_grant+12],R5_NEXT
    jne .out
    call r5_make_arm_request
    lea rdi,[rel r5_arm_request]
    call recovery_controller_arm_grant
.out:
    ret
r5_make_arm_request:
    mov rax,[rel pbm_attempt_nonce]
    mov [rel r5_arm_request],rax
    mov rax,[rel pbm_state_generation]
    mov [rel r5_arm_request+8],rax
    mov rax,[rel r5_grant+R5_OP]
    mov [rel r5_arm_request+16],rax
    mov qword [rel r5_arm_request+24],R5_SOFT_SECONDS
    mov qword [rel r5_arm_request+32],R5_HARD_SECONDS
    ret

; RDI points to exact tail after 'RECOVERY ': 'ARM|TOUCH|CANCEL ' and three
; 16-digit hex boot/gen/op fields, one ASCII space between, no trailing data.
; Existing BOOT dispatcher/session/AUTH2 replay guards surround this call.
recovery_boot_command:
    push rbx
    push r12
    mov rbx,rdi
    xor r12d,r12d
    cmp dword [rbx],'ARM '
    je .arm
    cmp dword [rbx],'TOUC'
    jne .cancel
    cmp word [rbx+4],'H '
    jne .no
    mov r12d,1
    add rbx,6
    jmp .parse
.cancel:
    cmp dword [rbx],'CANC'
    jne .no
    cmp word [rbx+4],'EL'
    jne .no
    cmp byte [rbx+6],' '
    jne .no
    mov r12d,2
    add rbx,7
    jmp .parse
.arm:
    cmp byte [rel r5_grant+12],R5_CURRENT
    jne .no
    add rbx,4
.parse:
    call r5_make_arm_request
    lea rdi,[rel r5_arm_request]
    mov ecx,3
.qword:
    push rcx
    push rdi
    mov rdi,rbx
    ; Strict parser consumes exactly16 hex digits and exposes the next byte.
    call command_auth_parse_hex64
    pop rdi
    pop rcx
    jc .no
    mov [rdi],rax
    add rdi,8
    add rbx,16
    dec ecx
    jz .end
    cmp byte [rbx],' '
    jne .no
    inc rbx
    jmp .qword
.end:
    cmp byte [rbx],0
    jne .no
    lea rdi,[rel r5_arm_request]
    cmp r12d,1
    je .touch
    cmp r12d,2
    je .cancel_call
    call recovery_controller_arm
    jmp .out
.touch:
    call recovery_controller_touch
    jmp .out
.cancel_call:
    call recovery_controller_cancel
    jmp .out
.no:
    xor eax,eax
.out:
    pop r12
    pop rbx
    ret

; Called only after the depth-zero claimed policy quiesced storage. Revalidate
; exact immutable grant/boot and current firmware option, reject ANY existing
; BootNext/request. Normal storage gates receive explicit signed-owner intent.
; EAX=1 only after BOTH persistent writes and exact distinct-buffer readbacks.
recovery_boot_expiry:
    cmp byte [rel recovery_controller_state],RC_CLAIMED
    jne .no
    call recovery_controller_validate
    test eax,eax
    jz .no
    call r5_option_revalidate
    test eax,eax
    jz .no
    call r5_bootnext_absent
    test eax,eax
    jz .no
    call r5_get_request
    mov rdx,R5_EFI_NOT_FOUND
    cmp rax,rdx
    jne .no
    lea rdi,[rel r5_nv_guid]
    lea rsi,[rel r5_nv_name]
    mov edx,SA_INTENT_SPECIAL
    lea rcx,[rel r5_caller]
    call storage_access_nvram_require
    test rax,rax
    jnz .no
    lea rdi,[rel r5_global_guid]
    lea rsi,[rel r5_bootnext_name]
    mov edx,SA_INTENT_SPECIAL
    lea rcx,[rel r5_caller]
    call storage_access_nvram_require
    test rax,rax
    jnz .no
    lea rdi,[rel r5_request]
    xor eax,eax
    mov ecx,R5_REQUEST_SIZE/8
    rep stosq
    mov rax,R5_REQUEST_MAGIC
    mov [rel r5_request],rax
    mov rax,[rel pbm_attempt_nonce]
    mov [rel r5_request+8],rax
    mov rax,[rel pbm_state_generation]
    mov [rel r5_request+16],rax
    mov rax,[rel r5_grant+R5_OP]
    mov [rel r5_request+24],rax
    lea rdi,[rel r5_request+32]
    lea rsi,[rel r5_digest]
    mov ecx,4
    rep movsq
    lea rdi,[rel r5_request+R5_REQUEST_GRANT]
    lea rsi,[rel r5_grant]
    mov ecx,R5_GRANT_SIZE/8
    rep movsq
    lea rdi,[rel r5_request]
    mov esi,R5_REQUEST_CRC
    call pbm_crc32
    mov [rel r5_request+R5_REQUEST_CRC],eax
    call recovery_boot_effect_budget
    test eax,eax
    jz .no
    mov byte [rel recovery_boot_uncertain],1  ; BEFORE first possibly durable effect
    call r5_set_request
    test eax,eax
    jz .no
    call recovery_boot_effect_budget
    test eax,eax
    jz .no
    call r5_set_bootnext
    test eax,eax
    jz .no
    ret
.no:
    xor eax,eax
    ret

; One attempt; 10s storage ceiling, 15s from initial claim to reset issue.
; Existing bounded driver and firmware calls cannot be preempted here. Any
; returned overrun refuses further effects; no hardware availability claim.
recovery_boot_effect_begin:
    cmp byte [rel recovery_controller_state],RC_CLAIMED
    jne recovery_boot_effect_budget.no
    call recovery_controller_validate
    test eax,eax
    jz recovery_boot_effect_budget.no
    mov rax,[rel rc_last_us]
    mov [rel r5_effect_start],rax
    add rax,R5_QUIESCE_US+R5_RESET_US
    jc recovery_boot_effect_budget.no
    mov [rel r5_effect_deadline],rax
    mov eax,1
    ret
recovery_boot_quiesced:
    call recovery_boot_effect_budget
    test eax,eax
    jz .out
    mov rax,[rel rc_last_us]
    sub rax,[rel r5_effect_start]
    cmp rax,R5_QUIESCE_US
    ja .no
    mov rax,[rel rc_last_us]
    add rax,R5_RESET_US              ; reset work itself gets at most5s, even after fast quiesce
    jc .no
    mov [rel r5_effect_deadline],rax
    mov eax,1
.out:
    ret
.no:
    xor eax,eax
    ret
recovery_boot_effect_budget:
    cmp byte [rel recovery_controller_state],RC_CLAIMED
    jne .no
    call recovery_controller_validate
    test eax,eax
    jz .no
    cmp qword [rel r5_effect_start],0
    je .no
    mov rax,[rel rc_last_us]
    cmp rax,[rel r5_effect_deadline]
    ja .no
    mov eax,1
    ret
.no:
    xor eax,eax
    ret

recovery_boot_failure:
    mov byte [rel recovery_controller_state],RC_REFUSED
    lea rdi,[rel r5_refusal]
    cmp byte [rel recovery_boot_uncertain],0
    je .print
    lea rdi,[rel r5_uncertainty]
.print:
    jmp serial_string
r5_caller: db 'r5-owner-grant',0
r5_refusal: db '[PAOS64] Recovery refused; no reset. Owner operation ended. [recovery.controller.refused]',13,10,0
r5_uncertainty: db '[PAOS64] Recovery incomplete; persistent request/BootNext may exist. No retry; owner reconciliation required. [recovery.controller.uncertain]',13,10,0
%macro WDATA_recovery_boot 0
align 8
recovery_boot_ready: db 0
recovery_boot_uncertain: db 0
r5_native_read0: db 0
r5_native_read1: db 0
align 8
r5_effect_start: dq 0
r5_effect_deadline: dq 0
r5_arm_request: times 5 dq 0
r5_native_manifest: times PBM_MANIFEST_SIZE db 0
r5_native_state0: times PBM_STATE_SIZE db 0
r5_native_state1: times PBM_STATE_SIZE db 0
r5_native_digest: times 32 db 0
%endmacro
%include "core/abi/wdata.inc"
WDATA_DEFER WDATA_recovery_boot
