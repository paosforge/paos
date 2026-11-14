;; MODULE cognition/classifier_service
;; LAYER 6
;; EXPORTS cog_classifier_command, cog_classifier_service_tick
;; IMPORTS cognition/classifier_artifact_admission, cognition/gpt2_engine, svc/command, svc/command_auth, sec/principal, sec/session, fs/vfs
;; CAPS PMCAP_COMPUTE
;; OWNER saga:cognition
;; CONTEXT: bsp_only
; MODELRUN CLASSIFY BEGIN <generation> <text> | STEP <generation> <ordinal>
;                     RESULT <generation> | CANCEL <generation>
; Exact native registry path, no extra verb. Every operation checks the in-flight
; OWNER ticket (or untainted local console) and live principal compute capability.
; SYSTEM/ADVISOR/internal/serial/unsigned callers cannot adopt an OWNER request.
; The existing MODELRUN dispatch also requires its native remote capability.
; Identity binds actual principal, ingress, session epoch, selected volume and
; namespace/write generation. Client generation and step ordinal are full64.
; Service lifetime identity passed to the lower engine is private, stable and
; never an authority grant. No request chooses pointers, model paths or policy.
; No text/result is retained in MODELOUT; shared transcript class redacts MODELRUN.
; Results include exact uncalibrated f32 score/runnerup/margin bits, index and
; choose/abstain status, calibrated=0 and action=none; never probabilities.
; Production ready=0 refuses before any allocation/I/O or ownership publication.
;
; BSP serialized, bounded one explicit step/command. Tick never advances inference:
; session/selection loss revokes result visibility then cancels and drains ONE
; bounded scrub step/pass. Custody persists through cleanup, then bindings/result
; are scrubbed. New BEGIN cannot replace a live or retiring request. No borrowed
; principal, credential, ticket or source is ever installed during cleanup.
%include "core/abi/wdata.inc"

cog_classifier_command:
    call cmd_handler_prologue
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,24
    mov r12,rdi
    mov r13,rsi
    mov r14,rdx
    mov ebp,CMDE_AUTHDENY
    call cog_out_reset
    ; Recheck native ownership even if a future internal caller bypasses routing.
    mov rdi,r12
    call command_auth_ticket_owner
    test eax,eax
    jz .denied
    mov rdi,[r12+REQ_PRINCIPAL]
    call principal_capabilities
    test rax,PMCAP_COMPUTE
    jz .denied
    mov ebp,CMDE_BADARG
    ; Entire suffix is bounded before parsing. No unbounded token scan.
    test r14,r14
    jz .bad
    xor ecx,ecx
.scan:
    cmp ecx,4192
    jae .bad
    cmp byte [r14+rcx],0
    je .scanned
    inc ecx
    jmp .scan
.scanned:
    mov r15,r14
    cmp ecx,6
    jb .bad
    cmp dword [r15],'BEGI'
    jne .not_begin
    cmp word [r15+4],'N '
    jne .bad
    xor ebx,ebx
    add r15,6
    jmp .generation
.not_begin:
    cmp dword [r15],'STEP'
    jne .not_step
    cmp byte [r15+4],' '
    jne .bad
    mov ebx,1
    add r15,5
    jmp .generation
.not_step:
    cmp dword [r15],'RESU'
    jne .not_result
    cmp word [r15+4],'LT'
    jne .bad
    cmp byte [r15+6],' '
    jne .bad
    mov ebx,2
    add r15,7
    jmp .generation
.not_result:
    cmp dword [r15],'CANC'
    jne .bad
    cmp word [r15+4],'EL'
    jne .bad
    cmp byte [r15+6],' '
    jne .bad
    mov ebx,3
    add r15,7
.generation:
    call cog_classifier_parse_u64
    jc .bad
    test rax,rax
    jz .bad
    mov [rsp],rax
    test ebx,ebx
    jz .begin
    cmp ebx,1
    je .step_arg
    cmp byte [r15],0
    jne .bad
    jmp .existing
.step_arg:
    cmp byte [r15],' '
    jne .bad
    inc r15
    call cog_classifier_parse_u64
    jc .bad
    cmp byte [r15],0
    jne .bad
    mov [rsp+8],rax
.existing:
    cmp qword [rel ccs_state],1
    jne .bad
    call cog_classifier_service_current
    test eax,eax
    jnz .revoke
    mov rax,[rsp]
    cmp rax,[rel ccs_client_generation]
    jne .bad
    mov rax,[r12+REQ_PRINCIPAL]
    cmp rax,[rel ccs_principal]
    jne .denied
    mov rax,[r12+REQ_SOURCE]
    cmp rax,[rel ccs_source]
    jne .denied
    cmp ebx,1
    je .step
    cmp ebx,2
    je .result
    call cog_classifier_service_retire
    mov eax,3
    jmp .status
.begin:
    cmp byte [r15],' '
    jne .bad
    inc r15
    ; Permit empty text; byte length is bounded and copied by the lower owner.
    xor ecx,ecx
.text:
    cmp byte [r15+rcx],0
    je .text_ready
    inc ecx
    cmp ecx,4096
    jbe .text
    jmp .bad
.text_ready:
    cmp qword [rel ccs_state],0
    jne .bad
    mov rax,[rsp]
    cmp rax,[rel ccs_last_generation]
    jbe .bad
    ; Admission owns readiness. No service state changes until begin succeeds.
    cmp qword [rel ccs_native_generation],-1
    je .bad
    lea rdi,[rel ccs_state]
    mov rsi,[rel ccs_native_generation]
    inc rsi
    mov rdx,r15
    mov r8d,[rel vfs_disk_handle]
    call cog_classifier_owned_begin_advisory
    cmp eax,3
    jne .unready
    inc qword [rel ccs_native_generation]
    mov rax,[rsp]
    mov [rel ccs_client_generation],rax
    mov [rel ccs_last_generation],rax
    mov rax,[r12+REQ_PRINCIPAL]
    mov [rel ccs_principal],rax
    mov rax,[r12+REQ_SOURCE]
    mov [rel ccs_source],rax
    mov rax,[rel session_authority_epoch]
    mov [rel ccs_epoch],rax
    mov eax,[rel vfs_disk_handle]
    mov [rel ccs_handle],rax
    mov rax,[rel vfs_write_generation]
    mov [rel ccs_writegen],rax
    mov qword [rel ccs_ordinal],0
    mov qword [rel ccs_state],1
    mov eax,3
    jmp .status
.step:
    mov rdx,[rsp+8]
    cmp rdx,[rel ccs_ordinal]
    jne .bad
    lea rdi,[rel ccs_state]
    mov rsi,[rel ccs_native_generation]
    call cog_classifier_owned_step_advisory
    mov r14d,eax
    cmp eax,3
    je .advanced
    cmp eax,1
    jbe .advanced
    ; Failure can enter lower bounded scrub. Tick drains it without publishing.
    call cog_classifier_service_retire
    mov eax,2
    jmp .status
.advanced:
    inc qword [rel ccs_ordinal]
    mov eax,r14d
    jmp .status
.result:
    lea rdi,[rel ccs_state]
    mov rsi,[rel ccs_native_generation]
    lea rdx,[rel ccs_advice]
    call cog_classifier_owned_result_advisory
    cmp eax,1
    ja .bad
    mov r14d,eax
    lea rdi,[rel ccs_msg_advice]
    call cog_put_str
    mov edi,[rel ccs_advice+4]
    call cog_put_dec
    lea rdi,[rel ccs_msg_action]
    call cog_put_str
    ; Unsigned decimal encodes the exact f32 bits, never a probability/percent.
    lea rdi,[rel ccs_msg_score]
    call cog_put_str
    mov edi,[rel ccs_advice+8]
    call cog_put_dec
    lea rdi,[rel ccs_msg_second]
    call cog_put_str
    mov edi,[rel ccs_advice+12]
    call cog_put_dec
    lea rdi,[rel ccs_msg_margin]
    call cog_put_str
    mov edi,[rel ccs_advice+16]
    call cog_put_dec
    lea rdi,[rel ccs_msg_uncalibrated]
    call cog_put_str
    mov eax,r14d
    jmp .status
.revoke:
    call cog_classifier_service_retire
.denied:
    mov ebp,CMDE_AUTHDENY
    lea rdi,[rel ccs_msg_denied]
    jmp .reply
.unready:
    lea rdi,[rel ccs_msg_unready]
    jmp .reply
.bad:
    lea rdi,[rel ccs_msg_bad]
    jmp .reply
.status:
    xor ebp,ebp
    mov [r13+RSP_VAL],rax
    mov r14,rax
    lea rdi,[rel ccs_msg_status]
    call cog_put_str
    mov rdi,r14
    call cog_put_dec
    lea rdi,[rel ccs_msg_ordinal]
    call cog_put_str
    mov rdi,[rel ccs_ordinal]
    call cog_put_dec
    lea rdi,[rel ccs_msg_none]
.reply:
    call cog_put_str
    ; Temporary advice is never an independent readable cache.
    mov qword [rel ccs_advice],0
    mov qword [rel ccs_advice+8],0
    mov qword [rel ccs_advice+16],0
    mov byte [rel cog_out_ready],1
    mov [r13+RSP_CODE],rbp
    xor eax,eax
    test ebp,ebp
    setz al
    mov [r13+RSP_ACCEPTED],rax
    add rsp,24
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Strict decimal at R15, returns RAX, R15 delimiter, CF=bad; no leading spaces,
; signs, overflow or >20 digits. Never consumes the delimiter.
cog_classifier_parse_u64:
    xor eax,eax
    xor ecx,ecx
.next:
    movzx edx,byte [r15]
    sub edx,'0'
    cmp edx,9
    ja .end
    inc ecx
    cmp ecx,20
    ja .bad
    mov r8,1844674407370955161
    cmp rax,r8
    ja .bad
    jne .add
    cmp edx,5
    ja .bad
.add:
    imul rax,10
    add rax,rdx
    inc r15
    jmp .next
.end:
    test ecx,ecx
    jz .bad
    clc
    ret
.bad:
    stc
    ret

; No ambient principal projection: the active local principal can differ during
; an authenticated remote frame. Revocation uses its actual session epoch and
; stored volume identity, not a temporary change to principal_current.
cog_classifier_service_current:
    sub rsp,8
    mov rdi,[rel ccs_principal]
    call principal_capabilities
    test rax,PMCAP_COMPUTE
    jz .bad
    mov rax,[rel session_authority_epoch]
    cmp rax,[rel ccs_epoch]
    jne .bad
    mov eax,[rel vfs_disk_handle]
    cmp rax,[rel ccs_handle]
    jne .bad
    mov rax,[rel vfs_write_generation]
    cmp rax,[rel ccs_writegen]
    jne .bad
    ; Lower map is private native metadata. Before first map there is none yet.
    cmp qword [rel cog_classifier_owned_map],0
    je .ok
    add rsp,8
    jmp cog_classifier_owned_volume_ok
.ok:
    xor eax,eax
    add rsp,8
    ret
.bad:
    mov eax,1
    add rsp,8
    ret

; Revoke first, then cancel. If the lower engine already entered cleanup its
; cancel refuses without resetting the scrub cursor; subsequent step drains it.
cog_classifier_service_retire:
    sub rsp,8
    mov qword [rel ccs_state],2
    mov qword [rel ccs_advice],0
    mov qword [rel ccs_advice+8],0
    mov qword [rel ccs_advice+16],0
    lea rdi,[rel ccs_state]
    mov rsi,[rel ccs_native_generation]
    call cog_classifier_owned_cancel_advisory
    add rsp,8
    ret

cog_classifier_service_tick:
    push rbx
    cmp qword [rel ccs_state],0
    je .out
    cmp qword [rel ccs_state],2
    je .drain
    call cog_classifier_service_current
    test eax,eax
    jz .out
    call cog_classifier_service_retire
.drain:
    lea rdi,[rel ccs_state]
    mov rsi,[rel ccs_native_generation]
    ; Cancel is not a step; failure may have advanced the lower ordinal.
    mov rdx,[rel cog_classifier_owned_ordinal]
    call cog_classifier_owned_step_advisory
    cmp eax,3
    je .out
    cmp qword [rel cog_classifier_owned_phase],11
    jb .out                     ; no release before actual lower retirement
    lea rdi,[rel ccs_bindings]
    mov ecx,ccs_bindings_end-ccs_bindings
    xor eax,eax
    cld
    rep stosb
    mov qword [rel ccs_state],0
.out:
    pop rbx
    ret

ccs_msg_denied: db ' classifier refused=owner_or_lifetime action=none',0
ccs_msg_unready: db ' classifier refused=admission action=none',0
ccs_msg_bad: db ' classifier refused=arguments_or_state action=none',0
ccs_msg_status: db ' classifier status=',0
ccs_msg_ordinal: db ' ordinal=',0
ccs_msg_none: db ' action=none',0
ccs_msg_advice: db ' classifier advice_index=',0
ccs_msg_action: db ' advisory=1',0
ccs_msg_score: db " score_f32_bits=",0
ccs_msg_second: db " second_f32_bits=",0
ccs_msg_margin: db " margin_f32_bits=",0
ccs_msg_uncalibrated: db " calibrated=0",0

%macro WDATA_cognition_classifier_service_0 0
align 8,db 0
ccs_state: dq 0                   ; idle=0,owned=1,retiring=2
ccs_native_generation: dq 0       ; monotonic internal engine lifetime
ccs_last_generation: dq 0         ; no client generation replay, even after scrub
ccs_bindings:
ccs_client_generation: dq 0
ccs_principal: dq 0
ccs_source: dq 0
ccs_epoch: dq 0
ccs_handle: dq 0
ccs_writegen: dq 0
ccs_ordinal: dq 0
ccs_advice: times 24 db 0
ccs_bindings_end:
%endmacro
WDATA_DEFER WDATA_cognition_classifier_service_0
