;; MODULE hv/guest_transport
;; LAYER 5
;; PURPOSE Dedicated bounded scalar PIO producer for the native typed WAIT adapter.
;; EXPORTS guest_transport_pio, guest_transport_retire, guest_transport_init
;; IMPORTS hv/guest_request, hv/vmx, core/smp, sec/session
;; CAPS
;; OWNER saga:guest_transport
; Codex / rc-live-claude. Stopped-vCPU cooperative BSP only; no yield or guest
; pointer. Ports are an endpoint, NOT process/bundle/grant authentication.
GT_CONTROL equ 0x5040
GT_DATA equ 0x5044
GT_MAGIC equ 0x31545747                ; GWT1
GT_FRAME_BYTES equ 40
GT_REPLY_BYTES equ 128
GT_STORAGE_BYTES equ 1856              ; GCA1 v2 (C11n); GCS1/GCR1 use 128

guest_transport_init:
    lea rdi,[rel guest_transport_retire]
    jmp guest_request_configure_transport

; Native retirement leaf. VM adapter calls this on START/STOP/config reset.
; Never calls the adapter recursively. Keep seen START and replay floor: guest
; reset, session/config retirement cannot resurrect the same native lifetime.
guest_transport_retire:
    pushfq
    push rax
    push rcx
    push rdi
    ; An interrupted scalar policy/history stream must not become an ordinary reply
    ; even after native retirement. Only an explicit new control transaction
    ; (gt_clear) can replace the poisoned stream.
    cmp byte [rel gt_receipt_mode],4
    je .retire_policy
    cmp byte [rel gt_receipt_mode],2
    je .retire_policy
    cmp byte [rel gt_receipt_mode],3
    je .retire_mode
    mov byte [rel gt_receipt_mode],0
    jmp .retire_mode
.retire_policy:
    mov byte [rel gt_receipt_mode],3
.retire_mode:
    mov byte [rel gt_bound],0
    mov dword [rel gt_count],0
    mov dword [rel gt_read],GT_REPLY_BYTES
    mov byte [rel gt_receiving],0
    lea rdi,[rel gt_frame]
    xor eax,eax
    mov ecx,(GT_FRAME_BYTES+48+GT_STORAGE_BYTES)/8
    cld
    rep stosq
    pop rdi
    pop rcx
    pop rax
    popfq
    ret

; EDI=VMX-normalized PIO qualification (SVM already normalizes),
; ESI=guest EAX -> EAX 1 claimed/0 unrelated, EDX bounded IN dword.
; The shared exit handler writes EDX to guest EAX for claimed IN, skips the
; exact original instruction, and retains the existing resume/retire path.
guest_transport_pio:
    push rbx
    push r12
    push r13
    mov ebx,edi
    mov r12d,esi
    mov r13d,edi
    shr r13d,16
    cmp r13d,GT_CONTROL
    je .ours
    cmp r13d,GT_DATA
    jne .unrelated
.ours:
    ; Check before lifetime/rebind: stale DATA must not activate a new START
    ; and consume an ordinary error frame as the suffix of an old GCS1/GCA1.
    cmp r13d,GT_DATA
    jne .context
    cmp byte [rel gt_receipt_mode],3
    je .refuse
.context:
    ; No AP/deferred-vCPU executor, interrupt or reentrant producer.
    cmp dword [rel vcb_handoff_active],0
    jne .refuse
    cmp byte [rel gt_busy],0
    jne .refuse
    call smp_current_logical
    test eax,eax
    jnz .refuse
    mov eax,ebx
    and eax,0xffff
    and eax,~0x40                    ; immediate/DX addressing immaterial
    cmp eax,3                       ; OUT dword, neither REP nor string
    je .width_ok
    cmp eax,11                      ; IN dword
    jne .invalidate
.width_ok:
    call gt_lifetime
    test eax,eax
    jz .invalidate
    test ebx,8
    jnz .input
    cmp r13d,GT_CONTROL
    jne .data
    cmp r12d,0
    je .clear
    cmp r12d,GT_FRAME_BYTES
    je .begin
    cmp r12d,1
    je .submit
    cmp r12d,2
    je .sequence
    cmp r12d,4
    je .receipt
    cmp r12d,5
    je .policy
    cmp r12d,6
    je .audit
    jmp .invalidate
.clear:
    call gt_clear
    jmp .claimed
.begin:
    call gt_clear
    mov byte [rel gt_receiving],1
    jmp .claimed
.sequence:
    call gt_clear
    mov rax,[rel gt_last_seq]
    mov [rel gt_reply+8],rax
    mov dword [rel gt_read],0
    jmp .claimed
; Driver-only original scalar query; CONTROL3 retains legacy/app semantics.
.receipt:
    call gt_clear
    lea rdi,[rel guest_request_endpoint]
    mov esi,[rel gt_start]
    lea rdx,[rel gt_reply]
    mov ecx,GT_REPLY_BYTES
    call guest_request_receipt_copy
    cmp eax,1
    jne .invalidate
    mov byte [rel gt_receipt_mode],1
    mov dword [rel gt_read],0
    jmp .claimed
; Read-only original settings observation; never changes policy or submits.
.policy:
    call gt_clear
    lea rdi,[rel guest_request_endpoint]
    mov esi,[rel gt_start]
    lea rdx,[rel gt_reply]
    mov ecx,GT_REPLY_BYTES
    call guest_request_command_policy_copy
    cmp eax,1
    jne .invalidate
    mov rax,[rel gt_reply+48]
    mov [rel gt_policy_generation],rax
    mov byte [rel gt_receipt_mode],2
    mov dword [rel gt_read],0
    jmp .claimed
.audit:
    call gt_clear
    lea rdi,[rel guest_request_endpoint]
    mov esi,[rel gt_start]
    lea rdx,[rel gt_reply]
    mov ecx,GT_STORAGE_BYTES
    call guest_request_audit_copy
    cmp eax,1
    jne .invalidate
    mov [rel gt_audit_refusal],rdx      ; C11n refusal generation of this copy
    mov rax,[rel gt_reply+48]
    mov [rel gt_audit_revision],rax
    mov rax,[rel gt_reply+72]
    mov [rel gt_audit_lost],rax
    mov byte [rel gt_receipt_mode],4
    mov dword [rel gt_limit],GT_STORAGE_BYTES
    mov dword [rel gt_read],0
    jmp .claimed
.data:
    cmp byte [rel gt_receiving],1
    jne .invalidate
    mov eax,[rel gt_count]
    cmp eax,GT_FRAME_BYTES
    jae .invalidate
    lea rdx,[rel gt_frame]
    mov [rdx+rax],r12d
    add dword [rel gt_count],4
    jmp .claimed
.submit:
    cmp byte [rel gt_receiving],1
    jne .invalidate
    mov byte [rel gt_receiving],0
    cmp dword [rel gt_count],GT_FRAME_BYTES
    jne .invalidate
    cmp dword [rel gt_frame],1
    jne .invalidate
    mov eax,[rel gt_frame+4]
    dec eax
    cmp eax,3
    ja .invalidate
    mov rax,[rel gt_frame+8]
    test rax,rax
    jz .invalidate
    cmp rax,[rel gt_last_seq]
    jbe .invalidate
    mov [rel gt_last_seq],rax       ; burn before adapter, including DENY
    mov [rel gt_reply+8],rax
    cmp qword [rel gt_frame+16],0
    je .invalidate
    cmp dword [rel gt_frame+4],2
    je .check_begin
    cmp qword [rel gt_frame+32],0
    jne .invalidate
    cmp dword [rel gt_frame+4],1
    jne .check_token
    cmp qword [rel gt_frame+24],0
    jne .invalidate
    jmp .dispatch
.check_token:
    cmp qword [rel gt_frame+24],0
    je .invalidate
    jmp .dispatch
.check_begin:
    cmp qword [rel gt_frame+32],5000
    ja .invalidate
.dispatch:
    mov byte [rel gt_busy],1
    lea rdi,[rel guest_request_endpoint] ; native endpoint, never guest bytes
    mov esi,[rel gt_start]               ; captured consumed START
    lea rdx,[rel gt_frame]               ; private complete native snapshot
    mov ecx,GT_FRAME_BYTES
    lea r8,[rel gt_response]             ; private envelope; NEVER put on wire
    call guest_request_submit
    mov eax,[rel gt_response+RSP_CODE]
    mov [rel gt_reply+4],eax
    test eax,eax
    jnz .redact
    lea rdi,[rel guest_request_endpoint]
    mov esi,[rel gt_start]
    mov rdx,[rel gt_frame+8]
    lea rcx,[rel gt_reply]
    mov r8d,GT_REPLY_BYTES
    call guest_request_result_copy       ; approved fixed wire snapshot, one shot
    test eax,eax
    jnz .no_result
    cmp byte [rel gt_bound],1
    jne .no_result
    jmp .ready
.no_result:
    mov dword [rel gt_reply],1
    mov dword [rel gt_reply+4],CMDE_AUTHDENY
.redact:
    lea rdi,[rel gt_reply+16]
    xor eax,eax
    mov ecx,(GT_REPLY_BYTES-16)/8
    rep stosq
.ready:
    mov byte [rel gt_busy],0
    mov dword [rel gt_read],0
    jmp .claimed
.input:
    cmp r13d,GT_CONTROL
    jne .read
    mov edx,GT_MAGIC
    jmp .out_claimed
.read:
    cmp byte [rel gt_receipt_mode],4
    je .audit_current
    cmp byte [rel gt_receipt_mode],2
    je .policy_current
    cmp byte [rel gt_receipt_mode],1
    jne .ordinary_read
    lea rdi,[rel guest_request_endpoint]
    mov esi,[rel gt_start]
    call guest_request_receipt_current
    cmp eax,1
    jne .invalidate
    jmp .ordinary_read
.policy_current:
    lea rdi,[rel guest_request_endpoint]
    mov esi,[rel gt_start]
    call guest_request_command_policy_current
    cmp eax,1
    jne .invalidate
    cmp rdx,[rel gt_policy_generation]
    jne .invalidate
    jmp .ordinary_read
.audit_current:
    lea rdi,[rel guest_request_endpoint]
    mov esi,[rel gt_start]
    call guest_request_audit_current
    cmp eax,1
    jne .invalidate
    cmp rdx,[rel gt_audit_revision]
    jne .invalidate
    cmp r8,[rel gt_audit_lost]
    jne .invalidate
    cmp r9,[rel gt_audit_refusal]
    jne .invalidate
.ordinary_read:
    mov eax,[rel gt_read]
    cmp eax,[rel gt_limit]
    jae .refuse
    lea rdx,[rel gt_reply]
    mov edx,[rdx+rax]
    add dword [rel gt_read],4
    jmp .out_claimed
.invalidate:
    cmp byte [rel gt_receipt_mode],4
    je .poison_policy
    cmp byte [rel gt_receipt_mode],2
    je .poison_policy
    cmp byte [rel gt_receipt_mode],3
    je .refuse
    call gt_clear
    mov dword [rel gt_reply+4],CMDE_BADARG
    mov dword [rel gt_read],0
.refuse:
    ; Even a transient context refusal during a policy/history read retires that
    ; copy. This single-byte fail-closed transition produces no data/callback
    ; on an AP or a reentrant path; subsequent DATA stays terminal.
    cmp byte [rel gt_receipt_mode],4
    je .poison_policy
    cmp byte [rel gt_receipt_mode],2
    jne .refused
.poison_policy:
    mov byte [rel gt_receipt_mode],3
.refused:
    mov edx,-1
    jmp .out_claimed
.claimed:
    xor edx,edx
.out_claimed:
    mov eax,1
    jmp .out
.unrelated:
    xor eax,eax
    xor edx,edx
.out:
    pop r13
    pop r12
    pop rbx
    ret

; First valid native exit in a NEW consumed START can activate once. Retirement
; or a lock/epoch change cannot rebind the same START from guest reset traffic.
gt_lifetime:
    cmp byte [rel hv_linux_running],1
    jne .bad
    cmp byte [rel hv_linux_run_req],0
    jne .bad
    cmp byte [rel hv_linux_stop_req],0
    jne .bad
    cmp byte [rel session_locked],SESSION_UNLOCKED
    jne .bad
    mov esi,[rel hv_linux_start_consumed]
    test esi,esi
    jz .bad
    cmp esi,[rel hv_linux_start_gen]
    jne .bad
    cmp byte [rel gt_bound],1
    je .bound
    cmp esi,[rel gt_start]
    je .bad
    lea rdi,[rel guest_request_endpoint]
    call guest_request_bind
    test rax,rax
    jz .bad
    mov eax,[rel hv_linux_start_consumed]
    mov [rel gt_start],eax
    mov rax,[rel session_authority_epoch]
    mov [rel gt_session],rax
    mov qword [rel gt_last_seq],0
    mov byte [rel gt_bound],1
    call gt_clear
.bound:
    mov eax,[rel hv_linux_start_consumed]
    cmp eax,[rel gt_start]
    jne .bad
    mov rax,[rel session_authority_epoch]
    cmp rax,[rel gt_session]
    jne .bad
    mov eax,1
    ret
.bad:
    call guest_transport_retire
    xor eax,eax
    ret

gt_clear:
    mov dword [rel gt_limit],GT_REPLY_BYTES
    mov byte [rel gt_receipt_mode],0
    push rdi
    push rcx
    push rax
    lea rdi,[rel gt_frame]
    xor eax,eax
    mov ecx,(GT_FRAME_BYTES+48+GT_STORAGE_BYTES)/8
    cld
    rep stosq
    mov dword [rel gt_reply],1
    mov dword [rel gt_count],0
    mov dword [rel gt_read],GT_REPLY_BYTES
    mov byte [rel gt_receiving],0
    pop rax
    pop rcx
    pop rdi
    ret

%include "core/abi/wdata.inc"
%macro WDATA_guest_transport 0
alignb 8
gt_start: resd 1
gt_count: resd 1
gt_read: resd 1
gt_bound: resb 1
gt_busy: resb 1
gt_receiving: resb 1
gt_receipt_mode: resb 1
gt_session: resq 1
gt_last_seq: resq 1
gt_policy_generation: resq 1
gt_audit_revision: resq 1
gt_audit_lost: resq 1
gt_audit_refusal: resq 1
gt_limit: resd 1
; Contiguous private buffers, zeroed together; no alignment gaps.
gt_frame: resb GT_FRAME_BYTES
gt_response: resb 48
gt_reply: resb GT_STORAGE_BYTES
%endmacro
WDATA_BSS_DEFER WDATA_guest_transport
