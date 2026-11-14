;; MODULE hv/snapshot_transport
;; LAYER 5
;; PURPOSE Finite SNAPSHOT scalar PIO route with original native endpoint and sequence.
;; EXPORTS snapshot_transport_configure_privacy, snapshot_transport_configure_visibility, snapshot_transport_configure_custody, snapshot_driver_pio, snapshot_app_pio, snapshot_transport_retire, snapshot_transport_configure
;; IMPORTS hv/guest_request, hv/guest_transport, hv/app_vm, core/smp
;; CAPS
;; OWNER saga:live_snapshot
; Codex / rc-live-claude. 5060 CONTROL / 5064 DATA, scalar32 only.
; CONTROL IN magic SNP1; OUT40 starts frame, OUT1 submits, OUT2 returns last
; sequence in a zeroed128B header. OUT0 clears staging, never replay floor.
; DATA OUT appends exactly40B; DATA IN streams native bounded frozen result.
ST_CONTROL equ 0x5060
ST_DATA equ 0x5064
ST_MAGIC equ 0x31504e53

 ; GUI owner installs exactly four trusted native callbacks at init. No callback
; address is decoded from the wire. The lower-layer producer owns only bytes,
; actual endpoint routing and invalidation, not GUI objects or a grant store.
; RDI submit, RSI read-word, RDX retire(register preserving), RCX replay-floor.
snapshot_transport_configure:
    cmp byte [rel snapshot_pio_busy],0
    jne .bad
    cmp dword [rel cmd_dispatch_depth],0
    jne .bad
    cmp byte [rel command_auth_remote_active],0
    jne .bad
    call snapshot_transport_retire
    mov [rel snapshot_pio_submit_op],rdi
    mov [rel snapshot_pio_word_op],rsi
    mov [rel snapshot_pio_retire_op],rdx
    mov [rel snapshot_pio_floor_op],rcx
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Original VMX/SVM stopped driver exit, never an app-exit fallback.
; Separate optional native custody callbacks; never wire pointers.
snapshot_transport_configure_custody:
    cmp byte [rel snapshot_pio_busy],0
    jne .bad
    cmp dword [rel cmd_dispatch_depth],0
    jne .bad
    push rdi
    push rsi
    call snapshot_transport_retire
    pop rsi
    pop rdi
    mov [rel snapshot_pio_custody_op],rdi
    mov [rel snapshot_pio_custody_current_op],rsi
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret
snapshot_transport_configure_visibility:
    cmp byte [rel command_auth_remote_active],0
    jne .bad
    cmp byte [rel snapshot_pio_busy],0
    jne .bad
    cmp dword [rel cmd_dispatch_depth],0
    jne .bad
    mov [rel snapshot_pio_visibility_op],rdi
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret
snapshot_transport_configure_privacy:
    cmp byte [rel command_auth_remote_active],0
    jne .bad
    cmp byte [rel snapshot_pio_busy],0
    jne .bad
    cmp dword [rel cmd_dispatch_depth],0
    jne .bad
    mov [rel snapshot_pio_privacy_op],rdi
    mov [rel snapshot_pio_privacy_current_op],rsi
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret
snapshot_driver_pio:
    push rbx
    push r12
    mov ebx,edi
    mov r12d,esi
    mov eax,edi
    shr eax,16
    cmp eax,ST_CONTROL
    je .ours
    cmp eax,ST_DATA
    jne .other
.ours:
    cmp dword [rel vcb_handoff_active],0
    jne .refuse
    call smp_current_logical
    test eax,eax
    jnz .refuse
    call gt_lifetime                 ; maintained driver identity; no duplicate bind
    test eax,eax
    jz .refuse
    lea rdi,[rel guest_request_endpoint]
    mov esi,[rel hv_linux_start_consumed]
    mov edx,1
    mov ecx,ebx
    mov r8d,r12d
    call snapshot_pio_pio
    jmp .out
.refuse:
    call snapshot_transport_retire
    mov eax,1
    xor edx,edx
    jmp .out
.other:
    xor eax,eax
.out:
    pop r12
    pop rbx
    ret

; Original app closed-exit proof gives actual endpoint and consumed START.
snapshot_app_pio:
    push rbx
    push r12
    mov ebx,edi
    mov r12d,esi
    call app_vm_exit_endpoint
    test rax,rax
    jz .bad
    mov rdi,rax
    mov esi,edx
    mov edx,2
    mov ecx,ebx
    mov r8d,r12d
    call snapshot_pio_pio
    jmp .out
.bad:
    call snapshot_transport_retire
    xor eax,eax
    xor edx,edx
.out:
    pop r12
    pop rbx
    ret

; Native endpoint, START, source, qualification, guest scalar. Never guest ptr.
snapshot_pio_pio:
    push rbx
    push r12
    push r13
    push r14
    mov rbx,rdi
    mov r12d,esi
    mov r13d,ecx
    mov r14d,r8d
    cmp byte [rel snapshot_pio_busy],0
    jne .refuse
    mov [rel snapshot_pio_source],edx
    cmp qword [rel snapshot_pio_submit_op],0
    je .refuse
    cmp qword [rel snapshot_pio_word_op],0
    je .refuse
    cmp qword [rel snapshot_pio_floor_op],0
    je .refuse
    mov eax,ecx
    shr eax,16
    cmp eax,ST_CONTROL
    je .port_ok
    cmp eax,ST_DATA
    jne .other
.port_ok:
    and ecx,0xffbf
    cmp ecx,3
    je .width_ok
    cmp ecx,11
    jne .invalidate
.width_ok:
    ; Validate full current native binding even for magic/floor queries.
    lea rdx,[rel snapshot_pio_probe]
    mov ecx,48
    call guest_request_binding_copy
    test eax,eax
    jz .invalidate
    mov rax,[rel snapshot_pio_probe+8]
    cmp rax,[rel snapshot_pio_binding]
    jb .invalidate
    je .bound
    call snapshot_transport_retire
    mov [rel snapshot_pio_binding],rax
.bound:
    test r13d,8
    jnz .input
    mov eax,r13d
    shr eax,16
    cmp eax,ST_DATA
    je .data
    cmp r14d,0
    je .clear
    cmp r14d,40
    je .begin
    cmp r14d,1
    je .submit
    cmp r14d,2
    je .sequence
    cmp r14d,5
    je .privacy
    cmp r14d,4
    je .visibility
    cmp r14d,3
    je .custody
    jmp .invalidate
.clear:
    call snapshot_transport_retire
    jmp .claimed
.begin:
    call snapshot_transport_retire
    mov byte [rel snapshot_pio_receiving],1
    jmp .claimed
.privacy:
    cmp qword [rel snapshot_pio_privacy_op],0
    je .invalidate
    mov dword [rel snapshot_pio_receipt_bytes],448
    jmp .observation
.visibility:
    cmp qword [rel snapshot_pio_visibility_op],0
    je .invalidate
    mov dword [rel snapshot_pio_receipt_bytes],512
    jmp .observation
.custody:
    mov dword [rel snapshot_pio_receipt_bytes],320
.observation:
    cmp dword [rel snapshot_pio_source],1
    jne .invalidate
    cmp byte [rel snapshot_pio_receiving],0
    jne .invalidate
    cmp qword [rel snapshot_pio_custody_op],0
    je .invalidate
    cmp qword [rel snapshot_pio_custody_current_op],0
    je .invalidate
    mov byte [rel snapshot_pio_busy],1
    mov rdi,rbx
    mov esi,r12d
    lea rdx,[rel snapshot_pio_custody]
    cmp dword [rel snapshot_pio_receipt_bytes],448
    je .privacy_call
    cmp dword [rel snapshot_pio_receipt_bytes],512
    jne .custody_call
    call [rel snapshot_pio_visibility_op]
    jmp .observation_done
.privacy_call:
    call [rel snapshot_pio_privacy_op]
    jmp .observation_done
.custody_call:
    call [rel snapshot_pio_custody_op]
.observation_done:
    mov byte [rel snapshot_pio_busy],0
    test eax,eax
    jnz .invalidate
    mov dword [rel snapshot_pio_mode],3
    mov dword [rel snapshot_pio_cursor],0
    jmp .claimed
.sequence:
    call snapshot_transport_retire
    mov dword [rel snapshot_pio_reply],1
    call [rel snapshot_pio_floor_op]           ; native producer replay floor
    mov [rel snapshot_pio_reply+8],rax
    mov dword [rel snapshot_pio_mode],1
    mov dword [rel snapshot_pio_cursor],0
    jmp .claimed
.data:
    cmp byte [rel snapshot_pio_receiving],1
    jne .invalidate
    mov eax,[rel snapshot_pio_count]
    cmp eax,40
    jae .invalidate
    lea rdx,[rel snapshot_pio_frame]
    mov [rdx+rax],r14d
    add dword [rel snapshot_pio_count],4
    jmp .claimed
.submit:
    cmp byte [rel snapshot_pio_receiving],1
    jne .invalidate
    mov byte [rel snapshot_pio_receiving],0
    cmp dword [rel snapshot_pio_count],40
    jne .invalidate
    mov byte [rel snapshot_pio_busy],1
    mov rdi,rbx
    mov esi,r12d
    lea rdx,[rel snapshot_pio_frame]
    mov ecx,40
    mov r8d,[rel snapshot_pio_source]
    call [rel snapshot_pio_submit_op]
    mov byte [rel snapshot_pio_busy],0
    test eax,eax
    jnz .error
    mov dword [rel snapshot_pio_mode],2
    mov dword [rel snapshot_pio_cursor],0
    jmp .claimed
.error:
    mov [rel snapshot_pio_reply+4],eax
    mov dword [rel snapshot_pio_reply],1
    mov rax,[rel snapshot_pio_frame+8]
    mov [rel snapshot_pio_reply+8],rax
    mov dword [rel snapshot_pio_mode],1
    mov dword [rel snapshot_pio_cursor],0
    jmp .claimed
.input:
    mov eax,r13d
    shr eax,16
    cmp eax,ST_CONTROL
    je .magic
    cmp dword [rel snapshot_pio_mode],3
    je .custody_word
    cmp dword [rel snapshot_pio_mode],2
    je .native_word
    cmp dword [rel snapshot_pio_mode],1
    jne .invalidate
    mov eax,[rel snapshot_pio_cursor]
    cmp eax,128
    jae .invalidate
    lea rdx,[rel snapshot_pio_reply]
    mov edx,[rdx+rax]
    add dword [rel snapshot_pio_cursor],4
    jmp .claimed_edx
.custody_word:
    cmp dword [rel snapshot_pio_source],1
    jne .invalidate
    mov eax,[rel snapshot_pio_cursor]
    cmp eax,[rel snapshot_pio_receipt_bytes]
    jae .invalidate
    mov byte [rel snapshot_pio_busy],1
    mov rdi,rbx
    mov esi,r12d
    lea rdx,[rel snapshot_pio_custody]
    cmp dword [rel snapshot_pio_receipt_bytes],448
    jne .custody_current
    cmp qword [rel snapshot_pio_privacy_current_op],0
    je .current_missing
    call [rel snapshot_pio_privacy_current_op]
    jmp .current_done
.current_missing:
    mov eax,-1
    jmp .current_done
.custody_current:
    call [rel snapshot_pio_custody_current_op]
.current_done:
    mov byte [rel snapshot_pio_busy],0
    test eax,eax
    jnz .invalidate
    mov eax,[rel snapshot_pio_cursor]
    lea rdx,[rel snapshot_pio_custody]
    mov edx,[rdx+rax]
    add dword [rel snapshot_pio_cursor],4
    jmp .claimed_edx
.native_word:
    mov rdi,rbx
    mov esi,r12d
    mov edx,[rel snapshot_pio_cursor]
    call [rel snapshot_pio_word_op]
    test eax,eax
    jnz .invalidate
    mov edx,ecx
    add dword [rel snapshot_pio_cursor],4
    jmp .claimed_edx
.magic:
    mov edx,ST_MAGIC
    jmp .claimed_edx
.invalidate:
    call snapshot_transport_retire
.refuse:
.claimed:
    xor edx,edx
.claimed_edx:
    mov eax,1
    jmp .out
.other:
    xor eax,eax
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Same canonical guest_request_retire invocation, register/flags preserving.
; Identity/floor remain monotonic. No adapter recursion from this leaf.
snapshot_transport_retire:
    pushfq
    cmp qword [rel snapshot_pio_retire_op],0
    je .no_producer
    call [rel snapshot_pio_retire_op]
.no_producer:
    push rax
    push rcx
    push rdi
    mov dword [rel snapshot_pio_count],0
    mov dword [rel snapshot_pio_cursor],0
    mov dword [rel snapshot_pio_mode],0
    mov byte [rel snapshot_pio_receiving],0
    lea rdi,[rel snapshot_pio_frame]
    xor eax,eax
    mov ecx,(40+128+512)/8
    cld
    rep stosq
    pop rdi
    pop rcx
    pop rax
    popfq
    ret
%include "core/abi/wdata.inc"
%macro WDATA_snapshot_transport 0
alignb 8
snapshot_pio_submit_op: resq 1
snapshot_pio_word_op: resq 1
snapshot_pio_retire_op: resq 1
snapshot_pio_floor_op: resq 1
snapshot_pio_visibility_op: resq 1
snapshot_pio_privacy_op: resq 1
snapshot_pio_privacy_current_op: resq 1
snapshot_pio_receipt_bytes: resq 1
snapshot_pio_custody_op: resq 1
snapshot_pio_custody_current_op: resq 1
snapshot_pio_binding: resq 1
snapshot_pio_count: resd 1
snapshot_pio_cursor: resd 1
snapshot_pio_mode: resd 1
snapshot_pio_source: resd 1
snapshot_pio_busy: resb 1
snapshot_pio_receiving: resb 1
alignb 8
snapshot_pio_probe: resb 48
snapshot_pio_frame: resb 40
snapshot_pio_reply: resb 128
snapshot_pio_custody: resb 512
snapshot_pio_data_end:
%endmacro
WDATA_BSS_DEFER WDATA_snapshot_transport
