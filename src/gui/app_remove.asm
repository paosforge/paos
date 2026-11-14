;; MODULE gui/app_remove
;; LAYER 6
;; PURPOSE Physical owner REMOVE coordinator for one exact authenticated installed row.
;; EXPORTS app_remove_begin, app_remove_poll, app_remove_tick, app_remove_intent_check, app_remove_store_busy
;; IMPORTS gui/settings_apps, gui/app_launch_flow, svc/app_store, svc/app_execution_state, svc/command, sec/session, sec/app_store_seal, sec/app_store_intent, sec/app_install_grants, core/smp
;; OWNER saga:app_store
;; CONTEXT: bsp_only
%include "fs/app_store_layout.inc"
ARM_PENDING equ 2
ARM_MARK equ 1
ARM_QUIESCE equ 2
ARM_GRANTS equ 3
ARM_FINAL equ 4

; begin(RDI exact displayed native row256)->EAX1 accepted/RDXticket,
; 3 unavailable/0 refused, RDX0. Only Settings' fixed physical consumer mints
; this operation. Builtins and arbitrary names/agent/script callers have no row.
app_remove_begin:
    push rbx
    push r12
    push r13
    mov r12,rdi
    mov esi,256
    call arm_span
    test eax,eax
    jz .no
    call arm_enter
    test eax,eax
    jz .no
    call app_remove_store_busy
    test eax,eax
    jnz .fail
    call arm_owner
    test eax,eax
    jz .fail
    mov [rel arm_epoch],rdx
    cmp qword [rel arm_serial],-1
    je .fail
    lea rdi,[rel arm_row]
    mov rsi,r12
    mov ecx,32
    cld
    rep movsq
    lea rdi,[rel arm_image]
    mov esi,ASL_MAX
    lea rdx,[rel arm_token]
    lea rcx,[rel arm_length]
    call app_store_snapshot
    cmp eax,1
    jne .unavailable
    ; Require room for both denial and finalization generations before confirm.
    mov rax,[rel arm_image+ASL_GENERATION]
    cmp rax,-2
    jae .fail
    cmp [rel arm_row+8],rax
    jne .fail
    ; An interrupted durable removal is not a new removal opportunity. Recovery
    ; remains read-only until an explicit native recovery transaction exists.
    lea rdi,[rel arm_image+ASL_HEADER]
    mov ecx,ASL_SLOTS
.denial:
    cmp dword [rdi+ASL_STATE],ASL_REMOVING
    je .unavailable
    add rdi,ASL_SLOT_BYTES
    loop .denial
    mov r12d,0
    lea r13,[rel arm_image+ASL_HEADER]
.find:
    cmp dword [r13+ASL_STATE],ASL_LIVE
    jne .next
    mov rax,[r13+ASL_ID]
    cmp rax,[rel arm_row+16]
    je .identity
.next:
    add r13,ASL_SLOT_BYTES
    inc r12d
    cmp r12d,ASL_SLOTS
    jb .find
    jmp .fail
.identity:
    lea rdi,[rel arm_expected]
    xor eax,eax
    mov ecx,32
    rep stosq
    mov qword [rel arm_expected],1
    mov rax,[rel arm_image+ASL_GENERATION]
    mov [rel arm_expected+8],rax
    mov rax,[r13+ASL_ID]
    mov [rel arm_expected+16],rax
    lea rdi,[rel arm_expected+24]
    lea rsi,[r13+ASL_DIGEST]
    mov ecx,20
    rep movsq
    lea rdi,[rel arm_row]
    lea rsi,[rel arm_expected]
    mov ecx,32
    repe cmpsq
    jne .fail
    mov [rel arm_slot],r12
    mov eax,[r13+ASL_PROFILE]
    mov [rel arm_profile],rax
    mov dword [r13+ASL_STATE],ASL_REMOVING
    inc qword [rel arm_image+ASL_GENERATION]
    lea rdi,[rel arm_image]
    mov rsi,[rel arm_length]
    call app_store_seal_sign
    cmp eax,1
    jne .fail
    lea rdi,[rel arm_row]
    mov rsi,[rel arm_epoch]
    call settings_apps_remove_confirm_take
    cmp eax,1
    jne .fail
    call arm_owner
    test eax,eax
    jz .fail
    cmp rdx,[rel arm_epoch]
    jne .fail
    inc qword [rel arm_serial]
    mov rax,[rel arm_serial]
    mov [rel arm_ticket],rax
    mov byte [rel arm_confirmed],1
    mov dword [rel arm_status],ARM_PENDING
    mov dword [rel arm_phase],ARM_MARK
    call arm_write
    test rax,rax
    jz .marked
    mov dword [rel arm_status],3
    cmp rax,-3
    jne .accepted
    mov dword [rel arm_status],4
    jmp .accepted
.marked:
    mov dword [rel arm_phase],ARM_QUIESCE
.accepted:
    mov eax,1
    mov rdx,[rel arm_ticket]
    jmp .leave
.unavailable:
    mov eax,3
    xor edx,edx
    jmp .leave
.fail:
    xor eax,eax
    xor edx,edx
.leave:
    mov byte [rel arm_busy],0
    jmp .out
.no:
    xor eax,eax
    xor edx,edx
.out:
    pop r13
    pop r12
    pop rbx
    ret

; poll(RDI ticket)->1 fully removed,2 pending,3 pre-effect failure,
; 4 uncertain/partial,0 invalid. One bounded phase per cooperative call; no spin.
app_remove_poll:
    push rbx
    mov rbx,rdi
    call arm_enter
    test eax,eax
    jz .no
    test rbx,rbx
    jz .invalid
    cmp rbx,[rel arm_ticket]
    jne .invalid
    call arm_owner
    test eax,eax
    jz .lost
    cmp rdx,[rel arm_epoch]
    jne .lost
    cmp dword [rel arm_status],ARM_PENDING
    jne .result
    cmp dword [rel arm_phase],ARM_QUIESCE
    je .quiesce
    cmp dword [rel arm_phase],ARM_GRANTS
    je .grants
    cmp dword [rel arm_phase],ARM_FINAL
    jne .partial
    call arm_finalize
    test rax,rax
    jnz .partial
    mov dword [rel arm_status],1
    mov byte [rel arm_confirmed],0
    jmp .result
.quiesce:
    lea rdi,[rel arm_row+24]
    mov rsi,[rel arm_epoch]
    call app_launch_flow_quiesce
    cmp eax,2
    je .result
    cmp eax,1
    jne .partial
    mov dword [rel arm_phase],ARM_GRANTS
    jmp .result
.grants:
    lea rdi,[rel arm_row+24]
    mov rsi,[rel arm_profile]
    mov rdx,[rel arm_epoch]
    call app_install_grants_revoke_exact
    cmp eax,1
    jne .partial
    mov dword [rel arm_phase],ARM_FINAL
    jmp .result
.lost:
    cmp dword [rel arm_status],ARM_PENDING
    jne .invalid
.partial:
    mov dword [rel arm_status],4
    mov byte [rel arm_confirmed],0
.result:
    mov eax,[rel arm_status]
    jmp .leave
.invalid:
    xor eax,eax
.leave:
    mov byte [rel arm_busy],0
    pop rbx
    ret
.no:
    xor eax,eax
    pop rbx
    ret

; Native idle turn keeps confirmed removal progressing even if its view closes.
app_remove_tick:
    cmp dword [rel arm_status],ARM_PENDING
    jne .done
    mov rdi,[rel arm_ticket]
    jmp app_remove_poll
.done:
    ret

; Fixed write authority. This never calls the consumed Settings confirmation
; again; private confirmed can be set only after that exact consumer returns1.
app_remove_intent_check:
    push rbx
    mov rbx,rdi
    call smp_current_logical
    test eax,eax
    jnz .no
    cmp byte [rel arm_busy],1
    jne .no
    cmp byte [rel arm_confirmed],1
    jne .no
    cmp dword [rel arm_status],ARM_PENDING
    jne .no
    test rbx,rbx
    jz .no
    cmp rbx,[rel arm_ticket]
    jne .no
    mov eax,[rel arm_phase]
    cmp eax,ARM_MARK
    je .owner
    cmp eax,ARM_FINAL
    jne .no
.owner:
    call arm_owner
    test eax,eax
    jz .no
    cmp rdx,[rel arm_epoch]
    jne .no
    mov eax,1
    pop rbx
    ret
.no:
    xor eax,eax
    pop rbx
    ret

; Installation cannot race an incomplete or uncertain removal. Reboot does not
; authorize recovery writes: authenticated REMOVING remains unavailable to list.
app_remove_store_busy:
    mov eax,[rel arm_status]
    cmp eax,ARM_PENDING
    je .yes
    cmp eax,4
    je .yes
    xor eax,eax
    ret
.yes:
    mov eax,1
    ret

arm_write:
    sub rsp,8
    call app_execution_invalidate    ; mark and final writes both retire old unsigned bindings
    lea rdi,[rel arm_token]
    lea rsi,[rel arm_image]
    mov rdx,[rel arm_length]
    mov rcx,[rel arm_ticket]
    mov r8d,2
    call app_store_intent_write
    cmp rax,-3
    jne .out
    call app_execution_uncertain     ; original result retained even if valid bytes reached DATA
.out:
    add rsp,8
    ret

; Fresh read must byte-match the durable REMOVING snapshot. A view's intervening
; bind is harmless: copy its fresh token only after the exact record matches.
; Any other catalog change refuses; never remove a new or unrelated instance.
arm_finalize:
    push rbx
    push r12
    push r13
    lea rdi,[rel arm_fresh]
    mov esi,ASL_MAX
    lea rdx,[rel arm_fresh_token]
    lea rcx,[rel arm_fresh_length]
    call app_store_snapshot
    cmp eax,1
    jne .no
    mov rcx,[rel arm_length]
    cmp rcx,[rel arm_fresh_length]
    jne .no
    lea rdi,[rel arm_image]
    lea rsi,[rel arm_fresh]
    cld
    repe cmpsb
    jne .no
    lea rdi,[rel arm_token]
    lea rsi,[rel arm_fresh_token]
    mov ecx,14
    rep movsq
    mov rbx,[rel arm_slot]
    shl rbx,8
    lea rax,[rel arm_image+ASL_HEADER]
    add rbx,rax
    mov r12,[rbx+ASL_OFFSET]
    mov r13,[rbx+ASL_LENGTH]
    lea rdi,[rel arm_image]
    add rdi,r12
    lea rsi,[rdi+r13]
    mov rcx,[rel arm_length]
    sub rcx,r12
    sub rcx,r13
    rep movsb
    sub [rel arm_length],r13
    lea rdi,[rel arm_image]
    add rdi,[rel arm_length]
    mov rcx,r13
    xor eax,eax
    rep stosb
    mov rdi,rbx
    mov ecx,ASL_SLOT_BYTES/8
    rep stosq
    lea rdi,[rel arm_image+ASL_HEADER]
    mov ecx,ASL_SLOTS
.offsets:
    cmp dword [rdi+ASL_STATE],0
    je .next
    cmp [rdi+ASL_OFFSET],r12
    jbe .next
    sub [rdi+ASL_OFFSET],r13
.next:
    add rdi,ASL_SLOT_BYTES
    loop .offsets
    dec dword [rel arm_image+ASL_COUNT]
    inc qword [rel arm_image+ASL_GENERATION]
    mov rax,[rel arm_length]
    mov [rel arm_image+ASL_TOTAL],rax
    lea rdi,[rel arm_image]
    mov rsi,rax
    call app_store_seal_sign
    cmp eax,1
    jne .no
    call arm_write
    jmp .out
.no:
    mov rax,-1
.out:
    pop r13
    pop r12
    pop rbx
    ret

arm_owner:
    cmp byte [rel cmd_in_dispatch],0
    jne .no
    cmp dword [rel cmd_dispatch_depth],0
    jne .no
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .no
    cmp rdx,-1
    je .no
    mov eax,1
    ret
.no:
    xor eax,eax
    xor edx,edx
    ret
arm_enter:
    call smp_current_logical
    test eax,eax
    jnz .no
    cmp byte [rel arm_busy],0
    jne .no
    mov byte [rel arm_busy],1
    mov eax,1
    ret
.no:
    xor eax,eax
    ret
arm_span:
    test rdi,rdi
    jz .no
    mov rax,rdi
    add rax,rsi
    jc .no
    lea rdx,[rel arm_private_end]
    cmp rdi,rdx
    jae .yes
    lea rdx,[rel arm_private_begin]
    cmp rax,rdx
    ja .no
.yes:
    mov eax,1
    ret
.no:
    xor eax,eax
    ret
%include "core/abi/wdata.inc"
%macro WDATA_BSS_gui_app_remove 0
alignb 8
arm_private_begin:
arm_busy: resb 1
arm_confirmed: resb 1
alignb 8
arm_serial: resq 1
arm_ticket: resq 1
arm_status: resd 1
arm_phase: resd 1
arm_epoch: resq 1
arm_slot: resq 1
arm_profile: resq 1
arm_row: resb 256
arm_expected: resb 256
arm_token: resb 112
arm_length: resq 1
arm_image: resb ASL_MAX
arm_fresh_token: resb 112
arm_fresh_length: resq 1
arm_fresh: resb ASL_MAX
arm_private_end:
%endmacro
WDATA_BSS_DEFER WDATA_BSS_gui_app_remove
