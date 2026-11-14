;; MODULE hv/app_account_transport
;; LAYER 6
;; PURPOSE Inactive private native account mailbox for the qualified PID1.
;; EXPORTS app_account_private_pio, app_account_private_retire_all
;; IMPORTS hv/app_vm, gui/app_account_sink
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; ADMIN owns future common include/define and exact qualified runtime pin.
; No production activation here. A real closed app exit identifies this VM,
; not a Linux PID: private PID1 isolation is a final-artifact trust assumption.
%ifdef APP_ACCOUNT_PRIVATE_ABI_V1
%ifndef APP_ACCOUNT_RECIPIENT_ABI_V1
%error "private account transport requires independent recipient containment"
%endif

; EDI normalized actual PIO qualification, ESI guest EAX ->EAX1/0, EDX IN32.
; 50c0 OUT32:1 FETCH,2 SEND,3 CURRENT,4 FINISH,5 CANCEL; IN32 result1/0.
; 50c4 IN32 streams original192 then frame512 once, in order, wiping each word.
; CURRENT/FINISH/CANCEL accept48 OUT32 original words at50c4, no pointer/seek.
; Unknown/malformed/partial transactions never grant authority or drop custody.
app_account_private_pio:
    push rbx
    push r12
    push r13
    mov ebx,edi
    mov r12d,esi
    cmp dword [rel apt_busy],0
    jne .bad
    call app_vm_exit_endpoint
    test rax,rax
    jz .bad
    mov eax,ebx
    and eax,0xffbf
    cmp eax,3
    je .width
    cmp eax,11
    jne .bad
.width:
    mov r13d,ebx
    shr r13d,16
    cmp r13d,0x50c0
    je .admitted
    cmp r13d,0x50c4
    jne .bad
.admitted:
    mov dword [rel apt_busy],1
    cmp r13d,0x50c4
    je .data
    test ebx,8
    jnz .status
    mov dword [rel apt_result],0
    cmp r12d,1
    je .begin
    cmp r12d,2
    je .begin
    cmp dword [rel apt_phase],3
    jne .cancel
    cmp r12d,3
    je .query
    cmp r12d,4
    je .query
    cmp r12d,5
    jne .cancel
.query:
    mov eax,r12d
    inc eax                         ; phase4 CURRENT,5 FINISH,6 CANCEL
    mov [rel apt_phase],eax
    mov dword [rel apt_upload],0
    jmp .zero
.begin:
    cmp dword [rel apt_phase],0
    jne .cancel
    mov dword [rel apt_phase],1    ; owned before native provider callbacks
    mov edi,r12d
    lea rsi,[rel apt_staging]
    mov edx,704
    call app_account_sink_acquire
    cmp eax,1
    jne .cancel
    cmp dword [rel apt_phase],1
    jne .cancel
    lea rdi,[rel apt_context]
    lea rsi,[rel apt_staging]
    mov ecx,24
    cld
    rep movsq
    mov dword [rel apt_cursor],0
    mov dword [rel apt_phase],2
    mov dword [rel apt_result],1
    jmp .zero
.status:
    cmp dword [rel apt_phase],2
    je .status_current
    cmp dword [rel apt_phase],3
    jne .status_value
.status_current:
    call apt_current
    cmp eax,1
    jne .cancel
.status_value:
    mov edx,[rel apt_result]
    cmp dword [rel apt_phase],0
    jne .ok
    mov dword [rel apt_result],0    ; consume the sole completion response
    jmp .ok
.data:
    test ebx,8
    jz .upload
    cmp dword [rel apt_phase],2
    jne .cancel
    call apt_current
    cmp eax,1
    jne .cancel
    ; A synchronous account wipe may have erased this whole transaction.
    cmp dword [rel apt_phase],2
    jne .cancel
    mov eax,[rel apt_cursor]
    cmp eax,704
    jae .cancel
    lea rcx,[rel apt_staging]
    mov edx,[rcx+rax]
    mov dword [rcx+rax],0
    add eax,4
    mov [rel apt_cursor],eax
    cmp eax,704
    jne .ok
    mov dword [rel apt_phase],3
    jmp .ok
.upload:
    cmp dword [rel apt_phase],4
    je .upload_current
    cmp dword [rel apt_phase],5
    je .upload_current
    cmp dword [rel apt_phase],6
    jne .cancel
.upload_current:
    call apt_current
    cmp eax,1
    jne .cancel
    mov eax,[rel apt_phase]
    cmp eax,4
    je .upload_word
    cmp eax,5
    je .upload_word
    cmp eax,6
    jne .cancel
.upload_word:
    mov ecx,[rel apt_upload]
    cmp ecx,192
    jae .cancel
    lea rdx,[rel apt_query]
    mov [rdx+rcx],r12d
    add ecx,4
    mov [rel apt_upload],ecx
    cmp ecx,192
    jne .zero
    mov r12d,eax
    lea rdi,[rel apt_query]
    lea rsi,[rel apt_context]
    mov ecx,24
    cld
    repe cmpsq
    jne .foreign
    cmp r12d,6
    je .cancel
    cmp r12d,5
    je .finish
    mov dword [rel apt_result],1
    jmp .query_done
.finish:
    cmp dword [rel apt_cursor],704
    jne .cancel
    lea rdi,[rel apt_staging]
    xor eax,eax
    mov ecx,88
    repe scasq
    jne .cancel
    lea rdi,[rel apt_context]
    call app_account_sink_finish
    cmp eax,1
    jne .cancel
    call app_account_private_retire_all
    ; One completion response remains; duplicate FINISH cannot reuse it.
    mov dword [rel apt_result],1
    jmp .zero
.foreign:
    ; A foreign original cannot erase the current native operation. Query
    ; scratch is wiped and native custody remains; it cannot begin anew.
    mov dword [rel apt_result],0
.query_done:
    lea rdi,[rel apt_query]
    xor eax,eax
    mov ecx,24
    cld
    rep stosq
    mov dword [rel apt_upload],0
    mov dword [rel apt_phase],3
    jmp .zero
.cancel:
    ; The sink's independent original survives this staging clear. Its exact
    ; retire either contains that VM or retains custody on refusal/replacement.
    lea rdi,[rel apt_context]
    call app_account_sink_retire
    call app_account_private_retire_all
.zero:
    xor edx,edx
.ok:
    mov dword [rel apt_busy],0
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
    xor edx,edx
.out:
    pop r13
    pop r12
    pop rbx
    ret

apt_current:
    sub rsp,8
    lea rdi,[rel apt_context]
    call app_account_sink_current
    add rsp,8
    ret

; Synchronous sink-clear hook. No calls, no authority query, no recursive
; retirement. Preserve all caller state and the outer mailbox busy ownership.
app_account_private_retire_all:
    pushfq
    push rax
    push rcx
    push rdi
    lea rdi,[rel apt_sensitive_begin]
    xor eax,eax
    mov ecx,(apt_sensitive_end-apt_sensitive_begin)/8
    cld
    rep stosq
    pop rdi
    pop rcx
    pop rax
    popfq
    ret

%include "core/abi/wdata.inc"
%macro WDATA_hv_app_account_transport 0
align 8
apt_busy: dd 0
    dd 0
apt_sensitive_begin:
apt_phase: dd 0
apt_result: dd 0
apt_cursor: dd 0
apt_upload: dd 0
apt_context: times 192 db 0
apt_staging: times 704 db 0
apt_query: times 192 db 0
apt_sensitive_end:
%endmacro
WDATA_DEFER WDATA_hv_app_account_transport
%endif
