;; MODULE gui/app_account_sink
;; LAYER 6
;; PURPOSE Inactive native original-context private account sink.
;; EXPORTS app_account_sink_acquire, app_account_sink_finish, app_account_recipient_tick, app_account_recipient_revoke, app_account_configure, app_account_begin, app_account_sink_ready, app_account_sink_write, app_account_sink_take, app_account_sink_current, app_account_sink_retire, app_account_retire_all
;; IMPORTS hv/app_account_transport, hv/app_vm, hv/app_vm_boot, hv/app_runtime, core/smp, gui/account_local
;; CAPS
;; OWNER saga:gui
;; CONTEXT: bsp_only
; No production include, PIO route or APP_ACCOUNT_SINK_ABI_V2 definition here.
; Configure is native initialization only, never a guest/public setter. Its
; input must be the exact qualified protected runtime descriptor from the
; maintained final artifact/Q proof. Default unconfigured always refuses.
%macro AAC_CALL 1
    sub rsp,8
    call %1
    add rsp,8
%endmacro

aac_local:
    cmp byte [rel cmd_in_dispatch],0
    jne .bad
    cmp dword [rel cmd_dispatch_depth],0
    jne .bad
    cmp byte [rel command_auth_remote_active],0
    jne .bad
    AAC_CALL smp_current_logical
    test eax,eax
    setz al
    movzx eax,al
    ret
.bad:
    xor eax,eax
    ret

; RDI exact qualified native runtime descriptor128, ESI128 ->1/0.
; No pointer retained. Actual signed runtime producer is independently read.
app_account_configure:
    push rbx
    mov rbx,rdi
    cmp esi,128
    jne .bad
    test rbx,rbx
    jz .bad
    call aac_local
    test eax,eax
    jz .bad
    cmp dword [rel aac_phase],0
    jne .bad
%ifdef APP_ACCOUNT_RECIPIENT_ABI_V1
    cmp dword [rel aac_recipient_held],0
    jne .bad
%endif
    call app_vm_exit_endpoint
    test rax,rax
    jnz .bad
    lea rdi,[rel aac_runtime_current]
    mov esi,128
    call app_runtime_descriptor
    cmp eax,1
    jne .bad
    lea rdi,[rel aac_runtime_current]
    mov rsi,rbx
    mov ecx,16
    cld
    repe cmpsq
    jne .bad
    cmp qword [rel aac_runtime_current],1
    jne .bad
    mov rax,[rel aac_runtime_current+8]
    test rax,rax
    jz .bad
    cmp rax,-1
    je .bad
    lea rdi,[rel aac_runtime_pin]
    lea rsi,[rel aac_runtime_current]
    mov ecx,16
    rep movsq
    mov dword [rel aac_configured],1
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; Native currentness, not guest-supplied principal/epoch/UID/profile assertion.
aac_actual:
    cmp dword [rel aac_configured],1
    jne .bad
    AAC_CALL aac_local
    test eax,eax
    jz .bad
    AAC_CALL app_vm_exit_endpoint
    test rax,rax
    jz .bad
    mov rdi,[rel avm_instance]
    lea rsi,[rel aac_current]
    mov edx,128
    AAC_CALL app_vm_snapshot
    cmp eax,1
    jne .bad
    AAC_CALL app_vm_boot_current
    cmp eax,1
    jne .bad
    lea rdi,[rel aac_runtime_current]
    mov esi,128
    AAC_CALL app_runtime_descriptor
    cmp eax,1
    jne .bad
    lea rdi,[rel aac_runtime_current]
    lea rsi,[rel aac_runtime_pin]
    mov ecx,16
    cld
    repe cmpsq
    jne .bad
    mov rax,[rel aac_current+104]
    test rax,rax
    jz .bad
    cmp rax,-1
    je .bad
    cmp rax,[rel aac_runtime_pin+8]
    jne .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

aac_policy:
    lea rdi,[rel aac_host_current]
    xor eax,eax
    mov ecx,32
    cld
    rep stosq
    lea rdi,[rel aac_current]
    lea rsi,[rel aac_host_current]
    mov edx,256
    mov ecx,[rel aac_port]
    AAC_CALL account_policy_copy
    cmp eax,1
    jne .bad
    test rdx,rdx
    jz .bad
    cmp rdx,-1
    je .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

aac_authorized:
    AAC_CALL aac_actual
    test eax,eax
    jz .bad
    lea rdi,[rel aac_current]
    lea rsi,[rel aac_context]
    mov ecx,16
    cld
    repe cmpsq
    jne .bad
    AAC_CALL aac_policy
    test eax,eax
    jz .bad
    cmp rdx,[rel aac_context+144]
    jne .bad
    lea rdi,[rel aac_host_current]
    lea rsi,[rel aac_host]
    mov ecx,32
    cld
    repe cmpsq
    jne .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; EDI fixed typed operation1FETCH/2SEND, actual closed app exit only.
; No frame, context, generation, credential or callback address from Linux.
; Direct LIVE consume is synchronous and independently rechecks original192.
app_account_begin:
    push rbx
%ifdef APP_ACCOUNT_RECIPIENT_ABI_V1
    cmp dword [rel aac_recipient_held],0
    jne .bad
%endif
    cmp dword [rel aac_phase],0
    jne .bad
    cmp edi,1
    je .fetch
    cmp edi,2
    jne .bad
    mov dword [rel aac_port],465
    jmp .op
.fetch:
    mov dword [rel aac_port],993
.op:
    mov ebx,edi
    call aac_actual
    test eax,eax
    jz .bad
    call aac_policy
    test eax,eax
    jz .bad
    cmp qword [rel aac_operation_floor],-1
    je .bad
    cmp qword [rel aac_worker_floor],-1
    je .bad
    inc qword [rel aac_operation_floor]
    inc qword [rel aac_worker_floor]
    mov [rel aac_context+144],rdx
    mov [rel aac_context+152],ebx
    mov eax,[rel aac_port]
    mov [rel aac_context+156],eax
    lea rdi,[rel aac_context]
    lea rsi,[rel aac_current]
    mov ecx,16
    cld
    rep movsq
    mov rax,[rel aac_current+104]
    mov [rel aac_context+160],rax
    mov rax,[rel aac_worker_floor]
    mov [rel aac_context+128],rax
    mov rbx,[rel aac_operation_floor]
    mov [rel aac_context+136],rbx
    lea rdi,[rel aac_host]
    lea rsi,[rel aac_host_current]
    mov ecx,32
    rep movsq
    mov dword [rel aac_phase],1
    call account_local_consume
    ; Never erase a replacement as a consequence of the original return.
    cmp rbx,[rel aac_context+136]
    jne .bad
    cmp eax,1
    jne .cancel
    cmp dword [rel aac_phase],2
    jne .cancel
    mov eax,1
    pop rbx
    ret
.cancel:
    call aac_clear
.bad:
    xor eax,eax
    pop rbx
    ret

; RDI native output192, ESI192 ->1/0. Nonsecret original context only.
app_account_sink_ready:
    push rbx
    mov rbx,rdi
    cmp esi,192
    jne .bad
    test rbx,rbx
    jz .bad
    cmp dword [rel aac_phase],1
    jne .bad
    call aac_authorized
    test eax,eax
    jz .cancel
    mov rdi,rbx
    lea rsi,[rel aac_context]
    mov ecx,24
    cld
    rep movsq
    mov eax,1
    pop rbx
    ret
.cancel:
    call aac_clear
.bad:
    xor eax,eax
    pop rbx
    ret

; RDI exact original192, RSI private typed512, EDX512 ->1 once/0.
; Wrong original never retires replacement. Exact write attempt burns BEFORE
; validation/copy. No external callback after copying credential bytes.
app_account_sink_write:
    push rbx
    push r12
    push r13
    mov r12,rsi
    mov r13d,edx
    test rdi,rdi
    jz .bad
    cmp dword [rel aac_phase],1
    jne .bad
    lea rsi,[rel aac_context]
    mov ecx,24
    cld
    repe cmpsq
    jne .bad
    mov dword [rel aac_phase],3
    cmp r13d,512
    jne .cancel
    test r12,r12
    jz .cancel
    call aac_authorized
    test eax,eax
    jz .cancel
    cmp dword [r12],1
    jne .cancel
    cmp dword [r12+12],0
    jne .cancel
    mov ebx,[r12+4]
    test ebx,ebx
    jz .cancel
    cmp ebx,39
    ja .cancel
    mov r8d,[r12+8]
    test r8d,r8d
    jz .cancel
    cmp r8d,128
    ja .cancel
    xor ecx,ecx
.account:
    mov al,[r12+16+rcx]
    cmp ecx,ebx
    jae .account_tail
    cmp al,33
    jb .cancel
    cmp al,126
    ja .cancel
    cmp al,':'
    je .cancel
    jmp .account_next
.account_tail:
    test al,al
    jnz .cancel
.account_next:
    inc ecx
    cmp ecx,40
    jb .account
    xor ecx,ecx
.secret:
    mov al,[r12+56+rcx]
    cmp ecx,r8d
    jae .secret_tail
    cmp al,32
    jb .cancel
    cmp al,126
    ja .cancel
    jmp .secret_next
.secret_tail:
    test al,al
    jnz .cancel
.secret_next:
    inc ecx
    cmp ecx,128
    jb .secret
    lea rdi,[r12+184]
    lea rsi,[rel aac_host]
    mov ecx,32
    cld
    repe cmpsq
    jne .cancel
    lea rdi,[r12+440]
    mov ecx,9
    xor eax,eax
    repe scasq
    jne .cancel
    lea rdi,[rel aac_frame]
    mov rsi,r12
    mov ecx,64
    rep movsq
    mov dword [rel aac_phase],2
    mov eax,1
    jmp .out
.cancel:
    call aac_clear
.bad:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Trusted disjoint native buffers only; never guest pointers or a public getter.
; RDI exact original192, RSI private output512, EDX512 ->1 once/0.
; Wrong original cannot burn replacement. The exact original attempt burns
; before capacity/currentness validation. Fixed-capacity output is zero on
; refusal; other capacities are not writable. No callback after secret copy.
app_account_sink_take:
    push rbx
    push r12
    push r13
    mov rbx,rdi
    mov r12,rsi
    mov r13d,edx
    cmp r13d,512
    jne .original
    test r12,r12
    jz .original
    mov rdi,r12
    xor eax,eax
    mov ecx,64
    cld
    rep stosq
.original:
    test rbx,rbx
    jz .bad
    cmp dword [rel aac_phase],2
    jne .bad
    mov rdi,rbx
    lea rsi,[rel aac_context]
    mov ecx,24
    cld
    repe cmpsq
    jne .bad
    mov dword [rel aac_phase],3
    cmp r13d,512
    jne .cancel
    test r12,r12
    jz .cancel
    call aac_authorized
    test eax,eax
    jz .cancel
%ifdef APP_ACCOUNT_RECIPIENT_ABI_V1
    ; Retain the exact native original BEFORE any credential leaves. This
    ; separate custody survives aac_clear, policy/wipe reentry and refusal.
    cmp dword [rel aac_recipient_held],0
    jne .cancel
    lea rdi,[rel aac_recipient_context]
    lea rsi,[rel aac_context]
    mov ecx,24
    cld
    rep movsq
    mov dword [rel aac_recipient_held],1
%endif
    mov rdi,r12
    lea rsi,[rel aac_frame]
    mov ecx,64
    cld
    rep movsq
    lea rdi,[rel aac_frame]
    xor eax,eax
    mov ecx,64
    rep stosq
    ; Retain original custody until explicit exact retirement; no replacement
    ; begin, duplicate take or ready succeeds while the operation is inflight.
    mov dword [rel aac_phase],4
    mov eax,1
    jmp .out
.cancel:
    call aac_clear
.bad:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

; RDI exact original192 ->1/0, no credential output or new authority.
; Future native transport must use this on every bounded transfer/result.
; A foreign original cannot cancel replacement. Current original staleness
; erases the whole pending region; restored authority cannot revive it.
app_account_sink_current:
    push rbx
    test rdi,rdi
    jz .bad
    cmp dword [rel aac_phase],4
    jne .bad
    lea rsi,[rel aac_context]
    mov ecx,24
    cld
    repe cmpsq
    jne .bad
    call aac_authorized
    test eax,eax
    jz .cancel
    mov eax,1
    pop rbx
    ret
.cancel:
    call aac_clear
.bad:
    xor eax,eax
    pop rbx
    ret

%ifdef APP_ACCOUNT_PRIVATE_ABI_V1
%ifndef APP_ACCOUNT_RECIPIENT_ABI_V1
%error "private account transport requires independent recipient containment"
%endif
; Trusted native transport only. EDI fixed operation, RSI disjoint output704,
; EDX704 ->1/0. Actual original is derived here, never chosen by Linux. This
; is not a guest pointer API. The one native copy precedes the private stream.
app_account_sink_acquire:
    push rbx
    mov rbx,rsi
    cmp edx,704
    jne .bad
    test rbx,rbx
    jz .bad
    push rdi
    mov rdi,rbx
    xor eax,eax
    mov ecx,88
    cld
    rep stosq
    pop rdi
    call app_account_begin
    cmp eax,1
    jne .wipe
    cmp dword [rel aac_phase],2
    jne .wipe
    mov rdi,rbx
    lea rsi,[rel aac_context]
    mov ecx,24
    cld
    rep movsq
    mov rdi,rbx
    lea rsi,[rbx+192]
    mov edx,512
    call app_account_sink_take
    cmp eax,1
    je .out
.wipe:
    mov rdi,rbx
    xor eax,eax
    mov ecx,88
    cld
    rep stosq
.bad:
    xor eax,eax
.out:
    pop rbx
    ret

; Separate successful completion, trusted native exact original192 only.
; Only the private transport may call this, after its entire native stream
; was consumed/wiped and the qualified PID1 has reaped/closed/wiped. Native
; checks cannot prove Linux erasure or turn a PID1 assertion into identity.
app_account_sink_finish:
    push rbx
    mov rbx,rdi
    test rbx,rbx
    jz .bad
    cmp dword [rel aac_recipient_held],1
    jne .bad
    cmp dword [rel aac_revoke_busy],0
    jne .bad
    cmp dword [rel aac_phase],4
    jne .bad
    lea rsi,[rel aac_context]
    mov ecx,24
    cld
    repe cmpsq
    jne .bad
    ; Burn this completion before any authority provider can reenter. Wipe
    ; and independent revocation win: no late success may discharge custody.
    mov dword [rel aac_phase],5
    call aac_authorized
    cmp eax,1
    jne .cancel
    cmp dword [rel aac_phase],5
    jne .bad
    cmp dword [rel aac_recipient_held],1
    jne .bad
    cmp dword [rel aac_revoke_busy],0
    jne .bad
    mov rdi,rbx
    lea rsi,[rel aac_context]
    mov ecx,24
    cld
    repe cmpsq
    jne .cancel
    mov rdi,rbx
    lea rsi,[rel aac_recipient_context]
    mov ecx,24
    repe cmpsq
    jne .cancel
    lea rdi,[rel aac_frame]
    xor eax,eax
    mov ecx,64
    repe scasq
    jne .cancel
    ; No callbacks after the last native checks. Do not use aac_clear: its
    ; cancellation path intentionally contains a delivered Linux recipient.
    lea rdi,[rel aac_sensitive_begin]
    mov ecx,(aac_sensitive_end-aac_sensitive_begin)/8
    rep stosq
    lea rdi,[rel aac_recipient_context]
    mov ecx,24
    rep stosq
    mov dword [rel aac_recipient_held],0
    mov eax,1
    pop rbx
    ret
.cancel:
    call aac_clear
.bad:
    xor eax,eax
    pop rbx
    ret
%endif

; Conditional original cancellation, no replacement cancellation.
app_account_sink_retire:
    test rdi,rdi
    jz .bad
    cmp dword [rel aac_phase],0
    je .bad
    lea rsi,[rel aac_context]
    mov ecx,24
    cld
    repe cmpsq
    jne .bad
    AAC_CALL aac_clear
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Whole VM/session retirement. Preserve caller registers/flags; floors and
; native runtime pin lie OUTSIDE wiped region and are never reset/reused.
app_account_retire_all:
    pushfq
    push rax
    push rcx
    push rdi
    AAC_CALL aac_clear
    pop rdi
    pop rcx
    pop rax
    popfq
    ret
aac_clear:
%ifdef APP_ACCOUNT_RECIPIENT_ABI_V1
    ; All legacy clear callers retain their register contract. A nested revoke
    ; keeps independent original custody until the outer containment proves1.
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
%ifdef APP_ACCOUNT_PRIVATE_ABI_V1
    call app_account_private_retire_all
%endif
    call app_account_recipient_revoke
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
%endif
    lea rdi,[rel aac_sensitive_begin]
    xor eax,eax
    mov ecx,(aac_sensitive_end-aac_sensitive_begin)/8
    cld
    rep stosq
    ret

%ifdef APP_ACCOUNT_RECIPIENT_ABI_V1
; Native idle freshness ONLY, never usable for a credential begin/read/write.
aac_idle_authorized:
    cmp dword [rel aac_configured],1
    jne .bad
    AAC_CALL aac_local
    test eax,eax
    jz .bad
    mov rdi,[rel avm_instance]
    lea rsi,[rel aac_current]
    mov edx,128
    AAC_CALL app_vm_snapshot
    cmp eax,1
    jne .bad
    AAC_CALL app_vm_boot_current
    cmp eax,1
    jne .bad
    lea rdi,[rel aac_runtime_current]
    mov esi,128
    AAC_CALL app_runtime_descriptor
    cmp eax,1
    jne .bad
    lea rdi,[rel aac_runtime_current]
    lea rsi,[rel aac_runtime_pin]
    mov ecx,16
    cld
    repe cmpsq
    jne .bad
    mov rax,[rel aac_current+104]
    cmp rax,[rel aac_runtime_pin+8]
    jne .bad
    lea rdi,[rel aac_current]
    lea rsi,[rel aac_recipient_context]
    mov ecx,16
    repe cmpsq
    jne .bad
    AAC_CALL aac_policy
    cmp eax,1
    jne .bad
    ; The policy may synchronously wipe/contain while this observer is active.
    cmp dword [rel aac_recipient_held],1
    jne .bad
    cmp rdx,[rel aac_recipient_context+144]
    jne .bad
    lea rdi,[rel aac_host_current]
    lea rsi,[rel aac_host]
    mov ecx,32
    cld
    repe cmpsq
    jne .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; After original account tick BSP/dispatch/both busy checks, before acl_busy.
; Every call rechecks native authority; no guest poll or new main-loop path.
app_account_recipient_tick:
    push rbx
    cmp dword [rel aac_recipient_held],1
    jne .out
    cmp dword [rel aac_observer_busy],0
    jne .out
    call aac_local
    cmp eax,1
    jne .out
    mov dword [rel aac_observer_busy],1
    cmp dword [rel aac_phase],4
    jne .revoke
    call aac_idle_authorized
    cmp eax,1
    je .done
.revoke:
    call app_account_recipient_revoke
.done:
    mov dword [rel aac_observer_busy],0
.out:
    pop rbx
    ret

; Trusted synchronous no-argument erase hook, including nested policy/consume
; wipe with acl_busy/acp_busy/avm_busy owned. No authority/provider/UI query.
; A recursive retirement hook cannot forget the sole original stop target.
; 1 means this original was contained;0 means no claim, custody still retained.
app_account_recipient_revoke:
    push rbx
    cmp dword [rel aac_recipient_held],1
    jne .bad
    cmp dword [rel aac_revoke_busy],0
    jne .bad
    mov dword [rel aac_revoke_busy],1
%ifdef APP_ACCOUNT_PRIVATE_ABI_V1
    ; The synchronous LIVE wipe enters here directly, before any legacy
    ; sink clear/transport callback. Erase staged native duplicates now.
    call app_account_private_retire_all
%endif
    lea rdi,[rel aac_recipient_context]
    mov esi,128
    call app_vm_recipient_revoke
    cmp eax,1
    jne .refused
    lea rdi,[rel aac_recipient_context]
    xor eax,eax
    mov ecx,24
    cld
    rep stosq
    mov dword [rel aac_recipient_held],0
    mov dword [rel aac_revoke_busy],0
    mov eax,1
    pop rbx
    ret
.refused:
    mov dword [rel aac_revoke_busy],0
.bad:
    xor eax,eax
    pop rbx
    ret
%endif

%unmacro AAC_CALL 1
%include "core/abi/wdata.inc"
%macro WDATA_gui_app_account_sink 0
align 8
aac_configured: dd 0
 dd 0
aac_operation_floor: dq 0
aac_worker_floor: dq 0
aac_runtime_pin: times 128 db 0
aac_sensitive_begin:
aac_phase: dd 0
aac_port: dd 0
aac_context: times 192 db 0
aac_frame: times 512 db 0
aac_current: times 128 db 0
aac_runtime_current: times 128 db 0
aac_host: times 256 db 0
aac_host_current: times 256 db 0
aac_sensitive_end:
%ifdef APP_ACCOUNT_RECIPIENT_ABI_V1
; Independent custody is deliberately OUTSIDE the legacy sensitive wipe range.
aac_recipient_held: dd 0
aac_observer_busy: dd 0
aac_revoke_busy: dd 0
    dd 0
aac_recipient_context: times 192 db 0
%endif
%endmacro
WDATA_DEFER WDATA_gui_app_account_sink
