;; MODULE hv/settings_update_service
;; LAYER 5
;; EXPORTS settings_update_service_pio, settings_update_service_original, settings_update_service_observe, settings_update_service_retire, settings_update_service_empty
;; IMPORTS hv/app_vm, sec/update_request, sec/session, core/time, core/smp
;; CAPS
;; OWNER rc-input-claude
;; CONTEXT: bsp_only
; Fixed VM-role consumer of the lower native request-policy record.
; No GUI call or dependency; not a backend registration or writer.
; Only a closed exit from VM's separately qualified updater PID1 can fetch.
; App compatibility/driver exits, Linux PID and guest-provided identity confer
; no authority. Runtime128 stays native; only the original Settings40 crosses
; this private scalar stream. No guest pointers, uploads, effects or completion.
;
; 50e0 OUT32 1=FETCH once, 2=CURRENT, 3=BUDGET once after original read.
; IN32 last command result, live-checked. 50e4 IN32 ten original words once,
; then only after BUDGET eight snapshot words once. Snapshot32: u32 version1,
; u32 size32, u64 original request, u64 original deadline, u64 sampled boot_ms.
; This read-only sample grants no authority and never changes any deadline.
; A partial transfer retains its original until native stopped+expired retire.
; No yield between synchronous role/request checks and the following copy.
%include "core/abi/wdata.inc"

; EDI actual exit qualification, ESI actual guest EAX -> EAX1 claimed/0 bad,
; EDX bounded result (0 on refusal). Dispatcher already checked closed exit;
; repeat the independent updater-role check before accessing any request.
settings_update_service_pio:
    push rbx
    push r12
    push r13
    mov ebx,edi
    mov r12d,esi
    mov r13d,edi
    shr r13d,16
    cmp r13d,0x50e0
    je .port
    cmp r13d,0x50e4
    jne .bad
.port:
    mov eax,ebx
    and eax,0xffbf                  ; immediate bit allowed; scalar dword only
    cmp eax,3
    je .width
    cmp eax,11
    jne .bad
.width:
    cmp dword [rel sus_busy],0
    jne .bad
    mov dword [rel sus_busy],1
    cmp r13d,0x50e4
    je .data
    test ebx,8
    jnz .status
    cmp r12d,1
    je .fetch
    mov dword [rel sus_result],0
    cmp r12d,3
    je .budget
    cmp r12d,2
    jne .zero
    call sus_current
    mov [rel sus_result],eax
    jmp .zero
.budget:
    ; Reserve once before callbacks. No seek/retry, replacement or guest input.
    mov dword [rel sus_budget_valid],0
    cmp dword [rel sus_phase],3
    jne .zero
    cmp dword [rel sus_budget_used],0
    jne .zero
    mov dword [rel sus_budget_used],1
    call sus_current
    cmp eax,1
    jne .zero
    call boot_ms_now
    cmp rax,[rel sus_original+32]
    jae .zero
    mov [rel sus_budget+24],rax
    mov dword [rel sus_budget],1
    mov dword [rel sus_budget+4],32
    mov rax,[rel sus_original]
    mov [rel sus_budget+8],rax
    mov rax,[rel sus_original+32]
    mov [rel sus_budget+16],rax
    call sus_current
    cmp eax,1
    jne .zero
    mov dword [rel sus_budget_valid],1
    mov dword [rel sus_result],1
    jmp .zero
.fetch:
    mov dword [rel sus_result],0
    cmp dword [rel sus_phase],0
    jne .zero                     ; cannot reacquire, seek or replace original
    mov dword [rel sus_phase],1     ; reserve BEFORE fixed native callbacks
    lea rdi,[rel sus_context]
    mov esi,128
    call app_vm_updater_exit
    cmp eax,1
    jne .unused
    cmp qword [rel sus_context],1
    jne .unused
    lea rdi,[rel sus_context]
    mov esi,128
    call app_vm_updater_current
    cmp eax,1
    jne .unused
    ; Refuse a foreign owner/session BEFORE consuming native UI's one request.
    call session_shell_local_authority
    test rax,rax
    jz .unused
    test rdx,rdx
    jz .unused
    cmp rax,[rel sus_context+48]
    jne .unused
    cmp rdx,[rel sus_context+40]
    jne .unused
    lea rdi,[rel sus_original]
    call update_request_take
    cmp eax,1
    jne .unused
    mov dword [rel sus_phase],2     ; consumed: retained even if recheck refuses
    call sus_current
    mov [rel sus_result],eax
    jmp .zero
.unused:
    ; No UI request consumed. No resources/lease exist; discard scratch only.
    call sus_clear
    jmp .zero
.status:
    cmp dword [rel sus_result],1
    jne .zero
    call sus_current
    mov edx,eax
    jmp .done
.data:
    test ebx,8
    jz .zero                       ; no guest data/context/ACK uploads
    cmp dword [rel sus_phase],3
    je .budget_data
    cmp dword [rel sus_phase],2
    jne .zero
    call sus_current
    cmp eax,1
    jne .zero
    mov ecx,[rel sus_cursor]
    cmp ecx,40
    jae .zero
    lea rax,[rel sus_original]
    mov edx,[rax+rcx]
    add ecx,4
    mov [rel sus_cursor],ecx
    cmp ecx,40
    jne .done
    mov dword [rel sus_phase],3     ; native original retained, stream exhausted
    jmp .done
.budget_data:
    cmp dword [rel sus_budget_valid],1
    jne .zero
    mov ecx,[rel sus_budget_cursor]
    cmp ecx,32
    jae .zero
    call sus_current
    cmp eax,1
    jne .budget_lost
    mov ecx,[rel sus_budget_cursor]
    lea rax,[rel sus_budget]
    mov r12d,[rax+rcx]
    call sus_current
    cmp eax,1
    jne .budget_lost
    add dword [rel sus_budget_cursor],4
    mov edx,r12d
    jmp .done
.budget_lost:
    mov dword [rel sus_budget_valid],0
    mov dword [rel sus_result],0
    jmp .zero
.zero:
    xor edx,edx
.done:
    mov dword [rel sus_busy],0
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

; Private helper, called with busy ownership. Both fixed producers must agree;
; VM compares all original128 including native instance/START/gen and identity.
; UI compares all original40 including op/serial/deadline and current session.
sus_current:
    sub rsp,8
    mov eax,[rel sus_phase]
    cmp eax,2
    je .phase
    cmp eax,3
    jne .no
.phase:
    lea rdi,[rel sus_context]
    mov esi,128
    call app_vm_updater_current
    cmp eax,1
    jne .no
    mov rax,[rel sus_original+16]
    cmp rax,[rel sus_context+48]
    jne .no
    mov rax,[rel sus_original+24]
    cmp rax,[rel sus_context+40]
    jne .no
    lea rdi,[rel sus_original]
    call update_request_current
    cmp eax,1
    jne .no
    ; Keep the role check adjacent to export; no scheduling/guest call occurs.
    lea rdi,[rel sus_context]
    mov esi,128
    call app_vm_updater_current
    jmp .out
.no:
    xor eax,eax
.out:
    add rsp,8
    ret

; TRUSTED native-only accessor for a subsequent ESP adapter. No guest route.
; RDI native out40, ESI=40, RDX native out128, ECX=128 -> EAX1/0, EDX
; read-only full40/fullbudget32 bits as passive observer below. Destinations
; must be non-null/nonwrapping/disjoint and cannot alias this private state.
; Native callers own validity/mapping of their buffers; this is not usercopy.
; Grants neither a slot lease nor authority after a yield; effects revalidate.
settings_update_service_original:
    push rbx
    push r12
    push r13
    mov r12,rdi
    mov r13,rdx
    cmp esi,40
    jne .no
    cmp ecx,128
    jne .no
    mov esi,40
    call sus_span
    test eax,eax
    jz .no
    mov rdi,r13
    mov esi,128
    call sus_span
    test eax,eax
    jz .no
    lea rax,[r12+40]
    cmp r13,rax
    jae .disjoint
    lea rax,[r13+128]
    cmp r12,rax
    jb .no
.disjoint:
    cmp dword [rel sus_busy],0
    jne .no
    mov dword [rel sus_busy],1
    call sus_current
    cmp eax,1
    jne .release
    mov rdi,r12
    lea rsi,[rel sus_original]
    mov ecx,5
    cld
    rep movsq
    mov rdi,r13
    lea rsi,[rel sus_context]
    mov ecx,16
    rep movsq
    mov eax,1
    call sus_transfer_facts
.release:
    test eax,eax
    jnz .unlock
    xor edx,edx
.unlock:
    mov dword [rel sus_busy],0
    jmp .out
.no:
    xor eax,eax
    xor edx,edx
.out:
    pop r13
    pop r12
    pop rbx
    ret

; TRUSTED native-only passive observer. RDI out40/ESI40, RDX out128/ECX128.
; EAX1 exact current original,2 matching stopped original,0 unknown/refused.
; EDX read-only transfer facts: bit0 original40 fully read; bit1 budget32
; fully read. Neither class nor facts establish completion or effect authority.
; Output unchanged on refusal; never takes/captures, retires, extends or yields.
settings_update_service_observe:
    push rbx
    push r12
    push r13
    sub rsp,128
    mov r12,rdi
    mov r13,rdx
    cmp esi,40
    jne .no
    cmp ecx,128
    jne .no
    mov esi,40
    call sus_span
    test eax,eax
    jz .no
    mov rdi,r13
    mov esi,128
    call sus_span
    test eax,eax
    jz .no
    lea rax,[r12+40]
    cmp r13,rax
    jae .disjoint
    lea rax,[r13+128]
    cmp r12,rax
    jb .no
.disjoint:
    cmp dword [rel sus_busy],0
    jne .no
    mov dword [rel sus_busy],1
    cmp dword [rel sus_phase],2
    je .observe
    cmp dword [rel sus_phase],3
    jne .release_no
.observe:
    mov rdi,rsp
    mov esi,128
    call app_vm_updater_observe_idle
    cmp eax,1
    je .class
    cmp eax,2
    jne .release_no
.class:
    mov ebx,eax
    mov rdi,rsp
    lea rsi,[rel sus_context]
    mov ecx,16
    cld
    repe cmpsq
    jne .release_no
    ; STOPPED remains diagnostic even after owner/deadline revocation. CURRENT
    ; must retain the exact independently current UI original and owner/session.
    cmp ebx,2
    je .copy
    mov rax,[rel sus_original+16]
    cmp rax,[rel sus_context+48]
    jne .release_no
    mov rax,[rel sus_original+24]
    cmp rax,[rel sus_context+40]
    jne .release_no
    lea rdi,[rel sus_original]
    call update_request_current
    cmp eax,1
    jne .release_no
    mov rdi,rsp
    mov esi,128
    call app_vm_updater_observe_idle
    cmp eax,1
    jne .release_no
    mov rdi,rsp
    lea rsi,[rel sus_context]
    mov ecx,16
    cld
    repe cmpsq
    jne .release_no
.copy:
    mov rdi,r12
    lea rsi,[rel sus_original]
    mov ecx,5
    cld
    rep movsq
    mov rdi,r13
    lea rsi,[rel sus_context]
    mov ecx,16
    rep movsq
    call sus_transfer_facts
.result:
    mov eax,ebx
    mov dword [rel sus_busy],0
    jmp .out
.release_no:
    mov dword [rel sus_busy],0
.no:
    xor eax,eax
    xor edx,edx
.out:
    add rsp,128
    pop r13
    pop r12
    pop rbx
    ret

; Read-only bounded historical transfer facts; preserves EAX class/result.
; Called while sus_busy is owned, never advances either original cursor.
sus_transfer_facts:
    xor edx,edx
    cmp dword [rel sus_phase],3
    jne .out
    cmp dword [rel sus_cursor],40
    jne .out
    or edx,1
    cmp dword [rel sus_budget_valid],1
    jne .out
    cmp dword [rel sus_budget_cursor],32
    jne .out
    or edx,2
.out:
    ret

; Trusted span validation only; never dereferences the proposed pointer.
sus_span:
    test rdi,rdi
    jz .no
    mov eax,esi
    add rax,rdi
    jc .no
    lea rcx,[rel sus_state_begin]
    cmp rax,rcx
    jbe .yes
    lea rcx,[rel sus_state_end]
    cmp rdi,rcx
    jb .no
.yes:
    mov eax,1
    ret
.no:
    xor eax,eax
    ret

; Native-only passive service absence. No args or output buffers. EAX1 only
; on BSP with every private service byte zero; EAX0 UNKNOWN/refused otherwise.
; This confirms neither VM stop/release nor ESP custody nor update completion.
; No take, retire, clear, callback or yield during the bounded state scan. BSP
; serialization is the same native service context as FETCH/retire; a busy or
; partially retained service must remain unknown, even with phase zero.
settings_update_service_empty:
    sub rsp,8
    call smp_current_logical
    test eax,eax
    jnz .no
    lea rdx,[rel sus_state_begin]
    mov ecx,(sus_state_end-sus_state_begin)/8
.scan:
    cmp qword [rdx],0
    jne .no
    add rdx,8
    dec ecx
    jnz .scan
    mov eax,1
    jmp .out
.no:
    xor eax,eax
.out:
    add rsp,8
    ret

; Native-only retirement. No guest FINISH/reset, no automatic stop/revoke.
; A real matching stopped-root receipt AND invalid/expired original40 are
; required. This module has no ESP lease/memory-free receipt to manufacture.
settings_update_service_retire:
    sub rsp,8
    cmp dword [rel sus_busy],0
    jne .no
    cmp dword [rel sus_phase],2
    jb .no
    mov dword [rel sus_busy],1
    lea rdi,[rel sus_context]
    mov esi,128
    call app_vm_updater_stopped
    cmp eax,1
    jne .release_no
    lea rdi,[rel sus_original]
    call update_request_current
    test eax,eax
    jnz .release_no
    call sus_clear
    mov eax,1
    jmp .release
.release_no:
    xor eax,eax
.release:
    mov dword [rel sus_busy],0
    jmp .out
.no:
    xor eax,eax
.out:
    add rsp,8
    ret

; Caller owns busy. Keep it owned while clearing all retained bytes/state.
sus_clear:
    lea rdi,[rel sus_original]
    mov ecx,21
    xor eax,eax
    cld
    rep stosq
    lea rdi,[rel sus_budget_state]
    mov ecx,6
    rep stosq
    mov dword [rel sus_phase],0
    mov dword [rel sus_cursor],0
    mov dword [rel sus_result],0
    ret

%macro WDATA_hv_settings_update_service 0
align 8
sus_state_begin:
sus_busy: dd 0
sus_phase: dd 0
sus_cursor: dd 0
sus_result: dd 0
sus_original: times 40 db 0
sus_context: times 128 db 0
sus_budget_state:
sus_budget_used: dd 0
sus_budget_cursor: dd 0
sus_budget_valid: dd 0
    dd 0
sus_budget: times 32 db 0
sus_state_end:
%endmacro
WDATA_DEFER WDATA_hv_settings_update_service
