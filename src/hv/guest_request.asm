;; MODULE hv/guest_request
;; LAYER 5
;; PURPOSE Native VM-wide principal binding and finite typed WAIT admission.
;; EXPORTS guest_request_command_policy_observe, guest_request_receipt_observe, guest_request_audit_copy, guest_request_audit_current, guest_request_command_policy_set, guest_request_command_policy_copy, guest_request_command_policy_current, guest_request_receipt_copy, guest_request_receipt_current, guest_request_configure_terminal_lifecycle, guest_request_configure_terminal_transport, guest_request_configure_snapshot_authorizer, guest_request_endpoint, guest_request_bind, guest_request_retire, guest_request_configure_wait, guest_request_submit, guest_request_authorize, guest_request_revalidate, guest_request_configure_transport, guest_request_capture_wait, guest_request_result_copy, guest_request_context_copy, guest_request_binding_copy
;; IMPORTS core/time, core/smp, svc/command, svc/command_auth, svc/command_audit, sec/session
;; OWNER saga:guest_request
; Cooperative BSP, owned stopped-vCPU boundary only. No yield, retained guest
; address, console parser, process/bundle assertion, credential or executor.
; Endpoint is a native transport-owned handle, NEVER decoded from payload.
; See GUEST_REQUEST.md for the native producer/grant callback contracts.
%include "hv/app_vm.inc"
GR_FRAME_BYTES equ 40
GR_BUDGET_US equ 100000
GR_RESULT_BYTES equ 128
; Immutable per-call native snapshot, callback RDI. All fields are u64.
GR_PID equ 0
GR_BINDING equ 8
GR_ENDPOINT equ 16
GR_START equ 24
GR_VM_EPOCH equ 32
GR_SESSION equ 40
GR_OP equ 48
GR_TARGET equ 56
GR_POLICY equ 64
GR_DEADLINE equ 72
GR_CONTEXT_BYTES equ 80

; RDI=native endpoint, ESI=native captured consumed START -> RAX=PID or 0.
; Native transport activation/rebind only, never called by a guest command.
guest_request_bind:
    push rbx
    push r12
    mov rbx,rdi
    mov r12d,esi
    cmp byte [rel gr_busy],0
    jne .bad
    call session_shell_local_authority
    test rax,rax
    jz .bad
    mov rdi,rbx
    mov esi,r12d
    call gr_live_endpoint
    test eax,eax
    jz .bad
    cmp qword [rel gr_serial],0x7fffffff
    jae .bad
    cmp qword [rel gr_vm_epoch],-1
    je .bad
    call guest_request_retire
    inc qword [rel gr_serial]
    mov rax,[rel gr_serial]
    mov rdx,0x4755455300000000          ; GUES namespace, no static principal IDs
    or rax,rdx
    mov [rel gr_pid],rax
    mov [rel gr_endpoint],rbx
    mov [rel gr_start],r12d
    mov rdx,[rel gr_vm_epoch]
    mov [rel gr_bound_vm_epoch],rdx
    mov rdx,[rel session_authority_epoch]
    mov [rel gr_session],rdx
    mov qword [rel gr_last_seq],0
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r12
    pop rbx
    ret

; No register clobbers. Admitted START/STOP calls this BEFORE publication/yield.
; Lock/rebind additionally checked by the existing nonwrapping session epoch.
; No pending queue: in-flight work is fenced at every admission/effect check.
guest_request_retire:
    call gr_command_policy_retire
    call gr_receipt_retire              ; pointer-free observation, no authority
    cmp qword [rel gr_terminal_lifecycle],0
    je .terminal_invalidated
    call [rel gr_terminal_lifecycle]   ; SEC invalidates live binding/authority
.terminal_invalidated:
    cmp qword [rel gr_terminal_retire],0
    je .terminal_retired
    call [rel gr_terminal_retire]      ; separate Terminal identity/results
.terminal_retired:
    call gr_confirmation_retire          ; private pending/approval state, no clobbers
    mov byte [rel gr_result_valid],0
    cmp qword [rel gr_snapshot_retire],0
    je .snapshot_retired
    call [rel gr_snapshot_retire]        ; additional finite endpoint, same retirement
.snapshot_retired:
    cmp qword [rel gr_transport_retire],0
    je .cleared
    call [rel gr_transport_retire]       ; native leaf MUST preserve all registers
.cleared:
    mov qword [rel gr_pid],0
    mov qword [rel gr_endpoint],0
    cmp qword [rel gr_vm_epoch],-1
    je .out
    inc qword [rel gr_vm_epoch]
.out:
    ret

; Native transport init only: RDI=register-preserving non-yielding retire leaf.
; Replace only outside dispatch. Clear old transport staging before replacement.
; The callback never calls any adapter function; zero uninstalls it.
guest_request_configure_transport:
    cmp byte [rel gr_busy],0
    jne .bad
    call guest_request_retire
    mov [rel gr_transport_retire],rdi
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Native Terminal producer joins the existing START/STOP retirement path.
; Separate callback: never replaces the app/WAIT transport or its identity.
guest_request_configure_terminal_transport:
    cmp byte [rel gr_busy],0
    jne .bad
    cmp dword [rel cmd_dispatch_depth],0
    jne .bad
    cmp byte [rel command_auth_remote_active],0
    jne .bad
    call guest_request_retire
    mov [rel gr_terminal_retire],rdi
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; SEC lifecycle invalidation is distinct from transport/cache clear. The leaf
; preserves registers/flags and never yields or calls guest_request recursively.
; Configure before restoring persisted scopes; zero removes the native hook.
guest_request_configure_terminal_lifecycle:
    cmp byte [rel gr_busy],0
    jne .bad
    cmp dword [rel cmd_dispatch_depth],0
    jne .bad
    cmp byte [rel command_auth_remote_active],0
    jne .bad
    call guest_request_retire
    mov [rel gr_terminal_lifecycle],rdi
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

 ; Native-only finite SNAPSHOT selector installed at GUI init. No wire mapping
; or new WAIT operation. RDI exact-ticket authorizer, RSI register-preserving
; snapshot retirement leaf; outside any dispatch/remote/busy invocation.
guest_request_configure_snapshot_authorizer:
    cmp byte [rel gr_busy],0
    jne .bad
    cmp dword [rel cmd_dispatch_depth],0
    jne .bad
    cmp byte [rel command_auth_remote_active],0
    jne .bad
    call guest_request_retire
    mov [rel gr_snapshot_authorizer],rdi
    mov [rel gr_snapshot_retire],rsi
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; RDI=registered WAIT verb ID, RSI=trusted native grant/revalidation callback.
; Configure at native module init; callback=0 installs DENY, never ALLOW.
; No arbitrary verb mapping, wildcard or injection operation exists.
guest_request_configure_wait:
    cmp byte [rel gr_busy],0
    jne .bad
    mov eax,[rel verb_count]
    cmp rdi,rax
    jae .bad
    imul rax,rdi,VERB_ENT_SZ
    lea rdx,[rel verb_table]
    add rdx,rax
    mov rax,[rdx+VERB_NAME]
    test rax,rax
    jz .bad
    cmp dword [rax],'WAIT'
    jne .bad
    cmp byte [rax+4],0
    jne .bad
    cmp qword [rdx+VERB_DESTR],0
    jne .bad
    mov [rel gr_verb],rdi
    mov [rel gr_grant_op],rsi
    ; Policy replacement/reconfiguration retires every old binding.
    call guest_request_retire
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Native endpoint check, no guest fields. Preserves all except EAX.
gr_live_endpoint:
    lea rax,[rel app_vm_endpoint]
    cmp rdi,rax
    je app_vm_endpoint_current
    ; The driver keeps running, but cannot steal the app's bound principal.
    ; Source endpoints are never authority supplied in the wire request.
    cmp qword [rel avm_state],AVM_READY
    je .bad
    cmp qword [rel avm_state],AVM_RUNNING
    je .bad
    lea rax,[rel guest_request_endpoint]
    cmp rdi,rax
    jne .bad
    test esi,esi
    jz .bad
    cmp esi,[rel hv_linux_start_gen]
    jne .bad
    cmp esi,[rel hv_linux_start_consumed]
    jne .bad
    cmp byte [rel hv_linux_running],1
    jne .bad
    cmp byte [rel hv_linux_run_req],0
    jne .bad
    cmp byte [rel hv_linux_stop_req],0
    jne .bad
    cmp byte [rel session_locked],SESSION_UNLOCKED
    jne .bad
    cmp qword [rel session_key_handle],0
    je .bad
    cmp qword [rel session_bound_pid],0
    je .bad
    mov rax,[rel session_authority_epoch]
    test rax,rax
    jz .bad
    cmp rax,-1
    je .bad
    cmp rax,[rel session_authority]
    jne .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Live binding check; no authority from the current ambient principal.
gr_binding_current:
    cmp rdi,[rel gr_endpoint]
    jne .bad
    cmp qword [rel gr_pid],0
    je .bad
    cmp esi,[rel gr_start]
    jne .bad
    mov rax,[rel gr_session]
    cmp rax,[rel session_authority_epoch]
    jne .bad
    mov rax,[rel gr_bound_vm_epoch]
    cmp rax,[rel gr_vm_epoch]
    jne .bad
    call gr_live_endpoint
    test eax,eax
    jnz .out
.bad:
    xor eax,eax
.out:
    ret

; RDI endpoint, ESI consumed START, RDX native output, ECX exact48 ->1/0.
; Read-only, non-yielding and grant-independent. Safe while gr_busy or an ASK
; continuation is executing; no admission, consume, bind or policy mutation.
; First48 of the actual request context: PID,serial,endpoint,START,VMepoch,session.
guest_request_binding_copy:
    push rbx
    mov rbx,rdx
    cmp ecx,48
    jne .bad
    test rbx,rbx
    jz .bad
    mov rax,rbx
    add rax,48
    jc .bad
    call gr_binding_current
    test eax,eax
    jz .bad
    mov rax,[rel gr_pid]
    mov [rbx],rax
    mov rax,[rel gr_serial]
    mov [rbx+8],rax
    mov rax,[rel gr_endpoint]
    mov [rbx+16],rax
    mov eax,[rel gr_start]
    mov [rbx+24],rax
    mov rax,[rel gr_bound_vm_epoch]
    mov [rbx+32],rax
    mov rax,[rel gr_session]
    mov [rbx+40],rax
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; RDI=native endpoint, ESI=native captured START, RDX=private payload snapshot,
; RCX=exact byte length, R8=native RSP_SZ buffer -> EAX=CMDE_*.
; Payload LE: version:u32=1, op:u32=1..4, seq:u64>last, window:u64,
; cursor/token:u64, timeout_ms:u64. STATUS has both last operands zero;
; BEGIN accepts 0..5000ms; POLL/CANCEL require nonzero token, timeout zero.
; Fixed request copies input before callback/dispatch. One outstanding, no wait.
; C11n (SEC 106351 R3/R4): every refusal after gr_binding_current has exactly
; one reason below and one GCA1 refusal record; earlier busy/remote/depth and
; no-binding refusals move only a counter. Codes, reply bytes and the sequence
; burn order are unchanged.
GRR_SIZE equ 1
GRR_NULL equ 2
GRR_VERSION equ 3
GRR_OP equ 4
GRR_SEQ_ZERO equ 5
GRR_SEQ_REPLAY equ 6
GRR_WINDOW equ 7
GRR_ARGUMENT equ 8
GRR_CONFIRMATION equ 9
guest_request_submit:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx,r8
    test rbx,rbx
    jz .no_response
    mov r12,rdi
    mov r13d,esi
    mov r14,rdx
    mov r15,rcx
    mov rdi,rbx
    xor eax,eax
    mov ecx,RSP_SZ/8
    rep stosq
    mov qword [rbx+RSP_CODE],CMDE_AUTHDENY
    cmp byte [rel gr_busy],0
    jne .denied_unbound
    cmp byte [rel command_auth_remote_active],0
    jne .denied_unbound
    cmp dword [rel cmd_dispatch_depth],0
    jne .denied_unbound
    mov rdi,r12
    mov esi,r13d
    call gr_binding_current
    test eax,eax
    jz .denied_unbound
    mov byte [rel gr_receipt_valid],0    ; any admitted attempt supersedes old receipt
    call gr_confirmation_blocked
    test eax,eax
    mov edx,GRR_CONFIRMATION
    jnz .denied_early
    mov edx,GRR_SIZE
    cmp r15,GR_FRAME_BYTES
    jne .badarg_early
    mov edx,GRR_NULL
    test r14,r14
    jz .badarg_early
    mov rsi,r14
    lea rdi,[rel gr_frame]
    mov ecx,GR_FRAME_BYTES/8
    rep movsq
    mov edx,GRR_VERSION
    cmp dword [rel gr_frame],1
    jne .badarg_frame
    mov edx,GRR_OP
    mov eax,[rel gr_frame+4]
    dec eax
    cmp eax,3
    ja .badarg_frame
    mov edx,GRR_SEQ_ZERO
    mov rax,[rel gr_frame+8]
    test rax,rax
    jz .denied_frame
    mov edx,GRR_SEQ_REPLAY
    cmp rax,[rel gr_last_seq]
    jbe .denied_frame
    ; Burn before policy or dispatch; failed attempts cannot later replay.
    mov [rel gr_last_seq],rax
    mov edx,GRR_WINDOW
    cmp qword [rel gr_frame+16],0
    je .badarg_frame
    mov edx,GRR_ARGUMENT
    cmp dword [rel gr_frame+4],2
    je .begin
    cmp qword [rel gr_frame+32],0
    jne .badarg_frame
    cmp dword [rel gr_frame+4],1
    jne .token
    cmp qword [rel gr_frame+24],0
    jne .badarg_frame
    jmp .typed
.token:
    cmp qword [rel gr_frame+24],0
    je .badarg_frame
    jmp .typed
.begin:
    cmp qword [rel gr_frame+32],5000
    ja .badarg_frame
.typed:
    mov rdi,r12
    mov esi,r13d
    mov rdx,rbx
    call gr_dispatch_frame
    jmp .out
.denied_unbound:
    call audit_guest_command_unbound
.denied:
    mov eax,CMDE_AUTHDENY
    jmp .out
.denied_early:                          ; no frame copied: op and sequence 0
    xor edi,edi
    xor esi,esi
    mov ecx,CMDE_AUTHDENY
    call audit_guest_command_refusal
    jmp .denied
.denied_frame:
    mov edi,[rel gr_frame+4]
    mov rsi,[rel gr_frame+8]
    mov ecx,CMDE_AUTHDENY
    call audit_guest_command_refusal
    jmp .denied
.badarg_early:
    xor edi,edi
    xor esi,esi
    mov ecx,CMDE_BADARG
    call audit_guest_command_refusal
    jmp .badarg
.badarg_frame:
    mov edi,[rel gr_frame+4]
    mov rsi,[rel gr_frame+8]
    mov ecx,CMDE_BADARG
    call audit_guest_command_refusal
.badarg:
    mov qword [rbx+RSP_CODE],CMDE_BADARG
    mov eax,CMDE_BADARG
    jmp .out
.no_response:
    mov eax,CMDE_BADARG
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; One maintained invocation engine for fresh submits and native consumed
; confirmations. Private native entry, never a replay-capable guest API.
; RDI=endpoint, ESI=START, RDX=RSP. Frame is already private and authenticated
; by the public submit or the exact frozen-original continuation transition.
gr_dispatch_frame:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx,rdx
    mov r12,rdi
    mov r13d,esi
    mov rax,[rel gr_verb]
    mov ecx,[rel verb_count]
    cmp rax,rcx
    jae .denied
    mov rax,[rel gr_cp_generation]
    mov [rel gr_call_setting_generation],rax
    mov byte [rel gr_busy],1
    mov qword [rel gr_receipt_decision],3 ; unknown until actual callback
    mov qword [rel gr_receipt_policy],0
    mov qword [rel gr_receipt_authorized],2 ; unknown until exact guest auth
    mov byte [rel gr_result_valid],0
    lea rdi,[rel gr_result]
    xor eax,eax
    mov ecx,GR_RESULT_BYTES/8
    rep stosq
    ; Fresh native-only context and request, no client identity/capability.
    lea rdi,[rel gr_context]
    xor eax,eax
    mov ecx,(GR_CONTEXT_BYTES+REQ_SZ+AUTH_T_SIZE)/8
    rep stosq
    mov rax,[rel gr_pid]
    mov [rel gr_context+GR_PID],rax
    mov [rel gr_req+REQ_PRINCIPAL],rax
    mov [rel gr_ticket+AUTH_T_PRINCIPAL],rax
    mov rax,[rel gr_serial]
    mov [rel gr_context+GR_BINDING],rax
    mov [rel gr_context+GR_ENDPOINT],r12
    mov [rel gr_context+GR_START],r13
    mov rax,[rel gr_vm_epoch]
    mov [rel gr_context+GR_VM_EPOCH],rax
    mov rax,[rel gr_session]
    mov [rel gr_context+GR_SESSION],rax
    mov eax,[rel gr_frame+4]
    mov [rel gr_context+GR_OP],rax
    mov rax,[rel gr_frame+16]
    mov [rel gr_context+GR_TARGET],rax
    mov rax,[rel gr_frame+8]
    mov [rel gr_req+REQ_IDEM],rax
    mov [rel gr_ticket+AUTH_T_SEQ],rax
    mov qword [rel gr_req+REQ_SOURCE],CMD_SOURCE_GUEST
    mov qword [rel gr_ticket+AUTH_T_STATE],AUTH_TS_GUEST
    mov rax,[rel gr_verb]
    mov [rel gr_req+REQ_VERB],rax
    imul rax,VERB_ENT_SZ
    lea rdx,[rel verb_table]
    add rdx,rax
    mov rdi,[rdx+VERB_NAME]
    mov [rel gr_ticket+AUTH_T_COMMAND],rdi
    mov rsi,[rdx+VERB_CAP]
    mov rdx,[rdx+VERB_DESTR]
    call command_auth_required_cap
    mov [rel gr_req+REQ_CAP],rax
    mov [rel gr_ticket+AUTH_T_CAP],rax
    call time_monotonic_now_us
    test rax,rax
    jz .finish_denied
    add rax,GR_BUDGET_US
    jc .finish_denied
    mov [rel gr_context+GR_DEADLINE],rax
    mov [rel gr_deadline],rax
    cmp byte [rel gr_defer_state],3
    jne .ordinary_budget
    mov [rel gr_defer_until],rax
    mov rax,[rel gr_defer_policy]
    mov [rel gr_context+GR_POLICY],rax
.ordinary_budget:
    call gr_build_argument
    lea rax,[rel gr_argument]
    mov [rel gr_req+REQ_ARG],rax
    lea rdi,[rel gr_ticket]
    call command_auth_remote_begin
    lea rdi,[rel gr_req]
    mov rsi,rbx
    call command_dispatch
    call command_auth_remote_end
    cmp qword [rbx+RSP_CODE],CMDE_OK
    jne .discard_result
    cmp byte [rel gr_result_valid],1
    jne .missing_result
    ; Only an exact handler capture may become a transport result. An ordinary
    ; envelope value or chat output never substitutes for typed native fields.
    mov dword [rel gr_result],1
    mov dword [rel gr_result+4],CMDE_OK
    mov byte [rel gr_result_valid],2
    jmp .result_done
.missing_result:
    mov qword [rbx+RSP_CODE],CMDE_AUTHDENY
.discard_result:
    mov byte [rel gr_result_valid],0
.result_done:
    call gr_command_policy_record       ; original outcome, existing Guardian spine
    call gr_receipt_record             ; original result, never reconstructed from wire
    mov byte [rel gr_busy],0
    ; The native RSP buffer is not a wire frame. Never export a native hint ptr.
    mov qword [rbx+RSP_HINT],0
    mov rax,[rbx+RSP_CODE]
    jmp .out
.finish_denied:
    mov byte [rel gr_busy],0
.denied:
    mov byte [rel gr_result_valid],0
    mov qword [rbx+RSP_CODE],CMDE_AUTHDENY
    mov eax,CMDE_AUTHDENY
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Original driver command observation, GCR1 v1/128. This receipt observes
; the exact native invocation; it neither grants nor replays it. App identity,
; general command authority, current configuration and None/Basic/Custom modes
; are NOT inferred. No endpoint, ticket, key or native buffer pointer escapes.
; Called while the original private frame/context/RSP are still authoritative.
gr_receipt_record:
    pushfq
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    mov byte [rel gr_receipt_valid],0
    lea rax,[rel guest_request_endpoint]
    cmp rax,[rel gr_context+GR_ENDPOINT]
    jne .out
    mov rdi,rax
    mov esi,[rel gr_context+GR_START]
    call gr_binding_current
    test eax,eax
    jz .out
    call time_monotonic_now_us
    test rax,rax
    jz .out
    cmp rax,[rel gr_context+GR_DEADLINE]
    jae .out
    mov [rel gr_receipt+104],rax
    mov rax,0x0080000131524347     ; GCR1,u16v1,u16len128
    mov [rel gr_receipt],rax
    mov rax,[rel gr_context+GR_PID]
    mov [rel gr_receipt+8],rax
    mov rax,[rel gr_context+GR_BINDING]
    mov [rel gr_receipt+16],rax
    mov rax,[rel gr_context+GR_START]
    mov [rel gr_receipt+24],rax
    mov rax,[rel gr_context+GR_VM_EPOCH]
    mov [rel gr_receipt+32],rax
    mov rax,[rel gr_context+GR_SESSION]
    mov [rel gr_receipt+40],rax
    mov rax,[rel gr_frame+8]
    mov [rel gr_receipt+48],rax
    mov rax,[rel gr_context+GR_OP]
    mov [rel gr_receipt+56],rax
    mov rax,[rel gr_context+GR_TARGET]
    mov [rel gr_receipt+64],rax
    mov rax,[rel gr_receipt_policy]
    mov [rel gr_receipt+72],rax
    mov rax,[rel gr_receipt_decision]
    mov [rel gr_receipt+80],rax
    mov rax,[rel gr_receipt_authorized]
    mov [rel gr_receipt+88],rax
    mov rax,[rbx+RSP_CODE]
    mov [rel gr_receipt+96],rax
    mov rax,[rel gr_context+GR_DEADLINE]
    mov [rel gr_receipt+112],rax
    mov qword [rel gr_receipt+120],0
    mov byte [rel gr_receipt_valid],1
.out:
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    popfq
    ret

; Endpoint/START native inputs; EAX1 current/0 absent. No callback, policy,
; effect, consume or authority mutation. Currentness is original binding/time,
; not a claim the historical policy verdict remains current after observation.
guest_request_receipt_current:
    cmp byte [rel gr_busy],0
    jne .bad
    cmp byte [rel command_auth_remote_active],0
    jne .bad
    cmp dword [rel cmd_dispatch_depth],0
    jne .bad
    jmp gr_receipt_current_native
.bad:
    xor eax,eax
    ret

; Shared original binding/sequence/deadline predicate. Its callers retain
; separate boundaries: strict transport current, or read-only native GUI.
gr_receipt_current_native:
    lea rax,[rel guest_request_endpoint]
    cmp rdi,rax
    jne .bad
    cmp byte [rel gr_receipt_valid],1
    jne .bad
    call gr_binding_current
    test eax,eax
    jz .bad
    mov rax,[rel gr_receipt+8]
    cmp rax,[rel gr_pid]
    jne .bad
    mov rax,[rel gr_receipt+16]
    cmp rax,[rel gr_serial]
    jne .bad
    mov rax,[rel gr_receipt+48]
    cmp rax,[rel gr_last_seq]
    jne .bad
    call time_monotonic_now_us
    cmp rax,[rel gr_receipt+104]
    jb .bad
    cmp rax,[rel gr_receipt+112]
    jae .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; RDI/ESI exact native endpoint/START, RDX native destination, ECX128 ->1/0.
; Caller supplies no expected principal or policy; failed copy writes nothing.
guest_request_receipt_copy:
    push rbx
    mov rbx,rdx
    cmp ecx,128
    jne .bad
    test rbx,rbx
    jz .bad
    mov rax,rbx
    add rax,128
    jc .bad
    call guest_request_receipt_current
    test eax,eax
    jz .bad
    push rsi
    push rdi
    call time_monotonic_now_us
    cmp rax,[rel gr_receipt+104]
    jb .copy_bad
    cmp rax,[rel gr_receipt+112]
    jae .copy_bad
    mov [rel gr_receipt+120],rax
    mov rdi,rbx
    lea rsi,[rel gr_receipt]
    mov ecx,16
    cld
    rep movsq
    pop rdi
    pop rsi
    mov eax,1
    pop rbx
    ret
.copy_bad:
    pop rdi
    pop rsi
.bad:
    xor eax,eax
    pop rbx
    ret

; Same canonical retirement: zero retained public scalar identity as well.
gr_receipt_retire:
    pushfq
    push rax
    push rcx
    push rdi
    mov byte [rel gr_receipt_valid],0
    lea rdi,[rel gr_receipt]
    xor eax,eax
    mov ecx,16
    cld
    rep stosq
    pop rdi
    pop rcx
    pop rax
    popfq
    ret

; Existing AUTH_TS_GUEST path: RDI=ticket, RSI=required cap, RDX=verb name.
; EAX=0 accepted / -1 refused. An arbitrary pointer/state/source/PID cannot
; manufacture this context, including public floor or nested APP dispatches.
guest_request_authorize:
    lea rax,[rel gr_ticket]
    cmp rdi,rax
    jne .snapshot
    cmp rsi,[rel gr_ticket+AUTH_T_CAP]
    jne .bad
    cmp rdx,[rel gr_ticket+AUTH_T_COMMAND]
    jne .bad
    lea rdi,[rel gr_req]
    call guest_request_revalidate
    mov qword [rel gr_receipt_authorized],1
    test eax,eax
    jnz .receipt_out
    mov qword [rel gr_receipt_authorized],0
.receipt_out:
    ret
.snapshot:
    cmp qword [rel gr_snapshot_authorizer],0
    je .bad
    jmp [rel gr_snapshot_authorizer]
.bad:
    mov eax,-1
    ret

; Identity-only currentness used by the native resolver context snapshot.
; No grant callback here: snapshotting does not authorize any effect.
gr_request_current:
    cmp byte [rel gr_busy],1
    jne .bad
    lea rax,[rel gr_req]
    cmp rdi,rax
    jne .bad
    cmp byte [rel command_auth_remote_active],1
    jne .bad
    lea rax,[rel gr_ticket]
    cmp rax,[rel command_auth_remote_ticket]
    jne .bad
    cmp qword [rel gr_req+REQ_SOURCE],CMD_SOURCE_GUEST
    jne .bad
    mov rax,[rel gr_context+GR_PID]
    cmp rax,[rel gr_pid]
    jne .bad
    cmp rax,[rel gr_req+REQ_PRINCIPAL]
    jne .bad
    cmp rax,[rel gr_ticket+AUTH_T_PRINCIPAL]
    jne .bad
    mov rax,[rel gr_context+GR_DEADLINE]
    cmp rax,[rel gr_deadline]
    jne .bad
    cmp qword [rel gr_ticket+AUTH_T_STATE],AUTH_TS_GUEST
    jne .bad
    mov rax,[rel gr_context+GR_VM_EPOCH]
    cmp rax,[rel gr_bound_vm_epoch]
    jne .bad
    mov rax,[rel gr_context+GR_SESSION]
    cmp rax,[rel gr_session]
    jne .bad
    mov eax,[rel gr_start]
    cmp rax,[rel gr_context+GR_START]
    jne .bad
    mov eax,[rel gr_frame+4]
    cmp rax,[rel gr_context+GR_OP]
    jne .bad
    mov rax,[rel gr_frame+16]
    cmp rax,[rel gr_context+GR_TARGET]
    jne .bad
    mov rax,[rel gr_context+GR_BINDING]
    cmp rax,[rel gr_serial]
    jne .bad
    mov rax,[rel gr_req+REQ_VERB]
    cmp rax,[rel gr_verb]
    jne .bad
    lea rax,[rel gr_argument]
    cmp rax,[rel gr_req+REQ_ARG]
    jne .bad
    cmp qword [rel gr_req+REQ_SEL],0
    jne .bad
    mov rax,[rel gr_req+REQ_IDEM]
    cmp rax,[rel gr_frame+8]
    jne .bad
    cmp rax,[rel gr_ticket+AUTH_T_SEQ]
    jne .bad
    mov rax,[rel gr_req+REQ_CAP]
    cmp rax,[rel gr_ticket+AUTH_T_CAP]
    jne .bad
    mov rdi,[rel gr_context+GR_ENDPOINT]
    mov esi,[rel gr_context+GR_START]
    call gr_binding_current
    test eax,eax
    jz .bad
    call time_monotonic_now_us
    test rax,rax
    jz .bad
    cmp rax,[rel gr_context+GR_DEADLINE]
    jae .bad
    xor eax,eax
    ret
.bad:
    mov eax,-1
    ret

; Copy the exact in-flight native context for a native grant/WAIT resolver.
; RDI=exactreq, RSI=private104B destination, RDX=104 -> EAX0/-1.
; Context80B followed by original seq/cursor-or-token/timeout, all qwords.
; No mutable request/context pointer is returned. Caller proves actual bundle,
; target and policy proof, then full revalidation immediately before effect.
guest_request_context_copy:
    push rbx
    mov rbx,rsi
    cmp rdx,104
    jne .bad
    test rbx,rbx
    jz .bad
    call gr_request_current
    test eax,eax
    jnz .bad
    lea rsi,[rel gr_context]
    mov rdi,rbx
    mov ecx,GR_CONTEXT_BYTES/8
    rep movsq
    mov rax,[rel gr_frame+8]
    mov [rdi],rax
    mov rax,[rel gr_frame+24]
    mov [rdi+8],rax
    mov rax,[rel gr_frame+32]
    mov [rdi+16],rax
    xor eax,eax
    jmp .out
.bad:
    mov eax,-1
.out:
    pop rbx
    ret

; Handler calls immediately before any effect: exactreq -> EAX0/-1.
; Native grant callback must not yield. ALLOW requires current nonzero policy
; generation; ASK is accepted only under the exact consumed native continuation.
; DENY/missing or changed policy generation refuses the invocation.
guest_request_revalidate:
    push rbx
    push r12
    call gr_request_current
    test eax,eax
    jnz .bad
    call gr_command_policy_admit
    test eax,eax
    jz .bad
    mov rbx,[rel gr_grant_op]
    test rbx,rbx
    jz .bad
    mov r12,[rel gr_context+GR_POLICY]
    lea rdi,[rel gr_context]
    lea rsi,[rel gr_req]
    mov rdx,[rel gr_ticket+AUTH_T_CAP]
    mov rcx,[rel gr_ticket+AUTH_T_COMMAND]
    call rbx
    ; Record only the actual trusted callback outcome at the request. Missing
    ; generation remains zero/unknown; this does not invent a None-mode setting.
    mov qword [rel gr_receipt_decision],3
    cmp eax,2
    ja .receipt_decision_done
    mov [rel gr_receipt_decision],rax
.receipt_decision_done:
    mov [rel gr_receipt_policy],rdx
    cmp eax,1
    je .allow_policy
    cmp eax,2
    jne .bad
    cmp byte [rel gr_defer_state],3
    jne .bad
    call gr_confirmation_live
    test eax,eax
    jz .bad
    mov rdx,[rel gr_defer_policy]
.allow_policy:
    test rdx,rdx
    jz .bad
    test r12,r12
    jz .first_policy
    cmp rdx,r12
    jne .bad
.first_policy:
    mov [rel gr_context+GR_POLICY],rdx
    ; Callback cannot smuggle a stale binding/deadline into the effect.
    mov rdi,[rel gr_context+GR_ENDPOINT]
    mov esi,[rel gr_context+GR_START]
    call gr_binding_current
    test eax,eax
    jz .bad
    call time_monotonic_now_us
    test rax,rax
    jz .bad
    cmp rax,[rel gr_context+GR_DEADLINE]
    jae .bad
    xor eax,eax
    jmp .out
.bad:
    mov eax,-1
.out:
    pop r12
    pop rbx
    ret

; Native WAIT handler only, after its pre-effect revalidation and bounded effect:
; RDI=exact request, ESI=state0..6, RDX=token, RCX=cursor, R8=native80B row
; or0. EAX=0/-1. Revalidate again before private copyout. EVENT requires an
; exact sequence row; other states cannot supply a row. No chat globals used.
guest_request_capture_wait:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov ebx,esi
    mov r12,rdx
    mov r13,rcx
    mov r14,r8
    cmp byte [rel gr_result_valid],0
    jne .bad
    cmp ebx,6
    ja .bad
    call guest_request_revalidate
    test eax,eax
    jnz .bad
    lea rdi,[rel gr_result]
    xor eax,eax
    mov ecx,GR_RESULT_BYTES/8
    rep stosq
    cmp ebx,2
    jne .no_event
    test r14,r14
    jz .bad
    cmp r13,[r14]
    jne .bad
    lea rsi,[r14+16]
    lea rdi,[rel gr_result+56]
    call gr_copy_name
    test eax,eax
    jnz .bad
    lea rsi,[r14+48]
    lea rdi,[rel gr_result+88]
    call gr_copy_name
    test eax,eax
    jnz .bad
    mov rax,[r14+8]
    mov [rel gr_result+48],rax
    jmp .capture
.no_event:
    test r14,r14
    jnz .bad
.capture:
    mov rax,[rel gr_req+REQ_IDEM]
    mov [rel gr_result+8],rax
    mov rax,[rel gr_context+GR_TARGET]
    mov [rel gr_result+16],rax
    mov [rel gr_result+24],rbx
    mov [rel gr_result+32],r12
    mov [rel gr_result+40],r13
    mov byte [rel gr_result_valid],1
    xor eax,eax
    jmp .out
.bad:
    mov eax,-1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Bounded ASCII name including NUL in32, copy only through NUL. Unused tail
; stays zero from per-invocation initialization, never stale native bytes.
gr_copy_name:
    mov ecx,32
.next:
    lodsb
    test al,al
    jz .ok
    cmp al,0x21
    jb .bad
    cmp al,0x7e
    ja .bad
    stosb
    loop .next
.bad:
    mov eax,-1
    ret
.ok:
    cmp ecx,32
    je .bad
    xor eax,eax
    ret

; Native transport only, immediately after submit unwinds and before guest runs.
; RDI=endpoint, ESI=START, RDX=original sequence, RCX=private128B destination,
; R8=exact128 -> EAX=0/-1. A successful copy consumes the result. Fresh binding,
; session/lifetime and exact sequence required. Ordinary results keep the
; original100ms deadline; confirmed results use their own bounded copyout TTL.
; Result layout: version:u32, CMDE:u32, requestseq:u64, window:u64, state:u64,
; token:u64, cursor:u64, event_monotonic_us:u64, action[32], widget[32], zero:u64.
; This output is bounded data, not a native RSP or address-bearing event row.
guest_request_result_copy:
    push r12
    push r13
    mov r12,rcx
    mov r13,rdx
    cmp r8,GR_RESULT_BYTES
    jne .bad
    test r12,r12
    jz .bad
    cmp byte [rel gr_busy],0
    jne .bad
    cmp byte [rel gr_defer_state],4
    jne .ordinary_result
    mov rdx,r13
    mov rcx,r12
    call gr_confirmation_copy
    jmp .out
.ordinary_result:
    cmp byte [rel gr_result_valid],2
    jne .bad
    call gr_binding_current
    test eax,eax
    jz .bad
    cmp r13,[rel gr_result+8]
    jne .bad
    cmp r13,[rel gr_last_seq]
    jne .bad
    cmp byte [rel command_auth_remote_active],0
    jne .bad
    cmp dword [rel cmd_dispatch_depth],0
    jne .bad
    ; Restore only the original native auth context for final copyout policy
    ; revalidation. This is not another command dispatch or guest submission.
    mov byte [rel gr_busy],1
    lea rdi,[rel gr_ticket]
    call command_auth_remote_begin
    lea rdi,[rel gr_req]
    call guest_request_revalidate
    mov r13d,eax
    call command_auth_remote_end
    mov byte [rel gr_busy],0
    test r13d,r13d
    jnz .bad
    lea rsi,[rel gr_result]
    mov rdi,r12
    mov ecx,GR_RESULT_BYTES/8
    rep movsq
    mov byte [rel gr_result_valid],0
    xor eax,eax
    jmp .out
.bad:
    mov eax,-1
.out:
    pop r13
    pop r12
    ret

; Canonical text for the existing WAIT parser; no guest-supplied text/string.
; Maximum 7+20+1+20+1+4+NUL < 80. Decimal writer is bounded to 20 digits.
gr_build_argument:
    lea rdi,[rel gr_argument]
    mov eax,[rel gr_frame+4]
    lea rsi,[rel gr_wait_status_text]
    cmp eax,1
    je .name
    lea rsi,[rel gr_begin]
    cmp eax,2
    je .name
    lea rsi,[rel gr_poll]
    cmp eax,3
    je .name
    lea rsi,[rel gr_cancel]
.name:
    lodsb
    stosb
    test al,al
    jnz .name
    dec rdi
    mov rax,[rel gr_frame+16]
    call gr_decimal
    cmp dword [rel gr_frame+4],1
    je .end
    mov byte [rdi],' '
    inc rdi
    mov rax,[rel gr_frame+24]
    call gr_decimal
    cmp dword [rel gr_frame+4],2
    jne .end
    mov byte [rdi],' '
    inc rdi
    mov rax,[rel gr_frame+32]
    call gr_decimal
.end:
    mov byte [rdi],0
    ret
gr_decimal:
    xor ecx,ecx
    mov r8d,10
.digit:
    xor edx,edx
    div r8
    push rdx
    inc ecx
    test rax,rax
    jnz .digit
.copy:
    pop rax
    add al,'0'
    stosb
    loop .copy
    ret

align 8
guest_request_endpoint: dq 0x3151455254535547 ; native sole VM slot, not a wire cookie
gr_vm_epoch: dq 1
gr_serial: dq 0
gr_pid: dq 0
gr_endpoint: dq 0
gr_bound_vm_epoch: dq 0
gr_session: dq 0
gr_last_seq: dq 0
gr_start: dd 0
gr_busy: db 0
align 8
gr_verb: dq -1
gr_deadline: dq 0
gr_grant_op: dq 0
gr_transport_retire: dq 0
gr_terminal_retire: dq 0
gr_terminal_lifecycle: dq 0
gr_snapshot_authorizer: dq 0
gr_snapshot_retire: dq 0
gr_receipt: times 128 db 0
gr_receipt_policy: dq 0
gr_receipt_decision: dq 3
gr_receipt_authorized: dq 2
gr_receipt_valid: db 0
align 8
gr_result: times GR_RESULT_BYTES db 0
gr_result_valid: db 0
align 8
gr_frame: times GR_FRAME_BYTES db 0
gr_context: times GR_CONTEXT_BYTES db 0
gr_req: times REQ_SZ db 0
gr_ticket: times AUTH_T_SIZE db 0
gr_argument: times 80 db 0
gr_wait_status_text: db 'STATUS ',0
gr_begin: db 'BEGIN ',0
gr_poll: db 'POLL ',0
gr_cancel: db 'CANCEL ',0

%include "hv/guest_confirmation.asm"

%include "hv/guest_command_policy.asm"

; Read-only checked-guest history. Exact current driver endpoint/lifetime only;
; never a generic principal selector, grant, setter, acknowledgement or clear.
guest_request_audit_current:
    cmp byte [rel gr_busy],0
    jne .bad
    cmp byte [rel command_auth_remote_active],0
    jne .bad
    cmp dword [rel cmd_dispatch_depth],0
    jne .bad
    cmp byte [rel cmd_in_dispatch],0
    jne .bad
    lea rax,[rel guest_request_endpoint]
    cmp rdi,rax
    jne .bad
    push rdi
    push rsi
    call smp_current_logical             ; real LAPIC path clobbers ESI/ECX/EDX
    pop rsi
    pop rdi
    test eax,eax
    jnz .bad
    call gr_binding_current
    test eax,eax
    jz .bad
    mov rdx,[rel ag_revision]
    mov r8,[rel ag_lost]
    mov r9,[rel ag_ref_change]          ; C11n: refusal rows/counters generation
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

guest_request_audit_copy:
    push rbx
    mov rbx,rdx
    cmp ecx,AG_BYTES
    jne .bad
    test rbx,rbx
    jz .bad
    mov rax,rbx
    add rax,AG_BYTES
    jc .bad
    call guest_request_audit_current
    cmp eax,1
    jne .bad
    mov rdi,rbx
    call audit_guest_command_snapshot
    mov rdx,[rel ag_ref_change]         ; the refusal generation this copy shows
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; Cohesive checked-driver extension; generic audit_sec_event remains unchanged.
%include "svc/guest_command_audit.asm"
