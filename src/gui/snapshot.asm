;; MODULE gui/snapshot
;; LAYER 6
;; PURPOSE Bounded read-only native UI snapshot with exact original gui.read custody.
;; EXPORTS snapshot_privacy_current, snapshot_privacy_read, snapshot_visibility_read, snapshot_visibility_draw, snapshot_visibility_scanout, snapshot_custody_read, snapshot_custody_current, snapshot_configure_driver_observer, snapshot_terminal_handler_op, snapshot_terminal_records_current, snapshot_terminal_configure, snapshot_terminal_read, snapshot_read_descriptor, snapshot_read_frame, snapshot_read_copy, snapshot_declare, snapshot_configure, snapshot_context_copy, snapshot_authorize, snapshot_submit, snapshot_word, snapshot_retire, snapshot_indicator_draw
;; IMPORTS hv/guest_request, hv/snapshot_transport, gui/widget, gui/window_mgmt, gui/form_loader, gui/taskbar, gui/window, svc/command, svc/command_auth, sec/session, core/time, core/smp, gui/terminal_consent, boot/gop
;; CAPS CAP_GUI
;; OWNER saga:live_snapshot
; Codex / rc-live-claude. No provider/client/grant store. Native callback is
; installed by the INPUT/SEC owner; NULL, DENY and ASK cannot read any GUI data.
%include "hv/snapshot.inc"

; Distinct TERMINAL read-only native bridge. SEC installs its final descriptor
; copyout/protected-object validator; no OWNER ticket or app binding is borrowed.
; RDI native nonyielding validator(desc256)->1, configured outside dispatch.
snapshot_terminal_configure:
    cmp byte [rel snapshot_native_busy],0
    jne .bad
    cmp dword [rel cmd_dispatch_depth],0
    jne .bad
    cmp byte [rel command_auth_remote_active],0
    jne .bad
    test rdi,rdi
    jz .bad
    mov [rel snapshot_terminal_validator],rdi
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; RDI SEC frozen desc256, RSI native output, RDX capacity<=65536.
; EAX0/EDX length on success, EAX-1/EDX0 on refusal. No retained Terminal read
; is exposed on the app/driver snapshot transport. It is retired before return.
snapshot_terminal_read:
    push rbx
    push r12
    push r13
    push r14
    mov rbx,rdi
    mov r12,rsi
    mov r13,rdx
    xor r14d,r14d
    cmp byte [rel snapshot_native_busy],0
    jne .bad
    cmp qword [rel snapshot_terminal_validator],0
    je .bad
    test rbx,rbx
    jz .bad
    test r13,r13
    jz .bad
    cmp r13,65536
    ja .bad
    call smp_current_logical
    test eax,eax
    jnz .bad
    mov rdi,r12
    mov rsi,r13
    call snapshot_native_output_disjoint
    test eax,eax
    jnz .bad
    mov byte [rel snapshot_native_busy],1
    call snapshot_retire
    mov rsi,rbx
    lea rdi,[rel snapshot_terminal_desc]
    mov ecx,32
    cld
    rep movsq
    cmp qword [rel snapshot_terminal_desc],1
    jne .retire_bad
    cmp qword [rel snapshot_terminal_desc+88],0
    jne .retire_bad
    mov rax,[rel snapshot_terminal_desc+56]
    sub rax,16
    cmp rax,3
    ja .retire_bad
    cmp rax,3
    jne .scope
    dec rax                         ; UI19 uses the window/widget record scope
.scope:
    inc rax
    lea rdi,[rel snapshot_native_context]
    push rax
    xor eax,eax
    mov ecx,SN_CONTEXT_BYTES/8
    rep stosq
    pop rax
    mov [rel snapshot_native_context+SN_SCOPE],rax
    mov rax,[rel snapshot_terminal_desc+8]
    mov [rel snapshot_native_context+SN_PID],rax
    mov rax,[rel snapshot_terminal_desc+16]
    mov [rel snapshot_native_context+SN_BINDING],rax
    mov rax,[rel snapshot_terminal_desc+24]
    mov [rel snapshot_native_context+SN_START],rax
    mov rax,[rel snapshot_terminal_desc+32]
    mov [rel snapshot_native_context+SN_VM_EPOCH],rax
    mov rax,[rel snapshot_terminal_desc+40]
    mov [rel snapshot_native_context+SN_SESSION],rax
    mov rax,[rel snapshot_terminal_desc+48]
    mov [rel snapshot_native_context+SN_POLICY],rax
    mov rax,[rel snapshot_terminal_desc+72]
    mov [rel snapshot_native_context+SN_TARGET],rax
    mov rax,[rel snapshot_terminal_desc+80]
    mov [rel snapshot_native_context+SN_GENERATION],rax
    mov rax,[rel snapshot_terminal_desc+200]
    mov [rel snapshot_native_context+SN_SEQUENCE],rax
    mov rax,[rel snapshot_terminal_desc+208]
    mov [rel snapshot_native_context+SN_DEADLINE],rax
    mov qword [rel snapshot_native_context+SN_SOURCE],3
    mov byte [rel snapshot_terminal_active],1
    call terminal_consent_present
    cmp eax,1
    jne .retire_bad
    call snapshot_native_capture
    test eax,eax
    jnz .retire_bad
    mov r14,[rel snapshot_native_buffer+72]
    cmp r14,r13
    ja .retire_bad
    call snapshot_native_policy
    test eax,eax
    jnz .retire_bad
    lea rsi,[rel snapshot_native_buffer]
    mov rdi,r12
    mov rcx,r14
    rep movsb
    call snapshot_native_policy
    test eax,eax
    jnz .wipe
    call snapshot_terminal_finish
    xor eax,eax
    mov edx,r14d
    jmp .out
.wipe:
    mov rdi,r12
    mov rcx,r14
    xor eax,eax
    rep stosb
.retire_bad:
    call snapshot_terminal_finish
.bad:
    mov eax,-1
    xor edx,edx
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

snapshot_terminal_finish:
    call snapshot_retire
    mov byte [rel snapshot_terminal_active],0
    mov byte [rel snapshot_native_busy],0
    lea rdi,[rel snapshot_terminal_desc]
    xor eax,eax
    mov ecx,32
    rep stosq
    ret

snapshot_terminal_current:
    cmp byte [rel session_locked],SESSION_UNLOCKED
    jne .bad
    mov rax,[rel session_authority_epoch]
    cmp rax,[rel snapshot_terminal_desc+40]
    jne .bad
    call time_monotonic_now_us
    test rax,rax
    jz .bad
    cmp rax,[rel snapshot_terminal_desc+208]
    jae .bad
    call terminal_consent_visible
    cmp eax,1
    jne .bad
    lea rdi,[rel snapshot_terminal_desc]
    call [rel snapshot_terminal_validator]
    cmp eax,1
    jne .bad
    cmp qword [rel snapshot_native_context+SN_SCOPE],1
    je .desktop
    mov rbx,[rel snapshot_native_context+SN_TARGET]
    movzx edi,bl
    call snapshot_native_window_allowed
    cmp rax,rbx
    jne .bad
    movzx eax,bl
    lea rdx,[rel wm_gen]
    mov edx,[rdx+rax*4]
    cmp rdx,[rel snapshot_native_context+SN_GENERATION]
    jne .bad
    jmp snapshot_native_records_current
.desktop:
    cmp qword [rel snapshot_native_context+SN_TARGET],0
    jne .bad
    cmp qword [rel snapshot_native_context+SN_GENERATION],0
    jne .bad
    jmp snapshot_native_records_current
.bad:
    mov eax,-1
    ret

snapshot_declare:
    lea rdi,[rel snapshot_native_name]
    lea rsi,[rel snapshot_native_handler]
    xor edx,edx
    mov ecx,ARGT_TEXT
    xor r8d,r8d
    xor r9d,r9d                     ; read-only
    call command_register_verb
    mov [rel snapshot_native_verb],rax
    lea rdi,[rel snapshot_submit]
    lea rsi,[rel snapshot_word]
    lea rdx,[rel snapshot_retire]
    lea rcx,[rel snapshot_floor]
    call snapshot_transport_configure
    lea rdi,[rel snapshot_custody_read]
    lea rsi,[rel snapshot_custody_current]
    call snapshot_transport_configure_custody
    lea rdi,[rel snapshot_visibility_read]
    call snapshot_transport_configure_visibility
    lea rdi,[rel snapshot_privacy_read]
    lea rsi,[rel snapshot_privacy_current]
    call snapshot_transport_configure_privacy
    lea rdi,[rel snapshot_authorize]
    lea rsi,[rel snapshot_transport_retire]
    jmp guest_request_configure_snapshot_authorizer

; Native init/owner policy layer ONLY, outside dispatch/remote and busy producer.
; RDI = non-yielding native resolver (0 default DENY). EAX1/0.
; Resolver: RDI private context128, RSI exact request, RDX required cap,
; RCX canonical SNAPSHOT name -> EAX1 ALLOW, EAX2 ASK, other DENY; RDX nonzero
; policy generation. It MUST use snapshot_context_copy for exact currentness.
; ASK is a refusal, with no read/copy/automatic retry. Native owner approval may
; install a standing scoped policy; the guest then submits a fresh sequence.
snapshot_floor:
    mov rax,[rel snapshot_native_last_seq]
    ret

snapshot_configure:
    cmp byte [rel snapshot_native_busy],0
    jne .bad
    cmp dword [rel cmd_dispatch_depth],0
    jne .bad
    cmp byte [rel command_auth_remote_active],0
    jne .bad
    mov [rel snapshot_native_resolver],rdi
    mov qword [rel snapshot_custody_observer],0
    call snapshot_retire
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Register-preserving leaf, composed into the one existing transport retire.
; Replay floor/read serial never reset by guest clear or binding retirement.
snapshot_retire:
    pushfq
    push rax
    push rcx
    push rdi
    mov byte [rel snapshot_native_valid],0
    lea rdi,[rel snapshot_native_buffer]
    xor eax,eax
    mov ecx,SN_BUFFER_BYTES/8
    cld
    rep stosq
    lea rdi,[rel snapshot_custody_copy_record]
    mov ecx,(192+192+48+5120+128)/8
    rep stosq
    pop rdi
    pop rcx
    pop rax
    popfq
    ret

; Native closed-exit caller: RDI endpoint, ESI actual START, RDX private40
; wire frame, ECX40, R8D actual source1driver/2app -> EAX CMDE code.
; Frame v1/u32, op5desktop/6active/7window:u32, seq:u64, target:u64,
; full generation:u64 (required for explicit window), reserved:u64=0.
; No guest principal/endpoint/pointer is decoded. Original identity is copied
; from the maintained VM binding, and every sequence is burned before policy.
snapshot_submit:
    push rbx
    push r12
    push r13
    mov rbx,rdx
    mov r12d,r8d
    mov r13,rcx
    cmp byte [rel snapshot_native_busy],0
    jne .denied
    cmp dword [rel cmd_dispatch_depth],0
    jne .denied
    cmp byte [rel command_auth_remote_active],0
    jne .denied
    lea rdx,[rel snapshot_native_probe]
    mov ecx,48
    call guest_request_binding_copy
    test eax,eax
    jz .denied
    cmp r12d,1
    jb .denied
    cmp r12d,2
    ja .denied
    ; Never reset the floor on a guest clear/rebind. A new binding serial is
    ; strictly increasing; an older serial cannot resurrect retired data.
    mov rax,[rel snapshot_native_probe+SN_BINDING]
    cmp rax,[rel snapshot_native_seen_binding]
    jb .denied
    je .same_binding
    mov [rel snapshot_native_seen_binding],rax
    mov qword [rel snapshot_native_last_seq],0
.same_binding:
    call snapshot_retire
    cmp r13,40
    jne .badarg
    test rbx,rbx
    jz .badarg
    mov rsi,rbx
    lea rdi,[rel snapshot_native_frame]
    mov ecx,5
    rep movsq
    ; v2 is an explicit identity copyout request, not a new authorization.
    mov eax,[rel snapshot_native_frame]
    sub eax,1
    cmp eax,1
    ja .badarg
    mov eax,[rel snapshot_native_frame+4]
    sub eax,5
    cmp eax,2
    ja .badarg
    mov rax,[rel snapshot_native_frame+8]
    test rax,rax
    jz .denied
    cmp rax,[rel snapshot_native_last_seq]
    jbe .denied
    mov [rel snapshot_native_last_seq],rax
    cmp qword [rel snapshot_native_frame+32],0
    jne .badarg
    lea rdi,[rel snapshot_native_context]
    xor eax,eax
    mov ecx,SN_CONTEXT_BYTES/8
    rep stosq
    lea rsi,[rel snapshot_native_probe]
    lea rdi,[rel snapshot_native_context]
    mov ecx,6
    rep movsq
    mov eax,[rel snapshot_native_frame+4]
    sub eax,4
    mov [rel snapshot_native_context+SN_SCOPE],rax
    mov [rel snapshot_native_context+SN_SOURCE],r12
    mov rax,[rel snapshot_native_frame+8]
    mov [rel snapshot_native_context+SN_SEQUENCE],rax
    lea rax,[rel snapshot_native_req]
    mov [rel snapshot_native_context+SN_REQUEST],rax
    call time_monotonic_now_us
    test rax,rax
    jz .denied
    add rax,1000000                 ; original finite read/copy lifetime1s
    jc .denied
    mov [rel snapshot_native_context+SN_DEADLINE],rax
    cmp qword [rel snapshot_native_context+SN_SCOPE],1
    jne .window
    cmp qword [rel snapshot_native_frame+16],0
    jne .badarg
    cmp qword [rel snapshot_native_frame+24],0
    jne .badarg
    jmp .request
.window:
    mov edi,[rel wm_focus]
    cmp qword [rel snapshot_native_context+SN_SCOPE],2
    je .active
    mov rax,[rel snapshot_native_frame+16]
    mov edi,eax
    shr rax,32
    jnz .badarg
    movzx edi,dil
    jmp .target
.active:
    cmp qword [rel snapshot_native_frame+16],0
    jne .badarg
    cmp qword [rel snapshot_native_frame+24],0
    jne .badarg
.target:
    call snapshot_native_window_allowed
    test eax,eax
    jz .denied
    mov [rel snapshot_native_context+SN_TARGET],rax
    movzx ecx,al
    lea rdx,[rel wm_gen]
    mov edx,[rdx+rcx*4]
    mov [rel snapshot_native_context+SN_GENERATION],rdx
    cmp qword [rel snapshot_native_context+SN_SCOPE],3
    jne .request
    cmp rax,[rel snapshot_native_frame+16]
    jne .denied
    cmp qword [rel snapshot_native_frame+24],0
    je .request
    cmp rdx,[rel snapshot_native_frame+24]
    jne .denied
.request:
    lea rdi,[rel snapshot_native_req]
    xor eax,eax
    mov ecx,(REQ_SZ+AUTH_T_SIZE+RSP_SZ)/8
    rep stosq
    mov rax,[rel snapshot_native_verb]
    cmp eax,[rel verb_count]
    jae .denied
    mov [rel snapshot_native_req+REQ_VERB],rax
    mov rax,[rel snapshot_native_context+SN_PID]
    mov [rel snapshot_native_req+REQ_PRINCIPAL],rax
    mov [rel snapshot_native_ticket+AUTH_T_PRINCIPAL],rax
    mov rax,[rel snapshot_native_context+SN_SEQUENCE]
    mov [rel snapshot_native_req+REQ_IDEM],rax
    mov [rel snapshot_native_ticket+AUTH_T_SEQ],rax
    mov qword [rel snapshot_native_req+REQ_SOURCE],CMD_SOURCE_GUEST
    mov qword [rel snapshot_native_ticket+AUTH_T_STATE],AUTH_TS_GUEST
    lea rdi,[rel snapshot_native_name]
    mov [rel snapshot_native_ticket+AUTH_T_COMMAND],rdi
    xor esi,esi
    xor edx,edx
    call command_auth_required_cap
    mov [rel snapshot_native_req+REQ_CAP],rax
    mov [rel snapshot_native_ticket+AUTH_T_CAP],rax
    call snapshot_native_argument
    lea rax,[rel snapshot_native_argument_buf]
    mov [rel snapshot_native_req+REQ_ARG],rax
    mov byte [rel snapshot_native_busy],1
    lea rdi,[rel snapshot_native_ticket]
    call command_auth_remote_begin
    lea rdi,[rel snapshot_native_req]
    lea rsi,[rel snapshot_native_rsp]
    call command_dispatch
    call command_auth_remote_end
    mov byte [rel snapshot_native_busy],0
    mov eax,[rel snapshot_native_rsp+RSP_CODE]
    test eax,eax
    jnz .failed
    cmp byte [rel snapshot_native_valid],1
    jne .denied
    jmp .out
.failed:
    call snapshot_retire
    jmp .out
.badarg:
    mov eax,CMDE_BADARG
    jmp .out
.denied:
    mov eax,CMDE_AUTHDENY
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Exact ticket delegated through existing guest authorization selector. Only
; this source's one native private request may use its gui.read callback.
snapshot_authorize:
    lea rax,[rel snapshot_native_ticket]
    cmp rdi,rax
    jne snapshot_native_bad
    cmp rsi,[rel snapshot_native_ticket+AUTH_T_CAP]
    jne snapshot_native_bad
    lea rax,[rel snapshot_native_name]
    cmp rdx,rax
    jne snapshot_native_bad
    cmp byte [rel snapshot_native_busy],1
    jne snapshot_native_bad
    lea rax,[rel snapshot_native_ticket]
    cmp rax,[rel command_auth_remote_ticket]
    jne snapshot_native_bad
    cmp byte [rel command_auth_remote_active],1
    jne snapshot_native_bad
    jmp snapshot_native_policy
snapshot_native_bad:
    mov eax,-1
    ret

; Native-only exact request getter. Copies128, returns0/-1, no grant callback
; recursion. Output is trusted disjoint mapped native memory, never guest RAM.
snapshot_context_copy:
    push rbx
    lea rax,[rel snapshot_native_req]
    cmp rdi,rax
    jne .bad
    cmp byte [rel snapshot_native_busy],1
    jne .bad
    cmp rdx,SN_CONTEXT_BYTES
    jne .bad
    test rsi,rsi
    jz .bad
    mov rbx,rsi
    call snapshot_native_current
    test eax,eax
    jnz .bad
    mov rdi,rbx
    lea rsi,[rel snapshot_native_context]
    mov ecx,SN_CONTEXT_BYTES/8
    rep movsq
    xor eax,eax
    pop rbx
    ret
.bad:
    mov eax,-1
    pop rbx
    ret

; Identity-only check before/after policy and every copy. Does not read labels
; or values. Private/chrome changes and full raw target reuse invalidate.
snapshot_native_current:
    push rbx
    cmp byte [rel snapshot_terminal_active],1
    jne .guest
    call snapshot_terminal_current
    pop rbx
    ret
.guest:
    mov rdi,[rel snapshot_native_context+SN_ENDPOINT]
    mov esi,[rel snapshot_native_context+SN_START]
    lea rdx,[rel snapshot_native_probe]
    mov ecx,48
    call guest_request_binding_copy
    test eax,eax
    jz .bad
    lea rdi,[rel snapshot_native_probe]
    lea rsi,[rel snapshot_native_context]
    mov ecx,6
    repe cmpsq
    jne .bad
    call time_monotonic_now_us
    test rax,rax
    jz .bad
    cmp rax,[rel snapshot_native_context+SN_DEADLINE]
    jae .bad
    cmp byte [rel session_locked],SESSION_UNLOCKED
    jne .bad
    cmp qword [rel snapshot_native_context+SN_SCOPE],1
    je .ok
    mov ebx,[rel snapshot_native_context+SN_TARGET]
    movzx edi,bl
    call snapshot_native_window_allowed
    cmp rax,rbx
    jne .bad
    movzx ecx,bl
    lea rdx,[rel wm_gen]
    mov edx,[rdx+rcx*4]
    cmp rdx,[rel snapshot_native_context+SN_GENERATION]
    jne .bad
.ok:
    call snapshot_native_records_current
    test eax,eax
    jnz .bad
    xor eax,eax
    pop rbx
    ret
.bad:
    mov eax,-1
    pop rbx
    ret
; Frozen records retain their original full native object lifetime. A window
; becoming private, reused or chrome, or a widget becoming secret, revokes
; the whole pending copy rather than releasing its previous readable bytes.
; RDI trusted native captured buffer, RSI exact length ->0/-1. This proves
; current exclusion/lifetime only; the SEC descriptor still supplies authority.
snapshot_terminal_records_current:
    push rbx
    push r12
    push r13
    cmp rsi,SN_HEADER_BYTES
    jb snapshot_records_bad
    cmp rsi,SN_BUFFER_BYTES
    ja snapshot_records_bad
    mov r12,[rdi+64]
    cmp r12,SN_MAX_RECORDS
    ja snapshot_records_bad
    mov rax,r12
    shl rax,9
    add rax,SN_HEADER_BYTES
    cmp rax,rsi
    jne snapshot_records_bad
    cmp rax,[rdi+72]
    jne snapshot_records_bad
    lea r13,[rdi+SN_HEADER_BYTES]
    jmp snapshot_records_loop

snapshot_native_records_current:
    push rbx
    push r12
    push r13
    cmp byte [rel snapshot_native_valid],1
    jne snapshot_records_loop.ok
    mov r12,[rel snapshot_native_buffer+64]
    cmp r12,SN_MAX_RECORDS
    ja snapshot_records_bad
    lea r13,[rel snapshot_native_buffer+128]
snapshot_records_loop:
.loop:
    test r12,r12
    jz .ok
    cmp qword [r13],1
    jne .widget
    mov rbx,[r13+8]
    movzx edi,bl
    call snapshot_native_window_allowed
    cmp rax,rbx
    jne .bad
    movzx eax,bl
    lea rdx,[rel wm_gen]
    mov edx,[rdx+rax*4]
    cmp rdx,[r13+24]
    jne .bad
    jmp .next
.widget:
    mov edi,[r13+8]
    cmp edi,[rel wgt_count]
    jae .bad
    cmp edi,WGT_MAX
    jae .bad
    call wgt_slot_ptr
    mov rbx,rax
    mov eax,[rbx+WGI_TYPE]
    test eax,eax
    jz .bad
    test dword [rbx+WGI_EDIT],WGT_EDIT_SECTEXT
    jnz .bad
    mov ecx,[rel wgt_secret_type]
    inc ecx
    cmp eax,ecx
    je .bad
    mov rsi,[rbx+WGI_ROLE]
    test rsi,rsi
    jz .host
    lea rdi,[rel str_wgt_role_password]
    call strcmp
    test eax,eax
    jz .bad
.host:
    mov edi,[rbx+WGI_WIN]
    cmp edi,WGT_HOST_DESKTOP
    jne .window
    cmp qword [r13+16],0
    jne .bad
    jmp .next
.window:
    call snapshot_native_window_allowed
    test eax,eax
    jz .bad
    cmp rax,[r13+16]
    jne .bad
.next:
    add r13,SN_RECORD_BYTES
    dec r12
    jmp .loop
.ok:
    xor eax,eax
    jmp snapshot_records_out
.bad:
snapshot_records_bad:
    mov eax,-1
snapshot_records_out:
    pop r13
    pop r12
    pop rbx
    ret

snapshot_native_policy:
    push rbx
    push r12
    cmp byte [rel snapshot_terminal_active],1
    jne .guest
    call snapshot_terminal_current
    pop r12
    pop rbx
    ret
.guest:
    call snapshot_native_current
    test eax,eax
    jnz .bad
    mov rbx,[rel snapshot_native_resolver]
    test rbx,rbx
    jz .bad
    mov r12,[rel snapshot_native_context+SN_POLICY]
    lea rdi,[rel snapshot_native_context]
    lea rsi,[rel snapshot_native_req]
    mov rdx,[rel snapshot_native_ticket+AUTH_T_CAP]
    lea rcx,[rel snapshot_native_name]
    call rbx
    cmp eax,1
    jne .bad
    test rdx,rdx
    jz .bad
    test r12,r12
    jz .first
    cmp rdx,r12
    jne .bad
.first:
    mov [rel snapshot_native_context+SN_POLICY],rdx
    call snapshot_native_current
    test eax,eax
    jnz .bad
    xor eax,eax
    jmp .out
.bad:
    mov eax,-1
.out:
    pop r12
    pop rbx
    ret

; Registered command has one grammar generated from typed scope. Ordinary
; OWNER/internal/remote caller does not borrow this private gui.read principal.
snapshot_native_handler:
    lea rax,[rel snapshot_native_req]
    cmp rdi,rax
    je .ordinary
    cmp qword [rel snapshot_terminal_handler_op],0
    je .ordinary
    jmp [rel snapshot_terminal_handler_op] ; exact request checked at native leaf
.ordinary:
    push rbx
    mov rbx,rsi
    lea rax,[rel snapshot_native_req]
    cmp rdi,rax
    jne .denied
    cmp byte [rel snapshot_native_busy],1
    jne .denied
    call snapshot_native_policy
    test eax,eax
    jnz .denied
    call snapshot_native_capture
    test eax,eax
    jnz .denied
    ; Diagnostic command channel is a receipt. Full snapshot bytes are copied
    ; by the finite private read plane, never a truncated staged UDP string.
    call f1_out_reset
    lea rdi,[rel snapshot_native_receipt]
    call f1_put_str
    mov rdi,[rel snapshot_native_buffer+16]
    call f1_put_dec
    mov byte [rel f1_out_ready],1
    mov qword [rbx+RSP_CODE],CMDE_OK
    xor eax,eax
    pop rbx
    ret
.denied:
    mov qword [rbx+RSP_CODE],CMDE_AUTHDENY
    mov eax,CMDE_AUTHDENY
    pop rbx
    ret

; Read-only scalar copy: endpoint/START, EDX exact read cursor byte offset ->
; EAX0/-1, ECX one dword. Every word checks original identity+policy+deadline.
; No client-chosen pointer/cursor replay: native cursor advances once per word.
snapshot_word:
    push rbx
    mov ebx,edx
    cmp byte [rel snapshot_native_valid],1
    jne .bad
    cmp rdi,[rel snapshot_native_context+SN_ENDPOINT]
    jne .bad
    cmp esi,[rel snapshot_native_context+SN_START]
    jne .bad
    cmp ebx,[rel snapshot_native_cursor]
    jne .bad
    cmp rbx,[rel snapshot_native_buffer+72]
    jae .bad
    cmp byte [rel snapshot_native_busy],0
    jne .bad
    mov byte [rel snapshot_native_busy],1
    call snapshot_native_policy
    mov byte [rel snapshot_native_busy],0
    test eax,eax
    jnz .bad
    call snapshot_custody_copy
    test eax,eax
    jnz .bad
    lea rax,[rel snapshot_native_buffer]
    mov ecx,[rax+rbx]
    add dword [rel snapshot_native_cursor],4
    call snapshot_visibility_copy_complete
    xor eax,eax
    pop rbx
    ret
.bad:
    call snapshot_retire
    xor ecx,ecx
    mov eax,-1
    pop rbx
    ret

; Native SEC freeze only. No wire pointer/guest entry; caller supplies mapped
; disjoint native output. Does NOT create a cloud permit or extend a lifetime.
; Descriptor: RDI exact nonreused read_id, RSI native out256, RDX256 ->0/-1.
; Output: original context128 followed by exact native header128.
snapshot_read_descriptor:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx,rdi
    xor r12d,r12d
    mov r13,rsi
    mov r14,rdx
    mov r15d,1
    cmp rdx,256
    jne snapshot_native_saved_bad
    jmp snapshot_native_saved_run

; RDI exact read_id, RSI native out40, RDX40 ->0/-1. Copy ORIGINAL wire
; spelling, including explicit generation0; context SN_REQUEST is a registry
; request pointer, never this wire frame. Same saved-read guards on both sides.
snapshot_read_frame:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx,rdi
    xor r12d,r12d
    mov r13,rsi
    mov r14,rdx
    mov r15d,2
    cmp rdx,40
    jne snapshot_native_saved_bad
    jmp snapshot_native_saved_run

; RDI read_id, RSI byte offset, RDX native output, RCX byte count ->0/-1.
; Repeat native copies are read-only; scalar guest cursor is never rewound.
; SEC freezes/rechecks without yielding during the original one-second read.
snapshot_read_copy:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx,rdi
    mov r12,rsi
    mov r13,rdx
    mov r14,rcx
    xor r15d,r15d
snapshot_native_saved_run:
    cmp byte [rel snapshot_native_busy],0
    jne snapshot_native_saved_bad
    cmp byte [rel snapshot_native_valid],1
    jne snapshot_native_saved_bad
    cmp rbx,[rel snapshot_native_buffer+16]
    jne snapshot_native_saved_bad
    call smp_current_logical
    test eax,eax
    jnz snapshot_native_saved_bad
    cmp dword [rel cmd_dispatch_depth],0
    jne snapshot_native_saved_bad
    cmp byte [rel command_auth_remote_active],0
    jne snapshot_native_saved_bad
    test r14,r14
    jz snapshot_native_saved_bad
    cmp r14,SN_BUFFER_BYTES
    ja snapshot_native_saved_bad
    mov rdi,r13
    mov rsi,r14
    call snapshot_native_output_disjoint
    test eax,eax
    jnz snapshot_native_saved_bad
    test r15d,r15d
    jnz .range_ok
    mov rax,r12
    add rax,r14
    jc snapshot_native_saved_bad
    cmp rax,[rel snapshot_native_buffer+72]
    ja snapshot_native_saved_bad
.range_ok:
    mov byte [rel snapshot_native_busy],1
    call snapshot_native_policy
    test eax,eax
    jnz .policy_bad
    mov rdi,r13
    cld
    test r15d,r15d
    jz .payload
    cmp r15d,2
    je .frame
    lea rsi,[rel snapshot_native_context]
    mov ecx,128
    rep movsb
    lea rsi,[rel snapshot_native_buffer]
    mov ecx,128
    rep movsb
    jmp .copied
.frame:
    lea rsi,[rel snapshot_native_frame]
    mov ecx,40
    rep movsb
    jmp .copied
.payload:
    lea rsi,[rel snapshot_native_buffer]
    add rsi,r12
    mov rcx,r14
    rep movsb
.copied:
    call snapshot_native_policy
    test eax,eax
    jz .ok
    ; A changed callback/epoch after copying must not leave readable output.
    mov rdi,r13
    mov rcx,r14
    xor eax,eax
    rep stosb
.policy_bad:
    call snapshot_retire
    mov byte [rel snapshot_native_busy],0
    jmp snapshot_native_saved_bad
.ok:
    mov byte [rel snapshot_native_busy],0
    xor eax,eax
    jmp snapshot_native_saved_out
snapshot_native_saved_bad:
    mov eax,-1
snapshot_native_saved_out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; RDI native out, RSI size. Reject NULL, wrap and any overlap with producer or
; port staging. This is a native pointer ABI, never a guest mapping primitive.
snapshot_native_output_disjoint:
    test rdi,rdi
    jz .bad
    mov rax,rdi
    add rax,rsi
    jc .bad
    lea rdx,[rel snapshot_native_verb]
    cmp rax,rdx
    jbe .bss
    lea rdx,[rel snapshot_native_data_end]
    cmp rdi,rdx
    jb .bad
.bss:
    lea rdx,[rel snapshot_native_probe]
    cmp rax,rdx
    jbe .port
    lea rdx,[rel snapshot_native_bss_end]
    cmp rdi,rdx
    jb .bad
.port:
    lea rdx,[rel snapshot_pio_submit_op]
    cmp rax,rdx
    jbe .ok
    lea rdx,[rel snapshot_pio_data_end]
    cmp rdi,rdx
    jb .bad
.ok:
    xor eax,eax
    ret
.bad:
    mov eax,-1
    ret

; No private/chrome/lock title or value is touched before this predicate.
; EDI slot -> EAX actual packed window id or0. Focus does not confer access.
snapshot_native_window_allowed:
    cmp edi,WM_MAX-1                ; lock slot is always excluded
    jae .bad
    lea rax,[rel wm_no_history]
    cmp byte [rax+rdi],0
    jne .bad
    lea rax,[rel wm_owner]
    cmp qword [rax+rdi*8],WM_OWNER_CHROME
    je .bad
    jmp wmx_window_id
.bad:
    xor eax,eax
    ret

; One bounded native read; same tables/vtable GET as the shipped commands.
; Secret predicate precedes type/label/value, including OWNER-approved reads.
snapshot_native_capture:
    push rbx
    push r12
    push r13
    push r14
    push r15
    call snapshot_retire
    cmp qword [rel snapshot_native_read_serial],-1
    je .bad
    call snapshot_native_policy
    test eax,eax
    jnz .bad
    call snapshot_native_indicator_present
    test eax,eax
    jz .bad
    inc qword [rel snapshot_native_read_serial]
    mov dword [rel snapshot_native_buffer],1
    ; Codex / rc-sec-claude: only the opt-in guest v2 capture emits these
    ; native scalar identities. No endpoint/request pointer or key is exposed.
    ; Terminal's separate descriptor bridge and all default v1 bytes stay v1.
    cmp byte [rel snapshot_terminal_active],1
    je .identity_done
    cmp dword [rel snapshot_native_frame],2
    jne .identity_done
    mov dword [rel snapshot_native_buffer],2
    mov rax,[rel snapshot_native_context+SN_PID]
    mov [rel snapshot_native_buffer+104],rax
    mov rax,[rel snapshot_native_context+SN_SESSION]
    mov [rel snapshot_native_buffer+112],rax
    mov rax,[rel snapshot_native_context+SN_DEADLINE]
    mov [rel snapshot_native_buffer+120],rax
.identity_done:
    mov rax,[rel snapshot_native_context+SN_SEQUENCE]
    mov [rel snapshot_native_buffer+8],rax
    mov rax,[rel snapshot_native_read_serial]
    mov [rel snapshot_native_buffer+16],rax
    mov rax,[rel snapshot_native_context+SN_SCOPE]
    mov [rel snapshot_native_buffer+24],rax
    mov rax,[rel snapshot_native_context+SN_TARGET]
    mov [rel snapshot_native_buffer+32],rax
    mov rax,[rel snapshot_native_context+SN_GENERATION]
    mov [rel snapshot_native_buffer+40],rax
    mov rax,[rel snapshot_native_context+SN_POLICY]
    mov [rel snapshot_native_buffer+88],rax
    call time_monotonic_now_us
    mov [rel snapshot_native_buffer+96],rax
    mov [rel snapshot_privacy_record+16],rax
    mov edi,[rel wm_focus]
    call snapshot_native_window_allowed
    mov [rel snapshot_native_buffer+48],rax
    xor r12d,r12d
    ; Select windows by native descending zstamp. Bounded16x16 scan, ties
    ; stable by slot. No arithmetic negation/wrapping z ordering.
    mov dword [rel snapshot_native_seen_windows],0
.window_next:
    mov r13d,WM_MAX
    xor r14d,r14d
    xor ebx,ebx
.scan:
    cmp ebx,WM_MAX
    jae .selected
    bt dword [rel snapshot_native_seen_windows],ebx
    jc .scan_next
    mov edi,ebx
    call snapshot_native_window_allowed
    test eax,eax
    jnz .allowed_window
    lea rax,[rel wm_state]
    mov eax,[rax+rbx*4]
    cmp eax,WM_VISIBLE
    je .redacted_window
    cmp eax,WM_MIN
    jne .scan_next
.redacted_window:
    mov qword [rel snapshot_native_buffer+80],1
    jmp .scan_next
.allowed_window:
    cmp qword [rel snapshot_native_context+SN_SCOPE],1
    je .scope_ok
    cmp rax,[rel snapshot_native_context+SN_TARGET]
    jne .scan_next
.scope_ok:
    lea rdx,[rel wm_zstamp]
    mov edx,[rdx+rbx*4]
    cmp r13d,WM_MAX
    je .choose
    cmp edx,r14d
    jbe .scan_next
.choose:
    mov r13d,ebx
    mov r14d,edx
.scan_next:
    inc ebx
    jmp .scan
.selected:
    cmp r13d,WM_MAX
    je .desktop_widgets
    bts dword [rel snapshot_native_seen_windows],r13d
    mov edi,r13d
    call snapshot_native_record_window
    mov edi,r13d
    call snapshot_native_record_widgets
    jmp .window_next
.desktop_widgets:
    cmp qword [rel snapshot_native_context+SN_SCOPE],1
    jne .finish
    mov edi,WGT_HOST_DESKTOP
    call snapshot_native_record_widgets
.finish:
    mov [rel snapshot_native_buffer+64],r12
    mov rax,r12
    shl rax,9
    add rax,SN_HEADER_BYTES
    mov [rel snapshot_native_buffer+72],rax
    call snapshot_native_policy
    test eax,eax
    jnz .bad
    ; Partial/truncated/unsupported walks cannot establish complete omission.
    cmp qword [rel snapshot_native_buffer+56],0
    jne .privacy_incomplete
    mov rax,[rel snapshot_native_read_serial]
    mov [rel snapshot_privacy_record+8],rax
    call time_monotonic_now_us
    mov [rel snapshot_privacy_record+24],rax
    mov rax,[rel snapshot_native_context+SN_SESSION]
    mov [rel snapshot_privacy_record+32],rax
    mov rax,[rel snapshot_native_context+SN_POLICY]
    mov [rel snapshot_privacy_record+40],rax
    mov qword [rel snapshot_privacy_record+80],1
    mov qword [rel snapshot_privacy_record+88],1
.privacy_incomplete:
    mov rax,[rel snapshot_native_read_serial]
    mov [rel snapshot_visibility_record+16],rax
    mov qword [rel snapshot_visibility_record+144],1
    mov qword [rel snapshot_visibility_record+152],1
    or qword [rel snapshot_visibility_record+8],16
    mov dword [rel snapshot_native_cursor],0
    mov byte [rel snapshot_native_valid],1
    xor eax,eax
    jmp .out
.bad:
    call snapshot_retire
    mov eax,-1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; R12 count, returns R15 next zeroed record. Capacity failure marks partial.
snapshot_native_record_next:
    cmp r12,SN_MAX_RECORDS
    jae .bad
    mov r15,r12
    shl r15,9
    lea rax,[rel snapshot_native_buffer+SN_HEADER_BYTES]
    add r15,rax
    inc r12
    mov eax,1
    ret
.bad:
    mov qword [rel snapshot_native_buffer+56],1
    xor eax,eax
    ret
snapshot_native_record_window:
    push rbx
    mov ebx,edi
    call snapshot_native_record_next
    test eax,eax
    jz .out
    mov qword [r15],1
    mov edi,ebx
    call wmx_window_id
    mov [r15+8],rax
    mov [r15+16],rax
    cmp rax,[rel snapshot_native_buffer+48]
    sete al
    movzx eax,al
    mov [r15+40],rax
    lea rax,[rel wm_gen]
    mov eax,[rax+rbx*4]
    mov [r15+24],rax
    lea rax,[rel wm_zstamp]
    mov eax,[rax+rbx*4]
    mov [r15+32],rax
    lea rax,[rel wm_state]
    mov eax,[rax+rbx*4]
    mov [r15+48],rax
    lea rsi,[rel snapshot_native_window_type]
    lea rdi,[r15+56]
    mov ecx,32
    call snapshot_native_string
    mov eax,ebx
    call wmx_label_ptr
    mov rsi,rdi
    lea rdi,[r15+88]
    mov ecx,128
    call snapshot_native_string
.out:
    pop rbx
    ret
snapshot_native_record_widgets:
    push rbx
    push r13
    push r14
    mov r13d,edi
    xor ebx,ebx
.loop:
    cmp ebx,[rel wgt_count]
    jae .out
    cmp ebx,WGT_MAX
    jae .out
    mov edi,ebx
    call wgt_slot_ptr
    mov r14,rax
    mov eax,[r14+WGI_TYPE]
    test eax,eax
    jz .next
    cmp [r14+WGI_WIN],r13d
    jne .next
    test dword [r14+WGI_FLAGS],1
    jz .next
    ; Withhold native security text before touching label/type/value providers.
    test dword [r14+WGI_EDIT],WGT_EDIT_SECTEXT
    jnz .redacted_sectext
    ; Do not export even a label/type/length for secret widgets.
    mov ecx,[rel wgt_secret_type]
    inc ecx
    cmp eax,ecx
    je .redacted
    mov rsi,[r14+WGI_ROLE]
    test rsi,rsi
    jz .ordinary
    lea rdi,[rel str_wgt_role_password]
    call strcmp
    test eax,eax
    jz .redacted_password
.ordinary:
    call snapshot_native_record_next
    test eax,eax
    jz .out
    mov qword [r15],2
    mov [r15+8],rbx
    cmp r13d,WGT_HOST_DESKTOP
    je .desktop
    mov edi,r13d
    call wmx_window_id
    mov [r15+16],rax
    lea rax,[rel wm_gen]
    mov eax,[rax+r13*4]
    mov [r15+24],rax
    lea rax,[rel wm_zstamp]
    mov eax,[rax+r13*4]
    mov [r15+32],rax
.desktop:
    mov eax,[r14+WGI_FLAGS]
    mov [r15+48],rax
    cmp ebx,[rel wgt_focus_id]
    sete al
    movzx eax,al
    mov [r15+40],rax
    mov eax,[r14+WGI_TYPE]
    cmp eax,WTYPE_MAX
    ja .unsupported
    mov edi,ebx
    call wgt_type_name_of
    mov rsi,rax
    lea rdi,[r15+56]
    mov ecx,32
    call snapshot_native_string
    mov rsi,[r14+WGI_LABEL]
    lea rdi,[r15+88]
    mov ecx,128
    call snapshot_native_string
    mov edi,ebx
    call snapshot_visibility_get_begin
    call form_widget_tree_text_ptr
    call snapshot_visibility_get_end
    test rax,rax
    jnz .value
    mov eax,[r14+WGI_TYPE]
    dec eax
    cmp eax,WTYPE_MAX
    jae .unsupported
    imul rax,WT_SZ
    lea rdx,[rel wgt_types]
    mov rax,[rdx+rax+WT_GET]
    test rax,rax
    jz .unsupported
    mov [rel snapshot_native_getter],rax
    mov edi,ebx
    lea rsi,[rel str_wf_value]
    call snapshot_visibility_get_begin
    call rax
    call snapshot_visibility_get_end
    test rax,rax
    jnz .value
    mov edi,ebx
    lea rsi,[rel str_wf_text]
    call snapshot_visibility_get_begin
    call [rel snapshot_native_getter]
    call snapshot_visibility_get_end
    test rax,rax
    jnz .value
    jmp .unsupported
.value:
    mov rsi,rax
    lea rdi,[r15+216]
    mov ecx,288
    call snapshot_native_string
    jmp .next
.unsupported:
    or qword [r15+504],2
    mov qword [rel snapshot_native_buffer+56],1
    jmp .next
.redacted:
    mov edx,1
    jmp .observe_omission
.redacted_password:
    mov edx,2
    jmp .observe_omission
.redacted_sectext:
    mov edx,4
.observe_omission:
    call snapshot_privacy_omitted
    mov qword [rel snapshot_native_buffer+80],1    ; boolean only, no secret count/length
.next:
    inc ebx
    jmp .loop
.out:
    pop r14
    pop r13
    pop rbx
    ret

; Bounded cstr copy to already-zeroed fixed field. Overflow marks partial;
; missing metadata stays empty; no pointer or uninitialised tail is exported.
snapshot_native_string:
    test rsi,rsi
    jz .done
    dec ecx
.loop:
    lodsb
    test al,al
    jz .done
    test ecx,ecx
    jz .truncated
    stosb
    dec ecx
    jmp .loop
.truncated:
    or qword [r15+504],1
    mov qword [rel snapshot_native_buffer+56],1
.done:
    ret

; Finite grammar generated by native scope, never guest text or a parser tunnel.
snapshot_native_argument:
    lea rsi,[rel snapshot_native_desktop]
    cmp qword [rel snapshot_native_context+SN_SCOPE],1
    je .text
    lea rsi,[rel snapshot_native_active]
    cmp qword [rel snapshot_native_context+SN_SCOPE],2
    je .text
    lea rsi,[rel snapshot_native_window]
.text:
    lea rdi,[rel snapshot_native_argument_buf]
.copy:
    lodsb
    stosb
    test al,al
    jnz .copy
    cmp qword [rel snapshot_native_context+SN_SCOPE],3
    jne .done
    dec rdi
    mov rax,[rel snapshot_native_context+SN_TARGET]
    xor ecx,ecx
    mov r8d,10
.decimal:
    xor edx,edx
    div r8
    push rdx
    inc ecx
    test rax,rax
    jnz .decimal
.digits:
    pop rax
    add al,'0'
    stosb
    loop .digits
    mov byte [rdi],0
.done:
    ret

; The native AI-read title shares the Guardian header; its lower alert status
; remains visible. PUBLIC builds show AI READ; other builds show GUARD+AI.
; Presented BEFORE the first label/getter read. Absence/blank/lock denies.
snapshot_native_indicator_present:
    cmp byte [rel snapshot_terminal_active],1
    je terminal_consent_present
    cmp qword [rel fb_base],0
    je .bad
    cmp dword [rel fb_width],192
    jl .bad
    cmp dword [rel fb_height],TASKBAR_H
    jl .bad
    cmp byte [rel dpms_blanked],0
    jne .bad
    cmp byte [rel session_locked],SESSION_UNLOCKED
    jne .bad
    ; Direct framebuffer is already scanout; a shadow requires a live present
    ; destination. Check the actual presentation relationship, not guest state.
    mov rax,[rel fb_base]
    cmp rax,[rel fb_shadow_base]
    jne .direct
    cmp qword [rel fb_scanout_base],0
    je .bad
.direct:
    call time_monotonic_now_us
    add rax,20000000
    jc .bad
    mov [rel snapshot_native_indicator_until],rax
    mov rax,[rel session_authority_epoch]
    mov [rel snapshot_native_indicator_session],rax
    call taskbar_draw_registry
    ; The ordinary registry is deferred once live. This security notice must
    ; paint its own exact bounded region now, before the explicit scanout and
    ; before any getter is authorized; an old shadow is never its receipt.
    call snapshot_indicator_draw
    call fb_present_flush
    ; Explicit rectangle present works even if caller entered a cadence batch.
    mov r8d,8
    mov r9d,[rel fb_height]
    sub r9d,TASKBAR_H-4
    mov r10d,80
    mov r11d,16
    call fb_present_rect
    call snapshot_visibility_scanout
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret
snapshot_indicator_draw:
    push rbx
    cmp byte [rel session_locked],SESSION_UNLOCKED
    jne .out
    mov rax,[rel session_authority_epoch]
    cmp rax,[rel snapshot_native_indicator_session]
    jne .out
    call time_monotonic_now_us
    cmp rax,[rel snapshot_native_indicator_until]
    jae .out
    lea rdi,[rel snapshot_native_indicator_text]
    call wmx_tray_notice_paint
    mov edi,1
    mov rsi,[rel snapshot_native_context+SN_POLICY]
    call snapshot_visibility_draw
.out:
    pop rbx
    ret


; Separate observational ABI. These hooks never authorize or change a capture.
; Preserve all caller registers/flags: getters and output words retain their ABI.
%macro SV_SAVE 0
    pushfq
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
%endmacro
%macro SV_RESTORE 0
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    popfq
%endmacro
; EDI notice kind1native/2terminal; RSI actual painter policy generation.
; Native-only hook after the real notice painter, never a guest scalar setter.
snapshot_visibility_draw:
    SV_SAVE
    cmp byte [rel snapshot_native_busy],1
    jne .out
    cmp byte [rel session_locked],SESSION_UNLOCKED
    jne .out
    mov rax,[rel session_authority_epoch]
    cmp rax,[rel snapshot_native_context+SN_SESSION]
    jne .out
    cmp rsi,[rel snapshot_native_context+SN_POLICY]
    jne .out
    test rsi,rsi
    jz .out
    cmp edi,1
    jne .terminal
    cmp byte [rel snapshot_terminal_active],0
    jne .out
    jmp .clock
.terminal:
    cmp edi,2
    jne .out
    cmp byte [rel snapshot_terminal_active],1
    jne .out
.clock:
    mov r12,rdi
    mov r13,rsi
    call time_monotonic_now_us
    test rax,rax
    jz .out
    mov [rel snapshot_visibility_record+24],rax
    mov rax,[rel session_authority_epoch]
    mov [rel snapshot_visibility_record+80],rax
    mov [rel snapshot_visibility_record+88],r13
    mov [rel snapshot_visibility_record+136],r12
    or qword [rel snapshot_visibility_record+8],1
    mov qword [rel snapshot_visibility_mapping],0
    call snapshot_visibility_region
    test eax,eax
    jz .out
    mov rax,[rel fb_shadow_base]
    mov [rel snapshot_visibility_mapping],rax
    mov rax,[rel fb_scanout_base]
    mov [rel snapshot_visibility_mapping+8],rax
    mov rax,[rel fb_width]
    mov [rel snapshot_visibility_mapping+16],rax
    mov eax,[rel fb_stride]
    mov [rel snapshot_visibility_mapping+24],rax
    lea rdi,[rel snapshot_visibility_pixels]
    mov ebx,16
.save_row:
    mov ecx,80
    cld
    rep movsd
    add rsi,rdx
    dec ebx
    jnz .save_row
.out:
    SV_RESTORE
    ret

; Compare only the bounded80x16 notice, never arbitrary desktop/secret pixels.
; Strict supported shadow mapping; unsupported/direct/scaled layouts remain U.
; Equality proves memory agreement at this sample, never physical panel visibility.
snapshot_visibility_scanout:
    SV_SAVE
    test qword [rel snapshot_visibility_record+8],1
    jz .out
    cmp byte [rel session_locked],SESSION_UNLOCKED
    jne .out
    cmp byte [rel dpms_blanked],0
    jne .out
    mov rax,[rel session_authority_epoch]
    cmp rax,[rel snapshot_visibility_record+80]
    jne .out
    cmp qword [rel snapshot_visibility_mapping],0
    je .out
    call snapshot_visibility_region
    test eax,eax
    jz .out
    mov rax,[rel fb_shadow_base]
    cmp rax,[rel snapshot_visibility_mapping]
    jne .out
    mov rax,[rel fb_scanout_base]
    cmp rax,[rel snapshot_visibility_mapping+8]
    jne .out
    mov rax,[rel fb_width]
    cmp rax,[rel snapshot_visibility_mapping+16]
    jne .out
    mov eax,[rel fb_stride]
    cmp rax,[rel snapshot_visibility_mapping+24]
    jne .out
    lea rsi,[rel snapshot_visibility_pixels]
    mov r12d,1
    mov ebx,16
.row:
    mov ecx,80
    cld
    repe cmpsd
    jne .mismatch
    mov eax,[rel fb_stride]
    sub eax,80
    shl rax,2
    add rdi,rax
    dec ebx
    jnz .row
    jmp .observed
.mismatch:
    mov r12d,2
.observed:
    call time_monotonic_now_us
    cmp rax,[rel snapshot_visibility_record+24]
    jb .out
    ; Retain the first reproduced mismatch and its actual sample time.
    cmp qword [rel snapshot_visibility_record+96],2
    je .flag
    mov [rel snapshot_visibility_record+32],rax
    mov [rel snapshot_visibility_record+96],r12
.flag:
    or qword [rel snapshot_visibility_record+8],2
.out:
    SV_RESTORE
    ret

snapshot_visibility_region:
    cmp byte [rel fb_scale],1
    jne .bad
    cmp dword [rel fb_bpp],32
    jne .bad
    mov eax,[rel fb_width]
    cmp eax,192
    jb .bad
    cmp eax,16384
    ja .bad
    cmp [rel fb_stride],eax
    jb .bad
    mov ecx,[rel fb_height]
    cmp ecx,TASKBAR_H
    jb .bad
    cmp ecx,16384
    ja .bad
    mov eax,[rel fb_stride]
    cmp eax,16384
    ja .bad
    imul rax,rcx
    shl rax,2
    cmp rax,[rel fb_size]
    ja .bad
    cmp rax,[rel fb_shadow_cap]
    ja .bad
    mov rsi,[rel fb_shadow_base]
    test rsi,rsi
    jz .bad
    cmp rsi,[rel fb_base]
    jne .bad
    mov rdi,[rel fb_scanout_base]
    test rdi,rdi
    jz .bad
    cmp rdi,rsi
    je .bad
    mov rdx,rsi
    add rdx,rax
    jc .bad
    mov rdx,rdi
    add rdx,rax
    jc .bad
    mov eax,[rel fb_height]
    sub eax,TASKBAR_H-4
    mov edx,[rel fb_stride]
    imul rax,rdx
    lea rax,[rax*4+32]
    add rsi,rax
    add rdi,rax
    mov edx,[rel fb_stride]
    sub edx,80
    shl rdx,2
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

snapshot_visibility_get_begin:
    SV_SAVE
    call time_monotonic_now_us
    test rax,rax
    jz .out
    cmp qword [rel snapshot_visibility_record+40],0
    jne .out
    mov [rel snapshot_visibility_record+40],rax
    mov rax,[rel session_authority_epoch]
    mov [rel snapshot_visibility_record+104],rax
    mov rax,[rel snapshot_native_context+SN_POLICY]
    mov [rel snapshot_visibility_record+112],rax
.out:
    SV_RESTORE
    ret
snapshot_visibility_get_end:
    SV_SAVE
    call time_monotonic_now_us
    cmp rax,[rel snapshot_visibility_record+40]
    jb .out
    cmp qword [rel snapshot_visibility_record+40],0
    je .out
    mov [rel snapshot_visibility_record+48],rax
    or qword [rel snapshot_visibility_record+8],4
.out:
    SV_RESTORE
    ret
snapshot_visibility_copy_complete:
    SV_SAVE
    cmp qword [rel snapshot_native_context+SN_SOURCE],1
    jne .out
    call time_monotonic_now_us
    ; Record actual completion even if clock/expiry conflicts. Codec refuses
    ; the available conflict rather than silently converting it to absence.
    cmp qword [rel snapshot_visibility_record+56],0
    jne .last
    mov [rel snapshot_visibility_record+56],rax
.last:
    mov [rel snapshot_visibility_record+64],rax
    mov eax,[rel snapshot_native_cursor]
    mov [rel snapshot_visibility_record+72],rax
    mov rax,[rel session_authority_epoch]
    mov [rel snapshot_visibility_record+120],rax
    mov rax,[rel snapshot_native_context+SN_POLICY]
    mov [rel snapshot_visibility_record+128],rax
    or qword [rel snapshot_visibility_record+8],8
    cmp dword [rel snapshot_native_cursor],4
    je .sample
    mov eax,[rel snapshot_native_cursor]
    cmp rax,[rel snapshot_native_buffer+72]
    jne .out
.sample:
    call snapshot_visibility_scanout
.out:
    SV_RESTORE
    ret

; Independent custody prefix + separate historical original-read observations.
; RDI actual endpoint, ESI actual START, RDX native512. No capture or grant.
snapshot_visibility_read:
    push rbx
    mov rbx,rdx
    test rbx,rbx
    jz .bad
    mov rax,rbx
    add rax,512
    jc .bad
    call snapshot_custody_read
    test eax,eax
    jnz .out
    lea rdi,[rbx+320]
    xor eax,eax
    mov ecx,24
    cld
    rep stosq
    mov dword [rbx+320],0x31564e53    ; SNV1
    mov word [rbx+324],1
    mov word [rbx+326],192
    test qword [rbx+24],4
    jz .ok
    mov rax,[rbx+128]
    cmp rax,[rel snapshot_visibility_record+16]
    jne .ok
    mov rax,[rbx+208]
    cmp rax,[rel snapshot_visibility_record+72]
    jne .ok
    lea rsi,[rel snapshot_visibility_record+8]
    lea rdi,[rbx+328]
    mov ecx,23
    rep movsq
.ok:
    xor eax,eax
    jmp .out
.bad:
    mov eax,-1
.out:
    pop rbx
    ret
; Original selected visible widget, before label/type/getter/export. Only
; non-secret metadata is inspected. No field pointer/value/hash is exported.
; RBX actual selected widget slot, R14 native slot, EDX first protected class.
snapshot_privacy_omitted:
    SV_SAVE
    mov r12d,edx
    mov eax,[rel wgt_secret_type]
    inc eax
    cmp eax,[r14+WGI_TYPE]
    jne .role
    or r12d,1
.role:
    mov rsi,[r14+WGI_ROLE]
    test rsi,rsi
    jz .sectext
    lea rdi,[rel str_wgt_role_password]
    call strcmp
    test eax,eax
    jnz .sectext
    or r12d,2
.sectext:
    test dword [r14+WGI_EDIT],WGT_EDIT_SECTEXT
    jz .population
    or r12d,4
.population:
    xor r13d,r13d                 ; unknown backing is not an empty field
    test r12d,1
    jz .stock
    cmp ebx,[rel wgt_secret_owner]
    jne .record
    mov eax,[rel wgt_secret_len]  ; kit-owned current metadata, never bytes
    cmp eax,128
    ja .record
    mov ecx,31
    cmp eax,ecx
    cmovb ecx,eax
    cmp ecx,[r14+WGI_VLEN]        ; reject stale owner/slot metadata
    jne .record
    jmp .known
.stock:
    cmp dword [r14+WGI_TYPE],2    ; native stock textfield's maintained length
    jne .record
    mov eax,[r14+WGI_VLEN]
    cmp eax,255
    ja .record
.known:
    test eax,eax
    setnz r13b
    inc r13d                     ; 1 empty observed, 2 nonempty observed
.record:
    or [rel snapshot_privacy_record+48],r12
    lea rdi,[rel snapshot_privacy_record+56]
    mov ecx,3
.merge:
    test r12b,1
    jz .next
    cmp [rdi],r13
    jae .next                    ; any known nonempty dominates
    mov [rdi],r13
.next:
    shr r12d,1
    add rdi,8
    loop .merge
    SV_RESTORE
    ret

; New optional driver receipt; old custody and visibility ABIs stay unchanged.
; RDI actual endpoint, ESI consumed START, RDX native448. Never captures/grants.
snapshot_privacy_read:
    push rbx
    mov rbx,rdx
    test rbx,rbx
    jz .bad
    mov rax,rbx
    add rax,448
    jc .bad
    call snapshot_custody_read
    test eax,eax
    jnz .out
    lea rdi,[rbx+320]
    xor eax,eax
    mov ecx,16
    cld
    rep stosq
    mov dword [rbx+320],0x314f4e53 ; SNO1
    mov word [rbx+324],1
    mov word [rbx+326],128
    test qword [rbx+24],4
    jz .ok
    mov rax,[rbx+128]
    cmp rax,[rel snapshot_privacy_record+8]
    jne .ok
    lea rsi,[rel snapshot_privacy_record+8]
    lea rdi,[rbx+328]
    mov ecx,15
    rep movsq
.ok:
    xor eax,eax
    jmp .out
.bad:
    mov eax,-1
.out:
    pop rbx
    ret
; Only the new privacy route requires the captured authority still to be
; current during every scalar read. Existing historical custody is unchanged.
; RDI endpoint, ESI START, RDX frozen448. No new scope or policy transition.
snapshot_privacy_current:
    push rbx
    mov rbx,rdx
    call snapshot_custody_current
    test eax,eax
    jnz .out
    test qword [rbx+24],4
    jz .out
    cmp byte [rel snapshot_native_busy],0
    jne .bad
    cmp byte [rel snapshot_native_valid],1
    jne .bad
    mov rax,[rbx+128]
    cmp rax,[rel snapshot_native_buffer+16]
    jne .bad
    mov byte [rel snapshot_native_busy],1
    call snapshot_native_policy
    mov byte [rel snapshot_native_busy],0
    jmp .out
.bad:
    mov eax,-1
.out:
    pop rbx
    ret
%unmacro SV_SAVE 0
%unmacro SV_RESTORE 0

; Codex / rc-sec-claude. Separate pointer-free native driver observation.
; Trusted observer -> EAX1 observed, RDX decision0/1/2, RCX generation,
; R8 reason. No request/context argument or authority is supplied to it.
snapshot_configure_driver_observer:
    cmp byte [rel snapshot_native_busy],0
    jne .bad
    cmp dword [rel cmd_dispatch_depth],0
    jne .bad
    cmp byte [rel command_auth_remote_active],0
    jne .bad
    push rdi
    call snapshot_transport_retire
    pop rdi
    mov [rel snapshot_custody_observer],rdi
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; RDI actual driver endpoint, ESI original consumed START, RDX native320.
; The binding getter independently validates maintained START/session/VM state.
; No field is read from snapshot_native_context to establish driver identity.
snapshot_custody_read:
    push rbx
    push r12
    push r13
    mov rbx,rdx
    mov r12,rdi
    mov r13d,esi
    cmp byte [rel snapshot_native_busy],0
    jne .bad
    cmp dword [rel cmd_dispatch_depth],0
    jne .bad
    call smp_current_logical
    test eax,eax
    jnz .bad
    lea rax,[rel guest_request_endpoint]
    cmp r12,rax
    jne .bad
    test rbx,rbx
    jz .bad
    mov rax,rbx
    add rax,320
    jc .bad
    lea rdx,[rel snapshot_custody_binding]
    mov ecx,48
    mov rdi,r12
    mov esi,r13d
    call guest_request_binding_copy
    test eax,eax
    jz .bad
    cmp qword [rel snapshot_custody_serial],-1
    je .bad
    call time_monotonic_now_us
    test rax,rax
    jz .bad
    mov rdx,rax
    mov rdi,rbx
    xor eax,eax
    mov ecx,40
    cld
    rep stosq
    mov dword [rbx],0x31434e53        ; SNC1
    mov word [rbx+4],1
    mov word [rbx+6],320
    inc qword [rel snapshot_custody_serial]
    mov rax,[rel snapshot_custody_serial]
    mov [rbx+8],rax
    mov [rbx+16],rdx
    mov qword [rbx+24],1
    mov rax,[rel snapshot_custody_binding]
    mov [rbx+32],rax
    mov rax,[rel snapshot_custody_binding+8]
    mov [rbx+40],rax
    mov rax,[rel snapshot_custody_binding+24]
    mov [rbx+48],rax
    mov rax,[rel snapshot_custody_binding+32]
    mov [rbx+56],rax
    mov rax,[rel snapshot_custody_binding+40]
    mov [rbx+64],rax
    mov qword [rbx+72],1
    mov qword [rbx+88],3              ; UNOBSERVED, never default ALLOW
    mov qword [rbx+104],1             ; native monotonic microseconds
    cmp qword [rel snapshot_custody_observer],0
    je .copy
    call [rel snapshot_custody_observer]
    cmp eax,1
    jne .copy
    test rcx,rcx
    jz .copy
    cmp rdx,2
    ja .copy
    or qword [rbx+24],2
    mov [rbx+80],rcx
    mov [rbx+88],rdx
    mov [rbx+96],r8
.copy:
    cmp qword [rel snapshot_custody_copy_record],0
    je .current
    ; A completed/prefix copy is about its original time, not permission now.
    lea rsi,[rel snapshot_custody_copy_record]
    lea rdi,[rbx+128]
    mov ecx,24
    cld
    rep movsq
    or qword [rbx+24],4
.current:
    mov rdi,r12
    mov esi,r13d
    mov rdx,rbx
    call snapshot_custody_current
    test eax,eax
    jnz .bad
    xor eax,eax
    jmp .out
.bad:
    mov eax,-1
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Revalidate each word of the independently queried record. Policy replacement,
; STOP/rebind/session change or backwards clock cannot publish stale custody.
snapshot_custody_current:
    push rbx
    mov rbx,rdx
    lea rax,[rel guest_request_endpoint]
    cmp rdi,rax
    jne .bad
    lea rdx,[rel snapshot_custody_binding]
    mov ecx,48
    call guest_request_binding_copy
    test eax,eax
    jz .bad
    mov rax,[rel snapshot_custody_binding]
    cmp [rbx+32],rax
    jne .bad
    mov rax,[rel snapshot_custody_binding+8]
    cmp [rbx+40],rax
    jne .bad
    mov rax,[rel snapshot_custody_binding+24]
    cmp [rbx+48],rax
    jne .bad
    mov rax,[rel snapshot_custody_binding+32]
    cmp [rbx+56],rax
    jne .bad
    mov rax,[rel snapshot_custody_binding+40]
    cmp [rbx+64],rax
    jne .bad
    call time_monotonic_now_us
    cmp rax,[rbx+16]
    jb .bad
    cmp qword [rel snapshot_custody_observer],0
    je .unobserved
    call [rel snapshot_custody_observer]
    cmp eax,1
    jne .unobserved
    test rcx,rcx
    jz .unobserved
    cmp rdx,2
    ja .unobserved
    test qword [rbx+24],2
    jz .bad
    cmp rcx,[rbx+80]
    jne .bad
    cmp rdx,[rbx+88]
    jne .bad
    cmp r8,[rbx+96]
    jne .bad
    jmp .copy
.unobserved:
    test qword [rbx+24],2
    jnz .bad
.copy:
    test qword [rbx+24],4
    jz .ok
    mov rax,[rbx+32]
    cmp [rbx+224],rax
    jne .bad
    mov rax,[rbx+40]
    cmp [rbx+232],rax
    jne .bad
    mov rax,[rbx+48]
    cmp [rbx+240],rax
    jne .bad
    mov rax,[rbx+56]
    cmp [rbx+248],rax
    jne .bad
    mov rax,[rbx+64]
    cmp [rbx+256],rax
    jne .bad
    mov rax,[rbx+200]
    cmp rax,[rbx+16]
    ja .bad
.ok:
    xor eax,eax
    pop rbx
    ret
.bad:
    mov eax,-1
    pop rbx
    ret

; Called only after every original per-word policy/currentness check succeeds.
; RBX original cursor. HOST positive controls do not install a product grant.
snapshot_custody_copy:
    push r12
    cmp qword [rel snapshot_native_context+SN_SOURCE],1
    jne .ok
    lea rdi,[rel guest_request_endpoint]
    mov esi,[rel hv_linux_start_consumed]
    lea rdx,[rel snapshot_custody_binding]
    mov ecx,48
    call guest_request_binding_copy
    test eax,eax
    jz .bad
    call time_monotonic_now_us
    mov r12,rax
    cmp rax,[rel snapshot_native_buffer+96]
    jb .bad
    cmp rax,[rel snapshot_native_context+SN_DEADLINE]
    jae .bad
    test ebx,ebx
    jz .first
    cmp rax,[rel snapshot_custody_copy_record+72]
    jb .bad
    jmp .last
.first:
    lea rdi,[rel snapshot_custody_copy_record]
    xor eax,eax
    mov ecx,24
    cld
    rep stosq
    lea rdi,[rel snapshot_custody_copy_record]
%macro SCC_BUFFER 2
    mov rax,[rel snapshot_native_buffer+%2]
    mov [rdi+%1],rax
%endmacro
    SCC_BUFFER 0,16
    SCC_BUFFER 8,8
    SCC_BUFFER 16,24
    SCC_BUFFER 24,32
    SCC_BUFFER 32,40
    SCC_BUFFER 40,88
    SCC_BUFFER 48,96
    mov rax,[rel snapshot_native_context+SN_DEADLINE]
    mov [rdi+56],rax
    mov [rdi+64],r12
    SCC_BUFFER 88,72
%unmacro SCC_BUFFER 2
    mov rax,[rel snapshot_custody_binding]
    mov [rdi+96],rax
    mov rax,[rel snapshot_custody_binding+8]
    mov [rdi+104],rax
    mov rax,[rel snapshot_custody_binding+24]
    mov [rdi+112],rax
    mov rax,[rel snapshot_custody_binding+32]
    mov [rdi+120],rax
    mov rax,[rel snapshot_custody_binding+40]
    mov [rdi+128],rax
    mov qword [rdi+136],1
    mov qword [rdi+152],1
.last:
    lea rdi,[rel snapshot_custody_copy_record]
    mov [rdi+72],r12
    lea rax,[rbx+4]
    mov [rdi+80],rax
    mov qword [rdi+144],1
    cmp rax,[rdi+88]
    jne .ok
    mov qword [rdi+144],2
.ok:
    xor eax,eax
    pop r12
    ret
.bad:
    mov eax,-1
    pop r12
    ret

snapshot_native_name: db 'SNAPSHOT',0
snapshot_native_desktop: db 'desktop',0
snapshot_native_active: db 'active',0
snapshot_native_window: db 'window ',0
snapshot_native_window_type: db 'window',0
snapshot_native_receipt: db 'snapshot read_id=',0
%if PAOS_PUBLIC_BUILD
snapshot_native_indicator_text: db 'AI READ',0
%else
snapshot_native_indicator_text: db 'GUARD+AI',0
%endif
%include "core/abi/wdata.inc"
%macro WDATA_snapshot 0
align 8
snapshot_native_verb: dq -1
snapshot_native_resolver: dq 0
snapshot_custody_observer: dq 0
snapshot_custody_serial: dq 0
snapshot_terminal_handler_op: dq 0
snapshot_terminal_validator: dq 0
snapshot_terminal_active: db 0
align 8
snapshot_native_seen_binding: dq 0
snapshot_native_last_seq: dq 0
snapshot_native_read_serial: dq 0
snapshot_native_indicator_until: dq 0
snapshot_native_indicator_session: dq 0
snapshot_native_getter: dq 0
snapshot_native_cursor: dd 0
snapshot_native_seen_windows: dd 0
snapshot_native_busy: db 0
snapshot_native_valid: db 0
snapshot_native_data_end:
%endmacro
WDATA_DEFER WDATA_snapshot
%macro WDATA_snapshot_bss 0
alignb 8
snapshot_native_probe: resb 48
snapshot_terminal_desc: resb 256
snapshot_native_frame: resb 40
snapshot_native_context: resb SN_CONTEXT_BYTES
snapshot_native_req: resb REQ_SZ
snapshot_native_ticket: resb AUTH_T_SIZE
snapshot_native_rsp: resb RSP_SZ
snapshot_native_argument_buf: resb 40
snapshot_native_buffer: resb SN_BUFFER_BYTES
snapshot_custody_binding: resb 48
snapshot_custody_copy_record: resb 192
snapshot_visibility_record: resb 192
snapshot_visibility_mapping: resb 48
snapshot_visibility_pixels: resb 5120
snapshot_privacy_record: resb 128
snapshot_native_bss_end:
%endmacro
WDATA_BSS_DEFER WDATA_snapshot_bss
