;; MODULE hv/driver_domain_power
;; LAYER 5
;; EXPORTS nd_power_register, nd_power_tick, nd_power_restart_step
;; IMPORTS hv/driver_domain_command, hv/driver_domain, hv/driver_domain_restart, hv/guestpower, hv/vmx, core/sched, svc/command, svc/command_auth, fs/storage_access, boot/header, core/lib/fmt
;; CAPS extension
;; OWNER saga:hv
;; CONTEXT: bsp_only
; T5-1.C10b-1b (spec 8.1.1 "Shut down asks the guest OS to close cleanly, then
; forces off after a bounded timeout"). INPUT unit, built on VM's C10b-1a ABI
; (nd_power_request, nd_power_state, nd_power_clean, nd_power_clean_generation,
; nd_power_clean_ms; VM 106657 and amendment 1 at 106671).
; NDSHUTDOWN only queues: a command handler never waits. nd_power_tick, called
; from nd_tick while the exact generation is attached, retries a not-yet-open
; port and forces off with the existing nd_stop at the deadline. The job is bound
; to one generation; a later START reads as ended, never as this job's outcome.
; NDSHUTDOWN checks START and all 16 nonce bytes against nd_generation/nd_nonce
; itself before arming, so a port-wait job (rc 5) never holds an unproved nonce;
; the tick then uses native's own nd_nonce for retries and nd_stop (VM Q1 term 1).
; NDPWRSTAT reports the job (no nonce, BDF or address).
; Restart (unit 2): an owner NDRESTART calls nd_power_restart_step from
; nd_restart_run before nd_quiesce. It asks once, waits within the same bound,
; and never calls nd_stop: if the guest is not cleanly retired by then,
; nd_quiesce issues its one original nd_stop exactly as before.
ND_SHUTDOWN_MS equ 10000
NDP_DONE      equ 2                 ; ndp_state only: the job has its final outcome
NDP_NONE      equ 0
NDP_PENDING   equ 1
NDP_CLEAN     equ 2
NDP_FORCED    equ 3
NDP_ENDED     equ 4                 ; retired another way (failure, owner NDSTOP, later START)
NDP_LATE      equ 5                 ; port-wait retry refused (rc 1-4), nothing forced
NDP_STOPFAIL  equ 6                 ; deadline reached, nd_stop refused
; Restart step outcomes (owner restart record +236; 0 = a build without the step)
NDPR_CLEAN    equ 1                 ; VM's three-part clean rule held
NDPR_BOUND    equ 2                 ; still attached at the bound: nd_quiesce forces
NDPR_REFUSED  equ 3                 ; 1a refused the request (rc 1-4)
NDPR_ENDED    equ 4                 ; not attached / retired another way / generation moved
NDPR_BUSY     equ 5                 ; an NDSHUTDOWN job is open for this generation
NDPR_CLOCK    equ 6                 ; no clock, or the clock went backwards
NDPR_NO_REQUEST equ 0xff            ; +232 when no request was made
NDPR_TURNS    equ 16384             ; finite even if a damaged clock stalls

nd_power_register:
    lea rdi,[rel ndp_verb_shutdown]
    lea rsi,[rel ndp_command_shutdown]
    mov rdx,CMD_AUTH_CAP_MUTATE
    mov ecx,ARGT_TEXT
    xor r8d,r8d
    mov r9d,1
    call command_register_verb
    lea rdi,[rel ndp_verb_stat]
    lea rsi,[rel ndp_command_stat]
    xor edx,edx
    mov ecx,ARGT_TEXT
    xor r8d,r8d
    xor r9d,r9d
    jmp command_register_verb

; NDSHUTDOWN <start> <nonce>. Same owner/special-intent gate and operands as NDSTOP.
ndp_command_shutdown:
    push rbx
    push r12
    push r13
    push r14
    sub rsp,8
    call cmd_handler_prologue
    mov r12,rsi
    mov rbx,[rdi+REQ_ARG]
    call hv_out_reset
    call storage_access_request_owner
    cmp eax,1
    jne .auth
    call storage_access_request_intent
    cmp eax,SA_INTENT_SPECIAL
    jne .auth
    mov rdi,rbx
    lea rsi,[rel ndp_arg_start]
    mov edx,11
    call nd_token
    test rax,rax
    jz .syntax
    mov rdi,rax
    lea rsi,[rel ndp_arg_nonce]
    mov edx,17
    call nd_token
    test rax,rax
    jz .syntax
    cmp byte [rax],0
    jne .syntax
    cmp byte [rel ndp_arg_start],'1'
    jb .syntax
    cmp byte [rel ndp_arg_start],'9'
    ja .syntax
    lea rdi,[rel ndp_arg_nonce]
    call nd_nonce_valid
    test eax,eax
    jz .syntax
    lea rdi,[rel ndp_arg_start]
    mov esi,10
    mov edx,10
    call nd_number
    jc .syntax
    mov r13d,eax                       ; requested START (u32)
    cmp dword [rel ndr_phase],0
    jne .pending                       ; an owner restart owns this domain's retirement
    call ndp_settle                    ; an older job keeps its own final outcome
    ; One job per generation: a second request while this one is open is refused.
    cmp byte [rel ndp_state],NDP_PENDING
    jne .request
    mov rax,[rel ndp_gen]
    cmp rax,[rel nd_generation]
    je .pending
.request:
    mov eax,r13d
    cmp rax,[rel nd_generation]
    jne .stale
    lea rdi,[rel ndp_arg_nonce]
    lea rsi,[rel nd_nonce]
    mov ecx,16
    cld
    repe cmpsb
    jne .stale
    mov edi,r13d
    lea rsi,[rel nd_nonce]
    call nd_power_request
    mov r14d,eax
    test eax,eax
    jz .arm
    cmp eax,5
    je .arm                            ; port not open yet: the tick retries within the bound
    cmp eax,1
    je .not_attached
    cmp eax,2
    je .stale
    cmp eax,3
    je .no_port
    jmp .pending                       ; 4, or any code 1a may add: nothing changed
.arm:
    mov [rel ndp_gen],r13
    mov [rel ndp_request_rc],r14d
    mov dword [rel ndp_stop_rc],0
    xor eax,eax
    cmp r14d,5
    sete al
    mov [rel ndp_port_wait],al
    call boot_ms_now
    mov [rel ndp_queued_ms],rax
    add rax,ND_SHUTDOWN_MS
    mov [rel ndp_deadline_ms],rax
    mov qword [rel ndp_end_ms],0
    mov byte [rel ndp_outcome],NDP_PENDING
    mov byte [rel ndp_state],NDP_PENDING
    lea rdi,[rel ndp_queued_text]
    call hv_out_str
    lea rdi,[rel ndp_arg_start]
    call hv_out_str
    cmp byte [rel ndp_port_wait],1
    jne .ok
    lea rdi,[rel ndp_port_wait_text]
    call hv_out_str
.ok:
    xor r14d,r14d
    jmp .ready
.auth:
    lea rdi,[rel ndp_err_auth]
    mov r14d,CMDE_AUTHDENY
    jmp .error
.syntax:
    lea rdi,[rel ndp_err_syntax]
    mov r14d,CMDE_BADARG
    jmp .error
.not_attached:
    lea rdi,[rel ndp_err_not_attached]
    mov r14d,CMDE_BUSY
    jmp .error
.stale:
    lea rdi,[rel ndp_err_stale]
    mov r14d,CMDE_BADSEL
    jmp .error
.no_port:
    lea rdi,[rel ndp_err_no_port]
    mov r14d,CMDE_BUSY
    jmp .error
.pending:
    lea rdi,[rel ndp_err_pending]
    mov r14d,CMDE_BUSY
.error:
    call hv_out_str
.ready:
    mov byte [rel hv_out_ready],1
    mov [r12+RSP_CODE],r14
    add rsp,8
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Called from nd_tick while the domain is attached (nd_state 2). BSP, never blocks.
; Preserves every register nd_tick relies on (callee-saved by the SysV rule).
nd_power_tick:
    cmp byte [rel ndp_state],NDP_PENDING
    jne .out
    mov rax,[rel ndp_gen]
    cmp rax,[rel nd_generation]
    jne .out                           ; another generation: read as ended by NDPWRSTAT
    cmp dword [rel nd_state],2
    jne .out
    sub rsp,8
    cmp byte [rel ndp_port_wait],1
    jne .deadline
    mov rdi,[rel ndp_gen]
    lea rsi,[rel nd_nonce]
    call nd_power_request
    mov [rel ndp_request_rc],eax
    cmp eax,5
    je .deadline
    mov byte [rel ndp_port_wait],0
    test eax,eax
    jz .deadline
    mov byte [rel ndp_outcome],NDP_LATE
    jmp .final
.deadline:
    call boot_ms_now
    cmp rax,[rel ndp_deadline_ms]
    jb .done
    mov rdi,[rel ndp_gen]
    lea rsi,[rel nd_nonce]
    call nd_stop                       ; exactly one forced stop, never retried
    mov [rel ndp_stop_rc],eax
    mov byte [rel ndp_outcome],NDP_FORCED
    test eax,eax
    jz .final
    mov byte [rel ndp_outcome],NDP_STOPFAIL
.final:
    call boot_ms_now
    mov [rel ndp_end_ms],rax
    mov byte [rel ndp_state],NDP_DONE
.done:
    add rsp,8
.out:
    ret

; Settle a pending job that ended without the tick (the tick never runs after retirement).
; Clean only on VM's three-part rule: nd_state 4, the clean flag for exactly this
; generation, and the flag set. Anything else that is no longer attached is ended.
ndp_settle:
    cmp byte [rel ndp_state],NDP_PENDING
    jne .out
    mov rax,[rel ndp_gen]
    cmp rax,[rel nd_generation]
    jne .ended
    cmp dword [rel nd_state],2
    je .out                            ; still attached: still pending
    cmp dword [rel nd_state],4
    jne .ended
    cmp byte [rel nd_power_clean],1
    jne .ended
    mov rax,[rel ndp_gen]
    cmp rax,[rel nd_power_clean_generation]
    jne .ended
    mov rax,[rel nd_power_clean_ms]    ; 1a's time of the clean retirement
    mov [rel ndp_end_ms],rax
    mov byte [rel ndp_outcome],NDP_CLEAN
    mov byte [rel ndp_state],NDP_DONE
    ret
.ended:
    mov byte [rel ndp_outcome],NDP_ENDED
.final:
    sub rsp,8
    call boot_ms_now
    add rsp,8
    mov [rel ndp_end_ms],rax           ; when native first saw the end, not the guest's own time
    mov byte [rel ndp_state],NDP_DONE
.out:
    ret

; RDI = 24-byte out (owner restart record +232):
;   +0 u32 request rc (NDPR_NO_REQUEST if none), +4 u32 outcome, +8 u64 requested_ms, +16 u64 ended_ms.
; BSP, from nd_restart_run only, with IF set (driver_domain_return_prepare
; refuses to yield otherwise). Yields; never blocks with IF clear, never calls
; nd_stop. Preserves rbx, rbp, r12-r15.
nd_power_restart_step:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,8
    mov rbx,rdi
    mov dword [rbx],NDPR_NO_REQUEST
    mov dword [rbx+4],NDPR_ENDED
    xor eax,eax
    mov [rbx+8],rax
    mov [rbx+16],rax
    mov r12,[rel nd_generation]
    test r12,r12
    jz .out
    cmp dword [rel nd_state],2
    jne .out
    call nd_current
    test eax,eax
    jz .out
    call ndp_settle
    cmp byte [rel ndp_state],NDP_PENDING
    jne .start
    mov dword [rbx+4],NDPR_BUSY        ; never two requests; nd_quiesce forces as before
    jmp .out
.start:
    call boot_ms_now
    test rax,rax
    jz .clock_none
    mov r15,rax                        ; last clock read
    mov [rbx+8],rax
    lea r14,[rax+ND_SHUTDOWN_MS]
    mov ebp,NDPR_TURNS
    mov rdi,r12
    lea rsi,[rel nd_nonce]
    call nd_power_request
    mov [rbx],eax
    test eax,eax
    jz .watch
    cmp eax,5
    jne .refused
.poll:
    cmp dword [rbx],5
    jne .watch
    cmp [rel nd_generation],r12
    jne .watch
    cmp dword [rel nd_state],2
    jne .watch
    mov rdi,r12
    lea rsi,[rel nd_nonce]
    call nd_power_request              ; port not open yet: ask again inside the bound
    mov [rbx],eax
    test eax,eax
    jz .watch
    cmp eax,5
    jne .refused
.watch:
    cmp [rel nd_generation],r12
    jne .ended
    mov eax,[rel nd_state]
    cmp eax,2
    je .wait
    cmp eax,3
    je .wait                           ; a retirement already under way: let it finish
    cmp eax,4
    jne .ended
    movzx eax,byte [rel nd_power_clean]
    cmp eax,1
    jne .ended                         ; retired, but not by the guest's clean exit
    cmp r12,[rel nd_power_clean_generation]
    jne .ended
    mov rax,[rel nd_power_clean_ms]    ; the step's end is 1a's clean time
    cmp rax,[rbx+8]
    jb .ended                          ; clean before this request: not this step's
    cmp rax,r14
    jae .bound                         ; clean, but after the bound: no clean credit
    mov dword [rbx+4],NDPR_CLEAN
    mov [rbx+16],rax
    jmp .out
.wait:
    call boot_ms_now
    cmp rax,r15
    jb .clock
    mov r15,rax
    cmp rax,r14
    jae .bound
    dec ebp
    jz .bound
    call sched_yield
    call boot_ms_now                   ; a yield may cross the bound: reread before any retry or credit
    cmp rax,r15
    jb .clock
    mov r15,rax
    cmp rax,r14
    jb .poll
    jmp .watch                         ; past the bound: never ask again; classify what already happened
.bound:
    mov dword [rbx+4],NDPR_BOUND
    jmp .end_now
.refused:
    mov dword [rbx+4],NDPR_REFUSED
    jmp .end_now
.ended:
    mov dword [rbx+4],NDPR_ENDED
.end_now:
    call boot_ms_now
    cmp rax,r15
    jb .clock
    mov [rbx+16],rax
    jmp .out
.clock:
    mov [rbx+16],r15                   ; last good reading, never before requested_ms
    mov dword [rbx+4],NDPR_CLOCK
    jmp .out
.clock_none:
    mov dword [rbx+4],NDPR_CLOCK
.out:
    add rsp,8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; NDPWRSTAT: NDPWR1 gen=<n> outcome=<word> request=<rc> stop=<rc> queued_ms=<n> end_ms=<n> power_state=<n>
ndp_command_stat:
    push rbx
    push r12
    sub rsp,8
    call cmd_handler_prologue
    mov r12,rsi
    call hv_out_reset
    call ndp_settle
    lea rdi,[rel ndp_stat_head]
    call hv_out_str
    mov rdi,[rel ndp_gen]
    call ndp_num
    lea rdi,[rel ndp_k_outcome]
    call hv_out_str
    movzx eax,byte [rel ndp_outcome]
    cmp eax,NDP_STOPFAIL
    jbe .word
    xor eax,eax
.word:
    lea rcx,[rel ndp_words]
    movsxd rdi,dword [rcx+rax*4]      ; org-0 image: offsets, never absolute pointers
    add rdi,rcx
    call hv_out_str
    lea rdi,[rel ndp_k_request]
    call hv_out_str
    mov edi,[rel ndp_request_rc]
    call ndp_num
    lea rdi,[rel ndp_k_stop]
    call hv_out_str
    mov edi,[rel ndp_stop_rc]
    call ndp_num
    lea rdi,[rel ndp_k_queued]
    call hv_out_str
    mov rdi,[rel ndp_queued_ms]
    call ndp_num
    lea rdi,[rel ndp_k_end]
    call hv_out_str
    mov rdi,[rel ndp_end_ms]
    call ndp_num
    lea rdi,[rel ndp_k_power]
    call hv_out_str
    call nd_power_state
    mov edi,eax
    call ndp_num
    mov byte [rel hv_out_ready],1
    mov qword [r12+RSP_CODE],CMDE_OK
    add rsp,8
    pop r12
    pop rbx
    ret

; RDI = unsigned value -> decimal into the hv_out reply (full 64-bit width).
ndp_num:
    sub rsp,8
    lea rsi,[rel ndp_dec]
    call fmt_dec
    lea rdi,[rel ndp_dec]
    call hv_out_str
    add rsp,8
    ret

ndp_verb_shutdown: db 'NDSHUTDOWN',0
ndp_verb_stat: db 'NDPWRSTAT',0
ndp_queued_text: db 'NDSHUT1 QUEUED ',0
ndp_port_wait_text: db ' PORTWAIT',0
ndp_err_auth: db 'NDSHUT1 ERR auth',0
ndp_err_syntax: db 'NDSHUT1 ERR syntax',0
ndp_err_not_attached: db 'NDSHUT1 ERR not_attached',0
ndp_err_stale: db 'NDSHUT1 ERR stale',0
ndp_err_no_port: db 'NDSHUT1 ERR no_power_port',0
ndp_err_pending: db 'NDSHUT1 ERR pending',0
ndp_stat_head: db 'NDPWR1 gen=',0
ndp_k_outcome: db ' outcome=',0
ndp_k_request: db ' request=',0
ndp_k_stop: db ' stop=',0
ndp_k_queued: db ' queued_ms=',0
ndp_k_end: db ' end_ms=',0
ndp_k_power: db ' power_state=',0
ndp_w_none: db 'none',0
ndp_w_pending: db 'pending',0
ndp_w_clean: db 'clean',0
ndp_w_forced: db 'forced',0
ndp_w_ended: db 'ended',0
ndp_w_late: db 'refused_late',0
ndp_w_stopfail: db 'stop_refused',0
align 4
ndp_words: dd ndp_w_none - ndp_words, ndp_w_pending - ndp_words, ndp_w_clean - ndp_words
           dd ndp_w_forced - ndp_words, ndp_w_ended - ndp_words, ndp_w_late - ndp_words
           dd ndp_w_stopfail - ndp_words

%include "core/abi/wdata.inc"
%macro WDATA_BSS_hv_driver_domain_power 0
alignb 8
ndp_gen: resq 1
ndp_queued_ms: resq 1
ndp_deadline_ms: resq 1
ndp_end_ms: resq 1
ndp_request_rc: resd 1
ndp_stop_rc: resd 1
ndp_state: resb 1
ndp_outcome: resb 1
ndp_port_wait: resb 1
ndp_arg_start: resb 11
ndp_arg_nonce: resb 17
ndp_dec: resb 24
%endmacro
WDATA_BSS_DEFER WDATA_BSS_hv_driver_domain_power
