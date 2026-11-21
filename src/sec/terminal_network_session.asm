;; MODULE sec/terminal_network_session
;; LAYER 6
;; PURPOSE Bounded native TLS staging and endpoint/policy lifetime core.
;; EXPORTS terminal_network_session_configure, terminal_network_session_open, terminal_network_session_stage, terminal_network_session_copy, terminal_network_session_advance, terminal_network_session_current, terminal_network_session_close, terminal_network_session_tick, terminal_network_session_phase, terminal_network_selected_peer
;; IMPORTS sec/terminal_network_gate, svc/command, core/smp, core/time
;; OWNER saga:terminal_network
;; CONTEXT: bsp_only
;
; This core has NO wire/device/verb entry, DNS, TCP, DATA or Settings binding.
; Native callbacks are installed once by trusted initialization, never by a
; request. NULL/default configuration refuses. A tools integration must supply
; its actual snapshot/currentness and authenticated policy; a snapshot creates
; no authority. Callers own stable, mapped, mutually disjoint native spans.
;
; configure(RDI native3q): snapshot(out128,128)->1 only for actual running tools;
; current(original128)->1 only for same current tools/local owner/session;
; policy(canonical host,len)->nonzero revision only if currently authorized.
; Callbacks preserve SysV callee-saved regs, do not yield, and retain no spans.
; They are NOT registered app/guest operations. No fabricated snapshot fallback.
TNSN_ID equ 0
TNSN_PHASE equ 8
TNSN_HOSTLEN equ 12
TNSN_POLICY equ 16
TNSN_DEADLINE equ 24
TNSN_LEN equ 32
TNSN_OFF equ 36
TNSN_OFFERED equ 40
TNSN_SNAPSHOT equ 48
TNSN_HOST equ 176
TNSN_WIRE equ 432
TNSN_SCRATCH equ 16816
TNSN_SIZE equ 33200
TNSN_COUNT equ 4
TNSN_STAGING equ 1
TNSN_READY equ 2
TNSN_STREAM equ 3
TNSN_LIMIT equ 16384
TNSN_TIMEOUT equ 10000000

%macro TNSN_CALL 1
    sub rsp,8
    call %1
    add rsp,8
%endmacro

sn_local:
    cmp byte [rel cmd_in_dispatch],0
    jne .no
    cmp dword [rel cmd_dispatch_depth],0
    jne .no
    cmp byte [rel command_auth_remote_active],0
    jne .no
    TNSN_CALL smp_current_logical
    test eax,eax
    setz al
    movzx eax,al
    ret
.no:
    xor eax,eax
    ret

terminal_network_session_configure:
    push rbx
    mov rbx,rdi
    call sn_local
    test eax,eax
    jz .no
    test rbx,rbx
    jz .no
    cmp qword [rel sn_callbacks],0
    jne .no                            ; immutable after successful init
    cmp qword [rbx],0
    je .no
    cmp qword [rbx+8],0
    je .no
    cmp qword [rbx+16],0
    je .no
    lea rdi,[rel sn_callbacks]
    mov rsi,rbx
    mov ecx,3
    cld
    rep movsq
    mov eax,1
    pop rbx
    ret
.no:
    xor eax,eax
    pop rbx
    ret

; RDI nonzero native-generated handle -> RAX slot or0. No guest identity input.
sn_find:
    test rdi,rdi
    jz .no
    lea rax,[rel sn_slots]
    mov ecx,TNSN_COUNT
.next:
    cmp rdi,[rax+TNSN_ID]
    je .out
    add rax,TNSN_SIZE
    loop .next
.no:
    xor eax,eax
.out:
    ret

; RBX slot. Before every staging/copy/acceptance effect and on native tick.
sn_current:
    sub rsp,8
    call sn_local
    test eax,eax
    jz .no
    lea rdi,[rbx+TNSN_SNAPSHOT]
    call [rel sn_callbacks+8]
    cmp eax,1
    jne .no
    lea rdi,[rbx+TNSN_HOST]
    mov esi,[rbx+TNSN_HOSTLEN]
    call [rel sn_callbacks+16]
    test rax,rax
    jz .no
    cmp rax,[rbx+TNSN_POLICY]
    jne .no
    call time_monotonic_now_us
    test rax,rax
    jz .no
    cmp dword [rbx+TNSN_PHASE],TNSN_STREAM
    je .yes
    cmp rax,[rbx+TNSN_DEADLINE]
    jae .no
.yes:
    mov eax,1
    jmp .out
.no:
    xor eax,eax
.out:
    add rsp,8
    ret

sn_clear:
    mov rdi,rbx
    mov ecx,TNSN_SIZE
    xor eax,eax
    cld
    rep stosb
    ret

; open(RDI host,ESI explicit length,EDX port443)->RAX monotonic handle or0.
; No DNS/allocation/network effect is performed by this core.
terminal_network_session_open:
    push rbx
    push r12
    push r13
    mov r12,rdi
    mov r13d,esi
    cmp edx,443
    jne .no
    call sn_local
    test eax,eax
    jz .no
    cmp qword [rel sn_callbacks],0
    je .no
    cmp qword [rel sn_serial],-1
    je .no
    lea rbx,[rel sn_slots]
    mov ecx,TNSN_COUNT
.free:
    cmp qword [rbx+TNSN_ID],0
    je .slot
    add rbx,TNSN_SIZE
    loop .free
    jmp .no
.slot:
    lea rdi,[rbx+TNSN_HOST]
    mov rsi,r12
    mov edx,r13d
    call terminal_network_host_canon
    test eax,eax
    js .drop
    mov [rbx+TNSN_HOSTLEN],eax
    lea rdi,[rbx+TNSN_SNAPSHOT]
    mov esi,128
    call [rel sn_callbacks]
    cmp eax,1
    jne .drop
    lea rdi,[rbx+TNSN_HOST]
    mov esi,[rbx+TNSN_HOSTLEN]
    call [rel sn_callbacks+16]
    test rax,rax
    jz .drop
    mov [rbx+TNSN_POLICY],rax
    call time_monotonic_now_us
    test rax,rax
    jz .drop
    add rax,TNSN_TIMEOUT
    jc .drop
    mov [rbx+TNSN_DEADLINE],rax
    call sn_current
    test eax,eax
    jz .drop
    inc qword [rel sn_serial]
    mov rax,[rel sn_serial]
    mov [rbx+TNSN_ID],rax
    mov dword [rbx+TNSN_PHASE],TNSN_STAGING
    jmp .out
.drop:
    call sn_clear
.no:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

; stage(handle,native bytes,len1..1024)->EAX admitted length or-1. Entire
; fragment is owned or refused. No wire prefix escapes before exact SNI.
terminal_network_session_stage:
    push rbx
    push r12
    push r13
    mov r12,rsi
    mov r13d,edx
    mov rbx,rdi
    call sn_local
    test eax,eax
    jz .no
    mov rdi,rbx
    call sn_find
    test rax,rax
    jz .no
    mov rbx,rax
    call sn_current
    test eax,eax
    jz .drop
    cmp dword [rbx+TNSN_PHASE],TNSN_STAGING
    jne .no
    test r12,r12
    jz .drop
    test r13d,r13d
    jz .drop
    cmp r13d,1024
    ja .drop
    mov eax,[rbx+TNSN_LEN]
    add eax,r13d
    cmp eax,TNSN_LIMIT
    ja .drop
    mov ecx,r13d
    lea rdi,[rbx+TNSN_WIRE]
    mov eax,[rbx+TNSN_LEN]
    add rdi,rax
    mov rsi,r12
    cld
    rep movsb
    add [rbx+TNSN_LEN],r13d
    lea rdi,[rbx+TNSN_HOST]
    mov esi,[rbx+TNSN_HOSTLEN]
    lea rdx,[rbx+TNSN_WIRE]
    mov ecx,[rbx+TNSN_LEN]
    lea r8,[rbx+TNSN_SCRATCH]
    call terminal_network_clienthello
    mov r12d,eax
    ; The parser's reassembly scratch is secret even for incomplete input.
    lea rdi,[rbx+TNSN_SCRATCH]
    mov ecx,TNSN_LIMIT
    xor eax,eax
    rep stosb
    test r12d,r12d
    js .drop
    jz .check
    mov dword [rbx+TNSN_PHASE],TNSN_READY
.check:
    call sn_current
    test eax,eax
    jz .drop
    mov eax,r13d
    jmp .out
.drop:
    call sn_clear
.no:
    mov eax,-1
.out:
    pop r13
    pop r12
    pop rbx
    ret

; copy(handle,native owned output,cap1..1024)->EAX bytes or-1. This is native
; TCP staging, NOT guest copyout. Repeated peek does not consume. Actual TCP
; acceptance must call advance exactly once; uncertain effects are not replayed.
terminal_network_session_copy:
    push rbx
    push r12
    push r13
    mov r12,rsi
    mov r13d,edx
    mov rbx,rdi
    call sn_local
    test eax,eax
    jz .no
    mov rdi,rbx
    call sn_find
    test rax,rax
    jz .no
    mov rbx,rax
    call sn_current
    test eax,eax
    jz .drop
    cmp dword [rbx+TNSN_PHASE],TNSN_READY
    jne .no
    test r12,r12
    jz .no
    test r13d,r13d
    jz .no
    cmp r13d,1024
    ja .no
    mov eax,[rbx+TNSN_LEN]
    sub eax,[rbx+TNSN_OFF]
    cmp r13d,eax
    cmova r13d,eax
    lea rsi,[rbx+TNSN_WIRE]
    mov eax,[rbx+TNSN_OFF]
    add rsi,rax
    mov rdi,r12
    mov ecx,r13d
    cld
    rep movsb
    call sn_current                    ; failed final check leaves no copyout
    test eax,eax
    jnz .copied
    mov rdi,r12
    mov ecx,r13d
    xor eax,eax
    rep stosb
    jmp .drop
.copied:
    mov [rbx+TNSN_OFFERED],r13d
    mov eax,r13d
    jmp .out
.drop:
    call sn_clear
.no:
    mov eax,-1
.out:
    pop r13
    pop r12
    pop rbx
    ret

; advance(handle,ESI bytes actually accepted by original owned TCP operation).
; Never registered as a device request; a guest cannot assert TCP acceptance.
terminal_network_session_advance:
    push rbx
    push r12
    sub rsp,8
    mov r12d,esi
    mov rbx,rdi
    call sn_local
    test eax,eax
    jz .no
    mov rdi,rbx
    call sn_find
    test rax,rax
    jz .no
    mov rbx,rax
    call sn_current
    test eax,eax
    jz .drop
    cmp dword [rbx+TNSN_PHASE],TNSN_READY
    jne .no
    test r12d,r12d
    jz .no
    cmp r12d,[rbx+TNSN_OFFERED]
    ja .no
    lea rdi,[rbx+TNSN_WIRE]
    mov eax,[rbx+TNSN_OFF]
    add rdi,rax
    mov ecx,r12d
    xor eax,eax
    cld
    rep stosb
    add [rbx+TNSN_OFF],r12d
    mov dword [rbx+TNSN_OFFERED],0
    mov eax,[rbx+TNSN_OFF]
    cmp eax,[rbx+TNSN_LEN]
    jne .yes
    mov dword [rbx+TNSN_PHASE],TNSN_STREAM
.yes:
    mov eax,1
    jmp .out
.drop:
    call sn_clear
.no:
    xor eax,eax
.out:
    add rsp,8
    pop r12
    pop rbx
    ret

terminal_network_session_current:
    push rbx
    mov rbx,rdi
    call sn_local
    test eax,eax
    jz .out
    mov rdi,rbx
    call sn_find
    test rax,rax
    jz .out
    mov rbx,rax
    call sn_current
    test eax,eax
    jnz .out
    call sn_clear
.out:
    pop rbx
    ret

; Native fresh state only, no pointer or snapshot disclosure.
terminal_network_session_phase:
    push rbx
    mov rbx,rdi
    call terminal_network_session_current
    test eax,eax
    jz .out
    mov rdi,rbx
    call sn_find
    mov eax,[rax+TNSN_PHASE]
.out:
    pop rbx
    ret

terminal_network_session_close:
    push rbx
    mov rbx,rdi
    call sn_local
    test eax,eax
    jz .out
    mov rdi,rbx
    call sn_find
    test rax,rax
    jz .out
    mov rbx,rax
    call sn_clear
    mov eax,1
.out:
    pop rbx
    ret

terminal_network_session_tick:
    push rbx
    push r12
    sub rsp,8
    call sn_local
    test eax,eax
    jz .out
    lea rbx,[rel sn_slots]
    mov r12d,TNSN_COUNT
.next:
    cmp qword [rbx+TNSN_ID],0
    je .skip
    call sn_current
    test eax,eax
    jnz .skip
    call sn_clear
.skip:
    add rbx,TNSN_SIZE
    dec r12d
    jnz .next
.out:
    add rsp,8
    pop r12
    pop rbx
    ret

; A selected wire route, unlike the shared classifier's class-only preflight,
; must supply actual nonzero source AND mask. Never authorize on zero-source.
%include "hv/guest_destination.inc"
terminal_network_selected_peer:
    test edx,edx
    jz .no
    test ecx,ecx
    jz .no
    HV_GUEST_PUBLIC_IP
.no:
    xor eax,eax
    ret

%include "core/abi/wdata.inc"
%macro WDATA_BSS_sec_terminal_network_session 0
alignb 8
sn_callbacks: resq 3
sn_serial: resq 1
sn_slots: resb TNSN_SIZE*TNSN_COUNT
%endmacro
WDATA_BSS_DEFER WDATA_BSS_sec_terminal_network_session
