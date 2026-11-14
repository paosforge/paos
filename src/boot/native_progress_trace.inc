; Native pre-EBS progress, default-off under the existing composition nonce.
; PNPFD002,224B: nonce8,phase16,handle24,measuredD32,acceptedPBH1[128]64,
; accepted flag192, full watchdog status200,TSC208,reserved zero216.
; 2=watchdog CALL returned (not success);3=validator accepted;4=pre-EBS path
; about to start (before memory-map/allocation/EBS work). Only phase3/4 bind
; the handoff. Later writes overwrite earlier progress, never early Entry.
; All are best effort positive lower bounds; persist-then-nonreturn remains
; possible. No call after EBS/child return, no readback/retry/policy consumer.
%macro PAOS_NATIVE_PROGRESS_CODE 0
%ifdef PAOS_NATIVE_TRACE_NONCE
native_progress_mark:
    push rbp
    mov rbp,rsp
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
    and rsp,-16
    sub rsp,560
%assign np_x 0
%rep 16
    movdqu [rsp+288+np_x*16],xmm %+ np_x
%assign np_x np_x+1
%endrep
    stmxcsr [rsp+544]
    cld
    mov r12d,eax
    cmp r12d,2
    jb %%out
    cmp r12d,4
    ja %%out
    cmp r12d,2
    je %%phase_ok
    cmp qword [rel native_progress_accepted],1
    jne %%out
%%phase_ok:
    mov rax,[rel system_table]
    test rax,rax
    jz %%out
    mov rdx,0x5453595320494249
    cmp [rax],rdx
    jne %%out
    mov rbx,[rel runtime_services]
    test rbx,rbx
    jz %%out
    cmp qword [rbx+0x58],0
    je %%out
    lea rdi,[rsp+48]
    xor eax,eax
    mov ecx,28
    rep stosq
    lea r13,[rsp+48]
    mov rax,0x3230304446504e50    ; PNPFD002
    mov [r13],rax
    mov rax,PAOS_NATIVE_TRACE_NONCE
    mov [r13+8],rax
    mov [r13+16],r12
    mov rax,[rel image_handle]
    mov [r13+24],rax
    lea rsi,[rel paos_build_measured]
    lea rdi,[r13+32]
    mov ecx,4
    rep movsq
    cmp r12d,2
    je %%unbound
    lea rsi,[rel native_progress_handoff]
    lea rdi,[r13+64]
    mov ecx,16
    rep movsq
    mov qword [r13+192],1
%%unbound:
    mov rax,[rel preebs_wdt_status] ; not interpreted as success by the marker
    mov [r13+200],rax
    lfence
    rdtsc
    shl rdx,32
    or rax,rdx
    mov [r13+208],rax
    lea rcx,[rel native_progress_name]
    lea rdx,[rel native_trace_guid]
    mov r8d,7
    mov r9d,224
    mov [rsp+32],r13
    call [rbx+0x58]
%%out:
    ldmxcsr [rsp+544]
%assign np_x 0
%rep 16
    movdqu xmm %+ np_x,[rsp+288+np_x*16]
%assign np_x np_x+1
%endrep
    lea rsp,[rbp-104]
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
    pop rbp
    ret
align 8
native_progress_accepted: dq 0
native_progress_handoff: times 128 db 0
align 2
native_progress_name:
    dw 'P','a','O','S','N','a','t','i','v','e','P','r','o','g','r','e','s','s',0
%endif
%endmacro
