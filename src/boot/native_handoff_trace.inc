; Default-off, bounded diagnostic observations. Never read by boot policy.
; Shared explicit nonzero 64-bit nonce binds the diagnostic composition only;
; PBH1 attempt nonce/state/sequence/hash bind the parent record to a launch.
; Best effort SetVariable may itself perturb or fail/nonreturn: absence never
; locates a stop. No readback, erase, retry, health or authorization side effect.
%ifndef PAOS_NATIVE_HANDOFF_TRACE_INCLUDED
%define PAOS_NATIVE_HANDOFF_TRACE_INCLUDED 1
%ifdef PAOS_NATIVE_TRACE_NONCE
%if PAOS_NATIVE_TRACE_NONCE = 0
%error "native trace requires a nonzero 64-bit nonce"
%endif
%endif
%macro PAOS_NATIVE_TRACE 1
%ifdef PAOS_NATIVE_TRACE_NONCE
    pushfq
    push rax
    mov eax,%1
    call native_trace_mark
    pop rax
    popfq
%endif
%endmacro
; New observations retain the existing PNHFD001/PNEFD001 raw meanings.
; Phase 3 is an INTERNAL request for a version-2 PAX1 intent (wire phase 1).
; It is emitted only at the actual bridge, after its refusal checks.
%macro PAOS_NATIVE_PROGRESS 1
%ifdef PAOS_NATIVE_TRACE_NONCE
    pushfq
    push rax
    mov eax,%1
    call native_progress_mark
    pop rax
    popfq
%endif
%endmacro
; Called only where the existing native validator has accepted R12. Do not
; invent/reconstruct an expected PBH1, or change its acceptance policy.
%macro PAOS_NATIVE_ACCEPT_HANDOFF 1
%ifdef PAOS_NATIVE_TRACE_NONCE
    pushfq
    push rcx
    push rsi
    push rdi
    cld
    mov rsi,%1
    lea rdi,[rel native_progress_handoff]
    mov ecx,16
    rep movsq
    mov qword [rel native_progress_accepted],1
    pop rdi
    pop rsi
    pop rcx
    popfq
    PAOS_NATIVE_PROGRESS 3
%endif
%endmacro
; Emit in a code region, after the entrypoint. 1=parent, 0=native child.
%macro PAOS_NATIVE_TRACE_CODE 1
%ifdef PAOS_NATIVE_TRACE_NONCE
native_trace_mark:
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
    sub rsp,512                   ; home+arg5, record, XMM0..15, MXCSR
%assign nt_x 0
%rep 16
    movdqu [rsp+240+nt_x*16],xmm %+ nt_x
%assign nt_x nt_x+1
%endrep
    stmxcsr [rsp+496]
    cld
    mov r12d,eax                  ; phase; caller's original RAX at RBP+16
    mov rbx,[rel runtime_services]
    test rbx,rbx
    jz %%out
    cmp qword [rbx+0x58],0
    je %%out
%if %1 = 1
    cmp r15d,PBM_ENTRY_PAOS_A
    jb %%out
    cmp r15d,PBM_ENTRY_PAOS_B
    ja %%out
    cmp byte [rel handoff+PBM_HANDOFF_ENTRY_OFF],r15b
    jne %%out
    test byte [rel handoff+PBM_HANDOFF_FLAGS_OFF],PBM_HF_MUTABLE_ATTEMPT
    jz %%out
    cmp qword [rel handoff+PBM_HANDOFF_ATTEMPT_NONCE_OFF],0
    je %%out
%else
    mov rax,[rel system_table]
    test rax,rax
    jz %%out
    mov rdx,0x5453595320494249     ; EFI_SYSTEM_TABLE_SIGNATURE
    cmp [rax],rdx
    jne %%out
%endif
    lea rdi,[rsp+48]
    xor eax,eax
    mov ecx,24
    rep stosq
    lea r13,[rsp+48]
%if %1 = 1
    mov rax,0x3130304446484e50     ; PNHFD001: legacy StartImage only
    cmp r12d,3
    jne %%parent_magic
%ifdef PBM_FEATURE_MANIFEST
    cmp qword [rel pax1_child_handle],0
    je %%out
    cmp qword [rel pax1_entry_address],0
    je %%out
    mov rax,0x3230304446484e50     ; PNHFD002: PAX1 direct intent only
%else
    jmp %%out
%endif
%%parent_magic:
%else
    mov rax,0x3130304446454e50     ; PNEFD001
%endif
    mov [r13],rax
    mov rax,PAOS_NATIVE_TRACE_NONCE
    mov [r13+8],rax
    mov [r13+16],r12
%if %1 = 1
    cmp r12d,3
    jne %%legacy_parent
%ifdef PBM_FEATURE_MANIFEST
    mov qword [r13+16],1          ; intent, never a returned child status
    mov qword [r13+24],-1
    mov rax,[rel pax1_child_handle]
    mov [r13+32],rax
    mov rax,[rel pax1_entry_address]
    mov [r13+40],rax
    jmp %%parent_handoff
%endif
%%legacy_parent:
    mov rax,-1
    cmp r12d,1
    je %%status
    mov rax,[rbp+16]              ; full returned EFI_STATUS, never truncated
%%status:
    mov [r13+24],rax
    mov rax,[rel child_image]
    mov [r13+32],rax
%%parent_handoff:
    lea rsi,[rel handoff]
    lea rdi,[r13+48]
    mov ecx,16
    rep movsq                    ; exact already-validated 128-byte PBH1
%else
    mov rax,[rel image_handle]
    mov [r13+24],rax
    lea rsi,[rel paos_build_measured]
    lea rdi,[r13+32]
    mov ecx,4
    rep movsq                    ; independently measured D, not Manager claim
%endif
    lea rcx,[rel native_trace_name]
    lea rdx,[rel native_trace_guid]
    mov r8d,7                    ; PaOS namespace: NV|BS|RT
%if %1 = 1
    mov r9d,192
%else
    mov r9d,96
%endif
    mov [rsp+32],r13
    call [rbx+0x58]              ; one SetVariable; status intentionally ignored
%%out:
    ldmxcsr [rsp+496]
%assign nt_x 0
%rep 16
    movdqu xmm %+ nt_x,[rsp+240+nt_x*16]
%assign nt_x nt_x+1
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
align 2
native_trace_name:
%if %1 = 1
    dw 'P','a','O','S','N','a','t','i','v','e','H','a','n','d','o','f','f',0
%else
    dw 'P','a','O','S','N','a','t','i','v','e','E','n','t','r','y',0
%endif
native_trace_guid:
    dd 0xd9e0b7ac
    dw 0x86c9,0x481b
    db 0x97,0xdd,0x35,0x5f,0x57,0xb0,0xc2,0x63
%if %1 = 0
    PAOS_NATIVE_PROGRESS_CODE
%endif
%endif
%endmacro
%include "boot/native_progress_trace.inc"
%endif
