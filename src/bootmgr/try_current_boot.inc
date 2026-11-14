; Current-boot Try admission. Called in the live Try A/B launch path, not by
; saved host observations. U=0, PASS=1, FAIL=2. Available contradictions dominate; not-a-credential: numeric verdict constants
; unavailable observations. No SetVariable, restart, enrollment or journal I/O.
; Exact DER is a public build input of this authenticated Manager. Media labels,
; filenames, subjects, caller booleans and yesterday's snapshot cannot select it.
%define PBM_TRY_MOK_MAX 1048576

try_current_launch_entry:                ; EDI=actual signed A/B entry
    push rdi
    call try_current_boot_gate
    pop rdi
    cmp eax,1
    je launch_entry
    mov byte [rel fatal_policy_failure],1
    mov eax,1
    ret

try_current_boot_gate:
    push rbx
    push r12
    push r13
    push r14
    mov byte [rel try_current_result],0  ; never reuse a prior invocation
    mov byte [rel try_current_mask],0
    mov qword [rel try_current_protocol],0
    mov qword [rel try_current_mok],0
    mov byte [rel try_current_end],0
    mov dword [rel try_current_total],0
    ; Read ALL available flags. An unreadable SecureBoot must not mask an
    ; observed SetupMode=1 or MokSBStateRT=1 contradiction.
    lea rcx,[rel try_name_secureboot]
    lea rdx,[rel try_global_guid]
    call try_current_flag
    cmp edx,1
    jne .sb_unknown
    cmp al,1
    je .setup
    or byte [rel try_current_mask],2
    jmp .setup
.sb_unknown:
    or byte [rel try_current_mask],1
.setup:
    lea rcx,[rel try_name_setupmode]
    lea rdx,[rel try_global_guid]
    call try_current_flag
    cmp edx,1
    jne .setup_unknown
    test al,al
    jz .shim_state
    or byte [rel try_current_mask],2
    jmp .shim_state
.setup_unknown:
    or byte [rel try_current_mask],1
.shim_state:
    lea rcx,[rel try_name_shimstate]
    lea rdx,[rel try_shim_guid]
    call try_current_flag
    cmp edx,2                         ; observed EFI_NOT_FOUND is normal shim secure mode
    je .mok
    test edx,edx
    jz .shim_unknown
    test al,al
    jz .mok
    or byte [rel try_current_mask],2
    jmp .mok
.shim_unknown:
    or byte [rel try_current_mask],1
.mok:
%ifdef PBM_TRY_CERT
    call try_current_mok_read
    cmp eax,1
    je .chain
    cmp eax,2
    jne .mok_unknown
    or byte [rel try_current_mask],2
    jmp .chain
.mok_unknown:
%endif
    or byte [rel try_current_mask],1
.chain:
    ; SB=1 alone says nothing about shim's validation policy. Locate the actual
    ; current protocol and exercise it on a structurally valid unsigned PE.
    ; shim15.8 shim_verify parses/hashes first, returns SUCCESS in insecure mode,
    ; and SECURITY_VIOLATION for a valid unsigned, non-allowlisted image in
    ; secure mode. Other errors do NOT establish enforcement (U).
    mov rax,[rel boot_services]
    test rax,rax
    jz .chain_unknown
    lea rcx,[rel try_shim_guid]
    xor edx,edx
    lea r8,[rel try_current_protocol]
    PBM_FW_ENTER 32
    call [rax + 0x140]                 ; LocateProtocol
    PBM_FW_LEAVE 32
    test rax,rax
    jnz .chain_unknown
    mov rbx,[rel try_current_protocol]
    test rbx,rbx
    jz .chain_unknown
    cmp qword [rbx],0
    je .chain_unknown
    ; SHIM_LOCK.Verify is SysV x64, NOT EFIAPI (shim.h15.8 typedef has no
    ; EFIAPI). Keep stack aligned; RDI/ESI carry buffer/UINT32 size.
    lea rdi,[rel try_unsigned_probe]
    mov esi,try_unsigned_probe_end - try_unsigned_probe
    PBM_FW_ENTER 32
    call [rbx]
    PBM_FW_LEAVE 32
    test rax,rax
    jz .chain_disabled
    mov rdx,0x800000000000001A        ; only actual EFI_SECURITY_VIOLATION qualifies
    cmp rax,rdx
    je .finish
.chain_unknown:
    or byte [rel try_current_mask],1
    jmp .finish
.chain_disabled:
    or byte [rel try_current_mask],2
.finish:
    mov ebx,1
    test byte [rel try_current_mask],2
    jnz .fail
    test byte [rel try_current_mask],1
    jz .pass
    xor ebx,ebx
    lea rdi,[rel str_try_current_unknown]
    jmp .emit
.fail:
    mov ebx,2
    lea rdi,[rel str_try_current_fail]
    jmp .emit
.pass:
    lea rdi,[rel str_try_current_pass]
.emit:
    mov [rel try_current_result],bl
    call serial_string
    mov eax,ebx
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; RCX=CHAR16 name RDX=guid -> AL byte; EDX=1 exact byte,2 observed
; EFI_NOT_FOUND,0 unreadable/malformed. All scratch reset for each call.
try_current_flag:
    mov qword [rel try_current_size],1
    mov byte [rel try_current_byte],0xFF
    mov dword [rel try_current_attrs],0
    mov rax,[rel runtime_services]
    test rax,rax
    jz .unknown
    lea r8,[rel try_current_attrs]
    lea r9,[rel try_current_size]
    PBM_FW_ENTER 40
    lea r10,[rel try_current_byte]
    mov [rsp + 32],r10
    call [rax + 0x48]
    PBM_FW_LEAVE 40
    test rax,rax
    jnz .error
    cmp qword [rel try_current_size],1
    jne .unknown
    movzx eax,byte [rel try_current_byte]
    mov edx,1
    ret
.error:
    mov rdx,0x800000000000000E
    cmp rax,rdx
    jne .unknown
    mov edx,2
    mov eax,0xFF
    ret
.unknown:
    xor edx,edx
    mov eax,0xFF
    ret

%ifdef PBM_TRY_CERT
; Gather MokListRT + continuations1..15 in one bounded private pool. Only exact
; X509 DER qualifies. Observed end + well-formed complete list without the
; selected cert is FAIL; absent base/unreadable/oversize/malformed/limit is U.
try_current_mok_read:
    push rbx
    push r12
    push r13
    mov rax,[rel boot_services]
    test rax,rax
    jz .unknown
    cmp qword [rel runtime_services],0
    je .unknown
    mov ecx,2
    mov edx,PBM_TRY_MOK_MAX
    lea r8,[rel try_current_mok]
    PBM_FW_ENTER 32
    call [rax + 0x40]
    PBM_FW_LEAVE 32
    test rax,rax
    jnz .unknown
    cmp qword [rel try_current_mok],0
    je .unknown
    xor ebx,ebx
.next:
    ; Writable CHAR16 suffix reset, base name never inherited from prior read.
    mov dword [rel try_name_mok + 18],0
    mov word [rel try_name_mok + 22],0
    test ebx,ebx
    jz .named
    mov eax,ebx
    cmp eax,10
    jb .one_digit
    mov word [rel try_name_mok + 18],'1'
    sub eax,10
    add eax,'0'
    mov [rel try_name_mok + 20],ax
    jmp .named
.one_digit:
    add eax,'0'
    mov [rel try_name_mok + 18],ax
.named:
    mov r12d,PBM_TRY_MOK_MAX
    sub r12d,[rel try_current_total]
    jz .free_unknown
    cmp r12d,65536
    jbe .bounded
    mov r12d,65536
.bounded:
    mov [rel try_current_size],r12
    mov dword [rel try_current_attrs],0
    mov rax,[rel runtime_services]
    lea rcx,[rel try_name_mok]
    lea rdx,[rel try_shim_guid]
    lea r8,[rel try_current_attrs]
    lea r9,[rel try_current_size]
    mov r13,[rel try_current_mok]
    mov edx,[rel try_current_total]
    add r13,rdx
    lea rdx,[rel try_shim_guid]
    PBM_FW_ENTER 40
    mov [rsp + 32],r13
    call [rax + 0x48]
    PBM_FW_LEAVE 40
    test rax,rax
    jnz .error
    mov rax,[rel try_current_size]
    test rax,rax
    jz .free_unknown
    cmp rax,r12
    ja .free_unknown
    mov edx,[rel try_current_attrs]
    and edx,7
    cmp edx,6                         ; shim mirrors are volatile BS+RT
    jne .free_unknown
    add [rel try_current_total],eax
    inc ebx
    cmp ebx,15
    jbe .next
    jmp .parse                        ; limit can prove presence, never absence
.error:
    mov rdx,0x800000000000000E
    cmp rax,rdx
    jne .free_unknown
    test ebx,ebx
    jz .free_unknown                  ; absent base is not proof of non-enrollment
    mov byte [rel try_current_end],1
.parse:
    mov rdi,[rel try_current_mok]
    mov esi,[rel try_current_total]
    call try_current_esl
    test eax,eax
    jnz .free_result                  ; 1 exact present,0 malformed/not found
    cmp byte [rel try_current_end],1
    jne .free_unknown
    ; parser distinguishes complete absence (2) from malformed (0)
    jmp .free_unknown
.free_unknown:
    xor eax,eax
.free_result:
    mov ebx,eax
    mov rcx,[rel try_current_mok]
    mov rax,[rel boot_services]
    PBM_FW_ENTER 32
    call [rax + 0x48]
    PBM_FW_LEAVE 32
    mov qword [rel try_current_mok],0
    mov eax,ebx
    jmp .done
.unknown:
    xor eax,eax
.done:
    pop r13
    pop r12
    pop rbx
    ret

; RDI=ESL bytes ESI=size. Bounded full parse: 1 exact DER present,2 absent
; with observed continuation end,0 malformed/incomplete/unknown. Never subject.
try_current_esl:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12,rdi
    mov r13d,esi
    xor r14d,r14d                    ; found flag; still validate remaining tail
.list:
    test r13,r13
    jz .complete
    cmp r13,28
    jb .unknown
    mov ebx,[r12 + 16]               ; SignatureListSize
    cmp ebx,28
    jb .unknown
    cmp rbx,r13
    ja .unknown
    mov r15d,[r12 + 20]              ; SignatureHeaderSize
    add r15,28
    cmp r15,rbx
    ja .unknown
    mov ecx,[r12 + 24]               ; SignatureSize includes owner GUID
    cmp ecx,16
    jbe .unknown
    mov rax,rbx
    sub rax,r15
    xor edx,edx
    div rcx
    test rdx,rdx
    jnz .unknown
    ; Exact EFI_CERT_X509_GUID, never hash or same-subject certificates.
    mov rax,[rel try_x509_guid]
    cmp [r12],rax
    jne .advance
    mov rax,[rel try_x509_guid + 8]
    cmp [r12 + 8],rax
    jne .advance
    cmp ecx,try_selected_der_end - try_selected_der + 16
    jne .advance
.entry:
    cmp r15,rbx
    jae .advance
    lea rdi,[r12 + r15 + 16]
    lea rsi,[rel try_selected_der]
    mov edx,try_selected_der_end - try_selected_der
    call pbm_bytes_differ
    test eax,eax
    jnz .next_entry
    mov r14d,1
.next_entry:
    add r15,try_selected_der_end - try_selected_der + 16
    jmp .entry
.advance:
    add r12,rbx
    sub r13,rbx
    jmp .list
.complete:
    mov eax,1
    test r14d,r14d
    jnz .done
    xor eax,eax
    cmp byte [rel try_current_end],1
    jne .done
    mov eax,2
    jmp .done
.unknown:
    xor eax,eax
.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
%endif

try_current_handoff:
%ifdef PBM_TRY_CERT
    cmp byte [rel try_media_boot],1
    jne .done
    cmp byte [rel try_current_result],1
    jne .done
    mov word [rel handoff + PBM_HANDOFF_TRY_TRUST_OFF],PBM_HANDOFF_TRY_TRUST_TAG
    lea rsi,[rel try_selected_sha]
    lea rdi,[rel handoff + PBM_HANDOFF_TRY_CERT_OFF]
    mov ecx,4
    rep movsq
.done:
%endif
    ret

%macro PBM_TRY_CURRENT_DATA 0
align 8
try_current_size: dq 0
try_current_protocol: dq 0
try_current_mok: dq 0
try_current_total: dd 0
try_current_attrs: dd 0
try_current_result: db 0
try_current_mask: db 0
try_current_end: db 0
try_current_byte: db 0
try_name_mok: dw 'M','o','k','L','i','s','t','R','T',0,0,0
%endmacro

%macro PBM_TRY_CURRENT_RDATA 0
%ifdef PBM_TRY_CERT
%include "pbm-try-cert.inc"
%endif
try_global_guid:
    dd 0x8BE4DF61
    dw 0x93CA,0x11D2
    db 0xAA,0x0D,0,0xE0,0x98,3,0x2B,0x8C
try_shim_guid:
    dd 0x605DAB50
    dw 0xE046,0x4300
    db 0xAB,0xB6,0x3D,0xD8,0x10,0xDD,0x8B,0x23
try_x509_guid:
    dd 0xA5C059A1
    dw 0x94E4,0x4AA7
    db 0x87,0xB5,0xAB,0x15,0x5C,0x2B,0xF0,0x72
try_name_secureboot: dw 'S','e','c','u','r','e','B','o','o','t',0
try_name_setupmode: dw 'S','e','t','u','p','M','o','d','e',0
try_name_shimstate: dw 'M','o','k','S','B','S','t','a','t','e','R','T',0
str_try_current_pass: db '[PBM] current boot: exact selected DER enrolled, Secure Boot and shim enforcement observed [boot.v2.try.trust.pass]',13,10,0
str_try_current_fail: db '[PBM] Try refused: current trust contradiction; return to existing OS, owner may correct and retry manually [boot.v2.try.trust.fail]',13,10,0
str_try_current_unknown: db '[PBM] Try unavailable: current enrollment or enforced chain unobserved; return to existing OS, retry manually [boot.v2.try.trust.unknown]',13,10,0
; Valid unsigned PE32+ EFI application, one RX section. Never loaded/executed.
; Rejection is a live enforcement probe; acceptance (including allowlisted
; hash) refuses conservatively. Header/TPM/protocol errors remain U.
align 8
try_unsigned_probe:
    db 'M','Z'
    times 0x3C-($-try_unsigned_probe) db 0
    dd 0x80
    times 0x80-($-try_unsigned_probe) db 0
    db 'P','E',0,0
    dw 0x8664,1
    dd 0,0,0
    dw 240,0x22
    dw 0x20B
    db 0,0
    dd 512,0,0,0x1000,0x1000
    dq 0x100000
    dd 4096,512
    dw 0,0,0,0,2,0
    dd 0,0x2000,512,0
    dw 10,0
    dq 0x100000,0x1000,0x100000,0x1000
    dd 0,16
    times 16 dq 0
    db '.text',0,0,0
    dd 1,0x1000,512,512,0,0
    dw 0,0
    dd 0x60000020
    times 512-($-try_unsigned_probe) db 0
    db 0xC3
    times 1024-($-try_unsigned_probe) db 0
try_unsigned_probe_end:
%endmacro
