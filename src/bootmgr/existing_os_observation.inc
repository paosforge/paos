; Non-authoritative external launch observation. Never read by boot policy.
; PXOS0001, 128-byte header followed by the exact LoadImage device path.
; A successful write records intent AFTER verification/LoadImage/attempt commit;
; only an independently fresh OS boot can establish child execution.
%ifdef PBM_EXTERNAL_OBSERVATION_DATA
align 8
external_observation: times 4096 db 0
external_observation_name: dw 'P','a','O','S','E','x','t','e','r','n','a','l','L','a','u','n','c','h',0
external_observation_guid:
    dd 0xc4a7c2f1
    dw 0x4bb5,0x4ae8
    db 0x9c,0x4f,0x6f,0x76,0xf7,0xc2,0xa0,0x51
%else
; Preserve flags and all volatile registers, from either caller stack parity.
external_launch_observe:
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
    push rbp
    mov rbp,rsp
    and rsp,-16
    sub rsp,48
    cmp r15d,PBM_ENTRY_WINDOWS
    jb .out
    cmp r15d,PBM_ENTRY_LINUX
    ja .out
    cmp byte [rel external_volume_matches],1
    jne .out
    mov rbx,[rel selected_state_ptr]
    test rbx,rbx
    jz .out
    cmp byte [rbx+PBM_STATE_EXTERNAL_PENDING_OFF],1
    jne .out
    mov rax,[rbx+PBM_STATE_EXTERNAL_NONCE_OFF]
    test rax,rax
    jz .out
    cmp rax,[rel current_attempt_nonce]
    jne .out
    cmp r15b,[rbx+PBM_STATE_EXTERNAL_ENTRY_OFF]
    jne .out
    mov ecx,[rel composite_size]
    cmp ecx,4
    jb .out
    cmp ecx,4096-128
    ja .out
    cmp qword [rel composite_path],0
    je .out
    cmp qword [rel runtime_services],0
    je .out
    lea rdi,[rel external_observation]
    xor eax,eax
    mov ecx,128/8
    rep stosq
    mov rax,0x31303030534f5850 ; PXOS0001
    mov [rel external_observation],rax
    mov eax,[rel composite_size]
    add eax,128
    mov [rel external_observation+8],eax
    mov dword [rel external_observation+12],1
    mov rax,[rel current_attempt_nonce]
    mov [rel external_observation+16],rax
    mov rax,[rbx+PBM_STATE_GENERATION_OFF]
    mov [rel external_observation+24],rax
    mov rax,[rbx+PBM_STATE_MANIFEST_SEQ_OFF]
    mov [rel external_observation+32],rax
    lea rsi,[rel verified_manifest_sha]
    lea rdi,[rel external_observation+40]
    mov ecx,32
    rep movsb
    lea rsi,[rel verified_payload_sha]
    mov ecx,32
    rep movsb
    mov eax,[rel verified_payload_size]
    stosq
    mov [rel external_observation+112],r15b
    mov al,[rel selected_profile]
    mov [rel external_observation+113],al
    mov al,[rel selected_reason]
    mov [rel external_observation+114],al
    mov byte [rel external_observation+115],1 ; before StartImage, NOT child success
    mov ecx,[rel composite_size]
    mov [rel external_observation+116],ecx
    mov rsi,[rel composite_path]
    lea rdi,[rel external_observation+128]
    rep movsb
    mov rbx,[rel runtime_services]
    lea rcx,[rel external_observation_name]
    lea rdx,[rel external_observation_guid]
    mov r8d,6                       ; volatile BS|RT, no NV write or health grant
    mov r9d,[rel external_observation+8]
    lea rax,[rel external_observation]
    mov [rsp+32],rax
    call [rbx+0x58]                 ; best effort; status cannot affect launch
.out:
    mov rsp,rbp
    pop rbp
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
    ret
%endif
