;; MODULE sec/app_store_seal
;; LAYER 6
;; PURPOSE Authenticate the fixed installed-app aggregate for the sealed local owner.
;; EXPORTS app_store_seal_preebs, app_store_seal_open, app_store_seal_sign
;; IMPORTS sec/owner_stage_key, sec/principal, sec/session, svc/command, fs/app_store_layout, core/smp, core/lib/hmac_sha256
;; OWNER saga:app_store
;; CONTEXT: bsp_only
%include "fs/app_store_layout.inc"
; Native internal only. No file, firmware, grant, install or removal authority.
; preebs derives a separate domain BEFORE owner_store discards Z. Runtime calls
; require current depth-zero local keyed OWNER. The caller owns mapped native
; lifetime and (sign only) writable bytes; no yield or untrusted callback here.
; Full record HMAC includes header, every catalog byte and payload, seal32 zero.
; Password change, missing Z or reset refuses old catalogs. Authentication does
; not provide disk antirollback, bundle signature validation or grant policy.
app_store_seal_preebs:
    mov byte [rel ass_key_ready],0
    lea rdi,[rel app_store_mac_key]
    xor eax,eax
    mov ecx,4
    cld
    rep stosq
    lea rdi,[rel ass_info]
    mov esi,ass_info.len
    lea rdx,[rel app_store_mac_key]
    call owner_stage_key_hkdf
    cmp eax,1
    sete byte [rel ass_key_ready]
    ret

; open(RDI immutable record, RSI exact bytes)->1 authentic current owner /0.
; Neither success nor refusal changes the input. No cached verification.
app_store_seal_open:
    xor edx,edx
    jmp ass_call
; sign(RDI writable record, RSI exact bytes)->1 owner32/seal32 published /0.
; Only those64 bytes change; refusal changes no caller bytes. Not a write intent.
app_store_seal_sign:
    mov edx,1
ass_call:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12,rdi
    mov r13,rsi
    mov r14d,edx
    call smp_current_logical
    test eax,eax
    jnz .refused
    cmp r13,ASL_PAYLOAD
    jb .refused
    cmp r13,ASL_MAX
    ja .refused
    test r12,r12
    jz .refused
    mov rax,r12
    add rax,r13
    jc .refused
    lea rdx,[rel ass_private_end]
    cmp r12,rdx
    jae .span_ok
    lea rdx,[rel ass_private_begin]
    cmp rax,rdx
    ja .refused
.span_ok:
    cmp byte [rel ass_busy],0
    jne .refused
    mov byte [rel ass_busy],1
    call ass_owner
    test eax,eax
    jz .fail
    mov r15,rdx
    lea rdi,[rel ass_image]
    mov rsi,r12
    mov rcx,r13
    cld
    rep movsb
    lea rdi,[rel ass_image]
    mov rsi,r13
    call app_store_layout_check
    cmp eax,1
    jne .fail
    ; Bind both MAC key and public opaque owner tag to all52 credential bytes.
    lea rdi,[rel ass_password]
    lea rsi,[rel prin_owner_pw]
    mov ecx,52
    rep movsb
    lea rdi,[rel ass_owner_key]
    lea rsi,[rel app_store_mac_key]
    mov edx,32
    lea rcx,[rel ass_password]
    mov r8d,52
    call hmac_sha256
    test rax,rax
    jnz .fail
    lea rdi,[rel ass_owner_tag]
    lea rsi,[rel ass_owner_key]
    mov edx,32
    lea rcx,[rel ass_owner_info]
    mov r8d,ass_owner_info.len
    call hmac_sha256
    test rax,rax
    jnz .fail
    test r14d,r14d
    jnz .set_owner
    lea rdi,[rel ass_image+ASL_OWNER]
    lea rsi,[rel ass_owner_tag]
    call ass_equal32
    test eax,eax
    jz .fail
    jmp .mac
.set_owner:
    lea rdi,[rel ass_image+ASL_OWNER]
    lea rsi,[rel ass_owner_tag]
    mov ecx,4
    rep movsq
.mac:
    lea rdi,[rel ass_received]
    lea rsi,[rel ass_image+ASL_SEAL]
    mov ecx,4
    rep movsq
    lea rdi,[rel ass_image+ASL_SEAL]
    xor eax,eax
    mov ecx,4
    rep stosq
    lea rdi,[rel ass_mac]
    lea rsi,[rel ass_owner_key]
    mov edx,32
    lea rcx,[rel ass_image]
    mov r8,r13
    call hmac_sha256
    test rax,rax
    jnz .fail
    test r14d,r14d
    jnz .recheck
    lea rdi,[rel ass_received]
    lea rsi,[rel ass_mac]
    call ass_equal32
    test eax,eax
    jz .fail
.recheck:
    call ass_owner
    test eax,eax
    jz .fail
    cmp rdx,r15
    jne .fail
    lea rdi,[rel prin_owner_pw]
    lea rsi,[rel ass_password]
    mov ecx,52
    repe cmpsb
    jne .fail
    test r14d,r14d
    jz .success
    lea rdi,[r12+ASL_OWNER]
    lea rsi,[rel ass_owner_tag]
    mov ecx,4
    rep movsq
    lea rdi,[r12+ASL_SEAL]
    lea rsi,[rel ass_mac]
    mov ecx,4
    rep movsq
.success:
    mov ebx,1
    jmp .wipe
.fail:
    xor ebx,ebx
.wipe:
    ; A fault at any point is also covered by reset_wipe's complete range.
    lea rdi,[rel ass_transient]
    xor eax,eax
    mov ecx,ass_transient_end-ass_transient
    rep stosb
    mov byte [rel ass_busy],0
    mov eax,ebx
    jmp .out
.refused:
    xor eax,eax
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

ass_owner:
    cmp byte [rel ass_key_ready],1
    jne .no
    cmp byte [rel cmd_in_dispatch],0
    jne .no
    cmp dword [rel cmd_dispatch_depth],0
    jne .no
    cmp byte [rel prin_owner_pw_state],1
    jne .no
    cmp dword [rel prin_owner_pw],0
    je .no
    call session_shell_local_authority
    cmp rax,PRIN_OWNER
    jne .no
    cmp rdx,-1
    je .no
    mov eax,1
    ret
.no:
    xor eax,eax
    xor edx,edx
    ret

; Constant-time equality for complete MAC/tag32 (not a key-dependent branch).
ass_equal32:
    xor eax,eax
    xor ecx,ecx
.loop:
    mov dl,[rdi+rcx]
    xor dl,[rsi+rcx]
    or al,dl
    inc ecx
    cmp ecx,32
    jb .loop
    test al,al
    sete al
    movzx eax,al
    ret

ass_info: db 'PaOS/sec/app_store/v1'
.len equ $-ass_info
ass_owner_info: db 'PaOS/sec/app_store/owner/v1'
.len equ $-ass_owner_info
%include "core/abi/wdata.inc"
%macro WDATA_BSS_sec_app_store_seal 0
alignb 8
ass_private_begin:
ass_busy: resb 1
ass_key_ready: resb 1
alignb 8
app_store_mac_key: resb 32
ass_transient:
ass_owner_key: resb 32
ass_owner_tag: resb 32
ass_mac: resb 32
ass_received: resb 32
ass_password: resb 52
ass_image: resb ASL_MAX
ass_transient_end:
ass_private_end:
%endmacro
WDATA_BSS_DEFER WDATA_BSS_sec_app_store_seal
