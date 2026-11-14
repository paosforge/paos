;; MODULE svc/settings_update_app_source
;; LAYER 5
;; EXPORTS settings_update_app_stage, settings_update_app_ready
;; IMPORTS svc/app_script, svc/app_bundle, hv/app_runtime, core/lib/sha256, bootmgr/rsa2048_verify, sec/session, sec/principal, core/smp
;; CAPS
;; OWNER saga:update
; Fixed BUILD-provisioned identity, never executable updater code or authority.
; ADMIN owns the paos.asm/profile include; N owns once-per-original admission.
; Call only at N's native idle/no-active-runtime boundary, before prepare(handle,0).
; No FETCH take, installed-owner staging, cached handle, retry or callback here.
; The strict stager separately checks current APPKEY, signature, session and BSP.
; The dedicated signed UPKERN/UPINIT runtime remains independently required.

%ifndef PAOS_SETTINGS_UPDATE_APP_SOURCE_ASM
%define PAOS_SETTINGS_UPDATE_APP_SOURCE_ASM 1

; No arguments -> RAX fresh genuine app_script handle, or zero.
settings_update_app_stage:
    sub rsp,40                      ; 32-byte digest, aligned native calls
    call smp_current_logical
    test eax,eax
    jnz .bad
    call session_shell_remote_context
    test eax,eax
    jnz .bad
    call principal_current
    cmp rax,PRIN_OWNER
    jne .bad
    mov rdi,rsp
    call suas_source_current
    test eax,eax
    jz .bad
    lea rdi,[rel suas_source]
    mov esi,SUAS_LENGTH
    add rsp,40
    jmp app_script_stage            ; one real verification/publication attempt
.identity_bad:
.bad:
    add rsp,40
    xor eax,eax
    ret

; Passive native prerequisites only. No handle, stage, allocation, selection,
; runtime binding, launch, FETCH, grant or availability setter. N owns its
; transition-only setter and independently rechecks admission at launch.
settings_update_app_ready:
    push rbx
    push r12
    push r13
    sub rsp,32
    call smp_current_logical
    test eax,eax
    jnz .bad
    call session_shell_remote_context
    test eax,eax
    jnz .bad
    call principal_current
    cmp rax,PRIN_OWNER
    jne .bad
    call session_shell_require_unlocked
    test eax,eax
    jnz .bad
    mov r12,[rel session_authority_epoch]
    test r12,r12
    jz .bad
    mov rdi,rsp
    call suas_source_current
    test eax,eax
    jz .bad
    ; The maintained generator emits classic signed container2. The complete
    ; independent pin is checked above before these bounded header reads.
    mov rax,'PAOSAPP1'
    cmp [rel suas_source],rax
    jne .bad
    cmp dword [rel suas_source+8],0x00400002
    jne .bad
    cmp dword [rel suas_source+12],SUAS_LENGTH
    jne .bad
    cmp dword [rel suas_source+20],256
    jne .bad
    mov rax,'BASHAPP1'
    cmp [rel suas_source+64],rax
    jne .bad
    lea rdi,[rel suas_source+48]
    call app_trust_find_readonly
    test rax,rax
    jz .bad
    mov rcx,rax
    lea rdi,[rel suas_source+SUAS_LENGTH-256]
    lea rsi,[rel suas_source]
    mov edx,SUAS_LENGTH-256
    call rsa2048_verify_sha256
    test eax,eax
    jnz .bad
    call app_runtime_updater_ready
    cmp eax,1
    jne .bad
    call session_shell_require_unlocked
    test eax,eax
    jnz .bad
    cmp r12,[rel session_authority_epoch]
    jne .bad
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    add rsp,32
    pop r13
    pop r12
    pop rbx
    ret

; RDI scratch32; exact immutable source pin and fixed identity. No publication.
suas_source_current:
    push rbx
    mov rbx,rdi
    mov edx,SUAS_LENGTH
    cmp edx,656
    jb .bad
    cmp edx,65536
    ja .bad
    mov rdi,rbx
    lea rsi,[rel suas_source]
    call sha256_hash
    test eax,eax
    jnz .bad
    mov rdi,rbx
    lea rsi,[rel suas_expected_sha256]
    mov ecx,4
    cld
    repe cmpsq
    jne .bad
    lea rdi,[rel suas_source+80]     ; canonical manifest fixed ID field
    lea rsi,[rel suas_updater_id]
    mov ecx,8
    repe cmpsq
    jne .identity_bad
    mov eax,1
    jmp .out
.identity_bad:
.bad:
    xor eax,eax
.out:
    pop rbx
    ret

; Immutable input, exact original signed public envelope. Build generator only;
; a digest or PEM operand never enrolls a native APPKEY or supplies a handle.
suas_updater_id: db 'org.paos.settings.updater',0
    times 64-($-suas_updater_id) db 0
%ifdef PAOS_SETTINGS_UPDATE_APP_SOURCE_INCLUDE
%include PAOS_SETTINGS_UPDATE_APP_SOURCE_INCLUDE
%else
SUAS_LENGTH equ 0
suas_expected_sha256: times 32 db 0
suas_source:
%endif
suas_source_end:
%if suas_source_end-suas_source != SUAS_LENGTH
    %error "settings updater source length drift"
%endif
%if suas_source-suas_expected_sha256 != 32
    %error "settings updater source digest size drift"
%endif

%endif
