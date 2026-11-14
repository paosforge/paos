;; MODULE sec/public_documents_seal
;; LAYER 6
;; EXPORTS public_documents_seal_preebs, public_documents_seal_after_owner_preebs, public_documents_root_key, public_documents_seal_open, public_documents_seal_sign, public_documents_owner_generation
;; IMPORTS fs/public_documents, sec/owner_stage_key, sec/owner_store, core/reset_wipe, core/smp, core/lib/sha256, core/lib/hmac_sha256
;; OWNER rc-fs-claude
;; CONTEXT: bsp_only
%include "fs/public_documents.inc"
; Independent owner-generation-bound domain. A seal authenticates creator
; provenance, never a grant, live principal, storage intent or antirollback.
; BOOT calls preebs before Z discard, after_owner after committed owner pass.
public_documents_seal_preebs:
    lea rdi,[rel pds_private_begin]
    xor eax,eax
    mov ecx,pds_private_end-pds_private_begin
    cld
    rep stosb
    lea rdi,[rel pds_info]
    mov esi,pds_info.len
    lea rdx,[rel pds_seed]
    call owner_stage_key_hkdf
    cmp eax,1
    sete byte [rel pds_seed_ready]
    ret

public_documents_seal_after_owner_preebs:
    mov byte [rel pds_ready],0
    cmp byte [rel reset_wipe_done],0
    jne .wipe
    cmp byte [rel pds_seed_ready],1
    jne .wipe
    cmp byte [rel ows_state],1
    jne .wipe
    cmp byte [rel ows_zbound],1
    jne .wipe
    cmp byte [rel ows_pw_ready],1
    jne .wipe
    cmp dword [rel ows_pw_handoff],0
    je .wipe
    mov rax,[rel ows_generation]
    test rax,rax
    jz .wipe
    cmp rax,-1
    je .wipe
    mov [rel public_documents_owner_generation],rax
    mov [rel pds_owner_input+52],rax
    lea rdi,[rel pds_owner_input]
    lea rsi,[rel ows_pw_handoff]
    mov ecx,52
    cld
    rep movsb
    lea rdi,[rel pds_key]
    lea rsi,[rel pds_seed]
    mov edx,32
    lea rcx,[rel pds_owner_input]
    mov r8d,60
    call hmac_sha256
    test rax,rax
    jnz .wipe
    cmp byte [rel reset_wipe_done],0
    jne .wipe
    mov byte [rel pds_ready],1
.wipe:
    lea rdi,[rel pds_seed]
    xor eax,eax
    mov ecx,32
    rep stosb
    lea rdi,[rel pds_owner_input]
    mov ecx,60
    rep stosb
    mov byte [rel pds_seed_ready],0
    cmp byte [rel pds_ready],1
    je .out
    lea rdi,[rel pds_key]
    mov ecx,32
    rep stosb
.out:
    ret

; Internal identity check, not a local-OWNER execution gate. SEC separately
; proves the actual Terminal principal and continuous consent for every read.
pds_current:
    call smp_current_logical
    test eax,eax
    jnz .bad
    cmp byte [rel reset_wipe_done],0
    jne .bad
    cmp byte [rel pds_ready],1
    jne .bad
    cmp byte [rel ows_state],1
    jne .bad
    cmp byte [rel ows_zbound],1
    jne .bad
    mov rax,[rel ows_generation]
    cmp rax,[rel public_documents_owner_generation]
    jne .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; root_key(native out64, sealed DATA volume identity64)->1/0. No authority.
; Two full digests bind volume geometry/GUIDs and native creator/owner domain.
; Separate synchronous root scratch/lock permits the fixed SEC validator to
; reprove root custody before/after record HMAC, never from inside HMAC.
public_documents_root_key:
    push rbx
    push r12
    push r13
    mov r12,rdi
    mov r13,rsi
    call pds_current
    test eax,eax
    jz .bad
    test r12,r12
    jz .bad
    test r13,r13
    jz .bad
    cmp byte [rel pds_root_busy],0
    jne .bad
    mov byte [rel pds_root_busy],1
    lea rdi,[rel pds_root]
    mov rsi,r13
    mov edx,64
    call sha256_hash
    test rax,rax
    jnz .failed
    lea rdi,[rel pds_root+32]
    lea rsi,[rel pds_key]
    mov edx,32
    lea rcx,[rel pds_namespace]
    mov r8d,pds_namespace.len
    call hmac_sha256
    test rax,rax
    jnz .failed
    call pds_current
    test eax,eax
    jz .failed
    mov rdi,r12
    lea rsi,[rel pds_root]
    mov ecx,8
    rep movsq
    mov ebx,1
    jmp .done
.failed:
    xor ebx,ebx
.done:
    lea rdi,[rel pds_root]
    xor eax,eax
    mov ecx,8
    rep stosq
    mov byte [rel pds_root_busy],0
    mov eax,ebx
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Native exact PUD_BYTES only; sign is reachable only from the live creator.
; Refusal changes no caller bytes. Neither path exports retained keys.
public_documents_seal_open:
    xor edx,edx
    jmp pds_call
public_documents_seal_sign:
    mov edx,1
pds_call:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12,rdi
    mov r13,rsi
    mov r14d,edx
    cmp r13,PUD_BYTES
    jne .bad
    test r12,r12
    jz .bad
    mov rax,r12
    add rax,PUD_BYTES
    jc .bad
    lea rdx,[rel pds_private_end]
    cmp r12,rdx
    jae .span
    lea rdx,[rel pds_private_begin]
    cmp rax,rdx
    ja .bad
.span:
    call pds_current
    test eax,eax
    jz .bad
    cmp byte [rel pds_busy],0
    jne .bad
    mov byte [rel pds_busy],1
    mov rax,[rel public_documents_owner_generation]
    cmp rax,[r12+PUD_OWNER]
    jne .fail
    mov rdi,r12
    call public_documents_record_check
    cmp eax,1
    jne .fail
    test r14d,r14d
    jz .copy
    call public_documents_sign_authorized
    cmp eax,1
    jne .fail
.copy:
    lea rdi,[rel pds_image]
    mov rsi,r12
    mov ecx,PUD_BYTES/8
    cld
    rep movsq
    lea rdi,[rel pds_image+PUD_MAC]
    xor eax,eax
    mov ecx,4
    rep stosq
    lea rdi,[rel pds_mac]
    lea rsi,[rel pds_key]
    mov edx,32
    lea rcx,[rel pds_image]
    mov r8d,PUD_BYTES
    call hmac_sha256
    test rax,rax
    jnz .fail
    test r14d,r14d
    jnz .recheck
    xor eax,eax
    xor edx,edx
.equal:
    mov rcx,[r12+PUD_MAC+rdx]
    lea rsi,[rel pds_mac]
    xor rcx,[rsi+rdx]
    or rax,rcx
    add edx,8
    cmp edx,32
    jb .equal
    test rax,rax
    jnz .fail
.recheck:
    call pds_current
    test eax,eax
    jz .fail
    test r14d,r14d
    jz .success
    call public_documents_sign_authorized
    cmp eax,1
    jne .fail
    lea rdi,[r12+PUD_MAC]
    lea rsi,[rel pds_mac]
    mov ecx,4
    rep movsq
.success:
    mov ebx,1
    jmp .wipe
.fail:
    xor ebx,ebx
.wipe:
    lea rdi,[rel pds_transient]
    xor eax,eax
    mov ecx,pds_transient_end-pds_transient
    rep stosb
    mov byte [rel pds_busy],0
    mov eax,ebx
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

pds_info: db 'paos.public-documents.creator.v1'
.len equ $-pds_info
pds_namespace: db 'PaOS native public Documents namespace v1'
.len equ $-pds_namespace
%macro WDATA_BSS_public_documents_seal 0
alignb 8
pds_private_begin:
pds_seed_ready: resb 1
pds_ready: resb 1
pds_busy: resb 1
pds_root_busy: resb 1
resb 4
public_documents_owner_generation: resq 1
pds_seed: resb 32
pds_key: resb 32
pds_owner_input: resb 60
resb 4
pds_transient:
pds_image: resb PUD_BYTES
pds_mac: resb 32
pds_root: resb 64
pds_transient_end:
pds_private_end:
%endmacro
WDATA_BSS_DEFER WDATA_BSS_public_documents_seal
