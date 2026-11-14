;; MODULE fs/copy_service_config
;; LAYER 4
;; EXPORTS copy_service_configure
;; IMPORTS fs/vfs_copy_service, fs/blockdev, fs/storage_access, hv/vm_profile, core/csprng, boot/header, boot/beacon
;; CAPS
;; OWNER saga:storage
;; CONTEXT: bsp_only
; Internal constructor for the original OWNER+SPECIAL FSSERVICE request.
; RDI=registered device name Z, RSI=independent FSCG256, RDX=actual principal.
; -> service mount/-1. No IO, lease acquisition, guest START or bulk operation.
; FSCG: magic4,versionH,reservedH,firstQ,countQ,diskGUID16,partGUID16,
; NTFSserialQ,maxbytesQ,lifetimeI,srclenH,dstlenH,src80,dst80,request16.
; Only native dev registry/profile table/current boot/principal/CSPRNG produce
; private pointers, incarnation, job/attachment/boot tokens and native epoch.
copy_service_configure:
    push rbx
    push r12
    push r13
    push r14
    sub rsp,8
    mov rbx,rdi
    mov r12,rsi
    mov r13,rdx
    test rbx,rbx
    jz .bad
    test r12,r12
    jz .bad
    test r13,r13
    jz .bad
    call storage_access_request_owner
    cmp eax,1
    jne .bad
    call storage_access_request_intent
    cmp eax,SA_INTENT_SPECIAL
    jne .bad
    cmp dword [r12],0x47435346     ; FSCG
    jne .bad
    cmp dword [r12+4],1           ; version1, zero reserved
    jne .bad
    mov rax,[r12+24]
    or rax,[r12+32]
    jz .bad
    mov rax,[r12+40]
    or rax,[r12+48]
    jz .bad
    cmp qword [r12+56],0
    je .bad
    cmp qword [r12+8],2048
    jb .bad
    cmp qword [r12+16],2048
    jb .bad
    mov rax,[r12+8]
    add rax,[r12+16]
    jc .bad
    mov rax,[r12+16]
    shr rax,55                   ; byte extent must not overflow
    jnz .bad
    cmp qword [rel boot_tsc_start],0
    je .bad
    cmp dword [rel boot_nonce],0
    je .bad
    xor esi,esi
.name:
    cmp esi,63
    jae .bad
    cmp byte [rbx+rsi],0
    je .found_name
    inc esi
    jmp .name
.found_name:
    test esi,esi
    jz .bad
    mov rdi,rbx
    call blk_find_named
    test rax,rax
    jz .bad
    mov r14,rax
    mov rax,[rax+dev.info]
    test rax,rax
    jz .bad
    cmp qword [rax+blk_info.media_generation],0
    je .bad
    lea rdi,[rel csc_profile_name]
    call vm_profile_find          ; signed builtin table only, never a pointer from text
    test rax,rax
    jz .bad
    mov [rel csc_profile],rax
    lea rdi,[rel csc_grant]
    mov ecx,40
    xor eax,eax
    cld
    rep stosq
    lea rdi,[rel csc_lease]
    mov ecx,17
    rep stosq
    lea rdi,[rel csc_random]
    mov esi,32
    call csprng_generate
    test eax,eax
    jnz .bad
    mov dword [rel csc_grant],0x31475346
    mov dword [rel csc_grant+4],0x00010001 ; v1, NTFS backend1
    lea rdi,[rel csc_grant+8]
    lea rsi,[r12+240]
    mov ecx,2
    rep movsq
    lea rdi,[rel csc_grant+24]
    lea rsi,[rel csc_random]
    mov ecx,2
    rep movsq
    mov [rel csc_grant+40],r13
    lea rdi,[rel csc_grant+56]
    lea rsi,[rel csc_random+16]
    mov ecx,2
    rep movsq
    mov qword [rel csc_grant+72],1
    mov rax,[r12+64]
    mov [rel csc_grant+80],rax
    mov rax,[r12+72]
    mov [rel csc_grant+88],rax    ; lifetime + exact two name lengths
    mov rax,[r12+56]
    mov [rel csc_grant+96],rax
    lea rdi,[rel csc_grant+104]
    lea rsi,[r12+80]
    mov ecx,20
    rep movsq
    mov rax,[rel boot_tsc_start]
    mov [rel csc_grant+264],rax
    mov eax,[rel boot_nonce]
    mov [rel csc_grant+272],eax
    mov rax,[r12+16]
    shl rax,9
    mov [rel csc_grant+280],rax
    mov [rel csc_lease],r14
    mov rax,[r14+dev.info]
    mov rax,[rax+blk_info.media_generation]
    mov [rel csc_lease+8],rax
    lea rdi,[rel csc_lease+16]
    lea rsi,[r12+8]
    mov ecx,6
    rep movsq                   ; first/count/diskGUID/partitionGUID
    mov [rel csc_lease+64],r13
    lea rdi,[rel csc_lease+80]
    lea rsi,[rel csc_grant+24]
    mov ecx,2
    rep movsq
    lea rdi,[rel csc_lease+96]
    lea rsi,[rel csc_grant+8]
    mov ecx,2
    rep movsq
    lea rdi,[rel csc_lease+112]
    lea rsi,[rel csc_grant+56]
    mov ecx,2
    rep movsq
    mov qword [rel csc_lease+128],1
    mov rdi,[rel csc_profile]
    lea rsi,[rel csc_lease]
    lea rdx,[rel csc_grant]
    call vfs_copy_service_register ; complete independent grant/name/limit validation
    jmp .out
.bad:
    mov rax,-1
.out:
    add rsp,8
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
csc_profile_name: db 'filesystem',0
%macro WDATA_fs_copy_service_config 0
align 8
csc_profile: dq 0
csc_random: times 32 db 0
csc_grant: times 320 db 0
csc_lease: times 136 db 0
%endmacro
WDATA_DEFER WDATA_fs_copy_service_config
