;; MODULE hv/app_runtime
;; LAYER 5
;; EXPORTS app_runtime_memory, app_runtime_descriptor, app_runtime_read, app_runtime_retire
;; IMPORTS hv/vm_profile, hv/vmx, fs/vfs, sec/session, core/smp
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Read-only runtime pair selected by ONE compiler-produced record embedded in
; the signed candidate. Never a caller profile/hash/path/verifier callback.
; No driver selectors, mutable guest RAM or VFS selected-volume writes.
; VM hashes every actual streamed byte against these signed pins before entry.

; Native signed-profile RAM floor, or zero. Same admission/currentness as
; descriptor; no caller RAM, output buffer or new descriptor version.
app_runtime_memory:
%ifndef PAOS_APP_RUNTIME_PROFILE_INC
    xor eax,eax
    ret
%else
    sub rsp,8
    call ar_enter
    test eax,eax
    jz .bad
    call ar_current
    test eax,eax
    jnz .ready
    call ar_bind
    test eax,eax
    jz .leave_bad
.ready:
    mov rax,[rel ar_profile+VP_RAM]
    mov byte [rel ar_busy],0
    add rsp,8
    ret
.leave_bad:
    mov byte [rel ar_busy],0
.bad:
    xor eax,eax
    add rsp,8
    ret
%endif

; RDI=native output, RSI=128 -> EAX1/0. Refusal leaves output untouched.
app_runtime_descriptor:
    push rbx
    push r12
    sub rsp,8
    mov r12,rdi
    cmp rsi,128
    jne .bad
    mov rsi,128
    call ar_output
    test eax,eax
    jz .bad
    call ar_enter
    test eax,eax
    jz .bad
    call ar_current
    test eax,eax
    jnz .copy
    call ar_bind
    test eax,eax
    jz .leave_bad
.copy:
    mov rdi,r12
    lea rsi,[rel ar_descriptor]
    mov ecx,128
    cld
    rep movsb
    mov eax,1
    jmp .leave
.leave_bad:
    xor eax,eax
.leave:
    mov byte [rel ar_busy],0
    jmp .out
.bad:
    xor eax,eax
.out:
    add rsp,8
    pop r12
    pop rbx
    ret

; RDI=generation, ESI=member1kernel/2initrd, RDX=offset, RCX=native
; destination, R8=count1..1MiB -> EAX1/0. No yield/caller pointer retained.
; A failed storage read may partially modify destination: VM must discard it.
app_runtime_read:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12,rdi
    mov r13d,esi
    mov r14,rdx
    mov r15,rcx
    mov rbx,r8
    cmp r13d,1
    jb .bad
    cmp r13d,2
    ja .bad
    test rbx,rbx
    jz .bad
    cmp rbx,0x100000
    ja .bad
    mov rdi,r15
    mov rsi,rbx
    call ar_output
    test eax,eax
    jz .bad
    call ar_enter
    test eax,eax
    jz .bad
    call ar_current
    test eax,eax
    jz .leave_bad
    test r12,r12
    jz .leave_bad
    cmp r12,[rel ar_descriptor+8]
    jne .leave_bad
    mov eax,r13d
    lea rdx,[rel ar_descriptor]
    mov rax,[rdx+8+rax*8]          ; member1 length16; member2 length24
    cmp r14,rax
    ja .leave_bad
    sub rax,r14
    cmp rbx,rax
    ja .leave_bad
    mov edi,[rel ar_handle]
    cmp r13d,1
    jne .initrd
    lea rsi,[rel ar_kernel_name]
    lea rcx,[rel ar_kpath]
    mov edx,[rel ar_klen]
    jmp .source
.initrd:
    lea rsi,[rel ar_initrd_name]
    lea rcx,[rel ar_ipath]
    mov edx,[rel ar_ilen]
.source:
    cmp byte [rel ar_nested],1
    jne .root
    mov rsi,rcx                    ; handle,path,len,offset,dest,count
    mov rcx,r14
    mov r8,r15
    mov r9,rbx
    call vfs_read_at_path
    jmp .read
.root:
    mov rdx,r14                    ; handle,name11,offset,dest,count
    mov rcx,r15
    mov r8,rbx
    call vfs_read_at
.read:
    cmp rax,rbx
    jne .invalidate
    call ar_current                ; no late session transition accepted
    test eax,eax
    jz .leave_bad
    mov eax,1
    jmp .leave
.invalidate:
    call ar_clear
.leave_bad:
    xor eax,eax
.leave:
    mov byte [rel ar_busy],0
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

; Native lifecycle may invalidate before replacement/stop/revoke. Sequence is
; never reset; a later descriptor publishes a different generation or refuses.
app_runtime_retire:
    sub rsp,8
    call ar_enter
    test eax,eax
    jz .out
    call ar_clear
    mov byte [rel ar_busy],0
    mov eax,1
.out:
    add rsp,8
    ret

ar_enter:
    sub rsp,8
    call smp_current_logical
    add rsp,8
    test eax,eax
    jnz .bad
    cmp byte [rel ar_busy],0
    jne .bad
    mov byte [rel ar_busy],1
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Native output must not alias producer-owned private state/immutable pins.
ar_output:
    test rdi,rdi
    jz .bad
    mov rax,rdi
    add rax,rsi
    jc .bad
    lea rdx,[rel ar_private]
    cmp rax,rdx
    jbe .profile
    lea rdx,[rel ar_private_end]
    cmp rdi,rdx
    jb .bad
.profile:
    lea rdx,[rel ar_readonly]
    cmp rax,rdx
    jbe .ok
    lea rdx,[rel ar_readonly_end]
    cmp rdi,rdx
    jb .bad
.ok:
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

ar_current:
    sub rsp,8
    call session_shell_require_unlocked
    add rsp,8
    test eax,eax
    jnz .invalidate
    mov rax,[rel session_authority_epoch]
    test rax,rax
    jz .invalidate
    cmp rax,[rel ar_epoch]
    jne .invalidate
    cmp qword [rel ar_descriptor+8],0
    je .invalidate
    mov eax,1
    ret
.invalidate:
    call ar_clear
    xor eax,eax
    ret

ar_clear:
    lea rdi,[rel ar_descriptor]
    xor eax,eax
    mov ecx,128+8                  ; descriptor plus epoch
    cld
    rep stosb
    mov dword [rel ar_handle],-1
    mov byte [rel ar_nested],0
    ret

ar_bind:
%ifndef PAOS_APP_RUNTIME_PROFILE_INC
    xor eax,eax                    ; no record, no fabricated runtime pins
    ret
%else
    push rbx
    push r12
    push r13
    call session_shell_require_unlocked
    test eax,eax
    jnz .bad
    mov r13,[rel session_authority_epoch]
    test r13,r13
    jz .bad
    cmp qword [rel ar_sequence],-1
    je .bad
    lea rdi,[rel ar_profile]
    mov esi,VP_BYTES
    call vm_profile_validate
    test eax,eax
    jnz .bad
    lea rbx,[rel ar_profile]
    lea rsi,[rel ar_profile_name]
    lea rdi,[rbx+VP_NAME]
    mov ecx,24
    cld
    repe cmpsb
    jne .bad
    cmp byte [rbx+VP_CLASS],VP_CLASS_THIN_CLI
    jne .bad
    cmp dword [rbx+VP_DEVICES],3
    jne .bad
    cmp qword [rbx+VP_RAM],0x4000000
    jb .bad
    cmp qword [rbx+VP_RAM],0x40000000
    ja .bad
    cmp byte [rbx+VP_DEPS+VPD_KIND],1
    jne .bad
    cmp byte [rbx+VP_DEPS+VP_DEP_BYTES+VPD_KIND],2
    jne .bad
    lea rdi,[rbx+VP_DEPS+VPD_NAME]
    lea rsi,[rel ar_kernel_name]
    mov ecx,11
    repe cmpsb
    jne .bad
    lea rdi,[rbx+VP_DEPS+VP_DEP_BYTES+VPD_NAME]
    lea rsi,[rel ar_initrd_name]
    mov ecx,11
    repe cmpsb
    jne .bad
    ; Retain a source handle; FSSEL cannot replace it during native loading.
    mov eax,[rel vfs_disk_handle]
    mov [rel ar_handle],eax
    mov byte [rel ar_nested],0
    cmp byte [rel pbm_manager_launch],1
    jne .root
    cmp byte [rel boot_esp_part_guid_ok],1
    jne .root
    lea rdi,[rel ar_kpath]
    lea rsi,[rel ar_kernel_name]
    call hv_guest_files_path
    test eax,eax
    js .bad
    mov [rel ar_klen],eax
    lea rdi,[rel ar_ipath]
    lea rsi,[rel ar_initrd_name]
    call hv_guest_files_path
    test eax,eax
    js .bad
    mov [rel ar_ilen],eax
    lea rdi,[rel boot_esp_part_guid]
    call vfs_open_boot_esp
    cmp rax,-1
    je .root
    mov r12d,eax
    mov edi,r12d
    lea rsi,[rel ar_kpath]
    mov edx,[rel ar_klen]
    lea rcx,[rel ar_stat]
    call vfs_stat_path
    test rax,rax
    jnz .root
    mov rax,[rel ar_stat]
    cmp rax,[rbx+VP_DEPS+VPD_SIZE]
    jne .bad
    mov edi,r12d
    lea rsi,[rel ar_ipath]
    mov edx,[rel ar_ilen]
    lea rcx,[rel ar_stat]
    call vfs_stat_path
    test rax,rax
    jnz .root
    mov rax,[rel ar_stat]
    cmp rax,[rbx+VP_DEPS+VP_DEP_BYTES+VPD_SIZE]
    jne .bad
    mov [rel ar_handle],r12d
    mov byte [rel ar_nested],1
    jmp .publish
.root:
    cmp dword [rel ar_handle],-1
    je .bad
    mov edi,[rel ar_handle]
    lea rsi,[rel ar_kernel_name]
    lea rdx,[rel ar_stat]
    call vfs_stat
    test rax,rax
    jnz .bad
    mov rax,[rel ar_stat]
    cmp rax,[rbx+VP_DEPS+VPD_SIZE]
    jne .bad
    mov edi,[rel ar_handle]
    lea rsi,[rel ar_initrd_name]
    lea rdx,[rel ar_stat]
    call vfs_stat
    test rax,rax
    jnz .bad
    mov rax,[rel ar_stat]
    cmp rax,[rbx+VP_DEPS+VP_DEP_BYTES+VPD_SIZE]
    jne .bad
.publish:
    call session_shell_require_unlocked
    test eax,eax
    jnz .bad
    cmp r13,[rel session_authority_epoch]
    jne .bad
    inc qword [rel ar_sequence]
    mov qword [rel ar_descriptor],1
    mov rax,[rel ar_sequence]
    mov [rel ar_descriptor+8],rax
    mov rax,[rbx+VP_DEPS+VPD_SIZE]
    mov [rel ar_descriptor+16],rax
    mov rax,[rbx+VP_DEPS+VP_DEP_BYTES+VPD_SIZE]
    mov [rel ar_descriptor+24],rax
    lea rsi,[rbx+VP_DEPS+VPD_SHA]
    lea rdi,[rel ar_descriptor+32]
    mov ecx,32
    rep movsb
    lea rsi,[rbx+VP_DEPS+VP_DEP_BYTES+VPD_SHA]
    mov ecx,32
    rep movsb
    mov [rel ar_epoch],r13
    mov eax,1
    jmp .out
.bad:
    call ar_clear
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret
%endif

ar_readonly:
ar_profile_name: db 'app-bash',0
    times 24-9 db 0
ar_kernel_name: db 'APKERN     '
ar_initrd_name: db 'APINIT  GZ '
%ifdef PAOS_APP_RUNTIME_PROFILE_INC
align 8
ar_profile:
%include PAOS_APP_RUNTIME_PROFILE_INC
ar_profile_end:
%if ar_profile_end-ar_profile != VP_BYTES
%error "app runtime requires one exact compiler-produced280B record"
%endif
%endif
ar_readonly_end:

%macro WDATA_hv_app_runtime 0
align 8
ar_private:
ar_descriptor: times 128 db 0
ar_epoch: dq 0
ar_sequence: dq 0
ar_handle: dd -1
ar_busy: db 0
ar_nested: db 0
align 8
ar_kpath: times 96 db 0
ar_ipath: times 96 db 0
ar_klen: dd 0
ar_ilen: dd 0
ar_stat: times 64 db 0
ar_private_end:
%endmacro
WDATA_DEFER WDATA_hv_app_runtime
