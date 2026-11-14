;; MODULE hv/app_runtime
;; LAYER 5
;; EXPORTS app_runtime_select_application, app_runtime_select_updater, app_runtime_updater_ready, app_runtime_updater_current, app_runtime_memory, app_runtime_descriptor, app_runtime_read, app_runtime_retire
;; IMPORTS hv/vm_profile, hv/vmx, fs/vfs, fs/fat32_disk, sec/session, core/smp
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Read-only runtime pairs selected by compiler-produced records embedded in
; the signed candidate. Never a caller profile/hash/path/verifier callback.
; No driver selectors, mutable guest RAM or VFS selected-volume writes.
; VM hashes every actual streamed byte against these signed pins before entry.

; Native signed-profile RAM floor, or zero. Same admission/currentness as
; descriptor; no caller RAM, output buffer or new descriptor version.
app_runtime_memory:
%ifndef PAOS_APP_RUNTIME_PROFILE_INC
%ifndef PAOS_UPDATER_RUNTIME_PROFILE_INC
%define AR_NO_RUNTIME 1
%endif
%endif
%ifdef AR_NO_RUNTIME
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
    call ar_source
    mov rax,[rax+48+VP_RAM]
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
    call ar_source
    test rax,rax
    jz .leave_bad
    mov edi,[rel ar_handle]
    cmp r13d,1
    jne .initrd
    lea rsi,[rax+24]
    lea rcx,[rel ar_kpath]
    mov edx,[rel ar_klen]
    jmp .source
.initrd:
    lea rsi,[rax+35]
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

; Native lifecycle selection only. No guest verb/PIO/setter is exported.
; Caller owns EMPTY admission. A switch always invalidates the cached pair;
; generation is never reused. No live VM can survive a pair replacement.
app_runtime_select_application:
    xor edx,edx
    jmp ar_select
app_runtime_select_updater:
%ifndef PAOS_UPDATER_RUNTIME_PROFILE_INC
    xor eax,eax
    ret
%else
    mov edx,1
%endif
ar_select:
    push rbx
    mov ebx,edx
    call ar_enter
    test eax,eax
    jz .bad
    call ar_clear
    mov [rel ar_role],bl
    call ar_source
    test rax,rax
    setnz bl
    mov byte [rel ar_busy],0
    movzx eax,bl
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; Passive fixed updater prerequisites. Read-only metadata on the already
; attached exact boot ESP; no open/scan, selected-volume fallback, ar_enter,
; ar_bind, descriptor publication, generation increment, selection or launch.
; Matching sizes are availability only: VM still hashes actual bytes before
; entry. Missing attachment is unavailable, never a reason to initialize it.
app_runtime_updater_ready:
%ifndef PAOS_UPDATER_RUNTIME_PROFILE_INC
    xor eax,eax
    ret
%else
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,256                    ; two96B paths + private64B stat
    call smp_current_logical
    test eax,eax
    jnz .bad
    call session_shell_require_unlocked
    test eax,eax
    jnz .bad
    mov r15,[rel session_authority_epoch]
    test r15,r15
    jz .bad
    cmp byte [rel ar_busy],0
    jne .bad
    lea r12,[rel ar_updater_profile]
    mov rdi,r12
    mov esi,VP_BYTES
    call vm_profile_validate
    test eax,eax
    jnz .bad
    lea rdi,[r12+VP_NAME]
    lea rsi,[rel ar_updater_name]
    mov ecx,24
    cld
    repe cmpsb
    jne .bad
    cmp byte [r12+VP_CLASS],VP_CLASS_THIN_CLI
    jne .bad
    cmp dword [r12+VP_DEVICES],3
    jne .bad
    cmp qword [r12+VP_RAM],0x4000000
    jb .bad
    cmp qword [r12+VP_RAM],0x40000000
    ja .bad
    cmp byte [r12+VP_DEPS+VPD_KIND],1
    jne .bad
    cmp byte [r12+VP_DEPS+VP_DEP_BYTES+VPD_KIND],2
    jne .bad
    lea rdi,[r12+VP_DEPS+VPD_NAME]
    lea rsi,[rel ar_updater_kernel]
    mov ecx,11
    repe cmpsb
    jne .bad
    lea rdi,[r12+VP_DEPS+VP_DEP_BYTES+VPD_NAME]
    lea rsi,[rel ar_updater_initrd]
    mov ecx,11
    repe cmpsb
    jne .bad
    call ar_updater_attached
    test eax,eax
    jz .bad
    lea r13d,[eax-1]
    mov rdi,rsp
    lea rsi,[rel ar_updater_kernel]
    call hv_guest_files_path
    test eax,eax
    js .bad
    mov ebx,eax
    lea rdi,[rsp+96]
    lea rsi,[rel ar_updater_initrd]
    call hv_guest_files_path
    test eax,eax
    js .bad
    mov r14d,eax
    mov edi,r13d
    mov rsi,rsp
    mov edx,ebx
    lea rcx,[rsp+192]
    call vfs_stat_path
    test rax,rax
    jnz .bad
    mov rax,[rsp+192]
    cmp rax,[r12+VP_DEPS+VPD_SIZE]
    jne .bad
    ; Every read must remain on the exact original attached source.
    call ar_updater_attached
    lea ecx,[r13d+1]
    cmp eax,ecx
    jne .bad
    mov edi,r13d
    lea rsi,[rsp+96]
    mov edx,r14d
    lea rcx,[rsp+192]
    call vfs_stat_path
    test rax,rax
    jnz .bad
    mov rax,[rsp+192]
    cmp rax,[r12+VP_DEPS+VP_DEP_BYTES+VPD_SIZE]
    jne .bad
    call ar_updater_attached
    lea ecx,[r13d+1]
    cmp eax,ecx
    jne .bad
    call session_shell_require_unlocked
    test eax,eax
    jnz .bad
    cmp r15,[rel session_authority_epoch]
    jne .bad
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    add rsp,256
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
%endif

; Pure peek of existing native FS facts, agreed with FS110655. No initializer
; or ambient selected-volume authority. Return exact handle+1, or zero.
ar_updater_attached:
%ifndef PAOS_UPDATER_RUNTIME_PROFILE_INC
    xor eax,eax
    ret
%else
    push rbx
    cmp byte [rel pbm_manager_launch],1
    jne .bad
    cmp byte [rel boot_esp_part_guid_ok],1
    jne .bad
    mov rax,[rel boot_esp_part_guid]
    or rax,[rel boot_esp_part_guid+8]
    jz .bad
    mov ebx,[rel fd_ro_handle]
    test ebx,ebx
    jz .bad
    lea edi,[ebx-1]
    call vfs_mount_ptr
    test rax,rax
    jz .bad
    lea rdx,[rel fd_ro_ctx]
    cmp [rax+fsmount.priv],rdx
    jne .bad
    lea rdx,[rel fd_ro_ops]
    cmp [rax+fsmount.ops],rdx
    jne .bad
    cmp dword [rel fd_ro_ctx+FD_MOUNTED],1
    jne .bad
    cmp byte [rel fd_ro_ctx+FD_PART_ESP],1
    jne .bad
    mov rax,[rel boot_esp_part_guid]
    cmp rax,[rel fd_ro_guid]
    jne .bad
    cmp rax,[rel fd_ro_ctx+FD_PART_GUID]
    jne .bad
    mov rax,[rel boot_esp_part_guid+8]
    cmp rax,[rel fd_ro_guid+8]
    jne .bad
    cmp rax,[rel fd_ro_ctx+FD_PART_GUID+8]
    jne .bad
    mov eax,ebx
    jmp .out
.bad:
    xor eax,eax
.out:
    pop rbx
    ret
%endif

; RDI exact runtime generation ->1 only the current qualified signed pair.
; This is not a closed-exit identity or authority; VM composes both predicates.
app_runtime_updater_current:
    push rbx
    mov rbx,rdi
    call ar_enter
    test eax,eax
    jz .bad
    cmp byte [rel ar_role],1
    jne .leave_bad
    call ar_source
    test rax,rax
    jz .leave_bad
    call ar_current
    cmp eax,1
    jne .leave_bad
    test rbx,rbx
    jz .leave_bad
    cmp rbx,[rel ar_descriptor+8]
    jne .leave_bad
    mov eax,1
    jmp .leave
.leave_bad:
    xor eax,eax
.leave:
    mov byte [rel ar_busy],0
.bad:
    pop rbx
    ret

; Immutable native source table: name24, kernel11, initrd11, pad2, profile280.
ar_source:
    cmp byte [rel ar_role],1
    je .updater
%ifdef PAOS_APP_RUNTIME_PROFILE_INC
    lea rax,[rel ar_profile_name]
    ret
%else
    xor eax,eax
    ret
%endif
.updater:
%ifdef PAOS_UPDATER_RUNTIME_PROFILE_INC
    lea rax,[rel ar_updater_name]
    ret
%else
    xor eax,eax
    ret
%endif

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
%ifdef AR_NO_RUNTIME
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
    call ar_source
    test rax,rax
    jz .bad
    lea rbx,[rax+48]
    mov rdi,rbx
    mov esi,VP_BYTES
    call vm_profile_validate
    test eax,eax
    jnz .bad
    lea rsi,[rbx-48]
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
    lea rsi,[rbx-24]
    mov ecx,11
    repe cmpsb
    jne .bad
    lea rdi,[rbx+VP_DEPS+VP_DEP_BYTES+VPD_NAME]
    lea rsi,[rbx-13]
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
    lea rsi,[rbx-24]
    call hv_guest_files_path
    test eax,eax
    js .bad
    mov [rel ar_klen],eax
    lea rdi,[rel ar_ipath]
    lea rsi,[rbx-13]
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
    lea rsi,[rbx-24]
    lea rdx,[rel ar_stat]
    call vfs_stat
    test rax,rax
    jnz .bad
    mov rax,[rel ar_stat]
    cmp rax,[rbx+VP_DEPS+VPD_SIZE]
    jne .bad
    mov edi,[rel ar_handle]
    lea rsi,[rbx-13]
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
align 8
ar_profile_name: db 'app-bash',0
    times 24-9 db 0
ar_kernel_name: db 'APKERN     '
ar_initrd_name: db 'APINIT  GZ '
    times 2 db 0
%ifdef PAOS_APP_RUNTIME_PROFILE_INC
align 8
ar_profile:
%include PAOS_APP_RUNTIME_PROFILE_INC
ar_profile_end:
%if ar_profile_end-ar_profile != VP_BYTES
%error "app runtime requires one exact compiler-produced280B record"
%endif
%endif
%ifdef PAOS_UPDATER_RUNTIME_PROFILE_INC
align 8
ar_updater_name: db 'updater-worker',0
    times 24-15 db 0
ar_updater_kernel: db 'UPKERN     '
ar_updater_initrd: db 'UPINIT  GZ '
    times 2 db 0
ar_updater_profile:
%include PAOS_UPDATER_RUNTIME_PROFILE_INC
ar_updater_profile_end:
%if ar_updater_profile_end-ar_updater_profile != VP_BYTES
%error "updater runtime requires one exact compiler-produced280B record"
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
ar_role: db 0
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
