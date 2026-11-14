;; MODULE fs/vfs_copy_service
;; LAYER 4
;; EXPORTS vfs_copy_service_register, vfs_copy_service_ops, vfs_copy_service_snapshot, vfs_copy_service_state, vfs_copy_service_bind_job
;; IMPORTS fs/vfs, fs/storage_access, fs/guest_volume, hv/filesystem_domain, hv/filesystem_wire
;; CAPS CAP_BLOCK_READ, CAP_BLOCK_WRITE
;; OWNER saga:storage
;; CONTEXT: bsp_only
; One independently authorized same-volume NTFS job in the Linux filesystem
; domain. The original FSCOPY BEGIN starts it, and the ordinary VFS idle step
; polls it. No native bulk engine, guest pointer or alternate copy-job ring.
; Register is an INTERNAL native supervisor entry, never a wire pointer API.
; vfs_copy_service_register(profile*, lease136*, native FSG1*) -> mount/-1.
; A mount is configured once per boot. Reuse requires a later explicit lifecycle
; extension; failure/uncertainty never authorizes another START here.

vfs_copy_service_register:
    push rbx
    push r12
    push r13
    push r14
    sub rsp,8
    mov rbx,rdi
    mov r12,rsi
    mov r13,rdx
    cmp dword [rel fsvc_configured],0
    jne .bad
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
    call vfs_copy_busy
    test eax,eax
    jnz .bad
    lea rdi,[rel fsvc_grant]
    mov rsi,r13
    mov ecx,40
    cld
    rep movsq
    lea rdi,[rel fsvc_volume]
    mov rsi,r12
    mov ecx,17
    rep movsq
    mov [rel fsvc_profile],rbx
    call fsvc_start_packet
    lea rdi,[rel fsvc_grant]
    lea rsi,[rel fsvc_request]
    call fsc_grant_validate
    test eax,eax
    jnz .bad
    ; Exact independently authored lease identity, not labels or device names.
    lea rdi,[rel fsvc_volume+64]
    lea rsi,[rel fsvc_grant+40]
    mov ecx,2
    repe cmpsq
    jne .bad
    lea rdi,[rel fsvc_volume+80]
    lea rsi,[rel fsvc_grant+24]
    mov ecx,2
    repe cmpsq
    jne .bad
    lea rdi,[rel fsvc_volume+96]
    lea rsi,[rel fsvc_grant+8]
    mov ecx,2
    repe cmpsq
    jne .bad
    lea rdi,[rel fsvc_volume+112]
    lea rsi,[rel fsvc_grant+56]
    mov ecx,2
    repe cmpsq
    jne .bad
    mov rax,[rel fsvc_volume+128]
    cmp rax,[rel fsvc_grant+72]
    jne .bad
    mov dword [rel fsvc_configured],1
    ; fs_ops holds native pointers. Populate them at the relocated image base
    ; only after the existing authority/identity checks, before publication.
    lea rax,[rel fsvc_backend_name]
    mov [rel vfs_copy_service_ops+fs_ops.name],rax
    lea rax,[rel fsvc_mount_op]
    mov [rel vfs_copy_service_ops+fs_ops.mount],rax
    lea rax,[rel fsvc_refuse]
    mov [rel vfs_copy_service_ops+fs_ops.readfile],rax
    mov [rel vfs_copy_service_ops+fs_ops.stat],rax
    mov [rel vfs_copy_service_ops+fs_ops.read_at],rax
    lea rax,[rel fsvc_copy]
    mov [rel vfs_copy_service_ops+fs_ops.copy],rax
    lea rax,[rel fsvc_armed]
    mov [rel vfs_copy_service_ops+fs_ops.mutate_armed],rax
    lea rdi,[rel vfs_copy_service_ops]
    xor esi,esi                        ; no attachment exists before BEGIN
    lea rdx,[rel fsvc_mount_name]
    call vfs_register_mount
    test rax,rax
    js .bad_registered
    mov [rel fsvc_mount],rax
    jmp .out
.bad_registered:
    ; Registration did not publish a mount or START; retain one-use refusal.
    mov dword [rel fsvc_used],1
.bad:
    mov rax,-1
.out:
    add rsp,8
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

fsvc_start_packet:
    lea rdi,[rel fsvc_request]
    mov ecx,32
    xor eax,eax
    cld
    rep stosq
    mov dword [rel fsvc_request],0x31435346
    mov dword [rel fsvc_request+4],0x00010002
    lea rdi,[rel fsvc_request+8]
    lea rsi,[rel fsvc_grant+8]
    mov ecx,9
    rep movsq
    mov eax,[rel fsvc_grant+92]
    mov [rel fsvc_request+80],eax
    lea rdi,[rel fsvc_request+88]
    lea rsi,[rel fsvc_grant+104]
    mov ecx,20
    rep movsq
    mov qword [rel fsvc_request+248],1
    ret

fsvc_mount_op:
    cmp dword [rel fsvc_configured],1
    jne fsvc_refuse
    xor eax,eax
    ret
fsvc_refuse:
    mov rax,-1
    ret

; Pure current-request authority/state read, no lease acquisition or IO.
fsvc_armed:
    sub rsp,8
    call storage_access_request_owner
    cmp eax,1
    jne .no
    call storage_access_request_intent
    cmp eax,SA_INTENT_SPECIAL
    jne .no
    cmp dword [rel fsvc_configured],1
    jne .no
    cmp dword [rel fsvc_used],0
    jne .no
    mov eax,1
    jmp .out
.no:
    xor eax,eax
.out:
    add rsp,8
    ret

; RSI=absolute single basename Z, RDX=authorized80, ECX=authorized length.
; No discovery, slash traversal, prefix match, mode or name substitution.
fsvc_name_equal:
    cmp byte [rsi],'/'
    jne .bad
    inc rsi
    test ecx,ecx
    jz .bad
    cmp ecx,80
    ja .bad
.loop:
    mov al,[rsi]
    cmp al,[rdx]
    jne .bad
    inc rsi
    inc rdx
    dec ecx
    jnz .loop
    cmp byte [rsi],0
    jne .bad
    xor eax,eax
    ret
.bad:
    mov eax,-1
    ret

fsvc_copy:
    push rbx
    push r12
    push r13
    push r14
    sub rsp,8
    mov rbx,rdi
    mov r12,r8
    cmp ecx,FS_COPY_BEGIN
    je .begin
    cmp r12,[rel fsvc_job]
    jne .bad
    cmp ecx,FS_COPY_CANCEL
    je .cancel
    cmp ecx,FS_COPY_STEP
    jne .bad
    jmp .step
.begin:
    test r9d,r9d                      ; no queued/carried/tree/replace policy
    jnz .bad
    mov r13,rsi
    mov r14,rdx
    call fsvc_armed
    cmp eax,1
    jne .bad
    mov rsi,r13
    lea rdx,[rel fsvc_grant+104]
    movzx ecx,word [rel fsvc_grant+92]
    call fsvc_name_equal
    test eax,eax
    jnz .bad
    mov rsi,r14
    lea rdx,[rel fsvc_grant+184]
    movzx ecx,word [rel fsvc_grant+94]
    call fsvc_name_equal
    test eax,eax
    jnz .bad
    mov dword [rel fsvc_used],1        ; unknown START cannot be reoffered
    mov rdi,[rel fsvc_profile]
    lea rsi,[rel fsvc_volume]
    lea rdx,[rel fsvc_grant]
    lea rcx,[rel fsvc_request]
    call fsg_begin
    test rax,rax
    jz .bad
    mov [rel fsvc_generation],rax
    mov rdi,rax
    call fsg_attachment
    test rax,rax
    jz .start_failed
    mov [rbx+fsmount.priv],rax
    mov [rel fsvc_handle],rax
    mov [rel fsvc_job],r12
    mov qword [r12+fs_copy_job.done],0
    mov qword [r12+fs_copy_job.total],-1
    mov dword [r12+fs_copy_job.state],FS_JOB_RUNNING
    mov dword [r12+fs_copy_job.error],0
    mov dword [r12+fs_copy_job.durable],FS_DUR_NO
    mov dword [r12+fs_copy_job.preserved],FS_PRES_NONE
    mov rax,[rel fsvc_volume]
    mov [r12+fs_copy_job.dev],rax
    mov qword [rel fsvc_last_total],-1
    mov dword [rel fsvc_pending],1
    jmp .ok
.start_failed:
    mov rdi,[rel fsvc_generation]
    call fsg_stop
    ; No VFS job was published; VM retains actual custody and terminal hook.
    jmp .bad
.cancel:
    mov dword [rel fsvc_cancel],1
    mov dword [r12+fs_copy_job.state],FS_JOB_CANCELLING
    jmp .ok                        ; in-flight RPC drains; never a second START
.step:
    cmp dword [rel fsvc_retiring],0
    jne .retire
    cmp dword [rel fsvc_pending],1
    jne .offer
    mov rdi,[rel fsvc_generation]
    lea rsi,[rel fsvc_reply]
    call fsg_poll
    test rax,rax
    jz .ok
    cmp rax,256
    jne .fault
    mov dword [rel fsvc_pending],0
    lea rdi,[rel fsvc_reply]
    lea rsi,[rel fsvc_request]
    call fsc_wire_reply
    test eax,eax
    jnz .fault
    cmp dword [rel fsvc_finishing],0
    jne .finish_reply
    test dword [rel fsvc_reply+88],-16 ; cleanup proof only on explicit FINISH
    jnz .fault
    cmp dword [rel fsvc_reply+192],1
    ja .fault
    cmp dword [rel fsvc_reply+196],1
    ja .fault
    mov rax,[rel fsvc_reply+72]
    cmp rax,[rel fsvc_grant+80]
    ja .fault
    cmp rax,[r12+fs_copy_job.done]
    jb .fault
    mov rdx,[rel fsvc_reply+80]
    cmp rdx,-1
    je .unknown_total
    cmp rdx,[rel fsvc_grant+80]
    ja .fault
    cmp rax,rdx
    ja .fault
    jmp .bounded
.unknown_total:
    test rax,rax
    jnz .fault
.bounded:
    mov rcx,[rel fsvc_last_total]
    cmp rcx,-1
    je .total
    cmp rdx,rcx
    jne .fault
.total:
    mov [r12+fs_copy_job.done],rax
    mov [r12+fs_copy_job.total],rdx
    mov [rel fsvc_last_total],rdx
    mov eax,[rel fsvc_reply+64]
    cmp eax,4
    je .completed
    cmp eax,5
    jae .failed_reply
    test eax,eax
    jz .fault                         ; START cannot report never started
    cmp dword [rel fsvc_reply+68],0
    jne .fault
    test dword [rel fsvc_reply+88],11
    jnz .fault
    cmp eax,3
    jne .offer
    mov dword [r12+fs_copy_job.state],FS_JOB_VERIFYING
    jmp .offer
.completed:
    cmp dword [rel fsvc_reply+68],0
    jne .fault
    cmp dword [rel fsvc_reply+88],7
    jne .fault
    mov rcx,0x100000001
    cmp qword [rel fsvc_reply+192],rcx
    jne .fault
    cmp rdx,-1
    je .fault
    cmp [r12+fs_copy_job.done],rdx
    jne .fault
    mov rax,[rel fsvc_reply+144]
    test rax,rax
    jz .fault
    cmp rax,[rel fsvc_reply+112]
    jne .fault
    cmp rax,[rel fsvc_reply+128]
    jne .fault
    cmp qword [rel fsvc_reply+120],0
    je .fault
    cmp qword [rel fsvc_reply+136],0
    je .fault
    cmp qword [rel fsvc_reply+152],0
    je .fault
    mov rax,[rel fsvc_reply+160]
    or rax,[rel fsvc_reply+168]
    or rax,[rel fsvc_reply+176]
    or rax,[rel fsvc_reply+184]
    jz .fault
    mov dword [rel fsvc_terminal],FS_JOB_DONE
    jmp .finish
.failed_reply:
    mov dword [rel fsvc_terminal],FS_JOB_FAILED
    mov edx,[rel fsvc_reply+68]
    test edx,edx
    jz .fault
    mov [r12+fs_copy_job.error],edx
    cmp eax,5
    jne .finish
    cmp dword [rel fsvc_cancel],1
    jne .fault
    test dword [rel fsvc_reply+88],9 ; published/unresolved cannot be cancelled
    jnz .fault
    mov dword [rel fsvc_terminal],FS_JOB_CANCELLED
.finish:
    ; Save the exact terminal data receipt. Linux must close its worker fds,
    ; unmount and flush before native may freeze/stop/reclaim this attachment.
    lea rdi,[rel fsvc_terminal_reply]
    lea rsi,[rel fsvc_reply]
    mov ecx,32
    cld
    rep movsq
    mov dword [rel fsvc_finishing],1
    mov dword [r12+fs_copy_job.state],FS_JOB_VERIFYING
    mov word [rel fsvc_request+6],4
    jmp .next
.finish_reply:
    ; Same terminal facts, exact next control sequence (codec), and independently
    ; returned Linux unmount+block flush. A peer cannot substitute another job's
    ; content or change the previously accepted terminal result at cleanup.
    lea rdi,[rel fsvc_reply+64]
    lea rsi,[rel fsvc_terminal_reply+64]
    mov ecx,3
    cld
    repe cmpsq
    jne .fault
    mov eax,[rel fsvc_terminal_reply+88]
    or eax,48
    cmp eax,[rel fsvc_reply+88]
    jne .fault
    mov eax,[rel fsvc_terminal_reply+92]
    cmp eax,[rel fsvc_reply+92]
    jne .fault
    mov rax,[rel fsvc_reply+96]
    cmp rax,[rel fsvc_terminal_reply+96]
    jb .fault
    lea rdi,[rel fsvc_reply+112]
    lea rsi,[rel fsvc_terminal_reply+112]
    mov ecx,11
    repe cmpsq
    jne .fault
    jmp .stop
.offer:
    mov word [rel fsvc_request+6],2
    cmp dword [rel fsvc_cancel],0
    je .next
    mov word [rel fsvc_request+6],3
.next:
    mov rax,[rel fsvc_request+248]
    inc rax
    jz .fault
    mov [rel fsvc_request+248],rax
.submit:
    mov rdi,[rel fsvc_generation]
    lea rsi,[rel fsvc_request]
    call fsg_submit
    test eax,eax
    jnz .fault
    mov dword [rel fsvc_pending],1
    jmp .ok
.fault:
    mov dword [r12+fs_copy_job.error],1
    mov dword [rel fsvc_terminal],FS_JOB_FAILED
.stop:
    mov dword [rel fsvc_retiring],1
    mov dword [r12+fs_copy_job.state],FS_JOB_VERIFYING
    mov rdi,[rel fsvc_generation]
    call fsg_stop
    test eax,eax
    jnz .quarantined
.retire:
    mov rdi,[rel fsvc_generation]
    call fsg_retire
    cmp eax,1
    je .ok
    test eax,eax
    jnz .quarantined
    mov eax,[rel fsvc_terminal]
    mov [r12+fs_copy_job.state],eax
    cmp eax,FS_JOB_DONE
    jne .ok
    mov dword [r12+fs_copy_job.durable],FS_DUR_YES
    jmp .ok
.quarantined:
    mov dword [r12+fs_copy_job.state],FS_JOB_FAILED
    mov dword [r12+fs_copy_job.error],1
    mov dword [r12+fs_copy_job.durable],FS_DUR_UNCERTAIN
.ok:
    xor eax,eax
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

; RDI=private output256, RSI=capacity ->256/0. A COPY of actual last reply;
; no guest access or reoffer. Command wrapper binds native generation/custody.
vfs_copy_service_snapshot:
    cmp rsi,256
    jb .no
    cmp dword [rel fsvc_used],1
    jne .no
    lea rsi,[rel fsvc_reply]
    mov ecx,32
    cld
    rep movsq
    mov eax,256
    ret
.no:
    xor eax,eax
    ret

 ; Original VFS assigns the actual id only after backend BEGIN. Retain it
; before publishing that job; a later reuse of the global job cannot alias it.
; RDI=actual job*, RSI=actual nonzero id ->0/-1.
vfs_copy_service_bind_job:
    cmp rdi,[rel fsvc_job]
    jne .bad
    test rsi,rsi
    jz .bad
    cmp qword [rel fsvc_job_id],0
    jne .bad
    cmp qword [rel fsvc_generation],0
    je .bad
    cmp rsi,[rdi+fs_copy_job.id]
    jne .bad
    mov eax,[rdi+fs_copy_job.mount]
    cmp rax,[rel fsvc_mount]
    jne .bad
    mov [rel fsvc_job_id],rsi
    xor eax,eax
    ret
.bad:
    mov eax,-1
    ret

; RDI=private1040out, RSI=capacity ->1040/0. Frozen by the command wrapper
; across its five pages. No IO, command, lease change or guest reoffer. Native
; addresses are removed; the profile is the signed record actually handed to
; the domain; fsg_identity compares the domain's independently retained grant.
vfs_copy_service_state:
    cmp rsi,1040
    jb .no
    cmp dword [rel fsvc_configured],1
    jne .no
    push rbx
    mov rbx,rdi
    lea rsi,[rel fsvc_grant]
    mov ecx,40
    cld
    rep movsq
    lea rsi,[rel fsvc_volume]
    mov ecx,17
    rep movsq
    mov qword [rbx+320],0          ; never expose dev*
    mov rsi,[rel fsvc_profile]
    mov ecx,35                    ; actual signed280B record, not a filename/hash label
    rep movsq
    lea rsi,[rel fsvc_reply]
    mov ecx,32
    rep movsq
    mov rax,[rel fsvc_generation]
    mov [rbx+992],rax
    mov rax,[rel fsvc_handle]
    mov [rbx+1000],rax
    mov rax,[rel fsvc_mount]
    mov [rbx+1008],rax
    xor eax,eax
    mov [rbx+1016],rax            ; domain state0, identity conflict0 before START
    mov [rbx+1024],rax
    mov [rbx+1032],rax
    cmp qword [rel fsvc_generation],0
    je .done
    mov rdi,[rel fsvc_generation]
    lea rsi,[rel fsvc_identity]
    mov edx,320
    call fsg_identity
    mov [rbx+1016],eax
    cmp eax,-1
    je .conflict
    lea rdi,[rel fsvc_grant]
    lea rsi,[rel fsvc_identity]
    mov ecx,40
    cld
    repe cmpsq
    je .job
.conflict:
    mov dword [rbx+1020],1
.job:
    mov rax,[rel fsvc_job]
    test rax,rax
    jz .done
    mov rdx,[rax+fs_copy_job.id]
    test rdx,rdx
    jz .job_conflict
    cmp rdx,[rel fsvc_job_id]
    jne .job_conflict
    mov ecx,[rax+fs_copy_job.mount]
    cmp rcx,[rel fsvc_mount]
    je .job_copy
.job_conflict:
    mov dword [rbx+1020],1
.job_copy:
    mov [rbx+1024],rdx
    mov edx,[rax+fs_copy_job.state]
    mov [rbx+1032],edx
    mov edx,[rax+fs_copy_job.durable]
    mov [rbx+1036],edx
.done:
    mov eax,1040
    pop rbx
    ret
.no:
    xor eax,eax
    ret

fsvc_mount_name: db 'fs-service',0
fsvc_backend_name: db 'isolated-linux-copy',0
%macro WDATA_fs_copy_service 0
align 8
vfs_copy_service_ops:
    times fs_ops_size db 0
fsvc_profile: dq 0
fsvc_generation: dq 0
fsvc_handle: dq 0
fsvc_mount: dq -1
fsvc_job: dq 0
fsvc_job_id: dq 0
fsvc_last_total: dq -1
fsvc_configured: dd 0
fsvc_used: dd 0
fsvc_pending: dd 0
fsvc_cancel: dd 0
fsvc_retiring: dd 0
fsvc_terminal: dd 0
fsvc_finishing: dd 0
fsvc_grant: times 320 db 0
fsvc_volume: times 136 db 0
fsvc_request: times 256 db 0
fsvc_reply: times 256 db 0
fsvc_terminal_reply: times 256 db 0
fsvc_identity: times 320 db 0
%endmacro
WDATA_DEFER WDATA_fs_copy_service
