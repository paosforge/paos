;; MODULE hv/filesystem_domain
;; LAYER 5
;; EXPORTS fsg_reply_validate, fsg_begin, fsg_submit, fsg_poll, fsg_stop, fsg_retire, fsg_identity, fsg_attachment, fsg_current, fsg_prepare, fsg_backend_stopped, fsg_cmdline, fsg_fault, fsg_tick
;; IMPORTS hv/driver_domain, hv/vmx, hv/vm_profile, hv/filesystem_wire, hv/guestfilesystem, fs/guest_volume, fs/fs_format, core/time
;; CAPS extension
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Original native supervisor, one copy or confirmed-format attachment/job/START. These APIs are
; INTERNAL to the independently authorized VFS owner, never guest endpoints.
; All callers share the BSP cooperative guest boundary. No waiting or retries.
; A fault freezes storage before asking STOP and retains custody until the
; actual loader/backend terminal boundary. Peer ACK/terminal is not CPU-off.

; Native buffers must not alias owner storage or live/retained guest reserve.
; RDI=pointer, RSI=fixed length ->0/-1. No arbitrary guest pointer accepted.
fsg_span:
    test rdi,rdi
    jz .bad
    mov rax,rdi
    add rax,rsi
    jc .bad
    mov rdx,0x0000800000000000
    cmp rax,rdx
    ja .bad
    lea rdx,[rel fsg_storage_end]
    cmp rdi,rdx
    jae .ram
    lea rdx,[rel fsg_storage]
    cmp rax,rdx
    ja .bad
.ram:
    lea rdx,[rel gf_storage_end]
    cmp rdi,rdx
    jae .guest_ram
    lea rdx,[rel gf_storage]
    cmp rax,rdx
    ja .bad
.guest_ram:
    mov rdx,[rel hv_linux_region]
    test rdx,rdx
    jz .ok
    mov rcx,rdx
    add rcx,[rel hv_linux_region_capacity]
    jc .bad
    cmp rdi,rcx
    jae .ok
    cmp rax,rdx
    ja .bad
.ok:
    xor eax,eax
    ret
.bad:
    mov eax,-1
    ret

; RDI=signed built-in profile, RSI=independently authorized copy136/format144,
; RDX=native-authored FSG1 320, RCX=START256(sequence1). ->STARTgen or0.
; No authority from a package string, guest disk identity or echoed FSC1.
fsg_begin:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,8
    mov rbx,rdi
    mov r12,rsi
    mov r13,rdx
    mov r14,rcx
    cmp dword [rel fsg_state],0
    jne .bad
%ifdef PAOS_NIC_ASSIGNMENT
    ; Refuse before acquiring the partition lease or changing the profile.
    cmp dword [rel nd_state],1
    je .bad
    cmp dword [rel nd_state],2
    je .bad
    cmp dword [rel nd_state],3
    je .bad
    cmp dword [rel nd_state],6
    je .bad
%endif
    cmp byte [rel hv_linux_running],0
    jne .bad
    cmp byte [rel hv_linux_start_active],0
    jne .bad
    cmp byte [rel hv_linux_run_req],0
    jne .bad
    cmp byte [rel hv_linux_vmx_live],0
    jne .bad
    cmp qword [rel hv_svm_cur_vmcb],0
    jne .bad
    cmp byte [rel cdp_bound],0
    jne .bad
    cmp byte [rel gws_bound],0
    jne .bad
    cmp byte [rel hvp_bound],0
    jne .bad
    cmp byte [rel hvw_bound],0
    jne .bad
    cmp byte [rel padc_bound],0
    jne .bad
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    cmp byte [rel hv_vcon_pmr_bound],0
    jne .bad
%endif
%endif
    mov rdi,rbx
    call vp_pair_trusted
    test eax,eax
    jnz .bad
    cmp dword [rbx+VP_DEVICES],VP_DEV_FSDOMAIN
    jne .bad
    cmp dword [rbx+VP_VCPUS],1
    jne .bad
    mov rdi,r12
    mov esi,136
    call fsg_span
    test eax,eax
    jnz .bad
    mov rdi,r13
    mov esi,320
    call fsg_span
    test eax,eax
    jnz .bad
    mov rdi,r14
    mov esi,256
    call fsg_span
    test eax,eax
    jnz .bad
    mov rdi,r13
    mov rsi,r14
    call fsc_grant_validate
    test eax,eax
    jnz .bad
    cmp qword [r14+248],1
    jne .bad
    cmp word [r13+6],2
    jne .lease_identity
    mov rdi,r12
    mov esi,144
    call fsg_span
    test eax,eax
    jnz .bad
    mov rax,[r12+16]
    cmp rax,[r13+96]
    jne .bad
    movzx eax,byte [r13+200]
    cmp eax,[r12+136]
    jne .bad
    movzx eax,byte [r13+201]
    cmp eax,[r12+140]
    jne .bad
.lease_identity:
    ; Exact private lease tuple -> independent native grant.
    mov rax,[r12+128]
    cmp rax,[r13+72]
    jne .bad
    lea rdi,[r12+64]                ; principal
    lea rsi,[r13+40]
    mov ecx,2
    cld
    repe cmpsq
    jne .bad
    lea rdi,[r12+80]                ; job
    lea rsi,[r13+24]
    mov ecx,2
    repe cmpsq
    jne .bad
    lea rdi,[r12+96]                ; request + attachment
    lea rsi,[r13+8]
    mov ecx,2
    repe cmpsq
    jne .bad
    lea rsi,[r13+56]
    mov ecx,2
    repe cmpsq
    jne .bad
    mov rax,[r12+24]
    mov rdx,rax
    shr rdx,55
    jnz .bad
    shl rax,9
    cmp rax,[r13+280]
    jne .bad
    call time_monotonic_now_us
    test rax,rax
    jz .bad
    mov [rel fsg_clock],rax
    mov edx,[r13+88]
    imul rdx,1000
    add rax,rdx
    jc .bad
    mov [rel fsg_deadline],rax      ; includes startup/mount, never extended
    ; Capture independent metadata BEFORE any lease/backend callback.
    lea rdi,[rel fsg_grant]
    mov rsi,r13
    mov ecx,40
    rep movsq
    lea rdi,[rel fsg_request]
    mov rsi,r14
    mov ecx,32
    rep movsq
    lea rdi,[rel fsg_initial]
    lea rsi,[rel fsg_request]
    mov ecx,32
    rep movsq
    cmp word [rel fsg_grant+6],2
    jne .copy_acquire
    lea rdi,[rel fsg_authorized]
    mov rsi,r12
    mov ecx,18
    rep movsq
    lea rdi,[rel fsg_grant+184]
    call fs_format_bind_start       ; original F1 decision, once; never guest input
    test eax,eax
    jnz .bad
    lea rdi,[rel fsg_authorized]
    call guest_volume_acquire_format
    jmp .acquired
.copy_acquire:
    mov rdi,r12
    call guest_volume_acquire
.acquired:
    test rax,rax
    jz .bad
    mov [rel fsg_handle],rax
    mov rdi,rax
    lea rsi,[rel fsg_volume]
    mov edx,136
    cmp word [rel fsg_grant+6],2
    jne .snapshot
    mov edx,144
.snapshot:
    call guest_volume_snapshot
    test rax,rax
    jnz .acquired_bad
    cmp word [rel fsg_grant+6],2
    jne .copy_vbr
    lea rdi,[rel fsg_volume]
    call fs_format_custody          ; exact original F1 incarnation/extent
    test eax,eax
    jnz .acquired_bad
    lea rdi,[rel fsg_volume]
    lea rsi,[rel fsg_authorized]
    mov ecx,18                     ; full original descriptor, including kind/slot
    cld
    repe cmpsq
    jne .acquired_bad
    mov rdi,[rel fsg_handle]
    call guest_volume_current      ; live media/lease; acquire_format owns geometry
    test rax,rax
    jnz .acquired_bad
    jmp .metadata_ready            ; no filesystem/VBR precondition for FORMAT
.copy_vbr:
    mov rdi,[rel fsg_handle]
    xor esi,esi
    mov edx,1
    lea rcx,[rel fsg_vbr]
    call guest_volume_read
    test rax,rax
    jnz .acquired_bad
    mov rax,0x202020205346544e
    cmp rax,[rel fsg_vbr+3]         ; NTFS VBR, actual leased relative LBA0
    jne .acquired_bad
    cmp word [rel fsg_vbr+11],512
    jne .acquired_bad
    cmp word [rel fsg_vbr+510],0xaa55
    jne .acquired_bad
    mov rax,[rel fsg_vbr+72]
    cmp rax,[rel fsg_grant+96]
    jne .acquired_bad
    mov rax,[rel fsg_vbr+40]
    test rax,rax
    jz .acquired_bad
    cmp rax,[rel fsg_volume+24]
    ja .acquired_bad
.metadata_ready:
    call time_monotonic_now_us
    cmp rax,[rel fsg_clock]
    jb .acquired_bad
    cmp rax,[rel fsg_deadline]
    jae .acquired_bad              ; charge FULL acquisition/read cost before START
    mov [rel fsg_clock],rax
    mov ebp,[rel hv_linux_start_gen]
    inc ebp
    jz .acquired_bad
    mov rdi,rbx
    mov esi,ebp
    call vm_profile_request
    test eax,eax
    jnz .acquired_bad
    call hv_guest_linux_request_start
    cmp eax,ebp
    jne .acquired_bad
    mov [rel fsg_generation],rax
    mov [rel vm_profile_gen],eax
    mov [rel fsg_profile],rbx
    mov dword [rel fsg_state],1     ; armed, original first request retained
    mov dword [rel fsg_pending],1
    mov dword [rel fsg_ready],0
    mov qword [rel fsg_sequence],1
    mov qword [rel fsg_frame_deadline],0
    jmp .out
.acquired_bad:
    ; No START was published on these admitted failures. Format uncertainty
    ; retains custody; the legacy copy path consumes known-no-CPU reclaim once.
    mov rdi,[rel fsg_handle]
    call guest_volume_freeze
    cmp word [rel fsg_grant+6],2
    je .quarantined               ; uncertain acquisition keeps original custody
    mov rdi,[rel fsg_handle]
    mov rsi,[rel fsg_grant+72]
    call guest_volume_reclaim
    test rax,rax
    jnz .quarantined
    lea rdi,[rel fsg_storage]
    mov ecx,fsg_storage_end-fsg_storage
    xor eax,eax
    cld
    rep stosb
    jmp .bad
.quarantined:
    mov dword [rel fsg_state],6     ; quarantine, never automatic reuse
.bad:
    xor eax,eax
.out:
    add rsp,8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Loader hook after exact selected/live map and actual RAM construction.
fsg_prepare:
    cmp dword [rel fsg_state],1
    jne .bad
    mov eax,[rel hv_linux_start_consumed]
    cmp rax,[rel fsg_generation]
    jne .bad
    cmp eax,[rel hv_linux_start_gen]
    jne .bad
    cmp eax,[rel vm_profile_gen]
    jne .bad
    mov rax,[rel vm_profile_active]
    cmp rax,[rel fsg_profile]
    jne .bad
    cmp dword [rel vm_profile_live_devices],VP_DEV_FSDOMAIN
    jne .bad
    mov rax,[rel hv_linux_ram]
    mov [rel fsg_ram],rax
    mov rax,[rel hv_linux_ram_bytes]
    mov [rel fsg_ram_bytes],rax
    mov rax,[rel hv_linux_region]
    mov [rel fsg_region],rax
    mov rax,[rel hv_linux_region_capacity]
    mov [rel fsg_capacity],rax
    mov rax,[rel hv_ops_active]
    mov [rel fsg_backend],rax
    mov dword [rel fsg_state],2
    jmp guestfilesystem_reset
.bad:
    xor eax,eax
    ret

; Exact currently stopped-vCPU service owner; no guest access on refusal.
fsg_current:
    cmp dword [rel fsg_state],2
    jne .bad
    cmp byte [rel hv_linux_running],1
    jne .bad
    cmp byte [rel hv_linux_stop_req],0
    jne .bad
    cmp byte [rel hv_linux_start_active],1
    jne .bad
    mov eax,[rel hv_linux_start_consumed]
    cmp rax,[rel fsg_generation]
    jne .bad
    cmp eax,[rel hv_linux_start_gen]
    jne .bad
    cmp eax,[rel vm_profile_gen]
    jne .bad
    cmp dword [rel vm_profile_dev_mask],VP_DEV_FSDOMAIN
    jne .bad
    cmp dword [rel vm_profile_live_devices],VP_DEV_FSDOMAIN
    jne .bad
%macro FSG_SAME 2
    mov rax,[rel %1]
    cmp rax,[rel %2]
    jne .bad
%endmacro
    FSG_SAME vm_profile_active,fsg_profile
    FSG_SAME hv_ops_active,fsg_backend
    FSG_SAME hv_linux_ram,fsg_ram
    FSG_SAME hv_linux_ram_bytes,fsg_ram_bytes
    FSG_SAME hv_linux_region,fsg_region
    FSG_SAME hv_linux_region_capacity,fsg_capacity
%unmacro FSG_SAME 2
    sub rsp,8
    call time_monotonic_now_us
    add rsp,8
    cmp rax,[rel fsg_clock]
    jb .bad
    cmp rax,[rel fsg_deadline]
    jae .bad
    mov [rel fsg_clock],rax
    mov rcx,[rel fsg_frame_deadline]
    test rcx,rcx
    jz .ok
    cmp rax,rcx
    jae .bad
.ok:
    sub rsp,8
    mov rdi,[rel fsg_handle]
    call guest_volume_current
    add rsp,8
    test rax,rax
    jnz .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; EDI=exact START ->0 stop requested/-1 stale. Freeze before STOP publication.
fsg_stop:
    cmp rdi,[rel fsg_generation]
    jne .bad
    cmp dword [rel fsg_state],1
    jb .bad
    cmp dword [rel fsg_state],3
    ja .bad
    sub rsp,8
    mov rdi,[rel fsg_handle]
    call guest_volume_freeze
    mov dword [rel fsg_state],3
    mov byte [rel hv_linux_stop_req],1
    cmp byte [rel hv_linux_start_active],0
    jne .requested
    mov eax,[rel hv_linux_start_consumed]
    cmp rax,[rel fsg_generation]
    je .requested
    ; Exact armed request, never consumed: withdraw before known-no-CPU reclaim.
    mov eax,[rel hv_linux_start_gen]
    cmp rax,[rel fsg_generation]
    jne .requested
    mov byte [rel hv_linux_run_req],0
    mov edi,eax
    call vm_profile_pair_finish
    cmp word [rel fsg_grant+6],2
    jne .armed_reclaim
    cmp dword [rel fsg_faulted],0
    jne .armed_quarantine
.armed_reclaim:
    mov rdi,[rel fsg_handle]
    mov rsi,[rel fsg_grant+72]
    call guest_volume_reclaim
    mov dword [rel fsg_state],5
    test rax,rax
    jz .requested
.armed_quarantine:
    mov dword [rel fsg_state],6
.requested:
    add rsp,8
    xor eax,eax
    ret
.bad:
    mov eax,-1
    ret

fsg_fault:
    mov dword [rel fsg_faulted],1
    mov rdi,[rel fsg_generation]
    jmp fsg_stop

; Every clean exit: fail closed on deadline/STOP/identity before queue access.
fsg_tick:
    cmp dword [rel fsg_state],2
    jne .out
    sub rsp,8
    call fsg_current
    test eax,eax
    jnz .live
    call fsg_fault
    jmp .done
.live:
    call guestfilesystem_pump
.done:
    add rsp,8
.out:
    ret

; Exact native terminal hook. This hook is never exported as a wire command.
; No speculative flag polling earns reclaim; actual backend caller owns it.
fsg_backend_stopped:
    cmp dword [rel fsg_state],1
    jb .out
    cmp dword [rel fsg_state],3
    ja .out
    mov eax,[rel hv_linux_start_consumed]
    cmp rax,[rel fsg_generation]
    jne .out
    sub rsp,8
    mov rdi,[rel fsg_generation]
    call fsg_stop
    ; Native terminal return must also prove both execution engines inactive.
    ; An uncertain backend keeps the lease/RAM quarantined, never reclaimed.
    cmp byte [rel hv_linux_running],0
    jne .uncertain
    cmp byte [rel hv_linux_vmx_live],0
    jne .uncertain
    cmp qword [rel hv_svm_cur_vmcb],0
    jne .uncertain
    call guestfilesystem_zero
    cmp word [rel fsg_grant+6],2
    jne .reclaim
    cmp dword [rel fsg_faulted],0
    jne .uncertain
.reclaim:
    mov rdi,[rel fsg_handle]
    mov rsi,[rel fsg_grant+72]
    call guest_volume_reclaim
    mov dword [rel fsg_state],5
    test rax,rax
    jz .done
.uncertain:
    mov dword [rel fsg_state],6     ; no custody release after uncertainty
.done:
    add rsp,8
.out:
    ret

; RDI=START, RSI=private256 STATUS/CANCEL/FINISH ->0queued/-1refused. One outstanding
; spans transport delivery AND consumer drain. No retry or sequence reuse.
fsg_submit:
    push rbx
    push r12
    sub rsp,8
    mov r12,rdi
    mov rbx,rsi
    cmp r12,[rel fsg_generation]
    jne .bad
    cmp dword [rel fsg_pending],0
    jne .bad
    cmp dword [rel fsg_ready],0
    jne .bad
    call fsg_current
    test eax,eax
    jz .bad
    mov rdi,rbx
    mov esi,256
    call fsg_span
    test eax,eax
    jnz .bad
    mov rdi,rbx
    call fsc_wire_request
    test eax,eax
    jnz .bad
    mov ax,[rel fsg_initial+4]
    cmp ax,[rbx+4]
    jne .bad
    cmp word [rbx+6],2
    jb .bad
    mov rax,[rel fsg_sequence]
    inc rax
    jz .bad
    cmp rax,[rbx+248]
    jne .bad
    lea rdi,[rbx+8]
    lea rsi,[rel fsg_initial+8]
    mov ecx,30                      ; v2 keeps all identity/names/padding
    cmp word [rbx+4],3
    jne .control_identity
    mov ecx,9                       ; v3 controls have zero80..247, already validated
.control_identity:
    cld
    repe cmpsq
    jne .bad
    mov [rel fsg_sequence],rax
    lea rdi,[rel fsg_request]
    mov rsi,rbx
    mov ecx,32
    rep movsq
    mov dword [rel fsg_tx_offset],0
    mov dword [rel fsg_rx_offset],0
    mov dword [rel fsg_pending],1
    xor eax,eax
    jmp .out
.bad:
    mov eax,-1
.out:
    add rsp,8
    pop r12
    pop rbx
    ret

; RDI=private reply, RSI=outstanding request ->0/-1. The pure wire
; syntax validator has no retained job. Bind every v3 echo to original START
; here, including STATUS/CANCEL/FINISH whose request payload is all zero.
fsg_reply_validate:
    push rbx
    mov rbx,rdi
    call fsc_wire_reply
    test eax,eax
    jnz .out
    cmp word [rbx+4],3
    jne .out
    cmp dword [rbx+64],7             ; identity-only refusal has no filesystem echo
    je .out
    mov ax,[rel fsg_initial+80]
    cmp ax,[rbx+112]
    jne .bad
    xor eax,eax
    jmp .out
.bad:
    mov eax,-1
.out:
    pop rbx
    ret

; RDI=START, RSI=private256out ->256complete/0pending/-1refused.
; Peer terminal is an observation only: caller then STOPs and retires before
; granting native access or presenting final custody/durability to the user.
fsg_poll:
    push rbx
    push r12
    sub rsp,8
    mov rbx,rsi
    cmp rdi,[rel fsg_generation]
    jne .bad
    cmp dword [rel fsg_state],6
    je .bad
    cmp dword [rel fsg_state],0
    je .bad
    mov rdi,rbx
    mov esi,256
    call fsg_span
    test eax,eax
    jnz .bad
    cmp dword [rel fsg_ready],1
    jne .pending
    mov rdi,rbx
    lea rsi,[rel fsg_response]
    mov ecx,32
    cld
    rep movsq
    mov dword [rel fsg_ready],0
    mov eax,256
    jmp .out
.pending:
    cmp dword [rel fsg_faulted],0
    jne .bad
    xor eax,eax
    jmp .out
.bad:
    mov eax,-1
.out:
    add rsp,8
    pop r12
    pop rbx
    ret

; RDI=START ->0 actual stopped+flush+reclaim complete/1pending/-1quarantine.
; Terminal observation may be taken BEFORE this call; successful retire clears
; original owner storage only once. Stale callers cannot stop a replacement.
fsg_retire:
    cmp rdi,[rel fsg_generation]
    jne .bad
    cmp dword [rel fsg_state],6
    je .bad
    cmp dword [rel fsg_state],5
    jne .pending
    cmp byte [rel hv_linux_start_active],0
    jne .pending
    cmp byte [rel hv_linux_running],0
    jne .pending
    lea rdi,[rel fsg_storage]
    mov ecx,fsg_storage_end-fsg_storage
    xor eax,eax
    cld
    rep stosb
    ret
.pending:
    mov eax,1
    ret
.bad:
    mov eax,-1
    ret

; Pure native identity readback. No clock or backend call, no guest authority.
; RDI=START, RSI=private320out, RDX=capacity ->state/-1. Does not consume state.
fsg_identity:
    cmp rdi,[rel fsg_generation]
    jne .bad
    cmp dword [rel fsg_state],0
    je .bad
    cmp rdx,320
    jb .bad
    push rbx
    mov rbx,rsi
    mov rdi,rsi
    mov esi,320
    call fsg_span
    test eax,eax
    jnz .invalid
    mov rdi,rbx
    lea rsi,[rel fsg_grant]
    mov ecx,40
    cld
    rep movsq
    mov eax,[rel fsg_state]
    pop rbx
    ret
.invalid:
    pop rbx
.bad:
    mov eax,-1
    ret

; Pure service-mount binding after successful BEGIN; never wire-visible.
fsg_attachment:
    cmp rdi,[rel fsg_generation]
    jne .bad
    cmp dword [rel fsg_state],1
    jb .bad
    cmp dword [rel fsg_state],3
    ja .bad
    mov rax,[rel fsg_handle]
    ret
.bad:
    xor eax,eax
    ret

; Signed profile cmdline seam: RAX=private terminated native metadata or0.
; It is constructed from retained native grant bytes, never a guest response.
fsg_cmdline:
    cmp dword [rel fsg_state],1
    jne .bad
    mov rax,[rel vm_profile_active]
    cmp rax,[rel fsg_profile]
    jne .bad
    lea rdi,[rel fsg_bootparam]
    lea rsi,[rel fsg_param_prefix]
    mov ecx,fsg_param_prefix_end-fsg_param_prefix
    cld
    rep movsb
    lea rsi,[rel fsg_grant]
    lea rdx,[rel fsg_hex]
    mov ecx,320
.hex:
    movzx eax,byte [rsi]
    mov r8d,eax
    shr eax,4
    mov al,[rdx+rax]
    stosb
    and r8d,15
    mov al,[rdx+r8]
    stosb
    inc rsi
    loop .hex
    mov byte [rdi],0
    lea rax,[rel fsg_bootparam]
    ret
.bad:
    xor eax,eax
    ret

fsg_param_prefix: db ' paos.fsg1='
fsg_param_prefix_end:
fsg_hex: db '0123456789abcdef'

%include "core/abi/wdata.inc"
%macro WDATA_hv_filesystem_domain 0
align 16
fsg_storage:
fsg_state: dd 0
fsg_faulted: dd 0
fsg_pending: dd 0
fsg_ready: dd 0
fsg_generation: dq 0
fsg_sequence: dq 0
fsg_handle: dq 0
fsg_clock: dq 0
fsg_deadline: dq 0
fsg_frame_deadline: dq 0
fsg_profile: dq 0
fsg_backend: dq 0
fsg_region: dq 0
fsg_capacity: dq 0
fsg_ram: dq 0
fsg_ram_bytes: dq 0
fsg_tx_offset: dd 0
fsg_rx_offset: dd 0
fsg_volume: times 144 db 0
fsg_authorized: times 144 db 0
fsg_vbr: times 512 db 0
fsg_grant: times 320 db 0
fsg_initial: times 256 db 0
fsg_request: times 256 db 0
fsg_response: times 256 db 0
fsg_bootparam: times 652 db 0
fsg_storage_end:
%endmacro
WDATA_DEFER WDATA_hv_filesystem_domain
