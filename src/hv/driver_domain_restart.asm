;; MODULE hv/driver_domain_restart
;; LAYER 5
;; EXPORTS nd_restart_register, nd_restart_select, nd_restart_select_owner, nd_restart_clock, nd_restart_run, nd_restart_finish, nd_restart_byte, nd_restart_record, ndr_phase
;; IMPORTS svc/command_udp, dev/net/virtio_domain, hv/driver_domain_failure, hv/driver_domain_power, hv/driver_domain_command, svc/command, core/time, hv/driver_domain, hv/driver_domain_return, hv/vmx, hv/vm_profile, hv/nic_assignment, hv/pci_assign, hv/guest_power, core/sched, core/smp, core/lib/sha256, svc/command_auth, fs/storage_access, boot/header
;; CAPS extension
;; OWNER rc-vm-claude
;; CONTEXT: bsp_only
; Explicit owner selection is inert until original signed-return ACK. The
; selected mode either requires C9 failure/service or actual orderly owner STOP.
; Both modes require exact old retirement before any fresh START.
; A distinct generation reloads the same trusted signed profile via nd_begin.
; Useful work is actual virtio TX SHA output, not START/readiness or input echo.
ND_RESTART_BYTES equ 1536
ND_RESTART_MS equ 80000
nd_restart_register:
    lea rdi,[rel ndr_verb]
    lea rsi,[rel ndr_command]
    mov rdx,CMD_AUTH_CAP_MUTATE
    mov ecx,ARGT_TEXT
    xor r8d,r8d
    mov r9d,1
    jmp command_register_verb
ndr_command:
    push rbx
    push r12
    sub rsp,8
    call cmd_handler_prologue
    mov r12,rsi
    mov rbx,[rdi+REQ_ARG]
    call hv_out_reset
    call storage_access_request_owner
    cmp eax,1
    jne .bad
    call storage_access_request_intent
    cmp eax,SA_INTENT_SPECIAL
    jne .bad
    mov rdi,rbx
    lea rsi,[rel ndr_arg_start]
    mov edx,24
    call nd_token
    test rax,rax
    jz .bad
    mov rdi,rax
    lea rsi,[rel ndr_arg_nonce]
    mov edx,17
    call nd_token
    test rax,rax
    jz .bad
    mov rdi,rax
    lea rsi,[rel ndr_arg_probe]
    mov edx,17
    call nd_token
    test rax,rax
    jz .bad
    mov dword [rel ndr_arg_mode],0
    cmp byte [rax],0
    je .arguments
    mov rdi,rax
    lea rsi,[rel ndr_arg_stop]
    mov edx,5
    call nd_token
    test rax,rax
    jz .bad
    cmp dword [rel ndr_arg_stop],0x504f5453 ; explicit STOP, not a fault
    jne .bad
    cmp byte [rel ndr_arg_stop+4],0
    jne .bad
    mov rdi,rax
    lea rsi,[rel ndr_arg_challenge]
    mov edx,17
    call nd_token
    test rax,rax
    jz .bad
    cmp byte [rax],0
    jne .bad
    mov dword [rel ndr_arg_mode],1
.arguments:
    cmp byte [rel ndr_arg_start],'1'
    jb .bad
    cmp byte [rel ndr_arg_start],'9'
    ja .bad
    lea rdi,[rel ndr_arg_start]
    mov esi,10
    mov edx,10
    call nd_number
    jc .bad
    mov edi,eax
    lea rsi,[rel ndr_arg_nonce]
    lea rdx,[rel ndr_arg_probe]
    cmp dword [rel ndr_arg_mode],1
    je .owner_select
    call nd_restart_select
    jmp .selected
.owner_select:
    lea rcx,[rel ndr_arg_challenge]
    call nd_restart_select_owner
.selected:
    test eax,eax
    jnz .bad
    lea rdi,[rel ndr_ok]
    call hv_out_str
    lea rdi,[rel ndr_arg_start]
    call hv_out_str
    lea rdi,[rel nd_space]
    call hv_out_str
    lea rdi,[rel ndr_arg_nonce]
    call hv_out_str
    lea rdi,[rel nd_space]
    call hv_out_str
    lea rdi,[rel ndr_arg_probe]
    call hv_out_str
    cmp dword [rel ndr_arg_mode],1
    jne .done
    lea rdi,[rel ndr_stop_ack]
    call hv_out_str
    lea rdi,[rel ndr_arg_challenge]
    call hv_out_str
    jmp .done
.bad:
    lea rdi,[rel ndr_bad]
    call hv_out_str
.done:
    mov byte [rel hv_out_ready],1
    mov qword [r12+RSP_CODE],CMDE_OK
    add rsp,8
    pop r12
    pop rbx
    ret

; RDI=old START,RSI=old nonce17,RDX=fresh restart nonce17 ->0/-1.
nd_restart_select:
    xor ecx,ecx                    ; legacy crash selection unchanged
nd_restart_select_owner:            ; RCX=explicit owner challenge17, or NULL C9
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r14,rcx
    mov rbx,rdi
    mov r12,rsi
    mov r13,rdx
    cmp dword [rel ndr_phase],0
    jne .bad
    test r14,r14
    jnz .owner_phase
    cmp dword [rel ndf_phase],1
    jne .bad
    cmp rbx,[rel nd_failure_record+16]
    jne .bad
    jmp .phase_ok
.owner_phase:
    cmp dword [rel ndf_phase],0
    jne .bad
.phase_ok:
    test rbx,rbx
    jz .bad
    mov eax,0xffffffff
    cmp rbx,rax
    jae .bad
    cmp rbx,[rel nd_generation]
    jne .bad
    mov rdi,r12
    call nd_nonce_valid
    test eax,eax
    jz .bad
    lea rdi,[rel nd_nonce]
    mov rsi,r12
    mov ecx,17
    cld
    repe cmpsb
    jne .bad
    mov rdi,r13
    call nd_nonce_valid
    test eax,eax
    jz .bad
    lea rdi,[rel nd_nonce]
    mov rsi,r13
    mov ecx,16
    repe cmpsb
    je .bad
    lea r15,[rel nd_failure_record+160]
    test r14,r14
    jz .challenge
    mov rdi,r14
    call nd_nonce_valid
    test eax,eax
    jz .bad
    mov rdi,r14
    mov rsi,r12
    mov ecx,16
    repe cmpsb
    je .bad
    mov r15,r14
.challenge:
    mov rdi,r15
    mov rsi,r13
    mov ecx,16
    repe cmpsb
    je .bad
    call hv_guest_power_admit
    test rax,rax
    jnz .bad
    call nd_current
    test eax,eax
    jz .bad
    cmp dword [rel nd_operational],1
    jne .bad
    cmp byte [rel hv_linux_panicked],0
    jne .bad
    mov rdi,[rel nd_profile]
    call vp_pair_trusted
    test eax,eax
    jnz .bad
    call boot_ms_now
    test rax,rax
    jz .bad
    test r14,r14
    jnz .clock_ok
    cmp rax,[rel nd_failure_record+48]
    jb .bad
.clock_ok:
    mov [rel ndr_selected_ms],rax
    lea rdi,[rel nd_restart_record]
    xor eax,eax
    mov ecx,ND_RESTART_BYTES/8
    rep stosq
    mov rax,0x003152545352444e ; NDRSTR1 NUL
    mov [rel nd_restart_record],rax
    mov dword [rel nd_restart_record+8],4
    test r14,r14
    jz .version_ok
    mov dword [rel nd_restart_record+8],2
    mov dword [rel nd_restart_record+224],1
.version_ok:
    mov dword [rel nd_restart_record+12],ND_RESTART_BYTES
    mov [rel nd_restart_record+16],rbx
    lea rdi,[rel nd_restart_record+24]
    mov rsi,r12
    mov ecx,16
    rep movsb
    mov eax,[rel nd_bdf]
    mov [rel nd_restart_record+40],eax
    mov dword [rel nd_restart_record+44],1
    mov rax,[rel ndr_selected_ms]
    mov [rel nd_restart_record+48],rax
    inc rbx
    mov [rel nd_restart_record+80],rbx
    lea rdi,[rel ndr_nonce]
    mov rsi,r13
    mov ecx,17
    rep movsb
    lea rdi,[rel nd_restart_record+88]
    mov rsi,r13
    mov ecx,16
    rep movsb
    lea rdi,[rel nd_restart_record+104]
    mov rsi,r15
    mov ecx,16
    rep movsb
    mov rax,[rel nd_profile]
    mov [rel ndr_profile],rax
    lea rdi,[rel nd_restart_record+520]
    mov rsi,rax
    mov ecx,35
    rep movsq
    mov eax,[rel nd_selector+24]
    mov [rel nd_restart_record+200],eax
    call ndr_build_work
    test eax,eax
    jz .bad
    cmp dword [rel nd_restart_record+8],4
    jne .selected
    lea rdi,[rel nd_restart_record+1184]
    call virtio_domain_restart_observation
.selected:
    mov dword [rel ndr_phase],1
    xor eax,eax
    jmp .out
.bad:
    mov eax,-1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; RAX=actual now, EAX=0 original boot,1 exact bounded restart,-1 refusal.
; Only original return owner sets this window, after actual old retirement.
; No boot origin, original first-boot deadline or RUN deadline is renewed.
nd_restart_clock:
    cmp qword [rel ndr_deadline],0
    je .original
    cmp dword [rel ndr_phase],2
    jne .bad
    cmp rax,[rel ndr_last_ms]
    jb .bad
    cmp rax,[rel ndr_deadline]
    jae .bad
    mov rcx,[rel nd_generation]
    cmp rcx,[rel nd_restart_record+80]
    je .yes
    cmp rcx,[rel nd_restart_record+16]
    jne .bad
.yes:
    mov eax,1
    ret
.original:
    xor eax,eax
    ret
.bad:
    mov eax,-1
    ret

nd_restart_run:
    push rbx
    push r12
    push r13
    cmp dword [rel ndr_phase],1
    jne .out
    mov dword [rel ndr_phase],2
    mov dword [rel nd_restart_record+44],2
    cmp dword [rel nd_restart_record+224],1
    je .owner_phase
    cmp dword [rel ndf_phase],2
    jne .out
    jmp .phase_ok
.owner_phase:
    cmp dword [rel ndf_phase],0
    jne .out
.phase_ok:
    mov rax,[rel nd_generation]
    cmp rax,[rel nd_restart_record+16]
    jne .out
    cmp dword [rel nd_restart_record+224],1
    jne .quiesce
    lea rdi,[rel nd_restart_record+232]
    call nd_power_restart_step         ; T5-1.C10b-1b u2: bounded clean Shut down; never nd_stop
.quiesce:
    lea rdi,[rel nd_restart_record+392]
    call nd_quiesce
    cmp dword [rel nd_restart_record+224],1
    je .old_result
    call nd_failure_finish
.old_result:
    test eax,eax
    jz .old_clean
    cmp eax,2                       ; safe late retirement retains original meaning
    jne .out
.old_clean:
    cmp dword [rel nd_restart_record+224],1
    je .owner_retired
    cmp dword [rel nd_failure_record+44],0
    jne .out
    jmp .old_complete
.owner_retired:
    lea rdi,[rel nd_restart_record+1184]
    call pcia_iommu_receipt
    mov [rel nd_restart_record+228],eax
    test eax,eax
    jnz .out
    lea rbx,[rel nd_restart_record+1184]
    mov rax,[rel nd_restart_record+16]
    call ndr_retired_exact
    test eax,eax
    jz .out
.old_complete:
    cmp dword [rel nd_restart_record+8],4
    jne .old_observed
    lea rdi,[rel nd_restart_record+1288]
    call virtio_domain_restart_observation
.old_observed:
    lea rsi,[rel nd_restart_record+520]
    mov rdi,[rel ndr_profile]
    mov ecx,35
    cld
    repe cmpsq
    jne .out
    call boot_ms_now
    cmp rax,[rel nd_restart_record+448] ; actual old quiescence end, both modes
    jb .clock
    cmp dword [rel nd_restart_record+224],1
    je .begin
    cmp rax,[rel nd_failure_record+64]
    jb .clock
.begin:
    mov [rel nd_restart_record+56],rax
    mov [rel ndr_last_ms],rax
    add rax,ND_RESTART_MS
    jc .clock
    mov [rel ndr_deadline],rax
    mov [rel nd_restart_record+64],rax
    mov dword [rel nd_restart_record+44],3
    mov rdi,[rel ndr_profile]
    mov esi,[rel nd_restart_record+40]
    lea rdx,[rel ndr_nonce]
    call nd_begin                    ; all original allocation/NIC/profile guards
    cmp rax,[rel nd_restart_record+80]
    jne .out
    cmp dword [rel nd_restart_record+8],4
    jne .net_started
    mov rdi,[rel nd_restart_record+80]
    lea rsi,[rel ndr_nonce]
    lea rdx,[rel command_udp_dhcp_accept] ; fixed native strict owner/XID handler
    call virtio_domain_restart_net_start
.net_started:
    mov dword [rel nd_restart_record+44],4
    mov ebx,16384
.poll:
    call boot_ms_now
    cmp rax,[rel ndr_last_ms]
    jb .clock
    mov [rel ndr_last_ms],rax
    cmp rax,[rel ndr_deadline]
    jae .out
    mov rax,[rel nd_generation]
    cmp rax,[rel nd_restart_record+80]
    jne .out
    lea rdi,[rel nd_nonce]
    lea rsi,[rel ndr_nonce]
    mov ecx,17
    cld
    repe cmpsb
    jne .out
    cmp dword [rel nd_state],3
    jae .out
    mov eax,[rel hv_linux_start_consumed]
    cmp rax,[rel nd_restart_record+80]
    jne .yield
    cmp byte [rel hv_linux_panicked],0
    jne .out
    cmp qword [rel nd_restart_record+120],0
    jne .work
    cmp dword [rel nd_operational],1
    jne .yield
    call nd_current
    test eax,eax
    jz .yield
    lea rdi,[rel nd_restart_record+800]
    call nic_assignment_receipt
    cmp eax,1
    jne .out
    mov rax,[rel hv_vcon_epoch]
    mov [rel nd_restart_record+136],rax
    call boot_ms_now
    mov [rel nd_restart_record+120],rax
    mov byte [rel ndr_line],1
    lea rdi,[rel ndr_work_command]
    call hv_vcon_rx_line             ; real original virtio queue; no retry
    cmp eax,1
    jne .delivery
.work:
    mov r12d,1                     ; terminal/missing if local slice expired
    cmp dword [rel nd_restart_record+8],4
    jne .work_sha
    call boot_ms_now
    mov rdx,[rel nd_restart_record+120]
    add rdx,8000
    cmp rax,rdx
    jae .work_sha
    mov rdx,[rel ndr_deadline]
    sub rdx,4000
    cmp rax,rdx
    jae .work_sha
    call virtio_domain_restart_net_step
    mov r12d,eax
.work_sha:
    cmp dword [rel nd_restart_record+204],1
    jne .yield
    cmp dword [rel ndr_service],0
    jne .service
    mov dword [rel ndr_service],1
    lea rdi,[rel ndr_service_task]
    call sched_spawn
    mov [rel nd_restart_record+192],eax
    cmp eax,-1
    je .service_bad
.service:
    cmp dword [rel ndr_service],2
    je .worked
.yield:
    dec ebx
    jz .out
    call sched_yield
    jmp .poll
.worked:
    cmp dword [rel nd_restart_record+8],4
    jne .work_done
    test r12d,r12d
    jnz .work_done
    call boot_ms_now
    mov rdx,[rel nd_restart_record+120]
    add rdx,8000                  ; optional traffic wait, inside original80s
    cmp rax,rdx
    jae .work_done
    mov rdx,[rel ndr_deadline]
    sub rdx,4000                  ; leave original final-quiesce allowance
    cmp rax,rdx
    jb .yield
.work_done:
    call nd_current
    test eax,eax
    jz .out
    cmp dword [rel nd_restart_record+8],4
    jne .new_observed
    lea rdi,[rel nd_restart_record+1392]
    call virtio_domain_restart_observation
.new_observed:
    mov dword [rel nd_restart_record+44],7 ; requires final real retirement
    jmp .out
.delivery:
    mov dword [rel nd_restart_record+44],5
    jmp .out
.service_bad:
    mov dword [rel nd_restart_record+44],6
    jmp .out
.clock:
    mov dword [rel nd_restart_record+44],8
.out:
    call boot_ms_now
    cmp dword [rel ndr_phase],2
    jne .done
    mov [rel nd_restart_record+72],rax
    cmp dword [rel nd_restart_record+8],4
    jne .done
    lea rdi,[rel nd_restart_record]
    call virtio_domain_restart_net_pack
.done:
    pop r13
    pop r12
    pop rbx
    ret

ndr_service_task:
    sub rsp,8
    call smp_current_logical
    test eax,eax
    jnz .out
    call boot_ms_now
    mov [rel nd_restart_record+144],rax
    lea rdi,[rel nd_restart_record+160]
    lea rsi,[rel nd_restart_record+104]
    mov edx,16
    call sha256_hash
    test rax,rax
    jnz .out
    call boot_ms_now
    mov [rel nd_restart_record+152],rax
    mov dword [rel ndr_service],2
.out:
    add rsp,8
    ret

; Actual original final NDRTN safety is preserved, including any refusal.
nd_restart_finish:
    push rax
    push rbx
    sub rsp,8
    cmp dword [rel ndr_phase],2
    jne .out
    mov dword [rel ndr_phase],3
    mov dword [rel nd_restart_record+196],0
    mov eax,[rel ndr_service]
    mov [rel nd_restart_record+196],eax
    lea rdi,[rel nd_restart_record+1056]
    lea rsi,[rel nd_return_record]
    mov ecx,16
    cld
    rep movsq
    lea rdi,[rel nd_restart_record+864]
    call pcia_iommu_receipt
    mov [rel nd_restart_record+212],eax
    call boot_ms_now
    mov [rel nd_restart_record+216],rax
    cmp dword [rel nd_restart_record+44],7
    jne .out
    cmp rax,[rel ndr_last_ms]
    jb .clock
    cmp rax,[rel ndr_deadline]
    jae .out
    cmp dword [rel nd_restart_record+196],2
    jne .out
    mov rax,[rel nd_restart_record+128]
    cmp rax,[rel nd_restart_record+120]
    jb .out
    cmp rax,[rel nd_restart_record+144]
    ja .out
    mov rax,[rel nd_restart_record+152]
    cmp rax,[rel nd_restart_record+144]
    jb .out
    cmp rax,[rel nd_restart_record+72]
    ja .out
    mov rax,[rel nd_generation]
    cmp rax,[rel nd_restart_record+80]
    jne .out
    lea rdi,[rel nd_nonce]
    lea rsi,[rel ndr_nonce]
    mov ecx,17
    repe cmpsb
    jne .out
    call nd_return_empty
    test eax,eax
    jz .out
    cmp dword [rel nd_state],4
    jne .out
    cmp dword [rel nd_terminal],1
    jne .out
    cmp dword [rel nd_released],1
    jne .out
    cmp dword [rel nd_restart_record+212],0
    jne .out
    lea rbx,[rel nd_restart_record+864]
    cmp qword [rbx],2
    jne .out
    mov rax,[rel nd_restart_record+80]
    cmp [rbx+8],rax
    jne .out
    mov eax,[rel nd_restart_record+40]
    cmp [rbx+16],rax
    jne .out
    cmp dword [rel nd_restart_record+200],1
    je .intel
    cmp dword [rel nd_restart_record+200],2
    jne .out
    cmp qword [rbx+24],3
    jne .out
    cmp qword [rbx+40],1
    jne .out
    jmp .common
.intel:
    cmp qword [rbx+24],0
    jne .out
    cmp qword [rbx+40],0
    jne .out
.common:
    mov rax,[rbx+32]
    or rax,[rbx+48]
    or rax,[rbx+56]
    jnz .out
    lea rdi,[rel nd_restart_record+520]
    mov rsi,[rel ndr_profile]
    mov ecx,35
    repe cmpsq
    jne .out
    mov dword [rel nd_restart_record+44],0
    jmp .out
.clock:
    mov dword [rel nd_restart_record+44],8
.out:
    mov qword [rel ndr_deadline],0
    add rsp,8
    pop rbx
    pop rax
    ret

 ; RBX=actual retired receipt64, RAX=exact generation; boolean only.
ndr_retired_exact:
    cmp qword [rbx],2
    jne .bad
    cmp [rbx+8],rax
    jne .bad
    mov eax,[rel nd_restart_record+40]
    cmp [rbx+16],rax
    jne .bad
    cmp dword [rel nd_restart_record+200],1
    je .intel
    cmp dword [rel nd_restart_record+200],2
    jne .bad
    cmp qword [rbx+24],3
    jne .bad
    cmp qword [rbx+40],1
    jne .bad
    jmp .common
.intel:
    cmp qword [rbx+24],0
    jne .bad
    cmp qword [rbx+40],0
    jne .bad
.common:
    mov rax,[rbx+32]
    or rax,[rbx+48]
    or rax,[rbx+56]
    jnz .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; AL = counted virtio TX only. Preserve caller's registers and flags.
; Exact anchored line, exact new generation/epoch, post-delivery clock.
nd_restart_byte:
    pushfq
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    cmp dword [rel ndr_phase],2
    jne .out
    cmp qword [rel nd_restart_record+120],0
    je .out
    cmp dword [rel nd_restart_record+204],0
    jne .out
    mov bl,al
    mov eax,[rel hv_linux_start_consumed]
    cmp rax,[rel nd_restart_record+80]
    jne .drop
    mov rax,[rel hv_vcon_epoch]
    cmp rax,[rel nd_restart_record+136]
    jne .drop
    cmp bl,10
    je .newline
    cmp byte [rel ndr_line],1
    jne .out
    mov eax,[rel ndr_pos]
    cmp eax,127
    jae .drop
    cmp bl,13
    je .cr
    cmp byte [rel ndr_cr],0
    jne .drop
    lea rdx,[rel ndr_work_expected]
    cmp bl,[rdx+rax]
    jne .drop
    lea rdx,[rel nd_restart_record+928]
    mov [rdx+rax],bl              ; actual observed TX, never copy expected text
    inc dword [rel ndr_pos]
    jmp .out
.cr:
    lea rdx,[rel ndr_work_expected]
    cmp byte [rdx+rax],0
    jne .drop
    cmp byte [rel ndr_cr],0
    jne .drop
    mov byte [rel ndr_cr],1
    jmp .out
.newline:
    cmp byte [rel ndr_line],1
    jne .line
    mov eax,[rel ndr_pos]
    lea rdx,[rel ndr_work_expected]
    cmp byte [rdx+rax],0
    jne .line
    mov [rel nd_restart_record+208],eax
    call boot_ms_now
    cmp rax,[rel nd_restart_record+120]
    jb .drop
    cmp rax,[rel ndr_deadline]
    jae .drop
    mov [rel nd_restart_record+128],rax
    mov dword [rel nd_restart_record+204],1
.line:
    mov byte [rel ndr_line],1
    mov byte [rel ndr_cr],0
    mov dword [rel ndr_pos],0
    jmp .out
.drop:
    mov byte [rel ndr_line],0
.out:
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    popfq
    ret

; All dynamic text is native-validated lowerhex. Actual command omits the
; expected digest, so tty input echo cannot satisfy this proof.
ndr_build_work:
    push rbx
    lea rdi,[rel ndr_expected_hash]
    lea rsi,[rel nd_restart_record+104]
    mov edx,16
    call sha256_hash
    test rax,rax
    jnz .bad
    lea rdi,[rel ndr_work_expected]
    lea rsi,[rel ndr_work_prefix]
    call ndr_append
    lea rsi,[rel ndr_nonce]
    call ndr_append
    lea rsi,[rel ndr_space]
    call ndr_append
    lea rsi,[rel nd_restart_record+104]
    mov ecx,16
    rep movsb
    lea rsi,[rel ndr_space]
    call ndr_append
    lea rsi,[rel ndr_expected_hash]
    lea rbx,[rel ndr_hex]
    mov ecx,32
.hex:
    lodsb
    mov dl,al
    shr al,4
    movzx eax,al
    mov al,[rbx+rax]
    stosb
    and edx,15
    mov al,[rbx+rdx]
    stosb
    loop .hex
    lea rsi,[rel ndr_sha_suffix]
    call ndr_append
    lea rdi,[rel ndr_work_command]
    lea rsi,[rel ndr_command_prefix]
    call ndr_append
    lea rsi,[rel ndr_nonce]
    call ndr_append
    lea rsi,[rel ndr_space]
    call ndr_append
    lea rsi,[rel nd_restart_record+104]
    mov ecx,16
    rep movsb
    lea rsi,[rel ndr_command_middle]
    call ndr_append
    lea rsi,[rel nd_restart_record+104]
    mov ecx,16
    rep movsb
    lea rsi,[rel ndr_command_suffix]
    call ndr_append
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret
ndr_append:
    lodsb
    mov [rdi],al
    test al,al
    jz .out
    inc rdi
    jmp ndr_append
.out:
    ret
ndr_verb: db 'NDRESTART',0
ndr_ok: db 'NDRESTART1 ',0
ndr_bad: db 'NDRESTARTERR1',0
ndr_space: db ' ',0
ndr_stop_ack: db ' STOP ',0
ndr_hex: db '0123456789abcdef'
ndr_work_prefix: db 'PAOS_NDR_WORK ',0
ndr_sha_suffix: db '  -',0
ndr_command_prefix: db "printf '\nPAOS_NDR_WORK %s %s ' ",0
ndr_command_middle: db ';printf %s ',0
ndr_command_suffix: db '|/bin/busybox sha256sum',0
%include "core/abi/wdata.inc"
%macro WDATA_BSS_hv_driver_domain_restart 0
alignb 8
nd_restart_record: resb ND_RESTART_BYTES
ndr_phase: resd 1
ndr_service: resd 1
ndr_pos: resd 1
ndr_line: resb 1
ndr_cr: resb 1
alignb 8
ndr_selected_ms: resq 1
ndr_profile: resq 1
ndr_deadline: resq 1
ndr_last_ms: resq 1
ndr_nonce: resb 17
ndr_expected_hash: resb 32
ndr_work_expected: resb 128
ndr_work_command: resb 256
ndr_arg_start: resb 24
ndr_arg_nonce: resb 17
ndr_arg_probe: resb 17
ndr_arg_stop: resb 5
ndr_arg_challenge: resb 17
alignb 4
ndr_arg_mode: resd 1
%endmacro
WDATA_BSS_DEFER WDATA_BSS_hv_driver_domain_restart
