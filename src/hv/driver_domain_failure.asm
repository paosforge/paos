;; MODULE hv/driver_domain_failure
;; LAYER 5
;; EXPORTS nd_failure_register, nd_failure_select, nd_failure_run, nd_failure_finish, nd_failure_record, ndf_phase
;; IMPORTS hv/driver_domain_command, svc/command, core/time, hv/driver_domain, hv/driver_domain_return, hv/vmx, hv/nic_assignment, hv/pci_assign, hv/guest_power, core/sched, core/smp, core/lib/sha256, svc/command_auth, fs/storage_access
;; CAPS extension
;; OWNER rc-vm-claude
;; CONTEXT: bsp_only
; NDFAIL selects the current domain; it does NOT inject in a request frame.
; The existing signed-return post-ACK owner calls run, then original quiescence
; and finish. The network may disappear only after that return is authorized.
; A request/ACK is never crash evidence. Existing backend #UD + Linux fatal
; output earns panicked. A separate scheduled native hash service runs AFTER
; that observation. Original native CPU/RAM and DMA/IRQ receipts earn retirement.
; No START, replacement guest, reset, deadline renewal or firmware here.
ND_FAILURE_BYTES equ 640
ND_FAILURE_MS equ 8000
nd_failure_register:
    lea rdi,[rel ndf_verb]
    lea rsi,[rel ndf_command]
    mov rdx,CMD_AUTH_CAP_MUTATE
    mov ecx,ARGT_TEXT
    xor r8d,r8d
    mov r9d,1
    jmp command_register_verb
ndf_command:
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
    lea rsi,[rel ndf_arg_start]
    mov edx,24
    call nd_token
    test rax,rax
    jz .bad
    mov rdi,rax
    lea rsi,[rel ndf_arg_nonce]
    mov edx,17
    call nd_token
    test rax,rax
    jz .bad
    mov rdi,rax
    lea rsi,[rel ndf_arg_probe]
    mov edx,17
    call nd_token
    test rax,rax
    jz .bad
    cmp byte [rax],0
    jne .bad
    cmp byte [rel ndf_arg_start],'1'
    jb .bad
    cmp byte [rel ndf_arg_start],'9'
    ja .bad
    lea rdi,[rel ndf_arg_start]
    mov esi,10
    mov edx,10
    call nd_number
    jc .bad
    mov edi,eax
    lea rsi,[rel ndf_arg_nonce]
    lea rdx,[rel ndf_arg_probe]
    call nd_failure_select
    test eax,eax
    jnz .bad
    lea rdi,[rel ndf_ok]
    call hv_out_str
    lea rdi,[rel ndf_arg_start]
    call hv_out_str
    lea rdi,[rel nd_space]
    call hv_out_str
    lea rdi,[rel ndf_arg_nonce]
    call hv_out_str
    lea rdi,[rel nd_space]
    call hv_out_str
    lea rdi,[rel ndf_arg_probe]
    call hv_out_str
    jmp .done
.bad:
    lea rdi,[rel ndf_bad]
    call hv_out_str
.done:
    mov byte [rel hv_out_ready],1
    mov qword [r12+RSP_CODE],CMDE_OK
    add rsp,8
    pop r12
    pop rbx
    ret

; Exact live START+domain nonce+fresh public probe -> 0 selected / -1 inert.
nd_failure_select:
    push rbx
    push r12
    push r13
    mov rbx,rdi
    mov r12,rsi
    mov r13,rdx
    cmp dword [rel ndf_phase],0
    jne .bad
    test rbx,rbx
    jz .bad
    cmp rbx,[rel nd_generation]
    jne .bad
    mov rdi,r12
    call nd_nonce_valid
    test eax,eax
    jz .bad
    lea rdi,[rel nd_nonce]
    mov rsi,r13
    mov ecx,16
    cld
    repe cmpsb
    je .bad ; challenge must not reuse the domain nonce
    mov rdi,r13
    call nd_nonce_valid
    test eax,eax
    jz .bad
    lea rdi,[rel nd_nonce]
    mov rsi,r12
    mov ecx,17
    cld
    repe cmpsb
    jne .bad
    cmp byte [rel hv_linux_panicked],0
    jne .bad
    call hv_guest_power_admit
    test rax,rax
    jnz .bad
    call nd_current
    test eax,eax
    jz .bad
    cmp dword [rel nd_operational],1
    jne .bad
    lea rdi,[rel nd_failure_record]
    xor eax,eax
    mov ecx,ND_FAILURE_BYTES/8
    rep stosq
    mov rax,0x00314c494146444e ; NDFAIL1 NUL
    mov [rel nd_failure_record],rax
    mov dword [rel nd_failure_record+8],1
    mov dword [rel nd_failure_record+12],ND_FAILURE_BYTES
    mov [rel nd_failure_record+16],rbx
    lea rdi,[rel nd_failure_record+24]
    mov rsi,r12
    mov ecx,16
    rep movsb
    lea rdi,[rel nd_failure_record+160]
    mov rsi,r13
    mov ecx,16
    rep movsb
    mov eax,[rel nd_bdf]
    mov [rel nd_failure_record+40],eax
    mov eax,[rel nd_selector+24]
    mov [rel nd_failure_record+216],eax
    mov dword [rel nd_failure_record+44],1
    call boot_ms_now
    test rax,rax
    jz .bad
    mov [rel nd_failure_record+48],rax
    lea rdi,[rel nd_failure_record+392]
    call nic_assignment_receipt
    cmp eax,1
    jne .bad
    mov dword [rel ndf_phase],1
    xor eax,eax
    jmp .out
.bad:
    mov eax,-1
.out:
    pop r13
    pop r12
    pop rbx
    ret

ndf_same:
    mov rax,[rel nd_failure_record+16]
    cmp rax,[rel nd_generation]
    jne .bad
    mov edx,[rel hv_linux_start_gen]
    cmp rax,rdx
    jne .bad
    mov edx,[rel hv_linux_start_consumed]
    cmp rax,rdx
    jne .bad
    mov edx,[rel nd_bdf]
    cmp edx,[rel nd_failure_record+40]
    jne .bad
    lea rdi,[rel nd_nonce]
    lea rsi,[rel nd_failure_record+24]
    mov ecx,16
    cld
    repe cmpsb
    jne .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Only original post-ACK return boundary. Bounded even if the clock stalls.
nd_failure_run:
    push rbx
    push r12
    sub rsp,8
    cmp dword [rel ndf_phase],1
    jne .out
    mov dword [rel ndf_phase],2
    mov dword [rel nd_failure_record+44],2
    call ndf_same
    test eax,eax
    jz .out
    call nd_current
    test eax,eax
    jz .out
    call boot_ms_now
    cmp rax,[rel nd_failure_record+48]
    jb .clock_bad
    mov [rel nd_failure_record+56],rax
    mov [rel ndf_last_ms],rax
    mov r12,rax
    mov dword [rel nd_failure_record+44],3
    call hv_guest_panic_request
    cmp eax,1
    jne .out
    mov dword [rel nd_failure_record+44],4
    mov ebx,4096
.poll:
    call ndf_same
    test eax,eax
    jz .changed
    call boot_ms_now
    cmp rax,[rel ndf_last_ms]
    jb .clock_bad
    mov [rel ndf_last_ms],rax
    sub rax,r12
    cmp rax,ND_FAILURE_MS
    jae .out
    cmp byte [rel hv_linux_panicked],1
    jne .yield
    cmp byte [rel hv_panic_injected],1
    jne .out
    cmp byte [rel hv_panic_text],1
    jne .out
    cmp dword [rel ndf_service],0
    jne .service_pending
    mov rax,[rel ndf_last_ms]
    mov [rel nd_failure_record+224],rax ; actual fatal observed before native service
    mov dword [rel nd_failure_record+44],6
    mov dword [rel ndf_service],1
    lea rdi,[rel ndf_native_service]
    call sched_spawn
    test eax,eax
    js .out
    mov [rel nd_failure_record+208],eax ; actual independent scheduler slot
.service_pending:
    cmp dword [rel ndf_service],2
    jne .yield
    mov dword [rel nd_failure_record+44],5 ; finish must observe actual retirement
    jmp .out
.yield:
    dec ebx
    jz .out
    call sched_yield
    jmp .poll
.changed:
    mov dword [rel nd_failure_record+44],2
    jmp .out
.clock_bad:
    mov dword [rel nd_failure_record+44],7
.out:
    add rsp,8
    pop r12
    pop rbx
    ret

; Real independent native service: SHA256(fresh selected probe), after panic.
; No guest callback, network, copied ready flag or host result supplies it.
ndf_native_service:
    sub rsp,8
    call smp_current_logical
    test eax,eax
    jnz .out ; SHA256 scratch and this lifecycle belong to the BSP
    cmp dword [rel ndf_phase],2
    jne .out
    cmp dword [rel ndf_service],1
    jne .out
    call ndf_same
    test eax,eax
    jz .out
    cmp byte [rel hv_linux_panicked],1
    jne .out
    call boot_ms_now
    mov [rel nd_failure_record+144],rax
    lea rdi,[rel nd_failure_record+176]
    lea rsi,[rel nd_failure_record+160]
    mov edx,16
    call sha256_hash
    test rax,rax
    jnz .out
    call boot_ms_now
    mov [rel nd_failure_record+152],rax
    mov dword [rel ndf_service],2
.out:
    add rsp,8
    ret ; existing sched_task_exit retires the task slot

; Called after ORIGINAL nd_return_prepare; that return still owns safe STOP.
; EAX return safety preserved. A timeout never gains failure-containment credit.
nd_failure_finish:
    push rax
    push rbx
    sub rsp,8
    cmp dword [rel ndf_phase],2
    jne .out
    mov dword [rel ndf_phase],3
    mov eax,[rel ndf_service]
    mov [rel nd_failure_record+220],eax
    call boot_ms_now
    mov [rel nd_failure_record+64],rax
    mov al,[rel hv_panic_armed]
    mov [rel nd_failure_record+72],al
    mov al,[rel hv_panic_injected]
    mov [rel nd_failure_record+73],al
    mov al,[rel hv_panic_text]
    mov [rel nd_failure_record+74],al
    mov al,[rel hv_linux_panicked]
    mov [rel nd_failure_record+75],al
    mov eax,[rel hv_linux_start_gen]
    mov [rel nd_failure_record+80],eax
    mov eax,[rel hv_linux_start_consumed]
    mov [rel nd_failure_record+84],eax
    mov al,[rel hv_linux_running]
    mov [rel nd_failure_record+88],al
    mov al,[rel hv_linux_start_active]
    mov [rel nd_failure_record+89],al
    mov al,[rel hv_linux_vmx_live]
    mov [rel nd_failure_record+90],al
    mov al,[rel hv_linux_run_req]
    mov [rel nd_failure_record+91],al
    mov eax,[rel nd_state]
    mov [rel nd_failure_record+92],eax
%macro NDF_COPY 2
    mov rax,[rel %1]
    mov [rel nd_failure_record+%2],rax
%endmacro
    NDF_COPY hv_linux_region,96
    NDF_COPY hv_linux_region_capacity,104
    NDF_COPY hv_linux_region_resident,112
    NDF_COPY hv_linux_ram,120
    NDF_COPY hv_linux_mb_token,128
    NDF_COPY hv_svm_cur_vmcb,136
%unmacro NDF_COPY 2
    lea rdi,[rel nd_failure_record+456]
    call pcia_iommu_receipt
    mov [rel nd_failure_record+212],eax
    cmp dword [rel nd_failure_record+44],5
    jne .out
    mov rax,[rel nd_failure_record+56]
    cmp rax,[rel nd_failure_record+48]
    jb .out
    mov rdx,[rel nd_failure_record+144]
    cmp rdx,rax
    jb .out
    cmp rdx,[rel nd_failure_record+224]
    jb .out
    mov rcx,[rel nd_failure_record+152]
    cmp rcx,rdx
    jb .out
    cmp rcx,[rel ndf_last_ms]
    ja .out
    mov rdx,[rel nd_failure_record+64]
    cmp rdx,[rel ndf_last_ms]
    jb .out
    sub rdx,rax
    cmp rdx,ND_FAILURE_MS+ND_CALL_MS
    jae .out

    call ndf_same
    test eax,eax
    jz .out
    call nd_return_empty
    test eax,eax
    jz .out
    cmp dword [rel nd_state],4
    jne .out
    cmp dword [rel nd_terminal],1
    jne .out
    cmp dword [rel nd_released],1
    jne .out
    cmp dword [rel nd_failure_record+212],0
    jne .out
    lea rbx,[rel nd_failure_record+456]
    cmp qword [rbx],2
    jne .out
    mov rax,[rel nd_failure_record+16]
    cmp [rbx+8],rax
    jne .out
    mov eax,[rel nd_failure_record+40]
    cmp [rbx+16],rax
    jne .out
    cmp dword [rel nd_failure_record+216],1
    je .intel
    cmp dword [rel nd_failure_record+216],2
    jne .out
    cmp qword [rbx+24],3 ; AMD valid abort-mode DTE, no read/write DMA
    jne .out
    cmp qword [rbx+40],1 ; AMD IRQ IntCtl abort, QW2=1
    jne .out
    jmp .common
.intel:
    cmp qword [rbx+24],0 ; Intel context not present
    jne .out
    cmp qword [rbx+40],0
    jne .out
.common:
    mov rax,[rbx+32]
    or rax,[rbx+48]
    or rax,[rbx+56]
    jnz .out
    mov dword [rel nd_failure_record+44],0
.out:
    add rsp,8
    pop rbx
    pop rax
    ret
ndf_verb: db 'NDFAIL',0
ndf_ok: db 'NDFAIL1 ',0
ndf_bad: db 'NDFAILERR1',0
%include "core/abi/wdata.inc"
%macro WDATA_BSS_hv_driver_domain_failure 0
alignb 8
nd_failure_record: resb ND_FAILURE_BYTES
ndf_phase: resd 1
ndf_service: resd 1
ndf_last_ms: resq 1
ndf_arg_start: resb 24
ndf_arg_nonce: resb 17
ndf_arg_probe: resb 17
%endmacro
WDATA_BSS_DEFER WDATA_BSS_hv_driver_domain_failure
