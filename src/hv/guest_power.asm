;; MODULE hv/guest_power
;; LAYER 5
;; EXPORTS hv_guest_power_register, hv_guest_power_validate, hv_guest_power_admit, hv_guest_power_io_admit, hv_guest_power_exit_gate, hv_guest_power_context, hv_guest_power_fenced, hv_guest_power_inflight, hv_guest_power_s5_inactive
;; IMPORTS svc/reinit_power, hv/vmx, hv/hv_ops, hv/svm, hv/vm_profile, hv/guestnet, hv/guestinput, hv/guestentropy, hv/guestrestore, hv/guestsound, hv/guestdisplay, hv/vtd, hv/pci_assign, hv/input_owner, hv/warm_lifecycle, hv/cdp_bridge, hv/guest_surface, hv/pad_channel, core/sched
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Explicit attachment of the existing single resident BSP vCPU to driver_power
; v1. No boot registration, firmware sleep, checkpoint, VMXOFF or reset here.
; A saved decoder continuation parks before either vendor's next entry, retaining
; VMCS/VMCB, GPRs, RAM, SLAT, queued descriptors, used indices and pending IRQs.
; This is co-resident quiesce only, not S3: platform CPU-state loss is unsupported.
; Purely emulated host-NAT is retained in place. Native DMA, passthrough and
; transparent physical-domain networking are refused before FENCE side effects.
%include "core/abi/driver_power.inc"

GP_IDLE equ 0
GP_FENCED equ 1
GP_PAUSED equ 2
GP_RESTORE equ 3
GP_PROBING equ 4
GP_PROVEN equ 5
GP_VERIFIED equ 6
GP_OWNER_BYTES equ 184

; Host S5 preflight -> EAX 0 only when no current guest work/assignment is live.
; EDX names the first actual blocker (1..23), or 0 when ready. Caller-saved
; observation only: no extra reads, teardown, retry or admission authority.
; Read-only scalar census: a pending stop, parked vCPU or service ACK is not
; actual stop, DMA/IRQ teardown or guest filesystem flush. Never follow a domain
; pointer. The terminal caller repeats this check with IF clear before effects;
; this predicate neither initiates teardown nor grants passthrough quiescence.
hv_guest_power_s5_inactive:
    xor r10d,r10d                ; no injected ownership refusal
    xor r11d,r11d                ; ordinary callers can never inherit exemptions
.census:
    mov edx,1                    ; first actual blocker ordinal
    cmp byte [rel hv_linux_running], 0
    jne .refused
    mov edx,2                    ; first actual blocker ordinal
    cmp byte [rel hv_linux_start_active], 0
    jne .refused
    mov edx,3                    ; first actual blocker ordinal
    cmp byte [rel hv_linux_run_req], 0
    jne .refused
    mov edx,4                    ; first actual blocker ordinal
    cmp byte [rel hv_linux_stop_req], 0
    jne .refused
    mov edx,5                    ; first actual blocker ordinal
    cmp byte [rel hv_linux_vmx_live], 0
    jne .refused
    ; CPU-off alone cannot release PIN1/warm custody or a live SVM context.
    ; Their existing terminal/revoke/scrub paths clear these receipts only
    ; after actual retirement. This reader never clears them on an ACK.
    mov edx,6                    ; first actual blocker ordinal
    cmp qword [rel hv_svm_cur_vmcb], 0
    jne .refused
    mov edx,7                    ; first actual blocker ordinal
    cmp byte [rel hvp_bound], 0
    jne .refused
    mov edx,8                    ; first actual blocker ordinal
    cmp byte [rel hvw_bound], 0
    jne .refused
    mov edx,9                    ; first actual blocker ordinal
    cmp byte [rel vtd_owner_guest], 0
    jne .refused
    mov edx,10                    ; first actual blocker ordinal
    cmp byte [rel vtd_network_mode], 0
    jne .refused
    mov edx,11                    ; first actual blocker ordinal
    cmp qword [rel guestnet_domain_ctx], 0
    jne .refused
    mov edx,12                    ; first actual blocker ordinal
    cmp byte [rel guestnet_active], 0
    jne .refused
    mov edx,13                    ; first actual blocker ordinal
    cmp byte [rel hv_guest_power_fenced], 0
    jne .refused
    mov edx,14                    ; first actual blocker ordinal
    cmp qword [rel hv_guest_power_inflight], 0
    jne .refused
    bt r11d,31                   ; dedicated contained reader avoids passive-record writes
    jc .retained_nic
    call pcia_guest_owned
    jmp .nic_result
.retained_nic:
    mov eax,1                    ; the caller proved this domain's POISON leaf now
.nic_result:
    mov edx,15                    ; helper may clobber caller-saved EDX
    test eax, eax
    jz .token
    bt r11d,15
    jnc .refused
.token:
    ; Ordinary release clears cached addresses BEFORE mb_release. On BUSY or
    ; stale-key refusal the real owner token remains: CPU-off and NULL addresses
    ; must not permit host S5. Never clear or retry any owner from this reader.
    mov edx,16                    ; first actual blocker ordinal
    cmp r10d,edx                ; private ownership proof failed at this ordinal
    je .refused
    cmp qword [rel hv_linux_mb_token], 0
    je .region
    bt r11d,16
    jnc .refused
.region:
    mov edx,17                    ; first actual blocker ordinal
    cmp r10d,edx                ; private ownership proof failed at this ordinal
    je .refused
    cmp qword [rel hv_linux_region], 0
    je .capacity
    bt r11d,17
    jnc .refused
.capacity:
    mov edx,18                    ; first actual blocker ordinal
    cmp r10d,edx                ; private ownership proof failed at this ordinal
    je .refused
    cmp qword [rel hv_linux_region_capacity], 0
    je .resident
    bt r11d,18
    jnc .refused
.resident:
    mov edx,19                    ; first actual blocker ordinal
    cmp r10d,edx                ; private ownership proof failed at this ordinal
    je .refused
    cmp qword [rel hv_linux_region_resident], 0
    je .readers
    bt r11d,19
    jnc .refused
.readers:
    ; External console/surface/audio readers retain guest spans independently
    ; of CPU state. Their own terminal paths must detach them first.
    mov edx,20                    ; first actual blocker ordinal
    cmp byte [rel cdp_bound], 0
    jne .refused
    mov edx,21                    ; first actual blocker ordinal
    cmp byte [rel gws_bound], 0
    jne .refused
    mov edx,22                    ; first actual blocker ordinal
    cmp byte [rel padc_bound], 0
    jne .refused
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    mov edx,23                    ; first actual blocker ordinal
    cmp byte [rel hv_vcon_pmr_bound], 0
    jne .refused
%endif
%endif
    xor edx, edx                    ; every existing check passed
    xor eax, eax
    ret
.refused:
    mov eax, 1
    ret

; Private entry, only nd_contained_power_ok after its fresh proof. R11D has
; bit31 (contained mode) plus exactly 15..19, backed by the actual allocator
; read. R10D is zero or the first failed ownership ordinal (16..19); it
; forces refusal even if a stale scalar is zero. The public entry clears both.
.contained:
    jmp .census


; Scalar receipts only. Never dereference a possibly replaced guest/domain
; pointer to establish identity. The still-pinned real backend and reservation
; are checked before any resumed device helper may touch guest memory.
hv_guest_power_owner_read:
    cmp byte [rel hv_linux_running], 1
    jne .changed
    cmp byte [rel hv_linux_start_active], 1
    jne .changed
    cmp byte [rel hv_linux_vmx_live], 1
    jne .changed
    cmp byte [rel hv_linux_kboot], 1
    jne .unsupported
    cmp byte [rel hv_linux_stop_req], 0
    jne .changed
    cmp byte [rel hv_linux_run_req], 0
    jne .changed
    cmp byte [rel hv_linux_load_err], 0
    jne .changed
    cmp dword [rel hv_vmwrite_fails], 0
    jne .changed
    cmp byte [rel vtd_owner_guest], 0
    jne .unsupported
    cmp byte [rel vtd_network_mode], 0
    jne .unsupported
    cmp qword [rel guestnet_domain_ctx], 0
    jne .unsupported
    call pcia_guest_owned                 ; RCQ-36 V2: an assigned host function is passthrough
    test eax, eax
    jnz .unsupported
    mov eax, [rel vm_profile_live_devices]
    cmp eax, [rel vm_profile_dev_mask]
    jne .changed
    mov [rdi + 0], rax
    mov eax, [rel hv_linux_start_consumed]
    test eax, eax
    jz .changed
    cmp eax, [rel hv_linux_start_gen]
    jne .changed
    cmp eax, [rel vm_profile_gen]
    jne .changed
    mov [rdi + 8], rax
    ; The host NIC remains host-owned. Only an emulated session in this START
    ; and selected profile can share custody; no domain pointer is followed.
    ; Network receipt follows the independent sound epoch and reserved qword.
    movzx edx, byte [rel guestnet_active]
    cmp edx, 1
    ja .unsupported
    mov [rdi + 168], rdx
    mov ecx, [rel guestnet_launch_gen]
    mov [rdi + 176], rcx
    test edx, edx
    jz .net_identity
    test dword [rel vm_profile_live_devices], VP_DEV_NET
    jz .unsupported
    cmp ecx, eax
    jne .changed
.net_identity:
    mov rax, [rel vm_profile_active]
    test rax, rax
    jz .unsupported                       ; legacy/passthrough is not enrolled
    mov [rdi + 16], rax
    mov rax, [rel hv_ops_active]
    lea rdx, [rel hv_ops_vmx]
    cmp rax, rdx
    je .backend
    lea rdx, [rel hv_ops_svm]
    cmp rax, rdx
    jne .unsupported
    cmp qword [rel hv_svm_cur_vmcb], 0
    je .changed
.backend:
    mov [rdi + 24], rax
    mov rax, [rel hv_linux_region]
    test rax, rax
    jz .changed
    mov [rdi + 32], rax
    mov rdx, [rel hv_linux_region_capacity]
    cmp rdx, HV_LINUX_CTRL_BYTES
    jb .changed
    mov [rdi + 40], rdx
    add rdx, rax
    jc .changed
    add rax, HV_LINUX_CTRL_BYTES
    jc .changed
    cmp rax, [rel hv_linux_ram]
    jne .changed
    mov [rdi + 48], rax
    mov rcx, [rel hv_linux_ram_bytes]
    test rcx, rcx
    jz .changed
    mov [rdi + 56], rcx
    add rax, rcx
    jc .changed
    mov rcx, [rel hv_linux_fb_bytes]
    mov [rdi + 64], rcx
    add rax, rcx
    jc .changed
    cmp rax, rdx
    ja .changed
    mov rax, [rel hv_linux_eptp]
    test rax, rax
    jz .changed
    mov [rdi + 72], rax
    mov rax, [rel hv_svm_cur_vmcb]
    mov [rdi + 80], rax
    mov rax, [rel hv_launch_vmcs_pa]
    mov [rdi + 88], rax
    mov rax, [rel hv_vcon_epoch]
    mov [rdi + 96], rax
    mov rax, [rel gi_owner_epoch]
    mov [rdi + 104], rax
    mov rax, [rel gr_epoch]
    mov [rdi + 112], rax
    mov rax, [rel guestnet_ring_epoch]
    mov [rdi + 120], rax
    movzx eax, byte [rel gd_state]
    mov [rdi + 128], rax
    mov rax, [rel gd_frame]
    mov [rdi + 136], rax
    mov rax, [rel hv_guest_power_generation]
    mov [rdi + 144], rax
    mov rax, [rel gs_epoch]
    mov [rdi + 152], rax
    mov qword [rdi + 160], 0
    xor eax, eax
    ret
.changed:
    mov rax, DP_CHANGED
    ret
.unsupported:
    mov rax, DP_UNSUPPORTED
    ret

hv_guest_power_current:
    sub rsp, GP_OWNER_BYTES
    mov rdi, rsp
    call hv_guest_power_owner_read
    test rax, rax
    jnz .out
    mov rdi, rsp
    lea rsi, [rel gp_owner]
    mov ecx, GP_OWNER_BYTES / 8
    cld
    repe cmpsq
    jne .changed
    xor eax, eax
    jmp .out
.changed:
    mov rax, DP_CHANGED
.out:
    add rsp, GP_OWNER_BYTES
    ret

; RDI=the pinned initialized v1 plan already holding this guest participant.
; Explicit native command preflight: validate the attached receipt before ANY
; participant is fenced. Read scalars only; never refresh/rebind the receipt.
hv_guest_power_validate:
    cld
    cmp rdi, [rel hv_guest_power_context]
    jne .changed
    test rdi, rdi
    jz .changed
    cmp byte [rel hv_guest_power_fenced], 0
    jne .busy
    jmp hv_guest_power_current
.changed:
    mov rax, DP_CHANGED
    ret
.busy:
    mov rax, DP_BUSY
    ret

; RDI=trusted pinned initialized v1 plan, ESI=already-registered dependencies.
; One attachment for the existing vCPU slot lifetime, not a new driver registry.
; Slot generation is full64 and pinned; START generation is separately receipted
; per operation. The plan/declaration remain pinned for all later cycle reuse.
hv_guest_power_register:
    push rbx
    push r12
    sub rsp, 8
    cld
    mov rbx, rdi
    mov r12d, esi
    mov rax, DP_BUSY
    cmp qword [rel hv_guest_power_context], 0
    jne .out
    lea rdi, [rel gp_owner]
    call hv_guest_power_owner_read
    test rax, rax
    jnz .out
    lea rsi, [rel gp_driver]
    mov dword [rsi + dp_driver.version], DP_VERSION
    mov dword [rsi + dp_driver.kind], DP_GUEST
    lea rax, [rel hv_linux_gpr]
    mov [rsi + dp_driver.owner], rax
    lea rax, [rel hv_guest_power_generation]
    mov [rsi + dp_driver.generation_ptr], rax
    mov rax, [rax]
    mov [rsi + dp_driver.generation], rax
    lea rax, [rel hv_guest_power_callback]
    mov [rsi + dp_driver.callback], rax
    mov [rsi + dp_driver.dependencies], r12d
    mov dword [rsi + dp_driver.capabilities], DP_CAP_IRQ
    mov rdi, rbx
    call reinit_power_register
    test rax, rax
    jnz .out
    mov [rel hv_guest_power_context], rbx
.out:
    add rsp, 8
    pop r12
    pop rbx
    cld
    ret

; All attached new host work uses the exact shared admit token contract.
; Read-only STAT remains available; no automatic registration or START replay.
hv_guest_power_admit:
    mov rdi, [rel hv_guest_power_context]
    test rdi, rdi
    jz .open
    cmp byte [rel hv_guest_power_fenced], 0
    jne .busy
    mov rsi, [rdi + dp_context.token]
    lea rdx, [rel hv_linux_gpr]
    mov rcx, [rel hv_guest_power_generation]
    jmp reinit_power_admit
.open:
    xor eax, eax
    ret
.busy:
    mov rax, DP_BUSY
    ret

; Only the original saved backend continuation may process already-owned
; device work during a readiness probe. External producers remain fenced.
hv_guest_power_io_admit:
    cmp byte [rel hv_guest_power_fenced], 0
    je hv_guest_power_admit
    cmp byte [rel gp_probe], 1
    jne .busy
    mov eax, [rel sched_cur]
    cmp eax, [rel gp_task]
    jne .busy
    jmp hv_guest_power_current
.busy:
    mov rax, DP_BUSY
    ret

; v1 callback: no yield, allocation, FP change or guest pointer access.
; Every phase authenticates context/token/owner and compares the live receipt.
hv_guest_power_callback:
    push rbx
    push r12
    sub rsp, 8
    cld
    mov r12d, esi
    mov rbx, rdx
    lea rax, [rel hv_linux_gpr]
    cmp rdi, rax
    jne .changed
    cmp rcx, [rel hv_guest_power_context]
    jne .changed
    test rcx, rcx
    jz .changed
    cmp dword [rcx + dp_context.version], DP_VERSION
    jne .changed
    cmp rbx, [rcx + dp_context.token]
    jne .changed
    test rbx, rbx
    jz .changed
    cmp r8, [rel hv_guest_power_generation]
    jne .changed
    cmp esi, [rcx + dp_context.phase]
    jne .changed
    mov eax, [rcx + dp_context.state]
    cmp r12d, DP_STOP
    ja .recovery_state
    cmp eax, DP_QUIESCING
    jne .changed
    jmp .state_ok
.recovery_state:
    cmp eax, DP_RESUMING
    je .state_ok
    cmp eax, DP_RECOVERING
    jne .changed
.state_ok:
    cmp r12d, DP_FENCE
    je .fence
    cmp rbx, [rel gp_token]
    jne .untouched
    call hv_guest_power_current
    test rax, rax
    jnz .out
    cmp r12d, DP_STOP
    je .stop
    cmp r12d, DP_RESTORE
    je .restore
    cmp r12d, DP_VERIFY
    je .verify
    mov rax, DP_UNSUPPORTED
    jmp .out
.fence:
    cmp byte [rel gp_mode], GP_IDLE
    jne .same_fence
    lea rdi, [rel gp_owner]
    call hv_guest_power_owner_read
    test rax, rax
    jnz .out                         ; explicit no-effect unsupported refusal
    mov [rel gp_token], rbx
    mov byte [rel hv_guest_power_fenced], 1
    mov byte [rel gp_probe], 0
    mov byte [rel gp_parked], 0
    mov byte [rel gp_mode], GP_FENCED
.same_fence:
    cmp rbx, [rel gp_token]
    jne .changed
    call hv_guest_power_current
    test rax, rax
    jnz .out
    mov edx, DP_ACK_FENCED
    jmp .ok
.stop:
    cmp byte [rel gp_mode], GP_PAUSED
    je .stopped
    cmp byte [rel gp_mode], GP_FENCED
    jne .changed
    cmp byte [rel gp_parked], 1
    jne .pending
    cmp qword [rel hv_guest_power_inflight], 0
    jne .pending
    mov byte [rel gp_mode], GP_PAUSED
.stopped:
    ; Deferred descriptors/host groups/IRQs retain custody, no inflight worker
    ; or vCPU can publish them while parked. No DMA capability is advertised.
    mov edx, DP_ACK_FENCED | DP_ACK_DRAINED | DP_ACK_IRQ_STOPPED
    jmp .ok
.restore:
    cmp byte [rel gp_mode], GP_PAUSED
    jne .restore_retry
    cmp byte [rel gp_parked], 1
    jne .pending
    cmp qword [rel hv_guest_power_inflight], 0
    jne .pending
    mov rax, [rel gp_exits]
    mov [rel gp_probe_start], rax
    mov byte [rel gp_mode], GP_RESTORE
.restore_retry:
    cmp byte [rel gp_mode], GP_RESTORE
    jb .changed
    mov edx, DP_ACK_FENCED
    jmp .ok
.verify:
    cmp byte [rel gp_mode], GP_FENCED
    jne .verify_probe
    ; Recovery after cancellation before STOP: never reset or claim PAUSED.
    ; Re-enter only the known original continuation and independently verify.
    cmp byte [rel gp_parked], 1
    jne .pending
    cmp qword [rel hv_guest_power_inflight], 0
    jne .pending
    mov rax, [rel gp_exits]
    mov [rel gp_probe_start], rax
    mov byte [rel gp_mode], GP_RESTORE
    jmp .pending
.verify_probe:
    cmp byte [rel gp_mode], GP_VERIFIED
    je .ready
    cmp byte [rel gp_mode], GP_PROVEN
    jne .pending
    cmp byte [rel gp_parked], 1
    jne .pending
    cmp qword [rel hv_guest_power_inflight], 0
    jne .pending
    mov rax, [rel gp_exits]
    cmp rax, [rel gp_probe_start]
    jbe .pending
    ; A decoder exit alone is insufficient: selected transports must still
    ; advertise their real negotiated readiness before admission can reopen.
    cmp byte [rel hv_vcon_ready], 1
    jne .pending
    test dword [rel vm_profile_dev_mask], VP_DEV_INPUT
    jz .entropy_ready
    cmp byte [rel gi_live], 1
    jne .pending
.entropy_ready:
    test dword [rel vm_profile_dev_mask], VP_DEV_ENTROPY
    jz .sound_ready
    cmp byte [rel gr_ready], 1
    jne .pending
    cmp dword [rel gr_status], 15
    jne .pending
.sound_ready:
    test dword [rel vm_profile_dev_mask], VP_DEV_SOUND
    jz .restore_ready
    cmp dword [rel gs_status], 15
    jne .pending
    cmp dword [rel gs_ctrl_ready], 1
    jne .pending
    cmp dword [rel gs_tx_ready], 1
    jne .pending
.restore_ready:
    test dword [rel vm_profile_dev_mask], VP_DEV_RESTORE
    jz .network_ready
    cmp dword [rel grs_status], 15
    jne .pending
.network_ready:
    test dword [rel vm_profile_dev_mask], VP_DEV_NET
    jz .transport_ready
    cmp dword [rel guestnet_status], 15
    jne .pending
    cmp byte [rel guestnet_driver_ok], 1
    jne .pending
    cmp byte [rel guestnet_net_up], 1
    jne .pending
    cmp byte [rel guestnet_q_ready], 1
    jne .pending
    cmp byte [rel guestnet_q_ready + 1], 1
    jne .pending
.transport_ready:
    mov byte [rel gp_mode], GP_VERIFIED
.ready:
    mov edx, DP_ACK_FENCED | DP_ACK_READY
    jmp .ok
.untouched:
    cmp r12d, DP_VERIFY
    jne .changed
    cmp byte [rel gp_mode], GP_IDLE
    jne .changed
    ; Cancel before this participant's FENCE: no resource was paused or freed.
    ; The still-live owner/backend must nevertheless be independently valid.
    lea rdi, [rel gp_owner]
    call hv_guest_power_owner_read
    test rax, rax
    jnz .out
    mov edx, DP_ACK_FENCED | DP_ACK_READY
.ok:
    xor eax, eax
    jmp .out
.pending:
    mov eax, DP_PENDING
    xor edx, edx
    jmp .out
.changed:
    mov rax, DP_CHANGED
    xor edx, edx
.out:
    add rsp, 8
    pop r12
    pop rbx
    cld
    ret

; Reached ONLY after the real vendor exit decoder completed and requested
; continuation, with guest GPRs saved and no device worker on this call stack.
; Not a callback wait: the resident task cooperatively parks, letting each
; bounded coordinator step run elsewhere on the same BSP. Existing host-slice
; STI/yield/CLI discipline is retained. VMX/SVM state is never reconstructed.
hv_guest_power_exit_gate:
    push rbx
    cmp qword [rel gp_exits], -1
    je .overflow
    inc qword [rel gp_exits]
.check:
    cmp byte [rel hv_guest_power_fenced], 0
    je .resume
    call hv_guest_power_current
    test rax, rax
    jnz .park                           ; changed owner: no pointer/device access
    cmp qword [rel hv_guest_power_inflight], 0
    jne .park
    mov byte [rel gp_parked], 1
    cmp byte [rel gp_mode], GP_RESTORE
    je .probe
    cmp byte [rel gp_mode], GP_PROBING
    jne .verified
    ; A second actual vendor exit/decoder, not RESTORE's assertion, earns proof.
    mov byte [rel gp_probe], 0
    mov byte [rel gp_mode], GP_PROVEN
.verified:
    cmp byte [rel gp_mode], GP_VERIFIED
    jne .park
    mov rax, [rel hv_guest_power_context]
    cmp dword [rax + dp_context.state], DP_RUNNING
    jne .park
    cmp qword [rax + dp_context.token], 0
    je .park
    mov rdx, [rel gp_token]
    cmp [rax + dp_context.token], rdx
    jne .park
    mov byte [rel gp_mode], GP_IDLE
    mov byte [rel gp_parked], 0
    mov byte [rel hv_guest_power_fenced], 0
    jmp .resume
.probe:
    mov eax, [rel sched_cur]
    mov [rel gp_task], eax
    mov byte [rel gp_mode], GP_PROBING
    mov byte [rel gp_probe], 1
    mov byte [rel gp_parked], 0
    jmp .resume
.park:
    call hv_guest_power_yield
    jmp .check
.overflow:
    cmp byte [rel hv_guest_power_fenced], 0
    jne .park
.resume:
    mov eax, 1
    pop rbx
    ret

; Same scheduling boundary as hv_linux_host_slice; tests replace only this
; privileged scheduling seam, never the parked lifecycle/phase implementation.
hv_guest_power_yield:
    sub rsp, 8
    sti
    call sched_yield
    cli
    add rsp, 8
    ret

%include "core/abi/wdata.inc"
%macro WDATA_hv_guest_power 0
align 8
hv_guest_power_context: dq 0
; Existing single vCPU slot lifetime. Never reset by pause, STOP or START.
hv_guest_power_generation: dq 1
hv_guest_power_inflight: dq 0
gp_token: dq 0
gp_exits: dq 0
gp_probe_start: dq 0
gp_driver: times dp_driver_size db 0
gp_owner: times GP_OWNER_BYTES db 0
hv_guest_power_fenced: db 0
gp_mode: db 0
gp_probe: db 0
gp_parked: db 0
align 4
gp_task: dd 0
%endmacro
WDATA_DEFER WDATA_hv_guest_power
