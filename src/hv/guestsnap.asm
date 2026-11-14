;; MODULE hv/guestsnap
%include "hv/guest_power.inc"
%include "core/abi/memory_budget.inc"

;; LAYER 5
;; EXPORTS guestsnap_verb, guestsnap_resume_admit, guestsnap_start_prepare, guestsnap_after_reserve, guestsnap_resume_ram, guestsnap_restore_devices, guestsnap_enter_state, guestsnap_capture, gsn_capture_req, gsn_resume_armed, gsn_resume_live, gsn_tsc_offset
;; IMPORTS hv/guest_power, hv/vmx, hv/vm_profile, hv/hv_ops, hv/guestnet, hv/guestrestore, boot/paging, core/memory_budget
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; In-memory guest snapshot and resume (RCQ-18 S2, spec 7.6.2 D4), Intel VMX only.
;
; Capture runs at hv_linux_enter.exit_landing after a handled exit that resumes
; the guest: the VMCS is current, the exit's side effects (RIP advance, pending
; injection) are written, and the guest-owned hardware state (syscall MSRs,
; KERNEL_GS_BASE, EFER SCE/NXE, XCR0, x87/SSE/AVX, CR2, DR0-3/DR6) is live.
; It stores a typed VMCS guest-state table, that CPU state, the PIC/PIT/UART
; and virtio transport fields of the selected devices, their guest-visible
; register pages, and all selected guest RAM in a host-private conventional
; memory buffer disjoint from the guest region. Never VMCS control/host fields,
; physical addresses, host pointers, NAT/ingress grants or identity latches.
;
; RESUME admits like START (same profile admission) and only when the snapshot
; is bound to the byte-identical profile record, device mask and RAM size on
; the VMX backend. The resumed run is a new START generation: new console,
; ring, restore-port owner and identity contexts; guest TSC continues from the
; captured value via TSC offsetting. The guest still needs the S1 restore-port
; notification (fresh generation/clock/seed) before any ingress is opened.
; The buffer holds guest secrets: never rendered, scrubbed on DISCARD.

GSN_DEV_SUPPORTED equ VP_DEV_TIMER | VP_DEV_CONSOLE | VP_DEV_NET | VP_DEV_RESTORE
GSN_XSAVE_MAX equ 8192
GSN_GRS_MAX equ 256
GSN_PAGES equ 3                          ; console, net, restore register pages
GSN_IDENTITY_CEILING equ 0x400000000     ; paging.asm identity-map ceiling
GSN_E_NONE equ 0
GSN_E_STATE equ 1                       ; not running / no snapshot / busy
GSN_E_DEVICES equ 2                     ; profile selects an unsupported device
GSN_E_BUFFER equ 3                      ; no disjoint conventional range
GSN_E_VMCS equ 4                        ; a VMREAD failed
GSN_E_XSAVE equ 5                       ; no XSAVE or area beyond bound
GSN_E_BACKEND equ 6                     ; not the VMX backend
GSN_E_BINDING equ 7                     ; profile record/mask/RAM differ
GSN_E_OVERLAP equ 8                     ; a new guest region took the buffer
GSN_E_WARM equ 10                       ; warm lifetime/exclusion fence not retired
GSN_E_GRS equ 9                         ; restore-port span beyond its slot

; Every device field is copied in both directions from this one list.
; Derived latches belong here too: a resumed driver never rewrites the MMIO
; that set them (guestnet_net_up gates GUESTSSH). Fields the device resets
; clear but this list omits are classified in test_rcq18_guestsnap_host.
%macro GSN_DEVICE_FIELDS 1
    %1 hv_pic_mask, 1
    %1 hv_pic_mask_s, 1
    %1 hv_port61, 1
    %1 hv_pit2_mode0, 1
    %1 hv_pit_ff, 3
    %1 hv_pit_latched, 3
    %1 hv_pit_reload, 6
    %1 hv_pit_latch, 6
    %1 hv_pic_state_m, 1
    %1 hv_pic_state_s, 1
    %1 hv_pic_icw1_m, 1
    %1 hv_pic_icw1_s, 1
    %1 hv_pic_vec_base, 1
    %1 hv_linux_uart, 8
    %1 hv_vcon_status, 4
    %1 hv_vcon_isr, 4
    %1 hv_vcon_q_num, 8
    %1 hv_vcon_qsel, 4
    %1 hv_vcon_dfsel, 4
    %1 hv_vcon_drvfsel, 4
    %1 hv_vcon_drvfeat, 8
    %1 hv_vcon_feat_bad, 4
    %1 hv_vcon_q_ready, 2
    %1 hv_vcon_ready, 1
    %1 hv_vcon_irq_pend, 1
    %1 hv_vcon_irq_inj, 1
    %1 hv_vcon_q_lastav, 4
    %1 hv_vcon_q_usedidx, 4
    %1 hv_vcon_q_desc, 16
    %1 hv_vcon_q_avail, 16
    %1 hv_vcon_q_used, 16
    %1 guestnet_q_desc, 16
    %1 guestnet_q_avail, 16
    %1 guestnet_q_used, 16
    %1 guestnet_qsel, 4
    %1 guestnet_dfsel, 4
    %1 guestnet_drvfsel, 4
    %1 guestnet_drvfeat, 8
    %1 guestnet_feat_bad, 1
    %1 guestnet_status, 4
    %1 guestnet_isr, 4
    %1 guestnet_q_num, 8
    %1 guestnet_q_lastav, 4
    %1 guestnet_q_usedidx, 4
    %1 guestnet_q_ready, 2
    %1 guestnet_driver_ok, 1
    %1 guestnet_net_up, 1
    %1 guestnet_irq_pending, 1
    %1 guestnet_irq_injected, 1
    %1 guestnet_lease_ip, 4
%endmacro

%assign gsn_dev_total 0
%macro GSN_SIZE 2
    %assign gsn_dev_total gsn_dev_total + %2
%endmacro
GSN_DEVICE_FIELDS GSN_SIZE
GSN_DEV_BYTES equ gsn_dev_total

%macro GSN_SAVE 2
    lea  rsi, [rel %1]
    lea  rdi, [rel gsn_dev + gsn_off]
    mov  ecx, %2
    rep  movsb
    %assign gsn_off gsn_off + %2
%endmacro
%macro GSN_LOAD 2
    lea  rsi, [rel gsn_dev + gsn_off]
    lea  rdi, [rel %1]
    mov  ecx, %2
    rep  movsb
    %assign gsn_off gsn_off + %2
%endmacro

; Each selected control page uses the exact live allocator record at its
; actual transfer boundary. This macro only names trusted static endpoints.
%macro GSN_CONTROL_PAGE 3
    test ebx, %1
    jz %%skip
    mov qword [rsp + MB_CONTROL_OFFSET], %2
    lea rax, [rel gsn_pages + %3 * 4096]
    mov [rsp + MB_CONTROL_HOST], rax
    mov rdi, rsp
    call mb_guest_control_copy
    test eax, eax
    jnz .out
%%skip:
%endmacro

; Guest-state VMCS fields restored on resume, in VMWRITE order. Controls, host
; area, EPTP, link pointer and MSR areas are rebuilt by the normal launch path.
gsn_vmcs_fields:
    dw VMXF_GUEST_ES_SEL, VMXF_GUEST_CS_SEL, VMXF_GUEST_SS_SEL, VMXF_GUEST_DS_SEL
    dw VMXF_GUEST_FS_SEL, VMXF_GUEST_GS_SEL, VMXF_GUEST_LDTR_SEL, VMXF_GUEST_TR_SEL
    dw VMXF_G_DEBUGCTL
    dw VMXF_G_ES_LIMIT, VMXF_G_CS_LIMIT, VMXF_G_SS_LIMIT, VMXF_G_DS_LIMIT, VMXF_G_FS_LIMIT
    dw VMXF_G_GS_LIMIT, VMXF_G_LDTR_LIMIT, VMXF_G_TR_LIMIT, VMXF_G_GDTR_LIMIT, VMXF_G_IDTR_LIMIT
    dw VMXF_G_ES_AR, VMXF_G_CS_AR, VMXF_G_SS_AR, VMXF_G_DS_AR, VMXF_G_FS_AR, VMXF_G_GS_AR
    dw VMXF_G_LDTR_AR, VMXF_G_TR_AR
    dw VMXF_G_INTERRUPT, VMXF_G_ACTIVITY, VMXF_G_SYSENTER_CS
    dw VMXF_G_CR0, VMXF_G_CR3, VMXF_G_CR4
    dw VMXF_G_ES_BASE, VMXF_G_CS_BASE, VMXF_G_SS_BASE, VMXF_G_DS_BASE, VMXF_G_FS_BASE
    dw VMXF_G_GS_BASE, VMXF_G_LDTR_BASE, VMXF_G_TR_BASE, VMXF_G_GDTR_BASE, VMXF_G_IDTR_BASE
    dw VMXF_G_DR7, VMXF_G_RSP, VMXF_G_RIP, VMXF_G_RFLAGS, VMXF_G_PEND_DBG
    dw VMXF_G_SYSENTER_ESP, VMXF_G_SYSENTER_EIP
    dw VMXF_ENTRY_INTR, VMXF_ENTRY_ERRCODE, VMXF_ENTRY_ILEN
gsn_vmcs_fields_end:
GSN_VMCS_COUNT equ (gsn_vmcs_fields_end - gsn_vmcs_fields) / 2
VMXF_TSC_OFFSET equ 0x2010
GSN_PROC_TSC_OFFSET equ 0x8

; Guest syscall MSRs restored on resume (EFER contributes only SCE/NXE).
gsn_msr_list:
    dd 0xC0000080, 0xC0000081, 0xC0000082, 0xC0000083, 0xC0000084, 0xC0000102
GSN_MSR_COUNT equ 6
GSN_EFER_GUEST_BITS equ 0x801

; EAX=1 when the active hv_ops backend is VMX.
guestsnap_is_vmx:
    lea  rax, [rel hv_ops_vmx]
    cmp  [rel hv_ops_active], rax
    sete al
    movzx eax, al
    ret

; EAX=1 when the active profile selects only supported devices.
guestsnap_devices_ok:
    xor  eax, eax
    cmp  qword [rel vm_profile_active], 0
    je   .out
    mov  ecx, [rel vm_profile_dev_mask]
    test ecx, ~GSN_DEV_SUPPORTED
    jnz  .out
    cmp  ecx, [rel vm_profile_live_devices]
    jne  .out
    mov  eax, 1
.out:
    ret

; RC-speed-reserve: the RAM copy is one shared span (owner GUESTSNAP, kind
; SNAPSHOT, generation = the capturing START), disjoint by construction from
; every live guest span. Held from the first capture until DISCARD scrubs and
; releases it; a later capture reuses it while large enough, else scrubs and
; releases it first. RAX = base or 0.
guestsnap_reserve:
    mov  rax, [rel gsn_buf]
    test rax, rax
    jz   .acquire
    mov  rcx, [rel hv_linux_ram_bytes]
    cmp  rcx, [rel gsn_buf_bytes]
    jbe  .out
    call guestsnap_release
    cmp  qword [rel gsn_buf], 0
    jne  .none
.acquire:
    mov  edi, MB_OWNER_GUESTSNAP
    mov  esi, [rel hv_linux_start_consumed]
    mov  edx, MB_KIND_SNAPSHOT
    mov  rcx, [rel hv_linux_ram_bytes]
    mov  r8d, 0x200000
    xor  r9d, r9d                               ; a copy, not resident guest RAM
    call mb_acquire
    test eax, eax
    jnz  .none
    mov  [rel gsn_mb_token], rdx
    mov  eax, [rel hv_linux_start_consumed]
    mov  [rel gsn_mb_gen], rax
    mov  [rel gsn_buf], r8
    mov  [rel gsn_buf_bytes], r9
    mov  rax, r8
.out:
    ret
.none:
    xor  eax, eax
    ret

; Scrub the whole RAM-copy span, then return it. Each bounded clear joins the
; cached geometry to the exact live allocator record under its lock. Native
; stopped-vCPU/BSP custody excludes capture/resume; this loop never yields.
; A refused clear/release keeps all addresses and keys for DISCARD retry.
guestsnap_release:
    push rbx
    sub  rsp, 32
    mov  rax, [rel gsn_buf]
    mov  [rsp], rax
    or   rax, [rel gsn_buf_bytes]
    or   rax, [rel gsn_mb_token]
    or   rax, [rel gsn_mb_gen]
    jz   .out                              ; only the fully empty state is idle
    mov  rax, [rel gsn_buf_bytes]
    mov  [rsp + 8], rax
    xor  ebx, ebx
.chunk:
    mov  rax, [rsp + 8]
    sub  rax, rbx
    cmp  rax, MB_SNAPSHOT_ZERO_MAX
    jbe  .extent
    mov  eax, MB_SNAPSHOT_ZERO_MAX
.extent:
    mov  [rsp + 16], rbx
    mov  [rsp + 24], rax
    mov  edi, MB_OWNER_GUESTSNAP
    mov  rsi, [rel gsn_mb_gen]
    mov  rdx, [rel gsn_mb_token]
    mov  rcx, rsp
    call mb_snapshot_zero
    test eax, eax
    jnz  .refused
    cmp  qword [rsp + 24], 0
    je   .release                          ; full extent validated, including retries
    add  rbx, [rsp + 24]                    ; progress only after the actual clear
    jmp  .chunk
.release:
    mov  edi, MB_OWNER_GUESTSNAP
    mov  rsi, [rel gsn_mb_gen]
    mov  rdx, [rel gsn_mb_token]
    call mb_release
    test eax, eax
    jnz  .refused
    mov  qword [rel gsn_buf], 0
    mov  qword [rel gsn_buf_bytes], 0
    mov  qword [rel gsn_mb_token], 0
    mov  qword [rel gsn_mb_gen], 0
.out:
    add  rsp, 32
    pop  rbx
    ret
.refused:
    inc  dword [rel gsn_release_refused]
    jmp  .out

; Capture at a handled, resuming VM exit. Consumes gsn_capture_req. Any
; refusal leaves no snapshot (a partial record is never valid).
guestsnap_capture:
    HV_POWER_WORK guestsnap_capture, 0, hv_guest_power_admit
    pushfq
    cld
    push rbx
    push r12
    sub  rsp, 32                           ; exact gen/token/serial + fence-held
    mov  qword [rsp + 24], 0
    mov  byte [rel gsn_capture_req], 0
    mov  byte [rel gsn_state], 0
    ; Retry an exact fence whose prior End refused BUSY. Never abandon it.
    mov  ebx, GSN_E_WARM
    call guestsnap_capture_unfence
    test eax, eax
    jnz  .refuse
    mov  ebx, GSN_E_STATE
    cmp  byte [rel hv_linux_running], 1
    jne  .refuse
    cmp  byte [rel hv_launch_mode], 1
    jne  .refuse
    mov  ebx, GSN_E_BACKEND
    call guestsnap_is_vmx
    test eax, eax
    jz   .refuse
    mov  ebx, GSN_E_DEVICES
    call guestsnap_devices_ok
    test eax, eax
    jz   .refuse
    mov  ebx, GSN_E_GRS
    mov  ecx, grs_state_end - grs_q_addr
    cmp  ecx, GSN_GRS_MAX
    ja   .refuse
    ; Fence admission through the actual copy; a warm grant cannot appear
    ; after a successful precheck. The guest is stopped, no yielding call.
    mov  ebx, GSN_E_WARM
    cmp  qword [rel gsn_capture_serial], -1
    je   .refuse                            ; never wrap/reuse a capture serial
    inc  qword [rel gsn_capture_serial]
    mov  rsi, [rel hv_linux_mb_gen]
    mov  rdx, [rel hv_linux_mb_token]
    mov  rcx, [rel gsn_capture_serial]
    mov  [rsp], rsi
    mov  [rsp + 8], rdx
    mov  [rsp + 16], rcx
    mov  edi, MB_OWNER_HV_LINUX
    call mb_guest_capture_begin
    cmp  eax, MB_E_BUSY
    jne  .fence_result
    mov  ebx, GSN_E_BUFFER                  ; retain existing busy diagnostic
.fence_result:
    test eax, eax
    jnz  .refuse
    mov  qword [rsp + 24], 1
    mov  ebx, GSN_E_BUFFER
    call guestsnap_reserve
    test rax, rax
    jz   .refuse
    ; Typed VMCS guest area.
    mov  ebx, GSN_E_VMCS
    xor  r12d, r12d
.vmcs:
    lea  rax, [rel gsn_vmcs_fields]
    movzx edi, word [rax + r12 * 2]
    call hv_vmx_guest_read
    jc   .refuse
    jz   .refuse
    lea  rcx, [rel gsn_vmcs]
    mov  [rcx + r12 * 8], rax
    inc  r12d
    cmp  r12d, GSN_VMCS_COUNT
    jb   .vmcs
    ; Guest-owned hardware state (privileged; one seam).
    mov  ebx, GSN_E_XSAVE
    call guestsnap_cpu_capture
    test eax, eax
    jz   .refuse
    lea  rsi, [rel hv_linux_gpr]
    lea  rdi, [rel gsn_gpr]
    mov  ecx, 15
    rep  movsq
    %assign gsn_off 0
    GSN_DEVICE_FIELDS GSN_SAVE
    lea  rsi, [rel grs_q_addr]
    lea  rdi, [rel gsn_grs]
    mov  ecx, grs_state_end - grs_q_addr
    rep  movsb
    mov  eax, [rel vm_profile_dev_mask]
    mov  [rel gsn_dev_mask], eax
    mov  ebx, GSN_E_BUFFER
    mov  rdi, [rel hv_linux_region]
    xor  esi, esi
    call guestsnap_copy_pages
    test eax, eax
    jnz  .refuse
    mov  rsi, [rel vm_profile_active]
    lea  rdi, [rel gsn_profile]
    mov  ecx, VP_BYTES
    rep  movsb
    mov  rax, [rel hv_linux_ram_bytes]
    mov  [rel gsn_ram_bytes], rax
    mov  eax, [rel hv_linux_start_consumed]
    mov  [rel gsn_cap_gen], eax
    ; All selected RAM last: the guest is stopped for the whole capture.
    mov  ebx, GSN_E_BUFFER
    xor  edi, edi                         ; capture under the exact live fence
    call guestsnap_copy_ram
    test eax, eax
    jnz  .refuse
    ; Publish validity only after dropping the exact exclusion fence below.
    xor  ebx, ebx
    jmp  .out
.refuse:
    inc  dword [rel gsn_refused]
.out:
    cmp  qword [rsp + 24], 0
    je   .publish
    mov  rax, [rsp]
    mov  [rel gsn_fence_gen], rax
    mov  rax, [rsp + 8]
    mov  [rel gsn_fence_token], rax
    mov  rax, [rsp + 16]
    mov  [rel gsn_fence_serial], rax
    call guestsnap_capture_unfence
    test eax, eax
    jz   .publish
    ; Refused release is fail-closed: keep the fence, never publish a copy.
    test ebx, ebx
    jnz  .end_refused
    inc  dword [rel gsn_refused]
.end_refused:
    mov  ebx, GSN_E_WARM
.publish:
    mov  [rel gsn_last_err], ebx
    test ebx, ebx
    jnz  .return
    mov  byte [rel gsn_state], 2
    inc  dword [rel gsn_captures]
.return:
    add  rsp, 32
    pop  r12
    pop  rbx
    popfq
    ret

; EDI=0 capture,1 restore. Both physical records and cached geometry are joined
; to each bounded real copy under the allocator lock; no unchecked raw pointer
; copy follows a precheck. Retain native stopped-vCPU/BSP custody across the
; nonyielding loop. Failure after a chunk never publishes capture/entry success.
guestsnap_copy_ram:
    push rbx
    sub rsp, MB_COPY_SIZE
    mov [rsp + MB_COPY_DIRECTION], rdi
    mov eax, MB_E_INPUT
    mov rdx, [rel hv_linux_region]
    mov [rsp + MB_COPY_GUEST_BASE], rdx
    add rdx, HV_LINUX_CTRL_BYTES
    jc .out
    cmp rdx, [rel hv_linux_ram]
    jne .out
    mov [rsp + MB_COPY_GUEST_RAM], rdx
    mov rdx, [rel hv_linux_region_capacity]
    mov [rsp + MB_COPY_GUEST_CAPACITY], rdx
    mov rdx, [rel hv_linux_ram_bytes]
    mov [rsp + MB_COPY_RAM_BYTES], rdx
    mov rdx, [rel hv_linux_mb_gen]
    mov [rsp + MB_COPY_GUEST_GEN], rdx
    mov rdx, [rel hv_linux_mb_token]
    mov [rsp + MB_COPY_GUEST_TOKEN], rdx
    mov rdx, [rel gsn_mb_gen]
    mov [rsp + MB_COPY_SNAP_GEN], rdx
    mov rdx, [rel gsn_mb_token]
    mov [rsp + MB_COPY_SNAP_TOKEN], rdx
    mov rdx, [rel gsn_buf]
    mov [rsp + MB_COPY_SNAP_BASE], rdx
    mov rdx, [rel gsn_buf_bytes]
    mov [rsp + MB_COPY_SNAP_CAPACITY], rdx
    xor edx, edx
    test rdi, rdi
    jnz .serial
    mov rdx, [rel gsn_capture_serial]
.serial:
    mov [rsp + MB_COPY_SERIAL], rdx
    xor ebx, ebx
.chunk:
    mov rax, [rsp + MB_COPY_RAM_BYTES]
    sub rax, rbx
    cmp rax, MB_SNAPSHOT_COPY_MAX
    jbe .extent
    mov eax, MB_SNAPSHOT_COPY_MAX
.extent:
    mov [rsp + MB_COPY_OFFSET], rbx
    mov [rsp + MB_COPY_LENGTH], rax
    mov rdi, rsp
    call mb_snapshot_copy
    test eax, eax
    jnz .out
    cmp qword [rsp + MB_COPY_LENGTH], 0
    je .out                              ; exact full extent validated last
    add rbx, [rsp + MB_COPY_LENGTH]
    jmp .chunk
.out:
    add rsp, MB_COPY_SIZE
    pop rbx
    ret

; RDI=actual control base, ESI=0 capture/1 restore, EAX=allocator status.
; Descriptor HOST endpoints and offsets are fixed native symbols/constants.
; No yield/callback; retain stopped-vCPU/BSP custody across selected pages.
guestsnap_copy_pages:
    push rbx
    sub rsp, MB_CONTROL_SIZE
    mov [rsp + MB_CONTROL_DIRECTION], rsi
    mov eax, MB_E_INPUT
    cmp rdi, [rel hv_linux_region]
    jne .out
    mov [rsp + MB_CONTROL_BASE], rdi
    add rdi, HV_LINUX_CTRL_BYTES
    jc .out
    cmp rdi, [rel hv_linux_ram]
    jne .out
    mov [rsp + MB_CONTROL_RAM], rdi
    mov rax, [rel hv_linux_region_capacity]
    mov [rsp + MB_CONTROL_CAPACITY], rax
    mov rax, [rel hv_linux_ram_bytes]
    mov [rsp + MB_CONTROL_RAM_BYTES], rax
    mov rax, [rel hv_linux_mb_gen]
    mov [rsp + MB_CONTROL_GEN], rax
    mov rax, [rel hv_linux_mb_token]
    mov [rsp + MB_CONTROL_TOKEN], rax
    xor eax, eax
    test rsi, rsi
    jnz .serial
    mov rax, [rel gsn_capture_serial]
.serial:
    mov [rsp + MB_CONTROL_SERIAL], rax
    mov ebx, [rel gsn_dev_mask]
    GSN_CONTROL_PAGE VP_DEV_CONSOLE, HV_VCON_PAGE, 0
    GSN_CONTROL_PAGE VP_DEV_NET, HV_GUESTNET_PAGE, 1
    GSN_CONTROL_PAGE VP_DEV_RESTORE, HV_GUESTRST_PAGE, 2
    xor eax, eax
.out:
    add rsp, MB_CONTROL_SIZE
    pop rbx
    ret

; Retry the saved exact End after a transient lock refusal. DISCARD also calls
; this, so a completed/refused capture cannot strand an exclusion indefinitely.
; No retry loop: the caller retains custody on BUSY and can retry later.
guestsnap_capture_unfence:
    cmp qword [rel gsn_fence_token], 0
    je .none
    sub rsp, 8
    mov edi, MB_OWNER_HV_LINUX
    mov rsi, [rel gsn_fence_gen]
    mov rdx, [rel gsn_fence_token]
    mov rcx, [rel gsn_fence_serial]
    call mb_guest_capture_end
    test eax, eax
    jnz .out
    mov qword [rel gsn_fence_token], 0
    mov qword [rel gsn_fence_gen], 0
    mov qword [rel gsn_fence_serial], 0
.out:
    add rsp, 8
    ret
.none:
    xor eax, eax
    ret

; Privileged capture of guest-owned hardware state. EAX=1 ok, 0 refused.
guestsnap_cpu_capture:
    push rbx
    push r12
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    add  rax, [rel gsn_tsc_offset]
    mov  [rel gsn_guest_tsc], rax
    mov  rax, cr2
    mov  [rel gsn_cr2], rax
    mov  rax, dr0
    mov  [rel gsn_dr + 0], rax
    mov  rax, dr1
    mov  [rel gsn_dr + 8], rax
    mov  rax, dr2
    mov  [rel gsn_dr + 16], rax
    mov  rax, dr3
    mov  [rel gsn_dr + 24], rax
    mov  rax, dr6
    mov  [rel gsn_dr + 32], rax
    xor  r12d, r12d
.msr:
    lea  rax, [rel gsn_msr_list]
    mov  ecx, [rax + r12 * 4]
    rdmsr
    shl  rdx, 32
    or   rax, rdx
    lea  rcx, [rel gsn_msr]
    mov  [rcx + r12 * 8], rax
    inc  r12d
    cmp  r12d, GSN_MSR_COUNT
    jb   .msr
    mov  rax, cr4
    bt   rax, 18                                ; OSXSAVE (hv_linux_host_xsave)
    jnc  .bad
    xor  ecx, ecx
    xgetbv
    shl  rdx, 32
    or   rax, rdx
    mov  [rel gsn_xcr0], rax
    mov  eax, 0xD
    xor  ecx, ecx
    cpuid                                       ; EBX = area for the current XCR0
    cmp  ebx, GSN_XSAVE_MAX
    ja   .bad
    mov  [rel gsn_xsave_bytes], ebx
    mov  eax, 1
    cpuid
    mov  [rel gsn_cpuid1], eax
    call guestsnap_xsave_area
    mov  rbx, rax
    mov  rdi, rax
    xor  eax, eax
    mov  ecx, GSN_XSAVE_MAX / 8
    rep  stosq
    mov  rax, [rel gsn_xcr0]
    mov  rdx, rax
    shr  rdx, 32
    xsave64 [rbx]
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

; RAX = 64-byte aligned XSAVE area inside gsn_xsave_raw.
guestsnap_xsave_area:
    lea  rax, [rel gsn_xsave_raw + 63]
    and  rax, -64
    ret

; Called once per admitted START (EDI = backend: 0 VMX). Decides whether this
; generation resumes; the armed request is always consumed.
guestsnap_start_prepare:
    mov  byte [rel gsn_resume_live], 0
    mov  qword [rel gsn_tsc_offset], 0
    cmp  byte [rel gsn_resume_armed], 1
    mov  byte [rel gsn_resume_armed], 0
    jne  .out
    test edi, edi
    jnz  .out
    cmp  byte [rel gsn_state], 2
    jne  .out
    mov  eax, [rel gsn_resume_gen]
    cmp  eax, [rel hv_linux_start_consumed]
    jne  .out
    mov  byte [rel gsn_resume_live], 1
.out:
    ret

; After hv_linux_reserve (RDI = control base). A new guest region overlapping
; the buffer invalidates the snapshot. EAX = 1 when this START resumes.
guestsnap_after_reserve:
    mov  rax, [rel gsn_buf]
    test rax, rax
    jz   .live
    mov  rdx, rdi
    add  rdx, HV_LINUX_CTRL_BYTES
    add  rdx, [rel hv_linux_ram_bytes]
    add  rdx, [rel hv_linux_fb_bytes]
    mov  rcx, rax
    add  rcx, [rel gsn_buf_bytes]
    cmp  rcx, rdi
    jbe  .live
    cmp  rax, rdx
    jae  .live
    ; Shared spans are disjoint, so this is a bypassed owner table: drop the
    ; snapshot but keep custody of the span (DISCARD scrubs and releases it).
    cmp  byte [rel gsn_state], 2
    jne  .drop
    mov  dword [rel gsn_last_err], GSN_E_OVERLAP
.drop:
    mov  byte [rel gsn_state], 0
    mov  byte [rel gsn_resume_live], 0
.live:
    movzx eax, byte [rel gsn_resume_live]
    ret

; Verify the resumed START is bound to the captured shape, then restore RAM
; (RDI = guest RAM HPA). EAX = 1 ok, 0 refused (snapshot kept).
guestsnap_resume_ram:
    pushfq
    cld
    mov  rdx, rdi
    call guestsnap_bound
    test eax, eax
    jz   .refused
    cmp  rdx, [rel hv_linux_ram]
    jne  .refused                         ; never accept an arbitrary destination
    mov  edi, 1
    call guestsnap_copy_ram
    test eax, eax
    jnz  .refused
    mov  eax, 1
    jmp  .out
.refused:
    mov  dword [rel gsn_last_err], GSN_E_BINDING
    mov  byte [rel gsn_resume_live], 0
    xor  eax, eax
.out:
    popfq
    ret

; EAX = 1 when the active profile, devices, RAM and backend match the
; snapshot. Preserves RDX.
guestsnap_bound:
    push rdx
    xor  eax, eax
    cmp  byte [rel gsn_state], 2
    jne  .out
    cmp  qword [rel gsn_buf], 0
    je   .out
    call guestsnap_is_vmx
    test eax, eax
    jz   .out
    xor  eax, eax
    mov  rcx, [rel hv_linux_ram_bytes]
    cmp  rcx, [rel gsn_ram_bytes]
    jne  .out
    mov  ecx, [rel vm_profile_dev_mask]
    cmp  ecx, [rel gsn_dev_mask]
    jne  .out
    mov  rsi, [rel vm_profile_active]
    test rsi, rsi
    jz   .out
    lea  rdi, [rel gsn_profile]
    mov  ecx, VP_BYTES
    repe cmpsb
    jne  .out
    mov  eax, 1
.out:
    pop  rdx
    ret

; After the normal device resets of a resumed START (RDI = control base):
; transport fields, restore-port span and register pages from the snapshot.
; Host deadlines restart; the init phrase is already behind the guest.
guestsnap_restore_devices:
    HV_POWER_WORK guestsnap_restore_devices, 0, hv_guest_power_admit
    pushfq
    cld
    push rdi
    cmp byte [rel gsn_resume_live], 1
    jne .refused
    call guestsnap_bound
    test eax, eax
    jz .refused
    mov rdi, [rsp]
    mov esi, 1
    call guestsnap_copy_pages
    test eax, eax
    jnz .refused
    add rsp, 8
    ; Publish device fields only after all selected page copies succeeded.
    %assign gsn_off 0
    GSN_DEVICE_FIELDS GSN_LOAD
    lea  rsi, [rel gsn_grs]
    lea  rdi, [rel grs_q_addr]
    mov  ecx, grs_state_end - grs_q_addr
    rep  movsb
    mov  byte [rel grs_notify_req], 0           ; a request never survives a resume
    mov  byte [rel hv_pit2_armed], 0
    mov  qword [rel hv_pit2_remaining], 0
    mov  qword [rel hv_pit2_deadline], 0
    mov  qword [rel hv_last_tick_tsc], 0
    mov  word [rel hv_uart_thre], 0             ; RCQ-36: a resumed THR is empty, THRE reasserts
    mov  byte [rel hv_linux_kboot], 1
    mov  eax, 1
    popfq
    ret
.refused:
    add rsp, 8
    mov dword [rel gsn_last_err], GSN_E_BINDING
    mov byte [rel gsn_resume_live], 0
    xor eax, eax                           ; actual loader takes .resume_bad
    popfq
    ret

; Inside hv_linux_enter after the normal state writes of a resumed START:
; the captured guest area, TSC offsetting and guest-owned hardware state.
guestsnap_enter_state:
    push rbx
    push r12
    xor  r12d, r12d
.vmcs:
    lea  rax, [rel gsn_vmcs_fields]
    movzx edi, word [rax + r12 * 2]
    lea  rax, [rel gsn_vmcs]
    mov  rsi, [rax + r12 * 8]
    call hv_w
    inc  r12d
    cmp  r12d, GSN_VMCS_COUNT
    jb   .vmcs
    ; TSC offsetting: the guest's TSC continues from the captured value.
    call guestsnap_tsc_offset_allowed
    test eax, eax
    jz   .no_offset
    mov  edi, VMXF_PROC_CTLS
    call hv_vmx_guest_read
    or   eax, GSN_PROC_TSC_OFFSET
    mov  edi, VMXF_PROC_CTLS
    mov  esi, eax
    call hv_w
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  rsi, [rel gsn_guest_tsc]
    sub  rsi, rax
    mov  [rel gsn_tsc_offset], rsi
    mov  edi, VMXF_TSC_OFFSET
    call hv_w
    jmp  .cpu
.no_offset:
    inc  dword [rel hv_vmwrite_fails]           ; refuse: guest time would jump
.cpu:
    call guestsnap_cpu_load
    lea  rsi, [rel gsn_gpr]
    lea  rdi, [rel hv_linux_gpr]
    mov  ecx, 15
    rep  movsq
    inc  dword [rel gsn_resumes]
    pop  r12
    pop  rbx
    ret

; EAX = 1 when the processor allows "use TSC offsetting" (privileged seam).
guestsnap_tsc_offset_allowed:
    mov  ecx, 0x480
    rdmsr
    mov  ecx, 0x482
    bt   edx, 23                                ; IA32_VMX_BASIC[55] => TRUE controls
    jnc  .proc_msr
    mov  ecx, 0x48E
.proc_msr:
    rdmsr
    xor  eax, eax
    test edx, GSN_PROC_TSC_OFFSET               ; allowed-1 half
    setnz al
    ret

; Privileged load of guest-owned hardware state, after the host MSRs/XCR0 are
; saved (hv_linux_save_host_msrs, hv_linux_host_xsave). Teardown restores them.
guestsnap_cpu_load:
    push rbx
    push r12
    xor  r12d, r12d
.msr:
    lea  rax, [rel gsn_msr_list]
    mov  ecx, [rax + r12 * 4]
    lea  rax, [rel gsn_msr]
    mov  rbx, [rax + r12 * 8]
    test r12d, r12d
    jnz  .write
    rdmsr                                       ; EFER: keep host LME/LMA
    shl  rdx, 32
    or   rax, rdx
    and  rax, ~GSN_EFER_GUEST_BITS
    and  rbx, GSN_EFER_GUEST_BITS
    or   rbx, rax
.write:
    mov  eax, ebx
    mov  rdx, rbx
    shr  rdx, 32
    wrmsr
    inc  r12d
    cmp  r12d, GSN_MSR_COUNT
    jb   .msr
    mov  rax, [rel gsn_dr + 0]
    mov  dr0, rax
    mov  rax, [rel gsn_dr + 8]
    mov  dr1, rax
    mov  rax, [rel gsn_dr + 16]
    mov  dr2, rax
    mov  rax, [rel gsn_dr + 24]
    mov  dr3, rax
    mov  rax, [rel gsn_dr + 32]
    mov  dr6, rax
    mov  rax, [rel gsn_xcr0]
    mov  rdx, rax
    shr  rdx, 32
    xor  ecx, ecx
    xsetbv
    call guestsnap_xsave_area
    mov  rbx, rax
    mov  rax, [rel gsn_xcr0]
    mov  rdx, rax
    shr  rdx, 32
    xrstor64 [rbx]
    mov  rax, [rel gsn_cr2]
    mov  cr2, rax
    pop  r12
    pop  rbx
    ret

; RESUME admission (RDI = profile record). EAX = 0 armed for the next
; published generation, else GSN_E_*. Arms nothing on refusal.
guestsnap_resume_admit:
    HV_POWER_WORK guestsnap_resume_admit, GSN_E_STATE, hv_guest_power_admit
    pushfq
    cld
    mov  byte [rel gsn_resume_armed], 0
    mov  eax, GSN_E_STATE
    cmp  byte [rel gsn_state], 2
    jne  .refuse
    cmp  qword [rel gsn_buf], 0
    je   .refuse
    mov  eax, GSN_E_BACKEND
    push rdi
    call guestsnap_is_vmx
    pop  rdi
    test eax, eax
    mov  eax, GSN_E_BACKEND
    jz   .refuse
    mov  rsi, rdi
    lea  rdi, [rel gsn_profile]
    mov  ecx, VP_BYTES
    repe cmpsb
    mov  eax, GSN_E_BINDING
    jne  .refuse
    mov  eax, [rel hv_linux_start_gen]
    inc  eax
    mov  [rel gsn_resume_gen], eax
    mov  byte [rel gsn_resume_armed], 1
    xor  eax, eax
    jmp  .out
.refuse:
    mov  [rel gsn_last_err], eax
    inc  dword [rel gsn_refused]
.out:
    popfq
    ret

; GUESTVM SNAPSHOT [STAT|DISCARD] (RDI = text after SNAPSHOT). Bare SNAPSHOT
; requests one capture at the next resuming exit of the running guest; STAT
; only renders; DISCARD scrubs the copy.
guestsnap_verb:
    HV_POWER_WORK guestsnap_verb, 0, hv_guest_power_admit
    push rbx
    mov  rbx, rdi
    call hv_out_reset
    lea  rdi, [rel str_gsn_head]
    call hv_out_str
    mov  rdi, rbx
    call hv_skip_spaces
    mov  rbx, rax
    cmp  byte [rax], 0
    je   .request
    mov  rdi, rax
    lea  rsi, [rel str_gsn_stat_tok]
    call hv_tok_is
    test al, al
    jnz  .stat
    mov  rdi, rbx
    lea  rsi, [rel str_gsn_discard]
    call hv_tok_is
    test al, al
    jz   .usage
    cmp  byte [rel gsn_capture_req], 0
    jne  .stat
    call guestsnap_discard
    lea  rdi, [rel str_gsn_discarded]
    mov  rax, [rel gsn_buf]
    or   rax, [rel gsn_buf_bytes]
    or   rax, [rel gsn_mb_token]
    or   rax, [rel gsn_mb_gen]
    or   rax, [rel gsn_fence_token]
    jz   .discard_result
    lea  rdi, [rel str_gsn_discard_retained]
.discard_result:
    call hv_out_str
    jmp  .stat
.request:
    cmp  byte [rel hv_linux_running], 1
    jne  .refused
    cmp  byte [rel hv_launch_mode], 1
    jne  .refused
    call guestsnap_is_vmx
    test eax, eax
    jz   .refused
    call guestsnap_devices_ok
    test eax, eax
    jz   .refused
    mov  byte [rel gsn_capture_req], 1
    lea  rdi, [rel str_gsn_queued]
    call hv_out_str
    jmp  .stat
.refused:
    lea  rdi, [rel str_gsn_refused_req]
    call hv_out_str
    jmp  .stat
.usage:
    lea  rdi, [rel str_gsn_usage]
    call hv_out_str
.stat:
    lea  rdi, [rel str_gsn_state]
    call hv_out_str
    movzx eax, byte [rel gsn_state]
    call hv_out_dec
    lea  rdi, [rel str_gsn_pending]
    call hv_out_str
    movzx eax, byte [rel gsn_capture_req]
    call hv_out_dec
    lea  rdi, [rel str_gsn_captures]
    call hv_out_str
    mov  eax, [rel gsn_captures]
    call hv_out_dec
    lea  rdi, [rel str_gsn_resumes]
    call hv_out_str
    mov  eax, [rel gsn_resumes]
    call hv_out_dec
    lea  rdi, [rel str_gsn_refused]
    call hv_out_str
    mov  eax, [rel gsn_refused]
    call hv_out_dec
    lea  rdi, [rel str_gsn_err]
    call hv_out_str
    mov  eax, [rel gsn_last_err]
    call hv_out_dec
    lea  rdi, [rel str_gsn_gen]
    call hv_out_str
    mov  eax, [rel gsn_cap_gen]
    call hv_out_dec
    lea  rdi, [rel str_gsn_ram]
    call hv_out_str
    mov  rax, [rel gsn_ram_bytes]
    shr  rax, 20
    call hv_out_dec
    lea  rdi, [rel str_gsn_xsave]
    call hv_out_str
    mov  eax, [rel gsn_xsave_bytes]
    call hv_out_dec
    lea  rdi, [rel str_gsn_resumed]
    call hv_out_str
    movzx eax, byte [rel gsn_resume_live]
    call hv_out_dec
    pop  rbx
    ret

; Scrub the RAM copy and every captured field.
guestsnap_discard:
    pushfq
    cld
    mov  byte [rel gsn_state], 0
    mov  byte [rel gsn_resume_armed], 0
    call guestsnap_capture_unfence             ; retry any exact pending End, no copy is valid
    call guestsnap_release                      ; RC-speed-reserve: scrub, then return the span
    lea  rdi, [rel gsn_record]
    mov  ecx, gsn_record_end - gsn_record
    xor  eax, eax
    rep  stosb
    popfq
    ret

str_gsn_head: db " GUESTVM SNAPSHOT", 0
str_gsn_discard: db "DISCARD", 0
str_gsn_stat_tok: db "STAT", 0
str_gsn_discarded: db " discarded=1", 0
str_gsn_discard_retained: db " discarded=0", 0
str_gsn_queued: db " capture_queued=1", 0
str_gsn_refused_req: db " capture_queued=0", 0
str_gsn_usage: db " usage=SNAPSHOT[STAT|DISCARD]", 0
str_gsn_state: db " state=", 0
str_gsn_pending: db " capture_pending=", 0
str_gsn_captures: db " captures=", 0
str_gsn_resumes: db " resumes=", 0
str_gsn_refused: db " refused=", 0
str_gsn_err: db " last_err=", 0
str_gsn_gen: db " captured_gen=", 0
str_gsn_ram: db " ram_mib=", 0
str_gsn_xsave: db " xsave_bytes=", 0
str_gsn_resumed: db " resumed_run=", 0

%include "core/abi/wdata.inc"
%macro WDATA_hv_guestsnap 0
alignb 8
; Lifetime counters and the request/run flags (never scrubbed).
gsn_captures: resd 1
gsn_resumes: resd 1
gsn_refused: resd 1
gsn_last_err: resd 1
gsn_resume_gen: resd 1
gsn_state: resb 1                       ; 0 none, 2 valid snapshot
gsn_capture_req: resb 1
gsn_resume_armed: resb 1
gsn_resume_live: resb 1
alignb 8
gsn_tsc_offset: resq 1                  ; active run's TSC offset (0 = none)
gsn_buf: resq 1                         ; RAM copy HPA (host-private)
gsn_buf_bytes: resq 1                   ; the shared span's page-rounded bytes
gsn_fence_gen: resq 1
gsn_fence_token: resq 1
gsn_fence_serial: resq 1
gsn_capture_serial: resq 1               ; monotonic through capture/discard
gsn_mb_token: resq 1                    ; RC-speed-reserve: core/memory_budget key (0 = none)
gsn_mb_gen: resq 1
gsn_release_refused: resd 1
alignb 8
; Captured record: scrubbed by DISCARD.
gsn_record:
gsn_ram_bytes: resq 1
gsn_guest_tsc: resq 1
gsn_cr2: resq 1
gsn_xcr0: resq 1
gsn_dr: resq 5
gsn_msr: resq GSN_MSR_COUNT
gsn_vmcs: resq GSN_VMCS_COUNT
gsn_gpr: resq 15
gsn_cap_gen: resd 1
gsn_dev_mask: resd 1
gsn_cpuid1: resd 1
gsn_xsave_bytes: resd 1
gsn_profile: resb VP_BYTES
gsn_dev: resb GSN_DEV_BYTES
alignb 8
gsn_grs: resb GSN_GRS_MAX
alignb 8
gsn_pages: resb GSN_PAGES * 4096
gsn_xsave_raw: resb GSN_XSAVE_MAX + 64
gsn_record_end:
%endmacro
WDATA_BSS_DEFER WDATA_hv_guestsnap
