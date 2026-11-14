;; MODULE hv/vcpu_bsp
;; LAYER 5
;; EXPORTS vcb_go, vcb_dispatch, vcb_handoff_active, vcb_entry_stop, vcb_guestcpu, vcb_fail_stop, vcb_owner_vmcs
;; IMPORTS hv/vcpu_svm_run, hv/vcpu_status, hv/vcpu_bsp_dispatch, hv/vcpu_bsp_lifecycle, hv/vmx, hv/vcpu_ap, hv/vcpu_ap_run, hv/vcpu_ap_vmx, core/smp, core/idt
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Creator: Codex / rc-vm-claude. START publishes READY only after preparation
; and complete retained-input verification. Dispatch requires both cores root.
%include "hv/vcpu_bsp.inc"
%include "hv/vcpu_ap_xstate.inc"
VCB_STOP equ 0x305

; BSP RDI retained boundary frame, IF0, AFTER own entry executor and last
; preparation helper, BEFORE FINAL. No executor call after publishing GO.
vcb_go:
    cmp  qword [rel vca_ready], 0
    je   .single
    cmp  qword [rel vca_ready], 1
    jne  vcb_stop
    cmp  dword [rel vcb_handoff_active], 0
    jne  vcb_entry_stop
    test dword [rel vcg_abort], VCG_ABORT_BIT
    jnz  vcg_bsp_abort_seen
    cmp  rdi, [rel hv_vmx_boundary_frame]
    jne  vcb_stop
    cmp  qword [rdi + HVB_ACTIVE], 1
    jne  vcb_stop
    cmp  qword [rdi + HVB_FRONTIER], 1
    jne  vcb_stop
    cmp  dword [rdi + HVB_SVM], 2
    jne  vcb_stop
    cmp  dword [rdi + HVB_CUSTODY_KIND], 3
    jne  vcb_stop
    mov  rax, [rdi + HVB_LEASE]
    test rax, rax
    jz   vcb_stop
    cmp  rax, -1
    je   vcb_stop
    cmp  byte [rel vcg_root], 1
    jne  vcb_stop
    cmp  byte [rel vcg_root + 1], 1
    jne  vcb_stop
    cmp  qword [rel vca_vmx + VAP_CURRENT], 0
    jne  vcb_stop
    cmp  qword [rel vca_xstate + VAX_SAVED], 0
    jne  vcb_stop
    cmp  qword [rel vca_go_desc], 1
    jne  vcb_stop
    mov  rdx, [rel vca_reset]
    test rdx, rdx
    jz   vcb_stop
    cmp  [rel vca_go_desc + 8], rdx
    jne  vcb_stop
    mov  rdx, [rel vca_vmx + VAP_CS]
    cmp  [rel vca_go_desc + 32], rdx
    jne  vcb_stop
    mov  ecx, [rel vcg_go]
    cmp  ecx, [rel vcg_ack]
    jne  vcb_stop
    inc  ecx
    jz   vcb_stop                       ; no generation reuse on wrap
    mov  [rel vca_go_desc + 16], rax
    mov  [rel vca_go_desc + 24], rcx
    mov  rdi, rax
    jmp  vcg_gang_go                    ; final ordinary CALL returns from GO
.single:
    ret

; Both cores root, AP has closed executor/cleared its VMCS and ACKed this GO.
; Called before vCPU0's ordinary dispatch, with the BSP's own pair closed.
; ->EAX1 continue,0 clean guest stop/refusal, or nonresuming poison.
vcb_dispatch:
    cmp  qword [rel vca_ready], 0
    je   .single
    cmp  qword [rel vca_ready], 1
    jne  vcb_stop
    cmp  dword [rel vcb_handoff_active], 0
    jne  vcb_entry_stop
    test dword [rel vcg_abort], VCG_ABORT_BIT
    jnz  vcg_bsp_abort_seen
    cmp  byte [rel vcg_root], 1
    jne  vcb_stop
    cmp  byte [rel vcg_root + 1], 1
    jne  vcb_stop
    mov  eax, [rel vcg_go]
    test eax, eax
    jz   vcb_stop
    cmp  eax, [rel vcg_ack]
    jne  vcb_stop
    cmp  qword [rel vca_vmx + VAP_CURRENT], 0
    jne  vcb_stop
    cmp  qword [rel vca_xstate + VAX_SAVED], 0
    jne  vcb_stop
    mov  rdx, [rel hv_vmx_boundary_frame]
    test rdx, rdx
    jz   vcb_stop
    cmp  qword [rdx + HVB_ACTIVE], 0
    jne  vcb_stop
    cmp  qword [rdx + HVB_FRONTIER], 0
    jne  vcb_stop
    cmp  dword [rel vca_status], 3
    je   .refused
    cmp  dword [rel vca_status], 2
    ja   vcb_stop
    jne  .idle_cycle
    cmp  eax, [rel vca_deferred]
    jne  vcb_stop
    jmp  .bound_cycle
.idle_cycle:
    cmp  dword [rel vca_deferred], 0
    jne  vcb_stop
.bound_cycle:
    cmp  rax, [rel vca_go_desc + 24]
    jne  vcb_stop
    mov  rax, [rel vca_reset]
    test rax, rax
    jz   vcb_stop
    cmp  [rel vca_go_desc + 8], rax
    jne  vcb_stop
    mov  rax, [rel vcg_token]
    cmp  [rel vca_go_desc + 16], rax
    jne  vcb_stop
    push rbx
    sub  rsp, 16
    vmptrst [rsp]
    jc   vcb_stop
    jz   vcb_stop
    mov  rax, [rsp]
    cmp  rax, [rel hv_launch_vmcs_pa]
    jne  vcb_stop
    cmp  rax, [rel vca_vmx + VAP_CS]
    je   vcb_stop
    mov  [rel vcb_owner_vmcs], rax
    call vcd_ops_check                   ; validate finite accessors BEFORE load1
    sidt [rel vcb_dispatch_idtr]
    mov  dword [rel vcb_handoff_active], 1 ; BEFORE making AP VMCS current
    lidt [rel vcg_idtr_bsp]               ; own fault path retires the AP VMCS
    vmptrld [rel vca_vmx + VAP_CS]
    jc   .load_fail
    jz   .load_fail
    call vcb_swap
    call vcl_service                    ; reset/SIPI only with both cores root
    test eax, eax
    jnz  .poll                          ; reset invalidates any deferred exit
    cmp  dword [rel vca_status], 2
    jne  .poll                          ; idle/timer cycles have no exit to replay
    call vcd_dispatch
    mov  ebx, eax
    test eax, eax
    jz   .dispatched
    call vcl_wake                       ; HLT wakes only on a queued legal event
    jmp  .dispatched
.poll:
    call vcl_poll                        ; local timer/IPI service, no stale exit
    mov  ebx, eax
.dispatched:
    call vcb_swap                        ; retain AP updates; restore all BSP records
    call vcb_retire
    call vst_status_cycle
    mov  dword [rel vca_deferred], 0     ; consume exactly once, after VMCS restore
    mov  dword [rel vca_status], 0
    mov  eax, ebx
    add  rsp, 16
    pop  rbx
    ret
.load_fail:
    call vcb_retire                     ; restore even on failed acquisition
    jmp  vcb_stop
.refused:
    sub  rsp, 8
    call vst_status_cycle
    add  rsp, 8
    xor  eax, eax
    ret
.single:
    mov  eax, 1
    ret

; Involutive swap, only while both cores root and AP cannot receive another GO.
; The table is fixed. Shared devices stay shared; per-vCPU registers/counters
; and XCR0 never alias vCPU0 during the selected dispatcher's call.
%macro VCB_SWAP_BYTES 3
    lea  rdi, [rel %1]
    lea  rsi, [rel %2]
    mov  ecx, %3
%%byte:
    mov  al, [rdi]
    mov  dl, [rsi]
    mov  [rdi], dl
    mov  [rsi], al
    inc  rdi
    inc  rsi
    dec  ecx
    jnz  %%byte
%endmacro
; RIP-relative addresses remain correct across initialized WDATA and the
; zero-fill tail. A stored A-B offset cannot span those placement domains.
vcb_swap:
    VCB_SWAP_BYTES hv_linux_gpr, vca_gpr, 120
    VCB_SWAP_BYTES hv_exit_reason, vcb_exit_reason, 4
    VCB_SWAP_BYTES hv_guestcpu_run_tsc_accum, vcb_guestcpu, 8
    VCB_SWAP_BYTES hv_guestcpu_last_progress_tsc, vcb_guestcpu+8, 8
    VCB_SWAP_BYTES hv_guestcpu_interrupts, vcb_guestcpu+16, 8
    VCB_SWAP_BYTES hv_guestcpu_halt_wakes, vcb_guestcpu+24, 8
    VCB_SWAP_BYTES hv_guestcpu_faults, vcb_guestcpu+32, 8
    VCB_SWAP_BYTES hv_linux_guest_xcr0, vca_xstate+VAX_VALUE, 8
    ret

; On all returning paths: VMCLEAR vCPU1 then load the exact saved vCPU0 identity.
; Attempt both even when CLEAR fails; retain the handoff flag on any failure.
vcb_retire:
    xor  r10d, r10d
    vmclear [rel vca_vmx + VAP_CS]
    setc r10b
    setz r11b
    or   r10b, r11b
    vmptrld [rel vcb_owner_vmcs]
    jc   vcb_stop
    jz   vcb_stop
    test r10d, r10d
    jnz  vcb_stop
    mov  dword [rel vcb_handoff_active], 0
    lidt [rel vcb_dispatch_idtr]
    ret

; Entry guard is also reachable after guest restore/FINAL: no CALL or RET
; before unconditional stop floor. Restore VMCS ownership before fatal output.
; Direct internal failures from the selected-vCPU handlers share retirement.
vcb_fail_stop:
    cmp qword [rel vsr_enabled], 1
    je vsr_stop
    cmp  dword [rel vcb_handoff_active], 0
    je   vcb_stop
vcb_entry_stop:
    vmclear [rel vca_vmx + VAP_CS]
    vmptrld [rel vcb_owner_vmcs]
vcb_stop:
    mov  byte [rel vcg_root], 1
    mov  dword [rel smp_core_custody_gate], 4
    VCG_STOP_FLOOR
    mov  edi, VCB_STOP
    jmp  cpu_boundary_fail_stop_reason

%macro WDATA_hv_vcpu_bsp 0
align 8, db 0
vcb_dispatch_idtr: times 10 db 0
align 8, db 0
vcb_owner_vmcs: dq 0
vcb_handoff_active: dd 0
vcb_exit_reason: dd 0
vcb_guestcpu: times 5 dq 0
%endmacro
WDATA_DEFER WDATA_hv_vcpu_bsp
