;; MODULE hv/vcpu_start_vmcs
;; LAYER 5
;; EXPORTS vst_vmcs_init, vst_initialized, vst_ap_controls, vst_manifest, vst_sealed, vst_reset_table, vst_reset_end
;; IMPORTS hv/vmx, hv/vcpu_ap, hv/vcpu_ap_run, hv/vcpu_ap_controls, hv/vcpu_ap_hash, hv/vcpu_bsp, hv/vcpu_bsp_state, hv/vcpu_bsp_context, hv/vcpu_cpuid, hv/vcpu_cpuid_sample, hv/vcpu_start_resources, hv/boundary
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Creator: Codex / rc-vm-claude. START after VMCS0's ordinary guest setup,
; private resource/IDT setup and owned two-core collection, before any GO.
; RDI the current guarded kind3 frame. Returns1 complete /0 no guest entry.
; Never publishes READY. VMCS1 gets guest/control state only: the AP must
; populate every HOST field from its own live state on every entry attempt.
%include "hv/vcpu_start.inc"
%include "hv/vcpu_cpuid.inc"
%include "hv/vcpu_ap_xstate.inc"

vst_vmcs_init:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 32
    mov  rbx, rdi
    cmp  qword [rel vca_ready], 0
    jne  .bad
    cmp  qword [rel vst_initialized], 0
    jne  .bad
    cmp  dword [rel vcb_handoff_active], 0
    jne  .bad
    test rbx, rbx
    jz   .bad
    cmp  rbx, [rel hv_vmx_boundary_frame]
    jne  .bad
    cmp  qword [rbx + HVB_ACTIVE], 0
    jne  .bad
    cmp  qword [rbx + HVB_FRONTIER], 0
    jne  .bad
    cmp  dword [rbx + HVB_CUSTODY_KIND], 3
    jne  .bad
    cmp  dword [rbx + HVB_SVM], 2
    jne  .bad
    mov  rax, [rbx + HVB_LEASE]
    test rax, rax
    jz   .bad
    cmp  rax, -1
    je   .bad
    cmp  rax, [rel vcg_token]
    jne  .bad
    cmp  rax, [rel vcs_epoch]
    jne  .bad
    mov  [rsp + 16], rax
    cmp  word [rel vcg_root], 0x101
    jne  .bad
    cmp  dword [rel vcg_go], 0
    jne  .bad
    cmp  dword [rel vcg_ack], 0
    jne  .bad
    cmp  dword [rel vcg_down], 0
    jne  .bad
    cmp  dword [rel vcg_abort], 0
    jne  .bad
    cmp  qword [rel vca_vmx + 48], 0
    jne  .bad
    cmp  qword [rel vca_vmx + 56], 0
    jne  .bad
    cmp  qword [rel vca_reset], -1
    je   .bad
    mov  r12, [rel vst_base]
    test r12, r12
    jz   .bad
    cmp  r12, [rel hv_linux_region]
    jne  .bad
    lea  rax, [r12 + VST_CS1]
    cmp  rax, [rel vca_vmx + 16]
    jne  .bad
    lea  rax, [r12 + VST_ON1]
    cmp  rax, [rel vca_vmx + 8]
    jne  .bad
    lea  rax, [r12 + VST_IDT0]
    cmp  rax, [rel vcg_idtr_bsp + 2]
    jne  .bad
    lea  rax, [r12 + VST_IDT1]
    cmp  rax, [rel vcg_idtr_ap + 2]
    jne  .bad
    lea  rax, [r12 + 0x1000]
    cmp  rax, [rel hv_launch_vmcs_pa]
    jne  .bad
    vmptrst [rsp]
    jc   .bad
    jz   .bad
    cmp  rax, [rsp]
    jne  .bad
    ; Use AP-sampled fixed bits to construct its initial nonpaged guest.
    ; No unsupported CR4 feature may leak into the virtual reset state.
    mov  rax, [rel vcs_ap_caps + 40]
    mov  rdx, 0x80000031                ; PE/PG relaxed by unrestricted guest
    not  rdx
    test rax, rdx
    jnz  .bad
    and  eax, 0x7FFFFFFE
    or   eax, 0x60000010                ; architectural ET/CD/NW, plus fixed NE
    mov  rdx, [rel vcs_ap_caps + 48]
    not  rdx
    test rax, rdx
    jnz  .bad
    mov  [rsp + 8], rax
    cmp  qword [rel vcs_ap_caps + 56], 1 << 13
    jne  .bad
    test qword [rel vcs_ap_caps + 64], 1 << 13
    jz   .bad
    mov  eax, [rel vcb_cpuid_table + VCP_EXT + 16 + 12]
    and  eax, (1 << 29) | (1 << 27) | (1 << 20) | (1 << 11)
    cmp  eax, (1 << 29) | (1 << 27) | (1 << 20) | (1 << 11)
    jne  .bad                          ; automatic syscall/TSC_AUX and NX model
    cmp  qword [rel vcb_xstate + VAX_ALLOWED], 3
    jne  .bad
    cmp  qword [rel vca_xstate + VAX_ALLOWED], 3
    jne  .bad
    mov  rdi, rbx
    call hv_boundary_intel_held
    ; Shared policy becomes a frozen manifest blob, never host state.
    mov  qword [rel vcb_efer_mask], 0x901
    mov  rax, [rel vcs_controls + 32]
    mov  [rel vcb_entry_ctls], rax
    mov  qword [rel vcb_xcr0_allowed], 3
    mov  qword [rel hv_linux_guest_xcr0], 3
    lea  rdi, [rel vcs_controls]
    lea  rsi, [rel vcb_guest_msrs]
    lea  rdx, [rel vcb_host_msrs]
    call vst_vmcs_controls
    test eax, eax
    jz   .bad
    mov  edi, 0x2806
    mov  esi, 0xD00                    ; private LME/LMA/NXE, SCE initially0
    call vst_vmwrite
    test eax, eax
    jz   .bad
    ; E2: save exact VMCS0 identity and IDT, set flag BEFORE loading VMCS1.
    mov  rax, [rel hv_launch_vmcs_pa]
    mov  [rel vcb_owner_vmcs], rax
    sidt [rel vcb_dispatch_idtr]
    mov  dword [rel vcb_handoff_active], 1
    lidt [rel vcg_idtr_bsp]
    vmclear [rel vca_vmx + 16]
    jc   vcb_entry_stop
    jz   vcb_entry_stop
    vmptrld [rel vca_vmx + 16]
    jc   vcb_entry_stop
    jz   vcb_entry_stop
    lea  rdi, [rel vcs_controls + 40]
    lea  rsi, [rel vca_guest_msrs]
    lea  rdx, [rel vca_host_msrs]
    call vst_vmcs_controls
    test eax, eax
    jz   .ap_bad
    lea  r13, [rel vst_reset_table]
.reset:
    mov  edi, [r13]
    cmp  edi, -1
    je   .reset_dynamic
    mov  rsi, [r13 + 8]
    call vst_vmwrite
    test eax, eax
    jz   .ap_bad
    add  r13, 16
    jmp  .reset
.reset_dynamic:
    mov  edi, 0x6800
    mov  rsi, [rsp + 8]
    call vst_vmwrite
    test eax, eax
    jz   .ap_bad
    lea  rdi, [rel vst_ap_controls]
    call vcpu_ap_controls_capture
    cmp  eax, 1
    jne  .ap_bad
    call vcb_retire                     ; clear1 + load exact0, restore own IDT
    call vst_freeze
    test eax, eax
    jz   .bad
    mov  rax, [rsp + 16]
    mov  [rel vst_manifest], rax
    inc  qword [rel vca_reset]
    mov  qword [rel vca_go_desc], 1
    mov  rax, [rel vca_reset]
    mov  [rel vca_go_desc + 8], rax
    mov  rax, [rsp + 16]
    mov  [rel vca_go_desc + 16], rax
    mov  qword [rel vca_go_desc + 24], 0
    mov  rax, [rel vca_vmx + 16]
    mov  [rel vca_go_desc + 32], rax
    mov  qword [rel vca_go_desc + 40], 0x901
    lea  rax, [rel vst_ap_controls]
    mov  [rel vca_go_desc + 48], rax
    lea  rax, [rel vst_manifest]
    mov  [rel vca_go_desc + 56], rax
    mov  qword [rel vst_initialized], 1 ; VMCS initialized, still READY0
    mov  eax, 1
    jmp  .out
.ap_bad:
    call vcb_retire
.bad:
    xor  eax, eax
.out:
    add  rsp, 32
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Current VMCS owned by START; RDI control5q,RSI guest96, RDX own host96.
; Controls/guest fields only. Even VMCS1's transient image has no BSP HOST.
vst_vmcs_controls:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    xor  ebx, ebx
.control:
    lea  rax, [rel vst_control_fields]
    mov  edi, [rax + rbx*4]
    mov  rsi, [r12 + rbx*8]
    call vst_vmwrite
    test eax, eax
    jz   .bad
    inc  ebx
    cmp  ebx, 5
    jb   .control
    lea  r15, [rel vst_common_table]
.common:
    mov  edi, [r15]
    cmp  edi, -1
    je   .pointers
    mov  rsi, [r15 + 8]
    call vst_vmwrite
    test eax, eax
    jz   .bad
    add  r15, 16
    jmp  .common
.pointers:
    mov  edi, 0x2000
    mov  rsi, [rel vst_base]
    add  rsi, VST_IOA
    call vst_vmwrite
    test eax, eax
    jz   .bad
    mov  edi, 0x2002
    add  rsi, VST_IOB - VST_IOA
    call vst_vmwrite
    test eax, eax
    jz   .bad
    mov  edi, 0x2004
    add  rsi, VST_MSR - VST_IOB
    call vst_vmwrite
    test eax, eax
    jz   .bad
    mov  edi, 0x2006
    mov  rsi, r13
    call vst_vmwrite
    test eax, eax
    jz   .bad
    mov  edi, 0x2008
    mov  rsi, r14
    call vst_vmwrite
    test eax, eax
    jz   .bad
    mov  edi, 0x200A
    mov  rsi, r13
    call vst_vmwrite
    test eax, eax
    jz   .bad
    mov  edi, 0x201A
    mov  rsi, [rel hv_linux_eptp]
    call vst_vmwrite
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

vst_vmwrite:
    vmwrite rdi, rsi
    jc   .bad
    jz   .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; Eight immutable blobs. Epoch metadata is bound only after every digest.
vst_freeze:
    push rbx
    push r12
    push r13
    mov  qword [rel vst_manifest], 0
    mov  qword [rel vst_manifest + 8], 8
    lea  r12, [rel vst_manifest + 16]
    mov  r13, [rel vst_base]
    add  r13, VST_IOA
    xor  ebx, ebx
.bitmap:
    mov  [r12], r13
    mov  qword [r12 + 8], 4096
    add  r13, 4096
    add  r12, 48
    inc  ebx
    cmp  ebx, 3
    jb   .bitmap
    lea  rax, [rel vcb_cpuid_table]
    mov  [r12], rax
    mov  qword [r12 + 8], VCP_BYTES
    lea  rax, [rel vcb_efer_mask]
    mov  [r12 + 48], rax
    mov  qword [r12 + 56], 24
    lea  rax, [rel vst_ap_controls]
    mov  [r12 + 96], rax
    mov  qword [r12 + 104], 23 * 8
    lea  rax, [rel vcs_controls]
    mov  [r12 + 144], rax
    mov  qword [r12 + 152], 80
    lea  rax, [rel vst_reset_table]
    mov  [r12 + 192], rax
    mov  qword [r12 + 200], vst_reset_end - vst_reset_table
    lea  r12, [rel vst_manifest + 16]
    mov  ebx, 8
.hash:
    mov  rsi, [r12]
    mov  rdx, [r12 + 8]
    lea  rdi, [r12 + 16]
    call vcpu_ap_sha256_hash
    test rax, rax
    jnz  .bad
    add  r12, 48
    dec  ebx
    jnz  .hash
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

align 4
vst_control_fields: dd 0x4000,0x4002,0x401E,0x400C,0x4012
align 8
vst_common_table:
    dq 0x4004,0x40100, 0x4006,0, 0x4008,0, 0x400A,0
    dq 0x400E,6, 0x4010,6, 0x4014,6
    dq 0x4016,0, 0x4018,0, 0x401A,0, 0x2800,-1, 0x2802,0
    dq 0x2804,0x0007040600070406
    dq 0x6000,0, 0x6002,(1<<12)|(1<<13)|(1<<19)|(1<<22)|(1<<23)
    dq 0x6004,0, 0x6006,0
    dq -1,0
vst_reset_table:
    dq 0x800,0, 0x802,0, 0x804,0, 0x806,0, 0x808,0, 0x80A,0
    dq 0x80C,0, 0x80E,0
    dq 0x4800,0xFFFF, 0x4802,0xFFFF, 0x4804,0xFFFF, 0x4806,0xFFFF
    dq 0x4808,0xFFFF, 0x480A,0xFFFF, 0x480C,0xFFFF, 0x480E,0xFFFF
    dq 0x4810,0xFFFF, 0x4812,0xFFFF
    dq 0x4814,0x93, 0x4816,0x9B, 0x4818,0x93, 0x481A,0x93
    dq 0x481C,0x93, 0x481E,0x93, 0x4820,0x10000, 0x4822,0x8B
    dq 0x4824,0, 0x4826,3, 0x4828,0, 0x482A,0
    dq 0x2806,0, 0x6802,0, 0x6804,1<<13
    dq 0x6806,0, 0x6808,0, 0x680A,0, 0x680C,0
    dq 0x680E,0, 0x6810,0, 0x6812,0, 0x6814,0
    dq 0x6816,0, 0x6818,0, 0x681A,0x400, 0x681C,0, 0x681E,0
    dq 0x6820,2, 0x6822,0, 0x6824,0, 0x6826,0
    dq -1,0
vst_reset_end:
%macro WDATA_hv_vcpu_start_vmcs 0
align 16, db 0
vst_initialized: dq 0
vst_ap_controls: times 23 dq 0
vst_manifest: times 146 dq 0
vst_sealed: dq 0
%endmacro
WDATA_DEFER WDATA_hv_vcpu_start_vmcs
