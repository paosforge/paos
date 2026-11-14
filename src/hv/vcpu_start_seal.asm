;; MODULE hv/vcpu_start_seal
;; LAYER 5
;; EXPORTS vst_seal
;; IMPORTS hv/vcpu_start_vmcs, hv/vcpu_start_resources, hv/vcpu_cpuid_sample, hv/vcpu_ap, hv/vcpu_ap_run, hv/vcpu_bsp_context, hv/vcpu_bsp, hv/vmx, hv/vm_profile, hv/boundary, hv/vcpu_ap_frozen, hv/vcpu_ap_hash
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Creator: Codex / rc-vm-claude. Seal the initial two-vCPU CLI closure:
; timer/console/x2APIC, 64MiB..1GiB contiguous RAM, no assignment/display.
; Validate every entry of the five actual EPT pages, without following any
; untrusted pointer. All other entries MUST be zero. EPT A/D is disabled.
; Thus no leaf exposes the control carve, host RAM or another device.
; Append those five pages, two epoch IDTs and both owned capability records
; plus IDTRs, private resource prefixes and the profile to the existing
; eight manifest blobs. Every physical GO hashes all23.
; RDI exact guarded BSP frame, READY0/no GO. Return1 sealed /0 refusal.
; A failed seal never publishes its completion marker or grants entry.
%include "hv/vcpu_start.inc"

vst_seal:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  rbx, rdi
    cmp  qword [rel vca_ready], 0
    jne  .bad
    cmp  qword [rel vst_sealed], 0
    jne  .bad
    cmp  qword [rel vst_initialized], 1
    jne  .bad
    cmp  dword [rel vcb_handoff_active], 0
    jne  .bad
    cmp  qword [rel vca_vmx + 56], 0
    jne  .bad
    cmp  qword [rel vca_xstate + 48], 0
    jne  .bad
    cmp  qword [rel vcb_xstate + 48], 0
    jne  .bad
    cmp  word [rel vcg_root], 0x101
    jne  .bad
    mov  eax, [rel vcg_go]
    or   eax, [rel vcg_ack]
    or   eax, [rel vcg_down]
    or   eax, [rel vcg_abort]
    jnz  .bad
    test rbx, rbx
    jz   .bad
    cmp  rbx, [rel hv_vmx_boundary_frame]
    jne  .bad
    cmp  qword [rbx + HVB_ACTIVE], 0
    jne  .bad
    cmp  qword [rbx + HVB_FRONTIER], 0
    jne  .bad
    cmp  dword [rbx + HVB_SVM], 2
    jne  .bad
    cmp  dword [rbx + HVB_CUSTODY_KIND], 3
    jne  .bad
    mov  r15, [rbx + HVB_LEASE]
    test r15, r15
    jz   .bad
    cmp  r15, -1
    je   .bad
    cmp  r15, [rel vcg_token]
    jne  .bad
    cmp  r15, [rel vcs_epoch]
    jne  .bad
    cmp  r15, [rel vst_manifest]
    jne  .bad
    cmp  qword [rel vst_manifest + 8], 8
    jne  .bad
    mov  r12, [rel vst_base]
    test r12, r12
    jz   .bad
    test r12, 0x1FFFFF
    jnz  .bad
    cmp  r12, [rel hv_linux_region]
    jne  .bad
    cmp  qword [rel hv_linux_mb_token], 0
    je   .bad
    lea  rax, [r12 + 0x200000]
    cmp  rax, [rel hv_linux_ram]
    jne  .bad
    mov  r13, [rel hv_linux_ram_bytes]
    cmp  r13, 0x4000000
    jb   .bad
    cmp  r13, 0x40000000
    ja   .bad
    test r13, 0x1FFFFF
    jnz  .bad
    add  rax, r13
    jc   .bad
    mov  rdx, rax
    shr  rdx, 52
    jnz  .bad
    sub  rax, r12
    cmp  rax, [rel hv_linux_region_capacity]
    ja   .bad
    lea  rax, [r12 + 0x2000]
    or   rax, 0x1E                     ; no hardware A/D mutation
    cmp  rax, [rel hv_linux_eptp]
    jne  .bad
    cmp  rax, [rel vca_vmx + 24]
    jne  .bad
    mov  rax, [rel vm_profile_active]
    test rax, rax
    jz   .bad
    cmp  dword [rax + 36], 2
    jne  .bad
    cmp  r13, [rax + 40]
    jne  .bad
    cmp  dword [rax + 48], 1027        ; timer, console, virtual LAPIC only
    jne  .bad
    cmp  dword [rel vm_profile_dev_mask], 1027
    jne  .bad
    mov  rdi, rbx
    call hv_boundary_intel_held
    ; This exact allocator owns all pages below; do not dereference any
    ; table entry. Compare every qword, including every unused slot.
    shr  r13, 21
    xor  ebx, ebx
.entry:
    xor  eax, eax
    test ebx, ebx
    jnz  .pml4
    lea  rax, [r12 + 0x3007]
.pml4:
    cmp  [r12 + 0x2000 + rbx*8], rax
    jne  .bad
    xor  eax, eax
    test ebx, ebx
    jnz  .pdpt3
    lea  rax, [r12 + 0x4007]
.pdpt3:
    cmp  ebx, 3
    jne  .pdpt
    lea  rax, [r12 + 0x6007]
.pdpt:
    cmp  [r12 + 0x3000 + rbx*8], rax
    jne  .bad
    xor  eax, eax
    cmp  rbx, r13
    jae  .ram
    mov  rax, rbx
    shl  rax, 21
    add  rax, [rel hv_linux_ram]
    or   rax, 0xB7                    ; exact WB/RWX/2MiB leaf
.ram:
    cmp  [r12 + 0x4000 + rbx*8], rax
    jne  .bad
    xor  eax, eax
    cmp  ebx, 128
    jne  .device_pd
    lea  rax, [r12 + 0x7007]
.device_pd:
    cmp  [r12 + 0x6000 + rbx*8], rax
    jne  .bad
    xor  eax, eax
    test ebx, ebx
    jnz  .device_pt
    lea  rax, [r12 + 0x5001]           ; console page read-only, UC, no execute
.device_pt:
    cmp  [r12 + 0x7000 + rbx*8], rax
    jne  .bad
    inc  ebx
    cmp  ebx, 512
    jb   .entry
    mov  eax, [r12]
    cmp  rax, [rel vca_vmx]
    jne  .bad
    lea  rax, [r12 + VST_ON1]
    cmp  rax, [rel vca_vmx + 8]
    jne  .bad
    lea  rax, [r12 + VST_CS1]
    cmp  rax, [rel vca_vmx + 16]
    jne  .bad
    lea  rax, [r12 + VST_HOST0]
    cmp  rax, [rel vcb_xstate]
    jne  .bad
    lea  rax, [r12 + VST_GUEST0]
    cmp  rax, [rel vcb_xstate + 8]
    jne  .bad
    lea  rax, [r12 + VST_HOST1]
    cmp  rax, [rel vca_xstate]
    jne  .bad
    lea  rax, [r12 + VST_GUEST1]
    cmp  rax, [rel vca_xstate + 8]
    jne  .bad
    cmp  qword [rel vcb_xstate + 16], 65536
    jne  .bad
    cmp  qword [rel vca_xstate + 16], 65536
    jne  .bad
    cmp  qword [rel vcb_xstate + 24], 3
    jne  .bad
    cmp  qword [rel vca_xstate + 24], 3
    jne  .bad
    lea  rax, [r12 + VST_IDT0]
    cmp  rax, [rel vcg_idtr_bsp + 2]
    jne  .bad
    lea  rax, [r12 + VST_IDT1]
    cmp  rax, [rel vcg_idtr_ap + 2]
    jne  .bad
    cmp  word [rel vcg_idtr_bsp], 4095
    jne  .bad
    cmp  word [rel vcg_idtr_ap], 4095
    jne  .bad
    ; Validate the existing eight hashes before extending the manifest.
    lea  rdi, [rel vst_manifest]
    mov  rsi, r15
    call vcpu_ap_frozen_check
    cmp  eax, 1
    jne  .bad
    mov  qword [rel vst_manifest], 0
    lea  r14, [rel vst_manifest + 16 + 8*48]
    xor  ebx, ebx
.page:
    lea  rax, [rel vst_seal_pages]
    mov  eax, [rax + rbx*4]
    add  rax, r12
    mov  [r14], rax
    mov  qword [r14 + 8], 4096
    add  r14, 48
    inc  ebx
    cmp  ebx, 7
    jb   .page
    lea  rax, [rel vcs_bsp_caps]
    mov  [r14], rax
    mov  qword [r14 + 8], 72
    lea  rax, [rel vcs_ap_caps]
    mov  [r14 + 48], rax
    mov  qword [r14 + 56], 72
    add  r14, 96
    lea  rax, [rel vcg_idtr_bsp]
    mov  [r14], rax
    mov  qword [r14 + 8], 10
    lea  rax, [rel vcg_idtr_ap]
    mov  [r14 + 48], rax
    mov  qword [r14 + 56], 10
    lea  rax, [rel vca_vmx]
    mov  [r14 + 96], rax
    mov  qword [r14 + 104], 32
    lea  rax, [rel vcb_xstate]
    mov  [r14 + 144], rax
    mov  qword [r14 + 152], 32
    lea  rax, [rel vca_xstate]
    mov  [r14 + 192], rax
    mov  qword [r14 + 200], 32
    mov  rax, [rel vm_profile_active]
    mov  [r14 + 240], rax
    mov  qword [r14 + 248], 280
    lea  r14, [rel vst_manifest + 16 + 8*48]
    mov  ebx, 15
.hash:
    mov  rsi, [r14]
    mov  rdx, [r14 + 8]
    lea  rdi, [r14 + 16]
    call vcpu_ap_sha256_hash
    test rax, rax
    jnz  .bad
    add  r14, 48
    dec  ebx
    jnz  .hash
    mov  qword [rel vst_manifest + 8], 23
    mov  [rel vst_manifest], r15
    mov  [rel vst_sealed], r15          ; all records complete, never READY
    mov  eax, 1
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
align 4
vst_seal_pages: dd 0x2000,0x3000,0x4000,0x6000,0x7000,VST_IDT0,VST_IDT1
