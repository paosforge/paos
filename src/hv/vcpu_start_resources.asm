;; MODULE hv/vcpu_start_resources
;; LAYER 5
;; EXPORTS vst_resources_init, vst_base
;; IMPORTS hv/vmx, hv/vcpu_ap, hv/vcpu_ap_run, hv/vcpu_bsp, hv/vcpu_bsp_state, hv/vcpu_bsp_context
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Creator: Codex / rc-vm-claude. START-only initialization, never an entry grant.
; RDI exact allocator-owned control base, RSI exact held span capacity,
; RDX exact current EPTP, RCX VMX revision (31 bits). IF0, both CPUs root,
; no custody epoch or VMCS1/native context live. All memory is identity mapped.
; Validate everything before the first write. Only the named carve is cleared;
; existing EPT/device tables and guest RAM are untouched. Return1/0. Caller
; owns VMCS initialization, IDTs, common CPUID/controls and retirement before
; READY publication. vst_base marks prepared resources, NOT a usable VMCS.
%include "hv/vcpu_start.inc"
%include "hv/vcpu_ap_xstate.inc"

vst_resources_init:
    cmp  qword [rel vca_ready], 0
    jne  .bad
    cmp  qword [rel vst_base], 0
    jne  .bad
    cmp  qword [rel vcg_token], 0
    jne  .bad
    cmp  qword [rel hv_linux_mb_token], 0
    je   .bad
    cmp  qword [rel vca_vmx + 48], 0      ; AP VMXON retired
    jne  .bad
    cmp  qword [rel vca_vmx + 56], 0      ; AP VMCS cleared
    jne  .bad
    cmp  qword [rel vca_xstate + VAX_SAVED], 0
    jne  .bad
    cmp  qword [rel vcb_xstate + VAX_SAVED], 0
    jne  .bad
    cmp  qword [rel vcb_context_loaded], 0
    jne  .bad
    cmp  dword [rel vcb_handoff_active], 0
    jne  .bad
    cmp  dword [rel vcg_go], 0
    jne  .bad
    cmp  dword [rel vcg_ack], 0
    jne  .bad
    cmp  dword [rel vcg_down], 0
    jne  .bad
    cmp  dword [rel vcg_abort], 0
    jne  .bad
    cmp  word [rel vcg_root], 0x101
    jne  .bad
    test rdi, rdi
    jz   .bad
    test rdi, 0x1FFFFF
    jnz  .bad
    cmp  rdi, [rel hv_linux_region]
    jne  .bad
    cmp  rsi, 0x200000
    jb   .bad
    cmp  rsi, [rel hv_linux_region_capacity]
    jne  .bad
    mov  rax, rdi
    add  rax, rsi
    jc   .bad
    shr  rax, 52
    jnz  .bad
    lea  rax, [rdi + 0x200000]
    cmp  rax, [rel hv_linux_ram]
    jne  .bad
    cmp  rdx, [rel hv_linux_eptp]
    jne  .bad
    lea  rax, [rdi + 0x2000]
    or   rax, 0x1E
    mov  r8, rdx
    and  r8, ~0x40                      ; only optional EPT A/D differs
    cmp  r8, rax
    jne  .bad
    mov  rax, rcx
    shr  rax, 31
    jnz  .bad
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12, rdx
    mov  r13d, ecx
    lea  rdi, [rbx + VST_ON1]
    xor  eax, eax
    mov  ecx, (VST_END - VST_ON1) / 8
    rep  stosq
    lea  rdi, [rbx + VST_IOA]
    mov  rax, -1                        ; trap every I/O and MSR bitmap bit
    mov  ecx, (VST_END - VST_IOA) / 8
    rep  stosq
    lea  rdi, [rel vca_vmx]
    xor  eax, eax
    mov  ecx, 72 / 8
    rep  stosq
    mov  [rel vca_vmx], r13
    lea  rax, [rbx + VST_ON1]
    mov  [rel vca_vmx + 8], rax
    lea  rax, [rbx + VST_CS1]
    mov  [rel vca_vmx + 16], rax
    mov  [rel vca_vmx + 24], r12
    mov  [rbx + VST_CS1], r13d
    lea  rdi, [rel vcb_xstate]
    lea  rsi, [rbx + VST_HOST0]
    lea  rdx, [rbx + VST_GUEST0]
    call vst_xstate_init
    lea  rdi, [rel vca_xstate]
    lea  rsi, [rbx + VST_HOST1]
    lea  rdx, [rbx + VST_GUEST1]
    call vst_xstate_init
    lea  rdi, [rel vca_gpr]
    xor  eax, eax
    mov  ecx, 120 / 8
    rep  stosq
    lea  rdi, [rel vca_exit]
    mov  ecx, 48 / 8
    rep  stosq
    lea  rdi, [rel vca_go_desc]
    mov  ecx, 64 / 8
    rep  stosq
    lea  rdi, [rel vca_debug]
    mov  ecx, 40 / 8
    rep  stosq
    mov  dword [rel vca_debug + 32], 0xFFFF0FF0
    lea  rdi, [rel vcb_debug]
    mov  ecx, 40 / 8
    rep  stosq
    mov  dword [rel vcb_debug + 32], 0xFFFF0FF0
    lea  rdi, [rel vca_host_msrs]
    mov  ecx, 96 / 8
    rep  stosq
    lea  rdi, [rel vcb_host_msrs]
    mov  ecx, 96 / 8
    rep  stosq
    lea  rdi, [rel vca_guest_msrs]
    call vst_msrs_init
    lea  rdi, [rel vcb_guest_msrs]
    call vst_msrs_init
    mov  [rel vst_base], rbx             ; last, no READY publication
    mov  eax, 1
    pop  r13
    pop  r12
    pop  rbx
    ret
.bad:
    xor  eax, eax
    ret

vst_xstate_init:
    mov  [rdi + VAX_HOST], rsi
    mov  [rdi + VAX_GUEST], rdx
    mov  qword [rdi + VAX_CAPACITY], VST_XSAVE_LEN
    mov  qword [rdi + VAX_ALLOWED], 3    ; conservative common x87/SSE policy
    mov  qword [rdi + VAX_VALUE], 3
    mov  qword [rdi + VAX_HOST_VALUE], 0
    mov  qword [rdi + VAX_SAVED], 0
    mov  qword [rdi + VAX_SUPPORTED], 0
    mov  word [rdx], 0x037F
    mov  dword [rdx + 24], 0x1F80
    ret

vst_msrs_init:
    lea  rsi, [rel vst_msr_ids]
    mov  ecx, 6
.record:
    mov  eax, [rsi]
    mov  [rdi], rax                    ; also clears reserved upper dword
    mov  qword [rdi + 8], 0
    add  rsi, 4
    add  rdi, 16
    dec  ecx
    jnz  .record
    ret

align 4
vst_msr_ids: dd 0xC0000081,0xC0000082,0xC0000083,0xC0000084,0xC0000102,0xC0000103
%macro WDATA_hv_vcpu_start_resources 0
align 8, db 0
vst_base: dq 0
%endmacro
WDATA_DEFER WDATA_hv_vcpu_start_resources
