;; MODULE hv/tools_vm_cpu
;; LAYER 5
;; EXPORTS tools_vm_cpu_prepare, tools_vm_cpu_turn, tools_vm_cpu_retire, tools_vm_cpu_stop, tools_vm_isolation_ready
;; IMPORTS hv/tools_vm_memory, hv/app_vm_cpu, hv/app_vm_cpuid, hv/app_vm_intel, hv/app_vm_amd, hv/app_vm_events, hv/boundary_execution, hv/vcpu_svm_life, hv/vcpu_svm_record, hv/vcpu_ap_xstate, hv/vcpu_cpuid, core/smp, sec/cpu_boundary_fault
;; CAPS
;; OWNER saga:hv
;; CONTEXT: bsp_only
; Creator: Codex / rc-vm-claude. Shared source, statically bound private CPU.
; No mutable context selector, copied backend or app/driver state bank switch.
; No product caller/admission, boot completion or device dispatch in this slice.
; Native lifecycle must establish original local-owner/runtime identity first.
%include "hv/tools_vm.inc"
%include "hv/app_vm_cpu.inc"

; Keep these aliases only around the shared code. Deferred storage below uses
; literal tvm names: deferring alias-dependent avm data would corrupt the app.
%define PAOS_TOOLS_CPU_INSTANCE 1
%define avm_exit_ctx tvm_exit_ctx
%define AVM_CPU_ASID 3
%define AVM_CPU_FAULT_CODE 0x30b
%define app_vm_amd_prepare tools_vm_amd_prepare
%define app_vm_amd_turn tools_vm_amd_turn
%define app_vm_cpu_prepare tvm_cpu_prepare_bound
%define app_vm_cpu_retire tvm_cpu_retire_bound
%define app_vm_cpu_stop tools_vm_cpu_stop
%define app_vm_cpu_turn tvm_cpu_turn_bound
%define app_vm_cpuid_prepare tools_vm_cpuid_prepare
%define app_vm_cpuid_query tools_vm_cpuid_query
%define app_vm_events_close tools_vm_events_close
%define app_vm_field_read tools_vm_field_read
%define app_vm_field_write tools_vm_field_write
%define app_vm_intel_prepare tools_vm_intel_prepare
%define app_vm_intel_turn tools_vm_intel_turn
%define app_vm_isolation_ready tools_vm_isolation_ready
%define app_vm_slat_build tvm_cpu_slat_bound
%define avm_arch tvm_arch
%define avm_base tvm_base
%define avm_boot_phase tvm_boot_phase
%define avm_cpu_live tvm_cpu_live
%define avm_cpu_ready tvm_cpu_ready
%define avm_cpuid tvm_cpuid
%define avm_debug tvm_debug
%define avm_exit tvm_exit
%define avm_fields tvm_fields
%define avm_gpr tvm_gpr
%define avm_guest_aux tvm_guest_aux
%define avm_guest_cr2 tvm_guest_cr2
%define avm_host_debug tvm_host_debug
%define avm_raw_cpuid tvm_raw_cpuid
%define avm_root tvm_root
%define avm_roots_retired tvm_roots_retired
%define avm_state tvm_state
%define avm_svm tvm_svm
%define avm_token tvm_token
%define avm_values tvm_values
%define avm_vector_error tvm_vector_error
%define avm_vectoring tvm_vectoring
%define avm_xstate tvm_xstate
%define avma_entered tvma_entered
%define avma_initial tvma_initial
%define avma_offsets tvma_offsets
%define avma_pull tvma_pull
%define avma_push tvma_push
%define avmi_check_cs tvmi_check_cs
%define avmi_close tvmi_close
%define avmi_control tvmi_control
%define avmi_cr4_fixed tvmi_cr4_fixed
%define avmi_cs tvmi_cs
%define avmi_entered tvmi_entered
%define avmi_failed_landing tvmi_failed_landing
%define avmi_frame tvmi_frame
%define avmi_init_fields tvmi_init_fields
%define avmi_initial tvmi_initial
%define avmi_invept tvmi_invept
%define avmi_landing tvmi_landing
%define avmi_msr_ids tvmi_msr_ids
%define avmi_old_cs tvmi_old_cs
%define avmi_open tvmi_open
%define avmi_out tvmi_out
%define avmi_pull tvmi_pull
%define avmi_push tvmi_push
%define avmi_selected tvmi_selected
%define avmi_write tvmi_write
%define avmi_write_failed tvmi_write_failed

%include "hv/app_vm_cpu.asm"
%include "hv/app_vm_cpuid.asm"
%include "hv/app_vm_intel.asm"
%include "hv/app_vm_amd.asm"
%include "hv/app_vm_events.asm"

%undef app_vm_amd_prepare
%undef app_vm_amd_turn
%undef app_vm_cpu_prepare
%undef app_vm_cpu_retire
%undef app_vm_cpu_stop
%undef app_vm_cpu_turn
%undef app_vm_cpuid_prepare
%undef app_vm_cpuid_query
%undef app_vm_events_close
%undef app_vm_field_read
%undef app_vm_field_write
%undef app_vm_intel_prepare
%undef app_vm_intel_turn
%undef app_vm_isolation_ready
%undef app_vm_slat_build
%undef avm_arch
%undef avm_base
%undef avm_boot_phase
%undef avm_cpu_live
%undef avm_cpu_ready
%undef avm_cpuid
%undef avm_debug
%undef avm_exit
%undef avm_fields
%undef avm_gpr
%undef avm_guest_aux
%undef avm_guest_cr2
%undef avm_host_debug
%undef avm_raw_cpuid
%undef avm_root
%undef avm_roots_retired
%undef avm_state
%undef avm_svm
%undef avm_token
%undef avm_values
%undef avm_vector_error
%undef avm_vectoring
%undef avm_xstate
%undef avma_entered
%undef avma_initial
%undef avma_offsets
%undef avma_pull
%undef avma_push
%undef avmi_check_cs
%undef avmi_close
%undef avmi_control
%undef avmi_cr4_fixed
%undef avmi_cs
%undef avmi_entered
%undef avmi_failed_landing
%undef avmi_frame
%undef avmi_init_fields
%undef avmi_initial
%undef avmi_invept
%undef avmi_landing
%undef avmi_msr_ids
%undef avmi_old_cs
%undef avmi_open
%undef avmi_out
%undef avmi_pull
%undef avmi_push
%undef avmi_selected
%undef avmi_write
%undef avmi_write_failed
%undef AVM_CPU_ASID
%undef AVM_CPU_FAULT_CODE
%undef PAOS_TOOLS_CPU_INSTANCE
%undef avm_exit_ctx

; Native original START/token ->1/0. These are allocation/CPU library calls,
; not public launch/admission verbs. Every entry joins the actual allocator.
tools_vm_cpu_prepare:
    sub rsp,8
    call tvm_memory_current
    test eax,eax
    jz .bad
    call tvm_cpu_prepare_bound
    add rsp,8
    ret
.bad:
    add rsp,8
    xor eax,eax
    ret

tools_vm_cpu_turn:
    sub rsp,8
    ; No decode context outlives the exit that captured it.
    mov byte [rel tvm_exit_ctx+TXC_VALID],0
    call tvm_memory_current
    test eax,eax
    jz .bad
    call tvm_cpu_turn_bound
    add rsp,8
    ret
.bad:
    add rsp,8
    xor eax,eax
    ret

tools_vm_cpu_retire:
    sub rsp,8
    call tvm_memory_current
    test eax,eax
    jz .bad
    call tvm_cpu_retire_bound
    add rsp,8
    ret
.bad:
    add rsp,8
    xor eax,eax
    ret

; Shared CPU code calls with EDI=architecture; bind only the native instance.
; BSP serialization/no yields preserves the original entry join until here.
tvm_cpu_slat_bound:
    mov edx,edi
    mov rdi,[rel tvm_start]
    mov rsi,[rel tvm_token]
    jmp tools_vm_slat_build

; Private native storage, no alias-dependent tokens in deferred data. The
; immutable field-id list is common; all writable snapshots are tools-owned.
%include "hv/vcpu_cpuid.inc"
%include "core/abi/wdata.inc"
%macro WDATA_hv_tools_vm_cpu 0
align 16
tvm_cpu_storage_begin:
tvm_arch: dq 0
tvm_cpu_ready: dq 0
tvm_gpr: times 120 db 0
tvm_exit: times 32 db 0
tvm_guest_cr2: dq 0
tvm_debug: times 48 db 0
tvm_host_debug: times 56 db 0
tvm_guest_aux: dq 0
tvm_svm: times VSP_SIZE db 0
tvm_fields: dd AVM_CPU_FIELDS
align 8
tvm_values: times AVM_CPU_FIELDS_N dq 0
tvm_cpuid: times VCP_BYTES db 0
tvm_raw_cpuid: times VCP_BYTES db 0
tvm_xstate: times VAX_SIZE db 0
tvmi_invept: times 16 db 0
tvmi_old_cs: dq 0
tvmi_check_cs: dq 0
tvmi_cs: dq 0
tvmi_frame: dq 0
tvmi_cr4_fixed: dq 0
tvmi_selected: db 0
tvmi_write_failed: db 0
tvmi_entered: db 0
tvma_entered: db 0
align 4
tvm_vectoring: dd 0
tvm_vector_error: dd 0
align 8
tvm_exit_ctx: times TXC_BYTES db 0
tvm_cpu_storage_end:
; Snapshot disjointness loads this span with ECX. Reject empty, reversed
; or truncated layouts at WDATA expansion, after both labels are defined.
times (((tvm_cpu_storage_end-tvm_cpu_storage_begin) <= 0) || ((tvm_cpu_storage_end-tvm_cpu_storage_begin) > 0xffffffff)) * -1 db 0
%endmacro
WDATA_DEFER WDATA_hv_tools_vm_cpu
