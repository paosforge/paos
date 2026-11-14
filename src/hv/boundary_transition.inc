; Actual transition frontiers expanded in callers, with no helper or RET.
; The v3 recipe has exactly 32 nonzero CALLs, each targeting the next fill slot.
; RSP is the retained private HVB frame. Guest GPRs are saved before LAND;
; FINAL runs after the last helper and before guest GPR load. Clobber A/B/C/D.
; Full Intel6/AMD7 use checked architectural or guarded-native custody.
; _TO macros take an explicit nonresuming failure target; default wrappers
; preserve core/AP containment. Never redefine the shared fail-stop symbol:
; its image-wide alias union must not connect AP/IRQ roots to BSP-only owners.
; Guarded-native keeps UNKNOWN/SMT gaps; legacy generic tokens never admit.
; Native faults remain guarded.
%ifndef HV_BOUNDARY_TRANSITION_INC
%define HV_BOUNDARY_TRANSITION_INC 1
; Explicit bounded expansion keeps the same instructions visible to the
; maintained call-graph lint as well as NASM; no runtime loop or helper.
%macro HV_BOUNDARY_FILL_STEP 0
    call %%fill_next
%%fill_trap:
    pause
    lfence
    jmp %%fill_trap
%%fill_next:
%endmacro
%macro HV_BOUNDARY_FILL32 0
    HV_BOUNDARY_FILL_STEP
    HV_BOUNDARY_FILL_STEP
    HV_BOUNDARY_FILL_STEP
    HV_BOUNDARY_FILL_STEP
    HV_BOUNDARY_FILL_STEP
    HV_BOUNDARY_FILL_STEP
    HV_BOUNDARY_FILL_STEP
    HV_BOUNDARY_FILL_STEP
    HV_BOUNDARY_FILL_STEP
    HV_BOUNDARY_FILL_STEP
    HV_BOUNDARY_FILL_STEP
    HV_BOUNDARY_FILL_STEP
    HV_BOUNDARY_FILL_STEP
    HV_BOUNDARY_FILL_STEP
    HV_BOUNDARY_FILL_STEP
    HV_BOUNDARY_FILL_STEP
    HV_BOUNDARY_FILL_STEP
    HV_BOUNDARY_FILL_STEP
    HV_BOUNDARY_FILL_STEP
    HV_BOUNDARY_FILL_STEP
    HV_BOUNDARY_FILL_STEP
    HV_BOUNDARY_FILL_STEP
    HV_BOUNDARY_FILL_STEP
    HV_BOUNDARY_FILL_STEP
    HV_BOUNDARY_FILL_STEP
    HV_BOUNDARY_FILL_STEP
    HV_BOUNDARY_FILL_STEP
    HV_BOUNDARY_FILL_STEP
    HV_BOUNDARY_FILL_STEP
    HV_BOUNDARY_FILL_STEP
    HV_BOUNDARY_FILL_STEP
    HV_BOUNDARY_FILL_STEP
    add rsp, 32 * 8
    lfence
%endmacro
; Intel BHI guidance Listing2, long sequence (12 outer / 7 inner).
; Direct balanced calls only, CET disabled by the VM owner contract. On LAND
; the selected RSB/PBRSB fill precedes these RETs. No host helper or indirect
; branch is introduced. Every stack change is balanced before the frontier.
%macro HV_BOUNDARY_BHB_LONG 0
    mov ecx, 12
    call %%outer
    jmp %%done
    align 64, db 0x90
%%outer:
    call %%inner
    ret
    align 64, db 0x90
%%inner:
    mov eax, 7
%%loop:
    jmp %%branch
    nop
%%branch:
    sub eax, 1
    jnz %%loop
    sub ecx, 1
    jnz %%outer
    ret
%%done:
    lfence
%endmacro
; Full Intel uses paired executor6 and full AMD7. Legacy recipes stay explicit.
; Mode2 is a VM-private producer contract, separate from the selector ABI.
; Its producer must freshly bind CIS/CIP, exact live native custody, CPU/revision,
; controls and CET-off state on both sides. The actual VMX producer binds
; this lifecycle; a generic parking token is never permission to set mode2.
; v0.73 executes every reported mechanism and software fallback selected by
; SEC; missing hardware mechanisms remain visible policy gaps, not CPU bans.
%macro HV_BOUNDARY_INTEL_CHECK 0
    HV_BOUNDARY_INTEL_CHECK_TO cpu_boundary_fail_stop
%endmacro
%macro HV_BOUNDARY_INTEL_CHECK_TO 1
    cmp qword [rsp + HVB_REQUEST], 6
    jne %1
    cmp qword [rsp + HVB_LEASE], 0
    je %1
    cmp qword [rsp + HVB_LEASE], -1
    je %1
    mov rax, [rsp + HVB_POLICY + 8]
    and rax, ~7                      ; only reported owned controls
    jnz %1
    mov rax, [rsp + HVB_POLICY + 16]
    and rax, ~87                     ; IBPB, L1D, VERW, BHB, MCU
    jnz %1
    mov rax, [rsp + HVB_POLICY + 24]
    and rax, ~125                     ; IBPB, VERW, RSB, BHB, PBRSB, MCU
    jnz %1
%endmacro
%macro HV_BOUNDARY_INTEL_MCU 1
    HV_BOUNDARY_INTEL_MCU_TO %1, cpu_boundary_fail_stop
%endmacro
%macro HV_BOUNDARY_INTEL_MCU_TO 2
    test qword [rsp + HVB_POLICY + %1], 64
    jz %%done
    mov rbx, [rsp + HVB_INTEL_MCU_MASK]
    test rbx, rbx
    jz %2
    test rbx, ~25
    jnz %2
    ; Preserve every live unowned bit. Never restore a prior full register;
    ; these repairs remain host mitigation floors on both sides of the pair.
    mov ecx, 0x123
    rdmsr
    shl rdx, 32
    or rax, rdx
    not rbx
    and rax, rbx
    mov rdx, rax
    shr rdx, 32
    mov ecx, 0x123
    wrmsr
    mov ecx, 0x123
    rdmsr
    shl rdx, 32
    or rax, rdx
    not rbx
    test rax, rbx
    jnz %2
    xor eax, eax
    xor ecx, ecx
    cpuid
%%done:
%endmacro
%macro HV_BOUNDARY_AMD_FULL_CHECK 0
    HV_BOUNDARY_AMD_FULL_CHECK_TO cpu_boundary_fail_stop
%endmacro
%macro HV_BOUNDARY_AMD_FULL_CHECK_TO 1
    cmp qword [rsp + HVB_REQUEST], 7
    jne %1
    cmp qword [rsp + HVB_LEASE], 0
    je %1
    cmp qword [rsp + HVB_LEASE], -1
    je %1
    mov rax, [rsp + HVB_POLICY + 8]
    and rax, ~7
    jnz %1
    mov rax, [rsp + HVB_POLICY + 16]
    or rax, [rsp + HVB_POLICY + 24]
    and rax, ~13
    jnz %1
%endmacro
%macro HV_BOUNDARY_AMD_FULL_ACTIONS 1
    HV_BOUNDARY_AMD_FULL_ACTIONS_TO %1, cpu_boundary_fail_stop
%endmacro
%macro HV_BOUNDARY_AMD_FULL_ACTIONS_TO 2
    HV_BOUNDARY_AMD_FULL_CHECK_TO %2
    mov ax, ds
    mov [rsp + HVB_VERW], ax
    test qword [rsp + HVB_POLICY + %1], 1
    jz %%no_ibpb
    mov ecx, 0x49
    mov eax, 1
    xor edx, edx
    wrmsr
    xor eax, eax
    xor ecx, ecx
    cpuid
%%no_ibpb:
    test qword [rsp + HVB_POLICY + %1], 8
    jz %%no_rsb
    HV_BOUNDARY_FILL32
%%no_rsb:
    ; Publish phase before the last memory-form clear. No helper/store follows.
    mov qword [rsp + HVB_FRONTIER], (%1 - 16) / 8 + 2
    test qword [rsp + HVB_POLICY + %1], 4
    jz %%done
    verw word [rsp + HVB_VERW]
%%done:
    lfence
%endmacro

%macro HV_BOUNDARY_FINAL 0
    HV_BOUNDARY_FINAL_TO cpu_boundary_fail_stop
%endmacro
%macro HV_BOUNDARY_FINAL_TO 1
    cmp qword [rsp + HVB_ACTIVE], 1
    jne %1
    cmp qword [rsp + HVB_GUARD], 0
    je %1
    cmp qword [rsp + HVB_FRONTIER], 1
    jne %1
    cmp dword [rsp + HVB_SVM], 2
    je %%intel
    cmp qword [rsp + HVB_REQUEST], 7
    je %%amd_full
    cmp qword [rsp + HVB_REQUEST], 1
    je %%legacy
    cmp qword [rsp + HVB_REQUEST], 3
    je %%hp
    cmp qword [rsp + HVB_REQUEST], 4
    je %%amd
    cmp qword [rsp + HVB_REQUEST], 2
    jne %1
%%amd:
    cmp qword [rsp + HVB_LEASE], 0
    je %1
    ; Accepted AMDv2/v4 plan only: IBPB+RAP at both transitions, memory VERW
    ; at the final trusted->untrusted frontier. No broad mask or WBINVD.
    cmp qword [rsp + HVB_POLICY + 16], 13
    jne %1
    cmp qword [rsp + HVB_POLICY + 24], 9
    jne %1
    mov ax, ds
    mov [rsp + HVB_VERW], ax
    mov ecx, 0x49
    mov eax, 1
    xor edx, edx
    wrmsr
    xor eax, eax
    xor ecx, ecx
    cpuid
    mov qword [rsp + HVB_FRONTIER], 2
    verw word [rsp + HVB_VERW]
    lfence
    jmp %%done
%%hp:
    cmp qword [rsp + HVB_LEASE], 0
    je %1
    cmp qword [rsp + HVB_POLICY + 8], 4
    jne %1
    cmp qword [rsp + HVB_POLICY + 16], 9
    jne %1
    cmp qword [rsp + HVB_POLICY + 24], 9
    jne %1
    mov ecx, 0x49
    mov eax, 1
    xor edx, edx
    wrmsr
    xor eax, eax
    xor ecx, ecx
    cpuid
    ; SECv3 installs/reads back DE_CFG.LFENCE and LS_CFG.SSBD first.
    ; Nonzero CALLs poison stale return predictions before the first RET;
    ; none RET here. Stack is exactly balanced before guest GPR load.
    HV_BOUNDARY_FILL32
    jmp %%legacy
%%amd_full:
    HV_BOUNDARY_AMD_FULL_ACTIONS_TO 16, %1
    jmp %%done
%%intel:
    HV_BOUNDARY_INTEL_CHECK_TO %1
    HV_BOUNDARY_INTEL_MCU_TO 16, %1
    mov ax, ds
    mov [rsp + HVB_VERW], ax
    test qword [rsp + HVB_POLICY + 16], 1
    jz %%intel_no_ibpb
    mov ecx, 0x49
    mov eax, 1
    xor edx, edx
    wrmsr
    xor eax, eax
    xor ecx, ecx
    cpuid
%%intel_no_ibpb:
    test qword [rsp + HVB_POLICY + 16], 16
    jz %%intel_no_bhb
    HV_BOUNDARY_BHB_LONG
%%intel_no_bhb:
    test qword [rsp + HVB_POLICY + 16], 2
    jz %%intel_no_l1d
    ; Write-only L1D_FLUSH, after the last helper. Stack/data stores and host
    ; helpers must not follow a selected final memory-form buffer clear.
    mov ecx, 0x10b
    mov eax, 1
    xor edx, edx
    wrmsr
    xor eax, eax
    xor ecx, ecx
    cpuid
%%intel_no_l1d:
    mov qword [rsp + HVB_FRONTIER], 2
    test qword [rsp + HVB_POLICY + 16], 4
    jz %%intel_entry_done
    verw word [rsp + HVB_VERW]
%%intel_entry_done:
    lfence
    jmp %%done
%%legacy:
    mov qword [rsp + HVB_FRONTIER], 2
%%done:
%endmacro

%macro HV_BOUNDARY_LAND 0
    HV_BOUNDARY_LAND_TO cpu_boundary_fail_stop
%endmacro
%macro HV_BOUNDARY_LAND_TO 1
    ; No helper, indirect branch or RET may precede this after guest exit.
    cmp qword [rsp + HVB_ACTIVE], 1
    jne %1
    cmp qword [rsp + HVB_GUARD], 0
    je %1
    cmp qword [rsp + HVB_FRONTIER], 2
    jne %1
    cmp dword [rsp + HVB_SVM], 2
    je %%intel
    cmp qword [rsp + HVB_REQUEST], 7
    je %%amd_full
    cmp qword [rsp + HVB_REQUEST], 1
    je %%legacy
    cmp qword [rsp + HVB_REQUEST], 3
    je %%hp
    cmp qword [rsp + HVB_REQUEST], 4
    je %%amd
    cmp qword [rsp + HVB_REQUEST], 2
    jne %1
%%amd:
    cmp qword [rsp + HVB_LEASE], 0
    je %1
    cmp qword [rsp + HVB_POLICY + 24], 9
    jne %1
    mov ecx, 0x49
    mov eax, 1
    xor edx, edx
    wrmsr
    xor eax, eax
    xor ecx, ecx
    cpuid
    jmp %%legacy
%%hp:
    cmp qword [rsp + HVB_LEASE], 0
    je %1
    cmp qword [rsp + HVB_POLICY + 24], 9
    jne %1
    mov ecx, 0x49
    mov eax, 1
    xor edx, edx
    wrmsr
    xor eax, eax
    xor ecx, ecx
    cpuid
    HV_BOUNDARY_FILL32
    jmp %%legacy
%%amd_full:
    HV_BOUNDARY_AMD_FULL_ACTIONS_TO 24, %1
    jmp %%done
%%intel:
    HV_BOUNDARY_INTEL_CHECK_TO %1
    HV_BOUNDARY_INTEL_MCU_TO 24, %1
    test qword [rsp + HVB_POLICY + 24], 1
    jz %%intel_no_ibpb
    mov ecx, 0x49
    mov eax, 1
    xor edx, edx
    wrmsr
    xor eax, eax
    xor ecx, ecx
    cpuid
%%intel_no_ibpb:
    test qword [rsp + HVB_POLICY + 24], 8 | 32
    jz %%intel_no_rsb
    ; Fill only after IBPB, before any selected VERW; no helper or RET may
    ; consume a stale prediction. CET-off is freshly checked by the producer.
    HV_BOUNDARY_FILL32
%%intel_no_rsb:
    test qword [rsp + HVB_POLICY + 24], 16
    jz %%intel_no_bhb
    HV_BOUNDARY_BHB_LONG
%%intel_no_bhb:
    mov qword [rsp + HVB_FRONTIER], 3
    test qword [rsp + HVB_POLICY + 24], 4
    jz %%intel_exit_done
    verw word [rsp + HVB_VERW]
%%intel_exit_done:
    lfence
    jmp %%done
%%legacy:
    mov qword [rsp + HVB_FRONTIER], 3
%%done:
%endmacro

%macro HV_BOUNDARY_HOST_XCR0 0
    ; Restore inline before the first host CALL/RET; guest GPRs already saved.
    cmp byte [rel hv_linux_xcr0_swap], 1
    jne %%done
    mov eax, [rel hv_linux_exit_xcr0]
    mov edx, [rel hv_linux_exit_xcr0 + 4]
    xor ecx, ecx
    xsetbv
%%done:
%endmacro
%endif
