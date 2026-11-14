;; MODULE sec/cpu_boundary_policy
;; LAYER 2
;; EXPORTS cpu_boundary_policy_plan
;; IMPORTS
;; CAPS
;; OWNER saga:security
; RCQ42 PURE boundary-plan validator; executor and VM inclusion are separate.
; No CPUID, MSR, VM instruction, callback, allocation, clock or global state.
; PLAN_OK means this finite requested plan is representable, NOT that the CPU
; is secure, microcode current, actions executed, or a VM boundary qualified.
;
; Trusted serialized in-image caller supplies a same-logical-CPU capture and
; actual executor/virtual-interface implementation masks. Guest text/CPUID or
; assertions cannot supply flags, host floors or implementation masks. This
; function cannot attest their truth/freshness or all-CPU/SMT coverage.
;
; Versions6 Intel/7 AMD are the spec073 full-default execution validators.
; They allow the legal VERW instruction without claiming patched clearing;
; the native executor reports unproved clearing separately. Guest interfaces
; remain zero. Full-only Intel actions16/32/64 are validated/executed by the
; version6 native executor, never silently accepted here.
; Current normalized observation contract (same numeric meanings as the
; separately reviewed CPU observation slice; no dependency on its code):
; Intel: IBRS1, IBPB2, STIBP4, SSBD8, MD_CLEAR16, L1D32, ARCH_CAPS64, BHI128.
; AMD v1: IBRS1, IBPB2, STIBP4 only. AMD v2 additionally accepts SSBD8 and
; patched memory-VERW16 from the versioned native executor's exact scope.
; Version3 is the exact HP LS_CFG host-only variant, normalized SSBD8|IBPB2,
; floor4/actions9. It grants no guest interfaces. See cpu_hp_policy_v3.md.
; Version4 retains version2 planning semantics and zero guest interfaces;
; its separate checked SRSO evidence is described in amd_srso_discovery_v4.md.
; The pure validator cannot establish those facts. Version2 requires AMD;
; Intel stays version1. BHI may
; be observed on Intel but is outside this helper's guest/control scope.
; No architectural-capability immunity bit is inferred or used as a waiver.
;
; Owned SPEC_CTRL bit mask is derived from IBRS/STIBP/SSBD enumeration and
; MUST equal the supplied capture mask. Observed owned bits are preserved:
; host floor = observed | requested host floor; entry = floor | guest bits;
; exit = floor. These are MASKED bits, never full WRMSR operands. A future
; executor must preserve other hardware bits and own actual entry/exit writes.
; Guests cannot reduce the host floor or directly program host controls.
;
; Boundary action bits: IBPB1, L1D_FLUSH2, VERW/MD_CLEAR4, software RSB8.
; Each requested action requires hardware support AND a declared executor;
; RSB needs a software executor, not an invented CPUID permission. No action
; is executed here. The caller owns applicability/order/coverage decisions;
; a zero request is not a complete mitigation policy or a guest launch grant.
;
; Advertised guest features must be supported physically and require actual
; virtual interfaces: IBRS/STIBP/SSBD -> SPEC_CTRL_RW1 (MSR48h); IBPB ->
; PRED_CMD_W2 (49h); ARCH_CAPS -> sanitized ARCH_CAPS_R4 (10Ah); L1D ->
; FLUSH_CMD_W8 (10Bh). Implemented means functional semantics, NOT trapping,
; zero reads, ignored writes, or host passthrough. MD_CLEAR has no MSR
; interface requirement here; its instruction/runtime semantics still need
; qualification. Guest requested control bits must also be advertised.
; Unsupported/unknown requests refuse explicitly, never silently mask CPUID.
;
; ABI: RDI=input, RSI=input capacity, RDX=output, RCX=output capacity.
; Returns RAX=status (0..10), or -1 for invalid fixed extents with NO touch.
; Caller supplies mapped extents. Validate NULL/wrap/overlap/capacities before
; access; use full-width lengths. Input/output fixed96-byte spans must be
; disjoint; adjacent/unaligned spans are permitted. Input is immutable.
; Valid extents always replace all output bytes, including on refusal. Only
; success publishes plan fields8..39; diagnostic masks40..95 carry no grant.
; Callee-save registers preserved, DF unchanged (no string instructions).
;
; Status priority follows validation order below; diagnostics are not a list
; of every applicability issue. No image/VM/BOOT call sites changed by this
; slice. Future callers must test status, bind virtual CPUID/MSR composition,
; implement/measure required actions, and qualify actual host↔guest↔guest
; transitions. Microcode load/AP-wide state, eIBRS/BHI/SRSO/Downfall and other
; vendor/model-specific mitigation selection remain separate required work.

CBI_VERSION      equ 0                  ; u32, 1 legacy, 2 AMD, 3 HP, 4 checked SRSO
CBI_VENDOR       equ 4                  ; u32: Intel1, AMD2
CBI_FLAGS        equ 8                  ; u64: caps valid1,native host2,ctrl valid4
CBI_CAPS         equ 16                 ; current normalized hardware enumeration
CBI_OWNED_MASK   equ 24                 ; observed supported SPEC_CTRL bits
CBI_OBSERVED     equ 32                 ; observed owned bits, not raw MSR
CBI_FLOOR        equ 40                 ; host-required owned bits
CBI_ACTIONS      equ 48                 ; required boundary actions
CBI_EXECUTORS    equ 56                 ; trusted implemented action mask
CBI_GUEST_CAPS   equ 64                 ; features actually advertised to guest
CBI_VIRTUAL      equ 72                 ; trusted implemented virtual interfaces
CBI_GUEST_BITS   equ 80                 ; untrusted guest requested SPEC_CTRL bits
CBI_RESERVED     equ 88                 ; must0
CBI_SIZE         equ 96

CBO_STATUS       equ 0
CBO_HOST_FLOOR   equ 8
CBO_ENTRY_BITS   equ 16
CBO_EXIT_BITS    equ 24
CBO_ACTIONS      equ 32
CBO_VREQUIRED    equ 40
CBO_VMISSING     equ 48
CBO_HW_MISSING   equ 56                 ; required actions absent in hardware
CBO_EXEC_MISSING equ 64                 ; required actions with no executor
CBO_CTRL_MISSING equ 72                 ; host floor bits not supported
CBO_GUEST_MASK   equ 80                 ; owned bits advertised to guest
CBO_GUEST_BAD    equ 88                 ; guest requests outside advertised mask
CBO_SIZE         equ 96

CBP_PLAN_OK       equ 0
CBP_BAD_CAPTURE   equ 1
CBP_VENDOR        equ 2
CBP_NOT_NATIVE    equ 3
CBP_REQUEST       equ 4
CBP_HOST_CONTROL  equ 5
CBP_HOST_ACTION   equ 6
CBP_EXECUTOR      equ 7
CBP_GUEST_FEATURE equ 8
CBP_GUEST_CONTROL equ 9
CBP_GUEST_VIRTUAL equ 10

cpu_boundary_policy_plan:
    cmp  rsi, CBI_SIZE
    jb   .bad_buffer
    cmp  rcx, CBO_SIZE
    jb   .bad_buffer
    test rdi, rdi
    jz   .bad_buffer
    test rdx, rdx
    jz   .bad_buffer
    mov  r8, rdi
    add  r8, CBI_SIZE
    jc   .bad_buffer
    mov  r9, rdx
    add  r9, CBO_SIZE
    jc   .bad_buffer
    cmp  r8, rdx
    jbe  .disjoint
    cmp  r9, rdi
    ja   .bad_buffer
.disjoint:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13, rdx
%assign cbp_out_offset 0
%rep CBO_SIZE / 8
    mov  qword [r13 + cbp_out_offset], 0
%assign cbp_out_offset cbp_out_offset + 8
%endrep
    cmp  dword [r12 + CBI_VERSION], 6
    je   .full_intel
    cmp  dword [r12 + CBI_VERSION], 7
    je   .amd_version
    cmp  dword [r12 + CBI_VERSION], 1
    je   .version_ok
    cmp  dword [r12 + CBI_VERSION], 2
    je   .amd_version
    cmp  dword [r12 + CBI_VERSION], 4
    je   .amd_version
    cmp  dword [r12 + CBI_VERSION], 3
    jne  .bad_capture
    cmp  qword [r12 + CBI_CAPS], 2 | 8
    jne  .bad_capture
    cmp  qword [r12 + CBI_FLOOR], 4
    jne  .request
    cmp  qword [r12 + CBI_ACTIONS], 9
    jne  .request
    jmp  .amd_version
.full_intel:
    cmp  dword [r12 + CBI_VENDOR], 1
    jne  .bad_capture
    jmp  .full_guest
.amd_version:
    cmp  dword [r12 + CBI_VENDOR], 2
    jne  .bad_capture
.full_guest:
    ; Scoped v2 caps include patched VERW, not an AMD guest CPUID promise.
    ; No new virtual interface or guest-advertisement semantics are granted.
    mov  rax, [r12 + CBI_GUEST_CAPS]
    or   rax, [r12 + CBI_VIRTUAL]
    or   rax, [r12 + CBI_GUEST_BITS]
    test rax, rax
    jnz  .request
.version_ok:
    cmp  qword [r12 + CBI_RESERVED], 0
    jne  .bad_capture
    mov  rax, [r12 + CBI_FLAGS]
    test rax, ~7
    jnz  .bad_capture
    test al, 1
    jz   .bad_capture
    mov  ecx, [r12 + CBI_VENDOR]
    cmp  ecx, 1
    je   .vendor_ok
    cmp  ecx, 2
    jne  .vendor
.vendor_ok:
    test al, 2
    jz   .not_native
    mov  r15, [r12 + CBI_CAPS]
    cmp  ecx, 1
    jne  .amd_caps
    test r15, ~255
    jnz  .bad_capture
    jmp  .caps_ok
.amd_caps:
    cmp  dword [r12 + CBI_VERSION], 7
    je   .amd_v2_caps
    cmp  dword [r12 + CBI_VERSION], 4
    je   .amd_v2_caps
    cmp  dword [r12 + CBI_VERSION], 3
    je   .amd_v2_caps
    cmp  dword [r12 + CBI_VERSION], 2
    je   .amd_v2_caps
    test r15, ~7
    jnz  .bad_capture
    jmp  .caps_ok
.amd_v2_caps:
    test r15, ~31
    jnz  .bad_capture
.caps_ok:
    xor  r14d, r14d
    bt   r15, 0                          ; IBRS -> SPEC_CTRL bit0
    jnc  .host_stibp
    or   r14d, 1
.host_stibp:
    bt   r15, 2
    jnc  .host_ssbd
    or   r14d, 2
.host_ssbd:
    bt   r15, 3
    jnc  .host_mask
    or   r14d, 4
.host_mask:
    cmp  r14, [r12 + CBI_OWNED_MASK]
    jne  .bad_capture
    test r14, r14
    jz   .capture_ctrl
    test byte [r12 + CBI_FLAGS], 4
    jz   .bad_capture
.capture_ctrl:
    mov  rax, r14
    not  rax
    test [r12 + CBI_OBSERVED], rax
    jnz  .bad_capture
    mov  rax, [r12 + CBI_EXECUTORS]
    or   rax, [r12 + CBI_VIRTUAL]
    test rax, ~15
    jnz  .bad_capture
    mov  rax, [r12 + CBI_FLOOR]
    or   rax, [r12 + CBI_GUEST_BITS]
    test rax, ~7
    jnz  .request
    test qword [r12 + CBI_ACTIONS], ~15
    jnz  .request
    mov  r8, [r12 + CBI_GUEST_CAPS]
    test r8, ~127
    jnz  .request

    xor  ecx, ecx
    bt   r8, 0
    jnc  .guest_stibp
    or   ecx, 1
.guest_stibp:
    bt   r8, 2
    jnc  .guest_ssbd
    or   ecx, 2
.guest_ssbd:
    bt   r8, 3
    jnc  .guest_mask
    or   ecx, 4
.guest_mask:
    mov  [r13 + CBO_GUEST_MASK], rcx
    not  rcx
    and  rcx, [r12 + CBI_GUEST_BITS]
    mov  [r13 + CBO_GUEST_BAD], rcx
    xor  r9d, r9d
    test r8b, 1 | 4 | 8
    jz   .virtual_pred
    or   r9d, 1
.virtual_pred:
    test r8b, 2
    jz   .virtual_arch
    or   r9d, 2
.virtual_arch:
    test r8b, 64
    jz   .virtual_flush
    or   r9d, 4
.virtual_flush:
    test r8b, 32
    jz   .virtual_mask
    or   r9d, 8
.virtual_mask:
    mov  [r13 + CBO_VREQUIRED], r9
    mov  rax, [r12 + CBI_VIRTUAL]
    not  rax
    and  rax, r9
    mov  [r13 + CBO_VMISSING], rax
    mov  ecx, 8                           ; software RSB still needs executor
    cmp  dword [r12 + CBI_VERSION], 6
    jb   .action_ibpb
    or   ecx, 4                           ; legal VERW attempt, not efficacy
.action_ibpb:
    bt   r15, 1
    jnc  .action_l1d
    or   ecx, 1
.action_l1d:
    bt   r15, 5
    jnc  .action_md
    or   ecx, 2
.action_md:
    bt   r15, 4
    jnc  .action_mask
    or   ecx, 4
.action_mask:
    not  rcx
    and  rcx, [r12 + CBI_ACTIONS]
    mov  [r13 + CBO_HW_MISSING], rcx
    mov  rax, [r12 + CBI_EXECUTORS]
    not  rax
    and  rax, [r12 + CBI_ACTIONS]
    mov  [r13 + CBO_EXEC_MISSING], rax
    mov  rax, r14
    not  rax
    and  rax, [r12 + CBI_FLOOR]
    mov  [r13 + CBO_CTRL_MISSING], rax
    test rax, rax
    jne  .missing_control
    cmp  qword [r13 + CBO_HW_MISSING], 0
    jne  .missing_action
    cmp  qword [r13 + CBO_EXEC_MISSING], 0
    jne  .missing_executor
    mov  rax, r15
    not  rax
    test rax, r8
    jnz  .guest_feature
    cmp  qword [r13 + CBO_GUEST_BAD], 0
    jne  .guest_control
    cmp  qword [r13 + CBO_VMISSING], 0
    jne  .missing_virtual

    mov  rbx, [r12 + CBI_FLOOR]
    or   rbx, [r12 + CBI_OBSERVED]
    mov  [r13 + CBO_HOST_FLOOR], rbx
    mov  [r13 + CBO_EXIT_BITS], rbx
    or   rbx, [r12 + CBI_GUEST_BITS]
    mov  [r13 + CBO_ENTRY_BITS], rbx
    mov  rax, [r12 + CBI_ACTIONS]
    mov  [r13 + CBO_ACTIONS], rax
    xor  eax, eax
    jmp  .status
.bad_capture:
    mov  eax, CBP_BAD_CAPTURE
    jmp  .status
.vendor:
    mov  eax, CBP_VENDOR
    jmp  .status
.not_native:
    mov  eax, CBP_NOT_NATIVE
    jmp  .status
.request:
    mov  eax, CBP_REQUEST
    jmp  .status
.missing_control:
    mov  eax, CBP_HOST_CONTROL
    jmp  .status
.missing_action:
    mov  eax, CBP_HOST_ACTION
    jmp  .status
.missing_executor:
    mov  eax, CBP_EXECUTOR
    jmp  .status
.guest_feature:
    mov  eax, CBP_GUEST_FEATURE
    jmp  .status
.guest_control:
    mov  eax, CBP_GUEST_CONTROL
    jmp  .status
.missing_virtual:
    mov  eax, CBP_GUEST_VIRTUAL
.status:
    mov  [r13 + CBO_STATUS], rax
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
.bad_buffer:
    mov  rax, -1
    ret
