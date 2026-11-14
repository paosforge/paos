;; MODULE sec/cpu_boundary_selector
;; LAYER 2
;; EXPORTS cpu_boundary_policy_select, cpu_boundary_policy_select_amd, cpu_boundary_amd_scope, cpu_boundary_hp_scope, cpu_boundary_amd_srso_scope
;; IMPORTS sec/cpu_security
;; CAPS
;; OWNER saga:security
; T1-6 explicit paired untrusted-VM policy, PURE; provenance and limits:
; gauntlet_v2/docs/t1_6_boundary_policy.md (spec21.1, Intel758381 v7,
; Intel823144 v2, L1TF/MDS/TAA/GDS guidance, AMD111006/SRSO guidance).
; No instruction here samples/writes hardware or launches a VM. This chooses
; obligations FIRST, then checks representability; availability is not policy.
; Trusted in-image caller supplies fresh same-CPU CSS112, never guest input.
; Pin CPU and serialize microcode/controls until the paired executor finishes.
; The executor must resample and validate its actual implementation, including
; RSB/CET restrictions. Status0 is a scoped plan, NOT execution/launch proof.
;
; Input144: CSS112 followed by qword version1, profile1 (untrusted VM pair),
; core custody0 unknown/1 exclusive core custody throughout the protected pair/
; 2 known shared core, reserved0. Exclusive means all sibling logical CPUs
; absent/offline/quiescent, including trusted host/interrupt activity, held
; from before paired mutation through restored host state. Trusted host work
; still shares core data with the untrusted guest and therefore maps to2.
; Unproved or expired exclusion maps to0. This is an actual host scheduling/
; quiescence fact, never CPUID SMT count, trust alone or a guest assertion.
; Profile1 covers first entry, every resume, exit and guest-to-guest via exit
; plus entry. No trusted-guest, zero-action or opt-out profile exists here.
;
; Output96 qwords: status, floor, entry actions, exit actions, unresolved,
; missing controls, missing actions, diagnostic floor/entry/exit, reserved0,0.
; Status0 SCOPED_PLAN,1 BAD_CAPTURE,2 VENDOR,3 NOT_NATIVE,4 UNKNOWN_UNSUPPORTED,
; 5 MISSING_CONTROL,6 MISSING_ACTION; -1 bad extents (no touch). Only status0
; publishes fields8..31; diagnostics are never executable requests/grants.
; Unresolved: ARCH1,BHI2,GDS4,TAA8,AMD_SSBD16,AMD_VENDOR_POLICY32,
; SMT_DATA64,eIBRS_PBRSB128,RFDS256,MMIO512. No broad immunity from ARCH_CAPS.
;
; Intel host floor: IBRS always; SSBD unless exact SSB_NO; preserve observed
; owned controls. IBRS also isolates sibling indirect prediction; do not add
; STIBP merely because available. Entry IBPB isolates prior same-mode guests;
; L1D flush unless RDCL_NO, VERW unless MDS_NO. These are separate obligations,
; not interchangeable capability fallbacks. Exit IBPB plus RSB overwrite on
; non-eIBRS; eIBRS requires PBRSB_NO here (special PBRSB sequence unsupported).
; No early host work/RET is protected merely by calling this selector later.
; Absent BHI_NO/GDS_NO/TAA_NO/RFDS_NO or MMIO not-affected bits is unresolved:
; existing CSS lacks the additional active controls/model applicability needed
; to discharge those obligations. Enumeration of a control is NOT enabled.
; Native-only policy does not use nested SKIP_L1DFL_VMENTRY as SMT immunity.
; L1TF/MDS vulnerability plus unknown/shared core custody refuses. No general
; SMT gate on exact scoped not-affected data cases. Other vulnerabilities,
; parser hardening, microcode freshness, EPT validity and allCPU coverage are
; outside this scoped plan, not proven by its success.
;
; AMD: derive IBRS + IBPB entry + IBPB/RAP-clear exit, but refuse explicitly:
; current normalized CSS has no AMD SSBD variants, SRSO/BTC/Zenbleed policy
; or their active-control/patch evidence. IBPB_RET is not SRSO immunity.
; This is a real missing implementation, not permission to skip mitigations.
;
; ABI RDI=input,RSI capacity,RDX=output,RCX capacity; full-width lengths,
; mapped fixed disjoint extents (adjacent/unaligned allowed). Input immutable.
; Every valid extent replaces output in full, even refusal. Callee saves and
; DF preserved; no callbacks, clock, allocation, global or privileged state.

CBS_INPUT_SIZE equ 144
CBS_OUTPUT_SIZE equ 96
CBS_VERSION equ 112
CBS_PROFILE equ 120
CBS_CORE equ 128
CBS_RESERVED equ 136
CBS_CORE_UNKNOWN equ 0
CBS_CORE_EXCLUSIVE equ 1
CBS_CORE_SHARED equ 2
CBS_O_STATUS equ 0
CBS_O_FLOOR equ 8
CBS_O_ENTRY equ 16
CBS_O_EXIT equ 24
CBS_O_UNRESOLVED equ 32
CBS_O_MISSING_CONTROL equ 40
CBS_O_MISSING_ACTION equ 48
CBS_O_DERIVED_FLOOR equ 56
CBS_O_DERIVED_ENTRY equ 64
CBS_O_DERIVED_EXIT equ 72

CBS_SCOPED_PLAN equ 0
CBS_BAD_CAPTURE equ 1
CBS_VENDOR equ 2
CBS_NOT_NATIVE equ 3
CBS_UNKNOWN_UNSUPPORTED equ 4
CBS_MISSING_CONTROL equ 5
CBS_MISSING_ACTION equ 6

cpu_boundary_policy_select:
    cmp  rsi, CBS_INPUT_SIZE
    jb   .bad_buffer
    cmp  rcx, CBS_OUTPUT_SIZE
    jb   .bad_buffer
    test rdi, rdi
    jz   .bad_buffer
    test rdx, rdx
    jz   .bad_buffer
    mov  r8, rdi
    add  r8, CBS_INPUT_SIZE
    jc   .bad_buffer
    mov  r9, rdx
    add  r9, CBS_OUTPUT_SIZE
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
%assign cbs_offset 0
%rep CBS_OUTPUT_SIZE / 8
    mov  qword [r13 + cbs_offset], 0
%assign cbs_offset cbs_offset + 8
%endrep
    cmp  qword [r12 + CBS_VERSION], 1
    jne  .bad_capture
    cmp  qword [r12 + CBS_PROFILE], 1
    jne  .bad_capture
    cmp  qword [r12 + CBS_RESERVED], 0
    jne  .bad_capture
    cmp  qword [r12 + CBS_CORE], CBS_CORE_SHARED
    ja   .bad_capture
    cmp  dword [r12 + CSS_HV], 1
    ja   .bad_capture
    je   .not_native
    mov  eax, [r12 + CSS_VENDOR]
    cmp  eax, 1
    je   .vendor_ok
    cmp  eax, 2
    jne  .vendor
.vendor_ok:
    cmp  dword [r12 + CSS_MAX], 1
    jb   .bad_capture
    test dword [r12 + CSS_EDX1], 1 << 5
    jz   .bad_capture
    cmp  dword [r12 + CSS_CTRL_VALID], 1
    ja   .bad_capture
    cmp  dword [r12 + CSS_ARCH_VALID], 1
    ja   .bad_capture
    mov  r14, [r12 + CSS_CAPS]
    mov  ecx, 255
    cmp  eax, 1
    je   .caps_bound
    mov  ecx, 7
.caps_bound:
    not  rcx
    test r14, rcx
    jnz  .bad_capture
    xor  edx, edx
    test r14b, 1
    jz   .stibp
    or   edx, 1
.stibp:
    test r14b, 4
    jz   .ssbd
    or   edx, 2
.ssbd:
    test r14b, 8
    jz   .mask
    or   edx, 4
.mask:
    cmp  rdx, [r12 + CSS_MASK]
    jne  .bad_capture
    test rdx, rdx
    jz   .observed
    cmp  dword [r12 + CSS_CTRL_VALID], 1
    jne  .bad_capture
.observed:
    not  rdx
    test rdx, [r12 + CSS_CTRL]
    jnz  .bad_capture
    xor  r10d, r10d                      ; unresolved obligations
    mov  ebx, 1                         ; IBRS floor from host threat model
    mov  r8d, 1                         ; IBPB on every entry/resume
    mov  r9d, 9                         ; IBPB + RSB on exit by default
    cmp  dword [r12 + CSS_VENDOR], 1
    jne  .amd
    cmp  dword [r12 + CSS_MAX], 7
    jb   .bad_capture
    xor  r15d, r15d
    test r14b, 64
    jnz  .arch_enumerated
    cmp  dword [r12 + CSS_ARCH_VALID], 0
    jne  .bad_capture
    jmp  .arch_unknown
.arch_enumerated:
    cmp  dword [r12 + CSS_ARCH_VALID], 1
    jne  .arch_unknown
    mov  r15, [r12 + CSS_ARCH]
    jmp  .intel
.arch_unknown:
    or   r10d, 1
.intel:
    bt   r15, 4                          ; SSB_NO, not SSBD availability
    jc   .l1tf
    or   ebx, 4
.l1tf:
    bt   r15, 0                          ; RDCL_NO discharges L1TF only
    jc   .mds
    or   r8d, 2
.mds:
    bt   r15, 5                          ; MDS_NO discharges MDS only
    jc   .smt
    or   r8d, 4
.smt:
    mov  eax, r8d
    and  eax, 6
    jz   .eibrs
    ; No sibling work, including trusted host/interrupt work, may overlap
    ; the protected pair when these data exposures require core exclusion.
    cmp  qword [r12 + CBS_CORE], CBS_CORE_EXCLUSIVE
    je   .eibrs
    or   r10d, 64
.eibrs:
    bt   r15, 1
    jnc  .bhi
    mov  r9d, 1                         ; eIBRS RSB semantics, not SW fill
    bt   r15, 24
    jc   .bhi
    or   r10d, 128                      ; needs special PBRSB sequence
.bhi:
    bt   r15, 20
    jc   .gds
    or   r10d, 2
.gds:
    bt   r15, 26
    jc   .taa
    or   r10d, 4
.taa:
    bt   r15, 8
    jc   .rfds
    or   r10d, 8
.rfds:
    bt   r15, 27
    jc   .mmio
    or   r10d, 256
.mmio:
    mov  eax, r15d
    and  eax, (1 << 13) | (1 << 14) | (1 << 15)
    cmp  eax, (1 << 13) | (1 << 14) | (1 << 15)
    je   .requirements
    or   r10d, 512
    jmp  .requirements
.amd:
    or   r10d, 16 | 32                 ; no AMD SSBD/vendor policy evidence
    cmp  qword [r12 + CBS_CORE], CBS_CORE_EXCLUSIVE
    je   .requirements
    or   ebx, 2                        ; AMD STIBP distinct from IBRS
.requirements:
    or   rbx, [r12 + CSS_CTRL]          ; never reduce observed owned floor
    mov  [r13 + CBS_O_DERIVED_FLOOR], rbx ; diagnostic only until success
    mov  [r13 + CBS_O_DERIVED_ENTRY], r8
    mov  [r13 + CBS_O_DERIVED_EXIT], r9
    mov  [r13 + CBS_O_UNRESOLVED], r10
    mov  rdx, [r12 + CSS_MASK]
    not  rdx
    and  rdx, rbx
    mov  [r13 + CBS_O_MISSING_CONTROL], rdx
    mov  ecx, 8                        ; software RSB; executor checks backend
    test r14b, 2
    jz   .hw_l1d
    or   ecx, 1
.hw_l1d:
    test r14b, 32
    jz   .hw_verw
    or   ecx, 2
.hw_verw:
    test r14b, 16
    jz   .hw_done
    or   ecx, 4
.hw_done:
    not  rcx
    mov  rsi, r8
    or   rsi, r9
    and  rsi, rcx
    mov  [r13 + CBS_O_MISSING_ACTION], rsi
    test r10, r10
    jnz  .unknown
    test rdx, rdx
    jnz  .missing_control
    test rsi, rsi
    jnz  .missing_action
    mov  [r13 + CBS_O_FLOOR], rbx
    mov  [r13 + CBS_O_ENTRY], r8
    mov  [r13 + CBS_O_EXIT], r9
    xor  eax, eax
    jmp  .status
.bad_capture:
    mov  eax, CBS_BAD_CAPTURE
    jmp  .status
.vendor:
    mov  eax, CBS_VENDOR
    jmp  .status
.not_native:
    mov  eax, CBS_NOT_NATIVE
    jmp  .status
.unknown:
    mov  eax, CBS_UNKNOWN_UNSUPPORTED
    jmp  .status
.missing_control:
    mov  eax, CBS_MISSING_CONTROL
    jmp  .status
.missing_action:
    mov  eax, CBS_MISSING_ACTION
.status:
    mov  [r13 + CBS_O_STATUS], rax
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
.bad_buffer:
    mov  rax, -1
    ret

; Additive AMD policy v2. Legacy144 selector above remains byte-for-byte.
; Input200: AI checked AMD160 followed by qwords version2/profile1/core custody/
; expected full32 APIC/reserved0 at160/168/176/184/192. Expected CPU is a trusted
; caller's pinned CPU, not a guest assertion. Status0 still only selects a plan.
; Pin CPU, serialize microcode/control state, and retain exclusive sibling custody
; through the entire pair. AI capture status0 does not itself prove these facts.
; Version3 uses the same fixed ABI for exact HP LS_CFG; see cpu_hp_policy_v3.md.
; Version4 requires capture v2 and separate checked SBPB evidence for the exact
; saved native client. See amd_srso_discovery_v4.md. Raw CPUID stays unchanged.
; Version2 scope: native SPEC_CTRL.SSBD only; exact signatures/patch branches in
; cpu_boundary_amd_scope below. TSA requires patched memory VERW on every entry;
; WBINVD/L1D_FLUSH and Intel MD_CLEAR enumeration are not substitutes.
; Both directions IBPB/RAP clear; host floor IBRS|SSBD plus all observed controls.
; No current225 eligibility, allCPU, idle-path or guest-visible MSR grant.
; Vendor citations and finite scope: gauntlet_v2/docs/amd_boundary_policy_v2.md.
CBS_AMD_INPUT equ 200
cpu_boundary_policy_select_amd:
    cmp  rsi, CBS_AMD_INPUT
    jb   .bad_buffer
    cmp  rcx, CBS_OUTPUT_SIZE
    jb   .bad_buffer
    test rdi, rdi
    jz   .bad_buffer
    test rdx, rdx
    jz   .bad_buffer
    mov  r8, rdi
    add  r8, CBS_AMD_INPUT
    jc   .bad_buffer
    mov  r9, rdx
    add  r9, CBS_OUTPUT_SIZE
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
    sub  rsp, CBS_INPUT_SIZE
    mov  r12, rdi
    mov  r13, rdx
%assign cba_i 0
%rep CBS_OUTPUT_SIZE / 8
    mov  qword [r13 + cba_i], 0
%assign cba_i cba_i + 8
%endrep
    cmp  qword [r12 + 160], 2
    je   .amd_version
    cmp  qword [r12 + 160], 3
    je   .amd_version
    cmp  qword [r12 + 160], 4
    jne  .bad_capture
.amd_version:
    cmp  qword [r12 + 168], 1
    jne  .bad_capture
    cmp  qword [r12 + 176], 2
    ja   .bad_capture
    cmp  qword [r12 + 192], 0
    jne  .bad_capture
    cmp  qword [r12 + 160], 4
    je   .v4_capture
    cmp  dword [r12 + 112], 1
    jne  .bad_capture
    cmp  dword [r12 + 156], 0
    jne  .bad_capture
    jmp  .checked_status
.v4_capture:
    cmp  dword [r12 + 112], 2
    jne  .bad_capture
    cmp  dword [r12 + CSS_SIG], 0x00a70f52
    jne  .bad_capture
    cmp  dword [r12 + 156], 1
    ja   .bad_capture
.checked_status:
    cmp  dword [r12 + 116], 0
    jne  .bad_capture
    cmp  dword [r12 + 128], 1
    jne  .bad_capture
    cmp  dword [r12 + 132], 1
    jne  .bad_capture
    mov  eax, [r12 + 120]
    cmp  eax, [r12 + 124]
    jne  .bad_capture
    cmp  rax, [r12 + 184]
    jne  .bad_capture
    cmp  dword [r12 + CSS_VENDOR], 2
    jne  .vendor
    cmp  dword [r12 + 136], 1
    ja   .bad_capture
    cmp  dword [r12 + CSS_EXTMAX], 0x80000021
    jb   .absent21
    cmp  dword [r12 + 136], 1
    jne  .bad_capture
    jmp  .legacy_capture
.absent21:
    cmp  dword [r12 + 136], 0
    jne  .bad_capture
    mov  rax, [r12 + 140]
    or   rax, [r12 + 148]
    jnz  .bad_capture
.legacy_capture:
    ; Checked producer's normalized legacy facts must agree with retained raw
    ; native enumeration; a mixed/stale capture never supplies a control gate.
    xor  eax, eax
    bt   dword [r12 + CSS_EBX8], 14
    jnc  .raw_ibpb
    or   eax, 1
.raw_ibpb:
    bt   dword [r12 + CSS_EBX8], 12
    jnc  .raw_stibp
    or   eax, 2
.raw_stibp:
    bt   dword [r12 + CSS_EBX8], 15
    jnc  .raw_caps
    or   eax, 4
.raw_caps:
    cmp  rax, [r12 + CSS_CAPS]
    jne  .bad_capture
    ; Reuse every existing CSS112 validation, without extending its ABI.
%assign cba_i 0
%rep CSS_SIZE / 8
    mov  rax, [r12 + cba_i]
    mov  [rsp + cba_i], rax
%assign cba_i cba_i + 8
%endrep
    mov  qword [rsp + 112], 1
    mov  qword [rsp + 120], 1
    mov  rax, [r12 + 176]
    mov  [rsp + 128], rax
    mov  qword [rsp + 136], 0
    mov  rdi, rsp
    mov  esi, CBS_INPUT_SIZE
    mov  rdx, r13
    mov  ecx, CBS_OUTPUT_SIZE
    call cpu_boundary_policy_select
    cmp  rax, CBS_UNKNOWN_UNSUPPORTED
    jne  .status
    cmp  qword [r12 + 160], 3
    je   .hp
    ; AMD's two legacy unresolved bits are exactly the new scope to discharge.
    mov  r14d, 16 | 32
    mov  rbx, [r13 + CBS_O_DERIVED_FLOOR]
    or   ebx, 4                         ; require SSBD, never availability=enabled
    mov  [r13 + CBS_O_DERIVED_FLOOR], rbx
    mov  qword [r13 + CBS_O_DERIVED_ENTRY], 13
    mov  qword [r13 + CBS_O_DERIVED_EXIT], 9
    bt   dword [r12 + CSS_EBX8], 24
    jnc  .scope
    and  r14d, ~16
.scope:
    mov  rdi, r12
    mov  esi, [r12 + 136]
    mov  edx, [r12 + 140]
    cmp  qword [r12 + 160], 4
    jne  .v2_scope
    mov  r8d, [r12 + 156]
    call cpu_boundary_amd_srso_scope
    jmp  .scope_status
.v2_scope:
    call cpu_boundary_amd_scope
.scope_status:
    test eax, eax
    jnz  .custody
    and  r14d, ~32
.custody:
    cmp  qword [r12 + 176], CBS_CORE_EXCLUSIVE
    je   .representable
    or   r14d, 64                      ; no sibling-proof surrogate
.representable:
    mov  [r13 + CBS_O_UNRESOLVED], r14
    mov  rdx, [r12 + CSS_MASK]
    bt   dword [r12 + CSS_EBX8], 24
    jnc  .control_mask
    or   edx, 4
.control_mask:
    not  rdx
    and  rdx, rbx
    mov  [r13 + CBS_O_MISSING_CONTROL], rdx
    xor  ecx, ecx
    bt   dword [r12 + CSS_EBX8], 12
    jnc  .rap
    or   ecx, 1
.rap:
    bt   dword [r12 + CSS_EBX8], 30
    jnc  .verw
    test cl, 1
    jz   .verw
    or   ecx, 8
.verw:
    test r14b, 32                      ; only patch-supported memory VERW
    jnz  .actions
    or   ecx, 4
.actions:
    not  rcx
    and  ecx, 13
    mov  [r13 + CBS_O_MISSING_ACTION], rcx
    mov  eax, CBS_UNKNOWN_UNSUPPORTED
    test r14, r14
    jnz  .status
    mov  eax, CBS_MISSING_CONTROL
    test rdx, rdx
    jnz  .status
    mov  eax, CBS_MISSING_ACTION
    test rcx, rcx
    jnz  .status
    mov  [r13 + CBS_O_FLOOR], rbx
    mov  qword [r13 + CBS_O_ENTRY], 13
    mov  qword [r13 + CBS_O_EXIT], 9
    xor  eax, eax
    jmp  .status
.hp:
%assign cbh_i 0
%rep CBS_OUTPUT_SIZE / 8
    mov  qword [r13 + cbh_i], 0
%assign cbh_i cbh_i + 8
%endrep
    mov  rdi, r12
    call cpu_boundary_hp_scope
    test eax, eax
    jnz  .hp_unknown
    mov  qword [r13 + CBS_O_DERIVED_FLOOR], 4
    mov  qword [r13 + CBS_O_DERIVED_ENTRY], 9
    mov  qword [r13 + CBS_O_DERIVED_EXIT], 9
    cmp  qword [r12 + 176], CBS_CORE_EXCLUSIVE
    jne  .hp_custody
    mov  qword [r13 + CBS_O_FLOOR], 4
    mov  qword [r13 + CBS_O_ENTRY], 9
    mov  qword [r13 + CBS_O_EXIT], 9
    xor  eax, eax
    jmp  .status
.hp_custody:
    mov  qword [r13 + CBS_O_UNRESOLVED], 64
    mov  eax, CBS_UNKNOWN_UNSUPPORTED
    jmp  .status
.hp_unknown:
    mov  qword [r13 + CBS_O_UNRESOLVED], 16 | 32
    mov  eax, CBS_UNKNOWN_UNSUPPORTED
    jmp  .status
.vendor:
    mov  eax, CBS_VENDOR
    jmp  .status
.bad_capture:
    mov  eax, CBS_BAD_CAPTURE
.status:
    mov  [r13], rax
    add  rsp, CBS_INPUT_SIZE
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
.bad_buffer:
    mov  rax, -1
    ret

; Internal shared pure predicate, never a launch grant. RDI=fresh trustedCSS112,
; ESI=leaf21 actually available0/1, EDX=raw leaf21 EAX. Return0 supported or4.
; No family/brand guess, cross-branch numeric revision, USER_KERNEL_NO waiver,
; or IBPB_RET=>SRSO inference. Same signature/revision predicate is resampled by
; BOTH v2 paired operations before accepting their native control/action scope.
; AMD TSA rev2 appendix exact mappings (higher only inside exact patch branch):
; 19h/01h/1 Milan A0011D7; 19h/50h/0 Cezanne A500012;
; 19h/75h/2 Phoenix A705208. No other signatures are admitted here.
; Milan SRSO patch lower bound A0011D1 per AMD-SB-7005, therefore D7 suffices;
; Client bulletins list AGESA, not a revision mapping: Cezanne/Phoenix require
; actual SRSO_NO or IBPB_BRTYPE. No AGESA-to-revision inference is made.
cpu_boundary_amd_scope:
    xor  r8d, r8d                       ; v2 never accepts probe evidence
    jmp  cpu_boundary_amd_scope_common

; Additive v4 trusted observation: R8D=completed checked SBPB0/1. Only exact
; saved native client/patch can use1. This does not change raw CPUID or v2.
cpu_boundary_amd_srso_scope:
    cmp  r8d, 1
    ja   .unknown
    cmp  dword [rdi + CSS_SIG], 0x00a70f52
    jne  .unknown
    test r8d, r8d
    jz   .scope
    cmp  qword [rdi + CSS_REV], 0x0a70520a
    jne  .unknown
    test edx, (1 << 28) | (1 << 29)
    jnz  .unknown                       ; producer skips probe when enumerated
.scope:
    jmp  cpu_boundary_amd_scope_common
.unknown:
    mov  eax, 4
    ret
cpu_boundary_amd_scope_common:
    cmp  dword [rdi + CSS_VENDOR], 2
    jne  .unknown
    cmp  dword [rdi + CSS_HV], 0
    jne  .unknown
    cmp  dword [rdi + CSS_MAX], 1
    jb   .unknown
    bt   dword [rdi + CSS_EDX1], 5
    jnc  .unknown
    cmp  dword [rdi + CSS_EXTMAX], 0x80000008
    jb   .unknown
    cmp  dword [rdi + CSS_REV_VALID], 1
    jne  .unknown
    cmp  dword [rdi + CSS_REV + 4], 0
    jne  .unknown
    mov  eax, [rdi + CSS_SIG]
    cmp  eax, 0x00A00F11
    je   .milan
    cmp  eax, 0x00A70F52
    je   .phoenix
    cmp  eax, 0x00A50F00
    jne  .unknown
    mov  eax, [rdi + CSS_REV]
    and  eax, 0xFFFFFF00
    cmp  eax, 0x0A500000
    jne  .unknown
    cmp  dword [rdi + CSS_REV], 0x0A500012
    jb   .unknown
    jmp  .client_srso
.phoenix:
    mov  eax, [rdi + CSS_REV]
    and  eax, 0xFFFFFF00
    cmp  eax, 0x0A705200
    jne  .unknown
    cmp  dword [rdi + CSS_REV], 0x0A705208
    jb   .unknown
.client_srso:
    cmp  esi, 1
    jne  .unknown
    cmp  dword [rdi + CSS_EXTMAX], 0x80000021
    jb   .unknown
    test edx, (1 << 28) | (1 << 29)
    jnz  .supported
    cmp  r8d, 1
    jne  .unknown
    cmp  dword [rdi + CSS_SIG], 0x00a70f52
    jne  .unknown
    cmp  qword [rdi + CSS_REV], 0x0a70520a
    jne  .unknown
.supported:
    xor  eax, eax
    ret
.milan:
    mov  eax, [rdi + CSS_REV]
    and  eax, 0xFFFFFF00
    cmp  eax, 0x0A001100
    jne  .unknown
    cmp  dword [rdi + CSS_REV], 0x0A0011D7
    jb   .unknown
    xor  eax, eax
    ret
.unknown:
    mov  eax, 4
    ret

; v3 exact HP legacy variant. Pure predicate over unextended native CSS112.
; This does NOT admit v2, infer SPEC_CTRL, or establish sibling custody.
; The single saved revision is an identity pin, not a fabricated mitigation
; patch minimum. Vendor mapping/variant obligations: cpu_hp_policy_v3.md.
; Require the actual IBPB-only form; architectural SSBD variants use other ABIs.
cpu_boundary_hp_scope:
    cmp  dword [rdi + CSS_VENDOR], 2
    jne  .unknown
    cmp  dword [rdi + CSS_HV], 0
    jne  .unknown
    cmp  dword [rdi + CSS_SIG], 0x00810F81
    jne  .unknown
    cmp  dword [rdi + CSS_MAX], 1
    jb   .unknown
    mov  eax, [rdi + CSS_EDX1]
    and  eax, (1 << 5) | (1 << 26)       ; native MSR and SSE2/LFENCE
    cmp  eax, (1 << 5) | (1 << 26)
    jne  .unknown
    cmp  dword [rdi + CSS_EXTMAX], 0x80000008
    jb   .unknown
    cmp  dword [rdi + CSS_REV_VALID], 1
    jne  .unknown
    cmp  qword [rdi + CSS_REV], 0x0810810E
    jne  .unknown
    mov  eax, [rdi + CSS_EBX8]
    and  eax, (1 << 12) | (1 << 14) | (1 << 15) | (7 << 24)
    cmp  eax, 1 << 12
    jne  .unknown
    cmp  qword [rdi + CSS_CAPS], CS_CAP_IBPB
    jne  .unknown
    cmp  qword [rdi + CSS_MASK], 0
    jne  .unknown
    cmp  dword [rdi + CSS_CTRL_VALID], 0
    jne  .unknown
    cmp  qword [rdi + CSS_CTRL], 0
    jne  .unknown
    xor  eax, eax
    ret
.unknown:
    mov  eax, 4
    ret
