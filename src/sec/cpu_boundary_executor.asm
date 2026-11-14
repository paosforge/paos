;; MODULE sec/cpu_boundary_executor
;; LAYER 2
;; EXPORTS cpu_boundary_execute, cpu_boundary_context_enter, cpu_boundary_context_exit
;; IMPORTS sec/cpu_security, sec/cpu_boundary_policy, sec/cpu_boundary_selector, sec/cpu_microcode_checked, core/smp
;; CAPS
;; OWNER saga:security
;; LOCK: cbc_lock PROTECTS cbc_generation, cbc_slots
; RCQ42 bounded native executor, included in the image; VM call sites remain
; VM-owned. This is NOT a complete mitigation policy or guest launch grant.
; Trusted caller pins the logical CPU, serializes controls/microcode changes,
; supplies mapped extents and does not yield/migrate during this call. DF=0.
; Caller owns entry/exit placement, interrupt/NMI handling and all GPR custody.
;
; Input32 bytes: u64 version=1,2,3 or4, host-required normalized floor, required action
; mask, reserved=0. Action meanings are the integrated planner's IBPB1,
; L1D2, VERW4, RSB8. IBPB, L1D_FLUSH and memory-VERW are implemented HERE;
; RSB8 uses bounded software filling or enumerated AMD RAP clearing below.
; No guest bits, capability
; advertising or virtual MSR contracts can be supplied through this API.
; Every call samples the actual native CPU; caller-supplied vendor/capture or
; implementation assertions are not accepted. Hypervisor observations refuse.
; Version3 is exact HP legacy AMD: normalized SSBD4 means LS_CFG10, actions9
; require IBPB plus software32CALL fill, guest bits0. DE_CFG1 and LS_CFG10 are
; permanent host floors, all other raw bits preserved. See cpu_hp_policy_v3.md.
; Version6 Intel/7 AMD implement spec073 full-default execution. Unknown
; models/patches are not refused. Version6 adds BHB16/PBRSB32/MCU-repair64;
; version7 uses reported SSBD plus a software return-fill fallback. A legal
; VERW attempt is not proof of updated clearing: unproved hardware semantics
; remain CBO_HW_MISSING4 in the standalone executor. The paired receipt has
; its existing distinct layout; VM retains selector diagnostics separately.
; Version2 is AMD-only: exact CPU/patch scope shared with the additive selector,
; native SPEC_CTRL.SSBD and patched memory-VERW at CPL0. Version1 is unchanged.
; Version4 adds fresh checked SRSO discovery for exact00a70f52/0a70520a; raw
; CPUID is unchanged. Both the paired preflight and inner execute resample on
; the calling full APIC. A checked probe failure refuses before control writes.
; gauntlet_v2/docs/amd_boundary_policy_v2.md pins vendor scope and obligations.
; New reads retain the raw nonresuming fault contract, not checked fixup success.
;
; RDI=input, RSI=capacity, RDX=output96, RCX=capacity; full-width extents.
; Output is the existing CBO96 diagnostic/plan layout; status0 publishes only
; AFTER the requested supported writes and serializing CPUID. Refusals publish
; diagnostics with usable plan fields zero. Invalid mapped-span geometry returns
; -1 with no touch/hardware access. Bad request returns11, no hardware access.
; Output status12 marks execution pending until final publication. It is never
; returned normally; a fault cannot leave an apparent successful output row.
; Other statuses retain CBP meanings. Input immutable; callee-save preserved.
;
; Fresh sampler preserves its own vendor/leaf/MSR gates (Intel revision latch
; clear only). The actual control write re-reads raw SPEC_CTRL and ORs the
; sampled observed|required floor into ALL live bits. Nothing is cleared,
; including high/unowned/newly enabled controls. IBPB is write-only MSR49 bit0;
; never RDMSR49/10B. SPEC_CTRL write precedes IBPB, then requested RSB fill,
; then L1D_FLUSH and memory-VERW+LFENCE; CPUID serializes completion. Required
; actions need independently enumerated support; L1D does not stand in for a
; requested VERW action or vice versa. Both Intel CPUID gates are in the sampler.
; Zero required actions is not a full policy. The original execute ABI never
; removes controls. The paired context ABI below owns temporary bits separately.
;
; Intel CPUID/MSR enumeration and IBPB guidance (retrieved 2026-10-16):
; https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/cpuid-enumeration-and-architectural-msrs.html
; https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/indirect-branch-predictor-barrier.html
; AMD111006: native80000008 EBX12/14/15, PRED_CMD49/bit0, SPEC_CTRL48.
; https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/white-papers/111006-architecture-guidelines-update-amd64-technology-indirect-branch-control-extension.pdf
; Intel MD_CLEAR CPUID7.0.EDX10 requires the MEMORY operand form of VERW;
; DS supplies a caller's current data selector, and immediate LFENCE prevents
; VERW fall-through speculation before subsequent execution. L1D_FLUSH is
; write-only MSR10B bit0, gated separately by CPUID7.0.EDX28. Guidance:
; https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/intel-analysis-microarchitectural-data-sampling.html
; AMD APM24593 rev3.44 (March2026), p69 PRED_CMD: raw native CPUID
; 80000008h EBX12 supports IBPB; EBX30 IBPB_RET means IBPB also clears
; the return address predictor. Therefore AMD required RSB8 performs a real
; PRED_CMD=1 write even when action1 is absent. One write serves both when
; both are required. No family/brand/revision, BTC_NO29 or ERAPS inference.
; https://docs.amd.com/api/khub/documents/sD1_QL~h4Afq2_tvzxqqSQ/content
; This is a RAP clear, not a branch-type/SRSO completeness claim. No software
; stuffing fallback, CET/control write or additional stack consumption. AMD
; PRED_CMD WRMSR is dispatch serializing, not a memory-ordering barrier.
; This callable path does not attest hardware effectiveness, SMT/AP coverage,
; signed/fresh microcode, eIBRS/BHI/SRSO/Downfall policy or costs. The
; backend owner must place the final clear near its actual security boundary;
; instructions/interrupts after a callable primitive can refill structures.

; Required RSB8: Intel family6, non-eIBRS only, excluding the documented
; reduced-width RSB models (their code-address alias treatment is not here).
; IBRS_ALL=ARCH_CAPABILITIES bit1 makes this implementation unavailable, NOT
; a waiver of required RSB. No ARCH_CAPS enumeration means no eIBRS; when
; enumerated the captured value must be valid. Fresh CR4.CET23 must be clear:
; unbalanced CALLs cannot be used with enabled shadow stacks; no CET writes,
; INCSSP or inferred shadow-stack permissions. AMD/unknown families refuse.
; Software availability is reflected through existing missing-executor status7,
; without changing the pure planner or its required-action policy.
;
; Inline32 nonzero-displacement near CALLs, no RET in the fill, each saved
; return address targets PAUSE/LFENCE/JMP-to-self; ADD RSP256 repairs the data
; stack and a retiring LFENCE completes the fill. Exactly256 additional stack
; bytes must be mapped below the normal304-byte frame (+40 saves/8 return).
; Fills AFTER IBPB (which can empty RSB), BEFORE L1D/VERW (stack stores can
; refill buffers). No nested helper RET consumes a fill entry. Later adapter
; calls/returns are balanced; ordinary final RET still consumes an entry.
; Backend must place this before its first unbalanced RET; this callable ABI
; cannot protect its own earlier sampler/planner calls or early VM landing.
; Pinned CPU, stable CR4/microcode and interrupt/NMI exclusion remain caller work.
;
; Intel required32 nonzero CALL surplus, eIBRS limitations, reduced-width model
; list and safe speculation traps (retrieved2026-10-16):
; https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/indirect-branch-restricted-speculation.html
; https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/retpoline-branch-target-injection-mitigation.html
; CR4.CET and shadow-stack CALL/RET semantics: Intel SDM Vol1 chapter18,
; Vol3A CR4 bit23. This executor conservatively refuses all CR4.CET-on RSB.
; https://cdrdv2-public.intel.com/868137/325462-089-sdm-vol-1-2abcd-3abcd-4.pdf

CBE_REQUEST_SIZE equ 32
CBE_INPUT        equ CSS_SIZE
CBE_PLAN         equ CSS_SIZE + CBI_SIZE
CBE_FULL_MASK    equ CSS_SIZE + CBI_SIZE + CBO_SIZE
CBE_STACK        equ CBE_FULL_MASK + 16

; AMD action8 alone writes PRED_CMD=1; action1|8 uses one write. Raw native
; EBX12+30 gate the implementation; no family/model or BTC_NO inference.
cpu_boundary_execute:
    xor  r10d, r10d
    xor  r11d, r11d
    jmp  cpu_boundary_execute_common

; Internal only: R10 points at private32-byte capture (before/after/observed/mask),
; R11 is the privately validated introduced-bit mask to remove on paired exit.
; No external ABI accepts these assertions. Public execute always forces zero.
cpu_boundary_execute_common:
    cmp  rsi, CBE_REQUEST_SIZE
    jb   .bad_buffer
    cmp  rcx, CBO_SIZE
    jb   .bad_buffer
    test rdi, rdi
    jz   .bad_buffer
    test rdx, rdx
    jz   .bad_buffer
    mov  r8, rdi
    add  r8, CBE_REQUEST_SIZE
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
    sub  rsp, CBE_STACK                  ; 320 bytes, calls aligned
    mov  r12, rdi
    mov  r13, rdx
    mov  r14, r10
    mov  r15, r11
%assign cbe_offset 0
%rep CBO_SIZE / 8
    mov  qword [r13 + cbe_offset], 0
    mov  qword [rsp + CBE_PLAN + cbe_offset], 0
    mov  qword [rsp + CBE_INPUT + cbe_offset], 0
%assign cbe_offset cbe_offset + 8
%endrep
    mov  qword [r13 + CBO_STATUS], 12
    cmp  qword [r12], 6
    je   .version_ok
    cmp  qword [r12], 7
    je   .version_ok
    cmp  qword [r12], 1
    je   .version_ok
    cmp  qword [r12], 2
    je   .version_ok
    cmp  qword [r12], 4
    je   .version_ok
    cmp  qword [r12], 3
    jne  .bad_request
    cmp  qword [r12 + 8], 4
    jne  .bad_request
    cmp  qword [r12 + 16], 9
    jne  .bad_request
.version_ok:
    cmp  qword [r12 + 24], 0
    jne  .bad_request
    test qword [r12 + 8], ~7
    jnz  .bad_request
    mov  eax,15
    cmp  qword [r12],6
    jne  .action_mask
    mov  eax,127
.action_mask:
    not  rax
    test [r12 + 16],rax
    jnz  .bad_request

    mov  rdi, rsp
    mov  esi, CSS_SIZE
    call cpu_security_sample
    test rax, rax
    jnz  .bad_capture
    cmp  dword [rsp + CSS_MAX], 1
    jb   .bad_capture
    bt   dword [rsp + CSS_EDX1], 5        ; no MSR permission from caps alone
    jnc  .bad_capture
    cmp  qword [r12], 7
    je   .full_amd_sample
    cmp  qword [r12], 6
    jne  .legacy_vendor
    cmp  dword [rsp + CSS_VENDOR],1
    jne  .bad_capture
.legacy_vendor:
    cmp  qword [r12], 4
    je   .srso_sample
    cmp  qword [r12], 3
    je   .hp_sample
    cmp  qword [r12], 2
    jne  .sample_ready
    mov  rdi, rsp
    call cpu_boundary_amd_v2_sample
    jmp  .sample_status
.full_amd_sample:
    mov  rdi,rsp
    call cpu_boundary_amd_full_sample
    jmp  .sample_status
.srso_sample:
    mov  rdi, rsp
    call cpu_boundary_amd_v4_sample
    jmp  .sample_status
.hp_sample:
    mov  rdi, rsp
    call cpu_boundary_hp_sample
.sample_status:
    test eax, eax
    jnz  .bad_capture
.sample_ready:
    mov  eax, [r12]
    mov  dword [rsp + CBE_INPUT + CBI_VERSION], eax
    mov  eax, [rsp + CSS_VENDOR]
    mov  [rsp + CBE_INPUT + CBI_VENDOR], eax
    mov  eax, 1                         ; enumeration valid
    cmp  dword [rsp + CSS_HV], 0
    jne  .flags_control
    or   eax, 2                         ; native host
.flags_control:
    cmp  dword [rsp + CSS_CTRL_VALID], 1
    jne  .flags_ready
    or   eax, 4
.flags_ready:
    mov  [rsp + CBE_INPUT + CBI_FLAGS], rax
    mov  rax, [rsp + CSS_CAPS]
    ; Local executable-action capability, NOT a CPUID MD_CLEAR advertisement.
    ; FB_CLEAR/RFDS_CLEAR independently extend memory VERW. Fresh raw CSS and
    ; guest-visible enumeration remain untouched. Applicability/active opt-outs
    ; are the trusted selector's separate obligation; execution is not immunity.
    cmp  qword [r12], 6
    je   .intel_action_caps
    cmp  qword [r12], 1
    jne  .action_caps_ready
.intel_action_caps:
    cmp  dword [rsp + CSS_VENDOR], 1
    jne  .action_caps_ready
    cmp  dword [rsp + CSS_HV], 0
    jne  .action_caps_ready
    test rax, CS_CAP_ARCH
    jz   .action_caps_ready
    cmp  dword [rsp + CSS_ARCH_VALID], 1
    jne  .action_caps_ready
    test qword [rsp + CSS_ARCH], (1 << 17) | (1 << 28)
    jz   .action_caps_ready
    or   rax, CS_CAP_MD_CLEAR
.action_caps_ready:
    mov  [rsp + CBE_INPUT + CBI_CAPS], rax
    mov  rax, [rsp + CSS_MASK]
    mov  [rsp + CBE_INPUT + CBI_OWNED_MASK], rax
    mov  rax, [rsp + CSS_CTRL]
    test r14, r14
    jz   .observed_ready
    mov  [r14 + 16], rax
    mov  rdx, [rsp + CSS_MASK]
    mov  [r14 + 24], rdx
    mov  rdx, r15
    not  rdx
    and  rax, rdx                       ; remove only private context bits
.observed_ready:
    mov  [rsp + CBE_INPUT + CBI_OBSERVED], rax
    mov  rax, [r12 + 8]
    mov  [rsp + CBE_INPUT + CBI_FLOOR], rax
    mov  rax, [r12 + 16]
    and  eax,15                        ; full-only software steps execute below
    mov  [rsp + CBE_INPUT + CBI_ACTIONS], rax
    mov  qword [rsp + CBE_INPUT + CBI_EXECUTORS], 7
    test qword [r12 + 16], 8
    jz   .plan                          ; no CR4 access for other actions
    cmp  dword [rsp + CSS_HV], 0
    jne  .plan
    cmp  qword [r12],6
    je   .rsb_cr4                       ; no model-based software refusal
    cmp  qword [r12],7
    je   .rsb_cr4
    cmp  dword [rsp + CSS_VENDOR], 1
    jne  .amd_rap
    mov  eax, [rsp + CSS_SIG]
    shr  eax, 8
    and  eax, 15
    cmp  eax, 6
    jne  .plan
    mov  eax, [rsp + CSS_SIG]
    mov  edx, eax
    shr  eax, 4
    and  eax, 15
    shr  edx, 12
    and  edx, 0xF0
    or   eax, edx                       ; Intel family6 display model
    cmp  eax, 0x37
    je   .plan
    cmp  eax, 0x4A
    je   .plan
    cmp  eax, 0x4C
    je   .plan
    cmp  eax, 0x4D
    je   .plan
    cmp  eax, 0x5A
    je   .plan
    cmp  eax, 0x5D
    je   .plan
    cmp  eax, 0x65
    je   .plan
    cmp  eax, 0x6E
    je   .plan
    test qword [rsp + CSS_CAPS], CS_CAP_ARCH
    jz   .rsb_cr4
    cmp  dword [rsp + CSS_ARCH_VALID], 1
    jne  .plan
    test qword [rsp + CSS_ARCH], 2       ; IBRS_ALL is NOT a required-action waiver
    jnz  .plan
.rsb_cr4:
    call cpu_boundary_read_cr4
    bt   rax, 23                        ; any active CET -> no unbalanced CALLs
    jc   .plan
    or   qword [rsp + CBE_INPUT + CBI_EXECUTORS], 8
    jmp  .plan
.amd_rap:
    cmp  qword [r12], 3
    je   .rsb_cr4                       ; exact scoped legacy AMD software fill
    cmp  dword [rsp + CSS_VENDOR], 2
    jne  .plan
    cmp  dword [rsp + CSS_EXTMAX], 0x80000008
    jb   .plan
    bt   dword [rsp + CSS_EBX8], 12
    jnc  .plan
    bt   dword [rsp + CSS_EBX8], 30
    jnc  .plan
    or   qword [rsp + CBE_INPUT + CBI_EXECUTORS], 8
.plan:
    cmp  qword [r12],6
    jne  .full_plan
    test qword [r12+16],32
    jz   .full_mcu_permission
    call cpu_boundary_read_cr4
    bt   rax,23
    jnc  .full_mcu_permission
    mov  qword [rsp+CBE_PLAN+CBO_STATUS],7
    mov  qword [rsp+CBE_PLAN+CBO_EXEC_MISSING],32
    jmp  .publish
.full_mcu_permission:
    test qword [r12+16],64
    jz   .full_plan
    xor  eax,eax
    cmp  dword [rsp+CSS_ARCH_VALID],1
    jne  .permission_srbds
    bt   qword [rsp+CSS_ARCH],25
    jnc  .permission_fb
    or   eax,16
.permission_fb:
    bt   qword [rsp+CSS_ARCH],18
    jnc  .permission_srbds
    or   eax,8
.permission_srbds:
    bt   dword [rsp+CSS_EDX7],9
    jnc  .permission_mask
    or   eax,1
.permission_mask:
    test eax,eax
    jz   .bad_request
    not  rax
    mov  [rsp+CBE_FULL_MASK],rax
.full_plan:
    lea  rdi, [rsp + CBE_INPUT]
    mov  esi, CBI_SIZE
    lea  rdx, [rsp + CBE_PLAN]
    mov  ecx, CBO_SIZE
    call cpu_boundary_policy_plan
    test rax, rax
    jnz  .publish                       ; no mitigation write on refusal

    cmp  qword [r12],6
    jb   .full_diagnostics_ready
    mov  rax,[r12+16]
    mov  [rsp+CBE_PLAN+CBO_ACTIONS],rax
    test eax,4
    jz   .full_diagnostics_ready
    test qword [rsp+CBE_INPUT+CBI_CAPS],CS_CAP_MD_CLEAR
    jnz  .full_diagnostics_ready
    or   qword [rsp+CBE_PLAN+CBO_HW_MISSING],4
.full_diagnostics_ready:
    cmp  qword [r12], 3
    je   .hp_controls
    cmp  qword [rsp + CSS_MASK], 0
    je   .actions                       ; IBPB-only AMD needs no SPEC_CTRL
    mov  ecx, 0x48
    call cpu_boundary_rdmsr
    shl  rdx, 32
    or   rax, rdx
    test r14, r14
    jz   .live_ready
    mov  [r14], rax
    mov  rdx, r15
    not  rdx
    and  rax, rdx                       ; preserve ALL other live bits
.live_ready:
    or   rax, [rsp + CBE_PLAN + CBO_HOST_FLOOR]
    test r14, r14
    jz   .write_live
    mov  [r14 + 8], rax
.write_live:
    mov  rdx, rax
    shr  rdx, 32
    mov  eax, eax
    mov  ecx, 0x48
    call cpu_boundary_wrmsr
    jmp  .actions
.hp_controls:
    ; Never clear these host floors. Caller excludes sibling/control writers.
    ; LFENCE dispatch serialization is an actual family17 DE_CFG control.
    mov  ecx, 0xC0011029
    call cpu_boundary_rdmsr
    shl  rdx, 32
    or   rax, rdx
    or   rax, 2
    mov  rdx, rax
    shr  rdx, 32
    mov  ecx, 0xC0011029
    call cpu_boundary_wrmsr
    mov  ecx, 0xC0011029
    call cpu_boundary_rdmsr
    test eax, 2
    jz   .hp_control_refused
    mov  ecx, 0xC0011020
    call cpu_boundary_rdmsr
    shl  rdx, 32
    or   rax, rdx
    test r14, r14
    jz   .hp_live
    mov  [r14], rax                     ; actual raw LS_CFG before
.hp_live:
    or   rax, 1 << 10                   ; family17 shared-core SSBD
    mov  rdx, rax
    shr  rdx, 32
    mov  ecx, 0xC0011020
    call cpu_boundary_wrmsr
    mov  ecx, 0xC0011020
    call cpu_boundary_rdmsr
    shl  rdx, 32
    or   rax, rdx
    test eax, 1 << 10
    jz   .hp_control_refused
    test r14, r14
    jz   .actions
    mov  [r14 + 8], rax                 ; actual raw readback, not SPEC_CTRL
    jmp  .actions
.hp_control_refused:
    ; A write may already have installed a permanent floor, but no completed
    ; boundary exists. Discard the earlier pure plan as well as its status.
%assign cbh_refuse_i 0
%rep CBO_SIZE / 8
    mov  qword [rsp + CBE_PLAN + cbh_refuse_i*8], 0
%assign cbh_refuse_i cbh_refuse_i + 1
%endrep
    jmp  .bad_capture
.actions:
    cmp  qword [r12],6
    jne  .ibpb_test
    test qword [r12+16],64
    jz   .ibpb_test
    ; Permission/mask validated before the first control mutation.
    mov  ecx,0x123
    call cpu_boundary_rdmsr
    shl  rdx,32
    or   rax,rdx
    and  rax,[rsp+CBE_FULL_MASK]
    mov  rdx,rax
    shr  rdx,32
    mov  ecx,0x123
    call cpu_boundary_wrmsr
    mov  ecx,0x123
    call cpu_boundary_rdmsr
    shl  rdx,32
    or   rax,rdx
    mov  rdx,[rsp+CBE_FULL_MASK]
    not  rdx
    test rax,rdx
    jnz  .full_control_unavailable     ; locked/ignored write is NOT success
.ibpb_test:
    test qword [rsp + CBE_PLAN + CBO_ACTIONS], 1
    jnz  .ibpb
    cmp  qword [r12],7
    je   .rsb
    cmp  dword [rsp + CSS_VENDOR], 2
    jne  .rsb
    test qword [rsp + CBE_PLAN + CBO_ACTIONS], 8
    jz   .rsb
.ibpb:
    mov  ecx, 0x49
    mov  eax, 1
    xor  edx, edx
    call cpu_boundary_wrmsr
.rsb:
    cmp  qword [r12],6
    jne  .rsb_test
    test qword [r12+16],32
    jz   .bhb
    call .pbrsb_target
    int3
.pbrsb_target:
    lea  rsp,[rsp+8]
    lfence
.bhb:
    test qword [r12+16],16
    jz   .rsb_test
    mov  ecx,12
    call .bhb_outer
    jmp  .bhb_done
    align 64
.bhb_outer:
    call .bhb_inner
    ret
    align 64
.bhb_inner:
    mov  eax,7
.bhb_loop:
    jmp  .bhb_taken
    nop
.bhb_taken:
    sub  eax,1
    jnz  .bhb_loop
    sub  ecx,1
    jnz  .bhb_outer
    ret
.bhb_done:
    lfence
.rsb_test:
    test qword [rsp + CBE_PLAN + CBO_ACTIONS], 8
    jz   .l1d
    cmp  qword [r12],7
    je   .rsb_fill
    cmp  qword [r12], 3
    je   .rsb_fill
    cmp  dword [rsp + CSS_VENDOR], 1
    jne  .l1d
.rsb_fill:
%assign cbe_rsb_i 0
%rep 32
    call .rsb_next_%+cbe_rsb_i
.rsb_trap_%+cbe_rsb_i:
    pause
    lfence
    jmp  .rsb_trap_%+cbe_rsb_i
.rsb_next_%+cbe_rsb_i:
%assign cbe_rsb_i cbe_rsb_i + 1
%endrep
    add  rsp, 32 * 8
    lfence
.rsb_filled:
.l1d:
    test qword [rsp + CBE_PLAN + CBO_ACTIONS], 2
    jz   .clear_buffers
    mov  ecx, 0x10B
    mov  eax, 1
    xor  edx, edx
    call cpu_boundary_wrmsr
.clear_buffers:
    test qword [rsp + CBE_PLAN + CBO_ACTIONS], 4
    jz   .serialize
    call cpu_boundary_verw
.serialize:
    call cpu_boundary_serialize
.publish:
%assign cbe_offset 0
%rep CBO_SIZE / 8
    mov  rax, [rsp + CBE_PLAN + cbe_offset]
    mov  [r13 + cbe_offset], rax
%assign cbe_offset cbe_offset + 8
%endrep
    mov  rax, [r13 + CBO_STATUS]
    add  rsp, CBE_STACK
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
.full_control_unavailable:
%assign cbe_full_clear 8
%rep 4
    mov qword [rsp+CBE_PLAN+cbe_full_clear],0
%assign cbe_full_clear cbe_full_clear+8
%endrep
    mov qword [rsp+CBE_PLAN+CBO_STATUS],16
    jmp .publish
.bad_request:
    mov  qword [rsp + CBE_PLAN + CBO_STATUS], 11
    jmp  .publish
.bad_capture:
    mov  qword [rsp + CBE_PLAN + CBO_STATUS], CBP_BAD_CAPTURE
    jmp  .publish
.bad_buffer:
    mov  rax, -1
    ret

; Only these adapters are replaced in native host tests. Production always
; contains real instructions; no test macro, callback or external function.
cpu_boundary_read_cr4:
    mov  rax, cr4
    ret
cpu_boundary_rdmsr:
    rdmsr
    ret
cpu_boundary_wrmsr:
    wrmsr
    ret
cpu_boundary_verw:
    sub  rsp, 8
    mov  word [rsp], ds
    verw word [rsp]
    lfence
    add  rsp, 8
    ret
cpu_boundary_serialize:
    xor  eax, eax
    cpuid
    ret


; Paired temporary controls, RCQ42. Trusted in-image caller ONLY. No guest
; virtual-MSR/CPUID interface is advertised or granted by this primitive.
; Caller supplies mapped spans, DF=0, pins this CPU and excludes interrupts/NMI,
; migration and concurrent control/microcode/topology changes throughout each
; call. APIC identity/topology must stay stable across a live context.
; Between calls guest controls may vary; host floor updates MUST be passed
; to exit, especially when a new floor overlaps this context's temporary bits.
; Guest/host scheduling and placement remain VM-owned. APIC mode must already be
; initialized by SMP; full live APIC identity uses its existing xAPIC/x2APIC rail.
;
; Both APIs: RDI=request48, RSI=capacity, RDX=receipt96, RCX=capacity.
; Request u64 fields: version1/2/3, CURRENT host floor, required actions0..15,
; guest bits0..7 (enter only; exit must0), token (enter0; exit exact), reserved0.
; Version3 fixes floor4/actions9/guest0 and keeps both legacy host floors set;
; raw before/after receipt fields then contain LS_CFG, never SPEC_CTRL.
; Receipt u64 fields: status, retained host floor, installed owned bits,
; required exit floor, executed actions, token, full APIC ID, lifecycle,
; owned mask, introduced bits, live raw before write, live raw after write.
; lifecycle2 is entered; lifecycle3 is a completed exit. status0 is published
; LAST after writes/actions/serialization and private state publication.
; Receipt bytes and address MUST remain unchanged between enter and exit.
; No allocation:8 concurrent contexts, at most1 per CPU; global try-lock, no
; spin or preemption. Busy14 writes only non-success status; malformed geometry
; returns-1/no touch. Bad request11, invalid context13, capacity/generation15,
; native capture/identity16, changed capture17; executor refusals retain0..12.
; Extents cannot overlap each other, private registry or any OTHER active
; receipt. No pointed-to guest input, arbitrary register masks or callbacks.
;
; Private monotonically unique nonzero generation + exact pointer/all96 bytes
; reject forged/copied/stale/reused contexts. Tokens are NOT credentials; this
; is a trusted caller lifecycle, not an authentication service for guest data.
; A matched exit consumes the context BEFORE native sampling. Refusal/fault is
; non-success, retains a poisoned slot and never authorizes resume. No retry,
; reset, cancel or recovery grant after uncertain execution. Fault also leaves
; try-lock held: no subsequent apparent-success call. VM owns fail-stop recovery.
; Successful exit frees its slot but never reuses generation (overflow refuses).
;
; Entry's floor includes both fresh sampled owned bits AND live prewrite bits;
; only guest bits absent from that floor are marked introduced. Exit merges
; (LIVE & ~introduced) | saved_floor | current_floor. Fresh native mask/vendor/
; signature and bound request version must match; executor resamples and enforces
; original Intel/AMD v1, exact scoped AMD v2 or exact HP legacy v3
; action gates/order. No stale full-register restore, no clearing unowned/high
; bits; new live bits outside introduced survive. Interrupt/control exclusion
; is essential because another writer's same temporary bit is indistinguishable
; without the explicit current host floor. This is NOT a complete CPU policy.

CBC_REQUEST equ 48
CBC_SLOT_SIZE equ 176
CBC_SLOTS equ 8
CBC_FRAME equ CSS_SIZE + 32 + 32 + CBO_SIZE + 16 ; 288, calls aligned
CBC_EXECREQ equ CSS_SIZE
CBC_CAPTURE equ CSS_SIZE + 32
CBC_RESULT equ CSS_SIZE + 64
CBC_OP equ CSS_SIZE + 64 + CBO_SIZE
CBC_CPU equ CBC_OP + 8

cpu_boundary_context_enter:
    xor  r10d, r10d
    jmp  cpu_boundary_context_common
cpu_boundary_context_exit:
    mov  r10d, 1
cpu_boundary_context_common:
    cmp  rsi, CBC_REQUEST
    jb   .bad_buffer
    cmp  rcx, CBO_SIZE
    jb   .bad_buffer
    test rdi, rdi
    jz   .bad_buffer
    test rdx, rdx
    jz   .bad_buffer
    mov  r8, rdi
    add  r8, CBC_REQUEST
    jc   .bad_buffer
    mov  r9, rdx
    add  r9, CBO_SIZE
    jc   .bad_buffer
    cmp  r8, rdx
    jbe  .private_geometry
    cmp  r9, rdi
    ja   .bad_buffer
.private_geometry:
    lea  rax, [rel cbc_private_end]
    cmp  rdi, rax
    jae  .out_geometry
    lea  rax, [rel cbc_private]
    cmp  r8, rax
    ja   .bad_buffer
.out_geometry:
    lea  rax, [rel cbc_private_end]
    cmp  rdx, rax
    jae  .geometry_ready
    lea  rax, [rel cbc_private]
    cmp  r9, rax
    ja   .bad_buffer
.geometry_ready:
    lock bts qword [rel cbc_lock], 0
    jc   .busy
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, CBC_FRAME
    mov  r12, rdi
    mov  r13, rdx
    mov  [rsp + CBC_OP], r10
    xor  r14d, r14d                    ; matched/free slot
    lea  r15, [rel cbc_slots]
    mov  ebx, CBC_SLOTS
.scan_geometry:
    cmp  qword [r15], 0
    je   .next_geometry
    mov  rax, [r15 + 16]
    lea  rcx, [rax + CBO_SIZE]
    cmp  rdi, rcx
    jae  .receipt_geometry
    cmp  r8, rax
    ja   .locked_bad_buffer
.receipt_geometry:
    cmp  rdx, rcx
    jae  .next_geometry
    cmp  r9, rax
    jbe  .next_geometry
    cmp  qword [rsp + CBC_OP], 1
    jne  .locked_bad_buffer
    cmp  rdx, rax                       ; exit may use its exact own receipt
    jne  .locked_bad_buffer
    mov  r14, r15
.next_geometry:
    add  r15, CBC_SLOT_SIZE
    dec  ebx
    jnz  .scan_geometry
    cmp  qword [rsp + CBC_OP], 0
    je   .clear_output
    test r14, r14
    jz   .invalid_context
    cmp  qword [r14], 2
    jne  .invalid_context
    mov  rax, [r12 + 32]
    cmp  rax, [r14 + 24]
    jne  .invalid_context
%assign cbc_i 0
%rep CBO_SIZE / 8
    mov  rax, [r13 + cbc_i]
    cmp  rax, [r14 + 64 + cbc_i]
    jne  .invalid_context
%assign cbc_i cbc_i + 8
%endrep
    mov  qword [r14], 1                 ; consumed before ANY hardware access
.clear_output:
%assign cbc_i 0
%rep CBO_SIZE / 8
    mov  qword [r13 + cbc_i], 0
%assign cbc_i cbc_i + 8
%endrep
    mov  qword [r13], 12                ; fault/pending is NEVER success
    cmp  qword [r12], 6
    je   .version_ok
    cmp  qword [r12], 7
    je   .version_ok
    cmp  qword [r12], 1
    je   .version_ok
    cmp  qword [r12], 2
    je   .version_ok
    cmp  qword [r12], 4
    je   .version_ok
    cmp  qword [r12], 3
    jne  .bad_request
    cmp  qword [r12 + 8], 4
    jne  .bad_request
    cmp  qword [r12 + 16], 9
    jne  .bad_request
    cmp  qword [r12 + 24], 0
    jne  .bad_request
.version_ok:
    cmp  qword [r12 + 40], 0
    jne  .bad_request
    test qword [r12 + 8], ~7
    jnz  .bad_request
    mov  eax,15
    cmp  qword [r12],6
    jne  .action_mask
    mov  eax,127
.action_mask:
    not  rax
    test [r12 + 16],rax
    jnz  .bad_request
    test qword [r12 + 24], ~7
    jnz  .bad_request
    cmp  qword [rsp + CBC_OP], 0
    je   .entry_request
    cmp  qword [r12 + 24], 0
    jne  .bad_request
    mov  rax, [r12]
    cmp  rax, [r14 + 160]
    jne  .changed_capture
    jmp  .sample
.entry_request:
    cmp  qword [r12 + 32], 0
    jne  .bad_request
.sample:
    mov  rdi, rsp
    mov  esi, CSS_SIZE
    call cpu_security_sample
    test rax, rax
    jnz  .bad_capture
    cmp  dword [rsp + CSS_HV], 0
    jne  .bad_capture
    cmp  dword [rsp + CSS_MAX], 1
    jb   .bad_capture
    bt   dword [rsp + CSS_EDX1], 5
    jnc  .bad_capture
    mov  eax, [rsp + CSS_VENDOR]
    sub  eax, 1
    cmp  eax, 1
    ja   .bad_capture
    cmp  qword [r12], 7
    je   .full_amd_sample
    cmp  qword [r12], 6
    jne  .legacy_vendor
    cmp  dword [rsp + CSS_VENDOR],1
    jne  .bad_capture
.legacy_vendor:
    cmp  qword [r12], 4
    je   .srso_sample
    cmp  qword [r12], 3
    je   .hp_sample
    cmp  qword [r12], 2
    jne  .sample_ready
    mov  rdi, rsp
    call cpu_boundary_amd_v2_sample
    jmp  .sample_status
.full_amd_sample:
    mov  rdi,rsp
    call cpu_boundary_amd_full_sample
    jmp  .sample_status
.srso_sample:
    mov  rdi, rsp
    call cpu_boundary_amd_v4_sample
    jmp  .sample_status
.hp_sample:
    mov  rdi, rsp
    call cpu_boundary_hp_sample
.sample_status:
    test eax, eax
    jnz  .bad_capture
.sample_ready:
    mov  rax, [rsp + CSS_MASK]
    mov  rdx, [r12 + 8]
    or   rdx, [r12 + 24]
    not  rax
    test rdx, rax
    jnz  .bad_capture
    call cpu_boundary_context_cpu
    mov  eax, eax                       ; full APIC ID, no 8-bit alias
    mov  [rsp + CBC_CPU], rax
    cmp  qword [rsp + CBC_OP], 0
    jne  .exit_capture
    lea  r15, [rel cbc_slots]
    xor  r14d, r14d
    mov  ebx, CBC_SLOTS
.scan_slot:
    cmp  qword [r15], 0
    jne  .occupied
    test r14, r14
    cmovz r14, r15
    jmp  .next_slot
.occupied:
    cmp  rax, [r15 + 8]
    je   .invalid_context               ; no nested entry on this CPU
.next_slot:
    add  r15, CBC_SLOT_SIZE
    dec  ebx
    jnz  .scan_slot
    test r14, r14
    jz   .exhausted
    mov  rax, [rel cbc_generation]
    cmp  rax, -1
    je   .exhausted
    inc  rax
    mov  [rel cbc_generation], rax
    mov  [r14 + 24], rax
    mov  qword [r14], 1
    mov  rax, [rsp + CBC_CPU]
    mov  [r14 + 8], rax
    mov  [r14 + 16], r13
    mov  rax, [r12]
    mov  [r14 + 160], rax
    mov  eax, [rsp + CSS_VENDOR]
    mov  edx, [rsp + CSS_SIG]
    shl  rdx, 32
    or   rax, rdx
    mov  [r14 + 32], rax
    mov  rax, [rsp + CSS_MASK]
    mov  [r14 + 40], rax
    mov  rax, [r12 + 8]
    or   rax, [rsp + CSS_CTRL]
    mov  [r14 + 48], rax
    xor  r15d, r15d                    ; entry never clears
    or   rax, [r12 + 24]
    jmp  .execute
.exit_capture:
    cmp  rax, [r14 + 8]
    jne  .invalid_context
    mov  eax, [rsp + CSS_VENDOR]
    mov  edx, [rsp + CSS_SIG]
    shl  rdx, 32
    or   rax, rdx
    cmp  rax, [r14 + 32]
    jne  .changed_capture
    mov  rax, [rsp + CSS_MASK]
    cmp  rax, [r14 + 40]
    jne  .changed_capture
    mov  rax, [r12 + 8]
    or   rax, [r14 + 48]                 ; exit cannot lower saved host floor
    mov  r15, [r14 + 56]
.execute:
    mov  rdx, [r12]
    mov  qword [rsp + CBC_EXECREQ], rdx
    mov  [rsp + CBC_EXECREQ + 8], rax
    mov  rax, [r12 + 16]
    mov  [rsp + CBC_EXECREQ + 16], rax
    mov  qword [rsp + CBC_EXECREQ + 24], 0
%assign cbc_i 0
%rep 4
    mov  qword [rsp + CBC_CAPTURE + cbc_i*8], 0
%assign cbc_i cbc_i + 1
%endrep
    lea  rdi, [rsp + CBC_EXECREQ]
    mov  esi, CBE_REQUEST_SIZE
    lea  rdx, [rsp + CBC_RESULT]
    mov  ecx, CBO_SIZE
    lea  r10, [rsp + CBC_CAPTURE]
    mov  r11, r15
    call cpu_boundary_execute_common
    test rax, rax
    jnz  .status                        ; pending slot, no usable return grant
    mov  rax, [rsp + CBC_CAPTURE + 24]
    cmp  rax, [r14 + 40]
    jne  .changed_capture
    cmp  qword [rsp + CBC_OP], 0
    jne  .exit_done
    mov  rax, [rsp + CBC_CAPTURE]
    cmp  qword [r12], 3
    jne  .baseline_normalized
    shr  rax, 8                        ; raw LS_CFG10 -> normalized SSBD4
.baseline_normalized:
    and  rax, [r14 + 40]
    or   rax, [rsp + CBC_CAPTURE + 16]
    or   rax, [r14 + 48]
    mov  [r14 + 48], rax                 ; actual live baseline, not guest
    not  rax
    and  rax, [r12 + 24]
    mov  [r14 + 56], rax
    mov  qword [r13 + 56], 2
    jmp  .receipt
.exit_done:
    mov  qword [r13 + 56], 3
.receipt:
    mov  rax, [r14 + 48]
    or   rax, [r12 + 8]
    mov  [r13 + 8], rax
    mov  [r13 + 24], rax
    mov  rdx, [rsp + CBC_CAPTURE + 8]
    cmp  qword [r12], 3
    jne  .after_normalized
    shr  rdx, 8
.after_normalized:
    and  rdx, [r14 + 40]
    mov  [r13 + 16], rdx
    mov  rax, [r12 + 16]
    mov  [r13 + 32], rax
    mov  rax, [r14 + 24]
    mov  [r13 + 40], rax
    mov  rax, [r14 + 8]
    mov  [r13 + 48], rax
    mov  rax, [r14 + 40]
    mov  [r13 + 64], rax
    mov  rax, [r14 + 56]
    mov  [r13 + 72], rax
    mov  rax, [rsp + CBC_CAPTURE]
    mov  [r13 + 80], rax
    mov  rax, [rsp + CBC_CAPTURE + 8]
    mov  [r13 + 88], rax
    cmp  qword [rsp + CBC_OP], 0
    jne  .release_slot
    mov  qword [r14 + 64], 0
%assign cbc_i 8
%rep CBO_SIZE / 8 - 1
    mov  rax, [r13 + cbc_i]
    mov  [r14 + 64 + cbc_i], rax
%assign cbc_i cbc_i + 8
%endrep
    mov  qword [r14], 2
    jmp  .success
.release_slot:
    mov  qword [r14], 0
.success:
    xor  eax, eax
    jmp  .status
.bad_request:
    mov  eax, 11
    jmp  .status
.invalid_context:
    mov  eax, 13
    jmp  .refuse
.bad_capture:
    mov  eax, 16
    jmp  .status
.changed_capture:
    mov  eax, 17
    jmp  .status
.exhausted:
    mov  eax, 15
    jmp  .status
.refuse:
%assign cbc_i 0
%rep CBO_SIZE / 8
    mov  qword [r13 + cbc_i], 0
%assign cbc_i cbc_i + 8
%endrep
.status:
    mov  [r13], rax                    ; success only AFTER complete execution
    mov  qword [rel cbc_lock], 0
.out:
    add  rsp, CBC_FRAME
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
.locked_bad_buffer:
    mov  qword [rel cbc_lock], 0
    mov  rax, -1
    jmp  .out
.busy:
    mov  qword [rdx], 14
    mov  eax, 14
    ret
.bad_buffer:
    mov  rax, -1
    ret

; v2 ONLY. Fresh native raw sample has already completed. Do not change CSS112
; producer/decoder or any v1 caller. Same exact vendor/CPU/patch predicate as
; selector; new SSBD and patched VERW capability is local to this execution.
; Existing raw exception contract is retained: a fault never returns through a
; success fixup. Caller holds CPU/control/microcode and nonresuming guard custody.
; No latch write, VIRT_SPEC_CTRL, LS_CFG, PRED_CMD read or control fallback.
cpu_boundary_amd_v2_sample:
    push rbx
    push r12
    sub  rsp, 8
    mov  r12, rdi
    cmp  dword [r12 + CSS_VENDOR], 2
    jne  .unknown
    cmp  dword [r12 + CSS_HV], 0
    jne  .unknown
    cmp  dword [r12 + CSS_MAX], 1
    jb   .unknown
    bt   dword [r12 + CSS_EDX1], 5
    jnc  .unknown
    cmp  dword [r12 + CSS_EXTMAX], 0x80000008
    jb   .unknown
    bt   dword [r12 + CSS_EBX8], 24
    jnc  .unknown
    xor  esi, esi
    xor  edx, edx
    cmp  dword [r12 + CSS_EXTMAX], 0x80000021
    jb   .scope
    mov  eax, 0x80000021
    xor  ecx, ecx
    call cpu_security_cpuid
    mov  edx, eax
    mov  esi, 1
.scope:
    mov  rdi, r12
    call cpu_boundary_amd_scope
    test eax, eax
    jnz  .out
    or   qword [r12 + CSS_CAPS], CS_CAP_SSBD | CS_CAP_MD_CLEAR
    or   qword [r12 + CSS_MASK], 4
    mov  ecx, 0x48
    call cpu_security_rdmsr
    shl  rdx, 32
    or   rax, rdx
    and  rax, [r12 + CSS_MASK]
    mov  [r12 + CSS_CTRL], rax
    mov  dword [r12 + CSS_CTRL_VALID], 1
    xor  eax, eax
    jmp  .out
.unknown:
    mov  eax, 4
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; v4 only: a private fresh checked capture/CIO. No supplied capture/probe bit
; is accepted by the executor. Serialization and IF0/IDT/private-stack custody
; are held by the existing trusted caller through both actual boundary edges.
; 1216 additional mapped stack bytes; no allocation/global observation cache.
cpu_boundary_amd_v4_sample:
    push rbx
    push r12
    push r13
    sub  rsp, 1216                      ; CAS160 + CIO1056, calls aligned
    mov  r12, rdi
    call cpu_boundary_context_cpu
    cmp  eax, -1
    je   .unknown
    mov  r13d, eax
    lea  rdi, [rsp + 160]
    mov  esi, r13d
    call cpu_checked_io_init
    mov  rdi, rsp
    mov  esi, 160
    lea  rdx, [rsp + 160]
    call cpu_security_amd_srso_sample_checked
    test rax, rax
    jnz  .unknown
    cmp  dword [rsp + 112], 2
    jne  .unknown
    cmp  dword [rsp + 116], 0
    jne  .unknown
    cmp  dword [rsp + 128], 1
    jne  .unknown
    cmp  dword [rsp + 132], 1
    jne  .unknown
    cmp  r13d, [rsp + 120]
    jne  .unknown
    cmp  r13d, [rsp + 124]
    jne  .unknown
    bt   dword [rsp + CSS_EBX8], 24
    jnc  .unknown
    mov  rdi, rsp
    mov  esi, [rsp + 136]
    mov  edx, [rsp + 140]
    mov  r8d, [rsp + 156]
    call cpu_boundary_amd_srso_scope
    test eax, eax
    jnz  .out
    mov  rdi, r12
    mov  rsi, rsp
    mov  ecx, CSS_SIZE / 8
    rep  movsq
    or   qword [r12 + CSS_CAPS], CS_CAP_SSBD | CS_CAP_MD_CLEAR
    or   qword [r12 + CSS_MASK], 4
    mov  ecx, 0x48
    call cpu_security_rdmsr              ; existing nonresuming raw-read contract
    shl  rdx, 32
    or   rax, rdx
    and  rax, [r12 + CSS_MASK]
    mov  [r12 + CSS_CTRL], rax
    mov  dword [r12 + CSS_CTRL_VALID], 1
    xor  eax, eax
    jmp  .out
.unknown:
    mov  eax, 4
.out:
    add  rsp, 1216
    pop  r13
    pop  r12
    pop  rbx
    ret

; v3 only: actual raw native sampler completed. Exact HP predicate excludes
; SPEC_CTRL/VIRT variants before this nonarchitectural family17 LS_CFG read.
; Internal normalized CSS fields never escape as a checked160 CPU capture.
cpu_boundary_hp_sample:
    push r12
    mov  r12, rdi
    call cpu_boundary_hp_scope
    test eax, eax
    jnz  .out
    mov  ecx, 0xC0011020
    call cpu_boundary_rdmsr
    shr  eax, 8
    and  eax, 4
    mov  [r12 + CSS_CTRL], rax
    mov  qword [r12 + CSS_MASK], 4
    mov  qword [r12 + CSS_CAPS], CS_CAP_IBPB | CS_CAP_SSBD
    mov  dword [r12 + CSS_CTRL_VALID], 1
    xor  eax, eax
.out:
    pop  r12
    ret

; Only hardware identity adapter; same canonical full-APIC native rail as SMP.
cpu_boundary_context_cpu:
    jmp  smp_lapic_read_id

%include "core/abi/wdata.inc"
%macro WDATA_BSS_sec_cpu_boundary_context 0
alignb 8
cbc_private:
cbc_lock: resq 1
cbc_generation: resq 1
cbc_slots: resb CBC_SLOT_SIZE * CBC_SLOTS
cbc_private_end:
%endmacro
WDATA_BSS_DEFER WDATA_BSS_sec_cpu_boundary_context

section .text
; Version7 native AMD. Only reported SPEC_CTRL permission is expanded. VERW
; instruction availability is distinct from proved updated clearing semantics.
; A vendor row or architectural VERW_CLEAR supplies the latter local fact.
cpu_boundary_amd_full_sample:
    push rbx
    push r12
    push r13
    mov r12,rdi
    cmp dword [r12+CSS_VENDOR],2
    jne .bad
    cmp dword [r12+CSS_HV],0
    jne .bad
    xor r13d,r13d
    cmp dword [r12+CSS_EXTMAX],0x80000008
    jb .ready
    cmp dword [r12+CSS_EXTMAX],0x80000021
    jb .scope_absent
    mov eax,0x80000021
    xor ecx,ecx
    call cpu_security_cpuid
    mov r13d,ecx
    mov edx,eax
    mov esi,1
    jmp .scope
.scope_absent:
    xor esi,esi
    xor edx,edx
.scope:
    mov rdi,r12
    call cpu_boundary_amd_scope
    test eax,eax
    jz .verw_known
    test r13d,1<<5
    jz .ssbd
.verw_known:
    or qword [r12+CSS_CAPS],CS_CAP_MD_CLEAR
.ssbd:
    bt dword [r12+CSS_EBX8],24
    jnc .ready
    or qword [r12+CSS_CAPS],CS_CAP_SSBD
    or qword [r12+CSS_MASK],4
    mov ecx,0x48
    call cpu_security_rdmsr
    shl rdx,32
    or rax,rdx
    and rax,[r12+CSS_MASK]
    mov [r12+CSS_CTRL],rax
    mov dword [r12+CSS_CTRL_VALID],1
.ready:
    xor eax,eax
    jmp .out
.bad:
    mov eax,4
.out:
    pop r13
    pop r12
    pop rbx
    ret
