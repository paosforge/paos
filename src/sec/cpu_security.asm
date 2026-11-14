;; MODULE sec/cpu_security
;; LAYER 2
;; EXPORTS cpu_security_sample, cpu_security_decode, cpu_security_text, cpu_security_snapshot_text, cpu_security_enumerate
;; IMPORTS core/lib/fmt
;; CAPS
;; OWNER saga:security
; RCQ-42 first slice: calling logical CPU observation, NOT an all-CPU policy.
; No control write, microcode load, guest/privilege boundary or immunity claim.
; Only Intel BIOS_SIGN_ID is cleared to latch its revision; that is NOT an
; update trigger. Unknown vendors/hypervisors never reach an MSR instruction.
; Every sample reevaluates CPUID: loading microcode can change enumeration.
;
; Primary facts (retrieved 2026-10-15): Intel "CPUID Enumeration and
; Architectural MSRs" ID758381 v7, and "Minimum Runtime Microcode Update
; Revision" (zero 8Bh, CPUID1, read high dword). AMD publication111006,
; "AMD64 Technology Indirect Branch Control Extension": 80000008h EBX
; bits12=IBPB,14=IBRS,15=STIBP. AMD SSBD variants are deliberately not inferred.
; AMD patch-level read is limited to the existing idle-probe17h/19h families.
; A revision is an observed number, never proof of freshness or signature.

CSS_VENDOR equ 0                        ; 0 unknown,1 Intel,2 AMD
CSS_HV equ 4
CSS_SIG equ 8
CSS_EDX1 equ 12
CSS_MAX equ 16
CSS_EXTMAX equ 20
CSS_EDX7 equ 24
CSS_EBX8 equ 28
CSS_ARCH_VALID equ 32
CSS_CTRL_VALID equ 36
CSS_REV_VALID equ 40
CSS_COST_VALID equ 44
CSS_ARCH equ 48
CSS_CTRL equ 56
CSS_REV equ 64
CSS_CAPS equ 72                         ; CS_CAP_* enumeration, not enabled state
CSS_MASK equ 80                         ; supported SPEC_CTRL bits0..2 only
CSS_COST equ 88                         ; TSC ticks after initial CPUID1
CSS_EDX72 equ 96
CSS_MAX7 equ 100
CSS_SIZE equ 112

CS_CAP_IBRS equ 1
CS_CAP_IBPB equ 2
CS_CAP_STIBP equ 4
CS_CAP_SSBD equ 8
CS_CAP_MD_CLEAR equ 16
CS_CAP_L1D equ 32
CS_CAP_ARCH equ 64
CS_CAP_BHI equ 128

; RDI caller-owned CSS_SIZE bytes, ESI capacity; RAX0 or -1 (no touch).
; Serialized calling CPU; no allocation/global sample, AP dispatch or cache.
cpu_security_sample:
    push r15
    sub  rsp, 8                         ; retain call alignment in shared body
    xor  r15d, r15d
    jmp  cpu_security_sample_mode

; Same CSS/capacity ABI, CPUID/clock only, all MSR validity remains zero.
; Used to reject unknown/HV/no-MSR contexts before even APIC identity MSRs.
cpu_security_enumerate:
    push r15
    sub  rsp, 8
    mov  r15d, 1
cpu_security_sample_mode:
    cmp  esi, CSS_SIZE
    jb   .bad
    push rbx
    push r12
    push r13
    mov  r12, rdi
    xor  eax, eax
    mov  ecx, CSS_SIZE / 8
    rep  stosq
    xor  eax, eax
    xor  ecx, ecx
    call cpu_security_cpuid
    mov  [r12 + CSS_MAX], eax
    cmp  ebx, 0x756e6547                 ; GenuineIntel, all twelve bytes
    jne  .amd
    cmp  edx, 0x49656e69
    jne  .leaf1
    cmp  ecx, 0x6c65746e
    jne  .leaf1
    mov  dword [r12 + CSS_VENDOR], 1
    jmp  .leaf1
.amd:
    cmp  ebx, 0x68747541                 ; AuthenticAMD
    jne  .leaf1
    cmp  edx, 0x69746e65
    jne  .leaf1
    cmp  ecx, 0x444d4163
    jne  .leaf1
    mov  dword [r12 + CSS_VENDOR], 2
.leaf1:
    cmp  dword [r12 + CSS_MAX], 1
    jb   .finish
    mov  eax, 1
    xor  ecx, ecx
    call cpu_security_cpuid
    mov  [r12 + CSS_SIG], eax
    mov  [r12 + CSS_EDX1], edx
    shr  ecx, 31
    mov  [r12 + CSS_HV], ecx
    bt   edx, 4                          ; RDTSC enumeration, independently of MSR
    jnc  .leaf7
    call cpu_security_clock
    mov  r13, rax
    mov  dword [r12 + CSS_COST_VALID], 1
.leaf7:
    cmp  dword [r12 + CSS_MAX], 7
    jb   .extended
    mov  eax, 7
    xor  ecx, ecx
    call cpu_security_cpuid
    mov  [r12 + CSS_EDX7], edx
    mov  [r12 + CSS_MAX7], eax
    cmp  eax, 2
    jb   .extended
    mov  eax, 7
    mov  ecx, 2
    call cpu_security_cpuid
    mov  [r12 + CSS_EDX72], edx
.extended:
    cmp  dword [r12 + CSS_VENDOR], 2
    jne  .decoded
    mov  eax, 0x80000000
    xor  ecx, ecx
    call cpu_security_cpuid
    mov  [r12 + CSS_EXTMAX], eax
    cmp  eax, 0x80000008
    jb   .decoded
    mov  eax, 0x80000008
    xor  ecx, ecx
    call cpu_security_cpuid
    mov  [r12 + CSS_EBX8], ebx
.decoded:
    mov  rdi, r12
    call cpu_security_decode
    test r15d, r15d
    jnz  .finish                        ; enumeration never enters an MSR path
    cmp  dword [r12 + CSS_HV], 0
    jne  .finish                        ; virtual capabilities are not MSR permission
    bt   dword [r12 + CSS_EDX1], 5
    jnc  .finish
    cmp  dword [r12 + CSS_VENDOR], 1
    jne  .amd_revision
    test qword [r12 + CSS_CAPS], CS_CAP_ARCH
    jz   .intel_revision
    mov  ecx, 0x10A
    call cpu_security_rdmsr
    shl  rdx, 32
    or   rax, rdx
    mov  [r12 + CSS_ARCH], rax
    mov  dword [r12 + CSS_ARCH_VALID], 1
.intel_revision:
    mov  eax, [r12 + CSS_SIG]
    shr  eax, 8
    and  eax, 15
    cmp  eax, 6                          ; supported Intel revision-read family
    jne  .controls
    mov  ecx, 0x8B
    xor  eax, eax
    xor  edx, edx
    call cpu_security_revision_clear     ; latch reset only, never MSR79h
    mov  eax, 1
    xor  ecx, ecx
    call cpu_security_cpuid
    mov  ecx, 0x8B
    call cpu_security_rdmsr
    mov  [r12 + CSS_REV], edx
    mov  dword [r12 + CSS_REV_VALID], 1
    jmp  .controls
.amd_revision:
    cmp  dword [r12 + CSS_VENDOR], 2
    jne  .finish
    mov  eax, [r12 + CSS_SIG]
    mov  edx, eax
    shr  eax, 8
    and  eax, 15
    cmp  eax, 15
    jne  .controls
    shr  edx, 20
    and  edx, 255
    add  eax, edx
    cmp  eax, 0x17
    je   .amd_read
    cmp  eax, 0x19
    jne  .controls
.amd_read:
    mov  ecx, 0x8B
    call cpu_security_rdmsr
    mov  [r12 + CSS_REV], eax
    mov  dword [r12 + CSS_REV_VALID], 1
.controls:
    cmp  qword [r12 + CSS_MASK], 0
    je   .finish
    mov  ecx, 0x48
    call cpu_security_rdmsr
    shl  rdx, 32
    or   rax, rdx
    and  rax, [r12 + CSS_MASK]            ; only observed supported bits; raw not exported
    mov  [r12 + CSS_CTRL], rax
    mov  dword [r12 + CSS_CTRL_VALID], 1
.finish:
    cmp  dword [r12 + CSS_COST_VALID], 1
    jne  .ok
    call cpu_security_clock
    sub  rax, r13
    jc   .clock_regressed
    mov  [r12 + CSS_COST], rax
    jmp  .ok
.clock_regressed:
    mov  dword [r12 + CSS_COST_VALID], 0
.ok:
    xor  eax, eax
    pop  r13
    pop  r12
    pop  rbx
    add  rsp, 8
    pop  r15
    ret
.bad:
    mov  rax, -1
    add  rsp, 8
    pop  r15
    ret

; Pure enumeration decoder over the sampled raw fields. No immunity decision.
cpu_security_decode:
    xor  eax, eax
    xor  edx, edx
    cmp  dword [rdi + CSS_MAX], 1
    jb   .done
    cmp  dword [rdi + CSS_VENDOR], 1
    jne  .amd
    cmp  dword [rdi + CSS_MAX], 7
    jb   .done
    mov  ecx, [rdi + CSS_EDX7]
    bt   ecx, 26
    jnc  .stibp
    or   eax, CS_CAP_IBRS | CS_CAP_IBPB
    or   edx, 1
.stibp:
    bt   ecx, 27
    jnc  .ssbd
    or   eax, CS_CAP_STIBP
    or   edx, 2
.ssbd:
    bt   ecx, 31
    jnc  .md_clear
    or   eax, CS_CAP_SSBD
    or   edx, 4
.md_clear:
    bt   ecx, 10
    jnc  .l1d
    or   eax, CS_CAP_MD_CLEAR
.l1d:
    bt   ecx, 28
    jnc  .arch
    or   eax, CS_CAP_L1D
.arch:
    bt   ecx, 29
    jnc  .bhi
    or   eax, CS_CAP_ARCH
.bhi:
    cmp  dword [rdi + CSS_MAX7], 2
    jb   .done
    bt   dword [rdi + CSS_EDX72], 4
    jnc  .done
    or   eax, CS_CAP_BHI
    jmp  .done
.amd:
    cmp  dword [rdi + CSS_VENDOR], 2
    jne  .done
    cmp  dword [rdi + CSS_EXTMAX], 0x80000008
    jb   .done
    mov  ecx, [rdi + CSS_EBX8]
    bt   ecx, 12
    jnc  .amd_ibrs
    or   eax, CS_CAP_IBPB
.amd_ibrs:
    bt   ecx, 14
    jnc  .amd_stibp
    or   eax, CS_CAP_IBRS
    or   edx, 1
.amd_stibp:
    bt   ecx, 15
    jnc  .done
    or   eax, CS_CAP_STIBP
    or   edx, 2
.done:
    mov  [rdi + CSS_CAPS], rax
    mov  [rdi + CSS_MASK], rdx
    ret

; Hardware adapters: tests replace only these bodies, never the sampler.
cpu_security_cpuid:
    cpuid
    ret
cpu_security_rdmsr:
    rdmsr
    ret
cpu_security_revision_clear:
    wrmsr
    ret
cpu_security_clock:
    lfence
    rdtsc
    lfence
    shl  rdx, 32
    or   rax, rdx
    ret

; RDI destination, ESI capacity, EDX0 full or nonzero compact. Returns length
; or -1; insufficient space clears the first byte (no misleading partial row).
; Current serialized BSP AUDIT/GUI consumers own distinct staging buffers.
cpu_security_text:
    xor  ecx, ecx                       ; retained raw sampler/text ABI
    jmp  cpu_security_text_entry

; Same output ABI, RCX points to a complete caller-owned CSS_SIZE snapshot.
; Pure formatting/copy: no CPUID/MSR, permission or validity promotion here.
; The checked live producer uses this after restoring the caller's interrupt
; state. The original raw entry above remains available to existing callers.
cpu_security_snapshot_text:
    test rcx, rcx
    jnz  cpu_security_text_entry
    mov  rax, -1
    ret

cpu_security_text_entry:
    test esi, esi
    jz   .bad_empty
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, CSS_SIZE + 24
    mov  rbx, rdi
    mov  r12, rdi
    mov  r13d, esi
    add  r13, rdi
    dec  r13                            ; final byte reserved for NUL
    mov  r14d, edx
    test rcx, rcx
    jz   .raw_sample
    mov  rsi, rcx
    mov  rdi, rsp
    mov  ecx, CSS_SIZE / 8
    rep  movsq
    jmp  .format
.raw_sample:
    mov  rdi, rsp
    mov  esi, CSS_SIZE
    call cpu_security_sample
.format:
    lea  rsi, [rel cs_text_header]
    call cpu_security_text_put
    test r14d, r14d
    jnz  .compact
    lea  r15, [rel cs_full_fields]
    mov  ebp, 7
    call cpu_security_text_fields
    call cpu_security_text_controls
.compact:
    lea  r15, [rel cs_common_fields]
    mov  ebp, 6
    call cpu_security_text_fields
    mov  byte [r12], 0
    cmp  r14d, -1                       ; sticky overflow, no partial snapshot
    je   .bad
    mov  rax, r12
    sub  rax, rbx
    jmp  .out
.bad:
    mov  byte [rbx], 0
    mov  rax, -1
.out:
    add  rsp, CSS_SIZE + 24
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret
.bad_empty:
    mov  rax, -1
    ret

; Field table entries are numeric offsets, never absolute link-time pointers.
cpu_security_text_fields:
    test ebp, ebp
    jz   .out
.field:
    mov  eax, [r15]
    lea  rsi, [rel cs_names]
    add  rsi, rax
    call cpu_security_text_put
    mov  eax, [r15 + 4]
    ; Explicit field widths prevent an adjacent dword from entering a value.
    mov  edi, [rsp + rax + 8]            ; return address above caller's snapshot
    cmp  dword [r15 + 8], 8
    jne  .number
    mov  rdi, [rsp + rax + 8]
.number:
    lea  rsi, [rsp + CSS_SIZE + 8]
    call fmt_dec
    lea  rsi, [rsp + CSS_SIZE + 8]
    call cpu_security_text_put
    add  r15, 12
    dec  ebp
    jnz  .field
.out:
    ret

; Full view only: name the three captured SPEC_CTRL bits. Reuse the caller's
; one snapshot, never sample again or infer an instruction/boundary action.
; Not enumerated means absent from our supported decoder, not CPU immunity.
; Unknown vendor/HV or missing control-read validity cannot become observed off.
cpu_security_text_controls:
    lea  r15, [rel cs_control_fields]
    mov  ebp, 3
.field:
    mov  eax, [r15]
    lea  rsi, [rel cs_names]
    add  rsi, rax
    call cpu_security_text_put
    lea  rsi, [rel cs_control_unknown]
    mov  eax, [rsp + 8 + CSS_VENDOR]    ; helper return above caller's snapshot
    sub  eax, 1
    cmp  eax, 1
    ja   .put
    cmp  dword [rsp + 8 + CSS_HV], 0
    jne  .put
    mov  edx, [r15 + 4]
    lea  rsi, [rel cs_control_not_enum]
    test [rsp + 8 + CSS_MASK], rdx
    jz   .put
    lea  rsi, [rel cs_control_unknown]
    cmp  dword [rsp + 8 + CSS_CTRL_VALID], 1
    jne  .put
    lea  rsi, [rel cs_control_off]
    test [rsp + 8 + CSS_CTRL], rdx
    jz   .put
    lea  rsi, [rel cs_control_on]
.put:
    call cpu_security_text_put
    add  r15, 8
    dec  ebp
    jnz  .field
    ret

cpu_security_text_put:
    movzx eax, byte [rsi]
    test eax, eax
    jz   .out
    cmp  r12, r13
    jae  .full
    mov  [r12], al
    inc  r12
    inc  rsi
    jmp  cpu_security_text_put
.full:
    mov  r14d, -1
.out:
    ret

cs_text_header: db " cpu_security=incomplete scope=calling_cpu policy=pending",0
cs_names:
cs_n_vendor: db " vendor=",0
cs_n_hv: db " hv=",0
cs_n_caps: db " caps=",0
cs_n_mask: db " ctrl_mask=",0
cs_n_archvalid: db " arch_valid=",0
cs_n_arch: db " arch=",0
cs_n_sig: db " sig=",0
cs_n_revvalid: db " rev_valid=",0
cs_n_rev: db " rev=",0
cs_n_ctrlvalid: db " ctrl_valid=",0
cs_n_ctrl: db " ctrl=",0
cs_n_costvalid: db " cost_valid=",0
cs_n_cost: db " sample_tsc=",0
cs_n_ibrs: db " spec_ibrs=",0
cs_n_stibp: db " spec_stibp=",0
cs_n_ssbd: db " spec_ssbd=",0
cs_control_on: db "on",0
cs_control_off: db "off",0
cs_control_not_enum: db "not_enumerated",0
cs_control_unknown: db "unknown",0
align 4
cs_control_fields:
    dd cs_n_ibrs-cs_names,1
    dd cs_n_stibp-cs_names,2
    dd cs_n_ssbd-cs_names,4
cs_full_fields:
    dd cs_n_vendor-cs_names,CSS_VENDOR,4
    dd cs_n_hv-cs_names,CSS_HV,4
    dd cs_n_caps-cs_names,CSS_CAPS,8
    dd cs_n_mask-cs_names,CSS_MASK,8
    dd cs_n_archvalid-cs_names,CSS_ARCH_VALID,4
    dd cs_n_arch-cs_names,CSS_ARCH,8
    dd cs_n_sig-cs_names,CSS_SIG,4
cs_common_fields:
    dd cs_n_revvalid-cs_names,CSS_REV_VALID,4
    dd cs_n_rev-cs_names,CSS_REV,8
    dd cs_n_ctrlvalid-cs_names,CSS_CTRL_VALID,4
    dd cs_n_ctrl-cs_names,CSS_CTRL,8
    dd cs_n_costvalid-cs_names,CSS_COST_VALID,4
    dd cs_n_cost-cs_names,CSS_COST,8
