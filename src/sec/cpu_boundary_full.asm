;; MODULE sec/cpu_boundary_full
;; LAYER 2
;; EXPORTS cpu_boundary_policy_select_full_intel, cpu_boundary_policy_select_full_amd
;; IMPORTS sec/cpu_intel_checked, sec/cpu_boundary_selector
;; CAPS
;; OWNER saga:security
; Spec073 full default. See gauntlet_v2/docs/cpu_boundary_full_default.md.
; Intel CIP232/version6 and AMD checked200/version7; otherwise unchanged tails.
; CBO96: desired56/64/72 NEVER shrink for missing mechanisms. Executable8/16/24
; use enumerated MSRs and legal software instructions. Status0 can retain
; unavailable/unproven diagnostics32/40/48: it is NOT an efficacy certificate.
; Invalid captures and missing actual core custody remain invalid operations.
; This pure function does not sample/write/execute or start a guest.

cpu_boundary_policy_select_full_intel:
    mov r8d,232
    mov r9d,192
    mov r10d,6
    jmp cpu_boundary_full_select
cpu_boundary_policy_select_full_amd:
    mov r8d,200
    mov r9d,160
    mov r10d,7
cpu_boundary_full_select:
    cmp rsi,r8
    jb .bad_buffer
    cmp rcx,96
    jb .bad_buffer
    test rdi,rdi
    jz .bad_buffer
    test rdx,rdx
    jz .bad_buffer
    mov rax,rdi
    add rax,r8
    jc .bad_buffer
    mov r11,rdx
    add r11,96
    jc .bad_buffer
    cmp rax,rdx
    jbe .disjoint
    cmp r11,rdi
    ja .bad_buffer
.disjoint:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,240
    mov r12,rdi
    mov r13,rdx
    mov r15d,r10d
    xor ecx,ecx
.copy:
    mov rax,[r12+rcx]
    mov [rsp+rcx],rax
    add ecx,8
    cmp rcx,r8
    jb .copy
%assign full_o 0
%rep 12
    mov qword [r13+full_o],0
%assign full_o full_o+8
%endrep
    cmp [r12+r9],r10
    jne .bad_capture
    cmp dword [r12+CSS_REV_VALID],1
    ja .bad_capture
    cmp dword [r12+CSS_REV+4],0
    jne .bad_capture
    cmp dword [r12+CSS_REV_VALID],0
    jne .revision_ready
    cmp qword [r12+CSS_REV],0
    jne .bad_capture
.revision_ready:
    ; State3 is the new full-only native guarded parking grant. Keep its
    ; architectural UNKNOWN/shared diagnosis, never coerce it to exclusive1.
    mov rax,[r12+r9+16]
    cmp rax,3
    ja .bad_capture
    jne .core_ready
    mov qword [rsp+r9+16],2
.core_ready:
    mov rdi,rsp
    mov rdx,r13
    mov ecx,96
    cmp r15d,7
    je .amd_validate
    mov qword [rsp+192],5
    mov esi,232
    call cpu_boundary_policy_select_intel
    jmp .validated
.amd_validate:
    ; Checked capture2 adds one explicit SBPB completion bit. Validate its
    ; canonical encoding, then reuse capture1 validation on an immutable copy.
    ; The original raw record and separate evidence remain untouched.
    cmp dword [r12+112],2
    jne .amd_capture_ready
    cmp dword [r12+156],1
    ja .bad_capture
    mov dword [rsp+112],1
    mov dword [rsp+156],0
.amd_capture_ready:
    mov qword [rsp+160],2
    mov esi,200
    call cpu_boundary_policy_select_amd
.validated:
    cmp eax,1
    je .status
    cmp eax,2
    je .status
    cmp eax,3
    je .status
    mov r14,[r13+32]
    mov rbx,[r13+56]
    mov r8,[r13+64]
    mov r9,[r13+72]
    cmp r15d,7
    je .amd
    ; Unavailable architecture/revision means no immunity assumptions.
    xor r10d,r10d
    cmp dword [r12+CSS_ARCH_VALID],1
    jne .intel_unknown
    mov r10,[r12+CSS_ARCH]
.intel_unknown:
    cmp dword [r12+CSS_REV_VALID],1
    je .intel_buffers
    or r14d,1024
.intel_buffers:
    ; Unclassified TAA/RFDS/MMIO keep the full buffer-clearing attempt.
    test r14d,8|256|512
    jnz .intel_clear
    bt r10,5
    jc .intel_bhi
.intel_clear:
    or r8d,4
    or r9d,4
.intel_bhi:
    test r14d,2
    jz .intel_pbrsb
    or r8d,16                         ; long software BHB sequence, both sides
    or r9d,16
    and r14d,~2
.intel_pbrsb:
    test r14d,128
    jz .intel_mcu
    or r9d,32                         ; post-barrier CALL/INT3/LEA/LFENCE
    and r14d,~128
.intel_mcu:
    cmp dword [r12+CIS_MCU_VALID],1
    jne .intel_available
    ; Only repair controls whose architectural permission actually exists.
    xor ecx,ecx
    bt r10,25                         ; GDS_CTRL -> GDS_MITG_DIS4
    jnc .intel_fb
    or ecx,16
    and r14d,~4
.intel_fb:
    bt r10,18                         ; FB_CLEAR_CTRL -> FB_CLEAR_DIS3
    jnc .intel_rng
    or ecx,8
.intel_rng:
    bt dword [r12+CSS_EDX7],9           ; SRBDS_CTRL -> RNGDS_MITG_DIS0
    jnc .intel_fb_proof
    or ecx,1
.intel_fb_proof:
    bt r10,17
    jnc .intel_mcu_needed
    and r14d,~512                      ; explicit FB_CLEAR plus repair
.intel_mcu_needed:
    ; Repair is a stable host floor: entry clearing an opt-out cannot remove
    ; the exit operation from a fresh plan. Executor independently rechecks
    ; the identical enumerated permission mask before touching MSR123.
    test ecx,ecx
    jz .intel_available
    or r8d,64
    or r9d,64
.intel_available:
    mov ecx,4|8|16|32|64               ; legal software instructions
    bt dword [r12+CSS_EDX7],26
    jnc .intel_l1d
    or ecx,1
.intel_l1d:
    bt dword [r12+CSS_EDX7],28
    jnc .intel_custody
    or ecx,2
.intel_custody:
    mov r11,[r12+CSS_MASK]
    mov rax,[r12+208]
    jmp .publish
.amd:
    ; Default full obligations; no signature/patch match is needed to run.
    cmp dword [r12+112],2
    jne .amd_floor
    mov rdi,r12
    mov esi,[r12+136]
    mov edx,[r12+140]
    mov r8d,[r12+156]
    call cpu_boundary_amd_srso_scope
    test eax,eax
    jnz .amd_floor
    and r14d,~32                      ; actual checked evidence, not admission
    and qword [r13+48],~4
.amd_floor:
    or ebx,5
    or rbx,[r12+CSS_CTRL]
    mov r8d,13
    mov r9d,13
    mov r11,[r12+CSS_MASK]
    bt dword [r12+CSS_EBX8],24          ; native SPEC_CTRL.SSBD permission
    jnc .amd_ssb_no
    or r11d,4
.amd_ssb_no:
    bt dword [r12+CSS_EBX8],26          ; architectural SSB_NO
    jnc .amd_tsa
    and ebx,~4
    and r14d,~16
.amd_tsa:
    cmp dword [r12+136],1
    jne .amd_available
    mov eax,[r12+148]                  ; raw leaf21 ECX, not normalized fiction
    and eax,6                         ; TSA_L1_NO and TSA_SQ_NO
    cmp eax,6
    jne .amd_verw_proof
    and r8d,~4
    and r9d,~4
.amd_verw_proof:
    bt dword [r12+148],5               ; architectural VERW_CLEAR
    jnc .amd_srso_proof
    and qword [r13+48],~4
.amd_srso_proof:
    test dword [r12+148],(1<<5)|6      ; VERW_CLEAR or both TSA_NO facts
    jz .amd_available
    test dword [r12+140],(1<<28)|(1<<29)
    jz .amd_available
    test dword [r12+148],1<<5
    jnz .amd_resolved
    mov eax,[r12+148]
    and eax,6
    cmp eax,6
    jne .amd_available
.amd_resolved:
    and r14d,~32
.amd_available:
    mov ecx,4|8                       ; VERW attempt + software RSB fallback
    bt dword [r12+CSS_EBX8],12
    jnc .amd_custody
    or ecx,1
.amd_custody:
    mov rax,[r12+176]
.publish:
    ; Classification diagnostics never select a refusal. Actual held core
    ; exclusion is a runtime resource, not a model/classification fact.
    mov [rsp+232],rax                  ; original full-only custody state
    mov rdx,r8
    or rdx,r9
    test edx,2|4
    jz .custody_ready
    cmp eax,1
    je .custody_ready
    or r14d,64
.custody_ready:
    mov [r13+32],r14
    mov [r13+56],rbx
    mov [r13+64],r8
    mov [r13+72],r9
    mov rdx,r11
    not rdx
    and rdx,rbx
    mov [r13+40],rdx
    mov rdx,rcx
    not rdx
    mov rax,r8
    or rax,r9
    and rdx,rax
    ; Missing microcode clearing is retained even though legal memory VERW
    ; is attempted. Its execution must never be reported as proved clearing.
    and [r13+48],rax
    or [r13+48],rdx
    and rbx,r11
    and r8,rcx
    and r9,rcx
    test r14d,64
    jz .custody_valid
    cmp qword [rsp+232],3              ; real guarded grant; honest SMT gap
    jne .custody_missing
.custody_valid:
    mov [r13+8],rbx
    mov [r13+16],r8
    mov [r13+24],r9
    xor eax,eax
    jmp .status
.custody_missing:
    mov qword [r13+8],0
    mov qword [r13+16],0
    mov qword [r13+24],0
    mov eax,4
    jmp .status
.bad_capture:
    mov eax,1
.status:
    mov [r13],rax
    add rsp,240
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.bad_buffer:
    mov rax,-1
    ret
