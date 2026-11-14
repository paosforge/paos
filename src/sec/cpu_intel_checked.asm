;; MODULE sec/cpu_intel_checked
;; LAYER 2
;; EXPORTS cpu_security_intel_sample_checked, cpu_boundary_policy_select_intel
;; IMPORTS sec/cpu_security, sec/cpu_microcode_checked, sec/cpu_boundary_selector, core/idt
;; CAPS
;; OWNER saga:security
; Additive calling-CPU capture and pure Intel plan. No guest admission or
; executor/frontier/custody claim. CSS112, legacy144 and AMD APIs are unchanged.
; Checked I/O requires caller IF0, private mapped stack, valid IDT/TSS, pinned
; full APIC, and serialization of microcode/control changes. No raw fallback.
; Intel BIOS_SIGN_ID clear is the existing revision latch, not an update.
; Scope and paired VM producer requirements: intel_checked_boundary_v5.md.

CIS_VERSION equ 112
CIS_STATUS equ 116
CIS_BEGIN_OWNER equ 120
CIS_END_OWNER equ 124
CIS_BEGIN_VALID equ 128
CIS_END_VALID equ 132
CIS_EBX7 equ 136
CIS_ECX1 equ 140
CIS_MCU_VALID equ 144
CIS_TSX_VALID equ 148
CIS_MCU equ 152
CIS_TSX equ 160
CIS_SIZE equ 192
CIP_SIZE equ 232
CIP_VERSION equ 192
CIP_PROFILE equ 200
CIP_CORE equ 208
CIP_OWNER equ 216
CIP_RESERVED equ 224

; RDI=192-byte mapped output, RSI full capacity, RDX=fresh initialized CIO1056.
; Disjoint extents required. Status0 complete,1 vendor,2 hypervisor,3 owner,
; 4 checked I/O failure,5 dirty CIO,6 pending,7 changed/incomplete CPUID.
; Unavailable fields retain validity0, never an apparent observed numeric zero.
cpu_security_intel_sample_checked:
    test rdi,rdi
    jz .bad
    cmp rsi,CIS_SIZE
    jb .bad
    test rdx,rdx
    jz .bad
    mov rax,rdi
    add rax,CIS_SIZE
    jc .bad
    mov rcx,rdx
    add rcx,CIO_SIZE
    jc .bad
    cmp rax,rdx
    jbe .geometry
    cmp rcx,rdi
    ja .bad
.geometry:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,8
    mov r12,rdi
    mov r13,rdx
    xor eax,eax
    mov ecx,CIS_SIZE / 8
    rep stosq
    mov dword [r12 + CIS_VERSION],1
    mov dword [r12 + CIS_STATUS],6
    cmp dword [r13 + CIO_COUNT],0
    jne .dirty
    cmp dword [r13 + CIO_FAILURE],0
    jne .dirty
    call idt_gp_fixup_cpu
    mov [r12 + CIS_BEGIN_OWNER],eax
    cmp eax,-1
    je .owner
    mov dword [r12 + CIS_BEGIN_VALID],1
    cmp eax,[r13 + CIO_OWNER]
    jne .owner
    xor eax,eax
    xor ecx,ecx
    call cpu_security_cpuid
    mov r14d,eax
    cmp ebx,0x756e6547
    jne .vendor
    cmp edx,0x49656e69
    jne .vendor
    cmp ecx,0x6c65746e
    jne .vendor
    cmp r14d,7
    jb .changed
    mov eax,1
    xor ecx,ecx
    call cpu_security_cpuid
    mov r15d,eax
    mov [r12 + CIS_ECX1],ecx
    bt ecx,31
    jc .guest
    bt edx,5
    jnc .changed
    mov rdi,r12
    mov esi,CSS_SIZE
    mov rdx,r13
    call cpu_security_sample_checked
    test rax,rax
    jnz .changed
    cmp dword [r12 + CSS_VENDOR],1
    jne .changed
    cmp dword [r12 + CSS_HV],0
    jne .changed
    cmp r14d,[r12 + CSS_MAX]
    jne .changed
    cmp r15d,[r12 + CSS_SIG]
    jne .changed
    mov eax,1
    xor ecx,ecx
    call cpu_security_cpuid
    cmp eax,[r12 + CSS_SIG]
    jne .changed
    cmp ecx,[r12 + CIS_ECX1]
    jne .changed
    cmp edx,[r12 + CSS_EDX1]
    jne .changed
    mov eax,7
    xor ecx,ecx
    call cpu_security_cpuid
    cmp edx,[r12 + CSS_EDX7]
    jne .changed
    cmp eax,[r12 + CSS_MAX7]
    jne .changed
    mov [r12 + CIS_EBX7],ebx
    ; Architectural enumeration is permission to read, not enabled state.
    xor ebp,ebp
    cmp dword [r12 + CSS_ARCH_VALID],1
    jne .srbds_permission
    mov rbp,[r12 + CSS_ARCH]
    test ebp,(1 << 25) | (1 << 18)       ; GDS_CTRL / FB_CLEAR_CTRL
    jnz .mcu
.srbds_permission:
    bt dword [r12 + CSS_EDX7],9         ; SRBDS_CTRL
    jnc .tsx
.mcu:
    mov rdi,r13
    mov ecx,0x123
    mov esi,1
    call cpu_checked_io
    cmp r10d,1
    jne .tsx
    shl rdx,32
    or rax,rdx
    mov [r12 + CIS_MCU],rax
    mov dword [r12 + CIS_MCU_VALID],1
.tsx:
    bt rbp,7                            ; TSX_CTRL
    jnc .end_owner
    mov rdi,r13
    mov ecx,0x122
    mov esi,1
    call cpu_checked_io
    cmp r10d,1
    jne .end_owner
    shl rdx,32
    or rax,rdx
    mov [r12 + CIS_TSX],rax
    mov dword [r12 + CIS_TSX_VALID],1
.end_owner:
    call idt_gp_fixup_cpu
    mov [r12 + CIS_END_OWNER],eax
    cmp eax,-1
    je .owner
    mov dword [r12 + CIS_END_VALID],1
    cmp eax,[r13 + CIO_OWNER]
    jne .owner
    cmp eax,[r12 + CIS_BEGIN_OWNER]
    jne .owner
    cmp dword [r13 + CIO_FAILURE],0
    jne .io_failed
    xor eax,eax
    jmp .publish
.vendor:
    mov eax,1
    jmp .publish
.guest:
    mov eax,2
    jmp .publish
.owner:
    mov eax,3
    jmp .publish
.io_failed:
    mov eax,4
    jmp .publish
.dirty:
    mov eax,5
    jmp .publish
.changed:
    mov eax,7
.publish:
    mov [r12 + CIS_STATUS],eax
    add rsp,8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
.bad:
    mov rax,-1
    ret

; RDI=input232: CIS192 + u64 version5/profile1/core0..2/expectedAPIC/reserved0.
; RDX=existing96 output, RSI/RCX full capacities. Pure trusted capture consumer.
; Status0 selects a capability-derived plan ONLY. A trusted VM producer must establish and
; continuously hold actual architectural/core custody. Native CPUID topology
; may prove all siblings absent; equal samples cannot hold present siblings.
; Per-CALL handoff, interrupts/NMI, sameCPU/microcode and exact inline
; final/landing recipes remain VM work. Callable executor RET is not a frontier.
; Architectural bits/control state drive every CPU. Exact906EA/fa is only an
; optional vendor override. Observation gap1024 is not an unknown-model gate.
cpu_boundary_policy_select_intel:
    test rdi,rdi
    jz .bad_buffer
    test rdx,rdx
    jz .bad_buffer
    cmp rsi,CIP_SIZE
    jb .bad_buffer
    cmp rcx,CBS_OUTPUT_SIZE
    jb .bad_buffer
    mov rax,rdi
    add rax,CIP_SIZE
    jc .bad_buffer
    mov r8,rdx
    add r8,CBS_OUTPUT_SIZE
    jc .bad_buffer
    cmp rax,rdx
    jbe .geometry
    cmp r8,rdi
    ja .bad_buffer
.geometry:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,CBS_INPUT_SIZE
    mov r12,rdi
    mov r13,rdx
%assign cip_i 0
%rep CBS_OUTPUT_SIZE / 8
    mov qword [r13 + cip_i],0
%assign cip_i cip_i + 8
%endrep
    cmp qword [r12 + CIP_VERSION],5
    jne .bad_capture
    cmp qword [r12 + CIP_PROFILE],1
    jne .bad_capture
    cmp qword [r12 + CIP_RESERVED],0
    jne .bad_capture
    cmp qword [r12 + CIP_CORE],2
    ja .bad_capture
    cmp dword [r12 + CIS_VERSION],1
    jne .bad_capture
    cmp dword [r12 + CIS_STATUS],0
    jne .bad_capture
    cmp dword [r12 + CIS_BEGIN_VALID],1
    jne .bad_capture
    cmp dword [r12 + CIS_END_VALID],1
    jne .bad_capture
    mov eax,[r12 + CIS_BEGIN_OWNER]
    cmp eax,-1
    je .bad_capture
    cmp eax,[r12 + CIS_END_OWNER]
    jne .bad_capture
    cmp rax,[r12 + CIP_OWNER]
    jne .bad_capture
    cmp dword [r12 + CIS_MCU_VALID],1
    ja .bad_capture
    cmp dword [r12 + CIS_TSX_VALID],1
    ja .bad_capture
    mov eax,[r12 + CIS_ECX1]
    shr eax,31
    cmp eax,[r12 + CSS_HV]
    jne .bad_capture
    cmp qword [r12 + 104],0
    jne .bad_capture
    cmp dword [r12 + CSS_REV_VALID],1
    ja .bad_capture
    cmp dword [r12 + CIS_MCU_VALID],0
    je .no_mcu
    cmp dword [r12 + CSS_ARCH_VALID],1
    jne .mcu_srbds_permission
    test qword [r12 + CSS_ARCH],(1 << 25) | (1 << 18)
    jnz .tsx_capture
.mcu_srbds_permission:
    bt dword [r12 + CSS_EDX7],9
    jnc .bad_capture
    jmp .tsx_capture
.no_mcu:
    cmp qword [r12 + CIS_MCU],0
    jne .bad_capture
.tsx_capture:
    cmp dword [r12 + CIS_TSX_VALID],0
    je .no_tsx
    cmp dword [r12 + CSS_ARCH_VALID],1
    jne .bad_capture
    bt qword [r12 + CSS_ARCH],7
    jnc .bad_capture
    jmp .reserved
.no_tsx:
    cmp qword [r12 + CIS_TSX],0
    jne .bad_capture
.reserved:
    cmp qword [r12 + 168],0
    jne .bad_capture
    cmp qword [r12 + 176],0
    jne .bad_capture
    cmp qword [r12 + 184],0
    jne .bad_capture
%assign cip_i 0
%rep CSS_SIZE / 8
    mov rax,[r12 + cip_i]
    mov [rsp + cip_i],rax
%assign cip_i cip_i + 8
%endrep
    ; Normalize fresh raw enumeration independently, reject mixed captures.
    mov rdi,rsp
    call cpu_security_decode
    mov rax,[rsp + CSS_CAPS]
    cmp rax,[r12 + CSS_CAPS]
    jne .bad_capture
    mov rax,[rsp + CSS_MASK]
    cmp rax,[r12 + CSS_MASK]
    jne .bad_capture
    mov qword [rsp + CBS_VERSION],1
    mov qword [rsp + CBS_PROFILE],1
    mov rax,[r12 + CIP_CORE]
    mov [rsp + CBS_CORE],rax
    mov qword [rsp + CBS_RESERVED],0
    mov rdi,rsp
    mov esi,CBS_INPUT_SIZE
    mov rdx,r13
    mov ecx,CBS_OUTPUT_SIZE
    call cpu_boundary_policy_select
    cmp eax,CBS_BAD_CAPTURE
    je .status
    cmp eax,CBS_VENDOR
    je .status
    cmp eax,CBS_NOT_NATIVE
    je .status
    ; The legacy plan is diagnostic until ALL capability obligations below
    ; are resolved. A previously successful legacy call must not leak a grant.
    mov qword [r13 + CBS_O_FLOOR],0
    mov qword [r13 + CBS_O_ENTRY],0
    mov qword [r13 + CBS_O_EXIT],0
    cmp dword [r12 + CSS_VENDOR],1
    jne .scope_unknown
    cmp dword [r12 + CSS_REV_VALID],1
    jne .scope_unknown                  ; unavailable observation, not model ID
    cmp dword [r12 + CSS_ARCH_VALID],1
    jne .scope_unknown
    mov r15,[r12 + CSS_ARCH]
    mov r14,[r13 + CBS_O_UNRESOLVED]
    and r14,~(2 | 4 | 8 | 64 | 128 | 256 | 512)
    xor ebx,ebx
    ; Optional vendor override for applicability/updated MMIO microcode only.
    ; Every other CPU follows the same architectural capability decisions.
    cmp dword [r12 + CSS_SIG],0x000906ea
    jne .bhi
    cmp qword [r12 + CSS_REV],0xfa
    jne .bhi
    bt r15,1                           ; vendor row is the non-eIBRS part
    jc .bhi
    mov ebx,1
.bhi:
    bt r15,20                          ; BHI_NO
    jc .gds
    test ebx,ebx
    jnz .gds
    or r14d,2
.gds:
    bt r15,26                          ; GDS_NO
    jc .rfds
    bt r15,25                          ; GDS_CTRL is not enabled-state proof
    jnc .gds_unknown
    cmp dword [r12 + CIS_MCU_VALID],1
    jne .gds_unknown
    test qword [r12 + CIS_MCU],1 << 4   ; GDS opt-out must be clear
    jz .rfds
.gds_unknown:
    or r14d,4
.rfds:
    bt r15,27                          ; RFDS_NO
    jc .pbrsb
    test ebx,ebx
    jnz .pbrsb
    bt r15,28                          ; RFDS_CLEAR: memory VERW, not MD_CLEAR
    jnc .rfds_unknown
    or qword [r13 + CBS_O_DERIVED_ENTRY],4
    or qword [r13 + CBS_O_DERIVED_EXIT],4
    jmp .pbrsb
.rfds_unknown:
    or r14d,256
.pbrsb:
    bt r15,1                           ; special PBRSB recipe only on eIBRS
    jnc .mds
    bt r15,24
    jc .mds
    or r14d,128
.mds:
    bt r15,5                           ; MDS_NO
    jc .taa
    ; MDS buffer clearing is needed in both directions. A distinct FB/RFDS
    ; mechanism cannot substitute for MD_CLEAR on an MDS-affected processor.
    or qword [r13 + CBS_O_DERIVED_EXIT],4
    bt dword [r12 + CSS_EDX7],10
    jc .taa
    or qword [r13 + CBS_O_MISSING_ACTION],4
.taa:
    bt r15,8                           ; TAA_NO
    jc .mmio
    bt r15,5                           ; MDS mitigation also covers TAA
    jnc .taa_clear
    bt r15,7                           ; MDS_NO1 needs TSX_CTRL microcode
    jnc .taa_unknown
    cmp dword [r12 + CIS_TSX_VALID],1
    jne .taa_unknown
    bt qword [r12 + CIS_TSX],0          ; checked RTM_DISABLE, HLE ignored
    jc .mmio
.taa_clear:
    bt dword [r12 + CSS_EDX7],10
    jnc .taa_unknown
    or qword [r13 + CBS_O_DERIVED_ENTRY],4
    or qword [r13 + CBS_O_DERIVED_EXIT],4
    jmp .mmio
.taa_unknown:
    or r14d,8
.mmio:
    mov eax,r15d
    and eax,(1 << 13) | (1 << 14) | (1 << 15)
    cmp eax,(1 << 13) | (1 << 14) | (1 << 15)
    je .custody
    bt r15,17                          ; explicit updated FB_CLEAR mechanism
    jc .mmio_control
    ; Older implicit MD_CLEAR path requires an updated-microcode override;
    ; the existence of an old MDS/SRBDS patch alone does not prove that update.
    test ebx,ebx
    jz .mmio_unknown
    bt dword [r12 + CSS_EDX7],10
    jnc .mmio_unknown
.mmio_control:
    ; If a control is enumerated its enabled state must be freshly observed.
    ; No read requirement for a nonexistent opt-out; no numeric-zero fiction.
    bt r15,18                          ; FB_CLEAR_CTRL
    jc .mmio_read
    bt dword [r12 + CSS_EDX7],9         ; SRBDS_CTRL
    jc .mmio_read
    test ebx,ebx                       ; exact override additionally checks it
    jz .mmio_clear
.mmio_read:
    cmp dword [r12 + CIS_MCU_VALID],1
    jne .mmio_unknown
    test qword [r12 + CIS_MCU],1 | (1 << 3)
    jnz .mmio_unknown
.mmio_clear:
    or qword [r13 + CBS_O_DERIVED_ENTRY],4
    or qword [r13 + CBS_O_DERIVED_EXIT],4
    jmp .custody
.mmio_unknown:
    or r14d,512
.custody:
    ; CPUID topology may prove all siblings absent. When peers exist, trusted
    ; CPU/VM code must hold their exclusion; a count cannot park a live peer.
    mov rax,[r13 + CBS_O_DERIVED_ENTRY]
    or rax,[r13 + CBS_O_DERIVED_EXIT]
    test eax,2 | 4
    jz .proofs
    cmp qword [r12 + CIP_CORE],1
    je .proofs
    or r14d,64
.proofs:
    mov [r13 + CBS_O_UNRESOLVED],r14
    ; Added actions need their own hardware mechanism. Keep distinct MDS/TAA
    ; checks above: FB_CLEAR/RFDS_CLEAR support only their own clearing duties.
    mov eax,[r12 + CSS_EDX7]
    xor ecx,ecx
    bt eax,26
    jnc .action_l1d
    or ecx,1
.action_l1d:
    bt eax,28
    jnc .action_verw
    or ecx,2
.action_verw:
    bt eax,10
    jc .verw_available
    test r15,(1 << 17) | (1 << 28)
    jz .action_available
.verw_available:
    or ecx,4
.action_available:
    or ecx,8                           ; backend must check RSB recipe/CET
    not rcx
    mov rax,[r13 + CBS_O_DERIVED_ENTRY]
    or rax,[r13 + CBS_O_DERIVED_EXIT]
    and rax,rcx
    or [r13 + CBS_O_MISSING_ACTION],rax
    test r14,r14
    jnz .unknown
    cmp qword [r13 + CBS_O_MISSING_CONTROL],0
    jne .missing_control
    cmp qword [r13 + CBS_O_MISSING_ACTION],0
    jne .missing_action
    mov rax,[r13 + CBS_O_DERIVED_FLOOR]
    mov [r13 + CBS_O_FLOOR],rax
    mov rax,[r13 + CBS_O_DERIVED_ENTRY]
    mov [r13 + CBS_O_ENTRY],rax
    mov rax,[r13 + CBS_O_DERIVED_EXIT]
    mov [r13 + CBS_O_EXIT],rax
    xor eax,eax
    jmp .status
.missing_control:
    mov eax,CBS_MISSING_CONTROL
    jmp .status
.missing_action:
    mov eax,CBS_MISSING_ACTION
    jmp .status
.scope_unknown:
    or qword [r13 + CBS_O_UNRESOLVED],1024
.unknown:
    mov eax,CBS_UNKNOWN_UNSUPPORTED
    mov qword [r13 + CBS_O_FLOOR],0
    mov qword [r13 + CBS_O_ENTRY],0
    mov qword [r13 + CBS_O_EXIT],0
    jmp .status
.bad_capture:
    mov eax,CBS_BAD_CAPTURE
.status:
    mov [r13 + CBS_O_STATUS],rax
    add rsp,CBS_INPUT_SIZE
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
.bad_buffer:
    mov rax,-1
    ret
