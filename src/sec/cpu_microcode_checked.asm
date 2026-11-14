;; MODULE sec/cpu_microcode_checked
;; LAYER 2
;; EXPORTS cpu_security_sample_checked, cpu_microcode_apply_checked, cpu_checked_io, cpu_checked_io_init, cpu_checked_mc_status, cpu_security_amd_sample_checked, cpu_security_amd_srso_sample_checked
;; IMPORTS core/smp, sec/cpu_security, sec/cpu_microcode, core/idt
;; CAPS
;; OWNER saga:security
; Calling-CPU checked API. Caller holds serialization, IF=0, a private stack
; and valid IDT/TSS. No allocation, dispatch, global sample or raw fallback.
; The original raw APIs and their consumers are deliberately unchanged.
; CIO owns a bounded operation transcript; phase is set by the caller. A failed
; observation is never a valid numeric zero. Raw exception error/RIP are NOT
; captured by the existing fixup: RAW_VALID stays zero, as do those fields.
CIO_COUNT equ 0
CIO_FAILURE equ 4                     ; first non-success completion, 0 none
CIO_PHASE equ 8                       ; 1 before,2 platform,3 apply,4 post
CIO_OWNER equ 12                      ; expected full APIC, not a dense index
CIO_TRACE equ 32
CIO_ENTRY equ 64
CIO_LIMIT equ 16
CIO_SIZE equ CIO_TRACE + CIO_LIMIT * CIO_ENTRY
CIE_PHASE equ 0
CIE_OP equ 4                          ; 1 RDMSR,2 latch clear,3 trigger
CIE_MSR equ 8
CIE_COMPLETION equ 12                 ; 0 unavailable,1 complete,2 busy,3 GP,4 owner,5 full
CIE_OWNER equ 16
CIE_OWNER_VALID equ 20
CIE_FAULT equ 24                      ; observed slot fault copied BEFORE disarm
CIE_RAW_VALID equ 28                  ; always0: raw error/RIP unavailable
CIE_VALUE equ 32                      ; completed actual read/written value only
CIE_RAW_ERROR equ 40
CIE_RAW_RIP equ 48

; RDI CIO_SIZE bytes, ESI expected full APIC. Must precede any checked call.
cpu_checked_io_init:
    push rdi
    push rsi
    xor eax,eax
    mov ecx,CIO_SIZE / 8
    rep stosq
    pop rsi
    pop rdi
    mov [rdi + CIO_OWNER],esi
    ret

; RDI initialized CIO, ECX MSR, ESI op(1 read,2 clear,3 trigger),
; EDX:EAX write value. -> R10D explicit completion; EDX:EAX read value ONLY
; when R10D=1. Preserves other registers except RCX; no instruction on busy.
; The exact-opcode fixup owns any #GP, not a global fault-count difference.
cpu_checked_io:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    push rdi
    push rsi
    push r8
    push r9
    push r11
    mov r12,rdi
    mov ebx,ecx
    mov r14d,esi
    mov ebp,eax
    shl rdx,32
    or rbp,rdx
    mov r10d,5
    mov eax,[r12 + CIO_COUNT]
    cmp eax,CIO_LIMIT
    jae .failure
    inc dword [r12 + CIO_COUNT]
    shl rax,6
    lea r13,[r12 + rax + CIO_TRACE]
    mov eax,[r12 + CIO_PHASE]
    mov [r13 + CIE_PHASE],eax
    mov [r13 + CIE_OP],r14d
    mov [r13 + CIE_MSR],ebx
    call idt_gp_fixup_cpu
.owner_sampled:
    mov [r13 + CIE_OWNER],eax
    mov r10d,4
    cmp eax,-1
    je .record_failure
    mov dword [r13 + CIE_OWNER_VALID],1
    cmp eax,[r12 + CIO_OWNER]
    jne .record_failure
    cmp r14d,1
    je .read_arm
    cmp r14d,3
    ja .record_failure
    cmp r14d,2
    jb .record_failure
    ; Direct checked-I/O callers cannot bypass the update writer gate. Reads
    ; and the Intel revision-latch clear remain usable during native custody.
    cmp ebx,0x79
    je .update_gate
    cmp ebx,0xc0010020
    jne .write_arm
.update_gate:
    cmp dword [rel smp_core_custody_gate],0
    je .write_arm
    mov r10d,2
    jmp .record_failure
.write_arm:
    lea rdi,[rel cpu_checked_wrmsr]
    lea rsi,[rel cpu_checked_wrmsr_ret]
    jmp .arm
.read_arm:
    lea rdi,[rel cpu_checked_rdmsr]
    lea rsi,[rel cpu_checked_rdmsr_ret]
.arm:
    call idt_gp_fixup_arm
    mov r10d,2
    test eax,eax
    jz .record_failure
    mov ecx,ebx
    cmp r14d,1
    je .read
    mov rax,rbp
    mov rdx,rbp
    shr rdx,32
    call cpu_checked_wrmsr
    jmp .snapshot
.read:
    call cpu_checked_rdmsr
    mov ebp,eax
    shl rdx,32
    or rbp,rdx
.snapshot:
    ; Slot stays owned (armed1 or fired3) until this CPU's disarm. The #GP
    ; handler checked vector13 + exact opcode RIP + full CPU owner already.
    call idt_gp_fixup_observe
    mov r15d,eax
    mov [r13 + CIE_FAULT],r15d
    call idt_gp_fixup_disarm
    mov r10d,3
    test r15d,r15d
    jnz .record_failure
    mov r10d,1
    mov [r13 + CIE_COMPLETION],r10d
    mov [r13 + CIE_VALUE],rbp
    jmp .out
.record_failure:
    mov [r13 + CIE_COMPLETION],r10d
.failure:
    cmp dword [r12 + CIO_FAILURE],0
    jne .failed
    mov [r12 + CIO_FAILURE],r10d
.failed:
    xor ebp,ebp                       ; value unavailable; completion is NOT1
.out:
    mov rax,rbp
    mov rdx,rbp
    shr rdx,32
    mov eax,eax
    pop r11
    pop r9
    pop r8
    pop rsi
    pop rdi
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Hardware edges only. Resume addresses name the ret after the exact opcode.
cpu_checked_rdmsr:
    rdmsr
cpu_checked_rdmsr_ret:
    ret
cpu_checked_wrmsr:
    wrmsr
cpu_checked_wrmsr_ret:
    ret

; RDI CSS, ESI capacity, RDX initialized CIO. Same CSS ABI as raw sampler.
cpu_security_sample_checked:
    push r15
    xor r15d,r15d
    jmp cpu_security_sample_checked_mode
; Private mode for the additive read-only AMD entry. Recheck the sampled vendor
; before any MSR, even if CPUID changed since the wrapper's preflight.
cpu_security_amd_css_checked:
    push r15
    mov r15d,1
cpu_security_sample_checked_mode:
    test rdx,rdx
    jz .bad
    cmp  esi, CSS_SIZE
    jb   .bad
    push rbx
    push r12
    push r13
    push r14
    mov r14,rdx
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
    test r15d,r15d
    jz .vendor_mode_ok
    cmp dword [r12 + CSS_VENDOR],2
    jne .finish
.vendor_mode_ok:
    cmp  dword [r12 + CSS_HV], 0
    jne  .finish                        ; virtual capabilities are not MSR permission
    bt   dword [r12 + CSS_EDX1], 5
    jnc  .finish
    cmp  dword [r12 + CSS_VENDOR], 1
    jne  .amd_revision
    test qword [r12 + CSS_CAPS], CS_CAP_ARCH
    jz   .intel_revision
    mov  ecx, 0x10A
    mov rdi,r14
    mov esi,1
    call cpu_checked_io
    cmp r10d,1
    jne .intel_revision
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
    mov rdi,r14
    mov esi,2
    call cpu_checked_io
    cmp r10d,1
    jne .controls
    mov  eax, 1
    xor  ecx, ecx
    call cpu_security_cpuid
    mov  ecx, 0x8B
    mov rdi,r14
    mov esi,1
    call cpu_checked_io
    cmp r10d,1
    jne .controls
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
    mov rdi,r14
    mov esi,1
    call cpu_checked_io
    cmp r10d,1
    jne .controls
    mov  [r12 + CSS_REV], eax
    mov  dword [r12 + CSS_REV_VALID], 1
.controls:
    cmp  qword [r12 + CSS_MASK], 0
    je   .finish
    mov  ecx, 0x48
    mov rdi,r14
    mov esi,1
    call cpu_checked_io
    cmp r10d,1
    jne .finish
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
    pop r14
    pop  r13
    pop  r12
    pop  rbx
    pop r15
    ret
.bad:
    mov  rax, -1
    pop r15
    ret

; Internal guarded load/readback only: R9 initialized CIO. A zero result is
; only a matching load readback; the public checked API below also resamples.
cpu_microcode_load_checked:
    cmp  dword [rel smp_core_custody_gate], 0
    je   .custody_free
    mov  rax, MC_E_BUSY
    ret
.custody_free:
    test r9,r9
    jz .noctx
    mov  rax, MC_E_ARGS
    test r8, r8
    jz   .noargs
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r15,r9
    mov  r12, rdi
    mov  rbx, rsi                       ; length, dead before CPUID
    mov  r14, rdx
    mov  r13, r8
    mov  dword [r13 + MCS_AFTER], 0
    test r12, r12
    jz   .out
    test r14, r14
    jz   .out
    mov  rax, MC_E_STATE
    cmp  dword [r13 + MCS_STATUS], MC_SELECTED
    jne  .out
    mov  rcx, [r13 + MCS_OFFSET]
    mov  rdx, [r13 + MCS_LENGTH]
    test rdx, rdx
    jz   .out
    cmp  rcx, rbx
    jae  .out
    mov  rsi, rbx
    sub  rsi, rcx
    cmp  rdx, rsi
    ja   .out                           ; the selected update lies inside the blob
    mov  esi, [r14 + CSS_VENDOR]
    cmp  esi, [r13 + MCS_VENDOR]
    jne  .out
    mov  rax, MC_E_GUEST
    cmp  dword [r14 + CSS_HV], 0
    jne  .out                           ; never write an update MSR from a guest
    mov rax,MC_E_STATE
    cmp esi,1
    je .known_vendor
    cmp esi,2
    jne .out
.known_vendor:
    mov rax,MC_E_REVISION
    cmp dword [r14 + CSS_REV_VALID],1
    jne .out
    mov rax,MC_E_UNSUPPORTED
    bt dword [r14 + CSS_EDX1],5
    jnc .out
    mov eax,[r14 + CSS_SIG]
    shr eax,8
    and eax,15
    cmp esi,1
    jne .amd_family
    cmp eax,6
    jne .unsupported
    jmp .family_ok
.amd_family:
    cmp eax,15
    jne .unsupported
    mov edx,[r14 + CSS_SIG]
    shr edx,20
    and edx,255
    add eax,edx
    cmp eax,0x17
    je .family_ok
    cmp eax,0x19
    jne .unsupported
.family_ok:
    lea  rdi, [r12 + rcx]
    cmp  esi, 1
    je   .intel
    mov  rax, MC_E_STATE
    cmp  esi, 2
    jne  .out
    mov  ecx, MC_AMD_PATCH_LOADER       ; patch header address
    mov  eax, edi
    mov  rdx, rdi
    shr  rdx, 32
    mov rdi,r15
    mov esi,3
    call cpu_checked_io
    call cpu_checked_mc_status
    test rax, rax
    jnz  .out                           ; MC_E_FAULT / MC_E_BUSY: nothing to read back
    mov  ecx, 0x8B
    mov rdi,r15
    mov esi,1
    call cpu_checked_io
    cmp r10d,1
    jne .io_failed
    jmp  .readback
.intel:
    add  rdi, MC_INTEL_HEADER           ; update data address
    mov  rax, MC_E_ALIGN
    test edi, 15
    jnz  .out
    mov  ecx, MC_INTEL_UPDATE_TRIGGER
    mov  eax, edi
    mov  rdx, rdi
    shr  rdx, 32
    mov rdi,r15
    mov esi,3
    call cpu_checked_io
    call cpu_checked_mc_status
    test rax, rax
    jnz  .out
    mov  ecx, 0x8B
    xor  eax, eax
    xor  edx, edx
    mov rdi,r15
    mov esi,2
    call cpu_checked_io
    call cpu_checked_mc_status
    test rax,rax
    jnz .out
    mov  eax, 1
    xor  ecx, ecx
    call cpu_security_cpuid             ; latches the new revision into 8Bh
    mov  ecx, 0x8B
    mov rdi,r15
    mov esi,1
    call cpu_checked_io
    cmp r10d,1
    jne .io_failed
    mov  eax, edx
.readback:
    mov  [r13 + MCS_AFTER], eax
    cmp  eax, [r13 + MCS_REV]
    mov  rax, MC_E_NOT_APPLIED
    jne  .out
    mov  eax, MC_APPLIED
.out:
    pop r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret
.unsupported:
    mov rax,MC_E_UNSUPPORTED
    jmp .out
.io_failed:
    call cpu_checked_mc_status
    jmp .out
.noctx:
    mov rax,MC_E_ARGS
.noargs:
    ret

; R10D completion -> existing MC refusal values. Value1 alone means I/O
; completed; caller must still compare the actual revision and resample.
cpu_checked_mc_status:
    xor eax,eax
    cmp r10d,1
    je .out
    mov rax,MC_E_FAULT
    cmp r10d,3
    je .out
    mov rax,MC_E_BUSY
.out:
    ret

; Public checked apply: raw arguments plus R9 -> caller-owned MCA_SIZE bytes.
; MCA_IO and MCA_POST are initialized pointers to private CIO and CSS storage.
; Returns MC_APPLIED ONLY after load/readback AND a separate complete fresh
; checked sample. MCA_LOAD_MATCH distinguishes a loaded CPU with unavailable
; post proof from a refused/ignored load. Raw MCS selection/status ABI unchanged.
MCA_IO equ 0
MCA_POST equ 8
MCA_LOAD_MATCH equ 16
MCA_POST_VALID equ 20
MCA_SIZE equ 32
MC_E_POST equ -22
cpu_microcode_apply_checked:
    test r9,r9
    jz .bad
    push r12
    push r13
    push r14
    push r15
    mov r12,r9
    mov r13,rdx
    mov r14,[r12 + MCA_POST]
    mov r15,r8
    mov dword [r12 + MCA_LOAD_MATCH],0
    mov dword [r12 + MCA_POST_VALID],0
    mov rax,MC_E_ARGS
    test r14,r14
    jz .out
    test r13,r13
    jz .out
    test r15,r15
    jz .out
    ; Distinct full before/after storage, never a copied/overwritten before.
    mov rax,r14
    sub rax,r13
    cmp rax,CSS_SIZE
    jb .args
    mov rax,r13
    sub rax,r14
    cmp rax,CSS_SIZE
    jb .args
    mov r9,[r12 + MCA_IO]
    test r9,r9
    jz .args
    mov dword [r9 + CIO_PHASE],3
    call cpu_microcode_load_checked
    test rax,rax
    jnz .out
    mov dword [r12 + MCA_LOAD_MATCH],1
    mov rdx,[r12 + MCA_IO]
    mov dword [rdx + CIO_PHASE],4
    mov rdi,r14
    mov esi,CSS_SIZE
    call cpu_security_sample_checked
    mov rax,MC_E_POST
    mov rdx,[r12 + MCA_IO]
    cmp dword [rdx + CIO_FAILURE],0
    jne .out
    cmp dword [r14 + CSS_REV_VALID],1
    jne .out
    cmp dword [r14 + CSS_HV],0
    jne .out
    mov ecx,[r13 + CSS_VENDOR]
    cmp ecx,[r14 + CSS_VENDOR]
    jne .out
    mov ecx,[r13 + CSS_SIG]
    cmp ecx,[r14 + CSS_SIG]
    jne .out
    mov ecx,[r15 + MCS_REV]
    cmp ecx,[r14 + CSS_REV]
    jne .out
    call idt_gp_fixup_cpu
    mov rdx,[r12 + MCA_IO]
    cmp eax,[rdx + CIO_OWNER]
    mov rax,MC_E_POST
    jne .out
    mov dword [r12 + MCA_POST_VALID],1
    mov eax,MC_APPLIED
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    ret
.args:
    mov rax,MC_E_ARGS
    jmp .out
.bad:
    mov rax,MC_E_ARGS
    ret

; Additive AMD evidence capture. CSS112 and every existing consumer stay as-is.
; RDI mapped CAS_SIZE output, RSI full-width capacity, RDX mapped initialized
; private CIO_SIZE. Caller pins this CPU and serializes control/microcode with
; IF=0, DF=0 and the existing private stack/IDT/TSS/fixup prerequisites. Begin/
; end ownership checks detect drift; they are NOT a replacement for pinning.
; Never decodes mitigation policy or grants VM entry. A completed capture may
; contain unavailable optional leaves/MSRs: consult each independent validity.
CAS_VERSION equ 112
CAS_STATUS equ 116
CAS_BEGIN_OWNER equ 120
CAS_END_OWNER equ 124
CAS_BEGIN_VALID equ 128
CAS_END_VALID equ 132
CAS_LEAF21_VALID equ 136
CAS_LEAF21_EAX equ 140
CAS_LEAF21_EBX equ 144
CAS_LEAF21_ECX equ 148
CAS_LEAF21_EDX equ 152
CAS_SIZE equ 160
; Status0 completed capture,1 nonAMD,2 guest,3 owner,4 checked I/O failure,
; 5 dirty CIO,6 pending (never normal return),7 absent/changed basic identity.
; Geometry errors return -1 before touching either buffer or sampling hardware.
cpu_security_amd_sample_checked:
    test rdi,rdi
    jz .bad
    cmp rsi,CAS_SIZE
    jb .bad
    test rdx,rdx
    jz .bad
    mov rax,rdi
    add rax,CAS_SIZE
    jc .bad
    mov rcx,rdx
    add rcx,CIO_SIZE
    jc .bad
    cmp rax,rdx                       ; adjacent ranges are allowed
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
    mov ecx,CAS_SIZE / 8
    rep stosq
    mov dword [r12 + CAS_VERSION],1
    mov dword [r12 + CAS_STATUS],6
    ; Do not erase a prior operation or failure to manufacture a fresh sample.
    cmp dword [r13 + CIO_COUNT],0
    jne .dirty
    cmp dword [r13 + CIO_FAILURE],0
    jne .dirty
    call idt_gp_fixup_cpu
    mov [r12 + CAS_BEGIN_OWNER],eax
    cmp eax,-1
    je .owner
    mov dword [r12 + CAS_BEGIN_VALID],1
    cmp eax,[r13 + CIO_OWNER]
    jne .owner
    ; Gate before invoking the shared sampler: an Intel preflight must never
    ; execute its revision-latch write through this read-only AMD entry.
    xor eax,eax
    xor ecx,ecx
    call cpu_security_cpuid
    mov r14d,eax
    cmp ebx,0x68747541
    jne .vendor
    cmp edx,0x69746e65
    jne .vendor
    cmp ecx,0x444d4163
    jne .vendor
    cmp r14d,1
    jb .changed
    mov eax,1
    xor ecx,ecx
    call cpu_security_cpuid
    mov r15d,eax
    bt ecx,31
    jc .guest
    mov rdi,r12
    mov esi,CSS_SIZE
    mov rdx,r13
    call cpu_security_amd_css_checked
    test rax,rax
    jnz .changed
    cmp dword [r12 + CSS_VENDOR],2
    jne .changed
    cmp dword [r12 + CSS_HV],0
    jne .changed
    cmp r14d,[r12 + CSS_MAX]
    jne .changed
    cmp r15d,[r12 + CSS_SIG]
    jne .changed
    cmp dword [r12 + CSS_EXTMAX],0x80000021
    jb .end_owner
    mov eax,0x80000021
    xor ecx,ecx
    call cpu_security_cpuid
    mov [r12 + CAS_LEAF21_EAX],eax
    mov [r12 + CAS_LEAF21_EBX],ebx
    mov [r12 + CAS_LEAF21_ECX],ecx
    mov [r12 + CAS_LEAF21_EDX],edx
    mov dword [r12 + CAS_LEAF21_VALID],1
.end_owner:
    call idt_gp_fixup_cpu
    mov [r12 + CAS_END_OWNER],eax
    cmp eax,-1
    je .owner
    mov dword [r12 + CAS_END_VALID],1
    cmp eax,[r13 + CIO_OWNER]
    jne .owner
    cmp eax,[r12 + CAS_BEGIN_OWNER]
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
    mov [r12 + CAS_STATUS],eax
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

; Additive trusted SRSO discovery. Same geometry/CIO/caller contract as the
; read-only AMD entry above, which remains unchanged. Other CPU signatures
; retain capture v1. Exact 00a70f52 emits capture v2: offset156 is completed
; SBPB evidence0/1, NOT CPUID. Only the saved revision0a70520a is probed.
; All raw CPUID words survive verbatim. Native leaf21 bit28/29 needs no probe.
; AMD-authored Linux5a15d834 uses fault-contained PRED_CMD.SBPB completion to
; detect Zen3/4 IBPB_BRTYPE microcode, including non-enumerating clients.
; SBPB is discovery here; security boundaries STILL execute IBPB(bit0).
; A busy/#GP/owner failure retains the transcript and refuses capture; no
; global-fault-count inference, sticky-failure reset, or raw WRMSR fallback.
; See gauntlet_v2/docs/amd_srso_discovery_v4.md for primary vendor evidence.
cpu_security_amd_srso_sample_checked:
    push rbx
    push r12
    push r13
    mov r12,rdi
    mov r13,rdx
    call cpu_security_amd_sample_checked
    test rax,rax
    jnz .out
    cmp dword [r12 + CSS_SIG],0x00a70f52
    jne .out
    mov dword [r12 + CAS_VERSION],2
    ; The TSA patch floor is not SRSO evidence. This exact revision merely
    ; bounds where we attempt AMD's independent checked capability probe.
    cmp qword [r12 + CSS_REV],0x0a70520a
    jne .out
    cmp dword [r12 + CSS_REV_VALID],1
    jne .out
    bt dword [r12 + CSS_EDX1],5
    jnc .out
    mov eax,[r12 + CSS_EBX8]
    and eax,(1 << 12) | (1 << 24) | (1 << 30)
    cmp eax,(1 << 12) | (1 << 24) | (1 << 30)
    jne .unavailable
    cmp dword [r12 + CAS_LEAF21_VALID],1
    jne .unavailable
    test dword [r12 + CAS_LEAF21_EAX],(1 << 28) | (1 << 29)
    jnz .unavailable
    mov dword [r12 + CAS_STATUS],6
    mov ecx,0x49
    mov esi,3
    mov eax,0x80
    xor edx,edx
    mov rdi,r13
    call cpu_checked_io
    mov ebx,r10d
    call idt_gp_fixup_cpu
    mov [r12 + CAS_END_OWNER],eax
    mov dword [r12 + CAS_END_VALID],0
    cmp eax,-1
    je .owner
    mov dword [r12 + CAS_END_VALID],1
    cmp eax,[r13 + CIO_OWNER]
    jne .owner
    cmp eax,[r12 + CAS_BEGIN_OWNER]
    jne .owner
    cmp ebx,1
    jne .io_failed
    cmp dword [r13 + CIO_FAILURE],0
    jne .io_failed
    mov dword [r12 + 156],1
.unavailable:
    xor eax,eax
    jmp .publish
.owner:
    mov eax,3
    jmp .publish
.io_failed:
    mov eax,4
.publish:
    mov [r12 + CAS_STATUS],eax
.out:
    pop r13
    pop r12
    pop rbx
    ret
