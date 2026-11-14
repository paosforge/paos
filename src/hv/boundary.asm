;; MODULE hv/boundary
;; LAYER 5
;; EXPORTS hv_boundary_guarded_check, hv_boundary_svm_gang_acquire, hv_boundary_svm_gang_bind, hv_boundary_intel_acquire, hv_boundary_intel_release, hv_boundary_gang_bind, hv_boundary_arm, hv_boundary_enter, hv_boundary_exit, hv_boundary_finish, hv_boundary_svm_acquire, hv_boundary_svm_prepare, hv_boundary_svm_transfer, hv_boundary_svm_land, hv_boundary_svm_host
;; IMPORTS hv/vcpu_ap, hv/boundary_execution, sec/cpu_microcode_checked, sec/cpu_security, sec/cpu_intel_checked, sec/cpu_boundary_selector, sec/cpu_boundary_executor, sec/cpu_boundary_full, core/idt, core/smp
;; CAPS
;; OWNER saga:hv
; Trusted BSP launch-frame adapter. No shared receipt, guest-provided masks or
; virtual mitigation interface. Caller holds IF0 (SVM GIF0 in protected phases),
; pins this CPU
; and keeps the nonresuming exception guard through host-state restoration.
; Every adapter takes RDI=retained mapped private HVB_SIZE-byte frame. Callee
; saves survive; guest GPRs must already be saved or not yet loaded.
;
; A selector/arm refusal before execution may return1. Once an executor has
; been attempted, any non-success or malformed receipt is uncertain and cannot
; return, dispatch, resume, clear a context or produce a guest verdict.
HVB_REQUEST equ 0
HVB_RECEIPT equ 48
HVB_ACTIVE equ 144
HVB_GUARD equ 152
HVB_CAPTURE equ 168
HVB_POLICY equ 312
HVB_STAGE equ 160                    ; 1 guard,2 sample,3 selector,4 scoped plan
HVB_SAMPLE_RC equ 408
HVB_SELECT_RC equ 416
HVB_AMD equ 424                     ; private checked160 + versioned tail40
HVB_CIO equ 624                     ; private fresh CIO_SIZE=1056
HVB_LEASE equ 1680                 ; opaque native SVM token, checked before SEC custody
HVB_FRONTIER equ 1688              ; 0 host,1 prepared,2 guest transfer,3 landed
HVB_VERW equ 1696                  ; private mapped memory-form selector
HVB_SVM equ 1700                   ; native transition mode:0 legacy,1 SVM,2 checked Intel
HVB_INTEL equ 1704                  ; private CIS192 + CIP40; AMD ABI unchanged
HVB_INTEL_BIND equ 1936             ; paired CIS192 + selected plan24
HVB_INTEL_MCU_MASK equ 2152         ; exact enumerated repair bits; no stale register restore
HVB_CUSTODY_KIND equ 2160           ; 1 SVM architectural,2 Intel absent,3 native guarded
HVB_CORE_STATE equ 2164             ; 1 architectural,3 guarded UNKNOWN (full ABI)
HVB_GUARDED_PHASE equ 2168          ; guarded SVM HOST/PREPARED/TRANSFER/LANDED
HVB_GANG_CPU equ 2176               ; T1-5 S7 kind 4: the designated AP's logical CPU
HVB_SIZE equ 2184                   ; diagnostic prefix unchanged, 8 mod16
HVB_HLT_SIZE equ 2192               ; five rather than six saved GPRs

hv_boundary_arm:
    push rbx
    mov rbx, rdi
    mov qword [rbx + HVB_ACTIVE], 0
    mov qword [rbx + HVB_REQUEST], 0
    mov qword [rbx + HVB_LEASE], 0
    mov qword [rbx + HVB_FRONTIER], 0
    mov qword [rbx + HVB_GUARD], 0
    mov dword [rbx + HVB_SVM], 0
    mov qword [rbx + HVB_CUSTODY_KIND], 0
    mov qword [rbx + HVB_GUARDED_PHASE], 0
    mov qword [rbx + HVB_AMD + 160], 1 ; retained Intel/v1 request binding
    mov qword [rbx + HVB_STAGE], 1
    mov qword [rbx + HVB_SAMPLE_RC], -2 ; NOT_CALLED, never synthesized success
    mov qword [rbx + HVB_SELECT_RC], -2
    lea rdi, [rbx + HVB_CAPTURE]
    xor eax, eax
    mov ecx, (144 + 96) / 8
    rep stosq
    call cpu_boundary_fault_arm
    test rax, rax
    jz .refused
    mov [rbx + HVB_GUARD], rax
.ready:
    xor eax, eax
    pop rbx
    ret
.refused:
    mov eax, 1
    pop rbx
    ret

; Only the actual SVM caller may bind the architectural provider. Its guard
; is already armed, original EFER/HSAVE saved and SVME enabled. Zero acquire
; is a clean refusal with incoming owner GIF unchanged (provider ABI rev3).
hv_boundary_svm_acquire:
    push rbx
    mov rbx, rdi
    cmp qword [rbx + HVB_GUARD], 0
    je cpu_boundary_fail_stop
    cmp qword [rbx + HVB_LEASE], 0
    jne cpu_boundary_fail_stop
    mov dword [rbx + HVB_SVM], 1
    mov rdx, [rbx + HVB_GUARD]
    mov edi, edx
    call smp_core_custody_acquire_svm
    cmp rax, -1
    je cpu_boundary_fail_stop
    test rax, rax
    jz .guarded
    mov dword [rbx + HVB_CUSTODY_KIND], 1
    mov dword [rbx + HVB_CORE_STATE], 1
    jmp .acquired
.guarded:
    mov rdx, [rbx + HVB_GUARD]
    mov edi, edx
    call smp_core_custody_acquire_native_guarded
    cmp rax, -1
    je cpu_boundary_fail_stop
    test rax, rax
    jz .acquired
    mov dword [rbx + HVB_CUSTODY_KIND], 3
    mov dword [rbx + HVB_CORE_STATE], 3
.acquired:
    mov [rbx + HVB_LEASE], rax
    test rax, rax
    setz al
    movzx eax, al
    pop rbx
    ret

 ; AMD S7 uses the native guarded provider. Its AP park does not pre-enable
; SVME or own VM_HSAVE_PA: each executor installs/restores those on its CPU.
; No architectural SVM provider is attempted for this gang.
hv_boundary_svm_gang_acquire:
    push rbx
    mov rbx, rdi
    cmp qword [rbx + HVB_ACTIVE], 0
    jne cpu_boundary_fail_stop
    cmp qword [rbx + HVB_GUARD], 0
    je cpu_boundary_fail_stop
    cmp qword [rbx + HVB_LEASE], 0
    jne cpu_boundary_fail_stop
    cmp dword [rel vcg_ap], -1
    je .refused
    mov dword [rbx + HVB_SVM], 1
    mov rdx, [rbx + HVB_GUARD]
    mov edi, edx
    call smp_core_custody_acquire_native_guarded
    cmp rax, -1
    je cpu_boundary_fail_stop
    test rax, rax
    jz .refused
    mov [rbx + HVB_LEASE], rax
    mov dword [rbx + HVB_CUSTODY_KIND], 3
    mov dword [rbx + HVB_CORE_STATE], 3
    mov rdi, rbx
    call hv_boundary_guarded_check
    xor eax, eax
    pop rbx
    ret
.refused:
    mov eax, 1
    pop rbx
    ret

; These phase transitions run only on host XCR0/IF0, outside the protected
; inline frontier. Every failed held transition is uncertain, never unwind.
hv_boundary_svm_prepare:
    cmp dword [rdi + HVB_SVM], 1
    jne cpu_boundary_fail_stop
    cmp dword [rdi + HVB_CUSTODY_KIND], 4
    je .native
    cmp dword [rdi + HVB_CUSTODY_KIND], 3
    jne .architectural
.native:
    cmp qword [rdi + HVB_GUARDED_PHASE], 0
    jne cpu_boundary_fail_stop
    push rbx
    mov rbx, rdi
    call hv_boundary_guarded_check
    clgi
    mov qword [rbx + HVB_GUARDED_PHASE], 1
    pop rbx
    ret
.architectural:
    mov rdi, [rdi + HVB_LEASE]
    sub rsp, 8
    call smp_core_custody_svm_prepare
    add rsp, 8
    cmp eax, 1
    jne cpu_boundary_fail_stop
    ret
hv_boundary_svm_transfer:
    cmp dword [rdi + HVB_SVM], 1
    jne cpu_boundary_fail_stop
    cmp dword [rdi + HVB_CUSTODY_KIND], 4
    je .native
    cmp dword [rdi + HVB_CUSTODY_KIND], 3
    jne .architectural
.native:
    cmp qword [rdi + HVB_GUARDED_PHASE], 1
    jne cpu_boundary_fail_stop
    push rbx
    mov rbx, rdi
    call hv_boundary_guarded_check
    mov qword [rbx + HVB_GUARDED_PHASE], 2
    pop rbx
    ret
.architectural:
    mov rdi, [rdi + HVB_LEASE]
    sub rsp, 8
    call smp_core_custody_svm_transfer
    add rsp, 8
    cmp eax, 1
    jne cpu_boundary_fail_stop
    ret
hv_boundary_svm_land:
    cmp dword [rdi + HVB_SVM], 1
    jne cpu_boundary_fail_stop
    cmp dword [rdi + HVB_CUSTODY_KIND], 4
    je .native
    cmp dword [rdi + HVB_CUSTODY_KIND], 3
    jne .architectural
.native:
    cmp qword [rdi + HVB_GUARDED_PHASE], 2
    jne cpu_boundary_fail_stop
    push rbx
    mov rbx, rdi
    call hv_boundary_guarded_check
    mov qword [rbx + HVB_GUARDED_PHASE], 3
    pop rbx
    ret
.architectural:
    mov rdi, [rdi + HVB_LEASE]
    sub rsp, 8
    call smp_core_custody_svm_land
    add rsp, 8
    cmp eax, 1
    jne cpu_boundary_fail_stop
    ret
hv_boundary_svm_host:
    cmp dword [rdi + HVB_SVM], 1
    jne cpu_boundary_fail_stop
    cmp dword [rdi + HVB_CUSTODY_KIND], 4
    je .native
    cmp dword [rdi + HVB_CUSTODY_KIND], 3
    jne .architectural
.native:
    cmp qword [rdi + HVB_ACTIVE], 0
    jne cpu_boundary_fail_stop
    cmp qword [rdi + HVB_GUARDED_PHASE], 1
    je .guarded
    cmp qword [rdi + HVB_GUARDED_PHASE], 3
    jne cpu_boundary_fail_stop
.guarded:
    push rbx
    mov rbx, rdi
    call hv_boundary_guarded_check
    mov qword [rbx + HVB_GUARDED_PHASE], 0
    stgi
    pop rbx
    ret
.architectural:
    mov rdi, [rdi + HVB_LEASE]
    test rdi, rdi
    jz .clean_acquire_refusal
    sub rsp, 8
    call smp_core_custody_svm_host
    add rsp, 8
    cmp eax, 1
    jne cpu_boundary_fail_stop
    ret
.clean_acquire_refusal:
    ; Acquire never changed owner GIF. No unowned STGI on a clean refusal.
    ret

; Fresh full capture for BOTH operations. Only the native architectural SVM
; provider can supply custody1; equal samples and native facts7 cannot do so.
hv_boundary_select:
    push rbx
    mov rbx, rdi
    ; Replace both outputs on every selection, including failed samples.
    lea rdi, [rbx + HVB_CAPTURE]
    xor eax, eax
    mov ecx, (144 + 96) / 8
    rep stosq
    mov qword [rbx + HVB_STAGE], 2
    mov qword [rbx + HVB_SAMPLE_RC], -2
    mov qword [rbx + HVB_SELECT_RC], -2
    cmp dword [rbx + HVB_SVM], 2
    je .intel
    call hv_boundary_native_amd
    test eax, eax
    jnz .amd
    lea rdi, [rbx + HVB_CAPTURE]
    mov esi, 112
    call cpu_security_sample
    mov [rbx + HVB_SAMPLE_RC], rax
    test rax, rax
    jnz .out
    mov qword [rbx + HVB_CAPTURE + 112], 1
    mov qword [rbx + HVB_CAPTURE + 120], 1
    mov qword [rbx + HVB_CAPTURE + 128], 0
    mov qword [rbx + HVB_CAPTURE + 136], 0
    lea rdi, [rbx + HVB_CAPTURE]
    mov esi, 144
    lea rdx, [rbx + HVB_POLICY]
    mov ecx, 96
    mov qword [rbx + HVB_STAGE], 3
    call cpu_boundary_policy_select
    mov [rbx + HVB_SELECT_RC], rax
    test rax, rax
    jnz .out
    cmp qword [rbx + HVB_POLICY], 0
    jne .refused
    mov qword [rbx + HVB_STAGE], 4
.out:
    pop rbx
    ret
.intel:
    mov rdi, rbx
    call hv_vmx_boundary_owner_check
    cmp eax, 1
    jne .refused
    mov rdi, rbx
    call hv_boundary_intel_held
    mov esi, [rbx + HVB_GUARD]
    lea rdi, [rbx + HVB_CIO]
    call cpu_checked_io_init
    lea rdi, [rbx + HVB_INTEL]
    mov esi, 192
    lea rdx, [rbx + HVB_CIO]
    call cpu_security_intel_sample_checked
    mov [rbx + HVB_SAMPLE_RC], rax
    test rax, rax
    jnz .out
    lea rsi, [rbx + HVB_INTEL]
    lea rdi, [rbx + HVB_CAPTURE]
    mov ecx, 112 / 8
    rep movsq
    mov qword [rbx + HVB_CAPTURE + 112], 1
    mov qword [rbx + HVB_CAPTURE + 120], 1
    xor eax, eax
    cmp dword [rbx + HVB_CORE_STATE], 1
    sete al                          ; legacy projection: guarded remains UNKNOWN0
    mov [rbx + HVB_CAPTURE + 128], rax
    mov qword [rbx + HVB_CAPTURE + 136], 0
    mov qword [rbx + HVB_INTEL + 192], 6
    mov qword [rbx + HVB_INTEL + 200], 1
    mov eax, [rbx + HVB_CORE_STATE]
    mov [rbx + HVB_INTEL + 208], rax
    mov eax, [rbx + HVB_GUARD]
    mov [rbx + HVB_INTEL + 216], rax
    mov qword [rbx + HVB_INTEL + 224], 0
    lea rdi, [rbx + HVB_INTEL]
    mov esi, 232
    lea rdx, [rbx + HVB_POLICY]
    mov ecx, 96
    mov qword [rbx + HVB_STAGE], 3
    call cpu_boundary_policy_select_full_intel
    mov [rbx + HVB_SELECT_RC], rax
    test rax, rax
    jnz .out
    cmp qword [rbx + HVB_POLICY], 0
    jne .refused
    ; SEC classification gaps never refuse v0.73. Execute available reported
    ; mechanisms and software fallbacks; desired/gap fields stay diagnostic.
    mov rax, [rbx + HVB_POLICY + 8]
    and rax, ~7
    jnz .refused
    mov rax, [rbx + HVB_POLICY + 16]
    and rax, ~87
    jnz .refused
    mov rax, [rbx + HVB_POLICY + 24]
    and rax, ~125
    jnz .refused
    mov rdi, rbx
    call hv_boundary_intel_repair_mask
    test eax, eax
    jnz .refused
    mov rdi, rbx
    call hv_boundary_intel_bind
    test eax, eax
    jnz .refused
    jmp .scoped
.amd:
    ; VMX/AIRLOCK may retain AMD diagnostics but cannot claim SVM custody.
    cmp dword [rbx + HVB_SVM], 1
    jne .no_lease
    cmp dword [rbx + HVB_CUSTODY_KIND], 4
    je .native
    cmp dword [rbx + HVB_CUSTODY_KIND], 3
    jne .architectural
.native:
    mov rdi, rbx
    call hv_boundary_guarded_check
    jmp .no_lease
.architectural:
    cmp dword [rbx + HVB_CUSTODY_KIND], 1
    jne cpu_boundary_fail_stop
    mov rdi, [rbx + HVB_LEASE]
    test rdi, rdi
    jz cpu_boundary_fail_stop
    call smp_core_custody_svm_check
    cmp eax, 1
    jne cpu_boundary_fail_stop
    cmp edx, 1                       ; distinct architectural enum, never facts7
    jne cpu_boundary_fail_stop
.no_lease:
    call hv_boundary_amd_flags
    test eax, eax
    jnz .refused
    call idt_gp_fixup_cpu
    cmp eax, -1
    je .refused
    cmp eax, [rbx + HVB_GUARD]         ; full32 identity from actual guard arm
    jne .refused
    mov esi, eax
    lea rdi, [rbx + HVB_CIO]
    call cpu_checked_io_init
    lea rdi, [rbx + HVB_AMD]
    mov esi, 160
    lea rdx, [rbx + HVB_CIO]
    call cpu_security_amd_srso_sample_checked
    mov [rbx + HVB_SAMPLE_RC], rax
    test rax, rax
    jnz .out
    ; Preserve BOUNDSTAT's legacy144-byte diagnostic ABI. Its tail describes
    ; the projection, never the separate checked160/versioned selector input.
    lea rsi, [rbx + HVB_AMD]
    lea rdi, [rbx + HVB_CAPTURE]
    mov ecx, 112 / 8
    rep movsq
    mov qword [rbx + HVB_CAPTURE + 112], 1
    mov qword [rbx + HVB_CAPTURE + 120], 1
    mov qword [rbx + HVB_CAPTURE + 128], 0
    mov qword [rbx + HVB_CAPTURE + 136], 0
    mov qword [rbx + HVB_AMD + 160], 7 ; full default, exact rows only relax
    mov qword [rbx + HVB_AMD + 168], 1
    mov qword [rbx + HVB_AMD + 176], 0
    cmp dword [rbx + HVB_SVM], 1
    jne .custody_selected
    mov eax, [rbx + HVB_CORE_STATE]
    mov [rbx + HVB_AMD + 176], rax ; architectural1 vs guarded UNKNOWN3
.custody_selected:
    mov eax, [rbx + HVB_GUARD]
    mov [rbx + HVB_AMD + 184], rax
    mov qword [rbx + HVB_AMD + 192], 0
    lea rdi, [rbx + HVB_AMD]
    mov esi, 200
    lea rdx, [rbx + HVB_POLICY]
    mov ecx, 96
    mov qword [rbx + HVB_STAGE], 3
    call cpu_boundary_policy_select_full_amd
    mov [rbx + HVB_SELECT_RC], rax
    test rax, rax
    jnz .out
    cmp qword [rbx + HVB_POLICY], 0
    jne .refused
    cmp dword [rbx + HVB_SVM], 1
    jne .refused
    ; Full AMD default executes reported controls and conservative software
    ; actions. Unknown model/patch data remains visible in CBO diagnostics.
    mov rax, [rbx + HVB_POLICY + 8]
    and rax, ~7
    jnz .refused
    mov rax, [rbx + HVB_POLICY + 16]
    or rax, [rbx + HVB_POLICY + 24]
    and rax, ~13
    jnz .refused
.scoped:
    mov qword [rbx + HVB_STAGE], 4
    xor eax, eax
    jmp .out
.refused:
    mov eax, 1
    jmp .out

; Actual VMX caller only, after checked owner controls with IF0 and live guard.
; Acquire0 is a clean refusal; a held invariant failure is uncertain.
hv_boundary_intel_acquire:
    push rbx
    mov rbx, rdi
    cmp qword [rbx + HVB_ACTIVE], 0
    jne cpu_boundary_fail_stop
    cmp qword [rbx + HVB_GUARD], 0
    je cpu_boundary_fail_stop
    cmp qword [rbx + HVB_LEASE], 0
    jne .held
    mov dword [rbx + HVB_SVM], 2
    ; T1-5 S7 (P1): an open gang needs every peer parked, vCPU1's AP among
    ; them. Absence custody (kind 2) parks nobody. One vCPU is unchanged.
    cmp dword [rel vcg_ap], -1
    jne .guarded
    mov rdx, [rbx + HVB_GUARD]
    mov edi, edx
    call smp_core_custody_acquire_intel_absent
    cmp rax, -1
    je cpu_boundary_fail_stop
    test rax, rax
    jz .guarded
    mov dword [rbx + HVB_CUSTODY_KIND], 2
    mov dword [rbx + HVB_CORE_STATE], 1
    jmp .acquired
.guarded:
    mov rdx, [rbx + HVB_GUARD]
    mov edi, edx
    call smp_core_custody_acquire_native_guarded
    cmp rax, -1
    je cpu_boundary_fail_stop
    test rax, rax
    jz .refused
    mov dword [rbx + HVB_CUSTODY_KIND], 3
    mov dword [rbx + HVB_CORE_STATE], 3
.acquired:
    mov [rbx + HVB_LEASE], rax
.held:
    mov rdi, rbx
    call hv_boundary_intel_held
    xor eax, eax
    pop rbx
    ret
.refused:
    mov eax, 1
    pop rbx
    ret

; Held kind and separate fact domains are checked on every use. A provider's
; native facts15 are never interpreted as an architectural custody1 grant.
hv_boundary_intel_held:
    cmp dword [rdi + HVB_SVM], 2
    jne cpu_boundary_fail_stop
    cmp dword [rdi + HVB_CUSTODY_KIND], 4
    je hv_boundary_gang_check
    cmp dword [rdi + HVB_CUSTODY_KIND], 3
    je hv_boundary_guarded_check
    cmp dword [rdi + HVB_CUSTODY_KIND], 2
    jne cpu_boundary_fail_stop
    cmp dword [rdi + HVB_CORE_STATE], 1
    jne cpu_boundary_fail_stop
    mov rdi, [rdi + HVB_LEASE]
    test rdi, rdi
    jz cpu_boundary_fail_stop
    sub rsp, 8
    call smp_core_custody_check_intel_absent
    add rsp, 8
    cmp eax, 1
    jne cpu_boundary_fail_stop
    cmp edx, 1
    jne cpu_boundary_fail_stop
    ret
hv_boundary_guarded_check:
    cmp dword [rdi + HVB_CUSTODY_KIND], 4
    je hv_boundary_gang_check
    cmp dword [rdi + HVB_CUSTODY_KIND], 3
    jne cpu_boundary_fail_stop
    cmp dword [rdi + HVB_CORE_STATE], 3
    jne cpu_boundary_fail_stop
    mov rdi, [rdi + HVB_LEASE]
    test rdi, rdi
    jz cpu_boundary_fail_stop
    sub rsp, 8
    call smp_core_custody_check_native_guarded
    add rsp, 8
    cmp eax, 1
    jne cpu_boundary_fail_stop
    test edx, edx
    jnz cpu_boundary_fail_stop
    cmp ecx, 15
    jne cpu_boundary_fail_stop
    ret
; T1-5 S7 (P2) kind 4: the AP's frame holds a copy of the BSP's live token and
; the park's guard. Still the gang's designated AP, and the provider's gang
; facts16 (never 15, never custody1) for this CPU on this generation.
hv_boundary_gang_check:
    cmp dword [rdi + HVB_CUSTODY_KIND], 4
    jne cpu_boundary_fail_stop
    cmp dword [rdi + HVB_CORE_STATE], 3
    jne cpu_boundary_fail_stop
    cmp dword [rdi + HVB_SVM], 1
    je .mode
    cmp dword [rdi + HVB_SVM], 2
    jne cpu_boundary_fail_stop
.mode:
    mov esi, [rdi + HVB_GANG_CPU]
    cmp esi, [rel vcg_ap]
    jne cpu_boundary_fail_stop
    mov rdx, [rdi + HVB_GUARD]
    mov rdi, [rdi + HVB_LEASE]
    test rdi, rdi
    jz cpu_boundary_fail_stop
    sub rsp, 8
    call smp_core_custody_check_gang_member
    add rsp, 8
    cmp eax, 1
    jne cpu_boundary_fail_stop
    test edx, edx
    jnz cpu_boundary_fail_stop
    cmp ecx, 16
    jne cpu_boundary_fail_stop
    ret

; T1-5 S7 (P2): the designated AP's own frame, in place of arm + acquire. RDI
; frame, RSI the BSP's live token, EDX this logical CPU, RCX the park's guard
; (fault_arm refuses a second guard on one CPU). AP, IF0, in its park. Held
; is checked before return: a miss poisons custody and stops. Never arms,
; acquires, releases or drains; finish leaves the guard to the park.
hv_boundary_gang_bind:
    push rbx
    mov rbx, rdi
    mov qword [rbx + HVB_ACTIVE], 0
    mov qword [rbx + HVB_REQUEST], 0
    mov qword [rbx + HVB_FRONTIER], 0
    mov qword [rbx + HVB_GUARDED_PHASE], 0
    mov qword [rbx + HVB_AMD + 160], 1
    mov qword [rbx + HVB_STAGE], 1
    mov qword [rbx + HVB_SAMPLE_RC], -2
    mov qword [rbx + HVB_SELECT_RC], -2
    mov [rbx + HVB_GUARD], rcx
    mov [rbx + HVB_LEASE], rsi
    mov [rbx + HVB_GANG_CPU], edx
    mov dword [rbx + HVB_SVM], 2
    mov dword [rbx + HVB_CUSTODY_KIND], 4
    mov dword [rbx + HVB_CORE_STATE], 3
    lea rdi, [rbx + HVB_CAPTURE]
    xor eax, eax
    mov ecx, (144 + 96) / 8
    rep stosq
    mov rdi, rbx
    call hv_boundary_intel_held
    xor eax, eax
    pop rbx
    ret

 ; Same guard/token binding, with the actual AMD selector/executor mode.
; The initial bind only validates native gang facts, never samples Intel.
hv_boundary_svm_gang_bind:
    push rbx
    mov rbx, rdi
    call hv_boundary_gang_bind
    mov dword [rbx + HVB_SVM], 1
    mov rdi, rbx
    call hv_boundary_gang_check
    xor eax, eax
    pop rbx
    ret

hv_boundary_intel_release:
    push rbx
    mov rbx, rdi
    cmp qword [rbx + HVB_ACTIVE], 0
    jne .bad_active
    cmp qword [rbx + HVB_FRONTIER], 0
    jne .bad_frontier
    mov rdi, [rbx + HVB_LEASE]
    test rdi, rdi
    jz .done
    cmp dword [rbx + HVB_SVM], 2
    jne .bad_mode
    cmp dword [rbx + HVB_CUSTODY_KIND], 4
    je .gang
    cmp dword [rbx + HVB_CUSTODY_KIND], 3
    jne .absence
    call smp_core_custody_release_native_guarded
    jmp .released
.absence:
    cmp dword [rbx + HVB_CUSTODY_KIND], 2
    jne .bad_kind
    call smp_core_custody_release_intel_absent
.released:
    cmp eax, 1
    jne .bad_provider
    mov qword [rbx + HVB_LEASE], 0
.done:
    pop rbx
    ret
.gang:
    mov qword [rbx + HVB_LEASE], 0      ; a copy only: the owner drains custody
    jmp .done

; Fixed source IDs, not authority or a resumable receipt. No uncertain release.
.bad_active:
    mov edi, 0x201
    jmp cpu_boundary_fail_stop_reason
.bad_frontier:
    mov edi, 0x202
    jmp cpu_boundary_fail_stop_reason
.bad_mode:
    mov edi, 0x203
    jmp cpu_boundary_fail_stop_reason
.bad_kind:
    mov edi, 0x204
    jmp cpu_boundary_fail_stop_reason
.bad_provider:
    mov edi, 0x205
    jmp cpu_boundary_fail_stop_reason

 ; No raw access here. The inline frontier uses only these checked permissions.
hv_boundary_intel_repair_mask:
    xor eax, eax
    mov rcx, [rdi + HVB_POLICY + 16]
    or rcx, [rdi + HVB_POLICY + 24]
    test ecx, 64
    jz .store
    cmp dword [rdi + HVB_INTEL + 144], 1
    jne .bad
    cmp dword [rdi + HVB_INTEL + 32], 1
    jne .srbds
    mov rcx, [rdi + HVB_INTEL + 48]
    bt rcx, 25                       ; GDS_CTRL
    jnc .fb
    or eax, 16
.fb:
    bt rcx, 18                       ; FB_CLEAR_CTRL
    jnc .srbds
    or eax, 8
.srbds:
    bt dword [rdi + HVB_INTEL + 24], 9 ; CPUID SRBDS_CTRL
    jnc .permission
    or eax, 1
.permission:
    test eax, eax
    jz .bad
.store:
    mov [rdi + HVB_INTEL_MCU_MASK], rax
    xor eax, eax
    ret
.bad:
    mov eax, 1
    ret

; Bind the fresh checked capture + exact plan across one protected pair.
; Context6 changes owned SPEC_CTRL and clears only enumerated MCU opt-outs;
; optional cost is not identity. Other active bits, TSX and revision are stable
; under the held generation/writer gate. Exit may never silently select anew.
hv_boundary_intel_bind:
    cmp qword [rdi + HVB_ACTIVE], 0
    jne .compare
    lea rsi, [rdi + HVB_INTEL]
    lea rdx, [rdi + HVB_POLICY + 8]
    lea rdi, [rdi + HVB_INTEL_BIND]
    mov ecx, 192 / 8
    rep movsq
    mov rsi, rdx
    mov ecx, 3
    rep movsq
    xor eax, eax
    ret
.compare:
    xor ecx, ecx
.loop:
    cmp ecx, 56                       ; owned SPEC_CTRL installed by context6
    je .next
    cmp ecx, 88                       ; optional measured sample cost
    je .next
    cmp ecx, 152                      ; compare exact repaired MCU postimage
    je .mcu
    cmp ecx, 40                       ; revision validity, exclude cost validity
    jne .qword
    mov eax, [rdi + HVB_INTEL + rcx]
    cmp eax, [rdi + HVB_INTEL_BIND + rcx]
    jne .changed
    jmp .next
.mcu:
    mov rax, [rdi + HVB_INTEL_BIND + 152]
    mov rdx, [rdi + HVB_INTEL_MCU_MASK]
    not rdx
    and rax, rdx
    cmp rax, [rdi + HVB_INTEL + 152]
    jne .changed
    jmp .next
.qword:
    mov rax, [rdi + HVB_INTEL + rcx]
    cmp rax, [rdi + HVB_INTEL_BIND + rcx]
    jne .changed
.next:
    add ecx, 8
    cmp ecx, 192
    jb .loop
    xor ecx, ecx
.plan:
    mov rax, [rdi + HVB_POLICY + 8 + rcx]
    cmp rax, [rdi + HVB_INTEL_BIND + 192 + rcx]
    jne .changed
    add ecx, 8
    cmp ecx, 24
    jb .plan
    xor eax, eax
    ret
.changed:
    mov eax, 1
    ret

; Native vendor only; preserve the retained frame pointer across CPUID.
hv_boundary_native_amd:
    push rbx
    xor eax, eax
    xor ecx, ecx
    cpuid
    xor eax, eax
    cmp ebx, 0x68747541
    jne .out
    cmp edx, 0x69746e65
    jne .out
    cmp ecx, 0x444d4163
    jne .out
    mov eax, 1
.out:
    pop rbx
    ret

; AMD capture is diagnostic under CPL0, IF0, DF0 and the retained fault guard.
; This check does not establish GIF/NMI/SMI, sibling or serialization custody.
hv_boundary_amd_flags:
    mov ax, cs
    and eax, 3
    jnz .out
    pushfq
    pop rax
    and eax, (1 << 9) | (1 << 10)
.out:
    ret

hv_boundary_enter:
    push rbx
    mov rbx, rdi
    cmp qword [rbx + HVB_ACTIVE], 0
    jne cpu_boundary_fail_stop
    cmp qword [rbx + HVB_GUARD], 0
    je cpu_boundary_fail_stop
    call hv_boundary_select
    test rax, rax
    jnz .out                         ; no executor/state mutation attempted
    mov eax, 1
    cmp dword [rbx + HVB_SVM], 2
    jne .amd_version
    mov eax, 6
    jmp .version_bound
.amd_version:
    cmp dword [rbx + HVB_SVM], 1
    jne .version_bound
    mov rax, [rbx + HVB_AMD + 160]
.version_bound:
    mov [rbx + HVB_REQUEST], rax
    mov rax, [rbx + HVB_POLICY + 8]
    mov [rbx + HVB_REQUEST + 8], rax
    mov rax, [rbx + HVB_POLICY + 16]
    mov [rbx + HVB_REQUEST + 16], rax
    mov qword [rbx + HVB_REQUEST + 24], 0 ; no implemented guest-control interface
    mov qword [rbx + HVB_REQUEST + 32], 0
    mov qword [rbx + HVB_REQUEST + 40], 0
    mov rdi, rbx
    mov esi, 0
    xor edx, edx
    call hv_boundary_cost_stamp
    lea rdi, [rbx + HVB_REQUEST]
    mov esi, 48
    lea rdx, [rbx + HVB_RECEIPT]
    mov ecx, 96
    call cpu_boundary_context_enter
    mov rdi, rbx
    mov esi, 0
    mov edx, 1
    call hv_boundary_cost_stamp
    test rax, rax
    jnz cpu_boundary_fail_stop
    cmp qword [rbx + HVB_RECEIPT], 0
    jne cpu_boundary_fail_stop
    cmp qword [rbx + HVB_RECEIPT + 56], 2
    jne cpu_boundary_fail_stop
    cmp qword [rbx + HVB_RECEIPT + 40], 0
    je cpu_boundary_fail_stop
    mov qword [rbx + HVB_ACTIVE], 1
    mov qword [rbx + HVB_FRONTIER], 1
    mov rdi, rbx
    call hv_boundary_exec_enter
    xor eax, eax
.out:
    pop rbx
    ret

hv_boundary_exit:
    push rbx
    mov rbx, rdi
    cmp qword [rbx + HVB_ACTIVE], 1
    jne cpu_boundary_fail_stop
    cmp qword [rbx + HVB_GUARD], 0
    je cpu_boundary_fail_stop
    cmp qword [rbx + HVB_FRONTIER], 3
    jne cpu_boundary_fail_stop
    call hv_boundary_select            ; current legitimate floor, never stale restore
    test rax, rax
    jnz cpu_boundary_fail_stop
    ; A changed policy version across the pair is never a new grant.
    cmp dword [rbx + HVB_SVM], 2
    jne .amd_version
    cmp qword [rbx + HVB_REQUEST], 6
    jne cpu_boundary_fail_stop
    jmp .version_bound
.amd_version:
    cmp dword [rbx + HVB_SVM], 1
    jne .legacy_version
    mov rax, [rbx + HVB_AMD + 160]
    cmp rax, [rbx + HVB_REQUEST]
    jne cpu_boundary_fail_stop
    jmp .version_bound
.legacy_version:
    mov qword [rbx + HVB_REQUEST], 1
.version_bound:
    mov rax, [rbx + HVB_POLICY + 8]
    mov [rbx + HVB_REQUEST + 8], rax
    mov rax, [rbx + HVB_POLICY + 24]
    mov [rbx + HVB_REQUEST + 16], rax
    mov qword [rbx + HVB_REQUEST + 24], 0
    mov rax, [rbx + HVB_RECEIPT + 40]
    mov [rbx + HVB_REQUEST + 32], rax
    mov qword [rbx + HVB_REQUEST + 40], 0
    mov rdi, rbx
    mov esi, 1
    xor edx, edx
    call hv_boundary_cost_stamp
    lea rdi, [rbx + HVB_REQUEST]
    mov esi, 48
    lea rdx, [rbx + HVB_RECEIPT]
    mov ecx, 96
    call cpu_boundary_context_exit
    mov rdi, rbx
    mov esi, 1
    mov edx, 1
    call hv_boundary_cost_stamp
    test rax, rax
    jnz cpu_boundary_fail_stop
    cmp qword [rbx + HVB_RECEIPT], 0
    jne cpu_boundary_fail_stop
    cmp qword [rbx + HVB_RECEIPT + 56], 3
    jne cpu_boundary_fail_stop
    mov qword [rbx + HVB_ACTIVE], 0
    mov qword [rbx + HVB_FRONTIER], 0
    xor eax, eax
    pop rbx
    ret

; Caller restores CRs/MSRs/XCR0 first, with IF0 still held, then releases this
; exact guard. Caller restores its original RFLAGS only after this returns.
hv_boundary_finish:
    push rbx
    mov rbx, rdi
    cmp qword [rbx + HVB_ACTIVE], 0
    jne cpu_boundary_fail_stop
    mov rdi, [rbx + HVB_LEASE]
    test rdi, rdi
    jz .disarm
    ; Caller has restored host CR/MSR/XCR0 with IF0. Release exact owner only;
    ; failure retains custody and guard, never proceeds to a host return.
    cmp dword [rbx + HVB_CUSTODY_KIND], 4
    jne .owner
    cmp qword [rbx + HVB_GUARDED_PHASE], 0
    jne cpu_boundary_fail_stop
    ; The owner has already published RELEASE when the AP departs. A held
    ; provider check here would poison that valid departure. Phase0 is the
    ; closed local fact; finish relinquishes only the token/guard copies.
    mov qword [rbx + HVB_LEASE], 0
    jmp .disarm
.owner:
    cmp dword [rbx + HVB_SVM], 2
    je .intel_release
    cmp dword [rbx + HVB_SVM], 1
    jne cpu_boundary_fail_stop
    cmp dword [rbx + HVB_CUSTODY_KIND], 3
    jne .svm_release
    cmp qword [rbx + HVB_GUARDED_PHASE], 0
    jne cpu_boundary_fail_stop
    call smp_core_custody_release_native_guarded
    jmp .svm_released
.svm_release:
    call smp_core_custody_release_svm
.svm_released:
    cmp eax, 1
    jne cpu_boundary_fail_stop
    mov qword [rbx + HVB_LEASE], 0
    jmp .disarm
.intel_release:
    mov rdi, rbx
    call hv_boundary_intel_release
.disarm:
    cmp dword [rbx + HVB_CUSTODY_KIND], 4
    je .gang_guard
    mov rdi, [rbx + HVB_GUARD]
    test rdi, rdi
    jz .done                         ; arm refused before any state mutation
    call cpu_boundary_fault_disarm
    test rax, rax
    jnz cpu_boundary_fail_stop
    mov qword [rbx + HVB_GUARD], 0
.done:
    xor eax, eax
    pop rbx
    ret
.gang_guard:
    mov qword [rbx + HVB_GUARD], 0      ; the park armed it and disarms it at departure
    jmp .done
