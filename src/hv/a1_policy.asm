;; MODULE hv/a1_policy
;; LAYER 5
;; EXPORTS a1_policy_check
;; IMPORTS hv/vm_profile
;; OWNER rc-vm-claude
;
; A1 trusted network mode: signed policy/profile binding, not an attach grant.
; The eventual original owner START must explicitly select this policy and
; pass fresh topology/requester/reset predicates. Legacy selection never calls
; this API. The v1 profile flags/reserved bytes keep their existing meaning.
;
; Both copies of the profile come from the same compiler-produced include in
; the signed payload. Pin every byte, including both artifact lengths/hashes,
; unused dependency slots and reserved fields. No caller-provided hash or
; profile copy is authority. Kernel image memory is host-owned and immutable
; to guests, as for the existing signed built-in profile table.

A1P_MAGIC       equ 0x31503141          ; "A1P1"
A1P_VERSION     equ 1
A1P_MODE        equ 1                   ; general trusted network guest
A1P_P2P_RISK    equ 1                   ; accepted shared-group peer reach
A1P_PROFILE     equ 16                  ; signed delta from descriptor to built-in profile
A1P_IMAGE       equ 32                  ; complete VP v1 image, not a hash prefix
A1P_BYTES       equ A1P_IMAGE + VP_BYTES

A1P_OK          equ 0
A1P_E_AUTHORITY equ 1
A1P_E_LENGTH    equ 2
A1P_E_POLICY    equ 3
A1P_E_PIN       equ 4
A1P_E_PROFILE   equ 5

; a1_policy_check(RDI=policy, RSI=exact policy bytes,
;                 RDX=profile, RCX=exact profile bytes) -> EAX=A1P status.
; Serialized native guest-control caller. Preserves SysV callee-saved registers;
; no persistent writes, device access, selection or lifecycle changes.
; Invalid addresses are rejected by pointer identity before dereference.
a1_policy_check:
    mov eax, A1P_E_LENGTH
    cmp rsi, A1P_BYTES
    jne .out ; exact policy extent
    cmp rcx, VP_BYTES
    jne .out ; exact profile extent
%ifdef PAOS_DRIVER_DOMAIN_PROFILE_INC
    lea rax, [rel a1_policy_network]
    cmp rdi, rax
    jne .authority ; exact signed descriptor
    lea rax, [rel vp_driver_domain]
    cmp rdx, rax
    jne .authority ; exact original built-in profile

    mov eax, A1P_E_POLICY
    cmp dword [rdi], A1P_MAGIC
    jne .out
    cmp word [rdi+4], A1P_VERSION
    jne .out
    cmp word [rdi+6], A1P_BYTES
    jne .out
    cmp dword [rdi+8], A1P_MODE
    jne .out ; mode identity
    cmp dword [rdi+12], A1P_P2P_RISK
    jne .out ; explicit accepted P2P policy
    mov r8, [rdi+A1P_PROFILE]
    add r8, rdi                        ; resolve signed descriptor-relative delta
    cmp r8, rdx
    jne .out ; exact signed profile binding
    cmp dword [rdi+24], VP_BYTES
    jne .out
    cmp dword [rdi+28], 0
    jne .out

    push rbx
    mov rbx, rdx
    lea rsi, [rdi+A1P_IMAGE]
    mov rdi, rdx
    mov ecx, VP_BYTES
    cld
    repe cmpsb
    mov eax, A1P_E_PIN
    jne .checked_out ; complete profile image
    mov eax, A1P_E_PROFILE
    cmp byte [rbx+VP_CLASS], VP_CLASS_CLI
    jne .checked_out
    cmp dword [rbx+VP_VCPUS], 1
    jne .checked_out
    cmp dword [rbx+VP_DEVICES], VP_DEV_NICDOMAIN
    jne .checked_out ; network-only closure
    mov rdi, rbx
    mov esi, VP_BYTES
    call vm_profile_validate
    test eax, eax
    jz .checked_out
    mov eax, A1P_E_PROFILE
.checked_out:
    pop rbx
    ret
%endif
.authority:
    mov eax, A1P_E_AUTHORITY
.out:
    ret

%ifdef PAOS_DRIVER_DOMAIN_PROFILE_INC
align 8, db 0
a1_policy_network:
    dd A1P_MAGIC
    dw A1P_VERSION, A1P_BYTES
    dd A1P_MODE, A1P_P2P_RISK
    dq vp_driver_domain - a1_policy_network
    dd VP_BYTES, 0
%include PAOS_DRIVER_DOMAIN_PROFILE_INC
.end:
%if a1_policy_network.end - a1_policy_network != A1P_BYTES
    %error "A1 policy must bind one complete compiler-produced VP record"
%endif
%endif
