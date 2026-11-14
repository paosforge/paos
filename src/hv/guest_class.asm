;; MODULE hv/guest_class
%include "core/abi/build_profile.inc"
;; LAYER 5
;; EXPORTS guest_class_init, guest_class_validate, guest_class_register, guest_class_set_posture, guest_class_launch, guest_class_registry, guest_class_host_context
;; IMPORTS core/lib/mem, hv/vmx, hv/browser_appliance
;; CAPS
;; OWNER saga:android_guest
; Task3346. Fixed little-endian v1 wire record; no host pointers on the wire.
; GUEST_WINDOW SPAWN(profile class) is a design seam, not an existing verb.
; This is its native class-parametric entry, over hv_guest_linux_request_start.
; Budgets are ceilings, not a claim that the selected runtime provides Android,
; SMP, a disk, credentials, or encryption. Profile 1 is the EXISTING normal
; Linux artifact selector. No new guest runtime is registered by this module.
;
; SysV ABI; caller-saved registers clobbered. Input spans must be host-readable.
; Registry writes are boot/owner-serialized; publish count LAST. Launch uses a
; private descriptor snapshot and cannot consume mutable caller fields later.

GC_VERSION       equ 0                  ; u32 = 1
GC_SIZE          equ 4                  ; u32 = 96, exact input extent required
GC_NAME          equ 8                  ; 24 bytes, canonical NUL + zero padding
GC_POSTURE       equ 32                 ; u8: 0 ephemeral, 1 persistent-credentialed
GC_REQUIRED      equ 33                 ; u8: derived from posture, never optional
GC_NETWORK       equ 34                 ; u8: 0 data-out, 1 mediated, 2 no-inbound
GC_FLAGS         equ 35                 ; u8: must be zero in v1
GC_VCPUS         equ 36                 ; u32, 1..256
GC_RAM           equ 40                 ; u64 bytes, 1..1 TiB
GC_STORAGE       equ 48                 ; u64 bytes, 1..1 PiB
GC_PROFILE       equ 56                 ; opaque runtime profile handle; v1 = 1
GC_BINDING       equ 64                 ; opaque credential capability slot; 0 empty
GC_RESERVED      equ 72                 ; 24 zero bytes
GC_BYTES         equ 96
GC_REG_BYTES     equ 8 + 2 * GC_BYTES    ; count:u32, reserved:u32, 2 owned records
GC_RAM_MAX       equ 1 << 40
GC_STORAGE_MAX   equ 1 << 50
GC_PROFILE_NORMAL equ 1

GC_OK            equ 0
GC_BAD_LENGTH    equ 1
GC_BAD_VERSION   equ 2
GC_BAD_ENUM      equ 3
GC_BAD_FLAGS     equ 4
GC_BAD_BINDING   equ 5
GC_BAD_BUDGET    equ 6
GC_BAD_NAME      equ 7
GC_DUPLICATE     equ 8
GC_FULL          equ 9
GC_OWNER_ENCRYPTION_REQUIRED equ 10
GC_RUNTIME_UNAVAILABLE equ 11
GC_BAD_REQUEST   equ 12
GC_QUEUED        equ 13
GC_RUNTIME_BUSY  equ 14                 ; the one vCPU seam is running, loading or queued

; Host-private launch context (NOT wire input, never a caller-supplied Boolean).
; A future L0-FDE issuer owns these immutable capability records and revocation
; generation. AN4's production context has no capability, issuer, or vault.
GC_CTX_OWNER     equ 0
GC_CTX_VOLUME    equ 8
GC_CTX_GENERATION equ 16
GC_CTX_CAP       equ 24                 ; opaque handle
GC_CTX_CAP_OWNER equ 32
GC_CTX_CAP_VOLUME equ 40
GC_CTX_CAP_GENERATION equ 48
GC_CTX_CAP_RIGHTS equ 56                ; exactly owner-bound encrypted storage=1
GC_CTX_START     equ 64                 ; trusted continuation, runtime LEA only
GC_CTX_BYTES     equ 72

; Caller-owned result. Counters record crossing resource boundaries; ELIGIBLE
; is deliberately distinct from QUEUED and from any actual guest launch proof.
GC_R_STATUS      equ 0
GC_R_ELIGIBLE    equ 4
GC_R_DISK        equ 8
GC_R_NET         equ 12
GC_R_CREDENTIAL  equ 16
GC_R_VM          equ 20
GC_R_LAUNCH      equ 24
GC_R_GATE        equ 28
GC_R_BACKEND     equ 32
GC_RESULT_BYTES  equ 40

; RDI=descriptor, ESI=posture. Constructor derives the required bit; validation
; independently rejects an inconsistent serialized bit (including attempts to
; clear it). No implicit credential binding is ever created or looked up.
guest_class_set_posture:
    cmp esi, 1
    ja .bad
    mov [rdi + GC_POSTURE], sil
    mov [rdi + GC_REQUIRED], sil
    xor eax, eax
    ret
.bad:
    mov eax, GC_BAD_ENUM
    ret

; RDI=record, RSI=EXACT span length. EAX=typed status. Writes nothing.
guest_class_validate:
    sub rsp, 8                          ; SysV alignment for bounded name helpers
    mov eax, GC_BAD_LENGTH
    cmp rsi, GC_BYTES
    jne .out
    test rdi, rdi
    jz .out
    cmp dword [rdi + GC_SIZE], GC_BYTES
    jne .out
    mov eax, GC_BAD_VERSION
    cmp dword [rdi + GC_VERSION], 1
    jne .out
    mov eax, GC_BAD_ENUM
    cmp byte [rdi + GC_POSTURE], 1
    ja .out
    cmp byte [rdi + GC_NETWORK], 2
    ja .out
    cmp qword [rdi + GC_PROFILE], GC_PROFILE_NORMAL
    jne .out
    mov eax, GC_BAD_FLAGS
    mov dl, [rdi + GC_POSTURE]
    cmp dl, [rdi + GC_REQUIRED]
    jne .out
    cmp byte [rdi + GC_FLAGS], 0
    jne .out
    mov rdx, [rdi + GC_RESERVED]
    or rdx, [rdi + GC_RESERVED + 8]
    or rdx, [rdi + GC_RESERVED + 16]
    jnz .out
    mov eax, GC_BAD_BINDING
    cmp byte [rdi + GC_POSTURE], 0
    jne .budget
    cmp qword [rdi + GC_BINDING], 0
    jne .out
.budget:
    mov eax, GC_BAD_BUDGET
    mov edx, [rdi + GC_VCPUS]
    dec rdx
    cmp rdx, 255
    ja .out
    mov rdx, [rdi + GC_RAM]
    dec rdx
    mov rcx, GC_RAM_MAX - 1
    cmp rdx, rcx
    ja .out
    mov rdx, [rdi + GC_STORAGE]
    dec rdx
    mov rcx, GC_STORAGE_MAX - 1
    cmp rdx, rcx
    ja .out
    ; Compare the complete fixed name, including its terminator and padding.
    ; This both bounds the reader and rejects aliases/trailing/hidden fields.
    lea rsi, [rel gc_mobile + GC_NAME]
    call gc_name_equal
    test eax, eax
    jnz .ok
    lea rsi, [rel gc_agent + GC_NAME]
    call gc_name_equal
    test eax, eax
    jnz .ok
    mov eax, GC_BAD_NAME
    jmp .out
.ok:
    xor eax, eax
.out:
    add rsp, 8
    ret

; RDI=descriptor, RSI=canonical 24-byte name. No unbounded string primitive.
gc_name_equal:
    mov rax, [rdi + GC_NAME]
    xor rax, [rsi]
    mov rdx, [rdi + GC_NAME + 8]
    xor rdx, [rsi + 8]
    or rax, rdx
    mov rdx, [rdi + GC_NAME + 16]
    xor rdx, [rsi + 16]
    or rax, rdx
    sete al
    movzx eax, al
    ret

; RDI=descriptor, RSI=length, RDX=host-owned GC_REG_BYTES registry.
; Validate a private copy before publication; rejection changes ZERO registry
; bytes (not even an error flag). No guest allocation occurs in this routine.
guest_class_register:
    push rbx
    push r12
    sub rsp, GC_BYTES + 8
    mov rbx, rdx
    cmp rsi, GC_BYTES
    jne .length
    test rdi, rdi
    jz .length
    mov rsi, rdi
    mov rdi, rsp
    mov edx, GC_BYTES
    call memcpy
    mov rdi, rsp
    mov esi, GC_BYTES
    call guest_class_validate
    test eax, eax
    jnz .out
    cmp dword [rbx], 2
    ja .full
    xor r12d, r12d
.scan:
    cmp r12d, [rbx]
    jae .publish
    imul esi, r12d, GC_BYTES
    lea rsi, [rbx + rsi + 8 + GC_NAME]
    mov rdi, rsp
    call gc_name_equal
    test eax, eax
    jnz .duplicate
    inc r12d
    jmp .scan
.publish:
    cmp r12d, 2
    jae .full
    imul edi, r12d, GC_BYTES
    lea rdi, [rbx + rdi + 8]
    mov rsi, rsp
    mov edx, GC_BYTES
    call memcpy
    inc dword [rbx]                      ; publish only the complete owned copy
    xor eax, eax
    jmp .out
.length:
    mov eax, GC_BAD_LENGTH
    jmp .out
.duplicate:
    mov eax, GC_DUPLICATE
    jmp .out
.full:
    mov eax, GC_FULL
.out:
    add rsp, GC_BYTES + 8
    pop r12
    pop rbx
    ret

; RDI=descriptor, RSI=length, RDX=TRUSTED host context, RCX=opaque cap
; handle, R8D=0 eligibility / 1 request start, R9=result (40 writable bytes).
; ONLY the keep chooses context/continuation; neither is a descriptor field or
; accepted from the guest/command wire. KATs use an isolated context, never mint
; a capability in guest_class_host_context. Gate precedes even continuation
; lookup. This same entry is the class-parametric launch path, not a parser KAT.
guest_class_launch:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, GC_BYTES + 16
    mov rbx, r9
    mov r12, rdx
    mov r13, rcx
    mov r14d, r8d
    mov r15, rdi
    mov [rsp + GC_BYTES], rsi
    mov rdi, rbx
    xor esi, esi
    mov edx, GC_RESULT_BYTES
    call memset
    mov eax, GC_BAD_REQUEST
    cmp r14d, 1
    ja .done
    test r12, r12
    jz .done
    mov eax, GC_BAD_LENGTH
    cmp qword [rsp + GC_BYTES], GC_BYTES
    jne .done
    test r15, r15
    jz .done
    mov rdi, rsp
    mov rsi, r15
    mov edx, GC_BYTES
    call memcpy
    mov rdi, rsp
    mov esi, GC_BYTES
    call guest_class_validate
    test eax, eax
    jnz .done
    inc dword [rbx + GC_R_GATE]
    ; Derive the security requirement from POSTURE again, never trust a flag
    ; whose accidental clearing could turn a credentialed guest ephemeral.
    cmp byte [rsp + GC_POSTURE], 0
    je .eligible
    mov eax, GC_OWNER_ENCRYPTION_REQUIRED
    test r13, r13
    jz .done
    cmp r13, [r12 + GC_CTX_CAP]
    jne .done
    cmp qword [r12 + GC_CTX_CAP_RIGHTS], 1
    jne .done
    mov rdx, [r12 + GC_CTX_OWNER]
    test rdx, rdx
    jz .done
    cmp rdx, [r12 + GC_CTX_CAP_OWNER]
    jne .done
    mov rdx, [r12 + GC_CTX_VOLUME]
    test rdx, rdx
    jz .done
    cmp rdx, [r12 + GC_CTX_CAP_VOLUME]
    jne .done
    mov rdx, [r12 + GC_CTX_GENERATION]
    test rdx, rdx
    jz .done
    cmp rdx, [r12 + GC_CTX_CAP_GENERATION]
    jne .done
.eligible:
    mov dword [rbx + GC_R_ELIGIBLE], 1
    xor eax, eax
    test r14d, r14d
    jz .done                            ; eligibility earns NO resource use
    mov eax, GC_RUNTIME_UNAVAILABLE
    mov rdx, [r12 + GC_CTX_START]
    test rdx, rdx
    jz .done
    inc dword [rbx + GC_R_BACKEND]
    mov rdi, rsp
    mov rsi, rbx
    call rdx                            ; first possible side-effect boundary
.done:
    mov [rbx + GC_R_STATUS], eax
    add rsp, GC_BYTES + 16
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Production continuation for the existing normal, no-credential artifact
; profile. No vault/encrypted runtime exists: even a future capability cannot
; make this backend persist credentials. Class callers get a typed refusal.
; The old GUESTVM/BROWSERIMG callers and their policy remain unchanged.
gc_runtime_start:
    mov eax, GC_RUNTIME_UNAVAILABLE
    cmp byte [rdi + GC_POSTURE], 0
    jne .out
    cmp qword [rdi + GC_PROFILE], GC_PROFILE_NORMAL
    jne .out
    cmp qword [rdi + GC_RAM], HV_LINUX_NORMAL_RAM_BYTES
    jb .out
    ; RCQ-18 (SEC CS-C1): refuse a busy seam before deselection, the selector or
    ; a START request, like gws_run. Busy is any nonzero byte of running, the
    ; loader's start_active or a queued run_req; then ram_bytes, fb_bytes and the
    ; START generation of the guest that owns the seam never move.
    mov eax, GC_RUNTIME_BUSY
    movzx ecx, byte [rel hv_linux_running]
    or cl, [rel hv_linux_start_active]
    or cl, [rel hv_linux_run_req]
    jnz .out
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    cmp byte [rel hv_vcon_pmr_bound], 0
    jne .out                            ; RCQ-37: the media owner holds the vCPU seam
%endif
%endif
    push rbx
    mov rbx, rsi
%if !PAOS_PUBLIC_BUILD
    call browser_appliance_deselect
%endif
    call hv_linux_select_default_artifacts
    call hv_guest_linux_request_start
    inc dword [rbx + GC_R_LAUNCH]         ; request queued, NOT a VM boot result
    mov eax, GC_QUEUED
    pop rbx
.out:
    ret

; Boot-only initialization. Exactly two class shapes; default bindings EMPTY.
guest_class_init:
    push rbx
    cmp dword [rel guest_class_registry], 2
    je .ok
    lea rdi, [rel guest_class_registry]
    xor esi, esi
    mov edx, GC_REG_BYTES
    call memset
    lea rdi, [rel gc_mobile]
    mov esi, GC_BYTES
    lea rdx, [rel guest_class_registry]
    call guest_class_register
    test eax, eax
    jnz .fail
    lea rdi, [rel gc_agent]
    mov esi, GC_BYTES
    lea rdx, [rel guest_class_registry]
    call guest_class_register
    test eax, eax
    jnz .fail
    lea rax, [rel gc_runtime_start]
    mov [rel guest_class_host_context + GC_CTX_START], rax
.ok:
    xor eax, eax
    pop rbx
    ret
.fail:
    mov ebx, eax
    lea rdi, [rel guest_class_registry]
    xor esi, esi
    mov edx, GC_REG_BYTES
    call memset
    mov eax, ebx
    pop rbx
    ret

align 8
gc_mobile:
    dd 1, GC_BYTES
    db 'mobile', 0
    times 17 db 0
    db 0, 0, 0, 0
    dd 2
    dq 2 << 30, 2 << 30, GC_PROFILE_NORMAL, 0
    times 24 db 0
.end:
%if gc_mobile.end - gc_mobile != GC_BYTES
    %error "mobile descriptor must be exactly GC_BYTES"
%endif
gc_agent:
    dd 1, GC_BYTES
    db 'credentialed-agent', 0
    times 5 db 0
    db 1, 1, 1, 0
    dd 2
    dq 2 << 30, 2 << 30, GC_PROFILE_NORMAL, 0
    times 24 db 0
.end:
%if gc_agent.end - gc_agent != GC_BYTES
    %error "credentialed-agent descriptor must be exactly GC_BYTES"
%endif
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_hv_guest_class_0 0
guest_class_registry: resb GC_REG_BYTES
guest_class_host_context: resb GC_CTX_BYTES
%endmacro
WDATA_BSS_DEFER WDATA_hv_guest_class_0
