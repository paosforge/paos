;; MODULE hv/driver_domain_a1probe
;; LAYER 5
;; EXPORTS nd_a1_probe, a1_original_method
;; IMPORTS hv/driver_domain, hv/a1_reset_dispatch, core/time, boot/smbios
;; CAPS
;; OWNER rc-vm-claude
;; CONTEXT: bsp_only
%include "hv/a1_reset.inc"
; Original A1 START R2 op1 caller (VM contract LEDGER118425). The loader calls
; this once, after the third fresh A1NS comparison, nd_owner and the original
; call budget, and BEFORE pool clearing or any device/DMA write. It builds one
; resident A1RQ320 from the frozen original tuple and asks the dispatcher for
; op1 (PCI config/MMIO READS only) on the exact family method. The A1RS256 is
; retained as an observation in native custody. Nothing here grants attach,
; reset, quiesce, mapping, readiness, reclaim or qualification; the caller
; stops this START with 46 whatever the probe status is.
;
; Not supplied (zero) because no op1 leaf consumes them and no op1 effect
; depends on them: policy/profile/kernel/initrd/snapshot SHA-256 and the held
; domain cookie (no domain is held). Any mutating op owes them first.

ND_A1_RESERVE_MS equ 1000      ; caller keeps >=1s of the original budget to stop
A1N_E_METHOD     equ 47        ; no exact family method for the selected function
A1N_E_BUDGET     equ 48        ; no calibrated TSC or original budget left for op1
%if ND_A1_PRIVATE_QWORDS*8 != A1_RQ_BYTES+A1_MP_BYTES+A1_RS_BYTES+8
%error nd_a1 private operand layout drifted from the R2 ABI
%endif

; a1_original_method(EDI=selected vendor/device dword) -> EAX=method or 0.
; Exact table, no fallback. 10ec:8168 is shared by HP RTL8168ep and Beelink
; RTL8168H: the pre-EBS SMBIOS HP identity (smbios_hp_phase0, already the HP
; quirk key) decides, and an unresolved or failed SMBIOS read refuses. The
; Beelink leaf rechecks XID itself. HP 0x10001 is only an op1 discovery label;
; the method bound for ops2..5 is AMD's qualified choice under a new attempt.
a1_original_method:
    cmp edi, 0x816110ec
    je .lenovo
    cmp edi, 0x15d78086
    je .dell
    cmp edi, 0x500010ec
    je .msi
    cmp edi, 0x816810ec
    jne .none
    cmp byte [rel smbios_identity_resolved], 1
    jne .none
    cmp dword [rel smbios_identity_state], 0     ; SMB_ST_OK
    jne .none
    movzx eax, byte [rel smbios_hp_phase0]
    cmp eax, 1
    je .hp
    test eax, eax
    jnz .none
    mov eax, A1_METHOD_BEELINK_RTL8168H
    ret
.hp:
    mov eax, A1_METHOD_HP_PCIE_FLR
    ret
.lenovo:
    mov eax, A1_METHOD_LENOVO_RTL8161
    ret
.dell:
    mov eax, A1_METHOD_DELL_I219
    ret
.msi:
    mov eax, A1_METHOD_MSI_E5000B
    ret
.none:
    xor eax, eax
    ret

; nd_a1_probe(RDI=original nd_prepare call-start ms) -> EAX=0 dispatched
; (A1RS retained, any status), or A1N 40/47/48 refused before the dispatcher.
; Caller has just refreshed nd_clock_ms. Preserves SysV callee-saved state.
nd_a1_probe:
    push rbx
    push r12
    push r13                         ; RSP now 16-aligned for calls
    mov r12, rdi
    lea rdi, [rel nd_a1_request]     ; request, map, result, scope are contiguous
    xor eax, eax
    mov ecx, ND_A1_PRIVATE_QWORDS
    cld
    rep stosq
    mov edi, [rel nd_a1_original+12]
    call a1_original_method
    mov ebx, eax
    mov eax, A1N_E_METHOD
    test ebx, ebx
    jz .out
    mov eax, 40                      ; A1N_E_ARGUMENT: frozen tuple disagrees
    mov edx, [rel nd_a1_original+8]
    cmp edx, [rel nd_bdf]
    jne .out
    lea r13, [rel nd_a1_request]
    mov dword [r13+A1_RQ_MAGIC], 'A1RQ'
    mov dword [r13+A1_RQ_VERSION], (A1_RQ_BYTES<<16)|A1_ABI_VERSION
    mov [r13+A1_RQ_METHOD], ebx
    mov dword [r13+A1_RQ_OP], A1_OP_PROBE
    mov dword [r13+A1_RQ_MODE], A1_MODE_TRUSTED_NETWORK
    mov dword [r13+A1_RQ_INTENT], A1_INTENT_ATTACH
    mov [r13+A1_RQ_BDF], edx
    mov [rel nd_a1_scope], edx       ; selected function only, never a group
    mov eax, [rel nd_a1_original+12]
    mov [r13+A1_RQ_VENDEV], eax
    mov eax, [rel nd_a1_original+16]
    mov [r13+A1_RQ_CLASSREV], eax
    mov eax, [rel nd_a1_original+64+0x2c]
    mov [r13+A1_RQ_SUBSYSTEM], eax
    mov rax, [rel nd_generation]
    mov [r13+A1_RQ_START], rax
    mov eax, [rel hv_linux_start_gen]
    mov [r13+A1_RQ_GENERATION], rax
    mov rax, [rel nd_attempt]
    mov [r13+A1_RQ_ATTEMPT], rax
    lea rax, [rel nd_a1_original]
    mov [r13+A1_RQ_SNAPSHOT], rax
    mov dword [r13+A1_RQ_SNAPSHOT_BYTES], 608
    mov dword [r13+A1_RQ_SCOPE_COUNT], 1
    lea rax, [rel nd_a1_scope]
    mov [r13+A1_RQ_SCOPE], rax
    mov eax, [rel nd_a1_original+24]
    mov [r13+A1_RQ_BACKEND], eax
    ; Exact 16 lowercase hex native nonce -> u64 (injective, never truncated).
    lea rsi, [rel nd_nonce]
    xor eax, eax
    mov ecx, 16
.hex:
    movzx edx, byte [rsi]
    sub edx, '0'
    cmp edx, 9
    jbe .digit
    sub edx, 'a'-'0'
    cmp edx, 5
    ja .argument
    add edx, 10
.digit:
    shl rax, 4
    or rax, rdx
    inc rsi
    dec ecx
    jnz .hex
    test rax, rax
    jz .argument
    mov [r13+A1_RQ_NONCE], rax
    ; Family MMIO window from the ORIGINAL config BAR (no sizing, no new map).
    ; The leaf independently checks the identity UC PDE and the live BAR.
    cmp ebx, A1_METHOD_MSI_E5000B
    je .budget_check                 ; config-only family: no map descriptor
    mov ecx, 0x10                    ; Dell I219 BAR0
    mov r8d, 0x4000
    xor r9d, r9d
    cmp ebx, A1_METHOD_DELL_I219
    je .bar
    mov ecx, 0x18                    ; Realtek BAR2 (HP, Lenovo, Beelink)
    mov r8d, 0x1000
    mov r9d, 2
.bar:
    lea rsi, [rel nd_a1_original+64]
    mov eax, [rsi+rcx]
    test al, 1
    jnz .budget_check                ; I/O BAR: leaf reports no map
    mov edx, eax
    and edx, 6
    and eax, ~15
    cmp edx, 4
    je .wide
    test edx, edx
    jnz .budget_check
    jmp .base
.wide:
    mov edx, [rsi+rcx+4]
    shl rdx, 32
    or rax, rdx
.base:
    test rax, rax
    jz .budget_check
    lea rdi, [rel nd_a1_map]
    mov dword [rdi+A1_MP_MAGIC], 'A1MP'
    mov dword [rdi+A1_MP_VERSION], (A1_MP_BYTES<<16)|A1_ABI_VERSION
    mov [rdi+A1_MP_BAR_VA], rax
    mov [rdi+A1_MP_SPAN], r8
    mov [rdi+A1_MP_BAR_INDEX], r9d
    mov dword [rdi+A1_MP_ACCESS], 1  ; READ only
    mov rax, [rel nd_generation]
    mov [rdi+A1_MP_GENERATION], rax
    mov [rdi+A1_MP_START], rax
    mov [r13+A1_RQ_MAPPING_GENERATION], rax
    mov eax, [rel nd_bdf]
    mov [rdi+A1_MP_BDF], eax
    mov [r13+A1_RQ_MAPPING], rdi
    mov dword [r13+A1_RQ_MAPPING_BYTES], A1_MP_BYTES
.budget_check:
    ; Original absolute budget, no new window: min(start+ND_CALL_MS, boot cap).
    mov rax, [rel tsc_khz]
    test rax, rax
    jz .budget
    cmp rax, 10000000
    ja .budget
    lea rcx, [r12+ND_CALL_MS]
    cmp rcx, ND_BOOT_MS
    jbe .capped
    mov ecx, ND_BOOT_MS
.capped:
    mov rdx, [rel nd_clock_ms]
    cmp rdx, rcx
    jae .budget
    sub rcx, rdx
    cmp rcx, ND_A1_RESERVE_MS
    jbe .budget
    mov [r13+A1_RQ_TSC_KHZ], rax
    imul rcx, rax                    ; <=4000ms * 1e7 kHz, no overflow
    imul rax, rax, ND_A1_RESERVE_MS
    mov [r13+A1_RQ_RETURN_RESERVE], rax
    mov rbx, rcx
    call tsc_now
    add rax, rbx
    jc .budget
    mov [r13+A1_RQ_DEADLINE], rax
    mov rdi, r13
    lea rsi, [rel nd_a1_result]
    mov edx, A1_RS_BYTES
    call a1_reset_dispatch           ; once; op1 reads only
    xor eax, eax
    jmp .out
.argument:
    mov eax, 40
    jmp .out
.budget:
    mov eax, A1N_E_BUDGET
.out:
    pop r13
    pop r12
    pop rbx
    ret
