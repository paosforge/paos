;; MODULE hv/guest_class_kat
;; LAYER 5
;; EXPORTS guest_class_boot_init, guest_class_kat
;; IMPORTS hv/guest_class, hv/vmx, boot/serial, boot/beacon, core/lib/mem, core/lib/fmt
;; CAPS
;; OWNER saga:android_guest
; Task3346. Native, action-free QEMU tests of the PRODUCT launch entry. Private
; fixture context only: no production encryption capability is ever installed.
; Every serialized field/counter comes from the records and invocation results.
; A tripwire continuation proves instrumentation is live, then must remain
; unreachable for the persistent/no-encryption mutation with START requested.

guest_class_boot_init:
    push rbx
    mov dword [rel gc_kat_stage], 0
    call guest_class_init
    test eax, eax
    jnz .fail
    cmp byte [rel boot_budget_qemu_fixture], 1
    jne .done
    call guest_class_kat
    jmp .done
.fail:
    call gc_kat_report_failure
.done:
    pop rbx
    jmp hv_register_verbs

guest_class_kat:
    push rbx
    push r12
    push r13
    push r14
    push r15
    ; Reuse boot/beacon's observation nonce and capture this invocation's TSC.
    ; QEMU's ordinary CPU need not provide entropy; this is a correlation token,
    ; NEVER a capability, key, or claim of cryptographic randomness. The external
    ; grader binds its first half to the independently emitted boot beacon and
    ; all records to the runner's exact candidate/serial receipt. No fixed-token
    ; fallback: an absent beacon or zero timestamp fails the KAT.
    mov dword [rel gc_kat_stage], 1
    mov eax, [rel boot_nonce]
    test eax, eax
    jz .fail
    mov [rel gc_kat_token], rax
    rdtsc
    shl rdx, 32
    or rax, rdx
    test rax, rax
    jz .fail
    mov [rel gc_kat_token + 8], rax
    mov dword [rel gc_kat_stage], 2
    cmp dword [rel guest_class_registry], 2
    jne .fail
    lea rdi, [rel guest_class_registry + 8]
    lea rsi, [rel gc_mobile]
    mov edx, GC_BYTES * 2
    call memcmp
    test eax, eax
    jnz .fail
    call gc_kat_prefix
    lea rdi, [rel gc_schema]
    call serial_string
    lea r12, [rel guest_class_registry + 8]
    call gc_kat_descriptor_line
    add r12, GC_BYTES
    call gc_kat_descriptor_line

    ; First use the production context, which has NO L0-FDE capability.
    mov dword [rel gc_kat_stage], 3
    lea r12, [rel guest_class_host_context]
    call gc_kat_mobile_copy
    xor ecx, ecx
    xor r8d, r8d
    call gc_kat_invoke
    test eax, eax
    jnz .fail
    call gc_kat_zero_effects
    test eax, eax
    jnz .fail
    cmp dword [rel gc_kat_result + GC_R_ELIGIBLE], 1
    jne .fail
    lea r13, [rel gc_case_ephemeral]
    call gc_kat_result_line

    ; Same record: change ONLY posture through its structural constructor.
    ; Assert the remaining 94 bytes did not move, including the empty binding,
    ; network policy, name, profile, and all three resource budgets.
    mov dword [rel gc_kat_stage], 4
    lea rdi, [rel gc_kat_record]
    mov esi, 1
    call guest_class_set_posture
    cmp word [rel gc_kat_record + GC_POSTURE], 0x0101
    jne .fail
    lea rdi, [rel gc_kat_record]
    lea rsi, [rel gc_mobile]
    mov edx, GC_POSTURE
    call memcmp
    test eax, eax
    jnz .fail
    lea rdi, [rel gc_kat_record + GC_NETWORK]
    lea rsi, [rel gc_mobile + GC_NETWORK]
    mov edx, GC_BYTES - GC_NETWORK
    call memcmp
    test eax, eax
    jnz .fail
    xor ecx, ecx
    mov r8d, 1                          ; REAL start request, must refuse first
    call gc_kat_invoke
    cmp eax, GC_OWNER_ENCRYPTION_REQUIRED
    jne .fail
    call gc_kat_zero_effects
    test eax, eax
    jnz .fail
    cmp dword [rel gc_kat_result + GC_R_ELIGIBLE], 0
    jne .fail
    lea r13, [rel gc_case_refused]
    call gc_kat_result_line

    ; Host-owned capability FIXTURE: active opaque handle, exact owner+volume
    ; scope and current generation. Never copied into the production context.
    mov dword [rel gc_kat_stage], 5
    lea r12, [rel gc_kat_context]
    lea rax, [rel gc_kat_tripwire]
    mov [r12 + GC_CTX_START], rax
    mov ecx, 3346
    xor r8d, r8d
    call gc_kat_invoke
    test eax, eax
    jnz .fail
    cmp dword [rel gc_kat_result + GC_R_ELIGIBLE], 1
    jne .fail
    call gc_kat_zero_effects
    test eax, eax
    jnz .fail
    lea r13, [rel gc_case_owner]
    call gc_kat_result_line

    ; One-axis capability negatives; restore each private fixture field before
    ; the next case. No verifier or callback is supplied through the descriptor.
    lea r14, [rel gc_cap_bad_offsets]
    mov r15d, gc_cap_bad_offsets.count
.cap_negative:
    mov eax, gc_cap_bad_offsets.count + 100
    sub eax, r15d
    mov [rel gc_kat_stage], eax
    mov eax, [r14]
    mov r13, [r12 + rax]
    inc qword [r12 + rax]
    mov ecx, 3346
    mov r8d, 1
    call gc_kat_invoke
    mov ebx, eax
    mov eax, [r14]
    mov [r12 + rax], r13
    cmp ebx, GC_OWNER_ENCRYPTION_REQUIRED
    jne .fail
    call gc_kat_zero_effects
    test eax, eax
    jnz .fail
    add r14, 4
    dec r15d
    jnz .cap_negative

    ; Instrument control: the same START path can reach the tripwire when
    ; policy allows it. Counters are incremented in that continuation itself.
    mov dword [rel gc_kat_stage], 6
    call gc_kat_mobile_copy
    xor ecx, ecx
    mov r8d, 1
    call gc_kat_invoke
    cmp eax, GC_QUEUED
    jne .fail
    lea rdi, [rel gc_kat_result + GC_R_DISK]
    mov ecx, 5
.tripwire_check:
    cmp dword [rdi], 1
    jne .fail
    add rdi, 4
    loop .tripwire_check
    cmp dword [rel gc_kat_result + GC_R_BACKEND], 1
    jne .fail
    ; Identical continuation and request, only persistent posture differs.
    mov dword [rel gc_kat_stage], 7
    lea rdi, [rel gc_kat_record]
    mov esi, 1
    call guest_class_set_posture
    xor ecx, ecx
    mov r8d, 1
    call gc_kat_invoke
    cmp eax, GC_OWNER_ENCRYPTION_REQUIRED
    jne .fail
    call gc_kat_zero_effects
    test eax, eax
    jnz .fail

    ; Hostile byte mutations, with each status checked at BOTH registration
    ; and the real launch entry. An exact before/after registry comparison
    ; proves no malformed record was retained, including padding/canaries.
    lea rdi, [rel gc_kat_registry]
    lea rsi, [rel guest_class_registry]
    mov edx, GC_REG_BYTES
    call memcpy
    lea r14, [rel gc_bad_records]
    mov r15d, gc_bad_records.count
.hostile:
    mov eax, gc_bad_records.count + 200
    sub eax, r15d
    mov [rel gc_kat_stage], eax
    call gc_kat_mobile_copy
    cmp dword [r14], 0
    je .mutate
    lea rdi, [rel gc_kat_record]
    mov esi, 1
    call guest_class_set_posture
.mutate:
    mov eax, [r14 + 4]
    lea rdi, [rel gc_kat_record]
    add rdi, rax
    mov rax, [r14 + 16]
    cmp dword [r14 + 8], 1
    jne .wide
    mov [rdi], al
    jmp .register
.wide:
    cmp dword [r14 + 8], 4
    jne .quad
    mov [rdi], eax
    jmp .register
.quad:
    mov [rdi], rax
.register:
    lea rdi, [rel gc_kat_record]
    mov esi, [r14 + 12]
    lea rdx, [rel gc_kat_registry]
    call guest_class_register
    cmp eax, [r14 + 24]
    jne .fail
    lea rdi, [rel gc_kat_registry]
    lea rsi, [rel guest_class_registry]
    mov edx, GC_REG_BYTES
    call memcmp
    test eax, eax
    jnz .fail
    lea rdi, [rel gc_kat_record]
    mov esi, [r14 + 12]
    mov rdx, r12
    xor ecx, ecx
    mov r8d, 1
    lea r9, [rel gc_kat_result]
    call guest_class_launch
    cmp eax, [r14 + 24]
    jne .fail
    call gc_kat_zero_effects
    test eax, eax
    jnz .fail
    add r14, 32
    dec r15d
    jnz .hostile

    ; Duplicate name refusal must win even in a full registry; no writes.
    mov dword [rel gc_kat_stage], 8
    lea rdi, [rel gc_mobile]
    mov esi, GC_BYTES
    lea rdx, [rel gc_kat_registry]
    call guest_class_register
    cmp eax, GC_DUPLICATE
    jne .fail
    lea rdi, [rel gc_kat_registry]
    lea rsi, [rel guest_class_registry]
    mov edx, GC_REG_BYTES
    call memcmp
    test eax, eax
    jnz .fail
    ; The third network posture and maxima must remain valid, too.
    mov dword [rel gc_kat_stage], 9
    call gc_kat_mobile_copy
    mov byte [rel gc_kat_record + GC_NETWORK], 2
    mov dword [rel gc_kat_record + GC_VCPUS], 256
    mov rax, GC_RAM_MAX
    mov [rel gc_kat_record + GC_RAM], rax
    mov rax, GC_STORAGE_MAX
    mov [rel gc_kat_record + GC_STORAGE], rax
    xor ecx, ecx
    xor r8d, r8d
    call gc_kat_invoke
    test eax, eax
    jnz .fail
    call gc_kat_zero_effects
    test eax, eax
    jnz .fail
    ; Real default context still has no capability and no start was queued.
    mov dword [rel gc_kat_stage], 10
    cmp qword [rel guest_class_host_context + GC_CTX_CAP], 0
    jne .fail
    cmp byte [rel hv_linux_run_req], 0
    jne .fail
    cmp dword [rel hv_linux_start_gen], 0
    jne .fail
    call gc_kat_prefix
    lea rdi, [rel gc_negatives]
    call serial_string
    lea rdi, [rel gc_descriptor_pass]
    call serial_string
    lea rdi, [rel gc_gate_pass]
    call serial_string
    jmp .out
.fail:
    call gc_kat_report_failure
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Stage 0=registry initialization, 1=token, 2=registry round-trip,
; 3..10=positive/transition controls, 100+i=capability, 200+i=hostile row.
; EAX is captured before formatting so a failure retains the observed value.
gc_kat_report_failure:
    push rbx
    mov ebx, eax
    lea rdi, [rel gc_failure_stage]
    call serial_string
    mov edi, [rel gc_kat_stage]
    call gc_kat_number
    lea rdi, [rel gc_failure_value]
    call serial_string
    mov edi, ebx
    call gc_kat_number
    call serial_newline
    lea rdi, [rel gc_kat_fail]
    call serial_string
    pop rbx
    ret

gc_kat_mobile_copy:
    lea rdi, [rel gc_kat_record]
    lea rsi, [rel gc_mobile]
    mov edx, GC_BYTES
    jmp memcpy

; R12=context, RCX=handle, R8D=mode. Result is cleared by the PRODUCT entry.
gc_kat_invoke:
    lea rdi, [rel gc_kat_record]
    mov esi, GC_BYTES
    mov rdx, r12
    lea r9, [rel gc_kat_result]
    jmp guest_class_launch

gc_kat_zero_effects:
    mov eax, [rel gc_kat_result + GC_R_DISK]
    or eax, [rel gc_kat_result + GC_R_NET]
    or eax, [rel gc_kat_result + GC_R_CREDENTIAL]
    or eax, [rel gc_kat_result + GC_R_VM]
    or eax, [rel gc_kat_result + GC_R_LAUNCH]
    or eax, [rel gc_kat_result + GC_R_BACKEND]
    ret

gc_kat_tripwire:
    inc dword [rsi + GC_R_DISK]
    inc dword [rsi + GC_R_NET]
    inc dword [rsi + GC_R_CREDENTIAL]
    inc dword [rsi + GC_R_VM]
    inc dword [rsi + GC_R_LAUNCH]
    mov eax, GC_QUEUED
    ret

; Use the shared formatter, not another integer encoder. Preserve callee-saves.
gc_kat_number:
    sub rsp, 40
    mov rsi, rsp
    call fmt_dec
    mov rdi, rsp
    call serial_string
    add rsp, 40
    ret

gc_kat_prefix:
    sub rsp, 40
    lea rdi, [rel gc_prefix]
    call serial_string
    mov rdi, [rel gc_kat_token]
    mov rsi, rsp
    mov edx, 16
    call fmt_hex
    mov rdi, rsp
    call serial_string
    mov rdi, [rel gc_kat_token + 8]
    mov rsi, rsp
    mov edx, 16
    call fmt_hex
    mov rdi, rsp
    call serial_string
    add rsp, 40
    ret

; R12=validated owned descriptor; output contains every field incl. profile.
gc_kat_descriptor_line:
    push rbx
    call gc_kat_prefix
    lea rdi, [rel gc_field_class]
    call serial_string
    lea rdi, [r12 + GC_NAME]
    call serial_string
    lea rdi, [rel gc_field_posture]
    call serial_string
    lea rdi, [rel gc_ephemeral]
    cmp byte [r12 + GC_POSTURE], 0
    je .posture
    lea rdi, [rel gc_persistent]
.posture:
    call serial_string
    lea rdi, [rel gc_field_binding]
    call serial_string
    cmp qword [r12 + GC_BINDING], 0
    jne .binding
    lea rdi, [rel gc_empty]
    call serial_string
    jmp .required
.binding:
    mov rdi, [r12 + GC_BINDING]
    call gc_kat_number
.required:
    lea rdi, [rel gc_field_required]
    call serial_string
    movzx edi, byte [r12 + GC_REQUIRED]
    call gc_kat_number
    lea rdi, [rel gc_field_network]
    call serial_string
    lea rdi, [rel gc_data_out]
    cmp byte [r12 + GC_NETWORK], 0
    je .network
    lea rdi, [rel gc_mediated]
    cmp byte [r12 + GC_NETWORK], 1
    je .network
    lea rdi, [rel gc_no_inbound]
.network:
    call serial_string
    lea rdi, [rel gc_field_ram]
    call serial_string
    mov rdi, [r12 + GC_RAM]
    call gc_kat_number
    lea rdi, [rel gc_field_vcpus]
    call serial_string
    mov edi, [r12 + GC_VCPUS]
    call gc_kat_number
    lea rdi, [rel gc_field_storage]
    call serial_string
    mov rdi, [r12 + GC_STORAGE]
    call gc_kat_number
    lea rdi, [rel gc_field_profile]
    call serial_string
    mov rdi, [r12 + GC_PROFILE]
    call gc_kat_number
    call serial_newline
    pop rbx
    ret

; R13=case name; status and counters rendered from the actual last invocation.
gc_kat_result_line:
    push rbx
    call gc_kat_prefix
    lea rdi, [rel gc_field_case]
    call serial_string
    mov rdi, r13
    call serial_string
    lea rdi, [rel gc_status_eligible]
    cmp dword [rel gc_kat_result + GC_R_STATUS], GC_OK
    je .status
    lea rdi, [rel gc_status_refused]
.status:
    call serial_string
    lea rax, [rel gc_case_owner]
    cmp r13, rax
    jne .effects
    lea rdi, [rel gc_capability]
    call serial_string
.effects:
    lea rdi, [rel gc_field_eligible]
    call serial_string
    mov edi, [rel gc_kat_result + GC_R_ELIGIBLE]
    call gc_kat_number
    lea rdi, [rel gc_field_disk]
    call serial_string
    mov edi, [rel gc_kat_result + GC_R_DISK]
    call gc_kat_number
    lea rdi, [rel gc_field_net]
    call serial_string
    mov edi, [rel gc_kat_result + GC_R_NET]
    call gc_kat_number
    lea rdi, [rel gc_field_credential]
    call serial_string
    mov edi, [rel gc_kat_result + GC_R_CREDENTIAL]
    call gc_kat_number
    lea rdi, [rel gc_field_vm]
    call serial_string
    mov edi, [rel gc_kat_result + GC_R_VM]
    call gc_kat_number
    lea rdi, [rel gc_field_launch]
    call serial_string
    mov edi, [rel gc_kat_result + GC_R_LAUNCH]
    call gc_kat_number
    lea rdi, [rel gc_field_gate]
    call serial_string
    mov edi, [rel gc_kat_result + GC_R_GATE]
    call gc_kat_number
    lea rdi, [rel gc_field_backend]
    call serial_string
    mov edi, [rel gc_kat_result + GC_R_BACKEND]
    call gc_kat_number
    call serial_newline
    pop rbx
    ret

; Mutation rows: persistent?, offset, write width, supplied extent, value,
; exact error, reserved. Integer data only, no static symbol pointers.
%macro GC_BAD 6
    dd %1, %2, %3, %4
    dq %5
    dd %6, 0
%endmacro
align 8
gc_bad_records:
    GC_BAD 0, GC_VERSION, 4, GC_BYTES, 2, GC_BAD_VERSION
    GC_BAD 0, GC_POSTURE, 1, GC_BYTES, 2, GC_BAD_ENUM
    GC_BAD 0, GC_NETWORK, 1, GC_BYTES, 3, GC_BAD_ENUM
    GC_BAD 0, GC_PROFILE, 8, GC_BYTES, 0, GC_BAD_ENUM
    GC_BAD 0, GC_PROFILE, 8, GC_BYTES, -1, GC_BAD_ENUM
    GC_BAD 1, GC_REQUIRED, 1, GC_BYTES, 0, GC_BAD_FLAGS
    GC_BAD 0, GC_REQUIRED, 1, GC_BYTES, 2, GC_BAD_FLAGS
    GC_BAD 0, GC_FLAGS, 1, GC_BYTES, 1, GC_BAD_FLAGS
    GC_BAD 0, GC_RESERVED, 8, GC_BYTES, 1, GC_BAD_FLAGS
    GC_BAD 0, GC_BINDING, 8, GC_BYTES, 1, GC_BAD_BINDING
    GC_BAD 0, GC_NAME, 1, GC_BYTES, 'x', GC_BAD_NAME
    GC_BAD 0, GC_NAME + 6, 1, GC_BYTES, 'x', GC_BAD_NAME
    GC_BAD 0, GC_NAME + 23, 1, GC_BYTES, 'x', GC_BAD_NAME
    GC_BAD 0, GC_SIZE, 4, GC_BYTES, GC_BYTES - 1, GC_BAD_LENGTH
    GC_BAD 0, GC_SIZE, 4, GC_BYTES, GC_BYTES + 1, GC_BAD_LENGTH
    GC_BAD 0, GC_SIZE, 4, GC_BYTES - 1, GC_BYTES, GC_BAD_LENGTH
    GC_BAD 0, GC_SIZE, 4, GC_BYTES + 1, GC_BYTES, GC_BAD_LENGTH
    GC_BAD 0, GC_SIZE, 4, 0, GC_BYTES, GC_BAD_LENGTH
    GC_BAD 0, GC_RAM, 8, GC_BYTES, 0, GC_BAD_BUDGET
    GC_BAD 0, GC_RAM, 8, GC_BYTES, -1, GC_BAD_BUDGET
    GC_BAD 0, GC_RAM, 8, GC_BYTES, GC_RAM_MAX + 1, GC_BAD_BUDGET
    GC_BAD 0, GC_STORAGE, 8, GC_BYTES, 0, GC_BAD_BUDGET
    GC_BAD 0, GC_STORAGE, 8, GC_BYTES, -1, GC_BAD_BUDGET
    GC_BAD 0, GC_STORAGE, 8, GC_BYTES, GC_STORAGE_MAX + 1, GC_BAD_BUDGET
    GC_BAD 0, GC_VCPUS, 4, GC_BYTES, 0, GC_BAD_BUDGET
    GC_BAD 0, GC_VCPUS, 4, GC_BYTES, 257, GC_BAD_BUDGET
    GC_BAD 0, GC_VCPUS, 4, GC_BYTES, -1, GC_BAD_BUDGET
.count: equ ($ - gc_bad_records) / 32
%unmacro GC_BAD 6
gc_cap_bad_offsets:
    dd GC_CTX_CAP, GC_CTX_CAP_OWNER, GC_CTX_CAP_VOLUME
    dd GC_CTX_CAP_GENERATION, GC_CTX_CAP_RIGHTS
.count: equ ($ - gc_cap_bad_offsets) / 4
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_hv_guest_class_kat_0 0
gc_kat_context:
    dq 101, 202, 1, 3346, 101, 202, 1, 1, 0
gc_kat_token: times 16 db 0
gc_kat_stage: dd 0
gc_kat_record: times GC_BYTES + 1 db 0
gc_kat_result: times GC_RESULT_BYTES db 0
gc_kat_registry: times GC_REG_BYTES db 0

gc_prefix: db 'GCLASS token=',0
gc_failure_stage: db '[PAOS64] guest class: failure stage=',0
gc_failure_value: db ' observed=',0
gc_schema: db ' schema=v1 fields=posture,credential_binding,requires_owner_bound_encryption,network_posture,ram_bytes,vcpus,storage_bytes,profile',13,10,0
gc_field_class: db ' class=',0
gc_field_posture: db ' posture=',0
gc_field_binding: db ' credential_binding=',0
gc_field_required: db ' encryption_required=',0
gc_field_network: db ' network=',0
gc_field_ram: db ' ram=',0
gc_field_vcpus: db ' vcpus=',0
gc_field_storage: db ' storage=',0
gc_field_profile: db ' profile=',0
gc_ephemeral: db 'ephemeral',0
gc_persistent: db 'persistent-credentialed',0
gc_empty: db 'empty',0
gc_data_out: db 'data-out-only-to-keep-verifier',0
gc_mediated: db 'mediated-egress',0
gc_no_inbound: db 'no-inbound-control',0
gc_field_case: db ' case=',0
gc_case_ephemeral: db 'ephemeral-no-encryption',0
gc_case_refused: db 'credentialed-no-encryption',0
gc_case_owner: db 'credentialed-owner-encryption',0
gc_status_eligible: db ' status=eligible',0
gc_status_refused: db ' status=refused reason=owner_encryption_required',0
gc_capability: db ' capability=owner-bound',0
gc_field_eligible: db ' eligible=',0
gc_field_disk: db ' disk_attach=',0
gc_field_net: db ' net_attach=',0
gc_field_credential: db ' credential_lookup=',0
gc_field_vm: db ' vm_alloc=',0
gc_field_launch: db ' launch=',0
gc_field_gate: db ' gate_calls=',0
gc_field_backend: db ' backend_calls=',0
gc_negatives: db ' negatives=version,enum,clear-required,duplicate-name,length,budget-overflow status=all-refused retained=0 hostile_cases=27 capability_cases=5 tripwire_control=1 tripwire_refused=1 posture_only=1',13,10,0
gc_descriptor_pass: db '[PAOS64] guest class: descriptor schema KAT PASS [guest.class.descriptor.kat]',13,10,0
gc_gate_pass: db '[PAOS64] guest class: credentialed launch without owner encryption REFUSED [guest.class.encryption.failclosed]',13,10,0
gc_kat_fail: db '[PAOS64] guest class: KAT FAIL [guest.class.kat.fail]',13,10,0
%endmacro
WDATA_DEFER WDATA_hv_guest_class_kat_0
