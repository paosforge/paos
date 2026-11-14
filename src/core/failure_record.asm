;; MODULE core/failure_record
;; LAYER 1
;; CONTEXT: bsp_only
;; EXPORTS diag_failure_begin, diag_failure_poll, diag_failure_status, diag_failure_exhaustion_control, diag_failure_snapshot, diag_failure_snapshot_bytes
;; IMPORTS core/heap, core/diag, core/build_id, boot/serial, boot/boot_v2_handoff, boot/boot_v2_health, boot/nvram_access, boot/header, boot/paging
;; CAPS
;; OWNER saga:core
; Fixed diagnostic projection of an observed post-initial-KAT heap OOM delta.
; No allocator/IRQ/panic calls, allocations, raw addresses or authority decisions.
; The BSP loop samples the existing atomic counter. Initial KAT is excluded;
; later deliberate KATs can contribute and are NOT labelled ordinary failures.
; One attempt per boot, <=1 SetVariable, no erase/retry after any uncertainty.
DFR_BYTES equ 32
DFR_MAGIC equ 0x52454650                  ; 'PFER'
DFR_ATTRS equ 7                          ; NV|BS|RT

; Called once immediately after the initial heap KAT, before later producers.
; Snapshot the baseline even when EFI is unavailable. Read-only prior readout
; is separate from current-boot write status; neither influences health/policy.
diag_failure_begin:
    cmp byte [rel diag_failure_initialized], 0
    jne .done
    mov byte [rel diag_failure_initialized], 1
    mov rax, [rel heap_stat_oom]
    mov [rel diag_failure_baseline], rax
    push rbp
    mov rbp, rsp
    and rsp, -16
    push rbx
    push r12
    mov byte [rel diag_failure_prev_status], 2 ; unavailable
    cmp byte [rel pbm_manager_launch], 1
    jne .report
    cmp byte [rel pbm_runtime_code_mapped], 1
    jne .report
    mov r12, [rel runtime_services]
    test r12, r12
    jz .report
    call diag_failure_read
    mov rbx, 0x800000000000000E
    cmp rax, rbx
    jne .present
    mov byte [rel diag_failure_prev_status], 0 ; absent
    jmp .report
.present:
    test rax, rax
    jnz .report
    mov byte [rel diag_failure_prev_status], 3 ; unknown/malformed: preserve
    cmp dword [rel diag_failure_attrs], DFR_ATTRS
    jne .report
    cmp qword [rel diag_failure_size], DFR_BYTES
    jne .report
    lea rdi, [rel diag_failure_verify]
    call diag_failure_wire_ok
    test eax, eax
    jz .report
    mov byte [rel diag_failure_prev_status], 1
.report:
    lea rdi, [rel str_dfr_previous]
    call serial_string
    movzx edi, byte [rel diag_failure_prev_status]
    call serial_hex64
    cmp byte [rel diag_failure_prev_status], 1
    jne .end
    lea rdi, [rel diag_failure_verify]
    call diag_failure_fields
.end:
    lea rdi, [rel str_dfr_end]
    call serial_string
    pop r12
    pop rbx
    mov rsp, rbp
    pop rbp
.done:
    ret

; Cheap on every normal BSP turn until the first positive counter delta. Does
; not run in the Safe loop. A counter wrap/reset is not invented as exhaustion.
; Initialization/attempt latches are BSP-owned; heap's atomic counter unchanged.
diag_failure_poll:
    cmp byte [rel diag_failure_initialized], 1
    jne .done
    cmp byte [rel diag_failure_attempted], 0
    jne .done
    mov rax, [rel heap_stat_oom]
    sub rax, [rel diag_failure_baseline]
    jbe .done
    mov byte [rel diag_failure_attempted], 1
    push rbp
    mov rbp, rsp
    and rsp, -16
    push rbx
    push r12
    mov dword [rel diag_failure_record], DFR_MAGIC
    mov word [rel diag_failure_record+4], 1
    mov word [rel diag_failure_record+6], DFR_BYTES
    mov word [rel diag_failure_record+8], 1 ; cause=heap OOM counter delta
    mov word [rel diag_failure_record+10], 1 ; post-initial-KAT observation
    mov edx, 0xFFFFFFFF
    cmp rax, rdx
    cmova rax, rdx
    mov [rel diag_failure_record+12], eax
    mov dword [rel diag_failure_record+16], 0
    cmp byte [rel paos_build_state], BID_ST_MATCH
    jne .boot
    mov eax, [rel paos_build_measured]
    mov [rel diag_failure_record+16], eax
    or word [rel diag_failure_record+10], 2
.boot:
    mov dword [rel diag_failure_record+20], 0
    cmp byte [rel diag_ready], 1
    jne .crc
    mov rax, [rel diag_ptr]
    test rax, rax
    jz .crc
    mov eax, [rax+DIAG_H_BOOT]
    mov [rel diag_failure_record+20], eax
    or word [rel diag_failure_record+10], 4
.crc:
    mov dword [rel diag_failure_record+24], 0
    lea rdi, [rel diag_failure_record]
    mov esi, 28
    call pbm_crc32
    mov [rel diag_failure_record+28], eax
    mov byte [rel diag_failure_status], 2
    cmp byte [rel pbm_manager_launch], 1
    jne .report
    cmp byte [rel pbm_runtime_code_mapped], 1
    jne .report
    mov r12, [rel runtime_services]
    test r12, r12
    jz .report
    test byte [rel pbm_flags], PBM_HF_MUTABLE_ATTEMPT
    jz .report
    call diag_failure_read
    mov rbx, 0x800000000000000E
    cmp rax, rbx
    je .write
    test rax, rax
    jnz .report
    cmp dword [rel diag_failure_attrs], DFR_ATTRS
    jne .report
    cmp qword [rel diag_failure_size], DFR_BYTES
    jne .report
    lea rdi, [rel diag_failure_verify]
    call diag_failure_wire_ok
    test eax, eax
    jz .report                         ; unknown stored schema/fields preserved
    lea rdi, [rel diag_failure_verify]
    lea rsi, [rel diag_failure_record]
    mov ecx, DFR_BYTES/8
    repe cmpsq
    jne .write
    mov byte [rel diag_failure_status], 4
    jmp .report
.write:
    lea rdi, [rel diag_failure_guid]
    lea rsi, [rel diag_failure_name]
    xor edx, edx
    lea rcx, [rel str_dfr_tag]
    call storage_access_nvram_require
    test rax, rax
    jnz .report
    mov byte [rel diag_failure_status], 3 ; uncertain until exact readback
    lea rcx, [rel diag_failure_name]
    lea rdx, [rel diag_failure_guid]
    mov r8d, DFR_ATTRS
    mov r9d, DFR_BYTES
    sub rsp, 48
    lea rax, [rel diag_failure_record]
    mov [rsp+32], rax
    call [r12+0x58]                    ; EFI_RUNTIME_SERVICES.SetVariable
    add rsp, 48
    test rax, rax
    jnz .report
    call diag_failure_read
    test rax, rax
    jnz .report
    cmp dword [rel diag_failure_attrs], DFR_ATTRS
    jne .report
    cmp qword [rel diag_failure_size], DFR_BYTES
    jne .report
    lea rdi, [rel diag_failure_verify]
    lea rsi, [rel diag_failure_record]
    mov ecx, DFR_BYTES/8
    repe cmpsq
    jne .report
    mov byte [rel diag_failure_status], 1
.report:
    lea rdi, [rel str_dfr_current]
    call serial_string
    movzx edi, byte [rel diag_failure_status]
    call serial_hex64
    lea rdi, [rel diag_failure_record]
    call diag_failure_fields
    lea rdi, [rel str_dfr_end]
    call serial_string
    pop r12
    pop rbx
    mov rsp, rbp
    pop rbp
.done:
    ret

; Owner readout, ordinary BSP context. EAX=1 valid, 0 absent, 2 unavailable,
; 3 unknown/malformed. Exactly one bounded GetVariable when available. Copies
; only a validated 32-byte record; every other result clears the projection.
; Does not call the writer, consume its attempt, allocate, erase or retry.
diag_failure_snapshot:
    push rbp
    mov rbp, rsp
    and rsp, -16
    push rbx
    push r12
    lea rdi, [rel diag_failure_snapshot_bytes]
    xor eax, eax
    mov ecx, DFR_BYTES/8
    rep stosq
    mov ebx, 2
    cmp byte [rel pbm_manager_launch], 1
    jne .done
    cmp byte [rel pbm_runtime_code_mapped], 1
    jne .done
    mov r12, [rel runtime_services]
    test r12, r12
    jz .done
    call diag_failure_read
    mov rdx, 0x800000000000000E
    cmp rax, rdx
    jne .present
    xor ebx, ebx
    jmp .done
.present:
    test rax, rax
    jnz .done
    mov ebx, 3
    cmp dword [rel diag_failure_attrs], DFR_ATTRS
    jne .done
    cmp qword [rel diag_failure_size], DFR_BYTES
    jne .done
    lea rdi, [rel diag_failure_verify]
    call diag_failure_wire_ok
    test eax, eax
    jz .done
    lea rsi, [rel diag_failure_verify]
    lea rdi, [rel diag_failure_snapshot_bytes]
    mov ecx, DFR_BYTES/8
    rep movsq
    mov ebx, 1
.done:
    mov eax, ebx
    pop r12
    pop rbx
    mov rsp, rbp
    pop rbp
    ret

; R12 runtime table; caller aligned. One bounded GetVariable, no mutation.
diag_failure_read:
    mov qword [rel diag_failure_size], DFR_BYTES
    mov dword [rel diag_failure_attrs], 0
    lea rcx, [rel diag_failure_name]
    lea rdx, [rel diag_failure_guid]
    lea r8, [rel diag_failure_attrs]
    lea r9, [rel diag_failure_size]
    sub rsp, 40
    lea rax, [rel diag_failure_verify]
    mov [rsp+32], rax
    call [r12+0x48]
    add rsp, 40
    ret

; RDI exact32B -> EAX1 only for complete known v1 scalar schema with CRC.
diag_failure_wire_ok:
    push rbx
    mov rbx, rdi
    xor eax, eax
    cmp dword [rbx], DFR_MAGIC
    jne .out
    cmp word [rbx+4], 1
    jne .out
    cmp word [rbx+6], DFR_BYTES
    jne .out
    cmp word [rbx+8], 1
    jne .out
    movzx edx, word [rbx+10]
    test edx, ~7
    jnz .out
    test edx, 1
    jz .out
    cmp dword [rbx+12], 0
    je .out
    cmp dword [rbx+24], 0
    jne .out
    test edx, 2
    jnz .boot
    cmp dword [rbx+16], 0
    jne .out
.boot:
    test edx, 4
    jnz .crc
    cmp dword [rbx+20], 0
    jne .out
.crc:
    mov esi, 28
    call pbm_crc32
    cmp eax, [rbx+28]
    mov eax, 0
    jne .out
    inc eax
.out:
    pop rbx
    ret

; Printed scalars only; flags disambiguate unknown/truncated build/ring identity.
diag_failure_fields:
    push rbx
    mov rbx, rdi
    lea rdi, [rel str_dfr_delta]
    call serial_string
    mov edi, [rbx+12]
    call serial_hex64
    lea rdi, [rel str_dfr_build]
    call serial_string
    mov edi, [rbx+16]
    call serial_hex64
    lea rdi, [rel str_dfr_boot]
    call serial_string
    mov edi, [rbx+20]
    call serial_hex64
    lea rdi, [rel str_dfr_flags]
    call serial_string
    movzx edi, word [rbx+10]
    call serial_hex64
    pop rbx
    ret

; Owner-only SELFTEST OOM control, called in ordinary BSP command context.
; EAX0: real insufficient-capacity refusal observed, persistence status remains
; separate. EAX1 unavailable;2 already controlled this boot;3 predicate failed.
; One kmalloc request exceeds the ENTIRE validated arena. No pointer/bounds
; replacement, allocation drain, fake counter increment or broad KAT. This
; controlled refusal is not spontaneous full-heap workload exhaustion.
diag_failure_exhaustion_control:
    cmp byte [rel diag_failure_control_used], 0
    jne .used
    cmp byte [rel diag_failure_initialized], 1
    jne .unavailable
    cmp byte [rel diag_failure_attempted], 0
    jne .unavailable
    cmp byte [rel pbm_manager_launch], 1
    jne .unavailable
    cmp byte [rel pbm_runtime_code_mapped], 1
    jne .unavailable
    cmp qword [rel runtime_services], 0
    je .unavailable
    test byte [rel pbm_flags], PBM_HF_MUTABLE_ATTEMPT
    jz .unavailable
    mov rax, [rel heap_stat_oom]
    cmp rax, [rel diag_failure_baseline]
    jne .unavailable                     ; earlier unsampled event is not this control
    cmp rax, -1
    je .unavailable                     ; do not wrap the observation counter
    mov rdi, [rel heap_end]
    mov rdx, [rel heap_base]
    test rdx, rdx
    jz .unavailable
    sub rdi, rdx
    jbe .unavailable                     ; nonempty, nonwrapped arena
    add rdi, 16                         ; strictly greater than TOTAL capacity
    jc .unavailable
    mov rax, rdi
    add rax, 15                         ; kmalloc round-up itself cannot wrap
    jc .unavailable
    and rax, -16
    add rax, [rel heap_end]              ; even largest possible next cannot wrap
    jc .unavailable
    mov rax, [rel heap_next]
    test rax, rax
    jz .unavailable
    test al, 15
    jnz .unavailable
    cmp rax, rdx
    jb .unavailable
    cmp rax, [rel heap_end]
    ja .unavailable
    mov byte [rel diag_failure_control_used], 1
    push rbp
    mov rbp, rsp
    and rsp, -16
    push rbx
    push r12
    mov rbx, [rel heap_stat_oom]
    mov r12, [rel heap_end]
    call kmalloc                        ; exactly one real call; request > total capacity
    test rax, rax
    jnz .failed
    cmp r12, [rel heap_end]
    jne .failed
    cmp rbx, [rel heap_stat_oom]
    jae .failed                         ; counter must advance without wrapping
    call diag_failure_poll              ; existing one-attempt/readback gate unchanged
    xor eax, eax
    jmp .out
.failed:
    mov eax, 3
.out:
    pop r12
    pop rbx
    mov rsp, rbp
    pop rbp
    ret
.unavailable:
    mov eax, 1
    ret
.used:
    mov eax, 2
    ret

%include "core/abi/wdata.inc"
%macro WDATA_core_failure_record 0
align 8, db 0
diag_failure_baseline: dq 0
diag_failure_control_used: db 0
diag_failure_initialized: db 0
diag_failure_attempted: db 0
diag_failure_status: db 0             ; 0none 1saved 2refused 3uncertain 4identical
diag_failure_prev_status: db 0        ; 0absent 1valid 2unavailable 3unknown
align 8, db 0
diag_failure_size: dq 0
diag_failure_attrs: dd 0
align 8, db 0
diag_failure_record: times DFR_BYTES db 0
diag_failure_verify: times DFR_BYTES db 0
diag_failure_snapshot_bytes: times DFR_BYTES db 0
; Existing PaOSInitCheckpoint namespace (nvram_access registry row7).
diag_failure_guid:
    dd 0x7A965D12
    dw 0xC839, 0x4A77
    db 0xB1,0xE2,0x90,0x6E,0xF7,0x24,0x43,0x8C
diag_failure_name: dw 'P','a','O','S','F','a','i','l','u','r','e','R','e','c','o','r','d',0
str_dfr_previous: db "[diag.failure-record.previous] status=",0
str_dfr_current: db "[diag.failure-record.current] status=",0
str_dfr_delta: db " cause=heap_oom_counter_delta delta=",0
str_dfr_build: db " build_prefix=",0
str_dfr_boot: db " ring_boot_low=",0
str_dfr_flags: db " flags=",0
str_dfr_tag: db "diag-failure-record",0
str_dfr_end: db " provenance=post_initial_heap_kat authority=diagnostic_only",13,10,0

%endmacro
WDATA_DEFER WDATA_core_failure_record
