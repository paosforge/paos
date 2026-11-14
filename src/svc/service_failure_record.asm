;; MODULE svc/service_failure_record
;; LAYER 5
;; CONTEXT: bsp_only
;; EXPORTS diag_service_failure_begin, diag_service_failure_poll, diag_service_failure_status
;; IMPORTS hv/audio_domain, core/diag, core/build_id, boot/serial, boot/boot_v2_handoff, boot/boot_v2_health, boot/nvram_access, boot/header
;; CAPS
;; OWNER saga:core
; Fixed diagnostic projection of an observed post-boot PADN terminal failure.
; The native owner publishes one aligned packed count/reason scalar before
; scrubbing PCM; retirement preserves it. No firmware call from that producer.
; The normal BSP samples once per turn. Initial boot tests are excluded; later
; deliberate controls can contribute and are NOT labelled ordinary failures.
; One attempt per boot, <=1 SetVariable, no erase/retry after any uncertainty.
SFR_BYTES equ 32
SFR_MAGIC equ 0x52464C50                  ; 'PLFR'
SFR_ATTRS equ 7                          ; NV|BS|RT

; Called once at normal live handoff, after initial boot tests.
; Snapshot the count baseline even when EFI is unavailable. Read-only readout
; is separate from current-boot write status; neither influences health/policy.
diag_service_failure_begin:
    cmp byte [rel diag_service_failure_initialized], 0
    jne .done
    mov byte [rel diag_service_failure_initialized], 1
    mov rax, [rel padn_failure_event]
    shr rax, 32
    mov [rel diag_service_failure_baseline], rax
    push rbp
    mov rbp, rsp
    and rsp, -16
    push rbx
    push r12
    mov byte [rel diag_service_failure_prev_status], 2 ; unavailable
    cmp byte [rel pbm_manager_launch], 1
    jne .report
    cmp byte [rel pbm_runtime_code_mapped], 1
    jne .report
    mov r12, [rel runtime_services]
    test r12, r12
    jz .report
    call diag_service_failure_read
    mov rbx, 0x800000000000000E
    cmp rax, rbx
    jne .present
    mov byte [rel diag_service_failure_prev_status], 0 ; absent
    jmp .report
.present:
    test rax, rax
    jnz .report
    mov byte [rel diag_service_failure_prev_status], 3 ; unknown/malformed: preserve
    cmp dword [rel diag_service_failure_attrs], SFR_ATTRS
    jne .report
    cmp qword [rel diag_service_failure_size], SFR_BYTES
    jne .report
    lea rdi, [rel diag_service_failure_verify]
    call diag_service_failure_wire_ok
    test eax, eax
    jz .report
    mov byte [rel diag_service_failure_prev_status], 1
.report:
    lea rdi, [rel str_sfr_previous]
    call serial_string
    movzx edi, byte [rel diag_service_failure_prev_status]
    call serial_hex64
    cmp byte [rel diag_service_failure_prev_status], 1
    jne .end
    lea rdi, [rel diag_service_failure_verify]
    call diag_service_failure_fields
.end:
    lea rdi, [rel str_sfr_end]
    call serial_string
    pop r12
    pop rbx
    mov rsp, rbp
    pop rbp
.done:
    ret

; Cheap normal BSP sample. One aligned read is the count/reason pair; no
; torn latest-reason/old-count observation. Saturation never wraps. A reset or
; invalid category is not invented as a new failure. Safe loop unchanged.
diag_service_failure_poll:
    cmp byte [rel diag_service_failure_initialized], 1
    jne .done
    cmp byte [rel diag_service_failure_attempted], 0
    jne .done
    mov rax, [rel padn_failure_event]
    mov edx, eax                     ; normalized reason, no arbitrary error/text
    shr rax, 32                      ; saturating event count
    sub rax, [rel diag_service_failure_baseline]
    jbe .done
    cmp edx, 1
    jb .done
    cmp edx, 3
    ja .done
    mov byte [rel diag_service_failure_attempted], 1
    mov [rel diag_service_failure_record+24], edx
    push rbp
    mov rbp, rsp
    and rsp, -16
    push rbx
    push r12
    mov dword [rel diag_service_failure_record], SFR_MAGIC
    mov word [rel diag_service_failure_record+4], 1
    mov word [rel diag_service_failure_record+6], SFR_BYTES
    mov word [rel diag_service_failure_record+8], 1 ; component=PADN terminal failure
    mov word [rel diag_service_failure_record+10], 1 ; post-initial-boot baseline
    mov edx, 0xFFFFFFFF
    cmp rax, rdx
    cmova rax, rdx
    mov [rel diag_service_failure_record+12], eax
    mov dword [rel diag_service_failure_record+16], 0
    cmp byte [rel paos_build_state], BID_ST_MATCH
    jne .boot
    mov eax, [rel paos_build_measured]
    mov [rel diag_service_failure_record+16], eax
    or word [rel diag_service_failure_record+10], 2
.boot:
    mov dword [rel diag_service_failure_record+20], 0
    cmp byte [rel diag_ready], 1
    jne .crc
    mov rax, [rel diag_ptr]
    test rax, rax
    jz .crc
    mov eax, [rax+DIAG_H_BOOT]
    mov [rel diag_service_failure_record+20], eax
    or word [rel diag_service_failure_record+10], 4
.crc:
    lea rdi, [rel diag_service_failure_record]
    mov esi, 28
    call pbm_crc32
    mov [rel diag_service_failure_record+28], eax
    mov byte [rel diag_service_failure_status], 2
    cmp byte [rel pbm_manager_launch], 1
    jne .report
    cmp byte [rel pbm_runtime_code_mapped], 1
    jne .report
    mov r12, [rel runtime_services]
    test r12, r12
    jz .report
    test byte [rel pbm_flags], PBM_HF_MUTABLE_ATTEMPT
    jz .report
    call diag_service_failure_read
    mov rbx, 0x800000000000000E
    cmp rax, rbx
    je .write
    test rax, rax
    jnz .report
    cmp dword [rel diag_service_failure_attrs], SFR_ATTRS
    jne .report
    cmp qword [rel diag_service_failure_size], SFR_BYTES
    jne .report
    lea rdi, [rel diag_service_failure_verify]
    call diag_service_failure_wire_ok
    test eax, eax
    jz .report                         ; unknown stored schema/fields preserved
    lea rdi, [rel diag_service_failure_verify]
    lea rsi, [rel diag_service_failure_record]
    mov ecx, SFR_BYTES/8
    repe cmpsq
    jne .write
    mov byte [rel diag_service_failure_status], 4
    jmp .report
.write:
    lea rdi, [rel diag_service_failure_guid]
    lea rsi, [rel diag_service_failure_name]
    xor edx, edx
    lea rcx, [rel str_sfr_tag]
    call storage_access_nvram_require
    test rax, rax
    jnz .report
    mov byte [rel diag_service_failure_status], 3 ; uncertain until exact readback
    lea rcx, [rel diag_service_failure_name]
    lea rdx, [rel diag_service_failure_guid]
    mov r8d, SFR_ATTRS
    mov r9d, SFR_BYTES
    sub rsp, 48
    lea rax, [rel diag_service_failure_record]
    mov [rsp+32], rax
    call [r12+0x58]                    ; EFI_RUNTIME_SERVICES.SetVariable
    add rsp, 48
    test rax, rax
    jnz .report
    call diag_service_failure_read
    test rax, rax
    jnz .report
    cmp dword [rel diag_service_failure_attrs], SFR_ATTRS
    jne .report
    cmp qword [rel diag_service_failure_size], SFR_BYTES
    jne .report
    lea rdi, [rel diag_service_failure_verify]
    lea rsi, [rel diag_service_failure_record]
    mov ecx, SFR_BYTES/8
    repe cmpsq
    jne .report
    mov byte [rel diag_service_failure_status], 1
.report:
    lea rdi, [rel str_sfr_current]
    call serial_string
    movzx edi, byte [rel diag_service_failure_status]
    call serial_hex64
    lea rdi, [rel diag_service_failure_record]
    call diag_service_failure_fields
    lea rdi, [rel str_sfr_end]
    call serial_string
    pop r12
    pop rbx
    mov rsp, rbp
    pop rbp
.done:
    ret

; R12 runtime table; caller aligned. One bounded GetVariable, no mutation.
diag_service_failure_read:
    mov qword [rel diag_service_failure_size], SFR_BYTES
    mov dword [rel diag_service_failure_attrs], 0
    lea rcx, [rel diag_service_failure_name]
    lea rdx, [rel diag_service_failure_guid]
    lea r8, [rel diag_service_failure_attrs]
    lea r9, [rel diag_service_failure_size]
    sub rsp, 40
    lea rax, [rel diag_service_failure_verify]
    mov [rsp+32], rax
    call [r12+0x48]
    add rsp, 40
    ret

; RDI exact32B -> EAX1 only for complete known v1 scalar schema with CRC.
diag_service_failure_wire_ok:
    push rbx
    mov rbx, rdi
    xor eax, eax
    cmp dword [rbx], SFR_MAGIC
    jne .out
    cmp word [rbx+4], 1
    jne .out
    cmp word [rbx+6], SFR_BYTES
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
    cmp dword [rbx+24], 1
    jb .out
    cmp dword [rbx+24], 3
    ja .out
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
diag_service_failure_fields:
    push rbx
    mov rbx, rdi
    lea rdi, [rel str_sfr_delta]
    call serial_string
    mov edi, [rbx+12]
    call serial_hex64
    lea rdi, [rel str_sfr_build]
    call serial_string
    mov edi, [rbx+16]
    call serial_hex64
    lea rdi, [rel str_sfr_boot]
    call serial_string
    mov edi, [rbx+20]
    call serial_hex64
    lea rdi, [rel str_sfr_reason]
    call serial_string
    mov edi, [rbx+24]
    call serial_hex64
    lea rdi, [rel str_sfr_flags]
    call serial_string
    movzx edi, word [rbx+10]
    call serial_hex64
    pop rbx
    ret

%include "core/abi/wdata.inc"
%macro WDATA_svc_service_failure_record 0
align 8, db 0
diag_service_failure_baseline: dq 0
diag_service_failure_initialized: db 0
diag_service_failure_attempted: db 0
diag_service_failure_status: db 0             ; 0none 1saved 2refused 3uncertain 4identical
diag_service_failure_prev_status: db 0        ; 0absent 1valid 2unavailable 3unknown
align 8, db 0
diag_service_failure_size: dq 0
diag_service_failure_attrs: dd 0
align 8, db 0
diag_service_failure_record: times SFR_BYTES db 0
diag_service_failure_verify: times SFR_BYTES db 0
; Existing PaOSInitCheckpoint namespace (nvram_access registry row7).
diag_service_failure_guid:
    dd 0x7A965D12
    dw 0xC839, 0x4A77
    db 0xB1,0xE2,0x90,0x6E,0xF7,0x24,0x43,0x8C
diag_service_failure_name: dw 'P','a','O','S','S','e','r','v','i','c','e','F','a','i','l','u','r','e','R','e','c','o','r','d',0
str_sfr_previous: db "[diag.service-failure.previous] status=",0
str_sfr_current: db "[diag.service-failure.current] status=",0
str_sfr_delta: db " component=padn_terminal count=",0
str_sfr_build: db " build_prefix=",0
str_sfr_boot: db " ring_boot_low=",0
str_sfr_reason: db " reason=",0
str_sfr_flags: db " flags=",0
str_sfr_tag: db "diag-service-failure-record",0
str_sfr_end: db " provenance=post_initial_boot_baseline authority=diagnostic_only",13,10,0

%endmacro
WDATA_DEFER WDATA_svc_service_failure_record
