;; MODULE core/boot_maintenance_source
;; LAYER 1
;; CONTEXT: bsp_only
;; EXPORTS boot_v2_maintenance_events_import
;; IMPORTS boot/boot_v2_health, boot/boot_v2_handoff, boot/header, core/maintenance_record, core/lib/sha256
;; CAPS
;; OWNER rc-boot-claude
; Read-only adapters of canonical retained diagnostic records. Normal BSP once
; after device-failure projection, never Manager, IRQ, Safe or boot authority.
; Store append owns dedup/budget/uncertainty. No source retry, clear or repair.
%include "core/abi/maintenance.inc"
%include "boot/image_refusal.inc"

boot_v2_maintenance_events_import:
    push rbp
    mov rbp,rsp
    and rsp,-16
    push rbx
    push r12
    push r13
    push r14
    cmp byte [rel boot_maintenance_imported],0
    jne .out
    mov byte [rel boot_maintenance_imported],1
    cmp byte [rel pbm_manager_launch],1
    jne .out
    cmp byte [rel pbm_runtime_code_mapped],1
    jne .out
    mov r12,[rel runtime_services]
    test r12,r12
    jz .out
    ; The retained archive is imported even if this boot did not write it.
    call boot_v2_failure_checkpoint_read
    test rax,rax
    jnz .image
    cmp dword [rel pbm_failure_checkpoint_attrs],7
    jne .image
    cmp qword [rel pbm_failure_checkpoint_size],128
    jne .image
    lea rsi,[rel pbm_failure_checkpoint_verify]
    lea rdi,[rel boot_maintenance_sanitized]
    call boot_v2_failure_checkpoint_prepare
    test eax,eax
    jz .image
    lea rsi,[rel pbm_failure_checkpoint_verify]
    lea rdi,[rel boot_maintenance_sanitized]
    mov ecx,16
    repe cmpsq
    jne .image                         ; no raw/live nonce or timing accepted
    call boot_maintenance_clear_event
    mov dword [rel boot_maintenance_event+ME_SOURCE],1
    mov word [rel boot_maintenance_event+ME_COMPONENT],1
    mov al,[rel boot_maintenance_sanitized+PBM_INIT_STAGE_OFF]
    mov [rel boot_maintenance_event+ME_PHASE],al
    mov byte [rel boot_maintenance_event+ME_GATE],255
    cmp word [rel boot_maintenance_sanitized+PBM_INIT_VERSION_OFF],PBM_INIT_GRAPH_VERSION
    jne .archive_gate_ready
    mov al,[rel boot_maintenance_sanitized+PBM_INIT_GATE_OFF]
    mov [rel boot_maintenance_event+ME_GATE],al
.archive_gate_ready:
    ; Source error: low8 = PBIC result+1, bits8..23 = implicated subsystem.
    movzx eax,byte [rel boot_maintenance_sanitized+PBM_INIT_RESULT_OFF]
    inc eax
    movzx edx,word [rel boot_maintenance_sanitized+PBM_INIT_IMPLICATED_OFF]
    shl edx,8
    or eax,edx
    mov [rel boot_maintenance_event+ME_ERROR],eax
    lea rsi,[rel boot_maintenance_sanitized+PBM_INIT_PAYLOAD_SHA_OFF]
    call boot_maintenance_identity
    lea rsi,[rel boot_maintenance_sanitized]
    call boot_maintenance_append
.image:
    mov qword [rel boot_maintenance_size],PBIR_BYTES
    mov dword [rel boot_maintenance_attrs],0
    lea rcx,[rel boot_maintenance_image_name]
    lea rdx,[rel pbm_init_var_guid]
    lea r8,[rel boot_maintenance_attrs]
    lea r9,[rel boot_maintenance_size]
    sub rsp,48
    lea rax,[rel boot_maintenance_sanitized]
    mov [rsp+32],rax
    call [r12+0x48]
    add rsp,48
    test rax,rax
    jnz .out
    cmp dword [rel boot_maintenance_attrs],7
    jne .out
    cmp qword [rel boot_maintenance_size],PBIR_BYTES
    jne .out
    lea rdi,[rel boot_maintenance_sanitized]
    call boot_maintenance_image_valid
    test eax,eax
    jz .out
    call boot_maintenance_clear_event
    mov dword [rel boot_maintenance_event+ME_SOURCE],2
    mov word [rel boot_maintenance_event+ME_COMPONENT],2
    mov byte [rel boot_maintenance_event+ME_PHASE],255
    mov byte [rel boot_maintenance_event+ME_GATE],255
    movzx eax,byte [rel boot_maintenance_sanitized+9]
    mov [rel boot_maintenance_event+ME_ERROR],eax
    lea rsi,[rel boot_maintenance_sanitized+32]
    call boot_maintenance_identity
    lea rsi,[rel boot_maintenance_sanitized]
    call boot_maintenance_append
.out:
    pop r14
    pop r13
    pop r12
    pop rbx
    mov rsp,rbp
    pop rbp
    ret

boot_maintenance_clear_event:
    lea rdi,[rel boot_maintenance_event]
    xor eax,eax
    mov ecx,ME_RECORD_BYTES/8
    rep stosq
    ret

; RSI=validated source's full32B image digest. Zero is honestly UNKNOWN.
boot_maintenance_identity:
    mov rax,[rsi]
    or rax,[rsi+8]
    or rax,[rsi+16]
    or rax,[rsi+24]
    jz .out
    mov dword [rel boot_maintenance_event+ME_IDENTITY],1
    lea rdi,[rel boot_maintenance_event+ME_BUILD]
    mov ecx,4
    rep movsq
.out:
    ret

; RSI=canonical sanitized128B, digest success required before append.
boot_maintenance_append:
    lea rdi,[rel boot_maintenance_event+ME_SOURCE_DIGEST]
    mov edx,128
    call sha256_hash
    test rax,rax
    jnz .out
    lea rdi,[rel boot_maintenance_event]
    call maintenance_event_append
.out:
    ret

PBIR_VALIDATOR boot_maintenance_image_valid,pbm_crc32,esi
align 2
boot_maintenance_image_name: dw 'P','a','O','S','I','m','a','g','e','R','e','f','u','s','a','l','R','e','c','o','r','d',0
%include "core/abi/wdata.inc"
%macro WDATA_boot_maintenance_source 0
boot_maintenance_imported: db 0
align 8
boot_maintenance_size: dq 0
boot_maintenance_attrs: dd 0
align 8
boot_maintenance_sanitized: times 128 db 0
boot_maintenance_event: times ME_RECORD_BYTES db 0
%endmacro
WDATA_DEFER WDATA_boot_maintenance_source
