; Optional production-policy diagnostic, not enabled in a release Manager.
; Actual firmware LoadImage is the oracle. Neither image is ever started.
; The signed diagnostic Manager binds both embedded public PE byte strings.
%ifdef PBM_DIAG_SB_PAIR
; Measure without adding raw input bytes to the PE. Large pairs use the
; maintained preparer's exact LZ4 block and single covered-byte mutation.
; The ordinary and combined-object small-pair paths remain byte-for-byte raw.
%ifndef PBM_MSI_COMBINED_OBJECT
[section .sbprobe_measure nobits]
sbprobe_input_start: incbin PBM_DIAG_SB_POSITIVE
sbprobe_input_end:
sbprobe_bad_input_start: incbin PBM_DIAG_SB_NEGATIVE
sbprobe_bad_input_end:
__SECT__
%if sbprobe_input_end-sbprobe_input_start != sbprobe_bad_input_end-sbprobe_bad_input_start
%error "SB pair PE sizes must match"
%endif
%if sbprobe_input_end-sbprobe_input_start < 512 || sbprobe_input_end-sbprobe_input_start > 2097152
%error "SB pair PE must be 512B..2MiB"
%endif
%if sbprobe_input_end - sbprobe_input_start > 393216
%strcat SBPROBE_PACKED_INCLUDE PBM_DIAG_SB_POSITIVE, ".sb3.inc"
%include SBPROBE_PACKED_INCLUDE
%if SBPROBE_PACKED_BYTES != sbprobe_input_end - sbprobe_input_start
%error "SB pair packed size differs from raw PE"
%endif
%if SBPROBE_MUTATION_OFFSET >= SBPROBE_PACKED_BYTES
%error "SB pair mutation outside PE"
%endif
%endif
%endif
%ifndef PBM_PRODUCTION_WITNESS
%error "SB pair requires the reviewed production entry witness"
%endif
%ifndef PBM_DIAG_ENTRY_CONTINUE
%error "SB pair must continue through ordinary signed native policy"
%endif
%ifndef PBM_DIAG_ENTRY_NONCE
%error "SB pair requires an operator-owned fresh diagnostic nonce"
%endif
%if PBM_DIAG_ENTRY_NONCE = 0
%error "SB pair nonce must be nonzero"
%endif
%ifndef PBM_DIAG_SB_POSITIVE
%error "SB pair requires exact existing public signed shim bytes"
%endif
%ifndef PBM_DIAG_SB_NEGATIVE
%error "SB pair requires the matching covered-byte mutation"
%endif
%ifdef PBM_DIAG_STAGE_TRACE
%error "SB receipt cannot share the stage-trace writer"
%endif
%ifdef PBM_DIAG_PREHEALTH_TRACE
%error "SB pair requires the ordinary continuing policy path"
%endif
%ifdef PBM_DIAG_RESOLVE_ONLY
%error "SB pair cannot use an early-return diagnostic"
%endif
%ifdef PBM_DIAG_STOP_AFTER_POLICY
%error "SB pair cannot use a later diagnostic receipt writer"
%endif

; EAX=0 only after actual SB=1/SetupMode=0, successful positive LoadImage,
; an exact LoadImage policy refusal with its matching handle contract on
; the negative (UEFI deny/defer or separately tagged shim no-handle refusal),
; all returned handles unloaded, and diagnostic
; SetVariable/byte-exact readback. The caller
; then boots the normal signed payload and uses its existing signed OS return.
; Any other outcome takes the Manager's prelaunch finite return. A firmware
; call that hangs remains under the existing finite watchdog; it earns no pass.
pbm_sb_negative_probe:
    push rbx
    push rsi
    push rdi
    cld
    mov byte [rel sbprobe_pass], 0
%ifdef SBPROBE_PACKED_BYTES
    mov qword [rel sbprobe_pool], 0
%endif
%ifdef PBM_MSI_COMBINED_OBJECT
    mov qword [rel sbprobe_detail + 16], -1
    mov qword [rel sbprobe_detail + 24], 0
    mov qword [rel sbprobe_detail + 32], -1
    mov qword [rel sbprobe_detail + 40], -1
    mov qword [rel sbprobe_detail + 48], 0
    mov qword [rel sbprobe_detail + 56], -1
    mov qword [rel sbprobe_detail + 64], 0
%endif
    mov rax, 'PSBTBAD2'
    mov [rel sbprobe_record], rax
    mov qword [rel sbprobe_record + 16], -1
    mov qword [rel sbprobe_record + 24], -1
    cmp qword [rel boot_services], 0
    je .refused
    cmp qword [rel runtime_services], 0
    je .refused
    cmp qword [rel image_handle], 0
    je .refused
    mov ecx, PBM_WATCHDOG_SECONDS
    call manager_watchdog_set
    test rax, rax
    jnz .refused                    ; no further firmware work without a bound
    lea rcx, [rel sbprobe_secure_boot]
    mov bl, 1
    call .trust
    test eax, eax
    jnz .finish
    lea rcx, [rel sbprobe_setup_mode]
    xor ebx, ebx
    call .trust
    test eax, eax
    jnz .finish

%ifdef SBPROBE_PACKED_BYTES
    call sbprobe_unpack_pair
    test eax, eax
    jnz .finish
    mov r9, [rel sbprobe_pool]
%else
    lea r9, [rel sbprobe_positive]
%endif
    call .load
    mov [rel sbprobe_record + 16], rax
%ifdef PBM_MSI_COMBINED_OBJECT
    mov [rel sbprobe_detail + 16], rax
    mov rdx, [rel sbprobe_child]
    mov [rel sbprobe_detail + 24], rdx
    or qword [rel sbprobe_detail + 64], 1
%endif
    test rax, rax
    jnz .positive_failed
    cmp qword [rel sbprobe_child], 0
    je .finish
    call .unload
    test rax, rax
    jnz .finish
%ifdef SBPROBE_PACKED_BYTES
    mov r9, [rel sbprobe_pool]
    add r9, SBPROBE_PACKED_BYTES
%else
    lea r9, [rel sbprobe_negative]
%endif
    call .load
    mov [rel sbprobe_record + 24], rax
%ifdef PBM_MSI_COMBINED_OBJECT
    mov [rel sbprobe_detail + 40], rax
    mov rdx, [rel sbprobe_child]
    mov [rel sbprobe_detail + 48], rdx
    or qword [rel sbprobe_detail + 64], 4
%endif
    ; UEFI 2.10, 7.4.1: ACCESS_DENIED prohibits loading (NULL handle);
    ; SECURITY_VIOLATION loads a handle but prohibits starting it.
    ; EDK2 DxeImageVerificationLib's DENY policy returns ACCESS_DENIED;
    ; its DEFER policy returns SECURITY_VIOLATION. Do not coerce either status.
    ; Distinct magics attest each checked contract in the same raw32 format.
    ; Alma shim 16.1 hooks LoadImage: verification failure frees the image and
    ; clears its handle while preserving SECURITY_VIOLATION. Tag that observed
    ; shim contract separately; it is not the UEFI loaded-handle contract.
    xor ebx, ebx
    mov rdx, 0x800000000000000F
    cmp rax, rdx
    je .negative_denied
    mov rdx, 0x800000000000001A
    cmp rax, rdx
    jne .negative_cleanup
    cmp qword [rel sbprobe_child], 0
    jne .negative_loaded
%ifdef PBM_MSI_COMBINED_OBJECT
    ; This first-child15.8 path attests firmware only. A shim-style no-handle
    ; SECURITY_VIOLATION is not the strict loaded-handle contract.
    jmp .finish
%endif
    mov rbx, 'PSBTSHN3'             ; shim rejected and left no loaded handle
    jmp .negative_clean
.negative_loaded:
    mov rbx, 'PSBTVIO2'
    jmp .negative_cleanup
.negative_denied:
    cmp qword [rel sbprobe_child], 0
    jne .negative_cleanup
    mov rbx, 'PSBTDEN2'
.negative_cleanup:
    ; Never start either image. Clean up even inconsistent error handles
    ; and unexpected successful admission, without granting them a pass.
    cmp qword [rel sbprobe_child], 0
    je .negative_clean
    call .unload
    test rax, rax
    jnz .finish
.negative_clean:
    test rbx, rbx
    jz .finish
    mov byte [rel sbprobe_pass], 1
    mov [rel sbprobe_record], rbx
    jmp .finish
.positive_failed:
    cmp qword [rel sbprobe_child], 0
    je .finish
    call .unload
.finish:
%ifdef SBPROBE_PACKED_BYTES
    mov rcx, [rel sbprobe_pool]
    test rcx, rcx
    jz .pool_done
    mov rax, [rel boot_services]
    PBM_FW_ENTER 32
    call [rax + 0x48]               ; FreePool: no pair storage survives child entry
    PBM_FW_LEAVE 32
    test rax, rax
    jz .pool_done
    mov byte [rel sbprobe_pass], 0
    mov rax, 'PSBTBAD2'
    mov [rel sbprobe_record], rax
.pool_done:
    mov qword [rel sbprobe_pool], 0
%endif
%ifdef PBM_MSI_COMBINED_OBJECT
    call sbprobe_detail_persist
    test eax, eax
    jz .detail_ok
    ; Never leave a strict-pass legacy receipt when companion readback fails.
    mov byte [rel sbprobe_pass], 0
    mov rax, 'PSBTBAD2'
    mov [rel sbprobe_record], rax
.detail_ok:
%endif
    call sbprobe_persist
    test eax, eax
    jnz .refused
    cmp byte [rel sbprobe_pass], 1
    jne .refused
    xor eax, eax
    jmp .out
.refused:
    mov eax, 1
.out:
    cld
    pop rdi
    pop rsi
    pop rbx
    ret
.load:
    mov qword [rel sbprobe_child], 0
    mov rax, [rel boot_services]
    xor ecx, ecx                    ; BootPolicy=FALSE; never a path search
    mov rdx, [rel image_handle]
    xor r8d, r8d                    ; SourceBuffer is the exact embedded PE
    PBM_FW_ENTER 48
%ifdef SBPROBE_PACKED_BYTES
    mov qword [rsp + 32], SBPROBE_PACKED_BYTES
%else
    mov qword [rsp + 32], sbprobe_positive_end - sbprobe_positive
%endif
    lea r10, [rel sbprobe_child]
    mov [rsp + 40], r10
    call [rax + 0xC8]               ; LoadImage, not StartImage
    PBM_FW_LEAVE 48
    ret
.unload:
    mov rcx, [rel sbprobe_child]
    mov qword [rel sbprobe_child], 0
%ifdef PBM_MSI_COMBINED_OBJECT
    test qword [rel sbprobe_detail + 64], 4
    jnz .unload_negative_flag
    or qword [rel sbprobe_detail + 64], 2
    jmp .unload_call
.unload_negative_flag:
    or qword [rel sbprobe_detail + 64], 8
.unload_call:
%endif
    mov rax, [rel boot_services]
    PBM_FW_ENTER 32
    call [rax + 0xE0]               ; UnloadImage (0xD8 is Exit)
    PBM_FW_LEAVE 32
%ifdef PBM_MSI_COMBINED_OBJECT
    test qword [rel sbprobe_detail + 64], 4
    jnz .unload_negative_result
    mov [rel sbprobe_detail + 32], rax
    ret
.unload_negative_result:
    mov [rel sbprobe_detail + 56], rax
%endif
    ret
.trust:
    mov qword [rel sbprobe_trust_size], 1
    mov dword [rel sbprobe_trust_attrs], 0
    mov rax, 0xB748E6ACF139025D
    mov [rel sbprobe_guard_before], rax
    mov [rel sbprobe_guard_after], rax
    mov byte [rel sbprobe_trust_data], 0xFF
    lea rdx, [rel sbprobe_global_guid]
    lea r8, [rel sbprobe_trust_attrs]
    lea r9, [rel sbprobe_trust_size]
    mov rax, [rel runtime_services]
    PBM_FW_ENTER 40
    lea r10, [rel sbprobe_trust_data]
    mov [rsp + 32], r10
    call [rax + 0x48]               ; GetVariable
    PBM_FW_LEAVE 40
    test rax, rax
    jnz .trust_bad
    mov rax, 0xB748E6ACF139025D
    cmp [rel sbprobe_guard_before], rax
    jne .trust_bad
    cmp [rel sbprobe_guard_after], rax
    jne .trust_bad
    cmp qword [rel sbprobe_trust_size], 1
    jne .trust_bad
    cmp dword [rel sbprobe_trust_attrs], 6
    jne .trust_bad
    cmp [rel sbprobe_trust_data], bl
    jne .trust_bad
    xor eax, eax
    ret
.trust_bad:
    mov eax, 1
    ret

%ifdef SBPROBE_PACKED_BYTES
; Allocate transient firmware storage, reconstruct the exact positive image,
; copy it and apply the builder-verified one-byte XOR. Neither image is started.
sbprobe_unpack_pair:
    push rsi
    push rdi
    mov rax, 'PSBPK001'
    cmp [rel sbprobe_positive], rax
    jne .bad
    cmp qword [rel sbprobe_positive + 8], SBPROBE_PACKED_BYTES
    jne .bad
    cmp qword [rel sbprobe_positive + 16], SBPROBE_MUTATION_OFFSET
    jne .bad
    cmp qword [rel sbprobe_positive + 24], 1
    jne .bad
    cmp qword [rel sbprobe_positive + 32], sbprobe_positive_end-sbprobe_positive-40
    jne .bad
    mov ecx, 2                     ; EfiLoaderData, never a fixed PaOS reservation
    mov edx, SBPROBE_PACKED_BYTES * 2
    lea r8, [rel sbprobe_pool]
    mov rax, [rel boot_services]
    PBM_FW_ENTER 32
    call [rax + 0x40]               ; AllocatePool
    PBM_FW_LEAVE 32
    test rax, rax
    jnz .bad
    cmp qword [rel sbprobe_pool], 0
    je .bad
    lea rsi, [rel sbprobe_positive + 40]
    lea rdx, [rel sbprobe_positive_end]
    mov rdi, [rel sbprobe_pool]
    mov ecx, SBPROBE_PACKED_BYTES
    call sbprobe_lz4
    test eax, eax
    jnz .bad
    mov rsi, [rel sbprobe_pool]
    lea rdi, [rsi + SBPROBE_PACKED_BYTES]
    mov ecx, SBPROBE_PACKED_BYTES
    rep movsb
    mov rax, [rel sbprobe_pool]
    xor byte [rax + SBPROBE_PACKED_BYTES + SBPROBE_MUTATION_OFFSET], 1
    xor eax, eax
    jmp .out
.bad:
    mov eax, 1
.out:
    pop rdi
    pop rsi
    ret

; Bounded raw LZ4 block decoder. RSI=input, RDX=end, RDI=output, ECX=exact
; output bytes. Every read/write and backwards match is checked before access.
; A truncated block or any non-exact output refuses the diagnostic.
sbprobe_lz4:
    push rbx
    push rbp
    push r12
    mov r8, rdi                    ; output start
    lea r9, [rdi + rcx]             ; output end
    mov r10, rdx                   ; input end
.token:
    cmp rsi, r10
    jae .bad
    movzx ebx, byte [rsi]
    inc rsi
    mov ecx, ebx
    shr ecx, 4
    cmp ecx, 15
    jne .literals
    call .extend
    test eax, eax
    jnz .bad
.literals:
    lea rax, [rsi + rcx]
    cmp rax, r10
    ja .bad
    lea rax, [rdi + rcx]
    cmp rax, r9
    ja .bad
    rep movsb
    cmp rsi, r10
    je .done
    lea rax, [rsi + 2]
    cmp rax, r10
    ja .bad
    movzx edx, word [rsi]
    add rsi, 2
    test edx, edx
    jz .bad
    mov rbp, rdi
    sub rbp, rdx
    cmp rbp, r8
    jb .bad
    mov ecx, ebx
    and ecx, 15
    cmp ecx, 15
    jne .match
    call .extend
    test eax, eax
    jnz .bad
.match:
    add ecx, 4
    lea rax, [rdi + rcx]
    cmp rax, r9
    ja .bad
    mov r12, rsi
    mov rsi, rbp
    rep movsb                     ; deliberately permits overlapping matches
    mov rsi, r12
    jmp .token
.done:
    cmp rdi, r9
    jne .bad
    xor eax, eax
    jmp .out
.extend:
    cmp rsi, r10
    jae .extend_bad
    movzx eax, byte [rsi]
    inc rsi
    add ecx, eax
    cmp ecx, SBPROBE_PACKED_BYTES  ; length cannot wrap or exceed the output
    ja .extend_bad
    cmp eax, 255
    je .extend
    xor eax, eax
    ret
.extend_bad:
    mov eax, 1
    ret
.bad:
    mov eax, 1
.out:
    pop r12
    pop rbp
    pop rbx
    ret
%endif

; Separate diagnostic name preserves the established PaOSMgrDiag entry witness.
; This record is observation only, never manifest/journal/authentication input.
sbprobe_persist:
    mov rbx, [rel runtime_services]
    lea rcx, [rel sbprobe_var_name]
    lea rdx, [rel diag_var_guid]
    mov r8d, 7
    mov r9d, 32
    PBM_FW_ENTER 40
    lea rax, [rel sbprobe_record]
    mov [rsp + 32], rax
    call [rbx + 0x58]
    PBM_FW_LEAVE 40
    test rax, rax
    jnz .bad
    mov qword [rel sbprobe_read_size], 32
    mov dword [rel sbprobe_read_attrs], 0
    lea rcx, [rel sbprobe_var_name]
    lea rdx, [rel diag_var_guid]
    lea r8, [rel sbprobe_read_attrs]
    lea r9, [rel sbprobe_read_size]
    PBM_FW_ENTER 40
    lea rax, [rel sbprobe_readback]
    mov [rsp + 32], rax
    call [rbx + 0x48]
    PBM_FW_LEAVE 40
    test rax, rax
    jnz .bad
    cmp qword [rel sbprobe_read_size], 32
    jne .bad
    cmp dword [rel sbprobe_read_attrs], 7
    jne .bad
    lea rsi, [rel sbprobe_record]
    lea rdi, [rel sbprobe_readback]
    mov ecx, 4
    repe cmpsq
    jne .bad
    xor eax, eax
    ret
.bad:
    mov eax, 1
    ret
%ifdef PBM_MSI_COMBINED_OBJECT
; Full64 statuses/handles/actual cleanup, with call flags and the same nonce.
sbprobe_detail_persist:
    mov rbx, [rel runtime_services]
    lea rcx, [rel sbprobe_detail_name]
    lea rdx, [rel diag_var_guid]
    mov r8d, 7
    mov r9d, 72
    PBM_FW_ENTER 40
    lea rax, [rel sbprobe_detail]
    mov [rsp + 32], rax
    call [rbx + 0x58]
    PBM_FW_LEAVE 40
    test rax, rax
    jnz .bad
    mov qword [rel sbprobe_detail_read_size], 72
    mov dword [rel sbprobe_detail_read_attrs], 0
    lea rcx, [rel sbprobe_detail_name]
    lea rdx, [rel diag_var_guid]
    lea r8, [rel sbprobe_detail_read_attrs]
    lea r9, [rel sbprobe_detail_read_size]
    PBM_FW_ENTER 40
    lea rax, [rel sbprobe_detail_readback]
    mov [rsp + 32], rax
    call [rbx + 0x48]
    PBM_FW_LEAVE 40
    test rax, rax
    jnz .bad
    cmp qword [rel sbprobe_detail_read_size], 72
    jne .bad
    cmp dword [rel sbprobe_detail_read_attrs], 7
    jne .bad
    lea rsi, [rel sbprobe_detail]
    lea rdi, [rel sbprobe_detail_readback]
    mov ecx, 9
    repe cmpsq
    jne .bad
    xor eax, eax
    ret
.bad:
    mov eax, 1
    ret
%endif

%endif

%macro SBPROBE_RDATA 0
%ifdef PBM_DIAG_SB_PAIR
align 8
sbprobe_global_guid:
    dd 0x8BE4DF61
    dw 0x93CA, 0x11D2
    db 0xAA,0x0D,0x00,0xE0,0x98,0x03,0x2B,0x8C
sbprobe_secure_boot: dw 'S','e','c','u','r','e','B','o','o','t',0
sbprobe_setup_mode: dw 'S','e','t','u','p','M','o','d','e',0
sbprobe_var_name: dw 'P','a','O','S','S','b','P','r','o','b','e',0
%ifdef PBM_MSI_COMBINED_OBJECT
sbprobe_detail_name: dw 'P','a','O','S','S','b','D','e','t','a','i','l',0
%endif
align 8
sbprobe_positive:
%ifdef SBPROBE_PACKED_BYTES
SBPROBE_PACKED_DATA
%else
incbin PBM_DIAG_SB_POSITIVE
%endif
sbprobe_positive_end:
%ifndef SBPROBE_PACKED_BYTES
sbprobe_negative: incbin PBM_DIAG_SB_NEGATIVE
sbprobe_negative_end:
%if (sbprobe_positive_end - sbprobe_positive) < 512 || (sbprobe_positive_end - sbprobe_positive) > 2097152
%error "SB pair PE must be 512B..2MiB"
%endif
%if (sbprobe_negative_end - sbprobe_negative) != (sbprobe_positive_end - sbprobe_positive)
%error "SB pair PE sizes must match"
%endif
%endif
%endif
%endmacro

%macro SBPROBE_MUTABLE 0
%ifdef PBM_DIAG_SB_PAIR
align 8
%ifdef PBM_MSI_COMBINED_OBJECT
sbprobe_detail: db 'PSBTDTL1'
    dq PBM_DIAG_ENTRY_NONCE, -1, 0, -1, -1, 0, -1, 0
sbprobe_detail_read_size: dq 0
sbprobe_detail_read_attrs: dd 0
sbprobe_detail_readback: times 72 db 0
%endif
sbprobe_record: db 'PSBTBAD2'
    dq PBM_DIAG_ENTRY_NONCE, -1, -1
sbprobe_child: dq 0
%ifdef SBPROBE_PACKED_BYTES
sbprobe_pool: dq 0
%endif
sbprobe_trust_size: dq 0
sbprobe_trust_attrs: dd 0
sbprobe_pass: db 0
sbprobe_read_size: dq 0
sbprobe_read_attrs: dd 0
sbprobe_readback: times 32 db 0
align 8
sbprobe_guard_before: dq 0
sbprobe_trust_data: times 16 db 0
sbprobe_guard_after: dq 0
%endif
%endmacro
