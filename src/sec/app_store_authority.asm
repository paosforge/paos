;; MODULE sec/app_store_authority
;; LAYER 5
;; EXPORTS app_store_data_write
;; IMPORTS fs/data_config_authority, fs/app_store_data, sec/app_store_intent
;; CAPS
;; OWNER saga:fs_wave
;; CONTEXT: bsp_only
; Fixed app-only writer. No caller-selected path/checker and no intent consume.
; app_store_effect_check is supplied by INPUT at composition, never a success stub.

; RDI=token112, RSI=record, RDX=len1..1MiB, RCX=intent, R8=1 install/2 remove.
; EAX0 durable+readback /-1 pre-effect refusal /-2 busy /-3 effect uncertain.
app_store_data_write:
    test rcx, rcx
    jz .no
    cmp r8, 1
    je .operation
    cmp r8, 2
    jne .no
.operation:
    mov r9, r8
    mov r8, rcx
    mov rcx, rdx
    mov rdx, rsi
    lea rsi, [rel asd_name]
    lea r11, [rel app_store_data_check]
    jmp data_config_write_app_guarded
.no:
    mov rax, -1
    ret

; Internal fixed callback: R8=intent, R9=op, RDX=provider's current token112.
; Provider freshly checks sealed role before and after this call at every effect.
app_store_data_check:
    mov rdi, r8
    mov esi, r9d
    jmp app_store_effect_check
