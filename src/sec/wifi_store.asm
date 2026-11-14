;; MODULE sec/wifi_store
;; LAYER 5
;; EXPORTS wifi_owner_context_snapshot, wifi_store_replace_local, wifi_store_open_local, wifi_store_reconcile_local, wifi_store_wipe, wifi_store_owner_change_begin
;; IMPORTS sec/session, sec/owner_store, sec/principal, sec/node_identity, core/lib/aes256_gcm, core/lib/hkdf_sha256, core/lib/sha256, core/lib/mem, core/csprng, fs/storage_access, boot/header, svc/command, core/reset_wipe
;; CAPS
;; OWNER saga:sec
;; CONTEXT: bsp_only
; Fixed private donor, not a command or public getter. Original local INPUT
; consumer owns caller buffers and one-shot grants. VM owns private delivery.
; Composition must include this module, reset/cancel wipe, and call
; wifi_store_owner_change_begin BEFORE any runtime owner-stage effect attempt.
; That latch is deliberately boot-lifetime; no pending owner hash is committed.
; No durable antirollback floor is claimed. See gauntlet_v2/docs/WIFI_STORE.md.
WS_CONTEXT equ 128
WS_PLAIN equ 256
WS_RECORD equ 400
WS_NOT_FOUND equ 0x800000000000000e

; RDI=out128, RSI=128 -> 0 / 2 unavailable / 3 refused. Never candidate authority.
wifi_owner_context_snapshot:
    push rbx
    push r12
    xor r12d, r12d
    mov rbx, rdi
    test rbx, rbx
    jz .bad
    cmp rsi, WS_CONTEXT
    jne .bad
    mov r12d, 1
    xor esi, esi
    mov edx, WS_CONTEXT
    call memset
    cmp byte [rel ws_owner_blocked], 0
    jne .bad
    cmp byte [rel reset_wipe_done], 0
    jne .bad
    cmp byte [rel pbm_try_media], 0
    jne .bad
    cmp byte [rel cmd_in_dispatch], 0
    jne .bad
    cmp dword [rel cmd_dispatch_depth], 0
    jne .bad
    cmp byte [rel ows_state], 1           ; OWS_LOADED
    jne .bad
    cmp byte [rel ows_zbound], 1
    jne .bad
    cmp byte [rel ows_local], 1
    jne .bad
    cmp byte [rel prin_pw_authority], 1  ; PRIN_PWA_STORE
    jne .bad
    cmp byte [rel ows_selected], 1
    ja .bad
    cmp byte [rel ows_stage], 1          ; NONE or fully APPLIED only
    ja .bad
    cmp qword [rel ows_generation], 0
    je .bad
    lea rdi, [rel ows_committed_hash]
    mov esi, 32
    call ws_nonzero
    test eax, eax
    jz .bad
    call session_shell_local_authority
    cmp rax, PRIN_OWNER
    jne .bad
    mov [rbx+8], rax
    mov [rbx+16], rdx
    mov rax, [rel ows_generation]
    mov [rbx+24], rax
    lea rdi, [rbx+32]
    lea rsi, [rel ows_committed_hash]
    mov edx, 32
    call memcpy
    call node_identity_active
    cmp eax, 1
    jne .unavailable
    lea rdi, [rel ws_node_input]
    lea rsi, [rel ws_node_domain]
    mov edx, ws_node_domain.len
    call memcpy
    lea rdi, [rel ws_node_input+ws_node_domain.len]
    mov esi, 32
    call node_identity_public
    test eax, eax
    jnz .unavailable
    lea rdi, [rbx+64]
    lea rsi, [rel ws_node_input]
    mov edx, ws_node_domain.len+32
    call sha256_hash
    test eax, eax
    jnz .unavailable
    ; Identity helper is native/non-yielding. Recheck session after its work.
    call session_shell_local_authority
    cmp rax, [rbx+8]
    jne .bad
    cmp rdx, [rbx+16]
    jne .bad
    mov dword [rbx], 'WFAC'
    mov word [rbx+4], 1
    mov word [rbx+6], WS_CONTEXT
    xor eax, eax
    jmp .out
.unavailable:
    mov eax, 2
    jmp .zero
.bad:
    mov eax, 3
.zero:
    push rax
    test r12d, r12d
    jz .zero_done
    mov rdi, rbx
    xor esi, esi
    mov edx, WS_CONTEXT
    call memset
.zero_done:
    pop rax
.out:
    push rax
    lea rdi, [rel ws_node_input]
    xor esi, esi
    mov edx, ws_node_domain.len+32
    call memset
    pop rax
    pop r12
    pop rbx
    ret

; Internal nonzero byte range -> EAX 0/1.
ws_nonzero:
    xor eax, eax
    xor ecx, ecx
.loop:
    or al, [rdi+rcx]
    inc ecx
    cmp ecx, esi
    jb .loop
    test al, al
    setnz al
    movzx eax, al
    ret

; RDI=input context. Caller first owns ws_busy and later wipes scratch.
ws_capture:
    test rdi, rdi
    jz ws_current.bad
    mov rsi, rdi
    lea rdi, [rel ws_expected]
    mov edx, WS_CONTEXT
    call memcpy
ws_current:
    cmp byte [rel ws_cancelled], 0
    jne .bad
    lea rdi, [rel ws_current_context]
    mov esi, WS_CONTEXT
    call wifi_owner_context_snapshot
    test eax, eax
    jnz .out
    lea rdi, [rel ws_current_context]
    lea rsi, [rel ws_expected]
    mov edx, WS_CONTEXT
    call memcmp
    test eax, eax
    jnz .bad
    xor eax, eax
.out:
    ret
.bad:
    mov eax, 3
    ret

; Context/profile schema and native bindings. RDI=profile256.
ws_profile:
    push rbx
    mov rbx, rdi
    cmp dword [rbx], 'WFP1'
    jne .bad
    cmp word [rbx+4], 1
    jne .bad
    cmp word [rbx+6], WS_PLAIN
    jne .bad
    cmp qword [rbx+8], 0
    je .bad
    lea rdi, [rbx+16]
    lea rsi, [rel ws_expected+32]
    mov edx, 32
    call memcmp
    test eax, eax
    jnz .bad
    mov rax, [rel ws_expected+24]
    cmp [rbx+48], rax
    jne .bad
    lea rdi, [rbx+56]
    lea rsi, [rel ws_expected+64]
    mov edx, 32
    call memcmp
    test eax, eax
    jnz .bad
    lea rdi, [rbx+88]
    mov esi, 16
    call ws_nonzero
    test eax, eax
    jz .bad
    cmp dword [rbx+104], 1             ; binary WPA2-personal PSK32
    jne .bad
    mov ecx, [rbx+108]
    test ecx, ecx
    jz .bad
    cmp ecx, 32
    ja .bad
.padding:
    cmp ecx, 32
    jae .reserved
    cmp byte [rbx+112+rcx], 0
    jne .bad
    inc ecx
    jmp .padding
.reserved:
    mov ecx, 176
.zero:
    cmp byte [rbx+rcx], 0
    jne .bad
    inc ecx
    cmp ecx, WS_PLAIN
    jb .zero
    xor eax, eax
    pop rbx
    ret
.bad:
    mov eax, 3
    pop rbx
    ret

; All crypto is existing native code. Credential lock spans derivation only.
ws_key:
    call prin_credential_lock_acquire
    call principal_system_auth_credential
    test rax, rax
    jz .bad
    cmp edx, 32
    jne .bad
    mov rdi, rax
    mov esi, 32
    lea rdx, [rel ws_expected+32]
    mov ecx, 32
    lea r8, [rel ws_key_info]
    mov r9d, ws_key_domain.len+32
    sub rsp, 8
    lea rax, [rel ws_key_bytes]
    mov [rsp], rax
    call principal_hkdf32
    add rsp, 8
    push rax
    call prin_credential_lock_release
    pop rax
    ret
.bad:
    call prin_credential_lock_release
    mov eax, 2
    ret

; RDI=record, RSI=plaintext, EDX=0 open / 1 seal.
ws_aead:
    push rbx
    push r12
    push r13
    mov rbx, rdi
    mov r12, rsi
    mov r13d, edx
    lea rdi, [rel ws_key_info]
    lea rsi, [rel ws_key_domain]
    mov edx, ws_key_domain.len
    call memcpy
    lea rdi, [rel ws_key_info+ws_key_domain.len]
    lea rsi, [rel ws_expected+64]
    mov edx, 32
    call memcpy
    call ws_key
    test eax, eax
    jnz .out
    lea rax, [rel ws_request]
    lea rdx, [rel ws_key_bytes]
    mov [rax+AEAD_KEY], rdx
    lea rdx, [rbx+112]
    mov [rax+AEAD_NONCE], rdx
    mov [rax+AEAD_AAD], rbx
    mov qword [rax+AEAD_AAD_LEN], 128
    mov qword [rax+AEAD_INPUT_LEN], WS_PLAIN
    lea rdx, [rbx+384]
    mov [rax+AEAD_TAG], rdx
    lea rdx, [rbx+128]
    test r13d, r13d
    jnz .seal
    mov [rax+AEAD_INPUT], rdx
    mov [rax+AEAD_OUTPUT], r12
    mov rdi, rax
    call aes256_gcm_open
    jmp .out
.seal:
    mov [rax+AEAD_INPUT], r12
    mov [rax+AEAD_OUTPUT], rdx
    mov rdi, rax
    call aes256_gcm_seal
.out:
    push rax
    lea rdi, [rel ws_key_bytes]
    xor esi, esi
    mov edx, 32
    call memset
    pop rax
    pop r13
    pop r12
    pop rbx
    ret

; Authenticate ws_read and complete plaintext; independent expected identity.
ws_open_record:
    cmp dword [rel ws_read], 'WFS1'
    jne .bad
    cmp word [rel ws_read+4], 1
    jne .bad
    cmp word [rel ws_read+6], 128
    jne .bad
    cmp dword [rel ws_read+8], WS_RECORD
    jne .bad
    cmp dword [rel ws_read+12], WS_PLAIN
    jne .bad
    cmp dword [rel ws_read+124], 0
    jne .bad
    mov rax, [rel ws_expected+24]
    cmp [rel ws_read+16], rax
    jne .bad
    lea rdi, [rel ws_read+32]
    lea rsi, [rel ws_expected+32]
    mov edx, 64
    call memcmp
    test eax, eax
    jnz .bad
    lea rdi, [rel ws_read]
    lea rsi, [rel ws_plain]
    xor edx, edx
    call ws_aead
    test eax, eax
    jnz .bad
    lea rdi, [rel ws_plain]
    call ws_profile
    test eax, eax
    jnz .bad
    mov rax, [rel ws_plain+8]
    cmp [rel ws_read+24], rax
    jne .bad
    lea rdi, [rel ws_plain+88]
    lea rsi, [rel ws_read+96]
    mov edx, 16
    call memcmp
    test eax, eax
    jnz .bad
    ; In-boot exact confirmed record floor, not a reboot rollback guarantee.
    cmp byte [rel ws_confirmed_valid], 0
    je .ok
    mov rax, [rel ws_confirmed+24]
    cmp [rel ws_read+24], rax
    jb .bad
    ja .ok
    lea rdi, [rel ws_read]
    lea rsi, [rel ws_confirmed]
    mov edx, WS_RECORD
    call memcmp
    test eax, eax
    jnz .bad
.ok:
    xor eax, eax
    ret
.bad:
    mov eax, 3
    ret

ws_remember:
    lea rdi, [rel ws_confirmed]
    lea rsi, [rel ws_read]
    mov edx, WS_RECORD
    call memcpy
    mov byte [rel ws_confirmed_valid], 1
    ret

; Private read does not resolve a prior uncertain write implicitly.
wifi_store_open_local:
    push rbx
    push r12
    mov rbx, rsi
    mov r12, rdi
    test rbx, rbx
    jz .invalid
    cmp rdx, WS_PLAIN
    jne .invalid
    mov rdi, rbx
    xor esi, esi
    mov edx, WS_PLAIN
    call memset
    cmp byte [rel ws_busy], 0
    jne .invalid
    mov byte [rel ws_busy], 1
    mov byte [rel ws_cancelled], 0
    cmp byte [rel ws_uncertain], 0
    jne .uncertain
    mov rdi, r12
    call ws_capture
    test eax, eax
    jnz .out
    call ws_read_firmware
    test eax, eax
    jnz .out
    call ws_open_record
    test eax, eax
    jnz .out
    call ws_current
    test eax, eax
    jnz .out
    call ws_remember
    mov rdi, rbx
    lea rsi, [rel ws_plain]
    mov edx, WS_PLAIN
    call memcpy
    xor eax, eax
    jmp .out
.uncertain:
    mov eax, 4
.out:
    push rax
    call ws_finish
    pop rax
    pop r12
    pop rbx
    ret
.invalid:
    mov eax, 3
    pop r12
    pop rbx
    ret

wifi_store_replace_local:
    push rbx
    push r12
    mov rbx, rdi
    mov r12, rsi
    cmp byte [rel ws_busy], 0
    jne .invalid
    cmp rdx, WS_PLAIN
    jne .invalid
    test r12, r12
    jz .invalid
    mov byte [rel ws_busy], 1
    mov byte [rel ws_cancelled], 0
    cmp byte [rel ws_uncertain], 0
    jne .uncertain
    mov rdi, rbx
    call ws_capture
    test eax, eax
    jnz .out
    lea rdi, [rel ws_want]
    mov rsi, r12
    mov edx, WS_PLAIN
    call memcpy
    lea rdi, [rel ws_want]
    call ws_profile
    test eax, eax
    jnz .out
    call ws_read_firmware
    cmp eax, 1
    je .absent
    test eax, eax
    jnz .out
    call ws_open_record
    test eax, eax
    jnz .out
    mov rax, [rel ws_plain+8]
    add rax, 1
    jc .refuse
    cmp [rel ws_want+8], rax
    jne .refuse
    lea rdi, [rel ws_plain+88]
    lea rsi, [rel ws_want+88]
    mov edx, 16
    call memcmp
    test eax, eax
    jnz .refuse
    mov byte [rel ws_old_absent], 0
    lea rdi, [rel ws_old]
    lea rsi, [rel ws_read]
    mov edx, WS_RECORD
    call memcpy
    jmp .seal
.absent:
    cmp byte [rel ws_confirmed_valid], 0
    jne .refuse
    cmp qword [rel ws_want+8], 1
    jne .refuse
    mov byte [rel ws_old_absent], 1
.seal:
    lea rdi, [rel ws_next]
    xor esi, esi
    mov edx, WS_RECORD
    call memset
    mov dword [rel ws_next], 'WFS1'
    mov word [rel ws_next+4], 1
    mov word [rel ws_next+6], 128
    mov dword [rel ws_next+8], WS_RECORD
    mov dword [rel ws_next+12], WS_PLAIN
    mov rax, [rel ws_expected+24]
    mov [rel ws_next+16], rax
    mov rax, [rel ws_want+8]
    mov [rel ws_next+24], rax
    lea rdi, [rel ws_next+32]
    lea rsi, [rel ws_expected+32]
    mov edx, 64
    call memcpy
    lea rdi, [rel ws_next+96]
    lea rsi, [rel ws_want+88]
    mov edx, 16
    call memcpy
    lea rdi, [rel ws_next+112]
    mov esi, 12
    call csprng_generate
    test eax, eax
    jnz .unavailable
    lea rdi, [rel ws_next]
    lea rsi, [rel ws_want]
    mov edx, 1
    call ws_aead
    test eax, eax
    jnz .unavailable
    call ws_write_firmware
    test eax, eax
    jnz .out
    ; ws_uncertain was set BEFORE the actual firmware call, never on refusal.
    call ws_read_firmware
    test eax, eax
    jnz .uncertain
    lea rdi, [rel ws_read]
    lea rsi, [rel ws_next]
    mov edx, WS_RECORD
    call memcmp
    test eax, eax
    jnz .uncertain
    call ws_open_record
    test eax, eax
    jnz .uncertain
    lea rdi, [rel ws_plain]
    lea rsi, [rel ws_want]
    mov edx, WS_PLAIN
    call memcmp
    test eax, eax
    jnz .uncertain
    call ws_current
    test eax, eax
    jnz .uncertain
    call ws_remember
    mov byte [rel ws_uncertain], 0
    xor eax, eax
    jmp .out
.unavailable:
    mov eax, 2
    jmp .out
.refuse:
    mov eax, 3
    jmp .out
.uncertain:
    mov eax, 4
.out:
    push rax
    call ws_finish
    pop rax
    pop r12
    pop rbx
    ret
.invalid:
    mov eax, 3
    pop r12
    pop rbx
    ret

; Explicit read-only original-record reconciliation. Only exact old/new bytes
; resolve, including proven absence iff original was absent. Foreign/unreadable
; records leave uncertainty latched. Caller must select/grant anew afterward.
wifi_store_reconcile_local:
    push rbx
    mov rbx, rdi
    cmp byte [rel ws_busy], 0
    jne .invalid
    mov byte [rel ws_busy], 1
    mov byte [rel ws_cancelled], 0
    mov rdi, rbx
    call ws_capture
    test eax, eax
    jnz .out
    cmp byte [rel ws_uncertain], 1
    jne .invalid_owned
    call ws_read_firmware
    cmp eax, 1
    je .absent
    test eax, eax
    jnz .uncertain
    lea rdi, [rel ws_read]
    lea rsi, [rel ws_next]
    mov edx, WS_RECORD
    call memcmp
    test eax, eax
    jz .matched
    cmp byte [rel ws_old_absent], 0
    jne .uncertain
    lea rdi, [rel ws_read]
    lea rsi, [rel ws_old]
    mov edx, WS_RECORD
    call memcmp
    test eax, eax
    jnz .uncertain
.matched:
    call ws_open_record
    test eax, eax
    jnz .uncertain
    call ws_current
    test eax, eax
    jnz .uncertain
    call ws_remember
    jmp .resolved
.absent:
    cmp byte [rel ws_old_absent], 1
    jne .uncertain
    call ws_current
    test eax, eax
    jnz .uncertain
.resolved:
    mov byte [rel ws_uncertain], 0
    xor eax, eax
    jmp .out
.uncertain:
    mov eax, 4
    jmp .out
.invalid_owned:
    mov eax, 3
.out:
    push rax
    call ws_finish
    pop rax
    pop rbx
    ret
.invalid:
    mov eax, 3
    pop rbx
    ret

; EFI read: 0 exact, 1 genuine missing, 2 unavailable, 3 refused/unreadable.
ws_read_firmware:
    push rbp
    mov rbp, rsp
    push r12
    and rsp, -16
    sub rsp, 48
    call ws_runtime
    test eax, eax
    jnz .out
    mov r12, [rel runtime_services]
    mov qword [rel ws_size], WS_RECORD
    mov dword [rel ws_attrs], 0
    lea rcx, [rel ws_name]
    lea rdx, [rel ws_guid]
    lea r8, [rel ws_attrs]
    lea r9, [rel ws_size]
    lea rax, [rel ws_read]
    mov [rsp+32], rax
    call [r12+0x48]
    test rax, rax
    jz .check
    mov rdx, WS_NOT_FOUND
    cmp rax, rdx
    jne .bad
    mov eax, 1
    jmp .out
.check:
    cmp qword [rel ws_size], WS_RECORD
    jne .bad
    cmp dword [rel ws_attrs], 7
    jne .bad
    xor eax, eax
    jmp .out
.bad:
    mov eax, 3
.out:
    mov r12, [rbp-8]
    mov rsp, rbp
    pop rbp
    ret

ws_runtime:
    cmp byte [rel pbm_runtime_code_mapped], 1
    jne .bad
    cmp byte [rel reset_wipe_done], 0
    jne .bad
    cmp qword [rel runtime_services], 0
    je .bad
    xor eax, eax
    ret
.bad:
    mov eax, 2
    ret

; Last storage gate may block. Re-read original record then recheck the actual
; owner/epoch immediately before effect. No callback between check and SetVar.
ws_write_firmware:
    push rbp
    mov rbp, rsp
    push r12
    and rsp, -16
    sub rsp, 48
    call storage_access_request_intent
    mov edx, eax
    lea rdi, [rel ws_guid]
    lea rsi, [rel ws_name]
    lea rcx, [rel ws_audit_tag]
    call storage_access_nvram_require
    test rax, rax
    jnz .refuse
    call ws_read_firmware
    cmp byte [rel ws_old_absent], 1
    je .was_absent
    test eax, eax
    jnz .refuse
    lea rdi, [rel ws_read]
    lea rsi, [rel ws_old]
    mov edx, WS_RECORD
    call memcmp
    test eax, eax
    jnz .refuse
    jmp .authority
.was_absent:
    cmp eax, 1
    jne .refuse
.authority:
    call ws_runtime
    test eax, eax
    jnz .out
    call ws_current
    test eax, eax
    jnz .out
    mov r12, [rel runtime_services]
    mov byte [rel ws_uncertain], 1
    lea rcx, [rel ws_name]
    lea rdx, [rel ws_guid]
    mov r8d, 7
    mov r9d, WS_RECORD
    lea rax, [rel ws_next]
    mov [rsp+32], rax
    call [r12+0x58]
    test rax, rax
    jnz .uncertain
    xor eax, eax
    jmp .out
.uncertain:
    mov eax, 4
    jmp .out
.refuse:
    mov eax, 3
.out:
    mov r12, [rbp-8]
    mov rsp, rbp
    pop rbp
    ret

wifi_store_owner_change_begin:
    mov byte [rel ws_owner_blocked], 1
wifi_store_wipe:
    cmp byte [rel ws_busy], 0
    je ws_scrub
    ; Cancellation during a blocking gate must not destroy comparison state.
    mov byte [rel ws_cancelled], 1
    ret
ws_finish:
    call ws_scrub
    mov byte [rel ws_busy], 0
    ret
ws_scrub:
    lea rdi, [rel ws_transient]
    xor esi, esi
    mov edx, ws_transient_end-ws_transient
    jmp memset

ws_node_domain: db 'PaOS/WiFi/node/v1'
.len equ $-ws_node_domain
ws_key_domain: db 'PaOS/WiFi/profile-wrap/v1'
.len equ $-ws_key_domain
ws_audit_tag: db 'wifi_profile_store',0
align 2
ws_name: dw 'P','a','O','S','W','i','F','i','1',0
ws_guid: db 0x29,0xc1,0x6e,0x5a,0x54,0x25,0x4c,0x49,0x99,0xbd,0xb0,0x39,0x60,0xdf,0x47,0x04
%include "core/abi/wdata.inc"
%macro WDATA_sec_wifi_store 0
align 8
ws_busy: db 0
ws_cancelled: db 0
ws_owner_blocked: db 0
ws_uncertain: db 0
ws_old_absent: db 0
ws_confirmed_valid: db 0
align 8
ws_size: dq 0
ws_attrs: dd 0
ws_old: times WS_RECORD db 0
ws_next: times WS_RECORD db 0
ws_confirmed: times WS_RECORD db 0
ws_read: times WS_RECORD db 0
ws_transient:
ws_expected: times WS_CONTEXT db 0
ws_current_context: times WS_CONTEXT db 0
ws_key_bytes: times 32 db 0
ws_request: times AEAD_REQ_SZ db 0
ws_plain: times WS_PLAIN db 0
ws_want: times WS_PLAIN db 0
ws_key_info: times ws_key_domain.len+32 db 0
ws_node_input: times ws_node_domain.len+32 db 0
ws_transient_end:
%endmacro
WDATA_DEFER WDATA_sec_wifi_store
