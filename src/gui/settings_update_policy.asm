;; MODULE gui/settings_update_policy
;; LAYER 6
;; EXPORTS settings_update_policy, settings_update_policy_current
;; IMPORTS gui/settings_updates, fs/data_config_authority, fs/data_config_provider, sec/data_config_local, sec/node_identity, core/lib/mem
;; CAPS CAP_GUI
;; OWNER rc-sec-claude
;; CONTEXT: bsp_only
; Internal native Settings component, NOT a worker/PIO/backend authority API.
; RDI=private exact take[40], CHECK1 / AUTO_ON3 / AUTO_OFF4 only.
; ->0 persisted manual (or CHECK confirmed absent),1 persisted automatic,
; -1 refused/unavailable,-2 busy,-3 uncertain. No completion or restart here.
; Caller must independently authenticate its worker and retain original40.
; Signed UPDATE.CFG: schema1/256/revision, sealed DATA identity64@16,
; consent semantics version1@80, auto download/stage u8@84, zero107@85,
; node signature64@192. No secrets/session tokens or restart permission.
; Unknown/stale formats NEVER migrate, default, truncate or overwrite bytes.
; Existing PAOS/PAOS2 and their rollback reader are untouched.
; In-boot revision floor (U1, ROOT109271 option C; wifi_store pattern): upol_read
; refuses (-1, never a default) a record below the highest revision this boot
; confirmed for the same DATA identity, a different record at that revision, and
; absence after one was confirmed; a write needs revision > floor. A write is
; confirmed only by its verified readback; an uncertain write latches -3.
; RESIDUAL: the floor is boot-lifetime. Across a reboot an older genuine
; owner-signed copy is still accepted; owner-only reachable per VR-1 (SEC109246).
; RESIDUAL: one slot. Within a boot, DATA A -> B -> A accepts a lower A revision
; (confirming B replaces A's floor); same class as the reboot residual, root
; accepted under ROOT109411 (2).
; PRECONDITION (ROOT109271 (B)): the first unit that adds a consumer of UPDATE CFG
; consent must either land a durable NV|BS consent floor on the replay_floor
; pattern (a boot-path design, with root acceptance and Peter's, plus a
; protected-region review), or carry an explicit root ruling accepting the
; reboot-rollback residual for that consumer.
%include "core/abi/wdata.inc"

settings_update_policy:
    push rbx
    cmp byte [rel upol_busy], 0
    jne .busy
    cmp byte [rel upol_uncertain], 0
    jne .uncertain_no_effect
    test rdi, rdi
    jz .null
    mov byte [rel upol_written], 0
    mov byte [rel upol_busy], 1
    mov rsi, rdi
    lea rdi, [rel upol_request]
    mov edx, 40
    call memcpy
    call settings_update_policy_current
    test eax, eax
    jnz .failed
    mov eax, [rel upol_request+8]
    cmp eax, 1
    je .op
    cmp eax, 3
    je .op
    cmp eax, 4
    jne .failed
.op:
    lea rdi, [rel upol_token]
    call data_config_acquire_provisioned
    test eax, eax
    jnz .failed
    call upol_read
    cmp eax, 1
    je .missing
    test eax, eax
    jnz .failed
    cmp dword [rel upol_request+8], 1
    je .loaded
    mov rbx, [rel upol_old+8]
    jmp .new
.missing:
    cmp dword [rel upol_request+8], 1
    je .manual
    xor ebx, ebx
.new:
    cmp rbx, -1
    je .failed
    inc rbx
    ; A write needs revision > this boot's confirmed floor (same DATA identity).
    call upol_floor_applies
    test eax, eax
    jnz .above_floor
    cmp rbx, [rel upol_floor+8]
    jbe .failed
.above_floor:
    lea rdi, [rel upol_new]
    xor esi, esi
    mov edx, 256
    call memset
    mov dword [rel upol_new], 'PUPC'
    mov word [rel upol_new+4], 1
    mov word [rel upol_new+6], 256
    mov [rel upol_new+8], rbx
    lea rdi, [rel upol_new+16]
    lea rsi, [rel upol_token+48]
    mov edx, 64
    call memcpy
    mov dword [rel upol_new+80], 1
    cmp dword [rel upol_request+8], 3
    sete byte [rel upol_new+84]
    lea rdi, [rel upol_new]
    mov esi, 192
    lea rdx, [rel upol_new+192]
    mov ecx, 64
    call node_identity_sign_active
    test eax, eax
    jnz .failed
    lea rdi, [rel upol_new]
    call upol_valid
    test eax, eax
    jnz .failed
    ; Fixed sec wrapper repeats exact40/deadline AND local owner at every
    ; underlying provider effect. Public callbacks cannot supply this checker.
    lea rdi, [rel upol_token]
    lea rsi, [rel upol_name]
    lea rdx, [rel upol_new]
    mov ecx, 256
    mov r8, [rel upol_request+16]
    mov r9, [rel upol_request+24]
    call data_config_write_updates
    cmp eax, -3
    je .uncertain
    test eax, eax
    jnz .failed
    mov byte [rel upol_written], 1
    ; Provider already flushes/reopens. Independently reopen exact bytes,
    ; validate node signature/binding/semantics/current request before success.
    call upol_read
    test eax, eax
    jnz .uncertain
    lea rdi, [rel upol_new]
    lea rsi, [rel upol_old]
    mov edx, 256
    call memcmp
    test eax, eax
    jnz .uncertain
.loaded:
    movzx ebx, byte [rel upol_old+84]
    jmp .current
.manual:
    xor ebx, ebx
.current:
    call settings_update_policy_current
    test eax, eax
    jz .success
    cmp byte [rel upol_written], 0
    jne .uncertain
    jmp .failed
.success:
    mov eax, ebx
    jmp .release
.uncertain:
    ; May have published: don't retry, read out enabled, or claim SAVED.
    ; Reconcile read-only from authenticated stored bytes after native restart.
    mov byte [rel upol_uncertain], 1
.uncertain_no_effect:
    mov eax, -3
    jmp .release
.busy:
    mov eax, -2
    pop rbx
    ret
.failed:
    mov eax, -1
.release:
    mov byte [rel upol_busy], 0
    pop rbx
    ret
.null:
    mov eax, -1
    pop rbx
    ret

; Fixed sec/data_config_local checker only. No authority outside this active
; serialized native operation; exact Settings generation/deadline never renewed.
; Return0 current / -1 refused, same convention as existing DATA fixed checkers.
settings_update_policy_current:
    cmp byte [rel upol_busy], 1
    jne .no
    lea rdi, [rel upol_request]
    sub rsp, 8
    call settings_updates_current
    add rsp, 8
    cmp eax, 1
    jne .no
    xor eax, eax
    ret
.no:
    mov eax, -1
    ret

; ->0 valid current,1 confirmed absent,-1 unavailable/corrupt/foreign/stale.
upol_read:
    sub rsp, 8
    lea rdi, [rel upol_token]
    lea rsi, [rel upol_name]
    lea rdx, [rel upol_old]
    mov ecx, 256
    call data_config_read
    cmp rax, -4
    je .missing
    cmp rax, 256
    jne .bad
    lea rdi, [rel upol_old]
    call upol_valid
    test eax, eax
    jnz .out
    ; In-boot confirmed record floor, not a reboot rollback guarantee.
    call upol_floor_applies
    test eax, eax
    jnz .confirm
    mov rax, [rel upol_floor+8]
    cmp [rel upol_old+8], rax
    jb .bad
    ja .confirm
    lea rdi, [rel upol_old]
    lea rsi, [rel upol_floor]
    mov edx, 256
    call memcmp
    test eax, eax
    jnz .bad
.confirm:
    lea rdi, [rel upol_floor]
    lea rsi, [rel upol_old]
    mov edx, 256
    call memcpy
    mov byte [rel upol_floor_valid], 1
    xor eax, eax
    jmp .out
.missing:
    ; Absence after this boot confirmed a record for this DATA is a rollback.
    call upol_floor_applies
    test eax, eax
    jz .bad
    mov eax, 1
    jmp .out
.bad:
    mov eax, -1
.out:
    add rsp, 8
    ret

; ->0 when this boot confirmed a record for the current token's DATA identity.
upol_floor_applies:
    cmp byte [rel upol_floor_valid], 0
    je .no
    sub rsp, 8
    lea rdi, [rel upol_floor+16]
    lea rsi, [rel upol_token+48]
    mov edx, 64
    call memcmp
    add rsp, 8
    ret
.no:
    mov eax, 1
    ret

upol_valid:
    push rbx
    mov rbx, rdi
    cmp dword [rdi], 'PUPC'
    jne .bad
    cmp word [rdi+4], 1
    jne .bad
    cmp word [rdi+6], 256
    jne .bad
    cmp qword [rdi+8], 0
    je .bad
    cmp dword [rdi+80], 1
    jne .bad
    cmp byte [rdi+84], 1
    ja .bad
    mov ecx, 85
.zero:
    cmp byte [rdi+rcx], 0
    jne .bad
    inc ecx
    cmp ecx, 192
    jb .zero
    lea rdi, [rbx+16]
    lea rsi, [rel upol_token+48]
    mov edx, 64
    call memcmp
    test eax, eax
    jnz .bad
    mov rdi, rbx
    mov esi, 192
    lea rdx, [rbx+192]
    mov ecx, 64
    call node_identity_verify
    test eax, eax
    jnz .bad
    lea rdi, [rel upol_token]
    call data_config_current
    test eax, eax
    jnz .bad
    call settings_update_policy_current
    pop rbx
    ret
.bad:
    mov eax, -1
    pop rbx
    ret

upol_name: db 'UPDATE  CFG'
%macro WDATA_gui_settings_update_policy 0
align 8, db 0
upol_token: times 112 db 0
upol_request: times 40 db 0
upol_old: times 256 db 0
upol_new: times 256 db 0
upol_floor: times 256 db 0
upol_floor_valid: db 0
upol_busy: db 0
upol_uncertain: db 0
upol_written: db 0
%endmacro
WDATA_DEFER WDATA_gui_settings_update_policy
