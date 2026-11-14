;; MODULE sec/update_request
;; LAYER 5
;; EXPORTS update_request_valid, update_request_take, update_request_current, upd_serial, upd_deadline, upd_pid, upd_token, upd_phase, upd_status, upd_op, upd_backend
;; IMPORTS sec/session, svc/command, svc/command_auth, core/time
;; CAPS
;; OWNER rc-input-claude
;; CONTEXT: bsp_only
; Native request record and policy, shared by the fixed GUI publisher and fixed
; VM consumer. No GUI dependency, callbacks, registration or guest setter.
; Only the existing native GUI producer creates/invalidates these named fields;
; they are NOT an untrusted pointer ABI or a worker publication path. The GUI
; retains presentation, discovery, gestures, result validation and restart UI.
; Every read validates actual backend/session/local-command/deadline state.
; Take consumes phase1 once; current requires exact original40 and phase2.
; Same BSP/non-yielding invariant as the former GUI-local implementation.
%include "core/abi/wdata.inc"

update_request_valid:
    cmp byte [rel upd_backend], 1
    jne .no
    cmp byte [rel session_locked], SESSION_LOCKED
    je .no
    cmp byte [rel cmd_in_dispatch], 0
    jne .no
    cmp byte [rel command_auth_remote_active], 0
    jne .no
    call session_shell_local_authority
    cmp rax, PRIN_OWNER
    jne .no
    cmp rax, [rel upd_pid]
    jne .no
    test rdx, rdx
    jz .no
    cmp rdx, [rel upd_token]
    jne .no
    call boot_ms_now
    cmp rax, [rel upd_deadline]
    jae .no
    mov eax, 1
    ret
.no:
    xor eax, eax
    ret

update_request_take:
    cmp dword [rel upd_phase], 1
    jne .no
    push rdi
    call update_request_valid
    pop rdi
    test eax, eax
    jz .expire
    mov rax, [rel upd_serial]
    mov [rdi], rax
    mov eax, [rel upd_op]
    mov [rdi+8], eax
    mov dword [rdi+12], 1
    mov rax, [rel upd_pid]
    mov [rdi+16], rax
    mov rax, [rel upd_token]
    mov [rdi+24], rax
    mov rax, [rel upd_deadline]
    mov [rdi+32], rax
    mov dword [rel upd_phase], 2
    mov eax, 1
    ret
.expire:
    mov dword [rel upd_phase], 0
    mov dword [rel upd_status], 8
.no:
    xor eax, eax
    ret

; Trusted native bridge only: RDI=private exact original40B -> EAX=1/0.
; Read-only and repeatable while the one taken request remains current. It
; grants no guest/process identity, ESP lease or engine-result authority.
; Called synchronously before an effect; no yield may follow authorization.
update_request_current:
    test rdi, rdi
    jz .no
    cmp dword [rel upd_phase], 2
    jne .no
    mov rax, [rdi]
    cmp rax, [rel upd_serial]
    jne .no
    mov eax, [rdi+8]
    cmp eax, [rel upd_op]
    jne .no
    cmp dword [rdi+12], 1
    jne .no
    mov rax, [rdi+16]
    cmp rax, [rel upd_pid]
    jne .no
    mov rax, [rdi+24]
    cmp rax, [rel upd_token]
    jne .no
    mov rax, [rdi+32]
    cmp rax, [rel upd_deadline]
    jne .no
    jmp update_request_valid
.no:
    xor eax, eax
    ret

%macro WDATA_sec_update_request 0
align 8
upd_serial: dq 0
upd_deadline: dq 0
upd_pid: dq 0
upd_token: dq 0
upd_phase: dd 0
upd_status: dd 0
upd_op: dd 0
upd_backend: db 0
%endmacro
WDATA_DEFER WDATA_sec_update_request
