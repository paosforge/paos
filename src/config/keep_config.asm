;; MODULE config/keep_config
%include "core/abi/build_profile.inc"
;; LAYER 5
;; EXPORTS keep_push_load, keep_push_save, keep_push_open, keep_push_modes, keep_presentation_load, keep_presentation_save, keep_presentation_selftest, keep_presentation_target, keep_presentation_saved_target, keep_push_migrate
;; IMPORTS data/config_store, core/lib/mem, sec/principal, boot/serial
;; CAPS
;; OWNER saga:login_surfaces
; One independently switched, authenticated envelope. Unset/corrupt defaults
; to off. Endpoint tokens and the existing data-key handle are never projected.
PC_MODES equ 0
PC_PROVIDER equ 1                     ; 1 ntfy, 2 Gotify
PC_PORT equ 2
PC_HOST equ 8                        ; 96 incl NUL
PC_PATH equ 104                      ; 128 incl NUL
PC_TOKEN equ 232                     ; 128 incl NUL
PC_PIN equ 360                       ; SHA256 of exact owner-approved leaf DER
PC_HANDLE equ 392                    ; v2: one-way handle of the owner key, or zero (P1)
PC_SALT equ 424                      ; invalidates config after credential rotation
PC_PRESENTATION equ 440              ; 0 gui (safe/default), 1 cli

PRESENTATION_GUI equ 0
PRESENTATION_CLI equ 1

; Runtime target always starts at the reachable GUI policy. Persistence is
; allowed to override it only after the protected envelope and value validate.
keep_presentation_load:
    mov byte [rel keep_presentation_target], PRESENTATION_GUI
    mov byte [rel keep_presentation_saved_target], PRESENTATION_GUI
    call config_store_load
    test eax, eax
    jnz .out
    call keep_push_validate
    test eax, eax
    jnz .out
    mov al, [rel config_store_plain + PC_PRESENTATION]
    mov [rel keep_presentation_target], al
    mov [rel keep_presentation_saved_target], al
.out:
    jmp config_store_wipe

%if !PAOS_PUBLIC_BUILD
keep_push_load:
    mov byte [rel keep_push_modes], 0
    mov byte [rel keep_presentation_target], PRESENTATION_GUI
    mov byte [rel keep_presentation_saved_target], PRESENTATION_GUI
    call config_store_load
    test eax, eax
    jnz .out
    call keep_push_validate
    test eax, eax
    jnz .out
    mov al, [rel config_store_plain + PC_MODES]
    mov [rel keep_push_modes], al
    mov al, [rel config_store_plain + PC_PRESENTATION]
    mov [rel keep_presentation_target], al
    mov [rel keep_presentation_saved_target], al
.out:
    jmp config_store_wipe

keep_push_open:
    call config_store_open
    test eax, eax
    jnz .bad
    call keep_push_validate
    test eax, eax
    jnz .bad
    xor eax, eax
    ret
.bad:
    call config_store_wipe
    mov eax, -1
    ret

%endif
keep_push_validate:
    cmp byte [rel config_store_plain + PC_PRESENTATION], PRESENTATION_CLI
    ja .bad
    cmp byte [rel config_store_plain + PC_MODES], 7
    ja .bad
    cmp byte [rel config_store_plain + PC_MODES], 0
    je .ok
    cmp byte [rel prin_password_enrolled], 1
    jne .bad
    lea rdi, [rel config_store_plain + PC_SALT]
    lea rsi, [rel prin_password_salt]
    mov edx, 16
    call memcmp
    test eax, eax
    jnz .bad
    cmp byte [rel config_store_plain + PC_PROVIDER], 1
    jb .bad
    cmp byte [rel config_store_plain + PC_PROVIDER], 2
    ja .bad
    cmp word [rel config_store_plain + PC_PORT], 0
    je .bad
    cmp byte [rel config_store_plain + PC_HOST], 0
    je .bad
    cmp byte [rel config_store_plain + PC_HOST + 95], 0
    jne .bad
    cmp byte [rel config_store_plain + PC_PATH], '/'
    jne .bad
    cmp byte [rel config_store_plain + PC_PATH + 127], 0
    jne .bad
    cmp byte [rel config_store_plain + PC_TOKEN + 127], 0
    jne .bad
.ok:
    xor eax, eax
    ret
.bad:
    mov eax, -1
    ret

; SEC-owner-key-in-push-record (P1). RDI=plaintext about to be sealed. PC_HANDLE
; becomes the one-way handle of the owner key in RAM; without one, a handle that
; came from a PaOSPush2 record stays and anything else (a v1 handle IS the
; owner key) is zeroed. No save can carry a v1 handle forward.
%if !PAOS_PUBLIC_BUILD
keep_push_stamp_handle:
    push rbx
    mov rbx, rdi
    lea rdi, [rbx + PC_HANDLE]
    call principal_push_handle
    test eax, eax
    jz .out
    cmp byte [rel config_store_version], 2
    jne .zero
    lea rax, [rel config_store_plain]
    cmp rbx, rax                        ; only the loaded v2 plaintext itself
    je .out
.zero:
    lea rdi, [rbx + PC_HANDLE]
    xor esi, esi
    mov edx, 32
    call memset
.out:
    pop rbx
    ret

; Called by authenticate_bind after an owner bind that put the owner key in RAM
; (no lock held). Retires PaOSPush1 (root 12:58 slice 1): a v1 record, push on
; or off, is re-sealed as v2 with the one-way handle, and config_store_save
; deletes PaOSPush1 only after PaOSPush2 reopens to the same plaintext. Any
; failure keeps v1. A v1 that no longer validates (stale salt or modes) is
; carried over as its effective state: push off, GUI. When both exist, v2 is
; authoritative and v1 is only deleted. A v2 record that names another key
; is stale: push stays off for this boot.
keep_push_migrate:
    push rbx
    sub rsp, 32                         ; the derived handle
    call config_store_load
    test eax, eax
    jnz .out
    cmp byte [rel config_store_version], 1
    je .from_v1
    cmp byte [rel config_store_v1_present], 0
    je .bind
    call config_store_drop_v1
.bind:
    mov rdi, rsp
    call principal_push_handle
    test eax, eax
    jnz .out
    lea rdi, [rel config_store_plain + PC_HANDLE]
    mov rsi, rsp
    mov edx, 32
    call memcmp
    test eax, eax
    jz .out                             ; already bound to this key
    lea rdi, [rel config_store_plain + PC_HANDLE]
    lea rsi, [rel keep_zero_handle]
    mov edx, 32
    call memcmp
    test eax, eax
    jz .save                            ; unbound (zero): bind it now
    mov byte [rel keep_push_modes], 0
    lea rdi, [rel str_keep_stale_handle]
    call serial_string
    jmp .out
.from_v1:
    call keep_push_validate
    test eax, eax
    jz .save
    lea rdi, [rel config_store_plain]
    xor esi, esi
    mov edx, PC_SIZE
    call memset
.save:
    lea rdi, [rel config_store_plain]
%if !PAOS_PUBLIC_BUILD
    call keep_push_stamp_handle
%endif
    lea rdi, [rel config_store_plain]
    call config_store_save
.out:
    mov rdi, rsp
    xor esi, esi
    mov edx, 32
    call memset
    call config_store_wipe
    add rsp, 32
    pop rbx
    ret

; RDI=validated policy plaintext, caller has earned owner/password authority.
keep_push_save:
    push rbx
    mov bl, [rdi + PC_MODES]
    mov al, [rel keep_presentation_saved_target]
    mov [rdi + PC_PRESENTATION], al     ; unrelated push-policy writes preserve boot target
    push rdi
%if !PAOS_PUBLIC_BUILD
    call keep_push_stamp_handle
%endif
    pop rdi
    call config_store_save
    test eax, eax
    jnz .out
    mov [rel keep_push_modes], bl
.out:
    pop rbx
    ret

%endif
; keep_presentation_save(EDI=target) persists only the validated enum inside
; the existing protected envelope. A missing/corrupt envelope is rebuilt as a
; zeroed (push-off, GUI-default) record only for this explicit authenticated
; mutation; boot-time reads never repair or silently change durable state.
keep_presentation_save:
    push rbx
    mov ebx, edi
    cmp ebx, PRESENTATION_CLI
    ja .bad
    call config_store_load
    test eax, eax
    jnz .fresh
    call keep_push_validate
    test eax, eax
    jz .stage
.fresh:
    lea rdi, [rel config_store_plain]
    xor esi, esi
    mov edx, PC_SIZE
    call memset
.stage:
    mov [rel config_store_plain + PC_PRESENTATION], bl
    lea rdi, [rel config_store_plain]
%if !PAOS_PUBLIC_BUILD
    call keep_push_stamp_handle
%endif
    lea rdi, [rel config_store_plain]
    call config_store_save
    test eax, eax
    jnz .bad
    mov [rel keep_presentation_saved_target], bl
    xor eax, eax
    pop rbx
    ret
.bad:
    call config_store_wipe
    mov eax, -1
    pop rbx
    ret

; Action-free policy KAT: missing state starts GUI, both declared values are
; accepted, and the first invalid value is rejected. The live target is saved
; and restored so this proof cannot select a presentation mode.
keep_presentation_selftest:
    push rbx
    mov bl, [rel keep_presentation_target]
    mov byte [rel keep_presentation_target], PRESENTATION_GUI
    cmp byte [rel keep_presentation_target], PRESENTATION_GUI
    jne .fail
    mov byte [rel config_store_plain + PC_PRESENTATION], PRESENTATION_GUI
    call keep_presentation_value_validate
    test eax, eax
    jnz .fail
    mov byte [rel config_store_plain + PC_PRESENTATION], PRESENTATION_CLI
    call keep_presentation_value_validate
    test eax, eax
    jnz .fail
    mov byte [rel config_store_plain + PC_PRESENTATION], PRESENTATION_CLI + 1
    call keep_presentation_value_validate
    test eax, eax
    jz .fail
    mov [rel keep_presentation_target], bl
    call config_store_wipe
    lea rdi, [rel str_keep_gui_default]
    call serial_string
    xor eax, eax
    pop rbx
    ret
.fail:
    mov [rel keep_presentation_target], bl
    call config_store_wipe
    mov eax, -1
    pop rbx
    ret

%if PAOS_PUBLIC_BUILD
; Return 0 only when no protected second-factor policy is enrolled. Reading
; never repairs, migrates, or clears a legacy enrollment. A corrupt/unreadable
; existing record refuses; a genuinely missing config is handled by load.
keep_presentation_auth_allowed:
    call config_store_load
    test eax, eax
    jnz .unavailable
    cmp byte [rel config_store_plain + PC_MODES], 7
    ja .blocked
    test byte [rel config_store_plain + PC_MODES], 1
    jnz .blocked
    call config_store_wipe
    xor eax, eax
    ret
.blocked:
    call config_store_wipe
    mov eax, -1
    ret
.unavailable:
    call config_store_absent
    push rax
    call config_store_wipe
    pop rax
    dec eax                         ; 1 absent -> allow; 0 unknown -> refuse
    ret
%endif

keep_presentation_value_validate:
    cmp byte [rel config_store_plain + PC_PRESENTATION], PRESENTATION_CLI
    ja .bad_value
    xor eax, eax
    ret
.bad_value:
    mov eax, -1
    ret

%if !PAOS_PUBLIC_BUILD
keep_push_modes: db 0
%endif
keep_presentation_target: db PRESENTATION_GUI
keep_presentation_saved_target: db PRESENTATION_GUI
str_keep_gui_default: db "[PAOS64] login R4: out-of-box target remains gui and Task2502 gate remains intact [login.cli.gui_default]",13,10,0
%if !PAOS_PUBLIC_BUILD
keep_zero_handle: times 32 db 0
%endif
%if !PAOS_PUBLIC_BUILD
str_keep_stale_handle: db "[PAOS64] push: the push record names another owner key; push stays off this boot [push.record.stale_handle]",13,10,0
%endif
