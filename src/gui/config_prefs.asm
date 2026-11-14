;; MODULE gui/config_prefs
;; LAYER 6
;; EXPORTS config_prefs_load, config_prefs_save, config_prefs_state
;; IMPORTS gui/wallpaper_prefs, fs/data_config_provider, fs/data_config_authority, sec/data_config_local, sec/node_identity, sec/session, sec/principal, svc/command, svc/command_auth, gui/window, gui/kbd_prefs, gui/lang_prefs, core/lib/mem, boot/serial
;; CAPS CAP_GUI
;; OWNER rc-input-claude
;; CONTEXT: bsp_only
; PAOS.CFG v1, exactly256B: PCFG/u16version/u16size, u64revision,
; partitionstart+descriptor56 @16, timezone minutes i32@80, zone u8@84,
; keyboard choice u8@85, stock wallpaper u8@86 (0default/1..9), zero@87, language padded ASCII8@88, zero96@96,
; native node signature64@192 over preceding192B. Public preferences only.
; The local owner authorizes the action; the node authenticates saved bytes.
; No credential/boot policy, request-global swap, raw disk IO or exported key.
; DATA is primary when valid; legacy protected NVRAM remains compatibility.
; A malformed existing file is never silently replaced. Uncertainty is sticky
; until restart/read-only boot reconciliation; no automatic resend or worker.

CFP_SIZE equ 256
CFP_SIGNED equ 192
CFP_UNLOADED equ 0
CFP_PENDING equ 1
CFP_REFUSED equ 2
CFP_LOADED equ 3
CFP_SAVED equ 4
CFP_UNCERTAIN equ 5

; Once at boot, after legacy loaders, before locale pack/sign-in composition.
; All fields/signature/current media validated before any preference changes.
config_prefs_load:
    cmp byte [rel config_prefs_state], CFP_UNLOADED
    jne .out
    cmp byte [rel cfp_busy], 0
    jne .out
    push rbx
    mov byte [rel cfp_busy], 1
    mov byte [rel config_prefs_state], CFP_PENDING
    lea rdi, [rel cfp_token]
    call data_config_bind_provisioned
    test eax, eax
    jnz .pending
    call cfp_read
    cmp eax, 1
    je .pending
    test eax, eax
    jnz .refused
    ; Both legacy arenas must exist before importing any member. These
    ; getters/imports allocate nothing, perform no IO and never save NVRAM.
    call kbd_prefs_data_choice
    test eax, eax
    js .pending
    call lang_prefs_data_choice
    test rax, rax
    jz .pending
    movzx edi, byte [rel cfp_old+85]
    call kbd_prefs_data_apply
    lea rdi, [rel cfp_old+88]
    call lang_prefs_data_apply
    mov eax, [rel cfp_old+80]
    mov [rel clock_tz_min], eax
    mov al, [rel cfp_old+84]
    mov [rel clock_tz_zone], al
    mov word [rel clock_last_hhmm], 0xffff
    movzx edi, byte [rel cfp_old+86]
    call wallpaper_stock_import
    mov byte [rel config_prefs_state], CFP_LOADED
    lea rdi, [rel cfp_s_loaded]
    jmp .say
.refused:
    mov byte [rel config_prefs_state], CFP_REFUSED
    lea rdi, [rel cfp_s_refused]
    jmp .say
.pending:
    lea rdi, [rel cfp_s_pending]
.say:
    call serial_string
    mov byte [rel cfp_busy], 0
    pop rbx
.out:
    xor eax, eax
    ret

; RDI=captured local OWNER PID, RSI=captured session epoch. One human action.
; ->0 DATA saved/unchanged,1 unavailable,-1 refused/failed before effect,
; -2 busy,-3 uncertain. A later click cannot implicitly retry an uncertain IO.
config_prefs_save:
    push rbx
    push rbp
    push r12
    push r13
    sub rsp, 8
    mov r12, rdi
    mov r13, rsi
    call cfp_local_owner
    test eax, eax
    jnz .bad
    cmp byte [rel config_prefs_state], CFP_UNCERTAIN
    je .uncertain_no_effect
    cmp byte [rel cfp_busy], 0
    jne .busy
    mov byte [rel cfp_busy], 1
    lea rdi, [rel cfp_token]
    call data_config_bind_provisioned
    test eax, eax
    jnz .pending
    call cfp_read
    cmp eax, 1
    je .missing
    test eax, eax
    jnz .failed
    mov ebp, 1
    mov rbx, [rel cfp_old+8]
    jmp .snapshot
.missing:
    xor ebp, ebp
    xor ebx, ebx
.snapshot:
    lea rdi, [rel cfp_new]
    xor esi, esi
    mov edx, CFP_SIZE
    call memset
    mov dword [rel cfp_new], 'PCFG'
    mov word [rel cfp_new+4], 1
    mov word [rel cfp_new+6], CFP_SIZE
    ; Start with a valid placeholder revision; advance only for a change.
    mov qword [rel cfp_new+8], 1
    lea rdi, [rel cfp_new+16]
    lea rsi, [rel cfp_token+48]
    mov edx, 64
    call memcpy
    mov eax, [rel clock_tz_min]
    mov [rel cfp_new+80], eax
    mov al, [rel clock_tz_zone]
    mov [rel cfp_new+84], al
    call kbd_prefs_data_choice
    test eax, eax
    js .failed
    mov [rel cfp_new+85], al
    mov al, [rel wallpaper_stock_choice]
    mov [rel cfp_new+86], al
    call lang_prefs_data_choice
    test rax, rax
    jz .failed
    mov [rel cfp_new+88], rax
    lea rdi, [rel cfp_new]
    call cfp_fields
    test eax, eax
    jnz .failed
    test ebp, ebp
    jz .changed
    lea rdi, [rel cfp_new+80]
    lea rsi, [rel cfp_old+80]
    mov edx, 16
    call memcmp
    test eax, eax
    jnz .changed
    call cfp_local_owner
    test eax, eax
    jnz .failed
    jmp .saved                         ; actual current file, no redundant IO
.changed:
    cmp rbx, -1
    je .failed                         ; never wrap the revision, even on Reset
    inc rbx
    mov [rel cfp_new+8], rbx
    lea rdi, [rel cfp_new]
    mov esi, CFP_SIGNED
    lea rdx, [rel cfp_new+CFP_SIGNED]
    mov ecx, 64
    call node_identity_sign_active
    test eax, eax
    jnz .failed
    lea rdi, [rel cfp_new]
    call cfp_valid
    test eax, eax
    jnz .failed
    call cfp_local_owner
    test eax, eax
    jnz .failed
    lea rdi, [rel cfp_token]
    lea rsi, [rel cfp_name]
    lea rdx, [rel cfp_new]
    mov ecx, CFP_SIZE
    mov r8, r12
    mov r9, r13
    call data_config_write_local
    cmp eax, -3
    je .uncertain
    test eax, eax
    jnz .failed
    ; Provider success includes flush/reopen equality. Independently reopen
    ; and validate the complete record before publishing Saved in Settings.
    call cfp_read
    test eax, eax
    jnz .uncertain
    lea rdi, [rel cfp_new]
    lea rsi, [rel cfp_old]
    mov edx, CFP_SIZE
    call memcmp
    test eax, eax
    jnz .uncertain
.saved:
    mov byte [rel config_prefs_state], CFP_SAVED
    xor eax, eax
    jmp .release
.pending:
    mov byte [rel config_prefs_state], CFP_PENDING
    mov eax, 1
    jmp .release
.failed:
    mov byte [rel config_prefs_state], CFP_REFUSED
    mov eax, -1
    jmp .release
.uncertain:
    mov byte [rel config_prefs_state], CFP_UNCERTAIN
    mov eax, -3
    jmp .release
.busy:
    mov eax, -2
    jmp .out
.uncertain_no_effect:
    mov eax, -3
    jmp .out
.bad:
    mov eax, -1
    jmp .out
.release:
    mov byte [rel cfp_busy], 0
.out:
    add rsp, 8
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Save uses captured local authority, never the active command principal.
cfp_local_owner:
    cmp byte [rel pbm_try_media], 0
    jne .bad
    cmp byte [rel cmd_in_dispatch], 0
    jne .bad
    cmp byte [rel command_auth_remote_active], 0
    jne .bad
    cmp r12, PRIN_OWNER
    jne .bad
    test r13, r13
    jz .bad
    sub rsp, 8
    call session_shell_local_authority
    add rsp, 8
    cmp rax, r12
    jne .bad
    cmp rdx, r13
    jne .bad
    xor eax, eax
    ret
.bad:
    mov eax, -1
    ret

; ->0 valid current record,1 confirmed missing,-1 all other outcomes.
cfp_read:
    sub rsp, 8
    lea rdi, [rel cfp_token]
    lea rsi, [rel cfp_name]
    lea rdx, [rel cfp_old]
    mov ecx, CFP_SIZE
    call data_config_read
    cmp rax, -4
    je .missing
    cmp rax, CFP_SIZE
    jne .bad
    lea rdi, [rel cfp_old]
    call cfp_valid
    jmp .out
.missing:
    mov eax, 1
    jmp .out
.bad:
    mov eax, -1
.out:
    add rsp, 8
    ret

; RDI complete256B kernel record. Structural validation precedes verification.
cfp_valid:
    push rbx
    mov rbx, rdi
    call cfp_fields
    test eax, eax
    jnz .bad
    lea rsi, [rel cfp_token+48]
    lea rdi, [rbx+16]
    mov edx, 64
    call memcmp
    test eax, eax
    jnz .bad
    mov rdi, rbx
    mov esi, CFP_SIGNED
    lea rdx, [rbx+CFP_SIGNED]
    mov ecx, 64
    call node_identity_verify
    test eax, eax
    jnz .bad
    lea rdi, [rel cfp_token]
    call data_config_current
    test eax, eax
    jnz .bad
    xor eax, eax
    pop rbx
    ret
.bad:
    mov eax, -1
    pop rbx
    ret

cfp_fields:
    cmp dword [rdi], 'PCFG'
    jne .bad
    cmp word [rdi+4], 1
    jne .bad
    cmp word [rdi+6], CFP_SIZE
    jne .bad
    cmp qword [rdi+8], 0
    je .bad
    cmp dword [rdi+80], 840
    jg .bad
    cmp dword [rdi+80], -840
    jl .bad
    cmp byte [rdi+84], CLOCK_ZONE_COUNT
    ja .bad
    cmp byte [rdi+85], INPUT_LAYOUT_COUNT
    jae .bad
    cmp byte [rdi+86], 9
    ja .bad
    cmp byte [rdi+87], 0
    jne .bad
    mov ecx, 96
.zero:
    cmp byte [rdi+rcx], 0
    jne .bad
    inc ecx
    cmp ecx, CFP_SIGNED
    jb .zero
    add rdi, 88
    sub rsp, 8
    call lang_prefs_tag_id
    add rsp, 8
    test eax, eax
    js .bad
    xor eax, eax
    ret
.bad:
    mov eax, -1
    ret

cfp_name: db 'PAOS    CFG'
cfp_s_loaded: db '[config.data.loaded]',13,10,0
cfp_s_pending: db '[config.data.pending]',13,10,0
cfp_s_refused: db '[config.data.refused]',13,10,0

%include "core/abi/wdata.inc"
%macro WDATA_gui_config_prefs 0
align 8, db 0
cfp_token: times 112 db 0
cfp_old: times CFP_SIZE db 0
cfp_new: times CFP_SIZE db 0
cfp_busy: db 0
config_prefs_state: db CFP_UNLOADED
%endmacro
WDATA_DEFER WDATA_gui_config_prefs
