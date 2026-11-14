;; MODULE gui/wifi_local
;; LAYER 6
;; EXPORTS wifi_local_show, wifi_local_scan, wifi_local_click, wifi_local_key, wifi_local_tick, wifi_local_wipe, wifi_local_close, wfl_ids, wfl_live, wfl_private, wfl_private_end, wfl_busy
;; IMPORTS gui/widget, gui/start_programs, gui/window, gui/wm_pointer, gui/form_loader, sec/session, sec/wifi_profile, core/lib/wpa2_psk, svc/command, dev/input/ps2, boot/pbm
;; CAPS CAP_GUI
;; OWNER rc-input-claude
; Local-only, design-neutral WiFi form. The stock secret editor holds either
; SSID or password. Public widget values contain masks only. No new verb,
; serializer, clipboard, PCFG field, painter, or network executor.
; Native profile/channel remain authoritative for custody and deadline.
WFL_COUNT equ 7
WFL_STATUS equ 0
WFL_ENTRY equ 1
WFL_NEXT equ 2
WFL_SAVE equ 3
WFL_CONNECT equ 4
WFL_CANCEL equ 5
WFL_NOTE equ 6
WFL_ACT_NEXT equ 1
WFL_ACT_SAVE equ 2
WFL_ACT_CONNECT equ 3

wifi_local_scan:
    mov byte [rel wfl_live], 0
    mov edi, FORM_WIFI_INDEX
    mov esi, WFL_COUNT
    lea rdx, [rel wfl_ids]
    call sp_form_widgets_n
    cmp eax, WFL_COUNT
    jb .out
    mov [rel wfl_slot], ecx
    mov byte [rel wfl_live], 1
.out:
    ret

; Wipe is synchronous and has no transport/store callbacks. Register downward
; before any draft; native lock/bind/owner hooks invoke it before effects.
; Reset uses call-free raw ranges. The outer operation alone clears busy.
wifi_local_wipe:
    push rdi
    push rcx
    push rax
    mov eax, [rel wfl_ids + WFL_ENTRY*4]
    cmp eax, -1
    je .private
    cmp eax, [rel wgt_secret_owner]
    jne .private
    call wgt_secret_clear
.private:
    lea rdi, [rel wfl_private]
    xor eax, eax
    mov ecx, wfl_private_end-wfl_private
    cld
    rep stosb
    pop rax
    pop rcx
    pop rdi
    ret

; EDI original closing slot, before widget retirement / slot reuse.
wifi_local_close:
    cmp edi, [rel wfl_slot]
    jne .out
    call wifi_local_wipe
    mov byte [rel wfl_live], 0
    mov dword [rel wfl_slot], -1
    jmp wifi_profile_cancel
.out:
    ret

wifi_local_show:
    push rbx
    lea rdi, [rel wifi_local_wipe]
    call session_shell_register_local_wipe
    call wifi_local_wipe
    call wifi_profile_cancel
    call wifi_local_scan
    cmp byte [rel wfl_live], 1
    jne .out
    mov eax, [rel wfl_ids + WFL_ENTRY*4]
    mov ebx, [rel wfl_slot]
    lea rdx, [rel wgt_focus_by_win]
    mov [rdx + rbx*4], eax
    cmp ebx, [rel wm_focus]
    jne .say
    mov [rel wgt_focus_id], eax
.say:
    lea rsi, [rel wfl_s_ssid]
    call wfl_say
.out:
    pop rbx
    ret

; Only exact actual local OWNER, outside all command / Try execution.
wfl_authority:
    cmp dword [rel cmd_dispatch_depth], 0
    jne .bad
    cmp byte [rel pbm_try_media], 0
    jne .bad
    call session_shell_local_authority
    cmp rax, 1
    jne .bad
    ret
.bad:
    xor eax, eax
    xor edx, edx
    ret

; EDI widget. HUMAN pointer entry only; Start's three existing geometry,
; overlay, screen and injection arm rows are checked before queuing.
wifi_local_click:
    push rbx
    mov ebx, edi
    call wifi_local_scan
    mov edi, ebx
    cmp byte [rel wfl_live], 1
    jne .pass
    cmp edi, [rel wfl_ids + WFL_CANCEL*4]
    je .cancel
    mov esi, SP_ARM_WIFI_NEXT
    mov ecx, WFL_ACT_NEXT
    cmp edi, [rel wfl_ids + WFL_NEXT*4]
    je .positive
    mov esi, SP_ARM_WIFI_SAVE
    mov ecx, WFL_ACT_SAVE
    cmp edi, [rel wfl_ids + WFL_SAVE*4]
    je .positive
    mov esi, SP_ARM_WIFI_CONNECT
    mov ecx, WFL_ACT_CONNECT
    cmp edi, [rel wfl_ids + WFL_CONNECT*4]
    jne .pass
.positive:
    cmp byte [rel wm_pointer_origin], WM_PTR_ORIGIN_HUMAN
    jne .taken
    push rcx
    call sp_arm_holds
    pop rcx
    test eax, eax
    jz .taken
    call wfl_queue
.taken:
    mov eax, 1
    pop rbx
    ret
.cancel:
    call wifi_local_wipe
    call wifi_profile_cancel
    lea rsi, [rel wfl_s_ssid]
    call wfl_say
    jmp .taken
.pass:
    xor eax, eax
    pop rbx
    ret

; EDI focused widget, EAX key. Secret editing stays in the stock kit.
; Injected events never edit or navigate this form, and cancel remains safe.
wifi_local_key:
    push rbx
    push r12
    sub rsp, 8
    mov ebx, edi
    mov r12d, eax
    call wifi_local_scan
    cmp byte [rel wfl_live], 1
    jne .pass
    cmp ebx, [rel wgt_count]
    jae .pass
    mov edi, ebx
    call wgt_slot_ptr
    mov ecx, [rel wfl_slot]
    cmp [rax + WGI_WIN], ecx
    jne .pass
    cmp r12d, GUI_KEY_ESC
    je .cancel
    cmp byte [rel input_key_origin], KO_HUMAN
    jne .taken
    cmp r12d, GUI_KEY_ENTER
    je .activate
    cmp r12d, ' '
    jne .pass
    cmp ebx, [rel wfl_ids + WFL_ENTRY*4]
    je .pass                            ; spaces in SSID/password are input
.activate:
    cmp ebx, [rel wfl_ids + WFL_CANCEL*4]
    je .cancel
    mov ecx, WFL_ACT_CONNECT
    cmp ebx, [rel wfl_ids + WFL_CONNECT*4]
    je .queue
    mov ecx, WFL_ACT_NEXT
    cmp ebx, [rel wfl_ids + WFL_NEXT*4]
    je .queue
    mov ecx, WFL_ACT_SAVE
    cmp ebx, [rel wfl_ids + WFL_SAVE*4]
    je .queue
    cmp ebx, [rel wfl_ids + WFL_ENTRY*4]
    jne .taken
    mov ecx, WFL_ACT_NEXT
    cmp byte [rel wfl_stage], 0
    je .queue
    mov ecx, WFL_ACT_SAVE
.queue:
    call wfl_queue
.taken:
    mov eax, 1
    jmp .out
.cancel:
    call wifi_local_wipe
    call wifi_profile_cancel
    lea rsi, [rel wfl_s_ssid]
    call wfl_say
    jmp .taken
.pass:
    xor eax, eax
.out:
    add rsp, 8
    pop r12
    pop rbx
    ret

; ECX action. A queued action is single-use. The tuple and secret revision
; come from activation, never from ambient execution authority at idle.
wfl_queue:
    push rbx
    mov ebx, ecx
    cmp byte [rel wfl_busy], 0
    jne .out
    cmp byte [rel wfl_pending], 0
    jne .out
    call wfl_authority
    cmp rax, 1
    jne .out
    cmp ebx, WFL_ACT_CONNECT
    je .capture
    cmp ebx, WFL_ACT_NEXT
    jne .password
    cmp byte [rel wfl_stage], 0
    jne .out
    jmp .editor
.password:
    cmp byte [rel wfl_stage], 1
    jne .out
    cmp rax, [rel wfl_draft_pid]
    jne .out
    cmp rdx, [rel wfl_draft_epoch]
    jne .out
.editor:
    mov ecx, [rel wfl_ids + WFL_ENTRY*4]
    cmp ecx, [rel wgt_secret_owner]
    jne .out
    cmp qword [rel wgt_secret_revision], -1
    je .out
.capture:
    mov [rel wfl_pid], rax
    mov [rel wfl_epoch], rdx
    mov rax, [rel wgt_secret_revision]
    mov [rel wfl_revision], rax
    mov [rel wfl_pending], bl
.out:
    pop rbx
    ret

; Revalidate after every potentially reentrant backend / derivation call.
wfl_current:
    cmp byte [rel wfl_busy], 1
    jne .bad
    call wifi_local_scan
    mov eax, [rel wfl_slot]
    cmp eax, [rel wm_focus]
    jne .bad
    call wfl_authority
    cmp rax, 1
    jne .bad
    cmp rax, [rel wfl_pid]
    jne .bad
    cmp rdx, [rel wfl_epoch]
    jne .bad
    cmp byte [rel wfl_live], 1
    jne .bad
    mov eax, 1
    ret
.bad:
    xor eax, eax
    ret

wifi_local_tick:
    push rbx
    cmp byte [rel wfl_busy], 0
    jne .nested
    call wifi_local_scan
    cmp byte [rel wfl_live], 1
    jne .erase
    ; Even the first editor is erased on authority or window-focus loss.
    call wfl_authority
    cmp rax, 1
    jne .erase
    mov eax, [rel wfl_slot]
    cmp eax, [rel wm_focus]
    jne .erase
    cmp byte [rel wfl_stage], 1
    jne .pending
    call wfl_authority
    cmp rax, [rel wfl_draft_pid]
    jne .erase
    cmp rdx, [rel wfl_draft_epoch]
    jne .erase
    mov eax, [rel wfl_slot]
    cmp eax, [rel wm_focus]
    jne .erase
.pending:
    movzx ebx, byte [rel wfl_pending]
    mov byte [rel wfl_pending], 0
    test ebx, ebx
    jz .out
    cmp byte [rel wfl_busy], 0
    jne .out
    mov byte [rel wfl_busy], 1
    call wfl_current
    test eax, eax
    jz .erase
    cmp ebx, WFL_ACT_CONNECT
    je .prepare
    mov eax, [rel wfl_ids + WFL_ENTRY*4]
    cmp eax, [rel wgt_secret_owner]
    jne .invalid
    mov rax, [rel wfl_revision]
    cmp rax, [rel wgt_secret_revision]
    jne .invalid
    call wgt_secret_human
    cmp eax, 1
    jne .invalid
    cmp ebx, WFL_ACT_SAVE
    je .save
    ; SSID remains private and padded, bound to the same live owner epoch.
    mov ecx, [rel wgt_secret_len]
    cmp ecx, 1
    jb .invalid
    cmp ecx, 32
    ja .invalid
    mov dword [rel wfl_draft], 'WFR1'
    mov dword [rel wfl_draft+4], (80 << 16) | 1
    mov dword [rel wfl_draft+8], 1
    mov [rel wfl_draft+12], ecx
    lea rsi, [rel wgt_secret_bytes]
    lea rdi, [rel wfl_draft+16]
    cld
    rep movsb
    mov rax, [rel wfl_pid]
    mov [rel wfl_draft_pid], rax
    mov rax, [rel wfl_epoch]
    mov [rel wfl_draft_epoch], rax
    call wgt_secret_clear
    mov byte [rel wfl_stage], 1
    mov byte [rel wfl_busy], 0
    call wfl_focus_entry
    lea rsi, [rel wfl_s_password]
    call wfl_say
    jmp .out
.save:
    cmp dword [rel wgt_secret_len], 8
    jb .invalid
    cmp dword [rel wgt_secret_len], 63
    ja .invalid
    ; SEC implements WPA2 PBKDF2-HMAC-SHA1/4096; caller owns output, no
    ; passphrase ever enters the stored profile or the guest frame.
    lea rdi, [rel wfl_draft+48]
    lea rsi, [rel wfl_draft+16]
    mov edx, [rel wfl_draft+12]
    lea rcx, [rel wgt_secret_bytes]
    mov r8d, [rel wgt_secret_len]
    call wpa2_psk_derive
    mov ebx, eax
    mov rax, [rel wfl_revision]
    cmp rax, [rel wgt_secret_revision]
    jne .invalid
    call wgt_secret_clear
    test ebx, ebx
    jnz .invalid
    call wfl_current
    test eax, eax
    jz .erase
    lea rdi, [rel wfl_draft]
    mov esi, 80
    mov rdx, [rel wfl_pid]
    mov rcx, [rel wfl_epoch]
    call wifi_profile_replace_local
    test eax, eax
    jnz .backend
    call wfl_current
    test eax, eax
    jz .erase
.prepare:
    lea rdi, [rel wfl_token]
    mov esi, 32
    mov rdx, [rel wfl_pid]
    mov rcx, [rel wfl_epoch]
    call wifi_profile_prepare_local
    test eax, eax
    jnz .backend
    call wfl_current
    test eax, eax
    jz .erase
    lea rdi, [rel wfl_token]
    mov esi, 32
    mov rdx, [rel wfl_pid]
    mov rcx, [rel wfl_epoch]
    call wifi_profile_consume_local
    test eax, eax
    jnz .backend
    call wfl_current
    test eax, eax
    jz .erase
    ; Queue acceptance is not association or Internet success.
    call wifi_local_wipe
    lea rsi, [rel wfl_s_queued]
    call wfl_say
    jmp .out
.backend:
    cmp eax, 4
    je .uncertain
    call wifi_local_wipe
    call wifi_profile_cancel
    lea rsi, [rel wfl_s_refused]
    call wfl_say
    jmp .out
.uncertain:
    call wifi_local_wipe
    call wifi_profile_cancel
    lea rsi, [rel wfl_s_uncertain]
    call wfl_say
    jmp .out
.invalid:
    call wifi_local_wipe
    call wifi_profile_cancel
    lea rsi, [rel wfl_s_invalid]
    call wfl_say
    jmp .out
.erase:
    cmp byte [rel wfl_busy], 1
    jne .idle_erase
    call wifi_local_wipe
    call wifi_profile_cancel            ; discard an intent prepared before revalidation failed
    jmp .out
.idle_erase:
    call wifi_local_wipe                ; no repeated native cancel on empty idle turns
.out:
    mov byte [rel wfl_busy], 0
.nested:
    pop rbx
    ret

wfl_focus_entry:
    mov eax, [rel wfl_ids + WFL_ENTRY*4]
    mov ecx, [rel wfl_slot]
    lea rdx, [rel wgt_focus_by_win]
    mov [rdx + rcx*4], eax
    cmp ecx, [rel wm_focus]
    jne .out
    mov [rel wgt_focus_id], eax
    mov edi, eax
    jmp wgt_draw_id
.out:
    ret

wfl_say:
    cmp byte [rel wfl_live], 1
    jne .out
    mov edi, [rel wfl_ids + WFL_STATUS*4]
    jmp wgt_set_text
.out:
    ret

%include "core/abi/wdata.inc"
%macro WDATA_gui_wifi_local 0
wfl_ids: times WFL_COUNT dd -1
wfl_slot: dd -1
wfl_live: db 0
align 8
; Whole range registered in the existing reset wipe by VM composition.
wfl_private:
wfl_draft: times 80 db 0
wfl_token: times 32 db 0
wfl_draft_pid: dq 0
wfl_draft_epoch: dq 0
wfl_pid: dq 0
wfl_epoch: dq 0
wfl_revision: dq 0
wfl_pending: db 0
wfl_stage: db 0
wfl_private_end:
wfl_busy: db 0 ; outer guard, not cleared by reentrant lifecycle wipe
wfl_s_ssid: db 'Enter network name; Next',0
wfl_s_password: db 'Enter Wi-Fi password (8-63)',0
wfl_s_invalid: db 'Entry refused; start again',0
wfl_s_refused: db 'Unavailable; start again',0
wfl_s_uncertain: db 'Uncertain; no automatic retry',0
wfl_s_queued: db 'Queued; connection not verified',0
%endmacro
WDATA_DEFER WDATA_gui_wifi_local
