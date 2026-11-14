;; MODULE gui/settings_apps
;; LAYER 6
;; EXPORTS settings_apps_click, settings_apps_show
;; IMPORTS gui/widget, gui/form_loader, sec/session
;; CAPS CAP_GUI
;; OWNER rc-amd-claude
;; CONTEXT: bsp_only
; Settings > Apps: what is installed, then what is coming to PaOS by version
; (gui/forms/settings_apps.frm, T5-14). Native PaOS has no Roadmap window, so a
; coming row shows its Roadmap entry in this window. Read-only: a click writes
; only the entry line, so it needs no origin gate. Installed rows are the 0.1
; windows; Network Monitor is shown only while its form is bound, because the
; form comes with a module public builds and failed loads lack. Other rows stay
; fixed until a store can report real install state.

SA_W_NETMON     equ 8                   ; settings_apps.frm declaration order
SA_W_ROW0       equ 10
SA_ROWS         equ 6
SA_W_ENTRY      equ SA_W_ROW0 + SA_ROWS
SA_W_COUNT      equ SA_W_ENTRY + 1

; settings_apps_click(EDI widget id) -> EAX 1 when it was a coming row. Needs
; sa_live. Clobbers caller-saved.
settings_apps_click:
    xor  eax, eax
    cmp  byte [rel sa_live], 1
    jne  .out
    cmp  byte [rel session_locked], SESSION_LOCKED
    je   .out
    xor  ecx, ecx
.find:
    lea  rax, [rel sa_ids + SA_W_ROW0*4]
    cmp  edi, [rax + rcx*4]
    je   .hit
    inc  ecx
    cmp  ecx, SA_ROWS
    jb   .find
    xor  eax, eax
.out:
    ret
.hit:
    lea  rsi, [rel sa_entries]
.skip:
    test ecx, ecx
    jz   .show
.skip_text:
    lodsb
    test al, al
    jnz  .skip_text
    dec  ecx
    jmp  .skip
.show:
    mov  edi, [rel sa_ids + SA_W_ENTRY*4]
    sub  rsp, 8
    call wgt_set_text
    add  rsp, 8
    mov  eax, 1
    ret

; settings_apps_show(): the window was just opened or raised. Needs sa_live.
; Clobbers caller-saved.
settings_apps_show:
    cmp  byte [rel sa_live], 1
    jne  .out
    mov  edi, FORM_NETMON_INDEX
    sub  rsp, 8
    call form_table_ptr
    add  rsp, 8
    lea  rsi, [rel sa_netmon_name]
    cmp  qword [rax + FORM_LEN], 0
    jne  .put
    lea  rsi, [rel sa_netmon_absent]
.put:
    mov  edi, [rel sa_ids + SA_W_NETMON*4]
    jmp  wgt_set_text
.out:
    ret

sa_netmon_name:   db "Network Monitor", 0
sa_netmon_absent: db 0
sa_entries:                             ; each at most WGI_VAL_MAX bytes
    db "Web browser: maybe in 0.1", 0
    db "Photos: coming in 0.2", 0
    db "Documents: coming in 0.2", 0
    db "Task Manager: coming in 0.2", 0
    db "Media Player: coming in 0.2", 0
    db "Email: 0.2 or later", 0

%include "core/abi/wdata.inc"
%macro WDATA_BSS_gui_settings_apps 0
alignb 4
sa_ids:          resd SA_W_COUNT
sa_live:         resb 1
%endmacro
WDATA_BSS_DEFER WDATA_BSS_gui_settings_apps
