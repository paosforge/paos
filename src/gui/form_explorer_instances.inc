; Bounded native Explorer instances. The existing Explorer implementation uses
; one BSP workspace. Save/load that workspace at widget/command/tick entry,
; retaining one complete bank per WM lifetime. No authority is synthesized:
; every original owner, focus, epoch, mount and gesture guard still executes.
; Banked strings returned to the widget painter stay stable across other views.
FORM_EXP_INSTANCE_BYTES equ form_titles - form_fsroot_snapshot_ms

; EDI=slot -> EAX=1 only for the registered live/minimized owner+generation.
form_exp_instance_valid:
    xor  eax, eax
    cmp  edi, WM_MAX
    jae  .out
    lea  rcx, [rel form_exp_instance_gen]
    mov  edx, [rcx + rdi*4]
    test edx, edx
    jz   .out
    lea  rcx, [rel wm_gen]
    cmp  edx, [rcx + rdi*4]
    jne  .out
    lea  rcx, [rel form_exp_instance_owner]
    mov  rdx, [rcx + rdi*8]
    lea  rcx, [rel wm_owner]
    cmp  rdx, [rcx + rdi*8]
    jne  .out
    lea  rcx, [rel wm_state]
    cmp  dword [rcx + rdi*4], WM_VISIBLE
    je   .yes
    cmp  dword [rcx + rdi*4], WM_MIN
    jne  .out
.yes:
    mov  eax, 1
.out:
    ret

; The filter chain and command nonce sequence are boot-wide, never banked.
; RSI=source image -> copy to workspace, preserving these three shared values.
form_exp_instance_load:
    push qword [rel form_exp_key_prev]
    push qword [rel form_exp_paste_seq]
    movzx eax, byte [rel form_exp_keys_hooked]
    push rax
    lea  rdi, [rel form_fsroot_snapshot_ms]
    mov  ecx, FORM_EXP_INSTANCE_BYTES
    rep  movsb
    pop  rax
    mov  [rel form_exp_keys_hooked], al
    pop  qword [rel form_exp_paste_seq]
    pop  qword [rel form_exp_key_prev]
    ret

form_exp_instance_init:
    lea  rsi, [rel form_fsroot_snapshot_ms]
    lea  rdi, [rel form_exp_instance_template]
    mov  ecx, FORM_EXP_INSTANCE_BYTES
    rep  movsb
    ret

form_exp_instance_save:
    mov  edi, [rel form_exp_instance_current]
    call form_exp_instance_valid
    test eax, eax
    jz   .out                         ; never save into a retired owner's bank
    imul eax, edi, FORM_EXP_INSTANCE_BYTES
    lea  rdi, [rel form_exp_instance_banks]
    add  rdi, rax
    lea  rsi, [rel form_fsroot_snapshot_ms]
    mov  ecx, FORM_EXP_INSTANCE_BYTES
    rep  movsb
.out:
    ret

; EDI=registered slot -> EAX=1 selected, 0 refused; ordinary caller clobbers.
form_exp_instance_select_slot:
    push rbx
    mov  ebx, edi
    call form_exp_instance_valid
    test eax, eax
    jz   .out
    cmp  ebx, [rel form_exp_instance_current]
    je   .selected
    call form_exp_instance_save
    imul eax, ebx, FORM_EXP_INSTANCE_BYTES
    lea  rsi, [rel form_exp_instance_banks]
    add  rsi, rax
    call form_exp_instance_load
    mov  [rel form_exp_instance_current], ebx
.selected:
    mov  [rel form_active_slot + FORM_EXPLORER_INDEX*4], ebx
    ; FSSEL is deliberately still the shared FS-command selection. A change
    ; invalidates each view's listing before any old row can be activated.
    lea  rdx, [rel form_exp_instance_vfs_gen]
    mov  rax, [rel vfs_write_generation]
    cmp  [rdx + rbx*8], rax
    je   .fresh
    mov  [rdx + rbx*8], rax
    mov  qword [rel form_fsroot_snapshot_ms], 0
    mov  dword [rel form_exp_rows_gen], -1
.fresh:
    mov  eax, 1
.out:
    pop  rbx
    ret

; EDI=Explorer slot, after successful widget materialization and WM/owner stamp,
; before first ordinary paint/callback. Refused shells are never published.
form_exp_instance_begin:
    push rbx
    mov  ebx, edi
    call form_exp_instance_save
    lea  rsi, [rel form_exp_instance_template]
    call form_exp_instance_load
    lea  rdx, [rel wm_gen]
    mov  eax, [rdx + rbx*4]
    lea  rdx, [rel form_exp_instance_gen]
    mov  [rdx + rbx*4], eax
    lea  rdx, [rel wm_owner]
    mov  rax, [rdx + rbx*8]
    lea  rdx, [rel form_exp_instance_owner]
    mov  [rdx + rbx*8], rax
    lea  rdx, [rel form_exp_instance_vfs_gen]
    mov  rax, [rel vfs_write_generation]
    mov  [rdx + rbx*8], rax
    mov  [rel form_exp_instance_current], ebx
    mov  [rel form_exp_instance_latest], ebx
    mov  [rel form_active_slot + FORM_EXPLORER_INDEX*4], ebx
    ; Each copy owns its caption too; the declaration's shared title buffer
    ; remains the stable placement identity, even with title= overrides.
    imul eax, ebx, FORM_TITLE_MAX
    lea  rdi, [rel form_exp_instance_titles]
    add  rdi, rax
    mov  [rel form_load_title_ptr], rdi
    lea  rdx, [rel wm_title]
    mov  rsi, [rdx + rbx*8]
    mov  [rdx + rbx*8], rdi
    mov  ecx, FORM_TITLE_MAX
    rep  movsb
    call form_exp_instance_save
    pop  rbx
    ret

; Public entry helpers preserve all registers except EAX (success/refusal).
; EDI=widget, or focus/latest for commands which have no widget argument.
form_exp_instance_select_widget:
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    xor  eax, eax
    cmp  edi, [rel wgt_count]
    jae  .out
    call wgt_slot_ptr
    mov  edi, [rax + WGI_WIN]
    call form_exp_instance_select_slot
.out:
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    ret

form_exp_instance_select_command:
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    mov  edi, [rel wm_focus]
    call form_exp_instance_select_slot
    test eax, eax
    jnz  .out
    mov  edi, [rel form_exp_instance_latest]
    call form_exp_instance_select_slot
.out:
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    ret

; RAX=builder text pointer -> stable pointer into selected instance bank.
form_exp_instance_text:
    push rbx
    mov  rbx, rax
    lea  rdx, [rel form_fsroot_snapshot_ms]
    cmp  rax, rdx
    jb   .out
    lea  rcx, [rel form_titles]
    cmp  rax, rcx
    jae  .out
    sub  rbx, rdx
    call form_exp_instance_save
    mov  edi, [rel form_exp_instance_current]
    call form_exp_instance_valid
    test eax, eax
    jz   .invalid
    imul eax, edi, FORM_EXP_INSTANCE_BYTES
    lea  rdx, [rel form_exp_instance_banks]
    add  rax, rdx
    add  rax, rbx
    pop  rbx
    ret
.invalid:
    xor  ebx, ebx
.out:
    mov  rax, rbx
    pop  rbx
    ret

; Every pending action is consumed only in its own live lifetime. Re-select
; after each callback: a callback may have composed other Explorer windows.
form_exp_instances_tick:
    push rbx
    xor  ebx, ebx
.next:
    cmp  ebx, WM_MAX
    jae  .out
    mov  edi, ebx
    call form_exp_instance_select_slot
    test eax, eax
    jz   .skip
    call form_exp_context_tick
    mov  edi, ebx
    call form_exp_instance_select_slot
    test eax, eax
    jz   .skip
    call form_explorer_paste_tick
    mov  edi, ebx
    call form_exp_instance_select_slot
    test eax, eax
    jz   .skip
    call form_explorer_delete_tick
    mov  edi, ebx
    call form_exp_instance_select_slot
    test eax, eax
    jz   .skip
    call form_explorer_rename_tick
    mov  edi, ebx
    call form_exp_instance_select_slot
    test eax, eax
    jz   .skip
    call form_explorer_cancel_tick
.skip:
    inc  ebx
    jmp  .next
.out:
    call form_exp_instance_save
    pop  rbx
    ret

%include "core/abi/wdata.inc"
%macro WDATA_gui_form_explorer_instances_0 0
align 8
form_exp_instance_current: dd -1
form_exp_instance_latest: dd -1
form_exp_instance_gen: times WM_MAX dd 0
form_exp_instance_owner: times WM_MAX dq 0
form_exp_instance_vfs_gen: times WM_MAX dq 0
%endmacro
WDATA_DEFER WDATA_gui_form_explorer_instances_0
%macro WDATA_BSS_gui_form_explorer_instances_0 0
alignb 8
form_exp_instance_titles: resb WM_MAX * FORM_TITLE_MAX
form_exp_instance_template: resb FORM_EXP_INSTANCE_BYTES
form_exp_instance_banks: resb WM_MAX * FORM_EXP_INSTANCE_BYTES
%endmacro
WDATA_BSS_DEFER WDATA_BSS_gui_form_explorer_instances_0
