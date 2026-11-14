;; MODULE gui/summon_palette
;; LAYER 6
;; EXPORTS summon_palette_selftest, summon_palette_init, summon_palette_set_open_direct, summon_palette_flush_deferred, summon_palette_registry_set, summon_palette_registry_select, summon_palette_form_load, summon_palette_taskbar_draw, summon_palette_taskbar_append, summon_palette_taskbar_press, summon_palette_pointer_press, summon_palette_global_key, summon_palette_modal_key
;; IMPORTS gui/calendar, gui/widget, gui/widget_listview, gui/widget_containers, gui/taskbar, gui/window_mgmt, gui/naming_picker, gui/input_route, svc/command, svc/command_auth, sec/principal, sec/session, boot/serial, core/lib/fmt, core/lib/str
;; CAPS CAP_GUI
;; OWNER saga:gui
;; Task3433: one desktop-hosted form composition. No private painter, launch
;; table, text editor, timer, or input queue lives here.

SUMMON_INTENT_POINTER  equ 1
SUMMON_INTENT_KEYBOARD equ 5
SUMMON_WIDGET_COUNT    equ 8

%macro SUMMON_CREATE 5
    mov  edi, %1
    xor  esi, esi
    call wgt_create
    cmp  eax, -1
    je   .init_fail
    mov  [rel %2], eax
    mov  edi, eax
    call wgt_slot_ptr
    mov  dword [rax + WGI_WIN], WGT_HOST_DESKTOP
    lea  rcx, [rel %3]
    mov  [rax + WGI_ID], rcx
    lea  rcx, [rel %4]
    mov  [rax + WGI_ROLE], rcx
    lea  rcx, [rel %5]
    mov  [rax + WGI_LABEL], rcx
%endmacro

; Locked-boot KAT.  It exercises only pure/read-only seams: the transition
; predicate, live form/command registries, deterministic naming match, centered
; taskbar geometry, and the absence of workspace key hooks before login.  The
; authenticated transition later constructs the real graph in
; summon_palette_init and repeats the allocation/idempotence checks there.
summon_palette_selftest:
    ; One well-formed bound transition must accept exactly one widget set.
    mov  edi, SESSION_UNLOCKED
    mov  esi, 1
    mov  edx, 2
    mov  ecx, 1
    mov  r8d, 17
    mov  r9d, 17 + SUMMON_WIDGET_COUNT
    call summon_palette_transition_check
    test eax, eax
    jnz  .fail

    ; Relock, principal substitution, and duplicate allocation all refuse.
    mov  edi, SESSION_LOCKED
    mov  esi, 1
    mov  edx, 2
    mov  ecx, 1
    mov  r8d, 17
    mov  r9d, 17 + SUMMON_WIDGET_COUNT
    call summon_palette_transition_check
    test eax, eax
    jz   .fail
    mov  edi, SESSION_UNLOCKED
    mov  esi, 1
    mov  edx, 2
    mov  ecx, 3
    mov  r8d, 17
    mov  r9d, 17 + SUMMON_WIDGET_COUNT
    call summon_palette_transition_check
    test eax, eax
    jz   .fail
    mov  edi, SESSION_UNLOCKED
    mov  esi, 1
    mov  edx, 2
    mov  ecx, 1
    mov  r8d, 17
    mov  r9d, 17 + SUMMON_WIDGET_COUNT*2
    call summon_palette_transition_check
    test eax, eax
    jz   .fail

    ; The consumer must resolve the already registered public verbs.
    lea  rdi, [rel summon_verb_widgetset]
    call command_lookup
    cmp  eax, -1
    je   .fail
    lea  rdi, [rel naming_verb_formload]
    call command_lookup
    cmp  eax, -1
    je   .fail

    ; The declarative summon form is the live registry row, not a copied menu.
    mov  edi, FORM_SUMMON_INDEX
    call form_table_ptr
    cmp  qword [rax + FORM_LEN], 0
    je   .fail
    mov  rdi, [rax + FORM_NAME]
    lea  rsi, [rel summon_form_name]
    call strcmp
    test eax, eax
    jnz  .fail

    ; Local matching is deterministic and an empty query never fabricates a hit.
    lea  rdi, [rel summon_kat_haystack]
    lea  rsi, [rel summon_kat_needle]
    call naming_picker_contains
    cmp  eax, 1
    jne  .fail
    lea  rdi, [rel summon_kat_haystack]
    lea  rsi, [rel summon_kat_miss]
    call naming_picker_contains
    test eax, eax
    jnz  .fail
    lea  rdi, [rel summon_kat_haystack]
    lea  rsi, [rel summon_empty]
    call naming_picker_contains
    test eax, eax
    jnz  .fail

    ; The shared taskbar calculation must be centered within one pixel and
    ; retain the standard bottom inset at the current GOP dimensions.
    call taskbar_cluster_rect
    test ecx, ecx
    jz   .fail
    mov  eax, esi
    add  eax, esi
    add  eax, ecx
    mov  edi, [rel fb_width]
    sub  edi, eax
    cmp  edi, 1
    ja   .fail
    mov  eax, [rel fb_height]
    sub  eax, TASKBAR_H - TB_Y_INSET
    cmp  edx, eax
    jne  .fail
    cmp  r8d, TB_BUTTON_H
    jne  .fail

    ; Locked boot must not install the desktop's global/modal key hooks.
    cmp  qword [rel gui_input_global_key_hook], 0
    jne  .fail
    cmp  qword [rel gui_input_modal_key_hook], 0
    jne  .fail
    xor  eax, eax
    ret
.fail:
    mov  eax, 1
    ret

summon_palette_init:
    cmp  byte [rel summon_palette_ready], 1
    je   .already
    ; This resident desktop composition belongs strictly after the session
    ; bind.  Refuse before touching wgt_count so locked boot cannot consume
    ; widget identities or install workspace input hooks.
    call session_shell_require_unlocked
    test eax, eax
    jnz  .guard_fail
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, [rel wgt_count]
    mov  r13, [rel session_authority_epoch]
    mov  r14, [rel session_bound_pid]
    mov  r15, [rel session_key_handle]
    inc  byte [rel wgt_paint_suspended]
    SUMMON_CREATE 0, summon_start_id, summon_id_start, summon_role_button, summon_label_start
    mov  dword [rax + WGI_LAYER], 0
    or   dword [rax + WGI_EDIT], WGT_EDIT_ACCENT
    mov  byte [rax + WGI_VAL], 0
    mov  dword [rax + WGI_VLEN], 0
    mov  edi, [rel wgt_overlay_type]
    SUMMON_CREATE edi, summon_root_id, summon_id_root, summon_role_dialog, summon_text_root
    SUMMON_CREATE 6, summon_panel_id, summon_id_panel, summon_role_group, summon_text_root
    SUMMON_CREATE 1, summon_query_id, summon_id_query, summon_role_search, summon_label_query
    SUMMON_CREATE 0, summon_resume_id, summon_id_resume, summon_role_button, summon_label_resume
    SUMMON_CREATE 0, summon_pinned_id, summon_id_pinned, summon_role_tab, summon_label_pinned
    SUMMON_CREATE 0, summon_recents_id, summon_id_recents, summon_role_tab, summon_label_recents
    mov  edi, [rel wgt_listview_type]
    SUMMON_CREATE edi, summon_results_id, summon_id_results, summon_role_listbox, summon_label_results
    mov  ecx, [rel summon_root_id]
    mov  edi, [rel summon_panel_id]
    call wgt_slot_ptr
    mov  [rax + WGI_PARENT], ecx
    mov  edi, [rel summon_query_id]
    call wgt_slot_ptr
    mov  [rax + WGI_PARENT], ecx
    mov  edi, [rel summon_resume_id]
    call wgt_slot_ptr
    mov  [rax + WGI_PARENT], ecx
    mov  edi, [rel summon_pinned_id]
    call wgt_slot_ptr
    mov  [rax + WGI_PARENT], ecx
    mov  edi, [rel summon_recents_id]
    call wgt_slot_ptr
    mov  [rax + WGI_PARENT], ecx
    mov  edi, [rel summon_results_id]
    call wgt_slot_ptr
    mov  [rax + WGI_PARENT], ecx
    mov  ecx, [rel summon_root_id]
.hide_nodes:
    cmp  ecx, [rel summon_results_id]
    ja   .nodes_ready
    mov  edi, ecx
    call wgt_slot_ptr
    mov  dword [rax + WGI_LAYER], 1
    mov  dword [rax + WGI_FLAGS], 0
    inc  ecx
    jmp  .hide_nodes
.nodes_ready:
    mov  edi, [rel summon_panel_id]
    lea  rsi, [rel summon_text_root]
    call wgt_set_text
    mov  edi, [rel summon_query_id]
    call wgt_textfield_long             ; RCQ-38 L3c (root 18:16:22): the 255 B search field; a full pool leaves 39 B
    mov  edi, [rel summon_query_id]
    lea  rsi, [rel summon_empty]
    mov  edx, WGT_LONG_MAX
    call wgt_set_text_cap
    mov  edi, [rel summon_resume_id]
    lea  rsi, [rel summon_text_resume]
    call wgt_set_text
    mov  edi, [rel summon_pinned_id]
    lea  rsi, [rel summon_text_pinned]
    call wgt_set_text
    mov  edi, [rel summon_recents_id]
    lea  rsi, [rel summon_text_recents]
    call wgt_set_text
    mov  edi, [rel summon_results_id]
    lea  rsi, [rel summon_text_results]
    call wgt_set_text
    mov  edi, [rel summon_results_id]
    call wgt_slot_ptr
    mov  dword [rax + WGI_BIND], FORM_BIND_SUMMON_PINNED
    lea  rax, [rel summon_focus_order]
    mov  ecx, [rel summon_query_id]
    mov  [rax], ecx
    mov  ecx, [rel summon_resume_id]
    mov  [rax + 4], ecx
    mov  ecx, [rel summon_pinned_id]
    mov  [rax + 8], ecx
    mov  ecx, [rel summon_recents_id]
    mov  [rax + 12], ecx
    mov  ecx, [rel summon_results_id]
    mov  [rax + 16], ecx
    call summon_palette_reflow

    ; Prove the real locked -> bound -> desktop construction transition did
    ; not change session authority, and that exactly one stable widget set was
    ; allocated.  The pure hostile calls below prove the predicate rejects a
    ; relock and a duplicate allocation without writing sec/session state.
    call session_shell_require_unlocked
    test eax, eax
    jnz  .kat_fail
    cmp  qword [rel session_authority_epoch], r13
    jne  .kat_fail
    cmp  qword [rel session_bound_pid], r14
    jne  .kat_fail
    cmp  qword [rel session_key_handle], r15
    jne  .kat_fail
    call principal_current
    mov  rcx, rax
    movzx edi, byte [rel session_locked]
    mov  rsi, r14
    mov  rdx, r15
    mov  r8d, r12d
    mov  r9d, [rel wgt_count]
    call summon_palette_transition_check
    test eax, eax
    jnz  .kat_fail
    mov  eax, r12d
    cmp  [rel summon_start_id], eax
    jne  .kat_fail
    inc  eax
    cmp  [rel summon_root_id], eax
    jne  .kat_fail
    inc  eax
    cmp  [rel summon_panel_id], eax
    jne  .kat_fail
    inc  eax
    cmp  [rel summon_query_id], eax
    jne  .kat_fail
    inc  eax
    cmp  [rel summon_resume_id], eax
    jne  .kat_fail
    inc  eax
    cmp  [rel summon_pinned_id], eax
    jne  .kat_fail
    inc  eax
    cmp  [rel summon_recents_id], eax
    jne  .kat_fail
    inc  eax
    cmp  [rel summon_results_id], eax
    jne  .kat_fail
    mov  edi, SESSION_LOCKED
    mov  rsi, r14
    mov  rdx, r15
    mov  rcx, r14
    mov  r8d, r12d
    mov  r9d, [rel wgt_count]
    call summon_palette_transition_check
    test eax, eax
    jz   .kat_fail
    mov  edi, SESSION_UNLOCKED
    mov  rsi, r14
    mov  rdx, r15
    mov  rcx, r14
    mov  r8d, r12d
    mov  r9d, r12d
    add  r9d, SUMMON_WIDGET_COUNT*2
    call summon_palette_transition_check
    test eax, eax
    jz   .kat_fail

    mov  byte [rel summon_palette_ready], 1
    mov  ebx, [rel wgt_count]
    call summon_palette_init
    test eax, eax
    jnz  .kat_fail_ready
    cmp  [rel wgt_count], ebx
    jne  .kat_fail_ready
    call session_shell_require_unlocked
    test eax, eax
    jnz  .kat_fail_ready
    lea  rax, [rel summon_palette_button_open]
    mov  [rel wgt_button_open_hook], rax
    lea  rax, [rel summon_palette_button_get]
    mov  [rel wgt_button_get_hook], rax
    lea  rax, [rel summon_palette_action]
    mov  [rel wgt_action_hook], rax
    lea  rax, [rel naming_picker_get_hook]
    mov  [rel wgt_listview_get_hook], rax
    lea  rax, [rel naming_picker_set_hook]
    mov  [rel wgt_listview_set_hook], rax
    lea  rax, [rel naming_picker_pointer_hook]
    mov  [rel wgt_listview_pointer_hook], rax
    lea  rax, [rel summon_palette_text_event]
    mov  [rel wgt_textfield_event_hook2], rax
    lea  rax, [rel summon_palette_global_key]
    mov  [rel gui_input_global_key_hook], rax
    lea  rax, [rel summon_palette_modal_key]
    mov  [rel gui_input_modal_key_hook], rax
    dec  byte [rel wgt_paint_suspended]
    lea  rdi, [rel summon_marker]
    call serial_string
    call wmx_draw_all
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
.already:
    xor  eax, eax
    ret
.kat_fail_ready:
    mov  byte [rel summon_palette_ready], 0
.kat_fail:
    dec  byte [rel wgt_paint_suspended]
    jmp  .rollback
.init_fail:
    dec  byte [rel wgt_paint_suspended]
.rollback:
    mov  ebx, [rel wgt_count]
.rollback_node:
    cmp  ebx, r12d
    jbe  .rollback_done
    dec  ebx
    mov  edi, ebx
    call wgt_slot_ptr
    call wgt_tf_long_free               ; RCQ-38 L3c: the query's long value is wiped
    mov  dword [rax + WGI_TYPE], 0
    mov  dword [rax + WGI_LAYER], 0
    jmp  .rollback_node
.rollback_done:
    mov  [rel wgt_count], r12d
    mov  dword [rel summon_start_id], -1
    mov  dword [rel summon_root_id], -1
    mov  dword [rel summon_panel_id], -1
    mov  dword [rel summon_query_id], -1
    mov  dword [rel summon_resume_id], -1
    mov  dword [rel summon_pinned_id], -1
    mov  dword [rel summon_recents_id], -1
    mov  dword [rel summon_results_id], -1
    mov  byte [rel summon_palette_ready], 0
    mov  byte [rel summon_palette_open], 0
.failed:
    lea  rdi, [rel summon_fail]
    call serial_string
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
.guard_fail:
    mov  eax, 1
    ret

; EDI=locked, RSI=bound pid, RDX=key handle, RCX=current principal,
; R8D=count before, R9D=count after.  This pure predicate lets the boot KAT
; exercise hostile transition facts without ever changing session authority.
summon_palette_transition_check:
    cmp  edi, SESSION_UNLOCKED
    jne  .bad
    test rsi, rsi
    jz   .bad
    test rdx, rdx
    jz   .bad
    cmp  rcx, rsi
    jne  .bad
    add  r8d, SUMMON_WIDGET_COUNT
    cmp  r9d, r8d
    jne  .bad
    xor  eax, eax
    ret
.bad:
    mov  eax, 1
    ret

summon_palette_reflow:
    push rbx
    push r12
    push r13
    call taskbar_cluster_rect
    mov  r12d, esi
    mov  r13d, edx
    mov  [rel summon_cluster_x], esi
    mov  [rel summon_cluster_y], edx
    mov  [rel summon_cluster_w], ecx
    mov  [rel summon_cluster_h], r8d
    mov  edi, [rel summon_start_id]
    call wgt_slot_ptr
    mov  [rax + WGI_X], r12d
    mov  [rax + WGI_Y], r13d
    mov  dword [rax + WGI_W], TB_START_W
    mov  dword [rax + WGI_H], TB_BUTTON_H
    mov  ebx, 560
    mov  eax, [rel fb_width]
    sub  eax, 32
    cmp  ebx, eax
    jbe  .width
    mov  ebx, eax
.width:
    cmp  ebx, 240
    jae  .height_start
    mov  ebx, 240
.height_start:
    mov  r12d, 400
    mov  eax, [rel fb_height]
    sub  eax, TASKBAR_H + 16
    cmp  r12d, eax
    jbe  .height
    mov  r12d, eax
.height:
    ; Keep the six-row public items page inside the one list body: 30 px
    ; header plus 6 * 18 px rows below the two shared mode buttons.
    cmp  r12d, 316
    jae  .place
    mov  r12d, 316
.place:
    mov  r13d, [rel fb_width]
    sub  r13d, ebx
    shr  r13d, 1
    mov  edx, [rel fb_height]
    sub  edx, TASKBAR_H + 8
    sub  edx, r12d
    mov  [rel summon_palette_x], r13d
    mov  [rel summon_palette_y], edx
    mov  [rel summon_palette_w], ebx
    mov  [rel summon_palette_h], r12d
    mov  esi, r13d
    mov  edi, [rel summon_root_id]
    call summon_palette_set_rect
    mov  edi, [rel summon_panel_id]
    call summon_palette_set_rect
    mov  esi, r13d
    add  esi, 24
    mov  edx, [rel summon_palette_y]
    add  edx, 24
    mov  ecx, ebx
    sub  ecx, 48
    mov  r8d, 30
    mov  edi, [rel summon_query_id]
    call summon_palette_store_rect
    mov  edx, [rel summon_palette_y]
    add  edx, 70
    mov  edi, [rel summon_resume_id]
    call summon_palette_store_rect
    mov  eax, ebx
    sub  eax, 56
    xor  edx, edx
    mov  ecx, 2
    div  ecx
    mov  r8d, eax
    mov  esi, r13d
    add  esi, 24
    mov  edx, [rel summon_palette_y]
    add  edx, 116
    mov  ecx, r8d
    mov  r9d, 30
    mov  edi, [rel summon_pinned_id]
    call summon_palette_store_list_rect
    add  esi, r8d
    add  esi, 8
    mov  edi, [rel summon_recents_id]
    call summon_palette_store_list_rect
    mov  esi, r13d
    add  esi, 24
    mov  edx, [rel summon_palette_y]
    add  edx, 154
    mov  ecx, ebx
    sub  ecx, 48
    mov  r9d, r12d
    sub  r9d, 178
    mov  edi, [rel summon_results_id]
    call summon_palette_store_list_rect
    pop  r13
    pop  r12
    pop  rbx
    ret

summon_palette_set_rect:
    call wgt_slot_ptr
    mov  [rax + WGI_X], esi
    mov  [rax + WGI_Y], edx
    mov  [rax + WGI_W], ebx
    mov  [rax + WGI_H], r12d
    ret
summon_palette_store_rect:
    call wgt_slot_ptr
    mov  [rax + WGI_X], esi
    mov  [rax + WGI_Y], edx
    mov  [rax + WGI_W], ecx
    mov  [rax + WGI_H], r8d
    ret
summon_palette_store_list_rect:
    call wgt_slot_ptr
    mov  [rax + WGI_X], esi
    mov  [rax + WGI_Y], edx
    mov  [rax + WGI_W], ecx
    mov  [rax + WGI_H], r9d
    ret

summon_palette_button_open:
    cmp  edi, [rel summon_start_id]
    jne  .bad
    mov  edi, esi
    call summon_palette_set_open_direct
    ret
.bad:
    mov  eax, 1
    ret

summon_palette_set_open_direct:
    cmp  edi, 1
    ja   .bad
    test edi, edi
    jz   .state_check
    cmp  byte [rel session_locked], SESSION_LOCKED
    je   .bad
.state_check:
    cmp  dil, [rel summon_palette_open]
    je   .ok
    test edi, edi
    jz   .close
    call calendar_close                 ; one shell flyout at a time
    call summon_palette_reflow
    ; Resume is derived from the shared listview's recents binding without
    ; creating a second list or retaining a palette-owned history model.
    mov  edi, [rel summon_results_id]
    call wgt_slot_ptr
    mov  ecx, [rax + WGI_BIND]
    push rcx
    mov  dword [rax + WGI_BIND], FORM_BIND_SUMMON_RECENTS
    mov  edi, [rel summon_results_id]
    xor  esi, esi
    call naming_picker_item_at
    mov  edx, eax
    mov  ecx, [rel naming_item_win]
    pop  r8
    mov  edi, [rel summon_results_id]
    call wgt_slot_ptr
    mov  [rax + WGI_BIND], r8d
    mov  eax, edx
    test eax, eax
    jz   .resume_current
    mov  eax, ecx
    jmp  .resume_ready
.resume_current:
    mov  eax, [rel wm_focus]
.resume_ready:
    mov  [rel summon_resume_window], eax
    call summon_palette_update_resume
    mov  eax, [rel wgt_focus_id]
    mov  [rel summon_prior_widget_focus], eax
    mov  byte [rel summon_palette_open], 1
    mov  ecx, [rel summon_root_id]
.show:
    cmp  ecx, [rel summon_results_id]
    ja   .shown
    mov  edi, ecx
    call wgt_slot_ptr
    or   dword [rax + WGI_FLAGS], 1
    inc  ecx
    jmp  .show
.shown:
    cmp  byte [rel summon_user_open], 1
    jne  .open_draw
    mov  eax, [rel summon_query_id]
    mov  [rel wgt_focus_id], eax
    mov  [rel summon_palette_focus], eax
.open_draw:
    call summon_palette_sync_start
    call summon_palette_request_draw
    jmp  .ok
.close:
    mov  byte [rel summon_palette_open], 0
    mov  ecx, [rel summon_root_id]
.hide:
    cmp  ecx, [rel summon_results_id]
    ja   .hidden
    mov  edi, ecx
    call wgt_slot_ptr
    and  dword [rax + WGI_FLAGS], ~1
    inc  ecx
    jmp  .hide
.hidden:
    mov  eax, [rel summon_prior_widget_focus]
    mov  [rel wgt_focus_id], eax
    call summon_palette_sync_start
    mov  byte [rel summon_palette_erase_pending], 1
    call summon_palette_request_draw
.ok:
    mov  byte [rel summon_user_open], 0
    xor  eax, eax
    ret
.bad:
    mov  eax, 1
    ret

; Palette transitions can originate inside command dispatch or input hooks.
; Queue their composition uniformly; the main idle loop erases any closed
; overlay footprint and repaints the shared desktop after those frames return.
summon_palette_request_draw:
    call wmx_draw_defer_begin
    call wmx_draw_all
    call wmx_draw_defer_end
    ret

summon_palette_flush_deferred:
    cmp  byte [rel summon_palette_erase_pending], 1
    jne  .done
    mov  byte [rel summon_palette_erase_pending], 0
    mov  edi, [rel summon_root_id]
    call wgt_desktop_erase_rect
.done:
    ret

summon_palette_sync_start:
    mov  edi, [rel summon_start_id]
    call wgt_slot_ptr
    and  dword [rax + WGI_EDIT], ~WGT_EDIT_OPEN
    cmp  byte [rel summon_palette_open], 1
    jne  .done
    or   dword [rax + WGI_EDIT], WGT_EDIT_OPEN
.done:
    ret

summon_palette_update_resume:
    mov  edi, [rel summon_resume_id]
    call wgt_slot_ptr
    or   dword [rax + WGI_EDIT], WGT_EDIT_DISABLED
    mov  ecx, [rel summon_resume_window]
    cmp  ecx, WM_MAX
    jae  .done
    lea  rdx, [rel wm_state]
    mov  edx, [rdx + rcx*4]
    cmp  edx, WM_VISIBLE
    je   .enable
    cmp  edx, WM_MIN
    jne  .done
.enable:
    and  dword [rax + WGI_EDIT], ~WGT_EDIT_DISABLED
.done:
    ret

; EDI=widget id, RSI=field, RDX=value, ECX=physical intent. Rendered controls
; enter the same registered WIDGETSET verb as headless callers.  An injected
; event retains the already-authorized outer request identity without consuming
; its one-shot AUTH1 ticket twice; a hardware event carries the local login
; (session_shell_local_authority: unlocked, keyed, not injected or remote) and
; only if that login is the owner or the local Try PID, through the
; console-local registry path. Try carries its own PID and zero capability.
; Neither path consults principal_current: that is the identity of whatever
; request or frame is running, not of who is at the console (RCQ-17).  The
; registry records one verb event; after dispatch this replaces only its origin
; code.
summon_palette_registry_set:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, edi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15d, ecx
    lea  rsi, [rel summon_registry_arg]
    mov  edi, r12d
    push rsi
    call fmt_dec
    pop  rsi
    add  rsi, rax
    lea  rbx, [rel summon_registry_arg + 127]
    cmp  rsi, rbx
    jae  .bad
    mov  byte [rsi], ' '
    inc  rsi
.field:
    cmp  rsi, rbx
    jae  .bad
    mov  al, [r13]
    test al, al
    jz   .field_done
    mov  [rsi], al
    inc  rsi
    inc  r13
    jmp  .field
.field_done:
    mov  byte [rsi], ' '
    inc  rsi
.value:
    cmp  rsi, rbx
    jae  .bad
    mov  al, [r14]
    mov  [rsi], al
    inc  rsi
    inc  r14
    test al, al
    jnz  .value
    movzx r14d, byte [rel cmd_in_dispatch]
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rbx, [rax + WGI_INTENT_SEQ]
    lea  rdi, [rel summon_verb_widgetset]
    call command_lookup
    cmp  eax, -1
    je   .bad
    mov  [rel summon_registry_req + REQ_VERB], rax
    mov  qword [rel summon_registry_req + REQ_CAP], -1
    mov  qword [rel summon_registry_req + REQ_IDEM], 0
    mov  qword [rel summon_registry_req + REQ_SEL], 0
    lea  rax, [rel summon_registry_arg]
    mov  [rel summon_registry_req + REQ_ARG], rax
    test r14d, r14d
    jz   .local_identity
    mov  rax, [rel cmd_dispatch_last_source]
    mov  [rel summon_registry_req + REQ_SOURCE], rax
    mov  rax, [rel cmd_dispatch_last_principal]
    cmp  rax, CMD_PRINCIPAL_OWNER
    jne  .bad
    mov  [rel summon_registry_req + REQ_PRINCIPAL], rax
    jmp  .identity_ready
.local_identity:
    call session_shell_local_authority  ; RAX=login PID, RDX=token; 0/0 refused
    cmp  rax, PRIN_TRY
    je   .local_try
    cmp  rax, PRIN_OWNER
    jne  .bad                           ; only the owner's own login
    mov  qword [rel summon_registry_req + REQ_SOURCE], CMD_SOURCE_CONSOLE
    mov  qword [rel summon_registry_req + REQ_PRINCIPAL], CMD_PRINCIPAL_OWNER
    jmp  .identity_ready
.local_try:
    ; The registry and the WIDGETSET slot gate decide; never an OWNER projection.
    mov  qword [rel summon_registry_req + REQ_SOURCE], CMD_SOURCE_CONSOLE
    mov  [rel summon_registry_req + REQ_PRINCIPAL], rax
    mov  qword [rel summon_registry_req + REQ_CAP], 0
.identity_ready:
    mov  al, [rel command_auth_remote_active]
    mov  [rel summon_registry_remote_active], al
    test r14d, r14d
    jz   .dispatch
    mov  byte [rel command_auth_remote_active], 0
.dispatch:
    lea  rdi, [rel summon_registry_req]
    lea  rsi, [rel summon_registry_rsp]
    call command_dispatch
    mov  dl, [rel summon_registry_remote_active]
    mov  [rel command_auth_remote_active], dl
    test r14d, r14d
    jz   .dispatch_done
    mov  byte [rel cmd_in_dispatch], 1
.dispatch_done:
    mov  byte [rel wgt_out_ready], 0
    test eax, eax
    jnz  .bad
    mov  edi, r12d
    call wgt_slot_ptr
    cmp  [rax + WGI_INTENT_SEQ], rbx
    je   .bad
    mov  [rax + WGI_INTENT], r15d
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, 1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; EDI=list widget, ESI=global item index, ECX=physical intent.
summon_palette_registry_select:
    push r12
    push r13
    mov  r12d, edi
    mov  r13d, ecx
    lea  rdx, [rel summon_selected_buf]
    push rdx
    mov  edi, esi
    mov  rsi, rdx
    call fmt_dec
    pop  rdx
    mov  byte [rdx + rax], 0
    mov  edi, r12d
    lea  rsi, [rel summon_field_selected]
    mov  ecx, r13d
    call summon_palette_registry_set
    pop  r13
    pop  r12
    ret

summon_palette_form_load:
    ; FORMLOAD can be invoked by an agent over UDP. Its focus=1 option must
    ; not impersonate the explicit desktop user's pointer/global-key intent.
    mov  byte [rel summon_user_open], 0
    cmp  byte [rel cmd_in_dispatch], 1
    jne  .open
    cmp  qword [rel cmd_dispatch_last_source], CMD_SOURCE_CONSOLE
    jne  .open
    test edi, edi
    setnz byte [rel summon_user_open]
.open:
    mov  edi, 1
    jmp  summon_palette_set_open_direct

summon_palette_button_get:
    cmp  edi, [rel summon_start_id]
    je   .start
    cmp  edi, [rel summon_resume_id]
    jne  .miss
    lea  rdi, [rel summon_field_target]
    call strcmp
    test eax, eax
    jnz  .miss
    mov  edi, [rel summon_resume_window]
    cmp  edi, WM_MAX
    jae  .none
    lea  rax, [rel wm_state]
    mov  eax, [rax + rdi*4]
    cmp  eax, WM_VISIBLE
    je   .window
    cmp  eax, WM_MIN
    jne  .none
.window:
    lea  rsi, [rel summon_target_buf + 7]
    push rsi
    call fmt_dec
    pop  rsi
    mov  byte [rsi + rax], 0
    lea  rax, [rel summon_target_buf]
    ret
.none:
    lea  rax, [rel summon_target_none]
    ret
.start:
    ; RCQ-09 modal rows: the palette control that owns the keyboard is the
    ; modal hook's own summon_palette_focus.  Read-only; "none" while closed
    ; or when that focus is not one of the palette's nodes.
    lea  rdi, [rel summon_field_focus]
    call strcmp
    test eax, eax
    jnz  .miss
    cmp  byte [rel summon_palette_open], 1
    jne  .none
    mov  edi, [rel summon_palette_focus]
    cmp  edi, [rel summon_root_id]
    jb   .none
    cmp  edi, [rel summon_results_id]
    ja   .none
    lea  rsi, [rel summon_focus_buf]
    push rsi
    call fmt_dec
    pop  rsi
    mov  byte [rsi + rax], 0
    lea  rax, [rel summon_focus_buf]
    ret
.miss:
    xor  eax, eax
    ret

summon_palette_action:
    push rbx
    mov  ebx, edi
    lea  rdi, [rel summon_action_activate]
    call strcmp
    test eax, eax
    jnz  .bad
    cmp  byte [rel summon_palette_open], 1
    jne  .bad
    cmp  ebx, [rel summon_pinned_id]
    je   .pinned
    cmp  ebx, [rel summon_recents_id]
    je   .recents
    cmp  ebx, [rel summon_resume_id]
    jne  .bad
    mov  edi, [rel summon_resume_window]
    cmp  edi, WM_MAX
    jae  .bad
    lea  rax, [rel wm_state]
    mov  eax, [rax + rdi*4]
    cmp  eax, WM_VISIBLE
    je   .raise
    cmp  eax, WM_MIN
    jne  .bad
.raise:
    call wmx_draw_defer_begin
    call naming_picker_dispatch_window
    test eax, eax
    jnz  .raise_bad
    xor  edi, edi
    call summon_palette_set_open_direct
    push rax
    call wmx_draw_defer_end
    pop  rax
    test eax, eax
    jnz  .bad
    xor  eax, eax
    jmp  .out
.raise_bad:
    call wmx_draw_defer_end
    jmp  .bad
.pinned:
    mov  edi, FORM_BIND_SUMMON_PINNED
    call summon_palette_set_list_mode
    jmp  .out
.recents:
    mov  edi, FORM_BIND_SUMMON_RECENTS
    call summon_palette_set_list_mode
    jmp  .out
.bad:
    mov  eax, 1
.out:
    pop  rbx
    ret

summon_palette_text_event:
    cmp  edi, [rel summon_query_id]
    jne  .done
    call wgt_slot_ptr
    call wgt_tf_buf                     ; RCQ-38 L3c
    mov  edi, FORM_BIND_SUMMON_RESULTS
    cmp  byte [rax], 0
    jne  .mode
    mov  edi, FORM_BIND_SUMMON_PINNED
.mode:
    call summon_palette_set_list_mode
.done:
    ret

; EDI=FORM_BIND_SUMMON_* switches the one listview's live registry projection.
summon_palette_set_list_mode:
    cmp  edi, FORM_BIND_SUMMON_PINNED
    jb   .bad
    cmp  edi, FORM_BIND_SUMMON_RESULTS
    ja   .bad
    mov  ecx, edi
    mov  edi, [rel summon_results_id]
    call wgt_slot_ptr
    mov  [rax + WGI_BIND], ecx
    mov  dword [rax + WGI_SEL_LO], 0
    cmp  byte [rel wgt_paint_suspended], 0
    jne  .updated
    call wmx_draw_all
.updated:
    xor  eax, eax
    ret
.bad:
    mov  eax, 1
    ret

summon_palette_taskbar_draw:
    cmp  byte [rel summon_palette_ready], 1
    jne  .done
    call summon_palette_reflow
    mov  edi, [rel summon_start_id]
    call wgt_draw_id
.done:
    ret

summon_palette_taskbar_append:
    cmp  byte [rel summon_palette_ready], 1
    jne  .done
    call summon_palette_reflow
    lea  rdi, [rel summon_tb_start_id]
    call f1_put_str
    mov  edi, [rel summon_start_id]
    call f1_put_dec
    lea  rdi, [rel summon_tb_start_rect]
    call f1_put_str
    mov  edi, [rel summon_start_id]
    call wgt_slot_ptr
    push rax
    mov  edi, [rax + WGI_X]
    call f1_put_dec
    lea  rdi, [rel summon_comma]
    call f1_put_str
    pop  rax
    push rax
    mov  edi, [rax + WGI_Y]
    call f1_put_dec
    lea  rdi, [rel summon_comma]
    call f1_put_str
    pop  rax
    push rax
    mov  edi, [rax + WGI_W]
    call f1_put_dec
    lea  rdi, [rel summon_comma]
    call f1_put_str
    pop  rax
    mov  edi, [rax + WGI_H]
    call f1_put_dec
    lea  rdi, [rel summon_tb_cluster_rect]
    call f1_put_str
    mov  edi, [rel summon_cluster_x]
    call f1_put_dec
    lea  rdi, [rel summon_comma]
    call f1_put_str
    mov  edi, [rel summon_cluster_y]
    call f1_put_dec
    lea  rdi, [rel summon_comma]
    call f1_put_str
    mov  edi, [rel summon_cluster_w]
    call f1_put_dec
    lea  rdi, [rel summon_comma]
    call f1_put_str
    mov  edi, [rel summon_cluster_h]
    call f1_put_dec
.done:
    ret

summon_palette_taskbar_press:
    cmp  byte [rel summon_palette_ready], 1
    jne  .no
    push r12
    push r13
    mov  r12d, edi
    mov  r13d, esi
    mov  edi, [rel summon_start_id]
    mov  esi, r12d
    mov  edx, r13d
    call wgt_rect_hittest
    test eax, eax
    jz   .out_no
    mov  byte [rel summon_user_open], 1
    lea  rdx, [rel summon_one]
    cmp  byte [rel summon_palette_open], 1
    jne  .toggle
    lea  rdx, [rel summon_zero]
.toggle:
    mov  edi, [rel summon_start_id]
    lea  rsi, [rel str_wf_open]
    mov  ecx, SUMMON_INTENT_POINTER
    call summon_palette_registry_set
    mov  eax, 1
    jmp  .out
.out_no:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    ret
.no:
    xor  eax, eax
    ret

summon_palette_pointer_press:
    cmp  byte [rel session_locked], SESSION_LOCKED
    je   .no                            ; RCQ-17: never over the sign-in surface
    cmp  byte [rel summon_palette_open], 1
    jne  .no
    push r12
    push r13
    mov  r12d, edi
    mov  r13d, esi
    call summon_palette_taskbar_press
    test eax, eax
    jnz  .yes
    mov  edi, [rel summon_root_id]
    mov  esi, r12d
    mov  edx, r13d
    call wgt_rect_hittest
    test eax, eax
    jz   .outside
    mov  edi, [rel summon_query_id]
    mov  esi, r12d
    mov  edx, r13d
    call wgt_rect_hittest
    test eax, eax
    jz   .resume
    mov  eax, [rel summon_query_id]
    mov  [rel summon_palette_focus], eax
    mov  [rel wgt_focus_id], eax
    jmp  .yes
.resume:
    mov  edi, [rel summon_resume_id]
    mov  esi, r12d
    mov  edx, r13d
    call wgt_rect_hittest
    test eax, eax
    jz   .lists
    mov  edi, [rel summon_resume_id]
    lea  rsi, [rel str_wf_action]
    lea  rdx, [rel summon_action_activate]
    mov  ecx, SUMMON_INTENT_POINTER
    call summon_palette_registry_set
    jmp  .yes
.lists:
    mov  edi, [rel summon_pinned_id]
    mov  esi, r12d
    mov  edx, r13d
    call wgt_rect_hittest
    test eax, eax
    jnz  .pinned
    mov  edi, [rel summon_recents_id]
    mov  esi, r12d
    mov  edx, r13d
    call wgt_rect_hittest
    test eax, eax
    jnz  .recents
    mov  edi, [rel summon_results_id]
    mov  esi, r12d
    mov  edx, r13d
    call wgt_listview_pointer_press
    jmp  .yes
.pinned:
    mov  edi, [rel summon_pinned_id]
    jmp  .mode_button
.recents:
    mov  edi, [rel summon_recents_id]
.mode_button:
    lea  rsi, [rel str_wf_action]
    lea  rdx, [rel summon_action_activate]
    mov  ecx, SUMMON_INTENT_POINTER
    call summon_palette_registry_set
    jmp  .yes
.outside:
    mov  edi, [rel summon_start_id]
    lea  rsi, [rel str_wf_open]
    lea  rdx, [rel summon_zero]
    mov  ecx, SUMMON_INTENT_POINTER
    call summon_palette_registry_set
.yes:
    mov  eax, 1
    pop  r13
    pop  r12
    ret
.no:
    xor  eax, eax
    ret

summon_palette_global_key:
    cmp  byte [rel session_locked], SESSION_LOCKED
    je   .ignored
    mov  byte [rel summon_user_open], 1
    lea  rdx, [rel summon_one]
    cmp  byte [rel summon_palette_open], 1
    jne  .toggle
    lea  rdx, [rel summon_zero]
.toggle:
    mov  edi, [rel summon_start_id]
    lea  rsi, [rel str_wf_open]
    mov  ecx, SUMMON_INTENT_KEYBOARD
    call summon_palette_registry_set
    mov  eax, 1
    ret
.ignored:
    xor  eax, eax
    ret

summon_palette_modal_key:
    cmp  byte [rel session_locked], SESSION_LOCKED
    je   .no                            ; RCQ-17: locked keys belong to the sign-in form
    cmp  byte [rel summon_palette_open], 1
    jne  .no
    push rbx
    mov  ebx, eax
    cmp  ebx, GUI_KEY_ESC
    je   .close
    cmp  ebx, GUI_KEY_TAB
    je   .tab
    cmp  ebx, GUI_KEY_UP
    je   .up
    cmp  ebx, GUI_KEY_DOWN
    je   .down
    cmp  ebx, GUI_KEY_ENTER
    je   .enter
    mov  edi, [rel summon_palette_focus]
    cmp  edi, [rel summon_query_id]
    jne  .handled
    ; Request canonical editor delivery at the shared input seam.  The modal
    ; callback owns focus policy only; it never calls the editor recursively.
    mov  [rel wgt_focus_id], edi
    mov  eax, GUI_INPUT_MODAL_EDIT
    pop  rbx
    ret
.close:
    mov  edi, [rel summon_start_id]
    lea  rsi, [rel str_wf_open]
    lea  rdx, [rel summon_zero]
    mov  ecx, SUMMON_INTENT_KEYBOARD
    call summon_palette_registry_set
    jmp  .handled
.tab:
    mov  eax, [rel summon_palette_focus]
    xor  ecx, ecx
.find_focus:
    cmp  ecx, 5
    jae  .focus_query
    lea  rdx, [rel summon_focus_order]
    cmp  eax, [rdx + rcx*4]
    je   .advance
    inc  ecx
    jmp  .find_focus
.advance:
    test byte [rel input_kbd_mods], 1
    jnz  .step_back
.step_forward:
    inc  ecx
    cmp  ecx, 5
    jb   .focus_candidate
    xor  ecx, ecx
    jmp  .focus_candidate
.step_back:
    test ecx, ecx
    jnz  .back_dec
    mov  ecx, 5
.back_dec:
    dec  ecx
.focus_candidate:
    lea  rdx, [rel summon_focus_order]
    mov  eax, [rdx + rcx*4]
    cmp  eax, [rel summon_resume_id]
    jne  .set_focus
    mov  edi, eax
    call wgt_slot_ptr
    test dword [rax + WGI_EDIT], WGT_EDIT_DISABLED
    jz   .set_focus_from_order
    test byte [rel input_kbd_mods], 1
    jnz  .step_back
    jmp  .step_forward
.set_focus_from_order:
    lea  rdx, [rel summon_focus_order]
    mov  eax, [rdx + rcx*4]
.set_focus:
    mov  [rel summon_palette_focus], eax
    mov  [rel wgt_focus_id], eax
    call wmx_draw_all
    jmp  .handled
.focus_query:
    mov  eax, [rel summon_query_id]
    mov  [rel summon_palette_focus], eax
    mov  [rel wgt_focus_id], eax
    jmp  .handled
.up:
    mov  edi, [rel summon_results_id]
    call wgt_slot_ptr
    cmp  dword [rax + WGI_SEL_LO], 0
    je   .handled
    mov  esi, [rax + WGI_SEL_LO]
    dec  esi
    mov  edi, [rel summon_results_id]
    mov  ecx, SUMMON_INTENT_KEYBOARD
    call summon_palette_registry_select
    jmp  .handled
.down:
    mov  edi, [rel summon_results_id]
    call wgt_slot_ptr
    mov  ebx, [rax + WGI_SEL_LO]
    inc  ebx
    mov  edi, [rel summon_results_id]
    mov  esi, ebx
    call naming_picker_item_at
    test eax, eax
    jz   .handled
    mov  edi, [rel summon_results_id]
    mov  esi, ebx
    mov  ecx, SUMMON_INTENT_KEYBOARD
    call summon_palette_registry_select
    jmp  .handled
.enter:
    mov  eax, [rel summon_palette_focus]
    cmp  eax, [rel summon_resume_id]
    je   .button_enter
    cmp  eax, [rel summon_pinned_id]
    je   .button_enter
    cmp  eax, [rel summon_recents_id]
    je   .button_enter
    mov  edi, [rel summon_results_id]
    call wgt_slot_ptr
    mov  esi, [rax + WGI_SEL_LO]
    mov  edi, [rel summon_results_id]
    call naming_picker_item_at
    test eax, eax
    jz   .handled
    mov  edi, [rel summon_results_id]
    lea  rsi, [rel str_wf_action]
    lea  rdx, [rel summon_action_activate]
    mov  ecx, SUMMON_INTENT_KEYBOARD
    call summon_palette_registry_set
    jmp  .handled
.button_enter:
    mov  edi, eax
    lea  rsi, [rel str_wf_action]
    lea  rdx, [rel summon_action_activate]
    mov  ecx, SUMMON_INTENT_KEYBOARD
    call summon_palette_registry_set
.handled:
    mov  eax, 1
    pop  rbx
    ret
.no:
    xor  eax, eax
    ret

align 8
summon_focus_order: times 5 dd 0
summon_start_id: dd -1
summon_root_id: dd -1
summon_panel_id: dd -1
summon_query_id: dd -1
summon_resume_id: dd -1
summon_pinned_id: dd -1
summon_recents_id: dd -1
summon_results_id: dd -1
summon_resume_window: dd WM_MAX
summon_prior_widget_focus: dd -1
summon_palette_focus: dd -1
summon_cluster_x: dd 0
summon_cluster_y: dd 0
summon_cluster_w: dd 0
summon_cluster_h: dd 0
summon_palette_x: dd 0
summon_palette_y: dd 0
summon_palette_w: dd 0
summon_palette_h: dd 0
summon_palette_ready: db 0
summon_palette_open: db 0
summon_user_open: db 0
summon_registry_remote_active: db 0
summon_palette_erase_pending: db 0

summon_id_start: db "summon.start",0
summon_id_root: db "summon.root",0
summon_id_panel: db "summon.panel",0
summon_id_query: db "summon.query",0
summon_id_resume: db "summon.resume",0
summon_id_pinned: db "summon.pinned",0
summon_id_recents: db "summon.recents",0
summon_id_results: db "summon.results",0
summon_label_start: db "Start/Talk",0
summon_label_query: db "summon.query",0
summon_label_resume: db "summon.resume",0
summon_label_pinned: db "summon.pinned",0
summon_label_recents: db "summon.recents",0
summon_label_results: db "summon.results",0
summon_role_button: db "button",0
summon_role_dialog: db "dialog",0
summon_role_group: db "group",0
summon_role_search: db "searchbox",0
summon_role_tab: db "tab",0
summon_role_listbox: db "listbox",0
summon_text_root: db "Summon",0
summon_text_resume: db "Resume",0
summon_text_pinned: db "Pinned",0
summon_text_recents: db "Recents",0
summon_text_results: db "Results",0
summon_empty: db 0
summon_zero: db "0",0
summon_one: db "1",0
summon_field_target: db "target",0
summon_field_focus: db "focus",0
summon_field_selected: db "selected",0
summon_action_activate: db "activate",0
summon_verb_widgetset: db "WIDGETSET",0
summon_target_buf: db "window:",0
times 23 db 0
summon_target_none: db "none",0
summon_focus_buf: times 12 db 0
summon_tb_start_id: db " start_id=",0
summon_tb_start_rect: db " start_rect=",0
summon_tb_cluster_rect: db " cluster_rect=",0
summon_comma: db ",",0
summon_marker: db "[PAOS64] desktop: shared Summon palette registry/input KAT PASS [desktop.summon.kat]",13,10,0
summon_fail: db "[PAOS64] desktop: shared Summon palette initialization FAILED",13,10,0
summon_kat_fail: db "[PAOS64] desktop: shared Summon palette registry/input KAT FAILED",13,10,0
summon_form_name: db "summon",0
summon_kat_haystack: db "host-nonce-71df64b930e52ca8",0
summon_kat_needle: db "71df64b930e52ca8",0
summon_kat_miss: db "web-search",0

align 8
summon_registry_req: times REQ_SZ db 0
summon_registry_rsp: times RSP_SZ db 0
summon_registry_arg: times 128 db 0
summon_selected_buf: times 24 db 0

%undef SUMMON_CREATE
