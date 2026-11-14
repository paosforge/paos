;; MODULE gui/form_loader
%include "core/abi/build_profile.inc"
;; LAYER 6
;; EXPORTS form_loader_declare, form_loader_selftest, form_verb_unlocked, form_load_internal, form_load_index, form_load_blob, form_load_app_blob, form_load_app_staged_blob, form_lint_blob, form_ephemeral_close, form_ephemeral_reap, form_ephemeral_busy, form_error_string, form_table_ptr, form_launcher_flags, form_out_reset, form_out_put_str, form_out_put_dec, form_out_buf, form_out_ready, form_out_cur, form_active_slot, form_card_loading, form_summon_gate, form_widget_tree_text_ptr, form_wintree_append_state, form_netmon_tick, form_cadence_live_init, form_netmon_bind, form_netmon_unbind, form_netmon_members_fn, form_netmon_address_fn
;; IMPORTS gui/widget_tabstrip, sec/platform_key_health, gui/form_events, fs/fat32_disk, fs/ext4_copy, core/unicode_edit, gui/widget, gui/widget_containers, gui/widget_progress, gui/widget_chart, gui/window, gui/window_mgmt, gui/wintree, gui/taskbar, gui/liveness_panel, svc/command, boot/pmod_loader, svc/command_udp, svc/boot_ab, dev/net/e1000e, boot/header, boot/gop, core/cadence, core/time, core/lib/fmt, core/lib/str, gui/widget_image, gui/img/img_core, gui/img/img_cache, fs/vfs, fs/ntfs_disk, svc/command_fs, gui/lock_screen, sec/session, sec/principal, sec/cpu_security_report
;; CAPS
;; OWNER saga:gui_foundation_ladder

; form_spec v1 proposal implementation. Every declaration is copied into a
; bounded scratch buffer and fully linted before a WM slot or widget id is
; allocated. The embedded table is populated with runtime VAs (never dq symbol).

%include "gui/form_explorer_observe.inc"

FORM_PARSE_MAX equ 1536
FORM_OUT_MAX   equ 1472
FORM_INFO_CHUNK equ 1280
FORM_TITLE_MAX equ 40
FORM_NODE_MAX  equ 32
FORM_NODE_ID_MAX equ 32
FORM_SPACING   equ 8
FORM_SYSPROPS_SNAPSHOT_MS equ 1000

FORM_BIND_NONE      equ 0
FORM_BIND_SYSPROPS  equ 1
FORM_BIND_NETMON    equ 2
FORM_BIND_RX_RATE   equ 3
FORM_BIND_TX_RATE   equ 4
FORM_BIND_FS_ROOT   equ 5             ; explorer: root listing of the FS-verb mount
FORM_BIND_FS_STATUS equ 6             ; explorer: mount/files/write status rows
FORM_BIND_SUMMON_PINNED  equ 7
FORM_BIND_SUMMON_RECENTS equ 8
FORM_BIND_SUMMON_RESULTS equ 9
FORM_BIND_NET_MEMBERS    equ 10       ; netmon.members: keep-owned member rows (gui/netmon_form; GUI/WINTREE only, never NETMON_STAT)
FORM_BIND_FS_DRIVES equ 12
FORM_BIND_FS_DETAILS equ 13
FORM_BIND_FS_CONTEXT equ 14
FORM_BIND_NET_ADDRESS    equ 11       ; netmon.address: effective selected address/route rows

FORM_ERR_NONE       equ 0
FORM_ERR_MISSING    equ 1
FORM_ERR_OVERSIZE   equ 2
FORM_ERR_SYNTAX     equ 3
FORM_ERR_UNKNOWN_KEY equ 4
FORM_ERR_UNKNOWN_WIDGET equ 5
FORM_ERR_NO_SLOT    equ 6
FORM_ERR_CAPACITY   equ 7
FORM_ERR_UNKNOWN_ASSET equ 8
FORM_ERR_CARD_SHOWN equ 9                ; RCQ-40 F4 (c): an agent's Summon palette while an action card is shown

; Keep the embedded declarations as data, but spell every label out: NASM does
; not interpolate a macro argument inside an INCBIN string.  The runtime table
; is likewise populated explicitly so every stored address is a relocated VA,
; never the low compile-time RVA produced by `dq symbol`.
FORM_GOOD_COUNT equ 5                  ; preserve 2111's byte-exact boot marker
FORM_EXPLORER_INDEX equ 6            ; explorer.frm (good row, like imgdemo at 5)
FORM_BAD_FIRST  equ 7
FORM_LOCK_INDEX equ 10
FORM_CONTAINERS_INDEX equ 11
FORM_DROPDOWN_INDEX equ 12
FORM_LIST_MODES_INDEX equ 13
FORM_SUMMON_INDEX equ 14
; hub packet 0010 (MSI conflict map: Start entries become Summon rows, new form
; indices from 15 up). terminal and the three power rows are catalogue entries
; whose FORMLOAD gui/start_programs.asm takes; settings and power are real forms.
FORM_TERMINAL_INDEX equ 15
FORM_SETTINGS_INDEX equ 16
FORM_POWER_INDEX    equ 17          ; the shared confirmation: opened only through a power row
FORM_RESTART_INDEX  equ 18
FORM_SHUTDOWN_INDEX equ 19
FORM_WINDOWS_INDEX  equ 20
FORM_CARD_INDEX     equ 21          ; RCQ-40 J2b: the owner action card; only gui/card_surface builds it
FORM_HELP_INDEX     equ 22          ; RCQ-38 H2: offline help (gui/help_view); pinned, and Win+F1
FORM_RECOVERY_INDEX equ 23          ; public fallback notice, once after workspace creation
FORM_WIFI_INDEX equ 24             ; local private owner Wi-Fi entry
FORM_TEXT_INDEX equ 25             ; T5-15 Text Viewer (gui/text_view); File Explorer opens it
FORM_APPS_INDEX equ 26
FORM_NETMON_INDEX equ 4
FORM_WALLPAPERS_INDEX equ 27
FORM_COUNT    equ 28
FORM_SLOT_COUNT equ (FORM_COUNT + 1)
FORM_EPHEMERAL_INDEX equ FORM_COUNT
FORM_NAME     equ 0
FORM_BLOB_PTR equ 8
FORM_LEN      equ 16
FORM_ENT_SZ   equ 24
FORM_LAUNCHABLE equ 1
FORM_PINNED     equ 2

form_blob_demo_a: incbin "gui/forms/demo_a.frm"
form_blob_demo_a_end: db 0
form_blob_demo_b: incbin "gui/forms/demo_b.frm"
form_blob_demo_b_end: db 0
form_blob_demo_c: incbin "gui/forms/demo_c.frm"
form_blob_demo_c_end: db 0
form_blob_sysprops: incbin "gui/forms/sysprops.frm"
; The shared worktree owns sysprops.frm this iteration.  Keep the consumer
; declarative by extending its embedded data blob at the loader seam without
; mutating those owner bytes.
db "widget type=toggle id=night_mode x=24 y=372 w=200 h=24 text=night_mode role=switch value=0 min=0 max=1 step=1",10
db "widget type=slider id=pointer_speed x=24 y=404 w=452 h=24 text=pointer_speed role=slider value=5 min=0 max=10 step=1",10
db "widget type=numeric id=text_scale x=24 y=436 w=200 h=26 text=text_scale role=spinbutton value=5 min=0 max=10 step=1",10
db "widget type=separator id=settings_divider x=24 y=476 w=452 h=2 text=settings_divider role=separator",10
form_blob_sysprops_end: db 0
form_blob_imgdemo: incbin "gui/forms/imgdemo.frm"
form_blob_imgdemo_end: db 0
form_blob_explorer: incbin "gui/forms/explorer.frm"
form_blob_explorer_end: db 0
form_blob_bad_rawcolor: incbin "gui/forms/bad_rawcolor.frm"
form_blob_bad_rawcolor_end: db 0
form_blob_bad_unknown_widget: incbin "gui/forms/bad_unknown_widget.frm"
form_blob_bad_unknown_widget_end: db 0
form_blob_bad_unknown_key: incbin "gui/forms/bad_unknown_key.frm"
form_blob_bad_unknown_key_end: db 0
form_blob_lock_screen: incbin "gui/forms/lock_screen.frm"
form_blob_lock_screen_end: db 0
form_name_lock_screen: db "lock_screen",0

form_name_demo_a: db "demo_a",0
form_name_demo_b: db "demo_b",0
form_name_demo_c: db "demo_c",0
form_name_sysprops: db "sysprops",0
form_name_netmon: db "netmon",0
form_name_imgdemo: db "imgdemo",0
form_name_explorer: db "explorer",0
form_name_bad_rawcolor: db "bad_rawcolor",0
form_name_bad_unknown_widget: db "bad_unknown_widget",0
form_name_bad_unknown_key: db "bad_unknown_key",0
form_name_dropdown: db "gui_kit_dropdown",0
form_blob_dropdown:
    db "form gui_kit_dropdown spec=v1",10
    db "window title=Dropdown w=320 h=180 x=180 y=180 resizable=0 min_w=320 min_h=180 chrome=standard restore=always",10
    db "widget type=overlay id=choices_layer x=24 y=144 w=220 h=72 text=choices role=group overlay_layer=1",10
    db "widget type=listview id=choices x=24 y=108 w=220 h=28 text=Slate,Signal,Daylight role=combobox value=0 min=0 max=2 step=1 mode=dropdown overlay=choices_layer",10
form_blob_dropdown_end: db 0
form_name_list_modes: db "gui_kit_list_modes",0
form_blob_list_modes:
    db "form gui_kit_list_modes spec=v1",10
    db "window title=List_Modes w=640 h=300 x=80 y=150 resizable=0 min_w=640 min_h=300 chrome=standard restore=always",10
    ; List text uses the stock widget's canonical 31-byte inline field. Keep
    ; fixtures within that inherited bound; hierarchy semantics live in the
    ; typed parent/expanded state, not in verbose display labels.
    db "widget type=listview id=tree_choices x=24 y=64 w=276 h=190 text=R,C,G,L,O,S role=tree value=0 min=0 max=5 step=1 mode=tree parents=r,0,1,2,r,r expanded=1",10
    db "widget type=listview id=radio_choices x=324 y=64 w=276 h=190 text=A,B,D role=radiogroup value=0 min=0 max=2 step=1 mode=radio disabled=4",10
form_blob_list_modes_end: db 0
form_name_summon: db "summon",0
form_blob_summon: incbin "gui/forms/summon.frm"
form_blob_summon_end: db 0
; hub packet 0010: the Start entries (gui/start_programs.asm). A catalogue row's
; FORMLOAD never reaches the loader; its declaration says where it goes, and
; restore=never keeps session restore from opening it.
form_name_terminal: db "terminal",0
form_blob_terminal:
    db "form terminal spec=v1",10
    db "window title=Terminal w=360 h=120 x=180 y=120 resizable=0 min_w=360 min_h=120 chrome=standard restore=never",10
    db "widget type=label id=route x=16 y=56 w=320 h=24 text=Opens_a_Terminal_window role=label",10
form_blob_terminal_end: db 0
form_name_settings: db "settings",0
form_blob_settings: incbin "gui/forms/settings.frm"
form_blob_settings_end: db 0
form_name_wallpapers: db "wallpapers",0
form_blob_wallpapers: incbin "gui/forms/wallpapers.frm"
form_blob_wallpapers_end: db 0
form_name_help: db "offline_help",0
form_blob_help: incbin "gui/forms/help.frm"
form_blob_help_end: db 0
form_name_text: db "text_viewer",0
form_blob_text: incbin "gui/forms/text_viewer.frm"
form_blob_text_end: db 0
form_name_wifi: db "wifi_local",0
form_blob_wifi: incbin "gui/forms/wifi_local.frm"
form_blob_wifi_end: db 0
form_name_apps: db "settings_apps",0
form_blob_apps: incbin "gui/forms/settings_apps.frm"
form_blob_apps_end: db 0
form_name_recovery: db "recovery_notice",0
form_blob_recovery: incbin "gui/forms/recovery_notice.frm"
form_blob_recovery_end: db 0
form_name_power: db "power",0
form_blob_power: incbin "gui/forms/power.frm"
form_blob_power_end: db 0
form_name_restart: db "restart",0
form_blob_restart:
    db "form restart spec=v1",10
    db "window title=Restart w=360 h=120 x=180 y=120 resizable=0 min_w=360 min_h=120 chrome=standard restore=never",10
    db "widget type=label id=route x=16 y=56 w=320 h=24 text=Asks_first_then_restarts role=label",10
form_blob_restart_end: db 0
form_name_shutdown: db "shut_down",0
form_blob_shutdown:
    db "form shut_down spec=v1",10
    db "window title=Shut_down w=360 h=120 x=180 y=120 resizable=0 min_w=360 min_h=120 chrome=standard restore=never",10
    db "widget type=label id=route x=16 y=56 w=320 h=24 text=Asks_first_then_powers_off role=label",10
form_blob_shutdown_end: db 0
form_name_windows: db "return_to_windows",0
form_blob_windows:
    db "form return_to_windows spec=v1",10
    db "window title=Return_to_Windows w=360 h=120 x=180 y=120 resizable=0 min_w=360 min_h=120 chrome=standard restore=never",10
    db "widget type=label id=route x=16 y=56 w=320 h=24 text=Asks_first_then_boots_Windows role=label",10
form_blob_windows_end: db 0
; RCQ-40 J2b: the owner action card (gui/card_surface). Chrome like the lock
; form: loadable only while form_card_loading is set; its text is set at runtime.
form_name_card: db "card",0
form_blob_card:
    db "form card spec=v1",10
    db "window title=Owner_action_card w=600 h=380 x=660 y=300 resizable=0 min_w=600 min_h=380 chrome=standard restore=never",10
    db "widget type=label id=card_who x=20 y=44 w=560 h=24 text=card role=label",10
    db "widget type=label id=card_verb x=20 y=72 w=560 h=24 text=card role=label",10
    db "widget type=label id=card_arg0 x=20 y=104 w=560 h=24 text=card role=label",10
    db "widget type=label id=card_arg1 x=20 y=130 w=560 h=24 text=card role=label",10
    db "widget type=label id=card_arg2 x=20 y=156 w=560 h=24 text=card role=label",10
    db "widget type=label id=card_arg3 x=20 y=182 w=560 h=24 text=card role=label",10
    db "widget type=label id=card_arg4 x=20 y=208 w=560 h=24 text=card role=label",10
    db "widget type=label id=card_arg5 x=20 y=234 w=560 h=24 text=card role=label",10
    db "widget type=label id=card_arg6 x=20 y=260 w=560 h=24 text=card role=label",10
    db "widget type=label id=card_note x=20 y=292 w=560 h=24 text=card role=label",10
    db "widget type=button id=card_deny x=310 y=326 w=270 h=38 text=Deny role=button",10
    db "widget type=button id=card_confirm x=20 y=326 w=270 h=38 text=Confirm role=button",10
form_blob_card_end: db 0
; The final row is runtime-only.  It is never listed by FORMLIST/FORMINFO and
; is cleared when its one-use window closes.
forms_table: times (FORM_SLOT_COUNT * FORM_ENT_SZ) db 0
; Launcher eligibility is registry metadata, not a palette-owned catalogue.
form_launcher_flags:
    db 0,0,0,FORM_LAUNCHABLE|FORM_PINNED,FORM_LAUNCHABLE,FORM_LAUNCHABLE
    db FORM_LAUNCHABLE|FORM_PINNED      ; 6 explorer: owner only, naming_picker_form_live
    db 0,0,0,0,0,0,0,0
    db FORM_LAUNCHABLE|FORM_PINNED,FORM_LAUNCHABLE|FORM_PINNED,0      ; 15 terminal, 16 settings, 17 power (0010)
    db FORM_LAUNCHABLE|FORM_PINNED,FORM_LAUNCHABLE|FORM_PINNED,FORM_LAUNCHABLE|FORM_PINNED ; 18-20 power rows
    db 0                                ; 21 card (RCQ-40 J2b): never listed for launch
    db FORM_LAUNCHABLE|FORM_PINNED      ; 22 offline_help (RCQ-38 H2)
    db 0                               ; 23 automatic recovery notice
    db FORM_LAUNCHABLE|FORM_PINNED      ; 24 Wi-Fi
    db FORM_LAUNCHABLE                  ; 25 text_viewer (T5-15)
    db FORM_LAUNCHABLE                  ; 26 Settings > Apps, found by search

    db FORM_LAUNCHABLE                ; 27 Wallpapers, native stock picker

forms_table_init:
    lea rax, [rel form_name_text]
    mov [rel forms_table + FORM_TEXT_INDEX*FORM_ENT_SZ + FORM_NAME], rax
    lea rax, [rel form_blob_text]
    mov [rel forms_table + FORM_TEXT_INDEX*FORM_ENT_SZ + FORM_BLOB_PTR], rax
    mov qword [rel forms_table + FORM_TEXT_INDEX*FORM_ENT_SZ + FORM_LEN], form_blob_text_end-form_blob_text
    lea rax, [rel form_name_wallpapers]
    mov [rel forms_table + FORM_WALLPAPERS_INDEX*FORM_ENT_SZ + FORM_NAME], rax
    lea rax, [rel form_blob_wallpapers]
    mov [rel forms_table + FORM_WALLPAPERS_INDEX*FORM_ENT_SZ + FORM_BLOB_PTR], rax
    mov qword [rel forms_table + FORM_WALLPAPERS_INDEX*FORM_ENT_SZ + FORM_LEN], form_blob_wallpapers_end-form_blob_wallpapers
    lea rax, [rel form_name_wifi]
    mov [rel forms_table + FORM_WIFI_INDEX*FORM_ENT_SZ + FORM_NAME], rax
    lea rax, [rel form_blob_wifi]
    mov [rel forms_table + FORM_WIFI_INDEX*FORM_ENT_SZ + FORM_BLOB_PTR], rax
    mov qword [rel forms_table + FORM_WIFI_INDEX*FORM_ENT_SZ + FORM_LEN], form_blob_wifi_end-form_blob_wifi
    lea rax, [rel form_name_apps]
    mov [rel forms_table + FORM_APPS_INDEX*FORM_ENT_SZ + FORM_NAME], rax
    lea rax, [rel form_blob_apps]
    mov [rel forms_table + FORM_APPS_INDEX*FORM_ENT_SZ + FORM_BLOB_PTR], rax
    mov qword [rel forms_table + FORM_APPS_INDEX*FORM_ENT_SZ + FORM_LEN], form_blob_apps_end-form_blob_apps
    lea rax, [rel form_name_demo_a]
    mov [rel forms_table + 0*FORM_ENT_SZ + FORM_NAME], rax
    lea rax, [rel form_blob_demo_a]
    mov [rel forms_table + 0*FORM_ENT_SZ + FORM_BLOB_PTR], rax
    mov qword [rel forms_table + 0*FORM_ENT_SZ + FORM_LEN], form_blob_demo_a_end-form_blob_demo_a
    lea rax, [rel form_name_demo_b]
    mov [rel forms_table + 1*FORM_ENT_SZ + FORM_NAME], rax
    lea rax, [rel form_blob_demo_b]
    mov [rel forms_table + 1*FORM_ENT_SZ + FORM_BLOB_PTR], rax
    mov qword [rel forms_table + 1*FORM_ENT_SZ + FORM_LEN], form_blob_demo_b_end-form_blob_demo_b
    lea rax, [rel form_name_demo_c]
    mov [rel forms_table + 2*FORM_ENT_SZ + FORM_NAME], rax
    lea rax, [rel form_blob_demo_c]
    mov [rel forms_table + 2*FORM_ENT_SZ + FORM_BLOB_PTR], rax
    mov qword [rel forms_table + 2*FORM_ENT_SZ + FORM_LEN], form_blob_demo_c_end-form_blob_demo_c
    lea rax, [rel form_name_sysprops]
    mov [rel forms_table + 3*FORM_ENT_SZ + FORM_NAME], rax
    lea rax, [rel form_blob_sysprops]
    mov [rel forms_table + 3*FORM_ENT_SZ + FORM_BLOB_PTR], rax
    mov qword [rel forms_table + 3*FORM_ENT_SZ + FORM_LEN], form_blob_sysprops_end-form_blob_sysprops
    lea rax, [rel form_name_netmon]
    mov [rel forms_table + 4*FORM_ENT_SZ + FORM_NAME], rax
    mov qword [rel forms_table + 4*FORM_ENT_SZ + FORM_BLOB_PTR], 0
    mov qword [rel forms_table + 4*FORM_ENT_SZ + FORM_LEN], 0
    lea rax, [rel form_name_imgdemo]
    mov [rel forms_table + 5*FORM_ENT_SZ + FORM_NAME], rax
    lea rax, [rel form_blob_imgdemo]
    mov [rel forms_table + 5*FORM_ENT_SZ + FORM_BLOB_PTR], rax
    mov qword [rel forms_table + 5*FORM_ENT_SZ + FORM_LEN], form_blob_imgdemo_end-form_blob_imgdemo
    lea rax, [rel form_name_explorer]
    mov [rel forms_table + 6*FORM_ENT_SZ + FORM_NAME], rax
    lea rax, [rel form_blob_explorer]
    mov [rel forms_table + 6*FORM_ENT_SZ + FORM_BLOB_PTR], rax
    mov qword [rel forms_table + 6*FORM_ENT_SZ + FORM_LEN], form_blob_explorer_end-form_blob_explorer
    lea rax, [rel form_name_bad_rawcolor]
    mov [rel forms_table + 7*FORM_ENT_SZ + FORM_NAME], rax
    lea rax, [rel form_blob_bad_rawcolor]
    mov [rel forms_table + 7*FORM_ENT_SZ + FORM_BLOB_PTR], rax
    mov qword [rel forms_table + 7*FORM_ENT_SZ + FORM_LEN], form_blob_bad_rawcolor_end-form_blob_bad_rawcolor
    lea rax, [rel form_name_bad_unknown_widget]
    mov [rel forms_table + 8*FORM_ENT_SZ + FORM_NAME], rax
    lea rax, [rel form_blob_bad_unknown_widget]
    mov [rel forms_table + 8*FORM_ENT_SZ + FORM_BLOB_PTR], rax
    mov qword [rel forms_table + 8*FORM_ENT_SZ + FORM_LEN], form_blob_bad_unknown_widget_end-form_blob_bad_unknown_widget
    lea rax, [rel form_name_bad_unknown_key]
    mov [rel forms_table + 9*FORM_ENT_SZ + FORM_NAME], rax
    lea rax, [rel form_blob_bad_unknown_key]
    mov [rel forms_table + 9*FORM_ENT_SZ + FORM_BLOB_PTR], rax
    mov qword [rel forms_table + 9*FORM_ENT_SZ + FORM_LEN], form_blob_bad_unknown_key_end-form_blob_bad_unknown_key
    lea rax, [rel form_name_lock_screen]
    mov [rel forms_table + FORM_LOCK_INDEX*FORM_ENT_SZ + FORM_NAME], rax
    lea rax, [rel form_blob_lock_screen]
    mov [rel forms_table + FORM_LOCK_INDEX*FORM_ENT_SZ + FORM_BLOB_PTR], rax
    mov qword [rel forms_table + FORM_LOCK_INDEX*FORM_ENT_SZ + FORM_LEN], form_blob_lock_screen_end-form_blob_lock_screen
    lea rax, [rel form_container_name]
    mov [rel forms_table + FORM_CONTAINERS_INDEX*FORM_ENT_SZ + FORM_NAME], rax
    lea rax, [rel form_container_fixture]
    mov [rel forms_table + FORM_CONTAINERS_INDEX*FORM_ENT_SZ + FORM_BLOB_PTR], rax
    mov qword [rel forms_table + FORM_CONTAINERS_INDEX*FORM_ENT_SZ + FORM_LEN], form_container_end-form_container_fixture
    lea rax, [rel form_name_dropdown]
    mov [rel forms_table + FORM_DROPDOWN_INDEX*FORM_ENT_SZ + FORM_NAME], rax
    lea rax, [rel form_blob_dropdown]
    mov [rel forms_table + FORM_DROPDOWN_INDEX*FORM_ENT_SZ + FORM_BLOB_PTR], rax
    mov qword [rel forms_table + FORM_DROPDOWN_INDEX*FORM_ENT_SZ + FORM_LEN], form_blob_dropdown_end-form_blob_dropdown
    lea rax, [rel form_name_list_modes]
    mov [rel forms_table + FORM_LIST_MODES_INDEX*FORM_ENT_SZ + FORM_NAME], rax
    lea rax, [rel form_blob_list_modes]
    mov [rel forms_table + FORM_LIST_MODES_INDEX*FORM_ENT_SZ + FORM_BLOB_PTR], rax
    mov qword [rel forms_table + FORM_LIST_MODES_INDEX*FORM_ENT_SZ + FORM_LEN], form_blob_list_modes_end-form_blob_list_modes
    lea rax, [rel form_name_summon]
    mov [rel forms_table + FORM_SUMMON_INDEX*FORM_ENT_SZ + FORM_NAME], rax
    lea rax, [rel form_blob_summon]
    mov [rel forms_table + FORM_SUMMON_INDEX*FORM_ENT_SZ + FORM_BLOB_PTR], rax
    mov qword [rel forms_table + FORM_SUMMON_INDEX*FORM_ENT_SZ + FORM_LEN], form_blob_summon_end-form_blob_summon
    lea rax, [rel form_name_terminal]
    mov [rel forms_table + FORM_TERMINAL_INDEX*FORM_ENT_SZ + FORM_NAME], rax
    lea rax, [rel form_blob_terminal]
    mov [rel forms_table + FORM_TERMINAL_INDEX*FORM_ENT_SZ + FORM_BLOB_PTR], rax
    mov qword [rel forms_table + FORM_TERMINAL_INDEX*FORM_ENT_SZ + FORM_LEN], form_blob_terminal_end-form_blob_terminal
    lea rax, [rel form_name_settings]
    mov [rel forms_table + FORM_SETTINGS_INDEX*FORM_ENT_SZ + FORM_NAME], rax
    lea rax, [rel form_blob_settings]
    mov [rel forms_table + FORM_SETTINGS_INDEX*FORM_ENT_SZ + FORM_BLOB_PTR], rax
    mov qword [rel forms_table + FORM_SETTINGS_INDEX*FORM_ENT_SZ + FORM_LEN], form_blob_settings_end-form_blob_settings
    lea rax, [rel form_name_power]
    mov [rel forms_table + FORM_POWER_INDEX*FORM_ENT_SZ + FORM_NAME], rax
    lea rax, [rel form_blob_power]
    mov [rel forms_table + FORM_POWER_INDEX*FORM_ENT_SZ + FORM_BLOB_PTR], rax
    mov qword [rel forms_table + FORM_POWER_INDEX*FORM_ENT_SZ + FORM_LEN], form_blob_power_end-form_blob_power
    lea rax, [rel form_name_restart]
    mov [rel forms_table + FORM_RESTART_INDEX*FORM_ENT_SZ + FORM_NAME], rax
    lea rax, [rel form_blob_restart]
    mov [rel forms_table + FORM_RESTART_INDEX*FORM_ENT_SZ + FORM_BLOB_PTR], rax
    mov qword [rel forms_table + FORM_RESTART_INDEX*FORM_ENT_SZ + FORM_LEN], form_blob_restart_end-form_blob_restart
    lea rax, [rel form_name_shutdown]
    mov [rel forms_table + FORM_SHUTDOWN_INDEX*FORM_ENT_SZ + FORM_NAME], rax
    lea rax, [rel form_blob_shutdown]
    mov [rel forms_table + FORM_SHUTDOWN_INDEX*FORM_ENT_SZ + FORM_BLOB_PTR], rax
    mov qword [rel forms_table + FORM_SHUTDOWN_INDEX*FORM_ENT_SZ + FORM_LEN], form_blob_shutdown_end-form_blob_shutdown
    lea rax, [rel form_name_windows]
    mov [rel forms_table + FORM_WINDOWS_INDEX*FORM_ENT_SZ + FORM_NAME], rax
    lea rax, [rel form_blob_windows]
    mov [rel forms_table + FORM_WINDOWS_INDEX*FORM_ENT_SZ + FORM_BLOB_PTR], rax
    mov qword [rel forms_table + FORM_WINDOWS_INDEX*FORM_ENT_SZ + FORM_LEN], form_blob_windows_end-form_blob_windows
    lea rax, [rel form_name_card]
    mov [rel forms_table + FORM_CARD_INDEX*FORM_ENT_SZ + FORM_NAME], rax
    lea rax, [rel form_blob_card]
    mov [rel forms_table + FORM_CARD_INDEX*FORM_ENT_SZ + FORM_BLOB_PTR], rax
    mov qword [rel forms_table + FORM_CARD_INDEX*FORM_ENT_SZ + FORM_LEN], form_blob_card_end-form_blob_card
    lea rax, [rel form_name_help]
    mov [rel forms_table + FORM_HELP_INDEX*FORM_ENT_SZ + FORM_NAME], rax
    lea rax, [rel form_blob_help]
    mov [rel forms_table + FORM_HELP_INDEX*FORM_ENT_SZ + FORM_BLOB_PTR], rax
    mov qword [rel forms_table + FORM_HELP_INDEX*FORM_ENT_SZ + FORM_LEN], form_blob_help_end-form_blob_help
    lea rax, [rel form_name_recovery]
    mov [rel forms_table + FORM_RECOVERY_INDEX*FORM_ENT_SZ + FORM_NAME], rax
    lea rax, [rel form_blob_recovery]
    mov [rel forms_table + FORM_RECOVERY_INDEX*FORM_ENT_SZ + FORM_BLOB_PTR], rax
    mov qword [rel forms_table + FORM_RECOVERY_INDEX*FORM_ENT_SZ + FORM_LEN], form_blob_recovery_end-form_blob_recovery
    ret

; Replace only the handler pointers in rung 0's existing registry rows. Their
; metadata remains exact: FORMLOAD destructive/owner-signed, the three reads T0.
form_loader_declare:
    call form_events_declare
    call forms_table_init
    ; L6 binds its parser/lifetime callbacks into the lower L5 transport. The
    ; transport never reaches upward by static symbol reference.
    lea  rdi, [rel form_load_blob]
    lea  rsi, [rel form_ephemeral_close]
    lea  rdx, [rel form_ephemeral_reap]
    lea  rcx, [rel form_lint_blob]
    lea  r8, [rel form_error_string]
    call ephform_bind_loader
    call widget_image_register
    call wgt_containers_register
    call wgt_chart_register
    call wgt_tabstrip_register          ; D2 tabstrip + menu types
    ; v1.1 explorer: FSCD <path> sets the directory the fs.root bind lists (view state only)
    lea  rdi, [rel str_verb_fscd]
    lea  rsi, [rel form_cmd_verb_fscd]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    ; Readonly, authenticated by the existing non-public command floor.
    lea  rdi, [rel str_verb_explorerobs]
    lea  rsi, [rel form_cmd_verb_explorerobs]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    mov  edi, [rel wgt_listview_type]   ; RCQ-21: the Explorer's file list takes its presses
    lea  rsi, [rel form_explorer_capture] ; (every other listview declines: unchanged)
    call wgt_type_bind_capture
    mov  edi, [rel wgt_listview_type]
    call wgt_type_capture_buttons      ; callback rejects middle/foreign binds
    mov  byte [rel form_fs_cwd], '/'
    mov  byte [rel form_fs_cwd + 1], 0
    mov  dword [rel form_fs_cwd_len], 1
    mov  qword [rel form_sysprops_snapshot_ms], 0
    mov  qword [rel form_fsroot_snapshot_ms], 0
    mov  ecx, FORM_SLOT_COUNT
    lea  rdi, [rel form_active_slot]
.slots:
    mov  dword [rdi], -1
    add  rdi, 4
    loop .slots
    lea  rdi, [rel str_verb_formload]
    lea  rsi, [rel form_cmd_verb_formload]
    call form_replace_handler
    lea  rdi, [rel str_verb_formlist]
    lea  rsi, [rel form_cmd_verb_formlist]
    call form_replace_handler
    lea  rdi, [rel str_verb_forminfo]
    lea  rsi, [rel form_cmd_verb_forminfo]
    call form_replace_handler
    lea  rdi, [rel str_verb_cadence]
    lea  rsi, [rel form_cmd_verb_cadence]
    call form_replace_handler
    ret

form_replace_handler:
    push r12
    mov  r12, rsi
    call command_lookup
    cmp  eax, -1
    je   .out
    imul rax, rax, VERB_ENT_SZ
    lea  rcx, [rel verb_table]
    mov  [rcx + rax + VERB_HANDLER], r12
.out:
    pop  r12
    ret

; ---------------------------------------------------------------------------
; Bounded reply writer (command_udp consumes this as one lean datagram).
form_out_reset:
    lea  rax, [rel form_out_buf]
    mov  [rel form_out_cur], rax
    mov  byte [rel form_out_ready], 0
    mov  byte [rax], 0
    ret

form_out_put_str:
    mov  rsi, [rel form_out_cur]
    lea  rdx, [rel form_out_buf + FORM_OUT_MAX - 1]
.cp:
    cmp  rsi, rdx
    jae  .done
    mov  al, [rdi]
    test al, al
    jz   .done
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .cp
.done:
    mov  byte [rsi], 0
    mov  [rel form_out_cur], rsi
    ret

form_out_put_n:
    mov  rax, [rel form_out_cur]
    lea  r8, [rel form_out_buf + FORM_OUT_MAX - 1]
.cp:
    test rsi, rsi
    jz   .done
    cmp  rax, r8
    jae  .done
    mov  dl, [rdi]
    mov  [rax], dl
    inc  rax
    inc  rdi
    dec  rsi
    jmp  .cp
.done:
    mov  byte [rax], 0
    mov  [rel form_out_cur], rax
    ret

form_out_put_dec:
    mov  rsi, [rel form_out_cur]
    lea  rax, [rel form_out_buf + FORM_OUT_MAX - 24]
    cmp  rsi, rax
    jae  .done
    push rsi
    call fmt_dec
    pop  rsi
    add  rsi, rax
    mov  byte [rsi], 0
    mov  [rel form_out_cur], rsi
.done:
    ret

; ---------------------------------------------------------------------------
; Table helpers.
form_table_ptr:
    mov  eax, edi
    imul rax, rax, FORM_ENT_SZ
    lea  rcx, [rel forms_table]
    add  rax, rcx
    ret

form_lookup:
    push rbx
    push r12
    mov  r12, rdi
    xor  ebx, ebx
.loop:
    cmp  ebx, FORM_COUNT
    jae  .miss
    mov  edi, ebx
    call form_table_ptr
    mov  rdi, r12
    mov  rsi, [rax + FORM_NAME]
    call strcmp
    test rax, rax
    jz   .hit
    inc  ebx
    jmp  .loop
.hit:
    mov  eax, ebx
    jmp  .out
.miss:
    mov  eax, -1
.out:
    pop  r12
    pop  rbx
    ret

; Shared bounded blob seam.  Baked rows and runtime staging both arrive here;
; the parser never needs to know where a declaration was stored.
; RDI=blob pointer, RSI=exact byte length.
form_copy_blob_ptr:
    mov  rcx, rsi
    cmp  rcx, FORM_PARSE_MAX - 1
    ja   .bad
    test rcx, rcx
    jz   .bad
    mov  rsi, rdi
    lea  rdi, [rel form_parse_buf]
    xor  edx, edx
.cp:
    cmp  rdx, rcx
    jae  .done
    mov  al, [rsi + rdx]
    mov  [rdi + rdx], al
    inc  rdx
    jmp  .cp
.done:
    mov  byte [rdi + rdx], 0
    xor  eax, eax
    jmp  .out
.bad:
    mov  dword [rel form_error], FORM_ERR_OVERSIZE
    mov  eax, 1
.out:
    ret

; Compatibility wrapper for table callers and the baked oversize KAT.
form_copy_blob:
    call form_table_ptr
    mov  rdi, [rax + FORM_BLOB_PTR]
    mov  rsi, [rax + FORM_LEN]
    jmp  form_copy_blob_ptr

; token key matcher: token `<key>=<value>` -> RAX=value, zero on mismatch.
form_key_value:
    push rbx
    mov  rbx, rdi
.key:
    mov  al, [rsi]
    test al, al
    jz   .eq
    cmp  al, [rbx]
    jne  .miss
    inc  rsi
    inc  rbx
    jmp  .key
.eq:
    cmp  byte [rbx], '='
    jne  .miss
    lea  rax, [rbx + 1]
    jmp  .out
.miss:
    xor  eax, eax
.out:
    pop  rbx
    ret

form_parse_u32:
    mov  rdi, rax
    call wgt_progress_parse_num         ; strict full-token, overflow-safe parser
    jc   .bad
    mov  ecx, 0xffffffff
    cmp  rax, rcx
    ja   .bad
    clc
    ret
.bad:
    stc
    ret

form_widget_type_lookup:
    push rbx
    push r12
    mov  r12, rdi
    xor  ebx, ebx
.loop:
    cmp  ebx, [rel wgt_type_count]
    jae  .miss
    mov  eax, ebx
    imul rax, rax, WT_SZ
    lea  rcx, [rel wgt_types]
    mov  rdi, r12
    mov  rsi, [rcx + rax + WT_NAME]
    call strcmp
    test rax, rax
    jz   .hit
    inc  ebx
    jmp  .loop
.hit:
    mov  eax, ebx
    jmp  .out
.miss:
    mov  eax, -1
.out:
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; First line: `form <name> spec=v1` exactly.
form_parse_header:
    push rbx
    push r12
    push r13
    mov  r12, rdi                       ; `form`
    call wgt_tok_split
    mov  rbx, rax                       ; name
    lea  rsi, [rel str_form_kw]
    mov  rdi, r12
    call strcmp
    test rax, rax
    jnz  .bad
    mov  rdi, rbx
    call wgt_tok_split
    mov  r13, rax                       ; spec token
    mov  rdi, rbx
    mov  rsi, [rel form_expected_name]
    call strcmp
    test rax, rax
    jnz  .bad
    mov  rdi, r13
    call wgt_tok_split
    cmp  byte [rax], 0                  ; no fourth token
    jne  .bad
    mov  rdi, r13
    lea  rsi, [rel str_spec_v1]
    call strcmp
    test rax, rax
    jnz  .bad
    xor  eax, eax
    jmp  .out
.bad:
    mov  dword [rel form_error], FORM_ERR_SYNTAX
    mov  eax, 1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Window line parser. All required keys must appear; unknown keys refuse.
form_parse_window:
    push rbx
    push r12
    push r13
    xor  r13d, r13d
    call wgt_tok_split
    mov  r12, rax
    lea  rsi, [rel str_window_kw]
    call strcmp
    test rax, rax
    jnz  .bad
.next:
    cmp  byte [r12], 0
    je   .finish
    mov  rdi, r12
    call wgt_tok_split
    mov  rbx, r12
    mov  r12, rax
    mov  rdi, rbx
    lea  rsi, [rel key_title]
    call form_key_value
    test rax, rax
    jnz  .title
    mov  rdi, rbx
    lea  rsi, [rel key_w]
    call form_key_value
    test rax, rax
    jnz  .width
    mov  rdi, rbx
    lea  rsi, [rel key_h]
    call form_key_value
    test rax, rax
    jnz  .height
    mov  rdi, rbx
    lea  rsi, [rel key_x]
    call form_key_value
    test rax, rax
    jnz  .x
    mov  rdi, rbx
    lea  rsi, [rel key_y]
    call form_key_value
    test rax, rax
    jnz  .y
    mov  rdi, rbx
    lea  rsi, [rel key_resizable]
    call form_key_value
    test rax, rax
    jnz  .resizable
    mov  rdi, rbx
    lea  rsi, [rel key_min_w]
    call form_key_value
    test rax, rax
    jnz  .minw
    mov  rdi, rbx
    lea  rsi, [rel key_min_h]
    call form_key_value
    test rax, rax
    jnz  .minh
    mov  rdi, rbx
    lea  rsi, [rel key_chrome]
    call form_key_value
    test rax, rax
    jnz  .chrome
    mov  rdi, rbx
    lea  rsi, [rel key_restore]
    call form_key_value
    test rax, rax
    jnz  .restore
    jmp  .unknown
.title:
    cmp  byte [rax], 0
    je   .bad
    mov  [rel form_win_title], rax
    or   r13d, 1
    jmp  .next
.width:
    call form_parse_u32
    jc   .bad
    mov  [rel form_win_w], eax
    or   r13d, 2
    jmp  .next
.height:
    call form_parse_u32
    jc   .bad
    mov  [rel form_win_h], eax
    or   r13d, 4
    jmp  .next
.x:
    call form_parse_u32
    jc   .bad
    mov  [rel form_win_x], eax
    or   r13d, 8
    jmp  .next
.y:
    call form_parse_u32
    jc   .bad
    mov  [rel form_win_y], eax
    or   r13d, 16
    jmp  .next
.resizable:
    call form_parse_u32
    jc   .bad
    cmp  eax, 1
    ja   .bad
    mov  [rel form_win_resizable], eax
    or   r13d, 32
    jmp  .next
.minw:
    call form_parse_u32
    jc   .bad
    mov  [rel form_win_min_w], eax
    or   r13d, 64
    jmp  .next
.minh:
    call form_parse_u32
    jc   .bad
    mov  [rel form_win_min_h], eax
    or   r13d, 128
    jmp  .next
.chrome:
    mov  byte [rel form_win_chrome], 0
    push rax                            ; rbx is the line cursor: keep it
    mov  rdi, rax
    lea  rsi, [rel val_standard]
    call strcmp
    test rax, rax
    pop  rdi
    jz   .chrome_ok
    ; D2 (PETER RULING 2026-09-29): chrome=tabs — the app draws its tab strip
    ; into the title band; the WM keeps frame, caption buttons and drag.
    lea  rsi, [rel val_chrome_tabs]
    call strcmp
    test rax, rax
    jnz  .bad
    mov  byte [rel form_win_chrome], 1
.chrome_ok:
    or   r13d, 256
    jmp  .next
.restore:
    mov  rdi, rax
    lea  rsi, [rel val_always]
    call strcmp
    test rax, rax
    jz   .rest_always
    mov  rdi, rbx
    lea  rsi, [rel key_restore]
    call form_key_value
    mov  rdi, rax
    lea  rsi, [rel val_fresh]
    call strcmp
    test rax, rax
    jz   .rest_fresh
    mov  rdi, rbx
    lea  rsi, [rel key_restore]
    call form_key_value
    mov  rdi, rax
    lea  rsi, [rel val_never]
    call strcmp
    test rax, rax
    jnz  .bad
    mov  byte [rel form_win_restore], WM_RESTORE_NEVER
    jmp  .rest_ok
.rest_always:
    mov  byte [rel form_win_restore], WM_RESTORE_ALWAYS
    jmp  .rest_ok
.rest_fresh:
    mov  byte [rel form_win_restore], WM_RESTORE_FRESH
.rest_ok:
    or   r13d, 512
    jmp  .next
.finish:
    cmp  r13d, 1023
    jne  .bad
    ; Lint the dimensions actually handed to the WM, before its clamp can
    ; turn a nominally contained ordinary child into an escaped rectangle.
    cmp  dword [rel form_win_w], WMX_MIN_W
    jb   .bad
    cmp  dword [rel form_win_w], 65535
    ja   .bad
    cmp  dword [rel form_win_h], WMX_MIN_H
    jb   .bad
    cmp  dword [rel form_win_h], 65535
    ja   .bad
    xor  eax, eax
    jmp  .out
.unknown:
    mov  dword [rel form_error], FORM_ERR_UNKNOWN_KEY
    mov  eax, 1
    jmp  .out
.bad:
    mov  dword [rel form_error], FORM_ERR_SYNTAX
    mov  eax, 1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=previously declared id, ESI=required vtable type -> EAX=ordinal or -1.
; Dropdown overlay references are linted before allocation, like parent ids.
form_lint_find_typed_id:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13d, esi
    xor  ebx, ebx
.loop:
    cmp  ebx, [rel form_lint_seen_count]
    jae  .miss
    mov  eax, ebx
    imul rax, rax, FORM_NODE_ID_MAX
    lea  rdi, [rel form_lint_ids]
    add  rdi, rax
    mov  rsi, r12
    call strcmp
    test eax, eax
    jnz  .next
    lea  rax, [rel form_lint_types]
    cmp  [rax + rbx*4], r13d
    jne  .miss
    mov  eax, ebx
    jmp  .out
.next:
    inc  ebx
    jmp  .loop
.miss:
    mov  eax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=comma-delimited inline options -> EAX=1..LV_OPTIONS_MAX, or zero.
form_dropdown_option_count:
    xor  eax, eax
    xor  ecx, ecx
.scan:
    mov  dl, [rdi]
    test dl, dl
    jz   .end
    cmp  dl, ','
    je   .comma
    inc  ecx
    inc  rdi
    jmp  .scan
.comma:
    test ecx, ecx
    jz   .bad
    inc  eax
    cmp  eax, LV_OPTIONS_MAX
    jae  .bad
    xor  ecx, ecx
    inc  rdi
    jmp  .scan
.end:
    test ecx, ecx
    jz   .bad
    inc  eax
    cmp  eax, LV_OPTIONS_MAX
    jbe  .out
.bad:
    xor  eax, eax
.out:
    ret

; Widget line parser. It builds one scratch plan and either only validates it
; (pass 0) or allocates it (pass 1).
form_parse_widget:
    push rbx
    push r12
    push r13
    push r15
    mov  dword [rel form_w_type], -1
    mov  qword [rel form_w_id], 0
    mov  qword [rel form_w_parent], 0
    mov  qword [rel form_w_text], 0
    mov  qword [rel form_w_role], 0
    mov  qword [rel form_w_click], 0
    mov  dword [rel form_w_bind], FORM_BIND_NONE
    mov  dword [rel form_w_scroll], 0
    mov  qword [rel form_w_value], 0
    mov  qword [rel form_w_min], 0
    mov  qword [rel form_w_max], 100
    mov  qword [rel form_w_step], 1
    mov  qword [rel form_w_src], 0
    mov  dword [rel form_w_fit], -1
    mov  dword [rel form_w_progress], 0 ; packed mode + indeterminate + key-present
    mov  qword [rel form_w_cadence], 10
    mov  qword [rel form_w_job], 0
    mov  qword [rel form_w_rows], 0
    mov  dword [rel form_w_layer], 0
    mov  dword [rel form_w_list_mode], 0
    mov  dword [rel form_w_chart_mode], 0 ; zero=default sparkline, else mode+1
    mov  qword [rel form_w_overlay], 0
    mov  qword [rel form_w_parents], 0
    mov  qword [rel form_w_parents_packed], 0
    mov  qword [rel form_w_expanded], 0
    mov  qword [rel form_w_disabled], 0
    mov  dword [rel form_w_list_flags], 0
    xor  r13d, r13d
    call wgt_tok_split
    mov  r12, rax
    lea  rsi, [rel str_widget_kw]
    call strcmp
    test rax, rax
    jnz  .bad
.next:
    cmp  byte [r12], 0
    je   .finish
    mov  rdi, r12
    call wgt_tok_split
    mov  rbx, r12
    mov  r12, rax
%macro WKEY 2
    mov  rdi, rbx
    lea  rsi, [rel %1]
    call form_key_value
    test rax, rax
    jnz  %2
%endmacro
    WKEY key_type, .type
    WKEY key_id, .id
    WKEY key_parent, .parent
    WKEY key_x, .x
    WKEY key_y, .y
    WKEY key_w, .width
    WKEY key_h, .height
    WKEY key_text, .text
    WKEY key_role, .role
    WKEY key_on_click, .on_click       ; bounded data event, never a verb
    WKEY key_bind, .bind
    WKEY key_cadence, .cadence
    WKEY key_scroll, .scroll
    WKEY key_value, .value
    WKEY key_min, .min
    WKEY key_max, .max
    WKEY key_step, .step
    WKEY key_src, .src
    WKEY key_fit, .fit
    WKEY str_pg_text_mode, .progress_text
    WKEY str_pg_indeterminate, .progress_indeterminate
    WKEY str_pg_job, .progress_job
    WKEY key_grid_rows, .grid_rows
    WKEY key_grid_cols, .grid_cols
    WKEY key_overlay_layer, .overlay_layer
    WKEY key_mode, .list_mode
    WKEY key_overlay, .list_overlay
    WKEY key_parents, .list_parents
    WKEY key_expanded, .list_expanded
    WKEY key_disabled, .list_disabled
    jmp  .unknown
.list_mode:
    mov  rdi, rax
    lea  rsi, [rel val_dropdown]
    call strcmp
    test eax, eax
    jz   .list_mode_dropdown
    mov  rdi, rbx
    lea  rsi, [rel key_mode]
    call form_key_value
    mov  rdi, rax
    lea  rsi, [rel val_tree]
    call strcmp
    test eax, eax
    jz   .list_mode_tree
    mov  rdi, rbx
    lea  rsi, [rel key_mode]
    call form_key_value
    mov  rdi, rax
    lea  rsi, [rel val_radio]
    call strcmp
    test eax, eax
    jz   .list_mode_radio
    mov  rdi, rbx
    lea  rsi, [rel key_mode]
    call form_key_value
    mov  rdi, rax
    lea  rsi, [rel str_chart_sparkline]
    call strcmp
    test eax, eax
    jz   .chart_mode_sparkline
    mov  rdi, rbx
    lea  rsi, [rel key_mode]
    call form_key_value
    mov  rdi, rax
    lea  rsi, [rel str_chart_bar]
    call strcmp
    test eax, eax
    jnz  .unknown
    mov  dword [rel form_w_chart_mode], CHART_MODE_BAR+1
    jmp  .next
.chart_mode_sparkline:
    mov  dword [rel form_w_chart_mode], CHART_MODE_SPARKLINE+1
    jmp  .next
.list_mode_radio:
    mov  dword [rel form_w_list_mode], LV_MODE_RADIO
    jmp  .next
.list_mode_tree:
    mov  dword [rel form_w_list_mode], LV_MODE_TREE
    jmp  .next
.list_mode_dropdown:
    mov  dword [rel form_w_list_mode], LV_MODE_DROPDOWN
    jmp  .next
.list_overlay:
    cmp  byte [rax], 0
    je   .bad
    mov  [rel form_w_overlay], rax
    jmp  .next
.list_parents:
    cmp  byte [rax], 0
    je   .bad
    mov  [rel form_w_parents], rax
    or   dword [rel form_w_list_flags], 1
    jmp  .next
.list_expanded:
    call form_parse_u32
    jc   .bad
    mov  [rel form_w_expanded], rax
    or   dword [rel form_w_list_flags], 2
    jmp  .next
.list_disabled:
    call form_parse_u32
    jc   .bad
    mov  [rel form_w_disabled], rax
    or   dword [rel form_w_list_flags], 4
    jmp  .next
.grid_rows:
    call form_parse_u32
    jc   .bad
    test eax, eax
    jz   .bad
    cmp  eax, 8
    ja   .bad
    mov  [rel form_w_rows], eax
    jmp  .next
.grid_cols:
    call form_parse_u32
    jc   .bad
    test eax, eax
    jz   .bad
    cmp  eax, 8
    ja   .bad
    mov  [rel form_w_cols], eax
    jmp  .next
.overlay_layer:
    call form_parse_u32
    jc   .bad
    cmp  eax, 1
    jne  .bad
    mov  [rel form_w_layer], eax
    jmp  .next
.type:
    mov  rdi, rax
    call form_widget_type_lookup
    cmp  eax, -1
    je   .unknown_widget
    mov  [rel form_w_type], eax
    or   r13d, 1
    jmp  .next
.id:
    cmp  byte [rax], 0
    je   .bad
    mov  [rel form_w_id], rax
    or   r13d, 2
    jmp  .next
.parent:
    mov  [rel form_w_parent], rax
    jmp  .next
.x:
    call form_parse_u32
    jc   .bad
    mov  [rel form_w_x], eax
    or   r13d, 4
    jmp  .next
.y:
    call form_parse_u32
    jc   .bad
    mov  [rel form_w_y], eax
    or   r13d, 8
    jmp  .next
.width:
    call form_parse_u32
    jc   .bad
    mov  [rel form_w_w], eax
    or   r13d, 16
    jmp  .next
.height:
    call form_parse_u32
    jc   .bad
    mov  [rel form_w_h], eax
    or   r13d, 32
    jmp  .next
.text:
    mov  [rel form_w_text], rax
    or   r13d, 64
    jmp  .next
.role:
    cmp  byte [rax], 0
    je   .bad
    mov  [rel form_w_role], rax
    or   r13d, 128
    jmp  .next
.on_click:
    cmp  qword [rel form_w_click], 0
    jne  .bad
    mov  [rel form_w_click], rax
    mov  rdi, rax
    call form_events_name_valid
    test eax, eax
    jnz  .bad
    jmp  .next
.bind:
    mov  rdi, rax
    lea  rsi, [rel val_bind_sysprops]
    call strcmp
    test rax, rax
    jz   .bind_sysprops
%if !PAOS_PUBLIC_BUILD
    mov  rdi, rbx
    lea  rsi, [rel key_bind]
    call form_key_value
    mov  rsi, rax
    mov  edi, 4
    call pmod_netmon_query
    test r8d, r8d
    jz   .bind_fs
    cmp  r8d, FORM_BIND_NETMON
    jb   .bad
    cmp  r8d, FORM_BIND_TX_RATE
    ja   .bad
    mov  [rel form_w_bind], r8d
    jmp  .next
%endif
.bind_fs:
    ; explorer (desktop bring-up 2026-09-07): fs.root / fs.status live rows
    mov  rdi, rbx
    lea  rsi, [rel key_bind]
    call form_key_value
    mov  rdi, rax
    lea  rsi, [rel val_bind_fsroot]
    call strcmp
    test rax, rax
    jz   .bind_fsroot
    mov  rdi, rbx
    lea  rsi, [rel key_bind]
    call form_key_value
    mov  rdi, rax
    lea  rsi, [rel val_bind_fsstatus]
    call strcmp
    test rax, rax
    jnz  .bind_fsdrives
    mov  dword [rel form_w_bind], FORM_BIND_FS_STATUS
    jmp  .next
.bind_fsroot:
    mov  dword [rel form_w_bind], FORM_BIND_FS_ROOT
    jmp  .next
.bind_fsdrives:
    mov  rdi, rbx
    lea  rsi, [rel key_bind]
    call form_key_value
    mov  rdi, rax
    lea  rsi, [rel val_bind_fsdrives]
    call strcmp
    test rax, rax
    jnz  .bind_fsdetails
    mov  dword [rel form_w_bind], FORM_BIND_FS_DRIVES
    jmp  .next
.bind_fsdetails:
    mov  rdi, rbx
    lea  rsi, [rel key_bind]
    call form_key_value
    mov  rdi, rax
    lea  rsi, [rel val_bind_fsdetails]
    call strcmp
    test rax, rax
    jnz  .bind_fscontext
    mov  dword [rel form_w_bind], FORM_BIND_FS_DETAILS
    jmp  .next
.bind_fscontext:
    mov  rdi, rbx
    lea  rsi, [rel key_bind]
    call form_key_value
    mov  rdi, rax
    lea  rsi, [rel val_bind_fscontext]
    call strcmp
    test rax, rax
    jnz  .bind_summon
    mov  dword [rel form_w_bind], FORM_BIND_FS_CONTEXT
    jmp  .next
.bind_summon:
    mov  rdi, rbx
    lea  rsi, [rel key_bind]
    call form_key_value
    mov  rdi, rax
    lea  rsi, [rel val_bind_netmembers]
    call strcmp
    test rax, rax
    jnz  .bind_netaddress
    mov  dword [rel form_w_bind], FORM_BIND_NET_MEMBERS   ; RCQ-35: keep-owned rows
    jmp  .next
.bind_netaddress:
    mov  rdi, rbx
    lea  rsi, [rel key_bind]
    call form_key_value
    mov  rdi, rax
    lea  rsi, [rel val_bind_netaddress]
    call strcmp
    test rax, rax
    jnz  .bind_summon_names
    mov  dword [rel form_w_bind], FORM_BIND_NET_ADDRESS
    jmp  .next
.bind_summon_names:
    mov  rdi, rbx
    lea  rsi, [rel key_bind]
    call form_key_value
    mov  rdi, rax
    lea  rsi, [rel val_bind_summon_pinned]
    call strcmp
    test rax, rax
    jz   .bind_summon_pinned
    mov  rdi, rbx
    lea  rsi, [rel key_bind]
    call form_key_value
    mov  rdi, rax
    lea  rsi, [rel val_bind_summon_recents]
    call strcmp
    test rax, rax
    jz   .bind_summon_recents
    mov  rdi, rbx
    lea  rsi, [rel key_bind]
    call form_key_value
    mov  rdi, rax
    lea  rsi, [rel val_bind_summon_results]
    call strcmp
    test rax, rax
    jnz  .bad
    mov  dword [rel form_w_bind], FORM_BIND_SUMMON_RESULTS
    jmp  .next
.bind_summon_pinned:
    mov  dword [rel form_w_bind], FORM_BIND_SUMMON_PINNED
    jmp  .next
.bind_summon_recents:
    mov  dword [rel form_w_bind], FORM_BIND_SUMMON_RECENTS
    jmp  .next
.bind_sysprops:
    mov  dword [rel form_w_bind], FORM_BIND_SYSPROPS
    jmp  .next
.cadence:
    mov  rdi, rax
    call wgt_progress_parse_num
    jc   .bad
    test eax, eax
    jz   .bad
    mov  [rel form_w_cadence], rax
    jmp  .next
.progress_text:
    mov  rdi, rax
    call wgt_progress_text_mode
    jc   .bad
    mov  [rel form_w_progress], al
    or   dword [rel form_w_progress], 0x10000
    jmp  .next
.progress_indeterminate:
    mov  rdi, rax
    call wgt_progress_parse_num
    jc   .bad
    cmp  rax, 1
    ja   .bad
    mov  [rel form_w_progress + 1], al
    or   dword [rel form_w_progress], 0x10000
    jmp  .next
.progress_job:
    mov  rdi, rax
    call wgt_progress_parse_num
    jc   .bad
    mov  [rel form_w_job], rax
    or   dword [rel form_w_progress], 0x10000
    jmp  .next
.scroll:
    call form_parse_u32
    jc   .bad
    mov  [rel form_w_scroll], eax
    jmp  .next
.value:
    call form_parse_u32
    jc   .bad
    mov  [rel form_w_value], rax
    jmp  .next
.min:
    call form_parse_u32
    jc   .bad
    mov  [rel form_w_min], rax
    jmp  .next
.max:
    call form_parse_u32
    jc   .bad
    test rax, rax
    jz   .bad
    mov  [rel form_w_max], rax
    jmp  .next
.step:
    call form_parse_u32
    jc   .bad
    test rax, rax
    jz   .bad
    mov  [rel form_w_step], rax
    jmp  .next
.src:
    cmp  byte [rax], 0
    je   .bad
    mov  rdi, rax
    call img_asset_find
    test rax, rax
    jz   .unknown_asset
    mov  [rel form_w_src], rax
    or   r13d, 256
    jmp  .next
.fit:
    mov  r15, rax
    mov  rdi, r15
    lea  rsi, [rel str_wimg_fit_none]
    call strcmp
    test rax, rax
    jz   .fit_none
    mov  rdi, r15
    lea  rsi, [rel str_wimg_fit_center]
    call strcmp
    test rax, rax
    jz   .fit_center
    mov  rdi, r15
    lea  rsi, [rel str_wimg_fit_scale]
    call strcmp
    test rax, rax
    jnz  .bad
    mov  dword [rel form_w_fit], WIMG_FIT_SCALE
    jmp  .fit_ok
.fit_center:
    mov  dword [rel form_w_fit], WIMG_FIT_CENTER
    jmp  .fit_ok
.fit_none:
    mov  dword [rel form_w_fit], WIMG_FIT_NONE
.fit_ok:
    or   r13d, 512
    jmp  .next
.finish:
    cmp  qword [rel form_w_click], 0
    je   .event_checked
    cmp  dword [rel form_w_type], WGT_TYPE_BUTTON-1
    jne  .bad
.event_checked:
    mov  eax, [rel form_w_type]
    cmp  eax, 3                       ; the one registered listview type
    je   .list_mode_check
    cmp  dword [rel form_w_list_mode], 0
    jne  .unknown
    cmp  qword [rel form_w_overlay], 0
    jne  .unknown
    cmp  dword [rel form_w_list_flags], 0
    jne  .unknown
    cmp  eax, [rel wgt_chart_type]
    je   .chart_mode_check
    cmp  dword [rel form_w_chart_mode], 0
    jne  .unknown
    jmp  .progress_gate
.chart_mode_check:
    ; Sparkline is the default. A chart-specific mode is valid only on chart.
    cmp  dword [rel form_w_chart_mode], CHART_MODE_BAR+1
    ja   .unknown
    jmp  .progress_gate
.list_mode_check:
    cmp  dword [rel form_w_chart_mode], 0
    jne  .unknown
    cmp  dword [rel form_w_list_mode], 0
    je   .list_plain
    cmp  dword [rel form_w_list_mode], LV_MODE_DROPDOWN
    je   .list_dropdown
    cmp  dword [rel form_w_list_mode], LV_MODE_TREE
    je   .list_tree
    cmp  dword [rel form_w_list_mode], LV_MODE_RADIO
    je   .list_radio
    jmp  .unknown
.list_plain:
    cmp  qword [rel form_w_overlay], 0
    jne  .unknown
    cmp  dword [rel form_w_list_flags], 0
    jne  .unknown
    jmp  .progress_gate
.list_dropdown:
    cmp  qword [rel form_w_overlay], 0
    je   .bad
    cmp  dword [rel form_w_list_flags], 0
    jne  .unknown
    mov  rdi, [rel form_w_text]
    test rdi, rdi
    jz   .bad
    call form_dropdown_option_count
    test eax, eax
    jz   .bad
    cmp  [rel form_w_value], rax
    jae  .bad
    jmp  .progress_gate
.list_tree:
    cmp  qword [rel form_w_overlay], 0
    jne  .unknown
    mov  eax, [rel form_w_list_flags]
    test eax, 1
    jz   .bad
    test eax, 4
    jnz  .unknown
    mov  rdi, [rel form_w_text]
    test rdi, rdi
    jz   .bad
    call form_dropdown_option_count
    test eax, eax
    jz   .bad
    cmp  eax, LV_TREE_OPTIONS_MAX
    ja   .bad
    mov  r15d, eax
    cmp  [rel form_w_value], rax
    jae  .bad
    mov  edi, eax
    mov  rsi, [rel form_w_parents]
    call wgt_listview_parse_parents
    jc   .bad
    mov  [rel form_w_parents_packed], rax
    mov  ecx, r15d
    mov  rax, [rel form_w_expanded]
    shr  rax, cl
    test rax, rax
    jnz  .bad
    jmp  .progress_gate
.list_radio:
    cmp  qword [rel form_w_overlay], 0
    jne  .unknown
    mov  eax, [rel form_w_list_flags]
    test eax, 3
    jnz  .unknown
    mov  rdi, [rel form_w_text]
    test rdi, rdi
    jz   .bad
    call form_dropdown_option_count
    test eax, eax
    jz   .bad
    mov  r15d, eax
    cmp  [rel form_w_value], rax
    jae  .bad
    mov  ecx, r15d
    mov  rax, [rel form_w_disabled]
    shr  rax, cl
    test rax, rax
    jnz  .bad
    mov  rcx, [rel form_w_value]
    mov  rax, [rel form_w_disabled]
    bt   rax, rcx
    jc   .bad
.progress_gate:
    mov  eax, [rel form_w_type]
    cmp  eax, PG_TYPE-1
    je   .progress_check
    cmp  dword [rel form_w_progress], 0
    jne  .unknown                    ; additive keys belong only to progress
    jmp  .type_check
.progress_check:
    cmp  qword [rel form_w_cadence], 10
    ja   .bad
    test r13d, 256|512               ; src/fit are image parameters
    jnz  .unknown
    cmp  byte [rel form_w_progress + 1], 0
    je   .type_check
    call wgt_progress_can_arm
    test eax, eax
    jnz  .capacity
    mov  eax, [rel form_w_type]
.type_check:
    cmp  eax, [rel image_type_id]
    jne  .ordinary_required
    mov  eax, r13d
    and  eax, 0x33F                    ; type/id/x/y/w/h + src + fit
    cmp  eax, 0x33F
    jne  .bad
    cmp  qword [rel form_w_role], 0
    jne  .required_ok
    lea  rax, [rel str_wt_image]
    mov  [rel form_w_role], rax
    jmp  .required_ok
.ordinary_required:
    mov  eax, [rel form_w_type]
    cmp  eax, [rel wgt_secret_type]
    jne  .ordinary_fields
    mov  rax, [rel form_w_text]
    test rax, rax
    jz   .empty_secret
    cmp  byte [rax], 0
    jne  .bad                          ; no declaration may contain a secret value
.empty_secret:
    or   r13d, 64                      ; secret text is absent/empty by construction
.ordinary_fields:
    cmp  r13d, 255
    jne  .bad
    mov  rax, [rel form_w_min]
    cmp  rax, [rel form_w_max]
    ja   .bad
    mov  rax, [rel form_w_value]
    cmp  rax, [rel form_w_min]
    jb   .bad
    cmp  rax, [rel form_w_max]
    ja   .bad
.required_ok:
    mov  eax, [rel form_w_type]
    cmp  eax, [rel wgt_grid_type]
    je   .grid_required
    cmp  qword [rel form_w_rows], 0
    jne  .bad
    jmp  .overlay_required
.grid_required:
    mov  edi, [rel form_w_w]
    mov  esi, [rel form_w_h]
    mov  edx, [rel form_w_rows]
    mov  ecx, [rel form_w_cols]
    xor  r8d, r8d
    call wgt_grid_cell
    jc   .bad
.overlay_required:
    mov  eax, [rel form_w_type]
    cmp  eax, [rel wgt_overlay_type]
    jne  .ordinary_layer
    cmp  dword [rel form_w_layer], 1
    jne  .bad
    cmp  qword [rel form_w_parent], 0 ; only explicit top-level overlay envelopes
    jne  .bad
    jmp  .layer_checked
.ordinary_layer:
    cmp  dword [rel form_w_layer], 0
    jne  .bad
.layer_checked:
    cmp  dword [rel form_w_list_mode], LV_MODE_DROPDOWN
    jne  .list_ref_checked
    cmp  byte [rel form_parse_mode], 0
    jne  .list_ref_checked
    mov  rdi, [rel form_w_overlay]
    mov  esi, [rel wgt_overlay_type]
    call form_lint_find_typed_id
    cmp  eax, -1
    je   .bad
.list_ref_checked:
    cmp  byte [rel form_parse_mode], 0
    jne  .tracked
    call form_lint_track_id
    test eax, eax
    jnz  .bad
.tracked:
    inc  dword [rel form_plan_widgets]
    cmp  byte [rel form_parse_mode], 1
    jne  .ok
    call form_allocate_widget
    test eax, eax
    jnz  .bad
.ok:
    xor  eax, eax
    jmp  .out
.unknown_widget:
    mov  dword [rel form_error], FORM_ERR_UNKNOWN_WIDGET
    mov  eax, 1
    jmp  .out
.capacity:
    mov  dword [rel form_error], FORM_ERR_CAPACITY
    mov  eax, 1
    jmp  .out
.unknown_asset:
    mov  dword [rel form_error], FORM_ERR_UNKNOWN_ASSET
    mov  eax, 1
    jmp  .out
.unknown:
    mov  dword [rel form_error], FORM_ERR_UNKNOWN_KEY
    mov  eax, 1
    jmp  .out
.bad:
    cmp  dword [rel form_error], FORM_ERR_NONE
    jne  .already
    mov  dword [rel form_error], FORM_ERR_SYNTAX
.already:
    mov  eax, 1
.out:
%undef WKEY
    pop  r15
    pop  r13
    pop  r12
    pop  rbx
    ret

form_parse_blob:
    push rbx
    push r12
    push r13
    lea  r12, [rel form_parse_buf]
    xor  r13d, r13d
.line:
    cmp  byte [r12], 0
    je   .finish
    mov  rbx, r12
.seek:
    mov  al, [r12]
    test al, al
    jz   .have
    cmp  al, 10
    je   .split
    inc  r12
    jmp  .seek
.split:
    mov  byte [r12], 0
    inc  r12
.have:
    mov  rdi, rbx
    test r13d, r13d
    jz   .header
    cmp  r13d, 1
    je   .window
    call form_parse_widget
    jmp  .checked
.header:
    call form_parse_header
    jmp  .checked
.window:
    call form_parse_window
.checked:
    test eax, eax
    jnz  .bad
    inc  r13d
    jmp  .line
.finish:
    cmp  r13d, 3
    jb   .bad_syntax
    xor  eax, eax
    jmp  .out
.bad_syntax:
    mov  dword [rel form_error], FORM_ERR_SYNTAX
.bad:
    mov  eax, 1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=blob, RSI=len, RDX=declared name.  This is the single lint-before-
; allocate entry used by both the baked registry and ephemeral ingestion.
form_lint_blob:
    push rbx
    push r12
    push r13
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rdx
    mov  dword [rel form_error], FORM_ERR_NONE
    mov  dword [rel form_plan_widgets], 0
    mov  dword [rel form_lint_seen_count], 0
    mov  byte [rel form_parse_mode], 0
    mov  [rel form_expected_name], r13
    mov  rdi, rbx
    mov  rsi, r12
    call form_copy_blob_ptr
    test eax, eax
    jnz  .out
    call form_parse_blob
    test eax, eax
    jnz  .out
    cmp  byte [rel form_lint_defer_capacity], 0
    jne  .ok                           ; B7a: form_load_index checks it where it allocates
    mov  edi, [rel form_plan_widgets]  ; WK-B7B: an interior free run counts, not only the tail
    call wgt_reserve_run
    cmp  eax, -1
    jne  .ok
    mov  dword [rel form_error], FORM_ERR_CAPACITY
    mov  eax, 1
    jmp  .out
.ok:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Optional netmon slot: lint before publishing; close and destroy its widgets
; before releasing the signed member. No embedded fallback owns this slot.

; Bounded generated-catalog lookup for optional late registry members. Plain
; CATALOG and its historical nonce argument retain the widget projection.
; CATALOG find=<exact-name> avoids truncating membership evidence at the UDP cap.
form_catalog_lookup:
    mov rax, [rdi+REQ_ARG]
    test rax, rax
    jz .legacy
    cmp dword [rax], 'find'
    jne .legacy
    cmp byte [rax+4], '='
    jne .legacy
    call cmd_handler_prologue
    push rbx
    push r12
    mov r12, rsi
    lea rdi, [rax+5]
    call command_lookup
    mov ebx, eax
    call form_out_reset
    lea rdi, [rel form_catalog_miss]
    cmp ebx, -1
    je .emit
    lea rdi, [rel form_catalog_hit]
    call form_out_put_str
    mov edi, ebx
    call command_verb_name
    mov rdi, rax
.emit:
    call form_out_put_str
    mov byte [rel form_out_ready], 1
    mov qword [r12+RSP_CODE], 0
    pop r12
    pop rbx
    ret
.legacy:
    jmp cmd_verb_catalog
form_catalog_verb: db "CATALOG",0
form_catalog_hit: db " catalog_match=1 name=",0
form_catalog_miss: db " catalog_match=0",0

form_netmon_bind:
    push r12
    push r13
    mov r12, rdi
    mov r13, rsi
    lea rdx, [rel form_name_netmon]
    call form_lint_blob
    test eax, eax
    jnz .out
    mov [rel forms_table+4*FORM_ENT_SZ+FORM_BLOB_PTR], r12
    mov [rel forms_table+4*FORM_ENT_SZ+FORM_LEN], r13
.out:
    pop r13
    pop r12
    ret

form_netmon_unbind:
    push rbx                           ; WM painter uses RBX as colour scratch
    mov edi, [rel form_active_slot+16]
    cmp edi, -1
    je .clear
    call wmx_close_slot
.clear:
    mov dword [rel form_active_slot+16], -1
    mov qword [rel forms_table+4*FORM_ENT_SZ+FORM_BLOB_PTR], 0
    mov qword [rel forms_table+4*FORM_ENT_SZ+FORM_LEN], 0
    xor eax, eax
    pop rbx
    ret

form_lint_index:
    call form_table_ptr
    mov  rdi, [rax + FORM_BLOB_PTR]
    mov  rsi, [rax + FORM_LEN]
    mov  rdx, [rax + FORM_NAME]
    jmp  form_lint_blob

; Stable bounded token copy. RDI=src RSI=dst EDX=capacity.
form_copy_token:
    xor  ecx, ecx
.cp:
    mov  al, [rdi + rcx]
    test al, al
    jz   .done
    mov  r8d, edx
    dec  r8d
    cmp  ecx, r8d
    jae  .skip
    mov  [rsi + rcx], al
.skip:
    inc  ecx
    jmp  .cp
.done:
    cmp  ecx, edx
    jb   .term
    mov  ecx, edx
    dec  ecx
.term:
    mov  byte [rsi + rcx], 0
    ret

; Lint-pass identity validation. Parent references must resolve to an earlier
; declaration and widget IDs must be unique. This operates only on scratch
; storage, so every identity failure is known before WM/widget allocation.
form_lint_track_id:
    push rbx
    push r12
    push r13
    mov  r12, [rel form_w_id]
    xor  ebx, ebx
.duplicate_loop:
    cmp  ebx, [rel form_lint_seen_count]
    jae  .parent
    mov  eax, ebx
    imul rax, rax, FORM_NODE_ID_MAX
    lea  rdi, [rel form_lint_ids]
    add  rdi, rax
    mov  rsi, r12
    call strcmp
    test rax, rax
    jz   .bad
    inc  ebx
    jmp  .duplicate_loop
.parent:
    mov  r13, [rel form_w_parent]
    test r13, r13
    jz   .add
    xor  ebx, ebx
.parent_loop:
    cmp  ebx, [rel form_lint_seen_count]
    jae  .bad
    mov  eax, ebx
    imul rax, rax, FORM_NODE_ID_MAX
    lea  rdi, [rel form_lint_ids]
    add  rdi, rax
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .parent_found
    inc  ebx
    jmp  .parent_loop
.parent_found:
    lea  rax, [rel form_lint_types]
    mov  eax, [rax + rbx*4]
    cmp  eax, 5                       ; row
    je   .add
    cmp  eax, 6                       ; col
    je   .add
    cmp  eax, 7                       ; status composite
    je   .add
    cmp  eax, [rel wgt_grid_type]
    je   .add
    cmp  eax, [rel wgt_overlay_type]
    jne  .bad
.add:
    ; EBX is the parent ordinal (ignored for top-level nodes). Build the
    ; complete immutable geometry plan before any live allocation or paint.
    call form_layout_plan
    test eax, eax
    jnz  .bad
    mov  ebx, [rel form_lint_seen_count]
    cmp  ebx, FORM_NODE_MAX
    jae  .bad
    mov  eax, ebx
    imul rax, rax, FORM_NODE_ID_MAX
    lea  rsi, [rel form_lint_ids]
    add  rsi, rax
    mov  rdi, r12
    mov  edx, FORM_NODE_ID_MAX
    call form_copy_token
    lea  rax, [rel form_lint_types]
    mov  ecx, [rel form_w_type]
    mov  [rax + rbx*4], ecx
    inc  dword [rel form_lint_seen_count]
    xor  eax, eax
    jmp  .out
.bad:
    mov  dword [rel form_error], FORM_ERR_SYNTAX
    mov  eax, 1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; A 32-byte row mirrors x/y/w/h and rows/cols/cell/layer. Coordinates in
; this scratch plan are host-relative; only allocation adds the live origin.
form_layout_plan:
    push rbx
    push r12
    push r13
    mov  eax, [rel form_lint_seen_count]
    cmp  eax, FORM_NODE_MAX
    jae  .bad
    mov  r12d, eax
    shl  r12d, 5
    lea  rax, [rel form_layouts]
    add  r12, rax
    mov  eax, [rel form_w_type]
    inc  eax
    call wgt_geometry_min
    cmp  [rel form_w_w], r8d
    jb   .bad
    cmp  [rel form_w_h], r11d
    jb   .bad
    mov  eax, [rel form_w_x]
    mov  [r12], eax
    mov  eax, [rel form_w_y]
    mov  [r12 + 4], eax
    mov  eax, [rel form_w_w]
    test eax, eax
    jz   .bad
    cmp  eax, 65535
    ja   .bad
    mov  [r12 + 8], eax
    mov  eax, [rel form_w_h]
    test eax, eax
    jz   .bad
    cmp  eax, 65535
    ja   .bad
    mov  [r12 + 12], eax
    mov  rax, [rel form_w_rows]
    mov  [r12 + 16], rax
    mov  dword [r12 + 24], 0
    mov  eax, [rel form_w_layer]
    mov  [r12 + 28], eax
    mov  eax, [rel form_lint_seen_count]
    lea  rcx, [rel form_layout_children]
    mov  dword [rcx + rax*4], 0
    cmp  qword [rel form_w_parent], 0
    je   .bounds
    mov  r8d, [rcx + rbx*4]
    inc  dword [rcx + rbx*4]
    mov  [r12 + 24], r8d
    mov  r13d, ebx
    shl  r13d, 5
    lea  rax, [rel form_layouts]
    add  r13, rax
    mov  eax, [r13 + 28]
    mov  [r12 + 28], eax
    lea  rax, [rel form_lint_types]
    mov  eax, [rax + rbx*4]
    cmp  eax, [rel wgt_grid_type]
    je   .grid
    cmp  eax, [rel wgt_overlay_type]
    je   .overlay
    cmp  eax, 6
    je   .col
    mov  eax, [r12 + 8]
    add  eax, FORM_SPACING
    imul eax, r8d
    add  eax, FORM_SPACING
    mov  [r12], eax
    mov  dword [r12 + 4], FORM_SPACING
    jmp  .parent_bound
.col:
    mov  eax, [r12 + 12]
    add  eax, FORM_SPACING
    imul eax, r8d
    add  eax, FORM_SPACING
    mov  [r12 + 4], eax
    mov  dword [r12], FORM_SPACING
.parent_bound:
    cmp  dword [r13 + 28], 1
    je   .overlay
    jmp  .relative
.grid:
    mov  edi, [r13 + 8]
    mov  esi, [r13 + 12]
    mov  edx, [r13 + 16]
    mov  ecx, [r13 + 20]
    call wgt_grid_cell
    jc   .bad
    cmp  [r12 + 8], r10d
    ja   .bad
    cmp  [r12 + 12], r11d
    ja   .bad
    mov  [r12], r8d
    mov  [r12 + 4], r9d
.overlay:
    mov  eax, [rel form_w_type]
    inc  eax
    call wgt_geometry_min
    cmp  [r12], r10d
    jb   .bad
    cmp  [r12 + 4], r10d
    jb   .bad
    mov  eax, [r12]
    add  eax, [r12 + 8]
    jc   .bad
    add  eax, r10d
    jc   .bad
    cmp  eax, [r13 + 8]
    ja   .bad
    mov  eax, [r12 + 4]
    add  eax, [r12 + 12]
    jc   .bad
    add  eax, r10d
    jc   .bad
    cmp  eax, [r13 + 12]
    ja   .bad
.relative:
    mov  eax, [r13]
    add  [r12], eax
    jc   .bad
    mov  eax, [r13 + 4]
    add  [r12 + 4], eax
    jc   .bad
.bounds:
    mov  eax, [rel form_w_type]
    inc  eax
    call wgt_geometry_min
    cmp  [r12], r10d
    jb   .bad
    cmp  [r12 + 4], r10d
    jb   .bad
    ; Small unsigned coordinates make every later edge addition safe.
    cmp  dword [r12], 65535
    ja   .bad
    cmp  dword [r12 + 4], 65535
    ja   .bad
    mov  ecx, [rel form_win_w]
    mov  edx, [rel form_win_h]
    cmp  dword [r12 + 28], 1
    jne  .edges
    ; Match form_load_index's initial whole-window clamp (vertically to the work
    ; area above the taskbar, RCQ-38), then constrain the declared overlay
    ; envelope to the framebuffer (taskbar paints above it).
    mov  ecx, [rel fb_width]
    mov  eax, ecx
    sub  eax, [rel form_win_w]
    ja   .x_room
    xor  eax, eax
.x_room:
    cmp  eax, [rel form_win_x]
    cmova eax, [rel form_win_x]
    sub  ecx, eax
    mov  edx, [rel fb_height]
    mov  eax, edx
    sub  eax, TASKBAR_H
    jbe  .y_low
    sub  eax, [rel form_win_h]
    ja   .y_room
.y_low:
    xor  eax, eax
.y_room:
    cmp  eax, [rel form_win_y]
    cmova eax, [rel form_win_y]
    sub  edx, eax
.edges:
    mov  eax, [r12]
    add  eax, [r12 + 8]
    add  eax, r10d
    cmp  eax, ecx
    ja   .bad
    mov  eax, [r12 + 4]
    add  eax, [r12 + 12]
    add  eax, r10d
    cmp  eax, edx
    ja   .bad
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, 1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

form_find_parent:
    push rbx
    push r12
    mov  r12, rdi
    mov  ebx, [rel form_widget_first]
.loop:
    mov  eax, [rel wgt_alloc_next]     ; WK-B7B: only this form's run (it may sit below later live entries);
    cmp  eax, -1                       ; outside a reservation, the historical [first, wgt_count) range
    jne  .bound
    mov  eax, [rel wgt_count]
.bound:
    cmp  ebx, eax
    jae  .miss
    mov  edi, ebx
    call wgt_slot_ptr
    mov  rdi, [rax + WGI_ID]
    test rdi, rdi
    jz   .next
    mov  rsi, r12
    call strcmp
    test rax, rax
    jz   .hit
.next:
    inc  ebx
    jmp  .loop
.hit:
    mov  eax, ebx
    jmp  .out
.miss:
    mov  eax, -1
.out:
    pop  r12
    pop  rbx
    ret

form_allocate_widget:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  edi, [rel form_w_type]
    mov  esi, [rel form_current_win]
    call wgt_create
    cmp  eax, -1
    je   .bad
    mov  r12d, eax
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rbx, rax
    ; Stable widget id storage is indexed by the global widget id.
    mov  eax, r12d
    imul eax, FORM_NODE_ID_MAX
    lea  rsi, [rel form_node_ids]
    add  rsi, rax
    mov  rdi, [rel form_w_id]
    mov  edx, FORM_NODE_ID_MAX
    call form_copy_token
    mov  [rbx + WGI_ID], rsi
    mov  eax, r12d
    imul eax, FORM_NODE_ID_MAX
    lea  rsi, [rel form_node_roles]
    add  rsi, rax
    mov  rdi, [rel form_w_role]
    mov  edx, FORM_NODE_ID_MAX
    call form_copy_token
    mov  [rbx + WGI_ROLE], rsi
    mov  eax, r12d
    imul eax, FORM_NODE_ID_MAX
    lea  rsi, [rel form_node_labels]
    add  rsi, rax
    mov  rdi, [rel form_w_text]
    test rdi, rdi
    jnz  .copy_label
    mov  rdi, [rel form_w_role]
.copy_label:
    mov  edx, FORM_NODE_ID_MAX
    call form_copy_token
    mov  [rbx + WGI_LABEL], rsi
    mov  eax, [rel form_w_w]
    mov  [rbx + WGI_W], eax
    mov  eax, [rel form_w_h]
    mov  [rbx + WGI_H], eax
    mov  eax, [rel form_w_scroll]
    mov  [rbx + WGI_SCROLL], eax
    mov  rax, [rel form_w_value]
    mov  [rbx + WGI_NUM], rax
    mov  rax, [rel form_w_min]
    mov  [rbx + WGI_MINVAL], rax
    mov  rax, [rel form_w_max]
    mov  [rbx + WGI_MAXVAL], rax
    mov  rax, [rel form_w_step]
    mov  [rbx + WGI_STEP], rax
    mov  eax, [rel form_w_bind]
    mov  [rbx + WGI_BIND], eax
    mov  rdi, [rel form_w_text]
    test rdi, rdi
    jz   .geometry
    mov  edi, r12d
    mov  rsi, [rel form_w_text]
    call wgt_set_text
    mov  edi, r12d
    call wgt_mark_formtext              ; declared label/button text: '_' paints as ' '
.geometry:
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rbx, rax
    mov  rdi, [rel form_w_parent]
    test rdi, rdi
    jz   .top
    call form_find_parent
    cmp  eax, -1
    je   .bad
    mov  r13d, eax
    mov  [rbx + WGI_PARENT], eax
.top:
    mov  eax, [rel form_plan_widgets]
    dec  eax
    shl  eax, 5
    lea  r14, [rel form_layouts]
    add  r14, rax
    mov  eax, [rel form_current_win]
    lea  rcx, [rel wm_x]
    mov  edx, [rcx + rax*4]
    add  edx, [r14]
    mov  [rbx + WGI_X], edx
    lea  rcx, [rel wm_y]
    mov  edx, [rcx + rax*4]
    add  edx, [r14 + 4]
    mov  [rbx + WGI_Y], edx
    mov  rax, [r14 + 16]
    mov  [rbx + WGI_ROWS], rax
    mov  rax, [r14 + 24]
    mov  [rbx + WGI_CELL], rax
    mov  eax, [rel form_w_list_mode]
    test eax, eax
    jz   .draw
    cmp  eax, LV_MODE_TREE
    je   .list_tree
    cmp  eax, LV_MODE_RADIO
    je   .list_radio
    cmp  eax, LV_MODE_DROPDOWN
    jne  .bad
    mov  rdi, [rel form_w_overlay]
    call form_find_parent
    cmp  eax, -1
    je   .bad
    mov  r15d, eax
    mov  edi, r15d
    call wgt_slot_ptr
    mov  ecx, [rel wgt_overlay_type]
    inc  ecx
    cmp  [rax + WGI_TYPE], ecx
    jne  .bad
    cmp  dword [rax + WGI_LAYER], 1
    jne  .bad
    mov  ecx, [rax + WGI_WIN]
    cmp  ecx, [rel form_current_win]
    jne  .bad
    mov  edi, r12d
    call wgt_slot_ptr
    mov  ebx, r15d
    inc  ebx
    mov  [rax + LV_OVERLAY], ebx
    mov  byte [rax + LV_MODE], LV_MODE_DROPDOWN
    mov  byte [rax + LV_OPEN], 0
    mov  ebx, [rel form_w_value]
    mov  [rax + WGI_SEL_LO], ebx
    mov  rbx, rax
    jmp  .draw
.list_tree:
    mov  edi, r12d
    call wgt_slot_ptr
    mov  byte [rax + LV_MODE], LV_MODE_TREE
    mov  byte [rax + LV_OPEN], 0
    mov  rdx, [rel form_w_parents_packed]
    mov  [rax + LV_PARENTS], rdx
    mov  rdx, [rel form_w_expanded]
    mov  [rax + LV_EXPANDED], rdx
    mov  qword [rax + LV_DISABLED], 0
    mov  edx, [rel form_w_value]
    mov  [rax + WGI_SEL_LO], edx
    mov  rbx, rax
    jmp  .draw
.list_radio:
    mov  edi, r12d
    call wgt_slot_ptr
    mov  byte [rax + LV_MODE], LV_MODE_RADIO
    mov  byte [rax + LV_OPEN], 0
    mov  qword [rax + LV_PARENTS], 0
    mov  qword [rax + LV_EXPANDED], 0
    mov  rdx, [rel form_w_disabled]
    mov  [rax + LV_DISABLED], rdx
    mov  edx, [rel form_w_value]
    mov  [rax + WGI_SEL_LO], edx
    mov  rbx, rax
.draw:
    mov  eax, [rel form_w_type]
    cmp  eax, [rel wgt_chart_type]
    jne  .progress
    mov  ecx, [rel form_w_chart_mode]
    test ecx, ecx
    jz   .chart_ready
    dec  ecx
    mov  [rbx + CHART_MODE], cl
.chart_ready:
    mov  qword [rbx + CHART_SCALE], 1
    jmp  .draw_now
.progress:
    cmp  eax, PG_TYPE-1
    jne  .image
    mov  eax, [rel form_w_progress]
    and  eax, 0xffff
    mov  [rbx + WGI_RSVD], eax
    mov  eax, [rel form_w_cadence]
    mov  [rbx + PG_HZ], eax
    mov  rax, [rel form_w_job]
    mov  [rbx + PG_JOB], rax
    call wgt_progress_sync
    jmp  .draw_now
.image:
    cmp  eax, [rel image_type_id]
    jne  .draw_now
    mov  edi, r12d
    mov  rsi, [rel form_w_src]
    mov  edx, [rel form_w_fit]
    call widget_image_bind              ; refusal is widget state, never form failure
.draw_now:
    mov  edi, r12d
    mov  rsi, [rel form_w_click]
    call form_events_bind
    mov  edi, r12d
    call wgt_draw_id
    xor  eax, eax
    jmp  .out
.bad:
    mov  dword [rel form_error], FORM_ERR_CAPACITY
    mov  eax, 1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

form_count_window_widgets:
    push rbx
    mov  ebx, edi
    xor  edx, edx
    xor  ecx, ecx
.loop:
    cmp  ecx, [rel wgt_count]
    jae  .done
    mov  edi, ecx
    call wgt_slot_ptr
    cmp  dword [rax + WGI_TYPE], 0
    je   .next
    cmp  [rax + WGI_WIN], ebx
    jne  .next
    inc  edx
.next:
    inc  ecx
    jmp  .loop
.done:
    mov  eax, edx
    pop  rbx
    ret

; A restored FRESH form is intentionally only a window shell: session replay
; cannot retain widget pointers.  Resolve one such shell without weakening the
; normal pool rules.  Exact-title ambiguity, foreign widgets, non-FRESH state,
; or any form already tracking the slot makes the shell non-adoptable.
; Uses form_load_title_ptr; returns EAX=slot or -1.
form_find_adoptable_shell:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, -1                     ; unique exact-title candidate
    xor  r13d, r13d                    ; slot cursor
    xor  r14d, r14d                    ; exact-title count
.scan:
    cmp  r13d, WM_MAX
    jae  .validate
    lea  rax, [rel wm_state]
    mov  eax, [rax + r13*4]
    cmp  eax, WM_VISIBLE
    je   .title
    cmp  eax, WM_MIN
    jne  .next
.title:
    lea  rax, [rel wm_title]
    mov  rdi, [rax + r13*8]
    test rdi, rdi
    jz   .next
    mov  rsi, [rel form_load_title_ptr]
    call strcmp
    test rax, rax
    jnz  .next
    inc  r14d
    mov  r12d, r13d
.next:
    inc  r13d
    jmp  .scan
.validate:
    cmp  r14d, 1
    jne  .miss
    lea  rax, [rel wm_restore_class]
    cmp  byte [rax + r12], WM_RESTORE_FRESH
    jne  .miss
    mov  edi, r12d
    call form_count_window_widgets
    test eax, eax
    jnz  .miss
    xor  ebx, ebx
.owner:
    cmp  ebx, FORM_SLOT_COUNT
    jae  .hit
    lea  rax, [rel form_active_slot]
    cmp  [rax + rbx*4], r12d
    je   .miss
    inc  ebx
    jmp  .owner
.hit:
    mov  eax, r12d
    jmp  .out
.miss:
    mov  eax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; EDI=form index, RSI=title override or 0, EDX=focus request -> EAX status,
; ECX=slot, EDX=widget count.
form_load_index:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, edi
    mov  r13, rsi
    mov  r14d, edx
    cmp  r12d, FORM_EXPLORER_INDEX
    jne  .copy_lifetime_ready
    call form_explorer_cancel_reset
.copy_lifetime_ready:
    mov  edi, r12d                    ; lifetime cleanup cannot change form identity
    call form_focus_request_gate
    mov  [rel form_last_index], edi
    cmp  r12d, FORM_SUMMON_INDEX
    jne  .ordinary_form
    mov  edi, r12d
    call form_lint_index
    test eax, eax
    jnz  .fail
    mov  rax, [rel form_summon_gate]    ; RCQ-40 F4 (c): gui/card_surface's gate, 0 = none
    test rax, rax
    jz   .summon_open
    call rax
    test eax, eax
    jz   .summon_open
    mov  dword [rel form_error], FORM_ERR_CARD_SHOWN
    jmp  .fail
.summon_open:
    mov  edi, r14d
    call summon_palette_form_load
    test eax, eax
    jnz  .fail
    mov  ecx, WGT_HOST_DESKTOP
    mov  edx, 7
    jmp  .out
.ordinary_form:
    ; The resident authentication form belongs to the boot/session boundary.
    ; Generic FORMLOAD must not allocate a second copy while it is hidden.
    cmp  r12d, FORM_LOCK_INDEX
    jne  .card_gate
    cmp  byte [rel lock_surface_loading], 1
    jne  .no_slot
.card_gate:
    ; RCQ-40 J2b: the owner action card is PaOS chrome too. No FORMLOAD/LAUNCH
    ; of any principal builds it; only gui/card_surface, in its idle tick.
    cmp  r12d, FORM_CARD_INDEX
    jne  .lint
    cmp  byte [rel form_card_loading], 1
    jne  .no_slot
.lint:
    ; B7a (2026-09-30, usage suite STM-04): the widget-capacity check moves to
    ; .allocate -- relaunching an OPEN form allocates nothing, so it must never
    ; be refused with widget_capacity. Syntax/structure lint still runs first.
    mov  byte [rel form_lint_defer_capacity], 1
    call form_lint_index               ; entire declaration validates first
    mov  byte [rel form_lint_defer_capacity], 0
    test eax, eax
    jnz  .fail
    mov  eax, r12d
    imul eax, FORM_TITLE_MAX
    lea  r15, [rel form_titles]
    add  r15, rax
    mov  rdi, r13
    test rdi, rdi
    jnz  .copy_title
    mov  rdi, [rel form_win_title]
.copy_title:
    mov  rsi, r15
    mov  edx, FORM_TITLE_MAX
    call form_copy_token
    mov  [rel form_load_title_ptr], r15
    ; Idempotent if the tracked slot remains live/minimized.
    lea  rbx, [rel form_active_slot]
    mov  eax, [rbx + r12*4]
    mov  [rel form_prior_active_slot], eax
    cmp  eax, 0
    jl   .allocate
    lea  rcx, [rel wm_state]
    mov  edx, [rcx + rax*4]
    cmp  edx, WM_VISIBLE
    je   .validate_existing
    cmp  edx, WM_MIN
    jne  .stale_active
.validate_existing:
    ; A closed form slot can be reused by WINNEW before this form is launched
    ; again. The numeric slot alone is not a live single-instance identity:
    ; require the form-owned title pointer and at least one surviving widget.
    lea  rcx, [rel wm_title]
    mov  rdx, [rcx + rax*8]
    cmp  rdx, [rel form_load_title_ptr]
    jne  .stale_active
    push rax
    mov  edi, eax
    call form_count_window_widgets
    test eax, eax
    pop  rax
    jz   .stale_active
    jmp  .existing
.stale_active:
    mov  dword [rbx + r12*4], -1
    mov  dword [rel form_prior_active_slot], -1
    jmp  .allocate
.existing:
    mov  [rel form_result_slot], eax
    lea  rdx, [rel wm_title]
    mov  [rdx + rax*8], r15
    mov  edi, eax
    push rax
    call widget_image_rebind_window     ; normal-context repair for an evicted entry
    pop  rax
    mov  edi, eax
    call form_count_window_widgets
    mov  [rel form_result_widgets], eax
    test r14d, r14d
    jnz  .focus_existing
    ; STM-04: a USER relaunch (typed into the console) of an open app focuses
    ; it, like a second Start click; agent FORMLOAD keeps the no-steal rule.
    cmp  byte [rel form_relaunch_focuses], 1
    je   .focus_existing
    lea  rax, [rel wm_attn]
    mov  ecx, [rel form_result_slot]
    mov  byte [rax + rcx], 1
    call wmx_draw_all
    xor  eax, eax
    jmp  .result
.focus_existing:
    mov  edi, [rel form_result_slot]
    call wmx_raise_slot
    xor  eax, eax
    jmp  .result
.allocate:
    ; B7a: the lint-time capacity check, applied only where widgets are allocated.
    ; WK-B7B: a contiguous run anywhere below the tail counts (the run is re-chosen at .materialize).
    mov  edi, [rel form_plan_widgets]
    call wgt_reserve_run
    cmp  eax, -1
    jne  .capacity_ok
    mov  dword [rel form_error], FORM_ERR_CAPACITY
    jmp  .fail
.capacity_ok:
    mov  r15d, [rel wm_focus]
    mov  byte [rel form_adopted_shell], 0
    cmp  qword [rel form_app_owner], 0
    jne  .new_window                   ; app never adopts an OWNER restore shell
    cmp  byte [rel form_card_loading], 1
    je   .new_window                    ; J2b: the card never adopts a window it did not open
    cmp  r12d, FORM_RECOVERY_INDEX
    je   .new_window                    ; an automatic notice cannot consume a restored app shell
    call form_find_adoptable_shell
    cmp  eax, -1
    je   .new_window
    mov  [rel form_current_win], eax
    mov  [rel form_result_slot], eax
    mov  byte [rel form_adopted_shell], 1
    jmp  .materialize
.new_window:
    call wmx_find_free_slot
    cmp  eax, -1
    je   .no_slot
    mov  rdi, [rel form_load_title_ptr]
    ; Form coordinates are logical preferred positions, not permission to hide
    ; the declared surface beyond the active framebuffer.  The generic WM keeps
    ; an 80px title-bar grab handle visible for freely moved windows; a freshly
    ; loaded form instead starts with its whole window visible when it fits.
    ; RCQ-38: vertically that is the work area above the taskbar (window.asm
    ; paints its TASKBAR_H band over every window), so a form that fits there
    ; never opens with controls under the band; a taller one starts at 0.
    mov  esi, [rel form_win_x]
    mov  eax, [rel fb_width]
    cmp  eax, [rel form_win_w]
    jbe  .form_x_zero
    sub  eax, [rel form_win_w]
    cmp  esi, eax
    jbe  .form_x_ready
    mov  esi, eax
    jmp  .form_x_ready
.form_x_zero:
    xor  esi, esi
.form_x_ready:
    mov  edx, [rel form_win_y]
    mov  eax, [rel fb_height]
    sub  eax, TASKBAR_H                 ; the work area's height
    jbe  .form_y_zero
    cmp  eax, [rel form_win_h]
    jbe  .form_y_zero
    sub  eax, [rel form_win_h]
    cmp  edx, eax
    jbe  .form_y_ready
    mov  edx, eax
    jmp  .form_y_ready
.form_y_zero:
    xor  edx, edx
.form_y_ready:
    mov  ecx, [rel form_win_w]
    mov  r8d, [rel form_win_h]
    movzx r9d, byte [rel form_win_restore]
    call wmx_open_window
    cmp  eax, -1
    je   .no_slot
    mov  [rel form_current_win], eax
    movzx ecx, byte [rel form_win_chrome]
    lea  rdx, [rel wm_chrome]
    mov  [rdx + rax], cl
    mov  [rel form_result_slot], eax
.materialize:
    ; Trusted native launcher supplied an enforced app principal. No dispatch,
    ; callback or paint occurs between open and this stamp. The ordinary local
    ; frame principal and focus admission stay unchanged.
    mov  rdx, [rel form_app_owner]
    test rdx, rdx
    jz   .owner_ready
    mov  eax, [rel form_current_win]
    lea  rcx, [rel wm_owner]
    mov  [rcx + rax*8], rdx
    lea  rcx, [rel wm_no_history]
    mov  byte [rcx + rax], 1
.owner_ready:
    cmp byte [rel form_app_staged],1
    jne .stage_ready
    mov eax,[rel form_current_win]
    lea rcx,[rel wm_state]
    mov dword [rcx+rax*4],WM_MIN       ; before reset, widget materialization, paint
.stage_ready:
    mov  edi, [rel form_current_win]
    call form_events_reset
    ; B4 (2026-09-30, usage suite CHR-08): the form's declared resizable/min_w/
    ; min_h become the window's user-resize rules (wm_pointer .drag_resize); the
    ; generic caption-button floor stays the lower bound.
    mov  eax, [rel form_current_win]
    mov  ecx, [rel form_win_min_w]
    cmp  ecx, WMX_USER_MIN_W
    jae  .min_w_ok
    mov  ecx, WMX_USER_MIN_W
.min_w_ok:
    lea  rdx, [rel wm_min_w]
    mov  [rdx + rax*4], ecx
    mov  ecx, [rel form_win_min_h]
    cmp  ecx, WMX_USER_MIN_H
    jae  .min_h_ok
    mov  ecx, WMX_USER_MIN_H
.min_h_ok:
    lea  rdx, [rel wm_min_h]
    mov  [rdx + rax*4], ecx
    mov  ecx, [rel form_win_resizable]
    lea  rdx, [rel wm_resizable]
    mov  [rdx + rax], cl
    ; WK-B7B: reserve the form's contiguous run now (after any window/shell work); wgt_create fills it in order.
    ; The rollback range starts empty, so a refusal right here frees nothing that belongs to another form.
    mov  dword [rel form_widget_first], 0
    mov  dword [rel form_widget_end], 0
    mov  edi, [rel form_plan_widgets]
    call wgt_reserve_run
    cmp  eax, -1
    je   .materialize_fail
    mov  [rel form_widget_first], eax
    mov  [rel wgt_alloc_next], eax
    mov  byte [rel form_parse_mode], 1
    mov  dword [rel form_plan_widgets], 0
    mov  edi, r12d
    call form_table_ptr
    mov  [rel form_current_entry], rax
    mov  edi, r12d
    call form_copy_blob
    inc  byte [rel wgt_paint_suspended]
    call form_parse_blob
    dec  byte [rel wgt_paint_suspended]
    mov  ecx, [rel wgt_alloc_next]
    mov  [rel form_widget_end], ecx    ; WK-B7B: the run actually filled is [form_widget_first, form_widget_end)
    mov  dword [rel wgt_alloc_next], -1
    test eax, eax
    jnz  .materialize_fail
    ; Publish form ownership only after every widget is materialized.  A
    ; restored shell remains byte-for-byte window state until this commit.
    lea  rbx, [rel form_active_slot]
    mov  eax, [rel form_current_win]
    mov  [rbx + r12*4], eax
    cmp  byte [rel form_adopted_shell], 1
    jne  .materialized
    lea  rdx, [rel wm_title]
    mov  rcx, [rel form_load_title_ptr]
    mov  [rdx + rax*8], rcx
.materialized:
    mov  eax, [rel form_plan_widgets]
    mov  [rel form_result_widgets], eax
    cmp  byte [rel form_adopted_shell], 1
    je   .adopted
    call form_fit_work_area             ; RCQ-38: a tall resizable form fits above the taskbar
    cmp byte [rel form_app_staged],1
    jne .stage_draw
    mov [rel wm_focus],r15d
    xor eax,eax
    jmp .result                        ; minimized app has never been painted
.stage_draw:
    test r14d, r14d
    jnz  .focus_new
    ; Restore the prior focus and set attention: agent-open never steals focus.
    mov  [rel wm_focus], r15d
    lea  rax, [rel wm_attn]
    mov  ecx, [rel form_current_win]
    mov  byte [rax + rcx], 1
    cmp  byte [rel form_card_loading], 1
    je   .card_undrawn                  ; J2b P1: the card paints once card_surface stamped and labelled it
    call wmx_draw_all
.card_undrawn:
    xor  eax, eax
    jmp  .result
.adopted:
    ; Default FORMLOAD preserves restored geometry/state/z/focus/attention.
    ; Only an explicit focus=1 request performs the ordinary raise transition.
    test r14d, r14d
    jnz  .focus_new
    call wmx_draw_all
    xor  eax, eax
    jmp  .result
.focus_new:
    mov  ecx, [rel form_current_win]
    mov  [rel wm_focus], ecx
    lea  rax, [rel wm_attn]
    mov  byte [rax + rcx], 0
    call wmx_draw_all
    xor  eax, eax
    jmp  .result
.materialize_fail:
    ; Lint normally makes this unreachable, but keep the adoption transaction
    ; atomic if a later widget allocator gains a runtime refusal.
    ; WK-B7B: free exactly the run this form filled (it may be interior), then the B7a tail shrink.
    mov  dword [rel wgt_alloc_next], -1
    mov  ebx, [rel form_widget_first]  ; RBX is reloaded below; no painter runs inside this loop
.rollback_run:
    cmp  ebx, [rel form_widget_end]
    jae  .rollback_shrink
    cmp  ebx, WGT_MAX
    jae  .rollback_shrink
    mov  edi, ebx
    call wgt_slot_ptr
    mov  dword [rax + WGI_TYPE], 0
    inc  ebx
    jmp  .rollback_run
.rollback_shrink:
    mov  eax, [rel wgt_count]
    test eax, eax
    jz   .rollback_done
    lea  edi, [eax - 1]
    call wgt_slot_ptr
    cmp  dword [rax + WGI_TYPE], 0
    jne  .rollback_done
    dec  dword [rel wgt_count]
    jmp  .rollback_shrink
.rollback_done:
    lea  rbx, [rel form_active_slot]
    mov  eax, [rel form_prior_active_slot]
    mov  [rbx + r12*4], eax
    cmp  byte [rel form_adopted_shell], 1
    je   .fail
    mov  edi, [rel form_current_win]
    call wmx_close_slot
    mov  [rel wm_focus], r15d
    jmp  .fail
.no_slot:
    mov  dword [rel form_error], FORM_ERR_NO_SLOT
.fail:
    mov  eax, 1
    jmp  .out
.result:
    mov  ecx, [rel form_result_slot]
    mov  edx, [rel form_result_widgets]
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; form_fit_work_area: a window form_load_index has just opened and filled, before
; its first paint. RCQ-38 (root 03:45:37): a resizable form taller than the work
; area above the taskbar (fb_height - TASKBAR_H; the open clamp already put it at
; y 0) is fitted to max(min_h, work area) through the user-resize anchoring
; (wgt_resize_window, CHR-08), so its lower rows move up out from under the band.
; A form that fits, a non-resizable one and an adopted shell keep their rect, and
; the anchoring stays reversible: resizing back to the declared size restores the
; declared layout. Clobbers caller-saved registers only.
form_fit_work_area:
    cmp  dword [rel form_win_resizable], 0
    je   .out
    mov  edi, [rel form_current_win]
    lea  rcx, [rel wm_h]
    mov  edx, [rcx + rdi*4]             ; old_h: the declared height it opened at
    mov  eax, [rel fb_height]
    sub  eax, TASKBAR_H                 ; the work area's height
    jbe  .out
    lea  rsi, [rel wm_min_h]
    cmp  eax, [rsi + rdi*4]
    jae  .min_ok
    mov  eax, [rsi + rdi*4]             ; never below the window's min_h
.min_ok:
    cmp  eax, edx
    jae  .out                           ; it fits: the declared rect stands
    mov  [rcx + rdi*4], eax
    lea  rcx, [rel wm_w]
    mov  esi, [rcx + rdi*4]             ; old_w = w: only the height changes
    call wgt_resize_window
.out:
    ret

; R14D=focus request -> R14D=0 unless this frame may take the keyboard
; (RCQ-16 F2b-2, rc-sec 23:50:07: focus=1 is the owner's alone; an agent's form
; opens with attention instead). Clobbers RAX only.
form_focus_request_gate:
    call wmx_frame_may_focus
    test eax, eax
    jz   .out
    xor  r14d, r14d
.out:
    ret

; form_verb_unlocked(RDI=request, RSI=response) -> EAX 0 = the desktop is
; unlocked for this request; else the desktop-lock refusal is staged (CMDE_OK:
; the one registry dispatcher reports CMDE_DESKTOP_LOCKED) and nothing else
; ran. Every FORMLOAD and LAUNCH entry, wrappers included, calls it before it
; reads its argument (RCQ-16 F2b-1, rc-sec 23:50:07). Preserves RDI and RSI.
form_verb_unlocked:
    push rdi
    call session_shell_require_unlocked
    pop  rdi
    test eax, eax
    jz   .out
    call cmd_handler_prologue
    push rdi
    push rsi
    call form_out_reset
    lea  rdi, [rel str_form_locked]
    call form_out_put_str
    pop  rsi
    pop  rdi
    mov  byte [rel form_out_ready], 1
    mov  qword [rsi + RSP_CODE], CMDE_OK
    mov  qword [rsi + RSP_VAL], 0
    mov  eax, -1
.out:
    ret

; Internal boot/demo entry: EDI=index, EDX=focus flag.
form_load_internal:
    xor  esi, esi
    jmp  form_load_index

; Trusted native app entry: RDI=immutable checked blob, RSI=length,
; RDX=stable native name, RCX=actual enforced app principal (> reserved IDs).
; Caller owns verified bundle/VM launch binding and storage until the original
; ephemeral closer/reaper finishes. This is not a command or a proof validator.
; Never projects a guest into the local OWNER frame. One shared ephemeral slot;
; busy/refusal does not replace it. No focus request, restoration or history.
; Same enforced-owner path, initially ordinary WM_MIN before widgets/paint.
; No hidden-window state or widget flag. Native lifecycle raises it after WAIT.
form_load_app_staged_blob:
    mov r8d,1
    jmp form_load_app_blob_entry
form_load_app_blob:
    xor r8d,r8d
    jmp form_load_app_blob_entry
form_load_app_blob_entry:
    push r15
    mov r15d,r8d
    push rbx
    push r12
    push r13
    push r14
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rdx
    mov  r14, rcx
    cmp  byte [rel cmd_in_dispatch], 0
    jne  .bad
    cmp  qword [rel form_app_owner], 0
    jne  .bad
    cmp  r14, PRIN_HOUSEHOLD
    jbe  .bad
    cmp  r14, WM_OWNER_CHROME
    je   .bad
    call session_shell_require_unlocked
    test eax, eax
    jnz  .bad
    mov  [rel form_app_owner], r14
    mov  [rel form_app_staged], r15b
    mov  rdi, rbx
    mov  rsi, r12
    mov  rdx, r13
    xor  ecx, ecx
    call form_load_blob
    mov  byte [rel form_app_staged], 0
    mov  qword [rel form_app_owner], 0 ; every success/refusal, before return
    jmp  .out
.bad:
    mov  eax, 1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  r15
    ret

; Runtime form entry. RDI=blob, RSI=len, RDX=stable name, ECX=focus request.
; Exactly one ephemeral form may be live because there is one bounded staging
; buffer.  The baked loader below remains unchanged above this pointer/length
; adapter, so both lifetimes execute form_lint_blob before any WM/widget write.
form_load_blob:
    push rbx
    push r12
    push r13
    push r14
    mov  rbx, rdi
    mov  r12, rsi
    mov  r13, rdx
    mov  r14d, ecx
    call form_focus_request_gate
    call form_ephemeral_reap
    cmp  dword [rel form_ephemeral_slot], -1
    jne  .busy
    test rbx, rbx
    jz   .syntax
    test r13, r13
    jz   .syntax
    cmp  byte [r13], 0
    je   .syntax
    test r12, r12
    jz   .syntax
    cmp  r12, FORM_PARSE_MAX - 1
    ja   .oversize
    mov  edi, FORM_EPHEMERAL_INDEX
    call form_table_ptr
    mov  [rax + FORM_NAME], r13
    mov  [rax + FORM_BLOB_PTR], rbx
    mov  [rax + FORM_LEN], r12
    mov  edi, FORM_EPHEMERAL_INDEX
    xor  esi, esi
    mov  edx, r14d
    call form_load_index
    test eax, eax
    jnz  .failed
    mov  [rel form_ephemeral_slot], ecx
    ; EPHEMERAL is a lifetime class, not a form-authored preference.  Even a
    ; valid blob that asks for restore=always is forced out of session state.
    lea  rax, [rel wm_restore_class]
    mov  byte [rax + rcx], WM_RESTORE_NEVER
    xor  eax, eax
    jmp  .out
.busy:
    mov  dword [rel form_error], FORM_ERR_CAPACITY
    mov  eax, 1
    jmp  .out
.oversize:
    mov  dword [rel form_error], FORM_ERR_OVERSIZE
    mov  eax, 1
    jmp  .out
.syntax:
    mov  dword [rel form_error], FORM_ERR_SYNTAX
.failed:
    ; A refused staged declaration must not leave a pointer into transport
    ; scratch after command_udp wipes that buffer.
    mov  edi, FORM_EPHEMERAL_INDEX
    call form_table_ptr
    mov  qword [rax + FORM_NAME], 0
    mov  qword [rax + FORM_BLOB_PTR], 0
    mov  qword [rax + FORM_LEN], 0
    lea  rax, [rel form_active_slot]
    mov  dword [rax + FORM_EPHEMERAL_INDEX*4], -1
    mov  eax, 1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Detect a user/chrome close, drop every runtime identity pointer, and compact
; only retired tail widgets. EAX=1 means transport storage may now be wiped.
form_ephemeral_reap:
    push rbx
    mov  ebx, [rel form_ephemeral_slot]
    cmp  ebx, -1
    je   .none
    lea  rax, [rel wm_state]
    mov  eax, [rax + rbx*4]
    cmp  eax, WM_VISIBLE
    je   .none
    cmp  eax, WM_MIN
    je   .none
    cmp  eax, LOCK_HIDDEN               ; relock hides a live form; it is not closed
    je   .none
    mov  dword [rel form_ephemeral_slot], -1
    lea  rax, [rel form_active_slot]
    mov  dword [rax + FORM_EPHEMERAL_INDEX*4], -1
    mov  edi, FORM_EPHEMERAL_INDEX
    call form_table_ptr
    mov  qword [rax + FORM_NAME], 0
    mov  qword [rax + FORM_BLOB_PTR], 0
    mov  qword [rax + FORM_LEN], 0
    lea  rdi, [rel form_titles + FORM_EPHEMERAL_INDEX*FORM_TITLE_MAX]
    mov  byte [rdi], 0
.shrink:
    mov  eax, [rel wgt_count]
    test eax, eax
    jz   .reaped
    dec  eax
    mov  edi, eax
    call wgt_slot_ptr
    cmp  dword [rax + WGI_TYPE], 0
    jne  .reaped
    dec  dword [rel wgt_count]
    jmp  .shrink
.reaped:
    mov  eax, 1
    pop  rbx
    ret
.none:
    xor  eax, eax
    pop  rbx
    ret

; Native read/reap seam for immutable form-storage owners. One means storage
; still backs a live/hidden runtime form and must not be replaced or wiped.
form_ephemeral_busy:
    call form_ephemeral_reap
    cmp  dword [rel form_ephemeral_slot], -1
    setne al
    movzx eax, al
    ret

; Explicit agent close avoids the persistent WINCLOSE path: ephemeral forms
; are never serialized into the session manifest. RDI=handle/name.
form_ephemeral_close:
    push rbx
    push r12
    mov  r12, rdi
    call form_ephemeral_reap
    mov  ebx, [rel form_ephemeral_slot]
    cmp  ebx, -1
    je   .bad
    mov  edi, FORM_EPHEMERAL_INDEX
    call form_table_ptr
    mov  rdi, [rax + FORM_NAME]
    mov  rsi, r12
    call strcmp
    test eax, eax
    jnz  .bad
    push rbx                            ; 2026-10-01: the closed slot survives the painters
    mov  edi, ebx
    call wmx_close_slot
    call form_ephemeral_reap
    pop  rax                            ; (wmx_close_slot leaves 0x181818 in RBX)
    pop  r12
    pop  rbx
    ret
.bad:
    mov  eax, -1
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; Command handlers.
form_arg_copy:
    lea  rax, [rel form_arg_buf]
    xor  ecx, ecx
.cp:
    cmp  ecx, 190
    jae  .done
    mov  dl, [rsi + rcx]
    test dl, dl
    jz   .done
    mov  [rax + rcx], dl
    inc  ecx
    jmp  .cp
.done:
    mov  byte [rax + rcx], 0
    ret

form_cmd_verb_formload:
    call form_verb_unlocked             ; RCQ-16 F2b-1: refused under the lock, first
    test eax, eax
    jz   .unlocked
    ret
.unlocked:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    mov  byte [rel form_relaunch_focuses], 0
    cmp  qword [rdi + REQ_SOURCE], CMD_SOURCE_CONSOLE
    jne  .source_known
    mov  byte [rel form_relaunch_focuses], 1   ; STM-04: typed by the user at the console
.source_known:
    mov  r13, rsi
    mov  rsi, [rdi + REQ_ARG]
    call form_arg_copy
    lea  rdi, [rel form_arg_buf]
    call wgt_tok_split
    mov  r12, rax
    lea  rdi, [rel form_arg_buf]
    call form_lookup
    cmp  eax, -1
    je   .missing
    mov  ebx, eax
    mov  [rel form_last_index], eax
    xor  r14d, r14d                    ; focus default 0
    mov  qword [rel form_arg_title], 0
.opts:
    cmp  byte [r12], 0
    je   .load
    mov  rdi, r12
    call wgt_tok_split
    mov  rdx, r12
    mov  r12, rax
    mov  rdi, rdx
    lea  rsi, [rel key_title]
    call form_key_value
    test rax, rax
    jnz  .title
    mov  rdi, rdx
    lea  rsi, [rel key_focus]
    call form_key_value
    test rax, rax
    jz   .badarg
    cmp  byte [rax], '1'
    jne  .badarg
    cmp  byte [rax + 1], 0
    jne  .badarg
    mov  r14d, 1
    jmp  .opts
.title:
    mov  [rel form_arg_title], rax
    jmp  .opts
.load:
    ; F-NEWBEHIND (2026-10-01, usage suite STM-03): a form the USER launches by
    ; typing FORMLOAD at the console opens on top with focus, like a launch
    ; from a terminal (STM-04 already focuses a relaunched one). Agent/remote
    ; FORMLOAD keeps the no-steal default unless it asks focus=1.
    cmp  byte [rel form_relaunch_focuses], 1
    jne  .focus_chosen
    mov  r14d, 1
.focus_chosen:
    mov  edi, ebx
    mov  rsi, [rel form_arg_title]
    mov  edx, r14d
    call form_load_index
    mov  byte [rel form_relaunch_focuses], 0
    test eax, eax
    jnz  .load_error
    mov  ebx, ecx
    mov  r12d, edx
    call form_out_reset
    lea  rdi, [rel str_formload_ok]
    call form_out_put_str
    mov  edi, [rel form_last_index]
    call form_table_ptr
    mov  rdi, [rax + FORM_NAME]
    call form_out_put_str
    lea  rdi, [rel str_formload_win]
    call form_out_put_str
    mov  edi, ebx
    call form_out_put_dec
    lea  rdi, [rel str_formload_widgets]
    call form_out_put_str
    mov  edi, r12d
    call form_out_put_dec
    jmp  .stage
.missing:
    mov  dword [rel form_error], FORM_ERR_MISSING
    jmp  .load_error
.badarg:
    mov  dword [rel form_error], FORM_ERR_SYNTAX
.load_error:
    mov  byte [rel form_relaunch_focuses], 0   ; never outlives this verb (refused before .load)
    call form_out_reset
    lea  rdi, [rel str_formload_err]
    call form_out_put_str
    mov  edi, [rel form_error]
    call form_error_string
    mov  rdi, rax
    call form_out_put_str
.stage:
    mov  byte [rel form_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  qword [r13 + RSP_VAL], 0
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; LAUNCH remains the one owner-signed mutation verb. This replacement preserves
; the two F2 mappings and adds app_imgdemo -> declarative form index 5.
form_cmd_verb_launch:
    call form_verb_unlocked             ; RCQ-16 F2b-1: refused under the lock, first
    test eax, eax
    jz   .unlocked
    ret
.unlocked:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov  r13, rsi
    mov  rbx, [rdi + REQ_ARG]
    test rbx, rbx
    jz   .bad
    mov  rdi, rbx
    lea  rsi, [rel form_str_app_sysprops]
    call strcmp
    test rax, rax
    jz   .sysprops
    mov  rdi, rbx
    lea  rsi, [rel form_str_app_netmon]
    call strcmp
    test rax, rax
    jz   .netmon
    mov  rdi, rbx
    lea  rsi, [rel str_app_imgdemo]
    call strcmp
    test rax, rax
    jnz  .bad
    mov  r12d, 5
    jmp  .load
.sysprops:
    mov  r12d, 3
    jmp  .load
.netmon:
    mov  r12d, 4
.load:
    mov  edi, r12d
    xor  esi, esi
    xor  edx, edx
    call form_load_index
    test eax, eax
    jnz  .bad
    mov  ebx, ecx
    call form_out_reset
    lea  rdi, [rel str_launch_img_ok]
    call form_out_put_str
    mov  edi, r12d
    call form_table_ptr
    mov  rdi, [rax + FORM_NAME]
    call form_out_put_str
    lea  rdi, [rel str_launch_img_idx]
    call form_out_put_str
    mov  edi, ebx
    call form_out_put_dec
    jmp  .stage
.bad:
    call form_out_reset
    lea  rdi, [rel str_launch_img_bad]
    call form_out_put_str
.stage:
    mov  byte [rel form_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  qword [r13 + RSP_VAL], 0
    pop  r13
    pop  r12
    pop  rbx
    ret

form_error_string:
    lea  rax, [rel val_err_syntax]
    cmp  edi, FORM_ERR_MISSING
    jne  .not_missing
    lea  rax, [rel val_err_missing]
    ret
.not_missing:
    cmp  edi, FORM_ERR_UNKNOWN_KEY
    jne  .not_key
    lea  rax, [rel val_err_unknown_key]
    ret
.not_key:
    cmp  edi, FORM_ERR_UNKNOWN_WIDGET
    jne  .not_widget
    lea  rax, [rel val_err_unknown_widget]
    ret
.not_widget:
    cmp  edi, FORM_ERR_UNKNOWN_ASSET
    jne  .not_asset
    lea  rax, [rel val_err_unknown_asset]
    ret
.not_asset:
    cmp  edi, FORM_ERR_NO_SLOT
    jne  .not_slot
    lea  rax, [rel val_err_no_slot]
    ret
.not_slot:
    cmp  edi, FORM_ERR_CARD_SHOWN
    jne  .not_card
    lea  rax, [rel val_err_card_shown]
    ret
.not_card:
    cmp  edi, FORM_ERR_CAPACITY
    jne  .ret
    lea  rax, [rel val_err_capacity]
.ret:
    ret

form_cmd_verb_formlist:
    call cmd_handler_prologue
    push r12
    mov  r12, rsi
    call form_out_reset
    lea  rdi, [rel str_formlist]
    call form_out_put_str
    mov  byte [rel form_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_OK
    pop  r12
    ret

form_cmd_verb_forminfo:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rsi
    mov  rsi, [rdi + REQ_ARG]
    call form_arg_copy
    lea  rdi, [rel form_arg_buf]
    call wgt_tok_split
    mov  r13, rax
    lea  rdi, [rel form_arg_buf]
    call form_lookup
    cmp  eax, -1
    je   .bad
    mov  ebx, eax
    mov  edi, ebx
    call form_table_ptr
    mov  rbx, rax
    mov  rax, [rbx + FORM_LEN]
    add  rax, FORM_INFO_CHUNK - 1
    xor  edx, edx
    mov  ecx, FORM_INFO_CHUNK
    div  rcx
    mov  r14d, eax                    ; total pages
    mov  eax, 1                       ; default page
    cmp  byte [r13], 0
    je   .page_ok
    mov  rdi, r13
    call wgt_parse_dec
    test rcx, rcx
    jz   .bad_page
    cmp  byte [rdx], 0
    jne  .bad_page
    test eax, eax
    jz   .bad_page
    cmp  eax, r14d
    ja   .bad_page
.page_ok:
    push rax                         ; selected page
    call form_out_reset
    lea  rdi, [rel str_forminfo]
    call form_out_put_str
    mov  rdi, [rbx + FORM_NAME]
    call form_out_put_str
    lea  rdi, [rel str_forminfo_page]
    call form_out_put_str
    mov  edi, [rsp]
    call form_out_put_dec
    lea  rdi, [rel str_forminfo_slash]
    call form_out_put_str
    mov  edi, r14d
    call form_out_put_dec
    lea  rdi, [rel form_str_nl]
    call form_out_put_str
    pop  rax
    dec  eax
    imul eax, FORM_INFO_CHUNK
    mov  rdi, [rbx + FORM_BLOB_PTR]
    add  rdi, rax
    mov  rsi, [rbx + FORM_LEN]
    sub  rsi, rax
    cmp  rsi, FORM_INFO_CHUNK
    jbe  .emit
    mov  rsi, FORM_INFO_CHUNK
.emit:
    call form_out_put_n
    jmp  .stage
.bad_page:
    call form_out_reset
    lea  rdi, [rel str_forminfo_page_err]
    call form_out_put_str
    jmp  .stage
.bad:
    call form_out_reset
    lea  rdi, [rel str_forminfo_err]
    call form_out_put_str
.stage:
    mov  byte [rel form_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_OK
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; Dynamic state: WINTREE calls these immediately before serializing a widget.
form_live_reset:
    lea  rax, [rel form_live_buf]
    mov  [rel form_live_cur], rax
    mov  byte [rax], 0
    ret
form_live_put_str:
    mov  rsi, [rel form_live_cur]
    lea  rdx, [rel form_live_buf + 1023]
.cp:
    cmp  rsi, rdx
    jae  .done
    mov  al, [rdi]
    test al, al
    jz   .done
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .cp
.done:
    mov  byte [rsi], 0
    mov  [rel form_live_cur], rsi
    ret

; Append one space-delimited token. STATUS's VERSION field is sourced from the
; canonical UDP prefix, avoiding a second hand-kept version literal in the form.
form_live_put_token:
    mov  rsi, [rel form_live_cur]
    lea  rdx, [rel form_live_buf + 1023]
.cp:
    cmp  rsi, rdx
    jae  .done
    mov  al, [rdi]
    test al, al
    jz   .done
    cmp  al, ' '
    je   .done
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .cp
.done:
    mov  byte [rsi], 0
    mov  [rel form_live_cur], rsi
    ret
form_live_put_dec:
    mov  rsi, [rel form_live_cur]
    push rsi
    call fmt_dec
    pop  rsi
    add  rsi, rax
    mov  byte [rsi], 0
    mov  [rel form_live_cur], rsi
    ret

form_build_sysprops:
    ; WINTREE is paged and callers use repeated reads to prove that a refused
    ; form left the semantic tree untouched.  Keep one bounded observation
    ; coherent for a second rather than letting uptime cross a tick between
    ; pages (or between the before/after reads of one transaction).  The
    ; sysprops contract still observes fresh state on the next >=1s read.
    call boot_ms_now
    mov  rdx, [rel form_sysprops_snapshot_ms]
    test rdx, rdx
    jz   .refresh
    mov  rcx, rax
    sub  rcx, rdx
    cmp  rcx, FORM_SYSPROPS_SNAPSHOT_MS
    jb   .cached
.refresh:
    mov  [rel form_sysprops_snapshot_ms], rax
    call form_live_reset
    call platform_key_health_text
    mov  rdi, rax
    call form_live_put_str
    lea  rdi, [rel live_version]
    call form_live_put_str
    lea  rdi, [rel str_udp_r_pre + 13] ; bytes after canonical "PAOS VERSION="
    call form_live_put_token
    lea  rdi, [rel live_boot_session]
    call form_live_put_str
    mov  rdi, [rel boot_tsc_start]
    call form_live_put_dec
    lea  rdi, [rel live_uptime]
    call form_live_put_str
    call boot_ms_now
    xor  edx, edx
    mov  rcx, 1000
    div  rcx
    mov  rdi, rax
    call form_live_put_dec
    lea  rdi, [rel live_heap]
    call form_live_put_str
    mov  rdi, [rel heap_mb]
    call form_live_put_dec
    lea  rdi, [rel live_nic]
    call form_live_put_str
    movzx edi, byte [rel e1000e_mac_ok]
    call form_live_put_dec
    lea  rdi, [rel live_crashes]
    call form_live_put_str
    movzx edi, byte [rel boot_crashes_observed]
    call form_live_put_dec
    lea  rdi, [rel live_native]
    call form_live_put_str
    mov  edi, [rel res_native_w]
    call form_live_put_dec
    lea  rdi, [rel live_x]
    call form_live_put_str
    mov  edi, [rel res_native_h]
    call form_live_put_dec
    lea  rdi, [rel live_active]
    call form_live_put_str
    mov  edi, [rel fb_width]
    call form_live_put_dec
    lea  rdi, [rel live_x]
    call form_live_put_str
    mov  edi, [rel fb_height]
    call form_live_put_dec
    lea  rdi, [rel live_source]
    call form_live_put_str
    lea  rdi, [rel form_val_none]
    cmp  byte [rel res_src], 1
    jne  .not_edid
    lea  rdi, [rel val_edid]
    jmp  .source
.not_edid:
    cmp  byte [rel res_src], 2
    jne  .source
    lea  rdi, [rel form_val_gop]
.source:
    call form_live_put_str
    lea  rdi, [rel form_cpu_security_buf]
    mov  esi, 384
    mov  edx, 1                        ; compact shared native snapshot
    call cpu_security_report_text
    lea  rdi, [rel form_cpu_security_unavailable]
    test rax, rax
    js   .cpu_text
    lea  rdi, [rel form_cpu_security_buf]
    call .cpu_rows
.cpu_text:
    call form_live_put_str
%ifdef PAOS_DRIVER_DOMAIN_EVERYBOOT
    call nd_properties_append
%endif
    lea  rdi, [rel form_live_buf]
    lea  rsi, [rel form_sysprops_snapshot_buf]
    mov  edx, 1024
    call form_copy_token
.cached:
    lea  rax, [rel form_sysprops_snapshot_buf]
    ret

; The facts list paints comma-delimited rows, not a wrapping paragraph. Keep
; every ASCII CPU field intact within 50 bytes (the facts widget paints 55).
; Only separator bytes in this successful, length-bounded private snapshot
; change; AUDIT, values, validity, scope and the one-second cache are unchanged.
.cpu_rows:
    mov  r8, rdi
    mov  r10, rax                     ; successful report length, excluding NUL
    xor  ecx, ecx                    ; current row bytes
.cpu_row_byte:
    test r10, r10
    jz   .cpu_rows_done
    cmp  byte [r8], ' '
    jne  .cpu_row_char
    test ecx, ecx
    jz   .cpu_row_break               ; leading space starts a separate row
    mov  r9d, 1
.cpu_row_word:
    cmp  r9, r10
    jae  .cpu_row_fit
    cmp  byte [r8 + r9], ' '
    je   .cpu_row_fit
    inc  r9
    jmp  .cpu_row_word
.cpu_row_fit:
    add  r9, rcx                     ; row + one space + the complete next field
    cmp  r9, 50
    jbe  .cpu_row_char
.cpu_row_break:
    mov  byte [r8], ','
    xor  ecx, ecx
    jmp  .cpu_row_next
.cpu_row_char:
    inc  ecx
.cpu_row_next:
    inc  r8
    dec  r10
    jmp  .cpu_row_byte
.cpu_rows_done:
    ret

form_build_netmon:
%if !PAOS_PUBLIC_BUILD
    mov  edi, 1
    xor  esi, esi
    call pmod_netmon_query
    test rax, rax
    jnz  .out
%endif
    lea  rax, [rel form_optional_empty]
.out:
    ret

; RCQ-35: netmon.members rows, rendered by gui/netmon_form (registered in
; form_netmon_members_fn when it declares; nothing before that).
form_build_netmembers:
    mov  rax, [rel form_netmon_members_fn]
    test rax, rax
    jz   .empty
    jmp  rax
.empty:
    lea  rax, [rel form_optional_empty]
    ret

; Same keep-owned optional callback as member rows; no signed-provider ABI change.
form_build_netaddress:
    mov  rax, [rel form_netmon_address_fn]
    test rax, rax
    jz   .empty
    jmp  rax
.empty:
    lea  rax, [rel form_optional_empty]
    ret

form_widget_tree_text_ptr:
    push rbx
    push r12
    mov  r12d, edi
    call wgt_slot_ptr
    mov  ebx, [rax + WGI_BIND]
    cmp  ebx, FORM_BIND_SYSPROPS
    je   .sysprops
    cmp  ebx, FORM_BIND_NETMON
    je   .netmon
    cmp  ebx, FORM_BIND_NET_MEMBERS
    je   .netmembers
    cmp  ebx, FORM_BIND_NET_ADDRESS
    je   .netaddress
    cmp  ebx, FORM_BIND_FS_ROOT
    je   .fsroot
    cmp  ebx, FORM_BIND_FS_DRIVES
    je   .fsdrives
    cmp  ebx, FORM_BIND_FS_DETAILS
    je   .fsdetails
    cmp  ebx, FORM_BIND_FS_STATUS
    je   .fsstatus
    cmp  ebx, FORM_BIND_SUMMON_PINNED
    je   .summon
    cmp  ebx, FORM_BIND_SUMMON_RECENTS
    je   .summon
    cmp  ebx, FORM_BIND_SUMMON_RESULTS
    je   .summon
    xor  eax, eax
    jmp  .out
.sysprops:
    call form_build_sysprops
    jmp  .out
.netmon:
    call form_build_netmon
    jmp  .out
.netmembers:
    call form_build_netmembers
    jmp  .out
.netaddress:
    call form_build_netaddress
    jmp  .out
.fsdrives:
    call form_build_fsdrives
    jmp  .out
.fsdetails:
    call form_build_fsdetails
    jmp  .out
.fsroot:
    mov  edi, r12d                      ; the file list: its height is the page
    call form_build_fsroot
    jmp  .out
.fsstatus:
    call form_build_fsstatus
    push rax
    mov  edi, r12d
    call form_explorer_copy_shown
    pop  rax
    jmp  .out
.summon:
    mov  edi, r12d
    call naming_picker_text_for_list
.out:
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; Explorer binds (desktop bring-up 2026-09-07; RCQ-21 folder browsing).
; fs.root renders the Explorer's folder (form_fs_cwd on the FS-verb mount,
; vfs_disk_handle; FSSEL moves it) as one comma-delimited row stream: a ".."
; row below "/", then "NAME SIZE D|F" rows (the selected one "> "), with
; "^ N above" / "... N more" rows when the folder is longer than the page.
; fs.status renders the volume rows (mount, files, dir = the path, write, and
; a refused open's note).  Both come from ONE bounded snapshot (<=
; FORM_FSROOT_CAP entries, 1 s coherence like sysprops; opening a folder
; invalidates it) so the pixels and the WINTREE text describe the same
; observation, and the disk is read at most once per second, never per
; repaint.  Names (long ones via vfs_dirent_name) are copied out of the
; listing, so a later FS verb cannot change rows already shown.  The file list
; is driven through its listview type's pointer capture (form_explorer_capture;
; every other listview declines) and the kit's chained key filter: double-click
; or Enter opens a folder, Backspace or the ".." row goes up (never above "/"),
; arrows/PgUp/PgDn/Home/End move the selection and the page follows it.
; Ctrl+C/Ctrl+V captures one local-owner file/directory and requests a supported
; keep-both copy at idle through FSCOPY. Rendering remains an observer; native
; FS admission, copy/flush/cancel/results remain the only write authority.
FORM_FSROOT_CAP         equ 64        ; entries per snapshot (RCQ-21: was 24, cut mid-row)
FORM_FSROOT_LIST        equ FORM_FSROOT_CAP + 2   ; dirents asked of the backend: "." and ".." are not entries
FORM_FS_CWD_MAX         equ 80        ; path bound (one status row): FSCD and opening refuse >= 80 chars
FORM_FSROOT_ENT         equ 32        ; sizeof fs_dirent (name13 pad3 size8 flags4 res4)
FORM_FSROOT_SNAPSHOT_MS equ 1000
FORM_FSROOT_BUF         equ 4096      ; >= FORM_EXP_ROWS_MAX rows of "> " NAME79 " " SIZE20 " D" ","
FORM_FSSTATUS_BUF       equ 512       ; six status rows (RCQ-21 elapsed/rate, result/tree/kept)
FORM_EXP_NAME           equ 80        ; copied name bytes (NUL incl.); a longer name shows clipped, never opens
FORM_EXP_DIR            equ 1         ; form_exp_flags: a folder
FORM_EXP_CLIPPED        equ 2         ;                 the name was clipped, invalid or omitted
FORM_EXP_ROWS_MAX       equ 32        ; page rows the row map describes
FORM_EXP_ROWS_MIN       equ 4         ; "..", "^ N above", one entry, "... N more"
FORM_EXP_LV_HEAD        equ 30        ; widget_listview draw_rows geometry: the header band,
FORM_EXP_LV_ROW         equ 18        ;   then one row per 18 px
FORM_EXP_UP             equ -1        ; row map and cursor: the ".." row
FORM_EXP_ABOVE          equ -2        ; row map: "^ N above" (a press pages up)
FORM_EXP_MORE           equ -3        ; row map: "... N more" (a press pages down)
FORM_EXP_NOTE           equ -4        ; row map: a message row (inert)
FORM_EXP_NONE           equ -5        ; cursor: nothing selected
FORM_EXP_DBLCLICK_MS    equ 500       ; = wm_pointer WM_DBLCLICK_MS: a press pairs only this recently

form_fsroot_put_str:                  ; RDI=cstr -> complete canonical scalars only
    push rbx
    mov  rbx, [rel form_fsroot_cur]
    mov  rdx, [rel form_fsroot_end]
    sub  rdx, rbx
    jbe  .done
    mov  rsi, rbx
    call ue_utf8_cstr_prefix
    add  rbx, rax
.done:
    mov  byte [rbx], 0
    mov  [rel form_fsroot_cur], rbx
    pop  rbx
    ret

form_fsroot_put_name:                 ; only DISPLAY escapes ','; owned identity stays exact
    push rbx
    mov  rbx, [rel form_fsroot_cur]
    call form_fsroot_put_str
    mov  rdx, [rel form_fsroot_cur]
.escape:
    cmp  rbx, rdx
    jae  .done
    cmp  byte [rbx], ','
    jne  .next
    mov  byte [rbx], ';'
.next:
    inc  rbx
    jmp  .escape
.done:
    pop  rbx
    ret

form_fsroot_put_dec:                  ; RDI=value -> decimal appended (skipped if < 21 bytes left)
    mov  rsi, [rel form_fsroot_cur]
    mov  rdx, [rel form_fsroot_end]
    sub  rdx, rsi
    cmp  rdx, 21
    jb   .skip
    push rsi
    call fmt_dec
    pop  rsi
    add  rsi, rax
    mov  byte [rsi], 0
    mov  [rel form_fsroot_cur], rsi
.skip:
    ret

form_fsroot_refresh:                  ; re-list form_fs_cwd when the 1 s snapshot is stale or invalidated
    push rbx
    push r12
    push r13
    call boot_ms_now
    mov  rdx, [rel form_fsroot_snapshot_ms]
    test rdx, rdx
    jz   .refresh
    mov  rcx, rax
    sub  rcx, rdx
    cmp  rcx, FORM_FSROOT_SNAPSHOT_MS
    jb   .done
.refresh:
    mov  [rel form_fsroot_snapshot_ms], rax
    mov  edi, [rel form_exp_cursor]               ; RCQ-21: the selection and the last press are
    lea  rsi, [rel form_exp_sel_name]             ; entries, not list positions: keep their names
    call form_exp_name_save
    mov  edi, [rel form_exp_last_press]
    lea  rsi, [rel form_exp_press_name]
    call form_exp_name_save
    mov  dword [rel form_fsroot_result + fs_list_result.count], 0
    mov  dword [rel form_fsroot_result + fs_list_result.truncated], 0
    mov  dword [rel form_fsroot_rc], -1
    inc  dword [rel form_exp_gen]                 ; row maps of earlier renders are stale
    mov  dword [rel form_exp_count], 0            ; never another listing's rows
    mov  dword [rel form_exp_trunc], 0
    mov  qword [rel form_exp_listing_mount], -1
    mov  edi, [rel vfs_disk_handle]
    cmp  edi, -1
    je   .clamp
    call vfs_mount_ptr
    test rax, rax
    jz   .clamp
    mov  rcx, [rax]                   ; bind this snapshot to the selected mount
    mov  [rel form_exp_listing_ops], rcx
    mov  rcx, [rax + 8]
    mov  [rel form_exp_listing_priv], rcx
    mov  edi, [rel vfs_disk_handle]
    mov  [rel form_exp_listing_mount], rdi
    cmp  dword [rel form_fs_cwd_len], 1
    jbe  .list_root
    lea  rsi, [rel form_fs_cwd]           ; a folder -> fs_ops.list_dir (v1.1 paths)
    mov  edx, [rel form_fs_cwd_len]
    lea  rcx, [rel form_fsroot_dirents]
    mov  r8d, FORM_FSROOT_LIST
    lea  r9, [rel form_fsroot_result]
    call vfs_list_dir
    mov  [rel form_fsroot_rc], eax
    jmp  .listed
.list_root:
    lea  rsi, [rel form_fsroot_dirents]
    mov  edx, FORM_FSROOT_LIST
    lea  rcx, [rel form_fsroot_result]
    call vfs_list_root
    mov  [rel form_fsroot_rc], eax
.listed:
    cmp  dword [rel form_fsroot_rc], 0
    jne  .clamp                       ; an error lists nothing (never the previous rows)
    mov  eax, [rel form_fsroot_result + fs_list_result.truncated]
    mov  [rel form_exp_trunc], eax
    xor  ebx, ebx                     ; dirent index
.copy:
    cmp  ebx, [rel form_fsroot_result + fs_list_result.count]
    jae  .clamp
    cmp  ebx, FORM_FSROOT_LIST
    jae  .clamp
    mov  eax, ebx
    shl  eax, 5                       ; * FORM_FSROOT_ENT
    lea  r13, [rel form_fsroot_dirents]
    add  r13, rax                     ; fs_dirent*
    mov  rdi, r13
    call vfs_dirent_name              ; the inline 8.3 name or the backend's long name
    mov  rsi, rax
    cmp  byte [rsi], '.'
    jne  .take
    cmp  byte [rsi + 1], 0
    je   .skip                        ; "." is this folder
    cmp  byte [rsi + 1], '.'
    jne  .take
    cmp  byte [rsi + 2], 0
    je   .skip                        ; ".." is the Explorer's own up row
.take:
    mov  r12d, [rel form_exp_count]
    cmp  r12d, FORM_FSROOT_CAP
    jb   .room
    mov  dword [rel form_exp_trunc], 1    ; a 65th entry: shown as the cap note
    jmp  .clamp
.room:
    mov  eax, r12d
    imul eax, eax, FORM_EXP_NAME
    lea  rdi, [rel form_exp_names]
    add  rdi, rax
    xchg rdi, rsi                    ; src provider / dst owned snapshot
    mov  edx, FORM_EXP_NAME - 1
    test dword [r13 + fs_dirent.flags], FS_DIRENT_LONG_NAME
    jnz  .long
    mov  edx, 12                     ; inline name is exactly13 bytes incl. NUL
.long:
    call ue_utf8_cstr_prefix
    shl  edx, 1                      ; incomplete/invalid -> FORM_EXP_CLIPPED
    test eax, eax
    jnz  .nonempty
    or   edx, FORM_EXP_CLIPPED        ; never restore an empty/invalid identity
.nonempty:
    test dword [r13 + fs_dirent.flags], FS_DIRENT_LONG_OMITTED
    jz   .named
    or   edx, FORM_EXP_CLIPPED        ; backend alias isn't the original name
.named:
    test dword [r13 + 24], FS_DIRENT_DIR   ; fs_dirent.flags
    jz   .kind
    or   edx, FORM_EXP_DIR
.kind:
    lea  rax, [rel form_exp_flags]
    mov  [rax + r12], dl
    mov  rcx, [r13 + 16]              ; fs_dirent.size
    lea  rax, [rel form_exp_size]
    mov  [rax + r12*8], rcx
    inc  dword [rel form_exp_count]
.skip:
    inc  ebx
    jmp  .copy
.clamp:                               ; the view stays inside the new listing
    call form_exp_sort
    lea  rdi, [rel form_exp_sel_name]
    mov  esi, [rel form_exp_cursor]
    call form_exp_name_find           ; the selected entry's new position, or none
    mov  [rel form_exp_cursor], eax
    lea  rdi, [rel form_exp_press_name]
    mov  esi, [rel form_exp_last_press]
    call form_exp_name_find           ; a double-click's first press pairs only with its entry
    mov  [rel form_exp_last_press], eax
    mov  eax, [rel form_exp_count]
    cmp  [rel form_exp_top], eax
    jl   .done
    mov  dword [rel form_exp_top], 0
.done:
    pop  r13
    pop  r12
    pop  rbx
    ret

; form_exp_name_save(EDI = entry index or a negative ref, RSI = FORM_EXP_NAME
; buffer): the entry's name, or "" for "..", nothing, or an index outside the
; snapshot. Clobbers RAX, RCX, RSI, RDI.
form_exp_name_save:
    mov  byte [rsi], 0
    test edi, edi
    js   .out
    cmp  edi, [rel form_exp_count]
    jae  .out
    lea  rax, [rel form_exp_flags]
    test byte [rax + rdi], FORM_EXP_CLIPPED
    jnz  .out                        ; a prefix is not a stable identity
    imul eax, edi, FORM_EXP_NAME
    mov  rdi, rsi
    lea  rsi, [rel form_exp_names]
    add  rsi, rax
    mov  ecx, FORM_EXP_NAME
    rep  movsb
.out:
    ret

; form_exp_name_find(RDI = saved name, ESI = the ref it was saved from) -> EAX
; the ref in the new snapshot: a negative ref (".." / none) unchanged, else
; the index of the entry with exactly that name, or FORM_EXP_NONE when it is
; gone. Clobbers RAX, RCX, RDX, R8, R9.
form_exp_name_find:
    mov  eax, esi
    test esi, esi
    js   .out
    mov  eax, FORM_EXP_NONE
    cmp  byte [rdi], 0
    je   .out
    xor  edx, edx
.entry:
    cmp  edx, [rel form_exp_count]
    jae  .out
    lea  r9, [rel form_exp_flags]
    test byte [r9 + rdx], FORM_EXP_CLIPPED
    jnz  .next                       ; never match a complete name to a prefix
    imul r8d, edx, FORM_EXP_NAME
    lea  r9, [rel form_exp_names]
    add  r9, r8
    xor  ecx, ecx
.cmp:
    mov  r8b, [r9 + rcx]
    cmp  r8b, [rdi + rcx]
    jne  .next
    test r8b, r8b
    jz   .found
    inc  ecx
    cmp  ecx, FORM_EXP_NAME
    jb   .cmp
.found:
    mov  eax, edx
    ret
.next:
    inc  edx
    jmp  .entry
.out:
    ret

; form_exp_page_of(EDI = the file list's widget id): the rows its listview
; draws (the same (H - 30) / 18 as wgt_listview_draw_rows), bounded.
form_exp_page_of:
    mov  eax, FORM_EXP_ROWS_MIN
    cmp  edi, [rel wgt_count]
    jae  .set
    call wgt_slot_ptr
    mov  eax, [rax + WGI_H]
    sub  eax, FORM_EXP_LV_HEAD
    jle  .min
    xor  edx, edx
    mov  ecx, FORM_EXP_LV_ROW
    div  ecx
    cmp  eax, FORM_EXP_ROWS_MIN
    jae  .max
.min:
    mov  eax, FORM_EXP_ROWS_MIN
.max:
    cmp  eax, FORM_EXP_ROWS_MAX
    jbe  .set
    mov  eax, FORM_EXP_ROWS_MAX
.set:
    mov  [rel form_exp_page], eax
    ret

; form_exp_slots(EDI = top entry) -> EAX entry rows the page shows from it,
; EDX entries below them (then the page ends in "... EDX more"; with the cap
; note, the last page keeps a row for it).
form_exp_slots:
    mov  eax, [rel form_exp_page]
    cmp  dword [rel form_fs_cwd_len], 1
    jbe  .no_up
    dec  eax                          ; ".."
.no_up:
    test edi, edi
    jz   .no_above
    dec  eax                          ; "^ N above"
.no_above:
    mov  edx, [rel form_exp_count]
    sub  edx, edi
    jle  .none
    cmp  dword [rel form_exp_trunc], 0
    jne  .last_row                    ; the cap note always keeps its own row
    cmp  edx, eax
    jbe  .all
.last_row:
    dec  eax                          ; "... N more", or the cap note on the last page
    cmp  edx, eax
    jbe  .all
    sub  edx, eax
    ret
.all:
    mov  eax, edx
    xor  edx, edx
    ret
.none:
    xor  eax, eax
    xor  edx, edx
    ret

form_exp_row:                         ; EDI = row-map ref of the next row (a comma separates rows)
    mov  eax, [rel form_exp_rows]
    cmp  eax, FORM_EXP_ROWS_MAX
    jae  .out
    lea  rcx, [rel form_exp_rowmap]
    mov  [rcx + rax*4], edi
    inc  dword [rel form_exp_rows]
    test eax, eax
    jz   .out
    lea  rdi, [rel str_fsroot_comma]
    jmp  form_fsroot_put_str
.out:
    ret

form_exp_mark:                        ; EDI = row ref: "> " when it is the selection
    cmp  edi, [rel form_exp_cursor]
    jne  .out
    lea  rdi, [rel str_exp_sel]
    jmp  form_fsroot_put_str
.out:
    ret

form_exp_up_row:                      ; the ".." row below "/"
    cmp  dword [rel form_fs_cwd_len], 1
    jbe  .out
    mov  edi, FORM_EXP_UP
    call form_exp_row
    mov  edi, FORM_EXP_UP
    call form_exp_mark
    lea  rdi, [rel str_exp_up]
    jmp  form_fsroot_put_str
.out:
    ret

; form_fsroot_render — the page of the snapshot (form_exp_top, form_exp_page)
; into form_fsroot_buf, and the row map a press or key resolves against.
form_fsroot_render:
    push rbx
    push r12
    push r13
    push r14
    push r15
    lea  rax, [rel form_fsroot_buf]
    mov  [rel form_fsroot_cur], rax
    mov  byte [rax], 0
    lea  rax, [rel form_fsroot_buf + FORM_FSROOT_BUF - 1]
    mov  [rel form_fsroot_end], rax
    mov  dword [rel form_exp_rows], 0
    mov  eax, [rel form_exp_gen]
    mov  [rel form_exp_rows_gen], eax
    cmp  dword [rel form_fsroot_rc], 0
    je   .listing
    cmp  dword [rel vfs_disk_handle], -1
    je   .no_mount
    call form_exp_up_row              ; a folder that cannot be listed: up, and say so
    mov  edi, FORM_EXP_NOTE
    call form_exp_row
    lea  rdi, [rel str_exp_failed]
    call form_fsroot_put_str
    jmp  .out
.listing:
    call form_exp_up_row
    mov  r12d, [rel form_exp_top]
    test r12d, r12d
    jz   .entries
    mov  edi, FORM_EXP_ABOVE
    call form_exp_row
    lea  rdi, [rel str_exp_above]
    call form_fsroot_put_str
    mov  edi, r12d
    call form_fsroot_put_dec
    lea  rdi, [rel str_exp_above_tail]
    call form_fsroot_put_str
.entries:
    mov  edi, r12d
    call form_exp_slots
    mov  r14d, edx                    ; entries below the page
    lea  r15d, [r12 + rax]            ; end of the page's entries
.entry:
    cmp  r12d, r15d
    jae  .below
    mov  edi, r12d
    call form_exp_row
    mov  edi, r12d
    call form_exp_mark
    mov  eax, r12d
    imul eax, eax, FORM_EXP_NAME
    lea  rdi, [rel form_exp_names]
    add  rdi, rax
    call form_fsroot_put_name
    lea  rdi, [rel str_fsroot_space]
    call form_fsroot_put_str
    lea  rax, [rel form_exp_size]
    mov  rdi, [rax + r12*8]
    call form_fsroot_put_dec
    lea  rdi, [rel str_fsroot_file]
    lea  rax, [rel form_exp_flags]
    test byte [rax + r12], FORM_EXP_DIR
    jz   .kind
    lea  rdi, [rel str_fsroot_dir]
.kind:
    call form_fsroot_put_str
    inc  r12d
    jmp  .entry
.below:
    test r14d, r14d
    jz   .tail
    mov  edi, FORM_EXP_MORE
    call form_exp_row
    lea  rdi, [rel str_exp_more]
    call form_fsroot_put_str
    mov  edi, r14d
    call form_fsroot_put_dec
    lea  rdi, [rel str_exp_more_tail]
    call form_fsroot_put_str
    jmp  .out
.tail:
    cmp  dword [rel form_exp_trunc], 0
    je   .empty
    mov  edi, FORM_EXP_NOTE           ; the backend stopped at FORM_FSROOT_CAP: say so
    call form_exp_row
    lea  rdi, [rel str_exp_capped]
    call form_fsroot_put_str
    jmp  .out
.empty:
    cmp  dword [rel form_exp_count], 0
    jne  .out
    mov  edi, FORM_EXP_NOTE
    call form_exp_row
    lea  rdi, [rel str_fsroot_empty]
    call form_fsroot_put_str
    jmp  .out
.no_mount:
    mov  edi, FORM_EXP_NOTE
    call form_exp_row
    lea  rdi, [rel str_fsroot_nomount]
    call form_fsroot_put_str
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

form_fsstatus_render:                 ; mount, files, dir (the path), write, note
    ; The existing four visible volume rows also carry the current copy. No
    ; percentage guesses or new UI geometry: the native record owns its phase.
    call form_explorer_copy_status
    test eax, eax
    jnz  .out
    lea  rax, [rel form_fsstatus_buf]
    mov  [rel form_fsroot_cur], rax
    mov  byte [rax], 0
    lea  rax, [rel form_fsstatus_buf + FORM_FSSTATUS_BUF - 1]
    mov  [rel form_fsroot_end], rax
    lea  rdi, [rel str_fsstatus_mount]
    call form_fsroot_put_str
    mov  edi, [rel vfs_disk_handle]
    cmp  edi, -1
    je   .m_none
    call vfs_mount_ptr
    test rax, rax
    jz   .m_none
    mov  rdi, [rax + 16]              ; fsmount.name
    call form_fsroot_put_str
    jmp  .m_done
.m_none:
    lea  rdi, [rel str_fsstatus_none]
    call form_fsroot_put_str
.m_done:
    lea  rdi, [rel str_fsstatus_files]
    call form_fsroot_put_str
    mov  edi, [rel form_exp_count]
    call form_fsroot_put_dec
    lea  rdi, [rel str_fsstatus_dir]
    call form_fsroot_put_str
    lea  rdi, [rel form_fs_cwd]
    call form_fsroot_put_name
    lea  rdi, [rel str_fsstatus_write]
    call form_fsroot_put_str
    call ntfs_disk_write_state        ; 1 armed / 0 readonly / -1 not an NTFS mount
    lea  rdi, [rel str_fsstatus_armed]
    cmp  eax, 1
    je   .w_put
    lea  rdi, [rel str_fsstatus_ro]
    test eax, eax
    jz   .w_put
    lea  rdi, [rel str_fsstatus_na]
.w_put:
    call form_fsroot_put_str
    cmp  qword [rel form_exp_note], 0
    je   .out
    lea  rdi, [rel str_fsstatus_note]
    call form_fsroot_put_str
    mov  rdi, [rel form_exp_note]
    call form_fsroot_put_str
.out:
    ret

; Native copy observer for fs.status. RAX=1 rendered, 0 ordinary volume rows.
; Observe this Explorer's accepted job by exact id; before its first copy use
; the native latest job. A refused start leaves the previous record intact. Read it afresh for every render,
; including WINTREE. No backend step, cancel, flush, or disk read here. The BSP
; GUI owns this bounded render; these helpers neither yield nor perform I/O.
form_explorer_copy_status:
    push rbx
    call session_shell_local_authority
    cmp  rax, PRIN_OWNER
    jne  .none
    call form_exp_observed_job
    test rax, rax
    jz   .none
    mov  rbx, rax
    mov  eax, [rbx + fs_copy_job.state]
    dec  eax
    cmp  eax, FS_JOB_QUEUED - 1
    ja   .none                         ; absent/invalid state never means completed
    lea  rax, [rel form_fsstatus_buf]
    mov  [rel form_fsroot_cur], rax
    mov  byte [rax], 0
    lea  rax, [rel form_fsstatus_buf + FORM_FSSTATUS_BUF - 1]
    mov  [rel form_fsroot_end], rax
    lea  rdi, [rel str_exp_copy_job]
    call form_fsroot_put_str
    mov  rdi, [rbx + fs_copy_job.id]
    call form_fsroot_put_dec
    lea  rdi, [rel str_exp_copy_mount]
    call form_fsroot_put_str
    mov  edi, [rbx + fs_copy_job.mount]
    call form_fsroot_put_dec
    lea  rdi, [rel str_exp_copy_bytes]
    call form_fsroot_put_str
    mov  rdi, [rbx + fs_copy_job.done]
    call form_fsroot_put_dec
    lea  rdi, [rel str_exp_copy_of]
    call form_fsroot_put_str
    mov  rdi, [rbx + fs_copy_job.total]
    cmp  rdi, FS_TOTAL_UNKNOWN
    je   .unknown_total
    call form_fsroot_put_dec
    jmp  .phase
.unknown_total:
    lea  rdi, [rel str_exp_copy_unknown]
    call form_fsroot_put_str
.phase:
    lea  rdi, [rel str_exp_copy_phase]
    call form_fsroot_put_str
    mov  eax, [rbx + fs_copy_job.state]
    dec  eax
    imul eax, eax, 20
    lea  rdi, [rel str_exp_copy_phases]
    add  rdi, rax
    call form_fsroot_put_str
    mov  rax, [rbx + fs_copy_job.id]
    cmp  rax, [rel form_exp_owned_job]
    jne  .cancel_hint_done
    call form_exp_copy_cancellable
    test eax, eax
    jz   .cancel_hint_done
    lea  rdi, [rel str_exp_copy_cancel_hint]
    call form_fsroot_put_str
.cancel_hint_done:
    mov  rax, [rbx + fs_copy_job.id]
    cmp  rax, [rel form_exp_cancel_notice_job]
    jne  .notice_done
    mov  eax, [rbx + fs_copy_job.state]
    sub  eax, FS_JOB_DONE
    cmp  eax, FS_JOB_FAILED - FS_JOB_DONE
    jbe  .notice_done                 ; terminal provider phase stands alone
    movzx eax, byte [rel form_exp_cancel_notice]
    dec  eax
    cmp  eax, 2
    ja   .notice_done
    imul eax, eax, 20
    lea  rdi, [rel str_exp_cancel_notices]
    add  rdi, rax
    call form_fsroot_put_str
.notice_done:
    lea  rdi, [rel str_exp_copy_durable]
    call form_fsroot_put_str
    mov  eax, [rbx + fs_copy_job.durable]
    lea  rdi, [rel str_exp_copy_unknown]
    cmp  eax, FS_DUR_UNCERTAIN
    ja   .durable
    imul eax, eax, 11
    lea  rdi, [rel str_exp_copy_durability]
    add  rdi, rax
.durable:
    call form_fsroot_put_str
    movzx eax, byte [rel form_exp_paste_notice]
    sub  eax, 2
    cmp  eax, 3
    ja   .request_done
    imul eax, 32
    lea  rdi, [rel str_exp_paste_notices]
    add  rdi, rax
    call form_fsroot_put_str
.request_done:
    ; RCQ-21: FSJOB's own clock rule and closed result word, from the same
    ; record (vfs_copy_rate, fs_job_result_word). Row 5 is elapsed and rate;
    ; row 6 exists for a failed, tree or keep-both job, or entry failures.
    mov  rdi, rbx
    call vfs_copy_rate
    push rdx
    push rax
    lea  rdi, [rel str_exp_copy_elapsed]
    call form_fsroot_put_str
    pop  rdi
    call form_fsroot_put_dec
    lea  rdi, [rel str_exp_copy_rate]
    call form_fsroot_put_str
    pop  rdi
    cmp  rdi, FS_RATE_UNKNOWN
    je   .rate_unknown
    call form_fsroot_put_dec
    lea  rdi, [rel str_exp_copy_bps]
    jmp  .rate
.rate_unknown:
    lea  rdi, [rel str_exp_copy_unknown]
.rate:
    call form_fsroot_put_str
    push r12
    xor  r12d, r12d                    ; row 6 not started
    cmp  dword [rbx + fs_copy_job.state], FS_JOB_FAILED
    jne  .result_done
    call .detail
    lea  rdi, [rel str_exp_copy_result]
    call form_fsroot_put_str
    mov  rdi, rbx
    call fs_job_result_word
    mov  rdi, rax
    call form_fsroot_put_str
.result_done:
    cmp  dword [rbx + fs_copy_job.tree], 1
    jne  .tree_done
    call .detail
    lea  rdi, [rel str_exp_copy_files]
    call form_fsroot_put_str
    mov  edi, [rbx + fs_copy_job.files]
    call form_fsroot_put_dec
    lea  rdi, [rel str_exp_copy_skipped]
    call form_fsroot_put_str
    mov  edi, [rbx + fs_copy_job.skipped]
    call form_fsroot_put_dec
.tree_done:
    ; Smart copy may reach DONE with uncopied entries. Show the engine's
    ; count independently of its phase, bytes, kept count and durability.
    cmp  dword [rbx + fs_copy_job.tree], 1
    je   .failed_count
    cmp  dword [rbx + fs_copy_job.failed], 0
    je   .failed_count_done
.failed_count:
    call .detail
    lea  rdi, [rel str_exp_copy_failed_count]
    call form_fsroot_put_str
    mov  edi, [rbx + fs_copy_job.failed]
    call form_fsroot_put_dec
.failed_count_done:
    cmp  dword [rbx + fs_copy_job.kept], 0
    je   .kept_done
    call .detail
    lea  rdi, [rel str_exp_copy_kept]
    call form_fsroot_put_str
    mov  edi, [rbx + fs_copy_job.kept]
    call form_fsroot_put_dec
.kept_done:
    pop  r12
    mov  eax, 1
    pop  rbx
    ret
.detail:                               ; row 6 opens with ',', its later fields with ' '
    lea  rdi, [rel str_exp_copy_row]
    test r12d, r12d
    jz   .detail_put
    lea  rdi, [rel str_exp_copy_sep]
.detail_put:
    mov  r12d, 1
    jmp  form_fsroot_put_str
.none:
    call form_exp_unavailable_status
    pop  rbx
    ret

; RCQ-21: a paint records what the local owner saw, never a cancellation.
; Each bounded stamp carries ID, login/token, device/start/mount and window.
; WINTREE/remote/injected dispatches cannot arm the stamp. EDI=status widget.
form_explorer_copy_shown:
    push rbx
    push r12
    mov  r12d, edi
    cmp  byte [rel cmd_in_dispatch], 0
    jne  .out
    mov  qword [rel form_exp_copy_shown], 0
    call session_shell_local_authority
    cmp  rax, PRIN_OWNER
    jne  .out
    mov  [rel form_exp_copy_shown + 8], rax
    mov  [rel form_exp_copy_shown + 16], rdx
    cmp  r12d, [rel wgt_count]
    jae  .out
    mov  edi, r12d
    call wgt_slot_ptr
    cmp  dword [rax + WGI_BIND], FORM_BIND_FS_STATUS
    jne  .out
    mov  ecx, [rel wgt_listview_type]
    inc  ecx
    cmp  [rax + WGI_TYPE], ecx
    jne  .out
    test dword [rax + WGI_FLAGS], 1
    jz   .out
    cmp  dword [rax + WGI_H], 102    ; all four existing status rows fit
    jl   .out
    mov  ecx, [rax + WGI_WIN]
    cmp  ecx, WM_MAX
    jae  .out
    cmp  ecx, [rel form_active_slot + FORM_EXPLORER_INDEX*4]
    jne  .out
    cmp  ecx, [rel wm_focus]
    jne  .out
    lea  rax, [rel wm_state]
    cmp  dword [rax + rcx*4], WM_VISIBLE
    jne  .out
    mov  [rel form_exp_copy_shown + 48], rcx
    mov  [rel form_exp_copy_shown + 56], r12
    call form_exp_observed_job
    test rax, rax
    jz   .out
    mov  rbx, rax
    call form_exp_copy_cancellable
    test eax, eax
    jz   .out
    mov  rax, [rbx + fs_copy_job.dev]
    mov  [rel form_exp_copy_shown + 24], rax
    mov  rax, [rbx + fs_copy_job.t_start]
    mov  [rel form_exp_copy_shown + 32], rax
    mov  eax, [rbx + fs_copy_job.mount]
    mov  [rel form_exp_copy_shown + 40], rax
    mov  rax, [rbx + fs_copy_job.id]
    mov  [rel form_exp_copy_shown], rax
.out:
    pop  r12
    pop  rbx
    ret

; RBX=native record -> EAX=1 only when cancellation can still be requested.
form_exp_copy_cancellable:
    mov  eax, [rbx + fs_copy_job.state]
    cmp  eax, FS_JOB_RUNNING
    je   .yes
    cmp  eax, FS_JOB_VERIFYING
    je   .yes
    cmp  eax, FS_JOB_QUEUED
    je   .yes
    xor  eax, eax
    ret
.yes:
    mov  eax, 1
    ret

; R12=stamp -> RAX=native record / 0. Pure, bounded custody recheck.
form_exp_copy_guard:
    cmp  byte [rel cmd_in_dispatch], 0
    jne  .bad
    call session_shell_local_authority
    cmp  rax, PRIN_OWNER
    jne  .bad
    cmp  rax, [r12 + 8]
    jne  .bad
    cmp  rdx, [r12 + 16]
    jne  .bad
    cmp  qword [rel form_exp_owned_job], 0
    je   .owner_checked
    mov  rax, [rel form_exp_owned_job]
    cmp  rax, [r12]
    jne  .bad
    mov  rax, [rel session_key_handle]
    cmp  rax, [rel form_exp_owned_job + 56]
    jne  .bad
.owner_checked:
    mov  rcx, [r12 + 48]
    cmp  rcx, WM_MAX
    jae  .bad
    cmp  ecx, [rel wm_focus]
    jne  .bad
    cmp  ecx, [rel form_active_slot + FORM_EXPLORER_INDEX*4]
    jne  .bad
    lea  rax, [rel wm_state]
    cmp  dword [rax + rcx*4], WM_VISIBLE
    jne  .bad
    mov  rdi, [r12 + 56]
    mov  eax, [rel wgt_count]
    cmp  rdi, rax
    jae  .bad
    call wgt_slot_ptr
    cmp  dword [rax + WGI_BIND], FORM_BIND_FS_STATUS
    jne  .bad
    mov  ecx, [rel wgt_listview_type]
    inc  ecx
    cmp  [rax + WGI_TYPE], ecx
    jne  .bad
    mov  ecx, [r12 + 48]
    cmp  [rax + WGI_WIN], ecx
    jne  .bad
    test dword [rax + WGI_FLAGS], 1
    jz   .bad
    cmp  dword [rax + WGI_H], 102
    jl   .bad
    mov  rdi, [r12]
    test rdi, rdi
    jz   .bad
    call vfs_copy_status
    test rax, rax
    jz   .bad
    mov  rdx, [rax + fs_copy_job.dev]
    cmp  rdx, [r12 + 24]
    jne  .bad
    mov  rdx, [rax + fs_copy_job.t_start]
    cmp  rdx, [r12 + 32]
    jne  .bad
    mov  edx, [rax + fs_copy_job.mount]
    cmp  rdx, [r12 + 40]
    jne  .bad
    ret
.bad:
    xor  eax, eax
    ret

; R12=stamp, EDI=file widget -> EAX=1 if still the actual focused file list.
form_exp_copy_focus:
    cmp  edi, [rel wgt_focus_id]
    jne  .bad
    cmp  edi, [rel wgt_count]
    jae  .bad
    call wgt_slot_ptr
    cmp  dword [rax + WGI_BIND], FORM_BIND_FS_ROOT
    jne  .bad
    mov  ecx, [rel wgt_listview_type]
    inc  ecx
    cmp  [rax + WGI_TYPE], ecx
    jne  .bad
    test dword [rax + WGI_FLAGS], 1
    jz   .bad
    mov  ecx, [r12 + 48]
    cmp  [rax + WGI_WIN], ecx
    jne  .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; Escape on the focused Explorer file list queues once; no provider mutation
; or registry dispatch on the input stack. EDI=file widget -> EAX=1 consumed.
form_explorer_cancel_request:
    push rbx
    push r12
    mov  ebx, edi
    lea  r12, [rel form_exp_copy_shown]
    call form_exp_copy_focus
    test eax, eax
    jz   .no
    call form_exp_copy_guard
    test rax, rax
    jz   .no
    push rbx
    mov  rbx, rax
    call form_exp_copy_cancellable
    pop  rbx
    test eax, eax
    jz   .no
    cmp  byte [rel form_exp_cancel_pending], 0
    jne  .yes
    mov  rax, [r12]
    cmp  rax, [rel form_exp_cancel_notice_job]
    jne  .queue
    cmp  byte [rel form_exp_cancel_notice], 2
    je   .yes                         ; repeated Escape does not reissue an accepted request
.queue:
    lea  rdi, [rel form_exp_copy_pending]
    mov  rsi, r12
    mov  ecx, 9
    rep  movsq
    mov  [rel form_exp_copy_pending + 64], rbx
    mov  rax, [r12]
    mov  [rel form_exp_cancel_notice_job], rax
    mov  byte [rel form_exp_cancel_notice], 1
    mov  byte [rel form_exp_cancel_pending], 1
.yes:
    mov  eax, 1
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

; One idle attempt. Spend before any callback; refusals never wait/replay.
; The command gate remains the only mutator. FSCANCEL's RSP_CODE is an OK
; shell even for text errors, so a fresh native state is required for accepted.
form_explorer_cancel_tick:
    cmp  byte [rel form_exp_cancel_pending], 1
    jne  .ret
    mov  byte [rel form_exp_cancel_pending], 0
    mov  byte [rel form_exp_cancel_notice], 3
    push rbx
    push r12
    lea  r12, [rel form_exp_copy_pending]
    mov  edi, [r12 + 64]
    call form_exp_copy_focus
    test eax, eax
    jz   .out
    call form_exp_copy_guard
    test rax, rax
    jz   .out
    mov  rbx, rax
    call form_exp_copy_cancellable
    test eax, eax
    jz   .out
    mov  rdi, [r12]
    lea  rsi, [rel form_exp_cancel_arg]
    call fmt_dec                     ; <=20 digits, then 18 bytes including NUL
    lea  rdi, [rel form_exp_cancel_arg]
    add  rdi, rax
    lea  rsi, [rel str_exp_cancel_nonce]
    mov  ecx, 18
    rep  movsb                       ; nonce is an echo token, not authority/idempotency
    lea  rdi, [rel str_exp_cancel_verb]
    call command_lookup
    cmp  eax, -1
    je   .out
    push rax
    lea  rdi, [rel form_exp_cancel_req]
    xor  eax, eax
    mov  ecx, REQ_SZ / 8
    rep  stosq
    pop  rax
    mov  [rel form_exp_cancel_req + REQ_VERB], rax
    mov  qword [rel form_exp_cancel_req + REQ_CAP], -1
    lea  rax, [rel form_exp_cancel_arg]
    mov  [rel form_exp_cancel_req + REQ_ARG], rax
    mov  qword [rel form_exp_cancel_req + REQ_SOURCE], CMD_SOURCE_CONSOLE
    mov  rax, [r12 + 8]
    mov  [rel form_exp_cancel_req + REQ_PRINCIPAL], rax
    lea  rdi, [rel form_exp_cancel_req]
    lea  rsi, [rel form_exp_cancel_rsp]
    call command_dispatch
    test rax, rax
    jnz  .out
    call form_exp_copy_guard
    test rax, rax
    jz   .out
    cmp  dword [rax + fs_copy_job.state], FS_JOB_CANCELLING
    je   .accepted
    cmp  dword [rax + fs_copy_job.state], FS_JOB_CANCELLED
    jne  .out
.accepted:
    mov  byte [rel form_exp_cancel_notice], 2
.out:
    pop  r12
    pop  rbx
.ret:
    ret

; New/opened Explorer never inherits a retired window's action or snapshot.
form_explorer_cancel_reset:
    call form_exp_context_reset
    call form_exp_observe_reset
    mov  byte [rel form_exp_file_kind], 0
    mov  byte [rel form_exp_file_ready], 0
    mov  byte [rel form_exp_paste_pending], 0
    mov  qword [rel form_exp_owned_job], 0
    mov  byte [rel form_exp_owned_queued], 0
    mov  byte [rel form_exp_paste_notice], 0
    mov  qword [rel form_exp_copy_shown], 0
    mov  byte [rel form_exp_cancel_pending], 0
    mov  byte [rel form_exp_cancel_notice], 0
    ret

; Explorer file-copy selection is RAM-local to this window and owner lifetime.
; Ctrl+C captures one complete file/directory and its kind; Ctrl+V spends it
; into one deferred FSCOPY MODE=keepboth. Directories add TREE=1 on the same
; volume or native FAT32 -> ext4 route. Distinct mounts use BOTH saved labels.
; No shared text clipboard entry or FS policy is changed.
; Common stamp: [8] owner, [16] epoch, [24/32] ops/priv, [40] mount,
; [48] window, [56] local key, [64] file widget. File stamps additionally
; retain [72] registered name pointer and [80..95] bounded original label.
; Never dispatch on the input/render stack.
form_exp_file_guard:
    cmp  byte [rel cmd_in_dispatch], 0
    jne  .bad
    call session_shell_local_authority
    cmp  rax, PRIN_OWNER
    jne  .bad
    cmp  rax, [r12 + 8]
    jne  .bad
    cmp  rdx, [r12 + 16]
    jne  .bad
    mov  rcx, [r12 + 48]
    cmp  rcx, WM_MAX
    jae  .bad
    cmp  ecx, [rel wm_focus]
    jne  .bad
    cmp  ecx, [rel form_active_slot + FORM_EXPLORER_INDEX*4]
    jne  .bad
    lea  rax, [rel wm_state]
    cmp  dword [rax + rcx*4], WM_VISIBLE
    jne  .bad
    mov  edi, [r12 + 64]
    call form_exp_copy_focus
    test eax, eax
    jz   .bad
    mov  rax, [rel session_key_handle]
    cmp  rax, [r12 + 56]
    jne  .bad
    ; A source remains bound to its original mount across FSSEL navigation.
    mov  edi, [r12 + 40]
    call vfs_mount_ptr
    test rax, rax
    jz   .bad
    mov  rcx, [rax]                  ; fsmount.ops
    cmp  rcx, [r12 + 24]
    jne  .bad
    mov  rcx, [rax + 8]              ; fsmount.priv
    cmp  rcx, [r12 + 32]
    jne  .bad
    mov  rdx, [rax + 16]             ; exact registered name and original bytes
    cmp  rdx, [r12 + 72]
    jne  .bad
    xor  ecx, ecx
.name:
    cmp  ecx, 16
    jae  .bad
    mov  al, [rdx + rcx]
    cmp  al, [r12 + 80 + rcx]
    jne  .bad
    test al, al
    jz   .named
    inc  ecx
    jmp  .name
.named:
    call form_exp_file_label
    test eax, eax
    jz   .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; Capture the selected mount's immutable identity into R12, leaving owner,
; epoch, window, widget and original key untouched. Labels fit native FSCOPY's
; 1..15-byte grammar; reject delimiters rather than inventing an alias.
form_exp_file_mount:
    mov  edi, [rel vfs_disk_handle]
    mov  [r12 + 40], rdi
    call vfs_mount_ptr
    test rax, rax
    jz   .bad
    mov  rcx, [rax]
    test rcx, rcx
    jz   .bad
    mov  [r12 + 24], rcx
    mov  rcx, [rax + 8]
    mov  [r12 + 32], rcx
    mov  rdx, [rax + 16]
    test rdx, rdx
    jz   .bad
    mov  [r12 + 72], rdx
    xor  ecx, ecx
.name:
    cmp  ecx, 16
    jae  .bad
    mov  al, [rdx + rcx]
    mov  [r12 + 80 + rcx], al
    test al, al
    jz   .end
    cmp  al, 32
    jbe  .bad
    cmp  al, 127
    jae  .bad
    cmp  al, ':'
    je   .bad
    cmp  al, '/'
    je   .bad
    cmp  al, '\'
    je   .bad
    inc  ecx
    jmp  .name
.end:
    test ecx, ecx
    jz   .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; Native qualified paths resolve the FIRST exact label. Refuse duplicate or
; changed registry bindings that would resolve our saved label to another mount.
form_exp_file_label:
    push rbx
    xor  ebx, ebx
.mount:
    cmp  ebx, VFS_MAX_MOUNTS
    jae  .bad
    mov  edi, ebx
    call vfs_mount_ptr
    test rax, rax
    jz   .bad
    mov  rdx, [rax + 16]
    test rdx, rdx
    jz   .next
    xor  ecx, ecx
.name:
    cmp  ecx, 16
    jae  .next
    mov  al, [rdx + rcx]
    cmp  al, [r12 + 80 + rcx]
    jne  .next
    test al, al
    jz   .found
    inc  ecx
    jmp  .name
.found:
    cmp  rbx, [r12 + 40]
    jne  .bad
    mov  eax, 1
    pop  rbx
    ret
.next:
    inc  ebx
    jmp  .mount
.bad:
    xor  eax, eax
    pop  rbx
    ret

; Validate BOTH original stamps, with only destination required to remain the
; selected view. Backend BEGIN still owns arm, device, medium and file custody.
form_exp_paste_guard:
    push r12
    lea  r12, [rel form_exp_file_stamp]
    call form_exp_file_guard
    test eax, eax
    jz   .out
    lea  r12, [rel form_exp_dest_stamp]
    call form_exp_file_guard
    test eax, eax
    jz   .out
    mov  edi, [rel vfs_disk_handle]
    cmp  rdi, [r12 + 40]
    jne  .bad
    mov  rax, [rel form_exp_file_stamp + 40]
    cmp  rax, [r12 + 40]
    je   .ok                          ; same-volume retains unqualified grammar
    cmp  byte [rel form_exp_file_kind], FORM_EXP_DIR
    je   .tree                        ; integrated native FAT32/NTFS tree routes
    mov  rdx, [r12 + 24]
    cmp  rdx, [rel form_exp_file_stamp + 24]
    jne  .ntfs_regular                ; accepted3055 exact native foreign-source predicate
    cmp  qword [rdx + fs_ops.copy_between], 0
    je   .bad
    cmp  qword [rdx + fs_ops.copy], 0
    je   .bad
    cmp  qword [r12 + 32], 0
    je   .bad
    cmp  qword [rel form_exp_file_stamp + 32], 0
    je   .bad
    jmp  .ok
.ntfs_regular:
    ; Native NTFS/exFAT -> ext4 regular-file routes have different source and
    ; destination tables. Match the maintained destination lifecycle and the
    ; exact mounted source context; labels never establish capability.
    mov  rdx, [r12 + 24]
    lea  rax, [rel ext_op_copy_between]
    cmp  [rdx + fs_ops.copy_between], rax
    jne  .bad
    lea  rax, [rel ext_op_copy]
    cmp  [rdx + fs_ops.copy], rax
    jne  .bad
    cmp  qword [r12 + 32], 0
    je   .bad
    mov  edi, [rel form_exp_file_stamp + 40]
    call vfs_mount_ptr
    test rax, rax
    jz   .bad
    mov  rdi, rax
    call ntfs_disk_source_device       ; pure check: no select, arm, read or grant
    test rax, rax
    jnz  .ok
    ; Re-resolve the original stamp for the other maintained regular-file
    ; source. Do not infer capability from a label or reuse scratch registers.
    mov  edi, [rel form_exp_file_stamp + 40]
    call vfs_mount_ptr
    test rax, rax
    jz   .bad
    mov  rdi, rax
    call exfat_disk_source_device      ; pure registered native context check
    test rax, rax
    jz   .bad
    jmp  .ok                          ; BEGIN still owns custody, distinct media and authority
.tree:
    ; Match the shipped destination BEGIN and STEP/CANCEL capability. Other
    ; tree providers remain unsupported here even if they can copy files.
    mov  rdx, [r12 + 24]
    lea  rax, [rel ext_op_copy_between]
    cmp  [rdx + fs_ops.copy_between], rax
    jne  .bad
    lea  rax, [rel ext_op_copy]
    cmp  [rdx + fs_ops.copy], rax
    jne  .bad
    cmp  qword [r12 + 32], 0
    je   .bad
    mov  edi, [rel form_exp_file_stamp + 40]
    call vfs_mount_ptr
    test rax, rax
    jz   .bad
    mov  rdi, rax
    ; Pure native table/context check, including read-only FAT mounts. This
    ; never selects, arms, reads, binds a job or acquires a source write grant.
    call fat32_disk_source_device
    test rax, rax
    jnz  .ok
    ; The integrated NTFS tree walker has the same destination lifecycle.
    ; Resolve again rather than relying on the FAT predicate's scratch regs.
    mov  edi, [rel form_exp_file_stamp + 40]
    call vfs_mount_ptr
    test rax, rax
    jz   .bad
    mov  rdi, rax
    call ntfs_disk_source_device
    test rax, rax
    jz   .bad
    ; Native BEGIN still checks distinct media, ext4 kind, destination owner
    ; arm/intent and complete source custody; no consumer grant is inferred.
.ok:
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r12
    ret

; Bounded unquoted native path. RDI=80-byte output, RSI=cwd, RDX=basename.
; The shipped tokenizer splits spaces; unsupported bytes never reach it.
; Directory paths may contain canonical UTF8; regular files keep their profile.
; Both components and the joined NUL must fit the existing 79-char envelope.
form_exp_file_path:
    xor  ecx, ecx
.cwd:
    cmp  ecx, FORM_FS_CWD_MAX - 1
    jae  .bad
    mov  al, [rsi + rcx]
    test al, al
    jz   .slash
    cmp  al, 32
    jbe  .bad
    cmp  al, 127
    je   .bad
    jb   .ascii
    cmp  byte [rel form_exp_file_kind], FORM_EXP_DIR
    jne  .bad                         ; retain regular-file input profile
.ascii:
    cmp  al, '\'
    je   .bad
    mov  [rdi + rcx], al
    inc  ecx
    jmp  .cwd
.slash:
    test ecx, ecx
    jz   .bad
    cmp  byte [rdi], '/'
    jne  .bad
    cmp  byte [rdi + rcx - 1], '/'
    je   .name
    mov  byte [rdi + rcx], '/'
    inc  ecx
.name:
    xor  r8d, r8d
.next:
    cmp  ecx, FORM_FS_CWD_MAX
    jae  .bad
    mov  al, [rdx + r8]
    test al, al
    jz   .done
    cmp  ecx, FORM_FS_CWD_MAX - 1
    jae  .bad
    cmp  al, 32
    jbe  .bad
    cmp  al, 127
    je   .bad
    jb   .name_ascii
    cmp  byte [rel form_exp_file_kind], FORM_EXP_DIR
    jne  .bad
.name_ascii:
    cmp  al, '/'
    je   .bad
    cmp  al, '\'
    je   .bad
    mov  [rdi + rcx], al
    inc  r8d
    inc  ecx
    jmp  .next
.done:
    test r8d, r8d
    jz   .bad
    mov  byte [rdi + rcx], 0
    mov  eax, ecx
    cmp  byte [rel form_exp_file_kind], FORM_EXP_DIR
    jne  .ret
    ; Complete owned names/CWD only: validate canonical UTF8 without changing
    ; identity bytes or the 79-byte path envelope. No display escape is parsed.
    push rdi
    mov  rsi, rdi
    mov  edx, FORM_FS_CWD_MAX - 1
    call ue_utf8_cstr_prefix
    pop  rdi
    test edx, edx
    jnz  .bad
.ret:
    ret
.bad:
    mov  byte [rdi], 0
    xor  eax, eax
    ret

; EDI=actual focused file widget. Invalid gestures clear any old selection.
form_explorer_file_copy:
    push rbx
    push r12
    mov  ebx, edi
    call form_exp_observe_reset
    mov  byte [rel form_exp_file_ready], 0
    cmp  byte [rel form_exp_paste_pending], 0
    jne  .out
    lea  r12, [rel form_exp_file_stamp]
    call session_shell_local_authority
    mov  [r12 + 8], rax
    mov  [r12 + 16], rdx
    cmp  rax, PRIN_OWNER
    jne  .out
    mov  [r12 + 64], rbx
    mov  edi, ebx
    call wgt_slot_ptr
    mov  eax, [rax + WGI_WIN]
    mov  [r12 + 48], rax
    mov  rax, [rel session_key_handle]
    mov  [r12 + 56], rax
    call form_exp_file_mount
    test eax, eax
    jz   .out
    call form_exp_file_guard
    test eax, eax
    jz   .out
    mov  rax, [r12 + 40]
    cmp  rax, [rel form_exp_listing_mount]
    jne  .unsupported
    mov  rax, [r12 + 24]
    cmp  rax, [rel form_exp_listing_ops]
    jne  .unsupported
    mov  rax, [r12 + 32]
    cmp  rax, [rel form_exp_listing_priv]
    jne  .unsupported                ; do not copy an old mount's cached row
    call form_fsroot_refresh
    mov  eax, [rel form_exp_cursor]
    cmp  eax, [rel form_exp_count]
    jae  .unsupported
    cmp  eax, FORM_FSROOT_CAP
    jae  .unsupported
    lea  rdx, [rel form_exp_flags]
    test byte [rdx + rax], FORM_EXP_CLIPPED
    jnz  .unsupported
    mov  dl, [rdx + rax]
    and  dl, FORM_EXP_DIR
    mov  [rel form_exp_file_kind], dl   ; pin kind with exact owned name/path
    imul eax, FORM_EXP_NAME
    lea  rdx, [rel form_exp_names]
    add  rdx, rax
    mov  rsi, rdx
    lea  rdi, [rel form_exp_file_name]
    mov  ecx, FORM_EXP_NAME
    rep  movsb
    lea  rdi, [rel form_exp_file_src]
    lea  rsi, [rel form_fs_cwd]
    lea  rdx, [rel form_exp_file_name]
    call form_exp_file_path
    test eax, eax
    jz   .unsupported
    mov  byte [rel form_exp_file_ready], 1
    lea  rax, [rel str_exp_file_ready]
    cmp  byte [rel form_exp_file_kind], FORM_EXP_DIR
    jne  .ready
    lea  rax, [rel str_exp_dir_ready]
.ready:
    mov  [rel form_exp_note], rax
    mov  edi, 1
    call form_exp_observe_capture
    mov  eax, 1
    jmp  .done
.unsupported:
    lea  rax, [rel str_exp_file_unsupported]
    mov  [rel form_exp_note], rax
.out:
    xor  eax, eax
.done:
    pop  r12
    pop  rbx
    ret

form_explorer_file_paste:
    push r12
    lea  r12, [rel form_exp_file_stamp]
    cmp  edi, [r12 + 64]
    jne  .out
    cmp  byte [rel form_exp_file_ready], 1
    jne  .out
    mov  byte [rel form_exp_file_ready], 0 ; spend even if custody/path is lost
    call form_exp_file_guard
    test eax, eax
    jz   .unsupported
    cmp  byte [rel form_exp_paste_pending], 0
    jne  .out
    mov  rsi, r12
    lea  rdi, [rel form_exp_dest_stamp]
    mov  ecx, 9
    rep  movsq                        ; owner/window/key remain original source's
    lea  r12, [rel form_exp_dest_stamp]
    call form_exp_file_mount
    test eax, eax
    jz   .unsupported
    call form_exp_paste_guard
    test eax, eax
    jz   .unsupported
    lea  rdi, [rel form_exp_file_dst]
    lea  rsi, [rel form_fs_cwd]
    lea  rdx, [rel form_exp_file_name]
    call form_exp_file_path
    test eax, eax
    jz   .unsupported
    lea  rsi, [rel form_fs_cwd]
    lea  rdi, [rel form_exp_paste_cwd]
    mov  ecx, FORM_FS_CWD_MAX
    rep  movsb
    mov  rax, [rel vfs_write_generation]
    mov  [rel form_exp_paste_generation], rax
    cmp  qword [rel form_exp_paste_seq], -1
    je   .out                         ; no nonce wrap/reuse in this boot
    inc  qword [rel form_exp_paste_seq]
    mov  rdi, [rel form_exp_paste_seq]
    lea  rsi, [rel form_exp_paste_nonce]
    mov  edx, 16
    call fmt_hex
    mov  byte [rel form_exp_paste_pending], 1
    mov  byte [rel form_exp_paste_notice], 2
    lea  rax, [rel str_exp_paste_pending]
    mov  [rel form_exp_note], rax
    mov  eax, 1
    jmp  .done
.unsupported:
    lea  rax, [rel str_exp_file_unsupported]
    mov  [rel form_exp_note], rax
.out:
    xor  eax, eax
.done:
    pop  r12
    ret

; Idle-only one-shot dispatch through the unchanged registry/owner admission.
form_explorer_paste_tick:
    cmp  byte [rel form_exp_paste_pending], 1
    jne  .ret
    mov  byte [rel form_exp_paste_pending], 0
    mov  byte [rel form_exp_paste_notice], 3
    push rbx
    push r12
    lea  r12, [rel form_exp_dest_stamp]
    lea  rax, [rel str_exp_paste_not_sent]
    mov  [rel form_exp_note], rax
    call form_exp_paste_guard
    test eax, eax
    jz   .out
    ; FSSEL (including away-and-back) and intervening namespace writes already
    ; advance this native invalidation counter. Compare only BEFORE BEGIN:
    ; our own admitted FSCOPY is allowed to advance it during dispatch.
    mov  rax, [rel vfs_write_generation]
    cmp  rax, [rel form_exp_paste_generation]
    jne  .out
    lea  rsi, [rel form_fs_cwd]
    lea  rdi, [rel form_exp_paste_cwd]
    mov  ecx, FORM_FS_CWD_MAX
    repe cmpsb
    jne  .out                         ; navigation after paste invalidates it
    lea  rdi, [rel form_exp_paste_arg]
    mov  rax, [rel form_exp_file_stamp + 40]
    cmp  rax, [r12 + 40]
    je   .source_path
    lea  rsi, [rel form_exp_file_stamp + 80]
    call .append
    mov  byte [rdi], ':'
    inc  rdi
.source_path:
    lea  rsi, [rel form_exp_file_src]
    call .append
    mov  byte [rdi], ' '
    inc  rdi
    mov  rax, [rel form_exp_file_stamp + 40]
    cmp  rax, [r12 + 40]
    je   .dest_path
    lea  rsi, [r12 + 80]
    call .append
    mov  byte [rdi], ':'
    inc  rdi
.dest_path:
    lea  rsi, [rel form_exp_file_dst]
    call .append
    mov  byte [rdi], ' '
    inc  rdi
    lea  rsi, [rel form_exp_paste_nonce]
    call .append
    lea  rsi, [rel str_exp_paste_mode]
    call .append                     ; files: <= 223 bytes including NUL
    cmp  byte [rel form_exp_file_kind], FORM_EXP_DIR
    jne  .argument_done
    lea  rsi, [rel str_exp_paste_tree]
    call .append                     ; qualified tree: <= 230 bytes including NUL
.argument_done:
    mov  byte [rdi], 0
    lea  rdi, [rel str_exp_paste_verb]
    call command_lookup
    cmp  eax, -1
    je   .out
    mov  ebx, eax
    lea  rdi, [rel form_exp_paste_req]
    xor  eax, eax
    mov  ecx, REQ_SZ / 8
    rep  stosq
    mov  [rel form_exp_paste_req + REQ_VERB], rbx
    mov  qword [rel form_exp_paste_req + REQ_CAP], -1
    lea  rax, [rel form_exp_paste_arg]
    mov  [rel form_exp_paste_req + REQ_ARG], rax
    mov  qword [rel form_exp_paste_req + REQ_SOURCE], CMD_SOURCE_CONSOLE
    mov  rax, [r12 + 8]
    mov  [rel form_exp_paste_req + REQ_PRINCIPAL], rax
    mov  byte [rel fs_out_ready], 0
    lea  rdi, [rel form_exp_paste_req]
    lea  rsi, [rel form_exp_paste_rsp]
    call command_dispatch
    mov  byte [rel form_exp_paste_notice], 4
    lea  rcx, [rel str_exp_paste_unconfirmed]
    mov  [rel form_exp_note], rcx
    test rax, rax
    jnz  .out
    call form_exp_paste_guard
    test eax, eax
    jz   .out
    cmp  byte [rel fs_out_ready], 1
    jne  .out
    ; A fresh explicit native refusal is known, unlike a missing/malformed reply.
    lea  rsi, [rel fs_out_buf]
    lea  rdi, [rel str_exp_paste_error]
    mov  ecx, 11
    repe cmpsb
    jne  .accepted_reply
    mov  byte [rel form_exp_paste_notice], 5
    lea  rax, [rel str_exp_paste_refused]
    mov  [rel form_exp_note], rax
    jmp  .out
.accepted_reply:
    ; Closed native response, not RSP_CODE (which is OK for text errors).
    lea  rsi, [rel fs_out_buf]
    lea  rdi, [rel str_exp_paste_prefix]
    mov  ecx, 13
    repe cmpsb
    jne  .out
    lea  rdi, [rel form_exp_paste_nonce]
    mov  ecx, 16
    repe cmpsb
    jne  .out
    lea  rdi, [rel str_exp_paste_job]
    mov  ecx, 8
    repe cmpsb
    jne  .out
    xor  eax, eax
    xor  ecx, ecx
    mov  r8d, 10
.digit:
    movzx ebx, byte [rsi]
    sub  ebx, '0'
    cmp  ebx, 9
    ja   .number
    inc  ecx
    cmp  ecx, 20
    ja   .out
    mul  r8
    test rdx, rdx
    jnz  .out
    add  rax, rbx
    jc   .out
    inc  rsi
    jmp  .digit
.number:
    test ecx, ecx
    jz   .out
    cmp  byte [rsi], ' '
    jne  .out                         ; native replies always have TOTAL/QUEUED/DUP
    test rax, rax
    jz   .out
    mov  rdi, rax
    call vfs_copy_status
    test rax, rax
    jz   .out
    mov  edx, [rax + fs_copy_job.mount]
    cmp  rdx, [r12 + 40]
    jne  .out
    mov  edx, [rax + fs_copy_job.state]
    dec  edx
    cmp  edx, FS_JOB_QUEUED - 1
    ja   .out
    ; Persist exact provider job identity. Later jobs never redirect this UI.
    mov  rbx, rax
    lea  rdi, [rel form_exp_owned_job]
    mov  rsi, r12
    mov  ecx, 9
    rep  movsq
    mov  rax, [rbx + fs_copy_job.id]
    mov  [rel form_exp_owned_job], rax
    mov  rax, [rbx + fs_copy_job.dev]
    mov  [rel form_exp_owned_job + 24], rax
    mov  rax, [rbx + fs_copy_job.t_start]
    mov  [rel form_exp_owned_job + 32], rax
    cmp  dword [rbx + fs_copy_job.state], FS_JOB_QUEUED
    sete byte [rel form_exp_owned_queued]
    mov  edi, 2
    call form_exp_observe_capture
    mov  byte [rel form_exp_paste_notice], 0
    lea  rax, [rel str_exp_paste_accepted]
    mov  [rel form_exp_note], rax
    mov  qword [rel form_fsroot_snapshot_ms], 0
.out:
    pop  r12
    pop  rbx
.ret:
    ret
.append:
    lodsb
    test al, al
    jz   .appended
    stosb
    jmp  .append
.appended:
    ret

; Shared progress and cancel paint use this same original job. A replaced or
; retired record is unavailable, never a new job under the old UI identity.
; Honest history limit: native status may retire an ended job. Keep its
; original identity visible without borrowing bytes/results from a later job.
form_exp_unavailable_status:
    cmp  qword [rel form_exp_owned_job], 0
    je   .none
    call session_shell_local_authority
    cmp  rax, PRIN_OWNER
    jne  .none
    cmp  rax, [rel form_exp_owned_job + 8]
    jne  .none
    cmp  rdx, [rel form_exp_owned_job + 16]
    jne  .none
    mov  rax, [rel session_key_handle]
    cmp  rax, [rel form_exp_owned_job + 56]
    jne  .none
    lea  rax, [rel form_fsstatus_buf]
    mov  [rel form_fsroot_cur], rax
    mov  byte [rax], 0
    lea  rax, [rel form_fsstatus_buf + FORM_FSSTATUS_BUF - 1]
    mov  [rel form_fsroot_end], rax
    lea  rdi, [rel str_exp_copy_job]
    call form_fsroot_put_str
    mov  rdi, [rel form_exp_owned_job]
    call form_fsroot_put_dec
    lea  rdi, [rel str_exp_copy_mount]
    call form_fsroot_put_str
    mov  rdi, [rel form_exp_owned_job + 40]
    call form_fsroot_put_dec
    lea  rdi, [rel str_exp_copy_unavailable]
    call form_fsroot_put_str
    mov  eax, 1
    ret
.none:
    xor  eax, eax
    ret

form_exp_observed_job:
    cmp  qword [rel form_exp_owned_job], 0
    je   .latest
    call session_shell_local_authority
    cmp  rax, [rel form_exp_owned_job + 8]
    jne  .none
    cmp  rdx, [rel form_exp_owned_job + 16]
    jne  .none
    mov  rax, [rel session_key_handle]
    cmp  rax, [rel form_exp_owned_job + 56]
    jne  .none
    mov  rdi, [rel form_exp_owned_job]
    call vfs_copy_status
    test rax, rax
    jz   .none
    mov  edx, [rax + fs_copy_job.mount]
    cmp  rdx, [rel form_exp_owned_job + 40]
    jne  .none
    cmp  byte [rel form_exp_owned_queued], 1
    jne  .started
    cmp  dword [rax + fs_copy_job.state], FS_JOB_QUEUED
    je   .started
    ; Same native id after queue admission: BEGIN legitimately sets dev/start.
    ; Latch that provider transition once; it cannot redirect to a later id.
    mov  rdx, [rax + fs_copy_job.dev]
    mov  [rel form_exp_owned_job + 24], rdx
    mov  rdx, [rax + fs_copy_job.t_start]
    mov  [rel form_exp_owned_job + 32], rdx
    mov  byte [rel form_exp_owned_queued], 0
.started:
    mov  rdx, [rax + fs_copy_job.dev]
    cmp  rdx, [rel form_exp_owned_job + 24]
    jne  .none
    mov  rdx, [rax + fs_copy_job.t_start]
    cmp  rdx, [rel form_exp_owned_job + 32]
    jne  .none
    mov  edx, [rax + fs_copy_job.mount]
    cmp  rdx, [rel form_exp_owned_job + 40]
    jne  .none
    ret
.latest:
    xor  edi, edi
    jmp  vfs_copy_status
.none:
    xor  eax, eax
    ret

form_build_fsroot:                    ; EDI = the file list's widget id (its height is the page)
    push rbx
    mov  ebx, edi
    call form_fsroot_refresh
    mov  edi, ebx
    call form_exp_page_of
    call form_fsroot_render
    lea  rax, [rel form_fsroot_buf]
    pop  rbx
    ret

form_build_fsstatus:
    call form_fsroot_refresh
    call form_fsstatus_render
    lea  rax, [rel form_fsstatus_buf]
    ret

; form_exp_entered — form_fs_cwd changed: page 1, nothing selected, no note,
; and the snapshot is invalid at once (the next paint, key or press lists the
; new folder; the previous folder's rows are never shown or opened). -> EAX 1
form_exp_entered:
    cmp  byte [rel form_exp_paste_pending], 1
    jne  .view
    mov  byte [rel form_exp_paste_pending], 0 ; even navigation away and back spends it
    mov  byte [rel form_exp_paste_notice], 3
.view:
    mov  dword [rel form_exp_top], 0
    mov  dword [rel form_exp_cursor], FORM_EXP_NONE
    mov  qword [rel form_exp_note], 0
    mov  dword [rel form_exp_count], 0
    mov  dword [rel form_exp_rows], 0
    mov  dword [rel form_exp_last_press], FORM_EXP_NONE
    mov  qword [rel form_fsroot_snapshot_ms], 0
    mov  eax, 1
    ret

; form_explorer_up -> EAX 1 went to the parent folder, 0 already at "/".
form_explorer_up:
    mov  ecx, [rel form_fs_cwd_len]
    lea  rdi, [rel form_fs_cwd]
    cmp  ecx, 1
    jbe  .root                        ; never above "/"
    cmp  byte [rdi + rcx - 1], '/'
    jne  .scan
    dec  ecx                          ; "/A/" is "/A"
.scan:
    test ecx, ecx
    jz   .parent_root
    dec  ecx
    cmp  byte [rdi + rcx], '/'
    jne  .scan
    test ecx, ecx
    jnz  .cut
.parent_root:
    mov  ecx, 1                       ; the parent of "/A" is "/"
.cut:
    mov  byte [rdi + rcx], 0
    mov  [rel form_fs_cwd_len], ecx
    jmp  form_exp_entered
.root:
    xor  eax, eax
    ret

; form_explorer_open(EDI = row ref) -> EAX 1 the folder changed, 0 not.
; ".." goes up; a folder row appends its name; a file row goes to its viewer and
; the folder stays; a path that would reach FORM_FS_CWD_MAX (or a clipped name)
; is refused with a note and the folder stays as it is.
form_explorer_open:
    cmp  edi, FORM_EXP_UP
    je   form_explorer_up
    xor  eax, eax
    test edi, edi
    js   .out
    cmp  edi, [rel form_exp_count]
    jae  .out
    lea  rdx, [rel form_exp_flags]
    movzx ecx, byte [rdx + rdi]
    lea  r9, [rel str_exp_note_name]
    test ecx, FORM_EXP_DIR
    jz   form_explorer_open_file      ; EDI the row, ECX its flags
    test ecx, FORM_EXP_CLIPPED
    jnz  .refuse
    imul edi, edi, FORM_EXP_NAME
    lea  rsi, [rel form_exp_names]
    add  rsi, rdi
    xor  ecx, ecx
.len:
    mov  al, [rsi + rcx]
    test al, al
    jz   .len_done
    cmp  al, '/'
    je   .refuse                      ; not one path component
    inc  ecx
    jmp  .len
.len_done:
    test ecx, ecx
    jz   .refuse
    lea  rdi, [rel form_fs_cwd]
    mov  edx, [rel form_fs_cwd_len]
    lea  r8d, [rdx + rcx]
    cmp  byte [rdi + rdx - 1], '/'
    je   .bound
    inc  r8d                          ; the separator
.bound:
    lea  r9, [rel str_exp_note_long]
    cmp  r8d, FORM_FS_CWD_MAX
    jae  .refuse
    cmp  byte [rdi + rdx - 1], '/'
    je   .copy
    mov  byte [rdi + rdx], '/'
    inc  edx
.copy:
    mov  al, [rsi]
    mov  [rdi + rdx], al
    inc  rsi
    inc  edx
    dec  ecx
    jnz  .copy
    mov  byte [rdi + rdx], 0
    mov  [rel form_fs_cwd_len], edx
    jmp  form_exp_entered
.refuse:
    mov  [rel form_exp_note], r9
    xor  eax, eax
.out:
    ret

; form_explorer_open_file(EDI row, ECX flags, R9 the name note) -> EAX 0. The
; viewer reads the mount this listing came from, or nothing: a changed selection
; never opens a same-named file elsewhere. A clipped name is never completed.
; form_exp_bad_path_byte(AL) -> ZF set for a byte no opened path carries, as
; img_source_acquire refuses. Clobbers flags only.
form_exp_bad_path_byte:
    cmp  al, 0x5C
    je   .out
    cmp  al, ':'
    je   .out
    cmp  al, 0x7F
    je   .out
    cmp  al, 0x20
    jae  .fine
    cmp  al, al
.out:
    ret
.fine:
    or   al, al
    ret

form_explorer_open_file:
    test ecx, FORM_EXP_CLIPPED
    jnz  .refuse
    imul edi, edi, FORM_EXP_NAME
    lea  rsi, [rel form_exp_names]
    add  rsi, rdi
    lea  rdi, [rel form_exp_open_path]
    lea  rdx, [rel form_fs_cwd]
    mov  ecx, [rel form_fs_cwd_len]
    test ecx, ecx
    jz   .refuse
.cwd:
    mov  al, [rdx]
    call form_exp_bad_path_byte       ; a folder's name reaches the read too
    je   .refuse
    mov  [rdi], al
    inc  rdx
    inc  rdi
    dec  ecx
    jnz  .cwd
    cmp  byte [rdi - 1], '/'
    je   .name
    mov  byte [rdi], '/'
    inc  rdi
.name:
    xor  ecx, ecx
.copy:
    mov  al, [rsi + rcx]
    test al, al
    jz   .copied
    cmp  al, '/'
    je   .refuse                      ; not one path component
    call form_exp_bad_path_byte
    je   .refuse
    mov  [rdi + rcx], al
    inc  ecx
    cmp  ecx, FORM_EXP_NAME
    jb   .copy
    jmp  .refuse
.copied:
    test ecx, ecx
    jz   .refuse
    add  rdi, rcx
    mov  byte [rdi], 0
    lea  rax, [rel form_exp_open_path]
    sub  rdi, rax
    push rdi                          ; the path's bytes
    mov  rdi, [rel form_exp_listing_mount]
    cmp  rdi, -1
    je   .stale
    call vfs_mount_ptr
    test rax, rax
    jz   .stale
    mov  rcx, [rax]
    cmp  rcx, [rel form_exp_listing_ops]
    jne  .stale
    mov  rcx, [rax + 8]
    cmp  rcx, [rel form_exp_listing_priv]
    jne  .stale
    mov  rdx, [rsp]
    mov  edi, [rel form_exp_listing_mount]
    lea  rsi, [rel form_exp_open_path]
    call text_view_open
    test eax, eax
    jz   .viewed
    cmp  eax, 1
    jne  .not_shown
    mov  rdx, [rsp]                   ; not a text type: the image viewer sniffs its bytes
    mov  edi, [rel form_exp_listing_mount]
    lea  rsi, [rel form_exp_open_path]
    call image_viewer_open
    test eax, eax
    jz   .viewed
.not_shown:
    add  rsp, 8
    lea  r9, [rel str_exp_note_noviewer]
    cmp  eax, 3
    jne  .refuse
    lea  r9, [rel str_exp_note_owner]
.refuse:
    mov  [rel form_exp_note], r9
.out:
    xor  eax, eax
    ret
.viewed:
    add  rsp, 8
    xor  eax, eax
    ret
.stale:
    add  rsp, 8
    lea  r9, [rel str_exp_note_stale]
    jmp  .refuse

; form_exp_follow — scroll so the selected entry is on the page.
form_exp_follow:
    mov  eax, [rel form_exp_cursor]
    cmp  eax, FORM_EXP_UP
    jne  .entry
    xor  eax, eax                     ; ".." heads page 1
.entry:
    test eax, eax
    js   .out                         ; nothing selected
    cmp  eax, [rel form_exp_top]
    jge  .fit
    mov  [rel form_exp_top], eax
    ret
.fit:
    push rbx
    mov  ebx, FORM_FSROOT_CAP + 1     ; bounded
.step:
    mov  edi, [rel form_exp_top]
    call form_exp_slots
    add  eax, [rel form_exp_top]
    cmp  [rel form_exp_cursor], eax
    jl   .done
    inc  dword [rel form_exp_top]
    dec  ebx
    jnz  .step
.done:
    pop  rbx
.out:
    ret

; form_exp_scroll(EDI = 1 down / 0 up) — one page, the selection stays.
form_exp_scroll:
    test edi, edi
    jz   .up
    mov  edi, [rel form_exp_top]
    call form_exp_slots
    test edx, edx
    jz   .out                         ; nothing below
    add  [rel form_exp_top], eax
    ret
.up:
    mov  eax, [rel form_exp_page]
    sub  eax, 3                       ; "..", "^ above", "... more"
    cmp  eax, 1
    jge  .back
    mov  eax, 1
.back:
    sub  [rel form_exp_top], eax
    jns  .out
    mov  dword [rel form_exp_top], 0
.out:
    ret

; form_explorer_key(EAX = translated key) -> EAX 1 consumed. The file list is
; focused: Enter opens the selection, Backspace goes up, Up/Down/PgUp/PgDn/
; Home/End move the selection (the first move selects the first row).
form_explorer_key:
    push rbx
    push r12
    push r13
    mov  ebx, eax
    call form_fsroot_refresh          ; the current listing (the selection kept by name)
    cmp  ebx, GUI_KEY_BACKSPACE
    je   .up
    cmp  ebx, GUI_KEY_ENTER
    je   .enter
    cmp  ebx, GUI_KEY_UP
    je   .move
    cmp  ebx, GUI_KEY_DOWN
    je   .move
    cmp  ebx, GUI_KEY_PGUP
    je   .move
    cmp  ebx, GUI_KEY_PGDN
    je   .move
    cmp  ebx, GUI_KEY_HOME
    je   .move
    cmp  ebx, GUI_KEY_END
    je   .move
    xor  eax, eax
    jmp  .out
.up:
    call form_explorer_up
    jmp  .consumed
.enter:
    mov  edi, [rel form_exp_cursor]
    cmp  edi, FORM_EXP_NONE
    je   .consumed
    call form_explorer_open
    jmp  .consumed
.move:
    xor  r12d, r12d                   ; lo: the first entry, or ".." below "/"
    cmp  dword [rel form_fs_cwd_len], 1
    jbe  .lo
    mov  r12d, FORM_EXP_UP
.lo:
    mov  r13d, [rel form_exp_count]
    dec  r13d                         ; hi
    cmp  r13d, r12d
    jl   .consumed                    ; nothing to select
    mov  eax, r12d
    cmp  ebx, GUI_KEY_HOME
    je   .bound
    mov  eax, r13d
    cmp  ebx, GUI_KEY_END
    je   .bound
    mov  eax, r12d
    cmp  dword [rel form_exp_cursor], FORM_EXP_NONE
    je   .bound
    mov  eax, [rel form_exp_page]
    sub  eax, 3                       ; a page step
    cmp  eax, 1
    jge  .stepped
    mov  eax, 1
.stepped:
    cmp  ebx, GUI_KEY_PGUP
    je   .back
    cmp  ebx, GUI_KEY_PGDN
    je   .fwd
    mov  eax, 1
    cmp  ebx, GUI_KEY_UP
    je   .back
.fwd:
    add  eax, [rel form_exp_cursor]
    jmp  .bound
.back:
    neg  eax
    add  eax, [rel form_exp_cursor]
.bound:
    cmp  eax, r12d
    jge  .lo_ok
    mov  eax, r12d
.lo_ok:
    cmp  eax, r13d
    jle  .hi_ok
    mov  eax, r13d
.hi_ok:
    mov  [rel form_exp_cursor], eax
    call form_exp_follow
.consumed:
    mov  eax, 1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; form_explorer_key_filter(EDI = focused widget, EAX = key) -> EAX 1 consumed:
; the kit's wgt_key_filter seam, chained. Only the Explorer's file list
; (bind fs.root) is handled here; anything else, and keys the list does not
; use (Tab, text), go to the filter installed before it. Escape requests
; cancellation only for an owner-painted, still-live copy of this Explorer.
form_explorer_key_filter:
    push rdi
    push rax
    cmp  edi, [rel wgt_count]
    jae  .other
    call wgt_slot_ptr
    cmp  dword [rax + WGI_BIND], FORM_BIND_FS_ROOT
    jne  .other
    mov  ecx, [rel wgt_listview_type]
    inc  ecx
    cmp  [rax + WGI_TYPE], ecx
    jne  .other
    mov  eax, [rsp]
    cmp  eax, 3                       ; native Ctrl+C
    je   .copy
    cmp  eax, 22                      ; native Ctrl+V
    je   .paste
    cmp  eax, GUI_KEY_ESC
    jne  .navigation
    mov  edi, [rsp + 8]
    call form_explorer_cancel_request
    jmp  .handled
.copy:
    mov  edi, [rsp + 8]
    call form_explorer_file_copy
    jmp  .handled
.paste:
    call form_explorer_file_paste
    jmp  .handled
.navigation:
    call form_explorer_key
.handled:
    test eax, eax
    jz   .other
    call wmx_draw_all
    add  rsp, 16
    mov  eax, 1
    ret
.other:
    pop  rax
    pop  rdi
    mov  rdx, [rel form_exp_key_prev]
    test rdx, rdx
    jz   .none
    jmp  rdx
.none:
    xor  eax, eax
    ret

; Installed on the first press on a file list, after every boot-time filter
; (the lock screen sets wgt_key_filter without chaining at init; the Console,
; Terminal and Start chain after it). Keys only reach the list once a press
; has focused it, so nothing is lost by installing late.
form_explorer_hook_keys:
    cmp  byte [rel form_exp_keys_hooked], 1
    je   .out
    mov  rax, [rel wgt_key_filter]
    mov  [rel form_exp_key_prev], rax
    lea  rax, [rel form_explorer_key_filter]
    mov  [rel wgt_key_filter], rax
    mov  byte [rel form_exp_keys_hooked], 1
.out:
    ret

; form_explorer_capture(EDI widget, ESI x, EDX y, ECX phase, R8D button) ->
; EAX 1 consumed: the listview type's pointer capture (wgt_type_bind_capture
; in form_loader_declare). Every listview but the Explorer's file list
; declines, so they keep the WM's raise-only rule. A press focuses the list
; (keys follow), selects the row under it; a double-click (wm_pointer_clicks
; == 2) opens it only when its first press, within FORM_EXP_DBLCLICK_MS, hit
; the same entry: a press on "^ above" / "... more" pages, and a relist
; between the presses keeps the first press on its entry by name (refresh),
; so the row under the second press may be another entry and must not open.
; Drag and release are ignored. Presses against a row map older than the
; listing (relisted since the paint) only repaint.
form_explorer_capture:
    push rdi
    push rsi
    push rdx
    push rcx
    push r8
    call form_exp_controls_capture
    pop  r8
    pop  rcx
    pop  rdx
    pop  rsi
    pop  rdi
    test eax, eax
    jnz  .ret
    cmp  r8d, 1                       ; middle is never a file activation
    je   .miss
    cmp  r8d, 2
    ja   .miss
    xor  eax, eax
    cmp  ecx, WGT_CAPTURE_PRESS
    jne  .ret
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, edi
    mov  r13d, esi
    mov  r14d, edx
    sub  rsp, 16
    mov  [rsp], r8d
    call wgt_slot_ptr
    mov  rbx, rax
    xor  eax, eax
    cmp  dword [rbx + WGI_BIND], FORM_BIND_FS_ROOT
    jne  .out
    call form_explorer_hook_keys
    call wmx_frame_may_focus          ; SEC D2: only an OWNER frame moves the keyboard;
    test eax, eax                     ; selection and navigation stay any origin
    jnz  .no_focus
    mov  edi, [rbx + WGI_WIN]
    mov  esi, r13d
    mov  edx, r14d
    call wgt_focus_at                 ; the file list takes the keyboard
.no_focus:
    mov  eax, [rbx + WGI_Y]
    add  eax, FORM_EXP_LV_HEAD
    mov  r15d, FORM_EXP_NONE          ; the row ref this press hit (none yet)
    sub  r14d, eax
    jl   .background                  ; header offers sort/refresh via context
    mov  eax, [rel form_exp_gen]
    cmp  eax, [rel form_exp_rows_gen]
    jne  .consumed                    ; relisted since the paint: rows not as shown
    mov  eax, r14d
    xor  edx, edx
    mov  ecx, FORM_EXP_LV_ROW
    div  ecx
    cmp  eax, [rel form_exp_rows]
    jae  .background                  ; background offers sort/refresh
    lea  rcx, [rel form_exp_rowmap]
    mov  r15d, [rcx + rax*4]
    cmp  dword [rsp], 2
    je   .context
    cmp  r15d, FORM_EXP_ABOVE
    je   .page_up
    cmp  r15d, FORM_EXP_MORE
    je   .page_down
    cmp  r15d, FORM_EXP_NOTE
    je   .inert
    mov  [rel form_exp_cursor], r15d
    cmp  dword [rel wm_pointer_clicks], 2
    jne  .consumed
    cmp  r15d, [rel form_exp_last_press]
    jne  .consumed                    ; the first press hit another entry (paged or relisted)
    call boot_ms_now
    sub  rax, [rel form_exp_last_press_ms]
    cmp  rax, FORM_EXP_DBLCLICK_MS
    ja   .consumed                    ; an old press (another window, a reopen) never pairs
    mov  edi, r15d
    call form_explorer_open
    mov  r15d, FORM_EXP_NONE
    jmp  .consumed
.background:
    cmp  dword [rsp], 2
    jne  .consumed
    mov  r15d, FORM_EXP_NONE
.context:
    cmp  r15d, FORM_EXP_UP
    je   .context_selected
    cmp  r15d, [rel form_exp_count]
    jae  .context_open
.context_selected:
    mov  [rel form_exp_cursor], r15d
.context_open:
    mov  edi, r12d
    mov  esi, r13d
    mov  edx, [rbx + WGI_Y]
    add  edx, FORM_EXP_LV_HEAD
    add  edx, r14d
    mov  ecx, r15d
    call form_exp_context_open
    mov  r15d, FORM_EXP_NONE           ; right presses never pair into activation
    jmp  .consumed
.page_up:
    xor  edi, edi
    call form_exp_scroll
    jmp  .inert
.page_down:
    mov  edi, 1
    call form_exp_scroll
.inert:
    mov  r15d, FORM_EXP_NONE          ; paging/note rows never pair into an open
.consumed:
    mov  [rel form_exp_last_press], r15d
    call boot_ms_now
    mov  [rel form_exp_last_press_ms], rax
    call wmx_draw_all
    mov  eax, 1
.out:
    add  rsp, 16
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
.ret:
    ret
.miss:
    xor  eax, eax
    ret

; FSCD <path> — the Explorer's directory (v1.1 paths).  GUI view state only: no
; disk I/O at verb time; the fs.root bind lists it on the next snapshot/repaint.
; Absolute "/DIR/SUB" (<= FORM_FS_CWD_MAX); "/" returns to the root listing.
form_cmd_verb_fscd:
    call cmd_handler_prologue
    push rbx
    push r12
    mov  r12, rsi
    mov  rbx, [rdi + REQ_ARG]
    test rbx, rbx
    jz   .bad
    cmp  byte [rbx], '/'
    jne  .bad
    xor  ecx, ecx
.len:
    mov  al, [rbx + rcx]
    test al, al
    jz   .len_done
    cmp  al, ' '
    je   .len_done
    inc  ecx
    cmp  ecx, FORM_FS_CWD_MAX
    jae  .bad
    jmp  .len
.len_done:
    test ecx, ecx
    jz   .bad
    lea  rdi, [rel form_fs_cwd]           ; RIP-relative base first: [rel sym + reg] is NOT
    xor  edx, edx                         ; encodable and silently degrades to the unrelocated RVA
.cp:
    cmp  edx, ecx
    jae  .cp_done
    mov  al, [rbx + rdx]
    mov  [rdi + rdx], al
    inc  edx
    jmp  .cp
.cp_done:
    mov  byte [rdi + rdx], 0
    mov  [rel form_fs_cwd_len], ecx
    call form_exp_entered                 ; next paint takes a fresh listing, page 1
    call form_out_reset
    lea  rdi, [rel str_fscd_ok]
    call form_out_put_str
    lea  rdi, [rel form_fs_cwd]
    call form_out_put_str
    mov  byte [rel form_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_OK
    pop  r12
    pop  rbx
    ret
.bad:
    call form_out_reset
    lea  rdi, [rel str_fscd_err]
    call form_out_put_str
    mov  byte [rel form_out_ready], 1
    pop  r12
    pop  rbx
    ret

%include "gui/form_explorer_controls.inc"

%include "gui/form_explorer_observe_cache.inc"

form_wintree_append_state:
    push rbx
    push r12
    mov  r12d, edi
    call wgt_slot_ptr
    mov  rbx, rax
    cmp  dword [rbx + WGI_LAYER], 1
    jne  .ordinary_tree
    lea  rdi, [rel tree_overlay_layer]
    call f1_put_str
    mov  edi, 1
    call f1_put_dec
.ordinary_tree:
    lea  rdi, [rel tree_label]
    call f1_put_str
    mov  rdi, [rbx + WGI_LABEL]
    call f1_put_escaped
    mov  eax, [rbx + WGI_TYPE]
    dec  eax
    cmp  eax, [rel wgt_grid_type]
    jne  .existing_type
    lea  rdi, [rel tree_grid_rows]
    call f1_put_str
    mov  edi, [rbx + WGI_ROWS]
    call f1_put_dec
    lea  rdi, [rel tree_grid_cols]
    call f1_put_str
    mov  edi, [rbx + WGI_COLS]
    call f1_put_dec
    jmp  .out
.existing_type:
    cmp  eax, 3                       ; listview
    jne  .progress
    lea  rdi, [rel tree_list_mode]
    call f1_put_str
    lea  rdi, [rel str_lv_list]
    cmp  byte [rbx + LV_MODE], LV_MODE_DROPDOWN
    jne  .list_mode_tree
    lea  rdi, [rel str_lv_dropdown]
    jmp  .list_mode_out
.list_mode_tree:
    cmp  byte [rbx + LV_MODE], LV_MODE_TREE
    jne  .list_mode_radio
    lea  rdi, [rel str_lv_tree]
    jmp  .list_mode_out
.list_mode_radio:
    cmp  byte [rbx + LV_MODE], LV_MODE_RADIO
    jne  .list_mode_out
    lea  rdi, [rel str_lv_radio]
.list_mode_out:
    call f1_put_str
    cmp  byte [rbx + LV_MODE], LV_MODE_DROPDOWN
    jne  .list_tree_state
    lea  rdi, [rel tree_list_overlay]
    call f1_put_str
    mov  edi, [rbx + LV_OVERLAY]
    test edi, edi
    jz   .list_overlay_out
    dec  edi
.list_overlay_out:
    call f1_put_dec
    lea  rdi, [rel tree_dropdown_open]
    call f1_put_str
    movzx edi, byte [rbx + LV_OPEN]
    call f1_put_dec
.list_tree_state:
    cmp  byte [rbx + LV_MODE], LV_MODE_TREE
    jne  .list_radio_state
    lea  rdi, [rel tree_list_parents]
    call f1_put_str
    mov  edi, r12d
    call wgt_listview_format_parents
    mov  rdi, rax
    call f1_put_str
    lea  rdi, [rel tree_list_expanded]
    call f1_put_str
    mov  rdi, [rbx + LV_EXPANDED]
    call f1_put_dec
    jmp  .list_common
.list_radio_state:
    cmp  byte [rbx + LV_MODE], LV_MODE_RADIO
    jne  .list_common
    lea  rdi, [rel tree_list_disabled]
    call f1_put_str
    mov  rdi, [rbx + LV_DISABLED]
    call f1_put_dec
.list_common:
    lea  rdi, [rel tree_scroll]
    call f1_put_str
    mov  edi, [rbx + WGI_SCROLL]
    call f1_put_dec
    lea  rdi, [rel tree_selection]
    call f1_put_str
    mov  edi, [rbx + WGI_SEL_LO]
    call f1_put_dec
    lea  rdi, [rel tree_value]
    call f1_put_str
    mov  edi, [rbx + WGI_SEL_LO]
    call f1_put_dec
    lea  rdi, [rel tree_intent]
    call f1_put_str
    mov  edi, [rbx + WGI_INTENT]
    call f1_put_dec
    lea  rdi, [rel tree_intent_seq]
    call f1_put_str
    mov  rdi, [rbx + WGI_INTENT_SEQ]
    call f1_put_dec
    jmp  .out
.progress:
    cmp  eax, [rel wgt_chart_type]
    jne  .progress_type
    lea  rdi, [rel tree_chart_mode]
    call f1_put_str
    lea  rdi, [rel str_chart_sparkline]
    cmp  byte [rbx + CHART_MODE], CHART_MODE_BAR
    jne  .chart_mode_ready
    lea  rdi, [rel str_chart_bar]
.chart_mode_ready:
    call f1_put_str
    lea  rdi, [rel tree_chart_count]
    call f1_put_str
    mov  edi, [rbx + CHART_COUNT]
    call f1_put_dec
    lea  rdi, [rel tree_chart_scale]
    call f1_put_str
    mov  rdi, [rbx + CHART_SCALE]
    call f1_put_dec
    lea  rdi, [rel tree_intent_seq]
    call f1_put_str
    mov  rdi, [rbx + WGI_INTENT_SEQ]
    call f1_put_dec
    jmp  .out
.progress_type:
    cmp  eax, 4
    jne  .scalar
    lea  rdi, [rel tree_value]
    call f1_put_str
    mov  rdi, [rbx + WGI_NUM]
    call f1_put_dec
    lea  rdi, [rel tree_max]
    call f1_put_str
    mov  rdi, [rbx + WGI_MAXVAL]
    call f1_put_dec
%macro PGTREE 2
    lea  rdi, [rel %1]
    call f1_put_str
    mov  edi, r12d
    lea  rsi, [rel %2]
    call wgt_progress_get
    mov  rdi, rax
    call f1_put_str
%endmacro
    PGTREE tree_pg_text_mode, str_pg_text_mode
    PGTREE tree_pg_indeterminate, str_pg_indeterminate
    ; Keep six-record WINTREE pages bounded. Detailed rate/phase/ticks/job_id
    ; remain available through the same state's public WIDGETGET projection.
%undef PGTREE
    jmp  .out
.scalar:
    cmp  eax, 8                       ; toggle
    je   .scalar_state
    cmp  eax, 9                       ; slider
    je   .scalar_state
    cmp  eax, 10                      ; numeric stepper
    jne  .out
.scalar_state:
    lea  rdi, [rel tree_value]
    call f1_put_str
    mov  rdi, [rbx + WGI_NUM]
    call f1_put_dec
    lea  rdi, [rel tree_min]
    call f1_put_str
    mov  rdi, [rbx + WGI_MINVAL]
    call f1_put_dec
    lea  rdi, [rel tree_max]
    call f1_put_str
    mov  rdi, [rbx + WGI_MAXVAL]
    call f1_put_dec
    lea  rdi, [rel tree_step]
    call f1_put_str
    mov  rdi, [rbx + WGI_STEP]
    call f1_put_dec
    lea  rdi, [rel tree_intent]
    call f1_put_str
    mov  edi, [rbx + WGI_INTENT]
    call f1_put_dec
    lea  rdi, [rel tree_intent_seq]
    call f1_put_str
    mov  rdi, [rbx + WGI_INTENT_SEQ]
    call f1_put_dec
.out:
    pop  r12
    pop  rbx
    ret

; Cadence hook: derive rates and refresh every netmon-bound object's pixels.
form_netmon_tick:
    push rbx
    push r12
    push r13
    call form_exp_context_tick         ; consume native menu generation once
    call form_explorer_paste_tick      ; deferred native start, before status repaint
    call form_explorer_cancel_tick     ; deferred action, before status repaint
    call form_ephemeral_reap
    test eax, eax
    jz   .lifetime_synced
    call ephform_transport_discard
.lifetime_synced:
%ifdef PAOS_NTFS_UNSIGNED_TEST
    ; QEMU oracle only (the harness has no owner-signed FORMLOAD: AUTHSTAT carries
    ; no durable counter there).  Open the Explorer once, on the first audit edge
    ; after an NTFS volume became the FS-verb mount (FSSEL ntfs0).  Never built
    ; into shipped binaries: there the owner opens it with a signed FORMLOAD.
    cmp  byte [rel form_explorer_autoload_done], 0
    jne  .autoload_done
    call ntfs_disk_write_state
    cmp  eax, -1
    je   .autoload_done
    mov  byte [rel form_explorer_autoload_done], 1
    mov  edi, FORM_EXPLORER_INDEX
    xor  esi, esi
    mov  edx, 1                       ; focus it (front of z-order) = what the pixel witness grades
    call form_load_index
    lea  rdi, [rel str_form_explorer_autoload]
    call serial_string
.autoload_done:
%endif
%if !PAOS_PUBLIC_BUILD
    mov  edi, 2
    xor  esi, esi
    call pmod_netmon_query
%endif
    xor  ebx, ebx
.loop:
    cmp  ebx, [rel wgt_count]
    jae  .done
    mov  edi, ebx
    call wgt_slot_ptr
    mov  ecx, [rax + WGI_BIND]
.fs:
    ; explorer listviews (fs.root / fs.status) repaint on this same audit edge,
    ; so an FSSEL that moves the FS-verb mount becomes visible within one
    ; cadence.  The rows come from the 1 s snapshot: no disk read per repaint.
    cmp  ecx, FORM_BIND_FS_DRIVES
    je   .fs_draw
    cmp  ecx, FORM_BIND_FS_DETAILS
    je   .fs_draw
    cmp  ecx, FORM_BIND_FS_ROOT
    je   .fs_draw
    cmp  ecx, FORM_BIND_NET_MEMBERS    ; RCQ-35: keep-owned rows, same focused repaint
    je   .fs_draw
    cmp  ecx, FORM_BIND_NET_ADDRESS
    je   .fs_draw
    cmp  ecx, FORM_BIND_FS_STATUS
    jne  .module_value
.fs_draw:
    cmp  byte [rel dpms_blanked], 1   ; RCQ-27 L3: no periodic repaint on a blanked screen
    je   .next                        ; (the next tick after the wake repaints)
    mov  ecx, [rax + WGI_WIN]
    cmp  ecx, [rel wm_focus]          ; only the front (focused) window repaints from the
    jne  .next                        ; tick: painting an occluded window's widgets here
    mov  edi, ebx                     ; would bypass the compositor's z-order.  Others
    call wgt_draw_id                  ; refresh on the next wmx_draw_all (raise/open).
    jmp  .next
.module_value:
%if !PAOS_PUBLIC_BUILD
    ; The signed provider chooses text/number and applies its binding policy.
    ; The keep only publishes the returned field through the existing widget API.
    mov  rdx, [rax + WGI_MAXVAL]
    mov  edi, [rax + WGI_TYPE]
    dec  edi
    cmp  edi, [rel wgt_chart_type]
    jne  .module_max_ready
    mov  edx, 100                     ; netmon provider's established rate ceiling
.module_max_ready:
    push rdx
    push rcx
    mov  rsi, rsp
    mov  edi, 5
    call pmod_netmon_query
    add  rsp, 16
    cmp  r8d, 1
    je   .text_value
    cmp  r8d, 2
    jne  .next
    mov  r12, r9
    mov  edi, ebx
    call wgt_slot_ptr
    mov  ecx, [rax + WGI_TYPE]
    dec  ecx
    cmp  ecx, [rel wgt_chart_type]
    jne  .number_value
    mov  esi, r12d
    mov  edi, ebx
    call wgt_chart_push               ; the sample is kept even while blanked
    test eax, eax
    jnz  .next
    cmp  byte [rel dpms_blanked], 1   ; RCQ-27 L3
    je   .next
    mov  edi, ebx
    call wgt_draw_id
    jmp  .next
.number_value:
    mov  [rax + WGI_NUM], r12
    cmp  byte [rel dpms_blanked], 1   ; RCQ-27 L3
    je   .next
    mov  edi, ebx
    call wgt_draw_id
    jmp  .next
.text_value:
    cmp  byte [rel dpms_blanked], 1   ; RCQ-27 L3: wgt_set_text draws; the provider republishes
    je   .next                        ; the text on the next tick after the wake
    mov  rsi, rax
    mov  edi, ebx
    call wgt_set_text
%endif
.next:
    inc  ebx
    jmp  .loop
.done:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Register the GUI customers into the one core table. Periods come from the
; current machine's calibrated TSC; registration remains an additive edge call.
form_cadence_live_init:
    push rbx
    call cadence_registry_init
    ; Preserve the shipped first-sample baseline in disposable module state.
%if !PAOS_PUBLIC_BUILD
    mov  edi, 3
    xor  esi, esi
    call pmod_netmon_query
%endif
    mov  rbx, [rel tsc_khz]
    imul rbx, rbx, 1000
    test rbx, rbx
    jnz  .have_ticks
    mov  rbx, 1000000
.have_ticks:
    lea  rdi, [rel str_cad_id_clock]
    xor  esi, esi
    mov  edx, 1
    mov  rcx, rbx
    lea  r8, [rel taskbar_clock_tick]
    call cadence_register_named
    cmp  eax, -1
    je   .fail
    call taskbar_clock_cadence_arm
    lea  rdi, [rel str_cad_id_attention]
    mov  esi, 1
    mov  edx, 2
    mov  rcx, rbx
    shr  rcx, 1
    lea  r8, [rel taskbar_attention_tick]
    call cadence_register_named
    lea  rdi, [rel str_cad_id_netmon]
    mov  esi, 2
    mov  edx, 2
    mov  rcx, rbx
    shr  rcx, 1
    lea  r8, [rel form_netmon_tick]
    call cadence_register_named
    cmp  dword [rel cad_count], 3
    jne  .fail
    lea  rdi, [rel str_cad_live_marker]
    call serial_string
    pop  rbx
    ret
.fail:
    lea  rdi, [rel str_cad_live_fail]
    call serial_string
    pop  rbx
    ret

; CADENCE/AUDIT is generated by walking the one core table.
form_cmd_verb_cadence:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov  r13, rsi
    call form_out_reset
    lea  rdi, [rel str_cadence_head]
    call form_out_put_str
    ; Report active entries, not holes left by an on-demand consumer.
    xor  edi, edi
    xor  ecx, ecx
    lea  rdx, [rel cad_table]
.count:
    cmp  ecx, [rel cad_count]
    jae  .counted
    imul eax, ecx, CAD_ENT_SZ
    cmp  qword [rdx + rax + CAD_ID], 0
    je   .count_next
    inc  edi
.count_next:
    inc  ecx
    jmp  .count
.counted:
    call form_out_put_dec
    xor  r12d, r12d
.loop:
    cmp  r12d, [rel cad_count]
    jae  .done
    mov  eax, r12d
    imul rax, rax, CAD_ENT_SZ
    lea  rbx, [rel cad_table]
    add  rbx, rax
    cmp  qword [rbx + CAD_ID], 0
    je   .next
    lea  rdi, [rel str_cad_open]
    call form_out_put_str
    mov  edi, r12d
    call form_out_put_dec
    lea  rdi, [rel str_cad_id]
    call form_out_put_str
    mov  rdi, [rbx + CAD_ID]
    call form_out_put_str
    lea  rdi, [rel str_cad_class]
    call form_out_put_str
    lea  rdi, [rel val_class_fixed]
    cmp  qword [rbx + CAD_CLASS], 1
    jne  .not_on_demand
    lea  rdi, [rel val_class_on_demand]
    jmp  .class
.not_on_demand:
    cmp  qword [rbx + CAD_CLASS], 2
    jne  .class
    lea  rdi, [rel val_class_freerun]
.class:
    call form_out_put_str
    lea  rdi, [rel str_cad_decl]
    call form_out_put_str
    mov  rdi, [rbx + CAD_DECL_HZ]
    call form_out_put_dec
    lea  rdi, [rel str_cad_meas]
    call form_out_put_str
    mov  rdi, [rbx + CAD_MEAS_HZ]
    call form_out_put_dec
    lea  rdi, [rel str_cad_jitter]
    call form_out_put_str
    mov  rdi, [rbx + CAD_JIT0]
    call form_out_put_dec
    lea  rdi, [rel form_str_comma]
    call form_out_put_str
    mov  rdi, [rbx + CAD_JIT1]
    call form_out_put_dec
    lea  rdi, [rel form_str_comma]
    call form_out_put_str
    mov  rdi, [rbx + CAD_JIT2]
    call form_out_put_dec
    lea  rdi, [rel form_str_comma]
    call form_out_put_str
    mov  rdi, [rbx + CAD_JIT3]
    call form_out_put_dec
    lea  rdi, [rel str_cad_missed]
    call form_out_put_str
    mov  rdi, [rbx + CAD_MISSED]
    call form_out_put_dec
    lea  rdi, [rel str_cad_audit]
    call form_out_put_str
    mov  rdi, [rbx + CAD_AUDIT]
    call form_out_put_dec
.next:
    inc  r12d
    jmp  .loop
.done:
    mov  byte [rel form_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
    pop  r13
    pop  r12
    pop  rbx
    ret

form_loader_selftest:
    push rbx
    push r12
    push r13
    lea  rdi, [rel str_verb_launch]     ; netmon_form registered LAUNCH immediately before us
    lea  rsi, [rel form_cmd_verb_launch]
    call form_replace_handler
    xor  ebx, ebx
.good:
    cmp  ebx, FORM_GOOD_COUNT
    jae  .bad_start
    cmp  ebx, 4
    jne  .present
    cmp  qword [rel forms_table+4*FORM_ENT_SZ+FORM_LEN], 0
    jne  .present
    inc  ebx                           ; absent PMOD is not a failed keep form
    jmp  .good
.present:
    mov  eax, ebx
    add  eax, 0x100                    ; 0x100..104: good form load
    mov  [rel form_selftest_stage], eax
    mov  r12d, [rel wgt_count]
    mov  edi, ebx
    xor  esi, esi
    xor  edx, edx
    call form_load_index
    test eax, eax
    jnz  .fail
    test edx, edx
    jnz  .good_loaded
    mov  eax, ebx
    add  eax, 0x120                    ; loaded but returned zero widgets
    mov  [rel form_selftest_stage], eax
    jmp  .fail
.good_loaded:
    mov  r13d, ecx
    mov  edi, r13d
    ; wmx_close_slot repaints the taskbar; that painter uses RBX as its colour
    ; scratch.  EBX is this loop's form index, so preserve it explicitly before
    ; clearing form_active_slot[index].  Losing it here skipped good forms 1..4
    ; and left form 0 tracked, making the pool-full negative test idempotently
    ; succeed (stage 0x301, form_error=NONE) instead of reaching NO_SLOT.
    push rbx
    call wmx_close_slot
    pop  rbx
    mov  [rel wgt_count], r12d
    lea  rax, [rel form_active_slot]
    mov  dword [rax + rbx*4], -1
    inc  ebx
    jmp  .good
.bad_start:
    mov  ebx, FORM_BAD_FIRST
.bad:
    cmp  ebx, FORM_LOCK_INDEX           ; only the three negative fixture rows
    jae  .edge_cases
    mov  eax, ebx
    add  eax, 0x200                    ; 0x205..207: bad fixture lint
    mov  [rel form_selftest_stage], eax
    mov  r12d, [rel wgt_count]
    mov  edi, ebx
    call form_lint_index
    test eax, eax
    jnz  .bad_refused
    mov  eax, ebx
    add  eax, 0x220                    ; bad fixture was incorrectly accepted
    mov  [rel form_selftest_stage], eax
    jmp  .fail
.bad_refused:
    cmp  r12d, [rel wgt_count]
    je   .bad_count_clean
    mov  eax, ebx
    add  eax, 0x240                    ; refused fixture changed widget count
    mov  [rel form_selftest_stage], eax
    jmp  .fail
.bad_count_clean:
    lea  rax, [rel form_active_slot]
    cmp  dword [rax + rbx*4], -1
    je   .bad_slot_clean
    mov  eax, ebx
    add  eax, 0x260                    ; refused fixture allocated a window
    mov  [rel form_selftest_stage], eax
    jmp  .fail
.bad_slot_clean:
    inc  ebx
    jmp  .bad
.edge_cases:
    mov  dword [rel form_selftest_stage], 0x300
    call form_selftest_oversize
    test eax, eax
    jnz  .fail
    mov  dword [rel form_selftest_stage], 0x301
    call form_selftest_pool_full
    test eax, eax
    jnz  .fail
.pass:
    call ephform_selftest
    test eax, eax
    jnz  .fail
    call form_progress_selftest
    test eax, eax
    jnz  .fail
    call form_container_selftest
    test eax, eax
    jnz  .fail
    call img_cache_reset                ; imgdemo selftest must not prewarm live proof
    lea  rdi, [rel str_form_marker]
    cmp  qword [rel forms_table+4*FORM_ENT_SZ+FORM_LEN], 0
    jne  .report
    lea  rdi, [rel str_form_marker_without_netmon]
.report:
    call serial_string
    pop  r13
    pop  r12
    pop  rbx
    ret
.fail:
    lea  rdi, [rel str_form_fail_stage]
    call serial_string
    mov  edi, [rel form_selftest_stage]
    call serial_hex64
    lea  rdi, [rel str_form_fail_error]
    call serial_string
    mov  edi, [rel form_error]
    call serial_hex64
    call serial_newline
    pop  r13
    pop  r12
    pop  rbx
    ret

; GK1-2: exercise the real two-pass lint and live vtable state, retaining the
; spare widget bytes/count. Timing and pixels are independently graded on metal.
form_progress_selftest:
    push rbx
    push r12
    push r13
    mov  dword [rel form_selftest_stage], 0x3020 ; valid WKEY declaration
    mov  r12d, [rel wgt_count]
    lea  rdi, [rel form_pg_fixture]
    mov  esi, form_pg_good_end-form_pg_fixture
    lea  rdx, [rel form_pg_name]
    call form_lint_blob
    test eax, eax
    jnz  .early_fail
    mov  dword [rel form_selftest_stage], 0x3021 ; unknown key, no allocation
    lea  rdi, [rel form_pg_fixture]
    mov  esi, form_pg_bad_end-form_pg_fixture
    lea  rdx, [rel form_pg_name]
    call form_lint_blob
    test eax, eax
    jz   .early_fail
    cmp  dword [rel form_error], FORM_ERR_UNKNOWN_KEY
    jne  .early_fail
    cmp  r12d, [rel wgt_count]
    jne  .early_fail
    cmp  r12d, WGT_MAX
    jae  .early_fail
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rbx, rax
    sub  rsp, WGI_SZ
    mov  rsi, rbx
    mov  rdi, rsp
    mov  ecx, WGI_SZ/8
    cld
    rep  movsq
    mov  rdi, rbx
    xor  eax, eax
    mov  ecx, WGI_SZ/8
    rep  stosq
    mov  dword [rbx + WGI_TYPE], PG_TYPE
    mov  dword [rbx + WGI_WIN], WM_MAX ; no test pixels escape into live windows
    mov  qword [rbx + WGI_NUM], 37
    mov  qword [rbx + WGI_MAXVAL], 80
    inc  dword [rel wgt_count]
    mov  r13d, 1
    mov  dword [rel form_selftest_stage], 0x3022 ; percentage from value/max
    mov  edi, r12d
    lea  rsi, [rel str_pg_text_mode]
    lea  rdx, [rel str_pg_percentage]
    call wgt_progress_set
    test eax, eax
    jnz  .restore
    call wgt_progress_format
    lea  rdi, [rel wgt_progress_text_buf]
    lea  rsi, [rel form_pg_percent]
    call strcmp
    test eax, eax
    jnz  .restore
    mov  dword [rel form_selftest_stage], 0x3023 ; value/max readout
    mov  edi, r12d
    lea  rsi, [rel str_pg_text_mode]
    lea  rdx, [rel str_pg_value]
    call wgt_progress_set
    test eax, eax
    jnz  .restore
    call wgt_progress_format
    lea  rdi, [rel wgt_progress_text_buf]
    lea  rsi, [rel form_pg_value]
    call strcmp
    test eax, eax
    jnz  .restore
    mov  dword [rel form_selftest_stage], 0x3024 ; registered controller edge
    mov  byte [rbx + PG_INDET], 1
    call wgt_progress_sync
    call wgt_progress_find_cadence
    cmp  eax, -1
    je   .restore
    imul eax, CAD_ENT_SZ
    lea  rdi, [rel cad_table]
    add  rdi, rax
    call qword [rdi + CAD_CTRL]
    cmp  dword [rbx + PG_PHASE], 1
    jne  .restore
    cmp  dword [rbx + PG_TICKS], 1
    jne  .restore
    cmp  qword [rbx + WGI_NUM], 37
    jne  .restore
    cmp  qword [rbx + WGI_MAXVAL], 80
    jne  .restore
    xor  r13d, r13d
.restore:
    mov  rsi, rsp
    mov  rdi, rbx
    mov  ecx, WGI_SZ/8
    rep  movsq
    add  rsp, WGI_SZ
    mov  [rel wgt_count], r12d
    call wgt_progress_sync
    call wgt_progress_find_cadence
    cmp  eax, -1
    jne  .early_fail
    test r13d, r13d
    jnz  .early_fail
    lea  rdi, [rel form_pg_marker]
    call serial_string
    mov  dword [rel form_error], FORM_ERR_NONE
    xor  eax, eax
    jmp  .out
.early_fail:
    mov  eax, 1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; The marker is earned by the real geometry/lint path. Metal closes paint,
; attention and focused-slot ordering with independent SCREEN2 samples.
form_container_selftest:
    push rbx
    push r12
    mov  r12d, [rel wgt_count]
    mov  dword [rel form_selftest_stage], 0x3030
    mov  edi, FORM_CONTAINERS_INDEX
    call form_lint_index
    test eax, eax
    jnz  .fail
    cmp  dword [rel form_layouts + 3*32], 24
    jne  .fail
    cmp  dword [rel form_layouts + 3*32 + 4], 120
    jne  .fail
    cmp  dword [rel form_layouts + 6*32 + 28], 1
    jne  .fail
    cmp  dword [rel form_layouts + 6*32], 248
    jne  .fail
    ; Same valid prefix, hostile ordinary child beyond its host: no allocation.
    lea  rdi, [rel form_container_fixture]
    mov  esi, form_container_bad_end-form_container_fixture
    lea  rdx, [rel form_container_name]
    call form_lint_blob
    test eax, eax
    jz   .fail
    cmp  r12d, [rel wgt_count]
    jne  .fail
    ; Exercise actual agent-open focus/attention semantics, then retire only
    ; this fixture through the normal close path before returning to boot.
    mov  ebx, [rel wm_focus]
    mov  edi, FORM_CONTAINERS_INDEX
    xor  esi, esi
    xor  edx, edx
    call form_load_index
    test eax, eax
    jnz  .fail
    push rcx
    mov  edx, 1
    cmp  ebx, [rel wm_focus]
    jne  .close_fixture
    lea  rax, [rel wm_attn]
    cmp  byte [rax + rcx], 1
    jne  .close_fixture
    xor  edx, edx
.close_fixture:
    push rdx
    mov  edi, ecx
    call wmx_close_slot
    pop  rdx
    pop  rcx
    mov  [rel wgt_count], r12d
    mov  dword [rel form_active_slot + FORM_CONTAINERS_INDEX*4], -1
    test edx, edx
    jnz  .fail
    mov  edi, 260
    mov  esi, 120
    xor  edx, edx
    mov  ecx, 2
    xor  r8d, r8d
    call wgt_grid_cell
    jnc  .fail
    mov  edi, 260
    mov  esi, 120
    mov  edx, 2
    mov  ecx, 2
    mov  r8d, 4
    call wgt_grid_cell
    jnc  .fail
    lea  rdi, [rel form_container_marker]
    call serial_string
    mov  dword [rel form_error], FORM_ERR_NONE
    xor  eax, eax
    jmp  .out
.fail:
    mov  eax, 1
.out:
    pop  r12
    pop  rbx
    ret

form_container_name: db "gui_kit_containers",0
form_container_fixture:
    db "form gui_kit_containers spec=v1",10
    db "window title=Containers w=320 h=240 x=100 y=180 resizable=0 min_w=320 min_h=240 chrome=standard restore=always",10
    db "widget type=grid id=grid x=16 y=56 w=260 h=120 text=cells role=group rows=2 cols=2",10
    db "widget type=button id=c0 parent=grid x=0 y=0 w=100 h=24 text=First role=button",10
    db "widget type=button id=c1 parent=grid x=0 y=0 w=100 h=24 text=Second role=button",10
    db "widget type=button id=c2 parent=grid x=0 y=0 w=100 h=24 text=Third role=button",10
    db "widget type=button id=c3 parent=grid x=0 y=0 w=100 h=24 text=Fourth role=button",10
    db "widget type=overlay id=layer x=240 y=64 w=160 h=96 text=overlay role=group overlay_layer=1",10
    db "widget type=button id=notice parent=layer x=8 y=8 w=144 h=80 text=Attention role=button",10
form_container_end:
    db "widget type=button id=escape x=310 y=64 w=100 h=24 text=escape role=button",10
form_container_bad_end: db 0
form_container_marker: db "[PAOS64] GUI kit: grid/overlay layout, clip and focus KAT PASS [gui.kit.containers_v2]",13,10,0
tree_overlay_layer: db " overlay_layer=",0
tree_grid_rows: db " rows=",0
tree_grid_cols: db " cols=",0

form_pg_name: db "progress_kat",0
form_pg_percent: db "46%",0
form_pg_value: db "37/80",0
form_pg_fixture:
    db "form progress_kat spec=v1",10
    db "window title=Progress w=300 h=200 x=100 y=100 resizable=0 min_w=100 min_h=100 chrome=standard restore=always",10
    db "widget type=progress id=p x=16 y=64 w=240 h=22 text=job role=progressbar value=37 max=80 text_mode=percentage indeterminate=0 cadence=5 job_id=17"
form_pg_good_end:
    db " not_a_progress_key=1"
form_pg_bad_end: db 0
form_pg_marker: db "[PAOS64] GUI kit: progress text/indeterminate cadence KAT PASS [gui.kit.progress_v2]",13,10,0

; Exercise the declaration-size bound without allocating anything. The table
; cell is restored before the result is returned.
form_selftest_oversize:
    push rbx
    push r12
    xor  edi, edi
    call form_table_ptr
    mov  rbx, rax
    mov  r12, [rbx + FORM_LEN]
    mov  qword [rbx + FORM_LEN], FORM_PARSE_MAX
    xor  edi, edi
    call form_lint_index
    mov  [rbx + FORM_LEN], r12
    test eax, eax
    jz   .fail
    cmp  dword [rel form_error], FORM_ERR_OVERSIZE
    jne  .fail
    xor  eax, eax
    jmp  .out
.fail:
    mov  eax, 1
.out:
    pop  r12
    pop  rbx
    ret

; A full window pool must refuse before the first widget allocation. Save and
; restore every WM state cell so this negative path leaves zero tree delta.
form_selftest_pool_full:
    push rbx
    push r12
    push r13
    push r14
    mov  r12d, [rel wgt_count]
    mov  r13d, [rel form_active_slot]
    xor  ebx, ebx
.save:
    cmp  ebx, WM_MAX
    jae  .fill
    lea  rcx, [rel wm_state]
    mov  eax, [rcx + rbx*4]
    lea  rdx, [rel form_test_wm_state]
    mov  [rdx + rbx*4], eax
    inc  ebx
    jmp  .save
.fill:
    xor  ebx, ebx
.fill_loop:
    cmp  ebx, WM_MAX
    jae  .try
    lea  rcx, [rel wm_state]
    mov  dword [rcx + rbx*4], WM_VISIBLE
    inc  ebx
    jmp  .fill_loop
.try:
    xor  edi, edi
    xor  esi, esi
    xor  edx, edx
    call form_load_index
    xor  r14d, r14d
    test eax, eax
    jnz  .check
    mov  r14d, 1
.check:
    cmp  dword [rel form_error], FORM_ERR_NO_SLOT
    je   .count
    mov  r14d, 1
.count:
    cmp  r12d, [rel wgt_count]
    je   .slot
    mov  r14d, 1
.slot:
    cmp  r13d, [rel form_active_slot]
    je   .restore
    mov  r14d, 1
.restore:
    xor  ebx, ebx
.restore_loop:
    cmp  ebx, WM_MAX
    jae  .done
    lea  rcx, [rel form_test_wm_state]
    mov  eax, [rcx + rbx*4]
    lea  rdx, [rel wm_state]
    mov  [rdx + rbx*4], eax
    inc  ebx
    jmp  .restore_loop
.done:
    mov  eax, r14d
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; --------------------------------------------------------------------------- data
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_gui_form_loader_0 0
align 8
form_current_entry: dq 0
form_expected_name: dq 0
form_load_title_ptr: dq 0
form_arg_title: dq 0
form_out_cur: dq 0
form_live_cur: dq 0
form_win_title: dq 0
form_w_id: dq 0
form_w_parent: dq 0
form_w_text: dq 0
form_w_role: dq 0
form_w_click: dq 0
form_w_value: dq 0
form_w_min: dq 0
form_w_max: dq 100
form_w_step: dq 1
form_w_job: dq 0
form_w_rows: dd 0
form_w_cols: dd 0
form_w_layer: dd 0
form_w_list_mode: dd 0
form_w_chart_mode: dd 0
form_w_overlay: dq 0
form_w_parents: dq 0
form_w_parents_packed: dq 0
form_w_expanded: dq 0
form_w_disabled: dq 0
form_w_list_flags: dd 0
form_layouts: times (FORM_NODE_MAX * 32) db 0
form_layout_children: times FORM_NODE_MAX dd 0
key_grid_rows: db "rows",0
key_grid_cols: db "cols",0
key_overlay_layer: db "overlay_layer",0
key_mode: db "mode",0
key_overlay: db "overlay",0
key_parents: db "parents",0
key_expanded: db "expanded",0
key_disabled: db "disabled",0
form_w_progress: dd 0
form_w_cadence: dq 10
form_w_src: dq 0                       ; validated img_assets row
form_sysprops_snapshot_ms: dq 0
form_active_slot: times FORM_SLOT_COUNT dd -1
form_app_owner: dq 0
form_app_staged: db 0                 ; native scoped latch, never guest input
form_ephemeral_slot: dd -1
form_current_win: dd -1
form_last_index: dd 0
form_result_slot: dd -1
form_result_widgets: dd 0
form_widget_first: dd 0
form_widget_end:   dd 0              ; WK-B7B: end of the run the last materialize filled
form_plan_widgets: dd 0
form_prior_active_slot: dd -1
form_adopted_shell: db 0
form_lint_seen_count: dd 0
form_error: dd 0
form_selftest_stage: dd 0
form_win_x: dd 0
form_win_y: dd 0
form_win_w: dd 0
form_win_h: dd 0
form_win_min_w: dd 0
form_win_min_h: dd 0
form_win_resizable: dd 0
form_lint_defer_capacity: db 0         ; B7a: form_load_index checks capacity at .allocate
form_relaunch_focuses: db 0            ; STM-04: console-typed FORMLOAD of an open form focuses it
form_card_loading: db 0                ; RCQ-40 J2b: 1 only inside card_surface's build of row 21
align 8, db 0
form_summon_gate: dq 0                  ; RCQ-40 F4 (c): gui/card_surface's cs_summon_gate (EAX 1 = refuse)
align 4
form_w_type: dd -1
form_w_x: dd 0
form_w_y: dd 0
form_w_w: dd 0
form_w_h: dd 0
form_w_bind: dd 0
align 8
form_netmon_members_fn: dq 0          ; RCQ-35: gui/netmon_form's netmon_members_text
form_netmon_address_fn: dq 0          ; gui/netmon_form's combined counter/address rows
form_w_scroll: dd 0
form_w_fit: dd -1
form_win_restore: db WM_RESTORE_FRESH
form_parse_mode: db 0
form_out_ready: db 0
align 8
form_parse_buf: times FORM_PARSE_MAX db 0
form_arg_buf: times 192 db 0
form_out_buf: times FORM_OUT_MAX db 0
form_live_buf: times 1024 db 0
form_sysprops_snapshot_buf: times 1024 db 0
form_cpu_security_buf: times 384 db 0
form_fsroot_snapshot_ms: dq 0
form_fsroot_cur: dq 0
form_fsroot_end: dq 0
form_fsroot_rc: dd 0
form_fsroot_result: times fs_list_result_size db 0
form_fsroot_dirents: times (FORM_FSROOT_LIST * FORM_FSROOT_ENT) db 0
form_fsroot_buf: times FORM_FSROOT_BUF db 0
form_fsstatus_buf: times FORM_FSSTATUS_BUF db 0
str_fsroot_comma: db ",",0
str_fsroot_space: db " ",0
str_fsroot_file: db " F",0
str_fsroot_dir: db " D",0
str_fsroot_empty: db "(empty)",0
str_fsroot_nomount: db "(nothing listed: FSSEL <mount> / FSCD <dir>)",0
str_fsstatus_dir: db ",dir=",0
str_verb_fscd: db "FSCD",0
str_verb_explorerobs: db "EXPLOREROBS",0
str_explorerobs_head: db " explorerobs=1 nonce=",0
str_explorerobs_none: db " phase=none",0
str_explorerobs_selected: db " phase=selected",0
str_explorerobs_accepted: db " phase=accepted",0
str_explorerobs_seq: db " seq=",0
str_explorerobs_job: db " job=",0
str_explorerobs_ms: db " ms=",0
str_explorerobs_win: db " win=",0
str_explorerobs_widget: db " widget=",0
str_explorerobs_owner: db " owner=",0
str_explorerobs_epoch: db " epoch=",0
str_explorerobs_src_mount: db " src_mount=",0
str_explorerobs_dst_mount: db " dst_mount=",0
str_explorerobs_src_label: db " src_label_hex=",0
str_explorerobs_dst_label: db " dst_label_hex=",0
str_explorerobs_src: db " src_hex=",0
str_explorerobs_dst: db " dst_hex=",0
str_explorerobs_op_nonce: db " op_nonce=",0
str_explorerobs_args: db "EXPLOREROBS ERR bad_args",0
str_explorerobs_refused: db "EXPLOREROBS ERR owner_or_stale",0
str_explorerobs_digits: db "0123456789abcdef",0
align 8
form_exp_observation: times EXP_OBS_SIZE db 0
str_fscd_ok: db " fscd dir=",0
str_fscd_err: db "FSCD ERR bad_args (absolute /path, < 80 chars)",0
form_fs_cwd: times (FORM_FS_CWD_MAX + 1) db 0
form_exp_open_path: times (FORM_FS_CWD_MAX + FORM_EXP_NAME + 2) db 0
form_fs_cwd_len: dd 1
str_fsstatus_mount: db "mount=",0
str_fsstatus_none: db "none",0
str_fsstatus_files: db ",files=",0
str_fsstatus_write: db ",write=",0
str_fsstatus_armed: db "armed",0
str_fsstatus_ro: db "readonly",0
str_fsstatus_note: db ",note=",0
str_exp_sel: db "> ",0
str_exp_up: db "..",0
str_exp_above: db "^ ",0
str_exp_above_tail: db " above",0
str_exp_more: db "... ",0
str_exp_more_tail: db " more",0
str_exp_capped: db "(the listing stops here: 64 entries max)",0   ; FORM_FSROOT_CAP
str_exp_failed: db "(cannot list this folder; Backspace goes up)",0
str_exp_note_long: db "path too long (79 chars max)",0
str_exp_note_name: db "name incomplete or invalid",0
str_exp_note_noviewer: db "this file cannot be shown here",0
str_exp_note_owner: db "only the owner can open this file",0
str_exp_note_stale: db "the drive changed; list it again",0
align 8
form_exp_size: times FORM_FSROOT_CAP dq 0
form_exp_note: dq 0                     ; a refused open's reason (status "note="), 0 none
form_exp_copy_shown: times 9 dq 0
form_exp_copy_pending: times 9 dq 0
form_exp_cancel_notice_job: dq 0
form_exp_cancel_pending: db 0
form_exp_cancel_notice: db 0
align 8
form_exp_cancel_req: times REQ_SZ db 0
form_exp_cancel_rsp: times RSP_SZ db 0
form_exp_cancel_arg: times 48 db 0
str_exp_cancel_nonce: db " 0000000000000000",0
str_exp_cancel_verb: db "FSCANCEL",0
str_exp_cancel_notices:
    db " (cancel pending)",0
    times (20 - ($ - str_exp_cancel_notices)) db 0
    db " (cancel requested)",0
    times (40 - ($ - str_exp_cancel_notices)) db 0
    db " (cancel not sent)",0
    times (60 - ($ - str_exp_cancel_notices)) db 0
form_exp_listing_mount: dq -1
form_exp_listing_ops: dq 0
form_exp_listing_priv: dq 0
form_exp_file_stamp: times 12 dq 0
form_exp_dest_stamp: times 12 dq 0
form_exp_owned_job: times 9 dq 0
form_exp_owned_queued: db 0
form_exp_paste_notice: db 0
form_exp_file_ready: db 0
form_exp_file_kind: db 0               ; captured 0=file, FORM_EXP_DIR=tree
form_exp_paste_pending: db 0
align 8
form_exp_paste_generation: dq 0
form_exp_paste_seq: dq 0x4558504c00000000 ; Explorer namespace; monotone, no reset/wrap in this boot
form_exp_paste_req: times REQ_SZ db 0
form_exp_paste_rsp: times RSP_SZ db 0
form_exp_file_name: times FORM_EXP_NAME db 0
form_exp_file_src: times FORM_FS_CWD_MAX db 0
form_exp_file_dst: times FORM_FS_CWD_MAX db 0
form_exp_paste_cwd: times FORM_FS_CWD_MAX db 0
form_exp_paste_nonce: times 17 db 0
form_exp_paste_arg: times 256 db 0
str_exp_copy_unavailable: db ",bytes=unknown of unknown,phase=unavailable,durable=unknown",0
str_exp_copy_cancel_hint: db " (Escape cancels)",0
str_exp_paste_notices:
    db " ; copy request pending",0
    times (32 - ($ - str_exp_paste_notices)) db 0
    db " ; copy request not sent",0
    times (64 - ($ - str_exp_paste_notices)) db 0
    db " ; copy request unconfirmed",0
    times (96 - ($ - str_exp_paste_notices)) db 0
    db " ; copy request refused",0
    times (128 - ($ - str_exp_paste_notices)) db 0
str_exp_paste_verb: db "FSCOPY",0
str_exp_paste_mode: db " MODE=keepboth",0
str_exp_paste_tree: db " TREE=1",0
str_exp_paste_error: db "FSCOPY ERR ",0
str_exp_paste_refused: db "copy request refused",0
str_exp_paste_prefix: db "FSCOPY NONCE=",0
str_exp_paste_job: db " OK JOB=",0
str_exp_file_ready: db "file selected for copy (Ctrl+V)",0
str_exp_dir_ready: db "directory selected for copy (Ctrl+V)",0
str_exp_file_unsupported: db "copy unavailable: source, destination or name unsupported",0
str_exp_paste_pending: db "copy request pending",0
str_exp_paste_not_sent: db "copy request not sent",0
str_exp_paste_unconfirmed: db "copy request unconfirmed",0
str_exp_paste_accepted: db "copy accepted; native job reports completion (Escape cancels)",0
form_exp_key_prev: dq 0                 ; the key filter installed before the Explorer's
form_exp_count: dd 0                    ; entries in the snapshot ("." and ".." excluded)
form_exp_trunc: dd 0                    ; the backend stopped at FORM_FSROOT_CAP
form_exp_top: dd 0                      ; first entry on the page
form_exp_cursor: dd FORM_EXP_NONE       ; the selection: an entry, FORM_EXP_UP or FORM_EXP_NONE
form_exp_page: dd FORM_EXP_ROWS_MIN     ; rows the file list draws (from its height)
form_exp_rows: dd 0                     ; rows of the last render
form_exp_rowmap: times FORM_EXP_ROWS_MAX dd 0
form_exp_keys_hooked: db 0
form_exp_gen: dd 0                      ; listings taken (a row map carries the one it shows)
form_exp_rows_gen: dd -1                ; the listing the row map describes
form_exp_last_press: dd FORM_EXP_NONE   ; row ref of the previous press (a double-click pairs it)
form_exp_sel_name: times FORM_EXP_NAME db 0
form_exp_press_name: times FORM_EXP_NAME db 0  ; the last press's entry across a relist
align 8
form_exp_last_press_ms: dq 0
form_exp_flags: times FORM_FSROOT_CAP db 0
form_exp_names: times FORM_FSROOT_CAP * FORM_EXP_NAME db 0
str_exp_copy_job: db "copy job=",0
str_exp_copy_mount: db " mount=",0
str_exp_copy_bytes: db ",bytes=",0
str_exp_copy_of: db " of ",0
str_exp_copy_phase: db ",phase=",0
str_exp_copy_durable: db ",durable=",0
str_exp_copy_unknown: db "unknown",0
str_exp_copy_elapsed: db ",elapsed=",0
str_exp_copy_rate: db " ms rate=",0
str_exp_copy_bps: db " B/s",0
str_exp_copy_row: db ",",0
str_exp_copy_sep: db " ",0
str_exp_copy_result: db "result=",0
str_exp_copy_files: db "files=",0
str_exp_copy_skipped: db " skipped=",0
str_exp_copy_failed_count: db "failed=",0
str_exp_copy_kept: db "kept=",0
str_exp_copy_phases:
str_exp_copy_copying: db "copying",0
    times 20-($-str_exp_copy_copying) db 0
str_exp_copy_finishing: db "finishing writes",0
    times 20-($-str_exp_copy_finishing) db 0
str_exp_copy_cancelling: db "cancelling",0
    times 20-($-str_exp_copy_cancelling) db 0
str_exp_copy_completed: db "completed",0
    times 20-($-str_exp_copy_completed) db 0
str_exp_copy_cancelled: db "cancelled",0
    times 20-($-str_exp_copy_cancelled) db 0
str_exp_copy_failed: db "failed",0
    times 20-($-str_exp_copy_failed) db 0
str_exp_copy_queued: db "queued",0
    times 20-($-str_exp_copy_queued) db 0
str_exp_copy_durability:
    db "0",0,0,0,0,0,0,0,0,0,0, "1",0,0,0,0,0,0,0,0,0,0, "unverified",0, "uncertain",0,0
; Native Explorer controls, retained within the owned Explorer data region.
form_exp_sort_mode: dd -1
form_exp_sort_desc: dd 0
form_exp_drives_count: dd 0
form_exp_drives: times 16 * 48 db 0
form_exp_drives_buf: times 512 db 0
form_exp_details_buf: times 512 db 0
form_exp_context_id: dd -1
form_exp_context_seq: dd 0
form_exp_context_ref: dd FORM_EXP_NONE
form_exp_context_win: dd -1
form_exp_context_epoch: dq 0
form_exp_context_key: dq 0
form_exp_context_mount: dq -1
form_exp_context_ops: dq 0
form_exp_context_priv: dq 0
form_exp_context_name: times FORM_EXP_NAME db 0
form_exp_context_path: times FORM_FS_CWD_MAX db 0
str_exp_details_size: db ",Bytes: ",0
str_exp_details_file: db ",File",0
str_exp_details_folder: db ",Folder",0
str_exp_details_clipped: db ",Name incomplete (cannot open)",0
str_exp_details_none: db "Select a file or folder",0
str_exp_details_path: db ",Folder: ",0
str_exp_details_sort: db ",Sort: ",0
str_exp_sort_provider: db "as listed",0
str_exp_sort_name: db "name",0
str_exp_sort_size: db "size",0
str_exp_sort_kind: db "kind",0
str_exp_sort_asc: db " ascending",0
str_exp_sort_descending: db " descending",0
str_fsstatus_na: db "n/a",0
form_titles: times (FORM_SLOT_COUNT * FORM_TITLE_MAX) db 0
; These are indexed by global widget id, including resident hidden forms.
; FORM_NODE_MAX remains the independent per-declaration lint bound.
form_node_ids: times (WGT_MAX * FORM_NODE_ID_MAX) db 0
form_node_roles: times (WGT_MAX * FORM_NODE_ID_MAX) db 0
form_node_labels: times (WGT_MAX * FORM_NODE_ID_MAX) db 0
form_lint_ids: times (FORM_NODE_MAX * FORM_NODE_ID_MAX) db 0
form_lint_types: times FORM_NODE_MAX dd 0
form_test_wm_state: times WM_MAX dd 0

str_form_kw: db "form",0
str_window_kw: db "window",0
str_widget_kw: db "widget",0
str_spec_v1: db "spec=v1",0
key_title: db "title",0
key_w: db "w",0
key_h: db "h",0
key_x: db "x",0
key_y: db "y",0
key_resizable: db "resizable",0
key_min_w: db "min_w",0
key_min_h: db "min_h",0
key_chrome: db "chrome",0
key_restore: db "restore",0
key_type: db "type",0
key_id: db "id",0
key_parent: db "parent",0
key_text: db "text",0
key_role: db "role",0
key_on_click: db "on_click",0
key_bind: db "bind",0
key_cadence: db "cadence",0
key_scroll: db "scroll",0
key_value: db "value",0
key_min: db "min",0
key_max: db "max",0
key_step: db "step",0
key_src: db "src",0
key_fit: db "fit",0
key_focus: db "focus",0
val_standard: db "standard",0
val_chrome_tabs: db "tabs",0
form_win_chrome: db 0
val_always: db "always",0
val_fresh: db "fresh",0
val_never: db "never",0
val_bind_sysprops: db "sysprops.live",0
form_optional_empty: db 0
val_bind_fsdrives: db "fs.drives",0
val_bind_fsdetails: db "fs.details",0
val_bind_fscontext: db "fs.context",0
val_bind_fsroot: db "fs.root",0
val_bind_fsstatus: db "fs.status",0
val_bind_netmembers: db "netmon.members",0
val_bind_netaddress: db "netmon.address",0
val_bind_summon_pinned: db "summon.pinned",0
val_bind_summon_recents: db "summon.recents",0
val_bind_summon_results: db "summon.results",0
val_dropdown: db "dropdown",0
val_tree: db "tree",0
val_radio: db "radio",0
form_explorer_autoload_done: db 0
str_form_explorer_autoload: db "[PAOS64] L6 gui: explorer auto-opened (PAOS_NTFS_UNSIGNED_TEST oracle door) [gui.explorer.autoload]", 13, 10, 0
val_err_syntax: db "syntax",0
val_err_missing: db "missing_form",0
val_err_unknown_key: db "unknown_key",0
val_err_unknown_widget: db "unknown_widget",0
val_err_unknown_asset: db "unknown_asset",0
val_err_no_slot: db "no_free_slot",0
val_err_capacity: db "widget_capacity",0
val_err_card_shown: db "card_shown",0
form_val_none: db "none",0
val_edid: db "edid",0
form_val_gop: db "gop",0

str_formload_ok: db " formload=ok name=",0
str_formload_win: db " win=",0
str_formload_widgets: db " widgets=",0
str_formload_err: db " FORMLOAD formload=ERR ",0
str_form_locked: db " session=locked",0
str_formlist: db " FORMLIST n=13 names=demo_a,demo_b,demo_c,sysprops,netmon,imgdemo,bad_rawcolor,bad_unknown_widget,bad_unknown_key,gui_kit_containers,gui_kit_dropdown,gui_kit_list_modes,summon",0
str_forminfo: db " FORMINFO name=",0
str_forminfo_err: db " FORMINFO FORMINFO=ERR missing_form",0
str_forminfo_page: db " page=",0
str_forminfo_slash: db "/",0
str_forminfo_page_err: db " FORMINFO FORMINFO=ERR bad_page",0
form_str_nl: db 10,0
form_str_comma: db ",",0

live_version: db ",version=",0
live_boot_session: db ",boot_session=",0
live_uptime: db ",uptime_s=",0
live_heap: db ",heap_mb=",0
live_native: db ",native=",0
live_active: db ",active=",0
live_source: db ",source=",0
live_nic: db " nic_ready=",0
live_crashes: db " crashes=",0
live_x: db "x",0
form_cpu_security_unavailable: db ",cpu_security=unavailable",0
tree_scroll: db " scroll=",0
tree_selection: db " selection=",0
tree_value: db " value=",0
tree_list_mode: db " mode=",0
tree_chart_mode: db " mode=",0
tree_chart_count: db " count=",0
tree_chart_scale: db " scale=",0
tree_list_overlay: db " overlay=",0
tree_dropdown_open: db " dropdown_open=",0
tree_list_parents: db " parents=",0
tree_list_expanded: db " expanded=",0
tree_list_disabled: db " disabled=",0
tree_min: db " min=",0
tree_max: db " max=",0
tree_step: db " step=",0
tree_intent: db " intent=",0
tree_intent_seq: db " intent_seq=",0
tree_label: db " label=",0

str_cadence_head: db " CADENCE n=",0
tree_pg_text_mode: db " text_mode=",0
tree_pg_indeterminate: db " indeterminate=",0
str_cad_open: db " CAD[",0
str_cad_id: db "] id=",0
str_cad_class: db " class=",0
str_cad_decl: db " declared_hz=",0
str_cad_meas: db " measured_hz=",0
str_cad_jitter: db " jitter_hist=",0
str_cad_missed: db " missed=",0
str_cad_audit: db " last_audit=",0
val_class_fixed: db "fixed",0
val_class_on_demand: db "on_demand",0
val_class_freerun: db "freerun_capped",0
str_cad_id_clock: db "taskbar.clock",0
str_cad_id_attention: db "taskbar.attention",0
str_cad_id_netmon: db "netmon.refresh",0
str_cad_live_marker: db "[PAOS64] M6 gui: core cadence registry extended (clock + attention + netmon.refresh entries, §12 vital tuple + class) [gui.cadence.registry]",13,10,0
str_cad_live_fail: db "[PAOS64] M6 gui: live cadence registry initialization FAILED",13,10,0

str_app_imgdemo:      db "app_imgdemo",0
form_str_app_sysprops: db "app_sysprops",0
form_str_app_netmon:   db "app_netmon",0
str_launch_img_ok: db " launch=ok app=app_",0
str_launch_img_idx: db " idx=",0
str_launch_img_bad: db " launch=ERR unknown_app",0
str_form_marker: db "[PAOS64] M6 gui: form_spec v1 loader selftest (5 forms load, 3 bad fixtures refused, zero delta) [gui.form.v1.loader]",13,10,0
str_form_marker_without_netmon: db "[PAOS64] M6 gui: form_spec v1 loader selftest (4 keep forms load, optional netmon absent, 3 bad fixtures refused, zero delta) [gui.form.v1.keep]",13,10,0
str_form_fail_stage: db "[PAOS64] M6 gui: form_spec v1 loader selftest FAILED stage=",0
str_form_fail_error: db " error=",0
%endmacro
WDATA_DEFER WDATA_gui_form_loader_0
