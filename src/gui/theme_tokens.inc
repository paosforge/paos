; DESKTOP_THEME D2 (PETER RULING 2026-09-29 13:50) — Windows 11 dark chrome
; measured from peter-windows-terminal-reference-20260929.png. D1 values it
; replaced: title 0x2858A0/0x305FA8, body 0x202830, border 0x687888.
; Values are 0x00RRGGBB; GOP stores them as BGRX bytes.
GUI_TOK_DESKTOP            equ 0x00103048  ; unchanged: beacon.asm BEACON_BG_COLOR mirrors it
GUI_TOK_WINDOW_BODY         equ 0x000C0C0C
GUI_TOK_BORDER              equ GUI_TOK_FIELD_BORDER  ; unfocused window frame. RCQ-16 S3 (provisional): was 0x3A3A3A,
                                            ; 1.20:1 on the desktop; now 3.18 desktop, 4.56 body, 3.80 unfocused title
GUI_TOK_OUTLINE             equ 0x003A3A3A  ; widget outlines / grid lines / resize grip (RCQ-16 S3: the pre-S3 BORDER value,
                                            ; unchanged on screen; the frame needs 3:1, these keep their look)
GUI_TOK_BORDER_FOCUSED      equ 0x0066843E  ; thin accent frame of the focused window (RCQ-16: the D2 0x4E652F
                                            ; olive, lightened to 3.21:1 on the desktop and 4.60:1 on the body)
GUI_TOK_TITLE_FOCUSED       equ 0x002E2E2E
GUI_TOK_TITLE_UNFOCUSED     equ 0x00202020
GUI_TOK_TITLE_SEPARATOR     equ 0x00292929  ; last title row, above the body
GUI_TOK_TITLE_TEXT          equ 0x00FFFFFF
GUI_TOK_TITLE_TEXT_UNFOCUSED equ 0x009D9D9D
GUI_TOK_CAPTION_HOVER       equ 0x003D3D3D  ; minimize / maximize hover
GUI_TOK_CLOSE_HOVER         equ 0x00C42B1C
GUI_TOK_MIN_BG              equ GUI_TOK_CAPTION_HOVER
GUI_TOK_MAX_BG              equ GUI_TOK_CAPTION_HOVER
GUI_TOK_CLOSE_BG            equ GUI_TOK_CLOSE_HOVER
GUI_TOK_CHROME_GLYPH        equ 0x00FFFFFF
GUI_TOK_CHROME_GLYPH_UNFOCUSED equ 0x009D9D9D
GUI_TOK_SELECTION           equ 0x000078D4  ; widget selection / progress fill (was TITLE_FOCUSED)
GUI_TOK_SELECTION_MUTED     equ 0x005E5E5E  ; unfocused selection / chart bars. RCQ-16 S3 (provisional): was 0x2D2D2D,
                                            ; 1.42:1 on the body; now 3.02:1, white text 6.48:1
GUI_TOK_STATUS_BG           equ 0x002D2D2D  ; status strip surface (RCQ-16 S3: the pre-S3 SELECTION_MUTED value, unchanged on screen)
GUI_TOK_CONTROL_BG          equ 0x002D2D2D  ; buttons / text fields
GUI_TOK_CONTROL_TEXT        equ 0x00FFFFFF
GUI_TOK_TASKBAR_BG          equ 0x001C1C1C
GUI_TOK_TASKBAR_ACTIVE      equ 0x003D3D3D
GUI_TOK_TASKBAR_NORMAL      equ 0x002A2A2A
GUI_TOK_TASKBAR_MINIMIZED   equ 0x00202020
GUI_TOK_TASKBAR_ATTENTION   equ 0x00A86400  ; RCQ-16: was 0xC08020 (white text 3.31:1); now 4.68:1, 3.64:1 on the bar
GUI_TOK_TASKBAR_TEXT        equ 0x00FFFFFF
GUI_TOK_LABEL_TEXT          equ 0x00CCCCCC
GUI_TOK_LABEL_BG            equ GUI_TOK_WINDOW_BODY
GUI_TOK_ACCENT              equ 0x004FC3CD  ; D1 teal living/agent/start mark
; UI wave 2 E10: tab strip + flyout menu colours (were widget_tabstrip.asm
; local literals; values unchanged).
GUI_TOK_TAB_ACTIVE_TEXT     equ 0x00FFFFFF
GUI_TOK_TAB_TEXT            equ 0x00E0E0E0
GUI_TOK_TAB_GLYPH           equ 0x00CCCCCC
GUI_TOK_TAB_DIVIDER         equ 0x003D3D3D
GUI_TOK_TAB_ICON            equ 0x004276D2  ; RCQ-16 S3 (provisional): 0x3A70D0 4% toward white, same hue; 2.85 -> 3.07:1 on TITLE_FOCUSED
GUI_TOK_MENU_BG             equ 0x002C2C2C
GUI_TOK_MENU_BORDER         equ GUI_TOK_FIELD_BORDER  ; RCQ-16 S3 (provisional): was 0x454545, 1.46:1 on MENU_BG; now 3.25:1
GUI_TOK_MENU_TEXT           equ 0x00FFFFFF
GUI_TOK_MENU_HOVER          equ GUI_TOK_SELECTION  ; highlighted flyout item (pointer hover / arrow keys).
                                            ; RCQ-16: was 0x3D3D3D, 1.29:1 on MENU_BG; the selection is 3.08:1
; RCQ-16 S1 (spec 5.4 Readability and targeting; gui_visual_floor.py checks every
; pair it names): text >= 4.5:1, essential boundaries / state / focus cues >= 3:1.
GUI_TOK_FIELD_BORDER        equ 0x007A7A7A  ; field/track boundary >= 3:1 on every host: body 4.56, field 3.84, desktop 3.18 (Summon query)
GUI_TOK_FOCUS_RING          equ 0x00FFFFFF  ; keyboard-focus ring of a focused button
GUI_TOK_TOGGLE_KNOB         equ 0x00FFFFFF  ; toggle knob on the off (FIELD_BORDER) / on (SELECTION) track
GUI_TOK_TASKBAR_PILL_ACTIVE equ GUI_TOK_ACCENT        ; state pill: focused window (wide)
GUI_TOK_TASKBAR_PILL        equ 0x009D9D9D  ; state pill: open (short) / minimized (dot)
GUI_TOK_TASKBAR_PILL_ATTENTION equ GUI_TOK_TASKBAR_BG ; state pill on the attention phase (wide)
; RCQ-16 S3 (provisional, design-neutral floor; Peter's design replaces these): boundaries reuse FIELD_BORDER.
GUI_TOK_CONTROL_BORDER      equ GUI_TOK_FIELD_BORDER  ; 1 px button outline: 4.56:1 on the body, 3.21:1 on CONTROL_BG
; RCQ-16 S4 (provisional, design-neutral; Peter's design replaces these): control states (widget.asm wgt_state_of).
; Hover is never the only cue a control needs; pressed / hover keep every text, boundary and knob floor.
GUI_TOK_CONTROL_HOVER       equ 0x00383838  ; button fill under the pointer: label 11.73:1
GUI_TOK_CONTROL_BORDER_HOVER equ 0x009D9D9D ; button outline / textfield border under the pointer: 4.32 hover fill, 6.08 field, 7.21 body, 5.03 desktop
GUI_TOK_CONTROL_PRESSED     equ 0x001F1F1F  ; button fill while a left press is held: label 16.48, outline 3.84
GUI_TOK_TRACK_HOVER         equ 0x00888888  ; toggle off track / slider track under the pointer: knob 3.54, body 5.52
GUI_TOK_SELECTION_HOVER     equ 0x001A86DA  ; toggle on track / slider handle under the pointer: knob 3.84, body 5.09
GUI_TOK_DISABLED_TEXT       equ 0x00787878  ; inactive control's text, knob, handle (WCAG 1.4.3 / 1.4.11 exempt
                                            ; inactive components; still 3.12:1 on CONTROL_BG, 4.43 on the body)
GUI_TOK_DISABLED_BORDER     equ GUI_TOK_OUTLINE ; inactive control's boundary / track (exempt; distinct from FIELD_BORDER)

GUI_CHROME_BORDER           equ 1   ; thin frame (reference: 1 px accent)
; Windows 11 caption buttons: 46 px wide, the full strip height below the
; frame row, flush right; the strip's last row is the separator.
GUI_CHROME_BUTTON_W         equ 46
GUI_CHROME_BUTTON_H         equ 38
GUI_CHROME_BUTTON_GAP       equ 0
GUI_CHROME_BUTTON_Y         equ 1
GUI_CHROME_BUTTON_RIGHT     equ 1   ; right margin of the close button (the frame)
GUI_CHROME_GLYPH            equ 10  ; caption glyph box (reference 10 px)
GUI_CHROME_TITLE_X          equ 12
GUI_CHROME_TITLE_Y          equ 10  ; 19 px AA cell centred in the 40 px strip
; title text keeps clear of the three caption buttons plus a 20 px gap.
GUI_CHROME_TITLE_RESERVE    equ GUI_CHROME_BUTTON_W * 3 + GUI_CHROME_TITLE_X + 20
GUI_CHROME_TITLE_ADV        equ 9   ; AA monospace advance (font_aa9x19)
GUI_CHROME_TITLE_CELL_H     equ 19
; UI wave 2 B1: the inside resize band of every window edge and the corner
; grip (were wm_pointer.asm WM_EDGE_PX / WM_GRIP_PX). Caption buttons win over
; both; a maximized window has no resize border.
GUI_CHROME_RESIZE_BAND      equ 6
GUI_CHROME_RESIZE_GRIP      equ 14
; UI wave 2 B6: tab strip geometry, relative to the tabstrip widget origin
; (window x+1, y+1), and the flyout menu rows (were widget_tabstrip.asm locals).
GUI_TAB_LEFT                equ 7
GUI_TAB_W                   equ 240
GUI_TAB_MIN                 equ 100
GUI_TAB_TOP                 equ 8
GUI_TAB_BTN_W               equ 31
GUI_TAB_CLOSE_DX            equ 25   ; close glyph at tab_w - 25
GUI_TAB_TEXT_X              equ 36
GUI_MENU_ITEM_H             equ 32
GUI_MENU_PAD                equ 4
; RCQ-16 S1: the taskbar state pill (Windows 11), centred at the bottom of a
; taskbar button; the width tells the state apart without colour.
GUI_TASKBAR_PILL_H          equ 3
GUI_TASKBAR_PILL_BOTTOM     equ 2   ; rows left below the pill inside the button
GUI_TASKBAR_PILL_W_ACTIVE   equ 20
GUI_TASKBAR_PILL_W_NORMAL   equ 10
GUI_TASKBAR_PILL_W_MIN      equ 4
GUI_TASKBAR_PILL_W_ATTENTION equ 20
GUI_FOCUS_RING_W            equ 2   ; inside the control's edge; labels start 8+ px in

WM_RESTORE_ALWAYS           equ 0
WM_RESTORE_FRESH            equ 1
WM_RESTORE_NEVER            equ 2

GUI_TOK_WARNING_TEXT        equ 0x00FF6B6B  ; red native label, 7.0+:1 on window body
