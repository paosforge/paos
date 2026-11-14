;; MODULE gui/command_gui
;; LAYER 6
;; EXPORTS gui_declare, gui_dpms_declare, gui_cursor_apply_relative, cmd_verb_kbinj, cmd_verb_kbdbuf, cmd_verb_mouseinj, cmd_verb_mousestat, cmd_verb_flicker, clock_zone_select, gui_out_buf, gui_out_ready, gui_out_cur
;; IMPORTS core/lib/fmt, svc/command, svc/command_auth, gui/window, gui/cadence_mark, dev/input/ps2, gui/input_route, dev/usb/hid, gui/wm_pointer, gui/widget, gui/chat_app, core/time, gui/window_mgmt, sec/keyprov, gui/input_domain_pad
;; CAPS
;; OWNER saga:gui_substrate_input
; ============================================================================
; svc/command_gui.asm — the BARE-METAL acceptance SURFACE for the 1016 GUI
; substrate (1016g). The QEMU visual+marker FLOOR of 1016 already ships (18 boot
; markers + verify_gui pixel content-grade). What was MISSING — and what the probe
; (probe_gui_substrate_input.sh gates 3/4/6/7) rides — is the live UDP-9997 verb
; surface that lets you POKE the running desktop from the network and read its
; input + render-health vitals back. This module is a THIN PROJECTION over the
; SAME command_register_verb / command_dispatch registry (1077), exactly like
; svc/thermal.asm and svc/resilience.asm — NO edit to the registry core (§9.4
; degenerate-Nth seam), additive only.
;
; Five GUI/input verbs (all ARGT_TEXT so the raw token round-trips verbatim via ARG=).
; USBLIST is owned by svc/command_usb.asm, which projects the live xHCI enumeration:
;   KBINJ <hex>    -> inject one scancode BYTE into the SAME ps2 kbd_ring the IRQ1
;                     handler fills; reply "kbinj=0xHH head=N" (gate 3 round-trip)
;   KBDBUF         -> protected diagnostics only; typed completion uses WIDGETGET
;   MOUSEINJ x,y,btn -> set the absolute cursor position + button state AND draw the
;                     cursor sprite there via the SAME ps2_cursor_draw the motion
;                     path uses (so the poke is VISIBLE on the HDMI capture, not a
;                     shadow variable); reply "mouseinj x=.. y=.. btn=.." (gate 4)
;   MOUSESTAT      -> "x=NNN y=NNN btn=N" from the live cursor state (gate 4 read-back)
;   FLICKER <arg>  -> legacy maxscore/flickering first, then CRC-derived
;                     regions/beat/stall/cost and per-region evidence (gate 6)
;
; The reply text is staged into gui_out_buf and framed verbatim by command_udp.asm's
; udp_send_reply (the SAME per-command staging pattern thermal/reinit/resilience use);
; gui_out_ready gates it so a plain PING/STATUS reply stays lean. command_udp.asm is
; %included AFTER this module so its [rel gui_out_buf]/[rel gui_out_ready] references
; resolve to data defined here (mirrors the resilience/boot_ab ordering note).
;
; PORT NOTE (M16): this REUSES proven seams rather than re-deriving them — the kbd
; ring + kbd_head (dev/input/ps2), ps2_cursor_draw sprite blit (dev/input/ps2), and
; flicker_maxscore (gui/window) all pre-exist from the 1016 floor; this module only
; adds the network projection over them (staging helpers mirror therm_out_*).
; ============================================================================

GUI_KBD_RING_LEN   equ 64            ; must match KBD_RING_LEN in dev/input/ps2.asm

; gui_cursor_apply_relative(EDI=dx,ESI=dy,EDX=buttons) — shared clamped
; pointer seam. HID boot-mouse deltas are already in framebuffer convention
; (positive Y is down); PS/2 performs its wire-specific Y inversion upstream.
gui_cursor_apply_relative:
    jmp  ps2_cursor_apply_relative

; ---------------------------------------------------------------------------
; gui_declare — register the five GUI/input verbs through command_register_verb
;   (additive, no registry-core edit). All ARGT_TEXT so a text nonce/arg echoes
;   back verbatim; KBINJ/MOUSEINJ carry a mutate flag (they poke live state).
;   clobbers: caller-saved.
; ---------------------------------------------------------------------------
gui_declare:
    call pingu_declare                    ; registers only; no input/GUI activation
    call ps2_cursor_draw_current        ; 2026-09-08: the arrow is on screen from boot (composed at present)
    ; form_cadence_live_init runs immediately before this declaration and resets
    ; the one core table; bind the on-demand flicker consumer only after that.
    call cadence_flicker_registry_init
    call treecheck_declare
    lea  rdi, [rel str_verb_kbinj]
    lea  rsi, [rel cmd_verb_kbinj]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1                              ; mutates the kbd ring
    call command_register_verb
    lea  rdi, [rel str_verb_kbdbuf]
    lea  rsi, [rel cmd_verb_kbdbuf]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_verb_mouseinj]
    lea  rsi, [rel cmd_verb_mouseinj]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1                              ; mutates the cursor position
    call command_register_verb
    lea  rdi, [rel str_verb_mousestat]
    lea  rsi, [rel cmd_verb_mousestat]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_verb_flicker]
    lea  rsi, [rel cmd_verb_flicker]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    ; --- 2026-09-08 input awareness + control (Peter): INPUTSTAT reads, INPUTSET adjusts ---
    lea  rdi, [rel str_verb_inputstat]
    lea  rsi, [rel cmd_verb_inputstat]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_verb_inputset]
    lea  rsi, [rel cmd_verb_inputset]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1                              ; mutates pointer settings (owner-signed)
    call command_register_verb
    lea  rdi, [rel str_verb_clock]          ; CLOCK: the taskbar clock's truth (public read)
    lea  rsi, [rel cmd_verb_clock]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    lea  rdi, [rel str_verb_tzset]          ; TZSET <+/-minutes>: display zone (owner-signed)
    lea  rsi, [rel cmd_verb_tzset]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1
    call command_register_verb
    lea  rdi, [rel str_verb_deskclean]      ; DESKCLEAN: retire the boot proofs now (owner-signed)
    lea  rsi, [rel cmd_verb_deskclean]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1
    call command_register_verb
    ret

; --- VERB: DESKCLEAN — repaint the desktop backdrop over the boot proofs (swatch, tile,
; beacon badge) and the windows back on top; the same thing the first human pointer event does.
cmd_verb_deskclean:
    call cmd_handler_prologue
    push rdi
    push rsi
    call wmx_clear_boot_marks_force
    call gui_out_reset
    lea  rdi, [rel str_dc_reply]
    call gui_out_str
    mov  byte [rel gui_out_ready], 1
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; gui_dpms_declare — RCQ-27 L3: register DPMS (owner-signed: it blanks / wakes the
;   live scanout). Its own declaration, called right after gui_declare, so the
;   pinned gui_declare authority span stays byte-identical. clobbers: caller-saved.
gui_dpms_declare:
    lea  rdi, [rel str_verb_dpms]
    lea  rsi, [rel cmd_verb_dpms]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    mov  r9, 1
    jmp  command_register_verb

; --- VERB: DPMS [BLANK|WAKE] — RCQ-27 L3 (B2 idle-power lever L3): blank the scanout
; now, or wake it, then report " dpms blanked=<0|1> idle_ms=<ms since input>
; timeout_ms=<idle-blank deadline> presents=<fb presents since boot>". No argument
; reports only. A forced blank holds until input or DPMS WAKE (the sign-in screen
; wakes on input too); presents= stops growing while blanked. Anything else is
; refused with applied=0 and the state unchanged, as TZSET does.
; BLANK is OWNER-only (admin C1, Guardian): a blanked screen hides the Guardian
; indicator, so every other principal, PRIN_SYSTEM included, gets AUTHDENY with
; " dpms applied=0 err=owner_only" and the screen stays visible. WAKE and the
; report stay open to any signed caller (showing the screen hides nothing).
cmd_verb_dpms:
    call cmd_handler_prologue
    push rdi
    push rsi
    push rbx
    mov  rbx, [rdi + REQ_ARG]
    test rbx, rbx
    jz   .report
.ws:
    cmp  byte [rbx], ' '
    jne  .kind
    inc  rbx
    jmp  .ws
.kind:
    cmp  byte [rbx], 0
    je   .report
    lea  rsi, [rel str_dpms_arg_blank]
    call dpms_arg_is
    test eax, eax
    jnz  .blank
    lea  rsi, [rel str_dpms_arg_wake]
    call dpms_arg_is
    test eax, eax
    jz   .bad
    xor  edi, edi
    call dpms_force
    jmp  .report
.blank:
    mov  rax, [rsp + 16]                    ; the request (pushed RDI)
    cmp  qword [rax + REQ_SOURCE], CMD_SOURCE_CONSOLE
    je   .owner                             ; the dispatcher already requires the console owner
    call command_auth_owner_request         ; 1 = own AUTH1 owner ticket, 2 = owner SSH key
    test eax, eax
    jz   .not_owner
.owner:
    mov  edi, 1
    call dpms_force
.report:
    xor  ebx, ebx                           ; CMDE_OK
    call gui_out_reset
    lea  rdi, [rel str_dpms_blanked]
    call gui_out_str
    movzx edi, byte [rel dpms_blanked]
    call gui_out_dec
    lea  rdi, [rel str_dpms_idle_ms]
    call gui_out_str
    call boot_ms_now
    sub  rax, [rel dpms_last_activity_ms]
    mov  rdi, rax
    call gui_out_dec
    lea  rdi, [rel str_dpms_timeout_ms]
    call gui_out_str
    mov  edi, DPMS_IDLE_MS
    call gui_out_dec
    lea  rdi, [rel str_dpms_presents]
    call gui_out_str
    mov  rdi, [rel fb_present_count]
    call gui_out_dec
    jmp  .done
.not_owner:
    mov  ebx, CMDE_AUTHDENY
    call gui_out_reset
    lea  rdi, [rel str_dpms_owner_only]
    call gui_out_str
    jmp  .done
.bad:
    xor  ebx, ebx                           ; CMDE_OK with applied=0, as TZSET
    call gui_out_reset
    lea  rdi, [rel str_dpms_bad]
    call gui_out_str
.done:
    mov  byte [rel gui_out_ready], 1
    mov  r8, rbx                            ; the code
    pop  rbx
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  [rsi + RSP_CODE], r8
    ret

; dpms_arg_is(RBX = arg, RSI = upper-case word) -> EAX = 1 iff the arg is that word
;   (any case), followed by NUL or a space. clobbers: RAX, RCX, RSI.
dpms_arg_is:
    mov  rcx, rbx
.cmp:
    mov  al, [rsi]
    test al, al
    jz   .end
    mov  ah, [rcx]
    cmp  ah, 'a'
    jb   .up
    cmp  ah, 'z'
    ja   .up
    sub  ah, 0x20
.up:
    cmp  ah, al
    jne  .no
    inc  rcx
    inc  rsi
    jmp  .cmp
.end:
    mov  al, [rcx]
    test al, al
    jz   .yes
    cmp  al, ' '
    je   .yes
.no:
    xor  eax, eax
    ret
.yes:
    mov  eax, 1
    ret

; --- VERB: CLOCK — what the taskbar shows and why: canonical UTC seconds, the display
; offset, whether the wall is valid, the HH:MM currently derived, and (RCQ-17 B1) what
; last set the wall: src=none|rtc|ntp (Peter 2026-09-08: "the desktop clock in paos is
; wrong" — it was UTC with no zone). ---
cmd_verb_clock:
    call cmd_handler_prologue
    push rdi
    push rsi
    call taskbar_read_wall
    call gui_out_reset
    lea  rdi, [rel str_ck_hdr]
    call gui_out_str
    call time_wall_now_s
    mov  rdi, rax
    call gui_out_dec
    call gui_out_tz_min
    lea  rdi, [rel str_ck_valid]
    call gui_out_str
    movzx edi, byte [rel clock_wall_valid]
    call gui_out_dec
    lea  rdi, [rel str_ck_shown]
    call gui_out_str
    call gui_out_hhmm
    call gui_out_tz_zone
    call gui_out_clock_src
    mov  byte [rel gui_out_ready], 1
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; gui_out_clock_src — RCQ-17 (B1): " src=none|rtc|ntp", what last set the wall
; (core/time.asm time_wall_source). Always the last CLOCK key, so the reply
; before it is unchanged. A byte outside the table prints "none".
gui_out_clock_src:
    lea  rdi, [rel str_ck_src]
    call gui_out_str
    movzx eax, byte [rel time_wall_source]
    cmp  eax, TIME_SRC_COUNT
    jb   .name
    xor  eax, eax
.name:
    imul eax, eax, 5
    lea  rdi, [rel str_ck_src_names]
    add  rdi, rax
    jmp  gui_out_str

; --- VERB: TZSET <+/-minutes> | <zone name> — set the taskbar display offset (clamped
; to +/-840, legacy fixed mode) or select a pinned named zone (window.asm clock_zone_*;
; UTC, America/Phoenix, America/New_York), force the next clock tick to repaint, reply
; with the new state. A name is refused (err=malformed_zone/unknown_zone/zone_range)
; without touching the prior setting; zone_range means a seeded wall lies outside the
; pinned rule interval. An applied change is saved (RCQ-17 clock_prefs_persist, a
; MACed PaOSClockPrefs record; the reply bytes are unchanged); no lookup. ---
cmd_verb_tzset:
    call cmd_handler_prologue
    push rdi
    push rsi
    push rbx
    mov  rbx, [rdi + REQ_ARG]
.tz_ws:
    cmp  byte [rbx], ' '
    jne  .tz_kind
    inc  rbx
    jmp  .tz_ws
.tz_kind:
    movzx eax, byte [rbx]
    or   eax, 0x20
    sub  eax, 'a'
    cmp  eax, 'z' - 'a'
    jbe  .tz_name                           ; a letter starts a zone name; else legacy path
.tz_sign:
    xor  esi, esi                           ; sign flag
    cmp  byte [rbx], '-'
    jne  .tz_plus
    mov  esi, 1
    inc  rbx
    jmp  .tz_num
.tz_plus:
    cmp  byte [rbx], '+'
    jne  .tz_num
    inc  rbx
.tz_num:
    movzx eax, byte [rbx]
    sub  eax, '0'
    cmp  eax, 9
    ja   .tz_bad                            ; no digits -> refuse, state unchanged
    ; Saturate while accumulating: the generic u32 parser can wrap a large
    ; decimal argument into a small offset before the display-zone clamp.
    xor  eax, eax
.tz_digits:
    movzx ecx, byte [rbx]
    sub  ecx, '0'
    cmp  ecx, 9
    ja   .tz_range                         ; retain leading-decimal prefix syntax
    imul eax, eax, 10
    add  eax, ecx
    cmp  eax, 840
    jae  .tz_clamped                       ; each prior value was below 840
    inc  rbx
    jmp  .tz_digits
.tz_clamped:
    mov  eax, 840
.tz_range:
    test esi, esi
    jz   .tz_store
    neg  eax
.tz_store:
    mov  [rel clock_tz_min], eax
    mov  byte [rel clock_tz_zone], 0        ; numeric minutes select the legacy fixed mode
.tz_applied:
    call clock_prefs_persist                ; RCQ-17: only a changed zone is written
    mov  word [rel clock_last_hhmm], 0xFFFF ; the next taskbar tick repaints the glyphs
    call taskbar_read_wall
    call gui_out_reset
    lea  rdi, [rel str_tz_hdr]
    call gui_out_str
    jmp  .tz_reply
.tz_name:
    mov  rdi, rbx
    call clock_zone_lookup                  ; bounded scan; EAX = id, 0 unknown, -1 malformed
    lea  rdi, [rel str_tz_malformed]
    test eax, eax
    js   .tz_refuse
    lea  rdi, [rel str_tz_unknown]
    jz   .tz_refuse
    mov  edi, eax
    call clock_zone_select                  ; the check Settings Apply shares (RCQ-17)
    lea  rdi, [rel str_tz_range]
    jc   .tz_refuse
    jmp  .tz_applied
.tz_bad:
    lea  rdi, [rel str_tz_bad]
.tz_refuse:
    call gui_out_reset
    call gui_out_str
    call taskbar_read_wall
.tz_reply:
    call gui_out_tz_min
    lea  rdi, [rel str_ck_shown]
    call gui_out_str
    call gui_out_hhmm
    call gui_out_tz_zone
    mov  byte [rel gui_out_ready], 1
    pop  rbx
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; clock_zone_select(EDI = zone id 1..CLOCK_ZONE_COUNT) -> CF=0: clock_tz_zone = id
;   (clock_tz_min is kept for a later numeric TZSET); CF=1: not a zone id, or a
;   seeded wall is unrepresentable or outside the regional rule interval - nothing
;   changed. Named UTC uses the existing calendar range. It neither
;   saves nor repaints; the caller does both. TZSET's name path and the Settings
;   Apply (gui/settings_prefs.asm) both select through here. Clobbers caller-saved.
clock_zone_select:
    push rbx
    mov  ebx, edi
    lea  eax, [rbx - 1]
    cmp  eax, CLOCK_ZONE_COUNT
    jae  .refuse                            ; 0 (fixed) and unknown ids never select
    call time_wall_now_s                    ; a seeded wall must be valid for this zone
    test rax, rax
    jz   .store                             ; unseeded: the read itself stays invalid
    mov  edx, ebx
    call clock_zone_offset
    jc   .out
.store:
    mov  [rel clock_tz_zone], bl
    clc
.out:
    pop  rbx
    ret
.refuse:
    stc
    pop  rbx
    ret

; gui_out_hhmm — append "HH:MM" from clock_hh/clock_mm (zero-padded).
gui_out_hhmm:
    movzx edi, byte [rel clock_hh]
    call gui_out_dec2
    lea  rdi, [rel str_ck_colon]
    call gui_out_str
    movzx edi, byte [rel clock_mm]
    call gui_out_dec2
    ret

; gui_out_tz_min — " tz_min=" + the fixed setting; in a named zone the offset the
; last wall read applied, or "none" while that read is invalid.
gui_out_tz_min:
    lea  rdi, [rel str_ck_tz]
    call gui_out_str
    cmp  byte [rel clock_tz_zone], 0
    jne  .named
    mov  edi, [rel clock_tz_min]
    jmp  gui_out_sdec
.named:
    cmp  byte [rel clock_wall_valid], 1
    jne  .none
    mov  edi, [rel clock_tz_eff_min]
    jmp  gui_out_sdec
.none:
    lea  rdi, [rel str_tz_none]
    jmp  gui_out_str

; gui_out_tz_zone — " zone=<pinned name>" in a named zone; nothing in fixed mode, so
; numeric-mode CLOCK/TZSET replies stay byte-identical.
gui_out_tz_zone:
    movzx eax, byte [rel clock_tz_zone]
    dec  eax
    cmp  eax, CLOCK_ZONE_COUNT
    jae  .ret                               ; 0 (fixed) wraps; never index past the table
    push rax
    lea  rdi, [rel str_tz_zone]
    call gui_out_str
    pop  rax
    imul eax, eax, CLOCK_ZONE_NAME_SLOT
    lea  rdi, [rel clock_zone_names]
    add  rdi, rax
    jmp  gui_out_str
.ret:
    ret

; gui_out_dec2(EDI) — two-digit zero-padded decimal.
gui_out_dec2:
    cmp  edi, 10
    jae  gui_out_dec
    push rdi
    lea  rdi, [rel str_ck_zero]
    call gui_out_str
    pop  rdi
    jmp  gui_out_dec

; --- VERB: KBINJ <hex> — inject one scancode byte into the ps2 kbd_ring at kbd_head
;     (the SAME ring IRQ1 fills + the selftest scans). Reply: "kbinj=0xHH head=N". ---
cmd_verb_kbinj:
    call cmd_handler_prologue
    push rdi
    push rsi
    push r12
    mov  rax, [rdi + REQ_ARG]                ; raw arg token ptr ("23")
    mov  rdi, rax
    call gui_parse_hex                       ; RAX = parsed byte value
    mov  r10d, eax                           ; injected byte (low 8 bits)
    mov  al, r10b
    mov  rdi, [rsp + 16]                     ; the request: its principal owns the byte (GA0-K)
    call keyprov_inject_scancode             ; same bounded producer as IRQ/USB, origin INJECTED
    mov  r12d, eax                           ; measured queued/drop result
    ; reply "kbinj=0xHH head=N"
    call gui_out_reset
    lea  rdi, [rel str_gu_kbinj]
    call gui_out_str
    movzx edi, r10b
    call gui_out_hex
    lea  rdi, [rel str_gu_head]
    call gui_out_str
    movzx edi, byte [rel kbd_head]
    call gui_out_dec
    lea  rdi, [rel str_gu_count]
    call gui_out_str
    movzx edi, byte [rel kbd_count]
    call gui_out_dec
    lea  rdi, [rel str_gu_queued]
    call gui_out_str
    mov  edi, r12d
    call gui_out_dec
    mov  byte [rel gui_out_ready], 1
    pop  r12
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; --- VERB: KBDBUF — protected ring diagnostics. Typed completion is graded
;     through WIDGETGET of the textfield's shared live value bytes. ---
cmd_verb_kbdbuf:
    call cmd_handler_prologue
    push rdi
    push rsi
    call gui_out_reset
    lea  rdi, [rel str_gu_kbdbuf]
    call gui_out_str
    xor  r10d, r10d                          ; ring index
.dump:
    cmp  r10d, GUI_KBD_RING_LEN
    jae  .done
    lea  r8, [rel kbd_ring]
    movzx edi, byte [r8 + r10]
    push r10
    call gui_out_hex
    lea  rdi, [rel str_gu_sp]
    call gui_out_str
    pop  r10
    inc  r10d
    jmp  .dump
.done:
    lea  rdi, [rel str_gu_head]
    call gui_out_str
    movzx edi, byte [rel kbd_head]
    call gui_out_dec
    lea  rdi, [rel str_gu_tail]
    call gui_out_str
    movzx edi, byte [rel kbd_tail]
    call gui_out_dec
    lea  rdi, [rel str_gu_count]
    call gui_out_str
    movzx edi, byte [rel kbd_count]
    call gui_out_dec
    lea  rdi, [rel str_gu_mods]
    call gui_out_str
    movzx edi, byte [rel input_kbd_mods]
    call gui_out_dec
    lea  rdi, [rel str_gu_caps]
    call gui_out_str
    movzx edi, byte [rel input_kbd_caps]
    call gui_out_dec
    lea  rdi, [rel str_gu_dropped]
    call gui_out_str
    mov  rdi, [rel kbd_dropped_count]
    call gui_out_dec
    lea  rdi, [rel str_gu_routed]
    call gui_out_str
    mov  rdi, [rel input_kbd_routed]
    call gui_out_dec
    lea  rdi, [rel str_gu_submit]
    call gui_out_str
    mov  rdi, [rel input_kbd_submits]
    call gui_out_dec
    mov  byte [rel gui_out_ready], 1
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; --- VERB: MOUSEINJ x,y,btn — set the absolute cursor position + button, and DRAW
;     the cursor sprite there (visible on HDMI) via the SAME ps2_cursor_draw the
;     motion path uses. Reply: "mouseinj x=NNN y=NNN btn=N". ---
cmd_verb_mouseinj:
    call cmd_handler_prologue
    push rdi
    push rsi
    mov  rax, [rdi + REQ_ARG]                ; "x,y,btn"
    mov  rdi, rax
    call gui_parse_u32                       ; RAX = x, RDI advanced past digits
    mov  [rel gui_cursor_x], eax
    call gui_skip_sep                        ; skip ',' (and any spaces)
    call gui_parse_u32                       ; RAX = y
    mov  [rel gui_cursor_y], eax
    call gui_skip_sep
    call gui_parse_u32                       ; RAX = btn
    mov  [rel gui_cursor_btn], eax
    ; The test hook enters the exact same dispatcher as IRQ12 and carries an
    ; explicit origin/intent receipt.
    CADENCE_BATCH_BEGIN
    mov  r8d, eax
    mov  edi, [rel gui_cursor_x]
    mov  esi, [rel gui_cursor_y]
    mov  edx, r8d
    mov  ecx, WM_PTR_ORIGIN_INJECTED
    call wm_pointer_event
    cmp  eax, WM_PTR_INTENT_FOCUS
    jne  .cursor
    call wmx_frame_may_focus            ; SEC D2: a non-OWNER injector steers no widget focus
    test eax, eax
    jnz  .cursor
    mov  edi, [rel wm_focus]
    mov  esi, [rel gui_cursor_x]
    mov  edx, [rel gui_cursor_y]
    call wgt_focus_at
    mov  edi, [rel wm_focus]
    call wgt_draw_window
.cursor:
    call ps2_cursor_draw_current              ; shared input-floor cursor painter
    CADENCE_BATCH_END
    ; reply "mouseinj x=NNN y=NNN btn=N"
    call gui_out_reset
    lea  rdi, [rel str_gu_minj]
    call gui_out_str
    mov  edi, [rel gui_cursor_x]
    call gui_out_dec
    lea  rdi, [rel str_gu_y]
    call gui_out_str
    mov  edi, [rel gui_cursor_y]
    call gui_out_dec
    lea  rdi, [rel str_gu_btn]
    call gui_out_str
    mov  edi, [rel gui_cursor_btn]
    call gui_out_dec
    lea  rdi, [rel str_gu_origin_injected]
    call gui_out_str
    lea  rdi, [rel str_gu_intent]
    call gui_out_str
    movzx edi, byte [rel wm_pointer_last_intent]
    call gui_out_dec
    mov  byte [rel gui_out_ready], 1
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; --- VERB: MOUSESTAT — live cursor state. Reply: "x=NNN y=NNN btn=N". ---
cmd_verb_mousestat:
    call cmd_handler_prologue
    push rdi
    push rsi
    call gui_out_reset
    lea  rdi, [rel str_gu_x]
    call gui_out_str
    mov  edi, [rel gui_cursor_x]
    call gui_out_dec
    lea  rdi, [rel str_gu_y]
    call gui_out_str
    mov  edi, [rel gui_cursor_y]
    call gui_out_dec
    lea  rdi, [rel str_gu_btn]
    call gui_out_str
    mov  edi, [rel gui_cursor_btn]
    call gui_out_dec
    mov  byte [rel gui_out_ready], 1
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; --- VERB: INPUTSTAT — one line an agent can read to know what the mouse and
;     keyboard are doing right now: cursor + buttons, which window/widget owns
;     the keyboard, the keyboard ring and routing counters, the USB HID report
;     counters + the last raw mouse report, and the live pointer settings. ---
cmd_verb_inputstat:
    call cmd_handler_prologue
    push rdi
    push rsi
    push rbx
    call gui_out_reset
    lea  rdi, [rel str_in_head]              ; " inputstat x="
    call gui_out_str
    mov  edi, [rel gui_cursor_x]
    call gui_out_dec
    lea  rdi, [rel str_gu_y]
    call gui_out_str
    mov  edi, [rel gui_cursor_y]
    call gui_out_dec
    lea  rdi, [rel str_gu_btn]
    call gui_out_str
    mov  edi, [rel gui_cursor_btn]
    call gui_out_dec
    lea  rdi, [rel str_in_wm_focus]
    call gui_out_str
    mov  edi, [rel wm_focus]
    call gui_out_dec
    lea  rdi, [rel str_in_focus_widget]
    call gui_out_str
    mov  eax, [rel wm_focus]
    cmp  eax, WM_MAX
    jae  .fw_none
    lea  rcx, [rel wgt_focus_by_win]
    mov  edi, [rcx + rax*4]
    jmp  .fw_put
.fw_none:
    mov  edi, -1
.fw_put:
    call gui_out_sdec
    lea  rdi, [rel str_in_last_intent]
    call gui_out_str
    movzx edi, byte [rel wm_pointer_last_intent]
    call gui_out_dec
    lea  rdi, [rel str_gu_head]
    call gui_out_str
    movzx edi, byte [rel kbd_head]
    call gui_out_dec
    lea  rdi, [rel str_gu_count]
    call gui_out_str
    movzx edi, byte [rel kbd_count]
    call gui_out_dec
    lea  rdi, [rel str_gu_dropped]
    call gui_out_str
    mov  rdi, [rel kbd_dropped_count]
    call gui_out_dec
    lea  rdi, [rel str_gu_routed]
    call gui_out_str
    mov  rdi, [rel input_kbd_routed]
    call gui_out_dec
    lea  rdi, [rel str_gu_submit]
    call gui_out_str
    mov  rdi, [rel input_kbd_submits]
    call gui_out_dec
    lea  rdi, [rel str_in_mouse_events]
    call gui_out_str
    mov  rdi, [rel mouse_event_count]
    call gui_out_dec
    lea  rdi, [rel str_in_last_dx]
    call gui_out_str
    mov  edi, [rel mouse_last_dx]
    call gui_out_sdec
    lea  rdi, [rel str_in_last_dy]
    call gui_out_str
    mov  edi, [rel mouse_last_dy]
    call gui_out_sdec
    lea  rdi, [rel str_in_speed]
    call gui_out_str
    mov  edi, [rel mouse_speed_pct]
    call gui_out_dec
    lea  rdi, [rel str_in_invert]
    call gui_out_str
    movzx edi, byte [rel mouse_invert_y]
    call gui_out_dec
    lea  rdi, [rel str_in_swap]
    call gui_out_str
    movzx edi, byte [rel mouse_swap_btn]
    call gui_out_dec
    lea  rdi, [rel str_in_hid_active]
    call gui_out_str
    movzx edi, byte [rel usb_hid_active_count]
    call gui_out_dec
    lea  rdi, [rel str_in_hid_reports]
    call gui_out_str
    mov  rdi, [rel usb_hid_mouse_reports]
    call gui_out_dec
    lea  rdi, [rel str_in_hid_polls]
    call gui_out_str
    mov  rdi, [rel usb_hid_poll_ticks]
    call gui_out_dec
    lea  rdi, [rel str_in_shadow]
    call gui_out_str
    xor  edi, edi
    cmp  qword [rel fb_scanout_base], 0
    je   .shadow_val
    mov  edi, 1
.shadow_val:
    call gui_out_dec
    lea  rdi, [rel str_in_shadow_src]
    call gui_out_str
    movzx edi, byte [rel fb_shadow_src]
    call gui_out_dec
    lea  rdi, [rel str_in_presents]
    call gui_out_str
    mov  rdi, [rel fb_present_count]
    call gui_out_dec
    lea  rdi, [rel str_in_present_px]
    call gui_out_str
    mov  rdi, [rel fb_present_px]
    call gui_out_dec
    lea  rdi, [rel str_in_present_tsc]
    call gui_out_str
    mov  rdi, [rel fb_present_tsc_last]
    call gui_out_dec
    lea  rdi, [rel str_in_present_max]
    call gui_out_str
    mov  rdi, [rel fb_present_tsc_max]
    call gui_out_dec
    lea  rdi, [rel str_in_move_last]
    call gui_out_str
    mov  rdi, [rel wmx_move_tsc_last]
    call gui_out_dec
    lea  rdi, [rel str_in_move_max]
    call gui_out_str
    mov  rdi, [rel wmx_move_tsc_max]
    call gui_out_dec
    lea  rdi, [rel str_in_tsc_khz]
    call gui_out_str
    mov  rdi, [rel tsc_khz]
    call gui_out_dec
    lea  rdi, [rel str_in_erase_tsc]
    call gui_out_str
    mov  rdi, [rel wmx_erase_tsc]
    call gui_out_dec
    lea  rdi, [rel str_in_draw_tsc]
    call gui_out_str
    xor  ebx, ebx
.is_draw_next:
    cmp  ebx, WM_MAX
    jae  .is_draw_done
    test ebx, ebx
    jz   .is_draw_val
    lea  rdi, [rel str_in_comma]
    call gui_out_str
.is_draw_val:
    lea  rax, [rel wmx_draw_tsc]
    mov  rdi, [rax + rbx*8]
    call gui_out_dec
    inc  ebx
    jmp  .is_draw_next
.is_draw_done:
    lea  rdi, [rel str_in_cursor_presents]
    call gui_out_str
    mov  rdi, [rel fb_cursor_presents]
    call gui_out_dec
    lea  rdi, [rel str_in_cursor_shape]
    call gui_out_str
    movzx edi, byte [rel gui_cursor_shape]
    call gui_out_dec
    lea  rdi, [rel str_in_resize_edges]
    call gui_out_str
    movzx edi, byte [rel wm_pointer_resize_edges]
    call gui_out_dec
    lea  rdi, [rel str_in_zorder]
    call gui_out_str
    xor  ebx, ebx
.is_z_next:
    cmp  ebx, WM_MAX
    jae  .is_z_done
    test ebx, ebx
    jz   .is_z_val
    lea  rdi, [rel str_in_comma]
    call gui_out_str
.is_z_val:
    lea  rax, [rel wm_zstamp]
    mov  edi, [rax + rbx*4]
    call gui_out_dec
    inc  ebx
    jmp  .is_z_next
.is_z_done:
    lea  rdi, [rel str_in_ptr_posted]
    call gui_out_str
    mov  rdi, [rel ps2_ptr_posted]
    call gui_out_dec
    lea  rdi, [rel str_in_ptr_pumped]
    call gui_out_str
    mov  rdi, [rel ps2_ptr_pumped]
    call gui_out_dec
    lea  rdi, [rel str_in_ptr_dropped]
    call gui_out_str
    mov  rdi, [rel ps2_ptr_dropped]
    call gui_out_dec
    lea  rdi, [rel str_in_pump_ticks]
    call gui_out_str
    mov  rdi, [rel ps2_pump_ticks]
    call gui_out_dec
    lea  rdi, [rel str_in_hid_raw]
    call gui_out_str
    movzx edi, byte [rel usb_hid_last_mouse_raw]
    shl  edi, 16
    movzx eax, byte [rel usb_hid_last_mouse_raw + 1]
    shl  eax, 8
    or   edi, eax
    movzx eax, byte [rel usb_hid_last_mouse_raw + 2]
    or   edi, eax
    call gui_out_hex
    lea  rdi, [rel str_in_ref_mal]
    call gui_out_str
    mov  rdi, [rel usb_hid_refused_malformed]
    call gui_out_dec
    lea  rdi, [rel str_in_ref_roll]
    call gui_out_str
    mov  rdi, [rel usb_hid_refused_rollover]
    call gui_out_dec
    lea  rdi, [rel str_in_ref_abs]
    call gui_out_str
    mov  rdi, [rel usb_hid_refused_absolute]
    call gui_out_dec
    lea  rdi, [rel str_in_ref_ws]
    call gui_out_str
    mov  rdi, [rel usb_hid_refused_wrong_slot]
    call gui_out_dec
    lea  rdi, [rel str_in_ref_stale]
    call gui_out_str
    mov  rdi, [rel usb_hid_refused_stale]
    call gui_out_dec
    lea  rdi, [rel str_in_ref_dup]
    call gui_out_str
    mov  rdi, [rel usb_hid_refused_duplicate]
    call gui_out_dec
    mov  byte [rel gui_out_ready], 1
    pop  rbx
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; --- VERB: INPUTSET key=value[,key=value] — adjust the pointer from an agent or
;     a user: mouse_speed=25..400 (percent), mouse_invert_y=0|1, mouse_swap_btn=0|1,
;     reset. Unknown keys are counted, never fatal. Owner-signed (destructiveness 1). ---
cmd_verb_inputset:
    call cmd_handler_prologue
    push rdi
    push rsi
    push rbx
    push r12
    push r13
    mov  rbx, [rdi + REQ_ARG]
    xor  r12d, r12d                          ; applied
    xor  r13d, r13d                          ; unknown
.is_next:
    cmp  byte [rbx], ' '
    je   .is_skip1
    cmp  byte [rbx], ','
    jne  .is_tok
.is_skip1:
    inc  rbx
    jmp  .is_next
.is_tok:
    cmp  byte [rbx], 0
    je   .is_done
    mov  rdi, rbx
    lea  rsi, [rel str_key_speed]
    call gui_match_key
    test eax, eax
    jz   .is_k2
    call gui_parse_u32
    mov  rbx, rdi
    cmp  eax, 25
    jae  .is_sp_lo
    mov  eax, 25
.is_sp_lo:
    cmp  eax, 400
    jbe  .is_sp_hi
    mov  eax, 400
.is_sp_hi:
    mov  [rel mouse_speed_pct], eax
    mov  dword [rel mouse_speed_rem_x], 0
    mov  dword [rel mouse_speed_rem_y], 0
    inc  r12d
    jmp  .is_next
.is_k2:
    mov  rdi, rbx
    lea  rsi, [rel str_key_invert]
    call gui_match_key
    test eax, eax
    jz   .is_k3
    call gui_parse_u32
    mov  rbx, rdi
    and  eax, 1
    mov  [rel mouse_invert_y], al
    inc  r12d
    jmp  .is_next
.is_k3:
    mov  rdi, rbx
    lea  rsi, [rel str_key_swap]
    call gui_match_key
    test eax, eax
    jz   .is_k4
    call gui_parse_u32
    mov  rbx, rdi
    and  eax, 1
    mov  [rel mouse_swap_btn], al
    inc  r12d
    jmp  .is_next
.is_k4:
    mov  rdi, rbx
    lea  rsi, [rel str_key_reset]
    call gui_match_key
    test eax, eax
    jz   .is_unknown
    mov  rbx, rdi
    mov  dword [rel mouse_speed_pct], 100
    mov  dword [rel mouse_speed_rem_x], 0
    mov  dword [rel mouse_speed_rem_y], 0
    mov  byte [rel mouse_invert_y], 0
    mov  byte [rel mouse_swap_btn], 0
    mov  qword [rel fb_present_tsc_max], 0  ; reset the worst-present watermark too
    mov  qword [rel wmx_move_tsc_max], 0
    inc  r12d
    jmp  .is_next
.is_unknown:
    inc  r13d
.is_skip_tok:
    mov  al, [rbx]
    test al, al
    jz   .is_done
    cmp  al, ','
    je   .is_next
    inc  rbx
    jmp  .is_skip_tok
.is_done:
    call gui_out_reset
    lea  rdi, [rel str_is_head]
    call gui_out_str
    mov  edi, r12d
    call gui_out_dec
    lea  rdi, [rel str_is_unknown]
    call gui_out_str
    mov  edi, r13d
    call gui_out_dec
    lea  rdi, [rel str_in_speed]
    call gui_out_str
    mov  edi, [rel mouse_speed_pct]
    call gui_out_dec
    lea  rdi, [rel str_in_invert]
    call gui_out_str
    movzx edi, byte [rel mouse_invert_y]
    call gui_out_dec
    lea  rdi, [rel str_in_swap]
    call gui_out_str
    movzx edi, byte [rel mouse_swap_btn]
    call gui_out_dec
    mov  byte [rel gui_out_ready], 1
    pop  r13
    pop  r12
    pop  rbx
    pop  rsi
    pop  rdi
    mov  rax, [rdi + REQ_ARG]
    mov  [rsi + RSP_VAL], rax
    mov  qword [rsi + RSP_CODE], CMDE_OK
    ret

; gui_match_key(RDI=ptr, RSI=key cstr) -> EAX 1 and RDI past the key on a prefix match, else EAX 0 (RDI kept).
gui_match_key:
    mov  rax, rdi
.mk:
    mov  cl, [rsi]
    test cl, cl
    jz   .mk_yes
    cmp  cl, [rax]
    jne  .mk_no
    inc  rax
    inc  rsi
    jmp  .mk
.mk_yes:
    mov  rdi, rax
    mov  eax, 1
    ret
.mk_no:
    xor  eax, eax
    ret

; gui_out_sdec(EDI=signed 32-bit) — "-" then magnitude for negatives.
gui_out_sdec:
    test edi, edi
    jns  gui_out_dec
    push rdi
    lea  rdi, [rel str_gu_minus]
    call gui_out_str
    pop  rdi
    neg  edi
    jmp  gui_out_dec

; --- VERB: FLICKER <arg> — render-cadence health vital.  Legacy fields remain
; first and byte-compatible; v2 appends bounded offline ring analysis.  STALLFIX
; arms one registered-cadence sample and deliberately withholds later updates;
; CRCFIX snapshots an already-rendered large rect for the sampled cross-check.
; CRCFIXCLR remains as an additive no-op for clients of the earlier fixture. ---
cmd_verb_flicker:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13, rsi
    mov  rax, [r12 + REQ_ARG]
    test rax, rax
    jz   .analyze
    cmp  dword [rax], 'STAL'
    jne  .beat_fixture
    cmp  dword [rax + 4], 'LFIX'
    jne  .analyze
    cmp  byte [rax + 8], 0
    jne  .analyze
    call flicker_stall_fixture_arm
    jmp  .analyze
.beat_fixture:
    cmp  dword [rax], 'CRCF'
    jne  .beat_match
    cmp  dword [rax + 4], 'IXCL'
    jne  .crc_fixture_arm
    cmp  byte [rax + 8], 'R'
    jne  .analyze
    cmp  byte [rax + 9], 0
    jne  .analyze
    call flicker_crc_fixture_clear
    jmp  .analyze
.crc_fixture_arm:
    cmp  word [rax + 4], 'IX'
    jne  .analyze
    cmp  byte [rax + 6], 0
    jne  .analyze
    call flicker_crc_fixture_arm
    jmp  .analyze
.beat_match:
    cmp  dword [rax], 'BEAT'
    jne  .analyze
    cmp  word [rax + 4], 'FI'
    jne  .analyze
    cmp  byte [rax + 6], 'X'
    jne  .analyze
    cmp  byte [rax + 7], 0
    jne  .analyze
    call flicker_beat_fixture_arm
.analyze:
    call flicker_analyze
    call gui_out_reset
    lea  rdi, [rel str_gu_maxscore]
    call gui_out_str
    mov  edi, [rel flicker_maxscore]         ; per-mille (0..999)
    call gui_out_frac3                        ; append "0.NNN"
    lea  rdi, [rel str_gu_flickering]
    call gui_out_str
    mov  eax, [rel flicker_maxscore]
    xor  edi, edi
    cmp  eax, 20                              ; >20‰ (0.020) counts as flickering
    jbe  .stable
    mov  edi, 1
.stable:
    call gui_out_dec
    lea  rdi, [rel str_gu_regions]
    call gui_out_str
    mov  edi, [rel flk_region_count]
    call gui_out_dec
    lea  rdi, [rel str_gu_beat]
    call gui_out_str
    mov  edi, [rel flk_beat_count]
    call gui_out_dec
    lea  rdi, [rel str_gu_stall]
    call gui_out_str
    mov  edi, [rel flk_stall_count]
    call gui_out_dec
    lea  rdi, [rel str_gu_crc_cost]
    call gui_out_str
    mov  edi, [rel flk_crc_cost_us_64k]
    call gui_out_dec
    lea  rdi, [rel str_gu_treecheck_periodic]
    call gui_out_str
    mov  rdi, [rel treecheck_periodic_mismatch]
    call gui_out_dec

    xor  ebx, ebx
    lea  r14, [rel flk_regions]
.row:
    cmp  ebx, [rel flk_region_count]
    jae  .ready
    lea  rdi, [rel str_gu_row_region]
    call gui_out_str
    movzx edi, word [r14 + FLKR_ID]
    call gui_out_dec
    lea  rdi, [rel str_gu_verdict]
    call gui_out_str
    lea  rdi, [rel str_gu_ok]
    cmp  byte [r14 + FLKR_VERDICT], FLKV_BEAT
    jne  .not_beat
    lea  rdi, [rel str_gu_beat_val]
    jmp  .put_verdict
.not_beat:
    cmp  byte [r14 + FLKR_VERDICT], FLKV_STALL
    jne  .put_verdict
    lea  rdi, [rel str_gu_stall_val]
.put_verdict:
    call gui_out_str
    lea  rdi, [rel str_gu_rect]
    call gui_out_str
    movzx edi, word [r14 + FLKR_X]
    call gui_out_dec
    lea  rdi, [rel str_gu_comma]
    call gui_out_str
    movzx edi, word [r14 + FLKR_Y]
    call gui_out_dec
    lea  rdi, [rel str_gu_comma]
    call gui_out_str
    movzx edi, word [r14 + FLKR_W]
    call gui_out_dec
    lea  rdi, [rel str_gu_comma]
    call gui_out_str
    movzx edi, word [r14 + FLKR_H]
    call gui_out_dec
    lea  rdi, [rel str_gu_events]
    call gui_out_str
    mov  edi, [r14 + FLKR_EVENTS]
    call gui_out_dec
    lea  rdi, [rel str_gu_sampled]
    call gui_out_str
    movzx edi, byte [r14 + FLKR_SAMPLED]
    call gui_out_dec
    add  r14, FLKR_SIZE
    inc  ebx
    jmp  .row
.ready:
    mov  byte [rel gui_out_ready], 1
    mov  rax, [r12 + REQ_ARG]
    mov  [r13 + RSP_VAL], rax
    mov  qword [r13 + RSP_CODE], CMDE_OK
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; arg-parse helpers (operate on RDI = token ptr, leave RDI past the digits)
; ---------------------------------------------------------------------------
; gui_parse_hex(RDI=ptr) -> RAX = hex value (0 if none). Accepts optional "0x".
gui_parse_hex:
    xor  eax, eax
    ; skip optional "0x"/"0X" prefix
    cmp  byte [rdi], '0'
    jne  .loop
    mov  cl, [rdi + 1]
    cmp  cl, 'x'
    je   .skip2
    cmp  cl, 'X'
    jne  .loop
.skip2:
    add  rdi, 2
.loop:
    movzx ecx, byte [rdi]
    ; 0-9
    mov  edx, ecx
    sub  edx, '0'
    cmp  edx, 9
    jbe  .digit
    ; a-f
    mov  edx, ecx
    or   edx, 0x20                            ; to lower
    sub  edx, 'a'
    cmp  edx, 5
    ja   .done
    add  edx, 10
.digit:
    shl  rax, 4
    add  rax, rdx
    inc  rdi
    jmp  .loop
.done:
    ret

; gui_parse_u32(RDI=ptr) -> RAX = leading decimal value (0 if none), RDI past digits.
gui_parse_u32:
    xor  eax, eax
.loop:
    movzx ecx, byte [rdi]
    sub  ecx, '0'
    cmp  ecx, 9
    ja   .done
    imul eax, eax, 10
    add  eax, ecx
    inc  rdi
    jmp  .loop
.done:
    ret

; gui_skip_sep(RDI=ptr) -> RDI advanced past one ',' plus any spaces.
gui_skip_sep:
    cmp  byte [rdi], ','
    jne  .sp
    inc  rdi
.sp:
    cmp  byte [rdi], ' '
    jne  .done
    inc  rdi
    jmp  .sp
.done:
    ret

; ---------------------------------------------------------------------------
; staged-reply buffer helpers (mirror the therm_out_* / reinit staging pattern)
; ---------------------------------------------------------------------------
gui_out_reset:
    lea  rax, [rel gui_out_buf]
    mov  [rel gui_out_cur], rax
    ret
; gui_out_str(RDI=cstr) — append NUL-terminated string at the cursor.
gui_out_str:
    mov  rsi, [rel gui_out_cur]
.cp:
    mov  al, [rdi]
    test al, al
    jz   .done
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .cp
.done:
    mov  byte [rsi], 0
    mov  [rel gui_out_cur], rsi
    ret
; gui_out_dec(RDI=value) — append unsigned decimal via canonical fmt_dec (G1).
gui_out_dec:
    mov  rsi, [rel gui_out_cur]
    push rsi
    call fmt_dec
    pop  rsi
    add  rsi, rax
    mov  [rel gui_out_cur], rsi
    ret
; gui_out_hex(RDI=value) — append "0x" + lowercase hex via canonical fmt_hex (G1).
gui_out_hex:
    push rdi
    lea  rdi, [rel str_gu_0x]
    call gui_out_str
    pop  rdi
    mov  rsi, [rel gui_out_cur]
    push rsi
    xor  edx, edx
    call fmt_hex
    pop  rsi
    add  rsi, rax
    mov  [rel gui_out_cur], rsi
    ret
; gui_out_frac3(RDI=permille 0..999) — append "0.NNN" (fixed 3-digit fraction).
gui_out_frac3:
    push rbx
    mov  ebx, edi
    lea  rdi, [rel str_gu_0dot]               ; "0."
    call gui_out_str
    mov  rsi, [rel gui_out_cur]
    ; hundreds
    mov  eax, ebx
    xor  edx, edx
    mov  ecx, 100
    div  ecx                                  ; eax = hundreds, edx = rem
    add  al, '0'
    mov  [rsi], al
    inc  rsi
    ; tens
    mov  eax, edx
    xor  edx, edx
    mov  ecx, 10
    div  ecx                                  ; eax = tens, edx = ones
    add  al, '0'
    mov  [rsi], al
    inc  rsi
    ; ones
    mov  al, dl
    add  al, '0'
    mov  [rsi], al
    inc  rsi
    mov  byte [rsi], 0
    mov  [rel gui_out_cur], rsi
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; data (in-image, RW under our page tables) — defined here so command_udp.asm's
; udp_send_reply can reference gui_out_buf/gui_out_ready (it is %included after us).
; ---------------------------------------------------------------------------
align 8
gui_out_cur:      dq 0                        ; live staged-reply cursor
gui_cursor_x:     dd 512                       ; absolute cursor X (MOUSEINJ sets, MOUSESTAT reads)
gui_cursor_y:     dd 384                       ; absolute cursor Y
gui_cursor_btn:   dd 0                         ; button bitmask (bit0=L bit1=R bit2=M)
gui_out_ready:    db 0                         ; a per-command reply line is staged in gui_out_buf
align 8
gui_out_buf:      times 1400 db 0              ; bounded FLICKER v2 evidence stays below one UDP payload

; --- verb name strings ---
str_verb_kbinj:     db "KBINJ", 0
str_verb_kbdbuf:    db "KBDBUF", 0
str_verb_mouseinj:  db "MOUSEINJ", 0
str_verb_mousestat: db "MOUSESTAT", 0
str_verb_flicker:   db "FLICKER", 0
str_verb_inputstat: db "INPUTSTAT", 0
str_verb_inputset:  db "INPUTSET", 0
str_verb_clock:     db "CLOCK", 0
str_verb_tzset:     db "TZSET", 0
str_ck_hdr:         db " clock utc_s=", 0
str_ck_tz:          db " tz_min=", 0
str_ck_valid:       db " wall_valid=", 0
str_ck_shown:       db " shown=", 0
str_ck_colon:       db ":", 0
str_ck_zero:        db "0", 0
str_ck_src:         db " src=", 0
str_ck_src_names:   db "none", 0, "rtc", 0, 0, "ntp", 0, 0   ; 5-byte slots, TIME_SRC_* order
str_tz_hdr:         db " tzset applied=1", 0
str_tz_bad:         db " tzset applied=0 err=expected_signed_minutes", 0
str_tz_malformed:   db " tzset applied=0 err=malformed_zone", 0
str_tz_unknown:     db " tzset applied=0 err=unknown_zone", 0
str_tz_range:       db " tzset applied=0 err=zone_range", 0
str_tz_none:        db "none", 0
str_tz_zone:        db " zone=", 0
str_in_head:        db " inputstat x=", 0
str_in_wm_focus:    db " wm_focus=", 0
str_in_focus_widget: db " focus_widget=", 0
str_in_last_intent: db " last_intent=", 0
str_in_mouse_events: db " mouse_events=", 0
str_in_last_dx:     db " mouse_last_dx=", 0
str_in_last_dy:     db " mouse_last_dy=", 0
str_in_speed:       db " mouse_speed_pct=", 0
str_in_invert:      db " mouse_invert_y=", 0
str_in_swap:        db " mouse_swap_btn=", 0
str_in_hid_active:  db " hid_active=", 0
str_in_hid_reports: db " hid_mouse_reports=", 0
str_in_hid_polls:   db " hid_poll_ticks=", 0
str_in_shadow:      db " shadow=", 0
str_in_shadow_src:  db " shadow_src=", 0
str_in_presents:    db " presents=", 0
str_in_present_px:  db " present_px=", 0
str_in_present_tsc: db " present_tsc_last=", 0
str_in_present_max: db " present_tsc_max=", 0
str_in_move_last:   db " move_tsc_last=", 0
str_in_erase_tsc:   db " erase_tsc=", 0
str_in_draw_tsc:    db " draw_tsc=", 0
str_in_comma:       db ",", 0
str_in_move_max:    db " move_tsc_max=", 0
str_in_tsc_khz:     db " tsc_khz=", 0
str_in_cursor_presents: db " cursor_presents=", 0
str_in_cursor_shape: db " cursor_shape=", 0
str_in_zorder:      db " zorder=", 0
str_in_resize_edges: db " resize_edges=", 0
str_in_ptr_posted:  db " ptr_posted=", 0
str_in_ptr_pumped:  db " ptr_pumped=", 0
str_in_ptr_dropped: db " ptr_dropped=", 0
str_in_pump_ticks:  db " pump_ticks=", 0
str_verb_deskclean: db "DESKCLEAN", 0
str_dc_reply:       db " deskclean cleared=1", 0
str_verb_dpms:      db "DPMS", 0
str_dpms_arg_blank: db "BLANK", 0
str_dpms_arg_wake:  db "WAKE", 0
str_dpms_blanked:   db " dpms blanked=", 0
str_dpms_idle_ms:   db " idle_ms=", 0
str_dpms_timeout_ms: db " timeout_ms=", 0
str_dpms_presents:  db " presents=", 0
str_dpms_bad:       db " dpms applied=0 err=expected_BLANK_or_WAKE", 0
str_dpms_owner_only: db " dpms applied=0 err=owner_only", 0
str_in_hid_raw:     db " hid_last_raw=", 0
str_in_ref_mal:     db " hid_refused_malformed=", 0
str_in_ref_roll:    db " hid_refused_rollover=", 0
str_in_ref_abs:     db " hid_refused_absolute=", 0
str_in_ref_ws:      db " hid_refused_wrong_slot=", 0
str_in_ref_stale:   db " hid_refused_stale=", 0
str_in_ref_dup:     db " hid_refused_duplicate=", 0
str_is_head:        db " inputset applied=", 0
str_is_unknown:     db " unknown=", 0
str_key_speed:      db "mouse_speed=", 0
str_key_invert:     db "mouse_invert_y=", 0
str_key_swap:       db "mouse_swap_btn=", 0
str_key_reset:      db "reset", 0
str_gu_minus:       db "-", 0

; --- staged reply fragments ---
str_gu_kbinj:       db " kbinj=", 0
str_gu_head:        db " head=", 0
str_gu_tail:        db " tail=", 0
str_gu_count:       db " count=", 0
str_gu_queued:      db " queued=", 0
str_gu_mods:        db " mods=", 0
str_gu_caps:        db " caps=", 0
str_gu_dropped:     db " input.kbd.dropped=", 0
str_gu_routed:      db " routed=", 0
str_gu_submit:      db " submits=", 0
str_gu_kbdbuf:      db " kbdbuf: ", 0
str_gu_minj:        db " mouseinj x=", 0
str_gu_x:           db " x=", 0
str_gu_y:           db " y=", 0
str_gu_btn:         db " btn=", 0
str_gu_maxscore:    db " maxscore=", 0
str_gu_flickering:  db " flickering=", 0
str_gu_regions:     db " regions=",0
str_gu_beat:        db " beat=",0
str_gu_stall:       db " stall=",0
str_gu_crc_cost:    db " crc_cost_us_64k=",0
str_gu_treecheck_periodic: db " treecheck_periodic_mismatch=",0
str_gu_row_region:  db " | r=",0
str_gu_verdict:     db " verdict=",0
str_gu_ok:          db "ok",0
str_gu_beat_val:    db "beat",0
str_gu_stall_val:   db "stall",0
str_gu_rect:        db " rect=",0
str_gu_comma:       db ",",0
str_gu_events:      db " ev=",0
str_gu_sampled:     db " crc_sampled=",0
str_gu_origin_injected: db " origin=injected",0
str_gu_intent:      db " intent=",0
str_gu_0x:          db "0x", 0
str_gu_0dot:        db "0.", 0
str_gu_sp:          db " ", 0
