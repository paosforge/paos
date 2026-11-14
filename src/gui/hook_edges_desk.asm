;; MODULE gui/hook_edges_desk
;; LAYER 6
;; EXPORTS hook_desk_edges_declare, hook_clock_plan, hook_taskbar_plan, hook_lock_plan, hook_wallpaper_plan, hook_clipboard_plan, hook_window_plan, hook_window_post
;; IMPORTS svc/command, svc/command_hook, gui/command_gui, gui/taskbar, gui/form_loader, gui/img/img_core, svc/clipboard, gui/chat_app
;; CAPS
;; OWNER saga:command
; ============================================================================
; gui/hook_edges_desk.asm -- RCQ-15 slices 5 to 7: the desktop-surface HOOK edges.
;
;   clock      (service)  the taskbar clock and display zone  native CLOCK / TZSET
;   taskbar    (desktop)  the taskbar row of live windows     native TASKBAR / WINATTN
;   lock       (session)  the sign-in screen                  native LOCKSTATE / LOCK
;   wallpaper  (desktop)  the desktop image layer             native WALLPAPER
;   clipboard  (service)  the shared clipboard (S7: content)  native CLIPINFO / CLIPGET / CLIPSET
;   window     (desktop)  the window manager's slots (S6)     native WINDOWS / FOCUSED / WINGEOM /
;                                                             FOCUS / RAISE / MIN / MAX / CLOSE /
;                                                             WINMOVE / WINRESIZE
;
; As in slices 1 to 4, an edge only PLANS a native verb and argument;
; svc/command_hook dispatches it with the caller's own source, principal,
; capability and idempotency key, so the native gate decides. LOCKSTATE,
; CLIPINFO and the empty WALLPAPER read are exact public spellings; every
; other native here needs the owner's authority remotely, and WALLPAPER gates
; each non-empty argument in its own handler. The S5 natives stage their reply
; text in a buffer the UDP reply chain frames ahead of the hook lean, so those
; edges need no post filter. The window natives (S6) stage into chat_out_buf,
; which the chain frames only in its marker tail, so the window edge relays it
; as the hook reply (hook_window_post, the S3b guest pattern).
;
; Typed rules the edges add (stricter only):
;   * clock: one instance; GET is CLOCK; SET takes exactly "zone <name>" (1..
;     HDK_ZONE_MAX of [A-Za-z0-9/_+-], first a letter, so TZSET reads it as a
;     name; an unknown zone is TZSET's own refusal) or "offset <minutes>"
;     (optional sign, 0..840 with no leading zero; TZSET would clamp, the edge
;     refuses);
;   * taskbar: GET is the whole row; SET taskbar:<slot> takes exactly
;     "attention 0|1" for a WM slot 0..HDK_WM_SLOTS-1 (WINATTN refuses a slot
;     that holds no live window);
;   * lock: one instance; GET is LOCKSTATE; SET takes exactly "on" (LOCK).
;     Unlocking is not typed: it needs the password at the sign-in form;
;   * wallpaper: one instance; GET is the empty WALLPAPER read; SET takes
;     exactly "image <asset>" (1..HDK_ASSET_MAX of [a-z0-9._-], first a letter
;     or digit, with a '.') or "token desktop|default|taskbar_normal";
;   * clipboard: one instance; GET is CLIPINFO (metadata). S7 (rc-sec ruling
;     11:47:56): GET "content <media>" is CLIPGET <media> in its bare form only
;     (no textfield paste target; CLIPGET keeps its CLIPBOARD_READ), and SET
;     takes exactly "text <media> inline <payload>" (CLIPSET, the payload
;     byte-exact; handle and textfield kinds are not typed). The media is 1..
;     HDK_MEDIA_MAX of [a-z0-9/.+-]; the native checks it against its list.
;     OBSERVE always plans CLIPINFO, and content never leaves the native's
;     own reply;
;   * window (S6): LIST is WINDOWS; GET with no instance is FOCUSED, GET
;     window:<slot> is WINGEOM <slot>; SET window:<slot> takes exactly focus,
;     raise, min, max or close (the native of that name), "move <x> <y>"
;     (WINMOVE) or "size <w> <h>" (WINRESIZE), each value 0..HDK_GEOM_MAX with no
;     leading zero (the native clamps the window on screen). Every window native
;     keeps its own lock and slot-owner gates (session_shell_require_unlocked,
;     wmx_req_may_act), which see the caller's principal through the nested
;     request. WINNEW / WINOPEN / WINCLOSE / ALTTAB are not typed.
; Every unsupported op answers "hook na".
; Identities: clock, taskbar[:<WM slot>], lock, wallpaper, clipboard, window[:<WM slot>|guest].
; SET window:guest show plans RAISE GUEST: owner-only explicit show/reopen of
; the current live display, no START or input capture; the native lock gate applies.
; ============================================================================

HDK_WM_SLOTS       equ 16              ; gui/chat_app WM_MAX (pinned by the host test)
HDK_ZONE_MAX       equ 32              ; gui/window CLOCK_ZONE_NAME_MAX (pinned by the host test)
HDK_ASSET_MAX      equ 31
HDK_TZ_MAX_MIN     equ 840             ; TZSET's clamp
HDK_GEOM_DIGITS    equ 4
HDK_GEOM_MAX       equ 9999            ; a move/size value; the native clamps the window on screen
HDK_MEDIA_MAX      equ 63              ; svc/clipboard CLIP_MEDIA_MAX (pinned by the host test)
HDK_CHAT_OUT_CAP   equ 640             ; gui/chat_app CHAT_OUT_MAX, chat_out_buf's size (pinned by the host test)
%if HDK_CHAT_OUT_CAP >= HOOK_OUT_MAX
%error "chat_out_buf no longer fits one hook reply: cut and flag it as hook_guest_post does"
%endif

; hook_desk_edges_declare -- bind the six descriptors (lea at init, ESSENCE S10)
;   and register them after the slice-4 edges. clobbers: caller-saved.
hook_desk_edges_declare:
    push rbx
    lea  rbx, [rel hook_edge_clock]
    lea  rax, [rel str_hdk_clock]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hdk_kind_service]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hdk_clock_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_clock_plan]
    mov  [rbx + HE_PLAN], rax
    mov  qword [rbx + HE_POST], 0
    lea  rax, [rel gui_out_buf]
    mov  [rbx + HE_OBUF], rax
    lea  rax, [rel gui_out_ready]
    mov  [rbx + HE_OREADY], rax
    lea  rax, [rel str_hdk_clock_witness]
    mov  [rbx + HE_WITNESS], rax
    mov  rdi, rbx
    call command_hook_edge_register

    lea  rbx, [rel hook_edge_taskbar]
    lea  rax, [rel str_hdk_taskbar]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hdk_kind_desktop]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hdk_taskbar_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_taskbar_plan]
    mov  [rbx + HE_PLAN], rax
    mov  qword [rbx + HE_POST], 0
    lea  rax, [rel f1_out_buf]
    mov  [rbx + HE_OBUF], rax
    lea  rax, [rel f1_out_ready]
    mov  [rbx + HE_OREADY], rax
    ; the whole row, its GUARD and BAT tokens included (srcreview S5 L1): each is a taskbar cell, the
    ; Guardian tray cell ("ok" / "<n> new") and the Dell battery text, so a change there is a taskbar change
    mov  qword [rbx + HE_WITNESS], 0
    mov  rdi, rbx
    call command_hook_edge_register

    lea  rbx, [rel hook_edge_lock]
    lea  rax, [rel str_hdk_lock]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hdk_kind_session]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hdk_lock_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_lock_plan]
    mov  [rbx + HE_PLAN], rax
    mov  qword [rbx + HE_POST], 0
    lea  rax, [rel form_out_buf]
    mov  [rbx + HE_OBUF], rax
    lea  rax, [rel form_out_ready]
    mov  [rbx + HE_OREADY], rax
    lea  rax, [rel str_hdk_lock_witness]
    mov  [rbx + HE_WITNESS], rax
    mov  rdi, rbx
    call command_hook_edge_register

    lea  rbx, [rel hook_edge_wallpaper]
    lea  rax, [rel str_hdk_wallpaper]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hdk_kind_desktop]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hdk_wallpaper_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_wallpaper_plan]
    mov  [rbx + HE_PLAN], rax
    mov  qword [rbx + HE_POST], 0
    lea  rax, [rel img_out_buf]
    mov  [rbx + HE_OBUF], rax
    lea  rax, [rel img_out_ready]
    mov  [rbx + HE_OREADY], rax
    lea  rax, [rel str_hdk_wallpaper_witness]
    mov  [rbx + HE_WITNESS], rax
    mov  rdi, rbx
    call command_hook_edge_register

    lea  rbx, [rel hook_edge_clipboard]
    lea  rax, [rel str_hdk_clipboard]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hdk_kind_service]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hdk_clipboard_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_clipboard_plan]
    mov  [rbx + HE_PLAN], rax
    mov  qword [rbx + HE_POST], 0
    lea  rax, [rel clipboard_out_buf]
    mov  [rbx + HE_OBUF], rax
    lea  rax, [rel clipboard_out_ready]
    mov  [rbx + HE_OREADY], rax
    lea  rax, [rel str_hdk_clipboard_witness]
    mov  [rbx + HE_WITNESS], rax
    mov  rdi, rbx
    call command_hook_edge_register

    lea  rbx, [rel hook_edge_window]
    lea  rax, [rel str_hdk_window]
    mov  [rbx + HE_NAME], rax
    lea  rax, [rel str_hdk_kind_desktop]
    mov  [rbx + HE_KIND], rax
    lea  rax, [rel str_hdk_window_schema]
    mov  [rbx + HE_SCHEMA], rax
    lea  rax, [rel hook_window_plan]
    mov  [rbx + HE_PLAN], rax
    lea  rax, [rel hook_window_post]
    mov  [rbx + HE_POST], rax
    lea  rax, [rel chat_out_buf]
    mov  [rbx + HE_OBUF], rax
    lea  rax, [rel chat_out_ready]
    mov  [rbx + HE_OREADY], rax
    lea  rax, [rel str_hdk_window_witness]
    mov  [rbx + HE_WITNESS], rax
    mov  rdi, rbx
    call command_hook_edge_register
    pop  rbx
    ret

; hdk_dec_exact(RDI text, ESI max digits, EDX max value) -> EAX 1 and RCX = the
;   value when RDI is exactly 1..ESI decimal digits (no leading zero unless the
;   number is 0) up to EDX; else EAX 0. clobbers: RAX, RCX, R8
hdk_dec_exact:
    xor  ecx, ecx
    xor  r8d, r8d
.d:
    movzx eax, byte [rdi + r8]
    test eax, eax
    jz   .end
    sub  eax, '0'
    cmp  eax, 9
    ja   .no
    cmp  r8d, esi
    jae  .no
    imul ecx, ecx, 10
    add  ecx, eax
    inc  r8d
    jmp  .d
.end:
    test r8d, r8d
    jz   .no
    cmp  r8d, 1
    je   .range
    cmp  byte [rdi], '0'
    je   .no                              ; one spelling per value
.range:
    cmp  ecx, edx
    ja   .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; hdk_zone_name(RDI) -> EAX 1 when RDI is 1..HDK_ZONE_MAX of [A-Za-z0-9/_+-]
;   and starts with a letter. clobbers: RAX, RCX, RDX
hdk_zone_name:
    xor  ecx, ecx
.c:
    movzx eax, byte [rdi + rcx]
    test eax, eax
    jz   .end
    cmp  ecx, HDK_ZONE_MAX
    jae  .no
    mov  edx, eax
    or   edx, 0x20
    sub  edx, 'a'
    cmp  edx, 'z' - 'a'
    jbe  .ok                              ; a letter
    test ecx, ecx
    jz   .no                              ; the first byte is a letter
    lea  edx, [rax - '0']
    cmp  edx, 9
    jbe  .ok
    cmp  eax, '/'
    je   .ok
    cmp  eax, '_'
    je   .ok
    cmp  eax, '+'
    je   .ok
    cmp  eax, '-'
    jne  .no
.ok:
    inc  ecx
    jmp  .c
.end:
    test ecx, ecx
    jz   .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; hdk_tz_minutes(RDI) -> EAX 1 when RDI is an optional sign then 0..HDK_TZ_MAX_MIN
;   (1..3 digits, no leading zero). clobbers: RAX, RCX, RDX, RSI, RDI, R8
hdk_tz_minutes:
    cmp  byte [rdi], '-'
    je   .sign
    cmp  byte [rdi], '+'
    jne  .num
.sign:
    inc  rdi
.num:
    mov  esi, 3
    mov  edx, HDK_TZ_MAX_MIN
    jmp  hdk_dec_exact

; hdk_asset_name(RDI) -> EAX 1 when RDI is 1..HDK_ASSET_MAX of [a-z0-9._-],
;   starts with a letter or digit and holds a '.'. clobbers: RAX, RCX, RDX
hdk_asset_name:
    xor  ecx, ecx
    xor  edx, edx                         ; dots seen
.c:
    movzx eax, byte [rdi + rcx]
    test eax, eax
    jz   .end
    cmp  ecx, HDK_ASSET_MAX
    jae  .no
    cmp  eax, 'a'
    jb   .not_lower
    cmp  eax, 'z'
    jbe  .ok
.not_lower:
    cmp  eax, '0'
    jb   .punct
    cmp  eax, '9'
    jbe  .ok
.punct:
    test ecx, ecx
    jz   .no                              ; the first byte is a letter or digit
    cmp  eax, '.'
    je   .dot
    cmp  eax, '_'
    je   .ok
    cmp  eax, '-'
    jne  .no
.ok:
    inc  ecx
    jmp  .c
.dot:
    inc  edx
    jmp  .ok
.end:
    test edx, edx
    jz   .no                              ; an asset name has an extension
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; clock edge. plan(EDI op, RSI inst, RDX rest) -> RAX native verb name / 0, EDX reason
;   GET clock                     CLOCK
;   SET clock zone <name>         TZSET <name>
;   SET clock offset <[+-]min>    TZSET <[+-]min>
; ---------------------------------------------------------------------------
hook_clock_plan:
    push rbx
    push r12
    sub  rsp, 8
    mov  r12, rdx
    cmp  byte [rsi], 0
    jne  .bad                             ; one instance: this node's display clock
    cmp  edi, HOP_GET
    je   .get
    cmp  edi, HOP_SET
    je   .set
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    jmp  .out
.get:
    cmp  byte [r12], 0
    jne  .bad
    call command_hook_arg_reset
    lea  rax, [rel str_hdk_verb_clock]
    jmp  .out
.set:
    mov  rdi, r12
    lea  rsi, [rel str_hdk_word_zone]
    call command_hook_after_word
    test rax, rax
    jz   .offset
    mov  rbx, rax
    mov  rdi, rax
    call hdk_zone_name
    test eax, eax
    jz   .bad
    jmp  .plan
.offset:
    mov  rdi, r12
    lea  rsi, [rel str_hdk_word_offset]
    call command_hook_after_word
    test rax, rax
    jz   .bad
    mov  rbx, rax
    mov  rdi, rax
    call hdk_tz_minutes
    test eax, eax
    jz   .bad
.plan:
    call command_hook_arg_reset
    mov  rdi, rbx
    call command_hook_arg_str
    lea  rax, [rel str_hdk_verb_tzset]
    jmp  .out
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; taskbar edge. plan(EDI op, RSI inst, RDX rest) -> RAX native verb name / 0, EDX reason
;   GET taskbar                       TASKBAR
;   SET taskbar:<slot> attention 0|1  WINATTN <slot> <0|1>
; ---------------------------------------------------------------------------
hook_taskbar_plan:
    push rbx
    push r12
    push r13
    mov  r12, rsi
    mov  r13, rdx
    cmp  edi, HOP_GET
    je   .get
    cmp  edi, HOP_SET
    je   .set
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    jmp  .out
.get:
    cmp  byte [r12], 0
    jne  .bad                             ; the row has no per-slot read
    cmp  byte [r13], 0
    jne  .bad
    call command_hook_arg_reset
    lea  rax, [rel str_hdk_verb_taskbar]
    jmp  .out
.set:
    mov  rdi, r12
    mov  esi, 2
    mov  edx, HDK_WM_SLOTS - 1
    call hdk_dec_exact
    test eax, eax
    jz   .bad
    mov  rdi, r13
    lea  rsi, [rel str_hdk_word_attention]
    call command_hook_after_word
    test rax, rax
    jz   .bad
    mov  rbx, rax                         ; the value
    cmp  byte [rbx + 1], 0
    jne  .bad
    cmp  byte [rbx], '0'
    je   .attn
    cmp  byte [rbx], '1'
    jne  .bad
.attn:
    call command_hook_arg_reset
    mov  rdi, r12                         ; the slot, as validated
    call command_hook_arg_str
    lea  rdi, [rel str_hdk_sp]
    call command_hook_arg_str
    mov  rdi, rbx
    call command_hook_arg_str
    lea  rax, [rel str_hdk_verb_winattn]
    jmp  .out
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; lock edge. plan(EDI op, RSI inst, RDX rest) -> RAX native verb name / 0, EDX reason
;   GET lock                      LOCKSTATE
;   SET lock on                   LOCK
; ---------------------------------------------------------------------------
hook_lock_plan:
    push rbx
    mov  rbx, rdx
    cmp  byte [rsi], 0
    jne  .bad                             ; one instance: the sign-in screen
    cmp  edi, HOP_GET
    je   .get
    cmp  edi, HOP_SET
    je   .set
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    jmp  .out
.get:
    cmp  byte [rbx], 0
    jne  .bad
    call command_hook_arg_reset
    lea  rax, [rel str_hdk_verb_lockstate]
    jmp  .out
.set:
    mov  rdi, rbx
    lea  rsi, [rel str_hdk_word_on]
    call command_hook_word_eq
    test eax, eax
    jz   .bad                             ; no unlock: that needs the password at the form
    call command_hook_arg_reset           ; LOCK with no argument (not the discard form)
    lea  rax, [rel str_hdk_verb_lock]
    jmp  .out
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
.out:
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; wallpaper edge. plan(EDI op, RSI inst, RDX rest) -> RAX native verb name / 0, EDX reason
;   GET wallpaper                 WALLPAPER                 (the public read)
;   SET wallpaper image <asset>   WALLPAPER <asset>
;   SET wallpaper token <name>    WALLPAPER token <name>    (desktop|default|taskbar_normal)
; ---------------------------------------------------------------------------
hook_wallpaper_plan:
    push rbx
    push r12
    sub  rsp, 8
    mov  r12, rdx
    cmp  byte [rsi], 0
    jne  .bad                             ; one instance: the desktop layer
    cmp  edi, HOP_GET
    je   .get
    cmp  edi, HOP_SET
    je   .set
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    jmp  .out
.get:
    cmp  byte [r12], 0
    jne  .bad
    call command_hook_arg_reset
    lea  rax, [rel str_hdk_verb_wallpaper]
    jmp  .out
.set:
    mov  rdi, r12
    lea  rsi, [rel str_hdk_word_image]
    call command_hook_after_word
    test rax, rax
    jz   .token
    mov  rbx, rax
    mov  rdi, rax
    call hdk_asset_name
    test eax, eax
    jz   .bad
    call command_hook_arg_reset
    mov  rdi, rbx
    call command_hook_arg_str
    lea  rax, [rel str_hdk_verb_wallpaper]
    jmp  .out
.token:
    mov  rdi, r12
    lea  rsi, [rel str_hdk_word_token]
    call command_hook_after_word
    test rax, rax
    jz   .bad
    mov  rbx, rax
    lea  r12, [rel str_hdk_wallpaper_tokens]
.tok:
    cmp  byte [r12], 0
    je   .bad
    mov  rdi, rbx
    mov  rsi, r12
    call hdk_streq
    test eax, eax
    jnz  .tok_hit
.tok_next:
    inc  r12
    cmp  byte [r12 - 1], 0
    jne  .tok_next
    jmp  .tok
.tok_hit:
    call command_hook_arg_reset
    lea  rdi, [rel str_hdk_token_prefix]
    call command_hook_arg_str
    mov  rdi, r12                         ; the native's own spelling
    call command_hook_arg_str
    lea  rax, [rel str_hdk_verb_wallpaper]
    jmp  .out
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; hdk_streq(RDI, RSI) -> EAX 1 iff the two strings are byte-equal (case kept:
;   WALLPAPER's token names are lower case). clobbers: RAX, RCX, RDX
hdk_streq:
    xor  ecx, ecx
.l:
    mov  al, [rdi + rcx]
    cmp  al, [rsi + rcx]
    jne  .no
    test al, al
    jz   .yes
    inc  ecx
    jmp  .l
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; clipboard edge. plan(EDI op, RSI inst, RDX rest) -> RAX native verb name / 0, EDX reason
;   GET clipboard                                CLIPINFO                          (metadata only, public)
;   GET clipboard content <media>                CLIPGET <media>                   (the bare form: no paste target)
;   SET clipboard text <media> inline <payload>  CLIPSET <media> inline <payload>  (the payload byte-exact)
;   OBSERVE clipboard                            CLIPINFO, always                  (no content-change oracle)
; RCQ-15 S7, rc-sec ruling 11:47:56 (a)-(c): content stays in the native's own reply (clipboard_out_buf).
; No post filter copies it, the event ring records no value, DESCRIBE names no value, and OBSERVE never
; plans CLIPGET: the core hands OBSERVE to planners as GET, so the real op is read from hook_p_op. A
; payload that does not fit the HOOK line is refused whole by the core (" hook err=too_long limit=191"),
; never cut: a cut clipboard command can change meaning.
; ---------------------------------------------------------------------------
hook_clipboard_plan:
    push rbx
    push r12
    sub  rsp, 8
    mov  r12, rdx
    cmp  byte [rsi], 0
    jne  .bad                             ; one instance: the shared clipboard
    cmp  dword [rel hook_p_op], HOP_OBSERVE
    je   .info                            ; OBSERVE: the metadata read only
    cmp  edi, HOP_GET
    je   .get
    cmp  edi, HOP_SET
    je   .set
    mov  edx, HOOK_PLAN_NA
    xor  eax, eax
    jmp  .out
.get:
    cmp  byte [r12], 0
    je   .info
    mov  rdi, r12
    lea  rsi, [rel str_hdk_word_content]
    call command_hook_after_word
    test rax, rax
    jz   .bad
    mov  rbx, rax                         ; the media
    mov  rdi, rax
    call hdk_media_tok
    test eax, eax
    jz   .bad
    cmp  byte [rsi], 0
    jne  .bad                             ; the bare form: no paste target, nothing after the media
    call command_hook_arg_reset
    mov  rdi, rbx
    call command_hook_arg_str
    lea  rax, [rel str_hdk_verb_clipget]
    jmp  .out
.info:
    cmp  byte [r12], 0
    jne  .bad                             ; CLIPINFO refuses any argument
    call command_hook_arg_reset
    lea  rax, [rel str_hdk_verb_clipinfo]
    jmp  .out
.set:
    mov  rdi, r12
    lea  rsi, [rel str_hdk_word_text]
    call command_hook_after_word
    test rax, rax
    jz   .bad
    mov  rbx, rax                         ; the media
    mov  rdi, rax
    call hdk_media_tok
    test eax, eax
    jz   .bad
    cmp  byte [rsi], ' '
    jne  .bad
    mov  r12, rsi
    sub  r12, rbx                         ; the media's length
    lea  rdi, [rsi + 1]
    lea  rsi, [rel str_hdk_word_inline]
    call command_hook_after_word
    test rax, rax
    jz   .bad
    cmp  byte [rax], 0
    je   .bad                             ; an empty payload
    push rax
    sub  rsp, 8
    call command_hook_arg_reset
    mov  rdi, rbx
    mov  esi, r12d
    call command_hook_arg_strn
    lea  rdi, [rel str_hdk_inline_arg]    ; the native's own kind spelling
    call command_hook_arg_str
    add  rsp, 8
    pop  rdi                              ; the payload: every byte to the end of the line, as typed
    call command_hook_arg_str
    lea  rax, [rel str_hdk_verb_clipset]
    jmp  .out
.bad:
    mov  edx, HOOK_PLAN_BADARG
    xor  eax, eax
.out:
    add  rsp, 8
    pop  r12
    pop  rbx
    ret

; hdk_media_tok(RDI) -> EAX 1 = a media token of 1..HDK_MEDIA_MAX bytes of [a-z0-9/.+-] ending at
;   a NUL or a space (CLIPSET/CLIPGET then check it against their own list); RSI = the byte that
;   ended it. EAX 0 otherwise. clobbers: RAX, RCX, RSI
hdk_media_tok:
    mov  rsi, rdi
.c:
    movzx eax, byte [rsi]
    test eax, eax
    jz   .end
    cmp  eax, ' '
    je   .end
    mov  rcx, rsi
    sub  rcx, rdi
    cmp  ecx, HDK_MEDIA_MAX
    jae  .no
    cmp  eax, 'a'
    jb   .sym
    cmp  eax, 'z'
    jbe  .ok
    jmp  .no
.sym:
    cmp  eax, '0'
    jb   .punct
    cmp  eax, '9'
    jbe  .ok
    jmp  .no
.punct:
    cmp  eax, '/'
    je   .ok
    cmp  eax, '.'
    je   .ok
    cmp  eax, '+'
    je   .ok
    cmp  eax, '-'
    jne  .no
.ok:
    inc  rsi
    jmp  .c
.end:
    cmp  rsi, rdi
    je   .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; hdk_dec_tok(RDI text, EDX max value) -> EAX 1 = one decimal token of 1..HDK_GEOM_DIGITS
;   digits, no leading zero unless the number is 0, value <= EDX, ending at a NUL or a
;   space; RSI = the byte that ended it. EAX 0 otherwise. clobbers: RAX, RCX, RSI, R8
hdk_dec_tok:
    xor  ecx, ecx
    mov  rsi, rdi
.d:
    movzx eax, byte [rsi]
    test eax, eax
    jz   .end
    cmp  eax, ' '
    je   .end
    sub  eax, '0'
    cmp  eax, 9
    ja   .no
    mov  r8, rsi
    sub  r8, rdi
    cmp  r8d, HDK_GEOM_DIGITS
    jae  .no
    imul ecx, ecx, 10
    add  ecx, eax
    inc  rsi
    jmp  .d
.end:
    mov  r8, rsi
    sub  r8, rdi
    jz   .no                              ; no digits
    cmp  r8d, 1
    je   .range
    cmp  byte [rdi], '0'
    je   .no                              ; one spelling per token value
.range:
    cmp  ecx, edx
    ja   .no
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; hook_window_plan(EDI op, RSI inst, RDX rest) -> RAX native verb name / 0, EDX reason (S6)
hook_window_plan:
    push rbx
    push r12
    push r13
    mov  ebx, edi
    mov  r12, rsi                         ; the WM slot, or empty
    mov  r13, rdx
    cmp  ebx, HOP_LIST
    je   .list
    cmp  ebx, HOP_GET
    je   .get
    cmp  ebx, HOP_SET
    je   .set
    mov  edx, HOOK_PLAN_NA
    jmp  .none
.list:
    cmp  byte [r12], 0
    jne  .bad                             ; the listing names every slot
    cmp  byte [r13], 0
    jne  .bad
    call command_hook_arg_reset
    lea  rax, [rel str_hdk_verb_windows]
    jmp  .out
.get:
    cmp  byte [r13], 0
    jne  .bad
    cmp  byte [r12], 0
    jne  .geom
    call command_hook_arg_reset
    lea  rax, [rel str_hdk_verb_focused]
    jmp  .out
.geom:
    mov  rdi, r12
    mov  esi, 2
    mov  edx, HDK_WM_SLOTS - 1            ; a window slot to read
    call hdk_dec_exact
    test eax, eax
    jz   .bad
    call command_hook_arg_reset
    mov  rdi, r12
    call command_hook_arg_str
    lea  rax, [rel str_hdk_verb_wingeom]
    jmp  .out
.set:
    mov  rdi, r12
    lea  rsi, [rel str_hdk_word_guest]
    call command_hook_word_eq
    test eax, eax
    jnz  .guest_show
    mov  rdi, r12
    mov  esi, 2
    mov  edx, HDK_WM_SLOTS - 1            ; a window slot to change
    call hdk_dec_exact
    test eax, eax
    jz   .bad                             ; every change names one slot
    lea  rbx, [rel str_hdk_window_verbs]
.word:
    cmp  byte [rbx], 0
    je   .geomset
    mov  rdi, r13
    mov  rsi, rbx
    call command_hook_word_eq
    test eax, eax
    jnz  .one
.skip:
    inc  rbx
    cmp  byte [rbx - 1], 0
    jne  .skip
    jmp  .word
.one:
    call command_hook_arg_reset
    mov  rdi, r12
    call command_hook_arg_str
    mov  rax, rbx                         ; the word is the native verb's own name
    jmp  .out
.guest_show:
    mov  rdi, r13
    lea  rsi, [rel str_hdk_word_show]
    call command_hook_word_eq
    test eax, eax
    jz   .bad
    call command_hook_arg_reset
    lea  rdi, [rel str_hdk_word_guest]
    call command_hook_arg_str
    lea  rax, [rel str_hdk_verb_raise]
    jmp  .out
.geomset:
    mov  rdi, r13
    lea  rsi, [rel str_hdk_word_move]
    call command_hook_after_word
    lea  rbx, [rel str_hdk_verb_winmove]
    test rax, rax
    jnz  .pair
    mov  rdi, r13
    lea  rsi, [rel str_hdk_word_size]
    call command_hook_after_word
    lea  rbx, [rel str_hdk_verb_winresize]
    test rax, rax
    jz   .bad
.pair:
    mov  r13, rax                         ; "<a> <b>"
    mov  rdi, rax
    mov  edx, HDK_GEOM_MAX
    call hdk_dec_tok
    test eax, eax
    jz   .bad
    cmp  byte [rsi], ' '
    jne  .bad
    lea  rdi, [rsi + 1]
    mov  edx, HDK_GEOM_MAX
    call hdk_dec_tok
    test eax, eax
    jz   .bad
    cmp  byte [rsi], 0
    jne  .bad
    call command_hook_arg_reset
    mov  rdi, r12
    call command_hook_arg_str
    lea  rdi, [rel str_hdk_sp]            ; the slot, then the pair
    call command_hook_arg_str
    mov  rdi, r13
    call command_hook_arg_str
    mov  rax, rbx
    jmp  .out
.bad:
    mov  edx, HOOK_PLAN_BADARG
.none:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; hook_window_post(EDI op, RSI inst, RDX rest, RCX rsp) -> EAX 1 = a hook reply staged, 0 = nothing staged (S6).
;   The window natives stage their reply in chat_out_buf, which the UDP reply chain sends only from its marker
;   tail, so a delegated window op would answer without it. As hook_guest_post (S3b), this relays the text:
;   * a native refusal (AUTHDENY " window=ERR denied") passes through untouched, as does an op that staged nothing;
;   * the text is measured only within chat_out_buf (HDK_CHAT_OUT_CAP bytes); with no NUL there, nothing is
;     copied, the reply is " hook err=window_reply_unterminated" and chat_out_ready stays set;
;   * HDK_CHAT_OUT_CAP < HOOK_OUT_MAX (assembly-time check above), so a terminated text always fits whole;
;   * chat_out_ready is cleared only after the copy, so the marker tail never sends the text a second time.
;   Authority is unchanged: this runs after the native gate, on the native's own reply to this caller.
;   clobbers: caller-saved.
hook_window_post:
    cmp  qword [rcx + RSP_CODE], CMDE_OK
    jne  .none                            ; a refusal passes through unchanged
    cmp  byte [rel chat_out_ready], 1
    jne  .none
    lea  rdi, [rel chat_out_buf]
    xor  ecx, ecx
.len:
    cmp  ecx, HDK_CHAT_OUT_CAP
    jae  .unterminated
    cmp  byte [rdi + rcx], 0
    je   .copy
    inc  ecx
    jmp  .len
.copy:
    call command_hook_out_reset           ; clobbers RAX only
    lea  rdi, [rel chat_out_buf]
    mov  esi, HOOK_OUT_MAX - 1
    call command_hook_out_strn
    mov  byte [rel chat_out_ready], 0     ; consumed: the hook reply carries it
    mov  eax, 1
    ret
.unterminated:
    call command_hook_out_reset
    lea  rdi, [rel str_hdk_window_unterm]
    call command_hook_out_str
    mov  eax, 1
    ret
.none:
    xor  eax, eax
    ret

str_hdk_clock:            db "clock", 0
str_hdk_taskbar:          db "taskbar", 0
str_hdk_lock:             db "lock", 0
str_hdk_wallpaper:        db "wallpaper", 0
str_hdk_clipboard:        db "clipboard", 0
str_hdk_window:           db "window", 0
str_hdk_kind_service:     db "service", 0
str_hdk_kind_desktop:     db "desktop", 0
str_hdk_kind_session:     db "session", 0

str_hdk_clock_schema:     db "inst=none get=CLOCK{utc_s,tz_min,wall_valid,shown,zone,src} set=zone <name [A-Za-z0-9/_+-]{1,32}, first a letter>:TZSET <name>(unknown zone: TZSET refuses, state kept)|offset <[+-]0..840>:TZSET <minutes> observe=tz_min,wall_valid,zone,src list=na input=na cancel=na", 0
str_hdk_taskbar_schema:   db "inst=none|<wm_slot 0..15> get=TASKBAR{n,TB[j] win,state,rect,title} set=<slot> attention 0|1:WINATTN <slot> <0|1>(a live window only) observe=the row(GUARD,BAT cells too) list=na input=na cancel=na", 0
str_hdk_lock_schema:      db "inst=none get=LOCKSTATE{form,slot,locked,principal,desktop,rendered,badge_*} set=on:LOCK(unlock is not typed: the password goes to the sign-in form) observe=form,locked,desktop,rendered,badge_dismissed list=na input=na cancel=na", 0
str_hdk_wallpaper_schema: db "inst=none get=WALLPAPER{mode,src,fit} set=image <asset [a-z0-9._-]{1,31} with a dot>:WALLPAPER <asset>|token desktop|default|taskbar_normal:WALLPAPER token <name>(owner) observe=mode,src list=na input=na cancel=na", 0
str_hdk_window_schema:    db "inst=none|<wm_slot 0..15>|guest list=WINDOWS{WIN[i] title,state} get=FOCUSED{FOCUSED,widget}|<slot>:WINGEOM <slot>{x,y,w,h} set=<slot> focus|raise|min|max|close:<that native> <slot>|move <x> <y>:WINMOVE|size <w> <h>:WINRESIZE (0..9999, no leading zero; the native clamps; its lock and slot-owner gates apply) set=guest show:RAISE GUEST (owner-only live graphical guest; reopen/restore/raise, no restart or capture) observe=FOCUSED,widget|x,y,w,h input=na cancel=na", 0
str_hdk_clipboard_schema: db "inst=none get=CLIPINFO{media_type,kind,bytes,provenance,generation}(metadata only)|content <media>:CLIPGET <media>(content; CLIPBOARD_READ) set=text <media> inline <payload>:CLIPSET <media> inline <payload>(byte-exact; a line over 191 bytes is refused, never cut) observe=CLIPINFO media_type,kind,bytes,generation(never content) list=na input=na cancel=na", 0

str_hdk_clock_witness:     db " tz_min=",0," wall_valid=",0," zone=",0," src=",0,0
str_hdk_lock_witness:      db " form=",0," locked=",0," desktop=",0," rendered=",0," badge_dismissed=",0,0
str_hdk_wallpaper_witness: db " mode=",0," src=",0,0
str_hdk_window_witness:    db " FOCUSED=",0," widget=",0," x=",0," y=",0," w=",0," h=",0,0
str_hdk_clipboard_witness: db " media_type=",0," kind=",0," bytes=",0," generation=",0,0

str_hdk_verb_clock:       db "CLOCK", 0
str_hdk_verb_tzset:       db "TZSET", 0
str_hdk_verb_taskbar:     db "TASKBAR", 0
str_hdk_verb_winattn:     db "WINATTN", 0
str_hdk_verb_lockstate:   db "LOCKSTATE", 0
str_hdk_verb_lock:        db "LOCK", 0
str_hdk_verb_wallpaper:   db "WALLPAPER", 0
str_hdk_verb_clipinfo:    db "CLIPINFO", 0
str_hdk_verb_clipget:     db "CLIPGET", 0
str_hdk_verb_clipset:     db "CLIPSET", 0
str_hdk_inline_arg:       db " inline ", 0
str_hdk_verb_windows:     db "WINDOWS", 0
str_hdk_verb_focused:     db "FOCUSED", 0
str_hdk_verb_wingeom:     db "WINGEOM", 0
str_hdk_verb_winmove:     db "WINMOVE", 0
str_hdk_verb_winresize:   db "WINRESIZE", 0
str_hdk_window_verbs:     db "FOCUS",0,"RAISE",0,"MIN",0,"MAX",0,"CLOSE",0,0   ; each SET word is its native's name
str_hdk_word_move:        db "MOVE", 0
str_hdk_word_size:        db "SIZE", 0
str_hdk_word_guest: db "GUEST",0
str_hdk_word_show: db "SHOW",0
str_hdk_verb_raise: db "RAISE",0
str_hdk_window_unterm:    db " hook err=window_reply_unterminated", 0
str_hdk_word_zone:        db "ZONE", 0
str_hdk_word_offset:      db "OFFSET", 0
str_hdk_word_attention:   db "ATTENTION", 0
str_hdk_word_on:          db "ON", 0
str_hdk_word_image:       db "IMAGE", 0
str_hdk_word_token:       db "TOKEN", 0
str_hdk_word_content:     db "CONTENT", 0
str_hdk_word_text:        db "TEXT", 0
str_hdk_word_inline:      db "INLINE", 0
str_hdk_token_prefix:     db "token ", 0
str_hdk_sp:               db " ", 0
str_hdk_wallpaper_tokens: db "desktop",0,"default",0,"taskbar_normal",0,0

align 8
hook_edge_clock:          times (HE_SZ / 8) dq 0
hook_edge_taskbar:        times (HE_SZ / 8) dq 0
hook_edge_lock:           times (HE_SZ / 8) dq 0
hook_edge_wallpaper:      times (HE_SZ / 8) dq 0
hook_edge_clipboard:      times (HE_SZ / 8) dq 0
hook_edge_window:         times (HE_SZ / 8) dq 0
