;; MODULE gui/widget_progress
;; LAYER 6
;; EXPORTS wgt_progress_draw, wgt_progress_set, wgt_progress_get, wgt_progress_sync, wgt_progress_can_arm, wgt_progress_text_mode, wgt_progress_parse_num, wgt_progress_tick
;; IMPORTS gui/widget, gui/window, gui/window_mgmt, gui/form_loader, core/cadence, core/time, core/lib/fmt, core/lib/str
;; CAPS
;; OWNER saga:gui_foundation_ladder
; GK1-2: additive text and marquee modes retain the canonical value/max fields.

; Type-local use of the base's reserved/edit state. Creation already zeroes it,
; so WIDGETNEW and reused form slots share the same defaults and lifetime.
PG_TEXT equ WGI_RSVD                 ; byte: 0 none, 1 percentage, 2 value/max
PG_INDET equ WGI_RSVD+1              ; byte: explicit activity (never changes value)
PG_PHASE equ WGI_CARET               ; bounded 0..31 animation position
PG_TICKS equ WGI_SUBMITS             ; actual widget animation edges
PG_HZ equ WGI_EDIT                   ; 0 = default 10 Hz, else 1..10 Hz
PG_ACC equ WGI_EDITPAD               ; fractional rate accumulator, 0..9
PG_JOB equ WGI_MINVAL                ; optional opaque job-record id, 0 unbound
PG_TYPE equ 5                       ; registered progress vtable index + 1

wgt_progress_draw:
    push rbx
    push r12
    mov  r12d, edi
    call wgt_slot_ptr
    mov  rbx, rax
    mov  r8d, [rbx + WGI_X]
    mov  r9d, [rbx + WGI_Y]
    mov  r10d, [rbx + WGI_W]
    mov  r11d, [rbx + WGI_H]
    ; A zero-valued progress widget must remain visibly present. Paint a
    ; token-backed top/bottom track boundary, then restore the center scanlines
    ; to the ordinary body token. The pixel witness samples the center row, so
    ; its last pixel remains the honest unfilled-track reference.
    mov  ebx, GUI_TOK_OUTLINE
    call fb_fill_rect
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rbx, rax
    mov  r8d, [rbx + WGI_X]
    mov  r9d, [rbx + WGI_Y]
    inc  r9d
    mov  r10d, [rbx + WGI_W]
    mov  r11d, [rbx + WGI_H]
    sub  r11d, 2
    jbe  .value
    mov  ebx, GUI_TOK_WINDOW_BODY
    call fb_fill_rect
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rbx, rax
.value:
    cmp  byte [rbx + PG_INDET], 0
    jne  .marquee
    mov  rcx, [rbx + WGI_MAXVAL]
    test rcx, rcx
    jz   .done
    mov  rax, [rbx + WGI_NUM]
    cmp  rax, rcx
    jbe  .bounded
    mov  rax, rcx
.bounded:
    mov  edx, [rbx + WGI_W]
    mul  rdx                         ; full product: value/max may be uint64
    div  rcx
    test eax, eax
    jz   .done
    ; Preserve one track pixel at the far edge even at value=max.  Besides the
    ; conventional visual boundary, this makes the rendered extent observable:
    ; a full bar must not become a uniform rectangle indistinguishable from an
    ; empty track in the tree-to-pixel consistency check.
    cmp  eax, [rbx + WGI_W]
    jb   .fill_ready
    cmp  eax, 1
    jbe  .done
    dec  eax
.fill_ready:
    mov  r8d, [rbx + WGI_X]
    mov  r9d, [rbx + WGI_Y]
    inc  r9d
    mov  r10d, eax
    mov  r11d, [rbx + WGI_H]
    sub  r11d, 2
    jbe  .done
    mov  ebx, GUI_TOK_SELECTION
    call fb_fill_rect
    jmp  .done
.marquee:
    mov  ecx, [rbx + WGI_W]
    cmp  ecx, 2
    jb   .done
    dec  ecx                         ; preserve the determinate track edge
    mov  r10d, ecx
    shr  r10d, 2
    jnz  .segment
    mov  r10d, 1
.segment:
    sub  ecx, r10d
    mov  eax, [rbx + PG_PHASE]
    and  eax, 31
    imul rax, rcx
    xor  edx, edx
    mov  ecx, 31
    div  rcx
    mov  r8d, [rbx + WGI_X]
    add  r8d, eax
    mov  r9d, [rbx + WGI_Y]
    inc  r9d
    mov  r11d, [rbx + WGI_H]
    sub  r11d, 2
    jbe  .done
    mov  ebx, GUI_TOK_SELECTION
    call fb_fill_rect
.done:
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rbx, rax
    cmp  byte [rbx + PG_TEXT], 0
    je   .out
    cmp  dword [rbx + WGI_H], 18
    jb   .out
    call wgt_progress_format
    ; Omit text that cannot fit rather than escaping the widget's bounds.
    mov  r11d, eax
    shl  eax, 3
    mov  r8d, [rbx + WGI_W]
    sub  r8d, eax
    jb   .out
    shr  r8d, 1
    add  r8d, [rbx + WGI_X]
    mov  r9d, [rbx + WGI_H]
    sub  r9d, 16
    shr  r9d, 1
    add  r9d, [rbx + WGI_Y]
    lea  rdi, [rel wgt_progress_text_buf]
    mov  ecx, GUI_TOK_WINDOW_BODY
    mov  ebx, GUI_TOK_TITLE_TEXT
    call wgt_draw_text
.out:
    pop  r12
    pop  rbx
    ret

wgt_progress_set:
    push rbx
    push r12
    push r13
    push r14
    mov  r12d, edi
    mov  r13, rsi
    mov  r14, rdx
%macro PGKEY 2
    lea  rdi, [rel %1]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   %2
%endmacro
    PGKEY str_pg_text_mode, .text_mode
    PGKEY str_pg_indeterminate, .indeterminate
    PGKEY str_pg_cadence, .cadence
    PGKEY str_pg_job, .job
    lea  rdi, [rel str_pg_value]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .value
    lea  rdi, [rel str_pg_max]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jnz  .unknown
    mov  ebx, 1
    jmp  .parse
.value:
    xor  ebx, ebx
.parse:
    mov  rdi, r14
    call wgt_progress_parse_num
    jc   .bad
    mov  r14, rax
    mov  edi, r12d
    call wgt_slot_ptr
    test ebx, ebx
    jnz  .store_max
    cmp  r14, [rax + WGI_MAXVAL]
    ja   .bad
    mov  [rax + WGI_NUM], r14
    jmp  .redraw
.store_max:
    test r14, r14
    jz   .bad
    mov  [rax + WGI_MAXVAL], r14
    cmp  [rax + WGI_NUM], r14
    jbe  .redraw
    mov  [rax + WGI_NUM], r14
    jmp  .redraw
.text_mode:
    mov  rdi, r14
    call wgt_progress_text_mode
    jc   .bad
    mov  ebx, eax
    mov  edi, r12d
    call wgt_slot_ptr
    mov  [rax + PG_TEXT], bl
    jmp  .redraw
.indeterminate:
    mov  rdi, r14
    call wgt_progress_parse_num
    jc   .bad
    cmp  rax, 1
    ja   .bad
    mov  ebx, eax
    test ebx, ebx
    jz   .indet_store
    call wgt_progress_can_arm
    test eax, eax
    jnz  .bad
.indet_store:
    mov  edi, r12d
    call wgt_slot_ptr
    mov  [rax + PG_INDET], bl
    mov  dword [rax + PG_PHASE], 0
    mov  dword [rax + PG_ACC], 0
    call wgt_progress_sync
    jmp  .redraw
.cadence:
    mov  rdi, r14
    call wgt_progress_parse_num
    jc   .bad
    test rax, rax
    jz   .bad
    cmp  rax, 10
    ja   .bad
    mov  ebx, eax
    mov  edi, r12d
    call wgt_slot_ptr
    mov  [rax + PG_HZ], ebx
    mov  dword [rax + PG_ACC], 0
    jmp  .redraw
.job:
    mov  rdi, r14
    call wgt_progress_parse_num
    jc   .bad
    mov  rbx, rax
    mov  edi, r12d
    call wgt_slot_ptr
    mov  [rax + PG_JOB], rbx
.redraw:
    mov  edi, r12d
    call wgt_draw_id
    xor  eax, eax
    jmp  .out
.unknown:
    ; The generic widget verb appends bad_field; preserve the form taxonomy
    ; in its same bounded reply without replacing the shared dispatcher.
    lea  rdi, [rel str_pg_unknown]
    call wgt_out_str
.bad:
    mov  eax, 1
.out:
%undef PGKEY
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

wgt_progress_get:
    push r12
    push r13
    mov  r12d, edi
    mov  r13, rsi
%macro PGGET 2
    lea  rdi, [rel %1]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   %2
%endmacro
    PGGET str_pg_text_mode, .text_mode
    PGGET str_pg_indeterminate, .indeterminate
    PGGET str_pg_cadence, .cadence
    PGGET str_pg_phase, .phase
    PGGET str_pg_ticks, .ticks
    PGGET str_pg_job, .job
    mov  rsi, r13
    lea  rdi, [rel str_pg_value]
    call strcmp
    test rax, rax
    jz   .value
    lea  rdi, [rel str_pg_max]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jnz  .bad
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rdi, [rax + WGI_MAXVAL]
    jmp  .number
.value:
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rdi, [rax + WGI_NUM]
    jmp  .number
.text_mode:
    mov  edi, r12d
    call wgt_slot_ptr
    movzx edi, byte [rax + PG_TEXT]
    call wgt_progress_mode_name
    jmp  .out
.indeterminate:
    mov  edi, r12d
    call wgt_slot_ptr
    movzx edi, byte [rax + PG_INDET]
    jmp  .number
.cadence:
    mov  edi, r12d
    call wgt_slot_ptr
    mov  edi, [rax + PG_HZ]
    test edi, edi
    jnz  .number
    mov  edi, 10
    jmp  .number
.phase:
    mov  edi, r12d
    call wgt_slot_ptr
    mov  edi, [rax + PG_PHASE]
    jmp  .number
.ticks:
    mov  edi, r12d
    call wgt_slot_ptr
    mov  edi, [rax + PG_TICKS]
    jmp  .number
.job:
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rdi, [rax + PG_JOB]
.number:
    lea  rsi, [rel wgt_progress_num_buf]
    push rsi
    call fmt_dec
    pop  rsi
    mov  byte [rsi + rax], 0
    lea  rax, [rel wgt_progress_num_buf]
    jmp  .out
.bad:
    xor  eax, eax
.out:
%undef PGGET
    pop  r13
    pop  r12
    ret

; Exact enum parser, shared by WKEY lint and the live setter.
wgt_progress_text_mode:
    push rbx
    push r12
    mov  r12, rdi
    xor  ebx, ebx
.next:
    mov  edi, ebx
    call wgt_progress_mode_name
    mov  rsi, rax
    mov  rdi, r12
    call strcmp
    test rax, rax
    jz   .found
    inc  ebx
    cmp  ebx, 3
    jb   .next
    stc
    jmp  .out
.found:
    mov  eax, ebx
    clc
.out:
    pop  r12
    pop  rbx
    ret

wgt_progress_mode_name:
    lea  rax, [rel str_pg_none]
    cmp  edi, 1
    jne  .value
    lea  rax, [rel str_pg_percentage]
    ret
.value:
    cmp  edi, 2
    jne  .done
    lea  rax, [rel str_pg_value]
.done:
    ret

; Full uint64 decimal, rejecting overflow and suffixes before any state store.
wgt_progress_parse_num:
    xor  eax, eax
    mov  r8, 1844674407370955161
    cmp  byte [rdi], 0
    je   .bad
.digit:
    movzx edx, byte [rdi]
    sub  edx, '0'
    cmp  edx, 9
    ja   .bad
    cmp  rax, r8
    ja   .bad
    jb   .add
    cmp  edx, 5
    ja   .bad
.add:
    imul rax, rax, 10
    add  rax, rdx
    inc  rdi
    cmp  byte [rdi], 0
    jne  .digit
    clc
    ret
.bad:
    stc
    ret

; RBX=canonical widget -> EAX=formatted length. One text engine, no new font.
wgt_progress_format:
    push r12
    mov  rdi, [rbx + WGI_NUM]
    cmp  byte [rbx + PG_TEXT], 1
    jne  .first
    mov  rcx, [rbx + WGI_MAXVAL]
    xor  edi, edi
    test rcx, rcx
    jz   .first
    mov  rax, [rbx + WGI_NUM]
    cmp  rax, rcx
    cmova rax, rcx
    mov  edx, 100
    mul  rdx
    div  rcx
    mov  rdi, rax
.first:
    lea  rsi, [rel wgt_progress_text_buf]
    call fmt_dec
    mov  r12, rax
    lea  rsi, [rel wgt_progress_text_buf]
    cmp  byte [rbx + PG_TEXT], 1
    jne  .value
    mov  byte [rsi + r12], '%'
    inc  r12
    jmp  .term
.value:
    mov  byte [rsi + r12], '/'
    inc  r12
    add  rsi, r12
    mov  rdi, [rbx + WGI_MAXVAL]
    call fmt_dec
    add  r12, rax
    lea  rsi, [rel wgt_progress_text_buf]
.term:
    mov  byte [rsi + r12], 0
    mov  eax, r12d
    pop  r12
    ret

; Find the shared marquee row by identity, never cache a potentially reused slot.
wgt_progress_find_cadence:
    xor  eax, eax
    lea  r8, [rel cad_table]
    lea  r9, [rel str_pg_cad_id]
.row:
    cmp  eax, [rel cad_count]
    jae  .missing
    imul rcx, rax, CAD_ENT_SZ
    cmp  [r8 + rcx + CAD_ID], r9
    je   .done
    inc  eax
    jmp  .row
.missing:
    mov  eax, -1
.done:
    ret

wgt_progress_can_arm:
    cmp  qword [rel tsc_khz], 0
    je   .full
    call wgt_progress_find_cadence
    cmp  eax, -1
    jne  .yes
    cmp  dword [rel cad_count], CAD_MAX
    jb   .yes
    xor  ecx, ecx
.hole:
    cmp  qword [r8 + rcx + CAD_ID], 0
    je   .yes
    add  ecx, CAD_ENT_SZ
    cmp  ecx, CAD_MAX*CAD_ENT_SZ
    jb   .hole
.full:
    mov  eax, 1
    ret
.yes:
    xor  eax, eax
    ret

; The single on-demand cadence serves every active progress widget. Disabling
; the last one releases its row. A closed window's destroyed widget cannot
; retain a cadence; the next callback reaps it. No background job is invented.
wgt_progress_sync:
    xor  ecx, ecx
.widget:
    cmp  ecx, [rel wgt_count]
    jae  .release
    mov  edi, ecx
    call wgt_slot_ptr
    cmp  dword [rax + WGI_TYPE], PG_TYPE
    jne  .next
    cmp  byte [rax + PG_INDET], 0
    jne  .needed
.next:
    inc  ecx
    jmp  .widget
.release:
    call wgt_progress_find_cadence
    mov  edi, eax
    jmp  cadence_unregister
.needed:
    call wgt_progress_find_cadence
    cmp  eax, -1
    jne  .done
    mov  rcx, [rel tsc_khz]
    imul rcx, rcx, 100                ; 10 Hz, calibrated milliseconds
    test rcx, rcx
    jz   .done                       ; no guessed TSC frequency
    lea  rdi, [rel str_pg_cad_id]
    mov  esi, 1                      ; on_demand
    mov  edx, 10
    lea  r8, [rel wgt_progress_tick]
    jmp  cadence_register_named
.done:
    ret

wgt_progress_tick:
    push rbx
    push r12
    xor  r12d, r12d
    xor  ebx, ebx
.widget:
    cmp  r12d, [rel wgt_count]
    jae  .paint
    mov  edi, r12d
    call wgt_slot_ptr
    cmp  dword [rax + WGI_TYPE], PG_TYPE
    jne  .next
    cmp  byte [rax + PG_INDET], 0
    je   .next
    mov  edx, [rax + PG_HZ]
    test edx, edx
    jnz  .rate
    mov  edx, 10
.rate:
    add  edx, [rax + PG_ACC]
    cmp  edx, 10
    jb   .acc
    sub  edx, 10
    inc  dword [rax + PG_PHASE]
    and  dword [rax + PG_PHASE], 31
    inc  dword [rax + PG_TICKS]
    ; Hidden widgets keep their state but cannot require a desktop repaint.
    ; In particular the boot KAT's detached widget exercises the controller
    ; without drawing unrelated live windows.
    test dword [rax + WGI_FLAGS], 1
    jz   .acc
    mov  ecx, [rax + WGI_WIN]
    cmp  ecx, WM_MAX
    jae  .acc
    lea  r8, [rel wm_state]
    cmp  dword [r8 + rcx*4], WM_VISIBLE
    jne  .acc
    mov  ebx, 1
.acc:
    mov  [rax + PG_ACC], edx
.next:
    inc  r12d
    jmp  .widget
.paint:
    test ebx, ebx
    jz   .sync
    cmp  byte [rel dpms_blanked], 1     ; RCQ-27 L3: phases advance, nothing is composited blank
    je   .sync
    ; Use the compositor so an animated bar cannot paint over a raised window
    ; or the pointer sprite. Damage/present stays on the existing GUI path.
    call wmx_draw_all
.sync:
    call wgt_progress_sync
    pop  r12
    pop  rbx
    ret

str_pg_value: db "value",0
str_pg_max:   db "max",0
str_pg_text_mode: db "text_mode",0
str_pg_indeterminate: db "indeterminate",0
str_pg_cadence: db "cadence",0
str_pg_phase: db "phase",0
str_pg_ticks: db "ticks",0
str_pg_job: db "job_id",0
str_pg_none: db "none",0
str_pg_percentage: db "percentage",0
str_pg_cad_id: db "progress.marquee",0
str_pg_unknown: db " FORM_ERR_UNKNOWN_KEY",0
wgt_progress_num_buf: times 24 db 0
wgt_progress_text_buf: times 48 db 0
