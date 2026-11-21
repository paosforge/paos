;; MODULE gui/clock_paint
;; LAYER 6
;; PURPOSE Bounded RAM record of clock prefix cells actually presented, for T1-3 C5b.
;; EXPORTS clock_paint_mark, clock_paint_lock_mark, clock_paint_present, clock_paint_format
;; IMPORTS gui/window, gui/command_gui, gui/lock_screen, gui/widget, sec/session, core/time, net/ntp
;; OWNER saga:clock
;; CONTEXT: bsp_only

CP_ENTRY equ 32                      ; frame, NOW_MS, mono_us (u64), site, prefix, padding
CP_PENDING equ 16                    ; x/y (s32), prefix, pending, padding
CP_KEEP equ 8

; EDI=site (0 tray,1 lock), ESI=actual prefix (~/_), R8D/R9D=marker cell.
; Preserves all registers. Drawing alone never publishes a frame.
clock_paint_mark:
    push rax
    push rdx
    cmp  edi, 1
    ja   .out
    mov  eax, edi
    shl  eax, 4
    lea  rdx, [rel cp_pending]
    add  rdx, rax
    mov  [rdx], r8d
    mov  [rdx + 4], r9d
    mov  [rdx + 8], sil
    mov  byte [rdx + 9], 1
    mov  byte [rel cp_pending_any], 1
.out:
    pop  rdx
    pop  rax
    ret

; Called by the lock card's native text raster callback. Only the exact public
; clock widget counts; its normalized text and actual glyph origin are inputs.
clock_paint_lock_mark:
    push rax
    push rdi
    push rsi
    cmp  dword [r12 + WGI_WIN], LOCK_SLOT
    jne  .out
    mov  eax, [rel lock_widget_first]
    add  eax, 11
    imul rax, rax, WGI_SZ
    lea  rsi, [rel wgt_tbl]
    add  rax, rsi
    cmp  r12, rax
    jne  .out
    test r11d, r11d
    jz   .out
    mov  esi, '~'
    cmp  byte [rdi], '~'
    je   .mark
    cmp  byte [rdi], ' '
    jne  .out
    mov  esi, '_'
.mark:
    mov  edi, 1
    call clock_paint_mark
.out:
    pop  rsi
    pop  rdi
    pop  rax
    ret

; R8D..R11D=clipped logical rectangle, AFTER sfence + fb_present_count++.
; Require the WHOLE 8x16 prefix cell: a cursor/partial copy cannot prove a glyph.
; Preserves all registers (fb_present_rect's public contract).
clock_paint_present:
    cmp  byte [rel cp_pending_any], 0
    je   .empty
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    sub  rsp, CP_ENTRY
    mov  r14, rsp
    xor  r12d, r12d
    lea  r13, [rel cp_pending]
.site:
    cmp  byte [r13 + 9], 0
    je   .next
    ; A pending cell from another scene cannot claim a later overdraw of it.
    cmp  byte [rel session_locked], SESSION_LOCKED
    sete al
    cmp  al, r12b
    jne  .discard
    mov  eax, [r13]
    test eax, eax
    js   .next
    cmp  r8d, eax
    jg   .next
    add  rax, 8
    mov  edx, r8d
    add  edx, r10d
    cmp  rax, rdx
    ja   .next
    mov  eax, [r13 + 4]
    test eax, eax
    js   .next
    cmp  r9d, eax
    jg   .next
    add  rax, 16
    mov  edx, r9d
    add  edx, r11d
    cmp  rax, rdx
    ja   .next
    ; A fade that copies only background is not a visible marker frame.
    cmp  word [rel lock_fade_alpha], 256
    jne  .next
    mov  byte [r13 + 9], 0
    mov  rax, [rel fb_present_count]
    mov  [r14], rax
    call boot_ms_now
    mov  [r14 + 8], rax
    call time_monotonic_now_us
    mov  [r14 + 16], rax
    mov  qword [r14 + 24], 0
    mov  al, 't'
    test r12d, r12d
    jz   .tag
    mov  al, 'l'
.tag:
    mov  [r14 + 24], al
    mov  al, [r13 + 8]
    mov  [r14 + 25], al
    cmp  qword [rel ntp_first_commit_us], 0
    jne  .after
    cmp  al, '~'
    jne  .blank
    cmp  qword [rel cp_n_tilde], -1
    je   .last
    inc  qword [rel cp_n_tilde]
    cmp  qword [rel cp_n_tilde], CP_KEEP
    ja   .last
    mov  rax, [rel cp_n_tilde]
    dec  rax
    shl  rax, 5
    lea  rdi, [rel cp_first]
    add  rdi, rax
    call clock_paint_copy
.last:
    lea  rdi, [rel cp_last]
    mov  eax, r12d
    shl  eax, 5
    add  rdi, rax
    call clock_paint_copy
    jmp  .next
.blank:
    cmp  qword [rel cp_n_blank], -1
    je   .next
    inc  qword [rel cp_n_blank]
    jmp  .next
.after:
    ; First post-commit paint per site, even a stale '~' (a grader failure).
    lea  rdi, [rel cp_clear]
    mov  eax, r12d
    shl  eax, 5
    add  rdi, rax
    cmp  qword [rdi], 0
    jne  .next
    call clock_paint_copy
    jmp  .next
.discard:
    mov  byte [r13 + 9], 0
.next:
    add  r13, CP_PENDING
    inc  r12d
    cmp  r12d, 2
    jb   .site
    mov  al, [rel cp_pending + 9]
    or   al, [rel cp_pending + CP_PENDING + 9]
    mov  [rel cp_pending_any], al
    add  rsp, CP_ENTRY
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rbp
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rbx
    pop  rax
.empty:
    ret

; Fixed 32-byte copy, source R14, destination RDI. No caller's vector state.
clock_paint_copy:
    mov  rax, [r14]
    mov  [rdi], rax
    mov  rax, [r14 + 8]
    mov  [rdi + 8], rax
    mov  rax, [r14 + 16]
    mov  [rdi + 16], rax
    mov  rax, [r14 + 24]
    mov  [rdi + 24], rax
    ret

; Standalone CLOCK PAINT content. At most 12 entries, all u64 decimal widths;
; no prefs, pixels, owner data, disk access, reset or lab-profile switch.
clock_paint_format:
    push rbx
    push r12
    push r13
    push r14
    call gui_out_reset
    lea  rdi, [rel str_cp_hdr]
    call gui_out_str
    mov  rdi, [rel cp_n_tilde]
    call gui_out_dec
    lea  rdi, [rel str_cp_blank]
    call gui_out_str
    mov  rdi, [rel cp_n_blank]
    call gui_out_dec
    lea  rdi, [rel str_cp_ovf]
    call gui_out_str
    xor  edi, edi
    cmp  qword [rel cp_n_tilde], CP_KEEP
    seta dil
    call gui_out_dec
    lea  rdi, [rel str_cp_commit]
    call gui_out_str
    mov  rdi, [rel ntp_first_commit_us]
    call gui_out_dec
    lea  rdi, [rel str_cp_origin]
    call gui_out_str
    mov  rdi, [rel ntp_first_commit_origin]
    call gui_out_dec
    lea  rdi, [rel str_cp_first]
    call gui_out_str
    lea  r12, [rel cp_first]
    mov  r13d, CP_KEEP
    call clock_paint_list
    lea  rdi, [rel str_cp_last]
    call gui_out_str
    lea  r12, [rel cp_last]
    mov  r13d, 2
    call clock_paint_list
    lea  rdi, [rel str_cp_clear]
    call gui_out_str
    lea  r12, [rel cp_clear]
    mov  r13d, 2
    call clock_paint_list
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; R12 entries, R13 count; empty list is '-', list separator ','.
clock_paint_list:
    xor  r14d, r14d
.next:
    cmp  qword [r12], 0
    je   .advance
    test r14d, r14d
    jz   .entry
    mov  al, ','
    call clock_paint_char
.entry:
    inc  r14d
    mov  al, [r12 + 24]
    call clock_paint_char
    mov  al, ':'
    call clock_paint_char
    mov  rdi, [r12]
    call gui_out_dec
    mov  al, ':'
    call clock_paint_char
    mov  rdi, [r12 + 8]
    call gui_out_dec
    mov  al, ':'
    call clock_paint_char
    mov  rdi, [r12 + 16]
    call gui_out_dec
    mov  al, ':'
    call clock_paint_char
    mov  al, [r12 + 25]
    call clock_paint_char
.advance:
    add  r12, CP_ENTRY
    dec  r13d
    jnz  .next
    test r14d, r14d
    jnz  .out
    mov  al, '-'
    call clock_paint_char
.out:
    ret

clock_paint_char:
    mov  rsi, [rel gui_out_cur]
    mov  [rsi], al
    inc  rsi
    mov  byte [rsi], 0
    mov  [rel gui_out_cur], rsi
    ret

str_cp_hdr: db "clock_paint v=1 paint_n_tilde=",0
str_cp_blank: db " paint_n_blank=",0
str_cp_ovf: db " paint_ovf=",0
str_cp_commit: db " paint_commit_mono_us=",0
str_cp_origin: db " paint_commit_origin=",0
str_cp_first: db " paint=",0
str_cp_last: db " paint_last=",0
str_cp_clear: db " paint_clear=",0

%include "core/abi/wdata.inc"
%macro WDATA_gui_clock_paint 0
align 8
cp_n_tilde: dq 0
cp_n_blank: dq 0
cp_pending_any: db 0
align 8
cp_pending: times 2*CP_PENDING db 0
cp_first: times CP_KEEP*CP_ENTRY db 0
cp_last: times 2*CP_ENTRY db 0
cp_clear: times 2*CP_ENTRY db 0
%endmacro
WDATA_DEFER WDATA_gui_clock_paint
