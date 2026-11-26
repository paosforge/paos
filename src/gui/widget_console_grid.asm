;; MODULE gui/widget_console_grid
;; LAYER 6
;; EXPORTS console_grid_content_state, grid_window_b_retire, grid_release_window, console_grid_register, console_grid_draw, console_grid_wheel, console_grid_reclaim, grid_claim_snapshot, console_grid_dump_for_window, console_grid_claim_plain, console_grid_restore_owner, console_grid_headless_configure, console_grid_headless_draw, grid_append, grid_clear, grid_scroll, grid_resize, grid_dump_visible_page, grid_scrollback_depth, grid_ansi_capture_top_row, grid_instance_open, grid_instance_close, grid_instance_feed, grid_instance_accept_input, grid_instance_load_widget, grid_instance_validate, grid_widget_id, grid_type_id, grid_cols, grid_rows, grid_line_count, grid_view_offset, grid_cadence_slot, grid_kat_ok, grid_mode, grid_dock_owner, grid_owner_generation, grid_visible_cells
;; IMPORTS gui/compose_job, gui/interpreter_feed, hv/context_execution, boot/serial, boot/beacon, boot/gop, core/heap, core/cadence, core/time, gui/widget, gui/window, gui/window_mgmt, gui/form_loader, gui/ansi_interp, gui/cadence_mark, svc/command_cons
;; CAPS
;; OWNER saga:verb_console
; Contract 2150: one allocation-free console cell grid.  Text pixels are drawn
; only by gui/chat_app::fb_draw_char (the shared font8x16 engine).  The history
; is a bounded byte ring; reflow records logical row starts/lengths, and the
; rendered surface is an explicit {glyph,attr} cell array.

GRID_RAW_BYTES       equ 4096
GRID_LINE_MAX        equ 4096
GRID_MAX_COLS        equ 96
GRID_MAX_ROWS        equ 24
GRID_CELL_BYTES      equ 2
GRID_ROWS_PER_PAGE   equ 8
GRID_CADENCE_MS      equ 100
GRID_FG              equ 0x00CCCCCC  ; D2 terminal text (reference)
GRID_BG              equ GUI_TOK_WINDOW_BODY ; D2 terminal background 0x0C0C0C
GRID_CURSOR_BG       equ 0x00CCCCCC  ; block cursor in the text colour
GRID_INSTANCE_MAX    equ 4              ; 2158: bounded terminal-instance table
GRID_INSTANCE_HANDLE_INDEX_BITS equ 8
GRID_INSTANCE_HANDLE_INDEX_MASK equ 0xff
GRID_INSTANCE_GEN_MAX equ 0x00ffffff
GRID_PIXEL_ROW_HEIGHT equ 16             ; one exact glyph row for CADMARK
GRID_PIXEL_ROW_MAX_BYTES equ (GRID_MAX_COLS * 8 * GRID_PIXEL_ROW_HEIGHT * 4)

GRID_INST_OK         equ 0
GRID_INST_ERR_FULL   equ 1
GRID_INST_ERR_HANDLE equ 2
GRID_INST_ERR_STALE  equ 3
GRID_INST_ERR_FOCUS  equ 4

; Fixed record: metadata followed by a byte-exact copy of the one shared
; interpreter working set and its three bounded buffers.  Slots persist state;
; the globals below are only the transient execution/paint scratch image.
GI_USED              equ 0              ; db
GI_GENERATION        equ 4              ; dd, 24-bit nonzero
GI_WIDGET            equ 8              ; dd
GI_WINDOW            equ 12             ; dd
GI_BACKEND           equ 16             ; dd
GI_SESSION           equ 20             ; dd
GI_SEQ               equ 24             ; dd accepted state transitions
GI_PAINT_SEQ         equ 28             ; dd completed visible paints
GI_INPUT_SEQ         equ 32             ; dd focus-authorized input chunks
GI_FLAGS             equ 36             ; dd reserved bounded status
GI_CANARY_LO         equ 40             ; dq
GI_SCALAR            equ 48
GRID_WORK_SCALAR_BYTES equ 136
GIS_COLS             equ 0
GIS_ROWS             equ 4
GIS_CURSOR_COL       equ 8
GIS_CURSOR_ROW       equ 12
GIS_RAW_HEAD         equ 16
GIS_RAW_LEN          equ 20
GIS_LINE_COUNT       equ 24
GIS_VIEW_OFFSET      equ 28
GIS_MODE             equ 32
GIS_DIRTY            equ 33
GIS_RESIZE_KAT       equ 34
GIS_ANSI             equ 36
GIS_ANSI_BYTES       equ 75
GIS_ALT              equ 112
GIS_ALT_BYTES        equ 21
GI_RAW                equ GI_SCALAR + GRID_WORK_SCALAR_BYTES
GI_CELLS              equ GI_RAW + GRID_RAW_BYTES
GI_ALT_CELLS          equ GI_CELLS + (GRID_MAX_COLS * GRID_MAX_ROWS * GRID_CELL_BYTES)
GI_CANARY_HI          equ GI_ALT_CELLS + (GRID_MAX_COLS * GRID_MAX_ROWS * GRID_CELL_BYTES)
GI_SIZE               equ (GI_CANARY_HI + 8 + 15) & -16
GI_CANARY_LO_VALUE    equ 0x2158A11CE11CA55E
GI_CANARY_HI_VALUE    equ 0xE558C11EC11A8512
GI_SCALAR_DIRTY       equ GI_SCALAR + 33 ; grid_dirty within fixed scalar image
%if GRID_INSTANCE_MAX > (GRID_INSTANCE_HANDLE_INDEX_MASK + 1)
    %error "Task2158 instance index does not fit the handle"
%endif
%if (GI_SIZE * GRID_INSTANCE_MAX) > 98304
    %error "Task2158 fixed table exceeds the contract memory delta"
%endif
%if GRID_PIXEL_ROW_MAX_BYTES > 65536
    %error "Task2158 exact-row CADMARK exceeds the full-CRC ceiling"
%endif

; First use is check-then-kmalloc without a lock: safe while every caller runs in the one GUI
; context on the BSP (frame/app tick, never an interrupt handler). A caller on a second CPU or in
; interrupt context could see 0 concurrently and allocate twice (one block leaks, two users see
; different tables); such a caller would need a lock or a lock cmpxchg publish of the pointer. A
; refusal is logged once (latch below; bb_fill_rect runs per frame); the next call still retries.
; grid_instance_table_base -> RAX = the instance table (GRID_INSTANCE_MAX x GI_SIZE, zeroed), or 0 if
; the heap refused. One kernel-heap block at first use, laid out as the image used to be:
; [table canary_lo][table][table canary_hi], so the boot KAT still proves both table canaries; RAX
; points at the table (8 mod 16, as the image's align 16 + canary). Every caller runs after
; PH_HEAP_INIT; before it kmalloc refuses and the next call retries. Was 54,016 zero bytes in the
; image (PAYLOAD-dell-headroom, c655fbc21 method). Preserves every register except RAX.
grid_instance_table_base:
    mov  rax, [rel grid_instance_table_ptr]
    test rax, rax
    jnz  .have
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    sub  rsp, 8
    mov  edi, GI_SIZE * GRID_INSTANCE_MAX + 16
    call kmalloc
    test rax, rax
    jz   .fail
    mov  rdi, rax
    mov  ecx, GI_SIZE * GRID_INSTANCE_MAX + 16
    push rax
    xor  eax, eax
    rep  stosb
    pop  rax
    mov  rdx, GI_CANARY_LO_VALUE
    mov  [rax], rdx
    mov  rdx, GI_CANARY_HI_VALUE
    mov  [rax + 8 + GI_SIZE * GRID_INSTANCE_MAX], rdx
    add  rax, 8
    mov  [rel grid_instance_table_ptr], rax
    jmp  .done
.fail:
    cmp  byte [rel grid_instance_table_refusal_logged], 0
    jne  .fail_quiet
    mov  byte [rel grid_instance_table_refusal_logged], 1
    lea  rdi, [rel str_grid_inst_alloc_fail]
    call serial_string
.fail_quiet:
    xor  eax, eax
.done:
    add  rsp, 8
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
.have:
    ret

; grid_instance_slot_ptr(EDI=index) -> RAX=record, or 0 when the table could not be allocated (every
; caller checks). Index is already bounded. Clobbers RDX.
grid_instance_slot_ptr:
    call grid_instance_table_base
    test rax, rax
    jz   .out
    mov  edx, edi
    imul rdx, rdx, GI_SIZE
    add  rax, rdx
.out:
    ret

; EDI=index, ESI=generation -> EAX=index+generation handle. Generation zero is
; never issued, so handle zero remains the invalid/unbound widget sentinel.
grid_instance_make_handle:
    mov  eax, esi
    shl  eax, GRID_INSTANCE_HANDLE_INDEX_BITS
    or   eax, edi
    ret

; grid_instance_validate(EDI=handle) -> RAX=record, ECX=index, CF=0.
; Failure returns CF=1 and EDX=GRID_INST_ERR_{HANDLE,STALE}.
grid_instance_validate:
    mov  eax, edi
    mov  ecx, eax
    and  ecx, GRID_INSTANCE_HANDLE_INDEX_MASK
    cmp  ecx, GRID_INSTANCE_MAX
    jae  .bad
    shr  eax, GRID_INSTANCE_HANDLE_INDEX_BITS
    test eax, eax
    jz   .bad
    cmp  eax, GRID_INSTANCE_GEN_MAX
    ja   .bad
    push rdi
    mov  edi, ecx
    call grid_instance_slot_ptr
    pop  rdi
    test rax, rax
    jz   .bad                           ; no table: no handle is valid
    cmp  byte [rax + GI_USED], 1
    jne  .stale
    mov  edx, edi
    shr  edx, GRID_INSTANCE_HANDLE_INDEX_BITS
    cmp  [rax + GI_GENERATION], edx
    jne  .stale
    xor  edx, edx
    clc
    ret
.bad:
    mov  edx, GRID_INST_ERR_HANDLE
    stc
    ret
.stale:
    mov  edx, GRID_INST_ERR_STALE
    stc
    ret

; Copy the transient shared interpreter image into/out of one persistent slot.
; Keep Task2155's shipped globals at their original addresses; the explicit
; groups below make the per-instance record layout independent of source order.
grid_instance_save_ptr:
    push rsi
    push rdi
    push rcx
    mov  rdx, rax
    mov  eax, [rel grid_cols]
    mov  [rdx + GI_SCALAR + GIS_COLS], eax
    mov  eax, [rel grid_rows]
    mov  [rdx + GI_SCALAR + GIS_ROWS], eax
    mov  eax, [rel grid_cursor_col]
    mov  [rdx + GI_SCALAR + GIS_CURSOR_COL], eax
    mov  eax, [rel grid_cursor_row]
    mov  [rdx + GI_SCALAR + GIS_CURSOR_ROW], eax
    mov  eax, [rel grid_raw_head]
    mov  [rdx + GI_SCALAR + GIS_RAW_HEAD], eax
    mov  eax, [rel grid_raw_len]
    mov  [rdx + GI_SCALAR + GIS_RAW_LEN], eax
    mov  eax, [rel grid_line_count]
    mov  [rdx + GI_SCALAR + GIS_LINE_COUNT], eax
    mov  eax, [rel grid_view_offset]
    mov  [rdx + GI_SCALAR + GIS_VIEW_OFFSET], eax
    mov  al, [rel grid_mode]
    mov  [rdx + GI_SCALAR + GIS_MODE], al
    mov  al, [rel grid_dirty]
    mov  [rdx + GI_SCALAR + GIS_DIRTY], al
    mov  al, [rel grid_resize_kat]
    mov  [rdx + GI_SCALAR + GIS_RESIZE_KAT], al
    mov  byte [rdx + GI_SCALAR + 35], 0
    lea  rsi, [rel ansi_cursor_x]
    lea  rdi, [rdx + GI_SCALAR + GIS_ANSI]
    mov  ecx, GIS_ANSI_BYTES
    cld
    rep  movsb
    lea  rsi, [rel ansi_alt_saved_x]
    lea  rdi, [rdx + GI_SCALAR + GIS_ALT]
    mov  ecx, GIS_ALT_BYTES
    rep  movsb
    lea  rsi, [rel grid_raw_ring]
    lea  rdi, [rdx + GI_RAW]
    mov  ecx, GRID_RAW_BYTES
    rep  movsb
    lea  rsi, [rel grid_visible_cells]
    lea  rdi, [rdx + GI_CELLS]
    mov  ecx, GRID_MAX_COLS * GRID_MAX_ROWS * GRID_CELL_BYTES
    rep  movsb
    lea  rsi, [rel ansi_alt_saved_cells]
    lea  rdi, [rdx + GI_ALT_CELLS]
    mov  ecx, GRID_MAX_COLS * GRID_MAX_ROWS * GRID_CELL_BYTES
    rep  movsb
    pop  rcx
    pop  rdi
    pop  rsi
    ret

grid_instance_load_ptr:
    push rsi
    push rdi
    push rcx
    mov  rdx, rax
    mov  eax, [rdx + GI_SCALAR + GIS_COLS]
    mov  [rel grid_cols], eax
    mov  eax, [rdx + GI_SCALAR + GIS_ROWS]
    mov  [rel grid_rows], eax
    mov  eax, [rdx + GI_SCALAR + GIS_CURSOR_COL]
    mov  [rel grid_cursor_col], eax
    mov  eax, [rdx + GI_SCALAR + GIS_CURSOR_ROW]
    mov  [rel grid_cursor_row], eax
    mov  eax, [rdx + GI_SCALAR + GIS_RAW_HEAD]
    mov  [rel grid_raw_head], eax
    mov  eax, [rdx + GI_SCALAR + GIS_RAW_LEN]
    mov  [rel grid_raw_len], eax
    mov  eax, [rdx + GI_SCALAR + GIS_LINE_COUNT]
    mov  [rel grid_line_count], eax
    mov  eax, [rdx + GI_SCALAR + GIS_VIEW_OFFSET]
    mov  [rel grid_view_offset], eax
    mov  al, [rdx + GI_SCALAR + GIS_MODE]
    mov  [rel grid_mode], al
    mov  al, [rdx + GI_SCALAR + GIS_DIRTY]
    mov  [rel grid_dirty], al
    mov  al, [rdx + GI_SCALAR + GIS_RESIZE_KAT]
    mov  [rel grid_resize_kat], al
    lea  rsi, [rdx + GI_SCALAR + GIS_ANSI]
    lea  rdi, [rel ansi_cursor_x]
    mov  ecx, GIS_ANSI_BYTES
    cld
    rep  movsb
    lea  rsi, [rdx + GI_SCALAR + GIS_ALT]
    lea  rdi, [rel ansi_alt_saved_x]
    mov  ecx, GIS_ALT_BYTES
    rep  movsb
    lea  rsi, [rdx + GI_RAW]
    lea  rdi, [rel grid_raw_ring]
    mov  ecx, GRID_RAW_BYTES
    rep  movsb
    cmp  byte [rel grid_mode], 1
    je   .lines_ready
    push rdx
    call grid_reflow                  ; rebuild derived plain scrollback index
    pop  rdx
.lines_ready:
    lea  rsi, [rdx + GI_CELLS]
    lea  rdi, [rel grid_visible_cells]
    mov  ecx, GRID_MAX_COLS * GRID_MAX_ROWS * GRID_CELL_BYTES
    rep  movsb
    lea  rsi, [rdx + GI_ALT_CELLS]
    lea  rdi, [rel ansi_alt_saved_cells]
    mov  ecx, GRID_MAX_COLS * GRID_MAX_ROWS * GRID_CELL_BYTES
    rep  movsb
    pop  rcx
    pop  rdi
    pop  rsi
    ret

grid_instance_reset_work:
    xor  eax, eax
    mov  dword [rel grid_cols], 48
    mov  dword [rel grid_rows], 12
    mov  [rel grid_cursor_col], eax
    mov  [rel grid_cursor_row], eax
    mov  [rel grid_raw_head], eax
    mov  [rel grid_raw_len], eax
    mov  [rel grid_line_count], eax
    mov  [rel grid_view_offset], eax
    mov  [rel grid_mode], al
    mov  [rel grid_dirty], al
    mov  [rel grid_resize_kat], al
    lea  rdi, [rel ansi_cursor_x]
    mov  ecx, GIS_ANSI_BYTES
    cld
    rep  stosb
    mov  byte [rel ansi_fg], 7
    mov  byte [rel ansi_cursor_visible], 1
    lea  rdi, [rel ansi_alt_saved_x]
    mov  ecx, GIS_ALT_BYTES
    xor  eax, eax
    rep  stosb
    lea  rdi, [rel grid_raw_ring]
    mov  ecx, GRID_RAW_BYTES
    xor  eax, eax
    rep  stosb
    lea  rdi, [rel ansi_alt_saved_cells]
    mov  ecx, GRID_MAX_COLS * GRID_MAX_ROWS * GRID_CELL_BYTES
    rep  stosb
    call ansi_grid_reset
    ret

; Allocate from the bounded table. EAX=nonzero handle/EDX=OK or EAX=0 and
; EDX=FULL. No heap path exists.
grid_instance_open:
    push rbx
    push r12
    xor  r12d, r12d
.scan:
    cmp  r12d, GRID_INSTANCE_MAX
    jae  .full
    mov  edi, r12d
    call grid_instance_slot_ptr
    test rax, rax
    jz   .full                          ; heap refused the table: refuse the create
    cmp  byte [rax + GI_USED], 0
    je   .take
    inc  r12d
    jmp  .scan
.take:
    mov  ebx, [rax + GI_GENERATION]
    test ebx, ebx
    jnz  .have_gen
    mov  ebx, 1
.have_gen:
    mov  rdi, rax
    mov  ecx, GI_SIZE / 8
    xor  eax, eax
    cld
    rep  stosq
    mov  byte [rdi - GI_SIZE + GI_USED], 1
    mov  [rdi - GI_SIZE + GI_GENERATION], ebx
    mov  dword [rdi - GI_SIZE + GI_WIDGET], -1
    mov  dword [rdi - GI_SIZE + GI_WINDOW], -1
    lea  rbx, [rdi - GI_SIZE]
    mov  rax, GI_CANARY_LO_VALUE
    mov  [rbx + GI_CANARY_LO], rax
    mov  rax, GI_CANARY_HI_VALUE
    mov  [rbx + GI_CANARY_HI], rax
    call grid_instance_reset_work
    mov  rax, rbx
    call grid_instance_save_ptr
    mov  esi, [rbx + GI_GENERATION]
    mov  edi, r12d
    call grid_instance_make_handle
    xor  edx, edx
    clc
    pop  r12
    pop  rbx
    ret
.full:
    xor  eax, eax
    mov  edx, GRID_INST_ERR_FULL
    stc
    pop  r12
    pop  rbx
    ret

; Close wipes all terminal/session bytes, advances generation, and leaves only
; that future-generation seed in the free slot.
; grid_window_b_retire -- B18 (ADMIN 2026-10-02 ruling (2)): PaOS-ANSI-B is a boot self-test window. After the
; instance KAT ([gui.ansi.instances], composed at boot) and the desktop start, retire it exactly as the instance
; "close" op does: close the instance (wiped, generation advanced), clear the widget binding, close the window.
; Consumers open their own instance on demand. Idempotent.
grid_window_b_retire:
    push rbx
    push rbx                          ; the pair keeps RSP 16-aligned; RBX survives wmx_close_slot's painters
    mov  edi, [rel grid_window_b_widget]
    cmp  edi, -1
    je   .out
    call wgt_slot_ptr
    mov  rbx, rax
    mov  eax, [rel grid_window_b_slot]
    cmp  [rbx + WGI_WIN], eax
    jne  .forget                      ; the record no longer belongs to window B: touch nothing
    mov  edi, [rbx + WGI_RSVD]
    call grid_instance_close
    mov  dword [rbx + WGI_RSVD], 0
    mov  dword [rbx + WGI_BIND], 0
    mov  edi, [rel grid_window_b_slot]
    cmp  edi, WM_MAX
    jae  .forget
    lea  rax, [rel wm_state]
    cmp  dword [rax + rdi*4], WM_FREE
    je   .forget
    cmp  dword [rax + rdi*4], WM_CLOSED
    je   .forget
    call wmx_close_slot
.forget:
    mov  dword [rel grid_window_b_widget], -1
    mov  dword [rel grid_window_b_slot], -1
.out:
    pop  rbx
    pop  rbx
    ret

; grid_release_window(EDI=WM slot) -- B18 (2026-10-02): wmx_close_slot calls this before the window's widgets are
; retired, so a closed grid window (title-bar close, CLOSE verb, the B18 retire) returns its bounded-table instance,
; as the tab-strip pool does. Without it the boot KAT's Demo-C instance stayed allocated after the retire. The
; console's compatibility claim (grid_claim_handle) keeps its existing lifetime (console_grid_reclaim owns it).
grid_release_window:
    push rbx
    push r12
    push r13
    mov  r13d, edi
    cmp  dword [rel grid_type_id], -1
    je   .done                        ; the grid type never registered: nothing can hold an instance
    xor  r12d, r12d
.scan:
    cmp  r12d, [rel wgt_count]
    jae  .done
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rbx, rax
    cmp  [rbx + WGI_WIN], r13d
    jne  .next
    mov  eax, [rel grid_type_id]
    inc  eax                          ; WGI_TYPE holds type index + 1
    cmp  [rbx + WGI_TYPE], eax
    jne  .next
    mov  edi, [rbx + WGI_RSVD]
    test edi, edi
    jz   .next
    cmp  edi, [rel grid_claim_handle]
    je   .next
    call grid_instance_close          ; CF on a stale handle: the binding is cleared either way
    mov  dword [rbx + WGI_RSVD], 0
    mov  dword [rbx + WGI_BIND], 0
.next:
    inc  r12d
    jmp  .scan
.done:
    pop  r13
    pop  r12
    pop  rbx
    ret

grid_instance_close:
    push rbx
    call grid_instance_validate
    jc   .out
    mov  ebx, [rax + GI_GENERATION]
    inc  ebx
    cmp  ebx, GRID_INSTANCE_GEN_MAX
    jbe  .gen_ok
    mov  ebx, 1
.gen_ok:
    mov  rdi, rax
    mov  ecx, GI_SIZE / 8
    xor  eax, eax
    cld
    rep  stosq
    lea  rdx, [rdi - GI_SIZE]
    mov  [rdx + GI_GENERATION], ebx
    mov  rax, GI_CANARY_LO_VALUE
    mov  [rdx + GI_CANARY_LO], rax
    mov  rax, GI_CANARY_HI_VALUE
    mov  [rdx + GI_CANARY_HI], rax
    xor  eax, eax
    xor  edx, edx
    clc
.out:
    pop  rbx
    ret

; EDI=handle, RSI=bytes, EDX=len. Parsing always progresses, including for a
; minimized/background binding; painting is a separate bounded decision.
grid_instance_feed:
    push rbx
    push r12
    push r13
    mov  r12, rsi
    mov  r13d, edx
    call grid_instance_validate
    jc   .bad
    mov  rbx, rax
    call grid_instance_load_ptr
    mov  rdi, r12
    mov  esi, r13d
    call context_ansi_enter
    call interpreter_ansi_feed
    call context_ansi_exit
    mov  rax, rbx
    call grid_instance_save_ptr
    inc  dword [rbx + GI_SEQ]
    xor  eax, eax
    xor  edx, edx
    clc
    jmp  .out
.bad:
    mov  eax, 1
    stc
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Same feed seam for keyboard/input routers, with the shipped focus arbiter as
; the only authority. Unfocused input refuses without changing any slot byte.
grid_instance_accept_input:
    push rbx
    push r12
    push r13
    push r14
    mov  r14d, edi
    mov  r12, rsi
    mov  r13d, edx
    call grid_instance_validate
    jc   .bad
    mov  rbx, rax
    mov  edi, [rbx + GI_WINDOW]
    cmp  edi, [rel wm_focus]
    jne  .focus
    cmp  edi, WM_MAX
    jae  .focus
    lea  rax, [rel wm_state]
    cmp  dword [rax + rdi*4], WM_VISIBLE
    jne  .focus
    mov  rsi, r12
    mov  edi, r14d
    mov  edx, r13d
    call grid_instance_feed
    jc   .bad
    inc  dword [rbx + GI_INPUT_SEQ]
    jmp  .ok
.focus:
    mov  eax, 1
    mov  edx, GRID_INST_ERR_FOCUS
    stc
    jmp  .out
.bad:
    mov  eax, 1
    stc
    jmp  .out
.ok:
    xor  eax, eax
    xor  edx, edx
    clc
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Bind an already-open handle to one existing widget/window. WGI_RSVD is the
; additive 32-bit handle field; WGI_BIND exposes the backend class.
; EDI=handle, ESI=widget, EDX=backend, ECX=session.
grid_instance_bind_widget:
    push rbx
    push r12
    push r13
    push r14
    mov  r12d, edi
    mov  r13d, esi
    mov  ebx, edx
    mov  r14d, ecx
    call grid_instance_validate
    jc   .out
    mov  [rax + GI_WIDGET], r13d
    mov  [rax + GI_BACKEND], ebx
    mov  [rax + GI_SESSION], r14d
    mov  edi, r13d
    call wgt_slot_ptr
    mov  [rax + WGI_RSVD], r12d
    mov  [rax + WGI_BIND], ebx
    mov  edx, [rax + WGI_WIN]
    push rdx
    mov  edi, r12d
    call grid_instance_validate
    pop  rdx
    jc   .out
    mov  [rax + GI_WINDOW], edx
    xor  eax, eax
    xor  edx, edx
    clc
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Load the instance attached to a widget. Invalid/unbound widgets fail closed.
grid_instance_load_widget:
    push rbx
    mov  ebx, edi
    call wgt_slot_ptr
    mov  edi, [rax + WGI_RSVD]
    call grid_instance_validate
    jc   .out
    call grid_instance_load_ptr
.out:
    pop  rbx
    ret

; grid_raw_get(EDI=logical byte offset) -> EAX=byte.
grid_raw_get:
    mov  eax, [rel grid_raw_head]
    add  eax, edi
    cmp  eax, GRID_RAW_BYTES
    jb   .idx
    sub  eax, GRID_RAW_BYTES
.idx:
    lea  rdx, [rel grid_raw_ring]
    movzx eax, byte [rdx + rax]
    ret

; ANSI scrollback owns the evicted full-screen rows as raw glyph bytes. This
; is intentionally separate from grid_append: capture must not reflow or
; rebuild the primary screen while the interpreter is moving rows.
grid_ansi_raw_put:
    mov  eax, [rel grid_raw_len]
    cmp  eax, GRID_RAW_BYTES
    jae  .overwrite
    mov  ecx, [rel grid_raw_head]
    add  ecx, eax
    cmp  ecx, GRID_RAW_BYTES
    jb   .store
    sub  ecx, GRID_RAW_BYTES
.store:
    lea  rdx, [rel grid_raw_ring]
    mov  [rdx + rcx], dil
    inc  dword [rel grid_raw_len]
    ret
.overwrite:
    mov  ecx, [rel grid_raw_head]
    lea  rdx, [rel grid_raw_ring]
    mov  [rdx + rcx], dil
    inc  ecx
    cmp  ecx, GRID_RAW_BYTES
    jb   .head
    xor  ecx, ecx
.head:
    mov  [rel grid_raw_head], ecx
    ret

grid_ansi_capture_top_row:
    push rbx
    cmp  dword [rel ansi_scroll_top], 0
    jne  .out
    mov  eax, [rel grid_rows]
    dec  eax
    cmp  [rel ansi_scroll_bottom], eax
    jne  .out
    xor  ebx, ebx
.cell:
    cmp  ebx, [rel grid_cols]
    jae  .newline
    lea  rax, [rel grid_visible_cells]
    movzx edi, byte [rax + rbx*2]
    call grid_ansi_raw_put
    inc  ebx
    jmp  .cell
.newline:
    mov  edi, 10
    call grid_ansi_raw_put
    cmp  dword [rel grid_line_count], GRID_LINE_MAX
    jae  .out
    inc  dword [rel grid_line_count]
.out:
    pop  rbx
    ret

; Reflow the raw ring at the current column width.  Wrap prefers the final
; space in a full row, then skips boundary spaces; a word wider than the row is
; split deterministically.  Newlines are explicit row boundaries.
grid_reflow:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r15d, [rel grid_cols]
    test r15d, r15d
    jnz  .cols_ok
    mov  r15d, 1
.cols_ok:
    xor  r12d, r12d                    ; logical source position
    xor  r13d, r13d                    ; output line count
    cmp  dword [rel grid_raw_len], 0
    jne  .line
    mov  dword [rel grid_line_starts], 0
    mov  word [rel grid_line_lens], 0
    mov  dword [rel grid_line_count], 1
    jmp  .done
.line:
    cmp  r12d, [rel grid_raw_len]
    jae  .finish
    cmp  r13d, GRID_LINE_MAX
    jae  .finish
    lea  rax, [rel grid_line_starts]
    mov  [rax + r13*4], r12d
    mov  ebx, r12d                     ; row start
    xor  r14d, r14d                    ; row length
    mov  r11d, -1                      ; last space logical offset
.scan:
    cmp  r12d, [rel grid_raw_len]
    jae  .store
    mov  edi, r12d
    call grid_raw_get
    cmp  al, 10
    je   .newline
    cmp  al, ' '
    jne  .not_space
    mov  r11d, r12d
.not_space:
    inc  r12d
    inc  r14d
    cmp  r14d, r15d
    jb   .scan
    ; A newline immediately after an exactly-full row terminates that row; it
    ; must not materialize as a spurious empty row on the next iteration.
    cmp  r12d, [rel grid_raw_len]
    jae  .word_wrap
    mov  edi, r12d
    call grid_raw_get
    cmp  al, 10
    jne  .word_wrap
    inc  r12d
    jmp  .store
.word_wrap:
    ; Full row: wrap at a word boundary when there is a non-leading space.
    cmp  r11d, -1
    je   .store
    cmp  r11d, ebx
    jbe  .store
    mov  r14d, r11d
    sub  r14d, ebx
    lea  r12d, [r11d + 1]
.skip_spaces:
    cmp  r12d, [rel grid_raw_len]
    jae  .store
    mov  edi, r12d
    call grid_raw_get
    cmp  al, ' '
    jne  .store
    inc  r12d
    jmp  .skip_spaces
.newline:
    inc  r12d                         ; consume newline, not a rendered cell
.store:
    lea  rax, [rel grid_line_lens]
    mov  [rax + r13*2], r14w
    inc  r13d
    jmp  .line
.finish:
    test r13d, r13d
    jnz  .have
    mov  r13d, 1
.have:
    mov  [rel grid_line_count], r13d
    ; A resize/append can reduce history; keep the viewport in range.
    mov  eax, r13d
    sub  eax, [rel grid_rows]
    jns  .max_ok
    xor  eax, eax
.max_ok:
    cmp  [rel grid_view_offset], eax
    jbe  .done
    mov  [rel grid_view_offset], eax
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Materialize the viewport as {glyph,attr} cells.  attr=1 identifies the live
; cursor cell and selects the third (cursor) color in console_grid_draw.
grid_build_visible:
    push rbx
    push r12
    push r13
    push r14
    push r15
    lea  rdi, [rel grid_visible_cells]
    mov  ecx, GRID_MAX_COLS * GRID_MAX_ROWS
.blank:
    mov  byte [rdi], ' '
    mov  byte [rdi + 1], 0
    add  rdi, GRID_CELL_BYTES
    dec  ecx
    jnz  .blank
    mov  eax, [rel grid_line_count]
    sub  eax, [rel grid_view_offset]    ; exclusive end line
    jns  .end_ok
    xor  eax, eax
.end_ok:
    mov  r15d, eax
    sub  eax, [rel grid_rows]
    jns  .start_ok
    xor  eax, eax
.start_ok:
    mov  r14d, eax                     ; first visible logical line
    xor  r12d, r12d                    ; viewport row
.row:
    mov  eax, r14d
    add  eax, r12d
    cmp  eax, r15d
    jae  .cursor
    mov  ebx, eax                      ; logical line index
    lea  rdx, [rel grid_line_starts]
    mov  r13d, [rdx + rbx*4]
    lea  rdx, [rel grid_line_lens]
    movzx ebx, word [rdx + rbx*2]
    cmp  ebx, [rel grid_cols]
    jbe  .len_ok
    mov  ebx, [rel grid_cols]
.len_ok:
    xor  ecx, ecx
.cell:
    cmp  ecx, ebx
    jae  .next_row
    mov  edi, r13d
    add  edi, ecx
    push rcx
    call grid_raw_get
    pop  rcx
    mov  edx, r12d
    imul edx, GRID_MAX_COLS
    add  edx, ecx
    shl  edx, 1
    lea  rdi, [rel grid_visible_cells]
    mov  [rdi + rdx], al
    inc  ecx
    jmp  .cell
.next_row:
    inc  r12d
    cmp  r12d, [rel grid_rows]
    jb   .row
.cursor:
    cmp  dword [rel grid_view_offset], 0
    jne  .done
    mov  eax, [rel grid_line_count]
    dec  eax
    sub  eax, r14d                    ; cursor viewport row
    js   .done
    cmp  eax, [rel grid_rows]
    jae  .done
    mov  edx, [rel grid_line_count]
    dec  edx
    lea  rdi, [rel grid_line_lens]
    movzx ecx, word [rdi + rdx*2]
    cmp  ecx, [rel grid_cols]
    jb   .cursor_col_ok
    mov  ecx, [rel grid_cols]
    dec  ecx
.cursor_col_ok:
    mov  [rel grid_cursor_row], eax
    mov  [rel grid_cursor_col], ecx
    imul eax, GRID_MAX_COLS
    add  eax, ecx
    shl  eax, 1
    lea  rdi, [rel grid_visible_cells]
    mov  byte [rdi + rax + 1], 1
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; grid_append(RDI=bytes, RSI=len) — bounded append, no allocation.
grid_append:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13, rsi
    xor  r14d, r14d
    mov  edi, [rel grid_claim_handle]
    call grid_instance_validate
    jc   .claim_loaded
    mov  r14, rax
    call grid_instance_load_ptr
.claim_loaded:
    xor  ebx, ebx
.append:
    cmp  rbx, r13
    jae  .rebuild
    mov  eax, [rel grid_raw_len]
    cmp  eax, GRID_RAW_BYTES
    jae  .overwrite
    mov  ecx, [rel grid_raw_head]
    add  ecx, eax
    cmp  ecx, GRID_RAW_BYTES
    jb   .store
    sub  ecx, GRID_RAW_BYTES
.store:
    lea  rdx, [rel grid_raw_ring]
    mov  al, [r12 + rbx]
    mov  [rdx + rcx], al
    inc  dword [rel grid_raw_len]
    jmp  .next
.overwrite:
    mov  ecx, [rel grid_raw_head]
    lea  rdx, [rel grid_raw_ring]
    mov  al, [r12 + rbx]
    mov  [rdx + rcx], al
    inc  ecx
    cmp  ecx, GRID_RAW_BYTES
    jb   .head_ok
    xor  ecx, ecx
.head_ok:
    mov  [rel grid_raw_head], ecx
.next:
    inc  ebx
    jmp  .append
.rebuild:
    mov  dword [rel grid_view_offset], 0
    call grid_reflow
    call grid_build_visible
    mov  byte [rel grid_dirty], 1
    test r14, r14
    jz   .saved
    mov  rax, r14
    call grid_instance_save_ptr
.saved:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

grid_clear:
    push rbx
    xor  ebx, ebx
    mov  edi, [rel grid_claim_handle]
    call grid_instance_validate
    jc   .claim_loaded
    mov  rbx, rax
    call grid_instance_load_ptr
.claim_loaded:
    mov  dword [rel grid_raw_head], 0
    mov  dword [rel grid_raw_len], 0
    mov  dword [rel grid_view_offset], 0
    call grid_reflow
    call grid_build_visible
    mov  byte [rel grid_dirty], 1
    test rbx, rbx
    jz   .saved
    mov  rax, rbx
    call grid_instance_save_ptr
.saved:
    pop  rbx
    ret

; Explicit singleton-owner transitions. A plain owner must select its mode
; before the first resize/reflow; otherwise a cadence draw can reinterpret
; freshly appended plain cells through stale ANSI cursor state. Restore uses
; the ANSI subsystem's documented live fixture rather than retaining a second
; text grid or copying the shared cell plane.
; console_grid_claim_plain(EDI=widget id, SIL=dock policy)
console_grid_claim_plain:
    push rbx
    push r12
    push r13
    push r14
    mov  r12d, edi
    movzx r13d, sil
    mov  dword [rel grid_claim_handle], 0
    call wgt_slot_ptr
    mov  ebx, [rax + WGI_RSVD]
    mov  r14d, [rax + WGI_WIN]
    mov  edi, ebx
    call grid_instance_validate
    jnc  .selected
    call grid_instance_open
    jc   .legacy
    mov  ebx, eax
    mov  edi, ebx
    mov  esi, r12d
    mov  edx, 1
    mov  ecx, r14d
    call grid_instance_bind_widget
    jc   .bind_failed
.selected:
    mov  [rel grid_claim_handle], ebx
    mov  edi, ebx
    call grid_instance_validate
    jc   .legacy
    call grid_instance_load_ptr
    jmp  .legacy
.bind_failed:
    mov  edi, ebx
    call grid_instance_close
    xor  ebx, ebx
.legacy:
    mov  [rel grid_widget_id], r12d
    mov  [rel grid_dock_owner], r13b
    mov  byte [rel grid_mode], 0
    inc  dword [rel grid_owner_generation]
    mov  edi, r12d
    call grid_resize
    mov  edi, [rel grid_claim_handle]
    call grid_instance_validate
    jc   .out
    call grid_instance_save_ptr
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; console_grid_reclaim(EDI=widget id) -- B5 (usage suite TAB-02/TAB-03): give the
; plain owner a FRESH instance (new handle, empty history) for the next tab's
; view. The outgoing instance is closed (wiped, generation advanced) first, so
; the bounded table never holds a parked view. Clobbers caller-saved registers.
console_grid_reclaim:
    push rbx
    mov  ebx, edi
    mov  edi, [rel grid_claim_handle]
    call grid_instance_close
    mov  dword [rel grid_claim_handle], 0
    mov  edi, ebx
    call wgt_slot_ptr
    mov  dword [rax + WGI_RSVD], 0
    mov  dword [rax + WGI_BIND], 0
    mov  edi, ebx
    xor  esi, esi
    call console_grid_claim_plain
    pop  rbx
    ret

; grid_claim_snapshot(RDI=dst, ESI=capacity) -> EAX = bytes copied: the claimed
; plain owner's history, oldest byte first (what grid_append replays verbatim).
; Reads the instance record only; the shared working set is untouched. 0 when
; there is no instanced claim. Clobbers RCX, RDX, RSI, RDI, R8.
grid_claim_snapshot:
    push rbx
    push r12
    mov  r12, rdi
    mov  ebx, esi
    mov  edi, [rel grid_claim_handle]
    call grid_instance_validate
    jc   .none
    mov  ecx, [rax + GI_SCALAR + GIS_RAW_LEN]
    cmp  ecx, GRID_RAW_BYTES
    jbe  .len_ok
    mov  ecx, GRID_RAW_BYTES
.len_ok:
    cmp  ecx, ebx
    jbe  .cap_ok
    mov  ecx, ebx
.cap_ok:
    mov  edx, [rax + GI_SCALAR + GIS_RAW_HEAD]
    xor  r8d, r8d
.copy:
    cmp  r8d, ecx
    jae  .done
    mov  esi, edx
    add  esi, r8d
    cmp  esi, GRID_RAW_BYTES
    jb   .idx
    sub  esi, GRID_RAW_BYTES
.idx:
    movzx edi, byte [rax + GI_RAW + rsi]
    mov  [r12 + r8], dil
    inc  r8d
    jmp  .copy
.done:
    mov  eax, ecx
    jmp  .out
.none:
    xor  eax, eax
.out:
    pop  r12
    pop  rbx
    ret

; console_grid_restore_owner(EDI=widget id, SIL=dock policy, DL=mode)
console_grid_restore_owner:
    push rbx
    push r12
    push r13
    push r14
    mov  ebx, edx
    mov  r12d, edi
    movzx r13d, sil
    mov  r14d, [rel grid_widget_id]
    mov  edi, [rel grid_claim_handle]
    call grid_instance_close
    cmp  r14d, [rel wgt_count]
    jae  .claim_released
    mov  edi, r14d
    call wgt_slot_ptr
    mov  dword [rax + WGI_RSVD], 0
    mov  dword [rax + WGI_BIND], 0
.claim_released:
    mov  dword [rel grid_claim_handle], 0
    mov  [rel grid_widget_id], r12d
    mov  [rel grid_dock_owner], r13b
    mov  edi, r12d
    call wgt_slot_ptr
    mov  edi, [rax + WGI_RSVD]
    call grid_instance_validate
    jc   .legacy
    call grid_instance_load_ptr
    jmp  .published
.legacy:
    ; Derive the restored owner's geometry using the plain reflow path before
    ; ANSI reset reconstructs its complete documented cell/cursor state.
    mov  byte [rel grid_mode], 0
    mov  edi, r12d
    call grid_resize
    test bl, bl
    jz   .published
    call ansi_grid_reset
    lea  rdi, [rel ansi_live_head]
    mov  esi, ansi_live_head.len
    call ansi_grid_feed
    lea  rdi, [rel grid_nonce_buf]
    mov  esi, grid_nonce_buf.len
    call ansi_grid_feed
    lea  rdi, [rel ansi_live_color]
    mov  esi, ansi_live_color.len
    call ansi_grid_feed
.published:
    inc  dword [rel grid_owner_generation]
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; grid_scroll(EDI=signed rows; positive=history/up, negative=down).
grid_scroll:
    cmp  byte [rel grid_mode], 1
    jne  .plain
    xor  eax, eax
    ret
.plain:
    mov  eax, [rel grid_line_count]
    sub  eax, [rel grid_rows]
    jns  .max_ok
    xor  eax, eax
.max_ok:
    mov  ecx, [rel grid_view_offset]
    add  ecx, edi
    jns  .lower_ok
    xor  ecx, ecx
.lower_ok:
    cmp  ecx, eax
    jbe  .upper_ok
    mov  ecx, eax
.upper_ok:
    mov  [rel grid_view_offset], ecx
    ; grid_build_visible is caller-clobbering and uses RCX for cell walks.
    ; Preserve the API's computed scroll position across materialization so
    ; EAX reports the new offset rather than the last rendered column.
    push rcx
    call grid_build_visible
    pop  rax
    mov  byte [rel grid_dirty], 1
    ret

; grid_resize(EDI=widget id) — derive cell geometry from the widget's current
; rect.  This is the public in-image resize API: callers establish the new rect,
; then this routine deterministically reflows it without allocating.
grid_resize:
    push rbx
    call wgt_slot_ptr
    mov  rbx, rax
    mov  edx, [rbx + WGI_W]
    cmp  edx, 8
    jae  .width_min
    mov  edx, 8
.width_min:
    cmp  edx, GRID_MAX_COLS * 8
    jbe  .width_max
    mov  edx, GRID_MAX_COLS * 8
.width_max:
    shr  edx, 3
    mov  [rel grid_cols], edx
    mov  edx, [rbx + WGI_H]
    cmp  edx, 16
    jae  .height_min
    mov  edx, 16
.height_min:
    cmp  edx, GRID_MAX_ROWS * 16
    jbe  .height_max
    mov  edx, GRID_MAX_ROWS * 16
.height_max:
    shr  edx, 4
    mov  [rel grid_rows], edx
    cmp  byte [rel grid_mode], 1
    jne  .plain
    call ansi_grid_resize
    mov  byte [rel grid_dirty], 1
    pop  rbx
    ret
.plain:
    call grid_reflow
    call grid_build_visible
    mov  byte [rel grid_dirty], 1
    pop  rbx
    ret

; The rung-0 proof widget is dock-filled in Demo C.  Keep that composition
; policy outside grid_resize so the API remains rect-driven and later forms can
; choose other layouts.  Cadence applies the dock policy before each redraw,
; making owner WINRESIZE changes reflow on the next registered tick.
console_grid_fit_owner:
    push rbx
    push r12
    push r13
    mov  r12d, edi
    xor  r13d, r13d                    ; geometry changed
    call wgt_slot_ptr
    mov  rbx, rax
    mov  eax, [rbx + WGI_WIN]
    cmp  eax, WM_MAX
    jae  .out
    lea  rcx, [rel wm_w]
    mov  edx, [rcx + rax*4]
    sub  edx, WGT_PAD_X * 2
    cmp  edx, 8
    jae  .width_min
    mov  edx, 8
.width_min:
    cmp  edx, GRID_MAX_COLS * 8
    jbe  .width_max
    mov  edx, GRID_MAX_COLS * 8
.width_max:
    and  edx, -8
    cmp  [rbx + WGI_W], edx
    je   .width_same
    mov  [rbx + WGI_W], edx
    mov  r13d, 1
.width_same:
    lea  rcx, [rel wm_y]
    mov  edx, [rcx + rax*4]
    lea  rcx, [rel wm_h]
    add  edx, [rcx + rax*4]
    sub  edx, [rbx + WGI_Y]
    sub  edx, 8
    cmp  edx, 16
    jae  .height_min
    mov  edx, 16
.height_min:
    cmp  edx, GRID_MAX_ROWS * 16
    jbe  .height_max
    mov  edx, GRID_MAX_ROWS * 16
.height_max:
    and  edx, -16
    cmp  [rbx + WGI_H], edx
    je   .height_same
    mov  [rbx + WGI_H], edx
    mov  r13d, 1
.height_same:
    test r13d, r13d
    jz   .out
    mov  edi, r12d
    call grid_resize
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

console_grid_draw:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r15d, edi
    call grid_instance_load_widget
    mov  edi, r15d                    ; loader consumes EDI as the handle
    call grid_resize
    mov  edi, r15d
    call wgt_slot_ptr
    mov  r14, rax
    ; Publish one exact glyph-row DRAW before the glyph loop. A whole terminal
    ; may exceed CADMARK's 64 KiB full-CRC ceiling (and would be sampled), while
    ; even the widest supported row is statically bounded below it. CADMARK's
    ; on-demand read finalizes this record after the painter returns, binding
    ; the generation handle to unsampled native framebuffer bytes without
    ; reopening release SCREEN/SCREEN2. Prefer row 1, which the Task2158 probe
    ; fills with its challenge; a one-row legacy grid safely falls back to 0.
    cmp  byte [rel cadence_mark_level], 0
    jne  .cadmark
    inc  dword [rel cadence_dropped]
    jmp  .cadmark_done
.cadmark:
    movzx edi, word [r14 + WGI_RSVD]   ; generation handle, exact live instance
    mov  esi, CADE_DRAW
    mov  edx, [r14 + WGI_X]
    mov  eax, [r14 + WGI_Y]
    cmp  dword [rel grid_rows], 1
    jbe  .cadmark_row_ready
    add  eax, GRID_PIXEL_ROW_HEIGHT
.cadmark_row_ready:
    shl  eax, 16
    or   edx, eax
    mov  ecx, [r14 + WGI_W]
    mov  eax, GRID_PIXEL_ROW_HEIGHT
    shl  eax, 16
    or   ecx, eax
    call cadence_mark
.cadmark_done:
    xor  r12d, r12d
.row:
    xor  r13d, r13d
.col:
    mov  eax, r12d
    imul eax, GRID_MAX_COLS
    add  eax, r13d
    shl  eax, 1
    mov  r15d, eax
    lea  rdx, [rel grid_visible_cells]
    movzx edx, byte [rdx + rax]
    mov  r8d, [r14 + WGI_X]
    mov  ecx, r13d
    shl  ecx, 3
    add  r8d, ecx
    mov  r9d, [r14 + WGI_Y]
    mov  eax, r12d
    shl  eax, 4
    add  r9d, eax
    cmp  byte [rel grid_mode], 1
    jne  .plain_colors
    lea  r10, [rel grid_visible_cells]
    movzx r11d, byte [r10 + r15 + 1]
    mov  eax, r11d
    and  eax, 7
    lea  r10, [rel grid_ansi_palette]
    test r11b, 8
    jz   .ansi_fg
    lea  r10, [rel grid_ansi_bright_palette]
.ansi_fg:
    mov  ebx, [r10 + rax*4]
    mov  eax, r11d
    shr  eax, 4
    and  eax, 7
    lea  r10, [rel grid_ansi_palette]
    mov  ecx, [r10 + rax*4]
    test r11b, 0x80
    jz   .paint
    mov  ecx, GRID_CURSOR_BG
    jmp  .paint
.plain_colors:
    mov  ebx, GRID_FG
    mov  ecx, GRID_BG
    lea  r10, [rel grid_visible_cells]
    cmp  byte [r10 + r15 + 1], 0
    je   .paint
    mov  ecx, GRID_CURSOR_BG
.paint:
    call wgt_draw_glyph
    inc  r13d
    cmp  r13d, [rel grid_cols]
    jb   .col
    inc  r12d
    cmp  r12d, [rel grid_rows]
    jb   .row
    sfence
    mov  byte [rel grid_dirty], 0
    ; Persist resize + paint state back to the widget's generation-checked
    ; record. Unbound legacy widgets retain the original global behavior.
    mov  edi, [r14 + WGI_RSVD]
    call grid_instance_validate
    jc   .paint_saved
    mov  rbx, rax
    call grid_instance_save_ptr
.paint_saved:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Task2505 uses the same cell plane and shared font painter without creating a
; widget or WM slot. Geometry is the framebuffer-clipped grid ceiling; direct
; GOP mode makes these writes immediately visible, while a pre-attached shadow
; remains compatible with fb_present_all.
console_grid_headless_configure:
    mov  dword [rel grid_claim_handle], 0
    mov  dword [rel grid_widget_id], -1
    mov  byte [rel grid_mode], 0
    mov  byte [rel grid_dock_owner], 0
    mov  eax, [rel fb_width]
    shr  eax, 3
    test eax, eax
    jnz  .cols_nonzero
    mov  eax, 1
.cols_nonzero:
    cmp  eax, GRID_MAX_COLS
    jbe  .cols_ready
    mov  eax, GRID_MAX_COLS
.cols_ready:
    mov  [rel grid_cols], eax
    mov  eax, [rel fb_height]
    shr  eax, 4
    test eax, eax
    jnz  .rows_nonzero
    mov  eax, 1
.rows_nonzero:
    cmp  eax, GRID_MAX_ROWS
    jbe  .rows_ready
    mov  eax, GRID_MAX_ROWS
.rows_ready:
    mov  [rel grid_rows], eax
    jmp  grid_clear

console_grid_headless_draw:
    call fb_compose_defer_scene
    jnc .draw
    ret
.draw:
    push rbx
    push r12
    push r13
    push r14
    xor  r12d, r12d
.row:
    xor  r13d, r13d
.col:
    mov  eax, r12d
    imul eax, GRID_MAX_COLS
    add  eax, r13d
    shl  eax, 1
    lea  r14, [rel grid_visible_cells]
    movzx edx, byte [r14 + rax]
    mov  r8d, r13d
    shl  r8d, 3
    mov  r9d, r12d
    shl  r9d, 4
    mov  ebx, GRID_FG
    mov  ecx, GRID_BG
    cmp  byte [r14 + rax + 1], 0
    je   .paint
    mov  ecx, GRID_CURSOR_BG
.paint:
    call wgt_draw_glyph
    inc  r13d
    cmp  r13d, [rel grid_cols]
    jb   .col
    inc  r12d
    cmp  r12d, [rel grid_rows]
    jb   .row
    sfence
    mov  byte [rel grid_dirty], 0
    call fb_present_all
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

console_grid_set:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12d, edi
    mov  r13, rsi
    mov  r14, rdx
    lea  rdi, [rel str_grid_field_feed]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .feed
    lea  rdi, [rel str_grid_field_input]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .input
    lea  rdi, [rel str_grid_field_close]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .close
    lea  rdi, [rel str_grid_field_minimize]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .minimize
    lea  rdi, [rel str_grid_field_restore]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .restore
    lea  rdi, [rel str_grid_field_spawn]
    mov  rsi, r13
    call strcmp
    test rax, rax
    jz   .spawn
    mov  eax, 1
    jmp  .out
; B18 ruling (2) (2026-10-02): PaOS-ANSI-B is retired after the boot KAT, so a consumer that needs a second live
; instance opens its own: a fresh bounded-table instance bound to a new grid widget in its own standard window, the
; shape and placement rule the KAT gave PaOS-ANSI-B (right of the target widget's window, else below it; 408x280).
; Refused (EAX=1) when the instance table, the WM or the widget pool is full; nothing half-made is left behind.
.spawn:
    call grid_instance_open
    jc   .bad
    mov  r15d, eax                    ; instance handle
    mov  edi, r12d
    call wgt_slot_ptr
    mov  eax, [rax + WGI_WIN]
    cmp  eax, WM_MAX
    jae  .spawn_close_instance
    lea  rcx, [rel wm_x]
    mov  esi, [rcx + rax*4]
    lea  rcx, [rel wm_w]
    add  esi, [rcx + rax*4]
    add  esi, 24
    lea  rcx, [rel wm_y]
    mov  edx, [rcx + rax*4]
    mov  ecx, esi
    add  ecx, 408
    cmp  ecx, [rel fb_width]
    jbe  .spawn_position_ready
    lea  rcx, [rel wm_x]
    mov  esi, [rcx + rax*4]
    lea  rcx, [rel wm_h]
    add  edx, [rcx + rax*4]
    add  edx, 24
.spawn_position_ready:
    lea  rdi, [rel str_grid_window_b_title]
    mov  ecx, 408
    mov  r8d, 280
    mov  r9d, WM_RESTORE_FRESH
    call wmx_open_window
    cmp  eax, -1
    je   .spawn_close_instance
    mov  r14d, eax                    ; window slot (R12-R15 survive the painters; RBX does not)
    mov  edi, [rel grid_type_id]
    mov  esi, r14d
    call wgt_create
    cmp  eax, -1
    je   .spawn_close_window
    mov  r13d, eax                    ; grid widget id
    mov  edi, r13d
    call console_grid_fit_owner
    mov  edi, r15d
    mov  esi, r13d
    mov  edx, 1                       ; local PaOS text backend
    mov  ecx, r14d
    call grid_instance_bind_widget
    jc   .spawn_close_window          ; closing the window releases its widget
    call wmx_draw_all
    xor  eax, eax
    jmp  .out
.spawn_close_window:
    mov  edi, r14d
    call wmx_close_slot
.spawn_close_instance:
    mov  edi, r15d
    call grid_instance_close
    jmp  .bad
.feed:
    mov  rdi, r14
    call strlen
    mov  ebx, eax
    mov  edi, r12d
    call wgt_slot_ptr
    mov  edi, [rax + WGI_RSVD]
    mov  rsi, r14
    mov  edx, ebx
    call grid_instance_feed
    jc   .bad
    jmp  .accepted
.input:
    mov  rdi, r14
    call strlen
    mov  ebx, eax
    mov  edi, r12d
    call wgt_slot_ptr
    mov  edi, [rax + WGI_RSVD]
    mov  rsi, r14
    mov  edx, ebx
    call grid_instance_accept_input
    jc   .bad
.accepted:
    mov  edi, r12d
    call wgt_slot_ptr
    mov  [rax + WGI_VLEN], ebx
    mov  ecx, [rax + WGI_WIN]
    lea  rdx, [rel wm_state]
    xor  r15d, r15d
    cmp  dword [rdx + rcx*4], WM_VISIBLE
    setz r15b
    mov  edi, r12d
    call wgt_draw_id                  ; hidden/minimized owner suppresses paint
    test r15d, r15d
    jz   .accepted_done
    mov  edi, r12d
    call wgt_slot_ptr
    mov  edi, [rax + WGI_RSVD]
    call grid_instance_validate
    jc   .bad
    inc  dword [rax + GI_PAINT_SEQ]
.accepted_done:
    xor  eax, eax
    jmp  .out
.close:
    mov  edi, r12d
    call wgt_slot_ptr
    mov  rbx, rax
    mov  edi, [rbx + WGI_RSVD]
    call grid_instance_close
    jc   .bad
    mov  dword [rbx + WGI_RSVD], 0
    mov  dword [rbx + WGI_BIND], 0
    mov  edi, [rbx + WGI_WIN]
    call wmx_close_slot
    xor  eax, eax
    jmp  .out
.minimize:
    mov  edi, r12d
    call wgt_slot_ptr
    mov  edi, [rax + WGI_WIN]
    call wmx_minimize_slot
    xor  eax, eax
    jmp  .out
.restore:
    mov  edi, r12d
    call wgt_slot_ptr
    mov  edi, [rax + WGI_WIN]
    call wmx_raise_slot
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
; EDI=already-admitted console widget id. Append only the existing bound
; handle and persistent dimensions; EAX=1 when complete, otherwise 0 without
; a partial suffix. Never allocate, load shared interpreter scratch, invoke a
; widget callback, or read terminal/session bytes. GUI BSP context, as above.
console_grid_content_state:
    push rbx
    push r12
    push r13
    mov  r12d, edi
    ; Original validate reaches the allocating table helper. An absent table
    ; must therefore be refused BEFORE that call, even for a plausible handle.
    cmp  qword [rel grid_instance_table_ptr], 0
    je   .missing
    call wgt_slot_ptr
    mov  rbx, rax
    mov  edi, [rbx + WGI_RSVD]
    mov  r13d, edi
    call grid_instance_validate
    jc   .missing
    cmp  [rax + GI_WIDGET], r12d
    jne  .missing
    mov  edx, [rbx + WGI_WIN]
    cmp  [rax + GI_WINDOW], edx
    jne  .missing
    mov  rdx, GI_CANARY_LO_VALUE
    cmp  [rax + GI_CANARY_LO], rdx
    jne  .missing
    mov  rdx, GI_CANARY_HI_VALUE
    cmp  [rax + GI_CANARY_HI], rdx
    jne  .missing
    mov  edx, [rax + GI_SCALAR + GIS_COLS]
    test edx, edx
    jz   .missing
    cmp  edx, GRID_MAX_COLS
    ja   .missing
    mov  edx, [rax + GI_SCALAR + GIS_ROWS]
    test edx, edx
    jz   .missing
    cmp  edx, GRID_MAX_ROWS
    ja   .missing
    mov  r12, rax
    lea  rdi, [rel str_grid_content_handle]
    call wgt_out_str
    mov  edi, r13d
    call wgt_out_dec
    lea  rdi, [rel str_grid_content_cols]
    call wgt_out_str
    mov  edi, [r12 + GI_SCALAR + GIS_COLS]
    call wgt_out_dec
    lea  rdi, [rel str_grid_content_rows]
    call wgt_out_str
    mov  edi, [r12 + GI_SCALAR + GIS_ROWS]
    call wgt_out_dec
    mov  eax, 1
    jmp  .out
.missing:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

console_grid_get:
    xor  eax, eax
    ret

; console_grid_wheel(EDI=window slot, ESI=signed notches, + = up/history) ->
; EAX=1 when an instanced console_grid in that window took the wheel.
; 2026-10-01 (usage suite CON-02, G11 wheel): the transcript scrolls back
; GRID_WHEEL_LINES lines a notch (Windows' default), clamped to the retained
; history by grid_scroll; new output returns to the live end (grid_append).
; The instance is loaded, scrolled and saved like every other mutation; the
; cadence repaints it (grid_scroll marks it dirty).
GRID_WHEEL_LINES equ 3
console_grid_wheel:
    push rbx
    push r12
    push r13
    mov  r12d, edi
    mov  r13d, esi
    xor  ebx, ebx
.scan:
    cmp  ebx, [rel wgt_count]
    jae  .none
    mov  edi, ebx
    call wgt_slot_ptr
    mov  edx, [rel grid_type_id]
    inc  edx
    cmp  [rax + WGI_TYPE], edx
    jne  .next
    cmp  [rax + WGI_WIN], r12d
    jne  .next
    mov  edi, [rax + WGI_RSVD]
    call grid_instance_validate
    jc   .next
    push rax
    call grid_instance_load_ptr
    imul edi, r13d, GRID_WHEEL_LINES
    call grid_scroll
    pop  rax
    call grid_instance_save_ptr
    mov  eax, 1
    jmp  .out
.next:
    inc  ebx
    jmp  .scan
.none:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Cadence controller: resize/reflow first, then repaint in place through the
; widget vtable path.  It preserves the registry driver's callee-saved state.
console_grid_cadence_draw:
    push rbx
    push r12
    xor  ebx, ebx
.scan:
    cmp  ebx, [rel wgt_count]
    jae  .out
    mov  edi, ebx
    call wgt_slot_ptr
    mov  edx, [rel grid_type_id]
    inc  edx
    cmp  [rax + WGI_TYPE], edx
    jne  .next
    mov  edi, [rax + WGI_RSVD]
    call grid_instance_validate
    jc   .legacy
    cmp  byte [rax + GI_SCALAR_DIRTY], 0
    je   .next
    mov  edi, ebx
    call wgt_draw_id
    jmp  .next
.legacy:
    cmp  ebx, [rel grid_widget_id]
    jne  .next
    cmp  byte [rel grid_dock_owner], 0
    je   .legacy_geometry_ready
    mov  edi, ebx
    call console_grid_fit_owner
.legacy_geometry_ready:
    cmp  byte [rel grid_dirty], 0
    je   .next
    mov  edi, ebx
    call wgt_draw_id
.next:
    inc  ebx
    jmp  .scan
.out:
    pop  r12
    pop  rbx
    ret

; Return scrollback depth (lines above the visible viewport) in EAX.
grid_scrollback_depth:
    cmp  byte [rel grid_mode], 1
    jne  .plain
    mov  eax, [rel grid_line_count]
    ret
.plain:
    mov  eax, [rel grid_line_count]
    sub  eax, [rel grid_rows]
    jns  .out
    xor  eax, eax
.out:
    ret

; Build the visible-grid page in grid_out_buf. EDI=widget id, ESI=1-based page.
; The command layer prepends the metadata header and owns error framing; this
; helper emits complete rows and never silently truncates one.
grid_dump_visible_page:
    push rbx
    push r12
    push r13
    push r14
    mov  r12d, edi
    mov  r13d, esi
    call grid_out_reset
    mov  ecx, GRID_ROWS_PER_PAGE
    cmp  byte [rel grid_mode], 1
    jne  .page_rows_ready
    mov  ecx, 3                         ; attrs + instance metadata stay <1472B
.page_rows_ready:
    mov  [rel grid_dump_rows_per_page], ecx
    mov  eax, [rel grid_rows]
    add  eax, ecx
    dec  eax
    xor  edx, edx
    div  ecx
    test eax, eax
    jnz  .pages
    mov  eax, 1
.pages:
    mov  [rel grid_dump_pages], eax
    cmp  r13d, 1
    jb   .bad
    cmp  r13d, eax
    ja   .bad
    lea  rdi, [rel str_grid_dump_head]
    call grid_out_str
    mov  edi, [rel grid_cols]
    call grid_out_dec
    lea  rdi, [rel str_grid_dump_rows]
    call grid_out_str
    mov  edi, [rel grid_rows]
    call grid_out_dec
    lea  rdi, [rel str_grid_dump_scroll]
    call grid_out_str
    call grid_scrollback_depth
    mov  edi, eax
    call grid_out_dec
    lea  rdi, [rel str_grid_dump_cursor]
    call grid_out_str
    mov  edi, [rel grid_cursor_row]
    call grid_out_dec
    lea  rdi, [rel str_grid_comma]
    call grid_out_str
    mov  edi, [rel grid_cursor_col]
    call grid_out_dec
    lea  rdi, [rel str_grid_dump_page]
    call grid_out_str
    mov  edi, r13d
    call grid_out_dec
    lea  rdi, [rel str_grid_slash]
    call grid_out_str
    mov  edi, [rel grid_dump_pages]
    call grid_out_dec
    lea  rdi, [rel str_grid_dump_resize]
    call grid_out_str
    movzx edi, byte [rel grid_resize_kat]
    call grid_out_dec
    cmp  byte [rel grid_mode], 1
    je   .mode_ansi
    lea  rdi, [rel str_grid_dump_plain]
    call grid_out_str
    call .owner_fields
    jmp  .header_done
.mode_ansi:
    lea  rdi, [rel str_grid_dump_ansi]
    call grid_out_str
    movzx edi, byte [rel ansi_grid_kat_flags]
    call grid_out_dec
    lea  rdi, [rel str_grid_dump_parser]
    call grid_out_str
    movzx edi, byte [rel ansi_parser_state]
    call grid_out_dec
    lea  rdi, [rel str_grid_dump_alt]
    call grid_out_str
    movzx edi, byte [rel ansi_alt_active]
    call grid_out_dec
    lea  rdi, [rel str_grid_dump_cursor_vis]
    call grid_out_str
    movzx edi, byte [rel ansi_cursor_visible]
    call grid_out_dec
    lea  rdi, [rel str_grid_dump_region]
    call grid_out_str
    mov  edi, [rel ansi_scroll_top]
    call grid_out_dec
    lea  rdi, [rel str_grid_comma]
    call grid_out_str
    mov  edi, [rel ansi_scroll_bottom]
    call grid_out_dec
    call .owner_fields
    jmp  .header_done
.owner_fields:
    lea  rdi, [rel str_grid_dump_owner]
    call grid_out_str
    mov  edi, [rel grid_dump_owner]
    call grid_out_dec
    lea  rdi, [rel str_grid_dump_owner_generation]
    call grid_out_str
    mov  edi, [rel grid_owner_generation]
    call grid_out_dec
    lea  rdi, [rel str_grid_dump_instance]
    call grid_out_str
    mov  edi, [rel grid_dump_handle]
    call grid_out_dec
    lea  rdi, [rel str_grid_dump_instance_generation]
    call grid_out_str
    mov  edi, [rel grid_dump_handle]
    shr  edi, GRID_INSTANCE_HANDLE_INDEX_BITS
    call grid_out_dec
    lea  rdi, [rel str_grid_dump_session]
    call grid_out_str
    mov  edi, [rel grid_dump_session]
    call grid_out_dec
    lea  rdi, [rel str_grid_dump_backend]
    call grid_out_str
    mov  edi, [rel grid_dump_backend]
    call grid_out_dec
    lea  rdi, [rel str_grid_dump_seq]
    call grid_out_str
    mov  edi, [rel grid_dump_seq]
    call grid_out_dec
    lea  rdi, [rel str_grid_dump_paint_seq]
    call grid_out_str
    mov  edi, [rel grid_dump_paint_seq]
    call grid_out_dec
    lea  rdi, [rel str_grid_dump_input_seq]
    call grid_out_str
    mov  edi, [rel grid_dump_input_seq]
    call grid_out_dec
    lea  rdi, [rel str_grid_dump_table]
    call grid_out_str
    mov  edi, GRID_INSTANCE_MAX
    call grid_out_dec
    lea  rdi, [rel str_grid_dump_table_kat]
    call grid_out_str
    movzx edi, byte [rel grid_instances_kat_flags]
    call grid_out_dec
    ret
.header_done:
    lea  eax, [r13d - 1]
    imul eax, [rel grid_dump_rows_per_page]
    mov  r14d, eax
    mov  ebx, eax
    add  ebx, [rel grid_dump_rows_per_page]
    cmp  ebx, [rel grid_rows]
    jbe  .rows
    mov  ebx, [rel grid_rows]
.rows:
    cmp  r14d, ebx
    jae  .next
    lea  rdi, [rel str_grid_row]
    call grid_out_str
    mov  edi, r14d
    call grid_out_dec
    lea  rdi, [rel str_grid_eq]
    call grid_out_str
    xor  ecx, ecx
.chars:
    cmp  ecx, [rel grid_cols]
    jae  .row_done
    mov  eax, r14d
    imul eax, GRID_MAX_COLS
    add  eax, ecx
    shl  eax, 1
    lea  rdx, [rel grid_visible_cells]
    movzx edi, byte [rdx + rax]
    call grid_out_char
    inc  ecx
    jmp  .chars
.row_done:
    cmp  byte [rel grid_mode], 1
    jne  .row_next
    lea  rdi, [rel str_grid_attr_row]
    call grid_out_str
    mov  edi, r14d
    call grid_out_dec
    lea  rdi, [rel str_grid_eq]
    call grid_out_str
    xor  ecx, ecx
.attrs:
    cmp  ecx, [rel grid_cols]
    jae  .row_next
    mov  eax, r14d
    imul eax, GRID_MAX_COLS
    add  eax, ecx
    shl  eax, 1
    lea  rdx, [rel grid_visible_cells]
    movzx edi, byte [rdx + rax + 1]
    and  edi, 0x7f
    call grid_out_hex_byte
    inc  ecx
    jmp  .attrs
.row_next:
    inc  r14d
    jmp  .rows
.next:
    lea  rdi, [rel str_grid_next]
    call grid_out_str
    xor  edi, edi
    mov  eax, [rel grid_dump_pages]
    cmp  r13d, eax
    jae  .next_emit
    lea  edi, [r13d + 1]
.next_emit:
    call grid_out_dec
    mov  byte [rel grid_out_ready], 1
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, 1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; L6 side of the command callback seam. EDI=owner window, ESI=page.
; Returns 0=page ready, 1=no console_grid for owner, 2=bad page.
console_grid_dump_for_window:
    push rbx
    push r12
    push r13
    mov  r12d, edi
    mov  r13d, esi
    xor  ebx, ebx
.scan:
    cmp  ebx, [rel wgt_count]
    jae  .not_found
    mov  edi, ebx
    call wgt_slot_ptr
    mov  edx, [rel grid_type_id]
    inc  edx
    cmp  [rax + WGI_TYPE], edx
    jne  .next
    cmp  [rax + WGI_WIN], r12d
    jne  .next
    mov  dword [rel grid_dump_handle], 0
    mov  [rel grid_dump_owner], ebx
    mov  dword [rel grid_dump_session], 0
    mov  dword [rel grid_dump_backend], 0
    mov  dword [rel grid_dump_seq], 0
    mov  dword [rel grid_dump_paint_seq], 0
    mov  dword [rel grid_dump_input_seq], 0
    mov  edi, [rax + WGI_RSVD]
    mov  [rel grid_dump_handle], edi
    call grid_instance_validate
    jc   .dump
    mov  ecx, [rax + GI_SESSION]
    mov  [rel grid_dump_session], ecx
    mov  ecx, [rax + GI_BACKEND]
    mov  [rel grid_dump_backend], ecx
    mov  ecx, [rax + GI_SEQ]
    mov  [rel grid_dump_seq], ecx
    mov  ecx, [rax + GI_PAINT_SEQ]
    mov  [rel grid_dump_paint_seq], ecx
    mov  ecx, [rax + GI_INPUT_SEQ]
    mov  [rel grid_dump_input_seq], ecx
    call grid_instance_load_ptr
.dump:
    mov  edi, ebx
    mov  esi, r13d
    call grid_dump_visible_page
    test eax, eax
    jz   .out
    mov  eax, 2
    jmp  .out
.next:
    inc  ebx
    jmp  .scan
.not_found:
    mov  eax, 1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; Task2158 hostile-interleave/stale-handle boot oracle. It exercises the same
; public handle operations used by windows, including a CSI split held across
; another instance's parse and an exact alternate-screen primary restore.
grid_instances_boot_kat:
    push rbx
    push r12
    push r13
    push r14
    mov  byte [rel grid_instances_kat_flags], 0
    xor  ebx, ebx
.open_four:
    call grid_instance_open
    jc   .fail
    lea  rdx, [rel grid_instance_handles]
    mov  [rdx + rbx*4], eax
    inc  ebx
    cmp  ebx, GRID_INSTANCE_MAX
    jb   .open_four
    call grid_instance_open
    jnc  .fail
    cmp  edx, GRID_INST_ERR_FULL
    jne  .fail
    mov  edi, 0x1ff                   ; invalid index with nonzero generation
    call grid_instance_validate
    jnc  .fail
    cmp  edx, GRID_INST_ERR_HANDLE
    jne  .fail
    or   byte [rel grid_instances_kat_flags], 0x01

    ; Instance 0 holds a split CSI while instance 1 consumes ordinary bytes.
    lea  rbx, [rel grid_instance_handles]
    mov  edi, [rbx]
    lea  rsi, [rel grid_inst_split_a]
    mov  edx, grid_inst_split_a.len
    call grid_instance_feed
    jc   .fail
    mov  edi, [rbx + 4]
    lea  rsi, [rel grid_inst_b]
    mov  edx, grid_inst_b.len
    call grid_instance_feed
    jc   .fail
    mov  edi, [rbx]
    lea  rsi, [rel grid_inst_split_b]
    mov  edx, grid_inst_split_b.len
    call grid_instance_feed
    jc   .fail
    mov  edi, [rbx]
    call grid_instance_validate
    jc   .fail
    call grid_instance_load_ptr
    cmp  byte [rel ansi_parser_state], ANSI_STATE_NORMAL
    jne  .fail
    cmp  byte [rel grid_visible_cells], 'A'
    jne  .fail
    mov  al, [rel grid_visible_cells + 1]
    and  al, 0x7f
    cmp  al, 1
    jne  .fail
    mov  edi, [rbx + 4]
    call grid_instance_validate
    jc   .fail
    call grid_instance_load_ptr
    cmp  byte [rel grid_visible_cells], 'B'
    jne  .fail
    or   byte [rel grid_instances_kat_flags], 0x02

    ; Primary B must return byte-exact after independent alternate-screen use.
    mov  edi, [rbx + 4]
    lea  rsi, [rel grid_inst_alt]
    mov  edx, grid_inst_alt.len
    call grid_instance_feed
    jc   .fail
    mov  edi, [rbx]
    lea  rsi, [rel grid_inst_zero]
    mov  edx, grid_inst_zero.len
    call grid_instance_feed
    jc   .fail
    mov  edi, [rbx + 4]
    lea  rsi, [rel grid_inst_alt_exit]
    mov  edx, grid_inst_alt_exit.len
    call grid_instance_feed
    jc   .fail
    mov  edi, [rbx + 4]
    call grid_instance_validate
    jc   .fail
    call grid_instance_load_ptr
    cmp  byte [rel ansi_alt_active], 0
    jne  .fail
    cmp  byte [rel grid_visible_cells], 'B'
    jne  .fail
    or   byte [rel grid_instances_kat_flags], 0x04

    ; A never-painted background slot still parses and advances its sequence.
    mov  edi, [rbx + 8]
    lea  rsi, [rel grid_inst_bg]
    mov  edx, grid_inst_bg.len
    call grid_instance_feed
    jc   .fail
    mov  edi, [rbx + 8]
    call grid_instance_validate
    jc   .fail
    cmp  dword [rax + GI_SEQ], 1
    jne  .fail
    cmp  dword [rax + GI_PAINT_SEQ], 0
    jne  .fail
    or   byte [rel grid_instances_kat_flags], 0x08

    ; Close/reopen must advance generation; stale input refuses and the new
    ; record remains byte-clean.
    mov  r12d, [rbx + 8]
    mov  edi, r12d
    call grid_instance_close
    jc   .fail
    mov  edi, r12d                    ; double-close is the same stale refusal
    call grid_instance_close
    jnc  .fail
    cmp  edx, GRID_INST_ERR_STALE
    jne  .fail
    call grid_instance_open
    jc   .fail
    mov  r13d, eax
    cmp  r13d, r12d
    je   .fail
    mov  edi, r12d
    lea  rsi, [rel grid_inst_stale]
    mov  edx, grid_inst_stale.len
    call grid_instance_feed
    jnc  .fail
    cmp  edx, GRID_INST_ERR_STALE
    jne  .fail
    mov  edi, r13d
    call grid_instance_validate
    jc   .fail
    cmp  dword [rax + GI_SEQ], 0
    jne  .fail
    mov  [rbx + 8], r13d
    or   byte [rel grid_instances_kat_flags], 0x10

    mov  rdx, [rel grid_instance_table_ptr]
    test rdx, rdx
    jz   .fail
    mov  rax, GI_CANARY_LO_VALUE
    cmp  [rdx - 8], rax                 ; table canary_lo, just below the heap table
    jne  .fail
    mov  rax, GI_CANARY_HI_VALUE
    cmp  [rdx + GI_SIZE * GRID_INSTANCE_MAX], rax ; table canary_hi, just above it
    jne  .fail
    xor  r12d, r12d
.slot_canary:
    mov  edi, r12d
    call grid_instance_slot_ptr
    test rax, rax
    jz   .fail
    mov  rdx, GI_CANARY_LO_VALUE
    cmp  [rax + GI_CANARY_LO], rdx
    jne  .fail
    mov  rdx, GI_CANARY_HI_VALUE
    cmp  [rax + GI_CANARY_HI], rdx
    jne  .fail
    inc  r12d
    cmp  r12d, GRID_INSTANCE_MAX
    jb   .slot_canary
    or   byte [rel grid_instances_kat_flags], 0x20

    ; Leave exactly two production instances. Slot 0 preserves Task2155's live
    ; fixture contract; slot 1 has a distinct nonce-bearing ANSI surface.
    mov  edi, [rbx + 8]
    call grid_instance_close
    jc   .fail
    mov  edi, [rbx + 12]
    call grid_instance_close
    jc   .fail
    mov  edi, [rbx]
    call grid_instance_validate
    jc   .fail
    mov  r14, rax
    call grid_instance_reset_work
    mov  byte [rel grid_resize_kat], 1
    mov  byte [rel ansi_grid_kat_flags], 0xff
    lea  rdi, [rel ansi_live_head]
    mov  esi, ansi_live_head.len
    call ansi_grid_feed
    lea  rdi, [rel grid_nonce_buf]
    mov  esi, grid_nonce_buf.len
    call ansi_grid_feed
    lea  rdi, [rel ansi_live_color]
    mov  esi, ansi_live_color.len
    call ansi_grid_feed
    mov  rax, r14
    call grid_instance_save_ptr
    mov  dword [r14 + GI_SEQ], 1
    mov  edi, [rbx + 4]
    call grid_instance_validate
    jc   .fail
    mov  r14, rax
    call grid_instance_reset_work
    mov  byte [rel grid_resize_kat], 1
    mov  byte [rel ansi_grid_kat_flags], 0xff
    lea  rdi, [rel grid_inst_live_b]
    mov  esi, grid_inst_live_b.len
    call ansi_grid_feed
    mov  rax, r14
    call grid_instance_save_ptr
    mov  dword [r14 + GI_SEQ], 1
    or   byte [rel grid_instances_kat_flags], 0x40
    mov  eax, 1
    jmp  .out
.fail:
    xor  eax, eax
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Bind the two surviving handles to two ordinary chrome windows. The first is
; the legacy Demo-C widget; the second uses a free slot from the one WM table.
grid_instances_bind_windows:
    push rbx
    push r12
    push r13
    push r14
    lea  rbx, [rel grid_instance_handles]
    mov  r12d, [rel grid_widget_id]
    mov  edi, r12d
    call wgt_slot_ptr
    mov  r13d, [rax + WGI_WIN]
    mov  edi, [rbx]
    mov  esi, r12d
    mov  edx, 1                       ; local PaOS text backend
    mov  ecx, r13d
    call grid_instance_bind_widget
    jc   .fail

    mov  eax, r13d
    lea  rcx, [rel wm_x]
    mov  esi, [rcx + rax*4]
    lea  rcx, [rel wm_w]
    add  esi, [rcx + rax*4]
    add  esi, 24
    lea  rcx, [rel wm_y]
    mov  edx, [rcx + rax*4]
    mov  ecx, esi
    add  ecx, 408
    cmp  ecx, [rel fb_width]
    jbe  .window_b_position_ready
    lea  rcx, [rel wm_x]
    mov  esi, [rcx + rax*4]
    lea  rcx, [rel wm_h]
    add  edx, [rcx + rax*4]
    add  edx, 24
.window_b_position_ready:
    lea  rdi, [rel str_grid_window_b_title]
    mov  ecx, 408
    mov  r8d, 280
    mov  r9d, WM_RESTORE_FRESH
    call wmx_open_window              ; one existing WM table + standard chrome
    cmp  eax, -1
    je   .fail
    mov  r14d, eax
    mov  edi, [rel grid_type_id]
    mov  esi, r14d
    call wgt_create
    cmp  eax, -1
    je   .fail
    mov  r12d, eax
    mov  edi, r12d
    call console_grid_fit_owner       ; same dock-fit policy as the legacy grid
    mov  edi, [rbx + 4]
    mov  esi, r12d
    mov  edx, 1
    mov  ecx, r14d
    call grid_instance_bind_widget
    jc   .fail
    mov  [rel grid_window_b_slot], r14d   ; B18: retired after the desktop start (grid_window_b_retire)
    mov  [rel grid_window_b_widget], r12d
    call wmx_draw_all
    or   byte [rel grid_instances_kat_flags], 0x80
    mov  eax, 1
    jmp  .out
.fail:
    xor  eax, eax
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Boot registration/KAT.  Called after the F1 three-window demo exists, so the
; proof grid is a real visible L1 child of Demo C rather than leaked pre-demo
; scaffolding. The marker proves the callback is in the one live registry;
; cadence_poll supplies the timing measurement after the interactive handoff.
console_grid_register:
    push rbx
    push r12
    push r13
    mov  byte [rel grid_fail_stage], 1
    lea  rdi, [rel str_wt_console_grid]
    lea  rsi, [rel console_grid_draw]
    lea  rdx, [rel wgt_rect_hittest]
    lea  rcx, [rel console_grid_set]
    lea  r8,  [rel console_grid_get]
    mov  r9, (64 << 32) | 240
    call wgt_type_register
    cmp  eax, -1
    je   .fail
    mov  [rel grid_type_id], eax
    mov  byte [rel grid_fail_stage], 2
    mov  edi, eax
    ; Form windows use the first live WM slots, not fixed semantic slot ids.
    ; Chat commonly owns slot 2, so the earlier literal attached this grid to
    ; chat's taller rect and made the scrollback KAT fail at stage 3. Resolve
    ; Demo C from the form loader's live ownership table every boot.
    mov  esi, [rel form_active_slot + 2*4]
    cmp  esi, WM_MAX
    jae  .fail
    call wgt_create
    cmp  eax, -1
    je   .fail
    mov  [rel grid_widget_id], eax
    mov  edi, eax
    call console_grid_fit_owner
    call grid_clear
    lea  rdi, [rel str_grid_seed]
    mov  esi, str_grid_seed.len
    call grid_append
    ; Per-boot nonce: host can correlate the rendered and dumped bytes without
    ; granting a mutation capability to this read-only rung.
    mov  eax, [rel boot_nonce]
    mov  ecx, 8
.hex:
    mov  edx, eax
    and  edx, 0x0f
    cmp  dl, 10
    jb   .hex_dec
    add  dl, 'A' - 10
    jmp  .hex_store
.hex_dec:
    add  dl, '0'
.hex_store:
    lea  rbx, [rel grid_nonce_buf + 6]
    mov  [rbx + rcx - 1], dl
    shr  eax, 4
    dec  ecx
    jnz  .hex
    lea  rdi, [rel str_grid_tail]
    mov  esi, str_grid_tail.len
    call grid_append
    ; Keep the per-boot correlation nonce in the rendered viewport even when
    ; the earlier seed/tail rows have already populated bounded scrollback.
    lea  rdi, [rel grid_nonce_buf]
    mov  esi, grid_nonce_buf.len
    call grid_append
    ; KAT: wrap made history, no wrapped row starts with a boundary space, and
    ; the materialized viewport contains the cursor attribute.
    mov  byte [rel grid_fail_stage], 3
    mov  eax, [rel grid_rows]
    inc  eax
    cmp  [rel grid_line_count], eax
    jb   .fail
    xor  ebx, ebx
    mov  byte [rel grid_fail_stage], 4
.line_kat:
    cmp  ebx, [rel grid_line_count]
    jae  .cursor_kat
    lea  rax, [rel grid_line_lens]
    cmp  word [rax + rbx*2], 0
    je   .line_next
    lea  rax, [rel grid_line_starts]
    mov  edi, [rax + rbx*4]
    call grid_raw_get
    cmp  al, ' '
    je   .fail
.line_next:
    inc  ebx
    jmp  .line_kat
.cursor_kat:
    mov  byte [rel grid_fail_stage], 5
    xor  ebx, ebx
.cursor_scan:
    cmp  ebx, GRID_MAX_COLS * GRID_MAX_ROWS
    jae  .fail
    lea  rdx, [rel grid_visible_cells]
    cmp  byte [rdx + rbx*2 + 1], 1
    je   .resize_kat
    inc  ebx
    jmp  .cursor_scan
.resize_kat:
    mov  byte [rel grid_fail_stage], 6
    ; Exercise a real rect-driven transition, not just the steady-state
    ; geometry.  Narrowing must change columns and increase reflowed lines;
    ; restoring must recover the original geometry before pixels are exposed.
    mov  edi, [rel grid_widget_id]
    call wgt_slot_ptr
    mov  rbx, rax
    mov  r12d, [rbx + WGI_W]
    mov  r13d, [rel grid_cols]
    mov  eax, [rel grid_line_count]
    push rax
    mov  dword [rbx + WGI_W], 80
    mov  edi, [rel grid_widget_id]
    call grid_resize
    cmp  [rel grid_cols], r13d
    je   .resize_fail_pop
    pop  rax
    cmp  [rel grid_line_count], eax
    jbe  .fail
    mov  [rbx + WGI_W], r12d
    mov  edi, [rel grid_widget_id]
    call grid_resize
    cmp  [rel grid_cols], r13d
    jne  .fail
    mov  byte [rel grid_resize_kat], 1
    jmp  .scroll_kat
.resize_fail_pop:
    pop  rax
    jmp  .fail
.scroll_kat:
    mov  byte [rel grid_fail_stage], 7
    mov  edi, 1
    call grid_scroll
    cmp  eax, 1
    jb   .fail
    mov  edi, -1
    call grid_scroll
    test eax, eax
    jnz  .fail
    lea  rdi, [rel str_grid_cadence_id]
    mov  byte [rel grid_fail_stage], 8
    xor  esi, esi
    mov  edx, 10
    mov  rcx, [rel tsc_khz]
    imul rcx, GRID_CADENCE_MS
    test rcx, rcx
    jnz  .period_ok
    mov  rcx, 200000000
.period_ok:
    lea  r8, [rel console_grid_cadence_draw]
    call cadence_register_named
    cmp  eax, -1
    je   .fail
    mov  [rel grid_cadence_slot], eax
    ; Boot-time glyph painting is not a cadence timing benchmark. QEMU can
    ; spend longer than one 100 ms period drawing the first full surface,
    ; which previously tripped CAD_VITAL and suppressed both contract markers
    ; even though registration and the grid KAT were correct. Render the dirty
    ; surface once, then let the resident cadence_poll path earn measured_hz.
    call console_grid_cadence_draw
    mov  eax, [rel grid_cadence_slot]
    imul eax, CAD_ENT_SZ
    lea  rbx, [rel cad_table]
    lea  rdx, [rel console_grid_cadence_draw]
    cmp  [rbx + rax + CAD_CTRL], rdx
    jne  .fail
    cmp  qword [rbx + rax + CAD_DECL_HZ], 10
    jne  .fail
    cmp  qword [rbx + rax + CAD_VITAL], 0
    jne  .fail
    mov  byte [rel grid_fail_stage], 9
    mov  byte [rel grid_kat_ok], 1
    lea  rdi, [rel console_grid_dump_for_window]
    lea  rsi, [rel grid_kat_ok]
    call cons_bind_grid
    lea  rdi, [rel str_grid_marker]
    call serial_string
    call ansi_grid_boot_kat
    cmp  byte [rel ansi_grid_kat_flags], 0xff
    jne  .instance_fail
    mov  byte [rel grid_fail_stage], 10
    call grid_instances_boot_kat
    test eax, eax
    jz   .instance_fail
    call grid_instances_bind_windows
    test eax, eax
    jz   .instance_fail
    cmp  byte [rel grid_instances_kat_flags], 0xff
    jne  .instance_fail
    mov  byte [rel grid_instances_kat_ok], 1
    lea  rdi, [rel str_grid_instances_marker]
    call serial_string
    pop  r13
    pop  r12
    pop  rbx
    ret
.instance_fail:
    lea  rdi, [rel str_grid_instances_fail]
    call serial_string
    movzx edi, byte [rel grid_instances_kat_flags]
    call serial_hex64
    call serial_newline
    pop  r13
    pop  r12
    pop  rbx
    ret
.fail:
    lea  rdi, [rel str_grid_fail]
    call serial_string
    movzx edi, byte [rel grid_fail_stage]
    call serial_hex64
    call serial_newline
    pop  r13
    pop  r12
    pop  rbx
    ret

align 8
grid_widget_id:      dd -1
grid_type_id:        dd -1
grid_cols:           dd 1
grid_rows:           dd 1
grid_cursor_col:     dd 0
grid_cursor_row:     dd 0
grid_raw_head:       dd 0
grid_raw_len:        dd 0
grid_line_count:     dd 0
grid_view_offset:    dd 0
grid_cadence_slot:   dd -1
grid_dump_pages:     dd 1
grid_dump_rows_per_page: dd GRID_ROWS_PER_PAGE
grid_owner_generation: dd 0
grid_claim_handle:   dd 0               ; compatibility owner, if instanced
grid_dump_owner:     dd 0
grid_dump_handle:    dd 0
grid_dump_session:   dd 0
grid_dump_backend:   dd 0
grid_dump_seq:       dd 0
grid_dump_paint_seq: dd 0
grid_dump_input_seq: dd 0
grid_mode:           db 0                 ; 0=Task2150 append/reflow, 1=ANSI terminal
grid_dock_owner:     db 1                 ; rung-0 Demo C docks; form consoles own their rect
grid_dirty:          db 0
grid_kat_ok:         db 0
grid_resize_kat:     db 0
grid_instances_kat_flags: db 0
grid_instances_kat_ok: db 0
grid_window_b_slot:   dd -1              ; B18: PaOS-ANSI-B, the second-instance boot-proof window
grid_window_b_widget: dd -1
; Boot-only failure diagnostic: 1=type, 2=create, 3=history, 4=wrap,
; 5=cursor, 6=resize, 7=scroll, 8=cadence, 9=bind, 10=instances.
grid_fail_stage:     db 0
align 8
grid_raw_ring:       times GRID_RAW_BYTES db 0
grid_line_starts:    times GRID_LINE_MAX dd 0
grid_line_lens:      times GRID_LINE_MAX dw 0
grid_cells_canary_lo: dq 0x2155A11CE11CA55E
grid_visible_cells:  times (GRID_MAX_COLS * GRID_MAX_ROWS * GRID_CELL_BYTES) db 0
grid_cells_canary_hi: dq 0xE55AC11EC11A5512

align 8
; -> heap [canary_lo][table][canary_hi] (grid_instance_table_base); was 54,016 image bytes
grid_instance_table_ptr: dq 0
grid_instance_table_refusal_logged: db 0              ; heap refusal already logged (grid_instance_table_base)
str_grid_inst_alloc_fail: db "[grid] instance table allocation refused; console grid instances disabled", 13, 10, 0

; ANSI/VGA ordering. Bright applies only to the foreground bold bit; inverse
; is resolved into the stored semantic attribute by ansi_interp.
grid_ansi_palette:
    dd 0x00000000, 0x00CC5555, 0x0055CC55, 0x00CCCC55
    dd 0x005555CC, 0x00CC55CC, 0x0055CCCC, 0x00CCCCCC
grid_ansi_bright_palette:
    dd 0x00555555, 0x00FF7777, 0x0077FF77, 0x00FFFF77
    dd 0x007777FF, 0x00FF77FF, 0x0077FFFF, 0x00FFFFFF

str_wt_console_grid: db "console_grid",0
str_grid_content_handle: db " grid_handle=",0
str_grid_content_cols: db " cols=",0
str_grid_content_rows: db " rows=",0
str_grid_cadence_id: db "console_grid",0
str_grid_seed: db "PaOS console grid ready",10,"word boundary wrap uses the shared font engine",10
.len equ $ - str_grid_seed
grid_nonce_buf: db "nonce="
                times 8 db '0'
                db 10
.len equ $ - grid_nonce_buf
str_grid_tail: db "scrollback history retained",10
               db "word wrapping remains deterministic",10
               db "bounded ring drops oldest bytes",10
               db "resize reflows from widget rect",10
               db "cursor cadence live"
.len equ $ - str_grid_tail
str_grid_dump_head:   db " CONSGRID v1 cols=",0
str_grid_dump_rows:   db " rows=",0
str_grid_dump_scroll: db " scrollback=",0
str_grid_dump_cursor: db " cursor=",0
str_grid_dump_page:   db " page=",0
str_grid_dump_resize: db " resize_kat=",0
str_grid_dump_plain:  db " mode=plain",0
str_grid_dump_owner:  db " owner=",0
str_grid_dump_owner_generation: db " owner_generation=",0
str_grid_dump_ansi:   db " mode=ansi ansi_kat=",0
str_grid_dump_parser: db " parser=",0
str_grid_dump_alt:    db " alt=",0
str_grid_dump_cursor_vis: db " cursor_visible=",0
str_grid_dump_region: db " scroll_region=",0
str_grid_dump_instance: db " instance=",0
str_grid_dump_instance_generation: db " generation=",0
str_grid_dump_session: db " session=",0
str_grid_dump_backend: db " backend=",0
str_grid_dump_seq: db " seq=",0
str_grid_dump_paint_seq: db " paint_seq=",0
str_grid_dump_input_seq: db " input_seq=",0
str_grid_dump_table: db " table=",0
str_grid_dump_table_kat: db " table_kat=",0
str_grid_slash:       db "/",0
str_grid_comma:       db ",",0
str_grid_row:         db 10,"R",0
str_grid_attr_row:    db 10,"A",0
str_grid_eq:          db "=",0
str_grid_next:        db 10,"next=",0
str_grid_marker: db "[PAOS64] verb-console rung 0: console_grid widget registered (grid+scrollback+cursor selftest, cadence entry live) [gui.widget.console_grid]",13,10,0
str_grid_fail:   db "[PAOS64] verb-console rung 0: console_grid widget FAILED stage=",0
str_grid_instances_marker: db "[PAOS64] text sessions: bounded independent ANSI instance table KAT PASS [gui.ansi.instances]",13,10,0
str_grid_instances_fail: db "[PAOS64] text sessions: bounded independent ANSI instance table KAT FAIL flags=",0
str_grid_field_feed: db "feed",0
str_grid_field_input: db "input",0
str_grid_field_close: db "close",0
str_grid_field_minimize: db "minimize",0
str_grid_field_restore: db "restore",0
str_grid_field_spawn: db "spawn",0         ; B18 ruling (2): an on-demand second instance window
str_grid_window_b_title: db "PaOS-ANSI-B",0

align 4
grid_instance_handles: times GRID_INSTANCE_MAX dd 0
grid_inst_split_a: db 0x1b,'['
.len equ $ - grid_inst_split_a
grid_inst_split_b: db '3','1','m','A'
.len equ $ - grid_inst_split_b
grid_inst_b: db 'B'
.len equ $ - grid_inst_b
grid_inst_alt: db 0x1b,'[','?','1','0','4','9','h','X'
.len equ $ - grid_inst_alt
grid_inst_alt_exit: db 0x1b,'[','?','1','0','4','9','l'
.len equ $ - grid_inst_alt_exit
grid_inst_zero: db '0'
.len equ $ - grid_inst_zero
grid_inst_bg: db 'B','G'
.len equ $ - grid_inst_bg
grid_inst_stale: db 'S','T','A','L','E'
.len equ $ - grid_inst_stale
grid_inst_live_b:
    db 'ANSI terminal instance B',13,10,'nonce=B2158B02',13,10
    db 0x1b,'[','3','2','m','GREEN',0x1b,'[','0','m',' '
    db 0x1b,'[','4','1',';','3','7','m','RED-BG',0x1b,'[','0','m'
.len equ $ - grid_inst_live_b

; Append two uppercase hex digits to the command layer's existing bounded
; output buffer. EDI is a byte; callers retain their row/column registers.
grid_out_hex_byte:
    push rbx
    mov  ebx, edi
    shr  edi, 4
    and  edi, 0x0f
    call .nibble
    mov  edi, ebx
    and  edi, 0x0f
    call .nibble
    pop  rbx
    ret
.nibble:
    cmp  edi, 10
    jb   .digit
    add  edi, 'A' - 10
    jmp  grid_out_char
.digit:
    add  edi, '0'
    jmp  grid_out_char
