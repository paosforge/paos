;; MODULE gui/ime_view
;; LAYER 6
;; EXPORTS ime_view_build, ime_view_get, ime_view_preedit, ime_view_mode
;; IMPORTS gui/ime_core, core/unicode_edit, core/lib/mem
;; OWNER rc-input-claude
;; CONTEXT: bsp_only
;
; RCQ-38 I3a, the candidate window and inline pre-edit as a layout MODEL (PLAN_I3_CANDIDATE_VIEW.md, root 17:39:33).
; Host-only and UNWIRED: not in paos.asm, no caller. I3b paints it (popup through the flyout seam, glyphs through
; I4, the field pre-edit through L3) once those exist.
;
; It only READS the IME (ime_cand_info / ime_cand_get / ime_conv_info / ime_preedit): it never calls ime_key or
; ime_cancel, and the window takes no input in RC (no pointer pick, not focusable). Widths, UTF-8 and grapheme
; boundaries come from relops' accepted core/unicode_edit; a row's width is the sum of ue_cell_width over its
; scalars. I1 does not check UTF-8 inside a shard, so a surface is measured over its valid prefix only and an
; invalid byte cuts the row there, with the cut mark: bounded and visible, never garbage.
;
; The window: one row per candidate on the selection's page of 9, "k." + a gap + the surface, the widest row
; deciding the width (at most IMV_COLS cells and the screen); a row wider than that is cut at a grapheme boundary
; and ends in '>'. When there are more than 9 candidates a last line carries '<' and '>' (paging wraps). Placement:
; below the caret line, else above it, else bottom-aligned on the screen; x and y clamped onto the screen. A screen too
; small for the window gives NO_ROOM and an empty model, never a partial rectangle.

IMV_PAGE            equ 9               ; = ime_core's IME_PAGE (census-pinned)
IMV_COLS            equ 40              ; the widest window content, in cells
IMV_LABEL           equ 3               ; "k." and a gap
IMV_PADY            equ 2               ; pixels above and below the lines
IMV_PADX            equ 2               ; cells: one either side of the content
IMV_SURF_CAP        equ 256             ; = ime_dict's PD_SURF_MAX (census-pinned)
IMV_S_CONVERTING    equ 2               ; = ime_core's IME_S_CONVERTING (census-pinned)
IMV_F_NO_CANDIDATES equ 1               ; = ime_core's flags (census-pinned)
IMV_F_UNAVAILABLE   equ 2

IMV_SHOWN           equ 0               ; ime_view_build statuses
IMV_EMPTY           equ 1               ; not converting: no window
IMV_NO_ROOM         equ 2
IMV_NO_CANDIDATES   equ 3
IMV_UNAVAILABLE     equ 4
IMV_ROW_CUT         equ 1               ; row flags

IMV_STATUS          equ 0               ; the model (ime_view_get copies IMV_SIZE bytes), u32 fields
IMV_X               equ 4
IMV_Y               equ 8
IMV_W               equ 12
IMV_H               equ 16
IMV_NCOLS           equ 20              ; content cells per line
IMV_ROWS            equ 24              ; candidate rows on the page
IMV_FIRST           equ 28              ; the candidate index of row 0
IMV_SELROW          equ 32
IMV_MARKS           equ 36              ; 1: the '<' '>' line follows the rows
IMV_COUNT           equ 40              ; all candidates
IMV_ROW0            equ 48              ; per row: u32 surface bytes shown, u16 cells (with the mark), u16 flags
IMV_ROW_SIZE        equ 8
IMV_SIZE            equ IMV_ROW0 + IMV_PAGE * IMV_ROW_SIZE

IMV_RUN_SIZE        equ 16              ; ime_view_preedit runs: u32 byte offset, bytes, cells, style
IMV_UNDERLINE       equ 1
IMV_THICK           equ 2

; imv_cells(RDI bytes, ESI end, EDX start) -> EAX the cells of the scalars in [start, end), EDX where the walk
; stopped: end, or the first byte that does not decode.
imv_cells:
    push rbx
    push r12
    push r13
    push r14
    sub  rsp, 8                         ; [rsp] = ue_utf8_decode's {scalar, bytes}
    mov  r12, rdi
    mov  r13d, esi
    mov  r14d, edx
    xor  ebx, ebx
.loop:
    cmp  r14d, r13d
    jae  .out
    mov  rdi, r12
    mov  esi, r13d
    mov  edx, r14d
    mov  rcx, rsp
    call ue_utf8_decode
    cmp  eax, 1
    jne  .out
    mov  edi, [rsp]
    call ue_cell_width
    test eax, eax
    js   .out
    add  ebx, eax
    add  r14d, [rsp + 4]
    jmp  .loop
.out:
    mov  eax, ebx
    mov  edx, r14d
    add  rsp, 8
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; imv_measure(EDI cap cells >= 2, ESI surface bytes in imv_surf) -> EAX bytes shown, EDX cells (with the mark),
; ECX flags. Whole when it is valid UTF-8 and fits; else the graphemes of its valid prefix that fit in cap - 1,
; then the mark.
imv_measure:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8
    mov  r12d, edi
    mov  r13d, esi
    lea  rdi, [rel imv_surf]
    xor  edx, edx
    call imv_cells
    mov  r14d, edx                      ; the valid prefix
    cmp  r14d, r13d
    jne  .cut
    cmp  eax, r12d
    ja   .cut
    mov  edx, eax
    mov  eax, r13d
    xor  ecx, ecx
    jmp  .out
.cut:
    xor  r15d, r15d                     ; the boundary reached
    xor  ebp, ebp                       ; its cells
.grapheme:
    cmp  r15d, r14d
    jae  .cut_done
    lea  rdi, [rel imv_surf]
    mov  esi, r14d
    mov  edx, r15d
    call ue_grapheme_next               ; -1 is returned as EAX (zero-extended): bound it, do not sign-test RAX
    cmp  eax, r15d
    jbe  .cut_done                      ; no progress
    cmp  eax, r14d
    ja   .cut_done                      ; -1, or past the valid prefix
    mov  ebx, eax
    lea  rdi, [rel imv_surf]
    mov  esi, ebx
    mov  edx, r15d
    call imv_cells
    add  eax, ebp
    lea  ecx, [r12 - 1]
    cmp  eax, ecx
    ja   .cut_done
    mov  ebp, eax
    mov  r15d, ebx
    jmp  .grapheme
.cut_done:
    mov  eax, r15d
    lea  edx, [rbp + 1]
    mov  ecx, IMV_ROW_CUT
.out:
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; ime_view_build(EDI caret x, ESI caret y, EDX caret height, ECX screen width, R8D screen height,
; R9D cell width | cell height << 16) -> EAX status. Rebuilds the model from the IME's current list; anything but
; SHOWN leaves the model empty apart from its status. Positions are signed pixels.
ime_view_build:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 40
    mov  [rsp], edi                     ; caret x
    mov  [rsp + 4], esi                 ; caret y
    mov  [rsp + 8], edx                 ; caret height
    mov  [rsp + 12], ecx                ; screen width
    mov  [rsp + 16], r8d                ; screen height
    movzx eax, r9w
    mov  [rsp + 20], eax                ; cell width
    mov  eax, r9d
    shr  eax, 16
    mov  [rsp + 24], eax                ; cell height
    call imv_wipe
    call ime_conv_info
    mov  eax, IMV_UNAVAILABLE
    test ch, IMV_F_UNAVAILABLE
    jnz  .status
    mov  eax, IMV_NO_CANDIDATES
    test ch, IMV_F_NO_CANDIDATES
    jnz  .status
    mov  eax, IMV_EMPTY
    cmp  cl, IMV_S_CONVERTING
    jne  .status
    call ime_cand_info
    mov  r12d, eax                      ; count
    mov  r13d, edx                      ; selection
    mov  eax, IMV_EMPTY
    test r12d, r12d
    jz   .status
    cmp  r13d, r12d
    jae  .status
    ; ---- the room: cells across, lines down
    mov  eax, IMV_NO_ROOM
    mov  ecx, [rsp + 20]
    test ecx, ecx
    jz   .status
    cmp  dword [rsp + 24], 0
    je   .status
    mov  ebx, [rsp + 12]
    test ebx, ebx
    jle  .status
    cmp  dword [rsp + 16], 0
    jle  .status
    mov  eax, ebx
    xor  edx, edx
    div  ecx
    sub  eax, IMV_PADX
    mov  ecx, IMV_COLS
    cmp  eax, ecx
    cmovg eax, ecx
    sub  eax, IMV_LABEL                 ; the surface cap
    cmp  eax, 2
    mov  ecx, eax
    mov  eax, IMV_NO_ROOM
    jl   .status
    mov  [rsp + 28], ecx
    mov  eax, r13d                      ; the page
    xor  edx, edx
    mov  ecx, IMV_PAGE
    div  ecx
    imul eax, eax, IMV_PAGE
    mov  r14d, eax                      ; first
    mov  r15d, r12d
    sub  r15d, eax
    cmp  r15d, IMV_PAGE
    jbe  .rows
    mov  r15d, IMV_PAGE
.rows:
    xor  ebp, ebp                       ; marks
    cmp  r12d, IMV_PAGE
    seta bpl
    lea  eax, [r15 + rbp]
    imul eax, [rsp + 24]
    add  eax, 2 * IMV_PADY
    mov  [rsp + 32], eax                ; h
    mov  ecx, eax
    mov  eax, IMV_NO_ROOM
    cmp  ecx, [rsp + 16]
    jg   .status
    ; ---- the rows
    mov  dword [rsp + 36], 0            ; the widest
    xor  ebx, ebx
.row:
    cmp  ebx, r15d
    jae  .rows_done
    lea  edi, [r14 + rbx]
    lea  rsi, [rel imv_surf]
    call ime_cand_get
    test eax, eax
    jnz  .unavailable
    cmp  edx, IMV_SURF_CAP
    ja   .unavailable
    mov  esi, edx
    mov  edi, [rsp + 28]
    call imv_measure
    lea  r8, [rel imv_model]
    mov  [r8 + IMV_ROW0 + rbx*8], eax
    mov  [r8 + IMV_ROW0 + rbx*8 + 4], dx
    mov  [r8 + IMV_ROW0 + rbx*8 + 6], cx
    cmp  edx, [rsp + 36]
    jbe  .row_next
    mov  [rsp + 36], edx
.row_next:
    inc  ebx
    jmp  .row
.unavailable:
    call imv_wipe
    mov  eax, IMV_UNAVAILABLE
    jmp  .status
.rows_done:
    lea  r8, [rel imv_model]
    mov  eax, [rsp + 36]
    add  eax, IMV_LABEL
    mov  [r8 + IMV_NCOLS], eax
    add  eax, IMV_PADX
    imul eax, [rsp + 20]                ; w (<= the screen: the cap came from it)
    mov  [r8 + IMV_W], eax
    mov  ecx, [rsp + 12]
    sub  ecx, eax                       ; the rightmost x
    mov  eax, [rsp]
    cmp  eax, ecx
    cmovg eax, ecx
    xor  ecx, ecx
    test eax, eax
    cmovs eax, ecx
    mov  [r8 + IMV_X], eax
    mov  edx, [rsp + 32]                ; h
    mov  [r8 + IMV_H], edx
    mov  eax, [rsp + 4]
    add  eax, [rsp + 8]                 ; below the caret line
    lea  ecx, [rax + rdx]
    cmp  ecx, [rsp + 16]
    jle  .placed
    mov  eax, [rsp + 4]
    sub  eax, edx                       ; above it
    jns  .placed
    mov  eax, [rsp + 16]
    sub  eax, edx                       ; bottom-aligned (h <= the screen)
.placed:
    mov  ecx, [rsp + 16]
    sub  ecx, edx                       ; the lowest y: a caret off the screen never moves the window off it
    cmp  eax, ecx
    cmovg eax, ecx
    test eax, eax
    jns  .y_ok
    xor  eax, eax
.y_ok:
    mov  [r8 + IMV_Y], eax
    mov  [r8 + IMV_ROWS], r15d
    mov  [r8 + IMV_FIRST], r14d
    mov  eax, r13d
    sub  eax, r14d
    mov  [r8 + IMV_SELROW], eax
    mov  [r8 + IMV_MARKS], ebp
    mov  [r8 + IMV_COUNT], r12d
    xor  eax, eax                       ; SHOWN
.status:
    lea  r8, [rel imv_model]
    mov  [r8 + IMV_STATUS], eax
    add  rsp, 40
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

imv_wipe:
    sub  rsp, 8
    lea  rdi, [rel imv_model]
    xor  esi, esi
    mov  edx, IMV_SIZE
    call memset
    add  rsp, 8
    ret

; ime_view_get(RDI out IMV_SIZE B) -> EAX status: a copy of the model.
ime_view_get:
    sub  rsp, 8
    lea  rsi, [rel imv_model]
    mov  edx, IMV_SIZE
    call memcpy
    mov  eax, [rel imv_model + IMV_STATUS]
    add  rsp, 8
    ret

; ime_view_preedit(RDI text out, ESI cap, RDX runs out 2 x IMV_RUN_SIZE) -> EAX the pre-edit bytes (-1 when cap is
; short: nothing written), ECX runs, EDX the caret in cells (at the end). CONVERTING: the converted span THICK,
; the rest (zh) UNDERLINE; COMPOSING: all of it UNDERLINE; IDLE: no runs.
ime_view_preedit:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 8
    mov  r12, rdi
    mov  r13d, esi
    mov  r14, rdx
    call ime_conv_info
    mov  ebp, eax                       ; the converted span
    mov  r15d, ecx
    mov  rdi, r12
    mov  esi, r13d
    call ime_preedit
    cmp  eax, -1
    je   .short
    mov  ebx, eax
    test ebx, ebx
    jz   .none
    cmp  ebp, ebx
    cmova ebp, ebx
    cmp  r15b, IMV_S_CONVERTING
    jne  .composing
    test ebp, ebp
    jz   .composing
    mov  rdi, r12
    mov  esi, ebp
    xor  edx, edx
    call imv_cells
    mov  dword [r14], 0
    mov  [r14 + 4], ebp
    mov  [r14 + 8], eax
    mov  dword [r14 + 12], IMV_THICK
    mov  r13d, eax
    cmp  ebp, ebx
    jae  .one
    mov  rdi, r12
    mov  esi, ebx
    mov  edx, ebp
    call imv_cells
    mov  [r14 + IMV_RUN_SIZE], ebp
    mov  ecx, ebx
    sub  ecx, ebp
    mov  [r14 + IMV_RUN_SIZE + 4], ecx
    mov  [r14 + IMV_RUN_SIZE + 8], eax
    mov  dword [r14 + IMV_RUN_SIZE + 12], IMV_UNDERLINE
    add  r13d, eax
    mov  ecx, 2
    jmp  .done
.composing:
    mov  rdi, r12
    mov  esi, ebx
    xor  edx, edx
    call imv_cells
    mov  dword [r14], 0
    mov  [r14 + 4], ebx
    mov  [r14 + 8], eax
    mov  dword [r14 + 12], IMV_UNDERLINE
    mov  r13d, eax
.one:
    mov  ecx, 1
.done:
    mov  eax, ebx
    mov  edx, r13d
    jmp  .out
.short:
    mov  eax, -1
.none:
    xor  ecx, ecx
    xor  edx, edx
.out:
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; ime_view_mode() -> EAX the taskbar mode indicator scalar: 'A' (off), U+3042 (ja), U+4E2D (zh-Hans).
ime_view_mode:
    sub  rsp, 8
    call ime_conv_info
    shr  ecx, 16
    mov  eax, 'A'
    mov  edx, 0x3042
    cmp  ecx, 1
    cmove eax, edx
    mov  edx, 0x4E2D
    cmp  ecx, 2
    cmove eax, edx
    add  rsp, 8
    ret

%macro WDATA_gui_ime_view 0
alignb 8
imv_model:           resb IMV_SIZE       ; the last ime_view_build's window
imv_surf:            resb IMV_SURF_CAP   ; one candidate's surface while it is measured
%endmacro
WDATA_BSS_DEFER WDATA_gui_ime_view
