;; MODULE gui/widget_image
;; LAYER 6
;; EXPORTS widget_image_refused_state, widget_image_bound_state, widget_image_register, widget_image_bind, widget_image_rebind_window, widget_image_state_ptr, image_type_id, wallpaper_paint_rect, wallpaper_perf_stage, wallpaper_tree, widget_image_contain_size
;; IMPORTS gui/compose_job, gui/compose_idle, gui/app_launcher, gui/lock_screen, gui/widget, gui/window, gui/window_mgmt, gui/wintree, gui/img/img_core, gui/img/img_cache, gui/img/img_cover, gui/img/img_source, boot/serial, core/time, svc/command, svc/command_auth
;; CAPS
;; OWNER saga:gui_image_pipeline

WIMG_FIT_NONE   equ 0
WIMG_FIT_TILE   equ 5                 ; repeat natural raster from image origin
WIB_APP_SZ      equ 40                ; bound app provenance: owner8 + sha256 32 (A4)
WIMG_FIT_CENTER equ 1
WIMG_FIT_SCALE  equ 2
WIMG_FIT_CONTAIN equ 4                ; aspect-preserving bounded fit, no upscale

WIMG_FIT_COVER equ 3                  ; natural cache + center-cover/scrim at draw

%include "gui/img/img_cover.asm"

WIMG_LOAD_MISSING equ 0
WIMG_LOAD_OK      equ 1
WIMG_LOAD_REFUSED equ 0x100            ; low byte is IMG_E_*

WIS_SRC    equ 0
WIS_FIT    equ 8
WIS_LOAD   equ 12
WIS_NW     equ 16
WIS_NH     equ 20
WIS_OUTW   equ 24
WIS_OUTH   equ 28
WIS_REBIND equ 32
WIS_SZ     equ 40
; Task2122: desktop image state shares this layout; bind before publishing it.

widget_image_state_ptr:
    imul rax, rdi, WIS_SZ
    lea  rdx, [rel widget_image_state]
    add  rax, rdx
    ret

; The vtable remains additive; image-only state is indexed by the stable global
; widget id so the 120-byte base prefix does not move again.
widget_image_register:
    call img_cache_init
    lea  rdi, [rel str_wt_image]
    lea  rsi, [rel widget_image_draw]
    lea  rdx, [rel wgt_rect_hittest]
    lea  rcx, [rel widget_image_set]
    lea  r8,  [rel widget_image_get]
    mov  r9, (64 << 32) | 64
    call wgt_type_register
    mov  [rel image_type_id], eax
    cmp  eax, -1
    je   .fail
    lea  rdi, [rel str_widget_image_marker]
    call serial_string
    call wallpaper_declare
    ret
.fail:
    lea  rdi, [rel str_widget_image_fail]
    call serial_string
    ret

widget_image_set:
    mov  eax, 1                         ; src/fit are declarative bind-time state
    ret

widget_image_get:
    xor  eax, eax
    ret

; EDI=widget id, RSI=asset row, EDX=fit. Decode happens here, in FORMLOAD's
; normal context. A present-but-bad asset records refusal and still returns to
; the loader; the form/window itself never fails.
widget_image_bind:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r12d, edi
    mov  r13, rsi
    mov  r14d, edx
    ; Passive provenance only. Invalidate before any original bind operation;
    ; retain the entry birth so callbacks cannot certify a recycled slot.
    mov  edi, r12d
    call wgt_birth_lifetime
    push rax
    imul rax, r12, 48
    lea  rdx, [rel widget_image_bound]
    mov  qword [rdx + rax], 0
    mov  edi, r12d
    call widget_image_state_ptr
    mov  rbp, rax
    mov  [rbp + WIS_SRC], r13
    mov  [rbp + WIS_FIT], r14d
    mov  dword [rbp + WIS_LOAD], WIMG_LOAD_MISSING
    mov  byte [rbp + WIS_REBIND], 0
    mov  rdi, [r13 + IMG_ASSET_PTR]
    mov  rsi, [r13 + IMG_ASSET_LEN]
    call img_probe
    mov  [rel widget_image_last_status], eax
    mov  [rbp + WIS_NW], ecx
    mov  [rbp + WIS_NH], edx
    test eax, eax
    jnz  .refused
    mov  r15d, ecx
    mov  [rel widget_image_natural_h], edx
    mov  edi, r12d
    call wgt_slot_ptr
    mov  esi, r15d
    mov  edx, [rel widget_image_natural_h]
    cmp  r14d, WIMG_FIT_COVER
    jne  .other_fit
    ; Keep this key <=8 MiB, leaving room for a <=16 MiB pinned desktop
    ; natural raster in the existing 24 MiB arena. Downsample only at bind.
.cover_size:
    mov  eax, esi
    mov  ecx, edx
    imul rax, rcx
    cmp  rax, 2097152
    jbe  .dims_ready
    inc  esi
    shr  esi, 1
    inc  edx
    shr  edx, 1
    jmp  .cover_size
.other_fit:
    cmp  r14d, WIMG_FIT_CONTAIN
    jne  .scale_fit
    mov  ecx, esi
    mov  r8d, [rax + WGI_H]
    mov  esi, [rax + WGI_W]
    call widget_image_contain_size
    jmp  .dims_ready
.scale_fit:
    cmp  r14d, WIMG_FIT_SCALE
    jne  .dims_ready
    mov  esi, [rax + WGI_W]
    mov  edx, [rax + WGI_H]
.dims_ready:
    mov  [rbp + WIS_OUTW], esi
    mov  [rbp + WIS_OUTH], edx
    mov  rdi, r13
    call img_cache_bind
    mov  [rel widget_image_last_status], eax
    test eax, eax
    jnz  .refused
    mov  dword [rbp + WIS_LOAD], WIMG_LOAD_OK
    jmp  .paint
.refused:
    mov  eax, [rel widget_image_last_status]
    or   eax, WIMG_LOAD_REFUSED
    mov  [rbp + WIS_LOAD], eax
.paint:
    mov  edi, r12d
    call widget_image_draw
    mov  edi, r12d
    mov  rsi, [rsp]
    call widget_image_bound_record
    add  rsp, 8
    mov  eax, [rel widget_image_last_status]
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; EDI=current id, RSI=original bind-entry birth. This private snapshot is
; bookkeeping for completed normal binds, never a new getter/decode or grant.
; Immutable embedded catalog rows qualify, and (widgets-01 A4, SEC A7) a
; live app bundle row, recorded with its owning handle and image sha256 (never
; its bytes); other owned/file sources stay U.
widget_image_bound_record:
    push rbx
    mov  rbx, rsi
    call wgt_birth_lifetime
    test rax, rax
    jz   .out
    cmp  rax, rbx
    jne  .out
    call widget_image_state_ptr
    mov  r11, rax
    imul r8, rdi, WIB_APP_SZ
    lea  r10, [rel widget_image_bound_app]
    add  r10, r8
    mov  qword [r10], 0                ; embedded rows carry no provenance
    mov  rax, [r11 + WIS_SRC]
    lea  rdx, [rel img_assets]
    sub  rax, rdx
    cmp  rax, IMG_ASSET_COUNT * IMG_ASSET_ENTSZ
    jae  .app_row
    xor  edx, edx
    mov  ecx, IMG_ASSET_ENTSZ
    div  rcx
    test edx, edx
    jnz  .out
    jmp  .record
.app_row:
    push rdi
    push r10
    push r11
    mov  rdi, [r11 + WIS_SRC]
    call app_launcher_image_provenance
    pop  r11
    pop  r10
    pop  rdi
    test rax, rax
    jz   .out
    mov  [r10], rax
%assign i 0
%rep 4
    mov  rdx, [rcx + i*8]
    mov  [r10 + 8 + i*8], rdx
%assign i i+1
%endrep
.record:
    imul r8, rdi, 48
    lea  r10, [rel widget_image_bound]
    add  r10, r8
    ; Private pointer remains internal; output contains only bounded scalars.
%assign i 0
%rep 5
    mov  rax, [r11 + i*8]
    mov  [r10 + 8 + i*8], rax
%assign i i+1
%endrep
    mov  [r10], rbx
.out:
    pop  rbx
    ret

; EDI=current id, RAX=its WIS state -> RAX unchanged when the original record
; is an embedded row or its recorded app owner and digest still match the live
; launcher row; 0 after that row was dropped or republished. Pure read.
widget_image_app_current:
    push rbx
    push r12
    push r13
    mov  r13, rax
    imul r12, rdi, WIB_APP_SZ
    lea  rdx, [rel widget_image_bound_app]
    add  r12, rdx
    cmp  qword [r12], 0
    je   .yes
    mov  rdi, [rax + WIS_SRC]
    call app_launcher_image_provenance
    cmp  rax, [r12]
    jne  .no
%assign i 0
%rep 4
    mov  rdx, [rcx + i*8]
    cmp  rdx, [r12 + 8 + i*8]
    jne  .no
%assign i i+1
%endrep
.yes:
    mov  rax, r13
    jmp  .out
.no:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; EDI=current id -> RAX=current state only when it still matches an original
; successful embedded bind of this exact birth. Pure read: no draw/cache/codec.
widget_image_bound_state:
    push rbx
    call wgt_birth_lifetime
    test rax, rax
    jz   .bad
    imul rbx, rdi, 48
    lea  rdx, [rel widget_image_bound]
    add  rbx, rdx
    cmp  [rbx], rax
    jne  .bad
    call widget_image_state_ptr
%assign i 0
%rep 5
    mov  rcx, [rax + i*8]
    cmp  rcx, [rbx + 8 + i*8]
    jne  .bad
%assign i i+1
%endrep
    call widget_image_app_current      ; A4: app provenance still live
    test rax, rax
    jz   .bad
    cmp  dword [rax + WIS_FIT], WIMG_FIT_TILE
    ja   .bad
    cmp  dword [rax + WIS_LOAD], WIMG_LOAD_OK
    jne  .bad
    cmp  byte [rax + WIS_REBIND], 0
    jne  .bad
    cmp  dword [rax + WIS_NW], 0
    je   .bad
    cmp  dword [rax + WIS_NH], 0
    je   .bad
    cmp  dword [rax + WIS_OUTW], 0
    je   .bad
    cmp  dword [rax + WIS_OUTH], 0
    je   .bad
    pop  rbx
    ret
.bad:
    xor  eax, eax
    pop  rbx
    ret

; EDI=current id -> RAX only for the exact completed original embedded bind
; failure of this birth. Private snapshot/asset-row proof is shared bookkeeping;
; no getter, loading, decoding, cache access, painting or replacement instance.
widget_image_refused_state:
    push rbx
    call wgt_birth_lifetime
    test rax, rax
    jz   .bad
    imul rbx, rdi, 48
    lea  rdx, [rel widget_image_bound]
    add  rbx, rdx
    cmp  [rbx], rax
    jne  .bad
    call widget_image_state_ptr
%assign i 0
%rep 5
    mov  rcx, [rax + i*8]
    cmp  rcx, [rbx + 8 + i*8]
    jne  .bad
%assign i i+1
%endrep
    call widget_image_app_current      ; A4: app provenance still live
    test rax, rax
    jz   .bad
    cmp  dword [rax + WIS_FIT], WIMG_FIT_TILE
    ja   .bad
    ; Only completed, finite original failures. Never interpret stale dimensions.
    mov  ecx, [rax + WIS_LOAD]
    sub  ecx, WIMG_LOAD_REFUSED + 1
    cmp  ecx, 6                        ; IMG_E_BAD_MAGIC through IMG_E_OOM
    ja   .bad
    cmp  byte [rax + WIS_REBIND], 0
    jne  .bad
    pop  rbx
    ret
.bad:
    xor  eax, eax
    pop  rbx
    ret

; ECX=natural w, EDX=natural h, ESI=viewport w, R8D=viewport h.
; -> ESI=out w, EDX=out h, both >=1, no upscale. Caller supplies validated
; positive dimensions (native image probe and bounded widget geometry).
widget_image_contain_size:
    mov  r9d, edx
    cmp  esi, ecx
    cmova esi, ecx
    mov  eax, esi
    imul rax, r9
    xor  edx, edx
    div  rcx
    cmp  eax, r8d
    jbe  .height_ready
    mov  eax, r8d
    imul rax, rcx
    xor  edx, edx
    div  r9
    mov  esi, eax
    mov  eax, r8d
.height_ready:
    mov  edx, eax
    mov  eax, 1
    test esi, esi
    cmovz esi, eax
    test edx, edx
    cmovz edx, eax
    ret

; Rebind only from FORMLOAD/idempotent normal context, never from damage paint.
widget_image_rebind_window:
    push rbx
    push r12
    push r13
    mov  r13d, edi
    xor  r12d, r12d
.loop:
    cmp  r12d, [rel wgt_count]
    jae  .out
    mov  edi, r12d
    call widget_image_state_ptr
    mov  rbx, rax
    mov  edi, r12d
    call wgt_slot_ptr
    cmp  [rax + WGI_WIN], r13d
    jne  .next
    mov  ecx, [rel image_type_id]
    inc  ecx
    cmp  [rax + WGI_TYPE], ecx
    jne  .next
    ; Owned disk snapshots keep their caption/source alive until close, but
    ; must not republish a cached raster after their authority or file identity
    ; changes. Validate on ordinary raise, before either rebind or paint; the
    ; full check performs VFS work and therefore never belongs in draw.
    mov  rdi, [rbx + WIS_SRC]
    lea  rax, [rel img_source_slots]
    cmp  rdi, rax
    je   .owned
    add  rax, ISS_SZ
    cmp  rdi, rax
    jne  .rebind
.owned:
    call img_source_current
    test eax, eax
    jz   .rebind
    mov  dword [rbx + WIS_LOAD], WIMG_LOAD_REFUSED
    mov  byte [rbx + WIS_REBIND], 0
    jmp  .next
.rebind:
    cmp  byte [rbx + WIS_REBIND], 0
    je   .next
    mov  edi, r12d
    mov  rsi, [rbx + WIS_SRC]
    mov  edx, [rbx + WIS_FIT]
    call widget_image_bind
.next:
    inc  r12d
    jmp  .loop
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; EDI=widget id. Paint is strictly cache lookup + blit (or token fill).
widget_image_draw:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r12d, edi
    call wgt_slot_ptr
    mov  rbp, rax
    mov  edi, r12d
    call widget_image_state_ptr
    mov  r15, rax
    cmp  dword [r15 + WIS_LOAD], WIMG_LOAD_OK
    jne  .placeholder
    mov  rdi, [r15 + WIS_SRC]
    mov  esi, [r15 + WIS_OUTW]
    mov  edx, [r15 + WIS_OUTH]
    call img_cache_lookup
    test eax, eax
    jnz  .evicted
    mov  r13, rbx                       ; current packed cache pointer
    cmp  dword [r15 + WIS_FIT], WIMG_FIT_TILE
    je   .tile
    cmp  dword [r15 + WIS_FIT], WIMG_FIT_COVER
    je   .cover
    cmp  byte [rel img_cache_ret_nat], 0
    jne  .natural
    mov  r14d, [r15 + WIS_OUTW]
    mov  r8d, [rbp + WGI_X]
    mov  r9d, [rbp + WGI_Y]
    mov  r10d, r14d
    mov  r11d, [r15 + WIS_OUTH]
    mov  eax, [r15 + WIS_FIT]
    cmp  eax, WIMG_FIT_SCALE
    je   .blit
    cmp  eax, WIMG_FIT_CONTAIN
    je   .center_fit
    cmp  eax, WIMG_FIT_CENTER
    jne  .clip_none
.center_fit:
    mov  eax, [rbp + WGI_W]
    cmp  r14d, eax
    ja   .crop_x
    sub  eax, r14d
    shr  eax, 1
    add  r8d, eax
    jmp  .center_y
.crop_x:
    sub  r14d, eax
    shr  r14d, 1
    lea  r13, [r13 + r14*4]
    mov  r14d, [rbp + WGI_W]
    mov  r10d, r14d
.center_y:
    mov  eax, [rbp + WGI_H]
    cmp  dword [r15 + WIS_OUTH], eax
    ja   .crop_y
    sub  eax, [r15 + WIS_OUTH]
    shr  eax, 1
    add  r9d, eax
    jmp  .blit
.crop_y:
    mov  edx, [r15 + WIS_OUTH]
    sub  edx, eax
    shr  edx, 1
    imul edx, [r15 + WIS_OUTW]
    lea  r13, [r13 + rdx*4]
    mov  r11d, [rbp + WGI_H]
    jmp  .blit
.clip_none:
    mov  eax, [rbp + WGI_W]
    cmp  r10d, eax
    cmova r10d, eax
    mov  eax, [rbp + WGI_H]
    cmp  r11d, eax
    cmova r11d, eax
.blit:
    call widget_image_backdrop          ; A5: the host backdrop under the same rect
    mov  rdi, r13
    mov  esi, [r15 + WIS_OUTW]
    call fb_blit_rgba_over              ; straight alpha over that backdrop
    jmp  .out
.tile:
    ; The natural cache key is shared across resize. Intersect the widget
    ; with the framebuffer in signed64 before looping, so negative origins,
    ; large endpoints and empty/offscreen widgets never multiply the work.
    cmp  byte [rel img_cache_ret_nat], 0
    jne  .placeholder
    cmp  dword [r15 + WIS_OUTW], 0
    je   .placeholder
    cmp  dword [r15 + WIS_OUTH], 0
    je   .placeholder
    movsxd rax, dword [rbp + WGI_X]
    movsxd rcx, dword [rbp + WGI_W]
    test rcx, rcx
    jle  .out
    add  rcx, rax
    mov  edx, [rel fb_width]
    cmp  rcx, rdx
    cmovg rcx, rdx
    test rax, rax
    jns  .tile_x0
    xor  eax, eax
.tile_x0:
    ; Bound tile enumeration itself before entering either loop. Primitive
    ; clipping alone still visited every tiny source tile on the full screen
    ; while an idle replay owned only one short row. Keep the original widget
    ; origin below for modulo phase; only the visible interval is narrowed.
    cmp  byte [rel fb_compose_clip_active], 0
    je   .tile_x_visible
    mov  esi, [rel fb_compose_x0]
    cmp  rax, rsi
    cmovl rax, rsi
    mov  esi, [rel fb_compose_x1]
    cmp  rcx, rsi
    cmovg rcx, rsi
.tile_x_visible:
    cmp  rax, rcx
    jge  .out
    mov  r14d, eax                     ; visible left, widget-relative phase below
    movsxd rax, dword [rbp + WGI_Y]
    movsxd rdx, dword [rbp + WGI_H]
    test rdx, rdx
    jle  .out
    add  rdx, rax
    mov  esi, [rel fb_height]
    cmp  rdx, rsi
    cmovg rdx, rsi
    test rax, rax
    jns  .tile_y0
    xor  eax, eax
.tile_y0:
    cmp  byte [rel fb_compose_clip_active], 0
    je   .tile_y_visible
    mov  esi, [rel fb_compose_y0]
    cmp  rax, rsi
    cmovl rax, rsi
    mov  esi, [rel fb_compose_y1]
    cmp  rdx, rsi
    cmovg rdx, rsi
.tile_y_visible:
    cmp  rax, rdx
    jge  .out
    mov  r12d, eax                     ; current visible row
    sub  rsp, 32
    mov  [rsp], ecx                    ; exclusive right
    mov  [rsp + 4], edx                ; exclusive bottom
.tile_row:
    mov  eax, r12d
    sub  eax, [rbp + WGI_Y]
    xor  edx, edx
    div  dword [r15 + WIS_OUTH]
    mov  [rsp + 8], edx                ; row within natural tile
    mov  eax, [r15 + WIS_OUTH]
    sub  eax, edx
    mov  ecx, [rsp + 4]
    sub  ecx, r12d
    cmp  eax, ecx
    cmova eax, ecx
    mov  [rsp + 12], eax               ; clipped row-block height
    mov  ebx, r14d
.tile_column:
    mov  eax, ebx
    sub  eax, [rbp + WGI_X]
    xor  edx, edx
    div  dword [r15 + WIS_OUTW]
    mov  eax, [rsp + 8]
    mov  esi, [r15 + WIS_OUTW]
    imul rax, rsi
    add  rax, rdx
    lea  rdi, [r13 + rax*4]
    mov  r10d, esi
    sub  r10d, edx
    mov  eax, [rsp]
    sub  eax, ebx
    cmp  r10d, eax
    cmova r10d, eax
    mov  [rsp + 16], r10d              ; clipped column-block width
    mov  r8d, ebx
    mov  r9d, r12d
    mov  r11d, [rsp + 12]
    call widget_image_backdrop         ; repaint alpha over original host backing
    call fb_blit_rgba_over
    add  ebx, [rsp + 16]
    cmp  ebx, [rsp]
    jb   .tile_column
    add  r12d, [rsp + 12]
    cmp  r12d, [rsp + 4]
    jb   .tile_row
    add  rsp, 32
    jmp  .out
.cover:
    ; COVER binds the natural dimensions, so the cache always holds a packed
    ; decoded raster <=8 MiB, independent of the output's 4K/33 MiB size.
    sub  rsp, 48
    mov  [rsp], r13
    mov  eax, [r15 + WIS_OUTW]
    mov  edx, [r15 + WIS_OUTH]
    mov  [rsp + 16], eax
    mov  [rsp + 20], edx
    imul rax, rdx
    shl  rax, 2
    mov  [rsp + 8], rax
    mov  eax, [rbp + WGI_X]
    mov  [rsp + 24], eax
    mov  eax, [rbp + WGI_Y]
    mov  [rsp + 28], eax
    mov  eax, [rbp + WGI_W]
    mov  [rsp + 32], eax
    mov  eax, [rbp + WGI_H]
    mov  [rsp + 36], eax
    mov  qword [rsp + 40], 0
    mov  rdi, rsp
    call img_cover_blit
    add  rsp, 48
    test eax, eax
    jnz  .placeholder
    jmp  .out
.natural:
    ; RCQ-27: a natural raster has no output stride; only the scaled fit maps it.
    cmp  dword [r15 + WIS_FIT], WIMG_FIT_SCALE
    jne  .placeholder
    mov  rdi, r13
    mov  esi, [r15 + WIS_OUTW]
    mov  edx, [r15 + WIS_OUTH]
    xor  ecx, ecx
    xor  eax, eax
    mov  r8d, [rbp + WGI_X]
    mov  r9d, [rbp + WGI_Y]
    mov  r10d, esi
    mov  r11d, edx
    call widget_image_backdrop
    call img_cache_nat_blit_over
    test eax, eax
    jnz  .placeholder
    jmp  .out
.evicted:
    mov  dword [r15 + WIS_LOAD], WIMG_LOAD_MISSING
    mov  byte [r15 + WIS_REBIND], 1
.placeholder:
    mov  r8d, [rbp + WGI_X]
    mov  r9d, [rbp + WGI_Y]
    mov  r10d, [rbp + WGI_W]
    mov  r11d, [rbp + WGI_H]
    mov  ebx, GUI_TOK_TASKBAR_NORMAL    ; existing neutral theme token, no raw colour
    call fb_fill_rect
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; widgets-01 A5 (ROOT 107385): before an image widget composes its alpha, paint
; what the host shows beneath it over exactly the rect about to be blitted
; (R8D..R11D, rbp = widget slot): the wallpaper for a desktop-hosted widget, the
; window body (WIN_BODY_COLOR, window.asm:45) otherwise. A lone repaint therefore
; never re-blends over its own earlier pixels. Preserves every register.
widget_image_backdrop:
    cmp  dword [rbp + WGI_WIN], WGT_HOST_DESKTOP
    jne  .body
    jmp  wallpaper_paint_rect           ; preserves all registers
.body:
    push rbx
    push rsi                            ; fb_fill_rect promises only r8..r11/ebx
    mov  ebx, GUI_TOK_WINDOW_BODY
    call fb_fill_rect
    pop  rsi
    pop  rbx
    ret

; Standing image-widget instance, owned by the desktop instead of a window.
; WIS_SRC=0 is the token variant of the same param. It takes no window slot,
; has no focus/hit target, and serializes through WINTREE's desktop selector.
; Runtime-only by contract 2122; persistence belongs to the config-store era.
wallpaper_declare:
    lea  rdi, [rel str_verb_wallpaper]
    lea  rsi, [rel cmd_verb_wallpaper]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8d, r8d
    xor  r9d, r9d                     ; public read; arguments gate in handler
    call command_register_verb
    test eax, eax
    js   .out
    cmp  qword [rel fb_base], 0
    je   .out
    cmp  byte [rel img_cache_reg_ok], 1
    jne  .out
    lea  rdi, [rel str_wallpaper_marker]
    call serial_string
.out:
    ret

; R8D/R9D/R10D/R11D = damage rectangle. Preserve all registers, as the old
; fill seam did. No allocation, decode, scale or full-screen repaint here.
wallpaper_paint_rect:
    call fb_compose_defer_scene
    jnc .compose
    ret
.compose:
    push rbp
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    call tray_clock_rearm_if_covered    ; 0.0.52 re-cut 1c: a paint over the tray cell re-arms the clock
    test r10d, r10d
    jle  .out
    test r11d, r11d
    jle  .out
    test r8d, r8d
    jns  .clip_y
    add  r10d, r8d
    xor  r8d, r8d
.clip_y:
    test r9d, r9d
    jns  .clip_right
    add  r11d, r9d
    xor  r9d, r9d
.clip_right:
    mov  eax, [rel fb_width]
    sub  eax, r8d
    jle  .out
    cmp  r10d, eax
    cmovg r10d, eax
    mov  eax, [rel fb_height]
    sub  eax, r9d
    jle  .out
    cmp  r11d, eax
    cmovg r11d, eax
    test r10d, r10d
    jle  .out
    test r11d, r11d
    jle  .out
    ; Bound tile/repeat traversal itself, before lookup and source expansion.
    call fb_compose_intersect
    jc .out
    mov  r12d, r8d
    mov  r13d, r9d
    mov  r14d, r10d
    mov  r15d, r11d
    mov  eax, r14d
    imul rax, r15
    add  [rel wallpaper_paint_pixels], rax
    test r12d, r12d
    jnz  .lookup
    test r13d, r13d
    jnz  .lookup
    cmp  r14d, [rel fb_width]
    jne  .lookup
    cmp  r15d, [rel fb_height]
    jne  .lookup
    inc  qword [rel wallpaper_full_paints]
.lookup:
    mov  rdi, [rel wallpaper_state + WIS_SRC]
    test rdi, rdi
    jz   .token
    mov  esi, [rel wallpaper_state + WIS_OUTW]
    mov  edx, [rel wallpaper_state + WIS_OUTH]
    call img_cache_lookup
    test eax, eax
    jnz  .token                        ; defensive; the live key is pinned
    cmp  dword [rel wallpaper_state + WIS_FIT], WIMG_FIT_TILE
    je   .tile
    cmp  dword [rel wallpaper_state + WIS_FIT], WIMG_FIT_CONTAIN
    je   .fit
    mov  rdi, rbx
    mov  esi, [rel wallpaper_state + WIS_OUTW]
    ; Resolution changes never permit reading outside the bound raster.
    mov  eax, r12d
    add  eax, r14d
    cmp  eax, esi
    ja   .token
    mov  eax, r13d
    add  eax, r15d
    cmp  eax, [rel wallpaper_state + WIS_OUTH]
    ja   .token
    cmp  byte [rel img_cache_ret_nat], 0
    je   .direct
    mov  edx, [rel wallpaper_state + WIS_OUTH]   ; RCQ-27: natural raster, mapped
    mov  ecx, r12d
    mov  eax, r13d
    mov  r8d, r12d
    mov  r9d, r13d
    mov  r10d, r14d
    mov  r11d, r15d
    call img_cache_nat_blit
    test eax, eax
    jnz  .token
    jmp  .out
.direct:
    mov  eax, r13d
    imul rax, rsi
    add  rax, r12
    lea  rdi, [rdi + rax*4]
    mov  r8d, r12d
    mov  r9d, r13d
    mov  r10d, r14d
    mov  r11d, r15d
    call fb_blit_rgba
    jmp  .out
.fit:
    ; The cache key is the aspect-fitted output. Fill only this damage, then
    ; intersect it with the centered image. No decode/scale/allocation here.
    mov  esi, [rel wallpaper_state + WIS_OUTW]
    mov  edx, [rel wallpaper_state + WIS_OUTH]
    test esi, esi
    jz   .token
    test edx, edx
    jz   .token
    cmp  esi, [rel fb_width]
    ja   .token
    cmp  edx, [rel fb_height]
    ja   .token
    mov  rbp, rbx                      ; cache pointer survives the bar fill
    mov  r8d, r12d
    mov  r9d, r13d
    mov  r10d, r14d
    mov  r11d, r15d
    mov  ebx, GUI_TOK_DESKTOP
    call fb_fill_rect
    mov  ecx, [rel fb_width]
    sub  ecx, [rel wallpaper_state + WIS_OUTW]
    shr  ecx, 1                       ; image left
    mov  eax, [rel fb_height]
    sub  eax, [rel wallpaper_state + WIS_OUTH]
    shr  eax, 1                       ; image top
    mov  r8d, r12d
    cmp  r8d, ecx
    cmovb r8d, ecx
    mov  r10d, r12d
    add  r10d, r14d
    mov  edx, ecx
    add  edx, [rel wallpaper_state + WIS_OUTW]
    cmp  r10d, edx
    cmova r10d, edx
    sub  r10d, r8d
    jle  .out
    mov  r9d, r13d
    cmp  r9d, eax
    cmovb r9d, eax
    mov  r11d, r13d
    add  r11d, r15d
    mov  edx, eax
    add  edx, [rel wallpaper_state + WIS_OUTH]
    cmp  r11d, edx
    cmova r11d, edx
    sub  r11d, r9d
    jle  .out
    mov  ebx, r8d
    sub  ebx, ecx
    mov  ecx, ebx                     ; source x in fitted output
    mov  ebx, r9d
    sub  ebx, eax
    mov  eax, ebx                     ; source y in fitted output
    mov  rdi, rbp
    mov  esi, [rel wallpaper_state + WIS_OUTW]
    cmp  byte [rel img_cache_ret_nat], 0
    je   .fit_direct
    mov  edx, [rel wallpaper_state + WIS_OUTH]
    call img_cache_nat_blit
    test eax, eax
    jnz  .token
    jmp  .out
.fit_direct:
    imul rax, rsi
    add  rax, rcx
    lea  rdi, [rdi + rax*4]
    call fb_blit_rgba
    jmp  .out
.tile:
    ; The cache key is the natural raster. Repeat from desktop origin even
    ; for partial damage. Every blit is bounded by both the tile and damage.
    mov  esi, [rel wallpaper_state + WIS_OUTW]
    test esi, esi
    jz   .token
    cmp  dword [rel wallpaper_state + WIS_OUTH], 0
    je   .token
    mov  rbp, rbx
    add  r14d, r12d                     ; exclusive damage right/bottom
    add  r15d, r13d
    sub  rsp, 16
.tile_row:
    mov  eax, r13d
    xor  edx, edx
    div  dword [rel wallpaper_state + WIS_OUTH]
    mov  [rsp], edx                     ; source y within this tile
    mov  eax, [rel wallpaper_state + WIS_OUTH]
    sub  eax, edx
    mov  ecx, r15d
    sub  ecx, r13d
    cmp  eax, ecx
    cmova eax, ecx
    mov  [rsp + 4], eax                 ; bounded row-block height
    mov  ebx, r12d
.tile_column:
    mov  eax, ebx
    xor  edx, edx
    div  dword [rel wallpaper_state + WIS_OUTW]
    mov  eax, [rsp]
    mov  esi, [rel wallpaper_state + WIS_OUTW]
    imul rax, rsi
    add  rax, rdx
    lea  rdi, [rbp + rax*4]
    mov  r10d, esi
    sub  r10d, edx
    mov  eax, r14d
    sub  eax, ebx
    cmp  r10d, eax
    cmova r10d, eax
    mov  [rsp + 8], r10d
    mov  r8d, ebx
    mov  r9d, r13d
    mov  r11d, [rsp + 4]
    call fb_blit_rgba
    add  ebx, [rsp + 8]
    cmp  ebx, r14d
    jb   .tile_column
    add  r13d, [rsp + 4]
    cmp  r13d, r15d
    jb   .tile_row
    add  rsp, 16
    jmp  .out
.token:
    mov  r8d, r12d
    mov  r9d, r13d
    mov  r10d, r14d
    mov  r11d, r15d
    mov  ebx, [rel wallpaper_token_color]
    call fb_fill_rect
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdi
    pop  rsi
    pop  rdx
    pop  rcx
    pop  rbx
    pop  rax
    pop  rbp
    ret

cmd_verb_wallpaper:
    call cmd_handler_prologue
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 24                       ; staged fit/output, published after bind
    mov  dword [rsp], WIMG_FIT_SCALE
    xor  ebp, ebp                      ; staged owned row, never live on failure
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, [r12 + REQ_ARG]
    test r14, r14
    jz   .read
    cmp  byte [r14], 0
    je   .read
    ; Exactly one durable Task2020 authorization for EVERY nonempty form,
    ; including invalid assets/tokens. The empty public read writes no NVRAM.
    mov  rdi, CMD_AUTH_CAP_MUTATE
    lea  rsi, [rel str_verb_wallpaper]
    call command_auth_gate
    test eax, eax
    jnz  .auth_refused
    call boot_ms_now
    mov  r15, rax
    cmp  qword [rel fb_base], 0
    je   .no_display
    cmp  dword [r14], 'lock'
    jne  .desktop_choice
    cmp  byte [r14 + 4], ' '
    je   .lock_choice
.desktop_choice:
    cmp  dword [r14], 'fit '
    jne  .maybe_tile
    mov  dword [rsp], WIMG_FIT_CONTAIN
    add  r14, 4                       ; same embedded catalog, no ambient path
    jmp  .asset
.maybe_tile:
    cmp  dword [r14], 'tile'
    jne  .ordinary
    cmp  byte [r14 + 4], ' '
    jne  .ordinary
    mov  dword [rsp], WIMG_FIT_TILE
    add  r14, 5                         ; embedded catalog only; no ambient path
    jmp  .asset
.ordinary:
    mov  rdi, r14
    lea  rsi, [rel str_wallpaper_none]
    call strcmp
    test eax, eax
    jz   .default_token
    cmp  dword [r14], 'file'
    jne  .token_or_asset
    cmp  byte [r14 + 4], ' '
    je   .file
.token_or_asset:
    cmp  dword [r14], 'toke'
    jne  .asset
    cmp  word [r14 + 4], 'n '
    jne  .asset
    lea  rdi, [r14 + 6]
    lea  rsi, [rel str_wallpaper_default]
    call strcmp
    test eax, eax
    jz   .default_token
    lea  rdi, [r14 + 6]
    lea  rsi, [rel str_wallpaper_desktop]
    call strcmp
    test eax, eax
    jz   .default_token
    lea  rdi, [r14 + 6]
    lea  rsi, [rel str_wallpaper_plain]
    call strcmp
    test eax, eax
    jnz  .bad_token
    mov  dword [rel wallpaper_token_color], GUI_TOK_TASKBAR_NORMAL
    lea  rax, [rel str_wallpaper_plain]
    jmp  .token_commit
.default_token:
    mov  dword [rel wallpaper_token_color], GUI_TOK_DESKTOP
    lea  rax, [rel str_wallpaper_desktop]
.token_commit:
    mov  dword [rel wallpaper_state + WIS_FIT], WIMG_FIT_SCALE
    mov  [rel wallpaper_token_name], rax
    mov  rdi, [rel wallpaper_state + WIS_SRC]
    mov  qword [rel wallpaper_state + WIS_SRC], 0
    ; Embedded cache entries remain cheap to rebind. Owned sources retire
    ; only after the live widget and its pin have detached.
    ; At 2560x1600 two full-screen rasters cannot share the 24 MiB arena.
    mov  qword [rel img_cache_pin_asset], 0
    call img_source_retire
    jmp  .compose
.file:
    ; Explicit decimal mount followed by one absolute counted path. Never
    ; change FSSEL or borrow its ambient handle. Spaces inside paths survive.
    lea  rsi, [r14 + 5]
    xor  edi, edi
    xor  ecx, ecx
.mount:
    movzx eax, byte [rsi]
    cmp  al, ' '
    je   .mount_end
    sub  eax, '0'
    cmp  eax, 9
    ja   .source_refused
    imul edi, edi, 10
    add  edi, eax
    cmp  edi, VFS_MAX_MOUNTS
    jae  .source_refused
    inc  ecx
    cmp  ecx, 2
    ja   .source_refused
    inc  rsi
    jmp  .mount
.mount_end:
    test ecx, ecx
    jz   .source_refused
    inc  rsi
    xor  edx, edx
.path_len:
    cmp  edx, 1024
    ja   .source_refused
    cmp  byte [rsi + rdx], 0
    je   .acquire
    inc  edx
    jmp  .path_len
.acquire:
%ifdef PAOS_IMG_COLD_LIVE
    mov ecx,255
    call img_cold_queue_file
    test eax,eax
    jnz .source_refused
    call img_out_reset
    lea rdi,[rel str_wallpaper_queued]
    call img_out_str
    jmp .ok                             ; admission only; old frame is still live
%else
    call img_source_acquire
    test rax, rax
    jz   .source_refused
    mov  rbp, rax
    jmp  .bind
%endif
.asset:
    mov  rdi, r14
    call img_asset_find
    test rax, rax
    jz   .missing
.bind:
    mov  r14, rax
    cmp  dword [rsp], WIMG_FIT_CONTAIN
    je   .probe_size
    cmp  dword [rsp], WIMG_FIT_TILE
    jne  .stretch
.probe_size:
    mov  rdi, [r14 + IMG_ASSET_PTR]
    mov  rsi, [r14 + IMG_ASSET_LEN]
    call img_probe
    test eax, eax
    jnz  .decode_refused
    mov  esi, ecx
    cmp  dword [rsp], WIMG_FIT_CONTAIN
    jne  .natural_size
    ; Desktop fit permits up/downscale. Widget contain's no-upscale helper is
    ; unchanged. Positive natural sizes came from the original bounded probe.
    mov  r8d, ecx                     ; natural width/height
    mov  r9d, edx
    mov  esi, [rel fb_width]
    mov  eax, esi
    imul rax, r9
    mov  ecx, [rel fb_height]
    imul rcx, r8
    ; Choose the limiting axis before rounding. A floored candidate height
    ; can equal the screen height while the exact ratio is already too tall.
    cmp  rax, rcx
    jbe  .width_bound
    mov  eax, [rel fb_height]
    imul rax, r8
    xor  edx, edx
    div  r9
    mov  esi, eax
    mov  edx, [rel fb_height]
    jmp  .fit_minimum
.width_bound:
    xor  edx, edx
    div  r8
    mov  edx, eax
.fit_minimum:
    mov  eax, 1
    test esi, esi
    cmovz esi, eax
    test edx, edx
    cmovz edx, eax
.natural_size:
    mov  rdi, r14
    jmp  .cache_bind
.stretch:
    mov  rdi, r14
    mov  esi, [rel fb_width]
    mov  edx, [rel fb_height]
.cache_bind:
    mov  [rsp + 8], esi
    mov  [rsp + 12], edx
    call img_cache_bind
    test eax, eax
    jnz  .decode_refused
    test rbp, rbp
    jz   .publish
    push rcx
    push rdx
    mov  rdi, rbp
    call img_source_current
    pop  rdx
    pop  rcx
    test eax, eax
    jnz  .source_refused
.publish:
    mov  rdi, [rel wallpaper_state + WIS_SRC]
    ; Commit ONLY after decode/scale succeeds, while the previous key remains
    ; pinned. Cache failure has not changed the live widget or its pixels.
    mov  [rel wallpaper_state + WIS_NW], ecx
    mov  [rel wallpaper_state + WIS_NH], edx
    mov  eax, [rsp]
    mov  [rel wallpaper_state + WIS_FIT], eax
    mov  eax, [rsp + 8]
    mov  [rel wallpaper_state + WIS_OUTW], eax
    mov  [rel img_cache_pin_w], eax
    mov  eax, [rsp + 12]
    mov  [rel wallpaper_state + WIS_OUTH], eax
    mov  [rel img_cache_pin_h], eax
    mov  [rel img_cache_pin_asset], r14
    mov  [rel wallpaper_state + WIS_SRC], r14
    xor  ebp, ebp                      ; ownership transferred to live state
    call img_source_retire             ; old row only, after the pin switch
.compose:
    call ps2_cursor_hide
    CADENCE_BATCH_BEGIN
    xor  r8d, r8d
    xor  r9d, r9d
    mov  r10d, [rel fb_width]
    mov  r11d, [rel fb_height]
    lfence
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    mov  rbx, rax
    call wallpaper_paint_rect
    lfence
    rdtsc
    shl  rdx, 32
    or   rax, rdx
    sub  rax, rbx
    cmp  qword [rel wallpaper_state + WIS_SRC], 0
    je   .windows
    mov  [rel wallpaper_blit_cycles], rax
    mov  ecx, [rel fb_width]
    mov  [rel wallpaper_perf_w], ecx
    mov  edx, [rel fb_height]
    mov  [rel wallpaper_perf_h], edx
    imul rcx, rdx
    shl  rcx, 2
    mov  [rel wallpaper_blit_bytes], rcx
    xor  ecx, ecx
    cmp  qword [rel tsc_khz], 0
    je   .timed
    ; Ceil to the advertised millisecond resolution; retain exact cycles too.
    xor  edx, edx
    div  qword [rel tsc_khz]
    test rdx, rdx
    setnz cl
    add  rcx, rax
.timed:
    mov  [rel wallpaper_blit_ms], rcx
.windows:
    call wmx_draw_all                  ; keeps focus and z stamps intact
    CADENCE_BATCH_END
    call ps2_cursor_show
    call boot_ms_now
    sub  rax, r15
    mov  [rel wallpaper_bind_ms], rax
    call img_out_reset
    lea  rdi, [rel str_wallpaper_ok]
    call img_out_str
    call wallpaper_report
    lea  rdi, [rel str_img_ms]
    call img_out_str
    mov  rdi, [rel wallpaper_bind_ms]
    call img_out_dec
    jmp  .ok
.lock_choice:
    ; Same nonempty-command MUTATE gate above, plus the existing lock floor.
    ; Stage only the sizing choice. Do not inspect the private node, bind,
    ; decode or paint while the owner's desktop is visible.
    cmp  byte [rel session_locked], SESSION_LOCKED
    je   .source_refused
    cmp  byte [rel lock_composition_ok], 1
    jne  .source_refused
    lea  rdi, [r14 + 5]
    lea  rsi, [rel str_wallpaper_lock_fit]
    call strcmp
    test eax, eax
    jz   .lock_fit
    lea  rdi, [r14 + 5]
    lea  rsi, [rel str_wallpaper_lock_stretch]
    call strcmp
    test eax, eax
    jz   .lock_stretch
    lea  rdi, [r14 + 5]
    lea  rsi, [rel str_wimg_fit_cover]
    call strcmp
    test eax, eax
    jz   .lock_cover
    lea  rdi, [r14 + 5]
    lea  rsi, [rel str_wallpaper_lock_tile]
    call strcmp
    test eax, eax
    jnz  .source_refused
    mov  ecx, WIMG_FIT_TILE
    lea  r14, [rel str_wallpaper_lock_tile_ok]
    jmp  .lock_publish
.lock_cover:
    mov  ecx, WIMG_FIT_COVER
    lea  r14, [rel str_wallpaper_lock_cover_ok]
    jmp  .lock_publish
.lock_fit:
    mov  ecx, WIMG_FIT_CONTAIN
    lea  r14, [rel str_wallpaper_lock_fit_ok]
    jmp  .lock_publish
.lock_stretch:
    mov  ecx, WIMG_FIT_SCALE
    lea  r14, [rel str_wallpaper_lock_stretch_ok]
.lock_publish:
    mov  [rel lock_wallpaper_fit_choice], ecx
    call img_out_reset
    mov  rdi, r14
    call img_out_str
    jmp  .ok
.read:
    call img_out_reset
    lea  rdi, [rel str_wallpaper_read]
    call img_out_str
    call wallpaper_report
    jmp  .ok
.decode_refused:
    call img_reason_name
    mov  r14, rax
    jmp  .error
.source_refused:
    lea  r14, [rel str_wallpaper_source]
    jmp  .error
.missing:
    lea  r14, [rel str_wallpaper_missing]
    jmp  .error
.bad_token:
    lea  r14, [rel str_wallpaper_bad_token]
    jmp  .error
.no_display:
    lea  r14, [rel str_wallpaper_no_display]
.error:
    test rbp, rbp
    jz   .report_error
    mov  rdi, rbp
    call img_source_retire
.report_error:
    call img_out_reset
    lea  rdi, [rel str_wallpaper_error]
    call img_out_str
    mov  rdi, r14
    call img_out_str
    mov  qword [r13 + RSP_CODE], CMDE_BADARG
    jmp  .ready
.ok:
    mov  qword [r13 + RSP_CODE], CMDE_OK
.ready:
    mov  byte [rel img_out_ready], 1
    mov  rax, [r12 + REQ_ARG]
    mov  [r13 + RSP_VAL], rax
    jmp  .out
.auth_refused:
    mov  qword [r13 + RSP_CODE], CMDE_AUTHDENY
.out:
    add  rsp, 24
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

wallpaper_source_name:
    mov  rax, [rel wallpaper_state + WIS_SRC]
    test rax, rax
    jz   .token
    mov  rax, [rax + IMG_ASSET_NAME]
    ret
.token:
    mov  rax, [rel wallpaper_token_name]
    test rax, rax
    jnz  .out
    lea  rax, [rel str_wallpaper_desktop]
.out:
    ret

wallpaper_mode_name:
    lea  rax, [rel str_wallpaper_mode_token]
    cmp  qword [rel wallpaper_state + WIS_SRC], 0
    je   .out
    lea  rax, [rel str_wallpaper_mode_image]
.out:
    ret

wallpaper_report:
    call wallpaper_mode_name
    mov  rdi, rax
    call img_out_str
    lea  rdi, [rel str_wallpaper_src]
    call img_out_str
    call wallpaper_source_name
    mov  rdi, rax
    call img_out_str
    lea  rdi, [rel str_wallpaper_state]
    cmp  dword [rel wallpaper_state + WIS_FIT], WIMG_FIT_CONTAIN
    je   .fit_state
    cmp  dword [rel wallpaper_state + WIS_FIT], WIMG_FIT_TILE
    jne  .state
    lea  rdi, [rel str_wallpaper_tile_state]
    jmp  .state
.fit_state:
    lea  rdi, [rel str_wallpaper_fit_state]
.state:
    call img_out_str
    ret

; PERF wallpaper reads the most recent actual full-screen IMAGE paint. It
; does not repaint, mutate, or substitute the primitive's tiny scratch bench.
wallpaper_perf_stage:
    call img_out_reset
    lea  rdi, [rel str_wallpaper_perf]
    call img_out_str
    mov  rdi, [rel wallpaper_blit_cycles]
    call img_out_dec
    lea  rdi, [rel str_img_ms]
    call img_out_str
    mov  rdi, [rel wallpaper_blit_ms]
    call img_out_dec
    lea  rdi, [rel str_wallpaper_bytes]
    call img_out_str
    mov  rdi, [rel wallpaper_blit_bytes]
    call img_out_dec
    lea  rdi, [rel str_img_w]
    call img_out_str
    mov  edi, [rel wallpaper_perf_w]
    call img_out_dec
    lea  rdi, [rel str_img_h]
    call img_out_str
    mov  edi, [rel wallpaper_perf_h]
    call img_out_dec
    lea  rdi, [rel str_wallpaper_full_paints]
    call img_out_str
    mov  rdi, [rel wallpaper_full_paints]
    call img_out_dec
    lea  rdi, [rel str_wallpaper_paint_pixels]
    call img_out_str
    mov  rdi, [rel wallpaper_paint_pixels]
    call img_out_dec
    mov  byte [rel img_out_ready], 1
    ret

wallpaper_tree:
    lea  rdi, [rel str_wallpaper_tree]
    call f1_put_str
    call wallpaper_mode_name
    mov  rdi, rax
    call f1_put_str
    lea  rdi, [rel str_wallpaper_src]
    call f1_put_str
    call wallpaper_source_name
    mov  rdi, rax
    call f1_put_escaped
    lea  rdi, [rel str_wallpaper_state]
    cmp  dword [rel wallpaper_state + WIS_FIT], WIMG_FIT_CONTAIN
    je   .fit_state
    cmp  dword [rel wallpaper_state + WIS_FIT], WIMG_FIT_TILE
    jne  .state
    lea  rdi, [rel str_wallpaper_tile_state]
    jmp  .state
.fit_state:
    lea  rdi, [rel str_wallpaper_fit_state]
.state:
    call f1_put_str
    lea  rdi, [rel str_img_w]
    call f1_put_str
    mov  edi, [rel fb_width]
    call f1_put_dec
    lea  rdi, [rel str_img_h]
    call f1_put_str
    mov  edi, [rel fb_height]
    call f1_put_dec
    ret

align 8
wallpaper_state:
    dq 0
    dd WIMG_FIT_SCALE, WIMG_LOAD_OK
    dd 0, 0, 0, 0
    dq 0
wallpaper_token_name: dq 0             ; runtime VA, never baked dq symbol
wallpaper_token_color: dd GUI_TOK_DESKTOP
wallpaper_perf_w: dd 0
wallpaper_perf_h: dd 0
align 8
wallpaper_blit_cycles: dq 0
wallpaper_blit_ms: dq 0
wallpaper_blit_bytes: dq 0
wallpaper_bind_ms: dq 0
wallpaper_full_paints: dq 0
wallpaper_paint_pixels: dq 0
str_verb_wallpaper: db "WALLPAPER",0
str_wallpaper_none: db "none",0
str_wallpaper_default: db "default",0
str_wallpaper_desktop: db "desktop",0
str_wallpaper_plain: db "taskbar_normal",0
str_wallpaper_queued: db "QUEUED; current wallpaper kept until ready",0
str_wallpaper_ok: db " wallpaper=ok",0
str_wallpaper_read: db " WALLPAPER",0
str_wallpaper_mode_token: db " mode=token",0
str_wallpaper_mode_image: db " mode=image",0
str_wallpaper_src: db " src=",0
str_wallpaper_tile_state: db " fit=tile load=ok persistence=runtime tree=WINTREE:desktop",0
str_wallpaper_fit_state: db " fit=contain load=ok persistence=runtime tree=WINTREE:desktop",0
str_wallpaper_state: db " fit=scale load=ok persistence=runtime tree=WINTREE:desktop",0
str_wallpaper_error: db " wallpaper=ERR reason=",0
str_wallpaper_source: db "source",0
str_wallpaper_missing: db "missing",0
str_wallpaper_bad_token: db "token",0
str_wallpaper_no_display: db "no_display",0
str_wallpaper_perf: db " PERF fn=wallpaper impl=fb_blit_rgba cycles=",0
str_wallpaper_bytes: db " bytes=",0
str_wallpaper_full_paints: db " full_paints=",0
str_wallpaper_paint_pixels: db " paint_px=",0
str_wallpaper_tree: db 10,"D id=desktop type=image layer=bottom x=0 y=0",0
str_wallpaper_marker: db "[PAOS64] M6 gui: wallpaper = image widget on desktop layer (token degenerate, refuse keeps prior, vacate-restore) [gui.desktop.wallpaper]",13,10,0

align 8
widget_image_state: times (WGT_MAX*WIS_SZ) db 0
widget_image_bound: times (WGT_MAX*48) db 0 ; birth + private original WIS snapshot
widget_image_bound_app: times (WGT_MAX*WIB_APP_SZ) db 0 ; A4: owner handle + image sha256
image_type_id: dd -1
widget_image_last_status: dd 0
widget_image_natural_h: dd 0

str_wt_image: db "image",0
str_wimg_fit_none: db "none",0
str_wimg_fit_center: db "center",0
str_wimg_fit_scale: db "scale",0
str_wimg_fit_contain: db "contain",0      ; .frm fit names (widgets-01 A4)
str_wimg_fit_cover: db "cover",0
str_wimg_fit_tile: db "tile",0
str_wallpaper_lock_fit: db "fit",0
str_wallpaper_lock_stretch: db "stretch",0
str_wallpaper_lock_tile: db "tile",0
str_wallpaper_lock_tile_ok: db " wallpaper=ok lock_fit=tile effect=next_lock persistence=runtime",0
str_wallpaper_lock_cover_ok: db " wallpaper=ok lock_fit=cover effect=next_lock persistence=runtime",0
str_wallpaper_lock_fit_ok: db " wallpaper=ok lock_fit=contain effect=next_lock persistence=runtime",0
str_wallpaper_lock_stretch_ok: db " wallpaper=ok lock_fit=scale effect=next_lock persistence=runtime",0
str_wimg_load_missing: db "missing",0
str_wimg_load_ok: db "ok",0
str_wimg_alpha_opaque: db "opaque",0
str_wimg_placeholder_token: db "taskbar_normal",0
str_widget_image_marker: db "[PAOS64] M6 widget: image type registered (src/fit/load-state serialized, placeholder on refusal) [ui.widget.image]",13,10,0
str_widget_image_fail: db "[PAOS64] M6 widget: image type registration FAILED [marker withheld]",13,10,0
