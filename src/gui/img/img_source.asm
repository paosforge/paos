;; MODULE gui/img/img_source
;; LAYER 6
;; EXPORTS img_source_acquire, img_source_current, img_source_retire, img_source_authority
;; IMPORTS fs/vfs, core/heap, sec/session, gui/widget, gui/widget_image, gui/window_mgmt, gui/img/img_cache, gui/img/img_core
;; CAPS
;; OWNER saga:gui_image_pipeline
;; CONTEXT: bsp_only  (serialized image pipeline, heap and shared SHA256 workspace)
; Included by widget_image after WIS_*: normal BSP command/backend context,
; never paint. The caller has already consumed the ONE MUTATE authorization.
; Creator of photo/GIF admission: rc-ai-claude on OpenAI Codex. Native BMP,
; PNG, JPEG and accepted still-GIF retain full core probe/decode limits,
; grammar and EXIF orientation; no path extension is treated as format proof.
; Caller serializes singleton image/heap and ALL shared SHA users on BSP
; (no AP/IRQ/reentry), including GIF private-source qualification on decode.
; Native reads retain their public filesystem semantics. Only backends with
; a checkable regular-file extent identity are admitted (currently FAT32,
; including its read-only boot-ESP mount); absent identity ops fail closed.
;
; kmalloc/kfree are bump/no-op. Allocate at most TWO reusable high-heap slabs,
; each bounded by the existing 24 MiB cache budget, instead of leaking a slab
; per selection. Decoder dimensions/pixels retain IMG_MAX_DIM/MAX_PIXELS.
; A slab is immutable while any cache/widget/desktop reference can reach it.
; Retirement invalidates ALL cache keys before returning the slot to the pool.
; Future explicit lock selection can retain a row through widget WIS_SRC;
; this backend does not select a lock image or implement persistence.
ISS_CAP       equ IMG_CACHE_BUDGET
ISS_PATH_CAP  equ 1024                  ; native path API / FS_PATH_CAP
ISS_CHUNK     equ 65536                 ; exact, bounded VFS read steps
ISS_BUSY      equ IMG_ASSET_ENTSZ       ; dd, 0 free / 1 owned (staged or live)
ISS_HANDLE    equ 28                    ; explicit mount, never ambient FSSEL
ISS_PATHLEN   equ 32
ISS_GEN       equ 40                    ; VFS write attempts, even failed ones
ISS_EPOCH     equ 48
ISS_KEY       equ 56
ISS_MAP       equ 64                    ; frozen native map header + first extent
ISS_STAT      equ ISS_MAP + fs_extent_map_size + 16
ISS_PATH      equ ISS_STAT + fs_stat_size
ISS_SZ        equ (ISS_PATH + ISS_PATH_CAP + 1 + 15) & ~15

; EAX=0 only for the current owner-bound desktop frame. AUTH1/MUTATE is
; necessary but cannot borrow another local session or act on PaOS chrome.
img_source_authority:
    call session_shell_require_unlocked
    test eax, eax
    jnz  .bad
    xor  edi, edi
    call session_shell_request_principal
    cmp  rax, PRIN_OWNER
    jne  .bad
    cmp  rax, [rel session_bound_pid]
    jne  .bad
    cmp  qword [rel session_authority_epoch], -1
    je   .bad
    mov  rax, [rel session_authority_epoch]
    test rax, rax
    jz   .bad
    cmp  rax, [rel session_authority]
    jne  .bad
    xor  eax, eax
    ret
.bad:
    mov  eax, 1
    ret

; RDI=row -> EAX=0 same authority, file/mount/device/media/namespace/size.
; Call after each read AND after decode/cache bind, before live publication.
img_source_current:
    push r12
    mov  r12, rdi
    call img_source_authority
    test eax, eax
    jnz  .bad
    mov  rax, [rel session_authority_epoch]
    cmp  rax, [r12 + ISS_EPOCH]
    jne  .bad
    mov  rax, [rel session_key_handle]
    cmp  rax, [r12 + ISS_KEY]
    jne  .bad
    mov  rax, [rel vfs_write_generation]
    cmp  rax, [r12 + ISS_GEN]
    jne  .bad
    mov  edi, [r12 + ISS_HANDLE]
    lea  rsi, [r12 + ISS_MAP]
    call vfs_file_extents_current
    test eax, eax
    jnz  .bad
    ; stat_path resolves this OWNED path again. The generation check below
    ; also covers a replacement during stat (equal-size replacements included).
    mov  edi, [r12 + ISS_HANDLE]
    lea  rsi, [r12 + ISS_PATH]
    mov  edx, [r12 + ISS_PATHLEN]
    lea  rcx, [r12 + ISS_STAT]
    mov  qword [rcx + fs_stat.flags], 0
    call vfs_stat_path
    test rax, rax
    jnz  .bad
    cmp  dword [r12 + ISS_STAT + fs_stat.reserved], 0
    jne  .bad                           ; directory (or unknown nonregular kind)
    mov  rax, [r12 + ISS_STAT + fs_stat.size]
    cmp  rax, [r12 + IMG_ASSET_LEN]
    jne  .bad
    mov  edi, [r12 + ISS_HANDLE]
    lea  rsi, [r12 + ISS_MAP]
    call vfs_file_extents_current
    test eax, eax
    jnz  .bad
    mov  rax, [rel vfs_write_generation]
    cmp  rax, [r12 + ISS_GEN]
    jne  .bad
    xor  eax, eax
    jmp  .out
.bad:
    mov  eax, 1
.out:
    pop  r12
    ret

; RDI=row -> EAX=0 retired/not ours, 1 still referenced. A widget (including
; a future explicit lock consumer) may outlive the desktop selection. Never
; recycle its row merely because its decoded cache entry was evicted/reset.
img_source_retire:
    push r12
    mov  r12, rdi
    lea  rax, [rel img_source_slots]
    cmp  rdi, rax
    je   .ours
    add  rax, ISS_SZ
    cmp  rdi, rax
    jne  .done
.ours:
    cmp  rdi, [rel wallpaper_state + WIS_SRC]
    je   .held
    lea  rax, [rel widget_image_state]
    mov  ecx, WGT_MAX
.widgets:
    cmp  [rax + WIS_SRC], r12
    je   .held
    add  rax, WIS_SZ
    loop .widgets
    call img_cache_forget
    test eax, eax
    jnz  .held
    ; No widget/pin/cache reference remains. Scrub even partial failed reads
    ; and the entire reusable slab, then discard path/identity metadata.
    ; Retain only the allocation pointer: kmalloc_model is bump/no-op-free.
    mov  r8, [r12 + IMG_ASSET_PTR]
    test r8, r8
    jz   .metadata
    mov  rdi, r8
    mov  ecx, ISS_CAP/8
    xor  eax, eax
    cld
    rep  stosq
.metadata:
    mov  rdi, r12
    mov  ecx, ISS_SZ/8
    xor  eax, eax
    cld
    rep  stosq
    mov  [r12 + IMG_ASSET_PTR], r8       ; slot is free only after teardown
.done:
    xor  eax, eax
    jmp  .out
.held:
    mov  eax, 1
.out:
    pop  r12
    ret

; EDI=explicit mount handle, RSI=absolute path, EDX=exact path length.
; RAX=owned immutable IMG_ASSET row / 0 refusal. No live state/pin changes.
; The caller must either publish after img_source_current or retire the row.
img_source_acquire:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r13d, edi
    mov  r14, rsi
    mov  r15d, edx
    xor  r12d, r12d
    cld
    call img_source_authority
    test eax, eax
    jnz  .fail
    cmp  r13d, VFS_MAX_MOUNTS
    jae  .fail
    test r14, r14
    jz   .fail
    cmp  r15d, 2
    jb   .fail
    cmp  r15d, ISS_PATH_CAP
    ja   .fail
    mov  rax, r14
    add  rax, r15
    jc   .fail
    ; Two slots suffice for a transactional desktop replacement. An explicit
    ; additional widget reference can hold a slot; fail rather than steal it.
    ; A staged row is owned by its acquirer until explicit publication or
    ; retirement. Do not scavenge it just because no widget references it yet.
    lea  r12, [rel img_source_slots]
    cmp  dword [r12 + ISS_BUSY], 0
    je   .slot
    add  r12, ISS_SZ
    cmp  dword [r12 + ISS_BUSY], 0
    je   .slot
    xor  r12d, r12d
    jmp  .fail
.slot:
    mov  dword [r12 + ISS_BUSY], 1
    mov  [r12 + ISS_HANDLE], r13d
    mov  [r12 + ISS_PATHLEN], r15d
    mov  rax, [rel session_authority_epoch]
    mov  [r12 + ISS_EPOCH], rax
    mov  rax, [rel session_key_handle]
    mov  [r12 + ISS_KEY], rax
    mov  rax, [rel vfs_write_generation]
    mov  [r12 + ISS_GEN], rax
    lea  rdi, [r12 + ISS_PATH]
    mov  [r12 + IMG_ASSET_NAME], rdi
    mov  rsi, r14
    mov  ecx, r15d
    rep  movsb                         ; caller path is never retained
    mov  byte [rdi], 0
    lea  rsi, [r12 + ISS_PATH]
    cmp  byte [rsi], '/'
    jne  .fail
    xor  ebx, ebx                      ; current component length
    mov  ecx, 1
.path:
    cmp  ecx, r15d
    jae  .last_component
    movzx eax, byte [rsi + rcx]
    cmp  al, '/'
    je   .component
    cmp  al, 32
    jb   .fail                         ; NUL/control inside the counted slice
    cmp  al, 127
    je   .fail
    cmp  al, '\'
    je   .fail
    cmp  al, ':'
    je   .fail
    inc  ebx
    cmp  ebx, 255
    ja   .fail
    inc  ecx
    jmp  .path
.component:
    call .check_component
    test eax, eax
    jnz  .fail
    xor  ebx, ebx
    inc  ecx
    jmp  .path
.last_component:
    call .check_component
    test eax, eax
    jnz  .fail
    mov  edi, r13d
    mov  edx, r15d
    lea  rcx, [r12 + ISS_MAP]
    mov  r8d, 1
    call vfs_file_extents              ; validates regular file + complete chain
    test rax, rax
    jle  .fail
    mov  rax, [r12 + ISS_MAP + fs_extent_map.size]
    cmp  rax, 2
    jb   .fail
    cmp  rax, ISS_CAP
    ja   .fail
    mov  [r12 + IMG_ASSET_LEN], rax
    mov  rdi, r12
    call img_source_current
    test eax, eax
    jnz  .fail
    cmp  qword [r12 + IMG_ASSET_PTR], 0
    jne  .buffer
    mov  edi, ISS_CAP
    call kmalloc_model
    test rax, rax
    jz   .fail
    mov  [r12 + IMG_ASSET_PTR], rax
.buffer:
    xor  ebp, ebp                      ; exact read offset
.read:
    mov  rdi, r12
    call img_source_current
    test eax, eax
    jnz  .fail
    mov  rbx, [r12 + IMG_ASSET_LEN]
    sub  rbx, rbp
    cmp  rbx, ISS_CHUNK
    jbe  .chunk
    mov  ebx, ISS_CHUNK
.chunk:
    mov  edi, r13d
    lea  rsi, [r12 + ISS_PATH]
    mov  edx, r15d
    mov  rcx, rbp
    mov  r8, [r12 + IMG_ASSET_PTR]
    add  r8, rbp
    mov  r9, rbx
    call vfs_read_at_path
    cmp  rax, rbx
    jne  .fail                         ; short, zero, error and over-return refuse
    mov  rdi, r12
    call img_source_current
    test eax, eax
    jnz  .fail
    add  rbp, rbx
    cmp  rbp, [r12 + IMG_ASSET_LEN]
    jb   .read
    mov  rdi, [r12 + IMG_ASSET_PTR]
    mov  rsi, [r12 + IMG_ASSET_LEN]
    call img_probe
    test eax, eax
    jnz  .fail
    cmp  ebx, IMG_FMT_BMP
    je   .format_ready
    cmp  ebx, IMG_FMT_PNG
    je   .format_ready
    cmp  ebx, IMG_FMT_JPEG
    je   .format_ready
    cmp  ebx, IMG_FMT_GIF
    jne  .fail
.format_ready:
    mov  rdi, r12
    call img_source_current
    test eax, eax
    jnz  .fail
    mov  rax, r12
    jmp  .out
.fail:
    test r12, r12
    jz   .failed
    mov  rdi, r12
    call img_source_retire
.failed:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret
.check_component:
    test ebx, ebx
    jz   .bad_component
    cmp  ebx, 2
    ja   .good_component
    mov  eax, ecx
    sub  eax, ebx
    cmp  byte [rsi + rax], '.'
    jne  .good_component
    cmp  ebx, 1
    je   .bad_component
    cmp  byte [rsi + rax + 1], '.'
    je   .bad_component
.good_component:
    xor  eax, eax
    ret
.bad_component:
    mov  eax, 1
    ret

%include "core/abi/wdata.inc"
%macro WDATA_BSS_gui_img_source 0
alignb 16
img_source_slots: resb ISS_SZ * 2
%endmacro
WDATA_BSS_DEFER WDATA_BSS_gui_img_source
