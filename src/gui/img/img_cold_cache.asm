;; MODULE gui/img/img_cold_cache
;; LAYER 6
;; EXPORTS img_cold_cache_prepare, img_cold_cache_enter, img_cold_cache_leave, img_cold_cache_commit
;; IMPORTS gui/img/img_cache, gui/img/img_cold_idle, core/heap
;; CAPS
;; OWNER saga:gui_image_pipeline
;; CONTEXT: bsp_only
; Transactional cache backing for one cold image. Between turns the ordinary
; cache and its exact old pixels remain live. The worker builds into a second
; retained24MiB arena; no partial compaction or scaling touches the live arena.
; Completed publication swaps bounded metadata, not a whole raster. Unrelated
; cache entries can become cold after a successful wallpaper change, as after
; cache reset; no widget is allowed to retain a cache pointer across idle turns.
;
; The coordinator alone may commit, AFTER checking source, authority, surface
; and preference again. It must finish publication and return without another
; checkpoint: retirement of old sources is separate deferred work.

IMG_COLD_CACHE_BYTES equ img_cache_scratch-img_cache_entries
IMG_COLD_CACHE_BASE equ img_cache_base-img_cache_entries

; Only before entering the worker. The old spare arena is reused; never add a
; fresh24MiB allocation for each preference. No pixels need clearing to prepare:
; an empty cache describes no accessible raster, and bind writes its full output
; before creating an entry. The coordinator owns later retirement/scrubbing.
img_cold_cache_prepare:
    push rbx
    cmp byte [rel img_cold_cache_active],0
    jne .bad
    mov rbx,[rel img_cold_cache_state+IMG_COLD_CACHE_BASE]
    test rbx,rbx
    jnz .clear
    mov edi,IMG_CACHE_BUDGET
    call kmalloc_model
    test rax,rax
    jz .bad
    mov rbx,rax
.clear:
    lea rdi,[rel img_cold_cache_state]
    mov ecx,IMG_COLD_CACHE_BYTES
    xor eax,eax
    cld
    rep stosb                         ; fixed metadata only, never pixel bytes
    mov [rel img_cold_cache_state+IMG_COLD_CACHE_BASE],rbx
    mov byte [rel img_cold_cache_ret_nat],0
    mov byte [rel img_cold_cache_build_nat],0
    mov byte [rel img_cold_cache_keep],0
    xor eax,eax
    pop rbx
    ret
.bad:
    mov eax,1
    pop rbx
    ret

; Preserve every codec-live register and flag. The only swapped region is the
; native bounded cache descriptor state; neither pixels nor source rows move.
img_cold_cache_swap:
    IMG_COLD_SAVE
    lea rsi,[rel img_cache_entries]
    lea rdi,[rel img_cold_cache_state]
    mov ecx,IMG_COLD_CACHE_BYTES/8
.word:
    mov rax,[rsi]
    xchg rax,[rdi]
    mov [rsi],rax
    add rsi,8
    add rdi,8
    dec ecx
    jnz .word
    mov al,[rel img_cache_ret_nat]
    xchg al,[rel img_cold_cache_ret_nat]
    mov [rel img_cache_ret_nat],al
    mov al,[rel img_cache_build_nat]
    xchg al,[rel img_cold_cache_build_nat]
    mov [rel img_cache_build_nat],al
    IMG_COLD_RESTORE
    ret

img_cold_cache_enter:
    pushfq
    cmp byte [rel img_cold_cache_active],0
    jne .out
    call img_cold_cache_swap
    mov byte [rel img_cold_cache_active],1
.out:
    popfq
    ret

img_cold_cache_leave:
    pushfq
    cmp byte [rel img_cold_cache_active],1
    jne .out
    cmp byte [rel img_cold_cache_keep],1
    je .kept
    call img_cold_cache_swap
.kept:
    mov byte [rel img_cold_cache_keep],0
    mov byte [rel img_cold_cache_active],0
.out:
    popfq
    ret

img_cold_cache_commit:
    pushfq
    cmp byte [rel img_cold_cache_active],1
    jne .out
    mov byte [rel img_cold_cache_keep],1
.out:
    popfq
    ret

%include "core/abi/wdata.inc"
%macro WDATA_BSS_gui_img_cold_cache 0
alignb 8
img_cold_cache_state: resb IMG_COLD_CACHE_BYTES
img_cold_cache_ret_nat: resb 1
img_cold_cache_build_nat: resb 1
img_cold_cache_active: resb 1
img_cold_cache_keep: resb 1
%endmacro
WDATA_BSS_DEFER WDATA_BSS_gui_img_cold_cache
