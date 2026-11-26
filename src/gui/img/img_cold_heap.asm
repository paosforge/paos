;; MODULE gui/img/img_cold_heap
;; LAYER 6
;; EXPORTS img_cold_boot_reserve, img_cold_heap_prepare, img_cold_heap_now, img_cold_heap_alloc, img_cold_heap_rewind
;; IMPORTS gui/img/img_core, gui/img/img_bmp, gui/img/img_cold_idle, core/heap
;; CAPS
;; OWNER saga:gui_image_pipeline
;; CONTEXT: bsp_only
; The suspended codec must not borrow the ordinary bump allocator's LIFO tip.
; An unrelated allocation between idle turns is legitimate. Retain one private
; high-memory slab, covering two nested BMP snapshots plus the largest admitted
; native decoder output. Never replace the global allocator's base/next/end.
; Preparation belongs to the coordinator before it marks a new job pending;
; cancellation must retire and scrub the previous job before reusing this slab.
IMG_COLD_HEAP_BYTES equ IMG_LARGE_CAP + 2*BMP_EMBED_MAX

; Before EBS, reserve this optional worker's permanent backing separately from
; the shared model arena. A preloaded cognition model must not consume image
; continuation space, nor may preparing a wallpaper steal the model's space.
; AllocateMaxAddress stays inside the existing 0..16GiB identity map. Firmware
; owns allocation only; no disk, variable, transport or framebuffer is touched.
; Ordinary standalone consumers can still use the original guarded model
; allocator when this boot-only reserve is absent.
%ifdef PAOS_IMG_COLD_LIVE
IMG_COLD_RESERVE_PAGES equ (IMG_COLD_HEAP_BYTES + IMG_CACHE_BUDGET + 2*ISS_CAP + 4095)/4096
img_cold_boot_reserve:
    push rbp
    mov rbp,rsp
    push rbx
    and rsp,-16
    sub rsp,32                         ; EFI Microsoft ABI shadow space
    cmp qword [rel img_cold_heap_base],0
    jne .out                           ; one reservation per boot
    mov rbx,[rel boot_services]
    test rbx,rbx
    jz .out
    mov rax,0x3ffffffff
    mov [rel img_cold_boot_address],rax
    mov ecx,1                          ; AllocateMaxAddress
    mov edx,2                          ; EfiLoaderData, preserved across EBS
    mov r8d,IMG_COLD_RESERVE_PAGES
    lea r9,[rel img_cold_boot_address]
    call [rbx+0x28]
    test rax,rax
    jnz .out                           ; no partial backing becomes usable
    mov rax,[rel img_cold_boot_address]
    test rax,rax
    jz .out
    test rax,4095
    jnz .out
    mov rdx,rax
    add rdx,IMG_COLD_RESERVE_PAGES*4096
    jc .out
    mov rcx,0x400000000
    cmp rdx,rcx
    ja .out
    mov [rel img_cold_heap_base],rax
    mov [rel img_cold_heap_next],rax
    mov [rel img_cold_heap_high],rax
    add rax,IMG_COLD_HEAP_BYTES
    mov [rel img_cold_heap_end],rax
    mov [rel img_cold_cache_state+IMG_COLD_CACHE_BASE],rax
    ; Keep both existing source slots usable even when the cognition model
    ; occupies the shared arena. The old live source must survive a complete
    ; replacement, so one source slab cannot serve both sides of publication.
    add rax,IMG_CACHE_BUDGET
    mov [rel img_source_slots+IMG_ASSET_PTR],rax
    add rax,ISS_CAP
    mov [rel img_source_slots+ISS_SZ+IMG_ASSET_PTR],rax
.out:
    mov rbx,[rbp-8]
    mov rsp,rbp
    pop rbp
    ret
%endif

img_cold_heap_prepare:
    cmp byte [rel img_cold_pending],0
    jne .bad
    cmp byte [rel img_cold_running],0
    jne .bad
    mov rax,[rel img_cold_heap_base]
    test rax,rax
    jz .allocate
    cmp [rel img_cold_heap_next],rax
    jne .bad                         ; unreleased output or unretired job
    jmp .retained
.allocate:
    mov edi,IMG_COLD_HEAP_BYTES
    call kmalloc_model
    test rax,rax
    jz .bad
    mov [rel img_cold_heap_base],rax
.retained:
    mov rdx,rax
    add rdx,IMG_COLD_HEAP_BYTES
    jc .bad
    test al,15
    jnz .bad
    mov [rel img_cold_heap_next],rax
    mov [rel img_cold_heap_end],rdx
    mov [rel img_cold_heap_high],rax
    xor eax,eax
    ret
.bad:
    mov eax,1
    ret

; Same result as reading heap_next; all other registers and flags preserved.
img_cold_heap_now:
    pushfq
    cmp byte [rel img_cold_running],1
    jne .ordinary
    mov rax,[rel img_cold_heap_next]
    popfq
    ret
.ordinary:
    mov rax,[rel heap_next]
    popfq
    ret

; kmalloc ABI: RDI=size -> RAX=ptr or0; clobbers RAX/RDX/RDI and flags only.
; A private miss refuses. It must never fall through to the shared allocator.
img_cold_heap_alloc:
    cmp byte [rel img_cold_running],1
    jne kmalloc
    add rdi,15
    jc .bad
    and rdi,-16
    jnz .size
    mov edi,16
.size:
    mov rax,[rel img_cold_heap_next]
    test rax,rax
    jz .bad
    cmp rax,[rel img_cold_heap_base]
    jb .bad
    cmp rax,[rel img_cold_heap_end]
    ja .bad
    test al,15
    jnz .bad
    mov rdx,rax
    add rdx,rdi
    jc .bad
    cmp rdx,[rel img_cold_heap_end]
    ja .bad
    mov [rel img_cold_heap_next],rdx
    cmp rdx,[rel img_cold_heap_high]
    jbe .recorded
    mov [rel img_cold_heap_high],rdx
.recorded:
    ret
.bad:
    xor eax,eax
    ret

; RDI=allocation, RAX=expected tip, RDX=prior tip. ZF=1 only on release.
; Ownership follows the pointer, including a completed output released after
; the worker returned. Never send a private pointer to ordinary kfree, and
; never rewind the ordinary heap for it. Invalid private records refuse.
img_cold_heap_rewind:
    cmp rdi,[rel img_cold_heap_base]
    jb .ordinary
    cmp rdi,[rel img_cold_heap_end]
    jae .ordinary
    cmp rdi,rdx
    jne .bad
    cmp rax,rdx
    jbe .bad
    cmp rax,[rel img_cold_heap_end]
    ja .bad
    lock cmpxchg [rel img_cold_heap_next],rdx
    ret
.ordinary:
    push rax
    push rdx
    call kfree
    pop rdx
    pop rax
    lock cmpxchg [rel heap_next],rdx
    ret
.bad:
    push rax
    mov eax,1
    test eax,eax
    pop rax
    ret

%include "core/abi/wdata.inc"
%macro WDATA_BSS_gui_img_cold_heap 0
alignb 16
img_cold_heap_base: resq 1
img_cold_heap_next: resq 1
img_cold_heap_end: resq 1
img_cold_heap_high: resq 1
img_cold_boot_address: resq 1
%endmacro
WDATA_BSS_DEFER WDATA_BSS_gui_img_cold_heap
