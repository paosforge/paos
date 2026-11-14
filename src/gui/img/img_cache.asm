;; MODULE gui/img/img_cache
;; LAYER 6
;; EXPORTS img_cache_init, img_cache_reset, img_cache_bind, img_cache_lookup, img_cache_nat_blit, img_cache_forget
;; IMPORTS gui/img/img_core, gui/img/img_rgba_resize, gui/window, core/heap, svc/command
;; CAPS
;; OWNER saga:gui_image_pipeline

; Contract 2121 decode-once cache. One fixed 24 MiB arena avoids allocating in
; paint and lets decoder temporaries remain strict LIFO allocations. The arena
; comes from PaOS's guarded high-memory allocator: the ordinary heap is 16 MiB,
; so asking kmalloc for this contract's required 24 MiB budget must refuse.
; Entries are packed; LRU eviction compacts bytes and fixes offsets, so lookup
; always returns the current pointer and no widget retains a stale address.

IMG_CACHE_MAX    equ 8
IMG_CACHE_BUDGET equ 25165824
IMG_CACHE_DIM_MAX equ 0xFFFF              ; output w/h cap: w*h*4 stays far from 2^64
; RCQ-27 (root 13:42:27): a scaled output over half the arena stores the NATURAL raster;
; paint maps it with the same floor(dst*src/out) as img_cache_scale (img_cache_nat_blit).
IMG_CACHE_NAT_MIN equ IMG_CACHE_BUDGET/2

ICE_ASSET equ 0                       ; dq: img_assets row
ICE_W     equ 8                       ; dd: cached output width
ICE_H     equ 12                      ; dd: cached output height
ICE_NW    equ 16                      ; dd: natural decoded width
ICE_NH    equ 20                      ; dd: natural decoded height
ICE_OFF   equ 24                      ; dq: packed arena byte offset
ICE_BYTES equ 32                      ; dq
ICE_TICK  equ 40                      ; dq: last touch
ICE_NAT   equ 48                      ; dd: 1 = natural raster, painted only via img_cache_nat_blit
ICE_SZ    equ 56

%include "gui/img/img_rgba_resize.asm"

img_cache_entry_ptr:
    imul rax, rdi, ICE_SZ
    lea  rdx, [rel img_cache_entries]
    add  rax, rdx
    ret

; RDI=retired asset key -> EAX=0 / 1 still pinned. The caller must first
; detach all widget references. Tombstones own no source reference; their
; packed ranges are scrubbed and remain first-choice LRU for compaction.
; Invalidate EVERY output-size key before reusing an owned source row/buffer.
img_cache_forget:
    cmp  rdi, [rel img_cache_pin_asset]
    je   .pinned
    xor  ecx, ecx
    lea  rdx, [rel img_cache_entries]
.scan:
    cmp  ecx, [rel img_cache_count]
    jae  .done
    cmp  [rdx + ICE_ASSET], rdi
    jne  .next
    ; Forget every size key, clearing only its owned packed pixel range.
    push rdi
    push rcx
    mov  rdi, [rel img_cache_base]
    add  rdi, [rdx + ICE_OFF]
    mov  rcx, [rdx + ICE_BYTES]
    xor  eax, eax
    cld
    rep  stosb
    pop  rcx
    pop  rdi
    mov  qword [rdx + ICE_ASSET], 0
    mov  qword [rdx + ICE_TICK], 0
.next:
    add  rdx, ICE_SZ
    inc  ecx
    jmp  .scan
.done:
    xor  eax, eax
    ret
.pinned:
    mov  eax, 1
    ret

img_cache_reset:
    push rax
    push rcx
    push rdi
    ; Reset drops all keys: clear their pixels before losing the ranges.
    mov  rdi, [rel img_cache_base]
    test rdi, rdi
    jz   .entries
    mov  rcx, [rel img_cache_bytes]
    xor  eax, eax
    cld
    rep  stosb
.entries:
    lea  rdi, [rel img_cache_entries]
    mov  ecx, IMG_CACHE_MAX*ICE_SZ
    xor  eax, eax
    cld
    rep  stosb
    mov  dword [rel img_cache_count], 0
    mov  qword [rel img_cache_bytes], 0
    mov  qword [rel img_cache_tick], 0
    mov  qword [rel img_cache_hits], 0
    mov  qword [rel img_cache_misses], 0
    mov  qword [rel img_cache_evictions], 0
    pop  rdi
    pop  rcx
    pop  rax
    ret

; RDI=asset row, ESI=out_w, EDX=out_h -> EAX=0 hit/1 absent;
; RBX=RGBA, ECX=natural_w, EDX=natural_h on hit. This is paint-safe: lookup,
; tick and counters only; no decode and no allocation.
img_cache_lookup:
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13d, esi
    mov  r14d, edx
    xor  r15d, r15d
.scan:
    cmp  r15d, [rel img_cache_count]
    jae  .miss
    mov  edi, r15d
    call img_cache_entry_ptr
    cmp  [rax + ICE_ASSET], r12
    jne  .next
    cmp  [rax + ICE_W], r13d
    jne  .next
    cmp  [rax + ICE_H], r14d
    jne  .next
    inc  qword [rel img_cache_hits]
    inc  qword [rel img_cache_tick]
    mov  rdx, [rel img_cache_tick]
    mov  [rax + ICE_TICK], rdx
    mov  rdx, [rel img_cache_base]
    add  rdx, [rax + ICE_OFF]
    mov  [rel img_cache_ret_ptr], rdx
    mov  edx, [rax + ICE_NW]
    mov  [rel img_cache_ret_nw], edx
    mov  edx, [rax + ICE_NH]
    mov  [rel img_cache_ret_nh], edx
    mov  edx, [rax + ICE_NAT]
    mov  [rel img_cache_ret_nat], dl
    xor  eax, eax
    jmp  .out
.next:
    inc  r15d
    jmp  .scan
.miss:
    mov  qword [rel img_cache_ret_ptr], 0
    mov  byte [rel img_cache_ret_nat], 0
    mov  eax, 1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    mov  rbx, [rel img_cache_ret_ptr]
    mov  ecx, [rel img_cache_ret_nw]
    mov  edx, [rel img_cache_ret_nh]
    ret

; Evict the least-recently-used packed entry, compacting its byte range.
img_cache_evict_lru:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  ecx, [rel img_cache_count]
    test ecx, ecx
    jz   .out
    mov  r12d, -1                     ; no eligible victim yet
    mov  r13, -1
    xor  r14d, r14d
.find:
    cmp  r14d, [rel img_cache_count]
    jae  .found
    mov  edi, r14d
    call img_cache_entry_ptr
    ; The standing desktop must survive unrelated form/cache pressure. Identify
    ; its pin by key, never by pointer (compaction moves the packed pixels).
    mov  rdx, [rel img_cache_pin_asset]
    ; Zero means no pin; retired tombstones must remain eligible at every size.
    test rdx, rdx
    jz   .eligible
    cmp  [rax + ICE_ASSET], rdx
    jne  .eligible
    mov  edx, [rel img_cache_pin_w]
    cmp  [rax + ICE_W], edx
    jne  .eligible
    mov  edx, [rel img_cache_pin_h]
    cmp  [rax + ICE_H], edx
    je   .find_next
.eligible:
    cmp  [rax + ICE_TICK], r13
    jae  .find_next
    mov  r13, [rax + ICE_TICK]
    mov  r12d, r14d
.find_next:
    inc  r14d
    jmp  .find
.found:
    cmp  r12d, -1
    je   .pinned
    mov  edi, r12d
    call img_cache_entry_ptr
    mov  rbx, rax
    mov  r13, [rbx + ICE_OFF]
    mov  r14, [rbx + ICE_BYTES]
    mov  rdi, [rel img_cache_base]
    add  rdi, r13
    lea  rsi, [rdi + r14]
    mov  rcx, [rel img_cache_bytes]
    sub  rcx, r13
    sub  rcx, r14
    cld
    rep  movsb                          ; dst<src, overlap-safe forward compaction
    xor  r15d, r15d
.fix_offsets:
    cmp  r15d, [rel img_cache_count]
    jae  .remove_row
    mov  edi, r15d
    call img_cache_entry_ptr
    cmp  [rax + ICE_OFF], r13
    jbe  .fix_next
    sub  [rax + ICE_OFF], r14
.fix_next:
    inc  r15d
    jmp  .fix_offsets
.remove_row:
    mov  ebp, [rel img_cache_count]
    dec  ebp                            ; last index
    cmp  r12d, ebp
    je   .zero_last
    mov  edi, ebp
    call img_cache_entry_ptr
    mov  rsi, rax
    mov  rdi, rbx
    mov  ecx, ICE_SZ/8
    rep  movsq
.zero_last:
    mov  edi, ebp
    call img_cache_entry_ptr
    mov  rdi, rax
    mov  ecx, ICE_SZ/8
    xor  eax, eax
    rep  stosq
    mov  [rel img_cache_count], ebp
    sub  [rel img_cache_bytes], r14
    ; Compaction leaves a duplicate tail outside all live keys.
    mov  rdi, [rel img_cache_base]
    add  rdi, [rel img_cache_bytes]
    mov  rcx, r14
    xor  eax, eax
    cld
    rep  stosb
    inc  qword [rel img_cache_evictions]
.out:
    xor  eax, eax
    jmp  .return
.pinned:
    mov  eax, IMG_E_OOM
.return:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    pop  rbx
    ret

; RDI=raw, RSI=dst, EDX=nw, ECX=nh, R8D=out_w, R9D=out_h.
; Cache bind has qualified packed disjoint buffers and the arena budget.
; Share the exact pixel kernel with the bounded image-service request API.
img_cache_scale:
    jmp  img_rgba_scale_packed

; RDI=asset row, ESI=out_w, EDX=out_h -> EAX=IMG_*, RBX=cached RGBA,
; ECX/EDX=natural dimensions. Decode and scale occur only on a miss here.
img_cache_bind:
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov  r12, rdi
    mov  r13d, esi
    mov  r14d, edx
    call img_cache_lookup
    test eax, eax
    jz   .success_return
    inc  qword [rel img_cache_misses]
    cmp  qword [rel img_cache_base], 0
    je   .oom
    test r13d, r13d
    jz   .oom
    test r14d, r14d
    jz   .oom
    ; msi-b70 F2: the output size is known before decode. An output the arena can
    ; never hold is refused without decoding; the lock wallpaper rebinds at the full
    ; mode on every lock paint, and a 4K mode would otherwise decode each time.
    ; Each dimension is capped first: at w = h = 2^31, w*h*4 wraps 64 bits to 0.
    cmp  r13d, IMG_CACHE_DIM_MAX
    ja   .oom
    cmp  r14d, IMG_CACHE_DIM_MAX
    ja   .oom
    mov  eax, r13d
    imul rax, r14
    shl  rax, 2
    mov  byte [rel img_cache_build_nat], 0
    cmp  rax, IMG_CACHE_NAT_MIN
    jbe  .decode
    ; RCQ-27: over half the arena, store the natural raster when the boot scratch
    ; holds a column map this wide. Without it, today's direct rule applies.
    cmp  qword [rel img_cache_scratch], 0
    je   .direct_only
    cmp  r13d, [rel img_cache_scratch_px]
    ja   .direct_only
    mov  byte [rel img_cache_build_nat], 1
    jmp  .decode
.direct_only:
    cmp  rax, IMG_CACHE_BUDGET
    ja   .oom
.decode:
    mov  rdi, [r12 + IMG_ASSET_PTR]
    mov  rsi, [r12 + IMG_ASSET_LEN]
    call img_decode
    test eax, eax
    jnz  .status_return
    mov  r15, rbx                       ; decoder temporary
    mov  [rel img_cache_build_nw], ecx
    mov  [rel img_cache_build_nh], edx
    mov  eax, r13d
    imul rax, r14
    shl  rax, 2
    cmp  byte [rel img_cache_build_nat], 0
    je   .sized
    ; srcreview F2: keep the natural raster only when it is SMALLER than the output.
    ; An equal one is the same raster either way; a larger one costs more bytes and a
    ; blit per output row. Either stays direct (refused over the arena, as before).
    mov  r8d, ecx
    mov  r9d, edx
    imul r8, r9
    shl  r8, 2                          ; natural bytes
    cmp  r8, rax
    jb   .natural_bytes
    mov  byte [rel img_cache_build_nat], 0
    jmp  .sized
.natural_bytes:
    mov  rax, r8
.sized:
    mov  rbp, rax                       ; requested bytes
    cmp  rax, IMG_CACHE_BUDGET
    ja   .release_oom
.ensure:
    cmp  dword [rel img_cache_count], IMG_CACHE_MAX
    jae  .evict
    mov  rax, [rel img_cache_bytes]
    add  rax, rbp
    cmp  rax, IMG_CACHE_BUDGET
    jbe  .space
.evict:
    call img_cache_evict_lru
    test eax, eax
    jnz  .release_oom                  ; no room without losing the live desktop
    jmp  .ensure
.space:
    mov  rsi, [rel img_cache_base]
    add  rsi, [rel img_cache_bytes]
    mov  [rel img_cache_ret_ptr], rsi
    mov  rdi, r15
    mov  edx, [rel img_cache_build_nw]
    mov  ecx, [rel img_cache_build_nh]
    mov  r8d, r13d
    mov  r9d, r14d
    cmp  byte [rel img_cache_build_nat], 0
    je   .scale
    mov  r8d, edx                       ; natural: an exact copy of the decoded raster
    mov  r9d, ecx
.scale:
    call img_cache_scale
    call img_output_release
    cmp  qword [rel img_active_out], 0
    jne  .oom                          ; retirement lost LIFO: publish no entry
    mov  edi, [rel img_cache_count]
    call img_cache_entry_ptr
    mov  [rax + ICE_ASSET], r12
    mov  [rax + ICE_W], r13d
    mov  [rax + ICE_H], r14d
    mov  edx, [rel img_cache_build_nw]
    mov  [rax + ICE_NW], edx
    mov  [rel img_cache_ret_nw], edx
    mov  edx, [rel img_cache_build_nh]
    mov  [rax + ICE_NH], edx
    mov  [rel img_cache_ret_nh], edx
    mov  rdx, [rel img_cache_bytes]
    mov  [rax + ICE_OFF], rdx
    mov  [rax + ICE_BYTES], rbp
    movzx edx, byte [rel img_cache_build_nat]
    mov  [rax + ICE_NAT], edx
    mov  [rel img_cache_ret_nat], dl
    inc  qword [rel img_cache_tick]
    mov  rdx, [rel img_cache_tick]
    mov  [rax + ICE_TICK], rdx
    inc  dword [rel img_cache_count]
    add  [rel img_cache_bytes], rbp
    xor  eax, eax
    jmp  .success_return
.release_oom:
    call img_output_release
.oom:
    mov  eax, IMG_E_OOM
    jmp  .status_return
.success_return:
    xor  eax, eax
.status_return:
    mov  [rel img_cache_ret_status], eax
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbp
    mov  eax, [rel img_cache_ret_status]
    mov  rbx, [rel img_cache_ret_ptr]
    mov  ecx, [rel img_cache_ret_nw]
    mov  edx, [rel img_cache_ret_nh]
    ret

; RCQ-27: paint a NATURAL raster (a hit with img_cache_ret_nat=1; its size is
; img_cache_ret_nw x _nh from that lookup) as its scaled output. RDI=raster,
; ESI/EDX=output w/h, ECX/EAX=source origin inside the output, R8D..R11D=screen
; rect. Pixels equal img_cache_scale's: column floor(dx*nw/out_w), row
; floor(dy*nh/out_h). Rows that map to the same source row go out as ONE blit
; with stride 0. Paint-safe: no decode, no allocation. -> EAX 0 painted, 1 refused
; (no scratch, too wide, or a rect outside the output); the caller paints its fill.
img_cache_nat_blit:
    mov  [rel img_nb_sy0], eax
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
    mov  [rel img_nb_ow], esi
    mov  [rel img_nb_oh], edx
    mov  [rel img_nb_sx0], ecx
    mov  [rel img_nb_x], r8d
    mov  [rel img_nb_y], r9d
    mov  [rel img_nb_w], r10d
    mov  [rel img_nb_h], r11d
    mov  esi, esi                       ; zero-extend: compared in 64 bits below
    mov  edx, edx
    mov  rbx, rdi
    mov  r13, [rel img_cache_scratch]
    test r13, r13
    jz   .refuse
    test rbx, rbx
    jz   .refuse
    test esi, esi
    jz   .refuse
    test edx, edx
    jz   .refuse
    cmp  esi, [rel img_cache_scratch_px]
    ja   .refuse
    cmp  dword [rel img_cache_ret_nw], 0
    je   .refuse
    cmp  dword [rel img_cache_ret_nh], 0
    je   .refuse
    mov  eax, ecx                       ; sx0 + w <= out_w, in 64 bits
    mov  r10d, r10d
    add  rax, r10
    cmp  rax, rsi
    ja   .refuse
    mov  eax, [rel img_nb_sy0]
    mov  r11d, r11d
    add  rax, r11
    cmp  rax, rdx
    ja   .refuse
    mov  eax, [rel img_cache_ret_nw]
    cmp  eax, [rel img_cache_map_nw]
    jne  .map
    cmp  esi, [rel img_cache_map_ow]
    je   .mapped
.map:
    xor  ecx, ecx
.map_col:
    cmp  ecx, [rel img_nb_ow]
    jae  .map_done
    mov  eax, ecx
    mul  dword [rel img_cache_ret_nw]
    div  dword [rel img_nb_ow]
    mov  [r13 + rcx*4], eax
    inc  ecx
    jmp  .map_col
.map_done:
    mov  eax, [rel img_cache_ret_nw]
    mov  [rel img_cache_map_nw], eax
    mov  eax, [rel img_nb_ow]
    mov  [rel img_cache_map_ow], eax
.mapped:
    mov  r12d, [rel img_cache_scratch_px]
    lea  r12, [r13 + r12*4]             ; row buffer
    xor  ebp, ebp
.row:
    cmp  ebp, [rel img_nb_h]
    jae  .done
    mov  eax, [rel img_nb_sy0]
    add  eax, ebp
    mul  dword [rel img_cache_ret_nh]
    div  dword [rel img_nb_oh]
    mov  r14d, eax                      ; sy
    mul  dword [rel img_cache_ret_nw]
    lea  rsi, [rbx + rax*4]             ; source row
    mov  edx, [rel img_nb_sx0]
    lea  rdx, [r13 + rdx*4]
    xor  ecx, ecx
.expand:
    cmp  ecx, [rel img_nb_w]
    jae  .run
    mov  eax, [rdx + rcx*4]
    mov  eax, [rsi + rax*4]
    mov  [r12 + rcx*4], eax
    inc  ecx
    jmp  .expand
.run:
    mov  r15d, 1
.run_next:
    lea  eax, [rbp + r15]
    cmp  eax, [rel img_nb_h]
    jae  .blit
    add  eax, [rel img_nb_sy0]
    mul  dword [rel img_cache_ret_nh]
    div  dword [rel img_nb_oh]
    cmp  eax, r14d
    jne  .blit
    inc  r15d
    jmp  .run_next
.blit:
    mov  rdi, r12
    xor  esi, esi                       ; stride 0: every row of the run is this row
    mov  r8d, [rel img_nb_x]
    mov  r9d, [rel img_nb_y]
    add  r9d, ebp
    mov  r10d, [rel img_nb_w]
    mov  r11d, r15d
    call fb_blit_rgba
    add  ebp, r15d
    jmp  .row
.done:
    xor  eax, eax
    jmp  .return
.refuse:
    mov  eax, 1
.return:
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
    ret

cmd_verb_imgcache:
    call cmd_handler_prologue
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    call img_out_reset
    lea  rdi, [rel str_imgcache_head]
    call img_out_str
    mov  edi, [rel img_cache_count]
    call img_out_dec
    lea  rdi, [rel str_imgcache_bytes]
    call img_out_str
    mov  rdi, [rel img_cache_bytes]
    call img_out_dec
    lea  rdi, [rel str_imgcache_hits]
    call img_out_str
    mov  rdi, [rel img_cache_hits]
    call img_out_dec
    lea  rdi, [rel str_imgcache_misses]
    call img_out_str
    mov  rdi, [rel img_cache_misses]
    call img_out_dec
    lea  rdi, [rel str_imgcache_evictions]
    call img_out_str
    mov  rdi, [rel img_cache_evictions]
    call img_out_dec
    xor  ebx, ebx
.entry:
    cmp  ebx, [rel img_cache_count]
    jae  .ready
    mov  edi, ebx
    call img_cache_entry_ptr
    mov  r12, rax
    cmp  qword [r12 + ICE_ASSET], 0
    je   .next                         ; retired tombstone has no asset/name
    lea  rdi, [rel str_imgcache_entry]
    call img_out_str
    mov  rax, [r12 + ICE_ASSET]
    mov  rdi, [rax + IMG_ASSET_NAME]
    call img_out_str
    lea  rdi, [rel str_imgcache_colon]
    call img_out_str
    mov  edi, [r12 + ICE_W]
    call img_out_dec
    lea  rdi, [rel str_imgcache_x]
    call img_out_str
    mov  edi, [r12 + ICE_H]
    call img_out_dec
    lea  rdi, [rel str_imgcache_colon]
    call img_out_str
    mov  rdi, [r12 + ICE_BYTES]
    call img_out_dec
.next:
    inc  ebx
    jmp  .entry
.ready:
    mov  byte [rel img_out_ready], 1
    mov  qword [r13 + RSP_CODE], CMDE_OK
    mov  qword [r13 + RSP_VAL], 0
    pop  r13
    pop  r12
    pop  rbx
    ret

img_cache_selftest:
    push rbx
    push r12
    push r13
    cmp  qword [rel img_cache_base], 0
    je   .fail
    cmp  byte [rel img_cache_reg_ok], 1
    jne  .fail
    xor  edi, edi
    call img_asset_row
    mov  r12, rax
    mov  rdi, r12
    mov  esi, 16
    mov  edx, 16
    call img_cache_bind
    test eax, eax
    jnz  .fail
    mov  rdi, r12
    mov  esi, 16
    mov  edx, 16
    call img_cache_bind
    test eax, eax
    jnz  .fail
    cmp  qword [rel img_cache_misses], 1
    jne  .fail
    cmp  qword [rel img_cache_hits], 1
    jne  .fail
    mov  edi, 8                         ; bad_crc: refusal must store nothing
    call img_asset_row
    mov  rdi, rax
    mov  esi, 48
    mov  edx, 32
    call img_cache_bind
    cmp  eax, IMG_E_CRC
    jne  .fail
    cmp  dword [rel img_cache_count], 1
    jne  .fail
    mov  r13d, 17
.fill:
    mov  rdi, r12
    mov  esi, r13d
    mov  edx, r13d
    call img_cache_bind
    test eax, eax
    jnz  .fail
    inc  r13d
    cmp  r13d, 25
    jb   .fill
    cmp  dword [rel img_cache_count], IMG_CACHE_MAX
    jne  .fail
    cmp  qword [rel img_cache_evictions], 1
    jb   .fail
    lea  rdi, [rel str_imgcache_marker]
    call serial_string
    call img_cache_reset
    jmp  .out
.fail:
    lea  rdi, [rel str_imgcache_fail]
    call serial_string
    call img_cache_reset
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

img_cache_init:
    push rbx
    call img_assets_init                 ; form/image boot path precedes command_udp_init
    mov  edi, IMG_CACHE_BUDGET
    call kmalloc_model                    ; 24 MiB cannot fit the 16 MiB ordinary heap
    mov  [rel img_cache_base], rax
    ; RCQ-27: column map + row buffer, 4 B each per column of the BOOT mode (RES only
    ; shrinks it). Refused or no display: natural rasters are off, today's rule holds.
    mov  ebx, [rel fb_width]
    test ebx, ebx
    jz   .no_scratch
    cmp  ebx, IMG_CACHE_DIM_MAX
    ja   .no_scratch
    lea  edi, [rbx*8]
    call kmalloc_model
    test rax, rax
    jz   .no_scratch
    mov  [rel img_cache_scratch], rax
    mov  [rel img_cache_scratch_px], ebx
.no_scratch:
    call img_cache_reset
    lea  rdi, [rel str_verb_imgcache]
    lea  rsi, [rel cmd_verb_imgcache]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9                        ; proposed public T0 read
    call command_register_verb
    test eax, eax
    js   .registered
    mov  byte [rel img_cache_reg_ok], 1
.registered:
    call fb_blit_rgba_declare
    call img_cache_selftest
    pop  rbx
    ret

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_gui_img_img_cache_0 0
align 8
img_cache_entries: times (IMG_CACHE_MAX*ICE_SZ) db 0
img_cache_base: dq 0
img_cache_bytes: dq 0
img_cache_tick: dq 0
img_cache_hits: dq 0
img_cache_misses: dq 0
img_cache_evictions: dq 0
img_cache_ret_ptr: dq 0
img_cache_ret_status: dd 0
img_cache_ret_nw: dd 0
img_cache_ret_nh: dd 0
img_cache_build_nw: dd 0
img_cache_build_nh: dd 0
img_cache_count: dd 0
img_cache_reg_ok: db 0
align 8
img_cache_pin_asset: dq 0
img_cache_pin_w: dd 0
img_cache_pin_h: dd 0
align 8
img_cache_scratch: dq 0                 ; RCQ-27: map[px] dd, then row[px] dd
img_cache_scratch_px: dd 0
img_cache_map_nw: dd 0                  ; the map's key; nw 0 never matches a raster
img_cache_map_ow: dd 0
img_nb_ow: dd 0
img_nb_oh: dd 0
img_nb_sx0: dd 0
img_nb_sy0: dd 0
img_nb_x: dd 0
img_nb_y: dd 0
img_nb_w: dd 0
img_nb_h: dd 0
img_cache_ret_nat: db 0
img_cache_build_nat: db 0

str_verb_imgcache: db "IMGCACHE",0
str_imgcache_head: db " IMGCACHE n=",0
str_imgcache_bytes: db " bytes=",0
str_imgcache_hits: db " hits=",0
str_imgcache_misses: db " misses=",0
str_imgcache_evictions: db " evictions=",0
str_imgcache_entry: db " entry=",0
str_imgcache_colon: db ":",0
str_imgcache_x: db "x",0
str_imgcache_marker: db "[PAOS64] M6 img: decode-once cache selftest (bind decodes once, paint is blit-only, LRU evicts, refusal stores nothing) [gui.img.cache]",13,10,0
str_imgcache_fail: db "[PAOS64] M6 img: decode-once cache selftest FAILED [marker withheld]",13,10,0
%endmacro
WDATA_DEFER WDATA_gui_img_img_cache_0
