;; MODULE gui/shared_surface_portal
;; LAYER 6
;; EXPORTS shared_surface_portal_kat, ssp_register, ssp_create, ssp_attach, ssp_validate, ssp_make_handle, ssp_present, ssp_damage, ssp_close, ssp_record
;; IMPORTS boot/serial
;; CAPS
;; OWNER saga:game_library
; ============================================================================
; Task3456 — Game-library L0: one GUI-owned shared surface/portal widget type
; and one slot-14 handle ABI shared by guest, video, RDP, and game producers.
;
; The type owns bounded dimensions, BGRX pixel format, source stride, clipping,
; producer/consumer identity, lifecycle, damage/present, and inspectable
; semantic state. Registration is additive (a distinct widget type id recorded
; in a self-owned bounded registry — no existing type is mutated). Consumers
; attach by an opaque generation-bearing handle; a stale/out-of-range/zero
; handle FAILS CLOSED. This slice reports honest current values only; it does
; not pretend scaling/compositing pipelines exist beyond present/damage counts.
;
; Position-independent: all state via [rel]; no dq <symbol>. Self-contained so
; the metal candidate builds small from a pre-crasher base (Task3250 pattern).
; ============================================================================

SSP_MAX             equ 8                 ; bounded surface table
SSP_SLOT_ABI        equ 14                ; slot-14 handle ABI id (shared attach seam)
SSP_HANDLE_IDX_BITS equ 8
SSP_HANDLE_IDX_MASK equ 0xFF
SSP_GEN_MAX         equ 0x00FFFFFF
SSP_W_MAX           equ 4096
SSP_H_MAX           equ 4096
SSP_FMT_BGRX        equ 0x34325258        ; 'XR24' BGRX 32bpp tag (honest fixed format)
SSP_WIDGET_TYPE_ID  equ 0x00535350        ; 'SSP' additive widget type id

; producer/consumer identity classes (opaque to the surface; recorded honestly)
SSP_ID_NONE   equ 0
SSP_ID_GUEST  equ 1
SSP_ID_VIDEO  equ 2
SSP_ID_RDP    equ 3
SSP_ID_GAME   equ 4

; lifecycle
SSP_LIFE_FREE   equ 0
SSP_LIFE_OPEN   equ 1
SSP_LIFE_CLOSED equ 2

struc ssp_surface
  .generation:  resd 1            ; 0 = free/invalid (generation zero is never issued)
  .producer:    resd 1
  .consumer:    resd 1
  .width:       resd 1
  .height:      resd 1
  .stride:      resd 1            ; bytes/row = width*4 (BGRX)
  .clip_w:      resd 1            ; clip <= width
  .clip_h:      resd 1            ; clip <= height
  .format:      resd 1
  .lifecycle:   resd 1
  .damage:      resd 1            ; 1 = damaged-since-present
  .present_ct:  resd 1
endstruc

; ssp_make_handle(EDI=index, ESI=generation) -> EAX handle
ssp_make_handle:
    mov  eax, esi
    shl  eax, SSP_HANDLE_IDX_BITS
    or   eax, edi
    ret

; ssp_record(ECX=index) -> RAX = record ptr (no bounds check; internal)
ssp_record:
    mov  eax, ecx
    imul eax, ssp_surface_size
    lea  rdx, [rel ssp_table]
    add  rax, rdx
    ret

; ssp_validate(EDI=handle) -> RAX=record, ECX=index, CF=0 on OK.
;   Fail closed (CF=1) on: zero handle, index >= SSP_MAX, generation mismatch,
;   or a non-OPEN lifecycle. No partial state is exposed on failure.
ssp_validate:
    test edi, edi
    jz   .bad                     ; handle 0 = invalid/unbound sentinel
    mov  ecx, edi
    and  ecx, SSP_HANDLE_IDX_MASK
    cmp  ecx, SSP_MAX
    jae  .bad
    mov  r8d, edi
    shr  r8d, SSP_HANDLE_IDX_BITS ; generation carried by the handle
    call ssp_record               ; RAX=record for ECX
    cmp  dword [rax + ssp_surface.generation], r8d
    jne  .bad
    cmp  dword [rax + ssp_surface.lifecycle], SSP_LIFE_OPEN
    jne  .bad
    clc
    ret
.bad:
    stc
    ret

%ifidn RCQ37_VIDEO_BUILT,1
; Named private validation seam. Public pointer-free 48B record unchanged.
; EDI=handle ESI=width EDX=height -> CF=0 actual VIDEO/XR24 full-clip record.
; No caller record or generation claim can manufacture a surface.
;; EXPORTS ssp_validate_video
ssp_validate_video:
    push rsi
    push rdx
    call ssp_validate
    pop rdx
    pop rsi
    jc .bad
    cmp dword [rax+ssp_surface.producer],SSP_ID_VIDEO
    jne .bad
    cmp dword [rax+ssp_surface.consumer],SSP_ID_VIDEO
    jne .bad
    cmp dword [rax+ssp_surface.format],SSP_FMT_BGRX
    jne .bad
    cmp [rax+ssp_surface.width],esi
    jne .bad
    cmp [rax+ssp_surface.height],edx
    jne .bad
    cmp [rax+ssp_surface.clip_w],esi
    jne .bad
    cmp [rax+ssp_surface.clip_h],edx
    jne .bad
    shl esi,2
    cmp [rax+ssp_surface.stride],esi
    jne .bad
    clc
    ret
.bad:
    stc
    ret
%endif

; ssp_create(EDI=producer, ESI=width, EDX=height) -> EAX handle (0 = refused).
;   Bounds: width/height in (0, MAX]; producer must be a known class. Finds a
;   free slot, bumps its generation (never zero), fixes BGRX + stride, opens it.
ssp_create:
    push rbx
    push r12
    push r13
    mov  r12d, edi                ; producer
    mov  r13d, esi                ; width
    mov  ebx, edx                 ; height
    cmp  r12d, SSP_ID_GAME        ; producer class 1..4
    ja   .refuse
    test r12d, r12d
    jz   .refuse
    test r13d, r13d
    jz   .refuse
    cmp  r13d, SSP_W_MAX
    ja   .refuse
    test ebx, ebx
    jz   .refuse
    cmp  ebx, SSP_H_MAX
    ja   .refuse
    xor  ecx, ecx
.find:
    cmp  ecx, SSP_MAX
    jae  .refuse
    call ssp_record
    cmp  dword [rax + ssp_surface.lifecycle], SSP_LIFE_OPEN
    je   .next
    ; free/closed slot -> claim it. Bump generation (wrap 1..GEN_MAX, never 0).
    mov  edx, [rax + ssp_surface.generation]
    inc  edx
    cmp  edx, SSP_GEN_MAX
    jbe  .gen_ok
    mov  edx, 1
.gen_ok:
    mov  [rax + ssp_surface.generation], edx
    mov  [rax + ssp_surface.producer], r12d
    mov  dword [rax + ssp_surface.consumer], SSP_ID_NONE
    mov  [rax + ssp_surface.width], r13d
    mov  [rax + ssp_surface.height], ebx
    mov  r8d, r13d
    shl  r8d, 2                   ; stride = width*4 (BGRX)
    mov  [rax + ssp_surface.stride], r8d
    mov  [rax + ssp_surface.clip_w], r13d
    mov  [rax + ssp_surface.clip_h], ebx
    mov  dword [rax + ssp_surface.format], SSP_FMT_BGRX
    mov  dword [rax + ssp_surface.lifecycle], SSP_LIFE_OPEN
    mov  dword [rax + ssp_surface.damage], 0
    mov  dword [rax + ssp_surface.present_ct], 0
    ; handle = (generation<<idxbits)|index
    mov  edi, ecx
    mov  esi, edx
    call ssp_make_handle
    jmp  .out
.next:
    inc  ecx
    jmp  .find
.refuse:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; ssp_attach(EDI=handle, ESI=consumer) -> EAX 1 ok / 0 fail (fail closed).
ssp_attach:
    push rsi
    call ssp_validate
    pop  rsi
    jc   .fail
    cmp  esi, SSP_ID_GAME
    ja   .fail
    test esi, esi
    jz   .fail
    mov  [rax + ssp_surface.consumer], esi
    mov  eax, 1
    ret
.fail:
    xor  eax, eax
    ret

; ssp_damage(EDI=handle) -> EAX 1/0 ; ssp_present(EDI=handle) -> EAX 1/0
ssp_damage:
    call ssp_validate
    jc   .fail
    mov  dword [rax + ssp_surface.damage], 1
    mov  eax, 1
    ret
.fail:
    xor  eax, eax
    ret
ssp_present:
    call ssp_validate
    jc   .fail
    mov  dword [rax + ssp_surface.damage], 0
    inc  dword [rax + ssp_surface.present_ct]
    mov  eax, 1
    ret
.fail:
    xor  eax, eax
    ret

; ssp_close(EDI=handle) -> EAX 1/0. Retires the surface; the handle goes stale.
ssp_close:
    call ssp_validate
    jc   .fail
    mov  dword [rax + ssp_surface.lifecycle], SSP_LIFE_CLOSED
    mov  dword [rax + ssp_surface.consumer], SSP_ID_NONE
    mov  eax, 1
    ret
.fail:
    xor  eax, eax
    ret

; ssp_register — additive registration of the surface/portal widget type into
; the self-owned type registry (no existing widget type mutated). Idempotent.
ssp_register:
    mov  dword [rel ssp_registered_type], SSP_WIDGET_TYPE_ID
    mov  dword [rel ssp_registered_abi], SSP_SLOT_ABI
    ret

; ----------------------------------------------------------------------------
; shared_surface_portal_kat — boot KAT. Proves: register; create (BGRX+stride);
; attach by handle; damage/present accounting; inspectable semantic state; and
; three HOSTILE handles fail closed (zero, out-of-range index, stale generation).
; Emits [game.library.shared_surface_portal_widget] only on a full pass.
; ----------------------------------------------------------------------------
shared_surface_portal_kat:
    push rbx
    push r12
    call ssp_register
    cmp  dword [rel ssp_registered_type], SSP_WIDGET_TYPE_ID
    jne  .fail
    cmp  dword [rel ssp_registered_abi], SSP_SLOT_ABI
    jne  .fail
    ; create a 640x360 game surface
    mov  edi, SSP_ID_GAME
    mov  esi, 640
    mov  edx, 360
    call ssp_create
    test eax, eax
    jz   .fail
    mov  ebx, eax                 ; keep the live handle
    ; semantic state: stride = 640*4, format BGRX, lifecycle OPEN
    mov  edi, ebx
    call ssp_validate
    jc   .fail
    cmp  dword [rax + ssp_surface.stride], 640*4
    jne  .fail
    cmp  dword [rax + ssp_surface.format], SSP_FMT_BGRX
    jne  .fail
    cmp  dword [rax + ssp_surface.width], 640
    jne  .fail
    ; attach an RDP consumer by the opaque handle
    mov  edi, ebx
    mov  esi, SSP_ID_RDP
    call ssp_attach
    test eax, eax
    jz   .fail
    ; damage then present -> damage clears, present_ct advances
    mov  edi, ebx
    call ssp_damage
    test eax, eax
    jz   .fail
    mov  edi, ebx
    call ssp_present
    test eax, eax
    jz   .fail
    mov  edi, ebx
    call ssp_validate
    jc   .fail
    cmp  dword [rax + ssp_surface.damage], 0
    jne  .fail
    cmp  dword [rax + ssp_surface.present_ct], 1
    jne  .fail
    cmp  dword [rax + ssp_surface.consumer], SSP_ID_RDP
    jne  .fail
    ; --- hostile handles must fail closed ---
    xor  edi, edi                 ; zero handle
    call ssp_validate
    jnc  .fail
    mov  edi, 0x000000FE          ; index 0xFE >= SSP_MAX (out of range)
    call ssp_validate
    jnc  .fail
    ; stale generation: same index as ebx but generation+1
    mov  eax, ebx
    mov  ecx, eax
    and  ecx, SSP_HANDLE_IDX_MASK ; index
    shr  eax, SSP_HANDLE_IDX_BITS
    inc  eax                      ; wrong generation
    mov  edi, ecx
    mov  esi, eax
    call ssp_make_handle
    mov  edi, eax
    call ssp_validate
    jnc  .fail
    ; all invariants held -> emit the earned marker
    lea  rdi, [rel str_ssp_kat_ok]
    call serial_string
    pop  r12
    pop  rbx
    ret
.fail:
    lea  rdi, [rel str_ssp_kat_fail]
    call serial_string
    pop  r12
    pop  rbx
    ret

; --- shared_surface_portal data (in-image; pre-W^X is fine, all RW+NX) ---
ssp_table:            times SSP_MAX*ssp_surface_size db 0
ssp_registered_type:  dd 0
ssp_registered_abi:   dd 0
str_ssp_kat_ok:   db "[PAOS64] game-library L0: shared surface/portal widget type + slot-14 handle ABI (BGRX/stride/clip/lifecycle/damage/present, hostile-handle fail-closed) PASS [game.library.shared_surface_portal_widget]", 13, 10, 0
str_ssp_kat_fail: db "[PAOS64] game-library L0: shared surface/portal KAT FAIL [game.library.shared_surface_portal_widget.fail]", 13, 10, 0
