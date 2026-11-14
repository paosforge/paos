;; MODULE gui/lock_fade
;; LAYER 6
;; EXPORTS lock_fade_begin, lock_fade_tick, lock_fade_row, lock_fade_row2, lock_fade_alpha, lock_fade_active
;; IMPORTS gui/window, gui/lock_screen, sec/session, boot/header
;; CAPS
;; OWNER saga:gui
; One normal boot sign-in fade. The existing input-live hook starts it; idle
; ticks after physical input advance it. No wait, firmware, allocation or login
; decision. The composed shadow stays exact; only scanout copies are shaded.
; Start at 1/4 brightness so no intentionally black frame or hidden input box.
; Lab keeps exact diagnostic pixels. Completion/unlock restores exact pixels.
%ifndef PAOS_PUBLICITY_LAB_PROFILE
%define PAOS_PUBLICITY_LAB_PROFILE 0
%endif
LOCK_FADE_MS equ 160
LOCK_FADE_STEP_MS equ 16
lock_fade_begin:
%if !PAOS_PUBLICITY_LAB_PROFILE
    push rax
    push rcx
    push rdx
    cmp byte [rel lock_fade_started],0
    jne .out
    mov byte [rel lock_fade_started],1
    cmp byte [rel session_locked],SESSION_LOCKED
    jne .out
    cmp byte [rel lock_composition_ok],1
    jne .out
    cmp qword [rel fb_scanout_base],0
    je .out
    mov rax,[rel fb_shadow_base]
    test rax,rax
    jz .out
    cmp rax,[rel fb_base]
    jne .out
    call boot_ms_now
    test rax,rax
    jz .out                            ; unavailable clock: exact immediate present
    mov [rel lock_fade_start_ms],rax
    mov [rel lock_fade_last_ms],rax
    mov word [rel lock_fade_alpha],64
    mov byte [rel lock_fade_active],1
.out:
    pop rdx
    pop rcx
    pop rax
%endif
    ret

; Called after the existing keyboard/pointer consumers, once per outer pass.
; No frame count controls duration; delayed passes go straight to current time.
lock_fade_tick:
%if !PAOS_PUBLICITY_LAB_PROFILE
    push rax
    push rcx
    push rdx
    cmp byte [rel lock_fade_active],1
    jne .out
    cmp byte [rel session_locked],SESSION_LOCKED
    jne .finish
    cmp byte [rel lock_composition_ok],1
    jne .finish
    cmp byte [rel fb_present_boot_hold],0
    jne .out
    call boot_ms_now
    cmp rax,[rel lock_fade_last_ms]
    jb .finish
    mov rcx,rax
    sub rax,[rel lock_fade_last_ms]
    cmp rax,LOCK_FADE_STEP_MS
    jb .out
    mov [rel lock_fade_last_ms],rcx
    sub rcx,[rel lock_fade_start_ms]
    cmp rcx,LOCK_FADE_MS
    jae .finish
    imul rax,rcx,192
    xor edx,edx
    mov ecx,LOCK_FADE_MS
    div rcx
    add eax,64
    mov [rel lock_fade_alpha],ax
    call fb_present_all
    jmp .out
.finish:
    mov word [rel lock_fade_alpha],256
    mov byte [rel lock_fade_active],0
    call fb_present_all
    ; Deferred DISPLAY/readback report describes the final exact composition.
    call lock_screen_boot_release
.out:
    pop rdx
    pop rcx
    pop rax
%endif
    ret

; RSI=source, RDI=scanout row, ECX=logical pixels; row2 R15=physical row bytes.
; The caller already clipped/admitted the shadow and destination. Preserve all
; GPR and SIMD registers used here; SIMD2 byte->word multiplication is exact
; floor(channel*alpha/256). RGB/BGR share the same per-byte operation.
%macro LOCK_FADE_ROW 1
    push rsi
    push rdi
    push rcx
    sub rsp,64
    movdqu [rsp],xmm0
    movdqu [rsp+16],xmm1
    movdqu [rsp+32],xmm2
    movdqu [rsp+48],xmm3
    pxor xmm3,xmm3
    movd xmm2,[rel lock_fade_alpha] ; next word is explicitly zero, below
    pshuflw xmm2,xmm2,0
    punpcklqdq xmm2,xmm2
.loop:
    cmp ecx,4
    jb .tail
    movdqu xmm0,[rsi]
    movdqa xmm1,xmm0
    punpcklbw xmm0,xmm3
    punpckhbw xmm1,xmm3
    pmullw xmm0,xmm2
    pmullw xmm1,xmm2
    psrlw xmm0,8
    psrlw xmm1,8
    packuswb xmm0,xmm1
%if %1 == 1
    movdqu [rdi],xmm0
    add rdi,16
%else
    movdqa xmm1,xmm0
    punpckldq xmm0,xmm0
    punpckhdq xmm1,xmm1
    movdqu [rdi],xmm0
    movdqu [rdi+16],xmm1
    movdqu [rdi+r15],xmm0
    movdqu [rdi+r15+16],xmm1
    add rdi,32
%endif
    add rsi,16
    sub ecx,4
    jmp .loop
.tail:
    test ecx,ecx
    jz .done
    movd xmm0,[rsi]
    punpcklbw xmm0,xmm3
    pmullw xmm0,xmm2
    psrlw xmm0,8
    packuswb xmm0,xmm0
%if %1 == 1
    movd [rdi],xmm0
    add rdi,4
%else
    punpckldq xmm0,xmm0
    movq [rdi],xmm0
    movq [rdi+r15],xmm0
    add rdi,8
%endif
    add rsi,4
    dec ecx
    jmp .tail
.done:
    movdqu xmm0,[rsp]
    movdqu xmm1,[rsp+16]
    movdqu xmm2,[rsp+32]
    movdqu xmm3,[rsp+48]
    add rsp,64
    pop rcx
    pop rdi
    pop rsi
    ret
%endmacro
lock_fade_row:
    LOCK_FADE_ROW 1
lock_fade_row2:
    LOCK_FADE_ROW 2

%include "core/abi/wdata.inc"
%macro WDATA_lock_fade 0
align 8
lock_fade_start_ms: dq 0
lock_fade_last_ms: dq 0
lock_fade_alpha: dw 256,0
lock_fade_started: db 0
lock_fade_active: db 0
%endmacro
WDATA_DEFER WDATA_lock_fade
