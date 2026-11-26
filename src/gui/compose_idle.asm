;; MODULE gui/compose_idle
;; LAYER 6
;; EXPORTS fb_compose_intersect, fb_compose_take, fb_compose_clip_active, fb_compose_x0, fb_compose_y0, fb_compose_x1, fb_compose_y1, fb_compose_seen, fb_compose_done, fb_compose_budget, fb_compose_blocked, fb_compose_prepaid
;; IMPORTS
;; CAPS
;; OWNER saga:gui
; Raster admission for an idle composition replay. A pass enters a small
; logical clip tile, calls the ordinary painters, and unwinds them completely.
; Only a scalar operation cursor crosses turns, never a painter stack, widget
; pointer, decoded-image pointer or open batch. The job owner must restart the
; cursor when its authority, geometry or logical redraw generation changes.
;
; This module does not activate a job or service commands. In particular it
; must never turn a raster operation into nested command dispatch. The idle
; owner, after all paint frames have returned, is the only continuation seam.

; R8D/R9D signed x/y; R10D/R11D signed positive w/h. Intersect with the
; current tile in signed64 before narrowing. EAX/ECX/EDX are scratch. CF=1
; means empty; otherwise the four coordinates describe the intersection.
; Disabled outside an idle replay, including the boot and primitive KATs.
fb_compose_intersect:
    cmp byte [rel fb_compose_clip_active],0
    je .unchanged
    test r10d,r10d
    jle .empty
    test r11d,r11d
    jle .empty
    movsxd rax,r8d
    movsxd rcx,r10d
    add rcx,rax
    mov edx,[rel fb_compose_x0]
    cmp rax,rdx
    cmovl rax,rdx
    mov edx,[rel fb_compose_x1]
    cmp rcx,rdx
    cmovg rcx,rdx
    sub rcx,rax
    jle .empty
    mov r8d,eax
    mov r10d,ecx
    movsxd rax,r9d
    movsxd rcx,r11d
    add rcx,rax
    mov edx,[rel fb_compose_y0]
    cmp rax,rdx
    cmovl rax,rdx
    mov edx,[rel fb_compose_y1]
    cmp rcx,rdx
    cmovg rcx,rdx
    sub rcx,rax
    jle .empty
    mov r9d,eax
    mov r11d,ecx
.unchanged:
    clc
    ret
.empty:
    xor r10d,r10d
    xor r11d,r11d
    stc
    ret

; Admit one already-intersected raster operation. Preserve all registers;
; CF=1 means do no pixel work on this replay. Earlier completed operations
; are skipped, so a later overlay resumes over the pixels already composed.
; Four units per logical pixel reserve room for source mapping/expansion and
; alpha composition as well as the final store. An operation that does not
; fit stops ALL later writes in this pass; it is never silently dropped.
; The owner resets seen/budget/blocked each turn and retains only done.
fb_compose_take:
    cmp byte [rel fb_compose_prepaid],0
    jne .admit
    cmp byte [rel fb_compose_clip_active],0
    je .admit
    push rax
    push rcx
    inc qword [rel fb_compose_seen]
    jz .blocked
    mov rax,[rel fb_compose_seen]
    cmp rax,[rel fb_compose_done]
    jbe .skip
    cmp byte [rel fb_compose_blocked],0
    jne .skip
    mov eax,r10d
    mov ecx,r11d
    imul rax,rcx
    ; A corrupt oversized tile must not wrap its cost into a small admission.
    cmp rax,200
    ja .blocked
    shl rax,2
    cmp rax,[rel fb_compose_budget]
    ja .blocked
    sub [rel fb_compose_budget],rax
    mov rax,[rel fb_compose_seen]
    mov [rel fb_compose_done],rax
    pop rcx
    pop rax
.admit:
    clc
    ret
.blocked:
    mov byte [rel fb_compose_blocked],1
.skip:
    pop rcx
    pop rax
    stc
    ret

%include "core/abi/wdata.inc"
%macro WDATA_gui_compose_idle 0
align 8
fb_compose_seen: dq 0
fb_compose_done: dq 0
fb_compose_budget: dq 0
fb_compose_x0: dd 0
fb_compose_y0: dd 0
fb_compose_x1: dd 0
fb_compose_y1: dd 0
fb_compose_clip_active: db 0
fb_compose_blocked: db 0
; An admitted image operation pays once for mapping, expansion and blending.
; Nested blits still clip, but must not spend or advance the operation twice.
; This byte is scoped entirely inside one native image call and is zero at
; every idle boundary. It is never a cross-turn painter continuation.
fb_compose_prepaid: db 0
%endmacro
WDATA_DEFER WDATA_gui_compose_idle
