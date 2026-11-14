;; MODULE gui/app_package_card
;; LAYER 6
;; PURPOSE Native read-only package disclosure with bounded whole-document pagination.
;; EXPORTS app_package_card_init, app_package_card_open, app_package_card_tick, app_package_card_close
;; IMPORTS gui/app_package_disclosure, gui/widget, gui/window, gui/window_mgmt, svc/command, core/smp, dev/input/ps2, boot/gop
;; OWNER saga:app_package
;; CONTEXT: bsp_only
; Native composition API, not guest ingress. This component grants nothing;
; durable installation/confirmation belongs to the subsequent FS transaction.
PC_ROWS equ 24
PC_PAGE equ 24
PC_PREV equ 25
PC_NEXT equ 26
PC_CLOSE equ 27
PC_COUNT equ 28
PC_WIDTH equ 560
PC_Y equ 60                      ; its buttons sit clear of the install card's (SRC N4)
PC_HEIGHT equ 370

app_package_card_init:
    cmp byte [rel pkgcard_initialized],0
    jne .out
    mov rax,[rel wgt_key_filter]
    mov [rel pkgcard_prev_filter],rax
    lea rax,[rel pkgcard_key]
    mov [rel wgt_key_filter],rax
    mov rax,[rel wgt_click_hook]
    mov [rel pkgcard_prev_click],rax
    lea rax,[rel pkgcard_click]
    mov [rel wgt_click_hook],rax
    mov byte [rel pkgcard_initialized],1
.out:
    ret

; RDI actual checked candidate handle. EAX1 only after first fully built frame.
app_package_card_open:
    push rbx
    push r12
    push r13
    mov r12,rdi
    call smp_current_logical
    test eax,eax
    jnz .refuse
    cmp byte [rel cmd_in_dispatch],0
    jne .refuse
    call app_package_card_close
    mov rdi,r12
    call app_disclosure_open
    cmp eax,1
    jne .refuse
    mov [rel pkgcard_lines],edx
    cmp dword [rel fb_width],PC_WIDTH
    jb .fail
    mov eax,[rel fb_height]
    sub eax,TASKBAR_H
    cmp eax,PC_HEIGHT+PC_Y
    jb .fail
    call app_package_card_init
    lea rdi,[rel pkgcard_title]
    xor esi,esi
    mov edx,PC_Y
    mov ecx,PC_WIDTH
    mov r8d,PC_HEIGHT
    xor r9d,r9d
    call wmx_open_window
    cmp eax,WM_MAX
    jae .fail
    mov r12d,eax
    mov [rel pkgcard_slot],eax
    lea rcx,[rel wm_gen]
    mov eax,[rcx+r12*4]
    mov [rel pkgcard_gen],eax
    lea rcx,[rel wm_owner]
    mov qword [rcx+r12*8],WM_OWNER_CHROME
    mov edi,PC_COUNT
    call wgt_reserve_run
    test eax,eax
    js .fail
    mov [rel wgt_alloc_next],eax
    inc byte [rel wgt_paint_suspended]
    xor ebx,ebx
.widgets:
    mov edi,2
    cmp ebx,PC_PREV
    jb .type
    xor edi,edi
.type:
    mov esi,r12d
    call wgt_create
    cmp eax,-1
    je .fail_widgets
    lea rcx,[rel pkgcard_ids]
    mov [rcx+rbx*4],eax
    mov edi,eax
    call wgt_slot_ptr
    mov r13,rax
    mov dword [rax+WGI_FLAGS],1
    mov dword [rax+WGI_LAYER],0          ; as app_install: a reused row may keep an overlay's layer
    mov dword [rax+WGI_EDIT],WGT_EDIT_ASCII
    mov dword [rax+WGI_W],248
    mov dword [rax+WGI_H],18
    mov dword [rax+WGI_X],8
    mov dword [rax+WGI_Y],28
    cmp ebx,PC_ROWS
    jae .footer
    mov eax,ebx
    cmp eax,12
    jb .first_col
    sub eax,12
    mov dword [r13+WGI_X],284
.first_col:
    imul eax,20
    add eax,GUI_TITLE_H+4                ; below the title strip, SEC 90177
    mov [r13+WGI_Y],eax
    jmp .next
.footer:
    mov dword [r13+WGI_Y],286
    cmp ebx,PC_PAGE
    je .next
    mov dword [r13+WGI_Y],320
    mov dword [r13+WGI_W],160
    mov dword [r13+WGI_H],30
    lea rsi,[rel pkgcard_previous]
    cmp ebx,PC_PREV
    je .text
    mov dword [r13+WGI_X],188
    lea rsi,[rel pkgcard_next]
    cmp ebx,PC_NEXT
    je .text
    mov dword [r13+WGI_X],368
    lea rsi,[rel pkgcard_close_text]
.text:
    lea rcx,[rel pkgcard_ids]
    mov edi,[rcx+rbx*4]
    call wgt_set_text
.next:
    lea rdx,[rel wm_x]                   ; widget rects are absolute, Q 90176
    mov eax,[rdx+r12*4]
    add [r13+WGI_X],eax
    lea rdx,[rel wm_y]
    mov eax,[rdx+r12*4]
    add [r13+WGI_Y],eax
    inc ebx
    cmp ebx,PC_COUNT
    jb .widgets
    mov dword [rel pkgcard_offset],0
    call pkgcard_render
    mov r13d,eax
    dec byte [rel wgt_paint_suspended]
    mov dword [rel wgt_alloc_next],-1
    cmp r13d,1
    jne .fail
    mov eax,[rel pkgcard_ids+PC_CLOSE*4]
    lea rcx,[rel wgt_focus_by_win]
    mov [rcx+r12*4],eax
    call wmx_draw_all
    mov eax,1
    jmp .out
.fail_widgets:
    dec byte [rel wgt_paint_suspended]
    mov dword [rel wgt_alloc_next],-1
.fail:
    call app_package_card_close
.refuse:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

pkgcard_scan:
    mov eax,[rel pkgcard_slot]
    cmp eax,WM_MAX
    jae .bad
    lea rcx,[rel wm_gen]
    mov edx,[rel pkgcard_gen]
    cmp [rcx+rax*4],edx
    jne .bad
    lea rcx,[rel wm_owner]
    cmp qword [rcx+rax*8],WM_OWNER_CHROME
    jne .bad
    lea rcx,[rel wm_title]
    lea rdx,[rel pkgcard_title]
    cmp [rcx+rax*8],rdx
    jne .bad
    lea rcx,[rel wm_state]
    cmp dword [rcx+rax*4],WM_FREE
    je .bad
    cmp dword [rcx+rax*4],WM_CLOSED
    je .bad
    ret
.bad:
    mov eax,-1
    ret

app_package_card_close:
    call smp_current_logical
    test eax,eax
    jnz .out
    cmp byte [rel cmd_in_dispatch],0
    jne .out
    jmp pkgcard_close_native
.out:
    ret
pkgcard_close_native:
    call pkgcard_scan
    mov dword [rel pkgcard_slot],-1
    mov byte [rel pkgcard_action],0
    mov dword [rel pkgcard_offset],0
    mov dword [rel pkgcard_lines],0
    cmp eax,-1
    je .data
    mov edi,eax
    call wmx_close_slot
.data:
    jmp app_disclosure_close

; Widget input frames queue navigation only. Effects stay at native idle depth0.
pkgcard_key:
    push rax
    push rdi
    call pkgcard_scan
    cmp eax,-1
    je .chain
    cmp eax,[rel wm_focus]
    jne .chain
    mov edi,[rsp]
    cmp edi,[rel wgt_count]
    jae .chain
    push rax
    call wgt_slot_ptr
    pop rcx
    cmp [rax+WGI_WIN],ecx
    jne .chain
    cmp byte [rel input_key_origin],KO_HUMAN
    jne .taken
    mov eax,[rsp+8]
    cmp eax,GUI_KEY_ESC
    je .close
    cmp eax,GUI_KEY_ENTER
    je .button
    cmp eax,' '
    jne .chain
.button:
    mov edi,[rsp]
    call pkgcard_action_for_id
    jmp .taken
.close:
    mov byte [rel pkgcard_action],3
.taken:
    pop rdi
    pop rax
    mov eax,1                       ; shared key filter: nonzero consumes
    ret
.chain:
    pop rdi
    pop rax
    cmp qword [rel pkgcard_prev_filter],0
    je .allow
    jmp [rel pkgcard_prev_filter]
.allow:
    xor eax,eax                     ; shared key filter: zero continues
    ret
pkgcard_action_for_id:
    cmp edi,[rel pkgcard_ids+PC_PREV*4]
    jne .next
    mov byte [rel pkgcard_action],1
    ret
.next:
    cmp edi,[rel pkgcard_ids+PC_NEXT*4]
    jne .close
    mov byte [rel pkgcard_action],2
    ret
.close:
    cmp edi,[rel pkgcard_ids+PC_CLOSE*4]
    jne .out
    mov byte [rel pkgcard_action],3
.out:
    ret
pkgcard_click:
    ; This card installs nothing, but closing it brings the install decision back under the pointer
    ; (SEC 89225), so a non-human press does nothing here. Paging is the owner's reading, gated with it.
    push rdi
    call pkgcard_scan
    cmp eax,-1
    je .chain
    cmp byte [rel wm_pointer_origin],WM_PTR_ORIGIN_HUMAN
    jne .chain
    cmp byte [rel wm_pointer_gesture_origin],WM_PTR_ORIGIN_HUMAN
    jne .chain
    mov edi,[rsp]
    call pkgcard_action_for_id
.chain:
    pop rdi
    cmp qword [rel pkgcard_prev_click],0
    je .out
    jmp [rel pkgcard_prev_click]
.out:
    ret

app_package_card_tick:
    call smp_current_logical
    test eax,eax
    jnz .out
    cmp byte [rel cmd_in_dispatch],0
    jne .out
    cmp dword [rel pkgcard_slot],-1
    je .out
    call pkgcard_scan
    cmp eax,-1
    je .close
    ; Refuse resize-induced hidden text; reopening reuses the same frozen bytes.
    lea rcx,[rel wm_w]
    cmp dword [rcx+rax*4],PC_WIDTH
    jne .close
    lea rcx,[rel wm_h]
    cmp dword [rcx+rax*4],PC_HEIGHT
    jne .close
    call pkgcard_widgets_current
    cmp eax,1
    jne .close
    call app_disclosure_current
    cmp eax,1
    jne .close
    movzx eax,byte [rel pkgcard_action]
    mov byte [rel pkgcard_action],0
    cmp eax,3
    je .close
    cmp eax,1
    je .prev
    cmp eax,2
    jne .out
    mov eax,[rel pkgcard_offset]
    add eax,PC_ROWS
    cmp eax,[rel pkgcard_lines]
    jae .out
    mov [rel pkgcard_offset],eax
    jmp .render
.prev:
    cmp dword [rel pkgcard_offset],0
    je .out
    sub dword [rel pkgcard_offset],PC_ROWS
.render:
    inc byte [rel wgt_paint_suspended]
    call pkgcard_render
    push rax
    dec byte [rel wgt_paint_suspended]
    pop rax
    cmp eax,1
    jne .close
    jmp wmx_draw_all
.close:
    jmp app_package_card_close
.out:
    ret

pkgcard_widgets_current:
    xor ecx,ecx
    lea r8,[rel pkgcard_ids]
.loop:
    mov eax,[r8+rcx*4]
    cmp eax,[rel wgt_count]
    jae .bad
    imul rax,WGI_SZ
    lea rdx,[rel wgt_tbl]
    add rax,rdx
    mov edx,[rel pkgcard_slot]
    cmp [rax+WGI_WIN],edx
    jne .bad
    mov edx,3
    cmp ecx,PC_PREV
    jb .type
    mov edx,1
.type:
    cmp [rax+WGI_TYPE],edx
    jne .bad
    inc ecx
    cmp ecx,PC_COUNT
    jb .loop
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Reuse all labels. Every page replacement is completed before paint resumes.
pkgcard_render:
    push rbx
    push r12
    call pkgcard_widgets_current
    cmp eax,1
    jne .bad
    xor ebx,ebx
.loop:
    lea rdi,[rel pkgcard_line]
    xor eax,eax
    mov ecx,5
    cld
    rep stosq
    mov edi,[rel pkgcard_offset]
    add edi,ebx
    cmp edi,[rel pkgcard_lines]
    jae .empty
    lea rsi,[rel pkgcard_line]
    mov edx,40
    call app_disclosure_line
    cmp eax,1
    jne .bad
.empty:
    lea rcx,[rel pkgcard_ids]
    mov edi,[rcx+rbx*4]
    mov r12d,edi
    call wgt_slot_ptr
    mov dword [rax+WGI_EDIT],WGT_EDIT_ASCII
    cmp qword [rel pkgcard_line+32],0
    je .text
    or dword [rax+WGI_EDIT],WGT_EDIT_WARNING
.text:
    mov edi,r12d
    lea rsi,[rel pkgcard_line]
    call wgt_set_text
    inc ebx
    cmp ebx,PC_ROWS
    jb .loop
    lea rdi,[rel pkgcard_line]
    mov rsi,[rel pkgcard_page_word]
    mov [rdi],rsi
    add rdi,5
    mov eax,[rel pkgcard_offset]
    xor edx,edx
    mov ecx,PC_ROWS
    div ecx
    inc eax
    call pkgcard_decimal
    mov byte [rdi],'/'
    inc rdi
    mov eax,[rel pkgcard_lines]
    add eax,PC_ROWS-1
    xor edx,edx
    div ecx
    call pkgcard_decimal
    lea rsi,[rel pkgcard_order]
.order:
    lodsb
    stosb
    test al,al
    jnz .order
    mov edi,[rel pkgcard_ids+PC_PAGE*4]
    lea rsi,[rel pkgcard_line]
    call wgt_set_text
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r12
    pop rbx
    ret
pkgcard_decimal:
    push rcx
    push rdx
    push rsi
    mov rsi,rdi
    mov ecx,10
.digit:
    xor edx,edx
    div ecx
    add dl,'0'
    mov [rdi],dl
    inc rdi
    test eax,eax
    jnz .digit
    push rdi
    dec rdi
.reverse:
    cmp rsi,rdi
    jae .done
    mov al,[rsi]
    mov dl,[rdi]
    mov [rsi],dl
    mov [rdi],al
    inc rsi
    dec rdi
    jmp .reverse
.done:
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    ret
pkgcard_title: db 'Package disclosure (read only)',0
pkgcard_order: db ' (left then right)',0
pkgcard_previous: db 'Previous',0
pkgcard_next: db 'Next',0
pkgcard_close_text: db 'Close',0
pkgcard_page_word: db 'Page ',0,0,0
%macro WDATA_gui_app_package_card 0
pkgcard_slot: dd -1
pkgcard_gen: dd 0
pkgcard_lines: dd 0
pkgcard_offset: dd 0
pkgcard_action: db 0
pkgcard_initialized: db 0
align 8, db 0
pkgcard_prev_filter: dq 0
pkgcard_prev_click: dq 0
pkgcard_ids: times PC_COUNT dd -1
pkgcard_line: times 40 db 0
%endmacro
WDATA_DEFER WDATA_gui_app_package_card
