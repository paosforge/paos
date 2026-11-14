; A3 0.1-stretch: bounded public plain UTF-8 editor. No clipboard capability,
; secret buffer, script grant, filesystem or persistence authority lives here.
; Four independently owned buffers, one undo snapshot per editor. Byte offsets
; are always UTF-8 grapheme boundaries; LF is a line break, other C0s refuse.
WED_N       equ 4
WED_MAX     equ 4095
WED_OWNER   equ 0
WED_BIRTH   equ 8
WED_LEN     equ 16
WED_CARET   equ 20
WED_ANCHOR  equ 24
WED_TOP     equ 28
WED_LEFT    equ 32
WED_VALID   equ 36
WED_ULEN    equ 40
WED_UCARET  equ 44
WED_UANCHOR equ 48
WED_UTOP    equ 52
WED_ULEFT   equ 56
WED_BUF     equ 64
WED_UNDO    equ WED_BUF + WED_MAX + 1
WED_SZ      equ WED_UNDO + WED_MAX + 1

wgt_editor_register:
    cmp dword [rel wgt_editor_type], -1
    jne .out
    lea rdi,[rel str_wt_editor]
    lea rsi,[rel wgt_editor_draw]
    lea rdx,[rel wgt_rect_hittest]
    lea rcx,[rel wgt_editor_set]
    lea r8,[rel wgt_editor_get]
    mov r9,(132 << 32) | 260
    call wgt_type_register
    mov [rel wgt_editor_type],eax
.out:
    ret

; EDI id -> RAX slot, CF clear only for exact registered visible public editor.
; A future secret/password role cannot turn this public type into a leak.
wgt_editor_public:
    cmp edi,[rel wgt_count]
    jae .bad
    cmp edi,WGT_MAX
    jae .bad
    call wgt_slot_ptr
    mov ecx,[rel wgt_editor_type]
    cmp ecx,WTYPE_MAX
    jae .bad
    mov edx,ecx
    inc edx
    cmp [rax+WGI_TYPE],edx
    jne .bad
    imul ecx,WT_SZ
    lea r10,[rel wgt_types]
    lea rdx,[rel wgt_editor_get]
    cmp [r10+rcx+WT_GET],rdx
    jne .bad
    lea rdx,[rel str_wt_editor]
    cmp [r10+rcx+WT_NAME],rdx
    jne .bad
    test dword [rax+WGI_FLAGS],1
    jz .bad
    test dword [rax+WGI_EDIT],WGT_EDIT_SECTEXT
    jnz .bad
    push rax
    mov rdi,[rax+WGI_ROLE]
    test rdi,rdi
    jz .role_ok
    lea rsi,[rel str_wgt_role_password]
    call strcmp
    test eax,eax
    jz .role_bad
.role_ok:
    pop rax
    clc
    ret
.role_bad:
    pop rax
.bad:
    xor eax,eax
    stc
    ret

; EDI id, ESI create (0 observation / 1 edit/paint) -> RAX state or zero.
; No observer allocates. Binding includes birth; a stale object is never read.
wgt_editor_state:
    push rbx
    push r12
    push r13
    mov r12d,edi
    mov r13d,esi
    call wgt_editor_public
    jc .bad
    mov rbx,rax
    lea r10,[rel wgt_birth_serial]
    mov r11,[r10+r12*8]
    test r11,r11
    jz .bad
    lea rax,[rel wgt_editor_pool]
    xor ecx,ecx
    xor edx,edx
.scan:
    cmp [rax+WED_OWNER],rbx
    jne .free
    cmp [rax+WED_BIRTH],r11
    jne .bad                            ; creator/retirement always wipes it
    jmp .out
.free:
    cmp qword [rax+WED_OWNER],0
    jne .next
    test rdx,rdx
    cmovz rdx,rax
.next:
    add rax,WED_SZ
    inc ecx
    cmp ecx,WED_N
    jb .scan
    test r13d,r13d
    jz .bad
    test rdx,rdx
    jz .bad
    mov rax,rdx
    mov [rax+WED_OWNER],rbx
    mov [rax+WED_BIRTH],r11
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

; RAX slot -> wipe owned live text AND undo, preserving all registers.
wgt_editor_free:
    push rax
    push rcx
    push rdx
    push rdi
    push rsi
    mov rdx,rax
    lea rsi,[rel wgt_editor_pool]
    mov ecx,WED_N
.scan:
    cmp [rsi+WED_OWNER],rdx
    jne .next
    push rcx
    mov rdi,rsi
    mov ecx,WED_SZ
    xor eax,eax
    cld
    rep stosb
    pop rcx
.next:
    add rsi,WED_SZ
    loop .scan
    pop rsi
    pop rdi
    pop rdx
    pop rcx
    pop rax
    ret

; RDI bytes, ESI length -> EAX 1 public editor text / 0 invalid.
wgt_ed_valid:
    push rbx
    push r12
    push r13
    sub rsp,8
    mov rbx,rdi
    mov r12d,esi
    cmp esi,WED_MAX
    ja .bad
    call ue_utf8_validate
    cmp eax,1
    jne .bad
    xor r13d,r13d
.loop:
    cmp r13d,r12d
    jae .ok
    mov rdi,rbx
    mov esi,r12d
    mov edx,r13d
    lea rcx,[rsp]
    call ue_utf8_decode
    cmp eax,1
    jne .bad
    add r13d,[rsp+4]
    mov edi,[rsp]
    cmp edi,10
    je .loop
    cmp edi,32
    jb .bad
    cmp edi,127
    jb .width
    cmp edi,159
    jbe .bad
.width:
    call ue_cell_width
    test eax,eax
    js .bad
    jmp .loop
.ok:
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    add rsp,8
    pop r13
    pop r12
    pop rbx
    ret

; RDI state -> validate whole value and both offsets. Refuse corruption without
; prefix reads, mutation, or undo; do not clear/relabel corrupt bytes as valid.
wgt_ed_ok:
    push rbx
    mov rbx,rdi
    mov esi,[rbx+WED_LEN]
    lea rdi,[rbx+WED_BUF]
    call wgt_ed_valid
    test eax,eax
    jz .out
    mov ecx,[rbx+WED_LEN]
    cmp byte [rbx+WED_BUF+rcx],0
    jne .bad
    mov edx,[rbx+WED_CARET]
    cmp edx,[rbx+WED_LEN]
    ja .bad
    call wgt_ed_boundary
    test eax,eax
    jz .out
    mov edx,[rbx+WED_ANCHOR]
    cmp edx,[rbx+WED_LEN]
    ja .bad
    call wgt_ed_boundary
    jmp .out
.bad:
    xor eax,eax
.out:
    pop rbx
    ret

; RBX state, EDX requested offset -> EAX 1 iff grapheme boundary.
wgt_ed_boundary:
    test edx,edx
    jz .yes
    push r12
    push r13
    mov r12d,edx
    xor r13d,r13d
.loop:
    lea rdi,[rbx+WED_BUF]
    mov esi,[rbx+WED_LEN]
    mov edx,r13d
    call ue_grapheme_next
    cmp eax,-1
    je .no
    cmp eax,r13d
    jbe .no
    mov r13d,eax
    cmp eax,r12d
    jb .loop
    sete al
    movzx eax,al
    jmp .out
.no:
    xor eax,eax
.out:
    pop r13
    pop r12
    ret
.yes:
    mov eax,1
    ret

; RDI state, RSI insertion, EDX size -> EAX 0 success / 1 refusal.
; Replace the selection atomically, after validating capacity and input.
wgt_ed_replace:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx,rdi
    mov r12,rsi
    mov r13d,edx
    call wgt_ed_ok
    test eax,eax
    jz .bad
    mov rdi,r12
    mov esi,r13d
    call wgt_ed_valid
    test eax,eax
    jz .bad
    mov r14d,[rbx+WED_CARET]
    mov r15d,[rbx+WED_ANCHOR]
    cmp r14d,r15d
    jbe .ordered
    xchg r14d,r15d
.ordered:
    mov eax,[rbx+WED_LEN]
    sub eax,r15d
    add eax,r14d
    add eax,r13d
    cmp eax,WED_MAX
    ja .bad
    mov rdi,rbx
    call wgt_ed_save
    ; memmove suffix incl terminator, backwards only when growing.
    mov ecx,[rbx+WED_LEN]
    sub ecx,r15d
    inc ecx
    lea rsi,[rbx+WED_BUF+r15]
    lea rdi,[rbx+WED_BUF+r14]
    add rdi,r13
    cmp rdi,rsi
    jbe .forward
    lea rsi,[rsi+rcx-1]
    lea rdi,[rdi+rcx-1]
    std
    rep movsb
    cld
    jmp .insert
.forward:
    cld
    rep movsb
.insert:
    lea rdi,[rbx+WED_BUF+r14]
    mov rsi,r12
    mov ecx,r13d
    rep movsb
    mov eax,[rbx+WED_LEN]
    sub eax,r15d
    add eax,r14d
    add eax,r13d
    mov [rbx+WED_LEN],eax
    add r14d,r13d
    mov [rbx+WED_CARET],r14d
    mov [rbx+WED_ANCHOR],r14d
    xor eax,eax
    jmp .out
.bad:
    mov eax,1
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

wgt_ed_save:                            ; RDI state, preserves nonvolatile
    mov r8,rdi
    mov eax,[rdi+WED_LEN]
    mov [rdi+WED_ULEN],eax
    mov eax,[rdi+WED_CARET]
    mov [rdi+WED_UCARET],eax
    mov eax,[rdi+WED_ANCHOR]
    mov [rdi+WED_UANCHOR],eax
    mov eax,[rdi+WED_TOP]
    mov [rdi+WED_UTOP],eax
    mov eax,[rdi+WED_LEFT]
    mov [rdi+WED_ULEFT],eax
    lea rsi,[rdi+WED_BUF]
    lea rdi,[rdi+WED_UNDO]
    mov ecx,WED_MAX+1
    cld
    rep movsb
    mov dword [r8+WED_VALID],1
    ret

wgt_ed_undo:                            ; RDI state -> EAX 0 or 1 no snapshot
    cmp dword [rdi+WED_VALID],1
    jne .bad
    push rbx
    mov rbx,rdi
    ; Snapshot validity is rechecked before copying it into live state.
    mov esi,[rbx+WED_ULEN]
    lea rdi,[rbx+WED_UNDO]
    call wgt_ed_valid
    test eax,eax
    jz .corrupt
    mov ecx,[rbx+WED_ULEN]
    cmp byte [rbx+WED_UNDO+rcx],0
    jne .corrupt
    mov edx,[rbx+WED_UCARET]
    call .boundary
    test eax,eax
    jz .corrupt
    mov edx,[rbx+WED_UANCHOR]
    call .boundary
    test eax,eax
    jz .corrupt
    mov eax,[rbx+WED_ULEN]
    mov [rbx+WED_LEN],eax
    mov eax,[rbx+WED_UCARET]
    mov [rbx+WED_CARET],eax
    mov eax,[rbx+WED_UANCHOR]
    mov [rbx+WED_ANCHOR],eax
    mov eax,[rbx+WED_UTOP]
    mov [rbx+WED_TOP],eax
    mov eax,[rbx+WED_ULEFT]
    mov [rbx+WED_LEFT],eax
    lea rsi,[rbx+WED_UNDO]
    lea rdi,[rbx+WED_BUF]
    mov ecx,WED_MAX+1
    cld
    rep movsb
    ; Consume and wipe the snapshot, including text past a shorter edit.
    lea rdi,[rbx+WED_UNDO]
    xor eax,eax
    mov ecx,WED_MAX+1
    rep stosb
    mov dword [rbx+WED_VALID],0
    pop rbx
    xor eax,eax
    ret
.corrupt:
    pop rbx
.bad:
    mov eax,1
    ret

.boundary:
    cmp edx,[rbx+WED_ULEN]
    ja .not_boundary
    test edx,edx
    jz .is_boundary
    push r12
    push r13
    mov r12d,edx
    xor r13d,r13d
.boundary_loop:
    lea rdi,[rbx+WED_UNDO]
    mov esi,[rbx+WED_ULEN]
    mov edx,r13d
    call ue_grapheme_next
    cmp eax,r13d
    jbe .boundary_bad
    cmp eax,-1
    je .boundary_bad
    mov r13d,eax
    cmp eax,r12d
    jb .boundary_loop
    sete al
    movzx eax,al
    jmp .boundary_out
.boundary_bad:
    xor eax,eax
.boundary_out:
    pop r13
    pop r12
    ret
.not_boundary:
    xor eax,eax
    ret
.is_boundary:
    mov eax,1
    ret

; RDI state, EAX key, EDX shift/ctrl bits, RSI payload, ECX payload len.
; Entry has already passed the current input route's authority/focus boundary.
wgt_ed_key:
    push rbx
    push r12
    push r13
    push r14
    sub rsp,16
    mov rbx,rdi
    mov r12d,eax
    mov r13d,edx
    mov [rsp],rsi
    mov [rsp+8],ecx
    call wgt_ed_ok
    test eax,eax
    jz .bad
    mov eax,[rbx+WED_ANCHOR]
    mov [rsp+12],eax
    test r13d,2
    jz .ordinary
    or r12d,0x20
    cmp r12d,'z'
    je .undo
    cmp r12d,'a'
    jne .handled
    mov dword [rbx+WED_ANCHOR],0
    mov eax,[rbx+WED_LEN]
    mov [rbx+WED_CARET],eax
    jmp .handled
.undo:
    mov rdi,rbx
    call wgt_ed_undo
    jmp .handled
.ordinary:
    mov r14d,[rbx+WED_CARET]
    cmp r12d,GUI_KEY_LEFT
    je .left
    cmp r12d,GUI_KEY_RIGHT
    je .right
    cmp r12d,GUI_KEY_HOME
    je .home
    cmp r12d,GUI_KEY_END
    je .end
    cmp r12d,GUI_KEY_UP
    je .up
    cmp r12d,GUI_KEY_DOWN
    je .down
    cmp r12d,GUI_KEY_BACKSPACE
    je .back
    cmp r12d,GUI_KEY_DELETE
    je .delete
    cmp r12d,GUI_KEY_ENTER
    je .newline
    cmp r12d,GUI_KEY_TEXT
    je .text
    cmp r12d,0x20
    jb .handled
    cmp r12d,0x7e
    ja .handled
    mov [rsp],r12b
    lea rsi,[rsp]
    mov edx,1
    jmp .replace
.newline:
    mov byte [rsp],10
    lea rsi,[rsp]
    mov edx,1
    jmp .replace
.text:
    mov rsi,[rsp]
    mov edx,[rsp+8]
    test edx,edx
    jz .handled
    cmp edx,WGT_TEXT_CAP
    jae .handled
.replace:
    mov rdi,rbx
    call wgt_ed_replace
    test eax,eax
    jnz .handled
    mov eax,[rsp+12]
    mov [rbx+WED_UANCHOR],eax
    jmp .handled
.back:
    cmp r14d,[rbx+WED_ANCHOR]
    jne .cut
    test r14d,r14d
    jz .handled
    lea rdi,[rbx+WED_BUF]
    mov esi,[rbx+WED_LEN]
    mov edx,r14d
    call ue_grapheme_prev
    cmp eax,-1
    je .handled
    mov [rbx+WED_ANCHOR],eax
    jmp .cut
.delete:
    cmp r14d,[rbx+WED_ANCHOR]
    jne .cut
    cmp r14d,[rbx+WED_LEN]
    jae .handled
    lea rdi,[rbx+WED_BUF]
    mov esi,[rbx+WED_LEN]
    mov edx,r14d
    call ue_grapheme_next
    cmp eax,-1
    je .handled
    mov [rbx+WED_ANCHOR],eax
.cut:
    lea rsi,[rel str_wed_empty]
    xor edx,edx
    jmp .replace
.left:
    test r13d,1
    jnz .prev
    mov eax,[rbx+WED_ANCHOR]
    cmp eax,r14d
    je .prev
    cmovb r14d,eax
    jmp .move
.prev:
    test r14d,r14d
    jz .move
    lea rdi,[rbx+WED_BUF]
    mov esi,[rbx+WED_LEN]
    mov edx,r14d
    call ue_grapheme_prev
    cmp eax,-1
    je .handled
    mov r14d,eax
    jmp .move
.right:
    test r13d,1
    jnz .next
    mov eax,[rbx+WED_ANCHOR]
    cmp eax,r14d
    je .next
    cmova r14d,eax
    jmp .move
.next:
    cmp r14d,[rbx+WED_LEN]
    jae .move
    lea rdi,[rbx+WED_BUF]
    mov esi,[rbx+WED_LEN]
    mov edx,r14d
    call ue_grapheme_next
    cmp eax,-1
    je .handled
    mov r14d,eax
    jmp .move
.home:
    test r14d,r14d
    jz .move
    cmp byte [rbx+WED_BUF+r14-1],10
    je .move
    dec r14d
    jmp .home
.end:
    cmp r14d,[rbx+WED_LEN]
    jae .move
    cmp byte [rbx+WED_BUF+r14],10
    je .move
    inc r14d
    jmp .end
.up:
    ; Use a grapheme column rather than a byte column on the adjacent line.
    xor r12d,r12d
.up_column:
    test r14d,r14d
    jz .move
    cmp byte [rbx+WED_BUF+r14-1],10
    je .previous_line
    lea rdi,[rbx+WED_BUF]
    mov esi,[rbx+WED_LEN]
    mov edx,r14d
    call ue_grapheme_prev
    mov r14d,eax
    inc r12d
    jmp .up_column
.previous_line:
    dec r14d
.prev_start:
    test r14d,r14d
    jz .column
    cmp byte [rbx+WED_BUF+r14-1],10
    je .column
    dec r14d
    jmp .prev_start
.down:
    xor r12d,r12d
    mov r14d,[rbx+WED_CARET]
.down_column:
    test r14d,r14d
    jz .next_line
    cmp byte [rbx+WED_BUF+r14-1],10
    je .next_line
    lea rdi,[rbx+WED_BUF]
    mov esi,[rbx+WED_LEN]
    mov edx,r14d
    call ue_grapheme_prev
    mov r14d,eax
    inc r12d
    jmp .down_column
.next_line:
    cmp r14d,[rbx+WED_LEN]
    jae .original_caret
    cmp byte [rbx+WED_BUF+r14],10
    je .line_found
    inc r14d
    jmp .next_line
.line_found:
    inc r14d
.column:
    test r12d,r12d
    jz .move
    cmp r14d,[rbx+WED_LEN]
    jae .move
    cmp byte [rbx+WED_BUF+r14],10
    je .move
    lea rdi,[rbx+WED_BUF]
    mov esi,[rbx+WED_LEN]
    mov edx,r14d
    call ue_grapheme_next
    mov r14d,eax
    dec r12d
    jmp .column
.original_caret:
    mov r14d,[rbx+WED_CARET]
.move:
    mov [rbx+WED_CARET],r14d
    test r13d,1
    jnz .handled
    mov [rbx+WED_ANCHOR],r14d
.handled:
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    add rsp,16
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; RDI state, RSI slot: keep caret visible and reflect public metadata. Scrolling
; is in lines/cells, bounded by the real inner geometry, not a global counter.
wgt_ed_view:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp,8
    mov rbx,rdi
    mov r12,rsi
    xor r13d,r13d                    ; byte offset
    xor r14d,r14d                    ; line
    xor r15d,r15d                    ; cell column
.loop:
    cmp r13d,[rbx+WED_CARET]
    jae .position
    cmp byte [rbx+WED_BUF+r13],10
    jne .scalar
    inc r14d
    xor r15d,r15d
    inc r13d
    jmp .loop
.scalar:
    lea rdi,[rbx+WED_BUF]
    mov esi,[rbx+WED_LEN]
    mov edx,r13d
    lea rcx,[rsp]
    call ue_utf8_decode
    cmp eax,1
    jne .position
    add r13d,[rsp+4]
    mov edi,[rsp]
    call ue_cell_width
    test eax,eax
    js .position
    add r15d,eax
    jmp .loop
.position:
    mov eax,[r12+WGI_H]
    sub eax,8
    sar eax,4
    cmp eax,1
    jge .rows
    mov eax,1
.rows:
    cmp r14d,[rbx+WED_TOP]
    jae .below
    mov [rbx+WED_TOP],r14d
.below:
    mov ecx,[rbx+WED_TOP]
    add ecx,eax
    cmp r14d,ecx
    jb .columns
    mov ecx,r14d
    sub ecx,eax
    inc ecx
    mov [rbx+WED_TOP],ecx
.columns:
    mov eax,[r12+WGI_W]
    sub eax,8
    sar eax,3
    cmp eax,1
    jge .cols
    mov eax,1
.cols:
    cmp r15d,[rbx+WED_LEFT]
    jae .right
    mov [rbx+WED_LEFT],r15d
.right:
    mov ecx,[rbx+WED_LEFT]
    add ecx,eax
    cmp r15d,ecx
    jb .sync
    mov ecx,r15d
    sub ecx,eax
    inc ecx
    mov [rbx+WED_LEFT],ecx
.sync:
    mov eax,[rbx+WED_LEN]
    mov [r12+WGI_VLEN],eax
    mov eax,[rbx+WED_CARET]
    mov [r12+WGI_CARET],eax
    mov edx,[rbx+WED_ANCHOR]
    cmp eax,edx
    jbe .ordered
    xchg eax,edx
.ordered:
    mov [r12+WGI_SEL_LO],eax
    mov [r12+WGI_SEL_HI],edx
    mov eax,[rbx+WED_TOP]
    mov [r12+WGI_SCROLL],eax
    add rsp,8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

wgt_editor_key:                         ; EDI id, EAX key
    push rbx
    push r12
    push r13
    mov r12d,edi
    mov r13d,eax
    cmp edi,[rel wgt_focus_id]
    jne .bad
    call wgt_editor_public
    jc .bad
    test dword [rax+WGI_EDIT],WGT_EDIT_DISABLED
    jnz .bad
    mov ecx,[rax+WGI_WIN]
    call wgt_overlay_host_shown
    jc .bad
    mov edi,r12d
    mov esi,1
    call wgt_editor_state
    test rax,rax
    jz .bad
    mov rbx,rax
    mov rdi,rax
    mov eax,r13d
    movzx edx,byte [rel input_kbd_mods]
    lea rsi,[rel wgt_text_buf]
    mov ecx,[rel wgt_text_len]
    call wgt_ed_key
    test eax,eax
    jz .bad
    mov edi,r12d
    call wgt_slot_ptr
    mov rsi,rax
    mov rdi,rbx
    call wgt_ed_view
    mov edi,r12d
    call wgt_state_repaint
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Standard authorized WIDGETSET, no new verb or alternate command authority.
; value = public text, hex = UTF-8/LF hex, undo = 1. Existing outer bound is31.
wgt_editor_set:
    push rbx
    push r12
    push r13
    push r14
    sub rsp,40
    mov r12d,edi
    mov r13,rsi
    mov r14,rdx
    call wgt_editor_public
    jc .bad
    test dword [rax+WGI_EDIT],WGT_EDIT_DISABLED
    jnz .bad
    mov rdi,r13
    lea rsi,[rel str_wf_value]
    call strcmp
    test eax,eax
    jz .value
    mov rdi,r13
    lea rsi,[rel str_wed_hex]
    call strcmp
    test eax,eax
    jz .hex
    mov rdi,r13
    lea rsi,[rel str_wed_select]
    call strcmp
    test eax,eax
    jz .select
    mov rdi,r13
    lea rsi,[rel str_wed_undo]
    call strcmp
    test eax,eax
    jnz .bad
    cmp word [r14],'1'
    jne .bad
    mov edi,r12d
    xor esi,esi
    call wgt_editor_state
    test rax,rax
    jz .bad
    mov rbx,rax
    mov rdi,rax
    call wgt_ed_undo
    test eax,eax
    jnz .bad
    jmp .changed
.select:
    mov rdi,r14
    call wgt_parse_dec
    test rcx,rcx
    jz .bad
    cmp rcx,4                         ; no wrapped or unbounded decimal offsets
    ja .bad
    cmp rax,WED_MAX
    ja .bad
    mov [rsp+24],eax
    cmp byte [rdx],','
    jne .bad
    lea rdi,[rdx+1]
    call wgt_parse_dec
    test rcx,rcx
    jz .bad
    cmp rcx,4                         ; no wrapped or unbounded decimal offsets
    ja .bad
    cmp rax,WED_MAX
    ja .bad
    cmp byte [rdx],0
    jne .bad
    mov [rsp+28],eax
    mov edi,r12d
    xor esi,esi
    call wgt_editor_state
    test rax,rax
    jz .bad
    mov rbx,rax
    mov rdi,rax
    call wgt_ed_ok
    test eax,eax
    jz .bad
    mov edx,[rsp+24]
    cmp edx,[rbx+WED_LEN]
    ja .bad
    call wgt_ed_boundary
    test eax,eax
    jz .bad
    mov edx,[rsp+28]
    cmp edx,[rbx+WED_LEN]
    ja .bad
    call wgt_ed_boundary
    test eax,eax
    jz .bad
    mov eax,[rsp+24]
    mov [rbx+WED_ANCHOR],eax
    mov eax,[rsp+28]
    mov [rbx+WED_CARET],eax
    jmp .changed
.hex:
    xor ebx,ebx
.hex_byte:
    cmp ebx,15                          ; WIDGETSET's legacy atomic31-byte cap
    jae .hex_end
    movzx eax,byte [r14+rbx*2]
    test eax,eax
    jz .hex_end
    call wgt_ed_nibble
    jc .bad
    mov ecx,eax
    shl ecx,4
    movzx eax,byte [r14+rbx*2+1]
    call wgt_ed_nibble
    jc .bad
    or eax,ecx
    mov [rsp+rbx],al
    inc ebx
    jmp .hex_byte
.hex_end:
    cmp byte [r14+rbx*2],0
    jne .bad
    mov r14,rsp
    jmp .replace_all
.value:
    xor ebx,ebx
.length:
    cmp ebx,31
    ja .bad
    cmp byte [r14+rbx],0
    je .replace_all
    inc ebx
    jmp .length
.replace_all:
    ; Validate BEFORE allocating or changing the prior selection.
    mov rdi,r14
    mov esi,ebx
    call wgt_ed_valid
    test eax,eax
    jz .bad
    mov edi,r12d
    mov esi,1
    call wgt_editor_state
    test rax,rax
    jz .bad
    mov r13,rax
    mov rdi,rax
    call wgt_ed_ok
    test eax,eax
    jz .bad
    ; Snapshot retains pre-command caret/selection, not the temporary full select.
    mov rdi,r13
    call wgt_ed_save
    lea rdi,[r13+WED_BUF]
    mov rsi,r14
    mov ecx,ebx
    cld
    rep movsb
    mov byte [rdi],0
    mov [r13+WED_LEN],ebx
    mov [r13+WED_CARET],ebx
    mov [r13+WED_ANCHOR],ebx
    mov rbx,r13
.changed:
    mov edi,r12d
    call wgt_slot_ptr
    mov rsi,rax
    mov rdi,rbx
    call wgt_ed_view
    mov edi,r12d
    call wgt_state_repaint
    xor eax,eax
    jmp .out
.bad:
    mov eax,1
.out:
    add rsp,40
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

wgt_ed_nibble:                          ; AL -> EAX nibble, CF bad
    sub eax,'0'
    cmp eax,9
    jbe .ok
    sub eax,'a'-'0'
    cmp eax,5
    ja .bad
    add eax,10
.ok:
    clc
    ret
.bad:
    stc
    ret

; Generic GET never returns a raw LF/control-bearing value. The original
; content path below owns bounded hex observation, identity and redaction.
wgt_editor_get:
    xor eax,eax
    ret

; EDI id -> selected UTF-8 bytes for existing CLIPSET text/plain textfield id.
; No clipboard write here. The service's original permission/capacity checks run.
wgt_editor_copy:
    push rbx
    xor esi,esi
    call wgt_editor_state
    test rax,rax
    jz .bad
    mov rbx,rax
    mov rax,[rbx+WED_OWNER]
    mov ecx,[rax+WGI_WIN]
    call wgt_overlay_host_shown
    jc .bad
    mov rdi,rbx
    call wgt_ed_ok
    test eax,eax
    jz .bad
    mov eax,[rbx+WED_CARET]
    mov ecx,[rbx+WED_ANCHOR]
    cmp eax,ecx
    jbe .ordered
    xchg eax,ecx
.ordered:
    sub ecx,eax
    jz .bad
    cmp ecx,768                         ; original clipboard inline capacity
    ja .bad
    lea rax,[rbx+WED_BUF+rax]
    xor edx,edx
    pop rbx
    ret
.bad:
    xor eax,eax
    xor ecx,ecx
    mov edx,1
    pop rbx
    ret

; Called only after the common content identity+public-role checks. Emits at
; most128 original bytes in hex, with an explicit complete flag (no fake prefix).
wgt_ed_out_ch:                         ; DIL one ASCII hex character
    sub rsp,8
    mov [rsp],dil
    mov byte [rsp+1],0
    mov rdi,rsp
    call wgt_out_str
    add rsp,8
    ret

wgt_editor_content:                     ; EDI id -> EAX 1 or 0 unavailable
    push rbx
    push r12
    push r13
    mov r12d,edi
    xor esi,esi
    call wgt_editor_state
    test rax,rax
    jz .bad
    mov rbx,rax
    mov rdi,rax
    call wgt_ed_ok
    test eax,eax
    jz .bad
    lea rdi,[rel str_wed_len]
    call wgt_out_str
    mov edi,[rbx+WED_LEN]
    call wgt_out_dec
    lea rdi,[rel str_wed_caret]
    call wgt_out_str
    mov edi,[rbx+WED_CARET]
    call wgt_out_dec
    lea rdi,[rel str_wed_anchor]
    call wgt_out_str
    mov edi,[rbx+WED_ANCHOR]
    call wgt_out_dec
    lea rdi,[rel str_wed_top]
    call wgt_out_str
    mov edi,[rbx+WED_TOP]
    call wgt_out_dec
    lea rdi,[rel str_wed_left]
    call wgt_out_str
    mov edi,[rbx+WED_LEFT]
    call wgt_out_dec
    lea rdi,[rel str_wed_bytes]
    call wgt_out_str
    xor r12d,r12d
    mov r13d,[rbx+WED_LEN]
    cmp r13d,128
    jbe .hex
    mov r13d,128
.hex:
    cmp r12d,r13d
    jae .complete
    movzx eax,byte [rbx+WED_BUF+r12]
    shr eax,4
    lea rdx,[rel str_wed_digits]
    mov dil,[rdx+rax]
    call wgt_ed_out_ch
    movzx eax,byte [rbx+WED_BUF+r12]
    and eax,15
    lea rdx,[rel str_wed_digits]
    mov dil,[rdx+rax]
    call wgt_ed_out_ch
    inc r12d
    jmp .hex
.complete:
    lea rdi,[rel str_wed_complete]
    call wgt_out_str
    xor edi,edi
    cmp dword [rbx+WED_LEN],128
    seta dil
    xor edi,1
    call wgt_out_dec
    lea rdi,[rel str_wed_end]
    call wgt_out_str
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Ordinary shared framebuffer primitives, solid background every draw. Real
; widget/window clipping remains in wgt_draw_id. LF advances a row; offscreen
; cells skip whole. No private framebuffer, retained pixels or counter proof.
wgt_editor_draw:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,40
    mov [rsp+32],edi
    mov esi,1
    call wgt_editor_state
    test rax,rax
    jz .out
    mov r12,rax
    mov edi,[rsp+32]
    call wgt_slot_ptr
    mov rbp,rax
    mov rdi,r12
    call wgt_ed_ok
    test eax,eax
    jz .out
    mov rdi,r12
    mov rsi,rbp
    call wgt_ed_view
    ; Also defend direct painter calls: no signed-negative/zero cell count
    ; may reach the unsigned cell comparisons or paint outside this rectangle.
    mov eax,[rbp+WGI_W]
    cmp eax,16
    jl .out
    sub eax,8
    sar eax,3
    test eax,eax
    jle .out
    mov [rsp+8],eax                    ; visible columns
    mov eax,[rbp+WGI_H]
    cmp eax,24
    jl .out
    sub eax,8
    sar eax,4
    test eax,eax
    jle .out
    mov [rsp+12],eax                   ; visible rows
    mov r8d,[rbp+WGI_X]
    mov r9d,[rbp+WGI_Y]
    mov r10d,[rbp+WGI_W]
    mov r11d,[rbp+WGI_H]
    mov ebx,WGT_TF_BG
    call fb_fill_rect
    xor r13d,r13d                     ; byte offset
    xor r14d,r14d                     ; line
    xor r15d,r15d                     ; cell column
.loop:
    cmp r13d,[r12+WED_LEN]
    ja .out
    mov dword [rsp+4],0
    mov dword [rsp],32                 ; paint caret even at end/line break
    cmp r13d,[r12+WED_LEN]
    jae .cell
    lea rdi,[r12+WED_BUF]
    mov esi,[r12+WED_LEN]
    mov edx,r13d
    lea rcx,[rsp]
    call ue_utf8_decode
    cmp eax,1
    jne .out
.cell:
    mov eax,r14d
    sub eax,[r12+WED_TOP]
    jb .next
    cmp eax,[rsp+12]
    jae .out
    shl eax,4
    mov r9d,[rbp+WGI_Y]
    lea r9d,[r9+rax+4]
    mov eax,r15d
    sub eax,[r12+WED_LEFT]
    jb .next
    cmp eax,[rsp+8]
    jae .next
    shl eax,3
    mov r8d,[rbp+WGI_X]
    lea r8d,[r8+rax+4]
    mov ebx,WGT_TF_FG
    mov ecx,WGT_TF_BG
    mov eax,[r12+WED_CARET]
    mov edx,[r12+WED_ANCHOR]
    cmp eax,edx
    jbe .ordered
    xchg eax,edx
.ordered:
    cmp r13d,eax
    jb .caret
    cmp r13d,edx
    jb .selected
.caret:
    mov eax,[rsp+32]
    cmp eax,[rel wgt_focus_id]
    jne .glyph
    mov eax,[r12+WED_CARET]
    cmp r13d,eax
    jne .glyph
.selected:
    xchg ebx,ecx
.glyph:
    mov edx,[rsp]
    cmp edx,10
    jne .font
    mov edx,32
.font:
    cmp edx,FONT8X16_SCALARS
    jb .paint
    mov edx,'?'                        ; missing-font scalar, never an ASCII byte split
.paint:
    call fb_draw_scalar
.next:
    cmp r13d,[r12+WED_LEN]
    jae .out
    cmp dword [rsp],10
    jne .advance
    inc r14d
    xor r15d,r15d
    jmp .step
.advance:
    mov edi,[rsp]
    call ue_cell_width
    test eax,eax
    js .out
    add r15d,eax
.step:
    add r13d,[rsp+4]
    jmp .loop
.out:
    add rsp,40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

%macro WDATA_gui_widget_editor 0
align 8
wgt_editor_type: dd -1
str_wt_editor: db 'editor',0
str_wed_empty: db 0
str_wed_hex: db 'hex',0
str_wed_undo: db 'undo',0
str_wed_select: db 'select',0
str_wed_context: db ' kind=editor source=',0
str_wed_len: db ' length=',0
str_wed_caret: db ' caret=',0
str_wed_anchor: db ' anchor=',0
str_wed_top: db ' top=',0
str_wed_left: db ' left=',0
str_wed_bytes: db ' text_hex=',0
str_wed_complete: db ' complete=',0
str_wed_end: db ' read=public_editor set=unchecked authority=unchecked action=na end=1',0
str_wed_digits: db '0123456789abcdef'
%endmacro
WDATA_DEFER WDATA_gui_widget_editor
%macro WDATA_BSS_gui_widget_editor 0
alignb 8
wgt_editor_pool: resb WED_N * WED_SZ
%endmacro
WDATA_BSS_DEFER WDATA_BSS_gui_widget_editor
