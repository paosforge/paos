; The Terminal's old term_clip arena is now temporary native work space.
; Only a focused shortcut calls these wrappers; the shared service independently
; checks actual local session, physical trigger and held-modifier custody.
term_clip_copy_human:
    call term_copy_selection
    cmp dword [rel term_clip_truncated], 0
    jne .refused
    lea rsi, [rel term_clip]
    mov ecx, [rel term_clip_len]
    call clipboard_text_publish_human
    test eax, eax
    jnz .refused
    call term_sel_clear
    jmp term_clip_wipe
.refused:
    call term_clip_wipe
    lea rsi, [rel term_clip_refused]
    jmp term_out_cstr

term_clip_paste_human:
    cmp dword [rel term_paste_inst], -1
    jne .refused                       ; never replace an admitted SSH frame
%ifdef PAOS_TERMINAL_GUEST
    cmp qword [rel term_guest_paste_instance], 0
    jne .refused                       ; preserve the complete guest frame
%endif
    lea rdi, [rel term_clip]
    mov esi, TERM_CLIP_MAX
    call clipboard_text_snapshot_human
    test eax, eax
    js .refused
    mov [rel term_clip_len], eax
    call term_paste                     ; one admitted snapshot for this action
    jmp term_clip_wipe                  ; queued frame has its independent copy
.refused:
    call term_clip_wipe
    lea rsi, [rel term_clip_refused]
    jmp term_out_cstr

term_clip_wipe:
    lea rdi, [rel term_clip]
    xor eax, eax
    mov ecx, TERM_CLIP_MAX
    cld
    rep stosb
    mov dword [rel term_clip_len], 0
    ret

%include "core/abi/wdata.inc"
%macro WDATA_gui_terminal_clipboard 0
term_clip_refused: db 7,"[clipboard action refused]",13,10,0
term_clip_length_withheld: db "withheld",0
%endmacro
WDATA_DEFER WDATA_gui_terminal_clipboard
