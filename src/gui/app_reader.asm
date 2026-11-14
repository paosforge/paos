;; MODULE gui/app_reader
;; LAYER 6
;; PURPOSE Bounded app-fed read-only text, isolated from native file-view storage.
;; EXPORTS app_reader_init, app_reader_write, app_reader_type
;; IMPORTS gui/widget, gui/window_mgmt, gui/form_events, gui/text_view
;; CAPS CAP_GUI
;; OWNER rc-input-claude
;; CONTEXT: bsp_only
; Native composition only: app_widget rechecks its actual app binding/policy.
; No generic setter/body getter, file access, edit hook or event engine.
AR_CAP equ 4096
APR_CONTEXT_COUNT equ 4
AR_ID_BYTES equ 48
AR_LEN equ 48
AR_TOP equ 56
AR_EXPECT equ 64
AR_WRITTEN equ 72
AR_PENDING equ 80
AR_BODY equ 88
AR_STAGE equ AR_BODY+AR_CAP
AR_SIZE equ AR_STAGE+AR_CAP

; Older native kit callers carry both stack alignments. Normalize only these
; new boundaries; private bodies and outgoing calls use the ordinary ABI.
app_reader_init:
    push rbp
    mov rbp,rsp
    and rsp,-16
    lea rdi,[rel ar_name]
    lea rsi,[rel ar_draw]
    lea rdx,[rel wgt_rect_hittest]
    lea rcx,[rel ar_set]
    lea r8,[rel ar_get]
    mov r9,(240<<32)|480
    call wgt_type_register
    mov [rel app_reader_type],eax
    mov rsp,rbp
    pop rbp
    ret
ar_set:
    mov eax,1
    ret
ar_get:
    xor eax,eax                        ; never disclose the body via generic GET
    ret

; EDI widget, RSI native output48 ->1 iff exact currently live app reader.
; Identity: widget+1, widget birth, enforced principal, slot, full rawgen, reset.
ar_identity:
    push rbx
    push r12
    push r13
    mov ebx,edi
    mov r12,rsi
    cmp edi,WGT_MAX
    jae .bad
    cmp edi,[rel wgt_count]
    jae .bad
    call wgt_slot_ptr
    mov ecx,[rel app_reader_type]
    cmp ecx,-1
    je .bad
    inc ecx
    cmp [rax+WGI_TYPE],ecx
    jne .bad
    test dword [rax+WGI_EDIT],WGT_EDIT_SECTEXT
    jnz .bad
    cmp dword [rax+WGI_BIND],0
    jne .bad
    mov r13d,[rax+WGI_WIN]
    cmp r13d,WM_MAX
    jae .bad
    lea rax,[rel wm_state]
    cmp dword [rax+r13*4],WM_VISIBLE
    je .state
    cmp dword [rax+r13*4],WM_MIN
    jne .bad
.state:
    lea rax,[rel wm_owner]
    mov rax,[rax+r13*8]
    cmp rax,5
    jbe .bad
    cmp rax,-1
    je .bad
    mov [r12+16],rax
    mov [r12+24],r13
    lea rax,[rel wm_gen]
    mov eax,[rax+r13*4]
    test eax,eax
    jz .bad
    mov [r12+32],rax
    mov edi,ebx
    call wgt_birth_lifetime
    test rax,rax
    jz .bad
    mov [r12+8],rax
    mov edi,r13d
    call wmx_window_id
    test eax,eax
    jz .bad
    mov edi,eax
    call form_events_lifetime
    test rax,rax
    jz .bad
    cmp rax,-1
    je .bad
    mov [r12+40],rax
    inc ebx
    mov [r12],rbx
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

; EDI widget, ESI claim0/1 -> RAX context or0. Reads cannot allocate/revive.
; A full table only reclaims a slot whose original native lifetime has ended.
ar_context:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    sub rsp,96
    mov ebp,esi
    mov rsi,rsp
    call ar_identity
    test eax,eax
    jz .bad
    lea rbx,[rel ar_contexts]
    xor r12d,r12d
    xor r13d,r13d
.scan:
    cmp qword [rbx],0
    je .free
    mov rsi,rsp
    mov rdi,rbx
    mov ecx,AR_ID_BYTES/8
    repe cmpsq
    je .found
    test ebp,ebp
    jz .next
    mov edi,[rbx]
    dec edi
    lea rsi,[rsp+48]
    call ar_identity
    test eax,eax
    jz .free
    mov rdi,rbx
    lea rsi,[rsp+48]
    mov ecx,AR_ID_BYTES/8
    repe cmpsq
    je .next
.free:
    test r13,r13
    cmovz r13,rbx
.next:
    add rbx,AR_SIZE
    inc r12d
    cmp r12d,APR_CONTEXT_COUNT
    jb .scan
    test ebp,ebp
    jz .bad
    test r13,r13
    jz .bad
    mov rbx,r13
    mov rdi,rbx
    xor eax,eax
    mov ecx,AR_SIZE/8
    rep stosq
    mov rdi,rbx
    mov rsi,rsp
    mov ecx,AR_ID_BYTES/8
    rep movsq
.found:
    mov rax,rbx
    jmp .out
.bad:
    xor eax,eax
.out:
    add rsp,96
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; EDI widget, ESI op7BEGIN/8APPEND/9COMMIT/10PAGE, RDX total/offset/page,
; RCX native input, R8 length -> EAX0 success/1 refusal, no queued work.
; PAGE operand0 first/1 next/2 previous. Caller authorizes and gates painting.
app_reader_write:
    push rbp
    mov rbp,rsp
    and rsp,-16
    call ar_write_body
    mov rsp,rbp
    pop rbp
    ret
ar_write_body:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,8
    mov ebx,edi
    mov ebp,esi
    mov r12,rdx
    mov r13,rcx
    mov r14,r8
    cmp esi,7
    jb .bad
    cmp esi,10
    ja .bad
    xor esi,esi
    cmp ebp,7
    sete sil
    cmp r14,256
    ja .bad
    cmp ebp,8
    je .context
    test r14,r14
    jnz .bad
    cmp ebp,7
    jne .other_bound
    cmp r12,AR_CAP
    ja .bad
    jmp .context
.other_bound:
    cmp ebp,9
    jne .page_bound
    test r12,r12
    jnz .bad
    jmp .context
.page_bound:
    cmp r12,2
    ja .bad
.context:
    call ar_context
    test rax,rax
    jz .bad
    mov r15,rax
    cmp ebp,7
    je .begin
    cmp ebp,10
    je .page
    cmp qword [r15+AR_PENDING],1
    jne .bad
    cmp ebp,9
    je .commit
    test r14,r14
    jz .bad
    test r13,r13
    jz .bad
    cmp r12,[r15+AR_WRITTEN]
    jne .bad
    mov rax,[r15+AR_EXPECT]
    sub rax,r12
    jc .bad
    cmp r14,rax
    ja .bad
    lea rdi,[r15+AR_STAGE+r12]
    mov rsi,r13
    mov rcx,r14
    rep movsb
    add [r15+AR_WRITTEN],r14
    jmp .ok
.begin:
    lea rdi,[r15+AR_STAGE]
    mov ecx,AR_CAP/8
    xor eax,eax
    rep stosq
    mov [r15+AR_EXPECT],r12
    mov qword [r15+AR_WRITTEN],0
    mov qword [r15+AR_PENDING],1
    jmp .ok
.commit:
    mov rcx,[r15+AR_WRITTEN]
    cmp rcx,[r15+AR_EXPECT]
    jne .bad
    lea rdi,[r15+AR_BODY]
    xor eax,eax
    mov ecx,AR_CAP/8
    rep stosq
    lea rdi,[r15+AR_BODY]
    lea rsi,[r15+AR_STAGE]
    mov rcx,[r15+AR_EXPECT]
    rep movsb
    mov rax,[r15+AR_EXPECT]
    mov [r15+AR_LEN],rax
    mov qword [r15+AR_TOP],0
    mov qword [r15+AR_PENDING],0
    lea rdi,[r15+AR_STAGE]
    xor eax,eax
    mov ecx,AR_CAP/8
    rep stosq
    jmp .draw
.page:
    mov edi,ebx
    call wgt_slot_ptr
    mov ecx,[rax+WGI_W]
    sub ecx,16
    sar ecx,3
    cmp ecx,2
    jl .bad
    mov r13d,ecx
    mov ecx,[rax+WGI_H]
    sub ecx,8
    sar ecx,4
    cmp ecx,1
    jl .bad
    mov r14d,ecx
    test r12,r12
    jz .first
    xor ebp,ebp                        ; previous-page candidate
    cmp r12,2
    je .prev
    mov ebp,[r15+AR_TOP]
    call ar_page_end
    cmp rax,[r15+AR_LEN]
    jae .ok                            ; keep the final nonempty page
    mov [r15+AR_TOP],rax
    jmp .draw
.prev:
    xor r12d,r12d
.prev_scan:
    cmp rbp,[r15+AR_TOP]
    jae .previous
    mov r12,rbp
    call ar_page_end
    cmp eax,ebp
    jbe .previous
    mov ebp,eax
    jmp .prev_scan
.previous:
    mov [r15+AR_TOP],r12
    jmp .draw
.first:
    mov qword [r15+AR_TOP],0
.draw:
    mov edi,ebx
    call wgt_draw_id
.ok:
    xor eax,eax
    jmp .out
.bad:
    mov eax,1
.out:
    add rsp,8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; Private page walk: EBP start,R13D columns,R14D rows,R15 context ->EAX end.
ar_page_end:
    push rbx
    push rbp
    push r12
    mov ebx,ebp
    mov r12d,r14d
.loop:
    cmp rbx,[r15+AR_LEN]
    jae .out
    lea rdi,[r15+AR_BODY]
    mov esi,[r15+AR_LEN]
    mov edx,ebx
    mov ecx,r13d
    call ar_next
    cmp eax,ebx
    jbe .out
    mov ebx,eax
    dec r12d
    jnz .loop
.out:
    mov eax,ebx
    pop r12
    pop rbp
    pop rbx
    ret

; One plain row, no global file-view context. RDI bytes,ESI length,EDX start,
; ECX columns>=2 ->EAX next offset. At most4096 bytes; tv_unit sanitizes data.
ar_next:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov rbx,rdi
    mov r12d,edx
    mov r13d,ecx
    mov r14d,esi
    xor r15d,r15d
.loop:
    cmp r12d,r14d
    jae .out
    movzx eax,byte [rbx+r12]
    cmp eax,10
    je .lf
    cmp eax,13
    jne .unit
    lea eax,[r12+1]
    cmp eax,r14d
    jae .unit
    cmp byte [rbx+rax],10
    jne .unit
    inc r12d
.lf:
    inc r12d
    jmp .out
.unit:
    mov rdi,rbx
    mov esi,r14d
    mov edx,r12d
    call tv_unit
    add r15d,eax
    cmp r15d,r13d
    ja .out
    add r12d,ecx
    cmp r15d,r13d
    jb .loop
.out:
    mov eax,r12d
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Native painter. Bounds come from current widget geometry, never body bytes.
ar_draw:
    push rbp
    mov rbp,rsp
    and rsp,-16
    call ar_draw_body
    mov rsp,rbp
    pop rbp
    ret
ar_draw_body:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    sub rsp,56
    mov r12d,edi
    call wgt_slot_ptr
    mov r8d,[rax+WGI_X]
    mov r9d,[rax+WGI_Y]
    mov r10d,[rax+WGI_W]
    mov r11d,[rax+WGI_H]
    mov [rsp],r8d
    mov [rsp+4],r9d
    mov [rsp+8],r10d
    mov [rsp+12],r11d
    mov ebx,GUI_TOK_WINDOW_BODY
    call wgt_fill_rect
    sub dword [rsp+8],16
    sar dword [rsp+8],3
    cmp dword [rsp+8],2
    jl .out
    sub dword [rsp+12],8
    sar dword [rsp+12],4
    cmp dword [rsp+12],1
    jl .out
    mov edi,r12d
    xor esi,esi
    call ar_context
    test rax,rax
    jz .out
    mov r13,rax
    mov r14d,[r13+AR_TOP]
    xor ebp,ebp
.row:
    cmp ebp,[rsp+12]
    jae .out
    cmp r14,[r13+AR_LEN]
    jae .out
    lea rdi,[r13+AR_BODY]
    mov esi,[r13+AR_LEN]
    mov edx,r14d
    mov ecx,[rsp+8]
    call ar_next
    mov r15d,eax
    cmp r15d,r14d
    jbe .out
    mov dword [rsp+16],0               ; cell column
.unit:
    cmp r14d,r15d
    jae .next_row
    cmp byte [r13+AR_BODY+r14],10
    je .next_row
    cmp byte [r13+AR_BODY+r14],13
    jne .scalar
    lea eax,[r14+1]
    cmp eax,r15d
    jae .scalar
    cmp byte [r13+AR_BODY+rax],10
    je .next_row
.scalar:
    lea rdi,[r13+AR_BODY]
    mov esi,[r13+AR_LEN]
    mov edx,r14d
    call tv_unit
    add r14d,ecx
    mov [rsp+20],eax
    mov r8d,[rsp+16]
    shl r8d,3
    add r8d,[rsp]
    add r8d,8
    mov r9d,ebp
    shl r9d,4
    add r9d,[rsp+4]
    add r9d,4
    mov ebx,GUI_TOK_LABEL_TEXT
    mov ecx,GUI_TOK_WINDOW_BODY
    call tv_paint_unit
    mov eax,[rsp+20]
    add [rsp+16],eax
    jmp .unit
.next_row:
    mov r14d,r15d
    inc ebp
    jmp .row
.out:
    add rsp,56
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

ar_name: db 'appreader',0
%include "core/abi/wdata.inc"
%macro WDATA_gui_app_reader 0
align 8
app_reader_type: dd -1
%endmacro
WDATA_DEFER WDATA_gui_app_reader
%macro WDATA_BSS_gui_app_reader 0
alignb 8
ar_contexts: resb AR_SIZE*APR_CONTEXT_COUNT
%endmacro
WDATA_BSS_DEFER WDATA_BSS_gui_app_reader
