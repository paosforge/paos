;; MODULE gui/app_launcher
;; LAYER 6
;; PURPOSE Checked bundle desktop entry and app-owned native form projection.
;; EXPORTS app_launcher_image_find, app_launcher_image_provenance, app_launcher_form_find, app_launcher_form_member, app_launcher_terminal_activation_begin, app_launcher_terminal_snapshot, app_launcher_terminal_validate, app_launcher_terminal_queue, app_launcher_terminal_current, app_launcher_observe, app_launcher_ended, app_launcher_stopped, app_launcher_init, app_launcher_configure, app_launcher_publish, app_launcher_clear, app_launcher_quiesce, app_launcher_form, app_launcher_tick, app_launcher_status, app_launcher_complete, app_launcher_chat_target, app_launcher_form_staged, app_launcher_failed, app_launcher_timings, app_launcher_click_observe
;; IMPORTS gui/img/img_cache, core/lib/sha256, core/lib/str, cognition/ai_intent_controller, svc/app_script, svc/command, sec/session, gui/widget, gui/window_mgmt, gui/form_loader, gui/wm_pointer, gui/window, boot/gop, core/time, core/smp, hv/vmx, hv/app_vm_memory
;; OWNER saga:app_launcher
; This is checked native data/UI, never a guest executor or binding validator.
; Actual isolated VM lifecycle/resolver composition installs the native callback.
; NULL by default: a click cannot launch through the driver guest/root PIO.
AL_DESC equ 384
AL_INDEX_MAX equ 1280
AL_FORM_MAX equ 1535
AL_FORM_MEMBERS equ 4
AL_ICON_EDGE equ 48
AL_IMAGES equ 4                    ; widgets-01 A4: kind-8 app images
AL_IMAGE_MAX equ 40960
AL_IMAGE_ROW equ 24                ; img_assets row shape: name, ptr, len
AL_ICON_BYTES equ 9216
AL_IDLE equ 0
AL_QUEUED equ 1
AL_NO_EXECUTOR equ 2
AL_REFUSED equ 3
AL_STARTED equ 4
AL_STARTING equ 5
AL_STOPPED equ 6

app_launcher_init:
    cmp byte [rel al_initialized], 0
    jne .out
    mov rax, [rel wgt_click_hook]
    mov [rel al_click_prev], rax
    lea rax, [rel al_click]
    mov [rel wgt_click_hook], rax
    mov rax, [rel wgt_button_paint_hook]
    mov [rel al_paint_prev], rax
    lea rax, [rel al_button_paint]
    mov [rel wgt_button_paint_hook], rax
    mov byte [rel al_initialized], 1
.out:
    ret

; Native lifecycle composition only, depth0. Does not assert VM proof, configure
; grants, dispatch a verb, or expose a guest setter. Callback(handle,attempt)
; ->1 only after actual activation, 2 pending, otherwise refusal. Completion is
; native-only, exact attempt, and never a guest-supplied success indication.
app_launcher_configure:
    cmp byte [rel cmd_in_dispatch], 0
    jne al_bad
    mov qword [rel al_active_attempt], 0
    mov qword [rel al_chat_attempt],0
    mov [rel al_launch], rdi
    mov qword [rel al_pending], 0
    mov byte [rel al_terminal_queued],0
    mov dword [rel al_status], AL_IDLE
    mov qword [rel al_lifecycle_attempt],0
    mov qword [rel al_request_us],0
    mov qword [rel al_feedback_us],0
    call al_click_clock_clear
    mov eax, 1
    ret

; Publish one current verified signed snapshot as a stock desktop button.
; RDI=opaque native app_script handle. No launch or effective grant occurs.
; One to four complete forms are copied, uniquely named and fully linted.
; All declarations stay pinned until every borrowing native window is gone.
app_launcher_publish:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    cmp byte [rel cmd_in_dispatch], 0
    jne .bad
    cmp qword [rel al_handle], 0
    jne .bad
    cmp byte [rel al_initialized], 1
    jne .bad
    call session_shell_require_unlocked
    test eax, eax
    jnz .bad
    test r12, r12
    jz .bad
    mov rdi, r12
    lea rsi, [rel al_scratch]
    mov edx, AL_DESC
    call app_script_descriptor
    cmp eax, 1
    jne .bad
    cmp qword [rel al_scratch], 1
    jne .bad
    cmp [rel al_scratch+8], r12
    jne .bad
    cmp qword [rel al_scratch+24], 2
    jb .bad
    cmp qword [rel al_scratch+24], 16
    ja .bad
    mov rax,[rel al_scratch+336]
    cmp rax,320
    je .index_base
    cmp rax,576
    jne .bad
.index_base:
    mov rax, [rel al_scratch+24]
    imul rax, 80
    cmp [rel al_scratch+344], rax
    jne .bad
    add rax,[rel al_scratch+336]
    cmp [rel al_scratch+352], rax
    jne .bad
    cmp qword [rel al_scratch+368], 1
    jne .bad
    cmp qword [rel al_scratch+376], 0
    jne .bad
    mov rdi, r12
    mov rsi,[rel al_scratch+336]
    lea rdx, [rel al_index]
    mov rcx, [rel al_scratch+344]
    call app_script_copy
    cmp eax, 1
    jne .bad
    ; widgets-01 A4 (SEC A3): images before forms, so lint resolves them.
    mov rdi, r12
    call al_images_publish
    cmp eax, 1
    jne .bad
    xor ebx, ebx
    xor r13d, r13d                     ; exact checked form count
.scan:
    mov eax, ebx
    imul eax, 80
    lea rdx, [rel al_index]
    add rdx, rax
    cmp dword [rdx], 2
    jne .next
    cmp r13d, AL_FORM_MEMBERS
    jae .bad
    mov r14d, [rdx+4]
    mov r15d, [rdx+8]
    test r15d, r15d
    jz .bad
    cmp r15d, AL_FORM_MAX
    ja .bad
    mov rsi, [rel al_scratch+352]
    add rsi, r14
    jc .bad
    imul eax, r13d, AL_FORM_MAX+1
    lea rdx, [rel al_form]
    add rdx, rax
    mov rdi, r12
    mov rcx, r15
    call app_script_copy
    cmp eax, 1
    jne .bad
    ; Private stable buffers, never an asset/index pointer retained by a VM.
    imul eax, r13d, AL_FORM_MAX+1
    lea rsi, [rel al_form]
    add rsi, rax
    mov eax, r13d
    shl eax, 6
    lea rdi, [rel al_form_name]
    add rdi, rax
    call al_form_name_copy
    cmp eax, 1
    jne .bad
    imul eax, r13d, AL_FORM_MAX+1
    lea rdi, [rel al_form]
    add rdi, rax
    mov eax, r13d
    shl eax, 6
    lea rdx, [rel al_form_name]
    add rdx, rax
    mov rsi, r15
    mov [rel al_image_scope], r12      ; this candidate's own rows only
    call form_lint_blob
    mov qword [rel al_image_scope], 0
    test eax, eax
    jnz .bad
    ; Name is the member selector. Duplicate names may not alias another form.
    xor r14d, r14d
.unique:
    cmp r14d, r13d
    jae .unique_done
    mov eax, r13d
    shl eax, 6
    lea rdi, [rel al_form_name]
    add rdi, rax
    mov eax, r14d
    shl eax, 6
    lea rsi, [rel al_form_name]
    add rsi, rax
    call strcmp
    test rax, rax
    jz .bad
    inc r14d
    jmp .unique
.unique_done:
    lea rax, [rel al_form_lengths]
    mov [rax+r13*8], r15
    inc r13d
.next:
    inc ebx
    cmp rbx, [rel al_scratch+24]
    jb .scan
    test r13d, r13d
    jz .bad
    mov [rel al_form_count], r13d
    ; Copy bounded checked bundle id. Descriptor is verified native data, but
    ; never permit an unterminated id to escape into widget text/title storage.
    lea rsi, [rel al_scratch+96]        ; manifest80 + bundle-id16
    lea rdi, [rel al_name]
    mov ecx, 64
.name:
    lodsb
    stosb
    test al, al
    jz .name_done
    loop .name
    jmp .bad
.name_done:
    cmp byte [rel al_name], 0
    je .bad
    ; VM-owned cache-copy ABI92267: only a current trusted handle, caller-owned
    ; tightly packed48x48 straightRGBA. Genuine absence (2) uses stock text;
    ; refusal (0) aborts publication. Never called from a paint/input path.
    xor r13d, r13d
    mov rdi, r12
    lea rsi, [rel al_icon_pixels]
    mov edx, AL_ICON_BYTES
    mov ecx, AL_ICON_EDGE
    call app_script_icon_copy
    cmp eax, 2
    je .icon_ready
    cmp eax, 1
    jne .bad
    mov r13d, 1
.icon_ready:
    ; Re-read after lint/cache copy before publishing: handle/trust/session must still be
    ; current and the whole immutable descriptor must be exactly unchanged.
    mov rdi, r12
    lea rsi, [rel al_current]
    mov edx, AL_DESC
    call app_script_descriptor
    cmp eax, 1
    jne .bad
    lea rdi, [rel al_scratch]
    lea rsi, [rel al_current]
    mov ecx, AL_DESC/8
    repe cmpsq
    jne .bad
    cmp dword [rel fb_width], 160
    jb .bad
    cmp dword [rel fb_height], 120
    jb .bad
    mov edi, 1
    call wgt_reserve_run
    cmp eax, -1
    je .bad
    mov [rel wgt_alloc_next], eax
    xor edi, edi                       ; maintained button type 0
    xor esi, esi                       ; create using real WM slot0 geometry
    call wgt_create
    mov dword [rel wgt_alloc_next], -1
    cmp eax, -1
    je .bad
    mov ebx, eax
    mov edi, eax
    call wgt_slot_ptr
    mov dword [rax+WGI_WIN], WGT_HOST_DESKTOP
    mov dword [rax+WGI_LAYER], 0
    mov dword [rax+WGI_FLAGS], 1
    mov dword [rax+WGI_EDIT], 0
    mov dword [rax+WGI_X], 16
    mov dword [rax+WGI_Y], 16
    mov dword [rax+WGI_W], 128
    mov dword [rax+WGI_H], 40
    test r13d, r13d
    jz .text_geometry
    mov dword [rax+WGI_Y], 4
    mov dword [rax+WGI_H], 56
.text_geometry:
    lea rdx, [rel al_widget_id]
    mov [rax+WGI_ID], rdx
    lea rdx, [rel al_role]
    mov [rax+WGI_ROLE], rdx
    lea rdx, [rel al_name]
    mov [rax+WGI_LABEL], rdx
    mov edi, ebx
    lea rsi, [rel al_name]
    call wgt_set_text
    mov [rel al_widget], ebx
    mov rax, [rel al_form_lengths]
    mov [rel al_form_len], rax
    lea rsi, [rel al_scratch]
    lea rdi, [rel al_descriptor]
    mov ecx, AL_DESC/8
    rep movsq
    mov [rel al_icon_valid], r13b
    mov rax, [rel session_authority_epoch]
    mov [rel al_owner_epoch], rax
    mov rax, [rel session_bound_pid]
    mov [rel al_owner], rax
    mov byte [rel al_withdrawing], 0
    mov [rel al_handle], r12            ; commit only after all checked data/UI
    mov dword [rel al_status], AL_IDLE
    mov qword [rel al_lifecycle_attempt],0
    mov qword [rel al_request_us],0
    mov qword [rel al_feedback_us],0
    call al_click_clock_clear
    call wmx_draw_all
    mov eax, 1
    jmp .out
.bad:
    ; Rows this refused candidate copied never stay visible. A live app's
    ; rows (owner is the committed al_handle) are never touched here.
    cmp [rel al_image_owner], r12
    jne .refused
    cmp [rel al_handle], r12
    je .refused
    call al_images_drop
.refused:
    xor eax, eax
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; widgets-01 A4. RDI=candidate handle whose verified index is in al_index and
; descriptor in al_scratch. SEC A3 order: (1) refuse while any app form is
; live, (2)+(3) al_images_drop zeroes then forgets every row and refuses if
; one is pinned, (4) copy each kind-8 member from the verified stage only,
; (5) publish its row. EAX=1 copied (zero images is 1), 0 refused.
al_images_publish:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov r12, rdi
    call form_app_members_busy
    test eax, eax
    jnz .bad
    call al_images_drop
    cmp eax, 1
    jne .bad
    xor ebx, ebx                       ; index member
    xor r13d, r13d                     ; image rows published
.scan:
    imul eax, ebx, 80
    lea r14, [rel al_index]
    add r14, rax
    cmp dword [r14], 8
    jne .next
    cmp r13d, AL_IMAGES
    jae .bad
    mov r15d, [r14+8]
    test r15d, r15d
    jz .bad
    cmp r15d, AL_IMAGE_MAX
    ja .bad
    cmp byte [r14+16+63], 0            ; stage pinned NUL padding; recheck
    jne .bad
    mov eax, r13d
    shl eax, 6
    lea rdi, [rel al_image_name]
    add rdi, rax
    lea rsi, [r14+16]
    mov ecx, 64
    rep movsb
    mov rsi, [rel al_scratch+352]
    mov eax, [r14+4]
    add rsi, rax
    jc .bad
    imul eax, r13d, AL_IMAGE_MAX
    lea rdx, [rel al_image]
    add rdx, rax
    mov rdi, r12
    mov rcx, r15
    call app_script_copy
    cmp eax, 1
    jne .bad
    mov eax, r13d                      ; SEC A7: provenance digest of the copy
    shl eax, 5
    lea rdi, [rel al_image_sha]
    add rdi, rax
    imul eax, r13d, AL_IMAGE_MAX
    lea rsi, [rel al_image]
    add rsi, rax
    mov rdx, r15
    call sha256_hash
    test rax, rax
    jnz .bad
    imul eax, r13d, AL_IMAGE_ROW
    lea rdi, [rel al_image_rows]
    add rdi, rax
    mov eax, r13d
    shl eax, 6
    lea rdx, [rel al_image_name]
    add rdx, rax
    mov [rdi], rdx
    imul eax, r13d, AL_IMAGE_MAX
    lea rdx, [rel al_image]
    add rdx, rax
    mov [rdi+8], rdx
    mov [rdi+16], r15
    inc r13d
    mov [rel al_image_count], r13d
    mov [rel al_image_owner], r12
.next:
    inc ebx
    cmp rbx, [rel al_scratch+24]
    jb .scan
    mov eax, 1
    jmp .out
.bad:
    xor eax, eax
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Retire every app image row: (2) zero its pointer/length, (3) forget every
; cache key on that row. EAX=1 done, 0 when a row is the pinned asset
; (checked first, so a refusal changes nothing).
al_images_drop:
    push rbx
    xor ebx, ebx
.pin_check:
    imul eax, ebx, AL_IMAGE_ROW
    lea rdi, [rel al_image_rows]
    add rdi, rax
    cmp rdi, [rel img_cache_pin_asset]
    je .pinned
    inc ebx
    cmp ebx, AL_IMAGES
    jb .pin_check
    mov dword [rel al_image_count], 0
    mov qword [rel al_image_owner], 0
    xor ebx, ebx
.row:
    imul eax, ebx, AL_IMAGE_ROW
    lea rdi, [rel al_image_rows]
    add rdi, rax
    mov qword [rdi], 0
    mov qword [rdi+8], 0
    mov qword [rdi+16], 0
    push rdi
    mov eax, ebx
    shl eax, 5
    lea rdi, [rel al_image_sha]
    add rdi, rax
    xor eax, eax
    mov ecx, 4
    rep stosq
    pop rdi
    call img_cache_forget
    test eax, eax
    jnz .pinned
    inc ebx
    cmp ebx, AL_IMAGES
    jb .row
    mov eax, 1
    pop rbx
    ret
.pinned:
    xor eax, eax
    pop rbx
    ret

; SEC A7 provenance. RDI=image row -> RAX=owning handle (0 when RDI is not a
; live app row), RDX=its path, RCX=sha256 of its copied bytes. Pure read.
app_launcher_image_provenance:
    xor eax, eax
    lea rdx, [rel al_image_rows]
    mov rcx, rdi
    sub rcx, rdx
    jb .out
    cmp rcx, AL_IMAGE_ROW*AL_IMAGES
    jae .none
    push rdx
    mov rax, rcx
    xor edx, edx
    mov ecx, AL_IMAGE_ROW
    div rcx
    test edx, edx
    pop rdx
    jnz .none
    cmp eax, [rel al_image_count]
    jae .none
    cmp qword [rdi+8], 0
    je .none
    shl eax, 5
    lea rcx, [rel al_image_sha]
    add rcx, rax
    mov rdx, [rdi]
    mov rax, [rel al_image_owner]
    ret
.none:
    xor eax, eax
.out:
    ret

; Form parser .src for an images/ name. RDI=NUL path -> RAX=row or 0. Only
; while the launcher has scoped a lint or load to the handle owning the rows;
; exact byte compare, no case fold or prefix match.
app_launcher_image_find:
    push rbx
    push r12
    push r13
    mov r12, rdi
    mov rax, [rel al_image_scope]
    test rax, rax
    jz .miss
    cmp rax, [rel al_image_owner]
    jne .miss
    xor r13d, r13d
    lea rbx, [rel al_image_rows]
.scan:
    cmp r13d, [rel al_image_count]
    jae .miss
    cmp qword [rbx+8], 0
    je .next
    mov rdi, [rbx]
    mov rsi, r12
    call strcmp
    test rax, rax
    jz .hit
.next:
    add rbx, AL_IMAGE_ROW
    inc r13d
    jmp .scan
.hit:
    mov rax, rbx
    jmp .out
.miss:
    xor eax, eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Bounded metadata extraction from copied form bytes. This recognizes only
; the first declaration name; form_lint_blob remains the complete grammar gate.
; RSI=copied form, RDI=private64B name, R15=exact byte length. No pointers escape.
al_form_name_copy:
    cmp r15, 8
    jb al_bad
    cmp dword [rsi], 'form'
    jne al_bad
    cmp byte [rsi+4], ' '
    jne al_bad
    mov ecx, 5
    xor edx, edx
.loop:
    cmp rcx, r15
    jae al_bad
    movzx eax, byte [rsi+rcx]
    cmp al, ' '
    je .end
    cmp al, '!'
    jb al_bad
    cmp al, '~'
    ja al_bad
    cmp edx, 63
    jae al_bad
    mov [rdi+rdx], al
    inc edx
    inc ecx
    jmp .loop
.end:
    test edx, edx
    jz al_bad
    mov byte [rdi+rdx], 0
    mov eax, 1
    ret

; No authority return: exact currently trusted snapshot equality only.
al_current_snapshot:
    cmp byte [rel al_withdrawing], 0
    jne al_bad
    mov rdi, [rel al_handle]
    test rdi, rdi
    jz al_bad
    lea rsi, [rel al_current]
    mov edx, AL_DESC
    call app_script_descriptor
    cmp eax, 1
    jne al_bad
    lea rdi, [rel al_descriptor]
    lea rsi, [rel al_current]
    mov ecx, AL_DESC/8
    repe cmpsq
    jne al_bad
    mov eax, 1
    ret

; Native Terminal finite launch operand400: immutable verified descriptor384
; followed by a nonreused attempt8 and exact executor8. No app binding or effective grants here.
; Snapshot/validate are read-only. SEC admits the queue at its original command
; leaf; the literal native callback checks the retained delegated authority on
; later depth-zero turns. Ordinary physical launch gates remain unchanged.
app_launcher_terminal_snapshot:
    push rbx
    mov rbx,rdi
    call al_terminal_idle
    cmp eax,1
    jne .bad
    call al_terminal_snapshot_current
    cmp eax,1
    jne .bad
    mov rdi,rbx
    lea rsi,[rel al_descriptor]
    mov ecx,AL_DESC/8
    rep movsq
    mov rax,[rel al_attempt_serial]
    inc rax
    mov [rdi],rax
    mov rax,[rel al_launch]
    mov [rdi+8],rax
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; RDI frozen operand400 ->1 only the same current publication and attempt.
; This observer never calls SEC (SEC uses it inside its own validation).
app_launcher_terminal_validate:
    push rbx
    mov rbx,rdi
    call al_terminal_snapshot_current
    cmp eax,1
    jne .bad
    mov rdi,rbx
    lea rsi,[rel al_descriptor]
    mov ecx,AL_DESC/8
    repe cmpsq
    jne .bad
    mov rax,[rbx+AL_DESC+8]
    cmp rax,[rel al_launch]
    jne .bad
    mov rax,[rbx+AL_DESC]
    test rax,rax
    jz .bad
    cmp rax,[rel al_terminal_attempt]
    je .queued
    call al_terminal_idle
    cmp eax,1
    jne .bad
    mov rax,[rel al_attempt_serial]
    inc rax
    cmp rax,[rbx+AL_DESC]
    jne .bad
    jmp .ok
.queued:
    ; A retained receipt is bound to exactly the original queued attempt,
    ; never a later pointer/tap launch of the same published app.
    mov rax,[rbx+8]
    cmp rax,[rel al_terminal_handle]
    jne .bad
    mov rdi,rbx
    lea rsi,[rel al_terminal_operand]
    mov ecx,(AL_DESC+16)/8
    repe cmpsq
    jne .bad
    mov rax,[rel al_lifecycle_attempt]
    cmp rax,[rel al_terminal_attempt]
    jne .bad
.ok:
    mov eax,1
    pop rbx
    ret
.bad:
    xor eax,eax
    pop rbx
    ret

; Native original-request leaf only. RDI frozen operand400, RSI literal native
; deferred-current(handle,attempt)->1 callback, never a guest-selected pointer.
; Queue acceptance is pending, not activation. The existing owner policy panel
; still obtains its separate physical per-app choices and Start.
app_launcher_terminal_queue:
    push rbx
    push r12
    mov rbx,rdi
    mov r12,rsi
    test r12,r12
    jz .bad
    cmp byte [rel cmd_in_dispatch],1
    jne .bad
    call al_terminal_idle
    cmp eax,1
    jne .bad
    mov rdi,rbx
    call app_launcher_terminal_validate
    cmp eax,1
    jne .bad
    mov rax,[rel al_attempt_serial]
    inc rax
    cmp rax,[rbx+AL_DESC]
    jne .bad                         ; retained receipts cannot queue again
    mov rsi,rbx
    lea rdi,[rel al_terminal_operand]
    mov ecx,(AL_DESC+16)/8
    rep movsq
    mov rax,[rbx+AL_DESC]
    mov [rel al_attempt_serial],rax    ; reserve once, never wrap/reuse
    mov [rel al_terminal_attempt],rax
    mov [rel al_lifecycle_attempt],rax
    mov [rel al_terminal_check],r12
    mov byte [rel al_terminal_queued],1
    mov byte [rel al_terminal_completed],0
    mov byte [rel al_terminal_activation_spent],0
    mov rax,[rbx+8]
    mov [rel al_terminal_handle],rax
    mov [rel al_pending],rax
    mov dword [rel al_status],AL_QUEUED
    call al_queued_feedback
    mov eax,1
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r12
    pop rbx
    ret

; Existing non-Terminal attempts keep their original OWNER/session gates.
; Terminal's exact pending attempt additionally keeps its original delegated
; authority until actual activation. A later app lifetime uses app binding.
app_launcher_terminal_current:
    cmp rsi,[rel al_terminal_attempt]
    jne .ordinary
    cmp rdi,[rel al_terminal_handle]
    jne al_bad
    cmp byte [rel al_terminal_completed],1
    je .ordinary
    cmp dword [rel al_status],AL_QUEUED
    je .pending
    cmp dword [rel al_status],AL_STARTING
    je .pending
    cmp byte [rel al_terminal_activation_spent],1
    jne al_bad
    cmp dword [rel al_status],AL_STARTED
    jne al_bad
.pending:
    push rbx
    push r12
    mov rbx,rdi
    mov r12,rsi
    lea rdi,[rel al_terminal_operand]
    call app_launcher_terminal_validate
    cmp eax,1
    jne .bad
    mov rax,[rel al_terminal_check]
    test rax,rax
    jz .bad
    mov rdi,rbx
    mov rsi,r12
    call rax
    jmp .out
.bad:
    xor eax,eax
.out:
    pop r12
    pop rbx
    ret
.ordinary:
    mov eax,1
    ret

 ; Actual activation leaf only. Consume before app_vm_activate; never infer
; completion from this admission. Any failed/uncertain activation is terminal.
app_launcher_terminal_activation_begin:
    cmp rsi,[rel al_terminal_attempt]
    jne .ordinary
    cmp rdi,[rel al_terminal_handle]
    jne al_bad
    cmp byte [rel al_terminal_completed],0
    jne al_bad
    cmp byte [rel al_terminal_activation_spent],0
    jne al_bad
    call app_launcher_terminal_current
    cmp eax,1
    jne al_bad
    mov byte [rel al_terminal_activation_spent],1
.ordinary:
    mov eax,1
    ret

al_terminal_idle:
    cmp byte [rel al_initialized],1
    jne al_bad
    cmp byte [rel al_withdrawing],0
    jne al_bad
    cmp qword [rel al_launch],0
    je al_bad
    cmp qword [rel al_pending],0
    jne al_bad
    cmp qword [rel al_active_attempt],0
    jne al_bad
    cmp dword [rel al_status],AL_STARTED
    je al_bad
    cmp qword [rel al_attempt_serial],-1
    je al_bad
    mov eax,1
    ret

; app_script's native descriptor observes the actual OWNER-owned staging
; lifetime from inside a Terminal registry frame without borrowing OWNER.
al_terminal_snapshot_current:
    cmp byte [rel al_withdrawing],0
    jne al_bad
    mov rdi,[rel al_handle]
    test rdi,rdi
    jz al_bad
    lea rsi,[rel al_current]
    mov edx,AL_DESC
    call app_script_native_descriptor
    cmp eax,1
    jne al_bad
    lea rdi,[rel al_descriptor]
    lea rsi,[rel al_current]
    mov ecx,AL_DESC/8
    repe cmpsq
    jne al_bad
    mov eax,1
    ret

; Native REMOVE UI leaf: RDI mapped/disjoint digest32, RSI current owner epoch.
; Internal RDX:0 first capture,-1 original absent,else exact original handle.
; Returns captured RDX even when clear succeeds; only flow owns this selector.
; 1 exact entry withdrawn/absent,2 matching storage still backs a live form,
; 0 refused. This is not VM retirement or durable removal success. Caller has
; persisted REMOVING denial and consumed its physical confirmation already.
; Match retained immutable data even after staging/trust changes; never ask a
; fresh descriptor to identify the old object. Unrelated entries stay intact.
app_launcher_quiesce:
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 8
    mov r13, rdx                     ; 0 capture, -1 absent, otherwise original handle
    mov r14, -1
    mov rbx, rdi
    mov r12, rsi
    cmp byte [rel cmd_in_dispatch], 0
    jne .bad
    call smp_current_logical
    test eax, eax
    jnz .bad
    test rbx, rbx
    jz .bad
    mov rax, rbx
    add rax, 32
    jc .bad
    mov rcx, rbx
    shl rcx, 16
    sar rcx, 16
    cmp rcx, rbx
    jne .bad
    lea rdx, [rax-1]
    mov rcx, rdx
    shl rcx, 16
    sar rcx, 16
    cmp rcx, rdx
    jne .bad
    ; The native caller owns mapped lifetime. Reject the complete span on
    ; wrap, VM broker alias or any overlap with this module's private state.
    mov rcx, [rel avm_base]
    mov rdx, [rel avm_capacity]
    test rcx, rcx
    jz .no_vm_base
    test rdx, rdx
    jz .bad
    add rdx, rcx
    jc .bad
    cmp rax, rcx
    jbe .linux_vm
    cmp rbx, rdx
    jb .bad                         ; app VM span
    jmp .linux_vm
.no_vm_base:
    test rdx, rdx
    jnz .bad
.linux_vm:
    mov rcx, [rel hv_linux_region]
    mov rdx, [rel hv_linux_region_capacity]
    test rdx, rdx
    jz .native
    test rcx, rcx
    jz .bad
    add rdx, rcx
    jc .bad
    cmp rax, rcx
    jbe .native
    cmp rbx, rdx
    jb .bad                         ; Linux guest span
.native:
    lea rcx, [rel al_private_end]
    cmp rbx, rcx
    jae .bss
    lea rcx, [rel al_initialized]
    cmp rax, rcx
    ja .bad
.bss:
    lea rcx, [rel al_private_bss_end]
    cmp rbx, rcx
    jae .authority
    lea rcx, [rel al_descriptor]
    cmp rax, rcx
    ja .bad
.authority:
    call session_shell_local_authority
    cmp rax, PRIN_OWNER
    jne .bad
    test r12, r12
    jz .bad
    cmp rdx, r12
    jne .bad
    cmp r13, -1
    je .absent
    test r13, r13
    jz .identity
    mov r14, r13
    cmp r13, [rel al_handle]
    jne .absent                     ; a replacement handle is never ours
.identity:
    cmp qword [rel al_handle], 0
    je .absent
    cmp r12, [rel al_owner_epoch]
    jne .absent
    cmp rax, [rel al_owner]
    jne .absent
    mov rsi, rbx
    lea rdi, [rel al_descriptor+32]
    mov ecx, 4
    cld
    repe cmpsq
    jne .absent
    ; Denial precedes close/reap. No pending pointer, TAP, form or completion
    ; may revive this entry while its original VM is still retiring.
    mov r14, [rel al_handle]         ; survive clear/reap for continuation
    mov byte [rel al_withdrawing], 1
    mov qword [rel al_pending], 0
    mov qword [rel al_active_attempt], 0
    mov qword [rel al_chat_attempt], 0
    call app_launcher_clear
    test eax, eax
    jnz .out
    mov eax, 2
    jmp .out
.absent:
    mov eax, 1
    jmp .out
.bad:
    xor eax, eax
.out:
    mov rdx, r14                    ; private continuation identity, not public ABI
    add rsp, 8
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; Original native launcher owns VM retirement and form close before uninstall.
; Clearing this UI entry alone does not report or simulate execution teardown.
app_launcher_clear:
    cmp byte [rel cmd_in_dispatch], 0
    jne al_bad
    cmp byte [rel al_form_created], 0
    je .no_live_form
    call form_app_members_busy
    test eax, eax
    jnz al_bad                         ; storage still backs a live form
.no_live_form:
    call al_images_drop                ; widgets-01 A4: zero + forget rows
    cmp eax, 1
    jne al_bad                         ; pinned row: nothing else cleared
    mov byte [rel al_withdrawing], 0
    mov byte [rel al_form_created], 0
    mov byte [rel al_icon_valid], 0
    lea rdi, [rel al_icon_pixels]
    mov ecx, 2*AL_ICON_BYTES/8          ; decoded cache + adjacent matte scratch
    xor eax, eax
    rep stosq
    mov qword [rel al_active_attempt], 0
    mov qword [rel al_chat_attempt],0
    mov qword [rel al_handle], 0
    mov qword [rel al_pending], 0
    mov byte [rel al_terminal_queued],0
    mov qword [rel al_form_len], 0
    mov dword [rel al_form_count], 0
    mov dword [rel al_status], AL_IDLE
    mov qword [rel al_lifecycle_attempt],0
    mov qword [rel al_request_us],0
    mov qword [rel al_feedback_us],0
    call al_click_clock_clear
    mov edi, [rel al_widget]
    mov dword [rel al_widget], -1
    cmp edi, [rel wgt_count]
    jae .done
    call wgt_slot_ptr
    lea rdx, [rel al_widget_id]
    cmp [rax+WGI_ID], rdx
    jne .done                          ; never retire a reused widget
    cmp dword [rax+WGI_WIN], WGT_HOST_DESKTOP
    jne .done
    mov dword [rax+WGI_FLAGS], 0
    mov dword [rax+WGI_TYPE], 0
.done:
    mov eax, 1
    ret

; Native real-VM composition invokes only after it has an enforced principal.
; RDI=exact handle, RSI=actual principal; returns original loader EAX/ECX/EDX.
; No invented VM binding, grants or script execution is performed here.
app_launcher_form_staged:
    mov r8d,1
    xor edx,edx
    jmp al_form_entry
app_launcher_form:
    xor r8d,r8d
    xor edx,edx
    jmp al_form_entry
; Native lookup in the copied verified member names. RDI exact handle,
; RSI bounded NUL name (at most63 bytes) -> EAX member index or -1.
; This is a selector only, never authority to load another package or principal.
app_launcher_form_find:
    push rbx
    push r12
    push r13
    mov rbx,rsi
    xor r12d,r12d
    cmp byte [rel cmd_in_dispatch],0
    jne .bad
    test rbx,rbx
    jz .bad
    cmp rdi,[rel al_handle]
    jne .bad
    sub rsp,8                         ; frameless helper calls descriptor
    call al_current_snapshot
    add rsp,8                         ; keep member-loader call aligned
    cmp eax,1
    jne .bad
.next:
    cmp r12d,[rel al_form_count]
    jae .bad
    mov eax,r12d
    shl eax,6
    lea r13,[rel al_form_name]
    add r13,rax
    xor ecx,ecx
.char:
    mov al,[rbx+rcx]
    cmp al,[r13+rcx]
    jne .other
    test al,al
    jz .found
    inc ecx
    cmp ecx,64
    jb .char
.other:
    inc r12d
    jmp .next
.found:
    mov eax,r12d
    jmp .out
.bad:
    mov eax,-1
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Native checked member projection: RDI handle, RSI actual app principal,
; EDX member0..count-1, ECX staged0/1. No guest selector or grant here.
app_launcher_form_member:
    mov r8d,ecx
al_form_entry:
    push r12
    push r13
    push rbx
    mov r12d,r8d
    mov r13d,edx
    mov rbx,rsi
    cmp byte [rel cmd_in_dispatch],0
    jne .bad
    cmp rdi,[rel al_handle]
    jne .bad
    cmp r13d,[rel al_form_count]
    jae .bad
    cmp r12d,1
    ja .bad
    sub rsp,8                         ; frameless helper calls descriptor
    call al_current_snapshot
    add rsp,8                         ; keep member-loader call aligned
    cmp eax,1
    jne .bad
    imul eax,r13d,AL_FORM_MAX+1
    lea rdi,[rel al_form]
    add rdi,rax
    lea rax,[rel al_form_lengths]
    mov rsi,[rax+r13*8]
    mov eax,r13d
    shl eax,6
    lea rdx,[rel al_form_name]
    add rdx,rax
    mov rcx,rbx
    mov r8d,r13d
    mov r9d,r12d
    mov rax,[rel al_handle]
    mov [rel al_image_scope],rax       ; A4: this app's rows during the load
    call form_load_app_member_blob
    mov qword [rel al_image_scope],0
    test eax,eax
    jnz .returned
    mov byte [rel al_form_created],1
.returned:
    pop rbx
    pop r13
    pop r12
    ret
.bad:
    mov eax,1
    jmp .returned

al_click:
    cmp edi, [rel al_widget]
    jne .chain
    cmp byte [rel al_withdrawing], 0
    jne .done
    cmp byte [rel wm_pointer_origin], WM_PTR_ORIGIN_HUMAN
    jne .done
    cmp byte [rel wm_pointer_gesture_origin], WM_PTR_ORIGIN_HUMAN
    jne .done                           ; an injected press with a human release
    cmp edi, [rel wgt_count]
    jae .done
    call wgt_slot_ptr
    lea rdx, [rel al_widget_id]
    cmp [rax+WGI_ID], rdx
    jne .done
    cmp dword [rax+WGI_WIN], WGT_HOST_DESKTOP
    jne .done
    cmp dword [rax+WGI_TYPE], 1          ; exact maintained button type
    jne .done
    test dword [rax+WGI_FLAGS], 1
    jz .done
    call session_shell_require_unlocked
    test eax, eax
    jnz .done
    mov rax, [rel al_handle]
    test rax, rax
    jz .done
    cmp qword [rel al_active_attempt], 0
    jne .done
    cmp qword [rel al_pending],0
    jne .done                          ; first queued intent/timestamp wins
    cmp dword [rel al_status],AL_STARTED
    je .done                           ; preserve the running instance/target
    mov [rel al_pending], rax           ; no dispatch/VM effect inside input
    mov dword [rel al_status], AL_QUEUED
    call al_queued_feedback
    mov rax,[rel al_request_us]         ; accepted physical queue, before paint time
    mov [rel al_pointer_pending_us],rax
    mov rax,[rel al_pending]
    mov [rel al_pointer_pending_handle],rax
.done:
    mov eax, 1
    ret
.chain:
    mov rax, [rel al_click_prev]
    test rax, rax
    jz .none
    jmp rax
.none:
    xor eax, eax
    ret

app_launcher_tick:
    cmp byte [rel cmd_in_dispatch], 0
    jne .out
    ; Peter87189: the existing sole consumer projects one fresh Win+Space TAP.
    ; Spend it even if no designated chat bundle is installed; never remember
    ; a press for a later install, replay persistent intent, or launch any other
    ; current bundle. The original owner-policy/VM callback still owns launch.
    call cog_ai_intent_take_tap
    cmp byte [rel al_withdrawing], 0
    jne .withdrawn
    cmp eax,2                          ; Copilot/voice gestures stay deferred
    jne .pending
    cmp byte [rel al_initialized],1
    jne .pending
    cmp qword [rel al_active_attempt],0
    jne .pending
    cmp dword [rel al_status],AL_STARTED
    je .pending                        ; another press cannot rebind a live chat
    cmp qword [rel al_pending],0
    jne .pending                       ; retain an already queued pointer intent
    cmp dword [rel al_name],0x736f6170  ; exact canonical "paos.chat", NUL included
    jne .pending
    cmp dword [rel al_name+4],0x6168632e
    jne .pending
    cmp word [rel al_name+8],0x0074
    jne .pending
    mov rax,[rel al_handle]
    test rax,rax
    jz .pending
    mov [rel al_pending],rax
    mov dword [rel al_status],AL_QUEUED
    call al_queued_feedback
.pending:
    cmp qword [rel al_pending], 0
    je .out
    mov rax, [rel al_pending]
    mov qword [rel al_pending], 0        ; spend input intent before callback
    cmp rax, [rel al_handle]
    jne .refused
    call session_shell_require_unlocked
    test eax, eax
    jnz .refused
    call al_current_snapshot
    cmp eax, 1
    jne .refused
    mov rax, [rel al_launch]
    test rax, rax
    jz .missing
    cmp byte [rel al_terminal_queued],1
    jne .physical_attempt
    mov byte [rel al_terminal_queued],0 ; spend before deferred admission
    mov rdi,[rel al_handle]
    mov rsi,[rel al_terminal_attempt]
    call app_launcher_terminal_current
    cmp eax,1
    jne .refused
    jmp .attempt_ready
.physical_attempt:
    cmp qword [rel al_attempt_serial], -1
    je .refused
    inc qword [rel al_attempt_serial]
.attempt_ready:
    mov rsi, [rel al_attempt_serial]
    mov [rel al_active_attempt], rsi
    mov [rel al_lifecycle_attempt],rsi
    mov rax,[rel al_pointer_pending_handle]
    cmp rax,[rel al_handle]
    jne .click_clock_done
    mov rax,[rel al_pointer_pending_us]
    mov [rel al_click_us],rax
    mov [rel al_click_attempt],rsi
    mov rax,[rel al_handle]
    mov [rel al_click_handle],rax
.click_clock_done:
    mov qword [rel al_pointer_pending_us],0
    mov qword [rel al_pointer_pending_handle],0
    mov dword [rel al_status], AL_STARTING
    call al_chat_capture_target        ; before the native policy panel changes focus
    mov rax,[rel al_launch]
    mov rdi, [rel al_handle]
    mov rsi,[rel al_active_attempt]
    call rax                           ; actual owned lifecycle, no fallback
    cmp eax, 2
    je .out                            ; pending is never reported STARTED
    mov edx, eax
    mov rdi, [rel al_handle]
    mov rsi, [rel al_active_attempt]
    jmp app_launcher_complete
.out:
    ret
.missing:
    call al_click_clock_clear
    mov byte [rel al_terminal_queued],0
    mov dword [rel al_status], AL_NO_EXECUTOR
    jmp al_feedback
.refused:
    call al_click_clock_clear
    mov byte [rel al_terminal_queued],0
    mov dword [rel al_status], AL_REFUSED
    jmp al_feedback
.withdrawn:
    call al_click_clock_clear
    mov byte [rel al_terminal_queued],0
    mov qword [rel al_pending], 0
    ret

; Exact nonreused attempt; invalidate before accepting a terminal native result.
; RDI handle, RSI attempt, EDX=1 actual activated, otherwise refusal ->1/0.
; This is not a command/guest setter. Original lifecycle owns cleanup.
app_launcher_complete:
    push rbx
    push r12
    push r13
    mov rbx,rdi
    mov r12,rsi
    mov r13d,edx
    cmp byte [rel cmd_in_dispatch],0
    jne .bad
    test r12,r12
    jz .bad
    cmp r12,[rel al_active_attempt]
    jne .bad
    cmp rbx,[rel al_handle]
    jne .bad
    cmp r12,[rel al_terminal_attempt]
    jne .record
    cmp r13d,1
    jne .record
    cmp byte [rel al_terminal_activation_spent],1
    jne .bad
    call app_launcher_terminal_current
    cmp eax,1
    jne .bad
.record:
    mov qword [rel al_active_attempt],0
    mov dword [rel al_status],AL_REFUSED
    cmp r13d,1
    je .started
    mov qword [rel al_chat_attempt],0
    jmp .feedback
.started:
    mov dword [rel al_status],AL_STARTED
.feedback:
    call al_feedback
    cmp r12,[rel al_terminal_attempt]
    jne .ok
    cmp r13d,1
    jne .ok
    mov rdi,rbx
    mov rsi,r12
    call app_launcher_terminal_current
    cmp eax,1
    jne .uncertain
    mov byte [rel al_terminal_completed],1
.ok:
    mov eax,1
    jmp .out
.uncertain:
    mov dword [rel al_status],AL_REFUSED ; possible activation, never retry
.bad:
    xor eax,eax
.out:
    pop r13
    pop r12
    pop rbx
    ret

; Capture the active target's native identity before opening the policy/chat
; window. No widget/text read or grant. No active window means no target; never
; reinterpret a missing/reused target as desktop or whatever later has focus.
al_chat_capture_target:
    mov qword [rel al_chat_attempt],0
    cmp dword [rel al_name],0x736f6170
    jne .out
    cmp dword [rel al_name+4],0x6168632e
    jne .out
    cmp word [rel al_name+8],0x0074
    jne .out
    mov edi,[rel wm_focus]
    cmp edi,WM_MAX
    jae .out
    lea rax,[rel wm_state]
    cmp dword [rax+rdi*4],WM_VISIBLE
    jne .out
    call wmx_window_id
    test eax,eax
    jz .out
    mov [rel al_chat_target_id],eax
    lea rax,[rel wm_gen]
    mov eax,[rax+rdi*4]
    mov [rel al_chat_target_gen],eax
    lea rax,[rel wm_owner]
    mov rax,[rax+rdi*8]
    mov [rel al_chat_target_owner],rax
    mov rax,[rel al_active_attempt]
    mov [rel al_chat_attempt],rax
.out:
    ret

; Native-only target observation, not gui.read or a guest endpoint.
; RDI exact published handle, RSI exact original launch attempt, RDX trusted
; mapped disjoint out32 ->1/0, refusal leaves output untouched. Four qwords:
; version1, captured window id, full raw generation, full owner principal.
; Revalidate snapshot/session and original window lifetime; later focus never
; substitutes the chat window. The future scoped adapter must independently
; resolve the app principal, gui.read, privacy and invocation/START lifetime.
app_launcher_chat_target:
    cmp byte [rel cmd_in_dispatch],0
    jne al_bad
    test rdx,rdx
    jz al_bad
    mov rax,rdx
    add rax,32
    jc al_bad
    test rsi,rsi
    jz al_bad
    cmp rsi,[rel al_chat_attempt]
    jne al_bad
    cmp rdi,[rel al_handle]
    jne al_bad
    push r12
    mov r12,rdx
    call session_shell_require_unlocked
    test eax,eax
    jnz .bad
    call al_current_snapshot
    cmp eax,1
    jne .bad
    mov edi,[rel al_chat_target_id]
    movzx edi,dil
    call wmx_window_id
    cmp eax,[rel al_chat_target_id]
    jne .bad
    lea rax,[rel wm_gen]
    mov ecx,[rax+rdi*4]
    cmp ecx,[rel al_chat_target_gen]
    jne .bad
    lea rax,[rel wm_owner]
    mov rdx,[rax+rdi*8]
    cmp rdx,[rel al_chat_target_owner]
    jne .bad
    mov qword [r12],1
    mov eax,[rel al_chat_target_id]
    mov [r12+8],rax
    mov [r12+16],rcx
    mov [r12+24],rdx
    mov eax,1
    pop r12
    ret
.bad:
    xor eax,eax
    pop r12
    ret

; Original lifecycle may report a later VM fault after activation. Native only,
; exact attempt/handle; never repaint another published/reused widget.
app_launcher_failed:
    mov edx,AL_REFUSED
    jmp al_attempt_end

; The app had shown, then its VM stopped on its own.
app_launcher_stopped:
    mov edx,AL_STOPPED
    jmp al_attempt_end

; Exact attempt ended without failure: the shown app was closed or its session
; or bundle changed, or the human declined. The button returns to its name and can launch.
app_launcher_ended:
    mov edx,AL_IDLE
al_attempt_end:
    cmp byte [rel cmd_in_dispatch],0
    jne al_bad
    test rsi,rsi
    jz al_bad
    cmp rdi,[rel al_handle]
    jne al_bad
    cmp rsi,[rel al_lifecycle_attempt]
    jne al_bad
    mov qword [rel al_active_attempt],0
    mov qword [rel al_chat_attempt],0
    mov [rel al_status],edx
    call al_feedback
    mov eax,1
    ret

; Observation state only; no pending intent, lifecycle or owner mutation.
al_click_clock_clear:
    mov qword [rel al_pointer_pending_us],0
    mov qword [rel al_pointer_pending_handle],0
    mov qword [rel al_click_us],0
    mov qword [rel al_click_attempt],0
    mov qword [rel al_click_handle],0
    ret

al_queued_feedback:
    mov qword [rel al_request_us],0
    mov qword [rel al_feedback_us],0
    call al_click_clock_clear
    cmp qword [rel tsc_khz],0
    je .paint
    call time_monotonic_now_us
    mov [rel al_request_us],rax
.paint:
    call al_feedback
    cmp qword [rel tsc_khz],0
    je .out
    call time_monotonic_now_us
    mov [rel al_feedback_us],rax         ; after actual text/paint request
.out:
    ret

; Pure UI, never a VM/grant effect. Called synchronously at queue acceptance.
al_feedback:
    push rbx
    lea rbx,[rel al_launching]
    mov eax,[rel al_status]
    cmp eax,AL_QUEUED
    je .paint
    cmp eax,AL_STARTING
    je .paint
    lea rbx,[rel al_running]
    cmp eax,AL_STARTED
    je .paint
    lea rbx,[rel al_name]
    cmp eax,AL_IDLE
    je .paint
    lea rbx,[rel al_stopped]
    cmp eax,AL_STOPPED
    je .paint
    lea rbx,[rel al_failed]
.paint:
    mov edi,[rel al_widget]
    cmp edi,[rel wgt_count]
    jae .out
    call wgt_slot_ptr
    lea rdx,[rel al_widget_id]
    cmp [rax+WGI_ID],rdx
    jne .out
    cmp dword [rax+WGI_WIN],WGT_HOST_DESKTOP
    jne .out
    cmp dword [rax+WGI_TYPE],1
    jne .out
    test dword [rax+WGI_FLAGS],1
    jz .out
    mov edi,[rel al_widget]
    mov rsi,rbx
    call wgt_set_text
    call wmx_draw_all
.out:
    pop rbx
    ret

; Native trusted mapped disjoint out32. Monotonic request/feedback times are
; observations, not a 100ms claim; REL measures actual QEMU/metal latency.
app_launcher_timings:
    cmp byte [rel cmd_in_dispatch],0
    jne al_bad
    test rdi,rdi
    jz al_bad
    cmp esi,32
    jne al_bad
    mov qword [rdi],1
    mov rax,[rel al_lifecycle_attempt]
    mov [rdi+8],rax
    mov rax,[rel al_request_us]
    mov [rdi+16],rax
    mov rax,[rel al_feedback_us]
    mov [rdi+24],rax
    mov eax,1
    ret

; Native trusted mapped disjoint out64, depth0. No guest/command setter.
; schema,handle,attempt,accepted physical click,feedback,physical present,status,0.
; TAP/Terminal request times stay available only through the original out32.
; This is raw diagnostic custody, not a fresh source/session authorization.
app_launcher_click_observe:
    cmp byte [rel cmd_in_dispatch],0
    jne al_bad
    test rdi,rdi
    jz al_bad
    cmp esi,64
    jne al_bad
    mov qword [rdi],1
    mov rax,[rel al_handle]
    mov [rdi+8],rax
    mov rax,[rel al_lifecycle_attempt]
    mov [rdi+16],rax
    mov qword [rdi+24],0
    mov rdx,[rel al_feedback_us]
    mov [rdi+32],rdx
    mov qword [rdi+40],0
    mov edx,[rel al_status]
    mov [rdi+48],rdx
    mov qword [rdi+56],0
    test rax,rax
    jz .out
    cmp rax,[rel al_click_attempt]
    jne .out
    mov rax,[rel al_handle]
    test rax,rax
    jz .out
    cmp rax,[rel al_click_handle]
    jne .out
    mov rax,[rel al_click_us]
    test rax,rax
    jz .out
    mov [rdi+24],rax
    mov qword [rdi+40],1
.out:
    mov eax,1
    ret

app_launcher_status:
    mov eax, [rel al_status]
    ret
al_bad:
    xor eax, eax
    ret

; Stock button callback: never parses PNG, allocates, or copies bundle bytes.
; Only this exact published desktop entry may replace its label with cached48.
; All other buttons chain unchanged; lifecycle feedback retains ordinary text.
al_button_paint:
    cmp edi, [rel al_widget]
    jne .chain
    lea rax, [rel al_widget_id]
    cmp [r12+WGI_ID], rax
    jne .chain
    cmp dword [r12+WGI_WIN], WGT_HOST_DESKTOP
    jne .chain
    cmp dword [r12+WGI_LAYER], 0
    jne .fallback
    cmp dword [r12+WGI_TYPE], 1
    jne .fallback
    cmp byte [rel al_icon_valid], 1
    jne .fallback
    cmp dword [rel al_status], AL_IDLE
    jne .fallback
    cmp dword [r12+WGI_W], 128
    jb .fallback
    cmp dword [r12+WGI_H], 56
    jb .fallback
    push rbx
    push r13
    mov rbx, r12
    mov r13d, ecx                     ; current hot/pressed/disabled body color
    call al_current_snapshot          ; current trust + exact immutable snapshot
    cmp eax, 1
    jne .stale
    lea rdi, [rel al_icon_matte]
    lea rsi, [rel al_icon_pixels]
    mov edx, r13d
    call al_icon_flatten
    lea rdi, [rel al_icon_matte]
    mov esi, AL_ICON_EDGE
    mov r8d, [rbx+WGI_X]
    add r8d, 4
    mov r9d, [rbx+WGI_Y]
    add r9d, 4
    mov r10d, AL_ICON_EDGE
    mov r11d, AL_ICON_EDGE
    call fb_blit_rgba                  ; clipped canonical RGBA -> GOP
    mov eax, 1
    jmp .out
.stale:
    xor eax, eax
.out:
    pop r13
    pop rbx
    ret
.fallback:
    xor eax, eax
    ret
.chain:
    mov rax, [rel al_paint_prev]
    test rax, rax
    jz .fallback
    jmp rax

; Straight RGBA cached pixels over the current opaque button body, not PNG
; decoding. The stock blitter ignores alpha, so flatten into private scratch
; with round((source*A + body*(255-A))/255), preserving the decoded cache.
; RDI=9216-byte out, RSI=9216-byte cache, EDX=0xRRGGBB body.
al_icon_flatten:
    push rbx
    push r14
    mov eax, edx
    bswap eax
    shr eax, 8
    mov r14d, eax
    mov r10d, AL_ICON_EDGE*AL_ICON_EDGE
    mov r11d, 255
.pixel:
    movzx r8d, byte [rsi+3]
    mov r9d, 255
    sub r9d, r8d
    mov ebx, r14d
    mov ecx, 3
.channel:
    movzx eax, byte [rsi]
    imul eax, r8d
    movzx edx, bl
    imul edx, r9d
    add eax, edx
    add eax, 127
    xor edx, edx
    div r11d
    mov [rdi], al
    inc rsi
    inc rdi
    shr ebx, 8
    dec ecx
    jnz .channel
    mov byte [rdi], 255
    inc rsi
    inc rdi
    dec r10d
    jnz .pixel
    pop r14
    pop rbx
    ret

; Native constants share the image section; mutable state uses original WDATA.
al_widget_id: db 'app_launcher_entry',0
al_role: db 'button',0
al_launching: db 'Launching...',0
al_running: db 'Running',0
al_failed: db 'Launch failed',0
al_stopped: db 'App stopped',0
%macro WDATA_gui_app_launcher_0 0
al_initialized: db 0
al_form_created: db 0
al_withdrawing: db 0
align 8
al_owner_epoch: dq 0
al_owner: dq 0
al_widget: dd -1
al_status: dd AL_IDLE
al_launch: dq 0
al_click_prev: dq 0
al_paint_prev: dq 0
al_icon_valid: db 0
al_pending: dq 0
al_attempt_serial: dq 0
al_active_attempt: dq 0
al_lifecycle_attempt: dq 0
al_request_us: dq 0
al_feedback_us: dq 0
al_pointer_pending_us: dq 0
al_pointer_pending_handle: dq 0
al_click_us: dq 0
al_click_attempt: dq 0
al_click_handle: dq 0
al_handle: dq 0
al_form_len: dq 0
al_form_count: dd 0
al_form_lengths: times AL_FORM_MEMBERS dq 0
al_chat_attempt: dq 0
al_chat_target_id: dd 0
al_chat_target_gen: dd 0
al_chat_target_owner: dq 0
al_terminal_attempt: dq 0
al_terminal_handle: dq 0
al_terminal_check: dq 0
al_terminal_queued: db 0
al_terminal_completed: db 0
al_terminal_activation_spent: db 0
al_private_end:
%endmacro
WDATA_DEFER WDATA_gui_app_launcher_0
%macro WDATA_BSS_gui_app_launcher 0
al_descriptor: resb AL_DESC
al_scratch: resb AL_DESC
al_current: resb AL_DESC
al_index: resb AL_INDEX_MAX
al_form: resb (AL_FORM_MAX+1)*AL_FORM_MEMBERS
al_name: resb 64
al_form_name: resb 64*AL_FORM_MEMBERS
al_icon_pixels: resb AL_ICON_BYTES
al_icon_matte: resb AL_ICON_BYTES
al_terminal_operand: resb AL_DESC+16
al_private_bss_end:
%endmacro
WDATA_BSS_DEFER WDATA_BSS_gui_app_launcher
%macro WDATA_BSS_gui_app_launcher_images 0
al_image: resb AL_IMAGE_MAX*AL_IMAGES    ; private copies of verified kind-8 bytes
al_image_name: resb 64*AL_IMAGES
al_image_rows: resb AL_IMAGE_ROW*AL_IMAGES
al_image_sha: resb 32*AL_IMAGES             ; sha256 of each copied image (SEC A7)
al_image_owner: resq 1                   ; handle whose bytes the rows hold
al_image_scope: resq 1                   ; handle allowed to resolve now, else 0
al_image_count: resd 1
%endmacro
WDATA_BSS_DEFER WDATA_BSS_gui_app_launcher_images

; Native read-only diagnostic: digest32, output24 -> matching entry, icon valid,
; both private pixel/matte buffers all-zero. No handle, pointer or pixels escape.
app_launcher_observe:
    push rbx
    mov rbx,rsi
    mov qword [rbx],0
    mov qword [rbx+8],0
    mov qword [rbx+16],0
    cmp qword [rel al_handle],0
    je .zero_check
    mov rsi,rdi
    lea rdi,[rel al_descriptor+32]
    mov ecx,4
    cld
    repe cmpsq
    jne .zero_check
    mov qword [rbx],1
    movzx eax,byte [rel al_icon_valid]
    mov [rbx+8],rax
.zero_check:
    lea rdi,[rel al_icon_pixels]
    xor eax,eax
    mov ecx,AL_ICON_BYTES/8
    repe scasq
    jne .out
    lea rdi,[rel al_icon_matte]
    mov ecx,AL_ICON_BYTES/8
    repe scasq
    jne .out
    mov qword [rbx+16],1
.out:
    pop rbx
    ret
