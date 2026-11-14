; Read-only current Network Monitor widget/native observation on WIDGETGET
; <actual counters widget> network. No form creation, input, network operation,
; provider load or staged NETCHECK reply. This observes the real renderer; it
; cannot assert scanout/pixel acceptance or invent an installed missing view.
; Full original renderer: <=412 isolation bytes + delimiter + <=255 stock
; bytes, plus NUL. Hex encoding plus bounded header/native/member peers fits
; 2304 bytes, below the existing 11264-byte original reply transport.
NM_OBS_VIEW_CAP equ 669
NM_OBS_OUT_CAP equ 2304
    push rbx
    push r12
    push r13
    push r14
    push r15
    xor eax,eax
    cmp byte [rel nm_obs_busy],0
    jne .none
    mov byte [rel nm_obs_busy],1
    mov r15d,edi
    call nm_observe_current
    test eax,eax
    jz .bad
    mov [rel nm_obs_window],r8d
    mov [rel nm_obs_generation],r9d
    mov rax,[rel form_netmon_refresh_tick]
    mov [rel nm_obs_tick],rax
    mov rax,[rel form_netmon_refresh_done]
    mov [rel nm_obs_completed_seq],rax
    xor eax,eax
    xor ecx,ecx
    cmp r8d,[rel form_netmon_refresh_window]
    jne .refresh_ready
    cmp r9d,[rel form_netmon_refresh_generation]
    jne .refresh_ready
    mov rax,[rel form_netmon_refresh_done]
    mov rcx,[rel form_netmon_refresh_ms]
.refresh_ready:
    mov [rel nm_obs_redraw],rax
    mov [rel nm_obs_refreshed_ms],rcx
    ; Observe actual bound code, not a provider label or an optional PMOD.
    ; Relative addresses disclose no image base; the saved reader must resolve
    ; both through the original paired listing and exact booted payload bytes.
    mov rax,[rel form_netmon_address_fn]
    mov [rel nm_obs_counters_fn],rax
    mov rax,[rel form_netmon_members_fn]
    mov [rel nm_obs_members_fn],rax
    call netcheck_snapshot_text
    mov r12,rdx
    mov r14,rcx
    lea rdi,[rel nm_obs_native]
    mov rsi,rax
    mov ecx,384
    call nm_observe_copy
    test eax,eax
    jz .bad
    mov rax,[rel form_netmon_address_fn]
    test rax,rax
    jz .bad
    call rax                           ; actual bound widget text renderer
    test rax,rax
    jz .bad
    lea rdi,[rel nm_obs_view]
    mov rsi,rax
    mov ecx,NM_OBS_VIEW_CAP
    call nm_observe_copy
    test eax,eax
    jz .bad
    ; Capture only the selected row of the actual netmon.members renderer.
    ; No additional offer, driver probe or alternate GUI text implementation.
    call nm_observe_members
    test eax,eax
    jz .bad
    call netcheck_snapshot_text
    test rax,rax
    jz .bad
    cmp rdx,r12
    jne .bad
    mov r13,rcx
    sub rcx,r14
    jc .bad
    cmp rcx,250                        ; no stale or changing native/widget join
    ja .bad
    lea rdi,[rel nm_obs_native]
    mov rsi,rax
    call strcmp
    test eax,eax
    jnz .bad
    mov edi,r15d
    call nm_observe_current
    test eax,eax
    jz .bad
    cmp r8d,[rel nm_obs_window]
    jne .bad
    cmp r9d,[rel nm_obs_generation]
    jne .bad
    mov rax,[rel form_netmon_refresh_tick]
    cmp rax,[rel nm_obs_tick]
    jne .bad
    mov rax,[rel form_netmon_refresh_done]
    cmp rax,[rel nm_obs_completed_seq]
    jne .bad
    call nm_observe_members_widget
    cmp eax,[rel nm_obs_members_widget]
    jne .bad
    mov rax,[rel form_netmon_address_fn]
    cmp rax,[rel nm_obs_counters_fn]
    jne .bad
    mov rax,[rel form_netmon_members_fn]
    cmp rax,[rel nm_obs_members_fn]
    jne .bad
    cmp qword [rel nm_obs_seq],-1
    je .bad
    mov byte [rel nm_obs_overflow],0
    lea rbx,[rel nm_obs_out]
    lea rsi,[rel nm_obs_head]
    call nm_observe_cat
    mov rdi,[rel nm_obs_seq]
    inc rdi
    call nm_observe_dec
    lea rsi,[rel nm_obs_win]
    call nm_observe_cat
    mov edi,[rel nm_obs_window]
    call nm_observe_dec
    lea rsi,[rel nm_obs_gen]
    call nm_observe_cat
    mov edi,[rel nm_obs_generation]
    call nm_observe_dec
    lea rsi,[rel nm_obs_widget]
    call nm_observe_cat
    mov edi,r15d
    call nm_observe_dec
    lea rsi,[rel nm_obs_started]
    call nm_observe_cat
    mov rdi,r14
    call nm_observe_dec
    lea rsi,[rel nm_obs_sampled]
    call nm_observe_cat
    mov rdi,r13
    call nm_observe_dec
    lea rsi,[rel nm_obs_provider]
    call nm_observe_cat
    lea rsi,[rel nm_obs_counters_rel]
    call nm_observe_cat
    mov rdi,[rel nm_obs_counters_fn]
    lea rax,[rel netmon_observe_widget]
    sub rdi,rax
    call nm_observe_dec
    lea rsi,[rel nm_obs_members_rel]
    call nm_observe_cat
    mov rdi,[rel nm_obs_members_fn]
    lea rax,[rel netmon_observe_widget]
    sub rdi,rax
    call nm_observe_dec
    ; Cadence input/completion are native state; getters never advance them.
    lea rsi,[rel nm_obs_tick_head]
    call nm_observe_cat
    mov rdi,[rel nm_obs_tick]
    call nm_observe_dec
    lea rsi,[rel nm_obs_redraw_head]
    call nm_observe_cat
    mov rdi,[rel nm_obs_redraw]
    call nm_observe_dec
    lea rsi,[rel nm_obs_refreshed_head]
    call nm_observe_cat
    mov rdi,[rel nm_obs_refreshed_ms]
    call nm_observe_dec
    lea rsi,[rel nm_obs_view_head]
    call nm_observe_cat
    lea r12,[rel nm_obs_view]
    call nm_observe_hex
    cmp dword [rel nm_obs_members_widget],0
    jl .facts
    lea rsi,[rel nm_obs_members_head]
    call nm_observe_cat
    mov edi,[rel nm_obs_members_widget]
    call nm_observe_dec
    lea rsi,[rel nm_obs_selected_head]
    call nm_observe_cat
    lea r12,[rel nm_obs_selected]
    call nm_observe_hex
.facts:
    mov al,10
    call nm_observe_byte
    lea rsi,[rel nm_obs_native]
    call nm_observe_cat
    xor eax,eax
    call nm_observe_byte
    cmp byte [rel nm_obs_overflow],0
    jne .bad
    inc qword [rel nm_obs_seq]
    lea rax,[rel nm_obs_out]
    jmp .done
.bad:
    xor eax,eax
.done:
    mov byte [rel nm_obs_busy],0
.none:
    ; A recursive getter must not clear its caller's busy ownership.
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

nm_observe_hex:
.hex:
    movzx r13d,byte [r12]
    test r13d,r13d
    jz .out
    lea rdx,[rel nm_obs_hex]
    mov eax,r13d
    shr eax,4
    mov al,[rdx+rax]
    call nm_observe_byte
    and r13d,15
    lea rdx,[rel nm_obs_hex]
    mov al,[rdx+r13]
    call nm_observe_byte
    inc r12
    jmp .hex
.out:
    ret

; Locate a unique real members listview in the same active Monitor window.
; -1 means absent (legacy partial observation); -2 is ambiguous/refused.
; wgt_slot_ptr clobbers R10. Keep scan state in preserved registers.
nm_observe_members_widget:
    push rbx
    push r12
    xor ebx,ebx
    mov r12d,-1
.loop:
    mov edi,ebx
    call wgt_slot_ptr
    cmp dword [rax+WGI_TYPE],11
    jne .next
    cmp dword [rax+WGI_BIND],10
    jne .next
    mov ecx,[rax+WGI_WIN]
    cmp ecx,[rel nm_obs_window]
    jne .next
    cmp r12d,-1
    jne .ambiguous
    mov r12d,ebx
.next:
    inc ebx
    cmp ebx,WGT_MAX
    jb .loop
    mov eax,r12d
    jmp .out
.ambiguous:
    mov eax,-2
.out:
    pop r12
    pop rbx
    ret

; Copy the original rendered rows, then the exact selected row substring.
; The renderer has <=8 rows *59 bytes, including separators; no fabricated name,
; link, selection or next hop. Multiple selected rows refuse instead of choosing.
; An installed members widget with no callback cannot yield a complete snapshot.
nm_observe_members:
    call nm_observe_members_widget
    mov [rel nm_obs_members_widget],eax
    cmp eax,-1
    je .good
    test eax,eax
    js .bad
    mov rax,[rel form_netmon_members_fn]
    test rax,rax
    jz .bad
    call rax
    mov rsi,rax
    lea rdi,[rel nm_obs_members]
    mov ecx,473
    call nm_observe_copy
    test eax,eax
    jz .bad
    lea rsi,[rel nm_obs_members]
    mov byte [rel nm_obs_selected],0
    xor r11d,r11d
.row:
    mov r8,rsi                       ; actual row start
    xor ecx,ecx                     ; spaces before the selection field
    xor r9d,r9d
.scan:
    mov al,[rsi]
    test al,al
    jz .endrow
    cmp al,','
    je .endrow
    cmp al,' '
    jne .next
    inc ecx
    cmp ecx,4
    jne .next
    lea r9,[rsi+1]
.next:
    inc rsi
    jmp .scan
.endrow:
    test r9,r9
    jz .advance
    mov rdx,rsi
    sub rdx,r9
    cmp rdx,4
    jb .advance
    cmp dword [r9],'sel '
    jne .advance
    inc r11d
    cmp r11d,1
    jne .bad
    mov rcx,rsi
    sub rcx,r8
    cmp rcx,58                      ; one actual row, excluding comma/NUL
    ja .bad
    lea rdi,[rel nm_obs_selected]
    push rsi
    mov rsi,r8
    rep movsb
    mov byte [rdi],0
    pop rsi
.advance:
    cmp byte [rsi],0
    je .good
    inc rsi
    jmp .row
.good:
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; EDI=widget. EAX=1, R8D=current native form window, R9D=generation, else0.
nm_observe_current:
    xor eax,eax
    cmp edi,WGT_MAX
    jae .bad
    cmp byte [rel session_locked],SESSION_LOCKED
    je .bad
    call wgt_slot_ptr
    cmp dword [rax+WGI_TYPE],11          ; actual listview type
    jne .bad
    cmp dword [rax+WGI_BIND],11          ; actual netmon.address binding
    jne .bad
    mov r8d,[rax+WGI_WIN]
    cmp r8d,WM_MAX
    jae .bad
    cmp r8d,[rel form_active_slot+16]
    jne .bad
    lea rcx,[rel wm_state]
    cmp dword [rcx+r8*4],WM_VISIBLE
    jne .bad
    lea rcx,[rel wm_owner]
    cmp qword [rcx+r8*8],WM_OWNER_CHROME
    jne .bad
    lea rcx,[rel wm_gen]
    mov r9d,[rcx+r8*4]
    test r9d,r9d
    jz .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

; Copy only a terminated source within ECX bytes. Refuse unbounded text.
nm_observe_copy:
    test rsi,rsi
    jz .bad
.loop:
    mov al,[rsi]
    mov [rdi],al
    inc rdi
    inc rsi
    test al,al
    jz .good
    dec ecx
    jnz .loop
.bad:
    xor eax,eax
    ret
.good:
    mov eax,1
    ret

nm_observe_dec:
    lea rsi,[rel nm_obs_number]
    call fmt_dec
    lea rsi,[rel nm_obs_number]
    mov byte [rsi+rax],0
nm_observe_cat:
    mov al,[rsi]
    test al,al
    jz .out
    call nm_observe_byte
    inc rsi
    jmp nm_observe_cat
.out:
    ret
nm_observe_byte:
    lea rcx,[rel nm_obs_out+NM_OBS_OUT_CAP]
    cmp rbx,rcx
    jae .full
    mov [rbx],al
    inc rbx
    ret
.full:
    mov byte [rel nm_obs_overflow],1
    ret

nm_obs_head: db 'NETMONOBS1 v=1 seq=',0
nm_obs_win: db ' window=',0
nm_obs_gen: db ' generation=',0
nm_obs_widget: db ' widget=',0
nm_obs_started: db ' started_ms=',0
nm_obs_sampled: db ' sampled_ms=',0
nm_obs_provider: db ' provider=compiled',0
nm_obs_counters_rel: db ' counters_rel=',0
nm_obs_members_rel: db ' members_rel=',0
nm_obs_tick_head: db ' tick=',0
nm_obs_redraw_head: db ' redraw=',0
nm_obs_refreshed_head: db ' refreshed_ms=',0
nm_obs_view_head: db 10,'view_hex=',0
nm_obs_members_head: db 10,'members_widget=',0
nm_obs_selected_head: db ' selected_hex=',0
nm_obs_hex: db '0123456789abcdef'
%include "core/abi/wdata.inc"
%macro WDATA_gui_netmon_observation 0
align 8
nm_obs_seq: dq 0
nm_obs_tick: dq 0
nm_obs_redraw: dq 0
nm_obs_completed_seq: dq 0
nm_obs_refreshed_ms: dq 0
nm_obs_counters_fn: dq 0
nm_obs_members_fn: dq 0
nm_obs_window: dd 0
nm_obs_generation: dd 0
nm_obs_members_widget: dd -1
nm_obs_busy: db 0
nm_obs_overflow: db 0
nm_obs_number: times 32 db 0
nm_obs_native: times 384 db 0
nm_obs_view: times NM_OBS_VIEW_CAP db 0
nm_obs_members: times 473 db 0
nm_obs_selected: times 59 db 0
nm_obs_out: times NM_OBS_OUT_CAP db 0
%endmacro
WDATA_DEFER WDATA_gui_netmon_observation
