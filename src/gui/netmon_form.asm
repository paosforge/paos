;; MODULE gui/netmon_form
%include "core/abi/build_profile.inc"
;; LAYER 6
;; EXPORTS netmon_form_declare, netmon_builtin_query, netmon_members_text, netmon_address_text, netmon_check_click_init, netmon_observe_widget
;; IMPORTS gui/form_loader, svc/command, svc/command_udp, net/dns, net/netdev, dev/net/e1000e, boot/serial, core/lib/fmt, gui/widget, svc/command_netcheck, gui/window_mgmt, gui/chat_app, sec/session, boot/header, hv/nd_isolation
;; CAPS
;; OWNER saga:pmod_first

; LAUNCH is shared by sysprops/imgdemo and stays in the keep. The Network
; Monitor provider is built in for every profile (T5-21.1; root 119679 route A):
; the form row and NETMON_STAT are bound here and nowhere else, so nothing read
; from the ESP can replace them (SEC 119690: the external netmon PMOD path is
; retired). A lint or registration failure leaves the row empty and the verb
; absent, with a serial stage marker: honest absence, never a fabricated view.
netmon_form_declare:
    lea rdi, [rel str_verb_launch]
    lea rsi, [rel form_cmd_verb_launch]
    xor edx, edx
    mov ecx, ARGT_TEXT
    xor r8d, r8d
    mov r9d, 1
    call command_register_verb
    lea rdi, [rel form_catalog_verb]
    lea rsi, [rel form_catalog_lookup]
    call form_replace_handler
    lea rax, [rel netmon_members_text]   ; RCQ-35: the keep-owned netmon.members rows
    mov [rel form_netmon_members_fn], rax
    lea rax, [rel netmon_details_text]
    mov [rel form_netmon_address_fn], rax
    ; The form linter resolves netmon.* bindings through op 4, so the provider
    ; is ready before the bind and withdrawn again if the bind fails.
    mov byte [rel nm_builtin_ready], 1
    mov edi, 3                           ; every boot starts at fresh counters
    xor esi, esi
    call netmon_builtin_query
    lea rdi, [rel nm_form]
    mov esi, nm_form_end-nm_form
    call form_netmon_bind
    test eax, eax
    jnz .bind_failed
    lea rdi, [rel nm_verb_name]
    lea rsi, [rel netmon_builtin_invoke]
    xor edx, edx                         ; flags as the retired pmod_netmon_verify registered
    mov ecx, ARGT_TEXT
    xor r8d, r8d
    xor r9d, r9d
    call command_register_verb
    cmp eax, -1
    je .verb_failed
    lea rdi, [rel nm_builtin_up_marker]
    call serial_string
    ret
.verb_failed:
    call form_netmon_unbind
    mov edi, 2
    jmp .refused
.bind_failed:
    mov edi, 1
.refused:
    mov byte [rel nm_builtin_ready], 0
    push rdi
    lea rdi, [rel nm_builtin_refused_marker]
    call serial_string
    pop rdi
    call serial_hex64
    lea rdi, [rel nm_builtin_marker_end]
    call serial_string
    ret

; netmon_builtin_query - the one bounded entry for the verb and the form's live
; bindings; the ABI of the retired pmod_netmon_query.
; EDI=operation 0..5, RSI=optional token (op 5: two-qword widget snapshot).
; RAX=reply pointer / 0 on refusal, RDX/RCX=RX/TX rates, R8D=binding/action id,
; R9=widget value. Single-flight across CPUs (the verb and the form tick can
; run on different CPUs): an atomic xchg acquires nm_builtin_busy.
netmon_builtin_query:
    push rbx
    push r12
    push r13
    mov r13d, edi
    mov r12, rsi
    cmp edi, 5
    ja .deny
    cmp byte [rel nm_builtin_ready], 1
    jne .deny
    mov al, 1
    xchg al, [rel nm_builtin_busy]       ; xchg with memory is locked
    test al, al
    jnz .deny
    test r12, r12
    jnz .have_arg
    cmp r13d, 5
    je .failed                           ; widget snapshots require both qwords
    lea r12, [rel nm_builtin_empty_arg]  ; preserve bare NETMON_STAT reads
.have_arg:
    lea rbx, [rel nm_builtin_state]
    mov rdi, rbx
    call netmon_snapshot
    mov [rbx+160], r13
    cmp r13d, 5
    jne .text_arg
    mov rax, [r12]
    mov [rbx+216], rax
    mov rax, [r12+8]
    mov [rbx+224], rax
    lea r12, [rel nm_builtin_empty_arg]
.text_arg:
    xor ecx, ecx
.copy:
    cmp ecx, 128
    jae .failed
    mov al, [r12+rcx]
    mov [rbx+rcx+32], al
    inc ecx
    test al, al
    jnz .copy
    mov byte [rbx+256], 0
    mov rdi, rbx
    lea rsi, [rbx+256]
    call nm_entry
    ; The reply checks the sandbox boundary made, kept in the keep: the reply
    ; starts at the output span, is shorter than 512 bytes and NUL-ended.
    lea r8, [rbx+256]
    cmp rax, r8
    jne .failed
    cmp rdx, 512
    jae .failed
    cmp byte [r8+rdx], 0
    jne .failed
    mov rax, r8
    mov rdx, [rbx+184]
    mov rcx, [rbx+192]
    mov r8, [rbx+208]
    mov r9, [rbx+200]
    mov byte [rel nm_builtin_busy], 0
    jmp .out
.failed:
    mov byte [rel nm_builtin_busy], 0
.deny:
    xor eax, eax
    xor edx, edx
    xor ecx, ecx
    xor r8d, r8d
    xor r9d, r9d
.out:
    pop r13
    pop r12
    pop rbx
    ret

; NETMON_STAT handler: registry -> bounded query (op 0 only) -> reply.
; The token is the only external byte; ops 1..5 stay form-only.
netmon_builtin_invoke:
    call cmd_handler_prologue
    push rbx
    mov rbx, rsi
    mov rsi, [rdi+REQ_ARG]
    xor edi, edi
    call netmon_builtin_query
    test rax, rax
    jz .deny
    mov rdi, rax
    call netmon_reply
    mov qword [rbx+RSP_CODE], 0
    pop rbx
    ret
.deny:
    mov qword [rbx+RSP_CODE], 5
    pop rbx
    ret

%include "gui/netmon_fmt.inc"
; Beside its registration: the SEC verb census reads names from .asm files.
nm_verb_name: db "NETMON_STAT",0
nm_builtin_empty_arg: db 0
nm_builtin_up_marker: db "[PAOS64] L6 netmon: built-in provider bound, NETMON_STAT registered [netmon.builtin.ready]",13,10,0
nm_builtin_refused_marker: db "[PAOS64] L6 netmon: built-in provider refused stage=",0
nm_builtin_marker_end: db " [netmon.builtin.refused]",13,10,0

; Join the kit's click chain. lock_screen_init calls this: it sets the chain's
; root, so a hook joined from netmon_form_declare would be dropped.
netmon_check_click_init:
    mov rax, [rel wgt_click_hook]
    mov [rel nm_check_prev], rax
    lea rax, [rel netmon_check_click]
    mov [rel wgt_click_hook], rax
    ret

; netmon_check_click(EDI = hit widget id): T5-21.4. The Network Check button takes
; the same read-only collect and classify as the NETCHECK verb, and shows the
; result as words. It stages no reply. Other widgets pass down the chain unchanged.
netmon_check_click:
    push rbx
    push r12
    push r13
    mov r12d, edi
    call wgt_slot_ptr
    mov rdi, [rax+WGI_ID]
    test rdi, rdi
    jz .chain
    mov r13d, [rax+WGI_WIN]
    lea rsi, [rel nm_check_button_id]
    call strcmp
    test rax, rax
    jnz .chain
    xor ebx, ebx
.find:
    cmp ebx, WGT_MAX
    jae .chain
    mov edi, ebx
    call wgt_slot_ptr
    cmp dword [rax+WGI_TYPE], 0
    je .next
    cmp [rax+WGI_WIN], r13d
    jne .next
    mov rdi, [rax+WGI_ID]
    test rdi, rdi
    jz .next
    lea rsi, [rel nm_check_result_id]
    call strcmp
    test rax, rax
    jz .found
.next:
    inc ebx
    jmp .find
.found:
    call netcheck_collect
    call netcheck_classify
    movzx eax, byte [rel nc_check]
    cmp eax, NC_ISO_REFUSED
    je .isolation
    cmp eax, NC_HEALTHY
    je .age
    cmp eax, NM_CHECK_CODES
    jb .text
    mov eax, NM_CHECK_CODES
.text:
    lea rcx, [rel nm_check_texts]
    jmp .pick
.age:
    ; Root 90165: the check sends nothing, so healthy words say how old the evidence is.
    call netcheck_evidence_age_ms
    xor edx, edx
    mov ecx, 60000
    div rcx
    cmp rax, NM_CHECK_AGE_MAX
    jbe .age_text
    mov eax, NM_CHECK_AGE_MAX
.age_text:
    lea rcx, [rel nm_check_ages]
.pick:
    movsxd rsi, dword [rcx+rax*4]
    add rsi, rcx
    jmp .show
.isolation:
    lea rsi, [rel ndiso_short_text]       ; AMD's one producer owns these words
.show:
    mov edi, ebx
    ; The result is a label with a 40-byte inline value. Keep all age/error
    ; words (up to 34 bytes); the legacy 31-byte setter truncates them.
    mov edx, WGI_SEL_LO-WGI_VAL-1       ; 39 bytes plus NUL, before selection
    call wgt_set_text_cap
    ; Passive completed-Check generation on its existing result widget. This
    ; records the actual handler path; no action or authority is added.
    mov edi, ebx
    call wgt_slot_ptr
    cmp qword [rax+WGI_INTENT_SEQ], -1
    je .chain                         ; saturated evidence never wraps
    inc qword [rax+WGI_INTENT_SEQ]
.chain:
    mov edi, r12d
    mov rax, [rel nm_check_prev]
    pop r13
    pop r12
    pop rbx
    test rax, rax
    jz .out
    jmp rax
.out:
    ret

netmon_observe_widget:
%include "gui/netmon_observation.inc"

; Snapshot for the built-in formatter (gui/netmon_fmt.inc), which owns the
; NETMON_STAT/live-view literals. The netmon.members rows (RCQ-35 slice 2) are
; keep-owned GUI text, like explorer's fs.root.
netmon_snapshot:
    push rbx
    push r12
    push r13
    mov r12, rdi
    mov qword [r12], -1
    mov qword [r12+8], -1
    mov qword [r12+16], -1
    mov qword [r12+232], 0
    mov qword [r12+240], 0
    mov qword [r12+248], 0
    movsxd rax, dword [rel form_active_slot+16]
    mov [r12+24], rax
    mov dword [rel nm_sel_link], 0xFFFFFFFF  ; a selected member that is not probed shows no link
    call netdev_select_peek              ; the egress choice, without counting an egress
    test rax, rax
    jz .done                            ; no healthy selected device
    mov rbx, rax
    mov [r12+248], rbx                   ; opaque identity, not a name exemption
    mov rsi, [rbx+dev.name]
    test rsi, rsi
    jz .named
    xor ecx, ecx
.name:
    mov al, [rsi+rcx]
    test al, al
    jz .named
    cmp al, 33                          ; names must not inject reply separators
    jb .name_bad
    cmp al, 126
    ja .name_bad
    cmp al, ','
    je .name_bad
    cmp al, '='
    je .name_bad
    mov [r12+232+rcx], al
    inc ecx
    cmp ecx, 15
    jb .name
    cmp byte [rsi+rcx], 0
    je .named
    mov byte [r12+246], '~'              ; visibly bounded/truncated name
    jmp .named
.name_bad:
    mov qword [r12+232], 0
    mov qword [r12+240], 0
.named:
    cmp dword [rbx+dev.health], HEALTH_OK
    jne .done
    mov rax, [rbx+dev.ops]
    test rax, rax
    jz .done
    mov r13, [rax+netdev_ops.link_status]
    test r13, r13
    jz .done
    lea rax, [rel e1000e_dev]
    cmp rbx, rax
    jne .link
    call e1000e_link_refresh             ; retain Intel's actual live refresh
.link:
    mov rdi, rbx
    call r13                            ; provider bit0, speed bits never become up
    mov r13d, eax                       ; preserve status across the selection recheck
    call netdev_select_peek              ; even an error callback may remove/degrade its owner
    cmp rax, rbx
    jne .changed
    mov eax, r13d
    mov [rel nm_sel_link], eax           ; RCQ-35: the selected member row's link (with speed)
    cmp eax, -1
    je .link_error
    and eax, 1
    mov [r12+16], rax
    mov rdi, rbx
    call netdev_frame_stats
    test eax, eax
    jnz .done
    mov [r12], rdx
    mov [r12+8], rcx
    jmp .done
.link_error:
    mov dword [rel nm_sel_link], 0xFFFFFFFE
    jmp .done
.changed:
    mov qword [r12+16], -1
    mov qword [r12+232], 0
    mov qword [r12+240], 0
    mov qword [r12+248], 0
.done:
    mov rax, [r12+248]                   ; the member whose link this snapshot holds
    mov [rel nm_sel_handle], rax
    pop r13
    pop r12
    pop rbx
    ret

; GUI presentation only. The provider observation and native address reader
; retain their existing authority/selection guards; NETMON_STAT is unchanged.
; Seven bounded stock rows; counters are successful frames, never bytes.
netmon_details_text:
    push rbx
    push r12
    push r13
    sub rsp, 16
    lea rax, [rel nm_details_buf]
    mov [rsp], rax                       ; stock rows start here if no record
    lea rdi, [rel nm_iso_buf]
    mov esi, NM_ISO_TEXT_MAX
    call ndiso_render
    test eax, eax
    jz .stock
    js .short
    mov edx, eax
    lea rsi, [rel nm_iso_buf]
    lea rdi, [rel nm_details_buf]
    call nm_iso_rows
    test eax, eax
    jle .short                           ; never turn a refusal into stock text
    lea rbx, [rel nm_details_buf]
    add rbx, rax
    jmp .prefix
.short:
    lea rbx, [rel nm_details_buf]
    lea rsi, [rel ndiso_short_text]
    call nm_cat
.prefix:
    mov byte [rbx], ','
    inc rbx
    mov [rsp], rbx
.stock:
    mov edi, 1
    xor esi, esi
    call netmon_builtin_query
    mov r12, rax
    mov r13d, NETDEV_LINK_UNPROBED
    test r12, r12
    jz .start
    call netdev_select_peek
    test rax, rax
    jz .unavailable
    cmp rax, [rel nm_sel_handle]
    jne .unavailable
    mov r13d, [rel nm_sel_link]
    jmp .start
.unavailable:
    xor r12d, r12d
.start:
    mov rbx, [rsp]
    lea rsi, [rel nm_gui_link]
    call nm_cat
    lea rsi, [rel nm_gui_unknown]
    cmp r13d, NETDEV_LINK_UNPROBED
    je .link
    cmp r13d, NETDEV_LINK_ERROR
    je .link
    lea rsi, [rel nm_gui_down]
    test r13d, 1
    jz .link
    lea rsi, [rel nm_gui_up]
.link:
    call nm_cat
    lea rsi, [rel nm_gui_speed]
    call nm_cat
    cmp r13d, NETDEV_LINK_UNPROBED
    je .no_speed
    cmp r13d, NETDEV_LINK_ERROR
    je .no_speed
    test r13d, 1
    jz .no_speed
    mov edi, r13d
    shr edi, 8
    test edi, edi
    jz .no_speed
    mov rsi, rbx
    call fmt_dec
    add rbx, rax
    lea rsi, [rel nm_gui_mbps]
    jmp .speed
.no_speed:
    lea rsi, [rel nm_gui_unknown]
.speed:
    call nm_cat
    call netmon_address_text
    mov r13, rax
    lea rsi, [rel nm_gui_ip]
    call nm_cat
    mov rdi, r13
    lea rsi, [rel nm_gui_key_ip]
    call nm_gui_address
    lea rsi, [rel nm_gui_gateway]
    call nm_cat
    mov rdi, r13
    lea rsi, [rel nm_gui_key_gateway]
    call nm_gui_address
    lea rsi, [rel nm_gui_dns]
    call nm_cat
    mov rdi, r13
    lea rsi, [rel nm_gui_key_dns]
    call nm_gui_address
    lea rsi, [rel nm_gui_sent]
    call nm_cat
    mov rdi, r12
    lea rsi, [rel nm_gui_key_tx]
    call nm_gui_counter
    lea rsi, [rel nm_gui_received]
    call nm_cat
    mov rdi, r12
    lea rsi, [rel nm_gui_key_rx]
    call nm_gui_counter
    mov byte [rbx], 0
    lea rax, [rel nm_details_buf]
    add rsp, 16
    pop r13
    pop r12
    pop rbx
    ret

; NM_ISO_TEXT_MAX is AMD's bounded render contract, checked by the composed
; HOST row. The Connection listview has seven rows of 58 glyphs and treats a
; comma as a row delimiter. Keep all punctuation; replace only word/line
; boundaries. A violated contract uses the producer's short form, never a
; clipped reason or a hidden line 2. No driver, network or classifier call.
NM_ISO_TEXT_MAX equ 412
NM_ISO_GLYPHS equ 58
NM_ISO_ROWS equ 7
; nm_iso_rows(RSI=text, EDX=length, RDI=output) -> EAX bytes or -1.
; Output needs NM_ISO_TEXT_MAX+1; clobbers RCX, RDX, RSI, RDI, R8-R11.
nm_iso_rows:
    cmp edx, NM_ISO_TEXT_MAX
    ja .bad
    xor eax, eax
    xor r8d, r8d                        ; open row glyphs
    xor r9d, r9d                        ; rows opened
    xor r10d, r10d                      ; source offset
.next:
    cmp r10d, edx
    jae .done
    cmp byte [rsi+r10], ' '
    je .space
    cmp byte [rsi+r10], 10
    je .line
    mov r11d, r10d
    xor ecx, ecx
.word:
    cmp r11d, edx
    jae .place
    cmp byte [rsi+r11], ' '
    je .place
    cmp byte [rsi+r11], 10
    je .place
    cmp byte [rsi+r11], 33
    jb .bad
    cmp byte [rsi+r11], 126
    ja .bad
    cmp byte [rsi+r11], ','
    je .bad
    inc r11d
    inc ecx
    cmp ecx, NM_ISO_GLYPHS
    ja .bad                             ; never split a word mid-row
    jmp .word
.place:
    test r8d, r8d
    jz .new_row
    lea r11d, [r8+rcx+1]
    cmp r11d, NM_ISO_GLYPHS
    ja .new_row
    mov byte [rdi+rax], ' '
    inc eax
    inc r8d
    jmp .copy_word
.new_row:
    cmp r9d, NM_ISO_ROWS
    jae .bad
    test r9d, r9d
    jz .first
    mov byte [rdi+rax], ','
    inc eax
.first:
    inc r9d
    xor r8d, r8d
.copy_word:
    add r8d, ecx
.copy:
    mov r11b, [rsi+r10]
    mov [rdi+rax], r11b
    inc eax
    inc r10d
    dec ecx
    jnz .copy
    jmp .next
.line:
    xor r8d, r8d
.space:
    inc r10d
    jmp .next
.done:
    mov byte [rdi+rax], 0
    ret
.bad:
    mov eax, -1
    ret

; RDI=source, RSI=literal separator+key -> RAX=value or0. Source bound144.
nm_gui_find:
    test rdi, rdi
    jz .none
    xor ecx, ecx
.next:
    cmp ecx, 144
    jae .none
    cmp byte [rdi+rcx], 0
    je .none
    xor edx, edx
.match:
    mov r8b, [rsi+rdx]
    test r8b, r8b
    jz .found
    lea r9, [rcx+rdx]
    cmp r9d, 144
    jae .none
    cmp r8b, [rdi+r9]
    jne .advance
    inc edx
    jmp .match
.advance:
    inc ecx
    jmp .next
.found:
    lea rax, [rdi+rcx]
    add rax, rdx
    ret
.none:
    xor eax, eax
    ret

; Validate the entire bounded u64 token before painting anything. Missing,
; overflow, UINT64_MAX sentinel and nondecimal values stay Unavailable.
nm_gui_counter:
    call nm_gui_find
    test rax, rax
    jz .unknown
    mov r9, rax
    xor r10d, r10d
    xor r11d, r11d
.digit:
    movzx r8d, byte [r9+r10]
    cmp r8b, 0
    je .end
    cmp r8b, ','
    je .end
    cmp r8b, '0'
    jb .unknown
    cmp r8b, '9'
    ja .unknown
    cmp r10d, 20
    jae .unknown
    sub r8d, '0'
    mov rax, r11
    mov ecx, 10
    mul rcx
    test rdx, rdx
    jnz .unknown
    add rax, r8
    jc .unknown
    mov r11, rax
    inc r10d
    jmp .digit
.end:
    test r10d, r10d
    jz .unknown
    cmp r11, -1
    je .unknown
    mov rdi, r11
    mov rsi, rbx
    call fmt_dec
    add rbx, rax
    lea rsi, [rel nm_gui_frames]
    jmp nm_cat
.unknown:
    lea rsi, [rel nm_gui_unknown]
    jmp nm_cat

; Native address reader above is the sole source. Only selected transport
; tuples can say Not set; absent/other owners remain explicitly Unavailable.
nm_gui_address:
    cmp byte [rdi+8], 's'
    jne .unknown
    call nm_gui_find
    test rax, rax
    jz .unknown
    cmp byte [rax], 'u'                 ; native reader's canonical unset
    je .unset
    xor ecx, ecx
.check:
    mov dl, [rax+rcx]
    test dl, dl
    jz .copy
    cmp dl, ','
    je .copy
    cmp dl, ' '
    je .copy
    cmp ecx, 15
    jae .unknown
    cmp dl, '.'
    je .valid
    cmp dl, '0'
    jb .unknown
    cmp dl, '9'
    ja .unknown
.valid:
    inc ecx
    jmp .check
.copy:
    test ecx, ecx
    jz .unknown
    mov rsi, rax
    mov rdi, rbx
    add rbx, rcx
    rep movsb
    ret
.unset:
    lea rsi, [rel nm_gui_unset]
    jmp nm_cat
.unknown:
    lea rsi, [rel nm_gui_unknown]
    jmp nm_cat

; netmon_address_text -> RAX = two comma-separated GUI rows, <= 95 bytes.
; Uses the command NIC's effective address only if that NIC is selected. The
; gateway/resolver come from live configuration whose source matches that IP.
; An absent/different selected owner never inherits another NIC's tuple.
; Read-only, no driver/query/frame/ARP touch; clobbers caller-saved registers.
netmon_address_text:
    push rbx
    push r12
    push r13
    push r14
    xor r12d, r12d                      ; gateway
    xor r13d, r13d                      ; resolver
    xor r14d, r14d                      ; effective IP
    call netdev_select_peek
    lea rsi, [rel nm_addr_none]
    test rax, rax
    jz .format
    lea rsi, [rel nm_addr_other]
    cmp rax, [rel udp_nic_handle]
    jne .format
    mov rbx, rax
    mov r14d, [rel udp_our_ip3]
    test r14d, r14d
    jnz .ip
    mov r14d, [rel udp_our_ip2]
.ip:
    call dns_wire_config_peek
    test eax, eax
    jz .route_done
    cmp eax, r14d
    jne .route_done
    mov r12d, edx
    mov r13d, ecx
.route_done:
    ; Refuse a changed selection/owner instead of presenting a mixed tuple.
    call netdev_select_peek
    cmp rax, rbx
    jne .changed
    cmp rbx, [rel udp_nic_handle]
    jne .changed
    lea rsi, [rel nm_addr_selected]
    jmp .format
.changed:
    xor r12d, r12d
    xor r13d, r13d
    xor r14d, r14d
    lea rsi, [rel nm_addr_other]
.format:
    lea rbx, [rel nm_address_buf]
    call nm_cat
    lea rsi, [rel nm_addr_ip]
    call nm_cat
    mov eax, r14d
    call nm_addr_ipv4
    lea rsi, [rel nm_addr_gateway]
    call nm_cat
    mov eax, r12d
    call nm_addr_ipv4
    lea rsi, [rel nm_addr_dns]
    call nm_cat
    mov eax, r13d
    call nm_addr_ipv4
    mov byte [rbx], 0
    lea rax, [rel nm_address_buf]
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; nm_addr_ipv4(EAX=wire-order IPv4, RBX=cursor): <= 15 chars or "unset".
nm_addr_ipv4:
    push r12
    push r13
    mov r12d, eax
    test eax, eax
    jnz .octets
    lea rsi, [rel nm_addr_unset]
    call nm_cat
    jmp .out
.octets:
    mov r13d, 4
.octet:
    movzx edi, r12b
    mov rsi, rbx
    call fmt_dec
    add rbx, rax
    shr r12d, 8
    dec r13d
    jz .out
    mov byte [rbx], '.'
    inc rbx
    jmp .octet
.out:
    pop r13
    pop r12
    ret

; netmon_members_text -> RAX = the netmon.members rows (RCQ-35 slice 2), keep-owned
;   GUI text like explorer's fs.root: one comma-separated listview row per member,
;     "<name> <driver> p<prio> <ok|degraded|dead|h?> <sel|-> <up<Mb/s>|down|err|->"
;   or "members=0". Registry fields only (netdev_member_brief): no driver call (no
;   USB control transfer; no AX88179 link-up read that would re-promote a DEGRADED
;   member), no MAC anywhere. Only the selected member shows a link: the one the
;   last NETMON snapshot probed. Names: <= 15 chars of [A-Za-z0-9._-], '_' otherwise,
;   '?' when absent, so a name can never forge a row (',') or a field. Every field is
;   bounded (prio <= 9999, speed <= 99999, else '?'): at most NM_MEMBER_MAX * 59 bytes.
;   Never part of NETMON_STAT or the netmon.live view.
NM_MEMBER_MAX  equ NETDEV_MAX_SLOTS
NM_ROW_MAX     equ 59                    ; name+' ' 16, driver+' ' 16, 'p'+prio 5, ' degraded' 9, ' sel ' 5, 'up'+speed 7, ',' 1
netmon_members_text:
    push rbx
    push r12
    push r13
    lea rbx, [rel nm_members_buf]        ; output cursor
    xor r12d, r12d                       ; slot
    xor r13d, r13d                       ; rows
.slot:
    cmp r12d, NM_MEMBER_MAX
    jae .done
    mov edi, r12d
    lea rsi, [rel nm_minfo]
    call netdev_member_brief
    test rax, rax
    jnz .next
    test r13d, r13d
    jz .first
    mov byte [rbx], ','
    inc rbx
.first:
    inc r13d
    mov rsi, [rel nm_minfo + netdev_minfo.name]
    call nm_field
    mov rsi, [rel nm_minfo + netdev_minfo.driver]
    call nm_field
    mov byte [rbx], 'p'
    inc rbx
    mov eax, [rel nm_minfo + netdev_minfo.prio]
    mov ecx, 9999
    call nm_bounded
    mov eax, [rel nm_minfo + netdev_minfo.health]
    lea rsi, [rel nm_w_ok]
    cmp eax, HEALTH_OK
    je .health
    lea rsi, [rel nm_w_degraded]
    cmp eax, HEALTH_DEGRADED
    jne .not_degraded
    test dword [rel nm_minfo + netdev_minfo.flags], NETDEV_F_ABSENT
    jz .health
    lea rsi, [rel nm_w_absent]           ; a backend with no device: not a fault
    jmp .health
.not_degraded:
    lea rsi, [rel nm_w_dead]
    cmp eax, HEALTH_DEAD
    je .health
    lea rsi, [rel nm_w_unknown]
.health:
    call nm_cat
    lea rsi, [rel nm_w_sel]
    cmp byte [rel nm_minfo + netdev_minfo.selected], 1
    je .sel
    lea rsi, [rel nm_w_nosel]
.sel:
    call nm_cat
    mov eax, NETDEV_LINK_UNPROBED
    mov rdx, [rel nm_minfo + netdev_minfo.handle]
    cmp rdx, [rel nm_sel_handle]         ; only the member the snapshot probed
    jne .link
    mov eax, [rel nm_sel_link]
.link:
    lea rsi, [rel nm_w_unprobed]
    cmp eax, NETDEV_LINK_UNPROBED
    je .link_word
    lea rsi, [rel nm_w_err]
    cmp eax, NETDEV_LINK_ERROR
    je .link_word
    lea rsi, [rel nm_w_down]
    test eax, 1
    jz .link_word
    shr eax, 8
    push rax
    lea rsi, [rel nm_w_up]
    call nm_cat
    pop rax
    mov ecx, 99999
    call nm_bounded
    jmp .next
.link_word:
    call nm_cat
.next:
    inc r12d
    jmp .slot
.done:
    test r13d, r13d
    jnz .terminate
    lea rsi, [rel nm_w_none]
    call nm_cat
.terminate:
    mov byte [rbx], 0
    lea rax, [rel nm_members_buf]
    pop r13
    pop r12
    pop rbx
    ret

; nm_field(RSI=cstr or 0): <= 15 sanitized chars and a space; '?' when absent/empty.
nm_field:
    xor ecx, ecx
    test rsi, rsi
    jz .empty
.copy:
    mov al, [rsi+rcx]
    test al, al
    jz .end
    cmp al, '-'
    je .keep
    cmp al, '.'
    je .keep
    cmp al, '_'
    je .keep
    cmp al, '0'
    jb .bad
    cmp al, '9'
    jbe .keep
    cmp al, 'A'
    jb .bad
    cmp al, 'Z'
    jbe .keep
    cmp al, 'a'
    jb .bad
    cmp al, 'z'
    jbe .keep
.bad:
    mov al, '_'
.keep:
    mov [rbx+rcx], al
    inc ecx
    cmp ecx, 15
    jb .copy
.end:
    test ecx, ecx
    jnz .spaced
.empty:
    mov byte [rbx], '?'
    mov ecx, 1
.spaced:
    add rbx, rcx
    mov byte [rbx], ' '
    inc rbx
    ret

; nm_bounded(EAX=value, ECX=max): decimal, or '?' above max.
nm_bounded:
    cmp eax, ecx
    ja .big
    mov edi, eax
    mov rsi, rbx
    call fmt_dec                         ; RAX = digits written (NUL after them)
    add rbx, rax
    ret
.big:
    mov byte [rbx], '?'
    inc rbx
    ret

; nm_cat(RSI=cstr): append.
nm_cat:
    mov al, [rsi]
    test al, al
    jz .out
    mov [rbx], al
    inc rbx
    inc rsi
    jmp nm_cat
.out:
    ret
netmon_reply:
    push rdi
    call form_out_reset
    pop rdi
    call form_out_put_str
    mov byte [rel form_out_ready], 1
    ret
str_verb_launch: db "LAUNCH",0
nm_w_ok:       db " ok",0
nm_w_degraded: db " degraded",0
nm_w_absent:   db " absent",0
nm_w_dead:     db " dead",0
nm_w_unknown:  db " h?",0
nm_w_sel:      db " sel ",0
nm_w_nosel:    db " - ",0
nm_w_unprobed: db "-",0
nm_w_err:      db "err",0
nm_w_down:     db "down",0
nm_w_up:       db "up",0
nm_w_none:     db "members=0",0
nm_addr_selected: db "address=selected",0
nm_addr_other: db "address=unavailable",0
nm_addr_none: db "address=no_adapter",0
nm_addr_ip: db " ip=",0
nm_addr_gateway: db ",gateway=",0
nm_addr_dns: db " dns=",0
nm_addr_unset: db "unset",0
nm_gui_link: db "Link: ",0
nm_gui_speed: db ",Speed: ",0
nm_gui_ip: db ",IPv4 address: ",0
nm_gui_gateway: db ",Gateway: ",0
nm_gui_dns: db ",DNS: ",0
nm_gui_sent: db ",Sent: ",0
nm_gui_received: db ",Received: ",0
nm_gui_key_rx: db ",rx=",0
nm_gui_key_tx: db ",tx=",0
nm_gui_key_ip: db " ip=",0
nm_gui_key_gateway: db ",gateway=",0
nm_gui_key_dns: db " dns=",0
nm_gui_up: db "Connected",0
nm_gui_down: db "Disconnected",0
nm_gui_unknown: db "Unavailable",0
nm_gui_unset: db "Not set",0
nm_gui_frames: db " frames",0
nm_gui_mbps: db " Mb/s",0
%include "core/abi/wdata.inc"
%macro WDATA_gui_netmon_form_0 0
align 8
nm_minfo: times netdev_minfo_size db 0
nm_sel_handle: dq 0
nm_sel_link: dd 0xFFFFFFFF
nm_check_prev: dq 0
NM_CHECK_CODES equ 11                    ; one text per NETCHECK layer, in NC_* order, then "unknown"
nm_check_texts:
    dd nm_check_t0-nm_check_texts, nm_check_t1-nm_check_texts, nm_check_t2-nm_check_texts
    dd nm_check_t3-nm_check_texts, nm_check_t4-nm_check_texts, nm_check_t5-nm_check_texts
    dd nm_check_t6-nm_check_texts, nm_check_t7-nm_check_texts, nm_check_t8-nm_check_texts
    dd nm_check_t9-nm_check_texts, nm_check_t10-nm_check_texts, nm_check_t11-nm_check_texts
nm_check_t0: db "No network adapter",0
nm_check_t1: db "Network is starting",0
nm_check_t2: db "Can't tell: adapter facts differ",0
nm_check_t3: db "No link: check the cable",0
nm_check_t4: db "No address from the network",0
nm_check_t5: db "Can't tell: router not seen yet",0
nm_check_t6: db "Name lookups are failing",0
nm_check_t7: db "Can't tell: no recent name lookup",0
nm_check_t8: db "Web fetch failed",0
nm_check_t9: db "Can't tell: no recent web fetch",0
nm_check_t10: db "Network was working under 1 min ago",0
nm_check_t11: db "Can't tell",0
NM_CHECK_AGE_MAX equ 5                   ; NETCHECK_FRESH_MS in whole minutes
nm_check_ages:
    dd nm_check_t10-nm_check_ages, nm_check_a1-nm_check_ages, nm_check_a2-nm_check_ages
    dd nm_check_a3-nm_check_ages, nm_check_a4-nm_check_ages, nm_check_a5-nm_check_ages
nm_check_a1: db "Network was working 1 min ago",0
nm_check_a2: db "Network was working 2 min ago",0
nm_check_a3: db "Network was working 3 min ago",0
nm_check_a4: db "Network was working 4 min ago",0
nm_check_a5: db "Network was working 5 min ago",0
nm_check_button_id: db "network_check",0
nm_check_result_id: db "network_check_result",0
nm_members_buf: times NM_MEMBER_MAX * NM_ROW_MAX + 1 db 0
nm_address_buf: times 128 db 0
nm_details_buf: times NM_ISO_TEXT_MAX + 256 + 1 db 0
nm_iso_buf: times NM_ISO_TEXT_MAX db 0
%endmacro
WDATA_DEFER WDATA_gui_netmon_form_0
%macro WDATA_BSS_gui_netmon_form_builtin 0
alignb 16
nm_builtin_state: resb 1024              ; snapshot 0..255, reply 256..767, private 768..775
nm_builtin_ready: resb 1
nm_builtin_busy: resb 1
%endmacro
WDATA_BSS_DEFER WDATA_BSS_gui_netmon_form_builtin
