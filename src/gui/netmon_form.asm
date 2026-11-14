;; MODULE gui/netmon_form
%include "core/abi/build_profile.inc"
;; LAYER 6
;; EXPORTS netmon_form_declare, netmon_members_text, netmon_address_text, netmon_check_click_init
;; IMPORTS gui/form_loader, svc/command, svc/command_udp, net/dns, net/netdev, dev/net/e1000e, boot/serial, boot/pmod_loader, core/lib/fmt, gui/widget, svc/command_netcheck
;; CAPS
;; OWNER saga:pmod_first

%ifdef PMOD_BUILD
; Native PMOD v1, pure PIC, no imports or relocations. The signed member owns
; NETMON_STAT formatting and the shipped form. Input is a bounded snapshot:
; rx, tx, link, window (four qwords), followed by a 128-byte nonce/token.
; At 160: operation (0=verb, 1=view, 2=tick, 3=reset, 4=bind name, 5=widget).
; At 168..199: module-owned previous counters and slew rates; 208: binding id.
; Operation 5 takes {binding id, widget maximum} at 216/224 and returns
; action 0=unbound/1=text/2=number at 208, clamped widget number at 200.
; RCQ-35: existing offsets/call API unchanged. Formerly unused 232..247 holds
; a bounded selected name, 248 holds opaque selected-handle identity. UINT64_MAX
; denotes unavailable rx/tx/link; never a valid zero sample. Private state at
; 768 holds the prior selection (outside the 256..767 output scratch span).
; Internal netdev_frame_stats reads exact registered-device software success
; counts; unsupported providers retain the explicit unavailable state.
bits 64
org 0
nm_header:
    db "PMOD"
    dw 1, 5
    dq 0
    dd 1, nm_end, 64, nm_end-64
    dd nm_entry-64, nm_selftest-64, nm_export
    dw 0, 1, 0, 0
    dd 2312, 1, 0
nm_entry:
    push rbx
    push r12
    push r13
    mov r12, rdi
    mov r13, rsi
    mov rbx, rsi
    cmp qword [r12+160], 5
    je .widget
    cmp qword [r12+160], 4
    je .bind
    cmp qword [r12+160], 3
    je .reset
    cmp qword [r12+160], 2
    je .tick
    cmp qword [r12+160], 1
    je .view
    lea rdi, [rel nm_rx]
    call nm_puts
    mov rax, [r12]
    call nm_sample
    lea rdi, [rel nm_tx]
    call nm_puts
    mov rax, [r12+8]
    call nm_sample
    lea rdi, [rel nm_link]
    call nm_puts
    mov rax, [r12+16]
    call nm_sample
    lea rdi, [rel nm_nic]
    call nm_puts
    call nm_name
    lea rdi, [rel nm_idx]
    call nm_puts
    mov rax, [r12+24]
    call nm_dec
    lea rdi, [rel nm_nonce]
    call nm_puts
    lea rdi, [r12+32]
    call nm_puts
.finish:
    mov byte [rbx], 0
    mov rax, r13
    mov rdx, rbx
    sub rdx, r13
    pop r13
    pop r12
    pop rbx
    ret
.reset:
    mov rax, [r12+248]
    mov [r12+768], rax
    cmp qword [r12], -1
    je .unavailable
    cmp qword [r12+8], -1
    je .unavailable
    mov rax, [r12]
    mov [r12+168], rax
    mov rax, [r12+8]
    mov [r12+176], rax
    mov qword [r12+184], 0
    mov qword [r12+192], 0
    cmp qword [r12+16], 1
    je .finish
    mov qword [r12+168], -1
    mov qword [r12+176], -1
    jmp .finish
.tick:
    cmp qword [r12], -1
    je .unavailable_view
    cmp qword [r12+8], -1
    je .unavailable_view
    mov rax, [r12+248]
    cmp rax, [r12+768]
    jne .baseline_view
    cmp qword [r12+168], -1
    je .baseline_view
    cmp qword [r12+176], -1
    je .baseline_view
    cmp qword [r12+16], 1
    jne .baseline_view                  ; offline/unknown cannot create rates
    mov rdx, [r12]
    cmp rdx, [r12+168]
    jb .baseline_view                   ; reset/wrap cannot create unsigned spikes
    mov rdx, [r12+8]
    cmp rdx, [r12+176]
    jb .baseline_view
    ; Port form_netmon_tick's unsigned delta, ceiling and one-step slew.
    ; State lives in the disposable RW module page, never the RX member.
    mov rax, [r12]
    mov rdx, rax
    sub rax, [r12+168]
    mov [r12+168], rdx
    mov rcx, [r12+184]
    call nm_rate
    mov [r12+184], rax
    mov rax, [r12+8]
    mov rdx, rax
    sub rax, [r12+176]
    mov [r12+176], rdx
    mov rcx, [r12+192]
    call nm_rate
    mov [r12+192], rax
    jmp .view
.baseline_view:
    mov [r12+768], rax
    cmp qword [r12+16], 1
    je .baseline_online
    mov qword [r12+168], -1
    mov qword [r12+176], -1
    mov qword [r12+184], 0
    mov qword [r12+192], 0
    jmp .view
.baseline_online:
    mov rax, [r12]
    mov [r12+168], rax
    mov rax, [r12+8]
    mov [r12+176], rax
    mov qword [r12+184], 0
    mov qword [r12+192], 0
    jmp .view
.unavailable_view:
    mov rax, [r12+248]
    mov [r12+768], rax
    mov qword [r12+168], -1
    mov qword [r12+176], -1
    mov qword [r12+184], -1
    mov qword [r12+192], -1
    jmp .view
.unavailable:
    mov rax, [r12+248]
    mov [r12+768], rax
    mov qword [r12+168], -1
    mov qword [r12+176], -1
    mov qword [r12+184], -1
    mov qword [r12+192], -1
    jmp .finish
.view:
    lea rdi, [rel nm_live_nic]
    call nm_puts
    call nm_name
    lea rdi, [rel nm_live_rx]
    call nm_puts
    mov rax, [r12]
    call nm_sample
    lea rdi, [rel nm_live_tx]
    call nm_puts
    mov rax, [r12+8]
    call nm_sample
    lea rdi, [rel nm_live_drops_link]
    call nm_puts
    mov rax, [r12+16]
    call nm_sample
    jmp .finish
.bind:
    mov qword [r12+208], 0
    lea rdi, [r12+32]
    lea rsi, [rel nm_bind_live]
    call nm_equal
    jz .bind_live
    lea rdi, [r12+32]
    lea rsi, [rel nm_bind_rx]
    call nm_equal
    jz .bind_rx
    lea rdi, [r12+32]
    lea rsi, [rel nm_bind_tx]
    call nm_equal
    jnz .finish
    mov qword [r12+208], 4
    jmp .finish
.bind_rx:
    mov qword [r12+208], 3
    jmp .finish
.bind_live:
    mov qword [r12+208], 2
    jmp .finish
.widget:
    mov qword [r12+208], 0
    cmp qword [r12+216], 2
    je .widget_text
    cmp qword [r12+216], 3
    je .widget_rx
    cmp qword [r12+216], 4
    jne .finish
    mov rax, [r12+192]
    jmp .widget_number
.widget_rx:
    mov rax, [r12+184]
.widget_number:
    cmp qword [r12+16], 1
    jne .finish
    cmp qword [r12], -1
    je .finish
    cmp qword [r12+8], -1
    je .finish
    cmp rax, -1
    je .finish
    mov rdx, [r12+248]
    cmp rdx, [r12+768]
    jne .finish                         ; selection changed before cadence baseline
    ; Preserve the shipped clamp against this widget's declared maximum.
    cmp rax, [r12+224]
    jbe .widget_store
    mov rax, [r12+224]
.widget_store:
    mov [r12+200], rax
    mov qword [r12+208], 2
    jmp .finish
.widget_text:
    mov qword [r12+208], 1
    jmp .view
nm_equal:
    mov al, [rdi]
    cmp al, [rsi]
    jne .out
    inc rdi
    inc rsi
    test al, al
    jnz nm_equal
.out:
    ret
nm_rate:
    cmp rax, 100
    jbe .bounded
    mov eax, 100
.bounded:
    cmp rax, rcx
    jb .decay
    lea rdx, [rcx+1]
    cmp rax, rdx
    jbe .out
    mov rax, rdx
    ret
.decay:
    test rcx, rcx
    jz .out
    lea rax, [rcx-1]
.out:
    ret
nm_selftest:
    ; Exercise the actual entry before integration: exact reply and view,
    ; first-sample reset, burst slew, idle decay and full-token bind matching.
    push r12
    push r13
    sub rsp, 1032
    mov r12, rsp
    lea r13, [rsp+256]
    mov rdi, rsp
    xor eax, eax
    mov ecx, 128
    rep stosq
    mov qword [r12], 123
    mov qword [r12+8], 456
    mov qword [r12+16], 1
    mov qword [r12+24], 7
    mov rax, 0x0000653030303165           ; "e1000e" + NUL
    mov [r12+232], rax
    mov dword [r12+32], 'kat-'
    mov dword [r12+36], '2312'
    mov rdi, r12
    mov rsi, r13
    call nm_entry
    cmp rax, r13
    jne .bad
    mov rdi, rax
    lea rsi, [rel nm_test_reply]
    call nm_equal
    jne .bad
    mov qword [r12+160], 3
    mov rdi, r12
    mov rsi, r13
    call nm_entry
    cmp qword [r12+168], 123
    jne .bad
    cmp qword [r12+176], 456
    jne .bad
    cmp qword [r12+184], 0
    jne .bad
    cmp qword [r12+192], 0
    jne .bad
    mov qword [r12], 623
    mov qword [r12+8], 457
    mov qword [r12+160], 2
    mov rdi, r12
    mov rsi, r13
    call nm_entry
    cmp qword [r12+184], 1
    jne .bad
    cmp qword [r12+192], 1
    jne .bad
    mov rdi, rax
    lea rsi, [rel nm_test_view]
    call nm_equal
    jne .bad
    mov rdi, r12
    mov rsi, r13
    call nm_entry
    cmp qword [r12+184], 0
    jne .bad
    cmp qword [r12+192], 0
    jne .bad
    mov rax, -1
    mov ecx, 100
    call nm_rate
    cmp eax, 100
    jne .bad
    ; Copy a NUL-terminated token and then make it invalid by suffixing it.
    lea rsi, [rel nm_bind_rx]
    lea rdi, [r12+32]
    mov ecx, nm_bind_tx-nm_bind_rx
    rep movsb
    mov qword [r12+160], 4
    mov rdi, r12
    mov rsi, r13
    call nm_entry
    cmp qword [r12+208], 3
    jne .bad
    mov byte [r12+32+nm_bind_tx-nm_bind_rx-1], 'x'
    mov rdi, r12
    mov rsi, r13
    call nm_entry
    cmp qword [r12+208], 0
    jne .bad
    mov qword [r12+160], 5
    mov qword [r12+216], 3
    mov qword [r12+224], 7
    mov qword [r12+184], 9
    mov rdi, r12
    mov rsi, r13
    call nm_entry
    cmp qword [r12+208], 2
    jne .bad
    cmp qword [r12+200], 7
    jne .bad
    mov qword [r12+216], 5             ; filesystem widgets belong to keep
    mov rdi, r12
    mov rsi, r13
    call nm_entry
    cmp qword [r12+208], 0
    jne .bad
    mov eax, 2312
    jmp .out
.bad:
    mov eax, -1
.out:
    add rsp, 1032
    pop r13
    pop r12
    ret
; Bound derives from four u64 decimal fields + literals + <=127 nonce bytes:
; fewer than 320 output bytes, in a dedicated 512-byte scratch span.
nm_puts:
    mov al, [rdi]
    test al, al
    jz .done
    mov [rbx], al
    inc rbx
    inc rdi
    jmp nm_puts
.done:
    ret
nm_dec:
    ; Port core/lib/fmt.asm's proven unsigned do-while/div/reverse sequence.
    ; RBX is the loader-provided non-NULL output span, already bounded above.
    mov r9d, 10
    xor r8d, r8d
.loop:
    xor edx, edx
    div r9
    add dl, '0'
    push rdx
    inc r8
    test rax, rax
    jnz .loop
.copy:
    pop rax
    mov [rbx], al
    inc rbx
    dec r8
    jnz .copy
    ret
; Render missing samples as text, never UINT64_MAX or fabricated zero.
nm_sample:
    cmp rax, -1
    jne nm_dec
    lea rdi, [rel nm_unavailable]
    jmp nm_puts
nm_name:
    lea rdi, [r12+232]
    cmp byte [rdi], 0
    jne nm_put_name
    lea rdi, [rel nm_unavailable]
    jmp nm_puts
nm_put_name:
    ; Name has its own limit even if a malformed snapshot lacks a terminator.
    mov ecx, 15
.loop:
    mov al, [rdi]
    test al, al
    jz .out
    mov [rbx], al
    inc rbx
    inc rdi
    dec ecx
    jnz .loop
.out:
    ret
nm_export: db "NETMON_STAT",0
    dd nm_form, nm_form_end-nm_form
nm_rx: db " netmon rx=",0
nm_tx: db " tx=",0
nm_link: db " link=",0
nm_nic: db " nic=",0
nm_idx: db " idx=",0
nm_unavailable: db "unavailable",0
nm_nonce: db " nonce=",0
nm_live_nic: db "nic=",0
nm_live_rx: db ",rx=",0
nm_live_tx: db ",tx=",0
nm_live_drops_link: db ",drops=unavailable,link=",0
nm_bind_live: db "netmon.live",0
nm_bind_rx: db "netmon.rx_rate",0
nm_bind_tx: db "netmon.tx_rate",0
nm_test_reply: db " netmon rx=123 tx=456 link=1 nic=e1000e idx=7 nonce=kat-2312",0
nm_test_view: db "nic=e1000e,rx=623,tx=457,drops=unavailable,link=1",0
nm_form: incbin "gui/forms/netmon.frm"
nm_form_end:
nm_end:
%else
; LAUNCH is shared by sysprops/imgdemo and stays in the keep. NETMON_STAT
; is registered only after the external signed member passes the loader.
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
%if !PAOS_PUBLIC_BUILD
    lea rdi, [rel form_netmon_bind]
    lea rsi, [rel form_netmon_unbind]
    lea rdx, [rel netmon_snapshot]
    lea rcx, [rel netmon_reply]
    call pmod_netmon_bind
%endif
    lea rax, [rel netmon_members_text]   ; RCQ-35: the keep-owned netmon.members rows
    mov [rel form_netmon_members_fn], rax
    lea rax, [rel netmon_details_text]
    mov [rel form_netmon_address_fn], rax
%if !PAOS_PUBLIC_BUILD
    call pmod_netmon_start
%endif
    ret

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
    mov edi, ebx
    call wgt_set_text
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

; Generic seam adapters only: all NETMON_STAT/live-view literals and formatting
; live in PMOD. The netmon.members rows (RCQ-35 slice 2) are keep-owned GUI text,
; like explorer's fs.root: the signed member's 4 KiB page (MAX_MEMBER) has room
; for the form line, not for a second renderer.
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

; netmon_details_text -> RAX = the existing provider counters in two rows plus
; two effective-address rows. Fits the existing five-row panel without moving
; widgets. The provider's normal observation remains separate from the read-only
; address tuple: no atomic cross-subsystem snapshot is claimed.
netmon_details_text:
    push rbx
    push r12
    push r13
%if !PAOS_PUBLIC_BUILD
    mov edi, 1
    xor esi, esi
    call pmod_netmon_query
%else
    xor eax, eax                      ; native address inventory below remains available
%endif
    mov r12, rax
    lea rbx, [rel nm_details_buf]
    xor r13d, r13d
    test r12, r12
    jz .address
    mov ecx, 144                       ; provider rows are bounded even if malformed
.copy:
    mov al, [r12]
    test al, al
    jz .separator
    cmp al, ','
    jne .put
    inc r13d
    cmp r13d, 2                        ; NIC/rx first; tx/drops/link second (<=63 chars)
    je .put
    mov al, ' '
.put:
    mov [rbx], al
    inc rbx
    inc r12
    dec ecx
    jnz .copy
.separator:
    mov byte [rbx], ','
    inc rbx
.address:
    call netmon_address_text
    mov rsi, rax
    call nm_cat                        ; <=95 bytes, total <256 including NUL
    mov byte [rbx], 0
    lea rax, [rel nm_details_buf]
    pop r13
    pop r12
    pop rbx
    ret

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
nm_details_buf: times 256 db 0
%endmacro
WDATA_DEFER WDATA_gui_netmon_form_0
%endif
