;; MODULE hv/cdp_bridge
%include "core/abi/build_profile.inc"
;; LAYER 5
;; EXPORTS cdp_bridge_init, cdp_bridge_prepare, cdp_bridge_foreign_start, cdp_bridge_revoke_ept, cdp_bridge_receive, cdp_bridge_pump, cdp_fixture_mode, cdp_bound, cdp_out_ready, cdp_out_buf
;; IMPORTS hv/domain_channel, hv/vmx, hv/hv_ops, hv/vtd, hv/browser_appliance, svc/command, svc/command_auth, core/time, core/lib/fmt, lib/safe_buffer, boot/serial, hv/vcpu_ap_run, hv/vcpu_bsp
;; CAPS extension
;; OWNER saga:web_browser
%include "hv/guest_media_contract.inc"
; Task2717. Transport only, no browser methods or Chromium launch.
; The deterministic guest is a port of 2716's proven EPT/console producer.
; Request BYTES are delivered exclusively through queue 0 AFTER the guest
; posts a writable descriptor. Queue 1 supplies the only reply-copy path.
; Configuration seeds only the hostile-fixture selector, never reply bytes.
; Every invocation scrubs reused RAM, ends at real HLT, and invalidates EPT.
; Host parsers use fixed limits before copying (SECURITY hostile field rule).
; Diagnostics are EXTENSION-gated registry entries with no public-floor bypass.
;
; INFO opens a generation when idle; STOP closes and scrubs.
; ECHO id JSON / HOLD id JSON [deadline_ms] / FRAG id 32hex
; HOSTILE case id JSON: 1 oversize, 2 truncated, 3 duplicate, 4 stale,
; 5 unsolicited, 6 out-of-order, 7 changed deadline, 8 wrong channel,
; 9 cancel at ingress completion and reject the resulting late guest reply.
; RUN drains the held request; CANCEL id terminates precisely that request.
; READ id offset returns <=256 reply bytes as hex; INFO expires idle deadlines.
; BACKPRESSURE is an alias of HOLD, so saturation exercises dc_submit itself.
; A full 64-ID replay ledger is reported as pressure until STOP + INFO.
; All native dc_* entry points require the caller to serialize against this
; channel owner at a stopped-vCPU boundary, just like the existing surface seam.

CDP_RX_DESC equ 0x11000
CDP_RX_AVAIL equ 0x12000
CDP_RX_USED equ 0x13000
CDP_TX_DESC equ 0x14000
CDP_TX_AVAIL equ 0x15000
CDP_TX_USED equ 0x16000
CDP_CONFIG equ 0x17000
CDP_BODY equ 0x18000
CDP_TX equ 0x19000
CDP_RX equ 0x1A000
CDP_FIRST equ 0x1B000
CDP_ENTRY equ HV_LINUX_KERN_GPA + 0x200

cdp_bridge_init:
    push rbx
    call cdp_kat
    lea rdi, [rel cdp_verb]
    lea rsi, [rel cmd_verb_cdpbridge]
    mov rdx, CMD_AUTH_CAP_EXTENSION
    mov ecx, ARGT_TEXT
    xor r8d, r8d
    mov r9d, 1
    call command_register_verb
    test eax, eax
    jns .out
    lea rdi, [rel cdp_registry_fail]
    call serial_string
.out:
    pop rbx
    ret

; R14=reserved guest RAM, R15=reserved VMX control, same ABI as 2716.
cdp_bridge_prepare:
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    cmp byte [rel hv_vcon_pmr_bound], 1
    je .bad                               ; before any RAM/control overwrite
%endif
%endif
    test r14, 0x1FFFFF
    jnz .bad
    test r15, 0x1FFFFF
    jnz .bad
    mov rdi, r14
    xor eax, eax
    mov rcx, [rel hv_linux_ram_bytes]
    shr rcx, 3
    rep stosq
    lea rsi, [rel cdp_guest_begin]
    lea rdi, [r14 + CDP_ENTRY]
    mov ecx, cdp_guest_end - cdp_guest_begin
    rep movsb
    mov eax, [rel cdp_hostile]
    mov [r14 + CDP_CONFIG], eax
    mov qword [r14 + 0x2000 + 3*8], 0x4003
    mov eax, HV_VCON_GPA | 0x83
    mov [r14 + 0x4000 + 128*8], rax
    mov byte [rel cdp_bound], 1
    mov byte [rel cdp_mapped], 1
    xor eax, eax
    ret
.bad:
    mov byte [rel hv_linux_load_err], 2
    mov eax, -1
    ret

cdp_bridge_foreign_start:
    cmp byte [rel cdp_fixture_mode], 1
    je .out
    cmp byte [rel dc_active], 0
    je .out
    call dc_reset
.out:
    ret

cdp_bridge_revoke_ept:
    ; S7: table lifetime is frozen until both vCPUs are retired.
    cmp  qword [rel vca_ready], 0
    jne  vcb_fail_stop
    cmp byte [rel cdp_bound], 1
    jne .out
    mov rax, [rel hv_linux_region]
    mov qword [rax + 0x2000], 0
    sfence
    call hv_slat_flush
    cmp eax, 1
    jne .failed
    mov byte [rel cdp_mapped], 0
    mov byte [rel cdp_bound], 0
    inc qword [rel cdp_revocations]
    ret
.failed:
    mov byte [rel cdp_poisoned], 1
    mov dword [rel cdp_error], 12
.out:
    ret

; Queue-0 notify handler: exactly one request fragment, immediate pressure.
cdp_bridge_pump:
    push rbx
    call dc_make_frame
    test eax, eax
    jz .out
    mov ebx, eax
    mov esi, eax
    lea rdi, [rel dc_wire]
    call hv_vcon_rx_bytes
    test eax, eax
    jz .out
    sub ebx, DC_HEADER
    add [rel dc_tx_offset], ebx
    inc qword [rel dc_tx_frames]
    ; Exercise an in-flight cancellation at the stopped-vCPU boundary, after
    ; the guest owns the final ingress bytes and before it can reply. The
    ; production cancel transition, not a fake reply flag, owns termination.
    cmp dword [rel cdp_hostile], 9
    jne .out
    mov eax, [rel dc_tx_offset]
    cmp eax, [rel dc_length]
    jne .out
    mov rdi, [rel dc_id]
    mov rsi, [rel dc_generation]
    call dc_cancel
.out:
    pop rbx
    ret

; ECX=actual bounded snapshot size, called before used-ring ownership release.
cdp_bridge_receive:
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    inc qword [rel cdp_ring_seen]
    mov esi, ecx
    lea rdi, [rel hv_vcon_txbuf]
    call dc_receive
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
    ret

; Guest source: fixed guest GPAs only. Relative calls stay within this blob.
; Every MMIO store uses the shipped MOV r/m32,r32 decoder's proven shape.
cdp_guest_begin:
    cld
    mov ebx, HV_VCON_GPA
    cmp dword [rbx], 0x74726976
    jne .failed
    cmp dword [rbx + 4], 2
    jne .failed
    cmp dword [rbx + 8], 3
    jne .failed
    mov eax, 1
    mov [rbx + 0x070], eax
    mov eax, 3
    mov [rbx + 0x070], eax
    mov eax, 1
    mov [rbx + 0x024], eax
    mov [rbx + 0x020], eax
    mov eax, 11
    mov [rbx + 0x070], eax
%macro CDP_GQUEUE 4
    mov eax, %1
    mov [rbx + 0x030], eax
    mov eax, 8
    mov [rbx + 0x038], eax
    mov eax, %2
    mov [rbx + 0x080], eax
    mov eax, %3
    mov [rbx + 0x090], eax
    mov eax, %4
    mov [rbx + 0x0A0], eax
    mov eax, 1
    mov [rbx + 0x044], eax
%endmacro
    CDP_GQUEUE 0, CDP_RX_DESC, CDP_RX_AVAIL, CDP_RX_USED
    CDP_GQUEUE 1, CDP_TX_DESC, CDP_TX_AVAIL, CDP_TX_USED
%unmacro CDP_GQUEUE 4
    mov eax, 15
    mov [rbx + 0x070], eax
    xor r12d, r12d                       ; assembled request offset
    xor r13d, r13d                       ; RX used sequence
.rx:
    mov qword [CDP_RX_DESC], CDP_RX
    mov dword [CDP_RX_DESC + 8], DC_FRAME
    mov dword [CDP_RX_DESC + 12], 2
    mov eax, r13d
    and eax, 7
    mov word [CDP_RX_AVAIL + 4 + rax*2], 0
    inc r13d
    sfence
    mov [CDP_RX_AVAIL + 2], r13w
    xor eax, eax
    mov [rbx + 0x050], eax
    lfence
    cmp [CDP_RX_USED + 2], r13w
    jne .failed
    mov eax, r13d
    dec eax
    and eax, 7
    mov r10d, [CDP_RX_USED + 8 + rax*8]
    mov ebp, CDP_RX
    cmp r10d, DC_HEADER
    jb .failed
    cmp r10d, DC_FRAME
    ja .failed
    cmp dword [rbp], 'CDP1'
    jne .failed
    cmp dword [rbp + 4], 0x00010A9D
    jne .failed
    mov rax, [rbp + 48]
    or rax, [rbp + 56]
    jnz .failed
    mov r14d, [rbp + 24]
    test r14d, r14d
    jz .failed
    cmp r14d, DC_MAX
    ja .failed
    cmp [rbp + 28], r12d
    jne .failed
    mov ecx, [rbp + 32]
    test ecx, ecx
    jz .failed
    cmp ecx, DC_CHUNK
    ja .failed
    lea eax, [rcx + DC_HEADER]
    cmp eax, r10d
    jne .failed
    lea r15d, [r12 + rcx]
    cmp r15d, r14d
    ja .failed
    xor eax, eax
    cmp r15d, r14d
    sete al
    cmp [rbp + 36], eax
    jne .failed
    test r12d, r12d
    jnz .same
    mov esi, CDP_RX
    mov edi, CDP_FIRST
    mov ecx, DC_HEADER / 8
    rep movsq
    jmp .copy
.same:
    mov rax, [rbp + 8]
    cmp rax, [CDP_FIRST + 8]
    jne .failed
    mov rax, [rbp + 16]
    cmp rax, [CDP_FIRST + 16]
    jne .failed
    mov rax, [rbp + 40]
    cmp rax, [CDP_FIRST + 40]
    jne .failed
    cmp r14d, [CDP_FIRST + 24]
    jne .failed
.copy:
    mov ecx, [rbp + 32]
    mov esi, CDP_RX + DC_HEADER
    lea edi, [r12 + CDP_BODY]
    rep movsb
    mov r12d, r15d
    cmp r12d, r14d
    jb .rx

    ; Deterministic parser fixture accepts {"id":u32,"value":"lowerhex"}.
    ; This grammar belongs only to this agent, never the byte transport.
    cmp r14d, 20
    jb .failed
    mov esi, CDP_BODY
    cmp dword [rsi], '{"id'
    jne .failed
    cmp word [rsi + 4], '":'
    jne .failed
    add esi, 6
    xor eax, eax
    xor ecx, ecx
.number:
    movzx edx, byte [rsi]
    sub edx, '0'
    cmp edx, 9
    ja .number_end
    cmp ecx, 10
    jae .failed
    cmp eax, 429496729
    ja .failed
    jne .digit
    cmp edx, 5
    ja .failed
.digit:
    imul eax, 10
    add eax, edx
    inc esi
    inc ecx
    jmp .number
.number_end:
    test ecx, ecx
    jz .failed
    cmp rax, [CDP_FIRST + 16]
    jne .failed
    cmp dword [rsi], ',"va'
    jne .failed
    cmp dword [rsi + 4], 'lue"'
    jne .failed
    cmp word [rsi + 8], ':"'
    jne .failed
    add esi, 10
    lea edi, [r14 + CDP_BODY - 2]
    cmp esi, edi
    jae .failed
.value:
    mov al, [rsi]
    cmp al, '0'
    jb .failed
    cmp al, '9'
    jbe .hex
    cmp al, 'a'
    jb .failed
    cmp al, 'f'
    ja .failed
.hex:
    inc esi
    cmp esi, edi
    jb .value
    cmp word [rdi], '"}'
    jne .failed
    mov [CDP_CONFIG + 16], r13d          ; guest observed actual RX used ring
    xor r12d, r12d                       ; reply offset
    xor r13d, r13d                       ; TX used sequence
.tx:
    mov esi, CDP_FIRST
    mov edi, CDP_TX
    mov ecx, DC_HEADER / 8
    rep movsq
    mov ebp, CDP_TX
    mov [rbp + 28], r12d
    mov eax, r14d
    sub eax, r12d
    mov edx, DC_CHUNK
    cmp dword [CDP_CONFIG], 3
    jne .chunk
    mov edx, 16                          ; duplicate a nonfinal first fragment
.chunk:
    cmp eax, edx
    jbe .sized
    mov eax, edx
.sized:
    mov [rbp + 32], eax
    mov r15d, eax
    lea edx, [r12 + r15]
    xor ecx, ecx
    cmp edx, r14d
    sete cl
    mov [rbp + 36], ecx
    lea esi, [r12 + CDP_BODY]
    mov edi, CDP_TX + DC_HEADER
    mov ecx, eax
    rep movsb
    mov eax, [CDP_CONFIG]
    cmp eax, 1
    jne .not_size
    mov dword [rbp + 24], DC_MAX + 1
.not_size:
    cmp eax, 4
    jne .not_stale
    dec qword [rbp + 8]
.not_stale:
    cmp eax, 5
    jne .not_unsolicited
    inc qword [rbp + 16]
.not_unsolicited:
    cmp eax, 6
    jne .not_order
    inc dword [rbp + 28]
.not_order:
    cmp eax, 7
    jne .not_deadline
    inc qword [rbp + 40]
.not_deadline:
    cmp eax, 8
    jne .not_channel
    inc word [rbp + 4]
.not_channel:
    mov qword [CDP_TX_DESC], CDP_TX
    lea eax, [r15 + DC_HEADER]
    cmp dword [CDP_CONFIG], 2
    jne .descriptor
    mov eax, DC_HEADER - 1
.descriptor:
    mov [CDP_TX_DESC + 8], eax
    mov dword [CDP_TX_DESC + 12], 0
.notify:
    mov eax, r13d
    and eax, 7
    mov word [CDP_TX_AVAIL + 4 + rax*2], 0
    inc r13d
    sfence
    mov [CDP_TX_AVAIL + 2], r13w
    mov eax, 1
    mov [rbx + 0x050], eax
    lfence
    cmp [CDP_TX_USED + 2], r13w
    jne .failed
    cmp dword [CDP_CONFIG], 3
    jne .not_duplicate
    cmp r13d, 1
    je .notify
.not_duplicate:
    cmp dword [CDP_CONFIG], 0
    jne .finish
    add r12d, r15d
    cmp r12d, r14d
    jb .tx
.finish:
    mov [CDP_CONFIG + 12], r13d
    mov dword [CDP_CONFIG + 8], 'USED'
    sfence
    hlt
.failed:
    ud2
    times 4096 - ($ - cdp_guest_begin) db 0
cdp_guest_end:

cdp_idle:
    mov al, [rel hv_linux_running]
    or al, [rel hv_linux_start_active]
    or al, [rel hv_linux_run_req]
    or al, [rel vtd_owner_guest]
    or al, [rel gws_mapped]
    or al, [rel cdp_mapped]
    or al, [rel cdp_poisoned]
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    or al, [rel hv_vcon_pmr_bound]        ; RCQ-37: the media owner holds the vCPU seam
%endif
%endif
    movzx eax, al
    ret

cdp_run:
    push rbx
    cmp byte [rel hvw_bound], 0
    jne .out
    mov qword [rel cdp_ring_seen], 0
    mov dword [rel cdp_guest_rx_ack], 0
    mov dword [rel cdp_guest_tx_ack], 0
    call dc_expire
    cmp byte [rel dc_pending], 1
    jne .out
    call cdp_idle
    test eax, eax
    jnz .unavailable
%if !PAOS_PUBLIC_BUILD
    call browser_appliance_deselect
%endif
    call hv_linux_select_default_artifacts
    mov byte [rel cdp_fixture_mode], 1
    mov byte [rel hv_linux_release_deferred], 1 ; RC-speed-reserve: the span outlives the stop until .out
    mov byte [rel hv_launch_mode], 1
    call hv_ops_launch_active
    mov byte [rel hv_launch_mode], 0
    mov byte [rel cdp_fixture_mode], 0
    cmp byte [rel cdp_poisoned], 0
    jne .discard
    cmp byte [rel cdp_bound], 0
    je .check
    ; Preparation may fail before VMXON. It was never installed on the CPU.
    cmp byte [rel hv_linux_vmx_live], 0
    jne .transport
    mov rax, [rel hv_linux_region]
    mov qword [rax + 0x2000], 0
    sfence
    mov byte [rel cdp_bound], 0
    mov byte [rel cdp_mapped], 0
.check:
    cmp byte [rel hv_linux_load_err], 0
    jne .transport
    cmp dword [rel hv_exit_reason], 12
    jne .transport
    mov rbx, [rel hv_linux_ram]
    test rbx, rbx
    jz .transport
    cmp dword [rbx + CDP_CONFIG + 8], 'USED'
    jne .transport
    mov eax, [rbx + CDP_CONFIG + 16]
    cmp eax, [rel hv_vcon_rx_used]
    jne .transport
    test eax, eax
    jz .transport
    mov [rel cdp_guest_rx_ack], eax
    mov eax, [rbx + CDP_CONFIG + 12]
    cmp eax, [rel hv_vcon_tx_used]
    jne .transport
    test eax, eax
    jz .transport
    mov [rel cdp_guest_tx_ack], eax
    cmp rax, [rel cdp_ring_seen]
    jne .transport
    cmp byte [rel dc_pending], 0
    jne .transport                       ; incomplete reply at terminal HLT
    jmp .out
.unavailable:
    mov dword [rel cdp_error], 10
    jmp .out
.transport:
    mov dword [rel cdp_error], 11
.discard:
    mov byte [rel dc_pending], 0
    mov byte [rel dc_delivered], 0
    mov dword [rel dc_reply_length], 0
.out:
    call hv_linux_release_after_fixture   ; after the CDP_CONFIG result read
    pop rbx
    ret

; Fixed command parser. <=1100 bytes / <=5 tokens, no prefix matches.
cdp_tokens:
    push rbx
    mov rbx, rdi
    mov esi, 1100
    call safe_capped_len
    test edx, edx
    jnz .bad
    mov rcx, rax
    mov rdx, rbx
    lea rdi, [rel cdp_args]
    mov esi, 1100
    call safe_copy
    test eax, eax
    jnz .bad
    lea rsi, [rel cdp_args]
    lea rdx, [rel cdp_tok]
    xor eax, eax
.skip:
    cmp byte [rsi], 0
    je .out
    cmp byte [rsi], ' '
    jne .token
    inc rsi
    jmp .skip
.token:
    cmp eax, 5
    jae .bad
    mov [rdx + rax*8], rsi
    inc eax
.scan:
    cmp byte [rsi], 0
    je .out
    cmp byte [rsi], ' '
    je .end
    inc rsi
    jmp .scan
.end:
    mov byte [rsi], 0
    inc rsi
    jmp .skip
.bad:
    xor eax, eax
.out:
    pop rbx
    ret

; Decimal reader ported from gws_number, u32 with checked multiply.
cdp_number:
    xor eax, eax
    cmp byte [rdi], 0
    je .bad
.loop:
    movzx ecx, byte [rdi]
    test ecx, ecx
    jz .ok
    sub ecx, '0'
    cmp ecx, 9
    ja .bad
    cmp eax, 429496729
    ja .bad
    jne .digit
    cmp ecx, 5
    ja .bad
.digit:
    imul eax, 10
    add eax, ecx
    inc rdi
    jmp .loop
.ok:
    clc
    ret
.bad:
    stc
    ret

cmd_verb_cdpbridge:
    push rbx
    push r12
    push r13
    push r14
    push r15
    call cmd_handler_prologue
    mov r12, rsi
    mov rdi, [rdi + REQ_ARG]
    mov al, 1
    xchg al, [rel cdp_busy]
    test al, al
    jnz .busy
    mov dword [rel cdp_error], 0
    mov dword [rel cdp_read_count], 0
    mov dword [rel cdp_read_offset], 0
    mov byte [rel cdp_opened], 0
    test rdi, rdi
    jz .syntax
    call cdp_tokens
    mov r13d, eax
    test eax, eax
    jz .syntax
    call dc_expire
%macro CDP_MATCH 2
    mov rdi, [rel cdp_tok]
    lea rsi, [rel %1]
    call hv_tok_is
    test al, al
    jnz %2
%endmacro
    CDP_MATCH cdp_info, .info
    CDP_MATCH cdp_stop, .stop
    CDP_MATCH cdp_echo, .echo
    CDP_MATCH cdp_frag, .frag
    CDP_MATCH cdp_hold, .hold
    CDP_MATCH cdp_pressure, .hold
    CDP_MATCH cdp_hostile_word, .hostile
    CDP_MATCH cdp_cancel_word, .cancel
    CDP_MATCH cdp_run_word, .run
    CDP_MATCH cdp_read_word, .read
    jmp .syntax
.info:
    cmp r13d, 1
    jne .syntax
    call dc_expire
    cmp byte [rel dc_active], 1
    je .render
    call cdp_idle
    test eax, eax
    jnz .unavailable
    cmp byte [rel dc_exhausted], 0
    jne .unavailable
    call dc_reset
    cmp byte [rel dc_exhausted], 0
    jne .unavailable
    mov byte [rel dc_active], 1
    mov byte [rel cdp_opened], 1
    jmp .render
.stop:
    cmp r13d, 1
    jne .syntax
    call cdp_idle
    test eax, eax
    jnz .unavailable
    call dc_reset
    jmp .render
.run:
    cmp r13d, 1
    jne .syntax
    mov dword [rel cdp_hostile], 0
    call cdp_run
    jmp .render
.cancel:
    cmp r13d, 2
    jne .syntax
    mov rdi, [rel cdp_tok + 8]
    call cdp_number
    jc .syntax
    mov edi, eax
    mov rsi, [rel dc_generation]
    call dc_cancel
    mov [rel cdp_error], eax
    jmp .render
.read:
    cmp r13d, 3
    jne .syntax
    mov rdi, [rel cdp_tok + 8]
    call cdp_number
    jc .syntax
    cmp rax, [rel dc_id]
    jne .syntax
    cmp byte [rel dc_delivered], 1
    jne .syntax
    mov rdi, [rel cdp_tok + 16]
    call cdp_number
    jc .syntax
    cmp eax, [rel dc_reply_length]
    jae .syntax
    mov [rel cdp_read_offset], eax
    mov edx, [rel dc_reply_length]
    sub edx, eax
    cmp edx, 256
    jbe .read_size
    mov edx, 256
.read_size:
    mov [rel cdp_read_count], edx
    jmp .render
.echo:
    xor r14d, r14d
    jmp .ordinary
.hold:
    mov r14d, 1
    mov dword [rel cdp_hold_ms], 10000
    cmp r13d, 3
    je .ordinary
    cmp r13d, 4
    jne .syntax
    mov rdi, [rel cdp_tok + 24]
    call cdp_number
    jc .syntax
    test eax, eax
    jz .syntax
    cmp eax, 30000
    ja .syntax
    mov [rel cdp_hold_ms], eax
    mov r13d, 3
.ordinary:
    cmp r13d, 3
    jne .syntax
    mov dword [rel cdp_hostile], 0
    mov rdi, [rel cdp_tok + 8]
    call cdp_number
    jc .syntax
    mov r15d, eax
    mov rbx, [rel cdp_tok + 16]
    jmp .submit
.hostile:
    cmp r13d, 4
    jne .syntax
    mov rdi, [rel cdp_tok + 8]
    call cdp_number
    jc .syntax
    cmp eax, 1
    jb .syntax
    cmp eax, 9
    ja .syntax
    mov [rel cdp_hostile], eax
    mov rdi, [rel cdp_tok + 16]
    call cdp_number
    jc .syntax
    mov r15d, eax
    mov rbx, [rel cdp_tok + 24]
    xor r14d, r14d
    jmp .submit
.frag:
    cmp r13d, 3
    jne .syntax
    mov rdi, [rel cdp_tok + 8]
    call cdp_number
    jc .syntax
    mov r15d, eax
    mov rdi, [rel cdp_tok + 16]
    xor ecx, ecx
.seed:
    mov al, [rdi + rcx]
    cmp al, '0'
    jb .syntax
    cmp al, '9'
    jbe .seed_next
    cmp al, 'a'
    jb .syntax
    cmp al, 'f'
    ja .syntax
.seed_next:
    inc ecx
    cmp ecx, 32
    jb .seed
    cmp byte [rdi + 32], 0
    jne .syntax
    lea rbx, [rel cdp_input]
    mov dword [rbx], '{"id'
    mov word [rbx + 4], '":'
    mov edi, r15d
    lea rsi, [rbx + 6]
    call fmt_dec
    mov dword [rsi], ',"va'
    mov dword [rsi + 4], 'lue"'
    mov word [rsi + 8], ':"'
    add rsi, 10
    lea rdx, [rel cdp_input + DC_MAX - 2]
    mov rdi, [rel cdp_tok + 16]
    xor ecx, ecx
.fill:
    mov al, [rdi + rcx]
    mov [rsi], al
    inc rsi
    inc ecx
    and ecx, 31
    cmp rsi, rdx
    jb .fill
    mov word [rsi], '"}'
    mov byte [rsi + 2], 0
    mov dword [rel cdp_hostile], 0
    xor r14d, r14d
.submit:
    xor esi, esi
.length:
    cmp byte [rbx + rsi], 0
    je .length_ok
    inc esi
    cmp esi, DC_MAX
    jbe .length
    mov dword [rel cdp_error], 3
    jmp .render
.length_ok:
    ; ECHO has a 5s host deadline; held work has an explicit bounded deadline.
    push rsi
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov rcx, [rel tsc_khz]
    test rcx, rcx
    jz .no_clock
    mov edx, 5000
    test r14d, r14d
    jz .deadline
    mov edx, [rel cdp_hold_ms]
.deadline:
    imul rcx, rdx
    add rcx, rax
    pop rsi
    mov rdi, rbx
    mov edx, r15d
    mov r8, [rel dc_generation]
    call dc_submit
    mov [rel cdp_error], eax
    test eax, eax
    jnz .render
    test r14d, r14d
    jnz .render
    call cdp_run
    jmp .render
.no_clock:
    pop rsi
.unavailable:
    mov dword [rel cdp_error], 10
    jmp .render
.syntax:
    mov dword [rel cdp_error], 1
.render:
    call cdp_render
    mov byte [rel cdp_busy], 0
    mov qword [r12 + RSP_CODE], CMDE_OK
    jmp .done
.busy:
    mov qword [r12 + RSP_CODE], CMDE_BADARG
.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
%unmacro CDP_MATCH 2

; Same bounded output pattern as the shipped GWSURFACE receipt.
cdp_put:
    mov rsi, [rel cdp_cur]
    lea rdx, [rel cdp_out_buf + 1399]
.loop:
    mov al, [rdi]
    test al, al
    jz .out
    cmp rsi, rdx
    jae .out
    mov [rsi], al
    inc rdi
    inc rsi
    jmp .loop
.out:
    mov byte [rsi], 0
    mov [rel cdp_cur], rsi
    ret
cdp_dec:
    mov rsi, [rel cdp_cur]
    lea rdx, [rel cdp_out_buf + 1378]
    cmp rsi, rdx
    jae .out
    call fmt_dec
    mov byte [rsi], 0
    mov [rel cdp_cur], rsi
.out:
    ret

%macro CDP_FIELD 3
    lea rdi, [rel %1]
    call cdp_put
    xor edi, edi
    mov %2, [rel %3]
    call cdp_dec
%endmacro
cdp_render:
    push rbx
    push r12
    lea rax, [rel cdp_out_buf]
    mov [rel cdp_cur], rax
    lea rdi, [rel cdp_prefix]
    call cdp_put
    mov edi, [rel cdp_error]
    call cdp_dec
    CDP_FIELD cdp_f_stream_error, edi, dc_error
    CDP_FIELD cdp_f_gen, rdi, dc_generation
    CDP_FIELD cdp_f_id, rdi, dc_id
    CDP_FIELD cdp_f_active, dil, dc_active
    CDP_FIELD cdp_f_opened, dil, cdp_opened
    CDP_FIELD cdp_f_pending, dil, dc_pending
    CDP_FIELD cdp_f_delivered, dil, dc_delivered
    CDP_FIELD cdp_f_length, edi, dc_reply_length
    CDP_FIELD cdp_f_deliveries, rdi, dc_deliveries
    CDP_FIELD cdp_f_refusals, rdi, dc_refusals
    CDP_FIELD cdp_f_cancelled, rdi, dc_cancelled
    CDP_FIELD cdp_f_tx, rdi, dc_tx_frames
    CDP_FIELD cdp_f_rx, rdi, dc_rx_frames
    CDP_FIELD cdp_f_ring, rdi, cdp_ring_seen
    CDP_FIELD cdp_f_guest_rx, edi, cdp_guest_rx_ack
    CDP_FIELD cdp_f_guest_tx, edi, cdp_guest_tx_ack
    CDP_FIELD cdp_f_mapped, dil, cdp_mapped
    CDP_FIELD cdp_f_revoke, rdi, cdp_revocations
    CDP_FIELD cdp_f_offset, edi, cdp_read_offset
    CDP_FIELD cdp_f_count, edi, cdp_read_count
    lea rdi, [rel cdp_f_data]
    call cdp_put
    mov ebx, [rel cdp_read_offset]
    mov r12d, [rel cdp_read_count]
.hex:
    test r12d, r12d
    jz .done
    lea rax, [rel dc_reply]
    movzx edi, byte [rax + rbx]
    mov rsi, [rel cdp_cur]
    mov edx, 2
    call fmt_hex
    mov [rel cdp_cur], rsi
    inc ebx
    dec r12d
    jmp .hex
.done:
    mov byte [rel cdp_out_ready], 1
    pop r12
    pop rbx
    ret
%unmacro CDP_FIELD 3

; QEMU/metal boot KAT: production sender, snapshot consumer, and lifecycle.
; The literal pattern oracle is independent of receive's copy implementation.
cdp_kat:
    push rbx
    push r12
    push r13
    mov byte [rel cdp_kat_ok], 0
    mov dword [rel cdp_kat_stage], 1
    lea rdi, [rel cdp_input]
    xor ecx, ecx
.pattern:
    mov eax, ecx
    xor al, 0xA7
    mov [rdi + rcx], al
    inc ecx
    cmp ecx, DC_MAX
    jb .pattern
    call dc_reset
    mov byte [rel dc_active], 1
    mov ebx, 101
    call cdp_kat_submit
    test eax, eax
    jnz .fail
    call cdp_kat_frames
    cmp eax, 6
    jne .fail
    lea r12, [rel cdp_kat_wire]
    xor r13d, r13d
.positive:
    mov rdi, r12
    mov esi, [r12 + 32]
    add esi, DC_HEADER
    call dc_receive
    test eax, eax
    jnz .fail
    inc r13d
    add r12, DC_FRAME
    cmp r13d, 6
    jb .positive
    cmp qword [rel dc_deliveries], 1
    jne .fail
    cmp byte [rel dc_delivered], 1
    jne .fail
    cmp dword [rel dc_reply_length], DC_MAX
    jne .fail
    lea rdi, [rel dc_reply]
    xor ecx, ecx
.oracle:
    mov eax, ecx
    xor al, 0xA7
    cmp [rdi + rcx], al
    jne .fail
    inc ecx
    cmp ecx, DC_MAX
    jb .oracle
    ; Replaying a fully completed response cannot yield a second delivery.
    lea rdi, [rel cdp_kat_wire]
    mov esi, DC_FRAME
    call dc_receive
    cmp eax, 8
    jne .fail
    cmp qword [rel dc_deliveries], 1
    jne .fail

    mov dword [rel cdp_kat_stage], 2
    ; Each hostile frame starts a fresh pending request; exercise the exact
    ; same field-reader used at the real ring boundary, with no VMX required.
    xor r13d, r13d
.negative:
    lea eax, [r13 + 10]
    mov [rel cdp_kat_stage], eax
    inc ebx
    call cdp_kat_submit
    test eax, eax
    jnz .fail
    call cdp_kat_frames
    lea r12, [rel cdp_kat_wire]
    mov esi, DC_FRAME
    cmp r13d, 0
    jne .n1
    mov dword [r12 + 24], DC_MAX + 1
    jmp .reject
.n1:
    cmp r13d, 1
    jne .n2
    mov esi, DC_HEADER - 1
    jmp .reject
.n2:
    cmp r13d, 2
    jne .n3
    dec qword [r12 + 8]
    jmp .reject
.n3:
    cmp r13d, 3
    jne .n4
    inc qword [r12 + 16]
    jmp .reject
.n4:
    cmp r13d, 4
    jne .n5
    inc dword [r12 + 28]
    jmp .reject
.n5:
    cmp r13d, 5
    jne .n6
    inc qword [r12 + 40]
    jmp .reject
.n6:
    cmp r13d, 6
    jne .n7
    inc word [r12 + 4]
    jmp .reject
.n7:
    cmp r13d, 7
    jne .n8
    mov dword [r12 + 36], 1             ; early last fragment
    jmp .reject
.n8:
    cmp r13d, 8
    jne .n9
    mov qword [r12 + 48], 1
    jmp .reject
.n9:
    ; Nonfinal fragment replay: first is staged, duplicate kills stream.
    mov rdi, r12
    call dc_receive
    test eax, eax
    jnz .fail
    mov esi, DC_FRAME
.reject:
    mov rdi, r12
    call dc_receive
    lea rdx, [rel cdp_kat_errors]
    movzx edx, byte [rdx + r13]
    cmp eax, edx
    jne .fail
    cmp byte [rel dc_pending], 0
    jne .fail
    cmp byte [rel dc_delivered], 0
    jne .fail
    cmp qword [rel dc_deliveries], 1
    jne .fail
    inc r13d
    cmp r13d, 10
    jb .negative

    ; Duplicate IDs and backpressure do not mutate the pending request.
    mov dword [rel cdp_kat_stage], 3
    inc ebx
    call cdp_kat_submit
    test eax, eax
    jnz .fail
    call cdp_kat_frames
    call cdp_kat_submit
    cmp eax, 8
    jne .fail
    inc ebx
    call cdp_kat_submit
    cmp eax, 7
    jne .fail
    mov edi, ebx
    mov rsi, [rel dc_generation]
    call dc_cancel
    cmp eax, 14
    jne .fail
    cmp byte [rel dc_pending], 1
    jne .fail
    dec ebx
    mov edi, ebx
    mov rsi, [rel dc_generation]
    call dc_cancel
    test eax, eax
    jnz .fail
    lea rdi, [rel cdp_kat_wire]
    mov esi, DC_FRAME
    call dc_receive
    cmp eax, 9
    jne .fail
    cmp byte [rel dc_delivered], 0
    jne .fail
    call cdp_kat_submit
    cmp eax, 8
    jne .fail

    ; A request expires without a reply; late correctly keyed bytes refuse.
    mov dword [rel cdp_kat_stage], 4
    inc ebx
    call cdp_kat_submit
    test eax, eax
    jnz .fail
    call cdp_kat_frames
    mov qword [rel dc_deadline], 1
    call dc_expire
    cmp byte [rel dc_pending], 0
    jne .fail
    lea rdi, [rel cdp_kat_wire]
    mov esi, DC_FRAME
    call dc_receive
    cmp eax, 6
    jne .fail
    cmp byte [rel dc_delivered], 0
    jne .fail
    mov r12, [rel dc_generation]
    call dc_reset
    cmp [rel dc_generation], r12
    jbe .fail
    lea rdi, [rel cdp_kat_wire]
    mov esi, DC_FRAME
    call dc_receive
    cmp eax, 2
    jne .fail

    ; Saturate the real tombstone ledger, without fabricating its count.
    mov dword [rel cdp_kat_stage], 5
    call dc_reset
    mov byte [rel dc_active], 1
    mov ebx, 1
.ledger:
    call cdp_kat_submit
    test eax, eax
    jnz .fail
    mov edi, ebx
    mov rsi, [rel dc_generation]
    call dc_cancel
    test eax, eax
    jnz .fail
    inc ebx
    cmp ebx, DC_IDS
    jbe .ledger
    call cdp_kat_submit
    cmp eax, 7
    jne .fail
    cmp dword [rel dc_id_count], DC_IDS
    jne .fail
    mov byte [rel cdp_kat_ok], 1
    lea rdi, [rel cdp_kat_pass]
    call serial_string
    jmp .cleanup
.fail:
    lea rdi, [rel cdp_kat_fail]
    call serial_string
    mov edi, [rel cdp_kat_stage]
    call serial_hex64
    lea rdi, [rel cdp_newline]
    call serial_string
.cleanup:
    call dc_reset
    lea rdi, [rel cdp_kat_wire]
    xor eax, eax
    mov ecx, 6 * DC_FRAME / 8
    rep stosq
    lea rdi, [rel cdp_input]
    mov ecx, DC_MAX + 1
    rep stosb
    pop r13
    pop r12
    pop rbx
    ret

; EBX=fixture ID, no clock-calibration dependency for a finite 10^12 tick KAT.
cdp_kat_submit:
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov rcx, 1000000000000
    add rcx, rax
    mov edx, ebx
    lea rdi, [rel cdp_input]
    mov esi, DC_MAX
    mov r8, [rel dc_generation]
    call dc_submit
    ret

; Save the actual sender's frames, then receive only AFTER request TX completed.
cdp_kat_frames:
    push r12
    push r13
    lea r12, [rel cdp_kat_wire]
    xor r13d, r13d
.loop:
    call dc_make_frame
    test eax, eax
    jz .out
    mov ecx, eax
    sub eax, DC_HEADER
    add [rel dc_tx_offset], eax
    lea rsi, [rel dc_wire]
    mov rdi, r12
    rep movsb
    add r12, DC_FRAME
    inc r13d
    cmp r13d, 6
    jb .loop
.out:
    mov eax, r13d
    pop r13
    pop r12
    ret

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_hv_cdp_bridge_0 0
align 8
times 45 db 0                  ; cdp_revocations..cdp_out_buf moved to WDATA_hv_cdp_bridge_0_bss1: keeps the labels below at their offset mod 64
cdp_verb: db "CDPBRIDGE",0
cdp_info: db "INFO",0
cdp_stop: db "STOP",0
cdp_echo: db "ECHO",0
cdp_frag: db "FRAG",0
cdp_hold: db "HOLD",0
cdp_pressure: db "BACKPRESSURE",0
cdp_hostile_word: db "HOSTILE",0
cdp_cancel_word: db "CANCEL",0
cdp_run_word: db "RUN",0
cdp_read_word: db "READ",0
cdp_prefix: db "CDPBRIDGE transport=shared_ring channel=2717 bounded=1 max=1024 chunk=192 depth=1 agent=isolated_parser error=",0
cdp_f_stream_error: db " stream_error=",0
cdp_f_gen: db " generation=",0
cdp_f_id: db " id=",0
cdp_f_active: db " active=",0
cdp_f_opened: db " opened=",0
cdp_f_pending: db " pending=",0
cdp_f_delivered: db " delivered=",0
cdp_f_length: db " total=",0
cdp_f_deliveries: db " deliveries=",0
cdp_f_refusals: db " refusals=",0
cdp_f_cancelled: db " cancelled=",0
cdp_f_tx: db " tx_frames=",0
cdp_f_rx: db " rx_frames=",0
cdp_f_ring: db " ring_seen=",0
cdp_f_guest_rx: db " guest_rx_ack=",0
cdp_f_guest_tx: db " guest_tx_ack=",0
cdp_f_mapped: db " mapped=",0
cdp_f_revoke: db " revocations=",0
cdp_f_offset: db " offset=",0
cdp_f_count: db " count=",0
cdp_f_data: db " data=",0
cdp_registry_fail: db "[PAOS64] CDP bridge registry FULL",13,10,0
cdp_kat_ok: db 0
cdp_kat_stage: dd 0
cdp_kat_errors: db 3,1,2,5,4,6,1,4,1,8
; cdp_kat_wire..cdp_kat_wire moved to WDATA_hv_cdp_bridge_0_bss2 (zero-fill tail)
cdp_kat_pass: db "[PAOS64] browser CDP bridge framing/generation/backpressure KAT PASS [browser.cdp.bridge.kat]",13,10,0
cdp_kat_fail: db "[PAOS64] browser CDP bridge KAT FAIL stage=",0
cdp_newline: db 13,10,0
%endmacro
WDATA_DEFER WDATA_hv_cdp_bridge_0
; Zero-initialised runs with no file bytes (core/abi/wdata.inc WDATA_BSS_DEFER), in block order.
%macro WDATA_hv_cdp_bridge_0_bss1 0
alignb 8
cdp_revocations: resq 1
cdp_ring_seen: resq 1
cdp_cur: resq 1
cdp_guest_rx_ack: resd 1
cdp_guest_tx_ack: resd 1
cdp_hostile: resd 1
cdp_error: resd 1
cdp_read_offset: resd 1
cdp_read_count: resd 1
cdp_hold_ms: resd 1
cdp_opened: resb 1
cdp_fixture_mode: resb 1
cdp_bound: resb 1
cdp_mapped: resb 1
cdp_poisoned: resb 1
cdp_busy: resb 1
cdp_out_ready: resb 1
alignb 8
cdp_tok: resq 5
cdp_args: resb 1100
cdp_input: resb DC_MAX + 1
cdp_out_buf: resb 1400
%endmacro
WDATA_BSS_DEFER WDATA_hv_cdp_bridge_0_bss1
%macro WDATA_hv_cdp_bridge_0_bss2 0
resb 61                 ; keeps cdp_kat_wire at its WDATA offset mod 64
cdp_kat_wire: resb 6 * DC_FRAME
%endmacro
WDATA_BSS_DEFER WDATA_hv_cdp_bridge_0_bss2
