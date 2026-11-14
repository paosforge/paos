; Native autonomous carrier pulse. Owner-only TCPPROBE l binds the current
; nonce, TCP incarnation, selected NIC and actual driver generation. Exactly
; one SYN-SENT and one ESTABLISHED pulse per boot; no host retry can re-arm it.
; Deadlines use the ordinary boot-ms clock. No packet is needed to restore.
%ifndef PAOS_LAB_RTL8126_204
%define PAOS_LAB_RTL8126_204 0
%endif

tcpprobe_link_arm:
    call tcpprobe_observe
    test r14d, r14d
    jnz  .out
    mov  r14d, 3
    mov  rcx, [rel tcpprobe_sample]
    cmp  ecx, 4
    je   .state_ok
    cmp  ecx, 2
    jne  .out
.state_ok:
    bt   [rel tpl_used_states], ecx
    jc   .out
    cmp  qword [rel tpl_phase], 0
    je   .prepare
    cmp  qword [rel tpl_phase], 4
    jne  .out                       ; previous restoration debt never displaced
.prepare:
    ; Consume this state intent before any driver call, including refusal.
    bts  [rel tpl_used_states], ecx
    mov  [rel tpl_state], rcx
    xor  edi, edi
    call netdev_egress_select
    test rax, rax
    jz   .out
    mov  [rel tpl_handle], rax
    mov  rdi, rax
    call netdev_carrier_drill_prepare
    cmp  rax, -1
    je   .out
    mov  [rel tpl_epoch], rax
    mov  rax, [r12]
    mov  [rel tpl_nonce], rax
    mov  rax, [r12 + 8]
    mov  [rel tpl_nonce + 8], rax
    mov  rax, [rel tcpprobe_pair]
    mov  [rel tpl_pair], rax
    mov  rax, [rel tcpprobe_pair + 8]
    mov  [rel tpl_pair + 8], rax
    mov  [rel tpl_tcp_epoch], rax
    mov  rax, [rel tcpprobe_opened]
    mov  [rel tpl_tcp_opened], rax
    call boot_ms_now
    mov  [rel tpl_armed], rax
    lea  rdx, [rax + 100]
    mov  [rel tpl_down_at], rdx
    lea  rdx, [rax + 2100]
    mov  [rel tpl_restore_at], rdx
    mov  [rel tpl_retry_at], rdx
    add  rax, 10000
    mov  [rel tpl_end_at], rax
    mov  qword [rel tpl_down_ms], 0
    mov  qword [rel tpl_up_ms], 0
    mov  qword [rel tpl_attempts], 0
    mov  qword [rel tpl_sample_at], 0
    mov  qword [rel tpl_down_rc], -2
    mov  qword [rel tpl_restore_rc], -2
    mov  qword [rel tpl_send_rc], -2
    mov  qword [rel tpl_phase], 1
    mov rax, [rel tpl_armed]
    add rax, 20000
    mov [rel tpw_until], rax
    mov qword [rel tpw_next], 0
    mov qword [rel tpw_previous + 0], 0
    mov qword [rel tpw_previous + 8], 0
    mov qword [rel tpw_previous + 16], 0
    mov qword [rel tpw_previous + 24], 0
    mov qword [rel tpw_previous + 32], 0
    mov qword [rel tpw_previous + 40], 0
    mov qword [rel tpw_action], 1
    call tcpprobe_link_witness
    xor  r14d, r14d
    ret
.out:
    ret

; BSP poll before public RX/DHCP policy, disjoint from INPUT's DHCP sampler.
; One bounded driver operation per branch, <=10 physical samples/second.
tcpprobe_link_tick:
    call tcpprobe_link_witness_tick
    cmp  qword [rel tpl_phase], 1
    jb   .out
    cmp  qword [rel tpl_phase], 3
    ja   .out
    push rbx
    push r14
    call boot_ms_now
    mov  rbx, rax
    cmp  qword [rel tpl_phase], 1
    jne  .active
    cmp  rbx, [rel tpl_restore_at]
    jae  .untouched                ; delayed poll must not create a stale loss
    cmp  rbx, [rel tpl_down_at]
    jb   .done
    ; Verify the same live state/incarnation immediately before actuation.
    mov  rdi, [rel tpl_pair]
    mov  rsi, [rel tpl_pair + 8]
    lea  rdx, [rel tpl_sample]
    call tcp_client_epoch_snapshot
    test rax, rax
    jnz  .untouched
    mov  rax, [rel tpl_sample]
    cmp  rax, [rel tpl_state]
    jne  .untouched
    mov  rdi, [rel tpl_handle]
    call netdev_selected_owner
    cmp  rax, [rel tpl_handle]
    jne  .untouched
    mov  qword [rel tpl_phase], 2 ; restoration owed even if write is ambiguous
    mov qword [rel tpw_action], 2
    call tcpprobe_link_witness
    mov  rdi, [rel tpl_handle]
    mov  rsi, [rel tpl_epoch]
    mov  edx, 1
    call netdev_carrier_drill_set
    mov  [rel tpl_down_rc], rax
    mov qword [rel tpw_action], 3
    call tcpprobe_link_witness
    jmp  .sample
.active:
    cmp  qword [rel tpl_phase], 3
    je   .sample
    cmp  rbx, [rel tpl_retry_at]
    jb   .sample
    cmp  qword [rel tpl_attempts], 3
    jae  .sample
    inc  qword [rel tpl_attempts]
    lea  rax, [rbx + 1000]
    mov  [rel tpl_retry_at], rax
    mov qword [rel tpw_action], 4
    call tcpprobe_link_witness
    mov  rdi, [rel tpl_handle]    ; original handle, never a replacement member
    mov  rsi, [rel tpl_epoch]
    xor  edx, edx
    call netdev_carrier_drill_set
    mov  [rel tpl_restore_rc], rax
    mov qword [rel tpw_action], 5
    call tcpprobe_link_witness
    test rax, rax
    jnz  .sample
    mov  qword [rel tpl_phase], 3
.sample:
    cmp  rbx, [rel tpl_sample_at]
    jb   .deadline
    lea  rax, [rbx + 100]
    mov  [rel tpl_sample_at], rax
    mov  rdi, [rel tpl_handle]
    mov  rsi, [rel tpl_epoch]
    call netdev_carrier_drill_link
    cmp  qword [rel tpl_phase], 2
    jne  .online
    test rax, rax
    jnz  .deadline
    cmp  qword [rel tpl_down_ms], 0
    jne  .deadline
    mov  [rel tpl_down_ms], rbx
    ; Queue the fixed public nonce only AFTER actual physical down. This
    ; exercises established common retransmission during the measured outage.
    cmp  qword [rel tpl_state], 2
    jne  .deadline
    mov  rdi, [rel tpl_pair]
    mov  rsi, [rel tpl_pair + 8]
    lea  rdx, [rel tpl_nonce]
    mov  ecx, 16
    mov  r8d, 1
    call tcp_client_epoch_io
    mov  [rel tpl_send_rc], rax
    jmp  .deadline
.online:
    cmp  rax, 1
    jne  .deadline
    mov  rdi, [rel tpl_handle]
    mov  rsi, [rel tpl_epoch]
    call netdev_carrier_drill_finish
    test rax, rax
    jnz  .deadline
    mov  [rel tpl_up_ms], rbx
    mov  qword [rel tpl_phase], 4
    jmp  .retain
.deadline:
    cmp  rbx, [rel tpl_end_at]
    jb   .done
    mov  qword [rel tpl_phase], 5 ; debt retained; no further pulse admitted
.retain:
    mov qword [rel tpw_action], 6
    call tcpprobe_link_witness
    mov  rdi, [rel tpl_handle]
    mov  rsi, [rel tpl_epoch]
    lea  rdx, [rel tpl_driver]
    call netdev_carrier_drill_observe
    jmp  .done
.untouched:
    mov  rdi, [rel tpl_handle]
    mov  rsi, [rel tpl_epoch]
    call netdev_carrier_drill_finish
    mov  qword [rel tpl_phase], 5 ; no physical-loss credit, no repeat
    jmp  .retain
.done:
    pop  r14
    pop  rbx
.out:
    ret

; Immutable completed pulse snapshot. An arm acknowledgement is never proof
; of physical down/up. Wrong pulse nonce cannot read a prior case's witness.
tcpprobe_link_render:
    call tcpdiag_out_reset
    lea  rdi, [rel str_tpl_prefix]
    call tcpdiag_out_text
    mov  rdi, [rel tcpdiag_out_cur]
    mov  rax, [r12]
    mov  [rdi], rax
    mov  rax, [r12 + 8]
    mov  [rdi + 8], rax
    mov  byte [rdi + 16], 0
    add  rdi, 16
    mov  [rel tcpdiag_out_cur], rdi
    lea  rdi, [rel str_tcpprobe_result]
    call tcpdiag_out_text
    mov  rax, [r12]
    cmp  rax, [rel tpl_nonce]
    jne  .bad
    mov  rax, [r12 + 8]
    cmp  rax, [rel tpl_nonce + 8]
    jne  .bad
    mov qword [rel tpw_action], 7
    call tcpprobe_link_witness
    mov  edi, 0
    jmp  .result
.bad:
    mov  edi, 3
.result:
    push rdi
    call tcpdiag_out_u64
    pop  rdi
    test edi, edi
    jnz  .out
    lea  r15, [rel tpl_fields]
.fields:
    mov  eax, [r15]
    cmp  eax, -1
    je   .out
    lea  rdi, [r15 + 4]
    call tcpdiag_out_text
    mov  eax, [r15]
    lea  rdx, [rel tpl_record]
    mov  rdi, [rdx + rax]
    call tcpdiag_out_u64
    add  r15, 24
    jmp  .fields
.out:
    ret

; Observations never drive carrier policy, TCP, authentication or deadlines.
; Serial is one nonblocking enqueue into the existing640-byte pending slot.
; At most64 lines per boot, <=1Hz for20s after acceptance plus finite edges/k.
; Two pulses/boot are already bounded by tpl_used_states. A dropped edge is
; also represented by its previous raw sample in the following capture.
tcpprobe_link_witness_tick:
    pushfq
    push rax
    push rdx
    cmp qword [rel tpw_until], 0
    je .out
    call boot_ms_now
    cmp rax, [rel tpw_until]
    jae .out
    cmp rax, [rel tpw_next]
    jb .out
    lea rdx, [rax + 1000]
    mov [rel tpw_next], rdx
    mov qword [rel tpw_action], 0
    call tcpprobe_link_witness
.out:
    pop rdx
    pop rax
    popfq
    ret

; Preserve every GPR/flag, including pending driver operands/results.
; Context words0..7: boot TSC, actual boot-ms, action, pulse phase, driver epoch,
; original handle, capture sequence, snapshot return(0/-1). Words8..27: driver's
; 20-word schema. Words28..33: previous ms, OWN, PHY, ISR, RX/TX status-ACKs.
; Prefix carries the original16-byte public pulse nonce, not a credential.
; Sequential BSP samples are not atomic DMA snapshots. A -1 snapshot return
; invalidates ALL20 driver words, including a partial failed HAL observation.
tcpprobe_link_witness:
    pushfq
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    cmp qword [rel tpw_count], 64
    jae .out
    cmp qword [rel tpl_phase], 0
    je .out
    inc qword [rel tpw_count]
    mov rax, [rel boot_tsc_start]
    mov [rel tpw_words], rax
    call boot_ms_now
    mov [rel tpw_words + 8], rax
    mov rax, [rel tpw_action]
    mov [rel tpw_words + 16], rax
    mov rax, [rel tpl_phase]
    mov [rel tpw_words + 24], rax
    mov rax, [rel tpl_epoch]
    mov [rel tpw_words + 32], rax
    mov rax, [rel tpl_handle]
    mov [rel tpw_words + 40], rax
    mov rax, [rel tpw_count]
    mov [rel tpw_words + 48], rax
    mov qword [rel tpw_words + 56], -1
    lea rdi, [rel tpw_words + 64]
    mov rax, -1
    mov ecx, 20
    rep stosq
    ; Validate the original selected identity AND generation before MMIO/DMA.
    mov rdi, [rel tpl_handle]
    call netdev_selected_owner
    cmp rax, [rel tpl_handle]
    jne .observed
    mov rdi, [rel tpl_handle]
    mov rsi, [rel tpl_epoch]
    lea rdx, [rel tpw_member]
    call netdev_carrier_drill_observe
    test rax, rax
    jnz .observed
    cmp qword [rel tpw_member], 1
    jne .observed
    mov rdi, [rel tpl_handle]
    lea rsi, [rel tpw_words + 64]
    call rtl8168_witness
    test rax, rax
    jz .valid
    mov rdi, [rel tpl_handle]
    lea rsi, [rel tpw_words + 64]
    call rtl8125_witness
    test rax, rax
    jz .valid
%if PAOS_LAB_RTL8126_204
    ; The selectable legacy provider has no witness ABI. Never alias its
    ; hardware/state to the clean driver; leave the snapshot unavailable.
    jmp .observed
%else
    mov rdi, [rel tpl_handle]
    lea rsi, [rel tpw_words + 64]
    call rtl8126_witness
    test rax, rax
    jnz .observed
%endif
.valid:
    mov qword [rel tpw_words + 56], 0
    cmp qword [rel tpw_words + 64], 8168
    jne .observed
    mov rax, [rel tpw_words + 128]      ; raw ISR can predate this pulse
    cmp qword [rel tpw_action], 1
    jne .isr_delta
    mov [rel tpw_isr_base], rax
.isr_delta:
    mov rdx, [rel tpw_isr_base]
    not rdx
    and rax, rdx
    mov [rel tpw_words + 184], rax      ; only newly latched bits, not an event count
.observed:
    cmp qword [rel tpw_words + 56], 0
    je .copy_previous
    lea rdi, [rel tpw_words + 64]
    mov rax, -1
    mov ecx, 20
    rep stosq
.copy_previous:
    lea rsi, [rel tpw_previous]
    lea rdi, [rel tpw_words + 224]
    mov ecx, 6
    rep movsq
    call tcpprobe_link_witness_serial
    mov rax, [rel tpw_words + 8]
    mov [rel tpw_previous], rax
    mov rax, [rel tpw_words + 96]       ; driver OWN bitmap
    mov [rel tpw_previous + 8], rax
    mov rax, [rel tpw_words + 120]      ; actual PHY
    mov [rel tpw_previous + 16], rax
    mov rax, [rel tpw_words + 128]      ; actual ISR
    mov [rel tpw_previous + 24], rax
    mov rax, [rel tpw_words + 160]      ; RX status-ACKs
    mov [rel tpw_previous + 32], rax
    mov rax, [rel tpw_words + 168]      ; TX status-ACKs
    mov [rel tpw_previous + 40], rax
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax
    popfq
    ret

tcpprobe_link_witness_serial:
    lea rsi, [rel str_tpw_prefix]
    lea rdi, [rel tpw_line]
.prefix:
    lodsb
    test al, al
    jz .nonce
    stosb
    jmp .prefix
.nonce:
    lea rsi, [rel tpl_nonce]
    mov ecx, 16
    rep movsb
    mov al, ' '
    stosb
    lea rsi, [rel tpw_words]
    mov ecx, 34
.word:
    lodsq
    call tcpprobe_link_witness_hex
    loop .word
    mov word [rdi], 0x0a0d
    mov byte [rdi + 2], 0
    lea rsi, [rdi + 2]
    lea rdi, [rel tpw_line]
    sub rsi, rdi
    call serial_telemetry_try
    ret

; Fixed16 hex digits + space; no formatting tables/image absolute pointers.
tcpprobe_link_witness_hex:
    push rcx
    mov ecx, 16
.digit:
    rol rax, 4
    mov edx, eax
    and edx, 15
    add dl, '0'
    cmp dl, '9'
    jbe .store
    add dl, 'a' - '9' - 1
.store:
    mov [rdi], dl
    inc rdi
    loop .digit
    mov byte [rdi], ' '
    inc rdi
    pop rcx
    ret

align 8
tpl_used_states: dq 0
tpl_record:
tpl_phase: dq 0
tpl_state: dq 0
tpl_handle: dq 0
tpl_epoch: dq 0
tpl_armed: dq 0
tpl_down_ms: dq 0
tpl_up_ms: dq 0
tpl_attempts: dq 0
tpl_down_rc: dq -2
tpl_restore_rc: dq -2
tpl_send_rc: dq -2
tpl_driver: times 8 dq 0
tpl_tcp_epoch: dq 0
tpl_tcp_opened: dq 0
tpl_nonce: times 16 db 0
tpl_pair: times 2 dq 0
tpl_down_at: dq 0
tpl_restore_at: dq 0
tpl_retry_at: dq 0
tpl_end_at: dq 0
tpl_sample_at: dq 0
tpl_sample: times 9 dq 0
str_tpl_prefix: db ' TCPLINK rev=1 nonce=',0
%macro TPL_FIELD 2
    dd %1-tpl_record
%%label: db %2,0
    times 20-($-%%label) db 0
%endmacro
tpl_fields:
    TPL_FIELD tpl_phase, ' phase='
    TPL_FIELD tpl_state, ' state='
    TPL_FIELD tpl_handle, ' handle='
    TPL_FIELD tpl_epoch, ' epoch='
    TPL_FIELD tpl_tcp_epoch, ' tcp_epoch='
    TPL_FIELD tpl_tcp_opened, ' tcp_opened='
    TPL_FIELD tpl_armed, ' armed_ms='
    TPL_FIELD tpl_down_ms, ' down_ms='
    TPL_FIELD tpl_up_ms, ' up_ms='
    TPL_FIELD tpl_attempts, ' restores='
    TPL_FIELD tpl_down_rc, ' down_rc='
    TPL_FIELD tpl_restore_rc, ' restore_rc='
    TPL_FIELD tpl_send_rc, ' send_rc='
    TPL_FIELD tpl_driver, ' driver_valid='
    TPL_FIELD tpl_driver+8, ' driver_phase='
    TPL_FIELD tpl_driver+32, ' bmcr='
    TPL_FIELD tpl_driver+40, ' phy='
    TPL_FIELD tpl_driver+56, ' final='
    dd -1
%unmacro TPL_FIELD 2

align 8
tpw_count: dq 0
tpw_until: dq 0
tpw_next: dq 0
tpw_action: dq 0
tpw_isr_base: dq 0
tpw_previous: times 6 dq 0
tpw_words: times 34 dq 0
tpw_member: times 8 dq 0
tpw_line: times 640 db 0
str_tpw_prefix: db '[net.tcp.carrier.v1] ',0
