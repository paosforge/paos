;; MODULE svc/command_hp_serial
;; LAYER 5
;; EXPORTS command_hp_serial_init, hp_serial_out_ready, hp_serial_out_buf, udp_hp_serial_take
;; IMPORTS boot/serial, core/lib/fmt, dev/net/e1000e, dev/net/e1000e_bus_route, net/netdev, svc/command_auth, svc/command, svc/command_udp
;; CAPS
;; OWNER saga:net
; HPSERIAL <decimal-u64-nonce>, OWNER only: the registry alone also admits SYSTEM's
; generic MUTATE, so the handler checks this request and its in-flight ticket.
; Concrete AX99100 TX operation and read-only selected Intel route identity.
; Not a UART configuration verb, link snapshot, or claim of external reception.
command_hp_serial_init:
    lea  rdi, [rel hps_verb]
    lea  rsi, [rel cmd_verb_hp_serial]
    xor  edx, edx
    mov  ecx, ARGT_U64
    xor  r8d, r8d
    mov  r9d, 1                        ; actual UART TX, normal mutating-owner policy
    jmp  command_register_verb

; Complete typed reply before unrelated boot markers, through the ordinary
; UDP envelope/CRC and production hooks. Exact verb/current success only;
; consume staging even for a refused or unrelated response.
udp_hp_serial_take:
    push rbx
    movzx ebx, byte [rel hp_serial_out_ready]
    mov  byte [rel hp_serial_out_ready], 0
    xor  eax, eax
    cmp  dword [rel udp_line], 'HPSE'
    jne  .out
    cmp  dword [rel udp_line + 4], 'RIAL'
    jne  .out
    cmp  byte [rel udp_line + 8], 0
    jne  .out
    call udp_put_uptime
    cmp  qword [rel udp_rsp + RSP_CODE], CMDE_OK
    jne  .yes
    test ebx, ebx
    jz   .yes
    lea  rdi, [rel hp_serial_out_buf]
    call udp_put_str
.yes:
    mov  eax, 1
.out:
    pop  rbx
    ret

cmd_verb_hp_serial:
    call cmd_handler_prologue
    call command_auth_ticket_owner
    cmp  eax, 1
    je   .owner
    mov  qword [rsi + RSP_CODE], CMDE_AUTHDENY
    ret
.owner:
    push rbx
    push r12
    mov  rbx, rsi
    lea  rax, [rel hp_serial_out_buf]
    mov  [rel hps_cur], rax
    mov  r12, [rdi + REQ_ARG]
    lea  rdi, [rel hps_prefix]
    call hps_text
    mov  rdi, r12
    call hps_num
    mov  rdi, r12
    call serial_hp_transmit_probe
    mov  [rel hps_result], eax
    mov  [rel hps_accepted], edx
    mov  [rel hps_lsr], ecx
    lea  rdi, [rel hps_result_word]
    call hps_text
    mov  edi, [rel hps_result]
    call hps_num
    lea  rdi, [rel hps_accepted_word]
    call hps_text
    mov  edi, [rel hps_accepted]
    call hps_num
    lea  rdi, [rel hps_lsr_word]
    call hps_text
    mov  edi, [rel hps_lsr]
    call hps_num
    ; Both command and selected egress must be this same native Intel handle.
    call netdev_select_peek
    lea  rdx, [rel e1000e_dev]
    xor  r12d, r12d
    cmp  rax, rdx
    jne  .selected
    cmp  [rel udp_nic_handle], rdx
    jne  .selected
    inc  r12d
.selected:
    lea  rdi, [rel hps_selected_word]
    call hps_text
    mov  edi, r12d
    call hps_num
    lea  rdi, [rel hps_devid_word]
    call hps_text
    mov  edi, [rel e1000e_devid]
    call hps_num
    lea  rdi, [rel hps_route_word]
    call hps_text
    movzx edi, byte [rel e1000e_bus_route_active]
    call hps_num
    mov  esi, [rel e1000e_pci_dev]
    mov  edx, [rel e1000e_pci_fn]
    call e1000e_bus_identity
    mov  r12d, eax
    lea  rdi, [rel hps_bus_word]
    call hps_text
    mov  edi, r12d
    call hps_num
    ; Tie the native handle to the independent Ethernet proof's exact MAC.
    lea  rdi, [rel hps_mac_word]
    call hps_text
    xor  r12d, r12d
.mac:
    lea  rax, [rel e1000e_mac]
    movzx edi, byte [rax + r12]
    call hps_num
    inc  r12d
    cmp  r12d, 6
    je   .done
    lea  rdi, [rel hps_comma]
    call hps_text
    jmp  .mac
.done:
    mov  byte [rel hp_serial_out_ready], 1
    mov  qword [rbx + RSP_CODE], CMDE_OK
    pop  r12
    pop  rbx
    ret

hps_num:
    lea  rsi, [rel hps_number]
    call fmt_dec
    lea  rdi, [rel hps_number]
hps_text:
    mov  rsi, [rel hps_cur]
.copy:
    lea  rdx, [rel hp_serial_out_buf + 319]
    cmp  rsi, rdx
    jae  .end
    mov  al, [rdi]
    test al, al
    jz   .end
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .copy
.end:
    mov  byte [rsi], 0
    mov  [rel hps_cur], rsi
    ret

hp_serial_out_ready: db 0
hp_serial_out_buf: times 320 db 0
hps_cur: dq 0
hps_result: dd 0
hps_accepted: dd 0
hps_lsr: dd 0
hps_number: times 24 db 0
hps_verb: db 'HPSERIAL', 0
hps_prefix: db ' HPSERIAL rev=1 nonce=', 0
hps_result_word: db ' result=', 0
hps_accepted_word: db ' accepted=', 0
hps_lsr_word: db ' lsr=', 0
hps_selected_word: db ' selected=', 0
hps_devid_word: db ' devid=', 0
hps_route_word: db ' routed=', 0
hps_bus_word: db ' bus=', 0
hps_mac_word: db ' mac=', 0
hps_comma: db ',', 0
