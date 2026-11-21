; One owner-configured, volatile USB command endpoint. No selection, DHCP,
; routing, driver reset, auth/replay state, or guest/domain publication changes.
; The BSP command pump owns this record. A registry generation change retires it.
command_usb_clear:
    mov  qword [rel udp_usb_member], 0          ; unpublish before clearing the tuple
    mov  dword [rel udp_usb_address], 0
    mov  dword [rel udp_usb_mask], 0
    ret

; -> RAX=exact attached native member / 0. Registry-only lifetime checks precede
; every RX and follow it before any frame effects. Never dereference a stale dev.
; A retire records which check failed (udp_usb_retire_reason, USB SHOW RETIRE=):
;  1 power member gone/unhealthy  2 epoch pointer  3 epoch  4 observation member
;  5 slot  6 generation  7 tx method null  8 tx method changed  9 primary alias
; 10 OOB alias  11 address zero  12 address now a primary/OOB/domain address.
command_usb_current:
    push rbx
    mov  rbx, [rel udp_usb_member]
    test rbx, rbx
    jz   .none
    mov  rdi, rbx
    mov  rsi, [rel udp_usb_member + 8]
    call netdev_power_member
    mov  ecx, 1
    test rax, rax
    jz   .lost
    mov  ecx, 2
    cmp  rax, [rel udp_usb_member + 32]
    jne  .lost
    mov  ecx, 3
    cmp  rdx, [rel udp_usb_member + 40]
    jne  .lost
    mov  rdi, rbx
    mov  rsi, [rel udp_usb_member + 16]
    call netdev_observation_member
    mov  ecx, 4
    test eax, eax
    jz   .lost
    dec  eax
    mov  ecx, 5
    cmp  eax, [rel udp_usb_slot]
    jne  .lost
    mov  ecx, 6
    cmp  rdx, [rel udp_usb_generation]
    jne  .lost
    ; Registry checks above establish the saved ops pointer is still live.
    ; A method replacement must retire the attachment before RX or plain TX.
    mov  rax, [rel udp_usb_member + 8]
    mov  rax, [rax + netdev_ops.tx]
    mov  ecx, 7
    test rax, rax
    jz   .lost
    mov  ecx, 8
    cmp  rax, [rel udp_usb_member + 24]
    jne  .lost
    mov  ecx, 9
    cmp  rbx, [rel udp_nic_handle]
    je   .lost
    mov  ecx, 10
    cmp  rbx, [rel udp_oob_nic_handle]
    je   .lost
    mov  eax, [rel udp_usb_address]
    mov  ecx, 11
    test eax, eax
    jz   .lost
    mov  ecx, 12
    cmp  eax, [rel udp_our_ip]
    je   .lost
    cmp  eax, [rel udp_our_ip2]
    je   .lost
    cmp  eax, [rel udp_our_ip3]
    je   .lost
    mov  rax, rbx
    pop  rbx
    ret
.lost:
    mov  [rel udp_usb_retire_reason], ecx
    inc  qword [rel udp_usb_retires]
    call command_usb_clear
.none:
    xor  eax, eax
    pop  rbx
    ret

command_usb_poll:
    sub  rsp, 8
    call command_usb_current
    test rax, rax
    jz   .out
    inc  qword [rel udp_usb_polls]             ; USB SHOW POLLS: live attachment reached RX
    mov  rdi, rax
    mov  rsi, [rel udp_usb_member + 16]
    lea  rdx, [rel udp_usb_member + 48]
    mov  byte [rel udp_usb_receiving], 1
    call command_udp_poll_one                   ; one frame per pump; RX readiness checked at attach
    mov  byte [rel udp_usb_receiving], 0
    mov  qword [rel udp_ingress_handle], 0
.out:
    add  rsp, 8
    ret

; NETCFG USB STATIC SET <slot0..7> <12hex actualMAC> <address> <mask>
; NETCFG USB CLEAR
; NETCFG USB SHOW <16hex nonce>
; All use the existing NETCFG consumed remote OWNER ticket, never a USB role.
command_usb_command:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 96                               ; helper64, expectedMAC8, address4/mask4, generation8
    mov  rbx, rsi
    mov  r12, rdi
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
    mov  byte [rel netlist_ready], 0
    cmp  qword [r12 + REQ_SOURCE], CMD_SOURCE_UDP
    jne  .out
    cmp  byte [rel command_auth_remote_active], 1
    jne  .out
    mov  rax, [rel command_auth_remote_ticket]
    test rax, rax
    jz   .out
    cmp  byte [rax + AUTH_T_STATE], AUTH_TS_CONSUMED
    jne  .out
    cmp  qword [rax + AUTH_T_PRINCIPAL], PRIN_OWNER
    jne  .out
    mov  r14, [r12 + REQ_ARG]
    test r14, r14
    jz   .out
    mov  rsi, r14
    lea  rdi, [rel str_usb_set]
    call hp_pfx
    jne  .try_clear
    add  r14, 15                               ; "USB STATIC SET "
    movzx r13d, byte [r14]
    sub  r13d, '0'
    cmp  r13d, 7
    ja   .out
    cmp  byte [r14 + 1], ' '
    jne  .out
    add  r14, 2
    xor  r15d, r15d
.mac:
    movzx ecx, byte [r14]
    call hp_nibble
    cmp  eax, -1
    je   .out
    shl  eax, 4
    mov  [rsp + r15 + 64], al
    movzx ecx, byte [r14 + 1]
    call hp_nibble
    cmp  eax, -1
    je   .out
    or   [rsp + r15 + 64], al
    add  r14, 2
    inc  r15
    cmp  r15, 6
    jb   .mac
    cmp  byte [r14], ' '
    jne  .out
    lea  rdi, [r14 + 1]
    call command_udp_manual_quad
    test edx, edx
    jz   .out
    mov  [rsp + 72], eax
    cmp  byte [rdi], ' '
    jne  .out
    inc  rdi
    call command_udp_manual_quad
    test edx, edx
    jz   .out
    cmp  byte [rdi], 0
    jne  .out
    mov  [rsp + 76], eax
    bswap eax
    test eax, eax
    jz   .out
    not  eax
    cmp  eax, 3
    jb   .out                                  ; /31,/32 unsupported
    lea  edx, [eax + 1]
    test eax, edx
    jnz  .out                                  ; noncontiguous mask
    mov  eax, [rsp + 72]
    call command_udp_manual_unicast
    test edx, edx
    jz   .out
    cmp  eax, [rel udp_our_ip]
    je   .out
    cmp  eax, [rel udp_our_ip2]
    je   .out
    cmp  eax, [rel udp_our_ip3]
    je   .out
    mov  ecx, [rsp + 76]
    not  ecx
    and  eax, ecx
    jz   .out
    cmp  eax, ecx
    je   .out                                  ; network/broadcast address
    mov  qword [rbx + RSP_CODE], CMDE_BADSEL
    mov  edi, r13d
    lea  rsi, [rsp + 64]
    mov  rdx, rsp
    call usb_command_member                    ; INPUT: registered, cached-MAC, nonblocking USB only
    test rax, rax
    jnz  .out
    mov  rax, [rsp]
    cmp  rax, [rel udp_nic_handle]
    je   .out
    cmp  rax, [rel udp_oob_nic_handle]
    je   .out
    mov  rdi, rax
    mov  rsi, [rsp + 16]
    call netdev_observation_member
    test eax, eax
    jz   .out
    dec  eax
    cmp  eax, r13d
    jne  .out
    mov  [rsp + 80], rdx
    ; Publication is failure-atomic: no live state was written during validation.
    call command_usb_clear
    lea  rdi, [rel udp_usb_member]
    mov  rsi, rsp
    mov  ecx, 8
    rep  movsq
    mov  [rel udp_usb_slot], r13d
    mov  rax, [rsp + 80]
    mov  [rel udp_usb_generation], rax
    mov  eax, [rsp + 76]
    mov  [rel udp_usb_mask], eax
    mov  eax, [rsp + 72]
    mov  [rel udp_usb_address], eax
    mov  [rbx + RSP_VAL], rax
    mov  rax, [rel udp_usb_member]
    mov  [rel udp_usb_last_handle], rax         ; SHOW counters survive CLEAR/retire
    jmp  .ok
.try_clear:
    mov  rsi, r14
    lea  rdi, [rel str_usb_clear]
    call hp_pfx
    jne  .try_show
    cmp  byte [r14 + 9], 0
    jne  .out
    call command_usb_clear
    jmp  .ok
.try_show:
    mov  rsi, r14
    lea  rdi, [rel str_usb_show]
    call hp_pfx
    jne  .out
    lea  r15, [r14 + 9]
    cmp  word [r15], '0x'
    je   .out
    mov  rdi, r15
    call hp_hex_u64_checked
    test ecx, ecx
    jz   .out
    sub  rdx, r15
    cmp  rdx, 16
    jne  .out
    cmp  byte [r15 + 16], 0
    jne  .out
    mov  r14, rax
    call command_usb_current
    mov  r15, rax
    lea  rax, [rel netlist_buf]
    mov  [rel netlist_cur], rax
    mov  byte [rax], 0
    lea  rdi, [rel str_usb_head]
    call netlist_str
    mov  rdi, [rel boot_tsc_start]
    call netlist_dec
    lea  rdi, [rel str_usb_nonce]
    call netlist_str
    mov  rdi, r14
    call netlist_dec
    lea  rdi, [rel str_usb_active]
    call netlist_str
    xor  edi, edi
    test r15, r15
    setnz dil
    call netlist_dec
    lea  rdi, [rel str_usb_endpoint_slot]
    call netlist_str
    mov  edi, [rel udp_usb_slot]
    call netlist_dec
    lea  rdi, [rel str_usb_generation]
    call netlist_str
    mov  rdi, [rel udp_usb_generation]
    call netlist_dec
    lea  rdi, [rel str_usb_ip]
    call netlist_str
    mov  edi, [rel udp_usb_address]
    call netlist_dec
    lea  rdi, [rel str_usb_mask]
    call netlist_str
    mov  edi, [rel udp_usb_mask]
    call netlist_dec
    lea  rdi, [rel str_usb_mac]
    call netlist_str
    xor  r13d, r13d
.show_mac:
    lea  rax, [rel udp_usb_member + 48]
    movzx edi, byte [rax + r13]
    call netlist_hex2
    inc  r13
    cmp  r13, 6
    jb   .show_mac
    ; ROOT118715: retire evidence and the attached backend's software counters.
    ; Counters are read by pointer equality on the last attached handle (never a
    ; dereference of a retired member), so SHOW after CLEAR or a retire still reports.
    lea  rdi, [rel str_usb_retire]
    call netlist_str
    mov  edi, [rel udp_usb_retire_reason]
    call netlist_dec
    lea  rdi, [rel str_usb_retires]
    call netlist_str
    mov  rdi, [rel udp_usb_retires]
    call netlist_dec
    lea  rdi, [rel str_usb_polls]
    call netlist_str
    mov  rdi, [rel udp_usb_polls]
    call netlist_dec
    mov  rdi, [rel udp_usb_last_handle]
    mov  rsi, rsp
    call usb_command_counters
    test eax, eax
    jz   .show_counters
    lea  rdi, [rel str_usb_backend_none]
    call netlist_str
    jmp  .show_done
.show_counters:
    lea  rdi, [rel str_usb_backend_ecm]
    call netlist_str
    xor  r13d, r13d
.show_counter:
    lea  rax, [rel usb_show_counter_names]
    movsxd rdi, dword [rax + r13*4]            ; self-relative: the image is not relocated
    add  rdi, rax
    call netlist_str
    mov  rdi, [rsp + r13*8]
    cmp  r13, 3                                ; RXRC and TXRC are signed rc values
    je   .show_signed
    cmp  r13, 7
    je   .show_signed
.show_unsigned:
    call netlist_dec
    jmp  .show_next
.show_signed:
    test rdi, rdi
    jns  .show_unsigned
    push rdi
    sub  rsp, 8
    lea  rdi, [rel str_usb_minus]
    call netlist_str
    add  rsp, 8
    pop  rdi
    neg  rdi
    call netlist_dec
.show_next:
    inc  r13
    cmp  r13, USB_SHOW_COUNTERS
    jb   .show_counter
.show_done:
    mov  byte [rel netlist_ready], 1
.ok:
    mov  qword [rbx + RSP_ACCEPTED], 1
    mov  qword [rbx + RSP_CODE], CMDE_OK
.out:
    add  rsp, 96
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

str_usb_prefix: db "USB ",0
str_usb_set: db "USB STATIC SET ",0
str_usb_clear: db "USB CLEAR",0
str_usb_show: db "USB SHOW ",0
str_usb_head: db " USBENDPOINT BOOT=",0
str_usb_nonce: db " NONCE=",0
str_usb_active: db " ACTIVE=",0
str_usb_endpoint_slot: db " SLOT=",0
str_usb_generation: db " GEN=",0
str_usb_ip: db " IP=",0
str_usb_mask: db " MASK=",0
str_usb_mac: db " MAC=",0
str_usb_retire: db " RETIRE=",0
str_usb_retires: db " RETIRES=",0
str_usb_polls: db " POLLS=",0
str_usb_backend_none: db " BACKEND=none",0
str_usb_backend_ecm: db " BACKEND=cdc_ecm",0
str_usb_minus: db "-",0
str_usb_rxc: db " RXC=",0
str_usb_rxf: db " RXF=",0
str_usb_rxerr: db " RXERR=",0
str_usb_rxrc: db " RXRC=",0
str_usb_rxgate: db " RXGATE=",0
str_usb_txc: db " TXC=",0
str_usb_txf: db " TXF=",0
str_usb_txrc: db " TXRC=",0
str_usb_health: db " HEALTH=",0
str_usb_streak: db " STREAK=",0
USB_SHOW_COUNTERS equ 10                       ; cdc_ecm_usb_counters order
align 4
usb_show_counter_names:
    dd str_usb_rxc - usb_show_counter_names, str_usb_rxf - usb_show_counter_names
    dd str_usb_rxerr - usb_show_counter_names, str_usb_rxrc - usb_show_counter_names
    dd str_usb_rxgate - usb_show_counter_names, str_usb_txc - usb_show_counter_names
    dd str_usb_txf - usb_show_counter_names, str_usb_txrc - usb_show_counter_names
    dd str_usb_health - usb_show_counter_names, str_usb_streak - usb_show_counter_names
%macro WDATA_command_usb_endpoint 0
align 8
udp_usb_member: times 8 dq 0
udp_usb_generation: dq 0
udp_usb_slot: dd 0
udp_usb_address: dd 0
udp_usb_mask: dd 0
udp_usb_receiving: db 0
align 8
udp_usb_last_handle: dq 0                      ; pointer-equality key only, never dereferenced
udp_usb_retires: dq 0
udp_usb_polls: dq 0
udp_usb_retire_reason: dd 0
%endmacro
WDATA_DEFER WDATA_command_usb_endpoint
