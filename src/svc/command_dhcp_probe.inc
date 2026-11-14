; Bounded, volatile DHCP-only failure observation. Included by command_udp.
; Consumed owner UDP: DHCPTEST ONCE <16hex> <server> / SHOW <16hex> <0..6>.
; Ordinary DHCP FSM owns every send, deadline, timeout and ACK. Capture before
; normal address retirement, recover after it, so loss of public control IP
; never requires another incoming command. No fixed address/lease fabrication.
; Serialized BSP command poll owns this record, like the LEASE staging buffer.
command_udp_dhcp_probe_command:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  rbx, rsi
    mov  byte [rel netlist_ready], 0
    mov  byte [rel udp_lt_ready], 0
    mov  qword [rbx + RSP_CODE], CMDE_BADARG
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
    mov  rsi, [r12 + REQ_ARG]
    lea  rdi, [rel str_dhcp_probe_once]
    call hp_pfx
    jne  .show
    xor  r14d, r14d
    jmp  .nonce
.show:
    mov  rsi, [r12 + REQ_ARG]
    lea  rdi, [rel str_dhcp_probe_show]
    call hp_pfx
    jne  .out
    mov  r14d, 1
.nonce:
    mov  r13, [r12 + REQ_ARG]
    add  r13, 14
    cmp  word [r13], '0x'
    je   .out
    cmp  word [r13], '0X'
    je   .out
    mov  rdi, r13
    call hp_hex_u64_checked
    test ecx, ecx
    jz   .out
    test rax, rax
    jz   .out
    sub  rdx, r13
    cmp  rdx, 16
    jne  .out
    cmp  byte [r13 + 16], ' '
    jne  .out
    test r14d, r14d
    jnz  .read
    mov  r14, rax
    lea  rdi, [r13 + 17]
    call command_udp_dhcp_ipv4_parse
    test edx, edx
    jz   .out
    mov  r13d, eax
    cmp  r14, [rel udp_dp_nonce]
    je   .out                         ; an uncertain arm cannot rearm itself
    mov  rax, [rel udp_dp_phase]
    cmp  rax, 1
    je   .out
    cmp  rax, 2
    je   .out
    cmp  byte [rel udp_netcfg_static], 0
    jne  .out                         ; never displace manual/static policy
    call netdev_select_peek
    test rax, rax
    jz   .out
    mov  rdi, rax
    call virtio_domain_is_handle
    test eax, eax
    jnz  .out                         ; explicit unsupported domain path
    call netdev_select_peek
    mov  rdi, rax
    call netdev_selected_link_ready
    test rax, rax
    jz   .out
    cmp  byte [rel udp_public_dhcp], 1
    je   .public
    cmp  rax, [rel udp_static_owner_handle]
    jne  .out
    cmp  byte [rel dhcp_wire_state], DHCP_WS_OFF
    je   .owner
    ; Fleet policy can retain a real bound lease (Bee738 PUBLIC=0).
    ; Require its selected dynamic owner, exactly as for public DHCP;
    ; do not mistake the fleet/public policy bit for lease validity.
.public:
    cmp  rax, [rel udp_dynamic_owner_handle]
    jne  .out
    cmp  byte [rel dhcp_wire_state], DHCP_WS_BOUND
    jne  .out
    cmp  dword [rel udp_our_ip3], 0
    je   .out
.owner:
    mov  [rel udp_dp_owner], rax
    mov  rax, [rel tsc_khz]
    test rax, rax
    jz   .out
    mov  rcx, 10000
    mul  rcx
    test rdx, rdx
    jnz  .out
    mov  [rel udp_dp_span], rax
    call tsc_now
    add  rax, [rel udp_dp_span]
    jc   .out
    mov  [rel udp_dp_deadline], rax
    mov  [rel udp_dp_nonce], r14
    mov  [rel udp_dp_server], r13d
    mov  qword [rel udp_dp_valid], 0
    mov  qword [rel udp_dp_error], 0
    mov  qword [rel udp_dp_started], 0
    mov  qword [rel udp_dp_next], 2
    mov  eax, [rel udp_primary_mac]
    mov  [rel udp_dp_mac], eax
    mov  ax, [rel udp_primary_mac + 4]
    mov  [rel udp_dp_mac + 4], ax
    xor  edi, edi
    call command_udp_dhcp_probe_capture
    mov  byte [rel udp_dhcp_boot_pending], 0
    mov  byte [rel udp_dhcp_boot_recovery_pending], 0
    mov  rsi, [rel udp_dp_owner]
    mov  [rel udp_dynamic_owner_handle], rsi
    lea  rdi, [rel udp_primary_mac]
    mov  edx, [rel udp_dp_server]
    call dhcp_wire_start_preferred
    test rax, rax
    jnz  .failed
    mov  edi, 1
    call command_udp_dhcp_probe_capture
    mov  rax, [rel udp_lease_words + 104]
    mov  [rel udp_dp_retry], rax
    mov  eax, [rel dhcp_wire_generation]
    mov  [rel udp_dp_generation], eax
    mov  rax, [rel tsc_khz]
    mov  [rel udp_dp_khz], rax
    mov  qword [rel udp_dp_phase], 1
    jmp  .ok
.failed:
    mov  qword [rel udp_dp_error], 1
    mov  qword [rel udp_dp_phase], 4
    jmp  .out
.read:
    cmp  rax, [rel udp_dp_nonce]
    jne  .out
    movzx r14d, byte [r13 + 17]
    sub  r14d, '0'
    cmp  r14d, 6
    ja   .out
    cmp  byte [r13 + 18], 0
    jne  .out
    bt   qword [rel udp_dp_valid], r14
    jnc  .out
    imul rsi, r14, 176
    lea  rax, [rel udp_dp_rows]
    add  rsi, rax
    lea  rdi, [rel udp_lease_words]
    mov  ecx, 22
    cld
    rep movsq
    mov  rax, [rel udp_dp_nonce]
    mov  [rel udp_lease_nonce], rax
    call command_udp_lease_format
    lea  rdi, [rel str_dhcp_probe_slot]
    call netlist_str
    mov  rdi, r14
    call netlist_dec
    lea  rdi, [rel str_dhcp_probe_phase]
    call netlist_str
    mov  rdi, [rel udp_dp_phase]
    call netlist_dec
    lea  rdi, [rel str_dhcp_probe_error]
    call netlist_str
    mov  rdi, [rel udp_dp_error]
    call netlist_dec
    lea  rdi, [rel str_dhcp_probe_server]
    call netlist_str
    mov  edi, [rel udp_dp_server]
    call netlist_dec
    mov  byte [rel netlist_ready], 1
    mov  byte [rel udp_lt_ready], 1
.ok:
    mov  qword [rbx + RSP_ACCEPTED], 1
    mov  qword [rbx + RSP_CODE], CMDE_OK
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; EDI=immutable row index 0..6, checked by the internal fixed callers.
command_udp_dhcp_probe_capture:
    push r12
    mov  r12d, edi
    call command_udp_lease_capture
    imul rdi, r12, 176
    lea  rax, [rel udp_dp_rows]
    add  rdi, rax
    lea  rsi, [rel udp_lease_words]
    mov  ecx, 22
    cld
    rep movsq
    bts  qword [rel udp_dp_valid], r12
    pop  r12
    ret

; Called immediately after the real DHCP FSM tick, before policy can retire
; the fallback/ACK projection. Never drive the FSM or backfill missed states.
command_udp_dhcp_probe_sample:
    cmp  qword [rel udp_dp_phase], 1
    je   .check
    cmp  qword [rel udp_dp_phase], 2
    jne  .out
.check:
    call command_udp_dhcp_probe_check
    test eax, eax
    jz   .failed
    cmp  qword [rel udp_dp_phase], 1
    je   .silent
    cmp  qword [rel udp_dp_phase], 2
    jne  .out
    cmp  qword [rel udp_dp_started], 1
    jne  .out
    cmp  byte [rel dhcp_wire_state], DHCP_WS_BOUND
    jne  .out
    mov  edi, 6
    call command_udp_dhcp_probe_capture
    mov  qword [rel udp_dp_phase], 3
    ret
.failed:
    mov  qword [rel udp_dp_error], 1
    mov  qword [rel udp_dp_phase], 4
    ret
.silent:
    cmp  byte [rel dhcp_wire_state], DHCP_WS_FALLBACK
    je   .fallback
    cmp  byte [rel dhcp_wire_state], DHCP_WS_SELECTING
    jne  .out
    mov  rax, [rel dhcp_wire_retry_tsc]
    cmp  rax, [rel udp_dp_retry]
    je   .out
    mov  [rel udp_dp_retry], rax
    mov  rdi, [rel udp_dp_next]
    cmp  rdi, 4
    ja   .out
    call command_udp_dhcp_probe_capture
    inc  qword [rel udp_dp_next]
    ret
.fallback:
    mov  edi, 5
    call command_udp_dhcp_probe_capture
    mov  qword [rel udp_dp_phase], 2
.out:
    ret

; Runs after ordinary DHCP/DNS policy retirement. A saved owner+MAC must
; still be selected. Recovery is one ordinary start, regardless of incoming
; control reachability; deadlines never rearm and no new server is guessed.
command_udp_dhcp_probe_tick:
    mov  rax, [rel udp_dp_phase]
    cmp  rax, 1
    je   .active
    cmp  rax, 2
    jne  .out
.active:
    call command_udp_dhcp_probe_check
    test eax, eax
    jz   .failed
    call tsc_now
    cmp  rax, [rel udp_dp_deadline]
    jbe  .deadline_ok
    mov  qword [rel udp_dp_error], 1
    cmp  qword [rel udp_dp_phase], 2
    jne  .force_recovery
    cmp  qword [rel udp_dp_started], 1
    je   .failed
.force_recovery:
    mov  qword [rel udp_dp_phase], 2   ; recover even if silent FSM missed bound
.deadline_ok:
    cmp  qword [rel udp_dp_phase], 2
    jne  .out
    cmp  qword [rel udp_dp_started], 0
    jne  .out
    mov  qword [rel udp_dp_started], 1 ; consume before any transmission
    call tsc_now
    add  rax, [rel udp_dp_span]
    jc   .failed
    mov  [rel udp_dp_deadline], rax
    mov  rsi, [rel udp_dp_owner]
    mov  [rel udp_dynamic_owner_handle], rsi
    lea  rdi, [rel udp_primary_mac]
    call dhcp_wire_start
    test rax, rax
    jnz  .failed
    mov  eax, [rel dhcp_wire_generation]
    mov  [rel udp_dp_generation], eax
.out:
    ret
.failed:
    mov  qword [rel udp_dp_error], 1
    mov  qword [rel udp_dp_phase], 4
    ret

; A local policy change, lease replacement, clock change or NIC replacement
; cancels observation. The probe never overrides a later explicit choice.
command_udp_dhcp_probe_check:
    cmp  byte [rel udp_netcfg_static], 0
    jne  .bad
    call netdev_select_peek
    cmp  rax, [rel udp_dp_owner]
    jne  .bad
    mov  eax, [rel udp_primary_mac]
    cmp  eax, [rel udp_dp_mac]
    jne  .bad
    mov  ax, [rel udp_primary_mac + 4]
    cmp  ax, [rel udp_dp_mac + 4]
    jne  .bad
    mov  rax, [rel tsc_khz]
    cmp  rax, [rel udp_dp_khz]
    jne  .bad
    mov  eax, [rel dhcp_wire_generation]
    cmp  eax, [rel udp_dp_generation]
    jne  .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret
str_dhcp_probe_once: db "DHCPTEST ONCE ",0
str_dhcp_probe_show: db "DHCPTEST SHOW ",0
str_dhcp_probe_slot: db " SLOT=",0
str_dhcp_probe_phase: db " PHASE=",0
str_dhcp_probe_error: db " ERROR=",0
str_dhcp_probe_server: db " SILENT=",0
%macro WDATA_command_dhcp_probe 0
align 8
udp_dp_phase: dq 0
udp_dp_nonce: dq 0
udp_dp_owner: dq 0
udp_dp_span: dq 0
udp_dp_deadline: dq 0
udp_dp_valid: dq 0
udp_dp_error: dq 0
udp_dp_started: dq 0
udp_dp_next: dq 0
udp_dp_retry: dq 0
udp_dp_khz: dq 0
udp_dp_generation: dd 0
udp_dp_server: dd 0
udp_dp_mac: times 8 db 0
align 8
udp_dp_rows: times 154 dq 0
%endmacro
WDATA_DEFER WDATA_command_dhcp_probe
