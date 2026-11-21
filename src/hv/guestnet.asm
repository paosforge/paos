;; MODULE hv/guestnet
%include "hv/guest_power.inc"
%include "hv/guest_destination.inc"

;; LAYER 5
;; EXPORTS guestnet_out_buf, guestnet_out_ready, guestnet_register_verbs, guestnet_status_line, guestnet_state_zero, guestnet_detach, guestnet_device_reset, guestnet_mmio_write, guestnet_try_inject_irq, guestnet_pump, guestnet_console_byte, guestnet_nat_rx_frame, guestnet_physical_dataplane_step, guestnet_domain_bind, guestnet_mmio_writes, guestnet_guest_tx_packets, guestnet_tx_used_advance, guestnet_tx_backpressure
;; IMPORTS hv/guest_power, svc/command, svc/command_udp, svc/command_auth, sec/session, hv/vmx, hv/hv_ops, hv/vm_profile, dev/net/virtio_domain, net/netdev, net/arp_cache, net/dhcp, net/dns, core/lib/cksum, boot/serial, core/sched, core/time
;; OWNER saga:hv
;; CONTEXT: bsp_only
; ============================================================================
; 1109 — guest virtio-net + host NAT (the easy networking path, ESSENCE E4).
;
; This is a seam-adapted port of Classic's wire-proven gl_vio_* split-ring
; device.  PaOS owns the physical NIC; Linux sees a modern virtio-mmio net
; device on a private 10.0.2.0/24 link.  PaOS answers DHCP and masquerades
; guest UDP/TCP/ICMP echo behind the runtime-selected physical address. NAT egress uses
; the one canonical netdev_tx dispatch and the shared live ARP cache.
;
; Device: GPA 0xD0001000, IRQ6, DeviceID=1, queues 0=RX / 1=TX.
; Guest:  10.0.2.15/24, gateway 10.0.2.2, current native upstream DNS if usable.
; NAT:    host UDP/TCP ports 40000..49151, tuple-checked before un-NAT; the host
;         address follows the runtime-selected physical NIC profile.
; ============================================================================

GN_INDIRECT      equ 1 << 28
GN_FEATURES      equ 0x20 | GN_INDIRECT
GN_QMAX          equ 64
GN_TXBUF_MAX     equ 1610
GN_FRAME_MAX     equ 1514
GN_NAT_SLOTS     equ 16
GN_NAT_PORT_BASE equ 40000
GN_NAT_PORT_END  equ 49152                 ; exclusive; native clients use 49152+
GN_TCP_CLOSE_US  equ 120000000             ; first accepted FIN, never extended
GN_TCP_IDLE_US   equ 432000000000          ; 5 days; conservative conntrack idle policy
GN_UDP_IDLE_US   equ 30000000              ; 30 seconds of accepted-forward inactivity
GN_TTL_INTERVAL  equ 100000                ; at most ten local error attempts/second
GN_TTL_QUOTE_MAX equ 548                   ; outer IPv4 + ICMP + quote <=576 bytes
GN_ER_SLOTS      equ 16
GN_ER_SIZE       equ 1568
GN_ER_IDLE_US    equ 30000000
GN_ER_GPORT      equ 2
GN_ER_CKSUM      equ 4
GN_ER_SESSION    equ 8
GN_ER_EPOCH      equ 16
GN_ER_AT         equ 24
GN_ER_LEN        equ 32
GN_ER_IP         equ 64                    ; complete accepted wire IPv4, up to1500 bytes
GN_IC_IDLE_US    equ 30000000              ; accepted echo request custody, not authentication
GN_IC_SLOTS      equ 16
GN_IC_SIZE       equ 1536
GN_IC_ID_BASE    equ 32768
GN_IC_ID_END     equ 65536                 ; exclusive, checked dword serial; no wrap
GN_IC_GID        equ 2
GN_IC_NID        equ 4
GN_IC_SEQ        equ 6
GN_IC_REMOTE     equ 8
GN_IC_HOST       equ 12
GN_IC_SESSION    equ 16
GN_IC_EPOCH      equ 24
GN_IC_LAST       equ 32
GN_IC_LEN        equ 40
GN_IC_PAYLOAD    equ 48                    ; up to1472 bytes, exact original payload

; IPv4 values are stored in wire-byte order as little-endian dwords.
GN_GUEST_IP      equ 0x0F02000A            ; 10.0.2.15
GN_GATEWAY_IP    equ 0x0202000A            ; 10.0.2.2

; Conntrack entry (24 bytes). Ports at +2/+4 remain in network byte order.
GN_N_VALID       equ 0
GN_N_GPORT       equ 2
GN_N_RPORT       equ 4
GN_N_NPORT       equ 6                     ; host-order NAT port
GN_N_GIP         equ 8
GN_N_RIP         equ 12
GN_N_PROTO       equ 16                     ; use reserved entry byte; no layout growth
GN_N_SIZE        equ 24

GN_LAUNCH_NONE      equ 0
GN_LAUNCH_REQUESTED equ 1
GN_LAUNCH_ACHIEVED  equ 2
GN_LAUNCH_REFUSED   equ 3
GN_LAUNCH_OWNER_CHANGED equ 254          ; local, not a native loader error
GN_LAUNCH_UNPUBLISHED   equ 253          ; local publisher refusal
GN_SHELL_PROBE_LIMIT equ 255               ; finite one-byte budget across delayed guest init
GN_SHELL_PROBE_MS    equ 7000              ; <=30 min total; pace even if RX ring is empty
GN_SHELL_ACK_LEN     equ 30                ; PAOS-GN-READY- + 16 hex serial digits
GN_SHELL_ACK_CR_WAIT equ 31                ; one terminal ONLCR CR before LF
GN_SHELL_DROP        equ 0xffffffff        ; ignore current line until LF
GN_SHELL_REPLY_LEN   equ 32                ; leading LF, complete token, final LF
GN_SHELL_CMD_PREFIX  equ 21                ; /bin/busybox printf '
GN_SHELL_CMD_LEN     equ GN_SHELL_CMD_PREFIX + GN_SHELL_REPLY_LEN * 4 + 1
%if GN_SHELL_CMD_LEN > 254
    %error shell_probe_exceeds_console_line_capacity
%endif

; ---------------------------------------------------------------------------
; Command surface: one transport-neutral GUESTNET verb with START/STAT/NONCE/
; STOP subverbs. The UDP projection only frames the staged line.
; ---------------------------------------------------------------------------
; Build the physical-uplink command through the already-proven guest sender.
; Linux's r8169, udhcpc, route table and neighbour table remain authoritative;
; PaOS neither synthesizes a lease nor claims ARP from assignment alone.
guestnet_physical_dataplane_step:
    HV_POWER_WORK guestnet_physical_dataplane_step, 0, hv_guest_power_admit
    mov  byte [rel guestnet_build_physical], 1
    call guestnet_build_nonce_command
    mov  byte [rel guestnet_build_physical], 0
    test eax, eax
    jz   .bad
    lea  rax, [rel guestnet_pending_cmd]
    ret
.bad:
    xor  eax, eax
    ret

; Bind/unbind transparent-L2 delivery to an ordinary virtio_domain context.
; RDI=ctx or 0. The virtio device remains generic: it only forwards complete
; Ethernet frames and never knows DHCP, ARP, UDP, or a physical NIC model.
guestnet_domain_bind:
    HV_POWER_WORK guestnet_domain_bind, 0, hv_guest_power_admit
    call guestnet_ingress_clear
    inc  qword [rel guestnet_ring_epoch]
    mov  [rel guestnet_domain_ctx], rdi
    mov  byte [rel guestnet_tx_retry_pending], 0
    jmp  guestnet_irq_revoke

guestnet_register_verbs:
    lea  rdi, [rel str_gn_verb]
    lea  rsi, [rel guestnet_command]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    ; Explicit owner mutation, including local console principal verification.
    lea  rdi, [rel str_gn_ssh_verb]
    lea  rsi, [rel guestnet_ingress_command]
    mov  rdx, CMD_AUTH_CAP_MUTATE
    mov  ecx, ARGT_TEXT
    xor  r8d, r8d
    mov  r9d, 1
    call command_register_verb
    ; Common-payload native NIC discovery. The RTL backend registers degraded
    ; and becomes healthy only after strict live PCI/revision/MAC_VER_46 bind.
    call rtl8168_boot_bringup
    ; MSI onboard Killer E5000B (RTL8126): registers only on an exact single
    ; 10ec:5000 bind with armed rings; every other target logs the absent path.
    call e5000b_hw_bringup
    ; Onboard Realtek RTL8125A/B (10ec:8125, e.g. Reatan A8): XID-gated,
    ; up to two ports; absent on every other target (one marker, nothing bound).
    call rtl8125_hw_bringup
    ret

guestnet_command:
    push rbx
    push r12
    call cmd_handler_prologue
    mov  r12, rsi
    mov  rbx, [rdi + REQ_ARG]
    mov  rdi, rbx
    lea  rsi, [rel str_gn_start]
    call hv_tok_is
    test al, al
    jnz  .start
    mov  rdi, rbx
    lea  rsi, [rel str_gn_stat]
    call hv_tok_is
    test al, al
    jnz  .stat
    mov  rdi, rbx
    lea  rsi, [rel str_gn_nonce]
    call hv_tok_is
    test al, al
    jnz  .nonce
    mov  rdi, rbx
    lea  rsi, [rel str_gn_stop]
    call hv_tok_is
    test al, al
    jnz  .stop
    call guestnet_out_reset
    lea  rdi, [rel str_gn_usage]
    call guestnet_out_str
    jmp  .ready
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
.start_media_busy:                         ; nothing changed: no session, stop_req or request
    call guestnet_out_reset
    lea  rdi, [rel str_gn_media_busy]
    call guestnet_out_str
    jmp  .ready
%endif
%endif

.start:
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    cmp  byte [rel hv_vcon_pmr_bound], 0
    jne  .start_media_busy                 ; RCQ-37: the media owner holds the vCPU seam
%endif
%endif
    HV_POWER_CHECK hv_guest_power_admit, .stat
    ; A queued request or in-progress loader owns the one VM seam. Do not
    ; replace its generation, selected artifacts or network session. Live
    ; attach remains supported, but only to an actually consumed generation.
    cmp  byte [rel hv_linux_run_req], 0
    jne  .start_busy
    cmp  byte [rel hv_linux_running], 0
    je   .start_idle
    cmp  byte [rel hv_linux_running], 1
    jne  .start_busy
    ; The resident task holds start_active throughout hv_ops_launch_active,
    ; including every host slice of a live VM. Require that exact managed
    ; seam here; a zero-running loader is still rejected in .start_idle.
    cmp  byte [rel hv_linux_start_active], 1
    jne  .start_busy
    cmp  byte [rel hv_linux_stop_req], 0
    jne  .start_busy
    mov  eax, [rel hv_linux_start_consumed]
    test eax, eax
    jz   .start_busy
    cmp  eax, [rel hv_linux_start_gen]
    jne  .start_busy
    jmp  .start_admitted
.start_idle:
    cmp  byte [rel hv_linux_start_active], 0
    jne  .start_busy
    cmp  dword [rel hv_linux_start_gen], -1
    je   .start_busy                       ; final nonzero generation is retained
.start_admitted:
    call guestnet_reset_session
    mov  byte [rel guestnet_active], 1
    mov  byte [rel guestnet_launch_state], GN_LAUNCH_REQUESTED
    mov  byte [rel guestnet_launch_err], 0
    mov  byte [rel hv_linux_stop_req], 0
    mov  byte [rel guestnet_dhcp_inject_pending], 1
    cmp  byte [rel hv_linux_running], 1
    jne  .start_request
    mov  eax, [rel hv_linux_start_consumed]
    mov  [rel guestnet_launch_gen], eax
    mov  byte [rel guestnet_launch_state], GN_LAUNCH_ACHIEVED
    jmp  .start_kick
.start_request:
    call hv_guest_linux_request_start       ; publish generation + run request together
    test eax, eax
    jz   .start_unpublished                ; power may revoke at the real publisher
    mov  [rel guestnet_launch_gen], eax
    cmp  byte [rel hv_linux_task_started], 1
    je   .start_kick
    lea  rdi, [rel hv_guest_linux_task]
    call sched_spawn
    cmp  eax, -1
    jne  .spawned
    mov  byte [rel hv_linux_run_req], 0
    mov  byte [rel hv_linux_load_err], 9
    mov  byte [rel guestnet_launch_err], 9
    mov  byte [rel guestnet_launch_state], GN_LAUNCH_REFUSED
    mov  byte [rel guestnet_active], 0
    mov  byte [rel guestnet_nat_up], 0
    mov  byte [rel guestnet_dhcp_inject_pending], 0
    call guestnet_render_stat
    jmp  .ready
.spawned:
    mov  byte [rel hv_linux_task_started], 1
.start_kick:
    call sched_yield
    call guestnet_render_stat
    jmp  .ready

.start_busy:
    call guestnet_out_reset
    lea  rdi, [rel str_gn_owner_busy]
    call guestnet_out_str
    jmp  .ready
.start_unpublished:
    mov  byte [rel guestnet_active], 0
    mov  byte [rel guestnet_nat_up], 0
    mov  byte [rel guestnet_dhcp_inject_pending], 0
    mov  byte [rel guestnet_launch_state], GN_LAUNCH_REFUSED
    mov  byte [rel guestnet_launch_err], GN_LAUNCH_UNPUBLISHED
    mov  dword [rel guestnet_launch_gen], 0
    call guestnet_render_stat
    jmp  .ready

.stat:
    call guestnet_render_stat
    jmp  .ready

.nonce:
    HV_POWER_CHECK hv_guest_power_admit, .stat
    mov  rdi, rbx
    call guestnet_build_nonce_command
    test eax, eax
    jz   .nonce_bad
    mov  byte [rel guestnet_pending_cmd_ready], 1
    call guestnet_out_reset
    lea  rdi, [rel str_gn_nonce_queued]
    call guestnet_out_str
    jmp  .ready
.nonce_bad:
    call guestnet_out_reset
    lea  rdi, [rel str_gn_nonce_bad]
    call guestnet_out_str
    jmp  .ready

.stop:
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
    cmp  byte [rel hv_vcon_pmr_bound], 0
    jne  .start_media_busy                 ; RCQ-37: never stops the media owner's guest
%endif
%endif
    HV_POWER_CHECK hv_guest_power_admit, .stat
    call guestnet_command_owns_run
    mov  ebx, eax                         ; survives rendering, reports actual stop
    test eax, eax
    jz   .stop_local
    mov  byte [rel hv_linux_run_req], 0
    cmp  byte [rel hv_linux_running], 1
    jne  .stop_local
    mov  byte [rel hv_linux_stop_req], 1
.stop_local:
    call guestnet_ingress_clear
    ; Retire local injection even after supersession. Foreign VM requests and
    ; stop flags are never modified by an old or absent GUESTNET session.
    mov  byte [rel guestnet_active], 0
    mov  byte [rel guestnet_launch_state], GN_LAUNCH_NONE
    mov  byte [rel guestnet_launch_err], 0
    mov  dword [rel guestnet_launch_gen], 0
    mov  byte [rel guestnet_nat_up], 0
    mov  byte [rel guestnet_dhcp_inject_pending], 0
    mov  byte [rel guestnet_shell_probe_pending], 0
    mov  byte [rel guestnet_shell_ready], 0
    mov  dword [rel guestnet_shell_match], GN_SHELL_DROP
    mov  dword [rel guestnet_shell_probe_gen], 0
    mov  qword [rel guestnet_shell_probe_epoch], 0
    mov  byte [rel guestnet_pending_cmd_ready], 0
    call guestnet_render_stat
    lea  rdi, [rel str_gn_stopping]
    test ebx, ebx
    jnz  .stop_emit
    lea  rdi, [rel str_gn_not_stopping]
.stop_emit:
    call guestnet_out_str
.ready:
    mov  byte [rel guestnet_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_OK
    pop  r12
    pop  rbx
    ret

; EAX=1 only for this active session's exact queued or consumed START.
; Pure check: no reset, transport, scheduler or power side effects.
guestnet_command_owns_run:
    xor  eax, eax
    cmp  byte [rel guestnet_active], 1
    jne  .out
    mov  ecx, [rel guestnet_launch_gen]
    test ecx, ecx
    jz   .out
    cmp  ecx, [rel hv_linux_start_gen]
    jne  .out
    cmp  byte [rel hv_linux_running], 1
    ja   .out
    cmp  byte [rel hv_linux_start_active], 1
    ja   .out
    mov  dl, [rel hv_linux_running]
    or   dl, [rel hv_linux_start_active]
    jnz  .consumed
    cmp  byte [rel hv_linux_run_req], 1
    jne  .out
    cmp  ecx, [rel hv_linux_start_consumed]
    je   .out                             ; cannot cancel a duplicate consumed request
    mov  eax, 1
    ret
.consumed:
    cmp  byte [rel hv_linux_run_req], 0
    jne  .out
    cmp  ecx, [rel hv_linux_start_consumed]
    sete al
.out:
    ret

; Called early from command_udp's reply builder so the bounded payload cannot
; truncate the staged GUESTNET line. Late marker tokens are BOOTLOG-only: this
; keeps unrelated replies byte-stable while preserving post-flush evidence.
guestnet_status_line:
    ; Append the selected native-NIC token only after real RTL hardware bound.
    call rtl8168_status_line
    cmp  byte [rel guestnet_out_ready], 1
    jne  .markers
    lea  rdi, [rel guestnet_out_buf]
    call udp_put_str
    mov  byte [rel guestnet_out_ready], 0
.markers:
    lea  rdi, [rel udp_line]
    lea  rsi, [rel str_verb_bootlog]
    call strcmp
    test rax, rax
    jnz  .done
    call rtl8168_bootlog_line            ; w046: bound-RTL-only RX wipe KAT + RX health
    lea  rdi, [rel str_gn_ports]
    call udp_put_str
    call guestnet_nat_ports_left
    mov  edi, eax
    call udp_put_dec
    cmp  byte [rel guestnet_marker_virtio], 1
    jne  .no_vio
    lea  rdi, [rel str_gn_udp_vio]
    call udp_put_str
.no_vio:
    cmp  byte [rel guestnet_marker_dhcp], 1
    jne  .done
    lea  rdi, [rel str_gn_udp_dhcp]
    call udp_put_str
.done:
    ret

; ---------------------------------------------------------------------------
; Session/control helpers.
; ---------------------------------------------------------------------------
guestnet_reset_session:
    call guestnet_ingress_clear
    cld
    xor  eax, eax
    mov  [rel guestnet_lease_ip], eax
    mov  [rel guestnet_guest_tx_packets], eax
    mov  [rel guestnet_nat_forwarded], eax
    mov  [rel guestnet_nat_returned], eax
    mov  [rel guestnet_dhcp_replies], eax
    mov  [rel guestnet_ipv4_packets], eax
    mov  [rel guestnet_udp_packets], eax
    mov  [rel guestnet_dhcp_packets], eax
    mov  [rel guestnet_dhcp_discover], eax
    mov  [rel guestnet_dhcp_request], eax
    mov  [rel guestnet_dhcp_tagged], eax
    mov  [rel guestnet_dhcp_reply_attempts], eax
    mov  [rel guestnet_rx_nobuf], eax
    mov  [rel guestnet_last_frame_len], eax
    mov  [rel guestnet_last_l2_at_10], eax
    mov  [rel guestnet_last_l2_at_12], eax
    mov  [rel guestnet_nat_next], eax
    mov  byte [rel guestnet_nat_up], 0
    mov  byte [rel guestnet_marker_dhcp], 0
    mov  byte [rel guestnet_dhcp_injected], 0
    mov  byte [rel guestnet_shell_ready], 0
    mov  byte [rel guestnet_shell_probe_pending], 0
    mov  byte [rel guestnet_shell_probe_tries], 0
    mov  dword [rel guestnet_shell_match], GN_SHELL_DROP
    mov  dword [rel guestnet_shell_probe_gen], 0
    mov  qword [rel guestnet_shell_probe_epoch], 0
    mov  qword [rel guestnet_shell_probe_due_ms], 0
    mov  byte [rel guestnet_pending_cmd_ready], 0
    lea  rdi, [rel guestnet_nat_table]
    mov  ecx, (GN_NAT_SLOTS * GN_N_SIZE) / 8
    rep  stosq
    lea  rdi, [rel guestnet_nat_udp_last]
    mov  ecx, GN_NAT_SLOTS
    rep  stosq
    lea  rdi, [rel guestnet_nat_tcp_reserved]
    mov  ecx, GN_NAT_SLOTS
    rep  stosq
    lea  rdi, [rel guestnet_nat_tcp_fin]
    mov  ecx, GN_NAT_SLOTS
    rep  stosq
    lea  rdi, [rel guestnet_icmp_table]
    mov  ecx, (GN_IC_SLOTS * GN_IC_SIZE) / 8
    rep  stosq                           ; identifiers/watermark survive session reset
    lea  rdi, [rel guestnet_error_table]
    mov  ecx, (GN_ER_SLOTS * GN_ER_SIZE) / 8
    rep  stosq
    mov  dword [rel guestnet_error_next], 0
    ret

; Run only at a clean VM-exit. Input is queued through the already-proven real
; virtio-console RX ring; it is never copied into the guest's output capture.
guestnet_pump:
    HV_POWER_WORK guestnet_pump, 0, hv_guest_power_io_admit
    call guestnet_ingress_poll
    cmp  byte [rel guestnet_tx_retry_pending], 1
    jne  .console
    mov  rdi, [rel guestnet_domain_ctx]
    test rdi, rdi
    jz   .console
    call virtio_domain_guest_rx_can_accept
    test eax, eax
    jz   .console
    ; Drain until the private domain ring fills or this bounded guest-ring
    ; batch ends. A later clean exit retries only after host consumption.
    mov  byte [rel guestnet_tx_retry_pending], 0
    call guestnet_serve_tx
.console:
    cmp  byte [rel guestnet_active], 1
    jne  .done
    cmp  byte [rel guestnet_dhcp_inject_pending], 1
    jne  .pending
    call guestnet_shell_live
    test eax, eax
    jz   .retire
    ; Completed readiness and retries belong to the same queued probe owner.
    cmp  byte [rel guestnet_shell_probe_pending], 1
    je   .probe_owner
    cmp  byte [rel guestnet_shell_ready], 1
    jne  .shell_owner_ok
.probe_owner:
    mov  eax, [rel guestnet_shell_probe_gen]
    cmp  eax, [rel guestnet_launch_gen]
    jne  .retire
    mov  rax, [rel guestnet_shell_probe_epoch]
    cmp  rax, [rel hv_vcon_epoch]
    jne  .retire
.shell_owner_ok:
    cmp  byte [rel guestnet_net_up], 1
    jne  .done
    cmp  byte [rel hv_vcon_ready], 1
    jne  .done
    cmp  byte [rel hv_linux_kboot], 1
    jne  .done
    cmp  byte [rel guestnet_shell_ready], 1
    jne  .probe_shell
    lea  rdi, [rel str_gn_dhcp_command]
    call hv_vcon_rx_line
    test eax, eax
    jz   .done
    mov  byte [rel guestnet_dhcp_inject_pending], 0
    mov  byte [rel guestnet_dhcp_injected], 1
    ret
.probe_shell:
    ; Kernel boot and a writable virtio RX descriptor do not prove that /init
    ; reached its shell. A harmless encoded printf must be EXECUTED by the
    ; guest and answered on the real virtio TX stream before DHCP renewal.
    cmp  byte [rel guestnet_shell_probe_tries], GN_SHELL_PROBE_LIMIT
    jae  .done
    call boot_ms_now
    cmp  rax, [rel guestnet_shell_probe_due_ms]
    jb   .done
    ; A guest which has not drained RX must not turn every VM-exit into a
    ; retry. Advance the due time before the descriptor attempt; count only
    ; successful sends below. The finite budget spans slow pre-shell init.
    add  rax, GN_SHELL_PROBE_MS
    jc   .retire                          ; no wrapped immediate retry deadline
    mov  [rel guestnet_shell_probe_due_ms], rax
    cmp  byte [rel guestnet_shell_probe_pending], 1
    je   .send_probe                      ; resend same admitted challenge
    call guestnet_shell_build
    test eax, eax
    jz   .done                            ; exhausted serial never wraps
.send_probe:
    lea  rdi, [rel guestnet_shell_command]
    call hv_vcon_rx_line
    test eax, eax
    jz   .done
    call guestnet_shell_live
    test eax, eax
    jz   .retire
    inc  byte [rel guestnet_shell_probe_tries]
    cmp  byte [rel guestnet_shell_probe_pending], 1
    je   .done                            ; retain partial delayed response
    mov  eax, [rel guestnet_launch_gen]
    mov  [rel guestnet_shell_probe_gen], eax
    mov  rax, [rel hv_vcon_epoch]
    mov  [rel guestnet_shell_probe_epoch], rax
    mov  byte [rel guestnet_shell_probe_pending], 1
    mov  dword [rel guestnet_shell_match], GN_SHELL_DROP
    ret
.retire:
    call guestnet_shell_retire
    ret
.pending:
    cmp  byte [rel guestnet_pending_cmd_ready], 1
    jne  .done
    cmp  byte [rel hv_vcon_ready], 1
    jne  .done
    lea  rdi, [rel guestnet_pending_cmd]
    call hv_vcon_rx_line
    test eax, eax
    jz   .done
    mov  byte [rel guestnet_pending_cmd_ready], 0
.done:
    ret

; AL is a real guest virtio-console TX byte. The command carries only octal
; escapes, so its raw TTY echo cannot contain this decoded acknowledgement.
; Only the exact line for the live session's successfully queued challenge may
; earn readiness. A leading decoded LF establishes a boundary after the prompt;
; prefix/suffix junk, echo and double CR cannot complete an acknowledgement.
guestnet_console_byte:
    ; Actual caller is the counted vcon TX worker. This bounded, no-yield
    ; matcher also fences direct callbacks while preserving the input AL.
    HV_POWER_CHECK hv_guest_power_io_admit, .return
    push rax
    push rbx
    push rcx
    push rdx
    call guestnet_shell_live
    test eax, eax
    jz   .retire
    mov  eax, [rel guestnet_shell_probe_gen]
    cmp  eax, [rel guestnet_launch_gen]
    jne  .retire
    mov  rax, [rel guestnet_shell_probe_epoch]
    cmp  rax, [rel hv_vcon_epoch]
    jne  .retire
    cmp  byte [rel guestnet_shell_probe_pending], 1
    jne  .out
    mov  rax, [rsp + 24]                   ; original AL, preserved across helper
    mov  ecx, [rel guestnet_shell_match]
    lea  rbx, [rel guestnet_shell_reply + 1]
    cmp  al, 10
    je   .line_end
    cmp  ecx, GN_SHELL_ACK_CR_WAIT
    jae  .drop                            ; includes GN_SHELL_DROP / corrupt index
    cmp  ecx, GN_SHELL_ACK_LEN
    jb   .compare
    cmp  al, 13
    jne  .drop
    mov  ecx, GN_SHELL_ACK_CR_WAIT
    jmp  .save
.compare:
    cmp  al, [rbx + rcx]
    jne  .drop
    inc  ecx
    jmp  .save
.line_end:
    cmp  ecx, GN_SHELL_ACK_LEN
    je   .complete
    cmp  ecx, GN_SHELL_ACK_CR_WAIT
    je   .complete
    xor  ecx, ecx                         ; new line, never substring restart
    jmp  .save
.complete:
    mov  byte [rel guestnet_shell_ready], 1
    mov  byte [rel guestnet_shell_probe_pending], 0
    xor  ecx, ecx
    jmp  .save
.drop:
    mov  ecx, GN_SHELL_DROP
.save:
    mov  [rel guestnet_shell_match], ecx
    jmp  .out
.retire:
    call guestnet_shell_retire
.out:
    pop  rdx
    pop  rcx
    pop  rbx
    pop  rax
.return:
    ret

; No yield. Guest task generation must still be the GUESTNET session owner.
; Called before queueing, before activation and on every real TX byte.
guestnet_shell_live:
    cmp  byte [rel guestnet_active], 1
    jne  .bad
    cmp  byte [rel hv_linux_running], 1
    jne  .bad
    cmp  byte [rel hv_linux_stop_req], 0
    jne  .bad
    cmp  byte [rel hv_linux_kboot], 1
    jne  .bad
    cmp  byte [rel hv_vcon_ready], 1
    jne  .bad
    cmp  byte [rel guestnet_net_up], 1
    jne  .bad
    mov  eax, [rel guestnet_launch_gen]
    test eax, eax
    jz   .bad
    cmp  eax, [rel hv_linux_start_gen]
    jne  .bad
    cmp  eax, [rel hv_linux_start_consumed]
    jne  .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

guestnet_shell_retire:
    mov  byte [rel guestnet_shell_probe_pending], 0
    mov  byte [rel guestnet_shell_ready], 0
    mov  dword [rel guestnet_shell_probe_gen], 0
    mov  qword [rel guestnet_shell_probe_epoch], 0
    mov  dword [rel guestnet_shell_match], GN_SHELL_DROP
    ret

; One fresh candidate per initial admission attempt, never recycled after a
; failed queue. Retries of an admitted candidate reuse its bytes and matcher.
; Serial lifetime is the loaded image, deliberately outside all session/reset
; zeroing. At UINT64_MAX refuse forever instead of reusing an old challenge.
guestnet_shell_build:
    cld
    mov  rdx, [rel guestnet_shell_serial]
    cmp  rdx, -1
    je   .bad
    inc  rdx
    mov  [rel guestnet_shell_serial], rdx
    lea  rdi, [rel guestnet_shell_reply]
    mov  byte [rdi], 10
    inc  rdi
    lea  rsi, [rel str_gn_shell_ack]
    mov  ecx, GN_SHELL_ACK_LEN - 16
    rep  movsb
    lea  rsi, [rel str_gn_shell_hex]
    mov  ecx, 16
.hex:
    rol  rdx, 4
    movzx eax, dl
    and  eax, 15
    mov  al, [rsi + rax]
    stosb
    loop .hex
    mov  byte [rdi], 10
    lea  rdi, [rel guestnet_shell_command]
    lea  rsi, [rel str_gn_shell_probe]
    mov  ecx, GN_SHELL_CMD_PREFIX
    rep  movsb
    lea  rsi, [rel guestnet_shell_reply]
    mov  ecx, GN_SHELL_REPLY_LEN
.octal:
    lodsb
    mov  dl, al
    mov  byte [rdi], 92                    ; backslash and exactly three octal digits
    shr  al, 6
    add  al, '0'
    mov  [rdi + 1], al
    mov  al, dl
    shr  al, 3
    and  al, 7
    add  al, '0'
    mov  [rdi + 2], al
    and  dl, 7
    add  dl, '0'
    mov  [rdi + 3], dl
    add  rdi, 4
    loop .octal
    mov  byte [rdi], 39                    ; closing quote, bounded command + NUL
    mov  byte [rdi + 1], 0
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; Parse `NONCE <safe-token> <numeric-ip> <port>` and form the BusyBox command
; the living guest executes. The strict character set makes console injection
; impossible through this administrative verb.
guestnet_build_nonce_command:
    push rbx
    push r12
    push r13
    cmp  byte [rel guestnet_build_physical], 1
    je   .args                               ; wrapper already points at nonce
    add  rdi, 5                              ; skip NONCE
.args:
    call guestnet_skip_spaces
    mov  r12, rdi
    lea  rdi, [rel guestnet_nonce_text]
    mov  ecx, 64
    mov  edx, 1                              ; token charset
    mov  rsi, r12
    call guestnet_copy_safe_token
    test rax, rax
    jz   .bad
    mov  r12, rax
    mov  rdi, r12
    call guestnet_skip_spaces
    mov  r12, rdi
    lea  rdi, [rel guestnet_ip_text]
    mov  ecx, 16
    mov  edx, 2                              ; numeric IPv4 charset
    mov  rsi, r12
    call guestnet_copy_safe_token
    test rax, rax
    jz   .bad
    mov  r12, rax
    mov  rdi, r12
    call guestnet_skip_spaces
    mov  r12, rdi
    lea  rdi, [rel guestnet_port_text]
    mov  ecx, 6
    mov  edx, 3                              ; decimal only
    mov  rsi, r12
    call guestnet_copy_safe_token
    test rax, rax
    jz   .bad
    cmp  byte [rax], 0
    jne  .bad
    lea  rsi, [rel guestnet_port_text]
    xor  ebx, ebx
.port:
    movzx eax, byte [rsi]
    test al, al
    jz   .port_done
    sub  eax, '0'
    imul ebx, ebx, 10
    add  ebx, eax
    cmp  ebx, 65535
    ja   .bad
    inc  rsi
    jmp  .port
.port_done:
    test ebx, ebx
    jz   .bad
    lea  rdi, [rel guestnet_pending_cmd]
    mov  [rel guestnet_cmd_cur], rdi
    mov  byte [rdi], 0
    mov  byte [rel guestnet_cmd_overflow], 0
    cmp  byte [rel guestnet_build_physical], 1
    jne  .sender
    lea  rdi, [rel str_gn_physical_pre]
    call guestnet_cmd_append
.sender:
    lea  rdi, [rel str_gn_cmd_pre]
    call guestnet_cmd_append
    lea  rdi, [rel guestnet_nonce_text]
    call guestnet_cmd_append
    lea  rdi, [rel str_gn_cmd_mid]
    call guestnet_cmd_append
    lea  rdi, [rel guestnet_ip_text]
    call guestnet_cmd_append
    lea  rdi, [rel str_gn_space]
    call guestnet_cmd_append
    lea  rdi, [rel guestnet_port_text]
    call guestnet_cmd_append
    cmp  byte [rel guestnet_build_physical], 1
    jne  .built
    lea  rdi, [rel str_gn_physical_post]
    call guestnet_cmd_append
.built:
    cmp  byte [rel guestnet_cmd_overflow], 0
    jne  .bad
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

guestnet_skip_spaces:
    cmp  byte [rdi], ' '
    jne  .done
    inc  rdi
    jmp  guestnet_skip_spaces
.done:
    ret

; RSI=source, RDI=dst, ECX=capacity incl NUL, EDX=charset. RAX=end source or 0.
guestnet_copy_safe_token:
    push rbx
    mov  rbx, rdi
    xor  r8d, r8d
    dec  ecx                                 ; last byte is reserved for NUL
.loop:
    movzx eax, byte [rsi]
    test al, al
    jz   .end
    cmp  al, ' '
    je   .end
    cmp  r8d, ecx
    jae  .bad
    cmp  edx, 3
    je   .digit
    cmp  edx, 2
    je   .ipchar
    cmp  al, '0'
    jb   .punct
    cmp  al, '9'
    jbe  .store
    cmp  al, 'A'
    jb   .punct
    cmp  al, 'Z'
    jbe  .store
    cmp  al, 'a'
    jb   .punct
    cmp  al, 'z'
    jbe  .store
.punct:
    cmp  al, '-'
    je   .store
    cmp  al, '_'
    je   .store
    cmp  al, '.'
    jne  .bad
    jmp  .store
.ipchar:
    cmp  al, '.'
    je   .store
.digit:
    cmp  al, '0'
    jb   .bad
    cmp  al, '9'
    ja   .bad
.store:
    mov  [rdi], al
    inc  rdi
    inc  rsi
    inc  r8d
    jmp  .loop
.end:
    test r8d, r8d
    jz   .bad
    mov  byte [rdi], 0
    mov  rax, rsi
    pop  rbx
    ret
.bad:
    mov  byte [rbx], 0
    xor  eax, eax
    pop  rbx
    ret

guestnet_cmd_append:
    mov  rsi, [rel guestnet_cmd_cur]
    lea  rdx, [rel guestnet_pending_cmd + 255]
.loop:
    cmp  rsi, rdx
    jae  .full
    mov  al, [rdi]
    test al, al
    jz   .done
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .loop
.full:
    cmp  byte [rdi], 0
    je   .done
    mov  byte [rel guestnet_cmd_overflow], 1
.done:
    mov  byte [rsi], 0
    mov  [rel guestnet_cmd_cur], rsi
    ret

; ---------------------------------------------------------------------------
; Modern virtio-mmio net transport. This preserves Classic's register and
; split-ring sequence; only the memory/command seams are renamed.
; ---------------------------------------------------------------------------
guestnet_state_zero:
    HV_POWER_WORK guestnet_state_zero, 0, hv_guest_power_admit
    call guestnet_ingress_clear
    inc  qword [rel guestnet_ring_epoch]
    xor  eax, eax
    mov  [rel guestnet_qsel], eax
    mov  [rel guestnet_dfsel], eax
    mov  [rel guestnet_drvfsel], eax
    mov  [rel guestnet_drvfeat], eax
    mov  [rel guestnet_drvfeat + 4], eax
    mov  [rel guestnet_feat_bad], al
    mov  [rel guestnet_status], eax
    mov  [rel guestnet_isr], eax
    mov  [rel guestnet_q_num], eax
    mov  [rel guestnet_q_num + 4], eax
    mov  [rel guestnet_mmio_writes], eax
    mov  [rel guestnet_notify_count], eax
    mov  [rel guestnet_irq_count], eax
    mov  qword [rel guestnet_q_desc], 0
    mov  qword [rel guestnet_q_desc + 8], 0
    mov  qword [rel guestnet_q_avail], 0
    mov  qword [rel guestnet_q_avail + 8], 0
    mov  qword [rel guestnet_q_used], 0
    mov  qword [rel guestnet_q_used + 8], 0
    mov  word [rel guestnet_q_lastav], 0
    mov  word [rel guestnet_q_lastav + 2], 0
    mov  word [rel guestnet_q_usedidx], 0
    mov  word [rel guestnet_q_usedidx + 2], 0
    mov  [rel guestnet_q_ready], al
    mov  [rel guestnet_q_ready + 1], al
    mov  [rel guestnet_net_up], al
    mov  [rel guestnet_driver_ok], al
    mov  [rel guestnet_irq_pending], al
    mov  [rel guestnet_irq_injected], al
    mov  [rel guestnet_tx_retry_pending], al
    mov  [rel guestnet_marker_virtio], al
    mov  [rel guestnet_shell_ready], al
    mov  [rel guestnet_shell_probe_pending], al
    mov  [rel guestnet_shell_probe_tries], al
    mov  dword [rel guestnet_shell_match], GN_SHELL_DROP
    mov  dword [rel guestnet_shell_probe_gen], 0
    mov  qword [rel guestnet_shell_probe_epoch], 0
    mov  qword [rel guestnet_shell_probe_due_ms], 0
    ret

guestnet_device_reset:
    HV_POWER_WORK guestnet_device_reset, 0, hv_guest_power_admit
    call guestnet_ingress_clear
    mov  rdx, [rel hv_linux_region]
    test rdx, rdx
    jz   .done
    lea  rdx, [rdx + HV_GUESTNET_PAGE]
    mov  dword [rdx + 0x000], 0x74726976    ; "virt"
    mov  dword [rdx + 0x004], 2             ; modern transport
    mov  dword [rdx + 0x008], 1             ; virtio-net
    mov  dword [rdx + 0x00C], 0x536F6150    ; "PaOS"
    mov  dword [rdx + 0x010], GN_FEATURES   ; MAC and negotiated indirect tables
    mov  dword [rdx + 0x034], GN_QMAX
    mov  dword [rdx + 0x044], 0
    mov  dword [rdx + 0x060], 0
    mov  dword [rdx + 0x070], 0
    mov  dword [rdx + 0x0FC], 0
    mov  byte [rdx + 0x100], 0x52
    mov  byte [rdx + 0x101], 0x54
    mov  byte [rdx + 0x102], 0x00
    mov  byte [rdx + 0x103], 0x50
    mov  byte [rdx + 0x104], 0x61
    mov  byte [rdx + 0x105], 0x4F
    call guestnet_state_zero
.done:
    ret

guestnet_raise_irq:
    or   dword [rel guestnet_isr], 1
    mov  rdx, [rel hv_linux_region]
    test rdx, rdx
    jz   .done
    mov  eax, [rel guestnet_isr]
    mov  [rdx + HV_GUESTNET_PAGE + 0x60], eax
    mov  byte [rel guestnet_irq_pending], 1
.done:
    ret

guestnet_eval_up:
    call guestnet_features_ok
    test eax, eax
    jz   .done
    cmp  dword [rel guestnet_status], 15
    jne  .done
    cmp  byte [rel guestnet_net_up], 1
    je   .done
    cmp  byte [rel guestnet_driver_ok], 1
    jne  .done
    cmp  byte [rel guestnet_q_ready], 1
    jne  .done
    cmp  byte [rel guestnet_q_ready + 1], 1
    jne  .done
    mov  byte [rel guestnet_net_up], 1
    mov  byte [rel guestnet_marker_virtio], 1
    lea  rdi, [rel str_gn_marker_vio]
    call serial_string
.done:
    ret

; EDI=register offset, ESI=value.
guestnet_mmio_write:
    HV_POWER_WORK guestnet_mmio_write, 0, hv_guest_power_io_admit
    cmp  edi, 0x050
    je   .epoch_ready
    cmp  edi, 0x064
    je   .epoch_ready
    inc  qword [rel guestnet_ring_epoch]
    mov  byte [rel guestnet_tx_retry_pending], 0
.epoch_ready:
    push rbx
    mov  rbx, [rel hv_linux_region]
    lea  rbx, [rbx + HV_GUESTNET_PAGE]
    cmp  edi, 0x014
    je   .dfsel
    cmp  edi, 0x020
    je   .drvfeat
    cmp  edi, 0x024
    je   .drvfsel
    cmp  edi, 0x030
    je   .qsel
    cmp  edi, 0x038
    je   .qnum
    cmp  edi, 0x044
    je   .qready
    cmp  edi, 0x050
    je   .notify
    cmp  edi, 0x064
    je   .intack
    cmp  edi, 0x070
    je   .status
    cmp  edi, 0x080
    je   .desclo
    cmp  edi, 0x084
    je   .deschi
    cmp  edi, 0x090
    je   .avail_lo
    cmp  edi, 0x094
    je   .avail_hi
    cmp  edi, 0x0A0
    je   .used_lo
    cmp  edi, 0x0A4
    je   .used_hi
    jmp  .done
.dfsel:
    mov  [rel guestnet_dfsel], esi
    xor  eax, eax
    test esi, esi
    jnz  .df1
    mov  eax, GN_FEATURES
    jmp  .df_store
.df1:
    cmp  esi, 1
    jne  .df_store
    mov  eax, 1                              ; VIRTIO_F_VERSION_1, bit 32
.df_store:
    mov  [rbx + 0x10], eax
    jmp  .done
.drvfeat:
    test dword [rel guestnet_status], 8
    jnz  .feature_bad                    ; negotiation immutable until reset
    mov  eax, [rel guestnet_drvfsel]
    cmp  eax, 1
    ja   .feature_bad
    lea  rdx, [rel guestnet_drvfeat]
    mov  [rdx + rax*4], esi
    jmp  .done
.drvfsel:
    mov  [rel guestnet_drvfsel], esi
    jmp  .done
.qsel:
    mov  [rel guestnet_qsel], esi
    cmp  esi, 2
    jae  .qsel_bad
    mov  dword [rbx + 0x34], GN_QMAX
    lea  rdx, [rel guestnet_q_ready]
    movzx eax, byte [rdx + rsi]
    mov  [rbx + 0x44], eax
    jmp  .done
.qsel_bad:
    mov  dword [rbx + 0x34], 0
    mov  dword [rbx + 0x44], 0
    jmp  .done
.qnum:
    mov  eax, [rel guestnet_qsel]
    cmp  eax, 2
    jae  .done
    cmp  esi, GN_QMAX
    jbe  .qnum_ok
    mov  esi, GN_QMAX
.qnum_ok:
    lea  rdx, [rel guestnet_q_num]
    mov  [rdx + rax*4], esi
    jmp  .done
.qready:
    mov  eax, [rel guestnet_qsel]
    cmp  eax, 2
    jae  .done
    and  esi, 1
    lea  rdx, [rel guestnet_q_ready]
    mov  [rdx + rax], sil
    mov  [rbx + 0x44], esi
    call guestnet_eval_up
    jmp  .done
.notify:
    inc  dword [rel guestnet_notify_count]
    cmp  esi, 1
    jne  .done
    call guestnet_serve_tx
    jmp  .done
.intack:
    mov  eax, esi
    not  eax
    and  [rel guestnet_isr], eax
    mov  eax, [rel guestnet_isr]
    mov  [rbx + 0x60], eax
    mov  byte [rel guestnet_irq_injected], 0
    test eax, eax
    jnz  .done
    mov  byte [rel guestnet_irq_pending], 0
    jmp  .done
.status:
    test esi, esi
    jnz  .status_set
    call guestnet_state_zero             ; reclaim features, rings, retry and IRQ
    mov  dword [rbx + 0x60], 0
    mov  dword [rbx + 0x44], 0
    mov  dword [rbx + 0x70], 0
    jmp  .done
.status_set:
    mov  eax, [rel guestnet_status]
    mov  edx, esi
    not  edx
    test eax, edx                        ; status is cumulative until reset
    jnz  .feature_bad
    mov  [rel guestnet_status], esi
    mov  [rbx + 0x70], esi
    test esi, ~15
    jnz  .feature_bad
    test esi, 8
    jz   .early_status
    mov  eax, esi
    and  eax, 3
    cmp  eax, 3
    jne  .feature_bad
    call guestnet_features_ok
    test eax, eax
    jz   .feature_bad
    test esi, 4
    jz   .done
    mov  byte [rel guestnet_driver_ok], 1
    call guestnet_eval_up
    jmp  .done
.early_status:
    test esi, 4
    jnz  .feature_bad
    jmp  .done
.feature_bad:
    mov  byte [rel guestnet_feat_bad], 1
    and  dword [rel guestnet_status], ~8
    mov  eax, [rel guestnet_status]
    mov  [rbx + 0x70], eax
    mov  byte [rel guestnet_driver_ok], 0
    mov  byte [rel guestnet_net_up], 0
    mov  byte [rel guestnet_irq_pending], 0
    mov  byte [rel guestnet_irq_injected], 0
    mov  dword [rel guestnet_isr], 0
    mov  dword [rbx + 0x60], 0
    jmp  .done
.desclo:
    lea  rdx, [rel guestnet_q_desc]
    jmp  .addr_lo
.deschi:
    lea  rdx, [rel guestnet_q_desc]
    jmp  .addr_hi
.avail_lo:
    lea  rdx, [rel guestnet_q_avail]
    jmp  .addr_lo
.avail_hi:
    lea  rdx, [rel guestnet_q_avail]
    jmp  .addr_hi
.used_lo:
    lea  rdx, [rel guestnet_q_used]
    jmp  .addr_lo
.used_hi:
    lea  rdx, [rel guestnet_q_used]
.addr_hi:
    mov  eax, [rel guestnet_qsel]
    cmp  eax, 2
    jae  .done
    shl  eax, 3
    add  rdx, rax
    mov  [rdx + 4], esi
    jmp  .done
.addr_lo:
    mov  eax, [rel guestnet_qsel]
    cmp  eax, 2
    jae  .done
    shl  eax, 3
    add  rdx, rax
    mov  [rdx], esi
.done:
    pop  rbx
    ret

; Rebind/detach revoke the old interrupt owner along with its retry.
guestnet_irq_revoke:
    mov  dword [rel guestnet_isr], 0
    mov  byte [rel guestnet_irq_pending], 0
    mov  byte [rel guestnet_irq_injected], 0
    mov  rax, [rel hv_linux_region]
    test rax, rax
    jz   .done
    mov  dword [rax + HV_GUESTNET_PAGE + 0x60], 0
.done:
    ret

; Only supported modern feature pages; invalid admission stays poisoned until reset.
guestnet_features_ok:
    cmp  byte [rel guestnet_feat_bad], 0
    jne  .bad
    test dword [rel guestnet_drvfeat], ~GN_FEATURES
    jnz  .bad
    cmp  dword [rel guestnet_drvfeat + 4], 1
    jne  .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; guestnet_detach — RCQ-18: a GUESTVM profile START is not a GUESTNET session.
; Drop any session intent (DHCP/shell injection into the console) without
; touching the run/stop requests, which the profile START owns.
guestnet_detach:
    HV_POWER_WORK guestnet_detach, 0, hv_guest_power_admit
    call guestnet_ingress_clear
    inc  qword [rel guestnet_ring_epoch]
    mov  word [rel guestnet_q_ready], 0
    mov  byte [rel guestnet_driver_ok], 0
    mov  byte [rel guestnet_net_up], 0
    mov  byte [rel guestnet_tx_retry_pending], 0
    mov  byte [rel guestnet_active], 0
    mov  byte [rel guestnet_launch_state], GN_LAUNCH_NONE
    mov  byte [rel guestnet_launch_err], 0
    mov  dword [rel guestnet_launch_gen], 0
    mov  byte [rel guestnet_nat_up], 0
    mov  byte [rel guestnet_dhcp_inject_pending], 0
    mov  byte [rel guestnet_shell_probe_pending], 0
    mov  byte [rel guestnet_shell_ready], 0
    mov  dword [rel guestnet_shell_match], GN_SHELL_DROP
    mov  dword [rel guestnet_shell_probe_gen], 0
    mov  qword [rel guestnet_shell_probe_epoch], 0
    mov  byte [rel guestnet_pending_cmd_ready], 0
    jmp  guestnet_irq_revoke

; PIC IRQ6, same IF/shadow/entry gate ladder as the proven console/tick paths.
guestnet_try_inject_irq:
    HV_POWER_WORK guestnet_try_inject_irq, 0, hv_guest_power_io_admit
    cmp  byte [rel guestnet_irq_pending], 1
    jne  .no
    cmp  byte [rel guestnet_irq_injected], 0
    jne  .no
    mov  edi, 6
    call hv_pic_try_inject
    test eax, eax
    jz   .no
    mov  byte [rel guestnet_irq_injected], 1
    inc  dword [rel guestnet_irq_count]
    ret
.no:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; Split-ring TX and RX, ported from Classic gl_vio_serve_tx/rx_deliver.
; ---------------------------------------------------------------------------
guestnet_serve_tx:
    HV_POWER_WORK guestnet_serve_tx, 0, hv_guest_power_io_admit
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, GN_RING_WORK_size
    mov  rbp, rsp
    pushfq
    pop  qword [rbp + GN_RING_WORK.df]
    cld
    xor  r15d, r15d
    mov  dword [rbp + GN_RING_WORK.queue], 1
    mov  dword [rbp + GN_RING_WORK.write], 0
    call guestnet_ring_init
    test eax, eax
    jz   .done
.loop:
    call guestnet_ring_head
    test eax, eax
    jz   .flush
    cmp  eax, 1
    jne  .malformed
    cmp  qword [rbp + GN_RING_WORK.capacity], 26 ; 12-byte header + Ethernet
    jb   .malformed
    call guestnet_ring_current
    test eax, eax
    jz   .flush
    ; Immutable private bytes before any NAT, domain or physical effect.
    lea  rdi, [rbp + GN_RING_WORK.packet]
    xor  r13d, r13d
.copy:
    mov  eax, r13d
    shl  eax, 4
    mov  rsi, [rbp + GN_RING_WORK.segments + rax]
    mov  rcx, [rbp + GN_RING_WORK.segments + rax + 8]
    rep  movsb
    inc  r13d
    cmp  r13d, [rbp + GN_RING_WORK.count]
    jb   .copy
    ; VERSION_1's actual 12-byte header. No offloads, GSO, checksum or
    ; mergeable buffers were offered: every TX header field must be zero.
    cmp  qword [rbp + GN_RING_WORK.packet], 0
    jne  .malformed
    cmp  dword [rbp + GN_RING_WORK.packet + 8], 0
    jne  .malformed
    mov  rdi, [rbp + GN_RING_WORK.domain]
    test rdi, rdi
    jz   .consumer
    call virtio_domain_guest_rx_can_accept
    test eax, eax
    jz   .backpressure                   ; full is not an attempted forwarding
.consumer:
    call guestnet_ring_current
    test eax, eax
    jz   .flush
    lea  rsi, [rbp + GN_RING_WORK.packet + 12]
    mov  ecx, [rbp + GN_RING_WORK.capacity]
    sub  ecx, 12
    call guestnet_tx_frame
    cmp  rax, -2
    je   .backpressure                   ; defensive full result transfers no bytes
    jmp  .retire
.malformed:
    ; Bad head is consumed once, truthfully writing no payload bytes.
    call guestnet_ring_current
    test eax, eax
    jz   .flush
.retire:
    call guestnet_ring_current           ; never release an old ring after a reset
    test eax, eax
    jz   .flush
    xor  edx, edx
    call guestnet_ring_used
    mov  byte [rel guestnet_tx_retry_pending], 0
    cmp  qword [rbp + GN_RING_WORK.domain], 0
    je   .next
    lock inc qword [rel guestnet_tx_used_advance]
.next:
    inc  r15d
    cmp  r15d, r14d
    jb   .loop
    jmp  .flush
.backpressure:
    call guestnet_ring_current
    test eax, eax
    jz   .flush
    lock inc qword [rel guestnet_tx_backpressure]
    mov  byte [rel guestnet_tx_retry_pending], 1
.flush:
    test r15d, r15d
    jz   .done
    call guestnet_ring_current           ; do not IRQ a replacement owner
    test eax, eax
    jz   .done
    call guestnet_raise_irq
.done:
    push qword [rbp + GN_RING_WORK.df]
    popfq
    add  rsp, GN_RING_WORK_size
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; RSI=Ethernet frame, ECX=len.
guestnet_tx_frame:
    mov  rax, [rel guestnet_domain_ctx]
    test rax, rax
    jz   .private_link
    mov  rdi, rax
    mov  rdx, rcx
    push rcx
    call virtio_domain_guest_rx_publish
    pop  rcx
    test rax, rax
    jnz  .domain_result
    inc  dword [rel guestnet_guest_tx_packets]
    mov  [rel guestnet_last_frame_len], ecx
.domain_result:
    ret                                    ; preserve accepted/full/invalid result
.private_link:
    inc  dword [rel guestnet_guest_tx_packets]
    mov  [rel guestnet_last_frame_len], ecx
    cmp  ecx, 14
    jb   .done
    movzx eax, word [rsi + 10]
    mov  [rel guestnet_last_l2_at_10], eax
    movzx eax, word [rsi + 12]
    mov  [rel guestnet_last_l2_at_12], eax
    cmp  word [rsi + 12], 0x0608            ; ARP
    je   .arp
    cmp  word [rsi + 12], 0x0008            ; IPv4
    jne  .done
    inc  dword [rel guestnet_ipv4_packets]
    cmp  ecx, 42
    jb   .done
    cmp  byte [rsi + 23], 17
    je   .l4_udp
    cmp  byte [rsi + 23], 1
    je   .l4_echo
    cmp  byte [rsi + 23], 6                 ; bee023: Linux TCP to the LAN
    jne  .done
    cmp  ecx, 54                           ; IPv4(20) + TCP(20), no short checksum write
    jb   .done
    call guestnet_nat_tx_frame
    jmp  .done
.l4_echo:
    call guestnet_nat_tx_frame
    jmp  .done
.l4_udp:
    inc  dword [rel guestnet_udp_packets]
    push rsi
    push rcx
    call guestnet_dhcp_from_guest
    pop  rcx
    pop  rsi
    test eax, eax
    jnz  .done
    call guestnet_nat_tx_frame
    jmp  .done
.arp:
    cmp  ecx, 42
    jb   .done
    cmp  word [rsi + 20], 0x0100            ; request
    jne  .done
    call guestnet_arp_respond
.done:
    xor  eax, eax
    ret

; RSI=frame, EDX=len -> EAX=1 delivered / 0 unavailable.
guestnet_rx_deliver:
    HV_POWER_WORK guestnet_rx_deliver, 0, hv_guest_power_io_admit
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, GN_RING_WORK_size
    mov  rbp, rsp
    pushfq
    pop  qword [rbp + GN_RING_WORK.df]
    cld
    xor  r15d, r15d
    mov  [rbp + GN_RING_WORK.input], rsi
    mov  [rbp + GN_RING_WORK.length], edx
    cmp  edx, 14
    jb   .out
    cmp  edx, GN_FRAME_MAX
    ja   .out
    ; Copy trusted caller-owned Ethernet bytes before guest memory can change.
    lea  rdi, [rbp + GN_RING_WORK.packet]
    mov  qword [rdi], 0
    mov  dword [rdi + 8], 0x00010000      ; num_buffers=1, actual modern header
    add  rdi, 12
    mov  ecx, edx
    rep  movsb
    mov  dword [rbp + GN_RING_WORK.queue], 0
    mov  dword [rbp + GN_RING_WORK.write], 2
    call guestnet_ring_init
    test eax, eax
    jz   .out
.loop:
    call guestnet_ring_head
    test eax, eax
    jz   .flush
    cmp  eax, 1
    jne  .malformed
    mov  eax, [rbp + GN_RING_WORK.length]
    add  eax, 12
    cmp  [rbp + GN_RING_WORK.capacity], rax
    jb   .malformed
    call guestnet_ring_current
    test eax, eax
    jz   .flush
    ; Full chain, all writable spans, capacity and epoch already validated.
    ; Scatter only exact header+frame bytes, leaving every unused tail intact.
    lea  rsi, [rbp + GN_RING_WORK.packet]
    mov  r12d, [rbp + GN_RING_WORK.length]
    add  r12d, 12
    xor  r13d, r13d
.scatter:
    mov  eax, r13d
    shl  eax, 4
    mov  rdi, [rbp + GN_RING_WORK.segments + rax]
    mov  rcx, [rbp + GN_RING_WORK.segments + rax + 8]
    cmp  rcx, r12
    cmova rcx, r12
    sub  r12, rcx
    rep  movsb
    inc  r13d
    test r12, r12
    jnz  .scatter
    mov  edx, [rbp + GN_RING_WORK.length]
    add  edx, 12
    call guestnet_ring_used
    inc  r15d
    call guestnet_raise_irq
    mov  eax, 1
    jmp  .done
.malformed:
    call guestnet_ring_current
    test eax, eax
    jz   .flush
    xor  edx, edx
    call guestnet_ring_used
    inc  r15d
    cmp  r15d, r14d
    jb   .loop                           ; later valid head still has a chance
.flush:
    test r15d, r15d
    jz   .out
    call guestnet_ring_current
    test eax, eax
    jz   .out
    call guestnet_raise_irq
.out:
    xor  eax, eax
.done:
    push qword [rbp + GN_RING_WORK.df]
    popfq
    add  rsp, GN_RING_WORK_size
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret

; RCQ-19 whole-frame ring helpers. Private stack state lives only during a
; serialized stopped-vCPU entry; no guest pointer or packet snapshot survives
; a return/backpressure. Retry rebuilds and validates the still-owned head.
struc GN_RING_WORK
    .segments: resq GN_QMAX * 2
    .metadata: resq 7 * 2               ; seventh span protects table storage
    .visited: resq 1
    .capacity: resq 1
    .epoch: resq 1
    .ram: resq 1
    .ram_bytes: resq 1
    .region: resq 1
    .domain: resq 1
    .domain_ring: resq 1
    .generation: resd 1
    .queue: resd 1
    .write: resd 1
    .count: resd 1
    .nmeta: resd 1
    .head: resd 1
    .lastav: resd 1
    .usedidx: resd 1
    .next: resd 1
    .flags: resd 1
    .input: resq 1
    .length: resd 1
    .packet: resb GN_FRAME_MAX + 12
    .table: resq GN_QMAX * 2             ; bounded private descriptor snapshot
    .descbase: resq 1
    .backend: resq 1
    .profile: resq 1
    .devices: resd 1
    .features: resd 1
    .limit: resd 1
    .indirect: resd 1
    .config: resq 7                     ; both queue addresses and sizes
    .df: resq 1
    .padding: resb 6                    ; work size mod16=8, external call alignment
endstruc

; RBP=private work. Capture lifetime and all six metadata spans. Returns EAX
; success and R14D selected queue size. Even the other queue is protected.
guestnet_ring_init:
    mov  eax, [rel guestnet_drvfeat]
    mov  [rbp + GN_RING_WORK.features], eax
    mov  rax, [rel hv_ops_active]
    mov  [rbp + GN_RING_WORK.backend], rax
    mov  rax, [rel vm_profile_active]
    mov  [rbp + GN_RING_WORK.profile], rax
    mov  eax, [rel vm_profile_live_devices]
    mov  [rbp + GN_RING_WORK.devices], eax
    mov  rax, [rel guestnet_q_num]
    mov  [rbp + GN_RING_WORK.config + 48], rax
    xor  ecx, ecx
.config:
    lea  rdx, [rel guestnet_q_desc]
    mov  rax, [rdx + rcx*8]
    mov  [rbp + GN_RING_WORK.config + rcx*8], rax
    inc  ecx
    cmp  ecx, 6
    jb   .config
    mov  rax, [rel guestnet_ring_epoch]
    mov  [rbp + GN_RING_WORK.epoch], rax
    mov  eax, [rel hv_linux_start_consumed]
    mov  [rbp + GN_RING_WORK.generation], eax
    mov  rax, [rel hv_linux_ram]
    test rax, rax
    jz   .bad
    mov  [rbp + GN_RING_WORK.ram], rax
    mov  rax, [rel hv_linux_ram_bytes]
    mov  [rbp + GN_RING_WORK.ram_bytes], rax
    mov  rax, [rel hv_linux_region]
    test rax, rax
    jz   .bad
    mov  [rbp + GN_RING_WORK.region], rax
    mov  rax, [rel guestnet_domain_ctx]
    mov  [rbp + GN_RING_WORK.domain], rax
    mov  qword [rbp + GN_RING_WORK.domain_ring], 0
    test rax, rax
    jz   .no_domain
    mov  rax, [rax + virtio_domain_ctx.rx_ring]
    mov  [rbp + GN_RING_WORK.domain_ring], rax
.no_domain:
    call guestnet_ring_current
    test eax, eax
    jz   .bad
    xor  ebx, ebx
    mov  dword [rbp + GN_RING_WORK.nmeta], 0
.queue:
    lea  rax, [rel guestnet_q_num]
    mov  r14d, [rax + rbx*4]
    test r14d, r14d
    jz   .bad
    cmp  r14d, GN_QMAX
    ja   .bad
    lea  eax, [r14d - 1]
    test eax, r14d
    jnz  .bad
    xor  r12d, r12d
.metadata:
    lea  rax, [rel guestnet_q_desc]
    mov  rdi, [rax + rbx*8]
    mov  esi, r14d
    shl  esi, 4
    test r12d, r12d
    jz   .span
    lea  rax, [rel guestnet_q_avail]
    mov  rdi, [rax + rbx*8]
    mov  esi, r14d
    shl  esi, 1
    add  esi, 6
    cmp  r12d, 1
    je   .span
    lea  rax, [rel guestnet_q_used]
    mov  rdi, [rax + rbx*8]
    mov  esi, r14d
    shl  esi, 3
    add  esi, 6
.span:
    call hv_linux_gpa2hva
    test rax, rax
    jz   .bad
    mov  rdx, rax
    mov  ecx, esi
    lea  rdi, [rbp + GN_RING_WORK.metadata]
    mov  esi, [rbp + GN_RING_WORK.nmeta]
    call guestnet_ring_disjoint
    test eax, eax
    jz   .bad
    mov  eax, [rbp + GN_RING_WORK.nmeta]
    shl  eax, 4
    mov  [rbp + GN_RING_WORK.metadata + rax], rdx
    mov  [rbp + GN_RING_WORK.metadata + rax + 8], rcx
    inc  dword [rbp + GN_RING_WORK.nmeta]
    inc  r12d
    cmp  r12d, 3
    jb   .metadata
    inc  ebx
    cmp  ebx, 2
    jb   .queue
    mov  eax, [rbp + GN_RING_WORK.queue]
    lea  rdx, [rel guestnet_q_num]
    mov  r14d, [rdx + rax*4]
    jmp  guestnet_ring_current
.bad:
    xor  eax, eax
    ret

; Reconfiguration, reset, detach and domain rebind all revoke the epoch.
; START/STOP/backing and device authority are checked independently.
guestnet_ring_current:
    call guestnet_features_ok
    test eax, eax
    jz   .bad
    mov  eax, [rbp + GN_RING_WORK.features]
    cmp  eax, [rel guestnet_drvfeat]
    jne  .bad
    mov  rax, [rbp + GN_RING_WORK.backend]
    test rax, rax
    jz   .bad
    cmp  rax, [rel hv_ops_active]
    jne  .bad
    mov  rax, [rbp + GN_RING_WORK.profile]
    cmp  rax, [rel vm_profile_active]
    jne  .bad
    mov  eax, [rbp + GN_RING_WORK.generation]
    test eax, eax
    jz   .bad
    cmp  eax, [rel hv_linux_start_gen]
    jne  .bad
    cmp  qword [rbp + GN_RING_WORK.profile], 0
    je   .legacy
    cmp  eax, [rel vm_profile_gen]
    jne  .bad
    jmp  .profile_bound
.legacy:
    cmp  dword [rel vm_profile_gen], 0
    jne  .bad
    cmp  dword [rel vm_profile_dev_mask], VP_DEV_LEGACY
    jne  .bad
.profile_bound:
    mov  eax, [rbp + GN_RING_WORK.devices]
    cmp  eax, [rel vm_profile_live_devices]
    jne  .bad
    cmp  eax, [rel vm_profile_dev_mask]
    jne  .bad
    mov  rax, [rbp + GN_RING_WORK.ram]
    add  rax, [rbp + GN_RING_WORK.ram_bytes]
    jc   .bad
    mov  rax, [rbp + GN_RING_WORK.config + 48]
    cmp  rax, [rel guestnet_q_num]
    jne  .bad
    xor  ecx, ecx
.config:
    lea  rdx, [rel guestnet_q_desc]
    mov  rax, [rbp + GN_RING_WORK.config + rcx*8]
    cmp  rax, [rdx + rcx*8]
    jne  .bad
    inc  ecx
    cmp  ecx, 6
    jb   .config
    mov  rax, [rbp + GN_RING_WORK.epoch]
    cmp  rax, [rel guestnet_ring_epoch]
    jne  .bad
    mov  eax, [rbp + GN_RING_WORK.generation]
    cmp  eax, [rel hv_linux_start_consumed]
    jne  .bad
    mov  rax, [rbp + GN_RING_WORK.ram]
    cmp  rax, [rel hv_linux_ram]
    jne  .bad
    mov  rax, [rbp + GN_RING_WORK.ram_bytes]
    cmp  rax, [rel hv_linux_ram_bytes]
    jne  .bad
    mov  rax, [rbp + GN_RING_WORK.region]
    cmp  rax, [rel hv_linux_region]
    jne  .bad
    mov  rax, [rbp + GN_RING_WORK.domain]
    cmp  rax, [rel guestnet_domain_ctx]
    jne  .bad
    test rax, rax
    jz   .no_domain
    cmp  byte [rel domain_capstone_active], 1
    jne  .bad
    cmp  dword [rax + virtio_domain_ctx.lifecycle], DOMAIN_LIFE_RUNNING
    jne  .bad
    mov  rax, [rax + virtio_domain_ctx.rx_ring]
    test rax, rax
    jz   .bad
    cmp  rax, [rbp + GN_RING_WORK.domain_ring]
    jne  .bad
.no_domain:
    cmp  byte [rel hv_linux_running], 1
    jne  .bad
    test dword [rel vm_profile_live_devices], VP_DEV_NET
    jz   .bad
    cmp  word [rel guestnet_q_ready], 0x0101
    jne  .bad
    cmp  byte [rel guestnet_driver_ok], 1
    jne  .bad
    mov  eax, [rel guestnet_status]
    and  eax, 0x8c                       ; FEATURES_OK|DRIVER_OK, no FAILED
    cmp  eax, 12
    jne  .bad
    test dword [rel guestnet_drvfeat], ~GN_FEATURES
    jnz  .bad
    cmp  dword [rel guestnet_drvfeat + 4], 1 ; VERSION_1 only
    jne  .bad
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; EAX=0 no trustworthy head, 1 complete chain, 2 malformed head. No effects.
guestnet_ring_head:
    call guestnet_ring_current
    test eax, eax
    jz   .none
    mov  eax, [rbp + GN_RING_WORK.queue]
    lea  rbx, [rax + rax*2]
    shl  ebx, 4
    mov  r12, [rbp + GN_RING_WORK.metadata + rbx + 16]
    lea  rdx, [rel guestnet_q_lastav]
    movzx ecx, word [rdx + rax*2]
    mov  [rbp + GN_RING_WORK.lastav], ecx
    movzx edx, word [r12 + 2]
    sub  dx, cx
    jz   .empty
    movzx edx, dx
    cmp  edx, r14d
    ja   .none
    lfence
    lea  edx, [r14d - 1]
    and  ecx, edx
    movzx r9d, word [r12 + 4 + rcx*2]
    mov  [rbp + GN_RING_WORK.head], r9d
    lea  rdx, [rel guestnet_q_usedidx]
    movzx ecx, word [rdx + rax*2]
    mov  [rbp + GN_RING_WORK.usedidx], ecx
    mov  qword [rbp + GN_RING_WORK.visited], 0
    mov  qword [rbp + GN_RING_WORK.capacity], 0
    mov  dword [rbp + GN_RING_WORK.count], 0
    mov  dword [rbp + GN_RING_WORK.nmeta], 6
    mov  dword [rbp + GN_RING_WORK.indirect], 0
    mov  [rbp + GN_RING_WORK.limit], r14d
    mov  rax, [rbp + GN_RING_WORK.metadata + rbx]
    mov  [rbp + GN_RING_WORK.descbase], rax
.chain:
    cmp  r9d, [rbp + GN_RING_WORK.limit]
    jae  .malformed
    bts  qword [rbp + GN_RING_WORK.visited], r9
    jc   .malformed
    cmp  [rbp + GN_RING_WORK.count], r14d
    jae  .malformed
    mov  eax, r9d
    shl  eax, 4
    add  rax, [rbp + GN_RING_WORK.descbase]
    test word [rax + 12], 4
    jz   .direct
    call guestnet_indirect_snapshot
    test eax, eax
    jz   .malformed
    xor  r9d, r9d
    jmp  .chain
.direct:
    movzx ecx, word [rax + 12]
    mov  edx, ecx
    and  edx, ~1
    cmp  edx, [rbp + GN_RING_WORK.write] ; READ[+NEXT] TX, WRITE[+NEXT] RX
    jne  .malformed
    mov  [rbp + GN_RING_WORK.flags], ecx
    movzx edx, word [rax + 14]
    mov  [rbp + GN_RING_WORK.next], edx
    mov  esi, [rax + 8]
    mov  rdi, [rax]
    call hv_linux_gpa2hva
    test rax, rax
    jz   .malformed
    mov  rdx, rax
    mov  ecx, esi
    lea  rdi, [rbp + GN_RING_WORK.metadata]
    mov  esi, [rbp + GN_RING_WORK.nmeta]
    call guestnet_ring_disjoint
    test eax, eax
    jz   .malformed
    cmp  dword [rbp + GN_RING_WORK.write], 0
    je   .capacity                       ; readable alias is legal, RX alias is not
    lea  rdi, [rbp + GN_RING_WORK.segments]
    mov  esi, [rbp + GN_RING_WORK.count]
    call guestnet_ring_disjoint
    test eax, eax
    jz   .malformed
.capacity:
    add  [rbp + GN_RING_WORK.capacity], rcx
    jc   .malformed
    cmp  dword [rbp + GN_RING_WORK.write], 0
    jne  .save
    cmp  qword [rbp + GN_RING_WORK.capacity], GN_FRAME_MAX + 12
    ja   .malformed
.save:
    mov  eax, [rbp + GN_RING_WORK.count]
    shl  eax, 4
    mov  [rbp + GN_RING_WORK.segments + rax], rdx
    mov  [rbp + GN_RING_WORK.segments + rax + 8], rcx
    inc  dword [rbp + GN_RING_WORK.count]
    test dword [rbp + GN_RING_WORK.flags], 1
    jz   .valid
    mov  r9d, [rbp + GN_RING_WORK.next]
    jmp  .chain
.valid:
    mov  eax, 1
    ret
.malformed:
    mov  eax, 2
    ret
.empty:
    cmp  dword [rbp + GN_RING_WORK.write], 2
    jne  .none
    inc  dword [rel guestnet_rx_nobuf]
.none:
    xor  eax, eax
    ret

; One negotiated table per chain. Outer WRITE is ignored; NEXT/reserved/nested
; indirect are refused. Validate all table bytes and aliases before snapshot;
; later walks read private bytes only. Direct prefixes remain part of the frame.
guestnet_indirect_snapshot:
    cmp  dword [rbp + GN_RING_WORK.indirect], 0
    jne  .bad
    test dword [rbp + GN_RING_WORK.features], GN_INDIRECT
    jz   .bad
    movzx ecx, word [rax + 12]
    and  ecx, ~2                         ; virtio 2.7.5.3.2: ignore outer WRITE
    cmp  ecx, 4
    jne  .bad
    mov  esi, [rax + 8]
    test esi, esi
    jz   .bad
    test esi, 15
    jnz  .bad
    cmp  esi, GN_QMAX * 16
    ja   .bad
    mov  edx, esi
    shr  edx, 4
    cmp  edx, r14d
    ja   .bad
    mov  [rbp + GN_RING_WORK.limit], edx
    mov  rdi, [rax]
    test rdi, 15
    jnz  .bad
    call hv_linux_gpa2hva
    test rax, rax
    jz   .bad
    mov  rdx, rax
    mov  ecx, esi
    lea  rdi, [rbp + GN_RING_WORK.metadata]
    mov  esi, 6
    call guestnet_ring_disjoint
    test eax, eax
    jz   .bad
    lea  rdi, [rbp + GN_RING_WORK.segments]
    mov  esi, [rbp + GN_RING_WORK.count]
    call guestnet_ring_disjoint
    test eax, eax
    jz   .bad
    mov  [rbp + GN_RING_WORK.metadata + 96], rdx
    mov  [rbp + GN_RING_WORK.metadata + 104], rcx
    mov  dword [rbp + GN_RING_WORK.nmeta], 7
    mov  rsi, rdx
    lea  rdi, [rbp + GN_RING_WORK.table]
    mov  [rbp + GN_RING_WORK.descbase], rdi
    shr  ecx, 3
    rep  movsq
    mov  qword [rbp + GN_RING_WORK.visited], 0
    mov  dword [rbp + GN_RING_WORK.indirect], 1
    mov  eax, 1
    ret
.bad:
    xor  eax, eax
    ret

; EDX=actual bytes written (TX and malformed heads always zero). Ordered
; single-head publication; selected queue size and counters are 16-bit bounded.
guestnet_ring_used:
    mov  eax, [rbp + GN_RING_WORK.queue]
    lea  rbx, [rax + rax*2]
    shl  ebx, 4
    mov  r12, [rbp + GN_RING_WORK.metadata + rbx + 32]
    mov  ecx, [rbp + GN_RING_WORK.usedidx]
    lea  ebx, [r14d - 1]
    and  ebx, ecx
    lea  rdi, [r12 + 4 + rbx*8]
    mov  ebx, [rbp + GN_RING_WORK.head]
    mov  [rdi], ebx
    mov  [rdi + 4], edx
    inc  ecx
    lea  rdx, [rel guestnet_q_usedidx]
    mov  [rdx + rax*2], cx
    sfence
    mov  [r12 + 2], cx
    mov  ecx, [rbp + GN_RING_WORK.lastav]
    inc  ecx
    lea  rdx, [rel guestnet_q_lastav]
    mov  [rdx + rax*2], cx
    ret

; Half-open full host spans, including overflow check and empty endpoints.
guestnet_ring_disjoint:
    lea r8, [rdx + rcx]
    cmp r8, rdx
    jb .bad
    test rcx, rcx
    jz .good
    xor r9d, r9d
.loop:
    cmp r9d, esi
    jae .good
    mov r10, [rdi]
    mov r11, [rdi + 8]
    test r11, r11
    jz .next
    add r11, r10
    jc .bad
    cmp rdx, r11
    jae .next
    cmp r10, r8
    jb .bad
.next:
    add rdi, 16
    inc r9d
    jmp .loop
.good:
    mov eax, 1
    ret
.bad:
    xor eax, eax
    ret

; ---------------------------------------------------------------------------
; Private-link ARP and DHCP.
; ---------------------------------------------------------------------------
guestnet_put_gateway_mac:
    mov  byte [rdi + 6], 0x02
    mov  byte [rdi + 7], 0x50
    mov  byte [rdi + 8], 0x61
    mov  byte [rdi + 9], 0x4F
    mov  byte [rdi + 10], 0x53
    mov  byte [rdi + 11], 0x02
    ret

guestnet_arp_respond:
    cld
    ; This private link has one Ethernet/IPv4 client. Validate the fixed
    ; layout and both sender identities before scratch, seen or RX effects.
    cmp  ecx, 42
    jb   .done
    cmp  dword [rsi + 14], 0x00080100
    jne  .done
    cmp  word [rsi + 18], 0x0406
    jne  .done
    cmp  word [rsi + 20], 0x0100
    jne  .done
    cmp  dword [rsi + 6], 0x50005452
    jne  .done
    cmp  word [rsi + 10], 0x4f61
    jne  .done
    mov  eax, [rsi + 6]
    cmp  eax, [rsi + 22]
    jne  .done
    mov  ax, [rsi + 10]
    cmp  ax, [rsi + 26]
    jne  .done
    ; A source-zero probe remains valid; other clients do not own this link.
    mov  eax, [rsi + 28]
    test eax, eax
    jz   .destination
    cmp  eax, GN_GUEST_IP
    jne  .done
.destination:
    cmp  dword [rsi], 0xffffffff
    jne  .unicast
    cmp  word [rsi + 4], 0xffff
    je   .target
.unicast:
    cmp  dword [rsi], 0x4f615002
    jne  .done
    cmp  word [rsi + 4], 0x0253
    jne  .done
.target:
    ; ARP request target hardware bytes are unspecified and ignored.
    cmp  dword [rsi + 38], GN_GATEWAY_IP
    jne  .done
    lea  rdi, [rel guestnet_frame]
    push rdi
    xor  eax, eax
    mov  ecx, 8
    rep  stosq
    pop  rdi
    mov  eax, [rsi + 22]
    mov  [rdi], eax
    mov  ax, [rsi + 26]
    mov  [rdi + 4], ax
    call guestnet_put_gateway_mac
    mov  word [rdi + 12], 0x0608
    mov  word [rdi + 14], 0x0100
    mov  word [rdi + 16], 0x0008
    mov  byte [rdi + 18], 6
    mov  byte [rdi + 19], 4
    mov  word [rdi + 20], 0x0200
    mov  byte [rdi + 22], 0x02
    mov  byte [rdi + 23], 0x50
    mov  byte [rdi + 24], 0x61
    mov  byte [rdi + 25], 0x4F
    mov  byte [rdi + 26], 0x53
    mov  byte [rdi + 27], 0x02
    mov  dword [rdi + 28], GN_GATEWAY_IP
    mov  eax, [rsi + 22]
    mov  [rdi + 32], eax
    mov  ax, [rsi + 26]
    mov  [rdi + 36], ax
    mov  eax, [rsi + 28]
    mov  [rdi + 38], eax
    mov  byte [rel guestnet_arp_seen], 1
    mov  rsi, rdi
    mov  edx, 60
    call guestnet_rx_deliver
.done:
    ret

; EAX=1 for the private DHCP port pair, including refused requests; zero
; leaves other UDP traffic to NAT. No provisional DHCP effects before admission.
guestnet_dhcp_from_guest:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rsi
    mov  r13, rcx
    xor  ebx, ebx
    cmp  r13, 42
    jb   .out
    mov  rax, r12
    add  rax, r13
    jc   .out
    cmp  word [r12 + 34], 0x4400            ; source 68
    jne  .out
    cmp  word [r12 + 36], 0x4300            ; destination 67
    jne  .out
    mov  ebx, 1                            ; malformed DHCP cannot enter NAT
    cmp  r13, GN_TXBUF_MAX
    ja   .out
    call guestnet_dhcp_admit
    test eax, eax
    jz   .out
    inc  dword [rel guestnet_dhcp_packets]
    add  dword [rel guestnet_dhcp_tagged], r15d
    cmp  eax, 1
    je   .offer
    inc  dword [rel guestnet_dhcp_request]
    mov  edx, 5
    jmp  .reply
.offer:
    inc  dword [rel guestnet_dhcp_discover]
    mov  edx, 2
.reply:
    mov  rsi, r12
    mov  ecx, r13d
    mov  r8d, r15d
    call guestnet_build_dhcp_reply
.out:
    mov  eax, ebx
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; R12=original frame, R13=full-width capture (bounded by caller).
; EAX=1 DISCOVER / 3 REQUEST / 0 refusal, R15D=hostname tag on success.
; Read-only: validate original checksums and the complete declared option list
; before returning any type/tag. RFC2131/2132 Ethernet, direct-client subset:
; fixed IPv4, no fragmentation/relay/overload, one relevant singleton each.
; SELECTING/INIT-REBOOT use ciaddr/source zero and requested-IP; RENEW/REBIND
; use the assigned ciaddr/source without requested-IP or server identifier.
; UDP checksum omission is legal for IPv4; offload is not negotiated.
guestnet_dhcp_admit:
    xor  r15d, r15d
    call guestnet_nat_ip_extent
    cmp  eax, 42 + 241                     ; fixed BOOTP plus at least END
    jb   .invalid
    cmp  byte [r12 + 23], 17
    jne  .invalid
    mov  r14d, eax                         ; validated exclusive frame end
    lea  rdi, [r12 + 14]
    mov  esi, 20
    call net_cksum16
    test ax, ax
    jnz  .invalid
    cmp  word [r12 + 40], 0
    je   .bootp
    lea  rdi, [r12 + 26]                   ; original IPv4 pseudoheader
    mov  esi, 8
    call net_cksum16
    movzx r8d, ax
    xor  r8d, 0xffff
    mov  esi, r14d
    sub  esi, 34
    add  r8d, esi
    add  r8d, 17
    lea  rdi, [r12 + 34]
    call net_cksum16
    movzx eax, ax
    xor  eax, 0xffff
    add  eax, r8d
    mov  edx, eax
    shr  edx, 16
    and  eax, 0xffff
    add  eax, edx
    mov  edx, eax
    shr  edx, 16
    and  eax, 0xffff
    add  eax, edx
    cmp  eax, 0xffff
    jne  .invalid
.bootp:
    cmp  dword [r12 + 42], 0x00060101       ; BOOTREQUEST/Ethernet/6/no relay
    jne  .invalid
    test word [r12 + 52], 0xff7f           ; only BROADCAST flag supported
    jnz  .invalid
    cmp  dword [r12 + 58], 0               ; yiaddr
    jne  .invalid
    cmp  qword [r12 + 62], 0               ; siaddr + giaddr
    jne  .invalid
    cmp  dword [r12 + 70], 0x50005452       ; configured private-link identity
    jne  .invalid
    cmp  word [r12 + 74], 0x4f61
    jne  .invalid
    mov  eax, [r12 + 6]
    cmp  eax, [r12 + 70]
    jne  .invalid
    mov  ax, [r12 + 10]
    cmp  ax, [r12 + 74]
    jne  .invalid
    mov  eax, [r12 + 54]                   ; ciaddr is zero or assigned address
    test eax, eax
    jz   .source
    cmp  eax, GN_GUEST_IP
    jne  .invalid
.source:
    cmp  eax, [r12 + 26]
    jne  .invalid
    cmp  dword [r12 + 30], 0xffffffff
    je   .cookie
    cmp  dword [r12 + 30], GN_GATEWAY_IP
    jne  .invalid
.cookie:
    cmp  dword [r12 + 278], 0x63538263
    jne  .invalid
    lea  r10, [r12 + 282]
    lea  r11, [r12 + r14]
    xor  r8d, r8d                         ; seen 53/12/50/54/61
    xor  r9d, r9d                         ; provisional type, local only
.options:
    cmp  r10, r11
    jae  .invalid                         ; END required within declared UDP
    movzx eax, byte [r10]
    inc  r10
    test eax, eax
    jz   .options                         ; PAD has no length
    cmp  eax, 255
    je   .end                             ; bytes after END are not options
    cmp  r10, r11
    jae  .invalid
    movzx ecx, byte [r10]
    inc  r10
    mov  rdx, r11
    sub  rdx, r10
    cmp  rcx, rdx
    ja   .invalid                         ; length before any value read
    cmp  eax, 52
    je   .invalid                         ; file/sname overload unsupported
    cmp  eax, 53
    je   .type
    cmp  eax, 12
    je   .hostname
    cmp  eax, 50
    je   .requested
    cmp  eax, 54
    je   .server
    cmp  eax, 61
    je   .client
.next:
    add  r10, rcx
    jmp  .options
.type:
    test r8d, 1
    jnz  .invalid
    or   r8d, 1
    cmp  ecx, 1
    jne  .invalid
    movzx r9d, byte [r10]
    cmp  r9d, 1
    je   .next
    cmp  r9d, 3
    jne  .invalid
    jmp  .next
.hostname:
    test r8d, 2
    jnz  .invalid
    or   r8d, 2
    test ecx, ecx
    jz   .invalid
    cmp  ecx, 13
    jne  .next
    cmp  dword [r10], 'paos'
    jne  .next
    cmp  dword [r10 + 4], '-gue'
    jne  .next
    cmp  dword [r10 + 8], 'stne'
    jne  .next
    cmp  byte [r10 + 12], 't'
    jne  .next
    mov  r15d, 1                          ; still local until END validation
    jmp  .next
.requested:
    test r8d, 4
    jnz  .invalid
    or   r8d, 4
    cmp  ecx, 4
    jne  .invalid
    cmp  dword [r10], GN_GUEST_IP
    jne  .invalid
    jmp  .next
.server:
    test r8d, 8
    jnz  .invalid
    or   r8d, 8
    cmp  ecx, 4
    jne  .invalid
    cmp  dword [r10], GN_GATEWAY_IP
    jne  .invalid
    jmp  .next
.client:
    test r8d, 16
    jnz  .invalid
    or   r8d, 16
    cmp  ecx, 2                           ; opaque RFC2132 client identifier
    jb   .invalid
    jmp  .next
.end:
    test r8d, 1
    jz   .invalid
    cmp  dword [r12 + 54], 0
    jne  .renew
    cmp  r9d, 1
    je   .discover
    test r8d, 4                           ; initial REQUEST needs requested-IP
    jz   .invalid
    jmp  .valid
.discover:
    test r8d, 8                           ; DISCOVER has no selected server
    jnz  .invalid
    jmp  .valid
.renew:
    cmp  r9d, 3
    jne  .invalid
    test r8d, 12                          ; ciaddr carries renewal identity
    jnz  .invalid
.valid:
    mov  eax, r9d
    ret
.invalid:
    xor  r15d, r15d
    xor  eax, eax
    ret

; RSI=request frame, ECX=len, EDX=DHCP type (2 offer / 5 ack), R8D=tagged.
guestnet_build_dhcp_reply:
    cld
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  r12, rsi
    mov  r14d, edx
    mov  r15d, r8d
    inc  dword [rel guestnet_dhcp_reply_attempts]
    lea  rdi, [rel guestnet_frame]
    push rdi
    xor  eax, eax
    mov  ecx, 48                             ; 384 bytes
    rep  stosq
    pop  rdi
    ; Ethernet dst = guest MAC from request source; src = synthetic gateway.
    mov  eax, [r12 + 6]
    mov  [rdi], eax
    mov  ax, [r12 + 10]
    mov  [rdi + 4], ax
    call guestnet_put_gateway_mac
    mov  word [rdi + 12], 0x0008
    ; IPv4 + UDP fixed fields. Lengths follow the emitted option extent below.
    mov  byte [rdi + 14], 0x45
    mov  byte [rdi + 15], 0
    mov  word [rdi + 18], 0
    mov  word [rdi + 20], 0
    mov  byte [rdi + 22], 64
    mov  byte [rdi + 23], 17
    mov  word [rdi + 24], 0
    mov  dword [rdi + 26], GN_GATEWAY_IP
    mov  dword [rdi + 30], 0xFFFFFFFF
    mov  word [rdi + 34], 0x4300            ; 67
    mov  word [rdi + 36], 0x4400            ; 68
    mov  word [rdi + 40], 0                ; IPv4 UDP checksum omitted (RFC768)
    lea  rbx, [rdi + 42]
    mov  byte [rbx + 0], 2                  ; BOOTREPLY
    mov  byte [rbx + 1], 1
    mov  byte [rbx + 2], 6
    mov  eax, [r12 + 42 + 4]                ; xid
    mov  [rbx + 4], eax
    mov  ax, [r12 + 42 + 8]                 ; secs
    mov  [rbx + 8], ax
    mov  ax, [r12 + 42 + 10]                ; flags
    mov  [rbx + 10], ax
    mov  dword [rbx + 16], GN_GUEST_IP      ; yiaddr
    mov  dword [rbx + 20], GN_GATEWAY_IP    ; siaddr
    mov  eax, [r12 + 42 + 28]
    mov  [rbx + 28], eax
    mov  eax, [r12 + 42 + 32]
    mov  [rbx + 32], eax
    mov  eax, [r12 + 42 + 36]
    mov  [rbx + 36], eax
    mov  eax, [r12 + 42 + 40]
    mov  [rbx + 40], eax
    mov  dword [rbx + 236], 0x63538263
    lea  r13, [rbx + 240]
    mov  byte [r13 + 0], 53
    mov  byte [r13 + 1], 1
    mov  [r13 + 2], r14b
    mov  byte [r13 + 3], 54                 ; server identifier
    mov  byte [r13 + 4], 4
    mov  dword [r13 + 5], GN_GATEWAY_IP
    mov  byte [r13 + 9], 51                 ; lease 3600 seconds
    mov  byte [r13 + 10], 4
    mov  dword [r13 + 11], 0x100E0000       ; 00 00 0e 10
    mov  byte [r13 + 15], 1                 ; subnet mask
    mov  byte [r13 + 16], 4
    mov  dword [r13 + 17], 0x00FFFFFF
    mov  byte [r13 + 21], 3                 ; router
    mov  byte [r13 + 22], 4
    mov  dword [r13 + 23], GN_GATEWAY_IP
    add  r13, 27
    call dns_wire_server_snapshot
    test eax, eax
    jz   .options_end
    mov  edx, eax
    and  edx, 0x00FFFFFF
    cmp  edx, 0x0002000A                   ; guest-connected 10.0.2/24 conflicts
    je   .options_end
    mov  byte [r13], 6                     ; RFC2132 3.8: selected single server
    mov  byte [r13 + 1], 4
    mov  [r13 + 2], eax
    add  r13, 6
.options_end:
    mov  byte [r13], 255
    inc  r13
    lea  rdi, [rel guestnet_frame]
    sub  r13, rdi                          ; actual Ethernet frame extent
    lea  eax, [r13 - 14]
    xchg al, ah
    mov  [rdi + 16], ax
    lea  eax, [r13 - 34]
    xchg al, ah
    mov  [rdi + 38], ax
    lea  rdi, [rel guestnet_frame + 14]
    mov  word [rdi + 10], 0
    mov  rsi, 20
    call net_cksum16
    lea  rdi, [rel guestnet_frame + 14]
    mov  [rdi + 10], ah
    mov  [rdi + 11], al
    lea  rsi, [rel guestnet_frame]
    mov  edx, r13d
    call guestnet_rx_deliver
    test eax, eax
    jz   .done
    inc  dword [rel guestnet_dhcp_replies]
    cmp  r14d, 5
    jne  .done
    ; A real ACK delivered to the guest establishes its lease. GUESTNET START
    ; is owner-authorized, so the guest may use NAT during /init network work
    ; *before* its shell exists. The tagged renewal remains a separate proof
    ; of the shell-command protocol and alone earns guest.net.dhcp. The
    ; hostname is untrusted protocol data, never native readiness authority.
    mov  dword [rel guestnet_lease_ip], GN_GUEST_IP
    cmp  byte [rel guestnet_active], 1
    jne  .mark_lease
    mov  byte [rel guestnet_nat_up], 1
.mark_lease:
    cmp  r15d, 1
    jne  .done
    cmp  byte [rel guestnet_marker_dhcp], 1
    je   .done
    mov  byte [rel guestnet_marker_dhcp], 1
    lea  rdi, [rel str_gn_marker_dhcp]
    call serial_string
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; UDP/TCP/echo NAT and accepted-wire ICMP error return.
; ---------------------------------------------------------------------------
; A live DHCP lease owns the primary physical endpoint. Without a lease,
; static ip2 needs a matching coherent native route snapshot; the guest never
; invents a prefix or gateway from the physical address alone.

; Owner-authorized guest SSH ingress. No socket/listener: one existing NAT tuple
; is reserved for TCP22, with an absolute deadline independent of accepted I/O.
; This is BSP/cooperative like the containing GUESTNET command and NAT module.
; All effectful callers retain normal power admission. Clear preserves all GPRs.
guestnet_ingress_clear:
    push rax
    push rcx
    push rdx
    mov  ecx, [rel guestnet_ingress_slot]
    test ecx, ecx
    jz   .done
    cmp  ecx, GN_NAT_SLOTS
    ja   .metadata
    dec  ecx
    imul edx, ecx, GN_N_SIZE
    lea  rax, [rel guestnet_nat_table]
    add  rdx, rax
    mov  ax, [rel guestnet_ingress_port]
    cmp  ax, [rdx + GN_N_NPORT]
    jne  .metadata                       ; never revoke a later slot occupant
    mov  byte [rdx + GN_N_VALID], 0
    lea  rax, [rel guestnet_nat_udp_last]
    mov  qword [rax + rcx * 8], 0
    lea  rax, [rel guestnet_nat_tcp_reserved]
    mov  qword [rax + rcx * 8], 0
    lea  rax, [rel guestnet_nat_tcp_fin]
    mov  qword [rax + rcx * 8], 0
.metadata:
    mov  dword [rel guestnet_ingress_slot], 0
.done:
    pop  rdx
    pop  rcx
    pop  rax
    ret

; RAX=validated monotonic observation. Preserve every register; only the grant
; and its exact reserved slot may be retired. A stale slot witness is discarded.
guestnet_ingress_check:
    push rax
    push rcx
    push rdx
    cmp  dword [rel guestnet_ingress_slot], 0
    je   .done
    cmp  rax, [rel guestnet_ingress_deadline]
    jae  .revoke
    cmp  byte [rel guestnet_active], 1
    jne  .revoke
    cmp  byte [rel guestnet_nat_up], 1
    jne  .revoke
    cmp  byte [rel guestnet_net_up], 1
    jne  .revoke
    cmp  byte [rel hv_linux_running], 1
    jne  .revoke
    cmp  byte [rel hv_linux_stop_req], 0
    jne  .revoke
    cmp  byte [rel hv_linux_run_req], 0
    jne  .revoke
    cmp  byte [rel hv_linux_start_active], 1
    jne  .revoke
    cmp  byte [rel hv_linux_kboot], 1
    jne  .revoke
    cmp  byte [rel hv_vcon_ready], 1
    jne  .revoke
    cmp  qword [rel guestnet_domain_ctx], 0
    jne  .revoke
    mov  ecx, [rel guestnet_ingress_gen]
    cmp  ecx, [rel guestnet_launch_gen]
    jne  .revoke
    cmp  ecx, [rel hv_linux_start_gen]
    jne  .revoke
    cmp  ecx, [rel hv_linux_start_consumed]
    jne  .revoke
    mov  rcx, [rel guestnet_ring_epoch]
    cmp  rcx, [rel guestnet_ingress_ring]
    jne  .revoke
    mov  rcx, [rel hv_vcon_epoch]
    cmp  rcx, [rel guestnet_ingress_console]
    jne  .revoke
    mov  rcx, [rel session_authority_epoch]
    cmp  rcx, [rel guestnet_ingress_owner]
    jne  .revoke
    mov  ecx, [rel udp_our_ip3]
    test ecx, ecx
    jnz  .host
    mov  ecx, [rel udp_our_ip2]
.host:
    cmp  ecx, [rel guestnet_ingress_host]
    jne  .revoke
.done:
    pop  rdx
    pop  rcx
    pop  rax
    ret
.revoke:
    call guestnet_ingress_clear
    jmp  .done

guestnet_ingress_poll:
    push rax
    cmp  dword [rel guestnet_ingress_slot], 0
    je   .done
    call time_monotonic_now_us
    test rax, rax
    jz   .revoke
    cmp  rax, [rel guestnet_nat_clock_seen]
    jb   .revoke
    mov  [rel guestnet_nat_clock_seen], rax
    call guestnet_ingress_check
.done:
    pop  rax
    ret
.revoke:
    call guestnet_ingress_clear
    jmp  .done

; Strict unsigned decimal token. RDI advances to delimiter, RAX=value, CF=bad.
; Bound the scan to20 digits and reject multiply/add overflow, signs and junk.
guestnet_ingress_number:
    xor  eax, eax
    xor  ecx, ecx
.loop:
    movzx edx, byte [rdi]
    sub  edx, '0'
    cmp  edx, 9
    ja   .end
    inc  ecx
    cmp  ecx, 20
    ja   .bad
    mov  r8, 10
    mul  r8
    test rdx, rdx
    jnz  .bad
    movzx edx, byte [rdi]
    sub  edx, '0'
    add  rax, rdx
    jc   .bad
    inc  rdi
    jmp  .loop
.end:
    test ecx, ecx
    jz   .bad
    clc
    ret
.bad:
    stc
    ret

; Request handler; the normal dispatcher enforces exact MUTATE scope first.
; The in-flight owner predicate additionally excludes internal/tainted callers.
; OPEN gen ring console owner_epoch a.b.c.d source_port seconds
; CANCEL host_port. STAT shows current live identity, never a host fingerprint.
guestnet_ingress_out_dec:
    push rbx
    push r12
    mov  rbx, rax
    lea  r12, [rel guestnet_ingress_dec_buf + 31]
    mov  byte [r12], 0
    test rbx, rbx
    jnz  .digits
    dec  r12
    mov  byte [r12], '0'
    jmp  .emit
.digits:
    mov  rax, rbx
.loop:
    xor  edx, edx
    mov  ecx, 10
    div  rcx
    add  dl, '0'
    dec  r12
    mov  [r12], dl
    test rax, rax
    jnz  .loop
.emit:
    mov  rdi, r12
    call guestnet_out_str
    pop  r12
    pop  rbx
    ret

guestnet_ingress_command:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 80
    mov  r12, rsi
    mov  rbx, [rdi + REQ_ARG]
    call cmd_handler_prologue
    call command_auth_ticket_owner
    test eax, eax
    jz   .denied
    HV_POWER_CHECK hv_guest_power_admit, .denied
    call guestnet_ingress_poll
    mov  rdi, rbx
    lea  rsi, [rel str_gn_ssh_stat]
    call hv_tok_is
    test al, al
    jnz  .stat_arg
    mov  rdi, rbx
    lea  rsi, [rel str_gn_ssh_cancel]
    call hv_tok_is
    test al, al
    jnz  .cancel
    mov  rdi, rbx
    lea  rsi, [rel str_gn_ssh_open]
    call hv_tok_is
    test al, al
    jz   .bad
    lea  rdi, [rbx + 4]
    xor  r13d, r13d
.identity:
    cmp  byte [rdi], ' '
    jne  .bad
    inc  rdi
    call guestnet_ingress_number
    jc   .bad
    mov  [rsp + r13 * 8], rax
    inc  r13d
    cmp  r13d, 4
    jb   .identity
    ; Four exact decimal octets become the existing wire-order IPv4 dword.
    xor  r14d, r14d
    xor  r15d, r15d
    cmp  byte [rdi], ' '
    jne  .bad
    inc  rdi
.ip:
    call guestnet_ingress_number
    jc   .bad
    cmp  rax, 255
    ja   .bad
    mov  ecx, r14d
    shl  eax, cl
    or   r15d, eax
    add  r14d, 8
    cmp  r14d, 32
    je   .ip_done
    cmp  byte [rdi], '.'
    jne  .bad
    inc  rdi
    jmp  .ip
.ip_done:
    ; Ordinary unicast only. No unspecified, loopback, multicast or broadcast.
    test r15b, r15b
    jz   .bad
    cmp  r15b, 127
    je   .bad
    cmp  r15b, 224
    jae  .bad
    cmp  byte [rdi], ' '
    jne  .bad
    inc  rdi
    call guestnet_ingress_number
    jc   .bad
    test rax, rax
    jz   .bad
    cmp  rax, 65535
    ja   .bad
    mov  [rsp + 32], rax
    cmp  byte [rdi], ' '
    jne  .bad
    inc  rdi
    call guestnet_ingress_number
    jc   .bad
    cmp  byte [rdi], 0
    jne  .bad
    test rax, rax
    jz   .bad
    cmp  rax, 300
    ja   .bad
    imul rax, 1000000
    mov  [rsp + 40], rax
    cmp  dword [rel guestnet_ingress_slot], 0
    jne  .bad                             ; no implicit replacement or refresh
    call guestnet_shell_live
    test eax, eax
    jz   .bad
    cmp  byte [rel hv_linux_run_req], 0
    jne  .bad
    cmp  byte [rel hv_linux_start_active], 1
    jne  .bad
    cmp  byte [rel guestnet_nat_up], 1
    jne  .bad
    cmp  qword [rel guestnet_domain_ctx], 0
    jne  .bad                             ; this grant is private-link NAT only
    mov  rax, [rsp]
    test rax, rax
    jz   .bad
    mov  ecx, [rel guestnet_launch_gen]
    cmp  rax, rcx
    jne  .bad
    mov  rax, [rsp + 8]
    cmp  rax, [rel guestnet_ring_epoch]
    jne  .bad
    mov  rax, [rsp + 16]
    test rax, rax
    jz   .bad
    cmp  rax, [rel hv_vcon_epoch]
    jne  .bad
    mov  rax, [rsp + 24]
    test rax, rax
    jz   .bad
    cmp  rax, [rel session_authority_epoch]
    jne  .bad
    call guestnet_host_source_ip
    test eax, eax
    jz   .bad
    cmp  eax, r15d
    je   .bad
    cmp  r15d, GN_GUEST_IP
    je   .bad
    mov  [rsp + 48], eax
    call time_monotonic_now_us
    test rax, rax
    jz   .bad
    cmp  rax, [rel guestnet_nat_clock_seen]
    jb   .bad
    mov  [rsp + 56], rax
    add  rax, [rsp + 40]
    jc   .bad
    mov  [rsp + 40], rax
    ; Do not evict or create a duplicate SSH tuple. No state changes on refusal.
    lea  rbx, [rel guestnet_nat_table]
    xor  r13d, r13d
    xor  r14d, r14d                         ; first free index+1
.scan:
    cmp  byte [rbx + GN_N_VALID], 0
    je   .free
    cmp  byte [rbx + GN_N_PROTO], 6
    jne  .next
    cmp  word [rbx + GN_N_GPORT], 0x1600
    jne  .next
    cmp  dword [rbx + GN_N_GIP], GN_GUEST_IP
    jne  .next
    cmp  [rbx + GN_N_RIP], r15d
    jne  .next
    mov  ax, [rsp + 32]
    xchg al, ah
    cmp  [rbx + GN_N_RPORT], ax
    je   .bad
    jmp  .next
.free:
    test r14d, r14d
    jnz  .next
    lea  r14d, [r13 + 1]
.next:
    add  rbx, GN_N_SIZE
    inc  r13d
    cmp  r13d, GN_NAT_SLOTS
    jb   .scan
    test r14d, r14d
    jz   .bad
    mov  eax, [rel guestnet_nat_port_next]
    cmp  eax, GN_NAT_PORT_BASE
    jb   .bad
    cmp  eax, GN_NAT_PORT_END
    jae  .bad
    inc  dword [rel guestnet_nat_port_next]
    mov  [rel guestnet_ingress_port], ax
    lea  ecx, [r14 - 1]
    imul edx, ecx, GN_N_SIZE
    lea  rbx, [rel guestnet_nat_table]
    add  rbx, rdx
    mov  [rbx + GN_N_NPORT], ax
    mov  word [rbx + GN_N_GPORT], 0x1600
    mov  ax, [rsp + 32]
    xchg al, ah
    mov  [rbx + GN_N_RPORT], ax
    mov  dword [rbx + GN_N_GIP], GN_GUEST_IP
    mov  [rbx + GN_N_RIP], r15d
    mov  byte [rbx + GN_N_PROTO], 6
    mov  rax, [rsp + 56]
    mov  [rel guestnet_nat_clock_seen], rax
    lea  rdx, [rel guestnet_nat_tcp_reserved]
    mov  [rdx + rcx * 8], rax
    lea  rdx, [rel guestnet_nat_udp_last]
    mov  qword [rdx + rcx * 8], 0
    mov  rax, [rsp + 40]
    mov  [rel guestnet_ingress_deadline], rax
    mov  eax, [rsp]
    mov  [rel guestnet_ingress_gen], eax
    mov  rax, [rsp + 8]
    mov  [rel guestnet_ingress_ring], rax
    mov  rax, [rsp + 16]
    mov  [rel guestnet_ingress_console], rax
    mov  rax, [rsp + 24]
    mov  [rel guestnet_ingress_owner], rax
    mov  eax, [rsp + 48]
    mov  [rel guestnet_ingress_host], eax
    mov  [rel guestnet_ingress_peer], r15d
    mov  ax, [rsp + 32]
    mov  [rel guestnet_ingress_peerport], ax
    mov  [rel guestnet_ingress_slot], r14d
    mov  byte [rbx + GN_N_VALID], 1          ; publish complete grant last
    jmp  .stat
.stat_arg:
    cmp  byte [rbx + 4], 0
    jne  .bad
    jmp  .stat
.cancel:
    lea  rdi, [rbx + 6]
    cmp  byte [rdi], ' '
    jne  .bad
    inc  rdi
    call guestnet_ingress_number
    jc   .bad
    cmp  byte [rdi], 0
    jne  .bad
    cmp  rax, GN_NAT_PORT_BASE
    jb   .bad
    cmp  rax, GN_NAT_PORT_END
    jae  .bad
    cmp  ax, [rel guestnet_ingress_port]
    jne  .bad
    call guestnet_ingress_clear
.stat:
    call guestnet_out_reset
    lea  rdi, [rel str_gn_ssh_line]
    call guestnet_out_str
    mov  eax, [rel guestnet_launch_gen]
    call guestnet_ingress_out_dec
    lea  rdi, [rel str_gn_ssh_ring]
    call guestnet_out_str
    mov  rax, [rel guestnet_ring_epoch]
    call guestnet_ingress_out_dec
    lea  rdi, [rel str_gn_ssh_console]
    call guestnet_out_str
    mov  rax, [rel hv_vcon_epoch]
    call guestnet_ingress_out_dec
    lea  rdi, [rel str_gn_ssh_owner]
    call guestnet_out_str
    mov  rax, [rel session_authority_epoch]
    call guestnet_ingress_out_dec
    lea  rdi, [rel str_gn_ssh_port]
    call guestnet_out_str
    xor  eax, eax
    cmp  dword [rel guestnet_ingress_slot], 0
    je   .port
    movzx eax, word [rel guestnet_ingress_port]
.port:
    call guestnet_ingress_out_dec
    lea  rdi, [rel str_gn_ssh_deadline]
    call guestnet_out_str
    xor  eax, eax
    cmp  dword [rel guestnet_ingress_slot], 0
    je   .deadline
    mov  rax, [rel guestnet_ingress_deadline]
.deadline:
    call guestnet_ingress_out_dec
    lea  rdi, [rel str_gn_ssh_peer]
    call guestnet_out_str
    xor  eax, eax
    cmp  dword [rel guestnet_ingress_slot], 0
    je   .peer
    mov  eax, [rel guestnet_ingress_peer]
.peer:
    call guestnet_out_ip
    lea  rdi, [rel str_gn_ssh_peerport]
    call guestnet_out_str
    xor  eax, eax
    cmp  dword [rel guestnet_ingress_slot], 0
    je   .peerport
    movzx eax, word [rel guestnet_ingress_peerport]
.peerport:
    call guestnet_ingress_out_dec
    lea  rdi, [rel str_gn_ssh_host]
    call guestnet_out_str
    call guestnet_host_source_ip
    call guestnet_out_ip
    jmp  .ready
.denied:
    call guestnet_out_reset
    lea  rdi, [rel str_gn_ssh_denied]
    jmp  .error
.bad:
    call guestnet_out_reset
    lea  rdi, [rel str_gn_ssh_bad]
.error:
    call guestnet_out_str
.ready:
    mov  byte [rel guestnet_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_OK
    add  rsp, 80
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; EDI=remote wire-order IPv4 -> EAX=static next hop or zero (no route).
; Use the native configuration owner's locked snapshot, bound to this selected
; endpoint. No route constants or default gateway live in the guest module.
; Caller-clobbered RAX/RCX/RDX/RDI; preserve all other registers.
guestnet_static_next_hop:
    push rbx
    sub  rsp, 32                         ; private snapshot, aligned call stack
    mov  ebx, edi
    mov  rdi, rsp
    call dns_wire_route_snapshot
    test eax, eax
    jnz  .none
    mov  eax, [rel udp_our_ip2]
    test eax, eax
    jz   .none
    cmp  eax, [rsp + dns_route_snapshot.source_ip]
    jne  .none                           ; stale/other endpoint configuration
    mov  edx, [rel udp_our_mac]
    cmp  edx, [rsp + dns_route_snapshot.source_mac]
    jne  .none
    movzx edx, word [rel udp_our_mac + 4]
    cmp  dx, [rsp + dns_route_snapshot.source_mac + 4]
    jne  .none
    mov  ecx, [rsp + dns_route_snapshot.mask_ip]
    test ecx, ecx
    jz   .none
    mov  edx, ecx
    bswap edx
    not  edx
    cmp  edx, 3                          ; ordinary /1../30 mask
    jb   .none
    lea  edi, [rdx + 1]
    test edi, edx
    jnz  .none                           ; noncontiguous mask
    mov  edx, eax
    xor  edx, ebx
    test edx, ecx
    jz   .direct
    mov  ebx, [rsp + dns_route_snapshot.gateway_ip]
    test ebx, ebx
    jz   .none                           ; off-link needs an explicit gateway
    cmp  ebx, eax
    je   .none                           ; cannot forward to ourselves
    xor  eax, ebx
    test eax, ecx
    jnz  .none                           ; gateway must be on the selected link
    not  ecx
    mov  eax, ebx
    and  eax, ecx
    jz   .none                           ; gateway is the network address
    cmp  eax, ecx
    je   .none                           ; gateway is the broadcast address
.direct:
    mov  eax, ebx
    jmp  .out
.none:
    xor  eax, eax
.out:
    add  rsp, 32
    pop  rbx
    ret

guestnet_host_source_ip:
    mov  eax, [rel udp_our_ip3]
    test eax, eax
    jnz  .selected
    mov  eax, [rel udp_our_ip2]
.selected:
    ret

; R12=Ethernet frame, R13=captured bytes. EAX=bounded declared frame
; length or zero. No tuple, buffer, ARP or delivery access on refusal. Only
; Fixed IPv4 headers, complete unfragmented UDP/TCP/echo, or bounded ICMP errors.
; Ethernet padding is outside the declared IP extent and is never forwarded.
; Clobbers EAX/ECX/EDX; preserves the packet and all saved registers.
guestnet_nat_ip_extent:
    cmp  r13, 42
    jb   .invalid
    cmp  byte [r12 + 14], 0x45
    jne  .invalid
    ; Wire flags/offset: allow DF alone; reject reserved, MF and any offset.
    test word [r12 + 20], 0xFFBF
    jnz  .invalid
    movzx eax, word [r12 + 16]
    xchg al, ah
    add  eax, 14
    cmp  rax, r13
    ja   .invalid
    cmp  eax, GN_FRAME_MAX
    ja   .invalid
    cmp  eax, 42
    jb   .invalid
    mov  ecx, eax
    sub  ecx, 34                           ; declared transport bytes
    cmp  byte [r12 + 23], 17
    je   .udp
    cmp  byte [r12 + 23], 1
    je   .echo
    cmp  byte [r12 + 23], 6
    jne  .invalid
    cmp  ecx, 20
    jb   .invalid
    movzx edx, byte [r12 + 46]
    shr  edx, 4
    shl  edx, 2                            ; actual TCP header including options
    cmp  edx, 20
    jb   .invalid
    cmp  edx, ecx
    ja   .invalid
    ret
.echo:
    cmp  byte [r12 + 34], 3
    je   .error
    cmp  byte [r12 + 34], 11
    je   .error
    cmp  byte [r12 + 35], 0              ; echo code must be zero
    jne  .invalid
    cmp  byte [r12 + 34], 8
    je   .echo_valid
    cmp  byte [r12 + 34], 0
    jne  .invalid
.echo_valid:
    ret
.error:
    cmp  eax, 70                          ; IPv4 + ICMP + quoted IPv4 +64bits
    jb   .invalid
    cmp  byte [r12 + 34], 3
    jne  .time_error
    cmp  byte [r12 + 35], 5               ; RFC792 destination-unreachable codes
    ja   .invalid
    ret
.time_error:
    cmp  byte [r12 + 35], 0               ; no fragment-reassembly errors
    jne  .invalid
    ret
.udp:
    movzx edx, word [r12 + 38]
    xchg dl, dh
    ; UDP length covers the IP payload.
    cmp  edx, ecx
    jne  .invalid
    ret
.invalid:
    xor  eax, eax
    ret

; Remaining image-lifetime reservation budget, clamped on invalid state.
guestnet_nat_ports_left:
    mov  ecx, [rel guestnet_nat_port_next]
    xor  eax, eax
    cmp  ecx, GN_NAT_PORT_BASE
    jb   .out
    cmp  ecx, GN_NAT_PORT_END
    jae  .out
    mov  eax, GN_NAT_PORT_END
    sub  eax, ecx
.out:
    ret

; Validated boot-relative microseconds. Never reset the watermark or port
; serial on device reset, STOP/START or rebind. Expired/rolled-back ports remain
; retired until this image is unloaded. No wall-clock adjustment is involved.
; EAX/RAX=now or zero; preserves saved registers and R14 packet extent.
; Legacy helper names now cover both TCP and UDP.
; Invalid clock observations change no expiry state. Equal samples are legal
; within one microsecond. A stalled source cannot prove elapsed inactivity.
guestnet_nat_udp_sweep:
    sub  rsp, 8
    call time_monotonic_now_us
    add  rsp, 8
    test rax, rax
    jz   .bad
    cmp  rax, [rel guestnet_nat_clock_seen]
    jb   .bad
    mov  rdx, rax
    cmp  byte [r12 + 23], 6
    jne  .udp_horizon
    mov  r11, GN_TCP_IDLE_US
    add  rdx, r11
    jmp  .horizon
.udp_horizon:
    add  rdx, GN_UDP_IDLE_US
.horizon:
    jc   .bad                            ; no arithmetic horizon wrap
    ; Preflight the whole timestamp set before any mutation: a future stamp
    ; cannot be refreshed backwards or make a partial expiry sweep commit.
    lea  rdx, [rel guestnet_nat_table]
    lea  r8, [rel guestnet_nat_udp_last]
    lea  rsi, [rel guestnet_nat_tcp_reserved]
    lea  rdi, [rel guestnet_nat_tcp_fin]
    mov  ecx, GN_NAT_SLOTS
.validate:
    cmp  byte [rdx + GN_N_VALID], 1
    jne  .validated_next
    cmp  byte [rdx + GN_N_PROTO], 6
    je   .validate_tcp
    cmp  byte [rdx + GN_N_PROTO], 17
    jne  .validated_next
    jmp  .validate_last
.validate_tcp:
    cmp [rdi],rax
    ja .bad
    cmp  [rsi], rax
    ja   .bad
    cmp  qword [r8], 0
    jne  .validate_last
    cmp  qword [rsi], 0
    je   .bad                            ; no TCP activity or reservation origin
.validate_last:
    cmp  [r8], rax
    ja   .bad
.validated_next:
    add  rdx, GN_N_SIZE
    add  r8, 8
    add  rsi, 8
    add  rdi, 8
    dec  ecx
    jnz  .validate
    mov  [rel guestnet_nat_clock_seen], rax
    call guestnet_ingress_check
    lea  rdx, [rel guestnet_nat_table]
    lea  r8, [rel guestnet_nat_udp_last]
    lea  rsi, [rel guestnet_nat_tcp_reserved]
    lea  rdi, [rel guestnet_nat_tcp_fin]
    mov  ecx, GN_NAT_SLOTS
.scan:
    cmp  byte [rdx + GN_N_VALID], 1
    jne  .next
    cmp  byte [rdx + GN_N_PROTO], 17
    jne  .tcp_scan
    mov  r9, [r8]
    test r9, r9
    jz   .expire                         ; no accepted forwarding authority
    mov  r10, rax
    sub  r10, r9
    cmp  r10, GN_UDP_IDLE_US
    jb   .next
    jmp  .expire
.tcp_scan:
    cmp  byte [rdx + GN_N_PROTO], 6
    jne  .next
    mov r9,[rdi]
    test r9,r9
    jz .tcp_idle
    mov r10,rax
    sub r10,r9
    cmp r10,GN_TCP_CLOSE_US
    jae .expire
.tcp_idle:
    mov  r9, [r8]                       ; only accepted forwarding refreshes this
    test r9, r9
    jnz  .tcp_age
    mov  r9, [rsi]                      ; unforwarded TCP reservation origin
.tcp_age:
    mov  r10, rax
    sub  r10, r9
    mov  r11, GN_TCP_IDLE_US            ; full 64-bit interval, not imm32
    cmp  r10, r11
    jb   .next
.expire:
    mov  byte [rdx + GN_N_VALID], 0
    mov  qword [r8], 0
    mov  qword [rsi], 0
    mov qword [rdi],0
.next:
    add  rdx, GN_N_SIZE
    add  r8, 8
    add  rsi, 8
    add  rdi, 8
    dec  ecx
    jnz  .scan
    ret
.bad:
    xor  eax, eax
    ret

; RBX=entry, RAX=validated observation at admission. Only called after actual
; NIC acceptance or real guest RX-ring delivery. Preserves saved registers.
guestnet_nat_udp_touch:
    mov  r8, rax
    mov  rax, rbx
    lea  rcx, [rel guestnet_nat_table]
    sub  rax, rcx
    xor  edx, edx
    mov  ecx, GN_N_SIZE
    div  rcx
    lea  rdx, [rel guestnet_nat_udp_last]
    mov  [rdx + rax * 8], r8
    cmp byte [rbx+GN_N_PROTO],6
    jne .out
    lea rcx,[rel guestnet_nat_tcp_fin]
    test byte [r12+47],4
    jnz .reset
    test byte [r12+47],1
    jz .out
    cmp qword [rcx+rax*8],0
    jne .out
    mov [rcx+rax*8],r8
    ret
.reset:
    mov byte [rbx+GN_N_VALID],0
    mov qword [rdx+rax*8],0
    mov qword [rcx+rax*8],0
    lea rcx,[rel guestnet_nat_tcp_reserved]
    mov qword [rcx+rax*8],0
.out:
    ret

; Read-only existing owner SSH return exception; never authorizes a new flow.
; R12=validated original packet. No tuple/rate/ARP/scratch publication.
guestnet_nat_owner_return:
    sub rsp,8
    call time_monotonic_now_us
    add rsp,8
    test rax,rax
    jz .bad
    cmp rax,[rel guestnet_nat_clock_seen]
    jb .bad
    cmp rax,[rel guestnet_ingress_deadline]
    jae .bad
    cmp  byte [rel guestnet_active], 1
    jne  .bad
    cmp  byte [rel guestnet_nat_up], 1
    jne  .bad
    cmp  byte [rel guestnet_net_up], 1
    jne  .bad
    cmp  byte [rel hv_linux_running], 1
    jne  .bad
    cmp  byte [rel hv_linux_stop_req], 0
    jne  .bad
    cmp  byte [rel hv_linux_run_req], 0
    jne  .bad
    cmp  byte [rel hv_linux_start_active], 1
    jne  .bad
    cmp  byte [rel hv_linux_kboot], 1
    jne  .bad
    cmp  byte [rel hv_vcon_ready], 1
    jne  .bad
    cmp  qword [rel guestnet_domain_ctx], 0
    jne  .bad
    mov  ecx, [rel guestnet_ingress_gen]
    cmp  ecx, [rel guestnet_launch_gen]
    jne  .bad
    cmp  ecx, [rel hv_linux_start_gen]
    jne  .bad
    cmp  ecx, [rel hv_linux_start_consumed]
    jne  .bad
    mov  rcx, [rel guestnet_ring_epoch]
    cmp  rcx, [rel guestnet_ingress_ring]
    jne  .bad
    mov  rcx, [rel hv_vcon_epoch]
    cmp  rcx, [rel guestnet_ingress_console]
    jne  .bad
    mov  rcx, [rel session_authority_epoch]
    cmp  rcx, [rel guestnet_ingress_owner]
    jne  .bad
    mov  ecx, [rel udp_our_ip3]
    test ecx, ecx
    jnz  .host
    mov  ecx, [rel udp_our_ip2]
.host:
    cmp  ecx, [rel guestnet_ingress_host]
    jne  .bad
    cmp byte [r12+23],6
    jne .bad
    cmp word [r12+34],0x1600
    jne .bad
    mov eax,[r12+30]
    cmp eax,[rel guestnet_ingress_peer]
    jne .bad
    mov ax,[r12+36]
    cmp ax,[rel guestnet_ingress_peerport]
    jne .bad
    mov ecx,[rel guestnet_ingress_slot]
    test ecx,ecx
    jz .bad
    cmp ecx,GN_NAT_SLOTS
    ja .bad
    dec ecx
    imul ecx,GN_N_SIZE
    lea rdx,[rel guestnet_nat_table]
    add rdx,rcx
    cmp byte [rdx+GN_N_VALID],1
    jne .bad
    cmp byte [rdx+GN_N_PROTO],6
    jne .bad
    cmp dword [rdx+GN_N_GIP],GN_GUEST_IP
    jne .bad
    cmp word [rdx+GN_N_GPORT],0x1600
    jne .bad
    mov ax,[rel guestnet_ingress_peerport]
    cmp ax,[rdx+GN_N_RPORT]
    jne .bad
    mov eax,[rel guestnet_ingress_peer]
    cmp eax,[rdx+GN_N_RIP]
    jne .bad
    mov ax,[rel guestnet_ingress_port]
    cmp ax,[rdx+GN_N_NPORT]
    jne .bad
    mov eax,1
    ret
.bad:
    xor eax,eax
    ret

guestnet_nat_public_ip:
    HV_GUEST_PUBLIC_IP

; Packet admission before any NAT state mutation, including expiry/TTL errors.
; Snapshot-only route read on static profiles; saved-register packet state stays.
guestnet_nat_destination_admit:
    push rbx
    sub rsp,32
    mov ebx,[r12+30]
    mov edx,[rel udp_our_ip3]
    mov ecx,[rel dhcp_ack_mask_v]
    test edx,edx
    jnz .classify
    mov rdi,rsp
    call dns_wire_route_snapshot
    test eax,eax
    jnz .unrouted
    mov edx,[rsp+dns_route_snapshot.source_ip]
    cmp edx,[rel udp_our_ip2]
    jne .unrouted
    mov eax,[rel udp_our_mac]
    cmp eax,[rsp+dns_route_snapshot.source_mac]
    jne .unrouted
    mov ax,[rel udp_our_mac+4]
    cmp ax,[rsp+dns_route_snapshot.source_mac+4]
    jne .unrouted
    mov ecx,[rsp+dns_route_snapshot.mask_ip]
.classify:
    test ecx,ecx
    jnz .subnet
    ; A maskless public attempt retains its old reservation-only behavior;
    ; the existing route check refuses before ARP/wire. No LAN is authorized.
    xor edx,edx
.subnet:
    mov eax,ebx
    call guestnet_nat_public_ip
    test eax,eax
    jnz .out
    call guestnet_nat_owner_return
    jmp .out
.unrouted:
    ; Preserve public no-route reservation semantics; the downstream route check
    ; still refuses transmission. Private classes need no route to be refused.
    xor edx,edx
    xor ecx,ecx
    mov eax,ebx
    call guestnet_nat_public_ip
.out:
    add rsp,32
    pop rbx
    ret

guestnet_nat_tx_frame:
    cld
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 64
    mov  qword [rsp + 8], 0              ; tentative UDP entry, if any
    mov  rax, [rel guestnet_ring_epoch]
    mov  [rsp + 40], rax
    mov  eax, [rel hv_linux_start_consumed]
    mov  [rsp + 48], eax
    mov  r12, rsi
    mov  r13d, ecx
    cmp  byte [rel guestnet_active], 1
    jne  .out
    cmp  byte [rel guestnet_nat_up], 1
    jne  .out
    call guestnet_nat_ip_extent
    test eax, eax
    jz   .out
    cmp  dword [r12 + 26], GN_GUEST_IP
    jne  .out
    mov  r13d, eax
    call guestnet_nat_destination_admit
    test eax,eax
    jz .out
    ; A forwarded hop must survive before tuple reservation, route/ARP or
    ; shared scratch access. Only the admitted copy is decremented below.
    cmp  byte [r12 + 22], 1
    jbe  .ttl_error
    ; The virtio TX header admits no checksum/GSO offload. Verify the original
    ; wire before reserving a tuple or touching route/ARP/shared scratch; later
    ; NAT checksum repair must not launder corrupt guest packets. The helpers
    ; read only the declared extent, including odd tails, and never write it.
    lea  rdi, [r12 + 14]
    mov  esi, 20
    call net_cksum16
    test ax, ax
    jnz  .out
    mov  r14d, r13d
    call guestnet_nat_transport_valid
    test eax, eax
    jz   .out
    cmp  byte [r12 + 23], 1
    jne  .transport
    call guestnet_icmp_tx
    jmp  .out
.transport:
    ; Sweep at most 16 entries. Invalid monotonic observations cannot admit
    ; either protocol or reclaim anything. The horizon is protocol-specific.
    call guestnet_nat_udp_sweep
    mov  [rsp], rax
    test rax, rax
    jz   .out
.find:
    ; Search past holes: an existing full tuple keeps its port. Accepted
    ; RST retires it; accepted FIN has a bounded non-refreshing close grace.
    ; New UDP reservations roll back on any send failure; the consumed host
    ; port stays retired even on rollback.
    lea  rbx, [rel guestnet_nat_table]
    xor  r14d, r14d
    mov  r15, -1
.scan:
    cmp  r14d, GN_NAT_SLOTS
    jae  .allocate
    cmp  byte [rbx + GN_N_VALID], 1
    jne  .remember_free
    mov  al, [r12 + 23]
    cmp  al, [rbx + GN_N_PROTO]
    jne  .next
    cmp  dword [rbx + GN_N_GIP], GN_GUEST_IP
    jne  .next
    mov  ax, [r12 + 34]
    cmp  ax, [rbx + GN_N_GPORT]
    jne  .next
    mov  ax, [r12 + 36]
    cmp  ax, [rbx + GN_N_RPORT]
    jne  .next
    mov  eax, [r12 + 30]
    cmp  eax, [rbx + GN_N_RIP]
    je   .entry
    jmp  .next
.remember_free:
    cmp  r15, -1
    jne  .next
    mov  r15, rbx
.next:
    add  rbx, GN_N_SIZE
    inc  r14d
    jmp  .scan
.allocate:
    cmp byte [r12+23],6
    jne .capacity
    test byte [r12+47],5                 ; stray FIN/RST creates no authority
    jnz .out
.capacity:
    cmp  r15, -1
    je   .out                           ; session owns all slots; never evict a live tuple
.use_free:
    mov  eax, [rel guestnet_nat_port_next]
    cmp  eax, GN_NAT_PORT_BASE
    jb   .out
    cmp  eax, GN_NAT_PORT_END
    jae  .out                           ; finite exhaustion, never wrap/reuse
    inc  dword [rel guestnet_nat_port_next]
    mov  rbx, r15
    cmp  byte [r12 + 23], 17
    jne  .reserve
    mov  [rsp + 8], rbx
    mov  rcx, [rbx]
    mov  [rsp + 16], rcx
    mov  rcx, [rbx + 8]
    mov  [rsp + 24], rcx
    mov  rcx, [rbx + 16]
    mov  [rsp + 32], rcx
.reserve:
    mov  [rbx + GN_N_NPORT], ax
    mov  byte [rbx + GN_N_VALID], 1
    cmp  byte [r12 + 23], 17
    jne  .reservation_ready
    ; A new UDP tuple earns reply authority only after accepted send and the
    ; same-owner check. A reset during the callback cannot strand it live.
    mov  byte [rbx + GN_N_VALID], 0
.reservation_ready:
    mov rax,rbx
    lea rcx,[rel guestnet_nat_table]
    sub rax,rcx
    xor edx,edx
    mov ecx,GN_N_SIZE
    div rcx
    lea rcx,[rel guestnet_nat_tcp_fin]
    mov qword [rcx+rax*8],0
    mov  al, [r12 + 23]
    mov  [rbx + GN_N_PROTO], al
    mov  ax, [r12 + 34]
    mov  [rbx + GN_N_GPORT], ax
    mov  ax, [r12 + 36]
    mov  [rbx + GN_N_RPORT], ax
    mov  dword [rbx + GN_N_GIP], GN_GUEST_IP
    mov  eax, [r12 + 30]
    mov  [rbx + GN_N_RIP], eax
    cmp  byte [r12 + 23], 6
    jne  .entry
    ; TCP reservations survive route/send refusal, but only for a finite idle
    ; interval from this first validated attempt. This is not accepted activity.
    mov  rax, rbx
    lea  rcx, [rel guestnet_nat_table]
    sub  rax, rcx
    xor  edx, edx
    mov  ecx, GN_N_SIZE
    div  rcx
    lea  rcx, [rel guestnet_nat_tcp_reserved]
    mov  rdx, [rsp]
    mov  [rcx + rax * 8], rdx
.entry:
    ; Resolve the real-wire next hop through the shared live ARP cache.
    mov  edi, [rbx + GN_N_RIP]
    mov  eax, [rel udp_our_ip3]
    test eax, eax
    jz   .static_next_hop
    mov  ecx, [rel dhcp_ack_mask_v]
    test ecx, ecx
    jz   .out                           ; no route without a valid lease mask
    mov  edx, eax
    xor  edx, edi
    and  edx, ecx
    jz   .lookup                        ; destination on the leased subnet
    mov  edi, [rel dhcp_ack_gw_v]
    test edi, edi
    jz   .out                           ; never invent a customer gateway
    jmp  .lookup
.static_next_hop:
    call guestnet_static_next_hop
    test eax, eax
    jz   .out
    mov  edi, eax
.lookup:
    mov  r14d, edi
    call arp_cache_lookup
    test rax, rax
    jnz  .have_mac
    mov  edi, r14d
    call guestnet_send_host_arp
    jmp  .out
.have_mac:
    mov  r15, rax
    lea  rdi, [rel guestnet_nat_tx_buf]
    mov  rsi, r12
    mov  ecx, r13d
    rep  movsb
    lea  rdi, [rel guestnet_nat_tx_buf]
    mov  eax, [r15 + E_MAC]
    mov  [rdi], eax
    mov  ax, [r15 + E_MAC + 4]
    mov  [rdi + 4], ax
    mov  eax, [rel udp_our_mac]
    mov  [rdi + 6], eax
    mov  ax, [rel udp_our_mac + 4]
    mov  [rdi + 10], ax
    call guestnet_host_source_ip
    test eax, eax
    jz   .out
    mov  [rdi + 26], eax
    dec  byte [rdi + 22]
    mov  word [rdi + 24], 0
    mov  ax, [rbx + GN_N_NPORT]
    xchg al, ah
    mov  [rdi + 34], ax
    ; The TCP checksum covers a pseudo-header; +40 is TCP sequence data and
    ; must never receive the UDP zero-checksum write.
    cmp  byte [rdi + 23], 6
    je   .tx_tcp_cksum
    mov  word [rdi + 40], 0                 ; IPv4 permits UDP checksum zero
    jmp  .tx_ip_cksum
.tx_tcp_cksum:
    mov  word [rdi + 50], 0
    push rdi
    call guestnet_tcp_cksum
    pop  rdi
.tx_ip_cksum:
    push rdi
    lea  rdi, [rdi + 14]
    mov  rsi, 20
    call net_cksum16
    pop  rdi
    mov  [rdi + 24], ah
    mov  [rdi + 25], al
    lea  rsi, [rel guestnet_nat_tx_buf]
    mov  edx, r13d
    call netdev_tx
    test rax, rax
    jnz  .out
    ; A synchronous endpoint may reset/detach/rebind the device. Old work
    ; cannot publish completion or undo the new owner's reset postimage.
    mov  rax, [rsp + 40]
    cmp  rax, [rel guestnet_ring_epoch]
    jne  .release
    mov  eax, [rsp + 48]
    cmp  eax, [rel hv_linux_start_consumed]
    jne  .release
    cmp  byte [rel guestnet_active], 1
    jne  .release
    cmp  byte [rel guestnet_nat_up], 1
    jne  .release
    mov  rdx, [rsp + 8]
    test rdx, rdx
    jz   .accepted
    mov  byte [rdx + GN_N_VALID], 1
.accepted:
    inc  dword [rel guestnet_nat_forwarded]
    mov  rax, [rsp]
    call guestnet_nat_udp_touch
    mov  qword [rsp + 8], 0              ; commit only accepted NIC forwarding
    mov  rax, [rsp]
    mov  rdx, [rsp + 40]
    mov  ecx, [rsp + 48]
    call guestnet_error_record
    jmp  .out
.ttl_error:
    mov  rdx, [rsp + 40]
    mov  ecx, [rsp + 48]
    call guestnet_ttl_error
.out:
    ; A synchronous endpoint may reset/detach/rebind the device. Old work
    ; cannot publish completion or undo the new owner's reset postimage.
    mov  rax, [rsp + 40]
    cmp  rax, [rel guestnet_ring_epoch]
    jne  .release
    mov  eax, [rsp + 48]
    cmp  eax, [rel hv_linux_start_consumed]
    jne  .release
    cmp  byte [rel guestnet_active], 1
    jne  .release
    cmp  byte [rel guestnet_nat_up], 1
    jne  .release
    mov  rdx, [rsp + 8]
    test rdx, rdx
    jz   .release
    mov  rax, [rsp + 16]
    mov  [rdx], rax
    mov  rax, [rsp + 24]
    mov  [rdx + 8], rax
    mov  rax, [rsp + 32]
    mov  [rdx + 16], rax
.release:
    add  rsp, 64
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; R12=immutable original, R13D=declared frame, RDX=TX epoch, ECX=TX session.
; Private-link router expiry only. No NIC/ARP, conntrack or accepted-wire credit.
; Rate state survives resets: STOP/START cannot replenish this loaded-image cap.
guestnet_ttl_error:
    HV_POWER_WORK guestnet_ttl_error, 0, hv_guest_power_io_admit
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 640                         ; bounded private reply, never shared scratch
    mov  [rsp], rdx
    mov  [rsp + 8], ecx
    cmp  byte [rel guestnet_active], 1
    jne  .out
    cmp  byte [rel guestnet_nat_up], 1
    jne  .out
    cmp  qword [rel guestnet_domain_ctx], 0
    jne  .out
    cmp  byte [r12 + 22], 1
    ja   .out
    cmp  word [r12 + 12], 0x0008
    jne  .out
    cmp  dword [r12 + 26], GN_GUEST_IP
    jne  .out
    ; Exact private unicast link identities suppress foreign and link group RX.
    cmp  dword [r12], 0x4F615002
    jne  .out
    cmp  word [r12 + 4], 0x0253
    jne  .out
    cmp  dword [r12 + 6], 0x50005452
    jne  .out
    cmp  word [r12 + 10], 0x4F61
    jne  .out
    call guestnet_nat_destination_admit
    test eax,eax
    jz .out
    ; Finite destination policy: ordinary host addresses only. Local private
    ; subnet is not forwarded; zero/loopback/group/reserved and host .0/.255
    ; are suppressed, including private and conventional directed broadcasts.
    mov  eax, [r12 + 30]
    test al, al
    jz   .out
    cmp  al, 127
    je   .out
    cmp  al, 224
    jae  .out
    mov  edx, eax
    and  edx, 0x00FFFFFF
    cmp  edx, 0x0002000A
    je   .out
    shr  eax, 24
    test al, al
    jz   .out
    cmp  al, 255
    je   .out
    ; Also suppress the current physical subnet's directed broadcast/network
    ; for non-/24 masks. These are read-only facts, never a route/ARP request.
    mov  ebx, [rel dhcp_ack_mask_v]
    test ebx, ebx
    jz   .protocol
    cmp  ebx, -1
    je   .protocol
    call guestnet_host_source_ip
    xor  eax, [r12 + 30]
    and  eax, ebx
    jnz  .protocol
    not  ebx
    mov  eax, [r12 + 30]
    and  eax, ebx
    test eax, eax
    jz   .out
    cmp  eax, ebx
    je   .out
.protocol:
    cmp  byte [r12 + 23], 1
    jne  .integrity
    cmp  word [r12 + 34], 8               ; echo requests only, never error-on-error
    jne  .out
.integrity:
    lea  rdi, [r12 + 14]
    mov  esi, 20
    call net_cksum16
    test ax, ax
    jnz  .out
    mov  r14d, r13d
    call guestnet_nat_transport_valid    ; complete original, including odd tail
    test eax, eax
    jz   .out
    call time_monotonic_now_us
    test rax, rax
    jz   .out
    cmp  rax, [rel guestnet_nat_clock_seen]
    jb   .out
    cmp  rax, [rel guestnet_ttl_clock_seen]
    jb   .out
    cmp  rax, [rel guestnet_ttl_next_us]
    jb   .out
    mov  rbx, rax
    add  rbx, GN_TTL_INTERVAL
    jc   .out
    ; The clock is currently non-yielding. Recheck the original TX custody
    ; before any reply or rate-state publication, even if its seam revokes it.
    mov  rdx, [rsp]
    cmp  rdx, [rel guestnet_ring_epoch]
    jne  .out
    mov  ecx, [rsp + 8]
    cmp  ecx, [rel hv_linux_start_consumed]
    jne  .out
    cmp  byte [rel guestnet_active], 1
    jne  .out
    cmp  byte [rel guestnet_nat_up], 1
    jne  .out
    cmp  qword [rel guestnet_domain_ctx], 0
    jne  .out
    mov  [rel guestnet_ttl_clock_seen], rax
    mov  [rel guestnet_ttl_next_us], rbx   ; full RX also consumes an attempt budget
    mov  r15d, r13d
    sub  r15d, 14
    cmp  r15d, GN_TTL_QUOTE_MAX
    jbe  .quote_size
    mov  r15d, GN_TTL_QUOTE_MAX
.quote_size:
    lea  r14d, [r15d + 42]
    lea  rdi, [rsp + 32]
    xor  eax, eax
    mov  ecx, 42
    rep  stosb
    lea  rdi, [rsp + 32]
    mov  dword [rdi], 0x50005452
    mov  word [rdi + 4], 0x4F61
    call guestnet_put_gateway_mac
    mov  word [rdi + 12], 0x0008
    mov  byte [rdi + 14], 0x45
    mov  ax, r14w
    sub  ax, 14
    xchg al, ah
    mov  [rdi + 16], ax
    mov  byte [rdi + 22], 64              ; fresh local TTL, never inherited expiry
    mov  byte [rdi + 23], 1
    mov  dword [rdi + 26], GN_GATEWAY_IP
    mov  dword [rdi + 30], GN_GUEST_IP
    mov  byte [rdi + 34], 11              ; code0, checksum and unused initially zero
    add  rdi, 42
    lea  rsi, [r12 + 14]
    mov  ecx, r15d
    rep  movsb                            ; original TTL/checksum/transport unchanged
    lea  rdi, [rsp + 32]
    call guestnet_icmp_checksums
    lea  rsi, [rsp + 32]
    mov  edx, r14d
    call guestnet_rx_deliver              ; real power, epoch and whole-chain checks
.out:
    add  rsp, 640
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; Read-only transport integrity for an already admitted IPv4 IHL=5 packet.
; R12=original frame, R14D=declared Ethernet+IP extent. EAX=1 valid/0 invalid.
; RFC 9293 3.1: TCP always checks the original pseudoheader + full segment,
; even when its checksum field is zero. RFC 768: IPv4 UDP zero means omitted;
; every nonzero UDP checksum must verify. No NIC checksum-valid metadata is
; supplied by the copied-frame RX ABI, and guest features grant no exemption.
; net_cksum16 preserves R8/RSI and handles odd tails without a padding read.
; Only caller-saved registers change; no packet or shared scratch writes.
guestnet_nat_transport_valid:
    cmp  byte [r12 + 23], 1
    jne  .transport
    jmp  guestnet_icmp_valid
.transport:
    cmp  byte [r12 + 23], 17
    jne  .check
    cmp  word [r12 + 40], 0
    je   .valid
.check:
    lea  rdi, [r12 + 26]
    mov  esi, 8
    call net_cksum16                    ; both original IPv4 addresses
    not  ax
    movzx r8d, ax                       ; address partial sum, network value
    movzx eax, byte [r12 + 23]
    add  r8d, eax                     ; pseudoheader zero/protocol word
    mov  esi, r14d
    sub  esi, 34
    add  r8d, esi                     ; pseudoheader transport length
    lea  rdi, [r12 + 34]
    call net_cksum16                    ; original segment INCLUDING checksum
    not  ax
    movzx eax, ax
    add  eax, r8d
    mov  ecx, eax
    shr  ecx, 16
    and  eax, 0xFFFF
    add  eax, ecx
    mov  ecx, eax
    shr  ecx, 16
    and  eax, 0xFFFF
    add  eax, ecx                      ; carry from the first fold
    cmp  eax, 0xFFFF
    jne  .invalid
.valid:
    mov  eax, 1
    ret
.invalid:
    xor  eax, eax
    ret

; Called from udp_handle_ipv4 before host-port dispatch. RDI=frame, RSI=len.
; EAX=1 iff a live NAT tuple owned and consumed the frame.
guestnet_nat_rx_frame:
    ; Host ingress is an external producer, even on the probing BSP task.
    ; Refusal leaves ordinary host-port dispatch live; no tuple or RAM write.
    HV_POWER_WORK guestnet_nat_rx_frame, 0, hv_guest_power_admit
    cld
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 32
    mov  rax, [rel guestnet_ring_epoch]
    mov  [rsp + 8], rax
    mov  eax, [rel hv_linux_start_consumed]
    mov  [rsp + 16], eax
    mov  r12, rdi
    mov  r13, rsi
    xor  r15d, r15d
    cmp  byte [rel guestnet_active], 1
    jne  .out
    cmp  byte [rel guestnet_nat_up], 1
    jne  .out
    call guestnet_nat_ip_extent
    test eax, eax
    jz   .out
    mov  r14d, eax
    ; Un-NAT forwards onto the guest link: the same hop rule applies.
    ; Refusal returns unowned with the original frame and host dispatch intact.
    cmp  byte [r12 + 22], 1
    jbe  .out
    ; Preserve the wire-proven Path-A ordering: a corrupt IPv4 header never
    ; reaches conntrack or bypasses normal host filtering through the NAT hook.
    lea  rdi, [r12 + 14]
    mov  esi, 20
    call net_cksum16
    test ax, ax
    jnz  .out
    call guestnet_nat_transport_valid
    test eax, eax
    jz   .out
    call guestnet_host_source_ip
    test eax, eax
    jz   .out
    cmp  dword [r12 + 30], eax
    jne  .out
    cmp  byte [r12 + 23], 1
    jne  .transport
    call guestnet_icmp_rx
    mov  r15d, eax
    jmp  .out
.transport:
    movzx eax, byte [r12 + 36]
    shl  eax, 8
    mov  al, [r12 + 37]
    cmp  eax, GN_NAT_PORT_BASE
    jb   .out
    cmp  eax, GN_NAT_PORT_END
    jae  .out
    call guestnet_nat_udp_sweep
    mov  [rsp], rax
    test rax, rax
    jz   .out
.find:
    ; Ports are image-lifetime serials, no longer slot-derived indices.
    ; Bounded scan keeps protocol and complete remote/guest identity checks.
    lea  rbx, [rel guestnet_nat_table]
    mov  ecx, GN_NAT_SLOTS
.scan:
    cmp  byte [rbx + GN_N_VALID], 1
    jne  .next
    mov  ax, [r12 + 36]
    xchg al, ah
    cmp  ax, [rbx + GN_N_NPORT]
    jne  .next
    mov  al, [r12 + 23]
    cmp  al, [rbx + GN_N_PROTO]
    jne  .next
    cmp  dword [rbx + GN_N_GIP], GN_GUEST_IP
    jne  .next
    mov  eax, [r12 + 26]
    cmp  eax, [rbx + GN_N_RIP]
    jne  .next
    mov  ax, [r12 + 34]
    cmp  ax, [rbx + GN_N_RPORT]
    je   .matched
.next:
    add  rbx, GN_N_SIZE
    dec  ecx
    jnz  .scan
    jmp  .out
.matched:
    lea  rdi, [rel guestnet_nat_rx_frame_buf]
    mov  rsi, r12
    mov  ecx, r14d
    rep  movsb
    lea  rdi, [rel guestnet_nat_rx_frame_buf]
    mov  byte [rdi + 0], 0x52
    mov  byte [rdi + 1], 0x54
    mov  byte [rdi + 2], 0x00
    mov  byte [rdi + 3], 0x50
    mov  byte [rdi + 4], 0x61
    mov  byte [rdi + 5], 0x4F
    call guestnet_put_gateway_mac
    mov  eax, [rbx + GN_N_GIP]
    mov  [rdi + 30], eax
    mov  ax, [rbx + GN_N_GPORT]
    mov  [rdi + 36], ax
    dec  byte [rdi + 22]                 ; one forwarded hop, before IP checksum
    cmp  byte [rdi + 23], 6
    je   .rx_tcp_cksum
    mov  word [rdi + 40], 0
    jmp  .rx_ip_cksum
.rx_tcp_cksum:
    mov  word [rdi + 50], 0
    push rdi
    call guestnet_tcp_cksum
    pop  rdi
.rx_ip_cksum:
    mov  word [rdi + 24], 0
    push rdi
    lea  rdi, [rdi + 14]
    mov  rsi, 20
    call net_cksum16
    pop  rdi
    mov  [rdi + 24], ah
    mov  [rdi + 25], al
    mov  rsi, rdi
    mov  edx, r14d
    call guestnet_rx_deliver
    test eax, eax
    jz   .owned
    ; Delivery may complete through a callback which revokes this session.
    ; Its new state is authoritative even when the endpoint returned success.
    mov  rax, [rsp + 8]
    cmp  rax, [rel guestnet_ring_epoch]
    jne  .owned
    mov  eax, [rsp + 16]
    cmp  eax, [rel hv_linux_start_consumed]
    jne  .owned
    cmp  byte [rel guestnet_active], 1
    jne  .owned
    cmp  byte [rel guestnet_nat_up], 1
    jne  .owned
    inc  dword [rel guestnet_nat_returned]
    mov  rax, [rsp]
    call guestnet_nat_udp_touch
.owned:
    mov  r15d, 1
.out:
    mov  eax, r15d
    add  rsp, 32
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; ICMP echo custody is per accepted request, not an endpoint connection.
; No identifier is ever recycled while this image remains loaded. Native ICMP
; is an echo responder, so its requests/replies do not allocate this namespace.
; The original frame is fully extent/checksum/TTL/address validated by callers.
; Helpers below preserve saved registers. All loops have fixed slot/MTU bounds.

; Boolean validity of the complete declared ICMP message, including checksum.
guestnet_icmp_valid:
    lea  rdi, [r12 + 34]
    mov  esi, r14d
    sub  esi, 34
    call net_cksum16                    ; ICMP has no pseudoheader
    test ax, ax
    setz al
    movzx eax, al
    ret

; RAX=validated observation or zero. Preflight all live echo timestamps before
; committing any expiry; share the loaded-image NAT clock highwater.
guestnet_icmp_now:
    sub  rsp, 8
    call time_monotonic_now_us
    add  rsp, 8
    test rax, rax
    jz   .bad
    cmp  rax, [rel guestnet_nat_clock_seen]
    jb   .bad
    mov  rdx, rax
    add  rdx, GN_IC_IDLE_US
    jc   .bad
    lea  rdi, [rel guestnet_icmp_table]
    mov  ecx, GN_IC_SLOTS
.validate:
    cmp  byte [rdi], 1
    jne  .valid_next
    cmp  qword [rdi + GN_IC_LAST], 0
    je   .bad
    cmp  [rdi + GN_IC_LAST], rax
    ja   .bad
.valid_next:
    add  rdi, GN_IC_SIZE
    dec  ecx
    jnz  .validate
    mov  [rel guestnet_nat_clock_seen], rax
    lea  rdi, [rel guestnet_icmp_table]
    mov  ecx, GN_IC_SLOTS
.sweep:
    cmp  byte [rdi], 1
    jne  .next
    mov  rdx, rax
    sub  rdx, [rdi + GN_IC_LAST]
    cmp  rdx, GN_IC_IDLE_US
    jb   .next
    mov  byte [rdi], 0
.next:
    add  rdi, GN_IC_SIZE
    dec  ecx
    jnz  .sweep
    ret
.bad:
    xor  eax, eax
    ret

; R12=validated original request, R13D=declared frame length.
; Reserve only a serial before send. A failed send has no reply authority and
; cannot disturb any existing accepted request, even an identical one.
guestnet_icmp_tx:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 32
    cmp  byte [r12 + 34], 8
    jne  .out
    call guestnet_icmp_now
    test rax, rax
    jz   .out
    mov  [rsp], rax
    lea  rbx, [rel guestnet_icmp_table]
    mov  ecx, GN_IC_SLOTS
.find:
    cmp  byte [rbx], 1
    jne  .free
    add  rbx, GN_IC_SIZE
    dec  ecx
    jnz  .find
    jmp  .out                            ; never evict accepted unexpired work
.free:
    mov  eax, [rel guestnet_icmp_id_next]
    cmp  eax, GN_IC_ID_BASE
    jb   .out
    cmp  eax, GN_IC_ID_END
    jae  .out                            ; finite budget, never truncate/wrap
    inc  dword [rel guestnet_icmp_id_next]
    mov  [rsp + 8], eax
    mov  eax, [rel hv_linux_start_consumed]
    mov  [rsp + 12], eax
    mov  rax, [rel guestnet_ring_epoch]
    mov  [rsp + 16], rax
    call guestnet_host_source_ip
    test eax, eax
    jz   .out
    mov  [rsp + 24], eax
    mov  edi, [r12 + 30]
    mov  eax, [rel udp_our_ip3]
    test eax, eax
    jz   .static
    mov  ecx, [rel dhcp_ack_mask_v]
    test ecx, ecx
    jz   .out
    xor  eax, edi
    and  eax, ecx
    jz   .lookup
    mov  edi, [rel dhcp_ack_gw_v]
    test edi, edi
    jz   .out
    jmp  .lookup
.static:
    call guestnet_static_next_hop
    test eax, eax
    jz   .out
    mov  edi, eax
.lookup:
    mov  r14d, edi
    call arp_cache_lookup
    test rax, rax
    jnz  .mac
    mov  edi, r14d
    call guestnet_send_host_arp
    jmp  .out
.mac:
    mov  r15, rax
    lea  rdi, [rel guestnet_nat_tx_buf]
    mov  rsi, r12
    mov  ecx, r13d
    rep  movsb
    lea  rdi, [rel guestnet_nat_tx_buf]
    mov  eax, [r15 + E_MAC]
    mov  [rdi], eax
    mov  ax, [r15 + E_MAC + 4]
    mov  [rdi + 4], ax
    mov  eax, [rel udp_our_mac]
    mov  [rdi + 6], eax
    mov  ax, [rel udp_our_mac + 4]
    mov  [rdi + 10], ax
    mov  eax, [rsp + 24]
    mov  [rdi + 26], eax
    mov  eax, [rsp + 8]
    xchg al, ah
    mov  [rdi + 38], ax
    dec  byte [rdi + 22]
    call guestnet_icmp_checksums
    lea  rsi, [rel guestnet_nat_tx_buf]
    mov  edx, r13d
    call netdev_tx
    test rax, rax
    jnz  .out
    ; A synchronous send seam may revoke/reset the ring. Do not publish old
    ; work into a new session even if the NIC accepted the packet.
    mov  eax, [rsp + 12]
    cmp  eax, [rel hv_linux_start_consumed]
    jne  .out
    mov  rax, [rsp + 16]
    cmp  rax, [rel guestnet_ring_epoch]
    jne  .out
    cmp  byte [rel guestnet_active], 1
    jne  .out
    cmp  byte [rel guestnet_nat_up], 1
    jne  .out
    mov  rdi, rbx
    xor  eax, eax
    mov  ecx, GN_IC_SIZE / 8
    rep  stosq                           ; retire stale payload tail before commit
    mov  ax, [r12 + 38]
    mov  [rbx + GN_IC_GID], ax
    mov  eax, [rsp + 8]
    mov  [rbx + GN_IC_NID], ax
    mov  ax, [r12 + 40]
    mov  [rbx + GN_IC_SEQ], ax
    mov  eax, [r12 + 30]
    mov  [rbx + GN_IC_REMOTE], eax
    mov  eax, [rsp + 24]
    mov  [rbx + GN_IC_HOST], eax
    mov  eax, [rsp + 12]
    mov  [rbx + GN_IC_SESSION], eax
    mov  rax, [rsp + 16]
    mov  [rbx + GN_IC_EPOCH], rax
    mov  rax, [rsp]
    mov  [rbx + GN_IC_LAST], rax
    mov  ecx, r13d
    sub  ecx, 42
    mov  [rbx + GN_IC_LEN], ecx
    lea  rdi, [rbx + GN_IC_PAYLOAD]
    lea  rsi, [r12 + 42]
    rep  movsb
    mov  byte [rbx], 1                    ; accepted request commits last
    inc  dword [rel guestnet_nat_forwarded]
    mov  rax, [rsp]
    mov  rdx, [rsp + 16]
    mov  ecx, [rsp + 12]
    call guestnet_error_record
.out:
    add  rsp, 32
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; R12=validated original reply, R14D=declared frame length. EAX=owned.
; A queue refusal keeps the outstanding request but never extends its deadline.
; Successful delivery retires it; duplicate/delayed replies cannot re-deliver.
guestnet_icmp_rx:
    cmp  byte [r12 + 34], 3
    je   guestnet_error_rx
    cmp  byte [r12 + 34], 11
    je   guestnet_error_rx
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 16
    mov  rax, [rel guestnet_ring_epoch]
    mov  [rsp], rax
    mov  eax, [rel hv_linux_start_consumed]
    mov  [rsp + 8], eax
    xor  r15d, r15d
    cmp  byte [r12 + 34], 0
    jne  .out
    call guestnet_icmp_now
    test rax, rax
    jz   .out
    lea  rbx, [rel guestnet_icmp_table]
    mov  r13d, GN_IC_SLOTS
.find:
    cmp  byte [rbx], 1
    jne  .next
    mov  ax, [r12 + 38]
    xchg al, ah
    cmp  ax, [rbx + GN_IC_NID]
    jne  .next
    mov  ax, [r12 + 40]
    cmp  ax, [rbx + GN_IC_SEQ]
    jne  .next
    mov  eax, [r12 + 26]
    cmp  eax, [rbx + GN_IC_REMOTE]
    jne  .next
    mov  eax, [r12 + 30]
    cmp  eax, [rbx + GN_IC_HOST]
    jne  .next
    mov  eax, [rel hv_linux_start_consumed]
    cmp  eax, [rbx + GN_IC_SESSION]
    jne  .next
    mov  rax, [rel guestnet_ring_epoch]
    cmp  rax, [rbx + GN_IC_EPOCH]
    jne  .next
    mov  ecx, r14d
    sub  ecx, 42
    cmp  ecx, [rbx + GN_IC_LEN]
    jne  .next
    lea  rsi, [r12 + 42]
    lea  rdi, [rbx + GN_IC_PAYLOAD]
    repe cmpsb
    jne  .next
    jmp  .matched
.next:
    add  rbx, GN_IC_SIZE
    dec  r13d
    jnz  .find
    jmp  .out
.matched:
    lea  rdi, [rel guestnet_nat_rx_frame_buf]
    mov  rsi, r12
    mov  ecx, r14d
    rep  movsb
    lea  rdi, [rel guestnet_nat_rx_frame_buf]
    mov  dword [rdi], 0x50005452
    mov  word [rdi + 4], 0x4F61
    call guestnet_put_gateway_mac
    mov  dword [rdi + 30], GN_GUEST_IP
    mov  ax, [rbx + GN_IC_GID]
    mov  [rdi + 38], ax
    dec  byte [rdi + 22]
    call guestnet_icmp_checksums
    lea  rsi, [rel guestnet_nat_rx_frame_buf]
    mov  edx, r14d
    call guestnet_rx_deliver
    test eax, eax
    jz   .owned
    ; The delivery endpoint can revoke/reset this device before returning.
    ; Its postimage owns the slot; old completion cannot retire or credit it.
    mov  rax, [rsp]
    cmp  rax, [rel guestnet_ring_epoch]
    jne  .owned
    mov  eax, [rsp + 8]
    cmp  eax, [rel hv_linux_start_consumed]
    jne  .owned
    cmp  byte [rel guestnet_active], 1
    jne  .owned
    cmp  byte [rel guestnet_nat_up], 1
    jne  .owned
    mov  byte [rbx], 0
    inc  dword [rel guestnet_nat_returned]
.owned:
    mov  r15d, 1
.out:
    mov  eax, r15d
    add  rsp, 16
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=bounded copied frame. Recompute ICMP over exactly the declared IP payload,
; then IPv4 header. No TCP pseudoheader, no padding, odd tails included.
guestnet_icmp_checksums:
    push rbx
    mov  rbx, rdi
    mov  word [rbx + 36], 0
    movzx esi, byte [rbx + 16]
    shl  esi, 8
    mov  sil, [rbx + 17]
    sub  esi, 20
    lea  rdi, [rbx + 34]
    call net_cksum16
    mov  [rbx + 36], ah
    mov  [rbx + 37], al
    mov  word [rbx + 24], 0
    lea  rdi, [rbx + 14]
    mov  esi, 20
    call net_cksum16
    mov  [rbx + 24], ah
    mov  [rbx + 25], al
    mov  rdi, rbx
    pop  rbx
    ret

; Fixed accepted-wire history, independent of tentative flow reservations.
; R12=original frame, R13D=declared length, RAX=accepted admission time,
; RDX=captured epoch, ECX=captured session. Called only after NIC acceptance.
; Preserves saved registers; never grants custody after callback revocation.
guestnet_error_record:
    push rbx
    push r12
    push r13
    push r14
    push r15
    cmp  byte [rel guestnet_active], 1
    jne  .out
    cmp  byte [rel guestnet_nat_up], 1
    jne  .out
    cmp  rdx, [rel guestnet_ring_epoch]
    jne  .out
    cmp  ecx, [rel hv_linux_start_consumed]
    jne  .out
    mov  r14, rax
    mov  r15, rdx
    mov  edx, [rel guestnet_error_next]
    cmp  edx, GN_ER_SLOTS
    jae  .out
    imul ebx, edx, GN_ER_SIZE
    lea  rdi, [rel guestnet_error_table]
    add  rbx, rdi
    mov  rdi, rbx
    xor  eax, eax
    mov  ecx, GN_ER_SIZE / 8
    rep  stosq
    mov  eax, [rel hv_linux_start_consumed]
    mov  [rbx + GN_ER_SESSION], eax
    mov  [rbx + GN_ER_EPOCH], r15
    mov  [rbx + GN_ER_AT], r14
    mov  eax, r13d
    sub  eax, 14
    mov  [rbx + GN_ER_LEN], eax
    mov  ax, [r12 + 34]
    mov  dx, [r12 + 40]                  ; original UDP checksum, including omission
    cmp  byte [r12 + 23], 17
    je   .identity
    cmp  byte [r12 + 23], 6
    jne  .echo_identity
    mov  dx, [r12 + 50]                  ; original complete TCP checksum
    jmp  .identity
.echo_identity:
    mov  ax, [r12 + 38]                  ; original echo identifier/checksum
    mov  dx, [r12 + 36]
.identity:
    mov  [rbx + GN_ER_GPORT], ax
    mov  [rbx + GN_ER_CKSUM], dx
    lea  rsi, [rel guestnet_nat_tx_buf + 14]
    lea  rdi, [rbx + GN_ER_IP]
    mov  ecx, r13d
    sub  ecx, 14
    rep  movsb
    mov  byte [rbx], 1                    ; publish accepted provenance last
    mov  eax, [rel guestnet_error_next]
    inc  eax
    and  eax, GN_ER_SLOTS - 1             ; bounded recent history, no flow eviction
    mov  [rel guestnet_error_next], eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; RBX=accepted provenance, R15=validated now. Read-only current owner check.
; Errors never sweep, close, consume, refresh or repair a flow or timestamp.
guestnet_error_live:
    push rbx
    push r12
    push r13
    push r14
    push r15
    lea  r12, [rbx + GN_ER_IP]
    cmp  byte [r12 + 9], 1
    je   .echo
    lea  rdi, [rel guestnet_nat_table]
    lea  rsi, [rel guestnet_nat_udp_last]
    lea  r14, [rel guestnet_nat_tcp_fin]
    mov  ecx, GN_NAT_SLOTS
.flow:
    cmp  byte [rdi + GN_N_VALID], 1
    jne  .next
    mov  al, [r12 + 9]
    cmp  al, [rdi + GN_N_PROTO]
    jne  .next
    cmp  dword [rdi + GN_N_GIP], GN_GUEST_IP
    jne  .next
    mov  ax, [rbx + GN_ER_GPORT]
    cmp  ax, [rdi + GN_N_GPORT]
    jne  .next
    mov  ax, [r12 + 20]
    xchg al, ah
    cmp  ax, [rdi + GN_N_NPORT]
    jne  .next
    mov  ax, [r12 + 22]
    cmp  ax, [rdi + GN_N_RPORT]
    jne  .next
    mov  eax, [r12 + 16]
    cmp  eax, [rdi + GN_N_RIP]
    jne  .next
    mov  rax, [rsi]
    mov  rdx, GN_UDP_IDLE_US
    cmp  byte [r12 + 9], 17
    je   .stamp
    mov rdx,[r14]
    test rdx,rdx
    jz .tcp_live
    cmp rdx,r15
    ja .bad
    mov rcx,r15
    sub rcx,rdx
    cmp rcx,GN_TCP_CLOSE_US
    jae .bad
.tcp_live:
    mov  rdx, GN_TCP_IDLE_US
    jmp  .stamp
.next:
    add  rdi, GN_N_SIZE
    add  rsi, 8
    add r14,8
    dec  ecx
    jnz  .flow
    jmp  .bad
.echo:
    lea  rdi, [rel guestnet_icmp_table]
    mov  ecx, GN_IC_SLOTS
.echo_scan:
    cmp  byte [rdi], 1
    jne  .echo_next
    mov  ax, [r12 + 24]
    xchg al, ah
    cmp  ax, [rdi + GN_IC_NID]
    jne  .echo_next
    mov  ax, [rbx + GN_ER_GPORT]
    cmp  ax, [rdi + GN_IC_GID]
    jne  .echo_next
    mov  ax, [r12 + 26]
    cmp  ax, [rdi + GN_IC_SEQ]
    jne  .echo_next
    mov  eax, [r12 + 16]
    cmp  eax, [rdi + GN_IC_REMOTE]
    jne  .echo_next
    mov  eax, [r12 + 12]
    cmp  eax, [rdi + GN_IC_HOST]
    jne  .echo_next
    mov  eax, [rel hv_linux_start_consumed]
    cmp  eax, [rdi + GN_IC_SESSION]
    jne  .echo_next
    mov  rax, [rel guestnet_ring_epoch]
    cmp  rax, [rdi + GN_IC_EPOCH]
    jne  .echo_next
    mov  rax, [rdi + GN_IC_LAST]
    mov  edx, GN_IC_IDLE_US
    jmp  .stamp
.echo_next:
    add  rdi, GN_IC_SIZE
    dec  ecx
    jnz  .echo_scan
    jmp  .bad
.stamp:
    test rax, rax                        ; failed TCP reservations have no accepted time
    jz   .bad
    cmp  rax, r15
    ja   .bad
    mov  rcx, r15
    sub  rcx, rax
    cmp  rcx, rdx
    jae  .bad
    mov  eax, 1
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; R12=outer frame, R14D=declared length. Common outer IPv4/ICMP validation,
; current host selection and power admission already passed. EAX=owned.
; Admit RFC792 type3 codes0..5 and type11 code0; no extension/padding ambiguity.
guestnet_error_rx:
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 32
    mov  qword [rsp], 0                  ; unique candidate, never first-match guess
    ; Nonzero unicast router/host source; not required to equal quoted remote.
    mov  eax, [r12 + 26]
    test eax, eax
    jz   .bad
    cmp  al, 224
    jae  .bad
    cmp  word [r12 + 38], 0              ; no RFC4884 extension length/profile
    jne  .bad
    lea  r13, [r12 + 42]                 ; quoted IPv4, no absent-payload reads
    cmp  byte [r13], 0x45
    jne  .bad
    test word [r13 + 6], 0xFFBF          ; only DF permitted, no fragments/options
    jnz  .bad
    movzx eax, word [r13 + 2]
    xchg al, ah
    cmp  eax, 28
    jb   .bad
    cmp  eax, 1500
    ja   .bad
    mov  [rsp + 8], eax                  ; quoted original declared length
    mov  edx, r14d
    sub  edx, 42
    cmp  edx, eax
    ja   .bad                            ; trailing extension/padding isn't a quote
    mov  [rsp + 12], edx                 ; available quote, at least28 by extent
    mov  eax, [r13 + 12]
    cmp  eax, [r12 + 30]                 ; quoted source is CURRENT physical host
    jne  .bad
    lea  rdi, [r13]
    mov  esi, 20
    call net_cksum16
    test ax, ax
    jnz  .bad
    cmp  byte [r12 + 34], 3
    jne  .unused
    cmp  byte [r12 + 35], 4
    jne  .unused
    test byte [r13 + 6], 0x40            ; fragmentation-needed describes DF work
    jz   .bad
    movzx eax, word [r12 + 40]
    xchg al, ah
    test eax, eax
    jz   .protocol                       ; RFC1191 old router, unknown MTU=0
    cmp  eax, 68
    jb   .bad
    cmp  eax, [rsp + 8]
    jae  .bad                            ; a useful MTU is below the original size
    jmp  .protocol
.unused:
    cmp  word [r12 + 40], 0
    jne  .bad
.protocol:
    cmp  byte [r13 + 9], 17
    je   .udp
    cmp  byte [r13 + 9], 1
    je   .echo
    cmp  byte [r13 + 9], 6
    jne  .bad
    cmp  dword [rsp + 8], 40             ; valid complete original TCP minimum
    jb   .bad
    cmp  dword [rsp + 12], 37            ; half a quoted TCP checksum is ambiguous
    je   .bad
    jmp  .clock
.udp:
    movzx eax, word [r13 + 24]
    xchg al, ah
    add  eax, 20
    cmp  eax, [rsp + 8]
    jne  .bad
    jmp  .clock
.echo:
    cmp  word [r13 + 20], 8              ; only original code0 echo request
    jne  .bad
.clock:
    call time_monotonic_now_us
    test rax, rax
    jz   .bad
    cmp  rax, [rel guestnet_nat_clock_seen]
    jb   .bad
    mov  rdx, rax
    add  rdx, GN_ER_IDLE_US
    jc   .bad
    mov  r15, rax                        ; observation is deliberately read-only
    lea  rbx, [rel guestnet_error_table]
    mov  dword [rsp + 16], GN_ER_SLOTS
.scan:
    cmp  byte [rbx], 1
    jne  .next
    mov  eax, [rel hv_linux_start_consumed]
    cmp  eax, [rbx + GN_ER_SESSION]
    jne  .next
    mov  rax, [rel guestnet_ring_epoch]
    cmp  rax, [rbx + GN_ER_EPOCH]
    jne  .next
    mov  rax, [rbx + GN_ER_AT]
    test rax, rax
    jz   .next
    cmp  rax, r15
    ja   .next
    mov  rdx, r15
    sub  rdx, rax
    cmp  rdx, GN_ER_IDLE_US
    jae  .next
    mov  eax, [rsp + 8]
    cmp  eax, [rbx + GN_ER_LEN]
    jne  .next
    mov  rax, [r13]
    cmp  rax, [rbx + GN_ER_IP]
    jne  .next
    mov  al, [r13 + 8]
    cmp  al, [rbx + GN_ER_IP + 8]         ; routers may only lower the quoted TTL
    ja   .next
    mov  al, [r13 + 9]
    cmp  al, [rbx + GN_ER_IP + 9]
    jne  .next
    lea  rsi, [r13 + 12]
    lea  rdi, [rbx + GN_ER_IP + 12]
    mov  ecx, [rsp + 12]
    sub  ecx, 12
    repe cmpsb                           ; all present immutable bytes, not just ports
    jne  .next
    call guestnet_error_live
    test eax, eax
    jz   .next
    cmp  qword [rsp], 0
    jne  .bad                            ; ambiguous accepted quotes cannot choose owner
    mov  [rsp], rbx
.next:
    add  rbx, GN_ER_SIZE
    dec  dword [rsp + 16]
    jnz  .scan
    mov  rbx, [rsp]
    test rbx, rbx
    jz   .bad
    ; All refusal checks precede the first shared scratch write.
    lea  rdi, [rel guestnet_nat_rx_frame_buf]
    mov  rsi, r12
    mov  ecx, r14d
    rep  movsb
    lea  rdi, [rel guestnet_nat_rx_frame_buf]
    mov  dword [rdi], 0x50005452
    mov  word [rdi + 4], 0x4F61
    call guestnet_put_gateway_mac
    mov  dword [rdi + 30], GN_GUEST_IP
    dec  byte [rdi + 22]
    mov  dword [rdi + 54], GN_GUEST_IP    ; quoted source
    mov  ax, [rbx + GN_ER_GPORT]
    cmp  byte [rdi + 51], 1
    je   .restore_echo
    mov  [rdi + 62], ax                  ; quoted original source port
    cmp  byte [rdi + 51], 17
    je   .restore_udp
    cmp  dword [rsp + 12], 38
    jb   .quoted_ip                      ; standard TCP quote has no checksum field
    mov  ax, [rbx + GN_ER_CKSUM]
    mov  [rdi + 78], ax                  ; restore known original, no absent body sum
    jmp  .quoted_ip
.restore_udp:
    mov  ax, [rbx + GN_ER_CKSUM]
    mov  [rdi + 68], ax
    jmp  .quoted_ip
.restore_echo:
    mov  [rdi + 66], ax
    mov  ax, [rbx + GN_ER_CKSUM]
    mov  [rdi + 64], ax
.quoted_ip:
    mov  word [rdi + 52], 0
    lea  rdi, [rdi + 42]
    mov  esi, 20
    call net_cksum16
    lea  rdi, [rel guestnet_nat_rx_frame_buf]
    mov  [rdi + 52], ah
    mov  [rdi + 53], al
    call guestnet_icmp_checksums          ; complete outer ICMP and IPv4 only
    lea  rsi, [rel guestnet_nat_rx_frame_buf]
    mov  edx, r14d
    call guestnet_rx_deliver
    test eax, eax
    jz   .owned
    inc  dword [rel guestnet_nat_returned]
.owned:
    mov  eax, 1                          ; queue refusal earns no state refresh
    jmp  .out
.bad:
    xor  eax, eax
.out:
    add  rsp, 32
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; bee023-proven TCP pseudo-header checksum, adapted to the common tuple guard.
; RDI=eth+IPv4(no options)+TCP frame with [frame+50] zeroed. The caller has
; already bounded the frame; a malformed segment leaves checksum zero and
; cannot obtain a NAT-owned reply. The scratch is private to this serial NAT
; path and never aliases the guest's virtio RX/TX buffers.
guestnet_tcp_cksum:
    push rbx
    push rcx
    push rsi
    push rdi
    push r8
    mov  rbx, rdi
    movzx r8d, byte [rbx + 16]
    shl  r8d, 8
    mov  r8b, [rbx + 17]
    sub  r8d, 20
    js   .done
    cmp  r8d, GN_FRAME_MAX - 12
    ja   .done
    cmp  r8d, 20                           ; TCP minimum header
    jb   .done
    lea  rdi, [rel guestnet_tcp_cksum_buf]
    mov  eax, [rbx + 26]
    mov  [rdi], eax
    mov  eax, [rbx + 30]
    mov  [rdi + 4], eax
    mov  byte [rdi + 8], 0
    mov  byte [rdi + 9], 6
    mov  eax, r8d
    mov  [rdi + 10], ah
    mov  [rdi + 11], al
    lea  rdi, [rel guestnet_tcp_cksum_buf + 12]
    lea  rsi, [rbx + 34]
    mov  ecx, r8d
    rep  movsb
    lea  rdi, [rel guestnet_tcp_cksum_buf]
    mov  esi, r8d
    add  esi, 12
    call net_cksum16
    mov  [rbx + 50], ah
    mov  [rbx + 51], al
.done:
    pop  r8
    pop  rdi
    pop  rsi
    pop  rcx
    pop  rbx
    ret

; EDI=target IPv4. Broadcast a canonical ARP who-has from the selected host IP.
guestnet_send_host_arp:
    cld
    push rbx
    mov  ebx, edi
    call arp_pending_note                ; SEC-S7a: EDI = the host-side next hop asked for
    mov  edi, ebx
    call guestnet_host_source_ip
    test eax, eax
    jz   .done
    lea  rdi, [rel guestnet_host_arp]
    mov  dword [rdi], 0xFFFFFFFF
    mov  word [rdi + 4], 0xFFFF
    mov  eax, [rel udp_our_mac]
    mov  [rdi + 6], eax
    mov  ax, [rel udp_our_mac + 4]
    mov  [rdi + 10], ax
    mov  word [rdi + 12], 0x0608
    mov  word [rdi + 14], 0x0100
    mov  word [rdi + 16], 0x0008
    mov  byte [rdi + 18], 6
    mov  byte [rdi + 19], 4
    mov  word [rdi + 20], 0x0100
    mov  eax, [rel udp_our_mac]
    mov  [rdi + 22], eax
    mov  ax, [rel udp_our_mac + 4]
    mov  [rdi + 26], ax
    call guestnet_host_source_ip
    mov  [rdi + 28], eax
    mov  qword [rdi + 32], 0
    mov  [rdi + 38], ebx
    lea  rdi, [rdi + 42]
    xor  eax, eax
    mov  ecx, 18
    rep  stosb
    lea  rsi, [rel guestnet_host_arp]
    mov  edx, 60
    call netdev_tx
.done:
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; Reply formatting.
; ---------------------------------------------------------------------------
; Keep the GUESTNET disposition scoped to a GUESTNET request. The loader owns
; load_err; this projection only turns its live result into an earned state.
guestnet_refresh_launch_state:
    ; STAT still renders the retained state; sampling cannot mutate a paused
    ; session. Loader failure remains an independent owner-change refusal.
    HV_POWER_CHECK hv_guest_power_admit, .done
    cmp  byte [rel guestnet_launch_state], GN_LAUNCH_NONE
    je   .done
    cmp  byte [rel guestnet_launch_state], GN_LAUNCH_REFUSED
    je   .done                              ; terminal GUESTNET verdict is retained
    mov  eax, [rel guestnet_launch_gen]
    test eax, eax
    jz   .superseded
    cmp  eax, [rel hv_linux_start_gen]
    jne  .superseded
    cmp  byte [rel guestnet_launch_state], GN_LAUNCH_REQUESTED
    jne  .consumed
    cmp  eax, [rel hv_linux_start_consumed]
    jne  .done                              ; task has not accepted this generation yet
.consumed:
    cmp  eax, [rel hv_linux_start_consumed]
    jne  .superseded
    jmp  .sample
.superseded:
    mov  byte [rel guestnet_launch_err], GN_LAUNCH_OWNER_CHANGED
    jmp  .refuse_local
.sample:
    mov  al, [rel hv_linux_load_err]
    mov  [rel guestnet_launch_err], al
    test al, al
    jne  .refused
    cmp  byte [rel hv_linux_running], 1
    jne  .done
    mov  byte [rel guestnet_launch_state], GN_LAUNCH_ACHIEVED
    ret
.refused:
.refuse_local:
    mov  byte [rel guestnet_launch_state], GN_LAUNCH_REFUSED
    mov  byte [rel guestnet_active], 0
    mov  byte [rel guestnet_nat_up], 0
    mov  byte [rel guestnet_dhcp_inject_pending], 0
.done:
    ret

guestnet_render_stat:
    call guestnet_refresh_launch_state
    call guestnet_out_reset
    lea  rdi, [rel str_gn_line]
    call guestnet_out_str
    mov  eax, [rel guestnet_lease_ip]
    call guestnet_out_ip
    lea  rdi, [rel str_gn_nat]
    call guestnet_out_str
    cmp  byte [rel guestnet_nat_up], 1
    jne  .nat_down
    lea  rdi, [rel str_gn_up]
    call guestnet_out_str
    jmp  .counters
.nat_down:
    lea  rdi, [rel str_gn_down]
    call guestnet_out_str
.counters:
    lea  rdi, [rel str_gn_launch]
    call guestnet_out_str
    movzx eax, byte [rel guestnet_launch_state]
    cmp  eax, GN_LAUNCH_REQUESTED
    je   .launch_requested
    cmp  eax, GN_LAUNCH_ACHIEVED
    je   .launch_achieved
    cmp  eax, GN_LAUNCH_REFUSED
    je   .launch_refused
    lea  rdi, [rel str_gn_launch_none]
    jmp  .launch_emit
.launch_requested:
    lea  rdi, [rel str_gn_launch_requested]
    jmp  .launch_emit
.launch_achieved:
    lea  rdi, [rel str_gn_launch_achieved]
    jmp  .launch_emit
.launch_refused:
    lea  rdi, [rel str_gn_launch_refused]
.launch_emit:
    call guestnet_out_str
    lea  rdi, [rel str_gn_load_err]
    call guestnet_out_str
    movzx eax, byte [rel guestnet_launch_err]
    call guestnet_out_dec
    lea  rdi, [rel str_gn_load_reason]
    call guestnet_out_str
    movzx eax, byte [rel guestnet_launch_err]
    cmp  eax, 1
    je   .reason_host
    cmp  eax, 2
    je   .reason_memory
    cmp  eax, 3
    je   .reason_bz_bad
    cmp  eax, 4
    je   .reason_bz_read
    cmp  eax, 5
    je   .reason_initrd
    cmp  eax, 6
    je   .reason_vmlaunch
    cmp  eax, 7
    je   .reason_vmexit
    cmp  eax, 8
    je   .reason_budget
    cmp  eax, 9
    je   .reason_spawn
    cmp  eax, GN_LAUNCH_OWNER_CHANGED
    je   .reason_owner
    cmp  eax, GN_LAUNCH_UNPUBLISHED
    je   .reason_request
    test eax, eax
    jnz  .reason_unknown
    cmp  byte [rel guestnet_launch_state], GN_LAUNCH_REQUESTED
    je   .reason_pending
    cmp  byte [rel guestnet_launch_state], GN_LAUNCH_ACHIEVED
    je   .reason_none
    lea  rdi, [rel str_gn_reason_not_requested]
    jmp  .reason_emit
.reason_host:
    lea  rdi, [rel str_gn_reason_host]
    jmp  .reason_emit
.reason_memory:
    lea  rdi, [rel str_gn_reason_memory]
    jmp  .reason_emit
.reason_bz_bad:
    lea  rdi, [rel str_gn_reason_bz_bad]
    jmp  .reason_emit
.reason_bz_read:
    lea  rdi, [rel str_gn_reason_bz_read]
    jmp  .reason_emit
.reason_initrd:
    lea  rdi, [rel str_gn_reason_initrd]
    jmp  .reason_emit
.reason_vmlaunch:
    lea  rdi, [rel str_gn_reason_vmlaunch]
    jmp  .reason_emit
.reason_vmexit:
    lea  rdi, [rel str_gn_reason_vmexit]
    jmp  .reason_emit
.reason_budget:
    lea  rdi, [rel str_gn_reason_budget]
    jmp  .reason_emit
.reason_spawn:
    lea  rdi, [rel str_gn_reason_spawn]
    jmp  .reason_emit
.reason_owner:
    lea  rdi, [rel str_gn_reason_owner]
    jmp  .reason_emit
.reason_request:
    lea  rdi, [rel str_gn_reason_request]
    jmp  .reason_emit
.reason_pending:
    lea  rdi, [rel str_gn_reason_pending]
    jmp  .reason_emit
.reason_none:
    lea  rdi, [rel str_gn_reason_none]
    jmp  .reason_emit
.reason_unknown:
    lea  rdi, [rel str_gn_reason_unknown]
.reason_emit:
    call guestnet_out_str
    lea  rdi, [rel str_gn_shell_ready]
    call guestnet_out_str
    movzx eax, byte [rel guestnet_shell_ready]
    call guestnet_out_dec
    lea  rdi, [rel str_gn_shell_probes]
    call guestnet_out_str
    movzx eax, byte [rel guestnet_shell_probe_tries]
    call guestnet_out_dec
    lea  rdi, [rel str_gn_dhcp_injected]
    call guestnet_out_str
    movzx eax, byte [rel guestnet_dhcp_injected]
    call guestnet_out_dec
    lea  rdi, [rel str_gn_tx]
    call guestnet_out_str
    mov  eax, [rel guestnet_guest_tx_packets]
    call guestnet_out_dec
    lea  rdi, [rel str_gn_fwd]
    call guestnet_out_str
    mov  eax, [rel guestnet_nat_forwarded]
    call guestnet_out_dec
    lea  rdi, [rel str_gn_ret]
    call guestnet_out_str
    mov  eax, [rel guestnet_nat_returned]
    call guestnet_out_dec
    lea  rdi, [rel str_gn_ipv4]
    call guestnet_out_str
    mov  eax, [rel guestnet_ipv4_packets]
    call guestnet_out_dec
    lea  rdi, [rel str_gn_udp]
    call guestnet_out_str
    mov  eax, [rel guestnet_udp_packets]
    call guestnet_out_dec
    lea  rdi, [rel str_gn_dhcp]
    call guestnet_out_str
    mov  eax, [rel guestnet_dhcp_packets]
    call guestnet_out_dec
    lea  rdi, [rel str_gn_disc]
    call guestnet_out_str
    mov  eax, [rel guestnet_dhcp_discover]
    call guestnet_out_dec
    lea  rdi, [rel str_gn_req]
    call guestnet_out_str
    mov  eax, [rel guestnet_dhcp_request]
    call guestnet_out_dec
    lea  rdi, [rel str_gn_tag]
    call guestnet_out_str
    mov  eax, [rel guestnet_dhcp_tagged]
    call guestnet_out_dec
    lea  rdi, [rel str_gn_reply]
    call guestnet_out_str
    mov  eax, [rel guestnet_dhcp_replies]
    call guestnet_out_dec
    lea  rdi, [rel str_gn_attempt]
    call guestnet_out_str
    mov  eax, [rel guestnet_dhcp_reply_attempts]
    call guestnet_out_dec
    lea  rdi, [rel str_gn_nobuf]
    call guestnet_out_str
    mov  eax, [rel guestnet_rx_nobuf]
    call guestnet_out_dec
    lea  rdi, [rel str_gn_flen]
    call guestnet_out_str
    mov  eax, [rel guestnet_last_frame_len]
    call guestnet_out_dec
    lea  rdi, [rel str_gn_l210]
    call guestnet_out_str
    mov  eax, [rel guestnet_last_l2_at_10]
    call guestnet_out_dec
    lea  rdi, [rel str_gn_l212]
    call guestnet_out_str
    mov  eax, [rel guestnet_last_l2_at_12]
    call guestnet_out_dec
    lea  rdi, [rel str_gn_running]
    call guestnet_out_str
    movzx eax, byte [rel hv_linux_running]
    call guestnet_out_dec
    ret

guestnet_out_reset:
    lea  rax, [rel guestnet_out_buf]
    mov  [rel guestnet_out_cur], rax
    mov  byte [rax], 0
    ret

guestnet_out_str:
    mov  rsi, [rel guestnet_out_cur]
    lea  rdx, [rel guestnet_out_buf + 511]
.copy:
    cmp  rsi, rdx
    jae  .done
    mov  al, [rdi]
    test al, al
    jz   .done
    mov  [rsi], al
    inc  rsi
    inc  rdi
    jmp  .copy
.done:
    mov  byte [rsi], 0
    mov  [rel guestnet_out_cur], rsi
    ret

guestnet_out_dec:
    push rbx
    push r12
    mov  ebx, eax
    lea  r12, [rel guestnet_dec_buf + 15]
    mov  byte [r12], 0
    test ebx, ebx
    jnz  .digits
    dec  r12
    mov  byte [r12], '0'
    jmp  .emit
.digits:
    mov  eax, ebx
.loop:
    xor  edx, edx
    mov  ecx, 10
    div  ecx
    add  dl, '0'
    dec  r12
    mov  [r12], dl
    test eax, eax
    jnz  .loop
.emit:
    mov  rdi, r12
    call guestnet_out_str
    pop  r12
    pop  rbx
    ret

guestnet_out_ip:
    push rbx
    push r12
    mov  ebx, eax
    xor  r12d, r12d
.octet:
    mov  eax, ebx
    mov  ecx, r12d
    shl  ecx, 3
    shr  eax, cl
    and  eax, 0xFF
    call guestnet_out_dec
    inc  r12d
    cmp  r12d, 4
    jae  .done
    lea  rdi, [rel str_gn_dot]
    call guestnet_out_str
    jmp  .octet
.done:
    pop  r12
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; Writable state and bounded buffers.
; ---------------------------------------------------------------------------
align 8
guestnet_q_desc:       times 2 dq 0
guestnet_q_avail:      times 2 dq 0
guestnet_q_used:       times 2 dq 0
guestnet_ingress_dec_buf: times 32 db 0
guestnet_ingress_slot: dd 0              ; slot+1; zero means no ingress grant
guestnet_ingress_gen: dd 0
guestnet_ingress_host: dd 0
guestnet_ingress_peer: dd 0
guestnet_ingress_port: dw 0
guestnet_ingress_peerport: dw 0
align 8
guestnet_ingress_deadline: dq 0
guestnet_ingress_ring: dq 0
guestnet_ingress_console: dq 0
guestnet_ingress_owner: dq 0
guestnet_ring_epoch:   dq 0              ; ring/reset/detach/rebind ownership
guestnet_domain_ctx:   dq 0
guestnet_out_cur:      dq 0
guestnet_cmd_cur:      dq 0
guestnet_qsel:         dd 0
guestnet_dfsel:        dd 0
guestnet_drvfsel:      dd 0
guestnet_drvfeat:      times 2 dd 0
guestnet_feat_bad:     db 0
align 4
guestnet_status:       dd 0
guestnet_isr:          dd 0
guestnet_q_num:        times 2 dd 0
guestnet_mmio_writes:  dd 0
guestnet_notify_count: dd 0
guestnet_irq_count:    dd 0
guestnet_guest_tx_packets: dd 0
align 8
guestnet_tx_used_advance: dq 0
guestnet_tx_backpressure: dq 0
guestnet_nat_forwarded: dd 0
guestnet_nat_returned: dd 0
guestnet_dhcp_replies: dd 0
guestnet_ipv4_packets: dd 0
guestnet_udp_packets: dd 0
guestnet_dhcp_packets: dd 0
guestnet_dhcp_discover: dd 0
guestnet_dhcp_request: dd 0
guestnet_dhcp_tagged: dd 0
guestnet_dhcp_reply_attempts: dd 0
guestnet_rx_nobuf:    dd 0
guestnet_last_frame_len: dd 0
guestnet_last_l2_at_10: dd 0
guestnet_last_l2_at_12: dd 0
guestnet_lease_ip:     dd 0
guestnet_nat_next:     dd 0
; Dedicated NAT range: native fixed listeners are below 40000, native dynamic
; clients start at 49152 (DNS/SSH/TLS/backup/NTP). Never recycle these serials.
guestnet_nat_port_next: dd GN_NAT_PORT_BASE
align 8
guestnet_ttl_clock_seen: dq 0
guestnet_ttl_next_us: dq 0
guestnet_error_next: dd 0
align 8
guestnet_error_table: times (GN_ER_SLOTS * GN_ER_SIZE) db 0
guestnet_icmp_id_next: dd GN_IC_ID_BASE
align 8
guestnet_icmp_table: times (GN_IC_SLOTS * GN_IC_SIZE) db 0
guestnet_nat_clock_seen: dq 0
; Legacy private name: accepted-forward timestamp for both TCP and UDP.
guestnet_nat_udp_last: times GN_NAT_SLOTS dq 0
guestnet_nat_tcp_reserved: times GN_NAT_SLOTS dq 0
guestnet_nat_tcp_fin: times GN_NAT_SLOTS dq 0
guestnet_launch_gen:   dd 0
guestnet_q_lastav:     times 2 dw 0
guestnet_q_usedidx:    times 2 dw 0
guestnet_q_ready:      times 2 db 0
guestnet_net_up:       db 0
guestnet_driver_ok:    db 0
guestnet_irq_pending:  db 0
guestnet_irq_injected: db 0
guestnet_tx_retry_pending: db 0
align 4
guestnet_tx_budget:     dd 0                ; SEC-D5: descriptors left in this guestnet_serve_tx call
guestnet_active:       db 0
guestnet_launch_state: db 0
guestnet_launch_err:   db 0
guestnet_nat_up:       db 0
guestnet_arp_seen:     db 0
guestnet_marker_virtio: db 0
guestnet_marker_dhcp:  db 0
guestnet_dhcp_inject_pending: db 0
guestnet_dhcp_injected: db 0
guestnet_shell_ready: db 0
guestnet_shell_probe_pending: db 0
guestnet_shell_probe_tries: db 0
align 4
guestnet_shell_match: dd GN_SHELL_DROP
guestnet_shell_probe_gen: dd 0
align 8
guestnet_shell_probe_epoch: dq 0
guestnet_shell_probe_due_ms: dq 0
guestnet_shell_serial: dq 0                ; never cleared by reset/STOP/START
guestnet_shell_reply: times GN_SHELL_REPLY_LEN db 0
guestnet_shell_command: times GN_SHELL_CMD_LEN + 1 db 0
guestnet_pending_cmd_ready: db 0
guestnet_out_ready:    db 0
guestnet_build_physical: db 0
guestnet_cmd_overflow: db 0

align 8
guestnet_nat_table:    times GN_NAT_SLOTS * GN_N_SIZE db 0
guestnet_txbuf:        times GN_TXBUF_MAX db 0
guestnet_frame:        times 384 db 0
guestnet_nat_tx_buf:   times GN_FRAME_MAX db 0
guestnet_nat_rx_frame_buf: times GN_FRAME_MAX db 0
guestnet_tcp_cksum_buf: times GN_FRAME_MAX db 0
guestnet_host_arp:     times 60 db 0
guestnet_pending_cmd:  times 256 db 0
guestnet_nonce_text:   times 64 db 0
guestnet_ip_text:      times 16 db 0
guestnet_port_text:    times 6 db 0
guestnet_out_buf:      times 512 db 0
guestnet_dec_buf:      times 16 db 0

; Static strings are addresses only via LEA at runtime (never baked dq pointers).
str_gn_verb:         db "GUESTNET", 0
str_gn_start:        db "START", 0
str_gn_stat:         db "STAT", 0
str_gn_nonce:        db "NONCE", 0
str_gn_stop:         db "STOP", 0
str_gn_usage:        db " GUESTNET ERR usage=START|STAT|NONCE|STOP", 0
%ifdef RCQ37_MEDIA_PROFILE
%if RCQ37_MEDIA_PROFILE
str_gn_media_busy:   db " GUESTNET ERR busy=media_guest", 0
%endif
%endif
str_gn_nonce_queued: db " GUESTNET nonce=queued", 0
str_gn_nonce_bad:    db " GUESTNET ERR invalid_nonce_args", 0
str_gn_stopping:     db " stopping=1", 0
str_gn_not_stopping: db " stopping=0", 0
str_gn_owner_busy:   db " GUESTNET ERR guest_owner_busy", 0
str_gn_reason_owner: db "owner_changed", 0
str_gn_reason_request: db "request_not_published", 0
str_gn_line:         db " GUESTNET lease=", 0
str_gn_nat:          db " nat=", 0
str_gn_up:           db "up", 0
str_gn_down:         db "down", 0
str_gn_launch:       db " launch=", 0
str_gn_launch_none:  db "none", 0
str_gn_launch_requested: db "requested", 0
str_gn_launch_achieved: db "achieved", 0
str_gn_launch_refused: db "refused", 0
str_gn_load_err:     db " load_err=", 0
str_gn_load_reason:  db " load_reason=", 0
str_gn_shell_ready: db " shell_ready=", 0
str_gn_shell_probes: db " shell_probes=", 0
str_gn_dhcp_injected: db " dhcp_injected=", 0
str_gn_reason_not_requested: db "not_requested", 0
str_gn_reason_pending: db "pending", 0
str_gn_reason_none:  db "none", 0
str_gn_reason_host:  db "host_state_or_vmx_refused", 0
str_gn_reason_memory: db "guest_memory_region_unavailable", 0
str_gn_reason_bz_bad: db "BZIMAGE2_missing_or_malformed", 0
str_gn_reason_bz_read: db "BZIMAGE2_read_failed", 0
str_gn_reason_initrd: db "INITRD2.GZ_missing_malformed_or_read_failed", 0
str_gn_reason_vmlaunch: db "vmlaunch_failed", 0
str_gn_reason_vmexit: db "vmexit_or_vmwrite_failed", 0
str_gn_reason_budget: db "boot_budget_exceeded", 0
str_gn_reason_spawn: db "guest_task_spawn_failed", 0
str_gn_reason_unknown: db "unknown", 0
str_gn_tx:           db " guest_tx_packets=", 0
str_gn_ports:        db " guest_nat_ports_left=", 0
str_gn_fwd:          db " nat_forwarded=", 0
str_gn_ret:          db " nat_returned=", 0
str_gn_ipv4:         db " ipv4=", 0
str_gn_udp:          db " udp=", 0
str_gn_dhcp:         db " dhcp=", 0
str_gn_disc:         db " discover=", 0
str_gn_req:          db " request=", 0
str_gn_tag:          db " tagged=", 0
str_gn_reply:        db " replies=", 0
str_gn_attempt:      db " reply_attempts=", 0
str_gn_nobuf:        db " rx_nobuf=", 0
str_gn_flen:         db " frame_len=", 0
str_gn_l210:         db " l2_at_10=", 0
str_gn_l212:         db " l2_at_12=", 0
str_gn_running:      db " running=", 0
str_gn_dot:          db ".", 0
str_gn_space:        db " ", 0
str_gn_cmd_pre:      db "/bin/paos-udp-send ", 0
str_gn_cmd_mid:      db " ", 0
; Stay within the bounded 256-byte console command. The explicit tokens are
; consumed by the streaming host latch; a ping return code or lease alone
; cannot earn the gateway-ARP and physical-wire gates.
str_gn_physical_pre: db "G=$(/bin/ip r|/bin/sed -n 's/default via \([^ ]*\).*/\1/p');[ $G ]&&/bin/ping -c1 -W2 $G&&/bin/ip n s $G|/bin/busybox grep -q lladdr&&echo PAOS_DDOM_ARP_OK;", 0
str_gn_physical_post: db ";echo PAOS_DDOM_SENT_RC=$?", 0
; The staged Ubuntu BusyBox 1.36.1 build has no udhcpc -H switch.  Its portable
; option-injection contract is -x OPT:VAL; keeping the hostname tag in option 12
; lets the host distinguish this shell-ready renewal from init-time DHCP.
str_gn_dhcp_command: db "/bin/busybox ip addr flush dev eth0; /bin/busybox udhcpc -i eth0 -n -q -t 8 -T 2 -x hostname:paos-guestnet -s /etc/udhcpc.script", 0
str_gn_shell_probe: db "/bin/busybox printf '"
str_gn_shell_ack: db "PAOS-GN-READY-"
str_gn_shell_hex: db "0123456789abcdef"
str_gn_marker_vio:   db "[PAOS64] guest virtio-net negotiated [guest.net.virtio.up]", 13, 10, 0
str_gn_marker_dhcp:  db "[PAOS64] guest DHCP ACK leased 10.0.2.15 [guest.net.dhcp.leased]", 13, 10, 0
str_gn_udp_vio:      db " [guest.net.virtio.up]", 0
str_gn_udp_dhcp:     db " [guest.net.dhcp.leased]", 0

str_gn_ssh_verb: db "GUESTSSH",0
str_gn_ssh_stat: db "STAT",0
str_gn_ssh_cancel: db "CANCEL",0
str_gn_ssh_open: db "OPEN",0
str_gn_ssh_line: db " GUESTSSH gen=",0
str_gn_ssh_ring: db " ring=",0
str_gn_ssh_console: db " console=",0
str_gn_ssh_owner: db " owner_epoch=",0
str_gn_ssh_port: db " port=",0
str_gn_ssh_deadline: db " deadline_us=",0
str_gn_ssh_denied: db " GUESTSSH ERR owner_required",0
str_gn_ssh_bad: db " GUESTSSH ERR invalid_or_unavailable",0
str_gn_ssh_peer: db " peer=",0
str_gn_ssh_peerport: db " peer_port=",0
str_gn_ssh_host: db " guest_port=22 host=",0
