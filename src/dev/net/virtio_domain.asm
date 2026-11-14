;; MODULE dev/net/virtio_domain
;; LAYER 3
;; EXPORTS virtio_domain_ops, virtio_domain_selected_census, virtio_domain_static_policy, virtio_domain_policy_generation, virtio_domain_dhcp_start, virtio_domain_create, virtio_domain_mode_status, virtio_domain_selftest, virtio_domain_register_verb, virtio_domain_autoboot_tick, virtio_domain_transport_pump, virtio_domain_guest_rx_publish, virtio_domain_guest_rx_can_accept, virtio_domain_is_handle, virtio_domain_note_dhcp, virtio_domain_note_arp, virtio_domain_gateway_resolution_start, virtio_domain_guest_progress, virtio_domain_service_health, virtio_domain_gateway_resolution_tick, virtio_domain_status_line, virtio_domain_frame_stats, virtio_domain_reply_retire
;; IMPORTS net/netdev, net/dhcp, hv/hv_ops, hv/vmx, hv/guestnet, hv/vtd, core/lib/mem, core/time, boot/serial
;; CAPS
;; OWNER saga:domain_backend_seam
; ============================================================================
; virtio_domain.asm — Linux-driver-domain backend for the ordinary netdev_ops
; class seam. The backend transports raw Ethernet frames over two bounded
; shared rings; it never imports a native NIC global or exposes guest details to
; the IP stack. A real driver-domain transport can replace the fake guest/ring
; handles without changing the struct dev header, vtable, or netdev core.
;
; Ring contract (one descriptor per direction in v1): the producer copies data
; and length, executes SFENCE, then transfers .owner and publishes .count=1.
; The consumer observes .count/.owner, executes LFENCE, consumes the bytes, and
; returns ownership. Full means -1/again immediately; there is no wait loop.
; ============================================================================

DOMAIN_MODE_TRANSPARENT_L2 equ 0
DOMAIN_MODE_L3_RELAY       equ 1

DOMAIN_LIFE_NO_GUEST       equ 0
DOMAIN_LIFE_READY          equ 1
DOMAIN_LIFE_RUNNING        equ 2
DOMAIN_LIFE_STOPPED        equ 3

DOMAIN_OWNER_HOST          equ 0
DOMAIN_OWNER_GUEST         equ 1

DOMAIN_FRAME_MIN           equ 14
DOMAIN_FRAME_MAX           equ 1514
DOMAIN_RING_DEPTH          equ 1
DOMAIN_UNIMPLEMENTED       equ -2
DOMAIN_PUBLISH_FULL        equ -2
DOMAIN_AUTOBOOT_GRACE_MS   equ 30000
DOMAIN_ARP_RETRY_MS        equ 1000

; DEVICE_SLOT.md section 6.1's seven additive N-ary hooks. The KAT requires
; every bit to be earned by a live operation before it prints hooks=7.
DOMAIN_HOOK_TABLE          equ (1 << 0)
DOMAIN_HOOK_HANDLE         equ (1 << 1)
DOMAIN_HOOK_EGRESS         equ (1 << 2)
DOMAIN_HOOK_ROUTE          equ (1 << 3)
DOMAIN_HOOK_POLICY         equ (1 << 4)
DOMAIN_HOOK_INSTRUMENT     equ (1 << 5)
DOMAIN_HOOK_AFFINITY       equ (1 << 6)
DOMAIN_HOOK_ALL            equ 0x7f

struc domain_ring
  .producer: resq 1              ; monotonically increasing producer sequence
  .consumer: resq 1              ; monotonically increasing consumer sequence
  .count:    resd 1              ; 0 empty / 1 full (bounded v1 depth)
  .owner:    resd 1              ; DOMAIN_OWNER_* allowed to touch the payload
  .len:      resd 1
  .reserved: resd 1
  .data:     resb DOMAIN_FRAME_MAX
endstruc

; The uniform dev header is deliberately first: a virtio_domain_ctx* IS the
; struct dev* handed to the class core. Everything after it is backend-private.
struc virtio_domain_ctx
  .devhdr:         resb dev_size
  .tx_ring:        resq 1
  .rx_ring:        resq 1
  .guest_handle:   resq 1
  .slot:           resq 1
  .affinity_tag:   resq 1
  .route_tag:      resq 1
  .tx_frames:      resq 1
  .rx_frames:      resq 1
  .tx_bytes:       resq 1
  .rx_bytes:       resq 1
  .route_lookups:  resq 1
  .policy_checks:  resq 1
  .guest_kicks:    resq 1
  .recoveries:     resq 1
  .mode:           resd 1
  .lifecycle:      resd 1
  .owner:          resd 1
  .hooks:          resd 1
endstruc

; Fill every runtime pointer with LEA. Static dq-symbol pointers are RVAs in
; this PE image and are not load-bias fixed up.
virtio_domain_build_common:
    lea  rdi, [rel virtio_domain_ops]
    lea  rax, [rel virtio_domain_init]
    mov  [rdi + netdev_ops.init], rax
    lea  rax, [rel virtio_domain_start]
    mov  [rdi + netdev_ops.start], rax
    lea  rax, [rel virtio_domain_stop]
    mov  [rdi + netdev_ops.stop], rax
    lea  rax, [rel virtio_domain_tx]
    mov  [rdi + netdev_ops.tx], rax
    lea  rax, [rel virtio_domain_rx_poll]
    mov  [rdi + netdev_ops.rx_poll], rax
    lea  rax, [rel virtio_domain_link_status]
    mov  [rdi + netdev_ops.link_status], rax
    lea  rax, [rel virtio_domain_get_mac]
    mov  [rdi + netdev_ops.get_mac], rax
    lea  rax, [rel virtio_domain_recover]
    mov  [rdi + netdev_ops.recover], rax

    lea  rax, [rel str_domain_name]
    mov  [rel virtio_domain_info + netdev_info.name], rax
    mov  dword [rel virtio_domain_info + netdev_info.mtu], 1500
    mov  byte [rel virtio_domain_info + netdev_info.dma_mask], 64
    mov  dword [rel virtio_domain_info + netdev_info.flags], 0
    mov  dword [rel virtio_domain_info + netdev_info.speed_caps], 0
    ret

; virtio_domain_create(RDI=ctx, RSI=tx_ring, RDX=rx_ring, RCX=guest_handle,
;                      R8D=mode, R9=name) -> RAX=netdev slot / -1.
; Registration succeeds even when the guest is absent; init then leaves the
; ordinary device handle honestly HEALTH_DEGRADED for bounded recovery later.
virtio_domain_create:
    push rbx
    push r12
    push r13
    push r14
    push r15
    push r9                              ; preserve runtime name across helpers
    mov  r12, rdi                        ; ctx
    mov  r13, rsi                        ; tx ring handle
    mov  r14, rdx                        ; rx ring handle
    mov  r15, rcx                        ; guest handle
    mov  ebx, r8d                        ; requested mode
    test r12, r12
    jz   .reject

    mov  rdi, r12
    xor  esi, esi
    mov  edx, virtio_domain_ctx_size
    call memset
    test r13, r13
    jz   .rx_clear
    mov  rdi, r13
    xor  esi, esi
    mov  edx, domain_ring_size
    call memset
.rx_clear:
    test r14, r14
    jz   .built
    mov  rdi, r14
    xor  esi, esi
    mov  edx, domain_ring_size
    call memset
.built:
    call virtio_domain_build_common

    lea  rax, [rel virtio_domain_ops]
    mov  [r12 + dev.ops], rax
    lea  rax, [rel virtio_domain_info]
    mov  [r12 + dev.info], rax
    mov  [r12 + dev.priv], r12
    mov  dword [r12 + dev.prio], PRIO_DOMAIN
    mov  dword [r12 + dev.health], HEALTH_DEGRADED
    mov  dword [r12 + dev.class], CLASS_NET
    mov  dword [r12 + dev.flags], 0
    mov  qword [r12 + dev.next], 0
    mov  rax, [rsp]
    mov  [r12 + dev.name], rax
    mov  [r12 + virtio_domain_ctx.tx_ring], r13
    mov  [r12 + virtio_domain_ctx.rx_ring], r14
    mov  [r12 + virtio_domain_ctx.guest_handle], r15
    mov  dword [r12 + virtio_domain_ctx.mode], ebx
    mov  dword [r12 + virtio_domain_ctx.lifecycle], DOMAIN_LIFE_NO_GUEST
    or   dword [r12 + dev.flags], NETDEV_F_ABSENT   ; no guest yet: 'absent', not a fault
    mov  dword [r12 + virtio_domain_ctx.owner], DOMAIN_OWNER_GUEST
    mov  dword [r12 + virtio_domain_ctx.hooks], DOMAIN_HOOK_HANDLE

    mov  rdi, r12
    call netdev_register                 ; the same API used by loopnet/e1000e
    test rax, rax
    js   .out
    mov  [r12 + virtio_domain_ctx.slot], rax
    or   dword [r12 + virtio_domain_ctx.hooks], DOMAIN_HOOK_TABLE
    mov  r15, rax                        ; registration success survives init
    mov  rdi, r12
    call virtio_domain_init
    test rax, rax
    jnz  .registered                     ; no guest/ring: registered + degraded
    mov  rdi, r12
    call virtio_domain_start
.registered:
    mov  rax, r15
    jmp  .out
.reject:
    mov  rax, -1
.out:
    add  rsp, 8
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; --- netdev_ops lifecycle ----------------------------------------------------
virtio_domain_init:
    test rdi, rdi
    jz   .fail
    cmp  qword [rdi + virtio_domain_ctx.guest_handle], 0
    je   .degraded
    mov  rax, [rdi + virtio_domain_ctx.tx_ring]
    test rax, rax
    jz   .degraded
    mov  rdx, [rdi + virtio_domain_ctx.rx_ring]
    test rdx, rdx
    jz   .degraded
    mov  qword [rax + domain_ring.producer], 0
    mov  qword [rax + domain_ring.consumer], 0
    mov  dword [rax + domain_ring.count], 0
    mov  dword [rax + domain_ring.len], 0
    mov  dword [rax + domain_ring.owner], DOMAIN_OWNER_HOST
    mov  qword [rdx + domain_ring.producer], 0
    mov  qword [rdx + domain_ring.consumer], 0
    mov  dword [rdx + domain_ring.count], 0
    mov  dword [rdx + domain_ring.len], 0
    mov  dword [rdx + domain_ring.owner], DOMAIN_OWNER_GUEST
    sfence
    mov  dword [rdi + virtio_domain_ctx.lifecycle], DOMAIN_LIFE_READY
    and  dword [rdi + dev.flags], ~NETDEV_F_ABSENT   ; a guest is attached
    mov  dword [rdi + dev.health], HEALTH_OK
    xor  eax, eax
    ret
.degraded:
    mov  dword [rdi + virtio_domain_ctx.lifecycle], DOMAIN_LIFE_NO_GUEST
    or   dword [rdi + dev.flags], NETDEV_F_ABSENT
    mov  dword [rdi + dev.health], HEALTH_DEGRADED
.fail:
    mov  rax, -1
    ret

virtio_domain_start:
    test rdi, rdi
    jz   .fail
    cmp  dword [rdi + virtio_domain_ctx.mode], DOMAIN_MODE_TRANSPARENT_L2
    jne  .mode_unimplemented
    cmp  dword [rdi + virtio_domain_ctx.lifecycle], DOMAIN_LIFE_READY
    jne  .fail
    mov  dword [rdi + virtio_domain_ctx.lifecycle], DOMAIN_LIFE_RUNNING
    mov  dword [rdi + dev.health], HEALTH_OK
    xor  eax, eax
    ret
.mode_unimplemented:
    mov  dword [rdi + dev.health], HEALTH_DEGRADED
    mov  rax, DOMAIN_UNIMPLEMENTED
    ret
.fail:
    mov  rax, -1
    ret

virtio_domain_stop:
    test rdi, rdi
    jz   .fail
    mov  dword [rdi + virtio_domain_ctx.lifecycle], DOMAIN_LIFE_STOPPED
    mov  rax, [rdi + virtio_domain_ctx.tx_ring]
    test rax, rax
    jz   .rx
    mov  dword [rax + domain_ring.count], 0
    mov  dword [rax + domain_ring.len], 0
    mov  dword [rax + domain_ring.owner], DOMAIN_OWNER_HOST
.rx:
    mov  rax, [rdi + virtio_domain_ctx.rx_ring]
    test rax, rax
    jz   .done
    mov  dword [rax + domain_ring.count], 0
    mov  dword [rax + domain_ring.len], 0
    mov  dword [rax + domain_ring.owner], DOMAIN_OWNER_GUEST
.done:
    sfence
    xor  eax, eax
    ret
.fail:
    mov  rax, -1
    ret

virtio_domain_recover:
    push r12
    mov  r12, rdi
    test r12, r12
    jz   .fail
    lock inc qword [r12 + virtio_domain_ctx.recoveries]
    mov  rdi, r12
    call virtio_domain_init
    test rax, rax
    jnz  .fail
    mov  rdi, r12
    call virtio_domain_start
    pop  r12
    ret
.fail:
    mov  rax, -1
    pop  r12
    ret

; --- the seven N-ary hooks used by the backend ------------------------------
virtio_domain_affinity_bind:
    test rdi, rdi
    jz   .fail
    test rsi, rsi
    jz   .fail
    mov  [rdi + virtio_domain_ctx.affinity_tag], rsi
    or   dword [rdi + virtio_domain_ctx.hooks], DOMAIN_HOOK_AFFINITY
    xor  eax, eax
    ret
.fail:
    mov  rax, -1
    ret

; Policy owns the hostile-frame bounds. It runs before route lookup or copy,
; so an oversize length cannot turn into an out-of-bounds read.
virtio_domain_policy:
    test rdi, rdi
    jz   .reject
    lock inc qword [rdi + virtio_domain_ctx.policy_checks]
    or   dword [rdi + virtio_domain_ctx.hooks], DOMAIN_HOOK_POLICY
    test rsi, rsi
    jz   .reject
    cmp  rdx, DOMAIN_FRAME_MIN
    jb   .reject
    cmp  rdx, DOMAIN_FRAME_MAX
    ja   .reject
    xor  eax, eax
    ret
.reject:
    mov  rax, -1
    ret

; v1 route lookup is degenerate-to-one but is a real, explicit step: retain the
; destination MAC as the route tag for later multi-address/policy expansion.
virtio_domain_route_lookup:
    test rdi, rdi
    jz   .fail
    lock inc qword [rdi + virtio_domain_ctx.route_lookups]
    or   dword [rdi + virtio_domain_ctx.hooks], DOMAIN_HOOK_ROUTE
    mov  rax, [rsi]
    mov  rdx, 0x0000ffffffffffff
    and  rax, rdx
    mov  [rdi + virtio_domain_ctx.route_tag], rax
    xor  eax, eax
    ret
.fail:
    mov  rax, -1
    ret

; --- netdev_ops data path ----------------------------------------------------
; BEGIN FRAME STATS -- pure registered-context readout, dev header first.
; The class core validates membership/ops/lifetime before this private seam.
virtio_domain_frame_stats:
    lea  rax, [rel virtio_domain_ops]
    cmp  [rdi + dev.ops], rax
    jne  .unavailable
    cmp  dword [rdi + virtio_domain_ctx.lifecycle], DOMAIN_LIFE_RUNNING
    jne  .unavailable
    mov  rdx, [rdi + virtio_domain_ctx.rx_frames]
    mov  rcx, [rdi + virtio_domain_ctx.tx_frames]
    xor  eax, eax
    ret
.unavailable:
    mov  rdx, -1
    mov  rcx, -1
    mov  eax, -1
    ret
; END FRAME STATS

virtio_domain_tx:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    lock inc qword [rel domain_reply_attempts]
    test r12, r12
    jz   .fail
    cmp  qword [r12 + virtio_domain_ctx.guest_handle], 0
    je   .degraded
    cmp  dword [r12 + virtio_domain_ctx.lifecycle], DOMAIN_LIFE_RUNNING
    jne  .fail
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, r14
    call virtio_domain_policy
    test rax, rax
    jnz  .fail
    mov  rdi, r12
    mov  rsi, r13
    mov  rdx, r14
    call virtio_domain_route_lookup
    test rax, rax
    jnz  .fail
    mov  rbx, [r12 + virtio_domain_ctx.tx_ring]
    test rbx, rbx
    jz   .degraded
    cmp  dword [rbx + domain_ring.count], DOMAIN_RING_DEPTH
    jae  .tx_full                        ; bounded -1/again, never wait
    cmp  dword [rbx + domain_ring.owner], DOMAIN_OWNER_HOST
    jne  .fail
    lea  rdi, [rbx + domain_ring.data]
    mov  rsi, r13
    mov  rdx, r14
    call memcpy
    mov  [rbx + domain_ring.len], r14d
    inc  qword [rbx + domain_ring.producer]
    sfence                               ; payload/len visible before ownership
    mov  dword [rbx + domain_ring.owner], DOMAIN_OWNER_GUEST
    mov  dword [rbx + domain_ring.count], DOMAIN_RING_DEPTH
    lock inc qword [r12 + virtio_domain_ctx.tx_frames]
    lock add qword [r12 + virtio_domain_ctx.tx_bytes], r14
    lock inc qword [rel domain_reply_accepted]
    or   dword [r12 + virtio_domain_ctx.hooks], DOMAIN_HOOK_INSTRUMENT
    xor  eax, eax
    jmp  .out
.degraded:
    mov  dword [r12 + virtio_domain_ctx.lifecycle], DOMAIN_LIFE_NO_GUEST
    or   dword [r12 + dev.flags], NETDEV_F_ABSENT
    mov  dword [r12 + dev.health], HEALTH_DEGRADED
.fail:
    lock inc qword [rel domain_reply_invalid]
    mov  rax, -1
    jmp  .out
.tx_full:
    lock inc qword [rel domain_reply_full]
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

virtio_domain_rx_poll:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    test r12, r12
    jz   .fail
    cmp  dword [r12 + virtio_domain_ctx.lifecycle], DOMAIN_LIFE_RUNNING
    jne  .fail
    mov  rbx, [r12 + virtio_domain_ctx.rx_ring]
    test rbx, rbx
    jz   .degraded
    cmp  dword [rbx + domain_ring.count], 0
    je   .empty
    cmp  dword [rbx + domain_ring.owner], DOMAIN_OWNER_HOST
    jne  .fail
    lfence                               ; observe payload after producer publish
    mov  edx, [rbx + domain_ring.len]
    cmp  rdx, r14
    ja   .fail                           ; caller buffer too short: do not consume
    cmp  rdx, DOMAIN_FRAME_MAX
    ja   .fail
    push rdx
    mov  rdi, r13
    lea  rsi, [rbx + domain_ring.data]
    call memcpy
    pop  r14                             ; return length; original cap no longer needed
    ; w046 secret hygiene: the frame now lives only in the caller's buffer.
    ; Zero the consumed bytes BEFORE ownership returns to the guest (the
    ; SFENCE below orders these fast-string stores ahead of the owner store).
    lea  rdi, [rbx + domain_ring.data]
    xor  esi, esi
    mov  rdx, r14
    call memset
    inc  qword [rbx + domain_ring.consumer]
    mov  dword [rbx + domain_ring.count], 0
    mov  dword [rbx + domain_ring.len], 0
    sfence
    mov  dword [rbx + domain_ring.owner], DOMAIN_OWNER_GUEST
    lock inc qword [r12 + virtio_domain_ctx.rx_frames]
    lock add qword [r12 + virtio_domain_ctx.rx_bytes], r14
    or   dword [r12 + virtio_domain_ctx.hooks], DOMAIN_HOOK_INSTRUMENT
    mov  rax, r14
    jmp  .out
.empty:
    xor  eax, eax
    jmp  .out
.degraded:
    mov  dword [r12 + dev.health], HEALTH_DEGRADED
.fail:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

virtio_domain_link_status:
    test rdi, rdi
    jz   .down
    cmp  dword [rdi + dev.health], HEALTH_OK
    jne  .down
    cmp  dword [rdi + virtio_domain_ctx.lifecycle], DOMAIN_LIFE_RUNNING
    jne  .down
    mov  eax, (10000 << 8) | 1
    ret
.down:
    xor  eax, eax
    ret

virtio_domain_get_mac:
    test rdi, rdi
    jz   .fail
    test rsi, rsi
    jz   .fail
    mov  byte [rsi + 0], 0x02
    mov  byte [rsi + 1], 0x50
    mov  byte [rsi + 2], 0x41
    mov  byte [rsi + 3], 0x4f
    mov  byte [rsi + 4], 0x53
    mov  rax, [rdi + virtio_domain_ctx.slot]
    mov  [rsi + 5], al
    xor  eax, eax
    ret
.fail:
    mov  rax, -1
    ret

; Query the configured mode. L3 has a stable enum/return code but deliberately
; does not masquerade as transparent L2 until its later relay contract lands.
virtio_domain_mode_status:
    test rdi, rdi
    jz   .invalid
    cmp  dword [rdi + virtio_domain_ctx.mode], DOMAIN_MODE_TRANSPARENT_L2
    je   .l2
    cmp  dword [rdi + virtio_domain_ctx.mode], DOMAIN_MODE_L3_RELAY
    jne  .invalid
    mov  rax, DOMAIN_UNIMPLEMENTED
    ret
.l2:
    xor  eax, eax
    ret
.invalid:
    mov  rax, -1
    ret

; ---------------------------------------------------------------------------
; 1013b no-native-NIC capstone. Linux bridges its passed physical interface to
; the already-proven virtio-net device. These functions connect that virtio
; queue to the ordinary domain rings, select the domain through class policy,
; and bind the existing command projection to it. No upper layer knows a chip.
; ---------------------------------------------------------------------------
virtio_domain_capstone_bootstrap:
    cmp  byte [rel domain_capstone_active], 1
    je   .already
    lea  rdi, [rel domain_ctx1]
    call virtio_domain_mode_status
    test rax, rax
    jnz  .fail
    lea  rdi, [rel domain_ctx1]
    call virtio_domain_recover
    test rax, rax
    jnz  .fail
%ifdef PAOS_NIC_ASSIGNMENT
    call nd_transport_alive
    test eax,eax
    jz .legacy_start
    mov byte [rel domain_capstone_nd],1
    xor eax,eax
    jmp .started
.legacy_start:
    mov byte [rel domain_capstone_nd],0
%endif
    call vtd_domainnet_start              ; local call: never native UDP
.started:
    test rax, rax
    jnz  .fail
    lea  rdi, [rel domain_ctx1]
    call guestnet_domain_bind
    call domain_prepare_egress
    lea  rdx, [rel domain_ctx1]
    cmp  rax, rdx
    jne  .rollback_egress
    lea  rdi, [rel domain_ctx1]
    call command_udp_bind_domain
    test rax, rax
    jnz  .rollback_bind
    mov  byte [rel domain_capstone_active], 1
    mov  byte [rel domain_dhcp_started], 0
    mov  dword [rel domain_ctx1 + virtio_domain_ctx.mode], DOMAIN_MODE_TRANSPARENT_L2
    call virtio_domain_gateway_resolution_reset
    cmp  byte [rel domain_marker_bootstrap], 1
    je   .already
    mov  byte [rel domain_marker_bootstrap], 1
    lea  rdi, [rel str_domain_bootstrap]
    call serial_string
.already:
    xor  eax, eax
    ret
.rollback_bind:
    call command_udp_unbind_domain
.rollback_egress:
    call domain_restore_egress
.rollback_guest:
    xor  edi, edi
    call guestnet_domain_bind
%ifdef PAOS_NIC_ASSIGNMENT
    cmp byte [rel domain_capstone_nd],1
    jne .nd_old_stop
    mov rdi,[rel nd_generation]
    lea rsi,[rel nd_nonce]
    call nd_stop
    jmp .nd_stop_done
.nd_old_stop:
%endif
    call vtd_domainnet_stop
.nd_stop_done:
.fail:
    mov  rax, -1
    ret

virtio_domain_capstone_stop:
    ; Idempotent: the transport pump already runs this rollback when the worker
    ; fails asynchronously, and DOMAINNET STOP may arrive with no live capstone.
    ; Undo the command-pump bind only for the capstone that installed it; a
    ; second unbind finds no saved OOB handle and would zero the native pump.
    mov  al, [rel domain_capstone_active]
    mov  [rel domain_stop_was_active], al
    call dhcp_wire_stop
    mov  byte [rel domain_dhcp_started], 0
    mov  byte [rel domain_static_policy], 0
    mov  byte [rel domain_capstone_active], 0
    call virtio_domain_gateway_resolution_reset
    xor  edi, edi
    call guestnet_domain_bind
%ifdef PAOS_NIC_ASSIGNMENT
    cmp byte [rel domain_capstone_nd],1
    jne .nd_old_stop
    mov rdi,[rel nd_generation]
    lea rsi,[rel nd_nonce]
    call nd_stop
    jmp .nd_stop_done
.nd_old_stop:
%endif
    call vtd_domainnet_stop
.nd_stop_done:
    push rax
    cmp  byte [rel domain_stop_was_active], 1
    jne  .unbound
    call command_udp_unbind_domain
    call domain_restore_egress
.unbound:
    lea  rdi, [rel domain_ctx1]
    call virtio_domain_stop
    mov  dword [rel domain_ctx1 + dev.health], HEALTH_DEGRADED
    pop  rax
    ret

; Boot policy for a machine with no native-priority NIC at all. A present native NIC
; keeps the command pump whatever its link (netdev_has_native_present: HEALTH_OK, or
; DEGRADED only for link as rtl8125/rtl8126 mark it): RCQ-10 G3 L3 (0.0.65) - with the
; cable out at boot, the old link-reading check counted the e1000e as absent, the
; capstone took the pump after 30 s and the cable's return never leased. An absent
; Intel NIC is DEGRADED+ABSENT, so a no-NIC box still launches after the 30-second
; grace. A failed local launch is retried only after another full grace window.
virtio_domain_autoboot_tick:
%ifdef PAOS_NIC_ASSIGNMENT
    ; The selected full-fat owner starts from the first-boot hook/NDSTART.
    ; Never race it with the retired secondary-only guest helper.
    cmp dword [rel nd_state],0
    jne .auto_done
%endif
    cmp  byte [rel domain_capstone_active], 1
    je   .auto_done
    cmp  byte [rel domain_autoboot_checked], 1
    je   .auto_done
    call netdev_has_native_present        ; presence, no link read (RCQ-10 G3 L3)
    test eax, eax
    jnz  .native_present
    call tsc_now
    mov  rdx, [rel domain_autoboot_first_tsc]
    test rdx, rdx
    jnz  .elapsed
    mov  [rel domain_autoboot_first_tsc], rax
    ret
.elapsed:
    sub  rax, rdx
    mov  rdx, [rel tsc_khz]
    test rdx, rdx
    jz   .auto_done
    imul rdx, DOMAIN_AUTOBOOT_GRACE_MS
    cmp  rax, rdx
    jb   .auto_done
    call virtio_domain_capstone_bootstrap
    test rax, rax
    jnz  .retry_later
    mov  byte [rel domain_autoboot_checked], 1
    ret
.retry_later:
    call tsc_now
    mov  [rel domain_autoboot_first_tsc], rax
    ret
.native_present:
    mov  byte [rel domain_autoboot_checked], 1
.auto_done:
    ret

; RCQ-19 lease seam (hv/vtd). RAX = frames the guest has offered to PaOS
; (accepted + ring-full): any change means the domain's data path is alive.
virtio_domain_guest_progress:
    mov  rax, [rel domain_publish_accepted]
    add  rax, [rel domain_publish_full]
    ret

; RCQ-19 lease seam (hv/vtd). EDI=1 healthy, 0 degraded. Touches the domain
; netdev only while the capstone owns it, so a stopped capstone stays degraded.
virtio_domain_service_health:
    cmp  byte [rel domain_capstone_active], 1
    jne  .health_done
    mov  dword [rel domain_ctx1 + dev.health], HEALTH_DEGRADED
    test edi, edi
    jz   .health_done
    mov  dword [rel domain_ctx1 + dev.health], HEALTH_OK
.health_done:
    ret

; Guest virtio TX -> domain RX ring (physical-to-PaOS bridge direction).
; RDI=ctx, RSI=frame, RDX=len. Non-blocking: 0 accepted, -2 full/again,
; -1 invalid. The split-ring consumer must retain a descriptor on -2.
virtio_domain_guest_rx_publish:
    push rbx
    push r12
    push r13
    mov  r12, rdi
    mov  r13, rsi
    mov  rbx, rdx
    lock inc qword [rel domain_publish_attempts]
    test r12, r12
    jz   .pub_invalid
    cmp  byte [rel domain_capstone_active], 1
    jne  .pub_invalid
    cmp  dword [r12 + virtio_domain_ctx.lifecycle], DOMAIN_LIFE_RUNNING
    jne  .pub_invalid
    cmp  rbx, DOMAIN_FRAME_MIN
    jb   .pub_invalid
    cmp  rbx, DOMAIN_FRAME_MAX
    ja   .pub_invalid
    mov  rax, [r12 + virtio_domain_ctx.rx_ring]
    test rax, rax
    jz   .pub_invalid
    cmp  dword [rax + domain_ring.count], 0
    jne  .pub_full
    cmp  dword [rax + domain_ring.owner], DOMAIN_OWNER_GUEST
    jne  .pub_invalid
    push rax
    lea  rdi, [rax + domain_ring.data]
    mov  rsi, r13
    mov  rdx, rbx
    call memcpy
    pop  rax
    mov  [rax + domain_ring.len], ebx
    inc  qword [rax + domain_ring.producer]
    sfence
    mov  dword [rax + domain_ring.owner], DOMAIN_OWNER_HOST
    mov  dword [rax + domain_ring.count], DOMAIN_RING_DEPTH
    lock inc qword [rel domain_publish_accepted]
    xor  eax, eax
    jmp  .pub_out
.pub_full:
    lock inc qword [rel domain_publish_full]
    mov  rax, DOMAIN_PUBLISH_FULL
    jmp  .pub_out
.pub_invalid:
    lock inc qword [rel domain_publish_invalid]
    mov  rax, -1
.pub_out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; RDI=ctx -> EAX=1 only when a retained guest TX descriptor can be retried
; without scanning or waiting inside the VM-exit path.
virtio_domain_guest_rx_can_accept:
    test rdi, rdi
    jz   .not_ready
    cmp  byte [rel domain_capstone_active], 1
    jne  .not_ready
    cmp  dword [rdi + virtio_domain_ctx.lifecycle], DOMAIN_LIFE_RUNNING
    jne  .not_ready
    mov  rax, [rdi + virtio_domain_ctx.rx_ring]
    test rax, rax
    jz   .not_ready
    cmp  dword [rax + domain_ring.count], 0
    jne  .not_ready
    cmp  dword [rax + domain_ring.owner], DOMAIN_OWNER_GUEST
    jne  .not_ready
    mov  eax, 1
    ret
.not_ready:
    xor  eax, eax
    ret

; Domain TX ring -> guest virtio RX queue (PaOS-to-physical bridge direction).
; Higher policy owns explicit static/off vs automatic DORA (EDI=0/1).
; Discard the bounded pending host TX slot when its L3 policy is replaced or
; revoked, before a later pump can forward a frame from the retired endpoint.
; No guest, NIC or native recovery handle is stopped by this operation.
virtio_domain_static_policy:
    mov  [rel domain_static_policy], dil
    mov  rax, [rel domain_ctx1 + virtio_domain_ctx.tx_ring]
    test rax, rax
    jz   .out
    cmp  dword [rax + domain_ring.count], 0
    je   .out
    inc  qword [rax + domain_ring.consumer]
    mov  dword [rax + domain_ring.count], 0
    mov  dword [rax + domain_ring.len], 0
    sfence
    mov  dword [rax + domain_ring.owner], DOMAIN_OWNER_HOST
.out:
    ret

; RDI=expected selected domain -> EAX=live physical START generation/0.
; Pointer identity, health and RUNNING alone do not prove a physical transport.
virtio_domain_policy_generation:
    lea  rax, [rel domain_ctx1]
    cmp  rdi, rax
    jne  .missing
    cmp  byte [rel domain_capstone_active], 1
    jne  .missing
    cmp  dword [rdi + dev.health], HEALTH_OK
    jne  .missing
    cmp  dword [rdi + virtio_domain_ctx.lifecycle], DOMAIN_LIFE_RUNNING
    jne  .missing
    cmp  dword [rdi + virtio_domain_ctx.mode], DOMAIN_MODE_TRANSPARENT_L2
    jne  .missing
%ifdef PAOS_NIC_ASSIGNMENT
    cmp byte [rel domain_capstone_nd],1
    je nd_ready_generation
%endif
    jmp  vtd_domainnet_ready_generation
.missing:
    xor  eax, eax
    ret

; RDI=client MAC, RSI=admitted domain owner, EDX=preferred server/0.
; Both explicit and automatic callers retain their live-generation admission.
; Publish startup custody only after the real FSM accepts the attempt. A send
; failure within an accepted FSM belongs to its own retry budget; a startup
; refusal leaves automatic startup retryable. Never change another owner's latch.
virtio_domain_dhcp_start:
    lea  rax, [rel domain_ctx1]
    cmp  rsi, rax
    jne  .bad
    mov  byte [rel domain_dhcp_started], 0
    sub  rsp, 8
    call dhcp_wire_start_preferred
    add  rsp, 8
    test rax, rax
    jnz  .out
    mov  byte [rel domain_dhcp_started], 1
.out:
    ret
.bad:
    mov  rax, -1
    ret

virtio_domain_transport_pump:
    cmp  byte [rel domain_capstone_active], 1
    jne  .pump_done
%ifdef PAOS_NIC_ASSIGNMENT
    cmp byte [rel domain_capstone_nd],1
    jne .legacy_alive
    call nd_transport_alive
    jmp .alive
.legacy_alive:
%endif
    call vtd_domainnet_alive
.alive:
    test eax, eax
    jnz  .pump_live
    ; The worker's bounded failure path has already reclaimed the PCI function.
    ; Complete the matching class-policy rollback so the saved native OOB handle
    ; becomes primary again without requiring another UDP command.
    call virtio_domain_capstone_stop
    ret
.pump_live:
    lea  rdi, [rel domain_ctx1]
    call virtio_domain_policy_generation
    test eax, eax
    jz   .pump_done
    ; Do not spend DORA attempts while the guest is still booting or building
    ; its bridge.  The v1 TX ring has one slot, so starting earlier leaves the
    ; initial DISCOVER parked behind a transport that intentionally cannot
    ; consume it yet.  Start at the readiness edge and drain that first frame
    ; in this same pump pass.
    cmp  byte [rel domain_static_policy], 0
    jne  .pump_frames                      ; explicit policy never auto-starts DORA
    cmp  byte [rel domain_dhcp_started], 1
    je   .pump_frames
    lea  rdi, [rel udp_our_mac]
    lea  rsi, [rel domain_ctx1]          ; opaque DORA ingress owner
    xor  edx, edx
    call virtio_domain_dhcp_start
    test rax, rax
    jnz  .pump_done
.pump_frames:
    push rbx
    lea  rdi, [rel domain_ctx1]
    mov  rbx, [rdi + virtio_domain_ctx.tx_ring]
    test rbx, rbx
    jz   .pump_out
    cmp  dword [rbx + domain_ring.count], DOMAIN_RING_DEPTH
    jne  .pump_out
    cmp  dword [rbx + domain_ring.owner], DOMAIN_OWNER_GUEST
    jne  .pump_out
    mov  edx, [rbx + domain_ring.len]
    cmp  edx, DOMAIN_FRAME_MAX
    ja   .pump_out
    lea  rsi, [rbx + domain_ring.data]
    call guestnet_rx_deliver
    test eax, eax
    jz   .pump_out
    inc  qword [rbx + domain_ring.consumer]
    mov  dword [rbx + domain_ring.count], 0
    mov  dword [rbx + domain_ring.len], 0
    sfence
    mov  dword [rbx + domain_ring.owner], DOMAIN_OWNER_HOST
    lock inc qword [rel domain_ctx1 + virtio_domain_ctx.guest_kicks]
.pump_out:
    pop  rbx
.pump_done:
    ret

; RDI=ordinary netdev handle -> EAX=1 only for the capstone domain instance.
; Consumers use this classifier instead of importing backend-private storage.
virtio_domain_is_handle:
    lea  rax, [rel domain_ctx1]
    cmp  rdi, rax
    sete al
    movzx eax, al
    ret

virtio_domain_note_dhcp:
    cmp  byte [rel domain_capstone_active], 1
    jne  .note_done
    cmp  byte [rel domain_marker_dhcp], 1
    je   .note_done
    mov  byte [rel domain_marker_dhcp], 1
    lea  rdi, [rel str_domain_dhcp]
    call serial_string
.note_done:
    ret

virtio_domain_note_arp:
    cmp  byte [rel domain_capstone_active], 1
    jne  .arp_done
    mov  byte [rel domain_arp_pending], 0
    mov  byte [rel domain_paos_arp], 1
    cmp  byte [rel domain_marker_arp], 1
    je   .arp_done
    mov  byte [rel domain_marker_arp], 1
    lea  rdi, [rel str_domain_arp]
    call serial_string
.arp_done:
    ret

virtio_domain_register_verb:
    lea  rdi, [rel str_domainnet_verb]
    lea  rsi, [rel virtio_domain_command]
    xor  edx, edx
    mov  ecx, ARGT_TEXT
    xor  r8, r8
    xor  r9, r9
    call command_register_verb
    ret

virtio_domain_command:
    push rbx
    push r12
    mov  byte [rel domain_cmd_error], 0     ; every invocation owns its error, including nested STAT
    call cmd_handler_prologue
    mov  r12, rsi
    mov  rbx, [rdi + REQ_ARG]
    mov  rdi, rbx
    lea  rsi, [rel str_domainnet_start]
    call hv_tok_is
    test al, al
    jnz  .cmd_start
    mov  rdi, rbx
    lea  rsi, [rel str_domainnet_stat]
    call hv_tok_is
    test al, al
    jnz  .cmd_ready
    mov  rdi, rbx
    lea  rsi, [rel str_domainnet_stop]
    call hv_tok_is
    test al, al
    jnz  .cmd_stop
    mov  byte [rel domain_cmd_error], 1
    jmp  .cmd_ready
.cmd_start:
    mov  rdi, rbx
    call domain_after_token
    lea  rsi, [rel str_domain_mode_l2]
    call hv_tok_is
    test al, al
    jz   .mode_check_l3
    call virtio_domain_capstone_bootstrap
    test rax, rax
    jz   .cmd_ready
    mov  byte [rel domain_cmd_error], 2
    jmp  .cmd_ready
.mode_check_l3:
    lea  rsi, [rel str_domain_mode_l3]
    call hv_tok_is
    test al, al
    jz   .bad_mode
    mov  byte [rel domain_cmd_error], 3       ; declared, clean unimplemented
    jmp  .cmd_ready
.bad_mode:
    mov  byte [rel domain_cmd_error], 1
    jmp  .cmd_ready
.cmd_stop:
    call virtio_domain_capstone_stop
    test rax, rax
    jz   .cmd_ready
    mov  byte [rel domain_cmd_error], 4
.cmd_ready:
    mov  byte [rel domain_out_ready], 1
    mov  qword [r12 + RSP_CODE], CMDE_OK
    pop  r12
    pop  rbx
    ret

domain_after_token:
.skip_word:
    cmp  byte [rdi], 0
    je   .after_done
    cmp  byte [rdi], ' '
    je   .skip_spaces
    inc  rdi
    jmp  .skip_word
.skip_spaces:
    cmp  byte [rdi], ' '
    jne  .after_done
    inc  rdi
    jmp  .skip_spaces
.after_done:
    ret

; Lean staged status, emitted before the legacy marker blocks so DOMAINNET STAT
; cannot be truncated. PING receives an additive PONG only when it arrived via
; the domain handle; that event earns the live UDP marker.
; Request staging only; live domain/boot/transport facts are untouched.
; clobbers: none. Shared request boundaries call this before dispatch and after framing.
virtio_domain_reply_retire:
    mov  byte [rel domain_out_ready], 0
    mov  byte [rel domain_cmd_error], 0
    ret

virtio_domain_status_line:
    cmp  byte [rel domain_out_ready], 1
    je   .emit
    ; These milestones occur after the boot_log_flush boundary. Project them
    ; through BOOTLOG as well as serial so the canonical late-boot evidence
    ; surface can retrieve the exact registered strings after the live probe.
    lea  rdi, [rel udp_line]
    lea  rsi, [rel str_verb_bootlog]
    call strcmp
    test rax, rax
    jz   .bootlog
    cmp  byte [rel domain_capstone_active], 1
    jne  .status_done
    lea  rdi, [rel udp_line]
    lea  rsi, [rel str_domain_ping]
    call strcmp
    test rax, rax
    jnz  .status_done
    mov  rax, [rel udp_ingress_handle]
    lea  rdx, [rel domain_ctx1]
    cmp  rax, rdx
    jne  .status_done
    lock inc qword [rel domain_ping_dispatch]
    lea  rdi, [rel str_domain_pong]
    call udp_put_str
    cmp  byte [rel domain_marker_udp], 1
    je   .status_done
    mov  byte [rel domain_marker_udp], 1
    lea  rdi, [rel str_domain_udp]
    call serial_string
    jmp  .status_done
.bootlog:
    cmp  byte [rel domain_marker_bootstrap], 1
    jne  .bootlog_dhcp
    lea  rdi, [rel str_domain_bootstrap]
    call udp_put_str
.bootlog_dhcp:
    cmp  byte [rel domain_marker_dhcp], 1
    jne  .bootlog_arp
    lea  rdi, [rel str_domain_dhcp]
    call udp_put_str
.bootlog_arp:
    cmp  byte [rel domain_marker_arp], 1
    jne  .bootlog_udp
    lea  rdi, [rel str_domain_arp]
    call udp_put_str
.bootlog_udp:
    cmp  byte [rel domain_marker_udp], 1
    jne  .status_done
    lea  rdi, [rel str_domain_udp]
    call udp_put_str
    jmp  .status_done
.emit:
    lea  rdi, [rel str_domain_status_head]
    call udp_put_str
    call domain_put_binding
    cmp  byte [rel domain_capstone_active], 1
    jne  .primary_native
    lea  rdi, [rel str_domain_primary_domain]
    call udp_put_str
    jmp  .lease
.primary_native:
    lea  rdi, [rel str_domain_primary_native]
    call udp_put_str
.lease:
    lea  rdi, [rel str_domain_lease]
    call udp_put_str
    mov  eax, [rel udp_our_ip3]
    call domain_put_ip
    lea  rdi, [rel str_domain_arp_field]
    call udp_put_str
    movzx edi, byte [rel domain_paos_arp]
    call udp_put_dec
    lea  rdi, [rel str_domain_arp_pending_field]
    call udp_put_str
    movzx edi, byte [rel domain_arp_pending]
    call udp_put_dec
    lea  rdi, [rel str_domain_arp_tx_field]
    call udp_put_str
    mov  rdi, [rel domain_arp_tx_attempts]
    call udp_put_dec
    lea  rdi, [rel str_domain_arp_tx_ok_field]
    call udp_put_str
    mov  rdi, [rel domain_arp_tx_ok]
    call udp_put_dec
    lea  rdi, [rel str_domain_arp_tx_fail_field]
    call udp_put_str
    mov  rdi, [rel domain_arp_tx_fail]
    call udp_put_dec
    lea  rdi, [rel str_domain_dhcp_state_field]
    call udp_put_str
    movzx edi, byte [rel dhcp_wire_state]
    call udp_put_dec
    lea  rdi, [rel str_domain_dhcp_tx_field]
    call udp_put_str
    mov  rdi, [rel dhcp_wire_tx_attempts]
    call udp_put_dec
    lea  rdi, [rel str_domain_dhcp_tx_ok_field]
    call udp_put_str
    mov  rdi, [rel dhcp_wire_tx_ok]
    call udp_put_dec
    lea  rdi, [rel str_domain_dhcp_tx_fail_field]
    call udp_put_str
    mov  rdi, [rel dhcp_wire_tx_fail]
    call udp_put_dec
    lea  rdi, [rel str_domain_dhcp_rx_field]
    call udp_put_str
    mov  rdi, [rel dhcp_wire_rx_frames]
    call udp_put_dec
    lea  rdi, [rel str_domain_dhcp_port68_field]
    call udp_put_str
    mov  rdi, [rel dhcp_wire_rx_port68]
    call udp_put_dec
    lea  rdi, [rel str_domain_dhcp_xid_ok_field]
    call udp_put_str
    mov  rdi, [rel dhcp_wire_rx_xid_ok]
    call udp_put_dec
    lea  rdi, [rel str_domain_boot_field]
    call udp_put_str
    mov  rdi, [rel domain_native_calls]
    call udp_put_dec
    lea  rdi, [rel str_domain_rx_field]
    call udp_put_str
    mov  rdi, [rel domain_ctx1 + virtio_domain_ctx.rx_frames]
    call udp_put_dec
    lea  rdi, [rel str_domain_tx_field]
    call udp_put_str
    mov  rdi, [rel domain_ctx1 + virtio_domain_ctx.tx_frames]
    call udp_put_dec
    ; Task1234 reuses the successful-crossing counters already proven by the
    ; netdev KAT. Summing them here keeps one source of packet truth and avoids
    ; changing virtio_domain_ctx's ABI merely to duplicate a monotonic total.
    lea  rdi, [rel str_domain_perf_packets_field]
    call udp_put_str
    mov  rdi, [rel domain_ctx1 + virtio_domain_ctx.tx_frames]
    add  rdi, [rel domain_ctx1 + virtio_domain_ctx.rx_frames]
    call udp_put_dec
    lea  rdi, [rel str_domain_vm_exits_field]
    call udp_put_str
    mov  rdi, [rel hv_ops_perf_vm_exits]
    call udp_put_dec
    lea  rdi, [rel str_domain_host_cycles_field]
    call udp_put_str
    mov  rdi, [rel hv_ops_perf_host_cycles]
    call udp_put_dec
    ; Conservation telemetry sits before the long lifecycle diagnostics so a
    ; full-size UDP status reply cannot hide the backpressure verdict.
    lea  rdi, [rel str_domain_resident_vcpus_field]
    call udp_put_str
    movzx edi, byte [rel hv_linux_running]
    call udp_put_dec
    lea  rdi, [rel str_domain_pub_try_field]
    call udp_put_str
    mov  rdi, [rel domain_publish_attempts]
    call udp_put_dec
    lea  rdi, [rel str_domain_pub_ok_field]
    call udp_put_str
    mov  rdi, [rel domain_publish_accepted]
    call udp_put_dec
    lea  rdi, [rel str_domain_pub_full_field]
    call udp_put_str
    mov  rdi, [rel domain_publish_full]
    call udp_put_dec
    lea  rdi, [rel str_domain_pub_bad_field]
    call udp_put_str
    mov  rdi, [rel domain_publish_invalid]
    call udp_put_dec
    lea  rdi, [rel str_domain_tx_try_field]
    call udp_put_str
    mov  rdi, [rel domain_reply_attempts]
    call udp_put_dec
    lea  rdi, [rel str_domain_tx_ok_field]
    call udp_put_str
    mov  rdi, [rel domain_reply_accepted]
    call udp_put_dec
    lea  rdi, [rel str_domain_tx_full_field]
    call udp_put_str
    mov  rdi, [rel domain_reply_full]
    call udp_put_dec
    lea  rdi, [rel str_domain_tx_bad_field]
    call udp_put_str
    mov  rdi, [rel domain_reply_invalid]
    call udp_put_dec
    lea  rdi, [rel str_domain_desc_used_field]
    call udp_put_str
    mov  rdi, [rel guestnet_tx_used_advance]
    call udp_put_dec
    lea  rdi, [rel str_domain_desc_defer_field]
    call udp_put_str
    mov  rdi, [rel guestnet_tx_backpressure]
    call udp_put_dec
    lea  rdi, [rel str_domain_ping_dispatch_field]
    call udp_put_str
    mov  rdi, [rel domain_ping_dispatch]
    call udp_put_dec
    lea  rdi, [rel str_domain_guest_vtx_field]
    call udp_put_str
    mov  edi, [rel guestnet_guest_tx_packets]
    call udp_put_dec
    lea  rdi, [rel str_domain_guest_vrx_field]
    call udp_put_str
    mov  rdi, [rel domain_ctx1 + virtio_domain_ctx.guest_kicks]
    call udp_put_dec
    lea  rdi, [rel str_domain_owner_field]
    call udp_put_str
    cmp  byte [rel vtd_owner_guest], 1
    jne  .owner_host
    lea  rdi, [rel str_domain_owner_guest]
    call udp_put_str
    jmp  .mode
.owner_host:
    lea  rdi, [rel str_domain_owner_host]
    call udp_put_str
.mode:
    lea  rdi, [rel str_domain_mode_field]
    call udp_put_str
    cmp  dword [rel domain_ctx1 + virtio_domain_ctx.mode], DOMAIN_MODE_TRANSPARENT_L2
    je   .critical_mode_l2
    lea  rdi, [rel str_domain_mode_l3_unimpl]
    call udp_put_str
    jmp  .critical_mode_done
.critical_mode_l2:
    lea  rdi, [rel str_domain_mode_l2]
    call udp_put_str
.critical_mode_done:
    ; Retain the domain lifecycle boundary even after automatic reclaim. These
    ; values come from the ownership worker rather than being inferred from the
    ; selected netdev, so a failed launch identifies the exact stopped edge.
    lea  rdi, [rel str_domain_bridge_ready_field]
    call udp_put_str
    movzx edi, byte [rel vtd_domain_bridge_ready]
    call udp_put_dec
    lea  rdi, [rel str_domain_bridge_stage_field]
    call udp_put_str
    movzx edi, byte [rel vtd_domain_bridge_stage]
    call udp_put_dec
    lea  rdi, [rel str_domain_iface_try_field]
    call udp_put_str
    movzx edi, byte [rel vtd_domain_iface_attempts]
    call udp_put_dec
    lea  rdi, [rel str_domain_iface_result_field]
    call udp_put_str
    movzx eax, byte [rel vtd_domain_iface_result]
    cmp  eax, VTD_DOMAIN_IFACE_RESULT_READY
    je   .iface_ready
    cmp  eax, VTD_DOMAIN_IFACE_RESULT_NOT_FOUND
    je   .iface_not_found
    cmp  eax, VTD_DOMAIN_IFACE_RESULT_LINK_UP_FAILED
    je   .iface_link_up
    cmp  eax, VTD_DOMAIN_IFACE_RESULT_MALFORMED
    je   .iface_malformed
    cmp  eax, VTD_DOMAIN_IFACE_RESULT_TIMEOUT_NO_RECEIPT
    je   .iface_timeout_no_receipt
    cmp  eax, VTD_DOMAIN_IFACE_RESULT_TIMEOUT_NOT_FOUND
    je   .iface_timeout_not_found
    cmp  eax, VTD_DOMAIN_IFACE_RESULT_TIMEOUT_LINK_UP
    je   .iface_timeout_link_up
    cmp  eax, VTD_DOMAIN_IFACE_RESULT_TIMEOUT_MALFORMED
    je   .iface_timeout_malformed
    cmp  byte [rel vtd_domain_iface_attempts], 0
    jne  .iface_waiting
    lea  rdi, [rel str_domain_iface_none]
    jmp  .iface_emit
.iface_ready:
    lea  rdi, [rel str_domain_iface_ready]
    jmp  .iface_emit
.iface_not_found:
    lea  rdi, [rel str_domain_iface_not_found]
    jmp  .iface_emit
.iface_link_up:
    lea  rdi, [rel str_domain_iface_link_up]
    jmp  .iface_emit
.iface_malformed:
    lea  rdi, [rel str_domain_iface_malformed]
    jmp  .iface_emit
.iface_timeout_no_receipt:
    lea  rdi, [rel str_domain_iface_timeout_no_receipt]
    jmp  .iface_emit
.iface_timeout_not_found:
    lea  rdi, [rel str_domain_iface_timeout_not_found]
    jmp  .iface_emit
.iface_timeout_link_up:
    lea  rdi, [rel str_domain_iface_timeout_link_up]
    jmp  .iface_emit
.iface_timeout_malformed:
    lea  rdi, [rel str_domain_iface_timeout_malformed]
    jmp  .iface_emit
.iface_waiting:
    lea  rdi, [rel str_domain_iface_waiting]
.iface_emit:
    call udp_put_str
    lea  rdi, [rel str_domain_guest_stage_field]
    call udp_put_str
    movzx edi, byte [rel vtd_guest_stage]
    cmp  byte [rel vtd_net_task_result], 2
    jne  .guest_stage_ready
    movzx edi, byte [rel vtd_assign_guest_stage]
.guest_stage_ready:
    call udp_put_dec
    lea  rdi, [rel str_domain_task_result_field]
    call udp_put_str
    movzx edi, byte [rel vtd_net_task_result]
    call udp_put_dec
    lea  rdi, [rel str_domain_fail_stage_field]
    call udp_put_str
    movzx edi, byte [rel vtd_assign_fail_stage]
    call udp_put_dec
    lea  rdi, [rel str_domain_guest_owner_field]
    call udp_put_str
    movzx edi, byte [rel vtd_owner_guest]
    call udp_put_dec
    lea  rdi, [rel str_domain_deadman_armed_field]
    call udp_put_str
    movzx edi, byte [rel vtd_deadman_armed]
    call udp_put_dec
    lea  rdi, [rel str_domain_deadman_fired_field]
    call udp_put_str
    movzx edi, byte [rel vtd_deadman_fired]
    call udp_put_dec
.error:
    movzx eax, byte [rel domain_cmd_error]
    test eax, eax
    jz   .emitted
    lea  rdi, [rel str_domain_error]
    call udp_put_str
    movzx edi, byte [rel domain_cmd_error]
    call udp_put_dec
.emitted:
    call virtio_domain_reply_retire
.status_done:
    ret

; Read the SAME physical/generation predicate used by explicit STATIC/DHCP.
; The asynchronous capstone/worker latch alone is not attachment evidence.
; Keep this small record first, before the longer diagnostic tail can clip.
domain_put_binding:
    push rbx
    lea  rdi, [rel domain_ctx1]
    call virtio_domain_policy_generation
    mov  ebx, eax
    lea  rdi, [rel str_domain_ready_field]
    call udp_put_str
    xor  edi, edi
    test ebx, ebx
    setnz dil
    call udp_put_dec
    lea  rdi, [rel str_domain_generation_field]
    call udp_put_str
    mov  edi, ebx
    call udp_put_dec
    pop  rbx
    ret

domain_put_ip:
    push rbx
    push r12
    mov  ebx, eax
    xor  r12d, r12d
.ip_octet:
    mov  eax, ebx
    mov  ecx, r12d
    shl  ecx, 3
    shr  eax, cl
    and  eax, 0xff
    mov  edi, eax
    call udp_put_dec
    inc  r12d
    cmp  r12d, 4
    jae  .ip_done
    lea  rdi, [rel str_domain_dot]
    call udp_put_str
    jmp  .ip_octet
.ip_done:
    pop  r12
    pop  rbx
    ret

; Fake guest used only by the QEMU seam KAT. It obeys the exact ownership
; protocol a later Linux/vhost transport uses: consume host TX, publish guest RX.
virtio_domain_fake_guest:
    push rbx
    push r12
    push r13
    push r14
    mov  r12, rdi
    test r12, r12
    jz   .fail
    cmp  qword [r12 + virtio_domain_ctx.guest_handle], 0
    je   .fail
    mov  r13, [r12 + virtio_domain_ctx.tx_ring]
    mov  rbx, [r12 + virtio_domain_ctx.rx_ring]
    test r13, r13
    jz   .fail
    test rbx, rbx
    jz   .fail
    cmp  dword [r13 + domain_ring.count], DOMAIN_RING_DEPTH
    jne  .fail
    cmp  dword [r13 + domain_ring.owner], DOMAIN_OWNER_GUEST
    jne  .fail
    cmp  dword [rbx + domain_ring.count], 0
    jne  .fail
    cmp  dword [rbx + domain_ring.owner], DOMAIN_OWNER_GUEST
    jne  .fail
    lfence
    mov  r14d, [r13 + domain_ring.len]
    cmp  r14, DOMAIN_FRAME_MIN
    jb   .fail
    cmp  r14, DOMAIN_FRAME_MAX
    ja   .fail
    lea  rdi, [rbx + domain_ring.data]
    lea  rsi, [r13 + domain_ring.data]
    mov  rdx, r14
    call memcpy
    inc  qword [r13 + domain_ring.consumer]
    mov  dword [r13 + domain_ring.count], 0
    mov  dword [r13 + domain_ring.len], 0
    mov  dword [r13 + domain_ring.owner], DOMAIN_OWNER_HOST
    mov  [rbx + domain_ring.len], r14d
    inc  qword [rbx + domain_ring.producer]
    sfence
    mov  dword [rbx + domain_ring.owner], DOMAIN_OWNER_HOST
    mov  dword [rbx + domain_ring.count], DOMAIN_RING_DEPTH
    lock inc qword [r12 + virtio_domain_ctx.guest_kicks]
    xor  eax, eax
    jmp  .out
.fail:
    mov  rax, -1
.out:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; FNV-1a-64, used only for content grading of bytes that actually occupied each
; ring. The probe independently computes the known answer from the frame rule.
domain_fnv1a64:
    mov  rax, 0xcbf29ce484222325
    mov  r8, 0x100000001b3
    test rsi, rsi
    jz   .done
.loop:
    movzx edx, byte [rdi]
    xor  rax, rdx
    imul rax, r8
    inc  rdi
    dec  rsi
    jnz  .loop
.done:
    ret

; Temporarily degrade only the currently selected non-domain handles so the
; canonical netdev_tx failover policy selects the domain backend. This uses the
; public selector and dev.health lifecycle field; it never reaches into the
; netdev table or imports e1000e/loopnet state. Boot is single-threaded here.
domain_prepare_egress:
    push r12
    push r13
    mov  qword [rel domain_saved_count], 0
    mov  r12d, NETDEV_MAX_SLOTS
.next:
    call netdev_egress_select
    test rax, rax
    jz   .fail
    lea  r13, [rel domain_ctx1]
    cmp  rax, r13
    je   .chosen
    lea  r13, [rel domain_ctx2]
    cmp  rax, r13
    je   .chosen
    mov  r13, [rel domain_saved_count]
    cmp  r13, 2
    jae  .fail
    lea  rdx, [rel domain_saved_handles]
    mov  [rdx + r13*8], rax
    lea  rdx, [rel domain_saved_health]
    mov  ecx, [rax + dev.health]
    mov  [rdx + r13*4], ecx
    inc  r13
    mov  [rel domain_saved_count], r13
    mov  dword [rax + dev.health], HEALTH_DEGRADED
    dec  r12d
    jnz  .next
.fail:
    xor  eax, eax
    jmp  .out
.chosen:
    or   dword [rax + virtio_domain_ctx.hooks], DOMAIN_HOOK_EGRESS
.out:
    pop  r13
    pop  r12
    ret

domain_restore_egress:
    mov  rcx, [rel domain_saved_count]
    test rcx, rcx
    jz   .done
    lea  r8, [rel domain_saved_handles]
    lea  r9, [rel domain_saved_health]
    xor  edx, edx
.loop:
    mov  rax, [r8 + rdx*8]
    mov  r10d, [r9 + rdx*4]
    mov  [rax + dev.health], r10d
    inc  edx
    cmp  rdx, rcx
    jb   .loop
.done:
    mov  qword [rel domain_saved_count], 0
    ret

; w046: after a consuming rx_poll the rx ring's first 96 data bytes (the KAT
; frame size) and its len must be zero. Records, never fails the seam KAT.
domain_rx_wipe_check:
    inc  byte [rel domain_rx_wipe_checks]
    cmp  dword [rel domain_rx_ring1 + domain_ring.len], 0
    jne  .bad
    lea  rdi, [rel domain_rx_ring1 + domain_ring.data]
    mov  ecx, 96
    xor  eax, eax
    cld
    repe scasb
    jne  .bad
    ret
.bad:
    mov  byte [rel domain_rx_wipe_bad], 1
    ret

; --- QEMU content KAT --------------------------------------------------------
; Registers TWO ordinary backends, proves canonical netdev_tx selection into
; backend #1, copies the deterministic frame through TX -> fake guest -> RX,
; hashes both ring-visible copies, and exercises every bounded negative path.
virtio_domain_selftest:
    push rbx
    push r12
    push r13
    push r14
    push r15
    mov  qword [rel domain_saved_count], 0

    lea  rdi, [rel domain_ctx1]
    lea  rsi, [rel domain_tx_ring1]
    lea  rdx, [rel domain_rx_ring1]
    lea  rcx, [rel domain_fake_guest_handle]
    mov  r8d, DOMAIN_MODE_TRANSPARENT_L2
    lea  r9, [rel str_domain_name1]
    call virtio_domain_create
    mov  [rel domain_slot1], rax
    test rax, rax
    js   .fail

    lea  rdi, [rel domain_ctx2]
    lea  rsi, [rel domain_tx_ring2]
    lea  rdx, [rel domain_rx_ring2]
    xor  ecx, ecx                        ; registered, but no guest attached
    mov  r8d, DOMAIN_MODE_L3_RELAY
    lea  r9, [rel str_domain_name2]
    call virtio_domain_create
    mov  [rel domain_slot2], rax
    test rax, rax
    js   .fail
    cmp  rax, [rel domain_slot1]
    je   .fail
    cmp  dword [rel domain_ctx2 + dev.health], HEALTH_DEGRADED
    jne  .fail
    mov  eax, [rel domain_ctx1 + virtio_domain_ctx.hooks]
    and  eax, DOMAIN_HOOK_TABLE | DOMAIN_HOOK_HANDLE
    cmp  eax, DOMAIN_HOOK_TABLE | DOMAIN_HOOK_HANDLE
    jne  .fail
    mov  eax, [rel domain_ctx2 + virtio_domain_ctx.hooks]
    and  eax, DOMAIN_HOOK_TABLE | DOMAIN_HOOK_HANDLE
    cmp  eax, DOMAIN_HOOK_TABLE | DOMAIN_HOOK_HANDLE
    jne  .fail
    lea  rdi, [rel str_domain_registered]
    call serial_string

    ; stop/recover is a real lifecycle, not a ceremonial vtable slot.
    lea  rdi, [rel domain_ctx1]
    call virtio_domain_stop
    test rax, rax
    jnz  .fail
    cmp  dword [rel domain_ctx1 + virtio_domain_ctx.lifecycle], DOMAIN_LIFE_STOPPED
    jne  .fail
    lea  rdi, [rel domain_ctx1]
    call virtio_domain_recover
    test rax, rax
    jnz  .fail
    cmp  dword [rel domain_ctx1 + virtio_domain_ctx.lifecycle], DOMAIN_LIFE_RUNNING
    jne  .fail

    lea  rdi, [rel domain_ctx1]
    call virtio_domain_mode_status
    test rax, rax
    jnz  .fail
    lea  rdi, [rel domain_ctx2]
    call virtio_domain_mode_status
    cmp  rax, DOMAIN_UNIMPLEMENTED
    jne  .fail

    ; byte[i] = (i*37+11)&0xff, written with a walking pointer (no complex
    ; indexed store displacement — keep the NASM addressing trap out).
    lea  rdi, [rel domain_kat_frame]
    xor  ecx, ecx
.fill:
    imul eax, ecx, 37
    add  eax, 11
    mov  [rdi], al
    inc  rdi
    inc  ecx
    cmp  ecx, 96
    jb   .fill

    lea  rdi, [rel domain_ctx1]
    lea  rsi, [rel domain_ctx1]
    call virtio_domain_affinity_bind
    test rax, rax
    jnz  .fail

    call domain_prepare_egress
    lea  rbx, [rel domain_ctx1]
    cmp  rax, rbx                        ; no-guest backend #2 must be skipped
    jne  .fail
    lea  rsi, [rel domain_kat_frame]
    mov  edx, 96
    call netdev_tx                       ; canonical selector -> netdev_ops.tx
    test rax, rax
    jnz  .fail
    lea  rdi, [rel str_domain_dispatch]
    call serial_string

    mov  r12, [rel domain_ctx1 + virtio_domain_ctx.tx_ring]
    cmp  dword [r12 + domain_ring.count], DOMAIN_RING_DEPTH
    jne  .fail
    cmp  dword [r12 + domain_ring.len], 96
    jne  .fail
    lea  rdi, [r12 + domain_ring.data]
    lea  rsi, [rel domain_kat_frame]
    mov  edx, 96
    call memcmp
    test rax, rax
    jnz  .fail
    lea  rdi, [r12 + domain_ring.data]
    mov  esi, 96
    call domain_fnv1a64
    mov  [rel domain_tx_hash], rax

    lea  rdi, [rel domain_ctx1]
    call virtio_domain_fake_guest
    test rax, rax
    jnz  .fail
    lea  rdi, [rel domain_ctx1]
    mov  r10, [rdi + dev.ops]
    mov  r11, [r10 + netdev_ops.rx_poll]
    lea  rsi, [rel domain_kat_rx]
    mov  edx, 96
    call r11                             ; same netdev_ops dispatch used by native RX
    cmp  rax, 96
    jne  .fail
    call domain_rx_wipe_check            ; w046: consumed RX bytes must be gone
    lea  rdi, [rel domain_kat_rx]
    lea  rsi, [rel domain_kat_frame]
    mov  edx, 96
    call memcmp
    test rax, rax
    jnz  .fail
    lea  rdi, [rel domain_kat_rx]
    mov  esi, 96
    call domain_fnv1a64
    mov  [rel domain_rx_hash], rax
    cmp  rax, [rel domain_tx_hash]
    jne  .fail
    cmp  dword [rel domain_ctx1 + virtio_domain_ctx.hooks], DOMAIN_HOOK_ALL
    jne  .fail
    cmp  qword [rel domain_ctx1 + virtio_domain_ctx.tx_frames], 1
    jb   .fail
    cmp  qword [rel domain_ctx1 + virtio_domain_ctx.rx_frames], 1
    jb   .fail

    ; Full/backpressure is a distinct, non-consuming result. Keep the original
    ; payload resident until a real RX poll returns ownership, then prove the
    ; readiness predicate changes at that exact edge.
    mov  byte [rel domain_capstone_active], 1
    mov  r15, [rel domain_publish_full]
    lea  rdi, [rel domain_ctx1]
    lea  rsi, [rel domain_kat_frame]
    mov  edx, 96
    call virtio_domain_guest_rx_publish
    test rax, rax
    jnz  .fail
    mov  r14, [rel domain_rx_ring1 + domain_ring.producer]
    lea  rdi, [rel domain_ctx1]
    lea  rsi, [rel domain_kat_frame]
    mov  edx, 96
    call virtio_domain_guest_rx_publish
    cmp  rax, DOMAIN_PUBLISH_FULL
    jne  .fail
    cmp  r14, [rel domain_rx_ring1 + domain_ring.producer]
    jne  .fail
    inc  r15
    cmp  r15, [rel domain_publish_full]
    jne  .fail
    lea  rdi, [rel domain_ctx1]
    call virtio_domain_guest_rx_can_accept
    test eax, eax
    jnz  .fail
    lea  rdi, [rel domain_ctx1]
    lea  rsi, [rel domain_kat_rx]
    mov  edx, 96
    call virtio_domain_rx_poll
    cmp  rax, 96
    jne  .fail
    call domain_rx_wipe_check            ; w046: second consume, same rule
    lea  rdi, [rel domain_ctx1]
    call virtio_domain_guest_rx_can_accept
    cmp  eax, 1
    jne  .fail
    mov  byte [rel domain_capstone_active], 0

    ; Emit both runtime-computed hashes on one line. serial_hex64 owns the 0x.
    lea  rdi, [rel str_domain_kat_prefix]
    call serial_string
    mov  rdi, [rel domain_tx_hash]
    call serial_hex64
    lea  rdi, [rel str_domain_kat_mid]
    call serial_string
    mov  rdi, [rel domain_rx_hash]
    call serial_hex64
    lea  rdi, [rel str_domain_kat_suffix]
    call serial_string

    ; Hostile-frame battery. Every verdict comes from the live backend path.
    lea  rsi, [rel domain_kat_frame]
    mov  edx, DOMAIN_FRAME_MIN - 1
    call netdev_tx
    cmp  rax, -1
    jne  .fail
    lea  rsi, [rel domain_kat_frame]
    mov  edx, DOMAIN_FRAME_MAX + 1
    call netdev_tx
    cmp  rax, -1
    jne  .fail
    lea  rsi, [rel domain_kat_frame]
    mov  edx, 96
    call netdev_tx                       ; occupy the sole TX descriptor
    test rax, rax
    jnz  .fail
    lea  rsi, [rel domain_kat_frame]
    mov  edx, 96
    call netdev_tx                       ; full -> immediate -1/again
    cmp  rax, -1
    jne  .fail

    lea  rdi, [rel domain_ctx1]
    call virtio_domain_stop              ; drain the deliberate full-ring case
    test rax, rax
    jnz  .fail
    lea  rdi, [rel domain_ctx1]
    call virtio_domain_recover
    test rax, rax
    jnz  .fail

    lea  rdi, [rel domain_ctx2]
    mov  r10, [rdi + dev.ops]
    mov  r11, [r10 + netdev_ops.tx]
    lea  rsi, [rel domain_kat_frame]
    mov  edx, 96
    call r11                             ; no guest -> -1 + HEALTH_DEGRADED
    cmp  rax, -1
    jne  .fail
    cmp  dword [rel domain_ctx2 + dev.health], HEALTH_DEGRADED
    jne  .fail
    lea  rdi, [rel domain_ctx2]
    call virtio_domain_mode_status
    cmp  rax, DOMAIN_UNIMPLEMENTED
    jne  .fail

    call domain_restore_egress
    lea  rdi, [rel str_domain_negative]
    call serial_string
    ; w046: separate verdict line; the seam KAT verdict above is unchanged.
    lea  rdi, [rel str_domain_rx_wipe_fail]
    cmp  byte [rel domain_rx_wipe_checks], 2
    jne  .wipe_verdict
    cmp  byte [rel domain_rx_wipe_bad], 0
    jne  .wipe_verdict
    lea  rdi, [rel str_domain_rx_wipe_pass]
.wipe_verdict:
    call serial_string
    xor  eax, eax
    jmp  .out
.fail:
    mov  byte [rel domain_capstone_active], 0
    call domain_restore_egress
    lea  rdi, [rel str_domain_fail]
    call serial_string
    mov  rax, -1
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; A DHCPACK arms gateway resolution. Keep it armed until the common ARP RX path
; observes a reply from the offered router to the leased PaOS address. The v1
; domain TX ring is deliberately one entry deep, so a one-shot send can lose to
; ordinary backpressure; one bounded retry per second makes that loss harmless.
virtio_domain_gateway_resolution_reset:
    mov  byte [rel domain_paos_arp], 0
    mov  byte [rel domain_arp_pending], 0
    mov  qword [rel domain_arp_retry_tsc], 0
    mov  qword [rel domain_arp_tx_attempts], 0
    mov  qword [rel domain_arp_tx_ok], 0
    mov  qword [rel domain_arp_tx_fail], 0
    ret

virtio_domain_gateway_resolution_start:
    cmp  byte [rel domain_capstone_active], 1
    jne  .start_done
    mov  byte [rel domain_paos_arp], 0
    mov  byte [rel domain_arp_pending], 1
    mov  qword [rel domain_arp_retry_tsc], 0
.start_done:
    ret

virtio_domain_gateway_resolution_tick:
    cmp  byte [rel domain_capstone_active], 1
    jne  .tick_done
    cmp  byte [rel domain_arp_pending], 1
    jne  .tick_done
    call tsc_now
    cmp  rax, [rel domain_arp_retry_tsc]
    jb   .tick_done
    call command_udp_domain_arp_probe
    lock inc qword [rel domain_arp_tx_attempts]
    test rax, rax
    jnz  .tx_failed
    lock inc qword [rel domain_arp_tx_ok]
    jmp  .arm_next
.tx_failed:
    lock inc qword [rel domain_arp_tx_fail]
.arm_next:
    call tsc_now
    mov  rdx, [rel tsc_khz]
    test rdx, rdx
    jnz  .scaled
    mov  rdx, 1000000
.scaled:
    imul rdx, DOMAIN_ARP_RETRY_MS
    add  rax, rdx
    mov  [rel domain_arp_retry_tsc], rax
.tick_done:
    ret

; --- writable in-image state -------------------------------------------------
%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_dev_net_virtio_domain_0 0
align 8
virtio_domain_ops:  times netdev_ops_size db 0
virtio_domain_info: times netdev_info_size db 0

align 8
domain_ctx1:       times virtio_domain_ctx_size db 0
domain_ctx2:       times virtio_domain_ctx_size db 0
align 8
domain_tx_ring1:   times domain_ring_size db 0
align 8
domain_rx_ring1:   times domain_ring_size db 0
align 8
domain_tx_ring2:   times domain_ring_size db 0
align 8
domain_rx_ring2:   times domain_ring_size db 0

align 8
domain_fake_guest_handle: dq 0x56495254444f4d31 ; opaque transport handle
domain_slot1:       dq -1
domain_slot2:       dq -1
domain_tx_hash:     dq 0
domain_rx_hash:     dq 0
domain_publish_attempts: dq 0
domain_publish_accepted: dq 0
domain_publish_full:     dq 0
domain_publish_invalid:  dq 0
domain_reply_attempts:   dq 0
domain_reply_accepted:   dq 0
domain_reply_full:       dq 0
domain_reply_invalid:    dq 0
domain_ping_dispatch:    dq 0
domain_saved_count: dq 0
domain_saved_handles: times 2 dq 0
domain_saved_health:  times 2 dd 0
domain_native_calls:  dq 0
domain_autoboot_first_tsc: dq 0
domain_arp_retry_tsc: dq 0
domain_arp_tx_attempts: dq 0
domain_arp_tx_ok:      dq 0
domain_arp_tx_fail:    dq 0
domain_kat_frame:   times 96 db 0
domain_kat_rx:      times 96 db 0
domain_capstone_nd: db 0
domain_capstone_active: db 0
domain_stop_was_active: db 0
domain_static_policy:   db 0
domain_dhcp_started:    db 0
domain_autoboot_checked: db 0
domain_paos_arp:       db 0
domain_arp_pending:    db 0
domain_out_ready:      db 0
domain_cmd_error:      db 0
domain_marker_bootstrap: db 0
domain_marker_dhcp:    db 0
domain_marker_arp:     db 0
domain_marker_udp:     db 0

str_domain_name:  db "virtio_domain", 0
str_domain_name1: db "virtio_domain0", 0
str_domain_name2: db "virtio_domain1", 0

str_domain_registered:
    db "[PAOS64] domain backends registered through netdev_ops second_backend=1 [netdev.domain.registered]", 13, 10, 0
str_domain_dispatch:
    db "[PAOS64] domain canonical netdev_tx dispatch PASS [domain.netdev.dispatch]", 13, 10, 0
str_domain_kat_prefix:
    db "[PAOS64] domain.kat backend=virtio_domain via=netdev_ops mode=transparent_l2 hooks=7 len=96 second_backend=1 tx_fnv=", 0
str_domain_kat_mid:
    db " rx_fnv=", 0
str_domain_kat_suffix:
    db " [domain.ring.roundtrip]", 13, 10, 0
str_domain_negative:
    db "[PAOS64] domain.kat.negative short=reject oversize=reject ringfull=again noguest=degraded l3_relay=unimplemented [domain.backend.degraded]", 13, 10, 0
str_domain_fail:
    db "[PAOS64] domain backend seam KAT FAIL", 13, 10, 0
str_domain_rx_wipe_pass:
    db "[PAOS64] domain.kat rx ring wiped after copy-out consumes=2 residue=none [domain.rx.wipe.kat]", 13, 10, 0
str_domain_rx_wipe_fail:
    db "[PAOS64] domain.kat rx ring NOT wiped after copy-out [domain.rx.wipe.fail]", 13, 10, 0

str_domainnet_verb:  db "DOMAINNET", 0
str_domainnet_start: db "START", 0
str_domainnet_stat:  db "STAT", 0
str_domainnet_stop:  db "STOP", 0
str_domain_mode_l2:  db "transparent_l2", 0
str_domain_mode_l3:  db "l3_relay", 0
str_domain_ping:     db "PING", 0
str_domain_dot:      db ".", 0
str_domain_pong:     db " PONG", 0
str_domain_status_head: db " DOMAINNET backend=virtio_domain", 0
str_domain_ready_field: db " domain_ready=", 0
str_domain_generation_field: db " domain_gen=", 0
str_domain_primary_domain: db " primary=domain", 0
str_domain_primary_native: db " primary=native", 0
str_domain_lease:    db " paos_lease=", 0
str_domain_arp_field: db " paos_arp=", 0
str_domain_arp_pending_field: db " arp_pending=", 0
str_domain_arp_tx_field: db " arp_tx=", 0
str_domain_arp_tx_ok_field: db " arp_tx_ok=", 0
str_domain_arp_tx_fail_field: db " arp_tx_fail=", 0
str_domain_dhcp_state_field: db " dhcp_state=", 0
str_domain_dhcp_tx_field: db " dhcp_tx=", 0
str_domain_dhcp_tx_ok_field: db " dhcp_tx_ok=", 0
str_domain_dhcp_tx_fail_field: db " dhcp_tx_fail=", 0
str_domain_dhcp_rx_field: db " dhcp_rx=", 0
str_domain_dhcp_port68_field: db " dhcp_port68=", 0
str_domain_dhcp_xid_ok_field: db " dhcp_xid_ok=", 0
str_domain_boot_field: db " bootstrap=local_ring native_calls=", 0
str_domain_rx_field: db " domain_rx=", 0
str_domain_tx_field: db " domain_tx=", 0
str_domain_perf_packets_field: db " perf_packets=", 0
str_domain_vm_exits_field: db " vm_exits=", 0
str_domain_host_cycles_field: db " host_cycles=", 0
str_domain_resident_vcpus_field: db " resident_vcpus=", 0
str_domain_pub_try_field: db " pub_try=", 0
str_domain_pub_ok_field: db " pub_ok=", 0
str_domain_pub_full_field: db " pub_full=", 0
str_domain_pub_bad_field: db " pub_bad=", 0
str_domain_tx_try_field: db " txq_try=", 0
str_domain_tx_ok_field: db " txq_ok=", 0
str_domain_tx_full_field: db " txq_full=", 0
str_domain_tx_bad_field: db " txq_bad=", 0
str_domain_desc_used_field: db " desc_used=", 0
str_domain_desc_defer_field: db " desc_defer=", 0
str_domain_ping_dispatch_field: db " ping_dispatch=", 0
str_domain_guest_vtx_field: db " guest_vtx=", 0
str_domain_guest_vrx_field: db " guest_vrx=", 0
str_domain_owner_field: db " secondary_owner=", 0
str_domain_owner_guest: db "guest", 0
str_domain_owner_host: db "host", 0
str_domain_bridge_ready_field: db " bridge_ready=", 0
str_domain_bridge_stage_field: db " bridge_stage=", 0
str_domain_iface_try_field: db " iface_try=", 0
str_domain_iface_result_field: db " iface=", 0
str_domain_iface_none: db "none", 0
str_domain_iface_waiting: db "waiting", 0
str_domain_iface_ready: db "ready", 0
str_domain_iface_not_found: db "not_found", 0
str_domain_iface_link_up: db "link_up_failed", 0
str_domain_iface_malformed: db "malformed", 0
str_domain_iface_timeout_no_receipt: db "timeout_no_receipt", 0
str_domain_iface_timeout_not_found: db "timeout_not_found", 0
str_domain_iface_timeout_link_up: db "timeout_link_up", 0
str_domain_iface_timeout_malformed: db "timeout_malformed", 0
str_domain_guest_stage_field: db " guest_stage=", 0
str_domain_task_result_field: db " task_result=", 0
str_domain_fail_stage_field: db " fail_stage=", 0
str_domain_guest_owner_field: db " guest_owner=", 0
str_domain_deadman_armed_field: db " deadman_armed=", 0
str_domain_deadman_fired_field: db " deadman_fired=", 0
str_domain_mode_field: db " mode=", 0
str_domain_mode_l3_unimpl: db "l3_relay(unimplemented)", 0
str_domain_error:    db " error=", 0

str_domain_bootstrap:
    db "[PAOS64] domain bootstrap uses local shared-ring control native_calls=0 [domain.bootstrap.local]", 13, 10, 0
str_domain_dhcp:
    db "[PAOS64] PaOS accepted a LAN DHCPACK through virtio_domain [domain.paos.dhcp]", 13, 10, 0
str_domain_arp:
    db "[PAOS64] PaOS resolved the LAN gateway through virtio_domain [domain.paos.arp]", 13, 10, 0
str_domain_udp:
    db "[PAOS64] PaOS served a UDP command through virtio_domain [domain.paos.udp]", 13, 10, 0
domain_rx_wipe_checks: db 0              ; w046: consuming rx_polls checked by the KAT
domain_rx_wipe_bad:    db 0              ; w046: 1 = a consumed frame stayed in the ring
%endmacro
WDATA_DEFER WDATA_dev_net_virtio_domain_0

virtio_domain_selected_census:
    jmp virtio_domain_census_read
%include "dev/net/virtio_domain_census.inc"
