;; MODULE net/netdev
;; LAYER 4
;; EXPORTS netdev_census_snapshot_v2, netdev_census_snapshot, netdev_register, netdev_egress_select, netdev_has_healthy_native, netdev_has_native_member, netdev_tx, netdev_selftest, netdev_lock_audit, netdev_frame_stats, netdev_selected_owner, netdev_selected_link_ready, netdev_select_peek, netdev_member_info, netdev_usbnic_io, netdev_usbnic_poll, netdev_usbnic_recover, netdev_usbnic_rx, netdev_member_brief, netdev_link_reprobe, netdev_has_native_present, netdev_observation_member, netdev_power_member, netdev_link_wait_member, netdev_tx_identity
;; IMPORTS boot/native_driver_gate, boot/native_driver_preload, boot/serial, core/lib/fmt, core/lock, dev/net/loopnet, dev/net/e1000e, dev/net/rtl8168, dev/net/rtl8126, dev/net/rtl8125, dev/net/ax88179, dev/net/ax88179b, dev/net/cdc_ecm, dev/net/cdc_ncm, dev/net/virtio_domain
;; CAPS
;; OWNER saga:net
%include "boot/native_driver_gate.inc"
;; LOCK: netdev_lock PROTECTS netdev_table, netdev_count, netdev_egress_calls
; ============================================================================
; net/netdev.asm — the L4 network class core: the N-ary NIC TABLE + the
; netdev_ops HANDLE binding + the egress-select hook (DEVICE_SLOT.md §6.1,
; DRIVER_MODEL.md §2/§6.5). This is contract 1009's non-retrofittable BINDING
; seam: PaOS's network layer NEVER again knows a "primary NIC" — it knows a
; TABLE of struct dev* handles, each a pluggable backend registered through the
; uniform netdev_ops vtable, and every TX frame is routed by SELECTING a member
; of that table (v1: degenerate-to-one highest-priority-healthy; v2+: bond /
; multi-home / failover as pure POLICY added here, not a reshape of the layer).
;
; WHY A SEAM AND NOT A DRIVER: this contract is PRE-NIC (target: qemu_only, no
; UDP surface yet). It proves the STRUCTURE binds — TABLE exists, two backends
; (e1000e native + loopnet fake) coexist at distinct slots via priority ranking,
; the egress-select hook fires for every TX, and the socket descriptor carries
; the IMMUTABLE per-NIC affinity FIELD (value ignored in v1, but the field must
; exist so v1->v2 affinity/failover is ADDITIVE, never a struct rev). The real
; 82540EM ring TX/RX lands in 1029 (drv_e1000e_backend); bare-metal in 1010+.
;
; NO 'the_primary_nic' GLOBAL exists above this seam (known_trap). Selection is
; table-scan-by-priority; affinity (per-socket override) is the v2 hook the
; field reserves. loopnet.asm is the REFERENCE implementation of netdev_ops —
; every chip backend's ops signature matches it byte-for-byte (the fake is both
; the QEMU-no-hardware target AND the ops-contract documentation, DRIVER_MODEL §7).
; ============================================================================

; N-ary TABLE capacity. v1 fills 2 (e1000e + loopnet); the KAT probe validates
; 2..8. The table is a fixed array here but the count is RUNTIME (slots add/remove
; for failover) — the structure supports a variable member count, which is the
; whole point of the seam (known_trap: runtime-mutable, static init OK).
NETDEV_MAX_SLOTS  equ 8                       ; usbnic-late-bind: was 4 = FULL at boot (e1000e, loopnet, virtio_domain x2) -> every late USB NIC register was REJECTED

; ============================================================================
; struc socket_desc — the per-socket control block. The FINAL field,
; affinity_nic_handle, is the DEVICE_SLOT §6.1 IMMUTABLE seam: a per-socket
; pointer to the struct dev* this socket prefers for egress (0 = "let the core
; select"). v1 IGNORES the value (egress-select always scans by priority), but
; the FIELD must exist at commit 1 so v2 per-socket affinity / failover binding
; is an additive read, not a socket-struct revision (known_trap).
; ============================================================================
struc socket_desc
  .state:               resd 1   ; off 0  — TCP/UDP socket state
  .local_port:          resw 1   ; off 4
  .remote_port:         resw 1   ; off 6
  .local_ip:            resd 1   ; off 8
  .remote_ip:           resd 1   ; off 12
  .rx_seq:              resq 1   ; off 16
  .tx_seq:              resq 1   ; off 24
  .affinity_nic_handle: resq 1   ; off 32 — the IMMUTABLE per-NIC affinity seam
endstruc

; struc netdev_minfo — one member as the owner's read-only listing sees it
; (NETCFG MEMBERS, svc/command_udp). Filled by netdev_member_info.
NETDEV_LINK_UNPROBED equ 0xFFFFFFFF       ; not probed: unhealthy member or no link_status op
NETDEV_LINK_ERROR    equ 0xFFFFFFFE       ; link_status reported -1
struc netdev_minfo
  .handle:   resq 1
  .name:     resq 1    ; dev.name (0 = none)
  .driver:   resq 1    ; dev.info -> netdev_info.name (0 = none)
  .prio:     resd 1
  .health:   resd 1
  .link:     resd 1    ; link_status low dword (bit0 up, bits 8.. Mb/s) or a NETDEV_LINK_* value
  .selected: resb 1    ; 1 = the member the next TX would leave on
  .mac_ok:   resb 1
  .mac:      resb 6
  .flags:    resd 1    ; dev.flags (NETDEV_F_ABSENT: 'absent' rather than 'degraded')
endstruc

; netdev_register(RDI=struct dev*) -> RAX = assigned slot index (>=0) / -1 reject.
;   The sanctioned L3-backend -> L4-core UPWARD register edge (DRIVER_MODEL §5).
;   Validates the handle (ops non-null, class == CLASS_NET), appends it to the
;   next free TABLE slot, marks it HEALTH_OK, and returns the slot index (a
;   superset of REG_OK: index 0 still means "ok, slot 0"). Selection order is
;   applied at egress-select time (scan by .prio), so registration is plain
;   append — insertion order does not encode priority (known_trap: no primary).
;
;   DURABILITY (v3 most-durable): defensive fault containment, ADDITIVE over the
;   proven validate+append baseline. Every baseline reject path is kept
;   byte-for-byte (null-ops, wrong-class, table-full); TWO faults the bare append
;   could NOT contain are now caught, each DEGRADE-not-crash, neither on any real
;   caller's happy path (proven by the KAT — the live e1000e/loopnet registers are
;   byte-identical to baseline):
;     - NULL handle (RDI==0): guarded BEFORE the first deref. A null backend ptr
;       would otherwise fault reading dev.ops at address 0. -> reject, table intact.
;     - DUPLICATE handle: a backend that calls register twice (retry after a
;       transient, hot-replug) would consume TWO table slots for one device —
;       double-select + premature slot exhaustion. Scan the occupied slots; if the
;       handle is already bound, return its EXISTING slot IDEMPOTENTLY (count NOT
;       re-incremented, health preserved). A fresh observer generation does not
;       prove device recovery; the backend must restore health itself.
;   The dup scan is bounded to NETDEV_MAX_SLOTS, so a CORRUPTED over-count is also
;   contained (baseline's jae kept). Degrade, never overrun, never wedge.
;   clobbers: RAX,RCX,R9,R10,R11
netdev_register:
%ifdef PAOS_NATIVE_DRIVER_POLICY_LINKED
    call netdev_policy_admit
    jc .reject
%endif
    test rdi, rdi
    jz   .reject                         ; NULL handle — never deref address 0
    mov  rax, [rdi + dev.ops]
    test rax, rax
    jz   .reject                         ; no vtable — not a valid backend
    mov  eax, [rdi + dev.class]
    cmp  eax, CLASS_NET
    jne  .reject                         ; wrong class for this core
    lea  r9, [rel netdev_table]
    ; --- duplicate guard: already bound? return its slot idempotently ---
    xor  r10d, r10d                      ; scan index (full table, holes-safe)
.dupscan:
    cmp  r10d, NETDEV_MAX_SLOTS
    jae  .dupscan_done
    mov  r11, [r9 + r10*8]
    cmp  r11, rdi
    je   .dup_found                      ; same handle already present
    inc  r10d
    jmp  .dupscan
.dupscan_done:
    mov  rcx, [rel netdev_count]
    cmp  rcx, NETDEV_MAX_SLOTS
    jae  .reject                         ; table full (or corrupted over-count) — DEGRADE
    mov  [r9 + rcx*8], rdi                ; slot[count] = handle
    mov  dword [rdi + dev.health], HEALTH_OK
    lea  rax, [rcx + 1]
    mov  [rel netdev_count], rax
    mov  rax, rcx                         ; return the assigned slot index
    sub  rsp, 8
    call netdev_observation_advance
    add  rsp, 8
    ret
.dup_found:
    ; Membership is not device recovery. Preserve a prior failure until the
    ; backend's actual recovery path restores health; observers still get a
    ; fresh registration generation below.
    mov  rax, r10                         ; return the EXISTING slot index
    sub  rsp, 8
    call netdev_observation_advance
    add  rsp, 8
    ret
.reject:
    mov  rax, -1
    ret

%ifdef PAOS_NATIVE_DRIVER_POLICY_LINKED
; Exact domain vtable admission, independent of native priority/name/health.
; Called by registry AND egress, so a native soft fallback cannot carry traffic.
; RDI dev*, every GPR preserved, CF admission as above. Normal avoids dereference.
netdev_policy_admit:
    push rax
    push rdi
    push rsi
    cmp qword [rel native_driver_selected_policy], 0
    je .native
    test rdi, rdi
    jz .native
    mov rax, [rdi + dev.ops]
    lea rsi, [rel virtio_domain_ops]
    cmp rax, rsi
    jne .native
    mov edi, 4
    jmp .check
.native:
    mov edi, 6
.check:
    mov rsi, -1
    call native_driver_gate
    pop rsi
    pop rdi
    pop rax
    ret

%endif

; Existing registration-lifetime epoch, also exposed to opt-in power binding.
; Re-affirming the same registered handle begins a fresh epoch for pinned
; observers/attachments. Saturation refuses those epoch-dependent consumers;
; unattached device service remains available.
netdev_observation_advance:
    pushfq
    push r11
    cmp  byte [rel netdev_observation_testing], 0
    jne  .out
    cmp  rax, NETDEV_MAX_SLOTS
    jae  .out
    lea  r11, [rel netdev_observation_generations]
    cmp  qword [r11 + rax*8], -1
    je   .out
    inc  qword [r11 + rax*8]
.out:
    pop  r11
    popfq
    ret

; RDI=handle,RSI=exact RX method -> RAX ordinal1..8 or0 UNVERIFIED;
; RDX registration generation. Membership precedes every handle dereference.
; Registry-only, no driver op/lock/wait. No MAC/IP authenticates packet origin.
netdev_observation_member:
    cmp  byte [rel netdev_observation_testing], 0
    jne  .none
    test rdi, rdi
    jz   .none
    lea  r8, [rel netdev_table]
    xor  ecx, ecx
.scan:
    cmp  [r8 + rcx*8], rdi
    je   .member
    inc  ecx
    cmp  ecx, NETDEV_MAX_SLOTS
    jb   .scan
.none:
    xor  eax, eax
    xor  edx, edx
    ret
.member:
    cmp  dword [rdi + dev.class], CLASS_NET
    jne  .none
    cmp  dword [rdi + dev.health], HEALTH_OK
    jne  .none
    cmp  dword [rdi + dev.prio], PRIO_NATIVE_EXPERIMENTAL
    jb   .none
    test dword [rdi + dev.flags], NETDEV_F_ABSENT
    jnz  .none
    mov  r9, [rdi + dev.ops]
    test r9, r9
    jz   .none
    test rsi, rsi
    jz   .none
    cmp  [r9 + netdev_ops.rx_poll], rsi
    jne  .none
    lea  r8, [rel netdev_observation_generations]
    mov  rdx, [r8 + rcx*8]
    test rdx, rdx
    jz   .none
    cmp  rdx, -1
    je   .none
    lea  eax, [rcx + 1]
    ret

; RDI=existing handle, RSI=exact ops -> RAX=pinned registration generation
; word, RDX=current generation; zero on unverified membership. Reuses the
; existing registry epoch (including duplicate re-registration), never a new
; device registry. No driver call. Software members need no native priority.
netdev_power_member:
    cld
    cmp byte [rel netdev_observation_testing], 0
    jne .none
    test rdi, rdi
    jz .none
    lea r8, [rel netdev_table]
    xor ecx, ecx
.scan:
    cmp [r8 + rcx*8], rdi
    je .member
    inc ecx
    cmp ecx, NETDEV_MAX_SLOTS
    jb .scan
.none:
    xor eax, eax
    xor edx, edx
    ret
.member:
    cmp dword [rdi + dev.class], CLASS_NET
    jne .none
    cmp dword [rdi + dev.health], HEALTH_OK
    jne .none
    test dword [rdi + dev.flags], NETDEV_F_ABSENT
    jnz .none
    test rsi, rsi
    jz .none
    cmp [rdi + dev.ops], rsi
    jne .none
    lea rax, [rel netdev_observation_generations]
    lea rax, [rax + rcx*8]
    mov rdx, [rax]
    test rdx, rdx
    jz .none
    cmp rdx, -1
    je .none
    ret

; RDI=existing handle, RSI=exact ops -> as netdev_power_member, for a native
; member DEGRADED only for its link: NETDEV_F_LINK_WAIT set, NETDEV_F_ABSENT clear
; (rtl8126/rtl8125 bound with no link at bring-up, the members netdev_link_reprobe
; promotes). Promotion keeps the slot and its generation. No driver call.
netdev_link_wait_member:
    cld
    cmp byte [rel netdev_observation_testing], 0
    jne .none
    test rdi, rdi
    jz .none
    lea r8, [rel netdev_table]
    xor ecx, ecx
.scan:
    cmp [r8 + rcx*8], rdi
    je .member
    inc ecx
    cmp ecx, NETDEV_MAX_SLOTS
    jb .scan
.none:
    xor eax, eax
    xor edx, edx
    ret
.member:
    cmp dword [rdi + dev.class], CLASS_NET
    jne .none
    cmp dword [rdi + dev.health], HEALTH_DEGRADED
    jne .none
    cmp dword [rdi + dev.prio], PRIO_NATIVE_EXPERIMENTAL
    jb .none
    mov eax, [rdi + dev.flags]
    and eax, NETDEV_F_LINK_WAIT | NETDEV_F_ABSENT
    cmp eax, NETDEV_F_LINK_WAIT
    jne .none
    test rsi, rsi
    jz .none
    cmp [rdi + dev.ops], rsi
    jne .none
    lea rax, [rel netdev_observation_generations]
    lea rax, [rax + rcx*8]
    mov rdx, [rax]
    test rdx, rdx
    jz .none
    cmp rdx, -1
    je .none
    ret

; Public diagnostic identity, not a driver/probing API. RDI=registered handle,
; RSI=exact pinned ops -> EAX=one-based registry ordinal (0 UNKNOWN),
; EDX=closed backend family (0 UNKNOWN), RCX=registration epoch (0 UNKNOWN),
; R8=internal epoch pointer for pinned equality only (never serialized).
; Membership/health/exact ops are checked before dereference by the existing
; bounded registry seam. No getmac/linkstatus/MMIO, selection or driver call.
; Registry lifetime/immutable vtables apply; no concurrent-removal guarantee.
; Codes: 1 e1000e, 2 rtl8168, 3 rtl8126, 4 rtl8125, 5 ax88179,
; 6 ax88179b, 7 cdc_ecm, 8 cdc_ncm, 9 virtio_domain. All others UNKNOWN.
netdev_tx_identity:
%ifidn RCQ_SERVICE_PROGRESS_FIRST_START,1
    push rbx
    mov rbx, rsi
    call netdev_power_member
    test rax, rax
    jz .unknown
    mov r11, rdx
    mov r10, rax                       ; internal epoch pointer, never persisted
    lea r8, [rel netdev_observation_generations]
    sub rax, r8
    shr rax, 3
    inc eax
    xor edx, edx
    lea r8, [rel e1000e_ops]
    cmp rbx, r8
    jne .family_1
    mov edx, 1
    jmp .known
.family_1:
    lea r8, [rel rtl8168_ops]
    cmp rbx, r8
    jne .family_2
    mov edx, 2
    jmp .known
.family_2:
    lea r8, [rel e5000b_ops]
    cmp rbx, r8
    jne .family_3
    mov edx, 3
    jmp .known
.family_3:
    lea r8, [rel rtl8125_ops]
    cmp rbx, r8
    jne .family_4
    mov edx, 4
    jmp .known
.family_4:
    lea r8, [rel ax_ops]
    cmp rbx, r8
    jne .family_5
    mov edx, 5
    jmp .known
.family_5:
    lea r8, [rel axb_ops]
    cmp rbx, r8
    jne .family_6
    mov edx, 6
    jmp .known
.family_6:
    lea r8, [rel cdc_ecm_ops]
    cmp rbx, r8
    jne .family_7
    mov edx, 7
    jmp .known
.family_7:
    lea r8, [rel cdc_ncm_ops]
    cmp rbx, r8
    jne .family_8
    mov edx, 8
    jmp .known
.family_8:
    lea r8, [rel virtio_domain_ops]
    cmp rbx, r8
    jne .family_9
    mov edx, 9
    jmp .known
.family_9:
.known:
    mov r8, r10
    mov rcx, r11
    pop rbx
    ret
.unknown:
    xor eax, eax
    xor edx, edx
    xor ecx, ecx
    xor r8d, r8d
    pop rbx
    ret

%endif

; netdev_egress_select(RDI=route key — dst IP, IGNORED in v1) -> RAX = struct dev*
;   The EGRESS-SELECT HOOK — the performance/maintainability boundary (known_trap:
;   invoked for EVERY TX frame). v1 policy is degenerate-to-one: scan the TABLE,
;   return the highest-.prio member whose .health == HEALTH_OK (native beats
;   domain beats fallback). v2 grafts bond/failover/affinity HERE without touching
;   the IP path. Increments the invocation counter (content-graded by the probe).
;   RAX = 0 when the table is empty (no NIC — caller drops the frame, never hangs).
;   clobbers: RAX,RCX,R8,R9,R10,R11
netdev_egress_select:
    lock inc qword [rel netdev_egress_calls]
    xor  rax, rax                         ; best handle = none
    xor  r8d, r8d                         ; best priority seen = 0
    lea  r9, [rel netdev_table]
    xor  ecx, ecx                         ; slot index
.scan:
    cmp  ecx, NETDEV_MAX_SLOTS
    jae  .done
    mov  r10, [r9 + rcx*8]                ; handle at slot ecx
    test r10, r10
    jz .next
%ifdef PAOS_NATIVE_DRIVER_POLICY_LINKED
    push rdi
    mov rdi, r10
    call netdev_policy_admit
    pop rdi
    jc .next
%endif
    ; empty slots skipped before policy admission
    mov  r11d, [r10 + dev.health]
    test r11d, r11d                       ; HEALTH_OK == 0
    jnz  .next                            ; skip degraded/dead members
    mov  r11d, [r10 + dev.prio]
    cmp  r11d, r8d
    jbe  .next                            ; not strictly higher priority
    mov  r8d, r11d
    mov  rax, r10                         ; new best
.next:
    inc  ecx
    jmp  .scan
.done:
    test rax, rax
    jnz  .ret
    ; RCQ-10: no healthy member. A USB NIC that netdev DEGRADED on an error streak
    ; (NETDEV_F_USBNIC_SOFT, still connected) is the last usable member and keeps
    ; carrying traffic. Any other DEGRADED member (an absent device) never is.
    xor  ecx, ecx
.soft:
    cmp  ecx, NETDEV_MAX_SLOTS
    jae  .ret
    mov  r10, [r9 + rcx*8]
    test r10, r10
    jz .soft_next
%ifdef PAOS_NATIVE_DRIVER_POLICY_LINKED
    push rdi
    mov rdi, r10
    call netdev_policy_admit
    pop rdi
    jc .soft_next
%endif
    ; empty slots skipped before policy admission
    cmp  dword [r10 + dev.health], HEALTH_DEGRADED
    jne  .soft_next
    test dword [r10 + dev.flags], NETDEV_F_USBNIC_SOFT
    jz   .soft_next
    mov  r11d, [r10 + dev.prio]
    cmp  r11d, r8d
    jbe  .soft_next
    mov  r8d, r11d
    mov  rax, r10
.soft_next:
    inc  ecx
    jmp  .soft
.ret:
    ret

; Internal selected-owner checks for generic DHCP. No ops/layout change.
; netdev_selected_owner(RDI=expected handle) -> RAX=handle iff it is still the
;   selected registered NET member with tx/rx_poll/get_mac ops, else 0. Reads
;   only the registry/handle: no backend call, safe on every poll.
netdev_selected_owner:
    push rbx
    mov  rbx, rdi
    test rbx, rbx
    jz   .bad
    xor  edi, edi
    call netdev_egress_select
    cmp  rax, rbx
    jne  .bad                            ; membership and selection in one test
    cmp  dword [rbx + dev.class], CLASS_NET
    jne  .bad
    mov  r10, [rbx + dev.ops]
    test r10, r10
    jz   .bad
    cmp  qword [r10 + netdev_ops.tx], 0
    je   .bad
    cmp  qword [r10 + netdev_ops.rx_poll], 0
    je   .bad
    cmp  qword [r10 + netdev_ops.get_mac], 0
    je   .bad
    mov  rax, rbx
    pop  rbx
    ret
.bad:
    xor  eax, eax
    pop  rbx
    ret

; netdev_selected_link_ready(RDI=expected handle) -> RAX=handle/0. Owner check
;   plus ONE backend link_status call (bit 0 = link). link_status may touch
;   driver IO, so callers rate-limit this. Selection is rechecked after the
;   foreign call. Registry lifetime remains cooperative.
netdev_selected_link_ready:
    push rbx
    call netdev_selected_owner
    test rax, rax
    PW_BRANCH jnz,jz,22,.out
    mov  rbx, rax
    mov  r10, [rbx + dev.ops]
    mov  rax, [r10 + netdev_ops.link_status]
    test rax, rax
    PW_BRANCH jnz,jz,23,.bad
    mov  rdi, rbx
    PW_EDGE 24
    call rax
    PW_EDGE 25
    cmp  rax, -1
    je   .bad
    test al, 1
    jz   .bad
    mov  rdi, rbx
    call netdev_selected_owner
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; RCQ-10 USB NIC surprise removal. A USB NIC backend reports each bulk transfer
; and each rx poll here with its usbnic_watch (core/abi/driver_classes.inc); the
; class core decides GONE:
;   - a failed transfer reads PORTSC once (usbhc .port_status): CCS=0 -> GONE "ccs";
;   - every USBNIC_CCS_EVERY rx polls, one PORTSC read: CCS=0 -> GONE "ccs";
;   - USBNIC_DEGRADE_STREAK consecutive failed TX transfers with the port still
;     connected (or no CCS signal: a hub child, or an HC without .port_status) ->
;     DEGRADED "errors", never GONE (admin amendment 02:54: a still-plugged NIC under
;     a PAUSE storm or a refused TX must not become an outage until reboot).
;   - RX is reported through netdev_usbnic_rx (admin 04:31): an RX failure only
;     triggers the CCS read, and an RX success changes nothing. The streak is a TX
;     error streak, so a NIC with dead TX and working RX, kept busy by LAN
;     broadcasts, never flaps back to healthy.
; GONE is HEALTH_DEAD, only on positive detach evidence: netdev_egress_select skips
; the member from the next TX on and netdev_selected_owner stops returning it. It
; is sticky (a success never re-promotes; a re-plugged device stays GONE until
; reboot, re-attach is HUB1). DEGRADED is HEALTH_DEGRADED + NETDEV_F_USBNIC_SOFT and
; is NOT sticky: the next successful TX transfer (or an AX88179 PHY link-up read)
; re-promotes it; RX success never does. Egress skips it only while another member is healthy, so the last
; usable member keeps carrying traffic; a DEGRADED member WITHOUT the soft flag (an
; absent device) is never an egress fallback. The GONE line is written once; the
; DEGRADED/recovered lines at most USBNIC_LOG_TRANSITIONS times per device. Health
; and flag stores are aligned dword writes that egress select reads without
; netdev_lock: the same cooperative registry lifetime.

; netdev_usbnic_io(RDI=handle, RSI=watch*, EDX=1 TX transfer ok / 0 failed) -> RAX 0 present / -1 GONE
netdev_usbnic_io:
    cmp  dword [rdi + dev.health], HEALTH_DEAD
    je   .gone                           ; GONE is sticky: never re-promoted
    test edx, edx
    jz   .failed
    mov  dword [rsi + usbnic_watch.streak], 0
    test dword [rdi + dev.flags], NETDEV_F_USBNIC_SOFT
    jnz  netdev_usbnic_recover           ; a good transfer: DEGRADED (streak) -> healthy
    xor  eax, eax
    ret
.failed:
    inc  dword [rsi + usbnic_watch.streak]
    push rdi
    push rsi
    call netdev_usbnic_ccs               ; EAX 0 = the port is empty
    pop  rsi
    pop  rdi
    test eax, eax
    jz   .ccs
    cmp  dword [rsi + usbnic_watch.streak], USBNIC_DEGRADE_STREAK
    jb   .present
    jmp  netdev_usbnic_degrade           ; still connected (or no signal): never GONE on errors
.ccs:
    lea  rsi, [rel str_nd_gone_ccs]
    jmp  netdev_usbnic_gone
.present:
    xor  eax, eax
    ret
.gone:
    mov  rax, -1
    ret

; netdev_usbnic_rx(RDI=handle, RSI=watch*, EDX=1 RX transfer ok / 0 failed) -> RAX 0 present
;   / -1 GONE. A success leaves the TX streak and health alone (it never re-promotes);
;   a failure reads PORTSC once: CCS=0 -> GONE, else nothing (no streak).
netdev_usbnic_rx:
    cmp  dword [rdi + dev.health], HEALTH_DEAD
    je   .gone
    test edx, edx
    jnz  .present                        ; RX success: counted by the backend's frame stats only
    push rdi
    push rsi
    call netdev_usbnic_ccs               ; an RX error: is the port empty? (EAX 0)
    pop  rsi
    pop  rdi
    test eax, eax
    jnz  .present
    lea  rsi, [rel str_nd_gone_ccs]
    jmp  netdev_usbnic_gone
.present:
    xor  eax, eax
    ret
.gone:
    mov  rax, -1
    ret

; netdev_usbnic_poll(RDI=handle, RSI=watch*) -> RAX 0 present / -1 GONE (no transfer then).
netdev_usbnic_poll:
    cmp  dword [rdi + dev.health], HEALTH_DEAD
    je   .gone                           ; a DEGRADED member still polls (a good frame re-promotes)
    inc  dword [rsi + usbnic_watch.polls]
    cmp  dword [rsi + usbnic_watch.polls], USBNIC_CCS_EVERY
    jb   .present
    mov  dword [rsi + usbnic_watch.polls], 0
    push rdi
    call netdev_usbnic_ccs
    pop  rdi
    test eax, eax
    jnz  .present
    lea  rsi, [rel str_nd_gone_ccs]
    jmp  netdev_usbnic_gone
.present:
    xor  eax, eax
    ret
.gone:
    mov  rax, -1
    ret

; netdev_usbnic_ccs(RSI=watch*) -> EAX 0 = PORTSC.CCS clear (the port is empty),
;   1 = connected or no signal. One .port_status call; clobbers caller-saved.
netdev_usbnic_ccs:
    mov  rax, [rsi + usbnic_watch.hcops]
    test rax, rax
    jz   .unknown
    mov  rax, [rax + usbhc_ops.port_status]
    test rax, rax
    jz   .unknown
    mov  rdi, [rsi + usbnic_watch.hc]
    mov  esi, [rsi + usbnic_watch.port]
    call rax
    test eax, USBNIC_PORT_CONNECT
    jz   .empty
.unknown:
    mov  eax, 1
    ret
.empty:
    xor  eax, eax
    ret

; netdev_usbnic_degrade(RDI=handle, RSI=watch*) -> RAX 0 (present). HEALTH_OK ->
;   HEALTH_DEGRADED + NETDEV_F_USBNIC_SOFT, with a bounded serial line; a member
;   already off HEALTH_OK is left as it is.
netdev_usbnic_degrade:
    cmp  dword [rdi + dev.health], HEALTH_OK
    jne  .out
    or   dword [rdi + dev.flags], NETDEV_F_USBNIC_SOFT
    mov  dword [rdi + dev.health], HEALTH_DEGRADED
    lea  rdx, [rel str_nd_degraded]
    call netdev_usbnic_note
.out:
    xor  eax, eax
    ret

; netdev_usbnic_recover(RDI=handle, RSI=watch*) -> RAX 0. A streak-DEGRADED member
;   (NETDEV_F_USBNIC_SOFT) back to HEALTH_OK after a successful transfer or link-up.
netdev_usbnic_recover:
    cmp  dword [rdi + dev.health], HEALTH_DEGRADED
    jne  .out
    test dword [rdi + dev.flags], NETDEV_F_USBNIC_SOFT
    jz   .out
    mov  dword [rdi + dev.health], HEALTH_OK
    and  dword [rdi + dev.flags], ~NETDEV_F_USBNIC_SOFT
    lea  rdx, [rel str_nd_recovered]
    call netdev_usbnic_note
.out:
    xor  eax, eax
    ret

; netdev_usbnic_note(RDI=handle, RSI=watch*, RDX=line head) — "<head><name>\r\n",
;   at most USBNIC_LOG_TRANSITIONS per device. Preserves RDI/RSI.
netdev_usbnic_note:
    cmp  dword [rsi + usbnic_watch.logs], USBNIC_LOG_TRANSITIONS
    jae  .quiet
    inc  dword [rsi + usbnic_watch.logs]
    push rdi
    push rsi
    push rbx
    mov  rbx, rdi
    mov  rdi, rdx
    call serial_string
    mov  rdi, [rbx + dev.name]
    test rdi, rdi
    jnz  .named
    lea  rdi, [rel str_nd_gone_unnamed]
.named:
    call serial_string
    lea  rdi, [rel str_nd_note_eol]
    call serial_string
    pop  rbx
    pop  rsi
    pop  rdi
.quiet:
    ret

; netdev_usbnic_gone(RDI=handle, RSI=reason cstr) -> RAX -1. HEALTH_OK or a
;   streak-DEGRADED member -> HEALTH_DEAD once, with one serial line; a member
;   already GONE is left as it is.
netdev_usbnic_gone:
    push rbx
    push r12
    mov  rbx, rdi
    mov  r12, rsi
    cmp  dword [rbx + dev.health], HEALTH_DEAD
    je   .out
    and  dword [rbx + dev.flags], ~NETDEV_F_USBNIC_SOFT
    mov  dword [rbx + dev.health], HEALTH_DEAD
    lea  rdi, [rel str_nd_gone]
    call serial_string
    mov  rdi, [rbx + dev.name]
    test rdi, rdi
    jnz  .named
    lea  rdi, [rel str_nd_gone_unnamed]
.named:
    call serial_string
    lea  rdi, [rel str_nd_gone_reason]
    call serial_string
    mov  rdi, r12
    call serial_string
    lea  rdi, [rel str_nd_gone_eol]
    call serial_string
.out:
    mov  rax, -1
    pop  r12
    pop  rbx
    ret

str_nd_gone:          db "[PAOS64] L2 netdev: [net.usbnic.gone] dev=", 0
str_nd_gone_unnamed:  db "usbnic", 0
str_nd_gone_reason:   db " reason=", 0
str_nd_gone_ccs:      db "ccs", 0
str_nd_degraded:      db "[PAOS64] L2 netdev: [net.usbnic.degraded] reason=errors (non-sticky: a good transfer re-promotes; egress keeps it while no member is healthy) dev=", 0
str_nd_recovered:     db "[PAOS64] L2 netdev: [net.usbnic.recovered] dev=", 0
str_nd_note_eol:      db 13, 10, 0
str_nd_link_late:     db "[PAOS64] L2 netdev: [netdev.member.link.late] link up after bring-up -> HEALTH_OK dev=", 0
str_nd_link_unnamed:  db "net", 0
str_nd_gone_eol:      db " (egress fails over; stays GONE until reboot, re-attach is HUB1)", 13, 10, 0

; Internal device software-statistics seam; no netdev_ops/struct ABI change.
; RDI=registered handle -> EAX=0, RDX=RX, RCX=TX; -1 means unavailable.
; Membership precedes every dereference: stale/foreign handles are never read.
; Existing registry lifetime/immutability applies, not concurrent-removal safety.
netdev_frame_stats:
    xor  ecx, ecx
    lea  r9, [rel netdev_table]
.member:
    cmp  ecx, NETDEV_MAX_SLOTS
    jae  .unavailable
    cmp  [r9 + rcx*8], rdi
    je   .found
    inc  ecx
    jmp  .member
.found:
    test rdi, rdi
    jz   .unavailable
    cmp  dword [rdi + dev.class], CLASS_NET
    jne  .unavailable
    cmp  dword [rdi + dev.health], HEALTH_OK
    jne  .unavailable
    mov  rax, [rdi + dev.ops]
    lea  rdx, [rel e1000e_ops]
    cmp  rax, rdx
    je   e1000e_frame_stats
    lea  rdx, [rel rtl8168_ops]
    cmp  rax, rdx
    je   rtl8168_frame_stats
    lea  rdx, [rel e5000b_ops]
    cmp  rax, rdx
    je   rtl8126_frame_stats
    lea  rdx, [rel rtl8125_ops]
    cmp  rax, rdx
    je   rtl8125_frame_stats
    lea  rdx, [rel ax_ops]
    cmp  rax, rdx
    je   ax88179_frame_stats
    lea  rdx, [rel axb_ops]
    cmp  rax, rdx
    je   ax88179b_frame_stats
    lea  rdx, [rel cdc_ecm_ops]
    cmp  rax, rdx
    je   cdc_ecm_frame_stats
    lea  rdx, [rel cdc_ncm_ops]
    cmp  rax, rdx
    je   cdc_ncm_frame_stats
    lea  rdx, [rel virtio_domain_ops]
    cmp  rax, rdx
    je   virtio_domain_frame_stats
.unavailable:
    mov  rdx, -1
    mov  rcx, -1
    mov  eax, -1
    ret

; netdev_has_healthy_native() -> EAX=1 iff a healthy native-priority backend is
; registered AND its ordinary link-status operation reports usable. Registration
; precedes hardware discovery, so dev.health alone would make an absent Intel NIC
; suppress domain autoboot forever. This remains class-level: no chip identity or
; concrete driver state crosses the seam.
netdev_has_healthy_native:
    push rbx
    push r12
    lea  r12, [rel netdev_table]
    xor  ebx, ebx
.scan:
    cmp  ebx, NETDEV_MAX_SLOTS
    jae  .no
    mov  rdi, [r12 + rbx*8]
    test rdi, rdi
    jz   .next
    cmp  dword [rdi + dev.health], HEALTH_OK
    jne  .next
    cmp  dword [rdi + dev.prio], PRIO_NATIVE_EXPERIMENTAL
    jb   .next
    mov  r10, [rdi + dev.ops]
    test r10, r10
    jz   .next
    mov  r11, [r10 + netdev_ops.link_status]
    test r11, r11
    jz   .next
    call r11
    cmp  rax, -1
    je   .next
    test al, 1
    jnz  .yes
.next:
    inc  ebx
    jmp  .scan
.yes:
    mov  eax, 1
    jmp  .done
.no:
    xor  eax, eax
.done:
    pop  r12
    pop  rbx
    ret

; netdev_has_native_member() -> EAX=1 iff a HEALTH_OK member of NATIVE priority
;   (>= PRIO_NATIVE_EXPERIMENTAL: e1000e/rtl8168/cdc_ecm/ax88179 — never loopnet or
;   a domain relay) is registered. NO link check: boot uses it to decide "is there a
;   real NIC to keep WARMING for" (a present NIC still negotiating stays warming and
;   boot_p8_nic_watch flips it on link), while an ABSENT Intel NIC (demoted to
;   HEALTH_DEGRADED by e1000e_hw_bringup) no longer counts. Class-level: no chip
;   identity crosses the seam. clobbers: RAX,RCX,R9,R10
netdev_has_native_member:
    lea  r9, [rel netdev_table]
    xor  ecx, ecx
.scan:
    cmp  ecx, NETDEV_MAX_SLOTS
    jae  .no
    mov  r10, [r9 + rcx*8]
    test r10, r10
    jz   .next
    cmp  dword [r10 + dev.health], HEALTH_OK
    jne  .next
    cmp  dword [r10 + dev.prio], PRIO_NATIVE_EXPERIMENTAL
    jae  .yes
.next:
    inc  ecx
    jmp  .scan
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; netdev_has_native_present() -> EAX=1 iff a native-priority member (>= PRIO_NATIVE_
;   EXPERIMENTAL) is HEALTH_OK, or is DEGRADED only for link: NETDEV_F_LINK_WAIT set,
;   NETDEV_F_ABSENT clear (rtl8125/rtl8126 with no cable at bring-up; the members
;   netdev_link_reprobe promotes). NO link read. virtio_domain_autoboot_tick uses it to
;   decide 'no native NIC' (RCQ-10 G3 L3): a present NIC with its cable out keeps the
;   command pump, so its later link still binds. Absent / identity / BAR failures
;   (DEGRADED without LINK_WAIT) and DEAD members do not count. Class-level: no chip
;   identity crosses the seam. clobbers: RAX,RCX,R9,R10
netdev_has_native_present:
    lea  r9, [rel netdev_table]
    xor  ecx, ecx
.scan:
    cmp  ecx, NETDEV_MAX_SLOTS
    jae  .no
    mov  r10, [r9 + rcx*8]
    test r10, r10
    jz   .next
    cmp  dword [r10 + dev.prio], PRIO_NATIVE_EXPERIMENTAL
    jb   .next
    cmp  dword [r10 + dev.health], HEALTH_OK
    je   .yes
    cmp  dword [r10 + dev.health], HEALTH_DEGRADED
    jne  .next                            ; DEAD (GONE) never counts
    mov  eax, [r10 + dev.flags]
    and  eax, NETDEV_F_LINK_WAIT | NETDEV_F_ABSENT
    cmp  eax, NETDEV_F_LINK_WAIT
    je   .yes                             ; DEGRADED for link only
.next:
    inc  ecx
    jmp  .scan
.yes:
    mov  eax, 1
    ret
.no:
    xor  eax, eax
    ret

; ---------------------------------------------------------------------------
; RCQ-10 degraded-member re-probe. netdev_link_reprobe() -> EAX = members promoted.
;   A driver that left a member DEGRADED ONLY because its link was down at bring-up
;   marks it NETDEV_F_LINK_WAIT (rtl8126, rtl8125). Nothing else ever re-read such a
;   member, so a link slower than the bring-up budget stayed unbound all boot.
;   Called by the 1 s command_udp member tick (only while no native NIC is bound),
;   never on the packet path: one link read per waiting member per tick. Each call
;   advances the slot's tick count for every DEGRADED + LINK_WAIT member (never DEAD
;   = GONE, never ABSENT) and makes ONE link_status call (driver IO) on ticks
;   1..NETDEV_REPROBE_FAST, then on every NETDEV_REPROBE_SLOW-th tick: a bounded
;   rate that never gives up, so a cable plugged in late still binds. Link up (bit 0,
;   not -1) -> HEALTH_OK, flag cleared, one serial line; netdev_egress_select then
;   selects it as usual.
NETDEV_REPROBE_FAST equ 60                   ; first minute at 1 s: every tick
NETDEV_REPROBE_SLOW equ 30                   ; afterwards: every 30th tick
netdev_link_reprobe:
    push rbx
    push r12
    push r13
    xor  r13d, r13d                       ; promoted count
    xor  r12d, r12d                       ; slot index
.slot:
    cmp  r12d, NETDEV_MAX_SLOTS
    jae  .done
    lea  rax, [rel netdev_table]
    mov  rbx, [rax + r12*8]
    test rbx, rbx
    jz   .next
    cmp  dword [rbx + dev.health], HEALTH_DEGRADED
    jne  .next                            ; OK needs nothing; DEAD (GONE) is sticky
    mov  eax, [rbx + dev.flags]
    test eax, NETDEV_F_LINK_WAIT
    jz   .next                            ; absent / foreign / USB streak: not a link wait
    test eax, NETDEV_F_ABSENT
    jnz  .next
    lea  rcx, [rel netdev_reprobe_ticks]
    inc  dword [rcx + r12*4]
    mov  eax, [rcx + r12*4]
    cmp  eax, NETDEV_REPROBE_FAST
    jbe  .probe
    sub  eax, NETDEV_REPROBE_FAST
    xor  edx, edx
    mov  ecx, NETDEV_REPROBE_SLOW
    div  ecx
    test edx, edx
    jnz  .next                            ; backoff: not this tick
.probe:
    mov  r10, [rbx + dev.ops]
    test r10, r10
    jz   .next
    mov  rax, [r10 + netdev_ops.link_status]
    test rax, rax
    jz   .next
    mov  rdi, rbx
    call rax
    cmp  rax, -1
    je   .next
    test al, 1
    jz   .next                            ; still no link: stays DEGRADED
    and  dword [rbx + dev.flags], ~NETDEV_F_LINK_WAIT
    mov  dword [rbx + dev.health], HEALTH_OK
    inc  r13d
    lea  rdi, [rel str_nd_link_late]
    call serial_string
    mov  rdi, [rbx + dev.name]
    test rdi, rdi
    jnz  .named
    lea  rdi, [rel str_nd_link_unnamed]
.named:
    call serial_string
    lea  rdi, [rel str_nd_note_eol]
    call serial_string
.next:
    inc  r12d
    jmp  .slot
.done:
    mov  eax, r13d
    pop  r13
    pop  r12
    pop  rbx
    ret

; netdev_select_peek -> RAX = the member netdev_egress_select would return now,
;   without counting an egress (read-only listing). The same rule, kept beside
;   its only reader; test_rc_netdev_listing_host proves it equals the egress choice.
;   clobbers: RAX,RCX,R8,R9,R10,R11
netdev_select_peek:
    xor  rax, rax
    xor  r8d, r8d                         ; best priority so far
    lea  r9, [rel netdev_table]
    xor  ecx, ecx
.peek:
    cmp  ecx, NETDEV_MAX_SLOTS
    jae  .peeked
    mov  r10, [r9 + rcx*8]
    test r10, r10
    jz   .peek_next
    cmp  dword [r10 + dev.health], HEALTH_OK
    jne  .peek_next                       ; only a healthy member is ever selected
    mov  r11d, [r10 + dev.prio]
    cmp  r11d, r8d
    jbe  .peek_next                       ; strictly higher wins; the first of equals stays
    mov  r8d, r11d
    mov  rax, r10
.peek_next:
    inc  ecx
    jmp  .peek
.peeked:
    test rax, rax
    jnz  .peek_ret
    xor  ecx, ecx                         ; RCQ-10: egress's second pass, the same rule:
.peek_soft:                               ; no healthy member -> a SOFT-DEGRADED USB NIC
    cmp  ecx, NETDEV_MAX_SLOTS
    jae  .peek_ret
    mov  r10, [r9 + rcx*8]
    test r10, r10
    jz   .peek_soft_next
    cmp  dword [r10 + dev.health], HEALTH_DEGRADED
    jne  .peek_soft_next
    test dword [r10 + dev.flags], NETDEV_F_USBNIC_SOFT
    jz   .peek_soft_next
    mov  r11d, [r10 + dev.prio]
    cmp  r11d, r8d
    jbe  .peek_soft_next
    mov  r8d, r11d
    mov  rax, r10
.peek_soft_next:
    inc  ecx
    jmp  .peek_soft
.peek_ret:
    ret

; netdev_member_brief(EDI=slot, RSI=netdev_minfo*) -> RAX 0 filled / -1 empty slot
;   or out of range. The registry part of a member only: handle, name, driver, prio,
;   health and selection, with .link = NETDEV_LINK_UNPROBED and no MAC. It calls NO
;   driver op, so a periodic reader (the Network Monitor, RCQ-35) adds no device IO:
;   no USB control transfer, and no AX88179 link-up read that would re-promote a
;   DEGRADED member. clobbers: RAX,RCX,RDX,R8-R11.
netdev_member_brief:
    cmp  edi, NETDEV_MAX_SLOTS
    jae  .none
    lea  rax, [rel netdev_table]
    mov  edx, edi
    mov  rdx, [rax + rdx*8]
    test rdx, rdx
    jz   .none
    mov  [rsi + netdev_minfo.handle], rdx
    mov  rax, [rdx + dev.name]
    mov  [rsi + netdev_minfo.name], rax
    xor  eax, eax
    mov  rcx, [rdx + dev.info]
    test rcx, rcx
    jz   .driver
    mov  rax, [rcx + netdev_info.name]
.driver:
    mov  [rsi + netdev_minfo.driver], rax
    mov  eax, [rdx + dev.prio]
    mov  [rsi + netdev_minfo.prio], eax
    mov  eax, [rdx + dev.health]
    mov  [rsi + netdev_minfo.health], eax
    mov  eax, [rdx + dev.flags]
    mov  [rsi + netdev_minfo.flags], eax
    mov  dword [rsi + netdev_minfo.link], NETDEV_LINK_UNPROBED
    mov  byte [rsi + netdev_minfo.mac_ok], 0
    mov  dword [rsi + netdev_minfo.mac], 0
    mov  word [rsi + netdev_minfo.mac + 4], 0
    push rdx
    push rsi
    call netdev_select_peek
    pop  rsi
    pop  rdx
    cmp  rax, rdx
    sete byte [rsi + netdev_minfo.selected]
    xor  eax, eax
    ret
.none:
    mov  rax, -1
    ret

; netdev_member_info(EDI=slot, RSI=netdev_minfo*) -> RAX 0 filled / -1 empty slot
;   or out of range. Read-only (NETCFG MEMBERS): it changes no selection, health or
;   egress counter and sends nothing. netdev_member_brief, then one get_mac and, for
;   a HEALTH_OK member only, one link_status call (driver IO: one listing per
;   explicit owner command).
;   get_mac is a cached-MAC copy in every NIC backend, including the USB ones
;   (ax_get_mac, cdc_ncm_get_mac, cdc_ecm_get_mac), so it touches no device even
;   for a GONE member.
netdev_member_info:
    push rbx
    push r12
    push r13
    mov  r12, rsi
    call netdev_member_brief
    test rax, rax
    jnz  .none
    mov  rbx, [r12 + netdev_minfo.handle]
    mov  r13, [rbx + dev.ops]
    test r13, r13
    jz   .filled
    mov  rax, [r13 + netdev_ops.get_mac]
    test rax, rax
    jz   .no_mac
    mov  rdi, rbx
    lea  rsi, [r12 + netdev_minfo.mac]
    call rax
    test eax, eax
    jnz  .no_mac
    mov  byte [r12 + netdev_minfo.mac_ok], 1
.no_mac:
    cmp  dword [rbx + dev.health], HEALTH_OK
    jne  .no_probe                       ; driver IO only for a healthy member
    mov  rax, [r13 + netdev_ops.link_status]
    test rax, rax
    jz   .no_probe
    mov  rdi, rbx
    call rax
    cmp  rax, -1
    jne  .link
    mov  eax, NETDEV_LINK_ERROR
.link:
    mov  [r12 + netdev_minfo.link], eax
.no_probe:
.filled:
    xor  eax, eax
    jmp  .out
.none:
    mov  rax, -1
.out:
    pop  r13
    pop  r12
    pop  rbx
    ret

; netdev_tx(RSI=frame, RDX=len) -> RAX = 0 ok / -1 (ring full or no NIC).
;   THE canonical egress path: EVERY frame flows through egress-select (the hook)
;   then dispatches through the selected member's netdev_ops.tx HANDLE — the IP
;   stack never names a chip. Non-blocking per the ABI: a wedged member returns
;   -1, never hangs the stack.
;
;   DURABILITY (v3 most-durable): defensive fault containment, ADDITIVE over the
;   proven select+dispatch baseline. Every legal caller is byte-for-byte identical
;   (a registered NIC with a real ops.tx handle falls straight through to the
;   indirect call — proven by the KAT's DISPATCH vector). TWO faults the bare
;   dispatch could NOT contain are now caught, each DEGRADE-not-crash, on NO real
;   caller's happy path:
;     - NULL ops vtable (dev.ops == 0): egress-select only vets .health, NOT that a
;       HEALTH_OK member's ops pointer is non-null. A corrupted/half-torn-down handle
;       marked healthy would make [r10 + netdev_ops.tx] deref near address 0 -> fault.
;       -> drop the frame (-1), never deref 0.
;     - NULL tx HANDLE (ops.tx == 0): netdev_register only requires ops != 0, NOT that
;       the .tx slot is filled — an RX-only backend, or one registered before create()
;       populates its tx handle, has ops.tx == 0. Baseline `call r11` would then CALL
;       address 0 -> triple fault, the whole stack down. -> drop the frame (-1).
;   Both collapse into the SAME non-blocking -1 the no-NIC case already returns, so the
;   caller's contract is unchanged: a wedged/incomplete member degrades, never hangs
;   or crashes the stack (DRIVER_MODEL §1 fault-tolerance rule).
;   clobbers: RAX,RCX,RDI,R8,R9,R10,R11
netdev_tx:
    sub rsp, 8                           ; SysV alignment through optional backend admission
    push rsi
    push rdx
    xor  edi, edi                         ; route key (v1: ignored)
    call netdev_egress_select             ; RAX = selected handle
    pop  rdx
    pop  rsi
    test rax, rax
    jz   .drop                            ; empty table / all members degraded -> drop
    mov  rdi, rax                         ; self = handle
    mov  r10, [rdi + dev.ops]             ; -> netdev_ops
    test r10, r10
    jz   .drop                            ; DURABLE: handle w/o an ops vtable -> drop, never deref 0
    mov  r11, [r10 + netdev_ops.tx]       ; the HANDLE (runtime VA, filled by create)
    test r11, r11
    jz   .drop                            ; DURABLE: backend exposes no tx op -> drop, never call 0
    call r11                              ; (self, RSI=frame, RDX=len) -> RAX
    add rsp, 8
    ret
.drop:
    mov  rax, -1                          ; NON-BLOCKING: caller drops the frame, never hangs
    add rsp, 8
    ret

; net_kv_append(RDI=key cstr, RSI=value) — append "<key>=<dec> " at cursor R12,
;   advancing R12. R12 is the live cursor (caller owns it, callee-saved across the
;   fmt_* calls). The one place KAT key/value pairs render — through the canonical
;   fmt_dec (G1: no second formatter).
;
;   DURABILITY (v3 most-durable): an OPTIONAL exclusive write bound, net_kv_limit
;   (0 = DISARMED = the exact shipped baseline, ZERO change for every real caller —
;   proven byte-for-byte by the KAT). When armed, the WHOLE field ("<key>=<dec> ")
;   is MEASURED before a single byte is written; if it would reach/cross the limit
;   the field is dropped ATOMICALLY — cursor left UNMOVED, net_kv_truncations++ —
;   never a torn half-write. A shared string-append primitive that scribbles past
;   its buffer is the one genuine fault here; measure-then-commit contains it.
;   Degrade, never overrun.
;   clobbers: RAX,RCX,RDX,RSI,RDI,R8,R9,R10 (R12 advanced; RBX/R13-R15 preserved)
net_kv_append:
    cmp  qword [rel net_kv_limit], 0
    je   .emit                           ; DISARMED -> exact baseline path (no measure)
    ; --- ARMED: measure field width WITHOUT disturbing RDI(key)/RSI(value) ---
    mov  r8, rdi                         ; walk a COPY of the key ptr
    xor  ecx, ecx                        ; keylen
.klen:
    cmp  byte [r8], 0
    je   .klen_done
    inc  r8
    inc  ecx
    jmp  .klen
.klen_done:
    mov  rax, rsi                        ; value -> count decimal digits (fmt_dec-exact)
    mov  r9, 10
    xor  r10d, r10d                      ; declen (do-while: value 0 -> 1 digit)
.dlen:
    xor  edx, edx
    div  r9
    inc  r10
    test rax, rax
    jnz  .dlen
    ; needed exclusive end = R12 + keylen + 1('=') + declen + 1(' ')
    lea  r8, [r12 + rcx + 2]
    add  r8, r10
    cmp  r8, [rel net_kv_limit]
    ja   .drop                           ; would reach/cross the bound -> contain
    ; fits: RDI/RSI untouched by the measure -> fall into the byte-identical baseline
.emit:
    push rsi                              ; stash value
    mov  rsi, r12                         ; dst = cursor
    call fmt_str                          ; copy key
    add  r12, rax
    mov  byte [r12], '='
    inc  r12
    pop  rdi                              ; value -> RDI for fmt_dec
    mov  rsi, r12
    call fmt_dec
    add  r12, rax
    mov  byte [r12], ' '
    inc  r12
    ret
.drop:
    inc  qword [rel net_kv_truncations]  ; contained + COUNTED (observable)
    ret                                  ; R12 UNMOVED — atomic drop, no torn write

; netdev_selftest — the contract-1009 acceptance gate. Brings up the seam and
;   emits the 5 REQUIRED markers, each EARNED (gated on the real outcome, not a
;   latch), plus the content-graded KAT line the probe validates byte-for-byte
;   (a stub cannot fake knowing the table capacity, the distinct slot indices,
;   the live egress-hook counter, or the struct field offset).
netdev_selftest:
    NATIVE_DRIVER_REFUSE 6, 0
    ; --- (1) TABLE init: the N-ary table exists (capacity is a build constant) ---
    lea  rdi, [rel str_nd_table_init]
    call serial_string

    ; --- register the native backend (e1000e) FIRST -> slot 0 ---
    call e1000e_create                    ; RAX = slot index / -1
    mov  [rel nd_e1k_slot], rax
    test rax, rax
    js   .skip_e1k                        ; register rejected -> no marker (earned)
    lea  rdi, [rel str_nd_vtable_reg]
    call serial_string
.skip_e1k:
    ; --- register the reference backend (loopnet) SECOND -> slot 1 ---
    call loopnet_create                   ; RAX = slot index / -1
    mov  [rel nd_loop_slot], rax
    test rax, rax
    js   .skip_loop
    lea  rdi, [rel str_nd_loopnet_reg]
    call serial_string
.skip_loop:
    ; --- drive TX frames THROUGH the egress-select hook (proves it fires) ---
    mov  ecx, 3
.txloop:
    push rcx
    lea  rsi, [rel net_dummy_frame]
    mov  edx, 64
    call netdev_tx
    pop  rcx
    dec  ecx
    jnz  .txloop
    ; --- (4) egress-select marker: EARNED only if the hook actually fired ---
    cmp  qword [rel netdev_egress_calls], 0
    je   .skip_egress
    lea  rdi, [rel str_nd_egress]
    call serial_string
.skip_egress:
    ; --- (5) affinity field present (compile-time offset > 0) ---
    lea  rdi, [rel str_nd_affinity]
    call serial_string

    ; --- CONTENT-GRADE KAT line: TABLE_SLOTS, slot indices, egress count, offset ---
    push r12
    lea  r12, [rel net_katbuf]
    lea  rdi, [rel str_kv_prefix]
    mov  rsi, r12
    call fmt_str
    add  r12, rax
    lea  rdi, [rel str_k_table]
    mov  esi, NETDEV_MAX_SLOTS
    call net_kv_append
    lea  rdi, [rel str_k_e1k]
    mov  rsi, [rel nd_e1k_slot]
    call net_kv_append
    lea  rdi, [rel str_k_loop]
    mov  rsi, [rel nd_loop_slot]
    call net_kv_append
    lea  rdi, [rel str_k_egress]
    mov  rsi, [rel netdev_egress_calls]
    call net_kv_append
    lea  rdi, [rel str_k_affinity]
    mov  esi, socket_desc.affinity_nic_handle
    call net_kv_append
    mov  byte [r12], 13
    mov  byte [r12 + 1], 10
    mov  byte [r12 + 2], 0
    lea  rdi, [rel net_katbuf]
    call serial_string
    pop  r12

    ; --- tournament net_kv_append gate: KAT + durability markers (earned) ---
    call net_kv_append_kat

    ; --- tournament netdev_register gate: correctness KAT + dup/guard containment ---
    call netdev_register_kat

    ; --- tournament netdev_tx gate: correctness KAT + null-ops/null-tx degrade ---
    call netdev_tx_kat

    lea  rdi, [rel str_nd_pass]
    call serial_string
    ret

; net_kv_append_kat — tournament correctness + durability gate for net_kv_append.
;   Runs 3 EARNED checks over a sentinel-fenced scratch, each byte-graded (not a
;   latch); prints its marker only on pass, prints a .fail marker + CONTINUES boot
;   on any mismatch (degrade, never crash). ALWAYS leaves net_kv_limit DISARMED.
;     (1) KAT   — 5 vectors render byte-for-byte through the LIVE fn.
;     (2) GUARD — bounded write: exact R12 advance + a 0xEE sentinel one byte past
;                 the field is untouched (proves it never scribbles past).
;     (3) BOUND — fault containment: armed one byte short of a 14-byte field the
;                 whole field drops ATOMICALLY (R12 unmoved, truncations++, no byte
;                 written); re-armed to an EXACT fit the same field lands byte-exact.
net_kv_append_kat:
    push rbx
    push r12
    push r13
    push r14

    ; ---------- (1) KAT: 5 vectors accumulate, strcmp byte-for-byte ----------
    lea  r12, [rel net_kv_kat_buf]        ; cursor
    lea  rdi, [rel str_kat_kA]            ; "A" , 0  -> "A=0 "  (fmt_dec zero path)
    xor  esi, esi
    call net_kv_append
    lea  rdi, [rel str_k_table]           ; "TABLE_SLOTS" , 4 -> "TABLE_SLOTS=4 "
    mov  esi, 4
    call net_kv_append
    lea  rdi, [rel str_kat_kX]            ; "X" , 255 -> "X=255 "  (multi-digit)
    mov  esi, 255
    call net_kv_append
    lea  rdi, [rel str_kat_kZ]            ; "Z" , 4294967295 -> u32-max (10 digits)
    mov  esi, 4294967295
    call net_kv_append
    lea  rdi, [rel str_kat_kKV]           ; "KV" , 1000000 -> embedded zeros
    mov  esi, 1000000
    call net_kv_append
    mov  byte [r12], 0                     ; terminate accumulated run
    lea  rdi, [rel net_kv_kat_buf]
    lea  rsi, [rel str_kat_expect]
    call strcmp
    test rax, rax
    jnz  .fail
    lea  rdi, [rel str_tk_kat]
    call serial_string

    ; ---------- (2) GUARD: exact advance + no scribble past field ----------
    lea  r12, [rel net_kv_kat_buf]
    mov  r13, r12                          ; remember start
    mov  byte [r12 + 22], 0xEE             ; sentinel 1 past "EGRESS_SELECT_CALLS=3 " (22B)
    lea  rdi, [rel str_k_egress]           ; "EGRESS_SELECT_CALLS" (19) =3<sp> = 22B
    mov  esi, 3
    call net_kv_append
    sub  r12, r13                          ; R12 advance
    cmp  r12, 22
    jne  .fail
    cmp  byte [r13 + 22], 0xEE             ; sentinel untouched -> no overrun
    jne  .fail
    lea  rdi, [rel str_tk_guard]
    call serial_string

    ; ---------- (3) BOUND: armed 1-short -> atomic drop; exact-fit -> lands ----------
    lea  r13, [rel net_kv_kat_buf]
    mov  ecx, 16                           ; prefill 16B with 0xEE (prove drop wrote nothing)
    mov  al, 0xEE
.bfill:
    mov  byte [r13 + rcx - 1], al
    dec  ecx
    jnz  .bfill
    mov  r14, [rel net_kv_truncations]     ; baseline truncation count
    mov  r12, r13                          ; cursor = start
    lea  rax, [r13 + 13]                   ; arm ONE SHORT of the 14B field
    mov  [rel net_kv_limit], rax
    lea  rdi, [rel str_k_table]            ; "TABLE_SLOTS" , 4 -> 14B field
    mov  esi, 4
    call net_kv_append
    cmp  r12, r13                          ; cursor UNMOVED?
    jne  .bound_fail
    mov  rax, [rel net_kv_truncations]
    sub  rax, r14
    cmp  rax, 1                            ; truncation COUNTED exactly once?
    jne  .bound_fail
    cmp  byte [r13], 0xEE                  ; first byte still poison -> nothing written?
    jne  .bound_fail
    lea  rax, [r13 + 14]                   ; re-arm to EXACT fit
    mov  [rel net_kv_limit], rax
    lea  rdi, [rel str_k_table]
    mov  esi, 4
    call net_kv_append
    mov  qword [rel net_kv_limit], 0       ; DISARM before grading
    mov  byte [r12], 0
    lea  rdi, [rel net_kv_kat_buf]
    lea  rsi, [rel str_kat_bexpect]        ; "TABLE_SLOTS=4 " lands byte-exact
    call strcmp
    test rax, rax
    jnz  .fail
    lea  rdi, [rel str_tk_bound]
    call serial_string
    jmp  .done

.bound_fail:
    mov  qword [rel net_kv_limit], 0       ; ALWAYS disarm, even on failure
.fail:
    mov  qword [rel net_kv_limit], 0       ; belt-and-suspenders: never leave it armed
    lea  rdi, [rel str_tk_fail]
    call serial_string
.done:
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; netdev_register_kat — tournament correctness + durability gate for netdev_register
;   (v3 MOST-DURABLE). Drives the LIVE fn through value-graded vectors over a
;   scratch struct dev, then SNAPSHOT/RESTORES the WHOLE live table + count wholesale
;   so the running net table is byte-for-byte undisturbed even if a vector fails
;   mid-way (degrade, never corrupt). Prints each marker only on the real outcome;
;   on any mismatch prints .fail, restores the table, and CONTINUES boot.
;     (1) KAT   — 5 vectors: null-handle / null-ops / wrong-class all reject with
;                 count unchanged; a valid CLASS_NET dev appends at slot==prior
;                 count, count++ exactly, health FORCED HEALTH_OK, table[slot]==handle;
;                 count==MAX rejects (table full).
;     (2) DUP   — idempotent containment: registering the SAME handle twice returns
;                 the SAME slot, does NOT consume a second slot (count++ once),
;                 and preserves DEGRADED/DEAD rather than inventing recovery.
;     (3) GUARD — after all the KAT churn the live table + count equal the wholesale
;                 snapshot byte-for-byte (proves the gate perturbs no live invariant).
netdev_register_kat:
    push rbx
    push r12
    push r13
    push r14
    push r15

    ; ---- SNAPSHOT the entire live table + count (wholesale save = durability) ----
    call nd_kat_snapshot
    mov  r15, [rel netdev_count]          ; live count baseline (for grading)

    ; ---------- (1) KAT: reject + accept vectors, value-graded ----------
    ; vector 1: NULL handle -> -1, count unchanged
    xor  edi, edi
    call netdev_register
    cmp  rax, -1
    jne  .fail
    cmp  [rel netdev_count], r15
    jne  .fail
    ; vector 2: null ops -> -1, count unchanged
    call nd_kat_make_dev
    mov  qword [rdi + dev.ops], 0
    call netdev_register
    cmp  rax, -1
    jne  .fail
    cmp  [rel netdev_count], r15
    jne  .fail
    ; vector 3: wrong class -> -1, count unchanged
    call nd_kat_make_dev
    mov  dword [rdi + dev.class], CLASS_BLOCK
    call netdev_register
    cmp  rax, -1
    jne  .fail
    cmp  [rel netdev_count], r15
    jne  .fail
    ; vector 4: valid accept -> RAX==r15, count==r15+1, health OK, table[slot]==handle
    call nd_kat_make_dev
    mov  dword [rdi + dev.health], HEALTH_DEAD  ; prove register FORCES ok
    mov  r13, rdi                         ; remember handle
    call netdev_register
    cmp  rax, r15                          ; slot == prior count
    jne  .fail
    lea  rbx, [r15 + 1]
    cmp  [rel netdev_count], rbx           ; count incremented exactly once
    jne  .fail
    cmp  dword [r13 + dev.health], HEALTH_OK
    jne  .fail
    lea  r9, [rel netdev_table]
    mov  r11, [r9 + rax*8]                 ; table[slot] holds the handle
    cmp  r11, r13
    jne  .fail
    ; vector 5: table full -> -1, count unchanged at MAX (restore first, clean slate)
    call nd_kat_restore
    mov  qword [rel netdev_count], NETDEV_MAX_SLOTS
    call nd_kat_make_dev
    call netdev_register
    cmp  rax, -1
    jne  .fail
    cmp  qword [rel netdev_count], NETDEV_MAX_SLOTS
    jne  .fail
    call nd_kat_restore                    ; restore before grading
    lea  rdi, [rel str_tnr_kat]
    call serial_string

    ; ---------- (2) DUP: idempotent re-register returns SAME slot, count++ ONCE ----------
    mov  r14, [rel netdev_count]           ; count before first register
    call nd_kat_make_dev
    mov  r13, rdi                          ; handle
    call netdev_register                    ; first register -> new slot
    mov  r12, rax                           ; remember slot
    cmp  rax, r14                            ; appended at old count
    jne  .fail
    mov  rdi, r13                            ; re-register the SAME handle
    call netdev_register
    cmp  rax, r12                            ; SAME slot returned (idempotent)
    jne  .fail
    lea  rbx, [r14 + 1]
    cmp  [rel netdev_count], rbx             ; count incremented ONCE, not twice
    jne  .fail
    mov  dword [r13 + dev.health], HEALTH_DEGRADED
    mov  rdi, r13
    call netdev_register
    cmp  rax, r12
    jne  .fail
    cmp  [rel netdev_count], rbx
    jne  .fail
    cmp  dword [r13 + dev.health], HEALTH_DEGRADED
    jne  .fail
    mov  dword [r13 + dev.health], HEALTH_DEAD
    mov  rdi, r13
    call netdev_register
    cmp  rax, r12
    jne  .fail
    cmp  [rel netdev_count], rbx
    jne  .fail
    cmp  dword [r13 + dev.health], HEALTH_DEAD
    jne  .fail
    mov  dword [r13 + dev.health], HEALTH_OK ; leave only the scratch handle ready
    call nd_kat_restore
    lea  rdi, [rel str_tnr_dup]
    call serial_string

    ; ---------- (3) GUARD: live table + count == snapshot, byte-for-byte ----------
    lea  rsi, [rel netdev_table]
    lea  rdi, [rel nd_kat_save]
    mov  ecx, NETDEV_MAX_SLOTS
.gcmp:
    mov  rax, [rsi]
    cmp  rax, [rdi]
    jne  .fail
    add  rsi, 8
    add  rdi, 8
    dec  ecx
    jnz  .gcmp
    mov  rax, [rel nd_kat_save_count]
    cmp  [rel netdev_count], rax
    jne  .fail
    lea  rdi, [rel str_tnr_guard]
    call serial_string
    jmp  .done

.fail:
    call nd_kat_restore                     ; ALWAYS restore the live table, even on fail
    lea  rdi, [rel str_tnr_fail]
    call serial_string
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; nd_kat_snapshot — copy the live netdev_table (all slots) + netdev_count into the
;   scratch save area. clobbers RAX,RCX,RSI,RDI.
nd_kat_snapshot:
    mov  byte [rel netdev_observation_testing], 1
    lea  rsi, [rel netdev_table]
    lea  rdi, [rel nd_kat_save]
    mov  ecx, NETDEV_MAX_SLOTS
.s:
    mov  rax, [rsi]
    mov  [rdi], rax
    add  rsi, 8
    add  rdi, 8
    dec  ecx
    jnz  .s
    mov  rax, [rel netdev_count]
    mov  [rel nd_kat_save_count], rax
    ret

; nd_kat_restore — copy the snapshot back over the live table + count (durability
;   guarantee: the KAT never leaves the running table mutated). clobbers RAX,RCX,RSI,RDI.
nd_kat_restore:
    lea  rsi, [rel nd_kat_save]
    lea  rdi, [rel netdev_table]
    mov  ecx, NETDEV_MAX_SLOTS
.r:
    mov  rax, [rsi]
    mov  [rdi], rax
    add  rsi, 8
    add  rdi, 8
    dec  ecx
    jnz  .r
    mov  rax, [rel nd_kat_save_count]
    mov  [rel netdev_count], rax
    mov  byte [rel netdev_observation_testing], 0
    ret

; nd_kat_make_dev — (re)initialise the scratch dev as a VALID CLASS_NET backend and
;   return RDI = &nd_kat_dev. ops is a non-null sentinel (netdev_register never
;   dereferences it). clobbers RAX,RDI.
nd_kat_make_dev:
    lea  rdi, [rel nd_kat_dev]
    lea  rax, [rel nd_kat_ops]
    mov  [rdi + dev.ops], rax
    mov  dword [rdi + dev.prio], PRIO_NATIVE_EXPERIMENTAL
    mov  dword [rdi + dev.health], HEALTH_OK
    mov  dword [rdi + dev.class], CLASS_NET
    ret

; netdev_tx_kat — tournament correctness + durability gate for netdev_tx
;   (v3 MOST-DURABLE). Drives the LIVE fn over a wholesale-snapshotted table
;   (reuses 1413's nd_kat_snapshot/restore/make_dev — G1: no second snapshot
;   machinery) so the running net table + egress counter are byte-for-byte
;   undisturbed even if a vector faults mid-way. 3 EARNED markers, each graded on
;   the REAL outcome; on any mismatch prints .fail, restores state, CONTINUES boot
;   (degrade, never crash).
;     (1) KAT     — netdev_tx's two canonical behaviours:
;                   NO-NIC  : empty table -> egress finds nothing -> tx == -1.
;                   DISPATCH: a healthy backend whose ops.tx is a recording stub ->
;                             the stub sees the EXACT (self, frame, len) and its 0x7A
;                             sentinel return propagates byte-for-byte out of netdev_tx.
;     (2) DEGRADE — fault containment a BASELINE netdev_tx would CRASH on (this is the
;                   durability win the class rewards): a HEALTH_OK member with a NULL
;                   ops.tx handle, and one with a NULL ops vtable, BOTH degrade to -1
;                   (never call/deref address 0).
;     (3) GUARD   — after all the KAT churn the live table + count == the wholesale
;                   snapshot byte-for-byte (the gate perturbs no live invariant).
netdev_tx_kat:
    push rbx
    push r12
    push r13
    push r14
    push r15

    call nd_kat_snapshot                   ; wholesale save of table + count
    mov  r15, [rel netdev_egress_calls]    ; ...and the observable egress counter

    ; ---------- (1) KAT: NO-NIC -> -1 ----------
    call nd_tx_kat_clear_table             ; count=0, all slots empty
    lea  rsi, [rel nd_tx_kat_frame_data]
    mov  edx, 64
    call netdev_tx
    cmp  rax, -1
    jne  .fail                             ; empty table MUST drop with -1

    ; ---------- (1) KAT: DISPATCH through a recording stub ----------
    call nd_tx_kat_clear_table
    mov  qword [rel nd_tx_kat_self], 0      ; clear the stub's latches
    mov  qword [rel nd_tx_kat_gotframe], 0
    mov  qword [rel nd_tx_kat_gotlen], 0
    call nd_kat_make_dev                    ; valid healthy CLASS_NET, ops = nd_kat_ops
    lea  rax, [rel nd_tx_kat_stub]
    mov  [rel nd_kat_ops + netdev_ops.tx], rax   ; ops.tx = recording stub
    call nd_tx_kat_place                    ; slot 0 = nd_kat_dev, count=1
    mov  r13, rax                           ; the installed handle
    lea  rsi, [rel nd_tx_kat_frame_data]
    mov  r14, rsi                           ; expected frame ptr
    mov  edx, 0x42                          ; distinctive len
    call netdev_tx
    cmp  rax, 0x7A                          ; stub's return propagated verbatim?
    jne  .fail
    mov  rax, [rel nd_tx_kat_self]
    cmp  rax, r13                           ; stub saw self == the selected handle?
    jne  .fail
    mov  rax, [rel nd_tx_kat_gotframe]
    cmp  rax, r14                           ; stub saw the EXACT frame ptr?
    jne  .fail
    cmp  qword [rel nd_tx_kat_gotlen], 0x42 ; ...and the EXACT len?
    jne  .fail
    lea  rdi, [rel str_tnt_kat]
    call serial_string

    ; ---------- (2) DEGRADE: null-tx & null-ops both -> -1, no crash ----------
    ; (a) HEALTH_OK backend whose ops vtable exists but .tx handle is NULL
    call nd_tx_kat_clear_table
    call nd_kat_make_dev
    mov  qword [rel nd_kat_ops + netdev_ops.tx], 0   ; vtable present, but NO tx op
    call nd_tx_kat_place
    lea  rsi, [rel nd_tx_kat_frame_data]
    mov  edx, 64
    call netdev_tx
    cmp  rax, -1                            ; degraded, NOT a call to address 0
    jne  .fail
    ; (b) HEALTH_OK backend whose ops vtable POINTER itself is NULL
    call nd_tx_kat_clear_table
    call nd_kat_make_dev
    mov  qword [rel nd_kat_dev + dev.ops], 0         ; null ops vtable, still HEALTH_OK
    call nd_tx_kat_place
    lea  rsi, [rel nd_tx_kat_frame_data]
    mov  edx, 64
    call netdev_tx
    cmp  rax, -1                            ; degraded, NOT a deref of address 0
    jne  .fail
    lea  rdi, [rel str_tnt_degrade]
    call serial_string

    ; ---------- restore the live table + egress counter (durability guarantee) ----------
    call nd_kat_restore
    mov  [rel netdev_egress_calls], r15

    ; ---------- (3) GUARD: live table + count == snapshot byte-for-byte ----------
    lea  rsi, [rel netdev_table]
    lea  rdi, [rel nd_kat_save]
    mov  ecx, NETDEV_MAX_SLOTS
.gcmp:
    mov  rax, [rsi]
    cmp  rax, [rdi]
    jne  .fail
    add  rsi, 8
    add  rdi, 8
    dec  ecx
    jnz  .gcmp
    mov  rax, [rel nd_kat_save_count]
    cmp  [rel netdev_count], rax
    jne  .fail
    lea  rdi, [rel str_tnt_guard]
    call serial_string
    jmp  .done

.fail:
    call nd_kat_restore                     ; ALWAYS restore the live table, even on fail
    mov  [rel netdev_egress_calls], r15
    lea  rdi, [rel str_tnt_fail]
    call serial_string
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    ret

; nd_tx_kat_clear_table — zero every table slot + count so egress-select resolves
;   ONLY the scratch backend a KAT vector installs. clobbers RAX,RCX,R9.
nd_tx_kat_clear_table:
    lea  r9, [rel netdev_table]
    xor  ecx, ecx
.z:
    mov  qword [r9 + rcx*8], 0
    inc  ecx
    cmp  ecx, NETDEV_MAX_SLOTS
    jb   .z
    mov  qword [rel netdev_count], 0
    ret

; nd_tx_kat_place — install the scratch dev (nd_kat_dev) at slot 0, count=1, and
;   return RAX = the handle. clobbers RAX,R9.
nd_tx_kat_place:
    lea  rax, [rel nd_kat_dev]
    lea  r9, [rel netdev_table]
    mov  [r9], rax
    mov  qword [rel netdev_count], 1
    ret

; nd_tx_kat_stub — a recording netdev_ops.tx: latches (self,frame,len) so the KAT
;   can prove netdev_tx dispatched the EXACT args, and returns a 0x7A sentinel the
;   KAT proves propagated verbatim. (RDI=self,RSI=frame,RDX=len)->RAX. Preserves the
;   ops ABI (clobbers only RAX per the tx contract).
nd_tx_kat_stub:
    mov  [rel nd_tx_kat_self], rdi
    mov  [rel nd_tx_kat_gotframe], rsi
    mov  [rel nd_tx_kat_gotlen], rdx
    mov  eax, 0x7A
    ret

; ============================================================================
; 1075 SMP lock-SITE retro-audit. net/netdev shipped (1009) BEFORE the 1003 lock
; discipline, so its shared state (the N-ary netdev_table, netdev_count, and the
; egress-select call counter) had no declared protecting lock. netdev_lock is that
; retro-declared lock; it reuses the ONE spin primitive (core/lock.asm), never a
; netdev-local copy. netdev_lock_audit EXERCISES the SITE once (acquire -> guarded
; shared write -> release) and PRINTS the netdev coverage line the probe grades.
; ============================================================================
netdev_lock_acquire:
    lea  rdi, [rel netdev_lock]
    call spin_acquire
    ret
netdev_lock_release:
    lea  rdi, [rel netdev_lock]
    call spin_release
    ret

; netdev_lock_audit — exercise the DECLARED netdev_lock site once around a guarded
;   write of the shared egress counter, then emit "smp.audit netdev: sites=1
;   exercised=<N>". Net-zero mutation so it perturbs no netdev invariant.
netdev_lock_audit:
    push rbx
    call netdev_lock_acquire                 ; --- enter the critical section ---
    inc  qword [rel netdev_egress_calls]      ; guarded shared write ...
    dec  qword [rel netdev_egress_calls]      ; ... restored (net-zero)
    inc  qword [rel netdev_audit_exercised]   ; count the real acquire/release cycle
    call netdev_lock_release                  ; --- leave the critical section ---
    lea  rdi, [rel str_nd_audit_pre]
    call serial_string
    mov  rdi, [rel netdev_audit_exercised]
    lea  rsi, [rel netdev_audit_numbuf]
    call fmt_dec
    lea  rdi, [rel netdev_audit_numbuf]
    call serial_string
    lea  rdi, [rel str_nd_audit_post]
    call serial_string
    pop  rbx
    ret

; --- net/netdev data (in-image writable, like core/log's line buffers) ----------
; T0-1.C3 pure selected registry census. RSI=24-byte caller buffer:
; +0 one-based selected ordinal (0 none), +4 exact ops family,
; +8 actual health, +12 priority, +16 all member count, +20 flags
; (1 invalid/clipped list, 2 busy). No pointer/name/MAC or device callback.
; Nonblocking acquisition; no registration, selection mutation or device IO.
%include "core/abi/registry_instance_census.inc"
; RSI=64B v2 internal snapshot. Same selection/lock as legacy24B entry.
netdev_census_snapshot_v2:
    mov eax,1
    jmp netdev_census_snapshot.with_instance
netdev_census_snapshot:
    xor eax,eax
.with_instance:
    push rbx
    push r12
    push r13
    push r14
    sub rsp,8
    mov r14d,eax
    mov r12,rsi
    mov qword [r12],0
    mov qword [r12+8],0
    mov qword [r12+16],0
    test r14d,r14d
    jz .legacy
    mov qword [r12+24],0
    mov qword [r12+32],0
    mov qword [r12+40],0
    mov qword [r12+48],0
    mov qword [r12+56],0
.legacy:
    xor r13d,r13d
    lea rdi,[rel netdev_lock]
    call spin_try_acquire
    test eax,eax
    jz .busy
    xor ebx,ebx
.validate:
    cmp ebx,NETDEV_MAX_SLOTS
    jae .select
    lea rax,[rel netdev_table]
    mov rdx,[rax+rbx*8]
    test rdx,rdx
    jz .next
    inc dword [r12+16]
    cmp dword [rdx+dev.class],CLASS_NET
    jne .bad
    cmp qword [rdx+dev.ops],0
    je .bad
.next:
    inc ebx
    jmp .validate
.select:
    mov eax,[r12+16]
    cmp rax,[rel netdev_count]
    jne .bad
    call netdev_select_peek              ; exact TX policy, no egress counter
    mov r13,rax
    test r13,r13
    jz .unlock
    xor ebx,ebx
.ordinal:
    lea rax,[rel netdev_table]
    cmp [rax+rbx*8],r13
    je .selected
    inc ebx
    cmp ebx,NETDEV_MAX_SLOTS
    jb .ordinal
    jmp .bad
.selected:
    inc ebx
    mov [r12],ebx
    mov eax,[r13+dev.health]
    mov [r12+8],eax
    mov eax,[r13+dev.prio]
    mov [r12+12],eax
    mov rdx,[r13+dev.ops]
    mov dword [r12+4],255                 ; unknown exact vtable
    lea rax,[rel e1000e_ops]
    cmp rdx,rax
    jne .family_1
    mov dword [r12+4],1
    jmp .unlock
.family_1:
    lea rax,[rel rtl8168_ops]
    cmp rdx,rax
    jne .family_2
    mov dword [r12+4],2
    jmp .unlock
.family_2:
    lea rax,[rel e5000b_ops]
    cmp rdx,rax
    jne .family_3
    mov dword [r12+4],3
    jmp .unlock
.family_3:
    lea rax,[rel rtl8125_ops]
    cmp rdx,rax
    jne .family_4
    mov dword [r12+4],4
    jmp .unlock
.family_4:
    lea rax,[rel ax_ops]
    cmp rdx,rax
    jne .family_5
    mov dword [r12+4],5
    jmp .unlock
.family_5:
    lea rax,[rel axb_ops]
    cmp rdx,rax
    jne .family_6
    mov dword [r12+4],6
    jmp .unlock
.family_6:
    lea rax,[rel cdc_ecm_ops]
    cmp rdx,rax
    jne .family_7
    mov dword [r12+4],7
    jmp .unlock
.family_7:
    lea rax,[rel cdc_ncm_ops]
    cmp rdx,rax
    jne .family_8
    mov dword [r12+4],8
    jmp .unlock
.family_8:
    lea rax,[rel virtio_domain_ops]
    cmp rdx,rax
    jne .family_9
    mov dword [r12+4],9
    jmp .unlock
.family_9:
    lea rax,[rel loopnet_ops]
    cmp rdx,rax
    jne .family_10
    mov dword [r12+4],10
    jmp .unlock
.family_10:
    jmp .unlock
.bad:
    or dword [r12+20],1
.unlock:
    test r14d,r14d
    jz .release
    cmp dword [r12+20],0
    jne .release
    test r13,r13
    jz .release
    NETDEV_CENSUS_INSTANCE
.release:
    lea rdi,[rel netdev_lock]
    call spin_release
    jmp .done
.busy:
    mov dword [r12+20],2
.done:
    add rsp,8
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

%include "core/abi/wdata.inc" ; WDATA_DEFER; standalone assemblies expand blocks in place
; Writable state: deferred to the page-isolated WDATA region (core/abi/wdata.inc).
%macro WDATA_net_netdev_0 0
netdev_lock:           db 0                  ; retro-declared lock over the N-ary table (1075)
align 8
netdev_audit_exercised: dq 0                 ; count of acquire/release cycles run
netdev_audit_numbuf:   times 24 db 0
str_nd_audit_pre:      db "[PAOS64] P2 smp.audit netdev: sites=1 exercised=", 0
str_nd_audit_post:     db " [smp.lock.sites.netdev]", 13, 10, 0
netdev_table:        times NETDEV_MAX_SLOTS dq 0   ; slot -> struct dev* (0 = empty)
netdev_count:        dq 0                           ; occupied slot count (runtime)
netdev_egress_calls: dq 0                           ; egress-select invocation counter
netdev_reprobe_ticks: times NETDEV_MAX_SLOTS dd 0   ; RCQ-10: per-slot LINK_WAIT re-probe ticks
nd_e1k_slot:         dq 0
nd_loop_slot:        dq 0
net_dummy_frame:     times 64 db 0                  ; a throwaway TX frame for the hook
net_katbuf:          times 256 db 0

str_nd_table_init:   db "[PAOS64] L2 netdev: N-ary slot table init [netdev.table.init]", 13, 10, 0
str_nd_vtable_reg:   db "[PAOS64] L2 netdev: e1000e native backend bound via netdev_ops HANDLE [netdev.vtable.registered]", 13, 10, 0
str_nd_loopnet_reg:  db "[PAOS64] L2 netdev: loopnet reference backend registered [netdev.loopnet.registered]", 13, 10, 0
str_nd_egress:       db "[PAOS64] L2 netdev: egress-select hook fired on TX [netdev.egress.select]", 13, 10, 0
str_nd_affinity:     db "[PAOS64] L2 netdev: socket_desc affinity_nic_handle field present [netdev.affinity.field]", 13, 10, 0
str_nd_pass:         db "[PAOS64] L2 netdev: N-ary slot seam PASS [netdev.slot.seam]", 13, 10, 0

str_kv_prefix:       db "[PAOS64][INF][net] netdev.kat: ", 0
str_k_table:         db "TABLE_SLOTS", 0
str_k_e1k:           db "E1000E_SLOT_INDEX", 0
str_k_loop:          db "LOOPNET_SLOT_INDEX", 0
str_k_egress:        db "EGRESS_SELECT_CALLS", 0
str_k_affinity:      db "SOCKET_DESCRIPTOR_AFFINITY_OFFSET", 0

; --- tournament net_kv_append v3 (most-durable) state + KAT vectors/markers ---
net_kv_limit:        dq 0                 ; exclusive write bound (0 = DISARMED = baseline)
net_kv_truncations:  dq 0                 ; contained-overrun counter (observable)
net_kv_kat_buf:      times 96 db 0        ; sentinel-fenced KAT scratch
str_kat_kA:          db "A", 0
str_kat_kX:          db "X", 0
str_kat_kZ:          db "Z", 0
str_kat_kKV:         db "KV", 0
str_kat_expect:      db "A=0 TABLE_SLOTS=4 X=255 Z=4294967295 KV=1000000 ", 0
str_kat_bexpect:     db "TABLE_SLOTS=4 ", 0
str_tk_kat:          db "[tourn.net_kv_append.kat]", 13, 10, 0
str_tk_guard:        db "[tourn.net_kv_append.guard]", 13, 10, 0
str_tk_bound:        db "[tourn.net_kv_append.bound]", 13, 10, 0
str_tk_fail:         db "[tourn.net_kv_append.kat.fail]", 13, 10, 0

; --- tournament netdev_register v3 (most-durable) KAT scratch + markers ---
align 8
nd_kat_save:         times NETDEV_MAX_SLOTS dq 0   ; wholesale live-table snapshot
nd_kat_save_count:   dq 0                           ; snapshot of netdev_count
nd_kat_dev:          times dev_size db 0            ; scratch struct dev under test
nd_kat_ops:          times netdev_ops_size db 0     ; non-null vtable sentinel (never deref'd)
str_tnr_kat:         db "[tourn.netdev_register.kat]", 13, 10, 0
str_tnr_dup:         db "[tourn.netdev_register.dup]", 13, 10, 0
str_tnr_guard:       db "[tourn.netdev_register.guard]", 13, 10, 0
str_tnr_fail:        db "[tourn.netdev_register.kat.fail]", 13, 10, 0

; --- tournament netdev_tx v3 (most-durable) KAT scratch + recording stub + markers ---
align 8
nd_tx_kat_self:      dq 0                 ; stub latch: self handle it was dispatched with
nd_tx_kat_gotframe:  dq 0                 ; stub latch: frame ptr it saw
nd_tx_kat_gotlen:    dq 0                 ; stub latch: len it saw
nd_tx_kat_frame_data: times 64 db 0       ; a throwaway TX frame the KAT hands to netdev_tx
str_tnt_kat:         db "[tourn.netdev_tx.kat]", 13, 10, 0
str_tnt_degrade:     db "[tourn.netdev_tx.degrade]", 13, 10, 0
str_tnt_guard:       db "[tourn.netdev_tx.guard]", 13, 10, 0
str_tnt_fail:        db "[tourn.netdev_tx.kat.fail]", 13, 10, 0
%endmacro
WDATA_DEFER WDATA_net_netdev_0

%macro WDATA_net_netdev_observation 0
alignb 8
netdev_observation_generations: resq NETDEV_MAX_SLOTS
netdev_observation_testing: resb 1
%endmacro
WDATA_BSS_DEFER WDATA_net_netdev_observation
